import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DiagnosticArtifactOperations } from "../src/modes/daemon/diagnostic-evidence-artifacts.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";

const directories: string[] = [];
afterEach(async () => {
	await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function fixture() {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-artifacts-"));
	directories.push(root);
	const store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
	const time = Date.now();
	await store.openIncident({
		id: "incident",
		triggerTimeMs: time,
		windowStartMs: time - 1000,
		windowEndMs: time + 1000,
		coverage: {},
		limitations: [],
	});
	await store.prepareOperation({
		id: "export",
		incidentId: "incident",
		kind: "export",
		artifact: { id: "raw", path: "incident.journal", format: "journal.export" },
	});
	return { root, store };
}

describe("durable native artifact operations", () => {
	it("shares exactly equal native content while retaining initial, final and cross-incident artifact identities", async () => {
		const { root, store } = await fixture();
		try {
			const time = Date.now();
			await store.openIncident({ id: "later", triggerTimeMs: time, windowStartMs: time, windowEndMs: time, coverage: {}, limitations: [] });
			for (const [id, incidentId] of [["final", "incident"], ["later", "later"]])
				await store.prepareOperation({ id, incidentId, kind: "export", artifact: { id, path: `${id}.journal`, format: "journal.export" } });
			const bytes = Buffer.from("MESSAGE=exact native evidence\n\n");
			const operations = await DiagnosticArtifactOperations.open({ store, root: join(root, "artifacts"), exportArtifact: async function* () { yield bytes; } });
			expect(await operations.reconcile()).toMatchObject({ completed: 3, pending: 0, failures: [] });
			const files = await Promise.all(["incident", "final", "later"].map(async (id) => {
				const path = join(root, "artifacts", `${id}.journal`);
				expect(await readFile(path)).toEqual(bytes);
				return stat(path);
			}));
			expect(new Set(files.map((file) => file.ino)).size).toBe(1);
			expect(await store.listArtifacts("incident")).toHaveLength(2);
			expect(await store.listArtifacts("later")).toHaveLength(1);
			expect(await store.stats()).toMatchObject({ artifactBytes: bytes.length * 3, artifactAllocatedBytes: files[0].blocks * 512, reservedArtifactBytes: 0 });
		} finally { await store.close(); }
	});
	it("advances past unavailable exports so a later incident is not starved", async () => {
		const { root, store } = await fixture();
		try {
			await store.prepareOperation({
				id: "z-export",
				incidentId: "incident",
				kind: "export",
				artifact: { id: "second", path: "second.journal", format: "journal.export" },
			});
			const operations = await DiagnosticArtifactOperations.open({
				store,
				root: join(root, "artifacts"),
				exportArtifact: async function* (operation) {
					if (operation.id === "export") throw new Error("source unavailable");
					yield Buffer.from("later available evidence");
				},
			});
			const first = await operations.reconcile({ limit: 1 });
			expect(first).toMatchObject({ completed: 0, nextId: "export" });
			const second = await operations.reconcile({ limit: 1, afterId: first.nextId });
			expect(second.completed).toBe(1);
			expect(await readFile(join(root, "artifacts", "second.journal"), "utf8")).toBe("later available evidence");
			expect((await store.unfinishedOperations()).map((operation) => operation.id)).toEqual(["export"]);
		} finally {
			await store.close();
		}
	});
	it("publishes exact native bytes and only then records the completed export", async () => {
		const { root, store } = await fixture();
		try {
			const bytes = Buffer.from("MESSAGE=provider-native\nBINARY\n\0\x01\x02\n\n");
			const operations = await DiagnosticArtifactOperations.open({
				store,
				root: join(root, "artifacts"),
				exportArtifact: async function* () {
					yield bytes.subarray(0, 9);
					yield bytes.subarray(9);
				},
			});
			expect(await operations.reconcile()).toEqual({ completed: 1, pending: 0, failures: [] });
			expect(await readFile(join(root, "artifacts", "incident.journal"))).toEqual(bytes);
			expect(await store.unfinishedOperations()).toEqual([]);
			expect(await store.listArtifacts("incident")).toEqual([
				expect.objectContaining({
					bytes: bytes.length,
					sha256: createHash("sha256").update(bytes).digest("hex"),
				}),
			]);
		} finally {
			await store.close();
		}
	});

	it("replays only unfinished operations after interruption and never promotes an incomplete file", async () => {
		const { root, store } = await fixture();
		try {
			const artifacts = join(root, "artifacts");
			const failed = await DiagnosticArtifactOperations.open({
				store,
				root: artifacts,
				exportArtifact: async function* () {
					yield Buffer.from("partial");
					throw new Error("provider gone");
				},
			});
			expect((await failed.reconcile()).failures).toEqual([{ id: "export", error: "provider gone" }]);
			expect((await store.unfinishedOperations()).map((entry) => entry.id)).toEqual(["export"]);
			expect((await store.stats()).reservedArtifactBytes).toBe(0);
			const recovered = await DiagnosticArtifactOperations.open({
				store,
				root: artifacts,
				exportArtifact: async function* () {
					yield Buffer.from("complete native artifact");
				},
			});
			expect((await recovered.reconcile()).completed).toBe(1);
			expect(await readFile(join(artifacts, "incident.journal"), "utf8")).toBe("complete native artifact");
			expect((await recovered.reconcile()).completed).toBe(0);
		} finally {
			await store.close();
		}
	});

	it.each(["staged", "published"])("recovers %s evidence without querying a vacuumed provider", async (phase) => {
		const { root, store } = await fixture();
		const artifactRoot = join(root, "new", "nested", "artifacts");
		const bytes = Buffer.from("only surviving native evidence\0\x01");
		const method = phase === "staged" ? "markOperationStaged" : "markOperationReady";
		const original = store[method].bind(store);
		const crash = vi.spyOn(store, method).mockImplementation(async (...args: unknown[]) => {
			if (phase === "staged") await Reflect.apply(original, store, args);
			throw new Error("recorder crash before acknowledgment");
		});
		try {
			const operations = await DiagnosticArtifactOperations.open({
				store,
				root: artifactRoot,
				exportArtifact: async function* () {
					yield bytes;
				},
			});
			expect((await operations.reconcile()).failures[0]?.error).toMatch(/recorder crash/);
			expect((await store.unfinishedOperations())[0]?.stagedAtMs).toBeTypeOf("number");
		} finally {
			crash.mockRestore();
			await store.close();
		}
		const reopened = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
		let providerCalls = 0;
		try {
			const recovery = await DiagnosticArtifactOperations.open({
				store: reopened,
				root: artifactRoot,
				availableBytes: async () => 0,
				exportArtifact: async function* () {
					providerCalls++;
					yield Buffer.alloc(0);
				},
			});
			expect(await recovery.reconcile()).toMatchObject({ completed: 1, pending: 0, failures: [] });
			expect(providerCalls).toBe(0);
			expect(await readFile(join(artifactRoot, "incident.journal"))).toEqual(bytes);
			expect((await reopened.listArtifacts("incident"))[0]).toMatchObject({
				bytes: bytes.length,
				sha256: createHash("sha256").update(bytes).digest("hex"),
			});
		} finally {
			await reopened.close();
		}
	});

	it.each([false, true])("preserves an existing final file when staged identity is %s", async (staged) => {
		const { root, store } = await fixture();
		try {
			let providerCalls = 0;
			const operations = await DiagnosticArtifactOperations.open({
				store,
				root: join(root, "artifacts"),
				exportArtifact: async function* () {
					providerCalls++;
					yield Buffer.alloc(0);
				},
			});
			if (staged) {
				await store.reserveOperationBytes("export", 4096);
				await store.markOperationStaged("export", {
					bytes: 5,
					sha256: createHash("sha256").update("other").digest("hex"),
					allocatedBytes: 4096,
				});
			}
			await writeFile(join(root, "artifacts", "incident.journal"), "uncertain captured evidence");
			const result = await operations.reconcile();
			expect(result.failures[0]?.error).toMatch(
				staged ? /artifact_identity_conflict/ : /artifact_identity_unavailable/,
			);
			expect(providerCalls).toBe(0);
			expect(await readFile(join(root, "artifacts", "incident.journal"), "utf8")).toBe(
				"uncertain captured evidence",
			);
			expect(await store.unfinishedOperations()).toHaveLength(1);
			expect(await store.listArtifacts("incident")).toHaveLength(0);
		} finally {
			await store.close();
		}
	});

	it("leaves budget-rejected exports pending and never follows an artifact directory symlink", async () => {
		const { root, store } = await fixture();
		try {
			const operations = await DiagnosticArtifactOperations.open({
				store,
				root: join(root, "artifacts"),
				maxArtifactBytes: 3,
				exportArtifact: async function* () {
					yield Buffer.from("four");
				},
			});
			expect((await operations.reconcile()).failures[0]?.error).toMatch(/artifact_budget/);
			expect(await store.unfinishedOperations()).toHaveLength(1);
			expect((await store.stats()).reservedArtifactBytes).toBe(0);
			await store.prepareOperation({
				id: "escape",
				incidentId: "incident",
				kind: "export",
				artifact: { id: "escape", path: "outside/escaped", format: "journal.export" },
			});
			await symlink(root, join(root, "artifacts", "outside"));
			const result = await operations.reconcile();
			expect(result.failures.find((entry) => entry.id === "escape")?.error).toMatch(/artifact_directory/);
			await expect(readFile(join(root, "escaped"))).rejects.toMatchObject({ code: "ENOENT" });
		} finally {
			await store.close();
		}
	});
});
