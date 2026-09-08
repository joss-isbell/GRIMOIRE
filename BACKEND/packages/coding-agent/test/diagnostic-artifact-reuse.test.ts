import { createHash } from "node:crypto";
import { link, lstat, mkdtemp, readFile, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DiagnosticArtifactOperations } from "../src/modes/daemon/diagnostic-evidence-artifacts.js";
import { DiagnosticEvidenceStore, type EvidenceOperationInput } from "../src/modes/daemon/diagnostic-evidence-store.js";

const directories: string[] = [];
const DAY = 86_400_000;
const bytes = Buffer.from("MESSAGE=native\nBINARY\n\0\x01\x02\n\n");
afterEach(async () => {
	vi.restoreAllMocks();
	await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});
const input = (id: string, incidentId = "later"): EvidenceOperationInput => ({
	id, incidentId, kind: "export", artifact: { id, path: `${id}.export`, format: "journal.export" },
});
async function fixture(seedCount = 1) {
	const root = await mkdtemp(join(tmpdir(), "artifact-reuse-"));
	directories.push(root);
	const path = join(root, "evidence.sqlite");
	const artifacts = join(root, "artifacts");
	const store = await DiagnosticEvidenceStore.open({ path });
	for (const [id, triggerTimeMs] of [["old", 1000], ["later", 1000 + DAY]] as const)
		await store.openIncident({ id, triggerTimeMs, windowStartMs: triggerTimeMs, windowEndMs: triggerTimeMs, coverage: {}, limitations: [] });
	for (let index = 0; index < seedCount; index++) await store.prepareOperation(input(`seed-${index}`, "old"));
	const executor = await DiagnosticArtifactOperations.open({ store, root: artifacts, exportArtifact: async function* (op) {
		yield seedCount === 1 ? bytes : Buffer.alloc(bytes.length, Number(op.id.split("-")[1]) + 65);
	} });
	expect((await executor.reconcile()).completed).toBe(seedCount);
	return { root, path, artifacts, store };
}
const pendingPath = (root: string, id: string) => join(root, `${id}.export.pending-${createHash("sha256").update(id).digest("hex").slice(0, 24)}`);

describe("exact native artifact reuse", () => {
	it.each(["pin", "decision", "link", "unlink", "before-commit", "after-commit"])("recovers %s interruption from SQL without a provider replay", async (phase) => {
		const f = await fixture();
		await f.store.prepareOperation(input("second"));
		const method = phase === "pin" ? "selectArtifactCandidate" : ["decision", "link", "unlink"].includes(phase) ? "selectArtifactContent" : "markOperationReady";
		const original = f.store[method].bind(f.store);
		const crash = vi.spyOn(f.store, method).mockImplementation(async (...args: unknown[]) => {
			if (phase !== "before-commit") await Reflect.apply(original, f.store, args);
			throw new Error("interrupted at durable boundary");
		});
		try {
			const executor = await DiagnosticArtifactOperations.open({ store: f.store, root: f.artifacts, exportArtifact: async function* () { yield bytes; } });
			expect((await executor.reconcile()).failures[0]?.error).toMatch(/interrupted/);
			if (phase === "link" || phase === "unlink") {
				await link(join(f.artifacts, "seed-0.export"), join(f.artifacts, "second.export"));
				if (phase === "unlink") await unlink(pendingPath(f.artifacts, "second"));
			}
		} finally { crash.mockRestore(); await f.store.close(); }
		const store = await DiagnosticEvidenceStore.open({ path: f.path });
		try {
			let calls = 0;
			const executor = await DiagnosticArtifactOperations.open({ store, root: f.artifacts, availableBytes: async () => 0, exportArtifact: async function* () { calls++; yield Buffer.alloc(0); } });
			expect(await executor.reconcile()).toMatchObject({ completed: phase === "after-commit" ? 0 : 1, pending: 0, failures: [] });
			expect(calls).toBe(0);
			expect(await readFile(join(f.artifacts, "second.export"))).toEqual(bytes);
			const old = await stat(join(f.artifacts, "seed-0.export"));
			expect((await stat(join(f.artifacts, "second.export"))).ino).toBe(old.ino);
			expect(await store.stats()).toMatchObject({ artifactBytes: bytes.length * 2, artifactAllocatedBytes: old.blocks * 512, reservedArtifactBytes: 0 });
			expect((await store.listArtifacts("old"))[0].contentId).toBe((await store.listArtifacts("later"))[0].contentId);
		} finally { await store.close(); }
	});

	it("pins the source across retention, then expires aliases independently and frees physical bytes only once", async () => {
		const f = await fixture();
		try {
			await f.store.prepareOperation(input("second"));
			const original = f.store.selectArtifactCandidate.bind(f.store);
			const paused = vi.spyOn(f.store, "selectArtifactCandidate").mockImplementation(async (id) => { await original(id); throw new Error("pause after pin"); });
			const executor = await DiagnosticArtifactOperations.open({ store: f.store, root: f.artifacts, exportArtifact: async function* () { yield bytes; } });
			expect((await executor.reconcile()).completed).toBe(0);
			paused.mockRestore();
			expect((await f.store.retain({ nowMs: 1001 + 14 * DAY })).operationsQueued).toBe(0);
			await expect(f.store.prepareOperation({ ...input("manual-delete", "old"), kind: "delete", artifact: input("seed-0").artifact })).rejects.toThrow("artifact_pinned");
			expect((await executor.reconcile()).completed).toBe(1);
			const allocated = (await f.store.stats()).artifactAllocatedBytes;
			expect((await f.store.retain({ nowMs: 1001 + 14 * DAY })).operationsQueued).toBe(1);
			expect((await executor.reconcile()).completed).toBe(1);
			expect(await readFile(join(f.artifacts, "second.export"))).toEqual(bytes);
			expect(await f.store.stats()).toMatchObject({ artifactBytes: bytes.length, artifactAllocatedBytes: allocated });
			expect((await f.store.retain({ nowMs: 1001 + 15 * DAY })).operationsQueued).toBe(1);
			expect((await executor.reconcile()).completed).toBe(1);
			expect(await f.store.stats()).toMatchObject({ artifactBytes: 0, artifactAllocatedBytes: 0 });
		} finally { await f.store.close(); }
	});

	it("rejects hash collisions byte-for-byte and resumes a bounded candidate cursor after restart", async () => {
		const f = await fixture(3);
		await f.store.close();
		const db = new DatabaseSync(f.path);
		const hash = createHash("sha256").update(bytes).digest("hex");
		db.prepare("UPDATE artifact_contents SET sha256=?").run(hash);
		db.prepare("UPDATE artifacts SET sha256=?").run(hash);
		db.close();
		let store = await DiagnosticEvidenceStore.open({ path: f.path });
		try {
			await store.prepareOperation(input("second"));
			let calls = 0;
			for (let pass = 0; pass < 4; pass++) {
				const executor = await DiagnosticArtifactOperations.open({ store, root: f.artifacts, maxReuseCandidatesPerPass: 1, exportArtifact: async function* () { calls++; yield bytes; } });
				expect(await executor.reconcile()).toMatchObject({ completed: pass === 3 ? 1 : 0, pending: pass === 3 ? 0 : 1, failures: [] });
				await store.close();
				store = await DiagnosticEvidenceStore.open({ path: f.path });
			}
			expect(calls).toBe(1);
			const inode = (await stat(join(f.artifacts, "second.export"))).ino;
			for (let i = 0; i < 3; i++) expect((await stat(join(f.artifacts, `seed-${i}.export`))).ino).not.toBe(inode);
			expect(await readFile(join(f.artifacts, "second.export"))).toEqual(bytes);
			expect((await store.listArtifacts("later"))[0].contentId).toBe(4);
		} finally { await store.close(); }
	});

	it.each(["missing", "symlink", "changed-size", "changed-bytes"])("preserves a %s candidate and retains distinct new evidence", async (fault) => {
		const f = await fixture();
		try {
			const seed = join(f.artifacts, "seed-0.export");
			if (fault === "missing" || fault === "symlink") await unlink(seed);
			if (fault === "symlink") { await writeFile(join(f.root, "outside"), bytes); await symlink(join(f.root, "outside"), seed); }
			if (fault === "changed-size") await writeFile(seed, "different");
			if (fault === "changed-bytes") await writeFile(seed, Buffer.alloc(bytes.length, 65));
			await f.store.prepareOperation(input("second"));
			const executor = await DiagnosticArtifactOperations.open({ store: f.store, root: f.artifacts, exportArtifact: async function* () { yield bytes; } });
			expect(await executor.reconcile()).toMatchObject({ completed: 1, failures: [] });
			expect(await readFile(join(f.artifacts, "second.export"))).toEqual(bytes);
			if (fault === "symlink") expect((await lstat(seed)).isSymbolicLink()).toBe(true);
			if (fault === "changed-size") expect(await readFile(seed, "utf8")).toBe("different");
			if (fault !== "changed-bytes") expect((await f.store.prepareOperation(input("second"))).reuseLimitations?.length).toBe(1);
			expect((await f.store.listArtifacts("old"))[0].contentId).not.toBe((await f.store.listArtifacts("later"))[0].contentId);
		} finally { await f.store.close(); }
	});

	it("cancellation after pin preserves the pending export and resumes without provider calls", async () => {
		const f = await fixture();
		try {
			await f.store.prepareOperation(input("second"));
			const controller = new AbortController();
			const original = f.store.selectArtifactCandidate.bind(f.store);
			const cancel = vi.spyOn(f.store, "selectArtifactCandidate").mockImplementation(async (id) => { const result = await original(id); controller.abort(); return result; });
			let calls = 0;
			const executor = await DiagnosticArtifactOperations.open({ store: f.store, root: f.artifacts, exportArtifact: async function* () { calls++; yield bytes; } });
			expect(await executor.reconcile({ signal: controller.signal })).toMatchObject({ completed: 0, pending: 1 });
			cancel.mockRestore();
			expect((await f.store.unfinishedOperations())[0].candidate?.id).toBe("seed-0");
			expect(await executor.reconcile()).toMatchObject({ completed: 1, failures: [] });
			expect(calls).toBe(1);
		} finally { await f.store.close(); }
	});
	it.each(["staged", "selected-stage", "selected-source", "unrelated-final"])("preserves %s replacement files instead of trusting equal bytes or a stale comparison", async (phase) => {
		const f = await fixture();
		await f.store.prepareOperation(input("second"));
		const method = phase === "staged" ? "markOperationStaged" : "selectArtifactContent";
		const original = f.store[method].bind(f.store);
		const crash = vi.spyOn(f.store, method).mockImplementation(async (...args: unknown[]) => {
			await Reflect.apply(original, f.store, args);
			throw new Error("pause before publication");
		});
		try {
			const executor = await DiagnosticArtifactOperations.open({ store: f.store, root: f.artifacts, exportArtifact: async function* () { yield bytes; } });
			expect((await executor.reconcile()).completed).toBe(0);
		} finally { crash.mockRestore(); await f.store.close(); }
		const changed = phase === "selected-source" ? join(f.artifacts, "seed-0.export") : phase === "unrelated-final" ? join(f.artifacts, "second.export") : pendingPath(f.artifacts, "second");
		// Retain the original inode so this check cannot accidentally reuse it.
		if (phase !== "unrelated-final") { await link(changed, join(f.root, "preserved-original")); await unlink(changed); }
		await writeFile(changed, bytes);
		const store = await DiagnosticEvidenceStore.open({ path: f.path });
		try {
			let calls = 0;
			const executor = await DiagnosticArtifactOperations.open({ store, root: f.artifacts, exportArtifact: async function* () { calls++; yield bytes; } });
			const result = await executor.reconcile();
			expect(result.completed).toBe(0);
			expect(result.failures[0]?.error).toMatch(/artifact_(identity_conflict|selection_unavailable)/);
			expect(calls).toBe(0);
			expect(await readFile(changed)).toEqual(bytes);
			expect(await store.listArtifacts("later")).toHaveLength(0);
		} finally { await store.close(); }
	});
});
