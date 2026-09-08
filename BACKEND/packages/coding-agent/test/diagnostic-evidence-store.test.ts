import { createHash } from "node:crypto";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Worker } from "node:worker_threads";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";

const DAY = 86_400_000;
const payload = (value: string) => Buffer.from(value);
const occurrence = (id: string, wallTimeMs = Date.now(), value = id) => ({
	id,
	wallTimeMs,
	kind: "journal",
	payload: payload(value),
});
async function selectUnique(store: DiagnosticEvidenceStore, id: string) {
	let operation = await store.selectArtifactCandidate(id);
	while (operation.candidate) {
		await store.rejectArtifactCandidate(id, operation.candidate.id);
		operation = await store.selectArtifactCandidate(id);
	}
	await store.selectArtifactContent(id, { kind: "unique", identity: { device: "1", inode: "1", size: operation.artifact.bytes!, mtimeNs: "1" } });
}

describe("SQLite diagnostic evidence store", () => {
	let directory: string;
	let path: string;
	let store: DiagnosticEvidenceStore;
	beforeEach(async () => {
		directory = await mkdtemp(join(tmpdir(), "diagnostic-evidence-test-"));
		path = join(directory, "evidence.sqlite");
		store = await DiagnosticEvidenceStore.open({ path });
	});
	afterEach(async () => {
		await store?.close().catch(() => {});
		await rm(directory, { recursive: true, force: true });
	});

	it("durably keeps exact payload bytes and all duplicate occurrences across reopen", async () => {
		const bytes = new Uint8Array([0, 255, 10, 128]);
		await store.ingest({
			batchId: "batch",
			source: "journal",
			expectedCursor: null,
			cursor: "c1",
			occurrences: [
				{ ...occurrence("a", 10), payload: bytes },
				{ ...occurrence("b", 11), payload: bytes },
			],
		});
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		expect(await store.getCursor("journal")).toBe("c1");
		const page = await store.readWindow({ startMs: 0, endMs: 20 });
		expect(page.occurrences.map((row) => row.id)).toEqual(["a", "b"]);
		expect(page.occurrences[0].sequence).toBeLessThan(page.occurrences[1].sequence);
		for (const row of page.occurrences) expect(row.payload).toEqual(bytes);
		expect((await store.stats()).payloads).toBe(1);
	});

	it("indexes causal input and advances incident revisions only for committed in-window evidence", async () => {
		const incident = await store.openIncident({
			id: "incident",
			triggerTimeMs: 1000,
			windowStartMs: 500,
			windowEndMs: 2000,
			coverage: {},
			limitations: [],
		});
		expect(incident.evidenceRevision).toBe(1);
		const batch = {
			batchId: "causal",
			source: "test",
			expectedCursor: null,
			cursor: "1",
			occurrences: [
				{ ...occurrence("start", 500), kind: "journal.json" },
				{ ...occurrence("end", 2000), kind: "diagnostic.gap" },
				{ ...occurrence("middle", 1000), kind: "evidence.gap" },
				{ ...occurrence("outside", 2001), kind: "journal.json" },
				{ ...occurrence("report", 1000), kind: "incident.analysis" },
			],
		};
		await store.ingest(batch);
		expect((await store.getIncident("incident"))!.evidenceRevision).toBe(4);
		await store.ingest(batch);
		expect((await store.getIncident("incident"))!.evidenceRevision).toBe(4);
		await expect(
			store.ingest({
				...batch,
				batchId: "rollback",
				expectedCursor: "1",
				cursor: "2",
				occurrences: [
					{ ...occurrence("would-insert", 1500), kind: "journal.json" },
					{ ...occurrence("start", 501), kind: "journal.json" },
				],
			}),
		).rejects.toThrow(/occurrence_conflict/);
		expect((await store.getIncident("incident"))!.evidenceRevision).toBe(4);
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		expect((await store.getIncident("incident"))!.evidenceRevision).toBe(4);
		const first = await store.readWindow({ startMs: 500, endMs: 2000, causalOnly: true, limit: 2 });
		const second = await store.readWindow({
			startMs: 500,
			endMs: 2000,
			causalOnly: true,
			afterSequence: first.nextSequence,
			limit: 2,
		});
		expect([...first.occurrences, ...second.occurrences].map((row) => row.id)).toEqual(["start", "middle", "end"]);
	});

	it("looks up one exact occurrence by source and identity across reopen", async () => {
		expect(await store.getOccurrence("detector", "gap")).toBeUndefined();
		const input = { ...occurrence("gap", 123), monotonicNs: "98765", payload: new Uint8Array([0, 255, 10]) };
		await store.ingest({
			batchId: "gap",
			source: "detector",
			expectedCursor: null,
			cursor: "1",
			occurrences: [input],
		});
		const captured = await store.getOccurrence("detector", "gap");
		expect(captured).toEqual({ ...input, source: "detector", sequence: 1 });
		expect(await store.getOccurrence("other-source", "gap")).toBeUndefined();
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		expect(await store.getOccurrence("detector", "gap")).toEqual(captured);
	});

	it("replays an ambiguous commit after worker termination with no duplicate occurrences", async () => {
		const batch = {
			batchId: "stable",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: [occurrence("a")],
		};
		await store.ingest(batch);
		await (store as unknown as { worker: Worker }).worker.terminate();
		store = await DiagnosticEvidenceStore.open({ path });
		expect(await store.ingest(batch)).toMatchObject({ inserted: 1, replayed: true, cursor: "1" });
		expect((await store.stats()).occurrences).toBe(1);
	});

	it("keeps replay receipts valid when old occurrence history expires first", async () => {
		const now = Date.now();
		const batch = {
			batchId: "old",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: [occurrence("old", now - 4 * DAY)],
		};
		await store.ingest(batch);
		await store.retain({ nowMs: now, limit: 10 });
		expect((await store.stats()).occurrences).toBe(0);
		expect(await store.ingest(batch)).toMatchObject({ replayed: true });
		expect((await store.stats()).occurrences).toBe(0);
		await store.retain({ nowMs: now + 4 * DAY, limit: 10 });
		await expect(store.ingest(batch)).rejects.toThrow("cursor_conflict");
	});

	it("compares candidate bytes even when the payload hash index contains a collision", async () => {
		await store.ingest({
			batchId: "a",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: [occurrence("a", 1, "alpha")],
		});
		await store.close();
		const inspect = new DatabaseSync(path);
		inspect.prepare("UPDATE payloads SET hash=?").run(createHash("sha256").update("beta").digest("hex"));
		inspect.close();
		store = await DiagnosticEvidenceStore.open({ path });
		await store.ingest({
			batchId: "b",
			source: "s",
			expectedCursor: "1",
			cursor: "2",
			occurrences: [occurrence("b", 2, "beta")],
		});
		expect((await store.stats()).payloads).toBe(2);
		expect((await store.readOccurrences()).occurrences.map((row) => Buffer.from(row.payload).toString())).toEqual([
			"alpha",
			"beta",
		]);
	});

	it("bounds queued requests and payload pages without losing the next occurrence", async () => {
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path, maxPendingRequests: 1 });
		const firstRequest = store.getCursor("s");
		await expect(store.getCursor("s")).rejects.toThrow("queue_full");
		await firstRequest;
		for (let index = 0; index < 2; index++)
			await store.ingest({
				batchId: String(index),
				source: "s",
				expectedCursor: index ? "0" : null,
				cursor: String(index),
				occurrences: [{ ...occurrence(String(index), 2 - index), payload: new Uint8Array(1024 * 1024) }],
			});
		const first = await store.readOccurrences({ limit: 1000 });
		expect(first.occurrences.map((row) => row.id)).toEqual(["0"]);
		const second = await store.readOccurrences({ afterSequence: first.nextSequence });
		expect(second.occurrences.map((row) => row.id)).toEqual(["1"]);
		await expect(
			store.openIncident({
				id: "oversized",
				triggerTimeMs: 1,
				windowStartMs: 0,
				windowEndMs: 2,
				coverage: { excessive: "x".repeat(300_000) },
				limitations: [],
			}),
		).rejects.toThrow("metadata_bytes");
	});

	it("drains accepted work before closing even when its request queue is full", async () => {
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path, maxPendingRequests: 1 });
		const ingest = store.ingest({
			batchId: "close",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: [occurrence("durable")],
		});
		await store.close();
		expect(await ingest).toMatchObject({ inserted: 1 });
		store = await DiagnosticEvidenceStore.open({ path });
		expect(await store.getCursor("s")).toBe("1");
	});

	it("leaves no cursor or rows after its worker dies while a transaction is waiting for a lock", async () => {
		const lock = new DatabaseSync(path);
		lock.exec("BEGIN IMMEDIATE");
		const rejected = expect(
			store.ingest({
				batchId: "blocked",
				source: "s",
				expectedCursor: null,
				cursor: "1",
				occurrences: [occurrence("a")],
			}),
		).rejects.toThrow(/worker_exited|database is locked/);
		await new Promise((resolve) => setTimeout(resolve, 30));
		await (store as unknown as { worker: Worker }).worker.terminate();
		await rejected;
		lock.exec("ROLLBACK");
		lock.close();
		store = await DiagnosticEvidenceStore.open({ path });
		expect(await store.getCursor("s")).toBeNull();
		expect((await store.stats()).occurrences).toBe(0);
	});

	it("rolls back the complete batch and cursor on conflicting occurrence identity", async () => {
		await store.ingest({
			batchId: "first",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: [occurrence("a", 1, "original")],
		});
		await expect(
			store.ingest({
				batchId: "bad",
				source: "s",
				expectedCursor: "1",
				cursor: "2",
				occurrences: [occurrence("b", 2), occurrence("a", 1, "changed")],
			}),
		).rejects.toThrow("occurrence_conflict");
		expect(await store.getCursor("s")).toBe("1");
		expect((await store.stats()).occurrences).toBe(1);
		await expect(
			store.ingest({ batchId: "cursor", source: "s", expectedCursor: "old", cursor: "2", occurrences: [] }),
		).rejects.toThrow("cursor_conflict");
		await expect(
			store.ingest({
				batchId: "first",
				source: "s",
				expectedCursor: null,
				cursor: "1",
				occurrences: [occurrence("a", 2, "original")],
			}),
		).rejects.toThrow("batch_conflict");
	});

	it("bounds timeline pages and retains stable ordering with equal or reordered timestamps", async () => {
		await store.ingest({
			batchId: "page",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: [occurrence("a", 3), occurrence("b", 1), occurrence("c", 1), occurrence("d", 2)],
		});
		const first = await store.readWindow({ startMs: 1, endMs: 3, limit: 2 });
		const second = await store.readWindow({ startMs: 1, endMs: 3, limit: 2, afterSequence: first.nextSequence });
		expect(first.occurrences.map((row) => row.id)).toEqual(["b", "c"]);
		expect(second.occurrences.map((row) => row.id)).toEqual(["d", "a"]);
		await expect(store.readWindow({ startMs: 0, endMs: 5, limit: 1001 })).rejects.toThrow("limit");
		await expect(
			store.ingest({
				batchId: "large",
				source: "s",
				expectedCursor: "1",
				cursor: "2",
				occurrences: [{ ...occurrence("large"), payload: new Uint8Array(1024 * 1024 + 1) }],
			}),
		).rejects.toThrow("batch_bytes");
	});

	it("publishes a live incident and reconciles pending export to ready artifact after restart", async () => {
		const incident = await store.openIncident({
			id: "incident",
			triggerTimeMs: 100,
			windowStartMs: 0,
			windowEndMs: 200,
			coverage: { journal: "available" },
			limitations: ["host unavailable"],
		});
		expect(incident.state).toBe("capturing");
		expect((await store.updateIncident("incident", { state: "published" })).state).toBe("published");
		await store.prepareOperation({
			id: "export",
			incidentId: "incident",
			kind: "export",
			artifact: { id: "artifact", path: "incident/journal.json", format: "journal-json" },
		});
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		expect((await store.unfinishedOperations({}))[0]).toMatchObject({
			id: "export",
			state: "pending",
			artifact: { path: "incident/journal.json" },
		});
		await expect(store.markOperationReady("export")).rejects.toThrow("artifact_stage_required");
		await store.reserveOperationBytes("export", 4096);
		await store.markOperationStaged("export", { bytes: 14, sha256: "a".repeat(64), allocatedBytes: 4096 });
		await selectUnique(store, "export");
		await store.markOperationReady("export", { bytes: 14, sha256: "a".repeat(64), allocatedBytes: 4096 });
		expect(await store.unfinishedOperations({})).toEqual([]);
		expect(await store.listArtifacts("incident")).toEqual([
			expect.objectContaining({ id: "artifact", bytes: 14, sha256: "a".repeat(64) }),
		]);
	});

	it.each(["export", "pin"] as const)(
		"requires durable staged identity before %s readiness and preserves it across reopen",
		async (kind) => {
			await store.openIncident({
				id: "i",
				triggerTimeMs: 1,
				windowStartMs: 0,
				windowEndMs: 2,
				coverage: {},
				limitations: [],
			});
			await store.prepareOperation({
				id: "staged",
				incidentId: "i",
				kind,
				artifact: { id: "a", path: "i/a.raw", format: "raw", bytes: 1, sha256: "a".repeat(64) },
			});
			await expect(
				store.markOperationReady("staged", { bytes: 1, sha256: "a".repeat(64), allocatedBytes: 4096 }),
			).rejects.toThrow("artifact_stage_required");
			const actual = { bytes: 14, sha256: "b".repeat(64), allocatedBytes: 4096 };
			await store.reserveOperationBytes("staged", 4096);
			const staged = await store.markOperationStaged("staged", actual);
			expect(staged).toMatchObject({ state: "pending", stagedAtMs: expect.any(Number), artifact: actual });
			expect(await store.markOperationStaged("staged", actual)).toEqual(staged);
			await expect(
				store.markOperationStaged("staged", { bytes: 15, sha256: "c".repeat(64), allocatedBytes: 4096 }),
			).rejects.toThrow("operation_staged_identity_conflict");
			await store.close();
			store = await DiagnosticEvidenceStore.open({ path });
			expect(await store.unfinishedOperations({})).toEqual([staged]);
			await expect(
				store.markOperationReady("staged", { bytes: 15, sha256: "c".repeat(64), allocatedBytes: 4096 }),
			).rejects.toThrow("operation_completion_conflict");
			await expect(store.markOperationReady("staged")).rejects.toThrow("artifact_selection_required");
			await selectUnique(store, "staged");
			const ready = await store.markOperationReady("staged");
			expect(ready).toMatchObject({ state: "ready", stagedAtMs: staged.stagedAtMs, artifact: actual });
			expect(await store.markOperationReady("staged", actual)).toEqual(ready);
			expect(await store.listArtifacts("i")).toEqual([expect.objectContaining(actual)]);
		},
	);

	it("reserves artifact paths and accounts completed bytes transactionally", async () => {
		await store.openIncident({
			id: "i",
			triggerTimeMs: 1,
			windowStartMs: 0,
			windowEndMs: 2,
			coverage: {},
			limitations: [],
		});
		await store.prepareOperation({
			id: "op",
			incidentId: "i",
			kind: "export",
			artifact: { id: "a", path: "i/a.raw", format: "raw" },
		});
		await expect(
			store.prepareOperation({
				id: "other",
				incidentId: "i",
				kind: "export",
				artifact: { id: "b", path: "i/a.raw", format: "raw" },
			}),
		).rejects.toThrow();
		expect(await store.stats()).toMatchObject({ artifactBytes: 0, pendingArtifactOperations: 1 });
		await store.reserveOperationBytes("op", 4096);
		await store.markOperationStaged("op", { bytes: 14, sha256: "a".repeat(64), allocatedBytes: 4096 });
		await selectUnique(store, "op");
		await store.markOperationReady("op", { bytes: 14, sha256: "a".repeat(64), allocatedBytes: 4096 });
		expect(await store.stats()).toMatchObject({ artifactBytes: 14, pendingArtifactOperations: 0 });
		await store.prepareOperation({
			id: "delete",
			incidentId: "i",
			kind: "delete",
			artifact: { id: "a", path: "i/a.raw", format: "raw" },
		});
		await store.markOperationReady("delete");
		expect(await store.stats()).toMatchObject({ artifactBytes: 0, pendingArtifactOperations: 0 });
	});

	it("tracks durable reservations and actual allocation through staging, restart, readiness and deletion", async () => {
		await store.openIncident({
			id: "i",
			triggerTimeMs: 1,
			windowStartMs: 0,
			windowEndMs: 2,
			coverage: {},
			limitations: [],
		});
		const operation = await store.prepareOperation({
			id: "op",
			incidentId: "i",
			kind: "export",
			artifact: { id: "a", path: "i/a.raw", format: "raw" },
		});
		expect(operation.reservationBytes).toBe(0);
		const actual = { bytes: 14, sha256: "a".repeat(64), allocatedBytes: 4096 };
		await expect(store.markOperationStaged("op", actual)).rejects.toThrow("artifact_reservation_required");
		await store.reserveOperationBytes("op", 8192);
		await expect(store.reserveOperationBytes("op", 4096)).rejects.toThrow("operation_reservation_decrease");
		expect(await store.stats()).toMatchObject({ reservedArtifactBytes: 8192, artifactAllocatedBytes: 0 });
		expect(await store.markOperationStaged("op", actual)).toMatchObject({ reservationBytes: 4096, artifact: actual });
		await expect(store.releaseOperationReservation("op")).rejects.toThrow("reservation_release_not_allowed");
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		expect(await store.stats()).toMatchObject({ reservedArtifactBytes: 4096, artifactAllocatedBytes: 0 });
		await selectUnique(store, "op");
		await store.markOperationReady("op");
		expect(await store.stats()).toMatchObject({
			reservedArtifactBytes: 0,
			artifactAllocatedBytes: 4096,
			artifactBytes: 14,
		});
		await store.prepareOperation({
			id: "delete",
			incidentId: "i",
			kind: "delete",
			artifact: { id: "a", path: "i/a.raw", format: "raw" },
		});
		await store.markOperationReady("delete");
		expect(await store.stats()).toMatchObject({
			reservedArtifactBytes: 0,
			artifactAllocatedBytes: 0,
			artifactBytes: 0,
		});
	});

	it("does not reserve speculative bytes for queued incidents and releases only unstaged reservations", async () => {
		await store.openIncident({
			id: "i",
			triggerTimeMs: 1,
			windowStartMs: 0,
			windowEndMs: 2,
			coverage: {},
			limitations: [],
		});
		for (let index = 0; index < 33; index++)
			await store.prepareOperation({
				id: String(index),
				incidentId: "i",
				kind: "pin",
				artifact: { id: String(index), path: `i/${index}.raw`, format: "raw" },
			});
		expect(await store.stats()).toMatchObject({ pendingArtifactOperations: 33, reservedArtifactBytes: 0 });
		await store.reserveOperationBytes("0", 4096);
		await store.releaseOperationReservation("0");
		expect(await store.stats()).toMatchObject({ reservedArtifactBytes: 0 });
		await store.reserveOperationBytes("0", 4096);
		expect((await store.unfinishedOperations({})).find((operation) => operation.id === "0")?.reservationBytes).toBe(
			4096,
		);
	});

	it("rejects a distinct exporter before it can overwrite a registered ready artifact", async () => {
		await store.openIncident({
			id: "i",
			triggerTimeMs: 1,
			windowStartMs: 0,
			windowEndMs: 2,
			coverage: {},
			limitations: [],
		});
		const original = {
			id: "original",
			incidentId: "i",
			kind: "export" as const,
			artifact: { id: "a", path: "i/a.raw", format: "raw" },
		};
		await store.prepareOperation(original);
		await store.reserveOperationBytes("original", 4096);
		await store.markOperationStaged("original", { bytes: 14, sha256: "a".repeat(64), allocatedBytes: 4096 });
		await selectUnique(store, "original");
		await store.markOperationReady("original", { bytes: 14, sha256: "a".repeat(64), allocatedBytes: 4096 });
		for (const kind of ["export", "pin"] as const)
			await expect(store.prepareOperation({ ...original, id: `different-${kind}`, kind })).rejects.toThrow(
				"artifact_already_registered",
			);
		expect(await store.prepareOperation(original)).toMatchObject({
			state: "ready",
			artifact: { bytes: 14, sha256: "a".repeat(64) },
		});
		expect(await store.listArtifacts("i")).toEqual([
			expect.objectContaining({ id: "a", bytes: 14, sha256: "a".repeat(64) }),
		]);
	});

	it("reports leading, interior and terminal sequence loss after history expires", async () => {
		const now = Date.now();
		await store.ingest({
			batchId: "gaps",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: [
				occurrence("old-1", now - 4 * DAY),
				occurrence("retained-2", now),
				occurrence("old-3", now - 4 * DAY),
				occurrence("retained-4", now),
				occurrence("old-5", now - 4 * DAY),
			],
		});
		await store.retain({ nowMs: now, limit: 100 });
		const first = await store.readOccurrences({ limit: 1 });
		expect(first).toMatchObject({ missingRanges: [{ firstSequence: 1, lastSequence: 1 }], throughSequence: 2 });
		const second = await store.readOccurrences({ afterSequence: 2 });
		expect(second).toMatchObject({
			missingRanges: [
				{ firstSequence: 3, lastSequence: 3 },
				{ firstSequence: 5, lastSequence: 5 },
			],
			throughSequence: 5,
		});
		const tail = await store.readOccurrences({ afterSequence: 4 });
		expect(tail).toMatchObject({
			occurrences: [],
			missingRanges: [{ firstSequence: 5, lastSequence: 5 }],
			throughSequence: 5,
		});
	});

	it("returns physical database capacity after accelerated retention without bulk vacuum", async () => {
		const now = Date.now();
		for (let index = 0; index < 8; index++)
			await store.ingest({
				batchId: `large-${index}`,
				source: "s",
				expectedCursor: index ? String(index - 1) : null,
				cursor: String(index),
				occurrences: [
					{ ...occurrence(`large-${index}`, now - 4 * DAY), payload: new Uint8Array(512 * 1024).fill(index) },
				],
			});
		await store.close();
		const peak = (await stat(path)).size;
		store = await DiagnosticEvidenceStore.open({ path });
		for (let step = 0; step < 16; step++) {
			const retained = await store.retain({ nowMs: now + 4 * DAY, limit: 100 });
			expect(retained.maintenance?.vacuumedPages).toBeLessThanOrEqual(256);
		}
		expect((await store.stats()).payloads).toBe(0);
		await store.close();
		const remaining = (await stat(path)).size;
		expect(remaining).toBeLessThan(peak / 2);
	});

	it.each([1, 2, 3, 4, 5, 6, 7])(
		"rejects prior candidate schema %s without migrating or changing its evidence",
		async (version) => {
			const legacyPath = join(directory, "prior-candidate.sqlite");
			const legacy = new DatabaseSync(legacyPath);
			legacy.exec(
				`PRAGMA user_version=${version}; CREATE TABLE preserved(value TEXT); INSERT INTO preserved VALUES('evidence')`,
			);
			legacy.close();
			await expect(DiagnosticEvidenceStore.open({ path: legacyPath })).rejects.toThrow(
				"unsupported_evidence_schema_capacity",
			);
			const inspect = new DatabaseSync(legacyPath, { readOnly: true });
			expect(inspect.prepare("PRAGMA user_version").get()!.user_version).toBe(version);
			expect(inspect.prepare("SELECT value FROM preserved").get()!.value).toBe("evidence");
			inspect.close();
		},
	);

	it("bounds incident metadata pages with an explicit limit and stable afterId continuation", async () => {
		for (let index = 0; index < 65; index++)
			await store.openIncident({
				id: String(index).padStart(3, "0"),
				triggerTimeMs: 1,
				windowStartMs: 0,
				windowEndMs: 2,
				coverage: {},
				limitations: [],
			});
		await expect(store.listIncidents({ limit: 65 })).rejects.toThrow("incident_list_limit");
		expect(await store.listIncidents()).toHaveLength(32);
		const boundary = await store.listIncidents({ limit: 64 });
		expect(boundary).toHaveLength(64);
		expect((await store.listIncidents({ limit: 64, afterId: boundary.at(-1)!.id })).map((item) => item.id)).toEqual([
			"064",
		]);
	});

	it("advances bounded retention batches past pinned history and resumes after restart", async () => {
		const now = Date.now();
		await store.ingest({
			batchId: "many",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: Array.from({ length: 5 }, (_, index) => occurrence(String(index), now - 4 * DAY + index)),
		});
		await store.openIncident({
			id: "pinned",
			triggerTimeMs: now - 4 * DAY,
			windowStartMs: now - 4 * DAY,
			windowEndMs: now - 4 * DAY + 1,
			coverage: {},
			limitations: [],
		});
		const first = await store.retain({ nowMs: now, limit: 2 });
		expect(first).toMatchObject({ occurrences: 0, more: true });
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		await store.retain({ nowMs: now, limit: 2 });
		await store.retain({ nowMs: now, limit: 2 });
		expect((await store.readOccurrences()).occurrences.map((row) => row.id)).toEqual(["0", "1"]);
	});

	it("uses three-day history and fourteen-day incident retention with pending deletion reconciliation", async () => {
		const now = Date.now();
		await store.ingest({
			batchId: "history",
			source: "s",
			expectedCursor: null,
			cursor: "1",
			occurrences: [
				occurrence("expired", now - 5 * DAY),
				occurrence("pinned", now - 4 * DAY),
				occurrence("recent", now - DAY),
			],
		});
		await store.openIncident({
			id: "i",
			triggerTimeMs: now - 4 * DAY,
			windowStartMs: now - 4 * DAY - 1,
			windowEndMs: now - 4 * DAY + 1,
			coverage: {},
			limitations: [],
		});
		await store.prepareOperation({
			id: "export",
			incidentId: "i",
			kind: "pin",
			artifact: { id: "a", path: "i/a.raw", format: "raw" },
		});
		await store.reserveOperationBytes("export", 4096);
		await store.markOperationStaged("export", { bytes: 1, sha256: "b".repeat(64), allocatedBytes: 4096 });
		await selectUnique(store, "export");
		await store.markOperationReady("export", { bytes: 1, sha256: "b".repeat(64), allocatedBytes: 4096 });
		await store.retain({ nowMs: now, limit: 10 });
		expect((await store.readWindow({ startMs: 0, endMs: now })).occurrences.map((row) => row.id)).toEqual([
			"pinned",
			"recent",
		]);
		await store.retain({ nowMs: now + 11 * DAY, limit: 10 });
		const deletions = await store.unfinishedOperations({});
		expect(deletions).toEqual([
			expect.objectContaining({ kind: "delete", artifact: expect.objectContaining({ path: "i/a.raw" }) }),
		]);
		expect(await store.getIncident("i")).toBeDefined();
		await store.markOperationReady(deletions[0].id);
		await store.retain({ nowMs: now + 11 * DAY, limit: 10 });
		expect(await store.getIncident("i")).toBeUndefined();
		expect((await store.stats()).occurrences).toBe(0);
	});

	it("rejects unowned artifact paths and preserves pending operations beyond retention", async () => {
		await store.openIncident({
			id: "i",
			triggerTimeMs: 1,
			windowStartMs: 0,
			windowEndMs: 2,
			coverage: {},
			limitations: [],
		});
		for (const path of ["/var/log/journal", "../history", "a/../../history", "", "C:\\history", "."]) {
			await expect(
				store.prepareOperation({
					id: "bad",
					incidentId: "i",
					kind: "export",
					artifact: { id: "a", path, format: "raw" },
				}),
			).rejects.toThrow("artifact_path");
		}
		await store.prepareOperation({
			id: "pending",
			incidentId: "i",
			kind: "export",
			artifact: { id: "a", path: "i/a.raw", format: "raw" },
		});
		await store.retain({ nowMs: 30 * DAY, limit: 10 });
		expect(await store.unfinishedOperations({})).toHaveLength(1);
		expect(await store.getIncident("i")).toBeDefined();
	});
});
