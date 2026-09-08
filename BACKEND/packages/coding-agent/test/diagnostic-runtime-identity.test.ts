import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, expect, it, vi } from "vitest";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";
import { EVIDENCE_RUNTIME_ROLE_LIMIT } from "../src/modes/daemon/diagnostic-evidence-store-protocol.js";

const DAY = 86_400_000;
const provider = { identifier: "runtime-probe", clockTicksPerSecond: 100 };
const roots: string[] = [];
const stores = new Set<DiagnosticEvidenceStore>();
afterEach(async () => {
	for (const store of stores) await store.close();
	stores.clear();
	for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});
const anchor = {
	schema: "prime-agent.diagnostic.v1",
	type: "supervisor_started",
	producerId: "supervisor-instance",
	producerPid: 12,
	producerStartId: "12345",
	producerPidNamespace: "pid:[4026532290]",
	producerBoottimeOffsetNs: "0",
};
const exit = {
	event: "process_exit",
	group_dead: 1,
	raw_exit_code: 9,
	init_pid: 9912,
	init_tid: 9912,
	subject_pid: 12,
	pidns_inode: 4026532290,
	start_boottime_ns: "123450000000",
	process_start_boottime_ns: "123450000000",
	time_ns: "223450000000",
};
function raw(id: string, event: Record<string, unknown>, at = Date.now(), native = false, bootId = "boot") {
	return Buffer.from(
		JSON.stringify({
			__CURSOR: id,
			__REALTIME_TIMESTAMP: String(BigInt(at) * 1000n),
			_BOOT_ID: bootId,
			SYSLOG_IDENTIFIER: native ? provider.identifier : "application",
			_UID: native ? "0" : "1000",
			_EXE: native ? "/usr/bin/bpftrace" : "/verified/node",
			MESSAGE: JSON.stringify(event),
		}),
	);
}
async function setup() {
	const root = await mkdtemp(join(tmpdir(), "runtime-role-test-"));
	roots.push(root);
	const path = join(root, "evidence.sqlite");
	const store = await DiagnosticEvidenceStore.open({ path });
	stores.add(store);
	return { store, path, pipeline: new DiagnosticEvidencePipeline(store, provider) };
}
async function occurrenceAt(store: DiagnosticEvidenceStore, at: number) {
	return (await store.readWindow({ startMs: at, endMs: at })).occurrences.find(
		(entry) => entry.kind === "journal.json",
	)!;
}
function reference(occurrence: { source: string; id: string }) {
	return { source: occurrence.source, occurrenceId: occurrence.id };
}

it.each([
	["supervisor", anchor],
	[
		"worker",
		{
			...anchor,
			type: "worker_process_spawned",
			workerId: "worker",
			workerPid: 12,
			workerProcessStartId: "proc:12345",
		},
	],
	[
		"kernel",
		{
			...anchor,
			type: "kernel_process_started",
			kernelInstanceId: "kernel",
			kernelPid: 12,
			kernelProcessStartId: "proc:12345",
			observerPidNamespace: anchor.producerPidNamespace,
			observerBoottimeOffsetNs: "0",
		},
	],
	[
		"forkserver",
		{
			...anchor,
			type: "forkserver_lifecycle",
			phase: "peer_authenticated",
			forkserverInstanceId: "forkserver",
			forkserverPid: 12,
			forkserverProcessStartId: "proc:12345",
			observerPidNamespace: anchor.producerPidNamespace,
			observerBoottimeOffsetNs: "0",
		},
	],
])("publishes only the evidenced %s runtime and retains its exact proof", async (role, event) => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	await pipeline.ingestJournalBatch("journal", [
		raw("anchor", event as Record<string, unknown>, at),
		raw("exit", exit, at + 1, true),
	]);
	expect(await pipeline.publishPending()).toBe(1);
	const [incident] = await store.listIncidents();
	expect(incident.coverage.runtimeRole).toMatchObject({
		role,
		pid: 12,
		processStartTicks: "12345",
		exit: { initPid: 9912, processStartBoottimeNs: exit.process_start_boottime_ns },
	});
	const proof = (incident.coverage.runtimeRole as { proof: { source: string; occurrenceId: string } }).proof;
	expect(Buffer.from((await store.getOccurrence(proof.source, proof.occurrenceId))!.payload)).toEqual(
		raw("anchor", event as Record<string, unknown>, at),
	);
	expect(await pipeline.publishPending()).toBe(0);
});

it("keeps ordinary nonzero command exits raw without generating incidents or causal gaps", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	const records = [
		raw("command1", { ...exit, raw_exit_code: 256 }, at, true),
		raw("command2", { ...exit, raw_exit_code: 512 }, at + 1, true),
	];
	await pipeline.ingestJournalBatch("journal", records);
	expect(await pipeline.publishPending()).toBe(0);
	expect(await store.listIncidents()).toEqual([]);
	const rows = (await store.readWindow({ startMs: at, endMs: at + 1 })).occurrences;
	expect(rows.filter((entry) => entry.kind === "runtime.scope")).toHaveLength(1);
	expect(rows.filter((entry) => entry.kind === "diagnostic.gap")).toHaveLength(0);
	expect(rows.filter((entry) => entry.kind === "journal.json").map((entry) => Buffer.from(entry.payload))).toEqual(
		records,
	);
});

it("matches namespace, boot, generation and exact leader identity for a nonleader final exit", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	await pipeline.ingestJournalBatch("journal", [
		raw("anchor", anchor, at),
		raw("namespace", { ...exit, pidns_inode: 4026532999 }, at + 1, true),
		raw(
			"generation",
			{ ...exit, start_boottime_ns: "123460000000", process_start_boottime_ns: "123460000000" },
			at + 2,
			true,
		),
		raw("boot", exit, at + 3, true, "other-boot"),
		raw("actual", { ...exit, init_tid: 9913, start_boottime_ns: "123455000000" }, at + 4, true),
	]);
	expect(await pipeline.publishPending()).toBe(1);
	expect((await store.listIncidents())[0].coverage.runtimeRole).toMatchObject({
		exit: { initPid: 9912, processStartBoottimeNs: "123450000000" },
	});
});

it("reports invalid and conflicting role anchors without assigning a role to the exit", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	await pipeline.ingestJournalBatch("journal", [
		raw("badclock", { ...anchor, producerBoottimeOffsetNs: "1" }, at),
		raw("anchor", anchor, at + 1),
		raw("conflict", { ...anchor, producerId: "another-generation" }, at + 2),
		raw("exit", exit, at + 3, true),
	]);
	expect(await pipeline.publishPending()).toBe(0);
	const reasons = (await store.readWindow({ startMs: at, endMs: at + 3 })).occurrences
		.filter((row) => row.kind === "diagnostic.gap")
		.map((row) => JSON.parse(Buffer.from(row.payload).toString()).reason);
	expect(reasons).toContain("runtime_role_invalid_anchor");
	expect(reasons).toContain("runtime_role_conflict");
});

it("keeps active proof beyond rolling history and restart, then pins it until its incident expires", async () => {
	let { store, path, pipeline } = await setup();
	const at = Date.now();
	await pipeline.ingestJournal("journal", raw("anchor", anchor, at - 4 * DAY));
	await pipeline.publishPending();
	const proof = reference(await occurrenceAt(store, at - 4 * DAY));
	await store.retain({ nowMs: at });
	expect(await store.getOccurrence(proof.source, proof.occurrenceId)).toBeDefined();
	await store.close();
	stores.delete(store);
	store = await DiagnosticEvidenceStore.open({ path });
	stores.add(store);
	pipeline = new DiagnosticEvidencePipeline(store, provider);
	await pipeline.ingestJournal("journal", raw("exit", exit, at, true));
	const exitProof = reference(await occurrenceAt(store, at));
	const result = await store.observeRuntimeExit(exitProof, provider);
	expect(result.status).toBe("matched");
	if (result.status !== "matched") throw new Error("missing runtime");
	expect(await store.observeRuntimeExit(exitProof, provider)).toEqual(result);
	await store.openIncident({
		id: "retention",
		triggerTimeMs: at,
		windowStartMs: at - 1000,
		windowEndMs: at + 1000,
		coverage: { runtimeRole: result.runtimeRole },
		limitations: [],
	});
	await store.retain({ nowMs: at + 4 * DAY });
	expect(await store.getOccurrence(proof.source, proof.occurrenceId)).toBeDefined();
	for (let i = 0; i < 8; i++) await store.retain({ nowMs: at + 15 * DAY });
	expect(await store.getIncident("retention")).toBeUndefined();
	expect(await store.getOccurrence(proof.source, proof.occurrenceId)).toBeUndefined();
});

it("closes a registered successful exit without creating an incident and prunes it after history", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	await pipeline.ingestJournalBatch("journal", [
		raw("anchor", anchor, at),
		raw("normal", { ...exit, raw_exit_code: 0 }, at + 1, true),
	]);
	expect(await pipeline.publishPending()).toBe(0);
	for (let i = 0; i < 8; i++) await store.retain({ nowMs: at + 4 * DAY });
	expect((await store.readWindow({ startMs: at, endMs: at + 1 })).occurrences).toHaveLength(0);
});

it("replays a closed runtime exit after a crash before incident publication", async () => {
	let { store, pipeline, path } = await setup();
	const at = Date.now();
	await pipeline.ingestJournalBatch("journal", [raw("anchor", anchor, at), raw("exit", exit, at + 1, true)]);
	vi.spyOn(store, "openIncident").mockRejectedValueOnce(new Error("simulated crash after role closure"));
	await expect(pipeline.publishPending()).rejects.toThrow("simulated crash");
	expect(await store.listIncidents()).toHaveLength(0);
	await store.close();
	stores.delete(store);
	store = await DiagnosticEvidenceStore.open({ path });
	stores.add(store);
	pipeline = new DiagnosticEvidencePipeline(store, provider);
	expect(await pipeline.publishPending()).toBe(1);
	expect(await pipeline.publishPending()).toBe(0);
	expect(await store.listIncidents()).toHaveLength(1);
});

it("refuses conflicting exact native generations even when their proc ticks collide", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	await pipeline.ingestJournalBatch("journal", [raw("anchor", anchor, at), raw("exit", exit, at + 1, true)]);
	expect(await pipeline.publishPending()).toBe(1);
	await pipeline.ingestJournal(
		"journal",
		raw(
			"conflicting-exit",
			{ ...exit, start_boottime_ns: "123450000001", process_start_boottime_ns: "123450000001" },
			at + 2,
			true,
		),
	);
	expect(await pipeline.publishPending()).toBe(0);
	expect(await store.listIncidents()).toHaveLength(1);
	const conflict = (await store.readWindow({ startMs: at + 2, endMs: at + 2 })).occurrences.find(
		(row) => row.kind === "diagnostic.gap",
	);
	expect(JSON.parse(Buffer.from(conflict!.payload).toString()).reason).toBe("runtime_role_conflict");
});

it("withholds role matching for incomplete or impossible final-thread identities", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	await pipeline.ingestJournalBatch("journal", [
		raw("anchor", anchor, at),
		raw("missing", { ...exit, process_start_boottime_ns: undefined }, at + 1, true),
		raw("future-start", { ...exit, process_start_boottime_ns: "323450000000" }, at + 2, true),
		raw("leader-conflict", { ...exit, process_start_boottime_ns: "123440000000" }, at + 3, true),
	]);
	expect(await pipeline.publishPending()).toBe(0);
	expect(await store.listIncidents()).toHaveLength(0);
	expect(
		(await store.readWindow({ startMs: at, endMs: at + 3 })).occurrences.some((row) => row.kind === "diagnostic.gap"),
	).toBe(true);
});

it("retains the missing-anchor limitation when the anchor arrives after the detector passed the exit", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	await pipeline.ingestJournal("journal", raw("early-exit", exit, at, true));
	expect(await pipeline.publishPending()).toBe(0);
	await pipeline.ingestJournal("journal", raw("late-anchor", anchor, at - 1));
	expect(await pipeline.publishPending()).toBe(0);
	expect(await store.listIncidents()).toHaveLength(0);
	expect(
		(await store.readWindow({ startMs: at, endMs: at })).occurrences.some((row) => row.kind === "runtime.scope"),
	).toBe(true);
});

it("preserves separate causal gaps in separate windows and replays each without duplication", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	const invalid = { ...anchor, producerBoottimeOffsetNs: "777" };
	await pipeline.ingestJournalBatch("journal", [raw("invalid1", invalid, at), raw("invalid2", invalid, at + DAY)]);
	await pipeline.publishPending();
	await pipeline.publishPending();
	for (const time of [at, at + DAY]) {
		const gaps = (await store.readWindow({ startMs: time, endMs: time })).occurrences.filter(
			(row) => row.kind === "diagnostic.gap",
		);
		expect(gaps).toHaveLength(1);
		expect(JSON.parse(Buffer.from(gaps[0].payload).toString()).reason).toBe("runtime_role_invalid_anchor");
	}
});

it("retires earlier boots in bounded batches without inventing exits, including late historical anchors", async () => {
	const { store, pipeline, path } = await setup();
	const at = Date.now();
	const currentBoot = "f".repeat(32);
	await pipeline.ingestJournalBatch("journal", [
		raw("old1", anchor, at - 4 * DAY),
		raw("old2", { ...anchor, producerPid: 13 }, at - 4 * DAY + 1),
	]);
	await pipeline.publishPending();
	expect(await store.recordRuntimeBoot({ bootId: currentBoot, observedAtMs: at, limit: 1 })).toEqual({
		retired: 1,
		more: true,
	});
	expect(await store.recordRuntimeBoot({ bootId: currentBoot, observedAtMs: at + 100, limit: 1 })).toEqual({
		retired: 1,
		more: true,
	});
	expect(await store.recordRuntimeBoot({ bootId: currentBoot, observedAtMs: at + 200, limit: 1 })).toEqual({
		retired: 0,
		more: false,
	});
	await pipeline.ingestJournalBatch("journal", [
		raw("late-old", { ...anchor, producerPid: 14 }, at - 1),
		raw("current", { ...anchor, producerPid: 15 }, at + 1, false, currentBoot),
	]);
	await pipeline.publishPending();
	const inspect = new DatabaseSync(path, { readOnly: true });
	try {
		const retired = inspect
			.prepare(
				"SELECT closed_at_ms,close_reason,exit_sequence,native_pid,native_start FROM runtime_roles WHERE boot_id!='ffffffffffffffffffffffffffffffff'",
			)
			.all();
		expect(retired).toHaveLength(3);
		for (const entry of retired)
			expect(entry).toMatchObject({
				closed_at_ms: at,
				close_reason: "boot_changed",
				exit_sequence: null,
				native_pid: null,
				native_start: null,
			});
	} finally {
		inspect.close();
	}
	expect(await store.listIncidents()).toHaveLength(0);
	for (let i = 0; i < 8; i++) await store.retain({ nowMs: at + 4 * DAY });
	const remaining = (await store.readWindow({ startMs: 0, endMs: at + 4 * DAY })).occurrences.filter(
		(row) => row.kind === "journal.json",
	);
	expect(remaining).toHaveLength(1);
	expect(JSON.parse(Buffer.from(remaining[0].payload).toString())._BOOT_ID).toBe(currentBoot);
});

it("caps sparse claims without evicting existing proof and persists a capacity gap", async () => {
	const { store, pipeline } = await setup();
	const at = Date.now();
	for (let base = 0; base <= EVIDENCE_RUNTIME_ROLE_LIMIT; base += 128) {
		const count = Math.min(128, EVIDENCE_RUNTIME_ROLE_LIMIT + 1 - base);
		await pipeline.ingestJournalBatch(
			"journal",
			Array.from({ length: count }, (_, i) =>
				raw(
					`anchor-${base + i}`,
					{ ...anchor, producerPid: 100 + base + i, producerId: `role-${base + i}` },
					at + base + i,
				),
			),
		);
		await pipeline.publishPending();
	}
	const page = await store.readWindow({
		startMs: at + EVIDENCE_RUNTIME_ROLE_LIMIT,
		endMs: at + EVIDENCE_RUNTIME_ROLE_LIMIT,
	});
	expect(
		page.occurrences.some(
			(row) =>
				row.kind === "diagnostic.gap" &&
				JSON.parse(Buffer.from(row.payload).toString()).reason === "runtime_role_capacity",
		),
	).toBe(true);
	await pipeline.ingestJournal(
		"journal",
		raw("first-exit", { ...exit, subject_pid: 100 }, at + EVIDENCE_RUNTIME_ROLE_LIMIT + 1, true),
	);
	expect(await pipeline.publishPending()).toBe(1);
}, 30_000);
