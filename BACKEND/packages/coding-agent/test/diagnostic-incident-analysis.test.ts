import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";
import { analyzeStoredIncident, INCIDENT_ANALYSIS_SOURCE } from "../src/modes/daemon/diagnostic-incident-analysis.js";

const roots: string[] = [];
const stores: DiagnosticEvidenceStore[] = [];
afterEach(async () => {
	for (const store of stores.splice(0)) await store.close();
	for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});
const provider = { identifier: "test-causal-provider", clockTicksPerSecond: 100 };
const base = {
	init_pid: 3130,
	init_tid: 3130,
	start_boottime_ns: "28478275484975",
};
const native = [
	{
		...base,
		event: "task_identity",
		time_ns: "28478275519564",
		subject_pid: 12,
		subject_tid: 12,
		pidns_inode: 4026532290,
		process_start_boottime_ns: base.start_boottime_ns,
	},
	{
		event: "signal_generate",
		time_ns: "28478276103119",
		context_init_pid: 3130,
		context_init_tid: 3130,
		context_start_boottime_ns: base.start_boottime_ns,
		target_init_pid: 3130,
		target_init_tid: 3130,
		target_start_boottime_ns: base.start_boottime_ns,
		signal: 11,
		code: 1,
		group: 0,
		result: 0,
		call_time_ns: "0",
	},
	{ ...base, event: "signal_deliver", time_ns: "28478276142549", signal: 11, code: 1 },
	{
		...base,
		event: "process_exit",
		time_ns: "28478276174058",
		raw_exit_code: 11,
		group_dead: 1,
		subject_pid: 12,
		pidns_inode: 4026532290,
		process_start_boottime_ns: base.start_boottime_ns,
	},
];
const trigger = {
	schema: "prime-agent.diagnostic.v1",
	type: "kernel_unexpected_exit",
	producerId: "producer",
	producerPid: 2,
	producerStartId: "2847633",
	producerPidNamespace: "pid:[4026532290]",
	producerBoottimeOffsetNs: "0",
	ownerPid: 2,
	ownerProcessStartId: "proc:2847633",
	kernelInstanceId: "original-kernel",
	kernelGeneration: 1,
	kernelPid: 12,
	kernelProcessStartId: "proc:2847827",
	monotonicNs: "28478276190000",
};
function row(cursor: string, at: number, value: unknown, trace = false, fields: Record<string, unknown> = {}) {
	return Buffer.from(
		JSON.stringify({
			__CURSOR: cursor,
			__REALTIME_TIMESTAMP: String(BigInt(at) * 1000n),
			_BOOT_ID: "captured-boot",
			_UID: trace ? "0" : "1000",
			_EXE: trace ? "/usr/bin/bpftrace" : "/verified/node",
			SYSLOG_IDENTIFIER: trace ? provider.identifier : "test-application",
			MESSAGE: typeof value === "string" ? value : JSON.stringify(value),
			...fields,
		}),
	);
}
async function setup(
	options: {
		traceFields?: Record<string, unknown>;
		event?: Record<string, unknown>;
		extra?: Buffer[];
		prefixRows?: number;
		hybridApplicationTrace?: boolean;
		nativeOnly?: boolean;
		nativeRows?: typeof native;
	} = {},
) {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-analysis-"));
	roots.push(root);
	const store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
	stores.push(store);
	const pipeline = new DiagnosticEvidencePipeline(store, options.nativeOnly ? provider : undefined);
	const now = Date.now();
	const rows = [
		...(options.nativeOnly
			? [
					row("runtime-role", now - 2000, {
						schema: "prime-agent.diagnostic.v1",
						type: "supervisor_started",
						producerId: "observed-runtime",
						producerPid: 12,
						producerStartId: "2847827",
						producerPidNamespace: "pid:[4026532290]",
						producerBoottimeOffsetNs: "0",
					}),
				]
			: []),
		...Array.from({ length: options.prefixRows ?? 0 }, (_, i) =>
			row(`ordinary${i}`, now - 1000, "ordinary product log"),
		),
		...(options.nativeRows ?? native).map((event, i) =>
			row(
				`probe${i}`,
				now + i,
				options.hybridApplicationTrace ? { ...event, schema: "prime-agent.diagnostic.v1" } : event,
				true,
				options.traceFields,
			),
		),
		row("ordinary-last", now + 5, "ordinary product log"),
		...(options.extra ?? []),
		...(options.nativeOnly ? [] : [row("trigger", now + 6, options.event ?? trigger)]),
	];
	for (let i = 0; i < rows.length; i += 256) await pipeline.ingestJournalBatch("journal:test", rows.slice(i, i + 256));
	for (let i = 0; i < Math.ceil(rows.length / 128); i++) await pipeline.publishPending();
	const [incident] = await store.listIncidents();
	expect(incident).toBeDefined();
	return { store, incident: incident! };
}

it("classifies stored native events with verified provider and producer clock identities", async () => {
	const { store, incident } = await setup();
	const result = await analyzeStoredIncident(store, incident, provider);
	expect(result.classification).toMatchObject({ status: "process_exited", cause: "native_fault" });
	expect(result.traceRecords).toBe(4);
	const captured = await store.getOccurrence(INCIDENT_ANALYSIS_SOURCE, result.analysisOccurrenceId);
	expect(captured?.kind).toBe("incident.analysis");
	expect(JSON.parse(Buffer.from(captured!.payload).toString()).classification.facts.length).toBeGreaterThan(0);
	for (const id of result.classification.supportingOccurrenceIds)
		expect(await store.getOccurrence("journal:test", id)).toBeDefined();
});

it("publishes and explains a native process death without any application failure message", async () => {
	const { store, incident } = await setup({ nativeOnly: true });
	expect(incident.coverage.trigger).toMatchObject({ type: "native_process_exit" });
	expect(incident.state).toBe("published");
	const result = await analyzeStoredIncident(store, incident, provider);
	expect(result.classification).toMatchObject({ status: "process_exited", cause: "native_fault" });
	expect(result.classification.missingEvidence).not.toContain("original_observer_identity_unavailable");
});

it.each([true, false])(
	"uses direct leader generation for a nonleader group-dead exit (earlier identity=%s)",
	async (identityPresent) => {
		const nativeRows = native.map((event) =>
			event.event === "process_exit" ? { ...event, init_tid: 3131, start_boottime_ns: "28478275500000" } : event,
		);
		if (identityPresent)
			nativeRows.unshift({
				...native[0],
				event: "task_identity",
				init_tid: 3131,
				start_boottime_ns: "28478275500000",
				time_ns: "28478275550000",
				process_start_boottime_ns: base.start_boottime_ns,
			} as (typeof native)[number]);
		const { store, incident } = await setup({ nativeOnly: true, nativeRows });
		const result = await analyzeStoredIncident(store, incident, provider);
		expect(result.classification.cause).toBe("native_fault");
		expect(result.classification.missingEvidence).not.toContain("native_target_generation_unavailable");
	},
);

it("reuses an immutable report without ingesting prior reports or artifact metadata as evidence", async () => {
	const { store, incident } = await setup();
	const first = await analyzeStoredIncident(store, incident, provider);
	await store.ingest({
		batchId: "metadata",
		source: "internal:test-metadata",
		expectedCursor: null,
		cursor: "1",
		occurrences: [
			{ id: "receipt", kind: "atop.receipt", wallTimeMs: incident.triggerTimeMs, payload: Buffer.alloc(900_000) },
		],
	});
	for (let i = 0; i < 3; i++) expect(await analyzeStoredIncident(store, incident, provider)).toEqual(first);
	expect(
		(await store.readWindow({ startMs: incident.windowStartMs, endMs: incident.windowEndMs })).occurrences.filter(
			(row) => row.kind === "incident.analysis",
		),
	).toHaveLength(1);
});

it.each([{ _UID: "1000" }, { _EXE: "/usr/bin/printf" }])(
	"withholds attribution for a provider with unverified trusted fields %j",
	async (traceFields) => {
		const { store, incident } = await setup({ traceFields });
		const result = await analyzeStoredIncident(store, incident, provider);
		expect(result.classification.cause).toBe("unresolved");
		expect(result.classification.missingEvidence).toContain("causal_provider_identity_unverified");
	},
);

it("rejects native-shaped application messages instead of bypassing provider identity checks", async () => {
	const { store, incident } = await setup({
		hybridApplicationTrace: true,
		traceFields: {
			_UID: "1000",
			_EXE: "/verified/node",
			SYSLOG_IDENTIFIER: "ordinary-application",
		},
	});
	const result = await analyzeStoredIncident(store, incident, provider);
	expect(result.traceRecords).toBe(0);
	expect(result.classification.cause).toBe("unresolved");
	expect(result.classification.missingEvidence).toContain("application_causal_shape_invalid");
});

it("does not assume the recorder and producer share a time namespace", async () => {
	const { producerBoottimeOffsetNs: _offset, ...event } = trigger;
	const { store, incident } = await setup({ event });
	const result = await analyzeStoredIncident(store, incident, provider);
	expect(result.classification.cause).toBe("unresolved");
	expect(result.classification.missingEvidence).toContain("process_clock_identity_unavailable");
});

it("uses the original observer identity after forwarding through a different producer namespace", async () => {
	const { store, incident } = await setup({
		event: {
			...trigger,
			ownerPid: 88,
			ownerProcessStartId: "proc:12345",
			producerPidNamespace: "pid:[999999]",
			producerBoottimeOffsetNs: "777777",
			observerPid: 88,
			observerProcessStartId: "12345",
			observerPidNamespace: "pid:[4026532290]",
			observerBoottimeOffsetNs: "0",
		},
	});
	expect((await analyzeStoredIncident(store, incident, provider)).classification.cause).toBe("native_fault");
});

it("does not substitute a forwarding supervisor identity for a missing source observer", async () => {
	const { store, incident } = await setup({ event: { ...trigger, ownerPid: 88, ownerProcessStartId: "proc:12345" } });
	const result = await analyzeStoredIncident(store, incident, provider);
	expect(result.classification.cause).toBe("unresolved");
	expect(result.classification.missingEvidence).toContain("original_observer_identity_unavailable");
});

it("preserves unparsed native-provider output as an attribution gap", async () => {
	const { store, incident } = await setup({ extra: [row("lost", Date.now(), "Lost 17 events", true)] });
	const result = await analyzeStoredIncident(store, incident, provider);
	expect(result.classification).toMatchObject({ status: "process_exited", cause: "unresolved" });
	expect(result.classification.missingEvidence).toContain("causal_provider_unparsed_output");
});

it("exposes a bounded historical scan without turning omitted events into a cause", async () => {
	const { store, incident } = await setup({ prefixRows: 4096 });
	const result = await analyzeStoredIncident(store, incident, provider);
	expect(result.scannedRows).toBe(4096);
	expect(result.truncated).toBe(true);
	expect(result.classification.cause).toBe("unresolved");
	expect(result.classification.missingEvidence).toContain("stored_analysis_scan_limit");
});

it("rejects oversized target identities and keeps the stored analysis below its hard cap", async () => {
	const { store, incident } = await setup({ event: { ...trigger, kernelInstanceId: "x".repeat(300 * 1024) } });
	const result = await analyzeStoredIncident(store, incident, provider);
	expect(result.classification.cause).toBe("unresolved");
	expect(result.classification.missingEvidence).toContain("stored_target_kernel_identity_unavailable");
	const occurrence = await store.getOccurrence(INCIDENT_ANALYSIS_SOURCE, result.analysisOccurrenceId);
	expect(occurrence!.payload.byteLength).toBeLessThanOrEqual(256 * 1024);
});
