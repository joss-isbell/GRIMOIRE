import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";

const directories: string[] = [];
afterEach(async () => {
	await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function journal(cursor: string, time: number, event: Record<string, unknown>): Buffer {
	return Buffer.from(
		JSON.stringify({
			__CURSOR: cursor,
			__REALTIME_TIMESTAMP: String(time * 1000),
			__MONOTONIC_TIMESTAMP: "1234567",
			_BOOT_ID: "boot",
			_PID: "17",
			MESSAGE: JSON.stringify({ schema: "prime-agent.diagnostic.v1", ...event }),
		}),
	);
}

it("accepts only a configured trusted native group exit and preserves its original record", async () => {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-pipeline-native-"));
	directories.push(root);
	const store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
	try {
		const pipeline = new DiagnosticEvidencePipeline(store, {
			identifier: "verified-probe",
			clockTicksPerSecond: 100,
		});
		const valid = {
			event: "process_exit",
			init_pid: 12,
			init_tid: 12,
			subject_pid: 12,
			pidns_inode: 1234,
			start_boottime_ns: "1230000000",
			process_start_boottime_ns: "1230000000",
			time_ns: "4560000000",
			group_dead: 1,
			raw_exit_code: 9,
		};
		const raws = [
			{
				event: {
					schema: "prime-agent.diagnostic.v1",
					type: "supervisor_started",
					producerId: "actual-owner",
					producerPid: 12,
					producerStartId: "123",
					producerPidNamespace: "pid:[1234]",
					producerBoottimeOffsetNs: "0",
				},
				fields: { _UID: "1000", _EXE: "/verified/node", SYSLOG_IDENTIFIER: "application" },
			},
			{ event: valid, fields: { _UID: "1000" } },
			{ event: valid, fields: { _EXE: "/usr/bin/printf" } },
			{ event: valid, fields: { SYSLOG_IDENTIFIER: "unconfigured" } },
			{ event: { ...valid, group_dead: 0 }, fields: {} },
			{ event: { ...valid, raw_exit_code: 0 }, fields: {} },
			{ event: { ...valid, raw_exit_code: 0.5 }, fields: {} },
			{ event: { schema: "prime-agent.diagnostic.v1", type: "native_process_exit" }, fields: { _UID: "1000" } },
			{ event: valid, fields: {} },
		].map(({ event, fields }, index) =>
			Buffer.from(
				JSON.stringify({
					__CURSOR: String(index),
					__REALTIME_TIMESTAMP: String(Date.now() * 1000),
					_BOOT_ID: "boot",
					SYSLOG_IDENTIFIER: "verified-probe",
					_UID: "0",
					_EXE: "/usr/bin/bpftrace",
					...fields,
					MESSAGE: JSON.stringify(event),
				}),
			),
		);
		await pipeline.ingestJournalBatch("journal:native", raws);
		expect(await pipeline.publishPending()).toBe(1);
		const [incident] = await store.listIncidents();
		expect(incident.coverage.trigger).toMatchObject({ type: "native_process_exit" });
		expect(
			(await store.readWindow({ startMs: incident.windowStartMs, endMs: incident.windowEndMs })).occurrences
				.filter((row) => row.kind === "journal.json")
				.map((row) => Buffer.from(row.payload)),
		).toEqual(raws);
	} finally {
		await store.close();
	}
});

it("publishes a durable incident while its producer remains alive, without inventing a cause", async () => {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-pipeline-"));
	directories.push(root);
	const store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
	const producer = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
	try {
		const pipeline = new DiagnosticEvidencePipeline(store);
		const time = Date.now();
		const raw = journal("cursor-1", time, {
			type: "kernel_channel_fault",
			channel: "shell",
			kernelPid: producer.pid,
			kernelInstanceId: "original",
			kernelGeneration: 1,
			kernelProcessStartId: "100",
			observerPid: process.pid,
			observerProcessStartId: "200",
			observerPidNamespace: "pid:[123]",
			observerBoottimeOffsetNs: "0",
			monotonicNs: "1000",
			requestMsgId: "request-1",
			reason: "receive_failed",
		});
		const result = await pipeline.ingestJournal("application-journal", raw);
		expect(result).toEqual({ journalObserved: true, durablyStored: true, cursor: "cursor-1" });
		expect(await store.listIncidents()).toEqual([]);
		expect(await pipeline.publishPending()).toBe(1);
		const [incident] = await store.listIncidents();
		expect(incident).toMatchObject({
			state: "published",
			triggerTimeMs: time,
			windowStartMs: time - 30 * 60_000,
			windowEndMs: time + 15 * 60_000,
			coverage: { cause: { status: "unresolved" }, durableTriggerObserved: true, exportComplete: false },
		});
		expect(incident?.limitations).toContain("The post-trigger window is still being captured.");
		expect((await store.unfinishedOperations()).map((entry) => entry.artifact.format)).toEqual(["journal.export"]);
		expect(producer.exitCode).toBeNull();
		process.kill(producer.pid!, 0);
		expect(await pipeline.publishPending()).toBe(0);
		const page = await store.readWindow({ startMs: time, endMs: time });
		expect(Buffer.from(page.occurrences[0]!.payload)).toEqual(raw);
	} finally {
		producer.kill("SIGTERM");
		await new Promise<void>((resolve) => producer.once("close", () => resolve()));
		await store.close();
	}
});

it("recovers a committed trigger that was never published and retains opaque journal fields exactly", async () => {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-pipeline-restart-"));
	directories.push(root);
	const path = join(root, "evidence.sqlite");
	let store = await DiagnosticEvidenceStore.open({ path });
	try {
		const time = Date.now();
		await new DiagnosticEvidencePipeline(store).ingestJournal(
			"application-journal",
			journal("cursor-1", time, {
				type: "kernel_unexpected_exit",
				kernelInstanceId: "original",
				reason: "forkserver_unavailable",
			}),
		);
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		expect(await new DiagnosticEvidencePipeline(store).publishPending()).toBe(1);
		expect(await store.listIncidents()).toHaveLength(1);
		expect((await store.listIncidents())[0]?.coverage.cause).toEqual({ status: "unresolved" });
		await expect(
			new DiagnosticEvidencePipeline(store).ingestJournal("application-journal", Buffer.from('{"MESSAGE":null}')),
		).rejects.toThrow("journal_metadata_unavailable");
		expect(await store.getCursor("application-journal")).toBe("cursor-1");
	} finally {
		await store.close();
	}
});

it("records retention loss before advancing its consumer and reuses that gap after a crash", async () => {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-pipeline-gap-"));
	directories.push(root);
	const path = join(root, "evidence.sqlite");
	let store = await DiagnosticEvidenceStore.open({ path });
	try {
		const time = Date.now() - 4 * 86_400_000;
		const pipeline = new DiagnosticEvidencePipeline(store);
		await pipeline.ingestJournal("application-journal", journal("old-1", time, { type: "kernel_channel_fault" }));
		await pipeline.ingestJournal("application-journal", journal("old-2", time + 1, { type: "kernel_channel_fault" }));
		await store.retain({ nowMs: Date.now() });
		const ingest = store.ingest.bind(store);
		const interrupted = vi.spyOn(store, "ingest").mockImplementation((batch) => {
			if (batch.source === "internal:incident-detector-v1") throw new Error("crash before detector cursor commit");
			return ingest(batch);
		});
		await expect(pipeline.publishPending()).rejects.toThrow("crash before detector cursor commit");
		const [gap] = (await store.readOccurrences()).occurrences;
		expect(gap?.kind).toBe("evidence.gap");
		expect(JSON.parse(Buffer.from(gap!.payload).toString("utf8"))).toMatchObject({
			reason: "occurrences_unavailable",
			missingRanges: [{ firstSequence: 1, lastSequence: 2 }],
			cause: "unknown",
		});
		interrupted.mockRestore();
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		const restarted = new DiagnosticEvidencePipeline(store);
		expect(await restarted.publishPending()).toBe(0);
		expect(await restarted.publishPending()).toBe(0);
		expect((await store.readOccurrences()).occurrences).toEqual([gap]);
		expect(await store.listIncidents()).toEqual([]);
	} finally {
		await store.close();
	}
});

it("publishes unexpected worker transport loss without treating an intentional close as process death", async () => {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-transport-"));
	directories.push(root);
	const store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
	try {
		const pipeline = new DiagnosticEvidencePipeline(store);
		for (const [index, status] of ["expected", undefined, "unexpected"].entries()) {
			await pipeline.ingestJournal(
				"journal:transport",
				journal(String(index), Date.now(), {
					type: "worker_connection_closed",
					status,
					workerId: "original",
					workerPid: 17,
					workerProcessStartId: "proc:100",
					reason: "worker_transport_closed",
				}),
			);
		}
		expect(await pipeline.publishPending()).toBe(1);
		const [incident] = await store.listIncidents();
		expect(incident.coverage).toMatchObject({
			trigger: { type: "worker_connection_closed" },
			cause: { status: "unresolved" },
		});
		expect((await store.readOccurrences()).occurrences.filter((row) => row.kind === "journal.json")).toHaveLength(3);
	} finally {
		await store.close();
	}
});
