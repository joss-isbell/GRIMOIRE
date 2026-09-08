import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	type IncidentRecorderServiceSignalSource,
	type RunIncidentRecorderServiceOptions,
	runIncidentRecorderService,
} from "../src/modes/daemon/incident-recorder.js";
import type {
	IncidentRecorderLiveRunEventsPage,
	IncidentRecorderRunHistoryEvent,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import { extractIncidentRecorderLiveTriggerIntentCandidate } from "../src/modes/daemon/incident-recorder-live-trigger-intent.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	INCIDENT_RECORDER_RUN_ID_ENV,
	INCIDENT_RECORDER_RUN_TOKEN_ENV,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const TARGET_START_ID = "proc:4242";
const RUN_NAME = `2026-09-01T00-00-00.000Z-${RUN_ID}`;
const roots: string[] = [];
const leases: IncidentRecorderWriterLifecycleLease[] = [];
const children: ChildProcess[] = [];

const lifecycleContract: IncidentRecorderWriterLifecycleAdmissionContract = {
	activationGenerationDigest: "a".repeat(64),
	revalidateActivation: () => ({ state: "valid" }),
	acquireCas: acquireIncidentRecorderNamespaceCas,
};

interface CompactorInternals {
	appendSegmentRecord(input: {
		idempotencyKey: string;
		runId: string;
		sourceId: string;
		observedAtMs: number;
		order: string;
		metadata: Record<string, string | number | boolean>;
		payload: Buffer;
	}): unknown;
	closeSegmentStore(): void;
	storageReservedBytes: number;
	storageReservedEntries: number;
	storageReservedInodes: number;
}

interface Fixture {
	agentDir: string;
	runDirectory: string;
	compactor: IncidentRecorderCompactor;
	internal: CompactorInternals;
	lease: IncidentRecorderWriterLifecycleLease;
}

class TestSignalSource implements IncidentRecorderServiceSignalSource {
	private readonly listeners = new Map<"SIGINT" | "SIGTERM", () => void>();

	once(signal: "SIGINT" | "SIGTERM", listener: () => void): void {
		this.listeners.set(signal, listener);
	}

	off(signal: "SIGINT" | "SIGTERM", listener: () => void): void {
		if (this.listeners.get(signal) === listener) this.listeners.delete(signal);
	}

	emit(signal: "SIGINT" | "SIGTERM"): void {
		const listener = this.listeners.get(signal);
		this.listeners.delete(signal);
		listener?.();
	}
}

async function waitUntil(predicate: () => boolean, message: string, timeoutMs = 5_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error(message);
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

function writeServiceRun(agentDir: string, socketPath: string, pid: number, processStartId: string): string {
	const runDirectory = join(agentDir, "incident-recorder", "runs", RUN_ID);
	mkdirSync(runDirectory, { recursive: true, mode: 0o700 });
	writeFileSync(
		join(runDirectory, "launch.json"),
		`${JSON.stringify({
			version: 2,
			canonical: false,
			purpose: "content-addressed-launch-index",
			socketPath,
			runtimeCategory: "node",
			nodeFatalReportsEnabled: true,
			launchArtifact: {
				canonical: false,
				encoding: "derived-diagnostic-json-v1",
				state: "relay-rejected",
				orphanPolicy: "fail-open",
				lifecycleTarget: "real-supervisor-identity",
			},
			derivedCommandSummary: {
				argumentCount: 0,
				flagCategories: [],
				positionalCount: 0,
				redactedValueCount: 0,
				nulSeparated: false,
			},
		})}\n`,
		{ mode: 0o600 },
	);
	const machineId = readFileSync("/etc/machine-id", "utf8").trim();
	const bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
	writeFileSync(
		join(runDirectory, "process.json"),
		`${JSON.stringify({
			runToken: RUN_TOKEN,
			machineId,
			bootId,
			systemdInvocationId: null,
			pid,
			processStartId,
			observed: { wallTime: new Date().toISOString(), monotonicNs: process.hrtime.bigint().toString() },
			runtimeCategory: "node",
			nodeFatalReportsEnabled: true,
			orphanPolicy: "fail-open",
			wrapperDeathSignalsSupervisor: false,
		})}\n`,
		{ mode: 0o600 },
	);
	return runDirectory;
}

function fixture(): Fixture {
	const root = mkdtempSync(join(tmpdir(), "grim16-live-trigger-intent-integration-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const recorderRoot = join(agentDir, "incident-recorder");
	const runDirectory = join(recorderRoot, "runs", RUN_NAME);
	mkdirSync(runDirectory, { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { recursive: true, mode: 0o700 });
	const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, lifecycleContract);
	if (admission.state !== "acquired") throw new Error(`normal lease unavailable: ${admission.reason}`);
	leases.push(admission.lease);
	const compactor = new IncidentRecorderCompactor({
		agentDir,
		freeReserveBytes: 0,
		storageScannerPath: "find",
		writerLifecycleLease: () => admission.lease,
	});
	return {
		agentDir,
		runDirectory,
		compactor,
		internal: compactor as unknown as CompactorInternals,
		lease: admission.lease,
	};
}

function identityKey(occurrenceId: string): string {
	return createHash("sha256").update(`${RUN_ID}\0${RUN_TOKEN}\0${PRODUCER_ID}\0${occurrenceId}`).digest("hex");
}

function event(
	type: "worker_request_end" | "kernel_unexpected_exit",
	occurrenceId: string,
	sequence: number,
	casPath?: string,
): IncidentRecorderRunHistoryEvent {
	const key = identityKey(occurrenceId);
	return {
		identityKey: key,
		identity: { runId: RUN_ID, runToken: RUN_TOKEN, producerId: PRODUCER_ID, occurrenceId },
		semanticFingerprint: createHash("sha256").update(`semantic:${key}`).digest("hex"),
		occurrenceReference: `segment-occurrence:${occurrenceId}`,
		source: "supervisor-events",
		type,
		encoding: "json",
		payloadKind: type === "worker_request_end" ? "derived-scalar" : "control",
		terminal: false,
		metadata:
			type === "worker_request_end"
				? { outcome: "timeout", requestId: `request-${sequence}`, requestType: "list", durationMs: 321 }
				: {
						sessionId: "session-1",
						kernelInstanceId: "kernel-1",
						kernelPid: 4242,
						kernelProcessStartId: TARGET_START_ID,
						launchMode: "direct",
						crashPhase: "executing",
						requestMsgId: "request-msg-1",
						code: null,
						signal: "SIGKILL",
						reason: "process_exit",
					},
		eventWallTimeMs: String(1_700_000_000_000 + sequence),
		eventMonotonicNs: String(9_000 + sequence),
		wrapperOrder: [String(sequence)],
		producerOrder: [String(sequence)],
		cursors: [`cursor:${sequence}`],
		transportIdentity: {},
		cas: { digest: "b".repeat(64), bytes: 1, path: casPath ?? `/tmp/cas-${sequence}.blob` },
	};
}

function heartbeatEvent(sequence: number): IncidentRecorderRunHistoryEvent {
	const value = event("worker_request_end", `88888888-8888-4888-8888-${String(sequence).padStart(12, "0")}`, sequence);
	return {
		...value,
		type: "supervisor_heartbeat",
		payloadKind: "control",
		metadata: { socketExists: true },
	};
}

function appendEvent(f: Fixture, value: IncidentRecorderRunHistoryEvent, sequence: number): void {
	f.internal.appendSegmentRecord({
		idempotencyKey: `occurrence:${value.identityKey}`,
		runId: RUN_ID,
		sourceId: "occurrence",
		observedAtMs: Number(value.eventWallTimeMs),
		order: String(sequence),
		metadata: { version: 1, state: "complete", occurrenceIdentity: value.identityKey, casDigest: value.cas.digest },
		payload: Buffer.from(
			`${JSON.stringify({
				version: 1,
				state: "complete",
				identity: value.identity,
				source: value.source,
				type: value.type,
				encoding: value.encoding,
				payloadKind: value.payloadKind,
				terminal: value.terminal,
				metadata: value.metadata,
				eventWallTimeMs: value.eventWallTimeMs,
				eventMonotonicNs: value.eventMonotonicNs,
				transportIdentity: value.transportIdentity,
				wrapperOrder: value.wrapperOrder,
				producerOrder: value.producerOrder,
				cursors: value.cursors,
				cas: {
					algorithm: "sha256",
					digest: value.cas.digest,
					bytes: value.cas.bytes,
					path: value.cas.path,
					compression: "none",
					resolution: "verified",
				},
				compactionDisposition: "compacted_and_cas_resolved",
				journalCanonicalUntilCompactionCommit: true,
			})}\n`,
			"utf8",
		),
	});
}

function candidate(value: IncidentRecorderRunHistoryEvent) {
	const result = extractIncidentRecorderLiveTriggerIntentCandidate(value, {
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		targetPid: 4242,
		targetProcessStartId: TARGET_START_ID,
	});
	if (!result) throw new Error("fixture event is not a trigger candidate");
	return result;
}

function page(
	state: "complete" | "pending" | "incomplete",
	events: IncidentRecorderRunHistoryEvent[],
	segmentSequence: number,
	ordinal: number,
	reason?: string,
): IncidentRecorderLiveRunEventsPage {
	return {
		version: 1,
		runId: RUN_ID,
		state,
		events,
		cursor: {
			version: 1,
			runId: RUN_ID,
			filterSha256: "c".repeat(64),
			segmentSequence,
			ordinal,
		},
		...(reason ? { reason } : {}),
		scannedSegments: 1,
		scannedRecords: events.length,
		scannedIndexBytes: 1,
	};
}

async function startServiceSeam(
	pages: IncidentRecorderLiveRunEventsPage[],
	seamOptions: {
		persistenceStates?: readonly ("applied" | "unavailable")[];
		minimumPersistenceAttempts?: number;
	} = {},
): Promise<{
	reads: unknown[];
	persisted: string[];
	stop(): Promise<void>;
}> {
	const root = mkdtempSync(join(tmpdir(), "grim16-live-trigger-service-seam-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const binDir = join(root, "bin");
	const socketPath = join(root, "supervisor.sock");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incident-recorder", "runs"), { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { recursive: true, mode: 0o700 });
	mkdirSync(binDir, { recursive: true, mode: 0o700 });
	const systemdCatPath = join(binDir, "systemd-cat");
	writeFileSync(
		systemdCatPath,
		`#!${process.execPath}\nprocess.stdin.resume(); process.stdin.on("end", () => process.exit(0)); process.once("SIGTERM", () => process.exit(0));\n`,
		{ mode: 0o700 },
	);
	const previousPath = process.env.PATH;
	process.env.PATH = `${binDir}${delimiter}${previousPath ?? ""}`;
	const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
		env: { ...process.env, [INCIDENT_RECORDER_RUN_ID_ENV]: RUN_ID, [INCIDENT_RECORDER_RUN_TOKEN_ENV]: RUN_TOKEN },
		stdio: "ignore",
	});
	children.push(child);
	if (!child.pid) throw new Error("live trigger service fixture child did not start");
	await waitUntil(
		() => getProcessStartId(child.pid as number) !== undefined,
		"service fixture child identity unavailable",
	);
	const processStartId = getProcessStartId(child.pid);
	if (!processStartId) throw new Error("service fixture process identity unavailable");
	writeServiceRun(agentDir, socketPath, child.pid, processStartId);
	const reads: unknown[] = [];
	const persisted: string[] = [];
	const persistenceStates = seamOptions.persistenceStates ?? ["applied"];
	const minimumPersistenceAttempts = seamOptions.minimumPersistenceAttempts ?? 2;
	let persistenceAttempt = 0;
	let pageIndex = 0;
	vi.spyOn(IncidentRecorderCompactor.prototype, "readLiveRunEvents").mockImplementation(() => {
		const next = pages[Math.min(pageIndex++, pages.length - 1)];
		if (!next) throw new Error("service seam has no scripted page");
		reads.push(next);
		return next;
	});
	vi.spyOn(IncidentRecorderCompactor.prototype, "persistLiveTriggerIntent").mockImplementation(
		({ candidate: value }) => {
			persisted.push(value.trigger.occurrenceId);
			const state = persistenceStates[Math.min(persistenceAttempt++, persistenceStates.length - 1)];
			if (state === "unavailable") return { state, reason: "injected_persistence_failure" };
			return {
				state: "applied",
				fileName: `live-trigger-intent-v1-${value.trigger.occurrenceId}.json`,
				intent: {} as never,
				peakStorageBytes: 0,
				effects: [],
			};
		},
	);
	vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
	vi.spyOn(IncidentRecorderCompactor.prototype, "beginPinRetentionMaintenance").mockReturnValue(false);
	vi.spyOn(IncidentRecorderWriter.prototype, "recordDerivedForRun").mockImplementation(() => ({
		accepted: true,
		occurrenceId: "88888888-8888-4888-8888-888888888888",
		disposition: "locally_admitted",
	}));
	vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async (options) => {
		options.onStorageMode?.("normal");
		if (!(await options.onNormalWriterAdmission?.())) throw new Error("service seam writer admission failed");
		options.onReaderReady?.();
		await new Promise<void>((resolve) => {
			if (options.signal.aborted) resolve();
			else options.signal.addEventListener("abort", () => resolve(), { once: true });
		});
	});
	const signals = new TestSignalSource();
	let running: Promise<void> | undefined;
	let readyResolve: () => void = () => {};
	const ready = new Promise<void>((resolve) => {
		readyResolve = resolve;
	});
	const serviceOptions: RunIncidentRecorderServiceOptions = {
		notify: (fields) => {
			if (fields.includes("READY=1")) readyResolve();
		},
		signalSource: signals,
		writerStopDeadlineMs: 1_000,
		writerLifecycleContract: {
			activationGenerationDigest: "a".repeat(64),
			revalidateActivation: () => ({ state: "valid" }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		},
	};
	running = runIncidentRecorderService(agentDir, serviceOptions);
	await ready;
	await waitUntil(
		() => persisted.length >= minimumPersistenceAttempts,
		"service seam did not reach the requested persistence attempts",
	);
	return {
		reads,
		persisted,
		stop: async () => {
			signals.emit("SIGTERM");
			if (running) await running;
			if (child.exitCode === null) child.kill("SIGKILL");
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
		},
	};
}

afterEach(() => {
	vi.restoreAllMocks();
	for (const lease of leases.splice(0).reverse()) lease.release();
	for (const root of roots.splice(0).reverse()) rmSync(root, { recursive: true, force: true });
	for (const child of children.splice(0).reverse()) if (child.exitCode === null) child.kill("SIGKILL");
});

describe("GRIM-16 live trigger intent compactor integration", () => {
	it("persists from an actual segment event under the normal lease and replays byte-identically", async () => {
		const f = fixture();
		await f.compactor.initializeStorageAccounting(new AbortController().signal);
		const casDigest = "b".repeat(64);
		const source = event(
			"worker_request_end",
			"44444444-4444-4444-8444-444444444444",
			1,
			join(f.agentDir, "incident-recorder", "cas", "sha256", casDigest.slice(0, 2), `${casDigest}.blob`),
		);
		appendEvent(f, source, 1);
		const read = f.compactor.readLiveRunEvents({ runId: RUN_ID });
		expect(read.state).toBe("complete");
		const observed = read.events[0];
		if (!observed) throw new Error("segment event was not read");
		const internals = f.compactor as unknown as {
			reserveStorage(bytes: number, entries: number, inodes: number): void;
			releaseReservedCapacity(bytes: number, entries: number, inodes: number): void;
		};
		const reserve = vi.spyOn(internals, "reserveStorage");
		const release = vi.spyOn(internals, "releaseReservedCapacity");
		const first = f.compactor.persistLiveTriggerIntent({
			runDirectory: f.runDirectory,
			candidate: candidate(observed),
		});
		expect(first.state).toBe("applied");
		expect(reserve).toHaveBeenCalledTimes(1);
		expect(release).toHaveBeenCalledTimes(1);
		if (first.state !== "applied") return;
		const bytes = readFileSync(join(f.runDirectory, first.fileName));
		const replay = f.compactor.persistLiveTriggerIntent({
			runDirectory: f.runDirectory,
			candidate: candidate(observed),
		});
		expect(replay.state).toBe("replayed");
		expect(reserve).toHaveBeenCalledTimes(2);
		expect(release).toHaveBeenCalledTimes(2);
		expect(readFileSync(join(f.runDirectory, first.fileName))).toEqual(bytes);
		expect(f.internal.storageReservedBytes).toBe(0);
		expect(f.internal.storageReservedEntries).toBe(0);
		expect(f.internal.storageReservedInodes).toBe(0);
	});

	it("does not overwrite a conflicting intent or write after finalization begins", async () => {
		const f = fixture();
		await f.compactor.initializeStorageAccounting(new AbortController().signal);
		const source = event("kernel_unexpected_exit", "55555555-5555-4555-8555-555555555555", 2);
		const original = candidate(source);
		const first = f.compactor.persistLiveTriggerIntent({ runDirectory: f.runDirectory, candidate: original });
		expect(first.state).toBe("applied");
		if (first.state !== "applied") return;
		const path = join(f.runDirectory, first.fileName);
		const bytes = readFileSync(path);
		const conflict = f.compactor.persistLiveTriggerIntent({
			runDirectory: f.runDirectory,
			candidate: { ...original, cause: { ...original.cause, code: 137 } },
		});
		expect(conflict.state).toBe("conflict");
		expect(readFileSync(path)).toEqual(bytes);
		const finalizationPath = join(f.runDirectory, "service-finalization-seal-intent.json");
		writeFileSync(finalizationPath, "started\n", { mode: 0o600 });
		const blocked = f.compactor.persistLiveTriggerIntent({ runDirectory: f.runDirectory, candidate: original });
		expect(blocked).toMatchObject({ state: "unavailable", reason: "service_finalization_already_started" });
		expect(readdirSync(f.runDirectory)).not.toContain("service-finalization-seal-replay-ambiguity.json");
	});

	it("keeps a held page at one qualifying event per refresh and retries without another read", async () => {
		const first = event("worker_request_end", "66666666-6666-4666-8666-666666666666", 3);
		const second = event("kernel_unexpected_exit", "77777777-7777-4777-8777-777777777777", 4);
		const harness = await startServiceSeam([page("complete", [first, second], 2, 2)]);
		try {
			expect(harness.reads).toHaveLength(1);
			expect(harness.persisted).toEqual([first.identity.occurrenceId, second.identity.occurrenceId]);
		} finally {
			await harness.stop();
		}
	});

	it("holds the failed qualifying index after the first intent commits", async () => {
		const first = event("worker_request_end", "99999999-9999-4999-8999-999999999991", 5);
		const second = event("kernel_unexpected_exit", "99999999-9999-4999-8999-999999999992", 6);
		const harness = await startServiceSeam([page("complete", [first, second], 3, 2)], {
			persistenceStates: ["applied", "unavailable"],
			minimumPersistenceAttempts: 3,
		});
		try {
			expect(harness.reads).toHaveLength(1);
			expect(harness.persisted).toEqual([
				first.identity.occurrenceId,
				second.identity.occurrenceId,
				second.identity.occurrenceId,
			]);
		} finally {
			await harness.stop();
		}
	});

	it("replays a valid prefix after an incomplete page without changing its cursor", async () => {
		const value = event("kernel_unexpected_exit", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", 7);
		const harness = await startServiceSeam(
			[page("incomplete", [value], 4, 1, "malformed trailing record"), page("complete", [value], 4, 1)],
			{ minimumPersistenceAttempts: 2 },
		);
		try {
			expect(harness.reads).toHaveLength(2);
			expect(harness.persisted).toEqual([value.identity.occurrenceId, value.identity.occurrenceId]);
		} finally {
			await harness.stop();
		}
	});

	it("reads one bounded page for 65 records while draining ordinary events around two intents", async () => {
		const first = event("worker_request_end", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1", 70);
		const second = event("kernel_unexpected_exit", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2", 71);
		const events = [...Array.from({ length: 63 }, (_, index) => heartbeatEvent(index + 1)), first, second];
		const harness = await startServiceSeam([page("complete", events, 5, 65)]);
		try {
			expect(harness.reads).toHaveLength(1);
			expect(harness.persisted).toEqual([first.identity.occurrenceId, second.identity.occurrenceId]);
		} finally {
			await harness.stop();
		}
	});
});
