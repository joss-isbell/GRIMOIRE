import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	type IncidentRecorderServiceSignalSource,
	type RunIncidentRecorderServiceOptions,
	runIncidentRecorderService,
} from "../src/modes/daemon/incident-recorder.js";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderLiveRunEventsPage,
	type IncidentRecorderRunHistoryEvent,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	INCIDENT_RECORDER_RUN_ID_ENV,
	INCIDENT_RECORDER_RUN_TOKEN_ENV,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const FILTER_SHA = "f".repeat(64);
const roots: string[] = [];
const children: ChildProcess[] = [];

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

function waitUntil(predicate: () => boolean, message: string, timeoutMs = 5_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	return new Promise<void>((resolve, reject) => {
		const poll = (): void => {
			if (predicate()) {
				resolve();
				return;
			}
			if (Date.now() >= deadline) {
				reject(new Error(message));
				return;
			}
			setTimeout(poll, 10).unref();
		};
		poll();
	});
}

function historyEvent(
	sequence: number,
	type: "supervisor_heartbeat" | "supervisor_exit" | "worker_request_end" | "list_status_sampling_trigger",
	wallTimeMs: number,
	metadata: Record<string, string | number | boolean | null> = {},
): IncidentRecorderRunHistoryEvent {
	const occurrenceId = `00000000-0000-4000-8000-${sequence.toString(16).padStart(12, "0")}`;
	const identityKey = createHash("sha256")
		.update(`${RUN_ID}\0${RUN_TOKEN}\0${PRODUCER_ID}\0${occurrenceId}`)
		.digest("hex");
	return {
		identityKey,
		identity: { runId: RUN_ID, runToken: RUN_TOKEN, producerId: PRODUCER_ID, occurrenceId },
		semanticFingerprint: "a".repeat(64),
		occurrenceReference: `service-live-observation:${sequence}`,
		source: "supervisor-events",
		type,
		encoding: "json",
		payloadKind: "derived-scalar",
		terminal: type === "supervisor_exit",
		metadata: { producerPid: process.pid, ...metadata },
		eventWallTimeMs: String(wallTimeMs),
		eventMonotonicNs: String(sequence),
		wrapperOrder: [String(sequence)],
		producerOrder: [String(sequence)],
		cursors: [`service-live-observation:${sequence}`],
		transportIdentity: {},
		cas: { digest: "b".repeat(64), bytes: 1, path: `/tmp/service-live-observation-${sequence}.blob` },
	};
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
		cursor: { version: 1, runId: RUN_ID, filterSha256: FILTER_SHA, segmentSequence, ordinal },
		...(reason ? { reason } : {}),
		scannedSegments: 1,
		scannedRecords: events.length,
		scannedIndexBytes: 1,
	};
}

function writeServiceRun(agentDir: string, socketPath: string, pid: number, processStartId: string): string {
	const runDir = join(agentDir, "incident-recorder", "runs", RUN_ID);
	mkdirSync(runDir, { recursive: true, mode: 0o700 });
	writeFileSync(
		join(runDir, "launch.json"),
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
		join(runDir, "process.json"),
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
	return runDir;
}

function writeLegacyOrderedEvents(agentDir: string, events: readonly IncidentRecorderRunHistoryEvent[]): void {
	const directory = join(
		agentDir,
		"incident-recorder",
		"refs",
		"runs",
		createHash("sha256").update(RUN_ID).digest("hex"),
	);
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	for (const [index, event] of events.entries())
		writeFileSync(
			join(directory, `seq-${index.toString().padStart(20, "0")}-${event.identity.occurrenceId}.json`),
			`${JSON.stringify(event)}\n`,
			{ mode: 0o600 },
		);
}

interface ServiceHarness {
	reads: Array<unknown>;
	cursorReads: Array<unknown>;
	detections: string[];
	runDir: string;
	stop(): Promise<void>;
}

async function startHarness(
	scriptedPages: IncidentRecorderLiveRunEventsPage[],
	legacyEvents: readonly IncidentRecorderRunHistoryEvent[] = [],
): Promise<ServiceHarness> {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-live-observation-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const binDir = join(root, "bin");
	const socketPath = join(root, "supervisor.sock");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incident-recorder"), { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { recursive: true, mode: 0o700 });
	mkdirSync(binDir, { recursive: true, mode: 0o700 });
	const systemdCatPath = join(binDir, "systemd-cat");
	writeFileSync(
		systemdCatPath,
		`#!${process.execPath}\nprocess.stdin.resume(); process.stdin.on("end", () => process.exit(0)); process.once("SIGTERM", () => process.exit(0));\n`,
		{ mode: 0o700 },
	);
	chmodSync(systemdCatPath, 0o700);
	const previousPath = process.env.PATH;
	process.env.PATH = `${binDir}${delimiter}${previousPath ?? ""}`;
	const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
		env: { ...process.env, [INCIDENT_RECORDER_RUN_ID_ENV]: RUN_ID, [INCIDENT_RECORDER_RUN_TOKEN_ENV]: RUN_TOKEN },
		stdio: "ignore",
	});
	children.push(child);
	if (!child.pid) throw new Error("live observation fixture child did not start");
	await waitUntil(
		() => getProcessStartId(child.pid as number) !== undefined,
		"live observation fixture child identity unavailable",
	);
	const processStartId = getProcessStartId(child.pid);
	if (!processStartId) throw new Error("live observation fixture process identity unavailable");
	const runDir = writeServiceRun(agentDir, socketPath, child.pid, processStartId);
	writeLegacyOrderedEvents(agentDir, legacyEvents);
	const reads: Array<unknown> = [];
	const cursorReads: Array<unknown> = [];
	const detections: string[] = [];
	let pageIndex = 0;
	let runCalls = 0;
	let writerAdmissions = 0;
	const readLiveRunEvents = vi
		.spyOn(IncidentRecorderCompactor.prototype, "readLiveRunEvents")
		.mockImplementation((input) => {
			const next = scriptedPages[Math.min(pageIndex++, scriptedPages.length - 1)];
			reads.push(next);
			cursorReads.push(input.cursor);
			return next;
		});
	const admitObservation = vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
	const beginMaintenance = vi
		.spyOn(IncidentRecorderCompactor.prototype, "beginPinRetentionMaintenance")
		.mockReturnValue(false);
	const recordDerivedForRun = vi
		.spyOn(IncidentRecorderWriter.prototype, "recordDerivedForRun")
		.mockImplementation((_identity, _source, type) => {
			if (type === "heartbeat_stalled" || type === "socket_lost" || type === "worker_hang_detected")
				detections.push(type);
			return {
				accepted: true,
				occurrenceId: "44444444-4444-4444-8444-444444444444",
				disposition: "locally_admitted",
			};
		});
	const run = vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async (options) => {
		runCalls += 1;
		options.onStorageMode?.("normal");
		writerAdmissions += 1;
		if (!(await options.onNormalWriterAdmission?.())) throw new Error("service fixture writer admission failed");
		options.onReaderReady?.();
		await new Promise<void>((resolve) => {
			if (options.signal.aborted) resolve();
			else options.signal.addEventListener("abort", () => resolve(), { once: true });
		});
	});
	const signals = new TestSignalSource();
	const restoreMocks = (): void => {
		readLiveRunEvents.mockRestore();
		admitObservation.mockRestore();
		beginMaintenance.mockRestore();
		recordDerivedForRun.mockRestore();
		run.mockRestore();
	};
	const restoreEnvironment = (): void => {
		if (previousPath === undefined) delete process.env.PATH;
		else process.env.PATH = previousPath;
	};
	let resolveReady: () => void = () => {};
	const ready = new Promise<void>((resolve) => {
		resolveReady = resolve;
	});
	let running: Promise<void> | undefined;
	let serviceError: unknown;
	try {
		const options: RunIncidentRecorderServiceOptions = {
			notify: (fields) => {
				if (fields.includes("READY=1")) resolveReady();
			},
			signalSource: signals,
			writerStopDeadlineMs: 1_000,
			writerLifecycleContract: {
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			},
		};
		running = runIncidentRecorderService(agentDir, options);
		running.catch((error) => {
			serviceError = error;
		});
		await ready;
		await waitUntil(
			() => reads.length > 0 || serviceError !== undefined,
			`service fixture did not inspect a live run (run=${runCalls}, admission=${writerAdmissions})${serviceError instanceof Error ? `: ${serviceError.message}` : ""}`,
		);
		if (serviceError !== undefined) throw serviceError;
		return {
			reads,
			cursorReads,
			detections,
			runDir,
			stop: async () => {
				signals.emit("SIGTERM");
				if (running) await running;
				if (child.exitCode === null) child.kill("SIGKILL");
				restoreMocks();
				restoreEnvironment();
			},
		};
	} catch (error) {
		signals.emit("SIGTERM");
		if (running) await running.catch(() => {});
		if (child.exitCode === null) child.kill("SIGKILL");
		restoreMocks();
		restoreEnvironment();
		throw error;
	}
}

afterEach(() => {
	vi.restoreAllMocks();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
	for (const child of children.splice(0)) {
		if (child.exitCode === null) child.kill("SIGKILL");
	}
});

describe("incident recorder live service observation", () => {
	it("does not classify a stale first page while a fresh heartbeat is pending", async () => {
		const now = Date.now();
		const old = Array.from({ length: 64 }, (_, index) =>
			historyEvent(index + 1, "supervisor_heartbeat", now - 60_000),
		);
		const fresh = historyEvent(65, "supervisor_heartbeat", now - 1_000, { socketExists: false });
		const harness = await startHarness([page("pending", old, 1, 64), page("complete", [fresh], 1, 65)]);
		try {
			await waitUntil(() => harness.reads.length >= 2, "fresh heartbeat page was not observed");
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(harness.detections).toEqual([]);
		} finally {
			await harness.stop();
		}
	});

	it("preserves the cursor across a transient reader failure and resumes without a false hang", async () => {
		const now = Date.now();
		const old = historyEvent(1, "supervisor_heartbeat", now - 60_000, { socketExists: false });
		const fresh = historyEvent(2, "supervisor_heartbeat", now - 1_000, { socketExists: false });
		const first = page("pending", [old], 2, 1);
		const failed = page("incomplete", [], 99, 99, "transient_reader_failure");
		const resumed = page("complete", [fresh], 2, 2);
		const harness = await startHarness([first, failed, resumed]);
		try {
			await waitUntil(() => harness.reads.length >= 3, "reader did not resume from its cursor");
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(harness.cursorReads[1]).toEqual(first.cursor);
			expect(harness.cursorReads[2]).toEqual(first.cursor);
			expect(harness.detections).toEqual([]);
		} finally {
			await harness.stop();
		}
	});

	it("resumes detection after the live cursor catches up", async () => {
		const now = Date.now();
		const pendingHeartbeat = historyEvent(1, "supervisor_heartbeat", now - 1_000);
		const staleHeartbeat = historyEvent(2, "supervisor_heartbeat", now - 60_000);
		const harness = await startHarness([
			page("pending", [pendingHeartbeat], 3, 1),
			page("complete", [staleHeartbeat], 3, 2),
		]);
		try {
			await waitUntil(() => harness.reads.length >= 2, "live cursor did not catch up");
			await waitUntil(
				() => harness.detections.includes("heartbeat_stalled"),
				"stale heartbeat was not detected after catch-up",
			);
			expect(harness.detections).toContain("heartbeat_stalled");
		} finally {
			await harness.stop();
		}
	});

	it("detects a stale legacy heartbeat when the caught-up segment page is empty", async () => {
		const now = Date.now();
		const legacyHeartbeat = historyEvent(1, "supervisor_heartbeat", now - 60_000, { socketExists: false });
		const harness = await startHarness([page("complete", [], 7, 0)], [legacyHeartbeat]);
		try {
			await waitUntil(
				() => harness.detections.includes("heartbeat_stalled"),
				"legacy heartbeat was not detected with an empty live page",
			);
			expect(harness.detections).toContain("heartbeat_stalled");
		} finally {
			await harness.stop();
		}
	});

	it("retains historical socket presence when the latest heartbeat reports false", async () => {
		const now = Date.now();
		const harness = await startHarness([
			page(
				"complete",
				[
					historyEvent(1, "supervisor_heartbeat", now - 1_000, { socketExists: true }),
					historyEvent(2, "supervisor_heartbeat", now - 500, { socketExists: false }),
				],
				4,
				2,
			),
		]);
		try {
			await waitUntil(() => harness.detections.includes("socket_lost"), "historical socket loss was not detected");
			expect(harness.detections).toContain("socket_lost");
		} finally {
			await harness.stop();
		}
	});

	it("selects a causally newer heartbeat when its wall clock rolls back", async () => {
		const now = Date.now();
		const harness = await startHarness([
			page(
				"complete",
				[
					historyEvent(1, "supervisor_heartbeat", now - 1_000),
					historyEvent(2, "supervisor_heartbeat", now - 20_000),
				],
				5,
				2,
			),
		]);
		try {
			await waitUntil(
				() => harness.detections.includes("heartbeat_stalled"),
				"rolled-back heartbeat was not selected",
			);
			expect(harness.detections).toContain("heartbeat_stalled");
		} finally {
			await harness.stop();
		}
	});

	it("preserves known supervisor-exit evidence during incomplete catch-up", async () => {
		const now = Date.now();
		const exit = historyEvent(1, "supervisor_exit", now - 60_000, { code: null, signal: "SIGKILL" });
		const staleHeartbeat = historyEvent(2, "supervisor_heartbeat", now - 60_000, { socketExists: false });
		const harness = await startHarness([
			page("pending", [exit], 6, 1),
			page("incomplete", [], 6, 1, "reader_pending"),
			page("complete", [staleHeartbeat], 6, 2),
		]);
		try {
			await waitUntil(() => harness.reads.length >= 3, "known supervisor exit was not retained");
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(harness.detections).not.toContain("heartbeat_stalled");
		} finally {
			await harness.stop();
		}
	});
});
