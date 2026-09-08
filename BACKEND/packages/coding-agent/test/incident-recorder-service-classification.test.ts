import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type IncidentRecorderServiceSignalSource,
	type RunIncidentRecorderServiceOptions,
	runIncidentRecorderService,
} from "../src/modes/daemon/incident-recorder.js";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderRunHistoryEvent,
	type IncidentRecorderRunHistoryResult,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

type RecorderSignal = "SIGINT" | "SIGTERM";

class TestSignalSource implements IncidentRecorderServiceSignalSource {
	private readonly listeners = new Map<RecorderSignal, () => void>();

	once(signal: RecorderSignal, listener: () => void): void {
		this.listeners.set(signal, listener);
	}

	off(signal: RecorderSignal, listener: () => void): void {
		if (this.listeners.get(signal) === listener) this.listeners.delete(signal);
	}

	emit(signal: RecorderSignal): void {
		const listener = this.listeners.get(signal);
		this.listeners.delete(signal);
		listener?.();
	}

	get size(): number {
		return this.listeners.size;
	}
}

const roots: string[] = [];

afterEach(() => {
	vi.restoreAllMocks();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function writeJson(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function fixture(): { root: string; agentDir: string; runDir: string; runId: string; runToken: string } {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-recorder-classification-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const runId = "f1010101-0101-4101-8101-010101010101";
	const runToken = "f2020202-0202-4202-8202-020202020202";
	const runDir = join(agentDir, "incident-recorder", "runs", `2026-08-31T00-00-00.000Z-${runId}`);
	mkdirSync(runDir, { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { recursive: true, mode: 0o700 });
	writeJson(join(runDir, "launch.json"), {
		version: 2,
		canonical: false,
		purpose: "content-addressed-launch-index",
		socketPath: join(root, "recorder.sock"),
		runtimeCategory: "foreign",
		nodeFatalReportsEnabled: false,
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
	});
	writeJson(join(runDir, "process.json"), {
		runToken,
		machineId: "00000000000000000000000000000000",
		bootId: "00000000-0000-4000-8000-000000000000",
		systemdInvocationId: null,
		pid: 2_147_483_647,
		processStartId: "proc:1",
		observed: { wallTime: "2026-08-31T00:00:00.000Z", monotonicNs: "1" },
		runtimeCategory: "foreign",
		nodeFatalReportsEnabled: false,
		orphanPolicy: "fail-open",
		wrapperDeathSignalsSupervisor: false,
	});
	writeJson(
		join(
			runDir,
			`service-finalization-barrier-deadline-${createHash("sha256").update(`${runId}\0${runToken}`).digest("hex")}.json`,
		),
		{
			schemaVersion: 1,
			kind: "service_finalization_barrier_deadline",
			runId,
			runToken,
			createdWallTimeMs: 0,
			retryThroughWallTimeMs: 60_000,
		},
	);
	writeJson(join(runDir, "service-finalization-stopped-observation.json"), {
		schemaVersion: 1,
		kind: "service_stopped_observation",
		runId,
		runToken,
		firstObservedStoppedWallTimeMs: 1_800_000_000_000,
		disposition: "exact_first_observation",
	});
	writeJson(join(runDir, "service-finalization-seal-intent.json"), {
		schemaVersion: 1,
		kind: "service_run_seal_intent",
		runId,
		runToken,
		terminalOccurrenceId: "f3030303-0303-4303-8303-030303030303",
		retentionAnchorWallTimeMs: 1_800_000_000_000,
		stoppedObservationDisposition: "exact_first_observation",
	});
	writeJson(join(runDir, "service-finalization-seal.json"), {
		schemaVersion: 1,
		state: "sealed",
		runId,
		runToken,
		terminal: {
			type: "capture_channel_terminal",
			admission: {
				accepted: true,
				occurrenceId: "f3030303-0303-4303-8303-030303030303",
				disposition: "locally_admitted",
			},
			frontier: {
				occurrenceId: "f3030303-0303-4303-8303-030303030303",
				producerId: "f4040404-0404-4404-8404-040404040404",
				type: "capture_channel_terminal",
				firstProducerSequence: "2",
				lastProducerSequence: "2",
				firstWrapperSequence: "2",
				lastWrapperSequence: "2",
			},
		},
		loss: {
			emitter: { records: 0, bytes: 0 },
			drainTimeout: {
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 0, bytes: 0 },
			},
			terminalRelay: {
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 0, bytes: 0 },
			},
		},
	});
	writeJson(join(runDir, "finalization-barrier-expectation.json"), {
		version: 1,
		runId,
		runToken,
		wrapperPid: 2_147_483_647,
		wrapperStartId: "proc:1",
		finalQueuedTailLoss: { records: 0, bytes: 0 },
		emitterFinalTailLoss: { records: 0, bytes: 0 },
		exitCode: "unavailable",
		exitSignal: "SIGKILL",
	});
	writeJson(join(runDir, "raw-reports", "capture-complete.json"), {
		schemaVersion: 1,
		kind: "node_report_capture_complete",
		state: "complete",
		runId,
		reasons: [],
	});
	writeJson(join(runDir, "evidence", "provider-artifacts", "capture-complete.json"), {
		schemaVersion: 1,
		kind: "provider_artifact_capture_complete",
		state: "complete",
		runId,
		reasons: [],
	});
	const runReferences = join(
		agentDir,
		"incident-recorder",
		"refs",
		"runs",
		createHash("sha256").update(runId).digest("hex"),
	);
	mkdirSync(runReferences, { recursive: true, mode: 0o700 });
	writeJson(join(runDir, "evidence", "provider-artifacts", "capture-frontier.json"), {
		schemaVersion: 1,
		kind: "provider_artifact_capture_frontier",
		runId,
		referenceCount: 0,
		referenceSetSha256: createHash("sha256").digest("hex"),
	});
	return { root, agentDir, runDir, runId, runToken };
}

function structuredEvent(
	fixtureValue: ReturnType<typeof fixture>,
	type: string,
	metadata: Record<string, string | number | boolean | null>,
	eventWallTimeMs = "1800000000000",
): IncidentRecorderRunHistoryEvent {
	const occurrenceId = "f5050505-0505-4505-8505-050505050505";
	const identityKey = createHash("sha256").update(`${fixtureValue.runId}\0${occurrenceId}`).digest("hex");
	return {
		identityKey,
		identity: {
			runId: fixtureValue.runId,
			runToken: fixtureValue.runToken,
			producerId: "f6060606-0606-4606-8606-060606060606",
			occurrenceId,
		},
		semanticFingerprint: createHash("sha256").update(`semantic:${identityKey}`).digest("hex"),
		occurrenceReference: `service-test:${occurrenceId}`,
		source: "recorder-events",
		type,
		encoding: "none",
		payloadKind: "derived-scalar",
		terminal: false,
		metadata,
		eventWallTimeMs,
		eventMonotonicNs: "1",
		wrapperOrder: ["1"],
		producerOrder: ["1"],
		cursors: [`service-test:${occurrenceId}`],
		transportIdentity: {},
		cas: {
			digest: createHash("sha256").update(`cas:${identityKey}`).digest("hex"),
			bytes: 0,
			path: `service-test-cas:${identityKey}`,
		},
	};
}

function terminalEvent(fixtureValue: ReturnType<typeof fixture>): IncidentRecorderRunHistoryEvent {
	const occurrenceId = "f3030303-0303-4303-8303-030303030303";
	const identityKey = createHash("sha256").update(`${fixtureValue.runId}\0${occurrenceId}`).digest("hex");
	return {
		identityKey,
		identity: {
			runId: fixtureValue.runId,
			runToken: fixtureValue.runToken,
			producerId: "f4040404-0404-4404-8404-040404040404",
			occurrenceId,
		},
		semanticFingerprint: createHash("sha256").update(`semantic:${identityKey}`).digest("hex"),
		occurrenceReference: `service-test:${occurrenceId}`,
		source: "recorder-control",
		type: "capture_channel_terminal",
		encoding: "none",
		payloadKind: "control",
		terminal: true,
		metadata: {},
		eventWallTimeMs: "1800000000001",
		eventMonotonicNs: "2",
		wrapperOrder: ["2"],
		producerOrder: ["2"],
		cursors: [`service-test:${occurrenceId}`],
		transportIdentity: {},
		cas: {
			digest: createHash("sha256").update(`cas:${identityKey}`).digest("hex"),
			bytes: 0,
			path: `service-test-cas:${identityKey}`,
		},
	};
}

function projection(
	fixtureValue: ReturnType<typeof fixture>,
	type: string,
	metadata: Record<string, string | number | boolean | null>,
	eventWallTimeMs = "1800000000000",
): IncidentRecorderRunHistoryResult {
	const events = [structuredEvent(fixtureValue, type, metadata, eventWallTimeMs), terminalEvent(fixtureValue)];
	return {
		state: "incomplete",
		reason: "service_classification_test_projection",
		projection: {
			version: 1,
			runId: fixtureValue.runId,
			fromWallTimeMs: 0,
			throughWallTimeMs: Number.MAX_SAFE_INTEGER,
			events,
			terminalEvents: [events[1]].map((event) => ({
				identityKey: event.identityKey,
				type: event.type,
				source: event.source,
				eventWallTimeMs: event.eventWallTimeMs,
				basis: "terminal_flag" as const,
			})),
			finalizationCandidates: [],
			ordering: {
				semantics: "partial_order",
				causalRelations: [],
				presentationTieBreak: "wall_time_then_identity_key",
				unrelatedPresentationOrderIsCausal: false,
				scope: "complete_snapshot",
			},
			evidence: [{ kind: "incomplete", reason: "service_classification_test_projection" }],
		},
	};
}

function writeEnvironmentCorrelation(runDir: string): void {
	const bootId = "11111111111111111111111111111111";
	writeJson(join(runDir, "evidence", "linux-system-journal.json"), {
		schemaVersion: 1,
		provider: "linux_system_journal",
		target: { pid: 2_147_483_647, processStartId: "proc:1" },
		capability: { status: "available", reason: "classification_test" },
		bounds: { start: { cursor: "start", bootId, realtimeTimestampUs: "1800000000000" } },
		lastObservation: {
			wallTime: "2026-08-31T00:00:00.000Z",
			outcome: "observed",
			reason: "classification_test",
			sourceTruncated: false,
		},
		records: [
			{
				cursor: "shutdown",
				bootId,
				source: "systemd_shutdown",
				sourceLayer: "service_resource",
				category: "shutdown",
				targetIdentityBinding: "pid_and_run_journal_window",
				targetPid: 2_147_483_647,
			},
		],
	});
}

function mockReadyServiceCompactor(): void {
	vi.spyOn(IncidentRecorderWriter.prototype, "start").mockResolvedValue(undefined);
	vi.spyOn(IncidentRecorderWriter.prototype, "journalReady", "get").mockReturnValue(true);
	vi.spyOn(IncidentRecorderCompactor.prototype, "storageMode", "get").mockReturnValue("normal");
	vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
	vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
	vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
		this: IncidentRecorderCompactor,
		...args: Parameters<IncidentRecorderCompactor["run"]>
	) {
		const [runOptions] = args;
		runOptions.onStorageMode?.("normal");
		await runOptions.onNormalWriterAdmission?.();
		runOptions.onReaderReady?.();
		await new Promise<void>((resolve) => {
			if (runOptions.signal.aborted) resolve();
			else runOptions.signal.addEventListener("abort", () => resolve(), { once: true });
		});
	});
}

async function waitForCondition(condition: () => boolean, message: string | (() => string)): Promise<void> {
	for (let attempt = 0; attempt < 300; attempt += 1) {
		if (condition()) return;
		await new Promise<void>((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`timed out waiting for ${typeof message === "function" ? message() : message}`);
}

async function runClassificationCase(
	type: string,
	metadata: Record<string, string | number | boolean | null>,
	expected: string,
	withEnvironmentCorrelation = false,
	eventWallTimeMs = "1800000000000",
): Promise<void> {
	const target = fixture();
	if (withEnvironmentCorrelation) writeEnvironmentCorrelation(target.runDir);
	mockReadyServiceCompactor();
	const projectRunHistory = vi
		.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
		.mockImplementation(() => projection(target, type, metadata, eventWallTimeMs) as never);
	const signals = new TestSignalSource();
	let resolveReady: () => void = () => {};
	const ready = new Promise<void>((resolve) => {
		resolveReady = resolve;
	});
	let running: Promise<void> | undefined;
	try {
		running = runIncidentRecorderService(target.agentDir, {
			notify: (fields) => {
				if (fields.includes("READY=1")) resolveReady();
			},
			signalSource: signals,
			writerStopDeadlineMs: 1_000,
			writerLifecycleContract: {
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			} satisfies NonNullable<RunIncidentRecorderServiceOptions["writerLifecycleContract"]>,
		});
		const readinessTimeout = new Promise<never>((_resolve, reject) =>
			setTimeout(() => reject(new Error("timed out waiting for recorder service readiness")), 10_000),
		);
		await Promise.race([
			ready,
			readinessTimeout,
			running.then(
				() => {
					throw new Error("recorder service stopped before readiness");
				},
				(error: unknown) => {
					throw error;
				},
			),
		]);
		const summaryPath = join(
			target.agentDir,
			"incidents",
			`2026-08-31T00-00-00.000Z-${target.runId}`,
			"summary.json",
		);
		let observedSummary = "missing";
		let observedRunFiles = "unknown";
		await waitForCondition(
			() => {
				observedRunFiles = readdirSync(target.runDir).join(",");
				if (!existsSync(summaryPath)) return false;
				observedSummary = readFileSync(summaryPath, "utf8");
				const summary = JSON.parse(observedSummary) as { classification?: unknown };
				return summary.classification === expected;
			},
			() =>
				`classification ${expected} (summary=${observedSummary}; runFiles=${observedRunFiles}; projections=${projectRunHistory.mock.calls.length}; controls=${existsSync(join(target.runDir, "service-finalization-seal.json")) ? "sealed" : "unsealed"})`,
		);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			classification?: unknown;
			causeLayer?: unknown;
		};
		expect(summary).toMatchObject({ classification: expected });
		if (withEnvironmentCorrelation) expect(summary.causeLayer).toBe("environment");
	} finally {
		if (signals.size > 0) signals.emit("SIGTERM");
		if (running) await running;
	}
}

describe("incident recorder service stopped classification", () => {
	it.each([
		["heartbeat_stalled", {}, "event_loop_hang"],
		["socket_lost", {}, "socket_loss"],
		["worker_request_end", { outcome: "timeout", requestId: "request-1" }, "worker_response_hang"],
	] as const)(
		"classifies canonical %s metadata despite empty legacy event reads",
		async (type, metadata, expected) => {
			await runClassificationCase(type, metadata, expected);
		},
	);

	it("retains classification when a canonical event timestamp is outside the Date range", async () => {
		await runClassificationCase("heartbeat_stalled", {}, "event_loop_hang", false, "8640000000000001");
	});

	it("keeps environment correlation precedence over canonical application events", async () => {
		await runClassificationCase("heartbeat_stalled", {}, "host_shutdown_correlated_exit", true);
	});
});
