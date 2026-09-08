import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	linkSync,
	mkdirSync,
	mkdtempSync,
	opendirSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	appendSupervisorDiagnosticBytes,
	appendSupervisorDiagnosticEvent,
	type IncidentRecorderServiceSignalSource,
	ingestIncidentRecorderEvidence,
	inspectIncidentRecorderRuns,
	type RunIncidentRecorderServiceOptions,
	registerIncidentProviderSourceManifest,
	runIncidentRecorderService as runIncidentRecorderServiceWithActivation,
} from "../src/modes/daemon/incident-recorder.js";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderRunHistoryEvent,
	type IncidentRecorderRunHistoryResult,
	IncidentRecorderSegmentOwnershipUncertainError,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import { INCIDENT_RECORDER_RUN_DIR_ENV } from "../src/modes/daemon/incident-recorder-env.js";
import {
	finalizeIncidentRecorderProjection,
	type IncidentRecorderFinalizationInput,
	type IncidentRecorderRelayFrontierExpectation,
	persistIncidentRetentionAuthority,
} from "../src/modes/daemon/incident-recorder-finalizer.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import * as retentionModule from "../src/modes/daemon/incident-recorder-retention.js";
import { INCIDENT_DIAGNOSTIC_RETENTION_MS } from "../src/modes/daemon/incident-recorder-retention.js";
import { IncidentRecorderServiceWriterLifecycle } from "../src/modes/daemon/incident-recorder-service-writer-lifecycle.js";
import {
	createIncidentRecorderWrapperFrontier,
	INCIDENT_RECORDER_SERVICE_SEAL_RESULT_MAX_IDENTITIES,
	type IncidentJournalLine,
	IncidentRecorderServiceIdentitySealFenceSaturatedError,
	IncidentRecorderWrapperFrontierSaturatedError,
	IncidentRecorderWriter,
} from "../src/modes/daemon/incident-recorder-writer.js";
import { acquireIncidentRecorderWriterNormalLease } from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

type RecorderSignal = "SIGINT" | "SIGTERM";

interface LifecycleSequenceReference {
	machineId: string;
	bootId: string;
	uid: string;
	identifier: string;
	transport: string;
	streamId: string;
	invocationId: string | null;
	realtimeUs: string;
	monotonicUs: string;
	journalPid: string | null;
	wrapperSequence: string;
	producerSequence: string;
	chunkIndex: number;
	chunkCount: number;
	bytes: number;
	memoryBytes: number;
	resolved: boolean;
	sequenceUpdates?: { wrapperKey: string; wrapper: string; producerKey: string; producer: string };
}

interface LifecycleSequenceCompactorInternals {
	checkSequences(line: IncidentJournalLine, reference: LifecycleSequenceReference): void;
	writeGap(value: unknown): void;
	wrapperSequences: Map<string, bigint>;
	producerSequences: Map<string, bigint>;
}

interface StartupAdmissionCompactorInternals {
	latchSegmentOwnershipUncertain(reason: string): void;
	segmentOwnershipUncertainError?: IncidentRecorderSegmentOwnershipUncertainError;
}

function runIncidentRecorderService(agentDir: string, options: RunIncidentRecorderServiceOptions): Promise<void> {
	mkdirSync(join(agentDir, "incident-recorder"), { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { recursive: true, mode: 0o700 });
	return runIncidentRecorderServiceWithActivation(agentDir, {
		...options,
		writerLifecycleContract: {
			activationGenerationDigest: "a".repeat(64),
			revalidateActivation: () => ({ state: "valid" }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		},
	});
}

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

class FaultingSignalSource implements IncidentRecorderServiceSignalSource {
	private readonly listeners = new Map<RecorderSignal, () => void>();
	readonly calls: string[] = [];

	constructor(
		private readonly onceFailures = new Map<RecorderSignal, unknown>(),
		private readonly offFailures = new Map<RecorderSignal, unknown>(),
	) {}

	once(signal: RecorderSignal, listener: () => void): void {
		this.calls.push(`once:${signal}`);
		this.listeners.set(signal, listener);
		if (this.onceFailures.has(signal)) throw this.onceFailures.get(signal);
	}

	off(signal: RecorderSignal, listener: () => void): void {
		this.calls.push(`off:${signal}`);
		if (this.offFailures.has(signal)) throw this.offFailures.get(signal);
		if (this.listeners.get(signal) === listener) this.listeners.delete(signal);
	}

	emit(signal: RecorderSignal): void {
		const listener = this.listeners.get(signal);
		this.listeners.delete(signal);
		listener?.();
	}

	has(signal: RecorderSignal): boolean {
		return this.listeners.has(signal);
	}
}

const roots: string[] = [];
const casHolderProcesses = new Map<number, { child: ChildProcess; processStartId: string }>();
const originalStorageHealthySentinel = process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL;

afterEach(() => {
	vi.restoreAllMocks();
	for (const [pid, holder] of casHolderProcesses) {
		try {
			if (getProcessStartId(pid) === holder.processStartId) holder.child.kill("SIGKILL");
		} catch {}
	}
	casHolderProcesses.clear();
	delete process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES;
	delete process.env.PRIME_TEST_STORAGE_LINES;
	if (originalStorageHealthySentinel === undefined) delete process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL;
	else process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL = originalStorageHealthySentinel;
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { root: string; agentDir: string; binDir: string; eventsPath: string } {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-recorder-service-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const binDir = join(root, "bin");
	mkdirSync(agentDir, { mode: 0o700 });
	mkdirSync(binDir, { mode: 0o700 });
	return { root, agentDir, binDir, eventsPath: join(root, "events.log") };
}

function writeExecutable(path: string, body: string): void {
	writeFileSync(path, `#!${process.execPath}\n${body}\n`, { mode: 0o700 });
	chmodSync(path, 0o700);
}

function writeExpiredPublishedIncident(
	agentDir: string,
	runId: string,
	terminalRelayDisposition = "relayed",
	publishedState: "complete" | "incomplete" = "incomplete",
	terminalOccurrenceId = "12121212-1212-4212-8212-121212121212",
	producerId = "13131313-1313-4313-8313-131313131313",
	publishedSealKind: "canonical" | "fence" = "canonical",
): string {
	const incidentId = `expired-${runId}`;
	const runToken = "11111111-1111-4111-8111-111111111111";
	const retentionAnchorWallTimeMs = Date.parse("2000-01-01T00:00:00.000Z");
	const canonicalSeal = testServiceSeal(runId, runToken, terminalOccurrenceId, producerId);
	const seal = publishedSealKind === "canonical" ? canonicalSeal : testFenceOnlyServiceSeal(runId, runToken);
	if (publishedState === "complete" && publishedSealKind === "fence")
		throw new Error("a fence-only service seal cannot publish a complete fixture");
	const complete = completeProjectionForSeal(runId, runToken, canonicalSeal, retentionAnchorWallTimeMs);
	const finalized = finalizeIncidentRecorderProjection({
		incidentsDirectory: join(agentDir, "incidents"),
		incidentId,
		runIdentity: { runId, runToken },
		runHistory:
			publishedState === "complete" ? complete.runHistory : incompleteProjectionForSeal(runId, runToken, seal),
		terminalExpectations:
			publishedState === "complete"
				? complete.terminalExpectations
				: {
						supervisorExit: { state: "unavailable", reason: "service_lifecycle_fixture" },
						wrapperTerminal: { state: "unavailable", reason: "service_lifecycle_fixture" },
						serviceTerminal:
							seal.terminal.frontier === null
								? { state: "unavailable", reason: "service_terminal_replay_unavailable" }
								: { state: "available", frontier: seal.terminal.frontier },
					},
		classification: { value: "unknown", causeLayer: "application" },
		exit: { code: null, signal: null },
		retentionAnchorWallTimeMs,
		stoppedTarget: { captureState: publishedState, artifacts: [] },
		wrapperLoss: {
			finalQueuedTailLoss: { records: 0, bytes: 0 },
			emitterFinalTailLoss: { records: 0, bytes: 0 },
		},
		serviceSeal: {
			terminalRelayDisposition,
			emitterLoss: seal.loss.emitter,
			drainTimeoutLoss: {
				definite: seal.loss.drainTimeout.definite,
				uncertain: seal.loss.drainTimeout.uncertain,
			},
			terminalRelayLoss: {
				definite: seal.loss.terminalRelay.definite,
				uncertain: seal.loss.terminalRelay.uncertain,
			},
		},
		...(publishedState === "complete"
			? { assertProjectionLeaseUsable: () => {}, releaseProjectionLease: () => {} }
			: {}),
	});
	if (finalized.publication === "ambiguous" || finalized.state !== publishedState)
		throw new Error("service lifecycle published incident fixture did not finalize");
	const authority = persistIncidentRetentionAuthority({
		incidentDirectory: finalized.incidentDirectory,
		finalizationId: finalized.finalizationId,
		runId,
		outcome: finalized.state,
		retentionAnchorWallTimeMs,
	});
	if (authority.state !== "authorized")
		throw new Error(`service lifecycle published incident fixture has no retention authority: ${authority.reason}`);
	return finalized.incidentDirectory;
}

function publishedFinalizationId(incidentDirectory: string): string {
	const manifest = JSON.parse(readFileSync(join(incidentDirectory, "finalization-manifest.json"), "utf8")) as {
		finalizationId?: unknown;
	};
	if (typeof manifest.finalizationId !== "string") throw new Error("missing published finalization ID");
	return manifest.finalizationId;
}

function writeCanonicalIncompleteIncidentPins(
	incidentDirectory: string,
	runId: string,
	anchorWallTimeMs: number,
): void {
	const fromWallTimeMs = anchorWallTimeMs - 30 * 60 * 1_000;
	const throughWallTimeMs = anchorWallTimeMs + 15 * 60 * 1_000;
	const retainUntilWallTimeMs = anchorWallTimeMs + INCIDENT_DIAGNOSTIC_RETENTION_MS;
	writeServiceTestJson(join(incidentDirectory, "journal-pin-request.json"), {
		version: 1,
		state: "pending",
		runId,
		anchorWallTimeMs,
		fromWallTimeMs,
		throughWallTimeMs,
		resolveAfterWallTimeMs: throughWallTimeMs,
		retainUntilWallTimeMs,
	});
	writeServiceTestJson(join(incidentDirectory, "sysdig-pin-request.json"), {
		version: 1,
		runId,
		anchorWallTimeMs,
		fromWallTimeMs,
		throughWallTimeMs,
		resolveAfterWallTimeMs: throughWallTimeMs,
		requestedAtWallTimeMs: anchorWallTimeMs,
		retainUntilWallTimeMs,
		ringBasePath: join(incidentDirectory, ".fixture-sysdig-ring"),
		initialRingSnapshot: {
			observedAtWallTimeMs: anchorWallTimeMs,
			candidates: [],
			issues: [],
		},
	});
	for (const provider of ["journal", "sysdig"] as const)
		writeServiceTestJson(join(incidentDirectory, `${provider}-pin-incomplete.json`), {
			version: 1,
			state: "pending_or_incomplete",
			provider,
			reason: "service_lifecycle_fixture",
			runId,
			anchorWallTimeMs,
			fromWallTimeMs,
			throughWallTimeMs,
		});
}

function withTimeout<T>(
	promise: Promise<T>,
	milliseconds = 5_000,
	message = "isolated recorder service timed out",
): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error(message)), milliseconds);
		promise.then(
			(value) => {
				clearTimeout(timer);
				resolve(value);
			},
			(error: unknown) => {
				clearTimeout(timer);
				reject(error);
			},
		);
	});
}

async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
	try {
		await promise;
	} catch (error) {
		return error;
	}
	throw new Error("expected recorder service rejection");
}

function waitForAbort(signal: AbortSignal): Promise<void> {
	return new Promise<void>((resolve) => {
		if (signal.aborted) resolve();
		else signal.addEventListener("abort", () => resolve(), { once: true });
	});
}

function mockReadyServiceCompactor(close: () => Promise<void> | void = () => {}): void {
	vi.spyOn(IncidentRecorderWriter.prototype, "start").mockResolvedValue(undefined);
	vi.spyOn(IncidentRecorderWriter.prototype, "journalReady", "get").mockReturnValue(true);
	vi.spyOn(IncidentRecorderCompactor.prototype, "storageMode", "get").mockReturnValue("normal");
	vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
		this: IncidentRecorderCompactor,
		...args: Parameters<IncidentRecorderCompactor["run"]>
	) {
		const [runOptions] = args;
		runOptions.onStorageMode?.("normal");
		await runOptions.onNormalWriterAdmission?.();
		runOptions.onReaderReady?.();
		await waitForAbort(runOptions.signal);
		await close();
	});
}

async function waitForFileText(path: string, expected: readonly string[]): Promise<void> {
	for (let attempt = 0; attempt < 200; attempt += 1) {
		const value = existsSync(path) ? readFileSync(path, "utf8") : "";
		if (expected.every((item) => value.includes(item))) return;
		await new Promise<void>((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`timed out waiting for isolated recorder events: ${expected.join(", ")}`);
}

async function waitForCondition(condition: () => boolean, message: string, attempts = 300): Promise<void> {
	for (let attempt = 0; attempt < attempts; attempt += 1) {
		if (condition()) return;
		await new Promise<void>((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`timed out waiting for ${message}`);
}

async function startServiceLifecycleCasHolder(recorderRoot: string): Promise<{ release: () => Promise<void> }> {
	const script = fileURLToPath(new URL("./fixtures/incident-recorder-cas-holder.ts", import.meta.url));
	const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	const child = spawn(process.execPath, ["--import", tsxLoader, script, recorderRoot], {
		stdio: ["pipe", "pipe", "pipe"],
	});
	if (!child.pid) throw new Error("service lifecycle CAS holder did not start");
	const pid = child.pid;
	const processStartId = getProcessStartId(pid);
	if (!processStartId) throw new Error("service lifecycle CAS holder has no stable process identity");
	casHolderProcesses.set(pid, { child, processStartId });
	let stdout = "";
	let stderr = "";
	child.stdout?.setEncoding("utf8");
	child.stderr?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		stdout += chunk;
	});
	child.stderr?.on("data", (chunk: string) => {
		stderr += chunk;
	});
	await waitForCondition(
		() => stdout.includes("ready\n") || child.exitCode !== null,
		`service lifecycle CAS holder readiness: ${stderr}`,
	);
	if (!stdout.includes("ready\n")) throw new Error(`service lifecycle CAS holder exited before readiness: ${stderr}`);
	return {
		release: async () => {
			if (child.exitCode === null && getProcessStartId(pid) === processStartId) child.stdin?.end("release\n");
			await waitForCondition(
				() => stdout.includes("released\n") && child.exitCode !== null,
				`service lifecycle CAS holder release: ${stderr}`,
			);
			casHolderProcesses.delete(pid);
		},
	};
}

function writeServiceTestJson(path: string, value: unknown): string {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const bytes = `${JSON.stringify(value)}\n`;
	writeFileSync(path, bytes, { mode: 0o600 });
	return bytes;
}

function writeServiceTestCapturedArtifact(
	agentDir: string,
	runId: string,
	sourcePath: string,
	encoding: string,
): { algorithm: "sha256"; digest: string; bytes: number; path: string; encoding: string } {
	const bytes = readFileSync(sourcePath);
	const digest = createHash("sha256").update(bytes).digest("hex");
	const recorderRoot = join(agentDir, "incident-recorder");
	const casPath = join(recorderRoot, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
	const leasePath = join(
		recorderRoot,
		"refs",
		"runs",
		createHash("sha256").update(runId).digest("hex"),
		`cas-${digest}.blob`,
	);
	if (!existsSync(casPath)) {
		mkdirSync(dirname(casPath), { recursive: true, mode: 0o700 });
		writeFileSync(casPath, bytes, { mode: 0o600 });
	}
	if (!existsSync(leasePath)) {
		mkdirSync(dirname(leasePath), { recursive: true, mode: 0o700 });
		linkSync(casPath, leasePath);
	}
	return { algorithm: "sha256", digest, bytes: bytes.length, path: casPath, encoding };
}

function serviceTestTimestamp(monotonicNs = "1"): { wallTime: string; monotonicNs: string } {
	return { wallTime: "2026-08-31T00:00:00.000Z", monotonicNs };
}

function serviceTestLaunchControl(socketPath: string): Record<string, unknown> {
	return {
		version: 2,
		canonical: false,
		purpose: "content-addressed-launch-index",
		socketPath,
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
	};
}

function serviceTestProcessControl(runToken: string): Record<string, unknown> {
	return {
		runToken,
		machineId: "00000000000000000000000000000000",
		bootId: "00000000-0000-4000-8000-000000000000",
		systemdInvocationId: null,
		pid: 2_147_483_647,
		processStartId: "proc:1",
		observed: serviceTestTimestamp(),
		runtimeCategory: "foreign",
		nodeFatalReportsEnabled: false,
		orphanPolicy: "fail-open",
		wrapperDeathSignalsSupervisor: false,
	};
}

function serviceTestBarrierExpectation(runId: string, runToken: string): Record<string, unknown> {
	return {
		version: 1,
		runId,
		runToken,
		wrapperPid: 2_147_483_647,
		wrapperStartId: "proc:1",
		finalQueuedTailLoss: { records: 0, bytes: 0 },
		emitterFinalTailLoss: { records: 0, bytes: 0 },
		exitCode: "unavailable",
		exitSignal: "unavailable",
	};
}

function diagnosticProviderManifest(provider: string, path: string, format: string): Record<string, unknown> {
	const property = (key: string, value: unknown) => ({ key: { type: "string", value: key }, value });
	return {
		$diagnosticType: "object",
		id: 1,
		properties: [
			property("provider", provider),
			property("artifacts", {
				$diagnosticType: "array",
				id: 2,
				properties: [
					property("0", {
						$diagnosticType: "object",
						id: 3,
						properties: [property("path", path), property("format", format)],
					}),
				],
			}),
		],
	};
}

function stoppedServiceRun(
	target: ReturnType<typeof fixture>,
	runId: string,
	runToken: string,
	runName = `2026-08-31T00-00-00.000Z-${runId}`,
): string {
	const runDir = join(target.agentDir, "incident-recorder", "runs", runName);
	mkdirSync(runDir, { recursive: true, mode: 0o700 });
	writeServiceTestJson(
		join(runDir, "launch.json"),
		serviceTestLaunchControl(join(target.root, `${runId}.stopped.sock`)),
	);
	writeServiceTestJson(join(runDir, "process.json"), serviceTestProcessControl(runToken));
	writeServiceTestJson(
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
	return runDir;
}

function writeLiveServiceProxy(runDir: string): void {
	const processStartId = getProcessStartId(process.pid);
	if (!processStartId) throw new Error("service lifecycle test process identity unavailable");
	writeServiceTestJson(join(runDir, ".recorder-active"), {
		role: "wrapper-proxy",
		machineId: readFileSync("/etc/machine-id", "utf8").trim(),
		bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
		pid: process.pid,
		processStartId,
		created: { wallTime: new Date().toISOString(), monotonicNs: process.hrtime.bigint().toString() },
	});
}

function testServiceSeal(runId: string, runToken: string, terminalOccurrenceId: string, producerId: string) {
	return {
		schemaVersion: 1 as const,
		state: "sealed" as const,
		runId,
		runToken,
		terminal: {
			type: "capture_channel_terminal" as const,
			admission: {
				accepted: true as const,
				occurrenceId: terminalOccurrenceId,
				disposition: "locally_admitted" as const,
			},
			frontier: {
				occurrenceId: terminalOccurrenceId,
				producerId,
				type: "capture_channel_terminal" as const,
				firstProducerSequence: "1",
				lastProducerSequence: "1",
				firstWrapperSequence: "1",
				lastWrapperSequence: "1",
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
	};
}

function testFenceOnlyServiceSeal(runId: string, runToken: string) {
	return {
		schemaVersion: 1 as const,
		state: "sealed" as const,
		runId,
		runToken,
		terminal: {
			type: "capture_channel_terminal" as const,
			admission: null,
			frontier: null,
		},
		loss: {
			emitter: { records: 0, bytes: 0 },
			drainTimeout: {
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 0, bytes: 0 },
			},
			terminalRelay: {
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 1, bytes: 0 },
			},
		},
	};
}

function readIncompleteServiceCompletion(runDir: string): {
	finalizationId: string;
	retentionAnchorWallTimeMs: number;
} {
	const completion = JSON.parse(readFileSync(join(runDir, ".service-finalization-complete"), "utf8")) as {
		schemaVersion?: unknown;
		state?: unknown;
		runId?: unknown;
		finalizationId?: unknown;
		outcome?: unknown;
		retentionAnchorWallTimeMs?: unknown;
	};
	expect(completion).toMatchObject({
		schemaVersion: 2,
		state: "incident_reclaimable",
		outcome: "incomplete",
	});
	if (
		typeof completion.finalizationId !== "string" ||
		!/^[0-9a-f]{64}$/.test(completion.finalizationId) ||
		!Number.isSafeInteger(completion.retentionAnchorWallTimeMs)
	) {
		throw new Error("missing canonical incomplete service completion");
	}
	return {
		finalizationId: completion.finalizationId,
		retentionAnchorWallTimeMs: Number(completion.retentionAnchorWallTimeMs),
	};
}

interface ServicePublicationConflictProof {
	schemaVersion: 1;
	kind: "service_finalization_publication_conflict";
	runId: string;
	runToken: string;
	publishedFinalizationId: string;
	publishedState: "complete" | "incomplete" | "corrupt";
	publishedRetentionAnchorWallTimeMs: number;
	publishedServiceTerminalRelayDisposition: string;
	intendedFinalizationId: string;
	intendedState: "complete" | "incomplete" | "corrupt";
	intendedRetentionAnchorWallTimeMs: number;
	intendedServiceTerminalRelayDisposition: string;
	reason: "published_finalization_conflict";
}

function readPublicationConflictProof(runDir: string): ServicePublicationConflictProof {
	const path = join(runDir, "service-finalization-publication-conflict.json");
	const bytes = readFileSync(path, "utf8");
	const proof = JSON.parse(bytes) as ServicePublicationConflictProof;
	expect(Object.keys(proof).sort()).toEqual(
		[
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"publishedFinalizationId",
			"publishedState",
			"publishedRetentionAnchorWallTimeMs",
			"publishedServiceTerminalRelayDisposition",
			"intendedFinalizationId",
			"intendedState",
			"intendedRetentionAnchorWallTimeMs",
			"intendedServiceTerminalRelayDisposition",
			"reason",
		].sort(),
	);
	expect(proof).toMatchObject({
		schemaVersion: 1,
		kind: "service_finalization_publication_conflict",
		reason: "published_finalization_conflict",
	});
	expect(proof.publishedFinalizationId).toMatch(/^[0-9a-f]{64}$/);
	expect(proof.intendedFinalizationId).toMatch(/^[0-9a-f]{64}$/);
	expect(proof.intendedFinalizationId).not.toBe(proof.publishedFinalizationId);
	expect(Number.isSafeInteger(proof.publishedRetentionAnchorWallTimeMs)).toBe(true);
	expect(Number.isSafeInteger(proof.intendedRetentionAnchorWallTimeMs)).toBe(true);
	expect(bytes).toBe(`${JSON.stringify(proof)}\n`);
	const stat = statSync(path);
	expect(stat.isFile()).toBe(true);
	expect(stat.nlink).toBe(1);
	expect(stat.mode & 0o077).toBe(0);
	return proof;
}

function readPublicationConflictCompletion(
	runDir: string,
	proof = readPublicationConflictProof(runDir),
): {
	publishedFinalizationId: string;
	intendedFinalizationId: string;
	conflictProofSha256: string;
	retentionAnchorWallTimeMs: number;
} {
	const completion = JSON.parse(readFileSync(join(runDir, ".service-finalization-complete"), "utf8")) as {
		schemaVersion?: unknown;
		state?: unknown;
		runId?: unknown;
		publishedFinalizationId?: unknown;
		intendedFinalizationId?: unknown;
		conflictProofSha256?: unknown;
		retentionAnchorWallTimeMs?: unknown;
	};
	expect(Object.keys(completion).sort()).toEqual(
		[
			"schemaVersion",
			"state",
			"runId",
			"publishedFinalizationId",
			"intendedFinalizationId",
			"conflictProofSha256",
			"retentionAnchorWallTimeMs",
		].sort(),
	);
	expect(completion).toEqual({
		schemaVersion: 2,
		state: "publication_conflict_reclaimable",
		runId: proof.runId,
		publishedFinalizationId: proof.publishedFinalizationId,
		intendedFinalizationId: proof.intendedFinalizationId,
		conflictProofSha256: createHash("sha256")
			.update(`${JSON.stringify(proof)}\n`)
			.digest("hex"),
		retentionAnchorWallTimeMs: Math.max(
			proof.publishedRetentionAnchorWallTimeMs,
			proof.intendedRetentionAnchorWallTimeMs,
		),
	});
	return completion as {
		publishedFinalizationId: string;
		intendedFinalizationId: string;
		conflictProofSha256: string;
		retentionAnchorWallTimeMs: number;
	};
}

function expectIncompleteRetentionAuthority(
	incidentDirectory: string,
	runId: string,
	completion: ReturnType<typeof readIncompleteServiceCompletion>,
): void {
	expect(JSON.parse(readFileSync(join(incidentDirectory, "retention-authority.json"), "utf8"))).toEqual({
		schemaVersion: 1,
		kind: "incident_retention_authority",
		finalizationId: completion.finalizationId,
		runId,
		outcome: "incomplete",
		retentionAnchorWallTimeMs: completion.retentionAnchorWallTimeMs,
	});
}

function writeDurableServiceSeal(
	runDir: string,
	runId: string,
	runToken: string,
	terminalOccurrenceId: string,
	producerId: string,
	retentionAnchorWallTimeMs = 1_800_000_000_000,
) {
	writeServiceTestJson(join(runDir, "service-finalization-stopped-observation.json"), {
		schemaVersion: 1,
		kind: "service_stopped_observation",
		runId,
		runToken,
		firstObservedStoppedWallTimeMs: retentionAnchorWallTimeMs,
		disposition: "exact_first_observation",
	});
	writeServiceTestJson(join(runDir, "service-finalization-seal-intent.json"), {
		schemaVersion: 1,
		kind: "service_run_seal_intent",
		runId,
		runToken,
		terminalOccurrenceId,
		retentionAnchorWallTimeMs,
		stoppedObservationDisposition: "exact_first_observation",
	});
	const seal = testServiceSeal(runId, runToken, terminalOccurrenceId, producerId);
	writeServiceTestJson(join(runDir, "service-finalization-seal.json"), seal);
	return seal;
}

function writeDurableNormalServiceCompletion(input: {
	runDir: string;
	runId: string;
	runToken: string;
	terminalOccurrenceId: string;
	producerId: string;
	finalizationId: string;
	retentionAnchorWallTimeMs?: number;
}): void {
	const retentionAnchorWallTimeMs = input.retentionAnchorWallTimeMs ?? 1_800_000_000_000;
	writeDurableServiceSeal(
		input.runDir,
		input.runId,
		input.runToken,
		input.terminalOccurrenceId,
		input.producerId,
		retentionAnchorWallTimeMs,
	);
	writeServiceTestJson(join(input.runDir, `service-finalization-normal-authority-${input.finalizationId}.json`), {
		schemaVersion: 1,
		kind: "service_normal_retention_authority",
		runId: input.runId,
		runToken: input.runToken,
		finalizationId: input.finalizationId,
		classification: "normal",
		analysisState: "complete",
		retentionAnchorWallTimeMs,
		terminalOccurrenceId: input.terminalOccurrenceId,
	});
	writeServiceTestJson(join(input.runDir, ".service-finalization-complete"), {
		schemaVersion: 2,
		state: "normal_reclaimable",
		runId: input.runId,
		finalizationId: input.finalizationId,
		classification: "normal",
		retentionAnchorWallTimeMs,
	});
}

function writeBoundExpiredPublishedIncident(
	target: ReturnType<typeof fixture>,
	runId: string,
): { incidentDirectory: string; runDir: string } {
	const runToken = "11111111-1111-4111-8111-111111111111";
	const terminalOccurrenceId = "12121212-1212-4212-8212-121212121212";
	const retentionAnchorWallTimeMs = Date.parse("2000-01-01T00:00:00.000Z");
	const runDir = stoppedServiceRun(target, runId, runToken, `expired-${runId}`);
	// This fixture represents a locally proven stopped process. A synthetic
	// cross-machine identity is intentionally unreclaimable under the strict
	// discovery contract.
	writeServiceTestJson(join(runDir, "process.json"), {
		...serviceTestProcessControl(runToken),
		machineId: readFileSync("/etc/machine-id", "utf8").trim(),
		bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
	});
	const incidentDirectory = writeExpiredPublishedIncident(target.agentDir, runId);
	const finalizationId = publishedFinalizationId(incidentDirectory);
	writeDurableServiceSeal(
		runDir,
		runId,
		runToken,
		terminalOccurrenceId,
		"13131313-1313-4313-8313-131313131313",
		retentionAnchorWallTimeMs,
	);
	writeServiceTestJson(join(runDir, `service-finalization-publication-intent-${finalizationId}.json`), {
		schemaVersion: 1,
		kind: "service_finalization_publication_intent",
		runId,
		finalizationId,
	});
	writeServiceTestJson(join(runDir, ".service-finalization-complete"), {
		schemaVersion: 2,
		state: "incident_reclaimable",
		runId,
		finalizationId,
		outcome: "incomplete",
		retentionAnchorWallTimeMs,
	});
	writeCanonicalIncompleteIncidentPins(incidentDirectory, runId, retentionAnchorWallTimeMs);
	return { incidentDirectory, runDir };
}

function providerCaptureFrontier(runId: string, names: readonly string[]): Record<string, unknown> {
	const hash = createHash("sha256");
	for (const name of [...names].sort()) hash.update(name).update("\0");
	return {
		schemaVersion: 1,
		kind: "provider_artifact_capture_frontier",
		runId,
		referenceCount: names.length,
		referenceSetSha256: hash.digest("hex"),
	};
}

function writeEmptyProviderCaptureFrontier(runDir: string, runId: string): void {
	const agentDir = dirname(dirname(dirname(runDir)));
	mkdirSync(join(agentDir, "incident-recorder", "refs", "runs", createHash("sha256").update(runId).digest("hex")), {
		recursive: true,
		mode: 0o700,
	});
	writeServiceTestJson(
		join(runDir, "evidence", "provider-artifacts", "capture-frontier.json"),
		providerCaptureFrontier(runId, []),
	);
}

function writeZeroArtifactCaptureCompletion(runDir: string, runId: string): void {
	writeServiceTestJson(join(runDir, "raw-reports", "capture-complete.json"), {
		schemaVersion: 1,
		kind: "node_report_capture_complete",
		state: "complete",
		runId,
		reasons: [],
	});
	writeServiceTestJson(join(runDir, "evidence", "provider-artifacts", "capture-complete.json"), {
		schemaVersion: 1,
		kind: "provider_artifact_capture_complete",
		state: "complete",
		runId,
		reasons: [],
	});
	writeEmptyProviderCaptureFrontier(runDir, runId);
}

function incompleteProjectionForSeal(
	runId: string,
	runToken: string,
	seal: {
		terminal: {
			frontier: IncidentRecorderRelayFrontierExpectation | null;
		};
	},
) {
	const frontier = seal.terminal.frontier;
	return {
		state: "incomplete" as const,
		reason: "service_lifecycle_test_projection",
		projection: {
			version: 1 as const,
			runId,
			fromWallTimeMs: 0,
			throughWallTimeMs: Number.MAX_SAFE_INTEGER,
			events: frontier
				? [
						{
							identityKey: createHash("sha256")
								.update(`${runId}\0${runToken}\0${frontier.occurrenceId}`)
								.digest("hex"),
							identity: {
								runId,
								runToken,
								producerId: frontier.producerId,
								occurrenceId: frontier.occurrenceId,
							},
							semanticFingerprint: createHash("sha256").update(`semantic:${runId}`).digest("hex"),
							occurrenceReference: `service-test:${runId}`,
							source: "recorder-control",
							type: "capture_channel_terminal",
							encoding: "none",
							payloadKind: "control" as const,
							terminal: true,
							metadata: {},
							eventWallTimeMs: "1800000000000",
							eventMonotonicNs: "1",
							wrapperOrder: [frontier.firstWrapperSequence],
							producerOrder: [frontier.firstProducerSequence],
							cursors: [`service-test:${frontier.occurrenceId}`],
							transportIdentity: {},
							cas: {
								digest: createHash("sha256").update(`cas:${runId}`).digest("hex"),
								bytes: 0,
								path: `service-test-cas:${runId}`,
							},
						},
					]
				: [],
			terminalEvents: [],
			finalizationCandidates: [],
			ordering: {
				semantics: "partial_order" as const,
				causalRelations: [],
				presentationTieBreak: "wall_time_then_identity_key" as const,
				unrelatedPresentationOrderIsCausal: false as const,
				scope: "complete_snapshot" as const,
			},
			evidence: [],
		},
	};
}

function completeProjectionForSeal(
	runId: string,
	runToken: string,
	seal: ReturnType<typeof testServiceSeal>,
	retentionAnchorWallTimeMs: number,
): {
	runHistory: Extract<IncidentRecorderRunHistoryResult, { state: "complete" }>;
	terminalExpectations: IncidentRecorderFinalizationInput["terminalExpectations"];
} {
	const event = (
		type: "supervisor_exit" | "capture_channel_terminal",
		source: "recorder-events" | "recorder-control",
		occurrenceId: string,
		producerId: string,
		sequence: string,
		wallTimeMs: number,
	): IncidentRecorderRunHistoryEvent => {
		const identityKey = createHash("sha256").update(`${runId}\0${occurrenceId}`).digest("hex");
		return {
			identityKey,
			identity: { runId, runToken, producerId, occurrenceId },
			semanticFingerprint: createHash("sha256").update(`semantic:${identityKey}`).digest("hex"),
			occurrenceReference: `service-test:${occurrenceId}`,
			source,
			type,
			encoding: "none",
			payloadKind: type === "supervisor_exit" ? ("derived-scalar" as const) : ("control" as const),
			terminal: type === "capture_channel_terminal",
			metadata: {},
			eventWallTimeMs: String(wallTimeMs),
			eventMonotonicNs: sequence,
			wrapperOrder: [sequence],
			producerOrder: [sequence],
			cursors: [`service-test:${occurrenceId}`],
			transportIdentity: {},
			cas: {
				digest: createHash("sha256").update(`cas:${identityKey}`).digest("hex"),
				bytes: 0,
				path: `service-test-cas:${identityKey}`,
			},
		};
	};
	const supervisorOccurrenceId = "14141414-1414-4414-8414-141414141414";
	const wrapperOccurrenceId = "15151515-1515-4515-8515-151515151515";
	const wrapperProducerId = "16161616-1616-4616-8616-161616161616";
	const supervisor = event(
		"supervisor_exit",
		"recorder-events",
		supervisorOccurrenceId,
		wrapperProducerId,
		"1",
		retentionAnchorWallTimeMs,
	);
	const wrapper = event(
		"capture_channel_terminal",
		"recorder-control",
		wrapperOccurrenceId,
		wrapperProducerId,
		"2",
		retentionAnchorWallTimeMs + 1,
	);
	const service = event(
		"capture_channel_terminal",
		"recorder-control",
		seal.terminal.frontier.occurrenceId,
		seal.terminal.frontier.producerId,
		seal.terminal.frontier.firstProducerSequence,
		retentionAnchorWallTimeMs + 2,
	);
	const frontier = (
		candidate: IncidentRecorderRunHistoryEvent,
		type: IncidentRecorderRelayFrontierExpectation["type"],
	): IncidentRecorderRelayFrontierExpectation => ({
		type,
		occurrenceId: candidate.identity.occurrenceId,
		producerId: candidate.identity.producerId,
		firstProducerSequence: candidate.producerOrder[0] ?? "0",
		lastProducerSequence: candidate.producerOrder[0] ?? "0",
		firstWrapperSequence: candidate.wrapperOrder[0] ?? "0",
		lastWrapperSequence: candidate.wrapperOrder[0] ?? "0",
	});
	return {
		runHistory: {
			state: "complete" as const,
			projection: {
				version: 1 as const,
				runId,
				fromWallTimeMs: 0,
				throughWallTimeMs: retentionAnchorWallTimeMs + 2,
				events: [supervisor, wrapper, service],
				terminalEvents: [wrapper, service].map((candidate) => ({
					identityKey: candidate.identityKey,
					type: candidate.type,
					source: candidate.source,
					eventWallTimeMs: candidate.eventWallTimeMs,
					basis: "terminal_flag" as const,
				})),
				finalizationCandidates: [
					{
						role: "supervisor_exit" as const,
						identityKey: supervisor.identityKey,
						basis: "type_and_source_candidate" as const,
						qualification: "candidate_requires_expectation_match" as const,
					},
					...[wrapper, service].map((candidate) => ({
						role: "capture_channel_terminal" as const,
						identityKey: candidate.identityKey,
						basis: "type_source_and_terminal_flag_candidate" as const,
						qualification: "candidate_requires_expectation_match" as const,
					})),
				],
				ordering: {
					semantics: "partial_order" as const,
					causalRelations: [],
					presentationTieBreak: "wall_time_then_identity_key" as const,
					unrelatedPresentationOrderIsCausal: false as const,
					scope: "complete_snapshot" as const,
				},
				evidence: [],
			},
			snapshot: {
				version: 1 as const,
				fingerprint: createHash("sha256").update(`snapshot:${runId}`).digest("hex"),
				segmentRecordCount: 3,
				segmentRecoveryGapCount: 0,
				segmentScannedSegments: 1,
				segmentScannedRecords: 3,
				segmentScannedIndexBytes: 1,
				legacyOccurrenceCount: 0,
				validatedCasDigestCount: 3,
			},
		},
		terminalExpectations: {
			supervisorExit: { state: "available" as const, frontier: frontier(supervisor, "supervisor_exit") },
			wrapperTerminal: {
				state: "available" as const,
				frontier: frontier(wrapper, "capture_channel_terminal"),
			},
			serviceTerminal: {
				state: "available" as const,
				frontier: frontier(service, "capture_channel_terminal"),
			},
		},
	};
}

async function runReadyServiceUntil(
	agentDir: string,
	condition: () => boolean,
	description: string,
	attempts = 300,
): Promise<void> {
	const signals = new TestSignalSource();
	let resolveReady: () => void = () => {};
	const ready = new Promise<void>((resolve) => {
		resolveReady = resolve;
	});
	let running: Promise<void> | undefined;
	try {
		running = runIncidentRecorderService(agentDir, {
			notify: (fields) => {
				if (fields.includes("READY=1")) resolveReady();
			},
			signalSource: signals,
			writerStopDeadlineMs: 1_000,
		});
		running.catch(() => {});
		await withTimeout(ready, 10_000);
		await waitForCondition(condition, description, attempts);
	} finally {
		if (signals.size > 0) signals.emit("SIGTERM");
		if (running) await withTimeout(running, 10_000);
	}
}

function fakeSystemdCatSource(exitImmediately = false): string {
	return `
const fs = require("node:fs");
const events = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
const record = (value) => fs.appendFileSync(events, value + "\\n");
record(process.env.NOTIFY_SOCKET ? "systemd-cat-notify-leak" : "systemd-cat-started");
${exitImmediately ? "process.exit(1);" : 'process.stdin.resume(); process.stdin.once("end", () => { record("systemd-cat-end"); process.exit(0); }); process.once("SIGTERM", () => { record("systemd-cat-term"); process.exit(0); });'}
if (process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES) process.stdin.on("data", (chunk) => fs.appendFileSync(process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES, chunk));
`;
}

function fakeJournalctlSource(exitImmediately = false): string {
	return `
const fs = require("node:fs");
const events = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
const record = (value) => fs.appendFileSync(events, value + "\\n");
record(process.env.NOTIFY_SOCKET ? "journalctl-notify-leak" : "journalctl-started");
${exitImmediately ? "process.exit(1);" : 'if (!process.argv.includes("--follow")) process.exit(0); process.once("SIGTERM", () => { record("journalctl-term"); process.exit(0); }); setInterval(() => {}, 1000);'}
`;
}

describe("incident recorder service lifecycle", () => {
	it("announces readiness only after startup and drains on SIGTERM", async () => {
		const target = fixture();
		const systemdCatPath = join(target.binDir, "systemd-cat");
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(systemdCatPath, fakeSystemdCatSource());
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousNotifySocket = process.env.NOTIFY_SOCKET;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.NOTIFY_SOCKET = "@isolated-recorder-test";
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: (fields) => {
					notifications.push([...fields]);
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(
				Promise.race([
					ready,
					running.then(() => {
						throw new Error("recorder service exited before readiness");
					}),
				]),
			);
			await waitForFileText(target.eventsPath, ["systemd-cat-started", "journalctl-started"]);
			signals.emit("SIGTERM");
			await withTimeout(running);
			const events = readFileSync(target.eventsPath, "utf8");
			expect(events).toContain("journalctl-term");
			expect(events).toContain("systemd-cat-end");
			expect(events).not.toContain("notify-leak");
			expect(notifications).toEqual([
				["READY=1", "STATUS=Incident recorder ready"],
				["STOPPING=1", "STATUS=Stopping after SIGTERM"],
			]);
			expect(signals.size).toBe(0);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousNotifySocket === undefined) delete process.env.NOTIFY_SOCKET;
			else process.env.NOTIFY_SOCKET = previousNotifySocket;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("does not overwrite a recovery transition while the startup readiness gate is pending", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		let storageMode: "normal" | "recovery-only" = "normal";
		vi.spyOn(IncidentRecorderCompactor.prototype, "storageMode", "get").mockImplementation(() => storageMode);
		vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			const [runOptions] = args;
			runOptions.onStorageMode?.("normal");
			await runOptions.onNormalWriterAdmission?.();
			runOptions.onReaderReady?.();
			queueMicrotask(() =>
				queueMicrotask(() =>
					queueMicrotask(() => {
						storageMode = "recovery-only";
						runOptions.onStorageMode?.("recovery-only", "startup_inspection_probe");
					}),
				),
			);
			await new Promise<void>((resolveClosed) => {
				if (runOptions.signal.aborted) resolveClosed();
				else runOptions.signal.addEventListener("abort", () => resolveClosed(), { once: true });
			});
		});
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		let resolveRecovery: () => void = () => {};
		const recovery = new Promise<void>((resolve) => {
			resolveRecovery = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: (fields) => {
					notifications.push([...fields]);
					if (fields.includes("STATUS=Incident recorder recovery-only: startup_inspection_probe"))
						resolveRecovery();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(recovery);
			await new Promise<void>((resolve) => setTimeout(resolve, 25));
			expect(notifications).toEqual([
				["READY=1", "STATUS=Incident recorder recovery-only: startup_inspection_probe"],
			]);
			expect(notifications.filter((fields) => fields.includes("READY=1"))).toHaveLength(1);
			expect(notifications.flat()).not.toContain("STATUS=Incident recorder ready");
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("binds normal prune continuation to a complete protection generation and restarts when it changes", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		vi.spyOn(retentionModule, "incidentRetentionNextDelayMs").mockReturnValue(10);
		const continuation = (sequence: number) => ({
			version: 1 as const,
			sessionId: `session-${sequence}`,
			storeInstanceId: "store-instance",
			highWaterSegmentSequence: 10,
			filterSha256: "a".repeat(64),
			segmentSequence: sequence,
		});
		const firstContinuation = continuation(1);
		const secondContinuation = continuation(2);
		const observed: Array<{
			generation: number;
			fingerprint: string;
			continuation: unknown;
			nowMs: number;
		}> = [];
		let pruneCalls = 0;
		vi.spyOn(IncidentRecorderCompactor.prototype, "pruneSegmentHistory").mockImplementation(
			(nowMs, protection, suppliedContinuation) => {
				observed.push({
					generation: protection.generation,
					fingerprint: protection.fingerprint,
					continuation: suppliedContinuation,
					nowMs,
				});
				pruneCalls += 1;
				if (pruneCalls === 1)
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 1,
						deletedBytes: 0,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: true,
						continuation: firstContinuation,
					};
				if (pruneCalls === 2) {
					const runId = "56565656-5656-4656-8656-565656565656";
					const runToken = "57575757-5757-4757-8757-575757575757";
					const runDir = stoppedServiceRun(target, runId, runToken, `2026-08-30T00-00-00.000Z-${runId}`);
					writeLiveServiceProxy(runDir);
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 1,
						deletedBytes: 0,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: true,
						continuation: secondContinuation,
					};
				}
				if (pruneCalls === 3)
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 0,
						deletedBytes: 0,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: false,
					};
				if (pruneCalls === 4)
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 1,
						deletedBytes: 0,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: true,
						continuation: secondContinuation,
					};
				return {
					deletedSegmentIds: [],
					corruptSegmentIds: [],
					examinedSegments: 0,
					deletedBytes: 0,
					locatorsInvalidated: false,
					requiresFullReconciliation: false,
					moreWork: false,
				};
			},
		);
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			await waitForCondition(() => pruneCalls >= 5, "five bounded segment prune passes");
			expect(observed[0].continuation).toBeUndefined();
			expect(observed[1].continuation).toEqual(firstContinuation);
			expect(observed[1].nowMs).toBe(observed[0].nowMs);
			expect(observed[1].generation).toBe(observed[0].generation);
			expect(observed[1].fingerprint).toBe(observed[0].fingerprint);
			expect(observed[2].continuation).toBeUndefined();
			expect(observed[2].nowMs).toBeGreaterThan(observed[1].nowMs);
			expect(observed[2].generation).toBeGreaterThan(observed[1].generation);
			expect(observed[2].fingerprint).not.toBe(observed[1].fingerprint);
			// Completion starts a fresh same-protection sweep with a new cutoff.
			expect(observed[3].continuation).toBeUndefined();
			expect(observed[3].nowMs).toBeGreaterThan(observed[2].nowMs);
			expect(observed[3].generation).toBe(observed[2].generation);
			expect(observed[3].fingerprint).toBe(observed[2].fingerprint);
			expect(observed[4].continuation).toEqual(secondContinuation);
			expect(observed[4].nowMs).toBe(observed[3].nowMs);
			expect(observed[4].generation).toBe(observed[3].generation);
			expect(observed[4].fingerprint).toBe(observed[3].fingerprint);
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("resets a failed normal prune continuation before retrying", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		vi.spyOn(retentionModule, "incidentRetentionNextDelayMs").mockReturnValue(10);
		const continuation = {
			version: 1 as const,
			sessionId: "failed-prune-retry",
			storeInstanceId: "store-instance",
			highWaterSegmentSequence: 10,
			filterSha256: "c".repeat(64),
			segmentSequence: 1,
		};
		const observedContinuations: unknown[] = [];
		const observedNowMs: number[] = [];
		let pruneCalls = 0;
		vi.spyOn(IncidentRecorderCompactor.prototype, "pruneSegmentHistory").mockImplementation(
			(nowMs, _protection, suppliedContinuation) => {
				observedContinuations.push(suppliedContinuation);
				observedNowMs.push(nowMs);
				pruneCalls += 1;
				if (pruneCalls === 1)
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 1,
						deletedBytes: 0,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: true,
						continuation,
					};
				if (pruneCalls === 2) throw new Error("segment store discarded during prune");
				return {
					deletedSegmentIds: [],
					corruptSegmentIds: [],
					examinedSegments: suppliedContinuation === undefined ? 1 : 0,
					deletedBytes: 0,
					locatorsInvalidated: false,
					requiresFullReconciliation: false,
					moreWork: false,
				};
			},
		);
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			await waitForCondition(() => pruneCalls >= 3, "failed segment prune retry");
			expect(observedContinuations).toEqual([undefined, continuation, undefined]);
			expect(observedNowMs[1]).toBe(observedNowMs[0]);
			expect(observedNowMs[2]).toBeGreaterThan(observedNowMs[1]);
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("defers a read-snapshot-blocked prune without losing its revisit anchor", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const revisitAnchor = {
			version: 1 as const,
			sessionId: "read-snapshot-revisit",
			storeInstanceId: "store-instance",
			highWaterSegmentSequence: 10,
			filterSha256: "b".repeat(64),
			segmentSequence: 1,
		};
		const observedContinuations: unknown[] = [];
		const observedNowMs: number[] = [];
		let pruneCalls = 0;
		let releaseReadSnapshot = false;
		let deletedAfterRelease = false;
		vi.spyOn(IncidentRecorderCompactor.prototype, "pruneSegmentHistory").mockImplementation(
			(nowMs, _protection, suppliedContinuation) => {
				observedContinuations.push(suppliedContinuation);
				observedNowMs.push(nowMs);
				pruneCalls += 1;
				if (pruneCalls === 1)
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 1,
						deletedBytes: 0,
						blockedByReadSnapshot: false,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: true,
						continuation: revisitAnchor,
					};
				if (!releaseReadSnapshot)
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 1,
						deletedBytes: 0,
						blockedByReadSnapshot: true,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: true,
					};
				deletedAfterRelease = true;
				return {
					deletedSegmentIds: ["released-segment"],
					corruptSegmentIds: [],
					examinedSegments: 1,
					deletedBytes: 4096,
					blockedByReadSnapshot: false,
					locatorsInvalidated: true,
					requiresFullReconciliation: true,
					moreWork: false,
				};
			},
		);
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			await waitForCondition(() => pruneCalls >= 2, "read-snapshot-blocked segment prune");
			const callsWhileBlocked = pruneCalls;
			await new Promise<void>((resolve) => setTimeout(resolve, 50));
			expect(pruneCalls).toBe(callsWhileBlocked);
			expect(deletedAfterRelease).toBe(false);
			releaseReadSnapshot = true;
			await waitForCondition(() => deletedAfterRelease, "released read-snapshot segment revisit");
			expect(observedContinuations[0]).toBeUndefined();
			expect(observedContinuations[1]).toEqual(revisitAnchor);
			expect(observedContinuations[2]).toEqual(revisitAnchor);
			expect(observedNowMs[1]).toBe(observedNowMs[0]);
			expect(observedNowMs[2]).toBe(observedNowMs[0]);
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			releaseReadSnapshot = true;
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("rebuilds retention protection after a deletion accounting rescan before pruning", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const expiredRunId = "67676767-6767-4676-8676-676767676767";
		const { incidentDirectory: expiredIncidentDir, runDir: expiredRunDir } = writeBoundExpiredPublishedIncident(
			target,
			expiredRunId,
		);
		const runIdAddedAcrossRescan = "68686868-6868-4686-8686-686868686868";
		let resolveRescanStarted: () => void = () => {};
		const rescanStarted = new Promise<void>((resolve) => {
			resolveRescanStarted = resolve;
		});
		let releaseRescan: () => void = () => {};
		const rescanRelease = new Promise<void>((resolve) => {
			releaseRescan = resolve;
		});
		let heldDeletionRescan = false;
		let pruneCallsAtRescanStart = 0;
		const observedProtectedRunIds: string[][] = [];
		vi.spyOn(IncidentRecorderCompactor.prototype, "pruneSegmentHistory").mockImplementation((_nowMs, protection) => {
			observedProtectedRunIds.push([...protection.protectedRunIds]);
			return {
				deletedSegmentIds: [],
				corruptSegmentIds: [],
				examinedSegments: 0,
				deletedBytes: 0,
				locatorsInvalidated: false,
				requiresFullReconciliation: false,
				moreWork: false,
			};
		});
		const originalInitializeStorageAccounting = IncidentRecorderCompactor.prototype.initializeStorageAccounting;
		vi.spyOn(IncidentRecorderCompactor.prototype, "initializeStorageAccounting").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["initializeStorageAccounting"]>
		) {
			const result = await originalInitializeStorageAccounting.apply(this, args);
			if (!heldDeletionRescan && !existsSync(expiredIncidentDir)) {
				heldDeletionRescan = true;
				pruneCallsAtRescanStart = observedProtectedRunIds.length;
				const runToken = "69696969-6969-4969-8969-696969696969";
				const runDir = stoppedServiceRun(
					target,
					runIdAddedAcrossRescan,
					runToken,
					`2026-08-30T00-00-00.000Z-${runIdAddedAcrossRescan}`,
				);
				writeLiveServiceProxy(runDir);
				resolveRescanStarted();
				await rescanRelease;
			}
			return result;
		});
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready, 5_000, "retention-rescan service readiness timed out");
			await withTimeout(rescanStarted, 5_000, "retention deletion accounting rescan timed out").catch(
				(error: unknown) => {
					const uncertaintyPath = join(target.agentDir, "incident-recorder", "retention-uncertainty.json");
					throw new Error(
						`retention fixture remained: incident=${JSON.stringify(
							existsSync(expiredIncidentDir) ? readdirSync(expiredIncidentDir).sort() : [],
						)} run=${JSON.stringify(
							existsSync(expiredRunDir) ? readdirSync(expiredRunDir).sort() : [],
						)} uncertainty=${existsSync(uncertaintyPath) ? readFileSync(uncertaintyPath, "utf8") : "missing"}`,
						{ cause: error },
					);
				},
			);
			expect(existsSync(expiredRunDir)).toBe(false);
			expect(observedProtectedRunIds).toHaveLength(pruneCallsAtRescanStart);
			releaseRescan();
			await waitForCondition(
				() => observedProtectedRunIds.length > pruneCallsAtRescanStart,
				"post-rescan retention protection rebuild and segment prune",
			);
			expect(observedProtectedRunIds[pruneCallsAtRescanStart]).toContain(runIdAddedAcrossRescan);
			expect(observedProtectedRunIds[pruneCallsAtRescanStart]).not.toContain(expiredRunId);
			await inspectIncidentRecorderRuns(target.agentDir);
			await inspectIncidentRecorderRuns(target.agentDir);
			expect(existsSync(expiredRunDir)).toBe(false);
			expect(readdirSync(dirname(expiredRunDir))).not.toContain(basename(expiredRunDir));
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			releaseRescan();
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("releases deletion-rerun maintenance after an inspection failure and resumes pin progress", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const expiredRunId = "6a6a6a6a-6a6a-46a6-86a6-6a6a6a6a6a6a";
		const { incidentDirectory: expiredIncidentDir, runDir: expiredRunDir } = writeBoundExpiredPublishedIncident(
			target,
			expiredRunId,
		);
		const inspectedRunId = "6b6b6b6b-6b6b-46b6-86b6-6b6b6b6b6b6b";
		const inspectedRunDir = stoppedServiceRun(target, inspectedRunId, "6c6c6c6c-6c6c-46c6-86c6-6c6c6c6c6c6c");
		writeLiveServiceProxy(inspectedRunDir);
		const inspectedProcessBytes = readFileSync(join(inspectedRunDir, "process.json"), "utf8");
		let insideRetention = false;
		let deletionObserved = false;
		let maintenanceHeld = false;
		let inspectionFailures = 0;
		let maintenanceEndCalls = 0;
		let pendingPinCalls = 0;
		let pendingPinCallsAfterFailure = 0;
		let deletionRescanStarted = false;
		let resolveDeletionRescanStarted: () => void = () => {};
		const deletionRescanStartedPromise = new Promise<void>((resolve) => {
			resolveDeletionRescanStarted = resolve;
		});
		let releaseDeletionRescan: () => void = () => {};
		const deletionRescanRelease = new Promise<void>((resolve) => {
			releaseDeletionRescan = resolve;
		});
		const originalBegin = IncidentRecorderCompactor.prototype.beginPinRetentionMaintenance;
		vi.spyOn(IncidentRecorderCompactor.prototype, "beginPinRetentionMaintenance").mockImplementation(function (
			this: IncidentRecorderCompactor,
		) {
			const began = originalBegin.call(this);
			if (began) maintenanceHeld = true;
			return began;
		});
		const originalEnd = IncidentRecorderCompactor.prototype.endPinRetentionMaintenance;
		vi.spyOn(IncidentRecorderCompactor.prototype, "endPinRetentionMaintenance").mockImplementation(function (
			this: IncidentRecorderCompactor,
		) {
			maintenanceEndCalls += 1;
			maintenanceHeld = false;
			return originalEnd.call(this);
		});
		const originalRetentionPass = retentionModule.runIncidentRetentionPass;
		vi.spyOn(retentionModule, "runIncidentRetentionPass").mockImplementation((options) => {
			insideRetention = true;
			try {
				const result = originalRetentionPass(options);
				if (!options.recoveryOnly && result.deletedEntries > 0) deletionObserved = true;
				return result;
			} finally {
				insideRetention = false;
			}
		});
		const originalProcessPendingPins = IncidentRecorderCompactor.prototype.processPendingPins;
		vi.spyOn(IncidentRecorderCompactor.prototype, "processPendingPins").mockImplementation(function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["processPendingPins"]>
		) {
			pendingPinCalls += 1;
			if (inspectionFailures > 0) pendingPinCallsAfterFailure += 1;
			return originalProcessPendingPins.apply(this, args);
		});
		const originalInitializeStorageAccounting = IncidentRecorderCompactor.prototype.initializeStorageAccounting;
		vi.spyOn(IncidentRecorderCompactor.prototype, "initializeStorageAccounting").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["initializeStorageAccounting"]>
		) {
			const result = await originalInitializeStorageAccounting.apply(this, args);
			if (!deletionRescanStarted && deletionObserved && !existsSync(expiredIncidentDir)) {
				deletionRescanStarted = true;
				expect(maintenanceHeld).toBe(true);
				expect(pendingPinCalls).toBe(0);
				resolveDeletionRescanStarted();
				await deletionRescanRelease;
			}
			return result;
		});
		const originalJsonParse = JSON.parse;
		vi.spyOn(JSON, "parse").mockImplementation((text: string) => {
			if (deletionObserved && maintenanceHeld && !insideRetention && text === inspectedProcessBytes) {
				inspectionFailures += 1;
				throw new Error("injected inspection failure after deletion-triggered rerun");
			}
			return originalJsonParse(text);
		});
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready, 5_000, "maintenance recovery service readiness timed out");
			await withTimeout(
				deletionRescanStartedPromise,
				5_000,
				"deletion accounting rescan maintenance hold timed out",
			);
			expect(maintenanceHeld).toBe(true);
			expect(pendingPinCalls).toBe(0);
			releaseDeletionRescan();
			await waitForCondition(
				() => deletionObserved && inspectionFailures > 0 && pendingPinCallsAfterFailure > 0,
				"maintenance hold release and post-failure pin progress",
				500,
			);
			expect(existsSync(expiredIncidentDir)).toBe(false);
			expect(existsSync(expiredRunDir)).toBe(false);
			expect(maintenanceEndCalls).toBeGreaterThan(0);
			expect(maintenanceHeld).toBe(false);
			expect(pendingPinCalls).toBeGreaterThan(0);
		} finally {
			releaseDeletionRescan();
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running, 10_000).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 15_000);

	it("does not prune segment history while retention protection is building", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const incidentDir = join(target.agentDir, "incidents", "uncertain-retained-incident");
		mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
		writeFileSync(
			join(incidentDir, "summary.json"),
			`${JSON.stringify({ stoppedTargetCaptureComplete: false, finalized: new Date().toISOString() })}\n`,
			{ mode: 0o600 },
		);
		const prune = vi.spyOn(IncidentRecorderCompactor.prototype, "pruneSegmentHistory");
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			await new Promise<void>((resolve) => setTimeout(resolve, 750));
			expect(prune).not.toHaveBeenCalled();
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("fails instead of remaining active when the compactor exits unexpectedly", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource(true));
		const shutdownOrder: string[] = [];
		const originalCompactorRun = IncidentRecorderCompactor.prototype.run;
		vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			try {
				return await originalCompactorRun.apply(this, args);
			} finally {
				shutdownOrder.push("compactor-closed");
			}
		});
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			shutdownOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: () => {},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			await expect(withTimeout(running)).rejects.toThrow();
			expect(shutdownOrder).toEqual(["compactor-closed", "writer-stop"]);
			expect(signals.size).toBe(0);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("rethrows a compactor close rejection after requested shutdown and writer drain", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const shutdownOrder: string[] = [];
		const closeError = new Error("compactor close rejected after requested shutdown");
		let resolveCloseStarted: () => void = () => {};
		const closeStarted = new Promise<void>((resolve) => {
			resolveCloseStarted = resolve;
		});
		let releaseClose: () => void = () => {};
		const closeRelease = new Promise<void>((resolve) => {
			releaseClose = resolve;
		});
		vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			const [runOptions] = args;
			runOptions.onStorageMode?.("normal");
			await runOptions.onNormalWriterAdmission?.();
			runOptions.onReaderReady?.();
			await new Promise<void>((resolveAborted) => {
				if (runOptions.signal.aborted) resolveAborted();
				else runOptions.signal.addEventListener("abort", () => resolveAborted(), { once: true });
			});
			shutdownOrder.push("compactor-close-start");
			resolveCloseStarted();
			await closeRelease;
			shutdownOrder.push("compactor-close-reject");
			throw closeError;
		});
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			shutdownOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			signals.emit("SIGTERM");
			await withTimeout(closeStarted);
			expect(shutdownOrder).toEqual(["compactor-close-start"]);
			releaseClose();
			await expect(withTimeout(running)).rejects.toBe(closeError);
			expect(shutdownOrder).toEqual(["compactor-close-start", "compactor-close-reject", "writer-stop"]);
			expect(signals.size).toBe(0);
		} finally {
			releaseClose();
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("rolls back every attempted signal registration and preserves rollback detail", async () => {
		const target = fixture();
		const registrationError = new Error("SIGINT registration rejected");
		const rollbackError = new Error("SIGINT rollback rejected");
		const signals = new FaultingSignalSource(
			new Map<RecorderSignal, unknown>([["SIGINT", registrationError]]),
			new Map<RecorderSignal, unknown>([["SIGINT", rollbackError]]),
		);
		const writerStart = vi.spyOn(IncidentRecorderWriter.prototype, "start");

		const rejection = await captureRejection(
			runIncidentRecorderService(target.agentDir, {
				notify: () => {},
				signalSource: signals,
			}),
		);

		expect(rejection).toBeInstanceOf(AggregateError);
		expect((rejection as AggregateError).errors).toEqual([registrationError, rollbackError]);
		expect((rejection as Error).message).toContain("signalSource.off(SIGINT)");
		expect(signals.calls).toEqual(["once:SIGTERM", "once:SIGINT", "off:SIGINT", "off:SIGTERM"]);
		expect(signals.has("SIGTERM")).toBe(false);
		expect(signals.has("SIGINT")).toBe(true);
		expect(writerStart).not.toHaveBeenCalled();
	});

	it("rethrows signal registration unchanged when rollback succeeds", async () => {
		const target = fixture();
		const registrationError = new Error("SIGINT registration rejected cleanly");
		const signals = new FaultingSignalSource(new Map<RecorderSignal, unknown>([["SIGINT", registrationError]]));

		const rejection = await captureRejection(
			runIncidentRecorderService(target.agentDir, {
				notify: () => {},
				signalSource: signals,
			}),
		);

		expect(rejection).toBe(registrationError);
		expect(signals.calls).toEqual(["once:SIGTERM", "once:SIGINT", "off:SIGINT", "off:SIGTERM"]);
		expect(signals.has("SIGTERM")).toBe(false);
		expect(signals.has("SIGINT")).toBe(false);
	});

	it("attempts every shutdown cleanup when both signal removals throw", async () => {
		const target = fixture();
		const sigtermRemovalError = new Error("SIGTERM removal rejected");
		const sigintRemovalError = new Error("SIGINT removal rejected");
		const signals = new FaultingSignalSource(
			new Map<RecorderSignal, unknown>(),
			new Map<RecorderSignal, unknown>([
				["SIGTERM", sigtermRemovalError],
				["SIGINT", sigintRemovalError],
			]),
		);
		mockReadyServiceCompactor();
		const writerStop = vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockResolvedValue(undefined);

		const rejection = await captureRejection(
			runIncidentRecorderService(target.agentDir, {
				notify: (fields) => {
					if (fields.includes("READY=1")) signals.emit("SIGTERM");
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			}),
		);

		expect(rejection).toBeInstanceOf(AggregateError);
		expect((rejection as AggregateError).errors).toEqual([sigtermRemovalError, sigintRemovalError]);
		expect(signals.calls).toEqual(["once:SIGTERM", "once:SIGINT", "off:SIGTERM", "off:SIGINT"]);
		expect(writerStop).toHaveBeenCalledOnce();
		expect(writerStop).toHaveBeenCalledWith(1_000);
	});

	it("keeps a compactor thrown undefined ahead of writer and signal cleanup failures", async () => {
		const target = fixture();
		const writerStopError = new Error("writer stop should lose to compactor");
		const removalError = new Error("signal cleanup should lose to compactor");
		const signals = new FaultingSignalSource(
			new Map<RecorderSignal, unknown>(),
			new Map<RecorderSignal, unknown>([["SIGTERM", removalError]]),
		);
		mockReadyServiceCompactor(() => Promise.reject(undefined));
		const writerStop = vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockRejectedValue(writerStopError);

		const rejection = await captureRejection(
			runIncidentRecorderService(target.agentDir, {
				notify: (fields) => {
					if (fields.includes("READY=1")) signals.emit("SIGTERM");
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			}),
		);

		expect(rejection).toBeUndefined();
		expect(signals.calls).toEqual(["once:SIGTERM", "once:SIGINT", "off:SIGTERM", "off:SIGINT"]);
		expect(writerStop).toHaveBeenCalledOnce();
	});

	it("keeps a writer-stop thrown undefined ahead of a run and signal cleanup failure", async () => {
		const target = fixture();
		const runError = new Error("writer start rejected");
		const removalError = new Error("signal cleanup should lose to writer stop");
		const signals = new FaultingSignalSource(
			new Map<RecorderSignal, unknown>(),
			new Map<RecorderSignal, unknown>([["SIGTERM", removalError]]),
		);
		vi.spyOn(IncidentRecorderWriter.prototype, "start").mockRejectedValue(runError);
		const writerStop = vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockRejectedValue(undefined);

		const rejection = await captureRejection(
			runIncidentRecorderService(target.agentDir, {
				notify: () => {},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			}),
		);

		expect(rejection).toBeUndefined();
		expect(signals.calls).toEqual(["once:SIGTERM", "once:SIGINT", "off:SIGTERM", "off:SIGINT"]);
		expect(writerStop).toHaveBeenCalledOnce();
	});

	it("keeps the run failure ahead of signal cleanup while still draining the writer", async () => {
		const target = fixture();
		const runError = new Error("writer start rejected before readiness");
		const removalError = new Error("signal cleanup should lose to run failure");
		const signals = new FaultingSignalSource(
			new Map<RecorderSignal, unknown>(),
			new Map<RecorderSignal, unknown>([["SIGTERM", removalError]]),
		);
		vi.spyOn(IncidentRecorderWriter.prototype, "start").mockRejectedValue(runError);
		const writerStop = vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockResolvedValue(undefined);

		const rejection = await captureRejection(
			runIncidentRecorderService(target.agentDir, {
				notify: () => {},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			}),
		);

		expect(rejection).toBe(runError);
		expect(signals.calls).toEqual(["once:SIGTERM", "once:SIGINT", "off:SIGTERM", "off:SIGINT"]);
		expect(writerStop).toHaveBeenCalledOnce();
	});

	it.each([false, true])(
		"reaches degraded readiness and remains stoppable when storage starts recovery-only (pin writer busy=%s)",
		async (pinWriterBusy) => {
			const target = fixture();
			let holdPinWriter = pinWriterBusy;
			let normalRetentionPasses = 0;
			const activePinWriterGetter = Object.getOwnPropertyDescriptor(
				IncidentRecorderCompactor.prototype,
				"hasActivePinWriters",
			)?.get;
			if (!activePinWriterGetter) throw new Error("Missing active pin writer observation");
			vi.spyOn(IncidentRecorderCompactor.prototype, "hasActivePinWriters", "get").mockImplementation(function (
				this: IncidentRecorderCompactor,
			) {
				return holdPinWriter || activePinWriterGetter.call(this);
			});
			const recoveryEvidence: unknown[] = [];
			const enterRecovery = IncidentRecorderServiceWriterLifecycle.prototype.enterRecovery;
			vi.spyOn(IncidentRecorderServiceWriterLifecycle.prototype, "enterRecovery").mockImplementation(async function (
				this: IncidentRecorderServiceWriterLifecycle,
			) {
				const result = await enterRecovery.call(this);
				if (recoveryEvidence.length < 8) recoveryEvidence.push(result);
				return result;
			});
			const retentionPass = retentionModule.runIncidentRetentionPass;
			vi.spyOn(retentionModule, "runIncidentRetentionPass").mockImplementation((options) => {
				if (!options.recoveryOnly) normalRetentionPasses += 1;
				const result = retentionPass(options);
				if (recoveryEvidence.length < 8) recoveryEvidence.push(result);
				return result;
			});
			writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
			const journalctlPath = join(target.binDir, "journalctl");
			writeExecutable(journalctlPath, fakeJournalctlSource());
			const { incidentDirectory: expiredIncidentDir } = writeBoundExpiredPublishedIncident(
				target,
				"78787878-7878-4787-8787-787878787878",
			);
			const scannerPath = join(target.binDir, "storage-scanner");
			const storageHealthySentinel = join(target.root, "storage-healthy");
			writeExecutable(
				scannerPath,
				`const fs = require("node:fs");
const healthy = fs.existsSync(process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL);
const unhealthyLines = Array.from(
	{ length: 65 },
	(_value, index) => "1\\t" + String(index + 10) + "\\t1\\t8",
).join("\\n") + "\\n";
fs.appendFileSync(
	process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS,
	healthy ? "storage-scan-clear\\n" : "storage-scan-high\\n",
);
process.stdout.write(healthy ? "" : unhealthyLines);`,
			);
			const previousStorageHealthySentinel = process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL;
			process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL = storageHealthySentinel;
			const previousPath = process.env.PATH;
			const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
			process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
			const signals = new TestSignalSource();
			const notifications: string[][] = [];
			let recoveryNotificationWasAllocationFree = false;
			let resolveReady: () => void = () => {};
			const ready = new Promise<void>((resolve) => {
				resolveReady = resolve;
			});
			let running: Promise<void> | undefined;
			try {
				running = runIncidentRecorderService(target.agentDir, {
					journalctlPath,
					compactorOptions: {
						storageScannerPath: scannerPath,
						storageAccountingMaxInodes: 64,
						freeReserveBytes: 0,
					},
					notify: (fields) => {
						notifications.push([...fields]);
						if (fields.includes("STATUS=Incident recorder recovery-only: inode_bound_exceeded")) {
							recoveryNotificationWasAllocationFree = !existsSync(
								join(target.agentDir, "incident-recorder", "segments"),
							);
							writeFileSync(storageHealthySentinel, "healthy\n", { mode: 0o600 });
						}
						if (fields.includes("READY=1")) resolveReady();
					},
					signalSource: signals,
					storageRecoveryCadenceMs: 10,
					writerStopDeadlineMs: 1_000,
				});
				running.catch(() => {});
				await withTimeout(ready);
				expect(notifications).toEqual([
					["READY=1", "STATUS=Incident recorder recovery-only: inode_bound_exceeded"],
				]);
				expect(recoveryNotificationWasAllocationFree).toBe(true);
				expect(readFileSync(target.eventsPath, "utf8")).not.toContain("systemd-cat-started");
				expect(readFileSync(target.eventsPath, "utf8")).not.toContain("journalctl-started");
				expect(existsSync(join(target.agentDir, "incident-recorder", "segments"))).toBe(false);
				if (pinWriterBusy) {
					await waitForCondition(
						() => notifications.some((fields) => fields.includes("STATUS=Incident recorder ready")),
						"normal reader readiness while pin writer is busy",
					);
					await new Promise<void>((resolve) => setTimeout(resolve, 50));
					expect(normalRetentionPasses).toBe(0);
					expect(existsSync(expiredIncidentDir)).toBe(true);
					holdPinWriter = false;
				}
				await waitForCondition(() => {
					const events = existsSync(target.eventsPath) ? readFileSync(target.eventsPath, "utf8") : "";
					return (
						!existsSync(expiredIncidentDir) &&
						events.includes("storage-scan-high") &&
						events.includes("storage-scan-clear")
					);
				}, "allocation-free recovery retention deletion and full storage rescan").catch((error: Error) => {
					throw new Error(`${error.message}; recovery evidence: ${JSON.stringify(recoveryEvidence)}`);
				});
				await waitForFileText(target.eventsPath, ["systemd-cat-started", "journalctl-started"]);
				for (
					let attempt = 0;
					attempt < 200 && !notifications.some((fields) => fields.includes("STATUS=Incident recorder ready"));
					attempt += 1
				)
					await new Promise<void>((resolve) => setTimeout(resolve, 10));
				expect(notifications.filter((fields) => fields.includes("READY=1"))).toHaveLength(1);
				expect(notifications).toContainEqual(["STATUS=Incident recorder ready"]);
				expect(notifications.filter((fields) => fields.includes("STATUS=Incident recorder ready"))).toHaveLength(1);
				signals.emit("SIGTERM");
				await withTimeout(running);
				expect(notifications.at(-1)).toEqual(["STOPPING=1", "STATUS=Stopping after SIGTERM"]);
			} finally {
				if (signals.size > 0) signals.emit("SIGTERM");
				if (running) await withTimeout(running).catch(() => undefined);
				if (previousPath === undefined) delete process.env.PATH;
				else process.env.PATH = previousPath;
				if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
				else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
				if (previousStorageHealthySentinel === undefined) delete process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL;
				else process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL = previousStorageHealthySentinel;
			}
		},
		10_000,
	);

	it("never announces readiness when the initial journal writer exits immediately", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource(true));
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: (fields) => notifications.push([...fields]),
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			await expect(withTimeout(running)).rejects.toThrow(
				/journal writer (?:did not become ready|exited before readiness)/,
			);
			expect(notifications.flat()).not.toContain("READY=1");
			expect(signals.size).toBe(0);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("drains admitted per-run service observations before closing the journal writer", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalBytes = join(target.root, "journal-lines.jsonl");
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES = journalBytes;
		const writer = new IncidentRecorderWriter({
			runDir: join(target.agentDir, "incident-recorder"),
			runId: "11111111-1111-4111-8111-111111111111",
			runToken: "22222222-2222-4222-8222-222222222222",
			serviceSink: true,
		});
		try {
			await writer.start({ requireJournal: true });
			const admission = writer.recordDerivedForRun(
				{
					runId: "33333333-3333-4333-8333-333333333333",
					runToken: "44444444-4444-4444-8444-444444444444",
				},
				"recorder-control",
				"service_shutdown_drain_probe",
				{ diagnosticOnly: true },
			);
			expect(admission.accepted).toBe(true);
			await writer.releaseRunIdentity({
				runId: "33333333-3333-4333-8333-333333333333",
				runToken: "44444444-4444-4444-8444-444444444444",
			});
			await writer.stop(1_000);
			const lines = readFileSync(journalBytes, "utf8")
				.trim()
				.split("\n")
				.map((line) => JSON.parse(line) as { type?: unknown });
			expect(lines.some((line) => line.type === "service_shutdown_drain_probe")).toBe(true);
		} finally {
			await writer.stop(250);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("anchors the first stopped observation before a live proxy delays finalization", async () => {
		const target = fixture();
		const runId = "f1010101-0101-4101-8101-010101010101";
		const runToken = "f2020202-0202-4202-8202-020202020202";
		const runDir = stoppedServiceRun(target, runId, runToken);
		const proxyPath = join(runDir, ".recorder-active");
		writeLiveServiceProxy(runDir);
		writeZeroArtifactCaptureCompletion(runDir, runId);
		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation(() => {
			throw new Error("Incident run-history projection capacity is saturated");
		});
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
			});
			running.catch(() => {});
			await withTimeout(ready);
			const stoppedObservationPath = join(runDir, "service-finalization-stopped-observation.json");
			await waitForCondition(
				() => existsSync(stoppedObservationPath),
				"first stopped observation behind live proxy",
			);
			const anchoredBytes = readFileSync(stoppedObservationPath, "utf8");
			const anchored = JSON.parse(anchoredBytes) as Record<string, unknown>;
			expect(anchored).toMatchObject({
				schemaVersion: 1,
				kind: "service_stopped_observation",
				runId,
				runToken,
				disposition: "exact_first_observation",
			});
			expect(Number.isSafeInteger(anchored.firstObservedStoppedWallTimeMs)).toBe(true);
			expect(existsSync(join(runDir, "service-finalization-seal-intent.json"))).toBe(false);
			await new Promise<void>((resolve) => setTimeout(resolve, 50));
			expect(readFileSync(stoppedObservationPath, "utf8")).toBe(anchoredBytes);

			rmSync(proxyPath);
			const sealIntentPath = join(runDir, "service-finalization-seal-intent.json");
			await waitForCondition(() => existsSync(sealIntentPath), "seal intent after proxy exit");
			expect(readFileSync(stoppedObservationPath, "utf8")).toBe(anchoredBytes);
			expect(JSON.parse(readFileSync(sealIntentPath, "utf8"))).toMatchObject({
				runId,
				runToken,
				retentionAnchorWallTimeMs: anchored.firstObservedStoppedWallTimeMs,
				stoppedObservationDisposition: "exact_first_observation",
			});
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running);
		}
	}, 10_000);

	it.each([
		["null", null, "1"],
		["primitive", 7, "2"],
		["malformed object", { unexpected: true }, "3"],
	] as const)(
		"quarantines and converges invalid %s service-finalization controls",
		async (_label, invalid, namespace) => {
			const target = fixture();
			const uuid = (slot: string): string => `f${namespace}${slot}00000-0000-4000-8000-00000000000${slot}`;
			const stoppedRunId = uuid("1");
			const stoppedRunToken = uuid("2");
			const stoppedRunDir = stoppedServiceRun(target, stoppedRunId, stoppedRunToken);
			writeZeroArtifactCaptureCompletion(stoppedRunDir, stoppedRunId);
			writeServiceTestJson(join(stoppedRunDir, "service-finalization-stopped-observation.json"), invalid);

			const sealRunId = uuid("3");
			const sealRunToken = uuid("4");
			const sealRunDir = stoppedServiceRun(target, sealRunId, sealRunToken);
			const sealNodeReportPath = join(sealRunDir, "raw-reports", "report.json");
			const sealNodeReportBytes = writeServiceTestJson(sealNodeReportPath, {
				header: { event: "Exception" },
			});
			mkdirSync(
				join(
					target.agentDir,
					"incident-recorder",
					"refs",
					"runs",
					createHash("sha256").update(sealRunId).digest("hex"),
				),
				{ recursive: true, mode: 0o700 },
			);
			writeServiceTestJson(join(sealRunDir, "service-finalization-stopped-observation.json"), {
				schemaVersion: 1,
				kind: "service_stopped_observation",
				runId: sealRunId,
				runToken: sealRunToken,
				firstObservedStoppedWallTimeMs: 1_800_000_000_000,
				disposition: "exact_first_observation",
			});
			for (const name of [
				"service-finalization-seal-intent.json",
				"service-finalization-seal.json",
				"service-finalization-seal-replay-ambiguity.json",
			])
				writeServiceTestJson(join(sealRunDir, name), invalid);

			const replayRunId = uuid("6");
			const replayRunToken = uuid("7");
			const replayRunDir = stoppedServiceRun(target, replayRunId, replayRunToken);
			const replayNodeReportPath = join(replayRunDir, "raw-reports", "report.json");
			const replayNodeReportBytes = writeServiceTestJson(replayNodeReportPath, {
				header: { event: "Exception" },
			});
			writeServiceTestJson(join(replayRunDir, "service-finalization-seal-replay-ambiguity.json"), invalid);
			mkdirSync(
				join(
					target.agentDir,
					"incident-recorder",
					"refs",
					"runs",
					createHash("sha256").update(replayRunId).digest("hex"),
				),
				{ recursive: true, mode: 0o700 },
			);

			mockReadyServiceCompactor();
			vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
			const streamStoppedTargetArtifact = vi
				.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
				.mockImplementation(
					(_candidateRunId, sourcePath, encoding) =>
						({
							state: "complete",
							artifact: {
								algorithm: "sha256",
								digest: createHash("sha256").update(readFileSync(sourcePath)).digest("hex"),
								bytes: readFileSync(sourcePath).length,
								path: sourcePath,
								encoding,
							},
						}) as never,
				);
			vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
			const originalSealRunIdentity = IncidentRecorderWriter.prototype.sealRunIdentity;
			const emittedSeals = new Map<string, ReturnType<typeof testServiceSeal>>();
			vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity").mockImplementation(function (
				this: IncidentRecorderWriter,
				...args: Parameters<IncidentRecorderWriter["sealRunIdentity"]>
			) {
				return originalSealRunIdentity.apply(this, args).then((seal) => {
					emittedSeals.set(seal.runId, seal as unknown as ReturnType<typeof testServiceSeal>);
					return seal;
				});
			});
			const projectRunHistory = vi
				.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
				.mockImplementation((input) => {
					const fixtureRunDir =
						input.runId === stoppedRunId ? stoppedRunDir : input.runId === sealRunId ? sealRunDir : replayRunDir;
					const seal =
						emittedSeals.get(input.runId) ??
						(JSON.parse(readFileSync(join(fixtureRunDir, "service-finalization-seal.json"), "utf8")) as {
							terminal: {
								frontier: ReturnType<typeof testServiceSeal>["terminal"]["frontier"] | null;
							};
						});
					const runToken =
						input.runId === stoppedRunId
							? stoppedRunToken
							: input.runId === sealRunId
								? sealRunToken
								: replayRunToken;
					return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
				});
			const stoppedIncident = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${stoppedRunId}`);
			const sealIncident = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${sealRunId}`);
			const replayIncident = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${replayRunId}`);
			await runReadyServiceUntil(
				target.agentDir,
				() => {
					return (
						existsSync(join(stoppedIncident, "finalization-descriptor.json")) &&
						existsSync(join(sealIncident, "finalization-descriptor.json")) &&
						existsSync(join(replayIncident, "finalization-descriptor.json"))
					);
				},
				"invalid service controls to quarantine and converge",
			);

			const stoppedObservation = JSON.parse(
				readFileSync(join(stoppedRunDir, "service-finalization-stopped-observation.json"), "utf8"),
			) as Record<string, unknown>;
			expect(stoppedObservation).toMatchObject({
				runId: stoppedRunId,
				runToken: stoppedRunToken,
				disposition: "recovered_after_invalid_control",
			});
			expect(
				JSON.parse(readFileSync(join(stoppedRunDir, "service-finalization-seal-intent.json"), "utf8")),
			).toMatchObject({
				stoppedObservationDisposition: "recovered_after_invalid_control",
				retentionAnchorWallTimeMs: stoppedObservation.firstObservedStoppedWallTimeMs,
			});
			const stoppedDescriptor = JSON.parse(
				readFileSync(join(stoppedIncident, "finalization-descriptor.json"), "utf8"),
			) as { state: string; reasons: string[] };
			expect(stoppedDescriptor.state).toBe("incomplete");
			expect(stoppedDescriptor.reasons).toContain(
				"service_terminal_relay_disposition:recovered_after_invalid_stopped_observation",
			);

			const quarantineLabels = (runDir: string): string[] =>
				readdirSync(join(runDir, ".service-control-quarantine"));
			expect(quarantineLabels(stoppedRunDir).some((name) => name.startsWith("stopped-observation-"))).toBe(true);
			const sealQuarantine = quarantineLabels(sealRunDir);
			for (const label of ["seal-intent-", "seal-replay-ambiguity-"])
				expect(sealQuarantine.some((name) => name.startsWith(label))).toBe(true);
			expect(
				sealQuarantine.some(
					(name) =>
						name.startsWith("seal-") &&
						!name.startsWith("seal-intent-") &&
						!name.startsWith("seal-replay-ambiguity-"),
				),
			).toBe(true);
			expect(
				streamStoppedTargetArtifact.mock.calls.some(([, sourcePath]) => sourcePath === sealNodeReportPath),
			).toBe(false);
			expect(readFileSync(sealNodeReportPath, "utf8")).toBe(sealNodeReportBytes);
			expect(existsSync(join(sealRunDir, "raw-reports", "capture-complete.json"))).toBe(false);
			expect(existsSync(join(sealRunDir, "evidence", "provider-artifacts"))).toBe(false);
			const recoveredSealIntent = JSON.parse(
				readFileSync(join(sealRunDir, "service-finalization-seal-intent.json"), "utf8"),
			) as { terminalOccurrenceId: string };
			expect(JSON.parse(readFileSync(join(sealRunDir, "service-finalization-seal.json"), "utf8"))).toEqual(
				testFenceOnlyServiceSeal(sealRunId, sealRunToken),
			);
			expect(
				JSON.parse(readFileSync(join(sealRunDir, "service-finalization-seal-replay-ambiguity.json"), "utf8")),
			).toEqual({
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId: sealRunId,
				runToken: sealRunToken,
				terminalOccurrenceId: recoveredSealIntent.terminalOccurrenceId,
				reason: "seal_namespace_invalid_or_unbound",
			});
			const sealDescriptor = JSON.parse(
				readFileSync(join(sealIncident, "finalization-descriptor.json"), "utf8"),
			) as { state: string; reasons: string[]; stoppedTarget: { captureState: string } };
			expect(sealDescriptor.state).toBe("incomplete");
			expect(sealDescriptor.stoppedTarget.captureState).toBe("incomplete");
			expect(sealDescriptor.reasons).toContain("stopped_target_capture_incomplete");
			expect(
				streamStoppedTargetArtifact.mock.calls.some(([, sourcePath]) => sourcePath === replayNodeReportPath),
			).toBe(false);
			expect(readFileSync(replayNodeReportPath, "utf8")).toBe(replayNodeReportBytes);
			expect(existsSync(join(replayRunDir, "raw-reports", "capture-complete.json"))).toBe(false);
			expect(existsSync(join(replayRunDir, "evidence", "provider-artifacts"))).toBe(false);
			const replayIntent = JSON.parse(
				readFileSync(join(replayRunDir, "service-finalization-seal-intent.json"), "utf8"),
			) as { terminalOccurrenceId: string };
			expect(JSON.parse(readFileSync(join(replayRunDir, "service-finalization-seal.json"), "utf8"))).toEqual(
				testFenceOnlyServiceSeal(replayRunId, replayRunToken),
			);
			expect(
				JSON.parse(readFileSync(join(replayRunDir, "service-finalization-seal-replay-ambiguity.json"), "utf8")),
			).toEqual({
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId: replayRunId,
				runToken: replayRunToken,
				terminalOccurrenceId: replayIntent.terminalOccurrenceId,
				reason: "seal_namespace_invalid_or_unbound",
			});
			expect(
				readdirSync(join(replayRunDir, ".service-control-quarantine")).some((name) =>
					name.startsWith("seal-replay-ambiguity-"),
				),
			).toBe(true);
			const replayDescriptor = JSON.parse(
				readFileSync(join(replayIncident, "finalization-descriptor.json"), "utf8"),
			) as { state: string; reasons: string[]; stoppedTarget: { captureState: string } };
			expect(replayDescriptor.state).toBe("incomplete");
			expect(replayDescriptor.stoppedTarget.captureState).toBe("incomplete");
			expect(replayDescriptor.reasons).toContain("stopped_target_capture_incomplete");
			expect(replayDescriptor.reasons).toContain(
				"service_terminal_relay_disposition:replayed_after_ambiguous_seal_attempt",
			);
			expect(new Set(projectRunHistory.mock.calls.map(([input]) => input.runId))).toEqual(
				new Set([replayRunId, sealRunId, stoppedRunId]),
			);
		},
		20_000,
	);

	it.each([
		["null", null, "4"],
		["primitive", 7, "5"],
		["malformed object", { unexpected: true }, "6"],
	] as const)(
		"repairs invalid %s publication controls from a semantically bound published incident",
		async (_label, invalid, namespace) => {
			const target = fixture();
			const uuid = (slot: string): string => `f${namespace}${slot}00000-0000-4000-8000-00000000000${slot}`;
			const runId = uuid("1");
			const runToken = "11111111-1111-4111-8111-111111111111";
			const retentionAnchorWallTimeMs = Date.parse("2000-01-01T00:00:00.000Z");
			const runDir = stoppedServiceRun(target, runId, runToken, `expired-${runId}`);
			const incidentDirectory = writeExpiredPublishedIncident(
				target.agentDir,
				runId,
				"relayed",
				"incomplete",
				uuid("2"),
				uuid("3"),
			);
			const finalizationId = publishedFinalizationId(incidentDirectory);
			writeDurableServiceSeal(runDir, runId, runToken, uuid("2"), uuid("3"), retentionAnchorWallTimeMs);
			const publicationIntentPath = join(runDir, `service-finalization-publication-intent-${finalizationId}.json`);
			const completionPath = join(runDir, ".service-finalization-complete");
			writeServiceTestJson(publicationIntentPath, invalid);
			writeServiceTestJson(completionPath, invalid);

			mockReadyServiceCompactor();
			vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
			const projectRunHistory = vi
				.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
				.mockImplementation(() => {
					throw new Error("published-control recovery attempted a new projection");
				});
			await runReadyServiceUntil(
				target.agentDir,
				() => {
					if (!existsSync(completionPath)) return false;
					const completion = JSON.parse(readFileSync(completionPath, "utf8")) as {
						finalizationId?: unknown;
						outcome?: unknown;
					};
					return completion.finalizationId === finalizationId && completion.outcome === "incomplete";
				},
				`${_label} publication control recovery`,
			);

			const quarantine = readdirSync(join(runDir, ".service-control-quarantine"));
			expect(quarantine.some((name) => name.startsWith("publication-intent-"))).toBe(true);
			expect(quarantine.some((name) => name.startsWith("completion-"))).toBe(true);
			expect(JSON.parse(readFileSync(publicationIntentPath, "utf8"))).toEqual({
				schemaVersion: 1,
				kind: "service_finalization_publication_intent",
				runId,
				finalizationId,
			});
			expect(JSON.parse(readFileSync(completionPath, "utf8"))).toEqual({
				schemaVersion: 2,
				state: "incident_reclaimable",
				runId,
				finalizationId,
				outcome: "incomplete",
				retentionAnchorWallTimeMs,
			});
			expect(projectRunHistory).not.toHaveBeenCalled();
		},
		20_000,
	);

	it.each([
		["shape-valid", true, "8"],
		["malformed", false, "9"],
	] as const)(
		"fences %s replay-only namespace evidence without recapturing stopped artifacts",
		async (_label, shapeValid, namespace) => {
			const target = fixture();
			const uuid = (slot: string): string => `e${namespace}${slot}00000-0000-4000-8000-00000000000${slot}`;
			const runId = uuid("1");
			const runToken = uuid("2");
			const replayOccurrenceId = uuid("3");
			const runDir = stoppedServiceRun(target, runId, runToken);
			const nodeReportPath = join(runDir, "raw-reports", "report.json");
			const nodeReportBytes = writeServiceTestJson(nodeReportPath, {
				header: { event: "Exception" },
			});
			writeServiceTestJson(
				join(runDir, "service-finalization-seal-replay-ambiguity.json"),
				shapeValid
					? {
							schemaVersion: 1,
							kind: "service_run_seal_replay_ambiguity",
							runId,
							runToken,
							terminalOccurrenceId: replayOccurrenceId,
							reason: "seal_intent_without_seal_observed",
						}
					: null,
			);

			mockReadyServiceCompactor();
			vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
			const streamStoppedTargetArtifact = vi
				.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
				.mockImplementation(() => {
					throw new Error("replay-only namespace attempted stopped-target recapture");
				});
			vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
			const fenceRunIdentity = vi.spyOn(IncidentRecorderWriter.prototype, "fenceRunIdentity");
			vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
				const seal = JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8")) as ReturnType<
					typeof testFenceOnlyServiceSeal
				>;
				return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
			});
			const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
			await runReadyServiceUntil(
				target.agentDir,
				() => existsSync(join(incidentDirectory, "finalization-descriptor.json")),
				`${_label} replay-only namespace recovery`,
			);

			expect(streamStoppedTargetArtifact).not.toHaveBeenCalled();
			expect(readFileSync(nodeReportPath, "utf8")).toBe(nodeReportBytes);
			expect(existsSync(join(runDir, "raw-reports", "capture-complete.json"))).toBe(false);
			expect(existsSync(join(runDir, "evidence", "provider-artifacts"))).toBe(false);
			const recoveredIntent = JSON.parse(
				readFileSync(join(runDir, "service-finalization-seal-intent.json"), "utf8"),
			) as { terminalOccurrenceId: string };
			if (shapeValid) expect(recoveredIntent.terminalOccurrenceId).toBe(replayOccurrenceId);
			else expect(recoveredIntent.terminalOccurrenceId).not.toBe(replayOccurrenceId);
			expect(JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8"))).toEqual(
				testFenceOnlyServiceSeal(runId, runToken),
			);
			expect(fenceRunIdentity).toHaveBeenCalledTimes(1);
			expect(fenceRunIdentity).toHaveBeenCalledWith(
				{
					runId,
					runToken,
					targetPid: 2_147_483_647,
					targetProcessStartId: "proc:1",
					disposition: "exact_process_control",
				},
				{ durableReplay: true },
			);
			expect(
				JSON.parse(readFileSync(join(runDir, "service-finalization-seal-replay-ambiguity.json"), "utf8")),
			).toEqual({
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId,
				runToken,
				terminalOccurrenceId: recoveredIntent.terminalOccurrenceId,
				reason: shapeValid ? "seal_intent_without_seal_observed" : "seal_namespace_invalid_or_unbound",
			});
			const quarantineDirectory = join(runDir, ".service-control-quarantine");
			expect(
				existsSync(quarantineDirectory) &&
					readdirSync(quarantineDirectory).some((name) => name.startsWith("seal-replay-ambiguity-")),
			).toBe(!shapeValid);
			const descriptor = JSON.parse(
				readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8"),
			) as { reasons: string[]; stoppedTarget: { captureState: string } };
			expect(descriptor.stoppedTarget.captureState).toBe("incomplete");
			expect(descriptor.reasons).toContain("stopped_target_capture_incomplete");
			expect(descriptor.reasons).toContain(
				"service_terminal_relay_disposition:replayed_after_ambiguous_seal_attempt",
			);
		},
		20_000,
	);

	it.each([
		["normal authority", "a"],
		["incident authority", "b"],
	] as const)(
		"quarantines a shape-valid completion unbound from its %s and converges to durable authority",
		async (binding, namespace) => {
			const target = fixture();
			const uuid = (slot: string): string => `d${namespace}${slot}00000-0000-4000-8000-00000000000${slot}`;
			const runId = uuid("1");
			const incidentBinding = binding === "incident authority";
			const runToken = incidentBinding ? "11111111-1111-4111-8111-111111111111" : uuid("2");
			const terminalOccurrenceId = uuid("3");
			const producerId = uuid("4");
			const retentionAnchorWallTimeMs = incidentBinding ? Date.parse("2000-01-01T00:00:00.000Z") : 1_800_000_000_000;
			const runDir = stoppedServiceRun(target, runId, runToken, incidentBinding ? `expired-${runId}` : undefined);
			const completionPath = join(runDir, ".service-finalization-complete");
			let finalizationId: string;
			let incidentDirectory: string;
			if (incidentBinding) {
				incidentDirectory = writeExpiredPublishedIncident(
					target.agentDir,
					runId,
					"relayed",
					"incomplete",
					terminalOccurrenceId,
					producerId,
				);
				finalizationId = publishedFinalizationId(incidentDirectory);
				writeDurableServiceSeal(
					runDir,
					runId,
					runToken,
					terminalOccurrenceId,
					producerId,
					retentionAnchorWallTimeMs,
				);
				writeServiceTestJson(join(runDir, `service-finalization-publication-intent-${finalizationId}.json`), {
					schemaVersion: 1,
					kind: "service_finalization_publication_intent",
					runId,
					finalizationId,
				});
				writeServiceTestJson(completionPath, {
					schemaVersion: 2,
					state: "incident_reclaimable",
					runId,
					finalizationId,
					outcome: "complete",
					retentionAnchorWallTimeMs,
				});
			} else {
				finalizationId = createHash("sha256").update(`normal-unbound:${runId}`).digest("hex");
				incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
				writeDurableNormalServiceCompletion({
					runDir,
					runId,
					runToken,
					terminalOccurrenceId,
					producerId,
					finalizationId,
					retentionAnchorWallTimeMs,
				});
				writeServiceTestJson(join(runDir, `service-finalization-normal-authority-${finalizationId}.json`), {
					schemaVersion: 1,
					kind: "service_normal_retention_authority",
					runId,
					runToken: uuid("5"),
					finalizationId,
					classification: "normal",
					analysisState: "complete",
					retentionAnchorWallTimeMs,
					terminalOccurrenceId,
				});
			}

			mockReadyServiceCompactor();
			vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
			vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
			const projectRunHistory = vi
				.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
				.mockImplementation((input) => {
					if (incidentBinding) throw new Error("bound incident recovery unexpectedly projected");
					const seal = JSON.parse(
						readFileSync(join(runDir, "service-finalization-seal.json"), "utf8"),
					) as ReturnType<typeof testServiceSeal>;
					return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
				});
			await runReadyServiceUntil(
				target.agentDir,
				() => {
					const current = JSON.parse(readFileSync(completionPath, "utf8")) as {
						finalizationId?: unknown;
						outcome?: unknown;
						state?: unknown;
					};
					return incidentBinding
						? current.state === "incident_reclaimable" && current.outcome === "incomplete"
						: existsSync(join(incidentDirectory, "finalization-descriptor.json")) &&
								current.state === "incident_reclaimable" &&
								typeof current.finalizationId === "string" &&
								current.finalizationId !== finalizationId;
				},
				`${binding} semantic completion recovery`,
			);

			expect(
				readdirSync(join(runDir, ".service-control-quarantine")).some((name) => name.startsWith("completion-")),
			).toBe(true);
			const recoveredCompletion = JSON.parse(readFileSync(completionPath, "utf8")) as {
				finalizationId: string;
				retentionAnchorWallTimeMs: number;
			};
			expect(recoveredCompletion).toEqual({
				schemaVersion: 2,
				state: "incident_reclaimable",
				runId,
				finalizationId: recoveredCompletion.finalizationId,
				outcome: "incomplete",
				retentionAnchorWallTimeMs: incidentBinding
					? retentionAnchorWallTimeMs
					: recoveredCompletion.retentionAnchorWallTimeMs,
			});
			if (incidentBinding) {
				expect(recoveredCompletion.finalizationId).toBe(finalizationId);
				expect(projectRunHistory).not.toHaveBeenCalled();
			} else {
				expect(recoveredCompletion.finalizationId).not.toBe(finalizationId);
				expect(recoveredCompletion.retentionAnchorWallTimeMs).toBe(retentionAnchorWallTimeMs);
				expect(projectRunHistory).toHaveBeenCalledTimes(1);
			}
			expect(JSON.parse(readFileSync(join(incidentDirectory, "retention-authority.json"), "utf8"))).toEqual({
				schemaVersion: 1,
				kind: "incident_retention_authority",
				finalizationId: recoveredCompletion.finalizationId,
				runId,
				outcome: "incomplete",
				retentionAnchorWallTimeMs: recoveredCompletion.retentionAnchorWallTimeMs,
			});
		},
		20_000,
	);

	it.each([
		["invalid primitive", "1"],
		["exact but insecure", "2"],
		["different occupant", "3"],
	] as const)(
		"converges an %s normal retention authority once across restart",
		async (variant, namespace) => {
			const target = fixture();
			const uuid = (slot: string): string => `cd${namespace}${slot}0000-0000-4000-8000-00000000000${slot}`;
			const runId = uuid("1");
			const runToken = uuid("2");
			const terminalOccurrenceId = uuid("3");
			const finalizationId = createHash("sha256").update(`normal-authority:${variant}:${runId}`).digest("hex");
			const runDir = stoppedServiceRun(target, runId, runToken);
			writeDurableNormalServiceCompletion({
				runDir,
				runId,
				runToken,
				terminalOccurrenceId,
				producerId: uuid("4"),
				finalizationId,
			});
			const authorityPath = join(runDir, `service-finalization-normal-authority-${finalizationId}.json`);
			if (variant === "invalid primitive") writeServiceTestJson(authorityPath, 7);
			else if (variant === "exact but insecure") chmodSync(authorityPath, 0o644);
			else
				writeServiceTestJson(authorityPath, {
					schemaVersion: 1,
					kind: "service_normal_retention_authority",
					runId,
					runToken: uuid("5"),
					finalizationId,
					classification: "normal",
					analysisState: "complete",
					retentionAnchorWallTimeMs: 1_800_000_000_000,
					terminalOccurrenceId,
				});

			mockReadyServiceCompactor();
			vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
			vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
			vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
				const seal = JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8")) as ReturnType<
					typeof testServiceSeal
				>;
				return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
			});
			const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
			const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
			await runReadyServiceUntil(
				target.agentDir,
				() => existsSync(join(incidentDirectory, "finalization-descriptor.json")),
				`${variant} normal authority convergence`,
			);
			expect(
				readdirSync(join(runDir, ".service-control-quarantine")).some((name) => name.startsWith("completion-")),
			).toBe(true);
			const completionPath = join(runDir, ".service-finalization-complete");
			const completionBytes = readFileSync(completionPath, "utf8");
			const runNames = readdirSync(runDir).sort();
			const quarantineNames = readdirSync(join(runDir, ".service-control-quarantine")).sort();
			const firstAdoptions = adoptRunIdentitySeal.mock.calls.filter(
				([candidate]) => (candidate as { runId?: string }).runId === runId,
			).length;
			await runReadyServiceUntil(
				target.agentDir,
				() =>
					adoptRunIdentitySeal.mock.calls.filter(
						([candidate]) => (candidate as { runId?: string }).runId === runId,
					).length > firstAdoptions,
				`${variant} normal authority second inspection`,
			);
			expect(readFileSync(completionPath, "utf8")).toBe(completionBytes);
			expect(readdirSync(runDir).sort()).toEqual(runNames);
			expect(readdirSync(join(runDir, ".service-control-quarantine")).sort()).toEqual(quarantineNames);
		},
		20_000,
	);

	it.each([
		["root extra key", "1"],
		["count extra key", "2"],
		["admission extra key", "3"],
		["frontier extra key", "4"],
		["arbitrary rejected reason", "5"],
		["rejected admission with frontier", "6"],
	] as const)(
		"rejects a normal completion backed by a seal with %s",
		async (variant, namespace) => {
			const target = fixture();
			const uuid = (slot: string): string => `c${namespace}${slot}00000-0000-4000-8000-00000000000${slot}`;
			const runId = uuid("1");
			const runToken = uuid("2");
			const terminalOccurrenceId = uuid("3");
			const producerId = uuid("4");
			const finalizationId = createHash("sha256").update(`strict-seal:${variant}:${runId}`).digest("hex");
			const runDir = stoppedServiceRun(target, runId, runToken);
			writeDurableNormalServiceCompletion({
				runDir,
				runId,
				runToken,
				terminalOccurrenceId,
				producerId,
				finalizationId,
			});
			const malformedSeal = testServiceSeal(runId, runToken, terminalOccurrenceId, producerId);
			switch (variant) {
				case "root extra key":
					(malformedSeal as typeof malformedSeal & { extra?: boolean }).extra = true;
					break;
				case "count extra key":
					(malformedSeal.loss.emitter as typeof malformedSeal.loss.emitter & { extra?: boolean }).extra = true;
					break;
				case "admission extra key":
					(
						malformedSeal.terminal.admission as typeof malformedSeal.terminal.admission & { extra?: boolean }
					).extra = true;
					break;
				case "frontier extra key":
					(malformedSeal.terminal.frontier as typeof malformedSeal.terminal.frontier & { extra?: boolean }).extra =
						true;
					break;
				case "arbitrary rejected reason":
					(malformedSeal.terminal as { admission: unknown; frontier: unknown }).admission = {
						accepted: false,
						disposition: "rejected",
						reason: "arbitrary-reason",
					};
					(malformedSeal.terminal as { admission: unknown; frontier: unknown }).frontier = null;
					break;
				case "rejected admission with frontier":
					(malformedSeal.terminal as { admission: unknown }).admission = {
						accepted: false,
						disposition: "rejected",
						reason: "run_identity_sealed",
					};
					break;
			}
			writeServiceTestJson(join(runDir, "service-finalization-seal.json"), malformedSeal);

			mockReadyServiceCompactor();
			vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
			vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
			vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
				const seal = JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8")) as ReturnType<
					typeof testFenceOnlyServiceSeal
				>;
				return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
			});
			const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
			await runReadyServiceUntil(
				target.agentDir,
				() => existsSync(join(incidentDirectory, "finalization-descriptor.json")),
				`${variant} seal rejection`,
			);

			const quarantined = readdirSync(join(runDir, ".service-control-quarantine"));
			expect(quarantined.some((name) => name.startsWith("completion-"))).toBe(true);
			expect(
				quarantined.some(
					(name) =>
						name.startsWith("seal-") &&
						!name.startsWith("seal-intent-") &&
						!name.startsWith("seal-replay-ambiguity-"),
				),
			).toBe(true);
			expect(JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8"))).toEqual(
				testFenceOnlyServiceSeal(runId, runToken),
			);
			expect(JSON.parse(readFileSync(join(runDir, ".service-finalization-complete"), "utf8"))).toMatchObject({
				schemaVersion: 2,
				state: "incident_reclaimable",
				runId,
				outcome: "incomplete",
			});
		},
		20_000,
	);

	it("rejects a normal completion whenever a canonical replay marker is present", async () => {
		const target = fixture();
		const runId = "ce010101-0101-4101-8101-010101010101";
		const runToken = "ce020202-0202-4202-8202-020202020202";
		const terminalOccurrenceId = "ce030303-0303-4303-8303-030303030303";
		const finalizationId = createHash("sha256").update(`normal-replay:${runId}`).digest("hex");
		const runDir = stoppedServiceRun(target, runId, runToken);
		writeDurableNormalServiceCompletion({
			runDir,
			runId,
			runToken,
			terminalOccurrenceId,
			producerId: "ce040404-0404-4404-8404-040404040404",
			finalizationId,
		});
		writeServiceTestJson(join(runDir, "service-finalization-seal-replay-ambiguity.json"), {
			schemaVersion: 1,
			kind: "service_run_seal_replay_ambiguity",
			runId,
			runToken,
			terminalOccurrenceId,
			reason: "seal_namespace_invalid_or_unbound",
		});
		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			const seal = JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8")) as ReturnType<
				typeof testServiceSeal
			>;
			return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
		});
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(join(incidentDirectory, "finalization-descriptor.json")),
			"normal completion replay-marker rejection",
		);
		expect(
			readdirSync(join(runDir, ".service-control-quarantine")).some((name) => name.startsWith("completion-")),
		).toBe(true);
		expect(JSON.parse(readFileSync(join(runDir, ".service-finalization-complete"), "utf8"))).toMatchObject({
			state: "incident_reclaimable",
			outcome: "incomplete",
		});
	}, 20_000);

	it("accepts an intent-A seal-B incident completion on repeated inspection without control churn", async () => {
		const target = fixture();
		const runId = "df010101-0101-4101-8101-010101010101";
		const runToken = "11111111-1111-4111-8111-111111111111";
		const intentOccurrenceId = "df020202-0202-4202-8202-020202020202";
		const sealOccurrenceId = "df030303-0303-4303-8303-030303030303";
		const retentionAnchorWallTimeMs = Date.parse("2000-01-01T00:00:00.000Z");
		const runDir = stoppedServiceRun(target, runId, runToken, `expired-${runId}`);
		const incidentDirectory = writeExpiredPublishedIncident(
			target.agentDir,
			runId,
			"replayed_after_ambiguous_seal_attempt",
			"incomplete",
			sealOccurrenceId,
			"df050505-0505-4505-8505-050505050505",
		);
		const finalizationId = publishedFinalizationId(incidentDirectory);
		writeDurableServiceSeal(
			runDir,
			runId,
			runToken,
			intentOccurrenceId,
			"df040404-0404-4404-8404-040404040404",
			retentionAnchorWallTimeMs,
		);
		writeServiceTestJson(
			join(runDir, "service-finalization-seal.json"),
			testServiceSeal(runId, runToken, sealOccurrenceId, "df050505-0505-4505-8505-050505050505"),
		);
		writeServiceTestJson(join(runDir, "service-finalization-seal-replay-ambiguity.json"), {
			schemaVersion: 1,
			kind: "service_run_seal_replay_ambiguity",
			runId,
			runToken,
			terminalOccurrenceId: intentOccurrenceId,
			reason: "seal_namespace_invalid_or_unbound",
		});
		writeServiceTestJson(join(runDir, `service-finalization-publication-intent-${finalizationId}.json`), {
			schemaVersion: 1,
			kind: "service_finalization_publication_intent",
			runId,
			finalizationId,
		});
		writeServiceTestJson(join(runDir, ".service-finalization-complete"), {
			schemaVersion: 2,
			state: "incident_reclaimable",
			runId,
			finalizationId,
			outcome: "incomplete",
			retentionAnchorWallTimeMs,
		});
		const initialNames = readdirSync(runDir).sort();
		const initialBytes = new Map(
			initialNames.map((name) => [name, readFileSync(join(runDir, name), "utf8")] as const),
		);

		mockReadyServiceCompactor();
		const streamStoppedTargetArtifact = vi
			.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
			.mockImplementation(() => {
				throw new Error("current mismatched-occurrence completion attempted stopped-target capture");
			});
		const projectRunHistory = vi
			.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
			.mockImplementation(() => {
				throw new Error("current mismatched-occurrence completion attempted projection");
			});
		const sealRunIdentity = vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity");
		const fenceRunIdentity = vi.spyOn(IncidentRecorderWriter.prototype, "fenceRunIdentity");
		const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
		const assertStable = (): void => {
			expect(readdirSync(runDir).sort()).toEqual(initialNames);
			for (const [name, bytes] of initialBytes) expect(readFileSync(join(runDir, name), "utf8"), name).toBe(bytes);
			expect(existsSync(join(runDir, ".service-control-quarantine"))).toBe(false);
			expect(existsSync(join(runDir, "raw-reports"))).toBe(false);
			expect(existsSync(join(runDir, "evidence", "provider-artifacts"))).toBe(false);
		};

		await runReadyServiceUntil(
			target.agentDir,
			() => adoptRunIdentitySeal.mock.calls.some(([candidate]) => (candidate as { runId?: string }).runId === runId),
			"first intent-A seal-B completion inspection",
		);
		assertStable();
		const firstInspectionAdoptions = adoptRunIdentitySeal.mock.calls.filter(
			([candidate]) => (candidate as { runId?: string }).runId === runId,
		).length;
		await runReadyServiceUntil(
			target.agentDir,
			() =>
				adoptRunIdentitySeal.mock.calls.filter(([candidate]) => (candidate as { runId?: string }).runId === runId)
					.length > firstInspectionAdoptions,
			"second intent-A seal-B completion inspection",
		);
		assertStable();
		expect(streamStoppedTargetArtifact).not.toHaveBeenCalled();
		expect(projectRunHistory).not.toHaveBeenCalled();
		expect(sealRunIdentity).not.toHaveBeenCalled();
		expect(fenceRunIdentity).not.toHaveBeenCalled();
	}, 20_000);

	it.each([
		["matching intent/seal after seal-without-intent replay", "a", "canonical", "seal_observed_without_intent"],
		["fence-only seal after intent-without-seal replay", "b", "fence", "seal_intent_without_seal_observed"],
	] as const)(
		"accepts a published replay-incomplete completion for %s without repeated control churn",
		async (_label, namespace, sealKind, replayReason) => {
			const target = fixture();
			const uuid = (slot: string): string => `d${namespace}${slot}00000-0000-4000-8000-00000000000${slot}`;
			const runId = uuid("1");
			const runToken = "11111111-1111-4111-8111-111111111111";
			const terminalOccurrenceId = uuid("2");
			const producerId = uuid("3");
			const retentionAnchorWallTimeMs = Date.parse("2000-01-01T00:00:00.000Z");
			const runDir = stoppedServiceRun(target, runId, runToken, `expired-${runId}`);
			const incidentDirectory = writeExpiredPublishedIncident(
				target.agentDir,
				runId,
				"replayed_after_ambiguous_seal_attempt",
				"incomplete",
				terminalOccurrenceId,
				producerId,
				sealKind,
			);
			const finalizationId = publishedFinalizationId(incidentDirectory);
			writeDurableServiceSeal(runDir, runId, runToken, terminalOccurrenceId, producerId, retentionAnchorWallTimeMs);
			if (sealKind === "fence")
				writeServiceTestJson(
					join(runDir, "service-finalization-seal.json"),
					testFenceOnlyServiceSeal(runId, runToken),
				);
			writeServiceTestJson(join(runDir, "service-finalization-seal-replay-ambiguity.json"), {
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId,
				runToken,
				terminalOccurrenceId,
				reason: replayReason,
			});
			writeServiceTestJson(join(runDir, `service-finalization-publication-intent-${finalizationId}.json`), {
				schemaVersion: 1,
				kind: "service_finalization_publication_intent",
				runId,
				finalizationId,
			});
			writeServiceTestJson(join(runDir, ".service-finalization-complete"), {
				schemaVersion: 2,
				state: "incident_reclaimable",
				runId,
				finalizationId,
				outcome: "incomplete",
				retentionAnchorWallTimeMs,
			});
			const initialNames = readdirSync(runDir).sort();
			const initialBytes = new Map(
				initialNames.map((name) => [name, readFileSync(join(runDir, name), "utf8")] as const),
			);

			mockReadyServiceCompactor();
			const streamStoppedTargetArtifact = vi
				.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
				.mockImplementation(() => {
					throw new Error("current replay-incomplete completion attempted stopped-target capture");
				});
			const projectRunHistory = vi
				.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
				.mockImplementation(() => {
					throw new Error("current replay-incomplete completion attempted projection");
				});
			const sealRunIdentity = vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity");
			const fenceRunIdentity = vi.spyOn(IncidentRecorderWriter.prototype, "fenceRunIdentity");
			const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
			const assertStable = (): void => {
				expect(readdirSync(runDir).sort()).toEqual(initialNames);
				for (const [name, bytes] of initialBytes)
					expect(readFileSync(join(runDir, name), "utf8"), name).toBe(bytes);
				expect(existsSync(join(runDir, ".service-control-quarantine"))).toBe(false);
			};

			await runReadyServiceUntil(
				target.agentDir,
				() =>
					adoptRunIdentitySeal.mock.calls.some(([candidate]) => (candidate as { runId?: string }).runId === runId),
				`first ${_label} inspection`,
			);
			assertStable();
			const firstAdoptions = adoptRunIdentitySeal.mock.calls.filter(
				([candidate]) => (candidate as { runId?: string }).runId === runId,
			).length;
			await runReadyServiceUntil(
				target.agentDir,
				() =>
					adoptRunIdentitySeal.mock.calls.filter(
						([candidate]) => (candidate as { runId?: string }).runId === runId,
					).length > firstAdoptions,
				`second ${_label} inspection`,
			);
			assertStable();
			expect(streamStoppedTargetArtifact).not.toHaveBeenCalled();
			expect(projectRunHistory).not.toHaveBeenCalled();
			expect(sealRunIdentity).not.toHaveBeenCalled();
			expect(fenceRunIdentity).not.toHaveBeenCalled();
		},
		20_000,
	);

	it.each([
		["intent-A seal-B replay", "7", "mismatch", "seal_namespace_invalid_or_unbound"],
		["matching intent and seal replay", "8", "matching", "seal_observed_without_intent"],
		["fence-only replay", "9", "fence", "seal_intent_without_seal_observed"],
	] as const)(
		"converges a published complete tuple with %s through immutable conflict authority",
		async (_label, namespace, replayKind, replayReason) => {
			const target = fixture();
			const uuid = (slot: string): string => `cf${namespace}${slot}0000-0000-4000-8000-00000000000${slot}`;
			const runId = uuid("1");
			const runToken = "11111111-1111-4111-8111-111111111111";
			const intentOccurrenceId = uuid("2");
			const emittedSealOccurrenceId = replayKind === "mismatch" ? uuid("3") : intentOccurrenceId;
			const emittedSealProducerId = replayKind === "mismatch" ? uuid("5") : uuid("4");
			const retentionAnchorWallTimeMs = Date.parse("2000-01-01T00:00:00.000Z");
			const runDir = stoppedServiceRun(target, runId, runToken, `expired-${runId}`);
			const incidentDirectory = writeExpiredPublishedIncident(
				target.agentDir,
				runId,
				"relayed",
				"complete",
				replayKind === "fence" ? uuid("6") : emittedSealOccurrenceId,
				replayKind === "fence" ? uuid("7") : emittedSealProducerId,
			);
			const publishedFinalization = publishedFinalizationId(incidentDirectory);
			writeDurableServiceSeal(runDir, runId, runToken, intentOccurrenceId, uuid("4"), retentionAnchorWallTimeMs);
			if (replayKind === "mismatch")
				writeServiceTestJson(
					join(runDir, "service-finalization-seal.json"),
					testServiceSeal(runId, runToken, emittedSealOccurrenceId, emittedSealProducerId),
				);
			else if (replayKind === "fence")
				writeServiceTestJson(
					join(runDir, "service-finalization-seal.json"),
					testFenceOnlyServiceSeal(runId, runToken),
				);
			writeServiceTestJson(join(runDir, "service-finalization-seal-replay-ambiguity.json"), {
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId,
				runToken,
				terminalOccurrenceId: intentOccurrenceId,
				reason: replayReason,
			});
			writeServiceTestJson(join(runDir, `service-finalization-publication-intent-${publishedFinalization}.json`), {
				schemaVersion: 1,
				kind: "service_finalization_publication_intent",
				runId,
				finalizationId: publishedFinalization,
			});
			const completionPath = join(runDir, ".service-finalization-complete");
			writeServiceTestJson(completionPath, {
				schemaVersion: 2,
				state: "incident_reclaimable",
				runId,
				finalizationId: publishedFinalization,
				outcome: "complete",
				retentionAnchorWallTimeMs,
			});
			const originalIncidentNames = readdirSync(incidentDirectory).sort();
			const originalIncidentBytes = new Map(
				originalIncidentNames
					.filter((name) => statSync(join(incidentDirectory, name)).isFile())
					.map((name) => [name, readFileSync(join(incidentDirectory, name))] as const),
			);

			mockReadyServiceCompactor();
			vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
			const projectRunHistory = vi
				.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
				.mockImplementation((input) => {
					const seal = JSON.parse(
						readFileSync(join(runDir, "service-finalization-seal.json"), "utf8"),
					) as ReturnType<typeof testFenceOnlyServiceSeal>;
					return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
				});
			const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
			await runReadyServiceUntil(
				target.agentDir,
				() => {
					if (!existsSync(completionPath)) return false;
					return (
						(JSON.parse(readFileSync(completionPath, "utf8")) as { state?: unknown }).state ===
						"publication_conflict_reclaimable"
					);
				},
				`${_label} publication conflict recovery`,
			);
			const proof = readPublicationConflictProof(runDir);
			readPublicationConflictCompletion(runDir, proof);
			expect(proof).toMatchObject({
				runId,
				runToken,
				publishedFinalizationId: publishedFinalization,
				publishedState: "complete",
				publishedRetentionAnchorWallTimeMs: retentionAnchorWallTimeMs,
				publishedServiceTerminalRelayDisposition: "relayed",
				intendedState: "incomplete",
				intendedRetentionAnchorWallTimeMs: retentionAnchorWallTimeMs,
				intendedServiceTerminalRelayDisposition: "replayed_after_ambiguous_seal_attempt",
			});
			const completionQuarantine = readdirSync(join(runDir, ".service-control-quarantine")).filter((name) =>
				name.startsWith("completion-"),
			);
			expect(completionQuarantine).toHaveLength(1);
			const publicationIntents = readdirSync(runDir).filter((name) =>
				name.startsWith("service-finalization-publication-intent-"),
			);
			expect(publicationIntents.sort()).toEqual(
				[
					`service-finalization-publication-intent-${publishedFinalization}.json`,
					`service-finalization-publication-intent-${proof.intendedFinalizationId}.json`,
				].sort(),
			);
			expect(readdirSync(incidentDirectory).sort()).toEqual(originalIncidentNames);
			for (const [name, bytes] of originalIncidentBytes)
				expect(readFileSync(join(incidentDirectory, name)), name).toEqual(bytes);

			const stableRunNames = readdirSync(runDir).sort();
			const stableRunBytes = new Map(
				stableRunNames
					.filter((name) => statSync(join(runDir, name)).isFile())
					.map((name) => [name, readFileSync(join(runDir, name))] as const),
			);
			const projectionsBeforeRepeatedInspection = projectRunHistory.mock.calls.length;
			const adoptionsBeforeRepeatedInspection = adoptRunIdentitySeal.mock.calls.length;
			await runReadyServiceUntil(
				target.agentDir,
				() => adoptRunIdentitySeal.mock.calls.length > adoptionsBeforeRepeatedInspection,
				`${_label} publication conflict repeated inspection`,
			);
			expect(projectRunHistory.mock.calls.length).toBe(projectionsBeforeRepeatedInspection);
			expect(readdirSync(runDir).sort()).toEqual(stableRunNames);
			for (const [name, bytes] of stableRunBytes) expect(readFileSync(join(runDir, name)), name).toEqual(bytes);
			expect(readdirSync(incidentDirectory).sort()).toEqual(originalIncidentNames);
			for (const [name, bytes] of originalIncidentBytes)
				expect(readFileSync(join(incidentDirectory, name)), name).toEqual(bytes);
		},
		20_000,
	);

	it("restarts from an immutable publication-conflict proof without reprojection or namespace churn", async () => {
		const target = fixture();
		const runId = "cfa10101-0101-4101-8101-010101010101";
		const runToken = "11111111-1111-4111-8111-111111111111";
		const terminalOccurrenceId = "cfa30303-0303-4303-8303-030303030303";
		const producerId = "cfa40404-0404-4404-8404-040404040404";
		const retentionAnchorWallTimeMs = Date.parse("2000-01-01T00:00:00.000Z");
		const completionPath = join(
			target.agentDir,
			"incident-recorder",
			"runs",
			`expired-${runId}`,
			".service-finalization-complete",
		);

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		let projectionEnabled = false;
		const projectRunHistory = vi
			.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
			.mockImplementation((input) => {
				if (!projectionEnabled) throw new Error("publication-conflict crash fixture projection held");
				const seal = JSON.parse(
					readFileSync(join(dirname(completionPath), "service-finalization-seal.json"), "utf8"),
				) as ReturnType<typeof testServiceSeal>;
				return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
			});
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		let runDir = dirname(completionPath);
		let incidentDirectory = "";
		let publishedFinalization = "";
		let originalIncidentBytes = new Map<string, Buffer>();
		const injected = new Error("crash after publication-conflict proof before completion");
		try {
			running = runIncidentRecorderService(target.agentDir, {
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready, 10_000);
			runDir = stoppedServiceRun(target, runId, runToken, `expired-${runId}`);
			incidentDirectory = writeExpiredPublishedIncident(
				target.agentDir,
				runId,
				"relayed",
				"complete",
				terminalOccurrenceId,
				producerId,
			);
			publishedFinalization = publishedFinalizationId(incidentDirectory);
			writeDurableServiceSeal(runDir, runId, runToken, terminalOccurrenceId, producerId, retentionAnchorWallTimeMs);
			writeServiceTestJson(join(runDir, "service-finalization-seal-replay-ambiguity.json"), {
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId,
				runToken,
				terminalOccurrenceId,
				reason: "seal_observed_without_intent",
			});
			writeServiceTestJson(join(runDir, `service-finalization-publication-intent-${publishedFinalization}.json`), {
				schemaVersion: 1,
				kind: "service_finalization_publication_intent",
				runId,
				finalizationId: publishedFinalization,
			});
			writeServiceTestJson(completionPath, {
				schemaVersion: 2,
				state: "incident_reclaimable",
				runId,
				finalizationId: publishedFinalization,
				outcome: "complete",
				retentionAnchorWallTimeMs,
			});
			originalIncidentBytes = new Map(
				readdirSync(incidentDirectory)
					.filter((name) => statSync(join(incidentDirectory, name)).isFile())
					.map((name) => [name, readFileSync(join(incidentDirectory, name))] as const),
			);
			projectionEnabled = true;
			let rejection: unknown;
			for (let attempt = 0; attempt < 64 && rejection === undefined; attempt += 1) {
				try {
					await inspectIncidentRecorderRuns(target.agentDir, Date.now(), {
						onFinalizationFaultBoundary: (boundary) => {
							if (boundary === "after_source_marker_before_reclaim_complete") throw injected;
						},
					});
				} catch (error) {
					rejection = error;
				}
			}
			expect(
				rejection,
				`projection calls=${projectRunHistory.mock.calls.length}; proof=${existsSync(join(runDir, "service-finalization-publication-conflict.json"))}; completion=${existsSync(completionPath)}`,
			).toBe(injected);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running, 10_000);
		}

		const proofPath = join(runDir, "service-finalization-publication-conflict.json");
		const proof = readPublicationConflictProof(runDir);
		const proofBytes = readFileSync(proofPath, "utf8");
		expect(proof).toMatchObject({
			runId,
			runToken,
			publishedFinalizationId: publishedFinalization,
			publishedState: "complete",
			intendedState: "incomplete",
			intendedServiceTerminalRelayDisposition: "replayed_after_ambiguous_seal_attempt",
		});
		expect(existsSync(completionPath)).toBe(false);
		expect(
			readdirSync(join(runDir, ".service-control-quarantine")).filter((name) => name.startsWith("completion-")),
		).toHaveLength(1);
		for (const [name, bytes] of originalIncidentBytes)
			expect(readFileSync(join(incidentDirectory, name)), name).toEqual(bytes);
		const projectionCountAfterCrash = projectRunHistory.mock.calls.length;
		expect(projectionCountAfterCrash).toBe(1);

		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(completionPath),
			"publication-conflict completion after restart",
		);
		readPublicationConflictCompletion(runDir, proof);
		expect(readFileSync(proofPath, "utf8")).toBe(proofBytes);
		expect(projectRunHistory.mock.calls.length).toBe(projectionCountAfterCrash);
		const stableRunNames = readdirSync(runDir).sort();
		const stableRunBytes = new Map(
			stableRunNames
				.filter((name) => statSync(join(runDir, name)).isFile())
				.map((name) => [name, readFileSync(join(runDir, name))] as const),
		);
		const stableIncidentNames = readdirSync(incidentDirectory).sort();
		await runReadyServiceUntil(target.agentDir, () => true, "publication-conflict stable heartbeat");
		expect(projectRunHistory.mock.calls.length).toBe(projectionCountAfterCrash);
		expect(readdirSync(runDir).sort()).toEqual(stableRunNames);
		for (const [name, bytes] of stableRunBytes) expect(readFileSync(join(runDir, name)), name).toEqual(bytes);
		expect(readdirSync(incidentDirectory).sort()).toEqual(stableIncidentNames);
		for (const [name, bytes] of originalIncidentBytes)
			expect(readFileSync(join(incidentDirectory, name)), name).toEqual(bytes);
	}, 20_000);

	it("discovers a provider manifest after more than eight ordered references", async () => {
		const target = fixture();
		const runId = "e1010101-0101-4101-8101-010101010101";
		const runToken = "e2020202-0202-4202-8202-020202020202";
		const runDir = stoppedServiceRun(target, runId, runToken);
		writeServiceTestJson(join(runDir, "raw-reports", "capture-complete.json"), {
			schemaVersion: 1,
			kind: "node_report_capture_complete",
			state: "complete",
			runId,
			reasons: [],
		});
		const referenceDirectory = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(runId).digest("hex"),
		);
		for (let index = 0; index < 9; index += 1)
			writeServiceTestJson(join(referenceDirectory, `seq-${index.toString().padStart(3, "0")}.json`), {
				type: "unrelated_test_reference",
			});
		const artifactPath = join(target.root, "late-provider-artifact.bin");
		writeFileSync(artifactPath, "provider artifact\n", { mode: 0o600 });
		const manifestPath = join(target.root, "late-provider-manifest.json");
		const manifestBytes = writeServiceTestJson(
			manifestPath,
			diagnosticProviderManifest("sysdig", artifactPath, "test-provider-bytes"),
		);
		writeServiceTestJson(join(referenceDirectory, "seq-999-provider.json"), {
			type: "provider_source_manifest_registered",
			cas: { path: manifestPath, bytes: Buffer.byteLength(manifestBytes) },
		});

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		const streamStoppedTargetArtifact = vi
			.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
			.mockImplementation(
				(candidateRunId, sourcePath, encoding) =>
					({
						state: "complete",
						artifact: writeServiceTestCapturedArtifact(target.agentDir, candidateRunId, sourcePath, encoding),
					}) as never,
			);
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation(() => {
			throw new Error("Incident run-history projection capacity is saturated");
		});
		const providerCompletionPath = join(runDir, "evidence", "provider-artifacts", "capture-complete.json");
		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(providerCompletionPath) && existsSync(join(runDir, "service-finalization-seal-intent.json")),
			"provider capture beyond the first ordered-reference batch",
		);
		expect(streamStoppedTargetArtifact).toHaveBeenCalledWith(
			runId,
			artifactPath,
			"test-provider-bytes",
			expect.any(Object),
		);
		expect(JSON.parse(readFileSync(providerCompletionPath, "utf8"))).toEqual({
			schemaVersion: 1,
			kind: "provider_artifact_capture_complete",
			state: "complete",
			runId,
			reasons: [],
		});
		expect(JSON.parse(readFileSync(join(dirname(providerCompletionPath), "capture-frontier.json"), "utf8"))).toEqual(
			providerCaptureFrontier(runId, ["seq-999-provider.json"]),
		);
	}, 20_000);

	it("reopens ordered provider discovery after EOF and finds a later append", async () => {
		const target = fixture();
		const runId = "e3030303-0303-4303-8303-030303030303";
		const runToken = "e4040404-0404-4404-8404-040404040404";
		const runDir = stoppedServiceRun(target, runId, runToken);
		const nodeReportPath = join(runDir, "raw-reports", "report.json");
		writeServiceTestJson(nodeReportPath, { header: { event: "Exception" } });
		const referenceDirectory = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(runId).digest("hex"),
		);
		mkdirSync(referenceDirectory, { recursive: true, mode: 0o700 });
		const artifactPath = join(target.root, "appended-provider-artifact.bin");
		writeFileSync(artifactPath, "appended provider artifact\n", { mode: 0o600 });

		let releaseNodeCapture = false;
		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		const streamStoppedTargetArtifact = vi
			.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
			.mockImplementation((_candidateRunId, sourcePath, encoding) => {
				if (sourcePath === nodeReportPath && !releaseNodeCapture) {
					return { state: "pending", reason: "work_budget", copiedBytes: 0, totalBytes: 1 } as never;
				}
				return {
					state: "complete",
					artifact: writeServiceTestCapturedArtifact(target.agentDir, _candidateRunId, sourcePath, encoding),
				} as never;
			});
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation(() => {
			throw new Error("Incident run-history projection capacity is saturated");
		});
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
			});
			running.catch(() => {});
			await withTimeout(ready);
			await waitForCondition(
				() => streamStoppedTargetArtifact.mock.calls.some(([, sourcePath]) => sourcePath === nodeReportPath),
				"node capture after initial ordered-reference EOF",
			);

			const manifestPath = join(target.root, "appended-provider-manifest.json");
			const manifestBytes = writeServiceTestJson(
				manifestPath,
				diagnosticProviderManifest("atop", artifactPath, "appended-provider-bytes"),
			);
			writeServiceTestJson(join(referenceDirectory, "seq-appended-provider.json"), {
				type: "provider_source_manifest_registered",
				cas: { path: manifestPath, bytes: Buffer.byteLength(manifestBytes) },
			});
			releaseNodeCapture = true;
			const providerCompletionPath = join(runDir, "evidence", "provider-artifacts", "capture-complete.json");
			await waitForCondition(
				() =>
					existsSync(providerCompletionPath) &&
					streamStoppedTargetArtifact.mock.calls.some(([, sourcePath]) => sourcePath === artifactPath) &&
					existsSync(join(runDir, "service-finalization-seal-intent.json")),
				"provider reference appended after ordered-reference EOF",
			);
			expect(JSON.parse(readFileSync(providerCompletionPath, "utf8"))).toEqual({
				schemaVersion: 1,
				kind: "provider_artifact_capture_complete",
				state: "complete",
				runId,
				reasons: [],
			});
			expect(
				JSON.parse(readFileSync(join(dirname(providerCompletionPath), "capture-frontier.json"), "utf8")),
			).toEqual(providerCaptureFrontier(runId, ["seq-appended-provider.json"]));
		} finally {
			releaseNodeCapture = true;
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running);
		}
	}, 20_000);

	it("never silently omits a provider reference appended after zero-artifact completion but before seal", async () => {
		const target = fixture();
		const runId = "e5050505-0505-4505-8505-050505050505";
		const runToken = "e6060606-0606-4606-8606-060606060606";
		const runDir = join(target.agentDir, "incident-recorder", "runs", `2026-08-31T00-00-00.000Z-${runId}`);
		const referenceDirectory = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(runId).digest("hex"),
		);
		const artifactPath = join(target.root, "post-completion-provider-artifact.bin");
		writeFileSync(artifactPath, "provider bytes appended before seal\n", { mode: 0o600 });
		const manifestPath = join(target.root, "post-completion-provider-manifest.json");
		const providerCompletionPath = join(runDir, "evidence", "provider-artifacts", "capture-complete.json");
		let completionObservedBeforeAppend: unknown;
		let frontierObservedBeforeAppend: unknown;
		let appended = false;

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		const streamStoppedTargetArtifact = vi
			.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
			.mockImplementation(
				(_candidateRunId, sourcePath, encoding) =>
					({
						state: "complete",
						artifact: {
							algorithm: "sha256",
							digest: createHash("sha256").update(readFileSync(sourcePath)).digest("hex"),
							bytes: readFileSync(sourcePath).length,
							path: sourcePath,
							encoding,
						},
					}) as never,
			);
		const originalSealRunIdentity = IncidentRecorderWriter.prototype.sealRunIdentity;
		let emittedSeal: ReturnType<typeof testServiceSeal> | undefined;
		vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity").mockImplementation(function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["sealRunIdentity"]>
		) {
			return originalSealRunIdentity.apply(this, args).then((seal) => {
				emittedSeal = seal as unknown as ReturnType<typeof testServiceSeal>;
				return seal;
			});
		});
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			if (!emittedSeal) throw new Error("missing seal after late provider reference gate");
			return incompleteProjectionForSeal(input.runId, runToken, emittedSeal) as never;
		});
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
		const appendAtBoundary = (boundary: string): void => {
			if (boundary !== "after_stopped_capture_before_seal" || appended) return;
			completionObservedBeforeAppend = JSON.parse(readFileSync(providerCompletionPath, "utf8"));
			frontierObservedBeforeAppend = JSON.parse(
				readFileSync(join(dirname(providerCompletionPath), "capture-frontier.json"), "utf8"),
			);
			const manifestBytes = writeServiceTestJson(
				manifestPath,
				diagnosticProviderManifest("atop", artifactPath, "post-completion-provider-bytes"),
			);
			writeServiceTestJson(join(referenceDirectory, "seq-post-completion-provider.json"), {
				type: "provider_source_manifest_registered",
				cas: { path: manifestPath, bytes: Buffer.byteLength(manifestBytes) },
			});
			appended = true;
		};
		try {
			running = runIncidentRecorderService(target.agentDir, {
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			stoppedServiceRun(target, runId, runToken);
			mkdirSync(referenceDirectory, { recursive: true, mode: 0o700 });
			for (
				let attempt = 0;
				attempt < 4 && !existsSync(join(incidentDirectory, "finalization-descriptor.json"));
				attempt += 1
			)
				await inspectIncidentRecorderRuns(target.agentDir, Date.now(), {
					onFinalizationFaultBoundary: appendAtBoundary,
				});
			await waitForCondition(
				() => existsSync(join(incidentDirectory, "finalization-descriptor.json")),
				"late provider reference capture or explicit incomplete finalization",
			);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running);
		}

		expect(appended).toBe(true);
		expect(completionObservedBeforeAppend).toEqual({
			schemaVersion: 1,
			kind: "provider_artifact_capture_complete",
			state: "complete",
			runId,
			reasons: [],
		});
		expect(frontierObservedBeforeAppend).toEqual(providerCaptureFrontier(runId, []));
		const descriptor = JSON.parse(readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8")) as {
			stoppedTarget: { captureState: string; artifacts: Array<{ role?: string }> };
		};
		const captured = streamStoppedTargetArtifact.mock.calls.some(([, sourcePath]) => sourcePath === artifactPath);
		expect(captured || descriptor.stoppedTarget.captureState === "incomplete").toBe(true);
		if (descriptor.stoppedTarget.captureState === "complete") {
			expect(captured).toBe(true);
			expect(descriptor.stoppedTarget.artifacts.some((artifact) => artifact.role === "provider-artifact")).toBe(
				true,
			);
		}
	}, 20_000);

	it("quarantines a stale seal-intent anchor and preserves replay ambiguity", async () => {
		const target = fixture();
		const runId = "da010101-0101-4101-8101-010101010101";
		const runToken = "da020202-0202-4202-8202-020202020202";
		const staleOccurrenceId = "da030303-0303-4303-8303-030303030303";
		const retentionAnchorWallTimeMs = 1_800_000_000_000;
		const runDir = stoppedServiceRun(target, runId, runToken);
		writeZeroArtifactCaptureCompletion(runDir, runId);
		writeServiceTestJson(join(runDir, "service-finalization-stopped-observation.json"), {
			schemaVersion: 1,
			kind: "service_stopped_observation",
			runId,
			runToken,
			firstObservedStoppedWallTimeMs: retentionAnchorWallTimeMs,
			disposition: "exact_first_observation",
		});
		writeServiceTestJson(join(runDir, "service-finalization-seal-intent.json"), {
			schemaVersion: 1,
			kind: "service_run_seal_intent",
			runId,
			runToken,
			terminalOccurrenceId: staleOccurrenceId,
			retentionAnchorWallTimeMs: retentionAnchorWallTimeMs - 1,
			stoppedObservationDisposition: "exact_first_observation",
		});

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		const sealRunIdentity = vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity");
		const fenceRunIdentity = vi.spyOn(IncidentRecorderWriter.prototype, "fenceRunIdentity");
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			const seal = JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8")) as ReturnType<
				typeof testFenceOnlyServiceSeal
			>;
			return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
		});
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(join(incidentDirectory, "finalization-descriptor.json")),
			"stale seal-intent replay finalization",
		);

		const recoveredIntent = JSON.parse(
			readFileSync(join(runDir, "service-finalization-seal-intent.json"), "utf8"),
		) as Record<string, unknown>;
		expect(recoveredIntent).toMatchObject({
			runId,
			runToken,
			retentionAnchorWallTimeMs,
			stoppedObservationDisposition: "exact_first_observation",
		});
		expect(recoveredIntent.terminalOccurrenceId).not.toBe(staleOccurrenceId);
		expect(
			JSON.parse(readFileSync(join(runDir, "service-finalization-seal-replay-ambiguity.json"), "utf8")),
		).toMatchObject({
			runId,
			runToken,
			terminalOccurrenceId: recoveredIntent.terminalOccurrenceId,
			reason: "seal_namespace_invalid_or_unbound",
		});
		expect(JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8"))).toEqual(
			testFenceOnlyServiceSeal(runId, runToken),
		);
		expect(sealRunIdentity).not.toHaveBeenCalled();
		expect(fenceRunIdentity).toHaveBeenCalledTimes(1);
		expect(fenceRunIdentity).toHaveBeenCalledWith(
			{
				runId,
				runToken,
				targetPid: 2_147_483_647,
				targetProcessStartId: "proc:1",
				disposition: "exact_process_control",
			},
			{ durableReplay: true },
		);
		expect(
			readdirSync(join(runDir, ".service-control-quarantine")).some((name) => name.startsWith("seal-intent-")),
		).toBe(true);
		const descriptor = JSON.parse(readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8")) as {
			state: string;
			reasons: string[];
		};
		expect(descriptor.state).toBe("incomplete");
		expect(descriptor.reasons).toContain("service_terminal_relay_disposition:replayed_after_ambiguous_seal_attempt");
	}, 20_000);

	it("does not capture evidence written after an adoptable durable service seal", async () => {
		const target = fixture();
		const runId = "ed010101-0101-4101-8101-010101010101";
		const runToken = "ed020202-0202-4202-8202-020202020202";
		const terminalOccurrenceId = "ed030303-0303-4303-8303-030303030303";
		const producerId = "ed040404-0404-4404-8404-040404040404";
		const runDir = stoppedServiceRun(target, runId, runToken);
		const seal = writeDurableServiceSeal(runDir, runId, runToken, terminalOccurrenceId, producerId);
		const sealPath = join(runDir, "service-finalization-seal.json");
		const intentPath = join(runDir, "service-finalization-seal-intent.json");
		const sealBytes = readFileSync(sealPath, "utf8");
		const intentBytes = readFileSync(intentPath, "utf8");
		const nodeReportPath = join(runDir, "raw-reports", "late-report.json");
		const nodeReportBytes = writeServiceTestJson(nodeReportPath, { header: { event: "Exception" } });
		const providerArtifactPath = join(target.root, "late-after-seal-provider.bin");
		writeFileSync(providerArtifactPath, "late provider bytes\n", { mode: 0o600 });
		const providerManifestPath = join(target.root, "late-after-seal-provider-manifest.json");
		const providerManifestBytes = writeServiceTestJson(
			providerManifestPath,
			diagnosticProviderManifest("sysdig", providerArtifactPath, "late-provider-bytes"),
		);
		writeServiceTestJson(
			join(
				target.agentDir,
				"incident-recorder",
				"refs",
				"runs",
				createHash("sha256").update(runId).digest("hex"),
				"seq-late-provider.json",
			),
			{
				type: "provider_source_manifest_registered",
				cas: { path: providerManifestPath, bytes: Buffer.byteLength(providerManifestBytes) },
			},
		);

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		const streamStoppedTargetArtifact = vi
			.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
			.mockImplementation(() => {
				throw new Error("post-seal stopped-target capture attempted");
			});
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation(
			(input) => incompleteProjectionForSeal(input.runId, runToken, seal) as never,
		);
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(join(incidentDirectory, "finalization-descriptor.json")),
			"durably sealed run finalization without later evidence capture",
		);

		expect(streamStoppedTargetArtifact).not.toHaveBeenCalled();
		expect(readFileSync(nodeReportPath, "utf8")).toBe(nodeReportBytes);
		expect(readFileSync(sealPath, "utf8")).toBe(sealBytes);
		expect(readFileSync(intentPath, "utf8")).toBe(intentBytes);
		expect(existsSync(join(runDir, "raw-reports", "capture-complete.json"))).toBe(false);
		expect(existsSync(join(runDir, "evidence", "provider-artifacts"))).toBe(false);
		const descriptor = JSON.parse(readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8")) as {
			reasons: string[];
			stoppedTarget: { captureState: string; artifacts: unknown[] };
		};
		expect(descriptor.stoppedTarget.captureState).toBe("incomplete");
		expect(descriptor.stoppedTarget.artifacts).toEqual([]);
		expect(descriptor.reasons).toContain("stopped_target_capture_incomplete");
	}, 20_000);

	it("rejects direct fallback evidence and manifests after durable seal adoption across restart", async () => {
		const target = fixture();
		const runId = "ee010101-0101-4101-8101-010101010101";
		const runToken = "ee020202-0202-4202-8202-020202020202";
		const terminalOccurrenceId = "ee030303-0303-4303-8303-030303030303";
		const runDir = stoppedServiceRun(target, runId, runToken);
		const seal = writeDurableServiceSeal(
			runDir,
			runId,
			runToken,
			terminalOccurrenceId,
			"ee040404-0404-4404-8404-040404040404",
		);
		const snapshotTree = (root: string): string[] => {
			const result: string[] = [];
			const visit = (directory: string, prefix: string): void => {
				for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
					a.name.localeCompare(b.name),
				)) {
					const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
					const path = join(directory, entry.name);
					if (entry.isDirectory()) {
						result.push(`directory:${relative}`);
						visit(path, relative);
					} else {
						result.push(`file:${relative}:${readFileSync(path).toString("base64")}`);
					}
				}
			};
			visit(root, "");
			return result;
		};
		const adoptOnRestart = async (namespace: string): Promise<void> => {
			const writer = new IncidentRecorderWriter({
				runDir: join(target.root, `service-writer-${namespace}`),
				runId: `ee${namespace}0000-0000-4000-8000-000000000001`,
				runToken: `ee${namespace}0000-0000-4000-8000-000000000002`,
				serviceSink: true,
			});
			try {
				expect(writer.adoptRunIdentitySeal(seal)).toMatchObject({ adopted: true });
			} finally {
				await writer.stop(25);
			}
		};

		const previousRunDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
		try {
			process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = runDir;
			await adoptOnRestart("11");
			const before = snapshotTree(target.agentDir);
			ingestIncidentRecorderEvidence(runDir, "kernel", Buffer.from("sealed direct evidence one"));
			registerIncidentProviderSourceManifest(runDir, { provider: "sysdig", artifacts: [] });
			appendSupervisorDiagnosticEvent("sealed_direct_derived_probe", { diagnosticOnly: true });
			appendSupervisorDiagnosticBytes("sealed_direct_bytes_probe", Buffer.from("sealed raw bytes one"), {
				diagnosticOnly: true,
			});
			await adoptOnRestart("22");
			ingestIncidentRecorderEvidence(runDir, "kernel", Buffer.from("sealed direct evidence two"));
			registerIncidentProviderSourceManifest(runDir, { provider: "sysdig", artifacts: [] });
			appendSupervisorDiagnosticEvent("sealed_direct_derived_probe_after_restart", {
				diagnosticOnly: true,
			});
			appendSupervisorDiagnosticBytes(
				"sealed_direct_bytes_probe_after_restart",
				Buffer.from("sealed raw bytes two"),
				{ diagnosticOnly: true },
			);
			await new Promise<void>((resolve) => setTimeout(resolve, 50));

			expect(existsSync(join(runDir, ".cas-leases"))).toBe(false);
			expect(existsSync(join(runDir, "evidence", "kernel.jsonl"))).toBe(false);
			expect(existsSync(join(runDir, "evidence", "provider-source-manifests.jsonl"))).toBe(false);
			expect(existsSync(join(runDir, "raw-segments"))).toBe(false);
			expect(existsSync(join(target.agentDir, "incident-recorder", "cas"))).toBe(false);
			expect(snapshotTree(target.agentDir)).toEqual(before);
		} finally {
			if (previousRunDir === undefined) delete process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
			else process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = previousRunDir;
		}
	});

	it.each([
		["missing", "5"],
		["invalid", "6"],
	] as const)(
		"adopts a durable seal with %s intent and recovers explicit ambiguity without later evidence writes",
		async (intentState, namespace) => {
			const target = fixture();
			const uuid = (slot: string): string => `ec${namespace}${slot}0000-0000-4000-8000-00000000000${slot}`;
			const runId = uuid("1");
			const runToken = uuid("2");
			const terminalOccurrenceId = uuid("3");
			const producerId = uuid("4");
			const runDir = stoppedServiceRun(target, runId, runToken);
			const seal = writeDurableServiceSeal(runDir, runId, runToken, terminalOccurrenceId, producerId);
			const sealPath = join(runDir, "service-finalization-seal.json");
			const intentPath = join(runDir, "service-finalization-seal-intent.json");
			const sealBytes = readFileSync(sealPath, "utf8");
			if (intentState === "missing") rmSync(intentPath);
			else writeServiceTestJson(intentPath, 7);
			const nodeReportPath = join(runDir, "raw-reports", "late-after-seal-report.json");
			const nodeReportBytes = writeServiceTestJson(nodeReportPath, { header: { event: "Exception" } });
			const providerArtifactPath = join(target.root, `${intentState}-intent-provider.bin`);
			writeFileSync(providerArtifactPath, "late provider evidence\n", { mode: 0o600 });
			const providerManifestPath = join(target.root, `${intentState}-intent-provider-manifest.json`);
			const providerManifestBytes = writeServiceTestJson(
				providerManifestPath,
				diagnosticProviderManifest("sysdig", providerArtifactPath, "late-provider-bytes"),
			);
			writeServiceTestJson(
				join(
					target.agentDir,
					"incident-recorder",
					"refs",
					"runs",
					createHash("sha256").update(runId).digest("hex"),
					"seq-late-provider.json",
				),
				{
					type: "provider_source_manifest_registered",
					cas: { path: providerManifestPath, bytes: Buffer.byteLength(providerManifestBytes) },
				},
			);

			mockReadyServiceCompactor();
			vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
			const streamStoppedTargetArtifact = vi
				.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact")
				.mockImplementation(() => {
					throw new Error("post-adoption stopped-target capture attempted");
				});
			const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
			vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
			vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation(
				(input) => incompleteProjectionForSeal(input.runId, runToken, seal) as never,
			);
			const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
			await runReadyServiceUntil(
				target.agentDir,
				() => existsSync(join(incidentDirectory, "finalization-descriptor.json")),
				`${intentState} intent durable-seal adoption`,
			);

			expect(
				adoptRunIdentitySeal.mock.calls.some(([candidate]) => (candidate as { runId?: string }).runId === runId),
			).toBe(true);
			expect(streamStoppedTargetArtifact).not.toHaveBeenCalled();
			expect(readFileSync(nodeReportPath, "utf8")).toBe(nodeReportBytes);
			expect(readFileSync(sealPath, "utf8")).toBe(sealBytes);
			expect(existsSync(join(runDir, "raw-reports", "capture-complete.json"))).toBe(false);
			expect(existsSync(join(runDir, "evidence", "provider-artifacts"))).toBe(false);
			expect(JSON.parse(readFileSync(intentPath, "utf8"))).toEqual({
				schemaVersion: 1,
				kind: "service_run_seal_intent",
				runId,
				runToken,
				terminalOccurrenceId,
				retentionAnchorWallTimeMs: 1_800_000_000_000,
				stoppedObservationDisposition: "exact_first_observation",
			});
			expect(
				JSON.parse(readFileSync(join(runDir, "service-finalization-seal-replay-ambiguity.json"), "utf8")),
			).toEqual({
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId,
				runToken,
				terminalOccurrenceId,
				reason: "seal_observed_without_intent",
			});
			if (intentState === "invalid") {
				expect(
					readdirSync(join(runDir, ".service-control-quarantine")).some((name) => name.startsWith("seal-intent-")),
				).toBe(true);
			}
			const descriptor = JSON.parse(
				readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8"),
			) as { reasons: string[]; stoppedTarget: { captureState: string; artifacts: unknown[] } };
			expect(descriptor.stoppedTarget.captureState).toBe("incomplete");
			expect(descriptor.stoppedTarget.artifacts).toEqual([]);
			expect(descriptor.reasons).toContain("stopped_target_capture_incomplete");
			expect(descriptor.reasons).toContain(
				"service_terminal_relay_disposition:replayed_after_ambiguous_seal_attempt",
			);
		},
		20_000,
	);

	it("reports stopped capture failures without rejecting zero or resolved artifact sets", async () => {
		const target = fixture();
		type CaptureFault = "open" | "read" | "overflow" | "pending" | "error";
		type CaptureRole = "node" | "provider";
		interface CaptureDefinition {
			name: string;
			runId: string;
			runToken: string;
			occurrenceId: string;
			producerId: string;
			role?: CaptureRole;
			fault?: CaptureFault;
		}
		const faultDefinitions = (["node", "provider"] as const).flatMap((role, roleIndex) =>
			(["open", "read", "overflow", "pending", "error"] as const).map((fault, faultIndex) => {
				const suffix = String(roleIndex * 5 + faultIndex + 1).padStart(12, "0");
				return {
					name: `${role}-${fault}`,
					role,
					fault,
					runId: `c9000000-0000-4000-8000-${suffix}`,
					runToken: `ca000000-0000-4000-8000-${suffix}`,
					occurrenceId: `cb000000-0000-4000-8000-${suffix}`,
					producerId: `cc000000-0000-4000-8000-${suffix}`,
				};
			}),
		);
		const definitions: CaptureDefinition[] = [
			{
				name: "zero",
				runId: "c1010101-0101-4101-8101-010101010101",
				runToken: "c2020202-0202-4202-8202-020202020202",
				occurrenceId: "c3030303-0303-4303-8303-030303030303",
				producerId: "c4040404-0404-4404-8404-040404040404",
			},
			{
				name: "resolved",
				runId: "c5050505-0505-4505-8505-050505050505",
				runToken: "c6060606-0606-4606-8606-060606060606",
				occurrenceId: "c7070707-0707-4707-8707-070707070707",
				producerId: "c8080808-0808-4808-8808-080808080808",
			},
			...faultDefinitions,
		];
		const captureDirectory = (runDir: string, role: CaptureRole): string =>
			role === "node" ? join(runDir, "raw-reports") : join(runDir, "evidence", "provider-artifacts");
		const writeCompleteCapture = (runDir: string, runId: string, role: CaptureRole): void => {
			writeServiceTestJson(join(captureDirectory(runDir, role), "capture-complete.json"), {
				schemaVersion: 1,
				kind: role === "node" ? "node_report_capture_complete" : "provider_artifact_capture_complete",
				state: "complete",
				runId,
				reasons: [],
			});
			if (role === "provider") writeEmptyProviderCaptureFrontier(runDir, runId);
		};
		const seals = new Map<string, ReturnType<typeof testServiceSeal>>();
		const incidentDirectories = new Map<string, string>();
		const readFaultDirectories = new Set<string>();
		for (const definition of definitions) {
			const runDir = stoppedServiceRun(target, definition.runId, definition.runToken);
			const seal = writeDurableServiceSeal(
				runDir,
				definition.runId,
				definition.runToken,
				definition.occurrenceId,
				definition.producerId,
			);
			seals.set(definition.runId, seal);
			incidentDirectories.set(
				definition.name,
				join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${definition.runId}`),
			);
			if (definition.name === "zero" || definition.name === "resolved") {
				writeZeroArtifactCaptureCompletion(runDir, definition.runId);
			}
			if (definition.name === "resolved") {
				for (const [role, directory, stem] of [
					["node", join(runDir, "raw-reports"), "report.json"],
					["provider", join(runDir, "evidence", "provider-artifacts"), "provider-artifact"],
				] as const) {
					const sourcePath = join(runDir, `${role}-resolved-source.bin`);
					writeFileSync(sourcePath, "", { mode: 0o600 });
					const source = statSync(sourcePath);
					const sourceMetadata = {
						path: sourcePath,
						dev: String(source.dev),
						ino: String(source.ino),
						bytes: source.size,
						mtimeMs: source.mtimeMs,
					};
					const artifact = writeServiceTestCapturedArtifact(
						target.agentDir,
						definition.runId,
						sourcePath,
						"exact-test-bytes",
					);
					writeServiceTestJson(join(directory, `${stem}.pending.json`), {
						schemaVersion: 1,
						state: "pending",
					});
					writeServiceTestJson(
						join(directory, `${stem}.reference.json`),
						role === "node"
							? {
									schemaVersion: 1,
									state: "complete",
									occurrence: { originalPath: sourcePath, sourceMetadata },
									artifact,
								}
							: {
									schemaVersion: 1,
									state: "complete",
									source: {
										provider: "fixture-provider",
										sourcePath,
										dev: sourceMetadata.dev,
										ino: sourceMetadata.ino,
										bytes: sourceMetadata.bytes,
										mtimeMs: sourceMetadata.mtimeMs,
									},
									artifact,
								},
					);
				}
			}
			if (definition.role && definition.fault) {
				const otherRole: CaptureRole = definition.role === "node" ? "provider" : "node";
				writeCompleteCapture(runDir, definition.runId, otherRole);
				const directory = captureDirectory(runDir, definition.role);
				if (definition.fault === "open") {
					mkdirSync(dirname(directory), { recursive: true, mode: 0o700 });
					writeFileSync(directory, "not a directory\n", { mode: 0o600 });
					continue;
				}
				writeCompleteCapture(runDir, definition.runId, definition.role);
				if (definition.fault === "read") {
					readFaultDirectories.add(directory);
				}
				if (definition.fault === "overflow") {
					for (let index = 0; index < 97; index += 1)
						writeFileSync(join(directory, `overflow-${index.toString().padStart(3, "0")}.txt`), "x", {
							mode: 0o600,
						});
				}
				if (definition.fault === "pending") {
					writeServiceTestJson(join(directory, "unresolved.pending.json"), { state: "pending" });
				}
				if (definition.fault === "error") {
					writeServiceTestJson(join(directory, "failed.error.json"), { state: "error" });
				}
			}
		}

		const probeDirectory = join(target.root, "capture-directory-prototype-probe");
		mkdirSync(probeDirectory, { mode: 0o700 });
		const probeHandle = opendirSync(probeDirectory);
		type TestDirectoryHandle = {
			path: string;
			readSync: () => ReturnType<typeof probeHandle.readSync>;
		};
		const directoryPrototype = Object.getPrototypeOf(probeHandle) as TestDirectoryHandle;
		const originalDirectoryReadSync = directoryPrototype.readSync;
		probeHandle.closeSync();
		vi.spyOn(directoryPrototype, "readSync").mockImplementation(function (this: TestDirectoryHandle) {
			if (readFaultDirectories.has(String(this.path))) {
				throw new Error("service lifecycle injected capture-directory read failure");
			}
			return originalDirectoryReadSync.call(this);
		});
		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			const definition = definitions.find((candidate) => candidate.runId === input.runId);
			const seal = seals.get(input.runId);
			if (!definition || !seal) throw new Error(`missing stopped capture fixture for ${input.runId}`);
			return incompleteProjectionForSeal(input.runId, definition.runToken, seal) as never;
		});
		await runReadyServiceUntil(
			target.agentDir,
			() =>
				[...incidentDirectories.values()].every((directory) =>
					existsSync(join(directory, "finalization-descriptor.json")),
				),
			"stopped capture finalizations",
		);

		for (const definition of definitions) {
			const incidentDirectory = incidentDirectories.get(definition.name);
			if (!incidentDirectory) throw new Error(`missing incident directory for ${definition.name}`);
			const descriptor = JSON.parse(
				readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8"),
			) as {
				reasons: string[];
				stoppedTarget: { captureState: string; artifacts: unknown[] };
			};
			const expectedComplete = definition.name === "zero" || definition.name === "resolved";
			expect(descriptor.stoppedTarget.captureState).toBe(expectedComplete ? "complete" : "incomplete");
			expect(descriptor.reasons.includes("stopped_target_capture_incomplete")).toBe(!expectedComplete);
			if (definition.name === "zero") expect(descriptor.stoppedTarget.artifacts).toEqual([]);
			if (definition.name === "resolved") expect(descriptor.stoppedTarget.artifacts).toHaveLength(2);
		}
	}, 20_000);

	it("quarantines malformed stopped-capture completions and converges with durable incomplete evidence", async () => {
		const target = fixture();
		const definitions = [
			{
				name: "primitive",
				runId: "ee010101-0101-4101-8101-010101010101",
				runToken: "ee020202-0202-4202-8202-020202020202",
			},
			{
				name: "extra-key",
				runId: "ee030303-0303-4303-8303-030303030303",
				runToken: "ee040404-0404-4404-8404-040404040404",
			},
			{
				name: "wrong-state",
				runId: "ee050505-0505-4505-8505-050505050505",
				runToken: "ee060606-0606-4606-8606-060606060606",
			},
		] as const;
		const runDirectories = new Map<string, string>();
		const incidentDirectories = new Map<string, string>();
		const invalidCompletion = (
			definition: (typeof definitions)[number],
			kind: "node_report_capture_complete" | "provider_artifact_capture_complete",
		): unknown => {
			if (definition.name === "primitive") return 7;
			if (definition.name === "extra-key") {
				return {
					schemaVersion: 1,
					kind,
					state: "complete",
					runId: definition.runId,
					reasons: [],
					unexpected: true,
				};
			}
			return {
				schemaVersion: 1,
				kind,
				state: "pending",
				runId: definition.runId,
				reasons: [],
			};
		};
		const invalidFrontier = (definition: (typeof definitions)[number]): unknown => {
			if (definition.name === "primitive") return 7;
			if (definition.name === "extra-key") {
				return { ...providerCaptureFrontier(definition.runId, []), unexpected: true };
			}
			return { ...providerCaptureFrontier(definition.runId, []), referenceCount: 1 };
		};
		for (const definition of definitions) {
			const runDir = stoppedServiceRun(target, definition.runId, definition.runToken);
			runDirectories.set(definition.name, runDir);
			incidentDirectories.set(
				definition.name,
				join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${definition.runId}`),
			);
			writeServiceTestJson(
				join(runDir, "raw-reports", "capture-complete.json"),
				invalidCompletion(definition, "node_report_capture_complete"),
			);
			writeServiceTestJson(
				join(runDir, "evidence", "provider-artifacts", "capture-complete.json"),
				invalidCompletion(definition, "provider_artifact_capture_complete"),
			);
			writeServiceTestJson(
				join(runDir, "evidence", "provider-artifacts", "capture-frontier.json"),
				invalidFrontier(definition),
			);
			mkdirSync(
				join(
					target.agentDir,
					"incident-recorder",
					"refs",
					"runs",
					createHash("sha256").update(definition.runId).digest("hex"),
				),
				{ recursive: true, mode: 0o700 },
			);
		}

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		const emittedSeals = new Map<string, ReturnType<typeof testServiceSeal>>();
		const originalSealRunIdentity = IncidentRecorderWriter.prototype.sealRunIdentity;
		vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity").mockImplementation(function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["sealRunIdentity"]>
		) {
			return originalSealRunIdentity.apply(this, args).then((seal) => {
				emittedSeals.set(seal.runId, seal as unknown as ReturnType<typeof testServiceSeal>);
				return seal;
			});
		});
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			const definition = definitions.find((candidate) => candidate.runId === input.runId);
			const seal = emittedSeals.get(input.runId);
			if (!definition || !seal) throw new Error(`missing recovered capture fixture for ${input.runId}`);
			return incompleteProjectionForSeal(input.runId, definition.runToken, seal) as never;
		});
		await runReadyServiceUntil(
			target.agentDir,
			() =>
				[...incidentDirectories.values()].every((directory) =>
					existsSync(join(directory, "finalization-descriptor.json")),
				),
			"malformed stopped-capture completion recovery",
		);

		for (const definition of definitions) {
			const runDir = runDirectories.get(definition.name);
			const incidentDirectory = incidentDirectories.get(definition.name);
			if (!runDir || !incidentDirectory) throw new Error(`missing malformed fixture for ${definition.name}`);
			expect(JSON.parse(readFileSync(join(runDir, "raw-reports", "capture-complete.json"), "utf8"))).toEqual({
				schemaVersion: 1,
				kind: "node_report_capture_complete",
				state: "incomplete",
				runId: definition.runId,
				reasons: ["invalid_prior_report_capture_completion"],
			});
			expect(
				JSON.parse(readFileSync(join(runDir, "evidence", "provider-artifacts", "capture-complete.json"), "utf8")),
			).toEqual({
				schemaVersion: 1,
				kind: "provider_artifact_capture_complete",
				state: "incomplete",
				runId: definition.runId,
				reasons: ["invalid_prior_provider_capture_completion"],
			});
			expect(
				JSON.parse(readFileSync(join(runDir, "evidence", "provider-artifacts", "capture-frontier.json"), "utf8")),
			).toEqual(providerCaptureFrontier(definition.runId, []));
			const quarantineNames = readdirSync(join(runDir, ".service-control-quarantine"));
			expect(quarantineNames.filter((name) => name.startsWith("node-report-capture-completion-"))).toHaveLength(1);
			expect(
				quarantineNames.filter((name) => name.startsWith("provider-artifact-capture-completion-")),
			).toHaveLength(1);
			expect(quarantineNames.filter((name) => name.startsWith("provider-artifact-capture-frontier-"))).toHaveLength(
				1,
			);
			const descriptor = JSON.parse(
				readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8"),
			) as { reasons: string[]; stoppedTarget: { captureState: string } };
			expect(descriptor.stoppedTarget.captureState).toBe("incomplete");
			expect(descriptor.reasons).toContain("stopped_target_capture_incomplete");
		}
	}, 20_000);

	it("keeps readiness with four pending run projections and a fifth capacity rejection", async () => {
		const target = fixture();
		const definitions = Array.from({ length: 5 }, (_, index) => {
			const suffix = String(index + 1).padStart(12, "0");
			return {
				runId: `d6000000-0000-4000-8000-${suffix}`,
				runToken: `d7000000-0000-4000-8000-${suffix}`,
				occurrenceId: `d8000000-0000-4000-8000-${suffix}`,
				producerId: `d9000000-0000-4000-8000-${suffix}`,
			};
		});
		const seals = new Map<string, ReturnType<typeof testServiceSeal>>();
		for (const definition of definitions) {
			const runDir = stoppedServiceRun(target, definition.runId, definition.runToken);
			writeZeroArtifactCaptureCompletion(runDir, definition.runId);
			seals.set(
				definition.runId,
				writeDurableServiceSeal(
					runDir,
					definition.runId,
					definition.runToken,
					definition.occurrenceId,
					definition.producerId,
				),
			);
		}
		const pendingRunIds = new Set(definitions.slice(0, 4).map((definition) => definition.runId));
		const observedRunIds = new Set<string>();
		mockReadyServiceCompactor();
		const projectRunHistory = vi
			.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
			.mockImplementation((input) => {
				observedRunIds.add(input.runId);
				if (!pendingRunIds.has(input.runId)) {
					throw new Error("Incident run-history projection capacity is saturated");
				}
				const definition = definitions.find((candidate) => candidate.runId === input.runId);
				const seal = seals.get(input.runId);
				if (!definition || !seal) throw new Error(`missing pending projection fixture for ${input.runId}`);
				return {
					state: "pending",
					cursor: {
						version: 1,
						token: `pending-${input.runId}`,
						requestFingerprint: createHash("sha256").update(input.runId).digest("hex"),
					},
					projection: incompleteProjectionForSeal(input.runId, definition.runToken, seal).projection,
				} as never;
			});
		await runReadyServiceUntil(
			target.agentDir,
			() => definitions.every((definition) => observedRunIds.has(definition.runId)),
			"five independent run projection attempts after readiness",
		);
		expect(observedRunIds).toEqual(new Set(definitions.map((definition) => definition.runId)));
		expect(projectRunHistory.mock.calls.some(([input]) => input.runId === definitions[4]?.runId)).toBe(true);
	}, 20_000);

	it("permanently seals a run identity with one exact terminal frontier", async () => {
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "91919191-9191-4191-8191-919191919191",
			runToken: "92929292-9292-4292-8292-929292929292",
			serviceSink: true,
		});
		const identity = {
			runId: "93939393-9393-4393-8393-939393939393",
			runToken: "94949494-9494-4494-8494-949494949494",
		};
		try {
			expect(
				writer.recordDerivedForRun(identity, "recorder-control", "before_seal", {
					diagnosticOnly: true,
				}).accepted,
			).toBe(true);

			const firstSeal = writer.sealRunIdentity(identity);
			const concurrentSeal = writer.sealRunIdentity(identity);
			expect(concurrentSeal).toBe(firstSeal);
			const [first, concurrent] = await Promise.all([firstSeal, concurrentSeal]);
			expect(concurrent).toBe(first);
			expect(first).toMatchObject({
				schemaVersion: 1,
				state: "sealed",
				runId: identity.runId,
				runToken: identity.runToken,
				terminal: {
					type: "capture_channel_terminal",
					admission: { accepted: true, disposition: "locally_admitted" },
					frontier: {
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
			if (!first.terminal.admission?.accepted) throw new Error("terminal admission was not accepted");
			expect(first.terminal.frontier?.occurrenceId).toBe(first.terminal.admission.occurrenceId);
			expect(Object.isFrozen(first)).toBe(true);
			expect(Object.isFrozen(first.terminal)).toBe(true);
			expect(Object.isFrozen(first.terminal.frontier)).toBe(true);
			expect(Object.isFrozen(first.loss)).toBe(true);

			await writer.releaseRunIdentity(identity);
			expect(writer.sealRunIdentity(identity)).toBe(firstSeal);
			expect(writer.recordDerivedForRun(identity, "recorder-control", "after_seal", {})).toMatchObject({
				accepted: false,
				reason: "run_identity_sealed",
			});
			expect(
				writer.recordExactBytesForRun(identity, "stderr", "after_seal", Buffer.from("late"), "utf8", {}),
			).toMatchObject({ accepted: false, reason: "run_identity_sealed" });
		} finally {
			await writer.stop(25);
		}
	});

	it("uses one deterministic terminal occurrence for a seal and its adopted replay", async () => {
		const original = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "d1919191-9191-4191-8191-919191919191",
			runToken: "d2929292-9292-4292-8292-929292929292",
			serviceSink: true,
		});
		const recovered = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "d3939393-9393-4393-8393-939393939393",
			runToken: "d4949494-9494-4494-8494-949494949494",
			serviceSink: true,
		});
		const identity = {
			runId: "d5959595-9595-4595-8595-959595959595",
			runToken: "d6969696-9696-4696-8696-969696969696",
		};
		const terminalOccurrenceId = "d7979797-9797-4797-8797-979797979797";
		try {
			const sealing = original.sealRunIdentity(identity, 1_000, terminalOccurrenceId);
			expect(original.sealRunIdentity(identity, 1_000, terminalOccurrenceId)).toBe(sealing);
			const seal = await sealing;
			expect(seal.terminal.admission).toMatchObject({
				accepted: true,
				occurrenceId: terminalOccurrenceId,
				disposition: "locally_admitted",
			});
			expect(seal.terminal.frontier?.occurrenceId).toBe(terminalOccurrenceId);

			const adoption = recovered.adoptRunIdentitySeal(JSON.parse(JSON.stringify(seal)));
			expect(adoption).toMatchObject({ adopted: true, disposition: "adopted" });
			if (!adoption.adopted) throw new Error("deterministic durable seal adoption failed");
			expect(await recovered.sealRunIdentity(identity, 1_000, terminalOccurrenceId)).toBe(adoption.seal);
		} finally {
			await Promise.all([original.stop(25), recovered.stop(25)]);
		}
	});

	it("keeps short-deadline drain and relay loss accounting bounded and coherent", async () => {
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "95959595-9595-4595-8595-959595959595",
			runToken: "96969696-9696-4696-8696-969696969696",
			serviceSink: true,
		});
		const identity = {
			runId: "97979797-9797-4797-8797-979797979797",
			runToken: "98989898-9898-4898-8898-989898989898",
		};
		try {
			const payload = Buffer.alloc(48 * 1024, 0x61);
			expect(writer.recordExactBytesForRun(identity, "stderr", "queued_one", payload, "exact", {}).accepted).toBe(
				true,
			);
			expect(writer.recordExactBytesForRun(identity, "stderr", "queued_two", payload, "exact", {}).accepted).toBe(
				true,
			);

			const seal = await writer.sealRunIdentity(identity, 1);
			for (const count of [
				seal.loss.emitter,
				seal.loss.drainTimeout.definite,
				seal.loss.drainTimeout.uncertain,
				seal.loss.terminalRelay.definite,
				seal.loss.terminalRelay.uncertain,
			]) {
				expect(Number.isSafeInteger(count.records)).toBe(true);
				expect(Number.isSafeInteger(count.bytes)).toBe(true);
				expect(count.records).toBeGreaterThanOrEqual(0);
				expect(count.bytes).toBeGreaterThanOrEqual(0);
				if (count.records === 0) expect(count.bytes).toBe(0);
			}
			expect(seal.loss.emitter.records).toBeLessThanOrEqual(2);
			expect(seal.loss.emitter.bytes).toBeLessThanOrEqual(2 * payload.length);
			expect(seal.loss.drainTimeout.definite.records + seal.loss.drainTimeout.uncertain.records).toBeLessThanOrEqual(
				2,
			);
			expect(seal.loss.drainTimeout.definite.bytes + seal.loss.drainTimeout.uncertain.bytes).toBeLessThanOrEqual(
				2 * payload.length,
			);
			expect(
				seal.loss.terminalRelay.definite.records + seal.loss.terminalRelay.uncertain.records,
			).toBeLessThanOrEqual(1);
			expect(seal.loss.terminalRelay.definite.bytes).toBe(0);
			expect(seal.loss.terminalRelay.uncertain.bytes).toBe(0);
		} finally {
			await writer.stop(25);
		}
	});

	it("adopts an exact durable seal without emitting another terminal and rejects active ambiguity", async () => {
		const original = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "a1919191-9191-4191-8191-919191919191",
			runToken: "a2929292-9292-4292-8292-929292929292",
			serviceSink: true,
		});
		const recovered = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "a3939393-9393-4393-8393-939393939393",
			runToken: "a4949494-9494-4494-8494-949494949494",
			serviceSink: true,
		});
		const ambiguous = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "a5959595-9595-4595-8595-959595959595",
			runToken: "a6969696-9696-4696-8696-969696969696",
			serviceSink: true,
		});
		const identity = {
			runId: "a7979797-9797-4797-8797-979797979797",
			runToken: "a8989898-9898-4898-8898-989898989898",
		};
		try {
			const durableSeal = await original.sealRunIdentity(identity);
			const adopted = recovered.adoptRunIdentitySeal(durableSeal);
			expect(adopted).toMatchObject({
				adopted: true,
				disposition: "adopted",
				seal: durableSeal,
			});
			const repeated = recovered.adoptRunIdentitySeal(JSON.parse(JSON.stringify(durableSeal)));
			expect(repeated).toMatchObject({ adopted: true, disposition: "already_adopted" });
			if (!adopted.adopted || !repeated.adopted) throw new Error("durable seal adoption failed");
			expect(repeated.seal).toBe(adopted.seal);
			expect(await recovered.sealRunIdentity(identity)).toBe(adopted.seal);
			expect(recovered.recordDerivedForRun(identity, "recorder-control", "late", {})).toMatchObject({
				accepted: false,
				reason: "run_identity_sealed",
			});

			expect(ambiguous.recordDerivedForRun(identity, "recorder-control", "active", {}).accepted).toBe(true);
			expect(ambiguous.adoptRunIdentitySeal(durableSeal)).toEqual({
				adopted: false,
				disposition: "rejected",
				reason: "run_identity_active_or_stopping",
			});
		} finally {
			await Promise.all([original.stop(25), recovered.stop(25), ambiguous.stop(25)]);
		}
	});

	it("keeps an intent-without-seal replay ambiguity durable across two service restarts", async () => {
		const target = fixture();
		const runId = "e1919191-9191-4191-8191-919191919191";
		const runToken = "e2929292-9292-4292-8292-929292929292";
		const terminalOccurrenceId = "e3939393-9393-4393-8393-939393939393";
		const retentionAnchorWallTimeMs = 1_800_000_000_000;
		const runDir = join(target.agentDir, "incident-recorder", "runs", `2026-08-31T00-00-00.000Z-${runId}`);
		mkdirSync(runDir, { recursive: true, mode: 0o700 });
		const writeRunControl = (name: string, value: unknown): string => {
			const bytes = `${JSON.stringify(value)}\n`;
			writeFileSync(join(runDir, name), bytes, { mode: 0o600 });
			return bytes;
		};
		writeRunControl("launch.json", serviceTestLaunchControl(join(target.root, "stopped.sock")));
		writeRunControl("process.json", serviceTestProcessControl(runToken));
		writeRunControl("service-finalization-stopped-observation.json", {
			schemaVersion: 1,
			kind: "service_stopped_observation",
			runId,
			runToken,
			firstObservedStoppedWallTimeMs: retentionAnchorWallTimeMs,
			disposition: "exact_first_observation",
		});
		const intentPath = join(runDir, "service-finalization-seal-intent.json");
		const intentBytes = writeRunControl("service-finalization-seal-intent.json", {
			schemaVersion: 1,
			kind: "service_run_seal_intent",
			runId,
			runToken,
			terminalOccurrenceId,
			retentionAnchorWallTimeMs,
			stoppedObservationDisposition: "exact_first_observation",
		});
		writeRunControl(
			`service-finalization-barrier-deadline-${createHash("sha256").update(`${runId}\0${runToken}`).digest("hex")}.json`,
			{
				schemaVersion: 1,
				kind: "service_finalization_barrier_deadline",
				runId,
				runToken,
				createdWallTimeMs: 0,
				retryThroughWallTimeMs: 60_000,
			},
		);
		const ambiguityPath = join(runDir, "service-finalization-seal-replay-ambiguity.json");
		const sealPath = join(runDir, "service-finalization-seal.json");

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation(() => {
			throw new Error("Incident run-history projection capacity is saturated");
		});
		const sealRunIdentity = vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity");
		const originalFenceRunIdentity = IncidentRecorderWriter.prototype.fenceRunIdentity;
		const fenceRunIdentity = vi
			.spyOn(IncidentRecorderWriter.prototype, "fenceRunIdentity")
			.mockImplementation(function (
				this: IncidentRecorderWriter,
				...args: Parameters<IncidentRecorderWriter["fenceRunIdentity"]>
			) {
				return originalFenceRunIdentity.apply(this, args);
			});
		const originalAdoptRunIdentitySeal = IncidentRecorderWriter.prototype.adoptRunIdentitySeal;
		const adoptRunIdentitySeal = vi
			.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal")
			.mockImplementation(function (
				this: IncidentRecorderWriter,
				...args: Parameters<IncidentRecorderWriter["adoptRunIdentitySeal"]>
			) {
				return originalAdoptRunIdentitySeal.apply(this, args);
			});
		const runOneRestart = async (processed: () => boolean, description: string): Promise<void> => {
			const signals = new TestSignalSource();
			let stopRequested = false;
			const requestStop = (): void => {
				if (stopRequested) return;
				stopRequested = true;
				signals.emit("SIGTERM");
			};
			let resolveReady: () => void = () => {};
			const ready = new Promise<void>((resolve) => {
				resolveReady = resolve;
			});
			let running: Promise<void> | undefined;
			try {
				running = runIncidentRecorderService(target.agentDir, {
					notify: (fields) => {
						if (fields.includes("READY=1")) {
							resolveReady();
							if (processed()) requestStop();
						}
					},
					signalSource: signals,
					writerStopDeadlineMs: 1_000,
				});
				running.catch(() => {});
				await withTimeout(ready);
				await waitForCondition(processed, description);
				requestStop();
			} finally {
				if (!stopRequested && signals.size > 0) requestStop();
				if (running) await withTimeout(running);
			}
		};

		await runOneRestart(
			() => existsSync(ambiguityPath) && existsSync(sealPath),
			"intent replay ambiguity and deterministic service seal",
		);
		const ambiguityBytes = readFileSync(ambiguityPath, "utf8");
		const sealBytes = readFileSync(sealPath, "utf8");
		expect(readFileSync(intentPath, "utf8")).toBe(intentBytes);
		expect(JSON.parse(ambiguityBytes)).toEqual({
			schemaVersion: 1,
			kind: "service_run_seal_replay_ambiguity",
			runId,
			runToken,
			terminalOccurrenceId,
			reason: "seal_intent_without_seal_observed",
		});
		expect(JSON.parse(sealBytes)).toEqual(testFenceOnlyServiceSeal(runId, runToken));
		expect(sealRunIdentity).not.toHaveBeenCalled();
		expect(fenceRunIdentity).toHaveBeenCalledTimes(1);
		expect(fenceRunIdentity.mock.calls[0]?.[0]).toEqual({
			runId,
			runToken,
			targetPid: 2_147_483_647,
			targetProcessStartId: "proc:1",
			disposition: "exact_process_control",
		});
		const fencingWriter = fenceRunIdentity.mock.instances[0];

		await runOneRestart(
			() => adoptRunIdentitySeal.mock.instances.some((writer) => writer !== fencingWriter),
			"durable service seal adoption on second restart",
		);
		expect(readFileSync(intentPath, "utf8")).toBe(intentBytes);
		expect(readFileSync(ambiguityPath, "utf8")).toBe(ambiguityBytes);
		expect(readFileSync(sealPath, "utf8")).toBe(sealBytes);
		expect(sealRunIdentity).not.toHaveBeenCalled();
		expect(fenceRunIdentity).toHaveBeenCalledTimes(1);
		const replayAdoptions = adoptRunIdentitySeal.mock.instances
			.map((writer, index) => ({ writer, call: adoptRunIdentitySeal.mock.calls[index] }))
			.filter(({ writer }) => writer !== fencingWriter);
		expect(replayAdoptions).toHaveLength(1);
		expect(replayAdoptions[0]?.call?.[0]).toEqual(JSON.parse(sealBytes));
		expect(replayAdoptions[0]?.call?.[1]).toEqual({ durableReplay: true });
	}, 10_000);

	it("preserves seal-without-intent ambiguity across a crash before reconstructed intent", async () => {
		const target = fixture();
		const runId = "b3010101-0101-4101-8101-010101010101";
		const runToken = "b3020202-0202-4202-8202-020202020202";
		const retentionAnchorWallTimeMs = 1_800_000_000_000;
		const runDir = join(target.agentDir, "incident-recorder", "runs", `2026-08-31T00-00-00.000Z-${runId}`);
		const stoppedPath = join(runDir, "service-finalization-stopped-observation.json");
		const intentPath = join(runDir, "service-finalization-seal-intent.json");
		const replayPath = join(runDir, "service-finalization-seal-replay-ambiguity.json");
		const sealPath = join(runDir, "service-finalization-seal.json");
		const completionPath = join(runDir, ".service-finalization-complete");
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			const seal = JSON.parse(readFileSync(sealPath, "utf8")) as ReturnType<typeof testFenceOnlyServiceSeal>;
			return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
		});
		const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		let replayBytesAfterCrash = "";
		try {
			running = runIncidentRecorderService(target.agentDir, {
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready, 10_000);
			stoppedServiceRun(target, runId, runToken);
			writeServiceTestJson(stoppedPath, {
				schemaVersion: 1,
				kind: "service_stopped_observation",
				runId,
				runToken,
				firstObservedStoppedWallTimeMs: retentionAnchorWallTimeMs,
				disposition: "exact_first_observation",
			});
			const sealBytes = writeServiceTestJson(sealPath, testFenceOnlyServiceSeal(runId, runToken));
			const injected = new Error("crash after replay marker before reconstructed intent");
			const rejection = await captureRejection(
				inspectIncidentRecorderRuns(target.agentDir, Date.now(), {
					onFinalizationFaultBoundary: (boundary) => {
						if (boundary === "after_replay_marker_durable_before_reconstructed_intent") throw injected;
					},
				}),
			);
			expect(rejection).toBe(injected);
			expect(existsSync(intentPath)).toBe(false);
			expect(readFileSync(sealPath, "utf8")).toBe(sealBytes);
			replayBytesAfterCrash = readFileSync(replayPath, "utf8");
			const replayAfterCrash = JSON.parse(replayBytesAfterCrash) as Record<string, unknown>;
			expect(replayAfterCrash).toMatchObject({
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId,
				runToken,
				reason: "seal_observed_without_intent",
			});
			expect(replayBytesAfterCrash).toBe(`${JSON.stringify(replayAfterCrash)}\n`);
			expect(existsSync(completionPath)).toBe(false);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running, 10_000);
		}

		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(completionPath),
			"seal-without-intent crash recovery publication",
		);
		const intent = JSON.parse(readFileSync(intentPath, "utf8")) as {
			terminalOccurrenceId: string;
			retentionAnchorWallTimeMs: number;
		};
		const replay = JSON.parse(readFileSync(replayPath, "utf8")) as Record<string, unknown>;
		expect(readFileSync(replayPath, "utf8")).toBe(replayBytesAfterCrash);
		expect(replay).toMatchObject({
			runId,
			runToken,
			terminalOccurrenceId: intent.terminalOccurrenceId,
			reason: "seal_observed_without_intent",
		});
		expect(intent.retentionAnchorWallTimeMs).toBe(retentionAnchorWallTimeMs);
		const descriptor = JSON.parse(readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8")) as {
			state: string;
			reasons: string[];
		};
		expect(descriptor.state).toBe("incomplete");
		expect(descriptor.reasons).toContain("service_terminal_relay_disposition:replayed_after_ambiguous_seal_attempt");
		const completion = readIncompleteServiceCompletion(runDir);
		expectIncompleteRetentionAuthority(incidentDirectory, runId, completion);
		expect(readdirSync(runDir).some((name) => name.startsWith("service-finalization-normal-authority-"))).toBe(false);

		const stableRunNames = readdirSync(runDir).sort();
		const stableIncidentNames = readdirSync(incidentDirectory).sort();
		const stablePaths = [
			stoppedPath,
			intentPath,
			replayPath,
			sealPath,
			completionPath,
			join(runDir, `service-finalization-publication-intent-${completion.finalizationId}.json`),
			join(incidentDirectory, "finalization-manifest.json"),
			join(incidentDirectory, "finalization-descriptor.json"),
			join(incidentDirectory, "retention-authority.json"),
		];
		const stableBytes = new Map(stablePaths.map((path) => [path, readFileSync(path, "utf8")] as const));
		const adoptionsBeforeRepeatedInspection = adoptRunIdentitySeal.mock.calls.filter(
			([candidate]) => (candidate as { runId?: string }).runId === runId,
		).length;
		await runReadyServiceUntil(
			target.agentDir,
			() =>
				adoptRunIdentitySeal.mock.calls.filter(([candidate]) => (candidate as { runId?: string }).runId === runId)
					.length > adoptionsBeforeRepeatedInspection,
			"stable seal-without-intent repeated inspection",
		);
		expect(readdirSync(runDir).sort()).toEqual(stableRunNames);
		expect(readdirSync(incidentDirectory).sort()).toEqual(stableIncidentNames);
		for (const [path, bytes] of stableBytes) expect(readFileSync(path, "utf8"), path).toBe(bytes);
	}, 20_000);

	it("preserves invalid stopped-observation provenance across a crash before quarantine", async () => {
		const target = fixture();
		const runId = "b4010101-0101-4101-8101-010101010101";
		const runToken = "b4020202-0202-4202-8202-020202020202";
		const producerId = "b4030303-0303-4303-8303-030303030303";
		const runDir = join(target.agentDir, "incident-recorder", "runs", `2026-08-31T00-00-00.000Z-${runId}`);
		const stoppedPath = join(runDir, "service-finalization-stopped-observation.json");
		const repairPath = join(runDir, "service-finalization-stopped-observation-repair.json");
		const intentPath = join(runDir, "service-finalization-seal-intent.json");
		const sealPath = join(runDir, "service-finalization-seal.json");
		const completionPath = join(runDir, ".service-finalization-complete");
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity").mockImplementation(
			async (identity, _deadlineMs, terminalOccurrenceId) => {
				if (!terminalOccurrenceId) throw new Error("missing deterministic terminal occurrence ID");
				return testServiceSeal(identity.runId, identity.runToken, terminalOccurrenceId, producerId) as never;
			},
		);
		const adoptRunIdentitySeal = vi
			.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal")
			.mockImplementation((seal) => ({ adopted: true, disposition: "adopted", seal }) as never);
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			const seal = JSON.parse(readFileSync(sealPath, "utf8")) as ReturnType<typeof testServiceSeal>;
			return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
		});
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		let repairBytesAfterCrash = "";
		try {
			running = runIncidentRecorderService(target.agentDir, {
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready, 10_000);
			stoppedServiceRun(target, runId, runToken);
			writeZeroArtifactCaptureCompletion(runDir, runId);
			const invalidObservationBytes = writeServiceTestJson(stoppedPath, null);
			const injected = new Error("crash after stopped-observation repair witness");
			const rejection = await captureRejection(
				inspectIncidentRecorderRuns(target.agentDir, Date.now(), {
					onFinalizationFaultBoundary: (boundary) => {
						if (boundary === "after_stopped_repair_witness_durable_before_observation_quarantine") {
							throw injected;
						}
					},
				}),
			);
			expect(rejection).toBe(injected);
			expect(readFileSync(stoppedPath, "utf8")).toBe(invalidObservationBytes);
			repairBytesAfterCrash = readFileSync(repairPath, "utf8");
			expect(JSON.parse(repairBytesAfterCrash)).toEqual({
				schemaVersion: 1,
				kind: "service_stopped_observation_repair",
				runId,
				runToken,
				reason: "invalid_control_observed",
			});
			expect(existsSync(intentPath)).toBe(false);
			expect(existsSync(completionPath)).toBe(false);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running, 10_000);
		}

		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(completionPath),
			"invalid stopped-observation crash recovery publication",
		);
		expect(readFileSync(repairPath, "utf8")).toBe(repairBytesAfterCrash);
		const stopped = JSON.parse(readFileSync(stoppedPath, "utf8")) as {
			firstObservedStoppedWallTimeMs: number;
			disposition: string;
		};
		expect(stopped.disposition).toBe("recovered_after_invalid_control");
		const intent = JSON.parse(readFileSync(intentPath, "utf8")) as Record<string, unknown>;
		expect(intent).toMatchObject({
			runId,
			runToken,
			retentionAnchorWallTimeMs: stopped.firstObservedStoppedWallTimeMs,
			stoppedObservationDisposition: "recovered_after_invalid_control",
		});
		expect(existsSync(join(runDir, "service-finalization-seal-replay-ambiguity.json"))).toBe(false);
		const descriptor = JSON.parse(readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8")) as {
			state: string;
			reasons: string[];
		};
		expect(descriptor.state).toBe("incomplete");
		expect(descriptor.reasons).toContain(
			"service_terminal_relay_disposition:recovered_after_invalid_stopped_observation",
		);
		const completion = readIncompleteServiceCompletion(runDir);
		expectIncompleteRetentionAuthority(incidentDirectory, runId, completion);
		expect(readdirSync(runDir).some((name) => name.startsWith("service-finalization-normal-authority-"))).toBe(false);
		expect(
			readdirSync(join(runDir, ".service-control-quarantine")).filter((name) =>
				name.startsWith("stopped-observation-"),
			),
		).toHaveLength(1);

		const stableRunNames = readdirSync(runDir).sort();
		const stableQuarantineNames = readdirSync(join(runDir, ".service-control-quarantine")).sort();
		const stablePaths = [
			stoppedPath,
			repairPath,
			intentPath,
			sealPath,
			completionPath,
			join(runDir, `service-finalization-publication-intent-${completion.finalizationId}.json`),
			join(incidentDirectory, "finalization-manifest.json"),
			join(incidentDirectory, "finalization-descriptor.json"),
			join(incidentDirectory, "retention-authority.json"),
		];
		const stableBytes = new Map(stablePaths.map((path) => [path, readFileSync(path, "utf8")] as const));
		const adoptionsBeforeRepeatedInspection = adoptRunIdentitySeal.mock.calls.length;
		await runReadyServiceUntil(
			target.agentDir,
			() => adoptRunIdentitySeal.mock.calls.length > adoptionsBeforeRepeatedInspection,
			"stable invalid stopped-observation repeated inspection",
		);
		expect(readdirSync(runDir).sort()).toEqual(stableRunNames);
		expect(readdirSync(join(runDir, ".service-control-quarantine")).sort()).toEqual(stableQuarantineNames);
		for (const [path, bytes] of stableBytes) expect(readFileSync(path, "utf8"), path).toBe(bytes);
		expect(JSON.parse(readFileSync(stoppedPath, "utf8"))).toMatchObject({
			disposition: "recovered_after_invalid_control",
		});
	}, 20_000);

	it("does not recreate a stopped run deleted at the repair-to-quarantine boundary", async () => {
		const target = fixture();
		const runId = "b4111111-1111-4111-8111-111111111111";
		const runToken = "b4122222-2222-4222-8222-222222222222";
		const runDir = join(target.agentDir, "incident-recorder", "runs", `2026-08-31T00-00-00.000Z-${runId}`);
		const stoppedPath = join(runDir, "service-finalization-stopped-observation.json");
		const incidentDirectory = join(target.agentDir, "incidents", basename(runDir));

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
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
			});
			running.catch(() => {});
			await withTimeout(ready, 10_000);
			stoppedServiceRun(target, runId, runToken);
			writeServiceTestJson(stoppedPath, null);

			let boundaryObserved = false;
			const finalized = await inspectIncidentRecorderRuns(target.agentDir, Date.now(), {
				onFinalizationFaultBoundary: (boundary) => {
					if (boundary !== "after_stopped_repair_witness_durable_before_observation_quarantine") return;
					boundaryObserved = true;
					rmSync(runDir, { recursive: true, force: true });
				},
			});
			expect(boundaryObserved).toBe(true);
			expect(finalized).toEqual([]);
			expect(existsSync(runDir)).toBe(false);
			expect(existsSync(incidentDirectory)).toBe(false);

			await inspectIncidentRecorderRuns(target.agentDir);
			expect(existsSync(runDir)).toBe(false);
			expect(existsSync(incidentDirectory)).toBe(false);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running, 10_000);
		}
	}, 20_000);

	it("makes a fresh terminal-unbound writer seal durably ambiguous and stably incomplete", async () => {
		const target = fixture();
		const runId = "b5010101-0101-4101-8101-010101010101";
		const runToken = "b5020202-0202-4202-8202-020202020202";
		const runDir = stoppedServiceRun(target, runId, runToken);
		writeZeroArtifactCaptureCompletion(runDir, runId);
		const sealPath = join(runDir, "service-finalization-seal.json");
		const intentPath = join(runDir, "service-finalization-seal-intent.json");
		const replayPath = join(runDir, "service-finalization-seal-replay-ambiguity.json");
		const completionPath = join(runDir, ".service-finalization-complete");
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		let emittedSeal: Awaited<ReturnType<IncidentRecorderWriter["sealRunIdentity"]>> | undefined;
		const sealRunIdentity = vi
			.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity")
			.mockImplementation(function (
				this: IncidentRecorderWriter,
				identity: Parameters<IncidentRecorderWriter["sealRunIdentity"]>[0],
			) {
				const seal = this.fenceRunIdentity(identity);
				emittedSeal = seal;
				return Promise.resolve(seal);
			});
		const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			return incompleteProjectionForSeal(input.runId, runToken, {
				terminal: { frontier: null },
			}) as never;
		});
		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(completionPath),
			"fresh terminal-unbound writer seal publication",
		);

		if (!emittedSeal) throw new Error("ordinary writer did not return a service seal");
		expect(emittedSeal.terminal.frontier).toBeNull();
		expect(emittedSeal.terminal.admission === null || emittedSeal.terminal.admission.accepted === false).toBe(true);
		expect(JSON.parse(readFileSync(sealPath, "utf8"))).toEqual(emittedSeal);
		const intent = JSON.parse(readFileSync(intentPath, "utf8")) as { terminalOccurrenceId: string };
		expect(JSON.parse(readFileSync(replayPath, "utf8"))).toEqual({
			schemaVersion: 1,
			kind: "service_run_seal_replay_ambiguity",
			runId,
			runToken,
			terminalOccurrenceId: intent.terminalOccurrenceId,
			reason: "seal_intent_without_seal_observed",
		});
		const descriptor = JSON.parse(readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8")) as {
			state: string;
			reasons: string[];
		};
		expect(descriptor.state).toBe("incomplete");
		expect(descriptor.reasons).toContain("service_terminal_relay_disposition:replayed_after_ambiguous_seal_attempt");
		const completion = readIncompleteServiceCompletion(runDir);
		expectIncompleteRetentionAuthority(incidentDirectory, runId, completion);
		expect(sealRunIdentity).toHaveBeenCalledTimes(1);
		expect(readdirSync(runDir).some((name) => name.startsWith("service-finalization-normal-authority-"))).toBe(false);

		const stableRunNames = readdirSync(runDir).sort();
		const stableIncidentNames = readdirSync(incidentDirectory).sort();
		const stableControlBytes = new Map(
			[sealPath, intentPath, replayPath, completionPath].map((path) => [path, readFileSync(path, "utf8")] as const),
		);
		const adoptionsBeforeRepeatedInspection = adoptRunIdentitySeal.mock.calls.length;
		await runReadyServiceUntil(
			target.agentDir,
			() => adoptRunIdentitySeal.mock.calls.length > adoptionsBeforeRepeatedInspection,
			"fresh terminal-unbound seal repeated inspection",
		);
		expect(sealRunIdentity).toHaveBeenCalledTimes(1);
		expect(readdirSync(runDir).sort()).toEqual(stableRunNames);
		expect(readdirSync(incidentDirectory).sort()).toEqual(stableIncidentNames);
		for (const [path, bytes] of stableControlBytes) expect(readFileSync(path, "utf8"), path).toBe(bytes);
	}, 20_000);

	it("converges a conflicting published complete tuple without a preexisting completion marker", async () => {
		const target = fixture();
		const runId = "b6010101-0101-4101-8101-010101010101";
		const runToken = "11111111-1111-4111-8111-111111111111";
		const terminalOccurrenceId = "b6020202-0202-4202-8202-020202020202";
		const producerId = "b6030303-0303-4303-8303-030303030303";
		const retentionAnchorWallTimeMs = Date.parse("2000-01-01T00:00:00.000Z");
		const runDir = stoppedServiceRun(target, runId, runToken, `expired-${runId}`);
		const incidentDirectory = writeExpiredPublishedIncident(
			target.agentDir,
			runId,
			"relayed",
			"complete",
			terminalOccurrenceId,
			producerId,
		);
		const forgedFinalizationId = publishedFinalizationId(incidentDirectory);
		writeDurableServiceSeal(runDir, runId, runToken, terminalOccurrenceId, producerId, retentionAnchorWallTimeMs);
		writeServiceTestJson(join(runDir, "service-finalization-seal-replay-ambiguity.json"), {
			schemaVersion: 1,
			kind: "service_run_seal_replay_ambiguity",
			runId,
			runToken,
			terminalOccurrenceId,
			reason: "seal_observed_without_intent",
		});
		writeServiceTestJson(join(runDir, `service-finalization-publication-intent-${forgedFinalizationId}.json`), {
			schemaVersion: 1,
			kind: "service_finalization_publication_intent",
			runId,
			finalizationId: forgedFinalizationId,
		});
		const completionPath = join(runDir, ".service-finalization-complete");
		expect(existsSync(completionPath)).toBe(false);

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
		const projectRunHistory = vi
			.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
			.mockImplementation((input) => {
				const seal = JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8")) as ReturnType<
					typeof testServiceSeal
				>;
				return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
			});
		const originalIncidentNames = readdirSync(incidentDirectory).sort();
		const originalIncidentBytes = new Map(
			originalIncidentNames
				.filter((name) => statSync(join(incidentDirectory, name)).isFile())
				.map((name) => [name, readFileSync(join(incidentDirectory, name))] as const),
		);
		await runReadyServiceUntil(
			target.agentDir,
			() => {
				if (!existsSync(completionPath)) return false;
				return (
					(JSON.parse(readFileSync(completionPath, "utf8")) as { state?: unknown }).state ===
					"publication_conflict_reclaimable"
				);
			},
			"forged complete publication conflict convergence",
		);
		expect(projectRunHistory).toHaveBeenCalledTimes(1);
		const proof = readPublicationConflictProof(runDir);
		readPublicationConflictCompletion(runDir, proof);
		expect(proof).toMatchObject({
			runId,
			runToken,
			publishedFinalizationId: forgedFinalizationId,
			publishedState: "complete",
			publishedRetentionAnchorWallTimeMs: retentionAnchorWallTimeMs,
			publishedServiceTerminalRelayDisposition: "relayed",
			intendedState: "incomplete",
			intendedRetentionAnchorWallTimeMs: retentionAnchorWallTimeMs,
			intendedServiceTerminalRelayDisposition: "replayed_after_ambiguous_seal_attempt",
		});
		expect(readdirSync(incidentDirectory).sort()).toEqual(originalIncidentNames);
		for (const [name, bytes] of originalIncidentBytes)
			expect(readFileSync(join(incidentDirectory, name)), name).toEqual(bytes);
		expect(
			existsSync(join(runDir, ".service-control-quarantine")) &&
				readdirSync(join(runDir, ".service-control-quarantine")).some((name) => name.startsWith("completion-")),
		).toBe(false);
		expect(readdirSync(runDir).some((name) => name.startsWith("service-finalization-normal-authority-"))).toBe(false);

		const stableRunNames = readdirSync(runDir).sort();
		const stableIncidentNames = readdirSync(incidentDirectory).sort();
		const adoptionsBeforeRepeatedInspection = adoptRunIdentitySeal.mock.calls.length;
		const projectionsBeforeRepeatedInspection = projectRunHistory.mock.calls.length;
		await runReadyServiceUntil(
			target.agentDir,
			() => adoptRunIdentitySeal.mock.calls.length > adoptionsBeforeRepeatedInspection,
			"forged complete publication stable conflict completion",
		);
		expect(projectRunHistory.mock.calls.length).toBe(projectionsBeforeRepeatedInspection);
		readPublicationConflictCompletion(runDir, proof);
		expect(readdirSync(runDir).sort()).toEqual(stableRunNames);
		expect(readdirSync(incidentDirectory).sort()).toEqual(stableIncidentNames);
		for (const [name, bytes] of originalIncidentBytes)
			expect(readFileSync(join(incidentDirectory, name)), name).toEqual(bytes);
	}, 20_000);

	it("quarantines untrusted discovery controls and converges them to stable incomplete incidents", async () => {
		const target = fixture();
		const definitions: Array<{
			runId: string;
			runToken: string;
			runDir: string;
			quarantineLabels: string[];
		}> = [];
		const addRun = (
			runId: string,
			runToken: string,
			quarantineLabels: string[],
			mutate: (runDir: string) => void,
		): string => {
			const runDir = stoppedServiceRun(target, runId, runToken);
			writeZeroArtifactCaptureCompletion(runDir, runId);
			writeServiceTestJson(
				join(runDir, "finalization-barrier-expectation.json"),
				serviceTestBarrierExpectation(runId, runToken),
			);
			mutate(runDir);
			definitions.push({ runId, runToken, runDir, quarantineLabels });
			return runDir;
		};

		addRun("b7010101-0101-4101-8101-010101010101", "b7020202-0202-4202-8202-020202020202", ["process-"], (runDir) =>
			chmodSync(join(runDir, "process.json"), 0o644),
		);
		addRun("b7030303-0303-4303-8303-030303030303", "b7040404-0404-4404-8404-040404040404", ["process-"], (runDir) => {
			rmSync(join(runDir, "process.json"));
			symlinkSync(join(target.root, "missing-process-target.json"), join(runDir, "process.json"));
		});
		const hardlinkedRunDir = addRun(
			"b7050505-0505-4505-8505-050505050505",
			"b7060606-0606-4606-8606-060606060606",
			["process-"],
			(runDir) => linkSync(join(runDir, "process.json"), join(target.root, "hardlinked-process.json")),
		);
		const swappedRunToken = "b7080808-0808-4808-8808-080808080808";
		const swappedRunDir = addRun("b7070707-0707-4707-8707-070707070707", swappedRunToken, ["process-"], () => {});
		addRun(
			"b7090909-0909-4909-8909-090909090909",
			"b70a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a",
			["process-", "active-marker-"],
			(runDir) => {
				const processStartId = getProcessStartId(process.pid);
				if (!processStartId) throw new Error("service lifecycle test process identity unavailable");
				writeServiceTestJson(join(runDir, "process.json"), {
					...serviceTestProcessControl("b70a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a"),
					machineId: readFileSync("/etc/machine-id", "utf8").trim(),
					bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
					pid: process.pid,
					processStartId,
				});
				writeLiveServiceProxy(runDir);
			},
		);
		addRun("b70b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b", "b70c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c", ["launch-"], (runDir) =>
			chmodSync(join(runDir, "launch.json"), 0o644),
		);
		addRun(
			"b70d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d",
			"b70e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e",
			["active-marker-"],
			(runDir) => {
				writeLiveServiceProxy(runDir);
				chmodSync(join(runDir, ".recorder-active"), 0o644);
			},
		);

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity").mockImplementation(
			async (identity, _deadlineMs, terminalOccurrenceId) => {
				if (!terminalOccurrenceId) throw new Error("missing deterministic terminal occurrence ID");
				return testServiceSeal(identity.runId, identity.runToken, terminalOccurrenceId, identity.runId) as never;
			},
		);
		const adoptRunIdentitySeal = vi
			.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal")
			.mockImplementation((seal) => ({ adopted: true, disposition: "adopted", seal }) as never);
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			const definition = definitions.find((candidate) => candidate.runId === input.runId);
			if (!definition) throw new Error(`missing discovery-control fixture for ${input.runId}`);
			const seal = JSON.parse(
				readFileSync(join(definition.runDir, "service-finalization-seal.json"), "utf8"),
			) as ReturnType<typeof testServiceSeal>;
			return incompleteProjectionForSeal(input.runId, seal.runToken, seal) as never;
		});

		const swappedProcessPath = join(swappedRunDir, "process.json");
		const swappedProcessBytes = readFileSync(swappedProcessPath, "utf8");
		let insideRetention = false;
		const retentionPass = retentionModule.runIncidentRetentionPass;
		vi.spyOn(retentionModule, "runIncidentRetentionPass").mockImplementation((options) => {
			insideRetention = true;
			try {
				return retentionPass(options);
			} finally {
				insideRetention = false;
			}
		});
		let pathSwapTriggered = false;
		const originalJsonParse = JSON.parse;
		const jsonParseSpy = vi.spyOn(JSON, "parse").mockImplementation((text: string) => {
			const value = originalJsonParse(text);
			if (!insideRetention && !pathSwapTriggered && text === swappedProcessBytes) {
				pathSwapTriggered = true;
				renameSync(swappedProcessPath, `${swappedProcessPath}.opened`);
				writeServiceTestJson(swappedProcessPath, value);
			}
			return value;
		});
		try {
			await runReadyServiceUntil(
				target.agentDir,
				() => definitions.every(({ runDir }) => existsSync(join(runDir, ".service-finalization-complete"))),
				"invalid discovery controls to converge incomplete",
				1_200,
			);
		} finally {
			jsonParseSpy.mockRestore();
		}
		expect(pathSwapTriggered).toBe(true);
		expect(existsSync(join(hardlinkedRunDir, "process.json"))).toBe(false);
		expect(existsSync(join(target.root, "hardlinked-process.json"))).toBe(true);

		for (const { runId, runToken, runDir, quarantineLabels } of definitions) {
			const repair = JSON.parse(
				readFileSync(join(runDir, "service-finalization-stopped-observation-repair.json"), "utf8"),
			) as Record<string, unknown>;
			expect(repair).toEqual({
				schemaVersion: 1,
				kind: "service_stopped_observation_repair",
				runId,
				runToken,
				reason: "invalid_control_observed",
			});
			const stopped = JSON.parse(
				readFileSync(join(runDir, "service-finalization-stopped-observation.json"), "utf8"),
			) as Record<string, unknown>;
			expect(stopped).toMatchObject({ runId, runToken, disposition: "recovered_after_invalid_control" });
			const intent = JSON.parse(
				readFileSync(join(runDir, "service-finalization-seal-intent.json"), "utf8"),
			) as Record<string, unknown>;
			expect(intent).toMatchObject({
				runId,
				runToken,
				retentionAnchorWallTimeMs: stopped.firstObservedStoppedWallTimeMs,
				stoppedObservationDisposition: "recovered_after_invalid_control",
			});
			const quarantineNames = readdirSync(join(runDir, ".service-control-quarantine"));
			for (const prefix of quarantineLabels) {
				expect(
					quarantineNames.filter((name) => name.startsWith(prefix)),
					`${runId}:${prefix}`,
				).toHaveLength(1);
			}
			const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
			const descriptor = JSON.parse(
				readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8"),
			) as { state: string; reasons: string[] };
			expect(descriptor.state).toBe("incomplete");
			expect(descriptor.reasons).toContain(
				"service_terminal_relay_disposition:recovered_after_invalid_stopped_observation",
			);
			const completion = readIncompleteServiceCompletion(runDir);
			expectIncompleteRetentionAuthority(incidentDirectory, runId, completion);
			expect(readdirSync(runDir).some((name) => name.startsWith("service-finalization-normal-authority-"))).toBe(
				false,
			);
		}

		const stable = definitions.map(({ runDir, runId }) => {
			const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
			return {
				runDir,
				incidentDirectory,
				runNames: readdirSync(runDir).sort(),
				quarantineNames: readdirSync(join(runDir, ".service-control-quarantine")).sort(),
				incidentNames: readdirSync(incidentDirectory).sort(),
				completionBytes: readFileSync(join(runDir, ".service-finalization-complete"), "utf8"),
			};
		});
		const adoptionsBeforeRestart = adoptRunIdentitySeal.mock.calls.length;
		await runReadyServiceUntil(
			target.agentDir,
			() => adoptRunIdentitySeal.mock.calls.length >= adoptionsBeforeRestart + definitions.length,
			"recovered discovery controls to remain stable after restart",
			1_200,
		);
		for (const snapshot of stable) {
			expect(readdirSync(snapshot.runDir).sort()).toEqual(snapshot.runNames);
			expect(readdirSync(join(snapshot.runDir, ".service-control-quarantine")).sort()).toEqual(
				snapshot.quarantineNames,
			);
			expect(readdirSync(snapshot.incidentDirectory).sort()).toEqual(snapshot.incidentNames);
			expect(readFileSync(join(snapshot.runDir, ".service-finalization-complete"), "utf8")).toBe(
				snapshot.completionBytes,
			);
		}
	}, 30_000);

	it("leaves non-canonical run directory identities outside service finalization authority", async () => {
		const target = fixture();
		const runId = "B70F0F0F-0F0F-4F0F-8F0F-0F0F0F0F0F0F";
		const runDir = stoppedServiceRun(target, runId, "b7101010-1010-4010-8010-101010101010");
		await inspectIncidentRecorderRuns(target.agentDir, Date.now());
		expect(readdirSync(runDir).sort()).toEqual([
			"launch.json",
			"process.json",
			`service-finalization-barrier-deadline-${createHash("sha256")
				.update(`${runId}\0b7101010-1010-4010-8010-101010101010`)
				.digest("hex")}.json`,
		]);
		expect(existsSync(join(runDir, ".service-control-quarantine"))).toBe(false);
	});

	it("routes the service barrier retry decision through the compactor and preserves pending control", async () => {
		const target = fixture();
		const runId = "b7202020-2020-4202-8202-202020202020";
		const runToken = "b7212121-2121-4212-8212-212121212121";
		const runDir = stoppedServiceRun(target, runId, runToken);
		const deadlinePath = join(
			runDir,
			`service-finalization-barrier-deadline-${createHash("sha256")
				.update(`${runId}\0${runToken}`)
				.digest("hex")}.json`,
		);
		const deadlineBytes = readFileSync(deadlinePath, "utf8");
		const ensureDeadline = vi
			.spyOn(IncidentRecorderCompactor.prototype, "ensureServiceFinalizationBarrierDeadline")
			.mockReturnValue({
				state: "available",
				elapsed: false,
				retryThroughWallTimeMs: 60_000,
			});
		await runReadyServiceUntil(
			target.agentDir,
			() => existsSync(join(runDir, ".service-finalization-pending")),
			"service barrier pending control",
		);
		expect(ensureDeadline).toHaveBeenCalledWith({
			runDirectory: runDir,
			runId,
			runToken,
			nowMs: expect.any(Number),
		});
		expect(readFileSync(deadlinePath, "utf8")).toBe(deadlineBytes);
		expect(JSON.parse(readFileSync(join(runDir, ".service-finalization-pending"), "utf8"))).toMatchObject({
			state: "waiting_for_compacted_supervisor_exit_and_wrapper_frontier",
			retryable: true,
		});
	});

	it("keeps stopped capture pending under CAS contention and binds the loss into finalization authority", async () => {
		const target = fixture();
		const runId = "b7111111-1111-4111-8111-111111111111";
		const runToken = "b7121212-1212-4212-8212-121212121212";
		const terminalProducerId = "b7131313-1313-4313-8313-131313131313";
		const recorderRoot = join(target.agentDir, "incident-recorder");
		const runDir = join(recorderRoot, "runs", `2026-08-31T00-00-00.000Z-${runId}`);
		const reportPath = join(runDir, "raw-reports", "report.json");

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "ensureServiceFinalizationBarrierDeadline").mockReturnValue({
			state: "available",
			elapsed: true,
			retryThroughWallTimeMs: Date.now(),
		});
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		vi.spyOn(IncidentRecorderCompactor.prototype, "streamStoppedTargetArtifact").mockImplementation(
			(candidateRunId, sourcePath, encoding) => {
				const bytes = readFileSync(sourcePath);
				const digest = createHash("sha256").update(bytes).digest("hex");
				const casPath = join(recorderRoot, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
				const leasePath = join(
					recorderRoot,
					"refs",
					"runs",
					createHash("sha256").update(candidateRunId).digest("hex"),
					`cas-${digest}.blob`,
				);
				if (!existsSync(casPath)) {
					mkdirSync(dirname(casPath), { recursive: true, mode: 0o700 });
					writeFileSync(casPath, bytes, { mode: 0o600 });
				}
				if (!existsSync(leasePath)) {
					mkdirSync(dirname(leasePath), { recursive: true, mode: 0o700 });
					linkSync(casPath, leasePath);
				}
				return {
					state: "complete",
					artifact: { algorithm: "sha256", digest, bytes: bytes.length, path: casPath, encoding },
				} as never;
			},
		);
		vi.spyOn(IncidentRecorderWriter.prototype, "sealRunIdentity").mockImplementation(
			async (identity, _deadlineMs, terminalOccurrenceId) => {
				if (!terminalOccurrenceId) throw new Error("missing deterministic terminal occurrence ID");
				return testServiceSeal(
					identity.runId,
					identity.runToken,
					terminalOccurrenceId,
					terminalProducerId,
				) as never;
			},
		);
		const adoptRunIdentitySeal = vi
			.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal")
			.mockImplementation((seal) => ({ adopted: true, disposition: "adopted", seal }) as never);
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation((input) => {
			const seal = JSON.parse(readFileSync(join(runDir, "service-finalization-seal.json"), "utf8")) as ReturnType<
				typeof testServiceSeal
			>;
			return incompleteProjectionForSeal(input.runId, runToken, seal) as never;
		});

		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		let holder: Awaited<ReturnType<typeof startServiceLifecycleCasHolder>> | undefined;
		let holderReleased = false;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready, 10_000);
			holder = await startServiceLifecycleCasHolder(recorderRoot);
			stoppedServiceRun(target, runId, runToken);
			writeServiceTestJson(reportPath, { header: { event: "Exception" } });
			writeServiceTestJson(join(runDir, "evidence", "provider-artifacts", "capture-complete.json"), {
				schemaVersion: 1,
				kind: "provider_artifact_capture_complete",
				state: "complete",
				runId,
				reasons: [],
			});
			writeEmptyProviderCaptureFrontier(runDir, runId);
			await inspectIncidentRecorderRuns(target.agentDir, Date.now());
			await inspectIncidentRecorderRuns(target.agentDir, Date.now());
			expect(existsSync(join(runDir, "raw-reports", "capture-complete.json"))).toBe(false);
			expect(existsSync(join(runDir, "service-finalization-seal-intent.json"))).toBe(false);
			expect(existsSync(join(runDir, "service-finalization-seal.json"))).toBe(false);
			expect(existsSync(join(runDir, ".service-finalization-complete"))).toBe(false);

			await holder.release();
			holderReleased = true;
			await waitForCondition(
				() => existsSync(join(runDir, ".service-finalization-complete")),
				"contention loss to bind the stopped-run finalization",
			);
		} finally {
			if (holder && !holderReleased) await holder.release().catch(() => undefined);
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running, 10_000);
		}

		const lossPath = join(runDir, "service-finalization-fallback-admission-loss.json");
		const loss = JSON.parse(readFileSync(lossPath, "utf8")) as Record<string, unknown>;
		expect(loss).toMatchObject({
			schemaVersion: 3,
			kind: "service_fallback_admission_loss",
			runId,
			synchronousAttemptLimit: 3,
			synchronousWaitIntervalMs: 5,
		});
		expect(Number(loss.lostAdmissions)).toBeGreaterThan(0);
		const sealPath = join(runDir, "service-finalization-seal.json");
		const seal = JSON.parse(readFileSync(sealPath, "utf8")) as ReturnType<typeof testServiceSeal>;
		expect(seal.loss.terminalRelay.uncertain.records).toBe(Number(loss.lostAdmissions));
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);
		const descriptor = JSON.parse(readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8")) as {
			state: string;
			reasons: string[];
		};
		expect(descriptor.state).toBe("incomplete");
		expect(descriptor.reasons).toContain("service_terminal_relay_uncertainty");
		const completion = readIncompleteServiceCompletion(runDir);
		expectIncompleteRetentionAuthority(incidentDirectory, runId, completion);

		const stableLossBytes = readFileSync(lossPath, "utf8");
		const stableSealBytes = readFileSync(sealPath, "utf8");
		const stableCompletionBytes = readFileSync(join(runDir, ".service-finalization-complete"), "utf8");
		const adoptionsBeforeRestart = adoptRunIdentitySeal.mock.calls.length;
		await runReadyServiceUntil(
			target.agentDir,
			() => adoptRunIdentitySeal.mock.calls.length > adoptionsBeforeRestart,
			"contention loss authority adoption after restart",
		);
		expect(readFileSync(lossPath, "utf8")).toBe(stableLossBytes);
		expect(readFileSync(sealPath, "utf8")).toBe(stableSealBytes);
		expect(readFileSync(join(runDir, ".service-finalization-complete"), "utf8")).toBe(stableCompletionBytes);
	}, 20_000);

	it("rejects a shape-valid complete seal with nonzero loss and converges incomplete", async () => {
		const target = fixture();
		const runId = "b8010101-0101-4101-8101-010101010101";
		const runToken = "b8020202-0202-4202-8202-020202020202";
		const terminalOccurrenceId = "b8030303-0303-4303-8303-030303030303";
		const producerId = "b8040404-0404-4404-8404-040404040404";
		const forgedFinalizationId = createHash("sha256").update(`nonzero-loss:${runId}`).digest("hex");
		const runDir = stoppedServiceRun(target, runId, runToken);
		writeDurableNormalServiceCompletion({
			runDir,
			runId,
			runToken,
			terminalOccurrenceId,
			producerId,
			finalizationId: forgedFinalizationId,
		});
		const sealPath = join(runDir, "service-finalization-seal.json");
		const seal = testServiceSeal(runId, runToken, terminalOccurrenceId, producerId);
		seal.loss.emitter = { records: 1, bytes: 128 };
		const sealBytes = writeServiceTestJson(sealPath, seal);
		const completionPath = join(runDir, ".service-finalization-complete");
		const incidentDirectory = join(target.agentDir, "incidents", `2026-08-31T00-00-00.000Z-${runId}`);

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "requestPin").mockImplementation(() => {});
		vi.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory").mockImplementation(
			(input) => incompleteProjectionForSeal(input.runId, runToken, seal) as never,
		);
		const adoptRunIdentitySeal = vi.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal");
		await runReadyServiceUntil(
			target.agentDir,
			() => {
				if (!existsSync(completionPath)) return false;
				const value = JSON.parse(readFileSync(completionPath, "utf8")) as {
					finalizationId?: unknown;
					outcome?: unknown;
				};
				return value.outcome === "incomplete" && value.finalizationId !== forgedFinalizationId;
			},
			"nonzero-loss complete-seal rejection",
		);

		expect(readFileSync(sealPath, "utf8")).toBe(sealBytes);
		expect(existsSync(join(runDir, "service-finalization-seal-replay-ambiguity.json"))).toBe(false);
		expect(
			readdirSync(join(runDir, ".service-control-quarantine")).filter((name) => name.startsWith("completion-")),
		).toHaveLength(1);
		const descriptor = JSON.parse(readFileSync(join(incidentDirectory, "finalization-descriptor.json"), "utf8")) as {
			state: string;
			reasons: string[];
		};
		expect(descriptor.state).toBe("incomplete");
		expect(descriptor.reasons).toContain("service_emitter_loss");
		const completion = readIncompleteServiceCompletion(runDir);
		expect(completion.finalizationId).not.toBe(forgedFinalizationId);
		expectIncompleteRetentionAuthority(incidentDirectory, runId, completion);

		const stableCompletionBytes = readFileSync(completionPath, "utf8");
		const stableQuarantineNames = readdirSync(join(runDir, ".service-control-quarantine")).sort();
		const adoptionsBeforeRepeatedInspection = adoptRunIdentitySeal.mock.calls.length;
		await runReadyServiceUntil(
			target.agentDir,
			() => adoptRunIdentitySeal.mock.calls.length > adoptionsBeforeRepeatedInspection,
			"nonzero-loss completion repeated inspection",
		);
		expect(readFileSync(completionPath, "utf8")).toBe(stableCompletionBytes);
		expect(readdirSync(join(runDir, ".service-control-quarantine")).sort()).toEqual(stableQuarantineNames);
	}, 20_000);

	it("bounds retained seal results while permanently fencing reclaimed identities", async () => {
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "b1919191-9191-4191-8191-919191919191",
			runToken: "b2929292-9292-4292-8292-929292929292",
			serviceSink: true,
		});
		const identity = (index: number) => {
			const suffix = index.toString(16).padStart(12, "0");
			return {
				runId: `b0000000-0000-4000-8000-${suffix}`,
				runToken: `c0000000-0000-4000-8000-${suffix}`,
			};
		};
		const firstIdentity = identity(0);
		try {
			const firstSeal = await writer.sealRunIdentity(firstIdentity);
			for (let index = 1; index <= INCIDENT_RECORDER_SERVICE_SEAL_RESULT_MAX_IDENTITIES; index += 1)
				await writer.sealRunIdentity(identity(index));

			const fenceOnly = await writer.sealRunIdentity(firstIdentity);
			expect(fenceOnly).not.toBe(firstSeal);
			expect(fenceOnly.terminal).toEqual({
				type: "capture_channel_terminal",
				admission: null,
				frontier: null,
			});
			expect(fenceOnly.loss.terminalRelay).toEqual({
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 1, bytes: 0 },
			});
			expect(writer.recordDerivedForRun(firstIdentity, "recorder-control", "after_reclamation", {})).toMatchObject({
				accepted: false,
				reason: "run_identity_sealed",
			});
			expect(
				writer.recordExactBytesForRun(
					firstIdentity,
					"stderr",
					"after_reclamation",
					Buffer.from("late"),
					"exact",
					{},
				),
			).toMatchObject({ accepted: false, reason: "run_identity_sealed" });
			await writer.releaseRunIdentity(firstIdentity);
			expect(await writer.sealRunIdentity(firstIdentity)).toEqual(fenceOnly);

			const rehydrated = writer.adoptRunIdentitySeal(firstSeal);
			expect(rehydrated).toMatchObject({ adopted: true, disposition: "adopted" });
			if (!rehydrated.adopted) throw new Error("durable seal rehydration failed");
			expect(await writer.sealRunIdentity(firstIdentity)).toBe(rehydrated.seal);
		} finally {
			await writer.stop(25);
		}
	});

	it("continues wrapper sequences across interrupted writer replacement and released emitters", async () => {
		const frontier = createIncidentRecorderWrapperFrontier(8);
		const writerIdentity = {
			runId: "e1010101-0101-4101-8101-010101010101",
			runToken: "e2020202-0202-4202-8202-020202020202",
		};
		const identity = {
			runId: "e3030303-0303-4303-8303-030303030303",
			runToken: "e4040404-0404-4404-8404-040404040404",
		};
		const replacementIdentity = {
			runId: "e5050505-0505-4505-8505-050505050505",
			runToken: "e6060606-0606-4606-8606-060606060606",
		};
		const first = new IncidentRecorderWriter({
			runDir: "unused",
			...writerIdentity,
			serviceSink: true,
			wrapperFrontier: frontier,
		});
		const second = new IncidentRecorderWriter({
			runDir: "unused",
			runId: "e7070707-0707-4707-8707-070707070707",
			runToken: "e8080808-0808-4808-8808-080808080808",
			serviceSink: true,
			wrapperFrontier: frontier,
		});
		try {
			expect(first.recordDerivedForRun(identity, "recorder-control", "before_interruption", {}).accepted).toBe(true);
			await first.stop(25);
			expect(second.recordDerivedForRun(identity, "recorder-control", "after_interruption", {}).accepted).toBe(true);
			const seal = await second.sealRunIdentity(identity, 25);
			expect(seal.terminal.frontier).toMatchObject({
				firstProducerSequence: "2",
				lastProducerSequence: "2",
				firstWrapperSequence: "4",
				lastWrapperSequence: "4",
			});

			expect(second.recordDerivedForRun(replacementIdentity, "recorder-control", "released_one", {}).accepted).toBe(
				true,
			);
			await second.releaseRunIdentity(replacementIdentity);
			expect(second.recordDerivedForRun(replacementIdentity, "recorder-control", "released_two", {}).accepted).toBe(
				true,
			);
			const releasedSeal = await second.sealRunIdentity(replacementIdentity, 25);
			expect(releasedSeal.terminal.frontier?.firstWrapperSequence).toBe("4");
		} finally {
			await Promise.all([first.stop(25), second.stop(25)]);
		}
	});

	it("fails closed on a new wrapper identity at frontier capacity and reports once", async () => {
		const frontier = createIncidentRecorderWrapperFrontier(1);
		const callback = vi.fn();
		const existing = {
			runId: "e9090909-0909-4909-8909-090909090909",
			runToken: "ea0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a",
		};
		const unseen = {
			runId: "eb0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b",
			runToken: "ec0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c",
		};
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			...existing,
			serviceSink: true,
			wrapperFrontier: frontier,
			onWrapperFrontierSaturated: callback,
		});
		try {
			expect(
				() =>
					new IncidentRecorderWriter({
						runDir: "unused",
						...unseen,
						serviceSink: true,
						wrapperFrontier: frontier,
					}),
			).toThrow(IncidentRecorderWrapperFrontierSaturatedError);
			expect(() => writer.recordDerivedForRun(unseen, "recorder-control", "saturated", {})).toThrow(
				IncidentRecorderWrapperFrontierSaturatedError,
			);
			expect(() => writer.sealRunIdentity(unseen, 25)).toThrow(IncidentRecorderWrapperFrontierSaturatedError);
			expect(writer.recordDerivedForRun(existing, "recorder-control", "existing_at_capacity", {}).accepted).toBe(
				true,
			);
			expect(callback).toHaveBeenCalledOnce();
			expect(callback.mock.calls[0]?.[0]).toBeInstanceOf(IncidentRecorderWrapperFrontierSaturatedError);
		} finally {
			await writer.stop(25);
		}
	});

	it("latches wrapper-frontier saturation as a service-fatal shutdown", async () => {
		const target = fixture();
		const frontier = createIncidentRecorderWrapperFrontier(1);
		frontier.reserve({
			runId: "ed0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d",
			runToken: "ee0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e",
		});
		mockReadyServiceCompactor();
		const closeWriterResources = vi
			.spyOn(IncidentRecorderCompactor.prototype, "closeWriterResourcesForLifecycle")
			.mockResolvedValue(undefined);
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		const running = runIncidentRecorderService(target.agentDir, {
			wrapperFrontier: frontier,
			notify: (fields) => notifications.push([...fields]),
			signalSource: signals,
			writerStopDeadlineMs: 1_000,
		});
		const rejection = await captureRejection(withTimeout(running));
		expect(rejection).toBeInstanceOf(IncidentRecorderWrapperFrontierSaturatedError);
		expect(notifications.flat()).toContain("STOPPING=1");
		expect(notifications.flat()).not.toContain("READY=1");
		expect(closeWriterResources).toHaveBeenCalledOnce();
		expect(signals.size).toBe(0);
	});

	it("keeps a run's wrapper frontier contiguous across normal recovery and writer replacement", async () => {
		const target = fixture();
		const frontier = createIncidentRecorderWrapperFrontier(32);
		const runId = "ef010101-0101-4101-8101-010101010101";
		const runToken = "ef020202-0202-4202-8202-020202020202";
		const runDir = join(target.root, `active-${runId}`);
		writeServiceTestJson(join(runDir, "process.json"), serviceTestProcessControl(runToken));

		const journalBytesPath = join(target.root, "writer-journal.jsonl");
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		const previousJournalBytes = process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES = journalBytesPath;

		const lifecycleOrder: string[] = [];
		let storageMode: "normal" | "recovery-only" = "normal";
		const closeWriterResources = vi
			.spyOn(IncidentRecorderCompactor.prototype, "closeWriterResourcesForLifecycle")
			.mockImplementation(async () => {
				lifecycleOrder.push("compactor-close");
			});
		vi.spyOn(IncidentRecorderCompactor.prototype, "resumeWriterResourcesForLifecycle").mockImplementation(() => {
			lifecycleOrder.push("compactor-resume");
		});
		vi.spyOn(IncidentRecorderCompactor.prototype, "storageMode", "get").mockImplementation(() => storageMode);
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(retentionModule, "runIncidentRetentionPass").mockReturnValue({
			deletedEntries: 0,
			moreWork: false,
		} as ReturnType<typeof retentionModule.runIncidentRetentionPass>);
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			lifecycleOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});

		let releaseRecovery: () => void = () => {};
		const recoveryPermission = new Promise<void>((resolve) => {
			releaseRecovery = resolve;
		});
		let resolveRecovery: () => void = () => {};
		const recoveryReached = new Promise<void>((resolve) => {
			resolveRecovery = resolve;
		});
		let resolveReplacement: () => void = () => {};
		const replacementReady = new Promise<void>((resolve) => {
			resolveReplacement = resolve;
		});
		const runMock = vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			void this;
			const [runOptions] = args;
			runOptions.onStorageMode?.("normal");
			await runOptions.onNormalWriterAdmission?.();
			runOptions.onReaderReady?.();
			await recoveryPermission;
			storageMode = "recovery-only";
			runOptions.onStorageMode?.("recovery-only", "test_recovery");
			expect(await runOptions.onRecoveryPass?.()).toBe(false);
			resolveRecovery();
			storageMode = "normal";
			runOptions.onStorageMode?.("normal");
			await runOptions.onNormalWriterAdmission?.();
			resolveReplacement();
			await waitForAbort(runOptions.signal);
		});

		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				wrapperFrontier: frontier,
				notify: (fields) => {
					notifications.push([...fields]);
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			ingestIncidentRecorderEvidence(runDir, "kernel", Buffer.from("first recovery-bound evidence"));
			releaseRecovery();
			await withTimeout(recoveryReached);
			await withTimeout(replacementReady);
			ingestIncidentRecorderEvidence(runDir, "kernel", Buffer.from("second producer evidence"));
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			releaseRecovery();
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
			if (previousJournalBytes === undefined) delete process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES;
			else process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES = previousJournalBytes;
		}

		expect(closeWriterResources).toHaveBeenCalledTimes(2);
		expect(runMock).toHaveBeenCalledOnce();
		expect(lifecycleOrder).toEqual([
			"compactor-resume",
			"writer-stop",
			"compactor-close",
			"compactor-resume",
			"writer-stop",
			"compactor-close",
		]);
		const lines = readFileSync(journalBytesPath, "utf8")
			.trim()
			.split("\n")
			.filter(Boolean)
			.map((value) => JSON.parse(value) as IncidentJournalLine)
			.filter((value) => value.runId === runId && value.runToken === runToken);
		expect(lines.map((value) => value.type)).toEqual([
			"external_raw_evidence_ingested",
			"capture_channel_terminal",
			"external_raw_evidence_ingested",
			"capture_channel_terminal",
		]);
		expect(lines.map((value) => value.wrapperSequence)).toEqual(["1", "2", "3", "4"]);
		expect(new Set(lines.map((value) => value.producerId)).size).toBe(2);

		const strictAgentDir = join(target.root, "strict-compactor-agent");
		mkdirSync(strictAgentDir, { recursive: true, mode: 0o700 });
		const strictCompactor = new IncidentRecorderCompactor({ agentDir: strictAgentDir, freeReserveBytes: 0 });
		const strict = strictCompactor as unknown as LifecycleSequenceCompactorInternals;
		const writeGap = vi.spyOn(strict, "writeGap").mockImplementation(() => {});
		for (const [index, lineValue] of lines.entries()) {
			const reference: LifecycleSequenceReference = {
				machineId: lineValue.machineId ?? "missing",
				bootId: lineValue.bootId ?? "missing",
				uid: "1000",
				identifier: "prime-agent-raw-v1",
				transport: "stdout",
				streamId: "service-lifecycle-sequence",
				invocationId: lineValue.systemdInvocationId,
				realtimeUs: String(1_700_000_000_000_000 + index),
				monotonicUs: String(index + 1),
				journalPid: lineValue.systemdCatPid === null ? null : String(lineValue.systemdCatPid),
				wrapperSequence: lineValue.wrapperSequence,
				producerSequence: lineValue.producerSequence,
				chunkIndex: lineValue.chunkIndex,
				chunkCount: lineValue.chunkCount,
				bytes: 0,
				memoryBytes: 0,
				resolved: false,
			};
			strict.checkSequences(lineValue, reference);
			if (reference.sequenceUpdates) {
				strict.wrapperSequences.set(
					reference.sequenceUpdates.wrapperKey,
					BigInt(reference.sequenceUpdates.wrapper),
				);
				strict.producerSequences.set(
					reference.sequenceUpdates.producerKey,
					BigInt(reference.sequenceUpdates.producer),
				);
			}
		}
		expect(writeGap).not.toHaveBeenCalled();
	}, 20_000);

	it("returns the original typed frontier fatal after post-readiness observation saturation and full cleanup", async () => {
		const target = fixture();
		const frontier = createIncidentRecorderWrapperFrontier(1);
		const runId = "ef030303-0303-4303-8303-030303030303";
		const runToken = "ef040404-0404-4404-8404-040404040404";
		const runDir = join(target.root, `observation-${runId}`);
		writeServiceTestJson(join(runDir, "process.json"), serviceTestProcessControl(runToken));
		const saturationErrors: unknown[] = [];
		const originalReserve = frontier.reserve.bind(frontier);
		vi.spyOn(frontier, "reserve").mockImplementation((identity) => {
			try {
				return originalReserve(identity);
			} catch (error) {
				saturationErrors.push(error);
				throw error;
			}
		});
		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		const cleanupOrder: string[] = [];
		const signals = new (class extends TestSignalSource {
			off(signal: RecorderSignal, listener: () => void): void {
				cleanupOrder.push(`off:${signal}`);
				super.off(signal, listener);
			}
		})();
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			cleanupOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});
		vi.spyOn(IncidentRecorderCompactor.prototype, "closeWriterResourcesForLifecycle").mockImplementation(async () => {
			cleanupOrder.push("compactor-close");
		});
		let serviceLifecycle: IncidentRecorderServiceWriterLifecycle | undefined;
		const originalEnterNormal = IncidentRecorderServiceWriterLifecycle.prototype.enterNormal;
		vi.spyOn(IncidentRecorderServiceWriterLifecycle.prototype, "enterNormal").mockImplementation(async function (
			this: IncidentRecorderServiceWriterLifecycle,
		) {
			serviceLifecycle = this;
			return originalEnterNormal.call(this);
		});
		const originalLifecycleClose = IncidentRecorderServiceWriterLifecycle.prototype.close;
		vi.spyOn(IncidentRecorderServiceWriterLifecycle.prototype, "close").mockImplementation(async function (
			this: IncidentRecorderServiceWriterLifecycle,
		) {
			const result = await originalLifecycleClose.call(this);
			cleanupOrder.push("lease-release");
			return result;
		});
		const enterRecovery = vi.spyOn(IncidentRecorderServiceWriterLifecycle.prototype, "enterRecovery");
		const notifications: string[][] = [];
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		let observationError: unknown;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				wrapperFrontier: frontier,
				notify: (fields) => {
					notifications.push([...fields]);
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			try {
				ingestIncidentRecorderEvidence(runDir, "kernel", Buffer.from("saturating observation"));
			} catch (error) {
				observationError = error;
			}
			const rejection = await captureRejection(withTimeout(running));
			expect(saturationErrors[0]).toBeDefined();
			expect(rejection).toBe(saturationErrors[0]);
			expect(rejection).toBeInstanceOf(IncidentRecorderWrapperFrontierSaturatedError);
			expect(observationError).toBeInstanceOf(IncidentRecorderWrapperFrontierSaturatedError);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
		}

		const readyIndex = notifications.findIndex((fields) => fields.includes("READY=1"));
		const stoppingIndex = notifications.findIndex((fields) => fields.includes("STOPPING=1"));
		expect(readyIndex).toBeGreaterThanOrEqual(0);
		expect(stoppingIndex).toBeGreaterThan(readyIndex);
		expect(notifications.flat()).not.toContain("Incident recorder recovery-only: test_recovery");
		expect(enterRecovery).not.toHaveBeenCalled();
		expect(cleanupOrder).toEqual(["off:SIGTERM", "off:SIGINT", "writer-stop", "compactor-close", "lease-release"]);
		expect(signals.size).toBe(0);
		expect(serviceLifecycle?.normalLease).toBeUndefined();
		const reacquired = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: target.agentDir },
			{
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			},
		);
		expect(reacquired.state).toBe("acquired");
		if (reacquired.state === "acquired") expect(reacquired.lease.release().state).toBe("released");
	}, 20_000);

	it("latches service identity seal-fence saturation as a service-fatal shutdown", async () => {
		const target = fixture();
		mockReadyServiceCompactor();
		let serviceWriter: IncidentRecorderWriter | undefined;
		const writerStart = vi.spyOn(IncidentRecorderWriter.prototype, "start");
		writerStart.mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["start"]>
		) {
			void args;
			serviceWriter = this;
		});
		let serviceSignal: AbortSignal | undefined;
		const compactorRun = vi.spyOn(IncidentRecorderCompactor.prototype, "run");
		const readyRun = compactorRun.getMockImplementation();
		if (!readyRun) throw new Error("ready service compactor mock is missing its run implementation");
		compactorRun.mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			serviceSignal = args[0].signal;
			return readyRun.call(this, ...args);
		});

		const cleanupOrder: string[] = [];
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		const writerStop = vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			cleanupOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});
		const closeWriterResources = vi
			.spyOn(IncidentRecorderCompactor.prototype, "closeWriterResourcesForLifecycle")
			.mockImplementation(async () => {
				cleanupOrder.push("compactor-close");
			});
		let serviceLifecycle: IncidentRecorderServiceWriterLifecycle | undefined;
		const originalEnterNormal = IncidentRecorderServiceWriterLifecycle.prototype.enterNormal;
		vi.spyOn(IncidentRecorderServiceWriterLifecycle.prototype, "enterNormal").mockImplementation(async function (
			this: IncidentRecorderServiceWriterLifecycle,
		) {
			serviceLifecycle = this;
			return originalEnterNormal.call(this);
		});
		const originalLifecycleClose = IncidentRecorderServiceWriterLifecycle.prototype.close;
		vi.spyOn(IncidentRecorderServiceWriterLifecycle.prototype, "close").mockImplementation(async function (
			this: IncidentRecorderServiceWriterLifecycle,
		) {
			const result = await originalLifecycleClose.call(this);
			cleanupOrder.push("lease-release");
			return result;
		});
		const enterRecovery = vi.spyOn(IncidentRecorderServiceWriterLifecycle.prototype, "enterRecovery");
		const signals = new (class extends TestSignalSource {
			off(signal: RecorderSignal, listener: () => void): void {
				cleanupOrder.push(`off:${signal}`);
				super.off(signal, listener);
			}
		})();
		const notifications: string[][] = [];
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		let saturationError: unknown;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				notify: (fields) => {
					notifications.push([...fields]);
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				serviceIdentitySealFenceMaxIdentities: 1,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			if (!serviceWriter) throw new Error("service writer was not captured after readiness");
			const firstIdentity = {
				runId: "f0010101-0101-4101-8101-010101010101",
				runToken: "f0020202-0202-4202-8202-020202020202",
			};
			const secondIdentity = {
				runId: "f0030303-0303-4303-8303-030303030303",
				runToken: "f0040404-0404-4404-8404-040404040404",
			};
			const firstSeal = serviceWriter.fenceRunIdentity(firstIdentity);
			expect(firstSeal).toMatchObject({ runId: firstIdentity.runId, runToken: firstIdentity.runToken });
			try {
				serviceWriter.fenceRunIdentity(secondIdentity);
			} catch (error) {
				saturationError = error;
			}
			expect(saturationError).toBeInstanceOf(IncidentRecorderServiceIdentitySealFenceSaturatedError);
			const rejection = await captureRejection(withTimeout(running));
			expect(rejection).toBe(saturationError);
			expect(rejection).toBeInstanceOf(IncidentRecorderServiceIdentitySealFenceSaturatedError);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
		}

		expect(writerStart).toHaveBeenCalledOnce();
		expect(writerStart).toHaveBeenCalledWith({ requireJournal: true });
		expect(compactorRun).toHaveBeenCalledOnce();
		expect(serviceSignal?.aborted).toBe(true);
		expect(notifications.filter((fields) => fields.includes("STOPPING=1"))).toHaveLength(1);
		expect(notifications.flat()).toContain("STATUS=Stopping after recorder writer failure");
		expect(notifications.flat()).not.toContain("Incident recorder recovery-only: test_recovery");
		expect(enterRecovery).not.toHaveBeenCalled();
		expect(writerStop).toHaveBeenCalledOnce();
		expect(closeWriterResources).toHaveBeenCalledOnce();
		expect(cleanupOrder).toEqual(["off:SIGTERM", "off:SIGINT", "writer-stop", "compactor-close", "lease-release"]);
		expect(signals.size).toBe(0);
		expect(serviceLifecycle?.normalLease).toBeUndefined();
	}, 20_000);

	it("rethrows a compactor ownership fatal from maintenance and preserves it through cleanup failure", async () => {
		const target = fixture();
		const fatal = new IncidentRecorderSegmentOwnershipUncertainError("live_publication_partial_filesystem_failure");
		mockReadyServiceCompactor(() => {
			throw fatal;
		});
		vi.spyOn(IncidentRecorderCompactor.prototype, "diskPaused", "get").mockReturnValue(false);
		vi.spyOn(IncidentRecorderCompactor.prototype, "processPendingPins").mockImplementation(() => {
			throw fatal;
		});
		const cleanupOrder: string[] = [];
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			cleanupOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});
		const closeWriterResources = vi
			.spyOn(IncidentRecorderCompactor.prototype, "closeWriterResourcesForLifecycle")
			.mockImplementation(async () => {
				cleanupOrder.push("compactor-close");
				throw new Error("injected cleanup failure");
			});
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		const running = runIncidentRecorderService(target.agentDir, {
			notify: (fields) => notifications.push([...fields]),
			signalSource: signals,
			writerStopDeadlineMs: 1_000,
		});
		const rejection = await captureRejection(withTimeout(running));
		expect(rejection).toBe(fatal);
		expect(rejection).toBeInstanceOf(IncidentRecorderSegmentOwnershipUncertainError);
		expect(notifications.flat()).toContain("STOPPING=1");
		expect(cleanupOrder).toEqual(["writer-stop", "compactor-close"]);
		expect(closeWriterResources).toHaveBeenCalledOnce();
		expect(signals.size).toBe(0);
	});

	it("preserves an ownership fatal latched during startup admission over disk admission failure", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;

		const fatalReason = "live_publication_partial_filesystem_failure";
		let admissionCallbackCalled = false;
		let admissionFatal: IncidentRecorderSegmentOwnershipUncertainError | undefined;
		const originalRun = IncidentRecorderCompactor.prototype.run;
		const compactorRun = vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			const [runOptions] = args;
			const originalAdmission = runOptions.onNormalWriterAdmission;
			return originalRun.call(this, {
				...runOptions,
				onNormalWriterAdmission: async () => {
					admissionCallbackCalled = true;
					const admitted = (await originalAdmission?.()) ?? false;
					if (admitted) {
						const internals = this as unknown as StartupAdmissionCompactorInternals;
						internals.latchSegmentOwnershipUncertain(fatalReason);
						admissionFatal = internals.segmentOwnershipUncertainError;
					}
					return admitted;
				},
			});
		});

		const cleanupOrder: string[] = [];
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		const writerStop = vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			cleanupOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});
		const closeWriterResources = vi
			.spyOn(IncidentRecorderCompactor.prototype, "closeWriterResourcesForLifecycle")
			.mockImplementation(async () => {
				cleanupOrder.push("compactor-close");
			});
		const originalLifecycleClose = IncidentRecorderServiceWriterLifecycle.prototype.close;
		const lifecycleClose = vi
			.spyOn(IncidentRecorderServiceWriterLifecycle.prototype, "close")
			.mockImplementation(async function (this: IncidentRecorderServiceWriterLifecycle) {
				const result = await originalLifecycleClose.call(this);
				cleanupOrder.push("lease-release");
				return result;
			});
		const signals = new (class extends TestSignalSource {
			off(signal: RecorderSignal, listener: () => void): void {
				cleanupOrder.push(`off:${signal}`);
				super.off(signal, listener);
			}
		})();
		const notifications: string[][] = [];
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: Number.MAX_SAFE_INTEGER },
				notify: (fields) => notifications.push([...fields]),
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			const rejection = await captureRejection(withTimeout(running));
			expect(admissionCallbackCalled).toBe(true);
			expect(admissionFatal).toBeInstanceOf(IncidentRecorderSegmentOwnershipUncertainError);
			expect(rejection).toBe(admissionFatal);
			expect(rejection).toBeInstanceOf(IncidentRecorderSegmentOwnershipUncertainError);
			expect((rejection as IncidentRecorderSegmentOwnershipUncertainError).reason).toBe(fatalReason);
			expect(notifications.flat()).not.toContain("READY=1");
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}

		expect(compactorRun).toHaveBeenCalledOnce();
		expect(writerStop).toHaveBeenCalledOnce();
		expect(closeWriterResources).toHaveBeenCalledOnce();
		expect(lifecycleClose).toHaveBeenCalledOnce();
		expect(cleanupOrder).toEqual(["off:SIGTERM", "off:SIGINT", "writer-stop", "compactor-close", "lease-release"]);
		expect(signals.size).toBe(0);
	});

	it("replays more than the historical service seal-fence capacity without saturation", async () => {
		const target = fixture();
		const definitions = Array.from({ length: 65 }, (_, index) => {
			const suffix = index.toString(16).padStart(12, "0");
			const runId = `f1${"0".repeat(6)}-0000-4000-8000-${suffix}`;
			return {
				runId,
				...writeBoundExpiredPublishedIncident(target, runId),
			};
		});
		const historicalRunIds = new Set(definitions.map(({ runId }) => runId));
		const snapshotTree = (root: string): string[] => {
			const result: string[] = [];
			const visit = (directory: string, prefix: string): void => {
				for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
					left.name.localeCompare(right.name),
				)) {
					const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
					const path = join(directory, entry.name);
					if (entry.isDirectory()) {
						result.push(`directory:${relative}`);
						visit(path, relative);
					} else result.push(`file:${relative}:${readFileSync(path).toString("base64")}`);
				}
			};
			visit(root, "");
			return result;
		};
		const snapshotControls = (): string[] =>
			definitions
				.flatMap(({ runDir, incidentDirectory }) => [
					...snapshotTree(runDir).map((entry) => `run:${runDir}:${entry}`),
					...snapshotTree(incidentDirectory).map((entry) => `incident:${incidentDirectory}:${entry}`),
				])
				.sort();
		const baselineControls = snapshotControls();

		mockReadyServiceCompactor();
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		const retentionPass = retentionModule.runIncidentRetentionPass;
		vi.spyOn(retentionModule, "runIncidentRetentionPass").mockImplementation((options) =>
			retentionPass({ ...options, nowMs: Date.parse("2000-01-01T00:00:00.000Z") }),
		);
		const projectRunHistory = vi
			.spyOn(IncidentRecorderCompactor.prototype, "projectRunHistory")
			.mockImplementation(() => {
				throw new Error("Incident run-history projection capacity is saturated");
			});
		const originalAdoptRunIdentitySeal = IncidentRecorderWriter.prototype.adoptRunIdentitySeal;
		const adoptRunIdentitySeal = vi
			.spyOn(IncidentRecorderWriter.prototype, "adoptRunIdentitySeal")
			.mockImplementation(function (
				this: IncidentRecorderWriter,
				...args: Parameters<IncidentRecorderWriter["adoptRunIdentitySeal"]>
			) {
				return originalAdoptRunIdentitySeal.apply(this, args);
			});
		const originalFenceRunIdentity = IncidentRecorderWriter.prototype.fenceRunIdentity;
		const fenceRunIdentity = vi
			.spyOn(IncidentRecorderWriter.prototype, "fenceRunIdentity")
			.mockImplementation(function (
				this: IncidentRecorderWriter,
				...args: Parameters<IncidentRecorderWriter["fenceRunIdentity"]>
			) {
				return originalFenceRunIdentity.apply(this, args);
			});
		const recordExactBytesForRun = vi.spyOn(IncidentRecorderWriter.prototype, "recordExactBytesForRun");
		const historicalAdoptionsSince = (callIndex: number): Set<string> =>
			new Set(
				adoptRunIdentitySeal.mock.calls.slice(callIndex).flatMap(([candidate]) => {
					if (!candidate || typeof candidate !== "object") return [];
					const runId = (candidate as { runId?: unknown }).runId;
					return typeof runId === "string" && historicalRunIds.has(runId) ? [runId] : [];
				}),
			);
		const inspectHistoricalRuns = async (callIndex: number, description: string): Promise<void> => {
			for (
				let attempt = 0;
				attempt < 48 && historicalAdoptionsSince(callIndex).size < historicalRunIds.size;
				attempt += 1
			) {
				await inspectIncidentRecorderRuns(target.agentDir, Date.now());
			}
			expect(historicalAdoptionsSince(callIndex), description).toEqual(historicalRunIds);
		};
		const runServicePasses = async (description: string, includeFreshEvidence: boolean): Promise<void> => {
			const signals = new TestSignalSource();
			let resolveReady: () => void = () => {};
			const ready = new Promise<void>((resolve) => {
				resolveReady = resolve;
			});
			let running: Promise<void> | undefined;
			const scanStart = adoptRunIdentitySeal.mock.calls.length;
			try {
				running = runIncidentRecorderService(target.agentDir, {
					notify: (fields) => {
						if (fields.includes("READY=1")) resolveReady();
					},
					serviceIdentitySealFenceMaxIdentities: 1,
					signalSource: signals,
					writerStopDeadlineMs: 1_000,
				});
				running.catch(() => {});
				await withTimeout(ready, 10_000);
				await inspectHistoricalRuns(scanStart, `${description}: bounded scan`);
				expect(snapshotControls(), `${description}: controls after scan`).toEqual(baselineControls);

				const reinspectionStart = adoptRunIdentitySeal.mock.calls.length;
				await inspectHistoricalRuns(reinspectionStart, `${description}: reinspection`);
				expect(snapshotControls(), `${description}: controls after reinspection`).toEqual(baselineControls);

				if (includeFreshEvidence) {
					const freshRunId = "f2f2f2f2-f2f2-42f2-82f2-f2f2f2f2f2f2";
					const freshRunToken = "f3f3f3f3-f3f3-43f3-83f3-f3f3f3f3f3f3";
					const freshRunDir = join(target.root, `fresh-${freshRunId}`);
					mkdirSync(freshRunDir, { recursive: true, mode: 0o700 });
					writeServiceTestJson(join(freshRunDir, "process.json"), serviceTestProcessControl(freshRunToken));
					const recordCallCount = recordExactBytesForRun.mock.calls.length;
					ingestIncidentRecorderEvidence(freshRunDir, "kernel", Buffer.from("fresh service evidence"));
					expect(recordExactBytesForRun.mock.calls.length).toBe(recordCallCount + 1);
					expect(recordExactBytesForRun.mock.calls.at(-1)?.[0]).toMatchObject({
						runId: freshRunId,
						runToken: freshRunToken,
					});
					expect(recordExactBytesForRun.mock.results.at(-1)?.value).toMatchObject({ accepted: true });
				}

				const sealedRunDir = definitions[0]?.runDir;
				if (!sealedRunDir) throw new Error("missing historical sealed run fixture");
				const previousRunDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
				try {
					process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = sealedRunDir;
					const recordCallCount = recordExactBytesForRun.mock.calls.length;
					ingestIncidentRecorderEvidence(sealedRunDir, "kernel", Buffer.from("sealed service evidence"));
					appendSupervisorDiagnosticEvent("sealed_service_derived_probe", { diagnosticOnly: true });
					appendSupervisorDiagnosticBytes("sealed_service_bytes_probe", Buffer.from("sealed service bytes"), {
						diagnosticOnly: true,
					});
					expect(recordExactBytesForRun.mock.calls.length).toBe(recordCallCount);
				} finally {
					if (previousRunDir === undefined) delete process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
					else process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = previousRunDir;
				}
				expect(snapshotControls(), `${description}: controls after namespace guard`).toEqual(baselineControls);
				signals.emit("SIGTERM");
				await withTimeout(running, 10_000);
			} finally {
				if (signals.size > 0) signals.emit("SIGTERM");
				if (running) await withTimeout(running, 10_000).catch(() => undefined);
			}
		};

		await runServicePasses("first service", true);
		await runServicePasses("restarted service", false);
		const historicalCalls = adoptRunIdentitySeal.mock.calls
			.map((call, index) => ({ call, result: adoptRunIdentitySeal.mock.results[index]?.value }))
			.filter(({ call: [candidate] }) => {
				if (!candidate || typeof candidate !== "object") return false;
				const runId = (candidate as { runId?: unknown }).runId;
				return typeof runId === "string" && historicalRunIds.has(runId);
			});
		expect(historicalCalls.length).toBeGreaterThanOrEqual(65 * 3);
		for (const { call, result } of historicalCalls) {
			expect(call[1]).toEqual({ durableReplay: true });
			expect(result).toMatchObject({ adopted: true });
		}
		expect(fenceRunIdentity).not.toHaveBeenCalled();
		expect(projectRunHistory).not.toHaveBeenCalled();
		expect(snapshotControls()).toEqual(baselineControls);
	}, 30_000);
});
