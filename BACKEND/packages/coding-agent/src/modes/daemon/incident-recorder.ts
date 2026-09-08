import { type ChildProcess, type SpawnSyncReturns, spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	chmodSync,
	closeSync,
	type Dir,
	type Dirent,
	existsSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	linkSync,
	lstatSync,
	mkdirSync,
	opendirSync,
	openSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	readSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative as relativePath, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { parseIncidentRecorderServiceArgs } from "../../cli/incident-recorder-service-args.js";
import {
	type CliSubprocessLaunchSpec,
	createCliSubprocessEnv,
	createCliSubprocessLaunchSpec,
} from "../../cli/subprocess-launch.js";
import { getAgentDir, getDaemonLogPath, VERSION } from "../../config.js";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "../../core/kernel/diagnostics.js";
import { getProcessStartId } from "../../core/session-lease.js";
import { resolveIncidentRecorderBootstrapPaths } from "./incident-recorder-bootstrap.js";
import {
	beginIncidentCasV2Cutover,
	INCIDENT_CAS_V2_SERVICE_ENTRYPOINT,
	INCIDENT_CAS_V2_SYSTEMD_UNIT,
	type IncidentCasV2CutoverTarget,
	openIncidentCasV2Activation,
	proveIncidentCasV1Quiescence,
	publishIncidentCasV2,
} from "./incident-recorder-cas-cutover.js";
import {
	acquireIncidentCasTransaction,
	acquireIncidentCasTransactionDetailed,
	type CasTransaction,
	type IncidentCasRelativePath,
	type IncidentCasRootMutation,
} from "./incident-recorder-cas-transaction.js";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderCompactorOptions,
	type IncidentRecorderLiveRunEventsCursor,
	type IncidentRecorderLiveRunEventsPage,
	type IncidentRecorderRetainedRunHistoryResult,
	type IncidentRecorderRunHistoryCursor,
	type IncidentRecorderRunHistoryEvent,
	type IncidentRecorderRunHistoryResult,
	IncidentRecorderSegmentOwnershipUncertainError,
	type IncidentRecorderStorageMode,
	type StoppedTargetArtifactReference,
} from "./incident-recorder-compactor.js";
import { INCIDENT_RECORDER_DERIVED_OBSERVATION_RESERVATION_BYTES } from "./incident-recorder-diagnostic-serializer.js";
import {
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
	INCIDENT_RECORDER_SOCKET_ENV,
} from "./incident-recorder-env.js";
import {
	type IncidentRecorderFinalizationBarrierProof,
	readCompactedFinalizationBarrier,
} from "./incident-recorder-finalization-barrier.js";
import {
	analyzeIncidentRecorderFinalization,
	finalizeIncidentRecorderProjection,
	type IncidentRecorderFinalizationFaultBoundary,
	type IncidentRecorderFinalizationInput,
	type IncidentRecorderRelayFrontierExpectation,
	inspectIncidentRetentionAuthority,
	persistIncidentFinalizationSeal,
	persistIncidentRetentionAuthority,
	recoverPublishedIncidentFinalization,
} from "./incident-recorder-finalizer.js";
import {
	baselineLinuxIncidentEvidence,
	hasPositiveLinuxCgroupOomKillDelta,
	type LinuxMemorySummary,
	type LinuxRawSourceOccurrence,
	readLinuxIncidentEvidenceCorrelation,
	sampleLinuxIncidentEvidence,
} from "./incident-recorder-linux.js";
import type { IncidentRecorderLiveObservationValidationCheckpoint } from "./incident-recorder-live-publication.js";
import {
	extractIncidentRecorderLiveTriggerIntentCandidate,
	type IncidentRecorderLiveTriggerIntentCandidate,
} from "./incident-recorder-live-trigger-intent.js";
import {
	INCIDENT_RECORDER_RUN_ID_ENV,
	INCIDENT_RECORDER_RUN_TOKEN_ENV,
	newIncidentRecorderToken,
} from "./incident-recorder-protocol.js";
import {
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	INCIDENT_RETENTION_SERVICE_BUDGET,
	incidentRetentionNextDelayMs,
	runIncidentRetentionPass,
} from "./incident-recorder-retention.js";
import type { IncidentRecorderSegmentPruneCursor } from "./incident-recorder-segment-store.js";
import { IncidentRecorderServiceWriterLifecycle } from "./incident-recorder-service-writer-lifecycle.js";
import {
	configureIncidentCaptureEmitter,
	emitIncidentBytes,
	emitIncidentControl,
	emitIncidentDerived,
	INCIDENT_RECORDER_CAPTURE_FD,
	INCIDENT_RECORDER_CAPTURE_FD_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV,
	INCIDENT_RECORDER_ROOT_FD,
	INCIDENT_RECORDER_ROOT_FD_ENV,
	type IncidentRecorderAdmission,
	type IncidentRecorderFinalizationExpectation,
	type IncidentRecorderRelayFrontier,
	type IncidentRecorderRunIdentitySealResult,
	type IncidentRecorderServiceIdentitySealFenceSaturatedError,
	type IncidentRecorderWrapperFrontier,
	type IncidentRecorderWrapperFrontierSaturatedError,
	IncidentRecorderWriter,
	parseIncidentRecorderRunIdentitySeal,
	stopIncidentCaptureEmitter,
	stopIncidentCaptureEmitterOnExit,
} from "./incident-recorder-writer.js";
import type { IncidentRecorderWriterLifecycleAdmissionContract } from "./incident-recorder-writer-lifecycle.js";
import { emitNativeDiagnostic, flushNativeDiagnostics, nativeDiagnosticsEnabled } from "./diagnostic-journal-emitter.js";

export {
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
	INCIDENT_RECORDER_SOCKET_ENV,
};

const EVENT_FILE_NAME = "timeline.jsonl";
const RAW_APPLICATION_DIR_NAME = "raw-application";
export const INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX = ".diagnostic-secret";

export function isIncidentRecorderExcludedApplicationPath(path: string): boolean {
	return basename(path).endsWith(INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX);
}
const ACTIVE_MARKER_FILE_NAME = ".recorder-active";
const FINALIZER_CLAIM_FILE_NAME = ".incident-finalizer-claim";
const HEARTBEAT_INTERVAL_MS = 1_000;
const STALL_THRESHOLD_MS = 10_000;
const RAW_MANIFEST_CHECKPOINT_MS = 5_000;
const RAW_SEGMENT_ROTATION_MS = 5 * 60 * 1_000;
const RAW_RECORD_SCHEMA_VERSION = 2;
const RAW_FRAME_PAYLOAD_BYTES = 32 * 1024;
const FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS = 3;
const FALLBACK_EVIDENCE_ADMISSION_WAIT_MS = 5;
const FALLBACK_EVIDENCE_ADMISSION_RETRY_MIN_MS = 25;
const FALLBACK_EVIDENCE_ADMISSION_RETRY_MAX_MS = 1_000;
const FALLBACK_EVIDENCE_ADMISSION_RECEIPT_LIMIT = 256;
const FALLBACK_EVIDENCE_ADMISSION_PENDING_LIMIT = 4_096;
const SERVICE_PROCESS_IDENTITY_PUBLICATION_GRACE_MS = 5_000;
const SERVICE_FINALIZATION_RETRY_GRACE_MS = 60_000;
const SERVICE_CONTROL_FUTURE_SKEW_MS = 5 * 60_000;
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const INCIDENT_RECORDER_SERVICE_ORCHESTRATION_FAULT_BOUNDARIES = [
	"after_stopped_repair_witness_durable_before_observation_quarantine",
	"after_replay_marker_durable_before_reconstructed_intent",
] as const;

export type IncidentRecorderServiceOrchestrationFaultBoundary =
	(typeof INCIDENT_RECORDER_SERVICE_ORCHESTRATION_FAULT_BOUNDARIES)[number];

type IncidentRecorderOrchestrationFaultBoundary =
	| IncidentRecorderFinalizationFaultBoundary
	| IncidentRecorderServiceOrchestrationFaultBoundary;

const LINUX_BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id";

function linuxBootId(): string | undefined {
	if (process.platform !== "linux") return undefined;
	try {
		const value = readFileSync(LINUX_BOOT_ID_PATH, "utf8").trim();
		return /^[0-9a-f-]{36}$/i.test(value) ? value : undefined;
	} catch {
		return undefined;
	}
}

function linuxMachineId(): string | undefined {
	if (process.platform !== "linux") return undefined;
	try {
		const value = readFileSync("/etc/machine-id", "utf8").trim();
		return /^[0-9a-f]{32}$/i.test(value) ? value : undefined;
	} catch {
		return undefined;
	}
}

type RawApplicationSource =
	| "recorder-events"
	| "supervisor-events"
	| "supervisor-stdout"
	| "supervisor-stderr"
	| "worker-stdout"
	| "worker-stderr"
	| "worker-transport"
	| "loss-accounting"
	| "linux-raw-source"
	| "linux-journal-source"
	| "provider-evidence"
	| "provider-manifest";

/** Segment size is a rotation boundary, not a retention or semantic filtering policy. */
export const INCIDENT_RECORDER_LIMITS = {
	rawSegmentBytes: 64 * 1024 * 1024,
	eventFileBytes: 1024 * 1024,
	eventRecordBytes: 8 * 1024,
	evidenceFileBytes: 256 * 1024,
	nodeReportInputBytes: 2 * 1024 * 1024,
	nodeReportFileBytes: 128 * 1024,
	perRunBytes: 8 * 1024 * 1024,
	perBundleBytes: 8 * 1024 * 1024,
	retentionAgeMs: INCIDENT_DIAGNOSTIC_RETENTION_MS,
	maxReportsPerRun: 4,
	maxDirectoryEntries: 256,
} as const;

export interface IncidentRecorderEvent {
	type: string;
	wallTime: string;
	monotonicNs: string;
	pid: number;
	[key: string]: unknown;
}

export interface RecordedProcessResult {
	code: number | null;
	signal: NodeJS.Signals | null;
	runDir: string;
	incidentDir?: string;
	classification: string;
}

export interface RecordProcessOptions {
	agentDir: string;
	socketPath: string;
	launch: CliSubprocessLaunchSpec;
	cwd?: string;
	environment?: NodeJS.ProcessEnv;
}

interface BoundedRead {
	value: Buffer;
	truncated: boolean;
}

interface RawSegmentState {
	runDir: string;
	source: RawApplicationSource;
	directory: string;
	segmentIndex: number;
	segmentBytes: number;
	segmentOpenedMs: number;
}

interface RawRecordFrame {
	schemaVersion: number;
	recordId: string;
	chunkIndex: number;
	chunkCount: number;
	encoding: "base64";
	payload: string;
}

const rawSegmentStates = new Map<string, RawSegmentState>();
const knownRawBlobDirectories = new Set<string>();
let rawRecordSequence = 0;
let providerOccurrenceSequence = 0;
let activeOrderedWriter: { runDir: string; writer: IncidentRecorderWriter } | undefined;
interface ServiceRecorderRuntime {
	writer: IncidentRecorderWriter;
	compactor: IncidentRecorderCompactor;
}
let activeServiceRecorder: ServiceRecorderRuntime | undefined;

function orderedWriterForRun(runDir: string): IncidentRecorderWriter | undefined {
	return activeOrderedWriter?.runDir === runDir ? activeOrderedWriter.writer : undefined;
}

const durablyFencedServiceRuns = new Set<string>();
const pendingProviderReferenceWrites = new Map<string, number>();
const providerReferenceWriteWaiters = new Map<string, Array<() => void>>();
const casTransactionRetryWait = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));

const FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS = [
	"cross_process_cas_transaction_backpressure",
	"root_detached_durable",
	"root_detached_pending",
	"release_pending",
	"capability_error",
] as const;

type FallbackEvidenceAdmissionLossReason = (typeof FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS)[number];

interface FallbackEvidenceAdmissionBackpressure {
	batchId: string;
	runIdentity: ServiceRunDirectoryIdentity;
	blockedAdmissions: number;
	retryAttempts: number;
	firstObservedWallTimeMs: number;
	lastObservedWallTimeMs: number;
	causes: Partial<Record<FallbackEvidenceAdmissionLossReason, number>>;
}

class FallbackEvidenceAdmissionCapacityError extends Error {
	constructor(message = "Fallback admission pending capacity is exhausted") {
		super(message);
		this.name = "FallbackEvidenceAdmissionCapacityError";
	}
}

function isFallbackEvidenceAdmissionCapacityError(error: unknown): error is FallbackEvidenceAdmissionCapacityError {
	return error instanceof FallbackEvidenceAdmissionCapacityError;
}

const fallbackEvidenceAdmissionBackpressure = new Map<string, FallbackEvidenceAdmissionBackpressure>();
const fallbackEvidenceAdmissionRetryTimers = new Map<string, NodeJS.Timeout>();

const providerFallbackAdmissionPostRawTestRuntime = Object.freeze({});
const providerFallbackAdmissionPostRawTestSynchronizations = new WeakMap<
	typeof providerFallbackAdmissionPostRawTestRuntime,
	() => void
>();

/** @internal One-shot synchronization for deterministic admission-loss crash tests. */
export function registerIncidentRecorderFallbackAdmissionPostRawTestSynchronization(hook: () => void): () => void {
	if (process.env.NODE_ENV !== "test") {
		throw new Error("Incident recorder admission-loss test synchronization is unavailable outside tests");
	}
	if (providerFallbackAdmissionPostRawTestSynchronizations.has(providerFallbackAdmissionPostRawTestRuntime)) {
		throw new Error("Incident recorder admission-loss test synchronization is already registered");
	}
	providerFallbackAdmissionPostRawTestSynchronizations.set(providerFallbackAdmissionPostRawTestRuntime, hook);
	return () => {
		if (
			providerFallbackAdmissionPostRawTestSynchronizations.get(providerFallbackAdmissionPostRawTestRuntime) === hook
		) {
			providerFallbackAdmissionPostRawTestSynchronizations.delete(providerFallbackAdmissionPostRawTestRuntime);
		}
	};
}

function runProviderFallbackAdmissionPostRawTestSynchronization(): void {
	const hook = providerFallbackAdmissionPostRawTestSynchronizations.get(providerFallbackAdmissionPostRawTestRuntime);
	if (!hook) return;
	providerFallbackAdmissionPostRawTestSynchronizations.delete(providerFallbackAdmissionPostRawTestRuntime);
	hook();
}

/** @internal Deterministic pressure seam for bounded fallback-loss tests. */
export function exerciseIncidentRecorderFallbackAdmissionPendingPressureForTest(
	runDir: string,
	operation?: () => void,
): {
	pendingEntries: number;
} {
	if (process.env.NODE_ENV !== "test") {
		throw new Error("Incident recorder admission pressure test seam is unavailable outside tests");
	}
	const runIdentity = fallbackAdmissionRunIdentity(runDir);
	if (!runIdentity) throw new Error("Fallback admission pressure run identity is invalid");
	if (fallbackEvidenceAdmissionBackpressure.has(runDir)) {
		throw new Error("Fallback admission pressure run already has pending loss");
	}
	const seededKeys: string[] = [];
	const seedPrefix = `${runDir}\0test-fallback-pressure-${randomUUID()}-`;
	try {
		while (fallbackEvidenceAdmissionBackpressure.size < FALLBACK_EVIDENCE_ADMISSION_PENDING_LIMIT) {
			const key = `${seedPrefix}${seededKeys.length}`;
			seededKeys.push(key);
			fallbackEvidenceAdmissionBackpressure.set(key, {
				batchId: randomUUID(),
				runIdentity,
				blockedAdmissions: 1,
				retryAttempts: 0,
				firstObservedWallTimeMs: Date.now(),
				lastObservedWallTimeMs: Date.now(),
				causes: { capability_error: 1 },
			});
		}
		if (operation) operation();
		else noteFallbackEvidenceAdmissionBackpressure(runDir, "capability_error");
		return {
			pendingEntries: fallbackEvidenceAdmissionBackpressure.size,
		};
	} finally {
		for (const key of seededKeys) fallbackEvidenceAdmissionBackpressure.delete(key);
		cancelFallbackEvidenceAdmissionRetry(runDir);
		fallbackEvidenceAdmissionBackpressure.delete(runDir);
	}
}

/** @internal Read-only state seam for deterministic fallback-admission lifecycle tests. */
export function inspectIncidentRecorderFallbackAdmissionForTest(runDir: string): {
	accountedLoss: number;
	pending: boolean;
	retryScheduled: boolean;
} {
	if (process.env.NODE_ENV !== "test") {
		throw new Error("Incident recorder admission inspection is unavailable outside tests");
	}
	return {
		accountedLoss: fallbackEvidenceAdmissionLossRecords(runDir),
		pending: fallbackEvidenceAdmissionBackpressure.has(runDir),
		retryScheduled: fallbackEvidenceAdmissionRetryTimers.has(runDir),
	};
}

interface FallbackEvidenceAdmissionLossBatch {
	batchId: string;
	lostAdmissions: number;
	firstObservedWallTimeMs: number;
	lastObservedWallTimeMs: number;
	asynchronousRetryAttempts: number;
	causes: Partial<Record<FallbackEvidenceAdmissionLossReason, number>>;
	rawAdmissions?: number;
	rawCauses?: Partial<Record<FallbackEvidenceAdmissionLossReason, number>>;
}

interface FallbackEvidenceAdmissionLoss {
	schemaVersion: 1 | 2 | 3;
	kind: "service_fallback_admission_loss";
	runId: string;
	lostAdmissions: number;
	firstObservedWallTimeMs: number;
	lastObservedWallTimeMs: number;
	synchronousAttemptLimit: number;
	synchronousWaitIntervalMs: number;
	asynchronousRetryAttempts: number;
	batches?: FallbackEvidenceAdmissionLossBatch[];
}

function fallbackEvidenceAdmissionLossPath(runDir: string): string {
	return join(runDir, "service-finalization-fallback-admission-loss.json");
}

function validFallbackEvidenceAdmissionLossCauses(
	value: unknown,
): value is Partial<Record<FallbackEvidenceAdmissionLossReason, number>> {
	if (!isRecordObject(value)) return false;
	return Object.entries(value).every(
		([reason, count]) =>
			FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS.includes(reason as FallbackEvidenceAdmissionLossReason) &&
			Number.isSafeInteger(count) &&
			Number(count) > 0,
	);
}

function parseFallbackEvidenceAdmissionLoss(value: unknown, runId: string): FallbackEvidenceAdmissionLoss | undefined {
	const baseKeys = [
		"schemaVersion",
		"kind",
		"runId",
		"lostAdmissions",
		"firstObservedWallTimeMs",
		"lastObservedWallTimeMs",
		"synchronousAttemptLimit",
		"synchronousWaitIntervalMs",
		"asynchronousRetryAttempts",
	];
	if (
		!CANONICAL_UUID.test(runId) ||
		!isRecordObject(value) ||
		(value.schemaVersion !== 1 && value.schemaVersion !== 2 && value.schemaVersion !== 3) ||
		!hasExactObjectKeys(value, value.schemaVersion === 1 ? baseKeys : [...baseKeys, "batches"]) ||
		value.kind !== "service_fallback_admission_loss" ||
		value.runId !== runId ||
		!Number.isSafeInteger(value.lostAdmissions) ||
		Number(value.lostAdmissions) <= 0 ||
		!Number.isSafeInteger(value.firstObservedWallTimeMs) ||
		Number(value.firstObservedWallTimeMs) < 0 ||
		!Number.isSafeInteger(value.lastObservedWallTimeMs) ||
		Number(value.lastObservedWallTimeMs) < Number(value.firstObservedWallTimeMs) ||
		value.synchronousAttemptLimit !== FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS ||
		value.synchronousWaitIntervalMs !== FALLBACK_EVIDENCE_ADMISSION_WAIT_MS ||
		!Number.isSafeInteger(value.asynchronousRetryAttempts) ||
		Number(value.asynchronousRetryAttempts) < 0
	) {
		return undefined;
	}
	if (
		(value.schemaVersion === 2 || value.schemaVersion === 3) &&
		(!Array.isArray(value.batches) ||
			value.batches.length > (value.schemaVersion === 3 ? FALLBACK_EVIDENCE_ADMISSION_RECEIPT_LIMIT : 4_096) ||
			value.batches.some(
				(batch) =>
					!isRecordObject(batch) ||
					!hasExactObjectKeys(
						batch,
						value.schemaVersion === 2
							? [
									"batchId",
									"lostAdmissions",
									"firstObservedWallTimeMs",
									"lastObservedWallTimeMs",
									"asynchronousRetryAttempts",
									"causes",
								]
							: [
									"batchId",
									"lostAdmissions",
									"firstObservedWallTimeMs",
									"lastObservedWallTimeMs",
									"asynchronousRetryAttempts",
									"causes",
									"rawAdmissions",
									"rawCauses",
								],
					) ||
					!CANONICAL_UUID.test(String(batch.batchId)) ||
					!Number.isSafeInteger(batch.lostAdmissions) ||
					Number(batch.lostAdmissions) <= 0 ||
					!Number.isSafeInteger(batch.firstObservedWallTimeMs) ||
					Number(batch.firstObservedWallTimeMs) < 0 ||
					!Number.isSafeInteger(batch.lastObservedWallTimeMs) ||
					Number(batch.lastObservedWallTimeMs) < Number(batch.firstObservedWallTimeMs) ||
					!Number.isSafeInteger(batch.asynchronousRetryAttempts) ||
					Number(batch.asynchronousRetryAttempts) < 0 ||
					!validFallbackEvidenceAdmissionLossCauses(batch.causes) ||
					(value.schemaVersion === 3 &&
						(!Number.isSafeInteger(batch.rawAdmissions) ||
							Number(batch.rawAdmissions) < 0 ||
							Number(batch.rawAdmissions) > Number(batch.lostAdmissions) ||
							!validFallbackEvidenceAdmissionLossCauses(batch.rawCauses))),
			))
	) {
		return undefined;
	}
	return value as unknown as FallbackEvidenceAdmissionLoss;
}

function currentFallbackEvidenceAdmissionLoss(runDir: string): FallbackEvidenceAdmissionLoss | undefined {
	const path = fallbackEvidenceAdmissionLossPath(runDir);
	const control =
		readPrivateCanonicalJson<unknown>(path, INCIDENT_RECORDER_LIMITS.evidenceFileBytes) ??
		readPrivateCanonicalControlJsonWithIdentity<unknown>(path, INCIDENT_RECORDER_LIMITS.evidenceFileBytes)?.value;
	return parseFallbackEvidenceAdmissionLoss(control, basename(runDir).slice(-36));
}

function fallbackAdmissionRunIdentity(runDir: string): ServiceRunDirectoryIdentity | undefined {
	return privateServiceRunDirectoryIdentity(runDir);
}

function fallbackAdmissionRunIdentityMatches(runDir: string, identity: ServiceRunDirectoryIdentity): boolean {
	return currentServiceRunDirectory(runDir, identity);
}

function appliedFallbackEvidenceAdmissionBatch(
	loss: FallbackEvidenceAdmissionLoss | undefined,
	pending: FallbackEvidenceAdmissionBackpressure,
): FallbackEvidenceAdmissionLossBatch | undefined {
	return loss?.schemaVersion === 2 || loss?.schemaVersion === 3
		? loss.batches?.find((batch) => batch.batchId === pending.batchId)
		: undefined;
}

function fallbackEvidenceAdmissionBatchPreservesPending(
	batch: FallbackEvidenceAdmissionLossBatch | undefined,
	pending: FallbackEvidenceAdmissionBackpressure,
): boolean {
	if (!batch || batch.lostAdmissions < pending.blockedAdmissions) return false;
	return FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS.every(
		(reason) => (batch.causes[reason] ?? 0) >= (pending.causes[reason] ?? 0),
	);
}

interface FallbackEvidenceAdmissionRawObservation {
	admissions: number;
	causes: Partial<Record<FallbackEvidenceAdmissionLossReason, number>>;
}

function observeFallbackEvidenceAdmissionRawRecords(
	records: readonly IncidentRecorderEvent[],
): FallbackEvidenceAdmissionRawObservation {
	const ranges: Array<{ start: number; end: number }> = [];
	const rangedReceiptKeys = new Set<string>();
	let unboundedAdmissions = 0;
	const causes: Partial<Record<FallbackEvidenceAdmissionLossReason, number>> = {};
	for (const record of records) {
		if (
			record.type !== "fallback_run_evidence_admission_loss" ||
			!Number.isSafeInteger(record.lostAdmissions) ||
			Number(record.lostAdmissions) <= 0
		)
			continue;
		const start = record.rawStartAdmissions;
		const end = record.rawEndAdmissions;
		let rangedReceipt = false;
		if (
			Number.isSafeInteger(start) &&
			Number.isSafeInteger(end) &&
			Number(start) >= 0 &&
			Number(end) >= Number(start) &&
			Number(end) - Number(start) === Number(record.lostAdmissions)
		) {
			rangedReceipt = true;
			ranges.push({ start: Number(start), end: Number(end) });
			const receiptKey = `${Number(start)}:${Number(end)}`;
			if (!rangedReceiptKeys.has(receiptKey) && validFallbackEvidenceAdmissionLossCauses(record.causes)) {
				Object.assign(causes, mergeFallbackEvidenceAdmissionCauses(causes, record.causes));
			}
			rangedReceiptKeys.add(receiptKey);
		} else {
			unboundedAdmissions = Math.min(Number.MAX_SAFE_INTEGER, unboundedAdmissions + Number(record.lostAdmissions));
		}
		if (!rangedReceipt && validFallbackEvidenceAdmissionLossCauses(record.causes)) {
			Object.assign(causes, mergeFallbackEvidenceAdmissionCauses(causes, record.causes));
		}
	}
	ranges.sort((left, right) => left.start - right.start || left.end - right.end);
	let rangedAdmissions = 0;
	let rangeEnd = -1;
	for (const range of ranges) {
		if (range.start > rangeEnd) {
			rangedAdmissions = Math.min(Number.MAX_SAFE_INTEGER, rangedAdmissions + range.end - range.start);
			rangeEnd = range.end;
		} else if (range.end > rangeEnd) {
			rangedAdmissions = Math.min(Number.MAX_SAFE_INTEGER, rangedAdmissions + range.end - rangeEnd);
			rangeEnd = range.end;
		}
	}
	return {
		admissions: Math.min(Number.MAX_SAFE_INTEGER, rangedAdmissions + unboundedAdmissions),
		causes,
	};
}

function observeFallbackEvidenceAdmissionRaw(runDir: string, batchId: string): FallbackEvidenceAdmissionRawObservation {
	return observeFallbackEvidenceAdmissionRawRecords(
		readRawEventSource(runDir, "loss-accounting").filter((record) => record.admissionBatchId === batchId),
	);
}

function fallbackEvidenceAdmissionPendingDelta(
	loss: FallbackEvidenceAdmissionLoss | undefined,
	pending: FallbackEvidenceAdmissionBackpressure,
): number {
	return Math.max(
		0,
		pending.blockedAdmissions - (appliedFallbackEvidenceAdmissionBatch(loss, pending)?.lostAdmissions ?? 0),
	);
}

function fallbackEvidenceAdmissionLossRecords(runDir: string): number {
	const loss = currentFallbackEvidenceAdmissionLoss(runDir);
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	const overflowAdmissions = readRawEventSource(runDir, "loss-accounting")
		.filter(
			(record) =>
				record.type === "fallback_run_evidence_admission_loss" &&
				record.admissionOverflow === true &&
				Number.isSafeInteger(record.lostAdmissions) &&
				Number(record.lostAdmissions) > 0,
		)
		.reduce((total, record) => Math.min(Number.MAX_SAFE_INTEGER, total + Number(record.lostAdmissions)), 0);
	return Math.min(
		Number.MAX_SAFE_INTEGER,
		(loss?.lostAdmissions ?? 0) +
			(pending ? fallbackEvidenceAdmissionPendingDelta(loss, pending) : 0) +
			overflowAdmissions,
	);
}

function bindFallbackAdmissionLossToServiceSeal(
	runDir: string,
	seal: IncidentRecorderRunIdentitySealResult,
): IncidentRecorderRunIdentitySealResult {
	const lostAdmissions = fallbackEvidenceAdmissionLossRecords(runDir);
	if (lostAdmissions === 0) return seal;
	return {
		...seal,
		loss: {
			...seal.loss,
			terminalRelay: {
				...seal.loss.terminalRelay,
				uncertain: {
					records: Math.min(Number.MAX_SAFE_INTEGER, seal.loss.terminalRelay.uncertain.records + lostAdmissions),
					bytes: seal.loss.terminalRelay.uncertain.bytes,
				},
			},
		},
	};
}

function cancelFallbackEvidenceAdmissionRetry(runDir: string): void {
	const timer = fallbackEvidenceAdmissionRetryTimers.get(runDir);
	if (timer) clearTimeout(timer);
	fallbackEvidenceAdmissionRetryTimers.delete(runDir);
}

function rememberDurablyFencedServiceRun(runDir: string): void {
	durablyFencedServiceRuns.add(runDir);
	while (durablyFencedServiceRuns.size > 4096)
		durablyFencedServiceRuns.delete(durablyFencedServiceRuns.values().next().value as string);
}

function serviceFinalizationNamespaceObserved(runDir: string): boolean {
	if (durablyFencedServiceRuns.has(runDir)) {
		if (!fallbackEvidenceAdmissionBackpressure.has(runDir)) cancelFallbackEvidenceAdmissionRetry(runDir);
		return true;
	}
	if (
		!existsSync(join(runDir, "service-finalization-seal-intent.json")) &&
		!existsSync(join(runDir, "service-finalization-seal.json")) &&
		!existsSync(join(runDir, "service-finalization-seal-replay-ambiguity.json"))
	) {
		return false;
	}
	rememberDurablyFencedServiceRun(runDir);
	if (!fallbackEvidenceAdmissionBackpressure.has(runDir)) cancelFallbackEvidenceAdmissionRetry(runDir);
	return true;
}

function tryAcquireFallbackRunEvidenceAdmission(
	runDir: string,
	expectedIdentity?: ServiceRunDirectoryIdentity,
): CasTransaction | undefined {
	const recorderRoot = dirname(dirname(runDir));
	const runIdentity =
		expectedIdentity ??
		fallbackEvidenceAdmissionBackpressure.get(runDir)?.runIdentity ??
		fallbackAdmissionRunIdentity(runDir);
	if (!runIdentity || !fallbackAdmissionRunIdentityMatches(runDir, runIdentity)) {
		return undefined;
	}
	if (serviceFinalizationNamespaceObserved(runDir)) return undefined;
	const transaction = acquireIncidentCasTransaction(recorderRoot);
	if (!transaction) return undefined;
	if (!fallbackAdmissionRunIdentityMatches(runDir, runIdentity) || serviceFinalizationNamespaceObserved(runDir)) {
		transaction.release();
		return undefined;
	}
	return transaction;
}

function mergeFallbackEvidenceAdmissionCauses(
	...values: Array<Partial<Record<FallbackEvidenceAdmissionLossReason, number>> | undefined>
): Partial<Record<FallbackEvidenceAdmissionLossReason, number>> {
	const merged: Partial<Record<FallbackEvidenceAdmissionLossReason, number>> = {};
	for (const reason of FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS) {
		const count = values.reduce((total, value) => total + (value?.[reason] ?? 0), 0);
		if (count > 0) merged[reason] = Math.min(Number.MAX_SAFE_INTEGER, count);
	}
	return merged;
}

function cumulativeFallbackEvidenceAdmissionLoss(
	runId: string,
	loss: FallbackEvidenceAdmissionLoss | undefined,
	pending: FallbackEvidenceAdmissionBackpressure,
	observedRaw: FallbackEvidenceAdmissionRawObservation = {
		admissions: 0,
		causes: {},
	},
): {
	reservedLoss: FallbackEvidenceAdmissionLoss;
	completedLoss: FallbackEvidenceAdmissionLoss;
	deltaAdmissions: number;
	rawDeltaAdmissions: number;
	rawDeltaCauses: Partial<Record<FallbackEvidenceAdmissionLossReason, number>>;
	rawStart: number;
	rawEnd: number;
} {
	const applied = appliedFallbackEvidenceAdmissionBatch(loss, pending);
	const appliedAdmissions = applied?.lostAdmissions ?? 0;
	const targetAdmissions = Math.max(appliedAdmissions, pending.blockedAdmissions);
	const deltaAdmissions = Math.max(0, targetAdmissions - appliedAdmissions);
	const deltaRetryAttempts = Math.max(0, pending.retryAttempts - (applied?.asynchronousRetryAttempts ?? 0));
	const batchCauses: Partial<Record<FallbackEvidenceAdmissionLossReason, number>> = {};
	for (const reason of FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS) {
		const count = Math.max(applied?.causes[reason] ?? 0, pending.causes[reason] ?? 0);
		if (count > 0) batchCauses[reason] = count;
	}
	const storedRawAdmissions = loss?.schemaVersion === 3 ? (applied?.rawAdmissions ?? 0) : appliedAdmissions;
	const storedRawCauses = loss?.schemaVersion === 3 ? (applied?.rawCauses ?? {}) : (applied?.causes ?? {});
	const rawAdmissions = Math.min(targetAdmissions, Math.max(storedRawAdmissions, observedRaw.admissions));
	const observedRawCauses = mergeFallbackEvidenceAdmissionCauses(storedRawCauses, observedRaw.causes);
	const rawCauses =
		rawAdmissions >= targetAdmissions
			? batchCauses
			: (Object.fromEntries(
					FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS.flatMap((reason) => {
						const count = Math.min(batchCauses[reason] ?? 0, observedRawCauses[reason] ?? 0);
						return count > 0 ? [[reason, count]] : [];
					}),
				) as Partial<Record<FallbackEvidenceAdmissionLossReason, number>>);
	const rawDeltaCauses: Partial<Record<FallbackEvidenceAdmissionLossReason, number>> = {};
	for (const reason of FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS) {
		const delta = Math.max(0, (batchCauses[reason] ?? 0) - (rawCauses[reason] ?? 0));
		if (delta > 0) rawDeltaCauses[reason] = delta;
	}
	const commonBatch = {
		batchId: pending.batchId,
		lostAdmissions: targetAdmissions,
		firstObservedWallTimeMs: Math.min(
			applied?.firstObservedWallTimeMs ?? pending.firstObservedWallTimeMs,
			pending.firstObservedWallTimeMs,
		),
		lastObservedWallTimeMs: Math.max(
			applied?.lastObservedWallTimeMs ?? pending.lastObservedWallTimeMs,
			pending.lastObservedWallTimeMs,
		),
		asynchronousRetryAttempts: Math.max(applied?.asynchronousRetryAttempts ?? 0, pending.retryAttempts),
		causes: batchCauses,
	};
	const reservedBatch: FallbackEvidenceAdmissionLossBatch = {
		...commonBatch,
		rawAdmissions,
		rawCauses,
	};
	const completedBatch: FallbackEvidenceAdmissionLossBatch = {
		...commonBatch,
		rawAdmissions: targetAdmissions,
		rawCauses: batchCauses,
	};
	const priorBatches =
		loss?.schemaVersion === 2
			? (loss.batches ?? []).map((batch) => ({
					...batch,
					rawAdmissions: batch.lostAdmissions,
					rawCauses: batch.causes,
				}))
			: loss?.schemaVersion === 3
				? (loss.batches ?? [])
				: [];
	const retainedBatches = priorBatches.filter((candidate) => candidate.batchId !== pending.batchId);
	if (!applied && retainedBatches.length >= FALLBACK_EVIDENCE_ADMISSION_RECEIPT_LIMIT) {
		throw new FallbackEvidenceAdmissionCapacityError("Fallback admission loss receipt capacity is exhausted");
	}
	if (retainedBatches.length >= FALLBACK_EVIDENCE_ADMISSION_RECEIPT_LIMIT) {
		throw new Error("Fallback admission loss receipt history exceeds its durable bound");
	}
	const commonLoss = {
		schemaVersion: 3 as const,
		kind: "service_fallback_admission_loss" as const,
		runId,
		lostAdmissions: Math.min(Number.MAX_SAFE_INTEGER, (loss?.lostAdmissions ?? 0) + deltaAdmissions),
		firstObservedWallTimeMs: Math.min(
			loss?.firstObservedWallTimeMs ?? pending.firstObservedWallTimeMs,
			pending.firstObservedWallTimeMs,
		),
		lastObservedWallTimeMs: Math.max(
			loss?.lastObservedWallTimeMs ?? pending.lastObservedWallTimeMs,
			pending.lastObservedWallTimeMs,
		),
		synchronousAttemptLimit: FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS,
		synchronousWaitIntervalMs: FALLBACK_EVIDENCE_ADMISSION_WAIT_MS,
		asynchronousRetryAttempts: Math.min(
			Number.MAX_SAFE_INTEGER,
			(loss?.asynchronousRetryAttempts ?? 0) + deltaRetryAttempts,
		),
	};
	return {
		reservedLoss: { ...commonLoss, batches: [...retainedBatches, reservedBatch] },
		completedLoss: { ...commonLoss, batches: [...retainedBatches, completedBatch] },
		deltaAdmissions,
		rawDeltaAdmissions: Math.max(0, targetAdmissions - rawAdmissions),
		rawDeltaCauses,
		rawStart: rawAdmissions,
		rawEnd: targetAdmissions,
	};
}

function fallbackEvidenceAdmissionPrimaryCause(
	causes: Partial<Record<FallbackEvidenceAdmissionLossReason, number>>,
): FallbackEvidenceAdmissionLossReason | "multiple_admission_uncertainties" {
	const observed = FALLBACK_EVIDENCE_ADMISSION_LOSS_REASONS.filter((reason) => (causes[reason] ?? 0) > 0);
	return observed.length === 1
		? (observed[0] ?? "multiple_admission_uncertainties")
		: "multiple_admission_uncertainties";
}

function persistFallbackEvidenceAdmissionLossControl(
	runDir: string,
	loss: FallbackEvidenceAdmissionLoss,
	expectedIdentity: ServiceRunDirectoryIdentity,
): boolean {
	const path = fallbackEvidenceAdmissionLossPath(runDir);
	for (let attempt = 0; attempt < 2; attempt += 1) {
		if (!fallbackAdmissionRunIdentityMatches(runDir, expectedIdentity)) return false;
		const existing = currentFallbackEvidenceAdmissionLoss(runDir);
		if (existing && canonicalJsonValuesEqual(existing, loss)) return true;
		if (!existing && serviceControlOccupantExists(path)) {
			if (!quarantineInvalidServiceControl(runDir, path, "fallback-admission-loss")) {
				return false;
			}
		}
		if (!fallbackAdmissionRunIdentityMatches(runDir, expectedIdentity)) return false;
		writePrivateJsonAtomicSync(path, loss);
		fsyncPrivateDirectorySync(dirname(path));
		const readback = currentFallbackEvidenceAdmissionLoss(runDir);
		if (readback && canonicalJsonValuesEqual(readback, loss)) return true;
	}
	return false;
}

function persistFallbackEvidenceAdmissionBackpressure(runDir: string, allowFinalizedNamespace = false): void {
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	if (!pending) return;
	if (!fallbackAdmissionRunIdentityMatches(runDir, pending.runIdentity)) return;
	const finalizedNamespace = serviceFinalizationNamespaceObserved(runDir);
	if (finalizedNamespace && !allowFinalizedNamespace) return;
	try {
		const runId = basename(runDir).slice(-36);
		if (!CANONICAL_UUID.test(runId)) throw new Error("Fallback admission loss run identity is invalid");
		const plan = cumulativeFallbackEvidenceAdmissionLoss(
			runId,
			currentFallbackEvidenceAdmissionLoss(runDir),
			pending,
			observeFallbackEvidenceAdmissionRaw(runDir, pending.batchId),
		);
		if (!persistFallbackEvidenceAdmissionLossControl(runDir, plan.reservedLoss, pending.runIdentity)) {
			throw new Error("Fallback admission loss authority could not be persisted");
		}
		if (!finalizedNamespace && plan.rawDeltaAdmissions > 0) {
			if (!fallbackAdmissionRunIdentityMatches(runDir, pending.runIdentity)) return;
			writeRawLinesFullySync(
				loadRawSegmentState(runDir, "loss-accounting"),
				serializeRawRecord(
					runDir,
					"loss-accounting",
					"fallback_run_evidence_admission_loss",
					{
						cause: fallbackEvidenceAdmissionPrimaryCause(plan.rawDeltaCauses),
						causes: plan.rawDeltaCauses,
						admissionBatchId: pending.batchId,
						lostAdmissions: plan.rawDeltaAdmissions,
						rawStartAdmissions: plan.rawStart,
						rawEndAdmissions: plan.rawEnd,
						firstObservedWallTimeMs: pending.firstObservedWallTimeMs,
						lastObservedWallTimeMs: pending.lastObservedWallTimeMs,
						synchronousAttemptLimit: FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS,
						synchronousWaitIntervalMs: FALLBACK_EVIDENCE_ADMISSION_WAIT_MS,
						asynchronousRetryAttempts: pending.retryAttempts,
						disposition: "loss_recorded_after_admission_recovered",
					},
					true,
				),
			);
		}
		if (!finalizedNamespace) {
			if (!fallbackAdmissionRunIdentityMatches(runDir, pending.runIdentity)) return;
			if (!persistFallbackEvidenceAdmissionLossControl(runDir, plan.completedLoss, pending.runIdentity))
				throw new Error("Fallback admission loss completion could not be persisted");
		}
		const current = currentFallbackEvidenceAdmissionLoss(runDir);
		const applied = appliedFallbackEvidenceAdmissionBatch(current, pending);
		if (
			applied &&
			fallbackEvidenceAdmissionBatchPreservesPending(applied, pending) &&
			(finalizedNamespace || (applied.rawAdmissions ?? 0) >= applied.lostAdmissions) &&
			fallbackEvidenceAdmissionBackpressure.get(runDir) === pending
		) {
			fallbackEvidenceAdmissionBackpressure.delete(runDir);
			cancelFallbackEvidenceAdmissionRetry(runDir);
		}
	} catch {
		const newer = fallbackEvidenceAdmissionBackpressure.get(runDir);
		if (!newer || newer === pending) {
			fallbackEvidenceAdmissionBackpressure.set(runDir, pending);
			return;
		}
		fallbackEvidenceAdmissionBackpressure.set(runDir, {
			batchId: pending.batchId,
			runIdentity: pending.runIdentity,
			blockedAdmissions: Math.min(
				Number.MAX_SAFE_INTEGER,
				pending.blockedAdmissions + (newer?.blockedAdmissions ?? 0),
			),
			retryAttempts: Math.max(pending.retryAttempts, newer?.retryAttempts ?? 0),
			firstObservedWallTimeMs: Math.min(
				pending.firstObservedWallTimeMs,
				newer?.firstObservedWallTimeMs ?? pending.firstObservedWallTimeMs,
			),
			lastObservedWallTimeMs: Math.max(
				pending.lastObservedWallTimeMs,
				newer?.lastObservedWallTimeMs ?? pending.lastObservedWallTimeMs,
			),
			causes: mergeFallbackEvidenceAdmissionCauses(pending.causes, newer?.causes),
		});
	}
}

function scheduleFallbackEvidenceAdmissionRetry(runDir: string): void {
	if (fallbackEvidenceAdmissionRetryTimers.has(runDir) || !fallbackEvidenceAdmissionBackpressure.has(runDir)) {
		return;
	}
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	if (!pending) return;
	const delayMs = Math.min(
		FALLBACK_EVIDENCE_ADMISSION_RETRY_MAX_MS,
		FALLBACK_EVIDENCE_ADMISSION_RETRY_MIN_MS * 2 ** Math.min(pending.retryAttempts, 5),
	);
	const timer = setTimeout(() => {
		fallbackEvidenceAdmissionRetryTimers.delete(runDir);
		const pendingAtCallback = fallbackEvidenceAdmissionBackpressure.get(runDir);
		if (!pendingAtCallback) return;
		if (!fallbackAdmissionRunIdentityMatches(runDir, pendingAtCallback.runIdentity)) {
			pendingAtCallback.retryAttempts = Math.min(Number.MAX_SAFE_INTEGER, pendingAtCallback.retryAttempts + 1);
			scheduleFallbackEvidenceAdmissionRetry(runDir);
			return;
		}
		const finalizedNamespace = serviceFinalizationNamespaceObserved(runDir);
		let transaction = finalizedNamespace
			? fallbackAdmissionRunIdentityMatches(runDir, pendingAtCallback.runIdentity)
				? acquireIncidentCasTransaction(dirname(dirname(runDir)))
				: undefined
			: tryAcquireFallbackRunEvidenceAdmission(runDir);
		if (transaction && !fallbackAdmissionRunIdentityMatches(runDir, pendingAtCallback.runIdentity)) {
			try {
				transaction.release();
			} catch {}
			transaction = undefined;
		}
		if (!transaction) {
			const current = fallbackEvidenceAdmissionBackpressure.get(runDir);
			if (current) current.retryAttempts = Math.min(Number.MAX_SAFE_INTEGER, current.retryAttempts + 1);
			scheduleFallbackEvidenceAdmissionRetry(runDir);
			return;
		}
		try {
			persistFallbackEvidenceAdmissionBackpressure(runDir, true);
		} finally {
			transaction.release();
		}
		if (fallbackEvidenceAdmissionBackpressure.has(runDir)) scheduleFallbackEvidenceAdmissionRetry(runDir);
	}, delayMs);
	timer.unref();
	fallbackEvidenceAdmissionRetryTimers.set(runDir, timer);
}

function noteFallbackEvidenceAdmissionBackpressure(
	runDir: string,
	reason: FallbackEvidenceAdmissionLossReason = "cross_process_cas_transaction_backpressure",
	expectedIdentity?: ServiceRunDirectoryIdentity,
): void {
	const nowMs = Date.now();
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	if (pending) {
		pending.blockedAdmissions = Math.min(Number.MAX_SAFE_INTEGER, pending.blockedAdmissions + 1);
		pending.lastObservedWallTimeMs = nowMs;
		pending.causes[reason] = Math.min(Number.MAX_SAFE_INTEGER, (pending.causes[reason] ?? 0) + 1);
	} else {
		const runIdentity = expectedIdentity ?? fallbackAdmissionRunIdentity(runDir);
		if (!runIdentity) return;
		if (serviceFinalizationNamespaceObserved(runDir)) return;
		const nextPending: FallbackEvidenceAdmissionBackpressure = {
			batchId: randomUUID(),
			runIdentity,
			blockedAdmissions: 1,
			retryAttempts: 0,
			firstObservedWallTimeMs: nowMs,
			lastObservedWallTimeMs: nowMs,
			causes: { [reason]: 1 },
		};
		if (fallbackEvidenceAdmissionBackpressure.size >= FALLBACK_EVIDENCE_ADMISSION_PENDING_LIMIT) {
			throw new FallbackEvidenceAdmissionCapacityError();
		}
		fallbackEvidenceAdmissionBackpressure.set(runDir, nextPending);
	}
	scheduleFallbackEvidenceAdmissionRetry(runDir);
}

function acquireFallbackRunEvidenceAdmission(runDir: string): CasTransaction | undefined {
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	const runIdentity = pending?.runIdentity ?? fallbackAdmissionRunIdentity(runDir);
	if (!runIdentity) return undefined;
	if (pending && !fallbackAdmissionRunIdentityMatches(runDir, runIdentity)) {
		noteFallbackEvidenceAdmissionBackpressure(runDir, "root_detached_pending", runIdentity);
		return undefined;
	}
	for (let attempt = 0; attempt < FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS; attempt += 1) {
		if (!fallbackAdmissionRunIdentityMatches(runDir, runIdentity)) {
			noteFallbackEvidenceAdmissionBackpressure(runDir, "root_detached_pending", runIdentity);
			return undefined;
		}
		const transaction = tryAcquireFallbackRunEvidenceAdmission(runDir, runIdentity);
		if (transaction) {
			if (!fallbackAdmissionRunIdentityMatches(runDir, runIdentity)) {
				transaction.release();
				noteFallbackEvidenceAdmissionBackpressure(runDir, "root_detached_pending", runIdentity);
				return undefined;
			}
			cancelFallbackEvidenceAdmissionRetry(runDir);
			persistFallbackEvidenceAdmissionBackpressure(runDir);
			if (fallbackEvidenceAdmissionBackpressure.has(runDir)) scheduleFallbackEvidenceAdmissionRetry(runDir);
			return transaction;
		}
		if (serviceFinalizationNamespaceObserved(runDir)) return undefined;
		if (attempt + 1 < FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS) {
			Atomics.wait(casTransactionRetryWait, 0, 0, FALLBACK_EVIDENCE_ADMISSION_WAIT_MS);
		}
	}
	noteFallbackEvidenceAdmissionBackpressure(runDir);
	return undefined;
}

function beginProviderReferenceWrite(runDir: string): void {
	pendingProviderReferenceWrites.set(runDir, (pendingProviderReferenceWrites.get(runDir) ?? 0) + 1);
}

function finishProviderReferenceWrite(runDir: string): void {
	const remaining = Math.max(0, (pendingProviderReferenceWrites.get(runDir) ?? 1) - 1);
	if (remaining > 0) {
		pendingProviderReferenceWrites.set(runDir, remaining);
		return;
	}
	pendingProviderReferenceWrites.delete(runDir);
	for (const resolveWaiter of providerReferenceWriteWaiters.get(runDir)?.splice(0) ?? []) resolveWaiter();
	providerReferenceWriteWaiters.delete(runDir);
}

function waitForProviderReferenceWrites(runDir: string): Promise<void> {
	if ((pendingProviderReferenceWrites.get(runDir) ?? 0) === 0) return Promise.resolve();
	return new Promise((resolveWaiter) => {
		const waiters = providerReferenceWriteWaiters.get(runDir) ?? [];
		waiters.push(resolveWaiter);
		providerReferenceWriteWaiters.set(runDir, waiters);
	});
}

interface ServiceRunIdentity {
	runId: string;
	runToken: string;
	targetPid?: number;
	targetProcessStartId?: string;
	disposition: "exact_process_control" | "recovered_after_invalid_discovery_control";
}

interface StoredServiceProcessControl {
	runToken: string;
	machineId?: string;
	bootId?: string;
	systemdInvocationId: string | null;
	pid: number;
	processStartId?: string;
	observed: { wallTime: string; monotonicNs: string };
	runtimeCategory: "node" | "foreign";
	nodeFatalReportsEnabled: boolean;
	orphanPolicy: "fail-open";
	wrapperDeathSignalsSupervisor: false;
}

function storedServiceStoppedObservationRepairIdentity(
	runDir: string,
	runId: string,
): { runId: string; runToken: string } | undefined {
	for (const path of [
		serviceStoppedObservationRepairPath(runDir),
		serviceStoppedObservationRepairWitnessPath(runDir),
	]) {
		const value = readPrivateCanonicalJson<unknown>(path);
		if (
			isRecordObject(value) &&
			hasExactObjectKeys(value, ["schemaVersion", "kind", "runId", "runToken", "reason"]) &&
			value.schemaVersion === 1 &&
			value.kind === "service_stopped_observation_repair" &&
			value.runId === runId &&
			typeof value.runToken === "string" &&
			CANONICAL_UUID.test(value.runToken) &&
			value.reason === "invalid_control_observed"
		) {
			return { runId, runToken: value.runToken };
		}
	}
	return undefined;
}

function serviceRunIdentity(runDir: string): ServiceRunIdentity | undefined {
	const runId = basename(runDir).slice(-36);
	if (!CANONICAL_UUID.test(runId)) return undefined;
	const repair = storedServiceStoppedObservationRepairIdentity(runDir, runId);
	const repairReadback = repair ? storedServiceStoppedObservationRepairIdentity(runDir, runId) : undefined;
	if (repair && canonicalJsonValuesEqual(repairReadback, repair)) {
		const processIdentity = readStableStoredServiceProcessControl(runDir);
		const matchingProcess = processIdentity?.runToken === repair.runToken ? processIdentity : undefined;
		return {
			...repair,
			targetPid: matchingProcess?.pid,
			targetProcessStartId: matchingProcess?.processStartId,
			disposition: "recovered_after_invalid_discovery_control",
		};
	}
	const processIdentity = readStableStoredServiceProcessControl(runDir);
	if (!processIdentity) return undefined;
	const runToken = processIdentity.runToken;
	const expectationPath = join(runDir, "finalization-barrier-expectation.json");
	let expectation: StoredFinalizationBarrierExpectation | undefined;
	if (serviceControlOccupantExists(expectationPath)) {
		expectation = readStableFinalizationBarrierExpectation(runDir);
		if (!expectation || expectation.runId !== runId || expectation.runToken !== runToken) {
			return undefined;
		}
	}
	if (serviceControlOccupantExists(expectationPath) !== (expectation !== undefined)) return undefined;
	return {
		runId,
		runToken,
		targetPid: processIdentity.pid,
		targetProcessStartId: processIdentity.processStartId,
		disposition: "exact_process_control",
	};
}

function serviceRecordDerived(
	runDir: string,
	source: Parameters<IncidentRecorderWriter["recordDerivedForRun"]>[1],
	type: string,
	fields: Record<string, unknown>,
): boolean {
	const runtime = activeServiceRecorder;
	const identity = serviceRunIdentity(runDir);
	if (
		!runtime ||
		!identity ||
		!serviceWriterAdmissionAllowed(runDir, identity) ||
		!runtime.compactor.admitObservation(INCIDENT_RECORDER_DERIVED_OBSERVATION_RESERVATION_BYTES)
	)
		return false;
	return runtime.writer.recordDerivedForRun(identity, source, type, {
		...fields,
		targetPid: identity.targetPid,
		targetProcessStartId: identity.targetProcessStartId,
	}).accepted;
}

function serviceWriterAdmissionAllowed(runDir: string, identity: { runId: string; runToken: string }): boolean {
	if (serviceFinalizationNamespaceObserved(runDir)) {
		adoptPreexistingServiceRunSealWithoutIntent(runDir, identity);
		return false;
	}
	return true;
}

function serviceRecordExactBytes(
	runDir: string,
	identity: ReturnType<typeof serviceRunIdentity>,
	source: Parameters<IncidentRecorderWriter["recordExactBytesForRun"]>[1],
	type: string,
	bytes: Uint8Array,
	encoding: string,
	metadata: Record<string, unknown>,
): ReturnType<IncidentRecorderWriter["recordExactBytesForRun"]> | undefined {
	const runtime = activeServiceRecorder;
	if (
		!runtime ||
		!identity ||
		!serviceWriterAdmissionAllowed(runDir, identity) ||
		!runtime.compactor.admitObservation(bytes.byteLength + 24 * 1024)
	)
		return undefined;
	return runtime.writer.recordExactBytesForRun(identity, source, type, bytes, encoding, metadata);
}

function nowFields(): Pick<IncidentRecorderEvent, "wallTime" | "monotonicNs"> {
	return { wallTime: new Date().toISOString(), monotonicNs: process.hrtime.bigint().toString() };
}

function readBoundedPrefix(path: string, limit: number): BoundedRead | undefined {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "r");
		const chunks: Buffer[] = [];
		let total = 0;
		while (total <= limit) {
			const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, limit + 1 - total));
			const count = readSync(descriptor, chunk, 0, chunk.length, null);
			if (count === 0) break;
			chunks.push(chunk.subarray(0, count));
			total += count;
		}
		const combined = Buffer.concat(chunks, total);
		return { value: combined.subarray(0, limit), truncated: combined.length > limit };
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

type InstallerUnitReadResult =
	| { state: "missing" }
	| { state: "read"; bounded: BoundedRead }
	| { state: "unsafe"; message: string };

/** Read an existing unit without following or blocking on an unsafe target. */
function readInstallerUnitBoundedPrefix(path: string, limit: number): InstallerUnitReadResult {
	let descriptor: number | undefined;
	let pathExisted = false;
	try {
		const pathStats = lstatSync(path, { bigint: true });
		pathExisted = true;
		if (!pathStats.isFile()) {
			return {
				state: "unsafe",
				message: `existing incident recorder unit is not a regular file: ${path}`,
			};
		}
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOFOLLOW);
		const descriptorStats = fstatSync(descriptor, { bigint: true });
		if (!descriptorStats.isFile()) {
			return {
				state: "unsafe",
				message: `existing incident recorder unit changed to a non-regular file: ${path}`,
			};
		}
		if (descriptorStats.dev !== pathStats.dev || descriptorStats.ino !== pathStats.ino) {
			return {
				state: "unsafe",
				message: `existing incident recorder unit changed while being read: ${path}`,
			};
		}
		const chunks: Buffer[] = [];
		let total = 0;
		while (total <= limit) {
			const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, limit + 1 - total));
			const count = readSync(descriptor, chunk, 0, chunk.length, null);
			if (count === 0) break;
			chunks.push(chunk.subarray(0, count));
			total += count;
		}
		const combined = Buffer.concat(chunks, total);
		return { state: "read", bounded: { value: combined.subarray(0, limit), truncated: combined.length > limit } };
	} catch (error) {
		if (!pathExisted && (error as NodeJS.ErrnoException).code === "ENOENT") return { state: "missing" };
		return {
			state: "unsafe",
			message: `unable to safely read existing incident recorder unit: ${path}`,
		};
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function readSmallJson<T>(path: string, limit = INCIDENT_RECORDER_LIMITS.evidenceFileBytes): T | undefined {
	try {
		const bounded = readBoundedPrefix(path, limit);
		if (!bounded || bounded.truncated) return undefined;
		return JSON.parse(bounded.value.toString("utf8")) as T;
	} catch {
		return undefined;
	}
}

interface PrivateCanonicalJsonIdentity {
	dev: bigint;
	ino: bigint;
	size: bigint;
	mtimeNs: bigint;
	ctimeNs: bigint;
}

interface PrivateCanonicalJsonRead<T> {
	value: T;
	identity: PrivateCanonicalJsonIdentity;
}

function samePrivateCanonicalJsonIdentity(
	left: PrivateCanonicalJsonIdentity,
	right: PrivateCanonicalJsonIdentity,
): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.size === right.size &&
		left.mtimeNs === right.mtimeNs &&
		left.ctimeNs === right.ctimeNs
	);
}

function readPrivateSerializedJsonWithIdentity<T>(
	path: string,
	serialize: (value: T) => string,
	limit = 64 * 1024,
): PrivateCanonicalJsonRead<T> | undefined {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const before = fstatSync(descriptor, { bigint: true });
		if (
			!before.isFile() ||
			before.isSymbolicLink() ||
			before.nlink !== 1n ||
			before.size <= 0n ||
			before.size > BigInt(limit) ||
			(typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) ||
			(before.mode & 0o077n) !== 0n
		) {
			return undefined;
		}
		const bytes = Buffer.alloc(Number(before.size));
		let offset = 0;
		while (offset < bytes.length) {
			const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
			if (count <= 0) return undefined;
			offset += count;
		}
		const after = fstatSync(descriptor, { bigint: true });
		if (
			after.dev !== before.dev ||
			after.ino !== before.ino ||
			after.size !== before.size ||
			after.mtimeNs !== before.mtimeNs ||
			after.ctimeNs !== before.ctimeNs
		) {
			return undefined;
		}
		const value = JSON.parse(bytes.toString("utf8")) as T;
		const pathname = lstatSync(path, { bigint: true });
		if (
			!pathname.isFile() ||
			pathname.isSymbolicLink() ||
			pathname.nlink !== 1n ||
			pathname.dev !== after.dev ||
			pathname.ino !== after.ino ||
			pathname.size !== after.size ||
			pathname.mtimeNs !== after.mtimeNs ||
			pathname.ctimeNs !== after.ctimeNs ||
			(typeof process.getuid === "function" && pathname.uid !== BigInt(process.getuid())) ||
			(pathname.mode & 0o077n) !== 0n
		) {
			return undefined;
		}
		return Buffer.from(serialize(value)).equals(bytes)
			? {
					value,
					identity: {
						dev: after.dev,
						ino: after.ino,
						size: after.size,
						mtimeNs: after.mtimeNs,
						ctimeNs: after.ctimeNs,
					},
				}
			: undefined;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function readPrivateSerializedJson<T>(path: string, serialize: (value: T) => string, limit = 64 * 1024): T | undefined {
	return readPrivateSerializedJsonWithIdentity(path, serialize, limit)?.value;
}

function readPrivateCanonicalJson<T>(path: string, limit = 64 * 1024): T | undefined {
	return readPrivateSerializedJson(path, (value) => `${JSON.stringify(value)}\n`, limit);
}

function readPrivateCanonicalControlJsonWithIdentity<T>(
	path: string,
	limit = 64 * 1024,
): PrivateCanonicalJsonRead<T> | undefined {
	return (
		readPrivateSerializedJsonWithIdentity<T>(path, (value) => `${JSON.stringify(value)}\n`, limit) ??
		readPrivateSerializedJsonWithIdentity<T>(path, (value) => `${JSON.stringify(value, null, 2)}\n`, limit)
	);
}

function validServiceControlTimestamp(value: unknown): value is { wallTime: string; monotonicNs: string } {
	if (
		!isRecordObject(value) ||
		!hasExactObjectKeys(value, ["wallTime", "monotonicNs"]) ||
		typeof value.wallTime !== "string" ||
		typeof value.monotonicNs !== "string" ||
		!/^(?:0|[1-9][0-9]{0,29})$/.test(value.monotonicNs)
	) {
		return false;
	}
	const parsedWallTime = Date.parse(value.wallTime);
	return Number.isFinite(parsedWallTime) && new Date(parsedWallTime).toISOString() === value.wallTime;
}

function validStoredServiceProcessControl(value: unknown): value is StoredServiceProcessControl {
	if (!isRecordObject(value)) return false;
	const optionalKeys = [
		...(value.machineId === undefined ? [] : ["machineId"]),
		...(value.bootId === undefined ? [] : ["bootId"]),
		...(value.processStartId === undefined ? [] : ["processStartId"]),
	];
	if (
		!hasExactObjectKeys(value, [
			"runToken",
			"systemdInvocationId",
			"pid",
			"observed",
			"runtimeCategory",
			"nodeFatalReportsEnabled",
			"orphanPolicy",
			"wrapperDeathSignalsSupervisor",
			...optionalKeys,
		]) ||
		typeof value.runToken !== "string" ||
		!CANONICAL_UUID.test(value.runToken) ||
		(value.machineId !== undefined &&
			(typeof value.machineId !== "string" || !/^[0-9a-f]{32}$/.test(value.machineId))) ||
		(value.bootId !== undefined &&
			(typeof value.bootId !== "string" ||
				!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.bootId))) ||
		!(
			value.systemdInvocationId === null ||
			(typeof value.systemdInvocationId === "string" &&
				Buffer.byteLength(value.systemdInvocationId, "utf8") <= 4 * 1024)
		) ||
		!Number.isSafeInteger(value.pid) ||
		Number(value.pid) <= 0 ||
		(value.processStartId !== undefined && safeProcessStartId(value.processStartId) === undefined) ||
		!validServiceControlTimestamp(value.observed) ||
		!(value.runtimeCategory === "node" || value.runtimeCategory === "foreign") ||
		typeof value.nodeFatalReportsEnabled !== "boolean" ||
		(value.runtimeCategory === "node") !== value.nodeFatalReportsEnabled ||
		value.orphanPolicy !== "fail-open" ||
		value.wrapperDeathSignalsSupervisor !== false
	) {
		return false;
	}
	return true;
}

function readStoredServiceProcessControlSnapshot(
	runDir: string,
): PrivateCanonicalJsonRead<StoredServiceProcessControl> | undefined {
	const snapshot = readPrivateCanonicalControlJsonWithIdentity<unknown>(join(runDir, "process.json"));
	return snapshot && validStoredServiceProcessControl(snapshot.value)
		? (snapshot as PrivateCanonicalJsonRead<StoredServiceProcessControl>)
		: undefined;
}

function readStableStoredServiceProcessControl(runDir: string): StoredServiceProcessControl | undefined {
	const first = readStoredServiceProcessControlSnapshot(runDir);
	if (!first) return undefined;
	const second = readStoredServiceProcessControlSnapshot(runDir);
	return second &&
		canonicalJsonValuesEqual(first.value, second.value) &&
		samePrivateCanonicalJsonIdentity(first.identity, second.identity)
		? first.value
		: undefined;
}

interface StoredServiceLaunchControl {
	version: 2;
	canonical: false;
	purpose: "content-addressed-launch-index";
	socketPath: string;
	runtimeCategory: "node" | "bun" | "foreign";
	nodeFatalReportsEnabled: boolean;
	launchArtifact: Record<string, unknown>;
	derivedCommandSummary: IncidentCommandSummary;
}

function validIncidentCommandSummary(value: unknown): value is IncidentCommandSummary {
	return (
		isRecordObject(value) &&
		hasExactObjectKeys(value, [
			"argumentCount",
			"flagCategories",
			"positionalCount",
			"redactedValueCount",
			"nulSeparated",
		]) &&
		Number.isSafeInteger(value.argumentCount) &&
		Number(value.argumentCount) >= 0 &&
		Array.isArray(value.flagCategories) &&
		value.flagCategories.length <= 64 &&
		new Set(value.flagCategories).size === value.flagCategories.length &&
		value.flagCategories.every(
			(entry) =>
				typeof entry === "string" && ["sensitive", "node_report", "daemon_control", "other_flag"].includes(entry),
		) &&
		Number.isSafeInteger(value.positionalCount) &&
		Number(value.positionalCount) >= 0 &&
		Number(value.positionalCount) <= Number(value.argumentCount) &&
		Number.isSafeInteger(value.redactedValueCount) &&
		Number(value.redactedValueCount) >= 0 &&
		Number(value.redactedValueCount) <= Number(value.argumentCount) &&
		typeof value.nulSeparated === "boolean"
	);
}

function validServiceLaunchArtifact(value: unknown): value is Record<string, unknown> {
	if (!isRecordObject(value)) return false;
	const hasOccurrence = value.producerOccurrenceId !== undefined;
	return (
		hasExactObjectKeys(value, [
			"canonical",
			"encoding",
			...(hasOccurrence ? ["producerOccurrenceId"] : []),
			"state",
			"orphanPolicy",
			"lifecycleTarget",
		]) &&
		value.canonical === false &&
		value.encoding === "derived-diagnostic-json-v1" &&
		(!hasOccurrence ||
			(typeof value.producerOccurrenceId === "string" && CANONICAL_UUID.test(value.producerOccurrenceId))) &&
		(value.state === "locally-admitted-pending-compactor" || value.state === "relay-rejected") &&
		(hasOccurrence ? value.state === "locally-admitted-pending-compactor" : value.state === "relay-rejected") &&
		value.orphanPolicy === "fail-open" &&
		value.lifecycleTarget === "real-supervisor-identity"
	);
}

function validStoredServiceLaunchControl(value: unknown): value is StoredServiceLaunchControl {
	return (
		isRecordObject(value) &&
		hasExactObjectKeys(value, [
			"version",
			"canonical",
			"purpose",
			"socketPath",
			"runtimeCategory",
			"nodeFatalReportsEnabled",
			"launchArtifact",
			"derivedCommandSummary",
		]) &&
		value.version === 2 &&
		value.canonical === false &&
		value.purpose === "content-addressed-launch-index" &&
		typeof value.socketPath === "string" &&
		isAbsolute(value.socketPath) &&
		Buffer.byteLength(value.socketPath, "utf8") > 0 &&
		Buffer.byteLength(value.socketPath, "utf8") <= 4 * 1024 &&
		(value.runtimeCategory === "node" || value.runtimeCategory === "bun" || value.runtimeCategory === "foreign") &&
		typeof value.nodeFatalReportsEnabled === "boolean" &&
		(value.runtimeCategory === "node") === value.nodeFatalReportsEnabled &&
		validServiceLaunchArtifact(value.launchArtifact) &&
		validIncidentCommandSummary(value.derivedCommandSummary)
	);
}

function readStoredServiceLaunchControlSnapshot(
	runDir: string,
): PrivateCanonicalJsonRead<StoredServiceLaunchControl> | undefined {
	const snapshot = readPrivateCanonicalControlJsonWithIdentity<unknown>(join(runDir, "launch.json"));
	return snapshot && validStoredServiceLaunchControl(snapshot.value)
		? (snapshot as PrivateCanonicalJsonRead<StoredServiceLaunchControl>)
		: undefined;
}

function readStableStoredServiceLaunchControl(runDir: string): StoredServiceLaunchControl | undefined {
	const first = readStoredServiceLaunchControlSnapshot(runDir);
	if (!first) return undefined;
	const second = readStoredServiceLaunchControlSnapshot(runDir);
	return second &&
		canonicalJsonValuesEqual(first.value, second.value) &&
		samePrivateCanonicalJsonIdentity(first.identity, second.identity)
		? first.value
		: undefined;
}

interface StoredServiceActiveMarkerControl {
	role: "wrapper-proxy";
	machineId?: string;
	bootId?: string;
	pid: number;
	processStartId?: string;
	created: { wallTime: string; monotonicNs: string };
}

function validStoredServiceActiveMarkerControl(value: unknown): value is StoredServiceActiveMarkerControl {
	if (!isRecordObject(value)) return false;
	const optionalKeys = [
		...(value.machineId === undefined ? [] : ["machineId"]),
		...(value.bootId === undefined ? [] : ["bootId"]),
		...(value.processStartId === undefined ? [] : ["processStartId"]),
	];
	return (
		hasExactObjectKeys(value, ["role", "pid", "created", ...optionalKeys]) &&
		value.role === "wrapper-proxy" &&
		(value.machineId === undefined ||
			(typeof value.machineId === "string" && /^[0-9a-f]{32}$/.test(value.machineId))) &&
		(value.bootId === undefined ||
			(typeof value.bootId === "string" &&
				/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.bootId))) &&
		Number.isSafeInteger(value.pid) &&
		Number(value.pid) > 0 &&
		(value.processStartId === undefined || safeProcessStartId(value.processStartId) !== undefined) &&
		validServiceControlTimestamp(value.created)
	);
}

function readStoredServiceActiveMarkerControlSnapshot(
	runDir: string,
): PrivateCanonicalJsonRead<StoredServiceActiveMarkerControl> | undefined {
	const snapshot = readPrivateCanonicalControlJsonWithIdentity<unknown>(join(runDir, ACTIVE_MARKER_FILE_NAME));
	return snapshot && validStoredServiceActiveMarkerControl(snapshot.value)
		? (snapshot as PrivateCanonicalJsonRead<StoredServiceActiveMarkerControl>)
		: undefined;
}

function serviceControlOccupantExists(path: string): boolean {
	try {
		lstatSync(path);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code !== "ENOENT";
	}
}

function serviceControlPathWithinRun(runDir: string, path: string): boolean {
	return resolve(path).startsWith(`${resolve(runDir)}${sep}`);
}

function quarantineInvalidServiceControl(runDir: string, path: string, label: string): boolean {
	if (!serviceControlPathWithinRun(runDir, path)) return false;
	const directoryIdentity = privateServiceRunDirectoryIdentity(runDir);
	if (!directoryIdentity) return false;
	const quarantineDirectory = join(runDir, ".service-control-quarantine");
	try {
		try {
			mkdirSync(quarantineDirectory, { mode: 0o700 });
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") return false;
		}
		if (
			!currentServiceRunDirectory(runDir, directoryIdentity) ||
			!privateServiceRunDirectoryIdentity(quarantineDirectory)
		) {
			return false;
		}
		const target = join(quarantineDirectory, `${label}-${randomUUID()}.invalid`);
		renameSync(path, target);
		if (!currentServiceRunDirectory(runDir, directoryIdentity)) return false;
		for (const directory of [quarantineDirectory, runDir]) {
			let descriptor: number | undefined;
			try {
				descriptor = openSync(directory, fsConstants.O_RDONLY);
				fsyncSync(descriptor);
			} finally {
				if (descriptor !== undefined) closeSync(descriptor);
			}
		}
		return true;
	} catch {
		return false;
	}
}

function persistExactCanonicalServiceControl(runDir: string, path: string, label: string, value: unknown): boolean {
	const directoryIdentity = privateServiceRunDirectoryIdentity(runDir);
	if (!directoryIdentity || !serviceControlPathWithinRun(runDir, path)) return false;
	for (let attempt = 0; attempt < 2; attempt += 1) {
		if (!currentServiceRunDirectory(runDir, directoryIdentity)) return false;
		const existing = readPrivateCanonicalJson<unknown>(path);
		if (existing !== undefined && canonicalJsonValuesEqual(existing, value)) return true;
		if (serviceControlOccupantExists(path) && !quarantineInvalidServiceControl(runDir, path, label)) return false;
		if (!currentServiceRunDirectory(runDir, directoryIdentity)) return false;
		const persisted = persistIncidentFinalizationSeal({ path, value });
		if (persisted.state === "applied" || persisted.state === "noop") {
			const readback = readPrivateCanonicalJson<unknown>(path);
			if (readback !== undefined && canonicalJsonValuesEqual(readback, value)) return true;
		}
	}
	return false;
}

function writePrivateJson(path: string, value: unknown, _limit = INCIDENT_RECORDER_LIMITS.evidenceFileBytes): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	let serialized: string;
	try {
		serialized = `${JSON.stringify(value, null, 2)}\n`;
	} catch (error) {
		serialized = `${JSON.stringify({ unavailable: true, serializationError: serializeError(error) }, null, 2)}\n`;
	}
	writeFileSync(path, serialized, { mode: 0o600 });
	chmodSync(path, 0o600);
}

function writePrivateJsonAtomicSync(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
	let descriptor: number | undefined;
	try {
		descriptor = openSync(temporary, "wx", 0o600);
		writeSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
		fsyncSync(descriptor);
		closeSync(descriptor);
		descriptor = undefined;
		renameSync(temporary, path);
		chmodSync(path, 0o600);
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
		try {
			rmSync(temporary, { force: true });
		} catch {}
	}
}

function fsyncPrivateDirectorySync(path: string): void {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
		fsyncSync(descriptor);
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function safeToken(value: unknown, fallback = "other"): string {
	return typeof value === "string" && /^[A-Za-z0-9_.:+-]{1,80}$/.test(value) ? value : fallback;
}

function finiteNumber(value: unknown): number | undefined {
	return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function serializeError(error: unknown, seen = new Map<object, number>()): Record<string, unknown> {
	if (!(error instanceof Error)) return { thrown: encodeDiagnosticValue(error, seen) };
	const ownProperties: Record<string, unknown> = {};
	for (const key of Reflect.ownKeys(error)) {
		const descriptor = Object.getOwnPropertyDescriptor(error, key);
		const name = typeof key === "symbol" ? key.toString() : key;
		if (descriptor && "value" in descriptor) ownProperties[name] = encodeDiagnosticValue(descriptor.value, seen);
	}
	return {
		name: error.name,
		message: error.message,
		stack: error.stack,
		cause: encodeDiagnosticValue(error.cause, seen),
		ownProperties,
	};
}

function encodeDiagnosticValue(value: unknown, seen = new Map<object, number>()): unknown {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") {
		return Number.isFinite(value) ? value : { $diagnosticType: "number", value: String(value) };
	}
	if (typeof value === "undefined") return { $diagnosticType: "undefined" };
	if (typeof value === "bigint") return { $diagnosticType: "bigint", value: value.toString() };
	if (typeof value === "symbol") return { $diagnosticType: "symbol", value: value.description };
	if (typeof value === "function") {
		return {
			$diagnosticType: "function",
			name: value.name,
			length: value.length,
			source: Function.prototype.toString.call(value),
		};
	}
	if (seen.has(value)) return { $diagnosticType: "reference", id: seen.get(value) };
	const id = seen.size + 1;
	seen.set(value, id);
	if (Buffer.isBuffer(value)) {
		return { $diagnosticType: "buffer", id, encoding: "base64", value: value.toString("base64") };
	}
	if (value instanceof Uint8Array) {
		return {
			$diagnosticType: "uint8array",
			id,
			encoding: "base64",
			value: Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("base64"),
		};
	}
	if (value instanceof Date) return { $diagnosticType: "date", id, value: value.toISOString() };
	if (value instanceof RegExp) return { $diagnosticType: "regexp", id, source: value.source, flags: value.flags };
	if (value instanceof Error) return { $diagnosticType: "error", id, ...serializeError(value, seen) };
	if (value instanceof Map) {
		return {
			$diagnosticType: "map",
			id,
			entries: [...value.entries()].map(([key, child]) => [
				encodeDiagnosticValue(key, seen),
				encodeDiagnosticValue(child, seen),
			]),
		};
	}
	if (value instanceof Set) {
		return { $diagnosticType: "set", id, values: [...value].map((child) => encodeDiagnosticValue(child, seen)) };
	}
	const properties = Reflect.ownKeys(value).map((key) => {
		const descriptor = Object.getOwnPropertyDescriptor(value, key);
		const encodedKey =
			typeof key === "symbol" ? { type: "symbol", value: key.description } : { type: "string", value: key };
		if (!descriptor) return { key: encodedKey, unavailable: true };
		return {
			key: encodedKey,
			enumerable: descriptor.enumerable,
			configurable: descriptor.configurable,
			...(descriptor.get || descriptor.set
				? {
						get: descriptor.get ? Function.prototype.toString.call(descriptor.get) : undefined,
						set: descriptor.set ? Function.prototype.toString.call(descriptor.set) : undefined,
					}
				: { writable: descriptor.writable, value: encodeDiagnosticValue(descriptor.value, seen) }),
		};
	});
	return {
		$diagnosticType: Array.isArray(value) ? "array" : "object",
		id,
		prototype: Object.getPrototypeOf(value)?.constructor?.name,
		properties,
	};
}

function decodeDiagnosticValue(value: unknown, references = new Map<number, unknown>()): unknown {
	if (!value || typeof value !== "object") return value;
	const encoded = value as Record<string, unknown>;
	const type = encoded.$diagnosticType;
	if (type === "undefined") return undefined;
	if (type === "bigint") return typeof encoded.value === "string" ? BigInt(encoded.value) : undefined;
	if (type === "number") return Number(encoded.value);
	if (type === "buffer" || type === "uint8array") {
		return typeof encoded.value === "string" ? Buffer.from(encoded.value, "base64") : Buffer.alloc(0);
	}
	if (type === "date") return encoded.value;
	if (type === "regexp" || type === "function" || type === "symbol") return encoded;
	if (type === "reference") return typeof encoded.id === "number" ? references.get(encoded.id) : undefined;
	if (type === "error") {
		const decoded = {
			name: encoded.name,
			message: encoded.message,
			stack: encoded.stack,
			cause: decodeDiagnosticValue(encoded.cause, references),
			ownProperties: decodeDiagnosticValue(encoded.ownProperties, references),
		};
		if (typeof encoded.id === "number") references.set(encoded.id, decoded);
		return decoded;
	}
	if (type !== "object" && type !== "array" && type !== "map" && type !== "set") {
		const result: Record<string, unknown> = {};
		for (const [key, child] of Object.entries(encoded)) result[key] = decodeDiagnosticValue(child, references);
		return result;
	}
	if (type === "map") {
		const result: unknown[] = [];
		if (typeof encoded.id === "number") references.set(encoded.id, result);
		for (const entry of Array.isArray(encoded.entries) ? encoded.entries : []) {
			if (Array.isArray(entry)) result.push(entry.map((child) => decodeDiagnosticValue(child, references)));
		}
		return result;
	}
	if (type === "set") {
		const result: unknown[] = [];
		if (typeof encoded.id === "number") references.set(encoded.id, result);
		for (const child of Array.isArray(encoded.values) ? encoded.values : []) {
			result.push(decodeDiagnosticValue(child, references));
		}
		return result;
	}
	const result: Record<string, unknown> | unknown[] = type === "array" ? [] : {};
	if (typeof encoded.id === "number") references.set(encoded.id, result);
	for (const property of Array.isArray(encoded.properties) ? encoded.properties : []) {
		if (!property || typeof property !== "object") continue;
		const item = property as Record<string, unknown>;
		const key = item.key as { type?: unknown; value?: unknown } | undefined;
		if (key?.type !== "string" || typeof key.value !== "string" || !("value" in item)) continue;
		(result as Record<string, unknown>)[key.value] = decodeDiagnosticValue(item.value, references);
	}
	return result;
}

function rawSourceDirectory(runDir: string, source: RawApplicationSource): string {
	return join(runDir, RAW_APPLICATION_DIR_NAME, source);
}

function rawSegmentPath(state: RawSegmentState): string {
	return join(state.directory, `segment-${String(state.segmentIndex).padStart(8, "0")}.jsonl`);
}

function loadRawSegmentState(runDir: string, source: RawApplicationSource): RawSegmentState {
	const key = `${runDir}\0${source}`;
	const existing = rawSegmentStates.get(key);
	if (existing) return existing;
	const directory = rawSourceDirectory(runDir, source);
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	chmodSync(directory, 0o700);
	const indexes = readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		const match = entry.isFile() ? entry.name.match(/^segment-(\d{8})\.jsonl$/) : undefined;
		return match ? [Number(match[1])] : [];
	});
	const segmentIndex = indexes.length > 0 ? Math.max(...indexes) : 0;
	let segmentBytes = 0;
	let segmentOpenedMs = Date.now();
	try {
		const stat = statSync(join(directory, `segment-${String(segmentIndex).padStart(8, "0")}.jsonl`));
		segmentBytes = stat.size;
		segmentOpenedMs = stat.birthtimeMs || stat.mtimeMs;
	} catch {}
	const state: RawSegmentState = {
		runDir,
		source,
		directory,
		segmentIndex,
		segmentBytes,
		segmentOpenedMs,
	};
	rawSegmentStates.set(key, state);
	return state;
}

function writeRawSegmentManifestSync(state: RawSegmentState): void {
	const segments = readdirSync(state.directory, { withFileTypes: true })
		.filter((entry) => entry.isFile() && /^segment-\d{8}\.jsonl$/.test(entry.name))
		.map((entry) => {
			const stat = statSync(join(state.directory, entry.name));
			return { file: entry.name, bytes: stat.size, mode: stat.mode & 0o777, mtimeMs: stat.mtimeMs };
		});
	writePrivateJsonAtomicSync(join(state.directory, "manifest.json"), {
		schemaVersion: 1,
		source: state.source,
		canonical: false,
		encoding: "json-lines/base64-chunked-utf8-json",
		rotation: { bytes: INCIDENT_RECORDER_LIMITS.rawSegmentBytes, milliseconds: RAW_SEGMENT_ROTATION_MS },
		checkpointMilliseconds: RAW_MANIFEST_CHECKPOINT_MS,
		segments,
		updated: nowFields(),
	});
}

interface RawBlobReference {
	algorithm: "sha256" | "journald-occurrence";
	digest?: string;
	bytes: number;
	path: string;
	collisionFallbackPath: string;
	encoding: string;
	compression?: "gzip";
	storedBytes?: number;
	rootRelativePath?: string;
	referenceKind?: "cas" | "ordered-occurrence-admission";
	producerOccurrenceId?: string;
	pending?: boolean;
	admissionDisposition?: "locally_admitted" | "rejected";
	durability?: "pending_compactor_cas_resolution" | "not_admitted";
}

function ensureRawBlobDirectory(directory: string): void {
	if (knownRawBlobDirectories.has(directory)) return;
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	chmodSync(directory, 0o700);
	knownRawBlobDirectories.add(directory);
}

function leaseRunRawBlob(runDir: string, sourcePath: string): void {
	const directory = join(runDir, ".cas-leases");
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	const target = join(directory, basename(sourcePath));
	try {
		linkSync(sourcePath, target);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
		const source = lstatSync(sourcePath);
		const existing = lstatSync(target);
		if (
			!source.isFile() ||
			source.isSymbolicLink() ||
			!existing.isFile() ||
			existing.isSymbolicLink() ||
			source.dev !== existing.dev ||
			source.ino !== existing.ino
		)
			throw new Error("CAS lease collision");
	}
}

function globalRawBlobDirectory(runDir: string, digest: string): string {
	return join(dirname(dirname(runDir)), "cas", "sha256", digest.slice(0, 2));
}

function contentAddressRawBytes(
	runDir: string,
	source: RawApplicationSource,
	value: Uint8Array,
	encoding: string,
): RawBlobReference {
	// Publish no path-only reference until its run-owned hard-link lease exists.
	// The fallback path is bounded to one occurrence and this synchronous commit
	// closes the cross-process GC race that the former queued write allowed.
	return contentAddressRawBytesLegacySync(runDir, source, value, encoding);
}

function contentAddressRawBytesLegacySync(
	runDir: string,
	source: RawApplicationSource,
	value: Uint8Array,
	encoding: string,
): RawBlobReference {
	if (serviceFinalizationNamespaceObserved(runDir)) throw new Error("Run evidence namespace is durably fenced");
	const transaction = acquireIncidentCasTransaction(dirname(dirname(runDir)));
	if (!transaction) throw new Error("Incident CAS transaction unavailable");
	if (serviceFinalizationNamespaceObserved(runDir)) {
		transaction.release();
		throw new Error("Run evidence namespace is durably fenced");
	}
	const bytes = Buffer.from(value);
	const digest = createHash("sha256").update(bytes).digest("hex");
	const directory = globalRawBlobDirectory(runDir, digest);
	ensureRawBlobDirectory(directory);
	const path = join(directory, `${digest}.blob`);
	const collisionFallbackPath = join(directory, `${digest}.collision-${process.pid}-${randomUUID()}.blob`);
	const temporary = join(directory, `.${digest}.tmp-${process.pid}-${randomUUID()}`);
	let descriptor: number | undefined;
	try {
		descriptor = openSync(temporary, "wx", 0o600);
		writeSync(descriptor, bytes);
		fsyncSync(descriptor);
		closeSync(descriptor);
		descriptor = undefined;
		try {
			linkSync(temporary, path);
			chmodSync(path, 0o600);
			rmSync(temporary, { force: true });
		} catch (linkError) {
			if ((linkError as NodeJS.ErrnoException).code !== "EEXIST") throw linkError;
			const existing = readFileSync(path);
			if (existing.length === bytes.length && existing.equals(bytes)) {
				rmSync(temporary, { force: true });
			} else {
				renameSync(temporary, collisionFallbackPath);
				chmodSync(collisionFallbackPath, 0o600);
				if (source !== "loss-accounting") {
					recordRawLoss(
						runDir,
						source,
						{
							name: "RawContentAddressCollisionError",
							message: "Existing SHA-256 blob did not match the captured bytes",
							digest,
							path,
							collisionFallbackPath,
						},
						bytes.length,
					);
				}
			}
		}
		const leasePath = existsSync(collisionFallbackPath) ? collisionFallbackPath : path;
		leaseRunRawBlob(runDir, leasePath);
	} catch (error) {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
		try {
			rmSync(temporary, { force: true });
		} catch {}
		if (source !== "loss-accounting") recordRawLoss(runDir, source, error, bytes.length);
		throw error;
	} finally {
		transaction.release();
	}
	return { algorithm: "sha256", digest, bytes: bytes.length, path, collisionFallbackPath, encoding };
}

function recordLinuxRawSource(runDir: string, occurrence: LinuxRawSourceOccurrence, durable = false): RawBlobReference {
	const rawSource: RawApplicationSource =
		occurrence.source === "system-journal-export" || occurrence.source === "journal-query-error"
			? "linux-journal-source"
			: "linux-raw-source";
	const rejected = (): RawBlobReference => ({
		algorithm: "journald-occurrence",
		bytes: occurrence.bytes.byteLength,
		path: runDir,
		collisionFallbackPath: runDir,
		encoding: occurrence.encoding,
		referenceKind: "ordered-occurrence-admission",
		pending: false,
		admissionDisposition: "rejected",
		durability: "not_admitted",
	});
	if (serviceFinalizationNamespaceObserved(runDir)) return rejected();
	const orderedWriter = orderedWriterForRun(runDir);
	if (orderedWriter) {
		if (serviceFinalizationNamespaceObserved(runDir)) return rejected();
		const admission = orderedWriter.recordExactBytes(
			rawSource,
			"linux_raw_source_occurrence",
			occurrence.bytes,
			occurrence.encoding,
			{
				source: occurrence.source,
				sourcePath: occurrence.sourcePath,
				phase: occurrence.phase,
				observedWallTime: occurrence.wallTime,
				observedMonotonicNs: occurrence.monotonicNs,
				identity: occurrence.identity,
				bounds: occurrence.bounds,
			},
		);
		return {
			algorithm: "journald-occurrence",
			bytes: occurrence.bytes.byteLength,
			path: runDir,
			collisionFallbackPath: runDir,
			encoding: occurrence.encoding,
			referenceKind: "ordered-occurrence-admission",
			producerOccurrenceId: admission.accepted ? admission.occurrenceId : undefined,
			pending: admission.accepted,
			admissionDisposition: admission.accepted ? "locally_admitted" : "rejected",
			durability: admission.accepted ? "pending_compactor_cas_resolution" : "not_admitted",
		};
	}
	const service = activeServiceRecorder;
	const serviceIdentity = serviceRunIdentity(runDir);
	if (service) {
		const admission = serviceRecordExactBytes(
			runDir,
			serviceIdentity,
			rawSource,
			"linux_raw_source_occurrence",
			occurrence.bytes,
			occurrence.encoding,
			{
				source: occurrence.source,
				sourcePath: occurrence.sourcePath,
				phase: occurrence.phase,
				observedWallTime: occurrence.wallTime,
				observedMonotonicNs: occurrence.monotonicNs,
				targetPid: serviceIdentity?.targetPid,
				targetProcessStartId: serviceIdentity?.targetProcessStartId,
			},
		);
		return {
			algorithm: "journald-occurrence",
			bytes: occurrence.bytes.byteLength,
			path: runDir,
			collisionFallbackPath: runDir,
			encoding: occurrence.encoding,
			referenceKind: "ordered-occurrence-admission",
			producerOccurrenceId: admission?.accepted ? admission.occurrenceId : undefined,
			pending: admission?.accepted === true,
			admissionDisposition: admission?.accepted ? "locally_admitted" : "rejected",
			durability: admission?.accepted ? "pending_compactor_cas_resolution" : "not_admitted",
		};
	}
	const transaction = acquireFallbackRunEvidenceAdmission(runDir);
	if (!transaction) return rejected();
	try {
		const payloadBlob = durable
			? contentAddressRawBytesLegacySync(runDir, rawSource, occurrence.bytes, occurrence.encoding)
			: contentAddressRawBytes(runDir, rawSource, occurrence.bytes, occurrence.encoding);
		const fields = {
			source: occurrence.source,
			sourcePath: occurrence.sourcePath,
			phase: occurrence.phase,
			observedWallTime: occurrence.wallTime,
			observedMonotonicNs: occurrence.monotonicNs,
			identity: occurrence.identity,
			bounds: occurrence.bounds,
			payloadBlob,
		};
		writeRawLinesFullySync(
			loadRawSegmentState(runDir, rawSource),
			serializeRawRecord(runDir, rawSource, "linux_raw_source_occurrence", fields, true),
		);
		return payloadBlob;
	} finally {
		transaction.release();
	}
}

function serializeRawRecord(
	runDir: string,
	source: RawApplicationSource,
	type: string,
	fields: Record<string, unknown>,
	durable = false,
): string[] {
	const timestamp = nowFields();
	const sequence = ++rawRecordSequence;
	const recordId = `${process.pid}:${sequence}:${randomUUID()}`;
	const payloadBytes = Buffer.from(JSON.stringify(encodeDiagnosticValue(fields)), "utf8");
	const payloadBlob = durable
		? contentAddressRawBytesLegacySync(runDir, source, payloadBytes, "utf8-json/derived-diagnostic-json-v1")
		: contentAddressRawBytes(runDir, source, payloadBytes, "utf8-json/derived-diagnostic-json-v1");
	const envelope = {
		schemaVersion: RAW_RECORD_SCHEMA_VERSION,
		recordId,
		sequence,
		...timestamp,
		pid: process.pid,
		processStartId: getProcessStartId(process.pid),
		type,
		provenance: {
			source,
			capture: "private-local-derived-diagnostic",
			canonical: false,
			preservesObjectGraphIdentity: false,
			preservesRuntimeObjectIdentity: false,
			valueEncoding: "derived-diagnostic-json-v1",
			characterEncoding: "utf-8",
			frameEncoding: "json-lines/base64",
			executable: process.execPath,
			argv: [...process.argv],
			cwd: process.cwd(),
			runtime: {
				release: process.release,
				versions: process.versions,
				platform: process.platform,
				arch: process.arch,
			},
		},
		payloadBlob,
	};
	const serialized = Buffer.from(JSON.stringify(envelope), "utf8");
	const chunkCount = Math.max(1, Math.ceil(serialized.length / RAW_FRAME_PAYLOAD_BYTES));
	const lines: string[] = [];
	for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
		const frame: RawRecordFrame = {
			schemaVersion: 1,
			recordId,
			chunkIndex,
			chunkCount,
			encoding: "base64",
			payload: serialized
				.subarray(chunkIndex * RAW_FRAME_PAYLOAD_BYTES, (chunkIndex + 1) * RAW_FRAME_PAYLOAD_BYTES)
				.toString("base64"),
		};
		lines.push(`${JSON.stringify(frame)}\n`);
	}
	return lines;
}

function recordRawLoss(runDir: string, source: RawApplicationSource, error: unknown, attemptedBytes: number): void {
	if (source === "loss-accounting") return;
	if (serviceFinalizationNamespaceObserved(runDir)) return;
	const orderedWriter = orderedWriterForRun(runDir);
	if (orderedWriter) {
		if (serviceFinalizationNamespaceObserved(runDir)) return;
		orderedWriter.recordDerived("loss-accounting", "raw_capture_loss", {
			source,
			attemptedBytes,
			error: serializeError(error),
		});
		return;
	}
	if (activeServiceRecorder) {
		serviceRecordDerived(runDir, "loss-accounting", "raw_capture_loss", {
			source,
			attemptedBytes,
			error: serializeError(error),
		});
		return;
	}
	const transaction = acquireFallbackRunEvidenceAdmission(runDir);
	if (!transaction) return;
	try {
		if (runHasLiveWriter(runDir)) return;
		writeRawLinesFullySync(
			loadRawSegmentState(runDir, "loss-accounting"),
			serializeRawRecord(
				runDir,
				"loss-accounting",
				"raw_capture_loss",
				{
					source,
					attemptedBytes,
					error: serializeError(error),
				},
				true,
			),
		);
	} catch {
		// The loss counter itself is best effort when the storage path is unavailable.
	} finally {
		transaction.release();
	}
}

function writeRawLinesFullySync(state: RawSegmentState, lines: readonly string[]): void {
	if (serviceFinalizationNamespaceObserved(state.runDir)) throw new Error("Run evidence namespace is durably fenced");
	for (const line of lines) {
		const bytes = Buffer.byteLength(line);
		if (
			state.segmentBytes > 0 &&
			(state.segmentBytes + bytes > INCIDENT_RECORDER_LIMITS.rawSegmentBytes ||
				Date.now() - state.segmentOpenedMs >= RAW_SEGMENT_ROTATION_MS)
		) {
			state.segmentIndex += 1;
			state.segmentBytes = 0;
			state.segmentOpenedMs = Date.now();
			writeRawSegmentManifestSync(state);
		}
		const path = rawSegmentPath(state);
		const descriptor = openSync(path, "a", 0o600);
		try {
			writeSync(descriptor, line);
			fsyncSync(descriptor);
		} finally {
			closeSync(descriptor);
		}
		chmodSync(path, 0o600);
		state.segmentBytes += bytes;
	}
	writeRawSegmentManifestSync(state);
}

function appendRunEvent(runDir: string, event: { type: string; [key: string]: unknown }): void {
	const { type, ...fields } = event;
	if (serviceFinalizationNamespaceObserved(runDir)) return;
	const orderedWriter = orderedWriterForRun(runDir);
	if (orderedWriter) {
		if (serviceFinalizationNamespaceObserved(runDir)) return;
		orderedWriter.recordDerived("recorder-events", type, fields);
		return;
	}
	if (activeServiceRecorder) {
		serviceRecordDerived(runDir, "recorder-events", type, fields);
		return;
	}
	let transaction: CasTransaction | undefined;
	try {
		transaction = acquireFallbackRunEvidenceAdmission(runDir);
		if (!transaction) return;
		writeRawLinesFullySync(
			loadRawSegmentState(runDir, "recorder-events"),
			serializeRawRecord(runDir, "recorder-events", type, fields, true),
		);
	} catch (error) {
		recordRawLoss(runDir, "recorder-events", error, 0);
	} finally {
		transaction?.release();
	}
}

export function appendSupervisorDiagnosticEvent(
	type: string,
	fields: Record<string, unknown> = {},
): IncidentRecorderAdmission | undefined {
	if (nativeDiagnosticsEnabled()) return emitNativeDiagnostic(type, fields);
	const runDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
	if (runDir && serviceFinalizationNamespaceObserved(runDir)) {
		return { accepted: false, disposition: "rejected", reason: "run_identity_sealed" };
	}
	return emitIncidentDerived("supervisor-events", type, fields);
}

export function appendSupervisorDiagnosticBytes(
	type: string,
	value: Uint8Array,
	fields: Record<string, unknown> = {},
): IncidentRecorderAdmission | undefined {
	if (nativeDiagnosticsEnabled()) return emitNativeDiagnostic(type, {
		...fields, bytes: value.subarray(0, 16 * 1024), sourceBytes: value.byteLength,
		sourceTruncated: value.byteLength > 16 * 1024,
	});
	const runDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
	if (runDir && serviceFinalizationNamespaceObserved(runDir)) {
		return { accepted: false, disposition: "rejected", reason: "run_identity_sealed" };
	}
	const source: RawApplicationSource =
		type === "worker_stdout"
			? "worker-stdout"
			: type === "worker_stderr"
				? "worker-stderr"
				: type.startsWith("worker_transport_")
					? "worker-transport"
					: "supervisor-events";
	return emitIncidentBytes(source, type, value, fields);
}

export async function flushSupervisorDiagnosticCapture(): Promise<void> {
	if (nativeDiagnosticsEnabled()) return flushNativeDiagnostics();
	await stopIncidentCaptureEmitter();
}

export function appendKernelDiagnosticCapture(
	event: KernelDiagnosticEvent,
	bridgeCorrelation: Record<string, unknown> = {},
): void {
	if (event.type !== "kernel_unexpected_exit") {
		const { type, ...fields } = event;
		appendSupervisorDiagnosticEvent(type, { ...bridgeCorrelation, ...fields });
		return;
	}

	const { type, stderrTail, stderrBytes, ...fields } = event;
	const retainedBytes = stderrTail?.byteLength ?? 0;
	const correlation: Record<string, unknown> = {
		...bridgeCorrelation,
		...fields,
		// The kernel event type is producer-owned; bridge correlation cannot
		// replace it in either the original capture metadata or its completion.
		type,
		sourceBytes: stderrBytes,
		retainedBytes,
	};
	const exitAdmission = appendSupervisorDiagnosticEvent(type, correlation);
	let tailAdmission: IncidentRecorderAdmission | undefined;
	if (stderrTail && retainedBytes > 0) {
		tailAdmission = appendSupervisorDiagnosticBytes("kernel_stderr_tail", stderrTail, correlation);
	}
	const {
		type: _correlationType,
		exitAdmissionReason: _correlationExitAdmissionReason,
		exitOccurrenceId: _correlationExitOccurrenceId,
		tailAdmissionReason: _correlationTailAdmissionReason,
		tailCaptureStatus: _correlationTailCaptureStatus,
		tailOccurrenceId: _correlationTailOccurrenceId,
		...completionCorrelation
	} = correlation;
	const completionFields: Record<string, unknown> = {
		...completionCorrelation,
		// Keep canonical completion fields after bridge correlation so a bridge
		// cannot overwrite producer-owned occurrence identities or status.
		type: "kernel_diagnostic_capture_complete",
		retainedBytes,
		sourceBytes: stderrBytes,
		tailCaptureStatus: retainedBytes === 0 ? "not_required" : tailAdmission?.accepted ? "admitted" : "rejected",
	};
	if (exitAdmission?.accepted) completionFields.exitOccurrenceId = exitAdmission.occurrenceId;
	else if (exitAdmission) completionFields.exitAdmissionReason = exitAdmission.reason;
	if (retainedBytes > 0) {
		if (tailAdmission?.accepted) completionFields.tailOccurrenceId = tailAdmission.occurrenceId;
		else if (tailAdmission) completionFields.tailAdmissionReason = tailAdmission.reason;
	}
	if (nativeDiagnosticsEnabled()) {
		emitNativeDiagnostic("kernel_diagnostic_capture_complete", { ...completionFields, delivery: "queue_accepted" });
		return;
	}
	const runDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
	if (runDir && serviceFinalizationNamespaceObserved(runDir)) return;
	emitIncidentControl("kernel_diagnostic_capture_complete", completionFields);
}

function flushRawSegmentManifests(runDir: string): void {
	const states = [...rawSegmentStates.values()].filter((state) => state.runDir === runDir);
	if (states.length === 0) return;
	const transaction = acquireFallbackRunEvidenceAdmission(runDir);
	if (!transaction) return;
	try {
		for (const state of states) writeRawSegmentManifestSync(state);
	} finally {
		transaction.release();
	}
}

async function flushRecordedProcessBytes(runDir: string): Promise<void> {
	await waitForProviderReferenceWrites(runDir);
	flushRawSegmentManifests(runDir);
}

export function installSupervisorDiagnosticHooks(socketPath: string): () => void {
	if (!nativeDiagnosticsEnabled() && (!process.env[INCIDENT_RECORDER_RUN_DIR_ENV] || !configureIncidentCaptureEmitter())) return () => {};
	const unsubscribeKernelDiagnostics = subscribeKernelDiagnostics(appendKernelDiagnosticCapture);
	appendSupervisorDiagnosticEvent("supervisor_started", {
		socketPath,
		runtimeCategory: process.versions.bun ? "bun" : process.versions.node ? "node" : "foreign",
		nodeVersion: process.versions.node,
		runtimeIdentity: {
			release: process.release,
			versions: process.versions,
			execPath: process.execPath,
			argv: process.argv,
		},
		nodeFatalReportsEnabled: process.release.name === "node" && !process.versions.bun,
	});
	const heartbeat = setInterval(() => {
		appendSupervisorDiagnosticEvent("supervisor_heartbeat", {
			memory: process.memoryUsage(),
			uptimeSeconds: process.uptime(),
		});
	}, HEARTBEAT_INTERVAL_MS);
	heartbeat.unref();
	const fatal = (error: Error, origin: "uncaughtException" | "unhandledRejection") => {
		appendSupervisorDiagnosticEvent(origin === "unhandledRejection" ? "unhandled_rejection" : "fatal_exception", {
			origin,
			error,
		});
	};
	const exit = () => stopIncidentCaptureEmitterOnExit();
	process.on("uncaughtExceptionMonitor", fatal);
	process.on("exit", exit);
	return () => {
		unsubscribeKernelDiagnostics();
		clearInterval(heartbeat);
		process.off("uncaughtExceptionMonitor", fatal);
		process.off("exit", exit);
	};
}

function safeRunName(): string {
	return `${new Date().toISOString().replaceAll(":", "-")}-${randomUUID()}`;
}

function createRunDir(agentDir: string): string {
	const root = join(agentDir, "incident-recorder", "runs");
	mkdirSync(root, { recursive: true, mode: 0o700 });
	chmodSync(root, 0o700);
	const runDir = join(root, safeRunName());
	mkdirSync(runDir, { mode: 0o700 });
	mkdirSync(join(runDir, "reports"), { mode: 0o700 });
	mkdirSync(join(runDir, "raw-reports"), { mode: 0o700 });
	writePrivateJson(join(runDir, ACTIVE_MARKER_FILE_NAME), {
		role: "wrapper-proxy",
		machineId: linuxMachineId(),
		bootId: linuxBootId(),
		pid: process.pid,
		processStartId: getProcessStartId(process.pid),
		created: nowFields(),
	});
	return runDir;
}

export function shouldRecordSupervisorLaunch(
	args: readonly string[],
	environment: NodeJS.ProcessEnv = process.env,
	workerProcess = false,
): boolean {
	const modeIndex = args.indexOf("--mode");
	return (
		!nativeDiagnosticsEnabled(environment) &&
		modeIndex !== -1 &&
		args[modeIndex + 1] === "daemon" &&
		!args.includes("--incident-recorder-service") &&
		environment[INCIDENT_RECORDER_SERVICE_ENV] !== "1" &&
		!workerProcess &&
		environment[INCIDENT_RECORDER_CHILD_ENV] !== "1"
	);
}

export function createRecordedSupervisorChildLaunch(args: readonly string[]): CliSubprocessLaunchSpec {
	return createCliSubprocessLaunchSpec(args, process.execPath, process.execArgv, process.argv[1]);
}

const SENSITIVE_FLAG =
	/(?:^|[-_])(prompt|body|launch[-_]?env|env(?:ironment)?|auth(?:orization)?|api[-_]?key|token|secret|password)(?:$|[-_])/i;

export interface IncidentCommandSummary {
	argumentCount: number;
	flagCategories: string[];
	positionalCount: number;
	redactedValueCount: number;
	nulSeparated: boolean;
}

export function summarizeIncidentCommandLine(args: readonly string[], nulSeparated = false): IncidentCommandSummary {
	const flagCategories = new Set<string>();
	let positionalCount = 0;
	let redactedValueCount = 0;
	let redactNext = false;
	for (const argument of args.slice(0, INCIDENT_RECORDER_LIMITS.maxDirectoryEntries)) {
		if (redactNext) {
			redactedValueCount += 1;
			redactNext = false;
			continue;
		}
		if (!argument.startsWith("-")) {
			positionalCount += 1;
			continue;
		}
		const equals = argument.indexOf("=");
		const flag = (equals === -1 ? argument : argument.slice(0, equals)).slice(0, 80);
		if (SENSITIVE_FLAG.test(flag)) {
			flagCategories.add("sensitive");
			if (equals === -1) redactNext = true;
			else redactedValueCount += 1;
			continue;
		}
		if (flag.startsWith("--report")) flagCategories.add("node_report");
		else if (["--mode", "--daemon-socket", "--agent-dir"].includes(flag)) flagCategories.add("daemon_control");
		else flagCategories.add("other_flag");
		if (equals !== -1) redactedValueCount += 1;
	}
	return {
		argumentCount: args.length,
		flagCategories: [...flagCategories].slice(0, 64),
		positionalCount,
		redactedValueCount,
		nulSeparated,
	};
}

function summarizeProcCommandLine(value: Buffer): IncidentCommandSummary {
	const nulSeparated = value.includes(0);
	const args = nulSeparated ? value.toString("utf8").split("\0").filter(Boolean) : [value.toString("utf8")];
	return summarizeIncidentCommandLine(args, nulSeparated);
}

function provenNodeLaunch(launch: CliSubprocessLaunchSpec): boolean {
	return (
		process.release.name === "node" &&
		Boolean(process.versions.node) &&
		!process.versions.bun &&
		resolve(launch.command) === resolve(process.execPath)
	);
}

function parseProcStatus(value: string): Record<string, number | string> {
	const result: Record<string, number | string> = {};
	const numericKeys = new Set([
		"FDSize",
		"Threads",
		"VmPeak",
		"VmSize",
		"VmLck",
		"VmPin",
		"VmHWM",
		"VmRSS",
		"RssAnon",
		"RssFile",
		"RssShmem",
		"VmData",
		"VmStk",
		"VmExe",
		"VmLib",
		"VmPTE",
		"VmSwap",
		"voluntary_ctxt_switches",
		"nonvoluntary_ctxt_switches",
	]);
	for (const line of value.split("\n")) {
		const separator = line.indexOf(":");
		if (separator === -1) continue;
		const key = line.slice(0, separator);
		const raw = line.slice(separator + 1).trim();
		if (key === "State") {
			const state = raw.match(/^[A-Za-z]/)?.[0];
			if (state) result.State = state;
		} else if (numericKeys.has(key)) {
			const numeric = Number(raw.match(/^\d+/)?.[0]);
			if (Number.isFinite(numeric)) result[key] = numeric;
		}
	}
	return result;
}

function parseProcStat(value: string): Record<string, number | string> {
	const commandEnd = value.lastIndexOf(")");
	if (commandEnd === -1) return {};
	const fields = value
		.slice(commandEnd + 2)
		.trim()
		.split(/\s+/);
	const result: Record<string, number | string> = {};
	if (/^[A-Za-z]$/.test(fields[0] ?? "")) result.state = fields[0];
	for (const [name, index] of [
		["parentPid", 1],
		["processGroup", 2],
		["session", 3],
		["userTicks", 11],
		["systemTicks", 12],
		["numThreads", 17],
		["processStartTicks", 19],
		["virtualBytes", 20],
		["rssPages", 21],
	] as const) {
		const numeric = Number(fields[index]);
		if (Number.isFinite(numeric)) result[name] = numeric;
	}
	return result;
}

function parseNumericLines(value: string): Record<string, number> {
	const result: Record<string, number> = {};
	for (const line of value.split("\n").slice(0, 128)) {
		const match = line.match(/^([A-Za-z][A-Za-z0-9_() -]{0,63}):?\s+(\d+)/);
		if (!match) continue;
		result[match[1].trim().replaceAll(" ", "_")] = Number(match[2]);
	}
	return result;
}

function parseCgroup(value: string): Array<{ hierarchy: number; controllers: string[]; path: string }> {
	return value
		.split("\n")
		.slice(0, 64)
		.flatMap((line) => {
			const match = line.match(/^(\d+):([A-Za-z0-9_,.-]*):(.*)$/);
			if (!match) return [];
			return [
				{
					hierarchy: Number(match[1]),
					controllers: match[2]
						.split(",")
						.filter(Boolean)
						.map((item) => safeToken(item)),
					path: match[3],
				},
			];
		});
}

function readProc(path: string): BoundedRead | undefined {
	return readBoundedPrefix(path, INCIDENT_RECORDER_LIMITS.evidenceFileBytes);
}

function readProcessTree(
	rootPid: number,
): Array<{ pid: number; processStartId?: string; status?: Record<string, unknown> }> {
	const result: Array<{ pid: number; processStartId?: string; status?: Record<string, unknown> }> = [];
	const pending = [rootPid];
	const seen = new Set<number>();
	while (pending.length > 0) {
		const pid = pending.shift();
		if (!pid || seen.has(pid)) continue;
		seen.add(pid);
		const status = readProc(`/proc/${pid}/status`);
		result.push({
			pid,
			processStartId: getProcessStartId(pid),
			status: status && !status.truncated ? parseProcStatus(status.value.toString("utf8")) : undefined,
		});
		const children = readProc(`/proc/${pid}/task/${pid}/children`);
		if (!children || children.truncated) continue;
		pending.push(
			...children.value
				.toString("utf8")
				.trim()
				.split(/\s+/)
				.map(Number)
				.filter((childPid) => Number.isInteger(childPid) && childPid > 0),
		);
	}
	return result;
}

function hasMatchingProcessIdentity(pid: number, processStartId: string | undefined): processStartId is string {
	return Boolean(processStartId) && getProcessStartId(pid) === processStartId;
}

type ProcRawRecorder = (sourcePath: string, value: Buffer) => unknown;

function captureRawProcFile(
	runDir: string,
	pid: number,
	processStartId: string,
	name: string,
	recorder?: ProcRawRecorder,
): Buffer | undefined {
	if (!hasMatchingProcessIdentity(pid, processStartId)) return undefined;
	const sourcePath = `/proc/${pid}/${name}`;
	try {
		const value = readFileSync(sourcePath);
		if (!hasMatchingProcessIdentity(pid, processStartId)) return undefined;
		const sha256 = createHash("sha256").update(value).digest("hex");
		if (serviceFinalizationNamespaceObserved(runDir)) return value;
		const orderedWriter = orderedWriterForRun(runDir);
		if (orderedWriter && !recorder) {
			orderedWriter.recordExactBytes("linux-raw-source", "proc_source_snapshot", value, "exact-file-bytes", {
				sourcePath,
				pid,
				processStartId,
				sha256,
			});
		} else if (recorder) {
			appendRunEvent(runDir, {
				type: "proc_source_snapshot",
				sourcePath,
				pid,
				processStartId,
				sha256,
				payloadBlob: recorder(sourcePath, value),
			});
		} else {
			const transaction = acquireFallbackRunEvidenceAdmission(runDir);
			if (!transaction) return value;
			try {
				const payloadBlob = contentAddressRawBytes(runDir, "recorder-events", value, "binary");
				appendRunEvent(runDir, {
					type: "proc_source_snapshot",
					sourcePath,
					pid,
					processStartId,
					sha256,
					payloadBlob,
				});
			} finally {
				transaction.release();
			}
		}
		return value;
	} catch (error) {
		appendRunEvent(runDir, { type: "proc_source_read_error", sourcePath, pid, processStartId, error });
		return undefined;
	}
}

function captureRawFileDescriptors(runDir: string, pid: number, processStartId: string): void {
	if (!hasMatchingProcessIdentity(pid, processStartId)) return;
	const directory = `/proc/${pid}/fd`;
	try {
		const descriptors = readdirSync(directory).map((name) => {
			try {
				return { descriptor: name, target: readlinkSync(join(directory, name)) };
			} catch (error) {
				return { descriptor: name, error: serializeError(error) };
			}
		});
		if (!hasMatchingProcessIdentity(pid, processStartId)) return;
		const encoded = Buffer.from(JSON.stringify(encodeDiagnosticValue(descriptors)), "utf8");
		const sha256 = createHash("sha256").update(encoded).digest("hex");

		appendRunEvent(runDir, {
			type: "process_descriptor_snapshot",
			sourcePath: directory,
			pid,
			processStartId,
			sha256,
			descriptors,
		});
	} catch (error) {
		appendRunEvent(runDir, {
			type: "process_descriptor_read_error",
			sourcePath: directory,
			pid,
			processStartId,
			error,
		});
	}
}

function captureRawProcessTree(
	runDir: string,
	rootPid: number,
	rootProcessStartId: string,
	recorder?: ProcRawRecorder,
): void {
	const pending = [rootPid];
	const seen = new Set<number>();
	while (pending.length > 0) {
		const pid = pending.shift();
		if (!pid || seen.has(pid)) continue;
		seen.add(pid);
		const processStartId = pid === rootPid ? rootProcessStartId : getProcessStartId(pid);
		if (!processStartId || !hasMatchingProcessIdentity(pid, processStartId)) continue;
		const children = captureRawProcFile(runDir, pid, processStartId, `task/${pid}/children`, recorder);
		if (pid !== rootPid) {
			for (const name of ["status", "stat", "io", "limits", "smaps_rollup", "cgroup", "cmdline", "environ"]) {
				captureRawProcFile(runDir, pid, processStartId, name, recorder);
			}
			captureRawFileDescriptors(runDir, pid, processStartId);
		}
		if (!children) continue;
		pending.push(
			...children
				.toString("utf8")
				.trim()
				.split(/\s+/)
				.map(Number)
				.filter((childPid) => Number.isInteger(childPid) && childPid > 0),
		);
	}
}

function captureProc(
	runDir: string,
	pid: number,
	processStartId: string | undefined,
	recorder?: ProcRawRecorder,
): void {
	if (
		serviceFinalizationNamespaceObserved(runDir) ||
		process.platform !== "linux" ||
		!hasMatchingProcessIdentity(pid, processStartId)
	)
		return;
	const transaction = acquireFallbackRunEvidenceAdmission(runDir);
	if (!transaction) return;
	try {
		captureProcUnderAdmission(runDir, pid, processStartId, recorder);
	} finally {
		transaction.release();
	}
}

function captureProcUnderAdmission(
	runDir: string,
	pid: number,
	processStartId: string,
	recorder?: ProcRawRecorder,
): void {
	const procDir = join(runDir, "proc");
	mkdirSync(procDir, { recursive: true, mode: 0o700 });
	const status = captureRawProcFile(runDir, pid, processStartId, "status", recorder);
	if (status) writePrivateJson(join(procDir, "status.json"), parseProcStatus(status.toString("utf8")));
	const stat = captureRawProcFile(runDir, pid, processStartId, "stat", recorder);
	if (stat) writePrivateJson(join(procDir, "stat.json"), parseProcStat(stat.toString("utf8")));
	for (const name of ["io", "limits", "smaps_rollup"]) {
		const value = captureRawProcFile(runDir, pid, processStartId, name, recorder);
		if (value) writePrivateJson(join(procDir, `${name}.json`), parseNumericLines(value.toString("utf8")));
	}
	const cgroup = captureRawProcFile(runDir, pid, processStartId, "cgroup", recorder);
	if (cgroup) writePrivateJson(join(procDir, "cgroup.json"), parseCgroup(cgroup.toString("utf8")));
	const cmdline = captureRawProcFile(runDir, pid, processStartId, "cmdline", recorder);
	if (cmdline) writePrivateJson(join(procDir, "cmdline.json"), summarizeProcCommandLine(cmdline));
	captureRawProcFile(runDir, pid, processStartId, "environ", recorder);
	captureRawFileDescriptors(runDir, pid, processStartId);
	captureRawProcessTree(runDir, pid, processStartId, recorder);
	writePrivateJson(join(procDir, "process-tree.json"), readProcessTree(pid));
}

function captureProcSafely(
	runDir: string,
	pid: number,
	processStartId: string | undefined,
	recorder?: ProcRawRecorder,
): void {
	try {
		captureProc(runDir, pid, processStartId, recorder);
	} catch (error) {
		recordRawLoss(runDir, "linux-raw-source", error, 0);
	}
}

function readRawEventSource(runDir: string, source: RawApplicationSource): IncidentRecorderEvent[] {
	const directory = rawSourceDirectory(runDir, source);
	let names: string[];
	try {
		names = readdirSync(directory)
			.filter((name) => /^segment-\d{8}\.jsonl$/.test(name))
			.sort();
	} catch {
		return [];
	}
	const frames = new Map<string, { chunkCount: number; chunks: Map<number, Buffer> }>();
	for (const name of names) {
		let value: string;
		try {
			value = readFileSync(join(directory, name), "utf8");
		} catch {
			continue;
		}
		for (const line of value.split("\n").filter(Boolean)) {
			try {
				const frame = JSON.parse(line) as Partial<RawRecordFrame>;
				if (
					typeof frame.recordId !== "string" ||
					typeof frame.chunkIndex !== "number" ||
					typeof frame.chunkCount !== "number" ||
					frame.encoding !== "base64" ||
					typeof frame.payload !== "string"
				) {
					continue;
				}
				const record = frames.get(frame.recordId) ?? { chunkCount: frame.chunkCount, chunks: new Map() };
				record.chunks.set(frame.chunkIndex, Buffer.from(frame.payload, "base64"));
				frames.set(frame.recordId, record);
			} catch {
				// Loss is represented by the finalized manifest and explicit loss records when writable.
			}
		}
	}
	const events: IncidentRecorderEvent[] = [];
	for (const record of frames.values()) {
		if (record.chunks.size !== record.chunkCount) continue;
		try {
			const chunks = Array.from({ length: record.chunkCount }, (_, index) => record.chunks.get(index));
			if (chunks.some((chunk) => chunk === undefined)) continue;
			const envelope = JSON.parse(Buffer.concat(chunks as Buffer[]).toString("utf8")) as Record<string, unknown>;
			let encodedFields = envelope.fields;
			if (envelope.payloadBlob && typeof envelope.payloadBlob === "object") {
				const reference = envelope.payloadBlob as Partial<RawBlobReference>;
				const candidates = [reference.path, reference.collisionFallbackPath].filter(
					(path): path is string => typeof path === "string",
				);
				for (const path of candidates) {
					try {
						const payload = readFileSync(path);
						if (
							typeof reference.digest === "string" &&
							createHash("sha256").update(payload).digest("hex") === reference.digest &&
							(typeof reference.bytes !== "number" || payload.length === reference.bytes)
						) {
							encodedFields = JSON.parse(payload.toString("utf8")) as unknown;
							break;
						}
					} catch {}
				}
			}
			const decoded = decodeDiagnosticValue(encodedFields);
			const fields = decoded && typeof decoded === "object" && !Array.isArray(decoded) ? decoded : {};
			if (
				typeof envelope.type === "string" &&
				typeof envelope.wallTime === "string" &&
				typeof envelope.monotonicNs === "string" &&
				typeof envelope.pid === "number"
			) {
				events.push({
					...(fields as Record<string, unknown>),
					type: envelope.type,
					wallTime: envelope.wallTime,
					monotonicNs: envelope.monotonicNs,
					pid: envelope.pid,
					recorderProvenance: {
						processStartId: envelope.processStartId,
						sequence: envelope.sequence,
						payloadBlob: envelope.payloadBlob,
						provenance: envelope.provenance,
					},
				});
			}
		} catch {
			// A malformed record is noncanonical analysis input; raw segment bytes remain available.
		}
	}
	return events;
}

interface OrderedEventCache {
	seen: Set<string>;
	events: Map<string, IncidentRecorderEvent & { wrapperSequence?: string }>;
	references: Map<string, Record<string, unknown>>;
	directory?: Dir;
	discoveryComplete: boolean;
	discoveryError?: string;
	lastOpenError?: string;
}
const orderedEventCaches = new Map<string, OrderedEventCache>();

function readOrderedEvents(runDir: string): IncidentRecorderEvent[] {
	const runId = basename(runDir).slice(-36);
	const runReferenceDirectory = join(
		dirname(dirname(runDir)),
		"refs",
		"runs",
		createHash("sha256").update(runId).digest("hex"),
	);
	let cache = orderedEventCaches.get(runDir);
	if (!cache) {
		cache = { seen: new Set(), events: new Map(), references: new Map(), discoveryComplete: false };
		orderedEventCaches.set(runDir, cache);
		while (orderedEventCaches.size > 4096) {
			const oldest = orderedEventCaches.keys().next().value as string;
			try {
				orderedEventCaches.get(oldest)?.directory?.closeSync();
			} catch {}
			orderedEventCaches.delete(oldest);
		}
	}
	if (!cache.directory) {
		cache.discoveryComplete = false;
		try {
			cache.directory = opendirSync(runReferenceDirectory);
			cache.lastOpenError = undefined;
		} catch (error) {
			cache.lastOpenError = error instanceof Error ? error.message : String(error);
			return [...cache.events.values()];
		}
	}
	const deadline = Date.now() + 5;
	let files = 0;
	let bytes = 0;
	while (files < 8 && bytes < 128 * 1024 && Date.now() < deadline) {
		const directory = cache.directory;
		if (!directory) break;
		let entry: Dirent | null;
		try {
			entry = directory.readSync();
		} catch (error) {
			cache.discoveryError = error instanceof Error ? error.message : String(error);
			entry = null;
		}
		if (!entry) {
			try {
				directory.closeSync();
			} catch {}
			cache.directory = undefined;
			cache.discoveryComplete = true;
			break;
		}
		if (!entry.isFile() || !/^seq-[A-Za-z0-9-]{1,180}\.json$/.test(entry.name) || cache.seen.has(entry.name))
			continue;
		files += 1;
		try {
			const path = join(runReferenceDirectory, entry.name);
			const stat = statSync(path);
			if (stat.size > 64 * 1024 || bytes + stat.size > 128 * 1024) {
				cache.discoveryError = `ordered_reference_oversized:${entry.name}`;
				continue;
			}
			cache.seen.add(entry.name);
			if (cache.seen.size > 4096) {
				cache.discoveryError = "ordered_reference_count_overflow";
				cache.seen.delete(cache.seen.values().next().value as string);
			}
			bytes += stat.size;
			const reference = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
			cache.references.set(entry.name, reference);
			if (cache.references.size > 4096) {
				cache.discoveryError = "ordered_reference_count_overflow";
				cache.references.delete(cache.references.keys().next().value as string);
			}
			const identity = reference.identity;
			if (!identity || typeof identity !== "object" || Array.isArray(identity)) continue;
			const identityFields = identity as Record<string, unknown>;
			if (
				identityFields.runId !== runId ||
				!["derived-scalar", "loss", "control"].includes(String(reference.payloadKind)) ||
				typeof reference.type !== "string" ||
				typeof reference.eventWallTimeMs !== "string" ||
				typeof reference.eventMonotonicNs !== "string" ||
				!reference.metadata ||
				typeof reference.metadata !== "object" ||
				Array.isArray(reference.metadata)
			)
				continue;
			const metadata = reference.metadata as Record<string, unknown>;
			const wrapperOrder =
				Array.isArray(reference.wrapperOrder) && typeof reference.wrapperOrder[0] === "string"
					? reference.wrapperOrder[0]
					: undefined;
			cache.events.set(entry.name, {
				...metadata,
				type: reference.type,
				wallTime: new Date(Number(reference.eventWallTimeMs)).toISOString(),
				monotonicNs: reference.eventMonotonicNs,
				pid: typeof metadata.producerPid === "number" ? metadata.producerPid : 0,
				wrapperSequence: wrapperOrder,
				recorderProvenance: { occurrenceId: identityFields.occurrenceId, compactorCommitted: true },
			});
			while (cache.events.size > 4096) cache.events.delete(cache.events.keys().next().value as string);
		} catch (error) {
			cache.discoveryError = `ordered_reference_invalid:${entry.name}:${error instanceof Error ? error.message : String(error)}`;
		}
	}
	return [...cache.events.values()].sort((left, right) => {
		try {
			return left.wrapperSequence && right.wrapperSequence
				? Number(BigInt(left.wrapperSequence) - BigInt(right.wrapperSequence))
				: 0;
		} catch {
			return 0;
		}
	});
}
function readLegacyFinalizationBarrierProof(runDir: string): IncidentRecorderFinalizationBarrierProof {
	const expectation = readFinalizationBarrierExpectation(runDir);
	if (
		!expectation?.supervisorExit ||
		!expectation.wrapperTerminal ||
		expectation.supervisorExit.producerId !== expectation.wrapperTerminal.producerId
	) {
		return { supervisorExit: false, wrapperTerminal: false };
	}
	const runId = basename(runDir).slice(-36);
	if (expectation.runId !== runId) return { supervisorExit: false, wrapperTerminal: false };
	readOrderedEvents(runDir);
	const references = [...(orderedEventCaches.get(runDir)?.references.values() ?? [])];
	const sequenceRangeEquals = (values: unknown, first: string, last: string): boolean => {
		if (!Array.isArray(values) || values.length < 1 || values.some((value) => typeof value !== "string"))
			return false;
		try {
			return (
				values[0] === first &&
				values.at(-1) === last &&
				values.every((value, index) => BigInt(value as string) === BigInt(first) + BigInt(index))
			);
		} catch {
			return false;
		}
	};
	const gapCovers = (expected: NonNullable<typeof expectation.supervisorExit>): boolean => {
		const producerStreams = new Set<string>();
		const wrapperStreams = new Set<string>();
		for (const reference of references) {
			if (
				reference.state !== "gap_or_uncertainty" ||
				!reference.evidence ||
				typeof reference.evidence !== "object" ||
				Array.isArray(reference.evidence)
			)
				continue;
			const evidence = reference.evidence as Record<string, unknown>;
			if (
				evidence.runId !== expectation.runId ||
				evidence.runToken !== expectation.runToken ||
				typeof evidence.streamKeyHash !== "string" ||
				!/^[0-9a-f]{64}$/.test(evidence.streamKeyHash)
			)
				continue;
			try {
				if (
					evidence.producerId === expected.producerId &&
					typeof evidence.expectedProducerFrom === "string" &&
					typeof evidence.expectedProducerThrough === "string" &&
					BigInt(evidence.expectedProducerFrom) <= BigInt(expected.firstProducerSequence) &&
					BigInt(evidence.expectedProducerThrough) >= BigInt(expected.lastProducerSequence)
				)
					producerStreams.add(evidence.streamKeyHash);
				if (
					evidence.wrapperPid === expectation.wrapperPid &&
					evidence.wrapperStartId === expectation.wrapperStartId &&
					typeof evidence.expectedWrapperFrom === "string" &&
					typeof evidence.expectedWrapperThrough === "string" &&
					BigInt(evidence.expectedWrapperFrom) <= BigInt(expected.firstWrapperSequence) &&
					BigInt(evidence.expectedWrapperThrough) >= BigInt(expected.lastWrapperSequence)
				)
					wrapperStreams.add(evidence.streamKeyHash);
			} catch {}
		}
		return [...producerStreams].some((stream) => wrapperStreams.has(stream));
	};
	const completeMatches = (
		expected: NonNullable<typeof expectation.supervisorExit>,
		kind: "exit" | "terminal",
	): boolean =>
		references.some((reference) => {
			if (reference.state !== "complete") return false;
			const identity = reference.identity;
			if (!identity || typeof identity !== "object" || Array.isArray(identity)) return false;
			const child = identity as Record<string, unknown>;
			if (
				child.runId !== expectation.runId ||
				child.runToken !== expectation.runToken ||
				child.producerId !== expected.producerId ||
				child.occurrenceId !== expected.occurrenceId
			)
				return false;
			if (
				!sequenceRangeEquals(reference.wrapperOrder, expected.firstWrapperSequence, expected.lastWrapperSequence) ||
				!sequenceRangeEquals(reference.producerOrder, expected.firstProducerSequence, expected.lastProducerSequence)
			)
				return false;
			const metadata = reference.metadata;
			const transport = reference.transportIdentity;
			if (
				!metadata ||
				typeof metadata !== "object" ||
				Array.isArray(metadata) ||
				!transport ||
				typeof transport !== "object" ||
				Array.isArray(transport)
			)
				return false;
			const fields = metadata as Record<string, unknown>;
			const transportFields = transport as Record<string, unknown>;
			if (
				fields.producerPid !== transportFields.wrapperPid ||
				transportFields.wrapperPid !== expectation.wrapperPid ||
				transportFields.wrapperStartId !== expectation.wrapperStartId
			)
				return false;
			if (kind === "exit")
				return (
					reference.type === "supervisor_exit" &&
					reference.source === "recorder-events" &&
					Object.hasOwn(fields, "code") &&
					Object.hasOwn(fields, "signal") &&
					fields.code === (expectation.exitCode === "unavailable" ? null : expectation.exitCode) &&
					fields.signal === (expectation.exitSignal === "unavailable" ? null : expectation.exitSignal)
				);
			return (
				reference.type === "capture_channel_terminal" &&
				reference.source === "recorder-control" &&
				reference.terminal === true
			);
		});
	return {
		supervisorExit: completeMatches(expectation.supervisorExit, "exit") || gapCovers(expectation.supervisorExit),
		wrapperTerminal:
			completeMatches(expectation.wrapperTerminal, "terminal") || gapCovers(expectation.wrapperTerminal),
	};
}

function hasCompactedFinalizationBarrier(runDir: string): boolean {
	const expectation = readFinalizationBarrierExpectation(runDir);
	const legacyProof = readLegacyFinalizationBarrierProof(runDir);
	if (expectation && activeIncidentCompactor) {
		const segmented = readCompactedFinalizationBarrier({
			runDir,
			expectation,
			compactor: activeIncidentCompactor,
			legacyProof,
		});
		if (segmented !== "empty") return segmented === "complete";
	}
	return legacyProof.supervisorExit && legacyProof.wrapperTerminal;
}

function readExpectedExitDisposition(runDir: string): { code: number | null; signal: NodeJS.Signals | null } {
	const value = readFinalizationBarrierExpectation(runDir);
	return {
		code: typeof value?.exitCode === "number" ? value.exitCode : null,
		signal:
			typeof value?.exitSignal === "string" && value.exitSignal !== "unavailable"
				? (value.exitSignal as NodeJS.Signals)
				: null,
	};
}

function readEvents(runDir: string): IncidentRecorderEvent[] {
	const orderedEvents = readOrderedEvents(runDir);
	if (orderedEvents.length > 0 || activeServiceRecorder) return orderedEvents;
	const rawEvents = [
		...readRawEventSource(runDir, "recorder-events"),
		...readRawEventSource(runDir, "supervisor-events"),
	].sort((left, right) => {
		const wall = left.wallTime.localeCompare(right.wallTime);
		return wall !== 0 ? wall : left.monotonicNs.localeCompare(right.monotonicNs);
	});
	if (rawEvents.length > 0) return rawEvents;
	const bounded = readBoundedPrefix(join(runDir, EVENT_FILE_NAME), INCIDENT_RECORDER_LIMITS.eventFileBytes);
	if (!bounded) return [];
	return bounded.value
		.toString("utf8")
		.split("\n")
		.filter(Boolean)
		.flatMap((line) => {
			try {
				return [JSON.parse(line) as IncidentRecorderEvent];
			} catch {
				return [];
			}
		});
}

function numericTree(value: unknown, depth = 0): unknown {
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value === "boolean") return value;
	if (!value || typeof value !== "object" || Array.isArray(value) || depth > 3) return undefined;
	const result: Record<string, unknown> = {};
	for (const [key, child] of Object.entries(value).slice(0, 128)) {
		if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key) || SENSITIVE_FLAG.test(key)) continue;
		const minimized = numericTree(child, depth + 1);
		if (minimized !== undefined) result[key] = minimized;
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

function nodeReportCategory(value: unknown): string {
	if (typeof value !== "string") return "other";
	const normalized = value.toLowerCase();
	if (normalized.includes("exception")) return "exception";
	if (normalized.includes("fatal")) return "fatal_error";
	if (normalized.includes("signal") || normalized.startsWith("sig")) return "signal";
	if (normalized.includes("javascript api")) return "javascript_api";
	return "other";
}

function minimizeNodeReport(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object") return { schemaVersion: 1, unavailable: true };
	const report = value as Record<string, unknown>;
	const headerValue = report.header;
	const header = headerValue && typeof headerValue === "object" ? (headerValue as Record<string, unknown>) : {};
	const minimizedHeader: Record<string, unknown> = {};
	for (const key of ["reportVersion", "processId", "threadId", "wordSize"]) {
		const numeric = finiteNumber(header[key]);
		if (numeric !== undefined) minimizedHeader[key] = numeric;
	}
	for (const key of ["event", "trigger"]) {
		if (header[key] !== undefined) minimizedHeader[key] = nodeReportCategory(header[key]);
	}
	for (const key of ["nodejsVersion", "arch", "platform"]) {
		if (header[key] !== undefined) minimizedHeader[key] = safeToken(header[key]);
	}
	if (typeof header.dumpEventTime === "string" && /^\d{4}-\d{2}-\d{2}T/.test(header.dumpEventTime))
		minimizedHeader.dumpEventTime = header.dumpEventTime.slice(0, 32);
	const libuv = Array.isArray(report.libuv) ? report.libuv : [];
	const knownHandleTypes = new Set([
		"async",
		"check",
		"fs_event",
		"fs_poll",
		"idle",
		"pipe",
		"poll",
		"prepare",
		"process",
		"signal",
		"tcp",
		"timer",
		"tty",
		"udp",
	]);
	const handleCounts: Record<string, number> = {};
	for (const handle of libuv.slice(0, 512)) {
		if (!handle || typeof handle !== "object") continue;
		const observedType = (handle as Record<string, unknown>).type;
		const type = typeof observedType === "string" && knownHandleTypes.has(observedType) ? observedType : "other";
		handleCounts[type] = (handleCounts[type] ?? 0) + 1;
	}
	return {
		schemaVersion: 1,
		header: minimizedHeader,
		resourceUsage: numericTree(report.resourceUsage),
		uvthreadResourceUsage: numericTree(report.uvthreadResourceUsage),
		resourceLimits: numericTree(report.resourceLimits),
		javascriptHeap: numericTree(report.javascriptHeap),
		libuvHandleCounts: handleCounts,
		workerCount: Array.isArray(report.workers) ? report.workers.length : undefined,
	};
}

interface NodeReportCaptureState {
	directory?: Dir;
	pending: string[];
	discoveryComplete: boolean;
	discoveryIssues: Set<string>;
}
const nodeReportCaptureStates = new Map<string, NodeReportCaptureState>();

function canonicalJsonValuesEqual(left: unknown, right: unknown): boolean {
	try {
		return JSON.stringify(left) === JSON.stringify(right);
	} catch {
		return false;
	}
}

function writeImmutableJsonOnce(path: string, value: unknown): boolean {
	const directory = dirname(path);
	try {
		mkdirSync(directory, { recursive: true, mode: 0o700 });
	} catch {
		return false;
	}
	let descriptor: number | undefined;
	let writeFailed = false;
	try {
		descriptor = openSync(path, "wx", 0o600);
		const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
		let offset = 0;
		while (offset < bytes.length) {
			const count = writeSync(descriptor, bytes, offset, bytes.length - offset);
			if (count <= 0) throw new Error("immutable_control_write_made_no_progress");
			offset += count;
		}
		fsyncSync(descriptor);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") writeFailed = true;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {
				writeFailed = true;
			}
		}
	}
	if (writeFailed) return false;
	try {
		for (const durableDirectory of new Set([directory, dirname(directory)])) {
			fsyncPrivateDirectorySync(durableDirectory);
		}
	} catch {
		return false;
	}
	const readback = readPrivateCanonicalJson<unknown>(path);
	return readback !== undefined && canonicalJsonValuesEqual(readback, value);
}

function writeImmutableServiceControl(runDir: string, path: string, label: string, value: unknown): boolean {
	if (writeImmutableJsonOnce(path, value)) return true;
	if (!existsSync(path) || !quarantineInvalidServiceControl(runDir, path, label)) return false;
	return writeImmutableJsonOnce(path, value);
}

function validStoppedCaptureCompletion(
	value: Record<string, unknown> | undefined,
	kind: "node_report_capture_complete" | "provider_artifact_capture_complete",
	runId: string,
): boolean {
	if (
		!value ||
		!hasExactObjectKeys(value, ["schemaVersion", "kind", "state", "runId", "reasons"]) ||
		value.schemaVersion !== 1 ||
		value.kind !== kind ||
		value.runId !== runId ||
		!["complete", "incomplete"].includes(String(value.state)) ||
		!Array.isArray(value.reasons) ||
		value.reasons.length > 64 ||
		value.reasons.some((reason) => typeof reason !== "string" || Buffer.byteLength(reason, "utf8") > 4096)
	) {
		return false;
	}
	const reasons = value.reasons as string[];
	const canonicalReasons = [...new Set(reasons)].sort();
	return (
		CANONICAL_UUID.test(runId) &&
		reasons.every((reason, index) => reason === canonicalReasons[index]) &&
		(value.state === "complete" ? reasons.length === 0 : reasons.length > 0)
	);
}

function validCaptureSourceMetadata(value: unknown): value is Record<string, unknown> {
	return (
		isRecordObject(value) &&
		hasExactObjectKeys(value, ["path", "dev", "ino", "bytes", "mtimeMs"]) &&
		typeof value.path === "string" &&
		isAbsolute(value.path) &&
		typeof value.dev === "string" &&
		/^(?:0|[1-9][0-9]*)$/.test(value.dev) &&
		typeof value.ino === "string" &&
		/^(?:0|[1-9][0-9]*)$/.test(value.ino) &&
		Number.isSafeInteger(value.bytes) &&
		Number(value.bytes) >= 0 &&
		typeof value.mtimeMs === "number" &&
		Number.isFinite(value.mtimeMs) &&
		value.mtimeMs >= 0
	);
}

function stoppedTargetArtifactReferenceBoundToRun(
	runDir: string,
	value: unknown,
): value is StoppedTargetArtifactReference {
	if (
		!isRecordObject(value) ||
		!hasExactObjectKeys(value, ["algorithm", "digest", "bytes", "path", "encoding"]) ||
		value.algorithm !== "sha256" ||
		typeof value.digest !== "string" ||
		!/^[0-9a-f]{64}$/.test(value.digest) ||
		!Number.isSafeInteger(value.bytes) ||
		Number(value.bytes) < 0 ||
		typeof value.encoding !== "string" ||
		value.encoding.length < 1 ||
		Buffer.byteLength(value.encoding, "utf8") > 256
	) {
		return false;
	}
	const recorderRoot = dirname(dirname(runDir));
	const casPath = join(recorderRoot, "cas", "sha256", value.digest.slice(0, 2), `${value.digest}.blob`);
	const runId = basename(runDir).slice(-36);
	if (!CANONICAL_UUID.test(runId) || value.path !== casPath) return false;
	const leasePath = join(
		recorderRoot,
		"refs",
		"runs",
		createHash("sha256").update(runId).digest("hex"),
		`cas-${value.digest}.blob`,
	);
	let casDescriptor: number | undefined;
	let leaseDescriptor: number | undefined;
	try {
		casDescriptor = openSync(casPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		leaseDescriptor = openSync(leasePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const casBefore = fstatSync(casDescriptor, { bigint: true });
		const leaseBefore = fstatSync(leaseDescriptor, { bigint: true });
		const privateLinkedFile = (metadata: typeof casBefore): boolean =>
			metadata.isFile() &&
			!metadata.isSymbolicLink() &&
			metadata.nlink >= 2n &&
			metadata.size === BigInt(Number(value.bytes)) &&
			(typeof process.getuid !== "function" || metadata.uid === BigInt(process.getuid())) &&
			(metadata.mode & 0o077n) === 0n;
		if (
			!privateLinkedFile(casBefore) ||
			!privateLinkedFile(leaseBefore) ||
			casBefore.dev !== leaseBefore.dev ||
			casBefore.ino !== leaseBefore.ino
		) {
			return false;
		}
		const digest = createHash("sha256");
		const buffer = Buffer.allocUnsafe(64 * 1024);
		let offset = 0;
		while (offset < Number(value.bytes)) {
			const count = readSync(
				casDescriptor,
				buffer,
				0,
				Math.min(buffer.length, Number(value.bytes) - offset),
				offset,
			);
			if (count <= 0) return false;
			digest.update(buffer.subarray(0, count));
			offset += count;
		}
		if (digest.digest("hex") !== value.digest) return false;
		const casAfter = fstatSync(casDescriptor, { bigint: true });
		const leaseAfter = fstatSync(leaseDescriptor, { bigint: true });
		const casPathname = lstatSync(casPath, { bigint: true });
		const leasePathname = lstatSync(leasePath, { bigint: true });
		for (const metadata of [casAfter, leaseAfter, casPathname, leasePathname]) {
			if (!privateLinkedFile(metadata) || metadata.dev !== casBefore.dev || metadata.ino !== casBefore.ino) {
				return false;
			}
		}
		return casAfter.mtimeNs === casBefore.mtimeNs && casAfter.ctimeNs === casBefore.ctimeNs;
	} catch {
		return false;
	} finally {
		if (casDescriptor !== undefined) {
			try {
				closeSync(casDescriptor);
			} catch {}
		}
		if (leaseDescriptor !== undefined) {
			try {
				closeSync(leaseDescriptor);
			} catch {}
		}
	}
}

function stoppedTargetReferenceArtifact(
	runDir: string,
	role: "node-report" | "provider-artifact",
	value: unknown,
): StoppedTargetArtifactReference | undefined {
	if (!isRecordObject(value) || value.schemaVersion !== 1 || value.state !== "complete") return undefined;
	if (role === "node-report") {
		if (!hasExactObjectKeys(value, ["schemaVersion", "state", "occurrence", "artifact"])) return undefined;
		if (
			!isRecordObject(value.occurrence) ||
			!hasExactObjectKeys(value.occurrence, ["originalPath", "sourceMetadata"]) ||
			typeof value.occurrence.originalPath !== "string" ||
			!validCaptureSourceMetadata(value.occurrence.sourceMetadata) ||
			value.occurrence.originalPath !== value.occurrence.sourceMetadata.path
		) {
			return undefined;
		}
	} else {
		if (!hasExactObjectKeys(value, ["schemaVersion", "state", "source", "artifact"])) return undefined;
		if (
			!isRecordObject(value.source) ||
			!hasExactObjectKeys(value.source, ["provider", "sourcePath", "dev", "ino", "bytes", "mtimeMs"]) ||
			typeof value.source.provider !== "string" ||
			Buffer.byteLength(value.source.provider, "utf8") > 1024 ||
			typeof value.source.sourcePath !== "string"
		) {
			return undefined;
		}
		const normalizedSource = {
			path: value.source.sourcePath,
			dev: value.source.dev,
			ino: value.source.ino,
			bytes: value.source.bytes,
			mtimeMs: value.source.mtimeMs,
		};
		if (!validCaptureSourceMetadata(normalizedSource)) return undefined;
	}
	return stoppedTargetArtifactReferenceBoundToRun(runDir, value.artifact) ? value.artifact : undefined;
}

function stoppedCaptureReferencesAreBound(
	runDir: string,
	directory: string,
	role: "node-report" | "provider-artifact",
): boolean {
	try {
		const names = readdirSync(directory).filter((name) => name.endsWith(".reference.json"));
		if (names.length > 96) return false;
		return names.every((name) => {
			const value = readPrivateCanonicalJson<unknown>(join(directory, name));
			return stoppedTargetReferenceArtifact(runDir, role, value) !== undefined;
		});
	} catch {
		return false;
	}
}

function canonicalStoppedCaptureReasons(values: Iterable<string>): string[] {
	return [...new Set([...values].map((value) => value.slice(0, 1024)))].sort().slice(0, 64);
}

async function sanitizeNodeReports(runDir: string, _removeRawDirectory = false): Promise<"pending" | "complete"> {
	if (serviceFinalizationNamespaceObserved(runDir)) return "complete";
	const transaction = acquireFallbackRunEvidenceAdmission(runDir);
	if (!transaction) return serviceFinalizationNamespaceObserved(runDir) ? "complete" : "pending";
	try {
		return sanitizeNodeReportsUnderAdmission(runDir);
	} finally {
		transaction.release();
	}
}

function sanitizeNodeReportsUnderAdmission(runDir: string): "pending" | "complete" {
	const rawReportsDir = join(runDir, "raw-reports");
	const reportsDir = join(runDir, "reports");
	mkdirSync(reportsDir, { recursive: true, mode: 0o700 });
	const completionPath = join(rawReportsDir, "capture-complete.json");
	const completed = readPrivateCanonicalJson<Record<string, unknown>>(completionPath);
	const runId = basename(runDir).slice(-36);
	if (
		validStoppedCaptureCompletion(completed, "node_report_capture_complete", runId) &&
		stoppedCaptureReferencesAreBound(runDir, rawReportsDir, "node-report")
	) {
		return "complete";
	}
	let recoveredInvalidCompletion = false;
	if (existsSync(completionPath)) {
		if (!quarantineInvalidServiceControl(runDir, completionPath, "node-report-capture-completion")) {
			return "pending";
		}
		recoveredInvalidCompletion = true;
	}
	let state = nodeReportCaptureStates.get(runDir);
	if (!state) {
		state = { pending: [], discoveryComplete: false, discoveryIssues: new Set() };
		nodeReportCaptureStates.set(runDir, state);
		while (nodeReportCaptureStates.size > 4096)
			nodeReportCaptureStates.delete(nodeReportCaptureStates.keys().next().value as string);
	}
	if (recoveredInvalidCompletion) state.discoveryIssues.add("invalid_prior_report_capture_completion");
	if (!state.directory && !state.discoveryComplete) {
		try {
			state.directory = opendirSync(rawReportsDir);
		} catch (error) {
			state.discoveryIssues.add(`report_directory_unreadable:${JSON.stringify(serializeError(error))}`);
			state.discoveryComplete = true;
			try {
				mkdirSync(rawReportsDir, { recursive: true, mode: 0o700 });
			} catch {}
		}
	}
	for (let scanned = 0; state.directory && scanned < 8; scanned += 1) {
		let entry: Dirent | null;
		try {
			entry = state.directory.readSync();
		} catch (error) {
			state.discoveryIssues.add(`report_directory_read_failed:${JSON.stringify(serializeError(error))}`);
			entry = null;
		}
		if (!entry) {
			try {
				state.directory.closeSync();
			} catch {}
			state.directory = undefined;
			state.discoveryComplete = true;
			break;
		}
		if (
			!entry.isFile() ||
			!entry.name.endsWith(".json") ||
			entry.name === "manifest.json" ||
			entry.name.endsWith(".reference.json") ||
			entry.name.endsWith(".pending.json") ||
			entry.name.endsWith(".error.json")
		)
			continue;
		const referencePath = join(rawReportsDir, `${entry.name}.reference.json`);
		if (existsSync(referencePath)) {
			const reference = readPrivateCanonicalJson<unknown>(referencePath);
			if (stoppedTargetReferenceArtifact(runDir, "node-report", reference)) continue;
			if (!quarantineInvalidServiceControl(runDir, referencePath, "node-report-reference")) continue;
			state.discoveryIssues.add(`invalid_prior_report_reference:${entry.name}`);
		}
		if (existsSync(join(rawReportsDir, `${entry.name}.error.json`))) continue;
		state.pending.push(entry.name);
		if (state.pending.length >= 32) break;
	}
	const entryName = state.pending[0];
	if (!entryName) {
		if (!state.discoveryComplete) return "pending";
		try {
			const names = readdirSync(rawReportsDir).slice(0, 97);
			if (names.length > 96) state.discoveryIssues.add("report_directory_entry_overflow");
			for (const name of names.slice(0, 96)) {
				if (name === "manifest.json" || name === "capture-complete.json" || name.endsWith(".error.json")) {
					continue;
				}
				if (name.endsWith(".reference.json")) {
					const reference = readPrivateCanonicalJson<unknown>(join(rawReportsDir, name));
					if (!stoppedTargetReferenceArtifact(runDir, "node-report", reference)) {
						state.discoveryIssues.add(`report_reference_invalid:${name}`);
					}
					continue;
				}
				if (name.endsWith(".pending.json")) {
					const original = name.slice(0, -".pending.json".length);
					if (
						!existsSync(join(rawReportsDir, `${original}.reference.json`)) &&
						!existsSync(join(rawReportsDir, `${original}.error.json`))
					) {
						state.discoveryIssues.add(`report_capture_pending:${original}`);
					}
					continue;
				}
				if (
					name.endsWith(".json") &&
					!existsSync(join(rawReportsDir, `${name}.reference.json`)) &&
					!existsSync(join(rawReportsDir, `${name}.error.json`))
				) {
					state.discoveryIssues.add(`report_capture_unresolved:${name}`);
				}
			}
		} catch (error) {
			state.discoveryIssues.add(`report_completion_scan_failed:${JSON.stringify(serializeError(error))}`);
		}
		const reasons = canonicalStoppedCaptureReasons(state.discoveryIssues);
		try {
			if (
				!writeImmutableServiceControl(runDir, completionPath, "node-report-capture-completion", {
					schemaVersion: 1,
					kind: "node_report_capture_complete",
					state: reasons.length === 0 ? "complete" : "incomplete",
					runId: basename(runDir).slice(-36),
					reasons,
				})
			)
				return "pending";
			return "complete";
		} catch {
			return "pending";
		}
	}
	const sourcePath = join(rawReportsDir, entryName);
	let sourceMetadata: Record<string, unknown>;
	try {
		const stat = statSync(sourcePath, { bigint: true });
		sourceMetadata = {
			path: sourcePath,
			dev: stat.dev.toString(),
			ino: stat.ino.toString(),
			bytes: Number(stat.size),
			mtimeMs: Number(stat.mtimeMs),
		};
		if (
			!writeImmutableServiceControl(
				runDir,
				join(rawReportsDir, `${entryName}.pending.json`),
				"node-report-pending",
				{
					schemaVersion: 1,
					state: "pending",
					source: sourceMetadata,
				},
			)
		)
			return "pending";
	} catch (error) {
		if (
			!writeImmutableServiceControl(runDir, join(rawReportsDir, `${entryName}.error.json`), "node-report-error", {
				schemaVersion: 1,
				state: "error",
				reason: serializeError(error),
			})
		)
			return "pending";
		state.pending.shift();
		return "pending";
	}
	const admission = activeIncidentCompactor?.streamStoppedTargetArtifact(
		basename(runDir).slice(-36),
		sourcePath,
		"node-report-json-bytes",
		{ deadlineMs: Date.now() + 40, byteBudget: 4 * 1024 * 1024 },
	);
	if (!admission || admission.state === "pending") return "pending";
	if (admission.state === "error") {
		if (
			!writeImmutableServiceControl(runDir, join(rawReportsDir, `${entryName}.error.json`), "node-report-error", {
				schemaVersion: 1,
				state: "error",
				source: sourceMetadata,
				reason: admission.reason,
			})
		)
			return "pending";
		appendRunEvent(runDir, { type: "node_report_capture_error", originalPath: sourcePath, reason: admission.reason });
		state.pending.shift();
		return "pending";
	}
	if (!stoppedTargetArtifactReferenceBoundToRun(runDir, admission.artifact)) {
		state.discoveryIssues.add(`report_artifact_cas_lease_invalid:${entryName}`);
		if (
			!writeImmutableServiceControl(runDir, join(rawReportsDir, `${entryName}.error.json`), "node-report-error", {
				schemaVersion: 1,
				state: "error",
				source: sourceMetadata,
				reason: "captured_artifact_cas_lease_invalid",
			})
		)
			return "pending";
		state.pending.shift();
		return "pending";
	}
	if (
		!writeImmutableServiceControl(
			runDir,
			join(rawReportsDir, `${entryName}.reference.json`),
			"node-report-reference",
			{
				schemaVersion: 1,
				state: "complete",
				occurrence: { originalPath: sourcePath, sourceMetadata },
				artifact: admission.artifact,
			},
		)
	)
		return "pending";
	appendRunEvent(runDir, { type: "node_report_captured", originalPath: sourcePath, bytes: admission.artifact.bytes });
	const summaryPrefix = readBoundedPrefix(sourcePath, 64 * 1024)?.value;
	const summary = minimizeNodeReport(summaryPrefix ? readJsonValue(summaryPrefix) : undefined);
	writePrivateJson(join(reportsDir, `report-${admission.artifact.digest.slice(0, 16)}.json`), {
		...summary,
		canonical: false,
		source: admission.artifact,
	});
	state.pending.shift();
	// A separate pass must publish the durable capture-complete marker before
	// orchestration is allowed to seal and finalize this run.
	return "pending";
}

interface ProviderArtifactCaptureState {
	seenReferences: Set<string>;
	pending: Array<{ provider: string; path: string; format: string }>;
	discoveryIssues: Set<string>;
}
const providerArtifactCaptureStates = new Map<string, ProviderArtifactCaptureState>();

interface ProviderArtifactCaptureFrontier {
	schemaVersion: 1;
	kind: "provider_artifact_capture_frontier";
	runId: string;
	referenceCount: number;
	referenceSetSha256: string;
}

function currentProviderArtifactCaptureFrontier(runDir: string): ProviderArtifactCaptureFrontier | undefined {
	readOrderedEvents(runDir);
	const cache = orderedEventCaches.get(runDir);
	if (!cache || cache.directory || !cache.discoveryComplete) return undefined;
	const names = [...cache.references.entries()]
		.filter(([, reference]) => reference.type === "provider_source_manifest_registered")
		.map(([name]) => name)
		.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
	if (names.length > 4096) return undefined;
	const hash = createHash("sha256");
	for (const name of names) hash.update(name).update("\0");
	return {
		schemaVersion: 1,
		kind: "provider_artifact_capture_frontier",
		runId: basename(runDir).slice(-36),
		referenceCount: names.length,
		referenceSetSha256: hash.digest("hex"),
	};
}

function validProviderArtifactCaptureFrontier(
	value: unknown,
	expected: ProviderArtifactCaptureFrontier,
): value is ProviderArtifactCaptureFrontier {
	return (
		isRecordObject(value) &&
		hasExactObjectKeys(value, ["schemaVersion", "kind", "runId", "referenceCount", "referenceSetSha256"]) &&
		value.schemaVersion === expected.schemaVersion &&
		value.kind === expected.kind &&
		value.runId === expected.runId &&
		CANONICAL_UUID.test(expected.runId) &&
		value.referenceCount === expected.referenceCount &&
		Number.isSafeInteger(value.referenceCount) &&
		Number(value.referenceCount) >= 0 &&
		Number(value.referenceCount) <= 4096 &&
		value.referenceSetSha256 === expected.referenceSetSha256 &&
		/^[0-9a-f]{64}$/.test(String(value.referenceSetSha256))
	);
}

function providerArtifactCaptureFrontierMatchesCurrent(runDir: string): boolean {
	const expected = currentProviderArtifactCaptureFrontier(runDir);
	if (!expected) return false;
	const value = readPrivateCanonicalJson<unknown>(
		join(runDir, "evidence", "provider-artifacts", "capture-frontier.json"),
	);
	return validProviderArtifactCaptureFrontier(value, expected);
}

function captureStoppedProviderArtifacts(runDir: string): "pending" | "complete" {
	if (serviceFinalizationNamespaceObserved(runDir)) return "complete";
	const transaction = acquireFallbackRunEvidenceAdmission(runDir);
	if (!transaction) return serviceFinalizationNamespaceObserved(runDir) ? "complete" : "pending";
	try {
		return captureStoppedProviderArtifactsUnderAdmission(runDir);
	} finally {
		transaction.release();
	}
}

function captureStoppedProviderArtifactsUnderAdmission(runDir: string): "pending" | "complete" {
	const evidenceDirectory = join(runDir, "evidence", "provider-artifacts");
	mkdirSync(evidenceDirectory, { recursive: true, mode: 0o700 });
	const completionPath = join(evidenceDirectory, "capture-complete.json");
	const frontierPath = join(evidenceDirectory, "capture-frontier.json");
	const completed = readPrivateCanonicalJson<Record<string, unknown>>(completionPath);
	const runId = basename(runDir).slice(-36);
	const completionValid = validStoppedCaptureCompletion(completed, "provider_artifact_capture_complete", runId);
	const currentFrontier = currentProviderArtifactCaptureFrontier(runDir);
	if (
		completionValid &&
		currentFrontier &&
		validProviderArtifactCaptureFrontier(readPrivateCanonicalJson<unknown>(frontierPath), currentFrontier) &&
		stoppedCaptureReferencesAreBound(runDir, evidenceDirectory, "provider-artifact")
	) {
		return "complete";
	}
	if (completionValid && !currentFrontier) return "pending";
	let recoveredInvalidCompletion = false;
	if (existsSync(completionPath)) {
		if (!quarantineInvalidServiceControl(runDir, completionPath, "provider-artifact-capture-completion")) {
			return "pending";
		}
		recoveredInvalidCompletion = true;
	}
	if (existsSync(frontierPath)) {
		if (!quarantineInvalidServiceControl(runDir, frontierPath, "provider-artifact-capture-frontier")) {
			return "pending";
		}
	}
	let state = providerArtifactCaptureStates.get(runDir);
	if (!state) {
		state = { seenReferences: new Set(), pending: [], discoveryIssues: new Set() };
		providerArtifactCaptureStates.set(runDir, state);
		while (providerArtifactCaptureStates.size > 4096)
			providerArtifactCaptureStates.delete(providerArtifactCaptureStates.keys().next().value as string);
	}
	if (recoveredInvalidCompletion) state.discoveryIssues.add("invalid_prior_provider_capture_completion");
	const cache = orderedEventCaches.get(runDir);
	if (!cache || cache.directory) return "pending";
	if (!cache.discoveryComplete) {
		const discoveryFailure = cache.discoveryError ?? cache.lastOpenError;
		if (!discoveryFailure) return "pending";
		state.discoveryIssues.add(`ordered_reference_discovery_incomplete:${discoveryFailure}`);
	}
	if (cache.discoveryError) state.discoveryIssues.add(`ordered_reference_invalid:${cache.discoveryError}`);
	for (const [name, reference] of cache?.references ?? []) {
		if (state.seenReferences.has(name) || reference.type !== "provider_source_manifest_registered") continue;
		state.seenReferences.add(name);
		const cas = reference.cas;
		if (!cas || typeof cas !== "object" || Array.isArray(cas)) {
			state.discoveryIssues.add(`manifest_cas_invalid:${name}`);
			continue;
		}
		const path = (cas as Record<string, unknown>).path;
		const bytes = (cas as Record<string, unknown>).bytes;
		if (typeof path !== "string" || !Number.isSafeInteger(bytes) || Number(bytes) < 0 || Number(bytes) > 256 * 1024) {
			state.discoveryIssues.add(`manifest_reference_invalid:${name}`);
			continue;
		}
		const encoded = readBoundedPrefix(path, 256 * 1024);
		if (!encoded || encoded.truncated) {
			state.discoveryIssues.add(`manifest_unreadable_or_oversized:${name}`);
			continue;
		}
		const decoded = decodeDiagnosticValue(readJsonValue(encoded.value));
		if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
			state.discoveryIssues.add(`manifest_payload_invalid:${name}`);
			continue;
		}
		const manifest = decoded as Record<string, unknown>;
		const provider = typeof manifest.provider === "string" ? manifest.provider : "unknown";
		if (!Array.isArray(manifest.artifacts)) {
			state.discoveryIssues.add(`manifest_artifacts_invalid:${name}`);
			continue;
		}
		const remaining = Math.max(0, 64 - state.pending.length);
		if (manifest.artifacts.length > remaining) state.discoveryIssues.add(`artifact_count_overflow:${name}`);
		for (const artifact of manifest.artifacts.slice(0, remaining)) {
			if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)) {
				state.discoveryIssues.add(`artifact_entry_invalid:${name}`);
				continue;
			}
			const fields = artifact as Record<string, unknown>;
			if (typeof fields.path !== "string" || !isAbsolute(fields.path)) {
				state.discoveryIssues.add(`artifact_path_invalid:${name}`);
				continue;
			}
			state.pending.push({
				provider,
				path: fields.path,
				format: typeof fields.format === "string" ? fields.format : "exact-provider-bytes",
			});
		}
	}
	const artifact = state.pending[0];
	if (!artifact) {
		try {
			const frontier = currentProviderArtifactCaptureFrontier(runDir);
			if (!frontier) return "pending";
			const names = readdirSync(evidenceDirectory).slice(0, 97);
			if (names.length > 96) state.discoveryIssues.add("provider_capture_directory_entry_overflow");
			for (const name of names.slice(0, 96)) {
				if (!name.endsWith(".reference.json")) continue;
				const reference = readPrivateCanonicalJson<unknown>(join(evidenceDirectory, name));
				if (!stoppedTargetReferenceArtifact(runDir, "provider-artifact", reference)) {
					state.discoveryIssues.add(`provider_reference_invalid:${name}`);
				}
			}
			const reasons = canonicalStoppedCaptureReasons(state.discoveryIssues);
			if (!writeImmutableServiceControl(runDir, frontierPath, "provider-artifact-capture-frontier", frontier)) {
				return "pending";
			}
			if (
				!writeImmutableServiceControl(runDir, completionPath, "provider-artifact-capture-completion", {
					schemaVersion: 1,
					kind: "provider_artifact_capture_complete",
					state: reasons.length === 0 ? "complete" : "incomplete",
					runId: basename(runDir).slice(-36),
					reasons,
				})
			)
				return "pending";
			return "pending";
		} catch {
			return "pending";
		}
	}
	const id = createHash("sha256").update(`${artifact.provider}\0${artifact.path}`).digest("hex");
	const completePath = join(evidenceDirectory, `${id}.reference.json`);
	const errorPath = join(evidenceDirectory, `${id}.error.json`);
	if (existsSync(completePath)) {
		const reference = readPrivateCanonicalJson<unknown>(completePath);
		if (stoppedTargetReferenceArtifact(runDir, "provider-artifact", reference)) {
			state.pending.shift();
			return "pending";
		}
		if (!quarantineInvalidServiceControl(runDir, completePath, "provider-artifact-reference")) return "pending";
		state.discoveryIssues.add(`invalid_prior_provider_reference:${id}`);
	}
	if (existsSync(errorPath)) {
		state.pending.shift();
		return "pending";
	}
	let metadata: Record<string, unknown>;
	try {
		const source = statSync(artifact.path, { bigint: true });
		metadata = {
			provider: artifact.provider,
			sourcePath: artifact.path,
			dev: source.dev.toString(),
			ino: source.ino.toString(),
			bytes: Number(source.size),
			mtimeMs: Number(source.mtimeMs),
		};
		if (
			!writeImmutableServiceControl(
				runDir,
				join(evidenceDirectory, `${id}.pending.json`),
				"provider-artifact-pending",
				{
					schemaVersion: 1,
					state: "pending",
					source: metadata,
				},
			)
		)
			return "pending";
	} catch (error) {
		if (
			!writeImmutableServiceControl(runDir, errorPath, "provider-artifact-error", {
				schemaVersion: 1,
				state: "error",
				reason: serializeError(error),
			})
		)
			return "pending";
		state.pending.shift();
		return "pending";
	}
	const admission = activeIncidentCompactor?.streamStoppedTargetArtifact(
		basename(runDir).slice(-36),
		artifact.path,
		artifact.format,
		{ deadlineMs: Date.now() + 40, byteBudget: 4 * 1024 * 1024 },
	);
	if (!admission || admission.state === "pending") return "pending";
	if (admission.state === "error") {
		if (
			!writeImmutableServiceControl(runDir, errorPath, "provider-artifact-error", {
				schemaVersion: 1,
				state: "error",
				source: metadata,
				reason: admission.reason,
			})
		)
			return "pending";
	} else if (!stoppedTargetArtifactReferenceBoundToRun(runDir, admission.artifact)) {
		state.discoveryIssues.add(`provider_artifact_cas_lease_invalid:${id}`);
		if (
			!writeImmutableServiceControl(runDir, errorPath, "provider-artifact-error", {
				schemaVersion: 1,
				state: "error",
				source: metadata,
				reason: "captured_artifact_cas_lease_invalid",
			})
		)
			return "pending";
	} else if (
		!writeImmutableServiceControl(runDir, completePath, "provider-artifact-reference", {
			schemaVersion: 1,
			state: "complete",
			source: metadata,
			artifact: admission.artifact,
		})
	)
		return "pending";
	state.pending.shift();
	return "pending";
}

function readJsonValue(value: Buffer): unknown {
	try {
		return JSON.parse(value.toString("utf8")) as unknown;
	} catch {
		return undefined;
	}
}

function reportIndicatesException(runDir: string): boolean {
	// Node writes these files only because this wrapper enabled uncaught/fatal reports.
	// Inspect the producer directory before any later stopped-target compaction moves or
	// replaces the report with a reference artifact.
	try {
		if (
			readdirSync(join(runDir, "raw-reports"), { withFileTypes: true }).some(
				(entry) => entry.isFile() && entry.name.endsWith(".json"),
			)
		) {
			return true;
		}
	} catch {}
	let entries: Dirent[];
	try {
		entries = readdirSync(join(runDir, "reports"), { withFileTypes: true }).filter((entry) => entry.isFile());
	} catch {
		return false;
	}
	return entries.some((entry) => {
		const report = readSmallJson<{ header?: { event?: unknown; trigger?: unknown } }>(
			join(runDir, "reports", entry.name),
		);
		const event = typeof report?.header?.event === "string" ? report.header.event.toLowerCase() : undefined;
		const trigger = typeof report?.header?.trigger === "string" ? report.header.trigger.toLowerCase() : undefined;
		return event === "exception" || trigger === "exception" || event === "fatal_error" || trigger === "fatal_error";
	});
}

function classify(
	events: IncidentRecorderEvent[],
	code: number | null,
	signal: NodeJS.Signals | null,
	runDir: string,
): string {
	if (events.some((event) => event.type === "worker_request_end" && event.outcome === "timeout"))
		return "worker_response_hang";
	if (events.some((event) => event.type === "socket_lost")) return "socket_loss";
	if (events.some((event) => event.type === "heartbeat_stalled")) return "event_loop_hang";
	if (events.some((event) => event.type === "native_abort") || signal === "SIGABRT") return "native_abort";
	if (events.some((event) => event.type === "unhandled_rejection")) return "unhandled_rejection";
	if (events.some((event) => event.type === "fatal_exception") || reportIndicatesException(runDir))
		return "uncaught_exception";
	if (hasPositiveLinuxCgroupOomKillDelta(runDir, signal).matched) return "kernel_oom_kill";
	const caughtSignal = [...events].reverse().find((event) => event.type === "signal_received")?.signal;
	if (typeof caughtSignal === "string") return `signal_${caughtSignal.toLowerCase()}`;
	if (signal) return `signal_${signal.toLowerCase()}`;
	if (code !== 0) return `exit_${code ?? "unknown"}`;
	return "normal";
}

interface CopyBudget {
	remaining: number;
	copied: string[];
}

function copyBoundedFile(source: string, target: string, relative: string, budget: CopyBudget): void {
	let sourceDescriptor: number | undefined;
	let targetDescriptor: number | undefined;
	try {
		sourceDescriptor = openSync(source, "r");
		const size = fstatSync(sourceDescriptor).size;
		const configuredFileLimit =
			relative === EVENT_FILE_NAME
				? INCIDENT_RECORDER_LIMITS.eventFileBytes
				: relative === "reports" || relative.startsWith("reports/") || relative.startsWith("reports\\")
					? INCIDENT_RECORDER_LIMITS.nodeReportFileBytes
					: INCIDENT_RECORDER_LIMITS.evidenceFileBytes;
		const fileLimit = Math.min(configuredFileLimit, budget.remaining);
		if (size > fileLimit) return;
		mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
		targetDescriptor = openSync(target, "w", 0o600);
		let copied = 0;
		while (copied < size) {
			const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, size - copied));
			const count = readSync(sourceDescriptor, chunk, 0, chunk.length, copied);
			if (count === 0) break;
			writeSync(targetDescriptor, chunk, 0, count);
			copied += count;
		}
		if (copied !== size) {
			closeSync(targetDescriptor);
			targetDescriptor = undefined;
			rmSync(target, { force: true });
			return;
		}
		budget.remaining -= copied;
		budget.copied.push(relative);
	} catch {
		try {
			rmSync(target, { force: true });
		} catch {}
	} finally {
		if (sourceDescriptor !== undefined) closeSync(sourceDescriptor);
		if (targetDescriptor !== undefined) closeSync(targetDescriptor);
	}
}

function copyEvidenceTree(source: string, target: string, relative: string, budget: CopyBudget, depth = 0): void {
	if (depth > 3 || budget.remaining <= 0) return;
	let entries: Dirent[];
	try {
		entries = readdirSync(source, { withFileTypes: true }).slice(0, INCIDENT_RECORDER_LIMITS.maxDirectoryEntries);
	} catch {
		return;
	}
	for (const entry of entries) {
		const childSource = join(source, entry.name);
		if (isIncidentRecorderExcludedApplicationPath(childSource)) continue;
		const childTarget = join(target, entry.name);
		const childRelative = join(relative, entry.name);
		if (entry.isDirectory()) copyEvidenceTree(childSource, childTarget, childRelative, budget, depth + 1);
		else if (entry.isFile()) copyBoundedFile(childSource, childTarget, childRelative, budget);
		if (budget.remaining <= 0) return;
	}
}

interface RawFileMetadata {
	path: string;
	relativePath?: string;
	bytes?: number;
	sha256?: string;
	mode?: number;
	dev?: number;
	ino?: number;
	mtimeMs?: number;
	stableDuringHash?: boolean;
	unavailable?: ReturnType<typeof serializeError>;
}

function hashFileMetadata(path: string, relativeRoot?: string): RawFileMetadata {
	if (isIncidentRecorderExcludedApplicationPath(path)) {
		throw new Error("Diagnostic capability files are excluded from incident recorder manifests");
	}
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "r");
		const before = fstatSync(descriptor);
		const hash = createHash("sha256");
		let position = 0;
		for (;;) {
			const chunk = Buffer.allocUnsafe(256 * 1024);
			const count = readSync(descriptor, chunk, 0, chunk.length, position);
			if (count === 0) break;
			hash.update(chunk.subarray(0, count));
			position += count;
		}
		const after = fstatSync(descriptor);
		return {
			path,
			...(relativeRoot ? { relativePath: path.slice(relativeRoot.length).replace(/^[/\\]/, "") } : {}),
			bytes: position,
			sha256: hash.digest("hex"),
			mode: after.mode & 0o777,
			dev: after.dev,
			ino: after.ino,
			mtimeMs: after.mtimeMs,
			stableDuringHash:
				before.dev === after.dev &&
				before.ino === after.ino &&
				before.size === after.size &&
				before.mtimeMs === after.mtimeMs &&
				position === after.size,
		};
	} catch (error) {
		return {
			path,
			...(relativeRoot ? { relativePath: path.slice(relativeRoot.length).replace(/^[/\\]/, "") } : {}),
			unavailable: serializeError(error),
		};
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function hashSourceTree(path: string): RawFileMetadata[] {
	if (isIncidentRecorderExcludedApplicationPath(path)) return [];
	let stat: ReturnType<typeof statSync>;
	try {
		stat = statSync(path);
	} catch (error) {
		return [{ path, unavailable: serializeError(error) }];
	}
	if (stat.isFile()) return [hashFileMetadata(path, dirname(path))];
	if (!stat.isDirectory()) return [{ path, unavailable: { reason: "not_a_regular_file_or_directory" } }];
	const files: RawFileMetadata[] = [];
	const pending = [path];
	while (pending.length > 0) {
		const directory = pending.pop();
		if (!directory) continue;
		let entries: Dirent[];
		try {
			entries = readdirSync(directory, { withFileTypes: true });
		} catch (error) {
			files.push({ path: directory, unavailable: serializeError(error) });
			continue;
		}
		for (const entry of entries) {
			const child = join(directory, entry.name);
			if (isIncidentRecorderExcludedApplicationPath(child)) continue;
			if (entry.isDirectory()) pending.push(child);
			else if (entry.isFile()) files.push(hashFileMetadata(child, path));
		}
	}
	return files.sort((left, right) => (left.relativePath ?? left.path).localeCompare(right.relativePath ?? right.path));
}

function createRawApplicationManifest(
	options: RecordProcessOptions,
	runDir: string,
	events: readonly IncidentRecorderEvent[],
	incidentPaths?: { partialDir: string; incidentDir: string },
): Record<string, unknown> {
	const processIdentity = readSmallJson<Record<string, unknown>>(join(runDir, "process.json"));
	const launch = readSmallJson<Record<string, unknown>>(join(runDir, "launch.json"));
	const referencedPaths = new Map<string, Record<string, unknown>>();
	for (const event of events) {
		if (
			event.type === "application_source_reference" &&
			typeof event.path === "string" &&
			!isIncidentRecorderExcludedApplicationPath(event.path)
		) {
			referencedPaths.set(event.path, event);
		}
		if (event.type === "supervisor_ready") {
			for (const key of ["descriptorDir", "supervisorConfigPath", "daemonLogPath"] as const) {
				const path = event[key];
				if (typeof path === "string") referencedPaths.set(path, { source: key, path });
			}
		}
	}
	const daemonLogPath = getDaemonLogPath(options.socketPath);
	referencedPaths.set(daemonLogPath, { source: "daemon-rotating-log", socketPath: options.socketPath });
	referencedPaths.set(`${daemonLogPath}.old`, {
		source: "daemon-rotating-log-previous-segment",
		socketPath: options.socketPath,
	});
	const sourceBounds: Record<
		string,
		Record<
			string,
			{
				processStartId?: unknown;
				start: { wallTime: string; monotonicNs: string };
				end: { wallTime: string; monotonicNs: string };
			}
		>
	> = {};
	for (const event of events) {
		const recorder =
			event.recorderProvenance && typeof event.recorderProvenance === "object"
				? (event.recorderProvenance as Record<string, unknown>)
				: undefined;
		const provenance =
			recorder?.provenance && typeof recorder.provenance === "object"
				? (recorder.provenance as Record<string, unknown>)
				: undefined;
		const source = typeof provenance?.source === "string" ? provenance.source : "legacy";
		const pid = String(event.pid);
		let bounds = sourceBounds[source];
		if (!bounds) {
			bounds = {};
			sourceBounds[source] = bounds;
		}
		const point = { wallTime: event.wallTime, monotonicNs: event.monotonicNs };
		const current = bounds[pid];
		if (!current) bounds[pid] = { processStartId: recorder?.processStartId, start: point, end: point };
		else current.end = point;
	}
	const rawRoots = [join(runDir, RAW_APPLICATION_DIR_NAME), join(runDir, "raw-reports")];
	return {
		schemaVersion: 1,
		canonical: false,
		purpose: "content-bound-index-of-private-local-raw-application-sources",
		generated: nowFields(),
		retentionPolicy: "3-days-time-expiry-with-bounded-reference-safe-gc",
		journalTransport: {
			namespace: "grimoire",
			identifier: "prime-agent-raw-v1",
			retention: "3d",
			occurrenceOrder: "wrapper-sequence-independent-of-journal-receive-time",
			streamSubmissionDurability: "uncertain",
			valueEncoding: "base64-exact-bytes-or-derived-scalar",
		},
		runtimeIdentity: {
			process: processIdentity,
			launch,
			finalizer: {
				pid: process.pid,
				processStartId: getProcessStartId(process.pid),
				executable: process.execPath,
				argv: process.argv,
				versions: process.versions,
			},
		},
		sourceVersion: RAW_RECORD_SCHEMA_VERSION,
		sourceBounds,
		timeBounds: {
			start: events.at(0) ? { wallTime: events[0].wallTime, monotonicNs: events[0].monotonicNs } : undefined,
			end: events.at(-1)
				? { wallTime: events.at(-1)?.wallTime, monotonicNs: events.at(-1)?.monotonicNs }
				: undefined,
		},
		rawSources: rawRoots.map((path) => ({ path, files: hashSourceTree(path) })),
		referenceRoots: {
			globalCas: join(dirname(dirname(runDir)), "cas", "sha256"),
			occurrences: join(dirname(dirname(runDir)), "refs", "occurrences", "sha256"),
			journalRecords: join(dirname(dirname(runDir)), "refs", "journal"),
			exactByteDeduplicationOnly: true,
		},
		incidentPinnedRawSources: incidentPaths
			? [
					{
						incidentPath: incidentPaths.incidentDir,
						manifest: join(incidentPaths.incidentDir, "journal-pin-manifest.json"),
						state: "pending-through-plus-15m-window",
						globalCasRoot: join(dirname(dirname(runDir)), "cas", "sha256"),
					},
				]
			: [],
		contentBoundReferences: [...referencedPaths.entries()].map(([path, provenance]) => ({
			path,
			provenance,
			files: hashSourceTree(path),
		})),
	};
}

type IncidentCauseLayer = "application" | "environment" | "mixed" | "unknown";

function incidentCauseLayer(
	classification: string,
	linuxEvidence: ReturnType<typeof readLinuxIncidentEvidenceCorrelation>,
): IncidentCauseLayer {
	const applicationClassification = new Set([
		"native_abort",
		"unhandled_rejection",
		"uncaught_exception",
		"event_loop_hang",
		"worker_response_hang",
	]);
	const application = applicationClassification.has(classification) || linuxEvidence.applicationEvidence;
	const environment = classification === "kernel_oom_kill" || linuxEvidence.environmentEvidence;
	if (application && environment) return "mixed";
	if (application) return "application";
	if (environment) return "environment";
	return "unknown";
}

function claimIncidentFinalization(runDir: string, incidentId: string): boolean {
	const path = join(runDir, FINALIZER_CLAIM_FILE_NAME);
	const bootId = linuxBootId();
	const processStartId = getProcessStartId(process.pid);
	if (!bootId || !processStartId) return false;
	const existing = readSmallJson<{ bootId?: unknown; pid?: unknown; processStartId?: unknown }>(path);
	if (existing) {
		const live =
			existing.bootId === bootId &&
			typeof existing.pid === "number" &&
			typeof existing.processStartId === "string" &&
			getProcessStartId(existing.pid) === existing.processStartId;
		if (live) return false;
		try {
			rmSync(path, { force: true });
		} catch {
			return false;
		}
	}
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "wx", 0o600);
		const claim = Buffer.from(
			`${JSON.stringify({
				incidentId,
				bootId,
				pid: process.pid,
				processStartId,
				claimed: nowFields(),
			})}\n`,
		);
		let offset = 0;
		while (offset < claim.length) {
			const written = writeSync(descriptor, claim, offset, claim.length - offset);
			if (written <= 0) throw new Error("Incident finalizer claim write made no progress");
			offset += written;
		}
		fsyncSync(descriptor);
		chmodSync(path, 0o600);
		return true;
	} catch {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
				descriptor = undefined;
			} catch {}
		}
		try {
			rmSync(path, { force: true });
		} catch {}
		return false;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

export function finalizeIncidentRecorderRun(
	options: RecordProcessOptions,
	runDir: string,
	result: Omit<RecordedProcessResult, "runDir" | "incidentDir">,
): string | undefined {
	if (result.classification === "normal") return undefined;
	const incidentId = basename(runDir);
	if (!/^[A-Za-z0-9_.+-]{1,160}$/.test(incidentId)) return undefined;
	const incidentRoot = join(options.agentDir, "incidents");
	mkdirSync(incidentRoot, { recursive: true, mode: 0o700 });
	const incidentDir = join(incidentRoot, incidentId);
	if (existsSync(incidentDir)) {
		const existing = readSmallJson<{ stoppedTargetCaptureComplete?: unknown }>(join(incidentDir, "summary.json"));
		return existing?.stoppedTargetCaptureComplete === true ? incidentDir : undefined;
	}
	if (!claimIncidentFinalization(runDir, incidentId)) return undefined;
	const claimPath = join(runDir, FINALIZER_CLAIM_FILE_NAME);
	const partialDir = join(incidentRoot, `.${incidentId}.partial`);
	try {
		rmSync(partialDir, { recursive: true, force: true });
		mkdirSync(partialDir, { mode: 0o700 });
		const events = readEvents(runDir);
		const budget: CopyBudget = {
			remaining: INCIDENT_RECORDER_LIMITS.perBundleBytes - INCIDENT_RECORDER_LIMITS.evidenceFileBytes,
			copied: [],
		};
		for (const name of [EVENT_FILE_NAME, "proc", "reports", "evidence"]) {
			const source = join(runDir, name);
			try {
				if (statSync(source).isDirectory()) copyEvidenceTree(source, join(partialDir, name), name, budget);
				else copyBoundedFile(source, join(partialDir, name), name, budget);
			} catch {}
		}
		const launch = readSmallJson<unknown>(join(runDir, "launch.json"));
		const processIdentity = readSmallJson<unknown>(join(runDir, "process.json"));
		const linuxEvidence = readLinuxIncidentEvidenceCorrelation(runDir);
		writePrivateJson(join(partialDir, "launch.json"), launch);
		writePrivateJson(join(partialDir, "process.json"), processIdentity);
		writePrivateJson(
			join(partialDir, "raw-manifest.json"),
			createRawApplicationManifest(options, runDir, events, { partialDir, incidentDir }),
		);
		writePrivateJson(join(partialDir, "summary.json"), {
			schemaVersion: 1,
			incidentId,
			classification: result.classification,
			stoppedTargetCaptureComplete: true,
			causeLayer: incidentCauseLayer(result.classification, linuxEvidence),
			correlation: linuxEvidence,
			exit: { code: result.code, signal: result.signal },
			socketPath: options.socketPath,
			socketIdentity: [...events].reverse().find((event) => event.type === "supervisor_ready")?.socketIdentity,
			launch,
			processIdentity,
			timelineBounds: {
				start: events.at(0) ? { wallTime: events[0].wallTime, monotonicNs: events[0].monotonicNs } : undefined,
				end: events.at(-1)
					? { wallTime: events.at(-1)?.wallTime, monotonicNs: events.at(-1)?.monotonicNs }
					: undefined,
			},
			evidence: budget.copied,
			finalized: nowFields(),
		});
		renameSync(partialDir, incidentDir);
		return incidentDir;
	} catch (error) {
		try {
			rmSync(partialDir, { recursive: true, force: true });
			rmSync(claimPath, { force: true });
		} catch {}
		throw error;
	}
}

export async function recordSupervisorProcess(options: RecordProcessOptions): Promise<RecordedProcessResult> {
	const runDir = createRunDir(options.agentDir);
	const runId = basename(runDir).slice(-36);
	const runToken = newIncidentRecorderToken();
	const bootId = linuxBootId();
	const wrapperStartId = getProcessStartId(process.pid);
	const orderedWriter = new IncidentRecorderWriter({
		runDir,
		runId,
		runToken,
		bootId,
		wrapperStartId,
	});
	await orderedWriter.start();
	activeOrderedWriter = { runDir, writer: orderedWriter };
	const nodeFatalReportsEnabled = provenNodeLaunch(options.launch);
	const environment = createCliSubprocessEnv({
		...options.environment,
		[INCIDENT_RECORDER_CHILD_ENV]: "1",
		[INCIDENT_RECORDER_RUN_DIR_ENV]: runDir,
		[INCIDENT_RECORDER_SOCKET_ENV]: options.socketPath,
		[INCIDENT_RECORDER_CAPTURE_FD_ENV]: String(INCIDENT_RECORDER_CAPTURE_FD),
		[INCIDENT_RECORDER_ROOT_FD_ENV]: String(INCIDENT_RECORDER_ROOT_FD),
		[INCIDENT_RECORDER_RUN_ID_ENV]: runId,
		[INCIDENT_RECORDER_RUN_TOKEN_ENV]: runToken,
		...(nodeFatalReportsEnabled ? { NODE_REPORT_DIRECTORY: join(runDir, "raw-reports") } : {}),
	});
	// This wrapper may itself be a captured descendant. The new supervisor is the
	// sole owner of its newly-created fd4 channel and must claim it after exec.
	delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV];
	delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV];
	const launch = nodeFatalReportsEnabled
		? {
				...options.launch,
				args: [
					"--report-on-fatalerror",
					"--report-uncaught-exception",
					`--report-directory=${join(runDir, "raw-reports")}`,
					...options.launch.args,
				],
			}
		: options.launch;
	const cwd = options.cwd ?? process.cwd();
	const exactLaunch = {
		version: 3,
		canonical: false,
		representation: "derived-diagnostic-json-v1",
		preservesRuntimeObjectIdentity: false,
		privacy: "private-local-0600",
		created: nowFields(),
		parent: {
			pid: process.pid,
			processStartId: getProcessStartId(process.pid),
			executable: process.execPath,
			argv: [...process.argv],
			cwd: process.cwd(),
		},
		socketPath: options.socketPath,
		runtimeCategory: nodeFatalReportsEnabled ? "node" : process.versions.bun ? "bun" : "foreign",
		nodeFatalReportsEnabled,
		build: { appVersion: VERSION, release: process.release, versions: process.versions },
		command: launch.command,
		argv: [...launch.args],
		cwd,
		environment,
		derivedCommandSummary: summarizeIncidentCommandLine(launch.args),
	};
	const launchBytes = Buffer.from(JSON.stringify(encodeDiagnosticValue(exactLaunch)), "utf8");
	const launchAdmission = serviceFinalizationNamespaceObserved(runDir)
		? undefined
		: orderedWriter.recordExactBytes(
				"recorder-events",
				"recorder_launch_raw_bytes",
				launchBytes,
				"derived-diagnostic-json-v1",
				{ source: "wrapper-launch-observation" },
			);
	const launchOccurrenceId = launchAdmission?.accepted ? launchAdmission.occurrenceId : undefined;
	const launchArtifact = {
		canonical: false,
		encoding: "derived-diagnostic-json-v1",
		producerOccurrenceId: launchOccurrenceId,
		state: launchAdmission?.accepted ? "locally-admitted-pending-compactor" : "relay-rejected",
		orphanPolicy: "fail-open",
		lifecycleTarget: "real-supervisor-identity",
	};
	writePrivateJson(join(runDir, "launch.json"), {
		version: 2,
		canonical: false,
		purpose: "content-addressed-launch-index",
		socketPath: options.socketPath,
		runtimeCategory: nodeFatalReportsEnabled ? "node" : process.versions.bun ? "bun" : "foreign",
		nodeFatalReportsEnabled,
		launchArtifact,
		derivedCommandSummary: summarizeIncidentCommandLine(launch.args),
	});
	appendRunEvent(runDir, {
		type: "recorder_launch",
		launchOccurrenceId: launchOccurrenceId ?? null,
		launchBytes: launchBytes.length,
		nodeFatalReportsEnabled,
	});
	let child: ChildProcess;
	let recorderRootDescriptor: number | undefined;
	try {
		const canonicalRecorderRoot = realpathSync(join(options.agentDir, "incident-recorder"));
		recorderRootDescriptor = openSync(
			canonicalRecorderRoot,
			fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
		);
		child = spawn(launch.command, launch.args, {
			cwd,
			env: environment,
			stdio: ["inherit", "inherit", "inherit", "ignore", "pipe", recorderRootDescriptor],
		});
		// fd4 is diagnostic-only. fd5 pins the actual canonical recorder root.
	} catch (error) {
		appendRunEvent(runDir, { type: "recorder_spawn_error", error, launchArtifact });
		await orderedWriter.stop().catch(() => undefined);
		activeOrderedWriter = undefined;
		writePrivateJson(join(runDir, ".retention-terminal.json"), {
			completed: nowFields(),
			disposition: "spawn_failed_before_target_identity",
			exitCode: null,
			exitSignal: null,
		});
		rmSync(join(runDir, ACTIVE_MARKER_FILE_NAME), { force: true });
		throw error;
	} finally {
		if (recorderRootDescriptor !== undefined) {
			try {
				closeSync(recorderRootDescriptor);
			} catch {}
		}
	}
	const pid = child.pid;
	if (!pid) {
		// A failed spawn reports ENOENT asynchronously even though no target PID
		// ever existed. Consume that diagnostic event; this branch owns the
		// terminal disposition and no live process can be hidden by it.
		const spawnErrorPromise = new Promise<Error>((resolve) => child.once("error", resolve));
		await orderedWriter.stop().catch(() => undefined);
		const spawnError = await spawnErrorPromise;
		activeOrderedWriter = undefined;
		writePrivateJson(join(runDir, ".retention-terminal.json"), {
			completed: nowFields(),
			disposition: "spawn_failed_before_target_identity",
			exitCode: null,
			exitSignal: null,
			spawnError: serializeError(spawnError),
		});
		rmSync(join(runDir, ACTIVE_MARKER_FILE_NAME), { force: true });
		throw new Error("Incident recorder could not obtain supervisor PID");
	}
	const processStartId = getProcessStartId(pid);
	await orderedWriter.setSourceIdentity({
		bootId: bootId ?? "",
		pid,
		processStartId: processStartId ?? "",
		socketPath: options.socketPath,
	});
	const captureChannel = child.stdio[INCIDENT_RECORDER_CAPTURE_FD];
	if (captureChannel instanceof Readable) orderedWriter.attachCaptureStream(captureChannel);
	else
		appendRunEvent(runDir, {
			type: "capture_channel_unavailable",
			fd: INCIDENT_RECORDER_CAPTURE_FD,
			reason: "missing-pipe",
		});
	appendRunEvent(runDir, {
		type: "supervisor_stdio_source_unavailable",
		stdout: "inherited-to-preserve-original-stream-and-tty-semantics",
		stderr: "inherited-to-preserve-original-stream-and-tty-semantics",
	});
	writePrivateJson(join(runDir, "process.json"), {
		runToken,
		machineId: linuxMachineId(),
		bootId,
		systemdInvocationId: process.env.INVOCATION_ID ?? null,
		pid,
		processStartId,
		observed: nowFields(),
		runtimeCategory: nodeFatalReportsEnabled ? "node" : "foreign",
		nodeFatalReportsEnabled,
		orphanPolicy: "fail-open",
		wrapperDeathSignalsSupervisor: false,
	});
	appendRunEvent(runDir, { type: "supervisor_spawned", childPid: pid, processStartId, nodeFatalReportsEnabled });
	if (!serviceFinalizationNamespaceObserved(runDir))
		orderedWriter.recordDerived("recorder-control", "service_sampling_owner", {
			owner: "incident-recorder-compactor-sampler",
			targetPid: pid,
			targetProcessStartId: processStartId ?? "",
		});
	let exit: { code: number | null; signal: NodeJS.Signals | null };
	try {
		exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolveExit, rejectExit) => {
			child.once("error", rejectExit);
			child.once("close", (code, signal) => resolveExit({ code, signal }));
		});
	} catch (error) {
		appendRunEvent(runDir, { type: "recorder_child_error", error, childPid: pid, processStartId });
		await orderedWriter.stop().catch(() => undefined);
		activeOrderedWriter = undefined;
		try {
			rmSync(join(runDir, ACTIVE_MARKER_FILE_NAME), { force: true });
		} catch {}
		throw error;
	}
	const exitAdmission = serviceFinalizationNamespaceObserved(runDir)
		? undefined
		: orderedWriter.recordDerived("recorder-events", "supervisor_exit", {
				childPid: pid,
				code: exit.code,
				signal: exit.signal,
			});
	await orderedWriter.stop().catch(() => undefined);
	if (exitAdmission?.accepted) {
		const expectation = orderedWriter.finalizationExpectation(exitAdmission.occurrenceId);
		writePrivateJson(join(runDir, "finalization-barrier-expectation.json"), {
			version: 1,
			...expectation,
			exitCode: exit.code ?? "unavailable",
			exitSignal: exit.signal ?? "unavailable",
		});
	}
	activeOrderedWriter = undefined;
	try {
		rmSync(join(runDir, ACTIVE_MARKER_FILE_NAME), { force: true });
	} catch {}
	writePrivateJson(join(runDir, ".retention-terminal.json"), {
		completed: nowFields(),
		exitCode: exit.code,
		exitSignal: exit.signal,
	});
	const classification =
		exit.signal === "SIGABRT"
			? "native_abort"
			: reportIndicatesException(runDir)
				? "uncaught_exception"
				: exit.signal
					? `signal_${exit.signal.toLowerCase()}`
					: exit.code === 143
						? "signal_sigterm"
						: exit.code === 0
							? "normal"
							: `exit_${exit.code ?? "unknown"}`;
	return { code: exit.code, signal: exit.signal, runDir, classification };
}

export async function runRecordedSupervisor(args: readonly string[], socketPath: string): Promise<never> {
	const wrapperStartId = getProcessStartId(process.pid);
	const result = await recordSupervisorProcess({
		agentDir: getAgentDir(),
		socketPath,
		launch: createRecordedSupervisorChildLaunch(args),
		environment: process.env,
	});
	if (result.signal && wrapperStartId && getProcessStartId(process.pid) === wrapperStartId) {
		// Self-signalling preserves the child's exit semantics and cannot target a reused external PID.
		process.kill(process.pid, result.signal);
	}
	process.exit(result.code ?? 1);
}

export type IncidentEvidenceProvider = "audit" | "cgroup" | "ebpf" | "kernel" | "signal";

export type IncidentEvidenceCategory =
	| "oom"
	| "process_exit"
	| "resource_pressure"
	| "signal"
	| "audit"
	| "cgroup"
	| "kernel"
	| "ebpf";
export type IncidentEvidenceOutcome =
	| "observed"
	| "matched"
	| "not_matched"
	| "unavailable"
	| "error"
	| "sent"
	| "not_sent";

export interface IncidentProviderEvidenceBase {
	category: IncidentEvidenceCategory;
	outcome: IncidentEvidenceOutcome;
	reason?: string;
	signal?: string;
	pid?: number;
	targetPid?: number;
	targetTid?: number;
	senderPid?: number;
	senderUid?: number;
	senderPpid?: number;
	count?: number;
	bytes?: number;
	durationMs?: number;
	code?: number;
	oomKillDelta?: number;
	processStartId?: string;
	senderProcessStartId?: string;
	identifier?: string;
	attribution?: "dedicated" | "shared" | "unknown" | "target_cgroup_only";
	executable?: string;
	lineageExecutables?: readonly string[];
	[key: string]: unknown;
}

export interface IncidentAuditProviderEvidence extends IncidentProviderEvidenceBase {
	category: "audit" | "signal";
}

export interface IncidentCgroupProviderEvidence extends IncidentProviderEvidenceBase {
	category: "cgroup" | "oom" | "resource_pressure";
}

export interface IncidentEbpfProviderEvidence extends IncidentProviderEvidenceBase {
	category: "ebpf" | "process_exit" | "signal";
}

export interface IncidentKernelProviderEvidence extends IncidentProviderEvidenceBase {
	category: "kernel" | "oom" | "resource_pressure";
}

export interface IncidentSignalProviderEvidence extends IncidentProviderEvidenceBase {
	category: "signal";
}

export interface IncidentProviderEvidenceMap {
	audit: IncidentAuditProviderEvidence;
	cgroup: IncidentCgroupProviderEvidence;
	ebpf: IncidentEbpfProviderEvidence;
	kernel: IncidentKernelProviderEvidence;
	signal: IncidentSignalProviderEvidence;
}

export type IncidentProviderArtifactSource = "atop" | "sysdig" | "lttng";

export interface IncidentProviderSourceManifest {
	provider: IncidentProviderArtifactSource;
	artifacts: ReadonlyArray<{
		path: string;
		format?: string;
		dev?: number;
		ino?: number;
		bytes?: number;
		sha256?: string;
		[key: string]: unknown;
	}>;
	configuration?: unknown;
	version?: unknown;
	clocks?: unknown;
	lossCounters?: unknown;
	[key: string]: unknown;
}

function safeProcessStartId(value: unknown): string | undefined {
	return typeof value === "string" &&
		(/^(?:proc|win):\d+$/.test(value) ||
			/^ps:[A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}$/.test(value))
		? value
		: undefined;
}

function evidenceTarget(runDir: string): Record<string, unknown> | undefined {
	const target = readSmallJson<{ pid?: unknown; processStartId?: unknown }>(join(runDir, "process.json"));
	const pid = finiteNumber(target?.pid);
	const processStartId = safeProcessStartId(target?.processStartId);
	return pid !== undefined && Number.isSafeInteger(pid) && pid > 0 && processStartId
		? { pid, processStartId }
		: { identityUnavailable: true, reason: "target_identity_unavailable" };
}

function rawProviderPayload(value: unknown): { bytes: Buffer; encoding: string } {
	if (Buffer.isBuffer(value)) return { bytes: value, encoding: "opaque-provider-bytes" };
	if (value instanceof Uint8Array) {
		return {
			bytes: Buffer.from(value.buffer, value.byteOffset, value.byteLength),
			encoding: "opaque-provider-bytes",
		};
	}
	return {
		bytes: Buffer.from(JSON.stringify(encodeDiagnosticValue(value)), "utf8"),
		encoding: "utf8-json/derived-diagnostic-json-v1",
	};
}

interface ProviderRawSegmentState {
	runDir: string;
	source: RawApplicationSource;
	segmentIndex: number;
	segmentBytes: number;
	segmentOpenedMs: number;
}

interface ProviderRootMutationContext {
	root: IncidentCasRootMutation;
	originalRunDir: string;
	directoryIdentity: ServiceRunDirectoryIdentity;
	runDir: string;
	runPath: IncidentCasRelativePath;
	runComponents: readonly [string, string];
	segmentStates: Map<RawApplicationSource, ProviderRawSegmentState>;
	rawRecordSequence: number;
	providerOccurrenceSequence: number;
}

interface ProviderRootMutationCommit {
	segmentStates: ProviderRawSegmentState[];
	rawRecordSequence: number;
	providerOccurrenceSequence: number;
	persistedAdmissionLoss?: {
		batchId: string;
		blockedAdmissions: number;
	};
}

function capabilityErrorCode(error: unknown): string | undefined {
	return error && typeof error === "object" && typeof (error as { code?: unknown }).code === "string"
		? String((error as { code: string }).code)
		: undefined;
}

function providerRunRelativeComponents(runDir: string): readonly [string, string] {
	const recorderRoot = resolve(dirname(dirname(runDir)));
	const resolvedRun = resolve(runDir);
	const components = relativePath(recorderRoot, resolvedRun).split(sep);
	if (
		components.length !== 2 ||
		components[0] !== "runs" ||
		components.some((component) => component.length === 0 || component === "." || component === "..")
	) {
		throw new Error("Provider evidence run is not directly beneath the recorder runs directory");
	}
	return [components[0], components[1]];
}

function createProviderRootMutationContext(
	root: IncidentCasRootMutation,
	runDir: string,
	expectedIdentity?: ServiceRunDirectoryIdentity,
): ProviderRootMutationContext {
	const directoryIdentity = expectedIdentity ?? fallbackAdmissionRunIdentity(runDir);
	if (!directoryIdentity || !fallbackAdmissionRunIdentityMatches(runDir, directoryIdentity)) {
		throw new Error("Provider evidence run directory identity changed");
	}
	const runComponents = providerRunRelativeComponents(runDir);
	const runPath = root.relative(...runComponents);
	const runStat = root.lstat(runPath);
	const expectedUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : runStat?.uid;
	if (
		!runStat?.isDirectory() ||
		runStat.isSymbolicLink() ||
		runStat.uid !== expectedUid ||
		(runStat.mode & 0o077n) !== 0n
	) {
		throw new Error("Provider evidence run directory is not private and stable");
	}
	if (!fallbackAdmissionRunIdentityMatches(runDir, directoryIdentity)) {
		throw new Error("Provider evidence run directory identity changed");
	}
	const canonicalRunPath = root.publicPath(root.realpath(runPath));
	if (canonicalRunPath !== root.publicPath(runPath)) {
		throw new Error("Provider evidence run directory is not canonical beneath the retained root");
	}
	return {
		root,
		originalRunDir: runDir,
		directoryIdentity,
		runDir: canonicalRunPath,
		runPath,
		runComponents,
		segmentStates: new Map(),
		rawRecordSequence,
		providerOccurrenceSequence,
	};
}

function providerRunPath(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	...components: string[]
): IncidentCasRelativePath {
	return root.relative(...context.runComponents, ...components);
}

function readProviderRootJson<T>(
	root: IncidentCasRootMutation,
	path: IncidentCasRelativePath,
	limit = INCIDENT_RECORDER_LIMITS.evidenceFileBytes,
): T | undefined {
	try {
		const before = root.lstat(path);
		const expectedUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : before?.uid;
		if (
			!before?.isFile() ||
			before.isSymbolicLink() ||
			before.uid !== expectedUid ||
			(before.mode & 0o077n) !== 0n ||
			before.size <= 0n ||
			before.size > BigInt(limit)
		) {
			return undefined;
		}
		const bytes = root.readFile(path, limit);
		const after = root.lstat(path);
		if (!after || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) {
			return undefined;
		}
		return JSON.parse(bytes.toString("utf8")) as T;
	} catch {
		return undefined;
	}
}

function providerFinalizationNamespaceObserved(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
): boolean {
	return [
		"service-finalization-seal-intent.json",
		"service-finalization-seal.json",
		"service-finalization-seal-replay-ambiguity.json",
	].some((name) => root.exists(providerRunPath(root, context, name)));
}

function providerRunHasLiveWriter(root: IncidentCasRootMutation, context: ProviderRootMutationContext): boolean {
	const marker = readProviderRootJson<Record<string, unknown>>(
		root,
		providerRunPath(root, context, ACTIVE_MARKER_FILE_NAME),
	);
	if (
		marker !== undefined &&
		marker.machineId === linuxMachineId() &&
		marker.bootId === linuxBootId() &&
		typeof marker.pid === "number" &&
		Number.isSafeInteger(marker.pid) &&
		marker.pid > 0 &&
		typeof marker.processStartId === "string" &&
		getProcessStartId(marker.pid) === marker.processStartId
	) {
		return true;
	}
	const processControl = readProviderRootJson<Record<string, unknown>>(
		root,
		providerRunPath(root, context, "process.json"),
	);
	const runId = context.runComponents[1].slice(-36);
	return (
		CANONICAL_UUID.test(runId) &&
		processControl !== undefined &&
		processControl.machineId === linuxMachineId() &&
		processControl.bootId === linuxBootId() &&
		typeof processControl.pid === "number" &&
		Number.isSafeInteger(processControl.pid) &&
		processControl.pid > 0 &&
		typeof processControl.processStartId === "string" &&
		typeof processControl.runToken === "string" &&
		CANONICAL_UUID.test(processControl.runToken) &&
		processEnvironmentBindsServiceRun(
			processControl.pid,
			processControl.processStartId,
			runId,
			processControl.runToken,
		)
	);
}

function evidenceTargetWithinRoot(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
): Record<string, unknown> {
	const target = readProviderRootJson<{ pid?: unknown; processStartId?: unknown }>(
		root,
		providerRunPath(root, context, "process.json"),
	);
	const pid = finiteNumber(target?.pid);
	const processStartId = safeProcessStartId(target?.processStartId);
	return pid !== undefined && Number.isSafeInteger(pid) && pid > 0 && processStartId
		? { pid, processStartId }
		: { identityUnavailable: true, reason: "target_identity_unavailable" };
}

function writeProviderRootBytesExclusive(
	root: IncidentCasRootMutation,
	path: IncidentCasRelativePath,
	bytes: Uint8Array,
): void {
	root.writeFileExclusive(path, bytes, 0o600);
	root.chmod(path, 0o600);
}

function appendProviderRootBytes(
	root: IncidentCasRootMutation,
	path: IncidentCasRelativePath,
	bytes: Uint8Array,
): number {
	try {
		return root.withFile(path, { access: "read_write" }, (file) => {
			const before = file.stat();
			if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Provider evidence append is too large");
			let offset = 0;
			const position = Number(before.size);
			while (offset < bytes.byteLength) {
				const count = file.write(bytes, offset, bytes.byteLength - offset, position + offset);
				if (count <= 0) throw new Error("Provider evidence append made no progress");
				offset += count;
			}
			file.chmod(0o600);
			file.sync();
			return position + bytes.byteLength;
		});
	} catch (error) {
		if (capabilityErrorCode(error) !== "ENOENT") throw error;
		writeProviderRootBytesExclusive(root, path, bytes);
		return bytes.byteLength;
	}
}

function providerDirectoryEntries(
	root: IncidentCasRootMutation,
	directory: IncidentCasRelativePath,
): Array<{ name: string; kind: string }> {
	const entries: Array<{ name: string; kind: string }> = [];
	let afterName: string | undefined;
	for (let pageIndex = 0; pageIndex < 4_096; pageIndex += 1) {
		const page = root.directoryPage(directory, {
			afterName,
			limit: INCIDENT_RECORDER_LIMITS.maxDirectoryEntries,
		});
		if (afterName !== undefined && !page.cursorFound) {
			throw new Error("Provider raw directory cursor changed during traversal");
		}
		entries.push(...page.entries);
		if (page.complete) return entries;
		if (!page.nextAfterName || page.nextAfterName === afterName) {
			throw new Error("Provider raw directory traversal made no progress");
		}
		afterName = page.nextAfterName;
	}
	throw new Error("Provider raw directory traversal exceeded its page bound");
}

function readProviderRawBlob(
	root: IncidentCasRootMutation,
	path: IncidentCasRelativePath,
	digest: string,
): Buffer | undefined {
	try {
		const before = root.lstat(path);
		const expectedUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : before?.uid;
		if (
			!before?.isFile() ||
			before.isSymbolicLink() ||
			before.uid !== expectedUid ||
			(before.mode & 0o077n) !== 0n ||
			before.size <= 0n ||
			before.size > BigInt(INCIDENT_RECORDER_LIMITS.evidenceFileBytes)
		) {
			return undefined;
		}
		const bytes = root.readFile(path, INCIDENT_RECORDER_LIMITS.evidenceFileBytes);
		const after = root.lstat(path);
		if (!after || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) {
			return undefined;
		}
		return createHash("sha256").update(bytes).digest("hex") === digest ? bytes : undefined;
	} catch {
		return undefined;
	}
}

function providerRawPayloadFields(
	root: IncidentCasRootMutation,
	envelope: Record<string, unknown>,
): Record<string, unknown> | undefined {
	let encodedFields = envelope.fields;
	const reference =
		envelope.payloadBlob && typeof envelope.payloadBlob === "object"
			? (envelope.payloadBlob as Partial<RawBlobReference>)
			: undefined;
	if (reference && typeof reference.digest === "string" && /^[0-9a-f]{64}$/i.test(reference.digest)) {
		const digest = reference.digest.toLowerCase();
		const directory = root.relative("cas", "sha256", digest.slice(0, 2));
		const candidates: IncidentCasRelativePath[] = [
			root.relative("cas", "sha256", digest.slice(0, 2), `${digest}.blob`),
		];
		try {
			for (const entry of providerDirectoryEntries(root, directory)) {
				if (
					entry.kind === "file" &&
					entry.name.startsWith(`${digest}.collision-`) &&
					entry.name.endsWith(".blob")
				) {
					candidates.push(root.relative("cas", "sha256", digest.slice(0, 2), entry.name));
				}
			}
		} catch {
			// The canonical blob may still be readable when collision discovery is unavailable.
		}
		for (const candidate of candidates) {
			const payload = readProviderRawBlob(root, candidate, digest);
			if (!payload) continue;
			if (typeof reference.bytes === "number" && payload.byteLength !== reference.bytes) {
				continue;
			}
			try {
				encodedFields = JSON.parse(payload.toString("utf8"));
				break;
			} catch {
				// Preserve the raw envelope as opaque evidence when its blob is malformed.
			}
		}
	}
	const decoded = decodeDiagnosticValue(encodedFields);
	return decoded && typeof decoded === "object" && !Array.isArray(decoded)
		? (decoded as Record<string, unknown>)
		: undefined;
}

function readProviderRawEventSource(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	source: RawApplicationSource,
): IncidentRecorderEvent[] {
	const directory = providerRunPath(root, context, RAW_APPLICATION_DIR_NAME, source);
	let names: string[];
	try {
		names = providerDirectoryEntries(root, directory)
			.filter((entry) => entry.kind === "file" && /^segment-\d{8}\.jsonl$/.test(entry.name))
			.map((entry) => entry.name)
			.sort();
	} catch {
		return [];
	}
	const frames = new Map<string, { chunkCount: number; chunks: Map<number, Buffer> }>();
	for (const name of names) {
		const path = providerRunPath(root, context, RAW_APPLICATION_DIR_NAME, source, name);
		let value: Buffer;
		try {
			const stat = root.lstat(path);
			if (!stat?.isFile() || stat.isSymbolicLink() || stat.size > BigInt(INCIDENT_RECORDER_LIMITS.rawSegmentBytes)) {
				continue;
			}
			value = root.readFile(path, INCIDENT_RECORDER_LIMITS.rawSegmentBytes);
		} catch {
			continue;
		}
		for (const line of value.toString("utf8").split("\n").filter(Boolean)) {
			try {
				const frame = JSON.parse(line) as Partial<RawRecordFrame>;
				if (
					typeof frame.recordId !== "string" ||
					typeof frame.chunkIndex !== "number" ||
					typeof frame.chunkCount !== "number" ||
					!Number.isSafeInteger(frame.chunkIndex) ||
					!Number.isSafeInteger(frame.chunkCount) ||
					frame.chunkIndex < 0 ||
					frame.chunkCount <= 0 ||
					frame.chunkIndex >= frame.chunkCount ||
					frame.encoding !== "base64" ||
					typeof frame.payload !== "string"
				) {
					continue;
				}
				const chunkIndex = frame.chunkIndex;
				const chunkCount = frame.chunkCount;
				const record = frames.get(frame.recordId) ?? {
					chunkCount,
					chunks: new Map<number, Buffer>(),
				};
				if (record.chunkCount !== chunkCount) continue;
				record.chunks.set(chunkIndex, Buffer.from(frame.payload, "base64"));
				frames.set(frame.recordId, record);
			} catch {
				// Incomplete or malformed frames remain raw evidence but are not trusted as receipts.
			}
		}
	}
	const events: IncidentRecorderEvent[] = [];
	for (const record of frames.values()) {
		if (record.chunks.size !== record.chunkCount) continue;
		try {
			const chunks = Array.from({ length: record.chunkCount }, (_, index) => record.chunks.get(index));
			if (chunks.some((chunk) => chunk === undefined)) continue;
			const envelope = JSON.parse(Buffer.concat(chunks as Buffer[]).toString("utf8")) as Record<string, unknown>;
			const fields = providerRawPayloadFields(root, envelope);
			if (
				fields &&
				typeof envelope.type === "string" &&
				typeof envelope.wallTime === "string" &&
				typeof envelope.monotonicNs === "string" &&
				typeof envelope.pid === "number"
			) {
				events.push({
					...fields,
					type: envelope.type,
					wallTime: envelope.wallTime,
					monotonicNs: envelope.monotonicNs,
					pid: envelope.pid,
				});
			}
		} catch {
			// A malformed provider record remains noncanonical raw input.
		}
	}
	return events;
}

function observeProviderFallbackEvidenceAdmissionRaw(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	batchId: string,
): FallbackEvidenceAdmissionRawObservation {
	return observeFallbackEvidenceAdmissionRawRecords(
		readProviderRawEventSource(root, context, "loss-accounting").filter(
			(record) => record.admissionBatchId === batchId,
		),
	);
}

function loadProviderRawSegmentState(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	source: RawApplicationSource,
): ProviderRawSegmentState {
	const cached = context.segmentStates.get(source);
	if (cached) return cached;
	const directory = providerRunPath(root, context, RAW_APPLICATION_DIR_NAME, source);
	root.mkdirPrivate(directory, true);
	const indexes = providerDirectoryEntries(root, directory).flatMap((entry) => {
		const match = entry.kind === "file" ? entry.name.match(/^segment-(\d{8})\.jsonl$/) : undefined;
		return match ? [Number(match[1])] : [];
	});
	const segmentIndex = indexes.length > 0 ? Math.max(...indexes) : 0;
	const segment = providerRunPath(
		root,
		context,
		RAW_APPLICATION_DIR_NAME,
		source,
		`segment-${String(segmentIndex).padStart(8, "0")}.jsonl`,
	);
	const stat = root.lstat(segment);
	const state: ProviderRawSegmentState = {
		runDir: context.runDir,
		source,
		segmentIndex,
		segmentBytes: stat?.isFile() && !stat.isSymbolicLink() ? Number(stat.size) : 0,
		segmentOpenedMs: stat?.isFile() && !stat.isSymbolicLink() ? Number(stat.birthtimeMs || stat.mtimeMs) : Date.now(),
	};
	context.segmentStates.set(source, state);
	return state;
}

function writeProviderRootJsonAtomic(
	root: IncidentCasRootMutation,
	directory: IncidentCasRelativePath,
	path: IncidentCasRelativePath,
	temporary: IncidentCasRelativePath,
	value: unknown,
): void {
	try {
		writeProviderRootBytesExclusive(root, temporary, Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8"));
		root.rename(temporary, path);
		root.chmod(path, 0o600);
		root.fsyncDirectory(directory);
	} finally {
		try {
			if (root.exists(temporary)) root.unlinkFile(temporary);
		} catch {}
	}
}

function currentProviderFallbackEvidenceAdmissionLoss(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
): FallbackEvidenceAdmissionLoss | undefined {
	return parseFallbackEvidenceAdmissionLoss(
		readProviderRootJson<unknown>(
			root,
			providerRunPath(root, context, "service-finalization-fallback-admission-loss.json"),
		),
		context.runComponents[1].slice(-36),
	);
}

function persistProviderFallbackEvidenceAdmissionLossControl(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	loss: FallbackEvidenceAdmissionLoss,
): void {
	const path = providerRunPath(root, context, "service-finalization-fallback-admission-loss.json");
	for (let attempt = 0; attempt < 2; attempt += 1) {
		const current = readProviderRootJson<unknown>(root, path);
		const parsed = parseFallbackEvidenceAdmissionLoss(current, context.runComponents[1].slice(-36));
		if (parsed && canonicalJsonValuesEqual(parsed, loss)) return;
		if (!parsed && root.exists(path)) {
			const quarantine = providerRunPath(root, context, ".service-control-quarantine");
			root.mkdirPrivate(quarantine, true);
			root.rename(
				path,
				providerRunPath(
					root,
					context,
					".service-control-quarantine",
					`fallback-admission-loss-${randomUUID()}.invalid`,
				),
			);
			root.fsyncDirectory(quarantine);
			root.fsyncDirectory(context.runPath);
		}
		writeProviderRootJsonAtomic(
			root,
			context.runPath,
			path,
			providerRunPath(
				root,
				context,
				`.service-finalization-fallback-admission-loss.tmp-${process.pid}-${randomUUID()}`,
			),
			loss,
		);
		const readback = readProviderRootJson<unknown>(root, path);
		if (readback !== undefined && canonicalJsonValuesEqual(readback, loss)) return;
	}
	throw new Error("Fallback admission loss authority could not be persisted through the retained root");
}

function writeProviderRawSegmentManifest(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	state: ProviderRawSegmentState,
): void {
	const directory = providerRunPath(root, context, RAW_APPLICATION_DIR_NAME, state.source);
	const segments = providerDirectoryEntries(root, directory)
		.filter((entry) => entry.kind === "file" && /^segment-\d{8}\.jsonl$/.test(entry.name))
		.sort((left, right) => left.name.localeCompare(right.name))
		.map((entry) => {
			const stat = root.stat(providerRunPath(root, context, RAW_APPLICATION_DIR_NAME, state.source, entry.name));
			return {
				file: entry.name,
				bytes: Number(stat.size),
				mode: Number(stat.mode & 0o777n),
				mtimeMs: Number(stat.mtimeMs),
			};
		});
	writeProviderRootJsonAtomic(
		root,
		directory,
		providerRunPath(root, context, RAW_APPLICATION_DIR_NAME, state.source, "manifest.json"),
		providerRunPath(
			root,
			context,
			RAW_APPLICATION_DIR_NAME,
			state.source,
			`.manifest.tmp-${process.pid}-${randomUUID()}`,
		),
		{
			schemaVersion: 1,
			source: state.source,
			canonical: false,
			encoding: "json-lines/base64-chunked-utf8-json",
			rotation: { bytes: INCIDENT_RECORDER_LIMITS.rawSegmentBytes, milliseconds: RAW_SEGMENT_ROTATION_MS },
			checkpointMilliseconds: RAW_MANIFEST_CHECKPOINT_MS,
			segments,
			updated: nowFields(),
		},
	);
}

function writeProviderRawLines(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	state: ProviderRawSegmentState,
	lines: readonly string[],
): void {
	if (providerFinalizationNamespaceObserved(root, context)) {
		throw new Error("Run evidence namespace is durably fenced");
	}
	for (const line of lines) {
		const bytes = Buffer.from(line, "utf8");
		if (
			state.segmentBytes > 0 &&
			(state.segmentBytes + bytes.byteLength > INCIDENT_RECORDER_LIMITS.rawSegmentBytes ||
				Date.now() - state.segmentOpenedMs >= RAW_SEGMENT_ROTATION_MS)
		) {
			state.segmentIndex += 1;
			state.segmentBytes = 0;
			state.segmentOpenedMs = Date.now();
			writeProviderRawSegmentManifest(root, context, state);
		}
		const path = providerRunPath(
			root,
			context,
			RAW_APPLICATION_DIR_NAME,
			state.source,
			`segment-${String(state.segmentIndex).padStart(8, "0")}.jsonl`,
		);
		state.segmentBytes = appendProviderRootBytes(root, path, bytes);
	}
	writeProviderRawSegmentManifest(root, context, state);
}

function leaseProviderRawBlob(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	source: IncidentCasRelativePath,
	fileName: string,
): void {
	const directory = providerRunPath(root, context, ".cas-leases");
	root.mkdirPrivate(directory, true);
	const target = providerRunPath(root, context, ".cas-leases", fileName);
	try {
		root.hardLink(source, target);
	} catch (error) {
		if (capabilityErrorCode(error) !== "EEXIST") throw error;
		const sourceStat = root.stat(source);
		const targetStat = root.stat(target);
		if (
			!sourceStat.isFile() ||
			sourceStat.isSymbolicLink() ||
			!targetStat.isFile() ||
			targetStat.isSymbolicLink() ||
			sourceStat.dev !== targetStat.dev ||
			sourceStat.ino !== targetStat.ino
		) {
			throw new Error("CAS lease collision");
		}
	}
	root.fsyncDirectory(directory);
}

function contentAddressRawBytesSync(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	source: RawApplicationSource,
	value: Uint8Array,
	encoding: string,
): RawBlobReference {
	if (providerFinalizationNamespaceObserved(root, context)) {
		throw new Error("Run evidence namespace is durably fenced");
	}
	const bytes = Buffer.from(value);
	const digest = createHash("sha256").update(bytes).digest("hex");
	const directory = root.relative("cas", "sha256", digest.slice(0, 2));
	root.mkdirPrivate(directory, true);
	const canonicalName = `${digest}.blob`;
	const collisionName = `${digest}.collision-${process.pid}-${randomUUID()}.blob`;
	const temporaryName = `.${digest}.tmp-${process.pid}-${randomUUID()}`;
	const path = root.relative("cas", "sha256", digest.slice(0, 2), canonicalName);
	const collisionFallback = root.relative("cas", "sha256", digest.slice(0, 2), collisionName);
	const temporary = root.relative("cas", "sha256", digest.slice(0, 2), temporaryName);
	const publicPath = root.publicPath(path);
	const publicCollisionFallbackPath = root.publicPath(collisionFallback);
	let selected = path;
	let selectedName = canonicalName;
	try {
		writeProviderRootBytesExclusive(root, temporary, bytes);
		let canonicalPublished = false;
		try {
			root.hardLink(temporary, path);
			canonicalPublished = true;
		} catch (error) {
			if (capabilityErrorCode(error) !== "EEXIST") throw error;
		}
		if (canonicalPublished) {
			root.chmod(path, 0o600);
			root.unlinkFile(temporary);
		} else {
			const existing = root.lstat(path);
			if (!existing?.isFile() || existing.isSymbolicLink()) {
				throw new Error("Existing CAS digest occupant is not a regular file");
			}
			const matches =
				existing.size === BigInt(bytes.byteLength) && root.readFile(path, bytes.byteLength).equals(bytes);
			if (matches) {
				root.unlinkFile(temporary);
			} else {
				root.rename(temporary, collisionFallback);
				root.chmod(collisionFallback, 0o600);
				selected = collisionFallback;
				selectedName = collisionName;
				if (source !== "loss-accounting") {
					recordProviderRawLoss(
						root,
						context,
						source,
						{
							name: "RawContentAddressCollisionError",
							message: "Existing SHA-256 blob did not match the captured bytes",
							digest,
							path: publicPath,
							collisionFallbackPath: publicCollisionFallbackPath,
						},
						bytes.byteLength,
					);
				}
			}
		}
		root.fsyncDirectory(directory);
		leaseProviderRawBlob(root, context, selected, selectedName);
	} catch (error) {
		try {
			if (root.exists(temporary)) root.unlinkFile(temporary);
		} catch {}
		if (source !== "loss-accounting") recordProviderRawLoss(root, context, source, error, bytes.byteLength);
		throw error;
	}
	return {
		algorithm: "sha256",
		digest,
		bytes: bytes.byteLength,
		path: publicPath,
		collisionFallbackPath: publicCollisionFallbackPath,
		encoding,
	};
}

function serializeProviderRawRecord(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	source: RawApplicationSource,
	type: string,
	fields: Record<string, unknown>,
): string[] {
	const timestamp = nowFields();
	const sequence = ++context.rawRecordSequence;
	const recordId = `${process.pid}:${sequence}:${randomUUID()}`;
	const payloadBytes = Buffer.from(JSON.stringify(encodeDiagnosticValue(fields)), "utf8");
	const payloadBlob = contentAddressRawBytesSync(
		root,
		context,
		source,
		payloadBytes,
		"utf8-json/derived-diagnostic-json-v1",
	);
	const envelope = {
		schemaVersion: RAW_RECORD_SCHEMA_VERSION,
		recordId,
		sequence,
		...timestamp,
		pid: process.pid,
		processStartId: getProcessStartId(process.pid),
		type,
		provenance: {
			source,
			capture: "private-local-derived-diagnostic",
			canonical: false,
			preservesObjectGraphIdentity: false,
			preservesRuntimeObjectIdentity: false,
			valueEncoding: "derived-diagnostic-json-v1",
			characterEncoding: "utf-8",
			frameEncoding: "json-lines/base64",
			executable: process.execPath,
			argv: [...process.argv],
			cwd: process.cwd(),
			runtime: {
				release: process.release,
				versions: process.versions,
				platform: process.platform,
				arch: process.arch,
			},
		},
		payloadBlob,
	};
	const serialized = Buffer.from(JSON.stringify(envelope), "utf8");
	const chunkCount = Math.max(1, Math.ceil(serialized.length / RAW_FRAME_PAYLOAD_BYTES));
	return Array.from({ length: chunkCount }, (_, chunkIndex) => {
		const frame: RawRecordFrame = {
			schemaVersion: 1,
			recordId,
			chunkIndex,
			chunkCount,
			encoding: "base64",
			payload: serialized
				.subarray(chunkIndex * RAW_FRAME_PAYLOAD_BYTES, (chunkIndex + 1) * RAW_FRAME_PAYLOAD_BYTES)
				.toString("base64"),
		};
		return `${JSON.stringify(frame)}\n`;
	});
}

function recordProviderRawLoss(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	source: RawApplicationSource,
	error: unknown,
	attemptedBytes: number,
): void {
	if (source === "loss-accounting" || providerFinalizationNamespaceObserved(root, context)) return;
	try {
		writeProviderRawLines(
			root,
			context,
			loadProviderRawSegmentState(root, context, "loss-accounting"),
			serializeProviderRawRecord(root, context, "loss-accounting", "raw_capture_loss", {
				source,
				attemptedBytes,
				error: serializeError(error),
			}),
		);
	} catch {
		// Loss accounting remains best effort after the original capability failure.
	}
}

function persistProviderFallbackEvidenceAdmissionBackpressure(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	pending: FallbackEvidenceAdmissionBackpressure,
): { batchId: string; blockedAdmissions: number } {
	const runId = context.runComponents[1].slice(-36);
	if (!CANONICAL_UUID.test(runId)) throw new Error("Fallback admission loss run identity is invalid");
	if (!fallbackAdmissionRunIdentityMatches(context.originalRunDir, pending.runIdentity)) {
		throw new Error("Fallback admission loss run directory identity changed");
	}
	const plan = cumulativeFallbackEvidenceAdmissionLoss(
		runId,
		currentProviderFallbackEvidenceAdmissionLoss(root, context),
		pending,
		observeProviderFallbackEvidenceAdmissionRaw(root, context, pending.batchId),
	);
	persistProviderFallbackEvidenceAdmissionLossControl(root, context, plan.reservedLoss);
	if (plan.rawDeltaAdmissions > 0) {
		writeProviderRawLines(
			root,
			context,
			loadProviderRawSegmentState(root, context, "loss-accounting"),
			serializeProviderRawRecord(root, context, "loss-accounting", "fallback_run_evidence_admission_loss", {
				cause: fallbackEvidenceAdmissionPrimaryCause(plan.rawDeltaCauses),
				causes: plan.rawDeltaCauses,
				admissionBatchId: pending.batchId,
				lostAdmissions: plan.rawDeltaAdmissions,
				firstObservedWallTimeMs: pending.firstObservedWallTimeMs,
				lastObservedWallTimeMs: pending.lastObservedWallTimeMs,
				rawStartAdmissions: plan.rawStart,
				rawEndAdmissions: plan.rawEnd,
				synchronousAttemptLimit: FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS,
				synchronousWaitIntervalMs: FALLBACK_EVIDENCE_ADMISSION_WAIT_MS,
				asynchronousRetryAttempts: pending.retryAttempts,
				disposition: "loss_recorded_after_admission_recovered",
			}),
		);
		runProviderFallbackAdmissionPostRawTestSynchronization();
	}
	if (!fallbackAdmissionRunIdentityMatches(context.originalRunDir, pending.runIdentity)) {
		throw new Error("Fallback admission loss run directory identity changed");
	}
	persistProviderFallbackEvidenceAdmissionLossControl(root, context, plan.completedLoss);
	if (!fallbackAdmissionRunIdentityMatches(context.originalRunDir, pending.runIdentity)) {
		throw new Error("Fallback admission loss run directory identity changed");
	}
	return { batchId: pending.batchId, blockedAdmissions: pending.blockedAdmissions };
}

function appendProviderRunEvent(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	event: { type: string; [key: string]: unknown },
): void {
	const { type, ...fields } = event;
	try {
		writeProviderRawLines(
			root,
			context,
			loadProviderRawSegmentState(root, context, "recorder-events"),
			serializeProviderRawRecord(root, context, "recorder-events", type, fields),
		);
	} catch (error) {
		recordProviderRawLoss(root, context, "recorder-events", error, 0);
	}
}

function appendProviderReferenceEnvelope(
	root: IncidentCasRootMutation,
	context: ProviderRootMutationContext,
	fileName: string,
	envelope: Record<string, unknown>,
	source: "provider-evidence" | "provider-manifest",
): void {
	beginProviderReferenceWrite(context.originalRunDir);
	const serialized = Buffer.from(`${JSON.stringify(envelope)}\n`, "utf8");
	try {
		if (providerFinalizationNamespaceObserved(root, context)) return;
		const evidenceDirectory = providerRunPath(root, context, "evidence");
		root.mkdirPrivate(evidenceDirectory, true);
		appendProviderRootBytes(root, providerRunPath(root, context, "evidence", fileName), serialized);
		root.fsyncDirectory(evidenceDirectory);
		root.fsyncDirectory(context.runPath);
	} catch (error) {
		recordProviderRawLoss(root, context, source, error, serialized.byteLength);
	} finally {
		finishProviderReferenceWrite(context.originalRunDir);
	}
}

function providerRootMutationCommit(
	context: ProviderRootMutationContext,
	persistedAdmissionLoss?: ProviderRootMutationCommit["persistedAdmissionLoss"],
): ProviderRootMutationCommit {
	return {
		segmentStates: [...context.segmentStates.values()].map((state) => ({ ...state })),
		rawRecordSequence: context.rawRecordSequence,
		providerOccurrenceSequence: context.providerOccurrenceSequence,
		...(persistedAdmissionLoss ? { persistedAdmissionLoss } : {}),
	};
}

function applyProviderRootMutationCommit(runDir: string, commit: ProviderRootMutationCommit): void {
	rawRecordSequence = Math.max(rawRecordSequence, commit.rawRecordSequence);
	providerOccurrenceSequence = Math.max(providerOccurrenceSequence, commit.providerOccurrenceSequence);
	for (const state of commit.segmentStates) {
		rawSegmentStates.set(`${state.runDir}\0${state.source}`, {
			...state,
			directory: rawSourceDirectory(state.runDir, state.source),
		});
	}
	const persisted = commit.persistedAdmissionLoss;
	if (!persisted) return;
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	if (pending?.batchId === persisted.batchId && pending.blockedAdmissions <= persisted.blockedAdmissions) {
		fallbackEvidenceAdmissionBackpressure.delete(runDir);
		cancelFallbackEvidenceAdmissionRetry(runDir);
		return;
	}
	if (pending) scheduleFallbackEvidenceAdmissionRetry(runDir);
}

type ProviderFallbackAdmission =
	| {
			state: "acquired";
			transaction: CasTransaction;
			runIdentity: ServiceRunDirectoryIdentity;
	  }
	| { state: "unavailable"; reason: "fenced" | "release_pending" | "busy" };

function acquireProviderFallbackAdmission(runDir: string): ProviderFallbackAdmission {
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	const runIdentity = pending?.runIdentity ?? fallbackAdmissionRunIdentity(runDir);
	if (!runIdentity) return { state: "unavailable", reason: "fenced" };
	if (!fallbackAdmissionRunIdentityMatches(runDir, runIdentity)) {
		noteFallbackEvidenceAdmissionBackpressure(runDir, "root_detached_pending", runIdentity);
		return { state: "unavailable", reason: "fenced" };
	}
	if (serviceFinalizationNamespaceObserved(runDir)) return { state: "unavailable", reason: "fenced" };
	for (let attempt = 0; attempt < FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS; attempt += 1) {
		if (!fallbackAdmissionRunIdentityMatches(runDir, runIdentity)) {
			noteFallbackEvidenceAdmissionBackpressure(runDir, "root_detached_pending", runIdentity);
			return { state: "unavailable", reason: "fenced" };
		}
		const admission = acquireIncidentCasTransactionDetailed(dirname(dirname(runDir)));
		if (admission.state === "acquired") {
			if (!fallbackAdmissionRunIdentityMatches(runDir, runIdentity)) {
				try {
					admission.transaction.release();
				} catch {}
				noteFallbackEvidenceAdmissionBackpressure(runDir, "root_detached_pending", runIdentity);
				return { state: "unavailable", reason: "fenced" };
			}
			return { ...admission, runIdentity };
		}
		if (admission.reason === "release_pending") {
			return { state: "unavailable", reason: "release_pending" };
		}
		if (serviceFinalizationNamespaceObserved(runDir)) return { state: "unavailable", reason: "fenced" };
		if (attempt + 1 < FALLBACK_EVIDENCE_ADMISSION_ATTEMPTS) {
			Atomics.wait(casTransactionRetryWait, 0, 0, FALLBACK_EVIDENCE_ADMISSION_WAIT_MS);
		}
	}
	noteFallbackEvidenceAdmissionBackpressure(runDir, "cross_process_cas_transaction_backpressure", runIdentity);
	return { state: "unavailable", reason: "busy" };
}

function fallbackEvidenceAdmissionBackpressureSnapshot(
	runDir: string,
): FallbackEvidenceAdmissionBackpressure | undefined {
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	return pending ? { ...pending, causes: { ...pending.causes } } : undefined;
}

function runProviderFallbackMutation(
	runDir: string,
	source: "provider-evidence" | "provider-manifest",
	operation: (root: IncidentCasRootMutation, context: ProviderRootMutationContext) => void,
): void {
	let admission: ProviderFallbackAdmission;
	try {
		admission = acquireProviderFallbackAdmission(runDir);
	} catch (error) {
		if (isFallbackEvidenceAdmissionCapacityError(error)) throw error;
		noteFallbackEvidenceAdmissionBackpressure(runDir, "capability_error");
		return;
	}
	if (admission.state !== "acquired") {
		if (admission.reason === "release_pending") {
			noteFallbackEvidenceAdmissionBackpressure(runDir, "release_pending");
		}
		return;
	}
	if (!fallbackAdmissionRunIdentityMatches(runDir, admission.runIdentity)) {
		try {
			admission.transaction.release();
		} catch {}
		noteFallbackEvidenceAdmissionBackpressure(runDir, "root_detached_pending", admission.runIdentity);
		return;
	}
	const pendingAdmissionLoss = fallbackEvidenceAdmissionBackpressureSnapshot(runDir);
	let mutation:
		| { state: "committed"; value: ProviderRootMutationCommit | undefined }
		| { state: "root_detached"; evidence: "durable" | "pending" }
		| undefined;
	let capabilityFailed = false;
	let capacityError: FallbackEvidenceAdmissionCapacityError | undefined;
	let staleAdmission = false;
	try {
		mutation = admission.transaction.withRoot((root) => {
			if (!fallbackAdmissionRunIdentityMatches(runDir, admission.runIdentity)) {
				staleAdmission = true;
				return undefined;
			}
			const context = createProviderRootMutationContext(root, runDir, admission.runIdentity);
			if (providerFinalizationNamespaceObserved(root, context) || providerRunHasLiveWriter(root, context)) {
				return undefined;
			}
			const persistedAdmissionLoss = pendingAdmissionLoss
				? persistProviderFallbackEvidenceAdmissionBackpressure(root, context, pendingAdmissionLoss)
				: undefined;
			try {
				operation(root, context);
			} catch (error) {
				recordProviderRawLoss(root, context, source, error, 0);
			}
			return providerRootMutationCommit(context, persistedAdmissionLoss);
		});
	} catch (error) {
		if (isFallbackEvidenceAdmissionCapacityError(error)) capacityError = error;
		else capabilityFailed = !staleAdmission;
	}
	let release: ReturnType<CasTransaction["release"]> | undefined;
	try {
		release = admission.transaction.release();
	} catch {
		capabilityFailed = true;
	}
	if (capacityError) throw capacityError;
	if (mutation?.state === "root_detached") {
		noteFallbackEvidenceAdmissionBackpressure(
			runDir,
			mutation.evidence === "durable" ? "root_detached_durable" : "root_detached_pending",
			admission.runIdentity,
		);
		return;
	}
	if (staleAdmission || !fallbackAdmissionRunIdentityMatches(runDir, admission.runIdentity)) {
		noteFallbackEvidenceAdmissionBackpressure(runDir, "root_detached_pending", admission.runIdentity);
		return;
	}
	if (capabilityFailed) {
		noteFallbackEvidenceAdmissionBackpressure(runDir, "capability_error", admission.runIdentity);
		return;
	}
	if (release?.state !== "released") {
		noteFallbackEvidenceAdmissionBackpressure(runDir, "release_pending", admission.runIdentity);
		return;
	}
	if (mutation?.state !== "committed" || !mutation.value) return;
	applyProviderRootMutationCommit(runDir, mutation.value);
}

export function ingestIncidentRecorderEvidence<P extends IncidentEvidenceProvider>(
	runDir: string,
	provider: P,
	evidence: IncidentProviderEvidenceMap[P] | Uint8Array,
): void {
	if (serviceFinalizationNamespaceObserved(runDir)) return;
	try {
		const payload = rawProviderPayload(evidence);
		const orderedWriter = orderedWriterForRun(runDir);
		if (orderedWriter) {
			if (serviceFinalizationNamespaceObserved(runDir)) return;
			orderedWriter.recordExactBytes(
				"provider-evidence",
				"external_raw_evidence_ingested",
				payload.bytes,
				payload.encoding,
				{
					provider,
					target: evidenceTarget(runDir),
					diagnosticOnly: true,
				},
			);
			return;
		}
		const serviceIdentity = serviceRunIdentity(runDir);
		if (activeServiceRecorder) {
			if (serviceIdentity) {
				serviceRecordExactBytes(
					runDir,
					serviceIdentity,
					"provider-evidence",
					"external_raw_evidence_ingested",
					payload.bytes,
					payload.encoding,
					{
						provider,
						diagnosticOnly: true,
						targetPid: serviceIdentity.targetPid,
						targetProcessStartId: serviceIdentity.targetProcessStartId,
					},
				);
			}
			return;
		}
		runProviderFallbackMutation(runDir, "provider-evidence", (root, context) => {
			const timestamp = nowFields();
			const payloadReference = contentAddressRawBytesSync(
				root,
				context,
				"provider-evidence",
				payload.bytes,
				payload.encoding,
			);
			const envelope = {
				schemaVersion: 2,
				canonical: false,
				canonicalPayloadReference: true,
				sequence: ++context.providerOccurrenceSequence,
				...timestamp,
				provider,
				target: evidenceTargetWithinRoot(root, context),
				payloadReference,
				payloadEncoding: payload.encoding,
				unknownFieldsPreserved: true,
				diagnosticOnly: true,
			};
			appendProviderRunEvent(root, context, {
				type: "external_raw_evidence_ingested",
				provider,
				payloadReference,
				occurrence: envelope,
			});
			appendProviderReferenceEnvelope(root, context, `${safeToken(provider)}.jsonl`, envelope, "provider-evidence");
		});
	} catch (error) {
		if (isFallbackEvidenceAdmissionCapacityError(error)) throw error;
		recordRawLoss(runDir, "provider-evidence", error, 0);
	}
}

export function registerIncidentProviderSourceManifest(runDir: string, manifest: IncidentProviderSourceManifest): void {
	if (serviceFinalizationNamespaceObserved(runDir)) return;
	try {
		const payload = rawProviderPayload(manifest);
		const orderedWriter = orderedWriterForRun(runDir);
		if (orderedWriter) {
			if (serviceFinalizationNamespaceObserved(runDir)) return;
			orderedWriter.recordExactBytes(
				"provider-manifest",
				"provider_source_manifest_registered",
				payload.bytes,
				payload.encoding,
				{
					provider: manifest.provider,
					registrationOnly: true,
					artifactBytesCopied: false,
				},
			);
			return;
		}
		const serviceIdentity = serviceRunIdentity(runDir);
		if (activeServiceRecorder) {
			if (serviceIdentity) {
				serviceRecordExactBytes(
					runDir,
					serviceIdentity,
					"provider-manifest",
					"provider_source_manifest_registered",
					payload.bytes,
					payload.encoding,
					{
						provider: manifest.provider,
						registrationOnly: true,
						artifactBytesCopied: false,
						targetPid: serviceIdentity.targetPid,
						targetProcessStartId: serviceIdentity.targetProcessStartId,
					},
				);
			}
			return;
		}
		runProviderFallbackMutation(runDir, "provider-manifest", (root, context) => {
			const timestamp = nowFields();
			const payloadReference = contentAddressRawBytesSync(
				root,
				context,
				"provider-manifest",
				payload.bytes,
				payload.encoding,
			);
			const envelope = {
				schemaVersion: 1,
				canonical: false,
				canonicalPayloadReference: true,
				sequence: ++context.providerOccurrenceSequence,
				...timestamp,
				provider: manifest.provider,
				payloadReference,
				registrationOnly: true,
				artifactBytesCopied: false,
				retentionPolicy:
					manifest.provider === "atop"
						? { milliseconds: 3 * 24 * 60 * 60 * 1_000 }
						: manifest.provider === "sysdig"
							? { rollingMilliseconds: 60 * 60 * 1_000, incidentPins: true }
							: { milliseconds: INCIDENT_RECORDER_LIMITS.retentionAgeMs },
				supportedStockFormats: {
					atop: "stock-atop-raw",
					sysdig: ".scap",
					lttng: "CTF",
				},
			};
			appendProviderRunEvent(root, context, {
				type: "provider_source_manifest_registered",
				provider: manifest.provider,
				payloadReference,
				occurrence: envelope,
			});
			appendProviderReferenceEnvelope(
				root,
				context,
				"provider-source-manifests.jsonl",
				envelope,
				"provider-manifest",
			);
		});
	} catch (error) {
		if (isFallbackEvidenceAdmissionCapacityError(error)) throw error;
		recordRawLoss(runDir, "provider-manifest", error, 0);
	}
}

interface ActiveRun {
	runDir: string;
	directoryIdentity: ServiceRunDirectoryIdentity;
	runId: string;
	runToken?: string;
	machineId?: string;
	bootId?: string;
	pid?: number;
	processStartId?: string;
	socketPath?: string;
	launchControlState: "exact" | "missing" | "invalid";
	processControlState: "exact" | "missing" | "invalid";
	processControl?: StoredServiceProcessControl;
}

interface ServiceRunDirectoryIdentity {
	dev: number;
	ino: number;
	uid: number;
	mode: number;
}

function privateServiceRunDirectoryIdentity(runDir: string): ServiceRunDirectoryIdentity | undefined {
	try {
		const stat = lstatSync(runDir);
		const expectedUid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
		if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedUid || (stat.mode & 0o077) !== 0) {
			return undefined;
		}
		return { dev: stat.dev, ino: stat.ino, uid: stat.uid, mode: stat.mode };
	} catch {
		return undefined;
	}
}

function currentServiceRunDirectory(runDir: string, expected: ServiceRunDirectoryIdentity): boolean {
	const current = privateServiceRunDirectoryIdentity(runDir);
	return (
		current !== undefined &&
		current.dev === expected.dev &&
		current.ino === expected.ino &&
		current.uid === expected.uid &&
		current.mode === expected.mode
	);
}

function processEnvironmentBindsServiceRun(
	pid: number,
	processStartId: string,
	runId: string,
	runToken: string,
): boolean {
	if (process.platform !== "linux" || getProcessStartId(pid) !== processStartId) return false;
	const environment = readBoundedPrefix(`/proc/${pid}/environ`, 1024 * 1024);
	if (!environment || environment.truncated || getProcessStartId(pid) !== processStartId) return false;
	const entries = new Set(environment.value.toString("utf8").split("\0").filter(Boolean));
	return (
		entries.has(`${INCIDENT_RECORDER_RUN_ID_ENV}=${runId}`) &&
		entries.has(`${INCIDENT_RECORDER_RUN_TOKEN_ENV}=${runToken}`)
	);
}

function inspectServiceTargetLiveness(run: ActiveRun): "live" | "stopped" | "invalid" {
	if (
		run.processControlState !== "exact" ||
		!run.processControl ||
		run.pid === undefined ||
		run.processStartId === undefined ||
		run.runToken === undefined ||
		run.machineId === undefined ||
		run.bootId === undefined
	) {
		return "invalid";
	}
	if (run.machineId !== linuxMachineId() || run.bootId !== linuxBootId()) return "stopped";
	if (!hasMatchingProcessIdentity(run.pid, run.processStartId)) return "stopped";
	if (!processEnvironmentBindsServiceRun(run.pid, run.processStartId, run.runId, run.runToken)) return "invalid";
	return canonicalJsonValuesEqual(readStableStoredServiceProcessControl(run.runDir), run.processControl)
		? "live"
		: "invalid";
}

function isMatchingLiveProcess(run: ActiveRun): boolean {
	return inspectServiceTargetLiveness(run) === "live";
}

function loadActiveRun(runDir: string): ActiveRun | undefined {
	const runId = basename(runDir).slice(-36);
	if (!CANONICAL_UUID.test(runId)) return undefined;
	const directoryIdentity = privateServiceRunDirectoryIdentity(runDir);
	if (!directoryIdentity) return undefined;
	const launchPath = join(runDir, "launch.json");
	const processPath = join(runDir, "process.json");
	const launch = readStableStoredServiceLaunchControl(runDir);
	const identity = readStableStoredServiceProcessControl(runDir);
	if (!currentServiceRunDirectory(runDir, directoryIdentity)) return undefined;
	return {
		runDir,
		directoryIdentity,
		runId,
		runToken: identity?.runToken,
		machineId: identity?.machineId,
		bootId: identity?.bootId,
		socketPath: launch?.socketPath,
		pid: identity?.pid,
		processStartId: identity?.processStartId,
		launchControlState: launch ? "exact" : serviceControlOccupantExists(launchPath) ? "invalid" : "missing",
		processControlState: identity ? "exact" : serviceControlOccupantExists(processPath) ? "invalid" : "missing",
		processControl: identity,
	};
}

function runHasLiveWriter(runDir: string): boolean {
	const run = loadActiveRun(runDir);
	return inspectLiveProxyControl(runDir).live || (run !== undefined && isMatchingLiveProcess(run));
}

interface LiveProxyControlInspection {
	state: "exact" | "missing" | "invalid";
	live: boolean;
	createdWallTimeMs?: number;
}

function inspectLiveProxyControl(runDir: string): LiveProxyControlInspection {
	const markerPath = join(runDir, ACTIVE_MARKER_FILE_NAME);
	const markerSnapshot = readStoredServiceActiveMarkerControlSnapshot(runDir);
	if (!markerSnapshot) {
		return { state: serviceControlOccupantExists(markerPath) ? "invalid" : "missing", live: false };
	}
	const marker = markerSnapshot.value;
	const live =
		marker.machineId === linuxMachineId() &&
		marker.bootId === linuxBootId() &&
		marker.processStartId !== undefined &&
		getProcessStartId(marker.pid) === marker.processStartId;
	const readback = live ? readStoredServiceActiveMarkerControlSnapshot(runDir) : undefined;
	const stable =
		readback !== undefined &&
		canonicalJsonValuesEqual(readback.value, marker) &&
		samePrivateCanonicalJsonIdentity(readback.identity, markerSnapshot.identity);
	return stable
		? { state: "exact", live: true, createdWallTimeMs: Date.parse(marker.created.wallTime) }
		: { state: "invalid", live: false };
}

function runHasLiveProxy(runDir: string): boolean {
	return inspectLiveProxyControl(runDir).live;
}

interface ServiceSamplingState {
	previous?: LinuxMemorySummary;
	anomalyBurstUntilMs: number;
	latencyBurstUntilMs: number;
	nextSampleMs: number;
	lastLatencyTriggerOccurrence?: string;
	diskPauseMarked: boolean;
	liveHangClassification?: string;
	liveRunEventsCursor?: IncidentRecorderLiveRunEventsCursor;
	liveRunEventsObservationState?: "pending" | "caught_up" | "incomplete";
	liveLastHeartbeat?: LiveHeartbeatObservation;
	liveSocketWasPresent?: boolean;
	liveWorkerTimeoutEvent?: LiveWorkerTimeoutObservation;
	liveLastLatencyTrigger?: LiveLatencyTriggerObservation;
	liveSupervisorExit?: LiveSupervisorExitObservation;
	liveRunEventsReadError?: string;
	liveRunEventsDeferredReported?: string;
	liveRunEventsHeldPage?: {
		page: IncidentRecorderLiveRunEventsPage;
		scanStartCursor?: IncidentRecorderLiveRunEventsCursor;
		nextIndex: number;
	};
	stoppedBroadCaptured?: boolean;
	nodeReportPendingMarked?: boolean;
}
const serviceSamplingRuns = new Map<string, ServiceSamplingState>();

interface LiveObservationProvenance {
	kind: "heartbeat" | "worker_timeout" | "latency_trigger" | "supervisor_exit";
	occurrenceId: string;
	producerId: string;
	producerOrder: string;
	wrapperOrder: string;
	eventMonotonicNs: string;
	eventWallTimeMs: number;
	producerPid: number;
}

interface LiveHeartbeatObservation extends LiveObservationProvenance {
	kind: "heartbeat";
	socketExists?: boolean;
}

interface LiveWorkerTimeoutObservation extends LiveObservationProvenance {
	kind: "worker_timeout";
	requestId?: string;
	requestType?: string;
	durationMs?: number;
}

interface LiveLatencyTriggerObservation extends LiveObservationProvenance {
	kind: "latency_trigger";
	requestId: string;
}

interface LiveSupervisorExitObservation extends LiveObservationProvenance {
	kind: "supervisor_exit";
	childPid?: number;
	code?: number | null;
	signal?: string | null;
}

type LiveObservation =
	| LiveHeartbeatObservation
	| LiveWorkerTimeoutObservation
	| LiveLatencyTriggerObservation
	| LiveSupervisorExitObservation;

const LIVE_OBSERVATION_FIELD_BYTES = 256;

function boundedLiveObservationString(value: unknown): string | undefined {
	return typeof value === "string" && Buffer.byteLength(value, "utf8") <= LIVE_OBSERVATION_FIELD_BYTES
		? value
		: undefined;
}

function boundedLiveObservationNumber(value: unknown): number | undefined {
	return typeof value === "number" && Number.isSafeInteger(value) ? value : undefined;
}

function liveObservationProvenance<K extends LiveObservationProvenance["kind"]>(
	event: IncidentRecorderRunHistoryEvent,
	kind: K,
): (LiveObservationProvenance & { kind: K }) | undefined {
	const eventWallTimeMs = Number(event.eventWallTimeMs);
	const producerOrder = event.producerOrder.at(-1);
	const wrapperOrder = event.wrapperOrder.at(-1);
	const producerPid = boundedLiveObservationNumber(event.metadata.producerPid) ?? 0;
	if (
		!Number.isSafeInteger(eventWallTimeMs) ||
		eventWallTimeMs < 0 ||
		!producerOrder ||
		!wrapperOrder ||
		!boundedLiveObservationString(event.identity.occurrenceId) ||
		!boundedLiveObservationString(event.identity.producerId)
	)
		return undefined;
	return {
		kind,
		occurrenceId: event.identity.occurrenceId,
		producerId: event.identity.producerId,
		producerOrder,
		wrapperOrder,
		eventMonotonicNs: event.eventMonotonicNs,
		eventWallTimeMs,
		producerPid,
	};
}

function compactLiveObservation(event: IncidentRecorderRunHistoryEvent): LiveObservation | undefined {
	if (event.type === "supervisor_heartbeat") {
		const provenance = liveObservationProvenance(event, "heartbeat");
		return provenance
			? {
					...provenance,
					socketExists: typeof event.metadata.socketExists === "boolean" ? event.metadata.socketExists : undefined,
				}
			: undefined;
	}
	if (event.type === "worker_request_end" && event.metadata.outcome === "timeout") {
		const provenance = liveObservationProvenance(event, "worker_timeout");
		return provenance
			? {
					...provenance,
					requestId: boundedLiveObservationString(event.metadata.requestId),
					requestType: boundedLiveObservationString(event.metadata.requestType),
					durationMs: boundedLiveObservationNumber(event.metadata.durationMs),
				}
			: undefined;
	}
	if (event.type === "list_status_sampling_trigger") {
		const requestId = boundedLiveObservationString(event.metadata.requestId);
		if (requestId === undefined) return undefined;
		const provenance = liveObservationProvenance(event, "latency_trigger");
		return provenance ? { ...provenance, requestId } : undefined;
	}
	if (event.type === "supervisor_exit") {
		const provenance = liveObservationProvenance(event, "supervisor_exit");
		return provenance
			? {
					...provenance,
					childPid: boundedLiveObservationNumber(event.metadata.childPid),
					code:
						typeof event.metadata.code === "number" && Number.isSafeInteger(event.metadata.code)
							? event.metadata.code
							: event.metadata.code === null
								? null
								: undefined,
					signal:
						boundedLiveObservationString(event.metadata.signal) ??
						(event.metadata.signal === null ? null : undefined),
				}
			: undefined;
	}
	return undefined;
}

function compareLiveObservationCausality(left: LiveObservation, right: LiveObservation): number {
	const compareUnsigned = (a: string, b: string): number => {
		try {
			const leftValue = BigInt(a);
			const rightValue = BigInt(b);
			return leftValue === rightValue ? 0 : leftValue < rightValue ? -1 : 1;
		} catch {
			return a.localeCompare(b);
		}
	};
	const monotonic = compareUnsigned(left.eventMonotonicNs, right.eventMonotonicNs);
	if (monotonic !== 0) return monotonic;
	if (left.producerId === right.producerId) {
		const producer = compareUnsigned(left.producerOrder, right.producerOrder);
		if (producer !== 0) return producer;
	}
	const wrapper = compareUnsigned(left.wrapperOrder, right.wrapperOrder);
	if (wrapper !== 0) return wrapper;
	return left.occurrenceId.localeCompare(right.occurrenceId);
}

function liveObservationEvent(observation: LiveObservation): IncidentRecorderEvent {
	const event: IncidentRecorderEvent = {
		type:
			observation.kind === "heartbeat"
				? "supervisor_heartbeat"
				: observation.kind === "worker_timeout"
					? "worker_request_end"
					: observation.kind === "latency_trigger"
						? "list_status_sampling_trigger"
						: "supervisor_exit",
		wallTime: new Date(observation.eventWallTimeMs).toISOString(),
		monotonicNs: observation.eventMonotonicNs,
		pid: observation.producerPid,
		recorderProvenance: { occurrenceId: observation.occurrenceId, compactorCommitted: true },
	};
	if (observation.kind === "heartbeat") {
		if (observation.socketExists !== undefined) event.socketExists = observation.socketExists;
	} else if (observation.kind === "worker_timeout") {
		event.outcome = "timeout";
		if (observation.requestId !== undefined) event.requestId = observation.requestId;
		if (observation.requestType !== undefined) event.requestType = observation.requestType;
		if (observation.durationMs !== undefined) event.durationMs = observation.durationMs;
	} else if (observation.kind === "latency_trigger") {
		event.requestId = observation.requestId;
	} else {
		if (observation.childPid !== undefined) event.childPid = observation.childPid;
		if (observation.code !== undefined) event.code = observation.code;
		if (observation.signal !== undefined) event.signal = observation.signal;
	}
	return event;
}

function rememberLiveRunHistoryEvents(
	sampling: ServiceSamplingState,
	events: readonly IncidentRecorderRunHistoryEvent[],
): void {
	for (const historyEvent of events) {
		const observation = compactLiveObservation(historyEvent);
		if (!observation) continue;
		if (observation.kind === "heartbeat") {
			const previous = sampling.liveLastHeartbeat;
			if (!previous || compareLiveObservationCausality(observation, previous) > 0)
				sampling.liveLastHeartbeat = observation;
			if (observation.socketExists === true) sampling.liveSocketWasPresent = true;
		}
		if (observation.kind === "worker_timeout") {
			const previous = sampling.liveWorkerTimeoutEvent;
			if (!previous || compareLiveObservationCausality(observation, previous) > 0)
				sampling.liveWorkerTimeoutEvent = observation;
		}
		if (observation.kind === "latency_trigger") {
			const previous = sampling.liveLastLatencyTrigger;
			if (!previous || compareLiveObservationCausality(observation, previous) > 0)
				sampling.liveLastLatencyTrigger = observation;
		}
		if (observation.kind === "supervisor_exit") {
			const previous = sampling.liveSupervisorExit;
			if (!previous || compareLiveObservationCausality(observation, previous) > 0)
				sampling.liveSupervisorExit = observation;
		}
	}
}

function refreshLiveRunHistoryEvents(
	runDir: string,
	runId: string,
	runToken: string,
	targetPid: number,
	targetProcessStartId: string,
	sampling: ServiceSamplingState,
): void {
	const compactor = activeIncidentCompactor;
	if (!compactor) {
		sampling.liveRunEventsObservationState = "incomplete";
		sampling.liveRunEventsReadError = "live_run_event_reader_unavailable";
		return;
	}
	if (
		!CANONICAL_UUID.test(runId) ||
		!CANONICAL_UUID.test(runToken) ||
		!Number.isSafeInteger(targetPid) ||
		targetPid <= 0 ||
		targetProcessStartId.length === 0
	) {
		sampling.liveRunEventsObservationState = "incomplete";
		sampling.liveRunEventsReadError = "live_trigger_intent_provenance_unavailable";
		return;
	}
	try {
		let heldPage = sampling.liveRunEventsHeldPage;
		if (!heldPage) {
			const scanStartCursor = sampling.liveRunEventsCursor;
			const page = compactor.readLiveRunEvents({ runId, ...(scanStartCursor ? { cursor: scanStartCursor } : {}) });
			heldPage = { page, ...(scanStartCursor ? { scanStartCursor } : {}), nextIndex: 0 };
			sampling.liveRunEventsHeldPage = heldPage;
		}

		let intentPersistedThisRefresh = false;
		while (heldPage.nextIndex < heldPage.page.events.length) {
			const event = heldPage.page.events[heldPage.nextIndex];
			if (!event) break;
			let candidate: IncidentRecorderLiveTriggerIntentCandidate | undefined;
			try {
				candidate = extractIncidentRecorderLiveTriggerIntentCandidate(event, {
					runId,
					runToken,
					targetPid,
					targetProcessStartId,
					...(heldPage.scanStartCursor ? { scanStartCursor: heldPage.scanStartCursor } : {}),
				});
			} catch (error) {
				sampling.liveRunEventsObservationState = "incomplete";
				sampling.liveRunEventsReadError = `live_trigger_intent_invalid_event:${error instanceof Error ? error.message : String(error)}`;
				return;
			}
			if (!candidate) {
				rememberLiveRunHistoryEvents(sampling, [event]);
				heldPage.nextIndex += 1;
				continue;
			}
			if (intentPersistedThisRefresh) break;
			let persisted: ReturnType<IncidentRecorderCompactor["persistLiveTriggerIntent"]>;
			try {
				persisted = compactor.persistLiveTriggerIntent({ runDirectory: runDir, candidate });
			} catch (error) {
				sampling.liveRunEventsObservationState = "incomplete";
				sampling.liveRunEventsReadError = `live_trigger_intent_persistence_failed:${error instanceof Error ? error.message : String(error)}`;
				return;
			}
			if (persisted.state === "applied" || persisted.state === "replayed") {
				// The durable intent is the commit point. Only then may the compact
				// observation reducer and live cursor move past this event.
				rememberLiveRunHistoryEvents(sampling, [event]);
				heldPage.nextIndex += 1;
				intentPersistedThisRefresh = true;
				continue;
			}
			sampling.liveRunEventsObservationState = "incomplete";
			sampling.liveRunEventsReadError = `live_trigger_intent_persistence_${persisted.state}:${
				"reason" in persisted ? persisted.reason : "unavailable"
			}`;
			return;
		}

		if (heldPage.nextIndex < heldPage.page.events.length) {
			sampling.liveRunEventsObservationState = heldPage.page.state === "incomplete" ? "incomplete" : "pending";
			sampling.liveRunEventsReadError =
				heldPage.page.reason ??
				(heldPage.page.state === "incomplete"
					? "live_run_event_read_incomplete"
					: "live_run_event_frontier_catchup_pending");
			return;
		}

		const completedPage = heldPage.page;
		sampling.liveRunEventsHeldPage = undefined;
		if (completedPage.state === "incomplete") {
			// An incomplete reader page may contain a valid prefix, but its
			// cursor is not an advancement proof. Re-read it on the next pass.
			sampling.liveRunEventsObservationState = "incomplete";
			sampling.liveRunEventsReadError = completedPage.reason ?? "live_run_event_read_incomplete";
			return;
		}
		sampling.liveRunEventsCursor = completedPage.cursor;
		sampling.liveRunEventsObservationState = completedPage.state === "complete" ? "caught_up" : "pending";
		sampling.liveRunEventsReadError =
			completedPage.state === "complete"
				? undefined
				: (completedPage.reason ?? "live_run_event_frontier_catchup_pending");
	} catch (error) {
		sampling.liveRunEventsObservationState = "incomplete";
		sampling.liveRunEventsReadError = `live_run_event_reader_failed:${error instanceof Error ? error.message : String(error)}`;
	}
}

function incidentEventOccurrenceId(event: IncidentRecorderEvent): string | undefined {
	const provenance = event.recorderProvenance;
	if (!provenance || typeof provenance !== "object") return undefined;
	const occurrenceId = (provenance as Record<string, unknown>).occurrenceId;
	return typeof occurrenceId === "string" && occurrenceId.length > 0 ? occurrenceId : undefined;
}

function mergeLiveIncidentEvents(
	legacyEvents: readonly IncidentRecorderEvent[],
	snapshotEvents: readonly IncidentRecorderEvent[],
): IncidentRecorderEvent[] {
	const merged: IncidentRecorderEvent[] = [];
	const positions = new Map<string, number>();
	const add = (event: IncidentRecorderEvent, fallbackKey: string): void => {
		const key = incidentEventOccurrenceId(event) ?? fallbackKey;
		const existing = positions.get(key);
		if (existing === undefined) {
			positions.set(key, merged.length);
			merged.push(event);
		} else {
			merged[existing] = event;
		}
	};
	legacyEvents.forEach((event, index) => {
		add(event, `legacy:${index}`);
	});
	snapshotEvents.forEach((event, index) => {
		add(event, `snapshot:${index}`);
	});
	return merged;
}

function liveCausalSnapshotEvents(sampling: ServiceSamplingState): IncidentRecorderEvent[] {
	return [
		sampling.liveLastHeartbeat,
		sampling.liveWorkerTimeoutEvent,
		sampling.liveLastLatencyTrigger,
		sampling.liveSupervisorExit,
	]
		.filter((event): event is LiveObservation => event !== undefined)
		.map(liveObservationEvent);
}

function reportDeferredLiveRunEventsObservation(
	runDir: string,
	targetPid: number,
	targetProcessStartId: string | undefined,
	sampling: ServiceSamplingState,
): void {
	const state = sampling.liveRunEventsObservationState;
	if (!state || state === "caught_up") {
		sampling.liveRunEventsDeferredReported = undefined;
		return;
	}
	const reason = sampling.liveRunEventsReadError ?? "live_run_event_observation_deferred";
	const marker = `${state}:${reason}`;
	if (sampling.liveRunEventsDeferredReported === marker) return;
	sampling.liveRunEventsDeferredReported = marker;
	serviceRecordDerived(runDir, "recorder-control", "live_run_events_observation_deferred", {
		state,
		reason,
		targetPid,
		targetProcessStartId: targetProcessStartId ?? "",
	});
}

let activeIncidentCompactor: IncidentRecorderCompactor | undefined;
let serviceRunsDirectory: Dir | undefined;
let serviceRunsDirectoryPath: string | undefined;
let serviceRunsDirectoryIdentity: ServiceRunDirectoryIdentity | undefined;
const serviceRunPaths = new Map<string, string>();
let serviceRunCursor = 0;

function resetServiceRunDiscovery(): void {
	try {
		serviceRunsDirectory?.closeSync();
	} catch {}
	serviceRunsDirectory = undefined;
	serviceRunsDirectoryPath = undefined;
	serviceRunsDirectoryIdentity = undefined;
	serviceRunPaths.clear();
	serviceRunCursor = 0;
}

interface ServiceFinalizationRuntimeState {
	cursor?: IncidentRecorderRunHistoryCursor;
	retained?: Extract<IncidentRecorderRetainedRunHistoryResult, { state: "complete" }>;
}

const serviceFinalizationRuns = new Map<string, ServiceFinalizationRuntimeState>();

function discardServiceFinalizationState(runDir: string): void {
	const state = serviceFinalizationRuns.get(runDir);
	serviceFinalizationRuns.delete(runDir);
	if (!state || !activeIncidentCompactor) return;
	try {
		if (state.retained) activeIncidentCompactor.cancelRunHistoryProjection(state.retained.publicationCapability);
		else if (state.cursor) activeIncidentCompactor.cancelRunHistoryProjection(state.cursor);
	} catch {}
}

function serviceFinalizationState(runDir: string): ServiceFinalizationRuntimeState {
	let state = serviceFinalizationRuns.get(runDir);
	if (state) return state;
	while (serviceFinalizationRuns.size >= 64) {
		const candidate = [...serviceFinalizationRuns].find(([, value]) => !value.retained);
		if (!candidate) throw new Error("Incident finalization retained-projection capacity is saturated");
		discardServiceFinalizationState(candidate[0]);
	}
	state = {};
	serviceFinalizationRuns.set(runDir, state);
	return state;
}

interface StoredFinalizationBarrierExpectation extends IncidentRecorderFinalizationExpectation {
	version: 1;
	exitCode: number | "unavailable";
	exitSignal: string | "unavailable";
}

function validBoundedCount(value: unknown): value is { records: number; bytes: number } {
	return (
		isRecordObject(value) &&
		hasExactObjectKeys(value, ["records", "bytes"]) &&
		Number.isSafeInteger(value.records) &&
		Number(value.records) >= 0 &&
		Number.isSafeInteger(value.bytes) &&
		Number(value.bytes) >= 0
	);
}

function validStoredRelayFrontier(value: unknown, type: IncidentRecorderRelayFrontier["type"]): boolean {
	if (
		!isRecordObject(value) ||
		!hasExactObjectKeys(value, [
			"occurrenceId",
			"producerId",
			"type",
			"firstProducerSequence",
			"lastProducerSequence",
			"firstWrapperSequence",
			"lastWrapperSequence",
		]) ||
		value.type !== type ||
		!CANONICAL_UUID.test(String(value.occurrenceId)) ||
		!CANONICAL_UUID.test(String(value.producerId))
	) {
		return false;
	}
	const sequences = [
		value.firstProducerSequence,
		value.lastProducerSequence,
		value.firstWrapperSequence,
		value.lastWrapperSequence,
	];
	if (sequences.some((entry) => typeof entry !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/.test(entry))) {
		return false;
	}
	try {
		const maximum = (1n << 64n) - 1n;
		const firstProducer = BigInt(value.firstProducerSequence as string);
		const lastProducer = BigInt(value.lastProducerSequence as string);
		const firstWrapper = BigInt(value.firstWrapperSequence as string);
		const lastWrapper = BigInt(value.lastWrapperSequence as string);
		return (
			lastProducer <= maximum &&
			lastWrapper <= maximum &&
			firstProducer <= lastProducer &&
			firstWrapper <= lastWrapper
		);
	} catch {
		return false;
	}
}

function storedFinalizationBarrierExpectation(value: unknown): StoredFinalizationBarrierExpectation | undefined {
	if (!isRecordObject(value)) return undefined;
	const keys = [
		"version",
		"runId",
		"runToken",
		"wrapperPid",
		"wrapperStartId",
		"finalQueuedTailLoss",
		"emitterFinalTailLoss",
		"exitCode",
		"exitSignal",
		...(value.supervisorExit === undefined ? [] : ["supervisorExit"]),
		...(value.wrapperTerminal === undefined ? [] : ["wrapperTerminal"]),
	];
	if (
		!hasExactObjectKeys(value, keys) ||
		value.version !== 1 ||
		!CANONICAL_UUID.test(String(value.runId)) ||
		!CANONICAL_UUID.test(String(value.runToken)) ||
		!Number.isSafeInteger(value.wrapperPid) ||
		Number(value.wrapperPid) <= 0 ||
		!(
			value.wrapperStartId === null ||
			(typeof value.wrapperStartId === "string" &&
				value.wrapperStartId.length > 0 &&
				Buffer.byteLength(value.wrapperStartId, "utf8") <= 256)
		) ||
		!validBoundedCount(value.finalQueuedTailLoss) ||
		!validBoundedCount(value.emitterFinalTailLoss) ||
		!(
			value.exitCode === "unavailable" ||
			(Number.isSafeInteger(value.exitCode) && Number(value.exitCode) >= 0 && Number(value.exitCode) <= 255)
		) ||
		!(
			value.exitSignal === "unavailable" ||
			(typeof value.exitSignal === "string" && /^SIG[A-Z0-9]+$/.test(value.exitSignal))
		) ||
		(value.supervisorExit !== undefined && !validStoredRelayFrontier(value.supervisorExit, "supervisor_exit")) ||
		(value.wrapperTerminal !== undefined &&
			!validStoredRelayFrontier(value.wrapperTerminal, "capture_channel_terminal"))
	) {
		return undefined;
	}
	return value as unknown as StoredFinalizationBarrierExpectation;
}

function readFinalizationBarrierExpectationSnapshot(
	runDir: string,
): PrivateCanonicalJsonRead<StoredFinalizationBarrierExpectation> | undefined {
	const snapshot = readPrivateCanonicalControlJsonWithIdentity<unknown>(
		join(runDir, "finalization-barrier-expectation.json"),
	);
	const value = storedFinalizationBarrierExpectation(snapshot?.value);
	return snapshot && value
		? {
				value,
				identity: snapshot.identity,
			}
		: undefined;
}

function readFinalizationBarrierExpectation(runDir: string): StoredFinalizationBarrierExpectation | undefined {
	return readFinalizationBarrierExpectationSnapshot(runDir)?.value;
}

function readStableFinalizationBarrierExpectation(runDir: string): StoredFinalizationBarrierExpectation | undefined {
	const first = readFinalizationBarrierExpectationSnapshot(runDir);
	if (!first) return undefined;
	const second = readFinalizationBarrierExpectationSnapshot(runDir);
	return second &&
		canonicalJsonValuesEqual(first.value, second.value) &&
		samePrivateCanonicalJsonIdentity(first.identity, second.identity)
		? first.value
		: undefined;
}

function finalizerFrontier(
	frontier: IncidentRecorderRelayFrontier | undefined,
	expectedType: IncidentRecorderRelayFrontierExpectation["type"],
): IncidentRecorderRelayFrontierExpectation | undefined {
	if (!frontier || frontier.type !== expectedType) return undefined;
	return {
		type: expectedType,
		occurrenceId: frontier.occurrenceId,
		producerId: frontier.producerId,
		firstProducerSequence: frontier.firstProducerSequence,
		lastProducerSequence: frontier.lastProducerSequence,
		firstWrapperSequence: frontier.firstWrapperSequence,
		lastWrapperSequence: frontier.lastWrapperSequence,
	};
}

function stoppedTargetFinalizationArtifacts(runDir: string): {
	captureState: "complete" | "incomplete";
	artifacts: IncidentRecorderFinalizationInput["stoppedTarget"]["artifacts"];
} {
	const artifacts: IncidentRecorderFinalizationInput["stoppedTarget"]["artifacts"] = [];
	let captureState: "complete" | "incomplete" = "complete";
	const nodeReportCapture = readPrivateCanonicalJson<Record<string, unknown>>(
		join(runDir, "raw-reports", "capture-complete.json"),
	);
	if (
		!validStoppedCaptureCompletion(nodeReportCapture, "node_report_capture_complete", basename(runDir).slice(-36)) ||
		nodeReportCapture?.state !== "complete"
	) {
		captureState = "incomplete";
	}
	const providerCapture = readPrivateCanonicalJson<Record<string, unknown>>(
		join(runDir, "evidence", "provider-artifacts", "capture-complete.json"),
	);
	if (
		!validStoppedCaptureCompletion(
			providerCapture,
			"provider_artifact_capture_complete",
			basename(runDir).slice(-36),
		) ||
		providerCapture?.state !== "complete" ||
		!providerArtifactCaptureFrontierMatchesCurrent(runDir)
	) {
		captureState = "incomplete";
	}
	const directories = [
		{ path: join(runDir, "raw-reports"), role: "node-report", required: true },
		{ path: join(runDir, "evidence", "provider-artifacts"), role: "provider-artifact", required: true },
	] as const;
	for (const directory of directories) {
		let handle: Dir | undefined;
		const names: string[] = [];
		try {
			handle = opendirSync(directory.path);
			while (names.length <= 96) {
				const entry = handle.readSync();
				if (!entry) break;
				names.push(entry.name);
			}
		} catch {
			if (directory.required) captureState = "incomplete";
			continue;
		} finally {
			try {
				handle?.closeSync();
			} catch {
				captureState = "incomplete";
			}
		}
		if (names.length > 96) captureState = "incomplete";
		const nameSet = new Set(names);
		if (names.some((name) => name.endsWith(".error.json"))) captureState = "incomplete";
		if (
			names.some((name) => {
				if (!name.endsWith(".pending.json")) return false;
				const source = name.slice(0, -".pending.json".length);
				return !nameSet.has(`${source}.reference.json`) && !nameSet.has(`${source}.error.json`);
			})
		) {
			captureState = "incomplete";
		}
		for (const name of names.slice(0, 96)) {
			if (!name.endsWith(".reference.json")) continue;
			const record = readPrivateCanonicalJson<unknown>(join(directory.path, name));
			const value = stoppedTargetReferenceArtifact(runDir, directory.role, record);
			if (!value) {
				captureState = "incomplete";
				continue;
			}
			artifacts.push({
				state: "complete",
				role: directory.role,
				required: directory.required,
				algorithm: value.algorithm,
				digest: value.digest,
				bytes: Number(value.bytes),
				encoding: value.encoding,
				path: value.path,
			});
		}
	}
	const canonicalArtifacts = new Map<
		string,
		IncidentRecorderFinalizationInput["stoppedTarget"]["artifacts"][number]
	>();
	for (const artifact of artifacts) {
		const key = [
			artifact.role,
			artifact.required ? "required" : "optional",
			artifact.algorithm,
			artifact.digest,
			String(artifact.bytes),
			artifact.encoding,
		].join("\0");
		const previous = canonicalArtifacts.get(key);
		if (!previous || artifact.path < previous.path) canonicalArtifacts.set(key, artifact);
	}
	return {
		captureState,
		artifacts: [...canonicalArtifacts.entries()]
			.sort(([leftKey, left], [rightKey, right]) => {
				const leftValue = leftKey === rightKey ? left.path : leftKey;
				const rightValue = leftKey === rightKey ? right.path : rightKey;
				return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
			})
			.map(([, artifact]) => artifact),
	};
}

async function durableServiceRunSeal(
	runDir: string,
	identity: { runId: string; runToken: string },
): Promise<IncidentRecorderRunIdentitySealResult | undefined> {
	const writer = activeServiceRecorder?.writer;
	if (!writer) return undefined;
	const intent = durableServiceRunSealIntent(runDir, identity);
	if (!intent) return undefined;
	rememberDurablyFencedServiceRun(runDir);
	const path = join(runDir, "service-finalization-seal.json");
	const existing = readPrivateCanonicalJson<unknown>(path);
	if (existsSync(path)) {
		const candidate = parseIncidentRecorderRunIdentitySeal(existing);
		const admittedOccurrenceId = candidate ? serviceSealTerminalOccurrenceId(candidate) : undefined;
		if (
			!candidate ||
			candidate.runId !== identity.runId ||
			candidate.runToken !== identity.runToken ||
			(admittedOccurrenceId !== undefined && admittedOccurrenceId !== intent.terminalOccurrenceId)
		) {
			if (!quarantineInvalidServiceControl(runDir, path, "seal")) return undefined;
			if (!durableServiceRunSealReplayAmbiguity(runDir, intent)) return undefined;
		} else {
			if (
				admittedOccurrenceId === undefined &&
				!durableServiceRunSealReplayAmbiguity(runDir, intent, "seal_intent_without_seal_observed")
			) {
				return undefined;
			}
			const reconciled = persistIncidentFinalizationSeal({ path, value: candidate });
			if (reconciled.state === "applied" || reconciled.state === "noop") {
				const adoption = writer.adoptRunIdentitySeal(candidate, { durableReplay: true });
				if (adoption.adopted) return bindFallbackAdmissionLossToServiceSeal(runDir, adoption.seal);
				if (adoption.reason !== "invalid_seal_record") return undefined;
			}
			if (!quarantineInvalidServiceControl(runDir, path, "seal")) return undefined;
			if (!durableServiceRunSealReplayAmbiguity(runDir, intent)) return undefined;
		}
	}
	const emittedSeal = parseIncidentRecorderRunIdentitySeal(
		await writer.sealRunIdentity(identity, 1_000, intent.terminalOccurrenceId),
	);
	const seal = emittedSeal ? bindFallbackAdmissionLossToServiceSeal(runDir, emittedSeal) : undefined;
	if (!seal || seal.runId !== identity.runId || seal.runToken !== identity.runToken) return undefined;
	if (
		serviceSealTerminalOccurrenceId(seal) === undefined &&
		!durableServiceRunSealReplayAmbiguity(runDir, intent, "seal_intent_without_seal_observed")
	) {
		return undefined;
	}
	for (let attempt = 0; attempt < 2; attempt += 1) {
		const persisted = persistIncidentFinalizationSeal({ path, value: seal });
		if (persisted.state === "applied" || persisted.state === "noop") return seal;
		if (persisted.state === "conflict") return undefined;
		if (!persisted.authoritativeBytesMatch) return undefined;
	}
	return undefined;
}

interface ServiceRunSealIntent {
	schemaVersion: 1;
	kind: "service_run_seal_intent";
	runId: string;
	runToken: string;
	terminalOccurrenceId: string;
	retentionAnchorWallTimeMs: number;
	stoppedObservationDisposition: ServiceStoppedObservation["disposition"];
}

interface ServiceStoppedObservation {
	schemaVersion: 1;
	kind: "service_stopped_observation";
	runId: string;
	runToken: string;
	firstObservedStoppedWallTimeMs: number;
	disposition: "exact_first_observation" | "recovered_after_invalid_control";
}

interface ServiceStoppedObservationRepair {
	schemaVersion: 1;
	kind: "service_stopped_observation_repair";
	runId: string;
	runToken: string;
	reason: "invalid_control_observed";
}

interface ServiceRunSealReplayAmbiguity {
	schemaVersion: 1;
	kind: "service_run_seal_replay_ambiguity";
	runId: string;
	runToken: string;
	terminalOccurrenceId: string;
	reason: "seal_intent_without_seal_observed" | "seal_observed_without_intent" | "seal_namespace_invalid_or_unbound";
}

function validServiceStoppedObservation(
	value: unknown,
	identity: { runId: string; runToken: string },
): value is ServiceStoppedObservation {
	return (
		isRecordObject(value) &&
		value.schemaVersion === 1 &&
		value.kind === "service_stopped_observation" &&
		value.runId === identity.runId &&
		value.runToken === identity.runToken &&
		hasExactObjectKeys(value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"firstObservedStoppedWallTimeMs",
			"disposition",
		]) &&
		Number.isSafeInteger(value.firstObservedStoppedWallTimeMs) &&
		Number(value.firstObservedStoppedWallTimeMs) >= 0 &&
		["exact_first_observation", "recovered_after_invalid_control"].includes(String(value.disposition))
	);
}

function validServiceStoppedObservationRepair(
	value: unknown,
	identity: { runId: string; runToken: string },
): value is ServiceStoppedObservationRepair {
	return (
		isRecordObject(value) &&
		hasExactObjectKeys(value, ["schemaVersion", "kind", "runId", "runToken", "reason"]) &&
		value.schemaVersion === 1 &&
		value.kind === "service_stopped_observation_repair" &&
		value.runId === identity.runId &&
		value.runToken === identity.runToken &&
		value.reason === "invalid_control_observed"
	);
}

function serviceStoppedObservationRepairPath(runDir: string): string {
	return join(runDir, "service-finalization-stopped-observation-repair.json");
}

function serviceStoppedObservationRepairWitnessPath(runDir: string): string {
	return join(runDir, "service-finalization-stopped-observation-repair-witness.json");
}

function serviceStoppedObservationRepairValue(identity: {
	runId: string;
	runToken: string;
}): ServiceStoppedObservationRepair {
	return {
		schemaVersion: 1,
		kind: "service_stopped_observation_repair",
		runId: identity.runId,
		runToken: identity.runToken,
		reason: "invalid_control_observed",
	};
}

function currentServiceStoppedObservationRepair(
	runDir: string,
	identity: { runId: string; runToken: string },
): ServiceStoppedObservationRepair | undefined {
	for (const path of [
		serviceStoppedObservationRepairPath(runDir),
		serviceStoppedObservationRepairWitnessPath(runDir),
	]) {
		const value = readPrivateCanonicalJson<unknown>(path);
		if (validServiceStoppedObservationRepair(value, identity)) return value;
	}
	return undefined;
}

function serviceStoppedObservationRepairOccupantExists(runDir: string): boolean {
	return [serviceStoppedObservationRepairPath(runDir), serviceStoppedObservationRepairWitnessPath(runDir)].some(
		(path) => existsSync(path),
	);
}

function persistServiceStoppedObservationRepair(
	runDir: string,
	identity: { runId: string; runToken: string },
): boolean {
	const primary = serviceStoppedObservationRepairPath(runDir);
	const witness = serviceStoppedObservationRepairWitnessPath(runDir);
	const value = serviceStoppedObservationRepairValue(identity);
	const primaryValue = readPrivateCanonicalJson<unknown>(primary);
	if (validServiceStoppedObservationRepair(primaryValue, identity)) return true;
	const witnessValue = readPrivateCanonicalJson<unknown>(witness);
	if (validServiceStoppedObservationRepair(witnessValue, identity)) {
		if (existsSync(primary) && !quarantineInvalidServiceControl(runDir, primary, "stopped-observation-repair")) {
			return true;
		}
		persistExactCanonicalServiceControl(runDir, primary, "stopped-observation-repair", value);
		return currentServiceStoppedObservationRepair(runDir, identity) !== undefined;
	}
	if (!existsSync(primary)) {
		return persistExactCanonicalServiceControl(runDir, primary, "stopped-observation-repair", value);
	}
	// Keep the primary occupant as a crash-stable degradation witness while a
	// canonical alternate is established. Only then may the fixed primary name
	// be quarantined and regenerated.
	if (existsSync(witness) && !quarantineInvalidServiceControl(runDir, witness, "stopped-observation-repair-witness")) {
		return false;
	}
	if (!persistExactCanonicalServiceControl(runDir, witness, "stopped-observation-repair-witness", value)) {
		return false;
	}
	if (!quarantineInvalidServiceControl(runDir, primary, "stopped-observation-repair")) return true;
	persistExactCanonicalServiceControl(runDir, primary, "stopped-observation-repair", value);
	return currentServiceStoppedObservationRepair(runDir, identity) !== undefined;
}

function stableServiceRunIdentityCandidate(
	readCandidate: () => { runId: string; runToken: string } | undefined,
): { runId: string; runToken: string } | undefined {
	const first = readCandidate();
	if (!first) return undefined;
	const second = readCandidate();
	return canonicalJsonValuesEqual(first, second) ? first : undefined;
}

function basicStoppedObservationIdentity(
	runDir: string,
	runId: string,
): { runId: string; runToken: string } | undefined {
	const value = readPrivateCanonicalJson<unknown>(join(runDir, "service-finalization-stopped-observation.json"));
	if (
		!isRecordObject(value) ||
		!hasExactObjectKeys(value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"firstObservedStoppedWallTimeMs",
			"disposition",
		]) ||
		value.schemaVersion !== 1 ||
		value.kind !== "service_stopped_observation" ||
		value.runId !== runId ||
		typeof value.runToken !== "string" ||
		!CANONICAL_UUID.test(value.runToken) ||
		!Number.isSafeInteger(value.firstObservedStoppedWallTimeMs) ||
		Number(value.firstObservedStoppedWallTimeMs) < 0 ||
		!(value.disposition === "exact_first_observation" || value.disposition === "recovered_after_invalid_control")
	) {
		return undefined;
	}
	return { runId, runToken: value.runToken };
}

function basicSealIntentIdentity(runDir: string, runId: string): { runId: string; runToken: string } | undefined {
	const value = readPrivateCanonicalJson<unknown>(join(runDir, "service-finalization-seal-intent.json"));
	if (
		!isRecordObject(value) ||
		!hasExactObjectKeys(value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"terminalOccurrenceId",
			"retentionAnchorWallTimeMs",
			"stoppedObservationDisposition",
		]) ||
		value.schemaVersion !== 1 ||
		value.kind !== "service_run_seal_intent" ||
		value.runId !== runId ||
		typeof value.runToken !== "string" ||
		!CANONICAL_UUID.test(value.runToken) ||
		typeof value.terminalOccurrenceId !== "string" ||
		!CANONICAL_UUID.test(value.terminalOccurrenceId) ||
		!Number.isSafeInteger(value.retentionAnchorWallTimeMs) ||
		Number(value.retentionAnchorWallTimeMs) < 0 ||
		!(
			value.stoppedObservationDisposition === "exact_first_observation" ||
			value.stoppedObservationDisposition === "recovered_after_invalid_control"
		)
	) {
		return undefined;
	}
	return { runId, runToken: value.runToken };
}

function basicReplayIdentity(runDir: string, runId: string): { runId: string; runToken: string } | undefined {
	const value = readPrivateCanonicalJson<unknown>(join(runDir, "service-finalization-seal-replay-ambiguity.json"));
	if (
		!isRecordObject(value) ||
		!hasExactObjectKeys(value, ["schemaVersion", "kind", "runId", "runToken", "terminalOccurrenceId", "reason"]) ||
		value.schemaVersion !== 1 ||
		value.kind !== "service_run_seal_replay_ambiguity" ||
		value.runId !== runId ||
		typeof value.runToken !== "string" ||
		!CANONICAL_UUID.test(value.runToken) ||
		typeof value.terminalOccurrenceId !== "string" ||
		!CANONICAL_UUID.test(value.terminalOccurrenceId) ||
		![
			"seal_intent_without_seal_observed",
			"seal_observed_without_intent",
			"seal_namespace_invalid_or_unbound",
		].includes(String(value.reason))
	) {
		return undefined;
	}
	return { runId, runToken: value.runToken };
}

function basicServiceSealIdentity(runDir: string, runId: string): { runId: string; runToken: string } | undefined {
	const seal = parseIncidentRecorderRunIdentitySeal(
		readPrivateCanonicalJson<unknown>(join(runDir, "service-finalization-seal.json")),
	);
	return seal?.runId === runId && CANONICAL_UUID.test(seal.runToken) ? { runId, runToken: seal.runToken } : undefined;
}

function durableStoppedServiceRunIdentityCandidate(
	runDir: string,
	runId: string,
): { runId: string; runToken: string } | undefined {
	for (const readCandidate of [
		() => basicServiceSealIdentity(runDir, runId),
		() => basicSealIntentIdentity(runDir, runId),
		() => basicStoppedObservationIdentity(runDir, runId),
		() => {
			const barrier = readStableFinalizationBarrierExpectation(runDir);
			return barrier?.runId === runId ? { runId, runToken: barrier.runToken } : undefined;
		},
		() => basicReplayIdentity(runDir, runId),
	]) {
		const candidate = stableServiceRunIdentityCandidate(readCandidate);
		if (candidate) return candidate;
	}
	return undefined;
}

function deterministicRecoveredServiceRunToken(runId: string): string {
	const digits = createHash("sha256")
		.update("grimoire-service-run-identity-recovery\0")
		.update(runId)
		.digest("hex")
		.slice(0, 32)
		.split("");
	digits[12] = "5";
	digits[16] = "8";
	const hex = digits.join("");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function recoverServiceRunIdentityAfterInvalidDiscoveryControl(runDir: string): ServiceRunIdentity | undefined {
	const runId = basename(runDir).slice(-36);
	if (!CANONICAL_UUID.test(runId)) return undefined;
	const existingRepair = stableServiceRunIdentityCandidate(() =>
		storedServiceStoppedObservationRepairIdentity(runDir, runId),
	);
	const processIdentity = readStableStoredServiceProcessControl(runDir);
	const candidate = existingRepair ??
		durableStoppedServiceRunIdentityCandidate(runDir, runId) ??
		(processIdentity ? { runId, runToken: processIdentity.runToken } : undefined) ?? {
			runId,
			runToken: deterministicRecoveredServiceRunToken(runId),
		};
	if (!persistServiceStoppedObservationRepair(runDir, candidate)) return undefined;
	const primaryRepair = readPrivateCanonicalJson<unknown>(serviceStoppedObservationRepairPath(runDir));
	if (!validServiceStoppedObservationRepair(primaryRepair, candidate)) return undefined;
	const recovered = serviceRunIdentity(runDir);
	return recovered?.runId === candidate.runId && recovered.runToken === candidate.runToken ? recovered : undefined;
}

function normalizeInvalidDiscoveryControls(
	runDir: string,
	identity: ServiceRunIdentity,
	targetLiveness: ReturnType<typeof inspectServiceTargetLiveness>,
): boolean {
	const controls: Array<{
		path: string;
		label: string;
		invalid: () => boolean;
	}> = [
		{
			path: join(runDir, "launch.json"),
			label: "launch",
			invalid: () => !readStableStoredServiceLaunchControl(runDir),
		},
		{
			path: join(runDir, "process.json"),
			label: "process",
			invalid: () => {
				const current = readStableStoredServiceProcessControl(runDir);
				return targetLiveness === "invalid" || !current || current.runToken !== identity.runToken;
			},
		},
		{
			path: join(runDir, "finalization-barrier-expectation.json"),
			label: "barrier-expectation",
			invalid: () => {
				const current = readStableFinalizationBarrierExpectation(runDir);
				return !current || current.runId !== identity.runId || current.runToken !== identity.runToken;
			},
		},
		{
			path: join(runDir, ACTIVE_MARKER_FILE_NAME),
			label: "active-marker",
			// Once the run has crossed into recovered identity, a proxy marker no
			// longer protects target identity. Preserving it as active would make a
			// forged or orphaned live PID an unbounded retention veto.
			invalid: () => true,
		},
	];
	for (const control of controls) {
		let normalized = false;
		for (let attempt = 0; attempt < 3; attempt += 1) {
			if (!serviceControlOccupantExists(control.path) || !control.invalid()) {
				normalized = true;
				break;
			}
			if (!quarantineInvalidServiceControl(runDir, control.path, control.label)) return false;
		}
		if (!normalized && serviceControlOccupantExists(control.path) && control.invalid()) return false;
	}
	return true;
}

function currentServiceStoppedObservation(
	runDir: string,
	identity: { runId: string; runToken: string },
): ServiceStoppedObservation | undefined {
	const value = readPrivateCanonicalJson<unknown>(join(runDir, "service-finalization-stopped-observation.json"));
	if (!validServiceStoppedObservation(value, identity)) return undefined;
	const repairOccupant = serviceStoppedObservationRepairOccupantExists(runDir);
	const repair = currentServiceStoppedObservationRepair(runDir, identity);
	if (value.disposition === "exact_first_observation" && repairOccupant) return undefined;
	if (value.disposition === "recovered_after_invalid_control" && !repair) return undefined;
	return value;
}

function validServiceRunSealIntent(
	value: unknown,
	identity: { runId: string; runToken: string },
	stopped: ServiceStoppedObservation,
): value is ServiceRunSealIntent {
	return (
		isRecordObject(value) &&
		value.schemaVersion === 1 &&
		value.kind === "service_run_seal_intent" &&
		value.runId === identity.runId &&
		value.runToken === identity.runToken &&
		hasExactObjectKeys(value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"terminalOccurrenceId",
			"retentionAnchorWallTimeMs",
			"stoppedObservationDisposition",
		]) &&
		typeof value.terminalOccurrenceId === "string" &&
		CANONICAL_UUID.test(value.terminalOccurrenceId) &&
		Number.isSafeInteger(value.retentionAnchorWallTimeMs) &&
		Number(value.retentionAnchorWallTimeMs) === stopped.firstObservedStoppedWallTimeMs &&
		value.stoppedObservationDisposition === stopped.disposition
	);
}

function currentServiceRunSealIntent(
	runDir: string,
	identity: { runId: string; runToken: string },
): ServiceRunSealIntent | undefined {
	const stopped = currentServiceStoppedObservation(runDir, identity);
	if (!stopped) return undefined;
	const intent = readPrivateCanonicalJson<unknown>(join(runDir, "service-finalization-seal-intent.json"));
	return validServiceRunSealIntent(intent, identity, stopped) ? intent : undefined;
}

function validServiceRunSealReplayAmbiguity(
	value: unknown,
	binding: { runId: string; runToken: string; terminalOccurrenceId: string },
): value is ServiceRunSealReplayAmbiguity {
	return (
		isRecordObject(value) &&
		value.schemaVersion === 1 &&
		value.kind === "service_run_seal_replay_ambiguity" &&
		value.runId === binding.runId &&
		value.runToken === binding.runToken &&
		value.terminalOccurrenceId === binding.terminalOccurrenceId &&
		CANONICAL_UUID.test(binding.runId) &&
		CANONICAL_UUID.test(binding.runToken) &&
		CANONICAL_UUID.test(binding.terminalOccurrenceId) &&
		[
			"seal_intent_without_seal_observed",
			"seal_observed_without_intent",
			"seal_namespace_invalid_or_unbound",
		].includes(String(value.reason)) &&
		hasExactObjectKeys(value, ["schemaVersion", "kind", "runId", "runToken", "terminalOccurrenceId", "reason"])
	);
}

function currentServiceRunSealReplayAmbiguityForIdentity(
	runDir: string,
	identity: { runId: string; runToken: string },
): ServiceRunSealReplayAmbiguity | undefined {
	const value = readPrivateCanonicalJson<unknown>(join(runDir, "service-finalization-seal-replay-ambiguity.json"));
	if (
		!isRecordObject(value) ||
		typeof value.terminalOccurrenceId !== "string" ||
		!validServiceRunSealReplayAmbiguity(value, {
			runId: identity.runId,
			runToken: identity.runToken,
			terminalOccurrenceId: value.terminalOccurrenceId,
		})
	) {
		return undefined;
	}
	return value;
}

function currentServiceRunSealReplayAmbiguity(
	runDir: string,
	intent: ServiceRunSealIntent,
): ServiceRunSealReplayAmbiguity | undefined {
	const value = readPrivateCanonicalJson<unknown>(join(runDir, "service-finalization-seal-replay-ambiguity.json"));
	return validServiceRunSealReplayAmbiguity(value, intent) ? value : undefined;
}

function serviceSealTerminalOccurrenceId(value: IncidentRecorderRunIdentitySealResult): string | undefined {
	return value.terminal.admission?.accepted === true
		? value.terminal.admission.occurrenceId
		: value.terminal.frontier?.occurrenceId;
}

function adoptPreexistingServiceRunSealWithoutIntent(
	runDir: string,
	identity: { runId: string; runToken: string },
): IncidentRecorderRunIdentitySealResult | undefined {
	const writer = activeServiceRecorder?.writer;
	if (!writer) return undefined;
	const directoryIdentity = fallbackAdmissionRunIdentity(runDir);
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	if (!directoryIdentity || (pending && !fallbackAdmissionRunIdentityMatches(runDir, pending.runIdentity))) {
		return undefined;
	}
	const transaction = acquireIncidentCasTransaction(dirname(dirname(runDir)));
	if (!transaction) return undefined;
	try {
		if (!fallbackAdmissionRunIdentityMatches(runDir, directoryIdentity)) {
			return undefined;
		}
		cancelFallbackEvidenceAdmissionRetry(runDir);
		persistFallbackEvidenceAdmissionBackpressure(runDir, true);
		if (fallbackEvidenceAdmissionBackpressure.has(runDir)) {
			scheduleFallbackEvidenceAdmissionRetry(runDir);
			return undefined;
		}
		if (!fallbackAdmissionRunIdentityMatches(runDir, directoryIdentity)) {
			return undefined;
		}
		const path = join(runDir, "service-finalization-seal.json");
		const existing = readPrivateCanonicalJson<unknown>(path);
		const parsed = parseIncidentRecorderRunIdentitySeal(existing);
		if (!existsSync(path) || !parsed || parsed.runId !== identity.runId || parsed.runToken !== identity.runToken) {
			return undefined;
		}
		if (!fallbackAdmissionRunIdentityMatches(runDir, directoryIdentity)) {
			return undefined;
		}
		const reconciled = persistIncidentFinalizationSeal({ path, value: parsed });
		if (reconciled.state !== "applied" && reconciled.state !== "noop") return undefined;
		const adoption = writer.adoptRunIdentitySeal(parsed, { durableReplay: true });
		if (!adoption.adopted) return undefined;
		rememberDurablyFencedServiceRun(runDir);
		return bindFallbackAdmissionLossToServiceSeal(runDir, adoption.seal);
	} finally {
		transaction.release();
	}
}

function durableServiceRunSealIntent(
	runDir: string,
	identity: { runId: string; runToken: string },
	terminalOccurrenceId?: string,
): ServiceRunSealIntent | undefined {
	if ((pendingProviderReferenceWrites.get(runDir) ?? 0) > 0) return undefined;
	const directoryIdentity = fallbackAdmissionRunIdentity(runDir);
	const pending = fallbackEvidenceAdmissionBackpressure.get(runDir);
	if (!directoryIdentity || (pending && !fallbackAdmissionRunIdentityMatches(runDir, pending.runIdentity))) {
		return undefined;
	}
	const transaction = acquireIncidentCasTransaction(dirname(dirname(runDir)));
	if (!transaction) return undefined;
	try {
		if (!fallbackAdmissionRunIdentityMatches(runDir, directoryIdentity)) {
			return undefined;
		}
		if ((pendingProviderReferenceWrites.get(runDir) ?? 0) > 0) return undefined;
		cancelFallbackEvidenceAdmissionRetry(runDir);
		persistFallbackEvidenceAdmissionBackpressure(runDir, true);
		if (fallbackEvidenceAdmissionBackpressure.has(runDir)) {
			scheduleFallbackEvidenceAdmissionRetry(runDir);
			return undefined;
		}
		if (!fallbackAdmissionRunIdentityMatches(runDir, directoryIdentity)) {
			return undefined;
		}
		const stopped = currentServiceStoppedObservation(runDir, identity);
		if (!stopped) return undefined;
		const path = join(runDir, "service-finalization-seal-intent.json");
		let existing = readPrivateCanonicalJson<unknown>(path);
		const replayPlan = currentServiceRunSealReplayAmbiguityForIdentity(runDir, identity);
		const requestedTerminalOccurrenceId = terminalOccurrenceId ?? replayPlan?.terminalOccurrenceId ?? randomUUID();
		if (!CANONICAL_UUID.test(requestedTerminalOccurrenceId)) return undefined;
		const existingValid =
			validServiceRunSealIntent(existing, identity, stopped) &&
			(terminalOccurrenceId === undefined || existing.terminalOccurrenceId === terminalOccurrenceId);
		if (existsSync(path) && !existingValid) {
			if (
				!durableServiceRunSealReplayAmbiguityBinding(
					runDir,
					{
						runId: identity.runId,
						runToken: identity.runToken,
						terminalOccurrenceId: requestedTerminalOccurrenceId,
					},
					"seal_namespace_invalid_or_unbound",
				)
			) {
				return undefined;
			}
			if (!quarantineInvalidServiceControl(runDir, path, "seal-intent")) return undefined;
			existing = undefined;
		}
		const value: ServiceRunSealIntent = existing
			? (existing as ServiceRunSealIntent)
			: {
					schemaVersion: 1,
					kind: "service_run_seal_intent",
					runId: identity.runId,
					runToken: identity.runToken,
					terminalOccurrenceId: requestedTerminalOccurrenceId,
					retentionAnchorWallTimeMs: Number(stopped.firstObservedStoppedWallTimeMs),
					stoppedObservationDisposition: stopped.disposition as ServiceStoppedObservation["disposition"],
				};
		if (!fallbackAdmissionRunIdentityMatches(runDir, directoryIdentity)) {
			return undefined;
		}
		const persisted = persistIncidentFinalizationSeal({ path, value });
		return persisted.state === "applied" || persisted.state === "noop" ? value : undefined;
	} finally {
		transaction.release();
	}
}

function durableServiceStoppedObservation(
	runDir: string,
	identity: { runId: string; runToken: string },
	nowMs: number,
	onFaultBoundary: (boundary: IncidentRecorderServiceOrchestrationFaultBoundary) => void = () => {},
): ServiceStoppedObservation | undefined {
	const path = join(runDir, "service-finalization-stopped-observation.json");
	let existing = readPrivateCanonicalJson<unknown>(path);
	let existingValid = validServiceStoppedObservation(existing, identity);
	let recoveredFromInvalid = serviceStoppedObservationRepairOccupantExists(runDir);
	let repair = currentServiceStoppedObservationRepair(runDir, identity);
	const existingClaimsExact =
		existingValid && isRecordObject(existing) && existing.disposition === "exact_first_observation";
	const existingClaimsRecovered =
		existingValid && isRecordObject(existing) && existing.disposition === "recovered_after_invalid_control";
	if (
		existsSync(path) &&
		(!existingValid || (existingClaimsExact && recoveredFromInvalid) || (existingClaimsRecovered && !repair))
	) {
		if (!persistServiceStoppedObservationRepair(runDir, identity)) return undefined;
		repair = currentServiceStoppedObservationRepair(runDir, identity);
		if (!repair) return undefined;
		onFaultBoundary("after_stopped_repair_witness_durable_before_observation_quarantine");
		if (!quarantineInvalidServiceControl(runDir, path, "stopped-observation")) return undefined;
		existing = undefined;
		existingValid = false;
		recoveredFromInvalid = true;
	}
	if (recoveredFromInvalid && !repair && !persistServiceStoppedObservationRepair(runDir, identity)) return undefined;
	if (recoveredFromInvalid && !currentServiceStoppedObservationRepair(runDir, identity)) return undefined;
	const value: ServiceStoppedObservation = existingValid
		? (existing as ServiceStoppedObservation)
		: {
				schemaVersion: 1,
				kind: "service_stopped_observation",
				runId: identity.runId,
				runToken: identity.runToken,
				firstObservedStoppedWallTimeMs: nowMs,
				disposition: recoveredFromInvalid ? "recovered_after_invalid_control" : "exact_first_observation",
			};
	const persisted = persistIncidentFinalizationSeal({ path, value });
	return persisted.state === "applied" || persisted.state === "noop" ? value : undefined;
}

function durableServiceRunSealReplayAmbiguity(
	runDir: string,
	intent: ServiceRunSealIntent,
	reason: ServiceRunSealReplayAmbiguity["reason"] = "seal_intent_without_seal_observed",
): ServiceRunSealReplayAmbiguity | undefined {
	return durableServiceRunSealReplayAmbiguityBinding(runDir, intent, reason);
}

function durableServiceRunSealReplayAmbiguityBinding(
	runDir: string,
	binding: { runId: string; runToken: string; terminalOccurrenceId: string },
	reason: ServiceRunSealReplayAmbiguity["reason"],
): ServiceRunSealReplayAmbiguity | undefined {
	const path = join(runDir, "service-finalization-seal-replay-ambiguity.json");
	let existing = readPrivateCanonicalJson<unknown>(path);
	const existingValid = validServiceRunSealReplayAmbiguity(existing, binding);
	if (existsSync(path) && !existingValid) {
		if (!quarantineInvalidServiceControl(runDir, path, "seal-replay-ambiguity")) return undefined;
		existing = undefined;
	}
	const value: ServiceRunSealReplayAmbiguity = existing
		? (existing as ServiceRunSealReplayAmbiguity)
		: {
				schemaVersion: 1,
				kind: "service_run_seal_replay_ambiguity",
				runId: binding.runId,
				runToken: binding.runToken,
				terminalOccurrenceId: binding.terminalOccurrenceId,
				reason,
			};
	const persisted = persistIncidentFinalizationSeal({ path, value });
	return persisted.state === "applied" || persisted.state === "noop" ? value : undefined;
}

function durableAmbiguousServiceRunFence(
	runDir: string,
	identity: { runId: string; runToken: string },
	reason: ServiceRunSealReplayAmbiguity["reason"],
): IncidentRecorderRunIdentitySealResult | undefined {
	const writer = activeServiceRecorder?.writer;
	if (!writer) return undefined;
	const intent = durableServiceRunSealIntent(runDir, identity);
	if (!intent || !durableServiceRunSealReplayAmbiguity(runDir, intent, reason)) return undefined;
	rememberDurablyFencedServiceRun(runDir);
	const path = join(runDir, "service-finalization-seal.json");
	if (existsSync(path) && !quarantineInvalidServiceControl(runDir, path, "seal")) return undefined;
	const emittedSeal = parseIncidentRecorderRunIdentitySeal(writer.fenceRunIdentity(identity, { durableReplay: true }));
	const seal = emittedSeal ? bindFallbackAdmissionLossToServiceSeal(runDir, emittedSeal) : undefined;
	if (!seal || seal.runId !== identity.runId || seal.runToken !== identity.runToken) return undefined;
	const persisted = persistIncidentFinalizationSeal({ path, value: seal });
	return persisted.state === "applied" || persisted.state === "noop" ? seal : undefined;
}

function stableRunRetentionAnchor(runDir: string, identity: { runId: string; runToken: string }): number | undefined {
	return durableServiceRunSealIntent(runDir, identity)?.retentionAnchorWallTimeMs;
}

function persistServiceFinalizationCompletion(runDir: string, value: Record<string, unknown>): boolean {
	const path = join(runDir, ".service-finalization-complete");
	const result = persistIncidentFinalizationSeal({
		path,
		value,
	});
	if (result.state !== "applied" && result.state !== "noop") return false;
	const readback = readPrivateCanonicalJson<unknown>(path);
	return readback !== undefined && canonicalJsonValuesEqual(readback, value);
}

function isRecordObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactObjectKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function serviceCompletionSealProof(runDir: string):
	| {
			identity: { runId: string; runToken: string };
			stopped: ServiceStoppedObservation;
			intent: ServiceRunSealIntent;
			seal: IncidentRecorderRunIdentitySealResult;
			terminalOccurrenceId?: string;
	  }
	| undefined {
	const identity = serviceRunIdentity(runDir);
	if (!identity) return undefined;
	const stopped = currentServiceStoppedObservation(runDir, identity);
	if (!stopped) return undefined;
	const intent = currentServiceRunSealIntent(runDir, identity);
	if (!intent) return undefined;
	const seal = adoptPreexistingServiceRunSealWithoutIntent(runDir, identity);
	if (!seal) return undefined;
	const terminalOccurrenceId = serviceSealTerminalOccurrenceId(seal);
	if (
		terminalOccurrenceId === undefined &&
		!durableServiceRunSealReplayAmbiguity(runDir, intent, "seal_intent_without_seal_observed")
	) {
		return undefined;
	}
	return { identity, stopped, intent, seal, terminalOccurrenceId };
}

function incidentServiceSealBindingValid(
	runDir: string,
	proof: NonNullable<ReturnType<typeof serviceCompletionSealProof>>,
): boolean {
	if (proof.terminalOccurrenceId === proof.intent.terminalOccurrenceId) return true;
	const ambiguity = currentServiceRunSealReplayAmbiguity(runDir, proof.intent);
	if (!ambiguity) return false;
	return proof.terminalOccurrenceId === undefined
		? [
				"seal_intent_without_seal_observed",
				"seal_observed_without_intent",
				"seal_namespace_invalid_or_unbound",
			].includes(ambiguity.reason)
		: ambiguity.reason === "seal_namespace_invalid_or_unbound";
}

function serviceSealLossIsZero(seal: IncidentRecorderRunIdentitySealResult): boolean {
	for (const count of [
		seal.loss.emitter,
		seal.loss.drainTimeout.definite,
		seal.loss.drainTimeout.uncertain,
		seal.loss.terminalRelay.definite,
		seal.loss.terminalRelay.uncertain,
	]) {
		if (count.records !== 0 || count.bytes !== 0) return false;
	}
	return true;
}

function serviceCompletionSemanticsValid(
	runDir: string,
	proof: NonNullable<ReturnType<typeof serviceCompletionSealProof>>,
	outcome: "complete" | "incomplete" | "corrupt",
	serviceTerminalRelayDisposition: string,
): boolean {
	const replayPath = join(runDir, "service-finalization-seal-replay-ambiguity.json");
	const replayObserved = existsSync(replayPath);
	const replay = currentServiceRunSealReplayAmbiguity(runDir, proof.intent);
	if (outcome === "complete") {
		return (
			!replayObserved &&
			proof.stopped.disposition === "exact_first_observation" &&
			proof.intent.stoppedObservationDisposition === "exact_first_observation" &&
			proof.seal.terminal.admission?.accepted === true &&
			proof.seal.terminal.admission.occurrenceId === proof.intent.terminalOccurrenceId &&
			proof.seal.terminal.frontier !== null &&
			proof.seal.terminal.frontier.occurrenceId === proof.intent.terminalOccurrenceId &&
			serviceSealLossIsZero(proof.seal) &&
			serviceTerminalRelayDisposition === "relayed"
		);
	}
	if (replayObserved) {
		return (
			replay !== undefined &&
			incidentServiceSealBindingValid(runDir, proof) &&
			serviceTerminalRelayDisposition === "replayed_after_ambiguous_seal_attempt"
		);
	}
	return (
		replay === undefined &&
		incidentServiceSealBindingValid(runDir, proof) &&
		serviceTerminalRelayDisposition !== "replayed_after_ambiguous_seal_attempt"
	);
}

interface ServiceFinalizationPublicationConflict {
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

function validServiceFinalizationPublicationConflict(value: unknown): value is ServiceFinalizationPublicationConflict {
	if (!isRecordObject(value)) return false;
	return (
		hasExactObjectKeys(value, [
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
		]) &&
		value.schemaVersion === 1 &&
		value.kind === "service_finalization_publication_conflict" &&
		typeof value.runId === "string" &&
		CANONICAL_UUID.test(value.runId) &&
		typeof value.runToken === "string" &&
		CANONICAL_UUID.test(value.runToken) &&
		typeof value.publishedFinalizationId === "string" &&
		/^[0-9a-f]{64}$/.test(value.publishedFinalizationId) &&
		typeof value.intendedFinalizationId === "string" &&
		/^[0-9a-f]{64}$/.test(value.intendedFinalizationId) &&
		value.publishedFinalizationId !== value.intendedFinalizationId &&
		["complete", "incomplete", "corrupt"].includes(String(value.publishedState)) &&
		["complete", "incomplete", "corrupt"].includes(String(value.intendedState)) &&
		Number.isSafeInteger(value.publishedRetentionAnchorWallTimeMs) &&
		Number(value.publishedRetentionAnchorWallTimeMs) >= 0 &&
		Number.isSafeInteger(value.intendedRetentionAnchorWallTimeMs) &&
		Number(value.intendedRetentionAnchorWallTimeMs) >= 0 &&
		typeof value.publishedServiceTerminalRelayDisposition === "string" &&
		value.publishedServiceTerminalRelayDisposition.length > 0 &&
		Buffer.byteLength(value.publishedServiceTerminalRelayDisposition, "utf8") <= 4 * 1024 &&
		typeof value.intendedServiceTerminalRelayDisposition === "string" &&
		value.intendedServiceTerminalRelayDisposition.length > 0 &&
		Buffer.byteLength(value.intendedServiceTerminalRelayDisposition, "utf8") <= 4 * 1024 &&
		value.reason === "published_finalization_conflict"
	);
}

function serviceFinalizationPublicationConflictPath(runDir: string): string {
	return join(runDir, "service-finalization-publication-conflict.json");
}

function serviceFinalizationPublicationConflictDigest(value: ServiceFinalizationPublicationConflict): string {
	return createHash("sha256")
		.update(`${JSON.stringify(value)}\n`, "utf8")
		.digest("hex");
}

function readServiceFinalizationPublicationConflict(
	runDir: string,
): ServiceFinalizationPublicationConflict | undefined {
	const value = readPrivateCanonicalJson<unknown>(serviceFinalizationPublicationConflictPath(runDir));
	return validServiceFinalizationPublicationConflict(value) ? value : undefined;
}

function persistServiceFinalizationPublicationConflict(
	runDir: string,
	value: ServiceFinalizationPublicationConflict,
): boolean {
	if (!validServiceFinalizationPublicationConflict(value)) return false;
	const path = serviceFinalizationPublicationConflictPath(runDir);
	const existing = readServiceFinalizationPublicationConflict(runDir);
	if (existing) return canonicalJsonValuesEqual(existing, value);
	if (serviceControlOccupantExists(path) && !quarantineInvalidServiceControl(runDir, path, "publication-conflict")) {
		return false;
	}
	const persisted = persistIncidentFinalizationSeal({ path, value });
	if (persisted.state !== "applied" && persisted.state !== "noop") return false;
	const readback = readServiceFinalizationPublicationConflict(runDir);
	return readback !== undefined && canonicalJsonValuesEqual(readback, value);
}

function samePublishedServiceFinalization(
	left: Exclude<ReturnType<typeof recoverPublishedIncidentFinalization>, { state: "pending" }>,
	right: Exclude<ReturnType<typeof recoverPublishedIncidentFinalization>, { state: "pending" }>,
): boolean {
	return (
		left.state === right.state &&
		left.finalizationId === right.finalizationId &&
		left.runId === right.runId &&
		left.supervisorExitAnchorWallTimeMs === right.supervisorExitAnchorWallTimeMs &&
		left.retentionAnchorWallTimeMs === right.retentionAnchorWallTimeMs &&
		left.authorityDirectory === right.authorityDirectory &&
		left.serviceTerminalRelayDisposition === right.serviceTerminalRelayDisposition &&
		canonicalJsonValuesEqual(left.manifest, right.manifest)
	);
}

function currentServiceFinalizationPublicationConflict(
	agentDir: string,
	runDir: string,
): ServiceFinalizationPublicationConflict | undefined {
	const marker = readServiceFinalizationPublicationConflict(runDir);
	if (!marker || marker.runId !== basename(runDir).slice(-36)) return undefined;
	const proof = serviceCompletionSealProof(runDir);
	if (
		!proof ||
		proof.identity.runId !== marker.runId ||
		proof.identity.runToken !== marker.runToken ||
		proof.intent.retentionAnchorWallTimeMs !== marker.intendedRetentionAnchorWallTimeMs ||
		marker.publishedRetentionAnchorWallTimeMs !== marker.intendedRetentionAnchorWallTimeMs
	) {
		return undefined;
	}
	const publicationIntent = readServiceFinalizationPublicationIntent(runDir, marker.intendedFinalizationId);
	if (
		publicationIntent?.runId !== marker.runId ||
		publicationIntent.finalizationId !== marker.intendedFinalizationId
	) {
		return undefined;
	}
	const incidentInput = {
		incidentsDirectory: join(agentDir, "incidents"),
		incidentId: basename(runDir),
		expectedFinalizationId: marker.publishedFinalizationId,
	};
	const published = recoverPublishedIncidentFinalization(incidentInput);
	const authority = inspectIncidentRetentionAuthority(incidentInput);
	if (
		published.state === "pending" ||
		published.finalizationId !== marker.publishedFinalizationId ||
		published.runId !== marker.runId ||
		published.manifest.runIdentity.runToken !== marker.runToken ||
		published.state !== marker.publishedState ||
		published.retentionAnchorWallTimeMs !== marker.publishedRetentionAnchorWallTimeMs ||
		published.serviceTerminalRelayDisposition !== marker.publishedServiceTerminalRelayDisposition ||
		authority.state !== "authorized" ||
		authority.finalizationId !== published.finalizationId ||
		authority.runId !== published.runId ||
		authority.outcome !== published.state ||
		authority.retentionAnchorWallTimeMs !== published.retentionAnchorWallTimeMs ||
		serviceCompletionSemanticsValid(runDir, proof, published.state, published.serviceTerminalRelayDisposition) ||
		!serviceCompletionSemanticsValid(
			runDir,
			proof,
			marker.intendedState,
			marker.intendedServiceTerminalRelayDisposition,
		)
	) {
		return undefined;
	}
	const stableMarker = readServiceFinalizationPublicationConflict(runDir);
	const stablePublicationIntent = readServiceFinalizationPublicationIntent(runDir, marker.intendedFinalizationId);
	const stablePublished = recoverPublishedIncidentFinalization(incidentInput);
	const stableAuthority = inspectIncidentRetentionAuthority(incidentInput);
	if (
		!stableMarker ||
		!canonicalJsonValuesEqual(stableMarker, marker) ||
		!stablePublicationIntent ||
		!canonicalJsonValuesEqual(stablePublicationIntent, publicationIntent) ||
		stablePublished.state === "pending" ||
		!samePublishedServiceFinalization(published, stablePublished) ||
		stableAuthority.state !== "authorized" ||
		stableAuthority.finalizationId !== authority.finalizationId ||
		stableAuthority.runId !== authority.runId ||
		stableAuthority.outcome !== authority.outcome ||
		stableAuthority.retentionAnchorWallTimeMs !== authority.retentionAnchorWallTimeMs ||
		stableAuthority.authoritySource !== authority.authoritySource ||
		stableAuthority.retentionClass !== authority.retentionClass
	) {
		return undefined;
	}
	return marker;
}

function isCurrentServiceFinalizationCompletion(
	agentDir: string,
	runDir: string,
	value: Record<string, unknown>,
): boolean {
	const runId = basename(runDir).slice(-36);
	if (value.schemaVersion !== 2 || value.runId !== runId) return false;
	if (value.state === "publication_conflict_reclaimable") {
		if (
			!hasExactObjectKeys(value, [
				"schemaVersion",
				"state",
				"runId",
				"publishedFinalizationId",
				"intendedFinalizationId",
				"conflictProofSha256",
				"retentionAnchorWallTimeMs",
			]) ||
			typeof value.publishedFinalizationId !== "string" ||
			!/^[0-9a-f]{64}$/.test(value.publishedFinalizationId) ||
			typeof value.intendedFinalizationId !== "string" ||
			!/^[0-9a-f]{64}$/.test(value.intendedFinalizationId) ||
			value.publishedFinalizationId === value.intendedFinalizationId ||
			typeof value.conflictProofSha256 !== "string" ||
			!/^[0-9a-f]{64}$/.test(value.conflictProofSha256) ||
			!Number.isSafeInteger(value.retentionAnchorWallTimeMs) ||
			Number(value.retentionAnchorWallTimeMs) < 0
		) {
			return false;
		}
		const conflict = currentServiceFinalizationPublicationConflict(agentDir, runDir);
		return (
			conflict?.runId === runId &&
			conflict.publishedFinalizationId === value.publishedFinalizationId &&
			conflict.intendedFinalizationId === value.intendedFinalizationId &&
			serviceFinalizationPublicationConflictDigest(conflict) === value.conflictProofSha256 &&
			Math.max(conflict.publishedRetentionAnchorWallTimeMs, conflict.intendedRetentionAnchorWallTimeMs) ===
				value.retentionAnchorWallTimeMs
		);
	}
	if (value.state === "normal_reclaimable") {
		if (
			!hasExactObjectKeys(value, [
				"schemaVersion",
				"state",
				"runId",
				"finalizationId",
				"classification",
				"retentionAnchorWallTimeMs",
			]) ||
			typeof value.finalizationId !== "string" ||
			!/^[0-9a-f]{64}$/.test(value.finalizationId) ||
			value.classification !== "normal" ||
			!Number.isSafeInteger(value.retentionAnchorWallTimeMs) ||
			Number(value.retentionAnchorWallTimeMs) < 0
		) {
			return false;
		}
		const proof = serviceCompletionSealProof(runDir);
		if (
			!proof?.terminalOccurrenceId ||
			proof.identity.runId !== runId ||
			!serviceCompletionSemanticsValid(runDir, proof, "complete", "relayed")
		) {
			return false;
		}
		const authority = readServiceNormalRetentionAuthority(runDir, value.finalizationId);
		return (
			authority?.runId === runId &&
			authority.runToken === proof.identity.runToken &&
			authority.terminalOccurrenceId === proof.terminalOccurrenceId &&
			authority.retentionAnchorWallTimeMs === value.retentionAnchorWallTimeMs &&
			proof.intent.retentionAnchorWallTimeMs === value.retentionAnchorWallTimeMs
		);
	}
	if (value.state !== "incident_reclaimable") return false;
	if (
		!hasExactObjectKeys(value, [
			"schemaVersion",
			"state",
			"runId",
			"finalizationId",
			"outcome",
			"retentionAnchorWallTimeMs",
		]) ||
		typeof value.finalizationId !== "string" ||
		!/^[0-9a-f]{64}$/.test(value.finalizationId) ||
		!["complete", "incomplete", "corrupt"].includes(String(value.outcome)) ||
		!Number.isSafeInteger(value.retentionAnchorWallTimeMs) ||
		Number(value.retentionAnchorWallTimeMs) < 0
	) {
		return false;
	}
	const proof = serviceCompletionSealProof(runDir);
	if (!proof || proof.identity.runId !== runId) return false;
	const publicationIntent = readServiceFinalizationPublicationIntent(runDir, value.finalizationId);
	if (publicationIntent?.runId !== runId || publicationIntent.finalizationId !== value.finalizationId) return false;
	const published = recoverPublishedIncidentFinalization({
		incidentsDirectory: join(agentDir, "incidents"),
		incidentId: basename(runDir),
		expectedFinalizationId: value.finalizationId,
	});
	if (
		published.state === "pending" ||
		published.finalizationId !== value.finalizationId ||
		published.runId !== runId ||
		published.manifest.runIdentity.runToken !== proof.identity.runToken ||
		published.state !== value.outcome ||
		published.retentionAnchorWallTimeMs !== value.retentionAnchorWallTimeMs
	) {
		return false;
	}
	if (!serviceCompletionSemanticsValid(runDir, proof, published.state, published.serviceTerminalRelayDisposition)) {
		return false;
	}
	const authority = inspectIncidentRetentionAuthority({
		incidentsDirectory: join(agentDir, "incidents"),
		incidentId: basename(runDir),
	});
	return (
		authority.state === "authorized" &&
		authority.finalizationId === value.finalizationId &&
		authority.runId === runId &&
		authority.outcome === value.outcome &&
		authority.retentionAnchorWallTimeMs === value.retentionAnchorWallTimeMs &&
		proof.intent.retentionAnchorWallTimeMs === value.retentionAnchorWallTimeMs
	);
}

function projectionContainsFinalizerFrontier(
	runHistory: IncidentRecorderRunHistoryResult,
	frontier: IncidentRecorderRelayFrontierExpectation,
): boolean {
	return runHistory.projection.events.some(
		(event) =>
			event.type === frontier.type &&
			event.identity.occurrenceId === frontier.occurrenceId &&
			event.identity.producerId === frontier.producerId &&
			event.producerOrder.at(0) === frontier.firstProducerSequence &&
			event.producerOrder.at(-1) === frontier.lastProducerSequence &&
			event.wrapperOrder.at(0) === frontier.firstWrapperSequence &&
			event.wrapperOrder.at(-1) === frontier.lastWrapperSequence,
	);
}

function serviceProjectionRetryElapsed(
	runDir: string,
	identity: { runId: string; runToken: string },
	frontier: IncidentRecorderRelayFrontierExpectation,
	nowMs: number,
): boolean {
	const deadlineId = createHash("sha256")
		.update(`${identity.runId}\0${identity.runToken}\0${frontier.occurrenceId}`)
		.digest("hex");
	const path = join(runDir, `service-finalization-projection-deadline-${deadlineId}.json`);
	const existing = readPrivateCanonicalJson<unknown>(path);
	if (isRecordObject(existing)) {
		const valid =
			hasExactObjectKeys(existing, [
				"schemaVersion",
				"kind",
				"runId",
				"runToken",
				"terminalOccurrenceId",
				"createdWallTimeMs",
				"retryThroughWallTimeMs",
			]) &&
			existing.schemaVersion === 1 &&
			existing.kind === "service_finalization_projection_deadline" &&
			existing.runId === identity.runId &&
			existing.runToken === identity.runToken &&
			existing.terminalOccurrenceId === frontier.occurrenceId &&
			CANONICAL_UUID.test(identity.runId) &&
			CANONICAL_UUID.test(identity.runToken) &&
			CANONICAL_UUID.test(frontier.occurrenceId) &&
			Number.isSafeInteger(existing.createdWallTimeMs) &&
			Number(existing.createdWallTimeMs) >= 0 &&
			Number(existing.createdWallTimeMs) <= nowMs + SERVICE_CONTROL_FUTURE_SKEW_MS &&
			Number.isSafeInteger(existing.retryThroughWallTimeMs) &&
			Number(existing.retryThroughWallTimeMs) ===
				Number(existing.createdWallTimeMs) + SERVICE_FINALIZATION_RETRY_GRACE_MS;
		if (valid) return nowMs >= Number(existing.retryThroughWallTimeMs);
	}
	if (existsSync(path) && !quarantineInvalidServiceControl(runDir, path, "projection-deadline")) return false;
	const value = {
		schemaVersion: 1,
		kind: "service_finalization_projection_deadline",
		runId: identity.runId,
		runToken: identity.runToken,
		terminalOccurrenceId: frontier.occurrenceId,
		createdWallTimeMs: nowMs,
		retryThroughWallTimeMs: nowMs + SERVICE_FINALIZATION_RETRY_GRACE_MS,
	};
	persistExactCanonicalServiceControl(runDir, path, "projection-deadline", value);
	return false;
}

function serviceBarrierRetryElapsed(
	runDir: string,
	identity: { runId: string; runToken: string },
	nowMs: number,
): boolean {
	const compactor = activeIncidentCompactor;
	if (!compactor) return false;
	try {
		const result = compactor.ensureServiceFinalizationBarrierDeadline({
			runDirectory: runDir,
			runId: identity.runId,
			runToken: identity.runToken,
			nowMs,
		});
		return result.state === "available" && result.elapsed;
	} catch {
		return false;
	}
}

function serviceLiveProxyGraceElapsed(
	runDir: string,
	identity: { runId: string; runToken: string },
	stopped: ServiceStoppedObservation,
	nowMs: number,
): boolean {
	const deadlineId = createHash("sha256").update(`${identity.runId}\0${identity.runToken}`).digest("hex");
	const path = join(runDir, `service-finalization-live-proxy-deadline-${deadlineId}.json`);
	const expected = {
		schemaVersion: 1,
		kind: "service_finalization_live_proxy_deadline",
		runId: identity.runId,
		runToken: identity.runToken,
		firstObservedStoppedWallTimeMs: stopped.firstObservedStoppedWallTimeMs,
		retryThroughWallTimeMs: stopped.firstObservedStoppedWallTimeMs + SERVICE_FINALIZATION_RETRY_GRACE_MS,
	};
	const anchorPlausible =
		Number.isSafeInteger(stopped.firstObservedStoppedWallTimeMs) &&
		stopped.firstObservedStoppedWallTimeMs >= 0 &&
		stopped.firstObservedStoppedWallTimeMs <= nowMs + SERVICE_CONTROL_FUTURE_SKEW_MS &&
		Number.isSafeInteger(expected.retryThroughWallTimeMs);
	if (!anchorPlausible) return true;
	const existing = readPrivateCanonicalJson<unknown>(path);
	if (existing !== undefined && canonicalJsonValuesEqual(existing, expected)) {
		return nowMs >= expected.retryThroughWallTimeMs;
	}
	if (existsSync(path) && !quarantineInvalidServiceControl(runDir, path, "live-proxy-deadline")) return false;
	if (!persistExactCanonicalServiceControl(runDir, path, "live-proxy-deadline", expected)) return false;
	return nowMs >= expected.retryThroughWallTimeMs;
}

interface ServiceFinalizationPublicationIntent {
	schemaVersion: 1;
	kind: "service_finalization_publication_intent";
	runId: string;
	finalizationId: string;
}

interface ServiceNormalRetentionAuthority {
	schemaVersion: 1;
	kind: "service_normal_retention_authority";
	runId: string;
	runToken: string;
	finalizationId: string;
	classification: "normal";
	analysisState: "complete";
	retentionAnchorWallTimeMs: number;
	terminalOccurrenceId: string;
}

function readServiceNormalRetentionAuthority(
	runDir: string,
	finalizationId: string,
): ServiceNormalRetentionAuthority | undefined {
	const value = readPrivateCanonicalJson<unknown>(
		join(runDir, `service-finalization-normal-authority-${finalizationId}.json`),
	);
	return validServiceNormalRetentionAuthority(value, finalizationId) ? value : undefined;
}

function validServiceNormalRetentionAuthority(
	value: unknown,
	finalizationId: string,
): value is ServiceNormalRetentionAuthority {
	return (
		isRecordObject(value) &&
		hasExactObjectKeys(value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"finalizationId",
			"classification",
			"analysisState",
			"retentionAnchorWallTimeMs",
			"terminalOccurrenceId",
		]) &&
		value.schemaVersion === 1 &&
		value.kind === "service_normal_retention_authority" &&
		typeof value.runId === "string" &&
		CANONICAL_UUID.test(value.runId) &&
		typeof value.runToken === "string" &&
		CANONICAL_UUID.test(value.runToken) &&
		value.finalizationId === finalizationId &&
		/^[0-9a-f]{64}$/.test(finalizationId) &&
		value.classification === "normal" &&
		value.analysisState === "complete" &&
		Number.isSafeInteger(value.retentionAnchorWallTimeMs) &&
		Number(value.retentionAnchorWallTimeMs) >= 0 &&
		typeof value.terminalOccurrenceId === "string" &&
		CANONICAL_UUID.test(value.terminalOccurrenceId)
	);
}

function persistServiceNormalRetentionAuthority(runDir: string, value: ServiceNormalRetentionAuthority): boolean {
	if (!validServiceNormalRetentionAuthority(value, value.finalizationId)) return false;
	return persistExactCanonicalServiceControl(
		runDir,
		join(runDir, `service-finalization-normal-authority-${value.finalizationId}.json`),
		"normal-retention-authority",
		value,
	);
}

function readServiceFinalizationPublicationIntent(
	runDir: string,
	finalizationId: string,
): ServiceFinalizationPublicationIntent | undefined {
	const value = readPrivateCanonicalJson<Partial<ServiceFinalizationPublicationIntent>>(
		join(runDir, `service-finalization-publication-intent-${finalizationId}.json`),
	);
	return value?.schemaVersion === 1 &&
		value.kind === "service_finalization_publication_intent" &&
		hasExactObjectKeys(value as Record<string, unknown>, ["schemaVersion", "kind", "runId", "finalizationId"]) &&
		typeof value.runId === "string" &&
		CANONICAL_UUID.test(value.runId) &&
		typeof value.finalizationId === "string" &&
		/^[0-9a-f]{64}$/.test(value.finalizationId)
		? (value as ServiceFinalizationPublicationIntent)
		: undefined;
}

function persistServiceFinalizationPublicationIntent(
	runDir: string,
	value: ServiceFinalizationPublicationIntent,
): boolean {
	const path = join(runDir, `service-finalization-publication-intent-${value.finalizationId}.json`);
	const existing = readServiceFinalizationPublicationIntent(runDir, value.finalizationId);
	if (existing?.runId === value.runId && existing.finalizationId === value.finalizationId) return true;
	if (existsSync(path) && !quarantineInvalidServiceControl(runDir, path, "publication-intent")) {
		return false;
	}
	const persisted = persistIncidentFinalizationSeal({
		path,
		value,
	});
	return persisted.state === "applied" || persisted.state === "noop";
}

function terminalExpectation(
	frontier: IncidentRecorderRelayFrontierExpectation | undefined,
	reason: string,
): IncidentRecorderFinalizationInput["terminalExpectations"]["supervisorExit"] {
	return frontier ? { state: "available", frontier } : { state: "unavailable", reason };
}

function serviceTerminalRelayDisposition(seal: IncidentRecorderRunIdentitySealResult): string {
	if (seal.terminal.frontier) return "relayed";
	if (!seal.terminal.admission) return "unavailable";
	return seal.terminal.admission.accepted ? "frontier_unavailable" : `rejected:${seal.terminal.admission.reason}`;
}

function linuxCountersAdvanced(
	previous: LinuxMemorySummary | undefined,
	current: LinuxMemorySummary | undefined,
): boolean {
	for (const source of ["eventsLocal", "events"] as const) {
		const before = previous?.latest?.[source];
		const after = current?.latest?.[source];
		for (const key of new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})])) {
			if ((after?.[key] ?? 0) > (before?.[key] ?? 0)) return true;
		}
	}
	return false;
}

export interface InspectIncidentRecorderRunsOptions {
	onFinalizationFaultBoundary?: (boundary: IncidentRecorderOrchestrationFaultBoundary) => void;
}

export async function inspectIncidentRecorderRuns(
	agentDir: string,
	nowMs = Date.now(),
	options: InspectIncidentRecorderRunsOptions = {},
): Promise<string[]> {
	const finalizationFault = options.onFinalizationFaultBoundary ?? (() => {});
	const runsRoot = join(agentDir, "incident-recorder", "runs");
	const runsRootIdentity = privateServiceRunDirectoryIdentity(runsRoot);
	if (!runsRootIdentity) {
		resetServiceRunDiscovery();
		return [];
	}
	if (
		serviceRunsDirectoryPath !== runsRoot ||
		!serviceRunsDirectoryIdentity ||
		!currentServiceRunDirectory(runsRoot, serviceRunsDirectoryIdentity)
	) {
		resetServiceRunDiscovery();
	}
	const finalized: string[] = [];
	if (!serviceRunsDirectory) {
		try {
			serviceRunsDirectory = opendirSync(runsRoot);
			if (!currentServiceRunDirectory(runsRoot, runsRootIdentity)) {
				resetServiceRunDiscovery();
				return [];
			}
			serviceRunsDirectoryPath = runsRoot;
			serviceRunsDirectoryIdentity = runsRootIdentity;
		} catch {
			resetServiceRunDiscovery();
			return [];
		}
	}
	for (let discovered = 0; discovered < 16; discovered += 1) {
		let entry: Dirent | null;
		try {
			entry = serviceRunsDirectory.readSync();
		} catch {
			entry = null;
		}
		if (!entry) {
			try {
				serviceRunsDirectory.closeSync();
			} catch {}
			serviceRunsDirectory = undefined;
			break;
		}
		if (
			!entry.isDirectory() ||
			!/^[A-Za-z0-9_.+-]{1,160}$/.test(entry.name) ||
			entry.name === "." ||
			entry.name === ".."
		)
			continue;
		serviceRunPaths.set(entry.name, join(runsRoot, entry.name));
		while (serviceRunPaths.size > 4096) serviceRunPaths.delete(serviceRunPaths.keys().next().value as string);
	}
	const names = [...serviceRunPaths.keys()];
	if (names.length === 0) return finalized;
	const batch = Array.from(
		{ length: Math.min(16, names.length) },
		(_, offset) => names[(serviceRunCursor + offset) % names.length],
	);
	serviceRunCursor = (serviceRunCursor + batch.length) % names.length;
	const workDeadlineMs = Date.now() + 100;
	for (const name of batch) {
		if (Date.now() >= workDeadlineMs) break;
		let run = loadActiveRun(serviceRunPaths.get(name) ?? join(runsRoot, name));
		if (!run) {
			serviceRunPaths.delete(name);
			continue;
		}
		const proxyInspection = inspectLiveProxyControl(run.runDir);
		const durableStoppedIdentity = durableStoppedServiceRunIdentityCandidate(run.runDir, run.runId);
		let targetLiveness = inspectServiceTargetLiveness(run);
		let targetReportsLive = targetLiveness === "live";
		if (
			run.processControlState === "missing" &&
			run.launchControlState === "exact" &&
			proxyInspection.live &&
			proxyInspection.createdWallTimeMs !== undefined &&
			proxyInspection.createdWallTimeMs <= nowMs + 1_000 &&
			nowMs - proxyInspection.createdWallTimeMs < SERVICE_PROCESS_IDENTITY_PUBLICATION_GRACE_MS &&
			!durableStoppedIdentity
		) {
			// The wrapper creates the run and launch controls before spawn can
			// publish process.json. A strictly identified live proxy makes this a
			// bounded in-flight launch, not a stopped run with missing identity.
			continue;
		}
		const livenessConflictsWithTerminalAuthority = targetReportsLive && durableStoppedIdentity !== undefined;
		let discoveredIdentity = serviceRunIdentity(run.runDir);
		const invalidDiscoveryControlObserved =
			run.launchControlState !== "exact" ||
			run.processControlState !== "exact" ||
			targetLiveness === "invalid" ||
			proxyInspection.state === "invalid" ||
			livenessConflictsWithTerminalAuthority ||
			discoveredIdentity === undefined ||
			discoveredIdentity.disposition === "recovered_after_invalid_discovery_control";
		if (invalidDiscoveryControlObserved) {
			if (!currentServiceRunDirectory(run.runDir, run.directoryIdentity)) {
				serviceRunPaths.delete(name);
				continue;
			}
			discoveredIdentity = recoverServiceRunIdentityAfterInvalidDiscoveryControl(run.runDir);
			if (!discoveredIdentity) continue;
			if (!normalizeInvalidDiscoveryControls(run.runDir, discoveredIdentity, targetLiveness)) continue;
			const normalizedRun = loadActiveRun(run.runDir);
			if (!normalizedRun) {
				serviceRunPaths.delete(name);
				continue;
			}
			run = normalizedRun;
			targetLiveness = inspectServiceTargetLiveness(run);
			targetReportsLive = targetLiveness === "live";
			if (targetLiveness === "invalid" || run.runToken !== discoveredIdentity.runToken) {
				run.pid = undefined;
				run.processStartId = undefined;
			}
		}
		if (!currentServiceRunDirectory(run.runDir, run.directoryIdentity)) {
			serviceRunPaths.delete(name);
			continue;
		}
		const live = targetReportsLive && !durableStoppedIdentity;
		const legacyEvents = readEvents(run.runDir);
		let events = legacyEvents;
		if (live) {
			const targetPid = run.pid;
			if (targetPid === undefined) continue;
			try {
				let sampling = serviceSamplingRuns.get(run.runDir);
				if (!sampling) {
					sampling = {
						anomalyBurstUntilMs: 0,
						latencyBurstUntilMs: 0,
						nextSampleMs: nowMs + 1_000,
						diskPauseMarked: false,
					};
					serviceSamplingRuns.set(run.runDir, sampling);
					while (serviceSamplingRuns.size > 4096)
						serviceSamplingRuns.delete(serviceSamplingRuns.keys().next().value as string);
					if (activeIncidentCompactor?.admitObservation(256 * 1024) !== true) {
						serviceRecordDerived(run.runDir, "recorder-control", "service_sampling_storage_paused", {
							state: "paused",
							targetPid: run.pid,
							targetProcessStartId: run.processStartId ?? "",
						});
						sampling.diskPauseMarked = true;
						continue;
					}
					const baselineTransaction = acquireFallbackRunEvidenceAdmission(run.runDir);
					if (!baselineTransaction) continue;
					try {
						sampling.previous = baselineLinuxIncidentEvidence({
							runDir: run.runDir,
							pid: targetPid,
							processStartId: run.processStartId,
							dependencies: { recordRawSource: (occurrence) => recordLinuxRawSource(run.runDir, occurrence) },
						});
					} finally {
						baselineTransaction.release();
					}
				}
				if (!run.runToken || !run.processStartId) {
					sampling.liveRunEventsObservationState = "incomplete";
					sampling.liveRunEventsReadError = "live_trigger_intent_provenance_unavailable";
				} else {
					refreshLiveRunHistoryEvents(
						run.runDir,
						run.runId,
						run.runToken,
						targetPid,
						run.processStartId,
						sampling,
					);
				}
				reportDeferredLiveRunEventsObservation(run.runDir, targetPid, run.processStartId, sampling);
				if (sampling.liveRunEventsObservationState === "caught_up")
					events = mergeLiveIncidentEvents(legacyEvents, liveCausalSnapshotEvents(sampling));
				else if (sampling.liveSupervisorExit)
					events = mergeLiveIncidentEvents(legacyEvents, [liveObservationEvent(sampling.liveSupervisorExit)]);
				const latencyTrigger = [...events]
					.reverse()
					.find((event) => event.type === "list_status_sampling_trigger" && typeof event.requestId === "string");
				const triggerOccurrence =
					latencyTrigger?.recorderProvenance && typeof latencyTrigger.recorderProvenance === "object"
						? String((latencyTrigger.recorderProvenance as Record<string, unknown>).occurrenceId ?? "")
						: undefined;
				if (latencyTrigger && triggerOccurrence && triggerOccurrence !== sampling.lastLatencyTriggerOccurrence) {
					sampling.lastLatencyTriggerOccurrence = triggerOccurrence;
					sampling.latencyBurstUntilMs = Math.max(sampling.latencyBurstUntilMs, nowMs + 15_000);
				}
				if (nowMs >= sampling.nextSampleMs) {
					const admitted = activeIncidentCompactor?.admitObservation(256 * 1024) === true;
					if (!admitted) {
						if (!sampling.diskPauseMarked) {
							serviceRecordDerived(run.runDir, "recorder-control", "service_sampling_storage_paused", {
								state: "paused",
								targetPid: run.pid,
								targetProcessStartId: run.processStartId ?? "",
							});
							sampling.diskPauseMarked = true;
						}
						sampling.nextSampleMs = nowMs + 1_000;
						continue;
					}
					sampling.diskPauseMarked = false;
					const inAnomalyBurst = nowMs < sampling.anomalyBurstUntilMs;
					const inLatencyBurst = nowMs < sampling.latencyBurstUntilMs;
					const samplingTransaction = acquireFallbackRunEvidenceAdmission(run.runDir);
					if (!samplingTransaction) continue;
					const current = (() => {
						try {
							return sampleLinuxIncidentEvidence({
								runDir: run.runDir,
								phase: inAnomalyBurst ? "anomaly" : "periodic",
								dependencies: { recordRawSource: (occurrence) => recordLinuxRawSource(run.runDir, occurrence) },
							});
						} finally {
							samplingTransaction.release();
						}
					})();
					if (linuxCountersAdvanced(sampling.previous, current)) {
						sampling.anomalyBurstUntilMs = Math.max(sampling.anomalyBurstUntilMs, nowMs + 60_000);
						appendRunEvent(run.runDir, {
							type: "linux_cgroup_anomaly_burst_started",
							cadenceMs: 250,
							durationMs: 60_000,
						});
					}
					sampling.previous = current ?? sampling.previous;
					sampling.nextSampleMs =
						nowMs + (inLatencyBurst ? 100 : nowMs < sampling.anomalyBurstUntilMs ? 250 : 1_000);
				}
			} catch (error) {
				appendRunEvent(run.runDir, { type: "linux_evidence_unavailable", phase: "service-periodic", error });
			}
		}
		const completionPath = join(run.runDir, ".service-finalization-complete");
		const completionValue = readPrivateCanonicalJson<unknown>(completionPath);
		const completion = isRecordObject(completionValue) ? completionValue : undefined;
		const completionIsCurrent = completion
			? isCurrentServiceFinalizationCompletion(agentDir, run.runDir, completion)
			: false;
		if (completionIsCurrent) {
			discardServiceFinalizationState(run.runDir);
			continue;
		}
		if (existsSync(completionPath) && !quarantineInvalidServiceControl(run.runDir, completionPath, "completion")) {
			continue;
		}
		const exitEvent = [...events].reverse().find((event) => event.type === "supervisor_exit");
		const exited = exitEvent !== undefined;
		if (!live) {
			const runId = run.runId;
			if (!currentServiceRunDirectory(run.runDir, run.directoryIdentity)) {
				serviceRunPaths.delete(name);
				continue;
			}
			const stoppedIdentity = discoveredIdentity ?? serviceRunIdentity(run.runDir);
			const stoppedAtGate =
				stoppedIdentity?.runId === runId
					? durableServiceStoppedObservation(run.runDir, stoppedIdentity, nowMs, finalizationFault)
					: undefined;
			if (!stoppedIdentity || !stoppedAtGate) continue;
			let liveProxyGraceExpired = false;
			if (runHasLiveProxy(run.runDir)) {
				if (!serviceLiveProxyGraceElapsed(run.runDir, stoppedIdentity, stoppedAtGate, nowMs)) continue;
				liveProxyGraceExpired = true;
			}
			const compactedBarrier = hasCompactedFinalizationBarrier(run.runDir);
			if (!compactedBarrier && !serviceBarrierRetryElapsed(run.runDir, stoppedIdentity, nowMs)) {
				const pendingPath = join(run.runDir, ".service-finalization-pending");
				if (!existsSync(pendingPath) && !activeIncidentCompactor?.diskPaused)
					writeImmutableJsonOnce(pendingPath, {
						state: "waiting_for_compacted_supervisor_exit_and_wrapper_frontier",
						retryable: true,
						observed: nowFields(),
					});
				continue;
			}
			const incidentsDirectory = join(agentDir, "incidents");
			const incidentId = basename(run.runDir);
			const recovered = recoverPublishedIncidentFinalization({ incidentsDirectory, incidentId });
			const recoveredSealProof =
				recovered.state !== "pending" &&
				stoppedIdentity.runId === runId &&
				recovered.runId === runId &&
				recovered.manifest.runIdentity.runToken === stoppedIdentity.runToken
					? serviceCompletionSealProof(run.runDir)
					: undefined;
			if (
				recovered.state !== "pending" &&
				recoveredSealProof !== undefined &&
				recoveredSealProof.identity.runToken === stoppedIdentity.runToken &&
				(!liveProxyGraceExpired ||
					(recovered.state !== "complete" &&
						["live_proxy_grace_expired", "replayed_after_ambiguous_seal_attempt"].includes(
							recovered.serviceTerminalRelayDisposition,
						))) &&
				serviceCompletionSemanticsValid(
					run.runDir,
					recoveredSealProof,
					recovered.state,
					recovered.serviceTerminalRelayDisposition,
				)
			) {
				const expectedPublicationIntent: ServiceFinalizationPublicationIntent = {
					schemaVersion: 1,
					kind: "service_finalization_publication_intent",
					runId,
					finalizationId: recovered.finalizationId,
				};
				let recoveredPublicationIntent = readServiceFinalizationPublicationIntent(
					run.runDir,
					recovered.finalizationId,
				);
				if (
					recoveredPublicationIntent?.runId !== runId ||
					recoveredPublicationIntent.finalizationId !== recovered.finalizationId
				) {
					if (!persistServiceFinalizationPublicationIntent(run.runDir, expectedPublicationIntent)) continue;
					recoveredPublicationIntent = readServiceFinalizationPublicationIntent(
						run.runDir,
						recovered.finalizationId,
					);
				}
				if (
					recoveredPublicationIntent?.runId !== runId ||
					recoveredPublicationIntent.finalizationId !== recovered.finalizationId
				) {
					continue;
				}
				const runtime = serviceFinalizationRuns.get(run.runDir);
				if (runtime?.retained && activeIncidentCompactor) {
					try {
						activeIncidentCompactor.releaseRunHistoryPublication(runtime.retained.publicationCapability);
					} catch {
						continue;
					}
					runtime.retained = undefined;
				}
				const anchor = recovered.retentionAnchorWallTimeMs;
				if (anchor === null || !activeIncidentCompactor) continue;
				try {
					activeIncidentCompactor.requestPin(runId, join(incidentsDirectory, incidentId), anchor);
				} catch {
					continue;
				}
				if (
					persistIncidentRetentionAuthority({
						incidentDirectory: join(incidentsDirectory, incidentId),
						finalizationId: recovered.finalizationId,
						runId,
						outcome: recovered.state,
						retentionAnchorWallTimeMs: anchor,
					}).state !== "authorized"
				) {
					continue;
				}
				finalizationFault("after_source_marker_before_reclaim_complete");
				if (
					!persistServiceFinalizationCompletion(run.runDir, {
						schemaVersion: 2,
						state: "incident_reclaimable",
						runId,
						finalizationId: recovered.finalizationId,
						outcome: recovered.state,
						retentionAnchorWallTimeMs: anchor,
					})
				) {
					continue;
				}
				discardServiceFinalizationState(run.runDir);
				serviceSamplingRuns.delete(run.runDir);
				nodeReportCaptureStates.delete(run.runDir);
				providerArtifactCaptureStates.delete(run.runDir);
				finalized.push(join(incidentsDirectory, incidentId));
				continue;
			}
			const recoveredPublicationConflict = currentServiceFinalizationPublicationConflict(agentDir, run.runDir);
			if (recoveredPublicationConflict) {
				const runtime = serviceFinalizationRuns.get(run.runDir);
				if (runtime?.retained && activeIncidentCompactor) {
					try {
						activeIncidentCompactor.releaseRunHistoryPublication(runtime.retained.publicationCapability);
					} catch {
						continue;
					}
					runtime.retained = undefined;
				}
				finalizationFault("after_source_marker_before_reclaim_complete");
				if (
					!persistServiceFinalizationCompletion(run.runDir, {
						schemaVersion: 2,
						state: "publication_conflict_reclaimable",
						runId,
						publishedFinalizationId: recoveredPublicationConflict.publishedFinalizationId,
						intendedFinalizationId: recoveredPublicationConflict.intendedFinalizationId,
						conflictProofSha256: serviceFinalizationPublicationConflictDigest(recoveredPublicationConflict),
						retentionAnchorWallTimeMs: Math.max(
							recoveredPublicationConflict.publishedRetentionAnchorWallTimeMs,
							recoveredPublicationConflict.intendedRetentionAnchorWallTimeMs,
						),
					})
				) {
					continue;
				}
				discardServiceFinalizationState(run.runDir);
				serviceSamplingRuns.delete(run.runDir);
				nodeReportCaptureStates.delete(run.runDir);
				providerArtifactCaptureStates.delete(run.runDir);
				finalized.push(join(incidentsDirectory, incidentId));
				continue;
			}
			const runIdentity = stoppedIdentity;
			if (!runIdentity || runIdentity.runId !== runId) continue;
			const stoppedObservation = durableServiceStoppedObservation(run.runDir, runIdentity, nowMs, finalizationFault);
			if (!stoppedObservation) continue;
			const sealIntentPath = join(run.runDir, "service-finalization-seal-intent.json");
			const serviceSealPath = join(run.runDir, "service-finalization-seal.json");
			const sealReplayPath = join(run.runDir, "service-finalization-seal-replay-ambiguity.json");
			const sealNamespaceObserved =
				existsSync(sealIntentPath) || existsSync(serviceSealPath) || existsSync(sealReplayPath);
			let durableIntent = currentServiceRunSealIntent(run.runDir, runIdentity);
			const invalidSealIntentObserved = existsSync(sealIntentPath) && !durableIntent;
			let sealIntentAlreadyDurable = durableIntent !== undefined;
			let serviceSeal: IncidentRecorderRunIdentitySealResult | undefined;
			let replayedAmbiguousSealAttempt = false;
			if (!durableIntent) {
				const adoptedSeal = adoptPreexistingServiceRunSealWithoutIntent(run.runDir, runIdentity);
				if (adoptedSeal) {
					const existingReplayPlan = currentServiceRunSealReplayAmbiguityForIdentity(run.runDir, runIdentity);
					const replayPlan = durableServiceRunSealReplayAmbiguityBinding(
						run.runDir,
						{
							runId: runIdentity.runId,
							runToken: runIdentity.runToken,
							terminalOccurrenceId:
								serviceSealTerminalOccurrenceId(adoptedSeal) ??
								existingReplayPlan?.terminalOccurrenceId ??
								randomUUID(),
						},
						"seal_observed_without_intent",
					);
					if (!replayPlan) continue;
					finalizationFault("after_replay_marker_durable_before_reconstructed_intent");
					durableIntent = durableServiceRunSealIntent(run.runDir, runIdentity, replayPlan.terminalOccurrenceId);
					if (!durableIntent) continue;
					serviceSeal = adoptedSeal;
					sealIntentAlreadyDurable = true;
					replayedAmbiguousSealAttempt = true;
				}
			}
			const serviceSealAlreadyDurable =
				serviceSeal !== undefined || (sealIntentAlreadyDurable && existsSync(serviceSealPath));
			const replayAmbiguityAlreadyDurable =
				durableIntent !== undefined &&
				currentServiceRunSealReplayAmbiguity(run.runDir, durableIntent) !== undefined;
			const sealAttemptAlreadyDurable =
				sealNamespaceObserved || sealIntentAlreadyDurable || serviceSealAlreadyDurable;
			replayedAmbiguousSealAttempt ||= replayAmbiguityAlreadyDurable;
			if (
				!serviceSeal &&
				sealIntentAlreadyDurable &&
				(!serviceSealAlreadyDurable || replayAmbiguityAlreadyDurable)
			) {
				const durableIntent = durableServiceRunSealIntent(run.runDir, runIdentity);
				if (!durableIntent) continue;
				const ambiguity = durableServiceRunSealReplayAmbiguity(run.runDir, durableIntent);
				if (!ambiguity) continue;
				replayedAmbiguousSealAttempt = true;
			}
			if (!serviceSeal && sealAttemptAlreadyDurable) {
				const adoptedSeal = adoptPreexistingServiceRunSealWithoutIntent(run.runDir, runIdentity);
				if (adoptedSeal) {
					const adoptedOccurrenceId = serviceSealTerminalOccurrenceId(adoptedSeal);
					if (
						durableIntent &&
						adoptedOccurrenceId === undefined &&
						!durableServiceRunSealReplayAmbiguity(run.runDir, durableIntent, "seal_intent_without_seal_observed")
					) {
						continue;
					}
					if (
						durableIntent &&
						adoptedOccurrenceId !== undefined &&
						adoptedOccurrenceId !== durableIntent.terminalOccurrenceId
					) {
						if (
							!durableServiceRunSealReplayAmbiguity(
								run.runDir,
								durableIntent,
								"seal_namespace_invalid_or_unbound",
							)
						) {
							continue;
						}
						replayedAmbiguousSealAttempt = true;
					}
					serviceSeal = adoptedSeal;
				} else {
					const ambiguityReason =
						invalidSealIntentObserved || existsSync(serviceSealPath) || existsSync(sealReplayPath)
							? "seal_namespace_invalid_or_unbound"
							: "seal_intent_without_seal_observed";
					serviceSeal = durableAmbiguousServiceRunFence(run.runDir, runIdentity, ambiguityReason);
					replayedAmbiguousSealAttempt = serviceSeal !== undefined;
				}
			}
			if (sealAttemptAlreadyDurable && !serviceSeal) continue;
			replayedAmbiguousSealAttempt ||= existsSync(
				join(run.runDir, "service-finalization-seal-replay-ambiguity.json"),
			);
			if (!serviceSeal) {
				let stoppedState = serviceSamplingRuns.get(run.runDir);
				if (!stoppedState) {
					stoppedState = {
						anomalyBurstUntilMs: 0,
						latencyBurstUntilMs: 0,
						nextSampleMs: Number.MAX_SAFE_INTEGER,
						diskPauseMarked: false,
					};
					serviceSamplingRuns.set(run.runDir, stoppedState);
					while (serviceSamplingRuns.size > 4096)
						serviceSamplingRuns.delete(serviceSamplingRuns.keys().next().value as string);
				}
				if (!activeIncidentCompactor?.admitObservation(8 * 1024 * 1024)) {
					if (!stoppedState.diskPauseMarked) {
						serviceRecordDerived(run.runDir, "recorder-control", "stopped_target_capture_storage_paused", {
							state: "pending",
							targetPid: run.pid,
							targetProcessStartId: run.processStartId ?? "",
						});
						stoppedState.diskPauseMarked = true;
					}
					continue;
				}
				stoppedState.diskPauseMarked = false;
				if (!stoppedState.stoppedBroadCaptured)
					try {
						const finalSamplingTransaction = acquireFallbackRunEvidenceAdmission(run.runDir);
						if (!finalSamplingTransaction) continue;
						try {
							sampleLinuxIncidentEvidence({
								runDir: run.runDir,
								phase: "final",
								captureBroadRaw: true,
								dependencies: { recordRawSource: (occurrence) => recordLinuxRawSource(run.runDir, occurrence) },
							});
						} finally {
							finalSamplingTransaction.release();
						}
						if (run.pid === undefined) {
							appendRunEvent(run.runDir, {
								type: "stopped_target_proc_capture_unavailable_after_exit",
								reason: "target_identity_control_invalid_or_missing",
							});
						} else {
							if (getProcessStartId(run.pid) !== run.processStartId)
								appendRunEvent(run.runDir, {
									type: "stopped_target_proc_capture_unavailable_after_exit",
									childPid: run.pid,
									reason: "proc_identity_no_longer_present",
								});
							captureProcSafely(run.runDir, run.pid, run.processStartId, (sourcePath, value) =>
								recordLinuxRawSource(run.runDir, {
									source: "procfs",
									sourcePath,
									bytes: value,
									encoding: "exact-file-bytes",
									phase: "incident-pin",
									...nowFields(),
									identity: { targetPid: run.pid, targetProcessStartId: run.processStartId },
								}),
							);
						}
						stoppedState.stoppedBroadCaptured = true;
					} catch (error) {
						stoppedState.stoppedBroadCaptured = true;
						appendRunEvent(run.runDir, { type: "linux_evidence_unavailable", phase: "service-final", error });
					}
				const reportCapture = await sanitizeNodeReports(run.runDir, true);
				if (reportCapture !== "complete") {
					if (!stoppedState.nodeReportPendingMarked) {
						appendRunEvent(run.runDir, { type: "stopped_target_report_capture_pending", state: "pending" });
						stoppedState.nodeReportPendingMarked = true;
					}
					continue;
				}
				if (captureStoppedProviderArtifacts(run.runDir) !== "complete") continue;
				await flushRecordedProcessBytes(run.runDir);
			}
			const expectedExit = readExpectedExitDisposition(run.runDir);
			const code = typeof exitEvent?.code === "number" ? exitEvent.code : expectedExit.code;
			const signal =
				typeof exitEvent?.signal === "string" ? (exitEvent.signal as NodeJS.Signals) : expectedExit.signal;
			const correlation = readLinuxIncidentEvidenceCorrelation(run.runDir);
			if (!sealAttemptAlreadyDurable && !exited && correlation.environmentClassification) {
				appendRunEvent(run.runDir, {
					type: "environment_exit_correlated",
					childPid: run.pid,
					classification: correlation.environmentClassification,
					attribution: "supporting_evidence",
				});
			}
			if (!sealAttemptAlreadyDurable) {
				finalizationFault("after_stopped_capture_before_seal");
			}
			if (
				!serviceSeal &&
				!sealAttemptAlreadyDurable &&
				(invalidSealIntentObserved ||
					existsSync(join(run.runDir, "service-finalization-seal-replay-ambiguity.json")))
			) {
				const recoveredIntent = durableServiceRunSealIntent(run.runDir, runIdentity);
				if (!recoveredIntent || !durableServiceRunSealReplayAmbiguity(run.runDir, recoveredIntent)) continue;
				replayedAmbiguousSealAttempt = true;
			}
			serviceSeal ??= await durableServiceRunSeal(run.runDir, runIdentity);
			if (!serviceSeal) continue;
			const sealedIntent = currentServiceRunSealIntent(run.runDir, runIdentity);
			const sealedReplay = sealedIntent ? currentServiceRunSealReplayAmbiguity(run.runDir, sealedIntent) : undefined;
			if (existsSync(sealReplayPath) && !sealedReplay) continue;
			replayedAmbiguousSealAttempt ||= sealedReplay !== undefined;
			finalizationFault("after_seal_before_terminal_frontier");
			const retentionAnchorWallTimeMs = stableRunRetentionAnchor(run.runDir, runIdentity);
			if (retentionAnchorWallTimeMs === undefined) continue;

			const observedBarrier = compactedBarrier ? readFinalizationBarrierExpectation(run.runDir) : undefined;
			const barrierMatchesIdentity =
				observedBarrier?.runId === runIdentity.runId && observedBarrier.runToken === runIdentity.runToken;
			if (observedBarrier && !barrierMatchesIdentity && runIdentity.disposition === "exact_process_control") {
				continue;
			}
			const barrier = barrierMatchesIdentity ? observedBarrier : undefined;
			const serviceFrontier = finalizerFrontier(
				serviceSeal.terminal.frontier ?? undefined,
				"capture_channel_terminal",
			);
			const runtime = serviceFinalizationState(run.runDir);
			let projected: IncidentRecorderRetainedRunHistoryResult | undefined = runtime.retained;
			if (!projected) {
				try {
					projected = activeIncidentCompactor?.projectRunHistory({
						runId,
						fromWallTimeMs: 0,
						throughWallTimeMs: Number.MAX_SAFE_INTEGER,
						cursor: runtime.cursor,
						deadlineMs: Date.now() + 30_000,
						retainForPublication: true,
						pendingResponse: "cursor-only",
					});
				} catch (error) {
					if (
						error instanceof Error &&
						error.message === "Incident run-history projection capacity is saturated"
					) {
						continue;
					}
					throw error;
				}
			}
			if (!projected || projected.state === "pending") {
				if (projected?.state === "pending") runtime.cursor = projected.cursor;
				continue;
			}
			runtime.cursor = undefined;
			if (projected.state === "complete") runtime.retained = projected;
			const runHistory: IncidentRecorderRunHistoryResult =
				projected.state === "complete"
					? { state: "complete", projection: projected.projection, snapshot: projected.snapshot }
					: projected;
			const classificationEvents = runHistory.projection.events.flatMap((event): IncidentRecorderEvent[] => {
				if (event.payloadKind !== "derived-scalar") return [];
				const eventWallTimeMs = Number(event.eventWallTimeMs);
				const eventDate = new Date(eventWallTimeMs);
				return [
					{
						...event.metadata,
						type: event.type,
						wallTime: Number.isNaN(eventDate.getTime()) ? new Date(0).toISOString() : eventDate.toISOString(),
						monotonicNs: event.eventMonotonicNs,
						pid: typeof event.metadata.producerPid === "number" ? event.metadata.producerPid : 0,
						canonicalEventWallTimeMs: event.eventWallTimeMs,
						recorderProvenance: {
							occurrenceId: event.identity.occurrenceId,
							producerId: event.identity.producerId,
							source: event.source,
							compactorCommitted: true,
						},
					},
				];
			});
			const classification =
				correlation.environmentClassification ?? classify(classificationEvents, code, signal, run.runDir);
			if (
				serviceFrontier &&
				!projectionContainsFinalizerFrontier(runHistory, serviceFrontier) &&
				!serviceProjectionRetryElapsed(run.runDir, runIdentity, serviceFrontier, nowMs)
			) {
				discardServiceFinalizationState(run.runDir);
				continue;
			}
			const capability = projected.state === "complete" ? projected.publicationCapability : undefined;
			if (capability && activeIncidentCompactor) {
				try {
					activeIncidentCompactor.assertRunHistoryPublicationReady(capability);
				} catch {
					runtime.retained = undefined;
					continue;
				}
			}
			const terminalRelayDisposition = replayedAmbiguousSealAttempt
				? "replayed_after_ambiguous_seal_attempt"
				: stoppedObservation.disposition !== "exact_first_observation"
					? "recovered_after_invalid_stopped_observation"
					: liveProxyGraceExpired
						? "live_proxy_grace_expired"
						: serviceTerminalRelayDisposition(serviceSeal);
			const finalizationInput: IncidentRecorderFinalizationInput = {
				incidentsDirectory,
				incidentId,
				runIdentity: { runId: runIdentity.runId, runToken: runIdentity.runToken },
				runHistory,
				terminalExpectations: {
					supervisorExit: terminalExpectation(
						finalizerFrontier(barrier?.supervisorExit, "supervisor_exit"),
						"wrapper_supervisor_exit_frontier_unavailable",
					),
					wrapperTerminal: terminalExpectation(
						finalizerFrontier(barrier?.wrapperTerminal, "capture_channel_terminal"),
						"wrapper_terminal_frontier_unavailable",
					),
					serviceTerminal: terminalExpectation(serviceFrontier, "service_terminal_frontier_unavailable"),
				},
				classification: { value: classification, causeLayer: incidentCauseLayer(classification, correlation) },
				exit: { code, signal },
				retentionAnchorWallTimeMs,
				stoppedTarget: stoppedTargetFinalizationArtifacts(run.runDir),
				wrapperLoss: {
					finalQueuedTailLoss: barrier?.finalQueuedTailLoss ?? { records: 0, bytes: 0 },
					emitterFinalTailLoss: barrier?.emitterFinalTailLoss ?? { records: 0, bytes: 0 },
				},
				serviceSeal: {
					terminalRelayDisposition,
					emitterLoss: serviceSeal.loss.emitter,
					drainTimeoutLoss: serviceSeal.loss.drainTimeout,
					terminalRelayLoss: serviceSeal.loss.terminalRelay,
				},
				...(capability && activeIncidentCompactor
					? {
							assertProjectionLeaseUsable: () =>
								activeIncidentCompactor?.assertRunHistoryPublicationReady(capability),
							releaseProjectionLease: () => {
								activeIncidentCompactor?.releaseRunHistoryPublication(capability);
								if (runtime.retained?.publicationCapability === capability) runtime.retained = undefined;
							},
						}
					: {}),
			};
			const analysis = analyzeIncidentRecorderFinalization(finalizationInput);
			if (analysis.state === "pending") continue;
			const completionProof = serviceCompletionSealProof(run.runDir);
			if (
				!completionProof ||
				!serviceCompletionSemanticsValid(run.runDir, completionProof, analysis.state, terminalRelayDisposition)
			) {
				continue;
			}
			if (
				classification === "normal" &&
				analysis.state === "complete" &&
				serviceCompletionSemanticsValid(run.runDir, completionProof, "complete", terminalRelayDisposition)
			) {
				try {
					finalizationInput.releaseProjectionLease?.();
				} catch {
					continue;
				}
				const terminalOccurrenceId = serviceSealTerminalOccurrenceId(serviceSeal);
				if (
					!terminalOccurrenceId ||
					!persistServiceNormalRetentionAuthority(run.runDir, {
						schemaVersion: 1,
						kind: "service_normal_retention_authority",
						runId,
						runToken: runIdentity.runToken,
						finalizationId: analysis.finalizationId,
						classification: "normal",
						analysisState: "complete",
						retentionAnchorWallTimeMs,
						terminalOccurrenceId,
					})
				) {
					continue;
				}
				if (
					!persistServiceFinalizationCompletion(run.runDir, {
						schemaVersion: 2,
						state: "normal_reclaimable",
						runId,
						finalizationId: analysis.finalizationId,
						classification: "normal",
						retentionAnchorWallTimeMs,
					})
				) {
					continue;
				}
				discardServiceFinalizationState(run.runDir);
				serviceSamplingRuns.delete(run.runDir);
				nodeReportCaptureStates.delete(run.runDir);
				providerArtifactCaptureStates.delete(run.runDir);
				continue;
			}
			if (
				!persistServiceFinalizationPublicationIntent(run.runDir, {
					schemaVersion: 1,
					kind: "service_finalization_publication_intent",
					runId,
					finalizationId: analysis.finalizationId,
				})
			) {
				continue;
			}
			const finalization = finalizeIncidentRecorderProjection(finalizationInput, {
				onFaultBoundary: finalizationFault,
			});
			if (finalization.publication === "ambiguous") continue;
			if (
				finalization.publication === "noop" &&
				finalization.reason === "published_finalization_conflict" &&
				finalization.finalizationId !== analysis.finalizationId
			) {
				const conflictingPublished = recoverPublishedIncidentFinalization({
					incidentsDirectory,
					incidentId,
					expectedFinalizationId: finalization.finalizationId,
				});
				if (
					conflictingPublished.state === "pending" ||
					conflictingPublished.finalizationId !== finalization.finalizationId ||
					conflictingPublished.runId !== runId ||
					conflictingPublished.manifest.runIdentity.runToken !== runIdentity.runToken ||
					conflictingPublished.retentionAnchorWallTimeMs === null ||
					analysis.retentionAnchorWallTimeMs === null ||
					conflictingPublished.retentionAnchorWallTimeMs !== analysis.retentionAnchorWallTimeMs ||
					serviceCompletionSemanticsValid(
						run.runDir,
						completionProof,
						conflictingPublished.state,
						conflictingPublished.serviceTerminalRelayDisposition,
					) ||
					!serviceCompletionSemanticsValid(run.runDir, completionProof, analysis.state, terminalRelayDisposition)
				) {
					continue;
				}
				if (!activeIncidentCompactor) continue;
				try {
					activeIncidentCompactor.requestPin(
						runId,
						join(incidentsDirectory, incidentId),
						conflictingPublished.retentionAnchorWallTimeMs,
					);
				} catch {
					continue;
				}
				const conflictingRetentionAuthority = persistIncidentRetentionAuthority({
					incidentDirectory: join(incidentsDirectory, incidentId),
					finalizationId: conflictingPublished.finalizationId,
					runId,
					outcome: conflictingPublished.state,
					retentionAnchorWallTimeMs: conflictingPublished.retentionAnchorWallTimeMs,
				});
				if (
					conflictingRetentionAuthority.state !== "authorized" ||
					conflictingRetentionAuthority.finalizationId !== conflictingPublished.finalizationId ||
					conflictingRetentionAuthority.runId !== runId ||
					conflictingRetentionAuthority.outcome !== conflictingPublished.state ||
					conflictingRetentionAuthority.retentionAnchorWallTimeMs !==
						conflictingPublished.retentionAnchorWallTimeMs
				) {
					continue;
				}
				const conflict: ServiceFinalizationPublicationConflict = {
					schemaVersion: 1,
					kind: "service_finalization_publication_conflict",
					runId,
					runToken: runIdentity.runToken,
					publishedFinalizationId: conflictingPublished.finalizationId,
					publishedState: conflictingPublished.state,
					publishedRetentionAnchorWallTimeMs: conflictingPublished.retentionAnchorWallTimeMs,
					publishedServiceTerminalRelayDisposition: conflictingPublished.serviceTerminalRelayDisposition,
					intendedFinalizationId: analysis.finalizationId,
					intendedState: analysis.state,
					intendedRetentionAnchorWallTimeMs: analysis.retentionAnchorWallTimeMs,
					intendedServiceTerminalRelayDisposition: terminalRelayDisposition,
					reason: "published_finalization_conflict",
				};
				if (!persistServiceFinalizationPublicationConflict(run.runDir, conflict)) continue;
				const currentConflict = currentServiceFinalizationPublicationConflict(agentDir, run.runDir);
				if (!currentConflict || !canonicalJsonValuesEqual(currentConflict, conflict)) continue;
				finalizationFault("after_source_marker_before_reclaim_complete");
				if (
					!persistServiceFinalizationCompletion(run.runDir, {
						schemaVersion: 2,
						state: "publication_conflict_reclaimable",
						runId,
						publishedFinalizationId: conflict.publishedFinalizationId,
						intendedFinalizationId: conflict.intendedFinalizationId,
						conflictProofSha256: serviceFinalizationPublicationConflictDigest(conflict),
						retentionAnchorWallTimeMs: Math.max(
							conflict.publishedRetentionAnchorWallTimeMs,
							conflict.intendedRetentionAnchorWallTimeMs,
						),
					})
				) {
					continue;
				}
				discardServiceFinalizationState(run.runDir);
				serviceSamplingRuns.delete(run.runDir);
				nodeReportCaptureStates.delete(run.runDir);
				providerArtifactCaptureStates.delete(run.runDir);
				finalized.push(join(incidentsDirectory, incidentId));
				continue;
			}
			const published = recoverPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: analysis.finalizationId,
			});
			if (
				published.state === "pending" ||
				published.runId !== runId ||
				published.finalizationId !== analysis.finalizationId ||
				published.retentionAnchorWallTimeMs === null
			)
				continue;
			const publishedProof = serviceCompletionSealProof(run.runDir);
			if (
				!publishedProof ||
				!serviceCompletionSemanticsValid(
					run.runDir,
					publishedProof,
					published.state,
					published.serviceTerminalRelayDisposition,
				)
			) {
				continue;
			}
			if (!activeIncidentCompactor) continue;
			try {
				activeIncidentCompactor.requestPin(
					runId,
					join(incidentsDirectory, incidentId),
					published.retentionAnchorWallTimeMs,
				);
			} catch {
				continue;
			}
			if (
				persistIncidentRetentionAuthority({
					incidentDirectory: join(incidentsDirectory, incidentId),
					finalizationId: published.finalizationId,
					runId,
					outcome: published.state,
					retentionAnchorWallTimeMs: published.retentionAnchorWallTimeMs,
				}).state !== "authorized"
			) {
				continue;
			}
			finalizationFault("after_source_marker_before_reclaim_complete");
			if (
				!persistServiceFinalizationCompletion(run.runDir, {
					schemaVersion: 2,
					state: "incident_reclaimable",
					runId,
					finalizationId: published.finalizationId,
					outcome: published.state,
					retentionAnchorWallTimeMs: published.retentionAnchorWallTimeMs,
				})
			) {
				continue;
			}
			discardServiceFinalizationState(run.runDir);
			serviceSamplingRuns.delete(run.runDir);
			nodeReportCaptureStates.delete(run.runDir);
			providerArtifactCaptureStates.delete(run.runDir);
			finalized.push(join(incidentsDirectory, incidentId));
			continue;
		}
		if (exited) continue;
		const sampling = serviceSamplingRuns.get(run.runDir);
		const liveEvidenceCaughtUp = !live || sampling?.liveRunEventsObservationState === "caught_up";
		const heartbeats = liveEvidenceCaughtUp ? events.filter((event) => event.type === "supervisor_heartbeat") : [];
		const lastHeartbeat = liveEvidenceCaughtUp ? sampling?.liveLastHeartbeat : undefined;
		const fallbackHeartbeat = heartbeats.at(-1);
		const heartbeatWall =
			lastHeartbeat?.eventWallTimeMs ?? (fallbackHeartbeat ? Date.parse(fallbackHeartbeat.wallTime) : Number.NaN);
		const heartbeatObserved = lastHeartbeat !== undefined || fallbackHeartbeat !== undefined;
		const socketWasPresent =
			liveEvidenceCaughtUp &&
			(sampling?.liveSocketWasPresent === true || heartbeats.some((event) => event.socketExists === true));
		let detected: "event_loop_hang" | "socket_loss" | "worker_response_hang" | undefined;
		if (
			liveEvidenceCaughtUp &&
			events.some((event) => event.type === "worker_request_end" && event.outcome === "timeout")
		)
			detected = "worker_response_hang";
		else if (heartbeatObserved && Number.isFinite(heartbeatWall) && nowMs - heartbeatWall > STALL_THRESHOLD_MS)
			detected = "event_loop_hang";
		else if (socketWasPresent && run.socketPath !== undefined && !existsSync(run.socketPath))
			detected = "socket_loss";
		if (!detected) continue;
		if (sampling?.liveHangClassification === detected) continue;
		if (sampling) sampling.liveHangClassification = detected;
		appendRunEvent(run.runDir, {
			type:
				detected === "event_loop_hang"
					? "heartbeat_stalled"
					: detected === "socket_loss"
						? "socket_lost"
						: "worker_hang_detected",
			childPid: run.pid,
		});
		appendRunEvent(run.runDir, {
			type: "broad_proc_capture_deferred_target_live",
			childPid: run.pid,
			reason: "stopped_target_identity_required",
			state: "deferred_or_unavailable",
		});
	}
	return finalized;
}

function serviceInspectionCadenceMs(nowMs = Date.now()): number {
	for (const sampling of serviceSamplingRuns.values()) if (nowMs < sampling.latencyBurstUntilMs) return 100;
	return 250;
}

type IncidentRecorderShutdownSignal = "SIGINT" | "SIGTERM";

export interface IncidentRecorderServiceSignalSource {
	once(signal: IncidentRecorderShutdownSignal, listener: () => void): unknown;
	off(signal: IncidentRecorderShutdownSignal, listener: () => void): unknown;
}

interface IncidentRecorderServiceCleanupFailure {
	operation: string;
	error: unknown;
}

function attemptIncidentRecorderServiceCleanup(
	failures: IncidentRecorderServiceCleanupFailure[],
	operation: string,
	cleanup: () => unknown,
): void {
	try {
		cleanup();
	} catch (error) {
		failures.push({ operation, error });
	}
}

function incidentRecorderServiceCleanupError(
	context: string,
	failures: readonly IncidentRecorderServiceCleanupFailure[],
): unknown {
	if (failures.length === 1) return failures[0].error;
	return new AggregateError(
		failures.map((failure) => failure.error),
		`${context}: ${failures.map((failure) => failure.operation).join(", ")}`,
	);
}

function incidentRecorderSignalRegistrationError(
	registrationError: unknown,
	rollbackFailures: readonly IncidentRecorderServiceCleanupFailure[],
): unknown {
	if (rollbackFailures.length === 0) return registrationError;
	return new AggregateError(
		[registrationError, ...rollbackFailures.map((failure) => failure.error)],
		`Incident recorder signal registration failed; rollback also failed: ${rollbackFailures
			.map((failure) => failure.operation)
			.join(", ")}`,
	);
}

export type IncidentRecorderServiceNotifier = (fields: readonly string[]) => void;

export interface RunIncidentRecorderServiceOptions {
	writerLifecycleContract?: IncidentRecorderWriterLifecycleAdmissionContract;
	journalctlPath?: string;
	/** Test/packaging overrides; the service always supplies agentDir and journalctlPath. */
	compactorOptions?: Omit<IncidentRecorderCompactorOptions, "agentDir" | "journalctlPath">;
	notify?: IncidentRecorderServiceNotifier;
	signalSource?: IncidentRecorderServiceSignalSource;
	writerStopDeadlineMs?: number;
	/** Test-only recovery retry cadence override. */
	storageRecoveryCadenceMs?: number;
	/** Test-only dependency injection for bounded wrapper-frontier exhaustion. */
	wrapperFrontier?: IncidentRecorderWrapperFrontier;
	/** Test-only dependency injection for bounded durable service-identity fence exhaustion. */
	serviceIdentitySealFenceMaxIdentities?: number;
}

function notifyIncidentRecorderSystemd(fields: readonly string[]): void {
	if (!process.env.NOTIFY_SOCKET) return;
	const result = spawnSync("/usr/bin/systemd-notify", [...fields], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
		timeout: 2_000,
	});
	if (result.error || result.status !== 0) {
		const detail = result.error?.message ?? (String(result.stderr ?? "").trim() || "unknown notification error");
		throw new Error(`Incident recorder systemd notification failed: ${detail}`);
	}
}

function defaultIncidentRecorderSignalSource(): IncidentRecorderServiceSignalSource {
	return {
		once: (signal, listener) => process.once(signal, listener),
		off: (signal, listener) => process.off(signal, listener),
	};
}

export async function runIncidentRecorderService(
	agentDir = getAgentDir(),
	options: RunIncidentRecorderServiceOptions = {},
): Promise<void> {
	if (process.platform !== "linux")
		throw new Error("Incident recorder service requires Linux journald namespace support");
	if (!options.writerLifecycleContract)
		throw new Error("Incident recorder service requires its v2 activation contract");
	const writerStopDeadlineMs = options.writerStopDeadlineMs ?? 5_000;
	if (!Number.isSafeInteger(writerStopDeadlineMs) || writerStopDeadlineMs < 1 || writerStopDeadlineMs > 10_000)
		throw new Error("Invalid incident recorder writer shutdown deadline");
	const notify = options.notify ?? notifyIncidentRecorderSystemd;
	const signalSource = options.signalSource ?? defaultIncidentRecorderSignalSource();
	const shutdown = new AbortController();
	let resolveStopRequested: () => void = () => {};
	const stopRequested = new Promise<void>((resolveStop) => {
		resolveStopRequested = resolveStop;
	});
	let stoppingNotified = false;
	let readyNotified = false;
	let writerAdmissionFailure: { error: unknown } | undefined;
	const notifyStopping = (status: string): void => {
		if (stoppingNotified) return;
		stoppingNotified = true;
		try {
			notify(["STOPPING=1", `STATUS=${status}`]);
		} catch {
			// Shutdown remains bounded even if the service manager notification path is unavailable.
		}
	};
	const requestShutdown = (signal: IncidentRecorderShutdownSignal): void => {
		if (shutdown.signal.aborted) return;
		notifyStopping(`Stopping after ${signal}`);
		shutdown.abort();
		resolveStopRequested();
	};
	let latchedWriterFatal:
		| IncidentRecorderWrapperFrontierSaturatedError
		| IncidentRecorderServiceIdentitySealFenceSaturatedError
		| undefined;
	const latchWriterFatal = (
		error: IncidentRecorderWrapperFrontierSaturatedError | IncidentRecorderServiceIdentitySealFenceSaturatedError,
	): void => {
		latchedWriterFatal ??= error;
		writerAdmissionFailure ??= { error };
		notifyStopping("Stopping after recorder writer failure");
		shutdown.abort();
		resolveStopRequested();
	};
	const onSigterm = () => requestShutdown("SIGTERM");
	const onSigint = () => requestShutdown("SIGINT");
	const signalRegistrations = [
		{ signal: "SIGTERM", listener: onSigterm },
		{ signal: "SIGINT", listener: onSigint },
	] as const;

	let lifecycle: IncidentRecorderServiceWriterLifecycle;
	const compactor = new IncidentRecorderCompactor({
		...options.compactorOptions,
		agentDir,
		journalctlPath: options.journalctlPath,
		writerLifecycleLease: () => lifecycle?.normalLease,
	});
	let serviceWriter: IncidentRecorderWriter | undefined;
	let normalInspectionOpen = false;
	// Lifecycle callbacks can run before the maintenance state is initialized below.
	let resetSegmentPruneState: () => void = () => {};
	const liveObservationValidationCheckpoints = new Map<string, IncidentRecorderLiveObservationValidationCheckpoint>();
	let inspectionRun: Promise<unknown> | undefined;
	const inspectAdmittedRuns = async (): Promise<void> => {
		if (!normalInspectionOpen) return;
		const pending = inspectIncidentRecorderRuns(agentDir);
		inspectionRun = pending;
		try {
			await pending;
		} finally {
			if (inspectionRun === pending) inspectionRun = undefined;
		}
	};
	lifecycle = new IncidentRecorderServiceWriterLifecycle(agentDir, options.writerLifecycleContract, {
		startNormalWriters: async () => {
			liveObservationValidationCheckpoints.clear();
			const admission = lifecycle.normalLease?.withRoot((root) => {
				const runs = root.relative("runs");
				root.mkdirPrivate(runs, true);
				root.fsyncDirectory(root.relative());
			});
			if (admission?.state !== "committed") throw new Error("Incident recorder run directory admission failed");
			serviceWriter = new IncidentRecorderWriter({
				runDir: join(agentDir, "incident-recorder"),
				runId: randomUUID(),
				runToken: randomUUID(),
				bootId: linuxBootId(),
				wrapperStartId: getProcessStartId(process.pid),
				serviceSink: true,
				wrapperFrontier: options.wrapperFrontier,
				onWrapperFrontierSaturated: latchWriterFatal,
				serviceIdentitySealFenceMaxIdentities: options.serviceIdentitySealFenceMaxIdentities,
				onServiceIdentitySealFenceSaturated: latchWriterFatal,
			});
			await serviceWriter.start({ requireJournal: true });
			compactor.resumeWriterResourcesForLifecycle();
			activeServiceRecorder = { writer: serviceWriter, compactor };
			normalInspectionOpen = true;
		},
		stopNormalWriters: async () => {
			normalInspectionOpen = false;
			liveObservationValidationCheckpoints.clear();
			resetSegmentPruneState();
			if (activeServiceRecorder?.writer === serviceWriter) activeServiceRecorder = undefined;
			await inspectionRun;
			if (hasWriterStopError) throw writerStopError;
			const failures: unknown[] = [];
			try {
				await serviceWriter?.stop(writerStopDeadlineMs);
			} catch (error) {
				hasWriterStopError = true;
				writerStopError = error;
				failures.push(error);
			}
			try {
				await compactor.closeWriterResourcesForLifecycle(writerStopDeadlineMs);
			} catch (error) {
				failures.push(error);
			}
			if (failures.length === 1) throw failures[0];
			if (failures.length > 1) throw new AggregateError(failures, "Incident recorder writer cleanup failed");
			serviceWriter = undefined;
		},
	});
	const attemptedSignalRegistrations: Array<(typeof signalRegistrations)[number]> = [];
	try {
		for (const registration of signalRegistrations) {
			attemptedSignalRegistrations.push(registration);
			signalSource.once(registration.signal, registration.listener);
		}
	} catch (registrationError) {
		const rollbackFailures: IncidentRecorderServiceCleanupFailure[] = [];
		for (const registration of attemptedSignalRegistrations.slice().reverse())
			attemptIncidentRecorderServiceCleanup(rollbackFailures, `signalSource.off(${registration.signal})`, () =>
				signalSource.off(registration.signal, registration.listener),
			);
		throw incidentRecorderSignalRegistrationError(registrationError, rollbackFailures);
	}
	let compactorRun: Promise<void> | undefined;
	let hasCompactorError = false;
	let firstCompactorError: unknown;
	const retainCompactorError = (error: unknown): void => {
		if (writerAdmissionFailure && writerAdmissionFailure.error === error) return;
		if (hasCompactorError) return;
		hasCompactorError = true;
		firstCompactorError = error;
	};
	let hasRunError = false;
	let runError: unknown;
	let hasWriterStopError = false;
	let writerStopError: unknown;
	const shutdownCleanupFailures: IncidentRecorderServiceCleanupFailure[] = [];
	try {
		await (async (): Promise<void> => {
			activeIncidentCompactor = compactor;
			if (shutdown.signal.aborted) return;
			let readerReady = false;
			let resolveReaderReady: () => void = () => {};
			const readerReadyPromise = new Promise<void>((resolveReady) => {
				resolveReaderReady = resolveReady;
			});
			let readinessGateComplete = false;
			let lastServiceStatus: string | undefined;
			let lastRecoveryReason: string | undefined;
			const announceNormalReady = (): void => {
				if (!readinessGateComplete || lastServiceStatus === "Incident recorder ready") return;
				if (!readyNotified) {
					notify(["READY=1", "STATUS=Incident recorder ready"]);
					readyNotified = true;
				} else notify(["STATUS=Incident recorder ready"]);
				lastServiceStatus = "Incident recorder ready";
			};
			const announceStorageMode = (mode: IncidentRecorderStorageMode, reason?: string): void => {
				if (mode !== "recovery-only") {
					lastRecoveryReason = undefined;
					announceNormalReady();
					return;
				}
				lastRecoveryReason = reason;
				const status = `Incident recorder recovery-only: ${reason ?? "storage_unavailable"}`;
				if (status === lastServiceStatus) return;
				if (!readyNotified) {
					notify(["READY=1", `STATUS=${status}`]);
					readyNotified = true;
				} else notify([`STATUS=${status}`]);
				lastServiceStatus = status;
			};
			compactorRun = compactor.run({
				signal: shutdown.signal,
				storageRecoveryCadenceMs: options.storageRecoveryCadenceMs,
				onStorageMode: announceStorageMode,
				onNormalWriterAdmission: async () => {
					if (shutdown.signal.aborted) return false;
					try {
						return (await lifecycle.enterNormal()).state === "normal";
					} catch (error) {
						writerAdmissionFailure = { error };
						throw error;
					}
				},
				onRecoveryPass: async () => {
					liveObservationValidationCheckpoints.clear();
					if (compactor.storageMode !== "recovery-only")
						throw new Error("Incident recorder recovery maintenance requires a closed recovery-only compactor");
					if ((await lifecycle.enterRecovery()).state !== "recovery") return false;
					const retention = runIncidentRetentionPass({
						agentDir,
						nowMs: Date.now(),
						recoveryOnly: true,
						writerLifecycleLease: lifecycle.recoveryLease,
						...INCIDENT_RETENTION_SERVICE_BUDGET,
					});
					// Recovery segment pruning remains fail-closed until the compactor-owned
					// continuation can restart when this proof generation changes. This
					// callback runs only after enterStorageRecovery has closed the store;
					// the recorder service is the external writer-start exclusion owner.
					if (retention.deletedEntries > 0) return false;
					return retention.moreWork;
				},
				onReaderReady: () => {
					if (readerReady) return;
					readerReady = true;
					resolveReaderReady();
				},
			});
			const monitoredCompactorRun = compactorRun.then(
				() => {
					if (!shutdown.signal.aborted) {
						const error = new Error("Incident recorder compactor exited unexpectedly");
						retainCompactorError(error);
						throw error;
					}
				},
				(error: unknown) => {
					retainCompactorError(error);
					throw error;
				},
			);
			monitoredCompactorRun.catch(() => {});
			await Promise.race([readerReadyPromise, monitoredCompactorRun]);
			if (shutdown.signal.aborted) return;
			if (!readerReady) throw new Error("Incident recorder compactor stopped before reader readiness");
			await Promise.race([inspectAdmittedRuns(), monitoredCompactorRun]);
			if (shutdown.signal.aborted) return;
			if (!serviceWriter?.journalReady) throw new Error("Incident recorder journal writer exited before readiness");
			readinessGateComplete = true;
			announceStorageMode(compactor.storageMode, lastRecoveryReason);

			let nextRetentionPassMs = 0;
			let retentionMaintenanceHeld = false;
			let segmentPruneState:
				| {
						generation: number;
						fingerprint: string;
						pruneNowMs: number;
						continuation?: IncidentRecorderSegmentPruneCursor;
				  }
				| undefined;
			resetSegmentPruneState = () => {
				segmentPruneState = undefined;
			};
			while (!shutdown.signal.aborted) {
				let rerunRetentionImmediately = false;
				try {
					await inspectAdmittedRuns();
					const nowMs = Date.now();
					if (
						normalInspectionOpen &&
						nowMs >= nextRetentionPassMs &&
						(retentionMaintenanceHeld || compactor.beginPinRetentionMaintenance())
					) {
						retentionMaintenanceHeld = true;
						let moreWork = false;
						try {
							const retention = runIncidentRetentionPass({
								agentDir,
								nowMs,
								writerLifecycleLease: lifecycle.normalLease,
								liveObservationValidationCheckpoints,
								...INCIDENT_RETENTION_SERVICE_BUDGET,
							});
							if (retention.state === "unavailable") liveObservationValidationCheckpoints.clear();
							moreWork = retention.moreWork;
							if (!compactor.diskPaused && retention.uncertainties.length > 0)
								writePrivateJsonAtomicSync(join(agentDir, "incident-recorder", "retention-uncertainty.json"), {
									version: 1,
									state: "fail_closed",
									observed: nowFields(),
									reasons: retention.uncertainties.slice(0, 32),
								});
							if (!compactor.diskPaused && retention.moreWork)
								writePrivateJsonAtomicSync(join(agentDir, "incident-recorder", "retention-deferred.json"), {
									version: 1,
									state: "bounded_incremental_work_remains",
									observed: nowFields(),
									scannedEntries: retention.scannedEntries,
									deletedEntries: retention.deletedEntries,
								});
							if (retention.deletedEntries > 0) {
								segmentPruneState = undefined;
								rerunRetentionImmediately = true;
								moreWork = true;
								await compactor.initializeStorageAccounting(shutdown.signal);
							} else if (
								!compactor.diskPaused &&
								!retention.pendingIncident &&
								retention.segmentPruneProtection.state === "complete"
							) {
								const protection = retention.segmentPruneProtection;
								if (
									!segmentPruneState ||
									segmentPruneState.generation !== protection.generation ||
									segmentPruneState.fingerprint !== protection.fingerprint
								)
									segmentPruneState = {
										generation: protection.generation,
										fingerprint: protection.fingerprint,
										pruneNowMs: nowMs,
									};
								const prune = compactor.pruneSegmentHistory(
									segmentPruneState.pruneNowMs,
									protection,
									segmentPruneState.continuation,
								);
								moreWork ||= prune.moreWork;
								if (prune.blockedByReadSnapshot) {
									// A frozen run-history reader owns the first eligible segment. Keep
									// the current anchor so a later pass revisits that same segment after
									// the lease is released; this is deferred work, not a malformed cursor.
									moreWork = true;
								} else {
									if (prune.moreWork && !prune.continuation) {
										segmentPruneState = undefined;
										throw new Error("Segment prune continuation was omitted while bounded work remains");
									}
									if (prune.moreWork) segmentPruneState.continuation = prune.continuation;
									else segmentPruneState = undefined;
								}
								if (prune.requiresFullReconciliation) {
									segmentPruneState = undefined;
									await compactor.initializeStorageAccounting(shutdown.signal);
								}
							} else segmentPruneState = undefined;
						} finally {
							if (!rerunRetentionImmediately) {
								compactor.endPinRetentionMaintenance();
								retentionMaintenanceHeld = false;
							}
							nextRetentionPassMs = rerunRetentionImmediately
								? 0
								: nowMs + incidentRetentionNextDelayMs(moreWork, serviceInspectionCadenceMs(nowMs));
						}
					}
					if (normalInspectionOpen && !compactor.diskPaused && !rerunRetentionImmediately)
						compactor.processPendingPins(nowMs);
				} catch (error) {
					if (error instanceof IncidentRecorderSegmentOwnershipUncertainError) throw error;
					// A malformed or unavailable evidence source must not stop later recorder passes.
					segmentPruneState = undefined;
					rerunRetentionImmediately = false;
				} finally {
					// A failed inspection or maintenance pass must relinquish any hold it owns.
					// Successful deletion-triggered reruns deliberately keep the hold across
					// the awaited accounting rescan and into the next loop iteration.
					if (!rerunRetentionImmediately && retentionMaintenanceHeld) {
						compactor.endPinRetentionMaintenance();
						retentionMaintenanceHeld = false;
					}
				}
				if (shutdown.signal.aborted) break;
				if (rerunRetentionImmediately) continue;
				await Promise.race([
					monitoredCompactorRun,
					stopRequested,
					new Promise<void>((resolveDelay) => setTimeout(resolveDelay, serviceInspectionCadenceMs())),
				]);
			}
		})();
	} catch (error) {
		hasRunError = true;
		runError = error;
	} finally {
		if (readyNotified && !stoppingNotified) notifyStopping("Stopping after recorder failure");
		shutdown.abort();
		resolveStopRequested();
		if (compactorRun) {
			try {
				await compactorRun;
			} catch (error) {
				retainCompactorError(error);
			}
		}
		if (activeServiceRecorder?.writer === serviceWriter) activeServiceRecorder = undefined;
		if (activeIncidentCompactor === compactor) activeIncidentCompactor = undefined;
		for (const registration of signalRegistrations)
			attemptIncidentRecorderServiceCleanup(
				shutdownCleanupFailures,
				`signalSource.off(${registration.signal})`,
				() => signalSource.off(registration.signal, registration.listener),
			);
		resetServiceRunDiscovery();
		serviceSamplingRuns.clear();
		compactor.endPinRetentionMaintenance();
		try {
			await lifecycle.close();
		} catch (error) {
			if (!hasWriterStopError) {
				hasWriterStopError = true;
				writerStopError = error;
			}
		}
	}
	if (latchedWriterFatal) throw latchedWriterFatal;
	if (hasCompactorError) throw firstCompactorError;
	if (hasWriterStopError) throw writerStopError;
	if (hasRunError) throw runError;
	if (shutdownCleanupFailures.length > 0)
		throw incidentRecorderServiceCleanupError("Incident recorder service cleanup failed", shutdownCleanupFailures);
}

export interface RenderServiceOptions {
	nodePath: string;
	entrypointPath: string;
	agentDir?: string;
	memoryMax?: string;
	memoryHigh?: string;
	memorySwapMax?: string;
	cpuQuota?: string;
	ioWeight?: number;
	restartSeconds?: number;
	tasksMax?: number;
	limitNOFILE?: number;
	startLimitIntervalSeconds?: number;
	startLimitBurst?: number;
	timeoutStartSeconds?: number;
	timeoutStopSeconds?: number;
}

export interface RenderJournaldNamespaceOptions {
	storageMaxUse?: string;
	systemKeepFree?: string;
	systemMaxFileSize?: string;
	lineMax?: string;
	maxFileSec?: string;
	maxRetentionSec?: string;
	rateLimitIntervalSec?: string;
	rateLimitBurst?: number;
	syncIntervalSec?: string;
}

export interface IncidentRecorderSystemdRequirements {
	journaldConfig: { path: "/etc/systemd/journald@grimoire.conf"; contents: string };
	socketDropIn: { path: "/etc/systemd/system/systemd-journald@grimoire.socket.d/prime-agent.conf"; contents: string };
	enableUnit: "systemd-journald@grimoire.socket";
	serviceUnit: string;
}

export const INCIDENT_RECORDER_BOOTSTRAP_ENTRYPOINT = "dist/bundle/incident-recorder-bootstrap.js";
export const INCIDENT_RECORDER_BOOTSTRAP_SYSTEMD_UNIT = "prime-agent-incident-recorder-bootstrap.service";
export const INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT = "prime-agent-incident-recorder-bootstrap.timer";

const INCIDENT_RECORDER_SYSTEMD_COMMAND_TIMEOUT_MS = 30_000;
const INCIDENT_RECORDER_SYSTEMD_COMMAND_MAX_BUFFER_BYTES = 256 * 1024;

export interface RenderIncidentRecorderBootstrapServiceOptions {
	nodePath: string;
	/** Canonical bootstrap entrypoint in the same installed package as the recorder service. */
	bootstrapEntrypointPath: string;
	agentDir?: string;
}

/** Derive the bootstrap entrypoint from the recorder service's installed package. */
export function deriveIncidentRecorderBootstrapEntrypointPath(entrypointPath: string): string {
	const serviceSuffix = `/${INCIDENT_CAS_V2_SERVICE_ENTRYPOINT}`;
	if (
		!entrypointPath.startsWith("/") ||
		resolve(entrypointPath) !== entrypointPath ||
		/[\u0000-\u001f\u007f$%]/.test(entrypointPath) ||
		!entrypointPath.endsWith(serviceSuffix)
	)
		throw new Error("Incident recorder bootstrap requires the canonical v2 service entrypoint");
	const packageRoot = entrypointPath.slice(0, -serviceSuffix.length);
	if (!packageRoot || packageRoot.endsWith("/"))
		throw new Error("Incident recorder bootstrap requires an installed package root");
	return join(packageRoot, INCIDENT_RECORDER_BOOTSTRAP_ENTRYPOINT);
}

function validateBootstrapRenderOptions(options: RenderIncidentRecorderBootstrapServiceOptions): {
	nodePath: string;
	bootstrapEntrypointPath: string;
	agentDir: string;
} {
	const bootstrapEntrypointPath = options.bootstrapEntrypointPath;
	const agentDir = options.agentDir ?? getAgentDir();
	parseIncidentRecorderServiceArgs(["--agent-dir", agentDir]);
	if (
		[options.nodePath, bootstrapEntrypointPath, agentDir].some(
			(path) => !path.startsWith("/") || resolve(path) !== path || /[\u0000-\u001f\u007f$%]/.test(path),
		) ||
		!bootstrapEntrypointPath.endsWith(`/${INCIDENT_RECORDER_BOOTSTRAP_ENTRYPOINT}`)
	)
		throw new Error("Incident recorder bootstrap requires canonical paths without systemd expansions");
	return { nodePath: options.nodePath, bootstrapEntrypointPath, agentDir };
}

export function renderIncidentRecorderBootstrapSystemdUnit(
	options: RenderIncidentRecorderBootstrapServiceOptions,
): string {
	const { nodePath, bootstrapEntrypointPath, agentDir } = validateBootstrapRenderOptions(options);
	const args = [nodePath, bootstrapEntrypointPath, "--agent-dir", agentDir];
	return `[Unit]\nDescription=GRIMOIRE incident recorder bootstrap and recovery\nStartLimitIntervalSec=0\n\n[Service]\nType=oneshot\nWorkingDirectory=/\nExecStart=${args.map(systemdQuote).join(" ")}\nTimeoutStartSec=30s\n`;
}

export function renderIncidentRecorderBootstrapSystemdTimer(): string {
	return `[Unit]\nDescription=Retry GRIMOIRE incident recorder bootstrap\n\n[Timer]\nOnActiveSec=60s\nOnUnitInactiveSec=60s\nAccuracySec=1s\nUnit=${INCIDENT_RECORDER_BOOTSTRAP_SYSTEMD_UNIT}\n\n[Install]\nWantedBy=timers.target\n`;
}

function systemdQuote(value: string): string {
	return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function systemdSizeBytes(value: string): number | undefined {
	const match = /^([1-9][0-9]*)([KMGT]?)$/.exec(value);
	if (!match) return undefined;
	const exponent = "KMGT".indexOf(match[2]) + 1;
	const bytes = Number(match[1]) * 1024 ** exponent;
	return Number.isSafeInteger(bytes) ? bytes : undefined;
}

export function renderIncidentRecorderJournaldNamespaceConfig(options: RenderJournaldNamespaceOptions = {}): string {
	const lineMax = options.lineMax ?? "48K";
	const storageMaxUse = options.storageMaxUse ?? "2G";
	const systemKeepFree = options.systemKeepFree ?? "8G";
	const systemMaxFileSize = options.systemMaxFileSize ?? "64M";
	const maxFileSec = options.maxFileSec ?? "1h";
	const maxRetentionSec = options.maxRetentionSec ?? "3d";
	const rateLimitIntervalSec = options.rateLimitIntervalSec ?? "30s";
	const rateLimitBurst = options.rateLimitBurst ?? 2_000;
	const syncIntervalSec = options.syncIntervalSec ?? "30s";
	const lineMaxBytes = systemdSizeBytes(lineMax);
	if (
		!lineMaxBytes ||
		lineMaxBytes < 48 * 1024 ||
		!systemdSizeBytes(storageMaxUse) ||
		!systemdSizeBytes(systemKeepFree) ||
		!systemdSizeBytes(systemMaxFileSize) ||
		!/^[1-9][0-9]*[smhdw]$/.test(maxFileSec) ||
		!/^[1-9][0-9]*[smhdw]$/.test(maxRetentionSec) ||
		!/^[1-9][0-9]*[smhdw]$/.test(rateLimitIntervalSec) ||
		!Number.isSafeInteger(rateLimitBurst) ||
		rateLimitBurst < 1 ||
		!/^[1-9][0-9]*[smhdw]$/.test(syncIntervalSec)
	) {
		throw new Error("Invalid journald namespace retention or size setting");
	}
	return `[Journal]\nStorage=persistent\nCompress=yes\nSeal=yes\nForwardToSyslog=no\nSyncIntervalSec=${syncIntervalSec}\nRateLimitIntervalSec=${rateLimitIntervalSec}\nRateLimitBurst=${rateLimitBurst}\nLineMax=${lineMax}\nSystemMaxUse=${storageMaxUse}\nSystemKeepFree=${systemKeepFree}\nSystemMaxFileSize=${systemMaxFileSize}\nMaxFileSec=${maxFileSec}\nMaxRetentionSec=${maxRetentionSec}\n`;
}

export function renderIncidentRecorderJournaldSocketDropIn(): string {
	return `[Unit]\nDescription=Automatic Prime Agent raw diagnostic journal namespace socket\n\n[Install]\nWantedBy=sockets.target\n`;
}

export function renderIncidentRecorderSystemdUnit(options: RenderServiceOptions): string {
	const agentDir = options.agentDir ?? getAgentDir();
	parseIncidentRecorderServiceArgs(["--agent-dir", agentDir]);
	const args = [options.nodePath, options.entrypointPath, "--agent-dir", agentDir];
	if (
		[options.nodePath, options.entrypointPath, agentDir].some(
			(path) => !path.startsWith("/") || resolve(path) !== path || /[\u0000-\u001f\u007f$%]/.test(path),
		) ||
		!options.entrypointPath.endsWith(`/${INCIDENT_CAS_V2_SERVICE_ENTRYPOINT}`)
	) {
		// systemd expands variables/specifiers even inside quotes. Refuse paths
		// whose effective argv would differ from the cutover's exact identity.
		throw new Error("Incident recorder requires canonical v2 service paths without systemd expansions");
	}
	const memoryMax = options.memoryMax ?? "256M";
	const memoryHigh = options.memoryHigh ?? "192M";
	const memorySwapMax = options.memorySwapMax ?? "0";
	const cpuQuota = options.cpuQuota ?? "25%";
	const ioWeight = options.ioWeight ?? 25;
	const restartSeconds = options.restartSeconds ?? 30;
	const tasksMax = options.tasksMax ?? 64;
	const limitNOFILE = options.limitNOFILE ?? 4096;
	const startLimitIntervalSeconds = options.startLimitIntervalSeconds ?? 600;
	const startLimitBurst = options.startLimitBurst ?? 3;
	const timeoutStartSeconds = options.timeoutStartSeconds ?? 30;
	const timeoutStopSeconds = options.timeoutStopSeconds ?? 15;
	if (
		!/^0$|^[1-9][0-9]*[KMGT]?$/.test(memoryMax) ||
		!/^0$|^[1-9][0-9]*[KMGT]?$/.test(memoryHigh) ||
		!/^0$|^[1-9][0-9]*[KMGT]?$/.test(memorySwapMax) ||
		!/^[1-9][0-9]*%$/.test(cpuQuota) ||
		!Number.isSafeInteger(ioWeight) ||
		ioWeight < 1 ||
		ioWeight > 10_000 ||
		!Number.isFinite(restartSeconds) ||
		restartSeconds < 1 ||
		!Number.isSafeInteger(tasksMax) ||
		tasksMax < 1 ||
		!Number.isSafeInteger(limitNOFILE) ||
		limitNOFILE < 64 ||
		!Number.isSafeInteger(startLimitIntervalSeconds) ||
		startLimitIntervalSeconds < 1 ||
		!Number.isSafeInteger(startLimitBurst) ||
		startLimitBurst < 1 ||
		!Number.isSafeInteger(timeoutStartSeconds) ||
		timeoutStartSeconds < 1 ||
		!Number.isSafeInteger(timeoutStopSeconds) ||
		timeoutStopSeconds < 1
	)
		throw new Error("Invalid incident recorder service resource controls");
	return `[Unit]\nDescription=GRIMOIRE incident compactor, sampler, and finalizer\nStartLimitIntervalSec=${startLimitIntervalSeconds}s\nStartLimitBurst=${startLimitBurst}\n\n[Service]\nType=notify\nNotifyAccess=all\nEnvironment=${INCIDENT_RECORDER_SERVICE_ENV}=1\nExecStartPre=/usr/bin/test -x /usr/bin/systemd-notify\nExecStartPre=/usr/bin/test -S /run/systemd/journal.grimoire/stdout\nExecStart=${args.map(systemdQuote).join(" ")}\nRestart=on-failure\nRestartSec=${restartSeconds}s\nTimeoutStartSec=${timeoutStartSeconds}s\nTimeoutStopSec=${timeoutStopSeconds}s\nKillMode=mixed\nKillSignal=SIGTERM\nSendSIGKILL=yes\nFinalKillSignal=SIGKILL\nMemoryHigh=${memoryHigh}\nMemoryMax=${memoryMax}\nMemorySwapMax=${memorySwapMax}\nCPUQuota=${cpuQuota}\nIOWeight=${ioWeight}\nNice=10\nTasksMax=${tasksMax}\nLimitNOFILE=${limitNOFILE}\nOOMPolicy=stop\nRuntimeDirectory=prime-agent\nRuntimeDirectoryMode=0700\nUMask=0077\n\n[Install]\nWantedBy=default.target\n`;
}

export function renderIncidentRecorderSystemdRequirements(
	service: RenderServiceOptions,
	namespace: RenderJournaldNamespaceOptions = {},
): IncidentRecorderSystemdRequirements {
	return {
		journaldConfig: {
			path: "/etc/systemd/journald@grimoire.conf",
			contents: renderIncidentRecorderJournaldNamespaceConfig(namespace),
		},
		socketDropIn: {
			path: "/etc/systemd/system/systemd-journald@grimoire.socket.d/prime-agent.conf",
			contents: renderIncidentRecorderJournaldSocketDropIn(),
		},
		enableUnit: "systemd-journald@grimoire.socket",
		serviceUnit: renderIncidentRecorderSystemdUnit(service),
	};
}

export interface InstallServiceOptions extends RenderServiceOptions {
	platform?: NodeJS.Platform;
	homeDir?: string;
	configHomeDir?: string;
	systemctlPath?: string;
	spawnSyncImpl?: (
		command: string,
		args: readonly string[],
	) => Pick<SpawnSyncReturns<string>, "status" | "error" | "stderr">;
	privilegedInstallFile?: (
		path: string,
		contents: string,
	) => { status: number | null; error?: Error; stderr?: string };
	privilegedReadFile?: (path: string) => string | undefined;
	privilegedCommandPath?: string;
}

export interface InstallServiceResult {
	status: "installed" | "unchanged" | "unsupported" | "unavailable" | "failed";
	unitPath?: string;
	message?: string;
}

function installerSpawnSync(
	options: InstallServiceOptions,
): (command: string, args: readonly string[]) => Pick<SpawnSyncReturns<string>, "status" | "error" | "stderr"> {
	if (options.spawnSyncImpl) return options.spawnSyncImpl;
	return (command, args) =>
		spawnSync(command, args, {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
			timeout: INCIDENT_RECORDER_SYSTEMD_COMMAND_TIMEOUT_MS,
			maxBuffer: INCIDENT_RECORDER_SYSTEMD_COMMAND_MAX_BUFFER_BYTES,
			killSignal: "SIGKILL",
		});
}

interface IncidentRecorderUserUnit {
	path: string;
	contents: string;
}

function preflightIncidentRecorderUserUnits(
	units: readonly IncidentRecorderUserUnit[],
): { state: "safe"; current: Array<BoundedRead | undefined> } | { state: "unsafe"; unitPath: string; message: string } {
	const current: Array<BoundedRead | undefined> = [];
	for (const unit of units) {
		const existing = readInstallerUnitBoundedPrefix(unit.path, INCIDENT_RECORDER_LIMITS.evidenceFileBytes);
		if (existing.state === "unsafe") return { state: "unsafe", unitPath: unit.path, message: existing.message };
		current.push(existing.state === "read" ? existing.bounded : undefined);
	}
	return { state: "safe", current };
}

function writeIncidentRecorderUserUnitAtomic(unitPath: string, contents: string, unitDir: string): void {
	mkdirSync(unitDir, { recursive: true, mode: 0o700 });
	const temporary = `${unitPath}.tmp-${process.pid}-${randomUUID()}`;
	try {
		writeFileSync(temporary, contents, { mode: 0o600 });
		renameSync(temporary, unitPath);
		chmodSync(unitPath, 0o600);
	} finally {
		try {
			rmSync(temporary, { force: true });
		} catch {}
	}
}

export function installIncidentRecorderJournaldNamespace(options: InstallServiceOptions): InstallServiceResult {
	if ((options.platform ?? process.platform) !== "linux")
		return { status: "unsupported", message: "journald namespace is only available on Linux" };
	const requirements = renderIncidentRecorderSystemdRequirements(options);
	const run = installerSpawnSync(options);
	const installFile: NonNullable<InstallServiceOptions["privilegedInstallFile"]> =
		options.privilegedInstallFile ??
		((path: string, contents: string) => {
			const temporary = join(options.agentDir ?? getAgentDir(), `namespace-install-${randomUUID()}`);
			try {
				writeFileSync(temporary, contents, { mode: 0o600 });
				if (typeof process.getuid === "function" && process.getuid() === 0) {
					mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
					writeFileSync(path, contents, { mode: 0o644 });
					return { status: 0 };
				}
				const result = run(options.privilegedCommandPath ?? "sudo", [
					"-n",
					"install",
					"-D",
					"-m",
					"0644",
					temporary,
					path,
				]);
				return { status: result.status, error: result.error, stderr: result.stderr };
			} finally {
				try {
					rmSync(temporary, { force: true });
				} catch {}
			}
		});
	const readPrivileged =
		options.privilegedReadFile ??
		((path: string) => {
			try {
				return readFileSync(path, "utf8");
			} catch {
				return undefined;
			}
		});
	let changed = false;
	for (const file of [requirements.journaldConfig, requirements.socketDropIn]) {
		const current = readPrivileged(file.path);
		if (current === file.contents) continue;
		const installed = installFile(file.path, file.contents);
		if (installed.error || installed.status !== 0)
			return {
				status: "unavailable",
				message: installed.error?.message ?? installed.stderr ?? `privilege unavailable for ${file.path}`,
			};
		const verified = readPrivileged(file.path);
		if (verified !== file.contents)
			return { status: "failed", message: `journald namespace file verification failed for ${file.path}` };
		changed = true;
	}
	const privileged = (args: readonly string[]) =>
		typeof process.getuid === "function" && process.getuid() === 0
			? run(options.systemctlPath ?? "systemctl", args)
			: run(options.privilegedCommandPath ?? "sudo", ["-n", options.systemctlPath ?? "systemctl", ...args]);
	if (changed) {
		const reload = privileged(["daemon-reload"]);
		if (reload.error || reload.status !== 0)
			return { status: "failed", message: reload.error?.message ?? reload.stderr ?? "system daemon-reload failed" };
	}
	const enabled = privileged(["enable", "--now", requirements.enableUnit]);
	if (enabled.error || enabled.status !== 0)
		return {
			status: "unavailable",
			message: enabled.error?.message ?? enabled.stderr ?? "journald namespace socket enable failed",
		};
	const serviceActivation = privileged([changed ? "restart" : "start", "systemd-journald@grimoire.service"]);
	if (serviceActivation.error || serviceActivation.status !== 0) {
		return {
			status: "failed",
			message:
				serviceActivation.error?.message ??
				serviceActivation.stderr ??
				`journald namespace service ${changed ? "restart" : "start"} failed`,
		};
	}
	const serviceReady = privileged(["is-active", "--quiet", "systemd-journald@grimoire.service"]);
	if (serviceReady.error || serviceReady.status !== 0)
		return {
			status: "failed",
			message:
				serviceReady.error?.message ??
				serviceReady.stderr ??
				"journald namespace service readiness verification failed",
		};
	const socketReady = privileged(["is-active", "--quiet", requirements.enableUnit]);
	if (socketReady.error || socketReady.status !== 0)
		return {
			status: "failed",
			message:
				socketReady.error?.message ??
				socketReady.stderr ??
				"journald namespace socket readiness verification failed",
		};
	if (!options.spawnSyncImpl) {
		try {
			if (!statSync("/run/systemd/journal.grimoire/stdout").isSocket())
				throw new Error("namespace stdout path is not a socket");
		} catch (error) {
			return {
				status: "failed",
				message: error instanceof Error ? error.message : "journald namespace stdout socket verification failed",
			};
		}
	}
	return {
		status: changed ? "installed" : "unchanged",
		message: `journald namespace ${changed ? "changed and restarted" : "unchanged"}; service and socket ready`,
	};
}

export function installIncidentRecorderSystemdService(options: InstallServiceOptions): InstallServiceResult {
	if (!isAbsolute(options.nodePath) || !isAbsolute(options.entrypointPath))
		return { status: "failed", message: "incident recorder service paths must be absolute" };
	if ((options.platform ?? process.platform) !== "linux")
		return { status: "unsupported", message: "systemd user service is only available on Linux" };
	let desired: string;
	let bootstrapEntrypointPath: string;
	let bootstrapDesired: string;
	const bootstrapTimerDesired = renderIncidentRecorderBootstrapSystemdTimer();
	try {
		desired = renderIncidentRecorderSystemdUnit(options);
		bootstrapEntrypointPath = deriveIncidentRecorderBootstrapEntrypointPath(options.entrypointPath);
		const bootstrapPaths = resolveIncidentRecorderBootstrapPaths({
			nodePath: options.nodePath,
			bootstrapEntrypointPath,
		});
		if (bootstrapPaths.serviceEntrypointPath !== options.entrypointPath)
			throw new Error("Incident recorder bootstrap is not bound to the configured service entrypoint");
		bootstrapDesired = renderIncidentRecorderBootstrapSystemdUnit({
			nodePath: options.nodePath,
			bootstrapEntrypointPath,
			agentDir: options.agentDir,
		});
	} catch (error) {
		return { status: "failed", message: error instanceof Error ? error.message : "invalid v2 launcher" };
	}
	const configHome =
		options.configHomeDir ??
		(options.homeDir ? join(options.homeDir, ".config") : process.env.XDG_CONFIG_HOME || join(homedir(), ".config"));
	const unitDir = join(configHome, "systemd", "user");
	const units: IncidentRecorderUserUnit[] = [
		{
			path: join(unitDir, INCIDENT_CAS_V2_SYSTEMD_UNIT),
			contents: desired,
		},
		{
			path: join(unitDir, INCIDENT_RECORDER_BOOTSTRAP_SYSTEMD_UNIT),
			contents: bootstrapDesired,
		},
		{
			path: join(unitDir, INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT),
			contents: bootstrapTimerDesired,
		},
	];
	const preflight = preflightIncidentRecorderUserUnits(units);
	if (preflight.state === "unsafe")
		return { status: "failed", unitPath: preflight.unitPath, message: preflight.message };
	const namespace = installIncidentRecorderJournaldNamespace(options);
	if (namespace.status === "failed" || namespace.status === "unavailable") return namespace;
	const systemctl = options.systemctlPath ?? "systemctl";
	const run = installerSpawnSync(options);
	const probe = run(systemctl, ["--user", "show-environment"]);
	if (probe.error || probe.status !== 0)
		return { status: "unavailable", message: "systemd user manager is unavailable; no files were changed" };
	const unitPath = units[0].path;
	const [current, currentBootstrap, currentTimer] = preflight.current;
	const changed = current === undefined || current.truncated || current.value.toString("utf8") !== desired;
	const bootstrapChanged =
		currentBootstrap === undefined ||
		currentBootstrap.truncated ||
		currentBootstrap.value.toString("utf8") !== bootstrapDesired;
	const timerChanged =
		currentTimer === undefined ||
		currentTimer.truncated ||
		currentTimer.value.toString("utf8") !== bootstrapTimerDesired;
	let stopped = false;
	const stopRecorder = (): InstallServiceResult | undefined => {
		const stop = run(systemctl, ["--user", "stop", basename(unitPath)]);
		if (stop.error || stop.status !== 0)
			return { status: "failed", unitPath, message: stop.error?.message ?? stop.stderr ?? "recorder stop failed" };
		stopped = true;
		return undefined;
	};
	if (changed && current) {
		const stopFailure = stopRecorder();
		if (stopFailure) return stopFailure;
	}
	if (changed) writeIncidentRecorderUserUnitAtomic(unitPath, desired, unitDir);
	if (bootstrapChanged)
		writeIncidentRecorderUserUnitAtomic(
			join(unitDir, INCIDENT_RECORDER_BOOTSTRAP_SYSTEMD_UNIT),
			bootstrapDesired,
			unitDir,
		);
	if (timerChanged)
		writeIncidentRecorderUserUnitAtomic(
			join(unitDir, INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT),
			bootstrapTimerDesired,
			unitDir,
		);
	{
		// Retry a previously failed reload even when its unit bytes are unchanged.
		const reload = run(systemctl, ["--user", "daemon-reload"]);
		if (reload.error || reload.status !== 0)
			return {
				status: "failed",
				unitPath,
				message: reload.error?.message ?? reload.stderr ?? "systemctl user daemon-reload failed",
			};
	}
	const bootstrapTimer = run(systemctl, ["--user", "enable", "--now", INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT]);
	if (bootstrapTimer.error || bootstrapTimer.status !== 0)
		return {
			status: "failed",
			unitPath,
			message: bootstrapTimer.error?.message ?? bootstrapTimer.stderr ?? "bootstrap timer enable failed",
		};
	const agentDir = options.agentDir ?? getAgentDir();
	const target: IncidentCasV2CutoverTarget = {
		agentDir,
		packageRoot: dirname(dirname(dirname(options.entrypointPath))),
		launcher: {
			unitPath,
			unitContents: desired,
			argv: [options.nodePath, options.entrypointPath, "--agent-dir", agentDir],
		},
	};
	try {
		// Bootstrap creates only the fixed namespaces; admission checks their real
		// identities and ownership before any recorder writer is allowed to start.
		mkdirSync(join(agentDir, "incident-recorder"), { recursive: true, mode: 0o700 });
		mkdirSync(join(agentDir, "incidents"), { recursive: true, mode: 0o700 });
		const begun = beginIncidentCasV2Cutover(target);
		if (begun.state === "unavailable")
			return { status: "unavailable", unitPath, message: `recorder cutover unavailable: ${begun.reason}` };
		if (begun.state === "draining") {
			try {
				if (!stopped) {
					const stopFailure = stopRecorder();
					if (stopFailure) return stopFailure;
				}
				const proof = proveIncidentCasV1Quiescence(begun.cutover);
				if (proof.state === "unavailable")
					return {
						status: "unavailable",
						unitPath,
						message: `recorder cutover waiting: ${proof.reason}; live Agents were not interrupted`,
					};
				const published = publishIncidentCasV2(begun.cutover, proof.witness);
				if (published.state === "unavailable")
					return {
						status: "unavailable",
						unitPath,
						message: `recorder cutover publication unavailable: ${published.reason}`,
					};
			} finally {
				begun.cutover.close();
			}
		}
		const opened = openIncidentCasV2Activation(target);
		if (opened.state !== "active")
			return { status: "unavailable", unitPath, message: `recorder activation unavailable: ${opened.reason}` };
		opened.activation.close();
	} catch (error) {
		return {
			status: "failed",
			unitPath,
			message: error instanceof Error ? error.message : "recorder cutover failed",
		};
	}
	const enable = run(systemctl, ["--user", "enable", basename(unitPath)]);
	if (enable.error || enable.status !== 0)
		return {
			status: "failed",
			unitPath,
			message: enable.error?.message ?? enable.stderr ?? "systemctl user enable failed",
		};
	const activate = run(systemctl, ["--user", "start", basename(unitPath)]);
	if (activate.error || activate.status !== 0)
		return {
			status: "failed",
			unitPath,
			message: activate.error?.message ?? activate.stderr ?? "systemctl user activation failed",
		};
	const verify = run(systemctl, ["--user", "is-active", "--quiet", basename(unitPath)]);
	if (verify.error || verify.status !== 0)
		return {
			status: "failed",
			unitPath,
			message: verify.error?.message ?? verify.stderr ?? "incident recorder service readiness verification failed",
		};
	return {
		status:
			changed || bootstrapChanged || timerChanged || namespace.status === "installed" ? "installed" : "unchanged",
		unitPath,
		message: `namespace=${namespace.status}; user-service=${changed ? "installed" : "unchanged"}; bootstrap-timer=armed`,
	};
}
