import { type ChildProcess, spawn } from "node:child_process";
import { createHash, type Hash } from "node:crypto";
import {
	type BigIntStats,
	chmodSync,
	closeSync,
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
	renameSync,
	rmSync,
	statfsSync,
	writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import {
	acquireIncidentCasTransaction,
	type IncidentCasRelativePath,
	type IncidentCasRootMutation,
} from "./incident-recorder-cas-transaction.js";
import {
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
	type IncidentRecorderFrameHeader,
	validateIncidentRecorderFrameFlags,
} from "./incident-recorder-protocol.js";
import { INCIDENT_DIAGNOSTIC_RETENTION_MS } from "./incident-recorder-retention.js";
import {
	estimateIncidentRecorderSegmentStoreOpenWithinRoot,
	type IncidentRecorderSegmentAppendInput,
	type IncidentRecorderSegmentAppendStorageEstimate,
	type IncidentRecorderSegmentDurableWrite,
	type IncidentRecorderSegmentLocator,
	type IncidentRecorderSegmentOpenResult,
	type IncidentRecorderSegmentOpenStorageEntry,
	type IncidentRecorderSegmentParentDirectoryEffect,
	type IncidentRecorderSegmentPruneCursor,
	type IncidentRecorderSegmentPruneProtectionComplete,
	type IncidentRecorderSegmentPruneResult,
	type IncidentRecorderSegmentQueryCursor,
	type IncidentRecorderSegmentReadLease,
	type IncidentRecorderSegmentRecord,
	type IncidentRecorderSegmentRecoveryGap,
	type IncidentRecorderSegmentRecoveryGapQueryCursor,
	type IncidentRecorderSegmentRootReceipt,
	IncidentRecorderSegmentStore,
	pruneIncidentRecorderSealedHistoryForRecovery,
} from "./incident-recorder-segment-store.js";
import {
	INCIDENT_RECORDER_JOURNAL_IDENTIFIER,
	INCIDENT_RECORDER_JOURNAL_NAMESPACE,
	type IncidentJournalLine,
} from "./incident-recorder-writer.js";
import {
	type IncidentRecorderWriterLifecycleLease,
	type IncidentRecorderWriterLifecycleMutationResult,
	inspectIncidentRecorderWriterLifecycleLeaseMode,
} from "./incident-recorder-writer-lifecycle.js";

const EXPORT_BUFFER_MAX_BYTES = 256 * 1024;
const MESSAGE_MAX_BYTES = 64 * 1024;
const PIN_BEFORE_MS = 30 * 60 * 1_000;
const PIN_AFTER_MS = 15 * 60 * 1_000;
const SEQUENCE_TRACKER_MAX_KEYS = 4096;
const PENDING_ENTRY_MAX_COUNT = 8192;
const PENDING_ENTRY_MAX_BYTES = 8 * 1024 * 1024;
const ASSEMBLY_DEADLINE_MS = 5_000;
const ASSEMBLY_MAX_COUNT = 256;
const ASSEMBLY_MAX_BYTES = 8 * 1024 * 1024;
const PIN_CURSOR_MAX_COUNT = 16_384;
const PIN_CURSOR_MAX_BYTES = 1024 * 1024;
const PIN_SCAN_DEADLINE_MS = 30_000;
const PIN_REFERENCE_BATCH_COUNT = 64;
const PIN_LEGACY_REFERENCE_MAX_BYTES = 64 * 1024;
const PENDING_PIN_DIRECTORY_DISCOVERY_ENTRIES = 256;
const PENDING_PIN_DIRECTORY_BATCH_COUNT = 256;
const PENDING_PIN_DIRECTORY_NAME_MAX_BYTES = 4096;
const SYSDIG_RING_DEFAULT_BASE_PATH = "/var/log/grimoire/sysdig/ring.scap";
const SYSDIG_RING_EXPECTED_SEGMENTS = 12;
const SYSDIG_RING_ROTATION_BYTES = 320 * 1024 * 1024;
const SYSDIG_PIN_MAX_DISCOVERY_ENTRIES = 256;
const SYSDIG_PIN_MAX_SEGMENTS = 32;
const SYSDIG_PIN_MAX_SEGMENT_BYTES = 384 * 1024 * 1024;
const SYSDIG_PIN_MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024;
const SYSDIG_PIN_COPY_BUFFER_BYTES = 1024 * 1024;
const SYSDIG_PIN_WORK_BYTES_PER_PASS = 4 * 1024 * 1024;
const SYSDIG_PIN_REQUEST_MAX_BYTES = 64 * 1024;
const SYSDIG_PIN_RETENTION_MS = INCIDENT_DIAGNOSTIC_RETENTION_MS;
const STORAGE_ACCOUNTING_MAX_INODES = 262_144;
const STORAGE_ACCOUNTING_MAX_ENTRIES = 1_000_000;
const STORAGE_ACCOUNTING_SCAN_TIMEOUT_MS = 20_000;
const STORAGE_ACCOUNTING_LINE_MAX_BYTES = 256;
const STORAGE_ACCOUNTING_STDERR_MAX_BYTES = 4 * 1024;
const STORAGE_ACCOUNTING_REFRESH_MS = 60_000;
const STORAGE_BYTE_CEILING = 2 * 1024 ** 3;
const STORAGE_HIGH_WATER_BYTES = 1536 * 1024 ** 2;
const STORAGE_LOW_WATER_BYTES = Math.floor(1.2 * 1024 ** 3);
const STORAGE_HIGH_WATER_INODES = 196_608;
const STORAGE_LOW_WATER_INODES = 131_072;
const STORAGE_HIGH_WATER_ENTRIES = 196_608;
const STORAGE_LOW_WATER_ENTRIES = 131_072;
const STORAGE_FREE_RESERVE_BYTES = 8 * 1024 ** 3;
const JOURNAL_CATCHUP_MAX_ENTRIES = 256;
const JOURNAL_CATCHUP_MAX_BYTES = 64 * 1024 * 1024;
const JOURNAL_CATCHUP_SLICE_MS = 5_000;
const JOURNAL_READER_STABILITY_MS = 25;
const CHILD_TERMINATION_GRACE_MS = 250;
const SEGMENT_SOURCE_JOURNAL_REFERENCE = "journal-reference";
const SEGMENT_SOURCE_OCCURRENCE = "occurrence";
const SEGMENT_SOURCE_GAP = "gap";
const SEGMENT_SOURCE_INCOMPLETE = "incomplete";
const SEGMENT_QUERY_PAGE_RECORDS = 64;
const SEGMENT_QUERY_PAGE_BYTES = 8 * 1024 * 1024;
const SEGMENT_PRUNE_MAX_SEGMENTS = 16;
const SEGMENT_PRUNE_MAX_BYTES = 128 * 1024 * 1024;
const RUN_HISTORY_RESULT_MAX_BYTES = 8 * 1024 * 1024;
const RUN_HISTORY_CAS_READ_BYTES = 64 * 1024;
const RUN_HISTORY_CAS_READS_PER_CALL = 4;
const RUN_HISTORY_SEGMENT_PAGE_SCANNED_SEGMENTS = 16;
const RUN_HISTORY_SEGMENT_PAGE_SCANNED_RECORDS = 4096;
const RUN_HISTORY_SEGMENT_PAGE_SCANNED_INDEX_BYTES = 32 * 1024 * 1024;
const RUN_HISTORY_SEGMENT_PAGE_SCANNED_GAPS = 64;
const RUN_HISTORY_SEGMENT_MAX_SCANNED_SEGMENTS = 4096;
const RUN_HISTORY_SEGMENT_MAX_SCANNED_RECORDS = 262_144;
const RUN_HISTORY_SEGMENT_MAX_SCANNED_INDEX_BYTES = 256 * 1024 * 1024;
const RUN_HISTORY_PROCFS_FDINFO_MAX_BYTES = 16 * 1024;
const LINUX_PROC_SUPER_MAGIC = 0x9fa0;

type JournalFields = Readonly<Record<string, Buffer>>;

interface JournalRecordReference {
	id: string;
	path: string;
	cursor: string;
	machineId: string;
	bootId: string;
	invocationId: string | null;
	realtimeUs: string;
	monotonicUs: string;
	journalPid: string | null;
	uid: string;
	identifier: string;
	transport: string;
	wrapperSequence: string;
	producerSequence: string;
	chunkIndex: number;
	chunkCount: number;
	bytes: number;
	memoryBytes: number;
	streamId: string;
	resolved: boolean;
	sequenceUpdates?: { wrapperKey: string; wrapper: string; producerKey: string; producer: string };
}

interface Assembly {
	identity: string;
	line: IncidentJournalLine;
	chunks: Buffer[];
	references: JournalRecordReference[];
	bytes: number;
	memoryBytes: number;
	deadlineMs: number;
	timer: ReturnType<typeof setTimeout>;
}

interface PinTraversal {
	incidentDir: string;
	request: {
		runId: string;
		anchorWallTimeMs: number;
		fromWallTimeMs: number;
		throughWallTimeMs: number;
	};
	scannedCursors: Set<string>;
	directory?: ReturnType<typeof opendirSync>;
	segmentCursor?: IncidentRecorderSegmentQueryCursor;
	legacyDeadlineMs?: number;
	legacyEntriesScanned: number;
	legacyBytesRead: number;
	seenOccurrenceIdentities: Set<string>;
	matches: PinOccurrenceMatch[];
	memoryBytes: number;
	phase: "segment-reading" | "legacy-reading" | "linking";
	linkIndex: number;
	linked: Map<string, { path: string; sealedArtifact: SealedArtifact }>;
	pinCasDir?: string;
}

interface TrackedCompactorChild {
	child: ChildProcess;
	completion: Promise<void>;
	terminate: () => void;
}

interface ActivePinScan extends TrackedCompactorChild {
	incidentDir: string;
	generation: number;
	cancelled: boolean;
}

interface PendingPinDirectoryTraversal {
	incidentRoot: string;
	boundary?: string;
	phase: "full" | "after-cursor" | "through-cursor";
	directory?: ReturnType<typeof opendirSync>;
	pendingNames: string[];
	pendingNameBytes: number;
	sawEntry: boolean;
	sweepComplete: boolean;
}

export interface SegmentOccurrenceReference {
	kind: "segment";
	locator: IncidentRecorderSegmentLocator;
}

export type JournalOccurrenceReference = string | SegmentOccurrenceReference;

export interface IncidentRecorderRunHistoryEvent {
	identityKey: string;
	identity: {
		runId: string;
		runToken: string;
		producerId: string;
		occurrenceId: string;
	};
	semanticFingerprint: string;
	occurrenceReference: JournalOccurrenceReference;
	source: string;
	type: string;
	encoding: string;
	payloadKind: "exact-bytes" | "derived-scalar" | "loss" | "control";
	terminal: boolean;
	metadata: IncidentJournalLine["metadata"];
	eventWallTimeMs: string;
	eventMonotonicNs: string;
	wrapperOrder: string[];
	producerOrder: string[];
	cursors: string[];
	transportIdentity: Readonly<Record<string, unknown>>;
	cas: { digest: string; bytes: number; path: string };
}

export interface IncidentRecorderRunHistoryEvidence {
	kind: "gap" | "incomplete" | "corrupt" | "truncated";
	reason: string;
	reference?: JournalOccurrenceReference | IncidentRecorderSegmentLocator | IncidentRecorderSegmentRecoveryGap;
}

export interface IncidentRecorderRunHistoryProjection {
	version: 1;
	runId: string;
	fromWallTimeMs: number;
	throughWallTimeMs: number;
	events: IncidentRecorderRunHistoryEvent[];
	terminalEvents: Array<{
		identityKey: string;
		type: string;
		source: string;
		eventWallTimeMs: string;
		basis: "terminal_flag";
	}>;
	finalizationCandidates: Array<{
		role: "supervisor_exit" | "capture_channel_terminal";
		identityKey: string;
		basis: "type_and_source_candidate" | "type_source_and_terminal_flag_candidate";
		qualification: "candidate_requires_expectation_match";
	}>;
	ordering: {
		semantics: "partial_order";
		causalRelations: Array<{
			beforeIdentityKey: string;
			afterIdentityKey: string;
			basis: "producer_sequence" | "wrapper_sequence";
			streamKeyHash: string;
		}>;
		presentationTieBreak: "wall_time_then_identity_key";
		unrelatedPresentationOrderIsCausal: false;
		scope: "observed_events_only" | "complete_snapshot";
	};
	evidence: IncidentRecorderRunHistoryEvidence[];
}

export interface IncidentRecorderRunHistoryCursor {
	version: 1;
	token: string;
	requestFingerprint: string;
}

export interface IncidentRecorderRunHistorySnapshot {
	version: 1;
	fingerprint: string;
	segmentRecordCount: number;
	segmentRecoveryGapCount: number;
	segmentScannedSegments: number;
	segmentScannedRecords: number;
	segmentScannedIndexBytes: number;
	legacyOccurrenceCount: number;
	validatedCasDigestCount: number;
}

export type IncidentRecorderRunHistoryResult =
	| {
			state: "pending";
			cursor: IncidentRecorderRunHistoryCursor;
			projection: IncidentRecorderRunHistoryProjection;
	  }
	| {
			state: "complete";
			projection: IncidentRecorderRunHistoryProjection;
			snapshot: IncidentRecorderRunHistorySnapshot;
	  }
	| {
			state: "incomplete";
			reason: string;
			projection: IncidentRecorderRunHistoryProjection;
	  };

export interface IncidentRecorderRunHistoryPendingProgress {
	readonly version: 1;
	readonly state: "projection_deferred";
	readonly phase:
		| "segment-occurrences"
		| "segment-run-gaps"
		| "segment-run-incomplete"
		| "segment-global-gaps"
		| "segment-recovery-gaps"
		| "legacy"
		| "cas-validation"
		| "publication-retained";
	readonly observedEventCount: number;
	readonly observedEvidenceCount: number;
}

export interface IncidentRecorderRunHistoryProgressPendingResult {
	state: "pending";
	cursor: IncidentRecorderRunHistoryCursor;
	progress: IncidentRecorderRunHistoryPendingProgress;
}

export type IncidentRecorderRunHistoryProgressResult =
	| Exclude<IncidentRecorderRunHistoryResult, { state: "pending" }>
	| Extract<IncidentRecorderRunHistoryResult, { state: "pending" }>
	| IncidentRecorderRunHistoryProgressPendingResult;

export type IncidentRecorderRunHistoryCursorOnlyResult =
	| Exclude<IncidentRecorderRunHistoryResult, { state: "pending" }>
	| IncidentRecorderRunHistoryProgressPendingResult;

export interface IncidentRecorderRunHistoryPublicationCapability {
	readonly version: 1;
	readonly kind: "run_history_publication";
	readonly id: string;
	readonly snapshotFingerprint: string;
}

export type IncidentRecorderRetainedRunHistoryResult =
	| Exclude<IncidentRecorderRunHistoryResult, { state: "complete" }>
	| (Extract<IncidentRecorderRunHistoryResult, { state: "complete" }> & {
			publicationCapability: IncidentRecorderRunHistoryPublicationCapability;
	  })
	| IncidentRecorderRunHistoryProgressPendingResult;

export type IncidentRecorderRetainedRunHistoryProgressResult =
	| Exclude<IncidentRecorderRetainedRunHistoryResult, { state: "pending" }>
	| Extract<IncidentRecorderRetainedRunHistoryResult, { state: "pending" }>
	| IncidentRecorderRunHistoryProgressPendingResult;

export type IncidentRecorderRetainedRunHistoryCursorOnlyResult =
	| Exclude<IncidentRecorderRetainedRunHistoryResult, { state: "pending" }>
	| IncidentRecorderRunHistoryProgressPendingResult;

export interface IncidentRecorderRunHistoryProjectionInput {
	runId: string;
	fromWallTimeMs: number;
	throughWallTimeMs: number;
	cursor?: IncidentRecorderRunHistoryCursor;
	deadlineMs?: number;
	retainForPublication?: boolean;
	pendingResponse?: "full" | "cursor-only";
}

export interface IncidentRecorderLiveRunEventsCursor {
	readonly version: 1;
	readonly runId: string;
	readonly filterSha256: string;
	readonly segmentSequence: number;
	readonly ordinal: number;
}

export interface IncidentRecorderLiveRunEventsPage {
	readonly version: 1;
	readonly runId: string;
	readonly state: "complete" | "pending" | "incomplete";
	readonly events: IncidentRecorderRunHistoryEvent[];
	readonly cursor: IncidentRecorderLiveRunEventsCursor;
	readonly reason?: string;
	readonly scannedSegments: number;
	readonly scannedRecords: number;
	readonly scannedIndexBytes: number;
}

export interface IncidentRecorderLiveRunGap {
	readonly occurrenceReference: SegmentOccurrenceReference;
	readonly evidence: Record<string, unknown>;
}

export interface IncidentRecorderLiveRunGapsPage {
	readonly version: 1;
	readonly runId: string;
	readonly state: "complete" | "pending" | "incomplete";
	readonly gaps: IncidentRecorderLiveRunGap[];
	readonly cursor: IncidentRecorderLiveRunEventsCursor;
	readonly reason?: string;
	readonly scannedSegments: number;
	readonly scannedRecords: number;
	readonly scannedIndexBytes: number;
}

interface StableFilesystemIdentity {
	dev: bigint;
	ino: bigint;
	mode: bigint;
	nlink: bigint;
	size: bigint;
	mtimeNs: bigint;
	ctimeNs: bigint;
}

interface RunHistoryCasClaim {
	digest: string;
	bytes: number;
	path: string;
}

interface RunHistoryCasDirectoryFence {
	role: "recorder_root" | "cas_directory" | "algorithm_directory" | "shard_directory";
	path: string;
	resolvedPath: string;
	name?: string;
	descriptor: number;
	identity: StableFilesystemIdentity;
	parentDescriptor?: number;
}

interface RunHistoryProcfsAuthority {
	rootPath: "/proc";
	descriptorDirectoryPath: string;
	descriptorInfoDirectoryPath: string;
	rootDescriptor: number;
	descriptorDirectoryDescriptor: number;
	descriptorInfoDirectoryDescriptor: number;
	rootIdentity: StableFilesystemIdentity;
	descriptorDirectoryIdentity: StableFilesystemIdentity;
	descriptorInfoDirectoryIdentity: StableFilesystemIdentity;
	mountId: bigint;
}

interface RunHistoryCasValidation {
	claim: RunHistoryCasClaim;
	procfsAuthority: RunHistoryProcfsAuthority;
	directoryFences: RunHistoryCasDirectoryFence[];
	fileDescriptor: number;
	fileResolvedPath: string;
	fileIdentity: StableFilesystemIdentity;
	offset: number;
	hash: Hash;
	readCount: number;
}

interface RunHistoryOrdering {
	events: IncidentRecorderRunHistoryEvent[];
	causalRelations: IncidentRecorderRunHistoryProjection["ordering"]["causalRelations"];
}

interface RunHistoryTraversal {
	token: string;
	requestFingerprint: string;
	runId: string;
	fromWallTimeMs: number;
	throughWallTimeMs: number;
	deadlineMs: number;
	deadlineTimer?: ReturnType<typeof setTimeout>;
	orderingFailure?: string;
	phase:
		| "segment-occurrences"
		| "segment-run-gaps"
		| "segment-run-incomplete"
		| "segment-global-gaps"
		| "segment-recovery-gaps"
		| "legacy"
		| "cas-validation"
		| "publication-retained";
	retainForPublication: boolean;
	pendingResponse: "full" | "cursor-only";
	publicationCapability?: IncidentRecorderRunHistoryPublicationCapability;
	segmentReadLease?: IncidentRecorderSegmentReadLease;
	segmentCursor?: IncidentRecorderSegmentQueryCursor;
	segmentRecoveryGapCursor?: IncidentRecorderSegmentRecoveryGapQueryCursor;
	segmentRecordCount: number;
	segmentRecoveryGapCount: number;
	segmentScannedSegments: number;
	segmentScannedRecords: number;
	segmentScannedIndexBytes: number;
	legacyOccurrenceCount: number;
	legacyEntriesScanned: number;
	legacyBytesRead: number;
	directory?: ReturnType<typeof opendirSync>;
	legacyDirectoryPath?: string;
	legacyDirectoryDescriptor?: number;
	legacyDirectoryIdentity?: StableFilesystemIdentity;
	legacyDirectoryResolvedPath?: string;
	legacyNamespacePath?: string;
	legacyNamespaceDescriptor?: number;
	legacyNamespaceIdentity?: StableFilesystemIdentity;
	semanticFingerprints: Map<string, string>;
	events: Map<string, IncidentRecorderRunHistoryEvent>;
	casClaims: Map<string, RunHistoryCasClaim>;
	casDigests?: string[];
	casIndex: number;
	procfsAuthority?: RunHistoryProcfsAuthority;
	activeCasValidation?: RunHistoryCasValidation;
	validatedCasFacts: Array<{
		digest: string;
		bytes: number;
		path: string;
		identity: Record<string, string>;
	}>;
	memoryBytes: number;
	evidence: IncidentRecorderRunHistoryEvidence[];
	snapshotFacts: string[];
}

function stableFilesystemIdentity(stats: BigIntStats): StableFilesystemIdentity {
	return {
		dev: stats.dev,
		ino: stats.ino,
		mode: stats.mode,
		nlink: stats.nlink,
		size: stats.size,
		mtimeNs: stats.mtimeNs,
		ctimeNs: stats.ctimeNs,
	};
}

function sameStableFilesystemIdentity(left: StableFilesystemIdentity, right: StableFilesystemIdentity): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.mode === right.mode &&
		left.nlink === right.nlink &&
		left.size === right.size &&
		left.mtimeNs === right.mtimeNs &&
		left.ctimeNs === right.ctimeNs
	);
}

function sameStableDirectoryIdentity(left: StableFilesystemIdentity, right: StableFilesystemIdentity): boolean {
	return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode;
}

function contiguousUnsigned64Range(values: string[]): boolean {
	if (values.length === 0) return false;
	for (let index = 1; index < values.length; index += 1) {
		if (BigInt(values[index] ?? "0") !== BigInt(values[index - 1] ?? "0") + 1n) return false;
	}
	return true;
}

function serializableFilesystemIdentity(identity: StableFilesystemIdentity): Record<string, string> {
	return {
		dev: identity.dev.toString(),
		ino: identity.ino.toString(),
		mode: identity.mode.toString(),
		nlink: identity.nlink.toString(),
		size: identity.size.toString(),
		mtimeNs: identity.mtimeNs.toString(),
		ctimeNs: identity.ctimeNs.toString(),
	};
}

interface PinOccurrenceMatch {
	identityKey: string;
	semanticFingerprint: string;
	occurrenceReference: JournalOccurrenceReference;
	cursors: string[];
	cas: { digest: string; bytes: number; path: string };
	eventWallTimeMs: string;
}

interface JournalManifestOccurrence {
	occurrenceReference: JournalOccurrenceReference;
	semanticFingerprint?: string;
	cursors: string[];
	cas: { digest: string; bytes: number; path: string };
	eventWallTimeMs: string;
	pinnedCasPath: string;
	sealedArtifact?: SealedArtifact;
}

interface SealedArtifact {
	version: 1;
	state: "sealed_private_copy";
	generationId: string;
	dev: string;
	ino: string;
	bytes: number;
	mtimeMs: number;
	ctimeMs: number;
	mode: 256;
	nlink: 1;
	sha256: string;
}

interface JournalManifestValidation {
	incidentDir: string;
	manifestPath: string;
	descriptor: number;
	runId: string;
	anchorWallTimeMs: number;
	fromWallTimeMs: number;
	throughWallTimeMs: number;
	retainUntilWallTimeMs: number;
	offset: number;
	size: number;
	dev: number;
	ino: number;
	mtimeMs: number;
	ctimeMs: number;
	nlink: number;
	phase: "header" | "occurrences" | "suffix";
	manifestVersion?: 1 | 2;
	artifactGenerationId?: string;
	textBuffer: string;
	objectText: string;
	objectDepth: number;
	objectInString: boolean;
	objectEscape: boolean;
	fileEnded: boolean;
	occurrenceCount: number;
	resolvedOccurrenceCount: number;
	cursorBytes: number;
	pendingOccurrence?: JournalManifestOccurrence;
	pinValidation?: {
		descriptor: number;
		digest: string;
		bytes: number;
		pinnedPath: string;
		offset: number;
		hash: Hash;
		dev: number;
		ino: number;
		mtimeMs: number;
		ctimeMs: number;
		mode: number;
		uid: number;
		nlink: number;
		sealedArtifact?: SealedArtifact;
	};
	verifiedPins: Map<
		string,
		{ bytes: number; pinnedPath: string; dev: number; ino: number; sealedArtifact?: SealedArtifact }
	>;
}

interface SysdigRingSnapshotCandidate {
	id: string;
	sourcePath: string;
	sourceName: string;
	activeAtRequest: boolean;
	source: { dev: string; ino: string; bytes: number; mtimeMs: number; ctimeMs: number };
}

interface SysdigRingSnapshot {
	observedAtWallTimeMs: number;
	candidates: SysdigRingSnapshotCandidate[];
	issues: string[];
}

interface SysdigCapturePlan {
	version: 1;
	state: "planned";
	phase: "initial" | "final";
	requestFingerprint: string;
	snapshot: SysdigRingSnapshot;
}

interface SysdigFinalVerificationPlan {
	version: 1;
	state: "planned";
	requestFingerprint: string;
	recordIds: string[];
}

interface SysdigPinRequest {
	version: 1;
	runId: string;
	anchorWallTimeMs: number;
	fromWallTimeMs: number;
	throughWallTimeMs: number;
	resolveAfterWallTimeMs: number;
	requestedAtWallTimeMs: number;
	retainUntilWallTimeMs: number;
	ringBasePath: string;
	initialRingSnapshot?: SysdigRingSnapshot;
}

interface JournalPinRequest {
	version: 1;
	state: "pending";
	runId: string;
	anchorWallTimeMs: number;
	fromWallTimeMs: number;
	throughWallTimeMs: number;
	resolveAfterWallTimeMs: number;
	retainUntilWallTimeMs: number;
}

type IncidentPinAuthority = SysdigPinRequest;

interface SysdigPinnedSegmentRecord {
	version: 1;
	id: string;
	sourcePath: string;
	sourceName: string;
	observedAtWallTimeMs: number;
	phase: "initial" | "rotated" | "final";
	source: { dev: string; ino: string; bytes: number; mtimeMs: number; ctimeMs: number };
	pinnedPath: string;
	captureMethod: "bounded_copy";
	captureReason: "closed_segment_private_snapshot" | "active_segment_snapshot";
	bytesAtCapture: number;
	artifactAtCapture: {
		dev: string;
		ino: string;
		bytes: number;
		mtimeMs: number;
		ctimeMs: number;
		mode: 384;
		nlink: 1;
	};
}

interface SysdigPinRecordState {
	records: SysdigPinnedSegmentRecord[];
	recordFileCount: number;
	totalBytes: number;
	saturated: boolean;
	issues: string[];
}

interface SysdigSegmentCaptureResult {
	complete: boolean;
	bytesWorked: number;
	record?: SysdigPinnedSegmentRecord;
}

interface SysdigWorkBudget {
	remainingBytes: number;
}

interface SysdigSegmentVerification {
	recordId: string;
	descriptor: number;
	offset: number;
	hash: Hash;
	identity: {
		dev: number;
		ino: number;
		bytes: number;
		mtimeMs: number;
		ctimeMs: number;
		nlink: number;
		mode: number;
		uid: number;
	};
}

interface SysdigSourceCaptureState {
	recordId: string;
	sourcePath: string;
	sourceDescriptor?: number;
	partialDescriptor?: number;
	partialDev: string;
	partialIno: string;
	partialUid: string;
	partialBytes: number;
	verifiedBytes: number;
	phase: "verify_existing" | "copy" | "verify_final";
	verificationSourceIdentity?: { bytes: number; mtimeMs: number; ctimeMs: number };
}

interface CursorCheckpoint {
	version: 1;
	cursor: string;
	machineId: string;
	bootId: string;
	invocationId: string | null;
	lastRealtimeUs: string;
	wrapperSequences: Record<string, string>;
	producerSequences: Record<string, string>;
}

class JournalExportParser {
	private buffer = Buffer.alloc(0);
	private fields: Record<string, Buffer> = {};
	private entryBytes = 0;
	private binaryFieldName?: string;
	private binaryLength?: number;

	constructor(private readonly onEntry: (fields: JournalFields) => void) {}

	push(chunk: Buffer): void {
		let offset = 0;
		while (offset < chunk.length) {
			const take = Math.min(64 * 1024, chunk.length - offset);
			this.buffer = Buffer.concat([this.buffer, chunk.subarray(offset, offset + take)]);
			offset += take;
			this.drain();
			if (this.buffer.length > EXPORT_BUFFER_MAX_BYTES)
				throw new Error("Incident journal export field exceeds its bound");
		}
	}

	private drain(): void {
		for (;;) {
			if (this.binaryFieldName) {
				if (this.binaryLength === undefined) {
					if (this.buffer.length < 8) return;
					const length = Number(this.buffer.readBigUInt64LE(0));
					const fieldLimit = this.binaryFieldName === "MESSAGE" ? MESSAGE_MAX_BYTES : EXPORT_BUFFER_MAX_BYTES;
					if (
						!Number.isSafeInteger(length) ||
						length > fieldLimit ||
						this.entryBytes + 8 + length + 1 > EXPORT_BUFFER_MAX_BYTES
					) {
						throw new Error("Journal export binary field exceeds its bound");
					}
					this.binaryLength = length;
				}
				const length = this.binaryLength;
				if (this.buffer.length < 8 + length + 1) return;
				if (this.buffer[8 + length] !== 10) throw new Error("Malformed journal export binary field terminator");
				this.fields[this.binaryFieldName] = Buffer.from(this.buffer.subarray(8, 8 + length));
				this.entryBytes += 8 + length + 1;
				this.buffer = this.buffer.subarray(8 + length + 1);
				this.binaryFieldName = undefined;
				this.binaryLength = undefined;
				continue;
			}
			const newline = this.buffer.indexOf(10);
			if (newline < 0) {
				if (this.buffer.length > EXPORT_BUFFER_MAX_BYTES - this.entryBytes)
					throw new Error("Journal export text field exceeds its bound");
				return;
			}
			const line = this.buffer.subarray(0, newline);
			this.buffer = this.buffer.subarray(newline + 1);
			if (line.length === 0) {
				this.entryBytes += 1;
				if (Object.getOwnPropertyNames(this.fields).length > 0) this.onEntry(this.fields);
				this.fields = {};
				this.entryBytes = 0;
				continue;
			}
			this.entryBytes += line.length + 1;
			if (this.entryBytes > EXPORT_BUFFER_MAX_BYTES) throw new Error("Journal export entry exceeds its total bound");
			const equals = line.indexOf(61);
			const nameBytes = equals < 0 ? line : line.subarray(0, equals);
			if (nameBytes.length < 1 || nameBytes.length > 255)
				throw new Error("Journal export field name exceeds its bound");
			const name = nameBytes.toString("ascii");
			if (!/^[A-Z_][A-Z0-9_]*$/.test(name) || Object.hasOwn(this.fields, name))
				throw new Error("Malformed or duplicate journal export field");
			if (equals < 0) {
				this.binaryFieldName = name;
				continue;
			}
			const value = Buffer.from(line.subarray(equals + 1));
			if (name === "MESSAGE" && value.length > MESSAGE_MAX_BYTES)
				throw new Error("Incident journal MESSAGE exceeds its bound");
			this.fields[name] = value;
		}
	}

	finish(): void {
		if (this.buffer.length > 0 || this.binaryFieldName || Object.getOwnPropertyNames(this.fields).length > 0) {
			throw new Error("Journal export ended with a truncated entry");
		}
	}

	poisonFields(): JournalFields {
		return { ...this.fields };
	}
}
function retainedBytes(value: unknown, seen = new Set<object>()): number {
	if (typeof value === "string") return Buffer.byteLength(value);
	if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") return 8;
	if (Buffer.isBuffer(value)) return value.length;
	if (!value || typeof value !== "object" || seen.has(value)) return 0;
	seen.add(value);
	if (Array.isArray(value)) return value.reduce((total, child) => total + retainedBytes(child, seen), 0);
	let bytes = 0;
	for (const [key, child] of Object.entries(value)) bytes += Buffer.byteLength(key) + retainedBytes(child, seen);
	return bytes;
}

function canonicalJson(value: unknown, depth = 0): string {
	if (depth > 32) throw new Error("Incident semantic value exceeded its nesting bound");
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
	if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map((child) => canonicalJson(child, depth + 1)).join(",")}]`;
	if (!value || typeof value !== "object") throw new Error("Incident semantic value is not canonical JSON");
	return `{${Object.keys(value as Record<string, unknown>)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key], depth + 1)}`)
		.join(",")}}`;
}

function hasExactOwnKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const observed = Object.keys(value as Record<string, unknown>).sort();
	const required = [...expected].sort();
	return observed.length === required.length && observed.every((key, index) => key === required[index]);
}

function isSealedArtifact(value: unknown): value is SealedArtifact {
	if (
		!hasExactOwnKeys(value, [
			"version",
			"state",
			"generationId",
			"dev",
			"ino",
			"bytes",
			"mtimeMs",
			"ctimeMs",
			"mode",
			"nlink",
			"sha256",
		])
	)
		return false;
	return (
		value.version === 1 &&
		value.state === "sealed_private_copy" &&
		typeof value.generationId === "string" &&
		/^[0-9a-f]{64}$/.test(value.generationId) &&
		typeof value.dev === "string" &&
		/^(?:0|[1-9]\d*)$/.test(value.dev) &&
		typeof value.ino === "string" &&
		/^(?:0|[1-9]\d*)$/.test(value.ino) &&
		Number.isSafeInteger(value.bytes) &&
		Number(value.bytes) >= 0 &&
		Number.isFinite(value.mtimeMs) &&
		Number.isFinite(value.ctimeMs) &&
		value.mode === 0o400 &&
		value.nlink === 1 &&
		typeof value.sha256 === "string" &&
		/^[0-9a-f]{64}$/.test(value.sha256)
	);
}

function sha256(value: Uint8Array | string): string {
	return createHash("sha256").update(value).digest("hex");
}

function boundedNonemptyUtf8(value: string, maximumBytes: number, fallback: string): string {
	const source = value.length > 0 ? value : fallback;
	let result = "";
	let bytes = 0;
	for (const character of source) {
		const characterBytes = Buffer.byteLength(character, "utf8");
		if (bytes + characterBytes > maximumBytes) break;
		result += character;
		bytes += characterBytes;
	}
	return result.length > 0 ? result : fallback;
}

function fsyncDirectory(path: string): void {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "r");
		fsyncSync(descriptor);
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function writeAll(descriptor: number, value: Buffer): void {
	let offset = 0;
	while (offset < value.length) {
		const written = writeSync(descriptor, value, offset, value.length - offset);
		if (written <= 0) throw new Error("Incident compactor write made no progress");
		offset += written;
	}
}

function writeImmutable(path: string, value: Buffer): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temporary = join(
		dirname(path),
		`.${basename(path)}.tmp-${process.pid}-${sha256(`${process.hrtime.bigint()}`)}`,
	);
	let descriptor: number | undefined;
	try {
		descriptor = openSync(temporary, "wx", 0o600);
		writeAll(descriptor, value);
		fsyncSync(descriptor);
		closeSync(descriptor);
		descriptor = undefined;
		try {
			linkSync(temporary, path);
			rmSync(temporary, { force: true });
			fsyncDirectory(dirname(path));
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			const existing = readFileSync(path);
			if (!existing.equals(value)) throw new Error(`Immutable incident reference collision at ${path}`);
			// A previous link may have succeeded even though its directory fsync failed.
			// Exact-byte replay must re-establish namespace durability before returning success.
			fsyncDirectory(dirname(path));
			rmSync(temporary, { force: true });
		}
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
		rmSync(temporary, { force: true });
	}
}

function optionalText(fields: JournalFields, name: string): string | null {
	const value = fields[name];
	return value && value.length > 0 ? value.toString("utf8") : null;
}

function strictBase64(value: string): Buffer {
	if (value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
		throw new Error("Incident journal payload is not canonical base64");
	}
	const decoded = Buffer.from(value, "base64");
	if (decoded.toString("base64") !== value) throw new Error("Incident journal payload base64 did not round trip");
	return decoded;
}

function isCanonicalUuid(value: unknown): value is string {
	return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function isRecordObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUnsigned64(value: unknown): value is string {
	if (typeof value !== "string" || !/^(?:0|[1-9]\d{0,19})$/.test(value)) return false;
	try {
		return BigInt(value) <= (1n << 64n) - 1n;
	} catch {
		return false;
	}
}

function segmentObservedAtMs(value: string, divisor = 1n): number {
	if (!/^\d+$/.test(value)) throw new Error("Segment observation time is not an unsigned decimal");
	const milliseconds = BigInt(value) / divisor;
	if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) {
		throw new Error("Segment observation time exceeds the safe integer range");
	}
	return Number(milliseconds);
}

function segmentObservedAtMsOrZero(value: string, divisor = 1n): number {
	try {
		return segmentObservedAtMs(value, divisor);
	} catch {
		return 0;
	}
}

function isSegmentLocator(value: unknown): value is IncidentRecorderSegmentLocator {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const locator = value as Record<string, unknown>;
	return (
		locator.version === 1 &&
		typeof locator.segmentId === "string" &&
		/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(locator.segmentId) &&
		["segmentSequence", "ordinal", "offset", "frameBytes", "payloadBytes"].every(
			(key) => Number.isSafeInteger(locator[key]) && Number(locator[key]) >= 0,
		) &&
		typeof locator.payloadSha256 === "string" &&
		/^[0-9a-f]{64}$/.test(locator.payloadSha256)
	);
}

function isJournalOccurrenceReference(
	value: unknown,
	version: 1 | 2,
	legacyRoot: string,
): value is JournalOccurrenceReference {
	if (typeof value === "string") return value.startsWith(`${legacyRoot}/`);
	if (version !== 2 || !value || typeof value !== "object" || Array.isArray(value)) return false;
	const reference = value as Record<string, unknown>;
	return reference.kind === "segment" && isSegmentLocator(reference.locator);
}

function isScalarMetadata(value: unknown): value is IncidentJournalLine["metadata"] {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	for (const [key, child] of Object.entries(value)) {
		if (!/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(key)) return false;
		if (
			child !== null &&
			typeof child !== "string" &&
			typeof child !== "boolean" &&
			!(typeof child === "number" && Number.isFinite(child))
		)
			return false;
	}
	return Buffer.byteLength(JSON.stringify(value)) <= 4 * 1024;
}

function hasValidChunkFlags(flags: unknown, chunkIndex: unknown, chunkCount: unknown): boolean {
	try {
		validateIncidentRecorderFrameFlags(Number(flags), Number(chunkIndex), Number(chunkCount));
		return true;
	} catch {
		return false;
	}
}

function isJournalLine(value: unknown): value is IncidentJournalLine {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const line = value as Partial<IncidentJournalLine>;
	const safeNullableInteger = (child: unknown) =>
		child === null || (Number.isSafeInteger(child) && Number(child) >= 0);
	return (
		line.schema === "prime-agent-raw-v1" &&
		isCanonicalUuid(line.runId) &&
		isCanonicalUuid(line.runToken) &&
		isCanonicalUuid(line.producerId) &&
		isCanonicalUuid(line.occurrenceId) &&
		isUnsigned64(line.producerSequence) &&
		isUnsigned64(line.wrapperSequence) &&
		isUnsigned64(line.eventWallTimeMs) &&
		isUnsigned64(line.eventMonotonicNs) &&
		Number.isSafeInteger(line.chunkIndex) &&
		Number(line.chunkIndex) >= 0 &&
		Number.isSafeInteger(line.chunkCount) &&
		Number(line.chunkCount) >= 1 &&
		Number(line.chunkCount) <= 40 &&
		Number(line.chunkIndex) < Number(line.chunkCount) &&
		typeof line.source === "string" &&
		line.source.length > 0 &&
		Buffer.byteLength(line.source) <= 255 &&
		typeof line.type === "string" &&
		line.type.length > 0 &&
		Buffer.byteLength(line.type) <= 255 &&
		typeof line.encoding === "string" &&
		line.encoding.length > 0 &&
		Buffer.byteLength(line.encoding) <= 255 &&
		["exact-bytes", "derived-scalar", "loss", "control"].includes(String(line.payloadKind)) &&
		typeof line.payloadBase64 === "string" &&
		typeof line.chunkSha256 === "string" &&
		/^[0-9a-f]{64}$/.test(line.chunkSha256) &&
		typeof line.occurrenceSha256 === "string" &&
		/^[0-9a-f]{64}$/.test(line.occurrenceSha256) &&
		Number.isSafeInteger(line.rawOccurrenceBytes) &&
		Number(line.rawOccurrenceBytes) >= 0 &&
		Number(line.rawOccurrenceBytes) <= 983_040 &&
		Number.isSafeInteger(line.chunkBytes) &&
		Number(line.chunkBytes) >= 0 &&
		Number(line.chunkBytes) <= 24 * 1024 &&
		Number.isSafeInteger(line.frameChecksum) &&
		Number(line.frameChecksum) >= 0 &&
		Number(line.frameChecksum) <= 0xffffffff &&
		hasValidChunkFlags(line.flags, line.chunkIndex, line.chunkCount) &&
		safeNullableInteger(line.producerPid) &&
		safeNullableInteger(line.targetPid) &&
		safeNullableInteger(line.systemdCatPid) &&
		Number.isSafeInteger(line.wrapperPid) &&
		Number(line.wrapperPid) > 0 &&
		(line.producerStartId === null || typeof line.producerStartId === "string") &&
		(line.wrapperStartId === null || typeof line.wrapperStartId === "string") &&
		(line.targetStartId === null || typeof line.targetStartId === "string") &&
		(line.systemdCatStartId === null || typeof line.systemdCatStartId === "string") &&
		(line.machineId === null || typeof line.machineId === "string") &&
		(line.bootId === null || typeof line.bootId === "string") &&
		(line.systemdInvocationId === null || typeof line.systemdInvocationId === "string") &&
		isScalarMetadata(line.metadata) &&
		line.observationDisposition === "observed_by_wrapper" &&
		line.queueDisposition === "locally_admitted" &&
		line.wrapperRelayDisposition === "locally_admitted" &&
		line.streamDisposition === "systemd_cat_stdin_write_attempted" &&
		line.journalDurability === "not_asserted_by_writer"
	);
}
function canonicalUuidFields(
	value: unknown,
): value is { runId: string; runToken: string; producerId: string; occurrenceId: string } {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const fields = value as Record<string, unknown>;
	return (
		isCanonicalUuid(fields.runId) &&
		isCanonicalUuid(fields.runToken) &&
		isCanonicalUuid(fields.producerId) &&
		isCanonicalUuid(fields.occurrenceId)
	);
}

export interface StoppedTargetArtifactReference {
	algorithm: "sha256";
	digest: string;
	bytes: number;
	path: string;
	encoding: string;
}

export type StoppedTargetArtifactAdmission =
	| {
			state: "pending";
			reason:
				| "work_budget"
				| "storage_paused"
				| "cas_transaction_busy"
				| "writer_lifecycle_lease_required"
				| "writer_lifecycle_lease_released"
				| "writer_lifecycle_recovery_conflict"
				| "writer_lifecycle_lease_lost"
				| "writer_lifecycle_namespace_changed"
				| "writer_lifecycle_unavailable"
				| "artifact_staging_reconciliation_required";
			copiedBytes: number;
			totalBytes: number;
	  }
	| { state: "complete"; artifact: StoppedTargetArtifactReference }
	| { state: "error"; reason: string };

interface StoppedTargetArtifactStream {
	sourcePath: string;
	encoding: string;
	dev: bigint;
	ino: bigint;
	mtimeNs: bigint;
	ctimeNs: bigint;
	stagedDev: bigint;
	stagedIno: bigint;
	totalBytes: number;
	copiedBytes: number;
	rehydrateBytes: number;
	stageWasExisting: boolean;
	hash: Hash;
	reservedBytes: number;
	reservedEntries: number;
	reservedInodes: number;
	reservationReleased: boolean;
	error?: string;
}

type StorageAccountingMetadata = {
	dev: number | bigint;
	ino: number | bigint;
	size: number | bigint;
	blocks?: number | bigint;
	nlink: number | bigint;
};

type StorageAccountingEffect =
	| { kind: "account"; metadata: StorageAccountingMetadata; entryCreated: boolean }
	| { kind: "remove"; metadata: StorageAccountingMetadata; releaseOwnedInode: boolean };

function allocatedStorageBytes(stat: { size: number | bigint; blocks?: number | bigint }): number {
	const size = Number(stat.size);
	const blocks = stat.blocks === undefined ? 0 : Number(stat.blocks);
	if (!Number.isSafeInteger(size) || size < 0 || !Number.isSafeInteger(blocks) || blocks < 0) {
		throw new Error("Incident storage metadata exceeded safe integer bounds");
	}
	return Math.max(size, blocks * 512);
}

function abortError(message: string): Error {
	const error = new Error(message);
	error.name = "AbortError";
	return error;
}

function childEnvironment(): NodeJS.ProcessEnv {
	const environment = { ...process.env };
	delete environment.NOTIFY_SOCKET;
	return environment;
}

function positiveBound(value: number | undefined, fallback: number): number {
	return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : fallback;
}

export interface IncidentRecorderCompactorOptions {
	agentDir: string;
	/** Current normal writer lease, supplied by the service lifecycle controller. */
	writerLifecycleLease?: () => IncidentRecorderWriterLifecycleLease | undefined;
	journalctlPath?: string;
	/** Test/packaging override only. Production uses GNU find for bounded storage discovery. */
	storageScannerPath?: string;
	storageByteCeiling?: number;
	freeReserveBytes?: number;
	/** Test/diagnostic crash boundary after durable CAS and lease publication steps. */
	onCasPublicationStep?: (step: "cas_durable" | "lease_durable") => void;
	/** Bounded diagnostic/test seam for run-history CAS reads and post-read stability injection. */
	onRunHistoryCasValidationStep?: (event: {
		step: "opened" | "read" | "verified";
		digest: string;
		offset: number;
		readCount: number;
	}) => void;
	/** Test-only descriptor lifecycle seam. The close hook runs after the real descriptor is closed. */
	runHistoryDescriptorIo?: {
		afterOpen?: (input: { role: "legacy_occurrence" | "stable_directory"; descriptor: number }) => void;
		afterClose?: (input: { role: "legacy_occurrence" | "stable_directory"; descriptor: number }) => void;
	};
	/** Test-only seam for exercising a replaced proc descriptor subtree. */
	runHistoryProcfs?: {
		descriptorDirectoryPath?: string;
		descriptorInfoDirectoryPath?: string;
		statfsType?: (path: string) => number | bigint;
		resolveDescriptorPath?: (input: { canonicalPath: string; descriptor: number; childName?: string }) => string;
		onAuthorityAdmitted?: (input: { mountId: bigint }) => void;
	};
	/** Test/packaging override only. Production uses the stock root-owned Sysdig ring. */
	sysdigRingBasePath?: string;
	/** Test-only work bound for resumable Sysdig copies and verification. */
	sysdigPinWorkBytesPerPass?: number;
	/** Test-only bound for raw incident-root entries discovered per pass. */
	pendingPinDirectoryDiscoveryEntriesPerPass?: number;
	/** Test-only bound for pending-pin names processed per pass. */
	pendingPinDirectoryBatchCount?: number;
	/** Test/diagnostic crash and ordering boundary for immutable Sysdig pin requests. */
	onSysdigPinStep?: (
		step: "sysdig_request_durable" | "provider_requests_durable" | "initial_capture_complete",
	) => void;
	/** Test-only bound overrides. */
	storageAccountingMaxInodes?: number;
	storageAccountingMaxEntries?: number;
	storageAccountingScanTimeoutMs?: number;
	storageHighWaterBytes?: number;
	storageLowWaterBytes?: number;
	storageHighWaterInodes?: number;
	storageLowWaterInodes?: number;
	storageHighWaterEntries?: number;
	storageLowWaterEntries?: number;
	journalCatchupMaxEntries?: number;
	journalCatchupMaxBytes?: number;
	journalCatchupSliceMs?: number;
}

export interface IncidentRecorderCompactorRunOptions {
	signal: AbortSignal;
	onReaderReady?: () => void;
	onStorageMode?: (mode: IncidentRecorderStorageMode, reason?: string) => void;
	onRecoveryPass?: () => boolean | Promise<boolean>;
	/** Reacquire normal writer ownership after recovery, before opening journal mutation. */
	onNormalWriterAdmission?: () => Promise<boolean>;
	/** Test-only cadence override. */
	storageRecoveryCadenceMs?: number;
}

export type IncidentRecorderStorageMode = "uninitialized" | "normal" | "recovery-only";

interface JournalReaderOutcome {
	code: number | null;
	signal: NodeJS.Signals | null;
	error?: Error;
	parserError?: Error;
	poisonFields: JournalFields;
	stderr: string;
	entries: number;
	lastCursor?: string;
	workBudgetExhausted: boolean;
	aborted: boolean;
}

type RecorderRootLifecycleUnavailableReason =
	| "writer_lifecycle_lease_required"
	| "writer_lifecycle_lease_released"
	| "writer_lifecycle_recovery_conflict"
	| "writer_lifecycle_lease_lost"
	| "writer_lifecycle_namespace_changed"
	| "writer_lifecycle_unavailable";

type RecorderRootMutationResult<T> =
	| { state: "committed"; value: T }
	| { state: "unavailable"; reason: RecorderRootLifecycleUnavailableReason };

export class IncidentRecorderCompactor {
	private readonly root: string;
	private readonly checkpointPath: string;
	private readonly pendingPinCursorPath: string;
	private readonly wrapperSequences = new Map<string, bigint>();
	private readonly producerSequences = new Map<string, bigint>();
	private checkpoint?: CursorCheckpoint;
	private readonly assemblies = new Map<string, Assembly>();
	private assemblyBytes = 0;
	private readonly pendingEntries: JournalRecordReference[] = [];
	private pendingEntryBytes = 0;
	private pausedUntilMs = 0;
	private storageBytes = 0;
	private storageEntries = 0;
	private storageInodes = new Map<string, number>();
	private storageReservedBytes = 0;
	private storageReservedEntries = 0;
	private storageReservedInodes = 0;
	private storageAccountingReadyState = false;
	/**
	 * Monotonic invalidation generation for scans that may overlap an uncertain
	 * storage mutation. A scan may reconcile successful concurrent mutations,
	 * but it must not publish a snapshot taken across an uncertain boundary.
	 */
	private storageAccountingInvalidationGeneration = 0;
	private storageModeState: IncidentRecorderStorageMode = "uninitialized";
	private storageRecoveryReasonState?: string;
	private storageScanPromise?: Promise<void>;
	private storageScanInProgress = false;
	private storageScanConcurrentEntries = 0;
	private readonly storageScanConcurrentInodes = new Map<string, number>();
	private storageScanSegmentMutation = false;
	private segmentStore?: IncidentRecorderSegmentStore;
	private segmentStoreCloseFailure?: unknown;
	private segmentStoreCloseUncertain = false;
	private transientFileCloseFailure?: Error;
	private readonly segmentOpenStorageEntries = new Map<string, IncidentRecorderSegmentOpenStorageEntry>();
	private readonly segmentAccountingSequences = new Map<string, number>();
	private segmentOpenRequiresReconciliation = false;
	private segmentRootCallbackDepth = 0;
	private segmentRootOpenReservation?: {
		bytes: number;
		entries: number;
		inodes: number;
	};
	private segmentRootAppendReservation?: {
		bytes: number;
		entries: number;
		inodes: number;
	};
	private segmentRecoveryPruneCursor?: IncidentRecorderSegmentPruneCursor;
	private checkpointDisposition: "valid" | "missing" | "invalid" = "missing";
	private readonly activePinScans = new Map<string, ActivePinScan>();
	private readonly activeCompactorChildren = new Set<TrackedCompactorChild>();
	private pinReaderGeneration = 0;
	private pinReadersQuiescing = false;
	private readonly lifecycleClosedDescriptors = new Set<number>();
	private readonly lifecycleClosedDirectories = new WeakSet<object>();
	private activePinTraversal?: PinTraversal;
	private pinRetentionMaintenance = false;
	private readonly runHistoryTraversals = new Map<string, RunHistoryTraversal>();
	private readonly runHistoryPublicationCapabilities = new Map<
		IncidentRecorderRunHistoryPublicationCapability,
		RunHistoryTraversal
	>();
	private readonly releasedRunHistoryPublicationCapabilities =
		new WeakSet<IncidentRecorderRunHistoryPublicationCapability>();
	private journalManifestValidation?: JournalManifestValidation;
	private readonly stoppedTargetStreams = new Map<string, StoppedTargetArtifactStream>();
	private sysdigSegmentVerification?: SysdigSegmentVerification;
	private sysdigSourceCapture?: SysdigSourceCaptureState;
	private pendingPinCursor?: string;
	private pendingPinDirectoryTraversal?: PendingPinDirectoryTraversal;
	private pendingPinDirectoryEntriesReadLastPass = 0;

	constructor(private readonly options: IncidentRecorderCompactorOptions) {
		this.root = join(options.agentDir, "incident-recorder");
		this.checkpointPath = join(this.root, "compactor-cursor.json");
		this.pendingPinCursorPath = join(this.root, "pending-pin-directory-cursor.json");
		const checkpointExists = existsSync(this.checkpointPath);
		try {
			const parsed = JSON.parse(readFileSync(this.checkpointPath, "utf8")) as CursorCheckpoint;
			if (parsed.version === 1 && typeof parsed.cursor === "string") {
				this.checkpoint = parsed;
				this.checkpointDisposition = "valid";
				for (const key of Object.getOwnPropertyNames(parsed.wrapperSequences ?? {}))
					this.wrapperSequences.set(key, BigInt(parsed.wrapperSequences[key]));
				for (const key of Object.getOwnPropertyNames(parsed.producerSequences ?? {}))
					this.producerSequences.set(key, BigInt(parsed.producerSequences[key]));
			} else if (checkpointExists) this.checkpointDisposition = "invalid";
		} catch {
			if (checkpointExists) this.checkpointDisposition = "invalid";
		}
		try {
			const cursor = JSON.parse(readFileSync(this.pendingPinCursorPath, "utf8")) as Record<string, unknown>;
			if (
				cursor.version === 1 &&
				(cursor.afterName === null ||
					(typeof cursor.afterName === "string" && Buffer.byteLength(cursor.afterName) <= 4096))
			) {
				this.pendingPinCursor = typeof cursor.afterName === "string" ? cursor.afterName : undefined;
			}
		} catch {}
	}

	private normalWriterLifecycleLease():
		| { state: "available"; lease: IncidentRecorderWriterLifecycleLease }
		| { state: "unavailable"; reason: RecorderRootLifecycleUnavailableReason } {
		const getter = this.options.writerLifecycleLease;
		if (!getter) return { state: "unavailable", reason: "writer_lifecycle_lease_required" };
		let lease: IncidentRecorderWriterLifecycleLease | undefined;
		try {
			lease = getter();
		} catch {
			return { state: "unavailable", reason: "writer_lifecycle_unavailable" };
		}
		if (!lease) return { state: "unavailable", reason: "writer_lifecycle_lease_required" };
		const mode = inspectIncidentRecorderWriterLifecycleLeaseMode(lease);
		if (!mode) return { state: "unavailable", reason: "writer_lifecycle_lease_released" };
		if (mode !== "normal") return { state: "unavailable", reason: "writer_lifecycle_recovery_conflict" };
		return { state: "available", lease };
	}

	private withRecorderRoot<T>(
		operation: (root: IncidentCasRootMutation, assertCurrent: () => void) => T,
		lease?: IncidentRecorderWriterLifecycleLease,
	): RecorderRootMutationResult<T> {
		const admission = lease ? { state: "available" as const, lease } : this.normalWriterLifecycleLease();
		if (admission.state === "unavailable") return admission;
		const assertCurrent = (): void => {
			if (inspectIncidentRecorderWriterLifecycleLeaseMode(admission.lease) !== "normal")
				throw this.writerLifecycleAdmissionError("writer_lifecycle_lease_lost");
		};
		this.segmentRootCallbackDepth += 1;
		let mutation: IncidentRecorderWriterLifecycleMutationResult<T>;
		try {
			mutation = admission.lease.withRoot((root) => operation(root, assertCurrent));
		} finally {
			this.segmentRootCallbackDepth -= 1;
		}
		if (mutation.state === "committed") return mutation;
		switch (mutation.reason) {
			case "released":
				return { state: "unavailable", reason: "writer_lifecycle_lease_released" };
			case "lease_lost":
				return { state: "unavailable", reason: "writer_lifecycle_lease_lost" };
			case "namespace_changed":
			case "root_detached":
				return { state: "unavailable", reason: "writer_lifecycle_namespace_changed" };
			default:
				return { state: "unavailable", reason: "writer_lifecycle_unavailable" };
		}
	}

	private writerLifecycleAdmissionError(reason: RecorderRootLifecycleUnavailableReason): Error {
		const error = new Error(`Incident recorder writer lifecycle unavailable: ${reason}`);
		error.name = "IncidentRecorderWriterLifecycleAdmissionError";
		return error;
	}

	get storageAccountingReady(): boolean {
		return this.storageAccountingReadyState;
	}

	get storageMode(): IncidentRecorderStorageMode {
		return this.storageModeState;
	}

	get storageRecoveryReason(): string | undefined {
		return this.storageRecoveryReasonState;
	}

	async initializeStorageAccounting(signal: AbortSignal): Promise<void> {
		if (this.storageScanPromise) return this.storageScanPromise;
		const hadTrustedBaseline = this.storageAccountingReadyState;
		const scanInvalidationGeneration = this.storageAccountingInvalidationGeneration;
		const scan = this.scanStorageUsage(signal);
		this.storageScanPromise = scan;
		try {
			await scan;
		} catch (error) {
			if (signal.aborted || (error instanceof Error && error.name === "AbortError")) throw error;
			const reason = this.storageScanRecoveryReason(error) ?? (hadTrustedBaseline ? "scan_failed" : undefined);
			if (!reason) throw error;
			this.storageAccountingReadyState =
				this.storageAccountingInvalidationGeneration === scanInvalidationGeneration ? hadTrustedBaseline : false;
			this.enterStorageRecovery(reason);
		} finally {
			if (this.storageScanPromise === scan) this.storageScanPromise = undefined;
		}
	}

	private storageScanRecoveryReason(error: unknown): string | undefined {
		const message = error instanceof Error ? error.message : String(error);
		if (message.includes("inode bound exceeded")) return "inode_bound_exceeded";
		if (message.includes("entry bound exceeded")) return "entry_bound_exceeded";
		if (message.includes("storage accounting exceeded")) return "scan_timeout";
		if (message.includes("storage accounting invalidated during discovery")) return "scan_invalidated";
		return undefined;
	}

	private invalidateStorageAccounting(): void {
		this.storageAccountingInvalidationGeneration += 1;
		this.storageAccountingReadyState = false;
	}

	private async scanStorageUsage(signal: AbortSignal): Promise<void> {
		if (signal.aborted) throw abortError("Incident storage accounting was aborted before discovery");
		const scanInvalidationGeneration = this.storageAccountingInvalidationGeneration;
		const incidentRoot = join(this.options.agentDir, "incidents");
		mkdirSync(this.root, { recursive: true, mode: 0o700 });
		mkdirSync(incidentRoot, { recursive: true, mode: 0o700 });
		const maximumInodes = positiveBound(this.options.storageAccountingMaxInodes, STORAGE_ACCOUNTING_MAX_INODES);
		const maximumEntries = positiveBound(this.options.storageAccountingMaxEntries, STORAGE_ACCOUNTING_MAX_ENTRIES);
		const timeoutMs = positiveBound(this.options.storageAccountingScanTimeoutMs, STORAGE_ACCOUNTING_SCAN_TIMEOUT_MS);
		const discovered = new Map<string, number>();
		let entries = 0;
		let bytes = 0;
		let lineBuffer = Buffer.alloc(0);
		let stderr = "";
		let scanError: Error | undefined;
		let aborted = false;
		let killTimer: ReturnType<typeof setTimeout> | undefined;
		const wasReady = this.storageAccountingReadyState;
		this.storageScanInProgress = true;
		this.storageScanConcurrentEntries = 0;
		this.storageScanConcurrentInodes.clear();
		this.storageScanSegmentMutation = false;
		const child = spawn(
			this.options.storageScannerPath ?? "find",
			[this.root, incidentRoot, "-xdev", "-printf", "%D\\t%i\\t%s\\t%b\\n"],
			{ stdio: ["ignore", "pipe", "pipe"], env: childEnvironment() },
		);
		let resolveChildCompletion: () => void = () => {};
		const childCompletion = new Promise<void>((resolve) => {
			resolveChildCompletion = resolve;
		});
		const trackedChild: TrackedCompactorChild = {
			child,
			completion: childCompletion,
			terminate: () => {},
		};
		const terminate = (): void => {
			try {
				child.kill("SIGTERM");
			} catch {}
			if (killTimer) return;
			killTimer = setTimeout(() => {
				try {
					if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
				} catch {}
			}, CHILD_TERMINATION_GRACE_MS);
			killTimer.unref();
		};
		trackedChild.terminate = terminate;
		this.activeCompactorChildren.add(trackedChild);
		const parseLine = (line: Buffer): void => {
			entries += 1;
			if (entries > maximumEntries) throw new Error("Incident storage accounting entry bound exceeded");
			const match = /^(\d+)\t(\d+)\t(\d+)\t(\d+)$/.exec(line.toString("ascii"));
			if (!match) throw new Error("Incident storage accounting emitted a malformed record");
			const identity = `${match[1]}:${match[2]}`;
			if (discovered.has(identity)) return;
			if (discovered.size >= maximumInodes) throw new Error("Incident storage accounting inode bound exceeded");
			const apparent = BigInt(match[3] ?? "0");
			const allocated = BigInt(match[4] ?? "0") * 512n;
			const contribution = apparent > allocated ? apparent : allocated;
			if (contribution > BigInt(Number.MAX_SAFE_INTEGER))
				throw new Error("Incident storage accounting record exceeds the safe byte range");
			discovered.set(identity, Number(contribution));
			bytes += Number(contribution);
			if (!Number.isSafeInteger(bytes))
				throw new Error("Incident storage accounting total exceeds the safe byte range");
		};
		child.stdout?.on("data", (chunk: Buffer) => {
			if (scanError || aborted) return;
			try {
				lineBuffer = Buffer.concat([lineBuffer, chunk]);
				for (;;) {
					const newline = lineBuffer.indexOf(10);
					if (newline < 0) break;
					if (newline > STORAGE_ACCOUNTING_LINE_MAX_BYTES)
						throw new Error("Incident storage accounting line bound exceeded");
					parseLine(lineBuffer.subarray(0, newline));
					lineBuffer = lineBuffer.subarray(newline + 1);
				}
				if (lineBuffer.length > STORAGE_ACCOUNTING_LINE_MAX_BYTES)
					throw new Error("Incident storage accounting line bound exceeded");
			} catch (error) {
				scanError = error instanceof Error ? error : new Error(String(error));
				terminate();
			}
		});
		child.stderr?.on("data", (chunk: Buffer) => {
			stderr = `${stderr}${chunk.toString("utf8")}`.slice(-STORAGE_ACCOUNTING_STDERR_MAX_BYTES);
		});
		child.once("error", (error) => {
			scanError ??= error;
		});
		const onAbort = (): void => {
			aborted = true;
			terminate();
		};
		signal.addEventListener("abort", onAbort, { once: true });
		const deadline = setTimeout(() => {
			scanError ??= new Error(`Incident storage accounting exceeded ${timeoutMs}ms`);
			terminate();
		}, timeoutMs);
		deadline.unref();
		try {
			const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
				child.once("close", (code, childSignal) => {
					resolve({ code, signal: childSignal });
					resolveChildCompletion();
				});
			});
			if (aborted || signal.aborted) throw abortError("Incident storage accounting was aborted");
			if (!scanError && lineBuffer.length > 0)
				scanError = new Error("Incident storage accounting ended with a truncated record");
			if (scanError) throw scanError;
			if (result.code !== 0)
				throw new Error(
					`Incident storage accounting exited (${result.code ?? result.signal ?? "unknown"}): ${stderr}`,
				);
			if (this.storageScanSegmentMutation) {
				throw new Error("Incident storage accounting changed during a segment-store mutation");
			}
			if (this.storageAccountingInvalidationGeneration !== scanInvalidationGeneration) {
				throw new Error("Incident storage accounting invalidated during discovery");
			}
			let concurrentBytes = 0;
			for (const [identity, added] of this.storageScanConcurrentInodes) {
				const previous = discovered.get(identity);
				if (previous === undefined) {
					if (discovered.size >= maximumInodes)
						throw new Error("Incident storage accounting inode bound exceeded during reconciliation");
					discovered.set(identity, added);
					concurrentBytes += added;
					continue;
				}
				discovered.set(identity, added);
				concurrentBytes += added - previous;
			}
			const reconciledBytes = bytes + concurrentBytes;
			entries += this.storageScanConcurrentEntries;
			if (entries > maximumEntries)
				throw new Error("Incident storage accounting entry bound exceeded during reconciliation");
			if (!Number.isSafeInteger(reconciledBytes))
				throw new Error("Incident storage accounting reconciliation exceeds the safe byte range");
			this.storageInodes = discovered;
			this.storageEntries = entries;
			this.storageBytes = reconciledBytes;
			this.storageAccountingReadyState = true;
			this.segmentOpenRequiresReconciliation = false;
			const pressure = this.storagePressureReason(this.storageModeState === "recovery-only");
			if (pressure) this.enterStorageRecovery(pressure);
			else {
				this.storageModeState = "normal";
				this.storageRecoveryReasonState = undefined;
				this.pausedUntilMs = 0;
			}
		} catch (error) {
			if (!wasReady) this.storageAccountingReadyState = false;
			throw error;
		} finally {
			clearTimeout(deadline);
			if (killTimer) clearTimeout(killTimer);
			signal.removeEventListener("abort", onAbort);
			this.storageScanInProgress = false;
			this.storageScanConcurrentEntries = 0;
			this.storageScanConcurrentInodes.clear();
			this.storageScanSegmentMutation = false;
			this.activeCompactorChildren.delete(trackedChild);
		}
	}

	private accountStoragePath(path: string, entryCreated = true): number {
		return this.accountStorageMetadata(lstatSync(path), entryCreated);
	}

	private accountStorageMetadata(
		metadata: { dev: number | bigint; ino: number | bigint; size: number | bigint; blocks?: number | bigint },
		entryCreated = true,
	): number {
		const identity = `${String(metadata.dev)}:${String(metadata.ino)}`;
		const added = allocatedStorageBytes(metadata);
		if (entryCreated) {
			this.storageEntries += 1;
			if (this.storageScanInProgress) this.storageScanConcurrentEntries += 1;
		}
		if (this.storageScanInProgress) this.storageScanConcurrentInodes.set(identity, added);
		const previous = this.storageInodes.get(identity);
		if (previous !== undefined) {
			this.storageInodes.set(identity, added);
			this.storageBytes = Math.max(0, this.storageBytes - previous + added);
			return Math.max(0, added - previous);
		}
		const maximumInodes = positiveBound(this.options.storageAccountingMaxInodes, STORAGE_ACCOUNTING_MAX_INODES);
		if (this.storageInodes.size >= maximumInodes) {
			this.enterStorageRecovery("inode_hard_bound");
			const error = new Error("Incident storage accounting inode bound reached") as NodeJS.ErrnoException;
			error.code = "ENOSPC";
			throw error;
		}
		this.storageInodes.set(identity, added);
		this.storageBytes += added;
		return added;
	}

	private accountRemovedStorageEntry(
		metadata: { dev: number | bigint; ino: number | bigint; nlink: number | bigint },
		releaseOwnedInode = false,
	): void {
		const identity = `${String(metadata.dev)}:${String(metadata.ino)}`;
		this.storageEntries = Math.max(0, this.storageEntries - 1);
		if (this.storageScanInProgress) this.storageScanConcurrentEntries -= 1;
		if (releaseOwnedInode || Number(metadata.nlink) <= 1) {
			const previous = this.storageInodes.get(identity) ?? 0;
			this.storageInodes.delete(identity);
			this.storageBytes = Math.max(0, this.storageBytes - previous);
			if (this.storageScanInProgress) this.storageScanConcurrentInodes.set(identity, 0);
		}
	}

	private applyStorageAccountingEffects(effects: readonly StorageAccountingEffect[]): number {
		let addedBytes = 0;
		for (const effect of effects) {
			if (effect.kind === "account") {
				addedBytes += this.accountStorageMetadata(effect.metadata, effect.entryCreated);
			} else {
				this.accountRemovedStorageEntry(effect.metadata, effect.releaseOwnedInode);
			}
		}
		return addedBytes;
	}

	private planOwnedDirectoryCreation(
		root: IncidentCasRootMutation,
		targets: readonly (readonly string[])[],
	): string[][] {
		const missing = new Map<string, string[]>();
		for (const target of targets) {
			for (let length = 1; length <= target.length; length += 1) {
				const components = target.slice(0, length);
				const parentKey = components.slice(0, -1).join("/");
				if (parentKey.length > 0 && missing.has(parentKey)) {
					missing.set(components.join("/"), [...components]);
					continue;
				}
				const metadata = root.lstat(root.relative(...components));
				if (!metadata) {
					missing.set(components.join("/"), [...components]);
					continue;
				}
				if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
					throw new Error(`Incident owned path is not a stable directory: ${components.join("/")}`);
				}
			}
		}
		return [...missing.values()].sort(
			(left, right) => left.length - right.length || left.join("/").localeCompare(right.join("/")),
		);
	}

	private createPlannedOwnedDirectories(
		root: IncidentCasRootMutation,
		missing: readonly (readonly string[])[],
		effects: StorageAccountingEffect[],
	): void {
		for (const components of missing) {
			const path = root.relative(...components);
			const parent = root.relative(...components.slice(0, -1));
			root.mkdirPrivate(path);
			effects.push({ kind: "account", metadata: root.stat(path), entryCreated: true });
			effects.push({ kind: "account", metadata: root.stat(parent), entryCreated: false });
			root.fsyncDirectory(parent);
		}
	}

	private ensureOwnedDirectories(
		root: IncidentCasRootMutation,
		targets: readonly (readonly string[])[],
		effects: StorageAccountingEffect[],
	): void {
		const missing = this.planOwnedDirectoryCreation(root, targets);
		if (missing.length === 0) return;
		const blockSize = Math.max(4096, Number(root.statfs(root.relative()).bsize));
		const reservedBytes = missing.length * blockSize * 2;
		this.reserveStorage(reservedBytes, missing.length, missing.length);
		try {
			this.createPlannedOwnedDirectories(root, missing, effects);
		} finally {
			this.releaseReservedCapacity(reservedBytes, missing.length, missing.length);
		}
	}

	private verifyCasFile(
		root: IncidentCasRootMutation,
		path: IncidentCasRelativePath,
		digest: string,
		bytes: number,
	): BigIntStats {
		return root.withFile(path, { access: "read" }, (file) => {
			const before = file.stat();
			if (!before.isFile() || before.isSymbolicLink() || before.size !== BigInt(bytes)) {
				throw new Error("Existing CAS blob did not verify");
			}
			const hash = createHash("sha256");
			const buffer = Buffer.allocUnsafe(64 * 1024);
			let offset = 0;
			while (offset < bytes) {
				const count = file.read(buffer, 0, Math.min(buffer.length, bytes - offset), offset);
				if (count <= 0) throw new Error("Existing CAS blob ended before its declared length");
				hash.update(buffer.subarray(0, count));
				offset += count;
			}
			const after = file.stat();
			if (
				before.dev !== after.dev ||
				before.ino !== after.ino ||
				before.size !== after.size ||
				before.mtimeNs !== after.mtimeNs ||
				before.ctimeNs !== after.ctimeNs ||
				hash.digest("hex") !== digest
			) {
				throw new Error("Existing CAS blob did not verify");
			}
			return after;
		});
	}

	private publishCasAndRunLease(
		root: IncidentCasRootMutation,
		input: {
			runId: string;
			digest: string;
			bytes: number;
			value?: Buffer;
			stagedPath?: IncidentCasRelativePath;
			mtimeNs?: bigint;
		},
		effects: StorageAccountingEffect[],
	): { casPath: string; leasePath: string } {
		if (
			input.runId.length === 0 ||
			Buffer.byteLength(input.runId) > 255 ||
			!/^[0-9a-f]{64}$/.test(input.digest) ||
			!Number.isSafeInteger(input.bytes) ||
			input.bytes < 0 ||
			(input.value === undefined) === (input.stagedPath === undefined) ||
			(input.mtimeNs !== undefined &&
				(input.stagedPath === undefined ||
					typeof input.mtimeNs !== "bigint" ||
					input.mtimeNs < 0n ||
					input.mtimeNs / 1_000n > BigInt(Number.MAX_SAFE_INTEGER))) ||
			(input.value !== undefined && (input.value.length !== input.bytes || sha256(input.value) !== input.digest))
		) {
			throw new Error("CAS publication input was not canonical");
		}
		const casDirectoryComponents = ["cas", "sha256", input.digest.slice(0, 2)] as const;
		const leaseDirectoryComponents = ["refs", "runs", sha256(input.runId)] as const;
		const casDirectory = root.relative(...casDirectoryComponents);
		const cas = root.relative(...casDirectoryComponents, `${input.digest}.blob`);
		const leaseDirectory = root.relative(...leaseDirectoryComponents);
		const lease = root.relative(...leaseDirectoryComponents, `cas-${input.digest}.blob`);
		const temporary = input.value
			? root.relative(
					...casDirectoryComponents,
					`.${input.digest}.tmp-${process.pid}-${sha256(`${process.hrtime.bigint()}`)}`,
				)
			: input.stagedPath;
		if (!temporary) throw new Error("CAS publication temporary path was unavailable");
		const stagedMetadata =
			input.stagedPath === undefined
				? undefined
				: this.verifyCasFile(root, input.stagedPath, input.digest, input.bytes);
		const missingDirectories = this.planOwnedDirectoryCreation(root, [
			casDirectoryComponents,
			leaseDirectoryComponents,
		]);
		const missingDirectoryKeys = new Set(missingDirectories.map((components) => components.join("/")));
		let casExists = !missingDirectoryKeys.has(casDirectoryComponents.join("/")) && root.lstat(cas) !== undefined;
		if (casExists) this.verifyCasFile(root, cas, input.digest, input.bytes);
		let leaseExists =
			!missingDirectoryKeys.has(leaseDirectoryComponents.join("/")) && root.lstat(lease) !== undefined;
		if (leaseExists) {
			const leaseMetadata = root.lstat(lease);
			if (!leaseMetadata?.isFile() || leaseMetadata.isSymbolicLink()) {
				throw new Error("Existing CAS run lease was invalid");
			}
		}
		if (leaseExists && !casExists) throw new Error("CAS run lease existed without its canonical blob");
		const blockSize = Math.max(4096, Number(root.statfs(root.relative()).bsize));
		const createTemporary = !casExists && input.value !== undefined;
		const createCasEntry = !casExists;
		const createLeaseEntry = !leaseExists;
		const reservedEntries =
			missingDirectories.length + (createTemporary ? 1 : 0) + (createCasEntry ? 1 : 0) + (createLeaseEntry ? 1 : 0);
		const reservedInodes = missingDirectories.length + (createTemporary ? 1 : 0);
		const fileBytes = createTemporary ? Math.ceil(input.bytes / blockSize) * blockSize : 0;
		const mutationCount =
			missingDirectories.length + (createTemporary ? 1 : 0) + (createCasEntry ? 1 : 0) + (createLeaseEntry ? 1 : 0);
		const reservedBytes = fileBytes + (mutationCount + missingDirectories.length) * blockSize;
		this.reserveStorage(reservedBytes, reservedEntries, reservedInodes);
		let temporaryCreated = false;
		let casCreated = false;
		try {
			this.createPlannedOwnedDirectories(root, missingDirectories, effects);
			if (!casExists && input.value) {
				root.writeFileExclusive(temporary, input.value, 0o600);
				temporaryCreated = true;
				effects.push({ kind: "account", metadata: root.stat(temporary), entryCreated: true });
				effects.push({ kind: "account", metadata: root.stat(casDirectory), entryCreated: false });
				root.fsyncDirectory(casDirectory);
			}
			if (!casExists) {
				root.hardLink(temporary, cas);
				casCreated = true;
				effects.push({ kind: "account", metadata: root.stat(cas), entryCreated: true });
				effects.push({ kind: "account", metadata: root.stat(casDirectory), entryCreated: false });
				root.fsyncDirectory(casDirectory);
				casExists = true;
			}
			const casMetadata = this.verifyCasFile(root, cas, input.digest, input.bytes);
			if (
				input.mtimeNs !== undefined &&
				stagedMetadata?.dev === casMetadata.dev &&
				stagedMetadata.ino === casMetadata.ino
			) {
				// Center the microsecond tick so floating-point conversion cannot
				// round a previously captured microsecond down by one on replay.
				const timestamp = (Number(input.mtimeNs / 1_000n) + 0.5) / 1_000_000;
				try {
					root.utimes(cas, timestamp, timestamp);
				} catch (error) {
					// Only undo this attempt's new link. A pre-existing shared blob or
					// durable crash residue belongs to its existing reference graph.
					const current = root.lstat(cas);
					if (casCreated && current?.dev === casMetadata.dev && current.ino === casMetadata.ino) {
						root.unlinkFile(cas);
						effects.push({ kind: "remove", metadata: current, releaseOwnedInode: false });
						effects.push({ kind: "account", metadata: root.stat(casDirectory), entryCreated: false });
						root.fsyncDirectory(casDirectory);
					}
					throw error;
				}
			}
			if (temporaryCreated) {
				const temporaryMetadata = root.stat(temporary);
				root.unlinkFile(temporary);
				effects.push({ kind: "remove", metadata: temporaryMetadata, releaseOwnedInode: false });
				temporaryCreated = false;
				effects.push({ kind: "account", metadata: root.stat(casDirectory), entryCreated: false });
				root.fsyncDirectory(casDirectory);
			}
			root.fsyncFile(cas);
			this.options.onCasPublicationStep?.("cas_durable");
			if (!leaseExists) {
				root.hardLink(cas, lease);
				effects.push({ kind: "account", metadata: root.stat(lease), entryCreated: true });
				effects.push({ kind: "account", metadata: root.stat(leaseDirectory), entryCreated: false });
				root.fsyncDirectory(leaseDirectory);
				leaseExists = true;
			}
			this.options.onCasPublicationStep?.("lease_durable");
			const leaseMetadata = root.stat(lease);
			if (
				!leaseMetadata.isFile() ||
				leaseMetadata.isSymbolicLink() ||
				leaseMetadata.dev !== casMetadata.dev ||
				leaseMetadata.ino !== casMetadata.ino ||
				leaseMetadata.size !== BigInt(input.bytes) ||
				leaseMetadata.nlink < 2n
			) {
				throw new Error("CAS run lease did not resolve to the durable blob");
			}
			return { casPath: root.publicPath(cas), leasePath: root.publicPath(lease) };
		} finally {
			if (temporaryCreated) {
				try {
					const metadata = root.stat(temporary);
					root.unlinkFile(temporary);
					effects.push({ kind: "remove", metadata, releaseOwnedInode: false });
					effects.push({ kind: "account", metadata: root.stat(casDirectory), entryCreated: false });
					root.fsyncDirectory(casDirectory);
				} catch {}
			}
			this.releaseReservedCapacity(reservedBytes, reservedEntries, reservedInodes);
		}
	}

	private setSegmentAccountedInode(
		deviceId: string,
		inodeId: string,
		logicalBytes: number,
		allocatedBytes: number,
		removed = false,
	): void {
		if (
			!/^\d+$/.test(deviceId) ||
			!/^\d+$/.test(inodeId) ||
			!Number.isSafeInteger(logicalBytes) ||
			logicalBytes < 0 ||
			!Number.isSafeInteger(allocatedBytes) ||
			allocatedBytes < 0
		) {
			throw new Error("Incident segment storage receipt is malformed");
		}
		const identity = `${deviceId}:${inodeId}`;
		const previous = this.storageInodes.get(identity) ?? 0;
		if (removed) {
			this.storageInodes.delete(identity);
			this.storageBytes = Math.max(0, this.storageBytes - previous);
			return;
		}
		const contribution = Math.max(logicalBytes, allocatedBytes);
		if (!this.storageInodes.has(identity)) {
			const maximumInodes = positiveBound(this.options.storageAccountingMaxInodes, STORAGE_ACCOUNTING_MAX_INODES);
			if (this.storageInodes.size >= maximumInodes) {
				const error = new Error("Incident segment storage accounting inode bound reached") as NodeJS.ErrnoException;
				error.code = "ENOSPC";
				throw error;
			}
		}
		this.storageInodes.set(identity, contribution);
		this.storageBytes = Math.max(0, this.storageBytes - previous + contribution);
		if (this.storageScanInProgress) this.storageScanConcurrentInodes.set(identity, contribution);
	}

	private applySegmentParentEffect(effect: IncidentRecorderSegmentParentDirectoryEffect): void {
		this.setSegmentAccountedInode(
			effect.deviceId,
			effect.inodeId,
			effect.afterLogicalBytes,
			effect.afterAllocatedBytes,
		);
	}

	private accountSegmentDurableWrite(event: IncidentRecorderSegmentDurableWrite): void {
		if (this.storageScanInProgress) this.storageScanSegmentMutation = true;
		const separator = event.eventId.lastIndexOf(":");
		const instanceId = event.eventId.slice(0, separator);
		const sequence = Number(event.eventId.slice(separator + 1));
		if (
			separator <= 0 ||
			!instanceId ||
			!Number.isSafeInteger(sequence) ||
			sequence <= 0 ||
			sequence !== event.accountingSequence
		) {
			throw new Error("Incident segment durable receipt identity is malformed");
		}
		const previousSequence = this.segmentAccountingSequences.get(instanceId);
		if (previousSequence !== undefined && sequence <= previousSequence) return;
		if (previousSequence !== undefined && sequence !== previousSequence + 1) {
			throw new Error("Incident segment durable receipt sequence has a gap");
		}
		if (previousSequence === undefined && sequence !== 1) {
			throw new Error("Incident segment durable receipt sequence did not start at one");
		}
		this.segmentAccountingSequences.set(instanceId, sequence);
		while (this.segmentAccountingSequences.size > 16) {
			const oldest = this.segmentAccountingSequences.keys().next().value as string | undefined;
			if (!oldest) break;
			this.segmentAccountingSequences.delete(oldest);
		}
		this.storageEntries = Math.max(0, this.storageEntries + event.entryDelta);
		if (this.storageScanInProgress) this.storageScanConcurrentEntries += event.entryDelta;
		this.setSegmentAccountedInode(
			event.deviceId,
			event.inodeId,
			event.logicalBytes,
			event.allocatedBytes,
			event.entryChange === "removed" && event.linkCount === 0,
		);
		for (const parentEffect of event.parentEffects) this.applySegmentParentEffect(parentEffect);
	}

	private accountSegmentOpenResult(result: IncidentRecorderSegmentOpenResult): void {
		if (this.storageScanInProgress) this.storageScanSegmentMutation = true;
		const current = new Map(result.entries.map((entry) => [entry.path, entry]));
		for (const [path, previous] of this.segmentOpenStorageEntries) {
			if (current.has(path)) continue;
			this.storageEntries = Math.max(0, this.storageEntries - 1);
			if (this.storageScanInProgress) this.storageScanConcurrentEntries -= 1;
			this.setSegmentAccountedInode(previous.deviceId, previous.inodeId, 0, 0, previous.linkCount <= 1);
		}
		for (const entry of result.entries) {
			const previous = this.segmentOpenStorageEntries.get(entry.path);
			if (!previous && entry.createdByOpen) {
				this.storageEntries += 1;
				if (this.storageScanInProgress) this.storageScanConcurrentEntries += 1;
			}
			if (previous && (previous.deviceId !== entry.deviceId || previous.inodeId !== entry.inodeId)) {
				this.setSegmentAccountedInode(previous.deviceId, previous.inodeId, 0, 0, previous.linkCount <= 1);
			}
			this.setSegmentAccountedInode(entry.deviceId, entry.inodeId, entry.logicalBytes, entry.allocatedBytes);
		}
		for (const parentEffect of result.parentEffects) this.applySegmentParentEffect(parentEffect);
		this.segmentOpenStorageEntries.clear();
		for (const entry of result.entries) this.segmentOpenStorageEntries.set(entry.path, entry);
		if (!result.complete || result.reconciliation === "full-dev-inode-required") {
			this.segmentOpenRequiresReconciliation = true;
		}
	}

	private enterStorageRecovery(reason: string): void {
		this.storageModeState = "recovery-only";
		this.storageRecoveryReasonState = reason;
		try {
			this.closeSegmentStore();
		} catch {
			this.segmentOpenRequiresReconciliation = true;
			this.storageRecoveryReasonState = "segment_store_close_failed";
		}
		this.discardRunHistoryTraversals();
		this.discardStoppedTargetStreams();
	}

	private storagePressureReason(
		useLowWater: boolean,
		observedBytes = this.storageBytes,
		observedInodes = this.storageInodes.size,
		observedEntries = this.storageEntries,
	): string | undefined {
		const ceiling = positiveBound(this.options.storageByteCeiling, STORAGE_BYTE_CEILING);
		const maximumInodes = positiveBound(this.options.storageAccountingMaxInodes, STORAGE_ACCOUNTING_MAX_INODES);
		const maximumEntries = positiveBound(this.options.storageAccountingMaxEntries, STORAGE_ACCOUNTING_MAX_ENTRIES);
		const bytes = Math.min(
			ceiling,
			positiveBound(
				useLowWater ? this.options.storageLowWaterBytes : this.options.storageHighWaterBytes,
				useLowWater ? STORAGE_LOW_WATER_BYTES : STORAGE_HIGH_WATER_BYTES,
			),
		);
		const inodes = Math.min(
			maximumInodes,
			positiveBound(
				useLowWater ? this.options.storageLowWaterInodes : this.options.storageHighWaterInodes,
				useLowWater ? STORAGE_LOW_WATER_INODES : STORAGE_HIGH_WATER_INODES,
			),
		);
		const entries = Math.min(
			maximumEntries,
			positiveBound(
				useLowWater ? this.options.storageLowWaterEntries : this.options.storageHighWaterEntries,
				useLowWater ? STORAGE_LOW_WATER_ENTRIES : STORAGE_HIGH_WATER_ENTRIES,
			),
		);
		if (observedBytes >= bytes) return "byte_high_water";
		if (observedInodes >= inodes) return "inode_high_water";
		if (observedEntries >= entries) return "entry_high_water";
		return undefined;
	}

	private ensureDiskAdmission(worstCase: number, worstCaseEntries = 1, worstCaseInodes = 1): void {
		if (!Number.isSafeInteger(worstCase) || worstCase < 0)
			throw new Error("Invalid incident compactor disk reservation");
		if (!Number.isSafeInteger(worstCaseEntries) || worstCaseEntries < 0)
			throw new Error("Invalid incident compactor entry reservation");
		if (!Number.isSafeInteger(worstCaseInodes) || worstCaseInodes < 0)
			throw new Error("Invalid incident compactor inode reservation");
		if (!this.storageAccountingReadyState) {
			const error = new Error("Incident compactor storage accounting is not ready") as NodeJS.ErrnoException;
			error.code = "ENOSPC";
			throw error;
		}
		if (this.storageModeState !== "normal") {
			const error = new Error("Incident compactor remains in storage recovery-only mode") as NodeJS.ErrnoException;
			error.code = "ENOSPC";
			throw error;
		}
		if (Date.now() < this.pausedUntilMs) {
			const error = new Error("Incident compactor remains paused by disk admission policy") as NodeJS.ErrnoException;
			error.code = "ENOSPC";
			throw error;
		}
		const ceiling = this.options.storageByteCeiling ?? STORAGE_BYTE_CEILING;
		const reserve = this.options.freeReserveBytes ?? STORAGE_FREE_RESERVE_BYTES;
		const statPath = existsSync(this.root) ? this.root : this.options.agentDir;
		const filesystem = statfsSync(statPath);
		const available = Number(filesystem.bavail) * Number(filesystem.bsize);
		const projectedBytes = this.storageBytes + this.storageReservedBytes + worstCase;
		const projectedInodes = this.storageInodes.size + this.storageReservedInodes + worstCaseInodes;
		const projectedEntries = this.storageEntries + this.storageReservedEntries + worstCaseEntries;
		const pressure = this.storagePressureReason(false, projectedBytes, projectedInodes, projectedEntries);
		if (pressure) this.enterStorageRecovery(pressure);
		if (pressure || available - worstCase < reserve || projectedBytes > ceiling) {
			this.pausedUntilMs = Date.now() + 30_000;
			const error = new Error("Incident compactor paused by disk admission policy") as NodeJS.ErrnoException;
			error.code = "ENOSPC";
			throw error;
		}
	}

	private reserveStorage(bytes: number, entries: number, inodes: number): void {
		this.ensureDiskAdmission(bytes, entries, inodes);
		this.storageReservedBytes += bytes;
		this.storageReservedEntries += entries;
		this.storageReservedInodes += inodes;
	}

	private consumeStorageReservation(
		state: StoppedTargetArtifactStream,
		bytes: number,
		entries: number,
		inodes: number,
	): void {
		const consumedBytes = Math.min(state.reservedBytes, Math.max(0, bytes));
		const consumedEntries = Math.min(state.reservedEntries, Math.max(0, entries));
		const consumedInodes = Math.min(state.reservedInodes, Math.max(0, inodes));
		state.reservedBytes -= consumedBytes;
		state.reservedEntries -= consumedEntries;
		state.reservedInodes -= consumedInodes;
		this.storageReservedBytes = Math.max(0, this.storageReservedBytes - consumedBytes);
		this.storageReservedEntries = Math.max(0, this.storageReservedEntries - consumedEntries);
		this.storageReservedInodes = Math.max(0, this.storageReservedInodes - consumedInodes);
	}

	private releaseStorageReservation(state: StoppedTargetArtifactStream): void {
		if (state.reservationReleased) return;
		state.reservationReleased = true;
		this.consumeStorageReservation(state, state.reservedBytes, state.reservedEntries, state.reservedInodes);
	}

	private releaseReservedCapacity(bytes: number, entries: number, inodes: number): void {
		this.storageReservedBytes = Math.max(0, this.storageReservedBytes - bytes);
		this.storageReservedEntries = Math.max(0, this.storageReservedEntries - entries);
		this.storageReservedInodes = Math.max(0, this.storageReservedInodes - inodes);
	}

	private segmentDirectory(): string {
		return join(this.root, "segments");
	}

	private closeSegmentStore(): void {
		if (this.segmentStoreCloseUncertain) throw this.segmentStoreCloseFailure;
		this.closePendingPinDirectoryTraversal();
		if (this.segmentRootCallbackDepth > 0) {
			// Storage admission may discover pressure while a root callback is
			// still active. Defer the close request rather than opening a nested
			// lifecycle/root lease; the admission path will fail and the enclosing
			// mutation will discard the store.
			return;
		}
		const store = this.segmentStore;
		if (!store) return;
		this.discardRunHistoryTraversals();
		if (store.isRootBacked) {
			let receipts: readonly IncidentRecorderSegmentRootReceipt[] = [];
			let mutation: RecorderRootMutationResult<boolean>;
			try {
				mutation = this.withRecorderRoot((root) => {
					const result = store.closeWithinRoot(root);
					receipts = result;
					return true;
				});
			} catch (error) {
				this.discardSegmentStoreAfterRootFailure("close_operation_failed");
				this.releaseSegmentRootReservations();
				this.segmentStoreCloseFailure = error;
				this.segmentStoreCloseUncertain = true;
				throw error;
			}
			if (mutation.state !== "committed") {
				this.discardSegmentStoreAfterRootFailure(mutation.reason);
				this.releaseSegmentRootReservations();
				this.segmentStoreCloseFailure = this.writerLifecycleAdmissionError(mutation.reason);
				this.segmentStoreCloseUncertain = true;
				throw this.segmentStoreCloseFailure;
			}
			try {
				this.applySegmentRootReceipts(receipts);
				this.assertSegmentAccountingReadyAfterRootReceipt();
			} catch (error) {
				this.discardSegmentStoreAfterRootFailure("close_receipt_application_failed");
				this.releaseSegmentRootReservations();
				this.segmentOpenRequiresReconciliation = true;
				this.segmentStoreCloseFailure = error;
				this.segmentStoreCloseUncertain = true;
				throw error;
			}
			this.releaseSegmentRootReservations();
			this.segmentStore = undefined;
			return;
		}
		try {
			store.close();
		} catch (error) {
			this.segmentOpenRequiresReconciliation = true;
			this.segmentStoreCloseFailure = error;
			this.segmentStoreCloseUncertain = true;
			throw error;
		}
		this.segmentStore = undefined;
	}

	private existingSegmentStore(): IncidentRecorderSegmentStore {
		if (!this.segmentStore) throw new Error("Incident segment store is not open in the current root scope");
		return this.segmentStore;
	}

	private appendSegmentRecord(input: IncidentRecorderSegmentAppendInput): IncidentRecorderSegmentLocator {
		let receipts: readonly IncidentRecorderSegmentRootReceipt[] = [];
		try {
			const mutation = this.withRecorderRoot((root) => {
				const locator = this.appendSegmentRecordWithinRoot(root, input, (estimate) => {
					this.reserveStorage(
						estimate.peakAdditionalAllocatedBytes,
						estimate.peakAdditionalEntries,
						estimate.peakAdditionalInodes,
					);
					this.segmentRootAppendReservation = {
						bytes: estimate.peakAdditionalAllocatedBytes,
						entries: estimate.peakAdditionalEntries,
						inodes: estimate.peakAdditionalInodes,
					};
				});
				if (this.segmentStore) receipts = this.segmentStore.drainWithinRootReceipts();
				return locator;
			});
			if (mutation.state !== "committed") {
				this.discardSegmentStoreAfterRootFailure(mutation.reason);
				throw this.writerLifecycleAdmissionError(mutation.reason);
			}
			this.applySegmentRootReceipts(receipts);
			this.assertSegmentAccountingReadyAfterRootReceipt();
			return mutation.value;
		} catch (error) {
			if (this.segmentStore?.isRootBacked && !this.isIdempotencyConflict(error))
				this.discardSegmentStoreAfterRootFailure("operation_failed");
			if ((error as NodeJS.ErrnoException).code === "ENOSPC") throw error;
			const wrapped = new Error(
				`Incident segment persistence failed: ${error instanceof Error ? error.message : String(error)}`,
				{ cause: error },
			);
			wrapped.name = "IncidentSegmentPersistenceError";
			throw wrapped;
		} finally {
			this.releaseSegmentRootReservations();
			const pressure = this.storagePressureReason(false);
			if (pressure && this.storageModeState === "normal") this.enterStorageRecovery(pressure);
		}
	}

	private ensureSegmentStoreWithinRoot(root: IncidentCasRootMutation): IncidentRecorderSegmentStore {
		if (this.segmentStore) {
			if (!this.segmentStore.isRootBacked) {
				throw new Error("raw incident segment store cannot be reused for root-backed mutation");
			}
			return this.segmentStore;
		}
		if (!this.storageAccountingReadyState || this.storageModeState !== "normal") {
			const error = new Error(
				"Incident segment store cannot open outside normal storage mode",
			) as NodeJS.ErrnoException;
			error.code = "ENOSPC";
			throw error;
		}
		this.segmentOpenRequiresReconciliation = false;
		const openEstimate = estimateIncidentRecorderSegmentStoreOpenWithinRoot(root, ["segments"]);
		let reservationHeld = false;
		try {
			this.reserveStorage(
				openEstimate.peakAdditionalBytes,
				openEstimate.peakAdditionalEntries,
				openEstimate.peakAdditionalInodes,
			);
			reservationHeld = true;
			this.segmentRootOpenReservation = {
				bytes: openEstimate.peakAdditionalBytes,
				entries: openEstimate.peakAdditionalEntries,
				inodes: openEstimate.peakAdditionalInodes,
			};
			const store = IncidentRecorderSegmentStore.openWithinRoot(root, {
				directory: ["segments"],
			});
			this.segmentStore = store;
			return store;
		} catch (error) {
			if (reservationHeld)
				this.releaseReservedCapacity(
					openEstimate.peakAdditionalBytes,
					openEstimate.peakAdditionalEntries,
					openEstimate.peakAdditionalInodes,
				);
			this.segmentRootOpenReservation = undefined;
			this.discardSegmentStoreAfterRootFailure("open_failed");
			throw error;
		}
	}

	private appendSegmentRecordWithinRoot(
		root: IncidentCasRootMutation,
		input: IncidentRecorderSegmentAppendInput,
		admit?: (estimate: IncidentRecorderSegmentAppendStorageEstimate) => void,
	): IncidentRecorderSegmentLocator {
		const store = this.ensureSegmentStoreWithinRoot(root);
		try {
			return store.appendWithinRoot(root, input, admit).locator;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOSPC") throw error;
			const wrapped = new Error(
				`Incident segment persistence failed: ${error instanceof Error ? error.message : String(error)}`,
				{ cause: error },
			);
			wrapped.name = "IncidentSegmentPersistenceError";
			throw wrapped;
		}
	}

	private withSegmentStoreRoot<T>(
		operation: (root: IncidentCasRootMutation, store: IncidentRecorderSegmentStore) => T,
	): T {
		let store: IncidentRecorderSegmentStore | undefined;
		let receipts: readonly IncidentRecorderSegmentRootReceipt[] = [];
		try {
			const mutation = this.withRecorderRoot((root) => {
				store = this.ensureSegmentStoreWithinRoot(root);
				const value = operation(root, store);
				receipts = store.drainWithinRootReceipts();
				return value;
			});
			if (mutation.state !== "committed") {
				this.discardSegmentStoreAfterRootFailure(mutation.reason);
				throw this.writerLifecycleAdmissionError(mutation.reason);
			}
			try {
				this.applySegmentRootReceipts(receipts);
				this.assertSegmentAccountingReadyAfterRootReceipt();
			} catch (error) {
				this.discardSegmentStoreAfterRootFailure("receipt_application_failed");
				throw error;
			}
			return mutation.value;
		} catch (error) {
			if (store?.isRootBacked) this.discardSegmentStoreAfterRootFailure("operation_failed");
			throw error;
		} finally {
			this.releaseSegmentRootReservations();
		}
	}

	private applySegmentRootReceipts(receipts: readonly IncidentRecorderSegmentRootReceipt[]): void {
		for (const receipt of receipts) {
			if (receipt.kind === "open") this.accountSegmentOpenResult(receipt.result);
			else this.accountSegmentDurableWrite(receipt.event);
		}
	}

	private assertSegmentAccountingReadyAfterRootReceipt(): void {
		if (!this.segmentOpenRequiresReconciliation) return;
		this.invalidateStorageAccounting();
		this.storageModeState = "recovery-only";
		this.storageRecoveryReasonState = "segment_open_reconciliation_required";
		const error = new Error("Incident segment open requires a full storage reconciliation") as NodeJS.ErrnoException;
		error.code = "ENOSPC";
		throw error;
	}

	private discardSegmentStoreAfterRootFailure(reason: string): void {
		this.segmentStore = undefined;
		this.segmentOpenRequiresReconciliation = true;
		this.invalidateStorageAccounting();
		this.storageModeState = "recovery-only";
		this.storageRecoveryReasonState = `segment_root_mutation_${reason}`;
	}

	private releaseSegmentRootReservations(): void {
		if (this.segmentRootOpenReservation) {
			this.releaseReservedCapacity(
				this.segmentRootOpenReservation.bytes,
				this.segmentRootOpenReservation.entries,
				this.segmentRootOpenReservation.inodes,
			);
			this.segmentRootOpenReservation = undefined;
		}
		if (this.segmentRootAppendReservation) {
			this.releaseReservedCapacity(
				this.segmentRootAppendReservation.bytes,
				this.segmentRootAppendReservation.entries,
				this.segmentRootAppendReservation.inodes,
			);
			this.segmentRootAppendReservation = undefined;
		}
	}

	private isSegmentPersistenceError(error: unknown): boolean {
		return error instanceof Error && error.name === "IncidentSegmentPersistenceError";
	}

	private isIdempotencyConflict(error: unknown): boolean {
		return error instanceof Error && error.message.includes("different canonical content");
	}

	private isWriterLifecycleAdmissionError(error: unknown): boolean {
		return error instanceof Error && error.name === "IncidentRecorderWriterLifecycleAdmissionError";
	}

	private isStoppedTargetReconciliationError(error: unknown): boolean {
		return (
			error instanceof Error &&
			(error.message === "artifact_staging_identity_changed_during_capture" ||
				error.message === "artifact_staging_changed_during_capture")
		);
	}

	private isStoppedTargetPublicationStructuralError(error: unknown): boolean {
		if (!(error instanceof Error)) return false;
		if (
			[
				"CAS publication input was not canonical",
				"CAS publication temporary path was unavailable",
				"Existing CAS blob did not verify",
				"Existing CAS blob ended before its declared length",
				"Existing CAS run lease was invalid",
				"CAS run lease existed without its canonical blob",
				"CAS run lease did not resolve to the durable blob",
				"CAS hard-link identity changed during publication",
			].includes(error.message)
		)
			return true;
		if (/^CAS capability filesystem operation failed \((?:EEXIST|EISDIR|ELOOP|ENOTDIR)\)$/.test(error.message))
			return true;
		const code = (error as NodeJS.ErrnoException).code;
		return code === "EEXIST" || code === "EISDIR" || code === "ELOOP" || code === "ENOTDIR";
	}

	private segmentReference(locator: IncidentRecorderSegmentLocator): string {
		return `segment:v1:${Buffer.from(JSON.stringify(locator), "utf8").toString("base64url")}`;
	}

	private segmentOccurrenceReference(locator: IncidentRecorderSegmentLocator): SegmentOccurrenceReference {
		return { kind: "segment", locator: { ...locator } };
	}

	private writeOwnedJson(path: string, value: unknown, extraWorstCase = 256 * 1024): void {
		const encoded = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
		this.ensureDiskAdmission(encoded.length + extraWorstCase);
		const existed = existsSync(path);
		writeImmutable(path, encoded);
		if (!existed) this.accountStoragePath(path);
	}

	private writeOwnedCheckpoint(path: string, value: CursorCheckpoint): void {
		if (path !== this.checkpointPath) throw new Error("Unknown recorder checkpoint path");
		this.writeRecorderCursor("compactor-cursor.json", value);
	}

	private writeRecorderCursor(
		name: "compactor-cursor.json" | "pending-pin-directory-cursor.json",
		value: unknown,
	): void {
		const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
		this.ensureDiskAdmission(bytes.length * 2 + 256 * 1024);
		let changed = false;
		try {
			const mutation = this.withRecorderRoot((root) => {
				const path = root.relative(name);
				// One fixed scratch slot makes repeated interrupted replacement bounded.
				const next = root.relative(`.${name}.next`);
				const previous = root.lstat(path);
				const scratch = root.lstat(next);
				for (const entry of [previous, scratch]) {
					if (
						entry &&
						(!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1n || (entry.mode & 0o777n) !== 0o600n)
					)
						throw new Error("Recorder cursor is not a private regular file");
				}
				changed = true;
				root.withFile(
					next,
					{ access: "write", ...(scratch ? {} : { create: "exclusive" as const }), mode: 0o600 },
					(file) => {
						const held = file.stat();
						if (scratch && (held.dev !== scratch.dev || held.ino !== scratch.ino))
							throw new Error("Recorder cursor scratch changed");
						file.truncate(0);
						let offset = 0;
						while (offset < bytes.length) {
							const count = file.write(bytes, offset, bytes.length - offset, offset);
							if (count <= 0) throw new Error("Recorder cursor write made no progress");
							offset += count;
						}
						file.sync();
					},
				);
				root.rename(next, path);
				root.fsyncDirectory(root.relative());
				const effects: StorageAccountingEffect[] = [];
				if (previous) effects.push({ kind: "remove", metadata: previous, releaseOwnedInode: true });
				if (scratch) effects.push({ kind: "remove", metadata: scratch, releaseOwnedInode: true });
				effects.push({ kind: "account", metadata: root.stat(path), entryCreated: true });
				effects.push({ kind: "account", metadata: root.stat(root.relative()), entryCreated: false });
				return effects;
			});
			if (mutation.state !== "committed") throw this.writerLifecycleAdmissionError(mutation.reason);
			this.applyStorageAccountingEffects(mutation.value);
		} catch (error) {
			if (changed) this.invalidateStorageAccounting();
			throw error;
		}
	}

	private pendingPinDirectoryDiscoveryEntriesPerPass(): number {
		return Math.min(
			positiveBound(
				this.options.pendingPinDirectoryDiscoveryEntriesPerPass,
				PENDING_PIN_DIRECTORY_DISCOVERY_ENTRIES,
			),
			PENDING_PIN_DIRECTORY_DISCOVERY_ENTRIES,
		);
	}

	private pendingPinDirectoryBatchCount(): number {
		return Math.min(
			positiveBound(this.options.pendingPinDirectoryBatchCount, PENDING_PIN_DIRECTORY_BATCH_COUNT),
			PENDING_PIN_DIRECTORY_BATCH_COUNT,
		);
	}

	private closePendingPinDirectoryTraversal(): void {
		const state = this.pendingPinDirectoryTraversal;
		if (!state) return;
		const directory = state.directory;
		if (directory) directory.closeSync();
		state.directory = undefined;
		state.pendingNames.length = 0;
		state.pendingNameBytes = 0;
		this.pendingPinDirectoryTraversal = undefined;
	}

	private discardPendingPinDirectoryTraversal(): void {
		try {
			this.closePendingPinDirectoryTraversal();
		} catch {}
	}

	private completePendingPinDirectoryNames(afterName: string | undefined): void {
		const state = this.pendingPinDirectoryTraversal;
		if (!state || afterName === undefined) return;
		const index = state.pendingNames.indexOf(afterName);
		if (index < 0) return;
		for (let offset = 0; offset <= index; offset += 1) {
			state.pendingNameBytes -= Buffer.byteLength(state.pendingNames[offset] ?? "");
		}
		state.pendingNames.splice(0, index + 1);
		state.pendingNameBytes = Math.max(0, state.pendingNameBytes);
		if (state.sweepComplete && state.pendingNames.length === 0) {
			this.pendingPinDirectoryTraversal = undefined;
		}
	}

	private beginPendingPinDirectoryTraversal(incidentRoot: string): PendingPinDirectoryTraversal | undefined {
		try {
			const boundary = this.pendingPinCursor;
			const state: PendingPinDirectoryTraversal = {
				incidentRoot,
				...(boundary === undefined ? {} : { boundary }),
				phase: boundary === undefined ? "full" : "after-cursor",
				directory: opendirSync(incidentRoot),
				pendingNames: [],
				pendingNameBytes: 0,
				sawEntry: false,
				sweepComplete: false,
			};
			this.pendingPinDirectoryTraversal = state;
			return state;
		} catch {
			return undefined;
		}
	}

	private discoverPendingPinDirectoryNames(incidentRoot: string): string[] {
		let state = this.pendingPinDirectoryTraversal;
		if (state && state.incidentRoot !== incidentRoot) {
			this.discardPendingPinDirectoryTraversal();
			state = undefined;
		}
		state ??= this.beginPendingPinDirectoryTraversal(incidentRoot);
		if (!state) return [];
		const discoveryLimit = this.pendingPinDirectoryDiscoveryEntriesPerPass();
		const batchLimit = this.pendingPinDirectoryBatchCount();
		if (state.pendingNames.length > 0) return state.pendingNames.slice(0, batchLimit);
		while (
			this.pendingPinDirectoryEntriesReadLastPass < discoveryLimit &&
			state.pendingNames.length < discoveryLimit &&
			!state.sweepComplete
		) {
			let directory = state.directory;
			if (!directory) {
				try {
					directory = opendirSync(incidentRoot);
					state.directory = directory;
				} catch {
					this.discardPendingPinDirectoryTraversal();
					return [];
				}
			}
			let entry: Dirent | null;
			try {
				entry = directory.readSync();
			} catch {
				this.discardPendingPinDirectoryTraversal();
				return [];
			}
			if (entry === null) {
				try {
					directory.closeSync();
				} catch {
					this.discardPendingPinDirectoryTraversal();
					return [];
				}
				state.directory = undefined;
				if (state.phase === "after-cursor") {
					state.phase = "through-cursor";
					if (state.pendingNames.length > 0) break;
					continue;
				}
				state.sweepComplete = true;
				break;
			}
			this.pendingPinDirectoryEntriesReadLastPass += 1;
			state.sawEntry = true;
			const name = entry.name;
			const nameBytes = Buffer.byteLength(name);
			if (nameBytes > PENDING_PIN_DIRECTORY_NAME_MAX_BYTES) continue;
			const eligible =
				state.phase === "full" ||
				(state.phase === "after-cursor" && name > (state.boundary ?? "")) ||
				(state.phase === "through-cursor" && name <= (state.boundary ?? ""));
			if (!eligible) continue;
			state.pendingNames.push(name);
			state.pendingNameBytes += nameBytes;
		}
		state.pendingNames.sort();
		if (state.sweepComplete && state.pendingNames.length === 0) {
			const rootWasEmpty = !state.sawEntry;
			this.pendingPinDirectoryTraversal = undefined;
			if (rootWasEmpty) this.persistPendingPinCursor(undefined);
			return [];
		}
		return state.pendingNames.slice(0, batchLimit);
	}

	private persistPendingPinCursor(afterName: string | undefined): void {
		if (this.pendingPinCursor === afterName) {
			this.completePendingPinDirectoryNames(afterName);
			return;
		}
		const value = { version: 1, afterName: afterName ?? null };
		this.writeRecorderCursor("pending-pin-directory-cursor.json", value);
		this.pendingPinCursor = afterName;
		this.completePendingPinDirectoryNames(afterName);
	}

	get diskPaused(): boolean {
		return !this.storageAccountingReadyState || this.storageModeState !== "normal" || Date.now() < this.pausedUntilMs;
	}
	get accountedStorageBytes(): number {
		return this.storageBytes;
	}

	admitObservation(worstCaseBytes = 256 * 1024): boolean {
		if (this.diskPaused) return false;
		try {
			this.ensureDiskAdmission(worstCaseBytes);
			return true;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOSPC") return false;
			throw error;
		}
	}

	pruneSegmentHistory(
		nowMs: number,
		protection: IncidentRecorderSegmentPruneProtectionComplete,
		continuation?: IncidentRecorderSegmentPruneCursor,
	): IncidentRecorderSegmentPruneResult {
		if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("Invalid segment prune time");
		void protection;
		void continuation;
		throw new Error("normal segment pruning is unavailable through root-backed storage");
	}

	pruneSegmentHistoryForRecovery(options: {
		externalWriterExcluded: true;
		protection: IncidentRecorderSegmentPruneProtectionComplete;
		nowMs?: number;
	}): IncidentRecorderSegmentPruneResult {
		if (options.externalWriterExcluded !== true) {
			throw new Error("Segment recovery pruning requires external writer-start exclusion");
		}
		const nowMs = options.nowMs ?? Date.now();
		if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("Invalid segment recovery prune time");
		if (this.storageModeState === "normal") this.enterStorageRecovery("segment_recovery_prune");
		else this.closeSegmentStore();
		const directory = this.segmentDirectory();
		if (!existsSync(directory) || !existsSync(join(directory, "sealed"))) {
			this.segmentRecoveryPruneCursor = undefined;
			return {
				deletedSegmentIds: [],
				corruptSegmentIds: [],
				examinedSegments: 0,
				deletedBytes: 0,
				locatorsInvalidated: false,
				requiresFullReconciliation: false,
				blockedByReadSnapshot: false,
				moreWork: false,
			};
		}
		const result = pruneIncidentRecorderSealedHistoryForRecovery({
			directory,
			externalWriterExcluded: true,
			sealedBeforeMs: Math.max(0, nowMs - INCIDENT_DIAGNOSTIC_RETENTION_MS),
			protection: options.protection,
			maxSegments: SEGMENT_PRUNE_MAX_SEGMENTS,
			maxDeletes: SEGMENT_PRUNE_MAX_SEGMENTS,
			maxBytes: SEGMENT_PRUNE_MAX_BYTES,
			...(this.segmentRecoveryPruneCursor ? { continuation: this.segmentRecoveryPruneCursor } : {}),
		});
		this.segmentRecoveryPruneCursor = result.moreWork ? result.continuation : undefined;
		return result;
	}

	private discardStoppedTargetStream(key: string, state: StoppedTargetArtifactStream): boolean {
		let mutation: RecorderRootMutationResult<{ cleaned: boolean; effects: StorageAccountingEffect[] }> | undefined;
		try {
			mutation = this.withRecorderRoot((root) => {
				const effects: StorageAccountingEffect[] = [];
				const stagingDirectory = root.relative("cas", "sha256", "staging");
				const staged = root.relative("cas", "sha256", "staging", `${key}.tmp`);
				const metadata = root.lstat(staged);
				if (metadata) {
					const metadataNlink = Number(metadata.nlink);
					if (
						!metadata.isFile() ||
						metadata.isSymbolicLink() ||
						metadata.dev !== state.stagedDev ||
						metadata.ino !== state.stagedIno ||
						metadata.size !== BigInt(state.copiedBytes) ||
						(metadataNlink !== 1 && metadataNlink !== 2 && metadataNlink !== 3) ||
						(metadataNlink !== 1 && metadata.size !== BigInt(state.totalBytes))
					)
						return { cleaned: false, effects };
					root.unlinkFile(staged);
					effects.push({ kind: "remove", metadata, releaseOwnedInode: false });
					effects.push({ kind: "account", metadata: root.stat(stagingDirectory), entryCreated: false });
					root.fsyncDirectory(stagingDirectory);
				}
				return { cleaned: true, effects };
			});
		} catch {
			// Keep the state and reservation for a later exact-capability retry.
			return false;
		}
		if (mutation?.state !== "committed" || !mutation.value.cleaned) return false;
		this.applyStorageAccountingEffects(mutation.value.effects);
		this.releaseStorageReservation(state);
		this.stoppedTargetStreams.delete(key);
		return true;
	}

	private discardStoppedTargetStreams(): void {
		for (const [key, state] of this.stoppedTargetStreams) this.discardStoppedTargetStream(key, state);
	}

	streamStoppedTargetArtifact(
		runId: string,
		sourcePath: string,
		encoding: string,
		work: { deadlineMs: number; byteBudget: number },
	): StoppedTargetArtifactAdmission {
		const key = sha256(`${runId}\0${sourcePath}\0${encoding}`);
		let state = this.stoppedTargetStreams.get(key);
		if (state?.error) {
			const reason = state.error;
			if (!this.discardStoppedTargetStream(key, state))
				return {
					state: "pending",
					reason: "writer_lifecycle_unavailable",
					copiedBytes: state.copiedBytes,
					totalBytes: state.totalBytes,
				};
			return { state: "error", reason };
		}
		if (!state) {
			if (this.stoppedTargetStreams.size >= 8)
				return { state: "pending", reason: "work_budget", copiedBytes: 0, totalBytes: 0 };
			if (this.diskPaused) return { state: "pending", reason: "storage_paused", copiedBytes: 0, totalBytes: 0 };
			const leaseAdmission = this.normalWriterLifecycleLease();
			if (leaseAdmission.state === "unavailable")
				return { state: "pending", reason: leaseAdmission.reason, copiedBytes: 0, totalBytes: 0 };
			let metadata: BigIntStats;
			try {
				metadata = lstatSync(sourcePath, { bigint: true });
			} catch (error) {
				return { state: "error", reason: error instanceof Error ? error.message : String(error) };
			}
			if (!metadata.isFile()) return { state: "error", reason: "artifact_source_not_regular_file" };
			const totalBytes = Number(metadata.size);
			if (!Number.isSafeInteger(totalBytes)) {
				return { state: "pending", reason: "storage_paused", copiedBytes: 0, totalBytes };
			}
			// Hold the complete staged-file plus worst-case first-use CAS/lease
			// publication peak for the lifetime of the resumable copy. The digest
			// fanout is not known until hashing finishes, so this bounded structural
			// allowance prevents concurrent streams from consuming its completion
			// capacity before the frozen publish plan can be formed.
			const reservationBytes = totalBytes + 512 * 1024;
			const reservationEntries = 8;
			const reservationInodes = 8;
			try {
				this.reserveStorage(reservationBytes, reservationEntries, reservationInodes);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOSPC")
					return { state: "pending", reason: "storage_paused", copiedBytes: 0, totalBytes };
				throw error;
			}
			let mutation:
				| RecorderRootMutationResult<{
						state?: StoppedTargetArtifactStream;
						pendingReason?: "artifact_staging_reconciliation_required";
						effects: StorageAccountingEffect[];
				  }>
				| undefined;
			let mutationError: unknown;
			try {
				mutation = this.withRecorderRoot((root) => {
					const effects: StorageAccountingEffect[] = [];
					const directoryComponents = ["cas", "sha256", "staging"] as const;
					this.ensureOwnedDirectories(root, [directoryComponents], effects);
					const directory = root.relative(...directoryComponents);
					const staged = root.relative(...directoryComponents, `${key}.tmp`);
					const existing = root.lstat(staged);
					if (existing) {
						const expectedUid = typeof process.getuid === "function" ? process.getuid() : existing.uid;
						const existingBytes = Number(existing.size);
						const existingNlink = Number(existing.nlink);
						if (
							!existing.isFile() ||
							existing.isSymbolicLink() ||
							(existingNlink !== 1 && existingNlink !== 2 && existingNlink !== 3) ||
							(existingNlink !== 1 && existingBytes !== totalBytes) ||
							Number(existing.uid) !== expectedUid ||
							(Number(existing.mode) & 0o077) !== 0 ||
							!Number.isSafeInteger(existingBytes) ||
							existingBytes < 0 ||
							existingBytes > totalBytes
						)
							return { pendingReason: "artifact_staging_reconciliation_required", effects };
						return {
							state: {
								sourcePath,
								encoding,
								dev: metadata.dev,
								ino: metadata.ino,
								mtimeNs: metadata.mtimeNs,
								ctimeNs: metadata.ctimeNs,
								stagedDev: existing.dev,
								stagedIno: existing.ino,
								totalBytes,
								copiedBytes: existingBytes,
								rehydrateBytes: 0,
								stageWasExisting: true,
								hash: createHash("sha256"),
								reservedBytes: reservationBytes,
								reservedEntries: reservationEntries,
								reservedInodes: reservationInodes,
								reservationReleased: false,
							},
							effects,
						};
					}
					let source: number | undefined;
					try {
						source = openSync(sourcePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
						const openedSource = fstatSync(source, { bigint: true });
						if (
							openedSource.dev !== metadata.dev ||
							openedSource.ino !== metadata.ino ||
							openedSource.size !== metadata.size ||
							openedSource.mtimeNs !== metadata.mtimeNs ||
							openedSource.ctimeNs !== metadata.ctimeNs
						) {
							throw new Error("artifact_source_identity_changed_before_capture");
						}
						root.writeFileExclusive(staged, Buffer.alloc(0), 0o600);
					} finally {
						if (source !== undefined) closeSync(source);
					}
					const stagedMetadata = root.stat(staged);
					const directoryMetadata = root.stat(directory);
					effects.push({ kind: "account", metadata: stagedMetadata, entryCreated: true });
					effects.push({ kind: "account", metadata: directoryMetadata, entryCreated: false });
					root.fsyncDirectory(directory);
					return {
						state: {
							sourcePath,
							encoding,
							dev: metadata.dev,
							ino: metadata.ino,
							mtimeNs: metadata.mtimeNs,
							ctimeNs: metadata.ctimeNs,
							stagedDev: stagedMetadata.dev,
							stagedIno: stagedMetadata.ino,
							totalBytes,
							copiedBytes: 0,
							rehydrateBytes: 0,
							stageWasExisting: false,
							hash: createHash("sha256"),
							reservedBytes: reservationBytes,
							reservedEntries: reservationEntries,
							reservedInodes: reservationInodes,
							reservationReleased: false,
						},
						effects,
					};
				}, leaseAdmission.lease);
			} catch (error) {
				mutationError = error;
			}
			if (mutationError !== undefined || !mutation || mutation.state === "unavailable") {
				this.releaseReservedCapacity(reservationBytes, reservationEntries, reservationInodes);
				if (mutationError !== undefined) {
					return {
						state: "error",
						reason: mutationError instanceof Error ? mutationError.message : String(mutationError),
					};
				}
				return {
					state: "pending",
					reason: mutation?.state === "unavailable" ? mutation.reason : "writer_lifecycle_unavailable",
					copiedBytes: 0,
					totalBytes,
				};
			}
			if (mutation.value.pendingReason) {
				this.releaseReservedCapacity(reservationBytes, reservationEntries, reservationInodes);
				return {
					state: "pending",
					reason: mutation.value.pendingReason,
					copiedBytes: 0,
					totalBytes,
				};
			}
			if (!mutation.value.state) {
				this.releaseReservedCapacity(reservationBytes, reservationEntries, reservationInodes);
				return {
					state: "pending",
					reason: "artifact_staging_reconciliation_required",
					copiedBytes: 0,
					totalBytes,
				};
			}
			state = mutation.value.state;
			this.stoppedTargetStreams.set(key, state);
			const addedBytes = this.applyStorageAccountingEffects(mutation.value.effects);
			this.consumeStorageReservation(
				state,
				addedBytes,
				state.stageWasExisting ? 0 : 1,
				state.stageWasExisting ? 0 : 1,
			);
		}
		if (this.diskPaused) {
			const copiedBytes = state.copiedBytes;
			const totalBytes = state.totalBytes;
			this.discardStoppedTargetStream(key, state);
			return {
				state: "pending",
				reason: "storage_paused",
				copiedBytes,
				totalBytes,
			};
		}
		const remaining = Math.max(0, Math.min(work.byteBudget, 4 * 1024 * 1024));
		if (remaining === 0 || Date.now() >= work.deadlineMs) {
			return {
				state: "pending",
				reason: "work_budget",
				copiedBytes: state.copiedBytes,
				totalBytes: state.totalBytes,
			};
		}
		const leaseAdmission = this.normalWriterLifecycleLease();
		if (leaseAdmission.state === "unavailable") {
			return {
				state: "pending",
				reason: leaseAdmission.reason,
				copiedBytes: state.copiedBytes,
				totalBytes: state.totalBytes,
			};
		}
		let mutation:
			| RecorderRootMutationResult<{
					copiedBytes: number;
					hash?: Hash;
					rehydrateBytes?: number;
					effects: StorageAccountingEffect[];
					artifact?: StoppedTargetArtifactReference;
					error?: string;
					pendingReason?: "artifact_staging_reconciliation_required";
			  }>
			| undefined;
		let mutationError: unknown;
		try {
			mutation = this.withRecorderRoot((root) => {
				const effects: StorageAccountingEffect[] = [];
				const directory = root.relative("cas", "sha256", "staging");
				const staged = root.relative("cas", "sha256", "staging", `${key}.tmp`);
				const stagedBefore = root.stat(staged);
				if (
					!stagedBefore.isFile() ||
					stagedBefore.isSymbolicLink() ||
					stagedBefore.dev !== state.stagedDev ||
					stagedBefore.ino !== state.stagedIno
				) {
					throw new Error("artifact_staging_identity_changed_during_capture");
				}
				const stagedBytes = Number(stagedBefore.size);
				const stagedNlink = Number(stagedBefore.nlink);
				const expectedUid = typeof process.getuid === "function" ? process.getuid() : stagedBefore.uid;
				if (
					!Number.isSafeInteger(stagedBytes) ||
					stagedBytes < state.copiedBytes ||
					stagedBytes > state.totalBytes ||
					Number(stagedBefore.uid) !== expectedUid ||
					(Number(stagedBefore.mode) & 0o077) !== 0 ||
					(stagedNlink !== 1 && stagedNlink !== 2 && stagedNlink !== 3) ||
					(stagedNlink !== 1 && stagedBytes !== state.totalBytes)
				) {
					throw new Error("artifact_staging_identity_changed_during_capture");
				}
				const capturedBytes = stagedBytes;
				let source: number | undefined;
				const nextHash = state.hash.copy();
				let copied = 0;
				let rehydrated = 0;
				let eof = false;
				let prefixMatches = true;
				try {
					source = openSync(state.sourcePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
					const sourceBefore = fstatSync(source, { bigint: true });
					if (
						sourceBefore.dev !== state.dev ||
						sourceBefore.ino !== state.ino ||
						sourceBefore.size !== BigInt(state.totalBytes) ||
						sourceBefore.mtimeNs !== state.mtimeNs ||
						sourceBefore.ctimeNs !== state.ctimeNs
					) {
						throw new Error("artifact_source_changed_during_capture");
					}
					root.withFile(staged, { access: "read_write" }, (target) => {
						const buffer = Buffer.allocUnsafe(64 * 1024);
						const sourceBuffer = Buffer.allocUnsafe(64 * 1024);
						let workUsed = 0;
						while (
							state.rehydrateBytes + rehydrated < capturedBytes &&
							workUsed < remaining &&
							Date.now() < work.deadlineMs
						) {
							const position = state.rehydrateBytes + rehydrated;
							const expected = Math.min(buffer.length, capturedBytes - position, remaining - workUsed);
							const stagedCount = target.read(buffer, 0, expected, position);
							const sourceCount = readSync(source as number, sourceBuffer, 0, expected, position);
							if (
								stagedCount !== sourceCount ||
								stagedCount <= 0 ||
								!buffer.subarray(0, stagedCount).equals(sourceBuffer.subarray(0, sourceCount))
							) {
								prefixMatches = false;
								break;
							}
							nextHash.update(sourceBuffer.subarray(0, sourceCount));
							rehydrated += sourceCount;
							workUsed += sourceCount;
						}
						while (prefixMatches && workUsed < remaining && Date.now() < work.deadlineMs) {
							const count = readSync(
								source as number,
								buffer,
								0,
								Math.min(buffer.length, remaining - workUsed),
								capturedBytes + copied,
							);
							if (count === 0) {
								eof = true;
								break;
							}
							let written = 0;
							while (written < count) {
								const amount = target.write(buffer, written, count - written, capturedBytes + copied + written);
								if (amount <= 0) throw new Error("artifact_staging_write_made_no_progress");
								written += amount;
							}
							nextHash.update(buffer.subarray(0, count));
							copied += count;
							workUsed += count;
						}
						target.sync();
					});
					const sourceAfter = fstatSync(source, { bigint: true });
					const currentPath = lstatSync(state.sourcePath, { bigint: true });
					if (
						sourceAfter.dev !== sourceBefore.dev ||
						sourceAfter.ino !== sourceBefore.ino ||
						sourceAfter.size !== sourceBefore.size ||
						sourceAfter.mtimeNs !== sourceBefore.mtimeNs ||
						sourceAfter.ctimeNs !== sourceBefore.ctimeNs ||
						currentPath.dev !== sourceAfter.dev ||
						currentPath.ino !== sourceAfter.ino ||
						currentPath.size !== sourceAfter.size ||
						currentPath.mtimeNs !== sourceAfter.mtimeNs ||
						currentPath.ctimeNs !== sourceAfter.ctimeNs
					) {
						throw new Error("artifact_source_changed_during_capture");
					}
				} finally {
					if (source !== undefined) closeSync(source);
				}
				const stagedAfter = root.stat(staged);
				if (
					stagedAfter.dev !== state.stagedDev ||
					stagedAfter.ino !== state.stagedIno ||
					stagedAfter.nlink !== BigInt(stagedNlink) ||
					stagedAfter.size !== BigInt(capturedBytes + copied) ||
					Number(stagedAfter.uid) !== expectedUid ||
					(Number(stagedAfter.mode) & 0o077) !== 0
				) {
					throw new Error("artifact_staging_changed_during_capture");
				}
				if (!prefixMatches) {
					return {
						copiedBytes: state.copiedBytes,
						hash: state.hash,
						rehydrateBytes: state.rehydrateBytes,
						effects,
						pendingReason: "artifact_staging_reconciliation_required",
					};
				}
				effects.push({ kind: "account", metadata: stagedAfter, entryCreated: false });
				if (state.rehydrateBytes + rehydrated < capturedBytes) {
					return {
						copiedBytes: capturedBytes,
						hash: nextHash,
						rehydrateBytes: state.rehydrateBytes + rehydrated,
						effects,
					};
				}
				if (!eof) {
					return {
						copiedBytes: capturedBytes + copied,
						hash: nextHash,
						rehydrateBytes: capturedBytes + copied,
						effects,
					};
				}
				if (capturedBytes + copied !== state.totalBytes) {
					throw new Error("artifact_source_ended_before_declared_length");
				}
				const digest = nextHash.digest("hex");
				if (stagedNlink === 2 || stagedNlink === 3) {
					const canonical = root.relative("cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
					const canonicalMetadata = root.lstat(canonical);
					if (
						!canonicalMetadata ||
						!canonicalMetadata.isFile() ||
						canonicalMetadata.isSymbolicLink() ||
						Number(canonicalMetadata.uid) !== expectedUid ||
						(Number(canonicalMetadata.mode) & 0o077) !== 0 ||
						canonicalMetadata.dev !== stagedAfter.dev ||
						canonicalMetadata.ino !== stagedAfter.ino ||
						canonicalMetadata.size !== BigInt(state.totalBytes) ||
						canonicalMetadata.nlink !== BigInt(stagedNlink)
					) {
						return {
							copiedBytes: state.copiedBytes,
							effects,
							pendingReason: "artifact_staging_reconciliation_required",
						};
					}
					if (stagedNlink === 3) {
						const lease = root.relative("refs", "runs", sha256(runId), `cas-${digest}.blob`);
						const leaseMetadata = root.lstat(lease);
						if (
							!leaseMetadata ||
							!leaseMetadata.isFile() ||
							leaseMetadata.isSymbolicLink() ||
							Number(leaseMetadata.uid) !== expectedUid ||
							(Number(leaseMetadata.mode) & 0o077) !== 0 ||
							leaseMetadata.dev !== stagedAfter.dev ||
							leaseMetadata.ino !== stagedAfter.ino ||
							leaseMetadata.size !== BigInt(state.totalBytes) ||
							leaseMetadata.nlink !== 3n
						) {
							return {
								copiedBytes: state.copiedBytes,
								effects,
								pendingReason: "artifact_staging_reconciliation_required",
							};
						}
					}
				}
				let casPath: string;
				try {
					casPath = this.publishCasAndRunLease(
						root,
						{ runId, digest, bytes: state.totalBytes, stagedPath: staged, mtimeNs: state.mtimeNs },
						effects,
					).casPath;
				} catch (error) {
					return {
						copiedBytes: state.copiedBytes,
						effects,
						error: error instanceof Error ? error.message : String(error),
					};
				}
				const stagedMetadata = root.stat(staged);
				root.unlinkFile(staged);
				effects.push({ kind: "remove", metadata: stagedMetadata, releaseOwnedInode: false });
				effects.push({ kind: "account", metadata: root.stat(directory), entryCreated: false });
				root.fsyncDirectory(directory);
				return {
					copiedBytes: state.totalBytes,
					effects,
					artifact: { algorithm: "sha256", digest, bytes: state.totalBytes, path: casPath, encoding },
				};
			}, leaseAdmission.lease);
		} catch (error) {
			mutationError = error;
		}
		if (mutationError !== undefined) {
			if (this.isStoppedTargetReconciliationError(mutationError))
				return {
					state: "pending",
					reason: "artifact_staging_reconciliation_required",
					copiedBytes: state.copiedBytes,
					totalBytes: state.totalBytes,
				};
			if (inspectIncidentRecorderWriterLifecycleLeaseMode(leaseAdmission.lease) === undefined)
				return {
					state: "pending",
					reason: "writer_lifecycle_namespace_changed",
					copiedBytes: state.copiedBytes,
					totalBytes: state.totalBytes,
				};
			state.error = mutationError instanceof Error ? mutationError.message : String(mutationError);
			if (!this.discardStoppedTargetStream(key, state))
				return {
					state: "pending",
					reason: "writer_lifecycle_unavailable",
					copiedBytes: state.copiedBytes,
					totalBytes: state.totalBytes,
				};
			return { state: "error", reason: state.error };
		}
		if (!mutation || mutation.state === "unavailable") {
			return {
				state: "pending",
				reason: mutation?.state === "unavailable" ? mutation.reason : "writer_lifecycle_unavailable",
				copiedBytes: state.copiedBytes,
				totalBytes: state.totalBytes,
			};
		}
		const addedBytes = this.applyStorageAccountingEffects(mutation.value.effects);
		if (mutation.value.pendingReason) {
			return {
				state: "pending",
				reason: mutation.value.pendingReason,
				copiedBytes: state.copiedBytes,
				totalBytes: state.totalBytes,
			};
		}
		if (mutation.value.error) {
			if (this.isStoppedTargetPublicationStructuralError(new Error(mutation.value.error))) {
				state.error = mutation.value.error;
				// Publication is reached only after the complete staged source has
				// been verified. Reflect that fact so recognized shared-link residue
				// can be retired without treating it as a partial capture.
				state.copiedBytes = state.totalBytes;
				state.rehydrateBytes = state.totalBytes;
				if (this.discardStoppedTargetStream(key, state)) return { state: "error", reason: state.error };
				return {
					state: "pending",
					reason: "writer_lifecycle_unavailable",
					copiedBytes: state.copiedBytes,
					totalBytes: state.totalBytes,
				};
			}
			// A lifecycle loss can surface as an operation error after the CAS
			// transaction has made durable progress. Do not turn that boundary
			// into a terminal artifact error or discard the resumable stage.
			return {
				state: "pending",
				reason: "writer_lifecycle_unavailable",
				copiedBytes: state.copiedBytes,
				totalBytes: state.totalBytes,
			};
		}
		if (mutation.value.artifact) {
			this.stoppedTargetStreams.delete(key);
			this.releaseStorageReservation(state);
			return { state: "complete", artifact: mutation.value.artifact };
		}
		state.copiedBytes = mutation.value.copiedBytes;
		if (mutation.value.hash) state.hash = mutation.value.hash;
		if (mutation.value.rehydrateBytes !== undefined) state.rehydrateBytes = mutation.value.rehydrateBytes;
		this.consumeStorageReservation(state, addedBytes, 0, 0);
		return {
			state: "pending",
			reason: "work_budget",
			copiedBytes: state.copiedBytes,
			totalBytes: state.totalBytes,
		};
	}

	async run(options: IncidentRecorderCompactorRunOptions): Promise<void> {
		const { signal } = options;
		try {
			await this.initializeStorageAccounting(signal);
		} catch (error) {
			if (signal.aborted && error instanceof Error && error.name === "AbortError") return;
			throw error;
		}
		let reportedStorageMode: IncidentRecorderStorageMode | undefined;
		let reportedRecoveryReason: string | undefined;
		const reportStorageMode = (): void => {
			if (
				reportedStorageMode === this.storageModeState &&
				reportedRecoveryReason === this.storageRecoveryReasonState
			)
				return;
			reportedStorageMode = this.storageModeState;
			reportedRecoveryReason = this.storageRecoveryReasonState;
			options.onStorageMode?.(this.storageModeState, this.storageRecoveryReasonState);
		};
		reportStorageMode();
		try {
			await this.waitUntilAdmitted(signal, options, reportStorageMode);
		} catch (error) {
			if (signal.aborted && error instanceof Error && error.name === "AbortError") return;
			throw error;
		}
		this.ensureDiskAdmission(256 * 1024);
		let readerReady = false;
		let readerValidated = false;
		let boundedStartEstablished = false;
		let resumeCursor = this.checkpoint?.cursor;
		const notifyReaderReady = (): void => {
			if (readerReady) return;
			readerReady = true;
			options.onReaderReady?.();
		};
		const refresh = setInterval(() => {
			if (signal.aborted || this.storageScanPromise) return;
			void this.initializeStorageAccounting(signal)
				.then(reportStorageMode)
				.catch(() => {
					// A failed refresh retains the prior conservative baseline. Saturation already fails admission closed.
				});
		}, STORAGE_ACCOUNTING_REFRESH_MS);
		refresh.unref();
		let hasRunError = false;
		let runError: unknown;
		let hasShutdownFlushError = false;
		let shutdownFlushError: unknown;
		let hasSegmentCloseError = false;
		let segmentCloseError: unknown;
		try {
			readerLoop: for (;;) {
				if (signal.aborted) break;
				if (!resumeCursor && !boundedStartEstablished) {
					try {
						this.writeGap({
							reason: "journal_history_before_bounded_start_not_asserted",
							checkpointDisposition: this.checkpointDisposition,
							selection: {
								strategy: "bounded_recent_tail",
								maxEntries: this.journalCatchupMaxEntries(),
								maxExportBytes: this.journalCatchupMaxBytes(),
							},
							coverageBeforeSelectedTail: "unknown_or_unavailable",
						});
					} catch (error) {
						if (!this.isStorageAdmissionError(error as Error)) throw error;
						await this.waitUntilAdmitted(signal, options, reportStorageMode);
						continue;
					}
					boundedStartEstablished = true;
				}
				for (;;) {
					await this.waitUntilAdmitted(signal, options, reportStorageMode);
					const maximumEntries = this.journalCatchupMaxEntries();
					const args = this.journalReaderBaseArgs();
					if (resumeCursor) {
						args.push(`--after-cursor=${resumeCursor}`, `--lines=+${maximumEntries}`);
					} else {
						args.push(`--lines=${maximumEntries}`);
					}
					const outcome = await this.readJournal(args, signal, readerValidated ? notifyReaderReady : () => {}, {
						maximumBytes: this.journalCatchupMaxBytes(),
						deadlineMs: positiveBound(this.options.journalCatchupSliceMs, JOURNAL_CATCHUP_SLICE_MS),
					});
					if (outcome.aborted || signal.aborted) break readerLoop;
					if (outcome.parserError) {
						if (this.isStorageAdmissionError(outcome.parserError)) {
							await this.waitUntilAdmitted(signal, options, reportStorageMode);
							continue;
						}
						resumeCursor = this.recoverPoisonedJournalEntry(outcome) ?? resumeCursor;
						continue;
					}
					if (this.isUnseekableCursor(outcome, resumeCursor)) {
						this.resetUnseekableCursor(outcome.stderr);
						resumeCursor = undefined;
						boundedStartEstablished = false;
						continue readerLoop;
					}
					if (outcome.workBudgetExhausted) {
						if (outcome.entries > 0 && outcome.lastCursor) readerValidated = true;
						resumeCursor = outcome.lastCursor ?? resumeCursor;
						await this.abortableDelay(1, signal);
						continue;
					}
					if (outcome.code !== 0 || outcome.error) throw this.journalReaderError(outcome);
					readerValidated = true;
					resumeCursor = outcome.lastCursor ?? resumeCursor;
					if (outcome.entries < maximumEntries) break;
					if (!outcome.lastCursor) throw new Error("Bounded incident journal catch-up made no cursor progress");
				}

				await this.waitUntilAdmitted(signal, options, reportStorageMode);
				const followArgs = this.journalReaderBaseArgs();
				followArgs.push("--follow");
				if (resumeCursor) followArgs.push("--no-tail", `--after-cursor=${resumeCursor}`);
				else followArgs.push("--lines=0");
				const outcome = await this.readJournal(followArgs, signal, notifyReaderReady);
				if (outcome.aborted || signal.aborted) break;
				this.flushAllIncomplete("journal_stream_disconnected_before_occurrence_completion");
				if (outcome.parserError) {
					if (this.isStorageAdmissionError(outcome.parserError)) {
						await this.waitUntilAdmitted(signal, options, reportStorageMode);
						continue;
					}
					resumeCursor = this.recoverPoisonedJournalEntry(outcome) ?? outcome.lastCursor ?? resumeCursor;
					continue;
				}
				if (this.isUnseekableCursor(outcome, resumeCursor)) {
					this.resetUnseekableCursor(outcome.stderr);
					resumeCursor = undefined;
					boundedStartEstablished = false;
					continue;
				}
				throw this.journalReaderError(outcome);
			}
		} catch (error) {
			if (!(signal.aborted && error instanceof Error && error.name === "AbortError")) {
				hasRunError = true;
				runError = error;
			}
		} finally {
			clearInterval(refresh);
			if (signal.aborted && this.assemblies.size > 0) {
				try {
					this.flushAllIncomplete("service_shutdown_before_occurrence_completion");
				} catch (error) {
					hasShutdownFlushError = true;
					shutdownFlushError = error;
				}
			}
			try {
				this.closeSegmentStore();
			} catch (error) {
				hasSegmentCloseError = true;
				segmentCloseError = error;
				this.segmentOpenRequiresReconciliation = true;
			}
			this.discardRunHistoryTraversals();
			this.discardTransientJournalState();
			this.discardTransientFileState();
		}
		if (hasRunError) throw runError;
		if (hasShutdownFlushError) throw shutdownFlushError;
		if (hasSegmentCloseError) throw segmentCloseError;
	}

	private journalCatchupMaxEntries(): number {
		return positiveBound(this.options.journalCatchupMaxEntries, JOURNAL_CATCHUP_MAX_ENTRIES);
	}

	private journalCatchupMaxBytes(): number {
		return positiveBound(this.options.journalCatchupMaxBytes, JOURNAL_CATCHUP_MAX_BYTES);
	}

	private journalReaderBaseArgs(): string[] {
		return [
			`--namespace=${INCIDENT_RECORDER_JOURNAL_NAMESPACE}`,
			`--identifier=${INCIDENT_RECORDER_JOURNAL_IDENTIFIER}`,
			"--output=export",
			"--all",
			"--no-pager",
		];
	}

	private async readJournal(
		args: string[],
		signal: AbortSignal,
		onSpawn: () => void,
		work?: { maximumBytes: number; deadlineMs: number },
	): Promise<JournalReaderOutcome> {
		if (signal.aborted)
			return {
				code: null,
				signal: null,
				poisonFields: {},
				stderr: "",
				entries: 0,
				workBudgetExhausted: false,
				aborted: true,
			};
		const child = spawn(this.options.journalctlPath ?? "journalctl", args, {
			stdio: ["ignore", "pipe", "pipe"],
			env: childEnvironment(),
		});
		let entries = 0;
		let lastCursor: string | undefined;
		const parser = new JournalExportParser((fields) => {
			entries += 1;
			lastCursor = optionalText(fields, "__CURSOR") ?? lastCursor;
			this.acceptEntry(fields);
		});
		let parserError: Error | undefined;
		let processError: Error | undefined;
		let stderr = "";
		let readBytes = 0;
		let workBudgetExhausted = false;
		let aborted = false;
		let killTimer: ReturnType<typeof setTimeout> | undefined;
		let readyTimer: ReturnType<typeof setTimeout> | undefined;
		let resolveCompletion: () => void = () => {};
		const completion = new Promise<void>((resolve) => {
			resolveCompletion = resolve;
		});
		const terminate = (): void => {
			try {
				child.kill("SIGTERM");
			} catch {}
			if (killTimer) return;
			killTimer = setTimeout(() => {
				try {
					if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
				} catch {}
			}, CHILD_TERMINATION_GRACE_MS);
			killTimer.unref();
		};
		const tracked: TrackedCompactorChild = { child, completion, terminate };
		this.activeCompactorChildren.add(tracked);
		child.once("spawn", () => {
			readyTimer = setTimeout(() => {
				readyTimer = undefined;
				if (child.exitCode !== null || child.signalCode !== null || aborted) return;
				try {
					onSpawn();
				} catch (error) {
					processError = error instanceof Error ? error : new Error(String(error));
					terminate();
				}
			}, JOURNAL_READER_STABILITY_MS);
			readyTimer.unref();
		});
		child.stdout?.on("data", (chunk: Buffer) => {
			if (parserError || processError || workBudgetExhausted || aborted) return;
			readBytes += chunk.length;
			if (work && readBytes > work.maximumBytes) {
				workBudgetExhausted = true;
				terminate();
				return;
			}
			try {
				parser.push(chunk);
			} catch (error) {
				parserError = error instanceof Error ? error : new Error(String(error));
				terminate();
			}
		});
		child.stderr?.on("data", (chunk: Buffer) => {
			stderr = `${stderr}${chunk.toString("utf8")}`.slice(-4096);
		});
		child.once("error", (error) => {
			processError ??= error;
		});
		const onAbort = (): void => {
			aborted = true;
			terminate();
		};
		signal.addEventListener("abort", onAbort, { once: true });
		const deadline = work
			? setTimeout(() => {
					workBudgetExhausted = true;
					terminate();
				}, work.deadlineMs)
			: undefined;
		deadline?.unref();
		const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
			child.once("close", (code, childSignal) => {
				resolve({ code, signal: childSignal });
				this.activeCompactorChildren.delete(tracked);
				resolveCompletion();
			});
		});
		if (deadline) clearTimeout(deadline);
		if (killTimer) clearTimeout(killTimer);
		if (readyTimer) clearTimeout(readyTimer);
		signal.removeEventListener("abort", onAbort);
		if (!aborted && !workBudgetExhausted && !parserError) {
			try {
				parser.finish();
			} catch (error) {
				parserError = error instanceof Error ? error : new Error(String(error));
			}
		}
		return {
			...result,
			...(processError ? { error: processError } : {}),
			...(parserError ? { parserError } : {}),
			poisonFields: parser.poisonFields(),
			stderr,
			entries,
			...(lastCursor ? { lastCursor } : {}),
			workBudgetExhausted,
			aborted,
		};
	}

	private recoverPoisonedJournalEntry(outcome: JournalReaderOutcome): string | undefined {
		const parserError = outcome.parserError;
		if (!parserError) return undefined;
		if (this.isStorageAdmissionError(parserError)) return undefined;
		if (this.isSegmentPersistenceError(parserError) || this.isWriterLifecycleAdmissionError(parserError))
			throw parserError;
		const poisonCursor = optionalText(outcome.poisonFields, "__CURSOR");
		const poisonMachine = optionalText(outcome.poisonFields, "_MACHINE_ID");
		const poisonBoot = optionalText(outcome.poisonFields, "_BOOT_ID");
		const poisonInvocation = optionalText(outcome.poisonFields, "_SYSTEMD_INVOCATION_ID");
		const poisonRealtime = optionalText(outcome.poisonFields, "__REALTIME_TIMESTAMP");
		// Cursor advancement is only safe after the loss evidence itself is
		// durable (or an idempotent replay returned its existing locator).
		// Propagate persistence/admission failures so the poisoned entry is
		// retried without checkpointing past it.
		this.writeGap({
			reason: "journal_export_truncated_or_poisoned",
			cursor: poisonCursor,
			error: parserError.message,
		});
		if (poisonCursor && poisonMachine && poisonBoot && poisonRealtime) {
			this.commitCursor(poisonCursor, poisonMachine, poisonBoot, poisonInvocation, poisonRealtime);
			return poisonCursor;
		}
		throw parserError;
	}

	private isUnseekableCursor(outcome: JournalReaderOutcome, cursor: string | undefined): boolean {
		return (
			Boolean(cursor) &&
			outcome.code !== 0 &&
			/(?:cursor[^\n]*(?:not found|invalid)|failed to seek[^\n]*cursor|cursor.*vacuum)/i.test(outcome.stderr)
		);
	}

	private resetUnseekableCursor(stderr: string): void {
		const admission = this.withRecorderRoot(() => true);
		if (admission.state !== "committed") throw this.writerLifecycleAdmissionError(admission.reason);
		this.flushAllIncomplete("journal_cursor_removed_before_occurrence_completion");
		this.writeGap({
			reason: "journal_cursor_removed_or_unseekable",
			removedCursor: this.checkpoint?.cursor,
			machineId: this.checkpoint?.machineId,
			bootId: this.checkpoint?.bootId,
			invocationId: this.checkpoint?.invocationId,
			journalctl: stderr,
		});
		let changed = false;
		try {
			const mutation = this.withRecorderRoot((root) => {
				const path = root.relative("compactor-cursor.json");
				const previous = root.lstat(path);
				if (previous) {
					if (!previous.isFile() || previous.isSymbolicLink() || previous.nlink !== 1n)
						throw new Error("Recorder cursor is not a regular private entry");
					changed = true;
					root.unlinkFile(path);
				}
				root.fsyncDirectory(root.relative());
				return previous;
			});
			if (mutation.state !== "committed") throw this.writerLifecycleAdmissionError(mutation.reason);
			if (mutation.value) this.accountRemovedStorageEntry(mutation.value, true);
		} catch (error) {
			if (changed) this.invalidateStorageAccounting();
			throw error;
		}
		this.checkpoint = undefined;
		this.checkpointDisposition = "missing";
		this.wrapperSequences.clear();
		this.producerSequences.clear();
		this.pendingEntries.length = 0;
		this.pendingEntryBytes = 0;
	}

	private journalReaderError(outcome: JournalReaderOutcome): Error {
		return (
			outcome.error ??
			new Error(`Incident journal reader exited (${outcome.code ?? outcome.signal ?? "unknown"}): ${outcome.stderr}`)
		);
	}

	private isStorageAdmissionError(error: Error): boolean {
		return (error as NodeJS.ErrnoException).code === "ENOSPC" || this.storageModeState === "recovery-only";
	}

	private async waitUntilAdmitted(
		signal: AbortSignal,
		recovery?: IncidentRecorderCompactorRunOptions,
		reportStorageMode?: () => void,
	): Promise<void> {
		let recoveryPassesSinceScan = 0;
		let unchangedScans = 0;
		for (;;) {
			if (!this.diskPaused) {
				if (!recovery?.onNormalWriterAdmission || (await recovery.onNormalWriterAdmission())) return;
				await this.abortableDelay(positiveBound(recovery.storageRecoveryCadenceMs, 250), signal);
				continue;
			}
			if (signal.aborted) throw abortError("Incident journal reader admission wait was aborted");
			if (this.storageModeState === "recovery-only") {
				let moreRecoveryWork = false;
				try {
					moreRecoveryWork = (await recovery?.onRecoveryPass?.()) ?? false;
				} catch {
					// Cleanup uncertainty remains fail-closed and a later bounded pass retries it.
				}
				recoveryPassesSinceScan += 1;
				const shouldScan = !moreRecoveryWork || recoveryPassesSinceScan >= 16;
				const idleBackoffMs = Math.min(30_000, 5_000 * 2 ** Math.min(unchangedScans, 3));
				await this.abortableDelay(
					positiveBound(recovery?.storageRecoveryCadenceMs, moreRecoveryWork ? 250 : idleBackoffMs),
					signal,
				);
				if (!shouldScan) continue;
				await this.initializeStorageAccounting(signal);
				recoveryPassesSinceScan = 0;
				if (this.storageModeState === "recovery-only") unchangedScans += 1;
				else unchangedScans = 0;
				reportStorageMode?.();
				continue;
			}
			if (!this.storageAccountingReadyState) {
				await this.initializeStorageAccounting(signal);
				reportStorageMode?.();
			} else await this.abortableDelay(Math.max(1, this.pausedUntilMs - Date.now()), signal);
		}
	}

	private async abortableDelay(delayMs: number, signal: AbortSignal): Promise<void> {
		if (signal.aborted) throw abortError("Incident compactor delay was aborted");
		await new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => {
				signal.removeEventListener("abort", onAbort);
				resolve();
			}, delayMs);
			const onAbort = (): void => {
				clearTimeout(timer);
				reject(abortError("Incident compactor delay was aborted"));
			};
			signal.addEventListener("abort", onAbort, { once: true });
		});
	}

	private discardTransientJournalState(): void {
		for (const assembly of this.assemblies.values()) clearTimeout(assembly.timer);
		this.assemblies.clear();
		this.assemblyBytes = 0;
		this.pendingEntries.length = 0;
		this.pendingEntryBytes = 0;
	}

	/**
	 * Drop only the in-memory journal frontier after all readers have stopped.
	 * The durable cursor remains authoritative; replay must start from the last
	 * committed checkpoint rather than from sequence state observed in a partial
	 * assembly.
	 */
	private discardVolatileJournalState(): void {
		this.discardTransientJournalState();
		this.wrapperSequences.clear();
		this.producerSequences.clear();
		const checkpoint = this.checkpoint;
		if (!checkpoint) return;
		for (const key of Object.getOwnPropertyNames(checkpoint.wrapperSequences ?? {})) {
			const value = checkpoint.wrapperSequences[key];
			if (typeof value === "string" && isUnsigned64(value)) this.wrapperSequences.set(key, BigInt(value));
		}
		for (const key of Object.getOwnPropertyNames(checkpoint.producerSequences ?? {})) {
			const value = checkpoint.producerSequences[key];
			if (typeof value === "string" && isUnsigned64(value)) this.producerSequences.set(key, BigInt(value));
		}
	}

	private discardTransientFileState(): void {
		this.discardPendingPinDirectoryTraversal();
		this.discardStoppedTargetStreams();
		const failures: unknown[] = [];
		const traversal = this.activePinTraversal;
		if (traversal?.directory) {
			try {
				traversal.directory.closeSync();
				traversal.directory = undefined;
			} catch (error) {
				failures.push(error);
			}
		}
		if (traversal && !traversal.directory) this.activePinTraversal = undefined;
		const validation = this.journalManifestValidation;
		if (validation) {
			if (validation.pinValidation) {
				try {
					closeSync(validation.pinValidation.descriptor);
				} catch (error) {
					failures.push(error);
				}
			}
			try {
				closeSync(validation.descriptor);
			} catch (error) {
				failures.push(error);
			}
			if (failures.length === 0) this.journalManifestValidation = undefined;
		}
		if (failures.length > 0)
			this.transientFileCloseFailure =
				this.transientFileCloseFailure ??
				new Error(`Incident compactor transient file cleanup failed: ${String(failures[0])}`, {
					cause: failures[0],
				});
	}

	private closeLifecycleDescriptor(descriptor: number): void {
		if (this.lifecycleClosedDescriptors.has(descriptor)) return;
		closeSync(descriptor);
		this.lifecycleClosedDescriptors.add(descriptor);
	}

	private closeLifecycleDirectory(directory: ReturnType<typeof opendirSync>): void {
		if (this.lifecycleClosedDirectories.has(directory)) return;
		directory.closeSync();
		this.lifecycleClosedDirectories.add(directory);
	}

	private async drainCompactorChildren(deadlineAtMs: number): Promise<void> {
		for (const scan of this.activePinScans.values()) scan.cancelled = true;
		for (;;) {
			const pending = new Set<TrackedCompactorChild>(this.activeCompactorChildren);
			for (const scan of this.activePinScans.values()) pending.add(scan);
			if (pending.size === 0) return;
			for (const resource of pending) resource.terminate();
			const remainingMs = deadlineAtMs - Date.now();
			if (remainingMs <= 0) throw new Error("Incident compactor child cleanup deadline exceeded");
			let timeout: ReturnType<typeof setTimeout> | undefined;
			const timeoutPromise = new Promise<"timeout">((resolve) => {
				timeout = setTimeout(() => resolve("timeout"), remainingMs);
			});
			const outcome = await Promise.race([
				Promise.all([...pending].map((resource) => resource.completion)).then(() => "complete" as const),
				timeoutPromise,
			]);
			if (timeout) clearTimeout(timeout);
			if (outcome === "timeout") throw new Error("Incident compactor child cleanup deadline exceeded");
		}
	}

	private closeRunHistoryTraversalForLifecycle(state: RunHistoryTraversal): Error[] {
		const failures: Error[] = [];
		const closeDescriptor = (descriptor: number, role: string): void => {
			try {
				this.closeLifecycleDescriptor(descriptor);
			} catch (error) {
				failures.push(new Error(`Incident compactor ${role} close failed`, { cause: error }));
			}
		};
		const active = state.activeCasValidation;
		if (active) {
			const activeFailureCount = failures.length;
			closeDescriptor(active.fileDescriptor, "run-history CAS file descriptor");
			for (const fence of active.directoryFences) closeDescriptor(fence.descriptor, "run-history CAS fence");
			closeDescriptor(
				active.procfsAuthority.descriptorInfoDirectoryDescriptor,
				"run-history procfs fdinfo descriptor",
			);
			closeDescriptor(active.procfsAuthority.descriptorDirectoryDescriptor, "run-history procfs fd descriptor");
			closeDescriptor(active.procfsAuthority.rootDescriptor, "run-history procfs root descriptor");
			if (failures.length === activeFailureCount) state.activeCasValidation = undefined;
		}
		if (state.directory) {
			try {
				this.closeLifecycleDirectory(state.directory);
				state.directory = undefined;
			} catch (error) {
				failures.push(new Error("Incident compactor run-history directory close failed", { cause: error }));
			}
		}
		const authority = state.procfsAuthority;
		if (authority) {
			const authorityFailureCount = failures.length;
			closeDescriptor(authority.descriptorInfoDirectoryDescriptor, "run-history procfs fdinfo descriptor");
			closeDescriptor(authority.descriptorDirectoryDescriptor, "run-history procfs fd descriptor");
			closeDescriptor(authority.rootDescriptor, "run-history procfs root descriptor");
			if (failures.length === authorityFailureCount) state.procfsAuthority = undefined;
		}
		for (const key of ["legacyDirectoryDescriptor", "legacyNamespaceDescriptor"] as const) {
			const descriptor = state[key];
			if (descriptor === undefined) continue;
			const descriptorFailureCount = failures.length;
			closeDescriptor(descriptor, `run-history ${key}`);
			if (failures.length === descriptorFailureCount) state[key] = undefined;
		}
		if (state.segmentReadLease) {
			try {
				if (!this.segmentStore) throw new Error("segment store unavailable for read-lease release");
				this.segmentStore.releaseReadLease(state.segmentReadLease);
				state.segmentReadLease = undefined;
			} catch (error) {
				failures.push(new Error("Incident compactor segment read lease release failed", { cause: error }));
			}
		}
		if (failures.length === 0) {
			const publicationCapability = state.publicationCapability;
			state.publicationCapability = undefined;
			if (publicationCapability) this.releasedRunHistoryPublicationCapabilities.add(publicationCapability);
			if (publicationCapability && this.runHistoryPublicationCapabilities.get(publicationCapability) === state) {
				this.runHistoryPublicationCapabilities.delete(publicationCapability);
			}
			if (this.runHistoryTraversals.get(state.token) === state) this.runHistoryTraversals.delete(state.token);
		}
		return failures;
	}

	private closeLifecycleFileStates(): Error[] {
		const failures: Error[] = [];
		const closeDescriptor = (descriptor: number, role: string): void => {
			try {
				this.closeLifecycleDescriptor(descriptor);
			} catch (error) {
				failures.push(new Error(`Incident compactor ${role} close failed`, { cause: error }));
			}
		};
		const closeDirectory = (directory: ReturnType<typeof opendirSync>, role: string): void => {
			try {
				this.closeLifecycleDirectory(directory);
			} catch (error) {
				failures.push(new Error(`Incident compactor ${role} close failed`, { cause: error }));
			}
		};
		const traversal = this.activePinTraversal;
		if (traversal?.directory) {
			const traversalFailureCount = failures.length;
			closeDirectory(traversal.directory, "active pin traversal directory");
			if (failures.length === traversalFailureCount) traversal.directory = undefined;
		}
		const pending = this.pendingPinDirectoryTraversal;
		if (pending?.directory) {
			const pendingFailureCount = failures.length;
			closeDirectory(pending.directory, "pending pin directory traversal");
			if (failures.length === pendingFailureCount) pending.directory = undefined;
		}
		const manifest = this.journalManifestValidation;
		if (manifest) {
			const manifestFailureCount = failures.length;
			closeDescriptor(manifest.descriptor, "journal manifest descriptor");
			if (manifest.pinValidation)
				closeDescriptor(manifest.pinValidation.descriptor, "journal manifest pin descriptor");
			if (failures.length === manifestFailureCount) {
				manifest.pinValidation = undefined;
				this.journalManifestValidation = undefined;
			}
		}
		const verification = this.sysdigSegmentVerification;
		if (verification) {
			const verificationFailureCount = failures.length;
			closeDescriptor(verification.descriptor, "Sysdig verification descriptor");
			if (failures.length === verificationFailureCount) this.sysdigSegmentVerification = undefined;
		}
		const sourceCapture = this.sysdigSourceCapture;
		if (sourceCapture) {
			const sourceFailureCount = failures.length;
			if (sourceCapture.sourceDescriptor !== undefined)
				closeDescriptor(sourceCapture.sourceDescriptor, "Sysdig source descriptor");
			if (sourceCapture.partialDescriptor !== undefined)
				closeDescriptor(sourceCapture.partialDescriptor, "Sysdig partial descriptor");
			if (failures.length === sourceFailureCount) this.sysdigSourceCapture = undefined;
		}
		if (failures.length === 0) {
			this.activePinTraversal = undefined;
			this.pendingPinDirectoryTraversal = undefined;
		}
		return failures;
	}

	/** Close all compactor-owned writers/readers before the normal lifecycle lease is released. */
	async closeWriterResourcesForLifecycle(deadlineMs: number): Promise<void> {
		if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1)
			throw new Error("Invalid incident compactor writer cleanup deadline");
		this.pinReadersQuiescing = true;
		this.pinReaderGeneration += 1;
		const deadlineAtMs = Date.now() + deadlineMs;
		const failures: Error[] = [];
		let childrenDrained = false;
		try {
			await this.drainCompactorChildren(deadlineAtMs);
			childrenDrained = true;
		} catch (error) {
			failures.push(error instanceof Error ? error : new Error(String(error)));
		}
		if (childrenDrained) this.discardVolatileJournalState();
		for (const state of this.runHistoryTraversals.values())
			failures.push(...this.closeRunHistoryTraversalForLifecycle(state));
		const fileFailures = this.closeLifecycleFileStates();
		failures.push(...fileFailures);
		if (fileFailures.length === 0) this.transientFileCloseFailure = undefined;
		if (failures.length === 0) {
			try {
				this.closeSegmentStore();
			} catch (error) {
				failures.push(error instanceof Error ? error : new Error(String(error)));
			}
		}
		if (failures.length > 0) {
			throw new AggregateError(failures, "Incident compactor writer resources did not quiesce");
		}
		this.lifecycleClosedDescriptors.clear();
	}

	/** Re-enable pin-reader creation only after a fresh, currently admitted normal lease is proved. */
	resumeWriterResourcesForLifecycle(): void {
		if (!this.pinReadersQuiescing) return;
		if (
			this.activeCompactorChildren.size > 0 ||
			this.activePinScans.size > 0 ||
			this.storageScanPromise ||
			this.storageScanInProgress ||
			this.segmentStore ||
			this.segmentStoreCloseUncertain ||
			this.segmentStoreCloseFailure !== undefined ||
			this.transientFileCloseFailure ||
			this.lifecycleClosedDescriptors.size > 0 ||
			this.activePinTraversal ||
			this.pendingPinDirectoryTraversal ||
			this.journalManifestValidation ||
			this.sysdigSegmentVerification ||
			this.sysdigSourceCapture ||
			this.runHistoryTraversals.size > 0 ||
			this.runHistoryPublicationCapabilities.size > 0 ||
			this.stoppedTargetStreams.size > 0 ||
			this.assemblies.size > 0 ||
			this.pendingEntries.length > 0
		)
			throw this.writerResourcesResumeError("writer_resources_not_quiescent");
		if (!this.storageAccountingReadyState || this.storageModeState !== "normal")
			throw this.writerResourcesResumeError("normal_storage_admission_not_ready");
		const admission = this.normalWriterLifecycleLease();
		if (admission.state === "unavailable") throw this.writerLifecycleAdmissionError(admission.reason);
		const revalidated = this.withRecorderRoot(() => true, admission.lease);
		if (revalidated.state === "unavailable") throw this.writerLifecycleAdmissionError(revalidated.reason);
		this.pinReadersQuiescing = false;
	}

	private writerResourcesResumeError(reason: string): Error {
		const error = new Error(`Incident compactor writer resources cannot resume: ${reason}`);
		error.name = "IncidentRecorderCompactorWriterResourcesResumeError";
		return error;
	}

	private acceptEntry(fields: JournalFields): void {
		const messageBytes = fields.MESSAGE ?? Buffer.alloc(0);
		const realCursor = optionalText(fields, "__CURSOR");
		const cursor = realCursor ?? `missing:${sha256(messageBytes)}`;
		const machineId = optionalText(fields, "_MACHINE_ID") ?? "missing";
		const bootId = optionalText(fields, "_BOOT_ID") ?? "missing";
		const invocationId = optionalText(fields, "_SYSTEMD_INVOCATION_ID");
		const streamId = optionalText(fields, "_STREAM_ID") ?? "missing";
		const realtimeUs = optionalText(fields, "__REALTIME_TIMESTAMP") ?? "missing";
		const monotonicUs = optionalText(fields, "__MONOTONIC_TIMESTAMP") ?? "missing";
		let parsed: unknown;
		try {
			parsed = JSON.parse(messageBytes.toString("utf8"));
		} catch {}
		const candidateLine = isJournalLine(parsed) ? parsed : undefined;
		if (realCursor) this.ensureDiskAdmission(messageBytes.length * 3 + 256 * 1024);
		const reference = realCursor
			? this.writeJournalReference({
					fields,
					cursor,
					machineId,
					bootId,
					invocationId,
					streamId,
					realtimeUs,
					monotonicUs,
					line: candidateLine,
					messageBytes,
				})
			: undefined;
		if (reference) {
			if (
				this.pendingEntries.length >= PENDING_ENTRY_MAX_COUNT ||
				this.pendingEntryBytes + reference.memoryBytes > PENDING_ENTRY_MAX_BYTES
			) {
				this.flushOldestIncomplete("pending_cursor_frontier_capacity_flush");
			}
			this.pendingEntries.push(reference);
			this.pendingEntryBytes += reference.memoryBytes;
			if (this.pendingEntries.length > PENDING_ENTRY_MAX_COUNT || this.pendingEntryBytes > PENDING_ENTRY_MAX_BYTES) {
				this.writeGap({
					reason: "pending_cursor_frontier_capacity_rejected",
					journalReference: reference.path,
					cursor,
				});
				reference.resolved = true;
			}
		}
		try {
			if (!realCursor || !reference) throw new Error("Journal export entry is missing __CURSOR");
			if (reference.resolved) {
				this.advanceCheckpoint();
				return;
			}
			if (optionalText(fields, "SYSLOG_IDENTIFIER") !== INCIDENT_RECORDER_JOURNAL_IDENTIFIER)
				throw new Error("Journal identifier mismatch");
			const transport = optionalText(fields, "_TRANSPORT");
			const uid = optionalText(fields, "_UID");
			if (transport !== "stdout") throw new Error("Journal transport mismatch");
			if (!uid || !/^\d+$/.test(uid)) throw new Error("Journal UID is missing or invalid");
			if (
				machineId === "missing" ||
				bootId === "missing" ||
				streamId === "missing" ||
				realtimeUs === "missing" ||
				monotonicUs === "missing"
			) {
				throw new Error("Journal identity or time field is missing");
			}
			if (!candidateLine) throw new Error("Invalid incident journal line schema");
			const line = candidateLine;
			const journalPid = optionalText(fields, "_PID");
			const normalizedIdentity = (value: string): string => value.replaceAll("-", "").toLowerCase();
			if (line.machineId === null || normalizedIdentity(line.machineId) !== normalizedIdentity(machineId))
				throw new Error("Wrapper and journal machine identity mismatch");
			if (line.bootId === null || normalizedIdentity(line.bootId) !== normalizedIdentity(bootId))
				throw new Error("Wrapper and journal boot identity mismatch");
			if (line.systemdInvocationId !== null && invocationId !== null && line.systemdInvocationId !== invocationId) {
				throw new Error("Wrapper and journal invocation identity mismatch");
			}
			if (
				!journalPid ||
				line.systemdCatPid === null ||
				String(line.systemdCatPid) !== journalPid ||
				line.systemdCatStartId === null
			) {
				throw new Error("systemd-cat trusted process identity mismatch");
			}
			const payload = strictBase64(line.payloadBase64);
			if (payload.length !== line.chunkBytes || sha256(payload) !== line.chunkSha256)
				throw new Error("Incident journal chunk checksum mismatch");
			const rebuilt = encodeIncidentRecorderFrame(
				{
					runId: line.runId,
					runToken: line.runToken,
					producerId: line.producerId,
					occurrenceId: line.occurrenceId,
					producerSequence: BigInt(line.producerSequence),
					wallTimeMs: BigInt(line.eventWallTimeMs),
					monotonicNs: BigInt(line.eventMonotonicNs),
					payloadKind: line.payloadKind,
					flags: line.flags,
					chunkIndex: line.chunkIndex,
					chunkCount: line.chunkCount,
					source: line.source,
					type: line.type,
					encoding: line.encoding,
					metadata: line.metadata,
				} satisfies Omit<IncidentRecorderFrameHeader, "version" | "payloadLength" | "checksum">,
				payload,
			);
			if (rebuilt.header.checksum !== line.frameChecksum)
				throw new Error("Incident journal frame checksum mismatch");
			this.checkSequences(line, reference);
			this.acceptChunk(line, payload, reference);
		} catch (error) {
			if (
				this.isSegmentPersistenceError(error) ||
				this.isWriterLifecycleAdmissionError(error) ||
				(error as NodeJS.ErrnoException).code === "ENOSPC"
			)
				throw error;
			this.writeGap({
				cursor,
				journalReference: reference?.path,
				reason: error instanceof Error ? error.message : String(error),
			});
			if (reference) {
				reference.resolved = true;
				this.advanceCheckpoint();
			}
		}
	}

	private writeJournalReference(input: {
		fields: JournalFields;
		cursor: string;
		machineId: string;
		bootId: string;
		invocationId: string | null;
		streamId: string;
		realtimeUs: string;
		monotonicUs: string;
		line?: IncidentJournalLine;
		messageBytes: Buffer;
	}): JournalRecordReference {
		const identity = `${input.machineId}\0${input.bootId}\0${input.invocationId ?? "missing"}\0${input.cursor}`;
		const id = sha256(identity);
		const reference: JournalRecordReference = {
			id,
			path: "",
			cursor: input.cursor,
			machineId: input.machineId,
			bootId: input.bootId,
			invocationId: input.invocationId,
			streamId: input.streamId,
			realtimeUs: input.realtimeUs,
			monotonicUs: input.monotonicUs,
			journalPid: optionalText(input.fields, "_PID"),
			uid: optionalText(input.fields, "_UID") ?? "missing",
			identifier: optionalText(input.fields, "SYSLOG_IDENTIFIER") ?? "missing",
			transport: optionalText(input.fields, "_TRANSPORT") ?? "missing",
			wrapperSequence: input.line?.wrapperSequence ?? "unknown",
			producerSequence: input.line?.producerSequence ?? "unknown",
			chunkIndex: input.line?.chunkIndex ?? -1,
			chunkCount: input.line?.chunkCount ?? -1,
			bytes: 0,
			memoryBytes: 0,
			resolved: false,
		};
		const persisted = {
			...reference,
			path: undefined,
			resolved: undefined,
			memoryBytes: undefined,
			runId: input.line?.runId,
			producerId: input.line?.producerId,
			occurrenceId: input.line?.occurrenceId,
			source: input.line?.source,
			type: input.line?.type,
			chunkSha256: input.line?.chunkSha256,
			frameChecksum: input.line?.frameChecksum,
			wrapperPid: input.line?.wrapperPid,
			wrapperStartId: input.line?.wrapperStartId,
			systemdCatPid: input.line?.systemdCatPid,
			systemdCatStartId: input.line?.systemdCatStartId,
			messageSha256: sha256(input.messageBytes),
			messageBytes: input.messageBytes.length,
			messageMirrored: false,
			validationDisposition: input.line ? "schema-recognized-payload-validation-pending" : "schema-unrecognized",
			invocationIdentityDisposition:
				input.invocationId === null
					? "trusted_journal_invocation_absent"
					: !input.line || input.line.systemdInvocationId === null
						? "wrapper_envelope_invocation_absent_or_unknown"
						: "both_present_and_equal",
		};
		const metadataBytes = Buffer.from(`${JSON.stringify(persisted)}\n`, "utf8");
		// Journal retention is not a durable content reference. Keep the exact
		// arbitrary MESSAGE bytes beside the immutable metadata in a bounded,
		// length-delimited envelope so incident reconstruction does not depend on
		// the source journal still containing this cursor.
		const envelopeHeader = Buffer.allocUnsafe(16);
		envelopeHeader.write("GRJR", 0, 4, "ascii");
		envelopeHeader.writeUInt8(1, 4);
		envelopeHeader.writeUInt8(0, 5);
		envelopeHeader.writeUInt16BE(0, 6);
		envelopeHeader.writeUInt32BE(metadataBytes.length, 8);
		envelopeHeader.writeUInt32BE(input.messageBytes.length, 12);
		const payload = Buffer.concat([envelopeHeader, metadataBytes, input.messageBytes]);
		const wrapperSequence = input.line?.wrapperSequence;
		const locator = this.appendSegmentRecord({
			idempotencyKey: `journal:${id}`,
			runId: input.line?.runId ?? "__journal__",
			sourceId: SEGMENT_SOURCE_JOURNAL_REFERENCE,
			observedAtMs: segmentObservedAtMsOrZero(input.realtimeUs, 1_000n),
			order: isUnsigned64(wrapperSequence) ? wrapperSequence : "0",
			metadata: {
				version: 1,
				journalReferenceId: id,
				cursorSha256: sha256(input.cursor),
			},
			payload,
		});
		reference.path = this.segmentReference(locator);
		reference.bytes = payload.length;
		reference.memoryBytes = retainedBytes(reference);
		return reference;
	}
	private checkSequences(line: IncidentJournalLine, reference: JournalRecordReference): void {
		// A journal stream and its systemd-cat PID change on reconnect. Keep those
		// values on each immutable record, but continuity must follow the stable
		// wrapper/run identity so losses between stream generations remain visible.
		const continuityKey = `${reference.machineId}\0${reference.bootId}\0${reference.uid}\0${reference.identifier}\0${reference.transport}\0${line.runId}\0${line.runToken}\0${line.wrapperPid}\0${line.wrapperStartId ?? "missing"}`;
		const wrapperKey = `${continuityKey}\0wrapper`;
		const wrapper = BigInt(line.wrapperSequence);
		const previousPendingWrapper = [...this.pendingEntries]
			.reverse()
			.find((entry) => entry.sequenceUpdates?.wrapperKey === wrapperKey)?.sequenceUpdates?.wrapper;
		const previousWrapper =
			previousPendingWrapper === undefined ? this.wrapperSequences.get(wrapperKey) : BigInt(previousPendingWrapper);
		if (previousWrapper !== undefined && wrapper !== previousWrapper + 1n) {
			if (wrapper <= previousWrapper) throw new Error("Wrapper sequence replay or backward reorder");
			this.writeGap({
				reason: "wrapper_sequence_gap",
				runId: line.runId,
				runToken: line.runToken,
				streamKeyHash: sha256(continuityKey),
				wrapperPid: line.wrapperPid,
				wrapperStartId: line.wrapperStartId,
				expectedWrapperFrom: (previousWrapper + 1n).toString(),
				expectedWrapperThrough: (wrapper - 1n).toString(),
				observedWrapperSequence: wrapper.toString(),
			});
		}
		const producerKey = `${continuityKey}\0producer\0${line.producerId}`;
		const producer = BigInt(line.producerSequence);
		const previousPendingProducer = [...this.pendingEntries]
			.reverse()
			.find((entry) => entry.sequenceUpdates?.producerKey === producerKey)?.sequenceUpdates?.producer;
		const previousProducer =
			previousPendingProducer === undefined
				? this.producerSequences.get(producerKey)
				: BigInt(previousPendingProducer);
		if (previousProducer !== undefined && producer !== previousProducer + 1n) {
			if (producer <= previousProducer) throw new Error("Producer sequence replay or backward reorder");
			this.writeGap({
				reason: "producer_sequence_gap",
				runId: line.runId,
				runToken: line.runToken,
				producerId: line.producerId,
				streamKeyHash: sha256(continuityKey),
				expectedProducerFrom: (previousProducer + 1n).toString(),
				expectedProducerThrough: (producer - 1n).toString(),
				observedProducerSequence: producer.toString(),
			});
		}
		const beforeMemory = reference.memoryBytes;
		reference.sequenceUpdates = {
			wrapperKey,
			wrapper: wrapper.toString(),
			producerKey,
			producer: producer.toString(),
		};
		reference.memoryBytes = retainedBytes(reference);
		this.pendingEntryBytes += reference.memoryBytes - beforeMemory;
		while (this.pendingEntryBytes > PENDING_ENTRY_MAX_BYTES && this.assemblies.size > 0) {
			this.flushOldestIncomplete("pending_sequence_frontier_byte_flush");
		}
		if (this.pendingEntryBytes > PENDING_ENTRY_MAX_BYTES)
			throw new Error("Pending sequence frontier exceeded its retained byte bound");
	}

	private setBoundedSequence(map: Map<string, bigint>, key: string, value: bigint): void {
		if (!map.has(key) && map.size >= SEQUENCE_TRACKER_MAX_KEYS) {
			const oldest = map.keys().next().value as string | undefined;
			if (oldest) {
				map.delete(oldest);
				this.writeGap({ reason: "sequence_tracker_capacity_eviction", keyHash: sha256(oldest) });
			}
		}
		map.delete(key);
		map.set(key, value);
	}

	private acceptChunk(line: IncidentJournalLine, payload: Buffer, reference: JournalRecordReference): void {
		const trustedStream = `${reference.machineId}\0${reference.bootId}\0${reference.streamId}\0${reference.uid}\0${reference.identifier}\0${reference.transport}\0${reference.journalPid ?? "missing"}`;
		const identity = `${trustedStream}\0${line.runId}\0${line.runToken}\0${line.wrapperPid}\0${line.wrapperStartId ?? "missing"}\0${line.producerId}\0${line.occurrenceId}`;
		const now = Date.now();
		for (const [key, candidate] of [...this.assemblies]) {
			if (now > candidate.deadlineMs) this.flushIncomplete(key, "occurrence_assembly_deadline_exceeded");
		}
		let assembly = this.assemblies.get(identity);
		if (!assembly) {
			if (line.chunkIndex !== 0) throw new Error("Occurrence did not start with chunk zero");
			while (this.assemblies.size >= ASSEMBLY_MAX_COUNT)
				this.flushOldestIncomplete("occurrence_assembly_global_count_flush");
			const lineBytes = retainedBytes(line);
			while (
				this.assemblies.size > 0 &&
				this.assemblyBytes + lineBytes + payload.length + reference.memoryBytes > ASSEMBLY_MAX_BYTES
			) {
				this.flushOldestIncomplete("occurrence_assembly_global_byte_flush");
			}
			if (lineBytes + payload.length + reference.memoryBytes > ASSEMBLY_MAX_BYTES)
				throw new Error("Occurrence assembly entry exceeds global byte bound");
			const flushOnTimeout = (): void => {
				try {
					this.flushIncomplete(identity, "occurrence_assembly_idle_timeout");
				} catch {
					const pending = this.assemblies.get(identity);
					if (!pending) return;
					pending.deadlineMs = Date.now() + ASSEMBLY_DEADLINE_MS;
					pending.timer = setTimeout(flushOnTimeout, ASSEMBLY_DEADLINE_MS);
					pending.timer.unref();
				}
			};
			const timer = setTimeout(flushOnTimeout, ASSEMBLY_DEADLINE_MS);
			timer.unref();
			assembly = {
				identity,
				line,
				chunks: [],
				references: [],
				bytes: 0,
				memoryBytes: lineBytes,
				deadlineMs: now + ASSEMBLY_DEADLINE_MS,
				timer,
			};
			this.assemblies.set(identity, assembly);
			this.assemblyBytes += lineBytes;
		}
		const semanticFlags = INCIDENT_RECORDER_FRAME_FLAGS.critical | INCIDENT_RECORDER_FRAME_FLAGS.terminal;
		const fixedHeader =
			line.runId === assembly.line.runId &&
			line.runToken === assembly.line.runToken &&
			line.producerId === assembly.line.producerId &&
			line.occurrenceId === assembly.line.occurrenceId &&
			line.source === assembly.line.source &&
			line.type === assembly.line.type &&
			line.encoding === assembly.line.encoding &&
			line.payloadKind === assembly.line.payloadKind &&
			line.chunkCount === assembly.line.chunkCount &&
			line.occurrenceSha256 === assembly.line.occurrenceSha256 &&
			line.rawOccurrenceBytes === assembly.line.rawOccurrenceBytes &&
			line.eventWallTimeMs === assembly.line.eventWallTimeMs &&
			line.eventMonotonicNs === assembly.line.eventMonotonicNs &&
			(line.flags & semanticFlags) === (assembly.line.flags & semanticFlags) &&
			line.wrapperPid === assembly.line.wrapperPid &&
			line.wrapperStartId === assembly.line.wrapperStartId &&
			line.systemdCatPid === assembly.line.systemdCatPid &&
			line.systemdCatStartId === assembly.line.systemdCatStartId &&
			JSON.stringify(line.metadata) === JSON.stringify(assembly.line.metadata);
		const expectedIndex = assembly.chunks.length;
		const firstProducer = BigInt(assembly.line.producerSequence);
		const firstWrapper = BigInt(assembly.line.wrapperSequence);
		if (
			!fixedHeader ||
			line.chunkIndex !== expectedIndex ||
			BigInt(line.producerSequence) !== firstProducer + BigInt(expectedIndex) ||
			BigInt(line.wrapperSequence) !== firstWrapper + BigInt(expectedIndex)
		) {
			this.flushIncomplete(identity, "inconsistent_or_noncontiguous_occurrence_header");
			throw new Error("Inconsistent or noncontiguous occurrence header");
		}
		if (assembly.bytes + payload.length > 983_040 || assembly.chunks.length >= 40) {
			this.flushIncomplete(identity, "occurrence_assembly_capacity_exceeded");
			throw new Error("Occurrence assembly capacity exceeded");
		}
		const addedMemory = payload.length + reference.memoryBytes;
		while (this.assemblies.size > 1 && this.assemblyBytes + addedMemory > ASSEMBLY_MAX_BYTES) {
			this.flushOldestIncomplete("occurrence_assembly_global_byte_flush", identity);
		}
		if (this.assemblyBytes + addedMemory > ASSEMBLY_MAX_BYTES) {
			this.flushIncomplete(identity, "occurrence_assembly_global_byte_rejected");
			throw new Error("Occurrence assembly exceeded global byte bound");
		}
		assembly.references.push(reference);
		assembly.chunks.push(payload);
		assembly.bytes += payload.length;
		assembly.memoryBytes += addedMemory;
		this.assemblyBytes += addedMemory;
		if (assembly.chunks.length !== line.chunkCount) return;
		const value = Buffer.concat(assembly.chunks, assembly.bytes);
		if (value.length !== line.rawOccurrenceBytes || sha256(value) !== line.occurrenceSha256) {
			this.flushIncomplete(identity, "occurrence_checksum_or_length_mismatch");
			throw new Error("Occurrence checksum or length mismatch");
		}
		let segmentReceipts: readonly IncidentRecorderSegmentRootReceipt[] = [];
		let mutation: RecorderRootMutationResult<{ effects: StorageAccountingEffect[] }>;
		try {
			mutation = this.withRecorderRoot((root, assertCurrent) => {
				const effects: StorageAccountingEffect[] = [];
				const { casPath } = this.publishCasAndRunLease(
					root,
					{
						runId: line.runId,
						digest: line.occurrenceSha256,
						bytes: value.length,
						value,
					},
					effects,
				);
				const occurrenceId = sha256(`${line.runId}\0${line.runToken}\0${line.producerId}\0${line.occurrenceId}`);
				const occurrenceRecord = {
					version: 1,
					state: "complete",
					identity: {
						runId: line.runId,
						runToken: line.runToken,
						producerId: line.producerId,
						occurrenceId: line.occurrenceId,
					},
					source: line.source,
					type: line.type,
					encoding: line.encoding,
					payloadKind: line.payloadKind,
					terminal: (line.flags & INCIDENT_RECORDER_FRAME_FLAGS.terminal) !== 0,
					metadata: line.metadata,
					eventWallTimeMs: line.eventWallTimeMs,
					eventMonotonicNs: line.eventMonotonicNs,
					transportIdentity: {
						wrapperPid: line.wrapperPid,
						wrapperStartId: line.wrapperStartId,
						targetPid: line.targetPid,
						targetStartId: line.targetStartId,
						machineId: reference.machineId,
						bootId: reference.bootId,
						journalStreamId: reference.streamId,
						journalInvocationId: reference.invocationId,
						invocationIdentityDisposition:
							reference.invocationId === null
								? "trusted_journal_invocation_absent"
								: line.systemdInvocationId === null
									? "wrapper_envelope_invocation_absent"
									: "both_present_and_equal",
						systemdCatPid: line.systemdCatPid,
						systemdCatStartId: line.systemdCatStartId,
						journalPresence: "journal_export_observed",
					},
					wrapperOrder: assembly.references.map((entry) => entry.wrapperSequence),
					producerOrder: assembly.references.map((entry) => entry.producerSequence),
					cursors: assembly.references.map((entry) => entry.cursor),
					journalReferences: assembly.references.map((entry) => entry.path),
					cas: {
						algorithm: "sha256",
						digest: line.occurrenceSha256,
						bytes: value.length,
						path: casPath,
						compression: "none",
						resolution: "verified",
					},
					compactionDisposition: "compacted_and_cas_resolved",
					journalCanonicalUntilCompactionCommit: true,
				};
				const firstWrapperSequence = assembly.references[0]?.wrapperSequence ?? "0";
				// This retained-store call is the final unresolved segment lifecycle
				// seam. It is replaced by the CAS-owned one-shot domain operation once
				// the shared writer/read lifecycle has crossed that boundary.
				// CAS publication hooks may replace/revoke the lifecycle root. Recheck
				// before the segment mutation so a detached callback cannot leave a
				// segment in either the old or successor namespace.
				assertCurrent();
				this.appendSegmentRecordWithinRoot(
					root,
					{
						idempotencyKey: `occurrence:${occurrenceId}`,
						runId: line.runId,
						sourceId: SEGMENT_SOURCE_OCCURRENCE,
						observedAtMs: segmentObservedAtMs(line.eventWallTimeMs),
						order: isUnsigned64(firstWrapperSequence) ? firstWrapperSequence : "0",
						metadata: {
							version: 1,
							state: "complete",
							occurrenceIdentity: occurrenceId,
							casDigest: line.occurrenceSha256,
						},
						payload: Buffer.from(`${JSON.stringify(occurrenceRecord)}\n`, "utf8"),
					},
					(estimate) => {
						this.reserveStorage(
							estimate.peakAdditionalAllocatedBytes,
							estimate.peakAdditionalEntries,
							estimate.peakAdditionalInodes,
						);
						this.segmentRootAppendReservation = {
							bytes: estimate.peakAdditionalAllocatedBytes,
							entries: estimate.peakAdditionalEntries,
							inodes: estimate.peakAdditionalInodes,
						};
					},
				);
				if (this.segmentStore) segmentReceipts = this.segmentStore.drainWithinRootReceipts();
				return { effects };
			});
		} catch (error) {
			if (this.isWriterLifecycleAdmissionError(error) || this.isSegmentPersistenceError(error)) {
				// The failure may occur before the lazy store is constructed (for
				// example, after CAS publication but before segment admission). The
				// absence of an instance is still a failed root mutation: invalidate
				// accounting and force recovery-only until reconciliation.
				this.discardSegmentStoreAfterRootFailure("operation_failed");
				this.rollbackOccurrenceChunk(identity, assembly, reference, payload);
			}
			this.releaseSegmentRootReservations();
			throw error;
		}
		if (mutation.state !== "committed") {
			const error = this.writerLifecycleAdmissionError(mutation.reason);
			this.discardSegmentStoreAfterRootFailure(mutation.reason);
			this.releaseSegmentRootReservations();
			this.rollbackOccurrenceChunk(identity, assembly, reference, payload);
			throw error;
		}
		try {
			this.applyStorageAccountingEffects(mutation.value.effects);
			this.applySegmentRootReceipts(segmentReceipts);
			this.assertSegmentAccountingReadyAfterRootReceipt();
		} catch (error) {
			this.discardSegmentStoreAfterRootFailure("receipt_application_failed");
			throw error;
		} finally {
			if (this.segmentRootOpenReservation) {
				this.releaseReservedCapacity(
					this.segmentRootOpenReservation.bytes,
					this.segmentRootOpenReservation.entries,
					this.segmentRootOpenReservation.inodes,
				);
				this.segmentRootOpenReservation = undefined;
			}
			if (this.segmentRootAppendReservation) {
				this.releaseReservedCapacity(
					this.segmentRootAppendReservation.bytes,
					this.segmentRootAppendReservation.entries,
					this.segmentRootAppendReservation.inodes,
				);
				this.segmentRootAppendReservation = undefined;
			}
		}
		this.removeAssembly(identity);
		for (const entry of assembly.references) entry.resolved = true;
		this.advanceCheckpoint();
		this.processPendingPins();
	}

	private rollbackOccurrenceChunk(
		identity: string,
		assembly: Assembly,
		reference: JournalRecordReference,
		payload: Buffer,
	): void {
		const lastReference = assembly.references[assembly.references.length - 1];
		const lastChunk = assembly.chunks[assembly.chunks.length - 1];
		if (lastReference !== reference || lastChunk !== payload || this.assemblies.get(identity) !== assembly) return;
		assembly.references.pop();
		assembly.chunks.pop();
		assembly.bytes = Math.max(0, assembly.bytes - payload.length);
		const removedMemory = payload.length + reference.memoryBytes;
		assembly.memoryBytes = Math.max(0, assembly.memoryBytes - removedMemory);
		this.assemblyBytes = Math.max(0, this.assemblyBytes - removedMemory);
		const pendingIndex = this.pendingEntries.lastIndexOf(reference);
		if (pendingIndex >= 0) {
			this.pendingEntries.splice(pendingIndex, 1);
			this.pendingEntryBytes = Math.max(0, this.pendingEntryBytes - reference.memoryBytes);
		}
	}

	private removeAssembly(identity: string): Assembly | undefined {
		const assembly = this.assemblies.get(identity);
		if (!assembly) return undefined;
		clearTimeout(assembly.timer);
		this.assemblies.delete(identity);
		this.assemblyBytes = Math.max(0, this.assemblyBytes - assembly.memoryBytes);
		return assembly;
	}

	private flushOldestIncomplete(reason: string, excludeIdentity?: string): void {
		const oldest = [...this.assemblies.keys()].find((identity) => identity !== excludeIdentity);
		if (oldest) this.flushIncomplete(oldest, reason);
	}

	private flushAllIncomplete(reason: string): void {
		let hasFlushError = false;
		let flushError: unknown;
		for (const identity of [...this.assemblies.keys()]) {
			try {
				this.flushIncomplete(identity, reason);
			} catch (error) {
				if (hasFlushError) continue;
				hasFlushError = true;
				flushError = error;
			}
		}
		if (hasFlushError) throw flushError;
	}

	private flushIncomplete(identity: string, reason: string): void {
		const assembly = this.assemblies.get(identity);
		if (!assembly) return;
		const id = sha256(
			`${assembly.identity}\0${reason}\0${assembly.references.map((entry) => entry.cursor).join("\0")}`,
		);
		const incompleteRecord = {
			version: 1,
			state: "incomplete",
			reason,
			type: assembly.line.type,
			terminal: (assembly.line.flags & INCIDENT_RECORDER_FRAME_FLAGS.terminal) !== 0,
			identity: {
				runId: assembly.line.runId,
				runToken: assembly.line.runToken,
				producerId: assembly.line.producerId,
				occurrenceId: assembly.line.occurrenceId,
			},
			expectedChunks: assembly.line.chunkCount,
			observedChunks: assembly.chunks.map((_chunk, index) => index),
			observedBytes: assembly.bytes,
			cursors: assembly.references.map((entry) => entry.cursor),
			wrapperOrder: assembly.references.map((entry) => entry.wrapperSequence),
			producerOrder: assembly.references.map((entry) => entry.producerSequence),
			compactionDisposition: "durable_segment_incomplete_record",
		};
		const firstWrapper = assembly.references[0]?.wrapperSequence ?? "0";
		this.appendSegmentRecord({
			idempotencyKey: `incomplete:${id}`,
			runId: assembly.line.runId,
			sourceId: SEGMENT_SOURCE_INCOMPLETE,
			observedAtMs: segmentObservedAtMs(assembly.line.eventWallTimeMs),
			order: isUnsigned64(firstWrapper) ? firstWrapper : "0",
			metadata: { version: 1, state: "incomplete", incompleteIdentity: id, reason },
			payload: Buffer.from(`${JSON.stringify(incompleteRecord)}\n`, "utf8"),
		});
		this.removeAssembly(identity);
		for (const entry of assembly.references) entry.resolved = true;
		this.advanceCheckpoint();
	}

	private advanceCheckpoint(): void {
		for (;;) {
			const entry = this.pendingEntries[0];
			if (!entry?.resolved) return;
			const previousWrappers = new Map(this.wrapperSequences);
			const previousProducers = new Map(this.producerSequences);
			try {
				if (entry.sequenceUpdates) {
					this.setBoundedSequence(
						this.wrapperSequences,
						entry.sequenceUpdates.wrapperKey,
						BigInt(entry.sequenceUpdates.wrapper),
					);
					this.setBoundedSequence(
						this.producerSequences,
						entry.sequenceUpdates.producerKey,
						BigInt(entry.sequenceUpdates.producer),
					);
				}
				this.commitCursor(entry.cursor, entry.machineId, entry.bootId, entry.invocationId, entry.realtimeUs);
			} catch (error) {
				this.wrapperSequences.clear();
				for (const [key, value] of previousWrappers) this.wrapperSequences.set(key, value);
				this.producerSequences.clear();
				for (const [key, value] of previousProducers) this.producerSequences.set(key, value);
				throw error;
			}
			this.pendingEntries.shift();
			this.pendingEntryBytes = Math.max(0, this.pendingEntryBytes - entry.memoryBytes);
		}
	}
	private writeGap(value: unknown): void {
		const serialized = JSON.stringify(value) ?? "null";
		const id = sha256(serialized);
		const evidence =
			value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
		const runId =
			typeof evidence.runId === "string" && isCanonicalUuid(evidence.runId) ? evidence.runId : "__recorder__";
		const sequence =
			typeof evidence.expectedWrapperFrom === "string" && isUnsigned64(evidence.expectedWrapperFrom)
				? evidence.expectedWrapperFrom
				: typeof evidence.observedWrapperSequence === "string" && isUnsigned64(evidence.observedWrapperSequence)
					? evidence.observedWrapperSequence
					: "0";
		const reason = typeof evidence.reason === "string" ? evidence.reason : "unspecified_uncertainty";
		this.appendSegmentRecord({
			idempotencyKey: `gap:${id}`,
			runId,
			sourceId: SEGMENT_SOURCE_GAP,
			observedAtMs: 0,
			order: sequence,
			metadata: { version: 1, state: "gap_or_uncertainty", gapIdentity: id, reason },
			payload: Buffer.from(
				`${JSON.stringify({ version: 1, state: "gap_or_uncertainty", evidence: value })}\n`,
				"utf8",
			),
		});
	}

	private commitCursor(
		cursor: string,
		machineId: string,
		bootId: string,
		invocationId: string | null,
		realtimeUs: string,
	): void {
		const wrapperSequences: Record<string, string> = {};
		for (const [key, value] of this.wrapperSequences) wrapperSequences[key] = value.toString();
		const producerSequences: Record<string, string> = {};
		for (const [key, value] of this.producerSequences) producerSequences[key] = value.toString();
		const checkpoint: CursorCheckpoint = {
			version: 1,
			cursor,
			machineId,
			bootId,
			invocationId,
			lastRealtimeUs: realtimeUs,
			wrapperSequences,
			producerSequences,
		};
		this.writeOwnedCheckpoint(this.checkpointPath, checkpoint);
		this.checkpoint = checkpoint;
		this.checkpointDisposition = "valid";
	}

	private writeProviderPinIncomplete(
		incidentDir: string,
		provider: "journal" | "sysdig",
		reason: string,
		request: {
			runId: string;
			anchorWallTimeMs: number;
			fromWallTimeMs: number;
			throughWallTimeMs: number;
		},
	): void {
		const path = join(incidentDir, `${provider}-pin-incomplete.json`);
		const value = {
			version: 1,
			state: "pending_or_incomplete",
			provider,
			reason: boundedNonemptyUtf8(reason, 4 * 1024, "unspecified_provider_pin_incomplete"),
			runId: request.runId,
			anchorWallTimeMs: request.anchorWallTimeMs,
			fromWallTimeMs: request.fromWallTimeMs,
			throughWallTimeMs: request.throughWallTimeMs,
		};
		if (existsSync(path)) {
			let matchesRequest = false;
			try {
				const metadata = lstatSync(path);
				const expectedUid = typeof process.getuid === "function" ? process.getuid() : metadata.uid;
				const existing = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
				matchesRequest =
					metadata.isFile() &&
					!metadata.isSymbolicLink() &&
					metadata.nlink === 1 &&
					metadata.uid === expectedUid &&
					(metadata.mode & 0o077) === 0 &&
					metadata.size <= 64 * 1024 &&
					hasExactOwnKeys(existing, [
						"version",
						"state",
						"provider",
						"reason",
						"runId",
						"anchorWallTimeMs",
						"fromWallTimeMs",
						"throughWallTimeMs",
					]) &&
					existing.version === 1 &&
					existing.state === "pending_or_incomplete" &&
					existing.provider === provider &&
					typeof existing.reason === "string" &&
					existing.reason.length > 0 &&
					Buffer.byteLength(existing.reason, "utf8") <= 4 * 1024 &&
					existing.runId === request.runId &&
					existing.anchorWallTimeMs === request.anchorWallTimeMs &&
					existing.fromWallTimeMs === request.fromWallTimeMs &&
					existing.throughWallTimeMs === request.throughWallTimeMs;
			} catch {}
			if (matchesRequest) {
				const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
				try {
					fsyncSync(descriptor);
				} finally {
					closeSync(descriptor);
				}
				fsyncDirectory(incidentDir);
				return;
			}
			this.quarantineInvalidProviderIncomplete(incidentDir, provider, path);
		}
		this.writeOwnedJson(path, value, 64 * 1024);
	}

	private journalArtifactGenerationId(request: {
		runId: string;
		anchorWallTimeMs: number;
		fromWallTimeMs: number;
		throughWallTimeMs: number;
	}): string {
		return sha256(
			canonicalJson({
				provider: "journal",
				runId: request.runId,
				anchorWallTimeMs: request.anchorWallTimeMs,
				fromWallTimeMs: request.fromWallTimeMs,
				throughWallTimeMs: request.throughWallTimeMs,
			}),
		);
	}

	private sysdigArtifactGenerationId(requestFingerprint: string): string {
		return sha256(canonicalJson({ provider: "sysdig", requestFingerprint }));
	}

	private sealPrivateArtifact(
		path: string,
		expectedBytes: number,
		expectedSha256: string,
		generationId: string,
	): SealedArtifact {
		let metadata = lstatSync(path);
		const expectedUid = typeof process.getuid === "function" ? process.getuid() : metadata.uid;
		if (
			!metadata.isFile() ||
			metadata.isSymbolicLink() ||
			metadata.nlink !== 1 ||
			metadata.uid !== expectedUid ||
			(metadata.mode & 0o077) !== 0 ||
			metadata.size !== expectedBytes
		)
			throw new Error("provider_pin_artifact_not_private_regular_copy");
		if ((metadata.mode & 0o777) !== 0o400) {
			chmodSync(path, 0o400);
			const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
			try {
				fsyncSync(descriptor);
			} finally {
				closeSync(descriptor);
			}
			fsyncDirectory(dirname(path));
			metadata = lstatSync(path);
		}
		if (
			!metadata.isFile() ||
			metadata.isSymbolicLink() ||
			metadata.nlink !== 1 ||
			metadata.uid !== expectedUid ||
			(metadata.mode & 0o777) !== 0o400 ||
			metadata.size !== expectedBytes
		)
			throw new Error("provider_pin_artifact_seal_failed");
		return {
			version: 1,
			state: "sealed_private_copy",
			generationId,
			dev: String(metadata.dev),
			ino: String(metadata.ino),
			bytes: expectedBytes,
			mtimeMs: metadata.mtimeMs,
			ctimeMs: metadata.ctimeMs,
			mode: 0o400,
			nlink: 1,
			sha256: expectedSha256,
		};
	}

	private materializeJournalPinArtifact(
		source: string,
		target: string,
		expectedBytes: number,
		expectedSha256: string,
		generationId: string,
	): SealedArtifact {
		const sourceBefore = lstatSync(source);
		if (
			!sourceBefore.isFile() ||
			sourceBefore.isSymbolicLink() ||
			sourceBefore.size !== expectedBytes ||
			expectedBytes > 983_040
		)
			throw new Error("journal_pin_source_identity_or_size_invalid");
		const bytes = readFileSync(source);
		const sourceAfter = lstatSync(source);
		if (
			sourceAfter.dev !== sourceBefore.dev ||
			sourceAfter.ino !== sourceBefore.ino ||
			sourceAfter.size !== sourceBefore.size ||
			sourceAfter.mtimeMs !== sourceBefore.mtimeMs ||
			bytes.length !== expectedBytes ||
			sha256(bytes) !== expectedSha256
		)
			throw new Error("journal_pin_source_changed_or_digest_mismatched");
		let targetValid = false;
		try {
			const existing = lstatSync(target);
			const expectedUid = typeof process.getuid === "function" ? process.getuid() : existing.uid;
			targetValid =
				existing.isFile() &&
				!existing.isSymbolicLink() &&
				existing.nlink === 1 &&
				existing.uid === expectedUid &&
				(existing.mode & 0o077) === 0 &&
				existing.size === expectedBytes &&
				sha256(readFileSync(target)) === expectedSha256;
			if (!targetValid) {
				rmSync(target);
				this.accountRemovedStorageEntry(existing, true);
				fsyncDirectory(dirname(target));
			}
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		if (!targetValid) {
			this.ensureDiskAdmission(expectedBytes + 64 * 1024);
			writeImmutable(target, bytes);
			this.accountStoragePath(target);
		}
		return this.sealPrivateArtifact(target, expectedBytes, expectedSha256, generationId);
	}

	private startPinRangeScan(
		incidentDir: string,
		request: {
			runId: string;
			anchorWallTimeMs: number;
			fromWallTimeMs: number;
			throughWallTimeMs: number;
		},
	): void {
		const proofPath = join(incidentDir, "journal-pin-scan-proof.json");
		if (
			this.pinReadersQuiescing ||
			existsSync(proofPath) ||
			this.activePinScans.has(incidentDir) ||
			this.activePinScans.size >= 1
		)
			return;
		const child = spawn(
			this.options.journalctlPath ?? "journalctl",
			[
				`--namespace=${INCIDENT_RECORDER_JOURNAL_NAMESPACE}`,
				`--identifier=${INCIDENT_RECORDER_JOURNAL_IDENTIFIER}`,
				"--output=export",
				"--all",
				"--no-pager",
				`--since=@${(request.fromWallTimeMs / 1_000).toFixed(3)}`,
				`--until=@${(request.throughWallTimeMs / 1_000).toFixed(3)}`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const cursors = new Set<string>();
		let cursorBytes = 0;
		const parser = new JournalExportParser((fields) => {
			const cursor = optionalText(fields, "__CURSOR");
			let parsed: unknown;
			try {
				parsed = JSON.parse((fields.MESSAGE ?? Buffer.alloc(0)).toString("utf8"));
			} catch {}
			if (!cursor || !isJournalLine(parsed) || parsed.runId !== request.runId || cursors.has(cursor)) return;
			const added = Buffer.byteLength(cursor);
			if (cursors.size >= PIN_CURSOR_MAX_COUNT || cursorBytes + added > PIN_CURSOR_MAX_BYTES) {
				throw new Error("Pin range scan cursor heap exceeded its bound");
			}
			cursors.add(cursor);
			cursorBytes += added;
		});
		let error: Error | undefined;
		let bytes = 0;
		let killTimer: ReturnType<typeof setTimeout> | undefined;
		let resolveCompletion: () => void = () => {};
		const completion = new Promise<void>((resolve) => {
			resolveCompletion = resolve;
		});
		const tracked: ActivePinScan = {
			incidentDir,
			generation: this.pinReaderGeneration,
			cancelled: false,
			child,
			completion,
			terminate: () => {},
		};
		const terminate = (): void => {
			try {
				child.kill("SIGTERM");
			} catch {}
			if (killTimer) return;
			killTimer = setTimeout(() => {
				try {
					if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
				} catch {}
			}, 250);
			killTimer.unref();
		};
		tracked.terminate = terminate;
		this.activePinScans.set(incidentDir, tracked);
		this.activeCompactorChildren.add(tracked);
		const deadlineTimer = setTimeout(() => {
			error ??= new Error("Pin range scan exceeded its process deadline");
			terminate();
		}, PIN_SCAN_DEADLINE_MS);
		deadlineTimer.unref();
		child.stdout?.on("data", (chunk: Buffer) => {
			bytes += chunk.length;
			if (bytes > PENDING_ENTRY_MAX_BYTES) {
				error = new Error("Pin range scan exceeded its byte bound");
				terminate();
				return;
			}
			try {
				parser.push(chunk);
			} catch (caught) {
				error = caught instanceof Error ? caught : new Error(String(caught));
				terminate();
			}
		});
		child.once("error", (caught) => {
			error = caught;
		});
		child.once("close", (code) => {
			clearTimeout(deadlineTimer);
			if (killTimer) clearTimeout(killTimer);
			if (this.activePinScans.get(incidentDir) === tracked) this.activePinScans.delete(incidentDir);
			this.activeCompactorChildren.delete(tracked);
			try {
				parser.finish();
			} catch (caught) {
				error ??= caught instanceof Error ? caught : new Error(String(caught));
			}
			if (tracked.cancelled || tracked.generation !== this.pinReaderGeneration) {
				resolveCompletion();
				return;
			}
			if (code !== 0 || error) {
				try {
					this.writeProviderPinIncomplete(
						incidentDir,
						"journal",
						error?.message ?? `journalctl_exit_${code ?? "unknown"}`,
						request,
					);
				} catch {}
				return;
			}
			try {
				this.writeOwnedJson(proofPath, {
					version: 1,
					state: "fixed_range_namespace_scan_complete",
					runId: request.runId,
					fromWallTimeMs: request.fromWallTimeMs,
					throughWallTimeMs: request.throughWallTimeMs,
					journalEntries: [...cursors],
					readBytes: bytes,
				});
			} catch {}
			resolveCompletion();
		});
	}

	private sysdigRequestPath(incidentDir: string): string {
		return join(incidentDir, "sysdig-pin-request.json");
	}

	private journalRequestPath(incidentDir: string): string {
		return join(incidentDir, "journal-pin-request.json");
	}

	private pinAuthorityPath(incidentDir: string): string {
		return join(incidentDir, "incident-pin-authority.json");
	}

	private sysdigInitialCompletePath(incidentDir: string): string {
		return join(incidentDir, "sysdig-pins", "initial-capture-complete.json");
	}

	private sysdigCapturePlanPath(incidentDir: string, phase: "initial" | "final"): string {
		return join(incidentDir, "sysdig-pins", `${phase}-capture-plan.json`);
	}

	private sysdigFinalCaptureCompletePath(incidentDir: string): string {
		return join(incidentDir, "sysdig-pins", "final-capture-complete.json");
	}

	private sysdigFinalPlanPath(incidentDir: string): string {
		return join(incidentDir, "sysdig-pins", "final-verification-plan.json");
	}

	private sysdigFinalVerificationPath(incidentDir: string, recordId: string): string {
		return join(incidentDir, "sysdig-pins", "final-verifications", `${recordId}.json`);
	}

	private sysdigCaptureGapPath(
		incidentDir: string,
		phase: "initial" | "rotated" | "final",
		candidateId: string,
	): string {
		return join(incidentDir, "sysdig-pins", `${phase}-capture-gaps`, `${candidateId}.json`);
	}

	private sysdigRequestFingerprint(request: SysdigPinRequest): string {
		return sha256(
			canonicalJson({
				version: request.version,
				runId: request.runId,
				anchorWallTimeMs: request.anchorWallTimeMs,
				fromWallTimeMs: request.fromWallTimeMs,
				throughWallTimeMs: request.throughWallTimeMs,
				resolveAfterWallTimeMs: request.resolveAfterWallTimeMs,
				retainUntilWallTimeMs: request.retainUntilWallTimeMs,
				ringBasePath: request.ringBasePath,
				requestedAtWallTimeMs: request.requestedAtWallTimeMs,
				initialRingSnapshot: request.initialRingSnapshot ?? null,
			}),
		);
	}

	private sysdigRequestBaseFingerprint(request: SysdigPinRequest): string {
		return sha256(
			canonicalJson({
				version: request.version,
				runId: request.runId,
				anchorWallTimeMs: request.anchorWallTimeMs,
				fromWallTimeMs: request.fromWallTimeMs,
				throughWallTimeMs: request.throughWallTimeMs,
				resolveAfterWallTimeMs: request.resolveAfterWallTimeMs,
				requestedAtWallTimeMs: request.requestedAtWallTimeMs,
				retainUntilWallTimeMs: request.retainUntilWallTimeMs,
				ringBasePath: request.ringBasePath,
			}),
		);
	}

	private discoverSysdigRingSnapshot(ringBasePath: string, observedAtWallTimeMs: number): SysdigRingSnapshot {
		const issues: string[] = [];
		const ringDir = dirname(ringBasePath);
		const ringName = basename(ringBasePath);
		let entries: Dirent[];
		try {
			entries = readdirSync(ringDir, { withFileTypes: true });
		} catch {
			return { observedAtWallTimeMs, candidates: [], issues: ["ring_directory_unavailable"] };
		}
		if (entries.length > SYSDIG_PIN_MAX_DISCOVERY_ENTRIES) issues.push("ring_directory_entry_bound_exceeded");
		const discovered: SysdigRingSnapshotCandidate[] = [];
		for (const entry of entries.slice(0, SYSDIG_PIN_MAX_DISCOVERY_ENTRIES)) {
			if (!entry.name.startsWith(ringName)) continue;
			const sourcePath = join(ringDir, entry.name);
			try {
				const metadata = lstatSync(sourcePath, { bigint: true });
				if (!metadata.isFile()) {
					issues.push(`non_regular_ring_entry:${entry.name}`);
					continue;
				}
				const bytes = Number(metadata.size);
				if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > SYSDIG_PIN_MAX_SEGMENT_BYTES) {
					issues.push(`oversize_ring_entry:${entry.name}`);
					continue;
				}
				const source = {
					dev: metadata.dev.toString(),
					ino: metadata.ino.toString(),
					bytes,
					mtimeMs: Number(metadata.mtimeMs),
					ctimeMs: Number(metadata.ctimeMs),
				};
				discovered.push({
					id: sha256(`${source.dev}\0${source.ino}\0${source.bytes}\0${source.mtimeMs}\0${source.ctimeMs}`),
					sourcePath,
					sourceName: entry.name,
					activeAtRequest: false,
					source,
				});
			} catch {
				issues.push(`unstatable_ring_entry:${entry.name}`);
			}
		}
		discovered.sort(
			(left, right) =>
				right.source.mtimeMs - left.source.mtimeMs ||
				(right.sourceName === left.sourceName ? 0 : right.sourceName < left.sourceName ? -1 : 1),
		);
		if (discovered.length > SYSDIG_RING_EXPECTED_SEGMENTS) issues.push("ring_has_more_than_configured_12_segments");
		if (discovered.length > SYSDIG_PIN_MAX_SEGMENTS) issues.push("ring_segment_count_bound_exceeded");
		const candidates: SysdigRingSnapshotCandidate[] = [];
		let totalBytes = 0;
		for (const [index, candidate] of discovered.slice(0, SYSDIG_PIN_MAX_SEGMENTS).entries()) {
			if (totalBytes + candidate.source.bytes > SYSDIG_PIN_MAX_TOTAL_BYTES) {
				issues.push("incident_sysdig_pin_total_byte_bound_exceeded");
				break;
			}
			totalBytes += candidate.source.bytes;
			candidates.push({ ...candidate, activeAtRequest: index === 0 });
		}
		return { observedAtWallTimeMs, candidates, issues };
	}

	private boundSysdigRequestSnapshot(
		request: Omit<SysdigPinRequest, "initialRingSnapshot">,
		snapshot: SysdigRingSnapshot,
	): SysdigRingSnapshot {
		const serializedBytes = (candidateSnapshot: SysdigRingSnapshot): number =>
			Buffer.byteLength(`${JSON.stringify({ ...request, initialRingSnapshot: candidateSnapshot })}\n`, "utf8");
		if (serializedBytes(snapshot) <= SYSDIG_PIN_REQUEST_MAX_BYTES) return snapshot;
		const bounded: SysdigRingSnapshot = {
			observedAtWallTimeMs: snapshot.observedAtWallTimeMs,
			candidates: [],
			issues: ["request_snapshot_byte_bound_exceeded"],
		};
		for (const candidate of snapshot.candidates) {
			const trial = { ...bounded, candidates: [...bounded.candidates, candidate] };
			if (serializedBytes(trial) > SYSDIG_PIN_REQUEST_MAX_BYTES) break;
			bounded.candidates.push(candidate);
		}
		for (const issue of snapshot.issues) {
			if (bounded.issues.length >= SYSDIG_PIN_MAX_DISCOVERY_ENTRIES) break;
			const trial = { ...bounded, issues: [...bounded.issues, issue] };
			if (serializedBytes(trial) > SYSDIG_PIN_REQUEST_MAX_BYTES) continue;
			bounded.issues.push(issue);
		}
		if (serializedBytes(bounded) > SYSDIG_PIN_REQUEST_MAX_BYTES) {
			throw new Error("Sysdig pin request base fields exceed the 64 KiB immutable request bound");
		}
		return bounded;
	}

	private readSysdigPinRequestPath(path: string): SysdigPinRequest | undefined {
		try {
			const metadata = lstatSync(path);
			if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > SYSDIG_PIN_REQUEST_MAX_BYTES)
				return undefined;
			const request = JSON.parse(readFileSync(path, "utf8")) as SysdigPinRequest;
			if (
				!hasExactOwnKeys(request, [
					"version",
					"runId",
					"anchorWallTimeMs",
					"fromWallTimeMs",
					"throughWallTimeMs",
					"resolveAfterWallTimeMs",
					"requestedAtWallTimeMs",
					"retainUntilWallTimeMs",
					"ringBasePath",
					"initialRingSnapshot",
				]) ||
				request.version !== 1 ||
				!isCanonicalUuid(request.runId) ||
				!Number.isSafeInteger(request.anchorWallTimeMs) ||
				request.anchorWallTimeMs < 0 ||
				!Number.isSafeInteger(request.fromWallTimeMs) ||
				!Number.isSafeInteger(request.throughWallTimeMs) ||
				!Number.isSafeInteger(request.resolveAfterWallTimeMs) ||
				!Number.isSafeInteger(request.requestedAtWallTimeMs) ||
				!Number.isSafeInteger(request.retainUntilWallTimeMs) ||
				typeof request.ringBasePath !== "string" ||
				request.ringBasePath.length === 0 ||
				Buffer.byteLength(request.ringBasePath) > 4096 ||
				request.fromWallTimeMs !== request.anchorWallTimeMs - PIN_BEFORE_MS ||
				request.throughWallTimeMs !== request.anchorWallTimeMs + PIN_AFTER_MS ||
				request.resolveAfterWallTimeMs !== request.throughWallTimeMs ||
				request.requestedAtWallTimeMs !== request.anchorWallTimeMs ||
				request.retainUntilWallTimeMs !== request.anchorWallTimeMs + SYSDIG_PIN_RETENTION_MS
			) {
				return undefined;
			}
			const snapshot = request.initialRingSnapshot;
			if (snapshot === undefined) return undefined;
			{
				if (
					!hasExactOwnKeys(snapshot, ["observedAtWallTimeMs", "candidates", "issues"]) ||
					!Number.isSafeInteger(snapshot.observedAtWallTimeMs) ||
					snapshot.observedAtWallTimeMs < 0 ||
					!Array.isArray(snapshot.candidates) ||
					snapshot.candidates.length > SYSDIG_PIN_MAX_SEGMENTS ||
					!Array.isArray(snapshot.issues) ||
					snapshot.issues.length > SYSDIG_PIN_MAX_DISCOVERY_ENTRIES
				) {
					return undefined;
				}
				if (snapshot.issues.some((issue) => typeof issue !== "string" || Buffer.byteLength(issue) > 4096))
					return undefined;
				let totalBytes = 0;
				const ids = new Set<string>();
				let activeCount = 0;
				const ringDir = dirname(request.ringBasePath);
				const ringName = basename(request.ringBasePath);
				for (const candidate of snapshot.candidates) {
					if (
						!hasExactOwnKeys(candidate, ["id", "sourcePath", "sourceName", "activeAtRequest", "source"]) ||
						!hasExactOwnKeys(candidate.source, ["dev", "ino", "bytes", "mtimeMs", "ctimeMs"]) ||
						!/^[0-9a-f]{64}$/.test(candidate.id) ||
						ids.has(candidate.id) ||
						typeof candidate.sourcePath !== "string" ||
						Buffer.byteLength(candidate.sourcePath, "utf8") > 4096 ||
						typeof candidate.sourceName !== "string" ||
						candidate.sourceName.length === 0 ||
						Buffer.byteLength(candidate.sourceName, "utf8") > 255 ||
						basename(candidate.sourceName) !== candidate.sourceName ||
						!candidate.sourceName.startsWith(ringName) ||
						candidate.sourcePath !== join(ringDir, candidate.sourceName) ||
						typeof candidate.activeAtRequest !== "boolean" ||
						Buffer.byteLength(candidate.source.dev, "utf8") > 32 ||
						!/^(?:0|[1-9]\d*)$/.test(candidate.source.dev) ||
						Buffer.byteLength(candidate.source.ino, "utf8") > 32 ||
						!/^(?:0|[1-9]\d*)$/.test(candidate.source.ino) ||
						!Number.isSafeInteger(candidate.source.bytes) ||
						candidate.source.bytes < 0 ||
						candidate.source.bytes > SYSDIG_PIN_MAX_SEGMENT_BYTES ||
						!Number.isFinite(candidate.source.mtimeMs) ||
						candidate.source.mtimeMs < 0 ||
						!Number.isFinite(candidate.source.ctimeMs) ||
						candidate.source.ctimeMs < 0
					) {
						return undefined;
					}
					if (
						candidate.id !==
						sha256(
							`${candidate.source.dev}\0${candidate.source.ino}\0${candidate.source.bytes}\0${candidate.source.mtimeMs}\0${candidate.source.ctimeMs}`,
						)
					)
						return undefined;
					ids.add(candidate.id);
					if (candidate.activeAtRequest) activeCount += 1;
					totalBytes += candidate.source.bytes;
					if (!Number.isSafeInteger(totalBytes) || totalBytes > SYSDIG_PIN_MAX_TOTAL_BYTES) return undefined;
				}
				if (
					(snapshot.candidates.length === 0 && activeCount !== 0) ||
					(snapshot.candidates.length > 0 &&
						(activeCount !== 1 || snapshot.candidates[0]?.activeAtRequest !== true))
				)
					return undefined;
			}
			return request;
		} catch {
			return undefined;
		}
	}

	private readSysdigPinRequest(incidentDir: string): SysdigPinRequest | undefined {
		return this.readSysdigPinRequestPath(this.sysdigRequestPath(incidentDir));
	}

	private readJournalPinRequest(incidentDir: string): JournalPinRequest | undefined {
		try {
			const request = JSON.parse(readFileSync(this.journalRequestPath(incidentDir), "utf8")) as JournalPinRequest;
			if (
				!hasExactOwnKeys(request, [
					"version",
					"state",
					"runId",
					"anchorWallTimeMs",
					"fromWallTimeMs",
					"throughWallTimeMs",
					"resolveAfterWallTimeMs",
					"retainUntilWallTimeMs",
				]) ||
				request.version !== 1 ||
				request.state !== "pending" ||
				!isCanonicalUuid(request.runId) ||
				!Number.isSafeInteger(request.anchorWallTimeMs) ||
				request.anchorWallTimeMs < 0 ||
				!Number.isSafeInteger(request.fromWallTimeMs) ||
				!Number.isSafeInteger(request.throughWallTimeMs) ||
				!Number.isSafeInteger(request.resolveAfterWallTimeMs) ||
				!Number.isSafeInteger(request.retainUntilWallTimeMs) ||
				request.fromWallTimeMs < 0 ||
				request.fromWallTimeMs > request.anchorWallTimeMs ||
				request.throughWallTimeMs < request.anchorWallTimeMs ||
				request.throughWallTimeMs - request.fromWallTimeMs > PIN_BEFORE_MS + PIN_AFTER_MS ||
				request.resolveAfterWallTimeMs < request.anchorWallTimeMs ||
				request.resolveAfterWallTimeMs > request.throughWallTimeMs ||
				request.retainUntilWallTimeMs !== request.anchorWallTimeMs + INCIDENT_DIAGNOSTIC_RETENTION_MS
			) {
				return undefined;
			}
			return request;
		} catch {
			return undefined;
		}
	}

	private readIncidentPinAuthority(incidentDir: string): IncidentPinAuthority | undefined {
		return this.readSysdigPinRequestPath(this.pinAuthorityPath(incidentDir));
	}

	private quarantineInvalidPinRequest(incidentDir: string, provider: "journal" | "sysdig", path: string): string {
		const metadata = lstatSync(path);
		if ((!metadata.isFile() && !metadata.isSymbolicLink()) || metadata.isDirectory()) {
			throw new Error(`Invalid ${provider} pin request could not be quarantined safely`);
		}
		const identity = sha256(
			`${metadata.dev}:${metadata.ino}:${metadata.mode}:${metadata.size}:${metadata.mtimeMs}:${metadata.ctimeMs}`,
		);
		const quarantineDir = join(incidentDir, "provider-request-quarantine");
		const quarantinePath = join(quarantineDir, `${provider}-${identity}.json`);
		mkdirSync(quarantineDir, { recursive: true, mode: 0o700 });
		const existed = existsSync(quarantinePath);
		if (!existed) linkSync(path, quarantinePath);
		const quarantined = lstatSync(quarantinePath);
		if (quarantined.dev !== metadata.dev || quarantined.ino !== metadata.ino) {
			throw new Error(`Invalid ${provider} pin request quarantine identity mismatch`);
		}
		if (!existed) this.accountStoragePath(quarantinePath);
		fsyncDirectory(quarantineDir);
		const removed = lstatSync(path);
		rmSync(path);
		this.accountRemovedStorageEntry(removed);
		fsyncDirectory(incidentDir);
		this.writeOwnedJson(join(quarantineDir, `${provider}-${identity}-recovery.json`), {
			version: 1,
			state: "quarantined_invalid_immutable_request",
			provider,
			identity,
		});
		return identity;
	}

	private quarantineInvalidProviderProof(incidentDir: string, provider: "journal" | "sysdig", path: string): void {
		const metadata = lstatSync(path);
		if ((!metadata.isFile() && !metadata.isSymbolicLink()) || metadata.isDirectory())
			throw new Error(`Invalid ${provider} pin proof could not be quarantined safely`);
		const identity = sha256(
			`${metadata.dev}:${metadata.ino}:${metadata.mode}:${metadata.size}:${metadata.mtimeMs}:${metadata.ctimeMs}`,
		);
		const quarantineDir = join(incidentDir, "provider-proof-quarantine");
		const quarantinePath = join(quarantineDir, `${provider}-${identity}.json`);
		mkdirSync(quarantineDir, { recursive: true, mode: 0o700 });
		const existed = existsSync(quarantinePath);
		if (!existed) {
			linkSync(path, quarantinePath);
			this.accountStoragePath(quarantinePath);
		}
		const quarantined = lstatSync(quarantinePath);
		if (quarantined.dev !== metadata.dev || quarantined.ino !== metadata.ino)
			throw new Error(`Invalid ${provider} pin proof quarantine identity mismatch`);
		fsyncDirectory(quarantineDir);
		const removed = lstatSync(path);
		rmSync(path);
		this.accountRemovedStorageEntry(removed);
		fsyncDirectory(incidentDir);
	}

	private quarantineInvalidProviderIncomplete(
		incidentDir: string,
		provider: "journal" | "sysdig",
		path: string,
	): void {
		const metadata = lstatSync(path);
		if ((!metadata.isFile() && !metadata.isSymbolicLink()) || metadata.isDirectory())
			throw new Error(`Invalid ${provider} incomplete marker could not be quarantined safely`);
		const identity = sha256(
			`${metadata.dev}:${metadata.ino}:${metadata.mode}:${metadata.size}:${metadata.mtimeMs}:${metadata.ctimeMs}`,
		);
		const quarantineDir = join(incidentDir, "provider-incomplete-quarantine");
		const quarantinePath = join(quarantineDir, `${provider}-${identity}.json`);
		mkdirSync(quarantineDir, { recursive: true, mode: 0o700 });
		if (!existsSync(quarantinePath)) {
			linkSync(path, quarantinePath);
			this.accountStoragePath(quarantinePath);
		}
		const quarantined = lstatSync(quarantinePath);
		if (quarantined.dev !== metadata.dev || quarantined.ino !== metadata.ino)
			throw new Error(`Invalid ${provider} incomplete marker quarantine identity mismatch`);
		fsyncDirectory(quarantineDir);
		const removed = lstatSync(path);
		rmSync(path);
		this.accountRemovedStorageEntry(removed);
		fsyncDirectory(incidentDir);
	}

	private writeOrRepairProviderPinProof(
		incidentDir: string,
		provider: "journal" | "sysdig",
		value: Record<string, unknown>,
	): void {
		const path = join(incidentDir, `${provider}-pin-retention-proof.json`);
		if (existsSync(path)) {
			let matches = false;
			try {
				const metadata = lstatSync(path);
				const expectedUid = typeof process.getuid === "function" ? process.getuid() : metadata.uid;
				const existing = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
				matches =
					metadata.isFile() &&
					!metadata.isSymbolicLink() &&
					metadata.nlink === 1 &&
					metadata.uid === expectedUid &&
					(metadata.mode & 0o077) === 0 &&
					metadata.size <= 64 * 1024 &&
					canonicalJson(existing) === canonicalJson(value);
			} catch {}
			if (matches) {
				const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
				try {
					fsyncSync(descriptor);
				} finally {
					closeSync(descriptor);
				}
				fsyncDirectory(incidentDir);
				return;
			}
			this.quarantineInvalidProviderProof(incidentDir, provider, path);
		}
		this.writeOwnedJson(path, value, 64 * 1024);
	}

	private readSysdigSegmentRecordState(incidentDir: string): SysdigPinRecordState {
		const recordsDir = join(incidentDir, "sysdig-pins", "records");
		const segmentsDir = join(incidentDir, "sysdig-pins", "segments");
		let entries: Dirent[];
		try {
			entries = readdirSync(recordsDir, { withFileTypes: true });
		} catch {
			return { records: [], recordFileCount: 0, totalBytes: 0, saturated: false, issues: [] };
		}
		const issues: string[] = [];
		let saturated = false;
		if (entries.length > SYSDIG_PIN_MAX_DISCOVERY_ENTRIES) {
			issues.push("pin_record_directory_entry_bound_exceeded");
			saturated = true;
		}
		const names = entries
			.slice(0, SYSDIG_PIN_MAX_DISCOVERY_ENTRIES)
			.filter((entry) => entry.isFile() && /^[0-9a-f]{64}\.json$/.test(entry.name))
			.map((entry) => entry.name)
			.sort();
		const recordFileCount = names.length;
		if (recordFileCount > SYSDIG_PIN_MAX_SEGMENTS) {
			issues.push("pin_record_count_bound_exceeded");
			saturated = true;
		}
		const records: SysdigPinnedSegmentRecord[] = [];
		let totalBytes = 0;
		for (const name of names) {
			try {
				const path = join(recordsDir, name);
				const stat = lstatSync(path);
				const expectedUid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
				if (
					!stat.isFile() ||
					stat.isSymbolicLink() ||
					stat.nlink !== 1 ||
					stat.uid !== expectedUid ||
					(stat.mode & 0o077) !== 0 ||
					stat.size > 64 * 1024
				)
					throw new Error("record_metadata_identity_or_byte_bound_invalid");
				const value = JSON.parse(readFileSync(path, "utf8")) as SysdigPinnedSegmentRecord;
				const artifactAtCapture = value.artifactAtCapture;
				if (
					!hasExactOwnKeys(value, [
						"version",
						"id",
						"sourcePath",
						"sourceName",
						"observedAtWallTimeMs",
						"phase",
						"source",
						"pinnedPath",
						"captureMethod",
						"captureReason",
						"bytesAtCapture",
						"artifactAtCapture",
					]) ||
					value.version !== 1 ||
					value.id !== name.slice(0, -5) ||
					!/^[0-9a-f]{64}$/.test(value.id) ||
					!hasExactOwnKeys(value.source, ["dev", "ino", "bytes", "mtimeMs", "ctimeMs"]) ||
					!hasExactOwnKeys(artifactAtCapture, ["dev", "ino", "bytes", "mtimeMs", "ctimeMs", "mode", "nlink"]) ||
					typeof value.sourcePath !== "string" ||
					Buffer.byteLength(value.sourcePath, "utf8") > 4096 ||
					typeof value.sourceName !== "string" ||
					value.sourceName.length === 0 ||
					Buffer.byteLength(value.sourceName, "utf8") > 255 ||
					basename(value.sourceName) !== value.sourceName ||
					!Number.isSafeInteger(value.observedAtWallTimeMs) ||
					value.observedAtWallTimeMs < 0 ||
					(value.phase !== "initial" && value.phase !== "rotated" && value.phase !== "final") ||
					value.pinnedPath !== join(segmentsDir, `${value.id}.scap`) ||
					value.captureMethod !== "bounded_copy" ||
					(value.captureReason !== "active_segment_snapshot" &&
						value.captureReason !== "closed_segment_private_snapshot") ||
					typeof value.source.dev !== "string" ||
					!/^(?:0|[1-9]\d*)$/.test(value.source.dev) ||
					typeof value.source.ino !== "string" ||
					!/^(?:0|[1-9]\d*)$/.test(value.source.ino) ||
					!Number.isSafeInteger(value.source.bytes) ||
					value.source.bytes < 0 ||
					value.source.bytes > SYSDIG_PIN_MAX_SEGMENT_BYTES ||
					!Number.isFinite(value.source.mtimeMs) ||
					value.source.mtimeMs < 0 ||
					!Number.isFinite(value.source.ctimeMs) ||
					value.source.ctimeMs < 0 ||
					value.id !==
						sha256(
							`${value.source.dev}\0${value.source.ino}\0${value.source.bytes}\0${value.source.mtimeMs}\0${value.source.ctimeMs}`,
						) ||
					!Number.isSafeInteger(value.bytesAtCapture) ||
					value.bytesAtCapture < 0 ||
					value.bytesAtCapture > SYSDIG_PIN_MAX_SEGMENT_BYTES ||
					value.source.bytes !== value.bytesAtCapture ||
					artifactAtCapture.bytes !== value.bytesAtCapture ||
					artifactAtCapture.mode !== 0o600 ||
					artifactAtCapture.nlink !== 1 ||
					!/^(?:0|[1-9]\d*)$/.test(artifactAtCapture.dev) ||
					!/^(?:0|[1-9]\d*)$/.test(artifactAtCapture.ino) ||
					!Number.isFinite(artifactAtCapture.mtimeMs) ||
					!Number.isFinite(artifactAtCapture.ctimeMs)
				)
					throw new Error("record_metadata_invalid");
				totalBytes += value.bytesAtCapture;
				if (!Number.isSafeInteger(totalBytes)) throw new Error("record_total_byte_accounting_overflow");
				if (records.length < SYSDIG_PIN_MAX_SEGMENTS) records.push(value);
			} catch (error) {
				issues.push(`invalid_pin_record:${name}:${error instanceof Error ? error.message : String(error)}`);
				saturated = true;
			}
		}
		if (totalBytes > SYSDIG_PIN_MAX_TOTAL_BYTES) {
			issues.push("existing_pin_record_total_byte_bound_exceeded");
			saturated = true;
		}
		return { records, recordFileCount, totalBytes, saturated, issues };
	}

	private recordSysdigPinIssues(incidentDir: string, issues: readonly string[]): void {
		const directory = join(incidentDir, "sysdig-pins", "issues");
		for (const reason of issues.slice(0, SYSDIG_PIN_MAX_DISCOVERY_ENTRIES)) {
			try {
				mkdirSync(directory, { recursive: true, mode: 0o700 });
				this.writeOwnedJson(join(directory, `${sha256(reason)}.json`), { version: 1, reason }, 64 * 1024);
			} catch {}
		}
	}

	private readSysdigPinIssues(incidentDir: string): string[] {
		const directory = join(incidentDir, "sysdig-pins", "issues");
		let names: string[];
		try {
			names = readdirSync(directory)
				.filter((name) => /^[0-9a-f]{64}\.json$/.test(name))
				.sort()
				.slice(0, SYSDIG_PIN_MAX_DISCOVERY_ENTRIES);
		} catch {
			return [];
		}
		const issues: string[] = [];
		for (const name of names) {
			try {
				const value = JSON.parse(readFileSync(join(directory, name), "utf8")) as { reason?: unknown };
				if (typeof value.reason === "string" && Buffer.byteLength(value.reason) <= 4096) issues.push(value.reason);
			} catch {}
		}
		return issues;
	}

	private resolveSysdigSnapshotSource(
		request: SysdigPinRequest,
		candidate: SysdigRingSnapshotCandidate,
		partialBytes: number,
	): { path: string; metadata: BigIntStats } {
		const ringDir = dirname(request.ringBasePath);
		const ringName = basename(request.ringBasePath);
		const paths: string[] = [];
		if (dirname(candidate.sourcePath) === ringDir && basename(candidate.sourcePath).startsWith(ringName)) {
			paths.push(candidate.sourcePath);
		}
		try {
			for (const entry of readdirSync(ringDir, { withFileTypes: true }).slice(0, SYSDIG_PIN_MAX_DISCOVERY_ENTRIES)) {
				if (entry.isFile() && entry.name.startsWith(ringName)) paths.push(join(ringDir, entry.name));
			}
		} catch {}
		for (const path of [...new Set(paths)]) {
			try {
				const metadata = lstatSync(path, { bigint: true });
				const exactRequestIdentity =
					Number(metadata.size) === candidate.source.bytes &&
					Number(metadata.mtimeMs) === candidate.source.mtimeMs &&
					Number(metadata.ctimeMs) === candidate.source.ctimeMs;
				if (
					metadata.isFile() &&
					metadata.dev.toString() === candidate.source.dev &&
					metadata.ino.toString() === candidate.source.ino &&
					(candidate.activeAtRequest && partialBytes > 0
						? Number(metadata.size) >= candidate.source.bytes
						: exactRequestIdentity)
				) {
					return { path, metadata };
				}
			} catch {}
		}
		throw new Error(`sysdig_planned_source_unavailable:${candidate.sourceName}`);
	}

	private discardSysdigSourceCapture(): void {
		const state = this.sysdigSourceCapture;
		if (!state) return;
		if (state.sourceDescriptor !== undefined) {
			try {
				closeSync(state.sourceDescriptor);
				state.sourceDescriptor = undefined;
			} catch {}
		}
		if (state.partialDescriptor !== undefined) {
			try {
				closeSync(state.partialDescriptor);
				state.partialDescriptor = undefined;
			} catch {}
		}
		if (state.sourceDescriptor === undefined && state.partialDescriptor === undefined)
			this.sysdigSourceCapture = undefined;
	}

	private beginSysdigSourceCapture(
		request: SysdigPinRequest,
		candidate: SysdigRingSnapshotCandidate,
		partialPath: string,
	): SysdigSourceCaptureState {
		let partialBytes = 0;
		let partialExisted = false;
		try {
			const partial = lstatSync(partialPath);
			if (!partial.isFile() || partial.isSymbolicLink() || partial.nlink !== 1)
				throw new Error("sysdig_partial_copy_invalid");
			partialBytes = partial.size;
			partialExisted = true;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		if (partialBytes > candidate.source.bytes) throw new Error("sysdig_partial_copy_exceeds_planned_bytes");
		const resolved = this.resolveSysdigSnapshotSource(request, candidate, partialBytes);
		let sourceDescriptor: number | undefined;
		let partialDescriptor: number | undefined;
		try {
			sourceDescriptor = openSync(resolved.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
			const openedSource = fstatSync(sourceDescriptor, { bigint: true });
			const pathIdentity = lstatSync(resolved.path, { bigint: true });
			const exactRequestIdentity =
				Number(openedSource.size) === candidate.source.bytes &&
				Number(openedSource.mtimeMs) === candidate.source.mtimeMs &&
				Number(openedSource.ctimeMs) === candidate.source.ctimeMs;
			if (
				!openedSource.isFile() ||
				!pathIdentity.isFile() ||
				openedSource.dev !== pathIdentity.dev ||
				openedSource.ino !== pathIdentity.ino ||
				openedSource.dev.toString() !== candidate.source.dev ||
				openedSource.ino.toString() !== candidate.source.ino ||
				(candidate.activeAtRequest && partialBytes > 0
					? Number(openedSource.size) < candidate.source.bytes
					: !exactRequestIdentity)
			) {
				throw new Error("sysdig_source_identity_changed_before_open");
			}
			partialDescriptor = openSync(
				partialPath,
				fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW,
				0o600,
			);
			const openedPartial = fstatSync(partialDescriptor, { bigint: true });
			const partialPathIdentity = lstatSync(partialPath, { bigint: true });
			const expectedUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : openedPartial.uid;
			if (
				!openedPartial.isFile() ||
				openedPartial.dev !== partialPathIdentity.dev ||
				openedPartial.ino !== partialPathIdentity.ino ||
				Number(openedPartial.nlink) !== 1 ||
				openedPartial.uid !== expectedUid ||
				(Number(openedPartial.mode) & 0o777) !== 0o600 ||
				Number(openedPartial.size) !== partialBytes
			) {
				throw new Error("sysdig_partial_copy_changed_before_resume");
			}
			const state: SysdigSourceCaptureState = {
				recordId: candidate.id,
				sourcePath: resolved.path,
				sourceDescriptor,
				partialDescriptor,
				partialDev: openedPartial.dev.toString(),
				partialIno: openedPartial.ino.toString(),
				partialUid: openedPartial.uid.toString(),
				partialBytes,
				verifiedBytes: 0,
				phase: partialBytes > 0 ? "verify_existing" : "copy",
				verificationSourceIdentity:
					partialBytes > 0
						? {
								bytes: Number(openedSource.size),
								mtimeMs: Number(openedSource.mtimeMs),
								ctimeMs: Number(openedSource.ctimeMs),
							}
						: undefined,
			};
			this.sysdigSourceCapture = state;
			if (!partialExisted) {
				this.accountStoragePath(partialPath);
				fsyncDirectory(dirname(partialPath));
			}
			return state;
		} catch (error) {
			if (this.sysdigSourceCapture?.recordId === candidate.id) this.sysdigSourceCapture = undefined;
			if (sourceDescriptor !== undefined) {
				try {
					closeSync(sourceDescriptor);
				} catch {}
			}
			if (partialDescriptor !== undefined) {
				try {
					closeSync(partialDescriptor);
				} catch {}
			}
			throw error;
		}
	}

	private advanceSysdigSourceCapture(
		request: SysdigPinRequest,
		candidate: SysdigRingSnapshotCandidate,
		partialPath: string,
		budget: SysdigWorkBudget,
	): SysdigSegmentCaptureResult {
		if (this.sysdigSourceCapture?.recordId !== candidate.id) this.discardSysdigSourceCapture();
		if (budget.remainingBytes <= 0) return { complete: false, bytesWorked: 0 };
		let bytesWorked = 0;
		try {
			const state = this.sysdigSourceCapture ?? this.beginSysdigSourceCapture(request, candidate, partialPath);
			const sourceDescriptor = state.sourceDescriptor;
			const partialDescriptor = state.partialDescriptor;
			if (sourceDescriptor === undefined || partialDescriptor === undefined)
				throw new Error("sysdig_source_capture_descriptor_unavailable");
			const validateDescriptors = (): {
				source: BigIntStats;
				partial: BigIntStats;
			} => {
				const source = fstatSync(sourceDescriptor, { bigint: true });
				const partial = fstatSync(partialDescriptor, { bigint: true });
				const partialPathIdentity = lstatSync(partialPath, { bigint: true });
				const exactClosedIdentity =
					Number(source.size) === candidate.source.bytes &&
					Number(source.mtimeMs) === candidate.source.mtimeMs &&
					Number(source.ctimeMs) === candidate.source.ctimeMs;
				if (
					!source.isFile() ||
					source.dev.toString() !== candidate.source.dev ||
					source.ino.toString() !== candidate.source.ino ||
					(candidate.activeAtRequest ? Number(source.size) < candidate.source.bytes : !exactClosedIdentity)
				) {
					throw new Error("sysdig_source_changed_during_bounded_capture");
				}
				if (
					!partial.isFile() ||
					partial.dev.toString() !== state.partialDev ||
					partial.ino.toString() !== state.partialIno ||
					partial.uid.toString() !== state.partialUid ||
					Number(partial.nlink) !== 1 ||
					(Number(partial.mode) & 0o777) !== 0o600 ||
					Number(partial.size) !== state.partialBytes ||
					partial.dev !== partialPathIdentity.dev ||
					partial.ino !== partialPathIdentity.ino
				) {
					throw new Error("sysdig_partial_copy_changed_during_capture");
				}
				return { source, partial };
			};
			while (budget.remainingBytes > 0) {
				const { source } = validateDescriptors();
				if (state.phase === "copy" && state.partialBytes >= candidate.source.bytes) {
					fsyncSync(partialDescriptor);
					state.phase = "verify_final";
					state.verifiedBytes = 0;
					state.verificationSourceIdentity = {
						bytes: Number(source.size),
						mtimeMs: Number(source.mtimeMs),
						ctimeMs: Number(source.ctimeMs),
					};
					continue;
				}
				if (state.phase === "verify_existing" || state.phase === "verify_final") {
					const verificationBytes = state.partialBytes;
					const allowance = Math.min(budget.remainingBytes, verificationBytes - state.verifiedBytes);
					if (allowance > 0) {
						const sourceBuffer = Buffer.allocUnsafe(Math.min(SYSDIG_PIN_COPY_BUFFER_BYTES, allowance));
						const partialBuffer = Buffer.allocUnsafe(sourceBuffer.length);
						while (state.verifiedBytes < verificationBytes && budget.remainingBytes > 0) {
							const requested = Math.min(
								sourceBuffer.length,
								budget.remainingBytes,
								verificationBytes - state.verifiedBytes,
							);
							const sourceCount = readSync(sourceDescriptor, sourceBuffer, 0, requested, state.verifiedBytes);
							const partialCount = readSync(partialDescriptor, partialBuffer, 0, requested, state.verifiedBytes);
							if (
								sourceCount !== requested ||
								partialCount !== requested ||
								!sourceBuffer.subarray(0, requested).equals(partialBuffer.subarray(0, requested))
							) {
								throw new Error("sysdig_partial_prefix_mismatch");
							}
							state.verifiedBytes += requested;
							budget.remainingBytes -= requested;
							bytesWorked += requested;
						}
					}
					if (state.verifiedBytes < verificationBytes) return { complete: false, bytesWorked };
					const afterVerification = validateDescriptors().source;
					const verificationIdentity = state.verificationSourceIdentity;
					if (
						verificationIdentity &&
						(Number(afterVerification.size) !== verificationIdentity.bytes ||
							Number(afterVerification.mtimeMs) !== verificationIdentity.mtimeMs ||
							Number(afterVerification.ctimeMs) !== verificationIdentity.ctimeMs)
					) {
						if (!candidate.activeAtRequest)
							throw new Error("sysdig_closed_source_changed_during_prefix_verification");
						state.verifiedBytes = 0;
						state.verificationSourceIdentity = {
							bytes: Number(afterVerification.size),
							mtimeMs: Number(afterVerification.mtimeMs),
							ctimeMs: Number(afterVerification.ctimeMs),
						};
						return { complete: false, bytesWorked };
					}
					if (state.phase === "verify_existing") {
						state.phase = "copy";
						state.verifiedBytes = state.partialBytes;
						state.verificationSourceIdentity = undefined;
						continue;
					}
					fsyncSync(partialDescriptor);
					this.discardSysdigSourceCapture();
					return { complete: true, bytesWorked };
				}
				const allowance = Math.min(budget.remainingBytes, candidate.source.bytes - state.partialBytes);
				const buffer = Buffer.allocUnsafe(Math.min(SYSDIG_PIN_COPY_BUFFER_BYTES, Math.max(1, allowance)));
				let copied = 0;
				while (copied < allowance) {
					const count = readSync(
						sourceDescriptor,
						buffer,
						0,
						Math.min(buffer.length, allowance - copied),
						state.partialBytes + copied,
					);
					if (count <= 0) throw new Error("sysdig_source_truncated_during_bounded_copy");
					let written = 0;
					while (written < count) {
						const amount = writeSync(
							partialDescriptor,
							buffer,
							written,
							count - written,
							state.partialBytes + copied + written,
						);
						if (amount <= 0) throw new Error("sysdig_bounded_copy_write_made_no_progress");
						written += amount;
					}
					copied += count;
				}
				state.partialBytes += copied;
				state.verifiedBytes = state.partialBytes;
				budget.remainingBytes -= copied;
				bytesWorked += copied;
				fsyncSync(partialDescriptor);
				this.accountStoragePath(partialPath, false);
				validateDescriptors();
			}
			return { complete: false, bytesWorked };
		} catch (error) {
			this.discardSysdigSourceCapture();
			throw error;
		}
	}

	private captureSysdigSegment(
		incidentDir: string,
		request: SysdigPinRequest,
		candidate: SysdigRingSnapshotCandidate,
		observedAtWallTimeMs: number,
		phase: SysdigPinnedSegmentRecord["phase"],
		preferCopy: boolean,
		budget: SysdigWorkBudget,
	): SysdigSegmentCaptureResult {
		const { id, source } = candidate;
		const pinRoot = join(incidentDir, "sysdig-pins");
		const segmentsDir = join(pinRoot, "segments");
		const recordsDir = join(pinRoot, "records");
		const pinnedPath = join(segmentsDir, `${id}.scap`);
		const recordPath = join(recordsDir, `${id}.json`);
		const partialPath = join(segmentsDir, `.${id}.partial`);
		const captureReason: SysdigPinnedSegmentRecord["captureReason"] = preferCopy
			? "active_segment_snapshot"
			: "closed_segment_private_snapshot";
		try {
			const existing = JSON.parse(readFileSync(recordPath, "utf8")) as SysdigPinnedSegmentRecord;
			if (existsSync(partialPath)) {
				const partial = lstatSync(partialPath, { bigint: true });
				const partialAccounting = lstatSync(partialPath);
				const published = lstatSync(pinnedPath, { bigint: true });
				if (
					!partial.isFile() ||
					partial.isSymbolicLink() ||
					partial.dev !== published.dev ||
					partial.ino !== published.ino ||
					BigInt(partial.nlink) !== 2n ||
					BigInt(published.nlink) !== 2n
				)
					throw new Error("sysdig_published_partial_identity_mismatch");
				rmSync(partialPath);
				this.accountRemovedStorageEntry(partialAccounting);
				fsyncDirectory(segmentsDir);
			}
			const pinned = lstatSync(pinnedPath, { bigint: true });
			const expectedUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : pinned.uid;
			const artifactAtCapture = existing.artifactAtCapture;
			const captureIdentityMatches =
				hasExactOwnKeys(artifactAtCapture, ["dev", "ino", "bytes", "mtimeMs", "ctimeMs", "mode", "nlink"]) &&
				artifactAtCapture.dev === pinned.dev.toString() &&
				artifactAtCapture.ino === pinned.ino.toString() &&
				artifactAtCapture.bytes === Number(pinned.size) &&
				artifactAtCapture.mtimeMs === Number(pinned.mtimeMs) &&
				artifactAtCapture.ctimeMs === Number(pinned.ctimeMs) &&
				artifactAtCapture.mode === (Number(pinned.mode) & 0o777) &&
				artifactAtCapture.nlink === Number(pinned.nlink);
			const sealedVerification = this.readSysdigFinalVerification(
				incidentDir,
				existing,
				this.sysdigArtifactGenerationId(this.sysdigRequestFingerprint(request)),
			);
			if (
				existing.version === 1 &&
				existing.id === id &&
				existing.pinnedPath === pinnedPath &&
				existing.source.dev === source.dev &&
				existing.source.ino === source.ino &&
				existing.source.bytes === source.bytes &&
				existing.source.mtimeMs === source.mtimeMs &&
				existing.source.ctimeMs === source.ctimeMs &&
				existing.captureMethod === "bounded_copy" &&
				existing.bytesAtCapture === source.bytes &&
				pinned.isFile() &&
				!pinned.isSymbolicLink() &&
				BigInt(pinned.nlink) === 1n &&
				pinned.uid === expectedUid &&
				(Number(pinned.mode) & 0o077) === 0 &&
				Number(pinned.size) === source.bytes &&
				(captureIdentityMatches || sealedVerification !== undefined)
			) {
				this.discardSysdigSourceCapture();
				return { complete: true, bytesWorked: 0, record: existing };
			}
		} catch {}
		if (existsSync(recordPath)) throw new Error("sysdig_existing_record_invalid");
		this.ensureDiskAdmission(source.bytes + 256 * 1024);
		mkdirSync(segmentsDir, { recursive: true, mode: 0o700 });
		mkdirSync(recordsDir, { recursive: true, mode: 0o700 });
		const captureMethod: SysdigPinnedSegmentRecord["captureMethod"] = "bounded_copy";
		if (existsSync(pinnedPath)) {
			if (existsSync(partialPath)) {
				const partial = lstatSync(partialPath);
				const published = lstatSync(pinnedPath);
				if (
					!partial.isFile() ||
					partial.isSymbolicLink() ||
					partial.dev !== published.dev ||
					partial.ino !== published.ino ||
					partial.nlink !== 2 ||
					published.nlink !== 2 ||
					partial.size !== source.bytes ||
					published.size !== source.bytes
				)
					throw new Error("sysdig_interrupted_publication_identity_mismatch");
				rmSync(pinnedPath);
				this.accountRemovedStorageEntry(published);
			} else {
				const published = lstatSync(pinnedPath);
				const expectedUid = typeof process.getuid === "function" ? process.getuid() : published.uid;
				if (
					!published.isFile() ||
					published.isSymbolicLink() ||
					published.nlink !== 1 ||
					published.uid !== expectedUid ||
					(published.mode & 0o777) !== 0o600 ||
					published.size !== source.bytes
				)
					throw new Error("sysdig_interrupted_private_copy_invalid");
				renameSync(pinnedPath, partialPath);
			}
			fsyncDirectory(segmentsDir);
		}
		const capture = this.advanceSysdigSourceCapture(request, candidate, partialPath, budget);
		if (!capture.complete) return capture;
		linkSync(partialPath, pinnedPath);
		this.accountStoragePath(pinnedPath);
		fsyncDirectory(segmentsDir);
		const partial = lstatSync(partialPath);
		rmSync(partialPath);
		this.accountRemovedStorageEntry(partial);
		fsyncDirectory(segmentsDir);
		const captured = lstatSync(pinnedPath);
		const expectedUid = typeof process.getuid === "function" ? process.getuid() : captured.uid;
		if (
			!captured.isFile() ||
			captured.isSymbolicLink() ||
			captured.nlink !== 1 ||
			captured.uid !== expectedUid ||
			(captured.mode & 0o777) !== 0o600 ||
			captured.size !== source.bytes
		)
			throw new Error("sysdig_private_copy_cleanup_invalid");
		const artifactAtCapture: SysdigPinnedSegmentRecord["artifactAtCapture"] = {
			dev: String(captured.dev),
			ino: String(captured.ino),
			bytes: captured.size,
			mtimeMs: captured.mtimeMs,
			ctimeMs: captured.ctimeMs,
			mode: 0o600,
			nlink: 1,
		};
		const record: SysdigPinnedSegmentRecord = {
			version: 1,
			id,
			sourcePath: candidate.sourcePath,
			sourceName: candidate.sourceName,
			observedAtWallTimeMs,
			phase,
			source,
			pinnedPath,
			captureMethod,
			captureReason,
			bytesAtCapture: source.bytes,
			artifactAtCapture,
		};
		this.writeOwnedJson(recordPath, record, 64 * 1024);
		return { complete: true, bytesWorked: capture.bytesWorked, record };
	}

	private readOrCreateSysdigCapturePlan(
		incidentDir: string,
		request: SysdigPinRequest,
		phase: "initial" | "final",
		nowMs: number,
	): SysdigCapturePlan {
		const path = this.sysdigCapturePlanPath(incidentDir, phase);
		const requestFingerprint = this.sysdigRequestFingerprint(request);
		try {
			const existing = JSON.parse(readFileSync(path, "utf8")) as SysdigCapturePlan;
			if (
				existing.version !== 1 ||
				existing.state !== "planned" ||
				existing.phase !== phase ||
				existing.requestFingerprint !== requestFingerprint ||
				!Array.isArray(existing.snapshot?.candidates) ||
				existing.snapshot.candidates.length > SYSDIG_PIN_MAX_SEGMENTS
			) {
				throw new Error(`sysdig_${phase}_capture_plan_invalid`);
			}
			return existing;
		} catch (error) {
			if (existsSync(path)) throw error;
		}
		const snapshot =
			phase === "initial" && request.initialRingSnapshot
				? request.initialRingSnapshot
				: this.discoverSysdigRingSnapshot(request.ringBasePath, nowMs);
		const plan: SysdigCapturePlan = {
			version: 1,
			state: "planned",
			phase,
			requestFingerprint,
			snapshot,
		};
		this.writeOwnedJson(path, plan, 128 * 1024);
		this.recordSysdigPinIssues(incidentDir, snapshot.issues);
		return plan;
	}

	private sysdigCaptureMarkerMatches(path: string, plan: SysdigCapturePlan): boolean {
		try {
			const marker = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
			const expectedGaps = this.sysdigPlanGaps(dirname(dirname(path)), plan);
			return (
				hasExactOwnKeys(marker, [
					"version",
					"state",
					"phase",
					"requestFingerprint",
					"candidateIds",
					"outcome",
					"gaps",
				]) &&
				marker.version === 1 &&
				marker.state === "complete" &&
				marker.phase === plan.phase &&
				marker.requestFingerprint === plan.requestFingerprint &&
				Array.isArray(marker.candidateIds) &&
				canonicalJson(marker.candidateIds) ===
					canonicalJson(plan.snapshot.candidates.map((candidate) => candidate.id)) &&
				marker.outcome === (expectedGaps.length === 0 ? "complete" : "incomplete") &&
				Array.isArray(marker.gaps) &&
				canonicalJson(marker.gaps) === canonicalJson(expectedGaps)
			);
		} catch {
			return false;
		}
	}

	private readSysdigCaptureGap(
		incidentDir: string,
		phase: "initial" | "rotated" | "final",
		requestFingerprint: string,
		candidate: SysdigRingSnapshotCandidate,
	): string | undefined {
		try {
			const gap = JSON.parse(
				readFileSync(this.sysdigCaptureGapPath(incidentDir, phase, candidate.id), "utf8"),
			) as Record<string, unknown>;
			if (
				gap.version !== 1 ||
				gap.state !== "gap" ||
				gap.phase !== phase ||
				gap.requestFingerprint !== requestFingerprint ||
				gap.candidateId !== candidate.id ||
				gap.sourceIdentity !==
					`${candidate.source.dev}:${candidate.source.ino}:${candidate.source.bytes}:${candidate.source.mtimeMs}:${candidate.source.ctimeMs}` ||
				typeof gap.reason !== "string" ||
				Buffer.byteLength(gap.reason) > 4096
			) {
				return undefined;
			}
			return gap.reason;
		} catch {
			return undefined;
		}
	}

	private writeSysdigCaptureGap(
		incidentDir: string,
		phase: "initial" | "rotated" | "final",
		requestFingerprint: string,
		candidate: SysdigRingSnapshotCandidate,
		reason: string,
	): void {
		this.writeOwnedJson(
			this.sysdigCaptureGapPath(incidentDir, phase, candidate.id),
			{
				version: 1,
				state: "gap",
				phase,
				requestFingerprint,
				candidateId: candidate.id,
				sourceIdentity: `${candidate.source.dev}:${candidate.source.ino}:${candidate.source.bytes}:${candidate.source.mtimeMs}:${candidate.source.ctimeMs}`,
				reason,
			},
			64 * 1024,
		);
	}

	private sysdigPlanGaps(incidentDir: string, plan: SysdigCapturePlan): string[] {
		const gaps: string[] = plan.snapshot.issues.map((issue) => `snapshot:${issue}`);
		for (const candidate of plan.snapshot.candidates) {
			const reason = this.readSysdigCaptureGap(incidentDir, plan.phase, plan.requestFingerprint, candidate);
			if (reason) gaps.push(`${candidate.sourceName}:${reason}`);
		}
		return gaps;
	}

	private captureSysdigSnapshot(
		incidentDir: string,
		request: SysdigPinRequest,
		snapshot: SysdigRingSnapshot,
		phase: "initial" | "rotated" | "final",
		requestFingerprint: string,
		budget: SysdigWorkBudget,
		includeActive: boolean,
	): boolean {
		for (const candidate of snapshot.candidates) {
			if (!includeActive && candidate.activeAtRequest) continue;
			if (this.readSysdigCaptureGap(incidentDir, phase, requestFingerprint, candidate)) continue;
			const state = this.readSysdigSegmentRecordState(incidentDir);
			this.recordSysdigPinIssues(incidentDir, state.issues);
			if (state.saturated) {
				this.writeSysdigCaptureGap(incidentDir, phase, requestFingerprint, candidate, "pin_record_state_saturated");
				this.writeProviderPinIncomplete(
					incidentDir,
					"sysdig",
					`${phase}_capture_incomplete:${candidate.sourceName}:pin_record_state_saturated`,
					request,
				);
				continue;
			}
			const existing = state.records.find((record) => record.id === candidate.id);
			if (!existing && state.recordFileCount >= SYSDIG_PIN_MAX_SEGMENTS) {
				this.recordSysdigPinIssues(incidentDir, ["pin_record_count_bound_reached"]);
				this.writeSysdigCaptureGap(
					incidentDir,
					phase,
					requestFingerprint,
					candidate,
					"pin_record_count_bound_reached",
				);
				this.writeProviderPinIncomplete(
					incidentDir,
					"sysdig",
					`${phase}_capture_incomplete:${candidate.sourceName}:pin_record_count_bound_reached`,
					request,
				);
				continue;
			}
			if (!existing && state.totalBytes + candidate.source.bytes > SYSDIG_PIN_MAX_TOTAL_BYTES) {
				this.recordSysdigPinIssues(incidentDir, ["incident_sysdig_pin_total_byte_bound_exceeded"]);
				this.writeSysdigCaptureGap(
					incidentDir,
					phase,
					requestFingerprint,
					candidate,
					"incident_sysdig_pin_total_byte_bound_exceeded",
				);
				this.writeProviderPinIncomplete(
					incidentDir,
					"sysdig",
					`${phase}_capture_incomplete:${candidate.sourceName}:incident_sysdig_pin_total_byte_bound_exceeded`,
					request,
				);
				continue;
			}
			try {
				const result = this.captureSysdigSegment(
					incidentDir,
					request,
					candidate,
					snapshot.observedAtWallTimeMs,
					phase,
					candidate.activeAtRequest,
					budget,
				);
				if (!result.complete) return false;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOSPC") throw error;
				const reason = error instanceof Error ? error.message : "capture_failed";
				this.recordSysdigPinIssues(incidentDir, [`capture_failed:${candidate.sourceName}:${reason}`]);
				this.writeSysdigCaptureGap(incidentDir, phase, requestFingerprint, candidate, reason);
				this.writeProviderPinIncomplete(
					incidentDir,
					"sysdig",
					`${phase}_capture_incomplete:${candidate.sourceName}:${reason}`,
					request,
				);
			}
		}
		return true;
	}

	private advancePlannedSysdigCapture(
		incidentDir: string,
		request: SysdigPinRequest,
		plan: SysdigCapturePlan,
		budget: SysdigWorkBudget,
	): boolean {
		const markerPath =
			plan.phase === "initial"
				? this.sysdigInitialCompletePath(incidentDir)
				: this.sysdigFinalCaptureCompletePath(incidentDir);
		if (this.sysdigCaptureMarkerMatches(markerPath, plan)) return true;
		if (
			!this.captureSysdigSnapshot(
				incidentDir,
				request,
				plan.snapshot,
				plan.phase,
				plan.requestFingerprint,
				budget,
				true,
			)
		)
			return false;
		const gaps = this.sysdigPlanGaps(incidentDir, plan);
		if (gaps.length > 0) {
			this.writeProviderPinIncomplete(incidentDir, "sysdig", `${plan.phase}_capture_incomplete:${gaps[0]}`, request);
		}
		this.writeOwnedJson(markerPath, {
			version: 1,
			state: "complete",
			phase: plan.phase,
			requestFingerprint: plan.requestFingerprint,
			candidateIds: plan.snapshot.candidates.map((candidate) => candidate.id),
			outcome: gaps.length === 0 ? "complete" : "incomplete",
			gaps,
		});
		if (plan.phase === "initial") this.options.onSysdigPinStep?.("initial_capture_complete");
		return true;
	}

	private captureRotatedSysdigSegments(
		incidentDir: string,
		request: SysdigPinRequest,
		nowMs: number,
		budget: SysdigWorkBudget,
	): boolean {
		const snapshot = this.discoverSysdigRingSnapshot(request.ringBasePath, nowMs);
		this.recordSysdigPinIssues(incidentDir, snapshot.issues);
		return this.captureSysdigSnapshot(
			incidentDir,
			request,
			snapshot,
			"rotated",
			this.sysdigRequestFingerprint(request),
			budget,
			false,
		);
	}

	private readSysdigFinalVerification(
		incidentDir: string,
		record: SysdigPinnedSegmentRecord,
		artifactGenerationId: string,
	): Record<string, unknown> | undefined {
		try {
			const verification = JSON.parse(
				readFileSync(this.sysdigFinalVerificationPath(incidentDir, record.id), "utf8"),
			) as Record<string, unknown>;
			const exactBytes = verification.exactBytes as Record<string, unknown> | undefined;
			const sealedArtifact = verification.sealedArtifact;
			if (
				!hasExactOwnKeys(verification, [
					"version",
					"state",
					"artifactGenerationId",
					"recordId",
					"pinnedPath",
					"exactBytes",
					"changedAfterCapture",
					"sealedArtifact",
				]) ||
				verification.version !== 1 ||
				verification.state !== "verified" ||
				verification.artifactGenerationId !== artifactGenerationId ||
				verification.recordId !== record.id ||
				verification.pinnedPath !== record.pinnedPath ||
				!exactBytes ||
				!Number.isSafeInteger(exactBytes.bytes) ||
				Number(exactBytes.bytes) < 0 ||
				Number(exactBytes.bytes) > SYSDIG_PIN_MAX_SEGMENT_BYTES ||
				typeof exactBytes.sha256 !== "string" ||
				!/^[0-9a-f]{64}$/.test(exactBytes.sha256) ||
				!isSealedArtifact(sealedArtifact) ||
				sealedArtifact.generationId !== artifactGenerationId ||
				sealedArtifact.bytes !== exactBytes.bytes ||
				sealedArtifact.sha256 !== exactBytes.sha256
			) {
				return undefined;
			}
			const artifact = lstatSync(record.pinnedPath);
			const expectedUid = typeof process.getuid === "function" ? process.getuid() : artifact.uid;
			if (
				!artifact.isFile() ||
				artifact.isSymbolicLink() ||
				artifact.uid !== expectedUid ||
				String(artifact.dev) !== sealedArtifact.dev ||
				String(artifact.ino) !== sealedArtifact.ino ||
				artifact.size !== sealedArtifact.bytes ||
				artifact.mtimeMs !== sealedArtifact.mtimeMs ||
				artifact.ctimeMs !== sealedArtifact.ctimeMs ||
				(artifact.mode & 0o777) !== sealedArtifact.mode ||
				artifact.nlink !== sealedArtifact.nlink
			)
				return undefined;
			return verification;
		} catch {
			return undefined;
		}
	}

	private discardSysdigSegmentVerification(): void {
		const state = this.sysdigSegmentVerification;
		this.sysdigSegmentVerification = undefined;
		if (!state) return;
		try {
			closeSync(state.descriptor);
		} catch {}
	}

	private advanceSysdigSegmentVerification(
		incidentDir: string,
		record: SysdigPinnedSegmentRecord,
		artifactGenerationId: string,
		budget: SysdigWorkBudget,
	): boolean {
		if (this.readSysdigFinalVerification(incidentDir, record, artifactGenerationId)) return true;
		if (this.sysdigSegmentVerification?.recordId !== record.id) this.discardSysdigSegmentVerification();
		let state = this.sysdigSegmentVerification;
		try {
			if (!state) {
				const descriptor = openSync(record.pinnedPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
				const opened = fstatSync(descriptor);
				const expectedUid = typeof process.getuid === "function" ? process.getuid() : opened.uid;
				const artifactAtCapture = record.artifactAtCapture;
				if (
					!hasExactOwnKeys(artifactAtCapture, ["dev", "ino", "bytes", "mtimeMs", "ctimeMs", "mode", "nlink"]) ||
					!opened.isFile() ||
					opened.size < 0 ||
					opened.size > SYSDIG_PIN_MAX_SEGMENT_BYTES ||
					opened.nlink !== 1 ||
					opened.uid !== expectedUid ||
					(opened.mode & 0o077) !== 0 ||
					artifactAtCapture.dev !== String(opened.dev) ||
					artifactAtCapture.ino !== String(opened.ino) ||
					artifactAtCapture.bytes !== opened.size ||
					artifactAtCapture.mtimeMs !== opened.mtimeMs ||
					artifactAtCapture.ctimeMs !== opened.ctimeMs ||
					artifactAtCapture.mode !== (opened.mode & 0o777) ||
					artifactAtCapture.nlink !== opened.nlink
				) {
					closeSync(descriptor);
					throw new Error("pinned_path_not_verifiable_regular_file");
				}
				state = {
					recordId: record.id,
					descriptor,
					offset: 0,
					hash: createHash("sha256"),
					identity: {
						dev: opened.dev,
						ino: opened.ino,
						bytes: opened.size,
						mtimeMs: opened.mtimeMs,
						ctimeMs: opened.ctimeMs,
						nlink: opened.nlink,
						mode: opened.mode,
						uid: opened.uid,
					},
				};
				this.sysdigSegmentVerification = state;
			}
			const buffer = Buffer.allocUnsafe(Math.min(SYSDIG_PIN_COPY_BUFFER_BYTES, Math.max(1, budget.remainingBytes)));
			while (state.offset < state.identity.bytes && budget.remainingBytes > 0) {
				const count = readSync(
					state.descriptor,
					buffer,
					0,
					Math.min(buffer.length, budget.remainingBytes, state.identity.bytes - state.offset),
					state.offset,
				);
				if (count <= 0) throw new Error("pinned_path_truncated_during_bounded_verification");
				state.hash.update(buffer.subarray(0, count));
				state.offset += count;
				budget.remainingBytes -= count;
			}
			if (state.offset < state.identity.bytes) return false;
			const after = fstatSync(state.descriptor);
			if (
				after.dev !== state.identity.dev ||
				after.ino !== state.identity.ino ||
				after.size !== state.identity.bytes ||
				after.mtimeMs !== state.identity.mtimeMs ||
				after.ctimeMs !== state.identity.ctimeMs ||
				after.nlink !== state.identity.nlink ||
				after.mode !== state.identity.mode ||
				after.uid !== state.identity.uid ||
				readSync(state.descriptor, Buffer.allocUnsafe(1), 0, 1, state.identity.bytes) !== 0
			) {
				throw new Error("pinned_path_changed_during_bounded_verification");
			}
			const digest = state.hash.digest("hex");
			const changedAfterCapture = state.identity.bytes !== record.bytesAtCapture;
			closeSync(state.descriptor);
			this.sysdigSegmentVerification = undefined;
			const sealedArtifact = this.sealPrivateArtifact(
				record.pinnedPath,
				state.identity.bytes,
				digest,
				artifactGenerationId,
			);
			this.writeOwnedJson(
				this.sysdigFinalVerificationPath(incidentDir, record.id),
				{
					version: 1,
					state: "verified",
					artifactGenerationId,
					recordId: record.id,
					pinnedPath: record.pinnedPath,
					exactBytes: { bytes: state.identity.bytes, sha256: digest },
					changedAfterCapture,
					sealedArtifact,
				},
				64 * 1024,
			);
			return true;
		} catch (error) {
			this.discardSysdigSegmentVerification();
			throw error;
		}
	}

	private readOrCreateSysdigFinalVerificationPlan(
		incidentDir: string,
		request: SysdigPinRequest,
	): SysdigFinalVerificationPlan {
		const path = this.sysdigFinalPlanPath(incidentDir);
		const requestFingerprint = this.sysdigRequestFingerprint(request);
		try {
			const plan = JSON.parse(readFileSync(path, "utf8")) as SysdigFinalVerificationPlan;
			if (
				plan.version !== 1 ||
				plan.state !== "planned" ||
				plan.requestFingerprint !== requestFingerprint ||
				!Array.isArray(plan.recordIds) ||
				plan.recordIds.length > SYSDIG_PIN_MAX_SEGMENTS ||
				plan.recordIds.some((id) => typeof id !== "string" || !/^[0-9a-f]{64}$/.test(id))
			) {
				throw new Error("sysdig_final_verification_plan_invalid");
			}
			return plan;
		} catch (error) {
			if (existsSync(path)) throw error;
		}
		const recordState = this.readSysdigSegmentRecordState(incidentDir);
		if (recordState.saturated) throw new Error("sysdig_pin_record_state_saturated_before_verification");
		const plan: SysdigFinalVerificationPlan = {
			version: 1,
			state: "planned",
			requestFingerprint,
			recordIds: recordState.records.map((record) => record.id).sort(),
		};
		this.writeOwnedJson(path, plan, 64 * 1024);
		return plan;
	}

	private advanceSysdigFinalVerifications(
		incidentDir: string,
		plan: SysdigFinalVerificationPlan,
		budget: SysdigWorkBudget,
	): boolean {
		const records = new Map(
			this.readSysdigSegmentRecordState(incidentDir).records.map((record) => [record.id, record]),
		);
		const artifactGenerationId = this.sysdigArtifactGenerationId(plan.requestFingerprint);
		for (const id of plan.recordIds) {
			const record = records.get(id);
			if (!record) throw new Error(`sysdig_final_verification_record_missing:${id}`);
			if (this.readSysdigFinalVerification(incidentDir, record, artifactGenerationId)) continue;
			if (budget.remainingBytes <= 0) return false;
			if (!this.advanceSysdigSegmentVerification(incidentDir, record, artifactGenerationId, budget)) return false;
		}
		return true;
	}

	private readSysdigCaptureOutcome(path: string): { outcome: "complete" | "incomplete"; gaps: string[] } {
		const marker = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
		if (
			(marker.outcome !== "complete" && marker.outcome !== "incomplete") ||
			!Array.isArray(marker.gaps) ||
			marker.gaps.some((gap) => typeof gap !== "string" || Buffer.byteLength(gap) > 4096)
		) {
			throw new Error("sysdig_capture_outcome_marker_invalid");
		}
		return { outcome: marker.outcome, gaps: marker.gaps as string[] };
	}

	private publishSysdigPinManifest(
		incidentDir: string,
		request: SysdigPinRequest,
		plan: SysdigFinalVerificationPlan,
	): void {
		const manifestPath = join(incidentDir, "sysdig-pin-manifest.json");
		const gaps = [...this.readSysdigPinIssues(incidentDir)];
		const initialCapture = this.readSysdigCaptureOutcome(this.sysdigInitialCompletePath(incidentDir));
		const finalCapture = this.readSysdigCaptureOutcome(this.sysdigFinalCaptureCompletePath(incidentDir));
		gaps.push(...initialCapture.gaps.map((gap) => `initial_capture_gap:${gap}`));
		gaps.push(...finalCapture.gaps.map((gap) => `final_capture_gap:${gap}`));
		const captureOutcome =
			initialCapture.outcome === "complete" && finalCapture.outcome === "complete" ? "complete" : "incomplete";
		const recordState = this.readSysdigSegmentRecordState(incidentDir);
		gaps.push(...recordState.issues);
		const records = new Map(recordState.records.map((record) => [record.id, record]));
		const artifactGenerationId = this.sysdigArtifactGenerationId(plan.requestFingerprint);
		const segments: Array<Record<string, unknown>> = [];
		for (const id of plan.recordIds) {
			const record = records.get(id);
			if (!record) throw new Error(`sysdig_final_manifest_record_missing:${id}`);
			const verification = this.readSysdigFinalVerification(incidentDir, record, artifactGenerationId);
			if (!verification) throw new Error(`sysdig_final_manifest_verification_missing:${id}`);
			if (verification.changedAfterCapture === true)
				gaps.push(`hard_link_changed_after_capture:${record.sourceName}`);
			segments.push({
				...record,
				exactBytes: verification.exactBytes,
				sealedArtifact: verification.sealedArtifact,
				changedAfterCapture: verification.changedAfterCapture === true,
			});
		}
		if (segments.length === 0) gaps.push("no_sysdig_ring_segments_were_pinned");
		gaps.push("scap_event_time_bounds_not_inspected_coverage_is_observation_based");
		this.writeOwnedJson(manifestPath, {
			version: 1,
			state: "finalized_with_observed_coverage",
			artifactGenerationId,
			diagnosticOnly: true,
			captureOutcome,
			capturePhases: { initial: initialCapture.outcome, final: finalCapture.outcome },
			runId: request.runId,
			requestedWindow: {
				fromWallTimeMs: request.fromWallTimeMs,
				anchorWallTimeMs: request.anchorWallTimeMs,
				throughWallTimeMs: request.throughWallTimeMs,
			},
			captureFinalizedAtWallTimeMs: request.resolveAfterWallTimeMs,
			retention: { milliseconds: SYSDIG_PIN_RETENTION_MS, retainUntilWallTimeMs: request.retainUntilWallTimeMs },
			sourceRing: {
				basePath: request.ringBasePath,
				configuredSegments: SYSDIG_RING_EXPECTED_SEGMENTS,
				rotationBytes: SYSDIG_RING_ROTATION_BYTES,
				compression: true,
			},
			coverage: {
				method:
					"all_observed_ring_segments_at_incident_finalization_plus_rotated_segments_observed_through_requested_end",
				historicalAvailability: "bounded_by_bytes_present_in_the_stock_ring_at_finalization",
				eventTimeBounds: "unknown_without_offline_scap_event_parsing",
				gaps: [...new Set(gaps)],
			},
			segments,
		});
		const sysdigManifestStat = lstatSync(manifestPath);
		const sysdigPinDirectory = join(incidentDir, "sysdig-pins", "segments");
		mkdirSync(sysdigPinDirectory, { recursive: true, mode: 0o700 });
		const sysdigPinDirectoryStat = lstatSync(sysdigPinDirectory);
		this.writeOrRepairProviderPinProof(incidentDir, "sysdig", {
			version: 1,
			state: "producer_verified_complete",
			provider: "sysdig",
			artifactGenerationId,
			manifestValidated: true,
			captureOutcome,
			capturePhases: { initial: initialCapture.outcome, final: finalCapture.outcome },
			runId: request.runId,
			fromWallTimeMs: request.fromWallTimeMs,
			throughWallTimeMs: request.throughWallTimeMs,
			retainUntilWallTimeMs: request.retainUntilWallTimeMs,
			retentionMilliseconds: SYSDIG_PIN_RETENTION_MS,
			segmentCount: segments.length,
			manifestIdentity: {
				dev: String(sysdigManifestStat.dev),
				ino: String(sysdigManifestStat.ino),
				size: sysdigManifestStat.size,
				mtimeMs: sysdigManifestStat.mtimeMs,
				ctimeMs: sysdigManifestStat.ctimeMs,
				nlink: sysdigManifestStat.nlink,
			},
			pinDirectoryIdentity: {
				path: "sysdig-pins/segments",
				dev: String(sysdigPinDirectoryStat.dev),
				ino: String(sysdigPinDirectoryStat.ino),
				mtimeMs: sysdigPinDirectoryStat.mtimeMs,
				ctimeMs: sysdigPinDirectoryStat.ctimeMs,
			},
		});
		fsyncDirectory(incidentDir);
	}

	private processSysdigPin(incidentDir: string, request: SysdigPinRequest, nowMs: number): boolean {
		const transaction = acquireIncidentCasTransaction(this.root);
		if (!transaction) return false;
		try {
			const budget: SysdigWorkBudget = {
				remainingBytes: positiveBound(this.options.sysdigPinWorkBytesPerPass, SYSDIG_PIN_WORK_BYTES_PER_PASS),
			};
			const initialPlan = this.readOrCreateSysdigCapturePlan(incidentDir, request, "initial", nowMs);
			if (!this.advancePlannedSysdigCapture(incidentDir, request, initialPlan, budget)) return false;
			if (nowMs < request.resolveAfterWallTimeMs) {
				return this.captureRotatedSysdigSegments(incidentDir, request, nowMs, budget);
			}
			const finalPlan = this.readOrCreateSysdigCapturePlan(incidentDir, request, "final", nowMs);
			if (!this.advancePlannedSysdigCapture(incidentDir, request, finalPlan, budget)) return false;
			const verificationPlan = this.readOrCreateSysdigFinalVerificationPlan(incidentDir, request);
			if (!this.advanceSysdigFinalVerifications(incidentDir, verificationPlan, budget)) return false;
			this.publishSysdigPinManifest(incidentDir, request, verificationPlan);
			return true;
		} finally {
			transaction.release();
		}
	}

	requestPin(runId: string, incidentDir: string, anchorWallTimeMs: number): void {
		if (this.pinRetentionMaintenance) throw new Error("Incident pin request deferred during retention maintenance");
		if (!isCanonicalUuid(runId) || !Number.isSafeInteger(anchorWallTimeMs) || anchorWallTimeMs < 0)
			throw new Error("Incident pin authority requires a canonical run id and non-negative integer anchor");
		const ringBasePath = this.options.sysdigRingBasePath ?? SYSDIG_RING_DEFAULT_BASE_PATH;
		const expectedRequest: SysdigPinRequest = {
			version: 1,
			runId,
			anchorWallTimeMs,
			fromWallTimeMs: anchorWallTimeMs - PIN_BEFORE_MS,
			throughWallTimeMs: anchorWallTimeMs + PIN_AFTER_MS,
			resolveAfterWallTimeMs: anchorWallTimeMs + PIN_AFTER_MS,
			// This request is immutable and may be replayed after a crash. Bind its bytes
			// to the incident anchor rather than the retrying service process's clock.
			requestedAtWallTimeMs: anchorWallTimeMs,
			retainUntilWallTimeMs: anchorWallTimeMs + SYSDIG_PIN_RETENTION_MS,
			ringBasePath,
		};
		const expectedJournalRequest: JournalPinRequest = {
			version: 1,
			state: "pending",
			runId,
			anchorWallTimeMs,
			fromWallTimeMs: anchorWallTimeMs - PIN_BEFORE_MS,
			throughWallTimeMs: anchorWallTimeMs + PIN_AFTER_MS,
			resolveAfterWallTimeMs: anchorWallTimeMs + PIN_AFTER_MS,
			retainUntilWallTimeMs: anchorWallTimeMs + INCIDENT_DIAGNOSTIC_RETENTION_MS,
		};
		const requestTransaction = acquireIncidentCasTransaction(this.root);
		if (!requestTransaction) throw new Error("Incident pin request transaction unavailable");
		let sysdigRequest: SysdigPinRequest;
		try {
			const existingAuthority = this.readIncidentPinAuthority(incidentDir);
			if (existingAuthority) {
				if (
					this.sysdigRequestBaseFingerprint(existingAuthority) !==
					this.sysdigRequestBaseFingerprint(expectedRequest)
				)
					throw new Error("Existing immutable incident pin authority does not match the requested incident pin");
				sysdigRequest = existingAuthority;
			} else if (existsSync(this.pinAuthorityPath(incidentDir))) {
				throw new Error("Existing immutable incident pin authority is invalid");
			} else {
				const snapshot = this.boundSysdigRequestSnapshot(
					expectedRequest,
					this.discoverSysdigRingSnapshot(ringBasePath, Date.now()),
				);
				sysdigRequest = { ...expectedRequest, initialRingSnapshot: snapshot };
				this.writeOwnedJson(this.pinAuthorityPath(incidentDir), sysdigRequest, 64 * 1024);
			}
			const sysdigPath = this.sysdigRequestPath(incidentDir);
			const existingSysdig = this.readSysdigPinRequest(incidentDir);
			if (!existingSysdig || canonicalJson(existingSysdig) !== canonicalJson(sysdigRequest)) {
				if (existsSync(sysdigPath)) {
					const identity = this.quarantineInvalidPinRequest(incidentDir, "sysdig", sysdigPath);
					this.writeProviderPinIncomplete(
						incidentDir,
						"sysdig",
						`${existingSysdig ? "sysdig_request_recreated_after_binding_mismatch" : "sysdig_request_recreated_after_corruption"}:${identity}`,
						sysdigRequest,
					);
				}
				this.writeOwnedJson(sysdigPath, sysdigRequest);
			}
			this.options.onSysdigPinStep?.("sysdig_request_durable");
			const journalPath = this.journalRequestPath(incidentDir);
			const existingJournal = this.readJournalPinRequest(incidentDir);
			if (existingJournal) {
				if (canonicalJson(existingJournal) !== canonicalJson(expectedJournalRequest)) {
					this.writeProviderPinIncomplete(
						incidentDir,
						"journal",
						"immutable_request_binding_conflict",
						expectedJournalRequest,
					);
					throw new Error("Existing immutable journal request does not match the requested incident pin");
				}
			} else {
				if (existsSync(journalPath)) {
					const identity = this.quarantineInvalidPinRequest(incidentDir, "journal", journalPath);
					this.writeProviderPinIncomplete(
						incidentDir,
						"journal",
						`journal_request_recreated_after_corruption:${identity}`,
						expectedJournalRequest,
					);
				}
				this.writeOwnedJson(journalPath, expectedJournalRequest);
			}
			this.options.onSysdigPinStep?.("provider_requests_durable");
		} finally {
			requestTransaction.release();
		}
		this.processSysdigPin(incidentDir, sysdigRequest, Date.now());
	}

	private retentionProofMatchesRequest(path: string, provider: "journal", request: JournalPinRequest): boolean {
		try {
			const stat = lstatSync(path);
			const expectedUid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
			if (
				!stat.isFile() ||
				stat.isSymbolicLink() ||
				stat.nlink !== 1 ||
				stat.uid !== expectedUid ||
				(stat.mode & 0o077) !== 0 ||
				stat.size > 64 * 1024
			)
				return false;
			const proof = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
			if (
				!hasExactOwnKeys(proof, [
					"version",
					"state",
					"provider",
					"artifactGenerationId",
					"manifestValidated",
					"occurrenceReferencesResolved",
					"runId",
					"fromWallTimeMs",
					"throughWallTimeMs",
					"retainUntilWallTimeMs",
					"retentionMilliseconds",
					"occurrenceCount",
					"manifestIdentity",
					"pinDirectoryIdentity",
				]) ||
				!hasExactOwnKeys(proof.manifestIdentity, ["dev", "ino", "size", "mtimeMs", "ctimeMs", "nlink"]) ||
				!hasExactOwnKeys(proof.pinDirectoryIdentity, ["path", "dev", "ino", "mtimeMs", "ctimeMs"])
			)
				return false;
			const manifestIdentity = proof.manifestIdentity;
			const pinDirectoryIdentity = proof.pinDirectoryIdentity;
			const manifestPath = join(dirname(path), "journal-pin-manifest.json");
			const manifest = lstatSync(manifestPath);
			const pinDirectoryPath = join(dirname(path), "journal-pins", "cas");
			const pinDirectory = lstatSync(pinDirectoryPath);
			return (
				proof.version === 1 &&
				proof.state === "producer_verified_complete" &&
				proof.provider === provider &&
				proof.artifactGenerationId === this.journalArtifactGenerationId(request) &&
				proof.manifestValidated === true &&
				proof.occurrenceReferencesResolved === true &&
				proof.runId === request.runId &&
				proof.fromWallTimeMs === request.fromWallTimeMs &&
				proof.throughWallTimeMs === request.throughWallTimeMs &&
				proof.retainUntilWallTimeMs === request.retainUntilWallTimeMs &&
				proof.retentionMilliseconds === INCIDENT_DIAGNOSTIC_RETENTION_MS &&
				Number.isSafeInteger(proof.occurrenceCount) &&
				Number(proof.occurrenceCount) >= 0 &&
				Number(proof.occurrenceCount) <= PENDING_ENTRY_MAX_COUNT &&
				manifest.isFile() &&
				!manifest.isSymbolicLink() &&
				manifest.nlink === 1 &&
				manifest.uid === expectedUid &&
				(manifest.mode & 0o077) === 0 &&
				manifest.size <= PENDING_ENTRY_MAX_BYTES &&
				manifestIdentity.dev === String(manifest.dev) &&
				manifestIdentity.ino === String(manifest.ino) &&
				manifestIdentity.size === manifest.size &&
				manifestIdentity.mtimeMs === manifest.mtimeMs &&
				manifestIdentity.ctimeMs === manifest.ctimeMs &&
				manifestIdentity.nlink === manifest.nlink &&
				pinDirectory.isDirectory() &&
				!pinDirectory.isSymbolicLink() &&
				pinDirectory.uid === expectedUid &&
				(pinDirectory.mode & 0o077) === 0 &&
				pinDirectoryIdentity.path === "journal-pins/cas" &&
				pinDirectoryIdentity.dev === String(pinDirectory.dev) &&
				pinDirectoryIdentity.ino === String(pinDirectory.ino) &&
				pinDirectoryIdentity.mtimeMs === pinDirectory.mtimeMs &&
				pinDirectoryIdentity.ctimeMs === pinDirectory.ctimeMs
			);
		} catch {
			return false;
		}
	}

	private startJournalManifestValidation(incidentDir: string, manifestPath: string, request: JournalPinRequest): void {
		let descriptor: number | undefined;
		try {
			const before = lstatSync(manifestPath);
			if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > PENDING_ENTRY_MAX_BYTES)
				throw new Error("manifest_metadata_invalid");
			descriptor = openSync(manifestPath, "r");
			const opened = fstatSync(descriptor);
			if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size)
				throw new Error("manifest_identity_changed");
			this.journalManifestValidation = {
				incidentDir,
				manifestPath,
				descriptor,
				runId: request.runId,
				anchorWallTimeMs: request.anchorWallTimeMs,
				fromWallTimeMs: request.fromWallTimeMs,
				throughWallTimeMs: request.throughWallTimeMs,
				retainUntilWallTimeMs: request.retainUntilWallTimeMs,
				offset: 0,
				size: opened.size,
				dev: opened.dev,
				ino: opened.ino,
				mtimeMs: opened.mtimeMs,
				ctimeMs: opened.ctimeMs,
				nlink: opened.nlink,
				phase: "header",
				textBuffer: "",
				objectText: "",
				objectDepth: 0,
				objectInString: false,
				objectEscape: false,
				fileEnded: false,
				occurrenceCount: 0,
				resolvedOccurrenceCount: 0,
				cursorBytes: 0,
				verifiedPins: new Map(),
			};
			descriptor = undefined;
		} catch (error) {
			if (descriptor !== undefined)
				try {
					closeSync(descriptor);
				} catch {}
			try {
				this.writeOwnedJson(join(incidentDir, "journal-pin-manifest-invalid.json"), {
					version: 1,
					state: "invalid",
					runId: request.runId,
					reason: error instanceof Error ? error.message : String(error),
				});
			} catch {}
		}
	}

	private failJournalManifestValidation(state: JournalManifestValidation, reason: string): void {
		try {
			closeSync(state.descriptor);
		} catch {}
		if (state.pinValidation)
			try {
				closeSync(state.pinValidation.descriptor);
			} catch {}
		this.journalManifestValidation = undefined;
		try {
			this.writeOwnedJson(join(state.incidentDir, "journal-pin-manifest-invalid.json"), {
				version: 1,
				state: "invalid",
				runId: state.runId,
				reason,
			});
		} catch {}
	}

	private parseNextJournalManifestOccurrence(
		state: JournalManifestValidation,
	): "need_more" | "occurrence" | "complete" {
		if (state.phase === "header") {
			const match = /"occurrences"\s*:\s*\[/.exec(state.textBuffer);
			if (!match) {
				if (state.textBuffer.length > 64 * 1024 || state.fileEnded)
					throw new Error("manifest_header_invalid_or_unbounded");
				return "need_more";
			}
			const openBracket = match.index + match[0].lastIndexOf("[");
			const syntheticHeader = `${state.textBuffer.slice(0, match.index)}"occurrences":[]}`;
			const header = JSON.parse(syntheticHeader) as Record<string, unknown>;
			if (
				(header.version !== 1 && header.version !== 2) ||
				(header.version === 1 &&
					!hasExactOwnKeys(header, [
						"version",
						"state",
						"runId",
						"fromWallTimeMs",
						"throughWallTimeMs",
						"occurrences",
					])) ||
				(header.version === 2 &&
					!hasExactOwnKeys(header, [
						"version",
						"state",
						"artifactGenerationId",
						"runId",
						"fromWallTimeMs",
						"throughWallTimeMs",
						"occurrences",
					])) ||
				header.state !== "complete_through_requested_window" ||
				(header.version === 2 &&
					(typeof header.artifactGenerationId !== "string" ||
						!/^[0-9a-f]{64}$/.test(header.artifactGenerationId) ||
						header.artifactGenerationId !==
							this.journalArtifactGenerationId({
								runId: state.runId,
								anchorWallTimeMs: state.anchorWallTimeMs,
								fromWallTimeMs: state.fromWallTimeMs,
								throughWallTimeMs: state.throughWallTimeMs,
							}))) ||
				header.runId !== state.runId ||
				header.fromWallTimeMs !== state.fromWallTimeMs ||
				header.throughWallTimeMs !== state.throughWallTimeMs ||
				!Array.isArray(header.occurrences) ||
				header.occurrences.length !== 0
			)
				throw new Error("manifest_header_schema_invalid");
			state.manifestVersion = header.version === 1 ? 1 : 2;
			state.artifactGenerationId =
				typeof header.artifactGenerationId === "string"
					? header.artifactGenerationId
					: this.journalArtifactGenerationId({
							runId: state.runId,
							anchorWallTimeMs: state.anchorWallTimeMs,
							fromWallTimeMs: state.fromWallTimeMs,
							throughWallTimeMs: state.throughWallTimeMs,
						});
			state.textBuffer = state.textBuffer.slice(openBracket + 1);
			state.phase = "occurrences";
		}
		if (state.phase === "occurrences") {
			let index = 0;
			while (index < state.textBuffer.length) {
				const character = state.textBuffer[index];
				if (state.objectDepth === 0) {
					if (/\s|,/.test(character)) {
						index += 1;
						continue;
					}
					if (character === "]") {
						state.textBuffer = state.textBuffer.slice(index + 1);
						state.phase = "suffix";
						break;
					}
					if (character !== "{") throw new Error("manifest_occurrence_array_syntax_invalid");
					state.objectDepth = 1;
					state.objectText = "{";
					index += 1;
					continue;
				}
				state.objectText += character;
				if (state.objectText.length > 64 * 1024) throw new Error("manifest_occurrence_record_unbounded");
				if (state.objectInString) {
					if (state.objectEscape) state.objectEscape = false;
					else if (character === "\\") state.objectEscape = true;
					else if (character === '"') state.objectInString = false;
				} else if (character === '"') state.objectInString = true;
				else if (character === "{") state.objectDepth += 1;
				else if (character === "}") state.objectDepth -= 1;
				index += 1;
				if (state.objectDepth === 0) {
					const parsed = JSON.parse(state.objectText) as Record<string, unknown>;
					state.objectText = "";
					state.textBuffer = state.textBuffer.slice(index);
					const cas = parsed.cas;
					const cursors = parsed.cursors;
					const manifestVersion = state.manifestVersion;
					if (
						(manifestVersion !== 1 && manifestVersion !== 2) ||
						(manifestVersion === 2 &&
							!hasExactOwnKeys(parsed, [
								"occurrenceReference",
								"semanticFingerprint",
								"cursors",
								"cas",
								"eventWallTimeMs",
								"pinnedCasPath",
								"sealedArtifact",
							])) ||
						!isJournalOccurrenceReference(parsed.occurrenceReference, manifestVersion, join(this.root, "refs")) ||
						(manifestVersion === 2 &&
							(typeof parsed.semanticFingerprint !== "string" ||
								!/^[0-9a-f]{64}$/.test(parsed.semanticFingerprint))) ||
						(manifestVersion === 1 &&
							parsed.semanticFingerprint !== undefined &&
							(typeof parsed.semanticFingerprint !== "string" ||
								!/^[0-9a-f]{64}$/.test(parsed.semanticFingerprint))) ||
						!Array.isArray(cursors) ||
						cursors.length > PIN_CURSOR_MAX_COUNT ||
						cursors.some((cursor) => typeof cursor !== "string") ||
						typeof parsed.eventWallTimeMs !== "string" ||
						typeof parsed.pinnedCasPath !== "string" ||
						!cas ||
						typeof cas !== "object" ||
						Array.isArray(cas)
					)
						throw new Error("manifest_occurrence_schema_invalid");
					const casRecord = cas as Record<string, unknown>;
					if (
						typeof casRecord.digest !== "string" ||
						!/^[0-9a-f]{64}$/.test(casRecord.digest) ||
						!Number.isSafeInteger(casRecord.bytes) ||
						Number(casRecord.bytes) < 0 ||
						Number(casRecord.bytes) > 983_040 ||
						casRecord.path !==
							join(this.root, "cas", "sha256", casRecord.digest.slice(0, 2), `${casRecord.digest}.blob`) ||
						parsed.pinnedCasPath !== join(state.incidentDir, "journal-pins", "cas", `${casRecord.digest}.blob`) ||
						(manifestVersion === 2 &&
							(!isSealedArtifact(parsed.sealedArtifact) ||
								parsed.sealedArtifact.generationId !== state.artifactGenerationId ||
								parsed.sealedArtifact.bytes !== casRecord.bytes ||
								parsed.sealedArtifact.sha256 !== casRecord.digest))
					)
						throw new Error("manifest_occurrence_cas_schema_invalid");
					state.cursorBytes += (cursors as string[]).reduce(
						(total, cursor) => total + Buffer.byteLength(cursor),
						0,
					);
					if (state.cursorBytes > PIN_CURSOR_MAX_BYTES) throw new Error("manifest_cursor_byte_bound_exceeded");
					state.occurrenceCount += 1;
					if (state.occurrenceCount > PENDING_ENTRY_MAX_COUNT)
						throw new Error("manifest_occurrence_count_bound_exceeded");
					state.pendingOccurrence = {
						occurrenceReference: parsed.occurrenceReference,
						...(typeof parsed.semanticFingerprint === "string"
							? { semanticFingerprint: parsed.semanticFingerprint }
							: {}),
						cursors: cursors as string[],
						cas: { digest: casRecord.digest, bytes: Number(casRecord.bytes), path: casRecord.path as string },
						eventWallTimeMs: parsed.eventWallTimeMs,
						pinnedCasPath: parsed.pinnedCasPath,
						...(isSealedArtifact(parsed.sealedArtifact) ? { sealedArtifact: parsed.sealedArtifact } : {}),
					};
					return "occurrence";
				}
			}
			if (state.phase === "occurrences") {
				state.textBuffer = state.objectDepth > 0 ? "" : state.textBuffer.slice(index);
				if (state.fileEnded) throw new Error("manifest_occurrence_array_truncated");
				return "need_more";
			}
		}
		if (state.phase === "suffix") {
			if (!state.fileEnded) return "need_more";
			if (state.objectDepth !== 0 || state.textBuffer.trim() !== "}") throw new Error("manifest_suffix_invalid");
			return "complete";
		}
		return "need_more";
	}

	private validatePendingJournalManifestPin(state: JournalManifestValidation): void {
		const occurrence = state.pendingOccurrence;
		if (!occurrence) return;
		this.resolveManifestOccurrenceReference(state, occurrence);
		const previous = state.verifiedPins.get(occurrence.cas.digest);
		if (previous) {
			if (
				previous.bytes !== occurrence.cas.bytes ||
				previous.pinnedPath !== occurrence.pinnedCasPath ||
				canonicalJson(previous.sealedArtifact ?? null) !== canonicalJson(occurrence.sealedArtifact ?? null)
			)
				throw new Error("manifest_duplicate_digest_inconsistent");
			state.pendingOccurrence = undefined;
			return;
		}
		const pinned = lstatSync(occurrence.pinnedCasPath);
		const global = lstatSync(occurrence.cas.path);
		const sealedArtifact = occurrence.sealedArtifact;
		const expectedUid = typeof process.getuid === "function" ? process.getuid() : pinned.uid;
		const sealedPrivateCopyValid =
			state.manifestVersion === 2 &&
			sealedArtifact !== undefined &&
			sealedArtifact.generationId === state.artifactGenerationId &&
			sealedArtifact.sha256 === occurrence.cas.digest &&
			sealedArtifact.bytes === occurrence.cas.bytes &&
			sealedArtifact.dev === String(pinned.dev) &&
			sealedArtifact.ino === String(pinned.ino) &&
			sealedArtifact.mtimeMs === pinned.mtimeMs &&
			sealedArtifact.ctimeMs === pinned.ctimeMs &&
			sealedArtifact.mode === (pinned.mode & 0o777) &&
			sealedArtifact.nlink === pinned.nlink &&
			pinned.nlink === 1 &&
			pinned.uid === expectedUid &&
			(pinned.mode & 0o777) === 0o400;
		const legacyHardLinkValid =
			state.manifestVersion === 1 && global.dev === pinned.dev && global.ino === pinned.ino && pinned.nlink >= 2;
		if (
			!pinned.isFile() ||
			pinned.isSymbolicLink() ||
			pinned.size !== occurrence.cas.bytes ||
			!global.isFile() ||
			global.isSymbolicLink() ||
			global.size !== occurrence.cas.bytes ||
			(!sealedPrivateCopyValid && !legacyHardLinkValid)
		) {
			throw new Error("manifest_pin_identity_or_size_invalid");
		}
		const descriptor = openSync(occurrence.pinnedCasPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const opened = fstatSync(descriptor);
		if (
			opened.dev !== pinned.dev ||
			opened.ino !== pinned.ino ||
			opened.size !== pinned.size ||
			(sealedArtifact !== undefined &&
				(opened.mtimeMs !== sealedArtifact.mtimeMs ||
					opened.ctimeMs !== sealedArtifact.ctimeMs ||
					(opened.mode & 0o777) !== sealedArtifact.mode ||
					opened.nlink !== sealedArtifact.nlink))
		) {
			closeSync(descriptor);
			throw new Error("manifest_pin_changed_before_hash");
		}
		state.pinValidation = {
			descriptor,
			digest: occurrence.cas.digest,
			bytes: occurrence.cas.bytes,
			pinnedPath: occurrence.pinnedCasPath,
			offset: 0,
			hash: createHash("sha256"),
			dev: opened.dev,
			ino: opened.ino,
			mtimeMs: opened.mtimeMs,
			ctimeMs: opened.ctimeMs,
			mode: opened.mode,
			uid: opened.uid,
			nlink: opened.nlink,
			...(sealedArtifact ? { sealedArtifact } : {}),
		};
		state.pendingOccurrence = undefined;
	}

	private advanceJournalManifestPinHash(state: JournalManifestValidation): void {
		const pin = state.pinValidation;
		if (!pin) return;
		const buffer = Buffer.allocUnsafe(64 * 1024);
		const count = readSync(pin.descriptor, buffer, 0, Math.min(buffer.length, pin.bytes - pin.offset), pin.offset);
		if (count > 0) {
			pin.hash.update(buffer.subarray(0, count));
			pin.offset += count;
			return;
		}
		const after = fstatSync(pin.descriptor);
		closeSync(pin.descriptor);
		state.pinValidation = undefined;
		if (
			pin.offset !== pin.bytes ||
			after.dev !== pin.dev ||
			after.ino !== pin.ino ||
			after.size !== pin.bytes ||
			after.mtimeMs !== pin.mtimeMs ||
			after.ctimeMs !== pin.ctimeMs ||
			after.mode !== pin.mode ||
			after.uid !== pin.uid ||
			after.nlink !== pin.nlink ||
			pin.hash.digest("hex") !== pin.digest
		)
			throw new Error("manifest_pin_content_verification_failed");
		state.verifiedPins.set(pin.digest, {
			bytes: pin.bytes,
			pinnedPath: pin.pinnedPath,
			dev: pin.dev,
			ino: pin.ino,
			...(pin.sealedArtifact ? { sealedArtifact: pin.sealedArtifact } : {}),
		});
	}

	private completeJournalManifestValidation(state: JournalManifestValidation): void {
		if (state.resolvedOccurrenceCount !== state.occurrenceCount) {
			throw new Error("manifest_occurrence_references_not_fully_resolved");
		}
		if (!state.artifactGenerationId) throw new Error("manifest_artifact_generation_missing");
		const after = fstatSync(state.descriptor);
		closeSync(state.descriptor);
		this.journalManifestValidation = undefined;
		if (
			after.dev !== state.dev ||
			after.ino !== state.ino ||
			after.size !== state.size ||
			after.mtimeMs !== state.mtimeMs ||
			after.ctimeMs !== state.ctimeMs ||
			after.nlink !== state.nlink
		)
			throw new Error("manifest_identity_changed_during_validation");
		const pinDirectory = join(state.incidentDir, "journal-pins", "cas");
		const pinStat = lstatSync(pinDirectory);
		this.writeOrRepairProviderPinProof(state.incidentDir, "journal", {
			version: 1,
			state: "producer_verified_complete",
			provider: "journal",
			artifactGenerationId: state.artifactGenerationId,
			manifestValidated: true,
			occurrenceReferencesResolved: true,
			runId: state.runId,
			fromWallTimeMs: state.fromWallTimeMs,
			throughWallTimeMs: state.throughWallTimeMs,
			retainUntilWallTimeMs: state.retainUntilWallTimeMs,
			retentionMilliseconds: INCIDENT_DIAGNOSTIC_RETENTION_MS,
			occurrenceCount: state.occurrenceCount,
			manifestIdentity: {
				dev: String(after.dev),
				ino: String(after.ino),
				size: after.size,
				mtimeMs: after.mtimeMs,
				ctimeMs: after.ctimeMs,
				nlink: after.nlink,
			},
			pinDirectoryIdentity: {
				path: "journal-pins/cas",
				dev: String(pinStat.dev),
				ino: String(pinStat.ino),
				mtimeMs: pinStat.mtimeMs,
				ctimeMs: pinStat.ctimeMs,
			},
		});
	}

	private advanceJournalManifestValidation(): void {
		const state = this.journalManifestValidation;
		if (!state) return;
		const buffer = Buffer.allocUnsafe(64 * 1024);
		try {
			let byteChunks = 0;
			for (let work = 0; work < 64; work += 1) {
				if (state.pinValidation) {
					if (byteChunks >= 4) return;
					this.advanceJournalManifestPinHash(state);
					byteChunks += 1;
					continue;
				}
				if (state.pendingOccurrence) {
					this.validatePendingJournalManifestPin(state);
					continue;
				}
				const parsed = this.parseNextJournalManifestOccurrence(state);
				if (parsed === "occurrence") continue;
				if (parsed === "complete") {
					this.completeJournalManifestValidation(state);
					return;
				}
				if (state.fileEnded) throw new Error("manifest_truncated");
				if (byteChunks >= 4) return;
				const count = readSync(state.descriptor, buffer, 0, buffer.length, state.offset);
				byteChunks += 1;
				if (count === 0) {
					state.fileEnded = true;
					continue;
				}
				state.textBuffer += buffer.subarray(0, count).toString("utf8");
				if (state.textBuffer.length > 128 * 1024) throw new Error("manifest_parser_buffer_bound_exceeded");
				state.offset += count;
			}
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOSPC") return;
			this.failJournalManifestValidation(state, error instanceof Error ? error.message : String(error));
		}
	}

	private parsePinOccurrence(
		value: unknown,
		occurrenceReference: JournalOccurrenceReference,
		runId: string,
		segmentRecord?: IncidentRecorderSegmentRecord,
	): PinOccurrenceMatch | undefined {
		if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
		const reference = value as Record<string, unknown>;
		const identity = reference.identity;
		const cursors = reference.cursors;
		const casValue = reference.cas;
		const wrapperOrder = reference.wrapperOrder;
		const producerOrder = reference.producerOrder;
		const transportIdentity = reference.transportIdentity;
		if (
			reference.version !== 1 ||
			reference.state !== "complete" ||
			!canonicalUuidFields(identity) ||
			identity.runId !== runId ||
			typeof reference.source !== "string" ||
			reference.source.length === 0 ||
			Buffer.byteLength(reference.source) > 255 ||
			typeof reference.type !== "string" ||
			reference.type.length === 0 ||
			Buffer.byteLength(reference.type) > 255 ||
			typeof reference.encoding !== "string" ||
			reference.encoding.length === 0 ||
			Buffer.byteLength(reference.encoding) > 255 ||
			!["exact-bytes", "derived-scalar", "loss", "control"].includes(String(reference.payloadKind)) ||
			typeof reference.terminal !== "boolean" ||
			!isScalarMetadata(reference.metadata) ||
			!Array.isArray(cursors) ||
			cursors.length === 0 ||
			cursors.length > PIN_CURSOR_MAX_COUNT ||
			cursors.some((cursor) => typeof cursor !== "string") ||
			!Array.isArray(wrapperOrder) ||
			wrapperOrder.length !== cursors.length ||
			wrapperOrder.some((order) => !isUnsigned64(order)) ||
			!contiguousUnsigned64Range(wrapperOrder as string[]) ||
			!Array.isArray(producerOrder) ||
			producerOrder.length !== cursors.length ||
			producerOrder.some((order) => !isUnsigned64(order)) ||
			!contiguousUnsigned64Range(producerOrder as string[]) ||
			typeof reference.eventWallTimeMs !== "string" ||
			!isUnsigned64(reference.eventWallTimeMs) ||
			typeof reference.eventMonotonicNs !== "string" ||
			!isUnsigned64(reference.eventMonotonicNs) ||
			!transportIdentity ||
			typeof transportIdentity !== "object" ||
			Array.isArray(transportIdentity) ||
			Buffer.byteLength(JSON.stringify(transportIdentity)) > 16 * 1024 ||
			!casValue ||
			typeof casValue !== "object" ||
			Array.isArray(casValue)
		) {
			return undefined;
		}
		const cas = casValue as Record<string, unknown>;
		if (
			cas.algorithm !== "sha256" ||
			typeof cas.digest !== "string" ||
			!/^[0-9a-f]{64}$/.test(cas.digest) ||
			!Number.isSafeInteger(cas.bytes) ||
			Number(cas.bytes) < 0 ||
			Number(cas.bytes) > 983_040 ||
			cas.path !== join(this.root, "cas", "sha256", cas.digest.slice(0, 2), `${cas.digest}.blob`) ||
			cas.compression !== "none" ||
			cas.resolution !== "verified"
		) {
			return undefined;
		}
		const identityKey = sha256(
			`${identity.runId}\0${identity.runToken}\0${identity.producerId}\0${identity.occurrenceId}`,
		);
		const wallTimeMs = segmentObservedAtMs(reference.eventWallTimeMs);
		if (segmentRecord) {
			if (
				segmentRecord.idempotencyKey !== `occurrence:${identityKey}` ||
				segmentRecord.runId !== runId ||
				segmentRecord.sourceId !== SEGMENT_SOURCE_OCCURRENCE ||
				segmentRecord.observedAtMs !== wallTimeMs ||
				segmentRecord.order !== wrapperOrder[0]
			) {
				return undefined;
			}
		} else if (
			typeof occurrenceReference !== "string" ||
			!basename(occurrenceReference).endsWith(`-${identityKey}.json`)
		) {
			return undefined;
		}
		let semanticFingerprint: string;
		try {
			semanticFingerprint = sha256(
				canonicalJson({
					identity,
					source: reference.source,
					type: reference.type,
					encoding: reference.encoding,
					payloadKind: reference.payloadKind,
					terminal: reference.terminal,
					metadata: reference.metadata,
					eventWallTimeMs: reference.eventWallTimeMs,
					eventMonotonicNs: reference.eventMonotonicNs,
					transportIdentity,
					wrapperOrder,
					producerOrder,
					cursors,
					cas,
					compactionDisposition: reference.compactionDisposition,
					journalCanonicalUntilCompactionCommit: reference.journalCanonicalUntilCompactionCommit,
				}),
			);
		} catch {
			return undefined;
		}
		return {
			identityKey,
			semanticFingerprint,
			occurrenceReference,
			cursors: cursors as string[],
			cas: { digest: cas.digest, bytes: Number(cas.bytes), path: cas.path as string },
			eventWallTimeMs: reference.eventWallTimeMs,
		};
	}

	private closeRunHistoryDescriptor(descriptor: number, role: "legacy_occurrence" | "stable_directory"): void {
		closeSync(descriptor);
		this.options.runHistoryDescriptorIo?.afterClose?.({ role, descriptor });
	}

	private readStableLegacyOccurrence(path: string, canonicalPath = path): { value: unknown; bytes: number } {
		let before: BigIntStats;
		try {
			before = lstatSync(path, { bigint: true });
		} catch (error) {
			throw new Error(
				`legacy_occurrence_reference_unavailable: ${error instanceof Error ? error.message : String(error)}`,
				{ cause: error },
			);
		}
		if (
			!before.isFile() ||
			before.isSymbolicLink() ||
			before.size < 1n ||
			before.size > BigInt(PIN_LEGACY_REFERENCE_MAX_BYTES)
		) {
			throw new Error("legacy_occurrence_reference_metadata_invalid");
		}
		const beforeIdentity = stableFilesystemIdentity(before);
		if (canonicalPath !== path) {
			const canonicalBefore = lstatSync(canonicalPath, { bigint: true });
			if (
				!canonicalBefore.isFile() ||
				canonicalBefore.isSymbolicLink() ||
				!sameStableFilesystemIdentity(beforeIdentity, stableFilesystemIdentity(canonicalBefore))
			) {
				throw new Error("legacy_occurrence_reference_canonical_path_changed_before_read");
			}
		}
		const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		let result: { value: unknown; bytes: number } | undefined;
		let hasReadError = false;
		let readError: unknown;
		try {
			this.options.runHistoryDescriptorIo?.afterOpen?.({ role: "legacy_occurrence", descriptor });
			const opened = fstatSync(descriptor, { bigint: true });
			const openedIdentity = stableFilesystemIdentity(opened);
			if (!opened.isFile() || !sameStableFilesystemIdentity(openedIdentity, beforeIdentity)) {
				throw new Error("legacy_occurrence_reference_changed_before_read");
			}
			const byteLength = Number(opened.size);
			const bytes = Buffer.alloc(byteLength);
			let offset = 0;
			while (offset < bytes.length) {
				const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
				if (count <= 0) throw new Error("legacy_occurrence_reference_truncated");
				offset += count;
			}
			const after = fstatSync(descriptor, { bigint: true });
			if (!after.isFile() || !sameStableFilesystemIdentity(stableFilesystemIdentity(after), openedIdentity)) {
				throw new Error("legacy_occurrence_reference_changed_during_read");
			}
			const authorityAfter = lstatSync(path, { bigint: true });
			const canonicalAfter = canonicalPath === path ? authorityAfter : lstatSync(canonicalPath, { bigint: true });
			if (
				!authorityAfter.isFile() ||
				authorityAfter.isSymbolicLink() ||
				!canonicalAfter.isFile() ||
				canonicalAfter.isSymbolicLink() ||
				!sameStableFilesystemIdentity(stableFilesystemIdentity(authorityAfter), openedIdentity) ||
				!sameStableFilesystemIdentity(stableFilesystemIdentity(canonicalAfter), openedIdentity)
			) {
				throw new Error("legacy_occurrence_reference_canonical_path_changed_during_read");
			}
			result = { value: JSON.parse(bytes.toString("utf8")) as unknown, bytes: bytes.length };
		} catch (error) {
			hasReadError = true;
			readError = error;
		}
		let hasCloseError = false;
		let closeError: unknown;
		try {
			this.closeRunHistoryDescriptor(descriptor, "legacy_occurrence");
		} catch (error) {
			hasCloseError = true;
			closeError = error;
		}
		if (hasReadError) throw readError;
		if (hasCloseError) throw closeError;
		if (!result) throw new Error("legacy_occurrence_reference_read_result_missing");
		return result;
	}

	private canonicalLegacyOccurrencePath(reference: string, runId: string): string {
		const directory = join(this.root, "refs", "runs", sha256(runId));
		const name = basename(reference);
		if (
			!/^seq-\d{20}-[0-9a-f]{64}\.json$/.test(name) ||
			reference !== join(directory, name) ||
			reference.split("/").includes("..")
		) {
			throw new Error("legacy_occurrence_reference_outside_canonical_run_directory");
		}
		return reference;
	}

	private readSegmentOccurrenceReference(locator: IncidentRecorderSegmentLocator): IncidentRecorderSegmentRecord {
		return this.withSegmentStoreRoot((_root, store) => {
			const record = store.readRecordWithinRoot(_root, locator);
			if (!record) throw new Error("segment_occurrence_reference_missing_or_stale");
			return record;
		});
	}

	private resolveManifestOccurrenceReference(
		state: JournalManifestValidation,
		occurrence: JournalManifestOccurrence,
	): void {
		let match: PinOccurrenceMatch | undefined;
		if (typeof occurrence.occurrenceReference === "string") {
			const path = this.canonicalLegacyOccurrencePath(occurrence.occurrenceReference, state.runId);
			const { value } = this.readStableLegacyOccurrence(path);
			match = this.parsePinOccurrence(value, path, state.runId);
		} else {
			const record = this.readSegmentOccurrenceReference(occurrence.occurrenceReference.locator);
			let value: unknown;
			try {
				value = JSON.parse(record.payload.toString("utf8")) as unknown;
			} catch {
				throw new Error("segment_occurrence_reference_payload_invalid");
			}
			match = this.parsePinOccurrence(value, occurrence.occurrenceReference, state.runId, record);
		}
		if (!match) throw new Error("manifest_occurrence_reference_semantic_resolution_failed");
		if (
			match.eventWallTimeMs !== occurrence.eventWallTimeMs ||
			match.cas.digest !== occurrence.cas.digest ||
			match.cas.bytes !== occurrence.cas.bytes ||
			match.cas.path !== occurrence.cas.path ||
			canonicalJson(match.cursors) !== canonicalJson(occurrence.cursors) ||
			(occurrence.semanticFingerprint !== undefined && match.semanticFingerprint !== occurrence.semanticFingerprint)
		) {
			throw new Error("manifest_occurrence_reference_semantic_mismatch");
		}
		state.resolvedOccurrenceCount += 1;
	}

	private parseRunHistoryEvent(
		value: unknown,
		occurrenceReference: JournalOccurrenceReference,
		runId: string,
		segmentRecord?: IncidentRecorderSegmentRecord,
	): IncidentRecorderRunHistoryEvent | undefined {
		const match = this.parsePinOccurrence(value, occurrenceReference, runId, segmentRecord);
		if (!match || !value || typeof value !== "object" || Array.isArray(value)) return undefined;
		const reference = value as Record<string, unknown>;
		return {
			identityKey: match.identityKey,
			identity: { ...(reference.identity as IncidentRecorderRunHistoryEvent["identity"]) },
			semanticFingerprint: match.semanticFingerprint,
			occurrenceReference,
			source: reference.source as string,
			type: reference.type as string,
			encoding: reference.encoding as string,
			payloadKind: reference.payloadKind as IncidentRecorderRunHistoryEvent["payloadKind"],
			terminal: reference.terminal as boolean,
			metadata: { ...(reference.metadata as IncidentJournalLine["metadata"]) },
			eventWallTimeMs: reference.eventWallTimeMs as string,
			eventMonotonicNs: reference.eventMonotonicNs as string,
			wrapperOrder: [...(reference.wrapperOrder as string[])],
			producerOrder: [...(reference.producerOrder as string[])],
			cursors: [...match.cursors],
			transportIdentity: { ...(reference.transportIdentity as Record<string, unknown>) },
			cas: { ...match.cas },
		};
	}

	private compareRunHistoryPresentation(
		left: IncidentRecorderRunHistoryEvent,
		right: IncidentRecorderRunHistoryEvent,
	): number {
		const leftWall = BigInt(left.eventWallTimeMs);
		const rightWall = BigInt(right.eventWallTimeMs);
		if (leftWall !== rightWall) return leftWall < rightWall ? -1 : 1;
		return left.identityKey.localeCompare(right.identityKey);
	}

	private buildRunHistoryOrdering(
		events: IncidentRecorderRunHistoryEvent[],
	): { ordering: RunHistoryOrdering } | { reason: string } {
		interface StreamRange {
			event: IncidentRecorderRunHistoryEvent;
			start: bigint;
			end: bigint;
			basis: "producer_sequence" | "wrapper_sequence";
			streamKey: string;
		}
		const streams = new Map<string, StreamRange[]>();
		const addRange = (range: StreamRange): void => {
			const key = `${range.basis}\0${range.streamKey}`;
			const entries = streams.get(key) ?? [];
			entries.push(range);
			streams.set(key, entries);
		};
		for (const event of events) {
			addRange({
				event,
				start: BigInt(event.producerOrder[0] ?? "0"),
				end: BigInt(event.producerOrder.at(-1) ?? "0"),
				basis: "producer_sequence",
				streamKey: canonicalJson({
					runId: event.identity.runId,
					runToken: event.identity.runToken,
					producerId: event.identity.producerId,
				}),
			});
			const transport = event.transportIdentity;
			if (
				typeof transport.machineId === "string" &&
				transport.machineId.length > 0 &&
				typeof transport.bootId === "string" &&
				transport.bootId.length > 0 &&
				Number.isSafeInteger(transport.wrapperPid) &&
				Number(transport.wrapperPid) > 0 &&
				typeof transport.wrapperStartId === "string" &&
				transport.wrapperStartId.length > 0
			) {
				addRange({
					event,
					start: BigInt(event.wrapperOrder[0] ?? "0"),
					end: BigInt(event.wrapperOrder.at(-1) ?? "0"),
					basis: "wrapper_sequence",
					streamKey: canonicalJson({
						runId: event.identity.runId,
						runToken: event.identity.runToken,
						machineId: transport.machineId,
						bootId: transport.bootId,
						wrapperPid: transport.wrapperPid,
						wrapperStartId: transport.wrapperStartId,
					}),
				});
			}
		}

		const causalRelations: IncidentRecorderRunHistoryProjection["ordering"]["causalRelations"] = [];
		const outgoing = new Map<string, Set<string>>();
		const indegree = new Map(events.map((event) => [event.identityKey, 0]));
		for (const ranges of streams.values()) {
			ranges.sort((left, right) => {
				if (left.start !== right.start) return left.start < right.start ? -1 : 1;
				if (left.end !== right.end) return left.end < right.end ? -1 : 1;
				return left.event.identityKey.localeCompare(right.event.identityKey);
			});
			for (let index = 1; index < ranges.length; index += 1) {
				const before = ranges[index - 1];
				const after = ranges[index];
				if (!before || !after) continue;
				if (after.start <= before.end) return { reason: "run_history_causal_sequence_overlap" };
				causalRelations.push({
					beforeIdentityKey: before.event.identityKey,
					afterIdentityKey: after.event.identityKey,
					basis: before.basis,
					streamKeyHash: sha256(before.streamKey),
				});
				const next = outgoing.get(before.event.identityKey) ?? new Set<string>();
				if (!next.has(after.event.identityKey)) {
					next.add(after.event.identityKey);
					outgoing.set(before.event.identityKey, next);
					indegree.set(after.event.identityKey, (indegree.get(after.event.identityKey) ?? 0) + 1);
				}
			}
		}
		causalRelations.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
		const byIdentity = new Map(events.map((event) => [event.identityKey, event]));
		const ready = events.filter((event) => (indegree.get(event.identityKey) ?? 0) === 0);
		ready.sort((left, right) => this.compareRunHistoryPresentation(left, right));
		const ordered: IncidentRecorderRunHistoryEvent[] = [];
		while (ready.length > 0) {
			const event = ready.shift();
			if (!event) break;
			ordered.push(event);
			for (const nextIdentity of outgoing.get(event.identityKey) ?? []) {
				const nextDegree = (indegree.get(nextIdentity) ?? 0) - 1;
				indegree.set(nextIdentity, nextDegree);
				if (nextDegree === 0) {
					const next = byIdentity.get(nextIdentity);
					if (next) {
						ready.push(next);
						ready.sort((left, right) => this.compareRunHistoryPresentation(left, right));
					}
				}
			}
		}
		if (ordered.length !== events.length) return { reason: "run_history_causal_order_cycle" };
		return { ordering: { events: ordered, causalRelations } };
	}

	private detachRunHistoryValue<T>(value: T): T {
		return JSON.parse(canonicalJson(value)) as T;
	}

	private runHistoryProjection(
		state: RunHistoryTraversal,
		scope: "observed_events_only" | "complete_snapshot" = "observed_events_only",
	): IncidentRecorderRunHistoryProjection {
		let ordering: RunHistoryOrdering;
		if (state.orderingFailure) {
			ordering = {
				events: [...state.events.values()].sort((left, right) => this.compareRunHistoryPresentation(left, right)),
				causalRelations: [],
			};
		} else {
			try {
				const built = this.buildRunHistoryOrdering([...state.events.values()]);
				if ("ordering" in built) ordering = built.ordering;
				else {
					state.orderingFailure = built.reason;
					ordering = {
						events: [...state.events.values()].sort((left, right) =>
							this.compareRunHistoryPresentation(left, right),
						),
						causalRelations: [],
					};
				}
			} catch {
				state.orderingFailure = "run_history_causal_order_validation_failed";
				ordering = {
					events: [...state.events.values()].sort((left, right) =>
						this.compareRunHistoryPresentation(left, right),
					),
					causalRelations: [],
				};
			}
		}
		const events = ordering.events;
		const terminalEvents = events
			.filter((event) => event.terminal)
			.map((event) => ({
				identityKey: event.identityKey,
				type: event.type,
				source: event.source,
				eventWallTimeMs: event.eventWallTimeMs,
				basis: "terminal_flag" as const,
			}));
		const finalizationCandidates: IncidentRecorderRunHistoryProjection["finalizationCandidates"] = [];
		for (const event of events) {
			if (event.type === "supervisor_exit" && event.source === "recorder-events") {
				finalizationCandidates.push({
					role: "supervisor_exit",
					identityKey: event.identityKey,
					basis: "type_and_source_candidate",
					qualification: "candidate_requires_expectation_match",
				});
			} else if (
				event.type === "capture_channel_terminal" &&
				event.source === "recorder-control" &&
				event.terminal
			) {
				finalizationCandidates.push({
					role: "capture_channel_terminal",
					identityKey: event.identityKey,
					basis: "type_source_and_terminal_flag_candidate",
					qualification: "candidate_requires_expectation_match",
				});
			}
		}
		return this.detachRunHistoryValue({
			version: 1,
			runId: state.runId,
			fromWallTimeMs: state.fromWallTimeMs,
			throughWallTimeMs: state.throughWallTimeMs,
			events,
			terminalEvents,
			finalizationCandidates,
			ordering: {
				semantics: "partial_order",
				causalRelations: ordering.causalRelations,
				presentationTieBreak: "wall_time_then_identity_key",
				unrelatedPresentationOrderIsCausal: false,
				scope,
			},
			evidence: state.evidence.map((evidence) => ({ ...evidence })),
		});
	}

	private closeRunHistoryCasValidation(state: RunHistoryTraversal): void {
		const active = state.activeCasValidation;
		state.activeCasValidation = undefined;
		if (!active) return;
		for (const descriptor of [
			active.fileDescriptor,
			...active.directoryFences.map((fence) => fence.descriptor).reverse(),
			active.procfsAuthority.descriptorInfoDirectoryDescriptor,
			active.procfsAuthority.descriptorDirectoryDescriptor,
			active.procfsAuthority.rootDescriptor,
		]) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}

	private discardRunHistoryTraversal(state: RunHistoryTraversal): void {
		if (state.deadlineTimer) {
			clearTimeout(state.deadlineTimer);
			state.deadlineTimer = undefined;
		}
		this.closeRunHistoryCasValidation(state);
		try {
			state.directory?.closeSync();
		} catch {}
		state.directory = undefined;
		const procfsAuthority = state.procfsAuthority;
		state.procfsAuthority = undefined;
		if (procfsAuthority) {
			for (const descriptor of [
				procfsAuthority.descriptorInfoDirectoryDescriptor,
				procfsAuthority.descriptorDirectoryDescriptor,
				procfsAuthority.rootDescriptor,
			]) {
				try {
					closeSync(descriptor);
				} catch {}
			}
		}
		for (const key of ["legacyDirectoryDescriptor", "legacyNamespaceDescriptor"] as const) {
			const descriptor = state[key];
			state[key] = undefined;
			if (descriptor === undefined) continue;
			try {
				closeSync(descriptor);
			} catch {}
		}
		if (state.segmentReadLease) {
			try {
				this.segmentStore?.releaseReadLease(state.segmentReadLease);
			} catch {}
			state.segmentReadLease = undefined;
		}
		const publicationCapability = state.publicationCapability;
		state.publicationCapability = undefined;
		if (publicationCapability) this.releasedRunHistoryPublicationCapabilities.add(publicationCapability);
		if (publicationCapability && this.runHistoryPublicationCapabilities.get(publicationCapability) === state) {
			this.runHistoryPublicationCapabilities.delete(publicationCapability);
		}
		if (this.runHistoryTraversals.get(state.token) === state) this.runHistoryTraversals.delete(state.token);
	}

	private discardRunHistoryTraversals(): void {
		for (const state of this.runHistoryTraversals.values()) this.discardRunHistoryTraversal(state);
	}

	private validateRunHistoryOrdering(state: RunHistoryTraversal): string | undefined {
		if (state.orderingFailure) return state.orderingFailure;
		try {
			const ordering = this.buildRunHistoryOrdering([...state.events.values()]);
			if (!("ordering" in ordering)) state.orderingFailure = ordering.reason;
		} catch {
			state.orderingFailure = "run_history_causal_order_validation_failed";
		}
		return state.orderingFailure;
	}

	private incompleteRunHistory(
		state: RunHistoryTraversal,
		reason: string,
		evidence: IncidentRecorderRunHistoryEvidence,
	): IncidentRecorderRunHistoryProgressResult {
		const orderingFailure = this.validateRunHistoryOrdering(state);
		if (orderingFailure) {
			reason = orderingFailure;
			evidence = { kind: "corrupt", reason: orderingFailure };
		}
		if (!state.evidence.some((entry) => entry.kind === evidence.kind && entry.reason === evidence.reason)) {
			state.evidence.push(evidence);
		}
		try {
			const projection = this.runHistoryProjection(state);
			return this.boundedRunHistoryResult(state, { state: "incomplete", reason, projection }, true);
		} catch (error) {
			const renderFailure = error instanceof Error ? error.message : String(error);
			return {
				state: "incomplete",
				reason: orderingFailure ?? "run_history_projection_render_failed",
				projection: {
					version: 1,
					runId: state.runId,
					fromWallTimeMs: state.fromWallTimeMs,
					throughWallTimeMs: state.throughWallTimeMs,
					events: [],
					terminalEvents: [],
					finalizationCandidates: [],
					ordering: {
						semantics: "partial_order",
						causalRelations: [],
						presentationTieBreak: "wall_time_then_identity_key",
						unrelatedPresentationOrderIsCausal: false,
						scope: "observed_events_only",
					},
					evidence: [
						{
							kind: "corrupt",
							reason: orderingFailure ?? `run_history_projection_render_failed:${renderFailure}`,
						},
					],
				},
			};
		} finally {
			this.discardRunHistoryTraversal(state);
		}
	}

	private boundedRunHistoryResult(
		state: RunHistoryTraversal,
		result: IncidentRecorderRunHistoryProgressResult,
		discardOnSuccess: boolean,
	): IncidentRecorderRunHistoryProgressResult {
		let detached: IncidentRecorderRunHistoryProgressResult;
		let serialized: string | undefined;
		try {
			detached = this.detachRunHistoryValue(result);
			serialized = JSON.stringify(detached);
		} catch (error) {
			if (discardOnSuccess || state.retainForPublication) this.discardRunHistoryTraversal(state);
			throw error;
		}
		if (serialized !== undefined && Buffer.byteLength(serialized, "utf8") <= RUN_HISTORY_RESULT_MAX_BYTES) {
			if (discardOnSuccess) this.discardRunHistoryTraversal(state);
			return detached;
		}
		return this.serializedRunHistoryBoundExceeded(state);
	}

	private serializedRunHistoryBoundExceeded(state: RunHistoryTraversal): IncidentRecorderRunHistoryResult {
		const truncated: IncidentRecorderRunHistoryResult = {
			state: "incomplete",
			reason: "run_history_projection_serialized_bound_exceeded",
			projection: {
				version: 1,
				runId: state.runId,
				fromWallTimeMs: state.fromWallTimeMs,
				throughWallTimeMs: state.throughWallTimeMs,
				events: [],
				terminalEvents: [],
				finalizationCandidates: [],
				ordering: {
					semantics: "partial_order",
					causalRelations: [],
					presentationTieBreak: "wall_time_then_identity_key",
					unrelatedPresentationOrderIsCausal: false,
					scope: "observed_events_only",
				},
				evidence: [
					{
						kind: "truncated",
						reason: "serialized_projection_result_exceeded_explicit_byte_bound",
					},
				],
			},
		};
		this.discardRunHistoryTraversal(state);
		return this.detachRunHistoryValue(truncated);
	}

	private retainCompletedRunHistory(
		state: RunHistoryTraversal,
		result: Extract<IncidentRecorderRunHistoryResult, { state: "complete" }>,
	): IncidentRecorderRunHistoryResult {
		let detached: Extract<IncidentRecorderRunHistoryResult, { state: "complete" }>;
		try {
			detached = this.detachRunHistoryValue(result);
		} catch (error) {
			this.discardRunHistoryTraversal(state);
			throw error;
		}
		const publicationCapability = Object.freeze({
			version: 1 as const,
			kind: "run_history_publication" as const,
			id: sha256(`${state.token}\0${detached.snapshot.fingerprint}\0publication\0${process.hrtime.bigint()}`),
			snapshotFingerprint: detached.snapshot.fingerprint,
		});
		const retained: IncidentRecorderRetainedRunHistoryResult = {
			...detached,
			publicationCapability,
		};
		let serialized: string | undefined;
		try {
			serialized = JSON.stringify(retained);
		} catch (error) {
			this.discardRunHistoryTraversal(state);
			throw error;
		}
		if (serialized === undefined || Buffer.byteLength(serialized, "utf8") > RUN_HISTORY_RESULT_MAX_BYTES) {
			return this.serializedRunHistoryBoundExceeded(state);
		}
		state.phase = "publication-retained";
		state.publicationCapability = publicationCapability;
		this.runHistoryPublicationCapabilities.set(publicationCapability, state);
		return retained;
	}

	private observeRunHistorySemanticFingerprint(
		state: RunHistoryTraversal,
		event: IncidentRecorderRunHistoryEvent,
	): string | undefined {
		const existing = state.semanticFingerprints.get(event.identityKey);
		if (existing) {
			return existing === event.semanticFingerprint
				? undefined
				: "run_history_duplicate_occurrence_semantic_conflict";
		}
		const addedBytes = retainedBytes({
			identityKey: event.identityKey,
			semanticFingerprint: event.semanticFingerprint,
		});
		if (
			state.semanticFingerprints.size >= PENDING_ENTRY_MAX_COUNT ||
			state.memoryBytes + addedBytes > PENDING_ENTRY_MAX_BYTES
		) {
			return "run_history_projection_truncated_by_explicit_bound";
		}
		state.semanticFingerprints.set(event.identityKey, event.semanticFingerprint);
		state.memoryBytes += addedBytes;
		return undefined;
	}

	private addRunHistoryEvent(state: RunHistoryTraversal, event: IncidentRecorderRunHistoryEvent): string | undefined {
		const semanticConflict = this.observeRunHistorySemanticFingerprint(state, event);
		if (semanticConflict) return semanticConflict;
		const existing = state.events.get(event.identityKey);
		if (existing) {
			return existing.semanticFingerprint === event.semanticFingerprint
				? undefined
				: "run_history_duplicate_occurrence_semantic_conflict";
		}
		const existingCasClaim = state.casClaims.get(event.cas.digest);
		if (
			existingCasClaim &&
			(existingCasClaim.bytes !== event.cas.bytes || existingCasClaim.path !== event.cas.path)
		) {
			return "run_history_cas_claim_conflict";
		}
		const addedBytes = retainedBytes(event);
		if (state.events.size >= PENDING_ENTRY_MAX_COUNT || state.memoryBytes + addedBytes > PENDING_ENTRY_MAX_BYTES) {
			return "run_history_projection_truncated_by_explicit_bound";
		}
		state.events.set(event.identityKey, event);
		state.casClaims.set(event.cas.digest, { ...event.cas });
		state.memoryBytes += addedBytes;
		return undefined;
	}

	private runHistoryCursor(state: RunHistoryTraversal): IncidentRecorderRunHistoryCursor {
		return { version: 1, token: state.token, requestFingerprint: state.requestFingerprint };
	}

	private pendingRunHistory(state: RunHistoryTraversal): IncidentRecorderRunHistoryProgressResult {
		if (state.pendingResponse === "cursor-only") {
			return this.boundedRunHistoryResult(
				state,
				{
					state: "pending",
					cursor: this.runHistoryCursor(state),
					progress: {
						version: 1,
						state: "projection_deferred",
						phase: state.phase,
						observedEventCount: state.events.size,
						observedEvidenceCount: state.evidence.length,
					},
				},
				false,
			);
		}
		const orderingFailure = this.validateRunHistoryOrdering(state);
		if (orderingFailure) {
			return this.incompleteRunHistory(state, orderingFailure, {
				kind: "corrupt",
				reason: orderingFailure,
			});
		}
		return this.boundedRunHistoryResult(
			state,
			{ state: "pending", cursor: this.runHistoryCursor(state), projection: this.runHistoryProjection(state) },
			false,
		);
	}

	private advanceRunHistorySegmentPhase(
		state: RunHistoryTraversal,
	): IncidentRecorderRunHistoryProgressResult | undefined {
		const phase = state.phase;
		if (phase === "legacy" || phase === "cas-validation" || phase === "publication-retained") {
			return undefined;
		}
		if (phase === "segment-recovery-gaps") return this.advanceRunHistoryRecoveryGaps(state);
		const sourceId =
			phase === "segment-occurrences"
				? SEGMENT_SOURCE_OCCURRENCE
				: phase === "segment-run-incomplete"
					? SEGMENT_SOURCE_INCOMPLETE
					: SEGMENT_SOURCE_GAP;
		const runId = phase === "segment-global-gaps" ? "__recorder__" : state.runId;
		const evidencePhase = phase !== "segment-occurrences";
		const fingerprintOccurrenceIdentityDomain = phase === "segment-occurrences";
		try {
			const page = this.withSegmentStoreRoot((root, store) => {
				state.segmentReadLease ??= store.acquireReadLease(state.deadlineMs);
				return store.queryRunWindowPageWithinRoot(root, {
					runId,
					sourceId,
					fromObservedAtMs:
						fingerprintOccurrenceIdentityDomain || (evidencePhase && sourceId === SEGMENT_SOURCE_GAP)
							? 0
							: state.fromWallTimeMs,
					throughObservedAtMs:
						fingerprintOccurrenceIdentityDomain || (evidencePhase && sourceId === SEGMENT_SOURCE_GAP)
							? Number.MAX_SAFE_INTEGER
							: state.throughWallTimeMs,
					maxRecords: SEGMENT_QUERY_PAGE_RECORDS,
					maxBytes: SEGMENT_QUERY_PAGE_BYTES,
					readLease: state.segmentReadLease,
					maxScannedSegments: RUN_HISTORY_SEGMENT_PAGE_SCANNED_SEGMENTS,
					maxScannedRecords: RUN_HISTORY_SEGMENT_PAGE_SCANNED_RECORDS,
					maxScannedIndexBytes: RUN_HISTORY_SEGMENT_PAGE_SCANNED_INDEX_BYTES,
					...(state.segmentCursor ? { after: state.segmentCursor } : {}),
				});
			});
			state.segmentScannedSegments += page.scannedSegments;
			state.segmentScannedRecords += page.scannedRecords;
			state.segmentScannedIndexBytes += page.scannedIndexBytes;
			if (
				state.segmentScannedSegments > RUN_HISTORY_SEGMENT_MAX_SCANNED_SEGMENTS ||
				state.segmentScannedRecords > RUN_HISTORY_SEGMENT_MAX_SCANNED_RECORDS ||
				state.segmentScannedIndexBytes > RUN_HISTORY_SEGMENT_MAX_SCANNED_INDEX_BYTES
			) {
				return this.incompleteRunHistory(state, "run_history_segment_scan_bound_exceeded", {
					kind: "truncated",
					reason: "segment_snapshot_examined_work_bound_exceeded",
				});
			}
			for (const record of page.records) {
				state.segmentRecordCount += 1;
				const snapshotFact = canonicalJson({ sourceId, runId, locator: record.locator });
				if (
					state.segmentRecordCount > PENDING_ENTRY_MAX_COUNT ||
					state.memoryBytes + Buffer.byteLength(snapshotFact) > PENDING_ENTRY_MAX_BYTES
				) {
					return this.incompleteRunHistory(state, "run_history_segment_snapshot_truncated", {
						kind: "truncated",
						reason: "segment_record_or_byte_bound_exceeded",
						reference: record.locator,
					});
				}
				state.snapshotFacts.push(snapshotFact);
				state.memoryBytes += Buffer.byteLength(snapshotFact);
				if (sourceId !== SEGMENT_SOURCE_OCCURRENCE) {
					let detail = sourceId;
					try {
						detail = canonicalJson(JSON.parse(record.payload.toString("utf8")) as unknown);
					} catch {}
					return this.incompleteRunHistory(state, `run_history_${sourceId}_evidence`, {
						kind: sourceId === SEGMENT_SOURCE_GAP ? "gap" : "incomplete",
						reason: detail,
						reference: record.locator,
					});
				}
				let value: unknown;
				try {
					value = JSON.parse(record.payload.toString("utf8")) as unknown;
				} catch {
					return this.incompleteRunHistory(state, "run_history_segment_occurrence_corrupt", {
						kind: "corrupt",
						reason: "segment_occurrence_payload_invalid_json",
						reference: record.locator,
					});
				}
				const event = this.parseRunHistoryEvent(
					value,
					this.segmentOccurrenceReference(record.locator),
					state.runId,
					record,
				);
				if (!event) {
					return this.incompleteRunHistory(state, "run_history_segment_occurrence_corrupt", {
						kind: "corrupt",
						reason: "segment_occurrence_semantic_validation_failed",
						reference: record.locator,
					});
				}
				const semanticConflict = this.observeRunHistorySemanticFingerprint(state, event);
				if (semanticConflict) {
					return this.incompleteRunHistory(state, semanticConflict, {
						kind: semanticConflict.includes("truncated") ? "truncated" : "corrupt",
						reason: semanticConflict,
						reference: event.occurrenceReference,
					});
				}
				const wall = segmentObservedAtMs(event.eventWallTimeMs);
				if (wall < state.fromWallTimeMs || wall > state.throughWallTimeMs) continue;
				const conflict = this.addRunHistoryEvent(state, event);
				if (conflict) {
					return this.incompleteRunHistory(state, conflict, {
						kind: conflict.includes("truncated") ? "truncated" : "corrupt",
						reason: conflict,
						reference: event.occurrenceReference,
					});
				}
			}
			if (!page.complete) {
				if (!page.nextCursor) {
					return this.incompleteRunHistory(state, "run_history_segment_continuation_missing", {
						kind: "truncated",
						reason: "segment_snapshot_page_did_not_return_continuation",
					});
				}
				state.segmentCursor = page.nextCursor;
				return this.pendingRunHistory(state);
			}
			state.segmentCursor = undefined;
			if (phase === "segment-occurrences") state.phase = "segment-run-gaps";
			else if (phase === "segment-run-gaps") state.phase = "segment-run-incomplete";
			else if (phase === "segment-run-incomplete") state.phase = "segment-global-gaps";
			else state.phase = "segment-recovery-gaps";
			return this.pendingRunHistory(state);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOSPC") throw error;
			return this.incompleteRunHistory(state, "run_history_segment_snapshot_stale_or_corrupt", {
				kind: "corrupt",
				reason: error instanceof Error ? error.message : String(error),
			});
		}
	}

	private advanceRunHistoryRecoveryGaps(state: RunHistoryTraversal): IncidentRecorderRunHistoryProgressResult {
		try {
			const page = this.withSegmentStoreRoot((root, store) => {
				if (!state.segmentReadLease) throw new Error("segment_read_lease_missing");
				return store.queryRecoveryGapsPageWithinRoot(root, {
					maxGaps: SEGMENT_QUERY_PAGE_RECORDS,
					maxBytes: SEGMENT_QUERY_PAGE_BYTES,
					maxScannedSegments: RUN_HISTORY_SEGMENT_PAGE_SCANNED_SEGMENTS,
					maxScannedGaps: RUN_HISTORY_SEGMENT_PAGE_SCANNED_GAPS,
					maxScannedIndexBytes: RUN_HISTORY_SEGMENT_PAGE_SCANNED_INDEX_BYTES,
					readLease: state.segmentReadLease,
					...(state.segmentRecoveryGapCursor ? { after: state.segmentRecoveryGapCursor } : {}),
				});
			});
			state.segmentScannedSegments += page.scannedSegments;
			state.segmentScannedRecords += page.scannedGaps;
			state.segmentScannedIndexBytes += page.scannedIndexBytes;
			if (
				state.segmentScannedSegments > RUN_HISTORY_SEGMENT_MAX_SCANNED_SEGMENTS ||
				state.segmentScannedRecords > RUN_HISTORY_SEGMENT_MAX_SCANNED_RECORDS ||
				state.segmentScannedIndexBytes > RUN_HISTORY_SEGMENT_MAX_SCANNED_INDEX_BYTES
			) {
				return this.incompleteRunHistory(state, "run_history_segment_scan_bound_exceeded", {
					kind: "truncated",
					reason: "segment_recovery_gap_examined_work_bound_exceeded",
				});
			}
			for (const gap of page.gaps) {
				const snapshotFact = canonicalJson({ recoveryGap: gap });
				if (
					state.segmentRecordCount + state.segmentRecoveryGapCount >= PENDING_ENTRY_MAX_COUNT ||
					state.memoryBytes + Buffer.byteLength(snapshotFact) > PENDING_ENTRY_MAX_BYTES
				) {
					return this.incompleteRunHistory(state, "run_history_segment_snapshot_truncated", {
						kind: "truncated",
						reason: "segment_recovery_gap_or_byte_bound_exceeded",
						reference: gap,
					});
				}
				state.segmentRecoveryGapCount += 1;
				state.snapshotFacts.push(snapshotFact);
				state.memoryBytes += Buffer.byteLength(snapshotFact);
				return this.incompleteRunHistory(state, "run_history_segment_recovery_gap_evidence", {
					kind: "gap",
					reason: canonicalJson(gap),
					reference: gap,
				});
			}
			if (!page.complete) {
				if (!page.nextCursor) {
					return this.incompleteRunHistory(state, "run_history_segment_recovery_gap_continuation_missing", {
						kind: "truncated",
						reason: "segment_recovery_gap_page_did_not_return_continuation",
					});
				}
				state.segmentRecoveryGapCursor = page.nextCursor;
				return this.pendingRunHistory(state);
			}
			state.segmentRecoveryGapCursor = undefined;
			state.phase = "legacy";
			return this.pendingRunHistory(state);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOSPC") throw error;
			return this.incompleteRunHistory(state, "run_history_segment_recovery_gap_snapshot_stale_or_corrupt", {
				kind: "corrupt",
				reason: error instanceof Error ? error.message : String(error),
			});
		}
	}

	private openStableRunHistoryDirectory(path: string): {
		descriptor: number;
		identity: StableFilesystemIdentity;
	} {
		const before = lstatSync(path, { bigint: true });
		if (!before.isDirectory() || before.isSymbolicLink()) {
			throw new Error("legacy_run_reference_directory_invalid");
		}
		const identity = stableFilesystemIdentity(before);
		const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
		let result: { descriptor: number; identity: StableFilesystemIdentity } | undefined;
		let hasValidationError = false;
		let validationError: unknown;
		try {
			this.options.runHistoryDescriptorIo?.afterOpen?.({ role: "stable_directory", descriptor });
			const opened = fstatSync(descriptor, { bigint: true });
			if (!opened.isDirectory() || !sameStableFilesystemIdentity(identity, stableFilesystemIdentity(opened))) {
				throw new Error("legacy_run_reference_directory_changed_before_open");
			}
			result = { descriptor, identity };
		} catch (error) {
			hasValidationError = true;
			validationError = error;
		}
		let hasCloseError = false;
		let closeError: unknown;
		if (hasValidationError) {
			try {
				this.closeRunHistoryDescriptor(descriptor, "stable_directory");
			} catch (error) {
				hasCloseError = true;
				closeError = error;
			}
		}
		if (hasValidationError) throw validationError;
		if (hasCloseError) throw closeError;
		if (!result) throw new Error("legacy_run_reference_directory_validation_result_missing");
		return result;
	}

	private openRunHistoryNamespaceFence(path: string): {
		path: string;
		descriptor: number;
		identity: StableFilesystemIdentity;
	} {
		let candidate = dirname(path);
		for (;;) {
			try {
				return { path: candidate, ...this.openStableRunHistoryDirectory(candidate) };
			} catch (error) {
				const parent = dirname(candidate);
				if ((error as NodeJS.ErrnoException).code !== "ENOENT" || parent === candidate) throw error;
				candidate = parent;
			}
		}
	}

	private assertRunHistoryDirectoryStable(
		path: string | undefined,
		descriptor: number | undefined,
		identity: StableFilesystemIdentity | undefined,
	): void {
		if (path === undefined || descriptor === undefined || identity === undefined) {
			throw new Error("legacy_directory_stability_fence_missing");
		}
		const opened = fstatSync(descriptor, { bigint: true });
		const canonical = lstatSync(path, { bigint: true });
		if (
			!opened.isDirectory() ||
			!canonical.isDirectory() ||
			canonical.isSymbolicLink() ||
			!sameStableFilesystemIdentity(identity, stableFilesystemIdentity(opened)) ||
			!sameStableFilesystemIdentity(identity, stableFilesystemIdentity(canonical))
		) {
			throw new Error("legacy_directory_identity_changed_during_projection");
		}
	}

	private beginRunHistoryCasValidation(state: RunHistoryTraversal): IncidentRecorderRunHistoryProgressResult {
		const orderingFailure = this.validateRunHistoryOrdering(state);
		if (orderingFailure) {
			return this.incompleteRunHistory(state, orderingFailure, {
				kind: "corrupt",
				reason: orderingFailure,
			});
		}
		state.phase = "cas-validation";
		state.casDigests = [...state.casClaims.keys()].sort();
		state.casIndex = 0;
		return this.pendingRunHistory(state);
	}

	private advanceRunHistoryLegacy(state: RunHistoryTraversal): IncidentRecorderRunHistoryProgressResult {
		const assertLegacyPageBoundary = (): IncidentRecorderRunHistoryProgressResult | undefined => {
			try {
				if (
					!state.procfsAuthority ||
					state.legacyDirectoryDescriptor === undefined ||
					state.legacyDirectoryResolvedPath === undefined
				) {
					throw new Error("legacy_procfs_stability_fence_missing");
				}
				this.assertRunHistoryProcfsDescriptorEntry(
					state.procfsAuthority,
					state.legacyDirectoryDescriptor,
					state.legacyDirectoryResolvedPath,
					"legacy_run_directory",
					"directory",
				);
			} catch (error) {
				return this.incompleteRunHistory(state, "run_history_legacy_snapshot_changed", {
					kind: "corrupt",
					reason: error instanceof Error ? error.message : String(error),
				});
			}
			return undefined;
		};
		const incompleteLegacyPage = (
			reason: string,
			evidence: IncidentRecorderRunHistoryEvidence,
		): IncidentRecorderRunHistoryProgressResult => {
			const pageBoundaryFailure = assertLegacyPageBoundary();
			return pageBoundaryFailure ?? this.incompleteRunHistory(state, reason, evidence);
		};
		const continuingPage = Boolean(state.directory);
		if (!state.directory) {
			const path = join(this.root, "refs", "runs", sha256(state.runId));
			try {
				const namespace = this.openRunHistoryNamespaceFence(path);
				state.legacyNamespacePath = namespace.path;
				state.legacyNamespaceDescriptor = namespace.descriptor;
				state.legacyNamespaceIdentity = namespace.identity;
				let targetExists = true;
				try {
					lstatSync(path, { bigint: true });
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
					targetExists = false;
				}
				if (!targetExists) {
					this.assertRunHistoryDirectoryStable(
						state.legacyNamespacePath,
						state.legacyNamespaceDescriptor,
						state.legacyNamespaceIdentity,
					);
					try {
						lstatSync(path, { bigint: true });
						throw new Error("legacy_run_reference_directory_appeared_during_absence_check");
					} catch (error) {
						if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
					}
					state.snapshotFacts.push(
						canonicalJson({
							legacyDirectoryAbsent: path,
							namespace: serializableFilesystemIdentity(namespace.identity),
						}),
					);
					return this.beginRunHistoryCasValidation(state);
				}
				const authority = this.openStableRunHistoryDirectory(path);
				state.legacyDirectoryPath = path;
				state.legacyDirectoryDescriptor = authority.descriptor;
				state.legacyDirectoryIdentity = authority.identity;
				this.assertRunHistoryDirectoryStable(
					state.legacyNamespacePath,
					state.legacyNamespaceDescriptor,
					state.legacyNamespaceIdentity,
				);
				state.procfsAuthority ??= this.openRunHistoryProcfsAuthority();
				state.legacyDirectoryResolvedPath = this.captureRunHistoryProcfsDescriptorPath(
					state.procfsAuthority,
					authority.descriptor,
					"legacy_run_directory",
					"directory",
				);
				state.directory = opendirSync(
					this.runHistoryProcfsDescriptorPath(state.procfsAuthority, authority.descriptor),
				);
				this.assertRunHistoryProcfsDescriptorEntry(
					state.procfsAuthority,
					authority.descriptor,
					state.legacyDirectoryResolvedPath,
					"legacy_run_directory",
					"directory",
				);
			} catch (error) {
				return this.incompleteRunHistory(state, "run_history_legacy_directory_corrupt", {
					kind: "corrupt",
					reason: error instanceof Error ? error.message : String(error),
				});
			}
		}
		const directory = state.directory;
		if (!directory) return this.beginRunHistoryCasValidation(state);
		if (continuingPage) {
			const pageStartFailure = assertLegacyPageBoundary();
			if (pageStartFailure) return pageStartFailure;
		}
		for (let count = 0; count < PIN_REFERENCE_BATCH_COUNT; count += 1) {
			if (Date.now() > state.deadlineMs) {
				return incompleteLegacyPage("run_history_deadline_exceeded", {
					kind: "truncated",
					reason: "legacy_snapshot_deadline_exceeded",
				});
			}
			let entry: Dirent | null;
			try {
				entry = directory.readSync();
			} catch (error) {
				return incompleteLegacyPage("run_history_legacy_directory_corrupt", {
					kind: "corrupt",
					reason: error instanceof Error ? error.message : String(error),
				});
			}
			if (!entry) {
				try {
					directory.closeSync();
				} catch {}
				state.directory = undefined;
				try {
					if (
						!state.procfsAuthority ||
						state.legacyDirectoryDescriptor === undefined ||
						state.legacyDirectoryResolvedPath === undefined
					) {
						throw new Error("legacy_procfs_stability_fence_missing");
					}
					this.assertRunHistoryProcfsDescriptorEntry(
						state.procfsAuthority,
						state.legacyDirectoryDescriptor,
						state.legacyDirectoryResolvedPath,
						"legacy_run_directory",
						"directory",
					);
					this.assertRunHistoryDirectoryStable(
						state.legacyDirectoryPath,
						state.legacyDirectoryDescriptor,
						state.legacyDirectoryIdentity,
					);
					this.assertRunHistoryDirectoryStable(
						state.legacyNamespacePath,
						state.legacyNamespaceDescriptor,
						state.legacyNamespaceIdentity,
					);
				} catch (error) {
					return this.incompleteRunHistory(state, "run_history_legacy_snapshot_changed", {
						kind: "corrupt",
						reason: error instanceof Error ? error.message : String(error),
					});
				}
				const before = state.legacyDirectoryIdentity;
				if (!before) {
					return this.incompleteRunHistory(state, "run_history_legacy_snapshot_changed", {
						kind: "corrupt",
						reason: "legacy_directory_identity_missing_during_projection",
					});
				}
				state.snapshotFacts.push(canonicalJson({ legacyDirectory: serializableFilesystemIdentity(before) }));
				return this.beginRunHistoryCasValidation(state);
			}
			state.legacyEntriesScanned += 1;
			if (state.legacyEntriesScanned > PENDING_ENTRY_MAX_COUNT) {
				return incompleteLegacyPage("run_history_legacy_entry_bound_exceeded", {
					kind: "truncated",
					reason: "legacy_directory_entry_bound_exceeded",
				});
			}
			if (!/^seq-\d{20}-[0-9a-f]{64}\.json$/.test(entry.name)) continue;
			const authorityPath = join(directory.path, entry.name);
			const canonicalPath = join(state.legacyDirectoryPath ?? "", entry.name);
			try {
				if (
					!state.procfsAuthority ||
					state.legacyDirectoryDescriptor === undefined ||
					state.legacyDirectoryResolvedPath === undefined
				) {
					throw new Error("legacy_procfs_stability_fence_missing");
				}
				const { value, bytes } = this.readStableLegacyOccurrence(authorityPath, canonicalPath);
				state.legacyBytesRead += bytes;
				if (state.legacyBytesRead > PENDING_ENTRY_MAX_BYTES) {
					return incompleteLegacyPage("run_history_legacy_byte_bound_exceeded", {
						kind: "truncated",
						reason: "legacy_reference_byte_bound_exceeded",
					});
				}
				const event = this.parseRunHistoryEvent(value, canonicalPath, state.runId);
				if (!event) throw new Error("legacy_occurrence_semantic_validation_failed");
				const semanticConflict = this.observeRunHistorySemanticFingerprint(state, event);
				if (semanticConflict) {
					return incompleteLegacyPage(semanticConflict, {
						kind: semanticConflict.includes("truncated") ? "truncated" : "corrupt",
						reason: semanticConflict,
						reference: canonicalPath,
					});
				}
				const wall = segmentObservedAtMs(event.eventWallTimeMs);
				if (wall < state.fromWallTimeMs || wall > state.throughWallTimeMs) continue;
				state.legacyOccurrenceCount += 1;
				const conflict = this.addRunHistoryEvent(state, event);
				if (conflict) {
					return incompleteLegacyPage(conflict, {
						kind: conflict.includes("truncated") ? "truncated" : "corrupt",
						reason: conflict,
						reference: canonicalPath,
					});
				}
			} catch (error) {
				return incompleteLegacyPage("run_history_legacy_reference_corrupt", {
					kind: error instanceof Error && error.message.includes("truncated") ? "truncated" : "corrupt",
					reason: error instanceof Error ? error.message : String(error),
					reference: canonicalPath,
				});
			}
		}
		const pageEndFailure = assertLegacyPageBoundary();
		if (pageEndFailure) return pageEndFailure;
		return this.pendingRunHistory(state);
	}

	private runHistoryProcfsType(path: string): bigint {
		const observed = this.options.runHistoryProcfs?.statfsType?.(path) ?? statfsSync(path).type;
		return typeof observed === "bigint" ? observed : BigInt(observed);
	}

	private runHistoryProcfsDescriptorPath(
		authority: RunHistoryProcfsAuthority,
		descriptor: number,
		childName?: string,
	): string {
		const canonicalPath =
			childName === undefined
				? join(authority.descriptorDirectoryPath, String(descriptor))
				: join(authority.descriptorDirectoryPath, String(descriptor), childName);
		return (
			this.options.runHistoryProcfs?.resolveDescriptorPath?.({
				canonicalPath,
				descriptor,
				...(childName === undefined ? {} : { childName }),
			}) ?? canonicalPath
		);
	}

	private assertRunHistoryProcfsDirectoryStable(
		path: string,
		descriptor: number,
		identity: StableFilesystemIdentity,
		role: string,
	): void {
		if (this.runHistoryProcfsType(path) !== BigInt(LINUX_PROC_SUPER_MAGIC)) {
			throw new Error(`run_history_cas_procfs_${role}_filesystem_mismatch`);
		}
		const held = fstatSync(descriptor, { bigint: true });
		const namedBefore = lstatSync(path, { bigint: true });
		if (
			!held.isDirectory() ||
			!namedBefore.isDirectory() ||
			namedBefore.isSymbolicLink() ||
			!sameStableDirectoryIdentity(identity, stableFilesystemIdentity(held)) ||
			!sameStableDirectoryIdentity(identity, stableFilesystemIdentity(namedBefore))
		) {
			throw new Error(`run_history_cas_procfs_${role}_identity_mismatch`);
		}
		let namedDescriptor: number | undefined;
		try {
			namedDescriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
			const namedOpened = fstatSync(namedDescriptor, { bigint: true });
			if (
				!namedOpened.isDirectory() ||
				!sameStableDirectoryIdentity(identity, stableFilesystemIdentity(namedOpened))
			) {
				throw new Error(`run_history_cas_procfs_${role}_identity_mismatch`);
			}
		} finally {
			if (namedDescriptor !== undefined) {
				try {
					closeSync(namedDescriptor);
				} catch {}
			}
		}
	}

	private readRunHistoryProcfsMountId(authority: RunHistoryProcfsAuthority, descriptor: number, role: string): bigint {
		this.assertRunHistoryProcfsDirectoryStable(
			authority.descriptorInfoDirectoryPath,
			authority.descriptorInfoDirectoryDescriptor,
			authority.descriptorInfoDirectoryIdentity,
			"fdinfo_directory",
		);
		const path = join(authority.descriptorInfoDirectoryPath, String(descriptor));
		let infoDescriptor: number | undefined;
		const chunks: Buffer[] = [];
		let bytes = 0;
		try {
			infoDescriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
			const before = fstatSync(infoDescriptor, { bigint: true });
			if (!before.isFile()) throw new Error(`run_history_cas_procfs_${role}_fdinfo_invalid`);
			for (;;) {
				const remaining = RUN_HISTORY_PROCFS_FDINFO_MAX_BYTES + 1 - bytes;
				if (remaining <= 0) throw new Error(`run_history_cas_procfs_${role}_fdinfo_oversized`);
				const buffer = Buffer.allocUnsafe(Math.min(4096, remaining));
				const count = readSync(infoDescriptor, buffer, 0, buffer.length, null);
				if (count === 0) break;
				chunks.push(Buffer.from(buffer.subarray(0, count)));
				bytes += count;
				if (bytes > RUN_HISTORY_PROCFS_FDINFO_MAX_BYTES) {
					throw new Error(`run_history_cas_procfs_${role}_fdinfo_oversized`);
				}
			}
			const after = fstatSync(infoDescriptor, { bigint: true });
			if (!after.isFile() || before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode) {
				throw new Error(`run_history_cas_procfs_${role}_fdinfo_changed`);
			}
		} finally {
			if (infoDescriptor !== undefined) {
				try {
					closeSync(infoDescriptor);
				} catch {}
			}
		}
		this.assertRunHistoryProcfsDirectoryStable(
			authority.descriptorInfoDirectoryPath,
			authority.descriptorInfoDirectoryDescriptor,
			authority.descriptorInfoDirectoryIdentity,
			"fdinfo_directory",
		);
		const candidates = Buffer.concat(chunks)
			.toString("utf8")
			.split("\n")
			.filter((line) => line.startsWith("mnt_id"));
		if (candidates.length !== 1) {
			throw new Error(`run_history_cas_procfs_${role}_fdinfo_mount_id_ambiguous`);
		}
		const match = /^mnt_id:\s+([0-9]+)$/.exec(candidates[0] ?? "");
		if (!match) throw new Error(`run_history_cas_procfs_${role}_fdinfo_mount_id_invalid`);
		const mountId = BigInt(match[1] ?? "-1");
		if (mountId <= 0n) {
			throw new Error(`run_history_cas_procfs_${role}_fdinfo_mount_id_invalid`);
		}
		return mountId;
	}

	private assertRunHistoryProcfsAuthorityStable(authority: RunHistoryProcfsAuthority): void {
		this.assertRunHistoryProcfsDirectoryStable(
			authority.rootPath,
			authority.rootDescriptor,
			authority.rootIdentity,
			"root",
		);
		this.assertRunHistoryProcfsDirectoryStable(
			authority.descriptorDirectoryPath,
			authority.descriptorDirectoryDescriptor,
			authority.descriptorDirectoryIdentity,
			"fd_directory",
		);
		this.assertRunHistoryProcfsDirectoryStable(
			authority.descriptorInfoDirectoryPath,
			authority.descriptorInfoDirectoryDescriptor,
			authority.descriptorInfoDirectoryIdentity,
			"fdinfo_directory",
		);
		if (authority.rootIdentity.ino !== 1n) {
			throw new Error("run_history_cas_procfs_root_inode_mismatch");
		}
		const rootMountId = this.readRunHistoryProcfsMountId(authority, authority.rootDescriptor, "root");
		const descriptorMountId = this.readRunHistoryProcfsMountId(
			authority,
			authority.descriptorDirectoryDescriptor,
			"fd_directory",
		);
		const descriptorInfoMountId = this.readRunHistoryProcfsMountId(
			authority,
			authority.descriptorInfoDirectoryDescriptor,
			"fdinfo_directory",
		);
		if (
			rootMountId !== authority.mountId ||
			descriptorMountId !== authority.mountId ||
			descriptorInfoMountId !== authority.mountId
		) {
			throw new Error("run_history_cas_procfs_mount_id_mismatch");
		}
	}

	/**
	 * This pure-Node containment is conditional on genuine kernel procfs/fdinfo and no concurrent
	 * privileged CAP_SYS_ADMIN mutation of this process's mount namespace. Held directory identities,
	 * descriptor-bound mount IDs, and before/after entry checks reject static route replacement, but
	 * Node cannot make the magic-link traversal atomic with those checks. Removing that residual mount
	 * race requires a native openat2-based helper rather than a procfs descriptor path.
	 */
	private openRunHistoryProcfsAuthority(): RunHistoryProcfsAuthority {
		if (process.platform !== "linux") throw new Error("run_history_cas_descriptor_anchoring_unavailable");
		const rootPath = "/proc" as const;
		const descriptorDirectoryPath = this.options.runHistoryProcfs?.descriptorDirectoryPath ?? "/proc/thread-self/fd";
		const descriptorInfoDirectoryPath =
			this.options.runHistoryProcfs?.descriptorInfoDirectoryPath ?? "/proc/thread-self/fdinfo";
		let rootDescriptor: number | undefined;
		let descriptorDirectoryDescriptor: number | undefined;
		let descriptorInfoDirectoryDescriptor: number | undefined;
		try {
			for (const path of [rootPath, descriptorDirectoryPath, descriptorInfoDirectoryPath]) {
				if (this.runHistoryProcfsType(path) !== BigInt(LINUX_PROC_SUPER_MAGIC)) {
					throw new Error("run_history_cas_procfs_filesystem_mismatch");
				}
			}
			rootDescriptor = openSync(rootPath, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
			descriptorDirectoryDescriptor = openSync(
				descriptorDirectoryPath,
				fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
			);
			descriptorInfoDirectoryDescriptor = openSync(
				descriptorInfoDirectoryPath,
				fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
			);
			const rootOpened = fstatSync(rootDescriptor, { bigint: true });
			const descriptorDirectoryOpened = fstatSync(descriptorDirectoryDescriptor, { bigint: true });
			const descriptorInfoDirectoryOpened = fstatSync(descriptorInfoDirectoryDescriptor, {
				bigint: true,
			});
			if (
				!rootOpened.isDirectory() ||
				!descriptorDirectoryOpened.isDirectory() ||
				!descriptorInfoDirectoryOpened.isDirectory() ||
				rootOpened.ino !== 1n
			) {
				throw new Error("run_history_cas_procfs_identity_invalid");
			}
			const authority: RunHistoryProcfsAuthority = {
				rootPath,
				descriptorDirectoryPath,
				descriptorInfoDirectoryPath,
				rootDescriptor,
				descriptorDirectoryDescriptor,
				descriptorInfoDirectoryDescriptor,
				rootIdentity: stableFilesystemIdentity(rootOpened),
				descriptorDirectoryIdentity: stableFilesystemIdentity(descriptorDirectoryOpened),
				descriptorInfoDirectoryIdentity: stableFilesystemIdentity(descriptorInfoDirectoryOpened),
				mountId: -1n,
			};
			const rootMountId = this.readRunHistoryProcfsMountId(authority, rootDescriptor, "root");
			const descriptorMountId = this.readRunHistoryProcfsMountId(
				authority,
				descriptorDirectoryDescriptor,
				"fd_directory",
			);
			const descriptorInfoMountId = this.readRunHistoryProcfsMountId(
				authority,
				descriptorInfoDirectoryDescriptor,
				"fdinfo_directory",
			);
			if (rootMountId !== descriptorMountId || rootMountId !== descriptorInfoMountId) {
				throw new Error("run_history_cas_procfs_mount_id_mismatch");
			}
			authority.mountId = rootMountId;
			this.assertRunHistoryProcfsAuthorityStable(authority);
			this.options.runHistoryProcfs?.onAuthorityAdmitted?.({ mountId: authority.mountId });
			return authority;
		} catch (error) {
			for (const descriptor of [descriptorInfoDirectoryDescriptor, descriptorDirectoryDescriptor, rootDescriptor]) {
				if (descriptor === undefined) continue;
				try {
					closeSync(descriptor);
				} catch {}
			}
			if (error instanceof Error && error.message.startsWith("run_history_cas_")) throw error;
			throw new Error(
				`run_history_cas_descriptor_anchoring_unavailable:${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}

	private assertRunHistoryProcfsDescriptorEntry(
		authority: RunHistoryProcfsAuthority,
		descriptor: number,
		expectedPath: string,
		role: string,
		kind: "directory" | "file",
	): void {
		this.assertRunHistoryProcfsAuthorityStable(authority);
		const entryPath = this.runHistoryProcfsDescriptorPath(authority, descriptor);
		let reopenedDescriptor: number | undefined;
		try {
			if (readlinkSync(entryPath, "utf8") !== expectedPath) {
				throw new Error(`run_history_cas_procfs_${role}_descriptor_target_mismatch`);
			}
			reopenedDescriptor = openSync(
				entryPath,
				fsConstants.O_RDONLY | (kind === "directory" ? fsConstants.O_DIRECTORY : fsConstants.O_NONBLOCK),
			);
			const held = fstatSync(descriptor, { bigint: true });
			const reopened = fstatSync(reopenedDescriptor, { bigint: true });
			const matches =
				kind === "directory"
					? held.isDirectory() &&
						reopened.isDirectory() &&
						sameStableDirectoryIdentity(stableFilesystemIdentity(held), stableFilesystemIdentity(reopened))
					: held.isFile() &&
						reopened.isFile() &&
						sameStableFilesystemIdentity(stableFilesystemIdentity(held), stableFilesystemIdentity(reopened));
			if (!matches || readlinkSync(entryPath, "utf8") !== expectedPath) {
				throw new Error(`run_history_cas_procfs_${role}_descriptor_identity_mismatch`);
			}
		} finally {
			if (reopenedDescriptor !== undefined) {
				try {
					closeSync(reopenedDescriptor);
				} catch {}
			}
		}
		this.assertRunHistoryProcfsAuthorityStable(authority);
	}

	private captureRunHistoryProcfsDescriptorPath(
		authority: RunHistoryProcfsAuthority,
		descriptor: number,
		role: string,
		kind: "directory" | "file",
	): string {
		this.assertRunHistoryProcfsAuthorityStable(authority);
		const path = readlinkSync(this.runHistoryProcfsDescriptorPath(authority, descriptor), "utf8");
		if (!path.startsWith("/") || path.endsWith(" (deleted)")) {
			throw new Error(`run_history_cas_procfs_${role}_descriptor_path_invalid`);
		}
		this.assertRunHistoryProcfsDescriptorEntry(authority, descriptor, path, role, kind);
		return path;
	}

	private openRunHistoryCasDirectoryFence(
		authority: RunHistoryProcfsAuthority,
		input: {
			role: RunHistoryCasDirectoryFence["role"];
			path: string;
			name?: string;
			parent?: RunHistoryCasDirectoryFence;
		},
	): RunHistoryCasDirectoryFence {
		let canonicalBefore: BigIntStats;
		try {
			canonicalBefore = lstatSync(input.path, { bigint: true });
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") {
				throw new Error(`run_history_cas_${input.role}_missing`);
			}
			throw error;
		}
		if (!canonicalBefore.isDirectory() || canonicalBefore.isSymbolicLink()) {
			throw new Error(`run_history_cas_${input.role}_invalid`);
		}
		if (input.parent) {
			this.assertRunHistoryProcfsDescriptorEntry(
				authority,
				input.parent.descriptor,
				input.parent.resolvedPath,
				input.parent.role,
				"directory",
			);
		}
		const target = input.parent
			? this.runHistoryProcfsDescriptorPath(authority, input.parent.descriptor, input.name ?? "")
			: input.path;
		let descriptor: number | undefined;
		try {
			descriptor = openSync(target, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
			if (input.parent) {
				this.assertRunHistoryProcfsDescriptorEntry(
					authority,
					input.parent.descriptor,
					input.parent.resolvedPath,
					input.parent.role,
					"directory",
				);
			}
			const opened = fstatSync(descriptor, { bigint: true });
			const identity = stableFilesystemIdentity(opened);
			if (
				!opened.isDirectory() ||
				!sameStableDirectoryIdentity(identity, stableFilesystemIdentity(canonicalBefore))
			) {
				throw new Error(`run_history_cas_${input.role}_invalid`);
			}
			const resolvedPath = this.captureRunHistoryProcfsDescriptorPath(
				authority,
				descriptor,
				input.role,
				"directory",
			);
			if (input.parent && resolvedPath !== join(input.parent.resolvedPath, input.name ?? "")) {
				throw new Error(`run_history_cas_${input.role}_path_mismatch`);
			}
			const canonicalAfter = lstatSync(input.path, { bigint: true });
			if (
				!canonicalAfter.isDirectory() ||
				canonicalAfter.isSymbolicLink() ||
				!sameStableDirectoryIdentity(identity, stableFilesystemIdentity(canonicalAfter))
			) {
				throw new Error(`run_history_cas_${input.role}_name_swapped`);
			}
			return {
				role: input.role,
				path: input.path,
				resolvedPath,
				...(input.name ? { name: input.name } : {}),
				descriptor,
				identity,
				...(input.parent ? { parentDescriptor: input.parent.descriptor } : {}),
			};
		} catch (error) {
			if (descriptor !== undefined) {
				try {
					closeSync(descriptor);
				} catch {}
			}
			if (error instanceof Error && error.message.startsWith("run_history_cas_")) throw error;
			const code = (error as NodeJS.ErrnoException).code;
			if (code === "ENOENT") throw new Error(`run_history_cas_${input.role}_missing`);
			if (code === "ELOOP" || code === "ENOTDIR") {
				throw new Error(`run_history_cas_${input.role}_invalid`);
			}
			throw error;
		}
	}

	private openRunHistoryCasValidation(
		claim: RunHistoryCasClaim,
		existingProcfsAuthority?: RunHistoryProcfsAuthority,
	): RunHistoryCasValidation {
		if (!/^[0-9a-f]{64}$/.test(claim.digest)) throw new Error("run_history_cas_path_invalid");
		const shardName = claim.digest.slice(0, 2);
		const expectedPath = join(this.root, "cas", "sha256", shardName, `${claim.digest}.blob`);
		if (claim.path !== expectedPath) throw new Error("run_history_cas_path_invalid");
		const procfsAuthority = existingProcfsAuthority ?? this.openRunHistoryProcfsAuthority();
		const directoryFences: RunHistoryCasDirectoryFence[] = [];
		let fileDescriptor: number | undefined;
		try {
			this.assertRunHistoryProcfsAuthorityStable(procfsAuthority);
			const recorderRoot = this.openRunHistoryCasDirectoryFence(procfsAuthority, {
				role: "recorder_root",
				path: this.root,
			});
			directoryFences.push(recorderRoot);
			const casDirectory = this.openRunHistoryCasDirectoryFence(procfsAuthority, {
				role: "cas_directory",
				path: join(this.root, "cas"),
				name: "cas",
				parent: recorderRoot,
			});
			directoryFences.push(casDirectory);
			const algorithmDirectory = this.openRunHistoryCasDirectoryFence(procfsAuthority, {
				role: "algorithm_directory",
				path: join(this.root, "cas", "sha256"),
				name: "sha256",
				parent: casDirectory,
			});
			directoryFences.push(algorithmDirectory);
			const shardDirectory = this.openRunHistoryCasDirectoryFence(procfsAuthority, {
				role: "shard_directory",
				path: join(this.root, "cas", "sha256", shardName),
				name: shardName,
				parent: algorithmDirectory,
			});
			directoryFences.push(shardDirectory);

			this.assertRunHistoryProcfsDescriptorEntry(
				procfsAuthority,
				shardDirectory.descriptor,
				shardDirectory.resolvedPath,
				shardDirectory.role,
				"directory",
			);
			try {
				fileDescriptor = openSync(
					this.runHistoryProcfsDescriptorPath(procfsAuthority, shardDirectory.descriptor, `${claim.digest}.blob`),
					fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
				);
			} catch (error) {
				const code = (error as NodeJS.ErrnoException).code;
				if (code === "ENOENT") throw new Error("run_history_cas_blob_missing");
				if (code === "ELOOP" || code === "ENOTDIR") throw new Error("run_history_cas_blob_invalid");
				throw error;
			}
			this.assertRunHistoryProcfsDescriptorEntry(
				procfsAuthority,
				shardDirectory.descriptor,
				shardDirectory.resolvedPath,
				shardDirectory.role,
				"directory",
			);
			const fileOpened = fstatSync(fileDescriptor, { bigint: true });
			if (!fileOpened.isFile()) throw new Error("run_history_cas_blob_invalid");
			if (fileOpened.size !== BigInt(claim.bytes)) throw new Error("run_history_cas_size_mismatch");
			const fileIdentity = stableFilesystemIdentity(fileOpened);
			const fileResolvedPath = this.captureRunHistoryProcfsDescriptorPath(
				procfsAuthority,
				fileDescriptor,
				"blob",
				"file",
			);
			if (fileResolvedPath !== join(shardDirectory.resolvedPath, `${claim.digest}.blob`)) {
				throw new Error("run_history_cas_blob_path_mismatch");
			}
			const canonicalFile = lstatSync(claim.path, { bigint: true });
			if (
				!canonicalFile.isFile() ||
				canonicalFile.isSymbolicLink() ||
				!sameStableFilesystemIdentity(fileIdentity, stableFilesystemIdentity(canonicalFile))
			) {
				throw new Error("run_history_cas_blob_name_swapped");
			}
			const active: RunHistoryCasValidation = {
				claim,
				procfsAuthority,
				directoryFences,
				fileDescriptor,
				fileResolvedPath,
				fileIdentity,
				offset: 0,
				hash: createHash("sha256"),
				readCount: 0,
			};
			this.options.onRunHistoryCasValidationStep?.({
				step: "opened",
				digest: claim.digest,
				offset: 0,
				readCount: 0,
			});
			return active;
		} catch (error) {
			for (const descriptor of [
				fileDescriptor,
				...directoryFences.map((fence) => fence.descriptor).reverse(),
				procfsAuthority.descriptorInfoDirectoryDescriptor,
				procfsAuthority.descriptorDirectoryDescriptor,
				procfsAuthority.rootDescriptor,
			]) {
				if (descriptor === undefined) continue;
				try {
					closeSync(descriptor);
				} catch {}
			}
			if (error instanceof Error && error.message.startsWith("run_history_cas_")) throw error;
			throw new Error(`run_history_cas_open_failed:${error instanceof Error ? error.message : String(error)}`);
		}
	}

	private assertRunHistoryCasValidationStable(active: RunHistoryCasValidation): void {
		this.assertRunHistoryProcfsAuthorityStable(active.procfsAuthority);
		const fileOpened = fstatSync(active.fileDescriptor, { bigint: true });
		if (
			!fileOpened.isFile() ||
			!sameStableFilesystemIdentity(active.fileIdentity, stableFilesystemIdentity(fileOpened))
		) {
			throw new Error("run_history_cas_blob_changed_during_read");
		}
		if (readSync(active.fileDescriptor, Buffer.allocUnsafe(1), 0, 1, active.claim.bytes) !== 0) {
			throw new Error("run_history_cas_blob_changed_during_read");
		}
		for (const fence of active.directoryFences) {
			const opened = fstatSync(fence.descriptor, { bigint: true });
			if (!opened.isDirectory() || !sameStableDirectoryIdentity(fence.identity, stableFilesystemIdentity(opened))) {
				throw new Error(`run_history_cas_${fence.role}_changed_during_read`);
			}
			this.assertRunHistoryProcfsDescriptorEntry(
				active.procfsAuthority,
				fence.descriptor,
				fence.resolvedPath,
				fence.role,
				"directory",
			);
			const target =
				fence.parentDescriptor === undefined
					? fence.path
					: this.runHistoryProcfsDescriptorPath(active.procfsAuthority, fence.parentDescriptor, fence.name ?? "");
			let namedDescriptor: number | undefined;
			try {
				namedDescriptor = openSync(target, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
				const named = fstatSync(namedDescriptor, { bigint: true });
				if (!named.isDirectory() || !sameStableDirectoryIdentity(fence.identity, stableFilesystemIdentity(named))) {
					throw new Error(`run_history_cas_${fence.role}_name_swapped`);
				}
			} catch (error) {
				if (error instanceof Error && error.message.startsWith("run_history_cas_")) throw error;
				throw new Error(`run_history_cas_${fence.role}_name_swapped`);
			} finally {
				if (namedDescriptor !== undefined) {
					try {
						closeSync(namedDescriptor);
					} catch {}
				}
			}
		}
		const shardDirectory = active.directoryFences.at(-1);
		if (!shardDirectory || shardDirectory.role !== "shard_directory") {
			throw new Error("run_history_cas_directory_fence_missing");
		}
		let namedFileDescriptor: number | undefined;
		try {
			this.assertRunHistoryProcfsDescriptorEntry(
				active.procfsAuthority,
				shardDirectory.descriptor,
				shardDirectory.resolvedPath,
				shardDirectory.role,
				"directory",
			);
			namedFileDescriptor = openSync(
				this.runHistoryProcfsDescriptorPath(
					active.procfsAuthority,
					shardDirectory.descriptor,
					`${active.claim.digest}.blob`,
				),
				fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
			);
			this.assertRunHistoryProcfsDescriptorEntry(
				active.procfsAuthority,
				shardDirectory.descriptor,
				shardDirectory.resolvedPath,
				shardDirectory.role,
				"directory",
			);
			const named = fstatSync(namedFileDescriptor, { bigint: true });
			if (!named.isFile() || !sameStableFilesystemIdentity(active.fileIdentity, stableFilesystemIdentity(named))) {
				throw new Error("run_history_cas_blob_name_swapped");
			}
		} catch (error) {
			if (error instanceof Error && error.message.startsWith("run_history_cas_")) throw error;
			throw new Error("run_history_cas_blob_name_swapped");
		} finally {
			if (namedFileDescriptor !== undefined) {
				try {
					closeSync(namedFileDescriptor);
				} catch {}
			}
		}
		try {
			this.assertRunHistoryProcfsDescriptorEntry(
				active.procfsAuthority,
				active.fileDescriptor,
				active.fileResolvedPath,
				"blob",
				"file",
			);
		} catch (error) {
			if (error instanceof Error && error.message.startsWith("run_history_cas_procfs_blob_descriptor_")) {
				throw new Error("run_history_cas_blob_changed_during_read");
			}
			throw error;
		}
		this.assertRunHistoryProcfsAuthorityStable(active.procfsAuthority);
	}

	private advanceRunHistoryCasValidation(state: RunHistoryTraversal): IncidentRecorderRunHistoryProgressResult {
		state.casDigests ??= [...state.casClaims.keys()].sort();
		let reads = 0;
		let completedDigests = 0;
		try {
			while (state.casIndex < state.casDigests.length && completedDigests < PIN_REFERENCE_BATCH_COUNT) {
				if (Date.now() > state.deadlineMs) {
					return this.incompleteRunHistory(state, "run_history_cas_deadline_exceeded", {
						kind: "truncated",
						reason: "cas_validation_deadline_exceeded",
					});
				}
				const digest = state.casDigests[state.casIndex];
				const claim = digest ? state.casClaims.get(digest) : undefined;
				if (!claim) throw new Error("run_history_cas_claim_missing");
				if (!state.activeCasValidation) {
					const procfsAuthority = state.procfsAuthority;
					state.procfsAuthority = undefined;
					state.activeCasValidation = this.openRunHistoryCasValidation(claim, procfsAuthority);
				}
				const active = state.activeCasValidation;
				if (active.claim.digest !== digest) throw new Error("run_history_cas_active_claim_mismatch");
				while (active.offset < active.claim.bytes && reads < RUN_HISTORY_CAS_READS_PER_CALL) {
					const length = Math.min(RUN_HISTORY_CAS_READ_BYTES, active.claim.bytes - active.offset);
					const buffer = Buffer.allocUnsafe(length);
					const count = readSync(active.fileDescriptor, buffer, 0, length, active.offset);
					reads += 1;
					active.readCount += 1;
					if (count <= 0) throw new Error("run_history_cas_truncated_during_read");
					active.hash.update(buffer.subarray(0, count));
					active.offset += count;
					this.options.onRunHistoryCasValidationStep?.({
						step: "read",
						digest,
						offset: active.offset,
						readCount: active.readCount,
					});
					if (Date.now() > state.deadlineMs) {
						return this.incompleteRunHistory(state, "run_history_cas_deadline_exceeded", {
							kind: "truncated",
							reason: "cas_validation_deadline_exceeded",
							reference: active.claim.path,
						});
					}
				}
				if (active.offset < active.claim.bytes) return this.pendingRunHistory(state);
				this.assertRunHistoryCasValidationStable(active);
				if (active.hash.digest("hex") !== digest) throw new Error("run_history_cas_digest_mismatch");
				state.validatedCasFacts.push({
					digest,
					bytes: active.claim.bytes,
					path: active.claim.path,
					identity: serializableFilesystemIdentity(active.fileIdentity),
				});
				state.snapshotFacts.push(
					canonicalJson({
						cas: { digest, bytes: active.claim.bytes, path: active.claim.path },
						identity: serializableFilesystemIdentity(active.fileIdentity),
					}),
				);
				this.options.onRunHistoryCasValidationStep?.({
					step: "verified",
					digest,
					offset: active.offset,
					readCount: active.readCount,
				});
				this.closeRunHistoryCasValidation(state);
				state.casIndex += 1;
				completedDigests += 1;
				if (reads >= RUN_HISTORY_CAS_READS_PER_CALL && state.casIndex < state.casDigests.length) {
					return this.pendingRunHistory(state);
				}
			}
			if (state.casIndex < state.casDigests.length) return this.pendingRunHistory(state);
			return this.completeRunHistory(state);
		} catch (error) {
			const reason =
				error instanceof Error && error.message.startsWith("run_history_cas_")
					? (error.message.split(":", 1)[0] ?? "run_history_cas_validation_failed")
					: "run_history_cas_validation_failed";
			const reference = state.activeCasValidation?.claim.path;
			return this.incompleteRunHistory(state, reason, {
				kind: reason.includes("missing") ? "incomplete" : "corrupt",
				reason: error instanceof Error ? error.message : String(error),
				...(reference ? { reference } : {}),
			});
		}
	}

	private completeRunHistory(state: RunHistoryTraversal): IncidentRecorderRunHistoryProgressResult {
		const orderingFailure = this.validateRunHistoryOrdering(state);
		if (orderingFailure) {
			return this.incompleteRunHistory(state, orderingFailure, {
				kind: "corrupt",
				reason: orderingFailure,
			});
		}
		if (state.evidence.length > 0) {
			return this.incompleteRunHistory(state, "run_history_contains_loss_evidence", {
				kind: "incomplete",
				reason: "projection_cannot_complete_with_loss_evidence",
			});
		}
		try {
			if (!state.segmentReadLease) throw new Error("segment_read_lease_missing");
			this.existingSegmentStore().assertReadLeaseUsable(state.segmentReadLease);
		} catch (error) {
			return this.incompleteRunHistory(state, "run_history_segment_snapshot_stale_or_corrupt", {
				kind: "corrupt",
				reason: error instanceof Error ? error.message : String(error),
			});
		}
		const projection = this.runHistoryProjection(state, "complete_snapshot");
		const snapshot: IncidentRecorderRunHistorySnapshot = {
			version: 1,
			fingerprint: sha256(
				canonicalJson({
					requestFingerprint: sha256(
						canonicalJson({
							runId: state.runId,
							fromWallTimeMs: state.fromWallTimeMs,
							throughWallTimeMs: state.throughWallTimeMs,
							...(state.retainForPublication ? { retainForPublication: true } : {}),
						}),
					),
					segmentReadFrontier: {
						storeInstanceId: state.segmentReadLease.storeInstanceId,
						highWaterSegmentSequence: state.segmentReadLease.highWaterSegmentSequence,
						highWaterOrdinal: state.segmentReadLease.highWaterOrdinal,
					},
					snapshotFacts: state.snapshotFacts,
					validatedCasFacts: state.validatedCasFacts,
					events: projection.events.map((event) => ({
						identityKey: event.identityKey,
						semanticFingerprint: event.semanticFingerprint,
					})),
				}),
			),
			segmentRecordCount: state.segmentRecordCount,
			segmentRecoveryGapCount: state.segmentRecoveryGapCount,
			segmentScannedSegments: state.segmentScannedSegments,
			segmentScannedRecords: state.segmentScannedRecords,
			segmentScannedIndexBytes: state.segmentScannedIndexBytes,
			legacyOccurrenceCount: state.legacyOccurrenceCount,
			validatedCasDigestCount: state.validatedCasFacts.length,
		};
		const result = { state: "complete" as const, projection, snapshot };
		return state.retainForPublication
			? this.retainCompletedRunHistory(state, result)
			: this.boundedRunHistoryResult(state, result, true);
	}

	private sweepExpiredRunHistoryTraversals(nowMs: number): void {
		for (const state of this.runHistoryTraversals.values()) {
			if (nowMs > state.deadlineMs) this.discardRunHistoryTraversal(state);
		}
	}

	private armRunHistoryDeadline(state: RunHistoryTraversal): void {
		if (state.deadlineTimer) clearTimeout(state.deadlineTimer);
		const delayMs = Math.max(1, state.deadlineMs - Date.now() + 1);
		const timer = setTimeout(() => {
			const current = this.runHistoryTraversals.get(state.token);
			if (current !== state || current.requestFingerprint !== state.requestFingerprint) return;
			if (Date.now() <= state.deadlineMs) {
				this.armRunHistoryDeadline(state);
				return;
			}
			this.discardRunHistoryTraversal(state);
		}, delayMs);
		timer.unref();
		state.deadlineTimer = timer;
	}

	private isRunHistoryPublicationCapability(
		value: IncidentRecorderRunHistoryCursor | IncidentRecorderRunHistoryPublicationCapability,
	): value is IncidentRecorderRunHistoryPublicationCapability {
		return "kind" in value && value.kind === "run_history_publication";
	}

	private exactRunHistoryPublicationState(
		capability: IncidentRecorderRunHistoryPublicationCapability,
	): RunHistoryTraversal {
		const state = this.runHistoryPublicationCapabilities.get(capability);
		if (!state || state.publicationCapability !== capability || state.phase !== "publication-retained") {
			throw new Error("Expected the exact run-history publication capability from this process");
		}
		return state;
	}

	assertRunHistoryPublicationReady(capability: IncidentRecorderRunHistoryPublicationCapability): void {
		this.sweepExpiredRunHistoryTraversals(Date.now());
		const state = this.exactRunHistoryPublicationState(capability);
		try {
			if (!state.segmentReadLease) throw new Error("segment_read_lease_missing");
			this.existingSegmentStore().assertReadLeaseUsable(state.segmentReadLease);
		} catch (error) {
			this.discardRunHistoryTraversal(state);
			throw error;
		}
	}

	releaseRunHistoryPublication(capability: IncidentRecorderRunHistoryPublicationCapability): void {
		this.sweepExpiredRunHistoryTraversals(Date.now());
		if (this.releasedRunHistoryPublicationCapabilities.has(capability)) return;
		this.discardRunHistoryTraversal(this.exactRunHistoryPublicationState(capability));
	}

	cancelRunHistoryProjection(cursor: IncidentRecorderRunHistoryCursor): boolean;
	cancelRunHistoryProjection(capability: IncidentRecorderRunHistoryPublicationCapability): true;
	cancelRunHistoryProjection(
		cursor: IncidentRecorderRunHistoryCursor | IncidentRecorderRunHistoryPublicationCapability,
	): boolean {
		this.sweepExpiredRunHistoryTraversals(Date.now());
		if (this.isRunHistoryPublicationCapability(cursor)) {
			if (this.releasedRunHistoryPublicationCapabilities.has(cursor)) return true;
			this.discardRunHistoryTraversal(this.exactRunHistoryPublicationState(cursor));
			return true;
		}
		if (
			cursor.version !== 1 ||
			!/^[0-9a-f]{64}$/.test(cursor.token) ||
			!/^[0-9a-f]{64}$/.test(cursor.requestFingerprint)
		) {
			throw new Error("Invalid incident run-history continuation cursor");
		}
		const state = this.runHistoryTraversals.get(cursor.token);
		if (!state || state.requestFingerprint !== cursor.requestFingerprint) return false;
		if (state.publicationCapability) {
			throw new Error("Retained run-history completion requires its exact run-history publication capability");
		}
		this.discardRunHistoryTraversal(state);
		return true;
	}

	projectRunHistory(
		input: IncidentRecorderRunHistoryProjectionInput & {
			retainForPublication: true;
			pendingResponse: "cursor-only";
		},
	): IncidentRecorderRetainedRunHistoryCursorOnlyResult;
	projectRunHistory(
		input: IncidentRecorderRunHistoryProjectionInput & {
			retainForPublication: true;
			pendingResponse?: "full" | "cursor-only" | undefined;
		},
	): IncidentRecorderRetainedRunHistoryProgressResult;
	projectRunHistory(
		input: IncidentRecorderRunHistoryProjectionInput & {
			retainForPublication?: false | undefined;
			pendingResponse: "cursor-only";
		},
	): IncidentRecorderRunHistoryCursorOnlyResult;
	projectRunHistory(
		input: IncidentRecorderRunHistoryProjectionInput & {
			retainForPublication?: false | undefined;
			pendingResponse?: "full" | undefined;
		},
	): IncidentRecorderRunHistoryResult;
	projectRunHistory(
		input: IncidentRecorderRunHistoryProjectionInput,
	):
		| IncidentRecorderRunHistoryResult
		| IncidentRecorderRetainedRunHistoryResult
		| IncidentRecorderRunHistoryProgressResult
		| IncidentRecorderRetainedRunHistoryProgressResult;
	projectRunHistory(
		input: IncidentRecorderRunHistoryProjectionInput,
	):
		| IncidentRecorderRunHistoryResult
		| IncidentRecorderRetainedRunHistoryResult
		| IncidentRecorderRunHistoryProgressResult
		| IncidentRecorderRetainedRunHistoryProgressResult {
		if (
			!isCanonicalUuid(input.runId) ||
			!Number.isSafeInteger(input.fromWallTimeMs) ||
			input.fromWallTimeMs < 0 ||
			!Number.isSafeInteger(input.throughWallTimeMs) ||
			input.throughWallTimeMs < input.fromWallTimeMs ||
			(input.deadlineMs !== undefined &&
				(!Number.isFinite(input.deadlineMs) || !Number.isSafeInteger(input.deadlineMs) || input.deadlineMs < 0)) ||
			(input.retainForPublication !== undefined && typeof input.retainForPublication !== "boolean") ||
			(input.pendingResponse !== undefined &&
				input.pendingResponse !== "full" &&
				input.pendingResponse !== "cursor-only")
		) {
			throw new Error("Invalid incident run-history projection request");
		}
		const nowMs = Date.now();
		this.sweepExpiredRunHistoryTraversals(nowMs);
		const retainForPublication = input.retainForPublication === true;
		const pendingResponse = input.pendingResponse ?? "full";
		const requestFingerprint = sha256(
			canonicalJson({
				runId: input.runId,
				fromWallTimeMs: input.fromWallTimeMs,
				throughWallTimeMs: input.throughWallTimeMs,
				...(retainForPublication ? { retainForPublication: true } : {}),
				pendingResponse,
			}),
		);
		let state: RunHistoryTraversal | undefined;
		if (input.cursor) {
			if (
				input.cursor.version !== 1 ||
				!/^[0-9a-f]{64}$/.test(input.cursor.token) ||
				input.cursor.requestFingerprint !== requestFingerprint
			) {
				throw new Error("Invalid incident run-history continuation cursor");
			}
			state = this.runHistoryTraversals.get(input.cursor.token);
			if (
				!state ||
				state.requestFingerprint !== requestFingerprint ||
				state.retainForPublication !== retainForPublication ||
				state.pendingResponse !== pendingResponse
			) {
				const empty: RunHistoryTraversal = {
					token: input.cursor.token,
					requestFingerprint,
					runId: input.runId,
					fromWallTimeMs: input.fromWallTimeMs,
					throughWallTimeMs: input.throughWallTimeMs,
					deadlineMs: Date.now(),
					phase: "segment-occurrences",
					retainForPublication,
					pendingResponse,
					segmentRecordCount: 0,
					segmentRecoveryGapCount: 0,
					segmentScannedSegments: 0,
					segmentScannedRecords: 0,
					segmentScannedIndexBytes: 0,
					legacyOccurrenceCount: 0,
					legacyEntriesScanned: 0,
					legacyBytesRead: 0,
					semanticFingerprints: new Map(),
					events: new Map(),
					casClaims: new Map(),
					casIndex: 0,
					validatedCasFacts: [],
					memoryBytes: 0,
					evidence: [
						{
							kind: "truncated",
							reason: "run_history_continuation_missing_or_expired",
						},
					],
					snapshotFacts: [],
				};
				return {
					state: "incomplete",
					reason: "run_history_continuation_missing_or_expired",
					projection: this.runHistoryProjection(empty),
				};
			}
		} else {
			if (this.runHistoryTraversals.size >= 4) {
				throw new Error("Incident run-history projection capacity is saturated");
			}
			const token = sha256(`${requestFingerprint}\0${process.pid}\0${process.hrtime.bigint()}`);
			state = {
				token,
				requestFingerprint,
				runId: input.runId,
				fromWallTimeMs: input.fromWallTimeMs,
				throughWallTimeMs: input.throughWallTimeMs,
				deadlineMs: Math.min(input.deadlineMs ?? nowMs + PIN_SCAN_DEADLINE_MS, nowMs + PIN_SCAN_DEADLINE_MS),
				phase: "segment-occurrences",
				retainForPublication,
				pendingResponse,
				segmentRecordCount: 0,
				segmentRecoveryGapCount: 0,
				segmentScannedSegments: 0,
				segmentScannedRecords: 0,
				segmentScannedIndexBytes: 0,
				legacyOccurrenceCount: 0,
				legacyEntriesScanned: 0,
				legacyBytesRead: 0,
				semanticFingerprints: new Map(),
				events: new Map(),
				casClaims: new Map(),
				casIndex: 0,
				validatedCasFacts: [],
				memoryBytes: 0,
				evidence: [],
				snapshotFacts: [],
			};
			this.runHistoryTraversals.set(token, state);
			this.armRunHistoryDeadline(state);
		}
		if (!state) throw new Error("Incident run-history traversal state was not initialized");
		if (state.phase === "publication-retained") {
			throw new Error("Retained run-history completion requires its exact run-history publication capability");
		}
		if (Date.now() > state.deadlineMs) {
			return this.incompleteRunHistory(state, "run_history_deadline_exceeded", {
				kind: "truncated",
				reason: "projection_deadline_exceeded",
			});
		}
		try {
			if (state.phase === "cas-validation") return this.advanceRunHistoryCasValidation(state);
			if (state.phase === "legacy") return this.advanceRunHistoryLegacy(state);
			return this.advanceRunHistorySegmentPhase(state) ?? this.pendingRunHistory(state);
		} catch (error) {
			if (state.retainForPublication) this.discardRunHistoryTraversal(state);
			throw error;
		}
	}

	private failPinTraversal(state: PinTraversal, reason: string, _evidence: Record<string, unknown> = {}): void {
		try {
			state.directory?.closeSync();
		} catch {}
		state.directory = undefined;
		this.activePinTraversal = undefined;
		this.writeProviderPinIncomplete(state.incidentDir, "journal", reason, state.request);
	}

	private addPinMatch(state: PinTraversal, match: PinOccurrenceMatch): boolean {
		const existing = state.matches.find((candidate) => candidate.identityKey === match.identityKey);
		if (existing) {
			if (existing.semanticFingerprint !== match.semanticFingerprint) {
				this.failPinTraversal(state, "duplicate_occurrence_identity_conflict", {
					occurrenceIdentity: match.identityKey,
					existingSemanticFingerprint: existing.semanticFingerprint,
					observedSemanticFingerprint: match.semanticFingerprint,
				});
				return false;
			}
			return true;
		}
		const added = retainedBytes(match);
		if (state.matches.length >= PENDING_ENTRY_MAX_COUNT || state.memoryBytes + added > PENDING_ENTRY_MAX_BYTES) {
			this.failPinTraversal(state, "occurrence_query_truncated_by_explicit_memory_bound", {
				maxOccurrences: PENDING_ENTRY_MAX_COUNT,
				maxRetainedBytes: PENDING_ENTRY_MAX_BYTES,
			});
			return false;
		}
		state.seenOccurrenceIdentities.add(match.identityKey);
		state.matches.push(match);
		state.memoryBytes += added;
		return true;
	}

	/** Retention must not remove directories still used by incremental pin writers. */
	get hasActivePinWriters(): boolean {
		return (
			this.activePinScans.size > 0 ||
			Boolean(
				this.activePinTraversal ||
					this.journalManifestValidation ||
					this.sysdigSourceCapture ||
					this.sysdigSegmentVerification,
			)
		);
	}

	beginPinRetentionMaintenance(): boolean {
		if (this.hasActivePinWriters) return false;
		this.pinRetentionMaintenance = true;
		return true;
	}

	endPinRetentionMaintenance(): void {
		this.pinRetentionMaintenance = false;
	}

	processPendingPins(nowMs = Date.now()): void {
		this.pendingPinDirectoryEntriesReadLastPass = 0;
		if (this.diskPaused || this.pinReadersQuiescing || this.pinRetentionMaintenance) return;
		if (this.journalManifestValidation) {
			this.advanceJournalManifestValidation();
			return;
		}
		if (this.activePinTraversal) {
			this.advancePinTraversal(this.activePinTraversal);
			return;
		}
		if (this.activePinScans.size > 0) return;
		const incidentRoot = join(this.options.agentDir, "incidents");
		const incidentNames = this.discoverPendingPinDirectoryNames(incidentRoot);
		if (incidentNames.length === 0) return;
		let completedCursor = this.pendingPinCursor;
		for (const name of incidentNames) {
			const incidentDir = join(incidentRoot, name);
			const manifestPath = join(incidentDir, "journal-pin-manifest.json");
			const request = this.readJournalPinRequest(incidentDir);
			const sysdigRequest = this.readSysdigPinRequest(incidentDir);
			if (!request && !sysdigRequest) {
				const authority = this.readIncidentPinAuthority(incidentDir);
				if (authority) {
					this.persistPendingPinCursor(completedCursor);
					this.requestPin(authority.runId, incidentDir, authority.anchorWallTimeMs);
					return;
				}
			}
			if (!request && sysdigRequest) {
				this.persistPendingPinCursor(completedCursor);
				this.requestPin(sysdigRequest.runId, incidentDir, sysdigRequest.anchorWallTimeMs);
				return;
			}
			if (!request) {
				completedCursor = name;
				continue;
			}
			if (!sysdigRequest) {
				const authority = this.readIncidentPinAuthority(incidentDir);
				if (authority) {
					this.persistPendingPinCursor(completedCursor);
					this.requestPin(authority.runId, incidentDir, authority.anchorWallTimeMs);
					return;
				}
				this.writeProviderPinIncomplete(
					incidentDir,
					"sysdig",
					"legacy_journal_only_request_has_no_sysdig_capture_authority",
					request,
				);
			} else {
				try {
					if (
						sysdigRequest.runId === request.runId &&
						sysdigRequest.fromWallTimeMs === request.fromWallTimeMs &&
						sysdigRequest.throughWallTimeMs === request.throughWallTimeMs &&
						typeof sysdigRequest.ringBasePath === "string"
					) {
						if (!this.processSysdigPin(incidentDir, sysdigRequest, nowMs)) {
							this.persistPendingPinCursor(completedCursor);
							return;
						}
					} else {
						this.writeProviderPinIncomplete(
							incidentDir,
							"sysdig",
							"provider_request_binding_conflict",
							sysdigRequest,
						);
						this.writeProviderPinIncomplete(incidentDir, "journal", "provider_request_binding_conflict", request);
						completedCursor = name;
						continue;
					}
				} catch (error) {
					this.writeProviderPinIncomplete(
						incidentDir,
						"sysdig",
						`pin_processing_failed:${error instanceof Error ? error.message : String(error)}`,
						sysdigRequest,
					);
					this.persistPendingPinCursor(completedCursor);
					return;
				}
			}
			if (existsSync(manifestPath)) {
				const retentionProofPath = join(incidentDir, "journal-pin-retention-proof.json");
				if (this.retentionProofMatchesRequest(retentionProofPath, "journal", request)) {
					completedCursor = name;
					continue;
				}
				if (existsSync(retentionProofPath)) {
					this.quarantineInvalidProviderProof(incidentDir, "journal", retentionProofPath);
				}
				this.startJournalManifestValidation(incidentDir, manifestPath, request);
				if (this.journalManifestValidation) this.advanceJournalManifestValidation();
				this.persistPendingPinCursor(completedCursor);
				return;
			}
			if (nowMs < request.resolveAfterWallTimeMs) {
				completedCursor = name;
				continue;
			}
			const proofPath = join(incidentDir, "journal-pin-scan-proof.json");
			if (!existsSync(proofPath)) {
				this.startPinRangeScan(incidentDir, request);
				this.persistPendingPinCursor(completedCursor);
				return;
			}
			let scanProof: {
				state?: string;
				runId?: string;
				fromWallTimeMs?: number;
				throughWallTimeMs?: number;
				journalEntries?: string[];
			};
			try {
				scanProof = JSON.parse(readFileSync(proofPath, "utf8")) as typeof scanProof;
			} catch {
				completedCursor = name;
				continue;
			}
			if (
				scanProof.state !== "fixed_range_namespace_scan_complete" ||
				scanProof.runId !== request.runId ||
				scanProof.fromWallTimeMs !== request.fromWallTimeMs ||
				scanProof.throughWallTimeMs !== request.throughWallTimeMs ||
				!Array.isArray(scanProof.journalEntries)
			) {
				try {
					this.writeOwnedJson(join(incidentDir, "journal-pin-proof-invalid.json"), {
						version: 1,
						state: "invalid",
						runId: request.runId,
						reason: "scan_proof_did_not_match_request",
					});
				} catch {}
				completedCursor = name;
				continue;
			}
			let cursorBytes = 0;
			const scannedCursors = new Set<string>();
			let valid = scanProof.journalEntries.length <= PIN_CURSOR_MAX_COUNT;
			for (const cursor of scanProof.journalEntries) {
				if (typeof cursor !== "string") {
					valid = false;
					break;
				}
				cursorBytes += Buffer.byteLength(cursor);
				if (cursorBytes > PIN_CURSOR_MAX_BYTES) {
					valid = false;
					break;
				}
				scannedCursors.add(cursor);
			}
			if (!valid) {
				completedCursor = name;
				continue;
			}
			this.activePinTraversal = {
				incidentDir,
				request,
				scannedCursors,
				legacyEntriesScanned: 0,
				legacyBytesRead: 0,
				seenOccurrenceIdentities: new Set(),
				matches: [],
				memoryBytes: cursorBytes,
				phase: "segment-reading",
				linkIndex: 0,
				linked: new Map(),
			};
			this.advancePinTraversal(this.activePinTraversal);
			this.persistPendingPinCursor(completedCursor);
			return;
		}
		this.persistPendingPinCursor(completedCursor);
	}

	private advancePinTraversal(state: PinTraversal): void {
		if (state.phase === "segment-reading") {
			try {
				const page = this.withSegmentStoreRoot((root, store) =>
					store.queryRunWindowPageWithinRoot(root, {
						runId: state.request.runId,
						sourceId: SEGMENT_SOURCE_OCCURRENCE,
						fromObservedAtMs: state.request.fromWallTimeMs,
						throughObservedAtMs: state.request.throughWallTimeMs,
						maxRecords: SEGMENT_QUERY_PAGE_RECORDS,
						maxBytes: SEGMENT_QUERY_PAGE_BYTES,
						...(state.segmentCursor ? { after: state.segmentCursor } : {}),
					}),
				);
				for (const record of page.records) {
					let value: unknown;
					try {
						value = JSON.parse(record.payload.toString("utf8")) as unknown;
					} catch {
						this.failPinTraversal(state, "segment_occurrence_payload_invalid_json", {
							segmentId: record.locator.segmentId,
							ordinal: record.locator.ordinal,
						});
						return;
					}
					const match = this.parsePinOccurrence(
						value,
						this.segmentOccurrenceReference(record.locator),
						state.request.runId,
						record,
					);
					if (!match) {
						this.failPinTraversal(state, "segment_occurrence_schema_or_identity_invalid", {
							segmentId: record.locator.segmentId,
							ordinal: record.locator.ordinal,
						});
						return;
					}
					if (!this.addPinMatch(state, match)) return;
				}
				if (!page.complete) {
					if (!page.nextCursor) {
						this.failPinTraversal(state, "segment_occurrence_query_lost_continuation");
						return;
					}
					state.segmentCursor = page.nextCursor;
					return;
				}
				state.segmentCursor = undefined;
				state.phase = "legacy-reading";
				state.legacyDeadlineMs = Date.now() + PIN_SCAN_DEADLINE_MS;
				try {
					state.directory = opendirSync(join(this.root, "refs", "runs", sha256(state.request.runId)));
				} catch {
					state.phase = "linking";
				}
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOSPC") throw error;
				this.failPinTraversal(state, "segment_occurrence_query_failed_or_snapshot_stale", {
					error: error instanceof Error ? error.message : String(error),
				});
				return;
			}
		}
		if (state.phase === "legacy-reading") {
			const directory = state.directory;
			if (!directory) state.phase = "linking";
			else {
				let complete = false;
				for (let count = 0; count < PIN_REFERENCE_BATCH_COUNT; count += 1) {
					if (Date.now() > (state.legacyDeadlineMs ?? 0)) {
						this.failPinTraversal(state, "legacy_occurrence_scan_deadline_exceeded", {
							scannedEntries: state.legacyEntriesScanned,
							readBytes: state.legacyBytesRead,
						});
						return;
					}
					let entry: Dirent | null;
					try {
						entry = directory.readSync();
					} catch (error) {
						this.failPinTraversal(state, "legacy_occurrence_directory_read_failed", {
							error: error instanceof Error ? error.message : String(error),
						});
						return;
					}
					if (!entry) {
						complete = true;
						break;
					}
					state.legacyEntriesScanned += 1;
					if (state.legacyEntriesScanned > PENDING_ENTRY_MAX_COUNT) {
						this.failPinTraversal(state, "legacy_occurrence_scan_entry_bound_exceeded", {
							maxEntries: PENDING_ENTRY_MAX_COUNT,
						});
						return;
					}
					if (!/^seq-\d{20}-[0-9a-f]{64}\.json$/.test(entry.name)) continue;
					const path = join(directory.path, entry.name);
					try {
						const { value, bytes } = this.readStableLegacyOccurrence(path);
						state.legacyBytesRead += bytes;
						if (state.legacyBytesRead > PENDING_ENTRY_MAX_BYTES) {
							this.failPinTraversal(state, "legacy_occurrence_scan_byte_bound_exceeded", {
								maxBytes: PENDING_ENTRY_MAX_BYTES,
							});
							return;
						}
						const match = this.parsePinOccurrence(value, path, state.request.runId);
						if (!match) throw new Error("legacy_occurrence_schema_or_identity_invalid");
						const wall = segmentObservedAtMs(match.eventWallTimeMs);
						if (wall < state.request.fromWallTimeMs || wall > state.request.throughWallTimeMs) continue;
						if (!this.addPinMatch(state, match)) return;
					} catch (error) {
						this.failPinTraversal(state, "legacy_occurrence_reference_corrupt_or_unstable", {
							entry: entry.name,
							error: error instanceof Error ? error.message : String(error),
						});
						return;
					}
				}
				if (!complete) return;
				try {
					directory.closeSync();
				} catch {}
				state.directory = undefined;
				state.phase = "linking";
			}
		}
		if (state.phase === "linking" && !state.pinCasDir) {
			state.pinCasDir = join(state.incidentDir, "journal-pins", "cas");
			this.ensureDiskAdmission(256 * 1024);
			mkdirSync(state.pinCasDir, { recursive: true, mode: 0o700 });
		}
		const pinCasDir = state.pinCasDir;
		if (!pinCasDir) {
			this.activePinTraversal = undefined;
			return;
		}
		const pinTransaction = acquireIncidentCasTransaction(this.root);
		if (!pinTransaction) return;
		const artifactGenerationId = this.journalArtifactGenerationId(state.request);
		try {
			for (
				let count = 0;
				count < PIN_REFERENCE_BATCH_COUNT && state.linkIndex < state.matches.length;
				count += 1, state.linkIndex += 1
			) {
				const match = state.matches[state.linkIndex];
				if (!match || state.linked.has(match.cas.digest)) continue;
				const target = join(pinCasDir, `${match.cas.digest}.blob`);
				try {
					const sealedArtifact = this.materializeJournalPinArtifact(
						match.cas.path,
						target,
						match.cas.bytes,
						match.cas.digest,
						artifactGenerationId,
					);
					state.linked.set(match.cas.digest, { path: target, sealedArtifact });
				} catch {}
			}
		} finally {
			pinTransaction.release();
		}
		if (state.linkIndex < state.matches.length) return;
		fsyncDirectory(pinCasDir);
		const compactedCursors = new Set(state.matches.flatMap((match) => match.cursors));
		const allVerified =
			state.matches.every((match) => state.linked.has(match.cas.digest)) &&
			[...state.scannedCursors].every((cursor) => compactedCursors.has(cursor));
		this.activePinTraversal = undefined;
		if (!allVerified) {
			this.writeProviderPinIncomplete(
				state.incidentDir,
				"journal",
				"occurrence_or_cas_link_verification_failed",
				state.request,
			);
			return;
		}
		this.writeOwnedJson(join(state.incidentDir, "journal-pin-manifest.json"), {
			version: 2,
			state: "complete_through_requested_window",
			artifactGenerationId,
			runId: state.request.runId,
			fromWallTimeMs: state.request.fromWallTimeMs,
			throughWallTimeMs: state.request.throughWallTimeMs,
			occurrences: state.matches.map((match) => ({
				occurrenceReference: match.occurrenceReference,
				semanticFingerprint: match.semanticFingerprint,
				cursors: match.cursors,
				cas: match.cas,
				eventWallTimeMs: match.eventWallTimeMs,
				pinnedCasPath: state.linked.get(match.cas.digest)?.path ?? null,
				sealedArtifact: state.linked.get(match.cas.digest)?.sealedArtifact ?? null,
			})),
		});
		fsyncDirectory(state.incidentDir);
	}

	/** Read newly committed occurrence events for bounded live service observation. */
	readLiveRunEvents(input: {
		runId: string;
		cursor?: IncidentRecorderLiveRunEventsCursor;
	}): IncidentRecorderLiveRunEventsPage {
		const filter = {
			runId: input.runId,
			sourceId: SEGMENT_SOURCE_OCCURRENCE,
			fromObservedAtMs: 0,
			throughObservedAtMs: Number.MAX_SAFE_INTEGER,
		};
		const filterSha256 = sha256(canonicalJson(filter));
		const initialCursor = (): IncidentRecorderLiveRunEventsCursor => ({
			version: 1,
			runId: input.runId,
			filterSha256,
			segmentSequence: 0,
			ordinal: 0,
		});
		const cursor = input.cursor;
		if (!isCanonicalUuid(input.runId)) throw new Error("Invalid live run-event runId");
		if (
			cursor &&
			(cursor.version !== 1 ||
				cursor.runId !== input.runId ||
				!/^[0-9a-f]{64}$/.test(cursor.filterSha256) ||
				!Number.isSafeInteger(cursor.segmentSequence) ||
				cursor.segmentSequence < 0 ||
				!Number.isSafeInteger(cursor.ordinal) ||
				cursor.ordinal < 0)
		) {
			throw new Error("Invalid live run-event continuation cursor");
		}
		const previous = cursor ?? initialCursor();
		const incomplete = (
			reason: string,
			events: IncidentRecorderRunHistoryEvent[] = [],
		): IncidentRecorderLiveRunEventsPage => ({
			version: 1,
			runId: input.runId,
			state: "incomplete",
			events,
			cursor: previous,
			reason,
			scannedSegments: 0,
			scannedRecords: 0,
			scannedIndexBytes: 0,
		});
		try {
			const segmentRead = this.withSegmentStoreRoot((root, store) => {
				const snapshot = store.createReadSnapshot();
				if (
					previous.segmentSequence > snapshot.highWaterSegmentSequence ||
					(previous.segmentSequence === snapshot.highWaterSegmentSequence &&
						previous.ordinal > snapshot.highWaterOrdinal)
				) {
					return {
						kind: "incomplete" as const,
						page: incomplete("live_run_event_cursor_beyond_segment_frontier"),
					};
				}
				const after: IncidentRecorderSegmentQueryCursor | undefined = cursor
					? {
							version: 1,
							snapshotId: snapshot.id,
							generation: snapshot.generation,
							highWaterSegmentSequence: snapshot.highWaterSegmentSequence,
							highWaterOrdinal: snapshot.highWaterOrdinal,
							filterSha256: cursor.filterSha256,
							segmentSequence: cursor.segmentSequence,
							ordinal: cursor.ordinal,
						}
					: undefined;
				const page = store.queryRunWindowPageWithinRoot(root, {
					runId: input.runId,
					sourceId: SEGMENT_SOURCE_OCCURRENCE,
					fromObservedAtMs: 0,
					throughObservedAtMs: Number.MAX_SAFE_INTEGER,
					maxRecords: SEGMENT_QUERY_PAGE_RECORDS,
					maxBytes: SEGMENT_QUERY_PAGE_BYTES,
					maxScannedSegments: RUN_HISTORY_SEGMENT_PAGE_SCANNED_SEGMENTS,
					maxScannedRecords: RUN_HISTORY_SEGMENT_PAGE_SCANNED_RECORDS,
					maxScannedIndexBytes: RUN_HISTORY_SEGMENT_PAGE_SCANNED_INDEX_BYTES,
					...(after ? { after } : { readSnapshot: snapshot }),
				});
				return { kind: "page" as const, snapshot, page };
			});
			if (segmentRead.kind === "incomplete") return segmentRead.page;
			const { page } = segmentRead;
			const events: IncidentRecorderRunHistoryEvent[] = [];
			for (const record of page.records) {
				let value: unknown;
				try {
					value = JSON.parse(record.payload.toString("utf8")) as unknown;
				} catch {
					return incomplete("live_run_event_segment_payload_invalid_json", events);
				}
				const event = this.parseRunHistoryEvent(
					value,
					this.segmentOccurrenceReference(record.locator),
					input.runId,
					record,
				);
				if (!event) return incomplete("live_run_event_segment_payload_invalid", events);
				events.push(event);
			}
			const frontier = page.nextCursor ?? {
				segmentSequence: page.snapshot.highWaterSegmentSequence,
				ordinal: page.snapshot.highWaterOrdinal,
			};
			const nextCursor: IncidentRecorderLiveRunEventsCursor = {
				version: 1,
				runId: input.runId,
				filterSha256: page.snapshot.filterSha256,
				segmentSequence: frontier.segmentSequence,
				ordinal: frontier.ordinal,
			};
			if (
				!page.complete &&
				frontier.segmentSequence === previous.segmentSequence &&
				frontier.ordinal === previous.ordinal
			) {
				return {
					version: 1,
					runId: input.runId,
					state: "incomplete",
					events,
					cursor: previous,
					reason: "live_run_event_query_made_no_progress",
					scannedSegments: page.scannedSegments,
					scannedRecords: page.scannedRecords,
					scannedIndexBytes: page.scannedIndexBytes,
				};
			}
			return {
				version: 1,
				runId: input.runId,
				state: page.complete ? "complete" : "pending",
				events,
				cursor: nextCursor,
				scannedSegments: page.scannedSegments,
				scannedRecords: page.scannedRecords,
				scannedIndexBytes: page.scannedIndexBytes,
			};
		} catch (error) {
			return incomplete(
				`live_run_event_query_unavailable:${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}

	/** Read bounded, committed gap evidence for live finalization-barrier observation. */
	readLiveRunGaps(input: {
		runId: string;
		cursor?: IncidentRecorderLiveRunEventsCursor;
	}): IncidentRecorderLiveRunGapsPage {
		if (input.runId !== "__recorder__" && !isCanonicalUuid(input.runId)) {
			throw new Error("Invalid live run-gap runId");
		}
		const filter = {
			runId: input.runId,
			sourceId: SEGMENT_SOURCE_GAP,
			fromObservedAtMs: 0,
			throughObservedAtMs: Number.MAX_SAFE_INTEGER,
		};
		const filterSha256 = sha256(canonicalJson(filter));
		const initialCursor = (): IncidentRecorderLiveRunEventsCursor => ({
			version: 1,
			runId: input.runId,
			filterSha256,
			segmentSequence: 0,
			ordinal: 0,
		});
		const cursor = input.cursor;
		if (
			cursor &&
			(cursor.version !== 1 ||
				cursor.runId !== input.runId ||
				!/^[0-9a-f]{64}$/.test(cursor.filterSha256) ||
				!Number.isSafeInteger(cursor.segmentSequence) ||
				cursor.segmentSequence < 0 ||
				!Number.isSafeInteger(cursor.ordinal) ||
				cursor.ordinal < 0)
		) {
			throw new Error("Invalid live run-gap continuation cursor");
		}
		const previous = cursor ?? initialCursor();
		const incomplete = (
			reason: string,
			gaps: IncidentRecorderLiveRunGap[] = [],
		): IncidentRecorderLiveRunGapsPage => ({
			version: 1,
			runId: input.runId,
			state: "incomplete",
			gaps,
			cursor: previous,
			reason,
			scannedSegments: 0,
			scannedRecords: 0,
			scannedIndexBytes: 0,
		});
		try {
			const segmentRead = this.withSegmentStoreRoot((root, store) => {
				const snapshot = store.createReadSnapshot();
				if (
					previous.segmentSequence > snapshot.highWaterSegmentSequence ||
					(previous.segmentSequence === snapshot.highWaterSegmentSequence &&
						previous.ordinal > snapshot.highWaterOrdinal)
				) {
					return { kind: "incomplete" as const, page: incomplete("live_run_gap_cursor_beyond_segment_frontier") };
				}
				const after: IncidentRecorderSegmentQueryCursor | undefined = cursor
					? {
							version: 1,
							snapshotId: snapshot.id,
							generation: snapshot.generation,
							highWaterSegmentSequence: snapshot.highWaterSegmentSequence,
							highWaterOrdinal: snapshot.highWaterOrdinal,
							filterSha256: cursor.filterSha256,
							segmentSequence: cursor.segmentSequence,
							ordinal: cursor.ordinal,
						}
					: undefined;
				const page = store.queryRunWindowPageWithinRoot(root, {
					runId: input.runId,
					sourceId: SEGMENT_SOURCE_GAP,
					fromObservedAtMs: 0,
					throughObservedAtMs: Number.MAX_SAFE_INTEGER,
					maxRecords: SEGMENT_QUERY_PAGE_RECORDS,
					maxBytes: SEGMENT_QUERY_PAGE_BYTES,
					maxScannedSegments: RUN_HISTORY_SEGMENT_PAGE_SCANNED_SEGMENTS,
					maxScannedRecords: RUN_HISTORY_SEGMENT_PAGE_SCANNED_RECORDS,
					maxScannedIndexBytes: RUN_HISTORY_SEGMENT_PAGE_SCANNED_INDEX_BYTES,
					...(after ? { after } : { readSnapshot: snapshot }),
				});
				return { kind: "page" as const, snapshot, page };
			});
			if (segmentRead.kind === "incomplete") return segmentRead.page;
			const { page } = segmentRead;
			const gaps: IncidentRecorderLiveRunGap[] = [];
			for (const record of page.records) {
				let value: unknown;
				try {
					value = JSON.parse(record.payload.toString("utf8")) as unknown;
				} catch {
					return incomplete("live_run_gap_segment_payload_invalid_json", gaps);
				}
				if (!isRecordObject(value) || value.version !== 1 || value.state !== "gap_or_uncertainty") {
					return incomplete("live_run_gap_segment_payload_invalid", gaps);
				}
				const evidence = value.evidence;
				if (!isRecordObject(evidence)) return incomplete("live_run_gap_segment_payload_invalid", gaps);
				const serializedEvidence = JSON.stringify(evidence);
				if (
					typeof serializedEvidence !== "string" ||
					sha256(serializedEvidence) !== record.metadata.gapIdentity ||
					record.metadata.version !== 1 ||
					record.metadata.state !== "gap_or_uncertainty" ||
					record.idempotencyKey !== `gap:${sha256(serializedEvidence)}`
				) {
					return incomplete("live_run_gap_segment_identity_invalid", gaps);
				}
				gaps.push({
					occurrenceReference: this.segmentOccurrenceReference(record.locator),
					evidence: JSON.parse(serializedEvidence) as Record<string, unknown>,
				});
			}
			const frontier = page.nextCursor ?? {
				segmentSequence: page.snapshot.highWaterSegmentSequence,
				ordinal: page.snapshot.highWaterOrdinal,
			};
			const nextCursor: IncidentRecorderLiveRunEventsCursor = {
				version: 1,
				runId: input.runId,
				filterSha256: page.snapshot.filterSha256,
				segmentSequence: frontier.segmentSequence,
				ordinal: frontier.ordinal,
			};
			if (
				!page.complete &&
				frontier.segmentSequence === previous.segmentSequence &&
				frontier.ordinal === previous.ordinal
			) {
				return {
					version: 1,
					runId: input.runId,
					state: "incomplete",
					gaps,
					cursor: previous,
					reason: "live_run_gap_query_made_no_progress",
					scannedSegments: page.scannedSegments,
					scannedRecords: page.scannedRecords,
					scannedIndexBytes: page.scannedIndexBytes,
				};
			}
			return {
				version: 1,
				runId: input.runId,
				state: page.complete ? "complete" : "pending",
				gaps,
				cursor: nextCursor,
				scannedSegments: page.scannedSegments,
				scannedRecords: page.scannedRecords,
				scannedIndexBytes: page.scannedIndexBytes,
			};
		} catch (error) {
			return incomplete(`live_run_gap_query_unavailable:${error instanceof Error ? error.message : String(error)}`);
		}
	}
}
