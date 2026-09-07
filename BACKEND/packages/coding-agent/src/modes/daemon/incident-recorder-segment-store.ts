import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import {
	type BigIntStats,
	chmodSync,
	closeSync,
	constants,
	fstatSync,
	fsyncSync,
	ftruncateSync,
	linkSync,
	lstatSync,
	mkdirSync,
	opendirSync,
	openSync,
	readFileSync,
	readlinkSync,
	readSync,
	realpathSync,
	renameSync,
	statfsSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import type {
	IncidentCasFileMutation,
	IncidentCasRelativePath,
	IncidentCasRootMutation,
} from "./incident-recorder-cas-transaction.js";

const FORMAT_VERSION = 2;
const FRAME_MAGIC = Buffer.from("GRM2", "ascii");
const FRAME_END_MAGIC = Buffer.from("GEND", "ascii");
const FRAME_PREFIX_BYTES = 16;
const FRAME_CHECKSUM_BYTES = 32;
const FRAME_TRAILER_BYTES = 8;
const FRAME_OVERHEAD_BYTES = FRAME_PREFIX_BYTES + FRAME_CHECKSUM_BYTES + FRAME_TRAILER_BYTES;
const MEBIBYTE = 1024 * 1024;
const FORMAT_MAX_PAYLOAD_BYTES = 4 * MEBIBYTE;
const FORMAT_MAX_METADATA_BYTES = 64 * 1024;
const FORMAT_MAX_RECORD_FRAME_BYTES = 5 * MEBIBYTE;
const FORMAT_MAX_INDEX_FRAME_BYTES = 16 * MEBIBYTE;
const FORMAT_MAX_FOOTER_FRAME_BYTES = 64 * 1024;
const FORMAT_MAX_SEGMENT_DATA_BYTES = 64 * MEBIBYTE;
const FORMAT_MAX_ACTIVE_BYTES = 96 * MEBIBYTE;
const FORMAT_MAX_RECORDS = 16_384;
const FORMAT_MAX_GAPS = 128;
const RECOVERY_READ_CHUNK_BYTES = 64 * 1024;
const DEFAULT_MAX_SEGMENT_BYTES = 64 * MEBIBYTE;
const DEFAULT_MAX_SEGMENT_AGE_MS = 5 * 60 * 1000;
const DEFAULT_MAX_RECORDS_PER_SEGMENT = FORMAT_MAX_RECORDS;
const DEFAULT_MAX_RECORD_BYTES = FORMAT_MAX_PAYLOAD_BYTES;
const DEFAULT_MAX_METADATA_BYTES = FORMAT_MAX_METADATA_BYTES;
const DEFAULT_MAX_STARTUP_ENTRIES = 8_192;
const DEFAULT_MAX_STARTUP_CATALOG_BYTES = 64 * MEBIBYTE;
const DEFAULT_MAX_QUERY_RECORDS = 4_096;
const DEFAULT_MAX_QUERY_BYTES = 32 * MEBIBYTE;
const DEFAULT_MAX_QUERY_SCANNED_SEGMENTS = 16;
const DEFAULT_MAX_QUERY_SCANNED_RECORDS = 4_096;
const DEFAULT_MAX_QUERY_SCANNED_GAPS = 4_096;
const DEFAULT_MAX_QUERY_SCANNED_INDEX_BYTES = 32 * MEBIBYTE;
const MAX_ACTIVE_READ_LEASES = 8;
const DEFAULT_MAX_IDEMPOTENCY_LOOKUP_SEGMENTS = DEFAULT_MAX_STARTUP_ENTRIES;
const DEFAULT_MAX_IDEMPOTENCY_LOOKUP_RECORDS = 1_048_576;
const DEFAULT_MAX_PRUNE_SEGMENTS = 16;
const DEFAULT_MAX_PRUNE_BYTES = 64 * MEBIBYTE;
const MAX_ACTIVE_PRUNE_CURSORS = 32;
const PRUNE_CURSOR_TTL_MS = 5 * 60 * 1000;
const PROC_SUPER_MAGIC = 0x9fa0n;
const PROC_FDINFO_MAX_BYTES = 4 * 1024;
const PROC_ROOT_PATH = "/proc";
const PROC_THREAD_SELF_PATH = "/proc/thread-self";
const PROC_THREAD_FD_DIRECTORY = "/proc/thread-self/fd";
const PROC_THREAD_FDINFO_DIRECTORY = "/proc/thread-self/fdinfo";
const PROC_THREAD_SELF_TARGET_PATTERN = /^[1-9][0-9]*\/task\/[1-9][0-9]*$/;
const MAX_UNSIGNED_64 = (1n << 64n) - 1n;
const OWNER_FILE_NAME = ".writer-owner.json";
const IDEMPOTENCY_BLOOM_BYTES = 8 * 1024;
const IDEMPOTENCY_BLOOM_HASHES = 7;

export const INCIDENT_RECORDER_SEGMENT_STORE_DEFAULTS = Object.freeze({
	maxSegmentBytes: DEFAULT_MAX_SEGMENT_BYTES,
	maxSegmentAgeMs: DEFAULT_MAX_SEGMENT_AGE_MS,
	maxRecordsPerSegment: DEFAULT_MAX_RECORDS_PER_SEGMENT,
	maxRecordBytes: DEFAULT_MAX_RECORD_BYTES,
	maxMetadataBytes: DEFAULT_MAX_METADATA_BYTES,
	maxStartupEntries: DEFAULT_MAX_STARTUP_ENTRIES,
	maxStartupCatalogBytes: DEFAULT_MAX_STARTUP_CATALOG_BYTES,
	maxQueryRecords: DEFAULT_MAX_QUERY_RECORDS,
	maxQueryBytes: DEFAULT_MAX_QUERY_BYTES,
});

enum FrameType {
	Header = 1,
	Record = 2,
	RecoveryGap = 3,
	Index = 4,
	Footer = 5,
}

export type IncidentRecorderSegmentJsonValue =
	| null
	| boolean
	| number
	| string
	| IncidentRecorderSegmentJsonValue[]
	| { [key: string]: IncidentRecorderSegmentJsonValue };

export type IncidentRecorderSegmentMetadata = { [key: string]: IncidentRecorderSegmentJsonValue };

export interface IncidentRecorderSegmentLocator {
	version: 1;
	segmentId: string;
	segmentSequence: number;
	ordinal: number;
	offset: number;
	frameBytes: number;
	payloadBytes: number;
	payloadSha256: string;
}

export interface IncidentRecorderSegmentAppendInput {
	idempotencyKey?: string;
	runId: string;
	sourceId: string;
	observedAtMs: number;
	order: string;
	metadata: IncidentRecorderSegmentMetadata;
	payload: Uint8Array;
}

export interface IncidentRecorderSegmentAppendResult {
	status: "appended" | "existing";
	locator: IncidentRecorderSegmentLocator;
}

export interface IncidentRecorderSegmentRecord extends IncidentRecorderSegmentAppendInput {
	locator: IncidentRecorderSegmentLocator;
	payload: Buffer;
}

export interface IncidentRecorderSegmentQuery {
	runId: string;
	sourceId?: string;
	fromObservedAtMs: number;
	throughObservedAtMs: number;
}

export interface IncidentRecorderSegmentQueryCursor {
	version: 1;
	snapshotId: string;
	generation: number;
	highWaterSegmentSequence: number;
	highWaterOrdinal: number;
	filterSha256: string;
	segmentSequence: number;
	ordinal: number;
}

export interface IncidentRecorderSegmentQuerySnapshot {
	version: 1;
	id: string;
	generation: number;
	highWaterSegmentSequence: number;
	highWaterOrdinal: number;
	filterSha256: string;
}

/**
 * A filter-independent, immutable view of the records that existed when it was
 * created. Callers may reuse it across differently filtered page queries.
 */
export interface IncidentRecorderSegmentReadSnapshot {
	readonly version: 1;
	readonly id: string;
	readonly generation: number;
	readonly highWaterSegmentSequence: number;
	readonly highWaterOrdinal: number;
}

/**
 * A process-local retention lease for one immutable read frontier. The exact
 * frozen object must remain registered with the store for every leased query.
 */
export interface IncidentRecorderSegmentReadLease {
	readonly version: 1;
	readonly storeInstanceId: string;
	readonly token: string;
	readonly acquiredAtMs: number;
	readonly expiresAtMs: number;
	readonly highWaterSegmentSequence: number;
	readonly highWaterOrdinal: number;
}

export interface IncidentRecorderSegmentPageQuery extends IncidentRecorderSegmentQuery {
	after?: IncidentRecorderSegmentQueryCursor;
	readSnapshot?: IncidentRecorderSegmentReadSnapshot;
	readLease?: IncidentRecorderSegmentReadLease;
	maxRecords?: number;
	maxBytes?: number;
	maxScannedSegments?: number;
	maxScannedRecords?: number;
	maxScannedIndexBytes?: number;
}

export interface IncidentRecorderSegmentQueryPage {
	records: IncidentRecorderSegmentRecord[];
	complete: boolean;
	nextCursor?: IncidentRecorderSegmentQueryCursor;
	selectedFrameBytes: number;
	scannedSegments: number;
	scannedRecords: number;
	scannedIndexBytes: number;
	snapshot: IncidentRecorderSegmentQuerySnapshot;
}

export type IncidentRecorderSegmentRecoveryGapQueryCursor = IncidentRecorderSegmentQueryCursor;

export interface IncidentRecorderSegmentRecoveryGapPageQuery {
	after?: IncidentRecorderSegmentRecoveryGapQueryCursor;
	readSnapshot?: IncidentRecorderSegmentReadSnapshot;
	readLease?: IncidentRecorderSegmentReadLease;
	maxGaps?: number;
	maxBytes?: number;
	maxScannedSegments?: number;
	maxScannedGaps?: number;
	maxScannedIndexBytes?: number;
}

export interface IncidentRecorderSegmentRecoveryGapQueryPage {
	gaps: IncidentRecorderSegmentRecoveryGap[];
	complete: boolean;
	nextCursor?: IncidentRecorderSegmentRecoveryGapQueryCursor;
	selectedBytes: number;
	scannedSegments: number;
	scannedGaps: number;
	scannedIndexBytes: number;
	snapshot: IncidentRecorderSegmentQuerySnapshot;
}

export interface IncidentRecorderSegmentRecoveryGap {
	version: 1;
	segmentId: string;
	segmentSequence: number;
	ordinal: number;
	reason: "invalid_or_torn_active_tail";
	observedAtMs: number;
	invalidOffset: number;
	discardedBytes: number;
	discardedSha256: string;
}

export interface IncidentRecorderSegmentOwnerIdentity {
	pid: number;
	startTime: string;
	bootId: string;
}

export type IncidentRecorderSegmentFaultPoint =
	| "after-header-fsync-before-publish"
	| "after-record-write-before-fsync"
	| "after-recovery-gap-fsync-before-truncate"
	| "after-sealed-link-before-directory-fsync"
	| "before-prune-unlink-after-verify"
	| "after-prune-unlink-before-directory-fsync"
	| "after-prune-index-handle-close"
	| "after-prune-verifier-failure-handle-close"
	| "after-recovery-catalog-directory-close"
	| "after-recovery-owner-claim-handle-close"
	| "after-recovery-root-directory-close"
	| "after-owner-claim-handle-close"
	| "before-close-root-accounting"
	| "after-poison-active-handle-close"
	| "after-prune-protected-handle-close";

export interface IncidentRecorderSegmentDurableWrite {
	eventId: string;
	accountingSequence: number;
	kind: "segment-created" | "record" | "recovery-gap" | "sealed" | "pruned";
	segmentId: string;
	path: string;
	previousPath?: string;
	entryChange: "published" | "same-inode-growth" | "same-inode-move" | "removed";
	entryDelta: -1 | 0 | 1;
	inodeDelta: -1 | 0 | 1;
	deviceId: string;
	inodeId: string;
	linkCount: number;
	previousLogicalBytes: number;
	previousAllocatedBytes: number;
	logicalBytes: number;
	allocatedBytes: number;
	parentEffects: IncidentRecorderSegmentParentDirectoryEffect[];
	reconciliation: "apply-by-event-id-then-reconcile-dev-inode";
}

export interface IncidentRecorderSegmentParentDirectoryEffect {
	path: string;
	deviceId: string;
	inodeId: string;
	beforeAllocatedBytes: number;
	afterAllocatedBytes: number;
	beforeLogicalBytes: number;
	afterLogicalBytes: number;
}

export interface IncidentRecorderSegmentOpenStorageEntry {
	path: string;
	kind: "root-directory" | "active-directory" | "sealed-directory" | "owner-file";
	createdByOpen: boolean;
	deviceId: string;
	inodeId: string;
	linkCount: number;
	logicalBytes: number;
	allocatedBytes: number;
}

export interface IncidentRecorderSegmentOpenPlan {
	version: 1;
	token: string;
	directory: string;
	stateFingerprint: string;
	peakAdditionalBytes: number;
	peakAdditionalEntries: number;
	peakAdditionalInodes: number;
	mayRecoverActiveTail: boolean;
}

export interface IncidentRecorderSegmentRootOpenStorageEstimate {
	peakAdditionalBytes: number;
	peakAdditionalEntries: number;
	peakAdditionalInodes: number;
	mayRecoverActiveTail: boolean;
}

export interface IncidentRecorderSegmentOpenResult {
	phase: "opened" | "failed" | "closed";
	complete: boolean;
	entries: readonly IncidentRecorderSegmentOpenStorageEntry[];
	parentEffects: readonly IncidentRecorderSegmentParentDirectoryEffect[];
	reconciliation: "incremental-complete" | "full-dev-inode-required";
	error?: string;
}

export interface IncidentRecorderSegmentPruneProtectionBuilding {
	state: "building";
	generation: number;
}

export interface IncidentRecorderSegmentPruneProtectionComplete {
	state: "complete";
	generation: number;
	protectedRunIds: readonly string[];
	fingerprint: string;
}

export type IncidentRecorderSegmentPruneProtection =
	| IncidentRecorderSegmentPruneProtectionBuilding
	| IncidentRecorderSegmentPruneProtectionComplete;

export interface IncidentRecorderSegmentPruneCursor {
	readonly version: 1;
	readonly sessionId: string;
	readonly storeInstanceId: string;
	readonly highWaterSegmentSequence: number;
	readonly filterSha256: string;
	readonly segmentSequence: number;
}

export interface IncidentRecorderSegmentAppendStorageEstimate {
	recordFrameBytes: number;
	headerFrameBytes: number;
	sealBeforeBytes: number;
	sealAfterBytes: number;
	peakAdditionalBytes: number;
	peakAdditionalAllocatedBytes: number;
	peakAdditionalEntries: number;
	peakAdditionalInodes: number;
	willSealBeforeAppend: boolean;
	willSealAfterAppend: boolean;
	willCreateSegment: boolean;
}

export interface IncidentRecorderSegmentAppendPlan {
	version: 1;
	token: string;
	estimate: IncidentRecorderSegmentAppendStorageEstimate;
}

interface FrozenAppendPlan {
	publicPlan: IncidentRecorderSegmentAppendPlan;
	input: IncidentRecorderSegmentAppendInput;
	sampledNow: number;
	stateRevision: number;
	plannedSegmentId?: string;
}

export interface IncidentRecorderSegmentStoreOptions {
	directory: string;
	maxSegmentBytes?: number;
	maxSegmentAgeMs?: number;
	maxRecordsPerSegment?: number;
	maxRecordBytes?: number;
	maxMetadataBytes?: number;
	maxFooterBytes?: number;
	maxRecoveryBytes?: number;
	maxRecoveryFrames?: number;
	maxStartupSegments?: number;
	maxStartupEntries?: number;
	maxStartupCatalogBytes?: number;
	maxQueryRecords?: number;
	maxQueryBytes?: number;
	maxIdempotencyLookupSegments?: number;
	maxIdempotencyLookupRecords?: number;
	now?: () => number;
	createSegmentId?: () => string;
	onDurableWrite?: (event: IncidentRecorderSegmentDurableWrite) => void;
	onIndexRead?: (segmentId: string) => void;
	onRecoveryRead?: (bytes: number) => void;
	onPruneExpiryCleanupDiagnostic?: (diagnostic: IncidentRecorderPruneExpiryCleanupDiagnostic) => void;
	faultInjector?: (point: IncidentRecorderSegmentFaultPoint) => void;
	ownerIdentity?: IncidentRecorderSegmentOwnerIdentity;
	isOwnerAlive?: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean;
	openPlan?: IncidentRecorderSegmentOpenPlan;
	onOpenAdmission?: (plan: IncidentRecorderSegmentOpenPlan) => void;
	onOpenStorageResult?: (result: IncidentRecorderSegmentOpenResult) => void;
}

/**
 * Options for a segment store whose filesystem authority is supplied by a
 * recorder CAS root. `directory` is deliberately a list of relative path
 * components; the root capability itself is never retained by the store.
 */
export interface IncidentRecorderSegmentStoreWithinRootOptions
	extends Omit<IncidentRecorderSegmentStoreOptions, "directory" | "openPlan"> {
	directory: readonly string[];
}

export type IncidentRecorderSegmentRootReceipt =
	| {
			readonly kind: "open";
			readonly sequence: number;
			readonly result: IncidentRecorderSegmentOpenResult;
	  }
	| {
			readonly kind: "durable";
			readonly sequence: number;
			readonly event: IncidentRecorderSegmentDurableWrite;
	  };

export interface IncidentRecorderSegmentStoreStats {
	activeSegments: 0 | 1;
	sealedSegments: number;
	corruptSegments: number;
	records: number;
	recoveryGaps: number;
}

export interface IncidentRecorderSegmentPruneInput {
	sealedBeforeMs: number;
	protection: IncidentRecorderSegmentPruneProtectionComplete;
	protectedSegmentIds?: ReadonlySet<string>;
	maxSegments?: number;
	maxDeletes?: number;
	maxBytes?: number;
	continuation?: IncidentRecorderSegmentPruneCursor;
}

export interface IncidentRecorderSegmentPruneResult {
	deletedSegmentIds: string[];
	corruptSegmentIds: string[];
	examinedSegments: number;
	deletedBytes: number;
	blockedByReadSnapshot?: boolean;
	locatorsInvalidated: boolean;
	requiresFullReconciliation: boolean;
	moreWork: boolean;
	continuation?: IncidentRecorderSegmentPruneCursor;
	requiredBytes?: number;
}

export type IncidentRecorderSegmentPruneMutationResult = Readonly<
	Omit<IncidentRecorderSegmentPruneResult, "deletedSegmentIds" | "corruptSegmentIds"> & {
		readonly deletedSegmentIds: readonly string[];
		readonly corruptSegmentIds: readonly string[];
	}
>;

export type IncidentRecorderSegmentDirectoryDurability = "unknown" | "confirmed";

export interface IncidentRecorderPruneExpiryCleanupDiagnostic {
	readonly kind: "prune-cursor-expiry-cleanup-failed";
	readonly cursor: IncidentRecorderSegmentPruneCursor;
	readonly scopeFingerprint: string;
	readonly error: unknown;
}

export interface IncidentRecorderSegmentRecoveryPruneOptions extends IncidentRecorderSegmentPruneInput {
	directory: string;
	externalWriterExcluded: true;
	maxStartupEntries?: number;
	maxStartupCatalogBytes?: number;
	isOwnerAlive?: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean;
	onOwnershipTransitionCheck?: () => void;
	onPruneExpiryCleanupDiagnostic?: (diagnostic: IncidentRecorderPruneExpiryCleanupDiagnostic) => void;
	faultInjector?: (point: IncidentRecorderSegmentFaultPoint) => void;
}

interface SegmentHeader {
	version: 2;
	kind: "segment-header";
	segmentId: string;
	segmentSequence: number;
	createdAtMs: number;
}

interface SegmentIndexEntry extends IncidentRecorderSegmentLocator {
	idempotencyKey: string;
	canonicalContentSha256: string;
	runId: string;
	sourceId: string;
	observedAtMs: number;
	order: string;
}

interface SegmentIndexDocument {
	version: 2;
	kind: "segment-index";
	segmentId: string;
	segmentSequence: number;
	records: SegmentIndexEntry[];
	recoveryGaps: IncidentRecorderSegmentRecoveryGap[];
}

interface SegmentFooter {
	version: 2;
	kind: "sealed-footer";
	segmentId: string;
	segmentSequence: number;
	createdAtMs: number;
	sealedAtMs: number;
	reason: string;
	recordCount: number;
	gapCount: number;
	minObservedAtMs: number | null;
	maxObservedAtMs: number | null;
	indexOffset: number;
	indexFrameBytes: number;
	indexSha256: string;
	contentBytes: number;
	contentSha256: string;
	idempotencyBloomBase64: string;
}

interface RecordEnvelope {
	version: 2;
	kind: "record";
	idempotencyKey: string;
	canonicalContentSha256: string;
	runId: string;
	sourceId: string;
	observedAtMs: number;
	order: string;
	metadata: IncidentRecorderSegmentMetadata;
	payloadBytes: number;
	payloadSha256: string;
}

interface ParsedFrame {
	type: FrameType;
	ordinal: number;
	content: Buffer;
	frameBytes: number;
	bytes: Buffer;
}

interface SegmentSummary {
	header: SegmentHeader;
	footer: SegmentFooter;
	path: string;
	fileBytes: number;
}

interface CorruptSegment {
	segmentId: string;
	path: string;
	reason: string;
	summary?: SegmentSummary;
}

interface ActiveSegment {
	header: SegmentHeader;
	path: string;
	identity: StorageState;
	size: number;
	nextOrdinal: number;
	records: SegmentIndexEntry[];
	recoveryGaps: IncidentRecorderSegmentRecoveryGap[];
}

interface OwnerClaim extends IncidentRecorderSegmentOwnerIdentity {
	version: 1;
	nonce: string;
}

interface PruneCursorCapability {
	readonly cursor: IncidentRecorderSegmentPruneCursor;
	readonly scopeFingerprint: string;
	readonly scopeLease?: RecoveryPruneStorageScopeLease;
	readonly expiresAtMs: number;
	readonly cleanupTimer: ReturnType<typeof setTimeout>;
	readonly expiryDiagnosticSink?: (diagnostic: IncidentRecorderPruneExpiryCleanupDiagnostic) => void;
}

interface IncidentRecorderSegmentStoreRootConstruction {
	root: IncidentCasRootMutation;
	directory: readonly string[];
}

const RECOVERY_PRUNE_CURSOR_CAPABILITIES = new Map<string, PruneCursorCapability>();
const PRUNE_CURSOR_ASYNC_EXPIRY_FAILURES = new WeakMap<
	IncidentRecorderSegmentPruneCursor,
	IncidentRecorderPrimaryFailure
>();

class InvalidFrameError extends Error {}

class SegmentCatalogBudgetExceededError extends Error {}

class IncidentRecorderIndexObserverError extends Error {
	constructor(cause: unknown) {
		super(`incident recorder index observer failed: ${errorText(cause)}`, { cause });
		this.name = "IncidentRecorderIndexObserverError";
	}
}

class IncidentRecorderSegmentUnlinkMutationError extends Error {
	readonly previousAllocation: StorageState;
	readonly directoryDurability: IncidentRecorderSegmentDirectoryDurability;

	constructor(
		cause: unknown,
		previousAllocation: StorageState,
		directoryDurability: IncidentRecorderSegmentDirectoryDurability,
	) {
		super(`sealed segment was unlinked but post-commit validation failed: ${errorText(cause)}`, { cause });
		this.name = "IncidentRecorderSegmentUnlinkMutationError";
		this.previousAllocation = previousAllocation;
		this.directoryDurability = directoryDurability;
	}
}

export class IncidentRecorderDescriptorCleanupError extends Error {
	readonly primaryError: unknown;
	readonly cleanupErrors: readonly unknown[];

	constructor(primaryError: unknown, cleanupErrors: readonly unknown[]) {
		super(`${errorText(primaryError)}; descriptor cleanup also failed: ${cleanupErrors.map(errorText).join("; ")}`, {
			cause: primaryError,
		});
		this.name = "IncidentRecorderDescriptorCleanupError";
		this.primaryError = primaryError;
		this.cleanupErrors = Object.freeze([...cleanupErrors]);
	}
}

export class IncidentRecorderSegmentPruneMutationError extends Error {
	readonly result: IncidentRecorderSegmentPruneMutationResult;
	readonly directoryDurability: IncidentRecorderSegmentDirectoryDurability;

	constructor(input: {
		cause: unknown;
		result: IncidentRecorderSegmentPruneMutationResult;
		directoryDurability: IncidentRecorderSegmentDirectoryDurability;
	}) {
		super(
			`incident recorder prune mutated storage and requires reconciliation; directory durability is ${input.directoryDurability}: ${errorText(input.cause)}`,
			{ cause: input.cause },
		);
		this.name = "IncidentRecorderSegmentPruneMutationError";
		this.result = input.result;
		this.directoryDurability = input.directoryDurability;
	}
}

function pruneMutationErrorIn(error: unknown): IncidentRecorderSegmentPruneMutationError | undefined {
	let candidate = error;
	const visited = new Set<unknown>();
	while (candidate instanceof IncidentRecorderDescriptorCleanupError && !visited.has(candidate)) {
		visited.add(candidate);
		candidate = candidate.primaryError;
	}
	return candidate instanceof IncidentRecorderSegmentPruneMutationError ? candidate : undefined;
}

function unlinkMutationErrorIn(error: unknown): IncidentRecorderSegmentUnlinkMutationError | undefined {
	let candidate = error;
	const visited = new Set<unknown>();
	while (candidate instanceof IncidentRecorderDescriptorCleanupError && !visited.has(candidate)) {
		visited.add(candidate);
		candidate = candidate.primaryError;
	}
	return candidate instanceof IncidentRecorderSegmentUnlinkMutationError ? candidate : undefined;
}

function indexObserverErrorIn(error: unknown): IncidentRecorderIndexObserverError | undefined {
	let candidate = error;
	const visited = new Set<unknown>();
	while (candidate instanceof IncidentRecorderDescriptorCleanupError && !visited.has(candidate)) {
		visited.add(candidate);
		candidate = candidate.primaryError;
	}
	return candidate instanceof IncidentRecorderIndexObserverError ? candidate : undefined;
}

export class IncidentRecorderSegmentStorePoisonedError extends Error {
	constructor(cause: unknown) {
		super(`incident recorder segment store is poisoned: ${errorText(cause)}`, { cause });
		this.name = "IncidentRecorderSegmentStorePoisonedError";
	}
}

export type IncidentRecorderSegmentPageBudgetFrameKind = "record-index" | "recovery-gap-index";

export class IncidentRecorderSegmentPageBudgetExceededError extends Error {
	readonly segmentId: string;
	readonly frameKind: IncidentRecorderSegmentPageBudgetFrameKind;
	readonly requiredBytes: number;
	readonly configuredBytes: number;

	constructor(input: {
		segmentId: string;
		frameKind: IncidentRecorderSegmentPageBudgetFrameKind;
		requiredBytes: number;
		configuredBytes: number;
	}) {
		super(
			`segment ${input.segmentId} index frame requires ${String(input.requiredBytes)} bytes but maxScannedIndexBytes is ${String(input.configuredBytes)}`,
		);
		this.name = "IncidentRecorderSegmentPageBudgetExceededError";
		this.segmentId = input.segmentId;
		this.frameKind = input.frameKind;
		this.requiredBytes = input.requiredBytes;
		this.configuredBytes = input.configuredBytes;
	}
}

interface IncidentRecorderPrimaryFailure {
	readonly error: unknown;
}

type IncidentRecorderOutcome<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly failure: IncidentRecorderPrimaryFailure };

function captureIncidentRecorderOutcome<T>(operation: () => T): IncidentRecorderOutcome<T> {
	try {
		return { ok: true, value: operation() };
	} catch (error) {
		return { ok: false, failure: { error } };
	}
}

function combinePrimaryAndCleanupErrors(primaryError: unknown, cleanupErrors: readonly unknown[]): unknown {
	return cleanupErrors.length === 0
		? primaryError
		: new IncidentRecorderDescriptorCleanupError(primaryError, cleanupErrors);
}

function runCleanupActionsAttemptAll(actions: readonly (() => void)[]): unknown[] {
	const cleanupErrors: unknown[] = [];
	for (const action of actions) {
		try {
			action();
		} catch (error) {
			cleanupErrors.push(error);
		}
	}
	return cleanupErrors;
}

function settleIncidentRecorderOutcome<T>(outcome: IncidentRecorderOutcome<T>, cleanupErrors: readonly unknown[]): T {
	if (!outcome.ok) throw combinePrimaryAndCleanupErrors(outcome.failure.error, cleanupErrors);
	if (cleanupErrors.length > 0) {
		throw new IncidentRecorderDescriptorCleanupError(cleanupErrors[0], cleanupErrors.slice(1));
	}
	return outcome.value;
}

function closeDescriptorsAttemptAll(
	descriptors: readonly number[],
	primaryFailure?: IncidentRecorderPrimaryFailure,
	closeDescriptor: (descriptor: number) => void = closeSync,
): void {
	const cleanupErrors: unknown[] = [];
	for (const descriptor of descriptors) {
		if (descriptor < 0) continue;
		try {
			closeDescriptor(descriptor);
		} catch (error) {
			cleanupErrors.push(error);
		}
	}
	if (primaryFailure) {
		throw combinePrimaryAndCleanupErrors(primaryFailure.error, cleanupErrors);
	}
	if (cleanupErrors.length > 0) {
		throw combinePrimaryAndCleanupErrors(cleanupErrors[0], cleanupErrors.slice(1));
	}
}

function closeDescriptorsPreservingFailure(descriptors: readonly number[], error: unknown): never {
	closeDescriptorsAttemptAll(descriptors, { error });
	throw error;
}

function runCleanupPreservingFailure(error: unknown, cleanup: () => void): never {
	throw combinePrimaryAndCleanupErrors(error, runCleanupActionsAttemptAll([cleanup]));
}

function runPruneExpiryCleanup(cleanup: () => void, onFailure?: (error: unknown) => void): void {
	try {
		cleanup();
	} catch (error) {
		// Expiry is asynchronous and has no caller. The registry entry is already
		// consumed and attempt-all close has run; emit bounded evidence without
		// letting either cleanup or its diagnostic observer escape into the daemon.
		try {
			onFailure?.(error);
		} catch {
			// A diagnostic observer is never mutation authority and cannot trigger retry.
		}
	}
}

/** @internal Exercises the exact production attempt-all close primitive. */
export function closeIncidentRecorderDescriptorsForTest(
	descriptors: readonly number[],
	primaryFailure: IncidentRecorderPrimaryFailure | undefined,
	afterClose?: (descriptor: number) => void,
): void {
	closeDescriptorsAttemptAll(descriptors, primaryFailure, (descriptor) => {
		closeSync(descriptor);
		afterClose?.(descriptor);
	});
}

/** @internal Exercises the non-throwing production expiry boundary. */
export function runIncidentRecorderPruneExpiryCleanupForTest(
	cleanup: () => void,
	onFailure?: (error: unknown) => void,
): void {
	runPruneExpiryCleanup(cleanup, onFailure);
}

function pruneCursorCapabilityKey(cursor: IncidentRecorderSegmentPruneCursor): string {
	return `${cursor.storeInstanceId}\u0000${cursor.sessionId}`;
}

interface PruneCursorCapabilityRelease {
	readonly removed: boolean;
	readonly cleanupErrors: readonly unknown[];
}

function releasePruneCursorCapability(
	registry: Map<string, PruneCursorCapability>,
	key: string,
	expectedCursor?: IncidentRecorderSegmentPruneCursor,
): PruneCursorCapabilityRelease {
	const capability = registry.get(key);
	if (!capability || (expectedCursor && capability.cursor !== expectedCursor)) {
		return { removed: false, cleanupErrors: [] };
	}
	registry.delete(key);
	clearTimeout(capability.cleanupTimer);
	const scopeLease = capability.scopeLease;
	const cleanupErrors = scopeLease
		? runCleanupActionsAttemptAll([() => closeRecoveryPruneStorageScope(scopeLease)])
		: [];
	return { removed: true, cleanupErrors };
}

function removePruneCursorCapability(
	registry: Map<string, PruneCursorCapability>,
	key: string,
	expectedCursor?: IncidentRecorderSegmentPruneCursor,
): boolean {
	const release = releasePruneCursorCapability(registry, key, expectedCursor);
	if (release.cleanupErrors.length > 0) {
		throw combinePrimaryAndCleanupErrors(release.cleanupErrors[0], release.cleanupErrors.slice(1));
	}
	return release.removed;
}

function sweepExpiredPruneCursorCapabilities(
	registry: Map<string, PruneCursorCapability>,
	now: number,
	retainedCapability?: PruneCursorCapability,
): void {
	const cleanupErrors: unknown[] = [];
	for (const [key, capability] of registry) {
		if (capability === retainedCapability) continue;
		if (capability.expiresAtMs <= now) {
			cleanupErrors.push(...releasePruneCursorCapability(registry, key, capability.cursor).cleanupErrors);
		}
	}
	if (cleanupErrors.length > 0) {
		throw combinePrimaryAndCleanupErrors(cleanupErrors[0], cleanupErrors.slice(1));
	}
}

function assertPruneCursorShape(cursor: IncidentRecorderSegmentPruneCursor): void {
	if (!cursor || typeof cursor !== "object" || cursor.version !== 1) {
		throw new Error("prune continuation version is unsupported");
	}
	if (!Object.isFrozen(cursor)) throw new Error("prune continuation must be the exact frozen registered object");
	if (typeof cursor.sessionId !== "string" || cursor.sessionId.length === 0) {
		throw new Error("prune continuation session is invalid");
	}
	if (typeof cursor.storeInstanceId !== "string" || cursor.storeInstanceId.length === 0) {
		throw new Error("prune continuation store instance is invalid");
	}
	if (!/^[a-f0-9]{64}$/.test(cursor.filterSha256)) throw new Error("prune continuation filter is invalid");
	assertSafeNonNegativeInteger(cursor.highWaterSegmentSequence, "prune continuation high-water segment sequence");
	assertSafeNonNegativeInteger(cursor.segmentSequence, "prune continuation segment sequence");
	if (cursor.segmentSequence > cursor.highWaterSegmentSequence) {
		throw new Error("prune continuation frontier exceeds its frozen high-water mark");
	}
}

function assertPruneCursorCapability(
	registry: Map<string, PruneCursorCapability>,
	cursor: IncidentRecorderSegmentPruneCursor,
	storeInstanceId: string,
	filterSha256: string,
	scopeFingerprint: string,
	now: number,
): PruneCursorCapability {
	assertPruneCursorShape(cursor);
	if (cursor.storeInstanceId !== storeInstanceId || cursor.filterSha256 !== filterSha256) {
		throw new Error("prune continuation is stale or does not match its frozen arguments");
	}
	const asynchronousExpiryFailure = PRUNE_CURSOR_ASYNC_EXPIRY_FAILURES.get(cursor);
	if (asynchronousExpiryFailure) {
		PRUNE_CURSOR_ASYNC_EXPIRY_FAILURES.delete(cursor);
		throw combinePrimaryAndCleanupErrors(new Error("prune continuation expired"), [asynchronousExpiryFailure.error]);
	}
	const key = pruneCursorCapabilityKey(cursor);
	const capability = registry.get(key);
	if (!capability) throw new Error("prune continuation is not an active process-local capability");
	if (capability.cursor !== cursor) throw new Error("prune continuation is not the exact registered object");
	if (capability.scopeFingerprint !== scopeFingerprint) {
		throw new Error("prune continuation storage identity changed; restart required");
	}
	if (capability.expiresAtMs <= now) {
		const expiredError = new Error("prune continuation expired");
		const release = releasePruneCursorCapability(registry, key, cursor);
		throw combinePrimaryAndCleanupErrors(expiredError, release.cleanupErrors);
	}
	return capability;
}

function registerPruneCursorCapability(
	registry: Map<string, PruneCursorCapability>,
	cursor: IncidentRecorderSegmentPruneCursor,
	scopeFingerprint: string,
	now: number,
	scopeLease?: RecoveryPruneStorageScopeLease,
	expectedPrevious?: PruneCursorCapability,
	expiryDiagnosticSink?: (diagnostic: IncidentRecorderPruneExpiryCleanupDiagnostic) => void,
): PruneCursorCapability {
	assertSafeNonNegativeInteger(now, "prune continuation registry time");
	const key = pruneCursorCapabilityKey(cursor);
	sweepExpiredPruneCursorCapabilities(registry, now, expectedPrevious);
	const existing = registry.get(key);
	if (expectedPrevious) {
		if (existing !== expectedPrevious) {
			throw new Error("prune continuation predecessor changed before atomic rotation");
		}
	} else if (existing) {
		throw new Error("prune continuation session already exists");
	}
	if (!existing && registry.size >= MAX_ACTIVE_PRUNE_CURSORS) {
		throw new Error(`prune continuation registry exceeds the ${String(MAX_ACTIVE_PRUNE_CURSORS)}-cursor ceiling`);
	}
	if (existing?.scopeLease && scopeLease && existing.scopeLease !== scopeLease) {
		throw new Error("prune continuation storage scope cannot change within a session");
	}
	const retainedScopeLease = scopeLease ?? existing?.scopeLease;
	const retainedExpiryDiagnosticSink = existing?.expiryDiagnosticSink ?? expiryDiagnosticSink;
	let cleanupTimer: ReturnType<typeof setTimeout> | undefined;
	let capability: PruneCursorCapability;
	try {
		cleanupTimer = setTimeout(() => {
			runPruneExpiryCleanup(
				() => {
					const release = releasePruneCursorCapability(registry, key, cursor);
					if (release.cleanupErrors.length > 0) {
						throw combinePrimaryAndCleanupErrors(release.cleanupErrors[0], release.cleanupErrors.slice(1));
					}
				},
				(error) => {
					PRUNE_CURSOR_ASYNC_EXPIRY_FAILURES.set(cursor, { error });
					retainedExpiryDiagnosticSink?.(
						Object.freeze({
							kind: "prune-cursor-expiry-cleanup-failed" as const,
							cursor,
							scopeFingerprint,
							error,
						}),
					);
				},
			);
		}, PRUNE_CURSOR_TTL_MS);
		cleanupTimer.unref();
		capability = {
			cursor,
			scopeFingerprint,
			...(retainedScopeLease ? { scopeLease: retainedScopeLease } : {}),
			...(retainedExpiryDiagnosticSink ? { expiryDiagnosticSink: retainedExpiryDiagnosticSink } : {}),
			expiresAtMs: Math.min(Number.MAX_SAFE_INTEGER, now + PRUNE_CURSOR_TTL_MS),
			cleanupTimer,
		};
		registry.set(key, capability);
	} catch (error) {
		if (cleanupTimer) clearTimeout(cleanupTimer);
		throw error;
	}
	if (existing) clearTimeout(existing.cleanupTimer);
	return capability;
}

function frozenPruneCursor(
	input: Omit<IncidentRecorderSegmentPruneCursor, "version">,
): IncidentRecorderSegmentPruneCursor {
	return Object.freeze({ version: 1 as const, ...input });
}

function pruneMutationResultSnapshot(
	result: IncidentRecorderSegmentPruneResult,
): IncidentRecorderSegmentPruneMutationResult {
	const snapshot: IncidentRecorderSegmentPruneMutationResult = {
		deletedSegmentIds: Object.freeze([...result.deletedSegmentIds]),
		corruptSegmentIds: Object.freeze([...result.corruptSegmentIds]),
		examinedSegments: result.examinedSegments,
		deletedBytes: result.deletedBytes,
		locatorsInvalidated: true,
		requiresFullReconciliation: true,
		moreWork: true,
		...(result.blockedByReadSnapshot === undefined ? {} : { blockedByReadSnapshot: result.blockedByReadSnapshot }),
		...(result.requiredBytes === undefined ? {} : { requiredBytes: result.requiredBytes }),
	};
	return Object.freeze(snapshot);
}

function classifyPruneFailure(error: unknown, result: IncidentRecorderSegmentPruneResult): unknown {
	const existingMutation = pruneMutationErrorIn(error);
	if (existingMutation) {
		return error === existingMutation
			? error
			: new IncidentRecorderSegmentPruneMutationError({
					cause: error,
					result: existingMutation.result,
					directoryDurability: existingMutation.directoryDurability,
				});
	}
	return result.deletedSegmentIds.length === 0
		? error
		: new IncidentRecorderSegmentPruneMutationError({
				cause: error,
				result: pruneMutationResultSnapshot(result),
				directoryDurability: "confirmed",
			});
}

function attachCleanupToPruneFailure(error: unknown, cleanupErrors: readonly unknown[]): unknown {
	if (cleanupErrors.length === 0) return error;
	const cleanupCause = combinePrimaryAndCleanupErrors(error, cleanupErrors);
	const mutation = pruneMutationErrorIn(error);
	return mutation
		? new IncidentRecorderSegmentPruneMutationError({
				cause: cleanupCause,
				result: mutation.result,
				directoryDurability: mutation.directoryDurability,
			})
		: cleanupCause;
}

function errorText(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function errnoCode(error: unknown): string | undefined {
	return isRecord(error) && typeof error.code === "string" ? error.code : undefined;
}

function sha256(value: Uint8Array): string {
	return createHash("sha256").update(value).digest("hex");
}

function pruneProtectionFingerprint(generation: number, protectedRunIds: readonly string[]): string {
	return sha256(Buffer.from(canonicalJson({ generation, protectedRunIds: [...protectedRunIds] }), "utf8"));
}

const PROTECTION_MAX_ENTRIES = 65_536;
const PROTECTION_MAX_CATALOG_BYTES = 64 * MEBIBYTE;

function boundedCanonicalIdentifiers(
	values: readonly string[],
	name: string,
	assertValue: (value: string) => void,
): readonly string[] {
	if (!Array.isArray(values)) throw new Error(`${name} must be an array`);
	if (values.length > PROTECTION_MAX_ENTRIES) {
		throw new Error(`${name} exceeds the 65,536-entry protection ceiling`);
	}
	let catalogBytes = 2;
	const unique = new Set<string>();
	for (let index = 0; index < values.length; index += 1) {
		const value = values[index];
		if (typeof value !== "string") throw new Error(`${name} must contain only strings`);
		catalogBytes += Buffer.byteLength(JSON.stringify(value), "utf8") + 257;
		if (catalogBytes > PROTECTION_MAX_CATALOG_BYTES) {
			throw new Error(`${name} exceeds the 64 MiB protection catalog ceiling`);
		}
		assertValue(value);
		unique.add(value);
		if (unique.size > PROTECTION_MAX_ENTRIES) {
			throw new Error(`${name} exceeds the 65,536-unique-entry protection ceiling`);
		}
	}
	const sorted = Array.from(unique);
	sorted.sort();
	return Object.freeze(sorted);
}

function snapshotProtectedSegmentIds(values: ReadonlySet<string> | undefined): {
	readonly set: ReadonlySet<string>;
	readonly sorted: readonly string[];
} {
	if (values === undefined) return { set: new Set<string>(), sorted: Object.freeze([]) };
	if (!Number.isSafeInteger(values.size) || values.size < 0 || values.size > PROTECTION_MAX_ENTRIES) {
		throw new Error("protected segment IDs exceed the 65,536-entry protection ceiling");
	}
	let rawCount = 0;
	let catalogBytes = 2;
	const snapshot = new Set<string>();
	for (const segmentId of values) {
		rawCount += 1;
		if (rawCount > PROTECTION_MAX_ENTRIES) {
			throw new Error("protected segment IDs exceed the 65,536-entry protection ceiling");
		}
		if (typeof segmentId !== "string") {
			throw new Error("protected segment IDs must contain only strings");
		}
		catalogBytes += Buffer.byteLength(JSON.stringify(segmentId), "utf8") + 257;
		if (catalogBytes > PROTECTION_MAX_CATALOG_BYTES) {
			throw new Error("protected segment IDs exceed the 64 MiB protection catalog ceiling");
		}
		assertSegmentId(segmentId);
		snapshot.add(segmentId);
		if (snapshot.size > PROTECTION_MAX_ENTRIES) {
			throw new Error("protected segment IDs exceed the 65,536-unique-entry protection ceiling");
		}
	}
	const sorted = Array.from(snapshot);
	sorted.sort();
	return { set: snapshot, sorted: Object.freeze(sorted) };
}

export function createIncidentRecorderSegmentPruneProtection(
	generation: number,
	protectedRunIds: readonly string[],
): IncidentRecorderSegmentPruneProtectionComplete {
	assertSafeNonNegativeInteger(generation, "prune protection generation");
	const sortedRunIds = boundedCanonicalIdentifiers(protectedRunIds, "protected run IDs", (runId) =>
		assertIdentifier(runId, "protected runId"),
	);
	return Object.freeze({
		state: "complete" as const,
		generation,
		protectedRunIds: Object.freeze(sortedRunIds),
		fingerprint: pruneProtectionFingerprint(generation, sortedRunIds),
	});
}

function validatedPruneProtection(protection: IncidentRecorderSegmentPruneProtectionComplete): {
	readonly generation: number;
	readonly fingerprint: string;
	readonly protectedRunIds: readonly string[];
	readonly protectedRunIdSet: ReadonlySet<string>;
} {
	if (!protection || protection.state !== "complete") {
		throw new Error("a complete prune protection proof is required");
	}
	assertSafeNonNegativeInteger(protection.generation, "prune protection generation");
	const sortedRunIds = boundedCanonicalIdentifiers(protection.protectedRunIds, "protected run IDs", (runId) =>
		assertIdentifier(runId, "protected runId"),
	);
	if (
		sortedRunIds.length !== protection.protectedRunIds.length ||
		sortedRunIds.some((runId, index) => runId !== protection.protectedRunIds[index])
	) {
		throw new Error("protected run IDs must be unique and sorted");
	}
	const expectedFingerprint = pruneProtectionFingerprint(protection.generation, sortedRunIds);
	if (protection.fingerprint !== expectedFingerprint) {
		throw new Error("prune protection fingerprint does not match its generation and protected run IDs");
	}
	return Object.freeze({
		generation: protection.generation,
		fingerprint: protection.fingerprint,
		protectedRunIds: sortedRunIds,
		protectedRunIdSet: new Set(sortedRunIds),
	});
}

function idempotencyBloom(entries: readonly SegmentIndexEntry[]): string {
	const bits = Buffer.alloc(IDEMPOTENCY_BLOOM_BYTES);
	for (const entry of entries) {
		const digest = createHash("sha256").update(entry.idempotencyKey, "utf8").digest();
		for (let index = 0; index < IDEMPOTENCY_BLOOM_HASHES; index += 1) {
			const bit = digest.readUInt32LE(index * 4) % (IDEMPOTENCY_BLOOM_BYTES * 8);
			bits[Math.floor(bit / 8)] = (bits[Math.floor(bit / 8)] ?? 0) | (1 << (bit % 8));
		}
	}
	return bits.toString("base64");
}

function idempotencyBloomMayContain(encoded: string, idempotencyKey: string): boolean {
	const bits = Buffer.from(encoded, "base64");
	if (bits.byteLength !== IDEMPOTENCY_BLOOM_BYTES) throw new InvalidFrameError("idempotency bloom size is invalid");
	const digest = createHash("sha256").update(idempotencyKey, "utf8").digest();
	for (let index = 0; index < IDEMPOTENCY_BLOOM_HASHES; index += 1) {
		const bit = digest.readUInt32LE(index * 4) % (IDEMPOTENCY_BLOOM_BYTES * 8);
		if (((bits[Math.floor(bit / 8)] ?? 0) & (1 << (bit % 8))) === 0) return false;
	}
	return true;
}

function assertSafeNonNegativeInteger(value: number, name: string): void {
	if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative safe integer`);
}

function positiveInteger(value: number | undefined, fallback: number, name: string, maximum?: number): number {
	const resolved = value ?? fallback;
	if (!Number.isSafeInteger(resolved) || resolved <= 0) throw new Error(`${name} must be a positive safe integer`);
	if (maximum !== undefined && resolved > maximum) throw new Error(`${name} exceeds the fixed format maximum`);
	return resolved;
}

function firstOrdinalAfter<T extends { ordinal: number }>(entries: readonly T[], ordinal: number): number {
	let low = 0;
	let high = entries.length;
	while (low < high) {
		const middle = low + Math.floor((high - low) / 2);
		if ((entries[middle]?.ordinal ?? Number.MAX_SAFE_INTEGER) <= ordinal) low = middle + 1;
		else high = middle;
	}
	return low;
}

function firstSegmentAtOrAfter(summaries: readonly SegmentSummary[], segmentSequence: number): number {
	let low = 0;
	let high = summaries.length;
	while (low < high) {
		const middle = low + Math.floor((high - low) / 2);
		if ((summaries[middle]?.header.segmentSequence ?? Number.MAX_SAFE_INTEGER) < segmentSequence) low = middle + 1;
		else high = middle;
	}
	return low;
}

function assertIdentifier(value: string, name: string): void {
	if (value.length === 0 || value.length > 256) throw new Error(`${name} must contain 1 to 256 characters`);
}

function assertSegmentId(value: string): void {
	if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value)) {
		throw new Error("segmentId must be a path-safe identifier of at most 128 characters");
	}
}

function assertRecordLocator(locator: IncidentRecorderSegmentLocator): void {
	if (!isRecord(locator) || locator.version !== 1) throw new Error("record locator version is unsupported");
	assertSegmentId(locator.segmentId);
	assertSafeNonNegativeInteger(locator.segmentSequence, "record locator segment sequence");
	if (!Number.isSafeInteger(locator.ordinal) || locator.ordinal <= 0) {
		throw new Error("record locator ordinal must be a positive safe integer");
	}
	assertSafeNonNegativeInteger(locator.offset, "record locator offset");
	if (!Number.isSafeInteger(locator.frameBytes) || locator.frameBytes <= FRAME_OVERHEAD_BYTES) {
		throw new Error("record locator frameBytes is invalid");
	}
	assertSafeNonNegativeInteger(locator.payloadBytes, "record locator payloadBytes");
	if (locator.payloadBytes > locator.frameBytes || !/^[a-f0-9]{64}$/.test(locator.payloadSha256)) {
		throw new Error("record locator payload identity is invalid");
	}
}

function assertOrder(value: string): void {
	if (!/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > MAX_UNSIGNED_64) {
		throw new Error("order must be a canonical unsigned 64-bit decimal string");
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJsonValue(value: unknown, seen = new Set<object>(), depth = 0): value is IncidentRecorderSegmentJsonValue {
	if (depth > 64) return false;
	if (value === null || typeof value === "string" || typeof value === "boolean") return true;
	if (typeof value === "number") return Number.isFinite(value) && !Object.is(value, -0);
	if (typeof value !== "object" || seen.has(value)) return false;
	seen.add(value);
	if (Array.isArray(value)) {
		const valid = value.every((entry) => isJsonValue(entry, seen, depth + 1));
		seen.delete(value);
		return valid;
	}
	const prototype = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null) return false;
	const valid = Object.values(value).every((entry) => isJsonValue(entry, seen, depth + 1));
	seen.delete(value);
	return valid;
}

function assertMetadata(value: unknown): asserts value is IncidentRecorderSegmentMetadata {
	if (!isRecord(value) || !isJsonValue(value))
		throw new Error("metadata must be an exact finite JSON object with depth at most 64");
}

function canonicalJson(value: IncidentRecorderSegmentJsonValue): string {
	if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isFinite(value) || Object.is(value, -0)) throw new Error("canonical JSON number is invalid");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
	return (
		"{" +
		Object.keys(value)
			.sort()
			.map((key) => JSON.stringify(key) + ":" + canonicalJson(value[key] ?? null))
			.join(",") +
		"}"
	);
}

function canonicalRecordIdentity(
	input: IncidentRecorderSegmentAppendInput,
	payloadBytes: number,
	payloadSha256: string,
): { idempotencyKey: string; canonicalContentSha256: string } {
	const canonicalContentSha256 = sha256(
		Buffer.from(
			canonicalJson({
				runId: input.runId,
				sourceId: input.sourceId,
				observedAtMs: input.observedAtMs,
				order: input.order,
				metadata: input.metadata,
				payloadBytes,
				payloadSha256,
			}),
			"utf8",
		),
	);
	const idempotencyKey = input.idempotencyKey ?? "content:" + canonicalContentSha256;
	assertIdentifier(idempotencyKey, "idempotencyKey");
	return { idempotencyKey, canonicalContentSha256 };
}

function encodeJson(value: unknown): Buffer {
	const encoded = JSON.stringify(value);
	if (encoded === undefined) throw new Error("value cannot be encoded as JSON");
	return Buffer.from(encoded, "utf8");
}

function parseJson(content: Uint8Array, label: string): unknown {
	try {
		return JSON.parse(Buffer.from(content).toString("utf8")) as unknown;
	} catch (error) {
		throw new InvalidFrameError(`${label} is not valid JSON: ${errorText(error)}`);
	}
}

function encodeFrame(type: FrameType, ordinal: number, content: Uint8Array): Buffer {
	assertSafeNonNegativeInteger(ordinal, "frame ordinal");
	if (ordinal > 0xffff_ffff) throw new Error("frame ordinal exceeds the format limit");
	if (content.byteLength > 0xffff_ffff - FRAME_OVERHEAD_BYTES)
		throw new Error("frame content exceeds the format limit");
	const prefix = Buffer.alloc(FRAME_PREFIX_BYTES);
	FRAME_MAGIC.copy(prefix, 0);
	prefix.writeUInt8(FORMAT_VERSION, 4);
	prefix.writeUInt8(type, 5);
	prefix.writeUInt16LE(0, 6);
	prefix.writeUInt32LE(content.byteLength, 8);
	prefix.writeUInt32LE(ordinal, 12);
	const contentCopy = Buffer.from(content);
	const checksum = createHash("sha256").update(prefix).update(contentCopy).digest();
	const trailer = Buffer.alloc(FRAME_TRAILER_BYTES);
	const frameBytes = FRAME_PREFIX_BYTES + contentCopy.byteLength + FRAME_CHECKSUM_BYTES + FRAME_TRAILER_BYTES;
	trailer.writeUInt32LE(frameBytes, 0);
	FRAME_END_MAGIC.copy(trailer, 4);
	return Buffer.concat([prefix, contentCopy, checksum, trailer]);
}

/**
 * The smallest file capability shared with CAS mutation views. Raw descriptors
 * stay inside `withOwnedSegmentFile`; callers receive only this scoped view.
 */
type IncidentRecorderSegmentFileView = Pick<IncidentCasFileMutation, "stat" | "read" | "write" | "truncate" | "sync">;
type IncidentRecorderSegmentFileHandle = number | IncidentRecorderSegmentFileView;

function scopedSegmentFileView(fileDescriptor: number): IncidentRecorderSegmentFileView {
	return Object.freeze({
		stat: () => fstatSync(fileDescriptor, { bigint: true }),
		read: (target: Uint8Array, offset: number, length: number, position: number | null): number =>
			readSync(
				fileDescriptor,
				Buffer.from(target.buffer, target.byteOffset, target.byteLength),
				offset,
				length,
				position,
			),
		write: (source: Uint8Array, offset: number, length: number, position: number | null): number =>
			writeSync(
				fileDescriptor,
				Buffer.from(source.buffer, source.byteOffset, source.byteLength),
				offset,
				length,
				position,
			),
		truncate: (length: number): void => ftruncateSync(fileDescriptor, length),
		sync: (): void => fsyncSync(fileDescriptor),
	});
}

function segmentFileView(file: IncidentRecorderSegmentFileHandle): IncidentRecorderSegmentFileView {
	return typeof file === "number" ? scopedSegmentFileView(file) : file;
}

function withOwnedSegmentFile<T>(
	path: string,
	flags: number,
	operation: (file: IncidentRecorderSegmentFileView) => T,
	mode?: number,
): T {
	const fileDescriptor = mode === undefined ? openSync(path, flags) : openSync(path, flags, mode);
	const outcome = captureIncidentRecorderOutcome(() => operation(scopedSegmentFileView(fileDescriptor)));
	return settleIncidentRecorderOutcome(outcome, runCleanupActionsAttemptAll([() => closeSync(fileDescriptor)]));
}

function readFully(file: IncidentRecorderSegmentFileHandle, buffer: Buffer, position: number): void {
	const fileView = segmentFileView(file);
	let completed = 0;
	while (completed < buffer.byteLength) {
		const bytes = fileView.read(buffer, completed, buffer.byteLength - completed, position + completed);
		if (bytes === 0) throw new InvalidFrameError("unexpected end of segment");
		completed += bytes;
	}
}

function writeFullyAt(file: IncidentRecorderSegmentFileHandle, buffer: Buffer, position: number): void {
	const fileView = segmentFileView(file);
	let completed = 0;
	while (completed < buffer.byteLength) {
		const bytes = fileView.write(buffer, completed, buffer.byteLength - completed, position + completed);
		if (bytes === 0) throw new Error("segment write made no progress");
		completed += bytes;
	}
}

function frameMaximum(type: FrameType): number {
	if (type === FrameType.Record) return FORMAT_MAX_RECORD_FRAME_BYTES;
	if (type === FrameType.Index) return FORMAT_MAX_INDEX_FRAME_BYTES;
	if (type === FrameType.Footer) return FORMAT_MAX_FOOTER_FRAME_BYTES;
	return 128 * 1024;
}

function parseFrameAt(file: IncidentRecorderSegmentFileHandle, offset: number, fileSize: number): ParsedFrame {
	if (offset < 0 || fileSize - offset < FRAME_OVERHEAD_BYTES) throw new InvalidFrameError("incomplete frame prefix");
	const prefix = Buffer.alloc(FRAME_PREFIX_BYTES);
	readFully(file, prefix, offset);
	if (!prefix.subarray(0, FRAME_MAGIC.byteLength).equals(FRAME_MAGIC)) throw new InvalidFrameError("bad frame magic");
	if (prefix.readUInt8(4) !== FORMAT_VERSION) throw new InvalidFrameError("unsupported frame version");
	const typeValue = prefix.readUInt8(5);
	if (typeValue < FrameType.Header || typeValue > FrameType.Footer) throw new InvalidFrameError("unknown frame type");
	const type = typeValue as FrameType;
	const contentBytes = prefix.readUInt32LE(8);
	const frameBytes = FRAME_OVERHEAD_BYTES + contentBytes;
	if (frameBytes > frameMaximum(type)) throw new InvalidFrameError("frame exceeds the fixed format maximum");
	if (offset + frameBytes > fileSize) throw new InvalidFrameError("incomplete frame body");
	const frame = Buffer.alloc(frameBytes);
	prefix.copy(frame, 0);
	readFully(file, frame.subarray(FRAME_PREFIX_BYTES), offset + FRAME_PREFIX_BYTES);
	if (frame.readUInt32LE(frameBytes - FRAME_TRAILER_BYTES) !== frameBytes) {
		throw new InvalidFrameError("frame length trailer mismatch");
	}
	if (!frame.subarray(frameBytes - 4).equals(FRAME_END_MAGIC)) throw new InvalidFrameError("bad frame end magic");
	const contentEnd = FRAME_PREFIX_BYTES + contentBytes;
	const expected = createHash("sha256").update(frame.subarray(0, contentEnd)).digest();
	const actual = frame.subarray(contentEnd, contentEnd + FRAME_CHECKSUM_BYTES);
	if (!timingSafeEqual(expected, actual)) throw new InvalidFrameError("frame checksum mismatch");
	return {
		type,
		ordinal: prefix.readUInt32LE(12),
		content: frame.subarray(FRAME_PREFIX_BYTES, contentEnd),
		frameBytes,
		bytes: frame,
	};
}

function ensurePrivateDirectory(path: string): void {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	const status = lstatSync(path);
	if (!status.isDirectory() || status.isSymbolicLink()) throw new Error(`segment path is not a directory: ${path}`);
	chmodSync(path, 0o700);
}

function assertPrivateRegularFile(file: IncidentRecorderSegmentFileHandle, path: string): void {
	const status = segmentFileView(file).stat();
	if (!status.isFile()) throw new Error(`segment path is not a regular file: ${path}`);
	if ((Number(status.mode) & 0o077) !== 0) throw new Error(`segment file is not private: ${path}`);
}

function syncDirectory(path: string): void {
	const fileDescriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
	try {
		fsyncSync(fileDescriptor);
	} finally {
		closeSync(fileDescriptor);
	}
}

function pathStatus(path: string): ReturnType<typeof lstatSync> | undefined {
	try {
		return lstatSync(path);
	} catch (error) {
		if (errnoCode(error) === "ENOENT") return undefined;
		throw error;
	}
}

function sameFile(left: string, right: string): boolean {
	const leftStatus = lstatSync(left, { bigint: true });
	const rightStatus = lstatSync(right, { bigint: true });
	return leftStatus.dev === rightStatus.dev && leftStatus.ino === rightStatus.ino;
}

function hashFileRange(
	file: IncidentRecorderSegmentFileHandle,
	start: number,
	bytes: number,
	onRead?: (bytes: number) => void,
): string {
	const hash = createHash("sha256");
	const buffer = Buffer.alloc(Math.min(RECOVERY_READ_CHUNK_BYTES, Math.max(1, bytes)));
	let offset = 0;
	while (offset < bytes) {
		const length = Math.min(buffer.byteLength, bytes - offset);
		const chunk = buffer.subarray(0, length);
		readFully(file, chunk, start + offset);
		hash.update(chunk);
		onRead?.(length);
		offset += length;
	}
	return hash.digest("hex");
}

interface StorageState {
	deviceId: string;
	inodeId: string;
	linkCount: number;
	logicalBytes: number;
	allocatedBytes: number;
}

function sameStorageState(left: StorageState, right: StorageState): boolean {
	return (
		left.deviceId === right.deviceId &&
		left.inodeId === right.inodeId &&
		left.linkCount === right.linkCount &&
		left.logicalBytes === right.logicalBytes &&
		left.allocatedBytes === right.allocatedBytes
	);
}

interface VerifiedSegmentIdentity extends StorageState {
	mode: string;
	fileSha256: string;
}

interface VerifiedSegmentHandle {
	fileDescriptor: number;
	identity: VerifiedSegmentIdentity;
}

interface RecoveryPruneStorageScope {
	sealedDirectory: string;
	fingerprint: string;
}

interface RecoveryPruneStorageScopeLease extends RecoveryPruneStorageScope {
	rootDescriptor: number;
	sealedDescriptor: number;
	procFdAuthority: AuthenticatedProcFdRoute;
}

interface DirectoryIdentity {
	deviceId: string;
	inodeId: string;
	mode: string;
}

interface AuthenticatedProcFdRoute {
	procRootDescriptor: number;
	fdDirectoryDescriptor: number;
	procRootIdentity: DirectoryIdentity;
	fdDirectoryIdentity: DirectoryIdentity;
	threadSelfTarget: string;
	procMountId: bigint;
}

interface ProcFdParentWitness {
	aliasPath: string;
	canonicalTarget: string;
	identity: DirectoryIdentity;
}

function fileAllocation(file: IncidentRecorderSegmentFileHandle): StorageState {
	const status = segmentFileView(file).stat();
	return {
		deviceId: status.dev.toString(),
		inodeId: status.ino.toString(),
		linkCount: Number(status.nlink),
		logicalBytes: Number(status.size),
		allocatedBytes: Number(status.blocks * 512n),
	};
}

function verifiedSegmentIdentity(fileDescriptor: number, expectedBytes: number): VerifiedSegmentIdentity {
	const allocation = fileAllocation(fileDescriptor);
	const status = segmentFileView(fileDescriptor).stat();
	if (allocation.logicalBytes !== expectedBytes) {
		throw new InvalidFrameError("sealed prune target size changed after verification");
	}
	return {
		...allocation,
		mode: status.mode.toString(),
		fileSha256: hashFileRange(fileDescriptor, 0, expectedBytes),
	};
}

function assertVerifiedSegmentIdentity(
	fileDescriptor: number,
	path: string,
	expected: VerifiedSegmentIdentity,
): StorageState {
	assertPrivateRegularFile(fileDescriptor, path);
	const actual = verifiedSegmentIdentity(fileDescriptor, expected.logicalBytes);
	if (
		actual.deviceId !== expected.deviceId ||
		actual.inodeId !== expected.inodeId ||
		actual.mode !== expected.mode ||
		actual.logicalBytes !== expected.logicalBytes ||
		actual.fileSha256 !== expected.fileSha256
	) {
		throw new InvalidFrameError("sealed prune target identity changed after verification");
	}
	return actual;
}

function directoryIdentity(fileDescriptor: number, label: string): DirectoryIdentity {
	const status = fstatSync(fileDescriptor, { bigint: true });
	if (!status.isDirectory()) throw new Error(`${label} is not a directory`);
	return {
		deviceId: status.dev.toString(),
		inodeId: status.ino.toString(),
		mode: status.mode.toString(),
	};
}

function assertDirectoryPathIdentity(path: string, expected: DirectoryIdentity, label: string): void {
	const status = lstatSync(path, { bigint: true });
	if (
		!status.isDirectory() ||
		status.isSymbolicLink() ||
		status.dev.toString() !== expected.deviceId ||
		status.ino.toString() !== expected.inodeId ||
		status.mode.toString() !== expected.mode
	) {
		throw new Error(`${label} identity changed`);
	}
}

function parseProcMountIdContent(content: Buffer): bigint {
	if (content.byteLength > PROC_FDINFO_MAX_BYTES) {
		throw new Error("proc fdinfo exceeds its fixed read bound");
	}
	const text = content.toString("utf8");
	if (text.includes("\u0000")) throw new Error("proc fdinfo contains an embedded NUL");
	const candidates = text.split("\n").filter((line) => line.startsWith("mnt_id"));
	if (candidates.length !== 1) throw new Error("proc fdinfo has no unique strict mnt_id");
	const match = /^mnt_id:\s+([1-9][0-9]{0,19})\s*$/.exec(candidates[0] ?? "");
	if (!match?.[1]) throw new Error("proc fdinfo mnt_id is malformed");
	const mountId = BigInt(match[1]);
	if (mountId > MAX_UNSIGNED_64) throw new Error("proc fdinfo mnt_id is out of range");
	return mountId;
}

/** @internal Pure test seam for the production fdinfo parser. */
export function parseIncidentRecorderProcFdInfoMountIdForTest(content: string | Buffer): bigint {
	return parseProcMountIdContent(typeof content === "string" ? Buffer.from(content, "utf8") : Buffer.from(content));
}

function assertMatchingProcMountIds(expected: bigint, observed: readonly bigint[], message: string): void {
	if (observed.length === 0 || observed.some((mountId) => mountId !== expected)) {
		throw new Error(message);
	}
}

/** @internal Pure test seam for the production proc-route mount comparison. */
export function assertIncidentRecorderProcFdMountIdsForTest(expected: bigint, observed: readonly bigint[]): void {
	assertMatchingProcMountIds(expected, observed, "proc fd route mount identity changed");
}

function readProcMountId(fileDescriptor: number): bigint {
	const path = join(PROC_THREAD_FDINFO_DIRECTORY, String(fileDescriptor));
	assertProcFsType(path);
	const fdinfoDescriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
	const outcome = captureIncidentRecorderOutcome(() => {
		const content = Buffer.alloc(PROC_FDINFO_MAX_BYTES + 1);
		let bytes = 0;
		for (;;) {
			const read = readSync(fdinfoDescriptor, content, bytes, content.byteLength - bytes, null);
			if (read === 0) break;
			bytes += read;
			if (bytes > PROC_FDINFO_MAX_BYTES) throw new Error("proc fdinfo exceeds its fixed read bound");
		}
		return parseProcMountIdContent(content.subarray(0, bytes));
	});
	return settleIncidentRecorderOutcome(outcome, runCleanupActionsAttemptAll([() => closeSync(fdinfoDescriptor)]));
}

function assertProcFsType(path: string): void {
	if (statfsSync(path, { bigint: true }).type !== PROC_SUPER_MAGIC) {
		throw new Error("descriptor-relative deletion requires a genuine procfs route");
	}
}

function sameDirectoryIdentity(left: DirectoryIdentity, right: DirectoryIdentity): boolean {
	return left.deviceId === right.deviceId && left.inodeId === right.inodeId && left.mode === right.mode;
}

function assertAuthenticatedProcFdRoute(route: AuthenticatedProcFdRoute): void {
	assertProcFsType(PROC_ROOT_PATH);
	assertProcFsType(PROC_THREAD_FD_DIRECTORY);
	assertProcFsType(PROC_THREAD_FDINFO_DIRECTORY);
	if (readlinkSync(PROC_THREAD_SELF_PATH) !== route.threadSelfTarget) {
		throw new Error("proc thread-self identity changed");
	}
	if (!PROC_THREAD_SELF_TARGET_PATTERN.test(route.threadSelfTarget)) {
		throw new Error("proc thread-self identity is invalid");
	}
	const heldProcRootIdentity = directoryIdentity(route.procRootDescriptor, "held proc root");
	if (!sameDirectoryIdentity(heldProcRootIdentity, route.procRootIdentity) || heldProcRootIdentity.inodeId !== "1") {
		throw new Error("held proc root identity changed");
	}
	const heldFdDirectoryIdentity = directoryIdentity(route.fdDirectoryDescriptor, "held proc fd directory");
	if (!sameDirectoryIdentity(heldFdDirectoryIdentity, route.fdDirectoryIdentity)) {
		throw new Error("held proc fd directory identity changed");
	}
	let freshProcRootDescriptor = -1;
	let freshFdDirectoryDescriptor = -1;
	const outcome = captureIncidentRecorderOutcome(() => {
		freshProcRootDescriptor = openSync(
			PROC_ROOT_PATH,
			constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
		);
		freshFdDirectoryDescriptor = openSync(
			PROC_THREAD_FD_DIRECTORY,
			constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
		);
		const freshRootIdentity = directoryIdentity(freshProcRootDescriptor, "current proc root");
		const freshFdDirectoryIdentity = directoryIdentity(
			freshFdDirectoryDescriptor,
			"current proc thread fd directory",
		);
		if (!sameDirectoryIdentity(freshRootIdentity, route.procRootIdentity) || freshRootIdentity.inodeId !== "1") {
			throw new Error("current proc root differs from held authority");
		}
		if (!sameDirectoryIdentity(freshFdDirectoryIdentity, route.fdDirectoryIdentity)) {
			throw new Error("current proc fd route differs from held authority");
		}
		assertDirectoryPathIdentity(PROC_ROOT_PATH, freshRootIdentity, "proc root");
		assertDirectoryPathIdentity(PROC_THREAD_FD_DIRECTORY, freshFdDirectoryIdentity, "proc thread fd directory");
		assertMatchingProcMountIds(
			route.procMountId,
			[
				route.procRootDescriptor,
				route.fdDirectoryDescriptor,
				freshProcRootDescriptor,
				freshFdDirectoryDescriptor,
			].map((descriptor) => readProcMountId(descriptor)),
			"proc fd route mount identity changed",
		);
		if (readlinkSync(PROC_THREAD_SELF_PATH) !== route.threadSelfTarget) {
			throw new Error("proc thread-self identity changed during route validation");
		}
	});
	settleIncidentRecorderOutcome(
		outcome,
		runCleanupActionsAttemptAll([
			() => {
				if (freshFdDirectoryDescriptor >= 0) closeSync(freshFdDirectoryDescriptor);
			},
			() => {
				if (freshProcRootDescriptor >= 0) closeSync(freshProcRootDescriptor);
			},
		]),
	);
}

function openAuthenticatedProcFdRoute(): AuthenticatedProcFdRoute {
	let procRootDescriptor = -1;
	let fdDirectoryDescriptor = -1;
	try {
		assertProcFsType(PROC_ROOT_PATH);
		const threadSelfTarget = readlinkSync(PROC_THREAD_SELF_PATH);
		if (!PROC_THREAD_SELF_TARGET_PATTERN.test(threadSelfTarget)) {
			throw new Error("proc thread-self identity is invalid");
		}
		procRootDescriptor = openSync(PROC_ROOT_PATH, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const procRootIdentity = directoryIdentity(procRootDescriptor, "proc root");
		if (procRootIdentity.inodeId !== "1") throw new Error("proc root inode is not canonical");
		fdDirectoryDescriptor = openSync(
			PROC_THREAD_FD_DIRECTORY,
			constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
		);
		const fdDirectoryIdentity = directoryIdentity(fdDirectoryDescriptor, "proc thread fd directory");
		const procMountId = readProcMountId(procRootDescriptor);
		assertMatchingProcMountIds(
			procMountId,
			[readProcMountId(fdDirectoryDescriptor)],
			"proc root and fd route have different mount identities",
		);
		const route: AuthenticatedProcFdRoute = {
			procRootDescriptor,
			fdDirectoryDescriptor,
			procRootIdentity,
			fdDirectoryIdentity,
			threadSelfTarget,
			procMountId,
		};
		assertAuthenticatedProcFdRoute(route);
		return route;
	} catch (error) {
		return closeDescriptorsPreservingFailure([fdDirectoryDescriptor, procRootDescriptor], error);
	}
}

function closeAuthenticatedProcFdRoute(route: AuthenticatedProcFdRoute): void {
	closeDescriptorsAttemptAll([route.fdDirectoryDescriptor, route.procRootDescriptor]);
}

function captureProcFdParentWitness(
	route: AuthenticatedProcFdRoute,
	directoryDescriptor: number,
	expectedPath: string,
): ProcFdParentWitness {
	assertAuthenticatedProcFdRoute(route);
	const aliasPath = join(PROC_THREAD_FD_DIRECTORY, String(directoryDescriptor));
	const canonicalTarget = realpathSync(expectedPath);
	if (readlinkSync(aliasPath) !== canonicalTarget) {
		throw new Error("proc fd parent link does not match its exact canonical path");
	}
	const identity = directoryIdentity(directoryDescriptor, "descriptor-relative parent");
	const aliasDescriptor = openSync(aliasPath, constants.O_RDONLY | constants.O_DIRECTORY);
	const outcome = captureIncidentRecorderOutcome(() => {
		const aliasIdentity = directoryIdentity(aliasDescriptor, "proc fd parent alias");
		if (
			aliasIdentity.deviceId !== identity.deviceId ||
			aliasIdentity.inodeId !== identity.inodeId ||
			aliasIdentity.mode !== identity.mode
		) {
			throw new Error("proc fd parent alias resolves to a different directory identity");
		}
	});
	settleIncidentRecorderOutcome(outcome, runCleanupActionsAttemptAll([() => closeSync(aliasDescriptor)]));
	return { aliasPath, canonicalTarget, identity };
}

function assertProcFdParentWitness(
	route: AuthenticatedProcFdRoute,
	directoryDescriptor: number,
	witness: ProcFdParentWitness,
): void {
	assertAuthenticatedProcFdRoute(route);
	if (readlinkSync(witness.aliasPath) !== witness.canonicalTarget) {
		throw new Error("proc fd parent link changed during descriptor-relative operation");
	}
	const identity = directoryIdentity(directoryDescriptor, "descriptor-relative parent");
	if (
		identity.deviceId !== witness.identity.deviceId ||
		identity.inodeId !== witness.identity.inodeId ||
		identity.mode !== witness.identity.mode
	) {
		throw new Error("descriptor-relative parent identity changed during operation");
	}
	const aliasDescriptor = openSync(witness.aliasPath, constants.O_RDONLY | constants.O_DIRECTORY);
	const outcome = captureIncidentRecorderOutcome(() => {
		const aliasIdentity = directoryIdentity(aliasDescriptor, "proc fd parent alias");
		if (!sameDirectoryIdentity(aliasIdentity, witness.identity)) {
			throw new Error("proc fd parent alias identity changed during operation");
		}
	});
	settleIncidentRecorderOutcome(outcome, runCleanupActionsAttemptAll([() => closeSync(aliasDescriptor)]));
}

function procFdChildPath(witness: ProcFdParentWitness, childName: string): string {
	if (childName.length === 0 || basename(childName) !== childName || childName === "." || childName === "..") {
		throw new Error("descriptor-relative child name is invalid");
	}
	return join(witness.aliasPath, childName);
}

function recoveryPruneStorageFingerprint(root: DirectoryIdentity, sealed: DirectoryIdentity): string {
	return canonicalJson({
		root: {
			deviceId: root.deviceId,
			inodeId: root.inodeId,
			mode: root.mode,
		},
		sealedEntry: {
			name: "sealed",
			parentDeviceId: root.deviceId,
			parentInodeId: root.inodeId,
			targetDeviceId: sealed.deviceId,
			targetInodeId: sealed.inodeId,
			targetMode: sealed.mode,
		},
	});
}

function openDirectoryChildAtDescriptor(
	route: AuthenticatedProcFdRoute,
	directoryDescriptor: number,
	directoryPath: string,
	childName: string,
): number {
	let childDescriptor = -1;
	try {
		const parentWitness = captureProcFdParentWitness(route, directoryDescriptor, directoryPath);
		childDescriptor = openSync(
			procFdChildPath(parentWitness, childName),
			constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
		);
		assertProcFdParentWitness(route, directoryDescriptor, parentWitness);
		const result = childDescriptor;
		childDescriptor = -1;
		return result;
	} catch (error) {
		return closeDescriptorsPreservingFailure([childDescriptor], error);
	}
}

function assertDirectoryChildIdentityAtDescriptor(
	route: AuthenticatedProcFdRoute,
	directoryDescriptor: number,
	directoryPath: string,
	childName: string,
	expected: DirectoryIdentity,
	label: string,
): void {
	const parentWitness = captureProcFdParentWitness(route, directoryDescriptor, directoryPath);
	assertDirectoryPathIdentity(procFdChildPath(parentWitness, childName), expected, label);
	assertProcFdParentWitness(route, directoryDescriptor, parentWitness);
}

function assertRecoveryPruneStorageScopeLease(
	scope: RecoveryPruneStorageScopeLease,
	directory: string,
	expectedFingerprint: string,
): void {
	const sealedDirectory = join(directory, "sealed");
	if (scope.sealedDirectory !== sealedDirectory) {
		throw new Error("recovery prune storage path changed");
	}
	const rootIdentity = directoryIdentity(scope.rootDescriptor, "recovery root descriptor");
	const sealedIdentity = directoryIdentity(scope.sealedDescriptor, "sealed recovery descriptor");
	if (
		recoveryPruneStorageFingerprint(rootIdentity, sealedIdentity) !== scope.fingerprint ||
		scope.fingerprint !== expectedFingerprint
	) {
		throw new Error("recovery prune storage descriptor identity changed");
	}
	assertDirectoryPathIdentity(directory, rootIdentity, "recovery root");
	assertDirectoryChildIdentityAtDescriptor(
		scope.procFdAuthority,
		scope.rootDescriptor,
		directory,
		"sealed",
		sealedIdentity,
		"sealed recovery entry",
	);
	assertDirectoryPathIdentity(sealedDirectory, sealedIdentity, "sealed recovery path");
}

// Node 22 has no inode-conditional unlink. The proc/fdinfo witness also cannot
// close a privileged concurrent mount race. Callers must retain their stable
// mount-namespace plus single-writer or externalWriterExcluded premise across
// this final compare/unlink sequence.
function unlinkVerifiedSegmentAtPath(
	route: AuthenticatedProcFdRoute,
	directoryDescriptor: number,
	directoryPath: string,
	childName: string,
	verifiedHandle: VerifiedSegmentHandle,
	afterUnlinkBeforeDirectoryFsync?: () => void,
): StorageState {
	let deleteDescriptor = -1;
	let previousAllocation: StorageState | undefined;
	let parentWitness: ProcFdParentWitness | undefined;
	let path = "";
	try {
		parentWitness = captureProcFdParentWitness(route, directoryDescriptor, directoryPath);
		path = procFdChildPath(parentWitness, childName);
		deleteDescriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		assertProcFdParentWitness(route, directoryDescriptor, parentWitness);
		previousAllocation = assertVerifiedSegmentIdentity(deleteDescriptor, path, verifiedHandle.identity);
		assertProcFdParentWitness(route, directoryDescriptor, parentWitness);
		const pathStatus = lstatSync(path, { bigint: true });
		const descriptorStatus = fstatSync(deleteDescriptor, { bigint: true });
		if (
			!pathStatus.isFile() ||
			pathStatus.isSymbolicLink() ||
			pathStatus.dev !== descriptorStatus.dev ||
			pathStatus.ino !== descriptorStatus.ino ||
			pathStatus.mode !== descriptorStatus.mode
		) {
			throw new InvalidFrameError("sealed prune target path changed immediately before unlink");
		}
		unlinkSync(path);
	} catch (error) {
		return closeDescriptorsPreservingFailure([deleteDescriptor], error);
	}
	const committedAllocation = previousAllocation ?? verifiedHandle.identity;
	const committedParentWitness = parentWitness;
	let directoryDurability: IncidentRecorderSegmentDirectoryDurability = "unknown";
	const postCommitErrors: unknown[] =
		previousAllocation && committedParentWitness
			? []
			: [new Error("sealed prune unlink completed without its verified mutation evidence")];
	const capturePostCommitError = (error: unknown): void => {
		postCommitErrors.push(error);
	};
	try {
		afterUnlinkBeforeDirectoryFsync?.();
	} catch (error) {
		// This seam models an abrupt stop at the named crash boundary. Crossing it
		// with a directory fsync would erase the durability uncertainty under test.
		const mutationCause = combinePrimaryAndCleanupErrors(
			error,
			runCleanupActionsAttemptAll([() => closeSync(deleteDescriptor)]),
		);
		throw new IncidentRecorderSegmentUnlinkMutationError(mutationCause, committedAllocation, "unknown");
	}
	try {
		fsyncSync(directoryDescriptor);
		directoryDurability = "confirmed";
	} catch (error) {
		capturePostCommitError(error);
	}
	try {
		const heldStatus = fstatSync(verifiedHandle.fileDescriptor, { bigint: true });
		if (Number(heldStatus.nlink) !== committedAllocation.linkCount - 1) {
			throw new InvalidFrameError("sealed prune target link count did not decrease after unlink");
		}
		if (committedParentWitness) {
			assertProcFdParentWitness(route, directoryDescriptor, committedParentWitness);
		}
	} catch (error) {
		capturePostCommitError(error);
	}
	try {
		closeSync(deleteDescriptor);
	} catch (error) {
		capturePostCommitError(error);
	}
	if (postCommitErrors.length > 0) {
		throw new IncidentRecorderSegmentUnlinkMutationError(
			combinePrimaryAndCleanupErrors(postCommitErrors[0], postCommitErrors.slice(1)),
			committedAllocation,
			directoryDurability,
		);
	}
	return committedAllocation;
}

function openRecoveryPruneStorageScope(directory: string): RecoveryPruneStorageScopeLease {
	const sealedDirectory = join(directory, "sealed");
	let rootDescriptor = -1;
	let sealedDescriptor = -1;
	let procFdAuthority: AuthenticatedProcFdRoute | undefined;
	try {
		procFdAuthority = openAuthenticatedProcFdRoute();
		rootDescriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const rootIdentity = directoryIdentity(rootDescriptor, "recovery root");
		sealedDescriptor = openDirectoryChildAtDescriptor(procFdAuthority, rootDescriptor, directory, "sealed");
		const sealedIdentity = directoryIdentity(sealedDescriptor, "sealed recovery path");
		assertDirectoryPathIdentity(directory, rootIdentity, "recovery root");
		assertDirectoryChildIdentityAtDescriptor(
			procFdAuthority,
			rootDescriptor,
			directory,
			"sealed",
			sealedIdentity,
			"sealed recovery entry",
		);
		assertDirectoryPathIdentity(sealedDirectory, sealedIdentity, "sealed recovery path");
		const scope = {
			sealedDirectory,
			fingerprint: recoveryPruneStorageFingerprint(rootIdentity, sealedIdentity),
		};
		return { ...scope, rootDescriptor, sealedDescriptor, procFdAuthority };
	} catch (error) {
		return closeDescriptorsPreservingFailure(
			[
				sealedDescriptor,
				rootDescriptor,
				procFdAuthority?.fdDirectoryDescriptor ?? -1,
				procFdAuthority?.procRootDescriptor ?? -1,
			],
			error,
		);
	}
}

function closeRecoveryPruneStorageScope(scope: RecoveryPruneStorageScopeLease): void {
	closeDescriptorsAttemptAll([
		scope.sealedDescriptor,
		scope.rootDescriptor,
		scope.procFdAuthority.fdDirectoryDescriptor,
		scope.procFdAuthority.procRootDescriptor,
	]);
}

function captureRecoveryPruneStorageScope(directory: string): RecoveryPruneStorageScope {
	const scope = openRecoveryPruneStorageScope(directory);
	try {
		return { sealedDirectory: scope.sealedDirectory, fingerprint: scope.fingerprint };
	} finally {
		closeRecoveryPruneStorageScope(scope);
	}
}

function pathAllocation(path: string): StorageState {
	const fileDescriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
	try {
		assertPrivateRegularFile(fileDescriptor, path);
		return fileAllocation(fileDescriptor);
	} finally {
		closeSync(fileDescriptor);
	}
}

function pathStorageState(path: string, directory: boolean): StorageState {
	const flags = constants.O_RDONLY | constants.O_NOFOLLOW | (directory ? constants.O_DIRECTORY : 0);
	const fileDescriptor = openSync(path, flags);
	const outcome = captureIncidentRecorderOutcome(() => {
		const status = fstatSync(fileDescriptor);
		if (directory ? !status.isDirectory() : !status.isFile()) throw new Error("storage accounting path type changed");
		return fileAllocation(fileDescriptor);
	});
	return settleIncidentRecorderOutcome(outcome, runCleanupActionsAttemptAll([() => closeSync(fileDescriptor)]));
}

function conservativeAllocatedBytes(logicalBytes: number): number {
	return Math.ceil(logicalBytes / 4096) * 4096;
}

function nearestExistingPath(path: string): string {
	let candidate = path;
	while (!pathStatus(candidate)) {
		const parent = dirname(candidate);
		if (parent === candidate) throw new Error("cannot locate an existing filesystem ancestor");
		candidate = parent;
	}
	return candidate;
}

function filesystemAllocationUnit(path: string): number {
	const value = Number(statfsSync(nearestExistingPath(path)).bsize);
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error("filesystem allocation unit is invalid");
	}
	return value;
}

function conservativeDirectoryEntryAllocatedBytes(path: string, entryCount: number): number {
	if (entryCount <= 0) return 0;
	return entryCount * filesystemAllocationUnit(path);
}

function parentDirectoryEffect(
	path: string,
	before: StorageState,
	after: StorageState,
): IncidentRecorderSegmentParentDirectoryEffect {
	return {
		path,
		deviceId: after.deviceId,
		inodeId: after.inodeId,
		beforeAllocatedBytes: before.allocatedBytes,
		afterAllocatedBytes: after.allocatedBytes,
		beforeLogicalBytes: before.logicalBytes,
		afterLogicalBytes: after.logicalBytes,
	};
}

function parseProcStartTime(contents: string): string | undefined {
	const end = contents.lastIndexOf(")");
	if (end < 0) return undefined;
	const fields = contents
		.slice(end + 1)
		.trim()
		.split(/\s+/);
	return fields[19];
}

function defaultOwnerIdentity(): IncidentRecorderSegmentOwnerIdentity {
	const startTime = parseProcStartTime(readFileSync("/proc/self/stat", "utf8"));
	if (!startTime) throw new Error("cannot determine current process start identity");
	return {
		pid: process.pid,
		startTime,
		bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
	};
}

function defaultIsOwnerAlive(identity: IncidentRecorderSegmentOwnerIdentity): boolean {
	let bootId: string;
	try {
		bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
	} catch {
		return true;
	}
	if (bootId !== identity.bootId) return false;
	try {
		return parseProcStartTime(readFileSync(`/proc/${identity.pid}/stat`, "utf8")) === identity.startTime;
	} catch (error) {
		return errnoCode(error) !== "ENOENT";
	}
}

function parseOwnerClaim(value: unknown): OwnerClaim {
	if (
		!isRecord(value) ||
		value.version !== 1 ||
		typeof value.nonce !== "string" ||
		typeof value.pid !== "number" ||
		typeof value.startTime !== "string" ||
		typeof value.bootId !== "string"
	) {
		throw new Error("writer ownership claim is malformed");
	}
	assertSafeNonNegativeInteger(value.pid, "owner pid");
	if (!value.nonce || !value.startTime || !value.bootId) throw new Error("writer ownership claim is malformed");
	return {
		version: 1,
		nonce: value.nonce,
		pid: value.pid,
		startTime: value.startTime,
		bootId: value.bootId,
	};
}

function parseHeader(frame: ParsedFrame): SegmentHeader {
	if (frame.type !== FrameType.Header || frame.ordinal !== 0) throw new InvalidFrameError("segment header is missing");
	const value = parseJson(frame.content, "segment header");
	if (
		!isRecord(value) ||
		value.version !== 2 ||
		value.kind !== "segment-header" ||
		typeof value.segmentId !== "string" ||
		typeof value.segmentSequence !== "number" ||
		typeof value.createdAtMs !== "number"
	) {
		throw new InvalidFrameError("segment header has an invalid schema");
	}
	assertSegmentId(value.segmentId);
	assertSafeNonNegativeInteger(value.segmentSequence, "segment sequence");
	assertSafeNonNegativeInteger(value.createdAtMs, "segment creation time");
	return {
		version: 2,
		kind: "segment-header",
		segmentId: value.segmentId,
		segmentSequence: value.segmentSequence,
		createdAtMs: value.createdAtMs,
	};
}

function parseRecoveryGapValue(value: unknown): IncidentRecorderSegmentRecoveryGap {
	if (
		!isRecord(value) ||
		value.version !== 1 ||
		typeof value.segmentId !== "string" ||
		typeof value.segmentSequence !== "number" ||
		typeof value.ordinal !== "number" ||
		value.reason !== "invalid_or_torn_active_tail" ||
		typeof value.observedAtMs !== "number" ||
		typeof value.invalidOffset !== "number" ||
		typeof value.discardedBytes !== "number" ||
		typeof value.discardedSha256 !== "string"
	) {
		throw new InvalidFrameError("recovery gap has an invalid schema");
	}
	for (const [numberValue, name] of [
		[value.segmentSequence, "gap segment sequence"],
		[value.ordinal, "gap ordinal"],
		[value.observedAtMs, "gap observation time"],
		[value.invalidOffset, "gap invalid offset"],
		[value.discardedBytes, "gap discarded bytes"],
	] as const) {
		assertSafeNonNegativeInteger(numberValue, name);
	}
	assertSegmentId(value.segmentId);
	if (!/^[a-f0-9]{64}$/.test(value.discardedSha256)) throw new InvalidFrameError("gap checksum is invalid");
	return {
		version: 1,
		segmentId: value.segmentId,
		segmentSequence: value.segmentSequence,
		ordinal: value.ordinal,
		reason: "invalid_or_torn_active_tail",
		observedAtMs: value.observedAtMs,
		invalidOffset: value.invalidOffset,
		discardedBytes: value.discardedBytes,
		discardedSha256: value.discardedSha256,
	};
}

function parseRecoveryGap(frame: ParsedFrame): IncidentRecorderSegmentRecoveryGap {
	if (frame.type !== FrameType.RecoveryGap) throw new InvalidFrameError("expected a recovery gap frame");
	return parseRecoveryGapValue(parseJson(frame.content, "recovery gap"));
}

function parseRecordContent(frame: ParsedFrame): { envelope: RecordEnvelope; payload: Buffer } {
	if (frame.type !== FrameType.Record || frame.content.byteLength < 4)
		throw new InvalidFrameError("record frame is invalid");
	const envelopeBytes = frame.content.readUInt32LE(0);
	if (envelopeBytes > FORMAT_MAX_METADATA_BYTES + 4096 || envelopeBytes > frame.content.byteLength - 4) {
		throw new InvalidFrameError("record metadata length is invalid");
	}
	const value = parseJson(frame.content.subarray(4, 4 + envelopeBytes), "record metadata");
	if (
		!isRecord(value) ||
		value.version !== 2 ||
		value.kind !== "record" ||
		typeof value.idempotencyKey !== "string" ||
		typeof value.canonicalContentSha256 !== "string" ||
		typeof value.runId !== "string" ||
		typeof value.sourceId !== "string" ||
		typeof value.observedAtMs !== "number" ||
		typeof value.order !== "string" ||
		typeof value.payloadBytes !== "number" ||
		typeof value.payloadSha256 !== "string"
	) {
		throw new InvalidFrameError("record metadata has an invalid schema");
	}
	assertIdentifier(value.runId, "record runId");
	assertIdentifier(value.sourceId, "record sourceId");
	assertIdentifier(value.idempotencyKey, "record idempotencyKey");
	if (!/^[a-f0-9]{64}$/.test(value.canonicalContentSha256)) {
		throw new InvalidFrameError("record canonical content checksum is invalid");
	}
	assertMetadata(value.metadata);
	assertSafeNonNegativeInteger(value.observedAtMs, "record observation time");
	assertSafeNonNegativeInteger(value.payloadBytes, "record payload bytes");
	assertOrder(value.order);
	if (encodeJson(value.metadata).byteLength > FORMAT_MAX_METADATA_BYTES) {
		throw new InvalidFrameError("record metadata exceeds the fixed format maximum");
	}
	if (value.payloadBytes > FORMAT_MAX_PAYLOAD_BYTES || !/^[a-f0-9]{64}$/.test(value.payloadSha256)) {
		throw new InvalidFrameError("record payload declaration exceeds the fixed format maximum");
	}
	const payload = Buffer.from(frame.content.subarray(4 + envelopeBytes));
	if (payload.byteLength !== value.payloadBytes || sha256(payload) !== value.payloadSha256) {
		throw new InvalidFrameError("record payload integrity check failed");
	}
	const canonical = canonicalRecordIdentity(
		{
			idempotencyKey: value.idempotencyKey,
			runId: value.runId,
			sourceId: value.sourceId,
			observedAtMs: value.observedAtMs,
			order: value.order,
			metadata: value.metadata,
			payload,
		},
		value.payloadBytes,
		value.payloadSha256,
	);
	if (canonical.canonicalContentSha256 !== value.canonicalContentSha256) {
		throw new InvalidFrameError("record canonical content checksum mismatch");
	}
	return {
		envelope: {
			version: 2,
			kind: "record",
			idempotencyKey: value.idempotencyKey,
			canonicalContentSha256: value.canonicalContentSha256,
			runId: value.runId,
			sourceId: value.sourceId,
			observedAtMs: value.observedAtMs,
			order: value.order,
			metadata: value.metadata,
			payloadBytes: value.payloadBytes,
			payloadSha256: value.payloadSha256,
		},
		payload,
	};
}

function indexEntryFromFrame(header: SegmentHeader, frame: ParsedFrame, offset: number): SegmentIndexEntry {
	const { envelope } = parseRecordContent(frame);
	return {
		version: 1,
		segmentId: header.segmentId,
		segmentSequence: header.segmentSequence,
		ordinal: frame.ordinal,
		offset,
		frameBytes: frame.frameBytes,
		payloadBytes: envelope.payloadBytes,
		payloadSha256: envelope.payloadSha256,
		idempotencyKey: envelope.idempotencyKey,
		canonicalContentSha256: envelope.canonicalContentSha256,
		runId: envelope.runId,
		sourceId: envelope.sourceId,
		observedAtMs: envelope.observedAtMs,
		order: envelope.order,
	};
}

function parseIndexEntry(value: unknown): SegmentIndexEntry {
	if (
		!isRecord(value) ||
		value.version !== 1 ||
		typeof value.idempotencyKey !== "string" ||
		typeof value.canonicalContentSha256 !== "string" ||
		typeof value.segmentId !== "string" ||
		typeof value.segmentSequence !== "number" ||
		typeof value.ordinal !== "number" ||
		typeof value.offset !== "number" ||
		typeof value.frameBytes !== "number" ||
		typeof value.payloadBytes !== "number" ||
		typeof value.payloadSha256 !== "string" ||
		typeof value.runId !== "string" ||
		typeof value.sourceId !== "string" ||
		typeof value.observedAtMs !== "number" ||
		typeof value.order !== "string"
	) {
		throw new InvalidFrameError("segment index entry has an invalid schema");
	}
	assertSegmentId(value.segmentId);
	assertIdentifier(value.idempotencyKey, "index idempotencyKey");
	if (!/^[a-f0-9]{64}$/.test(value.canonicalContentSha256)) {
		throw new InvalidFrameError("index canonical content checksum is invalid");
	}
	assertIdentifier(value.runId, "index runId");
	assertIdentifier(value.sourceId, "index sourceId");
	assertOrder(value.order);
	for (const [numberValue, name] of [
		[value.segmentSequence, "index segment sequence"],
		[value.ordinal, "index ordinal"],
		[value.offset, "index offset"],
		[value.frameBytes, "index frame bytes"],
		[value.payloadBytes, "index payload bytes"],
		[value.observedAtMs, "index observation time"],
	] as const) {
		assertSafeNonNegativeInteger(numberValue, name);
	}
	if (value.frameBytes < FRAME_OVERHEAD_BYTES || value.frameBytes > FORMAT_MAX_RECORD_FRAME_BYTES) {
		throw new InvalidFrameError("index record frame length exceeds the fixed format maximum");
	}
	if (value.payloadBytes > FORMAT_MAX_PAYLOAD_BYTES) {
		throw new InvalidFrameError("index payload length exceeds the fixed format maximum");
	}
	if (!/^[a-f0-9]{64}$/.test(value.payloadSha256)) {
		throw new InvalidFrameError("index payload checksum is invalid");
	}
	return {
		version: 1,
		segmentId: value.segmentId,
		segmentSequence: value.segmentSequence,
		ordinal: value.ordinal,
		offset: value.offset,
		frameBytes: value.frameBytes,
		payloadBytes: value.payloadBytes,
		payloadSha256: value.payloadSha256,
		idempotencyKey: value.idempotencyKey,
		canonicalContentSha256: value.canonicalContentSha256,
		runId: value.runId,
		sourceId: value.sourceId,
		observedAtMs: value.observedAtMs,
		order: value.order,
	};
}

function parseIndexDocument(frame: ParsedFrame): SegmentIndexDocument {
	if (frame.type !== FrameType.Index) throw new InvalidFrameError("expected a segment index frame");
	const value = parseJson(frame.content, "segment index");
	if (
		!isRecord(value) ||
		value.version !== 2 ||
		value.kind !== "segment-index" ||
		typeof value.segmentId !== "string" ||
		typeof value.segmentSequence !== "number" ||
		!Array.isArray(value.records) ||
		!Array.isArray(value.recoveryGaps)
	) {
		throw new InvalidFrameError("segment index has an invalid schema");
	}
	assertSegmentId(value.segmentId);
	assertSafeNonNegativeInteger(value.segmentSequence, "index segment sequence");
	if (value.records.length > FORMAT_MAX_RECORDS) throw new InvalidFrameError("segment index has too many records");
	if (value.recoveryGaps.length > FORMAT_MAX_GAPS) throw new InvalidFrameError("segment index has too many gaps");
	return {
		version: 2,
		kind: "segment-index",
		segmentId: value.segmentId,
		segmentSequence: value.segmentSequence,
		records: value.records.map(parseIndexEntry),
		recoveryGaps: value.recoveryGaps.map(parseRecoveryGapValue),
	};
}

function parseFooter(frame: ParsedFrame): SegmentFooter {
	if (frame.type !== FrameType.Footer) throw new InvalidFrameError("expected a sealed footer frame");
	const value = parseJson(frame.content, "sealed footer");
	if (
		!isRecord(value) ||
		value.version !== 2 ||
		value.kind !== "sealed-footer" ||
		typeof value.segmentId !== "string" ||
		typeof value.segmentSequence !== "number" ||
		typeof value.createdAtMs !== "number" ||
		typeof value.sealedAtMs !== "number" ||
		typeof value.reason !== "string" ||
		typeof value.recordCount !== "number" ||
		typeof value.gapCount !== "number" ||
		(value.minObservedAtMs !== null && typeof value.minObservedAtMs !== "number") ||
		(value.maxObservedAtMs !== null && typeof value.maxObservedAtMs !== "number") ||
		typeof value.indexOffset !== "number" ||
		typeof value.indexFrameBytes !== "number" ||
		typeof value.indexSha256 !== "string" ||
		typeof value.contentBytes !== "number" ||
		typeof value.contentSha256 !== "string" ||
		typeof value.idempotencyBloomBase64 !== "string"
	) {
		throw new InvalidFrameError("sealed footer has an invalid schema");
	}
	assertSegmentId(value.segmentId);
	for (const [numberValue, name] of [
		[value.segmentSequence, "footer segment sequence"],
		[value.createdAtMs, "footer creation time"],
		[value.sealedAtMs, "footer seal time"],
		[value.recordCount, "footer record count"],
		[value.gapCount, "footer gap count"],
		[value.indexOffset, "footer index offset"],
		[value.indexFrameBytes, "footer index frame bytes"],
		[value.contentBytes, "footer content bytes"],
	] as const) {
		assertSafeNonNegativeInteger(numberValue, name);
	}
	if (value.minObservedAtMs !== null) assertSafeNonNegativeInteger(value.minObservedAtMs, "footer minimum time");
	if (value.maxObservedAtMs !== null) assertSafeNonNegativeInteger(value.maxObservedAtMs, "footer maximum time");
	if (value.recordCount > FORMAT_MAX_RECORDS || value.gapCount > FORMAT_MAX_GAPS) {
		throw new InvalidFrameError("sealed footer cardinality exceeds the fixed format maximum");
	}
	if (value.reason.length === 0 || value.reason.length > 256)
		throw new InvalidFrameError("sealed footer reason is invalid");
	if (value.indexFrameBytes < FRAME_OVERHEAD_BYTES || value.indexFrameBytes > FORMAT_MAX_INDEX_FRAME_BYTES) {
		throw new InvalidFrameError("sealed footer index length exceeds the fixed format maximum");
	}
	if (!/^[a-f0-9]{64}$/.test(value.indexSha256) || !/^[a-f0-9]{64}$/.test(value.contentSha256)) {
		throw new InvalidFrameError("sealed footer checksum is invalid");
	}
	if (Buffer.from(value.idempotencyBloomBase64, "base64").byteLength !== IDEMPOTENCY_BLOOM_BYTES) {
		throw new InvalidFrameError("sealed footer idempotency bloom is invalid");
	}
	if (
		(value.recordCount === 0) !== (value.minObservedAtMs === null) ||
		(value.recordCount === 0) !== (value.maxObservedAtMs === null)
	) {
		throw new InvalidFrameError("sealed footer time bounds do not match its record count");
	}
	if (
		value.minObservedAtMs !== null &&
		value.maxObservedAtMs !== null &&
		value.minObservedAtMs > value.maxObservedAtMs
	) {
		throw new InvalidFrameError("sealed footer time bounds are reversed");
	}
	return {
		version: 2,
		kind: "sealed-footer",
		segmentId: value.segmentId,
		segmentSequence: value.segmentSequence,
		createdAtMs: value.createdAtMs,
		sealedAtMs: value.sealedAtMs,
		reason: value.reason,
		recordCount: value.recordCount,
		gapCount: value.gapCount,
		minObservedAtMs: value.minObservedAtMs,
		maxObservedAtMs: value.maxObservedAtMs,
		indexOffset: value.indexOffset,
		indexFrameBytes: value.indexFrameBytes,
		indexSha256: value.indexSha256,
		contentBytes: value.contentBytes,
		contentSha256: value.contentSha256,
		idempotencyBloomBase64: value.idempotencyBloomBase64,
	};
}

function ownerClaimsEqual(left: OwnerClaim, right: OwnerClaim): boolean {
	return (
		left.nonce === right.nonce &&
		left.pid === right.pid &&
		left.startTime === right.startTime &&
		left.bootId === right.bootId
	);
}

const OPEN_PLAN_TOKENS = new Set<string>();

function openPathFingerprint(path: string, identityOnly = false): string {
	const status = pathStatus(path);
	if (!status) return "missing";
	const bigintStatus = lstatSync(path, { bigint: true });
	const identity = [bigintStatus.dev.toString(), bigintStatus.ino.toString(), bigintStatus.mode.toString()];
	return (identityOnly ? identity : [...identity, bigintStatus.size.toString(), bigintStatus.mtimeNs.toString()]).join(
		":",
	);
}

function openStateFingerprint(directory: string): string {
	return sha256(
		Buffer.from(
			[
				directory,
				// Sibling churn must not invalidate a plan, but replacing or
				// changing the type/mode of the parent still must.
				openPathFingerprint(dirname(directory), true),
				openPathFingerprint(directory),
				openPathFingerprint(join(directory, "active")),
				openPathFingerprint(join(directory, "sealed")),
				openPathFingerprint(join(directory, OWNER_FILE_NAME)),
			].join("\n"),
			"utf8",
		),
	);
}

export function planIncidentRecorderSegmentStoreOpen(directory: string): IncidentRecorderSegmentOpenPlan {
	if (!directory) throw new Error("directory is required");
	const rootMissing = pathStatus(directory) === undefined;
	const activeMissing = pathStatus(join(directory, "active")) === undefined;
	const sealedMissing = pathStatus(join(directory, "sealed")) === undefined;
	const missingDirectories = Number(rootMissing) + Number(activeMissing) + Number(sealedMissing);
	const parentDirectoryEntriesAtPeak = Number(rootMissing) + Number(activeMissing) + Number(sealedMissing) + 2;
	const mayRecoverActiveTail = !activeMissing;
	const plan = Object.freeze({
		version: 1 as const,
		token: randomUUID(),
		directory,
		stateFingerprint: openStateFingerprint(directory),
		peakAdditionalBytes:
			conservativeAllocatedBytes((missingDirectories + 1) * 4096) +
			conservativeDirectoryEntryAllocatedBytes(directory, parentDirectoryEntriesAtPeak) +
			(mayRecoverActiveTail ? FORMAT_MAX_INDEX_FRAME_BYTES + FORMAT_MAX_FOOTER_FRAME_BYTES + 128 * 1024 : 0),
		peakAdditionalEntries: missingDirectories + 2,
		peakAdditionalInodes: missingDirectories + 1,
		mayRecoverActiveTail,
	});
	OPEN_PLAN_TOKENS.add(plan.token);
	return plan;
}

/**
 * Bound the first root-scoped open before its deferred receipt is applied.
 * This is intentionally conservative: the reservation covers the directory
 * chain, owner temporary/final entries, and a possible active-tail recovery.
 */
export function estimateIncidentRecorderSegmentStoreOpenWithinRoot(
	root: IncidentCasRootMutation,
	directory: readonly string[],
): IncidentRecorderSegmentRootOpenStorageEstimate {
	if (!Array.isArray(directory) || directory.length === 0) {
		throw new TypeError("root-backed segment directory components are required");
	}
	const rootPath = root.relative(...directory);
	const activePath = root.relative(...directory, "active");
	const sealedPath = root.relative(...directory, "sealed");
	const lstatMaybe = (path: IncidentCasRelativePath): BigIntStats | undefined => {
		try {
			return root.lstat(path);
		} catch (error) {
			if (errnoCode(error) === "ENOENT") return undefined;
			throw error;
		}
	};
	const missingDirectoryCount = [rootPath, activePath, sealedPath].filter(
		(path) => lstatMaybe(path) === undefined,
	).length;
	const mayRecoverActiveTail = lstatMaybe(activePath) !== undefined;
	const statfs = root.statfs(root.relative());
	const blockSize = Number(statfs.bsize);
	if (!Number.isSafeInteger(blockSize) || blockSize <= 0) throw new Error("filesystem allocation unit is invalid");
	const directoryEntries = missingDirectoryCount + 2; // owner temporary and final link
	const mutationCount = missingDirectoryCount + directoryEntries + (mayRecoverActiveTail ? 3 : 0);
	return {
		peakAdditionalBytes:
			missingDirectoryCount * blockSize * 2 +
			conservativeAllocatedBytes(blockSize) +
			mutationCount * blockSize +
			(mayRecoverActiveTail ? FORMAT_MAX_INDEX_FRAME_BYTES + FORMAT_MAX_FOOTER_FRAME_BYTES + 128 * 1024 : 0),
		peakAdditionalEntries: directoryEntries,
		// Every open writes a unique temporary owner claim before publishing it.
		// The temporary claim is a new inode even when a stale owner entry is
		// already present, so the peak reservation must not depend on ownerPath's
		// current existence.
		peakAdditionalInodes: missingDirectoryCount + 1,
		mayRecoverActiveTail,
	};
}

function captureOpenStorageEntries(
	directory: string,
	created: { root: boolean; active: boolean; sealed: boolean; owner: boolean },
): IncidentRecorderSegmentOpenStorageEntry[] {
	const definitions = [
		{ path: directory, kind: "root-directory" as const, createdByOpen: created.root, directory: true },
		{
			path: join(directory, "active"),
			kind: "active-directory" as const,
			createdByOpen: created.active,
			directory: true,
		},
		{
			path: join(directory, "sealed"),
			kind: "sealed-directory" as const,
			createdByOpen: created.sealed,
			directory: true,
		},
		{
			path: join(directory, OWNER_FILE_NAME),
			kind: "owner-file" as const,
			createdByOpen: created.owner,
			directory: false,
		},
	];
	return definitions.flatMap((definition) =>
		pathStatus(definition.path)
			? [
					{
						path: definition.path,
						kind: definition.kind,
						createdByOpen: definition.createdByOpen,
						...pathStorageState(definition.path, definition.directory),
					},
				]
			: [],
	);
}

export class IncidentRecorderSegmentStore {
	readonly #directory: string;
	readonly #activeDirectory: string;
	readonly #sealedDirectory: string;
	readonly #maxSegmentBytes: number;
	readonly #maxSegmentAgeMs: number;
	readonly #maxRecordsPerSegment: number;
	readonly #maxRecordBytes: number;
	readonly #maxMetadataBytes: number;
	readonly #maxStartupEntries: number;
	readonly #maxStartupCatalogBytes: number;
	readonly #maxQueryRecords: number;
	readonly #maxQueryBytes: number;
	readonly #maxIdempotencyLookupSegments: number;
	readonly #maxIdempotencyLookupRecords: number;
	readonly #now: () => number;
	readonly #createSegmentId: () => string;
	readonly #onDurableWrite?: (event: IncidentRecorderSegmentDurableWrite) => void;
	readonly #onIndexRead?: (segmentId: string) => void;
	readonly #onRecoveryRead?: (bytes: number) => void;
	readonly #onPruneExpiryCleanupDiagnostic?: (diagnostic: IncidentRecorderPruneExpiryCleanupDiagnostic) => void;
	readonly #faultInjector?: (point: IncidentRecorderSegmentFaultPoint) => void;
	readonly #ownerIdentity: IncidentRecorderSegmentOwnerIdentity;
	readonly #isOwnerAlive: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean;
	readonly #onOpenStorageResult?: (result: IncidentRecorderSegmentOpenResult) => void;
	readonly #rootBacked: boolean;
	readonly #rootDirectoryComponents?: readonly string[];
	#sealed: SegmentSummary[] = [];
	#corrupt: CorruptSegment[] = [];
	#readCatalog: SegmentSummary[] = [];
	#hasUncataloguedCorruptSegment = false;
	#active: ActiveSegment | undefined;
	#ownerClaim: OwnerClaim | undefined;
	#nextSequence = 0;
	#startupEntries = 0;
	#startupCatalogBytes = 0;
	#poisoned: IncidentRecorderSegmentStorePoisonedError | undefined;
	#closed = false;
	readonly #instanceId = randomUUID();
	#generation = 0;
	#stateRevision = 0;
	#appendPlans = new Map<string, FrozenAppendPlan>();
	#readLeases = new Map<string, IncidentRecorderSegmentReadLease>();
	#pruneCursorCapabilities = new Map<string, PruneCursorCapability>();
	#accountingSequence = 0;
	#validatedIdempotencyBloomSegmentIds = new Set<string>();
	#openRemovedPreexistingEntry = false;
	#insideCallback = false;
	#openStorageEntries: IncidentRecorderSegmentOpenStorageEntry[] = [];
	#rootReceiptSequence = 0;
	#rootReceipts: IncidentRecorderSegmentRootReceipt[] = [];

	constructor(
		options: IncidentRecorderSegmentStoreOptions,
		rootConstruction?: IncidentRecorderSegmentStoreRootConstruction,
	) {
		if (!options.directory) throw new Error("directory is required");
		this.#directory = options.directory;
		this.#activeDirectory = join(options.directory, "active");
		this.#sealedDirectory = join(options.directory, "sealed");
		this.#rootBacked = rootConstruction !== undefined;
		this.#rootDirectoryComponents = rootConstruction ? Object.freeze([...rootConstruction.directory]) : undefined;
		this.#maxSegmentBytes = positiveInteger(
			options.maxSegmentBytes,
			DEFAULT_MAX_SEGMENT_BYTES,
			"maxSegmentBytes",
			FORMAT_MAX_SEGMENT_DATA_BYTES,
		);
		this.#maxSegmentAgeMs = positiveInteger(options.maxSegmentAgeMs, DEFAULT_MAX_SEGMENT_AGE_MS, "maxSegmentAgeMs");
		this.#maxRecordsPerSegment = positiveInteger(
			options.maxRecordsPerSegment,
			DEFAULT_MAX_RECORDS_PER_SEGMENT,
			"maxRecordsPerSegment",
			FORMAT_MAX_RECORDS,
		);
		this.#maxRecordBytes = positiveInteger(
			options.maxRecordBytes,
			DEFAULT_MAX_RECORD_BYTES,
			"maxRecordBytes",
			FORMAT_MAX_PAYLOAD_BYTES,
		);
		this.#maxMetadataBytes = positiveInteger(
			options.maxMetadataBytes,
			DEFAULT_MAX_METADATA_BYTES,
			"maxMetadataBytes",
			FORMAT_MAX_METADATA_BYTES,
		);
		this.#maxStartupEntries = positiveInteger(
			options.maxStartupEntries ?? options.maxStartupSegments,
			DEFAULT_MAX_STARTUP_ENTRIES,
			"maxStartupEntries",
			65_536,
		);
		this.#maxStartupCatalogBytes = positiveInteger(
			options.maxStartupCatalogBytes,
			DEFAULT_MAX_STARTUP_CATALOG_BYTES,
			"maxStartupCatalogBytes",
			64 * MEBIBYTE,
		);
		this.#maxQueryRecords = positiveInteger(
			options.maxQueryRecords,
			DEFAULT_MAX_QUERY_RECORDS,
			"maxQueryRecords",
			FORMAT_MAX_RECORDS,
		);
		this.#maxQueryBytes = positiveInteger(
			options.maxQueryBytes,
			DEFAULT_MAX_QUERY_BYTES,
			"maxQueryBytes",
			64 * MEBIBYTE,
		);
		this.#maxIdempotencyLookupSegments = positiveInteger(
			options.maxIdempotencyLookupSegments,
			DEFAULT_MAX_IDEMPOTENCY_LOOKUP_SEGMENTS,
			"maxIdempotencyLookupSegments",
			65_536,
		);
		this.#maxIdempotencyLookupRecords = positiveInteger(
			options.maxIdempotencyLookupRecords,
			DEFAULT_MAX_IDEMPOTENCY_LOOKUP_RECORDS,
			"maxIdempotencyLookupRecords",
			16_777_216,
		);
		if (options.maxFooterBytes !== undefined) positiveInteger(options.maxFooterBytes, 1, "maxFooterBytes");
		if (options.maxRecoveryBytes !== undefined) positiveInteger(options.maxRecoveryBytes, 1, "maxRecoveryBytes");
		if (options.maxRecoveryFrames !== undefined) positiveInteger(options.maxRecoveryFrames, 1, "maxRecoveryFrames");
		this.#now = options.now ?? Date.now;
		this.#createSegmentId = options.createSegmentId ?? randomUUID;
		this.#onDurableWrite = options.onDurableWrite;
		this.#onIndexRead = options.onIndexRead;
		this.#onRecoveryRead = options.onRecoveryRead;
		this.#onPruneExpiryCleanupDiagnostic = options.onPruneExpiryCleanupDiagnostic;
		this.#faultInjector = options.faultInjector;
		this.#ownerIdentity = options.ownerIdentity ?? defaultOwnerIdentity();
		this.#isOwnerAlive = options.isOwnerAlive ?? defaultIsOwnerAlive;
		this.#onOpenStorageResult = options.onOpenStorageResult;
		assertSafeNonNegativeInteger(this.#ownerIdentity.pid, "owner pid");
		if (!this.#ownerIdentity.startTime || !this.#ownerIdentity.bootId)
			throw new Error("owner identity is incomplete");

		if (rootConstruction) {
			this.#openWithinRoot(rootConstruction.root);
			return;
		}

		const openPlan = options.openPlan ?? planIncidentRecorderSegmentStoreOpen(this.#directory);
		if (
			openPlan.version !== 1 ||
			openPlan.directory !== this.#directory ||
			!OPEN_PLAN_TOKENS.delete(openPlan.token) ||
			openPlan.stateFingerprint !== openStateFingerprint(this.#directory)
		) {
			throw new Error("open plan is stale, mismatched, or already consumed");
		}
		options.onOpenAdmission?.(openPlan);
		if (openPlan.stateFingerprint !== openStateFingerprint(this.#directory)) {
			throw new Error("open state changed during admission; replan required");
		}
		const rootParentPath = dirname(this.#directory);
		let rootParentBefore: StorageState | undefined;
		let rootBeforeChildren: StorageState | undefined;
		let rootCreated = false;
		let activeDirectoryCreated = false;
		let sealedDirectoryCreated = false;
		try {
			rootParentBefore = pathStorageState(rootParentPath, true);
			rootCreated = pathStatus(this.#directory) === undefined;
			ensurePrivateDirectory(this.#directory);
			rootBeforeChildren = pathStorageState(this.#directory, true);
			activeDirectoryCreated = pathStatus(this.#activeDirectory) === undefined;
			ensurePrivateDirectory(this.#activeDirectory);
			sealedDirectoryCreated = pathStatus(this.#sealedDirectory) === undefined;
			ensurePrivateDirectory(this.#sealedDirectory);
			this.#acquireOwnership();
			this.#loadSegments();
			this.#openStorageEntries = captureOpenStorageEntries(this.#directory, {
				root: rootCreated,
				active: activeDirectoryCreated,
				sealed: sealedDirectoryCreated,
				owner: true,
			});
			this.#onOpenStorageResult?.({
				phase: "opened",
				complete: true,
				reconciliation: this.#openRemovedPreexistingEntry ? "full-dev-inode-required" : "incremental-complete",
				entries: this.getOpenStorageEntries(),
				parentEffects: [
					parentDirectoryEffect(rootParentPath, rootParentBefore, pathStorageState(rootParentPath, true)),
					parentDirectoryEffect(this.#directory, rootBeforeChildren, pathStorageState(this.#directory, true)),
				],
			});
		} catch (error) {
			this.#closeActiveDescriptor();
			try {
				this.#releaseOwnership();
			} catch {
				// Preserve the initiating error; a mismatched owner claim is deliberately left in place.
			}
			try {
				this.#onOpenStorageResult?.({
					phase: "failed",
					complete: false,
					reconciliation: "full-dev-inode-required",
					entries: captureOpenStorageEntries(this.#directory, {
						root: rootCreated,
						active: activeDirectoryCreated,
						sealed: sealedDirectoryCreated,
						owner: false,
					}),
					parentEffects: [
						...(rootParentBefore
							? [parentDirectoryEffect(rootParentPath, rootParentBefore, pathStorageState(rootParentPath, true))]
							: []),
						...(rootBeforeChildren && pathStatus(this.#directory)
							? [
									parentDirectoryEffect(
										this.#directory,
										rootBeforeChildren,
										pathStorageState(this.#directory, true),
									),
								]
							: []),
					],
					error: errorText(error),
				});
			} catch {
				// The initiating construction error remains authoritative.
			}
			throw error;
		}
	}

	/**
	 * Open the store through one already-admitted recorder-root capability. The
	 * capability is used only during this synchronous call and is not retained.
	 */
	static openWithinRoot(
		root: IncidentCasRootMutation,
		options: IncidentRecorderSegmentStoreWithinRootOptions,
	): IncidentRecorderSegmentStore {
		if (!options || !Array.isArray(options.directory) || options.directory.length === 0) {
			throw new TypeError("root-backed segment directory components are required");
		}
		const directoryComponents = Object.freeze([...options.directory]);
		const directory = root.publicPath(root.relative(...directoryComponents));
		return new IncidentRecorderSegmentStore({ ...options, directory }, { root, directory: directoryComponents });
	}

	/** Return and consume root-scoped receipts after the surrounding CAS call commits. */
	drainWithinRootReceipts(): readonly IncidentRecorderSegmentRootReceipt[] {
		if (!this.#rootBacked) throw new Error("raw segment stores do not produce root receipts");
		const receipts = this.#rootReceipts;
		this.#rootReceipts = [];
		return receipts;
	}

	/**
	 * Append using a caller-owned root capability. Plans are single-use and may
	 * not cross a root callback boundary.
	 */
	appendWithinRoot(
		root: IncidentCasRootMutation,
		input: IncidentRecorderSegmentAppendInput,
		admit?: (estimate: IncidentRecorderSegmentAppendStorageEstimate) => void,
	): IncidentRecorderSegmentAppendResult {
		this.#assertRootBacked("appendWithinRoot");
		this.#assertUsable();
		const planned = this.#planAppendWithinRoot(root, input, admit);
		return this.#commitAppendPlanWithinRoot(root, planned);
	}

	/** Plan an append while retaining no root capability or writable file view. */
	planAppendWithinRoot(
		root: IncidentCasRootMutation,
		input: IncidentRecorderSegmentAppendInput,
		admit?: (estimate: IncidentRecorderSegmentAppendStorageEstimate) => void,
	): IncidentRecorderSegmentAppendPlan {
		return this.#planAppendWithinRoot(root, input, admit);
	}

	commitAppendPlanWithinRoot(
		root: IncidentCasRootMutation,
		plan: IncidentRecorderSegmentAppendPlan,
	): IncidentRecorderSegmentAppendResult {
		return this.#commitAppendPlanWithinRoot(root, plan);
	}

	/** Close through the root capability and return ordered open/durable receipts. */
	closeWithinRoot(root: IncidentCasRootMutation): readonly IncidentRecorderSegmentRootReceipt[] {
		this.#assertRootBacked("closeWithinRoot");
		this.#closeWithinRoot(root);
		return this.drainWithinRootReceipts();
	}

	sealWithinRoot(root: IncidentCasRootMutation, reason: string): void {
		this.#assertRootBacked("sealWithinRoot");
		this.#assertUsable();
		if (reason.length === 0 || reason.length > 256) throw new Error("seal reason must contain 1 to 256 characters");
		this.#sealActiveWithinRoot(root, reason);
		this.#stateRevision += 1;
	}

	getOpenStorageEntries(): readonly IncidentRecorderSegmentOpenStorageEntry[] {
		return this.#openStorageEntries.map((entry) => ({ ...entry }));
	}

	get isRootBacked(): boolean {
		return this.#rootBacked;
	}

	#assertRootBacked(operation: string): void {
		if (!this.#rootBacked) throw new Error(`${operation} is available only for root-backed segment stores`);
	}

	#assertRawMutation(operation: string): void {
		if (this.#rootBacked) {
			throw new Error(`${operation} is unavailable for root-backed segment stores; use ${operation}WithinRoot`);
		}
	}

	#assertRawRead(operation: string): void {
		if (this.#rootBacked) {
			throw new Error(`${operation} is unavailable for root-backed segment stores; use ${operation}WithinRoot`);
		}
	}

	#assertUsable(): void {
		if (this.#poisoned) throw this.#poisoned;
		if (this.#closed) throw new Error("incident recorder segment store is closed");
		if (this.#insideCallback) throw new Error("incident recorder segment store callback reentrancy is forbidden");
	}

	#emitDurable(
		event: Omit<IncidentRecorderSegmentDurableWrite, "eventId" | "accountingSequence" | "reconciliation">,
	): void {
		this.#accountingSequence += 1;
		const durable = {
			...event,
			eventId: `${this.#instanceId}:${String(this.#accountingSequence)}`,
			accountingSequence: this.#accountingSequence,
			reconciliation: "apply-by-event-id-then-reconcile-dev-inode" as const,
		};
		if (this.#rootBacked) {
			this.#rootReceipts.push(
				Object.freeze({ kind: "durable" as const, sequence: ++this.#rootReceiptSequence, event: durable }),
			);
			return;
		}
		if (!this.#onDurableWrite) return;
		this.#insideCallback = true;
		try {
			this.#onDurableWrite(durable);
		} finally {
			this.#insideCallback = false;
		}
	}

	#emitRootOpen(result: IncidentRecorderSegmentOpenResult): void {
		if (!this.#rootBacked) return;
		this.#rootReceipts.push(Object.freeze({ kind: "open" as const, sequence: ++this.#rootReceiptSequence, result }));
	}

	#rootPath(root: IncidentCasRootMutation, ...components: string[]): IncidentCasRelativePath {
		const base = this.#rootDirectoryComponents;
		if (!base) throw new Error("root-backed segment directory is unavailable");
		return root.relative(...base, ...components);
	}

	#rootPathString(root: IncidentCasRootMutation, ...components: string[]): string {
		return root.publicPath(this.#rootPath(root, ...components));
	}

	#rootExists(root: IncidentCasRootMutation, path: IncidentCasRelativePath): boolean {
		try {
			return root.exists(path);
		} catch (error) {
			if (errnoCode(error) === "ENOENT") return false;
			throw error;
		}
	}

	#rootStorageState(root: IncidentCasRootMutation, path: IncidentCasRelativePath, directory: boolean): StorageState {
		const status = root.stat(path);
		if (directory ? !status.isDirectory() : !status.isFile()) throw new Error("storage accounting path type changed");
		const logicalBytes = Number(status.size);
		const blocks = Number(status.blocks);
		const linkCount = Number(status.nlink);
		const allocatedBytes = blocks * 512;
		if (
			!Number.isSafeInteger(logicalBytes) ||
			logicalBytes < 0 ||
			!Number.isSafeInteger(blocks) ||
			blocks < 0 ||
			!Number.isSafeInteger(allocatedBytes) ||
			allocatedBytes < 0 ||
			!Number.isSafeInteger(linkCount) ||
			linkCount < 0
		)
			throw new Error("storage accounting metadata exceeded safe integer bounds");
		return {
			deviceId: status.dev.toString(),
			inodeId: status.ino.toString(),
			linkCount,
			logicalBytes,
			allocatedBytes,
		};
	}

	#rootDirectoryEffect(
		root: IncidentCasRootMutation,
		path: IncidentCasRelativePath,
		pathString: string,
		before: StorageState,
	): IncidentRecorderSegmentParentDirectoryEffect {
		return parentDirectoryEffect(pathString, before, this.#rootStorageState(root, path, true));
	}

	#rootDirectoryNames(root: IncidentCasRootMutation, path: IncidentCasRelativePath): string[] {
		const names: string[] = [];
		let afterName: string | undefined;
		for (;;) {
			const page = root.directoryPage(path, {
				...(afterName === undefined ? {} : { afterName }),
				limit: 1024,
				scanLimit: this.#maxStartupEntries,
			});
			for (const entry of page.entries) {
				this.#accountStartupEntry(entry.name);
				names.push(entry.name);
			}
			if (page.complete) return names;
			if (page.entries.length === 0) throw new Error("root directory scan made no progress");
			afterName = page.entries.at(-1)?.name;
			if (!afterName) throw new Error("root directory scan cursor is missing");
		}
	}

	#rootReadOwnerClaim(root: IncidentCasRootMutation, path: IncidentCasRelativePath): OwnerClaim {
		const bytes = root.readFile(path, 4096);
		if (bytes.byteLength === 0) throw new Error("writer ownership claim is malformed");
		return parseOwnerClaim(parseJson(bytes, "writer ownership claim"));
	}

	#acquireOwnershipWithinRoot(root: IncidentCasRootMutation): void {
		const ownerPath = this.#rootPath(root, OWNER_FILE_NAME);
		const abandoned: IncidentCasRelativePath[] = [];
		for (let attempt = 0; attempt < 16; attempt += 1) {
			const claim: OwnerClaim = { version: 1, nonce: randomUUID(), ...this.#ownerIdentity };
			const temporaryPath = this.#rootPath(root, `.writer-owner-${claim.nonce}.tmp`);
			const bytes = Buffer.from(`${JSON.stringify(claim)}\n`, "utf8");
			try {
				root.writeFileExclusive(temporaryPath, bytes, 0o600);
				try {
					root.hardLink(temporaryPath, ownerPath);
					this.#ownerClaim = claim;
					root.fsyncDirectory(this.#rootPath(root));
					root.unlinkFile(temporaryPath);
					root.fsyncDirectory(this.#rootPath(root));
					for (const stalePath of abandoned) {
						if (this.#rootExists(root, stalePath)) {
							root.unlinkFile(stalePath);
							this.#openRemovedPreexistingEntry = true;
						}
					}
					if (abandoned.length > 0) root.fsyncDirectory(this.#rootPath(root));
					return;
				} catch (error) {
					if (errnoCode(error) !== "EEXIST") throw error;
					if (this.#rootExists(root, temporaryPath)) root.unlinkFile(temporaryPath);
					const existing = this.#rootReadOwnerClaim(root, ownerPath);
					if (this.#isOwnerAlive(existing))
						throw new Error("incident recorder segment store is already owned by a live writer");
					const abandonedPath = this.#rootPath(root, `.writer-owner-stale-${claim.nonce}`);
					try {
						root.rename(ownerPath, abandonedPath);
					} catch (renameError) {
						if (errnoCode(renameError) === "ENOENT") continue;
						throw renameError;
					}
					root.fsyncDirectory(this.#rootPath(root));
					const moved = this.#rootReadOwnerClaim(root, abandonedPath);
					if (!ownerClaimsEqual(existing, moved)) {
						try {
							root.hardLink(abandonedPath, ownerPath);
							root.fsyncDirectory(this.#rootPath(root));
						} catch {
							// A concurrent claimant wins; retain the moved evidence and fail closed.
						}
						throw new Error("writer ownership claim changed during stale recovery");
					}
					abandoned.push(abandonedPath);
				}
			} finally {
				if (this.#rootExists(root, temporaryPath)) root.unlinkFile(temporaryPath);
			}
		}
		throw new Error("could not acquire unique incident recorder writer ownership");
	}

	#releaseOwnershipWithinRoot(root: IncidentCasRootMutation): void {
		const claim = this.#ownerClaim;
		if (!claim) return;
		const ownerPath = this.#rootPath(root, OWNER_FILE_NAME);
		if (!this.#rootExists(root, ownerPath)) {
			this.#ownerClaim = undefined;
			return;
		}
		const current = this.#rootReadOwnerClaim(root, ownerPath);
		if (!ownerClaimsEqual(claim, current)) throw new Error("writer ownership claim changed while held");
		root.unlinkFile(ownerPath);
		root.fsyncDirectory(this.#rootPath(root));
		this.#ownerClaim = undefined;
	}

	#withActiveSegmentFileWithinRoot<T>(
		root: IncidentCasRootMutation,
		access: "read" | "read_write",
		operation: (file: IncidentRecorderSegmentFileView) => T,
	): T {
		const active = this.#active;
		if (!active) throw new Error("active segment is unavailable");
		const relative = this.#rootPath(root, "active", `${basename(active.path).replace(/\.open$/, "")}.open`);
		return root.withFile(relative, { access }, (file) => {
			const path = this.#rootPathString(root, "active", basename(active.path));
			assertPrivateRegularFile(file, path);
			if (!sameStorageState(fileAllocation(file), active.identity))
				throw new Error("active segment identity changed before scoped operation");
			return operation(file);
		});
	}

	#readSealedSummaryWithinRoot(root: IncidentCasRootMutation, name: string): SegmentSummary {
		const path = this.#rootPathString(root, "sealed", name);
		const relative = this.#rootPath(root, "sealed", name);
		return root.withFile(relative, { access: "read" }, (file) => {
			assertPrivateRegularFile(file, path);
			const fileBytes = Number(file.stat().size);
			if (
				!Number.isSafeInteger(fileBytes) ||
				fileBytes < FRAME_OVERHEAD_BYTES * 3 ||
				fileBytes > FORMAT_MAX_ACTIVE_BYTES + FORMAT_MAX_INDEX_FRAME_BYTES + FORMAT_MAX_FOOTER_FRAME_BYTES
			)
				throw new InvalidFrameError("sealed segment size exceeds the fixed format maximum");
			const header = parseHeader(parseFrameAt(file, 0, fileBytes));
			const trailer = Buffer.alloc(FRAME_TRAILER_BYTES);
			readFully(file, trailer, fileBytes - FRAME_TRAILER_BYTES);
			if (!trailer.subarray(4).equals(FRAME_END_MAGIC))
				throw new InvalidFrameError("sealed footer trailer is missing");
			const footerFrameBytes = trailer.readUInt32LE(0);
			if (footerFrameBytes < FRAME_OVERHEAD_BYTES || footerFrameBytes > FORMAT_MAX_FOOTER_FRAME_BYTES)
				throw new InvalidFrameError("sealed footer length exceeds the fixed format maximum");
			const footerOffset = fileBytes - footerFrameBytes;
			const footerFrame = parseFrameAt(file, footerOffset, fileBytes);
			const footer = parseFooter(footerFrame);
			if (
				footer.segmentId !== header.segmentId ||
				footer.segmentSequence !== header.segmentSequence ||
				footer.createdAtMs !== header.createdAtMs ||
				footer.indexOffset < FRAME_OVERHEAD_BYTES + parseFrameAt(file, 0, fileBytes).frameBytes ||
				footer.contentBytes !== footer.indexOffset + footer.indexFrameBytes ||
				footer.contentBytes + footerFrame.frameBytes !== fileBytes ||
				footerFrame.ordinal !== footer.recordCount + footer.gapCount + 2 ||
				name !== `${header.segmentId}.segment`
			)
				throw new InvalidFrameError("sealed footer identity or bounds are invalid");
			return { header, footer, path, fileBytes };
		});
	}

	#loadSegmentsWithinRoot(root: IncidentCasRootMutation): void {
		const activeDirectory = this.#rootPath(root, "active");
		const sealedDirectory = this.#rootPath(root, "sealed");
		const activeNames = this.#rootDirectoryNames(root, activeDirectory);
		const sealedNames = this.#rootDirectoryNames(root, sealedDirectory);
		let cleanedTemporary = false;
		for (const name of activeNames) {
			if (!/^\.creating-[A-Za-z0-9_-]+\.tmp$/.test(name)) continue;
			root.unlinkFile(this.#rootPath(root, "active", name));
			this.#openRemovedPreexistingEntry = true;
			cleanedTemporary = true;
		}
		if (cleanedTemporary) root.fsyncDirectory(activeDirectory);
		for (const name of sealedNames) {
			if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.segment$/.test(name)) continue;
			try {
				const summary = this.#readSealedSummaryWithinRoot(root, name);
				if (this.#sealed.some((candidate) => candidate.header.segmentId === summary.header.segmentId))
					throw new InvalidFrameError("duplicate sealed segment identity");
				this.#accountSummary(summary);
				this.#sealed.push(summary);
			} catch (error) {
				if (
					error instanceof SegmentCatalogBudgetExceededError ||
					error instanceof IncidentRecorderDescriptorCleanupError
				)
					throw error;
				this.#corrupt.push({
					segmentId: name.slice(0, -".segment".length),
					path: this.#rootPathString(root, "sealed", name),
					reason: errorText(error),
				});
			}
		}
		const openNames = activeNames.filter((name) => /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.open$/.test(name));
		if (openNames.length > 1) throw new Error("multiple active segment files violate single-writer ownership");
		if (openNames.length === 1) {
			const recovered = this.#recoverActiveWithinRoot(root, openNames[0] ?? "missing");
			if ("footer" in recovered) {
				const existingIndex = this.#sealed.findIndex(
					(summary) => summary.header.segmentId === recovered.header.segmentId,
				);
				if (existingIndex >= 0) this.#sealed[existingIndex] = recovered;
				else {
					this.#accountSummary(recovered);
					this.#sealed.push(recovered);
				}
			} else {
				this.#active = recovered;
				this.#startupCatalogBytes += 512 + Buffer.byteLength(recovered.path, "utf8");
				if (this.#startupCatalogBytes > this.#maxStartupCatalogBytes)
					throw new Error("segment catalog exceeds maxStartupCatalogBytes");
			}
		}
		this.#sealed.sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
		for (let index = 1; index < this.#sealed.length; index += 1) {
			if (this.#sealed[index]?.header.segmentSequence === this.#sealed[index - 1]?.header.segmentSequence)
				throw new InvalidFrameError("duplicate sealed segment sequence");
		}
		const sequences = this.#sealed.map((summary) => summary.header.segmentSequence);
		for (const corrupt of this.#corrupt) if (corrupt.summary) sequences.push(corrupt.summary.header.segmentSequence);
		if (this.#active) sequences.push(this.#active.header.segmentSequence);
		if (new Set(sequences).size !== sequences.length) throw new InvalidFrameError("duplicate segment sequence");
		this.#nextSequence = sequences.length === 0 ? 0 : Math.max(...sequences) + 1;
		this.#refreshReadCatalog();
	}

	#openWithinRoot(root: IncidentCasRootMutation): void {
		const directory = this.#rootPath(root);
		const active = this.#rootPath(root, "active");
		const sealed = this.#rootPath(root, "sealed");
		const directoryPath = this.#rootPathString(root);
		const directoryComponents = this.#rootDirectoryComponents;
		if (!directoryComponents) throw new Error("root-backed segment directory is unavailable");
		const parent = root.relative(...directoryComponents.slice(0, -1));
		const parentPath = root.publicPath(parent);
		const parentBefore = this.#rootStorageState(root, parent, true);
		const rootCreated = !this.#rootExists(root, directory);
		const activeCreated = !this.#rootExists(root, active);
		const sealedCreated = !this.#rootExists(root, sealed);
		const ownerPath = this.#rootPath(root, OWNER_FILE_NAME);
		const ownerCreated = !this.#rootExists(root, ownerPath);
		try {
			root.mkdirPrivate(directory, true);
			root.mkdirPrivate(active, true);
			root.mkdirPrivate(sealed, true);
			// Persist the directory-chain entry in its retained parent before
			// publishing the owner claim and any segment records.
			root.fsyncDirectory(parent);
			this.#acquireOwnershipWithinRoot(root);
			this.#loadSegmentsWithinRoot(root);
			const entries = [
				{
					path: directoryPath,
					kind: "root-directory" as const,
					createdByOpen: rootCreated,
					rel: directory,
					dir: true,
				},
				{
					path: this.#rootPathString(root, "active"),
					kind: "active-directory" as const,
					createdByOpen: activeCreated,
					rel: active,
					dir: true,
				},
				{
					path: this.#rootPathString(root, "sealed"),
					kind: "sealed-directory" as const,
					createdByOpen: sealedCreated,
					rel: sealed,
					dir: true,
				},
				{
					path: this.#rootPathString(root, OWNER_FILE_NAME),
					kind: "owner-file" as const,
					createdByOpen: ownerCreated,
					rel: ownerPath,
					dir: false,
				},
			].flatMap((entry) =>
				this.#rootExists(root, entry.rel)
					? [
							{
								path: entry.path,
								kind: entry.kind,
								createdByOpen: entry.createdByOpen,
								...this.#rootStorageState(root, entry.rel, entry.dir),
							},
						]
					: [],
			);
			this.#openStorageEntries = entries;
			this.#emitRootOpen({
				phase: "opened",
				complete: true,
				reconciliation: this.#openRemovedPreexistingEntry ? "full-dev-inode-required" : "incremental-complete",
				entries: this.getOpenStorageEntries(),
				parentEffects: [
					parentDirectoryEffect(parentPath, parentBefore, this.#rootStorageState(root, parent, true)),
				],
			});
		} catch (error) {
			try {
				// A constructor failure can occur after ownership was acquired but
				// before the store becomes reachable by its caller. Release that
				// claim while the root capability is still scoped, preserving the
				// original failure as authoritative.
				this.#releaseOwnershipWithinRoot(root);
			} catch {}
			try {
				this.#emitRootOpen({
					phase: "failed",
					complete: false,
					reconciliation: "full-dev-inode-required",
					entries: [],
					parentEffects: [],
					error: errorText(error),
				});
			} catch {}
			throw error;
		}
	}

	#selectUniqueSegmentIdWithinRoot(root: IncidentCasRootMutation): string {
		if (this.#corrupt.some((segment) => !segment.summary))
			throw new Error("cannot allocate a stable segment sequence while a corrupt segment identity is unknown");
		for (let attempt = 0; attempt < 16; attempt += 1) {
			const candidate = this.#createSegmentId();
			assertSegmentId(candidate);
			if (
				!this.#rootExists(root, this.#rootPath(root, "active", `${candidate}.open`)) &&
				!this.#rootExists(root, this.#rootPath(root, "sealed", `${candidate}.segment`))
			)
				return candidate;
		}
		throw new Error("createSegmentId did not provide a unique segment identity");
	}

	#promoteActiveFileWithinRoot(
		root: IncidentCasRootMutation,
		active: ActiveSegment,
		footer: SegmentFooter,
		fileBytes: number,
	): SegmentSummary {
		const name = basename(active.path);
		const segmentName = name.endsWith(".open") ? name.slice(0, -".open".length) : name;
		const activePath = this.#rootPath(root, "active", name);
		const sealedPath = this.#rootPath(root, "sealed", `${segmentName}.segment`);
		let linked = false;
		try {
			root.hardLink(activePath, sealedPath);
			linked = true;
		} catch (error) {
			if (errnoCode(error) !== "EEXIST") throw error;
			const activeStatus = root.lstat(activePath);
			const sealedStatus = root.lstat(sealedPath);
			if (
				!activeStatus?.isFile() ||
				activeStatus.isSymbolicLink() ||
				!sealedStatus?.isFile() ||
				sealedStatus.isSymbolicLink() ||
				activeStatus.dev !== sealedStatus.dev ||
				activeStatus.ino !== sealedStatus.ino
			)
				throw new Error("sealed promotion refused to clobber an existing segment identity");
		}
		if (linked) this.#faultInjector?.("after-sealed-link-before-directory-fsync");
		root.fsyncFile(sealedPath);
		root.fsyncDirectory(this.#rootPath(root, "sealed"));
		const activeStatus = root.lstat(activePath);
		const sealedStatus = root.lstat(sealedPath);
		if (
			!activeStatus?.isFile() ||
			!sealedStatus?.isFile() ||
			activeStatus.dev !== sealedStatus.dev ||
			activeStatus.ino !== sealedStatus.ino
		)
			throw new Error("sealed promotion source changed before removal");
		root.unlinkFile(activePath);
		root.fsyncDirectory(this.#rootPath(root, "active"));
		return {
			header: active.header,
			footer,
			path: this.#rootPathString(root, "sealed", `${segmentName}.segment`),
			fileBytes,
		};
	}

	#recoverActiveWithinRoot(root: IncidentCasRootMutation, name: string): ActiveSegment | SegmentSummary {
		const relative = this.#rootPath(root, "active", name);
		const path = this.#rootPathString(root, "active", name);
		return root.withFile(relative, { access: "read_write" }, (file) => {
			assertPrivateRegularFile(file, path);
			const fileSize = Number(file.stat().size);
			const previousAllocation = fileAllocation(file);
			if (
				!Number.isSafeInteger(fileSize) ||
				fileSize < FRAME_OVERHEAD_BYTES ||
				fileSize > FORMAT_MAX_ACTIVE_BYTES + FORMAT_MAX_INDEX_FRAME_BYTES + FORMAT_MAX_FOOTER_FRAME_BYTES
			)
				throw new InvalidFrameError("active segment size exceeds the fixed format maximum");
			const headerFrame = parseFrameAt(file, 0, fileSize);
			const header = parseHeader(headerFrame);
			if (name !== `${header.segmentId}.open`)
				throw new InvalidFrameError("active segment filename does not match its header identity");
			const active: ActiveSegment = {
				header,
				path,
				identity: previousAllocation,
				size: headerFrame.frameBytes,
				nextOrdinal: 1,
				records: [],
				recoveryGaps: [],
			};
			let offset = headerFrame.frameBytes;
			let invalidError: unknown;
			while (offset < fileSize) {
				try {
					const frame = parseFrameAt(file, offset, fileSize);
					if (frame.ordinal !== active.nextOrdinal)
						throw new InvalidFrameError("active frame ordinal is not contiguous");
					if (frame.type === FrameType.Record) {
						if (active.records.length >= FORMAT_MAX_RECORDS)
							throw new InvalidFrameError("active segment has too many records");
						active.records.push(indexEntryFromFrame(header, frame, offset));
					} else if (frame.type === FrameType.RecoveryGap) {
						const gap = parseRecoveryGap(frame);
						if (
							active.recoveryGaps.length >= FORMAT_MAX_GAPS ||
							gap.segmentId !== header.segmentId ||
							gap.segmentSequence !== header.segmentSequence ||
							gap.ordinal !== frame.ordinal ||
							gap.invalidOffset !== offset
						)
							throw new InvalidFrameError("active recovery gap identity is invalid");
						active.recoveryGaps.push(gap);
					} else if (frame.type === FrameType.Index) {
						const index = parseIndexDocument(frame);
						const footerFrame = parseFrameAt(file, offset + frame.frameBytes, fileSize);
						const footer = parseFooter(footerFrame);
						if (offset + frame.frameBytes + footerFrame.frameBytes !== fileSize)
							throw new InvalidFrameError("sealed active segment has trailing bytes");
						this.#validateIndex(header, footer, frame, index);
						if (
							footer.indexOffset !== offset ||
							footer.contentBytes !== offset + frame.frameBytes ||
							footerFrame.ordinal !== frame.ordinal + 1 ||
							hashFileRange(file, 0, footer.contentBytes, this.#onRecoveryRead) !== footer.contentSha256
						)
							throw new InvalidFrameError("sealed active segment footer or content checksum is invalid");
						file.sync();
						return this.#promoteActiveFileWithinRoot(root, active, footer, fileSize);
					} else {
						throw new InvalidFrameError("unexpected frame type in active segment");
					}
					offset += frame.frameBytes;
					active.size = offset;
					active.nextOrdinal += 1;
				} catch (error) {
					invalidError = error;
					break;
				}
			}
			if (invalidError !== undefined) {
				if (active.recoveryGaps.length >= FORMAT_MAX_GAPS)
					throw new InvalidFrameError("active recovery gap limit reached");
				const discardedBytes = fileSize - offset;
				const gap: IncidentRecorderSegmentRecoveryGap = {
					version: 1,
					segmentId: header.segmentId,
					segmentSequence: header.segmentSequence,
					ordinal: active.nextOrdinal,
					reason: "invalid_or_torn_active_tail",
					observedAtMs: this.#now(),
					invalidOffset: offset,
					discardedBytes,
					discardedSha256: hashFileRange(file, offset, discardedBytes, this.#onRecoveryRead),
				};
				const gapFrame = encodeFrame(FrameType.RecoveryGap, gap.ordinal, encodeJson(gap));
				writeFullyAt(file, gapFrame, offset);
				file.sync();
				this.#faultInjector?.("after-recovery-gap-fsync-before-truncate");
				file.truncate(offset + gapFrame.byteLength);
				file.sync();
				active.recoveryGaps.push(gap);
				active.size = offset + gapFrame.byteLength;
				active.nextOrdinal += 1;
				const allocation = fileAllocation(file);
				active.identity = allocation;
				this.#emitDurable({
					kind: "recovery-gap",
					segmentId: header.segmentId,
					path,
					entryChange: "same-inode-growth",
					entryDelta: 0,
					inodeDelta: 0,
					previousLogicalBytes: previousAllocation.logicalBytes,
					previousAllocatedBytes: previousAllocation.allocatedBytes,
					...allocation,
					parentEffects: [],
				});
			}
			return active;
		});
	}

	#createActiveSegmentWithinRoot(
		root: IncidentCasRootMutation,
		createdAtMs = this.#now(),
		plannedSegmentId?: string,
	): ActiveSegment {
		const segmentId = plannedSegmentId ?? this.#selectUniqueSegmentIdWithinRoot(root);
		assertSegmentId(segmentId);
		const activeName = `${segmentId}.open`;
		if (
			this.#rootExists(root, this.#rootPath(root, "active", activeName)) ||
			this.#rootExists(root, this.#rootPath(root, "sealed", `${segmentId}.segment`))
		)
			throw new Error("planned segment identity is no longer unique");
		const header: SegmentHeader = {
			version: 2,
			kind: "segment-header",
			segmentId,
			segmentSequence: this.#nextSequence,
			createdAtMs,
		};
		assertSafeNonNegativeInteger(header.createdAtMs, "segment creation time");
		const headerFrame = encodeFrame(FrameType.Header, 0, encodeJson(header));
		const temporaryName = `.creating-${segmentId}-${randomUUID()}.tmp`;
		const temporaryPath = this.#rootPath(root, "active", temporaryName);
		const activePath = this.#rootPath(root, "active", activeName);
		const activeParentBefore = this.#rootStorageState(root, this.#rootPath(root, "active"), true);
		try {
			root.writeFileExclusive(temporaryPath, headerFrame, 0o600);
			this.#faultInjector?.("after-header-fsync-before-publish");
			root.hardLink(temporaryPath, activePath);
			root.fsyncDirectory(this.#rootPath(root, "active"));
			root.unlinkFile(temporaryPath);
			root.fsyncDirectory(this.#rootPath(root, "active"));
			const active: ActiveSegment = {
				header,
				path: this.#rootPathString(root, "active", activeName),
				identity: this.#rootStorageState(root, activePath, false),
				size: headerFrame.byteLength,
				nextOrdinal: 1,
				records: [],
				recoveryGaps: [],
			};
			this.#active = active;
			this.#nextSequence += 1;
			this.#emitDurable({
				kind: "segment-created",
				segmentId,
				path: active.path,
				entryChange: "published",
				entryDelta: 1,
				inodeDelta: 1,
				previousLogicalBytes: 0,
				previousAllocatedBytes: 0,
				...active.identity,
				parentEffects: [
					this.#rootDirectoryEffect(
						root,
						this.#rootPath(root, "active"),
						this.#rootPathString(root, "active"),
						activeParentBefore,
					),
				],
			});
			return active;
		} catch (error) {
			if (this.#rootExists(root, temporaryPath)) root.unlinkFile(temporaryPath);
			return this.#poison(error);
		}
	}

	#sealActiveWithinRoot(root: IncidentCasRootMutation, reason: string, sealedAtMs = this.#now()): void {
		const active = this.#active;
		if (!active) return;
		const indexDocument: SegmentIndexDocument = {
			version: 2,
			kind: "segment-index",
			segmentId: active.header.segmentId,
			segmentSequence: active.header.segmentSequence,
			records: active.records,
			recoveryGaps: active.recoveryGaps,
		};
		const indexFrame = encodeFrame(FrameType.Index, active.nextOrdinal, encodeJson(indexDocument));
		if (indexFrame.byteLength > FORMAT_MAX_INDEX_FRAME_BYTES)
			throw new Error("segment index exceeds the fixed format maximum");
		const indexOffset = active.size;
		const contentBytes = indexOffset + indexFrame.byteLength;
		if (contentBytes > FORMAT_MAX_ACTIVE_BYTES + FORMAT_MAX_INDEX_FRAME_BYTES)
			throw new Error("sealed segment content exceeds the fixed format maximum");
		const observations = active.records.map((record) => record.observedAtMs);
		const previousAllocation = active.identity;
		const activeParentBefore = this.#rootStorageState(root, this.#rootPath(root, "active"), true);
		const sealedParentBefore = this.#rootStorageState(root, this.#rootPath(root, "sealed"), true);
		try {
			this.#withActiveSegmentFileWithinRoot(root, "read_write", (file) => {
				writeFullyAt(file, indexFrame, indexOffset);
				const footer: SegmentFooter = {
					version: 2,
					kind: "sealed-footer",
					segmentId: active.header.segmentId,
					segmentSequence: active.header.segmentSequence,
					createdAtMs: active.header.createdAtMs,
					sealedAtMs,
					reason,
					recordCount: active.records.length,
					gapCount: active.recoveryGaps.length,
					minObservedAtMs: observations.length === 0 ? null : Math.min(...observations),
					maxObservedAtMs: observations.length === 0 ? null : Math.max(...observations),
					indexOffset,
					indexFrameBytes: indexFrame.byteLength,
					indexSha256: sha256(indexFrame),
					contentBytes,
					contentSha256: hashFileRange(file, 0, contentBytes),
					idempotencyBloomBase64: idempotencyBloom(active.records),
				};
				assertSafeNonNegativeInteger(footer.sealedAtMs, "segment seal time");
				const footerFrame = encodeFrame(FrameType.Footer, active.nextOrdinal + 1, encodeJson(footer));
				if (footerFrame.byteLength > FORMAT_MAX_FOOTER_FRAME_BYTES)
					throw new Error("sealed footer exceeds the fixed format maximum");
				writeFullyAt(file, footerFrame, contentBytes);
				file.sync();
				const summary = this.#promoteActiveFileWithinRoot(
					root,
					active,
					footer,
					contentBytes + footerFrame.byteLength,
				);
				this.#active = undefined;
				const existingIndex = this.#sealed.findIndex(
					(candidate) => candidate.header.segmentId === summary.header.segmentId,
				);
				if (existingIndex >= 0) this.#sealed[existingIndex] = summary;
				else this.#sealed.push(summary);
				this.#sealed.sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
				this.#refreshReadCatalog();
				const allocation = this.#rootStorageState(
					root,
					this.#rootPath(root, "sealed", basename(summary.path)),
					false,
				);
				this.#emitDurable({
					kind: "sealed",
					segmentId: summary.header.segmentId,
					path: summary.path,
					previousPath: active.path,
					entryChange: "same-inode-move",
					entryDelta: 0,
					inodeDelta: 0,
					previousLogicalBytes: previousAllocation.logicalBytes,
					previousAllocatedBytes: previousAllocation.allocatedBytes,
					...allocation,
					parentEffects: [
						this.#rootDirectoryEffect(
							root,
							this.#rootPath(root, "active"),
							this.#rootPathString(root, "active"),
							activeParentBefore,
						),
						this.#rootDirectoryEffect(
							root,
							this.#rootPath(root, "sealed"),
							this.#rootPathString(root, "sealed"),
							sealedParentBefore,
						),
					],
				});
			});
		} catch (error) {
			this.#poison(error);
		}
	}

	#readIndexWithinRoot(root: IncidentCasRootMutation, summary: SegmentSummary): SegmentIndexDocument {
		const name = basename(summary.path);
		return root.withFile(this.#rootPath(root, "sealed", name), { access: "read" }, (file) => {
			assertPrivateRegularFile(file, summary.path);
			const status = file.stat();
			if (Number(status.size) !== summary.fileBytes)
				throw new InvalidFrameError("sealed segment size changed after cataloging");
			const indexFrame = parseFrameAt(file, summary.footer.indexOffset, summary.fileBytes);
			const index = parseIndexDocument(indexFrame);
			this.#validateIndex(summary.header, summary.footer, indexFrame, index);
			return index;
		});
	}

	#withSealedSegmentFileWithinRoot<T>(
		root: IncidentCasRootMutation,
		summary: SegmentSummary,
		operation: (file: IncidentRecorderSegmentFileView, fileSize: number) => T,
	): T {
		const name = basename(summary.path);
		const path = this.#rootPathString(root, "sealed", name);
		return root.withFile(this.#rootPath(root, "sealed", name), { access: "read" }, (file) => {
			assertPrivateRegularFile(file, path);
			const fileSize = Number(file.stat().size);
			if (!Number.isSafeInteger(fileSize) || fileSize !== summary.fileBytes) {
				throw new InvalidFrameError("sealed segment size changed after cataloging");
			}
			return operation(file, fileSize);
		});
	}

	#withSealedSegmentFile<T>(
		summary: SegmentSummary,
		operation: (file: IncidentRecorderSegmentFileView, fileSize: number) => T,
	): T {
		const fileDescriptor = openSync(summary.path, constants.O_RDONLY | constants.O_NOFOLLOW);
		try {
			assertPrivateRegularFile(fileDescriptor, summary.path);
			const fileSize = Number(fstatSync(fileDescriptor, { bigint: true }).size);
			if (!Number.isSafeInteger(fileSize) || fileSize !== summary.fileBytes) {
				throw new InvalidFrameError("sealed segment size changed after cataloging");
			}
			return operation(scopedSegmentFileView(fileDescriptor), fileSize);
		} finally {
			closeSync(fileDescriptor);
		}
	}

	#findIdempotentRecordWithinRoot(
		root: IncidentCasRootMutation,
		idempotencyKey: string,
		canonicalContentSha256: string,
	): IncidentRecorderSegmentLocator | undefined {
		if (this.#corrupt.some((segment) => !segment.summary))
			throw new Error("cannot prove idempotency while retained segment identity is corrupt");
		const activeEntry = this.#active?.records.find((entry) => entry.idempotencyKey === idempotencyKey);
		if (activeEntry) {
			if (activeEntry.canonicalContentSha256 !== canonicalContentSha256)
				throw new Error("idempotencyKey was already committed with different canonical content");
			return this.#locatorFromEntry(activeEntry);
		}
		const summaries = [
			...this.#sealed,
			...this.#corrupt.flatMap((segment) => (segment.summary ? [segment.summary] : [])),
		].sort((left, right) => right.header.segmentSequence - left.header.segmentSequence);
		for (const summary of summaries) {
			const bloomMayContain = idempotencyBloomMayContain(summary.footer.idempotencyBloomBase64, idempotencyKey);
			if (!bloomMayContain) continue;
			const index = this.#readIndexWithinRoot(root, summary);
			const entry = index.records.find((candidate) => candidate.idempotencyKey === idempotencyKey);
			if (!entry) continue;
			if (entry.canonicalContentSha256 !== canonicalContentSha256)
				throw new Error("idempotencyKey was already committed with different canonical content");
			return this.#locatorFromEntry(entry);
		}
		return undefined;
	}

	#estimateAppendStorageWithinRoot(
		root: IncidentCasRootMutation,
		input: IncidentRecorderSegmentAppendInput,
		sampledNow = this.#now(),
	): IncidentRecorderSegmentAppendStorageEstimate {
		const payload = Buffer.from(input.payload);
		const recordIdentity = canonicalRecordIdentity(input, payload.byteLength, sha256(payload));
		const envelope: RecordEnvelope = {
			version: 2,
			kind: "record",
			...recordIdentity,
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
			metadata: input.metadata,
			payloadBytes: payload.byteLength,
			payloadSha256: sha256(payload),
		};
		const envelopeBytes = encodeJson(envelope);
		const length = Buffer.alloc(4);
		length.writeUInt32LE(envelopeBytes.byteLength, 0);
		const recordFrame = encodeFrame(FrameType.Record, 0, Buffer.concat([length, envelopeBytes, payload]));
		if (recordFrame.byteLength > FORMAT_MAX_RECORD_FRAME_BYTES)
			throw new Error("record frame exceeds the fixed format maximum");
		const current = this.#active;
		const now = sampledNow;
		const willSealBeforeAppend =
			current !== undefined &&
			current.records.length + current.recoveryGaps.length > 0 &&
			(now - current.header.createdAtMs >= this.#maxSegmentAgeMs ||
				current.records.length >= this.#maxRecordsPerSegment ||
				current.size + recordFrame.byteLength > this.#maxSegmentBytes);
		const sealBeforeBytes =
			current && willSealBeforeAppend
				? this.#estimateSealGrowth(current, current.records, "rotation-before-append", now)
				: 0;
		const willCreateSegment = current === undefined || willSealBeforeAppend;
		let headerFrameBytes = 0;
		let target: Pick<ActiveSegment, "header" | "size" | "nextOrdinal" | "records" | "recoveryGaps">;
		if (willCreateSegment) {
			const header: SegmentHeader = {
				version: 2,
				kind: "segment-header",
				segmentId: "s".repeat(128),
				segmentSequence: this.#nextSequence,
				createdAtMs: now,
			};
			headerFrameBytes = encodeFrame(FrameType.Header, 0, encodeJson(header)).byteLength;
			target = { header, size: headerFrameBytes, nextOrdinal: 1, records: [], recoveryGaps: [] };
		} else target = current;
		const entry: SegmentIndexEntry = {
			version: 1,
			segmentId: target.header.segmentId,
			segmentSequence: target.header.segmentSequence,
			ordinal: target.nextOrdinal,
			offset: target.size,
			frameBytes: recordFrame.byteLength,
			payloadBytes: payload.byteLength,
			payloadSha256: envelope.payloadSha256,
			idempotencyKey: envelope.idempotencyKey,
			canonicalContentSha256: envelope.canonicalContentSha256,
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
		};
		const projectedRecords = [...target.records, entry];
		const projectedSize = target.size + recordFrame.byteLength;
		const willSealAfterAppend =
			projectedRecords.length >= this.#maxRecordsPerSegment ||
			projectedSize >= this.#maxSegmentBytes ||
			now - target.header.createdAtMs >= this.#maxSegmentAgeMs;
		const sealAfterBytes = willSealAfterAppend
			? this.#estimateSealGrowth(target, projectedRecords, "rotation-after-append", now)
			: 0;
		const currentAllocated = current?.identity.allocatedBytes ?? 0;
		const fileGrowth = willCreateSegment
			? conservativeAllocatedBytes(headerFrameBytes + recordFrame.byteLength + sealAfterBytes)
			: Math.max(
					0,
					conservativeAllocatedBytes((current?.size ?? target.size) + recordFrame.byteLength + sealAfterBytes) -
						currentAllocated,
				);
		const statfs = root.statfs(this.#rootPath(root));
		const unit = Number(statfs.bsize);
		if (!Number.isSafeInteger(unit) || unit <= 0) throw new Error("filesystem allocation unit is invalid");
		const parentEntries = (willCreateSegment ? 2 : 0) + Number(willSealBeforeAppend) + Number(willSealAfterAppend);
		return {
			recordFrameBytes: recordFrame.byteLength,
			headerFrameBytes,
			sealBeforeBytes,
			sealAfterBytes,
			peakAdditionalBytes: sealBeforeBytes + headerFrameBytes + recordFrame.byteLength + sealAfterBytes,
			peakAdditionalAllocatedBytes: fileGrowth + parentEntries * unit,
			peakAdditionalEntries: willCreateSegment ? 2 : willSealAfterAppend ? 1 : 0,
			peakAdditionalInodes: willCreateSegment ? 1 : 0,
			willSealBeforeAppend,
			willSealAfterAppend,
			willCreateSegment,
		};
	}

	#appendFrozenWithinRoot(
		root: IncidentCasRootMutation,
		input: IncidentRecorderSegmentAppendInput,
		sampledNow: number,
		estimate: IncidentRecorderSegmentAppendStorageEstimate,
		plannedSegmentId?: string,
	): IncidentRecorderSegmentAppendResult {
		this.#assertUsable();
		assertIdentifier(input.runId, "runId");
		assertIdentifier(input.sourceId, "sourceId");
		assertSafeNonNegativeInteger(input.observedAtMs, "observedAtMs");
		assertOrder(input.order);
		assertMetadata(input.metadata);
		const metadataBytes = encodeJson(input.metadata).byteLength;
		if (metadataBytes > this.#maxMetadataBytes) throw new Error("metadata exceeds maxMetadataBytes");
		const payload = Buffer.from(input.payload);
		if (payload.byteLength > this.#maxRecordBytes) throw new Error("payload exceeds maxRecordBytes");
		const recordIdentity = canonicalRecordIdentity(input, payload.byteLength, sha256(payload));
		const existingLocator = this.#findIdempotentRecordWithinRoot(
			root,
			recordIdentity.idempotencyKey,
			recordIdentity.canonicalContentSha256,
		);
		if (existingLocator) return { status: "existing", locator: existingLocator };
		const envelope: RecordEnvelope = {
			version: 2,
			kind: "record",
			...recordIdentity,
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
			metadata: input.metadata,
			payloadBytes: payload.byteLength,
			payloadSha256: sha256(payload),
		};
		const envelopeBytes = encodeJson(envelope);
		const envelopeLength = Buffer.alloc(4);
		envelopeLength.writeUInt32LE(envelopeBytes.byteLength, 0);
		const frame = encodeFrame(FrameType.Record, 0, Buffer.concat([envelopeLength, envelopeBytes, payload]));
		if (frame.byteLength > FORMAT_MAX_RECORD_FRAME_BYTES)
			throw new Error("record frame exceeds the fixed format maximum");
		if (estimate.willSealBeforeAppend) this.#sealActiveWithinRoot(root, "rotation-before-append", sampledNow);
		const active = this.#active ?? this.#createActiveSegmentWithinRoot(root, sampledNow, plannedSegmentId);
		const encoded = encodeFrame(
			FrameType.Record,
			active.nextOrdinal,
			Buffer.concat([envelopeLength, envelopeBytes, payload]),
		);
		const offset = active.size;
		const entry: SegmentIndexEntry = {
			version: 1,
			segmentId: active.header.segmentId,
			segmentSequence: active.header.segmentSequence,
			ordinal: active.nextOrdinal,
			offset,
			frameBytes: encoded.byteLength,
			payloadBytes: payload.byteLength,
			payloadSha256: envelope.payloadSha256,
			idempotencyKey: envelope.idempotencyKey,
			canonicalContentSha256: envelope.canonicalContentSha256,
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
		};
		const previousAllocation = active.identity;
		try {
			this.#withActiveSegmentFileWithinRoot(root, "read_write", (file) => {
				writeFullyAt(file, encoded, offset);
				this.#faultInjector?.("after-record-write-before-fsync");
				file.sync();
				active.records.push(entry);
				active.size += encoded.byteLength;
				active.nextOrdinal += 1;
				active.identity = fileAllocation(file);
				this.#emitDurable({
					kind: "record",
					segmentId: active.header.segmentId,
					path: active.path,
					entryChange: "same-inode-growth",
					entryDelta: 0,
					inodeDelta: 0,
					previousLogicalBytes: previousAllocation.logicalBytes,
					previousAllocatedBytes: previousAllocation.allocatedBytes,
					...active.identity,
					parentEffects: [],
				});
			});
			if (estimate.willSealAfterAppend) this.#sealActiveWithinRoot(root, "rotation-after-append", sampledNow);
		} catch (error) {
			return this.#poison(error);
		}
		this.#stateRevision += 1;
		return { status: "appended", locator: this.#locatorFromEntry(entry) };
	}

	#planAppendWithinRoot(
		root: IncidentCasRootMutation,
		input: IncidentRecorderSegmentAppendInput,
		admit?: (estimate: IncidentRecorderSegmentAppendStorageEstimate) => void,
	): IncidentRecorderSegmentAppendPlan {
		this.#assertRootBacked("planAppendWithinRoot");
		this.#assertUsable();
		assertMetadata(input.metadata);
		const frozenMetadata = parseJson(Buffer.from(canonicalJson(input.metadata), "utf8"), "frozen append metadata");
		assertMetadata(frozenMetadata);
		const frozenInput: IncidentRecorderSegmentAppendInput = {
			...(input.idempotencyKey === undefined ? {} : { idempotencyKey: input.idempotencyKey }),
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
			metadata: frozenMetadata,
			payload: Buffer.from(input.payload),
		};
		const sampledNow = this.#now();
		const plannedRevision = this.#stateRevision;
		const payload = Buffer.from(frozenInput.payload);
		const identity = canonicalRecordIdentity(frozenInput, payload.byteLength, sha256(payload));
		const existing = this.#findIdempotentRecordWithinRoot(
			root,
			identity.idempotencyKey,
			identity.canonicalContentSha256,
		);
		const estimate = Object.freeze(
			existing
				? {
						recordFrameBytes: 0,
						headerFrameBytes: 0,
						sealBeforeBytes: 0,
						sealAfterBytes: 0,
						peakAdditionalBytes: 0,
						peakAdditionalAllocatedBytes: 0,
						peakAdditionalEntries: 0,
						peakAdditionalInodes: 0,
						willSealBeforeAppend: false,
						willSealAfterAppend: false,
						willCreateSegment: false,
					}
				: this.#estimateAppendStorageWithinRoot(root, frozenInput, sampledNow),
		);
		const plannedSegmentId =
			!existing && estimate.willCreateSegment ? this.#selectUniqueSegmentIdWithinRoot(root) : undefined;
		admit?.(estimate);
		this.#assertUsable();
		if (this.#stateRevision !== plannedRevision)
			throw new Error("store state changed during append admission; replan required");
		const publicPlan = Object.freeze({ version: 1 as const, token: randomUUID(), estimate });
		this.#appendPlans.set(publicPlan.token, {
			publicPlan,
			input: frozenInput,
			sampledNow,
			stateRevision: plannedRevision,
			...(plannedSegmentId === undefined ? {} : { plannedSegmentId }),
		});
		return publicPlan;
	}

	#commitAppendPlanWithinRoot(
		root: IncidentCasRootMutation,
		plan: IncidentRecorderSegmentAppendPlan,
	): IncidentRecorderSegmentAppendResult {
		this.#assertRootBacked("commitAppendPlanWithinRoot");
		this.#assertUsable();
		const frozen = this.#appendPlans.get(plan.token);
		this.#appendPlans.delete(plan.token);
		if (!frozen || frozen.publicPlan !== plan || plan.version !== 1)
			throw new Error("append plan is unknown or already consumed");
		if (frozen.stateRevision !== this.#stateRevision)
			throw new Error("append plan is stale because store state changed; replan required");
		if (
			frozen.plannedSegmentId &&
			(this.#rootExists(root, this.#rootPath(root, "active", `${frozen.plannedSegmentId}.open`)) ||
				this.#rootExists(root, this.#rootPath(root, "sealed", `${frozen.plannedSegmentId}.segment`)))
		)
			throw new Error("planned segment identity is no longer unique");
		return this.#appendFrozenWithinRoot(
			root,
			frozen.input,
			frozen.sampledNow,
			frozen.publicPlan.estimate,
			frozen.plannedSegmentId,
		);
	}

	#closeWithinRoot(root: IncidentCasRootMutation): void {
		this.#assertRootBacked("closeWithinRoot");
		if (this.#closed) return;
		const closeErrors: unknown[] = [];
		if (this.#active) {
			try {
				this.#withActiveSegmentFileWithinRoot(root, "read_write", (file) => file.sync());
			} catch (error) {
				closeErrors.push(error);
			}
		}
		try {
			this.#releaseOwnershipWithinRoot(root);
		} catch (error) {
			closeErrors.push(error);
		}
		this.#closed = true;
		this.#appendPlans.clear();
		this.#readLeases.clear();
		this.#pruneCursorCapabilities.clear();
		this.#emitRootOpen({
			phase: "closed",
			complete: closeErrors.length === 0,
			reconciliation: closeErrors.length === 0 ? "incremental-complete" : "full-dev-inode-required",
			entries: [],
			parentEffects: [],
			...(closeErrors.length === 0 ? {} : { error: errorText(closeErrors[0]) }),
		});
		if (closeErrors.length > 0) throw closeErrors[0];
	}

	#poison(error: unknown): never {
		if (!this.#poisoned) {
			const cleanupErrors = [
				...this.#closeActiveDescriptor(() => this.#faultInjector?.("after-poison-active-handle-close")),
				...runCleanupActionsAttemptAll(
					Array.from(
						this.#pruneCursorCapabilities.keys(),
						(key) => () => removePruneCursorCapability(this.#pruneCursorCapabilities, key),
					),
				),
			];
			this.#poisoned = new IncidentRecorderSegmentStorePoisonedError(
				attachCleanupToPruneFailure(error, cleanupErrors),
			);
		} else {
			this.#closeActiveDescriptor();
		}
		throw this.#poisoned;
	}

	#closeActiveDescriptor(afterClose?: () => void): readonly unknown[] {
		const cleanupErrors: unknown[] = [];
		if (!this.#active) return cleanupErrors;
		// Active segment descriptors are scoped to one synchronous operation and are
		// therefore already closed before this cleanup boundary is reached. Preserve
		// the existing post-poison fault boundary for callers that observe cleanup.
		try {
			afterClose?.();
		} catch (error) {
			cleanupErrors.push(error);
		}
		return cleanupErrors;
	}

	#withActiveSegmentFile<T>(
		access: "read" | "read_write",
		operation: (file: IncidentRecorderSegmentFileView) => T,
	): T {
		const active = this.#active;
		if (!active) throw new Error("active segment is unavailable");
		const flags = (access === "read" ? constants.O_RDONLY : constants.O_RDWR) | constants.O_NOFOLLOW;
		return withOwnedSegmentFile(active.path, flags, (file) => {
			assertPrivateRegularFile(file, active.path);
			if (!sameStorageState(fileAllocation(file), active.identity)) {
				throw new Error("active segment identity changed before scoped operation");
			}
			return operation(file);
		});
	}

	#readOwnerClaim(path: string): OwnerClaim {
		const fileDescriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const outcome = captureIncidentRecorderOutcome(() => {
			assertPrivateRegularFile(fileDescriptor, path);
			const status = fstatSync(fileDescriptor);
			if (status.size <= 0 || status.size > 4096) throw new Error("writer ownership claim is malformed");
			const bytes = Buffer.alloc(status.size);
			readFully(fileDescriptor, bytes, 0);
			return parseOwnerClaim(parseJson(bytes, "writer ownership claim"));
		});
		return settleIncidentRecorderOutcome(
			outcome,
			runCleanupActionsAttemptAll([
				() => {
					closeSync(fileDescriptor);
					this.#faultInjector?.("after-owner-claim-handle-close");
				},
			]),
		);
	}

	#acquireOwnership(): void {
		const ownerPath = join(this.#directory, OWNER_FILE_NAME);
		const abandoned: string[] = [];
		for (let attempt = 0; attempt < 16; attempt += 1) {
			const claim: OwnerClaim = { version: 1, nonce: randomUUID(), ...this.#ownerIdentity };
			const temporaryPath = join(this.#directory, ".writer-owner-" + claim.nonce + ".tmp");
			const bytes = Buffer.from(JSON.stringify(claim) + "\n", "utf8");
			let fileDescriptor = -1;
			try {
				fileDescriptor = openSync(
					temporaryPath,
					constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
					0o600,
				);
				writeFullyAt(fileDescriptor, bytes, 0);
				fsyncSync(fileDescriptor);
				closeSync(fileDescriptor);
				fileDescriptor = -1;
				try {
					linkSync(temporaryPath, ownerPath);
					this.#ownerClaim = claim;
					syncDirectory(this.#directory);
					unlinkSync(temporaryPath);
					syncDirectory(this.#directory);
					for (const path of abandoned) {
						if (pathStatus(path)) {
							unlinkSync(path);
							this.#openRemovedPreexistingEntry = true;
						}
					}
					if (abandoned.length > 0) syncDirectory(this.#directory);
					return;
				} catch (error) {
					if (errnoCode(error) !== "EEXIST") throw error;
					unlinkSync(temporaryPath);
					const existing = this.#readOwnerClaim(ownerPath);
					if (this.#isOwnerAlive(existing)) {
						throw new Error("incident recorder segment store is already owned by a live writer");
					}
					const abandonedPath = join(this.#directory, ".writer-owner-stale-" + claim.nonce);
					try {
						renameSync(ownerPath, abandonedPath);
					} catch (renameError) {
						if (errnoCode(renameError) === "ENOENT") continue;
						throw renameError;
					}
					syncDirectory(this.#directory);
					const moved = this.#readOwnerClaim(abandonedPath);
					if (!ownerClaimsEqual(existing, moved)) {
						try {
							linkSync(abandonedPath, ownerPath);
							syncDirectory(this.#directory);
						} catch {
							// A concurrent valid claimant wins; retain the moved evidence and fail closed.
						}
						throw new Error("writer ownership claim changed during stale recovery");
					}
					abandoned.push(abandonedPath);
				}
			} finally {
				if (fileDescriptor >= 0) closeSync(fileDescriptor);
				if (pathStatus(temporaryPath)) unlinkSync(temporaryPath);
			}
		}
		throw new Error("could not acquire unique incident recorder writer ownership");
	}

	#releaseOwnership(): void {
		const claim = this.#ownerClaim;
		if (!claim) return;
		const ownerPath = join(this.#directory, OWNER_FILE_NAME);
		if (!pathStatus(ownerPath)) {
			this.#ownerClaim = undefined;
			return;
		}
		const current = this.#readOwnerClaim(ownerPath);
		if (!ownerClaimsEqual(claim, current)) throw new Error("writer ownership claim changed while held");
		unlinkSync(ownerPath);
		syncDirectory(this.#directory);
		this.#ownerClaim = undefined;
	}

	#accountStartupEntry(name: string): void {
		this.#startupEntries += 1;
		this.#startupCatalogBytes += Buffer.byteLength(name, "utf8") + 256;
		if (this.#startupEntries > this.#maxStartupEntries) {
			throw new Error("segment directory exceeds maxStartupEntries");
		}
		if (this.#startupCatalogBytes > this.#maxStartupCatalogBytes) {
			throw new SegmentCatalogBudgetExceededError("segment catalog exceeds maxStartupCatalogBytes");
		}
	}

	#accountSummary(summary: SegmentSummary): void {
		this.#startupCatalogBytes +=
			Buffer.byteLength(summary.path, "utf8") +
			encodeJson(summary.header).byteLength +
			encodeJson(summary.footer).byteLength +
			384;
		if (this.#startupCatalogBytes > this.#maxStartupCatalogBytes) {
			throw new SegmentCatalogBudgetExceededError("segment catalog exceeds maxStartupCatalogBytes");
		}
	}

	#scanDirectory(path: string): string[] {
		const names: string[] = [];
		const directory = opendirSync(path);
		try {
			for (;;) {
				const entry = directory.readSync();
				if (!entry) break;
				this.#accountStartupEntry(entry.name);
				names.push(entry.name);
			}
		} finally {
			directory.closeSync();
		}
		return names;
	}

	#readSealedSummary(path: string): SegmentSummary {
		const fileDescriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const outcome = captureIncidentRecorderOutcome(() => {
			assertPrivateRegularFile(fileDescriptor, path);
			const fileBytes = fstatSync(fileDescriptor).size;
			if (
				fileBytes < FRAME_OVERHEAD_BYTES * 3 ||
				fileBytes > FORMAT_MAX_ACTIVE_BYTES + FORMAT_MAX_INDEX_FRAME_BYTES + FORMAT_MAX_FOOTER_FRAME_BYTES
			) {
				throw new InvalidFrameError("sealed segment size exceeds the fixed format maximum");
			}
			const headerFrame = parseFrameAt(fileDescriptor, 0, fileBytes);
			const header = parseHeader(headerFrame);
			const trailer = Buffer.alloc(FRAME_TRAILER_BYTES);
			readFully(fileDescriptor, trailer, fileBytes - FRAME_TRAILER_BYTES);
			if (!trailer.subarray(4).equals(FRAME_END_MAGIC))
				throw new InvalidFrameError("sealed footer trailer is missing");
			const footerFrameBytes = trailer.readUInt32LE(0);
			if (footerFrameBytes < FRAME_OVERHEAD_BYTES || footerFrameBytes > FORMAT_MAX_FOOTER_FRAME_BYTES) {
				throw new InvalidFrameError("sealed footer length exceeds the fixed format maximum");
			}
			const footerOffset = fileBytes - footerFrameBytes;
			const footerFrame = parseFrameAt(fileDescriptor, footerOffset, fileBytes);
			const footer = parseFooter(footerFrame);
			if (
				footer.segmentId !== header.segmentId ||
				footer.segmentSequence !== header.segmentSequence ||
				footer.createdAtMs !== header.createdAtMs ||
				footer.indexOffset < headerFrame.frameBytes ||
				footer.contentBytes !== footer.indexOffset + footer.indexFrameBytes ||
				footer.contentBytes + footerFrame.frameBytes !== fileBytes ||
				footerFrame.ordinal !== footer.recordCount + footer.gapCount + 2 ||
				basename(path) !== header.segmentId + ".segment"
			) {
				throw new InvalidFrameError("sealed footer identity or bounds are invalid");
			}
			return { header, footer, path, fileBytes };
		});
		return settleIncidentRecorderOutcome(outcome, runCleanupActionsAttemptAll([() => closeSync(fileDescriptor)]));
	}

	#loadSegments(): void {
		const activeNames = this.#scanDirectory(this.#activeDirectory);
		const sealedNames = this.#scanDirectory(this.#sealedDirectory);
		let cleanedTemporary = false;
		for (const name of activeNames) {
			if (/^\.creating-[A-Za-z0-9_-]+\.tmp$/.test(name)) {
				unlinkSync(join(this.#activeDirectory, name));
				this.#openRemovedPreexistingEntry = true;
				cleanedTemporary = true;
			}
		}
		if (cleanedTemporary) syncDirectory(this.#activeDirectory);

		for (const name of sealedNames) {
			if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.segment$/.test(name)) continue;
			const path = join(this.#sealedDirectory, name);
			try {
				const summary = this.#readSealedSummary(path);
				if (this.#sealed.some((candidate) => candidate.header.segmentId === summary.header.segmentId)) {
					throw new InvalidFrameError("duplicate sealed segment identity");
				}
				this.#accountSummary(summary);
				this.#sealed.push(summary);
			} catch (error) {
				if (
					error instanceof SegmentCatalogBudgetExceededError ||
					error instanceof IncidentRecorderDescriptorCleanupError ||
					errnoCode(error) !== undefined
				) {
					throw error;
				}
				this.#corrupt.push({ segmentId: name.slice(0, -".segment".length), path, reason: errorText(error) });
			}
		}

		const openNames = activeNames.filter((name) => /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.open$/.test(name));
		if (openNames.length > 1) throw new Error("multiple active segment files violate single-writer ownership");
		if (openNames.length === 1) {
			const recovered = this.#recoverActive(join(this.#activeDirectory, openNames[0] ?? "missing"));
			if ("footer" in recovered) {
				const existingIndex = this.#sealed.findIndex(
					(summary) => summary.header.segmentId === recovered.header.segmentId,
				);
				if (existingIndex >= 0) this.#sealed[existingIndex] = recovered;
				else {
					this.#accountSummary(recovered);
					this.#sealed.push(recovered);
				}
			} else {
				this.#active = recovered;
				this.#startupCatalogBytes += 512 + Buffer.byteLength(recovered.path, "utf8");
				if (this.#startupCatalogBytes > this.#maxStartupCatalogBytes) {
					throw new Error("segment catalog exceeds maxStartupCatalogBytes");
				}
			}
		}
		this.#sealed.sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
		for (let index = 1; index < this.#sealed.length; index += 1) {
			if (this.#sealed[index]?.header.segmentSequence === this.#sealed[index - 1]?.header.segmentSequence) {
				throw new InvalidFrameError("duplicate sealed segment sequence");
			}
		}
		const sequences = this.#sealed.map((summary) => summary.header.segmentSequence);
		for (const corrupt of this.#corrupt) {
			if (corrupt.summary) sequences.push(corrupt.summary.header.segmentSequence);
		}
		if (this.#active) sequences.push(this.#active.header.segmentSequence);
		if (new Set(sequences).size !== sequences.length) throw new InvalidFrameError("duplicate segment sequence");
		this.#nextSequence = sequences.length === 0 ? 0 : Math.max(...sequences) + 1;
		this.#refreshReadCatalog();
	}

	#refreshReadCatalog(): void {
		this.#hasUncataloguedCorruptSegment = this.#corrupt.some((segment) => !segment.summary);
		this.#readCatalog = [
			...this.#sealed,
			...this.#corrupt.flatMap((segment) => (segment.summary ? [segment.summary] : [])),
		].sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
	}

	#validateIndex(
		header: SegmentHeader,
		footer: SegmentFooter,
		indexFrame: ParsedFrame,
		index: SegmentIndexDocument,
	): void {
		if (
			index.segmentId !== header.segmentId ||
			index.segmentSequence !== header.segmentSequence ||
			footer.segmentId !== header.segmentId ||
			footer.segmentSequence !== header.segmentSequence ||
			idempotencyBloom(index.records) !== footer.idempotencyBloomBase64 ||
			index.records.length !== footer.recordCount ||
			index.recoveryGaps.length !== footer.gapCount ||
			indexFrame.frameBytes !== footer.indexFrameBytes ||
			indexFrame.ordinal !== footer.recordCount + footer.gapCount + 1 ||
			sha256(indexFrame.bytes) !== footer.indexSha256
		) {
			throw new InvalidFrameError("sealed index identity or cardinality is invalid");
		}
		const positions: Array<{ ordinal: number; offset: number }> = [];
		let minimum: number | null = null;
		let maximum: number | null = null;
		let lastRecordOrdinal = 0;
		for (const entry of index.records) {
			if (
				entry.segmentId !== header.segmentId ||
				entry.segmentSequence !== header.segmentSequence ||
				entry.ordinal <= lastRecordOrdinal ||
				entry.offset < FRAME_OVERHEAD_BYTES ||
				entry.offset + entry.frameBytes > footer.indexOffset
			) {
				throw new InvalidFrameError("sealed index record bounds or identity are invalid");
			}
			lastRecordOrdinal = entry.ordinal;
			positions.push({ ordinal: entry.ordinal, offset: entry.offset });
			minimum = minimum === null ? entry.observedAtMs : Math.min(minimum, entry.observedAtMs);
			maximum = maximum === null ? entry.observedAtMs : Math.max(maximum, entry.observedAtMs);
		}
		let lastGapOrdinal = 0;
		for (const gap of index.recoveryGaps) {
			if (
				gap.segmentId !== header.segmentId ||
				gap.segmentSequence !== header.segmentSequence ||
				gap.ordinal <= lastGapOrdinal ||
				gap.invalidOffset < FRAME_OVERHEAD_BYTES ||
				gap.invalidOffset >= footer.indexOffset
			) {
				throw new InvalidFrameError("sealed index gap bounds or identity are invalid");
			}
			lastGapOrdinal = gap.ordinal;
			positions.push({ ordinal: gap.ordinal, offset: gap.invalidOffset });
		}
		positions.sort((left, right) => left.ordinal - right.ordinal);
		for (let indexValue = 0; indexValue < positions.length; indexValue += 1) {
			const position = positions[indexValue];
			if (
				!position ||
				position.ordinal !== indexValue + 1 ||
				(indexValue > 0 && position.offset <= (positions[indexValue - 1]?.offset ?? -1))
			) {
				throw new InvalidFrameError("sealed index order is not strict and complete");
			}
		}
		if (minimum !== footer.minObservedAtMs || maximum !== footer.maxObservedAtMs) {
			throw new InvalidFrameError("sealed index time bounds do not match the footer");
		}
	}

	#readIndex(summary: SegmentSummary, poisonOnObserverFailure = true): SegmentIndexDocument {
		const fileDescriptor = openSync(summary.path, constants.O_RDONLY | constants.O_NOFOLLOW);
		let observerFailed = false;
		const outcome = captureIncidentRecorderOutcome(() => {
			assertPrivateRegularFile(fileDescriptor, summary.path);
			const status = fstatSync(fileDescriptor);
			if (status.size !== summary.fileBytes)
				throw new InvalidFrameError("sealed segment size changed after cataloging");
			const indexFrame = parseFrameAt(fileDescriptor, summary.footer.indexOffset, status.size);
			const index = parseIndexDocument(indexFrame);
			this.#validateIndex(summary.header, summary.footer, indexFrame, index);
			try {
				if (this.#onIndexRead) {
					this.#insideCallback = true;
					try {
						this.#onIndexRead(summary.header.segmentId);
					} finally {
						this.#insideCallback = false;
					}
				}
			} catch (error) {
				observerFailed = true;
				throw poisonOnObserverFailure ? error : new IncidentRecorderIndexObserverError(error);
			}
			return index;
		});
		try {
			return settleIncidentRecorderOutcome(
				outcome,
				runCleanupActionsAttemptAll([
					() => {
						closeSync(fileDescriptor);
						if (!poisonOnObserverFailure) this.#faultInjector?.("after-prune-index-handle-close");
					},
				]),
			);
		} catch (error) {
			if (observerFailed && poisonOnObserverFailure) return this.#poison(error);
			throw error;
		}
	}

	#promoteActiveFile(active: ActiveSegment, footer: SegmentFooter, fileBytes: number): SegmentSummary {
		const sealedPath = join(this.#sealedDirectory, active.header.segmentId + ".segment");
		let linked = false;
		try {
			linkSync(active.path, sealedPath);
			linked = true;
		} catch (error) {
			if (errnoCode(error) !== "EEXIST") throw error;
			const activeStatus = pathStatus(active.path);
			const sealedStatus = pathStatus(sealedPath);
			if (
				!activeStatus?.isFile() ||
				activeStatus.isSymbolicLink() ||
				!sealedStatus?.isFile() ||
				sealedStatus.isSymbolicLink() ||
				!sameFile(active.path, sealedPath)
			) {
				throw new Error("sealed promotion refused to clobber an existing segment identity");
			}
		}
		if (linked) this.#faultInjector?.("after-sealed-link-before-directory-fsync");
		const destinationDescriptor = openSync(sealedPath, constants.O_RDONLY | constants.O_NOFOLLOW);
		try {
			assertPrivateRegularFile(destinationDescriptor, sealedPath);
			fsyncSync(destinationDescriptor);
		} finally {
			closeSync(destinationDescriptor);
		}
		syncDirectory(this.#sealedDirectory);
		if (!sameFile(active.path, sealedPath)) throw new Error("sealed promotion source changed before removal");
		unlinkSync(active.path);
		syncDirectory(this.#activeDirectory);
		return { header: active.header, footer, path: sealedPath, fileBytes };
	}

	#recoverActive(path: string): ActiveSegment | SegmentSummary {
		return withOwnedSegmentFile(path, constants.O_RDWR | constants.O_NOFOLLOW, (file) => {
			assertPrivateRegularFile(file, path);
			const fileSize = Number(file.stat().size);
			const previousAllocation = fileAllocation(file);
			const recoveryParentBefore = pathStorageState(this.#activeDirectory, true);
			if (
				fileSize < FRAME_OVERHEAD_BYTES ||
				fileSize > FORMAT_MAX_ACTIVE_BYTES + FORMAT_MAX_INDEX_FRAME_BYTES + FORMAT_MAX_FOOTER_FRAME_BYTES
			) {
				throw new InvalidFrameError("active segment size exceeds the fixed format maximum");
			}
			const headerFrame = parseFrameAt(file, 0, fileSize);
			const header = parseHeader(headerFrame);
			if (basename(path) !== header.segmentId + ".open") {
				throw new InvalidFrameError("active segment filename does not match its header identity");
			}
			const active: ActiveSegment = {
				header,
				path,
				identity: previousAllocation,
				size: headerFrame.frameBytes,
				nextOrdinal: 1,
				records: [],
				recoveryGaps: [],
			};
			let offset = headerFrame.frameBytes;
			let invalidError: unknown;
			while (offset < fileSize) {
				try {
					const frame = parseFrameAt(file, offset, fileSize);
					if (frame.ordinal !== active.nextOrdinal)
						throw new InvalidFrameError("active frame ordinal is not contiguous");
					if (frame.type === FrameType.Record) {
						if (active.records.length >= FORMAT_MAX_RECORDS)
							throw new InvalidFrameError("active segment has too many records");
						active.records.push(indexEntryFromFrame(header, frame, offset));
						offset += frame.frameBytes;
						active.size = offset;
						active.nextOrdinal += 1;
						continue;
					}
					if (frame.type === FrameType.RecoveryGap) {
						if (active.recoveryGaps.length >= FORMAT_MAX_GAPS)
							throw new InvalidFrameError("active segment has too many recovery gaps");
						const gap = parseRecoveryGap(frame);
						if (
							gap.segmentId !== header.segmentId ||
							gap.segmentSequence !== header.segmentSequence ||
							gap.ordinal !== frame.ordinal ||
							gap.invalidOffset !== offset
						) {
							throw new InvalidFrameError("active recovery gap identity is invalid");
						}
						active.recoveryGaps.push(gap);
						offset += frame.frameBytes;
						active.size = offset;
						active.nextOrdinal += 1;
						continue;
					}
					if (frame.type === FrameType.Index) {
						const index = parseIndexDocument(frame);
						const footerOffset = offset + frame.frameBytes;
						const footerFrame = parseFrameAt(file, footerOffset, fileSize);
						const footer = parseFooter(footerFrame);
						if (footerOffset + footerFrame.frameBytes !== fileSize) {
							throw new InvalidFrameError("sealed active segment has trailing bytes");
						}
						this.#validateIndex(header, footer, frame, index);
						if (
							footer.indexOffset !== offset ||
							footer.contentBytes !== footerOffset ||
							footerFrame.ordinal !== frame.ordinal + 1 ||
							hashFileRange(file, 0, footer.contentBytes, this.#onRecoveryRead) !== footer.contentSha256
						) {
							throw new InvalidFrameError("sealed active segment footer or content checksum is invalid");
						}
						file.sync();
						return this.#promoteActiveFile(active, footer, fileSize);
					}
					throw new InvalidFrameError("unexpected frame type in active segment");
				} catch (error) {
					invalidError = error;
					break;
				}
			}
			if (invalidError !== undefined) {
				if (active.recoveryGaps.length >= FORMAT_MAX_GAPS) {
					throw new InvalidFrameError("active recovery gap limit reached");
				}
				const discardedBytes = fileSize - offset;
				const gap: IncidentRecorderSegmentRecoveryGap = {
					version: 1,
					segmentId: header.segmentId,
					segmentSequence: header.segmentSequence,
					ordinal: active.nextOrdinal,
					reason: "invalid_or_torn_active_tail",
					observedAtMs: this.#now(),
					invalidOffset: offset,
					discardedBytes,
					discardedSha256: hashFileRange(file, offset, discardedBytes, this.#onRecoveryRead),
				};
				const gapFrame = encodeFrame(FrameType.RecoveryGap, gap.ordinal, encodeJson(gap));
				writeFullyAt(file, gapFrame, offset);
				file.sync();
				this.#faultInjector?.("after-recovery-gap-fsync-before-truncate");
				file.truncate(offset + gapFrame.byteLength);
				file.sync();
				active.recoveryGaps.push(gap);
				active.size = offset + gapFrame.byteLength;
				active.nextOrdinal += 1;
				const allocation = fileAllocation(file);
				active.identity = allocation;
				this.#emitDurable({
					kind: "recovery-gap",
					segmentId: header.segmentId,
					path,
					entryChange: "same-inode-growth",
					entryDelta: 0,
					inodeDelta: 0,
					previousLogicalBytes: previousAllocation.logicalBytes,
					previousAllocatedBytes: previousAllocation.allocatedBytes,
					...allocation,
					parentEffects: [
						parentDirectoryEffect(
							this.#activeDirectory,
							recoveryParentBefore,
							pathStorageState(this.#activeDirectory, true),
						),
					],
				});
			}
			return active;
		});
	}

	#selectUniqueSegmentId(): string {
		if (this.#corrupt.some((segment) => !segment.summary)) {
			throw new Error("cannot allocate a stable segment sequence while a corrupt segment identity is unknown");
		}
		for (let attempt = 0; attempt < 16; attempt += 1) {
			const candidate = this.#createSegmentId();
			assertSegmentId(candidate);
			if (
				!pathStatus(join(this.#activeDirectory, candidate + ".open")) &&
				!pathStatus(join(this.#sealedDirectory, candidate + ".segment"))
			) {
				return candidate;
			}
		}
		throw new Error("createSegmentId did not provide a unique segment identity");
	}

	#createActiveSegment(createdAtMs = this.#now(), plannedSegmentId?: string): ActiveSegment {
		const segmentId = plannedSegmentId ?? this.#selectUniqueSegmentId();
		assertSegmentId(segmentId);
		if (
			pathStatus(join(this.#activeDirectory, segmentId + ".open")) ||
			pathStatus(join(this.#sealedDirectory, segmentId + ".segment"))
		) {
			throw new Error("planned segment identity is no longer unique");
		}
		const header: SegmentHeader = {
			version: 2,
			kind: "segment-header",
			segmentId,
			segmentSequence: this.#nextSequence,
			createdAtMs,
		};
		assertSafeNonNegativeInteger(header.createdAtMs, "segment creation time");
		const headerFrame = encodeFrame(FrameType.Header, 0, encodeJson(header));
		const temporaryPath = join(this.#activeDirectory, ".creating-" + segmentId + "-" + randomUUID() + ".tmp");
		const activePath = join(this.#activeDirectory, segmentId + ".open");
		const activeParentBefore = pathStorageState(this.#activeDirectory, true);
		try {
			return withOwnedSegmentFile(
				temporaryPath,
				constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
				(file) => {
					writeFullyAt(file, headerFrame, 0);
					file.sync();
					this.#faultInjector?.("after-header-fsync-before-publish");
					linkSync(temporaryPath, activePath);
					syncDirectory(this.#activeDirectory);
					unlinkSync(temporaryPath);
					syncDirectory(this.#activeDirectory);
					const active: ActiveSegment = {
						header,
						path: activePath,
						identity: fileAllocation(file),
						size: headerFrame.byteLength,
						nextOrdinal: 1,
						records: [],
						recoveryGaps: [],
					};
					this.#active = active;
					this.#nextSequence += 1;
					try {
						this.#emitDurable({
							kind: "segment-created",
							segmentId,
							path: activePath,
							entryChange: "published",
							entryDelta: 1,
							inodeDelta: 1,
							previousLogicalBytes: 0,
							previousAllocatedBytes: 0,
							...active.identity,
							parentEffects: [
								parentDirectoryEffect(
									this.#activeDirectory,
									activeParentBefore,
									pathStorageState(this.#activeDirectory, true),
								),
							],
						});
					} catch (error) {
						return this.#poison(error);
					}
					return active;
				},
				0o600,
			);
		} catch (error) {
			return this.#poison(error);
		}
	}

	#sealActive(reason: string, sealedAtMs = this.#now()): void {
		const active = this.#active;
		if (!active) return;
		const indexDocument: SegmentIndexDocument = {
			version: 2,
			kind: "segment-index",
			segmentId: active.header.segmentId,
			segmentSequence: active.header.segmentSequence,
			records: active.records,
			recoveryGaps: active.recoveryGaps,
		};
		const indexFrame = encodeFrame(FrameType.Index, active.nextOrdinal, encodeJson(indexDocument));
		if (indexFrame.byteLength > FORMAT_MAX_INDEX_FRAME_BYTES) {
			throw new Error("segment index exceeds the fixed format maximum");
		}
		const indexOffset = active.size;
		const contentBytes = indexOffset + indexFrame.byteLength;
		if (contentBytes > FORMAT_MAX_ACTIVE_BYTES + FORMAT_MAX_INDEX_FRAME_BYTES) {
			throw new Error("sealed segment content exceeds the fixed format maximum");
		}
		const observations = active.records.map((record) => record.observedAtMs);
		const previousAllocation = active.identity;
		const activeParentBefore = pathStorageState(this.#activeDirectory, true);
		const sealedParentBefore = pathStorageState(this.#sealedDirectory, true);
		try {
			this.#withActiveSegmentFile("read_write", (file) => {
				writeFullyAt(file, indexFrame, indexOffset);
				const footer: SegmentFooter = {
					version: 2,
					kind: "sealed-footer",
					segmentId: active.header.segmentId,
					segmentSequence: active.header.segmentSequence,
					createdAtMs: active.header.createdAtMs,
					sealedAtMs,
					reason,
					recordCount: active.records.length,
					gapCount: active.recoveryGaps.length,
					minObservedAtMs: observations.length === 0 ? null : Math.min(...observations),
					maxObservedAtMs: observations.length === 0 ? null : Math.max(...observations),
					indexOffset,
					indexFrameBytes: indexFrame.byteLength,
					indexSha256: sha256(indexFrame),
					contentBytes,
					contentSha256: hashFileRange(file, 0, contentBytes),
					idempotencyBloomBase64: idempotencyBloom(active.records),
				};
				assertSafeNonNegativeInteger(footer.sealedAtMs, "segment seal time");
				const footerFrame = encodeFrame(FrameType.Footer, active.nextOrdinal + 1, encodeJson(footer));
				if (footerFrame.byteLength > FORMAT_MAX_FOOTER_FRAME_BYTES) {
					throw new Error("sealed footer exceeds the fixed format maximum");
				}
				writeFullyAt(file, footerFrame, contentBytes);
				file.sync();
				const fileBytes = contentBytes + footerFrame.byteLength;
				const summary = this.#promoteActiveFile(active, footer, fileBytes);
				this.#active = undefined;
				const existingIndex = this.#sealed.findIndex(
					(candidate) => candidate.header.segmentId === summary.header.segmentId,
				);
				if (existingIndex >= 0) this.#sealed[existingIndex] = summary;
				else this.#sealed.push(summary);
				this.#sealed.sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
				this.#refreshReadCatalog();
				try {
					const allocation = pathAllocation(summary.path);
					this.#emitDurable({
						kind: "sealed",
						segmentId: summary.header.segmentId,
						path: summary.path,
						previousPath: active.path,
						entryChange: "same-inode-move",
						entryDelta: 0,
						inodeDelta: 0,
						previousLogicalBytes: previousAllocation.logicalBytes,
						previousAllocatedBytes: previousAllocation.allocatedBytes,
						...allocation,
						parentEffects: [
							parentDirectoryEffect(
								this.#activeDirectory,
								activeParentBefore,
								pathStorageState(this.#activeDirectory, true),
							),
							parentDirectoryEffect(
								this.#sealedDirectory,
								sealedParentBefore,
								pathStorageState(this.#sealedDirectory, true),
							),
						],
					});
				} catch (error) {
					this.#poison(error);
				}
			});
		} catch (error) {
			this.#poison(error);
		}
	}

	#estimateSealGrowth(
		active: Pick<ActiveSegment, "header" | "size" | "nextOrdinal" | "records" | "recoveryGaps">,
		records: SegmentIndexEntry[],
		reason: string,
		sealedAtMs: number,
	): number {
		const indexDocument: SegmentIndexDocument = {
			version: 2,
			kind: "segment-index",
			segmentId: active.header.segmentId,
			segmentSequence: active.header.segmentSequence,
			records,
			recoveryGaps: active.recoveryGaps,
		};
		const indexOrdinal = records.length + active.recoveryGaps.length + 1;
		const indexFrame = encodeFrame(FrameType.Index, indexOrdinal, encodeJson(indexDocument));
		if (indexFrame.byteLength > FORMAT_MAX_INDEX_FRAME_BYTES) {
			throw new Error("estimated segment index exceeds the fixed format maximum");
		}
		const addedRecordBytes = records.length > active.records.length ? (records.at(-1)?.frameBytes ?? 0) : 0;
		const indexOffset = active.size + addedRecordBytes;
		const observations = records.map((record) => record.observedAtMs);
		const footer: SegmentFooter = {
			version: 2,
			kind: "sealed-footer",
			segmentId: active.header.segmentId,
			segmentSequence: active.header.segmentSequence,
			createdAtMs: active.header.createdAtMs,
			sealedAtMs,
			reason,
			recordCount: records.length,
			gapCount: active.recoveryGaps.length,
			minObservedAtMs: observations.length === 0 ? null : Math.min(...observations),
			maxObservedAtMs: observations.length === 0 ? null : Math.max(...observations),
			indexOffset,
			indexFrameBytes: indexFrame.byteLength,
			indexSha256: "0".repeat(64),
			contentBytes: indexOffset + indexFrame.byteLength,
			contentSha256: "0".repeat(64),
			idempotencyBloomBase64: idempotencyBloom(records),
		};
		const footerFrame = encodeFrame(FrameType.Footer, indexOrdinal + 1, encodeJson(footer));
		if (footerFrame.byteLength > FORMAT_MAX_FOOTER_FRAME_BYTES) {
			throw new Error("estimated sealed footer exceeds the fixed format maximum");
		}
		return indexFrame.byteLength + footerFrame.byteLength;
	}

	estimateAppendStorage(
		input: IncidentRecorderSegmentAppendInput,
		sampledNow = this.#now(),
	): IncidentRecorderSegmentAppendStorageEstimate {
		this.#assertUsable();
		assertIdentifier(input.runId, "runId");
		assertIdentifier(input.sourceId, "sourceId");
		assertSafeNonNegativeInteger(input.observedAtMs, "observedAtMs");
		assertOrder(input.order);
		assertMetadata(input.metadata);
		if (encodeJson(input.metadata).byteLength > this.#maxMetadataBytes) {
			throw new Error("metadata exceeds maxMetadataBytes");
		}
		const payload = Buffer.from(input.payload);
		if (payload.byteLength > this.#maxRecordBytes) throw new Error("payload exceeds maxRecordBytes");
		const recordIdentity = canonicalRecordIdentity(input, payload.byteLength, sha256(payload));
		const envelope: RecordEnvelope = {
			version: 2,
			kind: "record",
			...recordIdentity,
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
			metadata: input.metadata,
			payloadBytes: payload.byteLength,
			payloadSha256: sha256(payload),
		};
		const envelopeBytes = encodeJson(envelope);
		if (envelopeBytes.byteLength > FORMAT_MAX_METADATA_BYTES + 4096) {
			throw new Error("record envelope exceeds the fixed format maximum");
		}
		const envelopeLength = Buffer.alloc(4);
		envelopeLength.writeUInt32LE(envelopeBytes.byteLength, 0);
		const recordFrame = encodeFrame(FrameType.Record, 0, Buffer.concat([envelopeLength, envelopeBytes, payload]));
		if (recordFrame.byteLength > FORMAT_MAX_RECORD_FRAME_BYTES) {
			throw new Error("record frame exceeds the fixed format maximum");
		}
		const now = sampledNow;
		assertSafeNonNegativeInteger(now, "storage estimate time");
		const current = this.#active;
		const willSealBeforeAppend =
			current !== undefined &&
			current.records.length + current.recoveryGaps.length > 0 &&
			(now - current.header.createdAtMs >= this.#maxSegmentAgeMs ||
				current.records.length >= this.#maxRecordsPerSegment ||
				current.size + recordFrame.byteLength > this.#maxSegmentBytes);
		const sealBeforeBytes =
			current && willSealBeforeAppend
				? this.#estimateSealGrowth(current, current.records, "rotation-before-append", now)
				: 0;
		const willCreateSegment = current === undefined || willSealBeforeAppend;
		let headerFrameBytes = 0;
		let target: Pick<ActiveSegment, "header" | "size" | "nextOrdinal" | "records" | "recoveryGaps">;
		if (willCreateSegment) {
			const conservativeId = "s".repeat(128);
			const header: SegmentHeader = {
				version: 2,
				kind: "segment-header",
				segmentId: conservativeId,
				segmentSequence: this.#nextSequence,
				createdAtMs: now,
			};
			headerFrameBytes = encodeFrame(FrameType.Header, 0, encodeJson(header)).byteLength;
			target = {
				header,
				size: headerFrameBytes,
				nextOrdinal: 1,
				records: [],
				recoveryGaps: [],
			};
		} else {
			target = current;
		}
		const projectedEntry: SegmentIndexEntry = {
			version: 1,
			segmentId: target.header.segmentId,
			segmentSequence: target.header.segmentSequence,
			ordinal: target.nextOrdinal,
			offset: target.size,
			frameBytes: recordFrame.byteLength,
			payloadBytes: payload.byteLength,
			payloadSha256: envelope.payloadSha256,
			idempotencyKey: envelope.idempotencyKey,
			canonicalContentSha256: envelope.canonicalContentSha256,
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
		};
		const projectedRecords = [...target.records, projectedEntry];
		const projectedSize = target.size + recordFrame.byteLength;
		const willSealAfterAppend =
			projectedRecords.length >= this.#maxRecordsPerSegment ||
			projectedSize >= this.#maxSegmentBytes ||
			now - target.header.createdAtMs >= this.#maxSegmentAgeMs;
		const sealAfterBytes = willSealAfterAppend
			? this.#estimateSealGrowth(target, projectedRecords, "rotation-after-append", now)
			: 0;
		let peakAdditionalAllocatedBytes: number;
		if (willSealBeforeAppend && current) {
			const currentAllocation = current.identity.allocatedBytes;
			const sealGrowth = Math.max(0, conservativeAllocatedBytes(current.size + sealBeforeBytes) - currentAllocation);
			const newFileBytes = headerFrameBytes + recordFrame.byteLength + sealAfterBytes;
			peakAdditionalAllocatedBytes = sealGrowth + conservativeAllocatedBytes(newFileBytes);
		} else if (willCreateSegment) {
			peakAdditionalAllocatedBytes = conservativeAllocatedBytes(
				headerFrameBytes + recordFrame.byteLength + sealAfterBytes,
			);
		} else if (current) {
			peakAdditionalAllocatedBytes = Math.max(
				0,
				conservativeAllocatedBytes(current.size + recordFrame.byteLength + sealAfterBytes) -
					current.identity.allocatedBytes,
			);
		} else {
			peakAdditionalAllocatedBytes = conservativeAllocatedBytes(recordFrame.byteLength + sealAfterBytes);
		}
		const parentDirectoryEntriesAtPeak =
			(willCreateSegment ? 2 : 0) + Number(willSealBeforeAppend) + Number(willSealAfterAppend);
		const parentDirectoryAllocatedBytes = conservativeDirectoryEntryAllocatedBytes(
			this.#directory,
			parentDirectoryEntriesAtPeak,
		);
		return {
			recordFrameBytes: recordFrame.byteLength,
			headerFrameBytes,
			sealBeforeBytes,
			sealAfterBytes,
			peakAdditionalBytes: sealBeforeBytes + headerFrameBytes + recordFrame.byteLength + sealAfterBytes,
			peakAdditionalAllocatedBytes: peakAdditionalAllocatedBytes + parentDirectoryAllocatedBytes,
			peakAdditionalEntries: willCreateSegment ? 2 : willSealAfterAppend ? 1 : 0,
			peakAdditionalInodes: willCreateSegment ? 1 : 0,
			willSealBeforeAppend,
			willSealAfterAppend,
			willCreateSegment,
		};
	}

	#appendFrozen(
		input: IncidentRecorderSegmentAppendInput,
		sampledNow: number,
		estimate: IncidentRecorderSegmentAppendStorageEstimate,
		plannedSegmentId?: string,
	): IncidentRecorderSegmentAppendResult {
		this.#assertUsable();
		assertIdentifier(input.runId, "runId");
		assertIdentifier(input.sourceId, "sourceId");
		assertSafeNonNegativeInteger(input.observedAtMs, "observedAtMs");
		assertOrder(input.order);
		assertMetadata(input.metadata);
		const metadataBytes = encodeJson(input.metadata).byteLength;
		if (metadataBytes > this.#maxMetadataBytes) throw new Error("metadata exceeds maxMetadataBytes");
		const payload = Buffer.from(input.payload);
		if (payload.byteLength > this.#maxRecordBytes) throw new Error("payload exceeds maxRecordBytes");
		const recordIdentity = canonicalRecordIdentity(input, payload.byteLength, sha256(payload));
		const envelope: RecordEnvelope = {
			version: 2,
			kind: "record",
			...recordIdentity,
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
			metadata: input.metadata,
			payloadBytes: payload.byteLength,
			payloadSha256: sha256(payload),
		};
		const existingLocator = this.#findIdempotentRecord(envelope.idempotencyKey, envelope.canonicalContentSha256);
		if (existingLocator) return { status: "existing", locator: existingLocator };
		const envelopeBytes = encodeJson(envelope);
		if (envelopeBytes.byteLength > FORMAT_MAX_METADATA_BYTES + 4096) {
			throw new Error("record envelope exceeds the fixed format maximum");
		}
		const envelopeLength = Buffer.alloc(4);
		envelopeLength.writeUInt32LE(envelopeBytes.byteLength, 0);
		const content = Buffer.concat([envelopeLength, envelopeBytes, payload]);
		const prospectiveFrameBytes = FRAME_OVERHEAD_BYTES + content.byteLength;
		if (prospectiveFrameBytes > FORMAT_MAX_RECORD_FRAME_BYTES) {
			throw new Error("record frame exceeds the fixed format maximum");
		}

		if (estimate.willSealBeforeAppend) {
			this.#sealActive("rotation-before-append", sampledNow);
		}
		const active = this.#active ?? this.#createActiveSegment(sampledNow, plannedSegmentId);
		const frame = encodeFrame(FrameType.Record, active.nextOrdinal, content);
		const offset = active.size;
		const entry: SegmentIndexEntry = {
			version: 1,
			segmentId: active.header.segmentId,
			segmentSequence: active.header.segmentSequence,
			ordinal: active.nextOrdinal,
			offset,
			frameBytes: frame.byteLength,
			payloadBytes: payload.byteLength,
			payloadSha256: envelope.payloadSha256,
			idempotencyKey: envelope.idempotencyKey,
			canonicalContentSha256: envelope.canonicalContentSha256,
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
		};
		const previousAllocation = active.identity;
		const recordParentBefore = pathStorageState(this.#activeDirectory, true);
		try {
			this.#withActiveSegmentFile("read_write", (file) => {
				writeFullyAt(file, frame, offset);
				this.#faultInjector?.("after-record-write-before-fsync");
				file.sync();
				active.records.push(entry);
				active.size += frame.byteLength;
				active.nextOrdinal += 1;
				const allocation = fileAllocation(file);
				active.identity = allocation;
				this.#emitDurable({
					kind: "record",
					segmentId: active.header.segmentId,
					path: active.path,
					entryChange: "same-inode-growth",
					entryDelta: 0,
					inodeDelta: 0,
					previousLogicalBytes: previousAllocation.logicalBytes,
					previousAllocatedBytes: previousAllocation.allocatedBytes,
					...allocation,
					parentEffects: [
						parentDirectoryEffect(
							this.#activeDirectory,
							recordParentBefore,
							pathStorageState(this.#activeDirectory, true),
						),
					],
				});
			});
			if (estimate.willSealAfterAppend) {
				this.#sealActive("rotation-after-append", sampledNow);
			}
		} catch (error) {
			return this.#poison(error);
		}
		this.#stateRevision += 1;
		return { status: "appended", locator: this.#locatorFromEntry(entry) };
	}

	planAppend(
		input: IncidentRecorderSegmentAppendInput,
		admit?: (estimate: IncidentRecorderSegmentAppendStorageEstimate) => void,
	): IncidentRecorderSegmentAppendPlan {
		this.#assertRawMutation("planAppend");
		this.#assertUsable();
		assertMetadata(input.metadata);
		const frozenMetadata = parseJson(Buffer.from(canonicalJson(input.metadata), "utf8"), "frozen append metadata");
		assertMetadata(frozenMetadata);
		const frozenInput: IncidentRecorderSegmentAppendInput = {
			...(input.idempotencyKey === undefined ? {} : { idempotencyKey: input.idempotencyKey }),
			runId: input.runId,
			sourceId: input.sourceId,
			observedAtMs: input.observedAtMs,
			order: input.order,
			metadata: frozenMetadata,
			payload: Buffer.from(input.payload),
		};
		const sampledNow = this.#now();
		const plannedRevision = this.#stateRevision;
		const payload = Buffer.from(frozenInput.payload);
		const identity = canonicalRecordIdentity(frozenInput, payload.byteLength, sha256(payload));
		const existing = this.#findIdempotentRecord(identity.idempotencyKey, identity.canonicalContentSha256);
		const estimate = Object.freeze(
			existing
				? {
						recordFrameBytes: 0,
						headerFrameBytes: 0,
						sealBeforeBytes: 0,
						sealAfterBytes: 0,
						peakAdditionalBytes: 0,
						peakAdditionalAllocatedBytes: 0,
						peakAdditionalEntries: 0,
						peakAdditionalInodes: 0,
						willSealBeforeAppend: false,
						willSealAfterAppend: false,
						willCreateSegment: false,
					}
				: this.estimateAppendStorage(frozenInput, sampledNow),
		);
		const plannedSegmentId = !existing && estimate.willCreateSegment ? this.#selectUniqueSegmentId() : undefined;
		admit?.(estimate);
		this.#assertUsable();
		if (this.#stateRevision !== plannedRevision) {
			throw new Error("store state changed during append admission; replan required");
		}
		const publicPlan = Object.freeze({ version: 1 as const, token: randomUUID(), estimate });
		this.#appendPlans.set(publicPlan.token, {
			publicPlan,
			input: frozenInput,
			sampledNow,
			stateRevision: plannedRevision,
			...(plannedSegmentId === undefined ? {} : { plannedSegmentId }),
		});
		return publicPlan;
	}

	commitAppendPlan(plan: IncidentRecorderSegmentAppendPlan): IncidentRecorderSegmentAppendResult {
		this.#assertRawMutation("commitAppendPlan");
		this.#assertUsable();
		const frozen = this.#appendPlans.get(plan.token);
		this.#appendPlans.delete(plan.token);
		if (!frozen || frozen.publicPlan !== plan || plan.version !== 1) {
			throw new Error("append plan is unknown or already consumed");
		}
		if (frozen.stateRevision !== this.#stateRevision) {
			throw new Error("append plan is stale because store state changed; replan required");
		}
		if (
			frozen.plannedSegmentId &&
			(pathStatus(join(this.#activeDirectory, frozen.plannedSegmentId + ".open")) ||
				pathStatus(join(this.#sealedDirectory, frozen.plannedSegmentId + ".segment")))
		) {
			throw new Error("planned segment identity is no longer unique");
		}
		return this.#appendFrozen(frozen.input, frozen.sampledNow, frozen.publicPlan.estimate, frozen.plannedSegmentId);
	}

	append(input: IncidentRecorderSegmentAppendInput): IncidentRecorderSegmentAppendResult {
		this.#assertRawMutation("append");
		return this.commitAppendPlan(this.planAppend(input));
	}

	seal(reason: string): void {
		this.#assertRawMutation("seal");
		this.#assertUsable();
		if (reason.length === 0 || reason.length > 256) throw new Error("seal reason must contain 1 to 256 characters");
		this.#sealActive(reason);
		this.#stateRevision += 1;
	}

	#locatorFromEntry(entry: SegmentIndexEntry): IncidentRecorderSegmentLocator {
		return {
			version: 1,
			segmentId: entry.segmentId,
			segmentSequence: entry.segmentSequence,
			ordinal: entry.ordinal,
			offset: entry.offset,
			frameBytes: entry.frameBytes,
			payloadBytes: entry.payloadBytes,
			payloadSha256: entry.payloadSha256,
		};
	}

	#findIdempotentRecord(
		idempotencyKey: string,
		canonicalContentSha256: string,
	): IncidentRecorderSegmentLocator | undefined {
		if (this.#corrupt.some((segment) => !segment.summary)) {
			throw new Error("cannot prove idempotency while retained segment identity is corrupt");
		}
		const activeEntry = this.#active?.records.find((entry) => entry.idempotencyKey === idempotencyKey);
		if (activeEntry) {
			if (activeEntry.canonicalContentSha256 !== canonicalContentSha256) {
				throw new Error("idempotencyKey was already committed with different canonical content");
			}
			return this.#locatorFromEntry(activeEntry);
		}
		let examinedSegments = 0;
		let examinedRecords = 0;
		const summaries = [
			...this.#sealed,
			...this.#corrupt.flatMap((segment) => (segment.summary ? [segment.summary] : [])),
		].sort((left, right) => right.header.segmentSequence - left.header.segmentSequence);
		const retainedSegmentIds = new Set(summaries.map((summary) => summary.header.segmentId));
		for (const segmentId of this.#validatedIdempotencyBloomSegmentIds) {
			if (!retainedSegmentIds.has(segmentId)) this.#validatedIdempotencyBloomSegmentIds.delete(segmentId);
		}
		for (const summary of summaries) {
			examinedSegments += 1;
			if (examinedSegments > this.#maxIdempotencyLookupSegments) {
				throw new Error("bounded idempotency lookup cannot prove absence within maxIdempotencyLookupSegments");
			}
			const bloomMayContain = idempotencyBloomMayContain(summary.footer.idempotencyBloomBase64, idempotencyKey);
			if (!bloomMayContain && this.#validatedIdempotencyBloomSegmentIds.has(summary.header.segmentId)) {
				continue;
			}
			if (examinedRecords + summary.footer.recordCount > this.#maxIdempotencyLookupRecords) {
				throw new Error("bounded idempotency lookup cannot prove absence within maxIdempotencyLookupRecords");
			}
			const index = this.#readIndex(summary);
			examinedRecords += summary.footer.recordCount;
			this.#validatedIdempotencyBloomSegmentIds.add(summary.header.segmentId);
			if (!bloomMayContain) continue;
			const entry = index.records.find((candidate) => candidate.idempotencyKey === idempotencyKey);
			if (!entry) continue;
			if (entry.canonicalContentSha256 !== canonicalContentSha256) {
				throw new Error("idempotencyKey was already committed with different canonical content");
			}
			return this.#locatorFromEntry(entry);
		}
		return undefined;
	}

	#assertLocatorMatchesEntry(locator: IncidentRecorderSegmentLocator, entry: SegmentIndexEntry): void {
		if (
			locator.segmentId !== entry.segmentId ||
			locator.segmentSequence !== entry.segmentSequence ||
			locator.ordinal !== entry.ordinal ||
			locator.offset !== entry.offset ||
			locator.frameBytes !== entry.frameBytes ||
			locator.payloadBytes !== entry.payloadBytes ||
			locator.payloadSha256 !== entry.payloadSha256
		) {
			throw new InvalidFrameError("record locator conflicts with the retained segment index");
		}
	}

	readRecord(locator: IncidentRecorderSegmentLocator): IncidentRecorderSegmentRecord | undefined {
		this.#assertRawRead("readRecord");
		this.#assertUsable();
		assertRecordLocator(locator);
		const corrupt = this.#corrupt.find((segment) => segment.segmentId === locator.segmentId);
		if (corrupt) {
			if (corrupt.summary && corrupt.summary.header.segmentSequence !== locator.segmentSequence) {
				throw new InvalidFrameError("record locator conflicts with a retained corrupt segment identity");
			}
			throw new InvalidFrameError("record locator references a corrupt retained segment");
		}
		const active = this.#active;
		if (active?.header.segmentId === locator.segmentId) {
			if (active.header.segmentSequence !== locator.segmentSequence) {
				throw new InvalidFrameError("record locator conflicts with the active segment identity");
			}
			const entry = active.records.find((candidate) => candidate.ordinal === locator.ordinal);
			if (!entry) throw new InvalidFrameError("record locator ordinal is absent from the active segment");
			this.#assertLocatorMatchesEntry(locator, entry);
			return this.#withActiveSegmentFile("read", (file) =>
				this.#readRecordAt(file, active.size, active.header, entry),
			);
		}
		const summary = this.#sealed.find((segment) => segment.header.segmentId === locator.segmentId);
		if (!summary) return undefined;
		if (summary.header.segmentSequence !== locator.segmentSequence) {
			throw new InvalidFrameError("record locator conflicts with the sealed segment identity");
		}
		const locatorEnd = locator.offset + locator.frameBytes;
		if (
			!Number.isSafeInteger(locatorEnd) ||
			locator.offset < FRAME_OVERHEAD_BYTES ||
			locatorEnd > summary.footer.indexOffset
		) {
			throw new InvalidFrameError("record locator lies outside sealed record bounds");
		}
		const index = this.#readIndex(summary);
		const entry = index.records.find((candidate) => candidate.ordinal === locator.ordinal);
		if (!entry) throw new InvalidFrameError("record locator ordinal is absent from the sealed index");
		this.#assertLocatorMatchesEntry(locator, entry);
		const fileDescriptor = openSync(summary.path, constants.O_RDONLY | constants.O_NOFOLLOW);
		try {
			assertPrivateRegularFile(fileDescriptor, summary.path);
			const status = fstatSync(fileDescriptor);
			if (status.size !== summary.fileBytes) {
				throw new InvalidFrameError("sealed segment size changed after locator validation");
			}
			return this.#readRecordAt(fileDescriptor, status.size, summary.header, entry);
		} finally {
			closeSync(fileDescriptor);
		}
	}

	readRecordWithinRoot(
		root: IncidentCasRootMutation,
		locator: IncidentRecorderSegmentLocator,
	): IncidentRecorderSegmentRecord | undefined {
		this.#assertRootBacked("readRecordWithinRoot");
		this.#assertUsable();
		assertRecordLocator(locator);
		const corrupt = this.#corrupt.find((segment) => segment.segmentId === locator.segmentId);
		if (corrupt) {
			if (corrupt.summary && corrupt.summary.header.segmentSequence !== locator.segmentSequence) {
				throw new InvalidFrameError("record locator conflicts with a retained corrupt segment identity");
			}
			throw new InvalidFrameError("record locator references a corrupt retained segment");
		}
		const active = this.#active;
		if (active?.header.segmentId === locator.segmentId) {
			if (active.header.segmentSequence !== locator.segmentSequence) {
				throw new InvalidFrameError("record locator conflicts with the active segment identity");
			}
			const entry = active.records.find((candidate) => candidate.ordinal === locator.ordinal);
			if (!entry) throw new InvalidFrameError("record locator ordinal is absent from the active segment");
			this.#assertLocatorMatchesEntry(locator, entry);
			return this.#withActiveSegmentFileWithinRoot(root, "read", (file) =>
				this.#readRecordAt(file, active.size, active.header, entry),
			);
		}
		const summary = this.#sealed.find((segment) => segment.header.segmentId === locator.segmentId);
		if (!summary) return undefined;
		if (summary.header.segmentSequence !== locator.segmentSequence) {
			throw new InvalidFrameError("record locator conflicts with the sealed segment identity");
		}
		const locatorEnd = locator.offset + locator.frameBytes;
		if (
			!Number.isSafeInteger(locatorEnd) ||
			locator.offset < FRAME_OVERHEAD_BYTES ||
			locatorEnd > summary.footer.indexOffset
		) {
			throw new InvalidFrameError("record locator lies outside sealed record bounds");
		}
		const index = this.#readIndexWithinRoot(root, summary);
		const entry = index.records.find((candidate) => candidate.ordinal === locator.ordinal);
		if (!entry) throw new InvalidFrameError("record locator ordinal is absent from the sealed index");
		this.#assertLocatorMatchesEntry(locator, entry);
		const path = this.#rootPathString(root, "sealed", basename(summary.path));
		return root.withFile(this.#rootPath(root, "sealed", basename(summary.path)), { access: "read" }, (file) => {
			assertPrivateRegularFile(file, path);
			const status = file.stat();
			if (Number(status.size) !== summary.fileBytes) {
				throw new InvalidFrameError("sealed segment size changed after locator validation");
			}
			return this.#readRecordAt(file, Number(status.size), summary.header, entry);
		});
	}

	#readRecordAt(
		file: IncidentRecorderSegmentFileHandle,
		fileSize: number,
		header: SegmentHeader,
		entry: SegmentIndexEntry,
	): IncidentRecorderSegmentRecord {
		const frame = parseFrameAt(file, entry.offset, fileSize);
		if (frame.type !== FrameType.Record || frame.ordinal !== entry.ordinal || frame.frameBytes !== entry.frameBytes) {
			throw new InvalidFrameError("record frame does not match its sealed index locator");
		}
		const { envelope, payload } = parseRecordContent(frame);
		if (
			entry.segmentId !== header.segmentId ||
			entry.segmentSequence !== header.segmentSequence ||
			envelope.runId !== entry.runId ||
			envelope.idempotencyKey !== entry.idempotencyKey ||
			envelope.canonicalContentSha256 !== entry.canonicalContentSha256 ||
			envelope.sourceId !== entry.sourceId ||
			envelope.observedAtMs !== entry.observedAtMs ||
			envelope.order !== entry.order ||
			envelope.payloadBytes !== entry.payloadBytes ||
			envelope.payloadSha256 !== entry.payloadSha256
		) {
			throw new InvalidFrameError("record frame identity does not match its sealed index");
		}
		return {
			idempotencyKey: envelope.idempotencyKey,
			runId: envelope.runId,
			sourceId: envelope.sourceId,
			observedAtMs: envelope.observedAtMs,
			order: envelope.order,
			metadata: envelope.metadata,
			payload,
			locator: {
				version: 1,
				segmentId: entry.segmentId,
				segmentSequence: entry.segmentSequence,
				ordinal: entry.ordinal,
				offset: entry.offset,
				frameBytes: entry.frameBytes,
				payloadBytes: entry.payloadBytes,
				payloadSha256: entry.payloadSha256,
			},
		};
	}

	#readHighWater(): { highWaterSegmentSequence: number; highWaterOrdinal: number } {
		let highWaterSegmentSequence = 0;
		let highWaterOrdinal = 0;
		const consider = (segmentSequence: number, ordinal: number): void => {
			if (
				segmentSequence > highWaterSegmentSequence ||
				(segmentSequence === highWaterSegmentSequence && ordinal > highWaterOrdinal)
			) {
				highWaterSegmentSequence = segmentSequence;
				highWaterOrdinal = ordinal;
			}
		};
		const latest = this.#readCatalog.at(-1);
		if (latest) consider(latest.header.segmentSequence, latest.footer.recordCount + latest.footer.gapCount);
		if (this.#active) consider(this.#active.header.segmentSequence, this.#active.nextOrdinal - 1);
		return { highWaterSegmentSequence, highWaterOrdinal };
	}

	createReadSnapshot(): IncidentRecorderSegmentReadSnapshot {
		this.#assertUsable();
		const { highWaterSegmentSequence, highWaterOrdinal } = this.#readHighWater();
		return Object.freeze({
			version: 1 as const,
			id: this.#instanceId,
			generation: this.#generation,
			highWaterSegmentSequence,
			highWaterOrdinal,
		});
	}

	#sweepExpiredReadLeases(now = this.#now()): void {
		for (const [token, lease] of this.#readLeases) {
			if (lease.expiresAtMs <= now) this.#readLeases.delete(token);
		}
	}

	#assertReadLeaseShape(lease: IncidentRecorderSegmentReadLease): void {
		if (!lease || lease.version !== 1) throw new Error("segment read lease version is unsupported");
		if (!Object.isFrozen(lease)) throw new Error("segment read lease must be the exact frozen registered object");
		if (typeof lease.storeInstanceId !== "string" || lease.storeInstanceId.length === 0) {
			throw new Error("segment read lease store instance is invalid");
		}
		if (typeof lease.token !== "string" || lease.token.length === 0) {
			throw new Error("segment read lease token is invalid");
		}
		assertSafeNonNegativeInteger(lease.acquiredAtMs, "segment read lease acquisition time");
		assertSafeNonNegativeInteger(lease.expiresAtMs, "segment read lease expiry time");
		if (lease.expiresAtMs <= lease.acquiredAtMs) {
			throw new Error("segment read lease expiry must follow acquisition");
		}
		assertSafeNonNegativeInteger(lease.highWaterSegmentSequence, "segment read lease segment sequence");
		assertSafeNonNegativeInteger(lease.highWaterOrdinal, "segment read lease ordinal");
	}

	acquireReadLease(expiresAtMs: number): IncidentRecorderSegmentReadLease {
		this.#assertUsable();
		const acquiredAtMs = this.#now();
		assertSafeNonNegativeInteger(acquiredAtMs, "segment read lease acquisition time");
		assertSafeNonNegativeInteger(expiresAtMs, "segment read lease expiry time");
		if (expiresAtMs <= acquiredAtMs) throw new Error("segment read lease expiry must be in the future");
		this.#sweepExpiredReadLeases(acquiredAtMs);
		if (this.#readLeases.size >= MAX_ACTIVE_READ_LEASES) {
			throw new Error(`segment read lease registry exceeds the ${String(MAX_ACTIVE_READ_LEASES)}-lease ceiling`);
		}
		const { highWaterSegmentSequence, highWaterOrdinal } = this.#readHighWater();
		const lease = Object.freeze({
			version: 1 as const,
			storeInstanceId: this.#instanceId,
			token: randomUUID(),
			acquiredAtMs,
			expiresAtMs,
			highWaterSegmentSequence,
			highWaterOrdinal,
		});
		this.#readLeases.set(lease.token, lease);
		return lease;
	}

	assertReadLeaseUsable(lease: IncidentRecorderSegmentReadLease): void {
		this.#assertUsable();
		this.#assertReadLeaseShape(lease);
		if (lease.storeInstanceId !== this.#instanceId) {
			throw new Error("segment read lease belongs to a different store instance");
		}
		const registered = this.#readLeases.get(lease.token);
		if (!registered) throw new Error("segment read lease is not active");
		if (registered !== lease) {
			throw new Error("segment read lease is not the exact registered object");
		}
		if (registered.expiresAtMs <= this.#now()) {
			this.#readLeases.delete(lease.token);
			throw new Error("segment read lease expired");
		}
	}

	releaseReadLease(lease: IncidentRecorderSegmentReadLease): boolean {
		if (this.#closed) return false;
		this.#assertUsable();
		this.#assertReadLeaseShape(lease);
		if (lease.storeInstanceId !== this.#instanceId) {
			throw new Error("segment read lease belongs to a different store instance");
		}
		const registered = this.#readLeases.get(lease.token);
		if (!registered) return false;
		if (registered !== lease) {
			throw new Error("segment read lease is not the exact registered object");
		}
		if (registered.expiresAtMs <= this.#now()) {
			this.#readLeases.delete(lease.token);
			return false;
		}
		return this.#readLeases.delete(lease.token);
	}

	assertReadSnapshotUsable(snapshot: IncidentRecorderSegmentReadSnapshot): void {
		this.#assertUsable();
		if (snapshot.version !== 1) throw new Error("segment read snapshot version is unsupported");
		assertSafeNonNegativeInteger(snapshot.generation, "segment read snapshot generation");
		assertSafeNonNegativeInteger(snapshot.highWaterSegmentSequence, "segment read snapshot segment sequence");
		assertSafeNonNegativeInteger(snapshot.highWaterOrdinal, "segment read snapshot ordinal");
		if (snapshot.id !== this.#instanceId || snapshot.generation !== this.#generation) {
			throw new Error("segment read snapshot is stale; restart required");
		}
	}

	queryRunWindowPage(query: IncidentRecorderSegmentPageQuery): IncidentRecorderSegmentQueryPage {
		this.#assertRawRead("queryRunWindowPage");
		return this.#queryRunWindowPage(query);
	}

	queryRunWindowPageWithinRoot(
		root: IncidentCasRootMutation,
		query: IncidentRecorderSegmentPageQuery,
	): IncidentRecorderSegmentQueryPage {
		this.#assertRootBacked("queryRunWindowPageWithinRoot");
		return this.#queryRunWindowPage(query, root);
	}

	#queryRunWindowPage(
		query: IncidentRecorderSegmentPageQuery,
		root?: IncidentCasRootMutation,
	): IncidentRecorderSegmentQueryPage {
		this.#assertUsable();
		assertIdentifier(query.runId, "query runId");
		if (query.sourceId !== undefined) assertIdentifier(query.sourceId, "query sourceId");
		assertSafeNonNegativeInteger(query.fromObservedAtMs, "query start time");
		assertSafeNonNegativeInteger(query.throughObservedAtMs, "query end time");
		if (query.fromObservedAtMs > query.throughObservedAtMs) throw new Error("query time bounds are reversed");
		const filterSha256 = sha256(
			Buffer.from(
				canonicalJson({
					runId: query.runId,
					sourceId: query.sourceId ?? null,
					fromObservedAtMs: query.fromObservedAtMs,
					throughObservedAtMs: query.throughObservedAtMs,
				}),
				"utf8",
			),
		);
		const pageMaxRecords = positiveInteger(
			query.maxRecords,
			this.#maxQueryRecords,
			"page maxRecords",
			this.#maxQueryRecords,
		);
		const pageMaxBytes = positiveInteger(query.maxBytes, this.#maxQueryBytes, "page maxBytes", this.#maxQueryBytes);
		const pageMaxScannedSegments = positiveInteger(
			query.maxScannedSegments,
			DEFAULT_MAX_QUERY_SCANNED_SEGMENTS,
			"page maxScannedSegments",
			DEFAULT_MAX_QUERY_SCANNED_SEGMENTS,
		);
		const pageMaxScannedRecords = positiveInteger(
			query.maxScannedRecords,
			DEFAULT_MAX_QUERY_SCANNED_RECORDS,
			"page maxScannedRecords",
			DEFAULT_MAX_QUERY_SCANNED_RECORDS,
		);
		const pageMaxScannedIndexBytes = positiveInteger(
			query.maxScannedIndexBytes,
			DEFAULT_MAX_QUERY_SCANNED_INDEX_BYTES,
			"page maxScannedIndexBytes",
			DEFAULT_MAX_QUERY_SCANNED_INDEX_BYTES,
		);
		if (query.readSnapshot && query.readLease) {
			throw new Error("query cannot combine a read snapshot descriptor with a live read lease");
		}
		let readSnapshot: IncidentRecorderSegmentReadSnapshot;
		if (query.readLease) {
			this.assertReadLeaseUsable(query.readLease);
			readSnapshot = {
				version: 1,
				id: query.readLease.token,
				generation: 0,
				highWaterSegmentSequence: query.readLease.highWaterSegmentSequence,
				highWaterOrdinal: query.readLease.highWaterOrdinal,
			};
		} else {
			readSnapshot = query.readSnapshot
				? query.readSnapshot
				: query.after
					? {
							version: 1,
							id: query.after.snapshotId,
							generation: query.after.generation,
							highWaterSegmentSequence: query.after.highWaterSegmentSequence,
							highWaterOrdinal: query.after.highWaterOrdinal,
						}
					: this.createReadSnapshot();
			this.assertReadSnapshotUsable(readSnapshot);
		}
		if (query.after) {
			if (query.after.version !== 1) throw new Error("query cursor version is unsupported");
			if (
				query.after.snapshotId !== readSnapshot.id ||
				query.after.generation !== readSnapshot.generation ||
				query.after.highWaterSegmentSequence !== readSnapshot.highWaterSegmentSequence ||
				query.after.highWaterOrdinal !== readSnapshot.highWaterOrdinal ||
				query.after.filterSha256 !== filterSha256
			) {
				throw new Error("query snapshot is stale or does not match the frozen filter; restart required");
			}
			assertSafeNonNegativeInteger(query.after.segmentSequence, "query cursor segment sequence");
			assertSafeNonNegativeInteger(query.after.ordinal, "query cursor ordinal");
			if (
				query.after.segmentSequence > readSnapshot.highWaterSegmentSequence ||
				(query.after.segmentSequence === readSnapshot.highWaterSegmentSequence &&
					query.after.ordinal > readSnapshot.highWaterOrdinal)
			) {
				throw new Error("query cursor lies beyond the frozen snapshot frontier");
			}
		}
		const highWaterSegmentSequence = readSnapshot.highWaterSegmentSequence;
		const highWaterOrdinal = readSnapshot.highWaterOrdinal;
		const snapshot: IncidentRecorderSegmentQuerySnapshot = {
			version: 1,
			id: readSnapshot.id,
			generation: readSnapshot.generation,
			highWaterSegmentSequence,
			highWaterOrdinal,
			filterSha256,
		};
		if (this.#hasUncataloguedCorruptSegment) {
			throw new InvalidFrameError("an uncatalogued corrupt segment prevents an exact query");
		}
		const records: IncidentRecorderSegmentRecord[] = [];
		let selectedFrameBytes = 0;
		let scannedSegments = 0;
		let scannedRecords = 0;
		let scannedIndexBytes = 0;
		let complete = true;
		let frontierSegmentSequence = query.after?.segmentSequence ?? 0;
		let frontierOrdinal = query.after?.ordinal ?? 0;
		const isAfterFrontier = (entry: SegmentIndexEntry): boolean =>
			(entry.segmentSequence > frontierSegmentSequence ||
				(entry.segmentSequence === frontierSegmentSequence && entry.ordinal > frontierOrdinal)) &&
			(entry.segmentSequence < highWaterSegmentSequence ||
				(entry.segmentSequence === highWaterSegmentSequence && entry.ordinal <= highWaterOrdinal));
		const matches = (entry: SegmentIndexEntry): boolean =>
			entry.runId === query.runId &&
			(query.sourceId === undefined || entry.sourceId === query.sourceId) &&
			entry.observedAtMs >= query.fromObservedAtMs &&
			entry.observedAtMs <= query.throughObservedAtMs;
		const canTake = (entry: SegmentIndexEntry): boolean => {
			if (records.length + 1 > pageMaxRecords || selectedFrameBytes + entry.frameBytes > pageMaxBytes) {
				if (records.length === 0)
					throw new Error("next selected full frame bytes exceed maxQueryBytes for this page");
				complete = false;
				return false;
			}
			selectedFrameBytes += entry.frameBytes;
			return true;
		};
		const advanceFrontier = (segmentSequence: number, ordinal: number): void => {
			if (
				segmentSequence > frontierSegmentSequence ||
				(segmentSequence === frontierSegmentSequence && ordinal > frontierOrdinal)
			) {
				frontierSegmentSequence = segmentSequence;
				frontierOrdinal = ordinal;
			}
		};
		const frozenOrdinalFor = (segmentSequence: number, availableOrdinal: number): number =>
			segmentSequence === highWaterSegmentSequence ? Math.min(availableOrdinal, highWaterOrdinal) : availableOrdinal;

		const firstSummaryIndex = firstSegmentAtOrAfter(this.#readCatalog, frontierSegmentSequence);
		for (let summaryIndex = firstSummaryIndex; summaryIndex < this.#readCatalog.length; summaryIndex += 1) {
			const summary = this.#readCatalog[summaryIndex];
			if (!summary) break;
			if (!complete) break;
			if (summary.header.segmentSequence > highWaterSegmentSequence) break;
			const frozenOrdinal = frozenOrdinalFor(
				summary.header.segmentSequence,
				summary.footer.recordCount + summary.footer.gapCount,
			);
			if (
				summary.header.segmentSequence < frontierSegmentSequence ||
				(summary.header.segmentSequence === frontierSegmentSequence && frozenOrdinal <= frontierOrdinal)
			) {
				continue;
			}
			if (scannedSegments >= pageMaxScannedSegments) {
				complete = false;
				break;
			}
			scannedSegments += 1;
			if (
				summary.footer.recordCount === 0 ||
				(summary.footer.maxObservedAtMs ?? -1) < query.fromObservedAtMs ||
				(summary.footer.minObservedAtMs ?? Number.MAX_SAFE_INTEGER) > query.throughObservedAtMs
			) {
				advanceFrontier(summary.header.segmentSequence, frozenOrdinal);
				continue;
			}
			if (summary.footer.indexFrameBytes > pageMaxScannedIndexBytes) {
				throw new IncidentRecorderSegmentPageBudgetExceededError({
					segmentId: summary.header.segmentId,
					frameKind: "record-index",
					requiredBytes: summary.footer.indexFrameBytes,
					configuredBytes: pageMaxScannedIndexBytes,
				});
			}
			if (scannedIndexBytes + summary.footer.indexFrameBytes > pageMaxScannedIndexBytes) {
				complete = false;
				break;
			}
			const index = root ? this.#readIndexWithinRoot(root, summary) : this.#readIndex(summary);
			scannedIndexBytes += summary.footer.indexFrameBytes;
			const visit = (file: IncidentRecorderSegmentFileView, fileSize: number): void => {
				const firstRecordIndex =
					summary.header.segmentSequence === frontierSegmentSequence
						? firstOrdinalAfter(index.records, frontierOrdinal)
						: 0;
				for (let recordIndex = firstRecordIndex; recordIndex < index.records.length; recordIndex += 1) {
					const entry = index.records[recordIndex];
					if (!entry || !isAfterFrontier(entry)) continue;
					if (scannedRecords >= pageMaxScannedRecords) {
						complete = false;
						break;
					}
					scannedRecords += 1;
					if (!matches(entry)) {
						advanceFrontier(entry.segmentSequence, entry.ordinal);
						continue;
					}
					if (!canTake(entry)) break;
					records.push(this.#readRecordAt(file, fileSize, summary.header, entry));
					advanceFrontier(entry.segmentSequence, entry.ordinal);
				}
			};
			if (root) this.#withSealedSegmentFileWithinRoot(root, summary, visit);
			else this.#withSealedSegmentFile(summary, visit);
			if (complete) advanceFrontier(summary.header.segmentSequence, frozenOrdinal);
		}
		const active = this.#active;
		if (complete && active) {
			const activeSequence = active.header.segmentSequence;
			const frozenOrdinal = frozenOrdinalFor(activeSequence, active.nextOrdinal - 1);
			const activeRemains =
				activeSequence <= highWaterSegmentSequence &&
				(activeSequence > frontierSegmentSequence ||
					(activeSequence === frontierSegmentSequence && frozenOrdinal > frontierOrdinal));
			if (activeRemains && scannedSegments >= pageMaxScannedSegments) complete = false;
			if (complete && activeRemains) {
				scannedSegments += 1;
				const firstActiveRecordIndex =
					activeSequence === frontierSegmentSequence ? firstOrdinalAfter(active.records, frontierOrdinal) : 0;
				const visitActive = (file: IncidentRecorderSegmentFileView): void => {
					for (let recordIndex = firstActiveRecordIndex; recordIndex < active.records.length; recordIndex += 1) {
						const entry = active.records[recordIndex];
						if (!entry || !complete || !isAfterFrontier(entry)) continue;
						if (scannedRecords >= pageMaxScannedRecords) {
							complete = false;
							break;
						}
						scannedRecords += 1;
						if (!matches(entry)) {
							advanceFrontier(entry.segmentSequence, entry.ordinal);
							continue;
						}
						if (!canTake(entry)) break;
						records.push(this.#readRecordAt(file, active.size, active.header, entry));
						advanceFrontier(entry.segmentSequence, entry.ordinal);
					}
				};
				if (root) this.#withActiveSegmentFileWithinRoot(root, "read", visitActive);
				else this.#withActiveSegmentFile("read", visitActive);
				if (complete) advanceFrontier(activeSequence, frozenOrdinal);
			}
		}
		return {
			records,
			complete,
			selectedFrameBytes,
			scannedSegments,
			scannedRecords,
			scannedIndexBytes,
			snapshot,
			...(complete
				? {}
				: {
						nextCursor: {
							version: 1 as const,
							snapshotId: snapshot.id,
							generation: snapshot.generation,
							highWaterSegmentSequence: snapshot.highWaterSegmentSequence,
							highWaterOrdinal: snapshot.highWaterOrdinal,
							filterSha256: snapshot.filterSha256,
							segmentSequence: frontierSegmentSequence,
							ordinal: frontierOrdinal,
						},
					}),
		};
	}

	queryRunWindow(query: IncidentRecorderSegmentQuery): IncidentRecorderSegmentRecord[] {
		const page = this.queryRunWindowPage(query);
		if (!page.complete) throw new Error("query exceeds the configured output or examined-work bounds");
		return page.records;
	}

	queryRecoveryGapsPage(
		query: IncidentRecorderSegmentRecoveryGapPageQuery,
	): IncidentRecorderSegmentRecoveryGapQueryPage {
		this.#assertRawRead("queryRecoveryGapsPage");
		return this.#queryRecoveryGapsPage(query);
	}

	queryRecoveryGapsPageWithinRoot(
		root: IncidentCasRootMutation,
		query: IncidentRecorderSegmentRecoveryGapPageQuery,
	): IncidentRecorderSegmentRecoveryGapQueryPage {
		this.#assertRootBacked("queryRecoveryGapsPageWithinRoot");
		return this.#queryRecoveryGapsPage(query, root);
	}

	#queryRecoveryGapsPage(
		query: IncidentRecorderSegmentRecoveryGapPageQuery,
		root?: IncidentCasRootMutation,
	): IncidentRecorderSegmentRecoveryGapQueryPage {
		this.#assertUsable();
		const filterSha256 = sha256(Buffer.from(canonicalJson({ kind: "global-recovery-gaps", version: 1 }), "utf8"));
		const pageMaxGaps = positiveInteger(query.maxGaps, this.#maxQueryRecords, "page maxGaps", this.#maxQueryRecords);
		const pageMaxBytes = positiveInteger(query.maxBytes, this.#maxQueryBytes, "page maxBytes", this.#maxQueryBytes);
		const pageMaxScannedSegments = positiveInteger(
			query.maxScannedSegments,
			DEFAULT_MAX_QUERY_SCANNED_SEGMENTS,
			"page maxScannedSegments",
			DEFAULT_MAX_QUERY_SCANNED_SEGMENTS,
		);
		const pageMaxScannedGaps = positiveInteger(
			query.maxScannedGaps,
			DEFAULT_MAX_QUERY_SCANNED_GAPS,
			"page maxScannedGaps",
			DEFAULT_MAX_QUERY_SCANNED_GAPS,
		);
		const pageMaxScannedIndexBytes = positiveInteger(
			query.maxScannedIndexBytes,
			DEFAULT_MAX_QUERY_SCANNED_INDEX_BYTES,
			"page maxScannedIndexBytes",
			DEFAULT_MAX_QUERY_SCANNED_INDEX_BYTES,
		);
		if (query.readSnapshot && query.readLease) {
			throw new Error("recovery-gap query cannot combine a read snapshot descriptor with a live read lease");
		}
		let readSnapshot: IncidentRecorderSegmentReadSnapshot;
		if (query.readLease) {
			this.assertReadLeaseUsable(query.readLease);
			readSnapshot = {
				version: 1,
				id: query.readLease.token,
				generation: 0,
				highWaterSegmentSequence: query.readLease.highWaterSegmentSequence,
				highWaterOrdinal: query.readLease.highWaterOrdinal,
			};
		} else {
			readSnapshot = query.readSnapshot
				? query.readSnapshot
				: query.after
					? {
							version: 1,
							id: query.after.snapshotId,
							generation: query.after.generation,
							highWaterSegmentSequence: query.after.highWaterSegmentSequence,
							highWaterOrdinal: query.after.highWaterOrdinal,
						}
					: this.createReadSnapshot();
			this.assertReadSnapshotUsable(readSnapshot);
		}
		if (query.after) {
			if (query.after.version !== 1) throw new Error("recovery-gap query cursor version is unsupported");
			if (
				query.after.snapshotId !== readSnapshot.id ||
				query.after.generation !== readSnapshot.generation ||
				query.after.highWaterSegmentSequence !== readSnapshot.highWaterSegmentSequence ||
				query.after.highWaterOrdinal !== readSnapshot.highWaterOrdinal ||
				query.after.filterSha256 !== filterSha256
			) {
				throw new Error(
					"recovery-gap query snapshot is stale or does not match the frozen filter; restart required",
				);
			}
			assertSafeNonNegativeInteger(query.after.segmentSequence, "recovery-gap query cursor segment sequence");
			assertSafeNonNegativeInteger(query.after.ordinal, "recovery-gap query cursor ordinal");
			if (
				query.after.segmentSequence > readSnapshot.highWaterSegmentSequence ||
				(query.after.segmentSequence === readSnapshot.highWaterSegmentSequence &&
					query.after.ordinal > readSnapshot.highWaterOrdinal)
			) {
				throw new Error("recovery-gap query cursor lies beyond the frozen snapshot frontier");
			}
		}
		const highWaterSegmentSequence = readSnapshot.highWaterSegmentSequence;
		const highWaterOrdinal = readSnapshot.highWaterOrdinal;
		const snapshot: IncidentRecorderSegmentQuerySnapshot = {
			version: 1,
			id: readSnapshot.id,
			generation: readSnapshot.generation,
			highWaterSegmentSequence,
			highWaterOrdinal,
			filterSha256,
		};
		if (this.#hasUncataloguedCorruptSegment) {
			throw new InvalidFrameError("an uncatalogued corrupt segment prevents an exact recovery-gap query");
		}
		const gaps: IncidentRecorderSegmentRecoveryGap[] = [];
		let selectedBytes = 0;
		let scannedSegments = 0;
		let scannedGaps = 0;
		let scannedIndexBytes = 0;
		let complete = true;
		let frontierSegmentSequence = query.after?.segmentSequence ?? 0;
		let frontierOrdinal = query.after?.ordinal ?? 0;
		const advanceFrontier = (segmentSequence: number, ordinal: number): void => {
			if (
				segmentSequence > frontierSegmentSequence ||
				(segmentSequence === frontierSegmentSequence && ordinal > frontierOrdinal)
			) {
				frontierSegmentSequence = segmentSequence;
				frontierOrdinal = ordinal;
			}
		};
		const frozenOrdinalFor = (segmentSequence: number, availableOrdinal: number): number =>
			segmentSequence === highWaterSegmentSequence ? Math.min(availableOrdinal, highWaterOrdinal) : availableOrdinal;
		const gapIsAfterFrontier = (gap: IncidentRecorderSegmentRecoveryGap): boolean =>
			(gap.segmentSequence > frontierSegmentSequence ||
				(gap.segmentSequence === frontierSegmentSequence && gap.ordinal > frontierOrdinal)) &&
			(gap.segmentSequence < highWaterSegmentSequence ||
				(gap.segmentSequence === highWaterSegmentSequence && gap.ordinal <= highWaterOrdinal));
		const admitGap = (gap: IncidentRecorderSegmentRecoveryGap): boolean => {
			const detached = { ...gap };
			const bytes = encodeJson(detached).byteLength;
			if (gaps.length + 1 > pageMaxGaps || selectedBytes + bytes > pageMaxBytes) {
				if (gaps.length === 0) throw new Error("next recovery gap exceeds the configured page output bounds");
				complete = false;
				return false;
			}
			selectedBytes += bytes;
			gaps.push(detached);
			advanceFrontier(gap.segmentSequence, gap.ordinal);
			return true;
		};

		const firstSummaryIndex = firstSegmentAtOrAfter(this.#readCatalog, frontierSegmentSequence);
		for (let summaryIndex = firstSummaryIndex; summaryIndex < this.#readCatalog.length; summaryIndex += 1) {
			const summary = this.#readCatalog[summaryIndex];
			if (!summary || !complete || summary.header.segmentSequence > highWaterSegmentSequence) break;
			const frozenOrdinal = frozenOrdinalFor(
				summary.header.segmentSequence,
				summary.footer.recordCount + summary.footer.gapCount,
			);
			if (
				summary.header.segmentSequence < frontierSegmentSequence ||
				(summary.header.segmentSequence === frontierSegmentSequence && frozenOrdinal <= frontierOrdinal)
			) {
				continue;
			}
			if (scannedSegments >= pageMaxScannedSegments) {
				complete = false;
				break;
			}
			scannedSegments += 1;
			if (summary.footer.indexFrameBytes > pageMaxScannedIndexBytes) {
				throw new IncidentRecorderSegmentPageBudgetExceededError({
					segmentId: summary.header.segmentId,
					frameKind: "recovery-gap-index",
					requiredBytes: summary.footer.indexFrameBytes,
					configuredBytes: pageMaxScannedIndexBytes,
				});
			}
			if (scannedIndexBytes + summary.footer.indexFrameBytes > pageMaxScannedIndexBytes) {
				complete = false;
				break;
			}
			const index = root ? this.#readIndexWithinRoot(root, summary) : this.#readIndex(summary);
			scannedIndexBytes += summary.footer.indexFrameBytes;
			const firstGapIndex =
				summary.header.segmentSequence === frontierSegmentSequence
					? firstOrdinalAfter(index.recoveryGaps, frontierOrdinal)
					: 0;
			for (let gapIndex = firstGapIndex; gapIndex < index.recoveryGaps.length; gapIndex += 1) {
				const gap = index.recoveryGaps[gapIndex];
				if (!gap || !gapIsAfterFrontier(gap)) continue;
				if (scannedGaps >= pageMaxScannedGaps) {
					complete = false;
					break;
				}
				scannedGaps += 1;
				if (!admitGap(gap)) break;
			}
			if (complete) advanceFrontier(summary.header.segmentSequence, frozenOrdinal);
		}
		if (complete && this.#active) {
			const activeSequence = this.#active.header.segmentSequence;
			const frozenOrdinal = frozenOrdinalFor(activeSequence, this.#active.nextOrdinal - 1);
			const activeRemains =
				activeSequence <= highWaterSegmentSequence &&
				(activeSequence > frontierSegmentSequence ||
					(activeSequence === frontierSegmentSequence && frozenOrdinal > frontierOrdinal));
			if (activeRemains && scannedSegments >= pageMaxScannedSegments) complete = false;
			if (complete && activeRemains) scannedSegments += 1;
			const firstGapIndex =
				activeSequence === frontierSegmentSequence
					? firstOrdinalAfter(this.#active.recoveryGaps, frontierOrdinal)
					: 0;
			for (let gapIndex = firstGapIndex; gapIndex < this.#active.recoveryGaps.length; gapIndex += 1) {
				const gap = this.#active.recoveryGaps[gapIndex];
				if (!gap || !complete || !gapIsAfterFrontier(gap)) continue;
				if (scannedGaps >= pageMaxScannedGaps) {
					complete = false;
					break;
				}
				scannedGaps += 1;
				if (!admitGap(gap)) break;
			}
			if (complete && activeRemains) advanceFrontier(activeSequence, frozenOrdinal);
		}
		return {
			gaps,
			complete,
			selectedBytes,
			scannedSegments,
			scannedGaps,
			scannedIndexBytes,
			snapshot,
			...(complete
				? {}
				: {
						nextCursor: {
							version: 1 as const,
							snapshotId: snapshot.id,
							generation: snapshot.generation,
							highWaterSegmentSequence: snapshot.highWaterSegmentSequence,
							highWaterOrdinal: snapshot.highWaterOrdinal,
							filterSha256: snapshot.filterSha256,
							segmentSequence: frontierSegmentSequence,
							ordinal: frontierOrdinal,
						},
					}),
		};
	}

	getRecoveryGaps(): IncidentRecorderSegmentRecoveryGap[] {
		this.#assertRawRead("getRecoveryGaps");
		return this.#getRecoveryGaps();
	}

	getRecoveryGapsWithinRoot(root: IncidentCasRootMutation): IncidentRecorderSegmentRecoveryGap[] {
		this.#assertRootBacked("getRecoveryGapsWithinRoot");
		return this.#getRecoveryGaps(root);
	}

	#getRecoveryGaps(root?: IncidentCasRootMutation): IncidentRecorderSegmentRecoveryGap[] {
		this.#assertUsable();
		if (this.#corrupt.some((segment) => !segment.summary)) {
			throw new InvalidFrameError("an uncatalogued corrupt segment prevents exact recovery-gap replay");
		}
		const gaps: IncidentRecorderSegmentRecoveryGap[] = [];
		let encodedBytes = 0;
		const admit = (gap: IncidentRecorderSegmentRecoveryGap): void => {
			const bytes = encodeJson(gap).byteLength;
			if (gaps.length + 1 > this.#maxQueryRecords || encodedBytes + bytes > this.#maxQueryBytes) {
				throw new Error("recovery-gap result exceeds the configured query bounds");
			}
			encodedBytes += bytes;
			gaps.push(gap);
		};
		const summaries = [
			...this.#sealed,
			...this.#corrupt.flatMap((segment) => (segment.summary ? [segment.summary] : [])),
		].sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
		for (const summary of summaries) {
			for (const gap of (root ? this.#readIndexWithinRoot(root, summary) : this.#readIndex(summary)).recoveryGaps)
				admit(gap);
		}
		for (const gap of this.#active?.recoveryGaps ?? []) admit(gap);
		return gaps.sort((left, right) => left.segmentSequence - right.segmentSequence || left.ordinal - right.ordinal);
	}

	#openVerifiedSegment(summary: SegmentSummary, index: SegmentIndexDocument): VerifiedSegmentHandle {
		const fresh = this.#readSealedSummary(summary.path);
		if (
			fresh.header.segmentId !== summary.header.segmentId ||
			fresh.header.segmentSequence !== summary.header.segmentSequence ||
			fresh.fileBytes !== summary.fileBytes ||
			fresh.footer.indexSha256 !== summary.footer.indexSha256 ||
			fresh.footer.contentSha256 !== summary.footer.contentSha256
		) {
			throw new InvalidFrameError("sealed segment changed after cataloging");
		}
		const fileDescriptor = openSync(summary.path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const outcome = captureIncidentRecorderOutcome(() => {
			assertPrivateRegularFile(fileDescriptor, summary.path);
			if (hashFileRange(fileDescriptor, 0, summary.footer.contentBytes) !== summary.footer.contentSha256) {
				throw new InvalidFrameError("sealed segment content checksum mismatch");
			}
			const positions: Array<
				| { kind: "record"; ordinal: number; offset: number; entry: SegmentIndexEntry }
				| { kind: "gap"; ordinal: number; offset: number; gap: IncidentRecorderSegmentRecoveryGap }
			> = [
				...index.records.map((entry) => ({
					kind: "record" as const,
					ordinal: entry.ordinal,
					offset: entry.offset,
					entry,
				})),
				...index.recoveryGaps.map((gap) => ({
					kind: "gap" as const,
					ordinal: gap.ordinal,
					offset: gap.invalidOffset,
					gap,
				})),
			].sort((left, right) => left.ordinal - right.ordinal);
			const headerFrame = parseFrameAt(fileDescriptor, 0, summary.fileBytes);
			let expectedOffset = headerFrame.frameBytes;
			for (const position of positions) {
				if (position.offset !== expectedOffset)
					throw new InvalidFrameError("sealed record/gap offsets are not contiguous");
				const frame = parseFrameAt(fileDescriptor, position.offset, summary.fileBytes);
				if (frame.ordinal !== position.ordinal)
					throw new InvalidFrameError("sealed frame ordinal differs from index");
				if (position.kind === "record") {
					const actual = indexEntryFromFrame(summary.header, frame, position.offset);
					if (JSON.stringify(actual) !== JSON.stringify(position.entry)) {
						throw new InvalidFrameError("sealed record differs from its index");
					}
				} else {
					const actual = parseRecoveryGap(frame);
					if (JSON.stringify(actual) !== JSON.stringify(position.gap)) {
						throw new InvalidFrameError("sealed recovery gap differs from its index");
					}
				}
				expectedOffset += frame.frameBytes;
			}
			if (expectedOffset !== summary.footer.indexOffset) {
				throw new InvalidFrameError("sealed content does not terminate at its index");
			}
			const identity = verifiedSegmentIdentity(fileDescriptor, summary.fileBytes);
			return { fileDescriptor, identity };
		});
		if (outcome.ok) return outcome.value;
		return settleIncidentRecorderOutcome(
			outcome,
			runCleanupActionsAttemptAll([
				() => {
					closeSync(fileDescriptor);
					this.#faultInjector?.("after-prune-verifier-failure-handle-close");
				},
			]),
		);
	}

	#markCorrupt(summary: SegmentSummary, error: unknown): void {
		this.#sealed = this.#sealed.filter((candidate) => candidate.header.segmentId !== summary.header.segmentId);
		if (!this.#corrupt.some((candidate) => candidate.segmentId === summary.header.segmentId)) {
			this.#corrupt.push({
				segmentId: summary.header.segmentId,
				path: summary.path,
				reason: errorText(error),
				summary,
			});
		}
		this.#refreshReadCatalog();
		this.#stateRevision += 1;
	}

	pruneSealedSegments(input: IncidentRecorderSegmentPruneInput): IncidentRecorderSegmentPruneResult {
		this.#assertRawMutation("pruneSealedSegments");
		this.#assertUsable();
		const pruneNow = this.#now();
		assertSafeNonNegativeInteger(pruneNow, "prune continuation registry time");
		this.#sweepExpiredReadLeases(pruneNow);
		assertSafeNonNegativeInteger(input.sealedBeforeMs, "sealedBeforeMs");
		const maxSegments = positiveInteger(input.maxSegments, DEFAULT_MAX_PRUNE_SEGMENTS, "maxSegments", 1024);
		const maxDeletes = positiveInteger(input.maxDeletes, maxSegments, "maxDeletes", maxSegments);
		const maxBytes = positiveInteger(input.maxBytes, DEFAULT_MAX_PRUNE_BYTES, "maxBytes", 256 * MEBIBYTE);
		const protection = validatedPruneProtection(input.protection);
		const protectedRunIds = protection.protectedRunIdSet;
		const protectedSegments = snapshotProtectedSegmentIds(input.protectedSegmentIds);
		const protectedSegmentIds = protectedSegments.set;
		const pruneFilterSha256 = sha256(
			Buffer.from(
				canonicalJson({
					sealedBeforeMs: input.sealedBeforeMs,
					protectionGeneration: protection.generation,
					protectionFingerprint: protection.fingerprint,
					protectedRunIds: [...protection.protectedRunIds],
					protectedSegmentIds: [...protectedSegments.sorted],
				}),
				"utf8",
			),
		);
		const continuation = input.continuation;
		let sessionCapability: PruneCursorCapability | undefined;
		if (continuation) {
			sessionCapability = assertPruneCursorCapability(
				this.#pruneCursorCapabilities,
				continuation,
				this.#instanceId,
				pruneFilterSha256,
				this.#instanceId,
				pruneNow,
			);
			sweepExpiredPruneCursorCapabilities(this.#pruneCursorCapabilities, pruneNow, sessionCapability);
		} else {
			sweepExpiredPruneCursorCapabilities(this.#pruneCursorCapabilities, pruneNow);
		}
		const availableHighWater = this.#sealed.reduce(
			(highWater, summary) => Math.max(highWater, summary.header.segmentSequence),
			0,
		);
		const pruneSession = {
			sessionId: continuation?.sessionId ?? randomUUID(),
			storeInstanceId: this.#instanceId,
			highWaterSegmentSequence: continuation?.highWaterSegmentSequence ?? availableHighWater,
			filterSha256: pruneFilterSha256,
		};
		const sessionReservation = continuation ?? frozenPruneCursor({ ...pruneSession, segmentSequence: 0 });
		if (!continuation) {
			sessionCapability = registerPruneCursorCapability(
				this.#pruneCursorCapabilities,
				sessionReservation,
				this.#instanceId,
				this.#now(),
				undefined,
				undefined,
				this.#onPruneExpiryCleanupDiagnostic,
			);
		}
		if (!sessionCapability) throw new Error("live prune session capability was not registered");
		let ownedSessionCapability = sessionCapability;
		const continuationFor = (segmentSequence: number): IncidentRecorderSegmentPruneCursor =>
			frozenPruneCursor({ ...pruneSession, segmentSequence });
		const result: IncidentRecorderSegmentPruneResult = {
			deletedSegmentIds: [],
			corruptSegmentIds: [],
			examinedSegments: 0,
			deletedBytes: 0,
			blockedByReadSnapshot: false,
			locatorsInvalidated: false,
			requiresFullReconciliation: false,
			moreWork: false,
		};
		const leasedHighWaterSegmentSequence = Array.from(this.#readLeases.values()).reduce(
			(highWater, lease) => Math.max(highWater, lease.highWaterSegmentSequence),
			-1,
		);
		let examinedBytes = 0;
		const sequenceAnchorId =
			this.#active || this.#sealed.length === 0
				? undefined
				: this.#sealed.reduce((latest, summary) =>
						summary.header.segmentSequence > latest.header.segmentSequence ? summary : latest,
					).header.segmentId;
		const candidates = [...this.#sealed]
			.sort((left, right) => left.header.segmentSequence - right.header.segmentSequence)
			.filter(
				(summary) =>
					summary.footer.sealedAtMs < input.sealedBeforeMs &&
					summary.header.segmentSequence <= pruneSession.highWaterSegmentSequence &&
					(!continuation || summary.header.segmentSequence > continuation.segmentSequence),
			);
		try {
			for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
				const summary = candidates[candidateIndex];
				if (!summary) continue;
				if (result.examinedSegments >= maxSegments) {
					result.moreWork = true;
					break;
				}
				if (summary.header.segmentSequence <= leasedHighWaterSegmentSequence) {
					result.blockedByReadSnapshot = true;
					result.examinedSegments += 1;
					result.moreWork = true;
					result.continuation = continuation;
					break;
				}
				if (protectedSegmentIds.has(summary.header.segmentId) || summary.header.segmentId === sequenceAnchorId) {
					result.examinedSegments += 1;
					result.continuation = continuationFor(summary.header.segmentSequence);
					continue;
				}
				if (result.deletedSegmentIds.length >= maxDeletes) {
					result.moreWork = true;
					break;
				}
				if (examinedBytes + summary.fileBytes > maxBytes) {
					result.moreWork = true;
					result.requiredBytes = summary.fileBytes;
					result.continuation = continuation;
					break;
				}
				result.examinedSegments += 1;
				examinedBytes += summary.fileBytes;
				result.continuation = continuationFor(summary.header.segmentSequence);
				let index: SegmentIndexDocument;
				let verifiedHandle: VerifiedSegmentHandle;
				try {
					index = this.#readIndex(summary, false);
					verifiedHandle = this.#openVerifiedSegment(summary, index);
				} catch (error) {
					if (
						indexObserverErrorIn(error) ||
						error instanceof IncidentRecorderDescriptorCleanupError ||
						errnoCode(error) !== undefined
					) {
						throw error;
					}
					this.#markCorrupt(summary, error);
					result.corruptSegmentIds.push(summary.header.segmentId);
					continue;
				}
				if (index.records.some((entry) => protectedRunIds.has(entry.runId))) {
					closeDescriptorsAttemptAll([verifiedHandle.fileDescriptor], undefined, (descriptor) => {
						closeSync(descriptor);
						this.#faultInjector?.("after-prune-protected-handle-close");
					});
					continue;
				}
				let sealedDescriptor = -1;
				let procFdAuthority: AuthenticatedProcFdRoute | undefined;
				const operationOutcome = captureIncidentRecorderOutcome(() => {
					if (dirname(summary.path) !== this.#sealedDirectory) {
						throw new InvalidFrameError("sealed prune target escaped its cataloged directory");
					}
					sealedDescriptor = openSync(
						this.#sealedDirectory,
						constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
					);
					const sealedIdentity = directoryIdentity(sealedDescriptor, "sealed segment directory");
					procFdAuthority = openAuthenticatedProcFdRoute();
					this.#faultInjector?.("before-prune-unlink-after-verify");
					assertDirectoryPathIdentity(this.#sealedDirectory, sealedIdentity, "sealed segment directory");
					const pruneParentBefore = fileAllocation(sealedDescriptor);
					let previousAllocation: StorageState = verifiedHandle.identity;
					let unlinkMutationError: IncidentRecorderSegmentUnlinkMutationError | undefined;
					let unlinkFailure: unknown;
					try {
						previousAllocation = unlinkVerifiedSegmentAtPath(
							procFdAuthority,
							sealedDescriptor,
							this.#sealedDirectory,
							basename(summary.path),
							verifiedHandle,
							() => this.#faultInjector?.("after-prune-unlink-before-directory-fsync"),
						);
					} catch (error) {
						unlinkMutationError = unlinkMutationErrorIn(error);
						if (!unlinkMutationError) throw error;
						unlinkFailure = error;
						previousAllocation = unlinkMutationError.previousAllocation;
					}
					result.deletedSegmentIds.push(summary.header.segmentId);
					result.deletedBytes += summary.fileBytes;
					result.locatorsInvalidated = true;
					const postCommitErrors: unknown[] = unlinkMutationError ? [unlinkFailure] : [];
					try {
						this.#sealed = this.#sealed.filter(
							(candidate) => candidate.header.segmentId !== summary.header.segmentId,
						);
						this.#refreshReadCatalog();
						this.#generation += 1;
						this.#stateRevision += 1;
						if (!unlinkMutationError) {
							this.#emitDurable({
								kind: "pruned",
								segmentId: summary.header.segmentId,
								path: summary.path,
								entryChange: "removed",
								entryDelta: -1,
								inodeDelta: previousAllocation.linkCount === 1 ? -1 : 0,
								deviceId: previousAllocation.deviceId,
								inodeId: previousAllocation.inodeId,
								linkCount: Math.max(0, previousAllocation.linkCount - 1),
								previousLogicalBytes: previousAllocation.logicalBytes,
								previousAllocatedBytes: previousAllocation.allocatedBytes,
								logicalBytes: previousAllocation.linkCount === 1 ? 0 : previousAllocation.logicalBytes,
								allocatedBytes: previousAllocation.linkCount === 1 ? 0 : previousAllocation.allocatedBytes,
								parentEffects: [
									parentDirectoryEffect(
										this.#sealedDirectory,
										pruneParentBefore,
										fileAllocation(sealedDescriptor),
									),
								],
							});
						}
					} catch (error) {
						postCommitErrors.push(error);
					}
					if (postCommitErrors.length > 0) {
						throw new IncidentRecorderSegmentPruneMutationError({
							cause: combinePrimaryAndCleanupErrors(postCommitErrors[0], postCommitErrors.slice(1)),
							result: pruneMutationResultSnapshot(result),
							directoryDurability: unlinkMutationError?.directoryDurability ?? "confirmed",
						});
					}
				});
				settleIncidentRecorderOutcome(
					operationOutcome,
					runCleanupActionsAttemptAll([
						() => {
							if (procFdAuthority) closeAuthenticatedProcFdRoute(procFdAuthority);
						},
						() => {
							if (sealedDescriptor >= 0) closeSync(sealedDescriptor);
						},
						() => closeSync(verifiedHandle.fileDescriptor),
					]),
				);
			}
			if (!result.moreWork) {
				delete result.continuation;
				removePruneCursorCapability(
					this.#pruneCursorCapabilities,
					pruneCursorCapabilityKey(sessionReservation),
					ownedSessionCapability.cursor,
				);
			} else if (result.continuation && result.continuation !== sessionReservation) {
				ownedSessionCapability = registerPruneCursorCapability(
					this.#pruneCursorCapabilities,
					result.continuation,
					this.#instanceId,
					this.#now(),
					undefined,
					ownedSessionCapability,
					this.#onPruneExpiryCleanupDiagnostic,
				);
			} else if (!continuation) {
				removePruneCursorCapability(
					this.#pruneCursorCapabilities,
					pruneCursorCapabilityKey(sessionReservation),
					sessionReservation,
				);
			}
			return result;
		} catch (error) {
			let surfacedError = classifyPruneFailure(error, result);
			const cursorCleanupErrors = runCleanupActionsAttemptAll([
				() => {
					removePruneCursorCapability(
						this.#pruneCursorCapabilities,
						pruneCursorCapabilityKey(sessionReservation),
						ownedSessionCapability.cursor,
					);
				},
			]);
			surfacedError = attachCleanupToPruneFailure(surfacedError, cursorCleanupErrors);
			return this.#poison(surfacedError);
		}
	}

	getStats(): IncidentRecorderSegmentStoreStats {
		this.#assertUsable();
		const summarizedCorrupt = this.#corrupt.flatMap((segment) => (segment.summary ? [segment.summary] : []));
		return {
			activeSegments: this.#active ? 1 : 0,
			sealedSegments: this.#sealed.length + this.#corrupt.length,
			corruptSegments: this.#corrupt.length,
			records:
				(this.#active?.records.length ?? 0) +
				this.#sealed.reduce((total, summary) => total + summary.footer.recordCount, 0) +
				summarizedCorrupt.reduce((total, summary) => total + summary.footer.recordCount, 0),
			recoveryGaps:
				(this.#active?.recoveryGaps.length ?? 0) +
				this.#sealed.reduce((total, summary) => total + summary.footer.gapCount, 0) +
				summarizedCorrupt.reduce((total, summary) => total + summary.footer.gapCount, 0),
		};
	}

	close(): void {
		this.#assertRawMutation("close");
		if (this.#closed) return;
		const closeErrors: unknown[] = [];
		const recordCloseFailure = (error: unknown): void => {
			closeErrors.push(error);
		};
		if (this.#active) {
			const syncOutcome = captureIncidentRecorderOutcome(() =>
				this.#withActiveSegmentFile("read_write", (file) => file.sync()),
			);
			try {
				settleIncidentRecorderOutcome(syncOutcome, this.#closeActiveDescriptor());
			} catch (error) {
				recordCloseFailure(error);
			}
		}
		let closeParentBefore: StorageState | undefined;
		if (this.#onOpenStorageResult) {
			const accountingOutcome = captureIncidentRecorderOutcome(() => {
				this.#faultInjector?.("before-close-root-accounting");
				return pathStorageState(this.#directory, true);
			});
			if (accountingOutcome.ok) closeParentBefore = accountingOutcome.value;
			else recordCloseFailure(accountingOutcome.failure.error);
		}
		try {
			this.#releaseOwnership();
		} catch (error) {
			recordCloseFailure(error);
		}
		this.#closed = true;
		this.#appendPlans.clear();
		this.#readLeases.clear();
		const cursorCleanupErrors = runCleanupActionsAttemptAll(
			Array.from(
				this.#pruneCursorCapabilities.keys(),
				(key) => () => removePruneCursorCapability(this.#pruneCursorCapabilities, key),
			),
		);
		for (const error of cursorCleanupErrors) {
			recordCloseFailure(error);
		}
		try {
			if (this.#onOpenStorageResult) {
				const closeError =
					closeErrors.length === 0
						? undefined
						: combinePrimaryAndCleanupErrors(closeErrors[0], closeErrors.slice(1));
				this.#onOpenStorageResult({
					phase: "closed",
					complete: closeErrors.length === 0,
					reconciliation: closeErrors.length === 0 ? "incremental-complete" : "full-dev-inode-required",
					entries: captureOpenStorageEntries(this.#directory, {
						root: false,
						active: false,
						sealed: false,
						owner: false,
					}),
					parentEffects: closeParentBefore
						? [parentDirectoryEffect(this.#directory, closeParentBefore, pathStorageState(this.#directory, true))]
						: [],
					...(closeErrors.length === 0 ? {} : { error: errorText(closeError) }),
				});
			}
		} catch (error) {
			recordCloseFailure(error);
		}
		if (closeErrors.length > 0) {
			if (this.#poisoned) {
				this.#poisoned = new IncidentRecorderSegmentStorePoisonedError(
					attachCleanupToPruneFailure(this.#poisoned.cause, closeErrors),
				);
			} else {
				this.#poisoned = new IncidentRecorderSegmentStorePoisonedError(
					combinePrimaryAndCleanupErrors(closeErrors[0], closeErrors.slice(1)),
				);
			}
			throw this.#poisoned;
		}
	}
}

function readRecoverySealedSummary(path: string): SegmentSummary {
	const fileDescriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
	const outcome = captureIncidentRecorderOutcome(() => {
		assertPrivateRegularFile(fileDescriptor, path);
		const fileBytes = fstatSync(fileDescriptor).size;
		if (
			fileBytes < FRAME_OVERHEAD_BYTES * 3 ||
			fileBytes > FORMAT_MAX_ACTIVE_BYTES + FORMAT_MAX_INDEX_FRAME_BYTES + FORMAT_MAX_FOOTER_FRAME_BYTES
		) {
			throw new InvalidFrameError("sealed segment size exceeds the fixed format maximum");
		}
		const headerFrame = parseFrameAt(fileDescriptor, 0, fileBytes);
		const header = parseHeader(headerFrame);
		const trailer = Buffer.alloc(FRAME_TRAILER_BYTES);
		readFully(fileDescriptor, trailer, fileBytes - FRAME_TRAILER_BYTES);
		if (!trailer.subarray(4).equals(FRAME_END_MAGIC)) throw new InvalidFrameError("sealed footer trailer is missing");
		const footerFrameBytes = trailer.readUInt32LE(0);
		if (footerFrameBytes < FRAME_OVERHEAD_BYTES || footerFrameBytes > FORMAT_MAX_FOOTER_FRAME_BYTES) {
			throw new InvalidFrameError("sealed footer length exceeds the fixed format maximum");
		}
		const footerOffset = fileBytes - footerFrameBytes;
		const footerFrame = parseFrameAt(fileDescriptor, footerOffset, fileBytes);
		const footer = parseFooter(footerFrame);
		if (
			footer.segmentId !== header.segmentId ||
			footer.segmentSequence !== header.segmentSequence ||
			footer.createdAtMs !== header.createdAtMs ||
			footer.indexOffset < headerFrame.frameBytes ||
			footer.contentBytes !== footer.indexOffset + footer.indexFrameBytes ||
			footer.contentBytes + footerFrame.frameBytes !== fileBytes ||
			footerFrame.ordinal !== footer.recordCount + footer.gapCount + 2 ||
			basename(path) !== header.segmentId + ".segment"
		) {
			throw new InvalidFrameError("sealed footer identity or bounds are invalid");
		}
		return { header, footer, path, fileBytes };
	});
	return settleIncidentRecorderOutcome(outcome, runCleanupActionsAttemptAll([() => closeSync(fileDescriptor)]));
}

function readRecoveryOwnerClaim(directory: string, afterClose?: () => void): OwnerClaim | undefined {
	const ownerPath = join(directory, OWNER_FILE_NAME);
	if (!pathStatus(ownerPath)) return undefined;
	const fileDescriptor = openSync(ownerPath, constants.O_RDONLY | constants.O_NOFOLLOW);
	const outcome = captureIncidentRecorderOutcome(() => {
		assertPrivateRegularFile(fileDescriptor, ownerPath);
		const status = fstatSync(fileDescriptor);
		if (status.size <= 0 || status.size > 4096) throw new Error("writer ownership claim is malformed");
		const content = Buffer.alloc(status.size);
		readFully(fileDescriptor, content, 0);
		return parseOwnerClaim(parseJson(content, "writer ownership claim"));
	});
	return settleIncidentRecorderOutcome(
		outcome,
		runCleanupActionsAttemptAll([
			() => {
				closeSync(fileDescriptor);
				afterClose?.();
			},
		]),
	);
}

function recoveryOwnerSnapshot(
	directory: string,
	isOwnerAlive: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean,
	maxEntries: number,
	maxCatalogBytes: number,
	afterRootClose?: () => void,
	afterOwnerClaimClose?: () => void,
): { snapshot: string; entries: number; catalogBytes: number } {
	const root = opendirSync(directory);
	let entries = 0;
	let catalogBytes = 0;
	const scanOutcome = captureIncidentRecorderOutcome(() => {
		for (;;) {
			const entry = root.readSync();
			if (!entry) break;
			entries += 1;
			catalogBytes += Buffer.byteLength(entry.name, "utf8") + 256;
			if (entries > maxEntries) throw new Error("recovery root exceeds maxStartupEntries");
			if (catalogBytes > maxCatalogBytes) throw new Error("recovery root exceeds maxStartupCatalogBytes");
			if (/^\.writer-owner-[A-Za-z0-9_-]+\.tmp$/.test(entry.name)) {
				throw new Error("writer ownership transition is in progress");
			}
		}
	});
	settleIncidentRecorderOutcome(
		scanOutcome,
		runCleanupActionsAttemptAll([
			() => {
				root.closeSync();
				afterRootClose?.();
			},
		]),
	);
	const claim = readRecoveryOwnerClaim(directory, afterOwnerClaimClose);
	if (!claim) return { snapshot: "absent", entries, catalogBytes };
	if (isOwnerAlive(claim)) throw new Error("incident recorder segment store is already owned by a live writer");
	return { snapshot: JSON.stringify(claim), entries, catalogBytes };
}

function recoveryOwnerFingerprint(
	directory: string,
	isOwnerAlive: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean,
	afterOwnerClaimClose?: () => void,
): string {
	const claim = readRecoveryOwnerClaim(directory, afterOwnerClaimClose);
	if (!claim) return "absent";
	if (isOwnerAlive(claim)) throw new Error("incident recorder segment store is already owned by a live writer");
	return JSON.stringify(claim);
}

function openAndVerifyRecoverySegment(
	summary: SegmentSummary,
	afterFailureClose?: () => void,
): VerifiedSegmentHandle & { index: SegmentIndexDocument } {
	const fileDescriptor = openSync(summary.path, constants.O_RDONLY | constants.O_NOFOLLOW);
	const outcome = captureIncidentRecorderOutcome(() => {
		assertPrivateRegularFile(fileDescriptor, summary.path);
		const status = fstatSync(fileDescriptor);
		if (status.size !== summary.fileBytes)
			throw new InvalidFrameError("sealed segment size changed during recovery prune");
		const indexFrame = parseFrameAt(fileDescriptor, summary.footer.indexOffset, status.size);
		const index = parseIndexDocument(indexFrame);
		if (
			index.segmentId !== summary.header.segmentId ||
			index.segmentSequence !== summary.header.segmentSequence ||
			index.records.length !== summary.footer.recordCount ||
			index.recoveryGaps.length !== summary.footer.gapCount ||
			indexFrame.frameBytes !== summary.footer.indexFrameBytes ||
			indexFrame.ordinal !== summary.footer.recordCount + summary.footer.gapCount + 1 ||
			sha256(indexFrame.bytes) !== summary.footer.indexSha256 ||
			hashFileRange(fileDescriptor, 0, summary.footer.contentBytes) !== summary.footer.contentSha256
		) {
			throw new InvalidFrameError("sealed segment index or content checksum is invalid");
		}
		const positions: Array<
			| { kind: "record"; ordinal: number; offset: number; entry: SegmentIndexEntry }
			| { kind: "gap"; ordinal: number; offset: number; gap: IncidentRecorderSegmentRecoveryGap }
		> = [
			...index.records.map((entry) => ({
				kind: "record" as const,
				ordinal: entry.ordinal,
				offset: entry.offset,
				entry,
			})),
			...index.recoveryGaps.map((gap) => ({
				kind: "gap" as const,
				ordinal: gap.ordinal,
				offset: gap.invalidOffset,
				gap,
			})),
		].sort((left, right) => left.ordinal - right.ordinal);
		const headerFrame = parseFrameAt(fileDescriptor, 0, status.size);
		let expectedOffset = headerFrame.frameBytes;
		for (let positionIndex = 0; positionIndex < positions.length; positionIndex += 1) {
			const position = positions[positionIndex];
			if (!position || position.ordinal !== positionIndex + 1 || position.offset !== expectedOffset) {
				throw new InvalidFrameError("sealed segment index ordering or offsets are invalid");
			}
			const frame = parseFrameAt(fileDescriptor, position.offset, status.size);
			if (frame.ordinal !== position.ordinal) throw new InvalidFrameError("sealed frame ordinal differs from index");
			if (position.kind === "record") {
				const actual = indexEntryFromFrame(summary.header, frame, position.offset);
				if (JSON.stringify(actual) !== JSON.stringify(position.entry)) {
					throw new InvalidFrameError("sealed record differs from its index");
				}
			} else {
				const actual = parseRecoveryGap(frame);
				if (JSON.stringify(actual) !== JSON.stringify(position.gap)) {
					throw new InvalidFrameError("sealed recovery gap differs from its index");
				}
			}
			expectedOffset += frame.frameBytes;
		}
		if (expectedOffset !== summary.footer.indexOffset) {
			throw new InvalidFrameError("sealed segment content does not end at its index");
		}
		const identity = verifiedSegmentIdentity(fileDescriptor, summary.fileBytes);
		return { fileDescriptor, identity, index };
	});
	if (outcome.ok) return outcome.value;
	return settleIncidentRecorderOutcome(
		outcome,
		runCleanupActionsAttemptAll([
			() => {
				closeSync(fileDescriptor);
				afterFailureClose?.();
			},
		]),
	);
}

// This recovery seam never creates a filesystem entry. Its owner checks detect
// transitions but cannot replace external service-start exclusion on Node 22.
export function pruneIncidentRecorderSealedHistoryForRecovery(
	options: IncidentRecorderSegmentRecoveryPruneOptions,
): IncidentRecorderSegmentPruneResult {
	if (!options.directory) throw new Error("directory is required");
	if (options.externalWriterExcluded !== true) {
		throw new Error("recovery pruning requires explicit external writer exclusion");
	}
	assertSafeNonNegativeInteger(options.sealedBeforeMs, "sealedBeforeMs");
	const maxSegments = positiveInteger(options.maxSegments, DEFAULT_MAX_PRUNE_SEGMENTS, "maxSegments", 1024);
	const maxDeletes = positiveInteger(options.maxDeletes, maxSegments, "maxDeletes", maxSegments);
	const maxBytes = positiveInteger(options.maxBytes, DEFAULT_MAX_PRUNE_BYTES, "maxBytes", 256 * MEBIBYTE);
	const maxEntries = positiveInteger(
		options.maxStartupEntries,
		DEFAULT_MAX_STARTUP_ENTRIES,
		"maxStartupEntries",
		65_536,
	);
	const maxCatalogBytes = positiveInteger(
		options.maxStartupCatalogBytes,
		DEFAULT_MAX_STARTUP_CATALOG_BYTES,
		"maxStartupCatalogBytes",
		64 * MEBIBYTE,
	);
	const protection = validatedPruneProtection(options.protection);
	const protectedRunIds = protection.protectedRunIdSet;
	const protectedSegments = snapshotProtectedSegmentIds(options.protectedSegmentIds);
	const protectedSegmentIds = protectedSegments.set;
	const continuation = options.continuation;
	let recoveryPruneCleanupCursor = continuation;
	let recoveryPruneOwnedCapability: PruneCursorCapability | undefined;
	try {
		const storageScope = captureRecoveryPruneStorageScope(options.directory);
		const sealedDirectory = storageScope.sealedDirectory;
		const recoveryStoreInstanceId =
			"recovery:" +
			sha256(
				Buffer.from(
					canonicalJson({ directory: options.directory, storageFingerprint: storageScope.fingerprint }),
					"utf8",
				),
			);
		const pruneFilterSha256 = sha256(
			Buffer.from(
				canonicalJson({
					sealedBeforeMs: options.sealedBeforeMs,
					protectionGeneration: protection.generation,
					protectionFingerprint: protection.fingerprint,
					protectedRunIds: [...protection.protectedRunIds],
					protectedSegmentIds: [...protectedSegments.sorted],
				}),
				"utf8",
			),
		);
		const pruneNow = Date.now();
		let admittedContinuationCapability: PruneCursorCapability | undefined;
		if (continuation) {
			admittedContinuationCapability = assertPruneCursorCapability(
				RECOVERY_PRUNE_CURSOR_CAPABILITIES,
				continuation,
				recoveryStoreInstanceId,
				pruneFilterSha256,
				storageScope.fingerprint,
				pruneNow,
			);
			recoveryPruneOwnedCapability = admittedContinuationCapability;
			sweepExpiredPruneCursorCapabilities(
				RECOVERY_PRUNE_CURSOR_CAPABILITIES,
				pruneNow,
				admittedContinuationCapability,
			);
		} else {
			sweepExpiredPruneCursorCapabilities(RECOVERY_PRUNE_CURSOR_CAPABILITIES, pruneNow);
		}
		const isOwnerAlive = options.isOwnerAlive ?? defaultIsOwnerAlive;
		const ownerScan = recoveryOwnerSnapshot(
			options.directory,
			isOwnerAlive,
			maxEntries,
			maxCatalogBytes,
			() => options.faultInjector?.("after-recovery-root-directory-close"),
			() => options.faultInjector?.("after-recovery-owner-claim-handle-close"),
		);
		const ownerSnapshot = ownerScan.snapshot;
		const summaries: SegmentSummary[] = [];
		const result: IncidentRecorderSegmentPruneResult = {
			deletedSegmentIds: [],
			corruptSegmentIds: [],
			examinedSegments: 0,
			deletedBytes: 0,
			blockedByReadSnapshot: false,
			locatorsInvalidated: false,
			requiresFullReconciliation: false,
			moreWork: false,
		};
		let entries = ownerScan.entries;
		let catalogBytes = ownerScan.catalogBytes;
		const directory = opendirSync(sealedDirectory);
		const catalogOutcome = captureIncidentRecorderOutcome(() => {
			for (;;) {
				const entry = directory.readSync();
				if (!entry) break;
				entries += 1;
				catalogBytes += Buffer.byteLength(entry.name, "utf8") + 256;
				if (entries > maxEntries) throw new Error("segment directory exceeds maxStartupEntries");
				if (catalogBytes > maxCatalogBytes) throw new Error("segment catalog exceeds maxStartupCatalogBytes");
				if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.segment$/.test(entry.name)) continue;
				const path = join(sealedDirectory, entry.name);
				let summary: SegmentSummary;
				try {
					summary = readRecoverySealedSummary(path);
				} catch (error) {
					if (error instanceof IncidentRecorderDescriptorCleanupError || errnoCode(error) !== undefined)
						throw error;
					result.corruptSegmentIds.push(entry.name.slice(0, -".segment".length));
					continue;
				}
				catalogBytes +=
					Buffer.byteLength(path, "utf8") +
					encodeJson(summary.header).byteLength +
					encodeJson(summary.footer).byteLength +
					384;
				if (catalogBytes > maxCatalogBytes) {
					throw new SegmentCatalogBudgetExceededError("segment catalog exceeds maxStartupCatalogBytes");
				}
				summaries.push(summary);
			}
		});
		settleIncidentRecorderOutcome(
			catalogOutcome,
			runCleanupActionsAttemptAll([
				() => {
					directory.closeSync();
					options.faultInjector?.("after-recovery-catalog-directory-close");
				},
			]),
		);
		summaries.sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
		for (let summaryIndex = 1; summaryIndex < summaries.length; summaryIndex += 1) {
			const previous = summaries[summaryIndex - 1];
			const current = summaries[summaryIndex];
			if (previous && current && previous.header.segmentSequence === current.header.segmentSequence) {
				throw new InvalidFrameError(
					`duplicate sealed segment sequence ${String(current.header.segmentSequence)} prevents recovery pruning`,
				);
			}
		}
		const sequenceAnchorId =
			summaries.length === 0
				? undefined
				: summaries.reduce((latest, summary) =>
						summary.header.segmentSequence > latest.header.segmentSequence ? summary : latest,
					).header.segmentId;
		const availableHighWater = summaries.reduce(
			(highWater, summary) => Math.max(highWater, summary.header.segmentSequence),
			0,
		);
		const pruneSession = {
			sessionId: continuation?.sessionId ?? randomUUID(),
			storeInstanceId: recoveryStoreInstanceId,
			highWaterSegmentSequence: continuation?.highWaterSegmentSequence ?? availableHighWater,
			filterSha256: pruneFilterSha256,
		};
		const sessionReservation = continuation ?? frozenPruneCursor({ ...pruneSession, segmentSequence: 0 });
		recoveryPruneCleanupCursor = sessionReservation;
		let sessionCapability: PruneCursorCapability;
		if (continuation) {
			if (!admittedContinuationCapability) {
				throw new Error("recovery prune continuation lost its admitted capability");
			}
			sessionCapability = admittedContinuationCapability;
			if (!sessionCapability.scopeLease) {
				throw new Error("recovery prune continuation lost its storage scope lease");
			}
			assertRecoveryPruneStorageScopeLease(
				sessionCapability.scopeLease,
				options.directory,
				storageScope.fingerprint,
			);
		} else {
			const scopeLease = openRecoveryPruneStorageScope(options.directory);
			try {
				assertRecoveryPruneStorageScopeLease(scopeLease, options.directory, storageScope.fingerprint);
				sessionCapability = registerPruneCursorCapability(
					RECOVERY_PRUNE_CURSOR_CAPABILITIES,
					sessionReservation,
					storageScope.fingerprint,
					Date.now(),
					scopeLease,
					undefined,
					options.onPruneExpiryCleanupDiagnostic,
				);
				recoveryPruneOwnedCapability = sessionCapability;
			} catch (error) {
				return runCleanupPreservingFailure(error, () => closeRecoveryPruneStorageScope(scopeLease));
			}
		}
		const sessionScopeLease = sessionCapability.scopeLease;
		if (!sessionScopeLease) throw new Error("recovery prune session has no storage scope lease");
		const continuationFor = (segmentSequence: number): IncidentRecorderSegmentPruneCursor =>
			frozenPruneCursor({ ...pruneSession, segmentSequence });
		const candidates = summaries.filter(
			(summary) =>
				summary.footer.sealedAtMs < options.sealedBeforeMs &&
				summary.header.segmentSequence <= pruneSession.highWaterSegmentSequence &&
				(!continuation || summary.header.segmentSequence > continuation.segmentSequence),
		);
		let examinedBytes = 0;
		try {
			for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
				const summary = candidates[candidateIndex];
				if (!summary) continue;
				if (result.examinedSegments >= maxSegments) {
					result.moreWork = true;
					break;
				}
				if (protectedSegmentIds.has(summary.header.segmentId) || summary.header.segmentId === sequenceAnchorId) {
					result.examinedSegments += 1;
					result.continuation = continuationFor(summary.header.segmentSequence);
					continue;
				}
				if (result.deletedSegmentIds.length >= maxDeletes) {
					result.moreWork = true;
					break;
				}
				if (examinedBytes + summary.fileBytes > maxBytes) {
					result.moreWork = true;
					result.requiredBytes = summary.fileBytes;
					result.continuation = continuation;
					break;
				}
				result.examinedSegments += 1;
				examinedBytes += summary.fileBytes;
				result.continuation = continuationFor(summary.header.segmentSequence);
				let verifiedHandle: VerifiedSegmentHandle & { index: SegmentIndexDocument };
				try {
					verifiedHandle = openAndVerifyRecoverySegment(summary, () =>
						options.faultInjector?.("after-prune-verifier-failure-handle-close"),
					);
				} catch (error) {
					if (error instanceof IncidentRecorderDescriptorCleanupError || errnoCode(error) !== undefined)
						throw error;
					result.corruptSegmentIds.push(summary.header.segmentId);
					continue;
				}
				if (verifiedHandle.index.records.some((entry) => protectedRunIds.has(entry.runId))) {
					closeDescriptorsAttemptAll([verifiedHandle.fileDescriptor]);
					continue;
				}
				const candidateOutcome = captureIncidentRecorderOutcome(() => {
					options.onOwnershipTransitionCheck?.();
					if (
						recoveryOwnerFingerprint(options.directory, isOwnerAlive, () =>
							options.faultInjector?.("after-recovery-owner-claim-handle-close"),
						) !== ownerSnapshot
					) {
						throw new Error("writer ownership changed during recovery pruning");
					}
					assertRecoveryPruneStorageScopeLease(sessionScopeLease, options.directory, storageScope.fingerprint);
					if (dirname(summary.path) !== sealedDirectory) {
						throw new InvalidFrameError("sealed recovery prune target escaped its cataloged directory");
					}
					try {
						unlinkVerifiedSegmentAtPath(
							sessionScopeLease.procFdAuthority,
							sessionScopeLease.sealedDescriptor,
							sealedDirectory,
							basename(summary.path),
							verifiedHandle,
						);
					} catch (error) {
						const unlinkMutationError = unlinkMutationErrorIn(error);
						if (!unlinkMutationError) throw error;
						result.deletedSegmentIds.push(summary.header.segmentId);
						result.deletedBytes += summary.fileBytes;
						result.locatorsInvalidated = true;
						result.requiresFullReconciliation = true;
						throw new IncidentRecorderSegmentPruneMutationError({
							cause: error,
							result: pruneMutationResultSnapshot(result),
							directoryDurability: unlinkMutationError.directoryDurability,
						});
					}
					result.deletedSegmentIds.push(summary.header.segmentId);
					result.deletedBytes += summary.fileBytes;
					result.locatorsInvalidated = true;
					result.requiresFullReconciliation = true;
					try {
						options.onOwnershipTransitionCheck?.();
						if (
							recoveryOwnerFingerprint(options.directory, isOwnerAlive, () =>
								options.faultInjector?.("after-recovery-owner-claim-handle-close"),
							) !== ownerSnapshot
						) {
							throw new Error("writer ownership changed during recovery pruning");
						}
					} catch (error) {
						throw new IncidentRecorderSegmentPruneMutationError({
							cause: error,
							result: pruneMutationResultSnapshot(result),
							directoryDurability: "confirmed",
						});
					}
				});
				settleIncidentRecorderOutcome(
					candidateOutcome,
					runCleanupActionsAttemptAll([() => closeSync(verifiedHandle.fileDescriptor)]),
				);
			}
			if (!result.moreWork) {
				delete result.continuation;
				removePruneCursorCapability(
					RECOVERY_PRUNE_CURSOR_CAPABILITIES,
					pruneCursorCapabilityKey(sessionReservation),
					sessionCapability.cursor,
				);
			} else if (result.continuation && result.continuation !== sessionReservation) {
				sessionCapability = registerPruneCursorCapability(
					RECOVERY_PRUNE_CURSOR_CAPABILITIES,
					result.continuation,
					storageScope.fingerprint,
					Date.now(),
					sessionScopeLease,
					sessionCapability,
					options.onPruneExpiryCleanupDiagnostic,
				);
				recoveryPruneOwnedCapability = sessionCapability;
			} else if (!continuation) {
				removePruneCursorCapability(
					RECOVERY_PRUNE_CURSOR_CAPABILITIES,
					pruneCursorCapabilityKey(sessionReservation),
					sessionCapability.cursor,
				);
			}
			return result;
		} catch (error) {
			const surfacedError = classifyPruneFailure(error, result);
			const cleanupErrors = runCleanupActionsAttemptAll([
				() => {
					removePruneCursorCapability(
						RECOVERY_PRUNE_CURSOR_CAPABILITIES,
						pruneCursorCapabilityKey(sessionReservation),
						sessionCapability.cursor,
					);
				},
			]);
			throw attachCleanupToPruneFailure(surfacedError, cleanupErrors);
		}
	} catch (error) {
		const cleanupCursor = recoveryPruneOwnedCapability?.cursor ?? recoveryPruneCleanupCursor;
		const cleanupErrors = cleanupCursor
			? runCleanupActionsAttemptAll([
					() => {
						removePruneCursorCapability(
							RECOVERY_PRUNE_CURSOR_CAPABILITIES,
							pruneCursorCapabilityKey(cleanupCursor),
							cleanupCursor,
						);
					},
				])
			: [];
		throw attachCleanupToPruneFailure(error, cleanupErrors);
	}
}
