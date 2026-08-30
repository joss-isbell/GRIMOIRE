import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import {
	chmodSync,
	closeSync,
	constants,
	fstatSync,
	fsyncSync,
	ftruncateSync,
	linkSync,
	lstatSync,
	statfsSync,
	mkdirSync,
	openSync,
	opendirSync,
	readFileSync,
	readSync,
	renameSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

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
const DEFAULT_MAX_IDEMPOTENCY_LOOKUP_SEGMENTS = DEFAULT_MAX_STARTUP_ENTRIES;
const DEFAULT_MAX_IDEMPOTENCY_LOOKUP_RECORDS = 1_048_576;
const DEFAULT_MAX_PRUNE_SEGMENTS = 16;
const DEFAULT_MAX_PRUNE_BYTES = 64 * MEBIBYTE;
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

const enum FrameType {
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

export interface IncidentRecorderSegmentPageQuery extends IncidentRecorderSegmentQuery {
	after?: IncidentRecorderSegmentQueryCursor;
	maxRecords?: number;
	maxBytes?: number;
}

export interface IncidentRecorderSegmentQueryPage {
	records: IncidentRecorderSegmentRecord[];
	complete: boolean;
	nextCursor?: IncidentRecorderSegmentQueryCursor;
	selectedFrameBytes: number;
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
	| "after-prune-unlink-before-directory-fsync";

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
	version: 1;
	sessionId: string;
	storeInstanceId: string;
	highWaterSegmentSequence: number;
	filterSha256: string;
	segmentSequence: number;
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
	faultInjector?: (point: IncidentRecorderSegmentFaultPoint) => void;
	ownerIdentity?: IncidentRecorderSegmentOwnerIdentity;
	isOwnerAlive?: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean;
	openPlan?: IncidentRecorderSegmentOpenPlan;
	onOpenAdmission?: (plan: IncidentRecorderSegmentOpenPlan) => void;
	onOpenStorageResult?: (result: IncidentRecorderSegmentOpenResult) => void;
}

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
	locatorsInvalidated: boolean;
	requiresFullReconciliation: boolean;
	moreWork: boolean;
	continuation?: IncidentRecorderSegmentPruneCursor;
	requiredBytes?: number;
}

export interface IncidentRecorderSegmentRecoveryPruneOptions extends IncidentRecorderSegmentPruneInput {
	directory: string;
	externalWriterExcluded: true;
	maxStartupEntries?: number;
	maxStartupCatalogBytes?: number;
	isOwnerAlive?: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean;
	onOwnershipTransitionCheck?: () => void;
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
	fileDescriptor: number;
	size: number;
	nextOrdinal: number;
	records: SegmentIndexEntry[];
	recoveryGaps: IncidentRecorderSegmentRecoveryGap[];
}

interface OwnerClaim extends IncidentRecorderSegmentOwnerIdentity {
	version: 1;
	nonce: string;
}

class InvalidFrameError extends Error {}

export class IncidentRecorderSegmentStorePoisonedError extends Error {
	constructor(cause: unknown) {
		super(`incident recorder segment store is poisoned: ${errorText(cause)}`, { cause });
		this.name = "IncidentRecorderSegmentStorePoisonedError";
	}
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
	return sha256(Buffer.from(canonicalJson({ generation, protectedRunIds }), "utf8"));
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

function validatedPruneProtection(
	protection: IncidentRecorderSegmentPruneProtectionComplete,
): {
	readonly generation: number;
	readonly fingerprint: string;
	readonly protectedRunIds: readonly string[];
	readonly protectedRunIdSet: ReadonlySet<string>;
} {
	if (!protection || protection.state !== "complete") {
		throw new Error("a complete prune protection proof is required");
	}
	assertSafeNonNegativeInteger(protection.generation, "prune protection generation");
	const sortedRunIds = boundedCanonicalIdentifiers(
		protection.protectedRunIds,
		"protected run IDs",
		(runId) => assertIdentifier(runId, "protected runId"),
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
	if (!isRecord(value) || !isJsonValue(value)) throw new Error("metadata must be an exact finite JSON object with depth at most 64");
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
	if (content.byteLength > 0xffff_ffff - FRAME_OVERHEAD_BYTES) throw new Error("frame content exceeds the format limit");
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

function readFully(fileDescriptor: number, buffer: Buffer, position: number): void {
	let completed = 0;
	while (completed < buffer.byteLength) {
		const bytes = readSync(fileDescriptor, buffer, completed, buffer.byteLength - completed, position + completed);
		if (bytes === 0) throw new InvalidFrameError("unexpected end of segment");
		completed += bytes;
	}
}

function writeFullyAt(fileDescriptor: number, buffer: Buffer, position: number): void {
	let completed = 0;
	while (completed < buffer.byteLength) {
		const bytes = writeSync(fileDescriptor, buffer, completed, buffer.byteLength - completed, position + completed);
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

function parseFrameAt(fileDescriptor: number, offset: number, fileSize: number): ParsedFrame {
	if (offset < 0 || fileSize - offset < FRAME_OVERHEAD_BYTES) throw new InvalidFrameError("incomplete frame prefix");
	const prefix = Buffer.alloc(FRAME_PREFIX_BYTES);
	readFully(fileDescriptor, prefix, offset);
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
	readFully(fileDescriptor, frame.subarray(FRAME_PREFIX_BYTES), offset + FRAME_PREFIX_BYTES);
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

function assertPrivateRegularFile(fileDescriptor: number, path: string): void {
	const status = fstatSync(fileDescriptor);
	if (!status.isFile()) throw new Error(`segment path is not a regular file: ${path}`);
	if ((status.mode & 0o077) !== 0) throw new Error(`segment file is not private: ${path}`);
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

function hashFileRange(fileDescriptor: number, start: number, bytes: number, onRead?: (bytes: number) => void): string {
	const hash = createHash("sha256");
	const buffer = Buffer.alloc(Math.min(RECOVERY_READ_CHUNK_BYTES, Math.max(1, bytes)));
	let offset = 0;
	while (offset < bytes) {
		const length = Math.min(buffer.byteLength, bytes - offset);
		const chunk = buffer.subarray(0, length);
		readFully(fileDescriptor, chunk, start + offset);
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

function fileAllocation(fileDescriptor: number): StorageState {
	const status = fstatSync(fileDescriptor, { bigint: true });
	return {
		deviceId: status.dev.toString(),
		inodeId: status.ino.toString(),
		linkCount: Number(status.nlink),
		logicalBytes: Number(status.size),
		allocatedBytes: Number(status.blocks * 512n),
	};
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
	try {
		const status = fstatSync(fileDescriptor);
		if (directory ? !status.isDirectory() : !status.isFile()) throw new Error("storage accounting path type changed");
		return fileAllocation(fileDescriptor);
	} finally {
		closeSync(fileDescriptor);
	}
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
	const fields = contents.slice(end + 1).trim().split(/\s+/);
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
	if (frame.type !== FrameType.Record || frame.content.byteLength < 4) throw new InvalidFrameError("record frame is invalid");
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
	if (value.reason.length === 0 || value.reason.length > 256) throw new InvalidFrameError("sealed footer reason is invalid");
	if (value.indexFrameBytes < FRAME_OVERHEAD_BYTES || value.indexFrameBytes > FORMAT_MAX_INDEX_FRAME_BYTES) {
		throw new InvalidFrameError("sealed footer index length exceeds the fixed format maximum");
	}
	if (!/^[a-f0-9]{64}$/.test(value.indexSha256) || !/^[a-f0-9]{64}$/.test(value.contentSha256)) {
		throw new InvalidFrameError("sealed footer checksum is invalid");
	}
	if (Buffer.from(value.idempotencyBloomBase64, "base64").byteLength !== IDEMPOTENCY_BLOOM_BYTES) {
		throw new InvalidFrameError("sealed footer idempotency bloom is invalid");
	}
	if ((value.recordCount === 0) !== (value.minObservedAtMs === null) || (value.recordCount === 0) !== (value.maxObservedAtMs === null)) {
		throw new InvalidFrameError("sealed footer time bounds do not match its record count");
	}
	if (value.minObservedAtMs !== null && value.maxObservedAtMs !== null && value.minObservedAtMs > value.maxObservedAtMs) {
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

function openPathFingerprint(path: string): string {
	const status = pathStatus(path);
	if (!status) return "missing";
	const bigintStatus = lstatSync(path, { bigint: true });
	return [
		bigintStatus.dev.toString(),
		bigintStatus.ino.toString(),
		bigintStatus.mode.toString(),
		bigintStatus.size.toString(),
		bigintStatus.mtimeNs.toString(),
	].join(":");
}

function openStateFingerprint(directory: string): string {
	return sha256(
		Buffer.from(
			[
				directory,
				openPathFingerprint(dirname(directory)),
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
	const parentDirectoryEntriesAtPeak =
		Number(rootMissing) + Number(activeMissing) + Number(sealedMissing) + 2;
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

function captureOpenStorageEntries(
	directory: string,
	created: { root: boolean; active: boolean; sealed: boolean; owner: boolean },
): IncidentRecorderSegmentOpenStorageEntry[] {
	const definitions = [
		{ path: directory, kind: "root-directory" as const, createdByOpen: created.root, directory: true },
		{ path: join(directory, "active"), kind: "active-directory" as const, createdByOpen: created.active, directory: true },
		{ path: join(directory, "sealed"), kind: "sealed-directory" as const, createdByOpen: created.sealed, directory: true },
		{ path: join(directory, OWNER_FILE_NAME), kind: "owner-file" as const, createdByOpen: created.owner, directory: false },
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
	readonly #faultInjector?: (point: IncidentRecorderSegmentFaultPoint) => void;
	readonly #ownerIdentity: IncidentRecorderSegmentOwnerIdentity;
	readonly #isOwnerAlive: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean;
	readonly #onOpenStorageResult?: (result: IncidentRecorderSegmentOpenResult) => void;
	#sealed: SegmentSummary[] = [];
	#corrupt: CorruptSegment[] = [];
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
	#accountingSequence = 0;
	#validatedIdempotencyBloomSegmentIds = new Set<string>();
	#openRemovedPreexistingEntry = false;
	#insideCallback = false;
	#openStorageEntries: IncidentRecorderSegmentOpenStorageEntry[] = [];

	constructor(options: IncidentRecorderSegmentStoreOptions) {
		if (!options.directory) throw new Error("directory is required");
		this.#directory = options.directory;
		this.#activeDirectory = join(options.directory, "active");
		this.#sealedDirectory = join(options.directory, "sealed");
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
		this.#faultInjector = options.faultInjector;
		this.#ownerIdentity = options.ownerIdentity ?? defaultOwnerIdentity();
		this.#isOwnerAlive = options.isOwnerAlive ?? defaultIsOwnerAlive;
		this.#onOpenStorageResult = options.onOpenStorageResult;
		assertSafeNonNegativeInteger(this.#ownerIdentity.pid, "owner pid");
		if (!this.#ownerIdentity.startTime || !this.#ownerIdentity.bootId) throw new Error("owner identity is incomplete");

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
				reconciliation: this.#openRemovedPreexistingEntry
					? "full-dev-inode-required"
					: "incremental-complete",
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

	getOpenStorageEntries(): readonly IncidentRecorderSegmentOpenStorageEntry[] {
		return this.#openStorageEntries.map((entry) => ({ ...entry }));
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
		if (!this.#onDurableWrite) return;
		this.#insideCallback = true;
		try {
			this.#onDurableWrite({
				...event,
				eventId: this.#instanceId + ":" + String(this.#accountingSequence),
				accountingSequence: this.#accountingSequence,
				reconciliation: "apply-by-event-id-then-reconcile-dev-inode",
			});
		} finally {
			this.#insideCallback = false;
		}
	}

	#poison(error: unknown): never {
		if (!this.#poisoned) this.#poisoned = new IncidentRecorderSegmentStorePoisonedError(error);
		this.#closeActiveDescriptor();
		throw this.#poisoned;
	}

	#closeActiveDescriptor(): void {
		if (!this.#active || this.#active.fileDescriptor < 0) return;
		try {
			closeSync(this.#active.fileDescriptor);
		} catch {
			// The first operation error remains authoritative once the store is poisoned.
		}
		this.#active.fileDescriptor = -1;
	}

	#readOwnerClaim(path: string): OwnerClaim {
		const fileDescriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		try {
			assertPrivateRegularFile(fileDescriptor, path);
			const status = fstatSync(fileDescriptor);
			if (status.size <= 0 || status.size > 4096) throw new Error("writer ownership claim is malformed");
			const bytes = Buffer.alloc(status.size);
			readFully(fileDescriptor, bytes, 0);
			return parseOwnerClaim(parseJson(bytes, "writer ownership claim"));
		} finally {
			closeSync(fileDescriptor);
		}
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
			throw new Error("segment catalog exceeds maxStartupCatalogBytes");
		}
	}

	#accountSummary(summary: SegmentSummary): void {
		this.#startupCatalogBytes +=
			Buffer.byteLength(summary.path, "utf8") +
			encodeJson(summary.header).byteLength +
			encodeJson(summary.footer).byteLength +
			384;
		if (this.#startupCatalogBytes > this.#maxStartupCatalogBytes) {
			throw new Error("segment catalog exceeds maxStartupCatalogBytes");
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
		try {
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
		} finally {
			closeSync(fileDescriptor);
		}
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
		for (const entry of index.records) {
			if (
				entry.segmentId !== header.segmentId ||
				entry.segmentSequence !== header.segmentSequence ||
				entry.offset < FRAME_OVERHEAD_BYTES ||
				entry.offset + entry.frameBytes > footer.indexOffset
			) {
				throw new InvalidFrameError("sealed index record bounds or identity are invalid");
			}
			positions.push({ ordinal: entry.ordinal, offset: entry.offset });
			minimum = minimum === null ? entry.observedAtMs : Math.min(minimum, entry.observedAtMs);
			maximum = maximum === null ? entry.observedAtMs : Math.max(maximum, entry.observedAtMs);
		}
		for (const gap of index.recoveryGaps) {
			if (
				gap.segmentId !== header.segmentId ||
				gap.segmentSequence !== header.segmentSequence ||
				gap.invalidOffset < FRAME_OVERHEAD_BYTES ||
				gap.invalidOffset >= footer.indexOffset
			) {
				throw new InvalidFrameError("sealed index gap bounds or identity are invalid");
			}
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

	#readIndex(summary: SegmentSummary): SegmentIndexDocument {
		const fileDescriptor = openSync(summary.path, constants.O_RDONLY | constants.O_NOFOLLOW);
		try {
			assertPrivateRegularFile(fileDescriptor, summary.path);
			const status = fstatSync(fileDescriptor);
			if (status.size !== summary.fileBytes) throw new InvalidFrameError("sealed segment size changed after cataloging");
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
				return this.#poison(error);
			}
			return index;
		} finally {
			closeSync(fileDescriptor);
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
		if (active.fileDescriptor >= 0) {
			closeSync(active.fileDescriptor);
			active.fileDescriptor = -1;
		}
		return { header: active.header, footer, path: sealedPath, fileBytes };
	}

	#recoverActive(path: string): ActiveSegment | SegmentSummary {
		const fileDescriptor = openSync(path, constants.O_RDWR | constants.O_NOFOLLOW);
		let descriptorOwned = true;
		try {
			assertPrivateRegularFile(fileDescriptor, path);
			const fileSize = fstatSync(fileDescriptor).size;
			const previousAllocation = fileAllocation(fileDescriptor);
			const recoveryParentBefore = pathStorageState(this.#activeDirectory, true);
			if (
				fileSize < FRAME_OVERHEAD_BYTES ||
				fileSize > FORMAT_MAX_ACTIVE_BYTES + FORMAT_MAX_INDEX_FRAME_BYTES + FORMAT_MAX_FOOTER_FRAME_BYTES
			) {
				throw new InvalidFrameError("active segment size exceeds the fixed format maximum");
			}
			const headerFrame = parseFrameAt(fileDescriptor, 0, fileSize);
			const header = parseHeader(headerFrame);
			if (basename(path) !== header.segmentId + ".open") {
				throw new InvalidFrameError("active segment filename does not match its header identity");
			}
			const active: ActiveSegment = {
				header,
				path,
				fileDescriptor,
				size: headerFrame.frameBytes,
				nextOrdinal: 1,
				records: [],
				recoveryGaps: [],
			};
			let offset = headerFrame.frameBytes;
			let invalidError: unknown;
			while (offset < fileSize) {
				try {
					const frame = parseFrameAt(fileDescriptor, offset, fileSize);
					if (frame.ordinal !== active.nextOrdinal) throw new InvalidFrameError("active frame ordinal is not contiguous");
					if (frame.type === FrameType.Record) {
						if (active.records.length >= FORMAT_MAX_RECORDS) throw new InvalidFrameError("active segment has too many records");
						active.records.push(indexEntryFromFrame(header, frame, offset));
						offset += frame.frameBytes;
						active.size = offset;
						active.nextOrdinal += 1;
						continue;
					}
					if (frame.type === FrameType.RecoveryGap) {
						if (active.recoveryGaps.length >= FORMAT_MAX_GAPS) throw new InvalidFrameError("active segment has too many recovery gaps");
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
						const footerFrame = parseFrameAt(fileDescriptor, footerOffset, fileSize);
						const footer = parseFooter(footerFrame);
						if (footerOffset + footerFrame.frameBytes !== fileSize) {
							throw new InvalidFrameError("sealed active segment has trailing bytes");
						}
						this.#validateIndex(header, footer, frame, index);
						if (
							footer.indexOffset !== offset ||
							footer.contentBytes !== footerOffset ||
							footerFrame.ordinal !== frame.ordinal + 1 ||
							hashFileRange(fileDescriptor, 0, footer.contentBytes, this.#onRecoveryRead) !== footer.contentSha256
						) {
							throw new InvalidFrameError("sealed active segment footer or content checksum is invalid");
						}
						fsyncSync(fileDescriptor);
						const promoted = this.#promoteActiveFile(active, footer, fileSize);
						descriptorOwned = false;
						return promoted;
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
					discardedSha256: hashFileRange(fileDescriptor, offset, discardedBytes, this.#onRecoveryRead),
				};
				const gapFrame = encodeFrame(FrameType.RecoveryGap, gap.ordinal, encodeJson(gap));
				writeFullyAt(fileDescriptor, gapFrame, offset);
				fsyncSync(fileDescriptor);
				this.#faultInjector?.("after-recovery-gap-fsync-before-truncate");
				ftruncateSync(fileDescriptor, offset + gapFrame.byteLength);
				fsyncSync(fileDescriptor);
				active.recoveryGaps.push(gap);
				active.size = offset + gapFrame.byteLength;
				active.nextOrdinal += 1;
				const allocation = fileAllocation(fileDescriptor);
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
			descriptorOwned = false;
			return active;
		} finally {
			if (descriptorOwned) closeSync(fileDescriptor);
		}
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
		let fileDescriptor = -1;
		try {
			fileDescriptor = openSync(
				temporaryPath,
				constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
				0o600,
			);
			writeFullyAt(fileDescriptor, headerFrame, 0);
			fsyncSync(fileDescriptor);
			this.#faultInjector?.("after-header-fsync-before-publish");
			linkSync(temporaryPath, activePath);
			syncDirectory(this.#activeDirectory);
			unlinkSync(temporaryPath);
			syncDirectory(this.#activeDirectory);
			const active: ActiveSegment = {
				header,
				path: activePath,
				fileDescriptor,
				size: headerFrame.byteLength,
				nextOrdinal: 1,
				records: [],
				recoveryGaps: [],
			};
			this.#active = active;
			this.#nextSequence += 1;
			try {
				const allocation = fileAllocation(fileDescriptor);
				this.#emitDurable({
					kind: "segment-created",
					segmentId,
					path: activePath,
					entryChange: "published",
					entryDelta: 1,
					inodeDelta: 1,
					previousLogicalBytes: 0,
					previousAllocatedBytes: 0,
					...allocation,
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
		} catch (error) {
			if (fileDescriptor >= 0) {
				try {
					closeSync(fileDescriptor);
				} catch {
					// Preserve the initiating error.
				}
			}
			if (this.#active?.fileDescriptor === fileDescriptor) this.#active.fileDescriptor = -1;
			return this.#poison(error);
		}
	}

	#sealActive(reason: string, sealedAtMs = this.#now()): void {
		const active = this.#active;
		if (!active) return;
		if (active.fileDescriptor < 0) return this.#poison("active segment descriptor is unavailable");
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
		const previousAllocation = fileAllocation(active.fileDescriptor);
		const activeParentBefore = pathStorageState(this.#activeDirectory, true);
		const sealedParentBefore = pathStorageState(this.#sealedDirectory, true);
		try {
			writeFullyAt(active.fileDescriptor, indexFrame, indexOffset);
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
				contentSha256: hashFileRange(active.fileDescriptor, 0, contentBytes),
				idempotencyBloomBase64: idempotencyBloom(active.records),
			};
			assertSafeNonNegativeInteger(footer.sealedAtMs, "segment seal time");
			const footerFrame = encodeFrame(FrameType.Footer, active.nextOrdinal + 1, encodeJson(footer));
			if (footerFrame.byteLength > FORMAT_MAX_FOOTER_FRAME_BYTES) {
				throw new Error("sealed footer exceeds the fixed format maximum");
			}
			writeFullyAt(active.fileDescriptor, footerFrame, contentBytes);
			fsyncSync(active.fileDescriptor);
			const fileBytes = contentBytes + footerFrame.byteLength;
			const summary = this.#promoteActiveFile(active, footer, fileBytes);
			this.#active = undefined;
			const existingIndex = this.#sealed.findIndex(
				(candidate) => candidate.header.segmentId === summary.header.segmentId,
			);
			if (existingIndex >= 0) this.#sealed[existingIndex] = summary;
			else this.#sealed.push(summary);
			this.#sealed.sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
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
				return this.#poison(error);
			}
		} catch (error) {
			return this.#poison(error);
		}
	}

	#estimateSealGrowth(active: ActiveSegment, records: SegmentIndexEntry[], reason: string, sealedAtMs: number): number {
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
		const addedRecordBytes = records.length > active.records.length ? records.at(-1)?.frameBytes ?? 0 : 0;
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
		const recordFrame = encodeFrame(
			FrameType.Record,
			0,
			Buffer.concat([envelopeLength, envelopeBytes, payload]),
		);
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
		let target: ActiveSegment;
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
				path: "",
				fileDescriptor: -1,
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
			const currentAllocation = fileAllocation(current.fileDescriptor).allocatedBytes;
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
					fileAllocation(current.fileDescriptor).allocatedBytes,
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
		const existingLocator = this.#findIdempotentRecord(
			envelope.idempotencyKey,
			envelope.canonicalContentSha256,
		);
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
		const previousAllocation = fileAllocation(active.fileDescriptor);
		const recordParentBefore = pathStorageState(this.#activeDirectory, true);
		try {
			writeFullyAt(active.fileDescriptor, frame, offset);
			this.#faultInjector?.("after-record-write-before-fsync");
			fsyncSync(active.fileDescriptor);
			active.records.push(entry);
			active.size += frame.byteLength;
			active.nextOrdinal += 1;
			const allocation = fileAllocation(active.fileDescriptor);
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
		return this.#appendFrozen(
			frozen.input,
			frozen.sampledNow,
			frozen.publicPlan.estimate,
			frozen.plannedSegmentId,
		);
	}

	append(input: IncidentRecorderSegmentAppendInput): IncidentRecorderSegmentAppendResult {
		return this.commitAppendPlan(this.planAppend(input));
	}

	seal(reason: string): void {
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
			const bloomMayContain = idempotencyBloomMayContain(
				summary.footer.idempotencyBloomBase64,
				idempotencyKey,
			);
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

	#assertLocatorMatchesEntry(
		locator: IncidentRecorderSegmentLocator,
		entry: SegmentIndexEntry,
	): void {
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
		this.#assertUsable();
		assertRecordLocator(locator);
		const corrupt = this.#corrupt.find((segment) => segment.segmentId === locator.segmentId);
		if (corrupt) {
			if (corrupt.summary && corrupt.summary.header.segmentSequence !== locator.segmentSequence) {
				throw new InvalidFrameError("record locator conflicts with a retained corrupt segment identity");
			}
			throw new InvalidFrameError("record locator references a corrupt retained segment");
		}
		if (this.#active?.header.segmentId === locator.segmentId) {
			if (this.#active.header.segmentSequence !== locator.segmentSequence) {
				throw new InvalidFrameError("record locator conflicts with the active segment identity");
			}
			const entry = this.#active.records.find((candidate) => candidate.ordinal === locator.ordinal);
			if (!entry) throw new InvalidFrameError("record locator ordinal is absent from the active segment");
			this.#assertLocatorMatchesEntry(locator, entry);
			return this.#readRecordAt(
				this.#active.fileDescriptor,
				this.#active.size,
				this.#active.header,
				entry,
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

	#readRecordAt(
		fileDescriptor: number,
		fileSize: number,
		header: SegmentHeader,
		entry: SegmentIndexEntry,
	): IncidentRecorderSegmentRecord {
		const frame = parseFrameAt(fileDescriptor, entry.offset, fileSize);
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

	queryRunWindowPage(query: IncidentRecorderSegmentPageQuery): IncidentRecorderSegmentQueryPage {
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
		const pageMaxRecords = positiveInteger(query.maxRecords, this.#maxQueryRecords, "page maxRecords", this.#maxQueryRecords);
		const pageMaxBytes = positiveInteger(query.maxBytes, this.#maxQueryBytes, "page maxBytes", this.#maxQueryBytes);
		if (query.after) {
			if (query.after.version !== 1) throw new Error("query cursor version is unsupported");
			if (
				query.after.snapshotId !== this.#instanceId ||
				query.after.generation !== this.#generation ||
				query.after.filterSha256 !== filterSha256
			) {
				throw new Error("query snapshot is stale or does not match the frozen filter; restart required");
			}
			assertSafeNonNegativeInteger(query.after.segmentSequence, "query cursor segment sequence");
			assertSafeNonNegativeInteger(query.after.ordinal, "query cursor ordinal");
		}
		let highWaterSegmentSequence = 0;
		let highWaterOrdinal = 0;
		const considerHighWater = (segmentSequence: number, ordinal: number): void => {
			if (
				segmentSequence > highWaterSegmentSequence ||
				(segmentSequence === highWaterSegmentSequence && ordinal > highWaterOrdinal)
			) {
				highWaterSegmentSequence = segmentSequence;
				highWaterOrdinal = ordinal;
			}
		};
		if (query.after) {
			highWaterSegmentSequence = query.after.highWaterSegmentSequence;
			highWaterOrdinal = query.after.highWaterOrdinal;
		} else {
			for (const summary of this.#sealed) {
				considerHighWater(summary.header.segmentSequence, summary.footer.recordCount + summary.footer.gapCount);
			}
			for (const corrupt of this.#corrupt) {
				if (corrupt.summary) {
					considerHighWater(
						corrupt.summary.header.segmentSequence,
						corrupt.summary.footer.recordCount + corrupt.summary.footer.gapCount,
					);
				}
			}
			if (this.#active) considerHighWater(this.#active.header.segmentSequence, this.#active.nextOrdinal - 1);
		}
		const snapshot: IncidentRecorderSegmentQuerySnapshot = {
			version: 1,
			id: this.#instanceId,
			generation: this.#generation,
			highWaterSegmentSequence,
			highWaterOrdinal,
			filterSha256,
		};
		if (this.#corrupt.some((segment) => !segment.summary)) {
			throw new InvalidFrameError("an uncatalogued corrupt segment prevents an exact query");
		}
		const summaries = [
			...this.#sealed,
			...this.#corrupt.flatMap((segment) => (segment.summary ? [segment.summary] : [])),
		].sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
		const records: IncidentRecorderSegmentRecord[] = [];
		let selectedFrameBytes = 0;
		let complete = true;
		const isAfterCursor = (entry: SegmentIndexEntry): boolean =>
			(!query.after ||
				entry.segmentSequence > query.after.segmentSequence ||
				(entry.segmentSequence === query.after.segmentSequence && entry.ordinal > query.after.ordinal)) &&
			(entry.segmentSequence < highWaterSegmentSequence ||
				(entry.segmentSequence === highWaterSegmentSequence && entry.ordinal <= highWaterOrdinal));
		const matches = (entry: SegmentIndexEntry): boolean =>
			isAfterCursor(entry) &&
			entry.runId === query.runId &&
			(query.sourceId === undefined || entry.sourceId === query.sourceId) &&
			entry.observedAtMs >= query.fromObservedAtMs &&
			entry.observedAtMs <= query.throughObservedAtMs;
		const canTake = (entry: SegmentIndexEntry): boolean => {
			if (records.length + 1 > pageMaxRecords || selectedFrameBytes + entry.frameBytes > pageMaxBytes) {
				if (records.length === 0) throw new Error("next selected full frame bytes exceed maxQueryBytes for this page");
				complete = false;
				return false;
			}
			selectedFrameBytes += entry.frameBytes;
			return true;
		};

		for (const summary of summaries) {
			if (!complete) break;
			if (
				summary.footer.recordCount === 0 ||
				(summary.footer.maxObservedAtMs ?? -1) < query.fromObservedAtMs ||
				(summary.footer.minObservedAtMs ?? Number.MAX_SAFE_INTEGER) > query.throughObservedAtMs ||
				(query.after !== undefined && summary.header.segmentSequence < query.after.segmentSequence)
			) {
				continue;
			}
			const index = this.#readIndex(summary);
			let fileDescriptor = -1;
			try {
				for (const entry of index.records) {
					if (!matches(entry)) continue;
					if (!canTake(entry)) break;
					if (fileDescriptor < 0) {
						fileDescriptor = openSync(summary.path, constants.O_RDONLY | constants.O_NOFOLLOW);
						assertPrivateRegularFile(fileDescriptor, summary.path);
					}
					records.push(
						this.#readRecordAt(fileDescriptor, summary.fileBytes, summary.header, entry),
					);
				}
			} finally {
				if (fileDescriptor >= 0) closeSync(fileDescriptor);
			}
		}
		if (complete && this.#active) {
			for (const entry of this.#active.records) {
				if (!matches(entry)) continue;
				if (!canTake(entry)) break;
				records.push(
					this.#readRecordAt(
						this.#active.fileDescriptor,
						this.#active.size,
						this.#active.header,
						entry,
					),
				);
			}
		}
		const last = records.at(-1)?.locator;
		return {
			records,
			complete,
			selectedFrameBytes,
			snapshot,
			...(complete || !last
				? {}
				: {
						nextCursor: {
							version: 1 as const,
							snapshotId: snapshot.id,
							generation: snapshot.generation,
							highWaterSegmentSequence: snapshot.highWaterSegmentSequence,
							highWaterOrdinal: snapshot.highWaterOrdinal,
							filterSha256: snapshot.filterSha256,
							segmentSequence: last.segmentSequence,
							ordinal: last.ordinal,
						},
					}),
		};
	}

	queryRunWindow(query: IncidentRecorderSegmentQuery): IncidentRecorderSegmentRecord[] {
		const page = this.queryRunWindowPage(query);
		if (!page.complete) throw new Error("selected full frame bytes exceed maxQueryBytes or records exceed maxQueryRecords");
		return page.records;
	}

	getRecoveryGaps(): IncidentRecorderSegmentRecoveryGap[] {
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
			for (const gap of this.#readIndex(summary).recoveryGaps) admit(gap);
		}
		for (const gap of this.#active?.recoveryGaps ?? []) admit(gap);
		return gaps.sort(
			(left, right) => left.segmentSequence - right.segmentSequence || left.ordinal - right.ordinal,
		);
	}

	#verifySegment(summary: SegmentSummary, index: SegmentIndexDocument): void {
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
		try {
			assertPrivateRegularFile(fileDescriptor, summary.path);
			if (hashFileRange(fileDescriptor, 0, summary.footer.contentBytes) !== summary.footer.contentSha256) {
				throw new InvalidFrameError("sealed segment content checksum mismatch");
			}
			const positions: Array<
				| { kind: "record"; ordinal: number; offset: number; entry: SegmentIndexEntry }
				| { kind: "gap"; ordinal: number; offset: number; gap: IncidentRecorderSegmentRecoveryGap }
			> = [
				...index.records.map((entry) => ({ kind: "record" as const, ordinal: entry.ordinal, offset: entry.offset, entry })),
				...index.recoveryGaps.map((gap) => ({ kind: "gap" as const, ordinal: gap.ordinal, offset: gap.invalidOffset, gap })),
			].sort((left, right) => left.ordinal - right.ordinal);
			const headerFrame = parseFrameAt(fileDescriptor, 0, summary.fileBytes);
			let expectedOffset = headerFrame.frameBytes;
			for (const position of positions) {
				if (position.offset !== expectedOffset) throw new InvalidFrameError("sealed record/gap offsets are not contiguous");
				const frame = parseFrameAt(fileDescriptor, position.offset, summary.fileBytes);
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
				throw new InvalidFrameError("sealed content does not terminate at its index");
			}
		} finally {
			closeSync(fileDescriptor);
		}
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
		this.#stateRevision += 1;
	}

	pruneSealedSegments(input: IncidentRecorderSegmentPruneInput): IncidentRecorderSegmentPruneResult {
		this.#assertUsable();
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
					protectedRunIds: protection.protectedRunIds,
					protectedSegmentIds: protectedSegments.sorted,
				}),
				"utf8",
			),
		);
		const availableHighWater = this.#sealed.reduce(
			(highWater, summary) => Math.max(highWater, summary.header.segmentSequence),
			0,
		);
		if (input.continuation) {
			if (input.continuation.version !== 1) throw new Error("prune continuation version is unsupported");
			assertSafeNonNegativeInteger(input.continuation.segmentSequence, "prune continuation segment sequence");
			if (
				input.continuation.storeInstanceId !== this.#instanceId ||
				input.continuation.filterSha256 !== pruneFilterSha256
			) {
				throw new Error("prune continuation is stale or does not match its frozen arguments");
			}
		}
		const pruneSession = {
			sessionId: input.continuation?.sessionId ?? randomUUID(),
			storeInstanceId: this.#instanceId,
			highWaterSegmentSequence: input.continuation?.highWaterSegmentSequence ?? availableHighWater,
			filterSha256: pruneFilterSha256,
		};
		const continuationFor = (segmentSequence: number): IncidentRecorderSegmentPruneCursor => ({
			version: 1,
			...pruneSession,
			segmentSequence,
		});
		const result: IncidentRecorderSegmentPruneResult = {
			deletedSegmentIds: [],
			corruptSegmentIds: [],
			examinedSegments: 0,
			deletedBytes: 0,
			locatorsInvalidated: false,
			requiresFullReconciliation: false,
			moreWork: false,
		};
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
					(!input.continuation || summary.header.segmentSequence > input.continuation.segmentSequence),
			);
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
				break;
			}
			result.examinedSegments += 1;
			examinedBytes += summary.fileBytes;
			result.continuation = continuationFor(summary.header.segmentSequence);
			let index: SegmentIndexDocument;
			try {
				index = this.#readIndex(summary);
				this.#verifySegment(summary, index);
			} catch (error) {
				if (this.#poisoned) throw this.#poisoned;
				this.#markCorrupt(summary, error);
				result.corruptSegmentIds.push(summary.header.segmentId);
				continue;
			}
			if (index.records.some((entry) => protectedRunIds.has(entry.runId))) continue;
			try {
				const before = lstatSync(summary.path);
				if (!before.isFile() || before.isSymbolicLink()) throw new Error("sealed prune target is not a regular file");
				const previousAllocation = pathAllocation(summary.path);
				const pruneParentBefore = pathStorageState(this.#sealedDirectory, true);
				unlinkSync(summary.path);
				this.#faultInjector?.("after-prune-unlink-before-directory-fsync");
				syncDirectory(this.#sealedDirectory);
				this.#sealed = this.#sealed.filter(
					(candidate) => candidate.header.segmentId !== summary.header.segmentId,
				);
				result.deletedSegmentIds.push(summary.header.segmentId);
				result.deletedBytes += summary.fileBytes;
				result.locatorsInvalidated = true;
				this.#generation += 1;
				this.#stateRevision += 1;
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
							pathStorageState(this.#sealedDirectory, true),
						),
					],
				});
			} catch (error) {
				return this.#poison(error);
			}
		}
		if (!result.moreWork) delete result.continuation;
		return result;
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
		if (this.#closed) return;
		let closeError: unknown;
		if (this.#active && this.#active.fileDescriptor >= 0) {
			try {
				fsyncSync(this.#active.fileDescriptor);
				closeSync(this.#active.fileDescriptor);
				this.#active.fileDescriptor = -1;
			} catch (error) {
				closeError = error;
				this.#closeActiveDescriptor();
			}
		}
		const closeParentBefore = pathStorageState(this.#directory, true);
		try {
			this.#releaseOwnership();
		} catch (error) {
			closeError ??= error;
		}
		try {
			this.#onOpenStorageResult?.({
				phase: "closed",
				complete: closeError === undefined,
				reconciliation:
					closeError === undefined ? "incremental-complete" : "full-dev-inode-required",
				entries: captureOpenStorageEntries(this.#directory, {
					root: false,
					active: false,
					sealed: false,
					owner: false,
				}),
				parentEffects: [
					parentDirectoryEffect(
						this.#directory,
						closeParentBefore,
						pathStorageState(this.#directory, true),
					),
				],
				...(closeError === undefined ? {} : { error: errorText(closeError) }),
			});
		} catch (error) {
			closeError ??= error;
		}
		this.#closed = true;
		this.#appendPlans.clear();
		if (closeError) {
			this.#poisoned ??= new IncidentRecorderSegmentStorePoisonedError(closeError);
			throw this.#poisoned;
		}
	}
}

function readRecoverySealedSummary(path: string): SegmentSummary {
	const fileDescriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
	try {
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
	} finally {
		closeSync(fileDescriptor);
	}
}

function readRecoveryOwnerClaim(directory: string): OwnerClaim | undefined {
	const ownerPath = join(directory, OWNER_FILE_NAME);
	if (!pathStatus(ownerPath)) return undefined;
	const fileDescriptor = openSync(ownerPath, constants.O_RDONLY | constants.O_NOFOLLOW);
	try {
		assertPrivateRegularFile(fileDescriptor, ownerPath);
		const status = fstatSync(fileDescriptor);
		if (status.size <= 0 || status.size > 4096) throw new Error("writer ownership claim is malformed");
		const content = Buffer.alloc(status.size);
		readFully(fileDescriptor, content, 0);
		return parseOwnerClaim(parseJson(content, "writer ownership claim"));
	} finally {
		closeSync(fileDescriptor);
	}
}

function recoveryOwnerSnapshot(
	directory: string,
	isOwnerAlive: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean,
	maxEntries: number,
	maxCatalogBytes: number,
): { snapshot: string; entries: number; catalogBytes: number } {
	const root = opendirSync(directory);
	let entries = 0;
	let catalogBytes = 0;
	try {
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
	} finally {
		root.closeSync();
	}
	const claim = readRecoveryOwnerClaim(directory);
	if (!claim) return { snapshot: "absent", entries, catalogBytes };
	if (isOwnerAlive(claim)) throw new Error("incident recorder segment store is already owned by a live writer");
	return { snapshot: JSON.stringify(claim), entries, catalogBytes };
}

function recoveryOwnerFingerprint(
	directory: string,
	isOwnerAlive: (identity: IncidentRecorderSegmentOwnerIdentity) => boolean,
): string {
	const claim = readRecoveryOwnerClaim(directory);
	if (!claim) return "absent";
	if (isOwnerAlive(claim)) throw new Error("incident recorder segment store is already owned by a live writer");
	return JSON.stringify(claim);
}

function readAndVerifyRecoveryIndex(summary: SegmentSummary): SegmentIndexDocument {
	const fileDescriptor = openSync(summary.path, constants.O_RDONLY | constants.O_NOFOLLOW);
	try {
		assertPrivateRegularFile(fileDescriptor, summary.path);
		const status = fstatSync(fileDescriptor);
		if (status.size !== summary.fileBytes) throw new InvalidFrameError("sealed segment size changed during recovery prune");
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
			...index.records.map((entry) => ({ kind: "record" as const, ordinal: entry.ordinal, offset: entry.offset, entry })),
			...index.recoveryGaps.map((gap) => ({ kind: "gap" as const, ordinal: gap.ordinal, offset: gap.invalidOffset, gap })),
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
		return index;
	} finally {
		closeSync(fileDescriptor);
	}
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
	const recoveryStoreInstanceId = "recovery:" + sha256(Buffer.from(options.directory, "utf8"));
	const pruneFilterSha256 = sha256(
		Buffer.from(
			canonicalJson({
				sealedBeforeMs: options.sealedBeforeMs,
				protectionGeneration: protection.generation,
				protectionFingerprint: protection.fingerprint,
				protectedRunIds: protection.protectedRunIds,
				protectedSegmentIds: protectedSegments.sorted,
			}),
			"utf8",
		),
	);
	if (options.continuation) {
		if (options.continuation.version !== 1) throw new Error("prune continuation version is unsupported");
		assertSafeNonNegativeInteger(options.continuation.segmentSequence, "prune continuation segment sequence");
		if (
			options.continuation.storeInstanceId !== recoveryStoreInstanceId ||
			options.continuation.filterSha256 !== pruneFilterSha256
		) {
			throw new Error("prune continuation is stale or does not match its frozen arguments");
		}
	}
	const rootStatus = lstatSync(options.directory);
	if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) throw new Error("recovery root is not a directory");
	const sealedDirectory = join(options.directory, "sealed");
	const sealedStatus = lstatSync(sealedDirectory);
	if (!sealedStatus.isDirectory() || sealedStatus.isSymbolicLink()) throw new Error("sealed recovery path is not a directory");
	const isOwnerAlive = options.isOwnerAlive ?? defaultIsOwnerAlive;
	const ownerScan = recoveryOwnerSnapshot(options.directory, isOwnerAlive, maxEntries, maxCatalogBytes);
	const ownerSnapshot = ownerScan.snapshot;
	const summaries: SegmentSummary[] = [];
	const result: IncidentRecorderSegmentPruneResult = {
		deletedSegmentIds: [],
		corruptSegmentIds: [],
		examinedSegments: 0,
		deletedBytes: 0,
		locatorsInvalidated: false,
		requiresFullReconciliation: false,
		moreWork: false,
	};
	let entries = ownerScan.entries;
	let catalogBytes = ownerScan.catalogBytes;
	const directory = opendirSync(sealedDirectory);
	try {
		for (;;) {
			const entry = directory.readSync();
			if (!entry) break;
			entries += 1;
			catalogBytes += Buffer.byteLength(entry.name, "utf8") + 256;
			if (entries > maxEntries) throw new Error("segment directory exceeds maxStartupEntries");
			if (catalogBytes > maxCatalogBytes) throw new Error("segment catalog exceeds maxStartupCatalogBytes");
			if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.segment$/.test(entry.name)) continue;
			const path = join(sealedDirectory, entry.name);
			try {
				const summary = readRecoverySealedSummary(path);
				catalogBytes +=
					Buffer.byteLength(path, "utf8") + encodeJson(summary.header).byteLength + encodeJson(summary.footer).byteLength + 384;
				if (catalogBytes > maxCatalogBytes) throw new Error("segment catalog exceeds maxStartupCatalogBytes");
				summaries.push(summary);
			} catch {
				result.corruptSegmentIds.push(entry.name.slice(0, -".segment".length));
			}
		}
	} finally {
		directory.closeSync();
	}
	summaries.sort((left, right) => left.header.segmentSequence - right.header.segmentSequence);
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
		sessionId: options.continuation?.sessionId ?? randomUUID(),
		storeInstanceId: recoveryStoreInstanceId,
		highWaterSegmentSequence: options.continuation?.highWaterSegmentSequence ?? availableHighWater,
		filterSha256: pruneFilterSha256,
	};
	const continuationFor = (segmentSequence: number): IncidentRecorderSegmentPruneCursor => ({
		version: 1,
		...pruneSession,
		segmentSequence,
	});
	const candidates = summaries.filter(
		(summary) =>
			summary.footer.sealedAtMs < options.sealedBeforeMs &&
			summary.header.segmentSequence <= pruneSession.highWaterSegmentSequence &&
			(!options.continuation || summary.header.segmentSequence > options.continuation.segmentSequence),
	);
	let examinedBytes = 0;
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
			break;
		}
		result.examinedSegments += 1;
		examinedBytes += summary.fileBytes;
		result.continuation = continuationFor(summary.header.segmentSequence);
		let index: SegmentIndexDocument;
		try {
			index = readAndVerifyRecoveryIndex(summary);
		} catch {
			result.corruptSegmentIds.push(summary.header.segmentId);
			continue;
		}
		if (index.records.some((entry) => protectedRunIds.has(entry.runId))) continue;
		options.onOwnershipTransitionCheck?.();
		if (recoveryOwnerFingerprint(options.directory, isOwnerAlive) !== ownerSnapshot) {
			throw new Error("writer ownership changed during recovery pruning");
		}
		unlinkSync(summary.path);
		syncDirectory(sealedDirectory);
		options.onOwnershipTransitionCheck?.();
		if (recoveryOwnerFingerprint(options.directory, isOwnerAlive) !== ownerSnapshot) {
			throw new Error("writer ownership changed during recovery pruning");
		}
		result.deletedSegmentIds.push(summary.header.segmentId);
		result.deletedBytes += summary.fileBytes;
		result.locatorsInvalidated = true;
		result.requiresFullReconciliation = true;
	}
	if (!result.moreWork) delete result.continuation;
	return result;
}
