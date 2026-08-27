import { spawn } from "node:child_process";
import { createHash, type Hash } from "node:crypto";
import {
	type BigIntStats,
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
	readFileSync,
	readSync,
	renameSync,
	rmSync,
	statfsSync,
	statSync,
	utimesSync,
	writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { acquireIncidentCasTransaction } from "./incident-recorder-cas-transaction.js";
import {
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
	type IncidentRecorderFrameHeader,
	validateIncidentRecorderFrameFlags,
} from "./incident-recorder-protocol.js";
import { INCIDENT_DIAGNOSTIC_RETENTION_MS } from "./incident-recorder-retention.js";
import {
	INCIDENT_RECORDER_JOURNAL_IDENTIFIER,
	INCIDENT_RECORDER_JOURNAL_NAMESPACE,
	type IncidentJournalLine,
} from "./incident-recorder-writer.js";

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
const STORAGE_DISCOVERY_ENTRY_BUDGET = 512;
const STORAGE_DISCOVERY_SLICE_MS = 4;
const STORAGE_DISCOVERY_MAX_DEPTH = 64;
const INCIDENT_DISCOVERY_BATCH_COUNT = 64;
const SYSDIG_RING_DEFAULT_BASE_PATH = "/var/log/grimoire/sysdig/ring.scap";
const SYSDIG_RING_EXPECTED_SEGMENTS = 12;
const SYSDIG_RING_ROTATION_BYTES = 320 * 1024 * 1024;
const SYSDIG_PIN_MAX_DISCOVERY_ENTRIES = 256;
const SYSDIG_DISCOVERY_BATCH_COUNT = 64;
const SYSDIG_PIN_MAX_SEGMENTS = 32;
const SYSDIG_PIN_MAX_SEGMENT_BYTES = 384 * 1024 * 1024;
const SYSDIG_PIN_MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024;
const SYSDIG_PIN_COPY_BUFFER_BYTES = 1024 * 1024;
const SYSDIG_PIN_RETENTION_MS = INCIDENT_DIAGNOSTIC_RETENTION_MS;

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
	request: { runId: string; fromWallTimeMs: number; throughWallTimeMs: number };
	scannedCursors: Set<string>;
	directory?: ReturnType<typeof opendirSync>;
	matches: Array<{
		occurrenceReference: string;
		cursors: string[];
		cas: { digest: string; bytes: number; path: string };
		eventWallTimeMs: string;
	}>;
	memoryBytes: number;
	phase: "reading" | "linking";
	linkIndex: number;
	linked: Map<string, string>;
	pinCasDir?: string;
}

interface JournalManifestOccurrence {
	occurrenceReference: string;
	cursors: string[];
	cas: { digest: string; bytes: number; path: string };
	eventWallTimeMs: string;
	pinnedCasPath: string;
}

interface JournalManifestValidation {
	incidentDir: string;
	manifestPath: string;
	descriptor: number;
	runId: string;
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
	textBuffer: string;
	objectText: string;
	objectDepth: number;
	objectInString: boolean;
	objectEscape: boolean;
	fileEnded: boolean;
	occurrenceCount: number;
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
	};
	verifiedPins: Map<string, { bytes: number; pinnedPath: string; dev: number; ino: number }>;
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
}

interface SysdigPinnedSegmentRecord {
	version: 1;
	id: string;
	sourcePath: string;
	sourceName: string;
	observedAtWallTimeMs: number;
	phase: "initial" | "rotated" | "final";
	source: { dev: string; ino: string; bytes: number; mtimeMs: number };
	pinnedPath: string;
	storageOwnerPath?: string;
	captureMethod: "hard_link" | "bounded_copy";
	captureReason: "closed_segment_hard_link" | "active_segment_snapshot" | "hard_link_unavailable";
	hardLinkErrorCode?: string;
	bytesAtCapture: number;
	sha256AtCapture?: string;
}

interface SysdigRingCandidate {
	path: string;
	metadata: BigIntStats;
}

interface SysdigRingDiscovery {
	incidentDir: string;
	request: SysdigPinRequest;
	phase: "initial" | "rotated" | "final";
	observedAtWallTimeMs: number;
	directory: Dir;
	ringName: string;
	candidates: SysdigRingCandidate[];
	candidateCount: number;
	issues: string[];
	issuesTruncated: boolean;
}

interface SysdigDiscoveryResult {
	complete: boolean;
	issues: string[];
}

interface SysdigPinRecordState {
	records: SysdigPinnedSegmentRecord[];
	recordFileCount: number;
	totalBytes: number;
	saturated: boolean;
	issues: string[];
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

interface StorageTopologySignature {
	dev: bigint;
	ino: bigint;
	mode: bigint;
	nlink: bigint;
	size: bigint;
	blocks: bigint;
	mtimeNs: bigint;
	ctimeNs: bigint;
}

interface StorageDiscoveryFrame {
	directory: Dir;
	path: string;
	depth: number;
	topology: StorageTopologySignature;
}

interface StorageDiscoveryPassSummary {
	bytes: number;
	entries: number;
	fingerprint: bigint;
}

interface StorageDiscovery {
	roots: readonly string[];
	rootIndex: number;
	stack: StorageDiscoveryFrame[];
	entries: number;
	lastSliceEntries: number;
	pass: 0 | 1;
	passBytes: number;
	passEntries: number;
	passFingerprint: bigint;
	baseline?: StorageDiscoveryPassSummary;
	complete: boolean;
	error?: string;
}

type RetainedDirectoryKind = "storage-discovery" | "incident-discovery" | "sysdig-discovery" | "pin-traversal";
type RetainedDescriptorKind = "journal-manifest" | "journal-pin" | "stopped-source" | "stopped-target";
export type IncidentRecorderCompactorRetainedResource =
	| { resource: "directory"; kind: RetainedDirectoryKind; path: string }
	| { resource: "descriptor"; kind: RetainedDescriptorKind; path: string };

export interface IncidentRecorderCompactorSurvivalSnapshot {
	pendingEntries: number;
	pendingEntryBytes: number;
	assemblies: number;
	assemblyBytes: number;
	wrapperSequenceKeys: number;
	producerSequenceKeys: number;
	accountedStorageBytes: number;
	reservedStorageBytes: number;
	storageDiscoveryEntries: number;
	storageDiscoverySliceEntries: number;
	storageDiscoveryDepth: number;
	storageDiscoveryRetainedPaths: number;
	storageDiscoveryPass: 0 | 1;
	storageDiscoveryComplete: boolean;
	incidentDiscoverySliceEntries: number;
	sysdigDiscoverySliceEntries: number;
	sysdigDiscoveryCandidates: number;
	retainedDirectories: number;
	retainedFileDescriptors: number;
	disposed: boolean;
	storageDiscoveryError?: string;
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

function sha256(value: Uint8Array | string): string {
	return createHash("sha256").update(value).digest("hex");
}

function sha256FileBounded(path: string, expectedBytes: number): string {
	if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 0 || expectedBytes > SYSDIG_PIN_MAX_SEGMENT_BYTES) {
		throw new Error("Sysdig pin hash input exceeds its byte bound");
	}
	const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
	const hash = createHash("sha256");
	const buffer = Buffer.allocUnsafe(SYSDIG_PIN_COPY_BUFFER_BYTES);
	let offset = 0;
	try {
		const before = fstatSync(descriptor, { bigint: true });
		if (!before.isFile() || Number(before.size) !== expectedBytes)
			throw new Error("Sysdig pinned segment changed before hashing");
		while (offset < expectedBytes) {
			const count = readSync(descriptor, buffer, 0, Math.min(buffer.length, expectedBytes - offset), offset);
			if (count <= 0) throw new Error("Sysdig pinned segment ended before its recorded byte length");
			hash.update(buffer.subarray(0, count));
			offset += count;
		}
		if (readSync(descriptor, buffer, 0, 1, offset) !== 0)
			throw new Error("Sysdig pinned segment grew beyond its recorded byte length");
		const after = fstatSync(descriptor, { bigint: true });
		if (
			after.dev !== before.dev ||
			after.ino !== before.ino ||
			after.size !== before.size ||
			after.mtimeMs !== before.mtimeMs ||
			after.ctimeMs !== before.ctimeMs
		) {
			throw new Error("Sysdig pinned segment changed while hashing");
		}
		return hash.digest("hex");
	} finally {
		closeSync(descriptor);
	}
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

function writeImmutable(path: string, value: Buffer): boolean {
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
			return true;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			const existing = readFileSync(path);
			if (!existing.equals(value)) throw new Error(`Immutable incident reference collision at ${path}`);
			rmSync(temporary, { force: true });
			return false;
		}
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
		rmSync(temporary, { force: true });
	}
}

function linkVerified(source: string, target: string): void {
	try {
		linkSync(source, target);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
		const expected = lstatSync(source);
		const observed = lstatSync(target);
		if (
			!expected.isFile() ||
			expected.isSymbolicLink() ||
			!observed.isFile() ||
			observed.isSymbolicLink() ||
			expected.dev !== observed.dev ||
			expected.ino !== observed.ino
		) {
			throw new Error(`Existing immutable link did not match source inode at ${target}`);
		}
	}
}

function writeCheckpoint(path: string, value: CursorCheckpoint): void {
	const temporary = `${path}.tmp-${process.pid}`;
	let descriptor: number | undefined;
	try {
		descriptor = openSync(temporary, "w", 0o600);
		writeAll(descriptor, Buffer.from(`${JSON.stringify(value)}\n`, "utf8"));
		fsyncSync(descriptor);
		closeSync(descriptor);
		descriptor = undefined;
		renameSync(temporary, path);
		fsyncDirectory(dirname(path));
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

function isUnsigned64(value: unknown): value is string {
	if (typeof value !== "string" || !/^(?:0|[1-9]\d{0,19})$/.test(value)) return false;
	try {
		return BigInt(value) <= (1n << 64n) - 1n;
	} catch {
		return false;
	}
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
			reason: "work_budget" | "storage_paused" | "cas_transaction_busy";
			copiedBytes: number;
			totalBytes: number;
	  }
	| { state: "complete"; artifact: StoppedTargetArtifactReference }
	| { state: "error"; reason: string };

interface StoppedStorageReservation {
	reservationBytes: number;
}

interface StoppedTargetArtifactStream extends StoppedStorageReservation {
	sourcePath: string;
	encoding: string;
	source: number;
	target: number;
	temporary: string;
	dev: bigint;
	ino: bigint;
	mtimeMs: number;
	ctimeMs: number;
	totalBytes: number;
	copiedBytes: number;
	hash: Hash;
	error?: string;
}

function allocatedStorageBytes(stat: { size: number | bigint; blocks?: number | bigint }): number {
	const size = Number(stat.size);
	const blocks = stat.blocks === undefined ? 0 : Number(stat.blocks);
	if (!Number.isSafeInteger(size) || size < 0 || !Number.isSafeInteger(blocks) || blocks < 0) {
		throw new Error("Incident compactor storage metadata exceeds its numeric bound");
	}
	return Math.max(size, blocks * 512);
}

function storageTopologySignature(stat: BigIntStats): StorageTopologySignature {
	return {
		dev: stat.dev,
		ino: stat.ino,
		mode: stat.mode,
		nlink: stat.nlink,
		size: stat.size,
		blocks: stat.blocks,
		mtimeNs: stat.mtimeNs,
		ctimeNs: stat.ctimeNs,
	};
}

function sameStorageTopology(left: StorageTopologySignature, right: StorageTopologySignature): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.mode === right.mode &&
		left.nlink === right.nlink &&
		left.size === right.size &&
		left.blocks === right.blocks &&
		left.mtimeNs === right.mtimeNs &&
		left.ctimeNs === right.ctimeNs
	);
}

function storageFingerprint(path: string, stat?: BigIntStats): bigint {
	const identity = stat
		? [path, stat.dev, stat.ino, stat.mode, stat.nlink, stat.size, stat.blocks, stat.mtimeNs, stat.ctimeNs].join("\0")
		: `${path}\0missing`;
	return BigInt(`0x${sha256(identity)}`);
}

function relativeDescendant(root: string, path: string): string | undefined {
	const value = relative(resolve(root), resolve(path));
	if (value === "") return "";
	if (value === ".." || value.startsWith(`..${sep}`) || isAbsolute(value)) return undefined;
	return value.split(sep).join("/");
}

function readDirectoryBounded(path: string, maximumEntries: number): { entries: Dirent[]; overflow: boolean } {
	const directory = opendirSync(path);
	const entries: Dirent[] = [];
	let overflow = false;
	try {
		for (let index = 0; index <= maximumEntries; index += 1) {
			const entry = directory.readSync();
			if (!entry) break;
			if (entries.length === maximumEntries) {
				overflow = true;
				break;
			}
			entries.push(entry);
		}
	} finally {
		try {
			directory.closeSync();
		} catch {}
	}
	return { entries, overflow };
}

export interface IncidentRecorderCompactorOptions {
	agentDir: string;
	journalctlPath?: string;
	storageByteCeiling?: number;
	freeReserveBytes?: number;
	/** Test/packaging override only. Production uses the stock root-owned Sysdig ring. */
	sysdigRingBasePath?: string;
	/** Test-only deterministic storage-topology mutation seam. */
	storageDiscoveryEntryHook?: (path: string, canonicalPath: string | undefined) => void;
	/** Test-only retained-resource observation and read-failure seam. */
	resourceLifecycleHooks?: {
		observe?: (event: IncidentRecorderCompactorRetainedResource & { action: "open" | "close" }) => void;
		beforeRead?: (resource: IncidentRecorderCompactorRetainedResource) => void;
	};
}

export class IncidentRecorderCompactor {
	private readonly root: string;
	private readonly checkpointPath: string;
	private readonly wrapperSequences = new Map<string, bigint>();
	private readonly producerSequences = new Map<string, bigint>();
	private checkpoint?: CursorCheckpoint;
	private readonly assemblies = new Map<string, Assembly>();
	private assemblyBytes = 0;
	private readonly pendingEntries: JournalRecordReference[] = [];
	private pendingEntryHead = 0;
	private pendingEntryBytes = 0;
	private pausedUntilMs = 0;
	private storageBytes = 0;
	private outstandingStorageReservationBytes = 0;
	private readonly storageDiscovery: StorageDiscovery;
	private incidentDiscovery?: Dir;
	private incidentDiscoverySliceEntries = 0;
	private sysdigRingDiscovery?: SysdigRingDiscovery;
	private sysdigDiscoverySliceEntries = 0;
	private readonly activePinScans = new Map<string, () => void>();
	private activePinTraversal?: PinTraversal;
	private journalManifestValidation?: JournalManifestValidation;
	private readonly stoppedTargetStreams = new Map<string, StoppedTargetArtifactStream>();
	private readonly retainedDirectories = new Map<Dir, { kind: RetainedDirectoryKind; path: string }>();
	private readonly retainedDescriptors = new Map<number, { kind: RetainedDescriptorKind; path: string }>();
	private readonly disposalWaiters = new Set<() => void>();
	private activeReaderTermination?: () => void;
	private disposed = false;

	constructor(private readonly options: IncidentRecorderCompactorOptions) {
		this.root = join(options.agentDir, "incident-recorder");
		this.checkpointPath = join(this.root, "compactor-cursor.json");
		this.storageDiscovery = {
			roots: [this.root, join(this.options.agentDir, "incidents")],
			rootIndex: 0,
			stack: [],
			entries: 0,
			lastSliceEntries: 0,
			pass: 0,
			passBytes: 0,
			passEntries: 0,
			passFingerprint: 0n,
			complete: false,
		};
		this.advanceStorageDiscovery();
		try {
			const parsed = JSON.parse(readFileSync(this.checkpointPath, "utf8")) as CursorCheckpoint;
			if (parsed.version === 1 && typeof parsed.cursor === "string") {
				this.checkpoint = parsed;
				for (const key of Object.getOwnPropertyNames(parsed.wrapperSequences ?? {}))
					this.wrapperSequences.set(key, BigInt(parsed.wrapperSequences[key]));
				for (const key of Object.getOwnPropertyNames(parsed.producerSequences ?? {}))
					this.producerSequences.set(key, BigInt(parsed.producerSequences[key]));
			}
		} catch {}
	}

	private disposedError(): Error {
		return new Error("Incident recorder compactor is disposed");
	}

	private assertActive(): void {
		if (this.disposed) throw this.disposedError();
	}

	private observeResource(resource: IncidentRecorderCompactorRetainedResource, action: "open" | "close"): void {
		try {
			this.options.resourceLifecycleHooks?.observe?.({ ...resource, action });
		} catch {}
	}

	private openRetainedDirectory(path: string, kind: RetainedDirectoryKind): Dir {
		this.assertActive();
		const directory = opendirSync(path);
		const resource = { resource: "directory" as const, kind, path };
		this.retainedDirectories.set(directory, { kind, path });
		this.observeResource(resource, "open");
		return directory;
	}

	private readRetainedDirectory(directory: Dir): Dirent | null {
		const retained = this.retainedDirectories.get(directory);
		if (!retained) throw new Error("Incident recorder compactor directory is not retained");
		this.options.resourceLifecycleHooks?.beforeRead?.({ resource: "directory", ...retained });
		return directory.readSync();
	}

	private closeRetainedDirectory(directory: Dir): boolean {
		const retained = this.retainedDirectories.get(directory);
		if (!retained) return true;
		this.retainedDirectories.delete(directory);
		let closed = true;
		try {
			directory.closeSync();
		} catch {
			closed = false;
		} finally {
			this.observeResource({ resource: "directory", ...retained }, "close");
		}
		return closed;
	}

	private retainDescriptor(descriptor: number, path: string, kind: RetainedDescriptorKind): number {
		this.assertActive();
		const resource = { resource: "descriptor" as const, kind, path };
		this.retainedDescriptors.set(descriptor, { kind, path });
		this.observeResource(resource, "open");
		return descriptor;
	}

	private openRetainedDescriptor(path: string, flags: number, kind: RetainedDescriptorKind): number {
		this.assertActive();
		return this.retainDescriptor(openSync(path, flags), path, kind);
	}

	private beforeRetainedDescriptorRead(descriptor: number): void {
		const retained = this.retainedDescriptors.get(descriptor);
		if (!retained) throw new Error("Incident recorder compactor file descriptor is not retained");
		this.options.resourceLifecycleHooks?.beforeRead?.({ resource: "descriptor", ...retained });
	}

	private closeRetainedDescriptor(descriptor: number): void {
		const retained = this.retainedDescriptors.get(descriptor);
		if (!retained) return;
		this.retainedDescriptors.delete(descriptor);
		try {
			closeSync(descriptor);
		} catch {
		} finally {
			this.observeResource({ resource: "descriptor", ...retained }, "close");
		}
	}

	private async waitForWorkDelay(delayMs: number): Promise<void> {
		this.assertActive();
		await new Promise<void>((resolveDelay) => {
			let timer: ReturnType<typeof setTimeout> | undefined;
			const wake = (): void => {
				if (timer) clearTimeout(timer);
				this.disposalWaiters.delete(wake);
				resolveDelay();
			};
			this.disposalWaiters.add(wake);
			timer = setTimeout(wake, Math.max(0, delayMs));
		});
		this.assertActive();
	}

	/** Explicit bounded shutdown for retained scan, validation, and stream resources. */
	dispose(): void {
		if (this.disposed) return;
		this.disposed = true;
		for (const wake of [...this.disposalWaiters]) wake();
		this.disposalWaiters.clear();
		const terminateReader = this.activeReaderTermination;
		this.activeReaderTermination = undefined;
		terminateReader?.();
		for (const terminate of [...this.activePinScans.values()]) terminate();
		this.activePinScans.clear();
		for (const directory of [...this.retainedDirectories.keys()]) this.closeRetainedDirectory(directory);
		for (const descriptor of [...this.retainedDescriptors.keys()]) this.closeRetainedDescriptor(descriptor);
		this.storageDiscovery.stack.splice(0);
		this.storageDiscovery.error ??= "compactor_disposed";
		this.incidentDiscovery = undefined;
		if (this.sysdigRingDiscovery) {
			this.sysdigRingDiscovery.candidates.length = 0;
			this.sysdigRingDiscovery.issues.length = 0;
		}
		this.sysdigRingDiscovery = undefined;
		if (this.activePinTraversal) {
			this.activePinTraversal.directory = undefined;
			this.activePinTraversal.matches.length = 0;
			this.activePinTraversal.linked.clear();
			this.activePinTraversal.scannedCursors.clear();
		}
		this.activePinTraversal = undefined;
		if (this.journalManifestValidation) {
			this.journalManifestValidation.pinValidation?.hash.destroy();
			this.journalManifestValidation.pinValidation = undefined;
			this.journalManifestValidation.pendingOccurrence = undefined;
			this.journalManifestValidation.textBuffer = "";
			this.journalManifestValidation.objectText = "";
			this.journalManifestValidation.verifiedPins.clear();
		}
		this.journalManifestValidation = undefined;
		for (const state of this.stoppedTargetStreams.values()) {
			this.releaseStoppedStorageReservation(state);
			state.hash.destroy();
			try {
				rmSync(state.temporary, { force: true });
			} catch {}
		}
		this.stoppedTargetStreams.clear();
		for (const assembly of this.assemblies.values()) clearTimeout(assembly.timer);
		this.assemblies.clear();
		this.assemblyBytes = 0;
		this.pendingEntries.length = 0;
		this.pendingEntryHead = 0;
		this.pendingEntryBytes = 0;
	}

	private canonicalStoragePathForLink(path: string): string | undefined {
		const immutableTemporary = /^\.(.+)\.tmp-\d+(?:-[0-9a-f]{64})?$/.exec(basename(path));
		if (immutableTemporary?.[1]) return join(dirname(path), immutableTemporary[1]);
		const recorderRelative = relativeDescendant(this.root, path);
		if (recorderRelative !== undefined) {
			let match = /^cas\/sha256\/([0-9a-f]{2})\/([0-9a-f]{64})\.blob$/.exec(recorderRelative);
			if (match?.[1] && match[2] && match[1] === match[2].slice(0, 2)) return path;
			match = /^refs\/occurrences\/sha256\/([0-9a-f]{2})\/([0-9a-f]{64})\.json$/.exec(recorderRelative);
			if (match?.[1] && match[2] && match[1] === match[2].slice(0, 2)) return path;
			match = /^refs\/(?:gaps|incomplete)\/([0-9a-f]{64})\.json$/.exec(recorderRelative);
			if (match?.[1]) return path;
			match = /^sysdig-pins\/owners\/([0-9a-f]{64})\.scap$/.exec(recorderRelative);
			if (match?.[1]) return path;
			match = /^refs\/runs\/[0-9a-f]{64}\/cas-([0-9a-f]{64})\.blob$/.exec(recorderRelative);
			if (match?.[1]) {
				const digest = match[1];
				return join(this.root, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
			}
			match = /^refs\/runs\/[0-9a-f]{64}\/seq-\d{20}-([0-9a-f]{64})\.json$/.exec(recorderRelative);
			if (match?.[1]) {
				const id = match[1];
				return join(this.root, "refs", "occurrences", "sha256", id.slice(0, 2), `${id}.json`);
			}
			match = /^refs\/runs\/[0-9a-f]{64}\/seq-\d{20}-gap-([0-9a-f]{64})\.json$/.exec(recorderRelative);
			if (match?.[1]) return join(this.root, "refs", "gaps", `${match[1]}.json`);
			match = /^refs\/runs\/[0-9a-f]{64}\/seq-\d{20}-incomplete-([0-9a-f]{64})\.json$/.exec(recorderRelative);
			if (match?.[1]) return join(this.root, "refs", "incomplete", `${match[1]}.json`);
			return undefined;
		}
		const incidentRelative = relativeDescendant(join(this.options.agentDir, "incidents"), path);
		if (incidentRelative === undefined) return undefined;
		let match = /^[^/]+\/journal-pins\/cas\/([0-9a-f]{64})\.blob$/.exec(incidentRelative);
		if (match?.[1]) {
			const digest = match[1];
			return join(this.root, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
		}
		match = /^([^/]+)\/sysdig-pins\/segments\/([0-9a-f]{64})\.scap$/.exec(incidentRelative);
		if (!match?.[1] || !match[2]) return undefined;
		const recordPath = join(
			this.options.agentDir,
			"incidents",
			match[1],
			"sysdig-pins",
			"records",
			`${match[2]}.json`,
		);
		let record: SysdigPinnedSegmentRecord;
		try {
			const recordStat = lstatSync(recordPath);
			if (!recordStat.isFile() || recordStat.isSymbolicLink() || recordStat.size > 64 * 1024) {
				throw new Error("record_metadata_invalid");
			}
			record = JSON.parse(readFileSync(recordPath, "utf8")) as SysdigPinnedSegmentRecord;
		} catch {
			throw new Error("sysdig_hard_link_storage_owner_record_unavailable");
		}
		const storageOwnerPath = record.storageOwnerPath;
		const ownerRelative =
			typeof storageOwnerPath === "string" ? relativeDescendant(this.root, storageOwnerPath) : undefined;
		if (
			record.version !== 1 ||
			record.id !== match[2] ||
			record.pinnedPath !== path ||
			record.captureMethod !== "hard_link" ||
			typeof storageOwnerPath !== "string" ||
			typeof record.source?.dev !== "string" ||
			typeof record.source.ino !== "string" ||
			ownerRelative !== `sysdig-pins/owners/${record.id}.scap`
		) {
			throw new Error("sysdig_hard_link_storage_owner_record_invalid");
		}
		try {
			const owner = lstatSync(storageOwnerPath, { bigint: true });
			if (
				!owner.isFile() ||
				owner.isSymbolicLink() ||
				owner.dev.toString() !== record.source.dev ||
				owner.ino.toString() !== record.source.ino
			) {
				throw new Error("owner_identity_invalid");
			}
		} catch {
			throw new Error("sysdig_hard_link_storage_owner_record_invalid");
		}
		return storageOwnerPath;
	}

	private storagePathDisposition(
		path: string,
		stat: BigIntStats,
	): { account: boolean; canonicalPath: string | undefined } {
		if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink <= 1n) {
			this.options.storageDiscoveryEntryHook?.(path, undefined);
			return { account: true, canonicalPath: undefined };
		}
		const canonicalPath = this.canonicalStoragePathForLink(path);
		if (!canonicalPath) throw new Error("unclassified_hard_link_blocks_exact_storage_accounting");
		let canonical: BigIntStats;
		try {
			canonical = lstatSync(canonicalPath, { bigint: true });
		} catch {
			throw new Error("hard_link_canonical_storage_owner_unavailable");
		}
		if (
			!canonical.isFile() ||
			canonical.isSymbolicLink() ||
			canonical.dev !== stat.dev ||
			canonical.ino !== stat.ino
		) {
			throw new Error("hard_link_canonical_storage_owner_mismatch");
		}
		this.options.storageDiscoveryEntryHook?.(path, canonicalPath);
		return { account: resolve(canonicalPath) === resolve(path), canonicalPath };
	}

	private advanceStorageDiscovery(
		entryBudget = STORAGE_DISCOVERY_ENTRY_BUDGET,
		deadlineMs = Date.now() + STORAGE_DISCOVERY_SLICE_MS,
	): boolean {
		this.assertActive();
		const state = this.storageDiscovery;
		state.lastSliceEntries = 0;
		if (state.complete || state.error) return state.complete;
		let worked = 0;
		const fail = (reason: string): false => {
			state.error = reason;
			state.lastSliceEntries = worked;
			for (const frame of state.stack.splice(0)) this.closeRetainedDirectory(frame.directory);
			return false;
		};
		const observe = (path: string, stat: BigIntStats): boolean => {
			let disposition: ReturnType<IncidentRecorderCompactor["storagePathDisposition"]>;
			try {
				disposition = this.storagePathDisposition(path, stat);
			} catch (error) {
				fail(error instanceof Error ? error.message : String(error));
				return false;
			}
			state.passFingerprint ^= storageFingerprint(path, stat);
			state.passEntries += 1;
			state.entries += 1;
			worked += 1;
			if (disposition.account) state.passBytes += allocatedStorageBytes(stat);
			return true;
		};
		const finishPass = (): boolean => {
			const summary: StorageDiscoveryPassSummary = {
				bytes: state.passBytes,
				entries: state.passEntries,
				fingerprint: state.passFingerprint,
			};
			if (state.pass === 0) {
				state.baseline = summary;
				state.pass = 1;
				state.rootIndex = 0;
				state.passBytes = 0;
				state.passEntries = 0;
				state.passFingerprint = 0n;
				return false;
			}
			const baseline = state.baseline;
			if (
				!baseline ||
				baseline.bytes !== summary.bytes ||
				baseline.entries !== summary.entries ||
				baseline.fingerprint !== summary.fingerprint
			) {
				return fail("storage_discovery_topology_changed_between_passes");
			}
			this.storageBytes = summary.bytes;
			state.complete = true;
			state.lastSliceEntries = worked;
			return true;
		};
		while (worked < entryBudget && Date.now() <= deadlineMs) {
			if (state.stack.length === 0) {
				const root = state.roots[state.rootIndex++];
				if (!root) {
					if (finishPass()) return true;
					if (state.error) return false;
					continue;
				}
				let rootStat: BigIntStats;
				try {
					rootStat = lstatSync(root, { bigint: true });
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
						return fail("storage_discovery_root_metadata_unavailable");
					}
					state.passFingerprint ^= storageFingerprint(root);
					continue;
				}
				if (!observe(root, rootStat)) return false;
				if (!rootStat.isDirectory()) continue;
				if (rootStat.isSymbolicLink()) return fail("storage_discovery_symbolic_directory_rejected");
				let directory: Dir | undefined;
				let openedStat: BigIntStats;
				try {
					directory = this.openRetainedDirectory(root, "storage-discovery");
					openedStat = lstatSync(root, { bigint: true });
				} catch {
					if (directory) this.closeRetainedDirectory(directory);
					return fail("storage_discovery_directory_open_failed");
				}
				if (!sameStorageTopology(storageTopologySignature(rootStat), storageTopologySignature(openedStat))) {
					this.closeRetainedDirectory(directory);
					return fail("storage_discovery_directory_changed_before_open");
				}
				state.stack.push({
					directory,
					path: root,
					depth: 0,
					topology: storageTopologySignature(openedStat),
				});
			}
			const frame = state.stack.at(-1);
			if (!frame) continue;
			let entry: Dirent | null;
			try {
				entry = this.readRetainedDirectory(frame.directory);
			} catch {
				return fail("storage_discovery_directory_read_failed");
			}
			if (!entry) {
				let after: BigIntStats;
				try {
					after = lstatSync(frame.path, { bigint: true });
				} catch {
					return fail("storage_discovery_directory_disappeared_during_scan");
				}
				if (!sameStorageTopology(frame.topology, storageTopologySignature(after))) {
					return fail("storage_discovery_directory_changed_during_scan");
				}
				if (!this.closeRetainedDirectory(frame.directory)) {
					return fail("storage_discovery_directory_close_failed");
				}
				state.stack.pop();
				continue;
			}
			const path = join(frame.path, entry.name);
			let stat: BigIntStats;
			try {
				stat = lstatSync(path, { bigint: true });
			} catch {
				return fail("storage_discovery_entry_disappeared_during_scan");
			}
			if (!observe(path, stat)) return false;
			if (!stat.isDirectory()) continue;
			if (stat.isSymbolicLink()) return fail("storage_discovery_symbolic_directory_rejected");
			if (frame.depth + 1 > STORAGE_DISCOVERY_MAX_DEPTH) return fail("storage_discovery_depth_bound_exceeded");
			let directory: Dir | undefined;
			let openedStat: BigIntStats;
			try {
				directory = this.openRetainedDirectory(path, "storage-discovery");
				openedStat = lstatSync(path, { bigint: true });
			} catch {
				if (directory) this.closeRetainedDirectory(directory);
				return fail("storage_discovery_directory_open_failed");
			}
			if (!sameStorageTopology(storageTopologySignature(stat), storageTopologySignature(openedStat))) {
				this.closeRetainedDirectory(directory);
				return fail("storage_discovery_directory_changed_before_open");
			}
			state.stack.push({
				directory,
				path,
				depth: frame.depth + 1,
				topology: storageTopologySignature(openedStat),
			});
		}
		state.lastSliceEntries = worked;
		return false;
	}

	private ownedStorageRoot(path: string): string | undefined {
		for (const root of this.storageDiscovery.roots) if (relativeDescendant(root, path) !== undefined) return root;
		return undefined;
	}

	private directoryMutationReservation(path: string, entries = 1): number {
		const filesystem = statfsSync(existsSync(path) ? path : this.existingStorageStatPath());
		const blockSize = Number(filesystem.bsize);
		if (!Number.isSafeInteger(blockSize) || blockSize <= 0) {
			throw new Error("Incident compactor filesystem block size is invalid");
		}
		return Math.max(64 * 1024, blockSize * (entries + 1));
	}

	private ensureOwnedDirectory(path: string, stoppedReservation?: StoppedStorageReservation): void {
		const target = resolve(path);
		const ownedRoot = this.ownedStorageRoot(target);
		if (!ownedRoot) throw new Error("Incident compactor directory escaped its accounted storage roots");
		const descendant = relativeDescendant(ownedRoot, target);
		if (descendant === undefined) throw new Error("Incident compactor directory containment changed");
		const names = [basename(ownedRoot), ...(descendant ? descendant.split("/") : [])];
		let current = dirname(ownedRoot);
		for (const name of names) {
			const parent = current;
			current = join(current, name);
			try {
				const existing = lstatSync(current, { bigint: true });
				if (!existing.isDirectory() || existing.isSymbolicLink()) {
					throw new Error("Incident compactor owned directory path is not a private directory");
				}
				continue;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			}
			const parentOwned = this.ownedStorageRoot(parent) !== undefined;
			const parentBefore = parentOwned ? allocatedStorageBytes(lstatSync(parent, { bigint: true })) : 0;
			this.ensureDiskAdmission(this.directoryMutationReservation(parent), stoppedReservation?.reservationBytes ?? 0);
			try {
				mkdirSync(current, { mode: 0o700 });
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "EEXIST") {
					throw new Error("Incident compactor owned directory topology changed during creation");
				}
				throw error;
			}
			const created = lstatSync(current, { bigint: true });
			if (!created.isDirectory() || created.isSymbolicLink()) {
				throw new Error("Incident compactor created directory identity is invalid");
			}
			let accountedGrowth = allocatedStorageBytes(created);
			if (parentOwned) {
				const parentAfter = allocatedStorageBytes(lstatSync(parent, { bigint: true }));
				accountedGrowth += Math.max(0, parentAfter - parentBefore);
			}
			if (stoppedReservation) this.consumeStoppedStorageReservation(stoppedReservation, accountedGrowth);
			else this.storageBytes += accountedGrowth;
		}
	}

	private withOwnedDirectoryMutation<T>(
		directory: string,
		entryWorstCase: number,
		operation: () => T,
		stoppedReservation?: StoppedStorageReservation,
	): T {
		this.ensureOwnedDirectory(directory, stoppedReservation);
		const before = allocatedStorageBytes(lstatSync(directory, { bigint: true }));
		this.ensureDiskAdmission(
			this.directoryMutationReservation(directory, entryWorstCase),
			stoppedReservation?.reservationBytes ?? 0,
		);
		try {
			return operation();
		} finally {
			const after = allocatedStorageBytes(lstatSync(directory, { bigint: true }));
			const accountedGrowth = Math.max(0, after - before);
			if (stoppedReservation) this.consumeStoppedStorageReservation(stoppedReservation, accountedGrowth);
			else this.storageBytes += accountedGrowth;
		}
	}

	private existingStorageStatPath(): string {
		let statPath = this.root;
		while (!existsSync(statPath)) {
			const parent = dirname(statPath);
			if (parent === statPath) throw new Error("Incident compactor storage filesystem is unavailable");
			statPath = parent;
		}
		return statPath;
	}

	private stoppedArtifactStorageReservation(totalBytes: number): number {
		const statPath = this.existingStorageStatPath();
		const filesystem = statfsSync(statPath);
		const blockSize = Number(filesystem.bsize);
		if (!Number.isSafeInteger(blockSize) || blockSize <= 0)
			throw new Error("Incident compactor filesystem block size is invalid");
		const fileBytes = totalBytes === 0 ? 0 : Math.ceil(totalBytes / blockSize) * blockSize;
		// Staging, shard, and run-reference publication can create at most eight
		// directories and three entries. Thirty-two filesystem blocks cover each
		// new directory plus its parent growth, with room for allocation rounding.
		const topologyAndReferenceBytes = Math.max(256 * 1024, blockSize * 32);
		const reservation = fileBytes + topologyAndReferenceBytes;
		if (!Number.isSafeInteger(reservation))
			throw new Error("Incident compactor stopped artifact reservation exceeds its numeric bound");
		return reservation;
	}

	private acquireStoppedStorageReservation(totalBytes: number): StoppedStorageReservation {
		const reservationBytes = this.stoppedArtifactStorageReservation(totalBytes);
		this.ensureDiskAdmission(reservationBytes);
		this.outstandingStorageReservationBytes += reservationBytes;
		return { reservationBytes };
	}

	private consumeStoppedStorageReservation(reservation: StoppedStorageReservation, accountedBytes: number): void {
		if (!Number.isSafeInteger(accountedBytes) || accountedBytes < 0 || accountedBytes > reservation.reservationBytes)
			throw new Error("Incident compactor stopped artifact exceeded its storage reservation");
		reservation.reservationBytes -= accountedBytes;
		this.outstandingStorageReservationBytes -= accountedBytes;
		this.storageBytes += accountedBytes;
	}

	private releaseStoppedStorageReservation(reservation: StoppedStorageReservation): void {
		if (reservation.reservationBytes === 0) return;
		this.outstandingStorageReservationBytes -= reservation.reservationBytes;
		reservation.reservationBytes = 0;
	}

	private accountStoragePath(path: string): void {
		// Callers invoke this only after creating a new canonical file. Hard-link
		// publication does not call it because it allocates no new file blocks.
		this.storageBytes += allocatedStorageBytes(lstatSync(path, { bigint: true }));
	}

	private ensureDiskAdmission(worstCase: number, coveredReservation = 0): void {
		this.assertActive();
		if (
			!Number.isSafeInteger(worstCase) ||
			worstCase < 0 ||
			!Number.isSafeInteger(coveredReservation) ||
			coveredReservation < 0 ||
			coveredReservation > this.outstandingStorageReservationBytes
		)
			throw new Error("Invalid incident compactor disk reservation");
		if (!this.advanceStorageDiscovery()) {
			const error = new Error(
				this.storageDiscovery.error ?? "Incident compactor storage discovery remains in progress",
			) as NodeJS.ErrnoException;
			error.code = "EAGAIN";
			throw error;
		}
		if (coveredReservation === 0 && Date.now() < this.pausedUntilMs) {
			const error = new Error("Incident compactor remains paused by disk admission policy") as NodeJS.ErrnoException;
			error.code = "ENOSPC";
			throw error;
		}
		const ceiling = this.options.storageByteCeiling ?? 8 * 1024 ** 3;
		const reserve = this.options.freeReserveBytes ?? 10 * 1024 ** 3;
		const filesystem = statfsSync(this.existingStorageStatPath());
		const available = Number(filesystem.bavail) * Number(filesystem.bsize);
		const otherReservations = this.outstandingStorageReservationBytes - coveredReservation;
		if (
			available - otherReservations - worstCase < reserve ||
			this.storageBytes + otherReservations + worstCase > ceiling
		) {
			this.pausedUntilMs = Date.now() + 30_000;
			const error = new Error("Incident compactor paused by disk admission policy") as NodeJS.ErrnoException;
			error.code = "ENOSPC";
			throw error;
		}
	}

	private writeOwnedJson(path: string, value: unknown, extraWorstCase = 256 * 1024): void {
		const encoded = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
		this.ensureDiskAdmission(encoded.length + extraWorstCase);
		const created = this.withOwnedDirectoryMutation(dirname(path), 2, () => writeImmutable(path, encoded));
		if (created) this.accountStoragePath(path);
	}

	private writeOwnedCheckpoint(path: string, value: CursorCheckpoint): void {
		const encodedBytes = Buffer.byteLength(`${JSON.stringify(value)}\n`);
		this.ensureDiskAdmission(encodedBytes * 2 + 256 * 1024);
		let previousBytes = 0;
		try {
			previousBytes = allocatedStorageBytes(lstatSync(path, { bigint: true }));
		} catch {}
		this.withOwnedDirectoryMutation(dirname(path), 2, () => writeCheckpoint(path, value));
		this.storageBytes = Math.max(
			0,
			this.storageBytes - previousBytes + allocatedStorageBytes(lstatSync(path, { bigint: true })),
		);
	}

	private linkOwnedVerified(source: string, target: string): void {
		this.withOwnedDirectoryMutation(dirname(target), 1, () => linkVerified(source, target));
	}

	get diskPaused(): boolean {
		return this.disposed || Date.now() < this.pausedUntilMs;
	}
	get accountedStorageBytes(): number {
		return this.storageBytes;
	}

	get reservedStorageBytes(): number {
		return this.outstandingStorageReservationBytes;
	}

	/** @internal Bounded state used by isolated survival fixtures and diagnostics. */
	survivalSnapshot(): IncidentRecorderCompactorSurvivalSnapshot {
		return {
			pendingEntries: this.pendingEntries.length - this.pendingEntryHead,
			pendingEntryBytes: this.pendingEntryBytes,
			assemblies: this.assemblies.size,
			assemblyBytes: this.assemblyBytes,
			wrapperSequenceKeys: this.wrapperSequences.size,
			producerSequenceKeys: this.producerSequences.size,
			accountedStorageBytes: this.storageBytes,
			reservedStorageBytes: this.outstandingStorageReservationBytes,
			storageDiscoveryEntries: this.storageDiscovery.entries,
			storageDiscoverySliceEntries: this.storageDiscovery.lastSliceEntries,
			storageDiscoveryDepth: this.storageDiscovery.stack.length,
			storageDiscoveryRetainedPaths: this.storageDiscovery.roots.length + this.storageDiscovery.stack.length,
			storageDiscoveryPass: this.storageDiscovery.pass,
			storageDiscoveryComplete: this.storageDiscovery.complete,
			incidentDiscoverySliceEntries: this.incidentDiscoverySliceEntries,
			sysdigDiscoverySliceEntries: this.sysdigDiscoverySliceEntries,
			sysdigDiscoveryCandidates: this.sysdigRingDiscovery?.candidates.length ?? 0,
			retainedDirectories: this.retainedDirectories.size,
			retainedFileDescriptors: this.retainedDescriptors.size,
			disposed: this.disposed,
			...(this.storageDiscovery.error ? { storageDiscoveryError: this.storageDiscovery.error } : {}),
		};
	}

	/** @internal Advances one fixed storage-discovery slice without opening journalctl. */
	advanceBoundedDiscovery(): boolean {
		this.assertActive();
		return this.advanceStorageDiscovery();
	}

	admitObservation(worstCaseBytes = 256 * 1024): boolean {
		if (this.disposed || this.diskPaused) return false;
		try {
			this.ensureDiskAdmission(worstCaseBytes);
			return true;
		} catch (error) {
			if (["ENOSPC", "EAGAIN"].includes((error as NodeJS.ErrnoException).code ?? "")) return false;
			throw error;
		}
	}

	streamStoppedTargetArtifact(
		runId: string,
		sourcePath: string,
		encoding: string,
		work: { deadlineMs: number; byteBudget: number },
	): StoppedTargetArtifactAdmission {
		if (this.disposed) return { state: "error", reason: "compactor_disposed" };
		const key = sha256(`${runId}\0${sourcePath}\0${encoding}`);
		let state = this.stoppedTargetStreams.get(key);
		if (state?.error) return { state: "error", reason: state.error };
		if (!state) {
			if (this.stoppedTargetStreams.size >= 8)
				return { state: "pending", reason: "work_budget", copiedBytes: 0, totalBytes: 0 };
			if (this.diskPaused) return { state: "pending", reason: "storage_paused", copiedBytes: 0, totalBytes: 0 };
			let metadata: BigIntStats;
			try {
				metadata = lstatSync(sourcePath, { bigint: true });
			} catch (error) {
				return { state: "error", reason: error instanceof Error ? error.message : String(error) };
			}
			if (!metadata.isFile()) return { state: "error", reason: "artifact_source_not_regular_file" };
			const totalBytes = Number(metadata.size);
			if (!Number.isSafeInteger(totalBytes))
				return { state: "error", reason: "artifact_source_size_exceeds_numeric_bound" };
			let reservation: StoppedStorageReservation;
			try {
				reservation = this.acquireStoppedStorageReservation(totalBytes);
			} catch (error) {
				if (["ENOSPC", "EAGAIN"].includes((error as NodeJS.ErrnoException).code ?? ""))
					return { state: "pending", reason: "storage_paused", copiedBytes: 0, totalBytes };
				return { state: "error", reason: error instanceof Error ? error.message : String(error) };
			}
			const directory = join(this.root, "cas", "sha256", "staging");
			const temporary = join(directory, `${key}.tmp`);
			let source: number | undefined;
			let target: number | undefined;
			try {
				this.ensureOwnedDirectory(directory, reservation);
				try {
					rmSync(temporary, { force: true });
				} catch {}
				source = this.openRetainedDescriptor(
					sourcePath,
					fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
					"stopped-source",
				);
				const openedSource = fstatSync(source, { bigint: true });
				if (
					openedSource.dev !== metadata.dev ||
					openedSource.ino !== metadata.ino ||
					openedSource.size !== metadata.size ||
					openedSource.mtimeMs !== metadata.mtimeMs ||
					openedSource.ctimeMs !== metadata.ctimeMs
				)
					throw new Error("artifact_source_identity_changed_before_capture");
				target = this.withOwnedDirectoryMutation(
					directory,
					1,
					() => this.retainDescriptor(openSync(temporary, "wx", 0o600), temporary, "stopped-target"),
					reservation,
				);
				state = {
					sourcePath,
					encoding,
					source,
					target,
					temporary,
					dev: metadata.dev,
					ino: metadata.ino,
					mtimeMs: Number(metadata.mtimeMs),
					ctimeMs: Number(metadata.ctimeMs),
					totalBytes,
					copiedBytes: 0,
					hash: createHash("sha256"),
					reservationBytes: reservation.reservationBytes,
				};
				reservation.reservationBytes = 0;
				this.stoppedTargetStreams.set(key, state);
			} catch (error) {
				if (source !== undefined) this.closeRetainedDescriptor(source);
				if (target !== undefined) this.closeRetainedDescriptor(target);
				try {
					rmSync(temporary, { force: true });
				} catch {}
				this.releaseStoppedStorageReservation(reservation);
				return { state: "error", reason: error instanceof Error ? error.message : String(error) };
			}
		}
		let remaining = Math.max(0, Math.min(work.byteBudget, 4 * 1024 * 1024));
		const buffer = Buffer.allocUnsafe(64 * 1024);
		try {
			while (remaining > 0 && Date.now() < work.deadlineMs) {
				this.beforeRetainedDescriptorRead(state.source);
				const count = readSync(state.source, buffer, 0, Math.min(buffer.length, remaining), null);
				if (count === 0) {
					const transaction = acquireIncidentCasTransaction(this.root);
					if (!transaction)
						return {
							state: "pending",
							reason: "cas_transaction_busy",
							copiedBytes: state.copiedBytes,
							totalBytes: state.totalBytes,
						};
					try {
						const currentPath = lstatSync(state.sourcePath, { bigint: true });
						const currentFd = fstatSync(state.source, { bigint: true });
						if (
							currentFd.dev !== state.dev ||
							currentFd.ino !== state.ino ||
							currentPath.dev !== state.dev ||
							currentPath.ino !== state.ino ||
							Number(currentFd.size) !== state.totalBytes ||
							Number(currentFd.mtimeMs) !== state.mtimeMs ||
							Number(currentFd.ctimeMs) !== state.ctimeMs ||
							currentPath.size !== currentFd.size ||
							currentPath.mtimeMs !== currentFd.mtimeMs ||
							currentPath.ctimeMs !== currentFd.ctimeMs
						)
							throw new Error("artifact_source_changed_during_capture");
						fsyncSync(state.target);
						this.closeRetainedDescriptor(state.source);
						this.closeRetainedDescriptor(state.target);
						const digest = state.hash.digest("hex");
						const path = join(this.root, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
						this.ensureOwnedDirectory(dirname(path), state);
						let created = true;
						try {
							this.withOwnedDirectoryMutation(dirname(path), 1, () => linkSync(state.temporary, path), state);
						} catch (error) {
							const existing = lstatSync(path);
							if (
								(error as NodeJS.ErrnoException).code !== "EEXIST" ||
								!existing.isFile() ||
								existing.isSymbolicLink() ||
								existing.size !== state.totalBytes ||
								sha256FileBounded(path, state.totalBytes) !== digest
							)
								throw error;
							created = false;
						}
						if (created)
							this.consumeStoppedStorageReservation(
								state,
								allocatedStorageBytes(lstatSync(path, { bigint: true })),
							);
						rmSync(state.temporary, { force: true });
						const runLeaseDirectory = join(this.root, "refs", "runs", sha256(runId));
						this.ensureOwnedDirectory(runLeaseDirectory, state);
						utimesSync(path, new Date(), new Date());
						this.withOwnedDirectoryMutation(
							runLeaseDirectory,
							1,
							() => linkVerified(path, join(runLeaseDirectory, `cas-${digest}.blob`)),
							state,
						);
						fsyncDirectory(runLeaseDirectory);
						this.releaseStoppedStorageReservation(state);
						this.stoppedTargetStreams.delete(key);
						return {
							state: "complete",
							artifact: { algorithm: "sha256", digest, bytes: state.totalBytes, path, encoding },
						};
					} finally {
						transaction.release();
					}
				}
				state.hash.update(buffer.subarray(0, count));
				writeAll(state.target, buffer.subarray(0, count));
				state.copiedBytes += count;
				remaining -= count;
			}
			return {
				state: "pending",
				reason: "work_budget",
				copiedBytes: state.copiedBytes,
				totalBytes: state.totalBytes,
			};
		} catch (error) {
			state.error = error instanceof Error ? error.message : String(error);
			this.closeRetainedDescriptor(state.source);
			this.closeRetainedDescriptor(state.target);
			try {
				rmSync(state.temporary, { force: true });
			} catch {}
			state.hash.destroy();
			this.releaseStoppedStorageReservation(state);
			this.stoppedTargetStreams.delete(key);
			return { state: "error", reason: state.error };
		}
	}

	async run(): Promise<never> {
		this.assertActive();
		try {
			return await this.runLoop();
		} finally {
			this.dispose();
		}
	}

	private async runLoop(): Promise<never> {
		while (!this.advanceStorageDiscovery()) {
			if (this.storageDiscovery.error) throw new Error(this.storageDiscovery.error);
			await this.waitForWorkDelay(0);
		}
		this.ensureDiskAdmission(256 * 1024);
		this.ensureOwnedDirectory(this.root);
		for (;;) {
			this.assertActive();
			if (this.diskPaused) await this.waitForWorkDelay(Math.max(1, this.pausedUntilMs - Date.now()));
			const args = [
				`--namespace=${INCIDENT_RECORDER_JOURNAL_NAMESPACE}`,
				`--identifier=${INCIDENT_RECORDER_JOURNAL_IDENTIFIER}`,
				"--output=export",
				"--all",
				"--follow",
				"--no-tail",
			];
			if (this.checkpoint?.cursor) args.push(`--after-cursor=${this.checkpoint.cursor}`);
			const child = spawn(this.options.journalctlPath ?? "journalctl", args, { stdio: ["ignore", "pipe", "pipe"] });
			let readerKillTimer: ReturnType<typeof setTimeout> | undefined;
			const terminateReader = (): void => {
				try {
					child.kill("SIGTERM");
				} catch {}
				if (readerKillTimer) return;
				readerKillTimer = setTimeout(() => {
					try {
						if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
					} catch {}
				}, 250);
				readerKillTimer.unref();
			};
			this.activeReaderTermination = terminateReader;
			const parser = new JournalExportParser((fields) => {
				this.assertActive();
				this.acceptEntry(fields);
			});
			let parserError: Error | undefined;
			child.stdout?.on("data", (chunk: Buffer) => {
				try {
					parser.push(chunk);
				} catch (error) {
					parserError = error instanceof Error ? error : new Error(String(error));
					terminateReader();
				}
			});
			let stderr = "";
			child.stderr?.on("data", (chunk: Buffer) => {
				stderr = `${stderr}${chunk.toString("utf8")}`.slice(-4096);
			});
			const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null; error?: Error }>(
				(resolve) => {
					child.once("error", (error) => resolve({ code: null, signal: null, error }));
					child.once("close", (code, signal) => resolve({ code, signal }));
				},
			);
			if (readerKillTimer) clearTimeout(readerKillTimer);
			if (!result.error && this.activeReaderTermination === terminateReader)
				this.activeReaderTermination = undefined;
			this.assertActive();
			try {
				parser.finish();
			} catch (error) {
				parserError ??= error instanceof Error ? error : new Error(String(error));
			}
			this.flushAllIncomplete("journal_stream_disconnected_before_occurrence_completion");
			if (parserError) {
				const poison = parser.poisonFields();
				const poisonCursor = optionalText(poison, "__CURSOR");
				const poisonMachine = optionalText(poison, "_MACHINE_ID");
				const poisonBoot = optionalText(poison, "_BOOT_ID");
				const poisonInvocation = optionalText(poison, "_SYSTEMD_INVOCATION_ID");
				const poisonRealtime = optionalText(poison, "__REALTIME_TIMESTAMP");
				try {
					this.writeGap({
						reason: "journal_export_truncated_or_poisoned",
						cursor: poisonCursor,
						error: parserError.message,
					});
				} catch {}
				if ((parserError as NodeJS.ErrnoException).code === "ENOSPC" || this.diskPaused) continue;
				if (poisonCursor && poisonMachine && poisonBoot && poisonRealtime) {
					this.commitCursor(poisonCursor, poisonMachine, poisonBoot, poisonInvocation, poisonRealtime);
					continue;
				}
				throw parserError;
			}
			if (
				this.checkpoint?.cursor &&
				result.code !== 0 &&
				/(?:cursor[^\n]*(?:not found|invalid)|failed to seek[^\n]*cursor|cursor.*vacuum)/i.test(stderr)
			) {
				this.flushAllIncomplete("journal_cursor_removed_before_occurrence_completion");
				this.writeGap({
					reason: "journal_cursor_removed_or_unseekable",
					removedCursor: this.checkpoint.cursor,
					machineId: this.checkpoint.machineId,
					bootId: this.checkpoint.bootId,
					invocationId: this.checkpoint.invocationId,
					journalctl: stderr,
				});
				this.checkpoint = undefined;
				this.wrapperSequences.clear();
				this.producerSequences.clear();
				this.pendingEntries.length = 0;
				this.pendingEntryHead = 0;
				this.pendingEntryBytes = 0;
				rmSync(this.checkpointPath, { force: true });
				fsyncDirectory(dirname(this.checkpointPath));
				continue;
			}
			throw (
				result.error ??
				new Error(`Incident journal reader exited (${result.code ?? result.signal ?? "unknown"}): ${stderr}`)
			);
		}
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
				this.pendingEntries.length - this.pendingEntryHead >= PENDING_ENTRY_MAX_COUNT ||
				this.pendingEntryBytes + reference.memoryBytes > PENDING_ENTRY_MAX_BYTES
			) {
				this.flushOldestIncomplete("pending_cursor_frontier_capacity_flush");
			}
			this.pendingEntries.push(reference);
			this.pendingEntryBytes += reference.memoryBytes;
			if (
				this.pendingEntries.length - this.pendingEntryHead > PENDING_ENTRY_MAX_COUNT ||
				this.pendingEntryBytes > PENDING_ENTRY_MAX_BYTES
			) {
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
		const path = join(
			this.root,
			"refs",
			"journal",
			sha256(input.machineId).slice(0, 16),
			sha256(input.bootId).slice(0, 16),
			sha256(input.invocationId ?? "missing").slice(0, 16),
			`${id}.json`,
		);
		const reference: JournalRecordReference = {
			id,
			path,
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
		reference.bytes = Buffer.byteLength(`${JSON.stringify(persisted)}\n`);
		reference.memoryBytes = retainedBytes(reference);
		this.writeOwnedJson(path, persisted);
		return reference;
	}

	private previousPendingSequence(kind: "wrapper" | "producer", key: string): string | undefined {
		for (let index = this.pendingEntries.length - 1; index >= this.pendingEntryHead; index -= 1) {
			const updates = this.pendingEntries[index]?.sequenceUpdates;
			if (kind === "wrapper" && updates?.wrapperKey === key) return updates.wrapper;
			if (kind === "producer" && updates?.producerKey === key) return updates.producer;
		}
		return undefined;
	}

	private checkSequences(line: IncidentJournalLine, reference: JournalRecordReference): void {
		// A journal stream and its systemd-cat PID change on reconnect. Keep those
		// values on each immutable record, but continuity must follow the stable
		// wrapper/run identity so losses between stream generations remain visible.
		const continuityKey = `${reference.machineId}\0${reference.bootId}\0${reference.uid}\0${reference.identifier}\0${reference.transport}\0${line.runId}\0${line.runToken}\0${line.wrapperPid}\0${line.wrapperStartId ?? "missing"}`;
		const wrapperKey = `${continuityKey}\0wrapper`;
		const wrapper = BigInt(line.wrapperSequence);
		const previousPendingWrapper = this.previousPendingSequence("wrapper", wrapperKey);
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
		const previousPendingProducer = this.previousPendingSequence("producer", producerKey);
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
		for (const [key, candidate] of this.assemblies) {
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
		const transaction = acquireIncidentCasTransaction(this.root);
		if (!transaction) throw new Error("Incident CAS transaction unavailable");
		try {
			const value = Buffer.concat(assembly.chunks, assembly.bytes);
			if (value.length !== line.rawOccurrenceBytes || sha256(value) !== line.occurrenceSha256) {
				this.flushIncomplete(identity, "occurrence_checksum_or_length_mismatch");
				throw new Error("Occurrence checksum or length mismatch");
			}
			const casPath = this.writeCas(value, line.occurrenceSha256);
			const occurrenceId = sha256(`${line.runId}\0${line.runToken}\0${line.producerId}\0${line.occurrenceId}`);
			const occurrencePath = join(
				this.root,
				"refs",
				"occurrences",
				"sha256",
				occurrenceId.slice(0, 2),
				`${occurrenceId}.json`,
			);
			const runReferenceDirectory = join(this.root, "refs", "runs", sha256(line.runId));
			this.ensureDiskAdmission(256 * 1024);
			this.ensureOwnedDirectory(runReferenceDirectory);
			// Establish one lease per exact digest/run before publishing a path-only
			// occurrence reference. This is idempotent for recurring identical bytes.
			utimesSync(casPath, new Date(), new Date());
			this.linkOwnedVerified(casPath, join(runReferenceDirectory, `cas-${line.occurrenceSha256}.blob`));
			this.writeOwnedJson(occurrencePath, {
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
			});
			const firstWrapperSequence = assembly.references[0]?.wrapperSequence ?? "0";
			const runReferencePath = join(
				runReferenceDirectory,
				`seq-${firstWrapperSequence.padStart(20, "0")}-${occurrenceId}.json`,
			);
			this.linkOwnedVerified(occurrencePath, runReferencePath);
			fsyncDirectory(runReferenceDirectory);
			this.removeAssembly(identity);
			for (const entry of assembly.references) entry.resolved = true;
			this.advanceCheckpoint();
			this.processPendingPins();
		} finally {
			transaction.release();
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
		for (const identity of this.assemblies.keys()) {
			if (identity === excludeIdentity) continue;
			this.flushIncomplete(identity, reason);
			return;
		}
	}

	private flushAllIncomplete(reason: string): void {
		while (this.assemblies.size > 0) {
			const identity = this.assemblies.keys().next().value as string | undefined;
			if (!identity) return;
			this.flushIncomplete(identity, reason);
		}
	}

	private flushIncomplete(identity: string, reason: string): void {
		const assembly = this.assemblies.get(identity);
		if (!assembly) return;
		const id = sha256(
			`${assembly.identity}\0${reason}\0${assembly.references.map((entry) => entry.cursor).join("\0")}`,
		);
		const incompletePath = join(this.root, "refs", "incomplete", `${id}.json`);
		this.writeOwnedJson(incompletePath, {
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
			compactionDisposition: "immutable_incomplete_ref",
		});
		const runReferenceDirectory = join(this.root, "refs", "runs", sha256(assembly.line.runId));
		this.ensureDiskAdmission(256 * 1024);
		this.ensureOwnedDirectory(runReferenceDirectory);
		const firstWrapper = assembly.references[0]?.wrapperSequence ?? "0";
		const runReferencePath = join(
			runReferenceDirectory,
			`seq-${firstWrapper.padStart(20, "0")}-incomplete-${id}.json`,
		);
		this.linkOwnedVerified(incompletePath, runReferencePath);
		fsyncDirectory(runReferenceDirectory);
		this.removeAssembly(identity);
		for (const entry of assembly.references) entry.resolved = true;
		this.advanceCheckpoint();
	}

	private advanceCheckpoint(): void {
		for (;;) {
			const entry = this.pendingEntries[this.pendingEntryHead];
			if (!entry?.resolved) {
				if (this.pendingEntryHead === this.pendingEntries.length) {
					this.pendingEntries.length = 0;
					this.pendingEntryHead = 0;
				} else if (this.pendingEntryHead >= 1024 && this.pendingEntryHead * 2 >= this.pendingEntries.length) {
					this.pendingEntries.splice(0, this.pendingEntryHead);
					this.pendingEntryHead = 0;
				}
				return;
			}
			this.pendingEntryHead += 1;
			this.pendingEntryBytes = Math.max(0, this.pendingEntryBytes - entry.memoryBytes);
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
		}
	}
	private writeCas(value: Buffer, digest: string): string {
		if (sha256(value) !== digest) throw new Error("CAS digest precondition failed");
		this.ensureDiskAdmission(value.length * 2 + 64 * 1024);
		const path = join(this.root, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
		const created = this.withOwnedDirectoryMutation(dirname(path), 2, () => writeImmutable(path, value));
		if (created) this.accountStoragePath(path);
		const observed = readFileSync(path);
		if (observed.length !== value.length || sha256(observed) !== digest)
			throw new Error("Existing CAS blob did not verify");
		return path;
	}

	private writeGap(value: unknown): void {
		const serialized = JSON.stringify(value);
		const id = sha256(serialized);
		const gapPath = join(this.root, "refs", "gaps", `${id}.json`);
		this.writeOwnedJson(gapPath, { version: 1, state: "gap_or_uncertainty", evidence: value });
		if (!value || typeof value !== "object" || Array.isArray(value)) return;
		const evidence = value as Record<string, unknown>;
		if (typeof evidence.runId !== "string" || !isCanonicalUuid(evidence.runId)) return;
		const sequence =
			typeof evidence.expectedWrapperFrom === "string"
				? evidence.expectedWrapperFrom
				: typeof evidence.observedWrapperSequence === "string"
					? evidence.observedWrapperSequence
					: "0";
		const runDirectory = join(this.root, "refs", "runs", sha256(evidence.runId));
		this.ensureDiskAdmission(256 * 1024);
		this.ensureOwnedDirectory(runDirectory);
		this.linkOwnedVerified(gapPath, join(runDirectory, `seq-${sequence.padStart(20, "0")}-gap-${id}.json`));
		fsyncDirectory(runDirectory);
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
		this.checkpoint = {
			version: 1,
			cursor,
			machineId,
			bootId,
			invocationId,
			lastRealtimeUs: realtimeUs,
			wrapperSequences,
			producerSequences,
		};
		this.writeOwnedCheckpoint(this.checkpointPath, this.checkpoint);
	}

	private startPinRangeScan(
		incidentDir: string,
		request: { runId: string; fromWallTimeMs: number; throughWallTimeMs: number },
	): void {
		this.assertActive();
		const proofPath = join(incidentDir, "journal-pin-scan-proof.json");
		if (existsSync(proofPath) || this.activePinScans.has(incidentDir) || this.activePinScans.size >= 1) return;
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
			if (this.disposed) return;
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
		let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
		const terminate = (): void => {
			if (deadlineTimer) {
				clearTimeout(deadlineTimer);
				deadlineTimer = undefined;
			}
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
		this.activePinScans.set(incidentDir, terminate);
		deadlineTimer = setTimeout(() => {
			error ??= new Error("Pin range scan exceeded its process deadline");
			terminate();
		}, PIN_SCAN_DEADLINE_MS);
		deadlineTimer.unref();
		child.stdout?.on("data", (chunk: Buffer) => {
			if (this.disposed) return;
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
			if (deadlineTimer) clearTimeout(deadlineTimer);
			if (killTimer) clearTimeout(killTimer);
			this.activePinScans.delete(incidentDir);
			if (this.disposed) return;
			try {
				parser.finish();
			} catch (caught) {
				error ??= caught instanceof Error ? caught : new Error(String(caught));
			}
			if (code !== 0 || error) {
				try {
					this.writeOwnedJson(join(incidentDir, "journal-pin-incomplete.json"), {
						version: 1,
						state: "pending_or_incomplete",
						reason: error?.message ?? `journalctl_exit_${code ?? "unknown"}`,
						runId: request.runId,
					});
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
		});
	}

	private sysdigRequestPath(incidentDir: string): string {
		return join(incidentDir, "sysdig-pin-request.json");
	}

	private readSysdigSegmentRecordState(incidentDir: string): SysdigPinRecordState {
		const recordsDir = join(incidentDir, "sysdig-pins", "records");
		let discovery: { entries: Dirent[]; overflow: boolean };
		try {
			discovery = readDirectoryBounded(recordsDir, SYSDIG_PIN_MAX_DISCOVERY_ENTRIES);
		} catch {
			return { records: [], recordFileCount: 0, totalBytes: 0, saturated: false, issues: [] };
		}
		const issues: string[] = [];
		let saturated = false;
		if (discovery.overflow) {
			issues.push("pin_record_directory_entry_bound_exceeded");
			saturated = true;
		}
		const names = discovery.entries
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
				const stat = statSync(path);
				if (stat.size > 64 * 1024) throw new Error("record_metadata_byte_bound_exceeded");
				const value = JSON.parse(readFileSync(path, "utf8")) as SysdigPinnedSegmentRecord;
				if (
					value.version !== 1 ||
					value.id !== name.slice(0, -5) ||
					!/^[0-9a-f]{64}$/.test(value.id) ||
					typeof value.pinnedPath !== "string" ||
					typeof value.sourcePath !== "string" ||
					!Number.isSafeInteger(value.bytesAtCapture) ||
					value.bytesAtCapture < 0 ||
					value.bytesAtCapture > SYSDIG_PIN_MAX_SEGMENT_BYTES
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
				this.ensureOwnedDirectory(directory);
				this.writeOwnedJson(join(directory, `${sha256(reason)}.json`), { version: 1, reason }, 64 * 1024);
			} catch {}
		}
	}

	private readSysdigPinIssues(incidentDir: string): string[] {
		const directory = join(incidentDir, "sysdig-pins", "issues");
		let names: string[];
		try {
			names = readDirectoryBounded(directory, SYSDIG_PIN_MAX_DISCOVERY_ENTRIES)
				.entries.filter((entry) => entry.isFile() && /^[0-9a-f]{64}\.json$/.test(entry.name))
				.map((entry) => entry.name);
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

	private captureSysdigSegment(
		incidentDir: string,
		sourcePath: string,
		metadata: BigIntStats,
		observedAtWallTimeMs: number,
		phase: SysdigPinnedSegmentRecord["phase"],
		preferCopy: boolean,
	): SysdigPinnedSegmentRecord {
		const source = {
			dev: metadata.dev.toString(),
			ino: metadata.ino.toString(),
			bytes: Number(metadata.size),
			mtimeMs: Number(metadata.mtimeMs),
		};
		if (!Number.isSafeInteger(source.bytes) || source.bytes < 0 || source.bytes > SYSDIG_PIN_MAX_SEGMENT_BYTES) {
			throw new Error("sysdig_segment_exceeds_per_file_byte_bound");
		}
		const id = sha256(`${source.dev}\0${source.ino}\0${source.bytes}\0${source.mtimeMs}`);
		const pinRoot = join(incidentDir, "sysdig-pins");
		const segmentsDir = join(pinRoot, "segments");
		const recordsDir = join(pinRoot, "records");
		const pinnedPath = join(segmentsDir, `${id}.scap`);
		const recordPath = join(recordsDir, `${id}.json`);
		try {
			const existing = JSON.parse(readFileSync(recordPath, "utf8")) as SysdigPinnedSegmentRecord;
			if (existing.id === id && existing.pinnedPath === pinnedPath) {
				if (existing.captureMethod === "hard_link") {
					const expectedOwnerPath = join(this.root, "sysdig-pins", "owners", `${id}.scap`);
					if (existing.storageOwnerPath !== expectedOwnerPath)
						throw new Error("legacy_sysdig_hard_link_missing_persistent_storage_owner");
					const owner = statSync(existing.storageOwnerPath, { bigint: true });
					const pinned = statSync(existing.pinnedPath, { bigint: true });
					if (
						owner.dev !== metadata.dev ||
						owner.ino !== metadata.ino ||
						pinned.dev !== owner.dev ||
						pinned.ino !== owner.ino
					)
						throw new Error("sysdig_hard_link_storage_owner_mismatch");
				}
				return existing;
			}
		} catch (error) {
			if (error instanceof Error && error.message.startsWith("legacy_sysdig_hard_link")) throw error;
			if (error instanceof Error && error.message === "sysdig_hard_link_storage_owner_mismatch") throw error;
		}
		this.ensureDiskAdmission(source.bytes + 256 * 1024);
		this.ensureOwnedDirectory(segmentsDir);
		this.ensureOwnedDirectory(recordsDir);
		let captureMethod: SysdigPinnedSegmentRecord["captureMethod"] = "hard_link";
		let captureReason: SysdigPinnedSegmentRecord["captureReason"] = preferCopy
			? "active_segment_snapshot"
			: "closed_segment_hard_link";
		let hardLinkErrorCode: string | undefined;
		let digest: string | undefined;
		let storageOwnerPath: string | undefined;
		let linked = false;
		const sourceAlreadyAccounted =
			relativeDescendant(this.root, sourcePath) !== undefined ||
			relativeDescendant(join(this.options.agentDir, "incidents"), sourcePath) !== undefined;
		if (!preferCopy && !sourceAlreadyAccounted) {
			storageOwnerPath = join(this.root, "sysdig-pins", "owners", `${id}.scap`);
			try {
				let owner: BigIntStats | undefined;
				try {
					owner = lstatSync(storageOwnerPath, { bigint: true });
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
				}
				if (owner) {
					if (
						!owner.isFile() ||
						owner.isSymbolicLink() ||
						owner.dev !== metadata.dev ||
						owner.ino !== metadata.ino
					) {
						throw new Error("sysdig_storage_owner_identity_mismatch");
					}
				} else {
					if (metadata.nlink !== 1n) throw new Error("sysdig_source_has_unowned_hard_links");
					this.withOwnedDirectoryMutation(dirname(storageOwnerPath), 1, () =>
						linkSync(sourcePath, storageOwnerPath as string),
					);
					this.accountStoragePath(storageOwnerPath);
				}
				this.linkOwnedVerified(storageOwnerPath, pinnedPath);
				const linkedStat = lstatSync(pinnedPath, { bigint: true });
				if (linkedStat.dev !== metadata.dev || linkedStat.ino !== metadata.ino) {
					throw new Error("sysdig_hard_link_identity_mismatch");
				}
				linked = true;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "EEXIST") throw error;
				// A persistent owner created before a later publication failure remains
				// accounted and reference-safe. Ordinary incident expiry cannot unlink it.
				hardLinkErrorCode = (error as NodeJS.ErrnoException).code ?? "UNKNOWN";
				captureReason = "hard_link_unavailable";
				storageOwnerPath = undefined;
			}
		} else if (!preferCopy) {
			hardLinkErrorCode = "SOURCE_ALREADY_ACCOUNTED";
			captureReason = "hard_link_unavailable";
		}
		if (!linked) {
			this.withOwnedDirectoryMutation(segmentsDir, 2, () => {
				captureMethod = "bounded_copy";
				const temporary = join(segmentsDir, `.${id}.tmp-${process.pid}`);
				let input: number | undefined;
				let output: number | undefined;
				try {
					rmSync(temporary, { force: true });
					input = openSync(sourcePath, "r");
					const opened = fstatSync(input, { bigint: true });
					if (
						!opened.isFile() ||
						opened.dev !== metadata.dev ||
						opened.ino !== metadata.ino ||
						Number(opened.size) < source.bytes
					) {
						throw new Error("sysdig_source_changed_before_bounded_copy");
					}
					output = openSync(temporary, "wx", 0o600);
					const hash = createHash("sha256");
					const buffer = Buffer.allocUnsafe(SYSDIG_PIN_COPY_BUFFER_BYTES);
					let offset = 0;
					while (offset < source.bytes) {
						const count = readSync(input, buffer, 0, Math.min(buffer.length, source.bytes - offset), offset);
						if (count <= 0) throw new Error("sysdig_source_truncated_during_bounded_copy");
						hash.update(buffer.subarray(0, count));
						writeAll(output, buffer.subarray(0, count));
						offset += count;
					}
					const after = fstatSync(input, { bigint: true });
					if (after.dev !== metadata.dev || after.ino !== metadata.ino || Number(after.size) < source.bytes) {
						throw new Error("sysdig_source_changed_during_bounded_copy");
					}
					fsyncSync(output);
					closeSync(input);
					input = undefined;
					closeSync(output);
					output = undefined;
					renameSync(temporary, pinnedPath);
					fsyncDirectory(segmentsDir);
					digest = hash.digest("hex");
				} finally {
					if (input !== undefined)
						try {
							closeSync(input);
						} catch {}
					if (output !== undefined)
						try {
							closeSync(output);
						} catch {}
					rmSync(temporary, { force: true });
				}
			});
		}
		const record: SysdigPinnedSegmentRecord = {
			version: 1,
			id,
			sourcePath,
			sourceName: basename(sourcePath),
			observedAtWallTimeMs,
			phase,
			source,
			pinnedPath,
			...(storageOwnerPath ? { storageOwnerPath } : {}),
			captureMethod,
			captureReason,
			...(hardLinkErrorCode ? { hardLinkErrorCode } : {}),
			bytesAtCapture: source.bytes,
			...(digest ? { sha256AtCapture: digest } : {}),
		};
		if (!linked) this.accountStoragePath(pinnedPath);
		this.writeOwnedJson(recordPath, record, 64 * 1024);
		return record;
	}

	private addSysdigDiscoveryIssue(state: SysdigRingDiscovery, issue: string): void {
		if (state.issues.length < SYSDIG_PIN_MAX_DISCOVERY_ENTRIES - 1) {
			state.issues.push(issue);
			return;
		}
		if (!state.issuesTruncated) {
			state.issues.push("ring_discovery_issue_bound_exceeded");
			state.issuesTruncated = true;
		}
	}

	private finishSysdigRingDiscovery(state: SysdigRingDiscovery): string[] {
		this.closeRetainedDirectory(state.directory);
		if (this.sysdigRingDiscovery === state) this.sysdigRingDiscovery = undefined;
		if (state.candidateCount > SYSDIG_RING_EXPECTED_SEGMENTS)
			this.addSysdigDiscoveryIssue(state, "ring_has_more_than_configured_12_segments");
		if (state.candidateCount > SYSDIG_PIN_MAX_SEGMENTS)
			this.addSysdigDiscoveryIssue(state, "ring_segment_count_bound_exceeded");
		const existing = this.readSysdigSegmentRecordState(state.incidentDir);
		const issues = [...state.issues, ...existing.issues];
		if (existing.saturated) return issues;
		const known = new Set(existing.records.map((record) => record.id));
		let admittedBytes = existing.totalBytes;
		let recordFileCount = existing.recordFileCount;
		for (let index = 0; index < state.candidates.length; index += 1) {
			const candidate = state.candidates[index];
			if (!candidate) continue;
			const bytes = Number(candidate.metadata.size);
			const id = sha256(
				`${candidate.metadata.dev.toString()}\0${candidate.metadata.ino.toString()}\0${bytes}\0${Number(candidate.metadata.mtimeMs)}`,
			);
			if (known.has(id)) continue;
			if (state.phase === "rotated" && index === 0) continue;
			if (recordFileCount >= SYSDIG_PIN_MAX_SEGMENTS) {
				issues.push("pin_record_count_bound_reached");
				break;
			}
			if (admittedBytes + bytes > SYSDIG_PIN_MAX_TOTAL_BYTES) {
				issues.push("incident_sysdig_pin_total_byte_bound_exceeded");
				break;
			}
			try {
				const record = this.captureSysdigSegment(
					state.incidentDir,
					candidate.path,
					candidate.metadata,
					state.observedAtWallTimeMs,
					state.phase,
					index === 0,
				);
				known.add(record.id);
				recordFileCount += 1;
				admittedBytes += record.bytesAtCapture;
			} catch (error) {
				issues.push(
					`capture_failed:${basename(candidate.path)}:${error instanceof Error ? error.message : String(error)}`,
				);
			}
		}
		return issues;
	}

	private advanceSysdigRingDiscovery(state: SysdigRingDiscovery): SysdigDiscoveryResult {
		this.sysdigDiscoverySliceEntries = 0;
		for (let discovered = 0; discovered < SYSDIG_DISCOVERY_BATCH_COUNT; discovered += 1) {
			let entry: Dirent | null;
			try {
				entry = this.readRetainedDirectory(state.directory);
			} catch {
				this.addSysdigDiscoveryIssue(state, "ring_directory_read_failed");
				return { complete: true, issues: this.finishSysdigRingDiscovery(state) };
			}
			if (!entry) return { complete: true, issues: this.finishSysdigRingDiscovery(state) };
			this.sysdigDiscoverySliceEntries += 1;
			if (!entry.name.startsWith(state.ringName)) continue;
			const sourcePath = join(String(state.directory.path), entry.name);
			try {
				const metadata = lstatSync(sourcePath, { bigint: true });
				if (!metadata.isFile()) {
					this.addSysdigDiscoveryIssue(state, `non_regular_ring_entry:${entry.name}`);
					continue;
				}
				const bytes = Number(metadata.size);
				if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > SYSDIG_PIN_MAX_SEGMENT_BYTES) {
					this.addSysdigDiscoveryIssue(state, `oversize_ring_entry:${entry.name}`);
					continue;
				}
				state.candidateCount += 1;
				state.candidates.push({ path: sourcePath, metadata });
				state.candidates.sort(
					(left, right) =>
						Number(right.metadata.mtimeMs - left.metadata.mtimeMs) ||
						basename(right.path).localeCompare(basename(left.path)),
				);
				if (state.candidates.length > SYSDIG_PIN_MAX_SEGMENTS) state.candidates.pop();
			} catch {
				this.addSysdigDiscoveryIssue(state, `unstatable_ring_entry:${entry.name}`);
			}
		}
		return { complete: false, issues: [] };
	}

	private captureSysdigRing(
		incidentDir: string,
		request: SysdigPinRequest,
		phase: "initial" | "rotated" | "final",
		nowMs: number,
	): SysdigDiscoveryResult {
		if (this.sysdigRingDiscovery) return { complete: false, issues: [] };
		let directory: Dir;
		try {
			directory = this.openRetainedDirectory(dirname(request.ringBasePath), "sysdig-discovery");
		} catch {
			return { complete: true, issues: ["ring_directory_unavailable"] };
		}
		const state: SysdigRingDiscovery = {
			incidentDir,
			request,
			phase,
			observedAtWallTimeMs: nowMs,
			directory,
			ringName: basename(request.ringBasePath),
			candidates: [],
			candidateCount: 0,
			issues: [],
			issuesTruncated: false,
		};
		this.sysdigRingDiscovery = state;
		return this.advanceSysdigRingDiscovery(state);
	}

	private completeActiveSysdigDiscovery(state: SysdigRingDiscovery, result: SysdigDiscoveryResult): void {
		if (!result.complete) return;
		if (state.phase === "final") {
			this.finalizeSysdigPin(state.incidentDir, state.request, state.observedAtWallTimeMs, result.issues);
			return;
		}
		this.recordSysdigPinIssues(state.incidentDir, result.issues);
	}

	private processSysdigPin(incidentDir: string, request: SysdigPinRequest, nowMs: number): void {
		const manifestPath = join(incidentDir, "sysdig-pin-manifest.json");
		if (existsSync(manifestPath)) return;
		if (nowMs < request.resolveAfterWallTimeMs) {
			const rotated = this.captureSysdigRing(incidentDir, request, "rotated", nowMs);
			if (rotated.complete) this.recordSysdigPinIssues(incidentDir, rotated.issues);
			return;
		}
		const final = this.captureSysdigRing(incidentDir, request, "final", nowMs);
		if (!final.complete) return;
		this.finalizeSysdigPin(incidentDir, request, nowMs, final.issues);
	}

	private finalizeSysdigPin(
		incidentDir: string,
		request: SysdigPinRequest,
		nowMs: number,
		captureIssues: readonly string[],
	): void {
		const manifestPath = join(incidentDir, "sysdig-pin-manifest.json");
		if (existsSync(manifestPath)) return;
		const gaps = [...this.readSysdigPinIssues(incidentDir), ...captureIssues];
		const recordState = this.readSysdigSegmentRecordState(incidentDir);
		gaps.push(...recordState.issues);
		const segments: Array<Record<string, unknown>> = [];
		for (const record of recordState.records) {
			try {
				const stat = statSync(record.pinnedPath, { bigint: true });
				if (!stat.isFile()) throw new Error("pinned_path_not_regular_file");
				const bytes = Number(stat.size);
				if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > SYSDIG_PIN_MAX_SEGMENT_BYTES)
					throw new Error("pinned_size_out_of_bounds");
				const digest = sha256FileBounded(record.pinnedPath, bytes);
				const changedAfterCapture =
					bytes !== record.bytesAtCapture ||
					(record.captureMethod === "hard_link" &&
						(stat.dev.toString() !== record.source.dev ||
							stat.ino.toString() !== record.source.ino ||
							Number(stat.mtimeMs) !== record.source.mtimeMs));
				if (record.sha256AtCapture && (bytes !== record.bytesAtCapture || digest !== record.sha256AtCapture)) {
					throw new Error("bounded_copy_failed_exact_byte_verification");
				}
				if (changedAfterCapture) gaps.push(`hard_link_changed_after_capture:${record.sourceName}`);
				segments.push({ ...record, exactBytes: { bytes, sha256: digest }, changedAfterCapture });
			} catch (error) {
				gaps.push(
					`verification_failed:${record.sourceName}:${error instanceof Error ? error.message : String(error)}`,
				);
			}
		}
		if (segments.length === 0) gaps.push("no_sysdig_ring_segments_were_pinned");
		gaps.push("scap_event_time_bounds_not_inspected_coverage_is_observation_based");
		this.writeOwnedJson(manifestPath, {
			version: 1,
			state: "finalized_with_observed_coverage",
			diagnosticOnly: true,
			runId: request.runId,
			requestedWindow: {
				fromWallTimeMs: request.fromWallTimeMs,
				anchorWallTimeMs: request.anchorWallTimeMs,
				throughWallTimeMs: request.throughWallTimeMs,
			},
			captureFinalizedAtWallTimeMs: nowMs,
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
		this.ensureOwnedDirectory(sysdigPinDirectory);
		const sysdigPinDirectoryStat = lstatSync(sysdigPinDirectory);
		this.writeOwnedJson(join(incidentDir, "sysdig-pin-retention-proof.json"), {
			version: 1,
			state: "producer_verified_complete",
			provider: "sysdig",
			manifestValidated: true,
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

	requestPin(runId: string, incidentDir: string, anchorWallTimeMs: number): void {
		this.assertActive();
		const sysdigRequest: SysdigPinRequest = {
			version: 1,
			runId,
			anchorWallTimeMs,
			fromWallTimeMs: anchorWallTimeMs - PIN_BEFORE_MS,
			throughWallTimeMs: anchorWallTimeMs + PIN_AFTER_MS,
			resolveAfterWallTimeMs: anchorWallTimeMs + PIN_AFTER_MS,
			requestedAtWallTimeMs: Date.now(),
			retainUntilWallTimeMs: anchorWallTimeMs + SYSDIG_PIN_RETENTION_MS,
			ringBasePath: this.options.sysdigRingBasePath ?? SYSDIG_RING_DEFAULT_BASE_PATH,
		};
		try {
			this.writeOwnedJson(this.sysdigRequestPath(incidentDir), sysdigRequest);
			const initial = this.captureSysdigRing(
				incidentDir,
				sysdigRequest,
				"initial",
				sysdigRequest.requestedAtWallTimeMs,
			);
			if (initial.complete) this.recordSysdigPinIssues(incidentDir, initial.issues);
		} catch (error) {
			try {
				this.writeOwnedJson(join(incidentDir, "sysdig-pin-incomplete.json"), {
					version: 1,
					state: "pending_or_incomplete",
					runId,
					reason: error instanceof Error ? error.message : String(error),
				});
			} catch {}
		}
		const requestPath = join(incidentDir, "journal-pin-request.json");
		this.writeOwnedJson(requestPath, {
			version: 1,
			state: "pending",
			runId,
			anchorWallTimeMs,
			fromWallTimeMs: anchorWallTimeMs - PIN_BEFORE_MS,
			throughWallTimeMs: anchorWallTimeMs + PIN_AFTER_MS,
			resolveAfterWallTimeMs: anchorWallTimeMs + PIN_AFTER_MS,
			retainUntilWallTimeMs: anchorWallTimeMs + INCIDENT_DIAGNOSTIC_RETENTION_MS,
		});
	}

	private retentionProofMatchesRequest(
		path: string,
		provider: "journal",
		request: { runId: string; fromWallTimeMs: number; throughWallTimeMs: number },
	): boolean {
		try {
			const stat = lstatSync(path);
			if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 64 * 1024) return false;
			const proof = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
			return (
				proof.version === 1 &&
				proof.state === "producer_verified_complete" &&
				proof.provider === provider &&
				proof.manifestValidated === true &&
				proof.runId === request.runId &&
				proof.fromWallTimeMs === request.fromWallTimeMs &&
				proof.throughWallTimeMs === request.throughWallTimeMs
			);
		} catch {
			return false;
		}
	}

	private startJournalManifestValidation(
		incidentDir: string,
		manifestPath: string,
		request: { runId: string; fromWallTimeMs: number; throughWallTimeMs: number; retainUntilWallTimeMs?: number },
	): void {
		let descriptor: number | undefined;
		try {
			const before = lstatSync(manifestPath);
			if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > PENDING_ENTRY_MAX_BYTES)
				throw new Error("manifest_metadata_invalid");
			descriptor = this.openRetainedDescriptor(manifestPath, fsConstants.O_RDONLY, "journal-manifest");
			const opened = fstatSync(descriptor);
			if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size)
				throw new Error("manifest_identity_changed");
			this.journalManifestValidation = {
				incidentDir,
				manifestPath,
				descriptor,
				runId: request.runId,
				fromWallTimeMs: request.fromWallTimeMs,
				throughWallTimeMs: request.throughWallTimeMs,
				retainUntilWallTimeMs:
					request.retainUntilWallTimeMs ??
					request.fromWallTimeMs + PIN_BEFORE_MS + INCIDENT_DIAGNOSTIC_RETENTION_MS,
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
				cursorBytes: 0,
				verifiedPins: new Map(),
			};
			descriptor = undefined;
		} catch (error) {
			if (descriptor !== undefined) this.closeRetainedDescriptor(descriptor);
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
		this.closeRetainedDescriptor(state.descriptor);
		if (state.pinValidation) {
			this.closeRetainedDescriptor(state.pinValidation.descriptor);
			state.pinValidation.hash.destroy();
		}
		state.pinValidation = undefined;
		state.pendingOccurrence = undefined;
		state.textBuffer = "";
		state.objectText = "";
		state.verifiedPins.clear();
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
				header.version !== 1 ||
				header.state !== "complete_through_requested_window" ||
				header.runId !== state.runId ||
				header.fromWallTimeMs !== state.fromWallTimeMs ||
				header.throughWallTimeMs !== state.throughWallTimeMs ||
				!Array.isArray(header.occurrences) ||
				header.occurrences.length !== 0
			)
				throw new Error("manifest_header_schema_invalid");
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
					if (
						typeof parsed.occurrenceReference !== "string" ||
						!parsed.occurrenceReference.startsWith(`${join(this.root, "refs")}/`) ||
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
						parsed.pinnedCasPath !== join(state.incidentDir, "journal-pins", "cas", `${casRecord.digest}.blob`)
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
						cursors: cursors as string[],
						cas: { digest: casRecord.digest, bytes: Number(casRecord.bytes), path: casRecord.path as string },
						eventWallTimeMs: parsed.eventWallTimeMs,
						pinnedCasPath: parsed.pinnedCasPath,
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
		const previous = state.verifiedPins.get(occurrence.cas.digest);
		if (previous) {
			if (previous.bytes !== occurrence.cas.bytes || previous.pinnedPath !== occurrence.pinnedCasPath)
				throw new Error("manifest_duplicate_digest_inconsistent");
			state.pendingOccurrence = undefined;
			return;
		}
		const pinned = lstatSync(occurrence.pinnedCasPath);
		const global = lstatSync(occurrence.cas.path);
		if (
			!pinned.isFile() ||
			pinned.isSymbolicLink() ||
			pinned.size !== occurrence.cas.bytes ||
			global.dev !== pinned.dev ||
			global.ino !== pinned.ino ||
			pinned.nlink < 2
		) {
			throw new Error("manifest_pin_identity_or_size_invalid");
		}
		const descriptor = this.openRetainedDescriptor(
			occurrence.pinnedCasPath,
			fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
			"journal-pin",
		);
		try {
			const opened = fstatSync(descriptor);
			if (opened.dev !== pinned.dev || opened.ino !== pinned.ino || opened.size !== pinned.size) {
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
			};
		} catch (error) {
			this.closeRetainedDescriptor(descriptor);
			throw error;
		}
		state.pendingOccurrence = undefined;
	}

	private advanceJournalManifestPinHash(state: JournalManifestValidation): void {
		const pin = state.pinValidation;
		if (!pin) return;
		const buffer = Buffer.allocUnsafe(64 * 1024);
		this.beforeRetainedDescriptorRead(pin.descriptor);
		const count = readSync(pin.descriptor, buffer, 0, Math.min(buffer.length, pin.bytes - pin.offset), pin.offset);
		if (count > 0) {
			pin.hash.update(buffer.subarray(0, count));
			pin.offset += count;
			return;
		}
		const after = fstatSync(pin.descriptor);
		this.closeRetainedDescriptor(pin.descriptor);
		state.pinValidation = undefined;
		if (
			pin.offset !== pin.bytes ||
			after.dev !== pin.dev ||
			after.ino !== pin.ino ||
			after.size !== pin.bytes ||
			after.mtimeMs !== pin.mtimeMs ||
			pin.hash.digest("hex") !== pin.digest
		)
			throw new Error("manifest_pin_content_verification_failed");
		state.verifiedPins.set(pin.digest, { bytes: pin.bytes, pinnedPath: pin.pinnedPath, dev: pin.dev, ino: pin.ino });
	}

	private completeJournalManifestValidation(state: JournalManifestValidation): void {
		const after = fstatSync(state.descriptor);
		this.closeRetainedDescriptor(state.descriptor);
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
		this.writeOwnedJson(join(state.incidentDir, "journal-pin-retention-proof.json"), {
			version: 1,
			state: "producer_verified_complete",
			provider: "journal",
			manifestValidated: true,
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
				this.beforeRetainedDescriptorRead(state.descriptor);
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
			this.failJournalManifestValidation(state, error instanceof Error ? error.message : String(error));
		}
	}

	processPendingPins(nowMs = Date.now()): void {
		this.assertActive();
		this.incidentDiscoverySliceEntries = 0;
		this.sysdigDiscoverySliceEntries = 0;
		if (this.sysdigRingDiscovery) {
			const state = this.sysdigRingDiscovery;
			this.completeActiveSysdigDiscovery(state, this.advanceSysdigRingDiscovery(state));
			return;
		}
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
		if (!this.incidentDiscovery) {
			try {
				this.incidentDiscovery = this.openRetainedDirectory(incidentRoot, "incident-discovery");
			} catch {
				return;
			}
		}
		const directory = this.incidentDiscovery;
		for (let discovered = 0; discovered < INCIDENT_DISCOVERY_BATCH_COUNT; discovered += 1) {
			let entry: Dirent | null;
			try {
				entry = this.readRetainedDirectory(directory);
			} catch {
				this.closeRetainedDirectory(directory);
				this.incidentDiscovery = undefined;
				return;
			}
			if (!entry) {
				this.closeRetainedDirectory(directory);
				this.incidentDiscovery = undefined;
				return;
			}
			this.incidentDiscoverySliceEntries += 1;
			if (!entry.isDirectory()) continue;
			const incidentDir = join(incidentRoot, entry.name);
			const requestPath = join(incidentDir, "journal-pin-request.json");
			const manifestPath = join(incidentDir, "journal-pin-manifest.json");
			let request: {
				runId: string;
				fromWallTimeMs: number;
				throughWallTimeMs: number;
				resolveAfterWallTimeMs: number;
				retainUntilWallTimeMs?: number;
			};
			try {
				request = JSON.parse(readFileSync(requestPath, "utf8")) as typeof request;
			} catch {
				continue;
			}
			try {
				const sysdigRequest = JSON.parse(
					readFileSync(this.sysdigRequestPath(incidentDir), "utf8"),
				) as SysdigPinRequest;
				if (
					sysdigRequest.version === 1 &&
					sysdigRequest.runId === request.runId &&
					sysdigRequest.fromWallTimeMs === request.fromWallTimeMs &&
					sysdigRequest.throughWallTimeMs === request.throughWallTimeMs &&
					typeof sysdigRequest.ringBasePath === "string"
				)
					this.processSysdigPin(incidentDir, sysdigRequest, nowMs);
			} catch {}
			if (existsSync(manifestPath)) {
				const retentionProofPath = join(incidentDir, "journal-pin-retention-proof.json");
				if (this.retentionProofMatchesRequest(retentionProofPath, "journal", request)) continue;
				this.startJournalManifestValidation(incidentDir, manifestPath, request);
				if (this.journalManifestValidation) this.advanceJournalManifestValidation();
				if (this.journalManifestValidation) return;
				continue;
			}
			if (nowMs < request.resolveAfterWallTimeMs) continue;
			const proofPath = join(incidentDir, "journal-pin-scan-proof.json");
			if (!existsSync(proofPath)) {
				this.startPinRangeScan(incidentDir, request);
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
			if (!valid) continue;
			try {
				const directory = this.openRetainedDirectory(
					join(this.root, "refs", "runs", sha256(request.runId)),
					"pin-traversal",
				);
				this.activePinTraversal = {
					incidentDir,
					request,
					scannedCursors,
					directory,
					matches: [],
					memoryBytes: cursorBytes,
					phase: "reading",
					linkIndex: 0,
					linked: new Map(),
				};
				this.advancePinTraversal(this.activePinTraversal);
			} catch {}
			return;
		}
	}

	private advancePinTraversal(state: PinTraversal): void {
		if (state.phase === "reading") {
			const directory = state.directory;
			if (!directory) {
				this.activePinTraversal = undefined;
				return;
			}
			let complete = false;
			for (let count = 0; count < PIN_REFERENCE_BATCH_COUNT; count += 1) {
				let entry: Dirent | null;
				try {
					entry = this.readRetainedDirectory(directory);
				} catch (error) {
					this.closeRetainedDirectory(directory);
					state.directory = undefined;
					this.activePinTraversal = undefined;
					try {
						this.writeOwnedJson(join(state.incidentDir, "journal-pin-incomplete.json"), {
							version: 1,
							state: "pending_or_incomplete",
							reason: error instanceof Error ? error.message : String(error),
							runId: state.request.runId,
						});
					} catch {}
					return;
				}
				if (!entry) {
					complete = true;
					break;
				}
				if (!entry.isFile() || !/^seq-\d{20}-[0-9a-f]{64}\.json$/.test(entry.name)) continue;
				const path = join(directory.path, entry.name);
				try {
					const reference = JSON.parse(readFileSync(path, "utf8")) as {
						state?: string;
						identity?: { runId?: string; runToken?: string; producerId?: string; occurrenceId?: string };
						eventWallTimeMs?: string;
						cursors?: unknown;
						cas?: { digest: string; bytes: number; path: string };
					};
					const wall = Number(reference.eventWallTimeMs);
					const identity = reference.identity;
					const cursors = reference.cursors;
					if (
						!canonicalUuidFields(identity) ||
						!Array.isArray(cursors) ||
						cursors.some((cursor) => typeof cursor !== "string")
					)
						continue;
					if (
						reference.state !== "complete" ||
						identity.runId !== state.request.runId ||
						!Number.isFinite(wall) ||
						wall < state.request.fromWallTimeMs ||
						wall > state.request.throughWallTimeMs ||
						!reference.cas ||
						!/^[0-9a-f]{64}$/.test(reference.cas.digest) ||
						!Number.isSafeInteger(reference.cas.bytes) ||
						reference.cas.bytes < 0 ||
						reference.cas.bytes > 983_040 ||
						reference.cas.path !==
							join(
								this.root,
								"cas",
								"sha256",
								reference.cas.digest.slice(0, 2),
								`${reference.cas.digest}.blob`,
							) ||
						cursors.length > PIN_CURSOR_MAX_COUNT ||
						!basename(path).endsWith(
							`-${sha256(`${identity.runId}\0${identity.runToken}\0${identity.producerId}\0${identity.occurrenceId}`)}.json`,
						)
					)
						continue;
					const match = {
						occurrenceReference: path,
						cursors: cursors as string[],
						cas: reference.cas,
						eventWallTimeMs: reference.eventWallTimeMs ?? "unknown",
					};
					const added = retainedBytes(match);
					if (state.memoryBytes + added > PENDING_ENTRY_MAX_BYTES)
						throw new Error("Pin reference traversal exceeded its heap bound");
					state.matches.push(match);
					state.memoryBytes += added;
				} catch (error) {
					if (error instanceof Error && error.message.includes("heap bound")) {
						this.closeRetainedDirectory(directory);
						state.directory = undefined;
						this.activePinTraversal = undefined;
						this.writeOwnedJson(join(state.incidentDir, "journal-pin-incomplete.json"), {
							version: 1,
							state: "pending_or_incomplete",
							reason: error.message,
							runId: state.request.runId,
						});
						return;
					}
				}
			}
			if (!complete) return;
			this.closeRetainedDirectory(directory);
			state.directory = undefined;
			state.phase = "linking";
			state.pinCasDir = join(state.incidentDir, "journal-pins", "cas");
			this.ensureDiskAdmission(256 * 1024);
			this.ensureOwnedDirectory(state.pinCasDir);
		}
		const pinCasDir = state.pinCasDir;
		if (!pinCasDir) {
			this.activePinTraversal = undefined;
			return;
		}
		const pinTransaction = acquireIncidentCasTransaction(this.root);
		if (!pinTransaction) return;
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
					this.linkOwnedVerified(match.cas.path, target);
					const stat = statSync(target);
					if (stat.size === match.cas.bytes && sha256(readFileSync(target)) === match.cas.digest)
						state.linked.set(match.cas.digest, target);
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
			this.writeOwnedJson(join(state.incidentDir, "journal-pin-incomplete.json"), {
				version: 1,
				state: "pending_or_incomplete",
				reason: "occurrence_or_cas_link_verification_failed",
				runId: state.request.runId,
			});
			return;
		}
		this.writeOwnedJson(join(state.incidentDir, "journal-pin-manifest.json"), {
			version: 1,
			state: "complete_through_requested_window",
			runId: state.request.runId,
			fromWallTimeMs: state.request.fromWallTimeMs,
			throughWallTimeMs: state.request.throughWallTimeMs,
			occurrences: state.matches.map((match) => ({
				...match,
				pinnedCasPath: state.linked.get(match.cas.digest) ?? null,
			})),
		});
		const journalManifestPath = join(state.incidentDir, "journal-pin-manifest.json");
		const journalManifestStat = lstatSync(journalManifestPath);
		const journalPinDirectoryStat = lstatSync(pinCasDir);
		this.writeOwnedJson(join(state.incidentDir, "journal-pin-retention-proof.json"), {
			version: 1,
			state: "producer_verified_complete",
			provider: "journal",
			manifestValidated: true,
			runId: state.request.runId,
			fromWallTimeMs: state.request.fromWallTimeMs,
			throughWallTimeMs: state.request.throughWallTimeMs,
			retainUntilWallTimeMs: state.request.fromWallTimeMs + PIN_BEFORE_MS + INCIDENT_DIAGNOSTIC_RETENTION_MS,
			retentionMilliseconds: INCIDENT_DIAGNOSTIC_RETENTION_MS,
			occurrenceCount: state.matches.length,
			manifestIdentity: {
				dev: String(journalManifestStat.dev),
				ino: String(journalManifestStat.ino),
				size: journalManifestStat.size,
				mtimeMs: journalManifestStat.mtimeMs,
				ctimeMs: journalManifestStat.ctimeMs,
				nlink: journalManifestStat.nlink,
			},
			pinDirectoryIdentity: {
				path: "journal-pins/cas",
				dev: String(journalPinDirectoryStat.dev),
				ino: String(journalPinDirectoryStat.ino),
				mtimeMs: journalPinDirectoryStat.mtimeMs,
				ctimeMs: journalPinDirectoryStat.ctimeMs,
			},
		});
		fsyncDirectory(state.incidentDir);
	}
}
