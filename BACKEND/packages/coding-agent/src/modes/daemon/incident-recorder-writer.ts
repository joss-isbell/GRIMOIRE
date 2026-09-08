import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	closeSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	lstatSync,
	openSync,
	readFileSync,
	readSync,
	unlinkSync,
	write,
	writeFileSync,
} from "node:fs";
import type { Readable as ReadableStream } from "node:stream";
import {
	type IncidentRecorderDiagnosticPayloadState,
	type IncidentRecorderDiagnosticPayloadSummary,
	serializeIncidentRecorderDiagnostic,
} from "./incident-recorder-diagnostic-serializer.js";
import {
	decodeIncidentRecorderFrame,
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
	INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES,
	INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES,
	INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES,
	INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES,
	INCIDENT_RECORDER_RUN_ID_ENV,
	INCIDENT_RECORDER_RUN_TOKEN_ENV,
	type IncidentRecorderEncodedFrame,
	type IncidentRecorderPayloadKind,
	newIncidentRecorderIdentity,
	validateIncidentRecorderFrameFlags,
} from "./incident-recorder-protocol.js";
import {
	encodeIncidentRecorderTransportPacket,
	type IncidentRecorderTransportCorruption,
	IncidentRecorderTransportDecoder,
	IncidentRecorderTransportSequenceTracker,
} from "./incident-recorder-transport.js";

export const INCIDENT_RECORDER_CAPTURE_FD_ENV = "PRIME_INCIDENT_RECORDER_CAPTURE_FD";
export const INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV = "PRIME_INCIDENT_RECORDER_CAPTURE_OWNER_PID";
export const INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV = "PRIME_INCIDENT_RECORDER_CAPTURE_OWNER_START_ID";
export const INCIDENT_RECORDER_CAPTURE_FD = 4;
export const INCIDENT_RECORDER_ROOT_FD_ENV = "PRIME_INCIDENT_RECORDER_ROOT_FD";
export const INCIDENT_RECORDER_ROOT_FD = 5;
export const INCIDENT_RECORDER_CAPTURE_OWNER_CLAIM_FILE = ".capture-owner-v1";
export const INCIDENT_RECORDER_EMITTER_MAX_BYTES = 8 * 1024 * 1024;
export const INCIDENT_RECORDER_EMITTER_CHUNK_BYTES = INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES;
export const INCIDENT_RECORDER_JOURNAL_NAMESPACE = "grimoire";
export const INCIDENT_RECORDER_JOURNAL_IDENTIFIER = "prime-agent-raw-v1";
export const INCIDENT_RECORDER_JOURNAL_LINE_MAX_BYTES = 48 * 1024;

const CONTROL_RESERVE_BYTES = 64 * 1024;
const JOURNAL_START_DEADLINE_MS = 150;
const JOURNAL_START_STABILITY_MS = 25;
const JOURNAL_RECONNECT_MS = 1_000;
const JOURNAL_RELAY_MAX_BYTES = 8 * 1024 * 1024;
const SERVICE_EMITTER_MAX_BYTES = 256 * 1024;
const SERVICE_EMITTER_MAX_IDENTITIES = 32;
export const INCIDENT_RECORDER_WRAPPER_FRONTIER_MAX_IDENTITIES = 4_096;
export const INCIDENT_RECORDER_SERVICE_SEAL_RESULT_MAX_IDENTITIES = 64;
export const INCIDENT_RECORDER_SERVICE_SEAL_FENCE_MAX_IDENTITIES = 4_096;
// One tombstone per occurrence that can be admitted inside the producer's bounded
// transport window. Real old-sequence duplicates remain fenced by sequence state
// after this LRU rolls over.
const CAPTURE_OCCURRENCE_TOMBSTONE_MAX = Math.ceil(
	INCIDENT_RECORDER_EMITTER_MAX_BYTES / (INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES + 3 * 255 + 4 * 1024),
);

type Scalar = string | number | boolean | null;
type ScalarMetadata = Readonly<Record<string, Scalar>>;
type CaptureSource = string;

export interface IncidentRecorderWrapperFrontierIdentity {
	runId: string;
	runToken: string;
}

/**
 * Raised when this process can no longer retain a new wrapper/run identity.
 * Existing identities remain usable so a bounded frontier never turns a
 * recoverable lifecycle transition into a silent queue-capacity loss.
 */
export class IncidentRecorderWrapperFrontierSaturatedError extends Error {
	readonly code = "INCIDENT_RECORDER_WRAPPER_FRONTIER_SATURATED" as const;
	readonly runId: string;
	readonly runToken: string;
	readonly maxIdentities: number;

	constructor(identity: IncidentRecorderWrapperFrontierIdentity, maxIdentities: number) {
		super(`Incident recorder wrapper sequence frontier is saturated at ${maxIdentities} identities`);
		this.name = "IncidentRecorderWrapperFrontierSaturatedError";
		this.runId = identity.runId;
		this.runToken = identity.runToken;
		this.maxIdentities = maxIdentities;
	}
}

export interface IncidentRecorderWrapperFrontier {
	readonly maxIdentities: number;
	reserve(identity: IncidentRecorderWrapperFrontierIdentity): void;
	allocate(identity: IncidentRecorderWrapperFrontierIdentity, count: number): bigint;
}

class ProcessLifetimeWrapperFrontier implements IncidentRecorderWrapperFrontier {
	private readonly lastSequences = new Map<string, bigint>();

	constructor(readonly maxIdentities: number) {
		if (
			!Number.isSafeInteger(maxIdentities) ||
			maxIdentities < 1 ||
			maxIdentities > INCIDENT_RECORDER_WRAPPER_FRONTIER_MAX_IDENTITIES
		)
			throw new Error("Invalid incident recorder wrapper frontier capacity");
	}

	private key(identity: IncidentRecorderWrapperFrontierIdentity): string {
		return `${identity.runId}\0${identity.runToken}`;
	}

	reserve(identity: IncidentRecorderWrapperFrontierIdentity): void {
		const key = this.key(identity);
		if (this.lastSequences.has(key)) return;
		if (this.lastSequences.size >= this.maxIdentities)
			throw new IncidentRecorderWrapperFrontierSaturatedError(identity, this.maxIdentities);
		this.lastSequences.set(key, 0n);
	}

	allocate(identity: IncidentRecorderWrapperFrontierIdentity, count: number): bigint {
		if (!Number.isSafeInteger(count) || count < 1)
			throw new Error("Invalid incident recorder wrapper sequence count");
		const key = this.key(identity);
		const previous = this.lastSequences.get(key);
		if (previous === undefined) {
			this.reserve(identity);
			return this.allocate(identity, count);
		}
		const first = previous + 1n;
		const last = previous + BigInt(count);
		if (last > (1n << 64n) - 1n) throw new Error("Incident recorder wrapper sequence frontier overflowed");
		this.lastSequences.set(key, last);
		return first;
	}
}

/** A test- and embedding-friendly bounded frontier with the production rules. */
export function createIncidentRecorderWrapperFrontier(
	maxIdentities = INCIDENT_RECORDER_WRAPPER_FRONTIER_MAX_IDENTITIES,
): IncidentRecorderWrapperFrontier {
	return new ProcessLifetimeWrapperFrontier(maxIdentities);
}

// This module-level instance intentionally survives writer construction and
// teardown for the lifetime of the process. Wrapper sequences are therefore
// monotonic across writer replacement/recovery for one run identity.
const processLifetimeWrapperFrontier = createIncidentRecorderWrapperFrontier();

export interface IncidentRecorderServiceIdentity {
	runId: string;
	runToken: string;
}

/**
 * Raised when this writer cannot retain a new exact service-identity fence.
 * Existing fences and emitters remain usable; this is deliberately narrower
 * than a service-wide fail-closed state.
 */
export class IncidentRecorderServiceIdentitySealFenceSaturatedError extends Error {
	readonly code = "INCIDENT_RECORDER_SERVICE_IDENTITY_SEAL_FENCE_SATURATED" as const;
	readonly identity: Readonly<IncidentRecorderServiceIdentity>;
	readonly runId: string;
	readonly runToken: string;
	readonly maxIdentities: number;

	constructor(identity: IncidentRecorderServiceIdentity, maxIdentities: number) {
		super(`Incident recorder service identity seal fence is saturated at ${maxIdentities} identities`);
		this.name = "IncidentRecorderServiceIdentitySealFenceSaturatedError";
		this.identity = Object.freeze({ ...identity });
		this.runId = identity.runId;
		this.runToken = identity.runToken;
		this.maxIdentities = maxIdentities;
	}
}

interface ServiceIdentitySealFence {
	readonly maxIdentities: number;
	reserve(identity: IncidentRecorderServiceIdentity): void;
	has(identity: IncidentRecorderServiceIdentity): boolean;
}

class ExactServiceIdentitySealFence implements ServiceIdentitySealFence {
	private readonly keys = new Set<string>();

	constructor(readonly maxIdentities: number) {
		if (
			!Number.isSafeInteger(maxIdentities) ||
			maxIdentities < 1 ||
			maxIdentities > INCIDENT_RECORDER_SERVICE_SEAL_FENCE_MAX_IDENTITIES
		)
			throw new Error("Invalid incident recorder service identity seal fence capacity");
	}

	private key(identity: IncidentRecorderServiceIdentity): string {
		return `${identity.runId}\0${identity.runToken}`;
	}

	reserve(identity: IncidentRecorderServiceIdentity): void {
		const key = this.key(identity);
		if (this.keys.has(key)) return;
		if (this.keys.size >= this.maxIdentities)
			throw new IncidentRecorderServiceIdentitySealFenceSaturatedError(identity, this.maxIdentities);
		this.keys.add(key);
	}

	has(identity: IncidentRecorderServiceIdentity): boolean {
		return this.keys.has(this.key(identity));
	}
}

const DIAGNOSTIC_METADATA_MAX_BYTES = INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES - 1024;
const DIAGNOSTIC_CAUSAL_TEXT_MAX_BYTES = 96;
const DIAGNOSTIC_TEXT_MAX_BYTES = 512;
const DIAGNOSTIC_ERROR_NAME_MAX_BYTES = 96;
const DIAGNOSTIC_ERROR_MESSAGE_MAX_BYTES = 512;
const DIAGNOSTIC_ERROR_STACK_HASH_MAX_BYTES = 64 * 1024;

// These fields are ordered ahead of general diagnostics so a crowded metadata
// envelope retains the identities needed to correlate a daemon or kernel crash.
const DIAGNOSTIC_CAUSAL_SCALAR_KEYS = [
	"captureId",
	"origin",
	"supervisorGeneration",
	"workerPid",
	"workerProcessStartId",
	"childProcessStartId",
	"rootSessionId",
	"rootActiveSessionId",
	"sessionId",
	"activeSessionId",
	"kernelInstanceId",
	"kernelPid",
	"kernelProcessStartId",
	"executionId",
	"requestId",
	"requestMsgId",
	"toolCallId",
	"type",
	"exitOccurrenceId",
	"exitAdmissionReason",
	"tailOccurrenceId",
	"tailAdmissionReason",
	"tailCaptureStatus",
	"triggerOccurrenceId",
	"sourceBytes",
	"selectedSubjectsSha256",
	"membershipSha256",
	"retainedBytes",
	"classification",
	"causeLayer",
	"crashPhase",
	"launchMode",
	"channel",
] as const;
const DIAGNOSTIC_CAUSAL_SCALAR_KEY_SET = new Set<string>(DIAGNOSTIC_CAUSAL_SCALAR_KEYS);

// The producer hot path only reads this fixed set of data properties. It never walks
// arbitrary diagnostic objects or invokes getters supplied by product code.
const DIAGNOSTIC_SCALAR_KEYS = [
	"agentId",
	"attemptedBytes",
	"attemptedRecords",
	"bootId",
	"bounds",
	"bytes",
	"bytesSinceLastMarker",
	"cadenceMs",
	"category",
	"cgroupDirectory",
	"cgroupDev",
	"cgroupIno",
	"childPid",
	"clientId",
	"code",
	"command",
	"commandId",
	"commandType",
	"connectionId",
	"descriptorDir",
	"diagnosticOnly",
	"durationMs",
	"drainTimeoutLostBytes",
	"drainTimeoutLostRecords",
	"drainTimeoutUncertainBytes",
	"drainTimeoutUncertainRecords",
	"encoding",
	"format",
	"exitAdmissionReason",
	"exitOccurrenceId",
	"fd",
	"incompleteBytes",
	"launchBytes",
	"launchOccurrenceId",
	"lostBytes",
	"lostRecords",
	"message",
	"membershipSourcePath",
	"monotonicNs",
	"name",
	"nodeFatalReportsEnabled",
	"observedMonotonicNs",
	"observedWallTime",
	"originalPath",
	"outcome",
	"phase",
	"pid",
	"processStartId",
	"producerOccurrenceId",
	"provider",
	"rootPid",
	"rootProcessStartId",
	"reason",
	"recordsSinceLastMarker",
	"registrationOnly",
	"requestType",
	"runId",
	"runName",
	"signal",
	"socketExists",
	"socketPath",
	"source",
	"sourceBytes",
	"retainedBytes",
	"sourceTruncated",
	"stderrCaptureStatus",
	"stderrCaptureComplete",
	"stderrSha256",
	"transportCorruptPackets",
	"transportCorruptPacketsSinceLastMarker",
	"transportCorruptWireBytes",
	"transportCorruptWireBytesSinceLastMarker",
	"transportMissingPackets",
	"transportMissingPacketsSinceLastMarker",
	"transportSequenceGapEvents",
	"transportSequenceGapEventsSinceLastMarker",
	"protocolClientId",
	"sourcePath",
	"sourceIndex",
	"subjectCount",
	"recordCount",
	"errorCount",
	"directoryEntriesSeen",
	"descriptorLimit",
	"livePopulation",
	"coherentSnapshot",
	"treeCompleteness",
	"beforeDev",
	"beforeIno",
	"beforeSize",
	"beforeMtimeNs",
	"afterDev",
	"afterIno",
	"afterSize",
	"afterMtimeNs",
	"grew",
	"shrank",
	"changedDuringRead",
	"additiveOnly",
	"sourceProducerId",
	"state",
	"tailAdmissionReason",
	"tailCaptureStatus",
	"tailOccurrenceId",
	"targetPid",
	"targetProcessStartId",
	"thresholdMs",
	"timeoutMs",
	"type",
	"wallTime",
	"workerId",
	"queueOverflow",
	"evictedNormal",
	"criticalOverflow",
	"oversize",
	"encodeFailure",
	"transportError",
	"shutdown",
	"droppedFrames",
	"expectedSequence",
	"observedSequence",
	"wrapperPid",
	"wrapperStartId",
	"payloadState",
	"payloadBytes",
	"payloadStoredBytes",
	"payloadNodes",
	"payloadProperties",
	"payloadOmissions",
	"payloadUnsupported",
	"payloadAccessorOmissions",
	"payloadDepthOmissions",
	"payloadStringTruncations",
	"payloadBinaryTruncations",
	"payloadUnavailable",
] as const;
const DIAGNOSTIC_PAYLOAD_SUMMARY_KEYS = [
	"payloadState",
	"payloadBytes",
	"payloadStoredBytes",
	"payloadNodes",
	"payloadProperties",
	"payloadOmissions",
	"payloadUnsupported",
	"payloadAccessorOmissions",
	"payloadDepthOmissions",
	"payloadStringTruncations",
	"payloadBinaryTruncations",
	"payloadUnavailable",
] as const;
const DIAGNOSTIC_PAYLOAD_SUMMARY_KEY_SET = new Set<string>(DIAGNOSTIC_PAYLOAD_SUMMARY_KEYS);

function linuxIdentity(path: string, pattern: RegExp): string | undefined {
	if (process.platform !== "linux") return undefined;
	try {
		const value = readFileSync(path, "utf8").trim();
		return pattern.test(value) ? value : undefined;
	} catch {
		return undefined;
	}
}

function linuxProcessStartId(pid: number): string | undefined {
	if (!Number.isSafeInteger(pid) || pid <= 0 || process.platform !== "linux") return undefined;
	try {
		const value = readFileSync(`/proc/${pid}/stat`, "utf8");
		const commandEnd = value.lastIndexOf(")");
		const startTime = value.slice(commandEnd + 2).split(" ")[19];
		return startTime ? `proc:${startTime}` : undefined;
	} catch {
		return undefined;
	}
}

interface DescriptorIdentity {
	device: string;
	inode: string;
}

interface CaptureOwnerClaim {
	schemaVersion: 1;
	runId: string;
	runToken: string;
	machineId: string;
	bootId: string;
	pid: number;
	processStartId: string;
	ownerNonce: string;
	rootDevice: string;
	rootInode: string;
	captureDevice: string;
	captureInode: string;
}

const CAPTURE_OWNER_CLAIM_MAX_BYTES = 4 * 1024;

function descriptorIdentity(fd: number, expected: "directory" | "capture"): DescriptorIdentity | undefined {
	try {
		const stat = fstatSync(fd, { bigint: true });
		if (expected === "directory" && !stat.isDirectory()) return undefined;
		// fd4 is currently a pipe. Keep the capability check transport-neutral, but
		// never accept a directory as the capture channel.
		if (expected === "capture" && stat.isDirectory()) return undefined;
		return { device: stat.dev.toString(), inode: stat.ino.toString() };
	} catch {
		return undefined;
	}
}

function sameDescriptorIdentity(actual: DescriptorIdentity | undefined, device: string, inode: string): boolean {
	return actual?.device === device && actual.inode === inode;
}

export function incidentRecorderCaptureOwnerClaimFileName(fd = INCIDENT_RECORDER_CAPTURE_FD): string | undefined {
	const identity = descriptorIdentity(fd, "capture");
	return identity
		? `${INCIDENT_RECORDER_CAPTURE_OWNER_CLAIM_FILE}.${identity.device}.${identity.inode}.json`
		: undefined;
}

function readCaptureOwnerClaim(path: string): Partial<CaptureOwnerClaim> | undefined {
	let descriptor: number | undefined;
	try {
		const before = lstatSync(path, { bigint: true });
		if (
			!before.isFile() ||
			before.isSymbolicLink() ||
			before.nlink !== 1n ||
			before.size <= 0n ||
			before.size > BigInt(CAPTURE_OWNER_CLAIM_MAX_BYTES)
		)
			return undefined;
		if (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) return undefined;
		if ((before.mode & 0o077n) !== 0n) return undefined;
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const opened = fstatSync(descriptor, { bigint: true });
		if (
			!opened.isFile() ||
			opened.nlink !== 1n ||
			opened.dev !== before.dev ||
			opened.ino !== before.ino ||
			opened.size !== before.size
		)
			return undefined;
		if (typeof process.getuid === "function" && opened.uid !== BigInt(process.getuid())) return undefined;
		if ((opened.mode & 0o077n) !== 0n) return undefined;
		const bytes = Buffer.alloc(Number(opened.size) + 1);
		let offset = 0;
		while (offset < bytes.length) {
			const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
			if (count === 0) break;
			offset += count;
		}
		if (offset !== Number(opened.size) || offset > CAPTURE_OWNER_CLAIM_MAX_BYTES) return undefined;
		const after = fstatSync(descriptor, { bigint: true });
		if (after.dev !== opened.dev || after.ino !== opened.ino || after.nlink !== 1n || after.size !== opened.size)
			return undefined;
		if (typeof process.getuid === "function" && after.uid !== BigInt(process.getuid())) return undefined;
		if ((after.mode & 0o077n) !== 0n) return undefined;
		return JSON.parse(bytes.subarray(0, offset).toString("utf8")) as Partial<CaptureOwnerClaim>;
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

class CaptureOwnerGuard {
	constructor(
		private readonly path: string,
		private readonly expected: CaptureOwnerClaim,
	) {}

	validCheap(): boolean {
		return (
			process.pid === this.expected.pid &&
			sameDescriptorIdentity(
				descriptorIdentity(INCIDENT_RECORDER_ROOT_FD, "directory"),
				this.expected.rootDevice,
				this.expected.rootInode,
			) &&
			sameDescriptorIdentity(
				descriptorIdentity(INCIDENT_RECORDER_CAPTURE_FD, "capture"),
				this.expected.captureDevice,
				this.expected.captureInode,
			)
		);
	}

	validAdmission(): boolean {
		if (!this.validCheap() || linuxProcessStartId(process.pid) !== this.expected.processStartId) return false;
		const value = readCaptureOwnerClaim(this.path);
		return (
			value?.schemaVersion === this.expected.schemaVersion &&
			value.runId === this.expected.runId &&
			value.runToken === this.expected.runToken &&
			value.machineId === this.expected.machineId &&
			value.bootId === this.expected.bootId &&
			value.pid === this.expected.pid &&
			value.processStartId === this.expected.processStartId &&
			value.ownerNonce === this.expected.ownerNonce &&
			value.rootDevice === this.expected.rootDevice &&
			value.rootInode === this.expected.rootInode &&
			value.captureDevice === this.expected.captureDevice &&
			value.captureInode === this.expected.captureInode
		);
	}

	release(): boolean {
		if (!this.validAdmission()) return false;
		try {
			const stat = lstatSync(this.path, { bigint: true });
			if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) return false;
			if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) return false;
			if ((stat.mode & 0o077n) !== 0n || !this.validAdmission()) return false;
			unlinkSync(this.path);
			fsyncSync(INCIDENT_RECORDER_ROOT_FD);
			return true;
		} catch {
			return false;
		}
	}
}

function claimCaptureOwner(runId: string, runToken: string): CaptureOwnerGuard | undefined {
	if (process.platform !== "linux") return undefined;
	const processStartId = linuxProcessStartId(process.pid);
	const machineId = linuxIdentity("/etc/machine-id", /^[0-9a-f]{32}$/i);
	const bootId = linuxIdentity("/proc/sys/kernel/random/boot_id", /^[0-9a-f-]{36}$/i);
	const root = descriptorIdentity(INCIDENT_RECORDER_ROOT_FD, "directory");
	const capture = descriptorIdentity(INCIDENT_RECORDER_CAPTURE_FD, "capture");
	if (!processStartId || !machineId || !bootId || !root || !capture) return undefined;
	const claim: CaptureOwnerClaim = {
		schemaVersion: 1,
		runId,
		runToken,
		machineId,
		bootId,
		pid: process.pid,
		processStartId,
		ownerNonce: newIncidentRecorderIdentity(),
		rootDevice: root.device,
		rootInode: root.inode,
		captureDevice: capture.device,
		captureInode: capture.inode,
	};
	const claimFileName = incidentRecorderCaptureOwnerClaimFileName();
	if (!claimFileName) return undefined;
	const path = `/proc/self/fd/${INCIDENT_RECORDER_ROOT_FD}/${claimFileName}`;
	let descriptor: number | undefined;
	try {
		descriptor = openSync(
			path,
			fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
			0o600,
		);
		const created = fstatSync(descriptor, { bigint: true });
		if (!created.isFile() || created.nlink !== 1n) return undefined;
		writeFileSync(
			descriptor,
			`${JSON.stringify(claim)}
`,
			{ encoding: "utf8" },
		);
		fsyncSync(descriptor);
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
	try {
		fsyncSync(INCIDENT_RECORDER_ROOT_FD);
	} catch {
		return undefined;
	}
	const guard = new CaptureOwnerGuard(path, claim);
	return guard.validAdmission() ? guard : undefined;
}

type OwnDataProperty = { found: true; value: unknown } | { found: false };

function ownDataProperty(value: object, key: string): OwnDataProperty {
	try {
		const descriptor = Object.getOwnPropertyDescriptor(value, key);
		return descriptor && "value" in descriptor ? { found: true, value: descriptor.value } : { found: false };
	} catch {
		return { found: false };
	}
}

function boundedUtf8(value: string, maximumBytes: number): { value: string; truncated: boolean } {
	if (value.length <= maximumBytes && Buffer.byteLength(value) <= maximumBytes) {
		return { value, truncated: false };
	}
	let low = 0;
	let high = Math.min(value.length, maximumBytes);
	while (low < high) {
		const middle = Math.ceil((low + high) / 2);
		if (Buffer.byteLength(value.slice(0, middle)) <= maximumBytes) low = middle;
		else high = middle - 1;
	}
	// Never end on the first half of a surrogate pair. Buffer would otherwise
	// replace it, making the retained diagnostic prefix ambiguous.
	if (low > 0 && /[\uD800-\uDBFF]/.test(value[low - 1])) low -= 1;
	return { value: value.slice(0, low), truncated: low < value.length };
}

function scalarValue(value: unknown, stringMaximumBytes: number): { value?: Scalar; truncated: boolean } {
	if (value === null || typeof value === "boolean") return { value, truncated: false };
	if (typeof value === "number" && Number.isFinite(value)) return { value, truncated: false };
	if (typeof value === "string") return boundedUtf8(value, stringMaximumBytes);
	return { truncated: false };
}

function metadataBytes(metadata: Readonly<Record<string, Scalar>>): number {
	return Buffer.byteLength(JSON.stringify(metadata));
}

function addMetadataValue(
	result: Record<string, Scalar>,
	key: string,
	value: Scalar,
	reserved?: Readonly<Record<string, Scalar>>,
): boolean {
	result[key] = value;
	if (
		metadataBytes(result) <= DIAGNOSTIC_METADATA_MAX_BYTES &&
		(reserved === undefined || metadataBytes({ ...result, ...reserved }) <= DIAGNOSTIC_METADATA_MAX_BYTES)
	)
		return true;
	delete result[key];
	return false;
}

function replaceMetadataValue(result: Record<string, Scalar>, key: string, value: Scalar): boolean {
	const previous = result[key];
	result[key] = value;
	if (metadataBytes(result) <= DIAGNOSTIC_METADATA_MAX_BYTES) return true;
	if (previous === undefined) delete result[key];
	else result[key] = previous;
	return false;
}

function payloadSummaryMetadata(
	summary: IncidentRecorderDiagnosticPayloadSummary,
	state: IncidentRecorderDiagnosticPayloadState | "queue_dropped" = summary.state,
	storedBytes = summary.storedBytes,
): Record<string, Scalar> {
	return {
		payloadState: state,
		payloadBytes: summary.bytes,
		payloadStoredBytes: storedBytes,
		payloadNodes: summary.nodes,
		payloadProperties: summary.properties,
		payloadOmissions: summary.omissions,
		payloadUnsupported: summary.unsupported,
		payloadAccessorOmissions: summary.accessorOmissions,
		payloadDepthOmissions: summary.depthOmissions,
		payloadStringTruncations: summary.stringTruncations,
		payloadBinaryTruncations: summary.binaryTruncations,
		payloadUnavailable: summary.unavailable,
	};
}

function normalizeErrorMetadata(
	fields: Record<string, unknown>,
	result: Record<string, Scalar>,
	markTruncated: () => void,
	reserved?: Readonly<Record<string, Scalar>>,
): void {
	const errorProperty = ownDataProperty(fields, "error");
	if (!errorProperty.found) return;
	const error = errorProperty.value;
	if (typeof error === "string") {
		const message = boundedUtf8(error, DIAGNOSTIC_ERROR_MESSAGE_MAX_BYTES);
		if (!addMetadataValue(result, "errorName", "Error", reserved)) markTruncated();
		if (!addMetadataValue(result, "errorMessage", message.value, reserved)) markTruncated();
		if (!addMetadataValue(result, "errorMessageTruncated", message.truncated, reserved)) markTruncated();
		if (message.truncated) markTruncated();
		return;
	}
	if ((typeof error !== "object" && typeof error !== "function") || error === null) return;

	const nameProperty = ownDataProperty(error, "name");
	const messageProperty = ownDataProperty(error, "message");
	const stackProperty = ownDataProperty(error, "stack");
	const hasMessage = messageProperty.found && typeof messageProperty.value === "string";
	const hasStack = stackProperty.found && typeof stackProperty.value === "string";
	if (!nameProperty.found && !hasMessage && !hasStack) return;

	const rawName = nameProperty.found && typeof nameProperty.value === "string" ? nameProperty.value : "Error";
	const name = boundedUtf8(rawName, DIAGNOSTIC_ERROR_NAME_MAX_BYTES);
	if (!addMetadataValue(result, "errorName", name.value, reserved)) markTruncated();
	if (name.truncated) markTruncated();

	if (hasMessage) {
		const message = boundedUtf8(messageProperty.value as string, DIAGNOSTIC_ERROR_MESSAGE_MAX_BYTES);
		if (!addMetadataValue(result, "errorMessage", message.value, reserved)) markTruncated();
		if (!addMetadataValue(result, "errorMessageTruncated", message.truncated, reserved)) markTruncated();
		if (message.truncated) markTruncated();
	}
	if (hasStack) {
		const stack = boundedUtf8(stackProperty.value as string, DIAGNOSTIC_ERROR_STACK_HASH_MAX_BYTES);
		const digest = createHash("sha256").update(stack.value).digest("hex");
		if (!addMetadataValue(result, "errorStackSha256", digest, reserved)) markTruncated();
		if (
			!addMetadataValue(result, "errorStackDigestScope", stack.truncated ? "retained_prefix" : "complete", reserved)
		)
			markTruncated();
		if (!addMetadataValue(result, "errorStackTruncated", stack.truncated, reserved)) markTruncated();
		if (stack.truncated) markTruncated();
	}
}

function scalarMetadata(
	fields: Record<string, unknown>,
	payloadSummary?: IncidentRecorderDiagnosticPayloadSummary,
): Record<string, Scalar> {
	const result: Record<string, Scalar> = { diagnosticMetadataTruncated: false };
	// A body that is rejected later is relabeled queue_dropped. Reserve that
	// longer state, while retaining the original stored-byte value as the
	// conservative fallback envelope bound.
	const reserved = payloadSummary === undefined ? undefined : payloadSummaryMetadata(payloadSummary, "queue_dropped");
	const markTruncated = (): void => {
		result.diagnosticMetadataTruncated = true;
	};
	for (const key of DIAGNOSTIC_CAUSAL_SCALAR_KEYS) {
		const property = ownDataProperty(fields, key);
		if (!property.found) continue;
		const normalized = scalarValue(property.value, DIAGNOSTIC_CAUSAL_TEXT_MAX_BYTES);
		if (normalized.value !== undefined && !addMetadataValue(result, key, normalized.value, reserved)) markTruncated();
		if (normalized.truncated) markTruncated();
	}
	normalizeErrorMetadata(fields, result, markTruncated, reserved);
	if (payloadSummary !== undefined) addDiagnosticPayloadSummary(result, payloadSummary);
	for (const key of DIAGNOSTIC_SCALAR_KEYS) {
		if (DIAGNOSTIC_CAUSAL_SCALAR_KEY_SET.has(key) || DIAGNOSTIC_PAYLOAD_SUMMARY_KEY_SET.has(key)) continue;
		const property = ownDataProperty(fields, key);
		if (!property.found) continue;
		const normalized = scalarValue(property.value, DIAGNOSTIC_TEXT_MAX_BYTES);
		if (normalized.value !== undefined && !addMetadataValue(result, key, normalized.value, reserved)) markTruncated();
		if (normalized.truncated) markTruncated();
	}
	return result;
}

function addDiagnosticPayloadSummary(
	metadata: Record<string, Scalar>,
	summary: IncidentRecorderDiagnosticPayloadSummary,
	state: "serialized" | "unavailable" | "queue_dropped" = summary.state,
	storedBytes = summary.storedBytes,
): void {
	const values = Object.entries(payloadSummaryMetadata(summary, state, storedBytes));
	for (const [key, value] of values) {
		if (!replaceMetadataValue(metadata, key, value)) metadata.diagnosticMetadataTruncated = true;
	}
}

function configuredEmitterMaximum(): number {
	const value = Number(process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES);
	return Number.isSafeInteger(value) && value >= 256 * 1024
		? Math.min(value, INCIDENT_RECORDER_EMITTER_MAX_BYTES)
		: INCIDENT_RECORDER_EMITTER_MAX_BYTES;
}

export type IncidentRecorderAdmission =
	| { accepted: true; occurrenceId: string; disposition: "locally_admitted" }
	| {
			accepted: false;
			disposition: "rejected";
			reason:
				| "stopped"
				| "terminal_reserved"
				| "occurrence_too_large"
				| "queue_capacity"
				| "encoding_failed"
				| "run_identity_sealed";
	  };

interface ProducerCounters {
	attemptedRecords: number;
	attemptedBytes: number;
	queuedRecords: number;
	queuedBytes: number;
	droppedRecords: number;
	droppedBytes: number;
}

interface BoundedFrameEmitterStopResult {
	terminalAdmission?: IncidentRecorderAdmission;
	totalLoss: { records: number; bytes: number };
	drainTimeoutLoss: { records: number; bytes: number };
	drainTimeoutUncertainty: { records: number; bytes: number };
	terminalDrained: boolean;
}

interface OutboundOccurrence {
	occurrenceId: string;
	source: string;
	type: string;
	bytes: Buffer;
	payloadKind: IncidentRecorderPayloadKind;
	encoding: string;
	metadata: ScalarMetadata;
	reserved: boolean;
	terminal: boolean;
	chunkCount: number;
	firstSequence: bigint;
	wallTimeMs: bigint;
	monotonicNs: bigint;
	estimatedWireBytes: number;
	lossSnapshot?: { records: number; bytes: number };
}

class BoundedFrameEmitter {
	private readonly producerId = newIncidentRecorderIdentity();
	private readonly producerStartId = linuxProcessStartId(process.pid) ?? "unavailable";
	private readonly queue: OutboundOccurrence[] = [];
	private queuedBytes = 0;
	private inFlightBytes = 0;
	private sequence = 0n;
	private writing = false;
	private stopping = false;
	private stopped = false;
	private terminalQueued = false;
	private reportedLostRecords = 0;
	private reportedLostBytes = 0;
	private lossCheckpointInProgress = false;
	private lossCheckpointQueued = false;
	private lossCheckpointRetry?: ReturnType<typeof setTimeout>;
	private lossCheckpointNextAttemptMs = 0;
	private readonly counters: ProducerCounters = {
		attemptedRecords: 0,
		attemptedBytes: 0,
		queuedRecords: 0,
		queuedBytes: 0,
		droppedRecords: 0,
		droppedBytes: 0,
	};
	private drainWaiters: Array<() => void> = [];
	private stopOperation?: Promise<BoundedFrameEmitterStopResult>;

	constructor(
		private readonly writeOccurrence: (
			frames: readonly IncidentRecorderEncodedFrame[],
			callback: (error?: Error) => void,
		) => void,
		private readonly maximumBytes: number,
		private readonly identity: { runId: string; runToken: string },
		private readonly validateOwner: () => boolean = () => true,
		private readonly validateAdmission: () => boolean = validateOwner,
	) {}

	private ownerIsValid(): boolean {
		try {
			return this.validateOwner();
		} catch {
			return false;
		}
	}

	private admissionIsValid(): boolean {
		try {
			return this.validateAdmission();
		} catch {
			return false;
		}
	}

	private disableInvalidOwner(): void {
		this.stopped = true;
		this.writing = false;
		this.inFlightBytes = 0;
		this.queue.length = 0;
		this.queuedBytes = 0;
		if (this.lossCheckpointRetry) clearTimeout(this.lossCheckpointRetry);
		this.lossCheckpointRetry = undefined;
		for (const resolve of this.drainWaiters.splice(0)) resolve();
	}

	fenceWithoutTerminal(): void {
		this.disableInvalidOwner();
	}

	emitDerived(
		source: CaptureSource,
		type: string,
		fields: Record<string, unknown>,
		occurrenceIdOverride?: string,
	): IncidentRecorderAdmission {
		if (occurrenceIdOverride !== undefined && !CANONICAL_INCIDENT_RECORDER_ID.test(occurrenceIdOverride))
			throw new Error("Invalid incident-recorder occurrence identity");
		const serialized = serializeIncidentRecorderDiagnostic(fields);
		const metadata = scalarMetadata(fields, serialized.summary);
		const admission = this.emitOccurrence(
			source,
			type,
			serialized.bytes,
			"derived-scalar",
			"utf8-json/derived-diagnostic-json-v2",
			metadata,
			false,
			false,
			false,
			occurrenceIdOverride,
		);
		if (admission.accepted || (admission.reason !== "queue_capacity" && admission.reason !== "occurrence_too_large"))
			return admission;
		// Keep causal scalar metadata when the body cannot enter the bounded queue.
		// The discarded serialized bytes are already counted by emitOccurrence; this
		// second, empty occurrence is a scalar-only fallback and is not a duplicate.
		addDiagnosticPayloadSummary(metadata, serialized.summary, "queue_dropped", 0);
		return this.emitOccurrence(
			source,
			type,
			Buffer.alloc(0),
			"derived-scalar",
			"none",
			metadata,
			false,
			false,
			false,
			occurrenceIdOverride,
		);
	}

	emitBytes(
		source: CaptureSource,
		type: string,
		bytes: Uint8Array,
		metadata: Record<string, unknown>,
		encoding = "exact-bytes",
	): IncidentRecorderAdmission {
		return this.emitOccurrence(source, type, bytes, "exact-bytes", encoding, scalarMetadata(metadata));
	}

	emitControl(type: string, fields: Record<string, unknown>, terminal = false): IncidentRecorderAdmission {
		return this.emitOccurrence(
			"recorder-control",
			type,
			Buffer.alloc(0),
			"control",
			"none",
			scalarMetadata(fields),
			true,
			terminal,
		);
	}

	private emitOccurrence(
		source: string,
		type: string,
		bytes: Uint8Array,
		payloadKind: IncidentRecorderPayloadKind,
		encoding: string,
		metadata: ScalarMetadata,
		reserved = false,
		terminal = false,
		internalDuringStop = false,
		occurrenceIdOverride?: string,
	): IncidentRecorderAdmission {
		this.counters.attemptedRecords += 1;
		this.counters.attemptedBytes += bytes.byteLength;
		const rejected = (
			reason: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"],
			scheduleLoss = true,
		): IncidentRecorderAdmission => {
			this.noteDrop(bytes.byteLength, scheduleLoss);
			return { accepted: false, disposition: "rejected", reason };
		};
		// Admission performs the durable claim read. Async encoding and each fd write
		// use only the cheap process/fd identity guard.
		if (!this.admissionIsValid()) {
			const admission = rejected("stopped", false);
			this.disableInvalidOwner();
			return admission;
		}
		if (this.stopped) return rejected("stopped", false);
		if (this.stopping && !internalDuringStop) return rejected("terminal_reserved", false);
		if (this.terminalQueued) return rejected("terminal_reserved", false);
		if (bytes.byteLength > INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES) return rejected("occurrence_too_large");
		const chunkCount = Math.max(1, Math.ceil(bytes.byteLength / INCIDENT_RECORDER_EMITTER_CHUNK_BYTES));
		const estimatedDecodedBytes =
			chunkCount * (INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES + 3 * 255 + 4096) + bytes.byteLength;
		const estimatedWireBytes = estimatedDecodedBytes + Math.floor(estimatedDecodedBytes / 254) + 2 * chunkCount;
		const ceiling = reserved ? this.maximumBytes : this.maximumBytes - CONTROL_RESERVE_BYTES;
		if (estimatedWireBytes > ceiling || this.queuedBytes + this.inFlightBytes + estimatedWireBytes > ceiling)
			return rejected("queue_capacity");
		let ownedBytes: Buffer;
		try {
			// Always detach from the caller's view. This avoids both later mutation and a
			// small slice retaining an arbitrarily large caller-owned ArrayBuffer.
			ownedBytes = Buffer.from(bytes);
		} catch {
			return rejected("encoding_failed");
		}
		const occurrenceId = occurrenceIdOverride ?? newIncidentRecorderIdentity();
		const firstSequence = this.sequence + 1n;
		this.sequence += BigInt(chunkCount);
		this.counters.queuedRecords += 1;
		this.counters.queuedBytes += ownedBytes.length;
		const occurrenceMetadata: ScalarMetadata = Object.freeze({
			...metadata,
			attemptedRecords: this.counters.attemptedRecords,
			attemptedBytes: this.counters.attemptedBytes,
			queuedRecords: this.counters.queuedRecords,
			queuedBytes: this.counters.queuedBytes,
			droppedRecords: this.counters.droppedRecords,
			droppedBytes: this.counters.droppedBytes,
			producerPid: process.pid,
			producerStartId: this.producerStartId,
			queueDisposition: "locally_admitted",
		});
		const item: OutboundOccurrence = {
			occurrenceId,
			source,
			type,
			bytes: ownedBytes,
			payloadKind,
			encoding,
			metadata: occurrenceMetadata,
			reserved,
			terminal,
			chunkCount,
			firstSequence,
			wallTimeMs: BigInt(Date.now()),
			monotonicNs: process.hrtime.bigint(),
			estimatedWireBytes,
		};
		this.queue.push(item);
		this.queuedBytes += estimatedWireBytes;
		if (terminal) this.terminalQueued = true;
		this.pump();
		return { accepted: true, occurrenceId, disposition: "locally_admitted" };
	}

	private noteDrop(bytes: number, scheduleLoss = true): void {
		this.counters.droppedRecords += 1;
		this.counters.droppedBytes += bytes;
		if (scheduleLoss) this.scheduleLossCheckpoint();
	}

	private scheduleLossCheckpoint(): void {
		if (!this.ownerIsValid()) {
			this.disableInvalidOwner();
			return;
		}
		if (
			this.stopped ||
			this.stopping ||
			this.terminalQueued ||
			this.lossCheckpointQueued ||
			this.lossCheckpointInProgress ||
			this.lossCheckpointRetry ||
			this.counters.droppedRecords === this.reportedLostRecords
		)
			return;
		const delay = Math.max(1, this.lossCheckpointNextAttemptMs - Date.now());
		this.lossCheckpointRetry = setTimeout(() => {
			this.lossCheckpointRetry = undefined;
			this.enqueueLossCheckpoint();
		}, delay);
		this.lossCheckpointRetry.unref();
	}

	private enqueueLossCheckpoint(internalDuringStop = false): void {
		if (!this.ownerIsValid()) {
			this.disableInvalidOwner();
			return;
		}
		if (
			this.stopped ||
			this.terminalQueued ||
			(this.stopping && !internalDuringStop) ||
			this.lossCheckpointQueued ||
			this.counters.droppedRecords === this.reportedLostRecords
		)
			return;
		if (!internalDuringStop && Date.now() < this.lossCheckpointNextAttemptMs) {
			this.scheduleLossCheckpoint();
			return;
		}
		const records = this.counters.droppedRecords;
		const bytes = this.counters.droppedBytes;
		this.lossCheckpointNextAttemptMs = Date.now() + 1_000;
		this.lossCheckpointInProgress = true;
		const admission = this.emitOccurrence(
			"loss-accounting",
			"capture_channel_loss_checkpoint",
			Buffer.alloc(0),
			"loss",
			"none",
			{
				lostRecords: records,
				lostBytes: bytes,
				recordsSinceLastMarker: records - this.reportedLostRecords,
				bytesSinceLastMarker: bytes - this.reportedLostBytes,
			},
			true,
			false,
			internalDuringStop,
		);
		this.lossCheckpointInProgress = false;
		if (!admission.accepted) {
			if (!this.stopping) this.scheduleLossCheckpoint();
			return;
		}
		const item = this.queue.at(-1);
		if (item?.occurrenceId === admission.occurrenceId) {
			item.lossSnapshot = { records, bytes };
			this.lossCheckpointQueued = true;
		}
	}

	private buildFrames(
		item: OutboundOccurrence,
		complete: (frames?: IncidentRecorderEncodedFrame[], error?: Error) => void,
	): void {
		const hash = createHash("sha256");
		let hashIndex = 0;
		const hashNext = (): void => {
			if (!this.ownerIsValid()) {
				this.disableInvalidOwner();
				complete(undefined, new Error("Incident recorder capture owner changed"));
				return;
			}
			const start = hashIndex * INCIDENT_RECORDER_EMITTER_CHUNK_BYTES;
			if (start >= item.bytes.length) {
				const digest = hash.digest("hex");
				const occurrenceMetadata: ScalarMetadata = Object.freeze({
					...item.metadata,
					occurrenceRawBytes: item.bytes.length,
					occurrenceSha256: digest,
				});
				const frames: IncidentRecorderEncodedFrame[] = [];
				let index = 0;
				const encodeNext = (): void => {
					if (!this.ownerIsValid()) {
						this.disableInvalidOwner();
						complete(undefined, new Error("Incident recorder capture owner changed"));
						return;
					}
					if (index >= item.chunkCount) {
						complete(frames);
						return;
					}
					const chunkStart = index * INCIDENT_RECORDER_EMITTER_CHUNK_BYTES;
					const payload = item.bytes.subarray(
						chunkStart,
						Math.min(item.bytes.length, chunkStart + INCIDENT_RECORDER_EMITTER_CHUNK_BYTES),
					);
					try {
						frames.push(
							encodeIncidentRecorderFrame(
								{
									runId: this.identity.runId,
									runToken: this.identity.runToken,
									producerId: this.producerId,
									occurrenceId: item.occurrenceId,
									producerSequence: item.firstSequence + BigInt(index),
									wallTimeMs: item.wallTimeMs,
									monotonicNs: item.monotonicNs,
									payloadKind: item.payloadKind,
									flags:
										(item.terminal ? INCIDENT_RECORDER_FRAME_FLAGS.terminal : 0) |
										(index === 0 ? INCIDENT_RECORDER_FRAME_FLAGS.firstChunk : 0) |
										(index === item.chunkCount - 1 ? INCIDENT_RECORDER_FRAME_FLAGS.lastChunk : 0),
									chunkIndex: index,
									chunkCount: item.chunkCount,
									source: item.source,
									type: item.type,
									encoding: item.encoding,
									metadata: occurrenceMetadata,
								},
								payload,
							),
						);
					} catch (error) {
						complete(undefined, error instanceof Error ? error : new Error(String(error)));
						return;
					}
					index += 1;
					setImmediate(encodeNext);
				};
				setImmediate(encodeNext);
				return;
			}
			const end = Math.min(item.bytes.length, start + INCIDENT_RECORDER_EMITTER_CHUNK_BYTES);
			hash.update(item.bytes.subarray(start, end));
			hashIndex += 1;
			setImmediate(hashNext);
		};
		setImmediate(hashNext);
	}

	private pump(): void {
		if (!this.ownerIsValid()) {
			this.disableInvalidOwner();
			return;
		}
		if (this.writing) return;
		this.enqueueLossCheckpoint();
		const item = this.queue[0];
		if (!item) {
			for (const resolve of this.drainWaiters.splice(0)) resolve();
			return;
		}
		this.writing = true;
		this.inFlightBytes = item.estimatedWireBytes;
		this.buildFrames(item, (frames, buildError) => {
			if (buildError || !frames) {
				this.finishItem(item, buildError ?? new Error("Incident occurrence encoding failed"));
				return;
			}
			this.writeOccurrence(frames, (error) => this.finishItem(item, error));
		});
	}

	private finishItem(item: OutboundOccurrence, error?: Error): void {
		if (!this.ownerIsValid()) {
			this.disableInvalidOwner();
			return;
		}
		this.writing = false;
		this.inFlightBytes = 0;
		const wasHead = this.queue[0] === item;
		if (wasHead) {
			this.queue.shift();
			this.queuedBytes = Math.max(0, this.queuedBytes - item.estimatedWireBytes);
		}
		if (!wasHead) {
			this.pump();
			return;
		}
		if (error) {
			if (item.lossSnapshot) this.lossCheckpointQueued = false;
			this.noteDrop(item.bytes.length);
		} else if (item.lossSnapshot) {
			this.reportedLostRecords = item.lossSnapshot.records;
			this.reportedLostBytes = item.lossSnapshot.bytes;
			this.lossCheckpointQueued = false;
			this.scheduleLossCheckpoint();
		}
		this.pump();
	}

	async flush(deadlineMs = 1_000): Promise<boolean> {
		if (!this.ownerIsValid()) {
			this.disableInvalidOwner();
			return false;
		}
		this.pump();
		if (!this.writing && this.queue.length === 0) return true;
		await Promise.race([
			new Promise<void>((resolve) => this.drainWaiters.push(resolve)),
			new Promise<void>((resolve) => setTimeout(resolve, deadlineMs).unref()),
		]);
		return !this.writing && this.queue.length === 0;
	}

	lossCounters(): { records: number; bytes: number } {
		return { records: this.counters.droppedRecords, bytes: this.counters.droppedBytes };
	}

	stop(deadlineMs = 1_000, terminalOccurrenceId?: string): Promise<BoundedFrameEmitterStopResult> {
		this.stopOperation ??= this.stopOnce(deadlineMs, terminalOccurrenceId);
		return this.stopOperation;
	}

	private async stopOnce(deadlineMs: number, terminalOccurrenceId?: string): Promise<BoundedFrameEmitterStopResult> {
		if (terminalOccurrenceId !== undefined && !CANONICAL_INCIDENT_RECORDER_ID.test(terminalOccurrenceId)) {
			throw new Error("Invalid incident-recorder terminal occurrence identity");
		}
		if (!this.ownerIsValid()) {
			this.disableInvalidOwner();
			return {
				totalLoss: this.lossCounters(),
				drainTimeoutLoss: { records: 0, bytes: 0 },
				drainTimeoutUncertainty: { records: 0, bytes: 0 },
				terminalDrained: false,
			};
		}
		if (this.stopped || this.stopping)
			return {
				totalLoss: this.lossCounters(),
				drainTimeoutLoss: { records: 0, bytes: 0 },
				drainTimeoutUncertainty: { records: 0, bytes: 0 },
				terminalDrained: false,
			};
		this.stopping = true;
		if (this.lossCheckpointRetry) clearTimeout(this.lossCheckpointRetry);
		this.lossCheckpointRetry = undefined;

		// Drain admitted product occurrences before taking the terminal snapshot. Calls
		// arriving during this phase are rejected and counted, so the final loss marker
		// and terminal record include them instead of freezing stale counters.
		const drained = await this.flush(deadlineMs);
		let drainTimeoutLostRecords = 0;
		let drainTimeoutLostBytes = 0;
		let drainTimeoutUncertainRecords = 0;
		let drainTimeoutUncertainBytes = 0;
		if (!drained) {
			const stranded = [...this.queue];
			if (stranded.some((item) => item.lossSnapshot)) this.lossCheckpointQueued = false;
			let firstDefiniteLoss = 0;
			if (this.writing && stranded[0]) {
				drainTimeoutUncertainRecords = 1;
				drainTimeoutUncertainBytes = stranded[0].bytes.length;
				firstDefiniteLoss = 1;
			}
			for (const item of stranded.slice(firstDefiniteLoss)) {
				drainTimeoutLostRecords += 1;
				drainTimeoutLostBytes += item.bytes.length;
				this.noteDrop(item.bytes.length, false);
			}
			this.queue.length = 0;
			this.queuedBytes = 0;
		}

		this.enqueueLossCheckpoint(true);
		const terminalAdmission = this.emitOccurrence(
			"recorder-control",
			"capture_channel_terminal",
			Buffer.alloc(0),
			"control",
			"none",
			{
				attemptedRecords: this.counters.attemptedRecords,
				attemptedBytes: this.counters.attemptedBytes,
				queuedRecords: this.counters.queuedRecords,
				queuedBytes: this.counters.queuedBytes,
				lostRecords: this.counters.droppedRecords,
				lostBytes: this.counters.droppedBytes,
				drainTimeoutLostRecords,
				drainTimeoutLostBytes,
				drainTimeoutUncertainRecords,
				drainTimeoutUncertainBytes,
			},
			true,
			true,
			true,
			terminalOccurrenceId,
		);
		const terminalDrained = await this.flush(deadlineMs);
		if (!terminalDrained) {
			// The final marker itself may be undeliverable on a permanently blocked or
			// broken channel. Keep this local tail bounded and stop all later writes.
			this.queue.length = 0;
			this.queuedBytes = 0;
		}
		this.stopped = true;
		this.stopping = false;
		if (this.lossCheckpointRetry) clearTimeout(this.lossCheckpointRetry);
		this.lossCheckpointRetry = undefined;
		return {
			terminalAdmission,
			totalLoss: this.lossCounters(),
			drainTimeoutLoss: { records: drainTimeoutLostRecords, bytes: drainTimeoutLostBytes },
			drainTimeoutUncertainty: {
				records: drainTimeoutUncertainRecords,
				bytes: drainTimeoutUncertainBytes,
			},
			terminalDrained,
		};
	}
}

let captureEmitter: BoundedFrameEmitter | undefined;
let captureEmitterStop: Promise<void> | undefined;
let captureOwnerGuard: CaptureOwnerGuard | undefined;

/** @internal */
export function writeEncodedFramesToFd(
	fd: number,
	frames: readonly IncidentRecorderEncodedFrame[],
	callback: (error?: Error) => void,
	validateOwner: () => boolean = () => true,
): void {
	let packets: readonly Buffer[];
	try {
		packets = frames.map((frame) => encodeIncidentRecorderTransportPacket(Buffer.concat(frame.parts)));
	} catch (error) {
		callback(error instanceof Error ? error : new Error(String(error)));
		return;
	}
	let packetIndex = 0;
	let offset = 0;
	let completed = false;
	const finish = (error?: Error): void => {
		if (completed) return;
		completed = true;
		callback(error);
	};
	const writeNext = (): void => {
		let valid = false;
		try {
			valid = validateOwner();
		} catch {}
		if (!valid) {
			finish(new Error("Incident recorder capture owner changed"));
			return;
		}
		const packet = packets[packetIndex];
		if (!packet) {
			finish();
			return;
		}
		write(fd, packet, offset, packet.length - offset, (error, written) => {
			if (error) {
				finish(error);
				return;
			}
			if (written <= 0) {
				setImmediate(writeNext);
				return;
			}
			offset += written;
			if (offset === packet.length) {
				packetIndex += 1;
				offset = 0;
			}
			writeNext();
		});
	};
	writeNext();
}

export function configureIncidentCaptureEmitter(): boolean {
	if (captureEmitter) return captureOwnerGuard?.validAdmission() === true;
	const fd = Number(process.env[INCIDENT_RECORDER_CAPTURE_FD_ENV]);
	const rootFd = Number(process.env[INCIDENT_RECORDER_ROOT_FD_ENV]);
	const runId = process.env[INCIDENT_RECORDER_RUN_ID_ENV];
	const runToken = process.env[INCIDENT_RECORDER_RUN_TOKEN_ENV];
	if (fd !== INCIDENT_RECORDER_CAPTURE_FD || rootFd !== INCIDENT_RECORDER_ROOT_FD || !runId || !runToken) return false;

	// The wrapper supplies two kernel capabilities: the fd4 capture channel and the
	// canonical recorder root directory at fd5. The supervisor creates its unique
	// claim below fd5, so a forged run-directory environment variable cannot move it.
	const guard = claimCaptureOwner(runId, runToken);
	if (!guard) return false;
	captureOwnerGuard = guard;
	process.env[INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV] = String(process.pid);
	process.env[INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV] = linuxProcessStartId(process.pid) ?? "unavailable";
	captureEmitter = new BoundedFrameEmitter(
		(frames, callback) => writeEncodedFramesToFd(fd, frames, callback, () => guard.validCheap()),
		configuredEmitterMaximum(),
		{ runId, runToken },
		() => guard.validCheap(),
		() => guard.validAdmission(),
	);
	// Do not propagate usable capability labels to controlled descendants. Their
	// spawn stdio also closes fd4/fd5 explicitly.
	delete process.env[INCIDENT_RECORDER_CAPTURE_FD_ENV];
	delete process.env[INCIDENT_RECORDER_ROOT_FD_ENV];
	return true;
}

export function emitIncidentDerived(
	source: CaptureSource,
	type: string,
	fields: Record<string, unknown>,
): IncidentRecorderAdmission {
	try {
		return (
			captureEmitter?.emitDerived(source, type, fields) ?? {
				accepted: false,
				disposition: "rejected",
				reason: "stopped",
			}
		);
	} catch {
		return { accepted: false, disposition: "rejected", reason: "encoding_failed" };
	}
}

/**
 * Emit one nonterminal reserved control occurrence from a configured capture
 * producer. Terminal authority remains private to the emitter stop path.
 */
export function emitIncidentControl(type: string, fields: Record<string, unknown>): IncidentRecorderAdmission {
	try {
		return (
			captureEmitter?.emitControl(type, fields, false) ?? {
				accepted: false,
				disposition: "rejected",
				reason: "stopped",
			}
		);
	} catch {
		return { accepted: false, disposition: "rejected", reason: "encoding_failed" };
	}
}

export function emitIncidentBytes(
	source: CaptureSource,
	type: string,
	bytes: Uint8Array,
	metadata: Record<string, unknown>,
): IncidentRecorderAdmission {
	try {
		return (
			captureEmitter?.emitBytes(source, type, bytes, metadata) ?? {
				accepted: false,
				disposition: "rejected",
				reason: "stopped",
			}
		);
	} catch {
		return { accepted: false, disposition: "rejected", reason: "encoding_failed" };
	}
}

export async function stopIncidentCaptureEmitter(): Promise<void> {
	if (captureEmitterStop) {
		await captureEmitterStop;
		return;
	}
	const emitter = captureEmitter;
	if (!emitter) return;
	const stopping = emitter.stop().then(() => undefined);
	captureEmitterStop = stopping;
	try {
		await stopping;
	} finally {
		if (captureEmitter === emitter) captureEmitter = undefined;
		if (captureEmitterStop === stopping) captureEmitterStop = undefined;
		captureOwnerGuard?.release();
		captureOwnerGuard = undefined;
	}
}

export function stopIncidentCaptureEmitterOnExit(): void {
	// Exit cannot await a flush. Strict PID/start/fd/claim equality still gates
	// removal, so a copied or tampered owner can never clean another claim.
	captureOwnerGuard?.release();
	captureOwnerGuard = undefined;
	captureEmitter = undefined;
	captureEmitterStop = undefined;
}

export interface IncidentJournalLine {
	schema: "prime-agent-raw-v1";
	runId: string;
	runToken: string;
	producerId: string;
	producerSequence: string;
	wrapperSequence: string;
	occurrenceId: string;
	chunkIndex: number;
	chunkCount: number;
	source: string;
	type: string;
	encoding: string;
	payloadKind: IncidentRecorderPayloadKind;
	producerPid: number | null;
	producerStartId: string | null;
	wrapperPid: number;
	wrapperStartId: string | null;
	targetPid: number | null;
	targetStartId: string | null;
	bootId: string | null;
	machineId: string | null;
	systemdInvocationId: string | null;
	systemdCatPid: number | null;
	systemdCatStartId: string | null;
	eventWallTimeMs: string;
	eventMonotonicNs: string;
	rawOccurrenceBytes: number;
	occurrenceSha256: string;
	chunkBytes: number;
	chunkSha256: string;
	frameChecksum: number;
	flags: number;
	metadata: ScalarMetadata;
	payloadBase64: string;
	attemptedRecords: number | null;
	attemptedBytes: number | null;
	queuedRecords: number | null;
	queuedBytes: number | null;
	droppedRecords: number | null;
	droppedBytes: number | null;
	observationDisposition: "observed_by_wrapper";
	queueDisposition: "locally_admitted";
	wrapperRelayDisposition: "locally_admitted";
	streamDisposition: "systemd_cat_stdin_write_attempted";
	journalDurability: "not_asserted_by_writer";
	wrapperRelayDroppedRecords: number;
	wrapperRelayDroppedBytes: number;
	wrapperRelayUncertainRecords: number;
}

interface RelayOccurrence {
	frames: readonly IncidentRecorderEncodedFrame[];
	wrapperSequences: readonly bigint[];
	bytes: number;
	rawBytes: number;
	lineIndex: number;
	reserved: boolean;
	occurrenceId: string;
}

export interface IncidentRecorderRelayFrontier {
	occurrenceId: string;
	producerId: string;
	type: string;
	firstProducerSequence: string;
	lastProducerSequence: string;
	firstWrapperSequence: string;
	lastWrapperSequence: string;
}

export interface IncidentRecorderFinalizationExpectation {
	runId: string;
	runToken: string;
	wrapperPid: number;
	wrapperStartId: string | null;
	supervisorExit?: IncidentRecorderRelayFrontier;
	wrapperTerminal?: IncidentRecorderRelayFrontier;
	finalQueuedTailLoss: { records: number; bytes: number };
	emitterFinalTailLoss: { records: number; bytes: number };
}

export interface IncidentRecorderBoundedCount {
	readonly records: number;
	readonly bytes: number;
}

export interface IncidentRecorderRunIdentitySealResult {
	readonly schemaVersion: 1;
	readonly state: "sealed";
	readonly runId: string;
	readonly runToken: string;
	readonly terminal: Readonly<{
		type: "capture_channel_terminal";
		admission: Readonly<IncidentRecorderAdmission> | null;
		// A relay frontier proves local wrapper admission, not journal durability.
		frontier: Readonly<IncidentRecorderRelayFrontier> | null;
	}>;
	readonly loss: Readonly<{
		// Total emitter-reported loss. The categories below may overlap it; do not sum blindly.
		emitter: IncidentRecorderBoundedCount;
		drainTimeout: Readonly<{
			definite: IncidentRecorderBoundedCount;
			uncertain: IncidentRecorderBoundedCount;
		}>;
		terminalRelay: Readonly<{
			definite: IncidentRecorderBoundedCount;
			uncertain: IncidentRecorderBoundedCount;
		}>;
	}>;
}

export type IncidentRecorderRunIdentitySealAdoption =
	| Readonly<{
			adopted: true;
			disposition: "adopted" | "already_adopted";
			seal: IncidentRecorderRunIdentitySealResult;
	  }>
	| Readonly<{
			adopted: false;
			disposition: "rejected";
			reason:
				| "invalid_seal_record"
				| "run_identity_active_or_stopping"
				| "run_identity_seal_capacity_exhausted"
				| "run_identity_seal_in_progress"
				| "run_identity_seal_conflict";
	  }>;

interface ServiceEmitterSealState {
	readonly promise: Promise<IncidentRecorderRunIdentitySealResult>;
	result?: IncidentRecorderRunIdentitySealResult;
	fingerprint?: string;
}

export interface IncidentRecorderRunIdentitySealReplayOptions {
	/**
	 * A seal loaded from durable service state may be validated without retaining
	 * per-identity process state when this writer has no local emitter for it.
	 */
	durableReplay?: boolean;
}

const INCIDENT_RECORDER_ADMISSION_REASONS = new Set<Extract<IncidentRecorderAdmission, { accepted: false }>["reason"]>([
	"stopped",
	"terminal_reserved",
	"occurrence_too_large",
	"queue_capacity",
	"encoding_failed",
	"run_identity_sealed",
]);

const CANONICAL_INCIDENT_RECORDER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function validServiceIdentity(value: unknown): value is IncidentRecorderServiceIdentity {
	const identity = objectRecord(value);
	return (
		identity !== undefined &&
		typeof identity.runId === "string" &&
		CANONICAL_INCIDENT_RECORDER_ID.test(identity.runId) &&
		typeof identity.runToken === "string" &&
		CANONICAL_INCIDENT_RECORDER_ID.test(identity.runToken)
	);
}

function immutableCount(records: number, bytes: number): IncidentRecorderBoundedCount {
	return Object.freeze({ records, bytes });
}

function immutableAdmission(value: IncidentRecorderAdmission | undefined): Readonly<IncidentRecorderAdmission> | null {
	return value ? Object.freeze({ ...value }) : null;
}

function immutableFrontier(
	value: IncidentRecorderRelayFrontier | undefined,
): Readonly<IncidentRecorderRelayFrontier> | null {
	return value ? Object.freeze({ ...value }) : null;
}

function immutableSealResult(
	identity: { runId: string; runToken: string },
	stop: BoundedFrameEmitterStopResult,
	frontier: IncidentRecorderRelayFrontier | undefined,
	terminalEvidenceRetired = false,
): IncidentRecorderRunIdentitySealResult {
	const admission = immutableAdmission(stop.terminalAdmission);
	const terminalFrontier = immutableFrontier(frontier);
	let terminalLost = 0;
	let terminalUncertain = 0;
	if (terminalEvidenceRetired) terminalUncertain = 1;
	else if (!admission?.accepted) terminalLost = 1;
	else if (!terminalFrontier) {
		if (stop.terminalDrained) terminalLost = 1;
		else terminalUncertain = 1;
	}
	return Object.freeze({
		schemaVersion: 1,
		state: "sealed",
		runId: identity.runId,
		runToken: identity.runToken,
		terminal: Object.freeze({
			type: "capture_channel_terminal",
			admission,
			frontier: terminalFrontier,
		}),
		loss: Object.freeze({
			emitter: immutableCount(stop.totalLoss.records, stop.totalLoss.bytes),
			drainTimeout: Object.freeze({
				definite: immutableCount(stop.drainTimeoutLoss.records, stop.drainTimeoutLoss.bytes),
				uncertain: immutableCount(stop.drainTimeoutUncertainty.records, stop.drainTimeoutUncertainty.bytes),
			}),
			terminalRelay: Object.freeze({
				definite: immutableCount(terminalLost, 0),
				uncertain: immutableCount(terminalUncertain, 0),
			}),
		}),
	});
}

function immutableFenceOnlySealResult(identity: {
	runId: string;
	runToken: string;
}): IncidentRecorderRunIdentitySealResult {
	return immutableSealResult(
		identity,
		{
			totalLoss: { records: 0, bytes: 0 },
			drainTimeoutLoss: { records: 0, bytes: 0 },
			drainTimeoutUncertainty: { records: 0, bytes: 0 },
			terminalDrained: false,
		},
		undefined,
		true,
	);
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function hasExactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
	const keys = Object.keys(record).sort();
	const sortedExpected = [...expected].sort();
	return keys.length === sortedExpected.length && keys.every((key, index) => key === sortedExpected[index]);
}

function normalizedCount(value: unknown): IncidentRecorderBoundedCount | undefined {
	const record = objectRecord(value);
	if (
		!record ||
		!hasExactKeys(record, ["records", "bytes"]) ||
		!Number.isSafeInteger(record.records) ||
		!Number.isSafeInteger(record.bytes) ||
		(record.records as number) < 0 ||
		(record.bytes as number) < 0
	)
		return undefined;
	return immutableCount(record.records as number, record.bytes as number);
}

function normalizedAdmission(value: unknown): Readonly<IncidentRecorderAdmission> | null | undefined {
	if (value === null) return null;
	const record = objectRecord(value);
	if (!record || record.disposition !== (record.accepted === true ? "locally_admitted" : "rejected")) return undefined;
	if (
		record.accepted === true &&
		hasExactKeys(record, ["accepted", "occurrenceId", "disposition"]) &&
		typeof record.occurrenceId === "string" &&
		CANONICAL_INCIDENT_RECORDER_ID.test(record.occurrenceId)
	)
		return Object.freeze({
			accepted: true,
			occurrenceId: record.occurrenceId,
			disposition: "locally_admitted",
		});
	if (
		record.accepted !== false ||
		!hasExactKeys(record, ["accepted", "disposition", "reason"]) ||
		typeof record.reason !== "string" ||
		!INCIDENT_RECORDER_ADMISSION_REASONS.has(
			record.reason as Extract<IncidentRecorderAdmission, { accepted: false }>["reason"],
		)
	)
		return undefined;
	return Object.freeze({
		accepted: false,
		disposition: "rejected",
		reason: record.reason as Extract<IncidentRecorderAdmission, { accepted: false }>["reason"],
	});
}

function normalizedFrontier(value: unknown): Readonly<IncidentRecorderRelayFrontier> | null | undefined {
	if (value === null) return null;
	const record = objectRecord(value);
	if (
		!record ||
		!hasExactKeys(record, [
			"occurrenceId",
			"producerId",
			"type",
			"firstProducerSequence",
			"lastProducerSequence",
			"firstWrapperSequence",
			"lastWrapperSequence",
		]) ||
		typeof record.occurrenceId !== "string" ||
		!CANONICAL_INCIDENT_RECORDER_ID.test(record.occurrenceId) ||
		typeof record.producerId !== "string" ||
		!CANONICAL_INCIDENT_RECORDER_ID.test(record.producerId) ||
		record.type !== "capture_channel_terminal" ||
		![
			record.firstProducerSequence,
			record.lastProducerSequence,
			record.firstWrapperSequence,
			record.lastWrapperSequence,
		].every((sequence) => typeof sequence === "string" && /^(?:0|[1-9][0-9]{0,19})$/.test(sequence))
	)
		return undefined;
	return Object.freeze({
		occurrenceId: record.occurrenceId,
		producerId: record.producerId,
		type: "capture_channel_terminal",
		firstProducerSequence: record.firstProducerSequence as string,
		lastProducerSequence: record.lastProducerSequence as string,
		firstWrapperSequence: record.firstWrapperSequence as string,
		lastWrapperSequence: record.lastWrapperSequence as string,
	});
}

export function parseIncidentRecorderRunIdentitySeal(
	value: unknown,
): IncidentRecorderRunIdentitySealResult | undefined {
	const record = objectRecord(value);
	const terminal = objectRecord(record?.terminal);
	const loss = objectRecord(record?.loss);
	const drainTimeout = objectRecord(loss?.drainTimeout);
	const terminalRelay = objectRecord(loss?.terminalRelay);
	const admission = normalizedAdmission(terminal?.admission);
	const frontier = normalizedFrontier(terminal?.frontier);
	const emitterLoss = normalizedCount(loss?.emitter);
	const drainDefinite = normalizedCount(drainTimeout?.definite);
	const drainUncertain = normalizedCount(drainTimeout?.uncertain);
	const terminalDefinite = normalizedCount(terminalRelay?.definite);
	const terminalUncertain = normalizedCount(terminalRelay?.uncertain);
	if (
		!record ||
		!hasExactKeys(record, ["schemaVersion", "state", "runId", "runToken", "terminal", "loss"]) ||
		record.schemaVersion !== 1 ||
		record.state !== "sealed" ||
		typeof record.runId !== "string" ||
		!CANONICAL_INCIDENT_RECORDER_ID.test(record.runId) ||
		typeof record.runToken !== "string" ||
		!CANONICAL_INCIDENT_RECORDER_ID.test(record.runToken) ||
		!terminal ||
		!hasExactKeys(terminal, ["type", "admission", "frontier"]) ||
		terminal.type !== "capture_channel_terminal" ||
		!loss ||
		!hasExactKeys(loss, ["emitter", "drainTimeout", "terminalRelay"]) ||
		!drainTimeout ||
		!hasExactKeys(drainTimeout, ["definite", "uncertain"]) ||
		!terminalRelay ||
		!hasExactKeys(terminalRelay, ["definite", "uncertain"]) ||
		admission === undefined ||
		frontier === undefined ||
		!emitterLoss ||
		!drainDefinite ||
		!drainUncertain ||
		!terminalDefinite ||
		!terminalUncertain ||
		(frontier !== null && (!admission?.accepted || frontier.occurrenceId !== admission.occurrenceId))
	)
		return undefined;
	return Object.freeze({
		schemaVersion: 1,
		state: "sealed",
		runId: record.runId,
		runToken: record.runToken,
		terminal: Object.freeze({ type: "capture_channel_terminal", admission, frontier }),
		loss: Object.freeze({
			emitter: emitterLoss,
			drainTimeout: Object.freeze({ definite: drainDefinite, uncertain: drainUncertain }),
			terminalRelay: Object.freeze({ definite: terminalDefinite, uncertain: terminalUncertain }),
		}),
	});
}

function sealFingerprint(value: IncidentRecorderRunIdentitySealResult): string {
	return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export interface IncidentRecorderWriterOptions {
	runDir: string;
	runId?: string;
	runToken?: string;
	bootId?: string;
	wrapperStartId?: string;
	serviceSink?: boolean;
	/** Internal process-fatal hook for bounded wrapper-frontier exhaustion. */
	onWrapperFrontierSaturated?: (error: IncidentRecorderWrapperFrontierSaturatedError) => void;
	/** Dependency-injection seam for deterministic bounded-frontier tests. */
	wrapperFrontier?: IncidentRecorderWrapperFrontier;
	/** Maximum exact service-identity fences retained by this writer. */
	serviceIdentitySealFenceMaxIdentities?: number;
	/** One-shot diagnostic hook for exact service-identity fence saturation. */
	onServiceIdentitySealFenceSaturated?: (error: IncidentRecorderServiceIdentitySealFenceSaturatedError) => void;
}

export class IncidentRecorderWriter {
	private readonly runId: string;
	private readonly runToken: string;
	private readonly wrapperStartId: string | undefined;
	private readonly bootId: string | undefined;
	private readonly serviceSink: boolean;
	private readonly wrapperFrontier: IncidentRecorderWrapperFrontier;
	private readonly onWrapperFrontierSaturated:
		| ((error: IncidentRecorderWrapperFrontierSaturatedError) => void)
		| undefined;
	private wrapperFrontierSaturationReported = false;
	private readonly machineId = linuxIdentity("/etc/machine-id", /^[0-9a-f]{32}$/i);
	private readonly invocationId = process.env.INVOCATION_ID?.match(/^[0-9a-f]{32}$/i)?.[0];
	private readonly emitter: BoundedFrameEmitter;
	private readonly serviceEmitters = new Map<string, BoundedFrameEmitter>();
	private readonly serviceEmitterStops = new Map<string, Promise<BoundedFrameEmitterStopResult>>();
	private readonly serviceIdentitySeals = new Map<string, ServiceEmitterSealState>();
	private readonly serviceIdentitySealFence: ServiceIdentitySealFence;
	private readonly onServiceIdentitySealFenceSaturated:
		| ((error: IncidentRecorderServiceIdentitySealFenceSaturatedError) => void)
		| undefined;
	private serviceIdentitySealFenceSaturationReported = false;
	private readonly relayQueue: RelayOccurrence[] = [];
	private relayBytes = 0;
	private relayDroppedRecords = 0;
	private relayDroppedBytes = 0;
	private relayUncertainRecords = 0;
	private relayLossReportedRecords = 0;
	private relayLossReportedBytes = 0;
	private readonly relayLossProducerId = newIncidentRecorderIdentity();
	private relayLossProducerSequence = 0n;
	private relayLossTimer?: ReturnType<typeof setInterval>;
	private relayLossIdentity?: { runId: string; runToken: string };
	private sourceIdentity: ScalarMetadata = {};
	private cat?: ChildProcess;
	private catStartId?: string;
	private reconnectTimer?: ReturnType<typeof setTimeout>;
	private captureDecoder?: IncidentRecorderTransportDecoder;
	private readonly captureSequences = new IncidentRecorderTransportSequenceTracker();
	private transportCorruptPackets = 0n;
	private transportCorruptWireBytes = 0n;
	private transportSequenceGapEvents = 0n;
	private transportMissingPackets = 0n;
	private transportReportedCorruptPackets = 0n;
	private transportReportedCorruptWireBytes = 0n;
	private transportReportedSequenceGapEvents = 0n;
	private transportReportedMissingPackets = 0n;
	private captureStream?: ReadableStream;
	private readonly captureCompletedOccurrences: Array<{
		frames: readonly Buffer[];
		wireBytes: number;
		rawBytes: number;
	}> = [];
	private captureCompletedBytes = 0;
	private captureValidationRunning = false;
	private captureStreamEnded = false;
	private captureStreamEndIncomplete = 0;
	private captureCloseRecorded = false;
	private captureFrames: Array<Buffer | undefined> = [];
	private captureOccurrenceId?: string;
	private captureProducerId?: string;
	private captureFirstSequence = 0n;
	private captureChunkCount = 0;
	private captureReceivedChunks = 0;
	private captureRawBytes = 0;
	private captureDeclaredRawBytes = 0;
	private captureStartedAt = 0;
	private readonly captureOccurrenceTombstones = new Map<string, "completed" | "discarded">();
	private stopped = false;
	private pumping = false;
	private readonly finalizationFrontiers = new Map<string, IncidentRecorderRelayFrontier>();
	private terminalOccurrenceId?: string;
	private finalTailDroppedRecords = 0;
	private finalTailDroppedBytes = 0;
	private emitterFinalTailLoss = { records: 0, bytes: 0 };

	constructor(options: IncidentRecorderWriterOptions) {
		this.runId = options.runId ?? process.env[INCIDENT_RECORDER_RUN_ID_ENV] ?? options.runDir.slice(-36);
		this.runToken = options.runToken ?? process.env[INCIDENT_RECORDER_RUN_TOKEN_ENV] ?? newIncidentRecorderIdentity();
		this.wrapperStartId = options.wrapperStartId ?? linuxProcessStartId(process.pid);
		this.bootId = options.bootId ?? linuxIdentity("/proc/sys/kernel/random/boot_id", /^[0-9a-f-]{36}$/i);
		this.serviceSink = options.serviceSink === true;
		this.wrapperFrontier = options.wrapperFrontier ?? processLifetimeWrapperFrontier;
		this.onWrapperFrontierSaturated = options.onWrapperFrontierSaturated;
		this.serviceIdentitySealFence = new ExactServiceIdentitySealFence(
			options.serviceIdentitySealFenceMaxIdentities ?? INCIDENT_RECORDER_SERVICE_SEAL_FENCE_MAX_IDENTITIES,
		);
		this.onServiceIdentitySealFenceSaturated = options.onServiceIdentitySealFenceSaturated;
		this.reserveWrapperFrontier({ runId: this.runId, runToken: this.runToken });
		this.emitter = this.createEmitter({ runId: this.runId, runToken: this.runToken });
	}

	private reserveWrapperFrontier(identity: IncidentRecorderWrapperFrontierIdentity): void {
		try {
			this.wrapperFrontier.reserve(identity);
		} catch (error) {
			if (!(error instanceof IncidentRecorderWrapperFrontierSaturatedError)) throw error;
			this.reportWrapperFrontierSaturation(error);
			throw error;
		}
	}

	private reportWrapperFrontierSaturation(error: IncidentRecorderWrapperFrontierSaturatedError): void {
		if (this.wrapperFrontierSaturationReported) return;
		this.wrapperFrontierSaturationReported = true;
		try {
			this.onWrapperFrontierSaturated?.(error);
		} catch {
			// The frontier error remains the authoritative failure. A diagnostic hook
			// must not replace it or prevent writer cleanup.
		}
	}

	private createEmitter(
		identity: { runId: string; runToken: string },
		maximumBytes = configuredEmitterMaximum(),
	): BoundedFrameEmitter {
		return new BoundedFrameEmitter(
			(frames, callback) => {
				const reserved = frames.every(
					(frame) => frame.header.payloadKind === "control" || frame.header.payloadKind === "loss",
				);
				const admission = this.enqueueFrames(frames, reserved, true);
				callback(
					admission.accepted ? undefined : new Error(admission.reason ?? "wrapper relay rejected occurrence"),
				);
			},
			maximumBytes,
			identity,
		);
	}

	private serviceEmitter(identity: { runId: string; runToken: string }): BoundedFrameEmitter | undefined {
		const key = `${identity.runId}\0${identity.runToken}`;
		if (this.serviceIdentityIsSealed(key)) return undefined;
		if (
			!this.serviceSink ||
			!CANONICAL_INCIDENT_RECORDER_ID.test(identity.runId) ||
			!CANONICAL_INCIDENT_RECORDER_ID.test(identity.runToken)
		)
			return undefined;
		let emitter = this.serviceEmitters.get(key);
		if (!emitter && this.serviceEmitters.size < SERVICE_EMITTER_MAX_IDENTITIES) {
			// Reserve before constructing an emitter. If the process-lifetime
			// frontier is full, construction and any later cleanup remain allocation-free.
			this.reserveWrapperFrontier(identity);
			emitter = this.createEmitter(identity, SERVICE_EMITTER_MAX_BYTES);
			this.serviceEmitters.set(key, emitter);
		}
		return emitter;
	}

	private serviceIdentityIsSealed(key: string): boolean {
		return this.serviceIdentitySeals.has(key) || this.serviceIdentitySealFence.has(this.identityFromKey(key));
	}

	private identityFromKey(key: string): IncidentRecorderServiceIdentity {
		const separator = key.indexOf("\0");
		return separator < 0
			? { runId: key, runToken: "" }
			: { runId: key.slice(0, separator), runToken: key.slice(separator + 1) };
	}

	private reserveServiceIdentitySealFence(identity: IncidentRecorderServiceIdentity): void {
		try {
			this.serviceIdentitySealFence.reserve(identity);
		} catch (error) {
			if (!(error instanceof IncidentRecorderServiceIdentitySealFenceSaturatedError)) throw error;
			this.reportServiceIdentitySealFenceSaturation(error);
			throw error;
		}
	}

	private reportServiceIdentitySealFenceSaturation(
		error: IncidentRecorderServiceIdentitySealFenceSaturatedError,
	): void {
		if (this.serviceIdentitySealFenceSaturationReported) return;
		this.serviceIdentitySealFenceSaturationReported = true;
		try {
			this.onServiceIdentitySealFenceSaturated?.(error);
		} catch {
			// A diagnostic hook must not replace the authoritative saturation error.
		}
	}

	private canRetainServiceIdentitySeal(): boolean {
		return (
			this.serviceIdentitySeals.size < INCIDENT_RECORDER_SERVICE_SEAL_RESULT_MAX_IDENTITIES ||
			[...this.serviceIdentitySeals.values()].some((candidate) => candidate.result !== undefined)
		);
	}

	private retainServiceIdentitySeal(key: string, state: ServiceEmitterSealState): boolean {
		while (this.serviceIdentitySeals.size >= INCIDENT_RECORDER_SERVICE_SEAL_RESULT_MAX_IDENTITIES) {
			const reclaimable = [...this.serviceIdentitySeals].find(([, candidate]) => candidate.result !== undefined);
			if (!reclaimable) return false;
			const [reclaimedKey, reclaimed] = reclaimable;
			this.serviceIdentitySeals.delete(reclaimedKey);
			const terminalOccurrenceId = reclaimed.result?.terminal.frontier?.occurrenceId;
			if (terminalOccurrenceId) this.finalizationFrontiers.delete(terminalOccurrenceId);
		}
		this.serviceIdentitySeals.set(key, state);
		return true;
	}

	async start(options: { requireJournal?: boolean } = {}): Promise<void> {
		const connected = await this.connectJournalWithDeadline();
		if (options.requireJournal && !connected) {
			await this.stop(250);
			throw new Error("Incident recorder journal writer did not become ready");
		}
		if (!this.relayLossTimer) {
			this.relayLossTimer = setInterval(() => this.emitRelayLossCheckpoint(), 1_000);
			this.relayLossTimer.unref();
		}
		if (!this.serviceSink)
			this.emitter.emitControl("journal_stream_start_checkpoint", {
				wrapperPid: process.pid,
				wrapperStartId: this.wrapperStartId ?? "unavailable",
			});
	}

	get journalReady(): boolean {
		return Boolean(
			this.cat &&
				this.cat.exitCode === null &&
				this.cat.signalCode === null &&
				this.cat.stdin &&
				!this.cat.stdin.destroyed,
		);
	}

	private async connectJournalWithDeadline(): Promise<boolean> {
		if (this.stopped) return false;
		if (this.cat && this.cat.stdin && !this.cat.stdin.destroyed) return true;
		const environment = { ...process.env };
		delete environment.NOTIFY_SOCKET;
		const child = spawn(
			"systemd-cat",
			[
				`--namespace=${INCIDENT_RECORDER_JOURNAL_NAMESPACE}`,
				`--identifier=${INCIDENT_RECORDER_JOURNAL_IDENTIFIER}`,
				"--priority=info",
				"--level-prefix=false",
			],
			{ env: environment, stdio: ["pipe", "ignore", "ignore"] },
		);
		this.cat = child;
		this.catStartId = child.pid ? linuxProcessStartId(child.pid) : undefined;
		child.once("spawn", () => {
			this.catStartId = child.pid ? linuxProcessStartId(child.pid) : undefined;
		});
		child.once("error", () => this.handleCatUnavailable(child));
		child.once("close", () => this.handleCatUnavailable(child));
		child.stdin?.once("error", () => this.handleCatUnavailable(child));
		const spawned = await new Promise<boolean>((resolveConnected) => {
			let settled = false;
			const finish = (value: boolean) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				child.off("spawn", onSpawn);
				child.off("error", onError);
				resolveConnected(value);
			};
			const onSpawn = () => finish(true);
			const onError = () => finish(false);
			const timer = setTimeout(() => finish(false), JOURNAL_START_DEADLINE_MS);
			timer.unref();
			child.once("spawn", onSpawn);
			child.once("error", onError);
		});
		const connected =
			spawned &&
			(await new Promise<boolean>((resolveStable) => {
				let settled = false;
				const finish = (value: boolean): void => {
					if (settled) return;
					settled = true;
					clearTimeout(timer);
					child.off("close", onClose);
					resolveStable(value);
				};
				const onClose = (): void => finish(false);
				const timer = setTimeout(() => finish(this.cat === child && this.journalReady), JOURNAL_START_STABILITY_MS);
				timer.unref();
				child.once("close", onClose);
			}));
		this.pumpRelay();
		return connected;
	}

	private handleCatUnavailable(child: ChildProcess): void {
		if (this.cat !== child) return;
		this.cat = undefined;
		this.catStartId = undefined;
		this.pumping = false;
		if (this.stopped) return;
		try {
			child.stdin?.destroy();
		} catch {}
		if (child.exitCode === null && child.signalCode === null) {
			try {
				child.kill("SIGTERM");
			} catch {}
			const killTimer = setTimeout(() => {
				try {
					if (child.exitCode === null) child.kill("SIGKILL");
				} catch {}
			}, 250);
			killTimer.unref();
		}
		if (this.stopped || this.reconnectTimer) return;
		this.reconnectTimer = setTimeout(() => {
			this.reconnectTimer = undefined;
			void this.connectJournalWithDeadline().then(() => {
				this.emitter.emitControl("journal_stream_reconnect_checkpoint", {
					lostRecords: this.relayDroppedRecords,
					lostBytes: this.relayDroppedBytes,
					attemptedRecords: this.relayUncertainRecords,
				});
			});
		}, JOURNAL_RECONNECT_MS);
		this.reconnectTimer.unref();
	}

	async setSourceIdentity(identity: Record<string, unknown>): Promise<IncidentRecorderAdmission> {
		this.sourceIdentity = scalarMetadata(identity);
		return this.emitter.emitControl("run_source_identity_checkpoint", identity);
	}

	attachCaptureStream(stream: ReadableStream): void {
		this.captureStream = stream;
		this.captureDecoder = new IncidentRecorderTransportDecoder(
			(frame, wireBytes) => this.acceptCaptureFrame(frame, wireBytes),
			(evidence) => this.noteCaptureTransportCorruption(evidence),
		);
		stream.on("data", (chunk: Buffer) => this.captureDecoder?.push(chunk));
		stream.once("end", () => {
			const incomplete = this.captureDecoder?.finish() ?? 0;
			this.noteCaptureSequenceAccounting(this.captureSequences.finish());
			if (this.captureFrames.length > 0) this.dropCaptureAssembly(0);
			this.captureStreamEnded = true;
			this.captureStreamEndIncomplete = incomplete;
			this.finishCaptureStreamIfDrained();
		});
	}

	private noteCaptureTransportCorruption(evidence: IncidentRecorderTransportCorruption): void {
		this.transportCorruptPackets += 1n;
		this.transportCorruptWireBytes += BigInt(evidence.wireBytes);
	}

	private noteCaptureSequenceAccounting(accounting: { gapEvents: bigint; missingPackets: bigint }): void {
		this.transportSequenceGapEvents += accounting.gapEvents;
		this.transportMissingPackets += accounting.missingPackets;
	}

	private acceptCaptureFrame(frameBytes: Buffer, wireBytes: number): void {
		let decoded: ReturnType<typeof decodeIncidentRecorderFrame>;
		try {
			decoded = decodeIncidentRecorderFrame(frameBytes);
		} catch {
			this.noteCaptureTransportCorruption({ kind: "invalid-protocol-packet", wireBytes });
			return;
		}
		const { header } = decoded;
		if (header.runId !== this.runId || header.runToken !== this.runToken) {
			this.noteRelayDrop(1, header.payloadLength);
			return;
		}
		try {
			validateIncidentRecorderFrameFlags(header.flags, header.chunkIndex, header.chunkCount);
		} catch {
			this.noteRelayDrop(1, header.payloadLength);
			return;
		}
		if (this.captureOccurrenceTombstones.has(header.occurrenceId)) return;
		if (this.captureFrames.length > 0 && Date.now() - this.captureStartedAt > 5_000) {
			this.dropCaptureAssembly(0);
			if (this.captureOccurrenceTombstones.has(header.occurrenceId)) return;
		}
		const firstSequence = header.producerSequence - BigInt(header.chunkIndex);
		const lastSequence = firstSequence + BigInt(header.chunkCount - 1);
		if (firstSequence < 0n || lastSequence > (1n << 64n) - 1n) {
			this.discardCaptureOccurrence(header.occurrenceId, this.declaredOccurrenceRawBytes(header));
			return;
		}
		if (this.captureFrames.length > 0 && header.occurrenceId === this.captureOccurrenceId) {
			const existing = this.captureFrames[header.chunkIndex];
			if (existing?.equals(frameBytes)) return;
			if (
				header.producerId !== this.captureProducerId ||
				firstSequence !== this.captureFirstSequence ||
				header.chunkCount !== this.captureChunkCount ||
				existing ||
				this.captureRawBytes + header.payloadLength > INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES
			) {
				this.dropCaptureAssembly(header.payloadLength);
				return;
			}
		}
		const sequence = this.captureSequences.observe(header.producerId, header.producerSequence);
		this.noteCaptureSequenceAccounting(sequence);
		if (sequence.duplicate) return;
		if (this.captureFrames.length === 0) this.startCaptureAssembly(header);
		else if (header.occurrenceId !== this.captureOccurrenceId) {
			this.dropCaptureAssembly(0);
			if (this.captureOccurrenceTombstones.has(header.occurrenceId)) return;
			this.startCaptureAssembly(header);
		}
		this.noteCaptureSequenceAccounting(this.captureSequences.expect(header.producerId, firstSequence, lastSequence));
		if (this.captureRawBytes + header.payloadLength > INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES) {
			this.dropCaptureAssembly(header.payloadLength);
			return;
		}
		this.captureFrames[header.chunkIndex] = frameBytes;
		this.captureRawBytes += header.payloadLength;
		this.captureReceivedChunks += 1;
		if (this.captureReceivedChunks !== this.captureChunkCount) return;
		const frames = this.captureFrames.filter((frame): frame is Buffer => frame !== undefined);
		if (frames.length !== this.captureChunkCount) {
			this.dropCaptureAssembly(0);
			return;
		}
		const occurrenceId = this.captureOccurrenceId;
		const rawBytes = this.captureRawBytes;
		this.resetCaptureAssembly();
		if (occurrenceId) this.rememberCaptureOccurrence(occurrenceId, "completed");
		const bufferedBytes = frames.reduce((total, value) => total + value.length, 0);
		if (bufferedBytes > configuredEmitterMaximum() - this.captureCompletedBytes) {
			this.noteRelayDrop(1, rawBytes);
			return;
		}
		this.captureCompletedOccurrences.push({ frames, wireBytes: bufferedBytes, rawBytes });
		this.captureCompletedBytes += bufferedBytes;
		if (this.captureCompletedBytes >= configuredEmitterMaximum()) this.captureStream?.pause();
		this.pumpCaptureValidation();
	}

	private declaredOccurrenceRawBytes(header: IncidentRecorderEncodedFrame["header"]): number {
		const value = header.metadata.occurrenceRawBytes;
		return typeof value === "number" &&
			Number.isSafeInteger(value) &&
			value >= 0 &&
			value <= INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES
			? value
			: header.payloadLength;
	}

	private startCaptureAssembly(header: IncidentRecorderEncodedFrame["header"]): void {
		this.captureOccurrenceId = header.occurrenceId;
		this.captureProducerId = header.producerId;
		this.captureFirstSequence = header.producerSequence - BigInt(header.chunkIndex);
		this.captureChunkCount = header.chunkCount;
		this.captureReceivedChunks = 0;
		this.captureFrames = new Array<Buffer | undefined>(header.chunkCount);
		this.captureRawBytes = 0;
		this.captureDeclaredRawBytes = this.declaredOccurrenceRawBytes(header);
		this.captureStartedAt = Date.now();
	}

	private resetCaptureAssembly(): void {
		this.captureFrames = [];
		this.captureOccurrenceId = undefined;
		this.captureProducerId = undefined;
		this.captureFirstSequence = 0n;
		this.captureChunkCount = 0;
		this.captureReceivedChunks = 0;
		this.captureRawBytes = 0;
		this.captureDeclaredRawBytes = 0;
		this.captureStartedAt = 0;
	}

	private rememberCaptureOccurrence(occurrenceId: string, disposition: "completed" | "discarded"): void {
		this.captureOccurrenceTombstones.delete(occurrenceId);
		this.captureOccurrenceTombstones.set(occurrenceId, disposition);
		while (this.captureOccurrenceTombstones.size > CAPTURE_OCCURRENCE_TOMBSTONE_MAX) {
			this.captureOccurrenceTombstones.delete(this.captureOccurrenceTombstones.keys().next().value as string);
		}
	}

	private discardCaptureOccurrence(occurrenceId: string, bytes: number): void {
		if (this.captureOccurrenceTombstones.has(occurrenceId)) return;
		this.rememberCaptureOccurrence(occurrenceId, "discarded");
		this.noteRelayDrop(1, bytes);
	}

	private pumpCaptureValidation(): void {
		if (this.captureValidationRunning) return;
		const occurrence = this.captureCompletedOccurrences[0];
		if (!occurrence) {
			this.finishCaptureStreamIfDrained();
			return;
		}
		this.captureValidationRunning = true;
		this.enqueueRawFrames(occurrence.frames, occurrence.rawBytes, () => {
			this.captureValidationRunning = false;
			if (this.captureCompletedOccurrences[0] === occurrence) this.captureCompletedOccurrences.shift();
			this.captureCompletedBytes = Math.max(0, this.captureCompletedBytes - occurrence.wireBytes);
			if (this.captureCompletedBytes < configuredEmitterMaximum() / 2) this.captureStream?.resume();
			setImmediate(() => this.pumpCaptureValidation());
		});
	}

	private finishCaptureStreamIfDrained(): void {
		if (
			!this.captureStreamEnded ||
			this.captureCloseRecorded ||
			this.captureValidationRunning ||
			this.captureCompletedOccurrences.length > 0
		)
			return;
		this.captureCloseRecorded = true;
		this.recordDerived("recorder-events", "capture_pipe_closed", {
			incompleteBytes: this.captureStreamEndIncomplete,
		});
	}

	private dropCaptureAssembly(extraBytes: number): void {
		const occurrenceId = this.captureOccurrenceId;
		const bytes = Math.max(this.captureDeclaredRawBytes, this.captureRawBytes + extraBytes);
		this.resetCaptureAssembly();
		if (occurrenceId) this.discardCaptureOccurrence(occurrenceId, bytes);
	}

	private enqueueRawFrames(frames: readonly Buffer[], knownRawBytes: number, complete: () => void): void {
		const decoded: IncidentRecorderEncodedFrame[] = [];
		const occurrenceHash = createHash("sha256");
		let rawBytes = 0;
		let index = 0;
		let first: IncidentRecorderEncodedFrame["header"] | undefined;
		const next = (): void => {
			const frame = frames[index];
			if (!frame) {
				if (
					!first ||
					rawBytes !== first.metadata.occurrenceRawBytes ||
					occurrenceHash.digest("hex") !== first.metadata.occurrenceSha256
				) {
					this.noteRelayDrop(1, knownRawBytes);
					complete();
					return;
				}
				this.enqueueFrames(decoded, false, true);
				complete();
				return;
			}
			try {
				const value = decodeIncidentRecorderFrame(frame);
				first ??= value.header;
				const semanticFlags = INCIDENT_RECORDER_FRAME_FLAGS.critical | INCIDENT_RECORDER_FRAME_FLAGS.terminal;
				if (
					value.header.runId !== this.runId ||
					value.header.runToken !== this.runToken ||
					value.header.runId !== first.runId ||
					value.header.runToken !== first.runToken ||
					value.header.producerId !== first.producerId ||
					value.header.occurrenceId !== first.occurrenceId ||
					value.header.source !== first.source ||
					value.header.type !== first.type ||
					value.header.encoding !== first.encoding ||
					value.header.payloadKind !== first.payloadKind ||
					value.header.chunkCount !== frames.length ||
					value.header.chunkIndex !== index ||
					value.header.producerSequence !== first.producerSequence + BigInt(index) ||
					value.header.wallTimeMs !== first.wallTimeMs ||
					value.header.monotonicNs !== first.monotonicNs ||
					(value.header.flags & semanticFlags) !== (first.flags & semanticFlags) ||
					JSON.stringify(value.header.metadata) !== JSON.stringify(first.metadata)
				)
					throw new Error("Capture occurrence contract changed across chunks");
				decoded.push({ header: value.header, parts: [value.payload], bytes: frame.length });
				occurrenceHash.update(value.payload);
				rawBytes += value.payload.length;
				index += 1;
				setImmediate(next);
			} catch {
				this.noteRelayDrop(1, knownRawBytes);
				complete();
			}
		};
		setImmediate(next);
	}

	private enqueueFrames(
		frames: readonly IncidentRecorderEncodedFrame[],
		reserved: boolean,
		prevalidated = false,
	): { accepted: boolean; reason?: string } {
		if (frames.length === 0) return { accepted: false, reason: "empty_occurrence" };
		const first = frames[0].header;
		const rawBytes = frames.reduce((sum, frame) => sum + frame.header.payloadLength, 0);
		const semanticFlags = INCIDENT_RECORDER_FRAME_FLAGS.critical | INCIDENT_RECORDER_FRAME_FLAGS.terminal;
		const fixed = (frame: IncidentRecorderEncodedFrame): boolean => {
			const header = frame.header;
			return (
				header.runId === first.runId &&
				header.runToken === first.runToken &&
				header.producerId === first.producerId &&
				header.occurrenceId === first.occurrenceId &&
				header.source === first.source &&
				header.type === first.type &&
				header.encoding === first.encoding &&
				header.payloadKind === first.payloadKind &&
				header.chunkCount === frames.length &&
				header.wallTimeMs === first.wallTimeMs &&
				header.monotonicNs === first.monotonicNs &&
				(header.flags & semanticFlags) === (first.flags & semanticFlags) &&
				JSON.stringify(header.metadata) === JSON.stringify(first.metadata)
			);
		};
		const acceptedIdentity =
			(first.runId === this.runId && first.runToken === this.runToken) ||
			(this.serviceSink && this.serviceEmitters.has(`${first.runId}\0${first.runToken}`));
		const relayIdentity =
			this.serviceSink && acceptedIdentity ? { runId: first.runId, runToken: first.runToken } : undefined;
		if (
			!acceptedIdentity ||
			rawBytes > INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES ||
			frames.some((frame, index) => {
				try {
					validateIncidentRecorderFrameFlags(frame.header.flags, frame.header.chunkIndex, frame.header.chunkCount);
				} catch {
					return true;
				}
				return (
					!fixed(frame) ||
					frame.header.chunkIndex !== index ||
					frame.header.producerSequence !== first.producerSequence + BigInt(index)
				);
			})
		) {
			this.noteRelayDrop(1, rawBytes, relayIdentity);
			return { accepted: false, reason: "invalid_occurrence_contract" };
		}
		if (!prevalidated) {
			const expectedDigest =
				typeof first.metadata.occurrenceSha256 === "string" ? first.metadata.occurrenceSha256 : undefined;
			const expectedBytes =
				typeof first.metadata.occurrenceRawBytes === "number" ? first.metadata.occurrenceRawBytes : undefined;
			const actualDigest = createHash("sha256");
			for (const frame of frames) actualDigest.update(frame.parts.at(-1) ?? Buffer.alloc(0));
			if (expectedBytes !== rawBytes || !expectedDigest || actualDigest.digest("hex") !== expectedDigest) {
				this.noteRelayDrop(1, rawBytes, relayIdentity);
				return { accepted: false, reason: "occurrence_checksum_or_length_mismatch" };
			}
		}
		const bytes = frames.reduce((sum, frame) => sum + Math.ceil((frame.header.payloadLength * 4) / 3) + 12 * 1024, 0);
		const ceiling = reserved ? JOURNAL_RELAY_MAX_BYTES : JOURNAL_RELAY_MAX_BYTES - CONTROL_RESERVE_BYTES;
		if (this.stopped || bytes > ceiling || this.relayBytes + bytes > ceiling) {
			this.noteRelayDrop(1, rawBytes, relayIdentity);
			return { accepted: false, reason: this.stopped ? "stopped" : "relay_capacity" };
		}
		const identity = { runId: first.runId, runToken: first.runToken };
		let firstWrapperSequence: bigint;
		try {
			firstWrapperSequence = this.wrapperFrontier.allocate(identity, frames.length);
		} catch (error) {
			if (error instanceof IncidentRecorderWrapperFrontierSaturatedError)
				this.reportWrapperFrontierSaturation(error);
			throw error;
		}
		const wrapperSequences = frames.map((_frame, index) => firstWrapperSequence + BigInt(index));
		if (first.type === "supervisor_exit" || first.type === "capture_channel_terminal") {
			this.finalizationFrontiers.set(first.occurrenceId, {
				occurrenceId: first.occurrenceId,
				producerId: first.producerId,
				type: first.type,
				firstProducerSequence: first.producerSequence.toString(),
				lastProducerSequence: (first.producerSequence + BigInt(frames.length - 1)).toString(),
				firstWrapperSequence: (wrapperSequences[0] ?? 0n).toString(),
				lastWrapperSequence: (wrapperSequences.at(-1) ?? 0n).toString(),
			});
		}
		this.relayQueue.push({
			frames,
			wrapperSequences,
			bytes,
			rawBytes,
			lineIndex: 0,
			reserved,
			occurrenceId: first.occurrenceId,
		});
		this.relayBytes += bytes;
		this.pumpRelay();
		return { accepted: true };
	}

	private renderJournalLine(frame: IncidentRecorderEncodedFrame, wrapperSequence: bigint): Buffer {
		const payload = frame.parts.at(-1) ?? Buffer.alloc(0);
		const metadata = frame.header.metadata;
		const line: IncidentJournalLine = {
			schema: "prime-agent-raw-v1",
			runId: frame.header.runId,
			runToken: frame.header.runToken,
			producerId: frame.header.producerId,
			producerSequence: frame.header.producerSequence.toString(),
			wrapperSequence: wrapperSequence.toString(),
			occurrenceId: frame.header.occurrenceId,
			chunkIndex: frame.header.chunkIndex,
			chunkCount: frame.header.chunkCount,
			source: frame.header.source,
			type: frame.header.type,
			encoding: frame.header.encoding,
			payloadKind: frame.header.payloadKind,
			producerPid: typeof metadata.producerPid === "number" ? metadata.producerPid : null,
			producerStartId: typeof metadata.producerStartId === "string" ? metadata.producerStartId : null,
			wrapperPid: process.pid,
			wrapperStartId: this.wrapperStartId ?? null,
			targetPid:
				typeof metadata.targetPid === "number"
					? metadata.targetPid
					: typeof this.sourceIdentity.pid === "number"
						? this.sourceIdentity.pid
						: null,
			targetStartId:
				typeof metadata.targetProcessStartId === "string"
					? metadata.targetProcessStartId
					: typeof this.sourceIdentity.processStartId === "string"
						? this.sourceIdentity.processStartId
						: null,
			bootId: this.bootId ?? null,
			machineId: this.machineId ?? null,
			systemdInvocationId: this.invocationId ?? null,
			systemdCatPid: this.cat?.pid ?? null,
			systemdCatStartId: this.catStartId ?? null,
			eventWallTimeMs: frame.header.wallTimeMs.toString(),
			eventMonotonicNs: frame.header.monotonicNs.toString(),
			rawOccurrenceBytes:
				typeof metadata.occurrenceRawBytes === "number" ? metadata.occurrenceRawBytes : payload.length,
			occurrenceSha256: typeof metadata.occurrenceSha256 === "string" ? metadata.occurrenceSha256 : "unavailable",
			chunkBytes: payload.length,
			chunkSha256: createHash("sha256").update(payload).digest("hex"),
			frameChecksum: frame.header.checksum,
			flags: frame.header.flags,
			metadata,
			payloadBase64: payload.toString("base64"),
			attemptedRecords: typeof metadata.attemptedRecords === "number" ? metadata.attemptedRecords : null,
			attemptedBytes: typeof metadata.attemptedBytes === "number" ? metadata.attemptedBytes : null,
			queuedRecords: typeof metadata.queuedRecords === "number" ? metadata.queuedRecords : null,
			queuedBytes: typeof metadata.queuedBytes === "number" ? metadata.queuedBytes : null,
			droppedRecords: typeof metadata.droppedRecords === "number" ? metadata.droppedRecords : null,
			droppedBytes: typeof metadata.droppedBytes === "number" ? metadata.droppedBytes : null,
			observationDisposition: "observed_by_wrapper",
			queueDisposition: "locally_admitted",
			wrapperRelayDisposition: "locally_admitted",
			streamDisposition: "systemd_cat_stdin_write_attempted",
			journalDurability: "not_asserted_by_writer",
			wrapperRelayDroppedRecords: this.relayDroppedRecords,
			wrapperRelayDroppedBytes: this.relayDroppedBytes,
			wrapperRelayUncertainRecords: this.relayUncertainRecords,
		};
		const encoded = Buffer.from(JSON.stringify(line), "utf8");
		if (encoded.includes(0) || encoded.includes(10) || encoded.length >= INCIDENT_RECORDER_JOURNAL_LINE_MAX_BYTES) {
			throw new Error("Incident journal line exceeds the dedicated namespace LineMax safety bound");
		}
		return Buffer.concat([encoded, Buffer.from("\n")]);
	}

	private emitRelayLossCheckpoint(): void {
		const transportChanged =
			this.transportCorruptPackets !== this.transportReportedCorruptPackets ||
			this.transportCorruptWireBytes !== this.transportReportedCorruptWireBytes ||
			this.transportSequenceGapEvents !== this.transportReportedSequenceGapEvents ||
			this.transportMissingPackets !== this.transportReportedMissingPackets;
		if (this.stopped || (this.relayDroppedRecords === this.relayLossReportedRecords && !transportChanged)) return;
		const snapshotRecords = this.relayDroppedRecords;
		const snapshotBytes = this.relayDroppedBytes;
		const identity = this.relayLossIdentity ?? { runId: this.runId, runToken: this.runToken };
		const sequence = ++this.relayLossProducerSequence;
		const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
		const frame = encodeIncidentRecorderFrame(
			{
				runId: identity.runId,
				runToken: identity.runToken,
				producerId: this.relayLossProducerId,
				occurrenceId: newIncidentRecorderIdentity(),
				producerSequence: sequence,
				wallTimeMs: BigInt(Date.now()),
				monotonicNs: process.hrtime.bigint(),
				payloadKind: "loss",
				flags: INCIDENT_RECORDER_FRAME_FLAGS.firstChunk | INCIDENT_RECORDER_FRAME_FLAGS.lastChunk,
				chunkIndex: 0,
				chunkCount: 1,
				source: "recorder-control",
				type: "wrapper_relay_loss_checkpoint",
				encoding: "none",
				metadata: {
					lostRecords: snapshotRecords,
					lostBytes: snapshotBytes,
					recordsSinceLastMarker: snapshotRecords - this.relayLossReportedRecords,
					bytesSinceLastMarker: snapshotBytes - this.relayLossReportedBytes,
					transportCorruptPackets: this.transportCorruptPackets.toString(),
					transportCorruptPacketsSinceLastMarker: (
						this.transportCorruptPackets - this.transportReportedCorruptPackets
					).toString(),
					transportCorruptWireBytes: this.transportCorruptWireBytes.toString(),
					transportCorruptWireBytesSinceLastMarker: (
						this.transportCorruptWireBytes - this.transportReportedCorruptWireBytes
					).toString(),
					transportSequenceGapEvents: this.transportSequenceGapEvents.toString(),
					transportSequenceGapEventsSinceLastMarker: (
						this.transportSequenceGapEvents - this.transportReportedSequenceGapEvents
					).toString(),
					transportMissingPackets: this.transportMissingPackets.toString(),
					transportMissingPacketsSinceLastMarker: (
						this.transportMissingPackets - this.transportReportedMissingPackets
					).toString(),
					occurrenceRawBytes: 0,
					occurrenceSha256: emptyDigest,
					producerPid: process.pid,
					producerStartId: this.wrapperStartId ?? "unavailable",
				},
			},
			Buffer.alloc(0),
		);
		const admission = this.enqueueFrames([frame], true, true);
		if (admission.accepted) {
			this.relayLossReportedRecords = snapshotRecords;
			this.relayLossReportedBytes = snapshotBytes;
			this.transportReportedCorruptPackets = this.transportCorruptPackets;
			this.transportReportedCorruptWireBytes = this.transportCorruptWireBytes;
			this.transportReportedSequenceGapEvents = this.transportSequenceGapEvents;
			this.transportReportedMissingPackets = this.transportMissingPackets;
			this.relayLossIdentity = undefined;
		}
	}

	private noteRelayDrop(records: number, bytes: number, identity?: { runId: string; runToken: string }): void {
		this.relayDroppedRecords += records;
		this.relayDroppedBytes += bytes;
		if (identity) this.relayLossIdentity = identity;
	}

	private pumpRelay(): void {
		if (this.pumping || (this.stopped && this.relayQueue.length === 0)) return;
		const child = this.cat;
		const stdin = child?.stdin;
		const occurrence = this.relayQueue[0];
		if (!child || !stdin || stdin.destroyed || !occurrence) return;
		const frame = occurrence.frames[occurrence.lineIndex];
		const wrapperSequence = occurrence.wrapperSequences[occurrence.lineIndex];
		if (!frame || wrapperSequence === undefined) {
			this.relayQueue.shift();
			this.relayBytes = Math.max(0, this.relayBytes - occurrence.bytes);
			this.pumpRelay();
			return;
		}
		let line: Buffer;
		try {
			line = this.renderJournalLine(frame, wrapperSequence);
		} catch {
			this.relayQueue.shift();
			this.relayBytes = Math.max(0, this.relayBytes - occurrence.bytes);
			this.noteRelayDrop(1, occurrence.rawBytes, { runId: frame.header.runId, runToken: frame.header.runToken });
			this.pumpRelay();
			return;
		}
		this.pumping = true;
		stdin.write(line, (error) => {
			this.pumping = false;
			if (error) {
				this.relayUncertainRecords += 1;
				this.relayQueue.shift();
				this.relayBytes = Math.max(0, this.relayBytes - occurrence.bytes);
				this.noteRelayDrop(1, occurrence.rawBytes, { runId: frame.header.runId, runToken: frame.header.runToken });
				try {
					child.stdin?.destroy();
				} catch {}
				this.handleCatUnavailable(child);
				return;
			}
			occurrence.lineIndex += 1;
			if (occurrence.lineIndex >= occurrence.frames.length) {
				this.relayQueue.shift();
				this.relayBytes = Math.max(0, this.relayBytes - occurrence.bytes);
			}
			setImmediate(() => this.pumpRelay());
		});
	}

	recordDerived(source: CaptureSource, type: string, fields: Record<string, unknown>): IncidentRecorderAdmission {
		return this.emitter.emitDerived(source, type, fields);
	}

	recordExactBytes(
		source: CaptureSource,
		type: string,
		bytes: Uint8Array,
		encoding: string,
		metadata: Record<string, unknown>,
	): IncidentRecorderAdmission {
		return this.emitter.emitBytes(source, type, bytes, metadata, encoding);
	}

	private recordDerivedForRunInternal(
		identity: { runId: string; runToken: string },
		source: CaptureSource,
		type: string,
		fields: Record<string, unknown>,
		occurrenceIdOverride?: string,
	): IncidentRecorderAdmission {
		const key = `${identity.runId}\0${identity.runToken}`;
		if (this.serviceIdentityIsSealed(key))
			return { accepted: false, disposition: "rejected", reason: "run_identity_sealed" };
		if (this.stopped) return { accepted: false, disposition: "rejected", reason: "stopped" };
		const emitter = this.serviceEmitter(identity);
		return (
			emitter?.emitDerived(source, type, fields, occurrenceIdOverride) ?? {
				accepted: false,
				disposition: "rejected",
				reason: this.stopped ? "stopped" : "queue_capacity",
			}
		);
	}

	recordDerivedForRun(
		identity: { runId: string; runToken: string },
		source: CaptureSource,
		type: string,
		fields: Record<string, unknown>,
	): IncidentRecorderAdmission {
		return this.recordDerivedForRunInternal(identity, source, type, fields);
	}

	recordDerivedForRunWithOccurrenceId(
		identity: { runId: string; runToken: string },
		source: CaptureSource,
		type: string,
		fields: Record<string, unknown>,
		occurrenceId: string,
	): IncidentRecorderAdmission {
		if (!CANONICAL_INCIDENT_RECORDER_ID.test(occurrenceId))
			throw new Error("Invalid incident-recorder occurrence identity");
		return this.recordDerivedForRunInternal(identity, source, type, fields, occurrenceId);
	}

	private stopServiceEmitter(
		key: string,
		emitter: BoundedFrameEmitter,
		deadlineMs: number,
		terminalOccurrenceId?: string,
	): Promise<BoundedFrameEmitterStopResult> {
		const existing = this.serviceEmitterStops.get(key);
		if (existing) return existing;
		const stopping = emitter.stop(deadlineMs, terminalOccurrenceId).finally(() => {
			if (this.serviceEmitters.get(key) === emitter) this.serviceEmitters.delete(key);
			if (this.serviceEmitterStops.get(key) === stopping) this.serviceEmitterStops.delete(key);
		});
		this.serviceEmitterStops.set(key, stopping);
		return stopping;
	}

	sealRunIdentity(
		identity: IncidentRecorderServiceIdentity,
		deadlineMs = 1_000,
		terminalOccurrenceId?: string,
	): Promise<IncidentRecorderRunIdentitySealResult> {
		const key = `${identity.runId}\0${identity.runToken}`;
		const existingSeal = this.serviceIdentitySeals.get(key);
		if (existingSeal) return existingSeal.promise;
		if (this.serviceIdentitySealFence.has(identity)) return Promise.resolve(immutableFenceOnlySealResult(identity));
		// Claim the exact, never-evicted fence before stopping an emitter. If this
		// writer is at fence capacity, the emitter and its queued records remain
		// untouched and the caller receives the typed saturation error.
		this.reserveServiceIdentitySealFence(identity);

		let emitter = this.serviceEmitters.get(key);
		if (
			!emitter &&
			this.serviceSink &&
			CANONICAL_INCIDENT_RECORDER_ID.test(identity.runId) &&
			CANONICAL_INCIDENT_RECORDER_ID.test(identity.runToken) &&
			this.serviceEmitters.size < SERVICE_EMITTER_MAX_IDENTITIES
		) {
			// The terminal occurrence consumes wrapper sequence space too; reserve
			// the identity before constructing its emitter.
			this.reserveWrapperFrontier(identity);
			emitter = this.createEmitter(identity, SERVICE_EMITTER_MAX_BYTES);
			this.serviceEmitters.set(key, emitter);
		}
		const stopping = emitter
			? this.stopServiceEmitter(key, emitter, deadlineMs, terminalOccurrenceId)
			: Promise.resolve<BoundedFrameEmitterStopResult>({
					terminalAdmission: {
						accepted: false,
						disposition: "rejected",
						reason: this.stopped ? "stopped" : "queue_capacity",
					},
					totalLoss: { records: 0, bytes: 0 },
					drainTimeoutLoss: { records: 0, bytes: 0 },
					drainTimeoutUncertainty: { records: 0, bytes: 0 },
					terminalDrained: true,
				});
		let sealState: ServiceEmitterSealState;
		const promise = stopping.then((stopResult) => {
			const terminalOccurrenceId = stopResult.terminalAdmission?.accepted
				? stopResult.terminalAdmission.occurrenceId
				: undefined;
			const result = immutableSealResult(
				identity,
				stopResult,
				terminalOccurrenceId ? this.finalizationFrontiers.get(terminalOccurrenceId) : undefined,
			);
			sealState.result = result;
			sealState.fingerprint = sealFingerprint(result);
			return result;
		});
		sealState = { promise };
		if (!this.retainServiceIdentitySeal(key, sealState))
			return Promise.resolve(immutableFenceOnlySealResult(identity));
		return promise;
	}

	fenceRunIdentity(
		identity: IncidentRecorderServiceIdentity,
		options: IncidentRecorderRunIdentitySealReplayOptions = {},
	): IncidentRecorderRunIdentitySealResult {
		if (options.durableReplay === true && !validServiceIdentity(identity))
			throw new Error("Invalid incident-recorder service identity");
		const key = `${identity.runId}\0${identity.runToken}`;
		const existing = this.serviceIdentitySeals.get(key);
		if (existing?.result) return existing.result;
		if (options.durableReplay === true && this.serviceEmitterStops.has(key))
			throw new Error("Incident recorder service identity is active or stopping");
		if (options.durableReplay === true && !this.serviceEmitters.has(key) && !this.serviceEmitterStops.has(key))
			return immutableFenceOnlySealResult(identity);
		if (!this.serviceIdentitySealFence.has(identity)) this.reserveServiceIdentitySealFence(identity);
		this.serviceEmitters.get(key)?.fenceWithoutTerminal();
		this.serviceEmitters.delete(key);
		this.serviceEmitterStops.delete(key);
		const result = immutableFenceOnlySealResult(identity);
		const promise = Promise.resolve(result);
		if (!this.retainServiceIdentitySeal(key, { promise, result, fingerprint: sealFingerprint(result) })) {
			return result;
		}
		return result;
	}

	adoptRunIdentitySeal(
		value: unknown,
		options: IncidentRecorderRunIdentitySealReplayOptions = {},
	): IncidentRecorderRunIdentitySealAdoption {
		const seal = parseIncidentRecorderRunIdentitySeal(value);
		if (!seal) return Object.freeze({ adopted: false, disposition: "rejected", reason: "invalid_seal_record" });
		const key = `${seal.runId}\0${seal.runToken}`;
		const fingerprint = sealFingerprint(seal);
		const existingSeal = this.serviceIdentitySeals.get(key);
		if (existingSeal) {
			if (!existingSeal.result)
				return Object.freeze({
					adopted: false,
					disposition: "rejected",
					reason: "run_identity_seal_in_progress",
				});
			if (existingSeal.fingerprint !== fingerprint)
				return Object.freeze({
					adopted: false,
					disposition: "rejected",
					reason: "run_identity_seal_conflict",
				});
			return Object.freeze({
				adopted: true,
				disposition: "already_adopted",
				seal: existingSeal.result,
			});
		}
		const localEmitter = this.serviceEmitters.get(key);
		if (this.serviceEmitterStops.has(key))
			return Object.freeze({
				adopted: false,
				disposition: "rejected",
				reason: "run_identity_active_or_stopping",
			});
		if (options.durableReplay === true) {
			if (!localEmitter) return Object.freeze({ adopted: true, disposition: "adopted", seal });
			try {
				this.reserveServiceIdentitySealFence({ runId: seal.runId, runToken: seal.runToken });
			} catch (error) {
				if (error instanceof IncidentRecorderServiceIdentitySealFenceSaturatedError)
					return Object.freeze({
						adopted: false,
						disposition: "rejected",
						reason: "run_identity_seal_capacity_exhausted",
					});
				throw error;
			}
			localEmitter.fenceWithoutTerminal();
			this.serviceEmitters.delete(key);
			const promise = Promise.resolve(seal);
			if (!this.retainServiceIdentitySeal(key, { promise, result: seal, fingerprint }))
				return Object.freeze({
					adopted: false,
					disposition: "rejected",
					reason: "run_identity_seal_capacity_exhausted",
				});
			return Object.freeze({ adopted: true, disposition: "adopted", seal });
		}
		if (localEmitter)
			return Object.freeze({
				adopted: false,
				disposition: "rejected",
				reason: "run_identity_active_or_stopping",
			});
		if (!this.canRetainServiceIdentitySeal())
			return Object.freeze({
				adopted: false,
				disposition: "rejected",
				reason: "run_identity_seal_capacity_exhausted",
			});
		if (!this.serviceIdentitySealFence.has({ runId: seal.runId, runToken: seal.runToken })) {
			try {
				this.reserveServiceIdentitySealFence({ runId: seal.runId, runToken: seal.runToken });
			} catch (error) {
				if (error instanceof IncidentRecorderServiceIdentitySealFenceSaturatedError)
					return Object.freeze({
						adopted: false,
						disposition: "rejected",
						reason: "run_identity_seal_capacity_exhausted",
					});
				throw error;
			}
		}
		const promise = Promise.resolve(seal);
		if (!this.retainServiceIdentitySeal(key, { promise, result: seal, fingerprint }))
			return Object.freeze({
				adopted: false,
				disposition: "rejected",
				reason: "run_identity_seal_capacity_exhausted",
			});
		return Object.freeze({ adopted: true, disposition: "adopted", seal });
	}

	async releaseRunIdentity(identity: { runId: string; runToken: string }, deadlineMs = 1_000): Promise<void> {
		if (!this.serviceSink) return;
		const key = `${identity.runId}\0${identity.runToken}`;
		const seal = this.serviceIdentitySeals.get(key);
		if (seal) {
			await seal.promise;
			return;
		}
		const emitter = this.serviceEmitters.get(key);
		if (!emitter) {
			const stopping = this.serviceEmitterStops.get(key);
			if (stopping) await stopping;
			return;
		}
		await this.stopServiceEmitter(key, emitter, deadlineMs);
	}

	recordExactBytesForRun(
		identity: { runId: string; runToken: string },
		source: CaptureSource,
		type: string,
		bytes: Uint8Array,
		encoding: string,
		metadata: Record<string, unknown>,
	): IncidentRecorderAdmission {
		if (this.serviceIdentityIsSealed(`${identity.runId}\0${identity.runToken}`))
			return { accepted: false, disposition: "rejected", reason: "run_identity_sealed" };
		const emitter = this.serviceEmitter(identity);
		return (
			emitter?.emitBytes(source, type, bytes, metadata, encoding) ?? {
				accepted: false,
				disposition: "rejected",
				reason: this.stopped ? "stopped" : "queue_capacity",
			}
		);
	}

	private async waitForCatClose(child: ChildProcess, deadlineMs: number): Promise<boolean> {
		if (child.exitCode !== null || child.signalCode !== null) return true;
		return await new Promise<boolean>((resolve) => {
			let settled = false;
			const finish = (closed: boolean) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				child.off("close", onClose);
				resolve(closed);
			};
			const onClose = () => finish(true);
			const timer = setTimeout(() => finish(false), Math.max(1, deadlineMs));
			timer.unref();
			child.once("close", onClose);
		});
	}

	async stop(deadlineMs = 1_000): Promise<void> {
		if (this.stopped) return;
		const shutdownDeadline = Date.now() + deadlineMs;
		const remaining = (): number => Math.max(1, shutdownDeadline - Date.now());
		while (
			(this.captureValidationRunning || this.captureCompletedOccurrences.length > 0) &&
			Date.now() < shutdownDeadline
		) {
			await new Promise<void>((resolve) => setTimeout(resolve, 10));
		}
		if (this.relayLossTimer) clearInterval(this.relayLossTimer);
		this.relayLossTimer = undefined;
		this.emitRelayLossCheckpoint();
		const serviceEmitters = [...this.serviceEmitters.entries()];
		await Promise.all(serviceEmitters.map(([key, emitter]) => this.stopServiceEmitter(key, emitter, remaining())));
		const emitterLossBefore = this.emitter.lossCounters();
		const emitterStop = await this.emitter.stop(remaining());
		const emitterLossAfter = this.emitter.lossCounters();
		this.emitterFinalTailLoss = {
			records: emitterLossAfter.records - emitterLossBefore.records,
			bytes: emitterLossAfter.bytes - emitterLossBefore.bytes,
		};
		if (emitterStop.terminalAdmission?.accepted)
			this.terminalOccurrenceId = emitterStop.terminalAdmission.occurrenceId;
		while ((this.relayQueue.length > 0 || this.pumping) && Date.now() < shutdownDeadline) {
			await new Promise<void>((resolve) => setTimeout(resolve, 10));
		}
		const cleanRelayDrain = this.relayQueue.length === 0 && !this.pumping;
		this.stopped = true;
		if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
		this.reconnectTimer = undefined;
		// Anything still queued was never handed to a completed stream write callback.
		for (const occurrence of this.relayQueue.splice(0)) {
			this.finalTailDroppedRecords += 1;
			this.finalTailDroppedBytes += occurrence.rawBytes;
			this.noteRelayDrop(1, occurrence.rawBytes);
		}
		this.relayBytes = 0;
		const child = this.cat;
		if (!child) return;
		if (cleanRelayDrain) {
			try {
				child.stdin?.end();
			} catch {}
			if (await this.waitForCatClose(child, remaining())) return;
		}
		try {
			child.stdin?.destroy();
		} catch {}
		try {
			child.kill("SIGTERM");
		} catch {}
		if (await this.waitForCatClose(child, 250)) return;
		try {
			child.kill("SIGKILL");
		} catch {}
		await this.waitForCatClose(child, 250);
	}

	finalizationExpectation(supervisorExitOccurrenceId: string): IncidentRecorderFinalizationExpectation {
		return {
			runId: this.runId,
			runToken: this.runToken,
			wrapperPid: process.pid,
			wrapperStartId: this.wrapperStartId ?? null,
			supervisorExit: this.finalizationFrontiers.get(supervisorExitOccurrenceId),
			wrapperTerminal: this.terminalOccurrenceId
				? this.finalizationFrontiers.get(this.terminalOccurrenceId)
				: undefined,
			finalQueuedTailLoss: { records: this.finalTailDroppedRecords, bytes: this.finalTailDroppedBytes },
			emitterFinalTailLoss: this.emitterFinalTailLoss,
		};
	}

	get isStopped(): boolean {
		return this.stopped;
	}
}
