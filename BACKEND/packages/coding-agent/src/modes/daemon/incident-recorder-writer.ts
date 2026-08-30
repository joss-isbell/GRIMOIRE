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
// One tombstone per occurrence that can be admitted inside the producer's bounded
// transport window. Real old-sequence duplicates remain fenced by sequence state
// after this LRU rolls over.
const CAPTURE_OCCURRENCE_TOMBSTONE_MAX = Math.ceil(
	INCIDENT_RECORDER_EMITTER_MAX_BYTES / (INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES + 3 * 255 + 4 * 1024),
);

type Scalar = string | number | boolean | null;
type ScalarMetadata = Readonly<Record<string, Scalar>>;
type CaptureSource = string;

const DIAGNOSTIC_METADATA_MAX_BYTES = INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES - 1024;
const DIAGNOSTIC_CAUSAL_TEXT_MAX_BYTES = 96;
const DIAGNOSTIC_TEXT_MAX_BYTES = 512;
const DIAGNOSTIC_ERROR_NAME_MAX_BYTES = 96;
const DIAGNOSTIC_ERROR_MESSAGE_MAX_BYTES = 512;
const DIAGNOSTIC_ERROR_STACK_HASH_MAX_BYTES = 64 * 1024;

// These fields are ordered ahead of general diagnostics so a crowded metadata
// envelope retains the identities needed to correlate a daemon or kernel crash.
const DIAGNOSTIC_CAUSAL_SCALAR_KEYS = [
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
	"fd",
	"incompleteBytes",
	"launchBytes",
	"launchOccurrenceId",
	"lostBytes",
	"lostRecords",
	"message",
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
	"reason",
	"recordsSinceLastMarker",
	"registrationOnly",
	"runId",
	"runName",
	"signal",
	"socketExists",
	"socketPath",
	"source",
	"sourceBytes",
	"retainedBytes",
	"sourceTruncated",
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
	"sourceProducerId",
	"state",
	"targetPid",
	"targetProcessStartId",
	"thresholdMs",
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
] as const;

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
		return descriptor && "value" in descriptor
			? { found: true, value: descriptor.value }
			: { found: false };
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

function addMetadataValue(result: Record<string, Scalar>, key: string, value: Scalar): boolean {
	result[key] = value;
	if (metadataBytes(result) <= DIAGNOSTIC_METADATA_MAX_BYTES) return true;
	delete result[key];
	return false;
}

function normalizeErrorMetadata(
	fields: Record<string, unknown>,
	result: Record<string, Scalar>,
	markTruncated: () => void,
): void {
	const errorProperty = ownDataProperty(fields, "error");
	if (!errorProperty.found) return;
	const error = errorProperty.value;
	if (typeof error === "string") {
		const message = boundedUtf8(error, DIAGNOSTIC_ERROR_MESSAGE_MAX_BYTES);
		if (!addMetadataValue(result, "errorName", "Error")) markTruncated();
		if (!addMetadataValue(result, "errorMessage", message.value)) markTruncated();
		if (!addMetadataValue(result, "errorMessageTruncated", message.truncated)) markTruncated();
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
	if (!addMetadataValue(result, "errorName", name.value)) markTruncated();
	if (name.truncated) markTruncated();

	if (hasMessage) {
		const message = boundedUtf8(messageProperty.value as string, DIAGNOSTIC_ERROR_MESSAGE_MAX_BYTES);
		if (!addMetadataValue(result, "errorMessage", message.value)) markTruncated();
		if (!addMetadataValue(result, "errorMessageTruncated", message.truncated)) markTruncated();
		if (message.truncated) markTruncated();
	}
	if (hasStack) {
		const stack = boundedUtf8(stackProperty.value as string, DIAGNOSTIC_ERROR_STACK_HASH_MAX_BYTES);
		const digest = createHash("sha256").update(stack.value).digest("hex");
		if (!addMetadataValue(result, "errorStackSha256", digest)) markTruncated();
		if (!addMetadataValue(result, "errorStackDigestScope", stack.truncated ? "retained_prefix" : "complete"))
			markTruncated();
		if (!addMetadataValue(result, "errorStackTruncated", stack.truncated)) markTruncated();
		if (stack.truncated) markTruncated();
	}
}

function scalarMetadata(fields: Record<string, unknown>): Record<string, Scalar> {
	const result: Record<string, Scalar> = { diagnosticMetadataTruncated: false };
	const markTruncated = (): void => {
		result.diagnosticMetadataTruncated = true;
	};
	for (const key of DIAGNOSTIC_CAUSAL_SCALAR_KEYS) {
		const property = ownDataProperty(fields, key);
		if (!property.found) continue;
		const normalized = scalarValue(property.value, DIAGNOSTIC_CAUSAL_TEXT_MAX_BYTES);
		if (normalized.value !== undefined && !addMetadataValue(result, key, normalized.value)) markTruncated();
		if (normalized.truncated) markTruncated();
	}
	normalizeErrorMetadata(fields, result, markTruncated);
	for (const key of DIAGNOSTIC_SCALAR_KEYS) {
		if (DIAGNOSTIC_CAUSAL_SCALAR_KEY_SET.has(key)) continue;
		const property = ownDataProperty(fields, key);
		if (!property.found) continue;
		const normalized = scalarValue(property.value, DIAGNOSTIC_TEXT_MAX_BYTES);
		if (normalized.value !== undefined && !addMetadataValue(result, key, normalized.value)) markTruncated();
		if (normalized.truncated) markTruncated();
	}
	return result;
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
			reason: "stopped" | "terminal_reserved" | "occurrence_too_large" | "queue_capacity" | "encoding_failed";
	  };

interface ProducerCounters {
	attemptedRecords: number;
	attemptedBytes: number;
	queuedRecords: number;
	queuedBytes: number;
	droppedRecords: number;
	droppedBytes: number;
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

	emitDerived(source: CaptureSource, type: string, fields: Record<string, unknown>): IncidentRecorderAdmission {
		return this.emitOccurrence(source, type, Buffer.alloc(0), "derived-scalar", "none", scalarMetadata(fields));
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
		const occurrenceId = newIncidentRecorderIdentity();
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

	async stop(deadlineMs = 1_000): Promise<IncidentRecorderAdmission | undefined> {
		if (!this.ownerIsValid()) {
			this.disableInvalidOwner();
			return undefined;
		}
		if (this.stopped || this.stopping) return undefined;
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
		return terminalAdmission;
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

export interface IncidentRecorderWriterOptions {
	runDir: string;
	runId?: string;
	runToken?: string;
	bootId?: string;
	wrapperStartId?: string;
	serviceSink?: boolean;
}

export class IncidentRecorderWriter {
	private readonly runId: string;
	private readonly runToken: string;
	private readonly wrapperStartId: string | undefined;
	private readonly bootId: string | undefined;
	private readonly serviceSink: boolean;
	private readonly machineId = linuxIdentity("/etc/machine-id", /^[0-9a-f]{32}$/i);
	private readonly invocationId = process.env.INVOCATION_ID?.match(/^[0-9a-f]{32}$/i)?.[0];
	private readonly emitter: BoundedFrameEmitter;
	private readonly serviceEmitters = new Map<string, BoundedFrameEmitter>();
	private readonly serviceEmitterStops = new Map<string, Promise<void>>();
	private readonly relayQueue: RelayOccurrence[] = [];
	private relayBytes = 0;
	private readonly wrapperSequences = new Map<string, bigint>();
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
		this.emitter = this.createEmitter({ runId: this.runId, runToken: this.runToken });
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
		if (!this.serviceSink || !/^[0-9a-f-]{36}$/i.test(identity.runId) || !/^[0-9a-f-]{36}$/i.test(identity.runToken))
			return undefined;
		const key = `${identity.runId}\0${identity.runToken}`;
		let emitter = this.serviceEmitters.get(key);
		if (!emitter && this.serviceEmitters.size < SERVICE_EMITTER_MAX_IDENTITIES) {
			emitter = this.createEmitter(identity, SERVICE_EMITTER_MAX_BYTES);
			this.serviceEmitters.set(key, emitter);
		}
		return emitter;
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
		const identityKey = `${first.runId}\0${first.runToken}`;
		let wrapperSequence = this.wrapperSequences.get(identityKey) ?? 0n;
		const wrapperSequences = frames.map(() => ++wrapperSequence);
		this.wrapperSequences.set(identityKey, wrapperSequence);
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

	recordDerivedForRun(
		identity: { runId: string; runToken: string },
		source: CaptureSource,
		type: string,
		fields: Record<string, unknown>,
	): IncidentRecorderAdmission {
		const emitter = this.serviceEmitter(identity);
		return (
			emitter?.emitDerived(source, type, fields) ?? {
				accepted: false,
				disposition: "rejected",
				reason: this.stopped ? "stopped" : "queue_capacity",
			}
		);
	}

	private async stopServiceEmitter(key: string, emitter: BoundedFrameEmitter, deadlineMs: number): Promise<void> {
		const existing = this.serviceEmitterStops.get(key);
		if (existing) {
			await existing;
			return;
		}
		const stopping = emitter.stop(deadlineMs).then(() => undefined);
		this.serviceEmitterStops.set(key, stopping);
		try {
			await stopping;
		} finally {
			if (this.serviceEmitters.get(key) === emitter) this.serviceEmitters.delete(key);
			this.wrapperSequences.delete(key);
			if (this.serviceEmitterStops.get(key) === stopping) this.serviceEmitterStops.delete(key);
		}
	}

	async releaseRunIdentity(identity: { runId: string; runToken: string }, deadlineMs = 1_000): Promise<void> {
		if (!this.serviceSink) return;
		const key = `${identity.runId}\0${identity.runToken}`;
		const emitter = this.serviceEmitters.get(key);
		if (!emitter) {
			this.wrapperSequences.delete(key);
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
		const terminalAdmission = await this.emitter.stop(remaining());
		const emitterLossAfter = this.emitter.lossCounters();
		this.emitterFinalTailLoss = {
			records: emitterLossAfter.records - emitterLossBefore.records,
			bytes: emitterLossAfter.bytes - emitterLossBefore.bytes,
		};
		if (terminalAdmission?.accepted) this.terminalOccurrenceId = terminalAdmission.occurrenceId;
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
