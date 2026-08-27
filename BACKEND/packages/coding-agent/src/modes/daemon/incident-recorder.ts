import { type ChildProcess, type SpawnSyncReturns, spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	appendFile,
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
	readFile,
	readFileSync,
	readlinkSync,
	readSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	writeFile,
	writeFileSync,
	writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { Readable } from "node:stream";
import {
	type CliSubprocessLaunchSpec,
	createCliSubprocessEnv,
	createCliSubprocessLaunchSpec,
} from "../../cli/subprocess-launch.js";
import { getAgentDir, getDaemonLogPath, VERSION } from "../../config.js";
import { getProcessStartId } from "../../core/session-lease.js";
import { acquireIncidentCasTransaction } from "./incident-recorder-cas-transaction.js";
import {
	IncidentRecorderCompactor,
	type StoppedTargetArtifactClosePublication,
} from "./incident-recorder-compactor.js";
import {
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
	INCIDENT_RECORDER_SOCKET_ENV,
} from "./incident-recorder-env.js";
import {
	baselineLinuxIncidentEvidence,
	hasPositiveLinuxCgroupOomKillDelta,
	type LinuxMemorySummary,
	type LinuxRawSourceOccurrence,
	readLinuxIncidentEvidenceCorrelation,
	sampleLinuxIncidentEvidence,
} from "./incident-recorder-linux.js";
import {
	INCIDENT_RECORDER_RUN_ID_ENV,
	INCIDENT_RECORDER_RUN_TOKEN_ENV,
	newIncidentRecorderToken,
} from "./incident-recorder-protocol.js";
import {
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	INCIDENT_RETENTION_SERVICE_BUDGET,
	runIncidentRetentionPass,
} from "./incident-recorder-retention.js";
import {
	configureIncidentCaptureEmitter,
	emitIncidentBytes,
	emitIncidentDerived,
	INCIDENT_RECORDER_CAPTURE_FD,
	INCIDENT_RECORDER_CAPTURE_FD_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV,
	INCIDENT_RECORDER_ROOT_FD,
	INCIDENT_RECORDER_ROOT_FD_ENV,
	IncidentRecorderWriter,
	stopIncidentCaptureEmitter,
	stopIncidentCaptureEmitterOnExit,
} from "./incident-recorder-writer.js";

export {
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
	INCIDENT_RECORDER_SOCKET_ENV,
};

const EVENT_FILE_NAME = "timeline.jsonl";
const RAW_APPLICATION_DIR_NAME = "raw-application";
const ACTIVE_MARKER_FILE_NAME = ".recorder-active";
const FINALIZER_CLAIM_FILE_NAME = ".incident-finalizer-claim";
const HEARTBEAT_INTERVAL_MS = 1_000;
const STALL_THRESHOLD_MS = 10_000;
const EVENT_FLUSH_INTERVAL_MS = 50;
const RAW_MANIFEST_CHECKPOINT_MS = 5_000;
const RAW_SEGMENT_ROTATION_MS = 5 * 60 * 1_000;
const EVENT_BUFFER_BYTES = 64 * 1024;
const RAW_RECORD_SCHEMA_VERSION = 2;
const RAW_FRAME_PAYLOAD_BYTES = 32 * 1024;

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
	lastManifestCheckpointMs: number;
	manifestTimer?: ReturnType<typeof setTimeout>;
	manifestWriting: boolean;
	manifestDirty: boolean;
	manifestWaiters: Array<() => void>;
}

interface BufferedEventState {
	runDir: string;
	source: RawApplicationSource;
	pending: string[];
	pendingBytes: number;
	writing: boolean;
	inFlight?: string[];
	timer?: ReturnType<typeof setTimeout>;
	waiters: Array<() => void>;
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
const pendingRawBlobWrites = new Map<string, number>();
const rawBlobWaiters = new Map<string, Array<() => void>>();
interface RawBlobWriteTask {
	runDir: string;
	source: RawApplicationSource;
	bytes: Buffer;
	digest: string;
	path: string;
	collisionFallbackPath: string;
	temporary: string;
}
const rawBlobWriteQueues = new Map<string, RawBlobWriteTask[]>();
const activeRawBlobWriteQueues = new Set<string>();
const bufferedApplicationStreams = new Map<string, BufferedEventState>();
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

const serviceRunIdentityCache = new Map<
	string,
	{ runId: string; runToken: string; targetPid?: number; targetProcessStartId?: string }
>();

function serviceRunIdentity(
	runDir: string,
): { runId: string; runToken: string; targetPid?: number; targetProcessStartId?: string } | undefined {
	const cached = serviceRunIdentityCache.get(runDir);
	if (cached) return cached;
	const processIdentity = readSmallJson<{ runToken?: unknown; pid?: unknown; processStartId?: unknown }>(
		join(runDir, "process.json"),
	);
	const expectation = readSmallJson<{ runToken?: unknown }>(join(runDir, "finalization-barrier-expectation.json"));
	const runId = basename(runDir).slice(-36);
	const runToken = typeof processIdentity?.runToken === "string" ? processIdentity.runToken : expectation?.runToken;
	if (!/^[0-9a-f-]{36}$/i.test(runId) || typeof runToken !== "string" || !/^[0-9a-f-]{36}$/i.test(runToken))
		return undefined;
	const identity = {
		runId,
		runToken,
		targetPid: typeof processIdentity?.pid === "number" ? processIdentity.pid : undefined,
		targetProcessStartId:
			typeof processIdentity?.processStartId === "string" ? processIdentity.processStartId : undefined,
	};
	serviceRunIdentityCache.set(runDir, identity);
	while (serviceRunIdentityCache.size > 4096)
		serviceRunIdentityCache.delete(serviceRunIdentityCache.keys().next().value as string);
	return identity;
}

function serviceRecordDerived(
	runDir: string,
	source: RawApplicationSource,
	type: string,
	fields: Record<string, unknown>,
): boolean {
	const runtime = activeServiceRecorder;
	const identity = serviceRunIdentity(runDir);
	if (!runtime || !identity || !runtime.compactor.admitObservation(24 * 1024)) return false;
	return runtime.writer.recordDerivedForRun(identity, source, type, {
		...fields,
		targetPid: identity.targetPid,
		targetProcessStartId: identity.targetProcessStartId,
	}).accepted;
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

function readSmallJson<T>(path: string, _limit = INCIDENT_RECORDER_LIMITS.evidenceFileBytes): T | undefined {
	try {
		return JSON.parse(readFileSync(path, "utf8")) as T;
	} catch {
		return undefined;
	}
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
		lastManifestCheckpointMs: 0,
		manifestWriting: false,
		manifestDirty: false,
		manifestWaiters: [],
	};
	rawSegmentStates.set(key, state);
	return state;
}

function finishRawSegmentManifestWrite(state: RawSegmentState): void {
	state.manifestWriting = false;
	if (state.manifestDirty) {
		writeRawSegmentManifest(state, true);
		return;
	}
	for (const resolveWaiter of state.manifestWaiters.splice(0)) resolveWaiter();
}

function writeRawSegmentManifest(state: RawSegmentState, force = false): void {
	const elapsed = Date.now() - state.lastManifestCheckpointMs;
	if (!force && elapsed < RAW_MANIFEST_CHECKPOINT_MS) {
		if (!state.manifestTimer) {
			state.manifestTimer = setTimeout(() => {
				state.manifestTimer = undefined;
				writeRawSegmentManifest(state, true);
			}, RAW_MANIFEST_CHECKPOINT_MS - elapsed);
			state.manifestTimer.unref();
		}
		return;
	}
	if (state.manifestWriting) {
		state.manifestDirty = true;
		return;
	}
	try {
		const segments = readdirSync(state.directory, { withFileTypes: true })
			.filter((entry) => entry.isFile() && /^segment-\d{8}\.jsonl$/.test(entry.name))
			.map((entry) => {
				const stat = statSync(join(state.directory, entry.name));
				return { file: entry.name, bytes: stat.size, mode: stat.mode & 0o777, mtimeMs: stat.mtimeMs };
			});
		const manifestPath = join(state.directory, "manifest.json");
		const temporary = `${manifestPath}.tmp-${process.pid}-${randomUUID()}`;
		const serialized = `${JSON.stringify(
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
			null,
			2,
		)}\n`;
		state.lastManifestCheckpointMs = Date.now();
		state.manifestDirty = false;
		state.manifestWriting = true;
		writeFile(temporary, serialized, { mode: 0o600 }, (error) => {
			if (error) {
				recordRawLoss(state.runDir, state.source, error, Buffer.byteLength(serialized));
				finishRawSegmentManifestWrite(state);
				return;
			}
			try {
				const descriptor = openSync(temporary, "r");
				try {
					fsyncSync(descriptor);
				} finally {
					closeSync(descriptor);
				}
				renameSync(temporary, manifestPath);
				chmodSync(manifestPath, 0o600);
			} catch (renameError) {
				recordRawLoss(state.runDir, state.source, renameError, Buffer.byteLength(serialized));
				try {
					rmSync(temporary, { force: true });
				} catch {}
			}
			finishRawSegmentManifestWrite(state);
		});
	} catch (error) {
		recordRawLoss(state.runDir, state.source, error, 0);
		state.manifestDirty = false;
		finishRawSegmentManifestWrite(state);
	}
}

function rotateRawSegmentIfNeeded(state: RawSegmentState, bytes: number): string {
	if (
		state.segmentBytes > 0 &&
		(state.segmentBytes + bytes > INCIDENT_RECORDER_LIMITS.rawSegmentBytes ||
			Date.now() - state.segmentOpenedMs >= RAW_SEGMENT_ROTATION_MS)
	) {
		state.segmentIndex += 1;
		state.segmentBytes = 0;
		state.segmentOpenedMs = Date.now();
		writeRawSegmentManifest(state, true);
	}
	const path = rawSegmentPath(state);
	state.segmentBytes += bytes;
	return path;
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

function finishRawBlobWrite(runDir: string): void {
	const remaining = Math.max(0, (pendingRawBlobWrites.get(runDir) ?? 1) - 1);
	if (remaining > 0) {
		pendingRawBlobWrites.set(runDir, remaining);
		return;
	}
	pendingRawBlobWrites.delete(runDir);
	for (const resolveWaiter of rawBlobWaiters.get(runDir)?.splice(0) ?? []) resolveWaiter();
	rawBlobWaiters.delete(runDir);
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

function completeRawBlobWrite(task: RawBlobWriteTask): void {
	finishRawBlobWrite(task.runDir);
	const queue = rawBlobWriteQueues.get(task.runDir);
	queue?.shift();
	if (!queue || queue.length === 0) {
		rawBlobWriteQueues.delete(task.runDir);
		activeRawBlobWriteQueues.delete(task.runDir);
		return;
	}
	runNextRawBlobWrite(task.runDir);
}

function runNextRawBlobWrite(runDir: string): void {
	const task = rawBlobWriteQueues.get(runDir)?.[0];
	if (!task) {
		activeRawBlobWriteQueues.delete(runDir);
		return;
	}
	activeRawBlobWriteQueues.add(runDir);
	writeFile(task.temporary, task.bytes, { mode: 0o600, flag: "wx" }, (error) => {
		if (error) {
			recordRawLoss(task.runDir, task.source, error, task.bytes.length);
			completeRawBlobWrite(task);
			return;
		}
		try {
			linkSync(task.temporary, task.path);
			chmodSync(task.path, 0o600);
			leaseRunRawBlob(task.runDir, task.path);
			rmSync(task.temporary, { force: true });
			completeRawBlobWrite(task);
			return;
		} catch (linkError) {
			if ((linkError as NodeJS.ErrnoException).code !== "EEXIST") {
				try {
					rmSync(task.temporary, { force: true });
				} catch {}
				recordRawLoss(task.runDir, task.source, linkError, task.bytes.length);
				completeRawBlobWrite(task);
				return;
			}
		}
		readFile(task.path, (readError, existing) => {
			if (!readError && existing.length === task.bytes.length && existing.equals(task.bytes)) {
				try {
					leaseRunRawBlob(task.runDir, task.path);
					rmSync(task.temporary, { force: true });
				} catch {}
				completeRawBlobWrite(task);
				return;
			}
			try {
				renameSync(task.temporary, task.collisionFallbackPath);
				chmodSync(task.collisionFallbackPath, 0o600);
				leaseRunRawBlob(task.runDir, task.collisionFallbackPath);
				recordRawLoss(
					task.runDir,
					task.source,
					{
						name: "RawContentAddressCollisionError",
						message: "Existing SHA-256 blob did not match the captured bytes",
						digest: task.digest,
						path: task.path,
						collisionFallbackPath: task.collisionFallbackPath,
						readError,
					},
					task.bytes.length,
				);
				completeRawBlobWrite(task);
			} catch (collisionError) {
				recordRawLoss(task.runDir, task.source, collisionError, task.bytes.length);
				completeRawBlobWrite(task);
			}
		});
	});
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
	return contentAddressRawBytesSync(runDir, source, value, encoding);
}

function contentAddressRawBytesSync(
	runDir: string,
	source: RawApplicationSource,
	value: Uint8Array,
	encoding: string,
): RawBlobReference {
	const transaction = acquireIncidentCasTransaction(dirname(dirname(runDir)));
	if (!transaction) throw new Error("Incident CAS transaction unavailable");
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
	const orderedWriter = orderedWriterForRun(runDir);
	if (orderedWriter) {
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
		const admission =
			serviceIdentity && service.compactor.admitObservation(occurrence.bytes.byteLength + 24 * 1024)
				? service.writer.recordExactBytesForRun(
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
							targetPid: serviceIdentity.targetPid,
							targetProcessStartId: serviceIdentity.targetProcessStartId,
						},
					)
				: undefined;
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
	const payloadBlob = durable
		? contentAddressRawBytesSync(runDir, rawSource, occurrence.bytes, occurrence.encoding)
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
	if (durable) {
		writeRawLinesSync(
			loadRawSegmentState(runDir, rawSource),
			serializeRawRecord(runDir, rawSource, "linux_raw_source_occurrence", fields, true),
		);
	} else {
		const key = `${runDir}\0${rawSource}`;
		let state = bufferedApplicationStreams.get(key);
		if (!state) {
			state = { runDir, source: rawSource, pending: [], pendingBytes: 0, writing: false, waiters: [] };
			bufferedApplicationStreams.set(key, state);
		}
		for (const line of serializeRawRecord(runDir, rawSource, "linux_raw_source_occurrence", fields)) {
			state.pending.push(line);
			state.pendingBytes += Buffer.byteLength(line);
		}
		if (state.pendingBytes >= EVENT_BUFFER_BYTES) flushSupervisorEvents(state);
		else scheduleSupervisorEventFlush(state);
	}
	return payloadBlob;
}

function waitForRawBlobWrites(runDir: string): Promise<void> {
	if ((pendingRawBlobWrites.get(runDir) ?? 0) === 0) return Promise.resolve();
	return new Promise((resolveWaiter) => {
		const waiters = rawBlobWaiters.get(runDir) ?? [];
		waiters.push(resolveWaiter);
		rawBlobWaiters.set(runDir, waiters);
	});
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
		? contentAddressRawBytesSync(runDir, source, payloadBytes, "utf8-json/derived-diagnostic-json-v1")
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
	const orderedWriter = orderedWriterForRun(runDir);
	if (orderedWriter) {
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
	if (runHasLiveWriter(runDir)) return;
	try {
		writeRawLinesSync(
			loadRawSegmentState(runDir, "loss-accounting"),
			serializeRawRecord(runDir, "loss-accounting", "raw_capture_loss", {
				source,
				attemptedBytes,
				error: serializeError(error),
			}),
		);
	} catch {
		// The loss counter itself is best effort when the storage path is unavailable.
	}
}

function writeRawLinesSync(state: RawSegmentState, lines: readonly string[]): void {
	for (const line of lines) {
		const bytes = Buffer.byteLength(line);
		try {
			const path = rotateRawSegmentIfNeeded(state, bytes);
			const descriptor = openSync(path, "a", 0o600);
			try {
				writeSync(descriptor, line);
				fsyncSync(descriptor);
			} finally {
				closeSync(descriptor);
			}
			chmodSync(path, 0o600);
		} catch (error) {
			recordRawLoss(state.runDir, state.source, error, bytes);
		}
	}
	writeRawSegmentManifest(state);
}

function planRawWrites(state: RawSegmentState, lines: readonly string[]): Array<{ path: string; payload: string }> {
	const writes: Array<{ path: string; payload: string }> = [];
	for (const line of lines) {
		const path = rotateRawSegmentIfNeeded(state, Buffer.byteLength(line));
		const previous = writes.at(-1);
		if (previous?.path === path) previous.payload += line;
		else writes.push({ path, payload: line });
	}
	return writes;
}

function writeRawLinesAsync(state: RawSegmentState, lines: readonly string[], complete: () => void): void {
	let writes: Array<{ path: string; payload: string }>;
	try {
		writes = planRawWrites(state, lines);
	} catch (error) {
		recordRawLoss(
			state.runDir,
			state.source,
			error,
			lines.reduce((total, line) => total + Buffer.byteLength(line), 0),
		);
		complete();
		return;
	}
	let index = 0;
	const next = () => {
		const write = writes[index++];
		if (!write) {
			writeRawSegmentManifest(state);
			complete();
			return;
		}
		appendFile(write.path, write.payload, { mode: 0o600 }, (error) => {
			if (error) recordRawLoss(state.runDir, state.source, error, Buffer.byteLength(write.payload));
			else {
				try {
					chmodSync(write.path, 0o600);
				} catch (chmodError) {
					recordRawLoss(state.runDir, state.source, chmodError, Buffer.byteLength(write.payload));
				}
			}
			next();
		});
	};
	next();
}

const IMMEDIATE_DURABLE_EVENT_TYPES = new Set([
	"recorder_spawn_error",
	"recorder_child_error",
	"supervisor_exit",
	"signal_received",
	"fatal_exception",
	"unhandled_rejection",
	"socket_lost",
	"supervisor_generation_changed",
	"supervisor_ready",
	"supervisor_relaunch",
	"node_report_captured",
]);

function appendRunEvent(runDir: string, event: { type: string; [key: string]: unknown }): void {
	const { type, ...fields } = event;
	const orderedWriter = orderedWriterForRun(runDir);
	if (orderedWriter) {
		orderedWriter.recordDerived("recorder-events", type, fields);
		return;
	}
	if (activeServiceRecorder) {
		serviceRecordDerived(runDir, "recorder-events", type, fields);
		return;
	}
	try {
		const key = `${runDir}\0recorder-events`;
		let state = bufferedApplicationStreams.get(key);
		if (!state) {
			state = {
				runDir,
				source: "recorder-events",
				pending: [],
				pendingBytes: 0,
				writing: false,
				waiters: [],
			};
			bufferedApplicationStreams.set(key, state);
		}
		if (IMMEDIATE_DURABLE_EVENT_TYPES.has(type)) {
			if (!state.writing && state.pending.length > 0) {
				const pending = state.pending;
				state.pending = [];
				state.pendingBytes = 0;
				writeRawLinesSync(loadRawSegmentState(runDir, state.source), pending);
			}
			writeRawLinesSync(
				loadRawSegmentState(runDir, "recorder-events"),
				serializeRawRecord(runDir, "recorder-events", type, fields, true),
			);
			return;
		}
		const lines = serializeRawRecord(runDir, "recorder-events", type, fields);
		for (const line of lines) {
			state.pending.push(line);
			state.pendingBytes += Buffer.byteLength(line);
		}
		if (state.pendingBytes >= EVENT_BUFFER_BYTES) flushSupervisorEvents(state);
		else scheduleSupervisorEventFlush(state);
	} catch (error) {
		recordRawLoss(runDir, "recorder-events", error, 0);
	}
}

function scheduleSupervisorEventFlush(state: BufferedEventState): void {
	if (state.timer || state.writing || state.pending.length === 0) return;
	state.timer = setTimeout(() => {
		state.timer = undefined;
		flushSupervisorEvents(state);
	}, EVENT_FLUSH_INTERVAL_MS);
	state.timer.unref();
}

function flushSupervisorEvents(state: BufferedEventState): void {
	if (state.writing || state.pending.length === 0) return;
	const lines = state.pending;
	state.pending = [];
	state.pendingBytes = 0;
	state.writing = true;
	state.inFlight = lines;
	writeRawLinesAsync(loadRawSegmentState(state.runDir, state.source), lines, () => {
		if (state.inFlight === lines) state.inFlight = undefined;
		state.writing = false;
		scheduleSupervisorEventFlush(state);
		if (state.pending.length === 0) {
			for (const resolveWaiter of state.waiters.splice(0)) resolveWaiter();
		}
	});
}

export function appendSupervisorDiagnosticEvent(type: string, fields: Record<string, unknown> = {}): void {
	emitIncidentDerived("supervisor-events", type, fields);
}

export function appendSupervisorDiagnosticBytes(
	type: string,
	value: Uint8Array,
	fields: Record<string, unknown> = {},
): void {
	const source: RawApplicationSource =
		type === "worker_stdout"
			? "worker-stdout"
			: type === "worker_stderr"
				? "worker-stderr"
				: type.startsWith("worker_transport_")
					? "worker-transport"
					: "supervisor-events";
	emitIncidentBytes(source, type, value, fields);
}

export async function flushSupervisorDiagnosticCapture(): Promise<void> {
	await stopIncidentCaptureEmitter();
}

async function flushRawSegmentManifests(runDir: string): Promise<void> {
	const states = [...rawSegmentStates.values()].filter((state) => state.runDir === runDir);
	await Promise.all(
		states.map(
			(state) =>
				new Promise<void>((resolveManifest) => {
					if (state.manifestTimer) {
						clearTimeout(state.manifestTimer);
						state.manifestTimer = undefined;
					}
					state.manifestWaiters.push(resolveManifest);
					writeRawSegmentManifest(state, true);
				}),
		),
	);
}

async function flushRecordedProcessBytes(runDir: string): Promise<void> {
	const states = [...bufferedApplicationStreams.values()].filter((state) => state.runDir === runDir);
	await Promise.all(
		states.map(
			(state) =>
				new Promise<void>((resolveFlush) => {
					if (state.timer) {
						clearTimeout(state.timer);
						state.timer = undefined;
					}
					if (!state.writing && state.pending.length === 0) {
						resolveFlush();
						return;
					}
					state.waiters.push(resolveFlush);
					flushSupervisorEvents(state);
				}),
		),
	);
	await waitForRawBlobWrites(runDir);
	await flushRawSegmentManifests(runDir);
}

export function installSupervisorDiagnosticHooks(socketPath: string): () => void {
	if (!process.env[INCIDENT_RECORDER_RUN_DIR_ENV] || !configureIncidentCaptureEmitter()) return () => {};
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
		const orderedWriter = orderedWriterForRun(runDir);
		if (orderedWriter && !recorder) {
			orderedWriter.recordExactBytes("linux-raw-source", "proc_source_snapshot", value, "exact-file-bytes", {
				sourcePath,
				pid,
				processStartId,
				sha256,
			});
		} else {
			appendRunEvent(runDir, {
				type: "proc_source_snapshot",
				sourcePath,
				pid,
				processStartId,
				sha256,
				payloadBlob: recorder
					? recorder(sourcePath, value)
					: contentAddressRawBytes(runDir, "recorder-events", value, "binary"),
			});
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
	if (process.platform !== "linux" || !hasMatchingProcessIdentity(pid, processStartId)) return;
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

function readRawEventSource(runDir: string, source: "recorder-events" | "supervisor-events"): IncidentRecorderEvent[] {
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
		cache = { seen: new Set(), events: new Map(), references: new Map() };
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
		try {
			cache.directory = opendirSync(runReferenceDirectory);
		} catch {
			return [...cache.events.values()];
		}
	}
	const deadline = Date.now() + 5;
	let files = 0;
	let bytes = 0;
	while (files < 8 && bytes < 128 * 1024 && Date.now() < deadline) {
		let entry: Dirent | null;
		try {
			entry = cache.directory.readSync();
		} catch {
			entry = null;
		}
		if (!entry) {
			try {
				cache.directory.closeSync();
			} catch {}
			cache.directory = undefined;
			break;
		}
		if (!entry.isFile() || !/^seq-[A-Za-z0-9-]{1,180}\.json$/.test(entry.name) || cache.seen.has(entry.name))
			continue;
		files += 1;
		try {
			const path = join(runReferenceDirectory, entry.name);
			const stat = statSync(path);
			if (stat.size > 64 * 1024 || bytes + stat.size > 128 * 1024) continue;
			cache.seen.add(entry.name);
			while (cache.seen.size > 4096) cache.seen.delete(cache.seen.values().next().value as string);
			bytes += stat.size;
			const reference = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
			cache.references.set(entry.name, reference);
			while (cache.references.size > 4096) cache.references.delete(cache.references.keys().next().value as string);
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
		} catch {}
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
function hasCompactedFinalizationBarrier(runDir: string): boolean {
	const expectationPath = join(runDir, "finalization-barrier-expectation.json");
	let expectation: {
		version?: number;
		runId?: string;
		runToken?: string;
		wrapperPid?: number;
		wrapperStartId?: string | null;
		exitCode?: number | "unavailable";
		exitSignal?: string | "unavailable";
		supervisorExit?: {
			occurrenceId: string;
			producerId: string;
			firstProducerSequence: string;
			lastProducerSequence: string;
			firstWrapperSequence: string;
			lastWrapperSequence: string;
		};
		wrapperTerminal?: {
			occurrenceId: string;
			producerId: string;
			firstProducerSequence: string;
			lastProducerSequence: string;
			firstWrapperSequence: string;
			lastWrapperSequence: string;
		};
	};
	try {
		expectation = JSON.parse(readFileSync(expectationPath, "utf8")) as typeof expectation;
	} catch {
		return false;
	}
	const canonicalUuid = (value: unknown): value is string =>
		typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
	const unsignedSequence = (value: unknown): value is string =>
		typeof value === "string" && /^(?:0|[1-9]\d{0,19})$/.test(value);
	const validFrontier = (
		value: typeof expectation.supervisorExit,
	): value is NonNullable<typeof expectation.supervisorExit> =>
		!!value &&
		canonicalUuid(value.occurrenceId) &&
		canonicalUuid(value.producerId) &&
		unsignedSequence(value.firstProducerSequence) &&
		unsignedSequence(value.lastProducerSequence) &&
		unsignedSequence(value.firstWrapperSequence) &&
		unsignedSequence(value.lastWrapperSequence) &&
		BigInt(value.firstProducerSequence) <= BigInt(value.lastProducerSequence) &&
		BigInt(value.firstWrapperSequence) <= BigInt(value.lastWrapperSequence);
	if (
		expectation.version !== 1 ||
		!canonicalUuid(expectation.runId) ||
		!canonicalUuid(expectation.runToken) ||
		!Number.isSafeInteger(expectation.wrapperPid) ||
		(expectation.wrapperPid ?? 0) <= 0 ||
		!(expectation.wrapperStartId === null || typeof expectation.wrapperStartId === "string") ||
		!(Number.isSafeInteger(expectation.exitCode) || expectation.exitCode === "unavailable") ||
		!(typeof expectation.exitSignal === "string" && expectation.exitSignal.length > 0) ||
		!validFrontier(expectation.supervisorExit) ||
		!validFrontier(expectation.wrapperTerminal) ||
		expectation.supervisorExit.producerId !== expectation.wrapperTerminal.producerId
	)
		return false;
	const runId = basename(runDir).slice(-36);
	if (expectation.runId !== runId) return false;
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
	return (
		(completeMatches(expectation.supervisorExit, "exit") || gapCovers(expectation.supervisorExit)) &&
		(completeMatches(expectation.wrapperTerminal, "terminal") || gapCovers(expectation.wrapperTerminal))
	);
}

function readExpectedExitDisposition(runDir: string): { code: number | null; signal: NodeJS.Signals | null } {
	try {
		const value = JSON.parse(readFileSync(join(runDir, "finalization-barrier-expectation.json"), "utf8")) as {
			exitCode?: unknown;
			exitSignal?: unknown;
		};
		return {
			code: typeof value.exitCode === "number" ? value.exitCode : null,
			signal:
				typeof value.exitSignal === "string" && value.exitSignal !== "unavailable"
					? (value.exitSignal as NodeJS.Signals)
					: null,
		};
	} catch {
		return { code: null, signal: null };
	}
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
}
const nodeReportCaptureStates = new Map<string, NodeReportCaptureState>();

function writeImmutableJsonOnce(path: string, value: unknown): void {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "wx", 0o600);
		const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
		let offset = 0;
		while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset, bytes.length - offset);
		fsyncSync(descriptor);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
	const directory = openSync(dirname(path), fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
	try {
		fsyncSync(directory);
	} finally {
		closeSync(directory);
	}
}

async function sanitizeNodeReports(runDir: string, _removeRawDirectory = false): Promise<"pending" | "complete"> {
	const rawReportsDir = join(runDir, "raw-reports");
	const reportsDir = join(runDir, "reports");
	mkdirSync(reportsDir, { recursive: true, mode: 0o700 });
	let state = nodeReportCaptureStates.get(runDir);
	if (!state) {
		state = { pending: [], discoveryComplete: false };
		nodeReportCaptureStates.set(runDir, state);
		while (nodeReportCaptureStates.size > 4096)
			nodeReportCaptureStates.delete(nodeReportCaptureStates.keys().next().value as string);
	}
	if (!state.directory && !state.discoveryComplete) {
		try {
			state.directory = opendirSync(rawReportsDir);
		} catch {
			state.discoveryComplete = true;
		}
	}
	for (let scanned = 0; state.directory && scanned < 8; scanned += 1) {
		let entry: Dirent | null;
		try {
			entry = state.directory.readSync();
		} catch {
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
			entry.name.endsWith(".closed.json") ||
			entry.name.endsWith(".error.json")
		)
			continue;
		if (
			existsSync(join(rawReportsDir, `${entry.name}.reference.json`)) ||
			existsSync(join(rawReportsDir, `${entry.name}.error.json`))
		)
			continue;
		state.pending.push(entry.name);
		if (state.pending.length >= 32) break;
	}
	const entryName = state.pending[0];
	if (!entryName) return state.discoveryComplete ? "complete" : "pending";
	const sourcePath = join(rawReportsDir, entryName);
	let sourceMetadata: Record<string, unknown>;
	const closePublicationPath = join(rawReportsDir, `${entryName}.closed.json`);
	try {
		const stat = lstatSync(sourcePath, { bigint: true });
		if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("node_report_source_not_regular_file");
		sourceMetadata = {
			path: sourcePath,
			dev: stat.dev.toString(),
			ino: stat.ino.toString(),
			bytes: Number(stat.size),
			mtimeMs: Number(stat.mtimeMs),
			ctimeMs: Number(stat.ctimeMs),
		};
		writeImmutableJsonOnce(closePublicationPath, {
			schemaVersion: 1,
			state: "closed",
			proof: "target_process_stopped",
			source: sourceMetadata,
		});
	} catch (error) {
		writeImmutableJsonOnce(join(rawReportsDir, `${entryName}.error.json`), {
			schemaVersion: 1,
			state: "error",
			reason: serializeError(error),
		});
		state.pending.shift();
		return "pending";
	}
	const admission = activeIncidentCompactor?.streamStoppedTargetArtifact(
		basename(runDir).slice(-36),
		sourcePath,
		"node-report-json-bytes",
		closePublicationPath,
		{ deadlineMs: Date.now() + 40, byteBudget: 4 * 1024 * 1024 },
	);
	if (!admission || admission.state === "pending") return "pending";
	if (admission.state === "error") {
		writeImmutableJsonOnce(join(rawReportsDir, `${entryName}.error.json`), {
			schemaVersion: 1,
			state: "error",
			source: sourceMetadata,
			reason: admission.reason,
		});
		appendRunEvent(runDir, { type: "node_report_capture_error", originalPath: sourcePath, reason: admission.reason });
		state.pending.shift();
		return "pending";
	}
	writeImmutableJsonOnce(join(rawReportsDir, `${entryName}.reference.json`), {
		schemaVersion: 1,
		state: "complete",
		occurrence: { originalPath: sourcePath, sourceMetadata },
		artifact: admission.artifact,
	});
	appendRunEvent(runDir, { type: "node_report_captured", originalPath: sourcePath, bytes: admission.artifact.bytes });
	const summaryPrefix = readBoundedPrefix(sourcePath, 64 * 1024)?.value;
	const summary = minimizeNodeReport(summaryPrefix ? readJsonValue(summaryPrefix) : undefined);
	writePrivateJson(join(reportsDir, `report-${admission.artifact.digest.slice(0, 16)}.json`), {
		...summary,
		canonical: false,
		source: admission.artifact,
	});
	state.pending.shift();
	return state.discoveryComplete && state.pending.length === 0 ? "complete" : "pending";
}

interface ProviderArtifactCaptureState {
	seenReferences: Set<string>;
	pending: Array<{
		provider: string;
		path: string;
		format: string;
		closePublication?: StoppedTargetArtifactClosePublication;
	}>;
}
const providerArtifactCaptureStates = new Map<string, ProviderArtifactCaptureState>();

function captureStoppedProviderArtifacts(runDir: string): "pending" | "complete" {
	let state = providerArtifactCaptureStates.get(runDir);
	if (!state) {
		state = { seenReferences: new Set(), pending: [] };
		providerArtifactCaptureStates.set(runDir, state);
		while (providerArtifactCaptureStates.size > 4096)
			providerArtifactCaptureStates.delete(providerArtifactCaptureStates.keys().next().value as string);
	}
	const cache = orderedEventCaches.get(runDir);
	for (const [name, reference] of cache?.references ?? []) {
		if (state.seenReferences.has(name) || reference.type !== "provider_source_manifest_registered") continue;
		state.seenReferences.add(name);
		const cas = reference.cas;
		if (!cas || typeof cas !== "object" || Array.isArray(cas)) continue;
		const path = (cas as Record<string, unknown>).path;
		const bytes = (cas as Record<string, unknown>).bytes;
		if (typeof path !== "string" || typeof bytes !== "number" || bytes > 256 * 1024) continue;
		const encoded = readBoundedPrefix(path, 256 * 1024);
		if (!encoded || encoded.truncated) continue;
		const decoded = decodeDiagnosticValue(readJsonValue(encoded.value));
		if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) continue;
		const manifest = decoded as Record<string, unknown>;
		const provider = typeof manifest.provider === "string" ? manifest.provider : "unknown";
		if (!Array.isArray(manifest.artifacts)) continue;
		for (const artifact of manifest.artifacts.slice(0, 64 - state.pending.length)) {
			if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)) continue;
			const fields = artifact as Record<string, unknown>;
			if (typeof fields.path !== "string" || !isAbsolute(fields.path)) continue;
			state.pending.push({
				provider,
				path: fields.path,
				format: typeof fields.format === "string" ? fields.format : "exact-provider-bytes",
				closePublication:
					fields.closePublication && typeof fields.closePublication === "object"
						? (fields.closePublication as StoppedTargetArtifactClosePublication)
						: undefined,
			});
		}
	}
	const artifact = state.pending[0];
	if (!artifact) return "complete";
	const evidenceDirectory = join(runDir, "evidence", "provider-artifacts");
	mkdirSync(evidenceDirectory, { recursive: true, mode: 0o700 });
	const id = createHash("sha256").update(`${artifact.provider}\0${artifact.path}`).digest("hex");
	const completePath = join(evidenceDirectory, `${id}.reference.json`);
	const errorPath = join(evidenceDirectory, `${id}.error.json`);
	if (existsSync(completePath) || existsSync(errorPath)) {
		state.pending.shift();
		return "pending";
	}
	let metadata: Record<string, unknown>;
	const closePublicationPath = join(evidenceDirectory, `${id}.closed.json`);
	try {
		const source = lstatSync(artifact.path, { bigint: true });
		const publication = artifact.closePublication;
		if (
			!source.isFile() ||
			source.isSymbolicLink() ||
			!publication ||
			publication.schemaVersion !== 1 ||
			publication.state !== "closed" ||
			publication.proof !== "provider_published_closed" ||
			publication.source?.path !== artifact.path ||
			publication.source.dev !== source.dev.toString() ||
			publication.source.ino !== source.ino.toString() ||
			publication.source.bytes !== Number(source.size) ||
			publication.source.mtimeMs !== Number(source.mtimeMs) ||
			publication.source.ctimeMs !== Number(source.ctimeMs)
		)
			throw new Error("artifact_close_publication_required_or_stale");
		metadata = {
			provider: artifact.provider,
			sourcePath: artifact.path,
			dev: source.dev.toString(),
			ino: source.ino.toString(),
			bytes: Number(source.size),
			mtimeMs: Number(source.mtimeMs),
			ctimeMs: Number(source.ctimeMs),
		};
		writeImmutableJsonOnce(closePublicationPath, publication);
	} catch (error) {
		writeImmutableJsonOnce(errorPath, {
			schemaVersion: 1,
			state: "gap_or_uncertainty",
			sourcePath: artifact.path,
			reason: serializeError(error),
		});
		appendRunEvent(runDir, {
			type: "provider_artifact_capture_gap",
			provider: artifact.provider,
			sourcePath: artifact.path,
			reason: serializeError(error),
		});
		state.pending.shift();
		return "pending";
	}
	const admission = activeIncidentCompactor?.streamStoppedTargetArtifact(
		basename(runDir).slice(-36),
		artifact.path,
		artifact.format,
		closePublicationPath,
		{ deadlineMs: Date.now() + 40, byteBudget: 4 * 1024 * 1024 },
	);
	if (!admission || admission.state === "pending") return "pending";
	if (admission.state === "error")
		writeImmutableJsonOnce(errorPath, {
			schemaVersion: 1,
			state: "error",
			source: metadata,
			reason: admission.reason,
		});
	else
		writeImmutableJsonOnce(completePath, {
			schemaVersion: 1,
			state: "complete",
			source: metadata,
			artifact: admission.artifact,
		});
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
		if (event.type === "application_source_reference" && typeof event.path === "string") {
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
		const bounds = sourceBounds[source] ?? {};
		sourceBounds[source] = bounds;
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

function finalizeIncident(
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
	const launchAdmission = orderedWriter.recordExactBytes(
		"recorder-events",
		"recorder_launch_raw_bytes",
		launchBytes,
		"derived-diagnostic-json-v1",
		{ source: "wrapper-launch-observation" },
	);
	const launchOccurrenceId = launchAdmission.accepted ? launchAdmission.occurrenceId : undefined;
	const launchArtifact = {
		canonical: false,
		encoding: "derived-diagnostic-json-v1",
		producerOccurrenceId: launchOccurrenceId,
		state: launchAdmission.accepted ? "locally-admitted-pending-compactor" : "relay-rejected",
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
	orderedWriter.recordDerived("recorder-events", "recorder_launch", {
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
	orderedWriter.recordDerived("recorder-events", "supervisor_stdio_source_unavailable", {
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
	const exitAdmission = orderedWriter.recordDerived("recorder-events", "supervisor_exit", {
		childPid: pid,
		code: exit.code,
		signal: exit.signal,
	});
	await orderedWriter.stop().catch(() => undefined);
	if (exitAdmission.accepted) {
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
		closePublication?: StoppedTargetArtifactClosePublication;
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

function appendProviderReferenceEnvelope(
	runDir: string,
	fileName: string,
	envelope: Record<string, unknown>,
	source: "provider-evidence" | "provider-manifest",
): void {
	const evidenceDirectory = join(runDir, "evidence");
	mkdirSync(evidenceDirectory, { recursive: true, mode: 0o700 });
	const path = join(evidenceDirectory, fileName);
	const serialized = `${JSON.stringify(envelope)}\n`;
	appendFile(path, serialized, { mode: 0o600 }, (error) => {
		if (error) recordRawLoss(runDir, source, error, Buffer.byteLength(serialized));
		else {
			try {
				chmodSync(path, 0o600);
			} catch (chmodError) {
				recordRawLoss(runDir, source, chmodError, Buffer.byteLength(serialized));
			}
		}
	});
}

export function ingestIncidentRecorderEvidence<P extends IncidentEvidenceProvider>(
	runDir: string,
	provider: P,
	evidence: IncidentProviderEvidenceMap[P] | Uint8Array,
): void {
	try {
		const payload = rawProviderPayload(evidence);
		const orderedWriter = orderedWriterForRun(runDir);
		if (orderedWriter) {
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
			if (serviceIdentity && activeServiceRecorder.compactor.admitObservation(payload.bytes.length + 24 * 1024)) {
				activeServiceRecorder.writer.recordExactBytesForRun(
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
		if (runHasLiveWriter(runDir)) return;
		const timestamp = nowFields();
		const payloadReference = contentAddressRawBytes(runDir, "provider-evidence", payload.bytes, payload.encoding);
		const envelope = {
			schemaVersion: 2,
			canonical: false,
			canonicalPayloadReference: true,
			sequence: ++providerOccurrenceSequence,
			...timestamp,
			provider,
			target: evidenceTarget(runDir),
			payloadReference,
			payloadEncoding: payload.encoding,
			unknownFieldsPreserved: true,
			diagnosticOnly: true,
		};
		appendProviderReferenceEnvelope(runDir, `${safeToken(provider)}.jsonl`, envelope, "provider-evidence");
		appendRunEvent(runDir, {
			type: "external_raw_evidence_ingested",
			provider,
			payloadReference,
			occurrence: envelope,
		});
	} catch (error) {
		recordRawLoss(runDir, "provider-evidence", error, 0);
	}
}

export function registerIncidentProviderSourceManifest(runDir: string, manifest: IncidentProviderSourceManifest): void {
	try {
		const payload = rawProviderPayload(manifest);
		const orderedWriter = orderedWriterForRun(runDir);
		if (orderedWriter) {
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
			if (serviceIdentity && activeServiceRecorder.compactor.admitObservation(payload.bytes.length + 24 * 1024)) {
				activeServiceRecorder.writer.recordExactBytesForRun(
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
		if (runHasLiveWriter(runDir)) return;
		const timestamp = nowFields();
		const payloadReference = contentAddressRawBytes(runDir, "provider-manifest", payload.bytes, payload.encoding);
		const envelope = {
			schemaVersion: 1,
			canonical: false,
			canonicalPayloadReference: true,
			sequence: ++providerOccurrenceSequence,
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
		appendProviderReferenceEnvelope(runDir, "provider-source-manifests.jsonl", envelope, "provider-manifest");
		appendRunEvent(runDir, {
			type: "provider_source_manifest_registered",
			provider: manifest.provider,
			payloadReference,
			occurrence: envelope,
		});
	} catch (error) {
		recordRawLoss(runDir, "provider-manifest", error, 0);
	}
}

interface ActiveRun {
	runDir: string;
	machineId: string;
	bootId: string;
	pid: number;
	processStartId?: string;
	socketPath: string;
}

function isMatchingLiveProcess(run: ActiveRun): boolean {
	return (
		run.machineId === linuxMachineId() &&
		run.bootId === linuxBootId() &&
		hasMatchingProcessIdentity(run.pid, run.processStartId)
	);
}

function loadActiveRun(runDir: string): ActiveRun | undefined {
	const launch = readSmallJson<{ socketPath?: unknown }>(join(runDir, "launch.json"));
	const identity = readSmallJson<{ machineId?: unknown; bootId?: unknown; pid?: unknown; processStartId?: unknown }>(
		join(runDir, "process.json"),
	);
	if (
		!launch ||
		!identity ||
		typeof launch.socketPath !== "string" ||
		typeof identity.machineId !== "string" ||
		typeof identity.bootId !== "string" ||
		typeof identity.pid !== "number"
	)
		return undefined;
	return {
		runDir,
		machineId: identity.machineId,
		bootId: identity.bootId,
		socketPath: launch.socketPath,
		pid: identity.pid,
		processStartId: typeof identity.processStartId === "string" ? identity.processStartId : undefined,
	};
}

function runHasLiveWriter(runDir: string): boolean {
	const run = loadActiveRun(runDir);
	return run !== undefined && (runHasLiveProxy(runDir) || isMatchingLiveProcess(run));
}

function runHasLiveProxy(runDir: string): boolean {
	const marker = readSmallJson<{
		role?: unknown;
		machineId?: unknown;
		bootId?: unknown;
		pid?: unknown;
		processStartId?: unknown;
	}>(join(runDir, ACTIVE_MARKER_FILE_NAME));
	const live =
		marker?.role === "wrapper-proxy" &&
		marker.machineId === linuxMachineId() &&
		marker.bootId === linuxBootId() &&
		typeof marker.pid === "number" &&
		typeof marker.processStartId === "string" &&
		getProcessStartId(marker.pid) === marker.processStartId;
	if (marker?.role === "wrapper-proxy" && !live) {
		const uncertaintyPath = join(runDir, ".stale-wrapper-marker-uncertainty.json");
		if (!existsSync(uncertaintyPath))
			writePrivateJson(uncertaintyPath, {
				state: "uncertain",
				reason: "wrapper_marker_owner_identity_not_live",
				orphanPolicy: "fail-open",
				wrapperDeathSignalsSupervisor: false,
				observed: nowFields(),
			});
	}
	return live;
}

interface ServiceSamplingState {
	previous?: LinuxMemorySummary;
	anomalyBurstUntilMs: number;
	latencyBurstUntilMs: number;
	nextSampleMs: number;
	lastLatencyTriggerOccurrence?: string;
	diskPauseMarked: boolean;
	liveHangClassification?: string;
	stoppedBroadCaptured?: boolean;
	nodeReportPendingMarked?: boolean;
}
const serviceSamplingRuns = new Map<string, ServiceSamplingState>();
let activeIncidentCompactor: IncidentRecorderCompactor | undefined;
let serviceRunsDirectory: Dir | undefined;
let serviceRunsDirectoryPath: string | undefined;
const serviceRunPaths = new Map<string, string>();
let serviceRunCursor = 0;

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

function closeServiceRunsDirectory(): void {
	const directory = serviceRunsDirectory;
	serviceRunsDirectory = undefined;
	serviceRunsDirectoryPath = undefined;
	if (!directory) return;
	try {
		directory.closeSync();
	} catch {}
}

/** @internal Replaces or releases the service-owned compactor and retained run scan. */
export function replaceIncidentRecorderServiceCompactor(replacement: IncidentRecorderCompactor | undefined): void {
	const previous = activeIncidentCompactor;
	if (previous === replacement) {
		if (!replacement) closeServiceRunsDirectory();
		return;
	}
	activeIncidentCompactor = replacement;
	if (activeServiceRecorder?.compactor === previous) activeServiceRecorder = undefined;
	closeServiceRunsDirectory();
	previous?.dispose();
}

export async function inspectIncidentRecorderRuns(agentDir: string, nowMs = Date.now()): Promise<string[]> {
	const runsRoot = join(agentDir, "incident-recorder", "runs");
	if (serviceRunsDirectoryPath !== undefined && serviceRunsDirectoryPath !== runsRoot) closeServiceRunsDirectory();
	if (!existsSync(runsRoot)) {
		closeServiceRunsDirectory();
		return [];
	}
	const finalized: string[] = [];
	if (!serviceRunsDirectory) {
		try {
			serviceRunsDirectory = opendirSync(runsRoot);
			serviceRunsDirectoryPath = runsRoot;
		} catch {
			closeServiceRunsDirectory();
			return [];
		}
	}
	for (let discovered = 0; discovered < 16; discovered += 1) {
		let entry: Dirent | null;
		try {
			entry = serviceRunsDirectory.readSync();
		} catch {
			closeServiceRunsDirectory();
			break;
		}
		if (!entry) {
			closeServiceRunsDirectory();
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
		const run = loadActiveRun(serviceRunPaths.get(name) ?? join(runsRoot, name));
		if (!run) continue;
		const live = isMatchingLiveProcess(run);
		const events = readEvents(run.runDir);
		if (live) {
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
						const identity = serviceRunIdentity(run.runDir);
						if (identity)
							activeServiceRecorder?.writer.recordDerivedForRun(
								identity,
								"recorder-control",
								"service_sampling_storage_paused",
								{
									state: "paused",
									targetPid: run.pid,
									targetProcessStartId: run.processStartId ?? "",
								},
							);
						sampling.diskPauseMarked = true;
						continue;
					}
					sampling.previous = baselineLinuxIncidentEvidence({
						runDir: run.runDir,
						pid: run.pid,
						processStartId: run.processStartId,
						dependencies: { recordRawSource: (occurrence) => recordLinuxRawSource(run.runDir, occurrence) },
					});
				}
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
							const identity = serviceRunIdentity(run.runDir);
							if (identity)
								activeServiceRecorder?.writer.recordDerivedForRun(
									identity,
									"recorder-control",
									"service_sampling_storage_paused",
									{
										state: "paused",
										targetPid: run.pid,
										targetProcessStartId: run.processStartId ?? "",
									},
								);
							sampling.diskPauseMarked = true;
						}
						sampling.nextSampleMs = nowMs + 1_000;
						continue;
					}
					sampling.diskPauseMarked = false;
					const inAnomalyBurst = nowMs < sampling.anomalyBurstUntilMs;
					const inLatencyBurst = nowMs < sampling.latencyBurstUntilMs;
					const current = sampleLinuxIncidentEvidence({
						runDir: run.runDir,
						phase: inAnomalyBurst ? "anomaly" : "periodic",
						dependencies: { recordRawSource: (occurrence) => recordLinuxRawSource(run.runDir, occurrence) },
					});
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
		if (existsSync(join(run.runDir, ".service-finalization-complete"))) continue;
		const exitEvent = [...events].reverse().find((event) => event.type === "supervisor_exit");
		const exited = exitEvent !== undefined;
		if (!live) {
			if (runHasLiveProxy(run.runDir)) continue;
			if (!hasCompactedFinalizationBarrier(run.runDir)) {
				const pendingPath = join(run.runDir, ".service-finalization-pending");
				if (!existsSync(pendingPath) && !activeIncidentCompactor?.diskPaused)
					writeImmutableJsonOnce(pendingPath, {
						state: "waiting_for_compacted_supervisor_exit_and_wrapper_frontier",
						retryable: true,
						observed: nowFields(),
					});
				continue;
			}
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
					const identity = serviceRunIdentity(run.runDir);
					if (identity)
						activeServiceRecorder?.writer.recordDerivedForRun(
							identity,
							"recorder-control",
							"stopped_target_capture_storage_paused",
							{
								state: "pending",
								targetPid: run.pid,
								targetProcessStartId: run.processStartId ?? "",
							},
						);
					stoppedState.diskPauseMarked = true;
				}
				continue;
			}
			stoppedState.diskPauseMarked = false;
			if (!stoppedState.stoppedBroadCaptured)
				try {
					sampleLinuxIncidentEvidence({
						runDir: run.runDir,
						phase: "final",
						captureBroadRaw: true,
						dependencies: { recordRawSource: (occurrence) => recordLinuxRawSource(run.runDir, occurrence) },
					});
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
			const expectedExit = readExpectedExitDisposition(run.runDir);
			const code = typeof exitEvent?.code === "number" ? exitEvent.code : expectedExit.code;
			const signal =
				typeof exitEvent?.signal === "string" ? (exitEvent.signal as NodeJS.Signals) : expectedExit.signal;
			const correlation = readLinuxIncidentEvidenceCorrelation(run.runDir);
			const classification = correlation.environmentClassification ?? classify(events, code, signal, run.runDir);
			if (!exited && correlation.environmentClassification) {
				appendRunEvent(run.runDir, {
					type: "environment_exit_correlated",
					childPid: run.pid,
					classification,
					attribution: "supporting_evidence",
				});
			}
			const incidentDir = finalizeIncident(
				{ agentDir, socketPath: run.socketPath, launch: { command: "", args: [] } },
				run.runDir,
				{ code, signal, classification },
			);
			if (incidentDir) {
				activeIncidentCompactor?.requestPin(
					basename(run.runDir).slice(-36),
					incidentDir,
					Number.isFinite(Date.parse(exitEvent?.wallTime ?? ""))
						? Date.parse(exitEvent?.wallTime ?? "")
						: Date.now(),
				);
				appendRunEvent(run.runDir, { type: "service_incident_finalized", incidentId: basename(incidentDir) });
				finalized.push(incidentDir);
			}
			if (incidentDir || classification === "normal") {
				writePrivateJson(join(run.runDir, ".service-finalization-complete"), {
					bootId: linuxBootId(),
					servicePid: process.pid,
					classification,
					completed: nowFields(),
				});
				const completedIdentity = serviceRunIdentity(run.runDir);
				if (completedIdentity) activeServiceRecorder?.writer.releaseRunIdentity(completedIdentity);
				serviceSamplingRuns.delete(run.runDir);
				nodeReportCaptureStates.delete(run.runDir);
				providerArtifactCaptureStates.delete(run.runDir);
			}
			continue;
		}
		if (exited) continue;
		const heartbeats = events.filter((event) => event.type === "supervisor_heartbeat");
		const lastHeartbeat = heartbeats.at(-1);
		const heartbeatWall = lastHeartbeat ? Date.parse(lastHeartbeat.wallTime) : Number.NaN;
		const socketWasPresent = heartbeats.some((event) => event.socketExists === true);
		let detected: "event_loop_hang" | "socket_loss" | "worker_response_hang" | undefined;
		if (events.some((event) => event.type === "worker_request_end" && event.outcome === "timeout"))
			detected = "worker_response_hang";
		else if (lastHeartbeat && Number.isFinite(heartbeatWall) && nowMs - heartbeatWall > STALL_THRESHOLD_MS)
			detected = "event_loop_hang";
		else if (socketWasPresent && !existsSync(run.socketPath)) detected = "socket_loss";
		if (!detected) continue;
		const sampling = serviceSamplingRuns.get(run.runDir);
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

export async function runIncidentRecorderService(agentDir = getAgentDir()): Promise<never> {
	if (process.platform !== "linux")
		throw new Error("Incident recorder service requires Linux journald namespace support");
	mkdirSync(join(agentDir, "incident-recorder", "runs"), { recursive: true, mode: 0o700 });
	const compactor = new IncidentRecorderCompactor({ agentDir });
	replaceIncidentRecorderServiceCompactor(compactor);
	try {
		const serviceWriter = new IncidentRecorderWriter({
			runDir: join(agentDir, "incident-recorder"),
			runId: randomUUID(),
			runToken: randomUUID(),
			bootId: linuxBootId(),
			wrapperStartId: getProcessStartId(process.pid),
			serviceSink: true,
		});
		await serviceWriter.start();
		activeServiceRecorder = { writer: serviceWriter, compactor };
		const compactorRun = compactor.run();
		let nextRetentionPassMs = 0;
		for (;;) {
			try {
				await inspectIncidentRecorderRuns(agentDir);
				const nowMs = Date.now();
				if (!compactor.diskPaused) compactor.processPendingPins(nowMs);
				if (nowMs >= nextRetentionPassMs) {
					const retention = runIncidentRetentionPass({ agentDir, nowMs, ...INCIDENT_RETENTION_SERVICE_BUDGET });
					if (retention.uncertainties.length > 0)
						writePrivateJsonAtomicSync(join(agentDir, "incident-recorder", "retention-uncertainty.json"), {
							version: 1,
							state: "fail_closed",
							observed: nowFields(),
							reasons: retention.uncertainties.slice(0, 32),
						});
					if (retention.moreWork)
						writePrivateJsonAtomicSync(join(agentDir, "incident-recorder", "retention-deferred.json"), {
							version: 1,
							state: "bounded_incremental_work_remains",
							observed: nowFields(),
							scannedEntries: retention.scannedEntries,
							deletedEntries: retention.deletedEntries,
						});
					nextRetentionPassMs = nowMs + 60_000;
				}
			} catch {
				// A malformed or unavailable evidence source must not stop later recorder passes.
			}
			await Promise.race([
				compactorRun,
				new Promise<void>((resolveDelay) => setTimeout(resolveDelay, serviceInspectionCadenceMs())),
			]);
		}
	} finally {
		if (activeIncidentCompactor === compactor) replaceIncidentRecorderServiceCompactor(undefined);
		else compactor.dispose();
	}
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
}

export interface RenderJournaldNamespaceOptions {
	storageMaxUse?: string;
	systemKeepFree?: string;
	lineMax?: string;
	maxRetentionSec?: string;
}

export interface IncidentRecorderSystemdRequirements {
	journaldConfig: { path: "/etc/systemd/journald@grimoire.conf"; contents: string };
	socketDropIn: { path: "/etc/systemd/system/systemd-journald@grimoire.socket.d/prime-agent.conf"; contents: string };
	enableUnit: "systemd-journald@grimoire.socket";
	serviceUnit: string;
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
	const storageMaxUse = options.storageMaxUse ?? "16G";
	const systemKeepFree = options.systemKeepFree ?? "10G";
	const maxRetentionSec = options.maxRetentionSec ?? "3d";
	const lineMaxBytes = systemdSizeBytes(lineMax);
	if (
		!lineMaxBytes ||
		lineMaxBytes < 48 * 1024 ||
		!systemdSizeBytes(storageMaxUse) ||
		!systemdSizeBytes(systemKeepFree) ||
		!/^[1-9][0-9]*[smhdw]$/.test(maxRetentionSec)
	) {
		throw new Error("Invalid journald namespace retention or size setting");
	}
	return `[Journal]\nStorage=persistent\nMaxRetentionSec=${maxRetentionSec}\nCompress=yes\nForwardToSyslog=no\nRateLimitIntervalSec=0\nRateLimitBurst=0\nLineMax=${lineMax}\nSystemMaxUse=${storageMaxUse}\nSystemKeepFree=${systemKeepFree}\n`;
}

export function renderIncidentRecorderJournaldSocketDropIn(): string {
	return `[Unit]\nDescription=Automatic Prime Agent raw diagnostic journal namespace socket\n\n[Install]\nWantedBy=sockets.target\n`;
}

export function renderIncidentRecorderSystemdUnit(options: RenderServiceOptions): string {
	if (!isAbsolute(options.nodePath) || !isAbsolute(options.entrypointPath)) {
		throw new Error("Incident recorder service paths must be absolute");
	}
	const args = [options.nodePath, options.entrypointPath, "--incident-recorder-service"];
	if (options.agentDir) args.push("--agent-dir", options.agentDir);
	// 192M/256M caused sustained cgroup reclaim and severe WSL latency in the
	// isolated recorder trial. These are the measured stable staged limits.
	const memoryMax = options.memoryMax ?? "1G";
	const memoryHigh = options.memoryHigh ?? "768M";
	const memorySwapMax = options.memorySwapMax ?? "0";
	const cpuQuota = options.cpuQuota ?? "25%";
	const ioWeight = options.ioWeight ?? 25;
	const restartSeconds = options.restartSeconds ?? 2;
	const tasksMax = options.tasksMax ?? 64;
	const limitNOFILE = options.limitNOFILE ?? 4096;
	const startLimitIntervalSeconds = options.startLimitIntervalSeconds ?? 60;
	const startLimitBurst = options.startLimitBurst ?? 5;
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
		startLimitBurst < 1
	)
		throw new Error("Invalid incident recorder service resource controls");
	return `[Unit]\nDescription=Prime Agent incident compactor, sampler, and finalizer\nStartLimitIntervalSec=${startLimitIntervalSeconds}s\nStartLimitBurst=${startLimitBurst}\n\n[Service]\nType=simple\nKillMode=control-group\nEnvironment=${INCIDENT_RECORDER_SERVICE_ENV}=1\nExecStartPre=/usr/bin/test -S /run/systemd/journal.grimoire/stdout\nExecStart=${args.map(systemdQuote).join(" ")}\nRestart=on-failure\nRestartSec=${restartSeconds}s\nMemoryHigh=${memoryHigh}\nMemoryMax=${memoryMax}\nMemorySwapMax=${memorySwapMax}\nCPUQuota=${cpuQuota}\nIOWeight=${ioWeight}\nNice=10\nTasksMax=${tasksMax}\nLimitNOFILE=${limitNOFILE}\nOOMPolicy=stop\nRuntimeDirectory=prime-agent\nRuntimeDirectoryMode=0700\nUMask=0077\n\n[Install]\nWantedBy=default.target\n`;
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

export function installIncidentRecorderJournaldNamespace(options: InstallServiceOptions): InstallServiceResult {
	if ((options.platform ?? process.platform) !== "linux")
		return { status: "unsupported", message: "journald namespace is only available on Linux" };
	const requirements = renderIncidentRecorderSystemdRequirements(options);
	const run =
		options.spawnSyncImpl ??
		((command: string, args: readonly string[]) =>
			spawnSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
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
	const namespace = installIncidentRecorderJournaldNamespace(options);
	if (namespace.status === "failed" || namespace.status === "unavailable") return namespace;
	const systemctl = options.systemctlPath ?? "systemctl";
	const run =
		options.spawnSyncImpl ??
		((command, args) => spawnSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
	const probe = run(systemctl, ["--user", "show-environment"]);
	if (probe.error || probe.status !== 0)
		return { status: "unavailable", message: "systemd user manager is unavailable; no files were changed" };
	const configHome =
		options.configHomeDir ??
		(options.homeDir ? join(options.homeDir, ".config") : process.env.XDG_CONFIG_HOME || join(homedir(), ".config"));
	const unitDir = join(configHome, "systemd", "user");
	const unitPath = join(unitDir, "prime-agent-incident-recorder.service");
	const desired = renderIncidentRecorderSystemdUnit(options);
	let changed = true;
	const current = readBoundedPrefix(unitPath, INCIDENT_RECORDER_LIMITS.evidenceFileBytes);
	if (current && !current.truncated) changed = current.value.toString("utf8") !== desired;
	if (changed) {
		mkdirSync(unitDir, { recursive: true, mode: 0o700 });
		const temporary = `${unitPath}.tmp-${process.pid}-${randomUUID()}`;
		writeFileSync(temporary, desired, { mode: 0o600 });
		renameSync(temporary, unitPath);
		chmodSync(unitPath, 0o600);
	}
	if (changed) {
		const reload = run(systemctl, ["--user", "daemon-reload"]);
		if (reload.error || reload.status !== 0)
			return {
				status: "failed",
				unitPath,
				message: reload.error?.message ?? reload.stderr ?? "systemctl user daemon-reload failed",
			};
	}
	const enable = run(systemctl, ["--user", "enable", basename(unitPath)]);
	if (enable.error || enable.status !== 0)
		return {
			status: "failed",
			unitPath,
			message: enable.error?.message ?? enable.stderr ?? "systemctl user enable failed",
		};
	const activate = run(systemctl, ["--user", changed ? "restart" : "start", basename(unitPath)]);
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
		status: changed || namespace.status === "installed" ? "installed" : "unchanged",
		unitPath,
		message: `namespace=${namespace.status}; user-service=${changed ? "installed" : "unchanged"}`,
	};
}
