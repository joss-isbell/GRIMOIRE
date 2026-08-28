import { randomUUID } from "node:crypto";
import {
	closeSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	lstatSync,
	openSync,
	renameSync,
	rmSync,
	write,
} from "node:fs";
import { join } from "node:path";
import { getProcessStartId } from "../../core/session-lease.js";
import { INCIDENT_RECORDER_RUN_DIR_ENV } from "./incident-recorder-env.js";

const EVENT_FILE_NAME = "supervisor-timeline.jsonl";
const PREVIOUS_EVENT_FILE_NAME = "supervisor-timeline.previous.jsonl";
const MAX_EVENT_FILE_BYTES = 1024 * 1024;
const MAX_EVENT_BYTES = 3584;
const MAX_QUEUE_EVENTS = 64;
const SENSITIVE_KEY =
	/(?:token|secret|password|credential|authorization|cookie|prompt|payload|content|body|argv|environment)/i;
const STRING_FIELDS = new Set([
	"activeSessionId",
	"arch",
	"callerCategory",
	"catchupPurpose",
	"classification",
	"clientGeneration",
	"code",
	"commandType",
	"disposition",
	"event",
	"forkserverProcessStartId",
	"kernelIdentityLivenessResult",
	"kernelProcessStartId",
	"name",
	"newState",
	"nodejsVersion",
	"oldState",
	"observationId",
	"origin",
	"outcome",
	"platform",
	"phase",
	"processStartId",
	"producerProcessStartId",
	"reason",
	"recoveryId",
	"requestId",
	"requestType",
	"requestedKillSignal",
	"role",
	"runId",
	"sessionId",
	"signal",
	"socketStatus",
	"sourceClientId",
	"sourceOperation",
	"sourceOperationType",
	"state",
	"syscall",
	"targetProcessStartId",
	"toolCallId",
	"trigger",
	"triggerRequestId",
	"workerId",
	"workerIdentityLivenessResult",
	"workerProcessStartId",
]);
const NON_CAUSAL_TYPES = new Set([
	"application_source_reference",
	"supervisor_log_record",
	"daemon_socket_outbound_write_outcome",
	"daemon_socket_outbound_attempt_result",
	"worker_transport_outbound_write_outcome",
]);
const RESERVED_FIELDS = new Set([
	"type",
	"source",
	"wallTime",
	"monotonicNs",
	"pid",
	"occurrenceId",
	"producerPid",
	"producerProcessStartId",
]);

type CaptureSource = "recorder-events" | "supervisor-events" | "recorder-control" | "loss-accounting" | string;
type EmitterPhase = "idle" | "running" | "stopping" | "stopped" | "failed";

export type IncidentRecorderAdmission =
	| { accepted: true; occurrenceId: string; fieldsTruncated?: true }
	| { accepted: false; occurrenceId: string; reason: string };

function safeValue(key: string, value: unknown, depth = 0): unknown {
	if (value === null || typeof value === "boolean") return value;
	if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
	if (typeof value === "string") {
		if (!STRING_FIELDS.has(key) || !/^[A-Za-z0-9_.:+-]{1,256}$/.test(value)) return undefined;
		return value;
	}
	if (depth >= 3 || typeof value !== "object") return undefined;
	if (Array.isArray(value))
		return value.slice(0, 16).flatMap((item) => {
			const safe = safeValue(key, item, depth + 1);
			return safe === undefined ? [] : [safe];
		});
	const result: Record<string, unknown> = {};
	const descriptors = Object.getOwnPropertyDescriptors(value);
	for (const [childKey, descriptor] of Object.entries(descriptors).slice(0, 64)) {
		if (!Object.hasOwn(descriptor, "value") || !/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(childKey)) continue;
		if (SENSITIVE_KEY.test(childKey) || RESERVED_FIELDS.has(childKey)) continue;
		const safe = safeValue(childKey, descriptor.value, depth + 1);
		if (safe !== undefined) result[childKey] = safe;
	}
	return result;
}

export function sanitizeIncidentCausalFields(fields: Record<string, unknown>): Record<string, unknown> {
	try {
		const value = safeValue("fields", fields);
		return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

function accepted(occurrenceId = randomUUID(), fieldsTruncated = false): IncidentRecorderAdmission {
	return { accepted: true, occurrenceId, ...(fieldsTruncated ? { fieldsTruncated: true as const } : {}) };
}
function rejected(reason: string, occurrenceId = randomUUID()): IncidentRecorderAdmission {
	return { accepted: false, occurrenceId, reason };
}

interface EmitterState {
	generation: number;
	phase: EmitterPhase;
	descriptor?: number;
	runDir?: string;
	eventPath?: string;
	queue: Buffer[];
	writing: boolean;
	stopPromise?: Promise<void>;
	resolveStop?: () => void;
	stopTimer?: ReturnType<typeof setTimeout>;
}
const emitter: EmitterState = { generation: 0, phase: "idle", queue: [], writing: false };

function closeEmitterDescriptor(): void {
	const descriptor = emitter.descriptor;
	emitter.descriptor = undefined;
	if (descriptor !== undefined)
		try {
			closeSync(descriptor);
		} catch {}
}

function settleEmitterStop(): void {
	if (emitter.writing) return;
	if (emitter.stopTimer) clearTimeout(emitter.stopTimer);
	emitter.stopTimer = undefined;
	if (emitter.phase === "stopping") emitter.phase = "stopped";
	closeEmitterDescriptor();
	emitter.resolveStop?.();
	emitter.resolveStop = undefined;
}

function failEmitter(generation: number): void {
	if (generation !== emitter.generation) return;
	emitter.phase = "failed";
	emitter.queue.length = 0;
	settleEmitterStop();
}

function rotateEmitterSinkIfNeeded(nextBytes: number): boolean {
	const descriptor = emitter.descriptor;
	const runDir = emitter.runDir;
	const eventPath = emitter.eventPath;
	if (descriptor === undefined || !runDir || !eventPath) return false;
	try {
		const stat = fstatSync(descriptor);
		if (stat.size + nextBytes <= MAX_EVENT_FILE_BYTES) return true;
		fsyncSync(descriptor);
		closeSync(descriptor);
		emitter.descriptor = undefined;
		rmSync(join(runDir, PREVIOUS_EVENT_FILE_NAME), { force: true });
		renameSync(eventPath, join(runDir, PREVIOUS_EVENT_FILE_NAME));
		const replacement = openSync(
			eventPath,
			fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW,
			0o600,
		);
		const replacementStat = fstatSync(replacement);
		if (!replacementStat.isFile() || replacementStat.nlink !== 1 || (replacementStat.mode & 0o077) !== 0) {
			closeSync(replacement);
			return false;
		}
		emitter.descriptor = replacement;
		return true;
	} catch {
		return false;
	}
}

function pumpEmitter(): void {
	if (emitter.writing || emitter.descriptor === undefined) return;
	if (emitter.phase !== "running" && emitter.phase !== "stopping") return;
	const next = emitter.queue.shift();
	if (!next) {
		if (emitter.phase === "stopping") settleEmitterStop();
		return;
	}
	const generation = emitter.generation;
	if (!rotateEmitterSinkIfNeeded(next.length) || emitter.descriptor === undefined) {
		failEmitter(generation);
		return;
	}
	const descriptor = emitter.descriptor;
	emitter.writing = true;
	try {
		write(descriptor, next, (error, bytesWritten) => {
			if (generation !== emitter.generation) {
				try {
					closeSync(descriptor);
				} catch {}
				return;
			}
			emitter.writing = false;
			if (error || bytesWritten !== next.length) {
				failEmitter(generation);
				return;
			}
			if (emitter.phase === "stopped" || emitter.phase === "failed") {
				closeEmitterDescriptor();
				return;
			}
			pumpEmitter();
		});
	} catch {
		emitter.writing = false;
		failEmitter(generation);
	}
}

export function configureIncidentCaptureEmitter(): boolean {
	if (emitter.phase === "running") return true;
	if (emitter.phase === "stopping") return false;
	closeEmitterDescriptor();
	const runDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
	const processStartId = getProcessStartId(process.pid);
	if (!runDir || !processStartId) return false;
	let descriptor: number | undefined;
	try {
		const eventPath = join(runDir, EVENT_FILE_NAME);
		const runStat = lstatSync(runDir);
		if (!runStat.isDirectory() || runStat.isSymbolicLink() || (runStat.mode & 0o077) !== 0)
			throw new Error("causal run directory is not private");
		if (typeof process.getuid === "function" && runStat.uid !== process.getuid())
			throw new Error("causal run directory owner mismatch");
		descriptor = openSync(
			eventPath,
			fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW,
			0o600,
		);
		const stat = fstatSync(descriptor);
		if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0)
			throw new Error("causal event sink is not a private single-link file");
		if (typeof process.getuid === "function" && stat.uid !== process.getuid())
			throw new Error("causal event sink owner mismatch");
		emitter.generation += 1;
		emitter.phase = "running";
		emitter.descriptor = descriptor;
		emitter.runDir = runDir;
		emitter.eventPath = eventPath;
		emitter.queue = [];
		emitter.writing = false;
		emitter.stopPromise = undefined;
		emitter.resolveStop = undefined;
		emitter.stopTimer = undefined;
		return true;
	} catch {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
		return false;
	}
}

export function emitIncidentDerived(
	source: CaptureSource,
	type: string,
	fields: Record<string, unknown>,
): IncidentRecorderAdmission {
	const occurrenceId = randomUUID();
	try {
		if (emitter.phase !== "running" || emitter.descriptor === undefined)
			return rejected("capture_not_configured", occurrenceId);
		if (!/^[a-z][a-z0-9_]{0,79}$/.test(type) || NON_CAUSAL_TYPES.has(type))
			return rejected("non_causal_event", occurrenceId);
		const processStartId = getProcessStartId(process.pid);
		if (!processStartId) return rejected("producer_identity_unavailable", occurrenceId);
		const event = {
			...sanitizeIncidentCausalFields(fields),
			type,
			wallTime: new Date().toISOString(),
			monotonicNs: process.hrtime.bigint().toString(),
			pid: process.pid,
			source: source === "supervisor-events" ? "supervisor-events" : "recorder-events",
			occurrenceId,
			producerPid: process.pid,
			producerProcessStartId: processStartId,
		};
		let bytes = Buffer.from(`${JSON.stringify(event)}\n`, "utf8");
		const fieldsTruncated = bytes.length > MAX_EVENT_BYTES;
		if (fieldsTruncated) {
			bytes = Buffer.from(
				`${JSON.stringify({
					type,
					wallTime: event.wallTime,
					monotonicNs: event.monotonicNs,
					pid: process.pid,
					source: event.source,
					occurrenceId,
					producerPid: process.pid,
					producerProcessStartId: processStartId,
					fieldsTruncated: true,
				})}\n`,
				"utf8",
			);
		}
		if (bytes.length > MAX_EVENT_BYTES || emitter.queue.length >= MAX_QUEUE_EVENTS)
			return rejected("bounded_queue_full", occurrenceId);
		emitter.queue.push(bytes);
		pumpEmitter();
		return accepted(occurrenceId, fieldsTruncated);
	} catch {
		return rejected("capture_failed_open", occurrenceId);
	}
}

export async function stopIncidentCaptureEmitter(): Promise<void> {
	if (emitter.phase === "idle" || emitter.phase === "stopped" || emitter.phase === "failed") {
		closeEmitterDescriptor();
		return;
	}
	if (emitter.stopPromise) return emitter.stopPromise;
	emitter.phase = "stopping";
	emitter.stopPromise = new Promise<void>((resolve) => {
		emitter.resolveStop = resolve;
		emitter.stopTimer = setTimeout(() => {
			if (emitter.phase !== "stopping") return;
			emitter.generation += 1;
			emitter.phase = "stopped";
			emitter.queue.length = 0;
			emitter.writing = false;
			// A pending libuv write still owns this descriptor. Detach it from the
			// reusable emitter state; its stale callback closes it after settlement.
			emitter.descriptor = undefined;
			emitter.stopTimer = undefined;
			emitter.resolveStop = undefined;
			resolve();
		}, 100);
	});
	pumpEmitter();
	settleEmitterStop();
	return emitter.stopPromise;
}

export function stopIncidentCaptureEmitterOnExit(): void {
	emitter.phase = "stopped";
	emitter.queue.length = 0;
	if (!emitter.writing) closeEmitterDescriptor();
}
