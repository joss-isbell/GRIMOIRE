import { randomUUID } from "node:crypto";
import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, write } from "node:fs";
import { join } from "node:path";
import type { Readable } from "node:stream";
import { getProcessStartId } from "../../core/session-lease.js";
import { INCIDENT_RECORDER_RUN_DIR_ENV } from "./incident-recorder-env.js";

export const INCIDENT_RECORDER_CAPTURE_FD_ENV = "PRIME_INCIDENT_RECORDER_CAPTURE_FD";
export const INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV = "PRIME_INCIDENT_RECORDER_CAPTURE_OWNER_PID";
export const INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV = "PRIME_INCIDENT_RECORDER_CAPTURE_OWNER_START_ID";
export const INCIDENT_RECORDER_CAPTURE_FD = 4;
export const INCIDENT_RECORDER_ROOT_FD_ENV = "PRIME_INCIDENT_RECORDER_ROOT_FD";
export const INCIDENT_RECORDER_ROOT_FD = 5;

const EVENT_FILE_NAME = "timeline.jsonl";
const MAX_EVENT_BYTES = 3584;
const MAX_QUEUE_EVENTS = 64;
const SENSITIVE_KEY =
	/(?:token|secret|password|credential|authorization|cookie|prompt|payload|content|body|argv|environment)/i;
const STRING_FIELDS = new Set([
	"classification",
	"code",
	"commandType",
	"name",
	"origin",
	"outcome",
	"phase",
	"processStartId",
	"producerProcessStartId",
	"reason",
	"requestId",
	"requestType",
	"runId",
	"signal",
	"socketStatus",
	"state",
	"syscall",
	"targetProcessStartId",
	"workerId",
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
	| { accepted: true; occurrenceId: string }
	| { accepted: false; occurrenceId: string; reason: string };

export interface IncidentRecorderFinalizationExpectation {
	supervisorExitOccurrenceId: string;
	durableStructuredCapture: true;
}

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

function safeFields(fields: Record<string, unknown>): Record<string, unknown> {
	try {
		const value = safeValue("fields", fields);
		return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

function accepted(occurrenceId = randomUUID()): IncidentRecorderAdmission {
	return { accepted: true, occurrenceId };
}
function rejected(reason: string, occurrenceId = randomUUID()): IncidentRecorderAdmission {
	return { accepted: false, occurrenceId, reason };
}

interface EmitterState {
	generation: number;
	phase: EmitterPhase;
	descriptor?: number;
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

function pumpEmitter(): void {
	if (emitter.writing || emitter.descriptor === undefined) return;
	if (emitter.phase !== "running" && emitter.phase !== "stopping") return;
	const next = emitter.queue.shift();
	if (!next) {
		if (emitter.phase === "stopping") settleEmitterStop();
		return;
	}
	const generation = emitter.generation;
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
		const runStat = lstatSync(runDir);
		if (!runStat.isDirectory() || runStat.isSymbolicLink() || (runStat.mode & 0o077) !== 0)
			throw new Error("causal run directory is not private");
		if (typeof process.getuid === "function" && runStat.uid !== process.getuid())
			throw new Error("causal run directory owner mismatch");
		descriptor = openSync(
			join(runDir, EVENT_FILE_NAME),
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
		emitter.queue = [];
		emitter.writing = false;
		emitter.stopPromise = undefined;
		emitter.resolveStop = undefined;
		emitter.stopTimer = undefined;
		delete process.env[INCIDENT_RECORDER_CAPTURE_FD_ENV];
		delete process.env[INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV];
		delete process.env[INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV];
		delete process.env[INCIDENT_RECORDER_ROOT_FD_ENV];
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
			...safeFields(fields),
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
		if (bytes.length > MAX_EVENT_BYTES) {
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
		return accepted(occurrenceId);
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

export interface IncidentRecorderWriterOptions {
	runDir: string;
	runId?: string;
	runToken?: string;
	bootId?: string;
	wrapperStartId?: string;
	serviceSink?: boolean;
	onStructuredEvent?: (source: string, type: string, fields: Record<string, unknown>) => boolean | undefined;
}

export class IncidentRecorderWriter {
	private readonly onStructuredEvent?: (
		source: string,
		type: string,
		fields: Record<string, unknown>,
	) => boolean | undefined;
	private stopped = false;

	constructor(options: IncidentRecorderWriterOptions) {
		this.onStructuredEvent = options.onStructuredEvent;
	}

	async start(): Promise<void> {}

	async setSourceIdentity(_identity: Record<string, unknown>): Promise<IncidentRecorderAdmission> {
		return this.stopped ? rejected("writer_stopped") : accepted();
	}

	attachCaptureStream(stream: Readable): void {
		stream.resume();
	}

	recordDerived(source: CaptureSource, type: string, fields: Record<string, unknown>): IncidentRecorderAdmission {
		const occurrenceId = randomUUID();
		if (this.stopped) return rejected("writer_stopped", occurrenceId);
		try {
			const result = this.onStructuredEvent?.(source, type, { ...safeFields(fields), occurrenceId });
			return result === false ? rejected("durable_sink_unavailable", occurrenceId) : accepted(occurrenceId);
		} catch {
			return rejected("durable_sink_failed_open", occurrenceId);
		}
	}

	recordExactBytes(
		_source: CaptureSource,
		_type: string,
		_value: Uint8Array,
		_encoding: string,
		_fields: Record<string, unknown>,
	): IncidentRecorderAdmission {
		return rejected("raw_bytes_not_causal");
	}

	recordDerivedForRun(
		_identity: { runId: string; runToken: string },
		source: CaptureSource,
		type: string,
		fields: Record<string, unknown>,
	): IncidentRecorderAdmission {
		return this.recordDerived(source, type, fields);
	}

	recordExactBytesForRun(
		_identity: { runId: string; runToken: string },
		_source: CaptureSource,
		_type: string,
		_value: Uint8Array,
		_encoding: string,
		_fields: Record<string, unknown>,
	): IncidentRecorderAdmission {
		return rejected("raw_bytes_not_causal");
	}

	releaseRunIdentity(_identity: { runId: string; runToken: string }): void {}

	async stop(_deadlineMs = 1_000): Promise<void> {
		this.stopped = true;
	}

	finalizationExpectation(supervisorExitOccurrenceId: string): IncidentRecorderFinalizationExpectation {
		return { supervisorExitOccurrenceId, durableStructuredCapture: true };
	}
}
