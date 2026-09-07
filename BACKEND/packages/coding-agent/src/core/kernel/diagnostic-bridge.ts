import { createHmac, timingSafeEqual } from "node:crypto";
import type { Writable } from "node:stream";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "./diagnostics.js";

export const KERNEL_DIAGNOSTIC_BRIDGE_VERSION = 1;
export const KERNEL_DIAGNOSTIC_BRIDGE_MAX_STDERR_BYTES = 16 * 1024;
export const KERNEL_DIAGNOSTIC_BRIDGE_MAX_PAYLOAD_BYTES = 32 * 1024;
export const KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES = 48 * 1024;
export const KERNEL_DIAGNOSTIC_BRIDGE_MAX_PENDING_BYTES = 256 * 1024;
export const KERNEL_DIAGNOSTIC_BRIDGE_MAX_REPLAY_BYTES = 512 * 1024;
export const KERNEL_DIAGNOSTIC_BRIDGE_CLOSE_TIMEOUT_MS = 250;
const KERNEL_DIAGNOSTIC_BRIDGE_HANDOFF_DRAIN_TIMEOUT_MS = 250;

const FRAME_PREFIX = "GKD1";
const MAX_SESSION_ID_BYTES = 4096;
const MAX_KERNEL_INSTANCE_ID_BYTES = 128;
const MAX_PROCESS_START_ID_BYTES = 256;
const MAX_REQUEST_MESSAGE_ID_BYTES = 512;
const MAX_REASON_BYTES = 4096;

export interface KernelDiagnosticBridgeDropCounts {
	queueOverflow: number;
	evictedNormal: number;
	criticalOverflow: number;
	oversize: number;
	encodeFailure: number;
	transportError: number;
	shutdown: number;
}

export type KernelDiagnosticBridgeLossReason =
	| "line_overflow"
	| "malformed_frame"
	| "authentication_failed"
	| "payload_oversize"
	| "invalid_payload"
	| "sequence_gap"
	| "sequence_replay"
	| "trailing_partial_frame";

export interface KernelDiagnosticBridgeLoss {
	reason: KernelDiagnosticBridgeLossReason;
	droppedFrames?: number;
	expectedSequence?: number;
	observedSequence?: number;
}

export interface KernelDiagnosticBridgeDecoderOptions {
	capability: string;
	initialSequence?: number;
	onEvent(event: KernelDiagnosticEvent): void;
	onDrop(counts: KernelDiagnosticBridgeDropCounts): void;
	onLoss(loss: KernelDiagnosticBridgeLoss): void;
	onSequence?(sequence: number): void;
}

interface KernelDiagnosticEventPayload {
	version: 1;
	kind: "event";
	sequence: number;
	event: Record<string, unknown>;
}

interface KernelDiagnosticDropPayload {
	version: 1;
	kind: "drop";
	sequence: number;
	counts: KernelDiagnosticBridgeDropCounts;
}

type KernelDiagnosticBridgePayload = KernelDiagnosticEventPayload | KernelDiagnosticDropPayload;

interface QueuedKernelDiagnostic {
	event: Record<string, unknown>;
	critical: boolean;
	estimatedBytes: number;
}

interface ActiveWrite {
	kind: "event" | "drop";
	dropSnapshot?: KernelDiagnosticBridgeDropCounts;
}

function emptyDropCounts(): KernelDiagnosticBridgeDropCounts {
	return {
		queueOverflow: 0,
		evictedNormal: 0,
		criticalOverflow: 0,
		oversize: 0,
		encodeFailure: 0,
		transportError: 0,
		shutdown: 0,
	};
}

function subtractDropCounts(target: KernelDiagnosticBridgeDropCounts, source: KernelDiagnosticBridgeDropCounts): void {
	for (const key of Object.keys(target) as Array<keyof KernelDiagnosticBridgeDropCounts>) {
		target[key] = Math.max(0, target[key] - source[key]);
	}
}

function hasDrops(counts: KernelDiagnosticBridgeDropCounts): boolean {
	return Object.values(counts).some((count) => count > 0);
}

function copyDropCounts(counts: KernelDiagnosticBridgeDropCounts): KernelDiagnosticBridgeDropCounts {
	return { ...counts };
}

function truncateUtf8(value: string, maxBytes: number): string {
	const bytes = Buffer.from(value);
	if (bytes.byteLength <= maxBytes) return value;
	let result = bytes.subarray(0, maxBytes).toString("utf8");
	while (Buffer.byteLength(result) > maxBytes) result = result.slice(0, -1);
	return result;
}

function boundedOptionalString(value: string | undefined, maxBytes: number): string | undefined {
	return value === undefined ? undefined : truncateUtf8(value, maxBytes);
}

function serializeEvent(event: KernelDiagnosticEvent): Record<string, unknown> {
	const identity = {
		type: event.type,
		...(event.sessionId !== undefined
			? { sessionId: boundedOptionalString(event.sessionId, MAX_SESSION_ID_BYTES) }
			: {}),
		kernelInstanceId: truncateUtf8(event.kernelInstanceId, MAX_KERNEL_INSTANCE_ID_BYTES),
		kernelPid: event.kernelPid,
		...(event.kernelProcessStartId !== undefined
			? {
					kernelProcessStartId: boundedOptionalString(event.kernelProcessStartId, MAX_PROCESS_START_ID_BYTES),
				}
			: {}),
		launchMode: event.launchMode,
	};
	if (event.type === "kernel_process_started" || event.type === "kernel_ready") {
		return { ...identity, phase: event.phase };
	}
	if (event.type === "kernel_execute_started") {
		return {
			...identity,
			phase: event.phase,
			requestMsgId: truncateUtf8(event.requestMsgId, MAX_REQUEST_MESSAGE_ID_BYTES),
		};
	}
	if (event.type === "kernel_channel_fault") {
		return {
			...identity,
			channel: event.channel,
			crashPhase: event.crashPhase,
			...(event.requestMsgId !== undefined
				? { requestMsgId: boundedOptionalString(event.requestMsgId, MAX_REQUEST_MESSAGE_ID_BYTES) }
				: {}),
			reason: truncateUtf8(event.reason, MAX_REASON_BYTES),
		};
	}
	const stderrTail = event.stderrTail
		? Buffer.from(event.stderrTail).subarray(-KERNEL_DIAGNOSTIC_BRIDGE_MAX_STDERR_BYTES)
		: undefined;
	return {
		...identity,
		crashPhase: event.crashPhase,
		...(event.requestMsgId !== undefined
			? { requestMsgId: boundedOptionalString(event.requestMsgId, MAX_REQUEST_MESSAGE_ID_BYTES) }
			: {}),
		code: event.code,
		signal: event.signal,
		reason: event.reason,
		...(stderrTail && stderrTail.byteLength > 0 ? { stderrTailBase64: stderrTail.toString("base64") } : {}),
		stderrCaptureStatus: event.stderrCaptureStatus ?? "unknown",
		...(event.stderrCaptureComplete !== undefined ? { stderrCaptureComplete: event.stderrCaptureComplete } : {}),
		stderrBytes: event.stderrBytes,
		sourceTruncated:
			event.sourceTruncated || (event.stderrTail?.byteLength ?? 0) > KERNEL_DIAGNOSTIC_BRIDGE_MAX_STDERR_BYTES,
	};
}

function isBoundedString(value: unknown, maxBytes: number, allowEmpty = false): value is string {
	return typeof value === "string" && (allowEmpty || value.length > 0) && Buffer.byteLength(value) <= maxBytes;
}

function isOptionalBoundedString(value: unknown, maxBytes: number): value is string | undefined {
	return value === undefined || isBoundedString(value, maxBytes);
}

function isSafeNonNegativeInteger(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isKernelIdentity(value: Record<string, unknown>): boolean {
	return (
		isOptionalBoundedString(value.sessionId, MAX_SESSION_ID_BYTES) &&
		isBoundedString(value.kernelInstanceId, MAX_KERNEL_INSTANCE_ID_BYTES) &&
		typeof value.kernelPid === "number" &&
		Number.isSafeInteger(value.kernelPid) &&
		value.kernelPid > 0 &&
		isOptionalBoundedString(value.kernelProcessStartId, MAX_PROCESS_START_ID_BYTES) &&
		(value.launchMode === "direct" || value.launchMode === "fork")
	);
}

function decodeEvent(value: unknown): KernelDiagnosticEvent | undefined {
	if (!value || typeof value !== "object") return undefined;
	const event = value as Record<string, unknown>;
	if (!isKernelIdentity(event)) return undefined;
	const identity = {
		...(typeof event.sessionId === "string" ? { sessionId: event.sessionId } : {}),
		kernelInstanceId: event.kernelInstanceId as string,
		kernelPid: event.kernelPid as number,
		...(typeof event.kernelProcessStartId === "string" ? { kernelProcessStartId: event.kernelProcessStartId } : {}),
		launchMode: event.launchMode as "direct" | "fork",
	};
	if (event.type === "kernel_process_started" && event.phase === "resolving_ports") {
		return { ...identity, type: event.type, phase: event.phase };
	}
	if (event.type === "kernel_ready" && event.phase === "idle") {
		return { ...identity, type: event.type, phase: event.phase };
	}
	if (
		event.type === "kernel_execute_started" &&
		event.phase === "executing" &&
		isBoundedString(event.requestMsgId, MAX_REQUEST_MESSAGE_ID_BYTES)
	) {
		return { ...identity, type: event.type, phase: event.phase, requestMsgId: event.requestMsgId };
	}
	const crashPhase = event.crashPhase;
	if (
		crashPhase !== "resolving_ports" &&
		crashPhase !== "ready_probe" &&
		crashPhase !== "idle" &&
		crashPhase !== "executing"
	) {
		return undefined;
	}
	if (
		event.type === "kernel_channel_fault" &&
		(event.channel === "shell" || event.channel === "iopub" || event.channel === "control") &&
		isOptionalBoundedString(event.requestMsgId, MAX_REQUEST_MESSAGE_ID_BYTES) &&
		isBoundedString(event.reason, MAX_REASON_BYTES)
	) {
		return {
			...identity,
			type: event.type,
			channel: event.channel,
			crashPhase,
			...(typeof event.requestMsgId === "string" ? { requestMsgId: event.requestMsgId } : {}),
			reason: event.reason,
		};
	}
	if (
		event.type !== "kernel_unexpected_exit" ||
		!isOptionalBoundedString(event.requestMsgId, MAX_REQUEST_MESSAGE_ID_BYTES) ||
		!(event.code === null || (typeof event.code === "number" && Number.isSafeInteger(event.code))) ||
		!(event.signal === null || isBoundedString(event.signal, 32)) ||
		(event.reason !== "process_exit" && event.reason !== "forkserver_unavailable") ||
		!isSafeNonNegativeInteger(event.stderrBytes) ||
		!(event.stderrCaptureComplete === undefined || typeof event.stderrCaptureComplete === "boolean") ||
		!(
			event.stderrCaptureStatus === undefined ||
			event.stderrCaptureStatus === "available" ||
			event.stderrCaptureStatus === "unavailable_fork" ||
			event.stderrCaptureStatus === "unknown"
		) ||
		typeof event.sourceTruncated !== "boolean" ||
		!(event.stderrTailBase64 === undefined || typeof event.stderrTailBase64 === "string")
	) {
		return undefined;
	}
	let stderrTail: Buffer | undefined;
	if (typeof event.stderrTailBase64 === "string") {
		if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(event.stderrTailBase64)) {
			return undefined;
		}
		stderrTail = Buffer.from(event.stderrTailBase64, "base64");
		if (stderrTail.toString("base64") !== event.stderrTailBase64) return undefined;
		if (stderrTail.byteLength > KERNEL_DIAGNOSTIC_BRIDGE_MAX_STDERR_BYTES) return undefined;
	}
	if ((stderrTail?.byteLength ?? 0) > event.stderrBytes) return undefined;
	return {
		...identity,
		type: event.type,
		crashPhase,
		...(typeof event.requestMsgId === "string" ? { requestMsgId: event.requestMsgId } : {}),
		code: event.code,
		signal: event.signal as NodeJS.Signals | null,
		reason: event.reason,
		...(stderrTail && stderrTail.byteLength > 0 ? { stderrTail } : {}),
		stderrCaptureStatus: event.stderrCaptureStatus ?? "unknown",
		...(typeof event.stderrCaptureComplete === "boolean"
			? { stderrCaptureComplete: event.stderrCaptureComplete }
			: {}),
		stderrBytes: event.stderrBytes,
		sourceTruncated: event.sourceTruncated,
	};
}

function isDropCounts(value: unknown): value is KernelDiagnosticBridgeDropCounts {
	if (!value || typeof value !== "object") return false;
	const counts = value as Record<string, unknown>;
	const keys: Array<keyof KernelDiagnosticBridgeDropCounts> = [
		"queueOverflow",
		"evictedNormal",
		"criticalOverflow",
		"oversize",
		"encodeFailure",
		"transportError",
		"shutdown",
	];
	return (
		Object.keys(counts).length === keys.length &&
		Object.keys(counts).every((key) => keys.includes(key as keyof KernelDiagnosticBridgeDropCounts)) &&
		keys.every((key) => isSafeNonNegativeInteger(counts[key]))
	);
}

export function isKernelDiagnosticBridgeCapability(value: string | undefined): value is string {
	if (!value || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
	const decoded = Buffer.from(value, "base64url");
	return decoded.byteLength === 32 && decoded.toString("base64url") === value;
}

function encodePayload(payload: KernelDiagnosticBridgePayload, capability: string): Buffer | undefined {
	try {
		const payloadBytes = Buffer.from(JSON.stringify(payload));
		if (payloadBytes.byteLength > KERNEL_DIAGNOSTIC_BRIDGE_MAX_PAYLOAD_BYTES) return undefined;
		const mac = createHmac("sha256", Buffer.from(capability, "base64url")).update(payloadBytes).digest("base64url");
		const line = Buffer.from(`${FRAME_PREFIX}.${payloadBytes.toString("base64url")}.${mac}\n`, "ascii");
		return line.byteLength <= KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES ? line : undefined;
	} catch {
		return undefined;
	}
}

export function encodeKernelDiagnosticBridgeEvent(
	event: KernelDiagnosticEvent,
	capability: string,
	sequence = 1,
): Buffer | undefined {
	if (!isKernelDiagnosticBridgeCapability(capability) || !Number.isSafeInteger(sequence) || sequence < 1) {
		return undefined;
	}
	return encodePayload(
		{ version: KERNEL_DIAGNOSTIC_BRIDGE_VERSION, kind: "event", sequence, event: serializeEvent(event) },
		capability,
	);
}

export function encodeKernelDiagnosticBridgeDrop(
	counts: KernelDiagnosticBridgeDropCounts,
	capability: string,
	sequence: number,
): Buffer | undefined {
	if (
		!isKernelDiagnosticBridgeCapability(capability) ||
		!Number.isSafeInteger(sequence) ||
		sequence < 1 ||
		!isDropCounts(counts)
	) {
		return undefined;
	}
	return encodePayload({ version: KERNEL_DIAGNOSTIC_BRIDGE_VERSION, kind: "drop", sequence, counts }, capability);
}

function decodeLine(
	line: Buffer,
	capability: string,
):
	| { kind: "event"; sequence: number; event: KernelDiagnosticEvent }
	| { kind: "drop"; sequence: number; counts: KernelDiagnosticBridgeDropCounts }
	| { kind: "loss"; reason: KernelDiagnosticBridgeLossReason } {
	if (!isKernelDiagnosticBridgeCapability(capability)) {
		return { kind: "loss", reason: "authentication_failed" };
	}
	if (line.byteLength > KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES) {
		return { kind: "loss", reason: "line_overflow" };
	}
	const text = line.toString("ascii");
	const parts = text.split(".");
	if (
		parts.length !== 3 ||
		parts[0] !== FRAME_PREFIX ||
		!parts[1] ||
		!parts[2] ||
		!/^[A-Za-z0-9_-]+$/.test(parts[1]) ||
		!/^[A-Za-z0-9_-]{43}$/.test(parts[2])
	) {
		return { kind: "loss", reason: "malformed_frame" };
	}
	const payloadBytes = Buffer.from(parts[1], "base64url");
	if (payloadBytes.toString("base64url") !== parts[1]) {
		return { kind: "loss", reason: "malformed_frame" };
	}
	if (payloadBytes.byteLength > KERNEL_DIAGNOSTIC_BRIDGE_MAX_PAYLOAD_BYTES) {
		return { kind: "loss", reason: "payload_oversize" };
	}
	const suppliedMac = Buffer.from(parts[2], "base64url");
	if (suppliedMac.toString("base64url") !== parts[2]) {
		return { kind: "loss", reason: "malformed_frame" };
	}
	const expectedMac = createHmac("sha256", Buffer.from(capability, "base64url")).update(payloadBytes).digest();
	if (suppliedMac.byteLength !== expectedMac.byteLength || !timingSafeEqual(suppliedMac, expectedMac)) {
		return { kind: "loss", reason: "authentication_failed" };
	}
	let payload: unknown;
	try {
		payload = JSON.parse(payloadBytes.toString("utf8"));
	} catch {
		return { kind: "loss", reason: "invalid_payload" };
	}
	if (!payload || typeof payload !== "object") return { kind: "loss", reason: "invalid_payload" };
	const candidate = payload as Record<string, unknown>;
	if (
		candidate.version !== KERNEL_DIAGNOSTIC_BRIDGE_VERSION ||
		!Number.isSafeInteger(candidate.sequence) ||
		(candidate.sequence as number) < 1
	) {
		return { kind: "loss", reason: "invalid_payload" };
	}
	if (candidate.kind === "event") {
		const event = decodeEvent(candidate.event);
		return event
			? { kind: "event", sequence: candidate.sequence as number, event }
			: { kind: "loss", reason: "invalid_payload" };
	}
	if (candidate.kind === "drop" && isDropCounts(candidate.counts)) {
		return { kind: "drop", sequence: candidate.sequence as number, counts: candidate.counts };
	}
	return { kind: "loss", reason: "invalid_payload" };
}

export class KernelDiagnosticBridgeDecoder {
	private pending: Buffer[] = [];
	private pendingBytes = 0;
	private discardingOverflow = false;
	private lastSequence: number;
	private ended = false;

	constructor(private readonly options: KernelDiagnosticBridgeDecoderOptions) {
		this.lastSequence =
			Number.isSafeInteger(options.initialSequence) && (options.initialSequence ?? 0) >= 0
				? (options.initialSequence ?? 0)
				: 0;
	}

	push(value: Uint8Array): void {
		if (this.ended) return;
		const chunk = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
		let offset = 0;
		while (offset < chunk.byteLength) {
			const newline = chunk.indexOf(0x0a, offset);
			const end = newline === -1 ? chunk.byteLength : newline;
			this.append(chunk.subarray(offset, end));
			if (newline === -1) return;
			this.finishLine();
			offset = newline + 1;
		}
	}

	end(): void {
		if (this.ended) return;
		this.ended = true;
		if (this.pendingBytes > 0 || this.discardingOverflow) {
			this.options.onLoss({ reason: "trailing_partial_frame" });
		}
		this.pending = [];
		this.pendingBytes = 0;
		this.discardingOverflow = false;
	}

	private append(segment: Buffer): void {
		if (this.discardingOverflow || segment.byteLength === 0) return;
		if (this.pendingBytes + segment.byteLength > KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES) {
			this.pending = [];
			this.pendingBytes = 0;
			this.discardingOverflow = true;
			this.options.onLoss({ reason: "line_overflow" });
			return;
		}
		this.pending.push(segment);
		this.pendingBytes += segment.byteLength;
	}

	private finishLine(): void {
		if (this.discardingOverflow) {
			this.discardingOverflow = false;
			this.pending = [];
			this.pendingBytes = 0;
			return;
		}
		const line = Buffer.concat(this.pending, this.pendingBytes);
		this.pending = [];
		this.pendingBytes = 0;
		const decoded = decodeLine(line, this.options.capability);
		if (decoded.kind === "loss") {
			this.options.onLoss({ reason: decoded.reason });
			return;
		}
		const expectedSequence = this.lastSequence + 1;
		if (decoded.sequence <= this.lastSequence) {
			this.options.onLoss({
				reason: "sequence_replay",
				expectedSequence,
				observedSequence: decoded.sequence,
			});
			return;
		}
		if (decoded.sequence > expectedSequence) {
			this.options.onLoss({
				reason: "sequence_gap",
				droppedFrames: decoded.sequence - expectedSequence,
				expectedSequence,
				observedSequence: decoded.sequence,
			});
		}
		this.lastSequence = decoded.sequence;
		this.options.onSequence?.(decoded.sequence);
		if (decoded.kind === "event") this.options.onEvent(decoded.event);
		else this.options.onDrop(decoded.counts);
	}
}

export class KernelDiagnosticBridgeWriter {
	private readonly pending: QueuedKernelDiagnostic[] = [];
	private readonly drops = emptyDropCounts();
	private pendingBytes = 0;
	private nextSequence = 1;
	private active?: ActiveWrite;
	private closed = false;
	private closing = false;
	private lastCompletedKind?: "event" | "drop";

	constructor(
		private readonly stream: Writable,
		private readonly capability: string,
		private readonly maxPendingBytes = KERNEL_DIAGNOSTIC_BRIDGE_MAX_PENDING_BYTES,
	) {
		if (!isKernelDiagnosticBridgeCapability(capability)) {
			this.closed = true;
			try {
				stream.destroy();
			} catch {
				// Invalid diagnostic setup cannot affect worker startup.
			}
			return;
		}
		stream.on("error", this.onTransportError);
		stream.on("close", this.onTransportClose);
		const unref = (stream as Writable & { unref?: () => void }).unref;
		if (typeof unref === "function") unref.call(stream);
	}

	get bufferedBytes(): number {
		return this.pendingBytes;
	}

	get dropCounts(): KernelDiagnosticBridgeDropCounts {
		return copyDropCounts(this.drops);
	}

	publish(event: KernelDiagnosticEvent): void {
		if (this.closed || this.closing) {
			this.drops.shutdown += 1;
			this.pump();
			return;
		}
		let serialized: Record<string, unknown>;
		try {
			serialized = serializeEvent(event);
		} catch {
			this.drops.encodeFailure += 1;
			this.pump();
			return;
		}
		const estimatedBytes = Buffer.byteLength(
			JSON.stringify({
				version: KERNEL_DIAGNOSTIC_BRIDGE_VERSION,
				kind: "event",
				sequence: Number.MAX_SAFE_INTEGER,
				event: serialized,
			}),
		);
		if (estimatedBytes > KERNEL_DIAGNOSTIC_BRIDGE_MAX_PAYLOAD_BYTES) {
			this.drops.oversize += 1;
			this.pump();
			return;
		}
		const critical = event.type === "kernel_channel_fault" || event.type === "kernel_unexpected_exit";
		if (!this.reserve(estimatedBytes, critical)) {
			if (critical) this.drops.criticalOverflow += 1;
			else this.drops.queueOverflow += 1;
			this.pump();
			return;
		}
		this.pending.push({ event: serialized, critical, estimatedBytes });
		this.pendingBytes += estimatedBytes;
		this.pump();
	}

	close(): void {
		if (this.closed || this.closing) return;
		this.closing = true;
		for (let index = 0; index < this.pending.length; ) {
			const candidate = this.pending[index];
			if (candidate.critical) {
				index += 1;
				continue;
			}
			this.pending.splice(index, 1);
			this.pendingBytes -= candidate.estimatedBytes;
			this.drops.shutdown += 1;
		}
		this.pump();
	}

	private reserve(bytes: number, critical: boolean): boolean {
		if (bytes > this.maxPendingBytes) return false;
		if (this.pendingBytes + bytes <= this.maxPendingBytes) return true;
		if (!critical) return false;
		for (let index = 0; index < this.pending.length && this.pendingBytes + bytes > this.maxPendingBytes; ) {
			const candidate = this.pending[index];
			if (candidate.critical) {
				index += 1;
				continue;
			}
			this.pending.splice(index, 1);
			this.pendingBytes -= candidate.estimatedBytes;
			this.drops.evictedNormal += 1;
		}
		return this.pendingBytes + bytes <= this.maxPendingBytes;
	}

	private pump(): void {
		if (this.active || this.closed) return;
		let frame: Buffer | undefined;
		let active: ActiveWrite;
		const dropsPending = hasDrops(this.drops);
		const criticalIndex = this.pending.findIndex((candidate) => candidate.critical);
		const sendDrop = dropsPending && !(this.lastCompletedKind === "drop" && criticalIndex !== -1);
		if (sendDrop) {
			const dropSnapshot = copyDropCounts(this.drops);
			frame = encodePayload(
				{
					version: KERNEL_DIAGNOSTIC_BRIDGE_VERSION,
					kind: "drop",
					sequence: this.nextSequence,
					counts: dropSnapshot,
				},
				this.capability,
			);
			active = { kind: "drop", dropSnapshot };
		} else {
			const nextIndex = dropsPending && criticalIndex !== -1 ? criticalIndex : 0;
			const queued = this.pending[nextIndex];
			if (!queued) {
				if (this.closing) this.finishClose();
				return;
			}
			this.pending.splice(nextIndex, 1);
			this.pendingBytes -= queued.estimatedBytes;
			frame = encodePayload(
				{
					version: KERNEL_DIAGNOSTIC_BRIDGE_VERSION,
					kind: "event",
					sequence: this.nextSequence,
					event: queued.event,
				},
				this.capability,
			);
			active = { kind: "event" };
		}
		if (!frame) {
			this.drops.encodeFailure += 1;
			if (active.kind === "drop") {
				this.failTransport();
				return;
			}
			setImmediate(() => this.pump());
			return;
		}
		this.nextSequence += 1;
		this.active = active;
		try {
			this.stream.write(frame, (error?: Error | null) => this.finishWrite(error ?? undefined));
		} catch {
			this.finishWrite(new Error("Kernel diagnostic bridge write failed"));
		}
	}

	private finishWrite(error?: Error): void {
		const active = this.active;
		if (!active) return;
		if (error) {
			this.failTransport();
			return;
		}
		this.active = undefined;
		if (active.kind === "drop" && active.dropSnapshot) subtractDropCounts(this.drops, active.dropSnapshot);
		this.lastCompletedKind = active.kind;
		this.pump();
	}

	private readonly onTransportError = (): void => {
		this.failTransport();
	};

	private readonly onTransportClose = (): void => {
		this.failTransport();
	};

	private failTransport(): void {
		if (this.closed) return;
		if (this.active) {
			this.drops.transportError += 1;
			this.active = undefined;
		}
		if (this.pending.length > 0) {
			this.drops.transportError += this.pending.length;
			this.pending.length = 0;
			this.pendingBytes = 0;
		}
		this.closed = true;
	}

	private finishClose(): void {
		if (this.closed) return;
		this.closed = true;
		try {
			this.stream.end();
		} catch {
			// Diagnostics cannot participate in product shutdown.
		}
	}
}

interface ReplayEntry {
	sequence: number;
	frame: Buffer;
	critical: boolean;
	kind: "event" | "drop";
	dropSnapshot?: KernelDiagnosticBridgeDropCounts;
}

export interface ReconnectableKernelDiagnosticBridgeWriterOptions {
	maxReplayBytes?: number;
}

export type KernelDiagnosticBridgeHandoffMode = "launch_handoff" | "reconnect";

export interface PreparedKernelDiagnosticBridgeHandoff {
	afterSequence: number;
	latestSequence: number;
	oldestReplaySequence?: number;
	commit(stream: Writable): void;
	abort(): void;
}

/**
 * A worker-owned diagnostic stream with bounded in-memory replay. Replacing the
 * transport never changes its sequence space and never touches product-channel
 * flow control.
 */
export class ReconnectableKernelDiagnosticBridgeWriter {
	private readonly entries: ReplayEntry[] = [];
	private readonly drops = emptyDropCounts();
	private readonly maxReplayBytes: number;
	private replayBytes = 0;
	private nextSequence = 1;
	private stream?: Writable;
	private streamEpoch = 0;
	private streamListeners?: { error: () => void; close: () => void };
	private outbound: ReplayEntry[] = [];
	private active?: { entry: ReplayEntry; epoch: number };
	private outstandingDrop?: ReplayEntry;
	private closed = false;
	private closing = false;
	private lastDeliveredSequence = 0;
	private lastDeliveredKind?: "event" | "drop";
	private handoffPending = false;
	private readonly activeWaiters: Array<() => void> = [];
	readonly whenClosed: Promise<void>;
	private resolveClosed!: () => void;

	constructor(
		private readonly capability: string,
		options: ReconnectableKernelDiagnosticBridgeWriterOptions = {},
	) {
		this.whenClosed = new Promise<void>((resolve) => {
			this.resolveClosed = resolve;
		});
		this.maxReplayBytes = Math.max(
			KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES,
			options.maxReplayBytes ?? KERNEL_DIAGNOSTIC_BRIDGE_MAX_REPLAY_BYTES,
		);
		if (!isKernelDiagnosticBridgeCapability(capability)) {
			this.closed = true;
			this.resolveClosed();
		}
	}

	get latestSequence(): number {
		return this.nextSequence - 1;
	}

	get oldestReplaySequence(): number | undefined {
		return this.entries[0]?.sequence;
	}

	get bufferedBytes(): number {
		return this.replayBytes;
	}

	get dropCounts(): KernelDiagnosticBridgeDropCounts {
		return copyDropCounts(this.drops);
	}

	publish(event: KernelDiagnosticEvent): void {
		if (this.closed || this.closing) {
			this.incrementDrop("shutdown");
			this.ensureDropEntry();
			return;
		}
		const sequence = this.nextSequence++;
		const frame = encodeKernelDiagnosticBridgeEvent(event, this.capability, sequence);
		if (!frame) {
			this.incrementDrop("encodeFailure");
			this.ensureDropEntry();
			return;
		}
		const critical = event.type === "kernel_channel_fault" || event.type === "kernel_unexpected_exit";
		const entry: ReplayEntry = { sequence, frame, critical, kind: "event" };
		if (!this.addEntry(entry)) {
			this.incrementDrop(critical ? "criticalOverflow" : "queueOverflow");
			this.ensureDropEntry();
			return;
		}
		if (this.stream) this.outbound.push(entry);
		this.ensureDropEntry();
		this.pump();
	}

	attach(stream: Writable, afterSequence = 0): void {
		if (this.closed || this.closing) {
			stream.destroy();
			return;
		}
		this.detachTransport(true);
		this.stream = stream;
		this.streamEpoch += 1;
		const epoch = this.streamEpoch;
		const onError = (): void => this.handleTransportFailure(epoch);
		const onClose = (): void => this.handleTransportFailure(epoch);
		this.streamListeners = { error: onError, close: onClose };
		stream.on("error", onError);
		stream.on("close", onClose);
		const unref = (stream as Writable & { unref?: () => void }).unref;
		if (typeof unref === "function") unref.call(stream);
		this.ensureDropEntry();
		this.outbound = this.entries.filter((entry) => entry.sequence > afterSequence);
		this.pump();
	}

	async prepareHandoff(
		mode: KernelDiagnosticBridgeHandoffMode,
		requestedAfterSequence: number,
	): Promise<PreparedKernelDiagnosticBridgeHandoff> {
		if (this.closed || this.closing || this.handoffPending) {
			throw new Error("Kernel diagnostic bridge cannot accept a transport handoff");
		}
		this.handoffPending = true;
		if (this.active) {
			let timeout: ReturnType<typeof setTimeout> | undefined;
			await Promise.race([
				new Promise<void>((resolve) => this.activeWaiters.push(resolve)),
				new Promise<void>((resolve) => {
					timeout = setTimeout(resolve, KERNEL_DIAGNOSTIC_BRIDGE_HANDOFF_DRAIN_TIMEOUT_MS);
					timeout.unref();
				}),
			]);
			if (timeout) clearTimeout(timeout);
			if (this.active) {
				const stalledStream = this.stream;
				this.handleTransportFailure(this.streamEpoch);
				try {
					stalledStream?.destroy();
				} catch {
					// Handoff continues on the independently authenticated transport.
				}
			}
		}
		const oldStream = this.stream;
		const listeners = this.streamListeners;
		const absorbHandoffError = (): void => {};
		this.stream = undefined;
		this.streamListeners = undefined;
		this.outbound = [];
		if (oldStream && listeners) {
			oldStream.off("error", listeners.error);
			oldStream.off("close", listeners.close);
		}
		// Keep the previous transport recoverable until the authenticated accept
		// frame has actually been written. A failed handshake can then resume the
		// exact sequence boundary instead of silently marooning fd6.
		oldStream?.on("error", absorbHandoffError);
		const requested = Number.isSafeInteger(requestedAfterSequence)
			? Math.max(0, Math.min(requestedAfterSequence, this.latestSequence))
			: 0;
		const afterSequence = mode === "launch_handoff" ? this.lastDeliveredSequence : requested;
		let settled = false;
		return {
			afterSequence,
			latestSequence: this.latestSequence,
			...(this.oldestReplaySequence !== undefined ? { oldestReplaySequence: this.oldestReplaySequence } : {}),
			commit: (stream) => {
				if (settled) {
					stream.destroy();
					return;
				}
				settled = true;
				if (oldStream) {
					oldStream.once("close", () => oldStream.off("error", absorbHandoffError));
					try {
						if (mode === "launch_handoff") oldStream.end();
						else oldStream.destroy();
					} catch {
						// The authenticated replacement remains independently usable.
					}
				}
				this.handoffPending = false;
				if (this.closing) {
					stream.destroy();
					this.finishClose();
					return;
				}
				this.attach(stream, afterSequence);
			},
			abort: () => {
				if (settled) return;
				settled = true;
				oldStream?.off("error", absorbHandoffError);
				this.handoffPending = false;
				if (this.closing) {
					try {
						oldStream?.end();
					} catch {
						oldStream?.destroy();
					}
					this.finishClose();
					return;
				}
				if (oldStream && !oldStream.destroyed) this.attach(oldStream, this.lastDeliveredSequence);
				else this.ensureDropEntry();
			},
		};
	}

	close(): void {
		if (this.closed || this.closing) return;
		this.closing = true;
		const pendingSequences = new Set(this.outbound.map((entry) => entry.sequence));
		for (const entry of [...this.outbound]) {
			if (entry.critical || this.active?.entry === entry) continue;
			this.removeEntry(entry, false);
			pendingSequences.delete(entry.sequence);
			this.incrementDrop("shutdown");
		}
		this.outbound = this.outbound.filter(
			(entry) => entry.critical || this.active?.entry === entry || pendingSequences.has(entry.sequence),
		);
		this.ensureDropEntry();
		if (this.outstandingDrop && !this.outbound.includes(this.outstandingDrop)) {
			this.outbound.unshift(this.outstandingDrop);
		}
		if (!this.stream && !this.handoffPending) {
			this.finishClose();
			return;
		}
		this.pump();
	}

	private incrementDrop(key: keyof KernelDiagnosticBridgeDropCounts, amount = 1): void {
		this.drops[key] = Math.min(Number.MAX_SAFE_INTEGER, this.drops[key] + amount);
	}

	private addEntry(entry: ReplayEntry): boolean {
		if (entry.frame.byteLength > this.maxReplayBytes) return false;
		while (this.replayBytes + entry.frame.byteLength > this.maxReplayBytes) {
			let evictionIndex = this.entries.findIndex(
				(candidate) => !candidate.critical && candidate !== this.active?.entry,
			);
			if (evictionIndex === -1 && entry.critical) {
				evictionIndex = this.entries.findIndex((candidate) => candidate !== this.active?.entry);
			}
			if (evictionIndex === -1) return false;
			const evicted = this.entries[evictionIndex];
			this.removeEntry(evicted, true);
		}
		this.entries.push(entry);
		this.replayBytes += entry.frame.byteLength;
		return true;
	}

	private removeEntry(entry: ReplayEntry, accountEviction: boolean): void {
		const index = this.entries.indexOf(entry);
		if (index !== -1) {
			this.entries.splice(index, 1);
			this.replayBytes -= entry.frame.byteLength;
		}
		this.outbound = this.outbound.filter((candidate) => candidate !== entry);
		if (this.outstandingDrop === entry) {
			this.outstandingDrop = undefined;
			if (entry.dropSnapshot) {
				for (const key of Object.keys(entry.dropSnapshot) as Array<keyof KernelDiagnosticBridgeDropCounts>) {
					this.incrementDrop(key, entry.dropSnapshot[key]);
				}
			}
		}
		if (accountEviction && entry.kind === "event") {
			this.incrementDrop(entry.critical ? "criticalOverflow" : "evictedNormal");
		}
	}

	private ensureDropEntry(): void {
		if (this.outstandingDrop || !hasDrops(this.drops) || this.closed) return;
		const snapshot = copyDropCounts(this.drops);
		const sequence = this.nextSequence++;
		const frame = encodeKernelDiagnosticBridgeDrop(snapshot, this.capability, sequence);
		if (!frame) return;
		const entry: ReplayEntry = {
			sequence,
			frame,
			critical: true,
			kind: "drop",
			dropSnapshot: snapshot,
		};
		if (!this.addEntry(entry)) return;
		this.outstandingDrop = entry;
		subtractDropCounts(this.drops, snapshot);
		if (this.stream) this.outbound.push(entry);
	}

	private pump(): void {
		if (this.active || !this.stream || this.closed || this.handoffPending) return;
		const criticalEventIndex = this.outbound.findIndex(
			(candidate) => candidate.critical && candidate.kind === "event",
		);
		const dropIndex = this.outbound.findIndex((candidate) => candidate.kind === "drop");
		const nextIndex =
			dropIndex !== -1 && !(this.lastDeliveredKind === "drop" && criticalEventIndex !== -1)
				? dropIndex
				: criticalEventIndex !== -1
					? criticalEventIndex
					: 0;
		const [entry] = this.outbound.splice(nextIndex, 1);
		if (!entry) {
			if (this.closing) this.finishClose();
			return;
		}
		const epoch = this.streamEpoch;
		this.active = { entry, epoch };
		try {
			this.stream.write(entry.frame, (error?: Error | null) => {
				if (this.active?.entry !== entry || this.active.epoch !== epoch) return;
				if (error) {
					this.handleTransportFailure(epoch);
					return;
				}
				this.active = undefined;
				this.lastDeliveredSequence = Math.max(this.lastDeliveredSequence, entry.sequence);
				this.lastDeliveredKind = entry.kind;
				this.resolveActiveWaiters();
				if (this.outstandingDrop === entry) {
					this.outstandingDrop = undefined;
				}
				// Space may only become available after a maximal active frame
				// completes; retry canonical loss materialization after every write.
				this.ensureDropEntry();
				this.pump();
			});
		} catch {
			this.handleTransportFailure(epoch);
		}
	}

	private handleTransportFailure(epoch: number): void {
		if (epoch !== this.streamEpoch || !this.stream) return;
		if (this.active) this.incrementDrop("transportError");
		this.active = undefined;
		this.resolveActiveWaiters();
		this.detachTransport(false);
		if (this.closing) {
			this.closed = true;
			this.resolveClosed();
			return;
		}
		this.ensureDropEntry();
	}

	private resolveActiveWaiters(): void {
		for (const resolve of this.activeWaiters.splice(0)) resolve();
	}

	private detachTransport(destroy: boolean): void {
		const stream = this.stream;
		const listeners = this.streamListeners;
		this.stream = undefined;
		this.streamListeners = undefined;
		this.active = undefined;
		this.outbound = [];
		if (!stream) return;
		if (listeners) {
			stream.off("error", listeners.error);
			stream.off("close", listeners.close);
		}
		if (destroy) {
			try {
				stream.destroy();
			} catch {
				// Replacing a diagnostic transport cannot affect worker lifecycle.
			}
		}
	}

	private finishClose(): void {
		if (this.closed) return;
		this.closed = true;
		const stream = this.stream;
		if (!stream) {
			this.resolveClosed();
			return;
		}
		let settled = false;
		const settle = (): void => {
			if (settled) return;
			settled = true;
			this.resolveClosed();
		};
		stream.once("finish", settle);
		stream.once("close", settle);
		stream.once("error", settle);
		try {
			stream.end();
		} catch {
			this.detachTransport(true);
			settle();
		}
	}
}

export interface ReconnectableKernelDiagnosticBridgeInstallation {
	writer: ReconnectableKernelDiagnosticBridgeWriter;
	close(): void;
}

export function installReconnectableKernelDiagnosticBridgeWriter(
	stream: Writable,
	capability: string,
): ReconnectableKernelDiagnosticBridgeInstallation {
	const writer = new ReconnectableKernelDiagnosticBridgeWriter(capability);
	writer.attach(stream);
	const unsubscribe = subscribeKernelDiagnostics((event) => writer.publish(event));
	return {
		writer,
		close: () => {
			unsubscribe();
			writer.close();
		},
	};
}

export function installKernelDiagnosticBridgeWriter(stream: Writable, capability: string): () => void {
	if (!isKernelDiagnosticBridgeCapability(capability)) {
		try {
			stream.destroy();
		} catch {
			// An invalid diagnostic capability cannot fail worker startup.
		}
		return () => {};
	}
	const writer = new KernelDiagnosticBridgeWriter(stream, capability);
	const unsubscribe = subscribeKernelDiagnostics((event) => writer.publish(event));
	return () => {
		unsubscribe();
		writer.close();
	};
}
