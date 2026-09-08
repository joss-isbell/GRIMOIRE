import { createHmac, randomBytes } from "node:crypto";
import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import {
	encodeKernelDiagnosticBridgeEvent,
	isKernelDiagnosticBridgeCapability,
	KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES,
	KernelDiagnosticBridgeDecoder,
	type KernelDiagnosticBridgeDropCounts,
	type KernelDiagnosticBridgeLoss,
	KernelDiagnosticBridgeWriter,
	ReconnectableKernelDiagnosticBridgeWriter,
} from "../src/core/kernel/diagnostic-bridge.js";
import type { ForkServerDiagnosticEvent, KernelDiagnosticEvent } from "../src/core/kernel/diagnostics.js";

const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

function capability(): string {
	return randomBytes(32).toString("base64url");
}

function unexpectedExit(
	stderrTail = Buffer.from([0x00, 0xff, 0x41, 0x0a]),
): Extract<KernelDiagnosticEvent, { type: "kernel_unexpected_exit" }> {
	return {
		type: "kernel_unexpected_exit",
		sessionId: "session-worker-boundary",
		kernelInstanceId: "kernel-instance-1",
		kernelPid: 4242,
		kernelProcessStartId: "12345",
		launchMode: "direct",
		crashPhase: "executing",
		requestMsgId: "request-17",
		code: 137,
		signal: "SIGKILL",
		reason: "process_exit",
		stderrTail,
		stderrBytes: stderrTail.byteLength + 91,
		sourceTruncated: true,
	};
}

function lifecycleIntent(): Extract<KernelDiagnosticEvent, { type: "kernel_lifecycle_intent" }> {
	return {
		type: "kernel_lifecycle_intent",
		sessionId: "session-lifecycle",
		kernelInstanceId: "lifecycle-kernel",
		kernelPid: 4242,
		kernelProcessStartId: "proc:kernel-start",
		launchMode: "direct",
		ownerPid: 4000,
		ownerProcessStartId: "proc:owner-start",
		kernelGeneration: 3,
		observedAt: "2026-09-08T00:00:00.000Z",
		monotonicNs: "12345678901234567",
		crashPhase: "executing",
		requestMsgId: "execution-request",
		operation: "shutdown",
		caller: "KernelManager.shutdown",
		reason: "requested",
		callerStack: ["at observedCaller (/test/caller.ts:12:4)"],
	};
}

function processExitObserved(): Extract<KernelDiagnosticEvent, { type: "kernel_process_exit_observed" }> {
	const {
		operation: _operation,
		caller: _caller,
		reason: _reason,
		callerStack: _stack,
		...observation
	} = lifecycleIntent();
	return {
		...observation,
		type: "kernel_process_exit_observed",
		lifecycleState: "shutdown",
		code: null,
		signal: "SIGTERM",
	};
}

function forkserverLifecycle(phase: ForkServerDiagnosticEvent["phase"]): ForkServerDiagnosticEvent {
	return {
		type: "forkserver_lifecycle",
		forkserverInstanceId: "forkserver-instance",
		forkserverPid: 4243,
		forkserverProcessStartId: "proc:forkserver-start",
		ownerPid: 4000,
		ownerProcessStartId: "proc:owner-start",
		observedAt: "2026-09-08T00:00:00.000Z",
		monotonicNs: "12345678901234567",
		phase,
		reason: "control_closed",
		connectionId: "connection-1",
		code: null,
		signal: "SIGTERM",
	};
}

class ControlledWritable extends Writable {
	readonly writes: Buffer[] = [];
	private readonly releases: Array<(error?: Error | null) => void> = [];

	_write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
		this.writes.push(Buffer.from(chunk));
		this.releases.push(callback);
	}

	get blockedWrites(): number {
		return this.releases.length;
	}

	release(error?: Error): void {
		const callback = this.releases.shift();
		if (!callback) throw new Error("No controlled bridge write is pending");
		callback(error);
	}
}

function decode(
	value: Uint8Array,
	secret: string,
): {
	events: KernelDiagnosticEvent[];
	drops: KernelDiagnosticBridgeDropCounts[];
	losses: KernelDiagnosticBridgeLoss[];
} {
	const events: KernelDiagnosticEvent[] = [];
	const drops: KernelDiagnosticBridgeDropCounts[] = [];
	const losses: KernelDiagnosticBridgeLoss[] = [];
	const decoder = new KernelDiagnosticBridgeDecoder({
		capability: secret,
		onEvent: (event) => events.push(event),
		onDrop: (counts) => drops.push(counts),
		onLoss: (loss) => losses.push(loss),
	});
	decoder.push(value);
	decoder.end();
	return { events, drops, losses };
}

function signedPayload(payload: unknown, secret: string): Buffer {
	const payloadBytes = Buffer.from(JSON.stringify(payload));
	const mac = createHmac("sha256", Buffer.from(secret, "base64url")).update(payloadBytes).digest("base64url");
	return Buffer.from(`GKD1.${payloadBytes.toString("base64url")}.${mac}\n`, "ascii");
}

describe("kernel diagnostic worker bridge", () => {
	it.each([
		"peer_rejected",
		"peer_authenticated",
		"control_closed",
		"control_error",
		"process_error",
		"process_exit",
		"shutdown_requested",
		"disposed",
	] as const)("round-trips shared forkserver %s evidence without claiming a kernel identity", (phase) => {
		const secret = capability();
		const event = forkserverLifecycle(phase);
		const encoded = encodeKernelDiagnosticBridgeEvent(event, secret)!;
		expect(decode(encoded, secret)).toEqual({ events: [event], losses: [], drops: [] });
		const extra = signedPayload(
			{
				version: 1,
				kind: "event",
				sequence: 1,
				event: { ...event, kernelInstanceId: "invented", capability: "must-not-survive" },
			},
			secret,
		);
		expect(decode(extra, secret).events).toEqual([event]);
	});

	it("rejects invalid shared forkserver fields with explicit loss", () => {
		const secret = capability();
		for (const invalid of [
			{ phase: "false_phase" },
			{ forkserverPid: -1 },
			{ forkserverInstanceId: "" },
			{ code: 0.5 },
			{ signal: 9 },
		]) {
			const result = decode(
				signedPayload(
					{
						version: 1,
						kind: "event",
						sequence: 1,
						event: { ...forkserverLifecycle("process_exit"), ...invalid },
					},
					secret,
				),
				secret,
			);
			expect(result.events).toEqual([]);
			expect(result.losses).toEqual([{ reason: "invalid_payload" }]);
		}
	});

	it("retains forkserver close, shutdown intent and actual exit during bridge close", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret);
		writer.attach(stream);
		const expected = [
			forkserverLifecycle("control_closed"),
			forkserverLifecycle("shutdown_requested"),
			forkserverLifecycle("process_exit"),
		];
		for (const event of expected) writer.publish(event);
		writer.close();
		while (stream.blockedWrites > 0) {
			stream.release();
			await settle();
		}
		await writer.whenClosed;
		expect(decode(Buffer.concat(stream.writes), secret)).toEqual({ events: expected, losses: [], drops: [] });
	});
	it("preserves the original observer namespace through the real writer and decoder", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret);
		writer.attach(stream);
		const expected = {
			...unexpectedExit(),
			stderrCaptureStatus: "unknown" as const,
			observerPid: 88,
			observerProcessStartId: "12345678901234567890",
			observerPidNamespace: "pid:[4026532290]",
			observerBoottimeOffsetNs: "-1000000000",
		};
		writer.publish(expected);
		writer.close();
		while (stream.blockedWrites) {
			stream.release();
			await settle();
		}
		await writer.whenClosed;
		expect(decode(Buffer.concat(stream.writes), secret)).toEqual({ events: [expected], losses: [], drops: [] });
	});
	it.each([
		{ observerPid: -1 },
		{ observerProcessStartId: "1".repeat(21) },
		{ observerPidNamespace: "different namespace" },
		{ observerBoottimeOffsetNs: "NaN" },
	])("rejects invalid observer metadata instead of truncating its identity %j", (invalid) => {
		const secret = capability();
		expect(() => encodeKernelDiagnosticBridgeEvent({ ...unexpectedExit(), ...invalid }, secret)).toThrow(
			/invalid_diagnostic_observer_identity/,
		);
	});
	it.each([lifecycleIntent(), processExitObserved()])(
		"round-trips every causal $type field without unknown payloads",
		(event) => {
			const secret = capability();
			const extra = { ...event, secretPayload: "must-not-be-serialized" };
			const encoded = encodeKernelDiagnosticBridgeEvent(extra, secret)!;
			expect(Buffer.from(encoded.toString().split(".")[1], "base64url").toString()).not.toContain(
				"must-not-be-serialized",
			);
			expect(decode(encoded, secret)).toEqual({ events: [event], drops: [], losses: [] });
			const signedExtra = signedPayload({ version: 1, kind: "event", sequence: 1, event: extra }, secret);
			expect(decode(signedExtra, secret).events).toEqual([event]);
		},
	);

	it("rejects malformed causal identity, clock, operation and stack fields with explicit loss", () => {
		const secret = capability();
		for (const invalid of [
			{ ownerPid: 0 },
			{ ownerProcessStartId: 99 },
			{ kernelGeneration: -1 },
			{ observedAt: "not-a-date" },
			{ monotonicNs: "1e6" },
			{ operation: "restart_everything" },
			{ caller: "" },
			{ reason: "" },
			{ callerStack: [123] },
			{ callerStack: Array(9).fill("at caller") },
		]) {
			const result = decode(
				signedPayload(
					{ version: 1, kind: "event", sequence: 1, event: { ...lifecycleIntent(), ...invalid } },
					secret,
				),
				secret,
			);
			expect(result.events).toEqual([]);
			expect(result.losses).toEqual([{ reason: "invalid_payload" }]);
		}
		const future = decode(
			signedPayload(
				{ version: 1, kind: "event", sequence: 1, event: { ...lifecycleIntent(), type: "kernel_future_event" } },
				secret,
			),
			secret,
		);
		expect(future.events).toEqual([]);
		expect(future.losses).toEqual([{ reason: "invalid_payload" }]);
	});

	it("bounds caller locations while retaining causal fields", () => {
		const secret = capability();
		const event = lifecycleIntent();
		event.callerStack = Array(20).fill("漢".repeat(1024));
		const result = decode(encodeKernelDiagnosticBridgeEvent(event, secret)!, secret);
		expect(result.losses).toEqual([]);
		const received = result.events[0];
		if (received.type !== "kernel_lifecycle_intent") throw new Error("missing lifecycle intent");
		expect(received.callerStack).toHaveLength(8);
		for (const frame of received.callerStack!) expect(Buffer.byteLength(frame)).toBeLessThanOrEqual(512);
	});

	it("preserves lifecycle intent and observed exit through queue pressure and close", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new KernelDiagnosticBridgeWriter(stream, secret, 1800);
		const normal: KernelDiagnosticEvent = {
			type: "kernel_ready",
			kernelInstanceId: "normal",
			kernelPid: 1,
			launchMode: "direct",
			phase: "idle",
		};
		writer.publish(normal);
		for (let i = 0; i < 40; i++) writer.publish(normal);
		writer.publish(lifecycleIntent());
		writer.publish(processExitObserved());
		expect(writer.bufferedBytes).toBeLessThanOrEqual(1800);
		writer.close();
		while (stream.blockedWrites > 0) {
			stream.release();
			await settle();
		}
		const result = decode(Buffer.concat(stream.writes), secret);
		expect(result.losses).toEqual([]);
		expect(result.events).toContainEqual(lifecycleIntent());
		expect(result.events).toContainEqual(processExitObserved());
		expect(result.drops.some((drop) => drop.evictedNormal > 0)).toBe(true);
	});

	it("retains lifecycle intent and observed exit in reconnect replay through close", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret);
		writer.attach(stream);
		writer.publish(lifecycleIntent());
		writer.publish(processExitObserved());
		writer.close();
		while (stream.blockedWrites > 0) {
			stream.release();
			await settle();
		}
		await writer.whenClosed;
		expect(decode(Buffer.concat(stream.writes), secret)).toEqual({
			events: [lifecycleIntent(), processExitObserved()],
			losses: [],
			drops: [],
		});
	});

	it("does not send later loss frames ahead of retained causal events during reconnect close", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret, {
			maxReplayBytes: KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES,
		});
		writer.attach(stream);
		writer.publish({
			type: "kernel_ready",
			kernelInstanceId: "active-normal",
			kernelPid: 1,
			launchMode: "direct",
			phase: "idle",
		});
		writer.publish(lifecycleIntent());
		writer.publish(processExitObserved());
		writer.publish({
			type: "kernel_ready",
			kernelInstanceId: "queued-normal",
			kernelPid: 1,
			launchMode: "direct",
			phase: "idle",
		});
		writer.close();
		while (stream.blockedWrites > 0) {
			stream.release();
			await settle();
		}
		await writer.whenClosed;
		const result = decode(Buffer.concat(stream.writes), secret);
		expect(result.events).toContainEqual(lifecycleIntent());
		expect(result.events).toContainEqual(processExitObserved());
		expect(result.losses.some((loss) => loss.reason === "sequence_replay")).toBe(false);
		expect(result.drops).toEqual([expect.objectContaining({ shutdown: 1 })]);
	});
	it("marks legacy capture availability unknown and rejects an invalid status", () => {
		const secret = capability();
		const legacy = { ...unexpectedExit(), stderrTail: undefined };
		const envelope = (event: unknown) => ({ version: 1, kind: "event", sequence: 1, event });
		const legacyEvent = decode(signedPayload(envelope(legacy), secret), secret).events[0];
		expect(legacyEvent).toMatchObject({
			stderrCaptureStatus: "unknown",
		});
		expect(legacyEvent).not.toHaveProperty("stderrCaptureComplete");
		const invalid = decode(
			signedPayload(envelope({ ...legacy, stderrCaptureStatus: "definitely_empty" }), secret),
			secret,
		);
		expect(invalid.events).toEqual([]);
		expect(invalid.losses).toMatchObject([{ reason: "invalid_payload" }]);
	});

	it("round-trips optional stderr drain completion and rejects invalid completion values", () => {
		const secret = capability();
		for (const stderrCaptureComplete of [true, false]) {
			const event = { ...unexpectedExit(), stderrCaptureComplete };
			const decoded = decode(encodeKernelDiagnosticBridgeEvent(event, secret)!, secret);
			expect(decoded.events[0]).toMatchObject({ stderrCaptureComplete });
		}
		const invalid = decode(
			signedPayload(
				{
					version: 1,
					kind: "event",
					sequence: 1,
					event: { ...unexpectedExit(), stderrCaptureComplete: "true" },
				},
				secret,
			),
			secret,
		);
		expect(invalid.events).toEqual([]);
		expect(invalid.losses).toMatchObject([{ reason: "invalid_payload" }]);
	});

	it("preserves unavailable fork stderr instead of reporting a known empty stream", () => {
		const secret = capability();
		const event = {
			...unexpectedExit(Buffer.alloc(0)),
			launchMode: "fork" as const,
			stderrBytes: 0,
			sourceTruncated: false,
			stderrCaptureStatus: "unavailable_fork" as const,
		};
		const frame = encodeKernelDiagnosticBridgeEvent(event, secret)!;
		expect(decode(frame, secret).events[0]).toMatchObject({
			stderrCaptureStatus: "unavailable_fork",
			stderrBytes: 0,
		});
	});

	it("authenticates a correlated crash and preserves the exact stderr tail across fragmented reads", () => {
		const secret = capability();
		const expected = unexpectedExit();
		const frame = encodeKernelDiagnosticBridgeEvent(expected, secret);
		expect(frame).toBeDefined();
		const events: KernelDiagnosticEvent[] = [];
		const losses: KernelDiagnosticBridgeLoss[] = [];
		const decoder = new KernelDiagnosticBridgeDecoder({
			capability: secret,
			onEvent: (event) => events.push(event),
			onDrop: () => undefined,
			onLoss: (loss) => losses.push(loss),
		});
		decoder.push(frame!.subarray(0, 7));
		decoder.push(frame!.subarray(7, frame!.byteLength - 3));
		decoder.push(frame!.subarray(frame!.byteLength - 3));
		decoder.end();

		expect(losses).toEqual([]);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			type: "kernel_unexpected_exit",
			sessionId: "session-worker-boundary",
			kernelInstanceId: "kernel-instance-1",
			kernelPid: 4242,
			kernelProcessStartId: "12345",
			requestMsgId: "request-17",
			code: 137,
			signal: "SIGKILL",
		});
		if (events[0]?.type !== "kernel_unexpected_exit") throw new Error("Expected a crash diagnostic");
		expect(Buffer.from(events[0].stderrTail ?? [])).toEqual(Buffer.from([0x00, 0xff, 0x41, 0x0a]));
	});

	it("rejects tampering and invalid bounded payloads, then resynchronizes", () => {
		const secret = capability();
		const frame = encodeKernelDiagnosticBridgeEvent(unexpectedExit(), secret)!;
		const tampered = Buffer.from(frame);
		tampered[tampered.byteLength - 3] = tampered[tampered.byteLength - 3] === 0x41 ? 0x42 : 0x41;
		const invalidTail = signedPayload(
			{
				version: 1,
				kind: "event",
				sequence: 2,
				event: {
					type: "kernel_unexpected_exit",
					kernelInstanceId: "kernel-instance-1",
					kernelPid: 4242,
					launchMode: "direct",
					crashPhase: "idle",
					code: 1,
					signal: null,
					reason: "process_exit",
					stderrTailBase64: Buffer.alloc(16 * 1024 + 1).toString("base64"),
					stderrBytes: 16 * 1024 + 1,
					sourceTruncated: true,
				},
			},
			secret,
		);
		const valid = encodeKernelDiagnosticBridgeEvent(unexpectedExit(), secret, 3)!;
		const result = decode(
			Buffer.concat([
				tampered,
				invalidTail,
				Buffer.alloc(KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES + 1, 0x78),
				Buffer.from("\n"),
				valid,
			]),
			secret,
		);

		expect(result.events).toHaveLength(1);
		expect(result.losses.map((loss) => loss.reason)).toEqual([
			"authentication_failed",
			"invalid_payload",
			"line_overflow",
			"sequence_gap",
		]);
	});

	it("reports sequence gaps and rejects replayed frames", () => {
		const secret = capability();
		const first = encodeKernelDiagnosticBridgeEvent(unexpectedExit(), secret, 1)!;
		const third = encodeKernelDiagnosticBridgeEvent(unexpectedExit(), secret, 3)!;
		const replay = encodeKernelDiagnosticBridgeEvent(unexpectedExit(), secret, 1)!;
		const result = decode(Buffer.concat([first, third, replay]), secret);
		expect(result.events).toHaveLength(2);
		expect(result.losses).toEqual([
			{
				reason: "sequence_gap",
				droppedFrames: 1,
				expectedSequence: 2,
				observedSequence: 3,
			},
			{
				reason: "sequence_replay",
				expectedSequence: 4,
				observedSequence: 1,
			},
		]);
	});

	it("bounds queued memory, preserves critical crashes, and emits canonical drop counters", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new KernelDiagnosticBridgeWriter(stream, secret, 700);
		const normal: KernelDiagnosticEvent = {
			type: "kernel_execute_started",
			sessionId: "session-worker-boundary",
			kernelInstanceId: "kernel-instance-1",
			kernelPid: 4242,
			launchMode: "direct",
			phase: "executing",
			requestMsgId: "request-normal",
		};
		writer.publish(normal);
		for (let index = 0; index < 20; index += 1) {
			writer.publish({ ...normal, requestMsgId: `request-${index}` });
		}
		writer.publish(unexpectedExit());
		expect(writer.bufferedBytes).toBeLessThanOrEqual(700);
		expect(writer.dropCounts.queueOverflow + writer.dropCounts.evictedNormal).toBeGreaterThan(0);

		while (stream.blockedWrites > 0 || writer.bufferedBytes > 0) {
			if (stream.blockedWrites > 0) stream.release();
			await settle();
		}
		while (stream.blockedWrites > 0) {
			stream.release();
			await settle();
		}
		const result = decode(Buffer.concat(stream.writes), secret);
		expect(result.losses).toEqual([]);
		expect(result.drops).toHaveLength(1);
		expect(result.drops[0].queueOverflow + result.drops[0].evictedNormal).toBeGreaterThan(0);
		expect(result.events.some((event) => event.type === "kernel_unexpected_exit")).toBe(true);
		writer.close();
	});

	it("retains unreported loss after a transport error without throwing into the publisher", async () => {
		const stream = new ControlledWritable();
		const writer = new KernelDiagnosticBridgeWriter(stream, capability(), 4096);
		expect(() => writer.publish(unexpectedExit())).not.toThrow();
		stream.release(new Error("pipe closed"));
		await settle();
		expect(writer.dropCounts.transportError).toBe(1);
		expect(() => writer.publish(unexpectedExit())).not.toThrow();
		expect(writer.dropCounts.shutdown).toBeGreaterThan(0);
	});

	it("flushes canonical loss and queued critical diagnostics during graceful close", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new KernelDiagnosticBridgeWriter(stream, secret, 900);
		const normal: KernelDiagnosticEvent = {
			type: "kernel_execute_started",
			sessionId: "session-close",
			kernelInstanceId: "kernel-close",
			kernelPid: 77,
			launchMode: "direct",
			phase: "executing",
			requestMsgId: "request-normal",
		};
		writer.publish(normal);
		for (let index = 0; index < 12; index += 1) {
			writer.publish({ ...normal, requestMsgId: `queued-normal-${index}` });
		}
		writer.publish(unexpectedExit(Buffer.from("critical-tail")));
		writer.close();
		while (stream.blockedWrites > 0) {
			stream.release();
			await settle();
		}

		const result = decode(Buffer.concat(stream.writes), secret);
		expect(result.losses).toEqual([]);
		expect(result.drops).toHaveLength(1);
		expect(result.drops[0].shutdown + result.drops[0].queueOverflow).toBeGreaterThan(0);
		expect(result.events.some((event) => event.type === "kernel_unexpected_exit")).toBe(true);
	});

	it("schedules a queued critical diagnostic immediately after a drop frame under sustained loss", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new KernelDiagnosticBridgeWriter(stream, secret, 700);
		const normal: KernelDiagnosticEvent = {
			type: "kernel_execute_started",
			kernelInstanceId: "kernel-starvation",
			kernelPid: 88,
			launchMode: "direct",
			phase: "executing",
			requestMsgId: "active-normal",
		};
		writer.publish(normal);
		for (let index = 0; index < 20; index += 1) {
			writer.publish({ ...normal, requestMsgId: `overflow-${index}` });
		}
		writer.publish(unexpectedExit(Buffer.from("must-not-starve")));
		stream.release();
		await settle();
		for (let index = 0; index < 20; index += 1) {
			writer.publish({ ...normal, requestMsgId: `continued-overflow-${index}` });
		}
		stream.release();
		await settle();
		expect(stream.writes).toHaveLength(3);
		const firstThree = decode(Buffer.concat(stream.writes), secret);
		expect(firstThree.drops).toHaveLength(1);
		expect(firstThree.events.map((event) => event.type)).toContain("kernel_unexpected_exit");
		writer.close();
		while (stream.blockedWrites > 0) {
			stream.release();
			await settle();
		}
	});

	it("requires canonical base64url capabilities and frame fields", () => {
		const secret = capability();
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const lastIndex = alphabet.indexOf(secret.at(-1) ?? "");
		const nonCanonicalSecret = `${secret.slice(0, -1)}${alphabet[(lastIndex & ~3) + 1]}`;
		expect(Buffer.from(nonCanonicalSecret, "base64url")).toEqual(Buffer.from(secret, "base64url"));
		expect(isKernelDiagnosticBridgeCapability(secret)).toBe(true);
		expect(isKernelDiagnosticBridgeCapability(nonCanonicalSecret)).toBe(false);
		expect(encodeKernelDiagnosticBridgeEvent(unexpectedExit(), nonCanonicalSecret)).toBeUndefined();
		expect(decode(encodeKernelDiagnosticBridgeEvent(unexpectedExit(), secret)!, nonCanonicalSecret).losses).toEqual([
			{ reason: "authentication_failed" },
		]);

		const frame = encodeKernelDiagnosticBridgeEvent(unexpectedExit(), secret)!;
		const parts = frame.toString("ascii").trimEnd().split(".");
		const macLastIndex = alphabet.indexOf(parts[2].at(-1) ?? "");
		parts[2] = `${parts[2].slice(0, -1)}${alphabet[(macLastIndex & ~3) + 1]}`;
		const result = decode(Buffer.from(`${parts.join(".")}\n`, "ascii"), secret);
		expect(result.events).toEqual([]);
		expect(result.losses).toEqual([{ reason: "malformed_frame" }]);
	});

	it("finalizes a partial decoder exactly once", () => {
		const losses: KernelDiagnosticBridgeLoss[] = [];
		const decoder = new KernelDiagnosticBridgeDecoder({
			capability: capability(),
			onEvent: () => undefined,
			onDrop: () => undefined,
			onLoss: (loss) => losses.push(loss),
		});
		decoder.push(Buffer.from("partial"));
		decoder.end();
		decoder.end();
		expect(losses).toEqual([{ reason: "trailing_partial_frame" }]);
	});

	it("bounds reconnect replay and preserves sequence order through loss and a retained crash", async () => {
		const secret = capability();
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret, {
			maxReplayBytes: KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES,
		});
		const normal: KernelDiagnosticEvent = {
			type: "kernel_execute_started",
			kernelInstanceId: "replay-kernel",
			kernelPid: 9191,
			launchMode: "direct",
			phase: "executing",
			requestMsgId: "x".repeat(3000),
		};
		for (let index = 0; index < 100; index += 1) {
			writer.publish({ ...normal, requestMsgId: `${index}-${normal.requestMsgId}` });
		}
		writer.publish(unexpectedExit(Buffer.from("retained-critical")));
		expect(writer.bufferedBytes).toBeLessThanOrEqual(KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES);

		const stream = new ControlledWritable({ highWaterMark: 1 });
		writer.attach(stream);
		for (let attempt = 0; attempt < 200; attempt += 1) {
			if (stream.blockedWrites > 0) stream.release();
			await settle();
			if (stream.blockedWrites === 0) {
				await settle();
				if (stream.blockedWrites === 0) break;
			}
		}

		expect(stream.writes.length).toBeGreaterThanOrEqual(2);
		const firstTwo = decode(Buffer.concat(stream.writes.slice(0, 2)), secret);
		expect(firstTwo.losses.some((loss) => loss.reason === "sequence_gap")).toBe(true);
		expect(firstTwo.drops).toHaveLength(1);
		expect(firstTwo.drops[0].evictedNormal + firstTwo.drops[0].queueOverflow).toBeGreaterThan(0);
		const replay = decode(Buffer.concat(stream.writes), secret);
		expect(replay.events.some((event) => event.type === "kernel_unexpected_exit")).toBe(true);
		expect(replay.losses.some((loss) => loss.reason === "sequence_replay")).toBe(false);
		writer.close();
		await writer.whenClosed;
	});

	it("restores the previous transport at the exact sequence boundary when a handoff aborts", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret);
		writer.attach(stream);
		writer.publish(unexpectedExit(Buffer.from("before-handoff")));
		const preparing = writer.prepareHandoff("launch_handoff", 0);
		stream.release();
		const prepared = await preparing;
		expect(prepared.afterSequence).toBe(1);
		prepared.abort();
		writer.publish({
			type: "kernel_ready",
			kernelInstanceId: "after-aborted-handoff",
			kernelPid: 4242,
			launchMode: "direct",
			phase: "idle",
		});
		await settle();
		stream.release();
		await settle();

		const result = decode(Buffer.concat(stream.writes), secret);
		expect(result.losses).toEqual([]);
		expect(result.events.map((event) => event.type)).toEqual(["kernel_unexpected_exit", "kernel_ready"]);
		writer.close();
		await writer.whenClosed;
	});

	it("materializes retained drop counters after a maximal active frame completes", async () => {
		const secret = capability();
		const stream = new ControlledWritable({ highWaterMark: 1 });
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret, {
			maxReplayBytes: KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES,
		});
		writer.attach(stream);
		const stderrTail = Buffer.alloc(16 * 1024, 0xab);
		writer.publish(unexpectedExit(stderrTail));
		const internals = writer as unknown as { drops: KernelDiagnosticBridgeDropCounts };
		internals.drops.queueOverflow = 1;
		stream.release();
		await settle();
		expect(stream.blockedWrites).toBe(1);
		stream.release();
		await settle();

		const result = decode(Buffer.concat(stream.writes), secret);
		expect(result.losses).toEqual([]);
		expect(result.events).toHaveLength(1);
		if (result.events[0]?.type !== "kernel_unexpected_exit") throw new Error("Expected maximal crash");
		expect(result.events[0].stderrTail).toEqual(stderrTail);
		expect(result.drops).toEqual([expect.objectContaining({ queueOverflow: 1 })]);
		writer.close();
		await writer.whenClosed;
	});
});
