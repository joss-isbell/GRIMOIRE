import { randomBytes } from "node:crypto";
import { Writable } from "node:stream";
import { setImmediate as settle } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import {
	KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES,
	KERNEL_DIAGNOSTIC_BRIDGE_MAX_REPLAY_BYTES,
	KernelDiagnosticBridgeDecoder,
	type KernelDiagnosticBridgeDropCounts,
	type KernelDiagnosticBridgeLoss,
	ReconnectableKernelDiagnosticBridgeWriter,
} from "../src/core/kernel/diagnostic-bridge.js";
import type { KernelDiagnosticEvent } from "../src/core/kernel/diagnostics.js";

function observation(index: number, critical: boolean): KernelDiagnosticEvent {
	const identity = {
		kernelInstanceId: "pressure-kernel",
		kernelPid: 42,
		kernelProcessStartId: "proc:100",
		launchMode: "direct" as const,
		requestMsgId: `request-${index}`,
	};
	return critical
		? {
				...identity,
				type: "kernel_protocol_observation",
				ownerPid: 41,
				ownerProcessStartId: "proc:99",
				kernelGeneration: 1,
				observedAt: "2026-09-08T00:00:00.000Z",
				monotonicNs: String(1_000_000 + index),
				crashPhase: "executing",
				observation: "execution_completed",
				status: "ok",
				completionSource: "iopub_idle",
				durationMs: 40,
			}
		: { ...identity, type: "kernel_execute_started", phase: "executing" };
}

class ObservingWritable extends Writable {
	readonly events: KernelDiagnosticEvent[] = [];
	readonly drops: KernelDiagnosticBridgeDropCounts[] = [];
	readonly losses: KernelDiagnosticBridgeLoss[] = [];
	readonly sequences: number[] = [];
	bytes = 0;
	private readonly decoder: KernelDiagnosticBridgeDecoder;

	constructor(secret: string, initialSequence = 0) {
		super({ highWaterMark: 1 });
		this.decoder = new KernelDiagnosticBridgeDecoder({
			capability: secret,
			initialSequence,
			onEvent: (event) => this.events.push(event),
			onDrop: (drop) => this.drops.push(drop),
			onLoss: (loss) => this.losses.push(loss),
			onSequence: (sequence) => this.sequences.push(sequence),
		});
	}

	_write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
		this.bytes += chunk.length;
		// Exercise framing across reads instead of bypassing the decoder.
		this.decoder.push(chunk.subarray(0, 7));
		this.decoder.push(chunk.subarray(7));
		callback();
	}

	_final(callback: (error?: Error | null) => void): void {
		this.decoder.end();
		callback();
	}
}

async function publishHealthy(
	writer: ReconnectableKernelDiagnosticBridgeWriter,
	events: KernelDiagnosticEvent[],
	limit: number,
): Promise<void> {
	for (const event of events) {
		writer.publish(event);
		// Let each local write finish: this is retained history pressure, not a blocked sink.
		await settle();
		expect(writer.bufferedBytes).toBeLessThanOrEqual(limit);
	}
}

describe("reconnectable kernel diagnostic bridge pressure", () => {
	it.each([KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES, KERNEL_DIAGNOSTIC_BRIDGE_MAX_REPLAY_BYTES])(
		"keeps every healthy event after critical replay history fills %i bytes",
		async (limit) => {
			const secret = randomBytes(32).toString("base64url");
			const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret, { maxReplayBytes: limit });
			const stream = new ObservingWritable(secret);
			writer.attach(stream);
			const events = Array.from({ length: 3000 }, (_, index) => observation(index, index < 1200 || index % 2 === 0));
			try {
				await publishHealthy(writer, events, limit);
				expect(stream.bytes).toBeGreaterThan(limit * 3);
				expect({ received: stream.events.length, drops: stream.drops.length, gaps: stream.losses.length }).toEqual({
					received: events.length,
					drops: 0,
					gaps: 0,
				});
				expect(stream.events).toEqual(events);
				expect(stream.sequences).toEqual(events.map((_, index) => index + 1));
			} finally {
				writer.close();
				await writer.whenClosed;
			}
		},
	);

	it("reports expired replay through the reconnect cursor without fabricating a live drop", async () => {
		const secret = randomBytes(32).toString("base64url");
		const limit = KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES;
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret, { maxReplayBytes: limit });
		const original = new ObservingWritable(secret);
		writer.attach(original);
		const events = Array.from({ length: 200 }, (_, index) => observation(index, true));
		try {
			await publishHealthy(writer, events, limit);
			const handoff = await writer.prepareHandoff("reconnect", 0);
			expect(handoff.afterSequence).toBe(0);
			expect(handoff.oldestReplaySequence).toBeGreaterThan(1);
			const replay = new ObservingWritable(secret);
			handoff.commit(replay);
			await settle();
			expect(original.drops).toEqual([]);
			expect(original.losses).toEqual([]);
			expect(replay.drops).toEqual([]);
			expect(replay.losses).toEqual([
				{
					reason: "sequence_gap",
					expectedSequence: 1,
					observedSequence: handoff.oldestReplaySequence,
					droppedFrames: handoff.oldestReplaySequence! - 1,
				},
			]);
			expect(replay.events).toEqual(events.slice(handoff.oldestReplaySequence! - 1));
			const current = await writer.prepareHandoff("reconnect", writer.latestSequence);
			const caughtUp = new ObservingWritable(secret, current.afterSequence);
			current.commit(caughtUp);
			const next = observation(200, false);
			await publishHealthy(writer, [next], limit);
			expect(caughtUp.events).toEqual([next]);
			expect(caughtUp.losses).toEqual([]);
			expect(caughtUp.drops).toEqual([]);
		} finally {
			writer.close();
			await writer.whenClosed;
		}
	});

	it("retains explicit real overflow and truthful sequence gaps when no transport can deliver", async () => {
		const secret = randomBytes(32).toString("base64url");
		const limit = KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES;
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret, { maxReplayBytes: limit });
		const stream = new ObservingWritable(secret);
		try {
			for (let index = 0; index < 600; index++) writer.publish(observation(index, index % 2 === 0));
			expect(writer.bufferedBytes).toBeLessThanOrEqual(limit);
			writer.attach(stream);
			await settle();
			expect(stream.events.length).toBeLessThan(600);
			expect(stream.drops.some((drop) => drop.queueOverflow + drop.criticalOverflow + drop.evictedNormal > 0)).toBe(
				true,
			);
			expect(stream.losses.some((loss) => loss.reason === "sequence_gap")).toBe(true);
			expect(stream.losses.some((loss) => loss.reason === "sequence_replay")).toBe(false);
			const dropCount = stream.drops.length;
			const next = observation(600, false);
			await publishHealthy(writer, [next], limit);
			expect(stream.events.at(-1)).toEqual(next);
			expect(stream.drops).toHaveLength(dropCount);
		} finally {
			writer.close();
			await writer.whenClosed;
		}
	});
});
