import { describe, expect, it, vi } from "vitest";
import {
	INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES,
	type IncidentRecorderEncodedFrame,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import {
	BoundedFrameEmitter,
	INCIDENT_RECORDER_EMITTER_CHUNK_BYTES,
	type IncidentRecorderAdmission,
} from "../src/modes/daemon/incident-recorder-writer.js";

const IDENTITY = {
	runId: "11111111-1111-4111-8111-111111111111",
	runToken: "22222222-2222-4222-8222-222222222222",
};
const TEST_MAXIMUM_BYTES = 256 * 1024;

type PendingWrite = {
	frames: readonly IncidentRecorderEncodedFrame[];
	complete: (error?: Error) => void;
};

function expectRejected(
	admission: IncidentRecorderAdmission,
	reason: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"],
): void {
	expect(admission).toEqual({ accepted: false, disposition: "rejected", reason });
}

async function waitFor(condition: () => boolean, message: string): Promise<void> {
	for (let turn = 0; turn < 200; turn += 1) {
		if (condition()) return;
		await new Promise<void>((resolve) => setTimeout(resolve, 1));
	}
	throw new Error(message);
}

async function yieldImmediateTurns(turns = 20): Promise<void> {
	for (let turn = 0; turn < turns; turn += 1) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

function frameType(write: PendingWrite): string {
	return write.frames[0]?.header.type ?? "missing";
}

describe("incident recorder producer survival", () => {
	it("rejects provable terminal, stopped, oversize, and capacity failures before durable owner validation", async () => {
		let admissionValidations = 0;
		const writes: PendingWrite[] = [];
		const emitter = new BoundedFrameEmitter(
			(frames, complete) => {
				writes.push({ frames, complete });
				complete();
			},
			TEST_MAXIMUM_BYTES,
			IDENTITY,
			() => true,
			() => {
				admissionValidations += 1;
				return true;
			},
		);

		expectRejected(
			emitter.emitBytes("test", "oversize", new Uint8Array(INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES + 1), {}),
			"occurrence_too_large",
		);
		expectRejected(emitter.emitBytes("test", "capacity", new Uint8Array(200 * 1024), {}), "queue_capacity");
		expect(admissionValidations).toBe(0);
		expect(writes).toHaveLength(0);

		expect(emitter.emitBytes("test", "admitted_after_rejections", Uint8Array.of(7), {})).toMatchObject({
			accepted: true,
		});
		expect(admissionValidations).toBe(1);
		await waitFor(() => writes.length >= 1, "admitted occurrence was not framed");
		expect(writes[0].frames.map((frame) => frame.header.producerSequence)).toEqual([1n]);

		const terminal = emitter.emitControl("fixture_terminal", {}, true);
		expect(terminal).toMatchObject({ accepted: true });
		const validationsAfterTerminal = admissionValidations;
		expectRejected(emitter.emitDerived("test", "after_terminal", {}), "terminal_reserved");
		expect(admissionValidations).toBe(validationsAfterTerminal);

		const stoppingWrites: PendingWrite[] = [];
		let stoppingValidations = 0;
		const stoppingEmitter = new BoundedFrameEmitter(
			(frames, complete) => {
				stoppingWrites.push({ frames, complete });
				complete();
			},
			TEST_MAXIMUM_BYTES,
			IDENTITY,
			() => true,
			() => {
				stoppingValidations += 1;
				return true;
			},
		);
		await stoppingEmitter.stop();
		expect(stoppingWrites.map(frameType)).toEqual(["capture_channel_terminal"]);
		const validationsAfterStop = stoppingValidations;
		expectRejected(stoppingEmitter.emitDerived("test", "after_stop", {}), "stopped");
		expect(stoppingValidations).toBe(validationsAfterStop);
	});

	it("validates every otherwise admissible occurrence and disables an invalid owner before framing", async () => {
		const writes: PendingWrite[] = [];
		let admissionValidations = 0;
		let ownerValid = true;
		const emitter = new BoundedFrameEmitter(
			(frames, complete) => {
				writes.push({ frames, complete });
				complete();
			},
			TEST_MAXIMUM_BYTES,
			IDENTITY,
			() => true,
			() => {
				admissionValidations += 1;
				return ownerValid;
			},
		);

		expect(emitter.emitDerived("test", "first", {})).toMatchObject({ accepted: true });
		expect(emitter.emitBytes("test", "second", Uint8Array.of(1, 2, 3), {})).toMatchObject({ accepted: true });
		expect(admissionValidations).toBe(2);
		await waitFor(() => writes.length === 2, "admitted occurrences were not framed");
		expect(writes.map(frameType)).toEqual(["first", "second"]);

		ownerValid = false;
		expectRejected(emitter.emitDerived("test", "invalid_owner", {}), "stopped");
		expect(admissionValidations).toBe(3);
		expectRejected(emitter.emitDerived("test", "disabled_owner", {}), "stopped");
		expect(admissionValidations).toBe(3);
		expect(writes.map(frameType)).toEqual(["first", "second"]);
	});

	it.each([
		{ callbackOutcome: "success", callbackError: undefined, finalRecords: 4, finalBytes: 204_817 },
		{
			callbackOutcome: "failure",
			callbackError: new Error("fixture late write failure"),
			finalRecords: 5,
			finalBytes: 204_828,
		},
	])(
		"accounts an invalid-owner tail once and reconciles the uncertain active write after late $callbackOutcome",
		async ({ callbackError, finalRecords, finalBytes }) => {
			const writes: PendingWrite[] = [];
			let admissionOwnerValid = true;
			const emitter = new BoundedFrameEmitter(
				(frames, complete) => writes.push({ frames, complete }),
				TEST_MAXIMUM_BYTES,
				IDENTITY,
				() => true,
				() => admissionOwnerValid,
			);

			expect(emitter.emitBytes("test", "active", Buffer.alloc(11), {})).toMatchObject({ accepted: true });
			await waitFor(() => writes.length === 1, "active occurrence write did not start");
			expect(emitter.emitBytes("test", "queued_product", Buffer.alloc(17), {})).toMatchObject({ accepted: true });
			expect(emitter.emitControl("queued_control", {})).toMatchObject({ accepted: true });
			expectRejected(emitter.emitBytes("test", "capacity_loss", Buffer.alloc(200 * 1024), {}), "queue_capacity");
			await waitFor(
				() => emitter.producerSnapshot().lossCheckpointQueued,
				"loss checkpoint was not queued behind the active write",
			);
			expect(emitter.producerSnapshot()).toMatchObject({ queueOccurrences: 4, lossCheckpointQueued: true });

			admissionOwnerValid = false;
			expectRejected(emitter.emitDerived("test", "invalid_owner", {}), "stopped");
			expect(emitter.lossCounters()).toEqual({ records: 4, bytes: 204_817 });
			expect(emitter.producerSnapshot()).toMatchObject({
				queueOccurrences: 0,
				retainedWireBytes: 0,
				uncertainRecords: 1,
				uncertainBytes: 11,
				lossCheckpointQueued: false,
			});
			expect(emitter.producerSnapshot().inFlightWireBytes).toBeGreaterThan(0);
			expect(await emitter.flush()).toBe(false);

			writes[0].complete(callbackError);
			expect(emitter.lossCounters()).toEqual({ records: finalRecords, bytes: finalBytes });
			expect(emitter.producerSnapshot()).toMatchObject({
				queueOccurrences: 0,
				retainedWireBytes: 0,
				inFlightWireBytes: 0,
				uncertainRecords: 0,
				uncertainBytes: 0,
				lossCheckpointQueued: false,
			});

			// A broken writer cannot turn one bounded callback tombstone into repeat loss.
			writes[0].complete(callbackError ? undefined : new Error("duplicate late callback"));
			expect(emitter.lossCounters()).toEqual({ records: finalRecords, bytes: finalBytes });
		},
	);

	it("releases stop waiters while preserving terminal-tail loss and late active-write reconciliation", async () => {
		const writes: PendingWrite[] = [];
		let ownerValid = true;
		const emitter = new BoundedFrameEmitter(
			(frames, complete) => writes.push({ frames, complete }),
			TEST_MAXIMUM_BYTES,
			IDENTITY,
			() => ownerValid,
		);

		expect(emitter.emitBytes("test", "active_during_stop", Buffer.alloc(9), {})).toMatchObject({ accepted: true });
		await waitFor(() => writes.length === 1, "stop-race active occurrence write did not start");
		expect(emitter.emitBytes("test", "stop_tail", Buffer.alloc(5), {})).toMatchObject({ accepted: true });
		expect(emitter.emitControl("fixture_terminal", {}, true)).toMatchObject({ accepted: true });

		const stopping = emitter.stop(10_000);
		ownerValid = false;
		expect(await emitter.flush()).toBe(false);
		expect(await stopping).toBeUndefined();
		expect(writes.map(frameType)).toEqual(["active_during_stop"]);
		expect(emitter.lossCounters()).toEqual({ records: 2, bytes: 5 });
		expect(emitter.producerSnapshot()).toMatchObject({
			queueOccurrences: 0,
			uncertainRecords: 1,
			uncertainBytes: 9,
		});

		writes[0].complete(new Error("fixture late stop-race failure"));
		expect(emitter.lossCounters()).toEqual({ records: 3, bytes: 14 });
		expect(emitter.producerSnapshot()).toMatchObject({
			queueOccurrences: 0,
			inFlightWireBytes: 0,
			uncertainRecords: 0,
			uncertainBytes: 0,
		});
	});

	it("keeps original loss pending without recursively counting failed loss checkpoints", async () => {
		const writes: PendingWrite[] = [];
		const emitter = new BoundedFrameEmitter(
			(frames, complete) => {
				const write = { frames, complete };
				writes.push(write);
				if (frameType(write) === "capture_channel_loss_checkpoint" || frameType(write) === "original") {
					complete(new Error("fixture write failure"));
				} else {
					complete();
				}
			},
			TEST_MAXIMUM_BYTES,
			IDENTITY,
		);

		expect(
			emitter.emitBytes(
				"test",
				"original",
				Uint8Array.from({ length: 37 }, (_, index) => index),
				{},
			),
		).toMatchObject({
			accepted: true,
		});
		await waitFor(
			() => writes.some((write) => frameType(write) === "capture_channel_loss_checkpoint"),
			"first loss checkpoint was not attempted",
		);

		const afterFailedCheckpoint = emitter.producerSnapshot();
		expect(emitter.lossCounters()).toEqual({ records: 1, bytes: 37 });
		expect(afterFailedCheckpoint).toMatchObject({
			attemptedRecords: 1,
			attemptedBytes: 37,
			droppedRecords: 1,
			droppedBytes: 37,
			lossCheckpointQueued: false,
		});

		await emitter.stop();
		const checkpointWrites = writes.filter((write) => frameType(write) === "capture_channel_loss_checkpoint");
		expect(checkpointWrites).toHaveLength(2);
		for (const checkpoint of checkpointWrites) {
			expect(checkpoint.frames[0].header.metadata).toMatchObject({
				lostRecords: 1,
				lostBytes: 37,
				recordsSinceLastMarker: 1,
				bytesSinceLastMarker: 37,
			});
		}
		const terminal = writes.find((write) => frameType(write) === "capture_channel_terminal");
		expect(terminal?.frames[0].header.metadata).toMatchObject({ lostRecords: 1, lostBytes: 37 });
		expect(emitter.lossCounters()).toEqual({ records: 1, bytes: 37 });
		expect(emitter.producerSnapshot()).toMatchObject({ droppedRecords: 1, droppedBytes: 37 });
	});

	it("retains one bounded pending-loss checkpoint across internal capacity rejection", async () => {
		vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
		let ownerValid = true;
		try {
			const writes: PendingWrite[] = [];
			const emitter = new BoundedFrameEmitter(
				(frames, complete) => writes.push({ frames, complete }),
				TEST_MAXIMUM_BYTES,
				IDENTITY,
				() => ownerValid,
			);
			let accepted = 0;
			for (;;) {
				const admission = emitter.emitControl("capacity_filler", { attemptedRecords: accepted + 1 });
				if (!admission.accepted) {
					expectRejected(admission, "queue_capacity");
					break;
				}
				accepted += 1;
			}
			expect(accepted).toBeGreaterThan(1);

			await vi.advanceTimersByTimeAsync(1);
			await yieldImmediateTurns();
			const afterRejectedCheckpoint = emitter.producerSnapshot();
			expect(afterRejectedCheckpoint).toMatchObject({
				attemptedRecords: accepted + 1,
				droppedRecords: 1,
				droppedBytes: 0,
				lossCheckpointQueued: false,
			});
			expect(writes.filter((write) => frameType(write) === "capture_channel_loss_checkpoint")).toHaveLength(0);

			expect(writes).toHaveLength(1);
			writes[0].complete();
			await vi.advanceTimersByTimeAsync(1_000);
			expect(emitter.lossCounters()).toEqual({ records: 1, bytes: 0 });
			expect(emitter.producerSnapshot()).toMatchObject({
				droppedRecords: 1,
				droppedBytes: 0,
				lossCheckpointQueued: true,
			});

			ownerValid = false;
			expect(await emitter.flush()).toBe(false);
		} finally {
			vi.useRealTimers();
		}
	});

	it("coalesces a scaled rejection burst into bounded queue and checkpoint state with truthful counters", async () => {
		const writes: PendingWrite[] = [];
		const emitter = new BoundedFrameEmitter(
			(frames, complete) => writes.push({ frames, complete }),
			TEST_MAXIMUM_BYTES,
			IDENTITY,
		);
		const payload = Buffer.alloc(8 * 1024, 0x5a);
		const attempts = 10_000;
		let accepted = 0;
		for (let index = 0; index < attempts; index += 1) {
			if (emitter.emitBytes("test", "burst", payload, { attemptedRecords: index + 1 }).accepted) accepted += 1;
		}
		const rejected = attempts - accepted;
		const snapshot = emitter.producerSnapshot();

		expect(accepted).toBeGreaterThan(0);
		expect(rejected).toBeGreaterThan(0);
		expect(snapshot).toMatchObject({
			attemptedRecords: attempts,
			attemptedBytes: attempts * payload.length,
			queuedRecords: accepted,
			queuedBytes: accepted * payload.length,
			droppedRecords: rejected,
			droppedBytes: rejected * payload.length,
			queueOccurrences: accepted,
			lossCheckpointQueued: false,
		});
		expect(snapshot.retainedWireBytes).toBeLessThanOrEqual(TEST_MAXIMUM_BYTES - 64 * 1024);
		expect(snapshot.inFlightWireBytes).toBeLessThanOrEqual(snapshot.retainedWireBytes);
		expect(snapshot.queueOccurrences).toBeLessThan(64);
		expect(writes).toHaveLength(0);

		await waitFor(() => writes.length === 1, "burst head occurrence was not framed");
		expect(writes[0].frames).toHaveLength(Math.ceil(payload.length / INCIDENT_RECORDER_EMITTER_CHUNK_BYTES));
		expect(emitter.lossCounters()).toEqual({ records: rejected, bytes: rejected * payload.length });
	});
});
