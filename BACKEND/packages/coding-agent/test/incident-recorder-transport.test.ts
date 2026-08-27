import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	decodeIncidentRecorderFrame,
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
	INCIDENT_RECORDER_PROTOCOL_VERSION,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import {
	decodeIncidentRecorderTransportPacket,
	encodeIncidentRecorderTransportPacket,
	INCIDENT_RECORDER_TRANSPORT_MAX_ENCODED_PACKET_BYTES,
	type IncidentRecorderTransportCorruption,
	IncidentRecorderTransportDecoder,
	IncidentRecorderTransportSequenceTracker,
} from "../src/modes/daemon/incident-recorder-transport.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

function frame(
	sequence: bigint,
	payload: Buffer,
	occurrence = `44444444-4444-4444-8444-${sequence.toString().padStart(12, "0")}`,
): Buffer {
	const encoded = encodeIncidentRecorderFrame(
		{
			runId: "11111111-1111-4111-8111-111111111111",
			runToken: "22222222-2222-4222-8222-222222222222",
			producerId: "33333333-3333-4333-8333-333333333333",
			occurrenceId: occurrence,
			producerSequence: sequence,
			wallTimeMs: 1n,
			monotonicNs: 1n,
			payloadKind: "exact-bytes",
			flags: INCIDENT_RECORDER_FRAME_FLAGS.firstChunk | INCIDENT_RECORDER_FRAME_FLAGS.lastChunk,
			chunkIndex: 0,
			chunkCount: 1,
			source: "worker-stdout",
			type: "test",
			encoding: "exact-bytes",
			metadata: {},
		},
		payload,
	);
	return Buffer.concat(encoded.parts);
}

function collect(
	wire: Buffer,
	fragmentBytes = wire.length,
): { packets: Buffer[]; corruptions: IncidentRecorderTransportCorruption[] } {
	const packets: Buffer[] = [];
	const corruptions: IncidentRecorderTransportCorruption[] = [];
	const decoder = new IncidentRecorderTransportDecoder(
		(packet) => packets.push(packet),
		(evidence) => corruptions.push(evidence),
	);
	for (let offset = 0; offset < wire.length; offset += fragmentBytes)
		decoder.push(wire.subarray(offset, offset + fragmentBytes));
	decoder.finish();
	return { packets, corruptions };
}

const TEST_RUN_ID = "11111111-1111-4111-8111-111111111111";
const TEST_RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const TEST_PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const TEST_OCCURRENCE_ID = "55555555-5555-4555-8555-555555555555";

function occurrenceFrames(payloads: readonly Buffer[]): Buffer[] {
	const occurrenceBytes = Buffer.concat(payloads);
	const occurrenceSha256 = createHash("sha256").update(occurrenceBytes).digest("hex");
	return payloads.map((payload, chunkIndex) =>
		Buffer.concat(
			encodeIncidentRecorderFrame(
				{
					runId: TEST_RUN_ID,
					runToken: TEST_RUN_TOKEN,
					producerId: TEST_PRODUCER_ID,
					occurrenceId: TEST_OCCURRENCE_ID,
					producerSequence: 100n + BigInt(chunkIndex),
					wallTimeMs: 1n,
					monotonicNs: 1n,
					payloadKind: "exact-bytes",
					flags:
						(chunkIndex === 0 ? INCIDENT_RECORDER_FRAME_FLAGS.firstChunk : 0) |
						(chunkIndex === payloads.length - 1 ? INCIDENT_RECORDER_FRAME_FLAGS.lastChunk : 0),
					chunkIndex,
					chunkCount: payloads.length,
					source: "transport-accounting-test",
					type: "reordered",
					encoding: "exact-bytes",
					metadata: { occurrenceRawBytes: occurrenceBytes.length, occurrenceSha256 },
				},
				payload,
			).parts,
		),
	);
}

function singleFrame(producerId: string, occurrenceId: string, sequence: bigint, payload = Buffer.from("one")): Buffer {
	const occurrenceSha256 = createHash("sha256").update(payload).digest("hex");
	return Buffer.concat(
		encodeIncidentRecorderFrame(
			{
				runId: TEST_RUN_ID,
				runToken: TEST_RUN_TOKEN,
				producerId,
				occurrenceId,
				producerSequence: sequence,
				wallTimeMs: 1n,
				monotonicNs: 1n,
				payloadKind: "exact-bytes",
				flags: INCIDENT_RECORDER_FRAME_FLAGS.firstChunk | INCIDENT_RECORDER_FRAME_FLAGS.lastChunk,
				chunkIndex: 0,
				chunkCount: 1,
				source: "transport-accounting-test",
				type: "single",
				encoding: "exact-bytes",
				metadata: { occurrenceRawBytes: payload.length, occurrenceSha256 },
			},
			payload,
		).parts,
	);
}

function reencodeFrame(
	frameBytes: Buffer,
	changes: { type?: string; chunkCount?: number; producerSequence?: bigint },
): Buffer {
	const value = decodeIncidentRecorderFrame(frameBytes);
	const header = value.header;
	return Buffer.concat(
		encodeIncidentRecorderFrame(
			{
				runId: header.runId,
				runToken: header.runToken,
				producerId: header.producerId,
				occurrenceId: header.occurrenceId,
				producerSequence: changes.producerSequence ?? header.producerSequence,
				wallTimeMs: header.wallTimeMs,
				monotonicNs: header.monotonicNs,
				payloadKind: header.payloadKind,
				flags: changes.chunkCount === undefined ? header.flags : INCIDENT_RECORDER_FRAME_FLAGS.firstChunk,
				chunkIndex: header.chunkIndex,
				chunkCount: changes.chunkCount ?? header.chunkCount,
				source: header.source,
				type: changes.type ?? header.type,
				encoding: header.encoding,
				metadata: header.metadata,
			},
			value.payload,
		).parts,
	);
}

type WriterInternals = {
	acceptCaptureFrame(frame: Buffer, wireBytes: number): void;
	captureSequences: IncidentRecorderTransportSequenceTracker;
	noteCaptureSequenceAccounting(accounting: { gapEvents: bigint; missingPackets: bigint }): void;
	dropCaptureAssembly(extraBytes: number): void;
	captureFrames: Array<Buffer | undefined>;
	captureCompletedOccurrences: unknown[];
	captureValidationRunning: boolean;
	relayQueue: Array<{
		occurrenceId: string;
		frames: Array<{ header: { chunkIndex: number; occurrenceId: string; producerId: string } }>;
	}>;
	relayDroppedRecords: number;
	relayDroppedBytes: number;
	transportSequenceGapEvents: bigint;
	transportMissingPackets: bigint;
};

async function feedFrames(
	frames: readonly Buffer[],
	order: readonly number[],
	finish = true,
	tracker?: IncidentRecorderTransportSequenceTracker,
): Promise<WriterInternals> {
	const writer = new IncidentRecorderWriter({ runDir: "/tmp", runId: TEST_RUN_ID, runToken: TEST_RUN_TOKEN });
	const internals = writer as unknown as WriterInternals;
	if (tracker) internals.captureSequences = tracker;
	for (const index of order) internals.acceptCaptureFrame(frames[index], frames[index].length);
	if (finish) {
		internals.noteCaptureSequenceAccounting(internals.captureSequences.finish());
		if (internals.captureFrames.length > 0) internals.dropCaptureAssembly(0);
	}
	for (
		let attempt = 0;
		attempt < 5000 && (internals.captureValidationRunning || internals.captureCompletedOccurrences.length > 0);
		attempt += 1
	) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
	return internals;
}

async function feedOccurrence(
	order: readonly number[],
	payloads: readonly Buffer[],
	finish = true,
): Promise<WriterInternals> {
	return feedFrames(occurrenceFrames(payloads), order, finish);
}

describe("incident recorder fd4 transport", () => {
	it("makes protocol revision 3 explicit and preserves empty and zero-containing payload bytes", () => {
		expect(INCIDENT_RECORDER_PROTOCOL_VERSION).toBe(3);
		for (const payload of [Buffer.alloc(0), Buffer.from([0, 1, 0, 2, 255, 0])]) {
			const raw = frame(1n, payload);
			const wire = encodeIncidentRecorderTransportPacket(raw);
			expect(wire.at(-1)).toBe(0);
			expect(wire.subarray(0, -1).includes(0)).toBe(false);
			expect(decodeIncidentRecorderTransportPacket(wire.subarray(0, -1))).toEqual(raw);
			const result = collect(wire, 1);
			expect(result.corruptions).toEqual([]);
			expect(decodeIncidentRecorderFrame(result.packets[0]).payload).toEqual(payload);
		}
	});

	it("bounds a delimiter-free attack and resumes at the following packet", () => {
		const swallowed = encodeIncidentRecorderTransportPacket(frame(1n, Buffer.from("swallowed")));
		const later = encodeIncidentRecorderTransportPacket(frame(2n, Buffer.from("later")));
		const attackBytes = INCIDENT_RECORDER_TRANSPORT_MAX_ENCODED_PACKET_BYTES + 37;
		const result = collect(Buffer.concat([Buffer.alloc(attackBytes, 0x7f), swallowed, later]), 17);
		expect(result.corruptions).toEqual([{ kind: "oversized-packet", wireBytes: attackBytes + swallowed.length }]);
		expect(result.packets).toHaveLength(1);
		expect(decodeIncidentRecorderFrame(result.packets[0]).payload.toString()).toBe("later");
	});

	it("contains bytes inserted inside one packet and resynchronizes later valid packets", () => {
		const first = encodeIncidentRecorderTransportPacket(frame(1n, Buffer.from("first")));
		const damaged = encodeIncidentRecorderTransportPacket(frame(2n, Buffer.from("damaged")));
		const last = encodeIncidentRecorderTransportPacket(frame(3n, Buffer.from("last")));
		const split = Math.floor(damaged.length / 2);
		const result = collect(
			Buffer.concat([first, damaged.subarray(0, split), Buffer.from([0]), damaged.subarray(split), last]),
			3,
		);
		const valid = result.packets.flatMap((packet) => {
			try {
				return [decodeIncidentRecorderFrame(packet)];
			} catch {
				return [];
			}
		});
		expect(valid.map((value) => value.payload.toString())).toEqual(["first", "last"]);
		expect(result.corruptions.length + result.packets.length - valid.length).toBeGreaterThan(0);
	});

	it("reports an exact non-delimited tail and exact bigint sequence gaps", () => {
		const corruptions: IncidentRecorderTransportCorruption[] = [];
		const decoder = new IncidentRecorderTransportDecoder(
			() => {},
			(evidence) => corruptions.push(evidence),
		);
		decoder.push(Buffer.from([1, 2, 3, 4]));
		expect(decoder.bufferedWireBytes).toBe(4);
		expect(decoder.finish()).toBe(4);
		expect(corruptions).toEqual([{ kind: "truncated-packet", wireBytes: 4 }]);

		const tracker = new IncidentRecorderTransportSequenceTracker(1);
		expect(tracker.observe("producer", 7n)).toEqual({ duplicate: false, gapEvents: 0n, missingPackets: 0n });
		expect(tracker.observe("producer", 10n)).toEqual({ duplicate: false, gapEvents: 0n, missingPackets: 0n });
		expect(tracker.observe("producer", 9n)).toEqual({ duplicate: false, gapEvents: 0n, missingPackets: 0n });
		expect(tracker.finish()).toEqual({ gapEvents: 1n, missingPackets: 1n });
	});
	it.each([
		{
			name: "reordered chunks",
			order: [1, 0, 2],
			chunks: [Buffer.from("aaa"), Buffer.from("bbb"), Buffer.from("ccc")],
		},
		{
			name: "duplicate first chunk",
			order: [0, 0, 1, 2],
			chunks: [Buffer.from("aaa"), Buffer.from("bbb"), Buffer.from("ccc")],
		},
		{
			name: "future chunk then recovery",
			order: [0, 2, 1],
			chunks: [Buffer.from("aaa"), Buffer.from("bbb"), Buffer.from("ccc")],
		},
		{ name: "duplicate single packet", order: [0, 0], chunks: [Buffer.from("only")] },
		{ name: "duplicate final packet", order: [0, 1, 1], chunks: [Buffer.from("first"), Buffer.from("last")] },
		{ name: "duplicate initial packet", order: [0, 0, 1], chunks: [Buffer.from("first"), Buffer.from("last")] },
	])("reassembles $name once without invented loss", async ({ order, chunks }) => {
		const state = await feedOccurrence(order, chunks);
		const occurrences = state.relayQueue.filter((item) => item.occurrenceId === TEST_OCCURRENCE_ID);
		expect(occurrences).toHaveLength(1);
		expect(occurrences[0].frames.map((value) => value.header.chunkIndex)).toEqual(chunks.map((_, index) => index));
		expect(occurrences[0].frames.map((value) => value.header.occurrenceId)).toEqual(
			chunks.map(() => TEST_OCCURRENCE_ID),
		);
		expect(state.relayDroppedRecords).toBe(0);
		expect(state.relayDroppedBytes).toBe(0);
		expect(state.transportSequenceGapEvents).toBe(0n);
		expect(state.transportMissingPackets).toBe(0n);
		expect(state.captureFrames).toHaveLength(0);
	});

	it("finalizes one exact missing packet and one occurrence loss at EOF", async () => {
		const chunks = [Buffer.from("aaa"), Buffer.from("bbb"), Buffer.from("ccc")];
		const state = await feedOccurrence([0, 2], chunks);
		expect(state.relayQueue.filter((item) => item.occurrenceId === TEST_OCCURRENCE_ID)).toEqual([]);
		expect(state.relayDroppedRecords).toBe(1);
		expect(state.relayDroppedBytes).toBe(Buffer.concat(chunks).length);
		expect(state.transportSequenceGapEvents).toBe(1n);
		expect(state.transportMissingPackets).toBe(1n);
		expect(state.captureFrames).toHaveLength(0);
	});

	it("never finalizes the currently observed lower packet at the default pending-range bound", () => {
		const tracker = new IncidentRecorderTransportSequenceTracker();
		let accounting = { gapEvents: 0n, missingPackets: 0n };
		const add = (value: { gapEvents: bigint; missingPackets: bigint }) => {
			accounting = {
				gapEvents: accounting.gapEvents + value.gapEvents,
				missingPackets: accounting.missingPackets + value.missingPackets,
			};
		};
		add(tracker.observe("producer", 1000n));
		for (let index = 1n; index <= 64n; index += 1n) add(tracker.observe("producer", 1000n + 2n * index));
		const lower = tracker.observe("producer", 0n);
		add(lower);
		add(tracker.finish());
		expect(lower.duplicate).toBe(false);
		expect(accounting).toEqual({ gapEvents: 65n, missingPackets: 1063n });
	});

	it("suppresses packets at a finalized producer frontier after bounded producer eviction", () => {
		const tracker = new IncidentRecorderTransportSequenceTracker();
		let accounting = { gapEvents: 0n, missingPackets: 0n };
		const add = (value: { gapEvents: bigint; missingPackets: bigint }) => {
			accounting = {
				gapEvents: accounting.gapEvents + value.gapEvents,
				missingPackets: accounting.missingPackets + value.missingPackets,
			};
		};
		add(tracker.observe("producer-a", 0n));
		add(tracker.observe("producer-a", 2n));
		for (let index = 0; index < 64; index += 1) add(tracker.observe(`producer-${index}`, 0n));
		const late = tracker.observe("producer-a", 1n);
		add(late);
		add(tracker.finish());
		expect(late.duplicate).toBe(true);
		expect(accounting).toEqual({ gapEvents: 1n, missingPackets: 1n });
	});

	it("rejects completed-ID alternate sequences and conflicting duplicates before expectation mutation", async () => {
		const frames = occurrenceFrames([Buffer.from("aaa"), Buffer.from("bbb"), Buffer.from("ccc")]);
		const conflicting = reencodeFrame(frames[0], { chunkCount: 40 });
		const state = await feedFrames([...frames, conflicting], [0, 1, 2, 3]);
		expect(state.relayQueue.filter((item) => item.occurrenceId === TEST_OCCURRENCE_ID)).toHaveLength(1);
		expect(state.transportSequenceGapEvents).toBe(0n);
		expect(state.transportMissingPackets).toBe(0n);
		expect(state.relayDroppedRecords).toBe(0);

		const one = occurrenceFrames([Buffer.from("only")]);
		const alternate = reencodeFrame(one[0], { producerSequence: 102n });
		const alternateState = await feedFrames([...one, alternate], [0, 1]);
		expect(alternateState.relayQueue.filter((item) => item.occurrenceId === TEST_OCCURRENCE_ID)).toHaveLength(1);
		expect(alternateState.transportSequenceGapEvents).toBe(0n);
		expect(alternateState.transportMissingPackets).toBe(0n);
	});

	it("preserves exact full raw bytes when async semantic validation rejects a complete occurrence", async () => {
		const chunks = [Buffer.alloc(3, 1), Buffer.alloc(4, 2), Buffer.alloc(5, 3)];
		const frames = occurrenceFrames(chunks);
		frames[1] = reencodeFrame(frames[1], { type: "changed-middle-type" });
		const state = await feedFrames(frames, [0, 1, 2]);
		expect(state.relayQueue.filter((item) => item.occurrenceId === TEST_OCCURRENCE_ID)).toEqual([]);
		expect(state.relayDroppedRecords).toBe(1);
		expect(state.relayDroppedBytes).toBe(12);
		expect(state.transportSequenceGapEvents).toBe(0n);
		expect(state.transportMissingPackets).toBe(0n);
	});

	it("fills a pending sequence below a reactivated producer minimum", () => {
		const tracker = new IncidentRecorderTransportSequenceTracker(1);
		let accounting = { gapEvents: 0n, missingPackets: 0n };
		const add = (value: { gapEvents: bigint; missingPackets: bigint }) => {
			accounting = {
				gapEvents: accounting.gapEvents + value.gapEvents,
				missingPackets: accounting.missingPackets + value.missingPackets,
			};
		};
		add(tracker.observe("producer-a", 0n));
		add(tracker.observe("producer-a", 2n));
		add(tracker.observe("producer-b", 0n));
		add(tracker.observe("producer-a", 4n));
		const recovered = tracker.observe("producer-a", 3n);
		add(recovered);
		add(tracker.finish());
		expect(recovered.duplicate).toBe(false);
		expect(accounting).toEqual({ gapEvents: 1n, missingPackets: 1n });
	});

	it("relays a recovered post-eviction packet without retaining a false missing count", async () => {
		const producerA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
		const producerB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
		const frames = [
			singleFrame(producerA, "73000000-0000-4000-8000-000000000000", 0n),
			singleFrame(producerA, "73000000-0000-4000-8000-000000000002", 2n),
			singleFrame(producerB, "74000000-0000-4000-8000-000000000000", 0n),
			singleFrame(producerA, "73000000-0000-4000-8000-000000000004", 4n),
			singleFrame(producerA, "73000000-0000-4000-8000-000000000003", 3n),
		];
		const state = await feedFrames(frames, [0, 1, 2, 3, 4], true, new IncidentRecorderTransportSequenceTracker(1));
		expect(state.relayQueue.filter((item) => item.frames[0].header.producerId === producerA)).toHaveLength(4);
		expect(state.transportSequenceGapEvents).toBe(1n);
		expect(state.transportMissingPackets).toBe(1n);
	});

	it("does not relay a late packet after its producer gap was finalized by bounded eviction", async () => {
		const producerA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
		const frames = [
			singleFrame(producerA, "71000000-0000-4000-8000-000000000000", 0n),
			singleFrame(producerA, "71000000-0000-4000-8000-000000000002", 2n),
			...Array.from({ length: 64 }, (_, index) =>
				singleFrame(
					`70000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
					`72000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
					0n,
				),
			),
			singleFrame(producerA, "71000000-0000-4000-8000-000000000001", 1n),
		];
		const state = await feedFrames(
			frames,
			frames.map((_, index) => index),
		);
		expect(state.relayQueue.filter((item) => item.frames[0].header.producerId === producerA)).toHaveLength(2);
		expect(state.relayQueue.some((item) => item.occurrenceId === "71000000-0000-4000-8000-000000000001")).toBe(false);
		expect(state.transportSequenceGapEvents).toBe(1n);
		expect(state.transportMissingPackets).toBe(1n);
	});

	it("suppresses real old-sequence duplicates after the proven transport tombstone window rolls over", async () => {
		const frames = Array.from({ length: 1800 }, (_, index) =>
			singleFrame(
				TEST_PRODUCER_ID,
				`60000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
				100n + BigInt(index),
			),
		);
		const state = await feedFrames(
			[...frames, frames[0]],
			Array.from({ length: 1801 }, (_, index) => index),
		);
		expect(
			state.relayQueue.filter((item) => item.occurrenceId === "60000000-0000-4000-8000-000000000000"),
		).toHaveLength(1);
		expect(state.transportSequenceGapEvents).toBe(0n);
		expect(state.transportMissingPackets).toBe(0n);
		// A CRC-valid reuse of that UUID with a genuinely new sequence is a semantic
		// same-UID forgery outside this bounded non-hostile corruption boundary.
	});

	it("rejects flags outside the exact unsigned v3 field range before encoding", () => {
		const encodeWithFlags = (flags: number) =>
			encodeIncidentRecorderFrame(
				{
					runId: TEST_RUN_ID,
					runToken: TEST_RUN_TOKEN,
					producerId: TEST_PRODUCER_ID,
					occurrenceId: TEST_OCCURRENCE_ID,
					producerSequence: 1n,
					wallTimeMs: 1n,
					monotonicNs: 1n,
					payloadKind: "exact-bytes",
					flags,
					chunkIndex: 0,
					chunkCount: 1,
					source: "flag-test",
					type: "flag-test",
					encoding: "exact-bytes",
					metadata: {},
				},
				Buffer.alloc(0),
			);
		for (const flags of [4294967308, -4294967284])
			expect(() => encodeWithFlags(flags)).toThrow("Invalid incident recorder frame flags");
		expect(
			encodeWithFlags(INCIDENT_RECORDER_FRAME_FLAGS.firstChunk | INCIDENT_RECORDER_FRAME_FLAGS.lastChunk).header
				.flags,
		).toBe(12);
	});
});
