import { describe, expect, it } from "vitest";
import {
	decodeIncidentRecorderFrame,
	type IncidentRecorderEncodedFrame,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const SERVICE_RUN_ID = "33333333-3333-4333-8333-333333333333";
const SERVICE_RUN_TOKEN = "44444444-4444-4444-8444-444444444444";
const SUPPLIED_OCCURRENCE_ID = "55555555-5555-4555-8555-555555555555";

type EmitterInternals = {
	counters: { attemptedRecords: number; droppedRecords: number };
	sequence: bigint;
	flush(deadlineMs?: number): Promise<boolean>;
};

type WriterInternals = {
	relayQueue: Array<{ occurrenceId: string; frames: readonly IncidentRecorderEncodedFrame[] }>;
	serviceEmitters: Map<string, EmitterInternals>;
};

function internals(writer: IncidentRecorderWriter): WriterInternals {
	return writer as unknown as WriterInternals;
}

function serviceIdentityKey(): string {
	return `${SERVICE_RUN_ID}\0${SERVICE_RUN_TOKEN}`;
}

function serviceIdentity() {
	return { runId: SERVICE_RUN_ID, runToken: SERVICE_RUN_TOKEN };
}

function writer(options: { serviceSink?: boolean } = {}): IncidentRecorderWriter {
	return new IncidentRecorderWriter({
		runDir: "/tmp/incident-recorder-writer-occurrence-id-test",
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		serviceSink: options.serviceSink ?? true,
	});
}

async function frameFor(
	writerValue: IncidentRecorderWriter,
	occurrenceId: string,
): Promise<IncidentRecorderEncodedFrame> {
	const state = internals(writerValue);
	for (let attempt = 0; attempt < 500; attempt += 1) {
		const occurrence = state.relayQueue.find((candidate) => candidate.occurrenceId === occurrenceId);
		if (occurrence?.frames[0]) return occurrence.frames[0];
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
	throw new Error(`timed out waiting for occurrence ${occurrenceId}`);
}

function largeDiagnosticFields(): Record<string, unknown> {
	const values = Object.freeze(Array.from({ length: 64 }, () => "x".repeat(8 * 1024)));
	return Object.freeze({ origin: "queue-capacity-test", values });
}

describe("caller-owned ordinary occurrence IDs", () => {
	it("uses the supplied ID in the framed body and preserves scalar metadata", async () => {
		const value = writer();
		try {
			const admission = value.recordDerivedForRunWithOccurrenceId(
				serviceIdentity(),
				"recorder-events",
				"ordinary_diagnostic",
				Object.freeze({ origin: "caller-owned-test", requestId: "request-7" }),
				SUPPLIED_OCCURRENCE_ID,
			);
			expect(admission).toMatchObject({ accepted: true, occurrenceId: SUPPLIED_OCCURRENCE_ID });

			const frame = await frameFor(value, SUPPLIED_OCCURRENCE_ID);
			const decoded = decodeIncidentRecorderFrame(Buffer.concat(frame.parts));
			expect(decoded.header.occurrenceId).toBe(SUPPLIED_OCCURRENCE_ID);
			expect(decoded.header.metadata).toMatchObject({
				origin: "caller-owned-test",
				requestId: "request-7",
				queueDisposition: "locally_admitted",
			});
			expect(decoded.payload.toString("utf8")).toContain('"schemaVersion":2');
		} finally {
			await value.stop(25);
		}
	});

	it("falls back to a scalar-only frame with the same supplied ID after body queue rejection", async () => {
		const value = writer();
		try {
			expect(
				value.recordDerivedForRun(serviceIdentity(), "recorder-events", "fill-one", largeDiagnosticFields())
					.accepted,
			).toBe(true);
			expect(
				value.recordDerivedForRun(serviceIdentity(), "recorder-events", "fill-two", largeDiagnosticFields())
					.accepted,
			).toBe(true);

			const admission = value.recordDerivedForRunWithOccurrenceId(
				serviceIdentity(),
				"recorder-events",
				"body_rejected",
				largeDiagnosticFields(),
				SUPPLIED_OCCURRENCE_ID,
			);
			expect(admission).toMatchObject({ accepted: true, occurrenceId: SUPPLIED_OCCURRENCE_ID });

			const frame = await frameFor(value, SUPPLIED_OCCURRENCE_ID);
			const decoded = decodeIncidentRecorderFrame(Buffer.concat(frame.parts));
			expect(decoded.header.occurrenceId).toBe(SUPPLIED_OCCURRENCE_ID);
			expect(decoded.payload).toHaveLength(0);
			expect(decoded.header.metadata).toMatchObject({
				payloadState: "queue_dropped",
				payloadStoredBytes: 0,
			});
			expect(decoded.header.metadata.droppedRecords).toBeGreaterThan(0);
		} finally {
			await value.stop(25);
		}
	});

	it("emits no frame when both body and scalar fallback are rejected, then preserves sequence continuity", async () => {
		const value = writer();
		try {
			const large = largeDiagnosticFields();
			expect(value.recordDerivedForRun(serviceIdentity(), "recorder-events", "fill-one", large).accepted).toBe(true);
			expect(value.recordDerivedForRun(serviceIdentity(), "recorder-events", "fill-two", large).accepted).toBe(true);
			for (let index = 0; index < 7; index += 1) {
				expect(
					value.recordExactBytesForRun(
						serviceIdentity(),
						"recorder-events",
						`fill-${index}`,
						Buffer.from([index]),
						"exact-bytes",
						{},
					).accepted,
				).toBe(true);
			}
			const state = internals(value);
			const emitter = state.serviceEmitters.get(serviceIdentityKey());
			expect(emitter).toBeDefined();
			const sequenceBeforeRejection = emitter?.sequence;

			const rejection = value.recordDerivedForRunWithOccurrenceId(
				serviceIdentity(),
				"recorder-events",
				"totally_rejected",
				large,
				SUPPLIED_OCCURRENCE_ID,
			);
			expect(rejection).toMatchObject({ accepted: false, reason: "queue_capacity" });

			await emitter?.flush(1_000);
			expect(state.relayQueue.filter((item) => item.occurrenceId === SUPPLIED_OCCURRENCE_ID)).toEqual([]);

			const ordinary = value.recordDerivedForRun(serviceIdentity(), "recorder-events", "ordinary_after_rejection", {
				origin: "ordinary",
			});
			expect(ordinary.accepted).toBe(true);
			const frame = await frameFor(value, ordinary.accepted ? ordinary.occurrenceId : SUPPLIED_OCCURRENCE_ID);
			// The rejected body and scalar fallback consume no producer sequence.
			const laterFrames = state.relayQueue
				.flatMap((item) => item.frames)
				.filter((candidate) => candidate.header.producerSequence > (sequenceBeforeRejection ?? 0n));
			const lossFrames = laterFrames.filter(
				(candidate) => candidate.header.type === "capture_channel_loss_checkpoint",
			);
			expect(laterFrames.filter((candidate) => candidate.header.type !== "ordinary_after_rejection")).toEqual(
				lossFrames,
			);
			expect(frame.header.producerSequence).toBe((sequenceBeforeRejection ?? 0n) + BigInt(lossFrames.length) + 1n);
			expect(frame.header.type).toBe("ordinary_after_rejection");
			expect(
				state.relayQueue.some((item) =>
					item.frames.some((candidate) => candidate.header.type === "capture_channel_terminal"),
				),
			).toBe(false);
		} finally {
			await value.stop(25);
		}
	});

	it("rejects malformed supplied IDs before serialization, counters, or queue mutation", async () => {
		const value = writer();
		try {
			const valid = value.recordDerivedForRun(serviceIdentity(), "recorder-events", "before_invalid", {});
			expect(valid.accepted).toBe(true);
			const state = internals(value);
			const emitter = state.serviceEmitters.get(serviceIdentityKey());
			expect(emitter).toBeDefined();
			const attemptedRecords = emitter?.counters.attemptedRecords;
			let getterReads = 0;
			const fields: Record<string, unknown> = {};
			Object.defineProperty(fields, "mustNotBeRead", {
				enumerable: true,
				get: () => {
					getterReads += 1;
					return "unreachable";
				},
			});
			expect(() =>
				value.recordDerivedForRunWithOccurrenceId(
					serviceIdentity(),
					"recorder-events",
					"invalid",
					fields,
					"00000000-0000-0000-8000-000000000000",
				),
			).toThrow(/Invalid incident-recorder occurrence identity/);
			expect(getterReads).toBe(0);
			expect(emitter?.counters.attemptedRecords).toBe(attemptedRecords);
			expect(
				state.relayQueue.filter((item) => item.occurrenceId === "00000000-0000-0000-8000-000000000000"),
			).toEqual([]);
		} finally {
			await value.stop(25);
		}
	});

	it("preserves sealed and stopped rejection while ordinary records remain non-terminal", async () => {
		const sealed = writer();
		try {
			expect(sealed.fenceRunIdentity(serviceIdentity())).toBeDefined();
			expect(
				sealed.recordDerivedForRunWithOccurrenceId(
					serviceIdentity(),
					"recorder-events",
					"sealed",
					{},
					SUPPLIED_OCCURRENCE_ID,
				),
			).toMatchObject({ accepted: false, reason: "run_identity_sealed" });
		} finally {
			await sealed.stop(25);
		}

		const stopped = writer();
		await stopped.stop(25);
		expect(
			stopped.recordDerivedForRunWithOccurrenceId(
				serviceIdentity(),
				"recorder-events",
				"stopped",
				{},
				SUPPLIED_OCCURRENCE_ID,
			),
		).toMatchObject({ accepted: false, reason: "stopped" });
	});
});
