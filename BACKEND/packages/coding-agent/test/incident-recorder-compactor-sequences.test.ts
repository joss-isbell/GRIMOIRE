import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import type { IncidentJournalLine } from "../src/modes/daemon/incident-recorder-writer.js";

const RUN_ID = "f1010101-0101-4101-8101-010101010101";
const RUN_TOKEN = "f2020202-0202-4202-8202-020202020202";
const PRODUCER_A = "f3030303-0303-4303-8303-030303030303";
const PRODUCER_B = "f4040404-0404-4404-8404-040404040404";
const PRODUCER_C = "f5050505-0505-4505-8505-050505050505";
const MACHINE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOOT_ID = "f6060606-0606-4606-8606-060606060606";

interface SequenceReference {
	machineId: string;
	bootId: string;
	uid: string;
	identifier: string;
	transport: string;
	streamId: string;
	sequenceUpdates?: { wrapperKey: string; wrapper: string; producerKey: string; producer: string };
	[key: string]: unknown;
}

interface CompactorSequenceInternals {
	checkSequences(line: IncidentJournalLine, reference: SequenceReference): void;
	writeGap(value: unknown): void;
	wrapperSequences: Map<string, bigint>;
	producerSequences: Map<string, bigint>;
}

const roots: string[] = [];

afterEach(() => {
	vi.restoreAllMocks();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { compactor: IncidentRecorderCompactor; internal: CompactorSequenceInternals } {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-compactor-sequences-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const compactor = new IncidentRecorderCompactor({ agentDir, freeReserveBytes: 0 });
	const internal = compactor as unknown as CompactorSequenceInternals;
	vi.spyOn(internal, "writeGap").mockImplementation(() => {});
	return { compactor, internal };
}

function line(input: {
	producerId: string;
	producerSequence: number;
	wrapperSequence: number;
	wrapperPid?: number;
	wrapperStartId?: string;
	systemdCatPid?: number;
	systemdCatStartId?: string;
	type?: string;
}): IncidentJournalLine {
	const producerSequence = String(input.producerSequence);
	const wrapperSequence = String(input.wrapperSequence);
	return {
		schema: "prime-agent-raw-v1",
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		producerId: input.producerId,
		producerSequence,
		wrapperSequence,
		occurrenceId: "f7070707-0707-4707-8707-070707070707",
		chunkIndex: 0,
		chunkCount: 1,
		source: "sequence-test",
		type: input.type ?? "observation",
		encoding: "none",
		payloadKind: "control",
		producerPid: null,
		producerStartId: null,
		wrapperPid: input.wrapperPid ?? 700,
		wrapperStartId: input.wrapperStartId ?? "wrapper-start",
		targetPid: null,
		targetStartId: null,
		bootId: BOOT_ID,
		machineId: MACHINE_ID,
		systemdInvocationId: null,
		systemdCatPid: input.systemdCatPid ?? 800,
		systemdCatStartId: input.systemdCatStartId ?? "cat-start",
		eventWallTimeMs: "1700000000000",
		eventMonotonicNs: "1000",
		rawOccurrenceBytes: 0,
		occurrenceSha256: "0".repeat(64),
		chunkBytes: 0,
		chunkSha256: "0".repeat(64),
		frameChecksum: 0,
		flags: 0,
		metadata: {},
		payloadBase64: "",
		attemptedRecords: null,
		attemptedBytes: null,
		queuedRecords: null,
		queuedBytes: null,
		droppedRecords: null,
		droppedBytes: null,
		observationDisposition: "observed_by_wrapper",
		queueDisposition: "locally_admitted",
		wrapperRelayDisposition: "locally_admitted",
		streamDisposition: "systemd_cat_stdin_write_attempted",
		journalDurability: "not_asserted_by_writer",
		wrapperRelayDroppedRecords: 0,
		wrapperRelayDroppedBytes: 0,
		wrapperRelayUncertainRecords: 0,
	};
}

function reference(lineValue: IncidentJournalLine): SequenceReference {
	return {
		id: `ref-${lineValue.wrapperSequence}`,
		path: `/tmp/ref-${lineValue.wrapperSequence}`,
		cursor: `cursor-${lineValue.wrapperSequence}`,
		machineId: MACHINE_ID,
		bootId: BOOT_ID,
		invocationId: null,
		realtimeUs: "1700000000000000",
		monotonicUs: "1",
		journalPid: String(lineValue.systemdCatPid),
		uid: "1000",
		identifier: "prime-agent-raw-v1",
		transport: "stdout",
		wrapperSequence: lineValue.wrapperSequence,
		producerSequence: lineValue.producerSequence,
		chunkIndex: 0,
		chunkCount: 1,
		bytes: 0,
		memoryBytes: 0,
		streamId: "sequence-stream",
		resolved: false,
	};
}

function observe(internal: CompactorSequenceInternals, value: IncidentJournalLine): SequenceReference {
	const item = reference(value);
	internal.checkSequences(value, item);
	if (item.sequenceUpdates) {
		internal.wrapperSequences.set(item.sequenceUpdates.wrapperKey, BigInt(item.sequenceUpdates.wrapper));
		internal.producerSequences.set(item.sequenceUpdates.producerKey, BigInt(item.sequenceUpdates.producer));
	}
	return item;
}

describe("incident recorder compactor sequence continuity", () => {
	it("accepts a new producer and cat identity when the wrapper frontier is contiguous through terminal", () => {
		const { internal } = fixture();
		observe(internal, line({ producerId: PRODUCER_A, producerSequence: 1, wrapperSequence: 1 }));
		observe(
			internal,
			line({
				producerId: PRODUCER_B,
				producerSequence: 1,
				wrapperSequence: 2,
				systemdCatPid: 801,
				systemdCatStartId: "cat-reconnect-start",
			}),
		);
		observe(
			internal,
			line({
				producerId: PRODUCER_B,
				producerSequence: 2,
				wrapperSequence: 3,
				type: "capture_channel_terminal",
			}),
		);
		expect(internal.wrapperSequences.size).toBe(1);
		expect(internal.producerSequences.size).toBe(2);
		expect(internal.writeGap).not.toHaveBeenCalled();
	});

	it("retains genuine wrapper replay, forward-gap, and producer replay detection", () => {
		const { internal } = fixture();
		observe(internal, line({ producerId: PRODUCER_A, producerSequence: 1, wrapperSequence: 1 }));
		observe(internal, line({ producerId: PRODUCER_B, producerSequence: 1, wrapperSequence: 2 }));
		observe(internal, line({ producerId: PRODUCER_B, producerSequence: 2, wrapperSequence: 3 }));

		expect(() =>
			observe(internal, line({ producerId: PRODUCER_B, producerSequence: 3, wrapperSequence: 3 })),
		).toThrow("Wrapper sequence replay or backward reorder");
		const gap = vi.mocked(internal.writeGap);
		observe(internal, line({ producerId: PRODUCER_C, producerSequence: 1, wrapperSequence: 5 }));
		expect(gap).toHaveBeenCalledWith(
			expect.objectContaining({
				reason: "wrapper_sequence_gap",
				expectedWrapperFrom: "4",
				expectedWrapperThrough: "4",
				observedWrapperSequence: "5",
			}),
		);
		expect(() =>
			observe(internal, line({ producerId: PRODUCER_B, producerSequence: 2, wrapperSequence: 6 })),
		).toThrow("Producer sequence replay or backward reorder");
	});
});
