import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type IncidentRecorderServiceSignalSource,
	inspectIncidentRecorderRuns,
	runIncidentRecorderService,
} from "../src/modes/daemon/incident-recorder.js";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderLiveRunEventsCursor,
	type IncidentRecorderLiveRunEventsPage,
	type IncidentRecorderLiveRunGapsPage,
	type IncidentRecorderRunHistoryEvent,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	type IncidentRecorderStoredFinalizationBarrierExpectation,
	readCompactedFinalizationBarrier,
} from "../src/modes/daemon/incident-recorder-finalization-barrier.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const SUPERVISOR_OCCURRENCE_ID = "44444444-4444-4444-8444-444444444444";
const TERMINAL_OCCURRENCE_ID = "55555555-5555-4555-8555-555555555555";
const roots: string[] = [];
const leases: IncidentRecorderWriterLifecycleLease[] = [];
const compactors: IncidentRecorderCompactor[] = [];

interface CompactorInternals {
	appendSegmentRecord(input: {
		idempotencyKey: string;
		runId: string;
		sourceId: string;
		observedAtMs: number;
		order: string;
		metadata: Record<string, string | number | boolean>;
		payload: Buffer;
	}): unknown;
	closeSegmentStore(): void;
}

function fixture(): {
	root: string;
	compactor: IncidentRecorderCompactor;
	internal: CompactorInternals;
	agentDir: string;
} {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-finalization-barrier-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const scanner = join(root, "storage-scanner.cjs");
	writeFileSync(scanner, `#!${process.execPath}\nprocess.stdout.write("1\\t1\\t0\\t0\\n");\n`, {
		mode: 0o700,
	});
	chmodSync(scanner, 0o700);
	let lease: IncidentRecorderWriterLifecycleLease | undefined;
	const contract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: "a".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: acquireIncidentRecorderNamespaceCas,
	};
	const acquireLease = (): IncidentRecorderWriterLifecycleLease => {
		if (lease) return lease;
		const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, contract);
		if (admission.state !== "acquired") throw new Error(`fixture lease unavailable: ${admission.reason}`);
		lease = admission.lease;
		leases.push(lease);
		return lease;
	};
	const compactor = new IncidentRecorderCompactor({
		agentDir,
		storageScannerPath: scanner,
		freeReserveBytes: 0,
		writerLifecycleLease: acquireLease,
	});
	compactors.push(compactor);
	return { root, compactor, internal: compactor as unknown as CompactorInternals, agentDir };
}

function expectation(
	supervisorOccurrenceId = SUPERVISOR_OCCURRENCE_ID,
	terminalOccurrenceId = TERMINAL_OCCURRENCE_ID,
): IncidentRecorderStoredFinalizationBarrierExpectation {
	return {
		version: 1,
		runId: RUN_ID,
		runToken: TOKEN,
		wrapperPid: 100,
		wrapperStartId: "wrapper-start",
		supervisorExit: {
			type: "supervisor_exit",
			occurrenceId: supervisorOccurrenceId,
			producerId: PRODUCER_ID,
			firstProducerSequence: "1",
			lastProducerSequence: "1",
			firstWrapperSequence: "1",
			lastWrapperSequence: "1",
		},
		wrapperTerminal: {
			type: "capture_channel_terminal",
			occurrenceId: terminalOccurrenceId,
			producerId: PRODUCER_ID,
			firstProducerSequence: "2",
			lastProducerSequence: "2",
			firstWrapperSequence: "2",
			lastWrapperSequence: "2",
		},
		finalQueuedTailLoss: { records: 0, bytes: 0 },
		emitterFinalTailLoss: { records: 0, bytes: 0 },
		exitCode: "unavailable",
		exitSignal: "SIGABRT",
	};
}

function appendOccurrence(
	target: ReturnType<typeof fixture>,
	options: {
		occurrenceId: string;
		type: string;
		source: string;
		sequence: string;
		terminal: boolean;
		metadata?: Record<string, string | number | boolean | null>;
	},
): void {
	const identity = {
		runId: RUN_ID,
		runToken: TOKEN,
		producerId: PRODUCER_ID,
		occurrenceId: options.occurrenceId,
	};
	const identityKey = createHash("sha256")
		.update(`${RUN_ID}\0${TOKEN}\0${PRODUCER_ID}\0${options.occurrenceId}`)
		.digest("hex");
	const digest = createHash("sha256").update(identityKey).digest("hex");
	const occurrence = {
		version: 1,
		state: "complete",
		identity,
		source: options.source,
		type: options.type,
		encoding: "json",
		payloadKind: options.terminal ? "control" : "derived-scalar",
		terminal: options.terminal,
		metadata: {
			producerPid: 100,
			...(options.type === "supervisor_exit" ? { code: null, signal: "SIGABRT" } : {}),
			...(options.metadata ?? {}),
		},
		eventWallTimeMs: "1700000000000",
		eventMonotonicNs: options.sequence,
		transportIdentity: { wrapperPid: 100, wrapperStartId: "wrapper-start" },
		wrapperOrder: [options.sequence],
		producerOrder: [options.sequence],
		cursors: [`fixture:${options.sequence}`],
		cas: {
			algorithm: "sha256",
			digest,
			bytes: 1,
			path: join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2), `${digest}.blob`),
			compression: "none",
			resolution: "verified",
		},
		compactionDisposition: "compacted_and_cas_resolved",
		journalCanonicalUntilCompactionCommit: true,
	};
	target.internal.appendSegmentRecord({
		idempotencyKey: `occurrence:${identityKey}`,
		runId: RUN_ID,
		sourceId: "occurrence",
		observedAtMs: 1_700_000_000_000,
		order: options.sequence,
		metadata: { version: 1, state: "complete", occurrenceIdentity: identityKey, casDigest: digest },
		payload: Buffer.from(`${JSON.stringify(occurrence)}\n`, "utf8"),
	});
}

function appendGap(target: ReturnType<typeof fixture>, evidence: Record<string, unknown>): void {
	const serializedEvidence = JSON.stringify(evidence);
	const gapIdentity = createHash("sha256").update(serializedEvidence).digest("hex");
	target.internal.appendSegmentRecord({
		idempotencyKey: `gap:${gapIdentity}`,
		runId: RUN_ID,
		sourceId: "gap",
		observedAtMs: 0,
		order: "0",
		metadata: { version: 1, state: "gap_or_uncertainty", gapIdentity },
		payload: Buffer.from(`${JSON.stringify({ version: 1, state: "gap_or_uncertainty", evidence })}\n`, "utf8"),
	});
}

function barrierEvent(kind: "exit" | "terminal"): IncidentRecorderRunHistoryEvent {
	const sequence = kind === "exit" ? "1" : "2";
	const occurrenceId = kind === "exit" ? SUPERVISOR_OCCURRENCE_ID : TERMINAL_OCCURRENCE_ID;
	return {
		identityKey: `service-${kind}`,
		identity: {
			runId: RUN_ID,
			runToken: TOKEN,
			producerId: PRODUCER_ID,
			occurrenceId,
		},
		semanticFingerprint: "a".repeat(64),
		occurrenceReference: `service-${kind}`,
		source: kind === "exit" ? "recorder-events" : "recorder-control",
		type: kind === "exit" ? "supervisor_exit" : "capture_channel_terminal",
		encoding: "json",
		payloadKind: kind === "exit" ? "derived-scalar" : "control",
		terminal: kind === "terminal",
		metadata: {
			producerPid: 100,
			...(kind === "exit" ? { code: null, signal: "SIGABRT" } : {}),
		},
		eventWallTimeMs: "1700000000000",
		eventMonotonicNs: sequence,
		wrapperOrder: [sequence],
		producerOrder: [sequence],
		cursors: [],
		transportIdentity: { wrapperPid: 100, wrapperStartId: "wrapper-start" },
		cas: { digest: "b".repeat(64), bytes: 1, path: "/tmp/service-barrier-fixture.blob" },
	};
}

function barrierCursor(runId: string): IncidentRecorderLiveRunEventsCursor {
	return {
		version: 1,
		runId,
		filterSha256: "c".repeat(64),
		segmentSequence: 0,
		ordinal: 0,
	};
}

function writeServiceBarrierRun(target: ReturnType<typeof fixture>): string {
	const runDir = join(target.agentDir, "incident-recorder", "runs", `2026-09-07T00-00-00.000Z-${RUN_ID}`);
	mkdirSync(runDir, { recursive: true, mode: 0o700 });
	writeFileSync(
		join(runDir, "launch.json"),
		`${JSON.stringify({
			version: 2,
			canonical: false,
			purpose: "content-addressed-launch-index",
			socketPath: join(target.root, "service-barrier.sock"),
			runtimeCategory: "foreign",
			nodeFatalReportsEnabled: false,
			launchArtifact: {
				canonical: false,
				encoding: "derived-diagnostic-json-v1",
				state: "relay-rejected",
				orphanPolicy: "fail-open",
				lifecycleTarget: "real-supervisor-identity",
			},
			derivedCommandSummary: {
				argumentCount: 0,
				flagCategories: [],
				positionalCount: 0,
				redactedValueCount: 0,
				nulSeparated: false,
			},
		})}\n`,
		{ mode: 0o600 },
	);
	writeFileSync(
		join(runDir, "process.json"),
		`${JSON.stringify({
			runToken: TOKEN,
			machineId: "0".repeat(32),
			bootId: "00000000-0000-4000-8000-000000000000",
			systemdInvocationId: null,
			pid: 2_147_483_647,
			processStartId: "proc:1",
			observed: { wallTime: "2026-09-07T00:00:00.000Z", monotonicNs: "1" },
			runtimeCategory: "foreign",
			nodeFatalReportsEnabled: false,
			orphanPolicy: "fail-open",
			wrapperDeathSignalsSupervisor: false,
		})}\n`,
		{ mode: 0o600 },
	);
	writeFileSync(join(runDir, "finalization-barrier-expectation.json"), `${JSON.stringify(expectation())}\n`, {
		mode: 0o600,
	});
	return runDir;
}

class TestSignalSource implements IncidentRecorderServiceSignalSource {
	private readonly listeners = new Map<"SIGINT" | "SIGTERM", () => void>();

	once(signal: "SIGINT" | "SIGTERM", listener: () => void): void {
		this.listeners.set(signal, listener);
	}

	off(signal: "SIGINT" | "SIGTERM", listener: () => void): void {
		if (this.listeners.get(signal) === listener) this.listeners.delete(signal);
	}

	emit(signal: "SIGINT" | "SIGTERM"): void {
		const listener = this.listeners.get(signal);
		this.listeners.delete(signal);
		listener?.();
	}
}

afterEach(() => {
	vi.restoreAllMocks();
	for (const compactor of compactors.splice(0).reverse()) {
		try {
			(compactor as unknown as CompactorInternals).closeSegmentStore();
		} catch {}
	}
	for (const lease of leases.splice(0).reverse()) lease.release();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("incident recorder segmented finalization barrier", () => {
	it("finds exact terminal occurrences after the segment frontier replaces legacy refs", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendOccurrence(target, {
			occurrenceId: SUPERVISOR_OCCURRENCE_ID,
			type: "supervisor_exit",
			source: "recorder-events",
			sequence: "1",
			terminal: false,
		});
		appendOccurrence(target, {
			occurrenceId: TERMINAL_OCCURRENCE_ID,
			type: "capture_channel_terminal",
			source: "recorder-control",
			sequence: "2",
			terminal: true,
		});

		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("complete");
	});

	it("retains an exact terminal match while continuing through bounded occurrence pages", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendOccurrence(target, {
			occurrenceId: SUPERVISOR_OCCURRENCE_ID,
			type: "supervisor_exit",
			source: "recorder-events",
			sequence: "1",
			terminal: false,
		});
		for (let index = 0; index < 63; index += 1) {
			appendOccurrence(target, {
				occurrenceId: `66666666-6666-4666-8666-${index.toString(16).padStart(12, "0")}`,
				type: "diagnostic_heartbeat",
				source: "recorder-events",
				sequence: "3",
				terminal: false,
			});
		}
		appendOccurrence(target, {
			occurrenceId: TERMINAL_OCCURRENCE_ID,
			type: "capture_channel_terminal",
			source: "recorder-control",
			sequence: "2",
			terminal: true,
		});

		const firstPage = readCompactedFinalizationBarrier({
			runDir: target.root,
			expectation: expectation(),
			compactor: target.compactor,
		});
		expect(firstPage).toBe("pending");
		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("complete");
	});

	it("lets service inspection pass the segmented barrier before later capture gates", async () => {
		const target = fixture();
		mkdirSync(join(target.agentDir, "incident-recorder"), { recursive: true, mode: 0o700 });
		mkdirSync(join(target.agentDir, "incidents"), { recursive: true, mode: 0o700 });
		const signals = new TestSignalSource();
		const eventsReader = vi.spyOn(IncidentRecorderCompactor.prototype, "readLiveRunEvents").mockImplementation(
			({ runId }): IncidentRecorderLiveRunEventsPage => ({
				version: 1,
				runId,
				state: "complete",
				events: [barrierEvent("exit"), barrierEvent("terminal")],
				cursor: barrierCursor(runId),
				scannedSegments: 1,
				scannedRecords: 2,
				scannedIndexBytes: 1,
			}),
		);
		vi.spyOn(IncidentRecorderCompactor.prototype, "readLiveRunGaps").mockImplementation(
			({ runId }): IncidentRecorderLiveRunGapsPage => ({
				version: 1,
				runId,
				state: "complete",
				gaps: [],
				cursor: barrierCursor(runId),
				scannedSegments: 1,
				scannedRecords: 0,
				scannedIndexBytes: 1,
			}),
		);
		vi.spyOn(IncidentRecorderWriter.prototype, "start").mockResolvedValue(undefined);
		vi.spyOn(IncidentRecorderWriter.prototype, "journalReady", "get").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "storageMode", "get").mockReturnValue("normal");
		vi.spyOn(IncidentRecorderCompactor.prototype, "admitObservation").mockReturnValue(true);
		vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			const [options] = args;
			options.onStorageMode?.("normal");
			const admission = await options.onNormalWriterAdmission?.();
			if (admission !== true) throw new Error("barrier fixture normal admission failed");
			options.onReaderReady?.();
			await new Promise<void>((resolve) => {
				if (options.signal.aborted) {
					resolve();
					return;
				}
				options.signal.addEventListener("abort", () => resolve(), { once: true });
			});
		});
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		const running = runIncidentRecorderService(target.agentDir, {
			writerLifecycleContract: {
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			},
			notify: (fields) => {
				if (fields.includes("READY=1")) resolveReady();
			},
			signalSource: signals,
			writerStopDeadlineMs: 1_000,
		});
		running.catch(() => {});
		try {
			await ready;
			const runDir = writeServiceBarrierRun(target);
			await inspectIncidentRecorderRuns(target.agentDir, Date.now());
			expect(eventsReader).toHaveBeenCalled();
			expect(existsSync(join(runDir, ".service-finalization-pending"))).toBe(false);
		} finally {
			signals.emit("SIGTERM");
			await running;
		}
	});

	it("does not accept wrong occurrence identity or sequence ranges", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendOccurrence(target, {
			occurrenceId: SUPERVISOR_OCCURRENCE_ID,
			type: "supervisor_exit",
			source: "recorder-events",
			sequence: "9",
			terminal: false,
		});
		appendOccurrence(target, {
			occurrenceId: TERMINAL_OCCURRENCE_ID,
			type: "capture_channel_terminal",
			source: "recorder-control",
			sequence: "10",
			terminal: true,
		});

		const result = readCompactedFinalizationBarrier({
			runDir: target.root,
			expectation: expectation(),
			compactor: target.compactor,
		});
		expect(result).toBe("pending");
		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation("66666666-6666-4666-8666-666666666666"),
				compactor: target.compactor,
			}),
		).toBe("pending");
	});

	it("does not combine producer coverage for one frontier with wrapper coverage for another", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendGap(target, {
			runId: RUN_ID,
			runToken: TOKEN,
			streamKeyHash: "b".repeat(64),
			producerId: PRODUCER_ID,
			expectedProducerFrom: "1",
			expectedProducerThrough: "1",
			wrapperPid: 100,
			wrapperStartId: "wrapper-start",
			expectedWrapperFrom: "2",
			expectedWrapperThrough: "2",
		});
		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("pending");
	});

	it("returns incomplete when bounded gap proof overflows alongside a matching proof", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendOccurrence(target, {
			occurrenceId: TERMINAL_OCCURRENCE_ID,
			type: "capture_channel_terminal",
			source: "recorder-control",
			sequence: "2",
			terminal: true,
		});
		for (let index = 0; index < 64; index += 1) {
			appendGap(target, {
				runId: RUN_ID,
				runToken: TOKEN,
				streamKeyHash: index.toString(16).padStart(64, "0"),
				producerId: PRODUCER_ID,
				expectedProducerFrom: "1",
				expectedProducerThrough: "1",
				wrapperPid: 100,
				wrapperStartId: "wrapper-start",
				expectedWrapperFrom: "2",
				expectedWrapperThrough: "2",
			});
		}
		appendGap(target, {
			runId: RUN_ID,
			runToken: TOKEN,
			streamKeyHash: "e".repeat(64),
			producerId: PRODUCER_ID,
			expectedProducerFrom: "1",
			expectedProducerThrough: "1",
			wrapperPid: 100,
			wrapperStartId: "wrapper-start",
			expectedWrapperFrom: "1",
			expectedWrapperThrough: "1",
		});

		const firstPage = readCompactedFinalizationBarrier({
			runDir: target.root,
			expectation: expectation(),
			compactor: target.compactor,
		});
		expect(firstPage).toBe("pending");
		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("incomplete");
		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("incomplete");
	});

	it("retains one frontier gap proof while reading the next bounded gap page", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendGap(target, {
			runId: RUN_ID,
			runToken: TOKEN,
			streamKeyHash: "d".repeat(64),
			producerId: PRODUCER_ID,
			expectedProducerFrom: "1",
			expectedProducerThrough: "1",
			wrapperPid: 100,
			wrapperStartId: "wrapper-start",
			expectedWrapperFrom: "1",
			expectedWrapperThrough: "1",
		});
		for (let index = 0; index < 63; index += 1) {
			appendGap(target, {
				runId: RUN_ID,
				runToken: TOKEN,
				streamKeyHash: (index + 1).toString(16).padStart(64, "0"),
				producerId: "66666666-6666-4666-8666-666666666666",
				expectedProducerFrom: "1",
				expectedProducerThrough: "1",
				wrapperPid: 101,
				wrapperStartId: "other-wrapper",
				expectedWrapperFrom: "1",
				expectedWrapperThrough: "1",
			});
		}
		appendGap(target, {
			runId: RUN_ID,
			runToken: TOKEN,
			streamKeyHash: "e".repeat(64),
			producerId: PRODUCER_ID,
			expectedProducerFrom: "2",
			expectedProducerThrough: "2",
			wrapperPid: 100,
			wrapperStartId: "wrapper-start",
			expectedWrapperFrom: "2",
			expectedWrapperThrough: "2",
		});

		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("pending");
		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("complete");
	});

	it("combines one exact segmented frontier with an independently covered gap frontier", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendOccurrence(target, {
			occurrenceId: SUPERVISOR_OCCURRENCE_ID,
			type: "supervisor_exit",
			source: "recorder-events",
			sequence: "1",
			terminal: false,
		});
		appendGap(target, {
			runId: RUN_ID,
			runToken: TOKEN,
			streamKeyHash: "c".repeat(64),
			producerId: PRODUCER_ID,
			expectedProducerFrom: "2",
			expectedProducerThrough: "2",
			wrapperPid: 100,
			wrapperStartId: "wrapper-start",
			expectedWrapperFrom: "2",
			expectedWrapperThrough: "2",
		});

		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("complete");
	});

	it("combines a legacy frontier proof with a segmented frontier during migration", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendOccurrence(target, {
			occurrenceId: TERMINAL_OCCURRENCE_ID,
			type: "capture_channel_terminal",
			source: "recorder-control",
			sequence: "2",
			terminal: true,
		});

		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
				legacyProof: { supervisorExit: true, wrapperTerminal: false },
			}),
		).toBe("complete");
	});

	it("accepts a matching segmented gap covering both terminal ranges", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		appendGap(target, {
			runId: RUN_ID,
			runToken: TOKEN,
			streamKeyHash: "a".repeat(64),
			producerId: PRODUCER_ID,
			expectedProducerFrom: "1",
			expectedProducerThrough: "2",
			wrapperPid: 100,
			wrapperStartId: "wrapper-start",
			expectedWrapperFrom: "1",
			expectedWrapperThrough: "2",
		});

		expect(
			readCompactedFinalizationBarrier({
				runDir: target.root,
				expectation: expectation(),
				compactor: target.compactor,
			}),
		).toBe("complete");
	});
});
