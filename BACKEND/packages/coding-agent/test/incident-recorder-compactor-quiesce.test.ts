import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderSegmentStore } from "../src/modes/daemon/incident-recorder-segment-store.js";
import type { IncidentJournalLine } from "../src/modes/daemon/incident-recorder-writer.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	acquireIncidentRecorderWriterRecoveryLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const roots: string[] = [];
const lifecycleLeases: IncidentRecorderWriterLifecycleLease[] = [];
const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const OCCURRENCE_ID = "44444444-4444-4444-8444-444444444444";
const MACHINE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOOT_ID = "55555555-5555-4555-8555-555555555555";

interface CompactorInternals {
	acceptEntry(fields: Record<string, Buffer>): void;
	appendSegmentRecord(input: {
		idempotencyKey?: string;
		runId: string;
		sourceId: string;
		observedAtMs: number;
		order: string;
		metadata: Record<string, never>;
		payload: Buffer;
	}): unknown;
	activePinScans: Map<string, unknown>;
	assemblies: Map<string, unknown>;
	pendingEntries: unknown[];
	pendingPinDirectoryTraversal?: { directory?: { closeSync(): void } };
	pinReadersQuiescing: boolean;
	segmentStore?: IncidentRecorderSegmentStore;
	startPinRangeScan(
		incidentDir: string,
		request: { runId: string; anchorWallTimeMs: number; fromWallTimeMs: number; throughWallTimeMs: number },
	): void;
}

afterEach(() => {
	vi.restoreAllMocks();
	delete process.env.PRIME_TEST_COMPACTOR_QUIESCE_MARKER;
	delete process.env.PRIME_TEST_COMPACTOR_QUIESCE_STORAGE_LINES;
	for (const lease of lifecycleLeases.splice(0).reverse()) lease.release();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function executable(root: string, name: string, source: string): string {
	const path = join(root, name);
	writeFileSync(path, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
	chmodSync(path, 0o700);
	return path;
}

function fixture(options: Partial<ConstructorParameters<typeof IncidentRecorderCompactor>[0]> = {}): {
	root: string;
	agentDir: string;
	compactor: IncidentRecorderCompactor;
	internal: CompactorInternals;
} {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-compactor-quiesce-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const scanner = executable(
		root,
		"storage-scanner.cjs",
		'process.stdout.write(process.env.PRIME_TEST_COMPACTOR_QUIESCE_STORAGE_LINES??"1\\t1\\t0\\t0\\n");',
	);
	const compactor = new IncidentRecorderCompactor({
		agentDir,
		storageScannerPath: scanner,
		freeReserveBytes: 0,
		...options,
	});
	return { root, agentDir, compactor, internal: compactor as unknown as CompactorInternals };
}

function lifecycleFixture(options: Partial<ConstructorParameters<typeof IncidentRecorderCompactor>[0]> = {}): {
	target: ReturnType<typeof fixture>;
	currentLease: () => IncidentRecorderWriterLifecycleLease | undefined;
	releaseCurrentLease: () => void;
	acquireNormalLease: () => IncidentRecorderWriterLifecycleLease;
	acquireRecoveryLease: () => IncidentRecorderWriterLifecycleLease;
} {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-compactor-quiesce-lifecycle-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const scanner = executable(
		root,
		"storage-scanner.cjs",
		'process.stdout.write(process.env.PRIME_TEST_COMPACTOR_QUIESCE_STORAGE_LINES??"1\\t1\\t0\\t0\\n");',
	);
	const contract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: "a".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: acquireIncidentRecorderNamespaceCas,
	};
	let lease: IncidentRecorderWriterLifecycleLease | undefined;
	const acquireNormalLease = (): IncidentRecorderWriterLifecycleLease => {
		const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, contract);
		if (admission.state !== "acquired") throw new Error(`normal lease unavailable: ${admission.reason}`);
		lease = admission.lease;
		lifecycleLeases.push(lease);
		return lease;
	};
	const acquireRecoveryLease = (): IncidentRecorderWriterLifecycleLease => {
		const admission = acquireIncidentRecorderWriterRecoveryLease({ agentDir }, contract);
		if (admission.state !== "acquired") throw new Error(`recovery lease unavailable: ${admission.reason}`);
		lease = admission.lease;
		lifecycleLeases.push(lease);
		return lease;
	};
	const releaseCurrentLease = (): void => {
		lease?.release();
		lease = undefined;
	};
	const compactor = new IncidentRecorderCompactor({
		...options,
		agentDir,
		storageScannerPath: scanner,
		freeReserveBytes: 0,
		writerLifecycleLease: () => lease,
	});
	return {
		target: { root, agentDir, compactor, internal: compactor as unknown as CompactorInternals },
		currentLease: () => lease,
		releaseCurrentLease,
		acquireNormalLease,
		acquireRecoveryLease,
	};
}

async function initialize(compactor: IncidentRecorderCompactor): Promise<void> {
	await compactor.initializeStorageAccounting(new AbortController().signal);
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error("timed out waiting for isolated compactor fixture");
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

function multiChunkJournalFields(chunkIndex: 0 | 1): Record<string, Buffer> {
	const chunks = [Buffer.from("quiesce-multi-chunk-first"), Buffer.from("quiesce-multi-chunk-last")];
	const payload = chunks[chunkIndex];
	if (!payload) throw new Error(`missing test payload ${chunkIndex}`);
	const occurrence = Buffer.concat(chunks);
	const occurrenceSha256 = createHash("sha256").update(occurrence).digest("hex");
	const eventWallTimeMs = "1700000000000";
	const eventMonotonicNs = "1000";
	const metadata = { occurrenceRawBytes: occurrence.length, occurrenceSha256 };
	const frame = encodeIncidentRecorderFrame(
		{
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			producerId: PRODUCER_ID,
			occurrenceId: OCCURRENCE_ID,
			producerSequence: BigInt(chunkIndex + 1),
			wallTimeMs: BigInt(eventWallTimeMs),
			monotonicNs: BigInt(eventMonotonicNs),
			payloadKind: "exact-bytes",
			flags: chunkIndex === 0 ? INCIDENT_RECORDER_FRAME_FLAGS.firstChunk : INCIDENT_RECORDER_FRAME_FLAGS.lastChunk,
			chunkIndex,
			chunkCount: chunks.length,
			source: "quiesce-test",
			type: "multi-chunk-occurrence",
			encoding: "binary",
			metadata,
		},
		payload,
	);
	const line: IncidentJournalLine = {
		schema: "prime-agent-raw-v1",
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		producerId: PRODUCER_ID,
		producerSequence: String(chunkIndex + 1),
		wrapperSequence: String(chunkIndex + 1),
		occurrenceId: OCCURRENCE_ID,
		chunkIndex,
		chunkCount: chunks.length,
		source: "quiesce-test",
		type: "multi-chunk-occurrence",
		encoding: "binary",
		payloadKind: "exact-bytes",
		producerPid: null,
		producerStartId: null,
		wrapperPid: 456,
		wrapperStartId: "wrapper-start",
		targetPid: null,
		targetStartId: null,
		bootId: BOOT_ID,
		machineId: MACHINE_ID,
		systemdInvocationId: null,
		systemdCatPid: 123,
		systemdCatStartId: "systemd-cat-start",
		eventWallTimeMs,
		eventMonotonicNs,
		rawOccurrenceBytes: occurrence.length,
		occurrenceSha256,
		chunkBytes: payload.length,
		chunkSha256: createHash("sha256").update(payload).digest("hex"),
		frameChecksum: frame.header.checksum,
		flags: frame.header.flags,
		metadata,
		payloadBase64: payload.toString("base64"),
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
	const fields: Record<string, Buffer> = {};
	for (const [key, value] of Object.entries({
		__CURSOR: `s=quiesce-replay-${chunkIndex + 1}`,
		_MACHINE_ID: MACHINE_ID,
		_BOOT_ID: BOOT_ID,
		_STREAM_ID: "quiesce-stream",
		__REALTIME_TIMESTAMP: `${BigInt(eventWallTimeMs) * 1_000n}`,
		__MONOTONIC_TIMESTAMP: `${BigInt(eventMonotonicNs) / 1_000n}`,
		_PID: "123",
		_UID: "1000",
		SYSLOG_IDENTIFIER: "prime-agent-raw-v1",
		_TRANSPORT: "stdout",
		MESSAGE: JSON.stringify(line),
	}))
		fields[key] = Buffer.from(value, "utf8");
	return fields;
}

describe("incident recorder compactor lifecycle quiescence", () => {
	it("closes the real segment writer before lifecycle handoff", async () => {
		const target = fixture();
		await initialize(target.compactor);
		target.internal.appendSegmentRecord({
			idempotencyKey: "quiesce-segment",
			runId: "quiesce-run",
			sourceId: "control",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("quiesce"),
		});
		const store = target.internal.segmentStore;
		expect(store).toBeDefined();

		await target.compactor.closeWriterResourcesForLifecycle(1_000);

		expect(target.internal.segmentStore).toBeUndefined();
	});

	it("terminates and drains an active pin reader without allowing its stale callback to publish", async () => {
		const target = fixture();
		const marker = join(target.root, "pin-reader-marker");
		process.env.PRIME_TEST_COMPACTOR_QUIESCE_MARKER = marker;
		const journal = executable(
			target.root,
			"journalctl.cjs",
			'const fs=require("node:fs");const marker=process.env.PRIME_TEST_COMPACTOR_QUIESCE_MARKER;fs.writeFileSync(marker,String(process.pid));process.once("SIGTERM",()=>{fs.appendFileSync(marker,"\\nterm");process.exit(0);});setInterval(()=>{},1000);',
		);
		const incidentDir = join(target.agentDir, "incidents", "quiesce-pin");
		mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
		const request = { runId: "quiesce-run", anchorWallTimeMs: 1, fromWallTimeMs: 0, throughWallTimeMs: 2 };
		const scan = target.internal.startPinRangeScan.bind(target.compactor);
		Object.assign(target.compactor, {
			options: { ...(target.compactor as unknown as { options: object }).options, journalctlPath: journal },
		});
		scan(incidentDir, request);
		await waitFor(() => target.internal.activePinScans.size === 1 && existsSync(marker));

		await target.compactor.closeWriterResourcesForLifecycle(1_000);

		await waitFor(() => target.internal.activePinScans.size === 0);
		expect(readFileSync(marker, "utf8")).toContain("term");
		expect(existsSync(join(incidentDir, "journal-pin-scan-proof.json"))).toBe(false);
	});

	it("retains a failed segment close so a second stop cannot masquerade as quiesced", async () => {
		const target = fixture();
		await initialize(target.compactor);
		target.internal.appendSegmentRecord({
			idempotencyKey: "quiesce-close-failure",
			runId: "quiesce-run",
			sourceId: "control",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("quiesce"),
		});
		const store = target.internal.segmentStore;
		if (!store) throw new Error("expected a real segment store");
		const close = vi.spyOn(store, "close").mockImplementation(() => {
			throw new Error("injected close failure");
		});

		await expect(target.compactor.closeWriterResourcesForLifecycle(1_000)).rejects.toThrow("did not quiesce");
		expect(target.internal.segmentStore).toBe(store);
		await expect(target.compactor.closeWriterResourcesForLifecycle(1_000)).rejects.toThrow("did not quiesce");
		expect(close).toHaveBeenCalledOnce();
	});

	it("retries a pending descriptor close after the first bounded stop fails", async () => {
		const target = fixture();
		const closeSync = vi
			.fn<() => void>()
			.mockImplementationOnce(() => {
				throw new Error("injected directory close failure");
			})
			.mockImplementation(() => {});
		Object.assign(target.internal, {
			pendingPinDirectoryTraversal: {
				phase: "full",
				pendingNames: [],
				pendingNameBytes: 0,
				directory: { closeSync },
			},
		});

		await expect(target.compactor.closeWriterResourcesForLifecycle(1_000)).rejects.toThrow("did not quiesce");
		expect(target.internal.pendingPinDirectoryTraversal).toBeDefined();
		await expect(target.compactor.closeWriterResourcesForLifecycle(1_000)).resolves.toBeUndefined();
		expect(target.internal.pendingPinDirectoryTraversal).toBeUndefined();
		expect(closeSync).toHaveBeenCalledTimes(2);
	});

	it("requires recovery exclusion and a fresh normal lease before resuming pin readers", async () => {
		const lifecycle = lifecycleFixture();
		await initialize(lifecycle.target.compactor);
		const normal = lifecycle.acquireNormalLease();
		await lifecycle.target.compactor.closeWriterResourcesForLifecycle(1_000);
		expect(lifecycle.target.internal.pinReadersQuiescing).toBe(true);
		const recoveryWhileNormal = acquireIncidentRecorderWriterRecoveryLease(
			{ agentDir: lifecycle.target.agentDir },
			{
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			},
		);
		expect(recoveryWhileNormal.state).toBe("pending");
		normal.release();
		const recovery = lifecycle.acquireRecoveryLease();
		expect(recovery).toBeDefined();
		recovery.release();
		lifecycle.releaseCurrentLease();
		lifecycle.acquireNormalLease();

		lifecycle.target.compactor.resumeWriterResourcesForLifecycle();

		expect(lifecycle.target.internal.pinReadersQuiescing).toBe(false);
	});

	it("discards a volatile multi-chunk frontier under storage pressure and replays it once", async () => {
		const lifecycle = lifecycleFixture({
			storageHighWaterBytes: 64 * 1024 * 1024,
			storageLowWaterBytes: 32 * 1024 * 1024,
			storageHighWaterInodes: 100,
			storageLowWaterInodes: 100,
			storageHighWaterEntries: 100,
			storageLowWaterEntries: 100,
		});
		await initialize(lifecycle.target.compactor);
		lifecycle.acquireNormalLease();
		const firstChunk = multiChunkJournalFields(0);
		lifecycle.target.internal.acceptEntry(firstChunk);
		expect(lifecycle.target.internal.assemblies.size).toBe(1);
		expect(lifecycle.target.internal.pendingEntries).toHaveLength(1);
		expect(existsSync(join(lifecycle.target.agentDir, "incident-recorder", "compactor-cursor.json"))).toBe(false);

		process.env.PRIME_TEST_COMPACTOR_QUIESCE_STORAGE_LINES = "1\t1\t134217728\t0\n";
		await initialize(lifecycle.target.compactor);
		expect(lifecycle.target.compactor.storageMode).toBe("recovery-only");
		expect(lifecycle.target.internal.assemblies.size).toBe(1);
		expect(lifecycle.target.internal.pendingEntries).toHaveLength(1);

		await lifecycle.target.compactor.closeWriterResourcesForLifecycle(1_000);
		expect(lifecycle.target.internal.assemblies.size).toBe(0);
		expect(lifecycle.target.internal.pendingEntries).toHaveLength(0);
		expect(existsSync(join(lifecycle.target.agentDir, "incident-recorder", "compactor-cursor.json"))).toBe(false);

		lifecycle.releaseCurrentLease();
		lifecycle.acquireRecoveryLease();
		lifecycle.releaseCurrentLease();
		process.env.PRIME_TEST_COMPACTOR_QUIESCE_STORAGE_LINES = "1\t1\t0\t0\n";
		await initialize(lifecycle.target.compactor);
		lifecycle.acquireNormalLease();
		lifecycle.target.compactor.resumeWriterResourcesForLifecycle();
		expect(lifecycle.target.internal.pinReadersQuiescing).toBe(false);

		lifecycle.target.internal.acceptEntry(firstChunk);
		lifecycle.target.internal.acceptEntry(multiChunkJournalFields(1));
		await lifecycle.target.compactor.closeWriterResourcesForLifecycle(1_000);

		const store = new IncidentRecorderSegmentStore({
			directory: join(lifecycle.target.agentDir, "incident-recorder", "segments"),
		});
		try {
			const occurrences = store.queryRunWindow({
				runId: RUN_ID,
				sourceId: "occurrence",
				fromObservedAtMs: 0,
				throughObservedAtMs: Number.MAX_SAFE_INTEGER,
			});
			expect(occurrences).toHaveLength(1);
			expect(occurrences[0]?.payload.toString("utf8")).toContain("compacted_and_cas_resolved");
			const references = store.queryRunWindow({
				runId: RUN_ID,
				sourceId: "journal-reference",
				fromObservedAtMs: 0,
				throughObservedAtMs: Number.MAX_SAFE_INTEGER,
			});
			expect(references).toHaveLength(2);
		} finally {
			store.close();
		}
		const checkpoint = JSON.parse(
			readFileSync(join(lifecycle.target.agentDir, "incident-recorder", "compactor-cursor.json"), "utf8"),
		) as { cursor?: string };
		expect(checkpoint.cursor).toBe("s=quiesce-replay-2");
	});

	it("does not resume after a failed cleanup", async () => {
		const lifecycle = lifecycleFixture();
		await initialize(lifecycle.target.compactor);
		lifecycle.acquireNormalLease();
		const closeSync = vi.fn<() => void>(() => {
			throw new Error("injected directory close failure");
		});
		Object.assign(lifecycle.target.internal, {
			pendingPinDirectoryTraversal: {
				phase: "full",
				pendingNames: [],
				pendingNameBytes: 0,
				directory: { closeSync },
			},
		});
		await expect(lifecycle.target.compactor.closeWriterResourcesForLifecycle(1_000)).rejects.toThrow(
			"did not quiesce",
		);
		expect(() => lifecycle.target.compactor.resumeWriterResourcesForLifecycle()).toThrow("not_quiescent");
		expect(lifecycle.target.internal.pinReadersQuiescing).toBe(true);
	});
});
