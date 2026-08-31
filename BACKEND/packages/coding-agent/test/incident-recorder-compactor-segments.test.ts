import { createHash } from "node:crypto";
import {
	appendFileSync,
	chmodSync,
	closeSync,
	constants as fsConstants,
	existsSync,
	fchmodSync,
	fstatSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readFileSync,
	readlinkSync,
	readdirSync,
	renameSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderRunHistoryCursor,
	type IncidentRecorderRunHistoryResult,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import {
	createIncidentRecorderSegmentPruneProtection,
	IncidentRecorderSegmentStore,
	type IncidentRecorderSegmentAppendInput,
	type IncidentRecorderSegmentLocator,
} from "../src/modes/daemon/incident-recorder-segment-store.js";
import type { IncidentJournalLine } from "../src/modes/daemon/incident-recorder-writer.js";

const roots: string[] = [];
const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const DAY = 24 * 60 * 60 * 1_000;

interface ProcfsAuthorityInternals {
	rootDescriptor: number;
	descriptorDirectoryDescriptor: number;
	descriptorInfoDirectoryDescriptor: number;
}

interface CompactorInternals {
	appendSegmentRecord(input: IncidentRecorderSegmentAppendInput): IncidentRecorderSegmentLocator;
	assemblies: Map<string, unknown>;
	closeSegmentStore(): void;
	readStableLegacyOccurrence(path: string, canonicalPath?: string): { value: unknown; bytes: number };
	openStableRunHistoryDirectory(path: string): { descriptor: number; identity: unknown };
	segmentStore?: IncidentRecorderSegmentStore;
	runHistoryTraversals: Map<
		string,
		{
			deadlineTimer?: { hasRef(): boolean };
			directory?: { path: string };
			legacyNamespaceDescriptor?: number;
			legacyDirectoryDescriptor?: number;
			procfsAuthority?: ProcfsAuthorityInternals;
			activeCasValidation?: {
				fileDescriptor: number;
				directoryFences: Array<{ descriptor: number }>;
				procfsAuthority: ProcfsAuthorityInternals;
			};
		}
	>;
	publishCasAndRunLease(input: {
		runId: string;
		digest: string;
		bytes: number;
		value?: Buffer;
		stagedPath?: string;
	}): { casPath: string; leasePath: string };
	writeJournalReference(input: {
		fields: Readonly<Record<string, Buffer>>;
		cursor: string;
		machineId: string;
		bootId: string;
		invocationId: string | null;
		streamId: string;
		realtimeUs: string;
		monotonicUs: string;
		messageBytes: Buffer;
	}): { id: string; path: string };
}

afterEach(() => {
	vi.useRealTimers();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function executable(root: string, name: string, source: string): string {
	const path = join(root, name);
	writeFileSync(path, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
	chmodSync(path, 0o700);
	return path;
}

function fixture(
	options: Partial<ConstructorParameters<typeof IncidentRecorderCompactor>[0]> = {},
): {
	root: string;
	agentDir: string;
	compactor: IncidentRecorderCompactor;
	internal: CompactorInternals;
} {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-compactor-segments-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const scanner = executable(root, "storage-scanner.cjs", 'process.stdout.write("1\\t1\\t0\\t0\\n");');
	const compactor = new IncidentRecorderCompactor({
		agentDir,
		storageScannerPath: scanner,
		freeReserveBytes: 0,
		...options,
	});
	return { root, agentDir, compactor, internal: compactor as unknown as CompactorInternals };
}

async function initialize(compactor: IncidentRecorderCompactor): Promise<void> {
	await compactor.initializeStorageAccounting(new AbortController().signal);
}

function occurrenceId(index: number): string {
	return `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function partialJournalEntry(index: number, sequence: number): string {
	const chunks = [Buffer.from(`partial-${index}-first`), Buffer.from(`partial-${index}-last`)];
	const occurrence = Buffer.concat(chunks);
	const occurrenceSha256 = createHash("sha256").update(occurrence).digest("hex");
	const eventWallTimeMs = String(1_700_000_000_000 + index);
	const eventMonotonicNs = String(1_000 + index);
	const metadata = { occurrenceRawBytes: occurrence.length, occurrenceSha256 };
	const payload = chunks[0] ?? Buffer.alloc(0);
	const frame = encodeIncidentRecorderFrame(
		{
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			producerId: PRODUCER_ID,
			occurrenceId: occurrenceId(index),
			producerSequence: BigInt(sequence),
			wallTimeMs: BigInt(eventWallTimeMs),
			monotonicNs: BigInt(eventMonotonicNs),
			payloadKind: "exact-bytes",
			flags: INCIDENT_RECORDER_FRAME_FLAGS.firstChunk,
			chunkIndex: 0,
			chunkCount: chunks.length,
			source: "shutdown-test",
			type: "partial-occurrence",
			encoding: "binary",
			metadata,
		},
		payload,
	);
	const machineId = "11111111111111111111111111111111";
	const bootId = "22222222-2222-4222-8222-222222222222";
	const line: IncidentJournalLine = {
		schema: "prime-agent-raw-v1",
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		producerId: PRODUCER_ID,
		producerSequence: String(sequence),
		wrapperSequence: String(sequence),
		occurrenceId: occurrenceId(index),
		chunkIndex: 0,
		chunkCount: chunks.length,
		source: "shutdown-test",
		type: "partial-occurrence",
		encoding: "binary",
		payloadKind: "exact-bytes",
		producerPid: null,
		producerStartId: null,
		wrapperPid: 456,
		wrapperStartId: "wrapper-start",
		targetPid: null,
		targetStartId: null,
		bootId,
		machineId,
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
	return [
		`__CURSOR=s=partial-shutdown-${index}`,
		`_MACHINE_ID=${machineId}`,
		`_BOOT_ID=${bootId}`,
		"_STREAM_ID=shutdown-stream",
		`__REALTIME_TIMESTAMP=${BigInt(eventWallTimeMs) * 1_000n}`,
		`__MONOTONIC_TIMESTAMP=${BigInt(eventMonotonicNs) / 1_000n}`,
		"_PID=123",
		"_UID=1000",
		"SYSLOG_IDENTIFIER=prime-agent-raw-v1",
		"_TRANSPORT=stdout",
		`MESSAGE=${JSON.stringify(line)}`,
		"",
		"",
	].join("\n");
}

function occurrenceIdentity(
	index: number,
	producerId = PRODUCER_ID,
): { occurrenceId: string; identityKey: string } {
	const id = occurrenceId(index);
	return {
		occurrenceId: id,
		identityKey: createHash("sha256").update(`${RUN_ID}\0${RUN_TOKEN}\0${producerId}\0${id}`).digest("hex"),
	};
}

interface OccurrenceOverrides {
	producerId?: string;
	source?: string;
	type?: string;
	terminal?: boolean;
	eventWallTimeMs?: string;
	eventMonotonicNs?: string;
	wrapperOrder?: string[];
	producerOrder?: string[];
	cursors?: string[];
	transportIdentity?: Record<string, unknown>;
	casBytes?: number;
}

function occurrenceInput(
	index: number,
	anchor: number,
	digest: string,
	casPath: string,
	overrides: OccurrenceOverrides = {},
): { input: IncidentRecorderSegmentAppendInput; payload: Record<string, unknown>; cursor: string; identityKey: string } {
	const producerId = overrides.producerId ?? PRODUCER_ID;
	const identity = occurrenceIdentity(index, producerId);
	const cursor = `cursor-${index}`;
	const cursors = overrides.cursors ?? [cursor];
	const wrapperOrder = overrides.wrapperOrder ?? [String(index + 1)];
	const producerOrder = overrides.producerOrder ?? [String(index + 1)];
	const eventWallTimeMs = overrides.eventWallTimeMs ?? String(anchor + index);
	const payload = {
		version: 1,
		state: "complete",
		identity: {
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			producerId,
			occurrenceId: identity.occurrenceId,
		},
		source: overrides.source ?? "kernel",
		type: overrides.type ?? "kernel_unexpected_exit",
		encoding: "binary",
		payloadKind: "exact-bytes",
		terminal: overrides.terminal ?? true,
		metadata: {},
		eventWallTimeMs,
		eventMonotonicNs: overrides.eventMonotonicNs ?? String(index),
		transportIdentity: overrides.transportIdentity ?? {},
		wrapperOrder,
		producerOrder,
		cursors,
		journalReferences: [],
		cas: {
			algorithm: "sha256",
			digest,
			bytes: overrides.casBytes ?? 1,
			path: casPath,
			compression: "none",
			resolution: "verified",
		},
		compactionDisposition: "compacted_and_cas_resolved",
		journalCanonicalUntilCompactionCommit: true,
	};
	return {
		input: {
			idempotencyKey: `occurrence:${identity.identityKey}`,
			runId: RUN_ID,
			sourceId: "occurrence",
			observedAtMs: Number(eventWallTimeMs),
			order: wrapperOrder[0] ?? "0",
			metadata: { version: 1, state: "complete", occurrenceIdentity: identity.identityKey, casDigest: digest },
			payload: Buffer.from(`${JSON.stringify(payload)}\n`, "utf8"),
		},
		payload,
		cursor,
		identityKey: identity.identityKey,
	};
}

function writeLegacyOccurrence(
	target: ReturnType<typeof fixture>,
	occurrence: ReturnType<typeof occurrenceInput>,
	sequence: number,
	payload: Record<string, unknown> = occurrence.payload,
): { directory: string; path: string } {
	const directory = join(
		target.agentDir,
		"incident-recorder",
		"refs",
		"runs",
		createHash("sha256").update(RUN_ID).digest("hex"),
	);
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	const path = join(
		directory,
		`seq-${String(sequence).padStart(20, "0")}-${occurrence.identityKey}.json`,
	);
	writeFileSync(path, `${JSON.stringify(payload)}\n`, { mode: 0o600 });
	return { directory, path };
}

function preparePinFixture(target: ReturnType<typeof fixture>, anchor: number): {
	incidentDir: string;
	digest: string;
	casPath: string;
} {
	const incidentDir = join(target.agentDir, "incidents", "segment-pin");
	mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
	const digest = createHash("sha256").update("x").digest("hex");
	const casPath = join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
	mkdirSync(dirname(casPath), { recursive: true, mode: 0o700 });
	writeFileSync(casPath, "x", { mode: 0o600 });
	writeFileSync(
		join(incidentDir, "journal-pin-request.json"),
		`${JSON.stringify({
			version: 1,
			state: "pending",
			runId: RUN_ID,
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
			resolveAfterWallTimeMs: anchor,
			retainUntilWallTimeMs: anchor + 3 * DAY,
		})}\n`,
		{ mode: 0o600 },
	);
	return { incidentDir, digest, casPath };
}

function writeCasFixture(target: ReturnType<typeof fixture>, value: Buffer): {
	digest: string;
	casPath: string;
} {
	const digest = createHash("sha256").update(value).digest("hex");
	const casPath = join(
		target.agentDir,
		"incident-recorder",
		"cas",
		"sha256",
		digest.slice(0, 2),
		`${digest}.blob`,
	);
	mkdirSync(dirname(casPath), { recursive: true, mode: 0o700 });
	writeFileSync(casPath, value, { mode: 0o600 });
	return { digest, casPath };
}

function highestObservedDescriptor(): number {
	const descriptors = readdirSync("/proc/thread-self/fd")
		.map((name) => Number(name))
		.filter((value) => Number.isSafeInteger(value) && value >= 0);
	return Math.max(32, ...descriptors);
}

function writeSyntheticFdinfoDirectory(directory: string, content: string): void {
	for (let descriptor = 0; descriptor <= highestObservedDescriptor() + 64; descriptor += 1) {
		writeFileSync(join(directory, String(descriptor)), content, { mode: 0o600 });
	}
}

function currentProcfsMountId(): bigint {
	const descriptor = openSync(
		"/proc",
		fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
	);
	try {
		const match = /^mnt_id:\s+([0-9]+)$/m.exec(
			readFileSync(join("/proc/thread-self/fdinfo", String(descriptor)), "utf8"),
		);
		if (match && BigInt(match[1] ?? "0") > 0n) return BigInt(match[1] ?? "0");
	} finally {
		closeSync(descriptor);
	}
	throw new Error("expected a positive procfs mount ID");
}

function descriptorsPointingTo(path: string): number[] {
	return readdirSync("/proc/thread-self/fd")
		.map((name) => Number(name))
		.filter((descriptor) => {
			if (!Number.isSafeInteger(descriptor) || descriptor < 0) return false;
			try {
				return readlinkSync(join("/proc/thread-self/fd", String(descriptor))) === path;
			} catch {
				return false;
			}
		});
}

function expectDescriptorsClosed(descriptors: Iterable<number>): void {
	for (const descriptor of new Set(descriptors)) {
		try {
			fstatSync(descriptor);
			throw new Error(`descriptor ${descriptor} remained open`);
		} catch (error) {
			expect((error as NodeJS.ErrnoException).code).toBe("EBADF");
		}
	}
}

function captureThrown(run: () => unknown): { threw: false } | { threw: true; error: unknown } {
	try {
		run();
		return { threw: false };
	} catch (error) {
		return { threw: true, error };
	}
}

function injectRecoveryGaps(target: ReturnType<typeof fixture>, observedAtMs: number[]): void {
	target.internal.closeSegmentStore();
	const segmentDirectory = join(target.agentDir, "incident-recorder", "segments");
	for (const observedAt of observedAtMs) {
		const activeName = readdirSync(join(segmentDirectory, "active")).at(0);
		if (!activeName) throw new Error("expected an active segment for recovery-gap injection");
		appendFileSync(
			join(segmentDirectory, "active", activeName),
			Buffer.from([0x47, 0x52, 0x49, 0x4d, 0xff, 0x00, 0x01]),
		);
		const recovered = new IncidentRecorderSegmentStore({
			directory: segmentDirectory,
			now: () => observedAt,
		});
		recovered.close();
	}
}

function writeScanProof(incidentDir: string, anchor: number, cursors: string[]): void {
	writeFileSync(
		join(incidentDir, "journal-pin-scan-proof.json"),
		`${JSON.stringify({
			version: 1,
			state: "fixed_range_namespace_scan_complete",
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
			journalEntries: cursors,
		})}\n`,
		{ mode: 0o600 },
	);
}

function finishRunHistoryProjection(
	compactor: IncidentRecorderCompactor,
	request: { runId: string; fromWallTimeMs: number; throughWallTimeMs: number; deadlineMs?: number },
	maximumPasses = 32,
	initialCursor?: IncidentRecorderRunHistoryCursor,
): IncidentRecorderRunHistoryResult {
	let cursor = initialCursor;
	for (let pass = 0; pass < maximumPasses; pass += 1) {
		const result = compactor.projectRunHistory({ ...request, ...(cursor ? { cursor } : {}) });
		if (result.state !== "pending") return result;
		cursor = result.cursor;
	}
	throw new Error("run-history projection did not finish within its bounded test passes");
}

describe("incident recorder compactor segment integration", () => {
	it("opens lazily after admission and replays deterministic journal references without another inode", async () => {
		const target = fixture();
		const segmentDirectory = join(target.agentDir, "incident-recorder", "segments");
		expect(existsSync(segmentDirectory)).toBe(false);
		await initialize(target.compactor);
		expect(existsSync(segmentDirectory)).toBe(false);

		const input = {
			fields: {
				_PID: Buffer.from("123"),
				_UID: Buffer.from("1000"),
				SYSLOG_IDENTIFIER: Buffer.from("prime-agent-raw-v1"),
				_TRANSPORT: Buffer.from("stdout"),
			},
			cursor: "s=semantic-cursor",
			machineId: "machine",
			bootId: "boot",
			invocationId: null,
			streamId: "stream",
			realtimeUs: "1700000000123000",
			monotonicUs: "10",
			messageBytes: Buffer.from("same-message"),
		};
		const first = target.internal.writeJournalReference(input);
		const accountedAfterFirst = target.compactor.accountedStorageBytes;
		const replayed = target.internal.writeJournalReference(input);
		expect(replayed).toEqual(first);
		expect(target.compactor.accountedStorageBytes).toBe(accountedAfterFirst);
		expect(() =>
			target.internal.writeJournalReference({ ...input, messageBytes: Buffer.from("conflicting-message") }),
		).toThrow(/segment persistence failed.*different canonical content/);
		target.internal.closeSegmentStore();

		const store = new IncidentRecorderSegmentStore({ directory: segmentDirectory });
		try {
			const records = store.queryRunWindow({
				runId: "__journal__",
				sourceId: "journal-reference",
				fromObservedAtMs: 0,
				throughObservedAtMs: Number.MAX_SAFE_INTEGER,
			});
			expect(records).toHaveLength(1);
			expect(records[0]?.payload.toString("utf8")).toContain("same-message");
			expect(first.path).toMatch(/^segment:v1:/);
		} finally {
			store.close();
		}
	});

	it("surfaces a real segment-store close failure after requested shutdown aborts the run loop", async () => {
		const target = fixture();
		await initialize(target.compactor);
		target.internal.appendSegmentRecord({
			idempotencyKey: "shutdown-close-failure",
			runId: "shutdown",
			sourceId: "control",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("shutdown"),
		});
		const store = target.internal.segmentStore;
		if (!store) throw new Error("expected a real segment store before shutdown");
		const closeFailure: unknown = undefined;
		const close = vi.spyOn(store, "close").mockImplementation(() => {
			throw closeFailure;
		});
		const shutdown = new AbortController();
		try {
			await expect(
				target.compactor.run({
					signal: shutdown.signal,
					onStorageMode: () => shutdown.abort(),
				}),
			).rejects.toBeUndefined();
			expect(shutdown.signal.aborted).toBe(true);
			expect(close).toHaveBeenCalledOnce();
		} finally {
			close.mockRestore();
			store.close();
		}
	});

	it("attempts every partial assembly and preserves the first shutdown persistence failure", async () => {
		const target = fixture();
		const journalExport = `${partialJournalEntry(900, 1)}${partialJournalEntry(901, 2)}`;
		const journalctlPath = executable(
			target.root,
			"partial-shutdown-journalctl.cjs",
			`if(!process.argv.includes("--follow"))process.exit(0);process.stdout.write(${JSON.stringify(journalExport)});process.once("SIGTERM",()=>process.exit(0));setInterval(()=>{},1000);`,
		);
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			journalctlPath,
			freeReserveBytes: 0,
		});
		const internal = compactor as unknown as CompactorInternals;
		const appendSegmentRecord = internal.appendSegmentRecord.bind(internal);
		const incompleteAttempts: string[] = [];
		const append = vi.spyOn(internal, "appendSegmentRecord").mockImplementation((input) => {
			if (input.sourceId === "incomplete") {
				if (typeof input.idempotencyKey !== "string") {
					throw new Error("expected incomplete-record idempotency key");
				}
				incompleteAttempts.push(input.idempotencyKey);
				if (incompleteAttempts.length === 1) throw undefined;
			}
			return appendSegmentRecord(input);
		});
		const shutdown = new AbortController();
		const running = compactor.run({ signal: shutdown.signal });
		let close: ReturnType<typeof vi.spyOn> | undefined;
		try {
			await expect.poll(() => internal.assemblies.size, { timeout: 2_000 }).toBe(2);
			const store = internal.segmentStore;
			if (!store) throw new Error("expected a real segment store before partial-assembly shutdown");
			close = vi.spyOn(store, "close");
			shutdown.abort();
			await expect(running).rejects.toBeUndefined();
			expect(incompleteAttempts).toHaveLength(2);
			expect(close).toHaveBeenCalledOnce();
			expect(internal.assemblies.size).toBe(0);
		} finally {
			shutdown.abort();
			await running.catch(() => {});
			append.mockRestore();
			close?.mockRestore();
		}
	});

	it("publishes first-use nested CAS and run-lease paths durably and resumes after the CAS crash boundary", async () => {
		let failAfterCas = true;
		const target = fixture({
			onCasPublicationStep: (step) => {
				if (step === "cas_durable" && failAfterCas) throw new Error("injected-after-cas-fsync");
			},
		});
		await initialize(target.compactor);
		const value = Buffer.from("first-use-cas");
		const digest = createHash("sha256").update(value).digest("hex");
		const casPath = join(
			target.agentDir,
			"incident-recorder",
			"cas",
			"sha256",
			digest.slice(0, 2),
			`${digest}.blob`,
		);
		const leasePath = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
			`cas-${digest}.blob`,
		);
		const before = target.compactor.accountedStorageBytes;
		expect(() =>
			target.internal.publishCasAndRunLease({ runId: RUN_ID, digest, bytes: value.length, value }),
		).toThrow("injected-after-cas-fsync");
		expect(readFileSync(casPath)).toEqual(value);
		expect(existsSync(leasePath)).toBe(false);
		expect(target.compactor.accountedStorageBytes).toBeGreaterThan(before);

		failAfterCas = false;
		const published = target.internal.publishCasAndRunLease({
			runId: RUN_ID,
			digest,
			bytes: value.length,
			value,
		});
		expect(published).toEqual({ casPath, leasePath });
		const cas = lstatSync(casPath);
		const lease = lstatSync(leasePath);
		expect({ dev: lease.dev, ino: lease.ino, size: lease.size }).toEqual({
			dev: cas.dev,
			ino: cas.ino,
			size: value.length,
		});
		const afterPublication = target.compactor.accountedStorageBytes;
		expect(
			target.internal.publishCasAndRunLease({ runId: RUN_ID, digest, bytes: value.length, value }),
		).toEqual({ casPath, leasePath });
		expect(target.compactor.accountedStorageBytes).toBe(afterPublication);
	});

	it("pages segment occurrences, merges a legacy duplicate, and validates v2 locator manifests", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		const legacyRunDirectory = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
		);
		mkdirSync(legacyRunDirectory, { recursive: true, mode: 0o700 });
		linkSync(pin.casPath, join(legacyRunDirectory, `cas-${pin.digest}.blob`));
		await initialize(target.compactor);

		const cursors: string[] = [];
		let firstOccurrence: ReturnType<typeof occurrenceInput> | undefined;
		for (let index = 1; index <= 65; index += 1) {
			const occurrence = occurrenceInput(index, anchor, pin.digest, pin.casPath);
			firstOccurrence ??= occurrence;
			cursors.push(occurrence.cursor);
			target.internal.appendSegmentRecord(occurrence.input);
		}
		if (!firstOccurrence) throw new Error("missing first occurrence fixture");
		writeFileSync(
			join(legacyRunDirectory, `seq-${"1".padStart(20, "0")}-${firstOccurrence.identityKey}.json`),
			`${JSON.stringify(firstOccurrence.payload)}\n`,
			{ mode: 0o600 },
		);
		writeScanProof(pin.incidentDir, anchor, cursors);
		const manifestPath = join(pin.incidentDir, "journal-pin-manifest.json");
		for (let pass = 0; pass < 20 && !existsSync(manifestPath); pass += 1) {
			target.compactor.processPendingPins(anchor + 1);
		}
		expect(existsSync(manifestPath)).toBe(true);
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
			version: number;
			occurrences: Array<{ occurrenceReference: unknown }>;
		};
		expect(manifest.version).toBe(2);
		expect(manifest.occurrences).toHaveLength(65);
		expect(manifest.occurrences.every((entry) => {
			const reference = entry.occurrenceReference as { kind?: unknown; locator?: unknown };
			return reference.kind === "segment" && typeof reference.locator === "object";
		})).toBe(true);

		rmSync(join(pin.incidentDir, "journal-pin-retention-proof.json"), { force: true });
		target.internal.closeSegmentStore();
		const validator = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			freeReserveBytes: 0,
		});
		await initialize(validator);
		for (
			let pass = 0;
			pass < 100 && !existsSync(join(pin.incidentDir, "journal-pin-retention-proof.json"));
			pass += 1
		) {
			validator.processPendingPins(anchor + 1);
		}
		expect(existsSync(join(pin.incidentDir, "journal-pin-retention-proof.json"))).toBe(true);
		(validator as unknown as CompactorInternals).closeSegmentStore();
	});

	it("rejects semantically conflicting v1/v2 duplicates instead of deduplicating by identity alone", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		const legacyRunDirectory = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
		);
		mkdirSync(legacyRunDirectory, { recursive: true, mode: 0o700 });
		await initialize(target.compactor);
		const occurrence = occurrenceInput(1, anchor, pin.digest, pin.casPath);
		target.internal.appendSegmentRecord(occurrence.input);
		writeFileSync(
			join(legacyRunDirectory, `seq-${"1".padStart(20, "0")}-${occurrence.identityKey}.json`),
			`${JSON.stringify({ ...occurrence.payload, source: "conflicting-source" })}\n`,
			{ mode: 0o600 },
		);
		writeScanProof(pin.incidentDir, anchor, [occurrence.cursor]);
		for (
			let pass = 0;
			pass < 10 && !existsSync(join(pin.incidentDir, "journal-pin-incomplete.json"));
			pass += 1
		) {
			target.compactor.processPendingPins(anchor + 1);
		}
		const incomplete = JSON.parse(
			readFileSync(join(pin.incidentDir, "journal-pin-incomplete.json"), "utf8"),
		) as { reason?: unknown };
		expect(incomplete.reason).toBe("duplicate_occurrence_identity_conflict");
		expect(existsSync(join(pin.incidentDir, "journal-pin-manifest.json"))).toBe(false);
		target.internal.closeSegmentStore();
	});

	it.each(["symlink", "oversized"] as const)(
		"turns a %s legacy occurrence reference into explicit incomplete evidence",
		async (kind) => {
			const target = fixture();
			const anchor = Date.now();
			const pin = preparePinFixture(target, anchor);
			const legacyRunDirectory = join(
				target.agentDir,
				"incident-recorder",
				"refs",
				"runs",
				createHash("sha256").update(RUN_ID).digest("hex"),
			);
			mkdirSync(legacyRunDirectory, { recursive: true, mode: 0o700 });
			const identity = occurrenceIdentity(1);
			const path = join(
				legacyRunDirectory,
				`seq-${"1".padStart(20, "0")}-${identity.identityKey}.json`,
			);
			if (kind === "symlink") {
				const source = join(target.root, "forged-legacy.json");
				writeFileSync(source, "{}\n", { mode: 0o600 });
				symlinkSync(source, path);
			} else {
				writeFileSync(path, Buffer.alloc(64 * 1024 + 1, 0x20), { mode: 0o600 });
			}
			writeScanProof(pin.incidentDir, anchor, []);
			await initialize(target.compactor);
			for (
				let pass = 0;
				pass < 5 && !existsSync(join(pin.incidentDir, "journal-pin-incomplete.json"));
				pass += 1
			) {
				target.compactor.processPendingPins(anchor + 1);
			}
			const incomplete = JSON.parse(
				readFileSync(join(pin.incidentDir, "journal-pin-incomplete.json"), "utf8"),
			) as { reason?: unknown };
			expect(incomplete.reason).toBe("legacy_occurrence_reference_corrupt_or_unstable");
			target.internal.closeSegmentStore();
		},
	);

	it("continues the legacy directory fairly across bounded batches", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		const legacyRunDirectory = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
		);
		mkdirSync(legacyRunDirectory, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 65; index += 1) {
			writeFileSync(join(legacyRunDirectory, `ignored-${index.toString().padStart(3, "0")}`), "", {
				mode: 0o600,
			});
		}
		writeScanProof(pin.incidentDir, anchor, []);
		await initialize(target.compactor);
		target.compactor.processPendingPins(anchor + 1);
		expect(existsSync(join(pin.incidentDir, "journal-pin-manifest.json"))).toBe(false);
		target.compactor.processPendingPins(anchor + 1);
		expect(existsSync(join(pin.incidentDir, "journal-pin-manifest.json"))).toBe(true);
		target.internal.closeSegmentStore();
	});

	it.each(["forged", "missing", "mismatched"] as const)(
		"refuses producer verification for a %s v1 occurrence reference",
		async (kind) => {
			const target = fixture();
			const anchor = Date.now();
			const pin = preparePinFixture(target, anchor);
			const occurrence = occurrenceInput(1, anchor, pin.digest, pin.casPath);
			const legacyRunDirectory = join(
				target.agentDir,
				"incident-recorder",
				"refs",
				"runs",
				createHash("sha256").update(RUN_ID).digest("hex"),
			);
			mkdirSync(legacyRunDirectory, { recursive: true, mode: 0o700 });
			const canonicalReference = join(
				legacyRunDirectory,
				`seq-${"1".padStart(20, "0")}-${occurrence.identityKey}.json`,
			);
			let occurrenceReference = canonicalReference;
			if (kind === "forged") {
				occurrenceReference = join(
					target.agentDir,
					"incident-recorder",
					"refs",
					`seq-${"1".padStart(20, "0")}-${occurrence.identityKey}.json`,
				);
			} else if (kind === "mismatched") {
				writeFileSync(canonicalReference, `${JSON.stringify(occurrence.payload)}\n`, { mode: 0o600 });
			}
			const pinCasDirectory = join(pin.incidentDir, "journal-pins", "cas");
			mkdirSync(pinCasDirectory, { recursive: true, mode: 0o700 });
			const pinnedCasPath = join(pinCasDirectory, `${pin.digest}.blob`);
			linkSync(pin.casPath, pinnedCasPath);
			writeFileSync(
				join(pin.incidentDir, "journal-pin-manifest.json"),
				`${JSON.stringify({
					version: 1,
					state: "complete_through_requested_window",
					runId: RUN_ID,
					fromWallTimeMs: anchor,
					throughWallTimeMs: anchor + 1_000,
					occurrences: [
						{
							occurrenceReference,
							cursors: kind === "mismatched" ? ["forged-cursor"] : [occurrence.cursor],
							cas: {
								digest: pin.digest,
								bytes: 1,
								path: pin.casPath,
							},
							eventWallTimeMs: String(anchor + 1),
							pinnedCasPath,
						},
					],
				})}\n`,
				{ mode: 0o600 },
			);
			await initialize(target.compactor);
			for (
				let pass = 0;
				pass < 10 && !existsSync(join(pin.incidentDir, "journal-pin-manifest-invalid.json"));
				pass += 1
			) {
				target.compactor.processPendingPins(anchor + 1);
			}
			expect(existsSync(join(pin.incidentDir, "journal-pin-retention-proof.json"))).toBe(false);
			const invalid = JSON.parse(
				readFileSync(join(pin.incidentDir, "journal-pin-manifest-invalid.json"), "utf8"),
			) as { reason?: unknown };
			expect(String(invalid.reason)).toMatch(/occurrence_reference/);
			target.internal.closeSegmentStore();
		},
	);

	it("projects a segment-only multipage history through an explicit pending continuation", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		await initialize(target.compactor);
		for (let index = 1; index <= 65; index += 1) {
			target.internal.appendSegmentRecord(occurrenceInput(index, anchor, pin.digest, pin.casPath).input);
		}
		const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
		const first = target.compactor.projectRunHistory(request);
		expect(first.state).toBe("pending");
		if (first.state !== "pending") throw new Error("expected a projection continuation");
		expect(first.projection.events).toHaveLength(64);
		const callerOwnedEvent = first.projection.events[0];
		if (!callerOwnedEvent) throw new Error("expected a detached pending event");
		callerOwnedEvent.metadata = { poisonedByCaller: true };
		callerOwnedEvent.wrapperOrder[0] = "999999";
		(callerOwnedEvent.transportIdentity as Record<string, unknown>).poisonedByCaller = true;
		callerOwnedEvent.cas.path = "poisoned-by-caller";
		if (typeof callerOwnedEvent.occurrenceReference !== "string") {
			(callerOwnedEvent.occurrenceReference.locator as { payloadSha256: string }).payloadSha256 =
				"0".repeat(64);
		}
		const late = occurrenceInput(66, anchor, pin.digest, pin.casPath);
		target.internal.appendSegmentRecord(late.input);
		const result = finishRunHistoryProjection(target.compactor, request, 16, first.cursor);
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected a complete projection");
		expect(result.projection.events).toHaveLength(65);
		expect(result.projection.events[0]?.eventWallTimeMs).toBe(String(anchor + 1));
		expect(result.projection.events[0]?.metadata).toEqual({});
		expect(result.projection.events[0]?.wrapperOrder).toEqual(["2"]);
		expect(result.projection.events[0]?.transportIdentity).toEqual({});
		expect(result.projection.events[0]?.cas.path).toBe(pin.casPath);
		expect(result.projection.events.some((event) => event.identityKey === late.identityKey)).toBe(false);
		expect(result.projection.events.at(-1)?.eventWallTimeMs).toBe(String(anchor + 65));
		expect(result.projection.evidence).toEqual([]);
		expect(result.snapshot).toMatchObject({ segmentRecordCount: 65, legacyOccurrenceCount: 0 });
		target.internal.closeSegmentStore();
	});

	it("merges and semantically deduplicates matching v1 and v2 run history", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		const occurrence = occurrenceInput(1, anchor, pin.digest, pin.casPath);
		const legacyDirectory = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
		);
		mkdirSync(legacyDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(
			join(legacyDirectory, `seq-${"1".padStart(20, "0")}-${occurrence.identityKey}.json`),
			`${JSON.stringify(occurrence.payload)}\n`,
			{ mode: 0o600 },
		);
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(occurrence.input);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected a complete merged projection");
		expect(result.projection.events).toHaveLength(1);
		expect(result.snapshot).toMatchObject({ segmentRecordCount: 1, legacyOccurrenceCount: 1 });
		target.internal.closeSegmentStore();
	});

	it("hashes a large CAS claim through bounded resumable reads and fingerprints the verified fact", async () => {
		const reads: Array<{ step: string; digest: string; offset: number; readCount: number }> = [];
		const target = fixture({ onRunHistoryCasValidationStep: (event) => reads.push(event) });
		const anchor = Date.now();
		const value = Buffer.alloc(700 * 1024, 0x61);
		const cas = writeCasFixture(target, value);
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(
			occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: value.length }).input,
		);
		const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
		let result = target.compactor.projectRunHistory(request);
		while (result.state === "pending" && reads.filter((event) => event.step === "read").length === 0) {
			result = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
		}
		expect(result.state).toBe("pending");
		expect(reads.filter((event) => event.step === "read")).toHaveLength(4);
		if (result.state !== "pending") throw new Error("expected bounded CAS continuation");
		result = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
		expect(result.state).toBe("pending");
		expect(reads.filter((event) => event.step === "read")).toHaveLength(8);
		if (result.state !== "pending") throw new Error("expected second bounded CAS continuation");
		result = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected CAS validation completion");
		expect(reads.filter((event) => event.step === "read")).toHaveLength(11);
		expect(reads.filter((event) => event.step === "verified")).toHaveLength(1);
		expect(result.snapshot.validatedCasDigestCount).toBe(1);
		expect(result.snapshot.fingerprint).toMatch(/^[0-9a-f]{64}$/);
		target.internal.closeSegmentStore();
	});

	it("validates duplicate CAS claims exactly once per digest", async () => {
		const steps: string[] = [];
		const target = fixture({ onRunHistoryCasValidationStep: (event) => steps.push(event.step) });
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("shared"));
		await initialize(target.compactor);
		for (let index = 1; index <= 2; index += 1) {
			target.internal.appendSegmentRecord(
				occurrenceInput(index, anchor, cas.digest, cas.casPath, { casBytes: 6 }).input,
			);
		}
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("complete");
		expect(steps.filter((step) => step === "opened")).toHaveLength(1);
		expect(steps.filter((step) => step === "read")).toHaveLength(1);
		expect(steps.filter((step) => step === "verified")).toHaveLength(1);
		target.internal.closeSegmentStore();
	});

	it("rejects conflicting byte claims for one CAS digest before validation", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(occurrenceInput(1, anchor, cas.digest, cas.casPath).input);
		target.internal.appendSegmentRecord(
			occurrenceInput(2, anchor, cas.digest, cas.casPath, { casBytes: 2 }).input,
		);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		if (result.state === "incomplete") {
			expect(result.reason).toBe("run_history_cas_claim_conflict");
			expect(result.projection.evidence[0]?.kind).toBe("corrupt");
		}
		target.internal.closeSegmentStore();
	});

	it.each(["missing", "corrupt"] as const)(
		"returns explicit incomplete evidence for a %s CAS blob",
		async (kind) => {
			const target = fixture();
			const anchor = Date.now();
			const cas = writeCasFixture(target, Buffer.from("original"));
			await initialize(target.compactor);
			target.internal.appendSegmentRecord(
				occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: 8 }).input,
			);
			if (kind === "missing") rmSync(cas.casPath);
			else writeFileSync(cas.casPath, "changed!", { mode: 0o600 });
			const result = finishRunHistoryProjection(target.compactor, {
				runId: RUN_ID,
				fromWallTimeMs: anchor,
				throughWallTimeMs: anchor + 1_000,
			});
			expect(result.state).toBe("incomplete");
			if (result.state !== "incomplete") throw new Error("expected CAS evidence failure");
			expect(result.reason).toBe(
				kind === "missing" ? "run_history_cas_blob_missing" : "run_history_cas_digest_mismatch",
			);
			expect(result.projection.evidence[0]?.kind).toBe(kind === "missing" ? "incomplete" : "corrupt");
			target.internal.closeSegmentStore();
		},
	);

	it("detects a canonical CAS name swap during a multi-call hash", async () => {
		let swapped = false;
		let casPath = "";
		const target = fixture({
			onRunHistoryCasValidationStep: (event) => {
				if (event.step !== "read" || event.readCount !== 1 || swapped) return;
				swapped = true;
				renameSync(casPath, `${casPath}.replaced`);
				writeFileSync(casPath, Buffer.alloc(700 * 1024, 0x61), { mode: 0o600 });
			},
		});
		const anchor = Date.now();
		const value = Buffer.alloc(700 * 1024, 0x61);
		const cas = writeCasFixture(target, value);
		casPath = cas.casPath;
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(
			occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: value.length }).input,
		);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(swapped).toBe(true);
		expect(result.state).toBe("incomplete");
		if (result.state === "incomplete") {
			expect(result.reason).toMatch(/^run_history_cas_blob_(?:name_swapped|changed_during_read)$/);
		}
		target.internal.closeSegmentStore();
	});

	it("rejects a persistent intermediate CAS symlink before reading the redirected blob", async () => {
		const validationSteps: string[] = [];
		const target = fixture({
			onRunHistoryCasValidationStep: (event) => validationSteps.push(event.step),
		});
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("redirected"));
		const casDirectory = join(target.agentDir, "incident-recorder", "cas");
		const redirectedDirectory = join(target.root, "redirected-cas");
		renameSync(casDirectory, redirectedDirectory);
		symlinkSync(redirectedDirectory, casDirectory, "dir");
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(
			occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: 10 }).input,
		);
		const recorderRoot = join(target.agentDir, "incident-recorder");
		const recorderRootDescriptorCount = (): number =>
			readdirSync("/proc/self/fd").filter((name) => {
				try {
					return readlinkSync(join("/proc/self/fd", name)) === recorderRoot;
				} catch {
					return false;
				}
			}).length;
		const rootDescriptorsBefore = recorderRootDescriptorCount();
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected an intermediate-symlink failure");
		expect(result.reason).toBe("run_history_cas_cas_directory_invalid");
		expect(result.projection.evidence[0]).toMatchObject({
			kind: "corrupt",
			reason: "run_history_cas_cas_directory_invalid",
		});
		expect(validationSteps).toEqual([]);
		expect(recorderRootDescriptorCount()).toBe(rootDescriptorsBefore);
		expect(readFileSync(cas.casPath, "utf8")).toBe("redirected");
		target.internal.closeSegmentStore();
	});

	it("rejects a forged proc descriptor subtree even when its filesystem type appears to be procfs", async () => {
		const procFixtureRoot = mkdtempSync(join(tmpdir(), "prime-agent-forged-procfd-"));
		roots.push(procFixtureRoot);
		const forgedDescriptorDirectory = join(procFixtureRoot, "fd");
		const redirectedBase = join(procFixtureRoot, "redirected");
		mkdirSync(forgedDescriptorDirectory, { mode: 0o700 });
		mkdirSync(redirectedBase, { mode: 0o700 });
		const validationSteps: string[] = [];
		const target = fixture({
			onRunHistoryCasValidationStep: (event) => validationSteps.push(event.step),
			runHistoryProcfs: {
				descriptorDirectoryPath: forgedDescriptorDirectory,
				descriptorInfoDirectoryPath: "/proc/thread-self/fdinfo",
				// Simulate an overmounted proc-looking subtree that defeats the old
				// statfs("/proc")-only admission check. Descriptor-bound mnt_id must
				// still reject the route before any CAS descriptor is trusted.
				statfsType: () => 0x9fa0,
			},
		});
		const anchor = Date.now();
		const value = Buffer.from("valid-looking-redirected-cas");
		const cas = writeCasFixture(target, value);
		for (const name of ["cas", "sha256", cas.digest.slice(0, 2)]) {
			mkdirSync(join(redirectedBase, name), { mode: 0o700 });
		}
		const redirectedBlob = join(redirectedBase, `${cas.digest}.blob`);
		writeFileSync(redirectedBlob, value, { mode: 0o600 });
		const openDescriptorNumbers = readdirSync("/proc/thread-self/fd")
			.map((name) => Number(name))
			.filter((value) => Number.isSafeInteger(value) && value >= 0);
		const highestDescriptor = Math.max(32, ...openDescriptorNumbers);
		for (let descriptor = 0; descriptor <= highestDescriptor + 64; descriptor += 1) {
			symlinkSync(redirectedBase, join(forgedDescriptorDirectory, String(descriptor)), "dir");
		}
		expect(readlinkSync(join(forgedDescriptorDirectory, "0"))).toBe(redirectedBase);
		expect(lstatSync(join(forgedDescriptorDirectory, "0", "cas")).isDirectory()).toBe(true);

		await initialize(target.compactor);
		target.internal.appendSegmentRecord(
			occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: value.length }).input,
		);
		const descriptorCountBefore = readdirSync("/proc/thread-self/fd").length;
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected forged procfd containment");
		expect(result.reason).toBe("run_history_cas_procfs_mount_id_mismatch");
		expect(result.projection.evidence[0]).toMatchObject({
			kind: "corrupt",
			reason: "run_history_cas_procfs_mount_id_mismatch",
		});
		expect(validationSteps).toEqual([]);
		expect(readFileSync(redirectedBlob)).toEqual(value);
		expect(target.internal.runHistoryTraversals.size).toBe(0);
		expect(readdirSync("/proc/thread-self/fd").length).toBe(descriptorCountBefore);
		const afterFailure = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(afterFailure.blockedByReadSnapshot).toBe(false);
		target.internal.closeSegmentStore();
	});

	it("rejects a proc descriptor route substituted after authority admission", async () => {
		const procFixtureRoot = mkdtempSync(join(tmpdir(), "prime-agent-replaced-procfd-"));
		roots.push(procFixtureRoot);
		const forgedDescriptorDirectory = join(procFixtureRoot, "fd");
		const redirectedBase = join(procFixtureRoot, "redirected");
		mkdirSync(forgedDescriptorDirectory, { mode: 0o700 });
		mkdirSync(redirectedBase, { mode: 0o700 });
		for (let descriptor = 0; descriptor <= highestObservedDescriptor() + 64; descriptor += 1) {
			symlinkSync(redirectedBase, join(forgedDescriptorDirectory, String(descriptor)), "dir");
		}
		let authorityAdmitted = false;
		let substitutedDereferences = 0;
		const validationSteps: string[] = [];
		const target = fixture({
			onRunHistoryCasValidationStep: (event) => validationSteps.push(event.step),
			runHistoryProcfs: {
				statfsType: () => 0x9fa0,
				onAuthorityAdmitted: () => {
					authorityAdmitted = true;
				},
				resolveDescriptorPath: ({ canonicalPath, descriptor, childName }) => {
					if (!authorityAdmitted) return canonicalPath;
					substitutedDereferences += 1;
					return childName === undefined
						? join(forgedDescriptorDirectory, String(descriptor))
						: join(forgedDescriptorDirectory, String(descriptor), childName);
				},
			},
		});
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(occurrenceInput(1, anchor, cas.digest, cas.casPath).input);
		const descriptorCountBefore = readdirSync("/proc/thread-self/fd").length;
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(authorityAdmitted).toBe(true);
		expect(substitutedDereferences).toBeGreaterThan(0);
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected post-admission procfd containment");
		expect(result.reason).toBe("run_history_cas_procfs_recorder_root_descriptor_identity_mismatch");
		expect(result.projection.evidence[0]).toMatchObject({ kind: "corrupt" });
		expect(validationSteps).toEqual([]);
		expect(target.internal.runHistoryTraversals.size).toBe(0);
		expect(readdirSync("/proc/thread-self/fd").length).toBe(descriptorCountBefore);
		target.internal.closeSegmentStore();
	});

	it.each([
		{
			name: "missing file",
			content: undefined,
			reason: "run_history_cas_descriptor_anchoring_unavailable",
		},
		{
			name: "missing mnt_id",
			content: "pos:\t0\nflags:\t0100000\n",
			reason: "run_history_cas_procfs_root_fdinfo_mount_id_ambiguous",
		},
		{
			name: "malformed",
			content: "pos:\t0\nflags:\t0100000\nmnt_id:\tnot-decimal\n",
			reason: "run_history_cas_procfs_root_fdinfo_mount_id_invalid",
		},
		{
			name: "duplicate",
			content: "pos:\t0\nflags:\t0100000\nmnt_id:\t1\nmnt_id:\t1\n",
			reason: "run_history_cas_procfs_root_fdinfo_mount_id_ambiguous",
		},
		{
			name: "oversized",
			content: `mnt_id:\t1\n${"x".repeat(16 * 1024)}\n`,
			reason: "run_history_cas_procfs_root_fdinfo_oversized",
		},
		{
			name: "zero",
			content: "pos:\t0\nflags:\t0100000\nmnt_id:\t0\n",
			reason: "run_history_cas_procfs_root_fdinfo_mount_id_invalid",
		},
	] as const)("fails closed on a $name proc fdinfo witness without leaking descriptors", async ({ content, reason }) => {
		const procFixtureRoot = mkdtempSync(join(tmpdir(), "prime-agent-forged-fdinfo-"));
		roots.push(procFixtureRoot);
		const forgedDescriptorInfoDirectory = join(procFixtureRoot, "fdinfo");
		mkdirSync(forgedDescriptorInfoDirectory, { mode: 0o700 });
		if (content !== undefined) writeSyntheticFdinfoDirectory(forgedDescriptorInfoDirectory, content);
		const validationSteps: string[] = [];
		const target = fixture({
			onRunHistoryCasValidationStep: (event) => validationSteps.push(event.step),
			runHistoryProcfs: {
				descriptorDirectoryPath: "/proc/thread-self/fd",
				descriptorInfoDirectoryPath: forgedDescriptorInfoDirectory,
				statfsType: () => 0x9fa0,
			},
		});
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(occurrenceInput(1, anchor, cas.digest, cas.casPath).input);
		const descriptorCountBefore = readdirSync("/proc/thread-self/fd").length;
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected malformed fdinfo containment");
		expect(result.reason).toBe(reason);
		expect(result.projection.evidence[0]).toMatchObject({ kind: "corrupt" });
		expect(validationSteps).toEqual([]);
		expect(target.internal.runHistoryTraversals.size).toBe(0);
		expect(readdirSync("/proc/thread-self/fd").length).toBe(descriptorCountBefore);
		target.internal.closeSegmentStore();
	});

	it("fails closed when a proc fdinfo mount witness drifts after admission", async () => {
		const procFixtureRoot = mkdtempSync(join(tmpdir(), "prime-agent-drifting-fdinfo-"));
		roots.push(procFixtureRoot);
		const forgedDescriptorInfoDirectory = join(procFixtureRoot, "fdinfo");
		mkdirSync(forgedDescriptorInfoDirectory, { mode: 0o700 });
		const mountId = currentProcfsMountId();
		writeSyntheticFdinfoDirectory(forgedDescriptorInfoDirectory, `mnt_id:\t${mountId}\n`);
		let admissions = 0;
		const validationSteps: string[] = [];
		const target = fixture({
			onRunHistoryCasValidationStep: (event) => validationSteps.push(event.step),
			runHistoryProcfs: {
				descriptorDirectoryPath: "/proc/thread-self/fd",
				descriptorInfoDirectoryPath: forgedDescriptorInfoDirectory,
				statfsType: () => 0x9fa0,
				onAuthorityAdmitted: () => {
					admissions += 1;
					writeSyntheticFdinfoDirectory(
						forgedDescriptorInfoDirectory,
						`mnt_id:\t${mountId + 1n}\n`,
					);
				},
			},
		});
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(occurrenceInput(1, anchor, cas.digest, cas.casPath).input);
		const descriptorCountBefore = readdirSync("/proc/thread-self/fd").length;
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(admissions).toBe(1);
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected fdinfo mount drift containment");
		expect(result.reason).toBe("run_history_cas_procfs_mount_id_mismatch");
		expect(result.projection.evidence[0]).toMatchObject({ kind: "corrupt" });
		expect(validationSteps).toEqual([]);
		expect(target.internal.runHistoryTraversals.size).toBe(0);
		expect(readdirSync("/proc/thread-self/fd").length).toBe(descriptorCountBefore);
		target.internal.closeSegmentStore();
	});

	it("preserves a legacy occurrence parse failure when descriptor close cleanup also fails", () => {
		const cleanupError = new Error("injected_legacy_occurrence_close_failure");
		let closedDescriptor: number | undefined;
		const target = fixture({
			runHistoryDescriptorIo: {
				afterClose: ({ role, descriptor }) => {
					if (role !== "legacy_occurrence") return;
					closedDescriptor = descriptor;
					throw cleanupError;
				},
			},
		});
		const path = join(target.root, "corrupt-legacy-occurrence.json");
		writeFileSync(path, "{", { mode: 0o600 });
		const captured = captureThrown(() => target.internal.readStableLegacyOccurrence(path));
		expect(captured.threw).toBe(true);
		if (!captured.threw) throw new Error("expected corrupt legacy occurrence read to throw");
		expect(captured.error).toBeInstanceOf(SyntaxError);
		expect(captured.error).not.toBe(cleanupError);
		if (closedDescriptor === undefined) throw new Error("expected legacy occurrence descriptor cleanup");
		expectDescriptorsClosed([closedDescriptor]);
		target.internal.closeSegmentStore();
	});

	it("surfaces a descriptor close failure after an otherwise successful legacy occurrence read", () => {
		const cleanupError = new Error("injected_legacy_occurrence_close_failure");
		let closedDescriptor: number | undefined;
		const target = fixture({
			runHistoryDescriptorIo: {
				afterClose: ({ role, descriptor }) => {
					if (role !== "legacy_occurrence") return;
					closedDescriptor = descriptor;
					throw cleanupError;
				},
			},
		});
		const path = join(target.root, "valid-legacy-occurrence.json");
		writeFileSync(path, '{"ok":true}\n', { mode: 0o600 });
		const captured = captureThrown(() => target.internal.readStableLegacyOccurrence(path));
		expect(captured.threw).toBe(true);
		if (!captured.threw) throw new Error("expected legacy occurrence close failure");
		expect(captured.error).toBe(cleanupError);
		if (closedDescriptor === undefined) throw new Error("expected legacy occurrence descriptor cleanup");
		expectDescriptorsClosed([closedDescriptor]);
		target.internal.closeSegmentStore();
	});

	it("preserves a stable-directory identity failure when descriptor close cleanup also fails", () => {
		const cleanupError = new Error("injected_stable_directory_close_failure");
		let closedDescriptor: number | undefined;
		const target = fixture({
			runHistoryDescriptorIo: {
				afterOpen: ({ role, descriptor }) => {
					if (role === "stable_directory") fchmodSync(descriptor, 0o755);
				},
				afterClose: ({ role, descriptor }) => {
					if (role !== "stable_directory") return;
					closedDescriptor = descriptor;
					throw cleanupError;
				},
			},
		});
		const captured = captureThrown(() => target.internal.openStableRunHistoryDirectory(target.agentDir));
		expect(captured.threw).toBe(true);
		if (!captured.threw) throw new Error("expected stable-directory identity failure");
		expect(captured.error).toBeInstanceOf(Error);
		expect((captured.error as Error).message).toBe("legacy_run_reference_directory_changed_before_open");
		expect(captured.error).not.toBe(cleanupError);
		if (closedDescriptor === undefined) throw new Error("expected stable-directory descriptor cleanup");
		expectDescriptorsClosed([closedDescriptor]);
		target.internal.closeSegmentStore();
	});

	it.each(["legacy_occurrence", "stable_directory"] as const)(
		"preserves a thrown undefined primary from the %s descriptor path when close cleanup fails",
		(role) => {
			const primaryError: unknown = undefined;
			const cleanupError = new Error(`injected_${role}_close_failure`);
			let closedDescriptor: number | undefined;
			const target = fixture({
				runHistoryDescriptorIo: {
					afterOpen: (event) => {
						if (event.role === role) throw primaryError;
					},
					afterClose: (event) => {
						if (event.role !== role) return;
						closedDescriptor = event.descriptor;
						throw cleanupError;
					},
				},
			});
			const path =
				role === "legacy_occurrence" ? join(target.root, "valid-legacy-occurrence.json") : target.agentDir;
			if (role === "legacy_occurrence") writeFileSync(path, '{"ok":true}\n', { mode: 0o600 });
			const captured = captureThrown(() => {
				if (role === "legacy_occurrence") target.internal.readStableLegacyOccurrence(path);
				else target.internal.openStableRunHistoryDirectory(path);
			});
			expect(captured.threw).toBe(true);
			if (!captured.threw) throw new Error("expected injected undefined primary");
			expect(captured.error).toBeUndefined();
			if (closedDescriptor === undefined) throw new Error(`expected ${role} descriptor cleanup`);
			expectDescriptorsClosed([closedDescriptor]);
			target.internal.closeSegmentStore();
		},
	);

	it("preserves producer causality across wall-clock regression", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		const first = occurrenceInput(1, anchor, cas.digest, cas.casPath, {
			eventWallTimeMs: String(anchor + 100),
			wrapperOrder: ["1"],
			producerOrder: ["1"],
		});
		const second = occurrenceInput(2, anchor, cas.digest, cas.casPath, {
			eventWallTimeMs: String(anchor + 1),
			wrapperOrder: ["2"],
			producerOrder: ["2"],
		});
		target.internal.appendSegmentRecord(first.input);
		target.internal.appendSegmentRecord(second.input);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected causal projection completion");
		expect(result.projection.events.map((event) => event.identityKey)).toEqual([
			first.identityKey,
			second.identityKey,
		]);
		expect(result.projection.ordering.causalRelations).toEqual([
			expect.objectContaining({
				beforeIdentityKey: first.identityKey,
				afterIdentityKey: second.identityKey,
				basis: "producer_sequence",
			}),
		]);
		expect(result.projection.ordering.unrelatedPresentationOrderIsCausal).toBe(false);
		expect(result.projection.events[0]?.identity).toMatchObject({
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			producerId: PRODUCER_ID,
		});
		target.internal.closeSegmentStore();
	});

	it("uses wall time only as deterministic presentation for unrelated streams", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		const producerA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
		const producerB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
		await initialize(target.compactor);
		const later = occurrenceInput(1, anchor, cas.digest, cas.casPath, {
			producerId: producerA,
			eventWallTimeMs: String(anchor + 20),
			wrapperOrder: ["1"],
			producerOrder: ["1"],
		});
		const earlier = occurrenceInput(2, anchor, cas.digest, cas.casPath, {
			producerId: producerB,
			eventWallTimeMs: String(anchor + 10),
			wrapperOrder: ["1"],
			producerOrder: ["1"],
		});
		target.internal.appendSegmentRecord(later.input);
		target.internal.appendSegmentRecord(earlier.input);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected unrelated-stream projection");
		expect(result.projection.events.map((event) => event.identityKey)).toEqual([
			earlier.identityKey,
			later.identityKey,
		]);
		expect(result.projection.ordering.causalRelations).toEqual([]);
		expect(result.projection.ordering).toMatchObject({
			semantics: "partial_order",
			presentationTieBreak: "wall_time_then_identity_key",
			unrelatedPresentationOrderIsCausal: false,
			scope: "complete_snapshot",
		});
		target.internal.closeSegmentStore();
	});

	it("orders different producers by a shared wrapper stream and rejects contradictory chains", async () => {
		const anchor = Date.now();
		const producerA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
		const producerB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
		const transportIdentity = {
			machineId: "machine",
			bootId: "boot",
			wrapperPid: 123,
			wrapperStartId: "start-1",
		};
		const ordered = fixture();
		const orderedCas = writeCasFixture(ordered, Buffer.from("x"));
		await initialize(ordered.compactor);
		const first = occurrenceInput(1, anchor, orderedCas.digest, orderedCas.casPath, {
			producerId: producerA,
			wrapperOrder: ["1"],
			producerOrder: ["1"],
			transportIdentity,
		});
		const second = occurrenceInput(2, anchor, orderedCas.digest, orderedCas.casPath, {
			producerId: producerB,
			wrapperOrder: ["2"],
			producerOrder: ["1"],
			transportIdentity,
		});
		ordered.internal.appendSegmentRecord(first.input);
		ordered.internal.appendSegmentRecord(second.input);
		const orderedResult = finishRunHistoryProjection(ordered.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(orderedResult.state).toBe("complete");
		if (orderedResult.state !== "complete") throw new Error("expected wrapper-order completion");
		expect(orderedResult.projection.ordering.causalRelations).toEqual([
			expect.objectContaining({
				beforeIdentityKey: first.identityKey,
				afterIdentityKey: second.identityKey,
				basis: "wrapper_sequence",
			}),
		]);
		ordered.internal.closeSegmentStore();

		const contradictory = fixture();
		const contradictoryCas = writeCasFixture(contradictory, Buffer.from("x"));
		await initialize(contradictory.compactor);
		contradictory.internal.appendSegmentRecord(
			occurrenceInput(3, anchor, contradictoryCas.digest, contradictoryCas.casPath, {
				wrapperOrder: ["2"],
				producerOrder: ["1"],
				transportIdentity,
			}).input,
		);
		contradictory.internal.appendSegmentRecord(
			occurrenceInput(4, anchor, contradictoryCas.digest, contradictoryCas.casPath, {
				wrapperOrder: ["1"],
				producerOrder: ["2"],
				transportIdentity,
			}).input,
		);
		const contradictoryResult = finishRunHistoryProjection(contradictory.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(contradictoryResult.state).toBe("incomplete");
		if (contradictoryResult.state === "incomplete") {
			expect(contradictoryResult.reason).toBe("run_history_causal_order_cycle");
			expect(contradictoryResult.projection.evidence[0]?.kind).toBe("corrupt");
		}
		contradictory.internal.closeSegmentStore();
	});

	it("contains a causal overlap first observed after 512 events and releases its read lease", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		for (let index = 1; index <= 513; index += 1) {
			target.internal.appendSegmentRecord(
				occurrenceInput(index, anchor, cas.digest, cas.casPath, {
					producerOrder: [String(index === 513 ? 512 : index)],
				}).input,
			);
		}
		const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
		const first = target.compactor.projectRunHistory(request);
		expect(first.state).toBe("pending");
		if (first.state !== "pending") throw new Error("expected a high-cardinality continuation");
		const result = finishRunHistoryProjection(target.compactor, request, 31, first.cursor);
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") {
			throw new Error("expected a contained high-cardinality overlap");
		}
		expect(result.reason).toBe("run_history_causal_sequence_overlap");
		expect(result.projection.events).toHaveLength(513);
		expect(result.projection.evidence[0]).toMatchObject({
			kind: "corrupt",
			reason: "run_history_causal_sequence_overlap",
		});
		expect(target.internal.runHistoryTraversals.size).toBe(0);
		expect(target.compactor.cancelRunHistoryProjection(first.cursor)).toBe(false);
		const afterFailure = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(afterFailure.blockedByReadSnapshot).toBe(false);
		target.internal.closeSegmentStore();
	});

	it("detects a conflicting legacy duplicate before applying the requested time window", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		const occurrence = occurrenceInput(1, anchor, pin.digest, pin.casPath);
		writeLegacyOccurrence(target, occurrence, 1, {
			...occurrence.payload,
			eventWallTimeMs: String(anchor + 2_000),
		});
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(occurrence.input);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected a semantic conflict");
		expect(result.reason).toBe("run_history_duplicate_occurrence_semantic_conflict");
		expect(result.projection.evidence[0]).toMatchObject({ kind: "corrupt" });
		target.internal.closeSegmentStore();
	});

	it("detects a conflicting segment duplicate before applying the requested time window", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		const segment = occurrenceInput(1, anchor, cas.digest, cas.casPath, {
			eventWallTimeMs: String(anchor - 1),
		});
		writeLegacyOccurrence(target, segment, 1, {
			...segment.payload,
			source: "conflicting-legacy-source",
			eventWallTimeMs: String(anchor + 1),
		});
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(segment.input);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected a semantic conflict");
		expect(result.reason).toBe("run_history_duplicate_occurrence_semantic_conflict");
		expect(result.projection.evidence[0]).toMatchObject({ kind: "corrupt" });
		target.internal.closeSegmentStore();
	});

	it("fails a legacy projection when its canonical directory is swapped between bounded pages", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		let legacyDirectory = "";
		for (let index = 1; index <= 64; index += 1) {
			legacyDirectory = writeLegacyOccurrence(
				target,
				occurrenceInput(index, anchor, pin.digest, pin.casPath),
				index,
			).directory;
		}
		await initialize(target.compactor);
		const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
		let result = target.compactor.projectRunHistory(request);
		for (let pass = 0; pass < 8 && result.state === "pending" && result.projection.events.length < 64; pass += 1) {
			result = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
		}
		expect(result.state).toBe("pending");
		if (result.state !== "pending") throw new Error("expected a legacy directory continuation");
		expect(result.projection.events).toHaveLength(64);
		renameSync(legacyDirectory, `${legacyDirectory}.replaced`);
		mkdirSync(legacyDirectory, { mode: 0o700 });
		const resumed = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
		expect(resumed.state).toBe("incomplete");
		if (resumed.state !== "incomplete") throw new Error("expected a changed-directory projection");
		expect(resumed.reason).toBe("run_history_legacy_snapshot_changed");
		expect(resumed.projection.evidence[0]).toMatchObject({ kind: "corrupt" });
		target.internal.closeSegmentStore();
	});

	it("sweeps abandoned projection cursors before capacity admission", async () => {
		const target = fixture();
		const anchor = Date.now();
		await initialize(target.compactor);
		const clock = vi.spyOn(Date, "now").mockReturnValue(anchor);
		try {
			for (let index = 0; index < 4; index += 1) {
				const result = target.compactor.projectRunHistory({
					runId: RUN_ID,
					fromWallTimeMs: anchor,
					throughWallTimeMs: anchor + 1_000,
					deadlineMs: anchor + 10,
				});
				expect(result.state).toBe("pending");
			}
			expect(() =>
				target.compactor.projectRunHistory({
					runId: RUN_ID,
					fromWallTimeMs: anchor,
					throughWallTimeMs: anchor + 1_000,
					deadlineMs: anchor + 10,
				}),
			).toThrow("Incident run-history projection capacity is saturated");
			expect(target.internal.runHistoryTraversals.size).toBe(4);
			clock.mockReturnValue(anchor + 20);
			const admitted = target.compactor.projectRunHistory({
				runId: RUN_ID,
				fromWallTimeMs: anchor,
				throughWallTimeMs: anchor + 1_000,
				deadlineMs: anchor + 30,
			});
			expect(admitted.state).toBe("pending");
			if (admitted.state === "pending") expect(target.compactor.cancelRunHistoryProjection(admitted.cursor)).toBe(true);
			expect(target.internal.runHistoryTraversals.size).toBe(0);
		} finally {
			clock.mockRestore();
		}
		target.internal.closeSegmentStore();
	});

	it("rejects invalid deadlines and supports explicit projection cancellation", async () => {
		const target = fixture();
		const anchor = Date.now();
		await initialize(target.compactor);
		expect(() =>
			target.compactor.projectRunHistory({
				runId: RUN_ID,
				fromWallTimeMs: anchor,
				throughWallTimeMs: anchor + 1_000,
				deadlineMs: Number.NaN,
			}),
		).toThrow(/Invalid incident run-history projection request/);
		const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
		const first = target.compactor.projectRunHistory(request);
		expect(first.state).toBe("pending");
		if (first.state !== "pending") throw new Error("expected a cancellable projection");
		expect(target.compactor.cancelRunHistoryProjection(first.cursor)).toBe(true);
		expect(target.compactor.cancelRunHistoryProjection(first.cursor)).toBe(false);
		const resumed = target.compactor.projectRunHistory({ ...request, cursor: first.cursor });
		expect(resumed.state).toBe("incomplete");
		if (resumed.state === "incomplete") {
			expect(resumed.reason).toBe("run_history_continuation_missing_or_expired");
		}
		target.internal.closeSegmentStore();
	});

	it("never returns a serialized projection above its explicit byte bound", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		const recordCount = 6_400;
		for (let index = 1; index <= recordCount; index += 1) {
			const occurrence = occurrenceInput(index, anchor, pin.digest, pin.casPath);
			writeLegacyOccurrence(target, occurrence, index, {
				...occurrence.payload,
				eventMonotonicNs: "1",
				cursors: ["c"],
			});
		}
		await initialize(target.compactor);
		const result = finishRunHistoryProjection(
			target.compactor,
			{
				runId: RUN_ID,
				fromWallTimeMs: anchor,
				throughWallTimeMs: anchor + recordCount + 1,
			},
			160,
		);
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected explicit returned-result truncation");
		expect(result.reason).toBe("run_history_projection_serialized_bound_exceeded");
		expect(result.projection.evidence).toEqual([
			{
				kind: "truncated",
				reason: "serialized_projection_result_exceeded_explicit_byte_bound",
			},
		]);
		expect(Buffer.byteLength(JSON.stringify(result) ?? "", "utf8")).toBeLessThanOrEqual(8 * 1024 * 1024);
		target.internal.closeSegmentStore();
	});

	it("holds one segment read lease across all filters and releases prune protection on completion", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		await initialize(target.compactor);
		for (let index = 1; index <= 64; index += 1) {
			target.internal.appendSegmentRecord(occurrenceInput(index, anchor, pin.digest, pin.casPath).input);
		}
		target.internal.segmentStore?.seal("projection-first-generation");
		target.internal.appendSegmentRecord(occurrenceInput(65, anchor, pin.digest, pin.casPath).input);
		target.internal.segmentStore?.seal("projection-anchor");
		const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
		const first = target.compactor.projectRunHistory(request);
		expect(first.state).toBe("pending");
		if (first.state !== "pending") throw new Error("expected a projection continuation");
		const blocked = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(blocked.deletedSegmentIds).toEqual([]);
		expect(blocked.blockedByReadSnapshot).toBe(true);
		const late = occurrenceInput(66, anchor, pin.digest, pin.casPath);
		target.internal.appendSegmentRecord(late.input);
		const resumed = finishRunHistoryProjection(target.compactor, request, 16, first.cursor);
		expect(resumed.state).toBe("complete");
		if (resumed.state !== "complete") throw new Error("expected the leased projection to complete");
		expect(resumed.projection.events).toHaveLength(65);
		expect(resumed.projection.events.some((event) => event.identityKey === late.identityKey)).toBe(false);
		const afterRelease = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(afterRelease.deletedSegmentIds).toHaveLength(2);
		expect(afterRelease.blockedByReadSnapshot).toBe(false);
		target.internal.closeSegmentStore();
	});

	it.each(["cancel", "expiry", "close"] as const)(
		"releases segment read-lease prune protection after projection %s",
		async (exit) => {
			const target = fixture();
			const anchor = Date.now();
			const pin = preparePinFixture(target, anchor);
			await initialize(target.compactor);
			for (let index = 1; index <= 3; index += 1) {
				target.internal.appendSegmentRecord(occurrenceInput(index, anchor, pin.digest, pin.casPath).input);
				if (index < 3) target.internal.segmentStore?.seal(`lease-release-${index}`);
			}
			const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
			let clock: ReturnType<typeof vi.spyOn> | undefined;
			if (exit === "expiry") clock = vi.spyOn(Date, "now").mockReturnValue(anchor);
			try {
				const first = target.compactor.projectRunHistory({
					...request,
					...(exit === "expiry" ? { deadlineMs: anchor + 10_000 } : {}),
				});
				expect(first.state).toBe("pending");
				if (first.state !== "pending") throw new Error("expected leased projection continuation");
				const blocked = target.compactor.pruneSegmentHistory(
					anchor + 4 * DAY,
					createIncidentRecorderSegmentPruneProtection(0, []),
				);
				expect(blocked.deletedSegmentIds).toEqual([]);
				expect(blocked.blockedByReadSnapshot).toBe(true);
				if (exit === "cancel") {
					expect(target.compactor.cancelRunHistoryProjection(first.cursor)).toBe(true);
				} else if (exit === "expiry") {
					clock?.mockReturnValue(anchor + 20_000);
					const expired = target.compactor.projectRunHistory({ ...request, cursor: first.cursor });
					expect(expired.state).toBe("incomplete");
				} else {
					target.internal.closeSegmentStore();
				}
				const afterRelease = target.compactor.pruneSegmentHistory(
					anchor + 4 * DAY,
					createIncidentRecorderSegmentPruneProtection(0, []),
				);
				expect(afterRelease.deletedSegmentIds.length).toBeGreaterThan(0);
				expect(afterRelease.blockedByReadSnapshot).toBe(false);
			} finally {
				clock?.mockRestore();
			}
			target.internal.closeSegmentStore();
		},
	);

	it.each(["complete", "incomplete", "cancel", "close", "expiry"] as const)(
		"closes every CAS/proc descriptor and clears the deadline timer after projection %s",
		async (exit) => {
			const target = fixture();
			const anchor = Date.now();
			const value = Buffer.alloc(700 * 1024, 0x61);
			const cas = writeCasFixture(target, value);
			await initialize(target.compactor);
			target.internal.appendSegmentRecord(
				occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: value.length }).input,
			);
			vi.useFakeTimers();
			vi.setSystemTime(anchor);
			const baselineTimers = vi.getTimerCount();
			try {
				const request = {
					runId: RUN_ID,
					fromWallTimeMs: anchor,
					throughWallTimeMs: anchor + 1_000,
					deadlineMs: anchor + 100,
				};
				let result = target.compactor.projectRunHistory(request);
				for (let pass = 0; pass < 16; pass += 1) {
					const traversal = [...target.internal.runHistoryTraversals.values()][0];
					if (traversal?.activeCasValidation) break;
					if (result.state !== "pending") {
						throw new Error("projection ended before active CAS validation");
					}
					result = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
				}
				const traversal = [...target.internal.runHistoryTraversals.values()][0];
				const active = traversal?.activeCasValidation;
				if (
					!traversal ||
					!active ||
					traversal.legacyNamespaceDescriptor === undefined ||
					result.state !== "pending"
				) {
					throw new Error("expected a live active CAS validation");
				}
				const descriptors = [
					traversal.legacyNamespaceDescriptor,
					active.fileDescriptor,
					...active.directoryFences.map((fence) => fence.descriptor),
					active.procfsAuthority.rootDescriptor,
					active.procfsAuthority.descriptorDirectoryDescriptor,
					active.procfsAuthority.descriptorInfoDirectoryDescriptor,
				];
				expect(traversal.deadlineTimer?.hasRef()).toBe(false);
				expect(vi.getTimerCount()).toBe(baselineTimers + 1);
				for (const descriptor of descriptors) expect(() => fstatSync(descriptor)).not.toThrow();

				if (exit === "complete") {
					const completed = finishRunHistoryProjection(target.compactor, request, 16, result.cursor);
					expect(completed.state).toBe("complete");
				} else if (exit === "incomplete") {
					renameSync(cas.casPath, `${cas.casPath}.replaced`);
					writeFileSync(cas.casPath, value, { mode: 0o600 });
					const incomplete = finishRunHistoryProjection(target.compactor, request, 16, result.cursor);
					expect(incomplete.state).toBe("incomplete");
					if (incomplete.state !== "incomplete") {
						throw new Error("expected injected CAS name replacement to fail closed");
					}
					expect(incomplete.reason).toMatch(
						/^run_history_cas_blob_(?:name_swapped|changed_during_read)$/,
					);
				} else if (exit === "cancel") {
					expect(target.compactor.cancelRunHistoryProjection(result.cursor)).toBe(true);
				} else if (exit === "close") {
					target.internal.closeSegmentStore();
				} else {
					await vi.advanceTimersByTimeAsync(101);
				}

				expect(target.internal.runHistoryTraversals.size).toBe(0);
				expectDescriptorsClosed(descriptors);
				expect(vi.getTimerCount()).toBe(baselineTimers);
				const afterExit = target.compactor.pruneSegmentHistory(
					anchor + 4 * DAY,
					createIncidentRecorderSegmentPruneProtection(0, []),
				);
				expect(afterExit.blockedByReadSnapshot).toBe(false);
			} finally {
				target.internal.closeSegmentStore();
				vi.useRealTimers();
			}
		},
	);

	it.each(["complete", "cancel", "close", "expiry"] as const)(
		"closes namespace, legacy directory, live Dir, and standalone proc descriptors after projection %s",
		async (exit) => {
			const target = fixture();
			const anchor = Date.now();
			const cas = writeCasFixture(target, Buffer.from("x"));
			let legacyDirectory = "";
			for (let index = 1; index <= 65; index += 1) {
				legacyDirectory = writeLegacyOccurrence(
					target,
					occurrenceInput(index, anchor, cas.digest, cas.casPath),
					index,
				).directory;
			}
			await initialize(target.compactor);
			vi.useFakeTimers();
			vi.setSystemTime(anchor);
			const baselineTimers = vi.getTimerCount();
			try {
				const request = {
					runId: RUN_ID,
					fromWallTimeMs: anchor,
					throughWallTimeMs: anchor + 1_000,
					deadlineMs: anchor + 100,
				};
				let result = target.compactor.projectRunHistory(request);
				for (let pass = 0; pass < 16; pass += 1) {
					const current = [...target.internal.runHistoryTraversals.values()][0];
					if (
						current?.directory &&
						current.legacyNamespaceDescriptor !== undefined &&
						current.legacyDirectoryDescriptor !== undefined &&
						current.procfsAuthority
					) {
						break;
					}
					if (result.state !== "pending") throw new Error("projection ended before live legacy traversal");
					result = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
				}
				const traversal = [...target.internal.runHistoryTraversals.values()][0];
				if (
					!traversal?.directory ||
					traversal.legacyNamespaceDescriptor === undefined ||
					traversal.legacyDirectoryDescriptor === undefined ||
					!traversal.procfsAuthority ||
					result.state !== "pending"
				) {
					throw new Error("expected a live legacy directory traversal");
				}
				const liveLegacyDirectoryDescriptors = descriptorsPointingTo(legacyDirectory);
				expect(liveLegacyDirectoryDescriptors).toContain(traversal.legacyDirectoryDescriptor);
				expect(liveLegacyDirectoryDescriptors.length).toBeGreaterThanOrEqual(2);
				const descriptors = [
					traversal.legacyNamespaceDescriptor,
					traversal.legacyDirectoryDescriptor,
					...liveLegacyDirectoryDescriptors,
					traversal.procfsAuthority.rootDescriptor,
					traversal.procfsAuthority.descriptorDirectoryDescriptor,
					traversal.procfsAuthority.descriptorInfoDirectoryDescriptor,
				];
				expect(traversal.deadlineTimer?.hasRef()).toBe(false);
				expect(vi.getTimerCount()).toBe(baselineTimers + 1);
				for (const descriptor of new Set(descriptors)) expect(() => fstatSync(descriptor)).not.toThrow();

				if (exit === "complete") {
					const completed = finishRunHistoryProjection(target.compactor, request, 32, result.cursor);
					expect(completed.state).toBe("complete");
				} else if (exit === "cancel") {
					expect(target.compactor.cancelRunHistoryProjection(result.cursor)).toBe(true);
				} else if (exit === "close") {
					target.internal.closeSegmentStore();
				} else {
					await vi.advanceTimersByTimeAsync(101);
				}

				expect(target.internal.runHistoryTraversals.size).toBe(0);
				expectDescriptorsClosed(descriptors);
				expect(vi.getTimerCount()).toBe(baselineTimers);
				const afterExit = target.compactor.pruneSegmentHistory(
					anchor + 4 * DAY,
					createIncidentRecorderSegmentPruneProtection(0, []),
				);
				expect(afterExit.blockedByReadSnapshot).toBe(false);
			} finally {
				target.internal.closeSegmentStore();
				vi.useRealTimers();
			}
		},
	);

	it.each(["gap", "corrupt-legacy"] as const)(
		"never completes a run history containing %s evidence",
		async (kind) => {
			const target = fixture();
			const anchor = Date.now();
			await initialize(target.compactor);
			if (kind === "gap") {
				target.internal.appendSegmentRecord({
					idempotencyKey: "gap:projection-gap",
					runId: RUN_ID,
					sourceId: "gap",
					observedAtMs: anchor,
					order: "1",
					metadata: { reason: "projection-test-gap" },
					payload: Buffer.from('{"reason":"projection-test-gap"}\n'),
				});
			} else {
				const identity = occurrenceIdentity(1);
				const legacyDirectory = join(
					target.agentDir,
					"incident-recorder",
					"refs",
					"runs",
					createHash("sha256").update(RUN_ID).digest("hex"),
				);
				mkdirSync(legacyDirectory, { recursive: true, mode: 0o700 });
				writeFileSync(
					join(legacyDirectory, `seq-${"1".padStart(20, "0")}-${identity.identityKey}.json`),
					"{truncated",
					{ mode: 0o600 },
				);
			}
			const result = finishRunHistoryProjection(target.compactor, {
				runId: RUN_ID,
				fromWallTimeMs: anchor,
				throughWallTimeMs: anchor + 1_000,
			});
			expect(result.state).toBe("incomplete");
			if (result.state !== "incomplete") throw new Error("expected explicit loss evidence");
			expect(result.projection.evidence[0]?.kind).toBe(kind === "gap" ? "gap" : "corrupt");
			target.internal.closeSegmentStore();
		},
	);

	it("returns truthful incomplete evidence for a gap-only recovered segment", async () => {
		const target = fixture();
		const anchor = Date.now();
		await initialize(target.compactor);
		target.internal.appendSegmentRecord({
			idempotencyKey: "unrelated:recovery-gap-prefix",
			runId: "unrelated-run",
			sourceId: "unrelated-source",
			observedAtMs: anchor,
			order: "1",
			metadata: {},
			payload: Buffer.from("unrelated"),
		});
		injectRecoveryGaps(target, [anchor + 2_000]);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected recovery-gap incompleteness");
		expect(result.reason).toBe("run_history_segment_recovery_gap_evidence");
		expect(result.projection.events).toEqual([]);
		expect(result.projection.evidence[0]).toMatchObject({
			kind: "gap",
			reference: {
				reason: "invalid_or_torn_active_tail",
				observedAtMs: anchor + 2_000,
				discardedBytes: 7,
			},
		});
		target.internal.closeSegmentStore();
	});

	it("never completes a mixed occurrence segment that also carries a recovery gap", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		const occurrence = occurrenceInput(1, anchor, cas.digest, cas.casPath);
		target.internal.appendSegmentRecord(occurrence.input);
		injectRecoveryGaps(target, [anchor + 2]);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected mixed recovery-gap incompleteness");
		expect(result.reason).toBe("run_history_segment_recovery_gap_evidence");
		expect(result.projection.events.map((event) => event.identityKey)).toEqual([
			occurrence.identityKey,
		]);
		expect(result.projection.evidence[0]?.kind).toBe("gap");
		target.internal.closeSegmentStore();
	});

	it("resumes bounded gap-free segments before surfacing a later global recovery gap", async () => {
		const target = fixture();
		const anchor = Date.now();
		await initialize(target.compactor);
		for (let index = 1; index <= 17; index += 1) {
			target.internal.appendSegmentRecord({
				idempotencyKey: `unrelated:recovery-gap-pagination:${index}`,
				runId: "unrelated-run",
				sourceId: "unrelated-source",
				observedAtMs: anchor,
				order: String(index),
				metadata: {},
				payload: Buffer.from("unrelated"),
			});
			if (index <= 16) target.internal.segmentStore?.seal(`gap-free-prefix-${index}`);
		}
		injectRecoveryGaps(target, [anchor + 2_000]);
		const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
		let result = target.compactor.projectRunHistory(request);
		let pendingPasses = 0;
		while (result.state === "pending" && pendingPasses < 20) {
			pendingPasses += 1;
			result = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
		}
		expect(pendingPasses).toBeGreaterThanOrEqual(9);
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected paged recovery-gap incompleteness");
		expect(result.reason).toBe("run_history_segment_recovery_gap_evidence");
		expect(result.projection.evidence[0]).toMatchObject({
			kind: "gap",
			reference: { observedAtMs: anchor + 2_000 },
		});
		target.internal.closeSegmentStore();
	});

	it("retains a kernel terminal fact without falsely treating it as a finalization candidate", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(occurrenceInput(1, anchor, pin.digest, pin.casPath).input);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected terminal projection completion");
		expect(result.projection.events[0]).toMatchObject({
			type: "kernel_unexpected_exit",
			terminal: true,
		});
		expect(result.projection.terminalEvents).toHaveLength(1);
		expect(result.projection.finalizationCandidates).toEqual([]);
		target.internal.closeSegmentStore();
	});

	it("exposes only exact supervisor-exit and capture-terminal expectation candidates", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		await initialize(target.compactor);
		const fixtures = [
			occurrenceInput(1, anchor, pin.digest, pin.casPath, {
				source: "recorder-events",
				type: "supervisor_exit",
				terminal: false,
			}),
			occurrenceInput(2, anchor, pin.digest, pin.casPath, {
				source: "recorder-control",
				type: "capture_channel_terminal",
				terminal: true,
			}),
			occurrenceInput(3, anchor, pin.digest, pin.casPath, {
				source: "wrong-source",
				type: "supervisor_exit",
			}),
			occurrenceInput(4, anchor, pin.digest, pin.casPath, {
				source: "recorder-control",
				type: "capture_channel_terminal",
				terminal: false,
			}),
		];
		for (const occurrence of fixtures) target.internal.appendSegmentRecord(occurrence.input);
		const result = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected candidate projection completion");
		expect(result.projection.finalizationCandidates).toEqual([
			{
				role: "supervisor_exit",
				identityKey: fixtures[0]?.identityKey,
				basis: "type_and_source_candidate",
				qualification: "candidate_requires_expectation_match",
			},
			{
				role: "capture_channel_terminal",
				identityKey: fixtures[1]?.identityKey,
				basis: "type_source_and_terminal_flag_candidate",
				qualification: "candidate_requires_expectation_match",
			},
		]);
		target.internal.closeSegmentStore();
	});

	it("turns a pruned query snapshot into explicit incomplete evidence instead of a partial manifest", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		await initialize(target.compactor);
		const cursors: string[] = [];
		for (let index = 1; index <= 64; index += 1) {
			const occurrence = occurrenceInput(index, anchor, pin.digest, pin.casPath);
			cursors.push(occurrence.cursor);
			target.internal.appendSegmentRecord(occurrence.input);
		}
		target.internal.segmentStore?.seal("first-query-generation");
		const last = occurrenceInput(65, anchor, pin.digest, pin.casPath);
		cursors.push(last.cursor);
		target.internal.appendSegmentRecord(last.input);
		target.internal.segmentStore?.seal("query-anchor");
		writeScanProof(pin.incidentDir, anchor, cursors);

		target.compactor.processPendingPins(anchor + 1);
		const beforePrune = target.compactor.accountedStorageBytes;
		const pruned = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(pruned.deletedSegmentIds).toHaveLength(1);
		expect(target.compactor.accountedStorageBytes).toBeLessThan(beforePrune);
		target.compactor.processPendingPins(anchor + 4 * DAY);
		expect(existsSync(join(pin.incidentDir, "journal-pin-manifest.json"))).toBe(false);
		const incomplete = JSON.parse(
			readFileSync(join(pin.incidentDir, "journal-pin-incomplete.json"), "utf8"),
		) as { reason?: unknown; retainedOccurrenceCount?: unknown };
		expect(incomplete).toMatchObject({
			reason: "segment_occurrence_query_failed_or_snapshot_stale",
			retainedOccurrenceCount: 64,
		});
		target.internal.closeSegmentStore();
	});

	it("runs the allocation-free recovery pruner only with explicit external writer exclusion", async () => {
		const target = fixture();
		await initialize(target.compactor);
		for (let index = 1; index <= 2; index += 1) {
			target.internal.appendSegmentRecord({
				idempotencyKey: `recovery:${index}`,
				runId: "recovery",
				sourceId: "gap",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
			target.internal.segmentStore?.seal(`recovery-${index}`);
		}
		const segmentDirectory = join(target.agentDir, "incident-recorder", "segments");
		const result = target.compactor.pruneSegmentHistoryForRecovery({
			externalWriterExcluded: true,
			protection: createIncidentRecorderSegmentPruneProtection(0, []),
			nowMs: Date.now() + 4 * DAY,
		});
		expect(result.deletedSegmentIds).toHaveLength(1);
		expect(existsSync(join(segmentDirectory, ".writer-owner.json"))).toBe(false);
	});
});
