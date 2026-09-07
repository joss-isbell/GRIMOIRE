import { createHash } from "node:crypto";
import {
	appendFileSync,
	chmodSync,
	closeSync,
	existsSync,
	fchmodSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	renameSync,
	rmSync,
	symlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	acquireIncidentCasTransactionDetailed,
	type IncidentCasFileMutation,
	type IncidentCasFileOpenOptions,
	type IncidentCasRelativePath,
	type IncidentCasRootMutation,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderRetainedRunHistoryResult,
	type IncidentRecorderRunHistoryCursor,
	type IncidentRecorderRunHistoryCursorOnlyResult,
	type IncidentRecorderRunHistoryPublicationCapability,
	type IncidentRecorderRunHistoryResult,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import {
	createIncidentRecorderSegmentPruneProtection,
	type IncidentRecorderSegmentAppendInput,
	type IncidentRecorderSegmentLocator,
	IncidentRecorderSegmentStore,
} from "../src/modes/daemon/incident-recorder-segment-store.js";
import type { IncidentJournalLine } from "../src/modes/daemon/incident-recorder-writer.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const roots: string[] = [];
const lifecycleLeases: IncidentRecorderWriterLifecycleLease[] = [];
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
	acceptEntry(fields: Readonly<Record<string, Buffer>>): void;
	assemblies: Map<string, unknown>;
	closeSegmentStore(): void;
	discardStoppedTargetStreams(): void;
	pendingEntries: unknown[];
	pendingPinCursor?: string;
	pendingPinDirectoryEntriesReadLastPass: number;
	pendingPinDirectoryTraversal?: {
		phase: "full" | "after-cursor" | "through-cursor";
		pendingNames: string[];
		pendingNameBytes: number;
	};
	readStableLegacyOccurrence(path: string, canonicalPath?: string): { value: unknown; bytes: number };
	openStableRunHistoryDirectory(path: string): { descriptor: number; identity: unknown };
	publishCasAndRunLease(
		root: IncidentCasRootMutation,
		input: {
			runId: string;
			digest: string;
			bytes: number;
			stagedPath: IncidentCasRelativePath;
			mtimeNs: bigint;
		},
		effects: unknown[],
	): { casPath: string; leasePath: string };
	segmentStore?: IncidentRecorderSegmentStore;
	stoppedTargetStreams: Map<string, Record<string, unknown>>;
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
	lifecycleLease: IncidentRecorderWriterLifecycleLease | undefined;
	acquireLifecycleLease(): IncidentRecorderWriterLifecycleLease | undefined;
	releaseLifecycleLease(): void;
} {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-compactor-segments-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const scanner = executable(root, "storage-scanner.cjs", 'process.stdout.write("1\\t1\\t0\\t0\\n");');
	let lifecycleLease: IncidentRecorderWriterLifecycleLease | undefined;
	const lifecycleContract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: "a".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: acquireIncidentRecorderNamespaceCas,
	};
	const defaultWriterLifecycleLease = (): IncidentRecorderWriterLifecycleLease | undefined => {
		if (!lifecycleLease) {
			const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, lifecycleContract);
			if (admission.state !== "acquired")
				throw new Error(`fixture lifecycle lease unavailable: ${admission.reason}`);
			lifecycleLease = admission.lease;
			lifecycleLeases.push(lifecycleLease);
		}
		return lifecycleLease;
	};
	const compactor = new IncidentRecorderCompactor({
		agentDir,
		storageScannerPath: scanner,
		freeReserveBytes: 0,
		writerLifecycleLease: defaultWriterLifecycleLease,
		...options,
	});
	return {
		root,
		agentDir,
		compactor,
		internal: compactor as unknown as CompactorInternals,
		get lifecycleLease() {
			return lifecycleLease;
		},
		acquireLifecycleLease() {
			return defaultWriterLifecycleLease();
		},
		releaseLifecycleLease() {
			lifecycleLease?.release();
		},
	};
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

function terminalJournalEntry(index: number, sequence: number): string {
	const fields = partialJournalEntry(index, sequence).split("\n");
	const messageIndex = fields.findIndex((entry) => entry.startsWith("MESSAGE="));
	if (messageIndex < 0) throw new Error("expected journal MESSAGE field");
	const line = JSON.parse(fields[messageIndex]?.slice("MESSAGE=".length) ?? "null") as Record<string, unknown>;
	const payload = Buffer.from(String(line.payloadBase64), "base64");
	const occurrenceSha256 = createHash("sha256").update(payload).digest("hex");
	const metadata = { occurrenceRawBytes: payload.length, occurrenceSha256 };
	const frame = encodeIncidentRecorderFrame(
		{
			runId: String(line.runId),
			runToken: String(line.runToken),
			producerId: String(line.producerId),
			occurrenceId: String(line.occurrenceId),
			producerSequence: BigInt(String(line.producerSequence)),
			wallTimeMs: BigInt(String(line.eventWallTimeMs)),
			monotonicNs: BigInt(String(line.eventMonotonicNs)),
			payloadKind: "exact-bytes",
			flags:
				INCIDENT_RECORDER_FRAME_FLAGS.critical |
				INCIDENT_RECORDER_FRAME_FLAGS.terminal |
				INCIDENT_RECORDER_FRAME_FLAGS.firstChunk |
				INCIDENT_RECORDER_FRAME_FLAGS.lastChunk,
			chunkIndex: 0,
			chunkCount: 1,
			source: String(line.source),
			type: String(line.type),
			encoding: String(line.encoding),
			metadata,
		},
		payload,
	);
	line.chunkIndex = 0;
	line.chunkCount = 1;
	line.rawOccurrenceBytes = payload.length;
	line.occurrenceSha256 = occurrenceSha256;
	line.chunkBytes = payload.length;
	line.chunkSha256 = createHash("sha256").update(payload).digest("hex");
	line.flags = frame.header.flags;
	line.frameChecksum = frame.header.checksum;
	line.metadata = metadata;
	fields[messageIndex] = `MESSAGE=${JSON.stringify(line)}`;
	return fields.join("\n");
}

function exportedJournalFields(value: string): Record<string, Buffer> {
	const fields: Record<string, Buffer> = {};
	for (const entry of value.split("\n")) {
		const separator = entry.indexOf("=");
		if (separator > 0) fields[entry.slice(0, separator)] = Buffer.from(entry.slice(separator + 1), "utf8");
	}
	return fields;
}

function occurrenceIdentity(index: number, producerId = PRODUCER_ID): { occurrenceId: string; identityKey: string } {
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
): {
	input: IncidentRecorderSegmentAppendInput;
	payload: Record<string, unknown>;
	cursor: string;
	identityKey: string;
} {
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
	const path = join(directory, `seq-${String(sequence).padStart(20, "0")}-${occurrence.identityKey}.json`);
	writeFileSync(path, `${JSON.stringify(payload)}\n`, { mode: 0o600 });
	return { directory, path };
}

function preparePinFixture(
	target: ReturnType<typeof fixture>,
	anchor: number,
): {
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

function writePendingJournalPinRequest(incidentDir: string, anchor: number, runId = RUN_ID): void {
	mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
	writeFileSync(
		join(incidentDir, "journal-pin-request.json"),
		`${JSON.stringify({
			version: 1,
			state: "pending",
			runId,
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
			resolveAfterWallTimeMs: anchor + 1_000,
			retainUntilWallTimeMs: anchor + 3 * DAY,
		})}\n`,
		{ mode: 0o600 },
	);
}

function writeCasFixture(
	target: ReturnType<typeof fixture>,
	value: Buffer,
): {
	digest: string;
	casPath: string;
} {
	const digest = createHash("sha256").update(value).digest("hex");
	const casPath = join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
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
	const descriptor = openSync("/proc", fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
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

type CasCapabilityProbeFault = "before_utimes" | "after_utimes";

interface CasCapabilityProbe {
	operations: string[];
	fault?: CasCapabilityProbeFault;
}

function observeCasCapability(
	root: IncidentCasRootMutation,
	probe: CasCapabilityProbe,
	target: { digest: string; runId: string },
): IncidentCasRootMutation {
	const casTokens = new Set<unknown>();
	const casDirectoryTokens = new Set<unknown>();
	const leaseTokens = new Set<unknown>();
	const leaseDirectoryTokens = new Set<unknown>();
	const casDirectoryComponents = ["cas", "sha256", target.digest.slice(0, 2)];
	const leaseDirectoryComponents = ["refs", "runs", createHash("sha256").update(target.runId).digest("hex")];
	const rootUtimes = Reflect.get(root, "utimes") as unknown;
	const observed: IncidentCasRootMutation & { utimes(...args: unknown[]): unknown } = {
		...root,
		relative(...components) {
			const path = root.relative(...components);
			if (
				components.length === casDirectoryComponents.length &&
				components.every((component, index) => component === casDirectoryComponents[index])
			) {
				casDirectoryTokens.add(path);
			} else if (
				components.length === casDirectoryComponents.length + 1 &&
				components.slice(0, -1).every((component, index) => component === casDirectoryComponents[index]) &&
				components.at(-1) === `${target.digest}.blob`
			) {
				casTokens.add(path);
			} else if (
				components.length === leaseDirectoryComponents.length &&
				components.every((component, index) => component === leaseDirectoryComponents[index])
			) {
				leaseDirectoryTokens.add(path);
			} else if (
				components.length === leaseDirectoryComponents.length + 1 &&
				components.slice(0, -1).every((component, index) => component === leaseDirectoryComponents[index]) &&
				components.at(-1) === `cas-${target.digest}.blob`
			) {
				leaseTokens.add(path);
			}
			return path;
		},
		hardLink(source, destination) {
			root.hardLink(source, destination);
			if (casTokens.has(destination)) {
				probe.operations.push("cas_linked");
			} else if (casTokens.has(source) && leaseTokens.has(destination)) {
				probe.operations.push("lease_linked");
			}
		},
		withFile<T>(
			path: IncidentCasRelativePath,
			options: IncidentCasFileOpenOptions,
			operation: (file: IncidentCasFileMutation) => T,
		): T {
			const result = root.withFile(path, options, operation);
			if (casTokens.has(path)) probe.operations.push("cas_validated");
			return result;
		},
		utimes(...args: unknown[]): unknown {
			probe.operations.push(casTokens.has(args[0]) ? "cas_utimes" : "opaque_utimes");
			if (probe.fault === "before_utimes") throw new Error("injected-cas-utimes");
			if (typeof rootUtimes !== "function") throw new Error("Opaque CAS utimes capability was unavailable");
			const result = Reflect.apply(rootUtimes, root, args);
			if (probe.fault === "after_utimes") throw new Error("injected-after-cas-utimes");
			return result;
		},
		fsyncFile(path) {
			root.fsyncFile(path);
			probe.operations.push(casTokens.has(path) ? "cas_fsynced" : "opaque_file_fsynced");
		},
		unlinkFile(path) {
			root.unlinkFile(path);
			if (casTokens.has(path)) probe.operations.push("cas_unlinked");
		},
		fsyncDirectory(path) {
			root.fsyncDirectory(path);
			if (casDirectoryTokens.has(path)) probe.operations.push("cas_directory_fsynced");
			else if (leaseDirectoryTokens.has(path)) probe.operations.push("lease_directory_fsynced");
		},
	};
	return observed;
}

function withCompactorCasRoot<T>(
	target: ReturnType<typeof fixture>,
	operation: (root: IncidentCasRootMutation) => T,
): T {
	const recorderRoot = join(target.agentDir, "incident-recorder");
	mkdirSync(recorderRoot, { recursive: true, mode: 0o700 });
	const admission = acquireIncidentCasTransactionDetailed(recorderRoot);
	if (admission.state !== "acquired") throw new Error(`CAS test transaction unavailable: ${admission.reason}`);
	try {
		const mutation = admission.transaction.withRoot(operation);
		if (mutation.state !== "committed") throw new Error("CAS test transaction root detached");
		return mutation.value;
	} finally {
		admission.transaction.release();
	}
}

function sealSegmentStoreWithinRoot(target: ReturnType<typeof fixture>, reason: string): void {
	const lease = target.lifecycleLease ?? target.acquireLifecycleLease();
	if (!lease) throw new Error("expected a writer lifecycle lease for segment seal");
	const store = target.internal.segmentStore;
	if (!store) throw new Error("expected a segment store for segment seal");
	const mutation = lease.withRoot((root) => store.sealWithinRoot(root, reason));
	if (mutation.state !== "committed") throw new Error("segment seal root detached");
}

function publishStagedCasForTest(
	target: ReturnType<typeof fixture>,
	input: { runId: string; value: Buffer; stageName: string; mtimeNs: bigint },
	probe: CasCapabilityProbe,
): { casPath: string; leasePath: string } {
	const digest = createHash("sha256").update(input.value).digest("hex");
	return withCompactorCasRoot(target, (root) => {
		const stagingDirectory = root.relative("cas", "sha256", "staging");
		root.mkdirPrivate(stagingDirectory, true);
		const stagedPath = root.relative("cas", "sha256", "staging", input.stageName);
		if (!root.exists(stagedPath)) root.writeFileExclusive(stagedPath, input.value, 0o600);
		return target.internal.publishCasAndRunLease(
			observeCasCapability(root, probe, { digest, runId: input.runId }),
			{
				runId: input.runId,
				digest,
				bytes: input.value.length,
				stagedPath,
				mtimeNs: input.mtimeNs,
			},
			[],
		);
	});
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
	request: {
		runId: string;
		fromWallTimeMs: number;
		throughWallTimeMs: number;
		deadlineMs?: number;
		pendingResponse?: "full" | "cursor-only";
	},
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

function finishRetainedRunHistoryProjection(
	compactor: IncidentRecorderCompactor,
	request: {
		runId: string;
		fromWallTimeMs: number;
		throughWallTimeMs: number;
		deadlineMs?: number;
		pendingResponse?: "full" | "cursor-only";
	},
	maximumPasses = 32,
	initialCursor?: IncidentRecorderRunHistoryCursor,
): IncidentRecorderRetainedRunHistoryResult {
	let cursor = initialCursor;
	for (let pass = 0; pass < maximumPasses; pass += 1) {
		const result = compactor.projectRunHistory({
			...request,
			retainForPublication: true,
			...(cursor ? { cursor } : {}),
		});
		if (result.state !== "pending") return result;
		cursor = result.cursor;
	}
	throw new Error("retained run-history projection did not finish within its bounded test passes");
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

	it("keeps root-backed segment mutation scoped and defers observers into ordered receipts", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const lease = target.acquireLifecycleLease();
		if (!lease) throw new Error("expected a writer lifecycle lease");
		const segmentDirectory = join(target.agentDir, "incident-recorder", "segments");
		let observerCalls = 0;
		let receipts: readonly ReturnType<IncidentRecorderSegmentStore["drainWithinRootReceipts"]>[number][] = [];
		const mutation = lease.withRoot((root) => {
			const store = IncidentRecorderSegmentStore.openWithinRoot(root, {
				directory: ["segments"],
				onOpenStorageResult: () => {
					observerCalls += 1;
				},
				onDurableWrite: () => {
					observerCalls += 1;
				},
			});
			const input: IncidentRecorderSegmentAppendInput = {
				idempotencyKey: "root-scoped-record",
				runId: "root-scoped-run",
				sourceId: "root-scoped-source",
				observedAtMs: 1,
				order: "1",
				metadata: {},
				payload: Buffer.from("root-scoped"),
			};
			expect(() => store.append(input)).toThrow(/unavailable for root-backed/);
			const appended = store.appendWithinRoot(root, input);
			expect(appended.status).toBe("appended");
			store.sealWithinRoot(root, "test");
			receipts = [...store.drainWithinRootReceipts(), ...store.closeWithinRoot(root)];
			expect(observerCalls).toBe(0);
		});
		expect(mutation.state).toBe("committed");
		expect(observerCalls).toBe(0);
		expect(receipts.map((receipt) => receipt.kind)).toEqual(["open", "durable", "durable", "durable", "open"]);
		const raw = new IncidentRecorderSegmentStore({ directory: segmentDirectory });
		try {
			expect(
				raw.queryRunWindow({
					runId: "root-scoped-run",
					sourceId: "root-scoped-source",
					fromObservedAtMs: 0,
					throughObservedAtMs: 10,
				}),
			).toHaveLength(1);
		} finally {
			raw.close();
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
		const closeFailure = new Error("injected segment-store close failure");
		const close = vi.spyOn(store, "closeWithinRoot").mockImplementation((_root) => {
			throw closeFailure;
		});
		const shutdown = new AbortController();
		try {
			await expect(
				target.compactor.run({
					signal: shutdown.signal,
					onStorageMode: () => shutdown.abort(),
				}),
			).rejects.toThrow("injected segment-store close failure");
			expect(shutdown.signal.aborted).toBe(true);
			expect(close).toHaveBeenCalledOnce();
		} finally {
			close.mockRestore();
			const lease = target.lifecycleLease;
			if (lease) {
				const mutation = lease.withRoot((root) => store.closeWithinRoot(root));
				expect(mutation.state).toBe("committed");
			}
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
			writerLifecycleLease: target.acquireLifecycleLease,
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
			close = vi.spyOn(store, "closeWithinRoot");
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

	it("orders opaque stopped-target timestamps before CAS durability and rolls back pre-fsync failures for retry", async () => {
		const operations: string[] = [];
		const target = fixture({ onCasPublicationStep: (step) => operations.push(step) });
		await initialize(target.compactor);
		const value = Buffer.from("opaque-cas-mtime");
		const digest = createHash("sha256").update(value).digest("hex");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		const casPath = join(recorderRoot, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
		const stageName = `${digest}.mtime-red.tmp`;
		const stagePath = join(recorderRoot, "cas", "sha256", "staging", stageName);
		const leasePath = join(
			recorderRoot,
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
			`cas-${digest}.blob`,
		);
		const mtimeNs = 1_700_000_000_123_000_000n;
		const probe: CasCapabilityProbe = { operations };

		for (const fault of ["before_utimes", "after_utimes"] as const) {
			operations.length = 0;
			probe.fault = fault;
			const failed = captureThrown(() =>
				publishStagedCasForTest(target, { runId: RUN_ID, value, stageName, mtimeNs }, probe),
			);
			expect(failed.threw).toBe(true);
			if (!failed.threw) throw new Error("expected opaque CAS utimes failure");
			expect(failed.error).toMatchObject({
				message: fault === "before_utimes" ? "injected-cas-utimes" : "injected-after-cas-utimes",
			});
			expect(operations).toEqual([
				"cas_linked",
				"cas_directory_fsynced",
				"cas_validated",
				"cas_utimes",
				"cas_unlinked",
				"cas_directory_fsynced",
			]);
			expect(existsSync(casPath)).toBe(false);
			expect(existsSync(leasePath)).toBe(false);
			expect(existsSync(stagePath)).toBe(true);
		}

		operations.length = 0;
		probe.fault = undefined;
		const retried = publishStagedCasForTest(target, { runId: RUN_ID, value, stageName, mtimeNs }, probe);
		expect(retried).toEqual({ casPath, leasePath });
		expect(operations).toEqual([
			"cas_linked",
			"cas_directory_fsynced",
			"cas_validated",
			"cas_utimes",
			"cas_fsynced",
			"cas_durable",
			"lease_linked",
			"lease_directory_fsynced",
			"lease_durable",
		]);
		const cas = lstatSync(casPath, { bigint: true });
		const lease = lstatSync(leasePath, { bigint: true });
		expect(cas.mtimeNs).toBe(mtimeNs);
		expect({ dev: lease.dev, ino: lease.ino, size: lease.size }).toEqual({
			dev: cas.dev,
			ino: cas.ino,
			size: BigInt(value.length),
		});
	});

	it("repairs only a same-inode staged CAS residue and never retimestamps an unrelated existing digest", async () => {
		const operations: string[] = [];
		const target = fixture({ onCasPublicationStep: (step) => operations.push(step) });
		await initialize(target.compactor);
		const recorderRoot = join(target.agentDir, "incident-recorder");
		const stagingDirectory = join(recorderRoot, "cas", "sha256", "staging");
		const repairedValue = Buffer.from("same-inode-cas-residue");
		const repairedDigest = createHash("sha256").update(repairedValue).digest("hex");
		const repairedCasDirectory = join(recorderRoot, "cas", "sha256", repairedDigest.slice(0, 2));
		const repairedCasPath = join(repairedCasDirectory, `${repairedDigest}.blob`);
		const repairedStageName = `${repairedDigest}.retained.tmp`;
		const repairedStagePath = join(stagingDirectory, repairedStageName);
		mkdirSync(stagingDirectory, { recursive: true, mode: 0o700 });
		mkdirSync(repairedCasDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(repairedStagePath, repairedValue, { mode: 0o600 });
		linkSync(repairedStagePath, repairedCasPath);
		const repairedMtimeNs = 1_600_000_000_456_000_000n;
		const repairedProbe: CasCapabilityProbe = { operations };
		const repaired = publishStagedCasForTest(
			target,
			{ runId: RUN_ID, value: repairedValue, stageName: repairedStageName, mtimeNs: repairedMtimeNs },
			repairedProbe,
		);
		expect(repaired.casPath).toBe(repairedCasPath);
		const repairedUtimes = operations.indexOf("cas_utimes");
		expect(repairedUtimes).toBeGreaterThanOrEqual(0);
		expect(operations.slice(0, repairedUtimes)).toContain("cas_validated");
		expect(operations.slice(repairedUtimes, repairedUtimes + 3)).toEqual([
			"cas_utimes",
			"cas_fsynced",
			"cas_durable",
		]);
		expect(operations).not.toContain("opaque_utimes");
		expect(lstatSync(repairedCasPath, { bigint: true }).mtimeNs).toBe(repairedMtimeNs);

		const sharedValue = Buffer.from("unrelated-existing-cas");
		const sharedDigest = createHash("sha256").update(sharedValue).digest("hex");
		const sharedCasDirectory = join(recorderRoot, "cas", "sha256", sharedDigest.slice(0, 2));
		const sharedCasPath = join(sharedCasDirectory, `${sharedDigest}.blob`);
		const sharedStageName = `${sharedDigest}.unrelated.tmp`;
		const sharedStagePath = join(stagingDirectory, sharedStageName);
		mkdirSync(sharedCasDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(sharedCasPath, sharedValue, { mode: 0o600 });
		writeFileSync(sharedStagePath, sharedValue, { mode: 0o600 });
		const sharedTime = new Date(1_500_000_000_789);
		utimesSync(sharedCasPath, sharedTime, sharedTime);
		const sharedMtimeNs = lstatSync(sharedCasPath, { bigint: true }).mtimeNs;
		operations.length = 0;
		const sharedProbe: CasCapabilityProbe = { operations, fault: "before_utimes" };
		const shared = publishStagedCasForTest(
			target,
			{
				runId: "44444444-4444-4444-8444-444444444444",
				value: sharedValue,
				stageName: sharedStageName,
				mtimeNs: 1_800_000_000_321_000_000n,
			},
			sharedProbe,
		);
		expect(shared.casPath).toBe(sharedCasPath);
		expect(operations).not.toContain("opaque_utimes");
		expect(operations).not.toContain("cas_utimes");
		expect(lstatSync(sharedCasPath, { bigint: true }).mtimeNs).toBe(sharedMtimeNs);
		expect(lstatSync(shared.leasePath, { bigint: true }).ino).toBe(lstatSync(sharedCasPath, { bigint: true }).ino);
	});

	it("carries the stopped target source mtime into a newly published canonical CAS blob", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const value = Buffer.from("stopped-target-source-mtime");
		const sourcePath = join(target.root, "stopped-target-source-mtime.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const sourceTime = new Date(1_650_000_000_234);
		utimesSync(sourcePath, sourceTime, sourceTime);
		const sourceMtimeNs = lstatSync(sourcePath, { bigint: true }).mtimeNs;
		const digest = createHash("sha256").update(value).digest("hex");
		const casPath = join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);

		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: value.length + 1,
			}),
		).toMatchObject({ state: "complete", artifact: { path: casPath } });
		expect(lstatSync(casPath, { bigint: true }).mtimeNs).toBe(sourceMtimeNs);
	});

	it("does not stage a stopped target without a configured normal writer lease", async () => {
		const target = fixture({ writerLifecycleLease: () => undefined });
		await initialize(target.compactor);
		const value = Buffer.from("missing-writer-lease");
		const sourcePath = join(target.root, "missing-writer-lease.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const stagingDirectory = join(target.agentDir, "incident-recorder", "cas", "sha256", "staging");

		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: value.length + 1,
			}),
		).toEqual({
			state: "pending",
			reason: "writer_lifecycle_lease_required",
			copiedBytes: 0,
			totalBytes: 0,
		});
		expect(existsSync(stagingDirectory)).toBe(false);
	});

	it("does not stage a stopped target after its normal writer lease is released", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const lease = target.acquireLifecycleLease();
		if (!lease) throw new Error("expected fixture writer lease");
		expect(lease.release().state).toBe("released");
		const value = Buffer.from("released-writer-lease");
		const sourcePath = join(target.root, "released-writer-lease.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const stagingDirectory = join(target.agentDir, "incident-recorder", "cas", "sha256", "staging");

		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: value.length + 1,
			}),
		).toEqual({
			state: "pending",
			reason: "writer_lifecycle_lease_released",
			copiedBytes: 0,
			totalBytes: 0,
		});
		expect(existsSync(stagingDirectory)).toBe(false);
	});

	it("retains a stopped-target cleanup reservation while its writer lease is unavailable", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const value = Buffer.from("retained-cleanup-state");
		const sourcePath = join(target.root, "retained-cleanup-state.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const first = target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1,
		});
		expect(first).toMatchObject({ state: "pending", reason: "work_budget", copiedBytes: 1 });
		const lease = target.acquireLifecycleLease();
		if (!lease) throw new Error("expected fixture writer lease");
		lease.release();

		target.internal.discardStoppedTargetStreams();
		const retainedState = [...target.internal.stoppedTargetStreams.values()][0];
		expect(retainedState).toBeDefined();
		expect(retainedState?.reservationReleased).toBe(false);
		expect(existsSync(join(target.agentDir, "incident-recorder", "cas", "sha256", "staging"))).toBe(true);
	});

	it("does not discard a partial stage with an unrecognized link count", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const value = Buffer.from("unknown-stage-link-count");
		const sourcePath = join(target.root, "unknown-stage-link-count.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const first = target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1,
		});
		expect(first).toMatchObject({ state: "pending", reason: "work_budget", copiedBytes: 1 });
		const key = createHash("sha256").update(`${RUN_ID}\0${sourcePath}\0binary`).digest("hex");
		const stagedPath = join(target.agentDir, "incident-recorder", "cas", "sha256", "staging", `${key}.tmp`);
		const foreignLinks = [1, 2, 3].map((index) => `${stagedPath}.foreign-${index}`);
		for (const foreignLink of foreignLinks) linkSync(stagedPath, foreignLink);
		expect(lstatSync(stagedPath, { bigint: true }).nlink).toBe(4n);

		target.internal.discardStoppedTargetStreams();
		const retainedState = [...target.internal.stoppedTargetStreams.values()][0];
		expect(retainedState).toBeDefined();
		expect(retainedState?.reservationReleased).toBe(false);
		expect(existsSync(stagedPath)).toBe(true);
		expect(lstatSync(stagedPath, { bigint: true }).nlink).toBe(4n);
	});

	it("does not delete a replaced stopped-target stage during cleanup", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const value = Buffer.from("replaced-cleanup-stage");
		const sourcePath = join(target.root, "replaced-cleanup-stage.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 1,
			}),
		).toMatchObject({ state: "pending", reason: "work_budget", copiedBytes: 1 });
		const key = createHash("sha256").update(`${RUN_ID}\0${sourcePath}\0binary`).digest("hex");
		const stagedPath = join(target.agentDir, "incident-recorder", "cas", "sha256", "staging", `${key}.tmp`);
		const retainedPath = `${stagedPath}.retained`;
		renameSync(stagedPath, retainedPath);
		const foreignValue = Buffer.from("foreign-stage");
		writeFileSync(stagedPath, foreignValue, { mode: 0o600 });

		target.internal.discardStoppedTargetStreams();
		const retainedState = [...target.internal.stoppedTargetStreams.values()][0];
		expect(retainedState).toBeDefined();
		expect(retainedState?.reservationReleased).toBe(false);
		expect(readFileSync(stagedPath)).toEqual(foreignValue);
	});

	it("does not stage into a replacement recorder root after lifecycle identity replacement", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const lease = target.acquireLifecycleLease();
		if (!lease) throw new Error("expected fixture writer lease");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		const retainedRoot = `${recorderRoot}.retained`;
		renameSync(recorderRoot, retainedRoot);
		mkdirSync(recorderRoot, { mode: 0o700 });
		const value = Buffer.from("replacement-recorder-root");
		const sourcePath = join(target.root, "replacement-recorder-root.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });

		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: value.length + 1,
			}),
		).toMatchObject({
			state: "pending",
			reason: "writer_lifecycle_namespace_changed",
			copiedBytes: 0,
			totalBytes: value.length,
		});
		expect(readdirSync(recorderRoot)).toEqual([]);
		expect(existsSync(join(retainedRoot, "cas", "sha256", "staging"))).toBe(false);
	});

	it("retries an occurrence after lifecycle loss without converting it to a durable gap", async () => {
		let replaced = false;
		const target = fixture({
			onCasPublicationStep: (step) => {
				if (step !== "cas_durable" || replaced) return;
				replaced = true;
				const recorderRoot = join(target.agentDir, "incident-recorder");
				renameSync(recorderRoot, `${recorderRoot}.retained`);
				mkdirSync(recorderRoot, { mode: 0o700 });
			},
		});
		await initialize(target.compactor);
		const fields = exportedJournalFields(terminalJournalEntry(902, 1));
		let thrown: unknown;
		try {
			target.internal.acceptEntry(fields);
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(Error);
		expect(thrown).toMatchObject({ name: "IncidentRecorderWriterLifecycleAdmissionError" });
		expect(target.internal.pendingEntries).toHaveLength(0);
		expect(target.internal.assemblies.size).toBe(1);
		expect(target.compactor.storageAccountingReady).toBe(false);
		expect(target.compactor.storageMode).toBe("recovery-only");
		expect(target.internal.segmentStore).toBeUndefined();
		expect(existsSync(join(target.agentDir, "incident-recorder", "compactor-cursor.json"))).toBe(false);
		expect(existsSync(join(target.agentDir, "incident-recorder", "segments"))).toBe(false);
	});

	it("publishes first-use nested CAS and run-lease paths durably and resumes after the CAS crash boundary", async () => {
		let failAtStep: "cas_durable" | "lease_durable" | undefined = "cas_durable";
		let activeLease: IncidentRecorderWriterLifecycleLease | undefined;
		const target = fixture({
			writerLifecycleLease: () => activeLease,
			onCasPublicationStep: (step) => {
				if (step === failAtStep) throw new Error(`injected-after-${step}-fsync`);
			},
		});
		await initialize(target.compactor);
		activeLease = target.acquireLifecycleLease();
		if (!activeLease) throw new Error("expected fixture writer lease");
		const value = Buffer.from("first-use-cas");
		const sourcePath = join(target.root, "first-use-cas.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const digest = createHash("sha256").update(value).digest("hex");
		const casPath = join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
		const leasePath = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
			`cas-${digest}.blob`,
		);
		const before = target.compactor.accountedStorageBytes;
		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: value.length + 1,
			}),
		).toMatchObject({ state: "pending", reason: "writer_lifecycle_unavailable" });
		expect(readFileSync(casPath)).toEqual(value);
		expect(existsSync(leasePath)).toBe(false);

		const lifecycleContract: IncidentRecorderWriterLifecycleAdmissionContract = {
			activationGenerationDigest: "a".repeat(64),
			revalidateActivation: () => ({ state: "valid" }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		};
		expect(activeLease.release().state).toBe("released");
		const admission = acquireIncidentRecorderWriterNormalLease({ agentDir: target.agentDir }, lifecycleContract);
		if (admission.state !== "acquired") throw new Error(`retry lease unavailable: ${admission.reason}`);
		activeLease = admission.lease;
		lifecycleLeases.push(activeLease);
		failAtStep = undefined;
		const published = target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: value.length + 1,
		});
		expect(published).toEqual({
			state: "complete",
			artifact: { algorithm: "sha256", digest, bytes: value.length, path: casPath, encoding: "binary" },
		});
		const cas = lstatSync(casPath);
		const lease = lstatSync(leasePath);
		expect({ dev: lease.dev, ino: lease.ino, size: lease.size }).toEqual({
			dev: cas.dev,
			ino: cas.ino,
			size: value.length,
		});
		const afterPublication = target.compactor.accountedStorageBytes;
		expect(target.compactor.accountedStorageBytes).toBeGreaterThan(before);
		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: value.length + 1,
			}),
		).toEqual({
			state: "complete",
			artifact: { algorithm: "sha256", digest, bytes: value.length, path: casPath, encoding: "binary" },
		});
		expect(target.compactor.accountedStorageBytes).toBe(afterPublication);

		const restartValue = Buffer.from("first-use-cas-restart");
		const restartSourcePath = join(target.root, "first-use-cas-restart.bin");
		writeFileSync(restartSourcePath, restartValue, { mode: 0o600 });
		const restartDigest = createHash("sha256").update(restartValue).digest("hex");
		const restartCasPath = join(
			target.agentDir,
			"incident-recorder",
			"cas",
			"sha256",
			restartDigest.slice(0, 2),
			`${restartDigest}.blob`,
		);
		const restartLeasePath = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
			`cas-${restartDigest}.blob`,
		);
		failAtStep = "cas_durable";
		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, restartSourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: restartValue.length + 1,
			}),
		).toMatchObject({ state: "pending", reason: "writer_lifecycle_unavailable" });
		expect(readFileSync(restartCasPath)).toEqual(restartValue);
		expect(existsSync(restartLeasePath)).toBe(false);
		expect(activeLease.release().state).toBe("released");
		const restartAdmission = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: target.agentDir },
			lifecycleContract,
		);
		if (restartAdmission.state !== "acquired")
			throw new Error(`fresh restart lease unavailable: ${restartAdmission.reason}`);
		lifecycleLeases.push(restartAdmission.lease);
		const restarted = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			freeReserveBytes: 0,
			writerLifecycleLease: () => restartAdmission.lease,
		});
		await initialize(restarted);
		const resumedAfterRestart = restarted.streamStoppedTargetArtifact(RUN_ID, restartSourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: restartValue.length + 1,
		});
		expect(resumedAfterRestart).toEqual({
			state: "complete",
			artifact: {
				algorithm: "sha256",
				digest: restartDigest,
				bytes: restartValue.length,
				path: restartCasPath,
				encoding: "binary",
			},
		});
		expect(readFileSync(restartCasPath)).toEqual(restartValue);
		const restartCas = lstatSync(restartCasPath);
		const restartLease = lstatSync(restartLeasePath);
		expect({ dev: restartLease.dev, ino: restartLease.ino, size: restartLease.size }).toEqual({
			dev: restartCas.dev,
			ino: restartCas.ino,
			size: restartValue.length,
		});

		activeLease = restartAdmission.lease;
		const leaseDurableValue = Buffer.from("first-use-cas-lease-durable");
		const leaseDurableSourcePath = join(target.root, "first-use-cas-lease-durable.bin");
		writeFileSync(leaseDurableSourcePath, leaseDurableValue, { mode: 0o600 });
		const leaseDurableDigest = createHash("sha256").update(leaseDurableValue).digest("hex");
		const leaseDurableCasPath = join(
			target.agentDir,
			"incident-recorder",
			"cas",
			"sha256",
			leaseDurableDigest.slice(0, 2),
			`${leaseDurableDigest}.blob`,
		);
		const leaseDurableLeasePath = join(
			target.agentDir,
			"incident-recorder",
			"refs",
			"runs",
			createHash("sha256").update(RUN_ID).digest("hex"),
			`cas-${leaseDurableDigest}.blob`,
		);
		const leaseDurableStagePath = join(
			target.agentDir,
			"incident-recorder",
			"cas",
			"sha256",
			"staging",
			`${createHash("sha256").update(`${RUN_ID}\0${leaseDurableSourcePath}\0binary`).digest("hex")}.tmp`,
		);
		failAtStep = "lease_durable";
		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, leaseDurableSourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: leaseDurableValue.length + 1,
			}),
		).toMatchObject({ state: "pending", reason: "writer_lifecycle_unavailable" });
		expect(readFileSync(leaseDurableCasPath)).toEqual(leaseDurableValue);
		expect(readFileSync(leaseDurableLeasePath)).toEqual(leaseDurableValue);
		const leaseDurableCas = lstatSync(leaseDurableCasPath, { bigint: true });
		const leaseDurableLease = lstatSync(leaseDurableLeasePath, { bigint: true });
		const leaseDurableStage = lstatSync(leaseDurableStagePath, { bigint: true });
		expect(leaseDurableCas.nlink).toBe(3n);
		expect(leaseDurableStage.nlink).toBe(3n);
		expect({ dev: leaseDurableLease.dev, ino: leaseDurableLease.ino, size: leaseDurableLease.size }).toEqual({
			dev: leaseDurableCas.dev,
			ino: leaseDurableCas.ino,
			size: BigInt(leaseDurableValue.length),
		});
		const foreignStageLink = `${leaseDurableStagePath}.foreign`;
		linkSync(leaseDurableStagePath, foreignStageLink);
		expect(
			target.compactor.streamStoppedTargetArtifact(RUN_ID, leaseDurableSourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: leaseDurableValue.length + 1,
			}),
		).toMatchObject({ state: "pending", reason: "artifact_staging_reconciliation_required" });
		expect(lstatSync(leaseDurableStagePath, { bigint: true }).nlink).toBe(4n);
		expect(existsSync(foreignStageLink)).toBe(true);
		rmSync(foreignStageLink);
		expect(lstatSync(leaseDurableStagePath, { bigint: true }).nlink).toBe(3n);
		expect(activeLease.release().state).toBe("released");
		const leaseDurableAdmission = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: target.agentDir },
			lifecycleContract,
		);
		if (leaseDurableAdmission.state !== "acquired")
			throw new Error(`lease-durable restart lease unavailable: ${leaseDurableAdmission.reason}`);
		lifecycleLeases.push(leaseDurableAdmission.lease);
		const leaseDurableRestarted = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			freeReserveBytes: 0,
			writerLifecycleLease: () => leaseDurableAdmission.lease,
		});
		await initialize(leaseDurableRestarted);
		expect(
			leaseDurableRestarted.streamStoppedTargetArtifact(RUN_ID, leaseDurableSourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: leaseDurableValue.length + 1,
			}),
		).toEqual({
			state: "complete",
			artifact: {
				algorithm: "sha256",
				digest: leaseDurableDigest,
				bytes: leaseDurableValue.length,
				path: leaseDurableCasPath,
				encoding: "binary",
			},
		});
		expect(existsSync(join(target.agentDir, "incident-recorder", "cas", "sha256", "staging"))).toBe(true);
		expect(existsSync(leaseDurableStagePath)).toBe(false);
	});

	it("reopens stopped-target files per capability scope and rejects a detached root without touching its successor", async () => {
		let swapRoot = false;
		let retainedRoot = "";
		let recorderRootToSwap = "";
		const target = fixture({
			onCasPublicationStep: (step) => {
				if (step !== "cas_durable" || !swapRoot) return;
				swapRoot = false;
				retainedRoot = `${recorderRootToSwap}.retained`;
				renameSync(recorderRootToSwap, retainedRoot);
				mkdirSync(recorderRootToSwap, { mode: 0o700 });
			},
		});
		recorderRootToSwap = join(target.agentDir, "incident-recorder");
		await initialize(target.compactor);
		const sourcePath = join(target.root, "detached-source.bin");
		const value = Buffer.from("detached-stopped-target");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const first = target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1,
		});
		expect(first).toMatchObject({ state: "pending", reason: "work_budget", copiedBytes: 1 });
		const stagingPath = join(
			target.agentDir,
			"incident-recorder",
			"cas",
			"sha256",
			"staging",
			`${createHash("sha256").update(`${RUN_ID}\0${sourcePath}\0binary`).digest("hex")}.tmp`,
		);
		expect(descriptorsPointingTo(sourcePath)).toEqual([]);
		expect(descriptorsPointingTo(stagingPath)).toEqual([]);
		const retainedState = [...target.internal.stoppedTargetStreams.values()][0];
		expect(retainedState).toBeDefined();
		expect(Object.keys(retainedState ?? {})).not.toEqual(
			expect.arrayContaining(["source", "target", "temporary", "descriptor", "root"]),
		);

		swapRoot = true;
		const detached = target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: value.length + 1,
		});
		expect(detached).toMatchObject({ state: "pending", reason: "writer_lifecycle_namespace_changed" });
		expect(target.internal.stoppedTargetStreams.size).toBe(1);
		expect(readdirSync(join(target.agentDir, "incident-recorder"))).toEqual([]);
		expect(retainedRoot).not.toBe("");
		expect(
			readFileSync(
				join(
					retainedRoot,
					"cas",
					"sha256",
					createHash("sha256").update(value).digest("hex").slice(0, 2),
					`${createHash("sha256").update(value).digest("hex")}.blob`,
				),
			),
		).toEqual(value);
	});

	it("rehydrates an owned stopped-target stage after compactor restart", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const value = Buffer.from("restart-safe-stopped-target-artifact");
		const sourcePath = join(target.root, "restart-safe-stopped-target.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const first = target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 5,
		});
		expect(first).toMatchObject({ state: "pending", reason: "work_budget", copiedBytes: 5 });
		const lifecycleContract: IncidentRecorderWriterLifecycleAdmissionContract = {
			activationGenerationDigest: "a".repeat(64),
			revalidateActivation: () => ({ state: "valid" }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		};
		target.releaseLifecycleLease();
		const admission = acquireIncidentRecorderWriterNormalLease({ agentDir: target.agentDir }, lifecycleContract);
		if (admission.state !== "acquired") throw new Error(`restart lease unavailable: ${admission.reason}`);
		lifecycleLeases.push(admission.lease);
		const restarted = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			freeReserveBytes: 0,
			writerLifecycleLease: () => admission.lease,
		});
		await initialize(restarted);
		const resumed = restarted.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: value.length + 1,
		});
		expect(resumed).toMatchObject({ state: "complete" });
		const digest = createHash("sha256").update(value).digest("hex");
		expect(
			readFileSync(
				join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2), `${digest}.blob`),
			),
		).toEqual(value);
	});

	it("leaves a mismatching restart stage untouched with explicit reconciliation evidence", async () => {
		const target = fixture();
		await initialize(target.compactor);
		const value = Buffer.from("restart-stage-source-content");
		const sourcePath = join(target.root, "restart-stage-source.bin");
		writeFileSync(sourcePath, value, { mode: 0o600 });
		const first = target.compactor.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 5,
		});
		expect(first).toMatchObject({ state: "pending", reason: "work_budget", copiedBytes: 5 });
		const key = createHash("sha256").update(`${RUN_ID}\0${sourcePath}\0binary`).digest("hex");
		const stagedPath = join(target.agentDir, "incident-recorder", "cas", "sha256", "staging", `${key}.tmp`);
		const foreignValue = Buffer.from("foreign");
		writeFileSync(stagedPath, foreignValue, { mode: 0o600 });
		const lifecycleContract: IncidentRecorderWriterLifecycleAdmissionContract = {
			activationGenerationDigest: "a".repeat(64),
			revalidateActivation: () => ({ state: "valid" }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		};
		target.releaseLifecycleLease();
		const admission = acquireIncidentRecorderWriterNormalLease({ agentDir: target.agentDir }, lifecycleContract);
		if (admission.state !== "acquired") throw new Error(`restart lease unavailable: ${admission.reason}`);
		lifecycleLeases.push(admission.lease);
		const restarted = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			freeReserveBytes: 0,
			writerLifecycleLease: () => admission.lease,
		});
		await initialize(restarted);
		expect(
			restarted.streamStoppedTargetArtifact(RUN_ID, sourcePath, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: value.length + 1,
			}),
		).toMatchObject({
			state: "pending",
			reason: "artifact_staging_reconciliation_required",
		});
		expect(readFileSync(stagedPath)).toEqual(foreignValue);
	});

	it("bounds incident-root discovery while progressing past many unrelated directories without losing journal evidence", async () => {
		const target = fixture({
			pendingPinDirectoryDiscoveryEntriesPerPass: 5,
			pendingPinDirectoryBatchCount: 5,
		});
		const anchor = Date.now();
		const incidentRoot = join(target.agentDir, "incidents");
		for (let index = 0; index < 301; index += 1) {
			mkdirSync(join(incidentRoot, `empty-${index.toString().padStart(4, "0")}`), {
				recursive: true,
				mode: 0o700,
			});
		}
		const pin = preparePinFixture(target, anchor);
		await initialize(target.compactor);
		const occurrence = occurrenceInput(1, anchor, pin.digest, pin.casPath);
		target.internal.appendSegmentRecord(occurrence.input);
		writeScanProof(pin.incidentDir, anchor, [occurrence.cursor]);
		const manifestPath = join(pin.incidentDir, "journal-pin-manifest.json");

		for (let pass = 0; pass < 256 && !existsSync(manifestPath); pass += 1) {
			target.compactor.processPendingPins(anchor + 1);
			expect(target.internal.pendingPinDirectoryEntriesReadLastPass).toBeLessThanOrEqual(5);
			const traversal = target.internal.pendingPinDirectoryTraversal;
			if (traversal) {
				expect(traversal.pendingNames.length).toBeLessThanOrEqual(5);
				expect(traversal.pendingNameBytes).toBeLessThanOrEqual(5 * 4096);
			}
		}

		expect(existsSync(manifestPath)).toBe(true);
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
			version?: unknown;
			occurrences?: Array<{
				occurrenceReference?: { kind?: unknown; locator?: unknown };
				cursors?: unknown;
				cas?: { digest?: unknown };
			}>;
		};
		expect(manifest.version).toBe(2);
		expect(manifest.occurrences).toHaveLength(1);
		expect(manifest.occurrences?.[0]).toMatchObject({
			occurrenceReference: { kind: "segment" },
			cursors: [occurrence.cursor],
			cas: { digest: pin.digest },
		});
		target.internal.closeSegmentStore();
	});

	it("resumes a cursor sweep after restart and fairly reconsiders names inserted on both sides of the cursor", async () => {
		const target = fixture({
			pendingPinDirectoryDiscoveryEntriesPerPass: 1,
			pendingPinDirectoryBatchCount: 1,
		});
		const anchor = Date.now();
		const incidentRoot = join(target.agentDir, "incidents");
		mkdirSync(join(incidentRoot, "middle-cursor"), { recursive: true, mode: 0o700 });
		await initialize(target.compactor);
		target.compactor.processPendingPins(anchor);
		expect(target.internal.pendingPinCursor).toBe("middle-cursor");
		expect(target.internal.pendingPinDirectoryEntriesReadLastPass).toBe(1);
		target.internal.closeSegmentStore();

		const later = join(incidentRoot, "zzz-existing-request");
		const earlier = join(incidentRoot, "000-new-request");
		writePendingJournalPinRequest(later, anchor);
		writePendingJournalPinRequest(earlier, anchor);
		const restarted = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			freeReserveBytes: 0,
			writerLifecycleLease: () => target.lifecycleLease,
			pendingPinDirectoryDiscoveryEntriesPerPass: 1,
			pendingPinDirectoryBatchCount: 1,
		});
		const restartedInternal = restarted as unknown as CompactorInternals;
		await initialize(restarted);
		for (
			let pass = 0;
			pass < 32 &&
			(!existsSync(join(later, "sysdig-pin-incomplete.json")) ||
				!existsSync(join(earlier, "sysdig-pin-incomplete.json")));
			pass += 1
		) {
			restarted.processPendingPins(anchor);
			expect(restartedInternal.pendingPinDirectoryEntriesReadLastPass).toBeLessThanOrEqual(1);
		}
		expect(existsSync(join(later, "sysdig-pin-incomplete.json"))).toBe(true);
		expect(existsSync(join(earlier, "sysdig-pin-incomplete.json"))).toBe(true);
		restartedInternal.closeSegmentStore();
	});

	it("discovers a stranded Sysdig request through a bounded root sweep and restores its journal pair", async () => {
		const ringDirectory = mkdtempSync(join(tmpdir(), "prime-agent-bounded-sysdig-"));
		const target = fixture({
			sysdigRingBasePath: join(ringDirectory, "ring.scap"),
			pendingPinDirectoryDiscoveryEntriesPerPass: 3,
			pendingPinDirectoryBatchCount: 3,
		});
		roots.push(ringDirectory);
		mkdirSync(ringDirectory, { recursive: true, mode: 0o700 });
		const anchor = Date.now();
		const incidentRoot = join(target.agentDir, "incidents");
		for (let index = 0; index < 40; index += 1) {
			mkdirSync(join(incidentRoot, `unrelated-${index.toString().padStart(3, "0")}`), {
				recursive: true,
				mode: 0o700,
			});
		}
		const incidentDir = join(incidentRoot, "sysdig-only-request");
		mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
		const requester = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			sysdigRingBasePath: join(ringDirectory, "ring.scap"),
			freeReserveBytes: 0,
			onSysdigPinStep: (step) => {
				if (step === "sysdig_request_durable") throw new Error("stranded-after-sysdig-request");
			},
		});
		await initialize(requester);
		expect(() => requester.requestPin(RUN_ID, incidentDir, anchor)).toThrow("stranded-after-sysdig-request");
		expect(existsSync(join(incidentDir, "sysdig-pin-request.json"))).toBe(true);
		expect(existsSync(join(incidentDir, "journal-pin-request.json"))).toBe(false);

		await initialize(target.compactor);
		for (let pass = 0; pass < 64 && !existsSync(join(incidentDir, "journal-pin-request.json")); pass += 1) {
			target.compactor.processPendingPins(anchor);
			expect(target.internal.pendingPinDirectoryEntriesReadLastPass).toBeLessThanOrEqual(3);
		}
		expect(existsSync(join(incidentDir, "journal-pin-request.json"))).toBe(true);
		expect(JSON.parse(readFileSync(join(incidentDir, "journal-pin-request.json"), "utf8"))).toMatchObject({
			version: 1,
			state: "pending",
			runId: RUN_ID,
			anchorWallTimeMs: anchor,
		});
		target.internal.closeSegmentStore();
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
		expect(
			manifest.occurrences.every((entry) => {
				const reference = entry.occurrenceReference as { kind?: unknown; locator?: unknown };
				return reference.kind === "segment" && typeof reference.locator === "object";
			}),
		).toBe(true);

		rmSync(join(pin.incidentDir, "journal-pin-retention-proof.json"), { force: true });
		target.internal.closeSegmentStore();
		const validator = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: join(target.root, "storage-scanner.cjs"),
			freeReserveBytes: 0,
			writerLifecycleLease: () => target.lifecycleLease,
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
		for (let pass = 0; pass < 10 && !existsSync(join(pin.incidentDir, "journal-pin-incomplete.json")); pass += 1) {
			target.compactor.processPendingPins(anchor + 1);
		}
		const incomplete = JSON.parse(readFileSync(join(pin.incidentDir, "journal-pin-incomplete.json"), "utf8")) as {
			reason?: unknown;
		};
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
			const path = join(legacyRunDirectory, `seq-${"1".padStart(20, "0")}-${identity.identityKey}.json`);
			if (kind === "symlink") {
				const source = join(target.root, "forged-legacy.json");
				writeFileSync(source, "{}\n", { mode: 0o600 });
				symlinkSync(source, path);
			} else {
				writeFileSync(path, Buffer.alloc(64 * 1024 + 1, 0x20), { mode: 0o600 });
			}
			writeScanProof(pin.incidentDir, anchor, []);
			await initialize(target.compactor);
			for (let pass = 0; pass < 5 && !existsSync(join(pin.incidentDir, "journal-pin-incomplete.json")); pass += 1) {
				target.compactor.processPendingPins(anchor + 1);
			}
			const incomplete = JSON.parse(readFileSync(join(pin.incidentDir, "journal-pin-incomplete.json"), "utf8")) as {
				reason?: unknown;
			};
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
			(callerOwnedEvent.occurrenceReference.locator as { payloadSha256: string }).payloadSha256 = "0".repeat(64);
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

	it("defers pending projection materialization behind an explicit cursor-only response", async () => {
		const target = fixture();
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		await initialize(target.compactor);
		for (let index = 1; index <= 65; index += 1) {
			target.internal.appendSegmentRecord(occurrenceInput(index, anchor, pin.digest, pin.casPath).input);
		}
		const request = {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
			pendingResponse: "cursor-only" as const,
		};
		const projection = vi.spyOn(
			target.compactor as unknown as { runHistoryProjection: (...args: unknown[]) => unknown },
			"runHistoryProjection",
		);
		const first = target.compactor.projectRunHistory(request);
		expect(first.state).toBe("pending");
		if (first.state !== "pending") throw new Error("expected a cursor-only continuation");
		expect(first).not.toHaveProperty("projection");
		expect(first.progress).toEqual({
			version: 1,
			state: "projection_deferred",
			phase: "segment-occurrences",
			observedEventCount: 64,
			observedEvidenceCount: 0,
		});
		expect(projection).not.toHaveBeenCalled();
		expect(() =>
			target.compactor.projectRunHistory({ ...request, cursor: first.cursor, pendingResponse: "full" }),
		).toThrow(/Invalid incident run-history continuation cursor/);

		let result: IncidentRecorderRunHistoryCursorOnlyResult = first;
		let pendingCount = 1;
		for (let pass = 0; result.state === "pending" && pass < 16; pass += 1) {
			result = target.compactor.projectRunHistory({ ...request, cursor: result.cursor });
			if (result.state === "pending") {
				pendingCount += 1;
				expect(result).not.toHaveProperty("projection");
			}
		}
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected a complete cursor-only projection");
		expect(pendingCount).toBeGreaterThan(2);
		expect(result.projection.events).toHaveLength(65);
		expect(projection).toHaveBeenCalledTimes(1);
		projection.mockRestore();
		const full = finishRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(full).toMatchObject({ state: "complete" });
		if (full.state !== "complete") throw new Error("expected the full projection baseline");
		expect(result.projection).toEqual(full.projection);
		expect(result.snapshot).toEqual(full.snapshot);
		target.internal.closeSegmentStore();
	});

	it("preserves legacy full pending responses while cursor-only progress reaches the same final output", async () => {
		const anchor = Date.now();
		const setup = async () => {
			const target = fixture();
			const pin = preparePinFixture(target, anchor);
			for (let index = 1; index <= 65; index += 1) {
				writeLegacyOccurrence(target, occurrenceInput(index, anchor, pin.digest, pin.casPath), index);
			}
			await initialize(target.compactor);
			return target;
		};
		const target = await setup();
		const request = { runId: RUN_ID, fromWallTimeMs: anchor, throughWallTimeMs: anchor + 1_000 };
		try {
			let fullPending = target.compactor.projectRunHistory(request);
			for (let pass = 0; fullPending.state === "pending" && fullPending.projection.events.length === 0; pass += 1) {
				if (pass >= 16) throw new Error("legacy full projection did not reach an event-bearing pending response");
				fullPending = target.compactor.projectRunHistory({ ...request, cursor: fullPending.cursor });
			}
			expect(fullPending.state).toBe("pending");
			if (fullPending.state !== "pending") throw new Error("expected a legacy full pending response");
			expect(fullPending.projection.events).toHaveLength(64);
			const callerOwnedEvent = fullPending.projection.events[0];
			if (!callerOwnedEvent) throw new Error("expected a detached legacy pending event");
			callerOwnedEvent.metadata = { poisonedByCaller: true };
			callerOwnedEvent.wrapperOrder[0] = "999999";
			callerOwnedEvent.cas.path = "poisoned-by-caller";

			const fullResult = finishRunHistoryProjection(target.compactor, request, 16, fullPending.cursor);
			expect(fullResult.state).toBe("complete");
			if (fullResult.state !== "complete") throw new Error("expected the legacy full projection to complete");
			expect(fullResult.projection.events[0]?.metadata).toEqual({});
			expect(fullResult.projection.events[0]?.wrapperOrder).toEqual(["2"]);
			expect(fullResult.projection.events[0]?.cas.path).not.toBe("poisoned-by-caller");

			const cursorRequest = { ...request, pendingResponse: "cursor-only" as const };
			let cursorResult = target.compactor.projectRunHistory(cursorRequest);
			let cursorPendingCount = 0;
			while (cursorResult.state === "pending" && cursorPendingCount < 16) {
				cursorPendingCount += 1;
				expect(cursorResult).not.toHaveProperty("projection");
				cursorResult = target.compactor.projectRunHistory({ ...cursorRequest, cursor: cursorResult.cursor });
			}
			expect(cursorPendingCount).toBeGreaterThan(2);
			expect(cursorResult.state).toBe("complete");
			if (cursorResult.state !== "complete")
				throw new Error("expected the legacy cursor-only projection to complete");
			expect(cursorResult.projection).toEqual(fullResult.projection);
			expect(cursorResult.snapshot).toEqual(fullResult.snapshot);
		} finally {
			target.internal.closeSegmentStore();
		}
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
		target.internal.appendSegmentRecord(occurrenceInput(2, anchor, cas.digest, cas.casPath, { casBytes: 2 }).input);
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

	it.each(["missing", "corrupt"] as const)("returns explicit incomplete evidence for a %s CAS blob", async (kind) => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("original"));
		await initialize(target.compactor);
		target.internal.appendSegmentRecord(occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: 8 }).input);
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
	});

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
		target.internal.appendSegmentRecord(occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: 10 }).input);
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
	] as const)(
		"fails closed on a $name proc fdinfo witness without leaking descriptors",
		async ({ content, reason }) => {
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
		},
	);

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
					writeSyntheticFdinfoDirectory(forgedDescriptorInfoDirectory, `mnt_id:\t${mountId + 1n}\n`);
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

	it("rejects a legacy projection when its procfd route changes midpage", async () => {
		const procFixtureRoot = mkdtempSync(join(tmpdir(), "prime-agent-midpage-procfd-"));
		roots.push(procFixtureRoot);
		const forgedDescriptorDirectory = join(procFixtureRoot, "fd");
		const redirectedBase = join(procFixtureRoot, "redirected");
		mkdirSync(forgedDescriptorDirectory, { mode: 0o700 });
		mkdirSync(redirectedBase, { mode: 0o700 });
		for (let descriptor = 0; descriptor <= highestObservedDescriptor() + 64; descriptor += 1) {
			symlinkSync(redirectedBase, join(forgedDescriptorDirectory, String(descriptor)), "dir");
		}
		let substituted = false;
		let openedOccurrences = 0;
		let descriptorRouteLookups = 0;
		let procfsStatfsLookups = 0;
		const target = fixture({
			runHistoryDescriptorIo: {
				afterOpen: ({ role }) => {
					if (role === "legacy_occurrence") {
						openedOccurrences += 1;
						substituted = true;
					}
				},
			},
			runHistoryProcfs: {
				statfsType: () => {
					procfsStatfsLookups += 1;
					return 0x9fa0;
				},
				resolveDescriptorPath: ({ canonicalPath, descriptor, childName }) => {
					descriptorRouteLookups += 1;
					if (!substituted) return canonicalPath;
					return childName === undefined
						? join(forgedDescriptorDirectory, String(descriptor))
						: join(forgedDescriptorDirectory, String(descriptor), childName);
				},
			},
		});
		const anchor = Date.now();
		const pin = preparePinFixture(target, anchor);
		for (let index = 1; index <= 64; index += 1) {
			writeLegacyOccurrence(target, occurrenceInput(index, anchor, pin.digest, pin.casPath), index);
		}
		await initialize(target.compactor);
		const result = finishRetainedRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(substituted).toBe(true);
		expect(openedOccurrences).toBe(64);
		expect(result.state).toBe("incomplete");
		if (result.state !== "incomplete") throw new Error("expected a midpage procfd route failure");
		expect(result.reason).toBe("run_history_legacy_snapshot_changed");
		expect(result.projection.evidence[0]).toMatchObject({
			kind: "corrupt",
			reason: "run_history_cas_procfs_legacy_run_directory_descriptor_target_mismatch",
		});
		expect(result).not.toHaveProperty("publicationCapability");
		expect(target.internal.runHistoryTraversals.size).toBe(0);
		expect(descriptorRouteLookups).toBeLessThan(20);
		expect(procfsStatfsLookups).toBeLessThan(1_000);
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
			if (admitted.state === "pending")
				expect(target.compactor.cancelRunHistoryProjection(admitted.cursor)).toBe(true);
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

	it("releases an opted-in projection when its serialized result exceeds the explicit byte bound", async () => {
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
		const result = finishRetainedRunHistoryProjection(
			target.compactor,
			{
				runId: RUN_ID,
				fromWallTimeMs: anchor,
				throughWallTimeMs: anchor + recordCount + 1,
				pendingResponse: "cursor-only",
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
		expect(target.internal.runHistoryTraversals.size).toBe(0);
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
		sealSegmentStoreWithinRoot(target, "projection-first-generation");
		target.internal.appendSegmentRecord(occurrenceInput(65, anchor, pin.digest, pin.casPath).input);
		sealSegmentStoreWithinRoot(target, "projection-anchor");
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

	it("retains one exact immutable publication capability until a descriptor-style caller releases it", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		for (let index = 1; index <= 2; index += 1) {
			target.internal.appendSegmentRecord(occurrenceInput(index, anchor, cas.digest, cas.casPath).input);
			sealSegmentStoreWithinRoot(target, `retained-publication-${index}`);
		}
		const result = finishRetainedRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("complete");
		if (result.state !== "complete") throw new Error("expected a retained complete projection");
		const capability = result.publicationCapability;
		expect(Object.isFrozen(capability)).toBe(true);
		target.compactor.assertRunHistoryPublicationReady(capability);

		const blocked = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(blocked.deletedSegmentIds).toEqual([]);
		expect(blocked.blockedByReadSnapshot).toBe(true);

		const descriptorPath = join(target.root, "run-history-descriptor.json");
		const descriptor = openSync(descriptorPath, "wx", 0o600);
		try {
			writeFileSync(descriptor, `${JSON.stringify(result.projection)}\n`);
			fsyncSync(descriptor);
		} finally {
			closeSync(descriptor);
		}
		target.compactor.assertRunHistoryPublicationReady(capability);

		const clone = { ...capability } as IncidentRecorderRunHistoryPublicationCapability;
		const forgery = Object.freeze({
			...capability,
			id: "f".repeat(64),
		}) as IncidentRecorderRunHistoryPublicationCapability;
		for (const rejected of [clone, forgery]) {
			expect(() => target.compactor.assertRunHistoryPublicationReady(rejected)).toThrow(
				/exact run-history publication capability/,
			);
			expect(() => target.compactor.releaseRunHistoryPublication(rejected)).toThrow(
				/exact run-history publication capability/,
			);
			expect(() => target.compactor.cancelRunHistoryProjection(rejected)).toThrow(
				/exact run-history publication capability/,
			);
		}
		target.compactor.assertRunHistoryPublicationReady(capability);
		target.compactor.releaseRunHistoryPublication(capability);
		expect(() => target.compactor.assertRunHistoryPublicationReady(capability)).toThrow(
			/exact run-history publication capability/,
		);
		expect(() => target.compactor.releaseRunHistoryPublication(capability)).not.toThrow();

		const afterRelease = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(afterRelease.deletedSegmentIds.length).toBeGreaterThan(0);
		expect(afterRelease.blockedByReadSnapshot).toBe(false);
		target.internal.closeSegmentStore();
	});

	it("accepts the exact retained capability for replay-safe cancellation", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		for (let index = 1; index <= 2; index += 1) {
			target.internal.appendSegmentRecord(occurrenceInput(index, anchor, cas.digest, cas.casPath).input);
			sealSegmentStoreWithinRoot(target, `retained-cancellation-${index}`);
		}
		const result = finishRetainedRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		if (result.state !== "complete") throw new Error("expected a cancellable retained projection");
		expect(target.compactor.cancelRunHistoryProjection(result.publicationCapability)).toBe(true);
		expect(target.compactor.cancelRunHistoryProjection(result.publicationCapability)).toBe(true);
		const afterCancel = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(afterCancel.deletedSegmentIds.length).toBeGreaterThan(0);
		expect(afterCancel.blockedByReadSnapshot).toBe(false);
		target.internal.closeSegmentStore();
	});

	it.each(["expiry", "shutdown"] as const)("releases a retained publication lease on %s", async (exit) => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		const clock = exit === "expiry" ? vi.spyOn(Date, "now").mockReturnValue(anchor) : undefined;
		await initialize(target.compactor);
		for (let index = 1; index <= 2; index += 1) {
			target.internal.appendSegmentRecord(occurrenceInput(index, anchor, cas.digest, cas.casPath).input);
			sealSegmentStoreWithinRoot(target, `retained-${exit}-${index}`);
		}
		try {
			const result = finishRetainedRunHistoryProjection(target.compactor, {
				runId: RUN_ID,
				fromWallTimeMs: anchor,
				throughWallTimeMs: anchor + 1_000,
				...(exit === "expiry" ? { deadlineMs: anchor + 100 } : {}),
			});
			if (result.state !== "complete") throw new Error("expected a retained complete projection");
			const blocked = target.compactor.pruneSegmentHistory(
				anchor + 4 * DAY,
				createIncidentRecorderSegmentPruneProtection(0, []),
			);
			expect(blocked.blockedByReadSnapshot).toBe(true);
			if (exit === "expiry") {
				clock?.mockReturnValue(anchor + 101);
				expect(() => target.compactor.assertRunHistoryPublicationReady(result.publicationCapability)).toThrow(
					/exact run-history publication capability/,
				);
			} else {
				target.internal.closeSegmentStore();
			}
			const afterExit = target.compactor.pruneSegmentHistory(
				anchor + 4 * DAY,
				createIncidentRecorderSegmentPruneProtection(0, []),
			);
			expect(afterExit.deletedSegmentIds.length).toBeGreaterThan(0);
			expect(afterExit.blockedByReadSnapshot).toBe(false);
		} finally {
			clock?.mockRestore();
			target.internal.closeSegmentStore();
		}
	});

	it("releases an opted-in traversal when projection validation returns an error result", async () => {
		const target = fixture();
		const anchor = Date.now();
		const cas = writeCasFixture(target, Buffer.from("x"));
		await initialize(target.compactor);
		for (let index = 1; index <= 2; index += 1) {
			target.internal.appendSegmentRecord(occurrenceInput(index, anchor, cas.digest, cas.casPath).input);
			sealSegmentStoreWithinRoot(target, `retained-error-${index}`);
		}
		rmSync(cas.casPath);
		const result = finishRetainedRunHistoryProjection(target.compactor, {
			runId: RUN_ID,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
		});
		expect(result.state).toBe("incomplete");
		expect(target.internal.runHistoryTraversals.size).toBe(0);
		const afterError = target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		expect(afterError.deletedSegmentIds.length).toBeGreaterThan(0);
		expect(afterError.blockedByReadSnapshot).toBe(false);
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
				if (index < 3) sealSegmentStoreWithinRoot(target, `lease-release-${index}`);
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
			vi.useFakeTimers();
			vi.setSystemTime(anchor);
			await initialize(target.compactor);
			target.internal.appendSegmentRecord(
				occurrenceInput(1, anchor, cas.digest, cas.casPath, { casBytes: value.length }).input,
			);
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
					expect(incomplete.reason).toMatch(/^run_history_cas_blob_(?:name_swapped|changed_during_read)$/);
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

	it.each(["gap", "corrupt-legacy"] as const)("never completes a run history containing %s evidence", async (kind) => {
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
	});

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
		expect(result.projection.events.map((event) => event.identityKey)).toEqual([occurrence.identityKey]);
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
			if (index <= 16) sealSegmentStoreWithinRoot(target, `gap-free-prefix-${index}`);
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
		sealSegmentStoreWithinRoot(target, "first-query-generation");
		const last = occurrenceInput(65, anchor, pin.digest, pin.casPath);
		cursors.push(last.cursor);
		target.internal.appendSegmentRecord(last.input);
		sealSegmentStoreWithinRoot(target, "query-anchor");
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
		) as Record<string, unknown>;
		expect(incomplete).toEqual({
			version: 1,
			state: "pending_or_incomplete",
			provider: "journal",
			reason: "segment_occurrence_query_failed_or_snapshot_stale",
			runId: RUN_ID,
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor,
			throughWallTimeMs: anchor + 1_000,
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
			sealSegmentStoreWithinRoot(target, `recovery-${index}`);
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
