import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
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
	createIncidentRecorderSegmentPruneProtection,
	IncidentRecorderSegmentStore,
	type IncidentRecorderSegmentAppendInput,
	type IncidentRecorderSegmentLocator,
} from "../src/modes/daemon/incident-recorder-segment-store.js";

const roots: string[] = [];
const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const DAY = 24 * 60 * 60 * 1_000;

interface CompactorInternals {
	appendSegmentRecord(input: IncidentRecorderSegmentAppendInput): IncidentRecorderSegmentLocator;
	closeSegmentStore(): void;
	segmentStore?: IncidentRecorderSegmentStore;
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

function occurrenceIdentity(index: number): { occurrenceId: string; identityKey: string } {
	const id = occurrenceId(index);
	return {
		occurrenceId: id,
		identityKey: createHash("sha256").update(`${RUN_ID}\0${RUN_TOKEN}\0${PRODUCER_ID}\0${id}`).digest("hex"),
	};
}

function occurrenceInput(
	index: number,
	anchor: number,
	digest: string,
	casPath: string,
): { input: IncidentRecorderSegmentAppendInput; payload: Record<string, unknown>; cursor: string; identityKey: string } {
	const identity = occurrenceIdentity(index);
	const cursor = `cursor-${index}`;
	const payload = {
		version: 1,
		state: "complete",
		identity: {
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			producerId: PRODUCER_ID,
			occurrenceId: identity.occurrenceId,
		},
		source: "kernel",
		type: "kernel_unexpected_exit",
		encoding: "binary",
		payloadKind: "exact-bytes",
		terminal: true,
		metadata: {},
		eventWallTimeMs: String(anchor + index),
		eventMonotonicNs: String(index),
		transportIdentity: {},
		wrapperOrder: [String(index + 1)],
		producerOrder: [String(index + 1)],
		cursors: [cursor],
		journalReferences: [],
		cas: {
			algorithm: "sha256",
			digest,
			bytes: 1,
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
			observedAtMs: anchor + index,
			order: String(index + 1),
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
	request: { runId: string; fromWallTimeMs: number; throughWallTimeMs: number },
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
			clock.mockReturnValue(anchor + 20);
			const admitted = target.compactor.projectRunHistory({
				runId: RUN_ID,
				fromWallTimeMs: anchor,
				throughWallTimeMs: anchor + 1_000,
				deadlineMs: anchor + 30,
			});
			expect(admitted.state).toBe("pending");
			if (admitted.state === "pending") expect(target.compactor.cancelRunHistoryProjection(admitted.cursor)).toBe(true);
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
				wrapperOrder: ["1"],
				producerOrder: ["1"],
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

	it("turns a pruned segment projection snapshot into explicit incomplete evidence", async () => {
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
		target.compactor.pruneSegmentHistory(
			anchor + 4 * DAY,
			createIncidentRecorderSegmentPruneProtection(0, []),
		);
		const resumed = target.compactor.projectRunHistory({ ...request, cursor: first.cursor });
		expect(resumed.state).toBe("incomplete");
		if (resumed.state !== "incomplete") throw new Error("expected an incomplete stale projection");
		expect(resumed.reason).toBe("run_history_segment_snapshot_stale_or_corrupt");
		expect(resumed.projection.evidence[0]).toMatchObject({ kind: "corrupt" });
		target.internal.closeSegmentStore();
	});

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

	it("retains ordered terminal facts as explicit finalization barriers", async () => {
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
		expect(result.projection.terminalEvents).toEqual(result.projection.finalizationBarriers);
		expect(result.projection.finalizationBarriers[0]).toMatchObject({
			type: "kernel_unexpected_exit",
			basis: "terminal_flag",
		});
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
