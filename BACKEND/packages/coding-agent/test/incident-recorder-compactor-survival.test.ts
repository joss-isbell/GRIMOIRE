import {
	chmodSync,
	existsSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	IncidentRecorderCompactor,
	incidentJournalReaderArguments,
	incidentJournalReaderRangeArguments,
	incidentJournalReaderResumeDelayMs,
	incidentJournalReaderSinceArgument,
	incidentJournalReplayFenceDisposition,
} from "../src/modes/daemon/incident-recorder-compactor.js";

const roots: string[] = [];
const compactors: IncidentRecorderCompactor[] = [];
const RUN_ID = "11111111-1111-4111-8111-111111111111";

function streamClosedArtifact(
	compactor: IncidentRecorderCompactor,
	runId: string,
	sourcePath: string,
	encoding: string,
	work: { deadlineMs: number; byteBudget: number },
) {
	const publicationPath = `${sourcePath}.closed-publication.json`;
	if (!existsSync(publicationPath)) {
		try {
			const source = statSync(sourcePath, { bigint: true });
			writeFileSync(
				publicationPath,
				`${JSON.stringify({
					schemaVersion: 1,
					state: "closed",
					proof: "target_process_stopped",
					source: {
						path: sourcePath,
						dev: source.dev.toString(),
						ino: source.ino.toString(),
						bytes: Number(source.size),
						mtimeMs: Number(source.mtimeMs),
						ctimeMs: Number(source.ctimeMs),
					},
				})}
`,
				{ mode: 0o600 },
			);
		} catch {}
	}
	return compactor.streamStoppedTargetArtifact(runId, sourcePath, encoding, publicationPath, work);
}

function createCompactor(
	options: ConstructorParameters<typeof IncidentRecorderCompactor>[0],
): IncidentRecorderCompactor {
	const compactor = new IncidentRecorderCompactor(options);
	compactors.push(compactor);
	return compactor;
}

function fixture(name: string): { root: string; agentDir: string } {
	const root = mkdtempSync(join(tmpdir(), `prime-agent-compactor-${name}-`));
	roots.push(root);
	return { root, agentDir: join(root, "agent") };
}

function finishStorageDiscovery(compactor: IncidentRecorderCompactor, maximumSlices = 128): void {
	for (let slice = 0; slice < maximumSlices; slice += 1) {
		const before = compactor.survivalSnapshot();
		expect(before.storageDiscoverySliceEntries).toBeLessThanOrEqual(512);
		expect(before.storageDiscoveryDepth).toBeLessThanOrEqual(65);
		expect(before.storageDiscoveryRetainedPaths).toBeLessThanOrEqual(67);
		if (before.storageDiscoveryComplete) return;
		const beforeEntries = before.storageDiscoveryEntries;
		compactor.advanceBoundedDiscovery();
		const after = compactor.survivalSnapshot();
		expect(after.storageDiscoveryEntries - beforeEntries).toBeLessThanOrEqual(512);
		expect(after.storageDiscoverySliceEntries).toBeLessThanOrEqual(512);
		expect(after.storageDiscoveryDepth).toBeLessThanOrEqual(65);
		expect(after.storageDiscoveryRetainedPaths).toBeLessThanOrEqual(67);
		if (after.storageDiscoveryError) throw new Error(after.storageDiscoveryError);
	}
	throw new Error("storage discovery did not converge within the deterministic slice bound");
}

function allocatedBytes(path: string): number {
	const stat = lstatSync(path);
	return Math.max(stat.size, stat.blocks * 512);
}

function uniqueAllocatedBytes(paths: readonly string[]): number {
	const pending = [...paths];
	const seen = new Set<string>();
	let bytes = 0;
	while (pending.length > 0) {
		const path = pending.pop();
		if (!path || !existsSync(path)) continue;
		const stat = lstatSync(path);
		const identity = `${stat.dev}:${stat.ino}`;
		if (!seen.has(identity)) {
			seen.add(identity);
			bytes += Math.max(stat.size, stat.blocks * 512);
		}
		if (stat.isDirectory()) {
			for (const name of readdirSync(path)) pending.push(join(path, name));
		}
	}
	return bytes;
}

function writeJson(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

afterEach(() => {
	for (const compactor of compactors.splice(0)) compactor.dispose();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
	vi.useRealTimers();
});

describe("incident compactor survival bounds", () => {
	it("bounds journal replay to retained time and paces provider reads", () => {
		const nowMs = 3 * 24 * 60 * 60 * 1_000 + 10_000;
		expect(incidentJournalReaderSinceArgument(undefined, nowMs)).toBe("--since=@10.000000");
		expect(incidentJournalReaderRangeArguments(undefined, nowMs)).toMatchObject({
			sinceArgument: "--since=@10.000000",
			untilArgument: "--until=@12.000000",
			reachesLiveEdge: false,
			seeksCheckpoint: false,
		});
		expect(incidentJournalReaderRangeArguments(undefined, nowMs, undefined, 30_000_000n)).toMatchObject({
			sinceArgument: "--since=@10.000000",
			untilArgument: "--until=@40.000000",
		});
		expect(() => incidentJournalReaderRangeArguments(undefined, nowMs, undefined, 30_000_001n)).toThrow(
			"Invalid incident journal reader wall time",
		);
		const invocation = incidentJournalReaderArguments(undefined, nowMs);
		expect(invocation.args).toContain("--since=@10.000000");
		expect(invocation.args).toContain("--until=@12.000000");
		expect(invocation.args).not.toContain("--follow");
		expect(invocation.args).not.toContain("--no-tail");
		expect(incidentJournalReaderSinceArgument({ lastRealtimeUs: "20000000" }, nowMs)).toBe("--since=@19.000000");
		expect(incidentJournalReaderRangeArguments({ lastRealtimeUs: "20000000" }, nowMs)).toMatchObject({
			sinceArgument: "--since=@19.000000",
			untilArgument: "--until=@21.000000",
			reachesLiveEdge: false,
			seeksCheckpoint: true,
		});
		expect(incidentJournalReaderRangeArguments({ lastRealtimeUs: "20000000" }, nowMs, 25_000_000n)).toMatchObject({
			sinceArgument: "--since=@25.000000",
			untilArgument: "--until=@27.000000",
			seeksCheckpoint: false,
		});
		expect(
			incidentJournalReaderSinceArgument({ lastRealtimeUs: String((nowMs + 6 * 60 * 1_000) * 1_000) }, nowMs),
		).toBe("--since=@10.000000");
		expect(incidentJournalReaderResumeDelayMs(1024 * 1024, 0)).toBe(4_000);
		expect(incidentJournalReaderResumeDelayMs(64 * 1024, 10)).toBe(240);
		expect(incidentJournalReaderResumeDelayMs(64 * 1024, 1_000)).toBe(0);
		expect(() => incidentJournalReaderResumeDelayMs(-1, 0)).toThrow("Invalid incident journal reader pacing input");
		const fence = { cursor: "durable-cursor", lastRealtimeUs: "20000000" };
		expect(incidentJournalReplayFenceDisposition(fence, "durable-cursor", "20000000")).toBe("matched");
		expect(incidentJournalReplayFenceDisposition(fence, "earlier", "20500000")).toBe("skip");
		expect(incidentJournalReplayFenceDisposition(fence, "later", "21000001")).toBe("missing");
		expect(incidentJournalReplayFenceDisposition(fence, undefined, undefined)).toBe("skip");
		expect(
			incidentJournalReplayFenceDisposition({ cursor: "durable-cursor", lastRealtimeUs: "invalid" }, "other", "1"),
		).toBe("missing");
	});

	it("invokes only finite journal windows and replays the durable cursor overlap", async () => {
		const target = fixture("finite-journal-windows");
		mkdirSync(target.agentDir, { recursive: true, mode: 0o700 });
		const journalctl = join(target.root, "fake-journalctl.sh");
		const argumentsLog = join(target.root, "arguments.log");
		const realtimeUs = String(Date.now() * 1_000);
		writeFileSync(
			journalctl,
			`#!/bin/sh
printf '%s\n' "$*" >> '${argumentsLog}'
printf '%s\n' '__CURSOR=fake-cursor' '_MACHINE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' '_BOOT_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' '_STREAM_ID=cccccccccccccccccccccccccccccccc' '__REALTIME_TIMESTAMP=${realtimeUs}' '__MONOTONIC_TIMESTAMP=1' 'SYSLOG_IDENTIFIER=prime-agent-capture' '_TRANSPORT=stdout' '_UID=1000' '_PID=1' 'MESSAGE={}' ''
`,
			{ mode: 0o700 },
		);
		chmodSync(journalctl, 0o700);
		const compactor = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0, journalctlPath: journalctl });
		const running = compactor.run();
		for (let attempt = 0; attempt < 100; attempt += 1) {
			if (existsSync(argumentsLog) && readFileSync(argumentsLog, "utf8").trim().split("\n").length >= 2) break;
			await new Promise((resolve) => setTimeout(resolve, 10));
		}
		const invocations = readFileSync(argumentsLog, "utf8").trim().split("\n");
		expect(invocations.length).toBeGreaterThanOrEqual(2);
		for (const invocation of invocations) {
			expect(invocation).toContain("--since=@");
			expect(invocation).toContain("--until=@");
			expect(invocation).not.toContain("--follow");
			expect(invocation).not.toContain("--no-tail");
		}
		const replaySinceUs = BigInt(realtimeUs) - 1_000_000n;
		const replaySince = `--since=@${replaySinceUs / 1_000_000n}.${(replaySinceUs % 1_000_000n)
			.toString()
			.padStart(6, "0")}`;
		expect(invocations[1]).toContain(replaySince);
		expect(readdirSync(join(target.agentDir, "incident-recorder", "refs", "gaps"))).toHaveLength(1);
		compactor.dispose();
		await expect(running).rejects.toThrow("Incident recorder compactor is disposed");
	});

	it("discovers a scaled CAS backlog in fixed slices and counts each regular hard-linked inode once", () => {
		const target = fixture("storage");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		const runDir = join(recorderRoot, "refs", "runs", "f".repeat(64));
		mkdirSync(runDir, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 2_048; index += 1) {
			const digest = index.toString(16).padStart(64, "0");
			const canonical = join(recorderRoot, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
			mkdirSync(dirname(canonical), { recursive: true, mode: 0o700 });
			writeFileSync(canonical, Buffer.from([index & 0xff]), { mode: 0o600 });
			linkSync(canonical, join(runDir, `cas-${digest}.blob`));
		}
		const pinnedDigest = (1_024).toString(16).padStart(64, "0");
		const pinnedCanonical = join(recorderRoot, "cas", "sha256", pinnedDigest.slice(0, 2), `${pinnedDigest}.blob`);
		const journalPin = join(target.agentDir, "incidents", "incident-a", "journal-pins", "cas");
		mkdirSync(journalPin, { recursive: true, mode: 0o700 });
		linkSync(pinnedCanonical, join(journalPin, `${pinnedDigest}.blob`));
		linkSync(pinnedCanonical, join(dirname(pinnedCanonical), `.${pinnedDigest}.blob.tmp-123-${"a".repeat(64)}`));

		const compactor = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(compactor);

		expect(compactor.survivalSnapshot().storageDiscoveryEntries).toBeGreaterThan(4_096);
		expect(compactor.accountedStorageBytes).toBe(
			uniqueAllocatedBytes([recorderRoot, join(target.agentDir, "incidents")]),
		);
	});

	it("admits each new nested directory block before allocation near the storage ceiling", () => {
		const target = fixture("directory-ceiling");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		mkdirSync(recorderRoot, { recursive: true, mode: 0o700 });
		const baseline = uniqueAllocatedBytes([recorderRoot]);
		const ceiling = baseline + 64 * 1024;
		const compactor = createCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			storageByteCeiling: ceiling,
		});
		finishStorageDiscovery(compactor);
		const nestedPath = join(recorderRoot, "nested-a", "nested-b", "nested-c", "value.json");
		const writer = compactor as unknown as {
			writeOwnedJson(path: string, value: unknown, extraWorstCase: number): void;
		};

		expect(() => writer.writeOwnedJson(nestedPath, { value: true }, 0)).toThrow(
			"Incident compactor paused by disk admission policy",
		);
		expect(existsSync(nestedPath)).toBe(false);
		expect(compactor.accountedStorageBytes).toBe(uniqueAllocatedBytes([recorderRoot]));
		expect(compactor.accountedStorageBytes).toBeLessThanOrEqual(ceiling);
	});

	it("restarts the bounded two-pass proof after a concurrent directory mutation", async () => {
		const target = fixture("transient-storage-mutation");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		mkdirSync(recorderRoot, { recursive: true, mode: 0o700 });
		writeFileSync(join(recorderRoot, "before.json"), "before", { mode: 0o600 });
		let mutated = false;
		const compactor = createCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			storageDiscoveryEntryHook(path) {
				if (!mutated && path === recorderRoot) {
					mutated = true;
					writeFileSync(join(recorderRoot, "during.json"), "during", { mode: 0o600 });
				}
			},
		});

		await compactor.initializeStorageDiscovery();

		const snapshot = compactor.survivalSnapshot();
		expect(mutated).toBe(true);
		expect(snapshot.storageDiscoveryComplete).toBe(true);
		expect(snapshot.storageDiscoveryRetries).toBe(1);
		expect(snapshot.storageDiscoveryLastTransientError).toBe("storage_discovery_directory_changed_before_open");
		expect(snapshot.storageDiscoveryError).toBeUndefined();
		expect(compactor.accountedStorageBytes).toBe(uniqueAllocatedBytes([recorderRoot]));
	});

	it("batches monotonic cursor persistence and flushes a quiet suffix on its deadline", async () => {
		const target = fixture("checkpoint-batching");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		mkdirSync(recorderRoot, { recursive: true, mode: 0o700 });
		const compactor = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(compactor);
		const checkpointPath = join(recorderRoot, "compactor-cursor.json");
		const cursorApi = compactor as unknown as {
			wrapperSequences: Map<string, bigint>;
			producerSequences: Map<string, bigint>;
			commitCursor(
				cursor: string,
				machineId: string,
				bootId: string,
				invocationId: string | null,
				realtimeUs: string,
			): void;
		};
		for (let index = 0; index < 4_096; index += 1) {
			cursorApi.wrapperSequences.set(`wrapper-${index}`, BigInt(index));
			cursorApi.producerSequences.set(`producer-${index}`, BigInt(index));
		}
		vi.useFakeTimers();

		for (let index = 1; index < 64; index += 1) {
			cursorApi.commitCursor(`cursor-${index}`, "machine", "boot", "invocation", String(index));
		}
		expect(existsSync(checkpointPath)).toBe(false);
		expect(compactor.survivalSnapshot().checkpointPendingEntries).toBe(63);

		cursorApi.commitCursor("cursor-64", "machine", "boot", "invocation", "64");
		const batched = JSON.parse(readFileSync(checkpointPath, "utf8")) as {
			cursor: string;
			wrapperSequences: Record<string, string>;
			producerSequences: Record<string, string>;
		};
		expect(batched.cursor).toBe("cursor-64");
		expect(Object.keys(batched.wrapperSequences)).toHaveLength(4_096);
		expect(Object.keys(batched.producerSequences)).toHaveLength(4_096);
		expect(compactor.survivalSnapshot().checkpointPendingEntries).toBe(0);

		cursorApi.commitCursor("cursor-65", "machine", "boot", "invocation", "65");
		expect(compactor.survivalSnapshot().checkpointPendingEntries).toBe(1);
		await vi.advanceTimersByTimeAsync(1_000);
		expect(JSON.parse(readFileSync(checkpointPath, "utf8"))).toMatchObject({ cursor: "cursor-65" });
		expect(compactor.survivalSnapshot().checkpointPendingEntries).toBe(0);
		expect(compactor.survivalSnapshot().checkpointPersistenceError).toBeUndefined();
	});

	it("fails closed when a canonical owner is removed after a sibling was classified mid-scan", () => {
		const target = fixture("canonical-mutation");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		const digest = "a".repeat(64);
		const canonical = join(recorderRoot, "cas", "sha256", "aa", `${digest}.blob`);
		const sibling = join(recorderRoot, "refs", "runs", "b".repeat(64), `cas-${digest}.blob`);
		mkdirSync(dirname(sibling), { recursive: true, mode: 0o700 });
		mkdirSync(dirname(canonical), { recursive: true, mode: 0o700 });
		writeFileSync(canonical, "retained", { mode: 0o600 });
		linkSync(canonical, sibling);
		let removed = false;
		const compactor = createCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			storageDiscoveryEntryHook(path, canonicalPath) {
				if (!removed && path === sibling && canonicalPath === canonical) {
					removed = true;
					rmSync(canonical);
				}
			},
		});
		for (let slice = 0; slice < 128 && !compactor.survivalSnapshot().storageDiscoveryError; slice += 1) {
			compactor.advanceBoundedDiscovery();
		}

		expect(removed).toBe(true);
		expect(existsSync(canonical)).toBe(false);
		expect(existsSync(sibling)).toBe(true);
		expect(compactor.survivalSnapshot().storageDiscoveryError).toBeDefined();
		expect(compactor.admitObservation(1)).toBe(false);
	});

	it("classifies the complete retained hard-link taxonomy and blocks unknown shapes", () => {
		const target = fixture("storage-taxonomy");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		const incidentRoot = join(target.agentDir, "incidents", "incident-taxonomy");
		const runRoot = join(recorderRoot, "refs", "runs", "1".repeat(64));
		const casId = "2".repeat(64);
		const occurrenceId = "3".repeat(64);
		const gapId = "4".repeat(64);
		const incompleteId = "5".repeat(64);
		const sysdigId = "6".repeat(64);
		const cas = join(recorderRoot, "cas", "sha256", casId.slice(0, 2), `${casId}.blob`);
		const occurrence = join(
			recorderRoot,
			"refs",
			"occurrences",
			"sha256",
			occurrenceId.slice(0, 2),
			`${occurrenceId}.json`,
		);
		const gap = join(recorderRoot, "refs", "gaps", `${gapId}.json`);
		const incomplete = join(recorderRoot, "refs", "incomplete", `${incompleteId}.json`);
		for (const path of [cas, occurrence, gap, incomplete]) {
			mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
			writeFileSync(path, basename(path), { mode: 0o600 });
		}
		mkdirSync(runRoot, { recursive: true, mode: 0o700 });
		const runCas = join(runRoot, `cas-${casId}.blob`);
		const runOccurrence = join(runRoot, `seq-${"1".padStart(20, "0")}-${occurrenceId}.json`);
		const runGap = join(runRoot, `seq-${"2".padStart(20, "0")}-gap-${gapId}.json`);
		const runIncomplete = join(runRoot, `seq-${"3".padStart(20, "0")}-incomplete-${incompleteId}.json`);
		linkSync(cas, runCas);
		linkSync(occurrence, runOccurrence);
		linkSync(gap, runGap);
		linkSync(incomplete, runIncomplete);
		const activeRun = join(recorderRoot, "runs", "2026-08-28T00-00-00.000Z-11111111-1111-4111-8111-111111111111");
		const rawCasId = "8".repeat(64);
		const rawCas = join(recorderRoot, "cas", "sha256", rawCasId.slice(0, 2), `${rawCasId}.blob`);
		const rawLease = join(activeRun, ".cas-leases", basename(rawCas));
		const collisionId = "9".repeat(64);
		const collisionName = `${collisionId}.collision-123-22222222-2222-4222-8222-222222222222.blob`;
		const collisionCas = join(recorderRoot, "cas", "sha256", collisionId.slice(0, 2), collisionName);
		const collisionLease = join(activeRun, ".cas-leases", collisionName);
		for (const [owner, lease] of [
			[rawCas, rawLease],
			[collisionCas, collisionLease],
		] as const) {
			mkdirSync(dirname(owner), { recursive: true, mode: 0o700 });
			mkdirSync(dirname(lease), { recursive: true, mode: 0o700 });
			writeFileSync(owner, basename(owner), { mode: 0o600 });
			linkSync(owner, lease);
		}
		const journalPin = join(incidentRoot, "journal-pins", "cas", `${casId}.blob`);
		mkdirSync(dirname(journalPin), { recursive: true, mode: 0o700 });
		linkSync(cas, journalPin);
		const immutableTemporary = join(dirname(gap), `.${basename(gap)}.tmp-123-${"7".repeat(64)}`);
		linkSync(gap, immutableTemporary);
		const sysdigSource = join(target.root, "stock-ring", "ring.scap0");
		const sysdigPin = join(incidentRoot, "sysdig-pins", "segments", `${sysdigId}.scap`);
		mkdirSync(dirname(sysdigSource), { recursive: true, mode: 0o700 });
		mkdirSync(dirname(sysdigPin), { recursive: true, mode: 0o700 });
		writeFileSync(sysdigSource, "sysdig", { mode: 0o600 });
		linkSync(sysdigSource, sysdigPin);
		const sysdigStat = lstatSync(sysdigPin);
		writeJson(join(incidentRoot, "sysdig-pins", "records", `${sysdigId}.json`), {
			version: 1,
			id: sysdigId,
			sourcePath: sysdigSource,
			sourceName: "ring.scap0",
			observedAtWallTimeMs: 1,
			phase: "initial",
			source: { dev: String(sysdigStat.dev), ino: String(sysdigStat.ino), bytes: 6, mtimeMs: 1 },
			pinnedPath: sysdigPin,
			captureMethod: "hard_link",
			captureReason: "closed_segment_hard_link",
			bytesAtCapture: 6,
		});
		const unknownDir = join(recorderRoot, "unknown");
		const unknownOwner = join(unknownDir, "owner.bin");
		const unknownReference = join(unknownDir, "reference.bin");
		const taxonomy = [
			{ shape: "CAS canonical and run ref", owner: cas, reference: runCas, admission: "allow" },
			{ shape: "occurrence canonical and run ref", owner: occurrence, reference: runOccurrence, admission: "allow" },
			{ shape: "gap canonical and run ref", owner: gap, reference: runGap, admission: "allow" },
			{
				shape: "incomplete canonical and run ref",
				owner: incomplete,
				reference: runIncomplete,
				admission: "allow",
			},
			{ shape: "journal pin", owner: cas, reference: journalPin, admission: "allow" },
			{ shape: "run-owned raw CAS lease", owner: rawCas, reference: rawLease, admission: "allow" },
			{
				shape: "run-owned raw CAS collision lease",
				owner: collisionCas,
				reference: collisionLease,
				admission: "allow",
			},
			{ shape: "immutable crash temp", owner: gap, reference: immutableTemporary, admission: "allow" },
			{
				shape: "Sysdig incident-owned pin",
				owner: sysdigSource,
				reference: sysdigPin,
				admission: "allow",
			},
			{ shape: "unknown hard-link shape", owner: unknownOwner, reference: unknownReference, admission: "block" },
		] as const;
		expect(taxonomy.map((row) => row.shape)).toEqual([
			"CAS canonical and run ref",
			"occurrence canonical and run ref",
			"gap canonical and run ref",
			"incomplete canonical and run ref",
			"journal pin",
			"run-owned raw CAS lease",
			"run-owned raw CAS collision lease",
			"immutable crash temp",
			"Sysdig incident-owned pin",
			"unknown hard-link shape",
		]);
		for (const row of taxonomy.filter((entry) => entry.admission === "allow")) {
			expect(statSync(row.owner).ino).toBe(statSync(row.reference).ino);
		}
		const classified = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(classified);
		expect(classified.accountedStorageBytes).toBe(
			uniqueAllocatedBytes([recorderRoot, join(target.agentDir, "incidents")]),
		);

		mkdirSync(unknownDir, { recursive: true, mode: 0o700 });
		writeFileSync(unknownOwner, "unknown", { mode: 0o600 });
		linkSync(unknownOwner, unknownReference);
		const unknown = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		for (let slice = 0; slice < 128 && !unknown.survivalSnapshot().storageDiscoveryError; slice += 1) {
			unknown.advanceBoundedDiscovery();
		}
		expect(unknown.survivalSnapshot().storageDiscoveryError).toBe(
			"unclassified_hard_link_blocks_exact_storage_accounting",
		);
		expect(unknown.admitObservation()).toBe(false);
	});

	it("uses incident-owned Sysdig pins and conservatively accounts each retained reference", () => {
		const target = fixture("sysdig-pin-owner");
		const ringDir = join(target.root, "stock-ring");
		const ringBase = join(ringDir, "ring.scap");
		const firstIncident = join(target.agentDir, "incidents", "incident-one");
		const secondIncident = join(target.agentDir, "incidents", "incident-two");
		mkdirSync(firstIncident, { recursive: true, mode: 0o700 });
		mkdirSync(secondIncident, { recursive: true, mode: 0o700 });
		mkdirSync(ringDir, { recursive: true, mode: 0o700 });
		const anchor = Date.now();
		const closed = `${ringBase}0`;
		writeFileSync(closed, Buffer.alloc(1024 * 1024, 0x41), { mode: 0o640 });
		writeFileSync(`${ringBase}1`, "active", { mode: 0o640 });
		utimesSync(closed, (anchor - 2_000) / 1_000, (anchor - 2_000) / 1_000);
		utimesSync(`${ringBase}1`, (anchor - 1_000) / 1_000, (anchor - 1_000) / 1_000);
		const compactor = createCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			sysdigRingBasePath: ringBase,
		});
		finishStorageDiscovery(compactor);

		const before = compactor.accountedStorageBytes;
		compactor.requestPin(RUN_ID, firstIncident, anchor);
		const afterFirst = compactor.accountedStorageBytes;
		compactor.requestPin("22222222-2222-4222-8222-222222222222", secondIncident, anchor);
		const afterSecond = compactor.accountedStorageBytes;
		expect(afterFirst - before).toBeGreaterThanOrEqual(allocatedBytes(closed));
		expect(afterSecond - afterFirst).toBeGreaterThanOrEqual(allocatedBytes(closed));

		const records = [firstIncident, secondIncident].map((incidentDir) => {
			const recordsDir = join(incidentDir, "sysdig-pins", "records");
			return readdirSync(recordsDir)
				.map((name) => JSON.parse(readFileSync(join(recordsDir, name), "utf8")) as Record<string, unknown>)
				.find((record) => record.sourceName === "ring.scap0");
		});
		for (const record of records) {
			expect(record?.captureMethod).toBe("hard_link");
			expect(record).not.toHaveProperty("storageOwnerPath");
			expect(statSync(String(record?.pinnedPath)).ino).toBe(statSync(closed).ino);
		}
		expect(existsSync(join(target.agentDir, "incident-recorder", "sysdig-pins", "owners"))).toBe(false);

		const survivingPin = String(records[1]?.pinnedPath);
		rmSync(closed);
		rmSync(firstIncident, { recursive: true, force: true });
		expect(existsSync(survivingPin)).toBe(true);
		expect(readFileSync(survivingPin)).toEqual(Buffer.alloc(1024 * 1024, 0x41));

		const restarted = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(restarted);
		expect(restarted.accountedStorageBytes).toBe(
			uniqueAllocatedBytes([join(target.agentDir, "incident-recorder"), join(target.agentDir, "incidents")]),
		);
	});

	it("preserves reverse pending-sequence lookup and drains the frontier without per-entry clones or shift", () => {
		const target = fixture("frontier");
		const compactor = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		type FrontierEntry = {
			resolved: boolean;
			memoryBytes: number;
			cursor: string;
			machineId: string;
			bootId: string;
			invocationId: string | null;
			realtimeUs: string;
			sequenceUpdates?: { wrapperKey: string; wrapper: string; producerKey: string; producer: string };
		};
		type FrontierAccess = {
			pendingEntries: FrontierEntry[];
			pendingEntryHead: number;
			pendingEntryBytes: number;
			previousPendingSequence(kind: "wrapper" | "producer", key: string): string | undefined;
			advanceCheckpoint(): void;
			commitCursor(...values: unknown[]): void;
			wrapperSequences: Map<string, bigint>;
			producerSequences: Map<string, bigint>;
		};
		const frontier = compactor as unknown as FrontierAccess;
		const reference = (index: number, resolved: boolean, wrapperKey = "wrapper-a"): FrontierEntry => ({
			resolved,
			memoryBytes: 1,
			cursor: `cursor-${index}`,
			machineId: "machine",
			bootId: "boot",
			invocationId: null,
			realtimeUs: String(index),
			sequenceUpdates: {
				wrapperKey,
				wrapper: String(index),
				producerKey: index === 3 ? "producer-b" : "producer-a",
				producer: String(index * 10),
			},
		});
		frontier.pendingEntries.push(reference(1, false), reference(2, false, "wrapper-b"), reference(3, false));
		expect(frontier.previousPendingSequence("wrapper", "wrapper-a")).toBe("3");
		expect(frontier.previousPendingSequence("producer", "producer-a")).toBe("20");

		frontier.pendingEntries.length = 0;
		frontier.pendingEntryHead = 0;
		frontier.pendingEntryBytes = 2_049;
		for (let index = 0; index < 2_049; index += 1) frontier.pendingEntries.push(reference(index, true));
		const entries = frontier.pendingEntries as FrontierEntry[] & {
			shift: () => never;
			slice: () => never;
			reverse: () => never;
		};
		entries.shift = () => {
			throw new Error("shift must not be used");
		};
		entries.slice = () => {
			throw new Error("slice clone must not be used");
		};
		entries.reverse = () => {
			throw new Error("reverse must not be used");
		};
		let spliceCalls = 0;
		const splice = entries.splice.bind(entries);
		entries.splice = ((...args: Parameters<typeof entries.splice>) => {
			spliceCalls += 1;
			return splice(...args);
		}) as typeof entries.splice;
		const cursors: string[] = [];
		frontier.commitCursor = (cursor) => cursors.push(String(cursor));

		frontier.advanceCheckpoint();

		expect(cursors).toHaveLength(2_049);
		expect(cursors[0]).toBe("cursor-0");
		expect(cursors.at(-1)).toBe("cursor-2048");
		expect(spliceCalls).toBeLessThanOrEqual(1);
		expect(frontier.pendingEntries).toHaveLength(0);
		expect(frontier.pendingEntryHead).toBe(0);
		expect(frontier.pendingEntryBytes).toBe(0);
		expect(frontier.wrapperSequences.get("wrapper-a")).toBe(2_048n);
		expect(frontier.producerSequences.get("producer-a")).toBe(20_480n);
	});

	it("bounds incident and Sysdig discovery slices and converges after a mid-scan restart", () => {
		const target = fixture("discovery-restart");
		const incidentRoot = join(target.agentDir, "incidents");
		for (let index = 0; index < 160; index += 1) {
			mkdirSync(join(incidentRoot, `noise-${String(index).padStart(3, "0")}`), {
				recursive: true,
				mode: 0o700,
			});
		}
		const incidentDir = join(incidentRoot, "eligible-last");
		mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
		const ringDir = join(target.root, "large-ring-directory");
		const ringBase = join(ringDir, "ring.scap");
		mkdirSync(ringDir, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 400; index += 1) {
			writeFileSync(join(ringDir, `noise-${String(index).padStart(3, "0")}`), "", { mode: 0o600 });
		}
		const anchor = Date.now();
		for (let index = 0; index < 3; index += 1) {
			const path = `${ringBase}${index}`;
			writeFileSync(path, `segment-${index}`, { mode: 0o640 });
			utimesSync(path, (anchor - (3 - index) * 1_000) / 1_000, (anchor - (3 - index) * 1_000) / 1_000);
		}
		const request = {
			version: 1,
			runId: RUN_ID,
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
			requestedAtWallTimeMs: anchor,
			retainUntilWallTimeMs: anchor + 3 * 24 * 60 * 60 * 1_000,
			ringBasePath: ringBase,
		};
		writeJson(join(incidentDir, "sysdig-pin-request.json"), request);
		writeJson(join(incidentDir, "journal-pin-request.json"), {
			...request,
			state: "pending",
		});

		const first = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(first);
		first.processPendingPins(anchor);
		expect(first.survivalSnapshot().incidentDiscoverySliceEntries).toBeLessThanOrEqual(64);
		first.dispose();

		const second = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(second);
		for (let call = 0; call < 4; call += 1) second.processPendingPins(anchor);
		second.dispose();

		const restarted = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(restarted);
		const observedSlices: Array<{ incident: number; sysdig: number; candidates: number }> = [];
		for (let call = 0; call < 48; call += 1) {
			restarted.processPendingPins(anchor);
			const snapshot = restarted.survivalSnapshot();
			observedSlices.push({
				incident: snapshot.incidentDiscoverySliceEntries,
				sysdig: snapshot.sysdigDiscoverySliceEntries,
				candidates: snapshot.sysdigDiscoveryCandidates,
			});
			const recordsDir = join(incidentDir, "sysdig-pins", "records");
			if (existsSync(recordsDir) && readdirSync(recordsDir).some((name) => name.endsWith(".json"))) break;
		}
		for (const slice of observedSlices) {
			expect(slice.incident).toBeLessThanOrEqual(64);
			expect(slice.sysdig).toBeLessThanOrEqual(64);
			expect(slice.candidates).toBeLessThanOrEqual(32);
		}
		const recordsDir = join(incidentDir, "sysdig-pins", "records");
		const sourceNames = readdirSync(recordsDir).map(
			(name) => (JSON.parse(readFileSync(join(recordsDir, name), "utf8")) as { sourceName: string }).sourceName,
		);
		expect(sourceNames).toEqual(expect.arrayContaining(["ring.scap0", "ring.scap1"]));
		restarted.dispose();
	});

	it("fails storage admission closed for an unclassified regular hard link", () => {
		const target = fixture("unclassified-link");
		const directory = join(target.agentDir, "incident-recorder", "unknown");
		mkdirSync(directory, { recursive: true, mode: 0o700 });
		writeFileSync(join(directory, "one"), "payload", { mode: 0o600 });
		linkSync(join(directory, "one"), join(directory, "two"));
		const compactor = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		for (let slice = 0; slice < 8 && !compactor.survivalSnapshot().storageDiscoveryError; slice += 1) {
			compactor.advanceBoundedDiscovery();
		}
		expect(compactor.survivalSnapshot().storageDiscoveryError).toBe(
			"unclassified_hard_link_blocks_exact_storage_accounting",
		);
		expect(compactor.admitObservation()).toBe(false);
	});
	it("requires a durable close publication and rejects a source changed after publication", () => {
		const target = fixture("stopped-close-publication");
		const source = join(target.root, "artifact.bin");
		const publication = join(target.root, "artifact.closed.json");
		writeFileSync(source, "before", { mode: 0o600 });
		const compactor = createCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(compactor);

		expect(
			compactor.streamStoppedTargetArtifact(RUN_ID, source, "exact", publication, {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 64,
			}),
		).toEqual({ state: "error", reason: "artifact_close_publication_required" });

		const closed = statSync(source, { bigint: true });
		writeJson(publication, {
			schemaVersion: 1,
			state: "closed",
			proof: "target_process_stopped",
			source: {
				path: source,
				dev: closed.dev.toString(),
				ino: closed.ino.toString(),
				bytes: Number(closed.size),
				mtimeMs: Number(closed.mtimeMs),
				ctimeMs: Number(closed.ctimeMs),
			},
		});
		writeFileSync(source, "after!", { mode: 0o600 });
		utimesSync(source, 1, 1);
		expect(
			compactor.streamStoppedTargetArtifact(RUN_ID, source, "exact", publication, {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 64,
			}),
		).toEqual({ state: "error", reason: "artifact_source_does_not_match_close_publication" });
	});

	it("reserves aggregate stopped-artifact storage before either 600 KiB stream can exceed a 1 MiB ceiling", () => {
		const target = fixture("stopped-aggregate-ceiling");
		mkdirSync(target.agentDir, { recursive: true, mode: 0o700 });
		const firstSource = join(target.root, "first.bin");
		const secondSource = join(target.root, "second.bin");
		writeFileSync(firstSource, Buffer.alloc(600 * 1024, 0x11), { mode: 0o600 });
		writeFileSync(secondSource, Buffer.alloc(600 * 1024, 0x22), { mode: 0o600 });
		const ceiling = 1024 * 1024;
		const compactor = createCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			storageByteCeiling: ceiling,
		});
		finishStorageDiscovery(compactor);

		const first = streamClosedArtifact(compactor, RUN_ID, firstSource, "exact", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1,
		});
		expect(first).toMatchObject({ state: "pending", copiedBytes: 1, totalBytes: 600 * 1024 });
		const afterFirst = compactor.survivalSnapshot();
		expect(afterFirst.accountedStorageBytes).toBe(compactor.accountedStorageBytes);
		expect(afterFirst.reservedStorageBytes).toBe(compactor.reservedStorageBytes);
		expect(afterFirst.reservedStorageBytes).toBeGreaterThan(600 * 1024);
		expect(afterFirst.accountedStorageBytes + afterFirst.reservedStorageBytes).toBeLessThanOrEqual(ceiling);

		const second = streamClosedArtifact(compactor, RUN_ID, secondSource, "exact", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1,
		});
		expect(second).toMatchObject({ state: "pending", reason: "storage_paused", copiedBytes: 0 });
		const afterSecond = compactor.survivalSnapshot();
		expect(afterSecond.accountedStorageBytes).toBe(afterFirst.accountedStorageBytes);
		expect(afterSecond.reservedStorageBytes).toBe(afterFirst.reservedStorageBytes);
		expect(afterSecond.accountedStorageBytes + afterSecond.reservedStorageBytes).toBeLessThanOrEqual(ceiling);

		const completed = streamClosedArtifact(compactor, RUN_ID, firstSource, "exact", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1024 * 1024,
		});
		expect(completed).toMatchObject({ state: "complete", artifact: { bytes: 600 * 1024 } });
		const afterCompletion = compactor.survivalSnapshot();
		expect(afterCompletion.accountedStorageBytes).toBe(compactor.accountedStorageBytes);
		expect(afterCompletion.reservedStorageBytes).toBe(0);
		expect(afterCompletion.accountedStorageBytes).toBeLessThanOrEqual(ceiling);
	});

	it("bounds stopped-artifact reservations at eight streams and releases all reservations on double dispose", () => {
		const target = fixture("stopped-eight");
		mkdirSync(target.agentDir, { recursive: true, mode: 0o700 });
		const ceiling = 4 * 1024 * 1024;
		const compactor = createCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			storageByteCeiling: ceiling,
		});
		finishStorageDiscovery(compactor);
		for (let index = 0; index < 8; index += 1) {
			const source = join(target.root, `source-${index}.bin`);
			writeFileSync(source, Buffer.from([index]), { mode: 0o600 });
			expect(
				streamClosedArtifact(compactor, `${RUN_ID}-${index}`, source, "exact", {
					deadlineMs: Date.now() + 1_000,
					byteBudget: 0,
				}),
			).toMatchObject({ state: "pending", reason: "work_budget" });
			const snapshot = compactor.survivalSnapshot();
			expect(snapshot.accountedStorageBytes).toBe(compactor.accountedStorageBytes);
			expect(snapshot.reservedStorageBytes).toBe(compactor.reservedStorageBytes);
			expect(snapshot.reservedStorageBytes).toBeGreaterThan(0);
			expect(snapshot.accountedStorageBytes + snapshot.reservedStorageBytes).toBeLessThanOrEqual(ceiling);
		}
		const rejectedSource = join(target.root, "source-rejected.bin");
		writeFileSync(rejectedSource, "rejected", { mode: 0o600 });
		const beforeRejected = compactor.survivalSnapshot();
		expect(
			streamClosedArtifact(compactor, "ninth", rejectedSource, "exact", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 0,
			}),
		).toMatchObject({ state: "pending", reason: "work_budget" });
		const afterRejected = compactor.survivalSnapshot();
		expect(afterRejected.accountedStorageBytes).toBe(beforeRejected.accountedStorageBytes);
		expect(afterRejected.reservedStorageBytes).toBe(beforeRejected.reservedStorageBytes);
		compactor.dispose();
		const afterDispose = compactor.survivalSnapshot();
		expect(afterDispose.accountedStorageBytes).toBe(beforeRejected.accountedStorageBytes);
		expect(afterDispose.reservedStorageBytes).toBe(0);
		compactor.dispose();
		expect(compactor.survivalSnapshot()).toMatchObject({
			accountedStorageBytes: afterDispose.accountedStorageBytes,
			reservedStorageBytes: 0,
		});
	});

	it("reserves directory, publication, and run-reference growth before creating a stopped stream", () => {
		const target = fixture("stopped-reference-overhead");
		mkdirSync(target.agentDir, { recursive: true, mode: 0o700 });
		const source = join(target.root, "small.bin");
		writeFileSync(source, Buffer.alloc(4 * 1024, 0x44), { mode: 0o600 });
		const ceiling = 128 * 1024;
		const compactor = createCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			storageByteCeiling: ceiling,
		});
		finishStorageDiscovery(compactor);
		expect(
			streamClosedArtifact(compactor, RUN_ID, source, "exact", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 1,
			}),
		).toMatchObject({ state: "pending", reason: "storage_paused" });
		const snapshot = compactor.survivalSnapshot();
		expect(snapshot.accountedStorageBytes).toBe(0);
		expect(snapshot.reservedStorageBytes).toBe(0);
		expect(existsSync(join(target.agentDir, "incident-recorder"))).toBe(false);
	});

	it("converts a late success once and releases a late mutation error without affecting the other stream", () => {
		const target = fixture("stopped-late-results");
		mkdirSync(target.agentDir, { recursive: true, mode: 0o700 });
		const successSource = join(target.root, "success.bin");
		const errorSource = join(target.root, "error.bin");
		writeFileSync(successSource, Buffer.alloc(64 * 1024, 0x55), { mode: 0o600 });
		writeFileSync(errorSource, Buffer.alloc(64 * 1024, 0x66), { mode: 0o600 });
		const ceiling = 2 * 1024 * 1024;
		const compactor = createCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			storageByteCeiling: ceiling,
		});
		finishStorageDiscovery(compactor);
		for (const [runId, source] of [
			[RUN_ID, successSource],
			["mutated", errorSource],
		] as const) {
			expect(
				streamClosedArtifact(compactor, runId, source, "exact", {
					deadlineMs: Date.now() + 1_000,
					byteBudget: 32 * 1024,
				}),
			).toMatchObject({ state: "pending", copiedBytes: 32 * 1024 });
			const snapshot = compactor.survivalSnapshot();
			expect(snapshot.accountedStorageBytes + snapshot.reservedStorageBytes).toBeLessThanOrEqual(ceiling);
		}
		const beforeError = compactor.survivalSnapshot();
		writeFileSync(errorSource, Buffer.alloc(64 * 1024, 0x77), { mode: 0o600 });
		expect(
			streamClosedArtifact(compactor, "mutated", errorSource, "exact", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 128 * 1024,
			}),
		).toMatchObject({ state: "error", reason: "artifact_source_changed_during_capture" });
		const afterError = compactor.survivalSnapshot();
		expect(afterError.accountedStorageBytes).toBe(beforeError.accountedStorageBytes);
		expect(afterError.reservedStorageBytes).toBeLessThan(beforeError.reservedStorageBytes);
		expect(afterError.reservedStorageBytes).toBeGreaterThan(0);
		expect(afterError.accountedStorageBytes + afterError.reservedStorageBytes).toBeLessThanOrEqual(ceiling);
		expect(
			streamClosedArtifact(compactor, RUN_ID, successSource, "exact", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 128 * 1024,
			}),
		).toMatchObject({ state: "complete", artifact: { bytes: 64 * 1024 } });
		const afterSuccess = compactor.survivalSnapshot();
		expect(afterSuccess.accountedStorageBytes).toBe(compactor.accountedStorageBytes);
		expect(afterSuccess.reservedStorageBytes).toBe(0);
		expect(afterSuccess.accountedStorageBytes).toBeLessThanOrEqual(ceiling);
	});
});
