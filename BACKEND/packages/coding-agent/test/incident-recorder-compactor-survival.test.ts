import {
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
import { afterEach, describe, expect, it } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";

const roots: string[] = [];
const RUN_ID = "11111111-1111-4111-8111-111111111111";

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
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("incident compactor survival bounds", () => {
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

		const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
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
		const compactor = new IncidentRecorderCompactor({
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
		const compactor = new IncidentRecorderCompactor({
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
		const journalPin = join(incidentRoot, "journal-pins", "cas", `${casId}.blob`);
		mkdirSync(dirname(journalPin), { recursive: true, mode: 0o700 });
		linkSync(cas, journalPin);
		const immutableTemporary = join(dirname(gap), `.${basename(gap)}.tmp-123-${"7".repeat(64)}`);
		linkSync(gap, immutableTemporary);
		const sysdigOwner = join(recorderRoot, "sysdig-pins", "owners", `${sysdigId}.scap`);
		const sysdigPin = join(incidentRoot, "sysdig-pins", "segments", `${sysdigId}.scap`);
		mkdirSync(dirname(sysdigOwner), { recursive: true, mode: 0o700 });
		mkdirSync(dirname(sysdigPin), { recursive: true, mode: 0o700 });
		writeFileSync(sysdigOwner, "sysdig", { mode: 0o600 });
		linkSync(sysdigOwner, sysdigPin);
		const sysdigStat = lstatSync(sysdigOwner);
		writeJson(join(incidentRoot, "sysdig-pins", "records", `${sysdigId}.json`), {
			version: 1,
			id: sysdigId,
			sourcePath: join(target.root, "stock-ring", "ring.scap0"),
			sourceName: "ring.scap0",
			observedAtWallTimeMs: 1,
			phase: "initial",
			source: { dev: String(sysdigStat.dev), ino: String(sysdigStat.ino), bytes: 6, mtimeMs: 1 },
			pinnedPath: sysdigPin,
			storageOwnerPath: sysdigOwner,
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
			{ shape: "immutable crash temp", owner: gap, reference: immutableTemporary, admission: "allow" },
			{
				shape: "Sysdig persistent owner and incident ref",
				owner: sysdigOwner,
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
			"immutable crash temp",
			"Sysdig persistent owner and incident ref",
			"unknown hard-link shape",
		]);
		for (const row of taxonomy.filter((entry) => entry.admission === "allow")) {
			expect(statSync(row.owner).ino).toBe(statSync(row.reference).ino);
		}
		const classified = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(classified);
		expect(classified.accountedStorageBytes).toBe(
			uniqueAllocatedBytes([recorderRoot, join(target.agentDir, "incidents")]),
		);

		mkdirSync(unknownDir, { recursive: true, mode: 0o700 });
		writeFileSync(unknownOwner, "unknown", { mode: 0o600 });
		linkSync(unknownOwner, unknownReference);
		const unknown = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		for (let slice = 0; slice < 128 && !unknown.survivalSnapshot().storageDiscoveryError; slice += 1) {
			unknown.advanceBoundedDiscovery();
		}
		expect(unknown.survivalSnapshot().storageDiscoveryError).toBe(
			"unclassified_hard_link_blocks_exact_storage_accounting",
		);
		expect(unknown.admitObservation()).toBe(false);
	});

	it("accounts one shared Sysdig storage owner across newly published incident hard links and restart", () => {
		const target = fixture("sysdig-owner");
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
		const compactor = new IncidentRecorderCompactor({
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
		expect(afterSecond - afterFirst).toBeLessThan(allocatedBytes(closed));

		const records = [firstIncident, secondIncident].map((incidentDir) => {
			const recordsDir = join(incidentDir, "sysdig-pins", "records");
			return readdirSync(recordsDir)
				.map((name) => JSON.parse(readFileSync(join(recordsDir, name), "utf8")) as Record<string, unknown>)
				.find((record) => record.sourceName === "ring.scap0");
		});
		expect(records[0]?.captureMethod).toBe("hard_link");
		expect(records[0]?.storageOwnerPath).toBe(records[1]?.storageOwnerPath);
		expect(statSync(String(records[0]?.pinnedPath)).ino).toBe(statSync(closed).ino);
		expect(statSync(String(records[0]?.storageOwnerPath)).ino).toBe(statSync(closed).ino);
		const persistentOwner = String(records[0]?.storageOwnerPath);
		const survivingPin = String(records[1]?.pinnedPath);
		expect(persistentOwner.startsWith(join(target.agentDir, "incident-recorder", "sysdig-pins", "owners"))).toBe(
			true,
		);

		rmSync(firstIncident, { recursive: true, force: true });
		expect(existsSync(persistentOwner)).toBe(true);
		expect(existsSync(survivingPin)).toBe(true);
		expect(statSync(persistentOwner).ino).toBe(statSync(survivingPin).ino);

		const restarted = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(restarted);
		expect(restarted.accountedStorageBytes).toBe(
			uniqueAllocatedBytes([join(target.agentDir, "incident-recorder"), join(target.agentDir, "incidents")]),
		);
	});

	it("preserves reverse pending-sequence lookup and drains the frontier without per-entry clones or shift", () => {
		const target = fixture("frontier");
		const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
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

		const first = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(first);
		first.processPendingPins(anchor);
		expect(first.survivalSnapshot().incidentDiscoverySliceEntries).toBeLessThanOrEqual(64);

		const second = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		finishStorageDiscovery(second);
		for (let call = 0; call < 4; call += 1) second.processPendingPins(anchor);

		const restarted = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
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
	});

	it("fails storage admission closed for an unclassified regular hard link", () => {
		const target = fixture("unclassified-link");
		const directory = join(target.agentDir, "incident-recorder", "unknown");
		mkdirSync(directory, { recursive: true, mode: 0o700 });
		writeFileSync(join(directory, "one"), "payload", { mode: 0o600 });
		linkSync(join(directory, "one"), join(directory, "two"));
		const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		for (let slice = 0; slice < 8 && !compactor.survivalSnapshot().storageDiscoveryError; slice += 1) {
			compactor.advanceBoundedDiscovery();
		}
		expect(compactor.survivalSnapshot().storageDiscoveryError).toBe(
			"unclassified_hard_link_blocks_exact_storage_accounting",
		);
		expect(compactor.admitObservation()).toBe(false);
	});
});
