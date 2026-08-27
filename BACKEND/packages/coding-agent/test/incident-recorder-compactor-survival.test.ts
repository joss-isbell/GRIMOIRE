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
import { dirname, join } from "node:path";
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
		if (before.storageDiscoveryComplete) return;
		const beforeEntries = before.storageDiscoveryEntries;
		compactor.advanceBoundedDiscovery();
		const after = compactor.survivalSnapshot();
		expect(after.storageDiscoveryEntries - beforeEntries).toBeLessThanOrEqual(512);
		expect(after.storageDiscoverySliceEntries).toBeLessThanOrEqual(512);
		expect(after.storageDiscoveryDepth).toBeLessThanOrEqual(65);
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
