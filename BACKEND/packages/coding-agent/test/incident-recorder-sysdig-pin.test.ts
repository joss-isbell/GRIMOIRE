import {
	chmodSync,
	existsSync,
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
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";

const roots: string[] = [];
const RUN_ID = "11111111-1111-4111-8111-111111111111";

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { root: string; agentDir: string; incidentDir: string; ringBase: string } {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-sysdig-pin-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const incidentDir = join(agentDir, "incidents", "incident-one");
	const ringDir = join(root, "stock-sysdig");
	mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
	mkdirSync(ringDir, { mode: 0o750 });
	return { root, agentDir, incidentDir, ringBase: join(ringDir, "ring.scap") };
}

function writeSegment(path: string, bytes: string, mtimeMs: number): void {
	writeFileSync(path, bytes, { mode: 0o640 });
	chmodSync(path, 0o640);
	utimesSync(path, mtimeMs / 1_000, mtimeMs / 1_000);
}

async function initializeStorageAccounting(compactor: IncidentRecorderCompactor): Promise<void> {
	const controller = new AbortController();
	await compactor.initializeStorageAccounting(controller.signal);
}

function finalizeWithoutJournalScan(
	target: ReturnType<typeof fixture>,
	anchor: number,
	compactor: IncidentRecorderCompactor,
): Record<string, any> {
	const request = JSON.parse(readFileSync(join(target.incidentDir, "journal-pin-request.json"), "utf8")) as Record<
		string,
		unknown
	>;
	writeFileSync(
		join(target.incidentDir, "journal-pin-manifest.json"),
		`${JSON.stringify({
			state: "complete_through_requested_window",
			runId: RUN_ID,
			fromWallTimeMs: request.fromWallTimeMs,
			throughWallTimeMs: request.throughWallTimeMs,
			occurrences: [],
		})}\n`,
		{ mode: 0o600 },
	);
	compactor.processPendingPins(anchor + 15 * 60 * 1_000);
	return JSON.parse(readFileSync(join(target.incidentDir, "sysdig-pin-manifest.json"), "utf8")) as Record<string, any>;
}

describe("stock Sysdig incident pins", () => {
	it("pins the current ring immediately with hard links for closed files and a private exact copy for the active file", async () => {
		const target = fixture();
		const anchor = Date.now();
		const closed = `${target.ringBase}0`;
		const active = `${target.ringBase}1`;
		writeSegment(closed, "closed-segment", anchor - 2_000);
		writeSegment(active, "active-segment", anchor - 1_000);
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);

		compactor.requestPin(RUN_ID, target.incidentDir, anchor);

		const recordsDir = join(target.incidentDir, "sysdig-pins", "records");
		const records = readdirSync(recordsDir).map(
			(name) => JSON.parse(readFileSync(join(recordsDir, name), "utf8")) as Record<string, any>,
		);
		expect(records).toHaveLength(2);
		const closedRecord = records.find((record) => record.sourceName === "ring.scap0");
		const activeRecord = records.find((record) => record.sourceName === "ring.scap1");
		if (!closedRecord || !activeRecord) throw new Error("Expected both closed and active Sysdig pin records");
		expect(closedRecord?.captureMethod).toBe("hard_link");
		expect(closedRecord?.captureReason).toBe("closed_segment_hard_link");
		expect(statSync(closedRecord.pinnedPath).ino).toBe(statSync(closed).ino);
		expect(activeRecord?.captureMethod).toBe("bounded_copy");
		expect(activeRecord?.captureReason).toBe("active_segment_snapshot");
		expect(statSync(activeRecord.pinnedPath).ino).not.toBe(statSync(active).ino);
		expect(statSync(activeRecord.pinnedPath).mode & 0o777).toBe(0o600);
		expect(statSync(join(target.incidentDir, "sysdig-pins")).mode & 0o777).toBe(0o700);
		expect(readFileSync(activeRecord.pinnedPath, "utf8")).toBe("active-segment");
	});

	it("adds the final active segment through +15m and reports exact bytes, retention, and coverage limits", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}0`, "before", anchor - 1_000);
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);
		compactor.requestPin(RUN_ID, target.incidentDir, anchor);
		writeSegment(`${target.ringBase}1`, "after", anchor + 1_000);

		const manifest = finalizeWithoutJournalScan(target, anchor, compactor);

		expect(manifest.state).toBe("finalized_with_observed_coverage");
		expect(manifest.diagnosticOnly).toBe(true);
		expect(manifest.requestedWindow).toEqual({
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			anchorWallTimeMs: anchor,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
		});
		expect(manifest.retention).toEqual({
			milliseconds: 3 * 24 * 60 * 60 * 1_000,
			retainUntilWallTimeMs: anchor + 3 * 24 * 60 * 60 * 1_000,
		});
		const retentionProof = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pin-retention-proof.json"), "utf8"),
		) as Record<string, any>;
		expect(retentionProof).toMatchObject({
			state: "producer_verified_complete",
			provider: "sysdig",
			manifestValidated: true,
			retentionMilliseconds: 3 * 24 * 60 * 60 * 1_000,
		});
		expect(manifest.segments.map((segment: Record<string, any>) => segment.sourceName).sort()).toEqual([
			"ring.scap0",
			"ring.scap1",
		]);
		for (const segment of manifest.segments) {
			expect(segment.exactBytes.bytes).toBe(readFileSync(segment.pinnedPath).length);
			expect(segment.exactBytes.sha256).toMatch(/^[0-9a-f]{64}$/);
		}
		expect(manifest.coverage.gaps).toContain("scap_event_time_bounds_not_inspected_coverage_is_observation_based");
	});

	it("marks a hard-linked segment that changed after the immediate pin as an honest gap", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}0`, "closed", anchor - 2_000);
		writeSegment(`${target.ringBase}1`, "active", anchor - 1_000);
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);
		compactor.requestPin(RUN_ID, target.incidentDir, anchor);
		writeFileSync(`${target.ringBase}0`, "reused-inode", { mode: 0o640 });

		const manifest = finalizeWithoutJournalScan(target, anchor, compactor);

		expect(
			manifest.coverage.gaps.some((gap: string) => gap.startsWith("hard_link_changed_after_capture:ring.scap0")),
		).toBe(true);
		expect(existsSync(join(target.incidentDir, "sysdig-pin-request.json"))).toBe(true);
	});
	it("accounts a shared live Sysdig inode only once across incident hard links", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}0`, "x".repeat(1024 * 1024), anchor - 2_000);
		writeSegment(`${target.ringBase}1`, "y", anchor - 1_000);
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);
		const before = compactor.accountedStorageBytes;
		compactor.requestPin(RUN_ID, target.incidentDir, anchor);
		const afterFirst = compactor.accountedStorageBytes;
		const secondIncident = join(target.agentDir, "incidents", "incident-two");
		mkdirSync(secondIncident, { recursive: true, mode: 0o700 });
		compactor.requestPin("22222222-2222-4222-8222-222222222222", secondIncident, anchor);
		const afterSecond = compactor.accountedStorageBytes;
		expect(afterFirst - before).toBeGreaterThan(1024 * 1024);
		expect(afterSecond - afterFirst).toBeLessThan(256 * 1024);
	});

	it("never creates a 33rd record across repeated rotated captures", async () => {
		const target = fixture();
		const anchor = Date.now();
		for (let index = 0; index < 12; index += 1) {
			writeSegment(`${target.ringBase}${index}`, `initial-${index}`, anchor - (12 - index) * 1_000);
		}
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);
		compactor.requestPin(RUN_ID, target.incidentDir, anchor);

		for (let round = 1; round <= 6; round += 1) {
			for (let index = 0; index < 12; index += 1) {
				writeSegment(
					`${target.ringBase}${index}`,
					`rotation-${round}-${index}`,
					anchor + (round * 100 + index) * 1_000,
				);
			}
			compactor.processPendingPins(anchor + round * 1_000);
		}

		const recordsDir = join(target.incidentDir, "sysdig-pins", "records");
		expect(readdirSync(recordsDir).filter((name) => name.endsWith(".json"))).toHaveLength(32);
		const issuesDir = join(target.incidentDir, "sysdig-pins", "issues");
		const issues = readdirSync(issuesDir).map(
			(name) => JSON.parse(readFileSync(join(issuesDir, name), "utf8")) as { reason: string },
		);
		expect(issues.map((issue) => issue.reason)).toContain("pin_record_count_bound_reached");
	});

	it.runIf(existsSync("/dev/shm"))(
		"falls back to a bounded private copy when a closed segment cannot be hard-linked",
		async () => {
			const target = fixture();
			const ringRoot = mkdtempSync("/dev/shm/prime-agent-sysdig-ring-");
			roots.push(ringRoot);
			const ringBase = join(ringRoot, "ring.scap");
			const anchor = Date.now();
			writeSegment(`${ringBase}0`, "closed-cross-device", anchor - 2_000);
			writeSegment(`${ringBase}1`, "active-cross-device", anchor - 1_000);
			const compactor = new IncidentRecorderCompactor({
				agentDir: target.agentDir,
				sysdigRingBasePath: ringBase,
				freeReserveBytes: 0,
			});
			await initializeStorageAccounting(compactor);

			compactor.requestPin(RUN_ID, target.incidentDir, anchor);

			const recordsDir = join(target.incidentDir, "sysdig-pins", "records");
			const records = readdirSync(recordsDir).map(
				(name) => JSON.parse(readFileSync(join(recordsDir, name), "utf8")) as Record<string, any>,
			);
			const closedRecord = records.find((record) => record.sourceName === "ring.scap0");
			if (!closedRecord) throw new Error("Expected the cross-device Sysdig pin record");
			expect(closedRecord).toMatchObject({
				captureMethod: "bounded_copy",
				captureReason: "hard_link_unavailable",
				hardLinkErrorCode: "EXDEV",
			});
			expect(statSync(closedRecord.pinnedPath).mode & 0o777).toBe(0o600);
			expect(readFileSync(closedRecord.pinnedPath, "utf8")).toBe("closed-cross-device");
		},
	);
});
