import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	statSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { IncidentRecorderCompactor as ProductionCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	acquireIncidentRecorderWriterRecoveryLease,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const roots: string[] = [];
const fixtureLeases = new Map<string, IncidentRecorderWriterLifecycleLease>();
const RUN_ID = "11111111-1111-4111-8111-111111111111";

// One fixture service owns admission across its reconstructed compactor instances.
class IncidentRecorderCompactor extends ProductionCompactor {
	constructor(options: ConstructorParameters<typeof ProductionCompactor>[0]) {
		super({
			...options,
			writerLifecycleLease:
				options.writerLifecycleLease ??
				(() => {
					const existing = fixtureLeases.get(options.agentDir);
					if (existing) return existing;
					const admitted = acquireIncidentRecorderWriterNormalLease(
						{ agentDir: options.agentDir },
						{
							activationGenerationDigest: "a".repeat(64),
							revalidateActivation: () => ({ state: "valid" }),
							acquireCas: acquireIncidentRecorderNamespaceCas,
						},
					);
					if (admitted.state !== "acquired") throw new Error(`fixture writer lease: ${admitted.reason}`);
					fixtureLeases.set(options.agentDir, admitted.lease);
					return admitted.lease;
				}),
		});
	}
}

afterEach(() => {
	for (const lease of fixtureLeases.values()) lease.release();
	fixtureLeases.clear();
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
	mkdirSync(join(target.incidentDir, "journal-pins", "cas"), { recursive: true, mode: 0o700 });
	writeFileSync(
		join(target.incidentDir, "journal-pin-manifest.json"),
		`${JSON.stringify({
			version: 1,
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

function internalStorageEntries(compactor: IncidentRecorderCompactor): number {
	return (compactor as unknown as { storageEntries: number }).storageEntries;
}

function internalStorageReservations(compactor: IncidentRecorderCompactor): {
	bytes: number;
	entries: number;
	inodes: number;
} {
	const state = compactor as unknown as {
		storageReservedBytes: number;
		storageReservedEntries: number;
		storageReservedInodes: number;
	};
	return {
		bytes: state.storageReservedBytes,
		entries: state.storageReservedEntries,
		inodes: state.storageReservedInodes,
	};
}

function setStorageHighWaterEntries(compactor: IncidentRecorderCompactor, value: number): void {
	(compactor as unknown as { options: { storageHighWaterEntries?: number } }).options.storageHighWaterEntries = value;
}

describe("stock Sysdig incident pins", () => {
	it("admits all root publication writes against one cumulative reservation", async () => {
		const target = fixture();
		let compactor!: IncidentRecorderCompactor;
		const options = {
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			storageHighWaterEntries: Number.MAX_SAFE_INTEGER,
			onSysdigPinStep: undefined as
				| ((step: "sysdig_request_durable" | "provider_requests_durable" | "initial_capture_complete") => void)
				| undefined,
		};
		const observations: Array<{ step: string; reservedEntries: number }> = [];
		options.onSysdigPinStep = (step) => {
			observations.push({ step, reservedEntries: internalStorageReservations(compactor).entries });
		};
		compactor = new IncidentRecorderCompactor(options);
		await initializeStorageAccounting(compactor);
		const before = internalStorageEntries(compactor);
		setStorageHighWaterEntries(compactor, before + 7);
		(compactor as unknown as { processSysdigPin: () => void }).processSysdigPin = () => {};

		compactor.requestPin(RUN_ID, target.incidentDir, Date.now());

		expect(observations).toEqual([
			{ step: "sysdig_request_durable", reservedEntries: 4 },
			{ step: "provider_requests_durable", reservedEntries: 6 },
		]);
		expect(internalStorageEntries(compactor)).toBe(before + 3);
		expect(internalStorageReservations(compactor)).toEqual({ bytes: 0, entries: 0, inodes: 0 });
		expect(compactor.storageAccountingReady).toBe(true);
		expect(compactor.storageMode).toBe("normal");

		const rescanned = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		await initializeStorageAccounting(rescanned);
		expect(rescanned.accountedStorageBytes).toBe(compactor.accountedStorageBytes);
	});

	it("rejects insufficient combined root publication headroom and releases the reservation", async () => {
		const target = fixture();
		const options = {
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			storageHighWaterEntries: Number.MAX_SAFE_INTEGER,
		};
		const compactor = new IncidentRecorderCompactor(options);
		await initializeStorageAccounting(compactor);
		const before = internalStorageEntries(compactor);
		setStorageHighWaterEntries(compactor, before + 3);
		(compactor as unknown as { processSysdigPin: () => void }).processSysdigPin = () => {};

		expect(() => compactor.requestPin(RUN_ID, target.incidentDir, Date.now())).toThrow(
			/ENOSPC|disk admission|filesystem/i,
		);
		expect(existsSync(join(target.incidentDir, "incident-pin-authority.json"))).toBe(true);
		expect(existsSync(join(target.incidentDir, "sysdig-pin-request.json"))).toBe(false);
		expect(internalStorageEntries(compactor)).toBe(before);
		expect(internalStorageReservations(compactor)).toEqual({ bytes: 0, entries: 0, inodes: 0 });
		expect(compactor.storageAccountingReady).toBe(false);
		expect(compactor.storageMode).toBe("recovery-only");
	});

	it("invalidates accounting and releases the cumulative reservation after a partial root write fails", async () => {
		const target = fixture();
		const options = {
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			onSysdigPinStep: (
				step: "sysdig_request_durable" | "provider_requests_durable" | "initial_capture_complete",
			) => {
				if (step === "sysdig_request_durable") throw new Error("after_partial_root_write");
			},
		};
		const compactor = new IncidentRecorderCompactor(options);
		await initializeStorageAccounting(compactor);
		const before = internalStorageEntries(compactor);
		const beforeBytes = compactor.accountedStorageBytes;

		expect(() => compactor.requestPin(RUN_ID, target.incidentDir, Date.now())).toThrow("after_partial_root_write");
		expect(existsSync(join(target.incidentDir, "incident-pin-authority.json"))).toBe(true);
		expect(existsSync(join(target.incidentDir, "sysdig-pin-request.json"))).toBe(true);
		expect(internalStorageEntries(compactor)).toBe(before);
		expect(compactor.accountedStorageBytes).toBe(beforeBytes);
		expect(internalStorageReservations(compactor)).toEqual({ bytes: 0, entries: 0, inodes: 0 });
		expect(compactor.storageAccountingReady).toBe(false);
		expect(compactor.storageMode).toBe("normal");
	});

	it("does not publish or account a detached incidents root, then converges after a new lease", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}1`, "detached-root", anchor - 1_000);
		const incidentsPath = join(target.agentDir, "incidents");
		const displacedIncidentsPath = join(target.root, "incidents-displaced");
		let leaseAdmission: ReturnType<typeof acquireIncidentRecorderWriterNormalLease>;
		let replaced = false;
		const interrupted = new ProductionCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			writerLifecycleLease: () => (leaseAdmission?.state === "acquired" ? leaseAdmission.lease : undefined),
			onSysdigPinStep: (step) => {
				if (step !== "sysdig_request_durable" || replaced) return;
				replaced = true;
				renameSync(incidentsPath, displacedIncidentsPath);
				mkdirSync(incidentsPath, { mode: 0o700 });
			},
		});
		await initializeStorageAccounting(interrupted);
		leaseAdmission = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: target.agentDir },
			{
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			},
		);
		expect(leaseAdmission.state).toBe("acquired");
		if (leaseAdmission.state !== "acquired") return;
		const before = interrupted.accountedStorageBytes;

		expect(() => interrupted.requestPin(RUN_ID, target.incidentDir, anchor)).toThrow(/writer lifecycle/);
		expect(replaced).toBe(true);
		expect(interrupted.storageAccountingReady).toBe(false);
		expect(interrupted.accountedStorageBytes).toBe(before);
		for (const name of [
			"incident-pin-authority.json",
			"sysdig-pin-request.json",
			"journal-pin-request.json",
			"sysdig-pin-incomplete.json",
			"journal-pin-incomplete.json",
			"provider-request-quarantine",
		])
			expect(existsSync(join(incidentsPath, "incident-one", name))).toBe(false);

		expect(leaseAdmission.lease.release().state).toBe("released");
		const recovery = acquireIncidentRecorderWriterRecoveryLease(
			{ agentDir: target.agentDir },
			{
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			},
		);
		expect(recovery.state).toBe("acquired");
		if (recovery.state !== "acquired") return;
		expect(recovery.lease.release().state).toBe("released");
		mkdirSync(join(incidentsPath, "incident-one"), { mode: 0o700 });
		const successor = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: target.agentDir },
			{
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			},
		);
		expect(successor.state).toBe("acquired");
		if (successor.state !== "acquired") return;
		const recovered = new ProductionCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			writerLifecycleLease: () => successor.lease,
		});
		await initializeStorageAccounting(recovered);
		recovered.requestPin(RUN_ID, join(incidentsPath, "incident-one"), anchor);
		const firstAuthority = readFileSync(join(incidentsPath, "incident-one", "incident-pin-authority.json"), "utf8");
		recovered.requestPin(RUN_ID, join(incidentsPath, "incident-one"), anchor);
		expect(readFileSync(join(incidentsPath, "incident-one", "incident-pin-authority.json"), "utf8")).toBe(
			firstAuthority,
		);
		expect(successor.lease.release().state).toBe("released");
	});

	it("starts initial capture only after both immutable provider requests are durable and recovers the request-time active inode", async () => {
		const target = fixture();
		const anchor = Date.now();
		const active = `${target.ringBase}1`;
		writeSegment(active, "request-time-active", anchor - 1_000);
		const steps: string[] = [];
		const interrupted = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			onSysdigPinStep: (step) => {
				steps.push(step);
				if (step === "sysdig_request_durable") {
					expect(existsSync(join(target.incidentDir, "sysdig-pin-request.json"))).toBe(true);
					expect(existsSync(join(target.incidentDir, "journal-pin-request.json"))).toBe(false);
					expect(existsSync(join(target.incidentDir, "sysdig-pins"))).toBe(false);
				}
				if (step === "provider_requests_durable") {
					expect(existsSync(join(target.incidentDir, "journal-pin-request.json"))).toBe(true);
					expect(existsSync(join(target.incidentDir, "sysdig-pins", "initial-capture-plan.json"))).toBe(false);
					throw new Error("crash_after_provider_requests");
				}
			},
		});
		await initializeStorageAccounting(interrupted);

		expect(() => interrupted.requestPin(RUN_ID, target.incidentDir, anchor)).toThrow("crash_after_provider_requests");
		expect(steps).toEqual(["sysdig_request_durable", "provider_requests_durable"]);
		const recovered = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(recovered);
		recovered.processPendingPins(anchor);

		const recordsDir = join(target.incidentDir, "sysdig-pins", "records");
		const records = readdirSync(recordsDir).map(
			(name) => JSON.parse(readFileSync(join(recordsDir, name), "utf8")) as Record<string, any>,
		);
		const initialActive = records.find(
			(record) => record.phase === "initial" && record.captureReason === "active_segment_snapshot",
		);
		if (!initialActive) throw new Error("Expected the request-time active segment to resume as initial capture");
		expect(readFileSync(initialActive.pinnedPath, "utf8")).toBe("request-time-active");
		expect(existsSync(join(target.incidentDir, "sysdig-pins", "initial-capture-complete.json"))).toBe(true);
	});

	it("verifies a resumed active prefix within the work budget and never treats an unrelated record as initial completion", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}1`, "0123456789", anchor - 1_000);
		const first = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			sysdigPinWorkBytesPerPass: 4,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(first);

		first.requestPin(RUN_ID, target.incidentDir, anchor);

		const request = JSON.parse(readFileSync(join(target.incidentDir, "sysdig-pin-request.json"), "utf8")) as Record<
			string,
			any
		>;
		const activeId = request.initialRingSnapshot.candidates[0].id as string;
		const segmentsDir = join(target.incidentDir, "sysdig-pins", "segments");
		const recordsDir = join(target.incidentDir, "sysdig-pins", "records");
		expect(statSync(join(segmentsDir, `.${activeId}.partial`)).size).toBe(4);
		expect(readdirSync(recordsDir)).toHaveLength(0);
		expect(existsSync(join(target.incidentDir, "sysdig-pins", "initial-capture-complete.json"))).toBe(false);
		expect(existsSync(join(target.incidentDir, "sysdig-pins", "sources"))).toBe(false);

		const unrelatedSource = { dev: "0", ino: "0", bytes: 0, mtimeMs: 0, ctimeMs: 0 };
		const unrelatedId = createHash("sha256")
			.update(
				`${unrelatedSource.dev}\0${unrelatedSource.ino}\0${unrelatedSource.bytes}\0${unrelatedSource.mtimeMs}\0${unrelatedSource.ctimeMs}`,
			)
			.digest("hex");
		const unrelatedPath = join(segmentsDir, `${unrelatedId}.scap`);
		writeFileSync(unrelatedPath, "", { mode: 0o600 });
		const unrelatedArtifact = statSync(unrelatedPath);
		writeFileSync(
			join(recordsDir, `${unrelatedId}.json`),
			`${JSON.stringify({
				version: 1,
				id: unrelatedId,
				sourcePath: "unrelated",
				sourceName: "unrelated",
				observedAtWallTimeMs: anchor,
				phase: "rotated",
				source: unrelatedSource,
				pinnedPath: unrelatedPath,
				captureMethod: "bounded_copy",
				captureReason: "closed_segment_private_snapshot",
				bytesAtCapture: 0,
				artifactAtCapture: {
					dev: String(unrelatedArtifact.dev),
					ino: String(unrelatedArtifact.ino),
					bytes: 0,
					mtimeMs: unrelatedArtifact.mtimeMs,
					ctimeMs: unrelatedArtifact.ctimeMs,
					mode: 0o600,
					nlink: 1,
				},
			})}\n`,
			{ mode: 0o600 },
		);

		const recovered = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			sysdigPinWorkBytesPerPass: 4,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(recovered);
		recovered.processPendingPins(anchor);
		expect(statSync(join(segmentsDir, `.${activeId}.partial`)).size).toBe(4);
		expect(existsSync(join(target.incidentDir, "sysdig-pins", "initial-capture-complete.json"))).toBe(false);

		for (let pass = 0; pass < 8 && !existsSync(join(recordsDir, `${activeId}.json`)); pass += 1) {
			recovered.processPendingPins(anchor);
		}
		const activeRecord = JSON.parse(readFileSync(join(recordsDir, `${activeId}.json`), "utf8")) as Record<
			string,
			any
		>;
		expect(activeRecord.phase).toBe("initial");
		expect(readFileSync(activeRecord.pinnedPath, "utf8")).toBe("0123456789");
		expect(existsSync(join(target.incidentDir, "sysdig-pins", "initial-capture-complete.json"))).toBe(true);
	});

	it("keeps an open request-time active inode across rotation without hard-linking the live ring", async () => {
		const target = fixture();
		const anchor = Date.now();
		const active = `${target.ringBase}1`;
		writeSegment(active, "0123456789", anchor - 1_000);
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			sysdigPinWorkBytesPerPass: 4,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);
		const sourceBeforeCapture = statSync(active);
		compactor.requestPin(RUN_ID, target.incidentDir, anchor);
		const sourceAfterCapture = statSync(active);
		expect(sourceAfterCapture.nlink).toBe(1);
		expect(sourceAfterCapture.ctimeMs).toBe(sourceBeforeCapture.ctimeMs);
		const request = JSON.parse(readFileSync(join(target.incidentDir, "sysdig-pin-request.json"), "utf8")) as Record<
			string,
			any
		>;
		const activeId = request.initialRingSnapshot.candidates[0].id as string;
		const recordsDir = join(target.incidentDir, "sysdig-pins", "records");
		renameSync(active, `${target.ringBase}0`);
		writeSegment(active, "replacement", anchor + 1_000);

		for (let pass = 0; pass < 8 && !existsSync(join(recordsDir, `${activeId}.json`)); pass += 1) {
			compactor.processPendingPins(anchor);
		}

		const record = JSON.parse(readFileSync(join(recordsDir, `${activeId}.json`), "utf8")) as Record<string, any>;
		expect(readFileSync(record.pinnedPath, "utf8")).toBe("0123456789");
		expect(readFileSync(record.pinnedPath, "utf8")).not.toBe("replacement");
		expect(existsSync(join(target.incidentDir, "sysdig-pins", "sources"))).toBe(false);
	});

	it("rejects a rewritten active inode when a restarted copy's durable prefix no longer matches", async () => {
		const target = fixture();
		const anchor = Date.now();
		const active = `${target.ringBase}1`;
		writeSegment(active, "0123456789", anchor - 1_000);
		const first = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			sysdigPinWorkBytesPerPass: 4,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(first);
		first.requestPin(RUN_ID, target.incidentDir, anchor);
		const request = JSON.parse(readFileSync(join(target.incidentDir, "sysdig-pin-request.json"), "utf8")) as Record<
			string,
			any
		>;
		const activeId = request.initialRingSnapshot.candidates[0].id as string;
		writeSegment(active, "abcdefghij", anchor + 1_000);
		const recovered = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			sysdigPinWorkBytesPerPass: 4,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(recovered);

		recovered.processPendingPins(anchor);

		expect(existsSync(join(target.incidentDir, "sysdig-pins", "records", `${activeId}.json`))).toBe(false);
		const incomplete = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pin-incomplete.json"), "utf8"),
		) as Record<string, unknown>;
		expect(incomplete).toMatchObject({
			version: 1,
			state: "pending_or_incomplete",
			provider: "sysdig",
			runId: RUN_ID,
		});
		expect(incomplete.reason).toContain("sysdig_partial_prefix_mismatch");
	});

	it("converges a vanished request-time source to an explicit initial gap and canonical incomplete marker", async () => {
		const target = fixture();
		const anchor = Date.now();
		const active = `${target.ringBase}1`;
		writeSegment(active, "request-time-active", anchor - 1_000);
		const interrupted = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			onSysdigPinStep: (step) => {
				if (step === "provider_requests_durable") throw new Error("crash_before_initial_capture");
			},
		});
		await initializeStorageAccounting(interrupted);
		expect(() => interrupted.requestPin(RUN_ID, target.incidentDir, anchor)).toThrow("crash_before_initial_capture");
		rmSync(active);

		const recovered = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(recovered);
		recovered.processPendingPins(anchor);

		const marker = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pins", "initial-capture-complete.json"), "utf8"),
		) as Record<string, any>;
		expect(marker.outcome).toBe("incomplete");
		expect(marker.gaps).toEqual([
			expect.stringMatching(/^ring\.scap1:sysdig_planned_source_unavailable:ring\.scap1$/),
		]);
		const incomplete = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pin-incomplete.json"), "utf8"),
		) as Record<string, unknown>;
		expect(Object.keys(incomplete).sort()).toEqual(
			[
				"anchorWallTimeMs",
				"fromWallTimeMs",
				"provider",
				"reason",
				"runId",
				"state",
				"throughWallTimeMs",
				"version",
			].sort(),
		);
		expect(incomplete).toMatchObject({
			version: 1,
			state: "pending_or_incomplete",
			provider: "sysdig",
			runId: RUN_ID,
			anchorWallTimeMs: anchor,
		});
	});

	it("persists a fair pending-incident cursor so a later pin is reached after retained directories", async () => {
		const target = fixture();
		const anchor = Date.now();
		mkdirSync(join(target.agentDir, "incidents", "aaa-retained"), { recursive: true, mode: 0o700 });
		writeSegment(`${target.ringBase}1`, "active", anchor - 1_000);
		const requester = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			onSysdigPinStep: (step) => {
				if (step === "provider_requests_durable") throw new Error("leave_pending");
			},
		});
		await initializeStorageAccounting(requester);
		expect(() => requester.requestPin(RUN_ID, target.incidentDir, anchor)).toThrow("leave_pending");

		const firstPass = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			pendingPinDirectoryBatchCount: 1,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(firstPass);
		firstPass.processPendingPins(anchor);
		expect(existsSync(join(target.incidentDir, "sysdig-pins", "initial-capture-plan.json"))).toBe(false);

		const restarted = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			pendingPinDirectoryBatchCount: 1,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(restarted);
		restarted.processPendingPins(anchor);
		expect(existsSync(join(target.incidentDir, "sysdig-pins", "initial-capture-complete.json"))).toBe(true);
	});

	it("bounds the complete immutable Sysdig request to 64 KiB and records snapshot truncation", async () => {
		const target = fixture();
		const anchor = Date.now();
		for (let index = 0; index < 256; index += 1) {
			mkdirSync(`${target.ringBase}${index}-${"x".repeat(220)}`, { mode: 0o750 });
		}
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);

		compactor.requestPin(RUN_ID, target.incidentDir, anchor);

		const requestPath = join(target.incidentDir, "sysdig-pin-request.json");
		expect(statSync(requestPath).size).toBeLessThanOrEqual(64 * 1024);
		const request = JSON.parse(readFileSync(requestPath, "utf8")) as Record<string, any>;
		expect(request.initialRingSnapshot.issues).toContain("request_snapshot_byte_bound_exceeded");
	});

	it("truncates provider-incomplete reasons by UTF-8 bytes without producing an empty reason", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}1`, "active", anchor - 1_000);
		const requester = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			onSysdigPinStep: (step) => {
				if (step === "provider_requests_durable") throw new Error("leave_pending");
			},
		});
		await initializeStorageAccounting(requester);
		expect(() => requester.requestPin(RUN_ID, target.incidentDir, anchor)).toThrow("leave_pending");

		const recovered = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			onSysdigPinStep: (step) => {
				if (step === "initial_capture_complete") throw new Error("💥".repeat(4096));
			},
		});
		await initializeStorageAccounting(recovered);
		recovered.processPendingPins(anchor);

		const incomplete = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pin-incomplete.json"), "utf8"),
		) as Record<string, unknown>;
		expect(typeof incomplete.reason).toBe("string");
		expect((incomplete.reason as string).length).toBeGreaterThan(0);
		expect(Buffer.byteLength(incomplete.reason as string, "utf8")).toBeLessThanOrEqual(4 * 1024);
	});

	it("quarantines malformed and stale provider-incomplete markers before recreating request-bound evidence", async () => {
		const target = fixture();
		const anchor = Date.now();
		const malformedSysdig = "{\n";
		const staleJournal = `${JSON.stringify({
			version: 1,
			state: "pending_or_incomplete",
			provider: "journal",
			reason: "stale",
			runId: "stale-run",
			anchorWallTimeMs: anchor - 1,
			fromWallTimeMs: anchor - 2,
			throughWallTimeMs: anchor + 1,
		})}\n`;
		writeFileSync(join(target.incidentDir, "sysdig-pin-request.json"), "{\n", { mode: 0o600 });
		writeFileSync(join(target.incidentDir, "journal-pin-request.json"), "{\n", { mode: 0o600 });
		writeFileSync(join(target.incidentDir, "sysdig-pin-incomplete.json"), malformedSysdig, {
			mode: 0o600,
		});
		writeFileSync(join(target.incidentDir, "journal-pin-incomplete.json"), staleJournal, {
			mode: 0o600,
		});
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);

		compactor.requestPin(RUN_ID, target.incidentDir, anchor);

		for (const provider of ["journal", "sysdig"] as const) {
			const incomplete = JSON.parse(
				readFileSync(join(target.incidentDir, `${provider}-pin-incomplete.json`), "utf8"),
			) as Record<string, unknown>;
			expect(Object.keys(incomplete).sort()).toEqual(
				[
					"anchorWallTimeMs",
					"fromWallTimeMs",
					"provider",
					"reason",
					"runId",
					"state",
					"throughWallTimeMs",
					"version",
				].sort(),
			);
			expect(incomplete).toMatchObject({
				version: 1,
				state: "pending_or_incomplete",
				provider,
				runId: RUN_ID,
				anchorWallTimeMs: anchor,
				fromWallTimeMs: anchor - 30 * 60_000,
				throughWallTimeMs: anchor + 15 * 60_000,
			});
			expect(typeof incomplete.reason).toBe("string");
			expect((incomplete.reason as string).length).toBeGreaterThan(0);
		}
		const quarantined = readdirSync(join(target.incidentDir, "provider-incomplete-quarantine"));
		const sysdigQuarantine = quarantined.find((name) => name.startsWith("sysdig-"));
		const journalQuarantine = quarantined.find((name) => name.startsWith("journal-"));
		expect(sysdigQuarantine).toBeDefined();
		expect(journalQuarantine).toBeDefined();
		expect(readFileSync(join(target.incidentDir, "provider-incomplete-quarantine", sysdigQuarantine!), "utf8")).toBe(
			malformedSysdig,
		);
		expect(readFileSync(join(target.incidentDir, "provider-incomplete-quarantine", journalQuarantine!), "utf8")).toBe(
			staleJournal,
		);
	});

	it("quarantines a corrupt Sysdig request, recreates exact authority, and publishes canonical incomplete evidence", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}1`, "active", anchor - 1_000);
		writeFileSync(join(target.incidentDir, "sysdig-pin-request.json"), "{", { mode: 0o600 });
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);

		compactor.requestPin(RUN_ID, target.incidentDir, anchor);

		const request = JSON.parse(readFileSync(join(target.incidentDir, "sysdig-pin-request.json"), "utf8")) as Record<
			string,
			any
		>;
		const authority = JSON.parse(
			readFileSync(join(target.incidentDir, "incident-pin-authority.json"), "utf8"),
		) as Record<string, any>;
		expect(request).toEqual(authority);
		const quarantine = readdirSync(join(target.incidentDir, "provider-request-quarantine"));
		expect(quarantine.some((name) => /^sysdig-[0-9a-f]{64}\.json$/.test(name))).toBe(true);
		const incomplete = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pin-incomplete.json"), "utf8"),
		) as Record<string, unknown>;
		expect(Object.keys(incomplete).sort()).toEqual(
			[
				"anchorWallTimeMs",
				"fromWallTimeMs",
				"provider",
				"reason",
				"runId",
				"state",
				"throughWallTimeMs",
				"version",
			].sort(),
		);
		expect(incomplete).toMatchObject({
			version: 1,
			state: "pending_or_incomplete",
			provider: "sysdig",
			runId: RUN_ID,
			anchorWallTimeMs: anchor,
		});
		const marker = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pins", "initial-capture-complete.json"), "utf8"),
		) as Record<string, any>;
		expect(marker.outcome).toBe("complete");
	});

	it("quarantines a corrupt journal request and recreates it with canonical request-bound incomplete evidence", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}1`, "active", anchor - 1_000);
		writeFileSync(join(target.incidentDir, "journal-pin-request.json"), "{", { mode: 0o600 });
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);

		compactor.requestPin(RUN_ID, target.incidentDir, anchor);

		const request = JSON.parse(readFileSync(join(target.incidentDir, "journal-pin-request.json"), "utf8")) as Record<
			string,
			unknown
		>;
		expect(request).toMatchObject({
			version: 1,
			state: "pending",
			runId: RUN_ID,
			anchorWallTimeMs: anchor,
		});
		const quarantine = readdirSync(join(target.incidentDir, "provider-request-quarantine"));
		expect(quarantine.some((name) => /^journal-[0-9a-f]{64}\.json$/.test(name))).toBe(true);
		const incomplete = JSON.parse(
			readFileSync(join(target.incidentDir, "journal-pin-incomplete.json"), "utf8"),
		) as Record<string, unknown>;
		expect(Object.keys(incomplete).sort()).toEqual(
			[
				"anchorWallTimeMs",
				"fromWallTimeMs",
				"provider",
				"reason",
				"runId",
				"state",
				"throughWallTimeMs",
				"version",
			].sort(),
		);
		expect(incomplete).toMatchObject({
			version: 1,
			state: "pending_or_incomplete",
			provider: "journal",
			runId: RUN_ID,
			anchorWallTimeMs: anchor,
		});
	});

	it("uses durable incident pin authority to recover when both provider requests are corrupt after restart", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}1`, "active", anchor - 1_000);
		const requester = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
			onSysdigPinStep: (step) => {
				if (step === "provider_requests_durable") throw new Error("leave_both_requests_durable");
			},
		});
		await initializeStorageAccounting(requester);
		expect(() => requester.requestPin(RUN_ID, target.incidentDir, anchor)).toThrow("leave_both_requests_durable");
		expect(existsSync(join(target.incidentDir, "incident-pin-authority.json"))).toBe(true);
		writeFileSync(join(target.incidentDir, "sysdig-pin-request.json"), "{", { mode: 0o600 });
		writeFileSync(join(target.incidentDir, "journal-pin-request.json"), "{", { mode: 0o600 });

		const recovered = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(recovered);
		recovered.processPendingPins(anchor);

		const sysdigRequest = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pin-request.json"), "utf8"),
		) as Record<string, unknown>;
		const journalRequest = JSON.parse(
			readFileSync(join(target.incidentDir, "journal-pin-request.json"), "utf8"),
		) as Record<string, unknown>;
		expect(sysdigRequest).toMatchObject({ version: 1, runId: RUN_ID, anchorWallTimeMs: anchor });
		expect(journalRequest).toMatchObject({ version: 1, state: "pending", runId: RUN_ID, anchorWallTimeMs: anchor });
		const quarantine = readdirSync(join(target.incidentDir, "provider-request-quarantine"));
		expect(quarantine.some((name) => /^sysdig-[0-9a-f]{64}\.json$/.test(name))).toBe(true);
		expect(quarantine.some((name) => /^journal-[0-9a-f]{64}\.json$/.test(name))).toBe(true);
		for (const provider of ["sysdig", "journal"] as const) {
			const incomplete = JSON.parse(
				readFileSync(join(target.incidentDir, `${provider}-pin-incomplete.json`), "utf8"),
			) as Record<string, unknown>;
			expect(incomplete).toMatchObject({
				version: 1,
				state: "pending_or_incomplete",
				provider,
				runId: RUN_ID,
				anchorWallTimeMs: anchor,
			});
		}
	});

	it("materializes private exact copies for closed and active files without mutating the live ring", async () => {
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
		expect(closedRecord?.captureMethod).toBe("bounded_copy");
		expect(closedRecord?.captureReason).toBe("closed_segment_private_snapshot");
		expect(statSync(closedRecord.pinnedPath).ino).not.toBe(statSync(closed).ino);
		expect(activeRecord?.captureMethod).toBe("bounded_copy");
		expect(activeRecord?.captureReason).toBe("active_segment_snapshot");
		expect(statSync(activeRecord.pinnedPath).ino).not.toBe(statSync(active).ino);
		expect(statSync(closedRecord.pinnedPath).nlink).toBe(1);
		expect(statSync(activeRecord.pinnedPath).nlink).toBe(1);
		expect(statSync(closedRecord.pinnedPath).mode & 0o777).toBe(0o600);
		expect(statSync(activeRecord.pinnedPath).mode & 0o777).toBe(0o600);
		for (const record of [closedRecord, activeRecord]) {
			const artifact = statSync(record.pinnedPath);
			expect(record.artifactAtCapture).toEqual({
				dev: String(artifact.dev),
				ino: String(artifact.ino),
				bytes: artifact.size,
				mtimeMs: artifact.mtimeMs,
				ctimeMs: artifact.ctimeMs,
				mode: 0o600,
				nlink: 1,
			});
			expect(record.source.ctimeMs).toEqual(expect.any(Number));
		}
		if (typeof process.getuid === "function") {
			expect(statSync(closedRecord.pinnedPath).uid).toBe(process.getuid());
			expect(statSync(activeRecord.pinnedPath).uid).toBe(process.getuid());
		}
		expect(statSync(closed).mode & 0o777).toBe(0o640);
		expect(statSync(active).mode & 0o777).toBe(0o640);
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
		expect(manifest.artifactGenerationId).toMatch(/^[0-9a-f]{64}$/);
		const retentionProof = JSON.parse(
			readFileSync(join(target.incidentDir, "sysdig-pin-retention-proof.json"), "utf8"),
		) as Record<string, any>;
		expect(retentionProof).toMatchObject({
			state: "producer_verified_complete",
			provider: "sysdig",
			artifactGenerationId: manifest.artifactGenerationId,
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
			expect(Object.keys(segment.sealedArtifact).sort()).toEqual(
				[
					"version",
					"state",
					"generationId",
					"dev",
					"ino",
					"bytes",
					"mtimeMs",
					"ctimeMs",
					"mode",
					"nlink",
					"sha256",
				].sort(),
			);
			const artifact = statSync(segment.pinnedPath);
			const bytes = readFileSync(segment.pinnedPath);
			const beforeReplay = {
				ino: artifact.ino,
				ctimeMs: artifact.ctimeMs,
				mtimeMs: artifact.mtimeMs,
				bytes,
			};
			expect(segment.sealedArtifact).toMatchObject({
				version: 1,
				state: "sealed_private_copy",
				generationId: manifest.artifactGenerationId,
				dev: String(artifact.dev),
				ino: String(artifact.ino),
				bytes: bytes.length,
				mtimeMs: artifact.mtimeMs,
				ctimeMs: artifact.ctimeMs,
				mode: 0o400,
				nlink: 1,
				sha256: segment.exactBytes.sha256,
			});
			expect(segment.artifactAtCapture).toMatchObject({
				dev: segment.sealedArtifact.dev,
				ino: segment.sealedArtifact.ino,
				bytes: segment.exactBytes.bytes,
				mtimeMs: segment.sealedArtifact.mtimeMs,
				mode: 0o600,
				nlink: 1,
			});
			expect(artifact.mode & 0o777).toBe(0o400);
			compactor.processPendingPins(anchor + 15 * 60 * 1_000);
			const afterReplay = statSync(segment.pinnedPath);
			expect({
				ino: afterReplay.ino,
				ctimeMs: afterReplay.ctimeMs,
				mtimeMs: afterReplay.mtimeMs,
				bytes: readFileSync(segment.pinnedPath),
			}).toEqual(beforeReplay);
		}
		expect(manifest.coverage.gaps).toContain("scap_event_time_bounds_not_inspected_coverage_is_observation_based");
	});

	it("quarantines invalid provider proofs and reconstructs exact request-bound proofs after restart", async () => {
		const target = fixture();
		const anchor = Date.now();
		writeSegment(`${target.ringBase}0`, "proof-repair", anchor - 1_000);
		const first = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(first);
		first.requestPin(RUN_ID, target.incidentDir, anchor);
		const manifest = finalizeWithoutJournalScan(target, anchor, first);
		const pinnedPath = manifest.segments[0]?.pinnedPath as string | undefined;
		if (!pinnedPath) throw new Error("Expected a sealed Sysdig artifact before proof repair");
		const artifactBefore = statSync(pinnedPath);
		const artifactBytesBefore = readFileSync(pinnedPath);

		const sysdigProofPath = join(target.incidentDir, "sysdig-pin-retention-proof.json");
		const journalProofPath = join(target.incidentDir, "journal-pin-retention-proof.json");
		const expectedSysdigProof = JSON.parse(readFileSync(sysdigProofPath, "utf8")) as Record<string, unknown>;
		const expectedJournalProof = JSON.parse(readFileSync(journalProofPath, "utf8")) as Record<string, unknown>;
		const journalRequest = JSON.parse(
			readFileSync(join(target.incidentDir, "journal-pin-request.json"), "utf8"),
		) as Record<string, unknown>;
		writeFileSync(sysdigProofPath, '{"version":1,"state":"corrupt"}\n', { mode: 0o600 });
		writeFileSync(
			journalProofPath,
			`${JSON.stringify({
				version: 1,
				state: "producer_verified_complete",
				provider: "journal",
				manifestValidated: true,
				occurrenceReferencesResolved: true,
				runId: journalRequest.runId,
				fromWallTimeMs: journalRequest.fromWallTimeMs,
				throughWallTimeMs: journalRequest.throughWallTimeMs,
			})}\n`,
			{ mode: 0o600 },
		);

		const recovered = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			sysdigRingBasePath: target.ringBase,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(recovered);
		recovered.processPendingPins(anchor + 15 * 60 * 1_000);

		expect(JSON.parse(readFileSync(sysdigProofPath, "utf8"))).toEqual(expectedSysdigProof);
		expect(JSON.parse(readFileSync(journalProofPath, "utf8"))).toEqual(expectedJournalProof);
		const artifactAfter = statSync(pinnedPath);
		expect({
			ino: artifactAfter.ino,
			ctimeMs: artifactAfter.ctimeMs,
			mtimeMs: artifactAfter.mtimeMs,
			mode: artifactAfter.mode & 0o777,
			nlink: artifactAfter.nlink,
			bytes: readFileSync(pinnedPath),
		}).toEqual({
			ino: artifactBefore.ino,
			ctimeMs: artifactBefore.ctimeMs,
			mtimeMs: artifactBefore.mtimeMs,
			mode: 0o400,
			nlink: 1,
			bytes: artifactBytesBefore,
		});
		const quarantine = readdirSync(join(target.incidentDir, "provider-proof-quarantine"));
		expect(quarantine.some((name) => name.startsWith("sysdig-"))).toBe(true);
		expect(quarantine.some((name) => name.startsWith("journal-"))).toBe(true);
	});

	it("keeps a closed private snapshot stable when the live ring path is later rewritten", async () => {
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

		const closedSegment = manifest.segments.find(
			(segment: Record<string, any>) => segment.sourceName === "ring.scap0" && segment.phase === "initial",
		);
		const rewrittenSegment = manifest.segments.find(
			(segment: Record<string, any>) => segment.sourceName === "ring.scap0" && segment.phase === "final",
		);
		if (!closedSegment) throw new Error("Expected the closed private snapshot in the manifest");
		if (!rewrittenSegment) throw new Error("Expected the rewritten ring generation in the final capture");
		expect(readFileSync(closedSegment.pinnedPath, "utf8")).toBe("closed");
		expect(readFileSync(rewrittenSegment.pinnedPath, "utf8")).toBe("reused-inode");
		expect(rewrittenSegment.id).not.toBe(closedSegment.id);
		expect(statSync(rewrittenSegment.pinnedPath).ino).not.toBe(statSync(closedSegment.pinnedPath).ino);
		expect(closedSegment.changedAfterCapture).toBe(false);
		expect(
			manifest.coverage.gaps.some((gap: string) => gap.startsWith("hard_link_changed_after_capture:ring.scap0")),
		).toBe(false);
		expect(existsSync(join(target.incidentDir, "sysdig-pin-request.json"))).toBe(true);
	});
	it("accounts each incident's private Sysdig copy independently", async () => {
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
		expect(afterSecond - afterFirst).toBeGreaterThan(1024 * 1024);
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
		"keeps a cross-device closed segment private without publishing a live-source hard link",
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
				captureReason: "closed_segment_private_snapshot",
			});
			expect(statSync(closedRecord.pinnedPath).nlink).toBe(1);
			expect(statSync(closedRecord.pinnedPath).mode & 0o777).toBe(0o600);
			expect(readFileSync(closedRecord.pinnedPath, "utf8")).toBe("closed-cross-device");
		},
	);
});
