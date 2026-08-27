import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	existsSync,
	linkSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	INCIDENT_RETENTION_SERVICE_BUDGET,
	runIncidentRetentionPass,
} from "../src/modes/daemon/incident-recorder-retention.js";

const roots: string[] = [];
const DAY = 24 * 60 * 60 * 1_000;
const NOW = Date.parse("2026-08-25T12:00:00.000Z");

function fixture(): { root: string; agentDir: string; recorder: string; incidents: string } {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-retention-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const recorder = join(agentDir, "incident-recorder");
	const incidents = join(agentDir, "incidents");
	for (const path of [join(recorder, "runs"), join(recorder, "refs"), join(recorder, "cas", "sha256"), incidents]) {
		mkdirSync(path, { recursive: true, mode: 0o700 });
	}
	return { root, agentDir, recorder, incidents };
}

function json(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function old(path: string, ageMs = INCIDENT_DIAGNOSTIC_RETENTION_MS + 1): void {
	utimesSync(path, (NOW - ageMs) / 1_000, (NOW - ageMs) / 1_000);
}

function runPath(target: ReturnType<typeof fixture>, id = "11111111-1111-4111-8111-111111111111"): string {
	const path = join(target.recorder, "runs", `2026-08-01T00-00-00.000Z-${id}`);
	mkdirSync(path, { recursive: true, mode: 0o700 });
	return path;
}

function finalizedIncident(target: ReturnType<typeof fixture>, name: string, finalizedMs: number): string {
	const path = join(target.incidents, name);
	mkdirSync(path, { recursive: true, mode: 0o700 });
	json(join(path, "summary.json"), {
		stoppedTargetCaptureComplete: true,
		finalized: { wallTime: new Date(finalizedMs).toISOString(), monotonicNs: "1" },
	});
	return path;
}

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("three-day diagnostic retention", () => {
	it("uses a conservative explicit service cleanup budget", () => {
		expect(INCIDENT_RETENTION_SERVICE_BUDGET).toEqual({ maxEntries: 64, maxDeletes: 16 });
	});

	it("protects an old active run only with exact nonempty boot/PID/start identity", () => {
		const target = fixture();
		const path = runPath(target);
		json(join(path, ".recorder-active"), {
			role: "wrapper-proxy",
			machineId: "machine",
			bootId: "boot",
			pid: 4242,
			processStartId: "99",
		});
		old(path);
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
			processIdentity: (pid) => (pid === 4242 ? { state: "live", startId: "99" } : { state: "dead" }),
		});
		expect(existsSync(path)).toBe(true);
		expect(result.protectedActiveRuns).toEqual([expect.stringContaining("11111111-1111-4111-8111-111111111111")]);
	});

	it("does not remove a completed incident before three days or a pending +15m incident", () => {
		const target = fixture();
		const completed = finalizedIncident(target, "completed", NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS + 1);
		const pending = finalizedIncident(target, "pending", NOW - 4 * DAY);
		json(join(pending, "journal-pin-request.json"), {
			runId: "11111111-1111-4111-8111-111111111111",
			anchorWallTimeMs: NOW,
			fromWallTimeMs: NOW - 30 * 60 * 1_000,
			throughWallTimeMs: NOW + 15 * 60 * 1_000,
			resolveAfterWallTimeMs: NOW + 15 * 60 * 1_000,
			retainUntilWallTimeMs: NOW + INCIDENT_DIAGNOSTIC_RETENTION_MS,
		});
		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(completed)).toBe(true);
		expect(existsSync(pending)).toBe(true);
	});

	it("removes a finalized incident after three days", () => {
		const target = fixture();
		const path = finalizedIncident(target, "expired", NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS - 1);
		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(path)).toBe(false);
	});

	it("keeps referenced CAS and removes unreferenced old CAS and refs", () => {
		const target = fixture();
		const keptDigest = "a".repeat(64);
		const removedDigest = "b".repeat(64);
		const keptBlob = join(target.recorder, "cas", "sha256", "aa", `${keptDigest}.blob`);
		const removedBlob = join(target.recorder, "cas", "sha256", "bb", `${removedDigest}.blob`);
		for (const [path, value] of [
			[keptBlob, "kept"],
			[removedBlob, "removed"],
		] as const) {
			mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
			writeFileSync(path, value, { mode: 0o600 });
			old(path);
		}
		const occurrence = join(target.recorder, "refs", "occurrences", "sha256", "aa", `${"c".repeat(64)}.json`);
		json(occurrence, { state: "complete", cas: { digest: keptDigest, path: keptBlob, bytes: 4 } });
		old(occurrence, DAY);
		const expiredRef = join(target.recorder, "refs", "gaps", `${"d".repeat(64)}.json`);
		json(expiredRef, { state: "gap_or_uncertainty" });
		old(expiredRef);

		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(keptBlob)).toBe(true);
		expect(existsSync(removedBlob)).toBe(false);
		expect(existsSync(expiredRef)).toBe(false);
		expect(existsSync(occurrence)).toBe(true);
	});

	it("preserves a CAS blob pinned by a retained hard link", () => {
		const target = fixture();
		const digest = "e".repeat(64);
		const blob = join(target.recorder, "cas", "sha256", "ee", `${digest}.blob`);
		mkdirSync(dirname(blob), { recursive: true, mode: 0o700 });
		writeFileSync(blob, "pinned", { mode: 0o600 });
		old(blob);
		const incident = finalizedIncident(target, "retained-pin", NOW - DAY);
		const pin = join(incident, "journal-pins", "cas", `${digest}.blob`);
		mkdirSync(dirname(pin), { recursive: true, mode: 0o700 });
		linkSync(blob, pin);
		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(blob)).toBe(true);
		expect(statSync(blob).nlink).toBe(2);
	});

	it("fails closed when run identity metadata is uncertain", () => {
		const target = fixture();
		const path = runPath(target);
		writeFileSync(join(path, ".recorder-active"), "not-json", { mode: 0o600 });
		old(path);
		const digest = "f".repeat(64);
		const blob = join(target.recorder, "cas", "sha256", "ff", `${digest}.blob`);
		mkdirSync(dirname(blob), { recursive: true, mode: 0o700 });
		writeFileSync(blob, "uncertain", { mode: 0o600 });
		old(blob);
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(path)).toBe(true);
		expect(existsSync(blob)).toBe(true);
		expect(result.uncertainties).toContain(`run-identity:${path}`);
	});

	it("bounds deletion work and makes progress over repeated passes", () => {
		const target = fixture();
		const paths = Array.from({ length: 4 }, (_value, index) =>
			finalizedIncident(target, `expired-${index}`, NOW - 4 * DAY),
		);
		let previous = paths.length;
		for (let pass = 0; pass < 8 && previous > 0; pass += 1) {
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxDeletes: 2,
				maxEntries: 128,
				machineId: "machine",
				bootId: "boot",
			});
			expect(result.deletedEntries).toBeLessThanOrEqual(2);
			const remaining = paths.filter((path) => existsSync(path)).length;
			expect(remaining).toBeLessThan(previous);
			previous = remaining;
		}
		expect(previous).toBe(0);
		expect(readdirSync(target.incidents).filter((name) => !name.startsWith(".retention-gc-"))).toHaveLength(0);
	});

	it("resumes directory discovery when a scan batch ends before expired entries", () => {
		const target = fixture();
		for (let index = 0; index < 4; index += 1) finalizedIncident(target, `fresh-${index}`, NOW - DAY);
		const expired = Array.from({ length: 3 }, (_value, index) =>
			finalizedIncident(target, `late-expired-${index}`, NOW - 4 * DAY),
		);
		for (let pass = 0; pass < 12 && expired.some((path) => existsSync(path)); pass += 1) {
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxDeletes: 4,
				maxEntries: 3,
				machineId: "machine",
				bootId: "boot",
			});
			expect(result.scannedEntries).toBeLessThanOrEqual(3);
		}
		expect(expired.every((path) => !existsSync(path))).toBe(true);
		for (let index = 0; index < 4; index += 1)
			expect(existsSync(join(target.incidents, `fresh-${index}`))).toBe(true);
	});

	it("matches the production proc:<start-ticks> identity format", () => {
		const target = fixture();
		const path = runPath(target, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
		const processStartId = getProcessStartId(process.pid);
		expect(processStartId).toMatch(/^proc:[0-9]+$/);
		json(join(path, ".recorder-active"), {
			role: "wrapper-proxy",
			machineId: readFileSync("/etc/machine-id", "utf8").trim(),
			bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
			pid: process.pid,
			processStartId,
		});
		old(path);
		const result = runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW });
		expect(existsSync(path)).toBe(true);
		expect(result.protectedActiveRuns.some((name) => name.includes("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))).toBe(
			true,
		);
	});

	it("retains an abnormal terminal run until service finalization completes", () => {
		const target = fixture();
		const path = runPath(target, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
		json(join(path, ".retention-terminal.json"), {
			completed: { wallTime: new Date(NOW - 4 * DAY).toISOString(), monotonicNs: "1" },
			exitCode: 1,
			exitSignal: null,
		});
		old(path, 4 * DAY);
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(path)).toBe(true);
		expect(result.uncertainties).toContain(`run-identity:${path}`);
	});

	it("uses the new three-day expiry for a valid legacy 14-day Sysdig manifest", () => {
		const target = fixture();
		const anchor = NOW - 4 * DAY;
		const path = finalizedIncident(target, "legacy-sysdig", anchor);
		json(join(path, "sysdig-pin-request.json"), {
			runId: "11111111-1111-4111-8111-111111111111",
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
			retainUntilWallTimeMs: anchor + 14 * DAY,
		});
		json(join(path, "sysdig-pin-manifest.json"), {
			state: "finalized_with_observed_coverage",
			runId: "11111111-1111-4111-8111-111111111111",
			retention: { milliseconds: 14 * DAY, retainUntilWallTimeMs: anchor + 14 * DAY },
			segments: [],
		});
		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(path)).toBe(false);
	});

	it("keeps active-run refs protected throughout a multi-pass run scan", () => {
		const target = fixture();
		const activeId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
		for (const id of ["dddddddd-dddd-4ddd-8ddd-dddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]) {
			const path = runPath(target, id);
			json(join(path, ".retention-terminal.json"), {
				completed: { wallTime: new Date(NOW - DAY).toISOString() },
				exitCode: 0,
				exitSignal: null,
			});
		}
		const active = runPath(target, activeId);
		json(join(active, ".recorder-active"), {
			role: "wrapper-proxy",
			machineId: "machine",
			bootId: "boot",
			pid: 1234,
			processStartId: "proc:88",
		});
		old(active, 4 * DAY);
		const runHash = createHash("sha256").update(activeId).digest("hex");
		const ref = join(target.recorder, "refs", "runs", runHash, "seq-old.json");
		json(ref, { runId: activeId, cas: { digest: "a".repeat(64) } });
		old(ref, 4 * DAY);
		for (let pass = 0; pass < 8; pass += 1) {
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 2,
				maxDeletes: 2,
				machineId: "machine",
				bootId: "boot",
				processIdentity: (pid) => (pid === 1234 ? { state: "live", startId: "proc:88" } : { state: "dead" }),
			});
			expect(existsSync(ref)).toBe(true);
		}
	});

	it("sweeps an old unreferenced CAS while an exact-active run protects its referenced CAS", () => {
		const target = fixture();
		const run = runPath(target, "12121212-1212-4212-8212-121212121212");
		json(join(run, ".recorder-active"), {
			role: "wrapper-proxy",
			machineId: "machine",
			bootId: "boot",
			pid: 777,
			processStartId: "proc:7",
		});
		const keptDigest = "1".repeat(64);
		const removedDigest = "2".repeat(64);
		const kept = join(target.recorder, "cas", "sha256", "11", `${keptDigest}.blob`);
		const removed = join(target.recorder, "cas", "sha256", "22", `${removedDigest}.blob`);
		for (const path of [kept, removed]) {
			mkdirSync(dirname(path), { recursive: true });
			writeFileSync(path, path === kept ? "kept" : "removed");
			old(path, 4 * DAY);
		}
		const legacyReference = join(run, "legacy-reference.json");
		json(legacyReference, { cas: { digest: keptDigest, path: kept, bytes: 4 } });
		old(legacyReference, DAY);
		for (let pass = 0; pass < 8 && existsSync(removed); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
				processIdentity: (pid) => (pid === 777 ? { state: "live", startId: "proc:7" } : { state: "dead" }),
			});
		expect(existsSync(kept)).toBe(true);
		expect(existsSync(removed)).toBe(false);
	});

	it("fails closed behind a live cross-process CAS owner, then commits canonical path plus lease after release", async () => {
		const target = fixture();
		const owner = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { stdio: "ignore" });
		const pid = owner.pid;
		expect(pid).toBeTypeOf("number");
		const startId = pid ? getProcessStartId(pid) : undefined;
		expect(startId).toMatch(/^proc:/);
		const lock = join(target.recorder, ".cas-transaction");
		mkdirSync(lock, { recursive: true, mode: 0o700 });
		json(join(lock, "owner.json"), {
			version: 1,
			machineId: readFileSync("/etc/machine-id", "utf8").trim(),
			bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
			pid,
			processStartId: startId,
		});
		const source = join(target.root, "stopped.bin");
		writeFileSync(source, "transactional-bytes", { mode: 0o600 });
		const runId = "92929292-9292-4292-8292-929292929292";
		const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		try {
			let admission = compactor.streamStoppedTargetArtifact(runId, source, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 1024,
			});
			if (admission.state === "pending" && admission.reason === "work_budget")
				admission = compactor.streamStoppedTargetArtifact(runId, source, "binary", {
					deadlineMs: Date.now() + 1_000,
					byteBudget: 1024,
				});
			expect(admission).toMatchObject({ state: "pending", reason: "cas_transaction_busy" });
			expect(readdirSync(join(target.recorder, "cas", "sha256", "staging"))).toHaveLength(1);
		} finally {
			if (pid && startId && getProcessStartId(pid) === startId) process.kill(pid, "SIGKILL");
			await new Promise<void>((resolve) => owner.once("close", () => resolve()));
		}
		const completed = compactor.streamStoppedTargetArtifact(runId, source, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1024,
		});
		expect(completed.state).toBe("complete");
		if (completed.state !== "complete") return;
		expect(existsSync(completed.artifact.path)).toBe(true);
		const lease = join(
			target.recorder,
			"refs",
			"runs",
			createHash("sha256").update(runId).digest("hex"),
			`cas-${completed.artifact.digest}.blob`,
		);
		expect(statSync(lease).ino).toBe(statSync(completed.artifact.path).ino);
	});

	it("never follows a CAS shard symlink to delete an outside victim", () => {
		const target = fixture();
		const outside = join(target.root, "outside");
		mkdirSync(outside, { mode: 0o700 });
		const victim = join(outside, `${"d".repeat(64)}.blob`);
		writeFileSync(victim, "victim", { mode: 0o600 });
		old(victim, 4 * DAY);
		symlinkSync(outside, join(target.recorder, "cas", "sha256", "malicious-shard"));
		for (let pass = 0; pass < 8; pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(readFileSync(victim, "utf8")).toBe("victim");
	});

	it("does not follow a fixed persisted-mark temp symlink", () => {
		const target = fixture();
		const victim = join(target.root, "mark-victim");
		writeFileSync(victim, "safe", { mode: 0o600 });
		const retentionDir = join(target.recorder, "retention");
		mkdirSync(retentionDir, { recursive: true, mode: 0o700 });
		symlinkSync(victim, join(retentionDir, "legacy-marks-v1.log.tmp"));
		runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		expect(readFileSync(victim, "utf8")).toBe("safe");
	});

	it("rejects an EEXIST lease symlink instead of accepting its target contents", () => {
		const target = fixture();
		const source = join(target.root, "lease-source.bin");
		writeFileSync(source, "lease-source", { mode: 0o600 });
		const digest = createHash("sha256").update("lease-source").digest("hex");
		const runId = "94949494-9494-4494-8494-949494949494";
		const owner = join(target.recorder, "refs", "runs", createHash("sha256").update(runId).digest("hex"));
		mkdirSync(owner, { recursive: true, mode: 0o700 });
		const victim = join(target.root, "lease-victim");
		writeFileSync(victim, "lease-source", { mode: 0o600 });
		symlinkSync(victim, join(owner, `cas-${digest}.blob`));
		const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		const result = compactor.streamStoppedTargetArtifact(runId, source, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1024,
		});
		expect(result.state).toBe("error");
		expect(readFileSync(victim, "utf8")).toBe("lease-source");
	});

	it("rejects a stopped artifact changed in already-read bytes even when size and mtime are restored", () => {
		const target = fixture();
		const source = join(target.root, "mutable.bin");
		writeFileSync(source, "abcdefgh", { mode: 0o600 });
		const original = statSync(source);
		const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		const first = compactor.streamStoppedTargetArtifact("93939393-9393-4393-8393-939393939393", source, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 4,
		});
		expect(first).toMatchObject({ state: "pending", copiedBytes: 4 });
		writeFileSync(source, "WXYZefgh", { mode: 0o600 });
		utimesSync(source, original.atime, original.mtime);
		const second = compactor.streamStoppedTargetArtifact("93939393-9393-4393-8393-939393939393", source, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 64,
		});
		expect(second).toMatchObject({ state: "error", reason: "artifact_source_changed_during_capture" });
	});

	it("skips more than 65,536 post-boundary leased refs while marking only legacy path refs", () => {
		const target = fixture();
		// Establish the durable lease-protocol boundary before current-protocol refs.
		runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		const leasedDigest = createHash("sha256").update("leased").digest("hex");
		const leasedBlob = join(target.recorder, "cas", "sha256", leasedDigest.slice(0, 2), `${leasedDigest}.blob`);
		mkdirSync(dirname(leasedBlob), { recursive: true, mode: 0o700 });
		writeFileSync(leasedBlob, "leased", { mode: 0o600 });
		const owner = join(target.recorder, "refs", "runs", "c".repeat(64));
		mkdirSync(owner, { recursive: true, mode: 0o700 });
		linkSync(leasedBlob, join(owner, `cas-${leasedDigest}.blob`));
		const bulk = join(target.recorder, "refs", "occurrences", "post-boundary-bulk");
		mkdirSync(bulk, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 65_537; index += 1) {
			const token = index.toString(16).padStart(64, "0");
			writeFileSync(join(bulk, `${index}.json`), `{"cas":{"digest":"${token}"}}\n`, { mode: 0o600 });
		}
		const legacyDigest = "a".repeat(64);
		const legacyBlob = join(target.recorder, "cas", "sha256", "aa", `${legacyDigest}.blob`);
		mkdirSync(dirname(legacyBlob), { recursive: true, mode: 0o700 });
		writeFileSync(legacyBlob, "legacy", { mode: 0o600 });
		old(legacyBlob, 4 * DAY);
		const legacyRef = join(target.recorder, "refs", "legacy-path.json");
		json(legacyRef, { cas: { digest: legacyDigest, path: legacyBlob } });
		old(legacyRef, DAY);
		const unreferencedDigest = "b".repeat(64);
		const unreferenced = join(target.recorder, "cas", "sha256", "bb", `${unreferencedDigest}.blob`);
		mkdirSync(dirname(unreferenced), { recursive: true, mode: 0o700 });
		writeFileSync(unreferenced, "old", { mode: 0o600 });
		old(unreferenced, 4 * DAY);
		let lastResult: ReturnType<typeof runIncidentRetentionPass> | undefined;
		for (let pass = 0; pass < 6_000 && existsSync(unreferenced); pass += 1)
			lastResult = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(existsSync(unreferenced)).toBe(false);
		expect(existsSync(legacyBlob)).toBe(true);
		expect(existsSync(leasedBlob)).toBe(true);
	});

	it("resumes past 100 empty ref and CAS shards and converges on late entries", () => {
		const target = fixture();
		for (let index = 0; index < 100; index += 1) {
			const retainedShard = join(target.recorder, "refs", "plateau", String(index).padStart(3, "0"));
			mkdirSync(retainedShard, { recursive: true });
			json(join(retainedShard, "retained.json"), { state: "retained-prefix" });
			mkdirSync(join(target.recorder, "cas", "sha256", `empty-${String(index).padStart(3, "0")}`), {
				recursive: true,
			});
		}
		const lateRef = join(target.recorder, "refs", "plateau", "zzz", "late.json");
		json(lateRef, { state: "expired" });
		old(lateRef, 4 * DAY);
		const digest = "3".repeat(64);
		const lateBlob = join(target.recorder, "cas", "sha256", "zz", `${digest}.blob`);
		mkdirSync(dirname(lateBlob), { recursive: true });
		writeFileSync(lateBlob, "late");
		old(lateBlob, 4 * DAY);
		for (let pass = 0; pass < 20 && (existsSync(lateRef) || existsSync(lateBlob)); pass += 1) {
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
			expect(result.scannedEntries).toBeLessThanOrEqual(64);
		}
		expect(existsSync(lateRef)).toBe(false);
		expect(existsSync(lateBlob)).toBe(false);
	});

	it("finishes a late mark across budget passes before sweeping", () => {
		const target = fixture();
		for (let index = 0; index < 100; index += 1)
			mkdirSync(join(target.recorder, "refs", "occurrences", String(index).padStart(3, "0")), { recursive: true });
		const keptDigest = "4".repeat(64);
		const removedDigest = "5".repeat(64);
		const kept = join(target.recorder, "cas", "sha256", "44", `${keptDigest}.blob`);
		const removed = join(target.recorder, "cas", "sha256", "55", `${removedDigest}.blob`);
		for (const path of [kept, removed]) {
			mkdirSync(dirname(path), { recursive: true });
			writeFileSync(path, path === kept ? "kept" : "gone");
			old(path, 4 * DAY);
		}
		const lateReference = join(target.recorder, "refs", "occurrences", "zzz", "late.json");
		json(lateReference, { cas: { digest: keptDigest, path: kept, bytes: 4 } });
		old(lateReference, DAY);
		for (let pass = 0; pass < 24 && existsSync(removed); pass += 1) {
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(kept)).toBe(true);
		}
		expect(existsSync(removed)).toBe(false);
		expect(existsSync(kept)).toBe(true);
	});

	it("keeps a durable incomplete pin local while unrelated cleanup progresses", () => {
		const target = fixture();
		const anchor = NOW - 2 * DAY;
		const incident = finalizedIncident(target, "locally-incomplete", anchor);
		json(join(incident, "journal-pin-request.json"), {
			runId: "67676767-6767-4767-8767-676767676767",
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
			retainUntilWallTimeMs: anchor + 3 * DAY,
		});
		json(join(incident, "journal-pin-incomplete.json"), {
			state: "pending_or_incomplete",
			reason: "storage_paused",
			runId: "67676767-6767-4767-8767-676767676767",
		});
		const ref = join(target.recorder, "refs", "gaps", "unrelated.json");
		json(ref, { state: "old" });
		old(ref, 4 * DAY);
		const digest = "6".repeat(64);
		const blob = join(target.recorder, "cas", "sha256", "66", `${digest}.blob`);
		mkdirSync(dirname(blob), { recursive: true });
		writeFileSync(blob, "old");
		old(blob, 4 * DAY);
		for (let pass = 0; pass < 10 && (existsSync(ref) || existsSync(blob)); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(existsSync(incident)).toBe(true);
		expect(existsSync(ref)).toBe(false);
		expect(existsSync(blob)).toBe(false);
	});

	it("expires durable incomplete and permanently missing pins after the effective three days", () => {
		for (const state of ["incomplete", "missing"] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const incident = finalizedIncident(target, `expired-${state}-pin`, anchor);
			json(join(incident, "journal-pin-request.json"), {
				runId: "89898989-8989-4989-8989-898989898989",
				anchorWallTimeMs: anchor,
				fromWallTimeMs: anchor - 30 * 60 * 1_000,
				throughWallTimeMs: anchor + 15 * 60 * 1_000,
				resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
				retainUntilWallTimeMs: anchor + 3 * DAY,
			});
			if (state === "incomplete")
				json(join(incident, "journal-pin-incomplete.json"), {
					state: "pending_or_incomplete",
					reason: "storage_paused",
					runId: "89898989-8989-4989-8989-898989898989",
				});
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident)).toBe(false);
		}
	});

	it("prunes an expired run owner lease by owner-directory age, not renewed CAS inode mtime", () => {
		const target = fixture();
		const digest = "7".repeat(64);
		const blob = join(target.recorder, "cas", "sha256", "77", `${digest}.blob`);
		mkdirSync(dirname(blob), { recursive: true });
		writeFileSync(blob, "recurring");
		const owners = join(target.recorder, "refs", "runs");
		const oldOwner = join(owners, "a".repeat(64));
		const newerOwner = join(owners, "b".repeat(64));
		mkdirSync(oldOwner, { recursive: true });
		linkSync(blob, join(oldOwner, `cas-${digest}.blob`));
		old(oldOwner, 4 * DAY);
		// A newer exact duplicate renews the shared inode, including the old hard link.
		utimesSync(blob, (NOW - DAY) / 1_000, (NOW - DAY) / 1_000);
		mkdirSync(newerOwner, { recursive: true });
		linkSync(blob, join(newerOwner, `cas-${digest}.blob`));
		for (let pass = 0; pass < 8 && existsSync(oldOwner); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(existsSync(oldOwner)).toBe(false);
		expect(existsSync(blob)).toBe(true);
		// End the newer owner's lifecycle, then allow its own three-day window to pass.
		old(newerOwner, 4 * DAY);
		for (let pass = 0; pass < 16 && existsSync(blob); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW + 4 * DAY,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(existsSync(newerOwner)).toBe(false);
		expect(existsSync(blob)).toBe(false);
	});

	it("resumably backfills a proof for a proofless producer manifest larger than one MiB", () => {
		const target = fixture();
		const anchor = NOW - DAY;
		const incident = finalizedIncident(target, "proofless-large-manifest", anchor);
		const runId = "90909090-9090-4090-8090-909090909090";
		json(join(incident, "journal-pin-request.json"), {
			version: 1,
			state: "pending",
			runId,
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
			retainUntilWallTimeMs: anchor + 3 * DAY,
		});
		const pinDirectory = join(incident, "journal-pins", "cas");
		mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
		const digest = createHash("sha256").update("x").digest("hex");
		const globalPath = join(target.recorder, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
		mkdirSync(dirname(globalPath), { recursive: true, mode: 0o700 });
		writeFileSync(globalPath, "x", { mode: 0o600 });
		const pinnedPath = join(pinDirectory, `${digest}.blob`);
		linkSync(globalPath, pinnedPath);
		const occurrences = Array.from({ length: 8192 }, (_value, index) => ({
			occurrenceReference: `${join(target.recorder, "refs")}/private-${index}`,
			cursors: [`cursor-${index}`],
			cas: { digest, bytes: 1, path: globalPath },
			eventWallTimeMs: String(anchor),
			pinnedCasPath: pinnedPath,
		}));
		writeFileSync(
			join(incident, "journal-pin-manifest.json"),
			JSON.stringify({
				version: 1,
				state: "complete_through_requested_window",
				runId,
				fromWallTimeMs: anchor - 30 * 60 * 1_000,
				throughWallTimeMs: anchor + 15 * 60 * 1_000,
				occurrences,
			}),
			{ mode: 0o600 },
		);
		expect(statSync(join(incident, "journal-pin-manifest.json")).size).toBeGreaterThan(1024 * 1024);
		const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		try {
			for (let pass = 0; pass < 400 && !existsSync(join(incident, "journal-pin-retention-proof.json")); pass += 1)
				compactor.processPendingPins(NOW);
			const proof = JSON.parse(readFileSync(join(incident, "journal-pin-retention-proof.json"), "utf8")) as Record<
				string,
				unknown
			>;
			expect(proof).toMatchObject({ state: "producer_verified_complete", occurrenceCount: 8192, runId });
		} finally {
			compactor.dispose();
		}
	});

	it("rejects proofless manifests that are truncated or have missing, wrong-content, or wrong-path pins", () => {
		for (const variant of ["truncated", "missing", "wrong-digest", "wrong-path"] as const) {
			const target = fixture();
			const anchor = NOW - DAY;
			const incident = finalizedIncident(target, `invalid-proofless-${variant}`, anchor);
			const runId = "91919191-9191-4191-8191-919191919191";
			json(join(incident, "journal-pin-request.json"), {
				version: 1,
				state: "pending",
				runId,
				anchorWallTimeMs: anchor,
				fromWallTimeMs: anchor - 30 * 60 * 1_000,
				throughWallTimeMs: anchor + 15 * 60 * 1_000,
				resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
				retainUntilWallTimeMs: anchor + 3 * DAY,
			});
			const digest = variant === "wrong-digest" ? "0".repeat(64) : createHash("sha256").update("x").digest("hex");
			const globalPath = join(target.recorder, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
			mkdirSync(dirname(globalPath), { recursive: true, mode: 0o700 });
			writeFileSync(globalPath, "x", { mode: 0o600 });
			const pinDirectory = join(incident, "journal-pins", "cas");
			mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
			const expectedPinnedPath = join(pinDirectory, `${digest}.blob`);
			if (variant !== "missing") linkSync(globalPath, expectedPinnedPath);
			const occurrence = {
				occurrenceReference: `${join(target.recorder, "refs")}/invalid`,
				cursors: ["cursor"],
				cas: { digest, bytes: 1, path: globalPath },
				eventWallTimeMs: String(anchor),
				pinnedCasPath: variant === "wrong-path" ? join(incident, "outside-pin.blob") : expectedPinnedPath,
			};
			const manifestPath = join(incident, "journal-pin-manifest.json");
			if (variant === "truncated")
				writeFileSync(
					manifestPath,
					`{"version":1,"state":"complete_through_requested_window","runId":"${runId}","fromWallTimeMs":${anchor - 30 * 60 * 1_000},"throughWallTimeMs":${anchor + 15 * 60 * 1_000},"occurrences":[`,
					{ mode: 0o600 },
				);
			else
				writeFileSync(
					manifestPath,
					JSON.stringify({
						version: 1,
						state: "complete_through_requested_window",
						runId,
						fromWallTimeMs: anchor - 30 * 60 * 1_000,
						throughWallTimeMs: anchor + 15 * 60 * 1_000,
						occurrences: [occurrence],
					}),
					{ mode: 0o600 },
				);
			const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
			for (let pass = 0; pass < 40 && !existsSync(join(incident, "journal-pin-manifest-invalid.json")); pass += 1)
				compactor.processPendingPins(NOW);
			expect(existsSync(join(incident, "journal-pin-retention-proof.json"))).toBe(false);
			expect(existsSync(join(incident, "journal-pin-manifest-invalid.json"))).toBe(true);
		}
	});

	it("uses a small producer proof instead of synchronously validating an 8 MiB journal manifest", () => {
		const target = fixture();
		const anchor = NOW - 4 * DAY;
		const incident = finalizedIncident(target, "large-proven-manifest", anchor);
		json(join(incident, "journal-pin-request.json"), {
			runId: "78787878-7878-4787-8787-787878787878",
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
			retainUntilWallTimeMs: anchor + 3 * DAY,
		});
		const manifestPath = join(incident, "journal-pin-manifest.json");
		writeFileSync(
			manifestPath,
			JSON.stringify({ state: "complete_through_requested_window", padding: "x".repeat(1024 * 1024 + 1) }),
			{ mode: 0o600 },
		);
		const pinDirectory = join(incident, "journal-pins", "cas");
		mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
		const manifestStat = statSync(manifestPath);
		const pinStat = statSync(pinDirectory);
		json(join(incident, "journal-pin-retention-proof.json"), {
			version: 1,
			state: "producer_verified_complete",
			provider: "journal",
			manifestValidated: true,
			runId: "78787878-7878-4787-8787-787878787878",
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			retainUntilWallTimeMs: anchor + 3 * DAY,
			retentionMilliseconds: 3 * DAY,
			occurrenceCount: 8192,
			manifestIdentity: {
				dev: String(manifestStat.dev),
				ino: String(manifestStat.ino),
				size: manifestStat.size,
				mtimeMs: manifestStat.mtimeMs,
				ctimeMs: manifestStat.ctimeMs,
				nlink: manifestStat.nlink,
			},
			pinDirectoryIdentity: {
				path: "journal-pins/cas",
				dev: String(pinStat.dev),
				ino: String(pinStat.ino),
				mtimeMs: pinStat.mtimeMs,
				ctimeMs: pinStat.ctimeMs,
			},
		});
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		expect(result.scannedEntries).toBeLessThanOrEqual(64);
		expect(existsSync(incident)).toBe(false);
	});
});
