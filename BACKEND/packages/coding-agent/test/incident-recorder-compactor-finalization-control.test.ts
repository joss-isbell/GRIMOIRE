import { createHash } from "node:crypto";
import { linkSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
	IncidentCasRelativePath,
	IncidentCasRootMutation,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	acquireIncidentRecorderWriterRecoveryLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const RUN_ID = "f1010101-0101-4101-8101-010101010101";
const RUN_TOKEN = "f2020202-0202-4202-8202-020202020202";
const RUN_NAME = `2026-08-31T00-00-00.000Z-${RUN_ID}`;
const NOW = 0;

const cleanupRoots: string[] = [];

afterEach(() => {
	vi.restoreAllMocks();
	for (const root of cleanupRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

interface Fixture {
	root: string;
	agentDir: string;
	recorderRoot: string;
	runsRoot: string;
	runDirectory: string;
	lease?: IncidentRecorderWriterLifecycleLease;
}

interface BarrierDeadlineInput {
	runDirectory: string;
	runId: string;
	runToken: string;
	nowMs: number;
}

interface BarrierDeadlineAvailable {
	state: "available";
	elapsed: boolean;
	retryThroughWallTimeMs: number;
}

interface BarrierDeadlineUnavailable {
	state: "unavailable";
	reason: string;
}

type BarrierDeadlineResult = BarrierDeadlineAvailable | BarrierDeadlineUnavailable;

interface BarrierDeadlineCompactor {
	ensureServiceFinalizationBarrierDeadline?: (input: BarrierDeadlineInput) => BarrierDeadlineResult;
}

interface CompactorRootInternals {
	withRecorderRoot<T>(
		operation: (root: IncidentCasRootMutation, assertCurrent: () => void) => T,
	): { state: "committed"; value: T } | { state: "unavailable"; reason: string };
	releaseReservedCapacity(bytes: number, entries: number, inodes: number): void;
}

const lifecycleContract: IncidentRecorderWriterLifecycleAdmissionContract = {
	activationGenerationDigest: "a".repeat(64),
	revalidateActivation: () => ({ state: "valid" }),
	acquireCas: acquireIncidentRecorderNamespaceCas,
};

function fixture(): Fixture {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-compactor-finalization-control-"));
	cleanupRoots.push(root);
	const agentDir = join(root, "agent");
	const recorderRoot = join(agentDir, "incident-recorder");
	const runsRoot = join(recorderRoot, "runs");
	mkdirSync(runsRoot, { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { recursive: true, mode: 0o700 });
	const runDirectory = join(runsRoot, RUN_NAME);
	mkdirSync(runDirectory, { recursive: true, mode: 0o700 });
	return { root, agentDir, recorderRoot, runsRoot, runDirectory };
}

function acquireNormal(f: Fixture): IncidentRecorderWriterLifecycleLease {
	const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, lifecycleContract);
	if (result.state !== "acquired") throw new Error(`normal lease unavailable: ${result.reason}`);
	f.lease = result.lease;
	return result.lease;
}

function compactor(f: Fixture, lease?: IncidentRecorderWriterLifecycleLease, options: Record<string, unknown> = {}) {
	return new IncidentRecorderCompactor({
		agentDir: f.agentDir,
		freeReserveBytes: 0,
		storageScannerPath: "find",
		writerLifecycleLease: lease ? () => lease : undefined,
		...options,
	});
}

async function readyStorage(value: IncidentRecorderCompactor): Promise<void> {
	await value.initializeStorageAccounting(new AbortController().signal);
}

function callBarrier(value: IncidentRecorderCompactor, input: BarrierDeadlineInput): BarrierDeadlineResult {
	const method = (value as unknown as BarrierDeadlineCompactor).ensureServiceFinalizationBarrierDeadline;
	if (typeof method !== "function") throw new Error("ensureServiceFinalizationBarrierDeadline is not implemented");
	return method.call(value, input);
}

function deadlinePath(f: Fixture): string {
	return join(
		f.runDirectory,
		`service-finalization-barrier-deadline-${createHash("sha256").update(`${RUN_ID}\0${RUN_TOKEN}`).digest("hex")}.json`,
	);
}

function quarantineNames(f: Fixture): string[] {
	return readdirSync(join(f.runDirectory, ".service-control-quarantine")).sort();
}

describe("incident recorder compactor service finalization barrier control", () => {
	it("writes the canonical deadline once, preserves it, and reports elapsed only at the retry boundary", async () => {
		const f = fixture();
		const lease = acquireNormal(f);
		const value = compactor(f, lease);
		await readyStorage(value);

		expect(
			callBarrier(value, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toEqual({
			state: "available",
			elapsed: false,
			retryThroughWallTimeMs: 60_000,
		});
		const firstBytes = readFileSync(deadlinePath(f), "utf8");
		expect(JSON.parse(firstBytes)).toEqual({
			schemaVersion: 1,
			kind: "service_finalization_barrier_deadline",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			createdWallTimeMs: 0,
			retryThroughWallTimeMs: 60_000,
		});
		const fresh = compactor(f);
		await readyStorage(fresh);
		expect(value.accountedStorageBytes).toBe(fresh.accountedStorageBytes);
		expect(
			callBarrier(value, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: 59_999 }),
		).toEqual({
			state: "available",
			elapsed: false,
			retryThroughWallTimeMs: 60_000,
		});
		expect(readFileSync(deadlinePath(f), "utf8")).toBe(firstBytes);
		expect(
			callBarrier(value, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: 60_000 }),
		).toEqual({
			state: "available",
			elapsed: true,
			retryThroughWallTimeMs: 60_000,
		});
		expect(readFileSync(deadlinePath(f), "utf8")).toBe(firstBytes);
		f.lease?.release();
	});

	it("reconciles a valid nlink-two deadline residue without resetting its original deadline", async () => {
		const f = fixture();
		const lease = acquireNormal(f);
		const first = compactor(f, lease);
		await readyStorage(first);
		expect(
			callBarrier(first, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toMatchObject({ state: "available", elapsed: false, retryThroughWallTimeMs: 60_000 });
		const firstBytes = readFileSync(deadlinePath(f));
		const stagingResidue = join(
			f.runDirectory,
			`.${basename(deadlinePath(f))}.${createHash("sha256").update(firstBytes).digest("hex")}.tmp`,
		);
		linkSync(deadlinePath(f), stagingResidue);

		const replay = compactor(f, lease);
		await readyStorage(replay);
		expect(
			callBarrier(replay, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: 60_000 }),
		).toEqual({
			state: "available",
			elapsed: true,
			retryThroughWallTimeMs: 60_000,
		});
		expect(readFileSync(deadlinePath(f))).toEqual(firstBytes);
		expect(() => readFileSync(stagingResidue)).toThrow();
		const fresh = compactor(f);
		await readyStorage(fresh);
		expect(replay.accountedStorageBytes).toBe(fresh.accountedStorageBytes);
		f.lease?.release();
	});

	it("fails closed after an accounting effect failure and converges through an independent rescan", async () => {
		const f = fixture();
		const lease = acquireNormal(f);
		const value = compactor(f, lease);
		await readyStorage(value);
		const accounting = value as unknown as {
			applyStorageAccountingEffects: (effects: readonly unknown[]) => number;
		};
		const failure = vi.spyOn(accounting, "applyStorageAccountingEffects").mockImplementation(() => {
			throw new Error("injected effects failure");
		});
		expect(
			callBarrier(value, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toEqual({ state: "unavailable", reason: "service_barrier_deadline_accounting_failed" });
		expect(readFileSync(deadlinePath(f), "utf8")).toContain('"createdWallTimeMs":0');
		failure.mockRestore();

		const replay = compactor(f, lease);
		await readyStorage(replay);
		expect(
			callBarrier(replay, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: 60_000 }),
		).toEqual({
			state: "available",
			elapsed: true,
			retryThroughWallTimeMs: 60_000,
		});
		const rescanned = compactor(f, lease);
		await readyStorage(rescanned);
		expect(replay.accountedStorageBytes).toBe(rescanned.accountedStorageBytes);
		f.lease?.release();
	});

	it("fails closed after post-publication durability ambiguity and replays the immutable residue", async () => {
		const f = fixture();
		const lease = acquireNormal(f);
		const value = compactor(f, lease);
		await readyStorage(value);
		const internals = value as unknown as CompactorRootInternals;
		const originalWithRecorderRoot = internals.withRecorderRoot.bind(value);
		const fault = vi
			.spyOn(internals, "withRecorderRoot")
			.mockImplementation(<T>(operation: (root: IncidentCasRootMutation, assertCurrent: () => void) => T) => {
				return originalWithRecorderRoot((root, assertCurrent) => {
					let syncs = 0;
					const inject = (capability: IncidentCasRootMutation): IncidentCasRootMutation =>
						Object.freeze({
							...capability,
							fsyncDirectory(path: IncidentCasRelativePath) {
								syncs += 1;
								if (syncs === 2) throw new Error("injected post-publication durability failure");
								capability.fsyncDirectory(path);
							},
							withDirectory<T>(
								path: IncidentCasRelativePath,
								nestedOperation: (nested: IncidentCasRootMutation) => T,
							): T {
								return capability.withDirectory(path, (nested) => nestedOperation(inject(nested)));
							},
						});
					return operation(inject(root), assertCurrent);
				});
			});
		const release = vi.spyOn(internals, "releaseReservedCapacity");
		expect(
			callBarrier(value, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toEqual({ state: "unavailable", reason: "service_barrier_deadline_persistence_unavailable" });
		expect(readFileSync(deadlinePath(f), "utf8")).toContain('"createdWallTimeMs":0');
		const residueName = readdirSync(f.runDirectory).find((name) => name.includes(".tmp"));
		if (!residueName) throw new Error("post-publication fault did not leave immutable residue");
		expect(readFileSync(deadlinePath(f))).toEqual(readFileSync(join(f.runDirectory, residueName)));
		expect(release).toHaveBeenCalledTimes(1);
		fault.mockRestore();

		const replay = compactor(f, lease);
		await readyStorage(replay);
		expect(
			callBarrier(replay, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: 60_000 }),
		).toEqual({
			state: "available",
			elapsed: true,
			retryThroughWallTimeMs: 60_000,
		});
		expect(readdirSync(f.runDirectory).filter((name) => name.includes(".tmp"))).toEqual([]);
		const fresh = compactor(f);
		await readyStorage(fresh);
		expect(replay.accountedStorageBytes).toBe(fresh.accountedStorageBytes);
		f.lease?.release();
	});

	it("quarantines one malformed occupant and remains stable across a fresh compactor and lease", async () => {
		const f = fixture();
		writeFileSync(deadlinePath(f), '{"unexpected":true}\n', { mode: 0o600 });
		const lease = acquireNormal(f);
		const first = compactor(f, lease);
		await readyStorage(first);
		expect(
			callBarrier(first, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toEqual({
			state: "available",
			elapsed: false,
			retryThroughWallTimeMs: 60_000,
		});
		const names = quarantineNames(f);
		expect(names).toHaveLength(1);
		expect(names[0]).toMatch(/^barrier-deadline-[0-9a-f-]+\.invalid$/);
		const firstBytes = readFileSync(deadlinePath(f), "utf8");
		f.lease?.release();

		const secondLease = acquireNormal(f);
		const second = compactor(f, secondLease);
		await readyStorage(second);
		expect(
			callBarrier(second, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: 60_000 }),
		).toEqual({
			state: "available",
			elapsed: true,
			retryThroughWallTimeMs: 60_000,
		});
		expect(quarantineNames(f)).toEqual(names);
		expect(readFileSync(deadlinePath(f), "utf8")).toBe(firstBytes);
		f.lease?.release();
	});

	it("fails closed for a missing or revoked lease, a recovery lease, and low storage headroom", async () => {
		const f = fixture();
		const withoutLease = compactor(f);
		expect(
			callBarrier(withoutLease, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toMatchObject({
			state: "unavailable",
		});
		expect(() => readFileSync(deadlinePath(f))).toThrow();

		const revokedLease = acquireNormal(f);
		revokedLease.release();
		const revoked = compactor(f, revokedLease);
		expect(
			callBarrier(revoked, { runDirectory: f.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toMatchObject({ state: "unavailable" });
		expect(() => readFileSync(deadlinePath(f))).toThrow();

		const recovery = acquireIncidentRecorderWriterRecoveryLease({ agentDir: f.agentDir }, lifecycleContract);
		if (recovery.state !== "acquired") throw new Error(`recovery lease unavailable: ${recovery.reason}`);
		const recoveryCompactor = compactor(f, recovery.lease);
		expect(
			callBarrier(recoveryCompactor, {
				runDirectory: f.runDirectory,
				runId: RUN_ID,
				runToken: RUN_TOKEN,
				nowMs: NOW,
			}),
		).toMatchObject({ state: "unavailable" });
		recovery.lease.release();

		const low = fixture();
		const lowLease = acquireNormal(low);
		const lowCompactor = compactor(low, lowLease, { storageHighWaterBytes: 1 });
		await readyStorage(lowCompactor);
		expect(
			callBarrier(lowCompactor, { runDirectory: low.runDirectory, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toMatchObject({
			state: "unavailable",
		});
		expect(() => readFileSync(deadlinePath(low))).toThrow();
		low.lease?.release();
		f.lease = undefined;
	});

	it("does not use a nested path or a detached path as a direct run child", async () => {
		const f = fixture();
		const lease = acquireNormal(f);
		const value = compactor(f, lease);
		await readyStorage(value);
		const nested = join(f.runsRoot, "nested", RUN_NAME);
		mkdirSync(nested, { recursive: true, mode: 0o700 });
		expect(
			callBarrier(value, { runDirectory: nested, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toMatchObject({ state: "unavailable" });
		expect(() => readFileSync(join(nested, basename(deadlinePath(f))))).toThrow();

		const detached = join(f.root, "detached", RUN_NAME);
		mkdirSync(detached, { recursive: true, mode: 0o700 });
		expect(
			callBarrier(value, { runDirectory: detached, runId: RUN_ID, runToken: RUN_TOKEN, nowMs: NOW }),
		).toMatchObject({ state: "unavailable" });
		expect(() => readFileSync(join(detached, basename(deadlinePath(f))))).toThrow();
		f.lease?.release();
	});
});
