import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	type IncidentRecorderServiceSignalSource,
	runIncidentRecorderService,
} from "../src/modes/daemon/incident-recorder.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

type RecorderSignal = "SIGINT" | "SIGTERM";

class TestSignalSource implements IncidentRecorderServiceSignalSource {
	private readonly listeners = new Map<RecorderSignal, () => void>();

	once(signal: RecorderSignal, listener: () => void): void {
		this.listeners.set(signal, listener);
	}

	off(signal: RecorderSignal, listener: () => void): void {
		if (this.listeners.get(signal) === listener) this.listeners.delete(signal);
	}

	emit(signal: RecorderSignal): void {
		const listener = this.listeners.get(signal);
		this.listeners.delete(signal);
		listener?.();
	}

	get size(): number {
		return this.listeners.size;
	}
}

const roots: string[] = [];
const originalStorageHealthySentinel = process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL;

afterEach(() => {
	vi.restoreAllMocks();
	delete process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES;
	delete process.env.PRIME_TEST_STORAGE_LINES;
	if (originalStorageHealthySentinel === undefined)
		delete process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL;
	else process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL = originalStorageHealthySentinel;
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { root: string; agentDir: string; binDir: string; eventsPath: string } {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-recorder-service-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const binDir = join(root, "bin");
	mkdirSync(agentDir, { mode: 0o700 });
	mkdirSync(binDir, { mode: 0o700 });
	return { root, agentDir, binDir, eventsPath: join(root, "events.log") };
}

function writeExecutable(path: string, body: string): void {
	writeFileSync(path, `#!${process.execPath}\n${body}\n`, { mode: 0o700 });
	chmodSync(path, 0o700);
}

function withTimeout<T>(promise: Promise<T>, milliseconds = 5_000): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("isolated recorder service timed out")), milliseconds);
		promise.then(
			(value) => {
				clearTimeout(timer);
				resolve(value);
			},
			(error: unknown) => {
				clearTimeout(timer);
				reject(error);
			},
		);
	});
}

async function waitForFileText(path: string, expected: readonly string[]): Promise<void> {
	for (let attempt = 0; attempt < 200; attempt += 1) {
		const value = existsSync(path) ? readFileSync(path, "utf8") : "";
		if (expected.every((item) => value.includes(item))) return;
		await new Promise<void>((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`timed out waiting for isolated recorder events: ${expected.join(", ")}`);
}

async function waitForCondition(condition: () => boolean, message: string): Promise<void> {
	for (let attempt = 0; attempt < 300; attempt += 1) {
		if (condition()) return;
		await new Promise<void>((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`timed out waiting for ${message}`);
}

function fakeSystemdCatSource(exitImmediately = false): string {
	return `
const fs = require("node:fs");
const events = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
const record = (value) => fs.appendFileSync(events, value + "\\n");
record(process.env.NOTIFY_SOCKET ? "systemd-cat-notify-leak" : "systemd-cat-started");
${exitImmediately ? "process.exit(1);" : 'process.stdin.resume(); process.stdin.once("end", () => { record("systemd-cat-end"); process.exit(0); }); process.once("SIGTERM", () => { record("systemd-cat-term"); process.exit(0); });'}
if (process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES) process.stdin.on("data", (chunk) => fs.appendFileSync(process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES, chunk));
`;
}

function fakeJournalctlSource(exitImmediately = false): string {
	return `
const fs = require("node:fs");
const events = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
const record = (value) => fs.appendFileSync(events, value + "\\n");
record(process.env.NOTIFY_SOCKET ? "journalctl-notify-leak" : "journalctl-started");
${exitImmediately ? "process.exit(1);" : 'if (!process.argv.includes("--follow")) process.exit(0); process.once("SIGTERM", () => { record("journalctl-term"); process.exit(0); }); setInterval(() => {}, 1000);'}
`;
}

describe("incident recorder service lifecycle", () => {
	it("announces readiness only after startup and drains on SIGTERM", async () => {
		const target = fixture();
		const systemdCatPath = join(target.binDir, "systemd-cat");
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(systemdCatPath, fakeSystemdCatSource());
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousNotifySocket = process.env.NOTIFY_SOCKET;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.NOTIFY_SOCKET = "@isolated-recorder-test";
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: (fields) => {
					notifications.push([...fields]);
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(
				Promise.race([
					ready,
					running.then(() => {
						throw new Error("recorder service exited before readiness");
					}),
				]),
			);
			await waitForFileText(target.eventsPath, ["systemd-cat-started", "journalctl-started"]);
			signals.emit("SIGTERM");
			await withTimeout(running);
			const events = readFileSync(target.eventsPath, "utf8");
			expect(events).toContain("journalctl-term");
			expect(events).toContain("systemd-cat-end");
			expect(events).not.toContain("notify-leak");
			expect(notifications).toEqual([
				["READY=1", "STATUS=Incident recorder ready"],
				["STOPPING=1", "STATUS=Stopping after SIGTERM"],
			]);
			expect(signals.size).toBe(0);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousNotifySocket === undefined) delete process.env.NOTIFY_SOCKET;
			else process.env.NOTIFY_SOCKET = previousNotifySocket;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("does not overwrite a recovery transition while the startup readiness gate is pending", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		let storageMode: "normal" | "recovery-only" = "normal";
		vi.spyOn(IncidentRecorderCompactor.prototype, "storageMode", "get").mockImplementation(
			() => storageMode,
		);
		vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			const [runOptions] = args;
			runOptions.onStorageMode?.("normal");
			runOptions.onReaderReady?.();
			queueMicrotask(() =>
				queueMicrotask(() =>
					queueMicrotask(() => {
						storageMode = "recovery-only";
						runOptions.onStorageMode?.("recovery-only", "startup_inspection_probe");
					}),
				),
			);
			await new Promise<void>((resolveClosed) => {
				if (runOptions.signal.aborted) resolveClosed();
				else runOptions.signal.addEventListener("abort", () => resolveClosed(), { once: true });
			});
		});
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		let resolveRecovery: () => void = () => {};
		const recovery = new Promise<void>((resolve) => {
			resolveRecovery = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: (fields) => {
					notifications.push([...fields]);
					if (fields.includes("STATUS=Incident recorder recovery-only: startup_inspection_probe"))
						resolveRecovery();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(recovery);
			await new Promise<void>((resolve) => setTimeout(resolve, 25));
			expect(notifications).toEqual([
				["READY=1", "STATUS=Incident recorder recovery-only: startup_inspection_probe"],
			]);
			expect(notifications.filter((fields) => fields.includes("READY=1"))).toHaveLength(1);
			expect(notifications.flat()).not.toContain("STATUS=Incident recorder ready");
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("binds normal prune continuation to a complete protection generation and restarts when it changes", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const continuation = (sequence: number) => ({
			version: 1 as const,
			sessionId: `session-${sequence}`,
			storeInstanceId: "store-instance",
			highWaterSegmentSequence: 10,
			filterSha256: "a".repeat(64),
			segmentSequence: sequence,
		});
		const firstContinuation = continuation(1);
		const secondContinuation = continuation(2);
		const observed: Array<{
			generation: number;
			fingerprint: string;
			continuation: unknown;
		}> = [];
		let pruneCalls = 0;
		vi.spyOn(IncidentRecorderCompactor.prototype, "pruneSegmentHistory").mockImplementation(
			(_nowMs, protection, suppliedContinuation) => {
				observed.push({
					generation: protection.generation,
					fingerprint: protection.fingerprint,
					continuation: suppliedContinuation,
				});
				pruneCalls += 1;
				if (pruneCalls === 1)
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 1,
						deletedBytes: 0,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: true,
						continuation: firstContinuation,
					};
				if (pruneCalls === 2) {
					const runDir = join(
						target.agentDir,
						"incident-recorder",
						"runs",
						"2026-08-30T00-00-00.000Z-56565656-5656-4656-8656-565656565656",
					);
					mkdirSync(runDir, { recursive: true, mode: 0o700 });
					writeFileSync(
						join(runDir, ".service-finalization-complete"),
						`${JSON.stringify({ completed: new Date().toISOString() })}\n`,
						{ mode: 0o600 },
					);
					return {
						deletedSegmentIds: [],
						corruptSegmentIds: [],
						examinedSegments: 1,
						deletedBytes: 0,
						locatorsInvalidated: false,
						requiresFullReconciliation: false,
						moreWork: true,
						continuation: secondContinuation,
					};
				}
				return {
					deletedSegmentIds: [],
					corruptSegmentIds: [],
					examinedSegments: 0,
					deletedBytes: 0,
					locatorsInvalidated: false,
					requiresFullReconciliation: false,
					moreWork: false,
				};
			},
		);
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			await waitForCondition(() => pruneCalls >= 3, "three bounded segment prune passes");
			expect(observed[0].continuation).toBeUndefined();
			expect(observed[1].continuation).toEqual(firstContinuation);
			expect(observed[1].generation).toBe(observed[0].generation);
			expect(observed[1].fingerprint).toBe(observed[0].fingerprint);
			expect(observed[2].continuation).toBeUndefined();
			expect(observed[2].generation).toBeGreaterThan(observed[1].generation);
			expect(observed[2].fingerprint).not.toBe(observed[1].fingerprint);
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("rebuilds retention protection after a deletion accounting rescan before pruning", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const expiredIncidentDir = join(
			target.agentDir,
			"incidents",
			"expired-67676767-6767-4676-8676-676767676767",
		);
		mkdirSync(expiredIncidentDir, { recursive: true, mode: 0o700 });
		writeFileSync(
			join(expiredIncidentDir, "summary.json"),
			`${JSON.stringify({
				runId: "67676767-6767-4676-8676-676767676767",
				stoppedTargetCaptureComplete: true,
				finalized: "2000-01-01T00:00:00.000Z",
			})}\n`,
			{ mode: 0o600 },
		);
		const runIdAddedAcrossRescan = "68686868-6868-4686-8686-686868686868";
		let resolveRescanStarted: () => void = () => {};
		const rescanStarted = new Promise<void>((resolve) => {
			resolveRescanStarted = resolve;
		});
		let releaseRescan: () => void = () => {};
		const rescanRelease = new Promise<void>((resolve) => {
			releaseRescan = resolve;
		});
		let heldDeletionRescan = false;
		let pruneCallsAtRescanStart = 0;
		const observedProtectedRunIds: string[][] = [];
		vi.spyOn(IncidentRecorderCompactor.prototype, "pruneSegmentHistory").mockImplementation(
			(_nowMs, protection) => {
				observedProtectedRunIds.push([...protection.protectedRunIds]);
				return {
					deletedSegmentIds: [],
					corruptSegmentIds: [],
					examinedSegments: 0,
					deletedBytes: 0,
					locatorsInvalidated: false,
					requiresFullReconciliation: false,
					moreWork: false,
				};
			},
		);
		const originalInitializeStorageAccounting =
			IncidentRecorderCompactor.prototype.initializeStorageAccounting;
		vi.spyOn(IncidentRecorderCompactor.prototype, "initializeStorageAccounting").mockImplementation(
			async function (
				this: IncidentRecorderCompactor,
				...args: Parameters<IncidentRecorderCompactor["initializeStorageAccounting"]>
			) {
				const result = await originalInitializeStorageAccounting.apply(this, args);
				if (!heldDeletionRescan && !existsSync(expiredIncidentDir)) {
					heldDeletionRescan = true;
					pruneCallsAtRescanStart = observedProtectedRunIds.length;
					const runDir = join(
						target.agentDir,
						"incident-recorder",
						"runs",
						`2026-08-30T00-00-00.000Z-${runIdAddedAcrossRescan}`,
					);
					mkdirSync(runDir, { recursive: true, mode: 0o700 });
					writeFileSync(
						join(runDir, ".service-finalization-complete"),
						`${JSON.stringify({ completed: new Date().toISOString() })}\n`,
						{ mode: 0o600 },
					);
					resolveRescanStarted();
					await rescanRelease;
				}
				return result;
			},
		);
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			await withTimeout(rescanStarted);
			expect(observedProtectedRunIds).toHaveLength(pruneCallsAtRescanStart);
			releaseRescan();
			await waitForCondition(
				() => observedProtectedRunIds.length > pruneCallsAtRescanStart,
				"post-rescan retention protection rebuild and segment prune",
			);
			expect(observedProtectedRunIds[pruneCallsAtRescanStart]).toContain(runIdAddedAcrossRescan);
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			releaseRescan();
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("does not prune segment history while retention protection is building", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const incidentDir = join(target.agentDir, "incidents", "uncertain-retained-incident");
		mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
		writeFileSync(
			join(incidentDir, "summary.json"),
			`${JSON.stringify({ stoppedTargetCaptureComplete: false, finalized: new Date().toISOString() })}\n`,
			{ mode: 0o600 },
		);
		const prune = vi.spyOn(IncidentRecorderCompactor.prototype, "pruneSegmentHistory");
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: { freeReserveBytes: 0 },
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			await new Promise<void>((resolve) => setTimeout(resolve, 750));
			expect(prune).not.toHaveBeenCalled();
			signals.emit("SIGTERM");
			await withTimeout(running);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("fails instead of remaining active when the compactor exits unexpectedly", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource(true));
		const shutdownOrder: string[] = [];
		const originalCompactorRun = IncidentRecorderCompactor.prototype.run;
		vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			try {
				return await originalCompactorRun.apply(this, args);
			} finally {
				shutdownOrder.push("compactor-closed");
			}
		});
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			shutdownOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: () => {},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			await expect(withTimeout(running)).rejects.toThrow();
			expect(shutdownOrder).toEqual(["compactor-closed", "writer-stop"]);
			expect(signals.size).toBe(0);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("rethrows a compactor close rejection after requested shutdown and writer drain", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const shutdownOrder: string[] = [];
		const closeError = new Error("compactor close rejected after requested shutdown");
		let resolveCloseStarted: () => void = () => {};
		const closeStarted = new Promise<void>((resolve) => {
			resolveCloseStarted = resolve;
		});
		let releaseClose: () => void = () => {};
		const closeRelease = new Promise<void>((resolve) => {
			releaseClose = resolve;
		});
		vi.spyOn(IncidentRecorderCompactor.prototype, "run").mockImplementation(async function (
			this: IncidentRecorderCompactor,
			...args: Parameters<IncidentRecorderCompactor["run"]>
		) {
			const [runOptions] = args;
			runOptions.onStorageMode?.("normal");
			runOptions.onReaderReady?.();
			await new Promise<void>((resolveAborted) => {
				if (runOptions.signal.aborted) resolveAborted();
				else runOptions.signal.addEventListener("abort", () => resolveAborted(), { once: true });
			});
			shutdownOrder.push("compactor-close-start");
			resolveCloseStarted();
			await closeRelease;
			shutdownOrder.push("compactor-close-reject");
			throw closeError;
		});
		const originalWriterStop = IncidentRecorderWriter.prototype.stop;
		vi.spyOn(IncidentRecorderWriter.prototype, "stop").mockImplementation(async function (
			this: IncidentRecorderWriter,
			...args: Parameters<IncidentRecorderWriter["stop"]>
		) {
			shutdownOrder.push("writer-stop");
			return originalWriterStop.apply(this, args);
		});
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: (fields) => {
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			signals.emit("SIGTERM");
			await withTimeout(closeStarted);
			expect(shutdownOrder).toEqual(["compactor-close-start"]);
			releaseClose();
			await expect(withTimeout(running)).rejects.toBe(closeError);
			expect(shutdownOrder).toEqual([
				"compactor-close-start",
				"compactor-close-reject",
				"writer-stop",
			]);
			expect(signals.size).toBe(0);
		} finally {
			releaseClose();
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("reaches degraded readiness and remains stoppable when storage starts recovery-only", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const expiredIncidentDir = join(
			target.agentDir,
			"incidents",
			"expired-78787878-7878-4787-8787-787878787878",
		);
		mkdirSync(expiredIncidentDir, { recursive: true, mode: 0o700 });
		writeFileSync(
			join(expiredIncidentDir, "summary.json"),
			`${JSON.stringify({
				runId: "78787878-7878-4787-8787-787878787878",
				stoppedTargetCaptureComplete: true,
				finalized: "2000-01-01T00:00:00.000Z",
			})}\n`,
			{ mode: 0o600 },
		);
		const scannerPath = join(target.binDir, "storage-scanner");
		const storageHealthySentinel = join(target.root, "storage-healthy");
		writeExecutable(
			scannerPath,
			`const fs = require("node:fs");
const healthy = fs.existsSync(process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL);
const unhealthyLines = Array.from(
	{ length: 65 },
	(_value, index) => "1\\t" + String(index + 10) + "\\t1\\t8",
).join("\\n") + "\\n";
fs.appendFileSync(
	process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS,
	healthy ? "storage-scan-clear\\n" : "storage-scan-high\\n",
);
process.stdout.write(healthy ? "" : unhealthyLines);`,
		);
		const previousStorageHealthySentinel = process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL;
		process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL = storageHealthySentinel;
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		let recoveryNotificationWasAllocationFree = false;
		let resolveReady: () => void = () => {};
		const ready = new Promise<void>((resolve) => {
			resolveReady = resolve;
		});
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				compactorOptions: {
					storageScannerPath: scannerPath,
					storageAccountingMaxInodes: 64,
					freeReserveBytes: 0,
				},
				notify: (fields) => {
					notifications.push([...fields]);
					if (fields.includes("STATUS=Incident recorder recovery-only: inode_bound_exceeded")) {
						recoveryNotificationWasAllocationFree = !existsSync(
							join(target.agentDir, "incident-recorder", "segments"),
						);
						writeFileSync(storageHealthySentinel, "healthy\n", { mode: 0o600 });
					}
					if (fields.includes("READY=1")) resolveReady();
				},
				signalSource: signals,
				storageRecoveryCadenceMs: 10,
				writerStopDeadlineMs: 1_000,
			});
			running.catch(() => {});
			await withTimeout(ready);
			expect(notifications).toEqual([
				["READY=1", "STATUS=Incident recorder recovery-only: inode_bound_exceeded"],
			]);
			expect(recoveryNotificationWasAllocationFree).toBe(true);
			expect(readFileSync(target.eventsPath, "utf8")).toContain("systemd-cat-started");
			expect(readFileSync(target.eventsPath, "utf8")).not.toContain("journalctl-started");
			expect(existsSync(join(target.agentDir, "incident-recorder", "segments"))).toBe(false);
			await waitForCondition(() => {
				const events = existsSync(target.eventsPath) ? readFileSync(target.eventsPath, "utf8") : "";
				return (
					!existsSync(expiredIncidentDir) &&
					events.includes("storage-scan-high") &&
					events.includes("storage-scan-clear")
				);
			}, "allocation-free recovery retention deletion and full storage rescan");
			await waitForFileText(target.eventsPath, ["journalctl-started"]);
			for (
				let attempt = 0;
				attempt < 200 && !notifications.some((fields) => fields.includes("STATUS=Incident recorder ready"));
				attempt += 1
			)
				await new Promise<void>((resolve) => setTimeout(resolve, 10));
			expect(notifications.filter((fields) => fields.includes("READY=1"))).toHaveLength(1);
			expect(notifications).toContainEqual(["STATUS=Incident recorder ready"]);
			expect(
				notifications.filter((fields) => fields.includes("STATUS=Incident recorder ready")),
			).toHaveLength(1);
			signals.emit("SIGTERM");
			await withTimeout(running);
			expect(notifications.at(-1)).toEqual(["STOPPING=1", "STATUS=Stopping after SIGTERM"]);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
			if (previousStorageHealthySentinel === undefined)
				delete process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL;
			else process.env.PRIME_TEST_STORAGE_HEALTHY_SENTINEL = previousStorageHealthySentinel;
		}
	}, 10_000);

	it("never announces readiness when the initial journal writer exits immediately", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource(true));
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		const signals = new TestSignalSource();
		const notifications: string[][] = [];
		let running: Promise<void> | undefined;
		try {
			running = runIncidentRecorderService(target.agentDir, {
				journalctlPath,
				notify: (fields) => notifications.push([...fields]),
				signalSource: signals,
				writerStopDeadlineMs: 1_000,
			});
			await expect(withTimeout(running)).rejects.toThrow("journal writer did not become ready");
			expect(notifications.flat()).not.toContain("READY=1");
			expect(signals.size).toBe(0);
		} finally {
			if (signals.size > 0) signals.emit("SIGTERM");
			if (running) await withTimeout(running).catch(() => undefined);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);

	it("drains admitted per-run service observations before closing the journal writer", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalBytes = join(target.root, "journal-lines.jsonl");
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
		process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = target.eventsPath;
		process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES = journalBytes;
		const writer = new IncidentRecorderWriter({
			runDir: join(target.agentDir, "incident-recorder"),
			runId: "11111111-1111-4111-8111-111111111111",
			runToken: "22222222-2222-4222-8222-222222222222",
			serviceSink: true,
		});
		try {
			await writer.start({ requireJournal: true });
			const admission = writer.recordDerivedForRun(
				{
					runId: "33333333-3333-4333-8333-333333333333",
					runToken: "44444444-4444-4444-8444-444444444444",
				},
				"recorder-control",
				"service_shutdown_drain_probe",
				{ diagnosticOnly: true },
			);
			expect(admission.accepted).toBe(true);
			await writer.releaseRunIdentity({
				runId: "33333333-3333-4333-8333-333333333333",
				runToken: "44444444-4444-4444-8444-444444444444",
			});
			await writer.stop(1_000);
			const lines = readFileSync(journalBytes, "utf8")
				.trim()
				.split("\n")
				.map((line) => JSON.parse(line) as { type?: unknown });
			expect(lines.some((line) => line.type === "service_shutdown_drain_probe")).toBe(true);
		} finally {
			await writer.stop(250);
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousEvents === undefined) delete process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
			else process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS = previousEvents;
		}
	}, 10_000);
});
