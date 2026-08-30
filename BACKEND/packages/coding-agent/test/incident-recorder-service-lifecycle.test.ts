import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
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

afterEach(() => {
	delete process.env.PRIME_TEST_RECORDER_JOURNAL_BYTES;
	delete process.env.PRIME_TEST_STORAGE_LINES;
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

	it("fails instead of remaining active when the compactor exits unexpectedly", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource(true));
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

	it("reaches degraded readiness and remains stoppable when storage starts recovery-only", async () => {
		const target = fixture();
		writeExecutable(join(target.binDir, "systemd-cat"), fakeSystemdCatSource());
		const journalctlPath = join(target.binDir, "journalctl");
		writeExecutable(journalctlPath, fakeJournalctlSource());
		const scannerPath = join(target.binDir, "storage-scanner");
		writeExecutable(
			scannerPath,
			'process.stdout.write(process.env.PRIME_TEST_STORAGE_LINES ?? "1\\t1\\t0\\t0\\n");',
		);
		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t1\t8\n1\t11\t1\t8\n1\t12\t1\t8\n";
		const previousPath = process.env.PATH;
		const previousEvents = process.env.PRIME_TEST_RECORDER_SERVICE_EVENTS;
		process.env.PATH = `${target.binDir}${delimiter}${previousPath ?? ""}`;
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
				compactorOptions: {
					storageScannerPath: scannerPath,
					storageAccountingMaxInodes: 2,
					freeReserveBytes: 0,
				},
				notify: (fields) => {
					notifications.push([...fields]);
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
			expect(readFileSync(target.eventsPath, "utf8")).toContain("systemd-cat-started");
			expect(readFileSync(target.eventsPath, "utf8")).not.toContain("journalctl-started");
			process.env.PRIME_TEST_STORAGE_LINES = "";
			await waitForFileText(target.eventsPath, ["journalctl-started"]);
			for (
				let attempt = 0;
				attempt < 200 && !notifications.some((fields) => fields.includes("STATUS=Incident recorder ready"));
				attempt += 1
			)
				await new Promise<void>((resolve) => setTimeout(resolve, 10));
			expect(notifications.filter((fields) => fields.includes("READY=1"))).toHaveLength(1);
			expect(notifications).toContainEqual(["STATUS=Incident recorder ready"]);
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
