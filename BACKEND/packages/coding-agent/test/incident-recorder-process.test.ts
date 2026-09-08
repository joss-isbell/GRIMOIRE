import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	closeSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readdirSync,
	readFileSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, delimiter, join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	exerciseIncidentRecorderFallbackAdmissionPendingPressureForTest,
	finalizeIncidentRecorderRun,
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
	type IncidentRecorderServiceSignalSource,
	ingestIncidentRecorderEvidence,
	inspectIncidentRecorderFallbackAdmissionForTest,
	isIncidentRecorderExcludedApplicationPath,
	type RecordedProcessResult,
	type RunIncidentRecorderServiceOptions,
	recordSupervisorProcess,
	registerIncidentProviderSourceManifest,
	registerIncidentRecorderFallbackAdmissionPostRawTestSynchronization,
	runIncidentRecorderService,
	shouldRecordSupervisorLaunch,
} from "../src/modes/daemon/incident-recorder.js";
import type {
	CasTransaction,
	IncidentCasRootMutation,
	IncidentCasRootMutationResult,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	decodeIncidentRecorderFrame,
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
	INCIDENT_RECORDER_RUN_ID_ENV,
	INCIDENT_RECORDER_RUN_TOKEN_ENV,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import {
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	runIncidentRetentionPass,
} from "../src/modes/daemon/incident-recorder-retention.js";
import { IncidentRecorderTransportDecoder } from "../src/modes/daemon/incident-recorder-transport.js";
import {
	INCIDENT_RECORDER_CAPTURE_FD_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV,
	INCIDENT_RECORDER_ROOT_FD_ENV,
	writeEncodedFramesToFd,
} from "../src/modes/daemon/incident-recorder-writer.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	acquireIncidentRecorderWriterRecoveryLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";
import { serializeJsonLine } from "../src/modes/rpc/jsonl.js";
import { encodePrivateFrame } from "../src/modes/session-worker/private-framing.js";

type CasFaultEvidence = "durable" | "pending";

const casFaultHarness = vi.hoisted(() => ({
	enabled: false,
	acquisitions: 0,
	withRootCalls: 0,
	releaseCalls: 0,
	capabilityError: false,
	detachedEvidence: undefined as CasFaultEvidence | undefined,
	releasePending: false,
	beforeWithRoot: undefined as ((recorderRoot: string) => void) | undefined,
	afterWithRoot: undefined as ((recorderRoot: string) => void) | undefined,
	retiredRoot: undefined as string | undefined,
}));

vi.mock("../src/modes/daemon/incident-recorder-cas-transaction.js", async (importOriginal) => {
	type DetailedAdmission =
		| { state: "acquired"; transaction: CasTransaction }
		| { state: "unavailable"; reason: string };
	type CasModule = Record<string, unknown> & {
		acquireIncidentCasTransaction(recorderRoot: string, runtime?: unknown): CasTransaction | undefined;
		acquireIncidentCasTransactionDetailed(recorderRoot: string, runtime?: unknown): DetailedAdmission;
	};
	const actual = (await importOriginal()) as CasModule;
	const decorate = (transaction: CasTransaction, recorderRoot: string): CasTransaction => {
		if (!casFaultHarness.enabled) return transaction;
		return {
			withRoot: <T>(operation: (root: IncidentCasRootMutation) => T): IncidentCasRootMutationResult<T> => {
				casFaultHarness.withRootCalls += 1;
				casFaultHarness.beforeWithRoot?.(recorderRoot);
				if (casFaultHarness.capabilityError) throw new Error("injected_provider_capability_error");
				const result = transaction.withRoot(operation);
				casFaultHarness.afterWithRoot?.(recorderRoot);
				return casFaultHarness.detachedEvidence
					? { state: "root_detached", evidence: casFaultHarness.detachedEvidence }
					: result;
			},
			release: () => {
				casFaultHarness.releaseCalls += 1;
				const result = transaction.release();
				return casFaultHarness.releasePending ? { state: "pending", reason: "io_error" as const } : result;
			},
		};
	};
	return {
		...actual,
		acquireIncidentCasTransaction: (recorderRoot: string, runtime?: unknown) => {
			const transaction = actual.acquireIncidentCasTransaction(recorderRoot, runtime);
			if (!transaction) return undefined;
			casFaultHarness.acquisitions += casFaultHarness.enabled ? 1 : 0;
			return decorate(transaction, recorderRoot);
		},
		acquireIncidentCasTransactionDetailed: (recorderRoot: string, runtime?: unknown): DetailedAdmission => {
			const admission = actual.acquireIncidentCasTransactionDetailed(recorderRoot, runtime);
			if (admission.state !== "acquired") return admission;
			casFaultHarness.acquisitions += casFaultHarness.enabled ? 1 : 0;
			return { state: "acquired", transaction: decorate(admission.transaction, recorderRoot) };
		},
	};
});

const roots: string[] = [];
const livePids = new Map<number, string>();

function signalFixture(pid: number, signal: NodeJS.Signals | 0): void {
	const expectedStartId = livePids.get(pid);
	if (!expectedStartId || getProcessStartId(pid) !== expectedStartId) {
		throw new Error(`Refusing to signal fixture without matching process identity: ${pid}`);
	}
	process.kill(pid, signal);
}

afterEach(() => {
	casFaultHarness.enabled = false;
	casFaultHarness.acquisitions = 0;
	casFaultHarness.withRootCalls = 0;
	casFaultHarness.releaseCalls = 0;
	casFaultHarness.capabilityError = false;
	casFaultHarness.detachedEvidence = undefined;
	casFaultHarness.releasePending = false;
	casFaultHarness.beforeWithRoot = undefined;
	casFaultHarness.afterWithRoot = undefined;
	casFaultHarness.retiredRoot = undefined;
	vi.restoreAllMocks();
	for (const [pid, expectedStartId] of livePids) {
		try {
			if (getProcessStartId(pid) === expectedStartId) process.kill(pid, "SIGKILL");
		} catch {}
	}
	livePids.clear();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(source: string): { root: string; agentDir: string; socketPath: string; script: string } {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-recorder-process-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { mode: 0o700 });
	const script = join(root, "fault.cjs");
	writeFileSync(script, source, { mode: 0o600 });
	return { root, agentDir, socketPath: join(root, "isolated.sock"), script };
}

function record(target: ReturnType<typeof fixture>): Promise<RecordedProcessResult> {
	return recordSupervisorProcess({
		agentDir: target.agentDir,
		socketPath: target.socketPath,
		launch: { command: process.execPath, args: [target.script] },
		environment: {},
		cwd: target.root,
	});
}

function fixtureLifecycleContract() {
	return {
		activationGenerationDigest: "a".repeat(64),
		revalidateActivation: () => ({ state: "valid" as const }),
		acquireCas: acquireIncidentRecorderNamespaceCas,
	};
}

function runRetentionPassWithFixtureLease(
	options: Parameters<typeof runIncidentRetentionPass>[0],
): ReturnType<typeof runIncidentRetentionPass> {
	const contract = fixtureLifecycleContract();
	const acquired = options.recoveryOnly
		? acquireIncidentRecorderWriterRecoveryLease({ agentDir: options.agentDir }, contract)
		: acquireIncidentRecorderWriterNormalLease({ agentDir: options.agentDir }, contract);
	if (acquired.state !== "acquired") throw new Error(`retention fixture lease unavailable: ${acquired.reason}`);
	let result: ReturnType<typeof runIncidentRetentionPass> | undefined;
	let released: ReturnType<typeof acquired.lease.release> | undefined;
	try {
		result = runIncidentRetentionPass({ ...options, writerLifecycleLease: acquired.lease });
	} finally {
		released = acquired.lease.release();
	}
	if (released?.state !== "released") throw new Error("retention fixture lease release pending");
	if (!result) throw new Error("retention fixture pass did not produce a result");
	return result;
}

type JournalBackedFault = "event_loop_hang" | "socket_loss" | "worker_response_hang";
type JournalBackedFaultTarget = ReturnType<typeof fixture> & {
	fault: JournalBackedFault;
	journalPath: string;
};

function journalBackedFaultFixture(fault: JournalBackedFault): JournalBackedFaultTarget {
	const target = fixture("");
	return { ...target, fault, journalPath: join(target.root, "journal-export-source.jsonl") };
}

function recordJournalBackedFault(target: JournalBackedFaultTarget): Promise<RecordedProcessResult> {
	const script = fileURLToPath(new URL("./fixtures/incident-recorder-causal-fault.ts", import.meta.url));
	const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	return recordSupervisorProcess({
		agentDir: target.agentDir,
		socketPath: target.socketPath,
		launch: { command: process.execPath, args: ["--import", tsxLoader, script] },
		environment: { PRIME_TEST_INCIDENT_RECORDER_FAULT: target.fault },
		cwd: target.root,
	});
}

function journalBackedSystemdCatSource(): string {
	return `
const fs = require("node:fs");
const path = require("node:path");
const destination = process.env.PRIME_TEST_INCIDENT_RECORDER_JOURNAL;
if (!destination) process.exit(2);
fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
process.stdin.on("data", (chunk) => fs.appendFileSync(destination, chunk));
process.stdin.once("end", () => process.exit(0));
process.once("SIGTERM", () => process.exit(0));
process.stdin.resume();
`;
}

function journalBackedJournalctlSource(): string {
	return `
const fs = require("node:fs");
const path = require("node:path");
const destination = process.env.PRIME_TEST_INCIDENT_RECORDER_JOURNAL;
if (!destination) process.exit(2);
const follow = process.argv.includes("--follow");
const afterArgument = process.argv.find((value) => value.startsWith("--after-cursor="));
const afterCursor = afterArgument ? Number(afterArgument.slice("--after-cursor=fixture:".length)) : undefined;
const linesArgument = process.argv.find((value) => value.startsWith("--lines="));
const lineLimit = linesArgument ? Number(linesArgument.slice("--lines=".length)) : 256;
const readRows = () => {
  if (!fs.existsSync(destination)) return [];
  return fs.readFileSync(destination, "utf8").split("\\n").filter(Boolean).flatMap((value) => {
    try { return [JSON.parse(value)]; } catch { return []; }
  });
};
let nextIndex = afterCursor === undefined ? 0 : afterCursor + 1;
const emitRow = (row, index) => {
  const machineId = row.machineId || "missing";
  const bootId = row.bootId || "missing";
  const realtime = String(BigInt(row.eventWallTimeMs) * 1000n);
  const monotonic = String(BigInt(row.eventMonotonicNs) / 1000n);
  const fields = [
    "__CURSOR=fixture:" + index,
    "_MACHINE_ID=" + machineId,
    "_BOOT_ID=" + bootId,
    "_STREAM_ID=fixture-stream",
    "_UID=" + String(typeof process.getuid === "function" ? process.getuid() : 0),
    "SYSLOG_IDENTIFIER=prime-agent-raw-v1",
    "_TRANSPORT=stdout",
    "_PID=" + String(row.systemdCatPid),
    "__REALTIME_TIMESTAMP=" + realtime,
    "__MONOTONIC_TIMESTAMP=" + monotonic,
    "MESSAGE=" + JSON.stringify(row),
    "",
  ];
  process.stdout.write(fields.join("\\n") + "\\n");
};
const pump = () => {
  const rows = readRows();
  const limit = follow ? rows.length : Math.min(rows.length, nextIndex + Math.max(0, lineLimit));
  while (nextIndex < limit) emitRow(rows[nextIndex], nextIndex++);
  if (!follow) process.exit(0);
};
pump();
if (follow) {
  const timer = setInterval(pump, 10);
  process.once("SIGTERM", () => { clearInterval(timer); process.exit(0); });
}
`;
}

class JournalBackedServiceSignals implements IncidentRecorderServiceSignalSource {
	private readonly listeners = new Map<"SIGINT" | "SIGTERM", () => void>();

	once(signal: "SIGINT" | "SIGTERM", listener: () => void): void {
		this.listeners.set(signal, listener);
	}

	off(signal: "SIGINT" | "SIGTERM", listener: () => void): void {
		if (this.listeners.get(signal) === listener) this.listeners.delete(signal);
	}

	emit(signal: "SIGINT" | "SIGTERM"): void {
		const listener = this.listeners.get(signal);
		this.listeners.delete(signal);
		listener?.();
	}
}

interface RunningJournalBackedService {
	stop(): Promise<void>;
}

interface PreparedJournalBackedServiceEnvironment {
	binDir: string;
	restore(): void;
}

function prepareJournalBackedServiceEnvironment(
	target: JournalBackedFaultTarget,
): PreparedJournalBackedServiceEnvironment {
	const binDir = join(target.root, "service-bin");
	mkdirSync(binDir, { recursive: true, mode: 0o700 });
	writeFileSync(join(binDir, "systemd-cat"), `#!${process.execPath}\n${journalBackedSystemdCatSource()}\n`, {
		mode: 0o700,
	});
	writeFileSync(join(binDir, "journalctl"), `#!${process.execPath}\n${journalBackedJournalctlSource()}\n`, {
		mode: 0o700,
	});
	mkdirSync(join(target.agentDir, "incident-recorder"), { recursive: true, mode: 0o700 });
	mkdirSync(join(target.agentDir, "incidents"), { recursive: true, mode: 0o700 });
	const previousPath = process.env.PATH;
	const previousJournal = process.env.PRIME_TEST_INCIDENT_RECORDER_JOURNAL;
	process.env.PATH = `${binDir}${delimiter}${previousPath ?? ""}`;
	process.env.PRIME_TEST_INCIDENT_RECORDER_JOURNAL = target.journalPath;
	let restored = false;
	return {
		binDir,
		restore: () => {
			if (restored) return;
			restored = true;
			if (previousPath === undefined) delete process.env.PATH;
			else process.env.PATH = previousPath;
			if (previousJournal === undefined) delete process.env.PRIME_TEST_INCIDENT_RECORDER_JOURNAL;
			else process.env.PRIME_TEST_INCIDENT_RECORDER_JOURNAL = previousJournal;
		},
	};
}

async function startJournalBackedService(
	target: JournalBackedFaultTarget,
	prepared = prepareJournalBackedServiceEnvironment(target),
): Promise<RunningJournalBackedService> {
	const { binDir, restore: restoreEnvironment } = prepared;
	const signals = new JournalBackedServiceSignals();
	let resolveReady: () => void = () => {};
	const ready = new Promise<void>((resolve) => {
		resolveReady = resolve;
	});
	let running: Promise<void> | undefined;
	try {
		const options: RunIncidentRecorderServiceOptions = {
			journalctlPath: join(binDir, "journalctl"),
			writerLifecycleContract: {
				activationGenerationDigest: "a".repeat(64),
				revalidateActivation: () => ({ state: "valid" }),
				acquireCas: acquireIncidentRecorderNamespaceCas,
			},
			notify: (fields) => {
				if (fields.includes("READY=1")) {
					resolveReady();
				}
			},
			signalSource: signals,
			writerStopDeadlineMs: 1_000,
		};
		running = runIncidentRecorderService(target.agentDir, options);
		running.catch(() => {});
		await withTimeout(ready, 10_000, "isolated journal-backed service readiness");
		return {
			stop: async () => {
				signals.emit("SIGTERM");
				if (running) await running;
				restoreEnvironment();
			},
		};
	} catch (error) {
		signals.emit("SIGTERM");
		if (running) await running.catch(() => {});
		restoreEnvironment();
		throw error;
	}
}

async function waitForJournalRecord(target: JournalBackedFaultTarget, type: string): Promise<void> {
	await waitUntil(
		() => {
			if (!existsSync(target.journalPath)) return false;
			return readFileSync(target.journalPath, "utf8")
				.split("\n")
				.filter(Boolean)
				.some((line) => {
					try {
						return (JSON.parse(line) as { type?: unknown }).type === type;
					} catch {
						return false;
					}
				});
		},
		`journal record ${type}`,
		10_000,
	);
}

async function waitForPublishedIncident(target: JournalBackedFaultTarget, runDir: string): Promise<string> {
	const incidentDir = join(target.agentDir, "incidents", basename(runDir));
	await waitUntil(
		() => existsSync(join(incidentDir, "summary.json")),
		`published incident ${basename(runDir)}`,
		20_000,
	);
	return incidentDir;
}

function readPublishedRunHistoryEvents(incidentDir: string): Array<Record<string, unknown>> {
	const value = JSON.parse(readFileSync(join(incidentDir, "run-history.json"), "utf8")) as {
		runHistory?: { projection?: { events?: unknown } };
	};
	return Array.isArray(value.runHistory?.projection?.events)
		? (value.runHistory?.projection?.events as Array<Record<string, unknown>>)
		: [];
}

function withTimeout<T>(promise: Promise<T>, milliseconds: number, message: string): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error(message)), milliseconds);
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

async function initializeStorageAccounting(compactor: IncidentRecorderCompactor): Promise<void> {
	const controller = new AbortController();
	await compactor.initializeStorageAccounting(controller.signal);
}

async function waitUntil(predicate: () => boolean, description: string, timeoutMs = 2_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error(`timed out waiting for ${description}`);
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

async function startCasHolder(recorderRoot: string): Promise<{ pid: number; release: () => Promise<void> }> {
	const script = fileURLToPath(new URL("./fixtures/incident-recorder-cas-holder.ts", import.meta.url));
	const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	const child = spawn(process.execPath, ["--import", tsxLoader, script, recorderRoot], {
		stdio: ["pipe", "pipe", "pipe"],
	});
	if (!child.pid) throw new Error("CAS holder fixture did not start");
	const pid = child.pid;
	const processStartId = getProcessStartId(pid);
	if (!processStartId) throw new Error("CAS holder fixture has no stable process identity");
	livePids.set(pid, processStartId);
	let stdout = "";
	let stderr = "";
	child.stdout?.setEncoding("utf8");
	child.stderr?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		stdout += chunk;
	});
	child.stderr?.on("data", (chunk: string) => {
		stderr += chunk;
	});
	await waitUntil(() => stdout.includes("ready\n") || child.exitCode !== null, `CAS holder readiness: ${stderr}`);
	if (!stdout.includes("ready\n")) throw new Error(`CAS holder exited before readiness: ${stderr}`);
	return {
		pid,
		release: async () => {
			if (child.exitCode === null) child.stdin?.end("release\n");
			await waitUntil(
				() => stdout.includes("released\n") && child.exitCode !== null,
				`CAS holder release: ${stderr}`,
			);
			livePids.delete(pid);
		},
	};
}

function fallbackRunDirectory(agentDir: string): { recorderRoot: string; runDir: string } {
	const recorderRoot = join(agentDir, "incident-recorder");
	const runDir = join(recorderRoot, "runs", "fixture-99999999-9999-4999-8999-999999999999");
	mkdirSync(runDir, { recursive: true, mode: 0o700 });
	return { recorderRoot, runDir };
}

function readRawRecordEnvelopes(runDir: string, source: string): Array<Record<string, unknown>> {
	const directory = join(runDir, "raw-application", source);
	if (!existsSync(directory)) return [];
	const frames = new Map<string, Array<{ chunkIndex: number; payload: string }>>();
	for (const name of readdirSync(directory)
		.filter((candidate) => /^segment-\d{8}\.jsonl$/.test(candidate))
		.sort()) {
		for (const line of readFileSync(join(directory, name), "utf8").split("\n")) {
			if (!line) continue;
			const frame = JSON.parse(line) as { recordId: string; chunkIndex: number; payload: string };
			const chunks = frames.get(frame.recordId) ?? [];
			chunks.push({ chunkIndex: frame.chunkIndex, payload: frame.payload });
			frames.set(frame.recordId, chunks);
		}
	}
	return [...frames.values()].map(
		(chunks) =>
			JSON.parse(
				Buffer.concat(
					chunks
						.sort((left, right) => left.chunkIndex - right.chunkIndex)
						.map((chunk) => Buffer.from(chunk.payload, "base64")),
				).toString("utf8"),
			) as Record<string, unknown>,
	);
}

interface StoredRawBlobReference {
	algorithm: "sha256";
	digest: string;
	bytes: number;
	path: string;
	collisionFallbackPath: string;
	encoding: string;
}

function readJsonLines(path: string): Array<Record<string, unknown>> {
	return readFileSync(path, "utf8")
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

function storedPayloadReference(envelope: Record<string, unknown>): StoredRawBlobReference {
	const reference = envelope.payloadReference as Partial<StoredRawBlobReference> | undefined;
	expect(reference).toMatchObject({ algorithm: "sha256" });
	expect(reference?.digest).toMatch(/^[0-9a-f]{64}$/);
	expect(reference?.bytes).toEqual(expect.any(Number));
	expect(reference?.path).toEqual(expect.any(String));
	expect(reference?.collisionFallbackPath).toEqual(expect.any(String));
	expect(reference?.encoding).toEqual(expect.any(String));
	return reference as StoredRawBlobReference;
}

function chosenBlobPath(reference: StoredRawBlobReference): string {
	return existsSync(reference.collisionFallbackPath) ? reference.collisionFallbackPath : reference.path;
}

function fallbackAdmissionLossRecords(runDir: string): Array<Record<string, unknown>> {
	return readRawRecordEnvelopes(runDir, "loss-accounting").filter(
		(record) => record.type === "fallback_run_evidence_admission_loss",
	);
}

function fallbackAdmissionLossPayload(runDir: string): string {
	const records = fallbackAdmissionLossRecords(runDir);
	expect(records).toHaveLength(1);
	const reference = records[0].payloadBlob as { path?: unknown } | undefined;
	expect(typeof reference?.path).toBe("string");
	return readFileSync(String(reference?.path), "utf8");
}

function diagnosticObjectNumber(serialized: string, field: string): number {
	const encoded = JSON.parse(serialized) as { properties?: unknown };
	if (!Array.isArray(encoded.properties)) throw new Error("Diagnostic loss payload has no properties");
	const property = encoded.properties.find((candidate) => {
		if (!candidate || typeof candidate !== "object") return false;
		const key = (candidate as { key?: unknown }).key;
		return !!key && typeof key === "object" && (key as { value?: unknown }).value === field;
	}) as { value?: unknown } | undefined;
	if (!property || typeof property.value !== "number") {
		throw new Error(`Diagnostic loss payload has no numeric ${field}`);
	}
	return property.value;
}

function fallbackAdmissionLossPayloads(runDir: string): string[] {
	return fallbackAdmissionLossRecords(runDir).map((record) => {
		const reference = record.payloadBlob as Partial<StoredRawBlobReference> | undefined;
		if (!reference || typeof reference.path !== "string" || typeof reference.collisionFallbackPath !== "string") {
			throw new Error("Fallback admission loss record has no payload blob");
		}
		return readFileSync(chosenBlobPath(reference as StoredRawBlobReference), "utf8");
	});
}

function writeSchema2FallbackAdmissionLoss(runDir: string, batchCount: number): string {
	const runId = basename(runDir).slice(-36);
	const batches = Array.from({ length: batchCount }, (_, index) => ({
		batchId: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
		lostAdmissions: 1,
		firstObservedWallTimeMs: index + 1,
		lastObservedWallTimeMs: index + 1,
		asynchronousRetryAttempts: 0,
		causes: { capability_error: 1 },
	}));
	const serialized = `${JSON.stringify({
		schemaVersion: 2,
		kind: "service_fallback_admission_loss",
		runId,
		lostAdmissions: batchCount,
		firstObservedWallTimeMs: 1,
		lastObservedWallTimeMs: batchCount,
		synchronousAttemptLimit: 3,
		synchronousWaitIntervalMs: 5,
		asynchronousRetryAttempts: 0,
		batches,
	})}\n`;
	writeFileSync(join(runDir, "service-finalization-fallback-admission-loss.json"), serialized, { mode: 0o600 });
	return serialized;
}

function replaceRecorderRoot(recorderRoot: string): void {
	const retiredRoot = `${recorderRoot}.retired-test`;
	renameSync(recorderRoot, retiredRoot);
	mkdirSync(recorderRoot, { mode: 0o700 });
	casFaultHarness.retiredRoot = retiredRoot;
}

function restoreRecorderRoot(recorderRoot: string): void {
	const retiredRoot = casFaultHarness.retiredRoot;
	if (!retiredRoot) return;
	rmSync(recorderRoot, { recursive: true, force: true });
	renameSync(retiredRoot, recorderRoot);
	casFaultHarness.retiredRoot = undefined;
}

function expectCanonicalBlobAndLease(
	recorderRoot: string,
	runDir: string,
	reference: StoredRawBlobReference,
	expectedBytes?: Buffer,
): void {
	const canonicalRoot = realpathSync(recorderRoot);
	for (const path of [reference.path, reference.collisionFallbackPath]) {
		expect(path.startsWith(`${canonicalRoot}/`)).toBe(true);
		expect(path).not.toContain("/proc/self/fd/");
	}
	const selected = chosenBlobPath(reference);
	const bytes = readFileSync(selected);
	expect(bytes.byteLength).toBe(reference.bytes);
	expect(createHash("sha256").update(bytes).digest("hex")).toBe(reference.digest);
	if (expectedBytes) expect(bytes.equals(expectedBytes)).toBe(true);
	const lease = join(runDir, ".cas-leases", selected.slice(selected.lastIndexOf("/") + 1));
	const sourceStat = statSync(selected);
	const leaseStat = statSync(lease);
	expect({ dev: leaseStat.dev, ino: leaseStat.ino }).toEqual({ dev: sourceStat.dev, ino: sourceStat.ino });
}

function probeCasAdmissionSynchronously(recorderRoot: string): Record<string, unknown> {
	const moduleUrl = new URL("../src/modes/daemon/incident-recorder-cas-transaction.ts", import.meta.url).href;
	const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	const script = `
		import { acquireIncidentCasTransactionDetailed } from ${JSON.stringify(moduleUrl)};
		const admission = acquireIncidentCasTransactionDetailed(process.argv[1]);
		const result = admission.state === "acquired"
			? { state: admission.state, release: admission.transaction.release() }
			: admission;
		process.stdout.write(JSON.stringify(result));
	`;
	const probe = spawnSync(
		process.execPath,
		["--import", tsxLoader, "--input-type=module", "--eval", script, recorderRoot],
		{ encoding: "utf8", timeout: 2_000 },
	);
	expect(probe.error).toBeUndefined();
	expect(probe.status, probe.stderr).toBe(0);
	return JSON.parse(probe.stdout) as Record<string, unknown>;
}

function decodeCaptureWire(wire: Buffer): ReturnType<typeof decodeIncidentRecorderFrame>[] {
	const packets: Buffer[] = [];
	const corruptions: unknown[] = [];
	const decoder = new IncidentRecorderTransportDecoder(
		(packet) => packets.push(packet),
		(evidence) => corruptions.push(evidence),
	);
	decoder.push(wire);
	decoder.finish();
	expect(corruptions).toEqual([]);
	return packets.map((packet) => decodeIncidentRecorderFrame(packet));
}

async function waitForPid(agentDir: string): Promise<number> {
	const runsRoot = join(agentDir, "incident-recorder", "runs");
	for (let attempt = 0; attempt < 200; attempt++) {
		const runName = existsSync(runsRoot) ? readdirSync(runsRoot)[0] : undefined;
		if (runName) {
			try {
				const identity = JSON.parse(readFileSync(join(runsRoot, runName, "process.json"), "utf8")) as {
					pid: number;
					processStartId?: string;
				};
				if (!identity.processStartId || getProcessStartId(identity.pid) !== identity.processStartId) continue;
				livePids.set(identity.pid, identity.processStartId);
				return identity.pid;
			} catch {}
		}
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	throw new Error("timed out waiting for isolated fixture pid");
}

async function signalAndWait(
	target: ReturnType<typeof fixture>,
	signal: NodeJS.Signals,
): Promise<RecordedProcessResult> {
	const pending = record(target);
	const pid = await waitForPid(target.agentDir);
	await new Promise((resolve) => setTimeout(resolve, 50));
	signalFixture(pid, signal);
	const result = await pending;
	livePids.delete(pid);
	return result;
}

function appendEventScript(event: Record<string, unknown>): string {
	return `(()=>{const fs=require("node:fs");const path=require("node:path");const run=process.env.PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_RUN_DIR;fs.appendFileSync(path.join(run,"timeline.jsonl"),JSON.stringify({wallTime:new Date().toISOString(),monotonicNs:process.hrtime.bigint().toString(),pid:process.pid,...${JSON.stringify(event)}})+"\\n")})();`;
}

function readArtifactFiles(root: string): Array<{ path: string; bytes: Buffer }> {
	const result: Array<{ path: string; bytes: Buffer }> = [];
	const pending = [root];
	while (pending.length > 0) {
		const directory = pending.pop();
		if (!directory || !existsSync(directory)) continue;
		for (const entry of readdirSync(directory, { withFileTypes: true })) {
			const path = join(directory, entry.name);
			if (entry.isDirectory()) pending.push(path);
			else if (entry.isFile()) result.push({ path, bytes: readFileSync(path) });
		}
	}
	return result;
}

describe("incident recorder isolated fault evidence", () => {
	it("excludes diagnostic capability files from recursive manifests, events, and CAS artifacts", async () => {
		const target = fixture("");
		const descriptorSource = join(target.root, "descriptor-source");
		mkdirSync(descriptorSource, { mode: 0o700 });
		const capability = "diagnostic-capability-bytes-that-must-never-be-recorded";
		const secretPath = join(descriptorSource, `worker-1${INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX}`);
		writeFileSync(secretPath, capability, { mode: 0o600 });
		writeFileSync(join(descriptorSource, "worker.json"), "safe-descriptor", { mode: 0o600 });
		expect(isIncidentRecorderExcludedApplicationPath(secretPath)).toBe(true);
		writeFileSync(
			target.script,
			`${appendEventScript({
				type: "application_source_reference",
				source: "daemon_descriptor_directory",
				path: descriptorSource,
			})};process.abort();`,
			{ mode: 0o600 },
		);

		const result = await record(target);
		expect(result.classification).not.toBe("normal");
		const incidentDir = finalizeIncidentRecorderRun(
			{
				agentDir: target.agentDir,
				socketPath: target.socketPath,
				launch: {
					command: process.execPath,
					args: [target.script],
				},
				cwd: target.root,
			},
			result.runDir,
			{
				code: result.code,
				signal: result.signal,
				classification: result.classification,
			},
		);
		expect(incidentDir).toBeDefined();
		if (!incidentDir) throw new Error("incident finalization did not produce an artifact directory");
		const manifestPath = join(incidentDir, "raw-manifest.json");
		const manifest = readFileSync(manifestPath, "utf8");
		expect(manifest).toContain("worker.json");
		const forbidden = [
			capability,
			createHash("sha256").update(capability).digest("hex"),
			secretPath,
			secretPath.slice(descriptorSource.length + 1),
		];
		for (const artifact of readArtifactFiles(target.agentDir)) {
			const text = artifact.bytes.toString("utf8");
			for (const value of forbidden) {
				expect(text, `${artifact.path} contains excluded diagnostic capability evidence`).not.toContain(value);
			}
			expect(artifact.bytes.includes(Buffer.from(capability))).toBe(false);
		}
	});

	it("wraps every non-worker daemon launch once", () => {
		const daemonArgs = ["--mode", "daemon", "--daemon-socket", "/tmp/isolated.sock"];
		expect(shouldRecordSupervisorLaunch(daemonArgs, {}, false)).toBe(true);
		expect(shouldRecordSupervisorLaunch(daemonArgs, { [INCIDENT_RECORDER_CHILD_ENV]: "1" }, false)).toBe(false);
		expect(shouldRecordSupervisorLaunch(daemonArgs, {}, true)).toBe(false);
		expect(shouldRecordSupervisorLaunch([...daemonArgs, "--incident-recorder-service"], {}, false)).toBe(false);
		expect(shouldRecordSupervisorLaunch(daemonArgs, { [INCIDENT_RECORDER_SERVICE_ENV]: "1" }, false)).toBe(false);
		expect(shouldRecordSupervisorLaunch(["--mode", "json"], {}, false)).toBe(false);
	});

	it("admits derived storage by allocated filesystem blocks", async () => {
		const target = fixture("");
		const recorderRoot = join(target.agentDir, "incident-recorder");
		mkdirSync(recorderRoot, { recursive: true, mode: 0o700 });
		writeFileSync(join(recorderRoot, "one-byte"), "x", { mode: 0o600 });
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageByteCeiling: 1024,
			freeReserveBytes: 0,
		});
		await initializeStorageAccounting(compactor);
		expect(compactor.admitObservation(0)).toBe(false);
	});

	it("commits sequential fallback provider evidence synchronously through canonical CAS paths", () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const evidenceBytes = Buffer.from("opaque-provider-evidence\0with-exact-bytes", "utf8");

		ingestIncidentRecorderEvidence(runDir, "signal", evidenceBytes);
		expect(probeCasAdmissionSynchronously(recorderRoot)).toMatchObject({
			state: "acquired",
			release: { state: "released" },
		});
		const evidenceEnvelopes = readJsonLines(join(runDir, "evidence", "signal.jsonl"));
		expect(evidenceEnvelopes).toHaveLength(1);
		const evidenceReference = storedPayloadReference(evidenceEnvelopes[0]);
		expectCanonicalBlobAndLease(recorderRoot, runDir, evidenceReference, evidenceBytes);

		registerIncidentProviderSourceManifest(runDir, {
			provider: "sysdig",
			artifacts: [{ path: "/var/lib/sysdig/fixture.scap", format: ".scap", bytes: 17 }],
			configuration: { snaplen: 256 },
		});
		expect(probeCasAdmissionSynchronously(recorderRoot)).toMatchObject({
			state: "acquired",
			release: { state: "released" },
		});
		const manifestEnvelopes = readJsonLines(join(runDir, "evidence", "provider-source-manifests.jsonl"));
		expect(manifestEnvelopes).toHaveLength(1);
		const manifestReference = storedPayloadReference(manifestEnvelopes[0]);
		expectCanonicalBlobAndLease(recorderRoot, runDir, manifestReference);
		expect(Number(manifestEnvelopes[0].sequence)).toBe(Number(evidenceEnvelopes[0].sequence) + 1);

		expect(readRawRecordEnvelopes(runDir, "recorder-events").map((record) => record.type)).toEqual([
			"external_raw_evidence_ingested",
			"provider_source_manifest_registered",
		]);
		for (const artifact of readArtifactFiles(recorderRoot)) {
			expect(artifact.bytes.toString("utf8"), artifact.path).not.toContain("/proc/self/fd/");
		}
	});

	it("preserves a collision occupant and leases the synchronous collision fallback", () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const payload = Buffer.from("provider-collision-payload", "utf8");
		const digest = createHash("sha256").update(payload).digest("hex");
		const directory = join(recorderRoot, "cas", "sha256", digest.slice(0, 2));
		const occupiedPath = join(directory, `${digest}.blob`);
		const occupiedBytes = Buffer.from("deliberately-different-occupant", "utf8");
		mkdirSync(directory, { recursive: true, mode: 0o700 });
		writeFileSync(occupiedPath, occupiedBytes, { mode: 0o600 });

		ingestIncidentRecorderEvidence(runDir, "kernel", payload);
		expect(probeCasAdmissionSynchronously(recorderRoot)).toMatchObject({ state: "acquired" });
		const envelope = readJsonLines(join(runDir, "evidence", "kernel.jsonl"))[0];
		const reference = storedPayloadReference(envelope);
		expect(reference.path).toBe(occupiedPath);
		expect(reference.collisionFallbackPath).not.toBe(reference.path);
		expect(readFileSync(occupiedPath).equals(occupiedBytes)).toBe(true);
		expectCanonicalBlobAndLease(recorderRoot, runDir, reference, payload);
		expect(
			readRawRecordEnvelopes(runDir, "loss-accounting").some((record) => record.type === "raw_capture_loss"),
		).toBe(true);
	});

	it("serializes canonical public paths when fallback ingestion enters through a recorder alias", () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const aliasRoot = join(target.root, "recorder-alias");
		symlinkSync(recorderRoot, aliasRoot, "dir");
		const aliasRunDir = join(aliasRoot, "runs", runDir.slice(runDir.lastIndexOf("/") + 1));

		registerIncidentProviderSourceManifest(aliasRunDir, {
			provider: "atop",
			artifacts: [{ path: "/var/log/atop/atop_20260831", format: "stock-atop-raw" }],
		});
		expect(probeCasAdmissionSynchronously(recorderRoot)).toMatchObject({ state: "acquired" });
		const envelope = readJsonLines(join(runDir, "evidence", "provider-source-manifests.jsonl"))[0];
		const reference = storedPayloadReference(envelope);
		expectCanonicalBlobAndLease(recorderRoot, runDir, reference);
		expect(reference.path.startsWith(`${aliasRoot}/`)).toBe(false);
		expect(reference.collisionFallbackPath.startsWith(`${aliasRoot}/`)).toBe(false);
	});

	it("bounds fallback admission behind a live foreign CAS owner and never retries across a seal", async () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const holder = await startCasHolder(recorderRoot);
		let eventLoopProgressed = false;
		const eventLoopProgress = new Promise<void>((resolve) =>
			setTimeout(() => {
				eventLoopProgressed = true;
				resolve();
			}, 0),
		);
		const started = Date.now();
		ingestIncidentRecorderEvidence(runDir, "signal", { category: "signal", outcome: "observed" });
		registerIncidentProviderSourceManifest(runDir, { provider: "lttng", artifacts: [] });
		expect(Date.now() - started).toBeLessThan(250);
		await eventLoopProgress;
		expect(eventLoopProgressed).toBe(true);
		await new Promise((resolve) => setTimeout(resolve, 75));
		expect(getProcessStartId(holder.pid)).toBe(livePids.get(holder.pid));

		writeFileSync(join(runDir, "service-finalization-seal-intent.json"), "{}\n", { mode: 0o600 });
		ingestIncidentRecorderEvidence(runDir, "signal", { category: "signal", outcome: "observed" });
		registerIncidentProviderSourceManifest(runDir, { provider: "lttng", artifacts: [] });
		await holder.release();
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(existsSync(join(runDir, "raw-application"))).toBe(false);
	});

	it("retries fallback admission asynchronously and records explicit backpressure loss", async () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const holder = await startCasHolder(recorderRoot);
		const started = Date.now();
		ingestIncidentRecorderEvidence(runDir, "signal", { category: "signal", outcome: "observed" });
		registerIncidentProviderSourceManifest(runDir, { provider: "sysdig", artifacts: [] });
		expect(Date.now() - started).toBeLessThan(250);
		await new Promise((resolve) => setTimeout(resolve, 40));
		await holder.release();
		await waitUntil(
			() =>
				readRawRecordEnvelopes(runDir, "loss-accounting").some(
					(record) => record.type === "fallback_run_evidence_admission_loss",
				),
			"fallback admission loss evidence",
		);
		const records = readRawRecordEnvelopes(runDir, "loss-accounting");
		const loss = records.find((record) => record.type === "fallback_run_evidence_admission_loss");
		expect(loss).toBeDefined();
		const payloadBlob = loss?.payloadBlob as { path?: unknown } | undefined;
		expect(typeof payloadBlob?.path).toBe("string");
		const payload = readFileSync(String(payloadBlob?.path), "utf8");
		expect(payload).toContain("cross_process_cas_transaction_backpressure");
		expect(payload).toContain("lostAdmissions");
		expect(records.some((record) => record.type === "external_raw_evidence_ingested")).toBe(false);
		expect(records.some((record) => record.type === "provider_source_manifest_registered")).toBe(false);
		expect(existsSync(join(runDir, "evidence", "signal.jsonl"))).toBe(false);
		expect(existsSync(join(runDir, "evidence", "provider-source-manifests.jsonl"))).toBe(false);
	});

	it("rejects a new fallback admission under bounded pending pressure without evicting or writing outside CAS", () => {
		const target = fixture("");
		const { runDir } = fallbackRunDirectory(target.agentDir);

		expect(() => exerciseIncidentRecorderFallbackAdmissionPendingPressureForTest(runDir)).toThrow(
			"Fallback admission pending capacity is exhausted",
		);
		expect(fallbackAdmissionLossRecords(runDir)).toHaveLength(0);
		expect(existsSync(join(runDir, "raw-application"))).toBe(false);
	});

	it("propagates bounded pressure rejection through both public provider boundaries", async () => {
		for (const invoke of [
			(runDir: string) => ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("pressure-evidence")),
			(runDir: string) => registerIncidentProviderSourceManifest(runDir, { provider: "sysdig", artifacts: [] }),
		]) {
			const target = fixture("");
			const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
			const holder = await startCasHolder(recorderRoot);
			try {
				expect(() =>
					exerciseIncidentRecorderFallbackAdmissionPendingPressureForTest(runDir, () => invoke(runDir)),
				).toThrow("Fallback admission pending capacity is exhausted");
				expect(fallbackAdmissionLossRecords(runDir)).toHaveLength(0);
			} finally {
				await holder.release();
			}
		}
	});

	it("keeps a pressure-saturated provider admission observational after sealing", () => {
		const target = fixture("");
		const { runDir } = fallbackRunDirectory(target.agentDir);

		const pressure = exerciseIncidentRecorderFallbackAdmissionPendingPressureForTest(runDir, () => {
			writeFileSync(join(runDir, "service-finalization-seal-intent.json"), "{}\n", { mode: 0o600 });
			ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("after-seal"));
		});

		expect(pressure).toEqual({ pendingEntries: 4_096 });
		expect(fallbackAdmissionLossRecords(runDir)).toHaveLength(0);
		expect(existsSync(join(runDir, "raw-application"))).toBe(false);
	});

	it("normalizes retained schema-2 batches before provider CAS recovery", async () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		writeSchema2FallbackAdmissionLoss(runDir, 255);
		const holder = await startCasHolder(recorderRoot);
		try {
			ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("schema-two-pending"));
			await holder.release();
			ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("schema-two-recovery"));

			const control = JSON.parse(
				readFileSync(join(runDir, "service-finalization-fallback-admission-loss.json"), "utf8"),
			) as {
				schemaVersion: number;
				lostAdmissions: number;
				batches: Array<{
					lostAdmissions: number;
					rawAdmissions?: number;
					causes: Record<string, number>;
					rawCauses?: Record<string, number>;
				}>;
			};
			expect(control.schemaVersion).toBe(3);
			expect(control.lostAdmissions).toBe(256);
			expect(control.batches).toHaveLength(256);
			for (const retained of control.batches.slice(0, 255)) {
				expect(retained.rawAdmissions).toBe(retained.lostAdmissions);
				expect(retained.rawCauses).toEqual(retained.causes);
			}
		} finally {
			if (getProcessStartId(holder.pid) === livePids.get(holder.pid)) await holder.release();
		}
	});

	it("refuses schema-2 receipt overflow without replacing the 256 retained batches", async () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const originalControl = writeSchema2FallbackAdmissionLoss(runDir, 256);
		const holder = await startCasHolder(recorderRoot);
		try {
			ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("capacity-pending"));
			await holder.release();
			expect(() => ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("capacity-recovery"))).toThrow(
				"Fallback admission loss receipt capacity is exhausted",
			);
			expect(readFileSync(join(runDir, "service-finalization-fallback-admission-loss.json"), "utf8")).toBe(
				originalControl,
			);
			expect(fallbackAdmissionLossRecords(runDir)).toHaveLength(0);
		} finally {
			if (getProcessStartId(holder.pid) === livePids.get(holder.pid)) await holder.release();
		}
	});

	it("terminates pending admission as bounded control uncertainty after seal intent", async () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const holder = await startCasHolder(recorderRoot);
		const deferredRetryCallbacks: Array<() => void> = [];
		const placeholderTimers: NodeJS.Timeout[] = [];
		const nativeSetTimeout = globalThis.setTimeout;
		vi.spyOn(globalThis, "setTimeout").mockImplementation(((
			callback: (...args: unknown[]) => void,
			delay?: number,
		) => {
			if (delay !== undefined && delay >= 25 && delay <= 1_000) {
				deferredRetryCallbacks.push(callback);
				const placeholder = nativeSetTimeout(() => {}, 60_000);
				placeholder.unref();
				placeholderTimers.push(placeholder);
				return placeholder;
			}
			return nativeSetTimeout(callback, delay);
		}) as typeof setTimeout);
		try {
			ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("lost-before-seal"));
			expect(inspectIncidentRecorderFallbackAdmissionForTest(runDir)).toEqual({
				accountedLoss: 1,
				pending: true,
				retryScheduled: true,
			});
			const sealIntent = '{"state":"intent-only"}\n';
			writeFileSync(join(runDir, "service-finalization-seal-intent.json"), sealIntent, { mode: 0o600 });
			await holder.release();
			deferredRetryCallbacks[0]();

			expect(inspectIncidentRecorderFallbackAdmissionForTest(runDir)).toEqual({
				accountedLoss: 1,
				pending: false,
				retryScheduled: false,
			});
			expect(readFileSync(join(runDir, "service-finalization-seal-intent.json"), "utf8")).toBe(sealIntent);
			expect(fallbackAdmissionLossRecords(runDir)).toHaveLength(0);
			const control = JSON.parse(
				readFileSync(join(runDir, "service-finalization-fallback-admission-loss.json"), "utf8"),
			) as { lostAdmissions: number; batches: Array<{ lostAdmissions: number; rawAdmissions: number }> };
			expect(control.lostAdmissions).toBe(1);
			expect(control.batches).toMatchObject([{ lostAdmissions: 1, rawAdmissions: 0 }]);
		} finally {
			for (const timer of placeholderTimers) clearTimeout(timer);
			if (getProcessStartId(holder.pid) === livePids.get(holder.pid)) await holder.release();
		}
	});

	it("persists queued busy loss in the immediately successful provider capability without replay or duplicates", async () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const holder = await startCasHolder(recorderRoot);
		const deferredRetryCallbacks: Array<() => void> = [];
		const placeholderTimers: NodeJS.Timeout[] = [];
		const nativeSetTimeout = globalThis.setTimeout;
		vi.spyOn(globalThis, "setTimeout").mockImplementation(((
			callback: (...callbackArgs: unknown[]) => void,
			delay?: number,
			...args: unknown[]
		) => {
			if (delay !== undefined && delay >= 25 && delay <= 1_000) {
				deferredRetryCallbacks.push(() => callback(...args));
				const placeholder = nativeSetTimeout(() => {}, 60_000);
				placeholder.unref();
				placeholderTimers.push(placeholder);
				return placeholder;
			}
			return nativeSetTimeout(callback, delay, ...args);
		}) as typeof setTimeout);
		try {
			ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("lost-busy-provider-payload"));
			expect(deferredRetryCallbacks).toHaveLength(1);
			await holder.release();

			const committedPayload = Buffer.from("immediately-committed-provider-payload");
			ingestIncidentRecorderEvidence(runDir, "signal", committedPayload);
			const lossControl = JSON.parse(
				readFileSync(join(runDir, "service-finalization-fallback-admission-loss.json"), "utf8"),
			) as { lostAdmissions: number };
			expect(lossControl.lostAdmissions).toBe(1);
			expect(fallbackAdmissionLossPayload(runDir)).toContain("cross_process_cas_transaction_backpressure");
			const references = readJsonLines(join(runDir, "evidence", "signal.jsonl"));
			expect(references).toHaveLength(1);
			expect(readFileSync(chosenBlobPath(storedPayloadReference(references[0]))).equals(committedPayload)).toBe(
				true,
			);
			expect(readRawRecordEnvelopes(runDir, "recorder-events").map((record) => record.type)).toEqual([
				"external_raw_evidence_ingested",
			]);

			deferredRetryCallbacks[0]();
			await new Promise((resolve) => nativeSetTimeout(resolve, 75));
			expect(fallbackAdmissionLossRecords(runDir)).toHaveLength(1);
			expect(readJsonLines(join(runDir, "evidence", "signal.jsonl"))).toHaveLength(1);
		} finally {
			for (const timer of placeholderTimers) clearTimeout(timer);
		}
	});

	it("does not overlap a durable admission batch when control publication fails after recovery", async () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		const holder = await startCasHolder(recorderRoot);
		const deferredRetryCallbacks: Array<() => void> = [];
		const placeholderTimers: NodeJS.Timeout[] = [];
		const nativeSetTimeout = globalThis.setTimeout;
		let postRawSynchronizationCalls = 0;
		let clearPostRawSynchronization: (() => void) | undefined;
		vi.spyOn(globalThis, "setTimeout").mockImplementation(((
			callback: (...callbackArgs: unknown[]) => void,
			delay?: number,
			...args: unknown[]
		) => {
			if (delay !== undefined && delay >= 25 && delay <= 1_000) {
				deferredRetryCallbacks.push(() => callback(...args));
				const placeholder = nativeSetTimeout(() => {}, 60_000);
				placeholder.unref();
				placeholderTimers.push(placeholder);
				return placeholder;
			}
			return nativeSetTimeout(callback, delay, ...args);
		}) as typeof setTimeout);
		try {
			ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("lost-before-control-failure"));
			expect(deferredRetryCallbacks).toHaveLength(1);
			await holder.release();

			clearPostRawSynchronization = registerIncidentRecorderFallbackAdmissionPostRawTestSynchronization(() => {
				postRawSynchronizationCalls += 1;
				throw new Error("injected_post_raw_admission_loss_failure");
			});
			ingestIncidentRecorderEvidence(runDir, "signal", Buffer.from("lost-during-control-failure"));
			expect(postRawSynchronizationCalls).toBe(1);
			deferredRetryCallbacks[0]();

			await waitUntil(
				() => existsSync(join(runDir, "service-finalization-fallback-admission-loss.json")),
				"admission loss control recovery",
			);
			const lossControl = JSON.parse(
				readFileSync(join(runDir, "service-finalization-fallback-admission-loss.json"), "utf8"),
			) as { lostAdmissions: number };
			const payloads = fallbackAdmissionLossPayloads(runDir);
			expect(lossControl.lostAdmissions).toBe(2);
			expect(payloads.reduce((total, payload) => total + diagnosticObjectNumber(payload, "lostAdmissions"), 0)).toBe(
				lossControl.lostAdmissions,
			);
			expect(existsSync(join(runDir, "evidence", "signal.jsonl"))).toBe(false);
		} finally {
			clearPostRawSynchronization?.();
			casFaultHarness.enabled = false;
			casFaultHarness.beforeWithRoot = undefined;
			casFaultHarness.afterWithRoot = undefined;
			casFaultHarness.detachedEvidence = undefined;
			casFaultHarness.releasePending = false;
			casFaultHarness.capabilityError = false;
			for (const timer of placeholderTimers) clearTimeout(timer);
		}
	});

	it("keeps detached admission loss anchored away from a same-shaped successor root", async () => {
		const target = fixture("");
		const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
		let successorArtifacts: Array<{ path: string; bytes: Buffer }> = [];
		let initialAcquisitionCount = 0;
		let acquisitionCount = 0;
		try {
			casFaultHarness.enabled = true;
			casFaultHarness.afterWithRoot = replaceRecorderRoot;
			casFaultHarness.detachedEvidence = "durable";
			ingestIncidentRecorderEvidence(runDir, "kernel", Buffer.from("lost-before-root-replacement"));
			initialAcquisitionCount = casFaultHarness.acquisitions;

			casFaultHarness.afterWithRoot = undefined;
			casFaultHarness.detachedEvidence = undefined;
			mkdirSync(join(recorderRoot, "runs", basename(runDir)), { recursive: true, mode: 0o700 });
			ingestIncidentRecorderEvidence(runDir, "kernel", Buffer.from("lost-while-successor-present"));
			await new Promise((resolve) => setTimeout(resolve, 75));
			successorArtifacts = readArtifactFiles(recorderRoot);
			acquisitionCount = casFaultHarness.acquisitions;
		} finally {
			casFaultHarness.enabled = false;
			casFaultHarness.beforeWithRoot = undefined;
			casFaultHarness.afterWithRoot = undefined;
			casFaultHarness.detachedEvidence = undefined;
			casFaultHarness.releasePending = false;
			casFaultHarness.capabilityError = false;
			restoreRecorderRoot(recorderRoot);
		}
		expect(initialAcquisitionCount).toBe(1);
		expect(acquisitionCount).toBe(1);
		expect(successorArtifacts).toEqual([]);
		await waitUntil(() => fallbackAdmissionLossRecords(runDir).length === 1, "restored-root admission loss");
		const lossControl = JSON.parse(
			readFileSync(join(runDir, "service-finalization-fallback-admission-loss.json"), "utf8"),
		) as { lostAdmissions: number };
		expect(lossControl.lostAdmissions).toBe(2);
		expect(readJsonLines(join(runDir, "evidence", "kernel.jsonl"))).toHaveLength(1);
		await new Promise((resolve) => setTimeout(resolve, 75));
		expect(fallbackAdmissionLossRecords(runDir)).toHaveLength(1);
	});

	for (const scenario of [
		{
			name: "pre-callback durable detachment",
			phase: "before",
			evidence: "durable",
			reason: "root_detached_durable",
		},
		{
			name: "pre-callback pending detachment",
			phase: "before",
			evidence: "pending",
			reason: "root_detached_pending",
		},
		{
			name: "post-callback durable detachment",
			phase: "after",
			evidence: "durable",
			reason: "root_detached_durable",
		},
		{
			name: "post-callback pending detachment",
			phase: "after",
			evidence: "pending",
			reason: "root_detached_pending",
		},
		{ name: "pending release", phase: "release", reason: "release_pending" },
		{ name: "capability error", phase: "error", reason: "capability_error" },
	] as const) {
		it(`records one bounded uncertainty without replay after ${scenario.name}`, async () => {
			const target = fixture("");
			const { recorderRoot, runDir } = fallbackRunDirectory(target.agentDir);
			casFaultHarness.enabled = true;
			if (scenario.phase === "before") casFaultHarness.beforeWithRoot = replaceRecorderRoot;
			if (scenario.phase === "after") casFaultHarness.afterWithRoot = replaceRecorderRoot;
			if (scenario.phase === "release") casFaultHarness.releasePending = true;
			if (scenario.phase === "error") casFaultHarness.capabilityError = true;
			if ("evidence" in scenario) casFaultHarness.detachedEvidence = scenario.evidence;

			ingestIncidentRecorderEvidence(runDir, "kernel", Buffer.from(`noncommit-${scenario.phase}`));
			expect(casFaultHarness.acquisitions).toBe(1);
			expect(casFaultHarness.withRootCalls).toBe(1);
			expect(casFaultHarness.releaseCalls).toBe(1);
			if (casFaultHarness.retiredRoot) {
				expect(readArtifactFiles(recorderRoot)).toEqual([]);
			}

			casFaultHarness.enabled = false;
			casFaultHarness.beforeWithRoot = undefined;
			casFaultHarness.afterWithRoot = undefined;
			casFaultHarness.detachedEvidence = undefined;
			casFaultHarness.releasePending = false;
			casFaultHarness.capabilityError = false;
			restoreRecorderRoot(recorderRoot);
			await waitUntil(() => fallbackAdmissionLossRecords(runDir).length === 1, `${scenario.name} loss evidence`);
			const lossControl = JSON.parse(
				readFileSync(join(runDir, "service-finalization-fallback-admission-loss.json"), "utf8"),
			) as { lostAdmissions: number };
			expect(lossControl.lostAdmissions).toBe(1);
			expect(fallbackAdmissionLossPayload(runDir)).toContain(scenario.reason);
			const referencesPath = join(runDir, "evidence", "kernel.jsonl");
			const referenceCount = existsSync(referencesPath) ? readJsonLines(referencesPath).length : 0;
			expect(referenceCount).toBeLessThanOrEqual(1);
			expect(
				readRawRecordEnvelopes(runDir, "recorder-events").filter(
					(record) => record.type === "external_raw_evidence_ingested",
				).length,
			).toBeLessThanOrEqual(1);
			await new Promise((resolve) => setTimeout(resolve, 75));
			expect(fallbackAdmissionLossRecords(runDir)).toHaveLength(1);
			expect(existsSync(referencesPath) ? readJsonLines(referencesPath).length : 0).toBe(referenceCount);
		});
	}

	it("records a terminal spawn failure and expires it after three days", async () => {
		const target = fixture("");
		await expect(
			recordSupervisorProcess({
				agentDir: target.agentDir,
				socketPath: target.socketPath,
				launch: { command: join(target.root, "definitely-missing-executable"), args: [] },
				environment: {},
				cwd: target.root,
			}),
		).rejects.toThrow();
		const runsRoot = join(target.agentDir, "incident-recorder", "runs");
		const runDir = join(runsRoot, readdirSync(runsRoot)[0]);
		const terminal = JSON.parse(readFileSync(join(runDir, ".retention-terminal.json"), "utf8")) as Record<
			string,
			unknown
		>;
		expect(terminal.disposition).toBe("spawn_failed_before_target_identity");
		expect(((terminal.spawnError as Record<string, unknown>).ownProperties as Record<string, unknown>).code).toBe(
			"ENOENT",
		);
		mkdirSync(join(target.agentDir, "incidents"), { mode: 0o700 });
		runRetentionPassWithFixtureLease({
			agentDir: target.agentDir,
			nowMs: Date.now() + INCIDENT_DIAGNOSTIC_RETENTION_MS + 1,
		});
		expect(existsSync(runDir)).toBe(false);
	});

	it("finishes writing a derived frame with an empty payload", async () => {
		const target = fixture("");
		const output = join(target.root, "derived-frame.bin");
		const fd = openSync(output, "w", 0o600);
		const frame = encodeIncidentRecorderFrame(
			{
				runId: "11111111-1111-4111-8111-111111111111",
				runToken: "22222222-2222-4222-8222-222222222222",
				producerId: "33333333-3333-4333-8333-333333333333",
				occurrenceId: "44444444-4444-4444-8444-444444444444",
				producerSequence: 1n,
				wallTimeMs: 1n,
				monotonicNs: 1n,
				payloadKind: "derived-scalar",
				flags: INCIDENT_RECORDER_FRAME_FLAGS.firstChunk | INCIDENT_RECORDER_FRAME_FLAGS.lastChunk,
				chunkIndex: 0,
				chunkCount: 1,
				source: "supervisor-events",
				type: "supervisor_heartbeat",
				encoding: "none",
				metadata: {},
			},
			Buffer.alloc(0),
		);
		try {
			await Promise.race([
				new Promise<void>((resolve, reject) =>
					writeEncodedFramesToFd(fd, [frame], (error) => (error ? reject(error) : resolve())),
				),
				new Promise<never>((_, reject) =>
					setTimeout(() => reject(new Error("empty payload write did not finish")), 250),
				),
			]);
		} finally {
			closeSync(fd);
		}
		const decoded = decodeCaptureWire(readFileSync(output));
		expect(decoded).toHaveLength(1);
		expect(decoded[0].payload).toHaveLength(0);
	});

	it("carries the kernel collapse causal spine and exact retained stderr bytes over fd4", async () => {
		const target = fixture("");
		const script = fileURLToPath(new URL("./fixtures/incident-recorder-kernel-diagnostic.ts", import.meta.url));
		const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
		const environment: NodeJS.ProcessEnv = {
			...process.env,
			[INCIDENT_RECORDER_CAPTURE_FD_ENV]: "4",
			[INCIDENT_RECORDER_ROOT_FD_ENV]: "5",
			[INCIDENT_RECORDER_RUN_ID_ENV]: "99999999-9999-4999-8999-999999999999",
			[INCIDENT_RECORDER_RUN_TOKEN_ENV]: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			[INCIDENT_RECORDER_RUN_DIR_ENV]: target.root,
		};
		delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV];
		delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV];
		const recorderRootFd = openSync(target.root, "r");
		const child = spawn(process.execPath, ["--import", tsxLoader, script], {
			env: environment,
			stdio: ["ignore", "pipe", "pipe", "ignore", "pipe", recorderRootFd],
		});
		closeSync(recorderRootFd);
		if (!child.pid) throw new Error("kernel diagnostic fixture did not start");
		const pid = child.pid;
		const processStartId = getProcessStartId(pid);
		if (!processStartId) throw new Error("kernel diagnostic fixture has no stable process identity");
		livePids.set(pid, processStartId);
		const capture = child.stdio[4];
		if (!(capture instanceof Readable)) throw new Error("kernel diagnostic fixture has no capture pipe");
		const captureChunks: Buffer[] = [];
		let stdout = "";
		let stderr = "";
		capture.on("data", (chunk: Buffer) => captureChunks.push(Buffer.from(chunk)));
		child.stdout?.setEncoding("utf8");
		child.stderr?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			stdout += chunk;
		});
		child.stderr?.on("data", (chunk: string) => {
			stderr += chunk;
		});
		const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
			(resolveExit, rejectExit) => {
				child.once("error", rejectExit);
				child.once("close", (code, signal) => resolveExit({ code, signal }));
			},
		);
		livePids.delete(pid);
		expect(exit, stderr).toEqual({ code: 0, signal: null });
		const summary = JSON.parse(stdout.trim()) as { pid: number; processStartId?: string; stderrTail: string };
		expect(summary).toMatchObject({ pid, processStartId });

		const decoded = decodeCaptureWire(Buffer.concat(captureChunks));
		const lifecycleTypes = [
			"kernel_process_started",
			"kernel_ready",
			"kernel_execute_started",
			"kernel_channel_fault",
			"kernel_unexpected_exit",
		];
		for (const type of lifecycleTypes) {
			const frame = decoded.find((candidate) => candidate.header.type === type);
			expect(frame?.header.metadata).toMatchObject({
				sessionId: "session-kernel-capture",
				kernelInstanceId: "kernel-instance-capture",
				kernelPid: 42424,
				kernelProcessStartId: "proc:kernel-capture",
				launchMode: "direct",
			});
		}
		expect(decoded.find((frame) => frame.header.type === "kernel_channel_fault")?.header.metadata).toMatchObject({
			requestMsgId: "request-message-capture",
			crashPhase: "executing",
			channel: "iopub",
			reason: "iopub fixture fault",
		});
		expect(decoded.find((frame) => frame.header.type === "kernel_unexpected_exit")?.header.metadata).toMatchObject({
			requestMsgId: "request-message-capture",
			crashPhase: "executing",
			code: null,
			signal: "SIGKILL",
			reason: "process_exit",
			sourceBytes: 64 * 1024,
			retainedBytes: 8,
			sourceTruncated: true,
		});
		const stderrFrame = decoded.find((frame) => frame.header.type === "kernel_stderr_tail");
		expect(stderrFrame?.header).toMatchObject({
			source: "supervisor-events",
			payloadKind: "exact-bytes",
			encoding: "exact-bytes",
			metadata: {
				sessionId: "session-kernel-capture",
				kernelInstanceId: "kernel-instance-capture",
				requestMsgId: "request-message-capture",
				crashPhase: "executing",
				sourceBytes: 64 * 1024,
				retainedBytes: 8,
				sourceTruncated: true,
			},
		});
		expect(stderrFrame?.payload.toString("hex")).toBe(summary.stderrTail);
	}, 15_000);

	it("keeps inherited fd4 single-owner under two-process saturation", async () => {
		const target = fixture("");
		const script = fileURLToPath(new URL("./fixtures/incident-recorder-shared-fd.ts", import.meta.url));
		const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
		const environment: NodeJS.ProcessEnv = {
			...process.env,
			[INCIDENT_RECORDER_CAPTURE_FD_ENV]: "4",
			[INCIDENT_RECORDER_ROOT_FD_ENV]: "5",
			[INCIDENT_RECORDER_RUN_ID_ENV]: "11111111-1111-4111-8111-111111111111",
			[INCIDENT_RECORDER_RUN_TOKEN_ENV]: "22222222-2222-4222-8222-222222222222",
			[INCIDENT_RECORDER_RUN_DIR_ENV]: target.root,
			PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES: String(256 * 1024),
			PRIME_TEST_TSX_LOADER: tsxLoader,
		};
		delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV];
		delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV];
		const recorderRootFd = openSync(target.root, "r");
		const child = spawn(process.execPath, ["--import", tsxLoader, script], {
			env: environment,
			stdio: ["ignore", "pipe", "pipe", "ignore", "pipe", recorderRootFd],
		});
		closeSync(recorderRootFd);
		if (!child.pid) throw new Error("shared fd fixture did not start");
		const ownerPid = child.pid;
		const ownerStartId = getProcessStartId(ownerPid);
		if (!ownerStartId) throw new Error("shared fd fixture has no stable process identity");
		livePids.set(ownerPid, ownerStartId);
		const capture = child.stdio[4];
		if (!(capture instanceof Readable)) throw new Error("shared fd fixture has no capture pipe");
		let stdout = "";
		let stderr = "";
		child.stdout?.setEncoding("utf8");
		child.stderr?.setEncoding("utf8");
		child.stderr?.on("data", (chunk: string) => {
			stderr += chunk;
		});
		const summary = await new Promise<Record<string, any>>((resolveSummary, rejectSummary) => {
			child.once("error", rejectSummary);
			child.stdout?.on("data", (chunk: string) => {
				stdout += chunk;
				const newline = stdout.indexOf("\n");
				if (newline < 0) return;
				try {
					resolveSummary(JSON.parse(stdout.slice(0, newline)) as Record<string, any>);
				} catch (error) {
					rejectSummary(error);
				}
			});
			child.once("close", (code, signal) =>
				rejectSummary(
					new Error(
						`shared fd fixture exited before summary: code=${String(code)} signal=${String(signal)} stderr=${stderr}`,
					),
				),
			);
		});
		// Reading starts only after the bounded producer queue has saturated.
		const chunks: Buffer[] = [];
		capture.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
		const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
			(resolveExit, rejectExit) => {
				child.once("error", rejectExit);
				child.once("close", (code, signal) => resolveExit({ code, signal }));
			},
		);
		livePids.delete(ownerPid);
		expect(exit, stderr).toEqual({ code: 0, signal: null });
		expect(summary.pid).toBe(ownerPid);
		expect(summary.processStartId).toBe(ownerStartId);
		expect(summary.configured).toBe(true);
		expect(summary.accepted).toBeGreaterThan(0);
		expect(summary.rejected).toBeGreaterThan(0);
		expect(summary.accepted + summary.rejected).toBe(summary.attempted);
		expect(summary.contender).toMatchObject({ configured: false, admission: { accepted: false, reason: "stopped" } });
		expect(summary.contenderExit).toEqual({ code: 0, signal: null });
		expect(getProcessStartId(summary.contender.pid)).not.toBe(summary.contender.processStartId);
		const ownerClaim = summary.ownerClaim as Record<string, unknown>;
		expect(ownerClaim).toMatchObject({
			schemaVersion: 1,
			runId: "11111111-1111-4111-8111-111111111111",
			runToken: "22222222-2222-4222-8222-222222222222",
			pid: ownerPid,
			processStartId: ownerStartId,
		});
		expect(ownerClaim.machineId).toMatch(/^[0-9a-f]{32}$/i);
		expect(ownerClaim.bootId).toMatch(/^[0-9a-f-]{36}$/i);
		expect(ownerClaim.ownerNonce).toMatch(/^[0-9a-f-]{36}$/i);

		const wire = Buffer.concat(chunks);
		const decoded = decodeCaptureWire(wire);
		const exact = decoded.filter((frame) => frame.header.type === "shared_fd_owner");
		expect(exact).toHaveLength(summary.accepted);
		expect(new Set(exact.map((frame) => frame.header.occurrenceId)).size).toBe(exact.length);
		for (let index = 0; index < exact.length; index += 1) {
			const frame = exact[index];
			expect(frame.header.producerSequence).toBe(BigInt(index + 1));
			expect(frame.header.metadata).toMatchObject({
				producerPid: ownerPid,
				producerStartId: ownerStartId,
			});
			expect(frame.payload.length).toBe(24 * 1024);
			expect(frame.payload.readUInt32BE(0)).toBe(index);
			expect(frame.payload.subarray(4).every((byte) => byte === index % 251)).toBe(true);
		}
		expect(decoded.some((frame) => frame.header.type === "shared_fd_contender")).toBe(false);
		const loss = decoded.filter((frame) => frame.header.type === "capture_channel_loss_checkpoint").at(-1);
		expect(loss?.header.metadata).toMatchObject({
			lostRecords: summary.rejected,
			lostBytes: summary.rejectedBytes,
		});
		const terminal = decoded.find((frame) => frame.header.type === "capture_channel_terminal");
		expect(terminal?.header.metadata).toMatchObject({
			lostRecords: summary.rejected,
			lostBytes: summary.rejectedBytes,
		});
	}, 15_000);

	it("includes calls made after stop begins in terminal loss accounting", async () => {
		const target = fixture("");
		const script = fileURLToPath(new URL("./fixtures/incident-recorder-shared-fd.ts", import.meta.url));
		const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
		const recorderRootFd = openSync(target.root, "r");
		const child = spawn(process.execPath, ["--import", tsxLoader, script, "stop-race"], {
			env: {
				...process.env,
				[INCIDENT_RECORDER_CAPTURE_FD_ENV]: "4",
				[INCIDENT_RECORDER_ROOT_FD_ENV]: "5",
				[INCIDENT_RECORDER_RUN_ID_ENV]: "55555555-5555-4555-8555-555555555555",
				[INCIDENT_RECORDER_RUN_TOKEN_ENV]: "66666666-6666-4666-8666-666666666666",
				[INCIDENT_RECORDER_RUN_DIR_ENV]: target.root,
			},
			stdio: ["ignore", "pipe", "pipe", "ignore", "pipe", recorderRootFd],
		});
		closeSync(recorderRootFd);
		if (!child.pid) throw new Error("stop-race fixture did not start");
		const pid = child.pid;
		const processStartId = getProcessStartId(pid);
		if (!processStartId) throw new Error("stop-race fixture has no stable process identity");
		livePids.set(pid, processStartId);
		const capture = child.stdio[4];
		if (!(capture instanceof Readable)) throw new Error("stop-race fixture has no capture pipe");
		const captureChunks: Buffer[] = [];
		let stdout = "";
		let stderr = "";
		capture.on("data", (chunk: Buffer) => captureChunks.push(Buffer.from(chunk)));
		child.stdout?.setEncoding("utf8");
		child.stderr?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			stdout += chunk;
		});
		child.stderr?.on("data", (chunk: string) => {
			stderr += chunk;
		});
		const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
			(resolveExit, rejectExit) => {
				child.once("error", rejectExit);
				child.once("close", (code, signal) => resolveExit({ code, signal }));
			},
		);
		livePids.delete(pid);
		expect(exit, stderr).toEqual({ code: 0, signal: null });
		const summary = JSON.parse(stdout.trim()) as Record<string, any>;
		expect(summary).toMatchObject({
			pid,
			processStartId,
			configured: true,
			first: { accepted: true },
			afterStopBegan: { accepted: false, reason: "terminal_reserved" },
		});
		const wire = Buffer.concat(captureChunks);
		const decoded = decodeCaptureWire(wire);
		expect(decoded.some((frame) => frame.header.type === "after_stop_began")).toBe(false);
		const loss = decoded.find((frame) => frame.header.type === "capture_channel_loss_checkpoint");
		expect(loss?.header.metadata).toMatchObject({ lostRecords: 1, lostBytes: 24 * 1024 });
		const terminal = decoded.find((frame) => frame.header.type === "capture_channel_terminal");
		expect(terminal?.header.metadata).toMatchObject({
			lostRecords: 1,
			lostBytes: 24 * 1024,
			drainTimeoutLostRecords: 0,
			drainTimeoutLostBytes: 0,
			drainTimeoutUncertainRecords: 0,
			drainTimeoutUncertainBytes: 0,
		});
	}, 15_000);

	it("reports definite and uncertain drain-timeout tail loss in the terminal frame", async () => {
		const target = fixture("");
		const script = fileURLToPath(new URL("./fixtures/incident-recorder-shared-fd.ts", import.meta.url));
		const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
		const recorderRootFd = openSync(target.root, "r");
		const child = spawn(process.execPath, ["--import", tsxLoader, script, "stop-timeout"], {
			env: {
				...process.env,
				[INCIDENT_RECORDER_CAPTURE_FD_ENV]: "4",
				[INCIDENT_RECORDER_ROOT_FD_ENV]: "5",
				[INCIDENT_RECORDER_RUN_ID_ENV]: "77777777-7777-4777-8777-777777777777",
				[INCIDENT_RECORDER_RUN_TOKEN_ENV]: "88888888-8888-4888-8888-888888888888",
				[INCIDENT_RECORDER_RUN_DIR_ENV]: target.root,
			},
			stdio: ["ignore", "pipe", "pipe", "ignore", "pipe", recorderRootFd],
		});
		closeSync(recorderRootFd);
		if (!child.pid) throw new Error("stop-timeout fixture did not start");
		const pid = child.pid;
		const processStartId = getProcessStartId(pid);
		if (!processStartId) throw new Error("stop-timeout fixture has no stable process identity");
		livePids.set(pid, processStartId);
		const capture = child.stdio[4];
		if (!(capture instanceof Readable)) throw new Error("stop-timeout fixture has no capture pipe");
		const captureChunks: Buffer[] = [];
		const delayedDrain = setTimeout(() => {
			capture.on("data", (chunk: Buffer) => captureChunks.push(Buffer.from(chunk)));
		}, 1_500);
		let stdout = "";
		let stderr = "";
		child.stdout?.setEncoding("utf8");
		child.stderr?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			stdout += chunk;
		});
		child.stderr?.on("data", (chunk: string) => {
			stderr += chunk;
		});
		const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
			(resolveExit, rejectExit) => {
				child.once("error", rejectExit);
				child.once("close", (code, signal) => resolveExit({ code, signal }));
			},
		);
		clearTimeout(delayedDrain);
		livePids.delete(pid);
		expect(exit, stderr).toEqual({ code: 0, signal: null });
		const summary = JSON.parse(stdout.trim()) as Record<string, any>;
		expect(summary.accepted).toBeGreaterThan(1);
		expect(summary.rejected).toBeGreaterThan(0);
		const wire = Buffer.concat(captureChunks);
		const decoded = decodeCaptureWire(wire);
		const terminal = decoded.find((frame) => frame.header.type === "capture_channel_terminal");
		expect(terminal).toBeDefined();
		const metadata = terminal?.header.metadata ?? {};
		expect(metadata.drainTimeoutLostRecords).toEqual(expect.any(Number));
		expect(metadata.drainTimeoutLostBytes).toBe(Number(metadata.drainTimeoutLostRecords) * 24 * 1024);
		expect(metadata.drainTimeoutUncertainRecords).toBe(1);
		expect(metadata.drainTimeoutUncertainBytes).toBe(24 * 1024);
		expect(metadata.lostRecords).toBe(summary.rejected + Number(metadata.drainTimeoutLostRecords));
		expect(metadata.lostBytes).toBe(summary.rejectedBytes + Number(metadata.drainTimeoutLostBytes));
	}, 15_000);

	it("self-disables a fork-copied emitter identity before any inherited-fd write", async () => {
		const target = fixture("");
		const script = fileURLToPath(new URL("./fixtures/incident-recorder-shared-fd.ts", import.meta.url));
		const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
		const environment: NodeJS.ProcessEnv = {
			...process.env,
			[INCIDENT_RECORDER_CAPTURE_FD_ENV]: "4",
			[INCIDENT_RECORDER_ROOT_FD_ENV]: "5",
			[INCIDENT_RECORDER_RUN_ID_ENV]: "33333333-3333-4333-8333-333333333333",
			[INCIDENT_RECORDER_RUN_TOKEN_ENV]: "44444444-4444-4444-8444-444444444444",
			[INCIDENT_RECORDER_RUN_DIR_ENV]: target.root,
		};
		delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV];
		delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV];
		const recorderRootFd = openSync(target.root, "r");
		const child = spawn(process.execPath, ["--import", tsxLoader, script, "fork-copy-identity-mismatch"], {
			env: environment,
			stdio: ["ignore", "pipe", "pipe", "ignore", "pipe", recorderRootFd],
		});
		closeSync(recorderRootFd);
		if (!child.pid) throw new Error("fork-copy fixture did not start");
		const pid = child.pid;
		const processStartId = getProcessStartId(pid);
		if (!processStartId) throw new Error("fork-copy fixture has no stable process identity");
		livePids.set(pid, processStartId);
		const capture = child.stdio[4];
		if (!(capture instanceof Readable)) throw new Error("fork-copy fixture has no capture pipe");
		const captureChunks: Buffer[] = [];
		capture.on("data", (chunk: Buffer) => captureChunks.push(Buffer.from(chunk)));
		let stdout = "";
		let stderr = "";
		child.stdout?.setEncoding("utf8");
		child.stderr?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			stdout += chunk;
		});
		child.stderr?.on("data", (chunk: string) => {
			stderr += chunk;
		});
		const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
			(resolveExit, rejectExit) => {
				child.once("error", rejectExit);
				child.once("close", (code, signal) => resolveExit({ code, signal }));
			},
		);
		livePids.delete(pid);
		expect(exit, stderr).toEqual({ code: 0, signal: null });
		const summary = JSON.parse(stdout.trim()) as Record<string, any>;
		expect(summary).toMatchObject({
			pid,
			processStartId,
			configured: true,
			admission: { accepted: false, reason: "stopped" },
		});
		expect(Buffer.concat(captureChunks)).toHaveLength(0);
	}, 15_000);

	it("classifies an uncaught exception and preserves its Node report", async () => {
		const result = await record(fixture('throw new Error("isolated uncaught fault");'));
		expect(result).toMatchObject({ code: 1, signal: null, classification: "uncaught_exception" });
		expect(readdirSync(join(result.runDir, "raw-reports")).some((name) => name.endsWith(".json"))).toBe(true);
	});

	it("classifies a native abort from the exact terminating signal", async () => {
		const result = await record(fixture("process.abort();"));
		expect(result.code).toBeNull();
		expect(result.signal).toBe("SIGABRT");
		expect(result.classification).toBe("native_abort");
	});

	it("preserves caught SIGTERM evidence and exit code", async () => {
		const source = `${appendEventScript({ type: "ready" })}process.on("SIGTERM",()=>{${appendEventScript({ type: "signal_received", signal: "SIGTERM" })}process.exit(143)});setInterval(()=>{},1000);`;
		const result = await signalAndWait(fixture(source), "SIGTERM");
		expect(result).toMatchObject({ code: 143, signal: null, classification: "signal_sigterm" });
	});

	it("preserves an external SIGKILL", async () => {
		const result = await signalAndWait(fixture("setInterval(()=>{},1000);"), "SIGKILL");
		expect(result).toMatchObject({ code: null, signal: "SIGKILL", classification: "signal_sigkill" });
	});

	it("detects a live event-loop heartbeat stall from journal-backed evidence without recovering the process", async () => {
		const target = journalBackedFaultFixture("event_loop_hang");
		const prepared = prepareJournalBackedServiceEnvironment(target);
		let service: RunningJournalBackedService | undefined;
		let finalizer: RunningJournalBackedService | undefined;
		try {
			const pending = recordJournalBackedFault(target);
			const pid = await waitForPid(target.agentDir);
			await waitForJournalRecord(target, "supervisor_heartbeat");
			service = await startJournalBackedService(target, prepared);
			expect(() => signalFixture(pid, 0)).not.toThrow();
			await waitForJournalRecord(target, "heartbeat_stalled");
			await service.stop();
			signalFixture(pid, "SIGKILL");
			const result = await pending;
			livePids.delete(pid);
			expect(result).toMatchObject({ signal: "SIGKILL", classification: "signal_sigkill" });
			finalizer = await startJournalBackedService(target);
			const incidentDir = await waitForPublishedIncident(target, result.runDir);
			const summary = JSON.parse(readFileSync(join(incidentDir, "summary.json"), "utf8")) as Record<string, unknown>;
			expect(summary).toMatchObject({ classification: "event_loop_hang", causeLayer: "application" });
			const events = readPublishedRunHistoryEvents(incidentDir);
			expect(events).toContainEqual(
				expect.objectContaining({
					type: "supervisor_heartbeat",
					source: "supervisor-events",
					metadata: expect.objectContaining({ socketExists: false }),
				}),
			);
			const stalled = events.find((event) => event.type === "heartbeat_stalled");
			expect(stalled).toMatchObject({
				source: "recorder-events",
				type: "heartbeat_stalled",
				encoding: "utf8-json/derived-diagnostic-json-v2",
				payloadKind: "derived-scalar",
				cas: {
					digest: expect.stringMatching(/^[0-9a-f]{64}$/),
					bytes: expect.any(Number),
					path: expect.any(String),
				},
			});
			if (!stalled) throw new Error("published heartbeat_stalled event missing");
			const cas = stalled.cas as { digest: string; bytes: number; path: string };
			const body = readFileSync(cas.path);
			expect(body.byteLength).toBe(cas.bytes);
			expect(createHash("sha256").update(body).digest("hex")).toBe(cas.digest);
			expect(JSON.parse(body.toString("utf8"))).toEqual({
				schemaVersion: 2,
				value: {
					$diagnosticType: "object",
					id: 1,
					properties: [["childPid", pid]],
				},
			});
		} finally {
			await finalizer?.stop().catch(() => undefined);
			await service?.stop().catch(() => undefined);
			prepared.restore();
		}
	});

	it("detects loss of an isolated live supervisor socket from journal-backed evidence", async () => {
		const target = journalBackedFaultFixture("socket_loss");
		const prepared = prepareJournalBackedServiceEnvironment(target);
		let service: RunningJournalBackedService | undefined;
		let finalizer: RunningJournalBackedService | undefined;
		try {
			const pending = recordJournalBackedFault(target);
			const pid = await waitForPid(target.agentDir);
			await waitForJournalRecord(target, "supervisor_heartbeat");
			service = await startJournalBackedService(target, prepared);
			expect(() => signalFixture(pid, 0)).not.toThrow();
			await waitForJournalRecord(target, "socket_lost");
			await service.stop();
			signalFixture(pid, "SIGKILL");
			const result = await pending;
			livePids.delete(pid);
			expect(result).toMatchObject({ signal: "SIGKILL", classification: "signal_sigkill" });
			finalizer = await startJournalBackedService(target);
			const incidentDir = await waitForPublishedIncident(target, result.runDir);
			const summary = JSON.parse(readFileSync(join(incidentDir, "summary.json"), "utf8")) as Record<string, unknown>;
			expect(summary).toMatchObject({ classification: "socket_loss", causeLayer: "unknown" });
			const events = readPublishedRunHistoryEvents(incidentDir);
			expect(events).toContainEqual(
				expect.objectContaining({
					type: "supervisor_heartbeat",
					source: "supervisor-events",
					metadata: expect.objectContaining({ socketExists: true }),
				}),
			);
			expect(events.some((event) => event.type === "socket_lost")).toBe(true);
		} finally {
			await finalizer?.stop().catch(() => undefined);
			await service?.stop().catch(() => undefined);
			prepared.restore();
		}
	});

	it("captures a real worker timeout through the wrapper fd4 and journal", async () => {
		const target = journalBackedFaultFixture("worker_response_hang");
		const prepared = prepareJournalBackedServiceEnvironment(target);
		let pid: number | undefined;
		try {
			const pending = recordJournalBackedFault(target);
			pid = await waitForPid(target.agentDir);
			await waitForJournalRecord(target, "worker_request_end");
			await waitForJournalRecord(target, "worker_transport_outbound");

			const journal = readJsonLines(target.journalPath);
			const event = (type: string): Record<string, unknown> => {
				const match = journal.find((record) => record.type === type);
				if (!match) throw new Error(`journal has no ${type} record`);
				return match;
			};
			const start = event("worker_request_start");
			const timeout = event("worker_request_timeout");
			const end = event("worker_request_end");
			const startMetadata = start.metadata as Record<string, unknown>;
			const timeoutMetadata = timeout.metadata as Record<string, unknown>;
			const endMetadata = end.metadata as Record<string, unknown>;
			const requestId = startMetadata.requestId;
			expect(requestId).toMatch(/^worker_[1-9][0-9]*$/);
			expect(startMetadata).toMatchObject({ requestId, requestType: "list", timeoutMs: 25 });
			expect(timeoutMetadata).toMatchObject({ requestId, requestType: "list", timeoutMs: 25 });
			expect(endMetadata).toMatchObject({ requestId, requestType: "list", timeoutMs: 25, outcome: "timeout" });
			expect(
				journal.some(
					(record) =>
						record.type === "worker_request_end" &&
						(record.metadata as Record<string, unknown>)?.outcome === "error",
				),
			).toBe(false);
			const durationMs = endMetadata.durationMs;
			expect(typeof durationMs).toBe("number");
			expect(Number.isFinite(durationMs)).toBe(true);
			expect(Number(durationMs)).toBeGreaterThan(0);

			const outbound = event("worker_transport_outbound");
			expect(outbound).toMatchObject({
				source: "worker-transport",
				type: "worker_transport_outbound",
				payloadKind: "exact-bytes",
				encoding: "exact-bytes",
			});
			const requestType = "list";
			const command = { type: requestType, id: requestId };
			const header = { kind: "command" as const, requestId, commandType: requestType };
			const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
			const payloadBytes = Buffer.from(serializeJsonLine(command), "utf8");
			const expectedOutbound = encodePrivateFrame(header, payloadBytes);
			expect(Buffer.from(String(outbound.payloadBase64), "base64")).toEqual(expectedOutbound);
			expect(expectedOutbound.readUInt32BE(0)).toBe(headerBytes.length);
			expect(expectedOutbound.readUInt32BE(4)).toBe(payloadBytes.length);
			expect(expectedOutbound.subarray(8, 8 + headerBytes.length).toString("utf8")).toBe(
				headerBytes.toString("utf8"),
			);
			expect(expectedOutbound.subarray(8 + headerBytes.length).toString("utf8")).toBe(serializeJsonLine(command));

			signalFixture(pid, "SIGKILL");
			const result = await pending;
			livePids.delete(pid);
			pid = undefined;
			expect(result).toMatchObject({ signal: "SIGKILL", classification: "signal_sigkill" });
		} finally {
			if (pid !== undefined) {
				try {
					if (getProcessStartId(pid) === livePids.get(pid)) process.kill(pid, "SIGKILL");
				} catch {}
			}
			prepared.restore();
		}
	});

	it("finalizes a live worker response hang from journal-backed evidence without recovering the process", async () => {
		const target = journalBackedFaultFixture("worker_response_hang");
		const prepared = prepareJournalBackedServiceEnvironment(target);
		let service: RunningJournalBackedService | undefined;
		let finalizer: RunningJournalBackedService | undefined;
		try {
			const pending = recordJournalBackedFault(target);
			const pid = await waitForPid(target.agentDir);
			await waitForJournalRecord(target, "worker_request_end");
			const workerRequestStart = readJsonLines(target.journalPath).find(
				(record) => record.type === "worker_request_start",
			);
			const workerRequestId = (workerRequestStart?.metadata as Record<string, unknown> | undefined)?.requestId;
			expect(workerRequestId).toMatch(/^worker_[1-9][0-9]*$/);
			service = await startJournalBackedService(target, prepared);
			expect(() => signalFixture(pid, 0)).not.toThrow();
			await waitForJournalRecord(target, "worker_hang_detected");
			await service.stop();
			signalFixture(pid, "SIGKILL");
			const result = await pending;
			livePids.delete(pid);
			expect(result).toMatchObject({ signal: "SIGKILL", classification: "signal_sigkill" });
			finalizer = await startJournalBackedService(target);
			const incidentDir = await waitForPublishedIncident(target, result.runDir);
			const summary = JSON.parse(readFileSync(join(incidentDir, "summary.json"), "utf8")) as Record<string, unknown>;
			expect(summary).toMatchObject({ classification: "worker_response_hang", causeLayer: "application" });
			const events = readPublishedRunHistoryEvents(incidentDir);
			expect(events).toContainEqual(
				expect.objectContaining({
					type: "worker_request_end",
					source: "supervisor-events",
					metadata: expect.objectContaining({
						requestId: workerRequestId,
						outcome: "timeout",
					}),
				}),
			);
			const publishedWorkerTimeout = events.find((event) => {
				const metadata = event.metadata;
				return (
					event.type === "worker_request_end" &&
					typeof metadata === "object" &&
					metadata !== null &&
					(metadata as Record<string, unknown>).outcome === "timeout"
				);
			});
			const publishedWorkerTimeoutMetadata = publishedWorkerTimeout?.metadata as Record<string, unknown> | undefined;
			expect(publishedWorkerTimeoutMetadata).toMatchObject({
				requestId: workerRequestId,
				requestType: "list",
				timeoutMs: 25,
				outcome: "timeout",
			});
			expect(Number.isFinite(publishedWorkerTimeoutMetadata?.durationMs)).toBe(true);
			expect(Number(publishedWorkerTimeoutMetadata?.durationMs)).toBeGreaterThan(0);
			expect(events.some((event) => event.type === "worker_hang_detected")).toBe(true);
		} finally {
			await finalizer?.stop().catch(() => undefined);
			await service?.stop().catch(() => undefined);
			prepared.restore();
		}
	});
});
