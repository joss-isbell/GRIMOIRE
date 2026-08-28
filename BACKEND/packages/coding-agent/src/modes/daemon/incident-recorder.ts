import { type ChildProcess, type SpawnSyncReturns, spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	chmodSync,
	closeSync,
	type Dir,
	type Dirent,
	existsSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	lstatSync,
	mkdirSync,
	opendirSync,
	openSync,
	readdirSync,
	readFileSync,
	readSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import {
	type CliSubprocessLaunchSpec,
	createCliSubprocessEnv,
	createCliSubprocessLaunchSpec,
} from "../../cli/subprocess-launch.js";
import { getAgentDir, VERSION } from "../../config.js";
import { getProcessStartId } from "../../core/session-lease.js";
import {
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
	INCIDENT_RECORDER_SOCKET_ENV,
} from "./incident-recorder-env.js";
import {
	baselineLinuxIncidentEvidence,
	hasPositiveLinuxCgroupOomKillDelta,
	type LinuxMemorySummary,
	readLinuxIncidentEvidenceCorrelation,
	sampleLinuxIncidentEvidence,
} from "./incident-recorder-linux.js";
import {
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	INCIDENT_RETENTION_SERVICE_BUDGET,
	runIncidentRetentionPass,
} from "./incident-recorder-retention.js";
import {
	configureIncidentCaptureEmitter,
	emitIncidentDerived,
	type IncidentRecorderAdmission,
	sanitizeIncidentCausalFields,
	stopIncidentCaptureEmitter,
	stopIncidentCaptureEmitterOnExit,
} from "./incident-recorder-writer.js";

export {
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
	INCIDENT_RECORDER_SOCKET_ENV,
};

export const INCIDENT_RECORDER_WORKER_ID_ENV = "PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_WORKER_ID";

const EVENT_FILE_NAME = "timeline.jsonl";
const SERVICE_EVENT_FILE_NAME = "service-timeline.jsonl";
const SUPERVISOR_EVENT_FILE_NAME = "supervisor-timeline.jsonl";
const CAUSAL_TIMELINE_FILES = [
	"timeline.previous.jsonl",
	EVENT_FILE_NAME,
	"service-timeline.previous.jsonl",
	SERVICE_EVENT_FILE_NAME,
	"supervisor-timeline.previous.jsonl",
	SUPERVISOR_EVENT_FILE_NAME,
] as const;
const ACTIVE_MARKER_FILE_NAME = ".recorder-active";
const FINALIZER_CLAIM_FILE_NAME = ".incident-finalizer-claim";
const HEARTBEAT_INTERVAL_MS = 1_000;
const STALL_THRESHOLD_MS = 10_000;

const LINUX_BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id";

function linuxBootId(): string | undefined {
	if (process.platform !== "linux") return undefined;
	try {
		const value = readFileSync(LINUX_BOOT_ID_PATH, "utf8").trim();
		return /^[0-9a-f-]{36}$/i.test(value) ? value : undefined;
	} catch {
		return undefined;
	}
}

function linuxMachineId(): string | undefined {
	if (process.platform !== "linux") return undefined;
	try {
		const value = readFileSync("/etc/machine-id", "utf8").trim();
		return /^[0-9a-f]{32}$/i.test(value) ? value : undefined;
	} catch {
		return undefined;
	}
}

type CausalEventSource = "recorder-events" | "supervisor-events" | "loss-accounting";

export const INCIDENT_RECORDER_LIMITS = {
	eventFileBytes: 1024 * 1024,
	evidenceFileBytes: 256 * 1024,
	nodeReportFileBytes: 128 * 1024,
	perBundleBytes: 8 * 1024 * 1024,
	retentionAgeMs: INCIDENT_DIAGNOSTIC_RETENTION_MS,
	maxDirectoryEntries: 256,
} as const;

export interface IncidentRecorderEvent {
	type: string;
	wallTime: string;
	monotonicNs: string;
	pid: number;
	[key: string]: unknown;
}

export interface RecordedProcessResult {
	code: number | null;
	signal: NodeJS.Signals | null;
	runDir: string;
	incidentDir?: string;
	classification: string;
}

export interface RecordProcessOptions {
	agentDir: string;
	socketPath: string;
	launch: CliSubprocessLaunchSpec;
	cwd?: string;
	environment?: NodeJS.ProcessEnv;
}

interface BoundedRead {
	value: Buffer;
	truncated: boolean;
}

function nowFields(): Pick<IncidentRecorderEvent, "wallTime" | "monotonicNs"> {
	return { wallTime: new Date().toISOString(), monotonicNs: process.hrtime.bigint().toString() };
}

function readBoundedPrefix(path: string, limit: number): BoundedRead | undefined {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "r");
		const chunks: Buffer[] = [];
		let total = 0;
		while (total <= limit) {
			const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, limit + 1 - total));
			const count = readSync(descriptor, chunk, 0, chunk.length, null);
			if (count === 0) break;
			chunks.push(chunk.subarray(0, count));
			total += count;
		}
		const combined = Buffer.concat(chunks, total);
		return { value: combined.subarray(0, limit), truncated: combined.length > limit };
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function readSmallJson<T>(path: string, _limit = INCIDENT_RECORDER_LIMITS.evidenceFileBytes): T | undefined {
	try {
		return JSON.parse(readFileSync(path, "utf8")) as T;
	} catch {
		return undefined;
	}
}

function writePrivateJson(path: string, value: unknown, _limit = INCIDENT_RECORDER_LIMITS.evidenceFileBytes): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	let serialized: string;
	try {
		serialized = `${JSON.stringify(value, null, 2)}\n`;
	} catch (error) {
		serialized = `${JSON.stringify({ unavailable: true, serializationError: serializeError(error) }, null, 2)}\n`;
	}
	writeFileSync(path, serialized, { mode: 0o600 });
	chmodSync(path, 0o600);
}

function fsyncPrivateDirectory(path: string): void {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
		fsyncSync(descriptor);
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function writePrivateJsonAtomicSync(path: string, value: unknown): void {
	const directory = dirname(path);
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
	let descriptor: number | undefined;
	try {
		descriptor = openSync(temporary, "wx", 0o600);
		const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
		let offset = 0;
		while (offset < bytes.length) {
			const written = writeSync(descriptor, bytes, offset, bytes.length - offset);
			if (written <= 0) throw new Error("Private JSON write made no progress");
			offset += written;
		}
		fsyncSync(descriptor);
		closeSync(descriptor);
		descriptor = undefined;
		renameSync(temporary, path);
		chmodSync(path, 0o600);
		fsyncPrivateDirectory(directory);
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
		try {
			rmSync(temporary, { force: true });
		} catch {}
	}
}

function publishTerminalDisposition(runDir: string, value: Record<string, unknown>): boolean {
	try {
		writePrivateJsonAtomicSync(join(runDir, ".retention-terminal.json"), value);
		rmSync(join(runDir, ACTIVE_MARKER_FILE_NAME), { force: true });
		fsyncPrivateDirectory(runDir);
		return true;
	} catch {
		return false;
	}
}

function safeToken(value: unknown, fallback = "other"): string {
	return typeof value === "string" && /^[A-Za-z0-9_.:+-]{1,80}$/.test(value) ? value : fallback;
}

function finiteNumber(value: unknown): number | undefined {
	return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function serializeError(error: unknown, seen = new Map<object, number>()): Record<string, unknown> {
	if (!(error instanceof Error)) return { thrown: encodeDiagnosticValue(error, seen) };
	const ownProperties: Record<string, unknown> = {};
	for (const key of Reflect.ownKeys(error)) {
		const descriptor = Object.getOwnPropertyDescriptor(error, key);
		const name = typeof key === "symbol" ? key.toString() : key;
		if (descriptor && "value" in descriptor) ownProperties[name] = encodeDiagnosticValue(descriptor.value, seen);
	}
	return {
		name: error.name,
		message: error.message,
		stack: error.stack,
		cause: encodeDiagnosticValue(error.cause, seen),
		ownProperties,
	};
}

function encodeDiagnosticValue(value: unknown, seen = new Map<object, number>()): unknown {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") {
		return Number.isFinite(value) ? value : { $diagnosticType: "number", value: String(value) };
	}
	if (typeof value === "undefined") return { $diagnosticType: "undefined" };
	if (typeof value === "bigint") return { $diagnosticType: "bigint", value: value.toString() };
	if (typeof value === "symbol") return { $diagnosticType: "symbol", value: value.description };
	if (typeof value === "function") {
		return {
			$diagnosticType: "function",
			name: value.name,
			length: value.length,
			source: Function.prototype.toString.call(value),
		};
	}
	if (seen.has(value)) return { $diagnosticType: "reference", id: seen.get(value) };
	const id = seen.size + 1;
	seen.set(value, id);
	if (Buffer.isBuffer(value)) {
		return { $diagnosticType: "buffer", id, encoding: "base64", value: value.toString("base64") };
	}
	if (value instanceof Uint8Array) {
		return {
			$diagnosticType: "uint8array",
			id,
			encoding: "base64",
			value: Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("base64"),
		};
	}
	if (value instanceof Date) return { $diagnosticType: "date", id, value: value.toISOString() };
	if (value instanceof RegExp) return { $diagnosticType: "regexp", id, source: value.source, flags: value.flags };
	if (value instanceof Error) return { $diagnosticType: "error", id, ...serializeError(value, seen) };
	if (value instanceof Map) {
		return {
			$diagnosticType: "map",
			id,
			entries: [...value.entries()].map(([key, child]) => [
				encodeDiagnosticValue(key, seen),
				encodeDiagnosticValue(child, seen),
			]),
		};
	}
	if (value instanceof Set) {
		return { $diagnosticType: "set", id, values: [...value].map((child) => encodeDiagnosticValue(child, seen)) };
	}
	const properties = Reflect.ownKeys(value).map((key) => {
		const descriptor = Object.getOwnPropertyDescriptor(value, key);
		const encodedKey =
			typeof key === "symbol" ? { type: "symbol", value: key.description } : { type: "string", value: key };
		if (!descriptor) return { key: encodedKey, unavailable: true };
		return {
			key: encodedKey,
			enumerable: descriptor.enumerable,
			configurable: descriptor.configurable,
			...(descriptor.get || descriptor.set
				? {
						get: descriptor.get ? Function.prototype.toString.call(descriptor.get) : undefined,
						set: descriptor.set ? Function.prototype.toString.call(descriptor.set) : undefined,
					}
				: { writable: descriptor.writable, value: encodeDiagnosticValue(descriptor.value, seen) }),
		};
	});
	return {
		$diagnosticType: Array.isArray(value) ? "array" : "object",
		id,
		prototype: Object.getPrototypeOf(value)?.constructor?.name,
		properties,
	};
}

function causalTimelineFileName(): string {
	return process.env[INCIDENT_RECORDER_SERVICE_ENV] === "1" ? SERVICE_EVENT_FILE_NAME : EVENT_FILE_NAME;
}

function rotateCausalTimelineIfNeeded(runDir: string, fileName: string, incomingBytes: number): boolean {
	const path = join(runDir, fileName);
	try {
		const stat = lstatSync(path);
		if (!stat.isFile() || stat.isSymbolicLink()) return false;
		if (stat.size + incomingBytes <= INCIDENT_RECORDER_LIMITS.eventFileBytes) return true;
		const previous = join(runDir, fileName.replace(/\.jsonl$/, ".previous.jsonl"));
		rmSync(previous, { force: true });
		renameSync(path, previous);
		fsyncPrivateDirectory(runDir);
		return true;
	} catch (error) {
		return Boolean((error as NodeJS.ErrnoException).code === "ENOENT");
	}
}

export function recordIncidentRecorderCausalEvent(
	runDir: string,
	type: string,
	fields: Record<string, unknown> = {},
	trusted: { source?: CausalEventSource; occurrenceId?: string } = {},
): boolean {
	if (!/^[a-z][a-z0-9_]{0,79}$/.test(type)) return false;
	let descriptor: number | undefined;
	try {
		const observed = nowFields();
		const source: CausalEventSource =
			trusted.source === "supervisor-events"
				? "supervisor-events"
				: trusted.source === "loss-accounting"
					? "loss-accounting"
					: "recorder-events";
		const occurrenceId =
			typeof trusted.occurrenceId === "string" &&
			/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(trusted.occurrenceId)
				? trusted.occurrenceId
				: randomUUID();
		const producerPid = process.pid;
		const trustedEnvelope = {
			type,
			...observed,
			pid: producerPid,
			source,
			occurrenceId,
			producerPid,
			producerProcessStartId: getProcessStartId(producerPid),
		};
		const safeFields = sanitizeIncidentCausalFields(fields);
		let bytes = Buffer.from(`${JSON.stringify({ ...safeFields, ...trustedEnvelope })}\n`, "utf8");
		if (bytes.length > 3584)
			bytes = Buffer.from(`${JSON.stringify({ ...trustedEnvelope, fieldsTruncated: true })}\n`, "utf8");
		if (bytes.length > 3584) return false;
		const fileName = causalTimelineFileName();
		if (!rotateCausalTimelineIfNeeded(runDir, fileName, bytes.length)) return false;
		descriptor = openSync(
			join(runDir, fileName),
			fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW,
			0o600,
		);
		if (writeSync(descriptor, bytes) !== bytes.length) return false;
		fsyncSync(descriptor);
		return true;
	} catch {
		return false;
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

function appendCausalRunEvent(
	runDir: string,
	source: CausalEventSource,
	type: string,
	fields: Record<string, unknown> = {},
): IncidentRecorderAdmission {
	const occurrenceId = randomUUID();
	const accepted = recordIncidentRecorderCausalEvent(runDir, type, sanitizeIncidentCausalFields(fields), {
		source,
		occurrenceId,
	});
	return accepted
		? { accepted: true, occurrenceId }
		: { accepted: false, occurrenceId, reason: "durable_sink_unavailable" };
}

function appendRunEvent(runDir: string, event: { type: string; [key: string]: unknown }): void {
	const { type, ...fields } = event;
	appendCausalRunEvent(runDir, "recorder-events", type, fields);
}

export function appendSupervisorDiagnosticEvent(
	type: string,
	fields: Record<string, unknown> = {},
): IncidentRecorderAdmission {
	return emitIncidentDerived("supervisor-events", type, fields);
}

export async function flushSupervisorDiagnosticCapture(): Promise<void> {
	await stopIncidentCaptureEmitter();
}

export type IncidentDiagnosticRole = "supervisor" | "worker";

export interface IncidentDiagnosticContext {
	workerId?: string;
	activeSessionId?: string;
	sessionId?: string;
}

function recordWorkerFatalEvidenceGap(
	runDir: string,
	correlation: Record<string, unknown>,
	origin: "uncaughtException" | "unhandledRejection",
	phase: "fatal_event" | "fatal_report_summary",
	reason: string,
	triggerRequestId: string,
): void {
	appendCausalRunEvent(runDir, "loss-accounting", "worker_fatal_evidence_gap", {
		...correlation,
		origin,
		phase,
		reason,
		triggerRequestId,
	});
}

export function installIncidentDiagnosticHooks(
	socketPath: string,
	role: IncidentDiagnosticRole,
	context: Readonly<IncidentDiagnosticContext>,
): () => void {
	const runDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
	if (!runDir || !configureIncidentCaptureEmitter()) return () => {};
	const correlation = { role, ...context };
	const nodeReport = role === "worker" ? process.report : undefined;
	const previousWorkerReportOnUncaughtException = nodeReport?.reportOnUncaughtException;
	if (nodeReport) nodeReport.reportOnUncaughtException = false;
	appendSupervisorDiagnosticEvent(`${role}_started`, {
		...correlation,
		socketPath,
		runtimeCategory: process.versions.bun ? "bun" : process.versions.node ? "node" : "foreign",
		nodeVersion: process.versions.node,
		runtimeIdentity: {
			release: process.release,
			versions: process.versions,
			execPath: process.execPath,
			argv: process.argv,
		},
		nodeFatalReportsEnabled: process.release.name === "node" && !process.versions.bun,
		workerFatalReportSummaryEnabled: role === "worker" && nodeReport !== undefined,
	});
	const heartbeat = setInterval(() => {
		appendSupervisorDiagnosticEvent(`${role}_heartbeat`, {
			...correlation,
			memory: process.memoryUsage(),
			uptimeSeconds: process.uptime(),
			socketExists: existsSync(socketPath),
		});
	}, HEARTBEAT_INTERVAL_MS);
	heartbeat.unref();
	const fatal = (error: Error, origin: "uncaughtException" | "unhandledRejection") => {
		const fatalAdmission = appendSupervisorDiagnosticEvent(
			origin === "unhandledRejection" ? "unhandled_rejection" : "fatal_exception",
			{
				...correlation,
				origin,
				error,
			},
		);
		if (role !== "worker") return;
		if (!fatalAdmission.accepted || fatalAdmission.fieldsTruncated) {
			recordWorkerFatalEvidenceGap(
				runDir,
				correlation,
				origin,
				"fatal_event",
				fatalAdmission.accepted ? "bounded_event_fields_truncated" : fatalAdmission.reason,
				fatalAdmission.occurrenceId,
			);
		}
		let reportSummary: Record<string, unknown>;
		let unavailable = false;
		try {
			reportSummary = minimizeWorkerNodeReport(nodeReport?.getReport(error));
			unavailable = nodeReport === undefined;
		} catch {
			reportSummary = { schemaVersion: 1, unavailable: true };
			unavailable = true;
		}
		const reportAdmission = appendSupervisorDiagnosticEvent("worker_fatal_report", {
			...correlation,
			origin,
			exception: workerFatalErrorSummary(error),
			report: reportSummary,
		});
		if (unavailable || !reportAdmission.accepted || reportAdmission.fieldsTruncated) {
			recordWorkerFatalEvidenceGap(
				runDir,
				correlation,
				origin,
				"fatal_report_summary",
				unavailable
					? "node_report_summary_unavailable"
					: reportAdmission.accepted
						? "bounded_event_fields_truncated"
						: reportAdmission.reason,
				reportAdmission.occurrenceId,
			);
		}
	};
	const exit = () => stopIncidentCaptureEmitterOnExit();
	process.on("uncaughtExceptionMonitor", fatal);
	process.on("exit", exit);
	return () => {
		clearInterval(heartbeat);
		process.off("uncaughtExceptionMonitor", fatal);
		process.off("exit", exit);
		if (nodeReport && previousWorkerReportOnUncaughtException !== undefined)
			nodeReport.reportOnUncaughtException = previousWorkerReportOnUncaughtException;
	};
}

export function installSupervisorDiagnosticHooks(socketPath: string): () => void {
	return installIncidentDiagnosticHooks(socketPath, "supervisor", {});
}

function safeRunName(): string {
	return `${new Date().toISOString().replaceAll(":", "-")}-${randomUUID()}`;
}

function createRunDir(agentDir: string): string {
	const root = join(agentDir, "incident-recorder", "runs");
	mkdirSync(root, { recursive: true, mode: 0o700 });
	chmodSync(root, 0o700);
	const runDir = join(root, safeRunName());
	mkdirSync(runDir, { mode: 0o700 });
	mkdirSync(join(runDir, "reports"), { mode: 0o700 });
	mkdirSync(join(runDir, "raw-reports"), { mode: 0o700 });
	writePrivateJson(join(runDir, ACTIVE_MARKER_FILE_NAME), {
		role: "wrapper-proxy",
		machineId: linuxMachineId(),
		bootId: linuxBootId(),
		pid: process.pid,
		processStartId: getProcessStartId(process.pid),
		created: nowFields(),
	});
	return runDir;
}

export function shouldRecordSupervisorLaunch(
	args: readonly string[],
	environment: NodeJS.ProcessEnv = process.env,
	workerProcess = false,
): boolean {
	const modeIndex = args.indexOf("--mode");
	return (
		modeIndex !== -1 &&
		args[modeIndex + 1] === "daemon" &&
		!args.includes("--incident-recorder-service") &&
		environment[INCIDENT_RECORDER_SERVICE_ENV] !== "1" &&
		!workerProcess &&
		environment[INCIDENT_RECORDER_CHILD_ENV] !== "1"
	);
}

export function createRecordedSupervisorChildLaunch(args: readonly string[]): CliSubprocessLaunchSpec {
	return createCliSubprocessLaunchSpec(args, process.execPath, process.execArgv, process.argv[1]);
}

const SENSITIVE_FLAG =
	/(?:^|[-_])(prompt|body|launch[-_]?env|env(?:ironment)?|auth(?:orization)?|api[-_]?key|token|secret|password)(?:$|[-_])/i;

export interface IncidentCommandSummary {
	argumentCount: number;
	flagCategories: string[];
	positionalCount: number;
	redactedValueCount: number;
	nulSeparated: boolean;
}

export function summarizeIncidentCommandLine(args: readonly string[], nulSeparated = false): IncidentCommandSummary {
	const flagCategories = new Set<string>();
	let positionalCount = 0;
	let redactedValueCount = 0;
	let redactNext = false;
	for (const argument of args.slice(0, INCIDENT_RECORDER_LIMITS.maxDirectoryEntries)) {
		if (redactNext) {
			redactedValueCount += 1;
			redactNext = false;
			continue;
		}
		if (!argument.startsWith("-")) {
			positionalCount += 1;
			continue;
		}
		const equals = argument.indexOf("=");
		const flag = (equals === -1 ? argument : argument.slice(0, equals)).slice(0, 80);
		if (SENSITIVE_FLAG.test(flag)) {
			flagCategories.add("sensitive");
			if (equals === -1) redactNext = true;
			else redactedValueCount += 1;
			continue;
		}
		if (flag.startsWith("--report")) flagCategories.add("node_report");
		else if (["--mode", "--daemon-socket", "--agent-dir"].includes(flag)) flagCategories.add("daemon_control");
		else flagCategories.add("other_flag");
		if (equals !== -1) redactedValueCount += 1;
	}
	return {
		argumentCount: args.length,
		flagCategories: [...flagCategories].slice(0, 64),
		positionalCount,
		redactedValueCount,
		nulSeparated,
	};
}

function provenNodeLaunch(launch: CliSubprocessLaunchSpec): boolean {
	return (
		process.release.name === "node" &&
		Boolean(process.versions.node) &&
		!process.versions.bun &&
		resolve(launch.command) === resolve(process.execPath)
	);
}

function hasMatchingProcessIdentity(pid: number, processStartId: string | undefined): processStartId is string {
	return Boolean(processStartId) && getProcessStartId(pid) === processStartId;
}

function hasDurableFinalizationBarrier(runDir: string): boolean {
	if (existsSync(join(runDir, ACTIVE_MARKER_FILE_NAME))) return false;
	const terminal = readSmallJson<{
		completed?: { wallTime?: unknown; monotonicNs?: unknown };
		exitCode?: unknown;
		exitSignal?: unknown;
	}>(join(runDir, ".retention-terminal.json"));
	if (
		!terminal?.completed ||
		typeof terminal.completed.wallTime !== "string" ||
		!Number.isFinite(Date.parse(terminal.completed.wallTime)) ||
		typeof terminal.completed.monotonicNs !== "string" ||
		!/^\d+$/.test(terminal.completed.monotonicNs)
	)
		return false;
	return (
		Object.hasOwn(terminal, "exitCode") &&
		Object.hasOwn(terminal, "exitSignal") &&
		(terminal.exitCode === null || Number.isSafeInteger(terminal.exitCode)) &&
		(terminal.exitSignal === null ||
			(typeof terminal.exitSignal === "string" && /^SIG[A-Z0-9]+$/.test(terminal.exitSignal)))
	);
}

function readExpectedExitDisposition(runDir: string): { code: number | null; signal: NodeJS.Signals | null } {
	const value = readSmallJson<{ exitCode?: unknown; exitSignal?: unknown }>(join(runDir, ".retention-terminal.json"));
	return {
		code: typeof value?.exitCode === "number" ? value.exitCode : null,
		signal: typeof value?.exitSignal === "string" ? (value.exitSignal as NodeJS.Signals) : null,
	};
}

function readEvents(runDir: string): IncidentRecorderEvent[] {
	const candidates: IncidentRecorderEvent[] = [];
	for (const fileName of CAUSAL_TIMELINE_FILES) {
		const bounded = readBoundedPrefix(join(runDir, fileName), INCIDENT_RECORDER_LIMITS.eventFileBytes);
		if (!bounded || bounded.truncated) continue;
		for (const line of bounded.value.toString("utf8").split("\n").filter(Boolean)) {
			try {
				candidates.push(JSON.parse(line) as IncidentRecorderEvent);
			} catch {}
		}
	}
	const unique = new Map<string, IncidentRecorderEvent>();
	for (const event of candidates) {
		const key = `${event.type} ${event.wallTime} ${event.monotonicNs} ${event.pid}`;
		if (!unique.has(key)) unique.set(key, event);
	}
	return [...unique.values()].sort((left, right) => {
		const wall = left.wallTime.localeCompare(right.wallTime);
		return wall !== 0 ? wall : left.monotonicNs.localeCompare(right.monotonicNs);
	});
}

function numericTree(value: unknown, depth = 0): unknown {
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value === "boolean") return value;
	if (!value || typeof value !== "object" || Array.isArray(value) || depth > 3) return undefined;
	const result: Record<string, unknown> = {};
	for (const [key, child] of Object.entries(value).slice(0, 128)) {
		if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key) || SENSITIVE_FLAG.test(key)) continue;
		const minimized = numericTree(child, depth + 1);
		if (minimized !== undefined) result[key] = minimized;
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

function nodeReportCategory(value: unknown): string {
	if (typeof value !== "string") return "other";
	const normalized = value.toLowerCase();
	if (normalized.includes("exception")) return "exception";
	if (normalized.includes("fatal")) return "fatal_error";
	if (normalized.includes("signal") || normalized.startsWith("sig")) return "signal";
	if (normalized.includes("javascript api")) return "javascript_api";
	return "other";
}

function minimizeNodeReport(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object") return { schemaVersion: 1, unavailable: true };
	const report = value as Record<string, unknown>;
	const headerValue = report.header;
	const header = headerValue && typeof headerValue === "object" ? (headerValue as Record<string, unknown>) : {};
	const minimizedHeader: Record<string, unknown> = {};
	for (const key of ["reportVersion", "processId", "threadId", "wordSize"]) {
		const numeric = finiteNumber(header[key]);
		if (numeric !== undefined) minimizedHeader[key] = numeric;
	}
	for (const key of ["event", "trigger"]) {
		if (header[key] !== undefined) minimizedHeader[key] = nodeReportCategory(header[key]);
	}
	for (const key of ["nodejsVersion", "arch", "platform"]) {
		if (header[key] !== undefined) minimizedHeader[key] = safeToken(header[key]);
	}
	if (typeof header.dumpEventTime === "string" && /^\d{4}-\d{2}-\d{2}T/.test(header.dumpEventTime))
		minimizedHeader.dumpEventTime = header.dumpEventTime.slice(0, 32);
	const libuv = Array.isArray(report.libuv) ? report.libuv : [];
	const knownHandleTypes = new Set([
		"async",
		"check",
		"fs_event",
		"fs_poll",
		"idle",
		"pipe",
		"poll",
		"prepare",
		"process",
		"signal",
		"tcp",
		"timer",
		"tty",
		"udp",
	]);
	const handleCounts: Record<string, number> = {};
	for (const handle of libuv.slice(0, 512)) {
		if (!handle || typeof handle !== "object") continue;
		const observedType = (handle as Record<string, unknown>).type;
		const type = typeof observedType === "string" && knownHandleTypes.has(observedType) ? observedType : "other";
		handleCounts[type] = (handleCounts[type] ?? 0) + 1;
	}
	return {
		schemaVersion: 1,
		header: minimizedHeader,
		resourceUsage: numericTree(report.resourceUsage),
		uvthreadResourceUsage: numericTree(report.uvthreadResourceUsage),
		resourceLimits: numericTree(report.resourceLimits),
		javascriptHeap: numericTree(report.javascriptHeap),
		libuvHandleCounts: handleCounts,
		workerCount: Array.isArray(report.workers) ? report.workers.length : undefined,
	};
}

function shallowNumericRecord(value: unknown): Record<string, number | boolean> | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const result: Record<string, number | boolean> = {};
	for (const [key, child] of Object.entries(value).slice(0, 32)) {
		if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key)) continue;
		if (typeof child === "boolean" || (typeof child === "number" && Number.isFinite(child))) result[key] = child;
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

function minimizeWorkerNodeReport(value: unknown): Record<string, unknown> {
	const minimized = minimizeNodeReport(value);
	return {
		schemaVersion: 1,
		header: minimized.header,
		resourceUsage: shallowNumericRecord(minimized.resourceUsage),
		uvthreadResourceUsage: shallowNumericRecord(minimized.uvthreadResourceUsage),
		javascriptHeap: shallowNumericRecord(minimized.javascriptHeap),
		libuvHandleCounts: minimized.libuvHandleCounts,
		workerCount: minimized.workerCount,
	};
}

function workerFatalErrorSummary(error: unknown): Record<string, unknown> {
	const failure = error instanceof Error ? error : undefined;
	const code = failure ? (failure as Error & { code?: unknown }).code : undefined;
	const fingerprintSource = failure?.stack ?? failure?.message ?? String(error);
	return {
		name: safeToken(failure?.name, "unknown_error"),
		...(typeof code === "string" ? { code: safeToken(code) } : {}),
		reason: `sha256:${createHash("sha256").update(fingerprintSource).digest("hex")}`,
		stackLineCount: failure?.stack?.split("\n").length,
	};
}

interface NodeReportCaptureState {
	directory?: Dir;
	pending: string[];
	discoveryComplete: boolean;
}
const nodeReportCaptureStates = new Map<string, NodeReportCaptureState>();

function writeImmutableJsonOnce(path: string, value: unknown): void {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "wx", 0o600);
		const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
		let offset = 0;
		while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset, bytes.length - offset);
		fsyncSync(descriptor);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
	const directory = openSync(dirname(path), fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
	try {
		fsyncSync(directory);
	} finally {
		closeSync(directory);
	}
}

async function sanitizeNodeReports(runDir: string, _removeRawDirectory = false): Promise<"pending" | "complete"> {
	const rawReportsDir = join(runDir, "raw-reports");
	const reportsDir = join(runDir, "reports");
	mkdirSync(reportsDir, { recursive: true, mode: 0o700 });
	let state = nodeReportCaptureStates.get(runDir);
	if (!state) {
		state = { pending: [], discoveryComplete: false };
		nodeReportCaptureStates.set(runDir, state);
		while (nodeReportCaptureStates.size > 4096)
			nodeReportCaptureStates.delete(nodeReportCaptureStates.keys().next().value as string);
	}
	if (!state.directory && !state.discoveryComplete) {
		try {
			state.directory = opendirSync(rawReportsDir);
		} catch {
			state.discoveryComplete = true;
		}
	}
	for (let scanned = 0; state.directory && scanned < 8; scanned += 1) {
		let entry: Dirent | null;
		try {
			entry = state.directory.readSync();
		} catch {
			entry = null;
		}
		if (!entry) {
			try {
				state.directory.closeSync();
			} catch {}
			state.directory = undefined;
			state.discoveryComplete = true;
			break;
		}
		if (
			!entry.isFile() ||
			!entry.name.endsWith(".json") ||
			entry.name === "manifest.json" ||
			entry.name.endsWith(".reference.json") ||
			entry.name.endsWith(".pending.json") ||
			entry.name.endsWith(".closed.json") ||
			entry.name.endsWith(".error.json")
		)
			continue;
		if (
			existsSync(join(rawReportsDir, `${entry.name}.reference.json`)) ||
			existsSync(join(rawReportsDir, `${entry.name}.error.json`))
		)
			continue;
		state.pending.push(entry.name);
		if (state.pending.length >= 32) break;
	}
	const entryName = state.pending[0];
	if (!entryName) return state.discoveryComplete ? "complete" : "pending";
	const sourcePath = join(rawReportsDir, entryName);
	let sourceMetadata: Record<string, unknown>;
	const closePublicationPath = join(rawReportsDir, `${entryName}.closed.json`);
	try {
		const stat = lstatSync(sourcePath, { bigint: true });
		if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("node_report_source_not_regular_file");
		sourceMetadata = {
			path: sourcePath,
			dev: stat.dev.toString(),
			ino: stat.ino.toString(),
			bytes: Number(stat.size),
			mtimeMs: Number(stat.mtimeMs),
			ctimeMs: Number(stat.ctimeMs),
		};
		writeImmutableJsonOnce(closePublicationPath, {
			schemaVersion: 1,
			state: "closed",
			proof: "target_process_stopped",
			source: sourceMetadata,
		});
	} catch (error) {
		writeImmutableJsonOnce(join(rawReportsDir, `${entryName}.error.json`), {
			schemaVersion: 1,
			state: "error",
			reason: serializeError(error),
		});
		state.pending.shift();
		return "pending";
	}
	const captured = readBoundedPrefix(sourcePath, 4 * 1024 * 1024);
	if (!captured || captured.truncated) {
		writeImmutableJsonOnce(join(rawReportsDir, `${entryName}.error.json`), {
			schemaVersion: 1,
			state: "gap_or_uncertainty",
			source: sourceMetadata,
			reason: captured ? "node_report_exceeded_4_mib_bound" : "node_report_unreadable",
		});
		state.pending.shift();
		return "pending";
	}
	const digest = createHash("sha256").update(captured.value).digest("hex");
	const report = readJsonValue(captured.value);
	if (!report || typeof report !== "object" || Array.isArray(report)) {
		writeImmutableJsonOnce(join(rawReportsDir, `${entryName}.error.json`), {
			schemaVersion: 1,
			state: "gap_or_uncertainty",
			source: sourceMetadata,
			reason: "node_report_json_invalid",
		});
		state.pending.shift();
		return "pending";
	}
	writePrivateJson(join(reportsDir, `report-${digest.slice(0, 16)}.json`), {
		...minimizeNodeReport(report),
		causalCapture: { sha256: digest, bytes: captured.value.length, source: sourceMetadata },
	});
	writeImmutableJsonOnce(join(rawReportsDir, `${entryName}.reference.json`), {
		schemaVersion: 1,
		state: "complete",
		originalPath: sourcePath,
		sha256: digest,
		bytes: captured.value.length,
	});
	appendRunEvent(runDir, { type: "node_report_captured", originalPath: sourcePath, bytes: captured.value.length });
	state.pending.shift();
	return state.discoveryComplete && state.pending.length === 0 ? "complete" : "pending";
}

function readJsonValue(value: Buffer): unknown {
	try {
		return JSON.parse(value.toString("utf8")) as unknown;
	} catch {
		return undefined;
	}
}

function reportIndicatesException(runDir: string): boolean {
	// Node writes these files only because this wrapper enabled uncaught/fatal reports.
	// Inspect the producer directory before any later stopped-target compaction moves or
	// replaces the report with a reference artifact.
	try {
		if (
			readdirSync(join(runDir, "raw-reports"), { withFileTypes: true }).some(
				(entry) => entry.isFile() && entry.name.endsWith(".json"),
			)
		) {
			return true;
		}
	} catch {}
	let entries: Dirent[];
	try {
		entries = readdirSync(join(runDir, "reports"), { withFileTypes: true }).filter((entry) => entry.isFile());
	} catch {
		return false;
	}
	return entries.some((entry) => {
		const report = readSmallJson<{ header?: { event?: unknown; trigger?: unknown } }>(
			join(runDir, "reports", entry.name),
		);
		const event = typeof report?.header?.event === "string" ? report.header.event.toLowerCase() : undefined;
		const trigger = typeof report?.header?.trigger === "string" ? report.header.trigger.toLowerCase() : undefined;
		return event === "exception" || trigger === "exception" || event === "fatal_error" || trigger === "fatal_error";
	});
}

function classify(
	events: IncidentRecorderEvent[],
	code: number | null,
	signal: NodeJS.Signals | null,
	runDir: string,
): string {
	if (events.some((event) => event.type === "native_abort") || signal === "SIGABRT") return "native_abort";
	if (events.some((event) => event.type === "unhandled_rejection")) return "unhandled_rejection";
	if (events.some((event) => event.type === "fatal_exception") || reportIndicatesException(runDir))
		return "uncaught_exception";
	if (hasPositiveLinuxCgroupOomKillDelta(runDir, signal).matched) return "kernel_oom_kill";
	const caughtSignal = [...events].reverse().find((event) => event.type === "signal_received")?.signal;
	if (typeof caughtSignal === "string") return `signal_${caughtSignal.toLowerCase()}`;
	if (signal) return `signal_${signal.toLowerCase()}`;
	if (events.some((event) => event.type === "worker_request_end" && event.outcome === "timeout"))
		return "worker_response_hang";
	if (events.some((event) => event.type === "socket_lost")) return "socket_loss";
	if (events.some((event) => event.type === "heartbeat_stalled")) return "event_loop_hang";
	if (code !== 0) return `exit_${code ?? "unknown"}`;
	return "normal";
}

interface CopyBudget {
	remaining: number;
	copied: string[];
}

function copyBoundedFile(source: string, target: string, relative: string, budget: CopyBudget): void {
	let sourceDescriptor: number | undefined;
	let targetDescriptor: number | undefined;
	try {
		sourceDescriptor = openSync(source, "r");
		const size = fstatSync(sourceDescriptor).size;
		const configuredFileLimit = CAUSAL_TIMELINE_FILES.some((name) => name === relative)
			? INCIDENT_RECORDER_LIMITS.eventFileBytes
			: relative === "reports" || relative.startsWith("reports/") || relative.startsWith("reports\\")
				? INCIDENT_RECORDER_LIMITS.nodeReportFileBytes
				: INCIDENT_RECORDER_LIMITS.evidenceFileBytes;
		const fileLimit = Math.min(configuredFileLimit, budget.remaining);
		if (size > fileLimit) return;
		mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
		targetDescriptor = openSync(target, "w", 0o600);
		let copied = 0;
		while (copied < size) {
			const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, size - copied));
			const count = readSync(sourceDescriptor, chunk, 0, chunk.length, copied);
			if (count === 0) break;
			let written = 0;
			while (written < count) {
				const progress = writeSync(targetDescriptor, chunk, written, count - written);
				if (progress <= 0) throw new Error("Incident bundle copy made no progress");
				written += progress;
			}
			copied += count;
		}
		if (copied !== size) {
			closeSync(targetDescriptor);
			targetDescriptor = undefined;
			rmSync(target, { force: true });
			return;
		}
		budget.remaining -= copied;
		budget.copied.push(relative);
	} catch {
		try {
			rmSync(target, { force: true });
		} catch {}
	} finally {
		if (sourceDescriptor !== undefined) closeSync(sourceDescriptor);
		if (targetDescriptor !== undefined) closeSync(targetDescriptor);
	}
}

function copyEvidenceTree(source: string, target: string, relative: string, budget: CopyBudget, depth = 0): void {
	if (depth > 3 || budget.remaining <= 0) return;
	let entries: Dirent[];
	try {
		entries = readdirSync(source, { withFileTypes: true }).slice(0, INCIDENT_RECORDER_LIMITS.maxDirectoryEntries);
	} catch {
		return;
	}
	for (const entry of entries) {
		const childSource = join(source, entry.name);
		const childTarget = join(target, entry.name);
		const childRelative = join(relative, entry.name);
		if (entry.isDirectory()) copyEvidenceTree(childSource, childTarget, childRelative, budget, depth + 1);
		else if (entry.isFile()) copyBoundedFile(childSource, childTarget, childRelative, budget);
		if (budget.remaining <= 0) return;
	}
}

type IncidentCauseLayer = "application" | "environment" | "mixed" | "unknown";

function incidentCauseLayer(
	classification: string,
	linuxEvidence: ReturnType<typeof readLinuxIncidentEvidenceCorrelation>,
): IncidentCauseLayer {
	const applicationClassification = new Set([
		"native_abort",
		"unhandled_rejection",
		"uncaught_exception",
		"event_loop_hang",
		"worker_response_hang",
	]);
	const application = applicationClassification.has(classification) || linuxEvidence.applicationEvidence;
	const environment = classification === "kernel_oom_kill" || linuxEvidence.environmentEvidence;
	if (application && environment) return "mixed";
	if (application) return "application";
	if (environment) return "environment";
	return "unknown";
}

function claimIncidentFinalization(runDir: string, incidentId: string): boolean {
	const path = join(runDir, FINALIZER_CLAIM_FILE_NAME);
	const bootId = linuxBootId();
	const processStartId = getProcessStartId(process.pid);
	if (!bootId || !processStartId) return false;
	const existing = readSmallJson<{ bootId?: unknown; pid?: unknown; processStartId?: unknown }>(path);
	if (existing) {
		const live =
			existing.bootId === bootId &&
			typeof existing.pid === "number" &&
			typeof existing.processStartId === "string" &&
			getProcessStartId(existing.pid) === existing.processStartId;
		if (live) return false;
		try {
			rmSync(path, { force: true });
		} catch {
			return false;
		}
	}
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "wx", 0o600);
		const claim = Buffer.from(
			`${JSON.stringify({
				incidentId,
				bootId,
				pid: process.pid,
				processStartId,
				claimed: nowFields(),
			})}\n`,
		);
		let offset = 0;
		while (offset < claim.length) {
			const written = writeSync(descriptor, claim, offset, claim.length - offset);
			if (written <= 0) throw new Error("Incident finalizer claim write made no progress");
			offset += written;
		}
		fsyncSync(descriptor);
		chmodSync(path, 0o600);
		return true;
	} catch {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
				descriptor = undefined;
			} catch {}
		}
		try {
			rmSync(path, { force: true });
		} catch {}
		return false;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function finalizeIncident(
	options: RecordProcessOptions,
	runDir: string,
	result: Omit<RecordedProcessResult, "runDir" | "incidentDir">,
): string | undefined {
	if (result.classification === "normal") return undefined;
	const incidentId = basename(runDir);
	if (!/^[A-Za-z0-9_.+-]{1,160}$/.test(incidentId)) return undefined;
	const incidentRoot = join(options.agentDir, "incidents");
	mkdirSync(incidentRoot, { recursive: true, mode: 0o700 });
	const incidentDir = join(incidentRoot, incidentId);
	if (existsSync(incidentDir)) {
		const existing = readSmallJson<{ stoppedTargetCaptureComplete?: unknown }>(join(incidentDir, "summary.json"));
		return existing?.stoppedTargetCaptureComplete === true ? incidentDir : undefined;
	}
	if (!claimIncidentFinalization(runDir, incidentId)) return undefined;
	const claimPath = join(runDir, FINALIZER_CLAIM_FILE_NAME);
	const partialDir = join(incidentRoot, `.${incidentId}.partial`);
	try {
		rmSync(partialDir, { recursive: true, force: true });
		mkdirSync(partialDir, { mode: 0o700 });
		const events = readEvents(runDir);
		const causalResourceName = "linux-causal-resource.json";
		const causalResourceSource = join(runDir, causalResourceName);
		const causalResourceExisted = existsSync(causalResourceSource);
		const causalResourceBudget: CopyBudget = {
			remaining: INCIDENT_RECORDER_LIMITS.evidenceFileBytes,
			copied: [],
		};
		copyBoundedFile(
			causalResourceSource,
			join(partialDir, causalResourceName),
			causalResourceName,
			causalResourceBudget,
		);
		const budget: CopyBudget = {
			remaining: INCIDENT_RECORDER_LIMITS.perBundleBytes - INCIDENT_RECORDER_LIMITS.evidenceFileBytes,
			copied: [],
		};
		for (const name of [...CAUSAL_TIMELINE_FILES, "reports"]) {
			const source = join(runDir, name);
			try {
				if (statSync(source).isDirectory()) copyEvidenceTree(source, join(partialDir, name), name, budget);
				else copyBoundedFile(source, join(partialDir, name), name, budget);
			} catch {}
		}
		const launch = readSmallJson<unknown>(join(runDir, "launch.json"));
		const processIdentity = readSmallJson<unknown>(join(runDir, "process.json"));
		const linuxEvidence = readLinuxIncidentEvidenceCorrelation(runDir);
		writePrivateJson(join(partialDir, "launch.json"), launch);
		writePrivateJson(join(partialDir, "process.json"), processIdentity);
		writePrivateJson(join(partialDir, "summary.json"), {
			schemaVersion: 1,
			incidentId,
			classification: result.classification,
			stoppedTargetCaptureComplete: true,
			causeLayer: incidentCauseLayer(result.classification, linuxEvidence),
			correlation: linuxEvidence,
			exit: { code: result.code, signal: result.signal },
			socketPath: options.socketPath,
			socketIdentity: [...events].reverse().find((event) => event.type === "supervisor_ready")?.socketIdentity,
			launch,
			processIdentity,
			timelineBounds: {
				start: events.at(0) ? { wallTime: events[0].wallTime, monotonicNs: events[0].monotonicNs } : undefined,
				end: events.at(-1)
					? { wallTime: events.at(-1)?.wallTime, monotonicNs: events.at(-1)?.monotonicNs }
					: undefined,
			},
			evidence: [...causalResourceBudget.copied, ...budget.copied],
			causalResourceEvidence: causalResourceBudget.copied.includes(causalResourceName)
				? "copied"
				: causalResourceExisted
					? "copy_failed_or_oversized"
					: "source_missing",
			finalized: nowFields(),
		});
		renameSync(partialDir, incidentDir);
		return incidentDir;
	} catch (error) {
		try {
			rmSync(partialDir, { recursive: true, force: true });
			rmSync(claimPath, { force: true });
		} catch {}
		throw error;
	}
}

function causalEnvironmentSummary(environment: NodeJS.ProcessEnv): Record<string, string> {
	const allowed = ["INVOCATION_ID", "SYSTEMD_EXEC_PID", "WSL_DISTRO_NAME", "WSL_UTF8", "NODE_OPTIONS"] as const;
	const summary: Record<string, string> = {};
	for (const key of allowed) {
		const value = environment[key];
		if (typeof value !== "string" || value.length === 0) continue;
		summary[key] = value.replace(/[\r\n\0]/g, " ").slice(0, 256);
	}
	return summary;
}

export async function recordSupervisorProcess(options: RecordProcessOptions): Promise<RecordedProcessResult> {
	const runDir = createRunDir(options.agentDir);
	const bootId = linuxBootId();
	const nodeFatalReportsEnabled = provenNodeLaunch(options.launch);
	const environment = createCliSubprocessEnv({
		...options.environment,
		[INCIDENT_RECORDER_CHILD_ENV]: "1",
		[INCIDENT_RECORDER_RUN_DIR_ENV]: runDir,
		[INCIDENT_RECORDER_SOCKET_ENV]: options.socketPath,
		...(nodeFatalReportsEnabled ? { NODE_REPORT_DIRECTORY: join(runDir, "raw-reports") } : {}),
	});
	const launch = nodeFatalReportsEnabled
		? {
				...options.launch,
				args: [
					"--report-on-fatalerror",
					"--report-uncaught-exception",
					`--report-directory=${join(runDir, "raw-reports")}`,
					...options.launch.args,
				],
			}
		: options.launch;
	const cwd = options.cwd ?? process.cwd();
	const launchSummary = {
		version: 1,
		purpose: "causal-supervisor-launch",
		privacy: "private-local-0600",
		created: nowFields(),
		parent: {
			pid: process.pid,
			processStartId: getProcessStartId(process.pid),
			executable: process.execPath,
			cwd: process.cwd(),
		},
		socketPath: options.socketPath,
		runtimeCategory: nodeFatalReportsEnabled ? "node" : process.versions.bun ? "bun" : "foreign",
		nodeFatalReportsEnabled,
		build: { appVersion: VERSION, node: process.versions.node, release: process.release.name },
		command: launch.command,
		cwd,
		environment: causalEnvironmentSummary(options.environment ?? {}),
		commandSummary: summarizeIncidentCommandLine(launch.args),
	};
	writePrivateJson(join(runDir, "launch.json"), launchSummary);
	appendCausalRunEvent(runDir, "recorder-events", "recorder_launch", launchSummary);
	let child: ChildProcess;
	try {
		child = spawn(launch.command, launch.args, {
			cwd,
			env: environment,
			stdio: ["inherit", "inherit", "inherit"],
		});
	} catch (error) {
		appendRunEvent(runDir, { type: "recorder_spawn_error", error });
		publishTerminalDisposition(runDir, {
			completed: nowFields(),
			disposition: "spawn_failed_before_target_identity",
			exitCode: null,
			exitSignal: null,
			structuredExit: { durable: false, reason: "target_not_spawned" },
		});
		throw error;
	}

	const pid = child.pid;
	if (!pid) {
		// A failed spawn reports ENOENT asynchronously even though no target PID
		// ever existed. Consume that diagnostic event; this branch owns the
		// terminal disposition and no live process can be hidden by it.
		const spawnErrorPromise = new Promise<Error>((resolve) => child.once("error", resolve));
		const spawnError = await spawnErrorPromise;
		publishTerminalDisposition(runDir, {
			completed: nowFields(),
			disposition: "spawn_failed_before_target_identity",
			exitCode: null,
			exitSignal: null,
			spawnError: serializeError(spawnError),
			structuredExit: { durable: false, reason: "target_not_spawned" },
		});
		throw new Error("Incident recorder could not obtain supervisor PID");
	}
	const processStartId = getProcessStartId(pid);
	appendCausalRunEvent(runDir, "recorder-events", "supervisor_stdio_source_unavailable", {
		stdout: "inherited-to-preserve-original-stream-and-tty-semantics",
		stderr: "inherited-to-preserve-original-stream-and-tty-semantics",
	});
	writePrivateJson(join(runDir, "process.json"), {
		machineId: linuxMachineId(),
		bootId,
		systemdInvocationId: process.env.INVOCATION_ID ?? null,
		pid,
		processStartId,
		observed: nowFields(),
		runtimeCategory: nodeFatalReportsEnabled ? "node" : "foreign",
		nodeFatalReportsEnabled,
		orphanPolicy: "fail-open",
		wrapperDeathSignalsSupervisor: false,
	});
	appendRunEvent(runDir, { type: "supervisor_spawned", childPid: pid, processStartId, nodeFatalReportsEnabled });
	let exit: { code: number | null; signal: NodeJS.Signals | null };
	try {
		exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolveExit, rejectExit) => {
			child.once("error", rejectExit);
			child.once("close", (code, signal) => resolveExit({ code, signal }));
		});
	} catch (error) {
		appendRunEvent(runDir, { type: "recorder_child_error", error, childPid: pid, processStartId });
		throw error;
	}
	const exitAdmission = appendCausalRunEvent(runDir, "recorder-events", "supervisor_exit", {
		childPid: pid,
		code: exit.code,
		signal: exit.signal,
	});
	publishTerminalDisposition(runDir, {
		completed: nowFields(),
		exitCode: exit.code,
		exitSignal: exit.signal,
		structuredExit: exitAdmission.accepted
			? { durable: true, occurrenceId: exitAdmission.occurrenceId }
			: { durable: false, occurrenceId: exitAdmission.occurrenceId, reason: exitAdmission.reason },
	});
	const classification =
		exit.signal === "SIGABRT"
			? "native_abort"
			: reportIndicatesException(runDir)
				? "uncaught_exception"
				: exit.signal
					? `signal_${exit.signal.toLowerCase()}`
					: exit.code === 143
						? "signal_sigterm"
						: exit.code === 0
							? "normal"
							: `exit_${exit.code ?? "unknown"}`;
	return { code: exit.code, signal: exit.signal, runDir, classification };
}

export async function runRecordedSupervisor(args: readonly string[], socketPath: string): Promise<never> {
	const wrapperStartId = getProcessStartId(process.pid);
	const result = await recordSupervisorProcess({
		agentDir: getAgentDir(),
		socketPath,
		launch: createRecordedSupervisorChildLaunch(args),
		environment: process.env,
	});
	if (result.signal && wrapperStartId && getProcessStartId(process.pid) === wrapperStartId) {
		// Self-signalling preserves the child's exit semantics and cannot target a reused external PID.
		process.kill(process.pid, result.signal);
	}
	process.exit(result.code ?? 1);
}

interface ActiveRun {
	runDir: string;
	machineId: string;
	bootId: string;
	socketPath: string;
	pid: number;
	processStartId: string;
}

function isMatchingLiveProcess(run: ActiveRun): boolean {
	return (
		run.machineId === linuxMachineId() &&
		run.bootId === linuxBootId() &&
		hasMatchingProcessIdentity(run.pid, run.processStartId)
	);
}

function loadActiveRun(runDir: string): ActiveRun | undefined {
	const launch = readSmallJson<{ socketPath?: unknown }>(join(runDir, "launch.json"));
	const identity = readSmallJson<{ machineId?: unknown; bootId?: unknown; pid?: unknown; processStartId?: unknown }>(
		join(runDir, "process.json"),
	);
	if (
		!launch ||
		!identity ||
		typeof launch.socketPath !== "string" ||
		typeof identity.machineId !== "string" ||
		typeof identity.bootId !== "string" ||
		typeof identity.pid !== "number" ||
		typeof identity.processStartId !== "string"
	)
		return undefined;
	return {
		runDir,
		machineId: identity.machineId,
		bootId: identity.bootId,
		socketPath: launch.socketPath,
		pid: identity.pid,
		processStartId: identity.processStartId,
	};
}

function runHasLiveProxy(runDir: string): boolean {
	const marker = readSmallJson<{
		role?: unknown;
		machineId?: unknown;
		bootId?: unknown;
		pid?: unknown;
		processStartId?: unknown;
	}>(join(runDir, ACTIVE_MARKER_FILE_NAME));
	const live =
		marker?.role === "wrapper-proxy" &&
		marker.machineId === linuxMachineId() &&
		marker.bootId === linuxBootId() &&
		typeof marker.pid === "number" &&
		typeof marker.processStartId === "string" &&
		getProcessStartId(marker.pid) === marker.processStartId;
	if (marker?.role === "wrapper-proxy" && !live) {
		const uncertaintyPath = join(runDir, ".stale-wrapper-marker-uncertainty.json");
		if (!existsSync(uncertaintyPath))
			writePrivateJson(uncertaintyPath, {
				state: "uncertain",
				reason: "wrapper_marker_owner_identity_not_live",
				orphanPolicy: "fail-open",
				wrapperDeathSignalsSupervisor: false,
				observed: nowFields(),
			});
	}
	return live;
}

interface ServiceSamplingState {
	previous?: LinuxMemorySummary;
	anomalyBurstUntilMs: number;
	latencyBurstUntilMs: number;
	nextSampleMs: number;
	lastLatencyTriggerOccurrence?: string;
	diskPauseMarked: boolean;
	liveHangClassification?: string;
	finalSampleCaptured?: boolean;
	nodeReportPendingMarked?: boolean;
}
const serviceSamplingRuns = new Map<string, ServiceSamplingState>();
let serviceRunsDirectory: Dir | undefined;
let serviceRunsDirectoryPath: string | undefined;
const serviceRunPaths = new Map<string, string>();
let serviceRunCursor = 0;

function linuxCountersAdvanced(
	previous: LinuxMemorySummary | undefined,
	current: LinuxMemorySummary | undefined,
): boolean {
	for (const source of ["eventsLocal", "events"] as const) {
		const before = previous?.latest?.[source];
		const after = current?.latest?.[source];
		for (const key of new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})])) {
			if ((after?.[key] ?? 0) > (before?.[key] ?? 0)) return true;
		}
	}
	return false;
}

function closeServiceRunsDirectory(): void {
	const directory = serviceRunsDirectory;
	serviceRunsDirectory = undefined;
	serviceRunsDirectoryPath = undefined;
	if (!directory) return;
	try {
		directory.closeSync();
	} catch {}
}

/** @internal Replaces or releases the service-owned compactor and retained run scan. */
export async function inspectIncidentRecorderRuns(agentDir: string, nowMs = Date.now()): Promise<string[]> {
	const runsRoot = join(agentDir, "incident-recorder", "runs");
	if (serviceRunsDirectoryPath !== undefined && serviceRunsDirectoryPath !== runsRoot) closeServiceRunsDirectory();
	if (!existsSync(runsRoot)) {
		closeServiceRunsDirectory();
		return [];
	}
	const finalized: string[] = [];
	if (!serviceRunsDirectory) {
		try {
			serviceRunsDirectory = opendirSync(runsRoot);
			serviceRunsDirectoryPath = runsRoot;
		} catch {
			closeServiceRunsDirectory();
			return [];
		}
	}
	for (let discovered = 0; discovered < 16; discovered += 1) {
		let entry: Dirent | null;
		try {
			entry = serviceRunsDirectory.readSync();
		} catch {
			closeServiceRunsDirectory();
			break;
		}
		if (!entry) {
			closeServiceRunsDirectory();
			break;
		}
		if (
			!entry.isDirectory() ||
			!/^[A-Za-z0-9_.+-]{1,160}$/.test(entry.name) ||
			entry.name === "." ||
			entry.name === ".."
		)
			continue;
		serviceRunPaths.set(entry.name, join(runsRoot, entry.name));
		while (serviceRunPaths.size > 4096) serviceRunPaths.delete(serviceRunPaths.keys().next().value as string);
	}
	const names = [...serviceRunPaths.keys()];
	if (names.length === 0) return finalized;
	const batch = Array.from(
		{ length: Math.min(16, names.length) },
		(_, offset) => names[(serviceRunCursor + offset) % names.length],
	);
	serviceRunCursor = (serviceRunCursor + batch.length) % names.length;
	const workDeadlineMs = Date.now() + 100;
	for (const name of batch) {
		if (Date.now() >= workDeadlineMs) break;
		const run = loadActiveRun(serviceRunPaths.get(name) ?? join(runsRoot, name));
		if (!run) continue;
		const live = isMatchingLiveProcess(run);
		const events = readEvents(run.runDir);
		if (live) {
			try {
				let sampling = serviceSamplingRuns.get(run.runDir);
				if (!sampling) {
					sampling = {
						anomalyBurstUntilMs: 0,
						latencyBurstUntilMs: 0,
						nextSampleMs: nowMs + 1_000,
						diskPauseMarked: false,
					};
					serviceSamplingRuns.set(run.runDir, sampling);
					while (serviceSamplingRuns.size > 4096)
						serviceSamplingRuns.delete(serviceSamplingRuns.keys().next().value as string);
					sampling.previous = baselineLinuxIncidentEvidence({
						runDir: run.runDir,
						pid: run.pid,
						processStartId: run.processStartId,
					});
				}
				const latencyTrigger = [...events]
					.reverse()
					.find((event) => event.type === "list_status_sampling_trigger" && typeof event.requestId === "string");
				const triggerOccurrence =
					typeof latencyTrigger?.occurrenceId === "string" ? latencyTrigger.occurrenceId : undefined;
				if (latencyTrigger && triggerOccurrence && triggerOccurrence !== sampling.lastLatencyTriggerOccurrence) {
					sampling.lastLatencyTriggerOccurrence = triggerOccurrence;
					sampling.latencyBurstUntilMs = Math.max(sampling.latencyBurstUntilMs, nowMs + 15_000);
				}
				if (nowMs >= sampling.nextSampleMs) {
					const inAnomalyBurst = nowMs < sampling.anomalyBurstUntilMs;
					const inLatencyBurst = nowMs < sampling.latencyBurstUntilMs;
					const current = sampleLinuxIncidentEvidence({
						runDir: run.runDir,
						phase: inAnomalyBurst ? "anomaly" : "periodic",
					});
					if (linuxCountersAdvanced(sampling.previous, current)) {
						sampling.anomalyBurstUntilMs = Math.max(sampling.anomalyBurstUntilMs, nowMs + 60_000);
						appendRunEvent(run.runDir, {
							type: "linux_cgroup_anomaly_burst_started",
							cadenceMs: 250,
							durationMs: 60_000,
						});
					}
					sampling.previous = current ?? sampling.previous;
					sampling.nextSampleMs =
						nowMs + (inLatencyBurst ? 100 : nowMs < sampling.anomalyBurstUntilMs ? 250 : 1_000);
				}
			} catch (error) {
				appendRunEvent(run.runDir, { type: "linux_evidence_unavailable", phase: "service-periodic", error });
			}
		}
		if (existsSync(join(run.runDir, ".service-finalization-complete"))) continue;
		const exitEvent = [...events].reverse().find((event) => event.type === "supervisor_exit");
		const exited = exitEvent !== undefined;
		if (!live) {
			if (runHasLiveProxy(run.runDir)) continue;
			if (!hasDurableFinalizationBarrier(run.runDir)) {
				const pendingPath = join(run.runDir, ".service-finalization-pending");
				if (!existsSync(pendingPath))
					writeImmutableJsonOnce(pendingPath, {
						state: "waiting_for_durable_wrapper_exit_disposition",
						retryable: true,
						observed: nowFields(),
					});
				continue;
			}
			let stoppedState = serviceSamplingRuns.get(run.runDir);
			if (!stoppedState) {
				stoppedState = {
					anomalyBurstUntilMs: 0,
					latencyBurstUntilMs: 0,
					nextSampleMs: Number.MAX_SAFE_INTEGER,
					diskPauseMarked: false,
				};
				serviceSamplingRuns.set(run.runDir, stoppedState);
				while (serviceSamplingRuns.size > 4096)
					serviceSamplingRuns.delete(serviceSamplingRuns.keys().next().value as string);
			}
			if (!stoppedState.finalSampleCaptured)
				try {
					sampleLinuxIncidentEvidence({ runDir: run.runDir, phase: "final" });
					stoppedState.finalSampleCaptured = true;
				} catch (error) {
					stoppedState.finalSampleCaptured = true;
					appendRunEvent(run.runDir, { type: "linux_evidence_unavailable", phase: "service-final", error });
				}
			const reportCapture = await sanitizeNodeReports(run.runDir, true);
			if (reportCapture !== "complete") {
				if (!stoppedState.nodeReportPendingMarked) {
					appendRunEvent(run.runDir, { type: "stopped_target_report_capture_pending", state: "pending" });
					stoppedState.nodeReportPendingMarked = true;
				}
				continue;
			}
			const expectedExit = readExpectedExitDisposition(run.runDir);
			const code = typeof exitEvent?.code === "number" ? exitEvent.code : expectedExit.code;
			const signal =
				typeof exitEvent?.signal === "string" ? (exitEvent.signal as NodeJS.Signals) : expectedExit.signal;
			const correlation = readLinuxIncidentEvidenceCorrelation(run.runDir);
			const classification = correlation.environmentClassification ?? classify(events, code, signal, run.runDir);
			if (!exited && correlation.environmentClassification) {
				appendRunEvent(run.runDir, {
					type: "environment_exit_correlated",
					childPid: run.pid,
					classification,
					attribution: "supporting_evidence",
				});
			}
			const incidentDir = finalizeIncident(
				{ agentDir, socketPath: run.socketPath, launch: { command: "", args: [] } },
				run.runDir,
				{ code, signal, classification },
			);
			if (incidentDir) {
				appendRunEvent(run.runDir, { type: "service_incident_finalized", incidentId: basename(incidentDir) });
				finalized.push(incidentDir);
			}
			if (incidentDir || classification === "normal") {
				writePrivateJson(join(run.runDir, ".service-finalization-complete"), {
					bootId: linuxBootId(),
					servicePid: process.pid,
					classification,
					completed: nowFields(),
				});
				serviceSamplingRuns.delete(run.runDir);
				nodeReportCaptureStates.delete(run.runDir);
			}
			continue;
		}
		if (exited) continue;
		const heartbeats = events.filter((event) => event.type === "supervisor_heartbeat");
		const lastHeartbeat = heartbeats.at(-1);
		const heartbeatWall = lastHeartbeat ? Date.parse(lastHeartbeat.wallTime) : Number.NaN;
		const socketWasPresent = heartbeats.some((event) => event.socketExists === true);
		let detected: "event_loop_hang" | "socket_loss" | "worker_response_hang" | undefined;
		if (events.some((event) => event.type === "worker_request_end" && event.outcome === "timeout"))
			detected = "worker_response_hang";
		else if (lastHeartbeat && Number.isFinite(heartbeatWall) && nowMs - heartbeatWall > STALL_THRESHOLD_MS)
			detected = "event_loop_hang";
		else if (socketWasPresent && !existsSync(run.socketPath)) detected = "socket_loss";
		if (!detected) continue;
		const sampling = serviceSamplingRuns.get(run.runDir);
		if (sampling?.liveHangClassification === detected) continue;
		if (sampling) sampling.liveHangClassification = detected;
		const detectionType =
			detected === "event_loop_hang"
				? "heartbeat_stalled"
				: detected === "socket_loss"
					? "socket_lost"
					: "worker_hang_detected";
		appendCausalRunEvent(run.runDir, "recorder-events", detectionType, { childPid: run.pid });
	}
	return finalized;
}

function serviceInspectionCadenceMs(nowMs = Date.now()): number {
	for (const sampling of serviceSamplingRuns.values()) if (nowMs < sampling.latencyBurstUntilMs) return 100;
	return 250;
}

export async function runIncidentRecorderService(agentDir = getAgentDir()): Promise<never> {
	if (process.platform !== "linux") throw new Error("Incident recorder service requires Linux process evidence");
	mkdirSync(join(agentDir, "incident-recorder", "runs"), { recursive: true, mode: 0o700 });
	let nextRetentionPassMs = 0;
	for (;;) {
		try {
			await inspectIncidentRecorderRuns(agentDir);
			const nowMs = Date.now();
			if (nowMs >= nextRetentionPassMs) {
				const retention = runIncidentRetentionPass({ agentDir, nowMs, ...INCIDENT_RETENTION_SERVICE_BUDGET });
				if (retention.uncertainties.length > 0)
					writePrivateJsonAtomicSync(join(agentDir, "incident-recorder", "retention-uncertainty.json"), {
						version: 1,
						state: "fail_closed",
						observed: nowFields(),
						reasons: retention.uncertainties.slice(0, 32),
					});
				nextRetentionPassMs = nowMs + 60_000;
			}
		} catch {
			// An unavailable evidence source must not stop later causal-observation passes.
		}
		await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, serviceInspectionCadenceMs()));
	}
}

export interface RenderServiceOptions {
	nodePath: string;
	entrypointPath: string;
	agentDir?: string;
	memoryMax?: string;
	memoryHigh?: string;
	memorySwapMax?: string;
	cpuQuota?: string;
	ioWeight?: number;
	restartSeconds?: number;
	tasksMax?: number;
	limitNOFILE?: number;
	startLimitIntervalSeconds?: number;
	startLimitBurst?: number;
}

function systemdQuote(value: string): string {
	return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

export function renderIncidentRecorderSystemdUnit(options: RenderServiceOptions): string {
	if (!isAbsolute(options.nodePath) || !isAbsolute(options.entrypointPath)) {
		throw new Error("Incident recorder service paths must be absolute");
	}
	const args = [options.nodePath, options.entrypointPath, "--incident-recorder-service"];
	if (options.agentDir) args.push("--agent-dir", options.agentDir);
	// The causal recorder performs bounded metadata sampling only. It never
	// replays journal history or compacts an application-output warehouse.
	const memoryMax = options.memoryMax ?? "256M";
	const memoryHigh = options.memoryHigh ?? "192M";
	const memorySwapMax = options.memorySwapMax ?? "0";
	const cpuQuota = options.cpuQuota ?? "10%";
	const ioWeight = options.ioWeight ?? 10;
	const restartSeconds = options.restartSeconds ?? 2;
	const tasksMax = options.tasksMax ?? 64;
	const limitNOFILE = options.limitNOFILE ?? 4096;
	const startLimitIntervalSeconds = options.startLimitIntervalSeconds ?? 60;
	const startLimitBurst = options.startLimitBurst ?? 5;
	if (
		!/^0$|^[1-9][0-9]*[KMGT]?$/.test(memoryMax) ||
		!/^0$|^[1-9][0-9]*[KMGT]?$/.test(memoryHigh) ||
		!/^0$|^[1-9][0-9]*[KMGT]?$/.test(memorySwapMax) ||
		!/^[1-9][0-9]*%$/.test(cpuQuota) ||
		!Number.isSafeInteger(ioWeight) ||
		ioWeight < 1 ||
		ioWeight > 10_000 ||
		!Number.isFinite(restartSeconds) ||
		restartSeconds < 1 ||
		!Number.isSafeInteger(tasksMax) ||
		tasksMax < 1 ||
		!Number.isSafeInteger(limitNOFILE) ||
		limitNOFILE < 64 ||
		!Number.isSafeInteger(startLimitIntervalSeconds) ||
		startLimitIntervalSeconds < 1 ||
		!Number.isSafeInteger(startLimitBurst) ||
		startLimitBurst < 1
	)
		throw new Error("Invalid incident recorder service resource controls");
	return `[Unit]\nDescription=Prime Agent causal incident recorder\nStartLimitIntervalSec=${startLimitIntervalSeconds}s\nStartLimitBurst=${startLimitBurst}\n\n[Service]\nType=simple\nKillMode=control-group\nEnvironment=${INCIDENT_RECORDER_SERVICE_ENV}=1\nExecStart=${args.map(systemdQuote).join(" ")}\nRestart=on-failure\nRestartSec=${restartSeconds}s\nMemoryHigh=${memoryHigh}\nMemoryMax=${memoryMax}\nMemorySwapMax=${memorySwapMax}\nCPUQuota=${cpuQuota}\nIOWeight=${ioWeight}\nIOSchedulingClass=idle\nNice=10\nTasksMax=${tasksMax}\nLimitNOFILE=${limitNOFILE}\nOOMPolicy=stop\nRuntimeDirectory=prime-agent\nRuntimeDirectoryMode=0700\nUMask=0077\n\n[Install]\nWantedBy=default.target\n`;
}

export interface InstallServiceOptions extends RenderServiceOptions {
	platform?: NodeJS.Platform;
	homeDir?: string;
	configHomeDir?: string;
	systemctlPath?: string;
	spawnSyncImpl?: (
		command: string,
		args: readonly string[],
	) => Pick<SpawnSyncReturns<string>, "status" | "error" | "stderr">;
}

export interface InstallServiceResult {
	status: "installed" | "unchanged" | "unsupported" | "unavailable" | "failed";
	unitPath?: string;
	message?: string;
}

export function installIncidentRecorderSystemdService(options: InstallServiceOptions): InstallServiceResult {
	if (!isAbsolute(options.nodePath) || !isAbsolute(options.entrypointPath))
		return { status: "failed", message: "incident recorder service paths must be absolute" };
	if ((options.platform ?? process.platform) !== "linux")
		return { status: "unsupported", message: "systemd user service is only available on Linux" };
	const systemctl = options.systemctlPath ?? "systemctl";
	const run =
		options.spawnSyncImpl ??
		((command, args) => spawnSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
	const probe = run(systemctl, ["--user", "show-environment"]);
	if (probe.error || probe.status !== 0)
		return { status: "unavailable", message: "systemd user manager is unavailable; no files were changed" };
	const configHome =
		options.configHomeDir ??
		(options.homeDir ? join(options.homeDir, ".config") : process.env.XDG_CONFIG_HOME || join(homedir(), ".config"));
	const unitDir = join(configHome, "systemd", "user");
	const unitPath = join(unitDir, "prime-agent-incident-recorder.service");
	const desired = renderIncidentRecorderSystemdUnit(options);
	let changed = true;
	const current = readBoundedPrefix(unitPath, INCIDENT_RECORDER_LIMITS.evidenceFileBytes);
	if (current && !current.truncated) changed = current.value.toString("utf8") !== desired;
	if (changed) {
		mkdirSync(unitDir, { recursive: true, mode: 0o700 });
		const temporary = `${unitPath}.tmp-${process.pid}-${randomUUID()}`;
		writeFileSync(temporary, desired, { mode: 0o600 });
		renameSync(temporary, unitPath);
		chmodSync(unitPath, 0o600);
	}
	if (changed) {
		const reload = run(systemctl, ["--user", "daemon-reload"]);
		if (reload.error || reload.status !== 0)
			return {
				status: "failed",
				unitPath,
				message: reload.error?.message ?? reload.stderr ?? "systemctl user daemon-reload failed",
			};
	}
	const enable = run(systemctl, ["--user", "enable", basename(unitPath)]);
	if (enable.error || enable.status !== 0)
		return {
			status: "failed",
			unitPath,
			message: enable.error?.message ?? enable.stderr ?? "systemctl user enable failed",
		};
	const activate = run(systemctl, ["--user", changed ? "restart" : "start", basename(unitPath)]);
	if (activate.error || activate.status !== 0)
		return {
			status: "failed",
			unitPath,
			message: activate.error?.message ?? activate.stderr ?? "systemctl user activation failed",
		};
	const verify = run(systemctl, ["--user", "is-active", "--quiet", basename(unitPath)]);
	if (verify.error || verify.status !== 0)
		return {
			status: "failed",
			unitPath,
			message: verify.error?.message ?? verify.stderr ?? "incident recorder service readiness verification failed",
		};
	return {
		status: changed ? "installed" : "unchanged",
		unitPath,
		message: `causal-recorder user-service=${changed ? "installed" : "unchanged"}`,
	};
}
