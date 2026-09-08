import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	chmodSync,
	closeSync,
	mkdirSync,
	openSync,
	readlinkSync,
	readSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, posix } from "node:path";
import { getProcessStartId } from "../../core/session-lease.js";
import { INCIDENT_DIAGNOSTIC_RETENTION_MS } from "./incident-recorder-retention.js";

const MONITOR_FILE_NAME = ".incident-recorder-linux-monitor.json";
const MEMORY_FILE_NAME = "linux-memory.json";
const AUDIT_FILE_NAME = "linux-audit.json";
const SYSTEM_JOURNAL_FILE_NAME = "linux-system-journal.json";
const SOURCE_READ_LIMIT = 16 * 1024;
const MOUNTINFO_READ_LIMIT = 256 * 1024;
const MEMORY_FILE_LIMIT = 256 * 1024;
const MONITOR_FILE_LIMIT = 32 * 1024;
const SAMPLE_TAIL_LIMIT = 12;
const COUNTER_CHANGE_LIMIT = 24;
const AUDIT_RECORD_LIMIT = 24;
const AUDIT_LINE_LIMIT = 128;
const AUDIT_STDOUT_LIMIT = 128 * 1024;
const AUDIT_TIMEOUT_MS = 250;
const MAX_LINEAGE_DEPTH = 6;
const JOURNAL_RETENTION_MS = INCIDENT_DIAGNOSTIC_RETENTION_MS;
const JOURNAL_QUERY_ERROR_LIMIT = 16;
const JOURNAL_EXPORT_LIMIT = 64 * 1024 * 1024;
const JOURNAL_EXPORT_TIMEOUT_MS = 2_000;

export interface BoundedText {
	value: string;
	rawValue?: Uint8Array;
	truncated: boolean;
}

export interface FileIdentity {
	dev: number;
	ino: number;
	isDirectory: boolean;
}

export interface JournalResult {
	status: number | null;
	stdout: string | Buffer;
	stderr: string | Buffer;
	errorCode?: string;
}

export interface LinuxRawSourceOccurrence {
	source: "procfs" | "cgroupfs" | "system-journal-export" | "journal-query-error";
	sourcePath: string;
	bytes: Uint8Array;
	encoding: string;
	phase: "startup" | "baseline" | "periodic" | "service" | "anomaly" | "final" | "incident-pin";
	wallTime: string;
	monotonicNs: string;
	identity?: Record<string, unknown>;
	bounds?: {
		start?: LinuxJournalPosition;
		end?: LinuxJournalPosition;
		startExclusive?: boolean;
		endInclusive?: boolean;
	};
}

export type LinuxRawSourceRecorder = (occurrence: LinuxRawSourceOccurrence) => unknown;

export interface LinuxIncidentCollectorDependencies {
	platform: NodeJS.Platform;
	now: () => Date;
	monotonicNs: () => string;
	getProcessStartId: (pid: number) => string | undefined;
	readBounded: (path: string, limit: number) => BoundedText | undefined;
	stat: (path: string) => FileIdentity | undefined;
	readLink: (path: string) => string | undefined;
	runJournalctl: (args: readonly string[], timeoutMs: number, stdoutLimit: number) => JournalResult;
	recordRawSource?: LinuxRawSourceRecorder;
}

/** The stable identity and exact process-membership observation for one cgroup v2 directory. */
export interface ResolvedLinuxCgroupV2Directory {
	directory: string;
	dev: number;
	ino: number;
	identityHash: string;
	membershipRaw: Buffer;
	membershipSourcePath: string;
	membershipSha256: string;
}

export type LinuxCgroupV2ResolutionDependencies = Pick<LinuxIncidentCollectorDependencies, "readBounded" | "stat">;

export interface LinuxIncidentPreparationOptions {
	runDir: string;
	dependencies?: Partial<LinuxIncidentCollectorDependencies>;
}

export interface LinuxIncidentJournalPinOptions extends LinuxIncidentPreparationOptions {
	recordRawSource: LinuxRawSourceRecorder;
}

export interface LinuxIncidentTargetOptions {
	runDir: string;
	pid: number;
	processStartId: string | undefined;
	dependencies?: Partial<LinuxIncidentCollectorDependencies>;
}

export type LinuxMemorySamplePhase = "baseline" | "periodic" | "service" | "anomaly" | "final";

export interface LinuxIncidentSampleOptions {
	runDir: string;
	phase: LinuxMemorySamplePhase;
	skipMemorySample?: boolean;
	captureBroadRaw?: boolean;
	dependencies?: Partial<LinuxIncidentCollectorDependencies>;
}

export interface LinuxPressureValues {
	avg10: number;
	avg60: number;
	avg300: number;
	total: number;
}

export interface LinuxPressureSample {
	some?: LinuxPressureValues;
	full?: LinuxPressureValues;
}

export interface LinuxMemorySample {
	sequence: number;
	phase: LinuxMemorySamplePhase;
	wallTime: string;
	monotonicNs: string;
	targetIdentity: "matched" | "saved_after_exit" | "pid_reused" | "unavailable";
	memberCount?: number;
	targetMember?: boolean;
	memoryCurrent?: number;
	memoryPeak?: number;
	memoryMax?: number;
	memoryMaxUnlimited?: boolean;
	eventsLocal?: Record<string, number>;
	events?: Record<string, number>;
	pressure?: LinuxPressureSample;
	hostPressure?: LinuxPressureSample;
}

export interface LinuxMemorySummary {
	schemaVersion: 1;
	provider: "linux_cgroup_v2";
	target?: { pid: number; processStartId: string };
	capability: {
		status: "available" | "unavailable";
		reason: string;
		sourceLayer: "service_resource";
		diagnosticOnly: true;
		unprivilegedOnly: true;
	};
	cgroup?: {
		identityHash: string;
		directory: string;
		dev: number;
		ino: number;
		attribution: "dedicated" | "shared" | "unknown";
	};
	targetIdentityValidated: boolean;
	baseline?: LinuxMemorySample;
	latest?: LinuxMemorySample;
	extrema: Record<string, { min: number; max: number }>;
	sampleTail: LinuxMemorySample[];
	counterChanges: Array<{
		sequence: number;
		wallTime: string;
		local?: Record<string, number>;
		hierarchical?: Record<string, number>;
	}>;
	sampleCount: number;
}

export interface LinuxAuditSignalEvidence {
	wallTime?: string;
	syscall: "kill" | "tkill" | "tgkill";
	signalNumber: number;
	signal?: string;
	targetPid: number;
	targetTid?: number;
	senderPid: number;
	senderUid: number;
	senderPpid: number;
	senderProcessStartId?: string;
	senderExecutable?: string;
	senderExecutableStatus: "observed" | "unavailable";
	lineageExecutables: string[];
	lineageStatus: "observed" | "unavailable";
	targetIdentityBinding: "run_lifetime_pid_window";
}

export interface LinuxAuditSummary {
	schemaVersion: 1;
	provider: "linux_audit_journal";
	target?: { pid: number; processStartId: string };
	capability: {
		status: "available" | "unavailable";
		reason: string;
		sourceLayer: "kernel";
		diagnosticOnly: true;
		preexistingRecordsOnly: true;
		crossBootJournalQuery: true;
		automaticJournalConfiguration: false;
		operatorManagedPersistentJournalCompatible: true;
		unprivilegedOnly: true;
		rawRecordsPersisted: false;
		canonicalRawSource: "linux_system_journal_range";
		ruleInstallation: false;
		groupTargets: false;
		pidfdTargets: false;
		targetStartIdentityInAuditRecord: false;
		senderStartIdentitySource: "bounded_post_observation";
		timeoutMs: number;
		queryStdoutByteLimit: number;
		journalRecordLimit: false;
		retainedDerivedRecords: number;
		lineageDepth: number;
	};
	lastObservation: {
		wallTime: string;
		outcome: "observed" | "not_observed" | "unavailable";
		reason: string;
		sourceTruncated: boolean;
	};
	records: LinuxAuditSignalEvidence[];
	droppedRecordCount: number;
}

export type LinuxSystemJournalCategory =
	| "kernel_oom_kill"
	| "kernel_memory_pressure"
	| "systemd_oom_action"
	| "systemd_lifecycle"
	| "shutdown"
	| "poweroff"
	| "reboot"
	| "coredump"
	| "signal_exit"
	| "kernel_signal_fault"
	| "unknown";

export type LinuxSystemJournalSource =
	| "audit"
	| "kernel"
	| "systemd"
	| "systemd_shutdown"
	| "systemd_oomd"
	| "systemd_coredump"
	| "other";

export interface LinuxJournalPosition {
	cursor: string;
	bootId?: string;
	realtimeTimestampUs?: string;
}

export interface LinuxSystemJournalEvidence extends LinuxJournalPosition {
	source: LinuxSystemJournalSource;
	sourceLayer: "service_resource" | "kernel";
	category: LinuxSystemJournalCategory;
	targetIdentityBinding: "pid_and_run_journal_window" | "global_timeline";
	targetPid?: number;
	signalNumber?: number;
	signal?: string;
	executable?: string;
	unit?: string;
}

export interface LinuxJournalQueryError {
	wallTime: string;
	status: number | null;
	errorCode?: string;
	stderr: string;
	operation: "cursor" | "range" | "incident_export" | "provider_version";
	lossOrRotation: boolean;
}

export interface LinuxJournalSourceReference {
	canonicalSource: "persistent-system-journal";
	retentionMilliseconds: number;
	resolvabilityDependency: "journal-provider-retains-range";
	resolvabilityVerified: false;
	contentBinding: "cursor_boot_and_file_identity_best_effort";
	provider: {
		name: "systemd-journald";
		queryTool: "journalctl";
		versionOutput?: string;
	};
	configurationAndStorageIdentities: Array<{ path: string; dev: number; ino: number; isDirectory: boolean }>;
	identityEnumerationTruncated: boolean;
	queryErrors: LinuxJournalQueryError[];
	queryErrorDropCount: number;
	lossIndicators: string[];
	rawExportSegments: Array<{
		captured: { wallTime: string; monotonicNs: string };
		bounds: { start?: LinuxJournalPosition; end?: LinuxJournalPosition; startExclusive: true; endInclusive: true };
		payloadReference: unknown;
		bytes: number;
		encoding: "journal-export";
	}>;
}

export interface LinuxSystemJournalSummary {
	schemaVersion: 1;
	provider: "linux_system_journal";
	target?: { pid: number; processStartId: string };
	capability: {
		status: "available" | "unavailable";
		reason: string;
		sourceLayer: "kernel";
		diagnosticOnly: true;
		preexistingRecordsOnly: true;
		crossBootJournalQuery: true;
		automaticJournalConfiguration: false;
		operatorManagedPersistentJournalCompatible: true;
		rawMessagesPersisted: false;
		canonicalRawSourceReferenced: true;
		incidentRawExportPinSupported: true;
		timeoutMs: number;
		queryStdoutByteLimit: number;
		journalRecordLimit: false;
	};
	bounds: { start?: LinuxJournalPosition; end?: LinuxJournalPosition };
	sourceReference: LinuxJournalSourceReference;
	lastObservation: {
		wallTime: string;
		outcome: "observed" | "not_observed" | "unavailable";
		reason: string;
		sourceTruncated: boolean;
	};
	records: LinuxSystemJournalEvidence[];
	droppedRecordCount: number;
}

interface LinuxMonitorState {
	schemaVersion: 1;
	targetPid: number;
	targetProcessStartId: string;
	cgroupDirectory?: string;
	cgroupDev?: number;
	cgroupIno?: number;
	cgroupIdentityHash?: string;
	baselineEpochMs: number;
	systemJournalCursor?: string;
	journalStartCursor?: string;
	journalStartBootId?: string;
	journalStartRealtimeTimestampUs?: string;
	journalProviderVersion?: string;
	journalSourceIdentities?: Array<{ path: string; dev: number; ino: number; isDirectory: boolean }>;
	journalSourceIdentityEnumerationTruncated?: boolean;
	journalQueryErrors?: LinuxJournalQueryError[];
}

const EVENT_KEYS = ["low", "high", "max", "oom", "oom_kill", "oom_group_kill"] as const;

function defaultReadBounded(path: string, limit: number): BoundedText | undefined {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, "r");
		const chunks: Buffer[] = [];
		let total = 0;
		while (total <= limit) {
			const chunk = Buffer.allocUnsafe(Math.min(4096, limit + 1 - total));
			const count = readSync(descriptor, chunk, 0, chunk.length, null);
			if (count === 0) break;
			chunks.push(chunk.subarray(0, count));
			total += count;
		}
		const combined = Buffer.concat(chunks, total);
		return {
			value: combined.subarray(0, limit).toString("utf8"),
			rawValue: combined.subarray(0, limit),
			truncated: combined.length > limit,
		};
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function defaultJournalctl(args: readonly string[], timeoutMs: number, stdoutLimit: number): JournalResult {
	const result: Pick<SpawnSyncReturns<Buffer>, "status" | "stdout" | "stderr" | "error"> = spawnSync(
		"journalctl",
		args,
		{
			stdio: ["ignore", "pipe", "pipe"],
			timeout: timeoutMs,
			maxBuffer: stdoutLimit,
			killSignal: "SIGKILL",
		},
	);
	return {
		status: result.status,
		stdout: result.stdout ?? Buffer.alloc(0),
		stderr: result.stderr ?? Buffer.alloc(0),
		errorCode: (result.error as NodeJS.ErrnoException | undefined)?.code,
	};
}

function journalBytes(value: string | Buffer): Buffer {
	return Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
}

function journalText(value: string | Buffer): string {
	return Buffer.isBuffer(value) ? value.toString("utf8") : value;
}

function clearJournalResult(result: JournalResult): void {
	result.stdout = Buffer.alloc(0);
	result.stderr = Buffer.alloc(0);
}

function dependencies(
	overrides: Partial<LinuxIncidentCollectorDependencies> | undefined,
): LinuxIncidentCollectorDependencies {
	return {
		platform: process.platform,
		now: () => new Date(),
		monotonicNs: () => process.hrtime.bigint().toString(),
		getProcessStartId,
		readBounded: defaultReadBounded,
		stat: (path) => {
			try {
				const stat = statSync(path);
				return { dev: stat.dev, ino: stat.ino, isDirectory: stat.isDirectory() };
			} catch {
				return undefined;
			}
		},
		readLink: (path) => {
			try {
				return readlinkSync(path);
			} catch {
				return undefined;
			}
		},
		runJournalctl: defaultJournalctl,
		...overrides,
	};
}

export function defaultLinuxCgroupV2ResolutionDependencies(): LinuxCgroupV2ResolutionDependencies {
	const resolved = dependencies(undefined);
	return { readBounded: resolved.readBounded, stat: resolved.stat };
}

function evidenceDir(runDir: string): string {
	return join(runDir, "evidence");
}

function monitorPath(runDir: string): string {
	return join(runDir, MONITOR_FILE_NAME);
}

function memoryPath(runDir: string): string {
	return join(evidenceDir(runDir), MEMORY_FILE_NAME);
}

function auditPath(runDir: string): string {
	return join(evidenceDir(runDir), AUDIT_FILE_NAME);
}

function systemJournalPath(runDir: string): string {
	return join(evidenceDir(runDir), SYSTEM_JOURNAL_FILE_NAME);
}

function atomicWriteJson(path: string, value: unknown, limit: number): boolean {
	let serialized: string;
	try {
		serialized = `${JSON.stringify(value)}\n`;
	} catch {
		return false;
	}
	if (Buffer.byteLength(serialized) > limit) return false;
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
	try {
		writeFileSync(temporary, serialized, { mode: 0o600 });
		chmodSync(temporary, 0o600);
		renameSync(temporary, path);
		chmodSync(path, 0o600);
		return true;
	} catch {
		try {
			rmSync(temporary, { force: true });
		} catch {}
		return false;
	}
}

function readJson(path: string, limit: number): unknown {
	const bounded = defaultReadBounded(path, limit);
	if (!bounded || bounded.truncated) return undefined;
	try {
		return JSON.parse(bounded.value) as unknown;
	} catch {
		return undefined;
	}
}

function unavailableMemorySummary(reason: string): LinuxMemorySummary {
	return {
		schemaVersion: 1,
		provider: "linux_cgroup_v2",
		capability: {
			status: "unavailable",
			reason,
			sourceLayer: "service_resource",
			diagnosticOnly: true,
			unprivilegedOnly: true,
		},
		targetIdentityValidated: false,
		extrema: {},
		sampleTail: [],
		counterChanges: [],
		sampleCount: 0,
	};
}

function writeUnavailableAudit(runDir: string, reason: string, deps: LinuxIncidentCollectorDependencies): void {
	const existing = readAuditSummary(runDir);
	const monitor = readMonitor(runDir);
	const target = monitor ? { pid: monitor.targetPid, processStartId: monitor.targetProcessStartId } : existing?.target;
	const summary: LinuxAuditSummary = existing ?? {
		schemaVersion: 1,
		provider: "linux_audit_journal",
		target,
		capability: auditCapability("unavailable", reason),
		lastObservation: { wallTime: deps.now().toISOString(), outcome: "unavailable", reason, sourceTruncated: false },
		records: [],
		droppedRecordCount: 0,
	};
	summary.target = target;
	summary.capability = auditCapability("unavailable", reason);
	summary.lastObservation = {
		wallTime: deps.now().toISOString(),
		outcome: "unavailable",
		reason,
		sourceTruncated: false,
	};
	atomicWriteJson(auditPath(runDir), summary, MEMORY_FILE_LIMIT);
}

function auditCapability(status: "available" | "unavailable", reason: string): LinuxAuditSummary["capability"] {
	return {
		status,
		reason,
		sourceLayer: "kernel",
		diagnosticOnly: true,
		preexistingRecordsOnly: true,
		crossBootJournalQuery: true,
		automaticJournalConfiguration: false,
		operatorManagedPersistentJournalCompatible: true,
		unprivilegedOnly: true,
		rawRecordsPersisted: false,
		canonicalRawSource: "linux_system_journal_range",
		ruleInstallation: false,
		groupTargets: false,
		pidfdTargets: false,
		targetStartIdentityInAuditRecord: false,
		senderStartIdentitySource: "bounded_post_observation",
		timeoutMs: AUDIT_TIMEOUT_MS,
		queryStdoutByteLimit: AUDIT_STDOUT_LIMIT,
		journalRecordLimit: false,
		retainedDerivedRecords: AUDIT_RECORD_LIMIT,
		lineageDepth: MAX_LINEAGE_DEPTH,
	};
}

function safeInteger(value: unknown, minimum = 0): number | undefined {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum ? value : undefined;
}

function isHash(value: unknown): value is string {
	return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function safeJournalCursor(value: unknown): string | undefined {
	return typeof value === "string" && /^[\x20-\x7e]{1,2048}$/.test(value) ? value : undefined;
}

function safeBootId(value: unknown): string | undefined {
	return typeof value === "string" && /^[a-fA-F0-9]{32}$/.test(value) ? value.toLowerCase() : undefined;
}

function safeRealtimeTimestampUs(value: unknown): string | undefined {
	return typeof value === "string" && /^\d{10,20}$/.test(value) ? value : undefined;
}

function journalPosition(record: Readonly<Record<string, unknown>>): LinuxJournalPosition | undefined {
	const cursor = safeJournalCursor(record.__CURSOR ?? record._CURSOR);
	if (!cursor) return undefined;
	return {
		cursor,
		bootId: safeBootId(record._BOOT_ID),
		realtimeTimestampUs: safeRealtimeTimestampUs(record.__REALTIME_TIMESTAMP),
	};
}

function sanitizeJournalQueryErrors(value: unknown): LinuxJournalQueryError[] {
	if (!Array.isArray(value)) return [];
	return value
		.flatMap((item) => {
			if (!item || typeof item !== "object" || Array.isArray(item)) return [];
			const error = item as Record<string, unknown>;
			const operation = ["cursor", "range", "incident_export", "provider_version"].includes(String(error.operation))
				? (error.operation as LinuxJournalQueryError["operation"])
				: undefined;
			return operation && typeof error.wallTime === "string" && typeof error.stderr === "string"
				? [
						{
							wallTime: error.wallTime,
							status: typeof error.status === "number" ? error.status : null,
							errorCode: typeof error.errorCode === "string" ? error.errorCode : undefined,
							stderr: error.stderr,
							operation,
							lossOrRotation: error.lossOrRotation === true,
						},
					]
				: [];
		})
		.slice(-JOURNAL_QUERY_ERROR_LIMIT);
}

function sanitizeSourceIdentities(
	value: unknown,
): Array<{ path: string; dev: number; ino: number; isDirectory: boolean }> {
	if (!Array.isArray(value)) return [];
	return value.flatMap((item) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) return [];
		const record = item as Record<string, unknown>;
		const dev = safeInteger(record.dev);
		const ino = safeInteger(record.ino);
		return typeof record.path === "string" &&
			dev !== undefined &&
			ino !== undefined &&
			typeof record.isDirectory === "boolean"
			? [{ path: record.path, dev, ino, isDirectory: record.isDirectory }]
			: [];
	});
}

function readMonitor(runDir: string): LinuxMonitorState | undefined {
	const value = readJson(monitorPath(runDir), MONITOR_FILE_LIMIT);
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	const targetPid = safeInteger(record.targetPid, 1);
	if (
		record.schemaVersion !== 1 ||
		!targetPid ||
		typeof record.targetProcessStartId !== "string" ||
		!/^proc:[1-9]\d*$/.test(record.targetProcessStartId) ||
		typeof record.baselineEpochMs !== "number" ||
		!Number.isFinite(record.baselineEpochMs)
	)
		return undefined;
	let cgroupDirectory: string | undefined;
	let cgroupDev: number | undefined;
	let cgroupIno: number | undefined;
	let cgroupIdentityHash: string | undefined;
	const hasCgroupValue =
		record.cgroupDirectory !== undefined ||
		record.cgroupDev !== undefined ||
		record.cgroupIno !== undefined ||
		record.cgroupIdentityHash !== undefined;
	if (hasCgroupValue) {
		cgroupDev = safeInteger(record.cgroupDev);
		cgroupIno = safeInteger(record.cgroupIno);
		if (
			typeof record.cgroupDirectory !== "string" ||
			!safeAbsoluteComponents(record.cgroupDirectory) ||
			cgroupDev === undefined ||
			cgroupIno === undefined ||
			!isHash(record.cgroupIdentityHash)
		)
			return undefined;
		cgroupDirectory = record.cgroupDirectory;
		cgroupIdentityHash = record.cgroupIdentityHash;
	}
	return {
		schemaVersion: 1,
		targetPid,
		targetProcessStartId: record.targetProcessStartId,
		cgroupDirectory,
		cgroupDev,
		cgroupIno,
		cgroupIdentityHash,
		baselineEpochMs: record.baselineEpochMs,
		systemJournalCursor: safeJournalCursor(record.systemJournalCursor),
		journalStartCursor: safeJournalCursor(record.journalStartCursor),
		journalStartBootId: safeBootId(record.journalStartBootId),
		journalStartRealtimeTimestampUs: safeRealtimeTimestampUs(record.journalStartRealtimeTimestampUs),
		journalProviderVersion:
			typeof record.journalProviderVersion === "string" ? record.journalProviderVersion : undefined,
		journalSourceIdentities: sanitizeSourceIdentities(record.journalSourceIdentities),
		journalSourceIdentityEnumerationTruncated: record.journalSourceIdentityEnumerationTruncated === true,
		journalQueryErrors: sanitizeJournalQueryErrors(record.journalQueryErrors),
	};
}

function writeMonitor(runDir: string, monitor: LinuxMonitorState): boolean {
	return atomicWriteJson(monitorPath(runDir), monitor, MONITOR_FILE_LIMIT);
}

function safeAbsoluteComponents(value: string): string[] | undefined {
	if (!posix.isAbsolute(value) || /[\0\r\n]/.test(value) || value.includes("(deleted)")) return undefined;
	if (value === "/") return [];
	const components = value.slice(1).split("/");
	if (components.some((component) => component.length === 0 || component === "." || component === ".."))
		return undefined;
	return components;
}

function decodeMountField(value: string): string | undefined {
	if (/\\(?!040|011|012|134)/.test(value)) return undefined;
	const decoded = value.replace(/\\(040|011|012|134)/g, (_match, octal: string) =>
		String.fromCharCode(Number.parseInt(octal, 8)),
	);
	return safeAbsoluteComponents(decoded) ? decoded : undefined;
}

function exactBoundedBytes(value: BoundedText): Buffer | undefined {
	const bytes = Buffer.from(value.rawValue ?? Buffer.from(value.value, "utf8"));
	return Buffer.from(value.value, "utf8").equals(bytes) ? bytes : undefined;
}

function safeCgroupRelativePath(value: string): string | undefined {
	if (value.includes("\\")) return undefined;
	const components = safeAbsoluteComponents(value);
	return components ? components.join("/") : undefined;
}

function suffixWithinRoot(root: string, membership: string): string | undefined {
	const rootComponents = safeAbsoluteComponents(root);
	const membershipComponents = safeAbsoluteComponents(membership);
	if (!rootComponents || !membershipComponents || rootComponents.length > membershipComponents.length)
		return undefined;
	if (rootComponents.some((component, index) => membershipComponents[index] !== component)) return undefined;
	return membershipComponents.slice(rootComponents.length).join("/");
}

function insideMount(mountPoint: string, candidate: string): boolean {
	const relative = posix.relative(mountPoint, candidate);
	return relative === "" || (!relative.startsWith("../") && relative !== ".." && !posix.isAbsolute(relative));
}

function unifiedCgroupPath(value: string): string | undefined {
	let selected: string | undefined;
	for (const line of value.split("\n").slice(0, 64)) {
		const match = line.match(/^0::(\/[^\r\n]*)$/);
		if (match) {
			if (selected !== undefined) return undefined;
			selected = safeCgroupRelativePath(match[1]);
			if (selected === undefined) return undefined;
		} else if (line.startsWith("0:")) return undefined;
	}
	return selected;
}

function currentCgroupIdentityHash(
	pid: number,
	dev: number,
	ino: number,
	deps: LinuxIncidentCollectorDependencies,
): string | undefined {
	const cgroup = deps.readBounded(`/proc/${pid}/cgroup`, SOURCE_READ_LIMIT);
	if (!cgroup || cgroup.truncated) return undefined;
	const relative = unifiedCgroupPath(cgroup.value);
	return relative === undefined ? undefined : createHash("sha256").update(`${relative}\0${dev}\0${ino}`).digest("hex");
}

export function resolveCgroupDirectory(
	pid: number,
	deps: LinuxCgroupV2ResolutionDependencies,
): ResolvedLinuxCgroupV2Directory | undefined {
	const membershipSourcePath = `/proc/${pid}/cgroup`;
	const cgroup = deps.readBounded(membershipSourcePath, SOURCE_READ_LIMIT);
	const mountinfo = deps.readBounded("/proc/self/mountinfo", MOUNTINFO_READ_LIMIT);
	const membershipRaw = cgroup && !cgroup.truncated ? exactBoundedBytes(cgroup) : undefined;
	const mountinfoRaw = mountinfo && !mountinfo.truncated ? exactBoundedBytes(mountinfo) : undefined;
	if (
		!cgroup ||
		cgroup.truncated ||
		!membershipRaw ||
		membershipRaw.length > SOURCE_READ_LIMIT ||
		!mountinfo ||
		mountinfo.truncated ||
		!mountinfoRaw ||
		mountinfoRaw.length > MOUNTINFO_READ_LIMIT
	)
		return undefined;
	const relativeCgroup = unifiedCgroupPath(cgroup.value);
	if (relativeCgroup === undefined) return undefined;
	const resolved: Array<{ directory: string; dev: number; ino: number }> = [];
	for (const line of mountinfo.value.split("\n").slice(0, 256)) {
		const separator = line.indexOf(" - ");
		if (separator === -1) continue;
		const before = line.slice(0, separator).split(" ");
		const after = line.slice(separator + 3).split(" ");
		if (before.length < 6 || after[0] !== "cgroup2") continue;
		const root = decodeMountField(before[3]);
		const mountPoint = decodeMountField(before[4]);
		if (!root || !mountPoint) continue;
		const membership = relativeCgroup ? `/${relativeCgroup}` : "/";
		const rootedSuffix = suffixWithinRoot(root, membership);
		const candidates = new Set([posix.resolve(mountPoint, relativeCgroup)]);
		if (rootedSuffix !== undefined) candidates.add(posix.resolve(mountPoint, rootedSuffix));
		for (const directory of candidates) {
			if (!insideMount(mountPoint, directory)) continue;
			const identity = deps.stat(directory);
			if (!identity?.isDirectory || !Number.isSafeInteger(identity.dev) || !Number.isSafeInteger(identity.ino))
				continue;
			const cgroupRecheck = deps.readBounded(membershipSourcePath, SOURCE_READ_LIMIT);
			const identityRecheck = deps.stat(directory);
			if (
				!cgroupRecheck ||
				cgroupRecheck.truncated ||
				!exactBoundedBytes(cgroupRecheck) ||
				!exactBoundedBytes(cgroupRecheck)?.equals(membershipRaw) ||
				!identityRecheck?.isDirectory ||
				identityRecheck.dev !== identity.dev ||
				identityRecheck.ino !== identity.ino
			)
				continue;
			resolved.push({ directory, dev: identity.dev, ino: identity.ino });
		}
	}
	if (resolved.length === 0) return undefined;
	const identities = new Set(resolved.map((item) => `${item.dev}:${item.ino}`));
	if (identities.size !== 1) return undefined;
	const selected = resolved[0];
	const identityHash = createHash("sha256")
		.update(`${relativeCgroup}\0${selected.dev}\0${selected.ino}`)
		.digest("hex");
	return {
		...selected,
		identityHash,
		membershipRaw,
		membershipSourcePath,
		membershipSha256: createHash("sha256").update(membershipRaw).digest("hex"),
	};
}

function parseCounterFile(value: BoundedText | undefined): Record<string, number> | undefined {
	if (!value || value.truncated) return undefined;
	const result: Record<string, number> = {};
	for (const line of value.value.split("\n").slice(0, 32)) {
		const match = line.match(/^([a-z_]{1,32})\s+(\d+)$/);
		if (!match || !EVENT_KEYS.includes(match[1] as (typeof EVENT_KEYS)[number])) continue;
		const numeric = Number(match[2]);
		if (Number.isSafeInteger(numeric) && numeric >= 0) result[match[1]] = numeric;
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

function parseSingleNumber(value: BoundedText | undefined): { value?: number; unlimited?: boolean } {
	if (!value || value.truncated) return {};
	const trimmed = value.value.trim();
	if (trimmed === "max") return { unlimited: true };
	if (!/^\d{1,24}$/.test(trimmed)) return {};
	const numeric = Number(trimmed);
	return Number.isSafeInteger(numeric) && numeric >= 0 ? { value: numeric } : {};
}

function parsePressure(value: BoundedText | undefined): LinuxPressureSample | undefined {
	if (!value || value.truncated) return undefined;
	const result: LinuxPressureSample = {};
	for (const line of value.value.split("\n").slice(0, 4)) {
		const match = line.match(
			/^(some|full) avg10=(\d+(?:\.\d+)?) avg60=(\d+(?:\.\d+)?) avg300=(\d+(?:\.\d+)?) total=(\d+)$/,
		);
		if (!match) continue;
		const [avg10, avg60, avg300, total] = match.slice(2).map(Number);
		if (
			![avg10, avg60, avg300, total].every(Number.isFinite) ||
			![avg10, avg60, avg300].every((average) => average >= 0 && average <= 100) ||
			!Number.isSafeInteger(total) ||
			total < 0
		)
			continue;
		result[match[1] as "some" | "full"] = { avg10, avg60, avg300, total };
	}
	return result.some || result.full ? result : undefined;
}

function targetIdentityState(
	monitor: LinuxMonitorState,
	deps: LinuxIncidentCollectorDependencies,
): LinuxMemorySample["targetIdentity"] {
	const current = deps.getProcessStartId(monitor.targetPid);
	if (current === monitor.targetProcessStartId) return "matched";
	if (current === undefined) return "saved_after_exit";
	if (!/^proc:[1-9]\d*$/.test(current)) return "unavailable";
	return "pid_reused";
}

function readExactDiagnosticSource(
	path: string,
	limit: number,
	phase: LinuxMemorySamplePhase,
	monitor: LinuxMonitorState,
	deps: LinuxIncidentCollectorDependencies,
): BoundedText | undefined {
	const value = deps.readBounded(path, limit);
	if (value) {
		persistRawOccurrence(deps, {
			source: path.startsWith("/proc/") ? "procfs" : "cgroupfs",
			sourcePath: path,
			bytes: value.rawValue ?? Buffer.from(value.value, "utf8"),
			encoding: "exact-file-bytes",
			phase,
			wallTime: deps.now().toISOString(),
			monotonicNs: deps.monotonicNs(),
			identity: {
				targetPid: monitor.targetPid,
				targetProcessStartId: monitor.targetProcessStartId,
				cgroupDirectory: monitor.cgroupDirectory,
				cgroupDev: monitor.cgroupDev,
				cgroupIno: monitor.cgroupIno,
				truncated: value.truncated,
			},
		});
	}
	return value;
}

function captureMemorySample(
	monitor: LinuxMonitorState,
	phase: LinuxMemorySamplePhase,
	sequence: number,
	deps: LinuxIncidentCollectorDependencies,
	captureBroadRaw: boolean,
): LinuxMemorySample | undefined {
	const directory = monitor.cgroupDirectory;
	const expectedDev = monitor.cgroupDev;
	const expectedIno = monitor.cgroupIno;
	const expectedHash = monitor.cgroupIdentityHash;
	if (!directory || expectedDev === undefined || expectedIno === undefined || !expectedHash) return undefined;
	const targetState = targetIdentityState(monitor, deps);
	if (targetState === "matched") {
		const liveCgroup = resolveCgroupDirectory(monitor.targetPid, deps);
		if (
			!liveCgroup ||
			liveCgroup.dev !== expectedDev ||
			liveCgroup.ino !== expectedIno ||
			liveCgroup.identityHash !== expectedHash
		)
			return undefined;
	}
	const identity = deps.stat(directory);
	if (!identity?.isDirectory || identity.dev !== expectedDev || identity.ino !== expectedIno) return undefined;
	const broadRawCapture = captureBroadRaw && targetState !== "matched";
	const broadDerivedCapture = true;
	const targetCgroup =
		targetState === "matched"
			? readExactDiagnosticSource(`/proc/${monitor.targetPid}/cgroup`, MOUNTINFO_READ_LIMIT, phase, monitor, deps)
			: undefined;
	void targetCgroup;
	const membersSource = readExactDiagnosticSource(
		join(directory, "cgroup.procs"),
		MOUNTINFO_READ_LIMIT,
		phase,
		monitor,
		deps,
	);
	const membership =
		membersSource && !membersSource.truncated
			? (() => {
					const members = new Set(
						membersSource.value
							.split("\n")
							.filter((line) => /^\d{1,10}$/.test(line))
							.map(Number),
					);
					return { memberCount: members.size, targetMember: members.has(monitor.targetPid) };
				})()
			: {};
	const localSource = readExactDiagnosticSource(
		join(directory, "memory.events.local"),
		MOUNTINFO_READ_LIMIT,
		phase,
		monitor,
		deps,
	);
	const hierarchicalSource = readExactDiagnosticSource(
		join(directory, "memory.events"),
		MOUNTINFO_READ_LIMIT,
		phase,
		monitor,
		deps,
	);
	const eventsLocal = parseCounterFile(localSource);
	const events = parseCounterFile(hierarchicalSource);
	const currentSource = readExactDiagnosticSource(join(directory, "memory.current"), 128, phase, monitor, deps);
	const peakSource = readExactDiagnosticSource(join(directory, "memory.peak"), 128, phase, monitor, deps);
	const maximumSource = readExactDiagnosticSource(join(directory, "memory.max"), 128, phase, monitor, deps);
	const pressureSource = readExactDiagnosticSource(
		join(directory, "memory.pressure"),
		MOUNTINFO_READ_LIMIT,
		phase,
		monitor,
		deps,
	);
	const hostPressureSource = readExactDiagnosticSource(
		"/proc/pressure/memory",
		MOUNTINFO_READ_LIMIT,
		phase,
		monitor,
		deps,
	);
	const current = broadDerivedCapture ? parseSingleNumber(currentSource) : {};
	const peak = broadDerivedCapture ? parseSingleNumber(peakSource) : {};
	const maximum = broadDerivedCapture ? parseSingleNumber(maximumSource) : {};
	const pressure = broadDerivedCapture ? parsePressure(pressureSource) : undefined;
	const hostPressure = broadDerivedCapture ? parsePressure(hostPressureSource) : undefined;
	if (broadRawCapture) {
		for (const name of [
			"memory.stat",
			"memory.swap.current",
			"memory.swap.max",
			"memory.low",
			"memory.high",
			"memory.min",
			"memory.oom.group",
		]) {
			readExactDiagnosticSource(join(directory, name), MOUNTINFO_READ_LIMIT, phase, monitor, deps);
		}
	}
	const identityRecheck = deps.stat(directory);
	if (!identityRecheck?.isDirectory || identityRecheck.dev !== identity.dev || identityRecheck.ino !== identity.ino)
		return undefined;
	if (
		targetState === "matched" &&
		(deps.getProcessStartId(monitor.targetPid) !== monitor.targetProcessStartId ||
			currentCgroupIdentityHash(monitor.targetPid, expectedDev, expectedIno, deps) !== expectedHash)
	)
		return undefined;
	return {
		sequence,
		phase,
		wallTime: deps.now().toISOString(),
		monotonicNs: deps.monotonicNs(),
		targetIdentity: targetState,
		...membership,
		memoryCurrent: current.value,
		memoryPeak: peak.value,
		memoryMax: maximum.value,
		memoryMaxUnlimited: maximum.unlimited,
		eventsLocal,
		events,
		pressure,
		hostPressure,
	};
}

function validSample(value: unknown): value is LinuxMemorySample {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const record = value as Record<string, unknown>;
	return (
		safeInteger(record.sequence, 1) !== undefined &&
		typeof record.wallTime === "string" &&
		/^\d{4}-\d{2}-\d{2}T/.test(record.wallTime) &&
		typeof record.monotonicNs === "string" &&
		["baseline", "periodic", "service", "anomaly", "final"].includes(String(record.phase))
	);
}

function sanitizePersistedCounters(value: unknown): Record<string, number> | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	const result: Record<string, number> = {};
	for (const key of EVENT_KEYS) {
		const numeric = safeInteger(record[key]);
		if (numeric !== undefined) result[key] = numeric;
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

function sanitizePersistedPressure(value: unknown): LinuxPressureSample | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	const result: LinuxPressureSample = {};
	for (const key of ["some", "full"] as const) {
		const candidate = record[key];
		if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
		const values = candidate as Record<string, unknown>;
		const avg10 = typeof values.avg10 === "number" && Number.isFinite(values.avg10) ? values.avg10 : undefined;
		const avg60 = typeof values.avg60 === "number" && Number.isFinite(values.avg60) ? values.avg60 : undefined;
		const avg300 = typeof values.avg300 === "number" && Number.isFinite(values.avg300) ? values.avg300 : undefined;
		const total = safeInteger(values.total);
		if (
			avg10 === undefined ||
			avg60 === undefined ||
			avg300 === undefined ||
			total === undefined ||
			![avg10, avg60, avg300].every((average) => average >= 0 && average <= 100)
		)
			continue;
		result[key] = { avg10, avg60, avg300, total };
	}
	return result.some || result.full ? result : undefined;
}

function sanitizeMemorySample(value: unknown): LinuxMemorySample | undefined {
	if (!validSample(value)) return undefined;
	const record = value as unknown as Record<string, unknown>;
	const phase = record.phase as LinuxMemorySamplePhase;
	const targetIdentity =
		record.targetIdentity === "matched" ||
		record.targetIdentity === "saved_after_exit" ||
		record.targetIdentity === "pid_reused" ||
		record.targetIdentity === "unavailable"
			? record.targetIdentity
			: "unavailable";
	const numeric = (key: string) => safeInteger(record[key]);
	return {
		sequence: safeInteger(record.sequence, 1) as number,
		phase,
		wallTime: String(record.wallTime).slice(0, 32),
		monotonicNs: /^\d{1,32}$/.test(String(record.monotonicNs)) ? String(record.monotonicNs) : "0",
		targetIdentity,
		memberCount: numeric("memberCount"),
		targetMember: typeof record.targetMember === "boolean" ? record.targetMember : undefined,
		memoryCurrent: numeric("memoryCurrent"),
		memoryPeak: numeric("memoryPeak"),
		memoryMax: numeric("memoryMax"),
		memoryMaxUnlimited: record.memoryMaxUnlimited === true ? true : undefined,
		eventsLocal: sanitizePersistedCounters(record.eventsLocal),
		events: sanitizePersistedCounters(record.events),
		pressure: sanitizePersistedPressure(record.pressure),
		hostPressure: sanitizePersistedPressure(record.hostPressure),
	};
}

const EXTREMA_KEYS = [
	"memoryCurrent",
	"memoryPeak",
	"memoryMax",
	"pressureSomeAvg10",
	"pressureSomeAvg60",
	"pressureSomeAvg300",
	"pressureSomeTotal",
	"pressureFullAvg10",
	"pressureFullAvg60",
	"pressureFullAvg300",
	"pressureFullTotal",
	"hostPressureSomeAvg10",
	"hostPressureSomeAvg60",
	"hostPressureSomeAvg300",
	"hostPressureSomeTotal",
	"hostPressureFullAvg10",
	"hostPressureFullAvg60",
	"hostPressureFullAvg300",
	"hostPressureFullTotal",
] as const;

function readMemorySummary(runDir: string, identityHash?: string): LinuxMemorySummary | undefined {
	const value = readJson(memoryPath(runDir), MEMORY_FILE_LIMIT);
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	if (
		record.schemaVersion !== 1 ||
		record.provider !== "linux_cgroup_v2" ||
		typeof record.targetIdentityValidated !== "boolean" ||
		!record.extrema ||
		typeof record.extrema !== "object" ||
		Array.isArray(record.extrema) ||
		!Array.isArray(record.sampleTail) ||
		record.sampleTail.length > SAMPLE_TAIL_LIMIT ||
		!Array.isArray(record.counterChanges) ||
		record.counterChanges.length > COUNTER_CHANGE_LIMIT
	)
		return undefined;
	const targetIdentityValidated = record.targetIdentityValidated;
	let target: LinuxMemorySummary["target"];
	if (record.target && typeof record.target === "object" && !Array.isArray(record.target)) {
		const identity = record.target as Record<string, unknown>;
		const pid = safeInteger(identity.pid, 1);
		if (pid && typeof identity.processStartId === "string" && /^proc:[1-9]\d*$/.test(identity.processStartId))
			target = { pid, processStartId: identity.processStartId };
	}
	if (targetIdentityValidated && !target) return undefined;
	let cgroup: LinuxMemorySummary["cgroup"];
	if (record.cgroup !== undefined) {
		if (!record.cgroup || typeof record.cgroup !== "object" || Array.isArray(record.cgroup)) return undefined;
		const identity = record.cgroup as Record<string, unknown>;
		const dev = safeInteger(identity.dev);
		const ino = safeInteger(identity.ino);
		const observedAttribution = identity.attribution;
		if (
			!isHash(identity.identityHash) ||
			typeof identity.directory !== "string" ||
			!safeAbsoluteComponents(identity.directory) ||
			dev === undefined ||
			ino === undefined ||
			(observedAttribution !== "dedicated" && observedAttribution !== "shared" && observedAttribution !== "unknown")
		)
			return undefined;
		cgroup = {
			identityHash: identity.identityHash,
			directory: identity.directory,
			dev,
			ino,
			attribution: observedAttribution,
		};
	}
	if (identityHash && cgroup?.identityHash !== identityHash) return undefined;
	const extrema: LinuxMemorySummary["extrema"] = {};
	const persistedExtrema = record.extrema as Record<string, unknown>;
	for (const key of EXTREMA_KEYS) {
		const candidate = persistedExtrema[key];
		if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
		const bounds = candidate as Record<string, unknown>;
		const minimum = typeof bounds.min === "number" && Number.isFinite(bounds.min) ? bounds.min : undefined;
		const maximum = typeof bounds.max === "number" && Number.isFinite(bounds.max) ? bounds.max : undefined;
		if (minimum !== undefined && maximum !== undefined && minimum >= 0 && maximum >= minimum)
			extrema[key] = { min: minimum, max: maximum };
	}
	const sampleTail = record.sampleTail.flatMap((item) => {
		const sample = sanitizeMemorySample(item);
		return sample ? [sample] : [];
	});
	const counterChanges: LinuxMemorySummary["counterChanges"] = record.counterChanges.flatMap((item) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) return [];
		const change = item as Record<string, unknown>;
		const sequence = safeInteger(change.sequence, 1);
		if (!sequence || typeof change.wallTime !== "string" || !/^\d{4}-\d{2}-\d{2}T/.test(change.wallTime)) return [];
		const deltas = (source: unknown): Record<string, number> | undefined => {
			if (!source || typeof source !== "object" || Array.isArray(source)) return undefined;
			const input = source as Record<string, unknown>;
			const result: Record<string, number> = {};
			for (const key of EVENT_KEYS) {
				const numeric = input[key];
				if (typeof numeric === "number" && Number.isSafeInteger(numeric) && numeric !== 0) result[key] = numeric;
			}
			return Object.keys(result).length > 0 ? result : undefined;
		};
		return [
			{
				sequence,
				wallTime: change.wallTime.slice(0, 32),
				local: deltas(change.local),
				hierarchical: deltas(change.hierarchical),
			},
		];
	});
	const capabilityRecord =
		record.capability && typeof record.capability === "object" && !Array.isArray(record.capability)
			? (record.capability as Record<string, unknown>)
			: {};
	const status = capabilityRecord.status === "available" ? "available" : "unavailable";
	const reason =
		typeof capabilityRecord.reason === "string" && /^[A-Za-z0-9_.:+-]{1,80}$/.test(capabilityRecord.reason)
			? capabilityRecord.reason
			: "summary_invalid";
	return {
		schemaVersion: 1,
		provider: "linux_cgroup_v2",
		target,
		capability: { status, reason, sourceLayer: "service_resource", diagnosticOnly: true, unprivilegedOnly: true },
		cgroup,
		targetIdentityValidated,
		baseline: sanitizeMemorySample(record.baseline),
		latest: sanitizeMemorySample(record.latest),
		extrema,
		sampleTail,
		counterChanges,
		sampleCount: safeInteger(record.sampleCount) ?? sampleTail.length,
	};
}

function updateExtrema(summary: LinuxMemorySummary, sample: LinuxMemorySample): void {
	const candidates: Record<string, number | undefined> = {
		memoryCurrent: sample.memoryCurrent,
		memoryPeak: sample.memoryPeak,
		memoryMax: sample.memoryMax,
		pressureSomeAvg10: sample.pressure?.some?.avg10,
		pressureSomeAvg60: sample.pressure?.some?.avg60,
		pressureSomeAvg300: sample.pressure?.some?.avg300,
		pressureSomeTotal: sample.pressure?.some?.total,
		pressureFullAvg10: sample.pressure?.full?.avg10,
		pressureFullAvg60: sample.pressure?.full?.avg60,
		pressureFullAvg300: sample.pressure?.full?.avg300,
		pressureFullTotal: sample.pressure?.full?.total,
		hostPressureSomeAvg10: sample.hostPressure?.some?.avg10,
		hostPressureSomeAvg60: sample.hostPressure?.some?.avg60,
		hostPressureSomeAvg300: sample.hostPressure?.some?.avg300,
		hostPressureSomeTotal: sample.hostPressure?.some?.total,
		hostPressureFullAvg10: sample.hostPressure?.full?.avg10,
		hostPressureFullAvg60: sample.hostPressure?.full?.avg60,
		hostPressureFullAvg300: sample.hostPressure?.full?.avg300,
		hostPressureFullTotal: sample.hostPressure?.full?.total,
	};
	for (const [key, value] of Object.entries(candidates)) {
		if (value === undefined || !Number.isFinite(value)) continue;
		const previous = summary.extrema[key];
		summary.extrema[key] = previous
			? { min: Math.min(previous.min, value), max: Math.max(previous.max, value) }
			: { min: value, max: value };
	}
}

function counterDelta(
	previous: Record<string, number> | undefined,
	latest: Record<string, number> | undefined,
): Record<string, number> | undefined {
	if (!previous || !latest) return undefined;
	const result: Record<string, number> = {};
	for (const key of EVENT_KEYS) {
		const before = previous[key];
		const after = latest[key];
		if (before === undefined || after === undefined || before === after) continue;
		const delta = after - before;
		if (Number.isSafeInteger(delta)) result[key] = delta;
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

function attribution(summary: LinuxMemorySummary): "dedicated" | "shared" | "unknown" {
	const samples = [summary.baseline, ...summary.sampleTail].filter(validSample);
	if (samples.some((sample) => sample.memberCount !== undefined && sample.memberCount > 1)) return "shared";
	const baseline = summary.baseline;
	if (baseline?.memberCount !== 1 || baseline.targetMember !== true) return "unknown";
	if (
		samples.some(
			(sample) =>
				sample.memberCount === undefined ||
				sample.targetIdentity === "pid_reused" ||
				sample.targetIdentity === "unavailable",
		)
	)
		return "unknown";
	if (samples.some((sample) => sample.targetIdentity === "saved_after_exit" && (sample.memberCount ?? 0) > 0))
		return "unknown";
	return "dedicated";
}

function appendMemorySample(
	runDir: string,
	monitor: LinuxMonitorState,
	phase: LinuxMemorySamplePhase,
	deps: LinuxIncidentCollectorDependencies,
	captureBroadRaw = false,
): LinuxMemorySummary | undefined {
	if (
		!monitor.cgroupIdentityHash ||
		monitor.cgroupDev === undefined ||
		monitor.cgroupIno === undefined ||
		!monitor.cgroupDirectory
	)
		return readMemorySummary(runDir);
	const existing = readMemorySummary(runDir, monitor.cgroupIdentityHash);
	if (!existing && phase !== "baseline") return undefined;
	const summary: LinuxMemorySummary = existing ?? {
		schemaVersion: 1,
		provider: "linux_cgroup_v2",
		target: { pid: monitor.targetPid, processStartId: monitor.targetProcessStartId },
		capability: {
			status: "available",
			reason: "sampled",
			sourceLayer: "service_resource",
			diagnosticOnly: true,
			unprivilegedOnly: true,
		},
		cgroup: {
			identityHash: monitor.cgroupIdentityHash,
			directory: monitor.cgroupDirectory,
			dev: monitor.cgroupDev,
			ino: monitor.cgroupIno,
			attribution: "unknown",
		},
		targetIdentityValidated: true,
		extrema: {},
		sampleTail: [],
		counterChanges: [],
		sampleCount: 0,
	};
	const sample = captureMemorySample(monitor, phase, summary.sampleCount + 1, deps, captureBroadRaw);
	if (!sample) {
		summary.capability = {
			status: "unavailable",
			reason: "cgroup_identity_unavailable",
			sourceLayer: "service_resource",
			diagnosticOnly: true,
			unprivilegedOnly: true,
		};
		atomicWriteJson(memoryPath(runDir), summary, MEMORY_FILE_LIMIT);
		return summary;
	}
	const previous = summary.latest;
	const previousAttribution = summary.cgroup?.attribution;
	const hadSamples = summary.sampleCount > 0;
	if (!summary.baseline) summary.baseline = sample;
	summary.latest = sample;
	summary.sampleCount += 1;
	summary.sampleTail = [...summary.sampleTail, sample].slice(-SAMPLE_TAIL_LIMIT);
	const local = counterDelta(previous?.eventsLocal, sample.eventsLocal);
	const hierarchical = counterDelta(previous?.events, sample.events);
	if (local || hierarchical) {
		summary.counterChanges = [
			...summary.counterChanges,
			{ sequence: sample.sequence, wallTime: sample.wallTime, local, hierarchical },
		].slice(-COUNTER_CHANGE_LIMIT);
	}
	updateExtrema(summary, sample);
	if (summary.cgroup) {
		const observedAttribution = attribution(summary);
		summary.cgroup.attribution = !hadSamples
			? observedAttribution
			: previousAttribution === "shared" || observedAttribution === "shared"
				? "shared"
				: previousAttribution === "unknown" || observedAttribution === "unknown"
					? "unknown"
					: "dedicated";
	}
	summary.capability = {
		status: "available",
		reason: "sampled",
		sourceLayer: "service_resource",
		diagnosticOnly: true,
		unprivilegedOnly: true,
	};
	atomicWriteJson(memoryPath(runDir), summary, MEMORY_FILE_LIMIT);
	return summary;
}

function cursorFromOutput(output: string | Buffer): string | undefined {
	const stdout = journalText(output);
	const marker = stdout.match(/^-- cursor: ([\x20-\x7e]{1,2048})$/m)?.[1];
	if (marker) return marker;
	let cursor: string | undefined;
	for (const line of stdout.split("\n").slice(0, AUDIT_LINE_LIMIT)) {
		if (Buffer.byteLength(line) > SOURCE_READ_LIMIT) continue;
		try {
			const record = JSON.parse(line) as Record<string, unknown>;
			const observed = record.__CURSOR ?? record._CURSOR;
			if (typeof observed === "string" && /^[\x20-\x7e]{1,2048}$/.test(observed)) cursor = observed;
		} catch {}
	}
	return cursor;
}

function journalFailure(result: JournalResult, stdoutLimit = AUDIT_STDOUT_LIMIT): string | undefined {
	if (result.errorCode === "ETIMEDOUT") return "journal_query_timeout";
	if (result.errorCode === "ENOBUFS" || journalBytes(result.stdout).length > stdoutLimit)
		return "journal_stdout_limit";
	if (result.errorCode === "ENOENT") return "journalctl_unavailable";
	if (result.status === 0) return undefined;
	const stderr = journalText(result.stderr).toLowerCase();
	if (stderr.includes("permission") || stderr.includes("access denied")) return "journal_permission_denied";
	if (stderr.includes("cursor")) return "journal_cursor_unavailable";
	return "journal_query_failed";
}

function journalQueryError(
	result: JournalResult,
	operation: LinuxJournalQueryError["operation"],
	deps: LinuxIncidentCollectorDependencies,
): LinuxJournalQueryError {
	const stderr = journalText(result.stderr);
	const lower = stderr.toLowerCase();
	return {
		wallTime: deps.now().toISOString(),
		status: result.status,
		errorCode: result.errorCode,
		stderr,
		operation,
		lossOrRotation: lower.includes("rotat") || lower.includes("cursor") || lower.includes("data lost"),
	};
}

function acquireAuditCursor(deps: LinuxIncidentCollectorDependencies): {
	cursor?: string;
	bootId?: string;
	realtimeTimestampUs?: string;
	reason: string;
	queryError?: LinuxJournalQueryError;
} {
	const result = deps.runJournalctl(
		["--no-pager", "--quiet", "--output=json", "--lines=1", "--show-cursor"],
		AUDIT_TIMEOUT_MS,
		AUDIT_STDOUT_LIMIT,
	);
	const failure = journalFailure(result);
	if (failure) {
		const queryError = journalQueryError(result, "cursor", deps);
		for (const [stream, bytes] of [
			["stdout", journalBytes(result.stdout)],
			["stderr", journalBytes(result.stderr)],
		] as const) {
			persistRawOccurrence(deps, {
				source: "journal-query-error",
				sourcePath: `journalctl:${stream}`,
				bytes,
				encoding: `journalctl-error-${stream}`,
				phase: "startup",
				wallTime: queryError.wallTime,
				monotonicNs: deps.monotonicNs(),
				identity: { status: result.status, errorCode: result.errorCode, operation: "cursor", stream },
			});
		}
		clearJournalResult(result);
		return { reason: failure, queryError };
	}
	let position: LinuxJournalPosition | undefined;
	for (const line of journalText(result.stdout).split("\n").slice(0, 4)) {
		try {
			const parsed = JSON.parse(line) as Record<string, unknown>;
			position = journalPosition(parsed) ?? position;
		} catch {}
	}
	const cursor = cursorFromOutput(result.stdout) ?? position?.cursor;
	clearJournalResult(result);
	if (!cursor) return { reason: "journal_cursor_not_observed" };
	return {
		cursor,
		bootId: position?.bootId,
		realtimeTimestampUs: position?.realtimeTimestampUs,
		reason: "baseline_cursor_established",
	};
}

function safeExecutable(value: string | undefined): string | undefined {
	if (!value) return undefined;
	const unquoted = value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
	if (unquoted.length < 1 || unquoted.length > 512 || !unquoted.startsWith("/") || /[\0-\x1f\x7f]/.test(unquoted))
		return undefined;
	return unquoted;
}

function validAuditSignalEvidence(value: unknown): LinuxAuditSignalEvidence | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	const syscall =
		record.syscall === "kill" || record.syscall === "tkill" || record.syscall === "tgkill"
			? record.syscall
			: undefined;
	if (!syscall) return undefined;
	const signalNumber = safeInteger(record.signalNumber, 1);
	const targetPid = safeInteger(record.targetPid, 1);
	const targetTid = record.targetTid === undefined ? undefined : safeInteger(record.targetTid, 1);
	const senderPid = safeInteger(record.senderPid, 1);
	const senderUid = safeInteger(record.senderUid);
	const senderPpid = safeInteger(record.senderPpid);
	const senderExecutable = safeExecutable(
		typeof record.senderExecutable === "string" ? record.senderExecutable : undefined,
	);
	if (
		!signalNumber ||
		signalNumber > 64 ||
		!targetPid ||
		!senderPid ||
		senderUid === undefined ||
		senderPpid === undefined ||
		record.targetIdentityBinding !== "run_lifetime_pid_window" ||
		(record.senderExecutableStatus !== "observed" && record.senderExecutableStatus !== "unavailable") ||
		(record.lineageStatus !== "observed" && record.lineageStatus !== "unavailable") ||
		!Array.isArray(record.lineageExecutables)
	)
		return undefined;
	const lineageExecutables = record.lineageExecutables
		.flatMap((item) => {
			const executable = safeExecutable(typeof item === "string" ? item : undefined);
			return executable ? [executable] : [];
		})
		.slice(0, MAX_LINEAGE_DEPTH);
	const senderProcessStartId =
		typeof record.senderProcessStartId === "string" && /^proc:[1-9]\d*$/.test(record.senderProcessStartId)
			? record.senderProcessStartId
			: undefined;
	const signal =
		typeof record.signal === "string" && /^SIG[A-Z0-9]{1,16}$/.test(record.signal) ? record.signal : undefined;
	const wallTime =
		typeof record.wallTime === "string" && /^\d{4}-\d{2}-\d{2}T/.test(record.wallTime)
			? record.wallTime.slice(0, 32)
			: undefined;
	const lineageStatus: LinuxAuditSignalEvidence["lineageStatus"] =
		record.lineageStatus === "observed" ? "observed" : "unavailable";
	return {
		wallTime,
		syscall,
		signalNumber,
		signal,
		targetPid,
		targetTid,
		senderPid,
		senderUid,
		senderPpid,
		senderProcessStartId,
		senderExecutable,
		senderExecutableStatus: senderExecutable ? "observed" : "unavailable",
		lineageExecutables,
		lineageStatus,
		targetIdentityBinding: "run_lifetime_pid_window",
	};
}

function readAuditSummary(runDir: string): LinuxAuditSummary | undefined {
	const value = readJson(auditPath(runDir), MEMORY_FILE_LIMIT);
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	const capability = record.capability;
	const observation = record.lastObservation;
	if (
		record.schemaVersion !== 1 ||
		record.provider !== "linux_audit_journal" ||
		!capability ||
		typeof capability !== "object" ||
		Array.isArray(capability) ||
		!observation ||
		typeof observation !== "object" ||
		Array.isArray(observation) ||
		!Array.isArray(record.records)
	)
		return undefined;
	const capabilityRecord = capability as Record<string, unknown>;
	const observationRecord = observation as Record<string, unknown>;
	const status = capabilityRecord.status === "available" ? "available" : "unavailable";
	const reason =
		typeof capabilityRecord.reason === "string" && /^[A-Za-z0-9_.:+-]{1,80}$/.test(capabilityRecord.reason)
			? capabilityRecord.reason
			: "summary_invalid";
	const outcome: LinuxAuditSummary["lastObservation"]["outcome"] =
		observationRecord.outcome === "observed" ||
		observationRecord.outcome === "not_observed" ||
		observationRecord.outcome === "unavailable"
			? observationRecord.outcome
			: "unavailable";
	const observationReason =
		typeof observationRecord.reason === "string" && /^[A-Za-z0-9_.:+-]{1,80}$/.test(observationRecord.reason)
			? observationRecord.reason
			: "summary_invalid";
	let target: LinuxAuditSummary["target"];
	if (record.target && typeof record.target === "object" && !Array.isArray(record.target)) {
		const candidate = record.target as Record<string, unknown>;
		const pid = safeInteger(candidate.pid, 1);
		if (pid && typeof candidate.processStartId === "string" && /^proc:[1-9]\d*$/.test(candidate.processStartId))
			target = { pid, processStartId: candidate.processStartId };
	}
	return {
		schemaVersion: 1,
		provider: "linux_audit_journal",
		target,
		capability: auditCapability(status, reason),
		lastObservation: {
			wallTime:
				typeof observationRecord.wallTime === "string" && /^\d{4}-\d{2}-\d{2}T/.test(observationRecord.wallTime)
					? observationRecord.wallTime.slice(0, 32)
					: new Date(0).toISOString(),
			outcome,
			reason: observationReason,
			sourceTruncated: observationRecord.sourceTruncated === true,
		},
		records: record.records
			.flatMap((item) => {
				const normalized = validAuditSignalEvidence(item);
				return normalized ? [normalized] : [];
			})
			.slice(-AUDIT_RECORD_LIMIT),
		droppedRecordCount: safeInteger(record.droppedRecordCount) ?? 0,
	};
}

function systemJournalCapability(
	status: "available" | "unavailable",
	reason: string,
): LinuxSystemJournalSummary["capability"] {
	return {
		status,
		reason,
		sourceLayer: "kernel",
		diagnosticOnly: true,
		preexistingRecordsOnly: true,
		crossBootJournalQuery: true,
		automaticJournalConfiguration: false,
		operatorManagedPersistentJournalCompatible: true,
		rawMessagesPersisted: false,
		canonicalRawSourceReferenced: true,
		incidentRawExportPinSupported: true,
		timeoutMs: AUDIT_TIMEOUT_MS,
		queryStdoutByteLimit: AUDIT_STDOUT_LIMIT,
		journalRecordLimit: false,
	};
}

function sanitizeSystemJournalEvidence(value: unknown): LinuxSystemJournalEvidence | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	const cursor = safeJournalCursor(record.cursor);
	const source = [
		"audit",
		"kernel",
		"systemd",
		"systemd_shutdown",
		"systemd_oomd",
		"systemd_coredump",
		"other",
	].includes(String(record.source))
		? (record.source as LinuxSystemJournalSource)
		: undefined;
	const category = [
		"kernel_oom_kill",
		"kernel_memory_pressure",
		"systemd_oom_action",
		"systemd_lifecycle",
		"shutdown",
		"poweroff",
		"reboot",
		"coredump",
		"signal_exit",
		"kernel_signal_fault",
		"unknown",
	].includes(String(record.category))
		? (record.category as LinuxSystemJournalCategory)
		: undefined;
	if (!cursor || !source || !category) return undefined;
	const signalNumber = safeInteger(record.signalNumber, 1);
	const targetPid = safeInteger(record.targetPid, 1);
	return {
		cursor,
		bootId: safeBootId(record.bootId),
		realtimeTimestampUs: safeRealtimeTimestampUs(record.realtimeTimestampUs),
		source,
		sourceLayer: source === "kernel" || source === "audit" ? "kernel" : "service_resource",
		category,
		targetIdentityBinding:
			targetPid && record.targetIdentityBinding === "pid_and_run_journal_window"
				? "pid_and_run_journal_window"
				: "global_timeline",
		targetPid,
		signalNumber: signalNumber !== undefined && signalNumber <= 64 ? signalNumber : undefined,
		signal:
			typeof record.signal === "string" && /^SIG[A-Z0-9]{1,16}$/.test(record.signal) ? record.signal : undefined,
		executable: typeof record.executable === "string" ? record.executable : undefined,
		unit: typeof record.unit === "string" ? record.unit : undefined,
	};
}

function sanitizeJournalSourceReference(value: unknown): LinuxJournalSourceReference | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	if (record.canonicalSource !== "persistent-system-journal") return undefined;
	const providerRecord =
		record.provider && typeof record.provider === "object" && !Array.isArray(record.provider)
			? (record.provider as Record<string, unknown>)
			: {};
	const errors: LinuxJournalQueryError[] = Array.isArray(record.queryErrors)
		? record.queryErrors
				.flatMap((item) => {
					if (!item || typeof item !== "object" || Array.isArray(item)) return [];
					const error = item as Record<string, unknown>;
					const operation = ["cursor", "range", "incident_export", "provider_version"].includes(
						String(error.operation),
					)
						? (error.operation as LinuxJournalQueryError["operation"])
						: undefined;
					return operation && typeof error.wallTime === "string" && typeof error.stderr === "string"
						? [
								{
									wallTime: error.wallTime,
									status: typeof error.status === "number" ? error.status : null,
									errorCode: typeof error.errorCode === "string" ? error.errorCode : undefined,
									stderr: error.stderr,
									operation,
									lossOrRotation: error.lossOrRotation === true,
								},
							]
						: [];
				})
				.slice(-JOURNAL_QUERY_ERROR_LIMIT)
		: [];
	const rawExportSegments = Array.isArray(record.rawExportSegments)
		? record.rawExportSegments.flatMap((item): LinuxJournalSourceReference["rawExportSegments"] => {
				if (!item || typeof item !== "object" || Array.isArray(item)) return [];
				const segment = item as Record<string, unknown>;
				const captured =
					segment.captured && typeof segment.captured === "object" && !Array.isArray(segment.captured)
						? (segment.captured as Record<string, unknown>)
						: {};
				const bounds =
					segment.bounds && typeof segment.bounds === "object" && !Array.isArray(segment.bounds)
						? (segment.bounds as Record<string, unknown>)
						: {};
				const position = (positionValue: unknown): LinuxJournalPosition | undefined => {
					if (!positionValue || typeof positionValue !== "object" || Array.isArray(positionValue))
						return undefined;
					const positionRecord = positionValue as Record<string, unknown>;
					const cursor = safeJournalCursor(positionRecord.cursor);
					return cursor
						? {
								cursor,
								bootId: safeBootId(positionRecord.bootId),
								realtimeTimestampUs: safeRealtimeTimestampUs(positionRecord.realtimeTimestampUs),
							}
						: undefined;
				};
				const bytes = safeInteger(segment.bytes);
				if (
					typeof captured.wallTime !== "string" ||
					typeof captured.monotonicNs !== "string" ||
					bytes === undefined
				)
					return [];
				return [
					{
						captured: { wallTime: captured.wallTime, monotonicNs: captured.monotonicNs },
						bounds: {
							start: position(bounds.start),
							end: position(bounds.end),
							startExclusive: true,
							endInclusive: true,
						},
						payloadReference: segment.payloadReference,
						bytes,
						encoding: "journal-export",
					},
				];
			})
		: [];
	return {
		canonicalSource: "persistent-system-journal",
		retentionMilliseconds: safeInteger(record.retentionMilliseconds) ?? JOURNAL_RETENTION_MS,
		resolvabilityDependency: "journal-provider-retains-range",
		resolvabilityVerified: false,
		contentBinding: "cursor_boot_and_file_identity_best_effort",
		provider: {
			name: "systemd-journald",
			queryTool: "journalctl",
			versionOutput: typeof providerRecord.versionOutput === "string" ? providerRecord.versionOutput : undefined,
		},
		configurationAndStorageIdentities: sanitizeSourceIdentities(record.configurationAndStorageIdentities),
		identityEnumerationTruncated: record.identityEnumerationTruncated === true,
		queryErrors: errors,
		queryErrorDropCount: safeInteger(record.queryErrorDropCount) ?? 0,
		lossIndicators: Array.isArray(record.lossIndicators)
			? record.lossIndicators.filter((item): item is string => typeof item === "string")
			: [],
		rawExportSegments,
	};
}

function readSystemJournalSummary(runDir: string): LinuxSystemJournalSummary | undefined {
	const value = readJson(systemJournalPath(runDir), MEMORY_FILE_LIMIT);
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const record = value as Record<string, unknown>;
	if (record.schemaVersion !== 1 || record.provider !== "linux_system_journal" || !Array.isArray(record.records))
		return undefined;
	const records = record.records
		.flatMap((item) => {
			const normalized = sanitizeSystemJournalEvidence(item);
			return normalized ? [normalized] : [];
		})
		.slice(-AUDIT_RECORD_LIMIT);
	const bounds =
		record.bounds && typeof record.bounds === "object" && !Array.isArray(record.bounds)
			? (record.bounds as Record<string, unknown>)
			: {};
	const position = (value: unknown): LinuxJournalPosition | undefined => {
		if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
		const item = value as Record<string, unknown>;
		const cursor = safeJournalCursor(item.cursor);
		return cursor
			? {
					cursor,
					bootId: safeBootId(item.bootId),
					realtimeTimestampUs: safeRealtimeTimestampUs(item.realtimeTimestampUs),
				}
			: undefined;
	};
	const capability =
		record.capability && typeof record.capability === "object" && !Array.isArray(record.capability)
			? (record.capability as Record<string, unknown>)
			: {};
	const observation =
		record.lastObservation && typeof record.lastObservation === "object" && !Array.isArray(record.lastObservation)
			? (record.lastObservation as Record<string, unknown>)
			: {};
	const status = capability.status === "available" ? "available" : "unavailable";
	const reason =
		typeof capability.reason === "string" && /^[A-Za-z0-9_.:+-]{1,80}$/.test(capability.reason)
			? capability.reason
			: "summary_invalid";
	const outcome: LinuxSystemJournalSummary["lastObservation"]["outcome"] =
		observation.outcome === "observed" ||
		observation.outcome === "not_observed" ||
		observation.outcome === "unavailable"
			? observation.outcome
			: "unavailable";
	const observationReason =
		typeof observation.reason === "string" && /^[A-Za-z0-9_.:+-]{1,80}$/.test(observation.reason)
			? observation.reason
			: "summary_invalid";
	return {
		schemaVersion: 1,
		provider: "linux_system_journal",
		target:
			record.target && typeof record.target === "object" && !Array.isArray(record.target)
				? (() => {
						const target = record.target as Record<string, unknown>;
						const pid = safeInteger(target.pid, 1);
						return pid &&
							typeof target.processStartId === "string" &&
							/^proc:[1-9]\d*$/.test(target.processStartId)
							? { pid, processStartId: target.processStartId }
							: undefined;
					})()
				: undefined,
		capability: systemJournalCapability(status, reason),
		bounds: { start: position(bounds.start), end: position(bounds.end) },
		sourceReference: sanitizeJournalSourceReference(record.sourceReference) ?? {
			canonicalSource: "persistent-system-journal",
			retentionMilliseconds: JOURNAL_RETENTION_MS,
			resolvabilityDependency: "journal-provider-retains-range",
			resolvabilityVerified: false,
			contentBinding: "cursor_boot_and_file_identity_best_effort",
			provider: { name: "systemd-journald", queryTool: "journalctl" },
			configurationAndStorageIdentities: [],
			identityEnumerationTruncated: false,
			queryErrors: [],
			queryErrorDropCount: 0,
			lossIndicators: ["legacy_reference_metadata_unavailable"],
			rawExportSegments: [],
		},
		lastObservation: {
			wallTime:
				typeof observation.wallTime === "string" && /^\d{4}-\d{2}-\d{2}T/.test(observation.wallTime)
					? observation.wallTime.slice(0, 32)
					: new Date(0).toISOString(),
			outcome,
			reason: observationReason,
			sourceTruncated: observation.sourceTruncated === true,
		},
		records,
		droppedRecordCount: safeInteger(record.droppedRecordCount) ?? 0,
	};
}

function monitorJournalStart(monitor: LinuxMonitorState): LinuxJournalPosition | undefined {
	return monitor.journalStartCursor
		? {
				cursor: monitor.journalStartCursor,
				bootId: monitor.journalStartBootId,
				realtimeTimestampUs: monitor.journalStartRealtimeTimestampUs,
			}
		: undefined;
}

function journalSourceReference(
	monitor: LinuxMonitorState,
	previous?: LinuxSystemJournalSummary,
): LinuxJournalSourceReference {
	return (
		previous?.sourceReference ?? {
			canonicalSource: "persistent-system-journal",
			retentionMilliseconds: JOURNAL_RETENTION_MS,
			resolvabilityDependency: "journal-provider-retains-range",
			resolvabilityVerified: false,
			contentBinding: "cursor_boot_and_file_identity_best_effort",
			provider: {
				name: "systemd-journald",
				queryTool: "journalctl",
				versionOutput: monitor.journalProviderVersion,
			},
			configurationAndStorageIdentities: monitor.journalSourceIdentities ?? [],
			identityEnumerationTruncated: monitor.journalSourceIdentityEnumerationTruncated === true,
			queryErrors: monitor.journalQueryErrors ?? [],
			queryErrorDropCount: 0,
			lossIndicators: [
				"journal_3d_resolvability_unverified",
				...(monitor.journalSourceIdentityEnumerationTruncated ? ["journal_identity_enumeration_truncated"] : []),
			],
			rawExportSegments: [],
		}
	);
}

function appendJournalQueryError(reference: LinuxJournalSourceReference, error: LinuxJournalQueryError): void {
	const combined = [...reference.queryErrors, error];
	reference.queryErrors = combined.slice(-JOURNAL_QUERY_ERROR_LIMIT);
	reference.queryErrorDropCount += combined.length - reference.queryErrors.length;
	if (error.lossOrRotation)
		reference.lossIndicators = [...new Set([...reference.lossIndicators, "cursor_or_rotation_loss_possible"])];
}

function writeUnavailableSystemJournal(
	runDir: string,
	monitor: LinuxMonitorState,
	reason: string,
	deps: LinuxIncidentCollectorDependencies,
	queryError?: LinuxJournalQueryError,
): void {
	const previous = readSystemJournalSummary(runDir);
	const reference = journalSourceReference(monitor, previous);
	if (queryError) appendJournalQueryError(reference, queryError);
	const summary: LinuxSystemJournalSummary = {
		schemaVersion: 1,
		provider: "linux_system_journal",
		target: { pid: monitor.targetPid, processStartId: monitor.targetProcessStartId },
		capability: systemJournalCapability("unavailable", reason),
		bounds: { start: previous?.bounds.start ?? monitorJournalStart(monitor), end: previous?.bounds.end },
		sourceReference: reference,
		lastObservation: {
			wallTime: deps.now().toISOString(),
			outcome: "unavailable",
			reason,
			sourceTruncated: false,
		},
		records: previous?.records ?? [],
		droppedRecordCount: previous?.droppedRecordCount ?? 0,
	};
	atomicWriteJson(systemJournalPath(runDir), summary, MEMORY_FILE_LIMIT);
}

export function prepareLinuxIncidentAuditEvidence(options: LinuxIncidentPreparationOptions): void {
	const deps = dependencies(options.dependencies);
	writeUnavailableAudit(options.runDir, "shared_canonical_journal_reader_required", deps);
}
export function baselineLinuxIncidentEvidence(options: LinuxIncidentTargetOptions): LinuxMemorySummary | undefined {
	const deps = dependencies(options.dependencies);
	if (deps.platform !== "linux") {
		const summary = unavailableMemorySummary("platform_unsupported");
		atomicWriteJson(memoryPath(options.runDir), summary, MEMORY_FILE_LIMIT);
		writeUnavailableAudit(options.runDir, "platform_unsupported", deps);
		return summary;
	}
	if (
		!Number.isSafeInteger(options.pid) ||
		options.pid <= 0 ||
		!options.processStartId ||
		!/^proc:[1-9]\d*$/.test(options.processStartId) ||
		deps.getProcessStartId(options.pid) !== options.processStartId
	) {
		const summary = unavailableMemorySummary("target_process_identity_unavailable");
		atomicWriteJson(memoryPath(options.runDir), summary, MEMORY_FILE_LIMIT);
		writeUnavailableAudit(options.runDir, "target_process_identity_unavailable", deps);
		return summary;
	}
	const targetLifetimeStartEpochMs = deps.now().getTime();
	const resolved = resolveCgroupDirectory(options.pid, deps);
	const validatedCgroup =
		resolved && deps.getProcessStartId(options.pid) === options.processStartId ? resolved : undefined;
	const cursor = {
		cursor: undefined,
		bootId: undefined,
		realtimeTimestampUs: undefined,
		reason: "shared_canonical_journal_reader_required",
		providerVersion: undefined,
		sourceIdentities: undefined,
		sourceIdentityEnumerationTruncated: false,
		queryErrors: [] as LinuxJournalQueryError[],
	};
	const monitor: LinuxMonitorState = {
		schemaVersion: 1,
		targetPid: options.pid,
		targetProcessStartId: options.processStartId,
		cgroupDirectory: validatedCgroup?.directory,
		cgroupDev: validatedCgroup?.dev,
		cgroupIno: validatedCgroup?.ino,
		cgroupIdentityHash: validatedCgroup?.identityHash,
		baselineEpochMs: targetLifetimeStartEpochMs,
		systemJournalCursor: cursor.cursor,
		journalStartCursor: cursor.cursor,
		journalStartBootId: cursor.bootId,
		journalStartRealtimeTimestampUs: cursor.realtimeTimestampUs,
		journalProviderVersion: cursor.providerVersion,
		journalSourceIdentities: cursor.sourceIdentities,
		journalSourceIdentityEnumerationTruncated: cursor.sourceIdentityEnumerationTruncated,
		journalQueryErrors: cursor.queryErrors,
	};
	if (!writeMonitor(options.runDir, monitor)) return undefined;
	let summary: LinuxMemorySummary | undefined;
	if (validatedCgroup) summary = appendMemorySample(options.runDir, monitor, "baseline", deps);
	else {
		summary = unavailableMemorySummary("cgroup_v2_target_unavailable");
		summary.target = { pid: monitor.targetPid, processStartId: monitor.targetProcessStartId };
		summary.targetIdentityValidated = true;
		atomicWriteJson(memoryPath(options.runDir), summary, MEMORY_FILE_LIMIT);
	}
	if (cursor.cursor) {
		const audit: LinuxAuditSummary = {
			schemaVersion: 1,
			provider: "linux_audit_journal",
			target: { pid: monitor.targetPid, processStartId: monitor.targetProcessStartId },
			capability: auditCapability("available", cursor.reason),
			lastObservation: {
				wallTime: deps.now().toISOString(),
				outcome: "not_observed",
				reason: cursor.reason,
				sourceTruncated: false,
			},
			records: [],
			droppedRecordCount: 0,
		};
		atomicWriteJson(auditPath(options.runDir), audit, MEMORY_FILE_LIMIT);
		const start = monitorJournalStart(monitor);
		const system: LinuxSystemJournalSummary = {
			schemaVersion: 1,
			provider: "linux_system_journal",
			target: { pid: monitor.targetPid, processStartId: monitor.targetProcessStartId },
			capability: systemJournalCapability("available", cursor.reason),
			bounds: { start, end: start },
			sourceReference: journalSourceReference(monitor),
			lastObservation: {
				wallTime: deps.now().toISOString(),
				outcome: "not_observed",
				reason: cursor.reason,
				sourceTruncated: false,
			},
			records: [],
			droppedRecordCount: 0,
		};
		atomicWriteJson(systemJournalPath(options.runDir), system, MEMORY_FILE_LIMIT);
	} else {
		writeUnavailableAudit(options.runDir, cursor.reason, deps);
		writeUnavailableSystemJournal(options.runDir, monitor, cursor.reason, deps);
	}
	return summary;
}

export function sampleLinuxIncidentEvidence(options: LinuxIncidentSampleOptions): LinuxMemorySummary | undefined {
	const deps = dependencies(options.dependencies);
	const monitor = readMonitor(options.runDir);
	if (deps.platform !== "linux" || !monitor) return undefined;
	const summary = options.skipMemorySample
		? readMemorySummary(options.runDir, monitor.cgroupIdentityHash)
		: appendMemorySample(options.runDir, monitor, options.phase, deps, options.captureBroadRaw === true);
	return summary;
}

function persistRawOccurrence(deps: LinuxIncidentCollectorDependencies, occurrence: LinuxRawSourceOccurrence): unknown {
	try {
		return deps.recordRawSource?.(occurrence);
	} catch {
		return undefined;
	}
}

function cropJournalExportAtCursor(
	bytes: Buffer,
	requiredEndCursor: string,
): { bytes?: Buffer; end?: LinuxJournalPosition; lastCursor?: string; parseLoss: boolean } {
	let offset = 0;
	let cursor: string | undefined;
	let bootId: string | undefined;
	let realtimeTimestampUs: string | undefined;
	let lastCursor: string | undefined;
	while (offset < bytes.length) {
		const lineEnd = bytes.indexOf(0x0a, offset);
		if (lineEnd === -1) return { lastCursor, parseLoss: true };
		if (lineEnd === offset) {
			offset += 1;
			if (cursor) lastCursor = cursor;
			if (cursor === requiredEndCursor) {
				return {
					bytes: bytes.subarray(0, offset),
					end: { cursor, bootId, realtimeTimestampUs },
					lastCursor,
					parseLoss: false,
				};
			}
			cursor = undefined;
			bootId = undefined;
			realtimeTimestampUs = undefined;
			continue;
		}
		const line = bytes.subarray(offset, lineEnd);
		const equals = line.indexOf(0x3d);
		if (equals !== -1) {
			const name = line.subarray(0, equals).toString("ascii");
			const value = line.subarray(equals + 1).toString("utf8");
			if (name === "__CURSOR") cursor = safeJournalCursor(value);
			else if (name === "_BOOT_ID") bootId = safeBootId(value);
			else if (name === "__REALTIME_TIMESTAMP") realtimeTimestampUs = safeRealtimeTimestampUs(value);
			offset = lineEnd + 1;
			continue;
		}
		const name = line.toString("ascii");
		const lengthOffset = lineEnd + 1;
		if (!/^[A-Z_][A-Z0-9_]*$/.test(name) || lengthOffset + 8 > bytes.length) return { lastCursor, parseLoss: true };
		const length = bytes.readBigUInt64LE(lengthOffset);
		if (length > BigInt(Number.MAX_SAFE_INTEGER)) return { lastCursor, parseLoss: true };
		const next = lengthOffset + 8 + Number(length);
		if (next >= bytes.length || bytes[next] !== 0x0a) return { lastCursor, parseLoss: true };
		offset = next + 1;
	}
	return { lastCursor, parseLoss: false };
}

export function pinLinuxIncidentJournalEvidence(options: LinuxIncidentJournalPinOptions): void {
	const deps = dependencies({ ...options.dependencies, recordRawSource: options.recordRawSource });
	const monitor = readMonitor(options.runDir);
	if (deps.platform !== "linux" || !monitor) return;
	const summary = readSystemJournalSummary(options.runDir);
	const start = summary?.bounds.start ?? monitorJournalStart(monitor);
	const frozenEnd = acquireAuditCursor(deps);
	const requiredEnd = frozenEnd.cursor
		? { cursor: frozenEnd.cursor, bootId: frozenEnd.bootId, realtimeTimestampUs: frozenEnd.realtimeTimestampUs }
		: undefined;
	if (summary) {
		if (requiredEnd) summary.bounds.end = requiredEnd;
		if (frozenEnd.queryError) appendJournalQueryError(summary.sourceReference, frozenEnd.queryError);
		atomicWriteJson(systemJournalPath(options.runDir), summary, MEMORY_FILE_LIMIT);
	}
	if (!start?.cursor || !requiredEnd?.cursor || !requiredEnd.realtimeTimestampUs) {
		writeUnavailableSystemJournal(options.runDir, monitor, "incident_export_exact_bounds_unavailable", deps);
		return;
	}
	if (start.cursor === requiredEnd.cursor) {
		if (summary) {
			summary.lastObservation = {
				wallTime: deps.now().toISOString(),
				outcome: "not_observed",
				reason: "incident_journal_range_empty",
				sourceTruncated: false,
			};
			atomicWriteJson(systemJournalPath(options.runDir), summary, MEMORY_FILE_LIMIT);
		}
		return;
	}
	const untilSeconds = Number(requiredEnd.realtimeTimestampUs) / 1_000_000;
	if (!Number.isFinite(untilSeconds)) {
		writeUnavailableSystemJournal(options.runDir, monitor, "incident_export_end_time_unavailable", deps);
		return;
	}
	const result = deps.runJournalctl(
		[
			"--no-pager",
			"--quiet",
			"--output=export",
			"--all",
			`--after-cursor=${start.cursor}`,
			`--until=@${untilSeconds.toFixed(6)}`,
		],
		JOURNAL_EXPORT_TIMEOUT_MS,
		JOURNAL_EXPORT_LIMIT,
	);
	const failure = journalFailure(result, JOURNAL_EXPORT_LIMIT);
	if (failure) {
		const queryError = journalQueryError(result, "incident_export", deps);
		persistRawOccurrence(deps, {
			source: "journal-query-error",
			sourcePath: "journalctl:stdout",
			bytes: journalBytes(result.stdout),
			encoding: "journalctl-error-stdout",
			phase: "incident-pin",
			wallTime: queryError.wallTime,
			monotonicNs: deps.monotonicNs(),
			identity: {
				status: result.status,
				errorCode: result.errorCode,
				operation: "incident_export",
				stream: "stdout",
			},
		});
		persistRawOccurrence(deps, {
			source: "journal-query-error",
			sourcePath: "journalctl:stderr",
			bytes: journalBytes(result.stderr),
			encoding: "journalctl-stderr",
			phase: "incident-pin",
			wallTime: queryError.wallTime,
			monotonicNs: deps.monotonicNs(),
			identity: { status: result.status, errorCode: result.errorCode, operation: "incident_export" },
		});
		clearJournalResult(result);
		writeUnavailableSystemJournal(options.runDir, monitor, failure, deps, queryError);
		return;
	}
	const parsed = cropJournalExportAtCursor(journalBytes(result.stdout), requiredEnd.cursor);
	clearJournalResult(result);
	if (!parsed.bytes || !parsed.end) {
		const current = readSystemJournalSummary(options.runDir);
		if (!current) return;
		current.sourceReference.lossIndicators = [
			...new Set([
				...current.sourceReference.lossIndicators,
				parsed.parseLoss
					? "incident_export_format_parse_loss"
					: "incident_export_end_cursor_missing_rotation_or_loss",
			]),
		];
		current.lastObservation = {
			wallTime: deps.now().toISOString(),
			outcome: "unavailable",
			reason: parsed.parseLoss ? "incident_export_format_parse_loss" : "incident_export_end_cursor_missing",
			sourceTruncated: true,
		};
		atomicWriteJson(systemJournalPath(options.runDir), current, MEMORY_FILE_LIMIT);
		return;
	}
	const captured = { wallTime: deps.now().toISOString(), monotonicNs: deps.monotonicNs() };
	const payloadReference = persistRawOccurrence(deps, {
		source: "system-journal-export",
		sourcePath: "persistent-system-journal",
		bytes: parsed.bytes,
		encoding: "journal-export",
		phase: "incident-pin",
		wallTime: captured.wallTime,
		monotonicNs: captured.monotonicNs,
		identity: {
			provider: "systemd-journald",
			queryTool: "journalctl",
			providerVersion: monitor.journalProviderVersion,
			configurationAndStorageIdentities: monitor.journalSourceIdentities,
		},
		bounds: { start, end: parsed.end, startExclusive: true, endInclusive: true },
	});
	const current = readSystemJournalSummary(options.runDir);
	if (!current) return;
	if (payloadReference === undefined) {
		current.sourceReference.lossIndicators = [
			...new Set([...current.sourceReference.lossIndicators, "incident_export_cas_unavailable"]),
		];
		current.lastObservation = {
			wallTime: captured.wallTime,
			outcome: "unavailable",
			reason: "incident_export_cas_unavailable",
			sourceTruncated: false,
		};
		atomicWriteJson(systemJournalPath(options.runDir), current, MEMORY_FILE_LIMIT);
		return;
	}
	current.sourceReference.rawExportSegments.push({
		captured,
		bounds: { start, end: parsed.end, startExclusive: true, endInclusive: true },
		payloadReference,
		bytes: parsed.bytes.length,
		encoding: "journal-export",
	});
	current.bounds.end = parsed.end;
	current.lastObservation = {
		wallTime: captured.wallTime,
		outcome: "observed",
		reason: "incident_raw_export_pinned",
		sourceTruncated: false,
	};
	atomicWriteJson(systemJournalPath(options.runDir), current, MEMORY_FILE_LIMIT);
}

export function hasPositiveLinuxCgroupOomKillDelta(
	runDir: string,
	signal: NodeJS.Signals | null,
): { matched: boolean; attribution?: "dedicated" | "shared" | "unknown"; delta?: number } {
	if (signal !== "SIGKILL") return { matched: false };
	const summary = readMemorySummary(runDir);
	const audit = readAuditSummary(runDir);
	if (
		summary?.target &&
		audit?.target?.pid === summary.target.pid &&
		audit.target.processStartId === summary.target.processStartId &&
		audit.records.some((record) => record.targetPid === summary.target?.pid && record.signalNumber === 9)
	)
		return { matched: false };
	const baseline = summary?.baseline?.eventsLocal?.oom_kill;
	const latest = summary?.latest?.eventsLocal?.oom_kill;
	if (
		!summary?.targetIdentityValidated ||
		summary.capability.status !== "available" ||
		!summary.cgroup ||
		summary.latest?.phase !== "final" ||
		summary.baseline?.targetMember !== true ||
		(summary.latest?.targetIdentity !== "matched" && summary.latest?.targetIdentity !== "saved_after_exit") ||
		typeof baseline !== "number" ||
		typeof latest !== "number" ||
		!Number.isSafeInteger(baseline) ||
		!Number.isSafeInteger(latest) ||
		latest <= baseline
	)
		return { matched: false };
	return { matched: true, attribution: summary.cgroup.attribution, delta: latest - baseline };
}

export interface LinuxIncidentEvidenceCorrelation {
	target?: { pid: number; processStartId: string };
	providers: Array<{
		provider: "incident_recorder" | "linux_cgroup_v2" | "linux_audit_journal" | "linux_system_journal";
		sourceLayer: "application" | "service_resource" | "kernel";
		status: "available" | "unavailable";
		reason: string;
		attribution?: "dedicated" | "shared" | "unknown";
	}>;
	supportingEvidence: string[];
	missingEvidence: string[];
	applicationEvidence: boolean;
	environmentEvidence: boolean;
	environmentClassification?:
		| "kernel_oom_correlated_exit"
		| "systemd_oom_correlated_exit"
		| "host_shutdown_correlated_exit"
		| "external_signal_correlated_exit";
}

export function readLinuxIncidentEvidenceCorrelation(runDir: string): LinuxIncidentEvidenceCorrelation {
	const memory = readMemorySummary(runDir);
	const audit = readAuditSummary(runDir);
	const system = readSystemJournalSummary(runDir);
	const target = memory?.target ?? audit?.target ?? system?.target;
	const systemSourceLayer: "service_resource" | "kernel" = system?.records.some(
		(record) => record.sourceLayer === "kernel",
	)
		? "kernel"
		: "service_resource";
	const providers: LinuxIncidentEvidenceCorrelation["providers"] = [];
	for (const provider of [
		{
			provider: "incident_recorder" as const,
			sourceLayer: "application" as const,
			status: "available" as const,
			reason: "run_timeline_available",
		},
		memory
			? {
					provider: "linux_cgroup_v2" as const,
					sourceLayer: "service_resource" as const,
					status: memory.capability.status,
					reason: memory.capability.reason,
					attribution: memory.cgroup?.attribution,
				}
			: undefined,
		audit
			? {
					provider: "linux_audit_journal" as const,
					sourceLayer: "kernel" as const,
					status: audit.capability.status,
					reason: audit.capability.reason,
				}
			: undefined,
		system
			? {
					provider: "linux_system_journal" as const,
					sourceLayer: systemSourceLayer,
					status: system.capability.status,
					reason: system.capability.reason,
				}
			: undefined,
	]) {
		if (provider) providers.push(provider);
	}
	const supportingEvidence: string[] = [];
	const missingEvidence = providers
		.filter((provider) => provider.status === "unavailable")
		.map((provider) => `${provider.provider}:${provider.reason}`);
	if (memory?.latest?.eventsLocal || memory?.latest?.pressure || memory?.latest?.hostPressure)
		supportingEvidence.push("cgroup_memory_evidence");
	if ((audit?.records.length ?? 0) > 0) supportingEvidence.push("audit_signal_sender");
	const systemCategories = new Set(
		(system?.records ?? []).filter((record) => record.category !== "unknown").map((record) => record.category),
	);
	for (const category of systemCategories) supportingEvidence.push(`system_journal:${category}`);
	const targetPid = target?.pid;
	const targetBootId = system?.bounds.start?.bootId;
	const targetSystemEvidence = (system?.records ?? []).some(
		(record) =>
			(targetBootId !== undefined &&
				record.bootId === targetBootId &&
				record.source === "systemd_shutdown" &&
				["shutdown", "poweroff", "reboot"].includes(record.category)) ||
			(targetPid !== undefined &&
				record.targetPid === targetPid &&
				record.targetIdentityBinding === "pid_and_run_journal_window" &&
				targetBootId !== undefined &&
				record.bootId === targetBootId &&
				(record.category === "kernel_oom_kill" || record.category === "systemd_oom_action")),
	);
	const selfAuditEvidence =
		targetPid !== undefined &&
		(audit?.records ?? []).some(
			(record) => record.senderPid === targetPid && [1, 2, 3, 6, 9, 11, 15].includes(record.signalNumber),
		);
	const externalAuditEvidence =
		targetPid !== undefined &&
		(audit?.records ?? []).some(
			(record) => record.senderPid !== targetPid && [1, 2, 3, 6, 9, 11, 15].includes(record.signalNumber),
		);
	const externalKillEvidence =
		targetPid !== undefined &&
		(audit?.records ?? []).some((record) => record.senderPid !== targetPid && record.signalNumber === 9);
	const targetApplicationEvidence =
		selfAuditEvidence ||
		(system?.records ?? []).some(
			(record) =>
				targetPid !== undefined &&
				record.targetPid === targetPid &&
				record.targetIdentityBinding === "pid_and_run_journal_window" &&
				targetBootId !== undefined &&
				record.bootId === targetBootId &&
				record.category === "kernel_signal_fault",
		);
	const targetSystemCategories = new Set(
		(system?.records ?? [])
			.filter(
				(record) =>
					targetPid !== undefined &&
					record.targetPid === targetPid &&
					record.targetIdentityBinding === "pid_and_run_journal_window" &&
					targetBootId !== undefined &&
					record.bootId === targetBootId,
			)
			.map((record) => record.category),
	);
	const hostShutdownEvidence = (system?.records ?? []).some(
		(record) =>
			targetBootId !== undefined &&
			record.bootId === targetBootId &&
			record.source === "systemd_shutdown" &&
			["shutdown", "poweroff", "reboot"].includes(record.category),
	);
	const environmentClassification: LinuxIncidentEvidenceCorrelation["environmentClassification"] =
		targetSystemCategories.has("kernel_oom_kill")
			? "kernel_oom_correlated_exit"
			: targetSystemCategories.has("systemd_oom_action")
				? "systemd_oom_correlated_exit"
				: hostShutdownEvidence
					? "host_shutdown_correlated_exit"
					: externalKillEvidence
						? "external_signal_correlated_exit"
						: undefined;
	return {
		target,
		providers,
		supportingEvidence: supportingEvidence.slice(0, 32),
		missingEvidence: missingEvidence.slice(0, 16),
		applicationEvidence: targetApplicationEvidence,
		environmentEvidence: externalAuditEvidence || targetSystemEvidence,
		environmentClassification,
	};
}
