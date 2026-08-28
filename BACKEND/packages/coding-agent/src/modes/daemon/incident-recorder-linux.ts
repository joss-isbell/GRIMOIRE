import { randomUUID } from "node:crypto";
import {
	closeSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	lstatSync,
	mkdirSync,
	opendirSync,
	openSync,
	readSync,
	realpathSync,
	renameSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { getProcessStartId } from "../../core/session-lease.js";

const SUMMARY_FILE = "linux-causal-resource.json";
const MONITOR_FILE = "linux-causal-monitor.json";
const MAX_FILE_BYTES = 256 * 1024;
const MAX_SAMPLES = 32;

export interface LinuxPressureValues {
	some?: { avg10: number; avg60: number; avg300: number; total: number };
	full?: { avg10: number; avg60: number; avg300: number; total: number };
}

export interface LinuxMemorySample {
	phase: "baseline" | "periodic" | "anomaly" | "final";
	wallTime: string;
	monotonicNs: string;
	current?: number;
	peak?: number;
	swapCurrent?: number;
	events: Record<string, number>;
	eventsLocal: Record<string, number>;
	memoryStat: Record<string, number>;
	cpuStat: Record<string, number>;
	pidsCurrent?: number;
	memoryPressure?: LinuxPressureValues;
	ioPressure?: LinuxPressureValues;
}

export interface LinuxMemorySummary {
	schemaVersion: 2;
	provider: "linux_cgroup_v2";
	target: { pid: number; processStartId: string };
	targetIdentityValidated: boolean;
	cgroup?: { path: string; dev: string; ino: string };
	capability: { status: "available" | "unavailable"; reason?: string };
	baseline?: LinuxMemorySample;
	latest?: LinuxMemorySample;
	recent: LinuxMemorySample[];
}

interface Monitor {
	schemaVersion: 2;
	pid: number;
	processStartId: string;
	cgroupPath: string;
	cgroupDev: string;
	cgroupIno: string;
}

export interface LinuxIncidentCollectorDependencies {
	platform?: NodeJS.Platform;
	now?: () => Date;
	getProcessStartId?: (pid: number) => string | undefined;
}

export interface LinuxIncidentTargetOptions {
	runDir: string;
	pid: number;
	processStartId: string;
	dependencies?: LinuxIncidentCollectorDependencies;
}

export type LinuxMemorySamplePhase = "baseline" | "periodic" | "anomaly" | "final";
export interface LinuxIncidentSampleOptions {
	runDir: string;
	phase: LinuxMemorySamplePhase;
	dependencies?: LinuxIncidentCollectorDependencies;
}

function nowFields(now = new Date()): { wallTime: string; monotonicNs: string } {
	return { wallTime: now.toISOString(), monotonicNs: process.hrtime.bigint().toString() };
}

function boundedRead(path: string, maximum = MAX_FILE_BYTES): Buffer | undefined {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const before = fstatSync(descriptor, { bigint: true });
		if (!before.isFile() || before.size < 0n || before.size > BigInt(maximum)) return undefined;
		const chunks: Buffer[] = [];
		let total = 0;
		while (total <= maximum) {
			const chunk = Buffer.alloc(Math.min(4096, maximum + 1 - total));
			const count = readSync(descriptor, chunk, 0, chunk.length, null);
			if (count === 0) break;
			chunks.push(chunk.subarray(0, count));
			total += count;
		}
		if (total > maximum) return undefined;
		const after = fstatSync(descriptor, { bigint: true });
		if (after.dev !== before.dev || after.ino !== before.ino) return undefined;
		return Buffer.concat(chunks, total);
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

function readJson<T>(path: string): T | undefined {
	const bytes = boundedRead(path);
	if (!bytes) return undefined;
	try {
		return JSON.parse(bytes.toString("utf8")) as T;
	} catch {
		return undefined;
	}
}

function writeJson(path: string, value: unknown): void {
	const bytes = Buffer.from(JSON.stringify(value), "utf8");
	if (bytes.length > MAX_FILE_BYTES) throw new Error("causal Linux evidence exceeds bounded file size");
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
	writeFileSync(temporary, bytes, { mode: 0o600 });
	const descriptor = openSync(temporary, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
	try {
		fsyncSync(descriptor);
	} finally {
		closeSync(descriptor);
	}
	renameSync(temporary, path);
}

function numberMap(path: string): Record<string, number> {
	const bytes = boundedRead(path, 64 * 1024);
	if (!bytes) return {};
	const result: Record<string, number> = {};
	for (const line of bytes.toString("utf8").split("\n")) {
		const [key, raw] = line.trim().split(/\s+/, 2);
		if (!key || !/^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$/.test(key)) continue;
		const value = Number(raw);
		if (Number.isSafeInteger(value) && value >= 0) result[key] = value;
	}
	return result;
}

function scalar(path: string): number | undefined {
	const bytes = boundedRead(path, 128);
	if (!bytes) return undefined;
	const value = Number(bytes.toString("utf8").trim());
	return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function pressure(path: string): LinuxPressureValues | undefined {
	const bytes = boundedRead(path, 4096);
	if (!bytes) return undefined;
	const result: LinuxPressureValues = {};
	for (const line of bytes.toString("utf8").split("\n")) {
		const [kind, ...fields] = line.trim().split(/\s+/);
		if (kind !== "some" && kind !== "full") continue;
		const values = Object.fromEntries(fields.map((field) => field.split("=", 2)));
		const parsed = {
			avg10: Number(values.avg10),
			avg60: Number(values.avg60),
			avg300: Number(values.avg300),
			total: Number(values.total),
		};
		if (Object.values(parsed).every((value) => Number.isFinite(value) && value >= 0)) result[kind] = parsed;
	}
	return result.some || result.full ? result : undefined;
}

function resolveCgroup(pid: number): { path: string; dev: string; ino: string } | undefined {
	const membership = boundedRead(`/proc/${pid}/cgroup`, 64 * 1024)?.toString("utf8");
	const relative = membership
		?.split("\n")
		.find((line) => line.startsWith("0::"))
		?.slice(3);
	if (relative === undefined || !relative.startsWith("/")) return undefined;
	try {
		const root = realpathSync("/sys/fs/cgroup");
		const path = realpathSync(resolve(root, `.${relative}`));
		if (path !== root && !path.startsWith(`${root}/`)) return undefined;
		const stat = lstatSync(path, { bigint: true });
		if (!stat.isDirectory() || stat.isSymbolicLink()) return undefined;
		return { path, dev: String(stat.dev), ino: String(stat.ino) };
	} catch {
		return undefined;
	}
}

function sample(monitor: Monitor, phase: LinuxMemorySamplePhase, now: Date): LinuxMemorySample | undefined {
	if (getProcessStartId(monitor.pid) !== monitor.processStartId) return undefined;
	try {
		const stat = lstatSync(monitor.cgroupPath, { bigint: true });
		if (!stat.isDirectory() || String(stat.dev) !== monitor.cgroupDev || String(stat.ino) !== monitor.cgroupIno)
			return undefined;
	} catch {
		return undefined;
	}
	return {
		phase,
		...nowFields(now),
		current: scalar(join(monitor.cgroupPath, "memory.current")),
		peak: scalar(join(monitor.cgroupPath, "memory.peak")),
		swapCurrent: scalar(join(monitor.cgroupPath, "memory.swap.current")),
		events: numberMap(join(monitor.cgroupPath, "memory.events")),
		eventsLocal: numberMap(join(monitor.cgroupPath, "memory.events.local")),
		memoryStat: numberMap(join(monitor.cgroupPath, "memory.stat")),
		cpuStat: numberMap(join(monitor.cgroupPath, "cpu.stat")),
		pidsCurrent: scalar(join(monitor.cgroupPath, "pids.current")),
		memoryPressure: pressure(join(monitor.cgroupPath, "memory.pressure")),
		ioPressure: pressure(join(monitor.cgroupPath, "io.pressure")),
	};
}

function unavailable(target: LinuxIncidentTargetOptions, reason: string): LinuxMemorySummary {
	return {
		schemaVersion: 2,
		provider: "linux_cgroup_v2",
		target: { pid: target.pid, processStartId: target.processStartId },
		targetIdentityValidated: false,
		capability: { status: "unavailable", reason },
		recent: [],
	};
}

export function baselineLinuxIncidentEvidence(options: LinuxIncidentTargetOptions): LinuxMemorySummary | undefined {
	const platform = options.dependencies?.platform ?? process.platform;
	const identity = options.dependencies?.getProcessStartId ?? getProcessStartId;
	const now = options.dependencies?.now?.() ?? new Date();
	if (platform !== "linux" || identity(options.pid) !== options.processStartId) {
		const summary = unavailable(
			options,
			platform !== "linux" ? "platform_unsupported" : "target_identity_unavailable",
		);
		writeJson(join(options.runDir, SUMMARY_FILE), summary);
		return summary;
	}
	const cgroup = resolveCgroup(options.pid);
	if (!cgroup) {
		const summary = unavailable(options, "cgroup_v2_target_unavailable");
		summary.targetIdentityValidated = true;
		writeJson(join(options.runDir, SUMMARY_FILE), summary);
		return summary;
	}
	const monitor: Monitor = {
		schemaVersion: 2,
		pid: options.pid,
		processStartId: options.processStartId,
		cgroupPath: cgroup.path,
		cgroupDev: cgroup.dev,
		cgroupIno: cgroup.ino,
	};
	writeJson(join(options.runDir, MONITOR_FILE), monitor);
	const baseline = sample(monitor, "baseline", now);
	const summary: LinuxMemorySummary = {
		schemaVersion: 2,
		provider: "linux_cgroup_v2",
		target: { pid: options.pid, processStartId: options.processStartId },
		targetIdentityValidated: true,
		cgroup,
		capability: {
			status: baseline ? "available" : "unavailable",
			reason: baseline ? undefined : "sample_unavailable",
		},
		baseline,
		latest: baseline,
		recent: baseline ? [baseline] : [],
	};
	writeJson(join(options.runDir, SUMMARY_FILE), summary);
	return summary;
}

export function sampleLinuxIncidentEvidence(options: LinuxIncidentSampleOptions): LinuxMemorySummary | undefined {
	const summaryPath = join(options.runDir, SUMMARY_FILE);
	const summary = readJson<LinuxMemorySummary>(summaryPath);
	const monitor = readJson<Monitor>(join(options.runDir, MONITOR_FILE));
	if (!summary || !monitor) return summary;
	const next = sample(monitor, options.phase, options.dependencies?.now?.() ?? new Date());
	if (!next) return summary;
	summary.latest = next;
	summary.recent = [...summary.recent, next].slice(-MAX_SAMPLES);
	writeJson(summaryPath, summary);
	return summary;
}

export type LinuxRelevantProcessRole = "supervisor" | "worker" | "forkserver" | "kernel" | "relevant_descendant";
export type LinuxKnownProcessRole = Exclude<LinuxRelevantProcessRole, "supervisor" | "relevant_descendant">;

export interface LinuxKnownRoleIdentity {
	pid: number;
	processStartId: string;
	role: LinuxKnownProcessRole;
}

export interface LinuxProcessTreeBounds {
	maxProcEntriesVisited: number;
	maxProcessesRetained: number;
	maxBytesPerProc: number;
	maxTotalSampleBytes: number;
}

export const DEFAULT_LINUX_PROCESS_TREE_BOUNDS: Readonly<LinuxProcessTreeBounds> = {
	maxProcEntriesVisited: 4096,
	maxProcessesRetained: 64,
	maxBytesPerProc: 8192,
	maxTotalSampleBytes: 256 * 1024,
};

export interface LinuxProcReadResult {
	value?: string;
	bytesRead: number;
	truncated?: boolean;
	error?: "missing" | "not_file" | "changed" | "read_failed";
}

export interface LinuxProcEntriesResult {
	pids: number[];
	entriesVisited: number;
	truncated: boolean;
	error?: "read_failed";
}

export interface LinuxProcessTreeProcReader {
	listPids(maxEntriesVisited: number): LinuxProcEntriesResult;
	readStat(pid: number, maxBytes: number): LinuxProcReadResult;
	readExecutable(pid: number, maxBytes: number): LinuxProcReadResult;
}

export interface LinuxRelevantProcess {
	pid: number;
	ppid: number;
	processStartId: string;
	role: LinuxRelevantProcessRole;
	state: string;
	executableIdentity?: string;
	cpuTicks: { user: string; system: string; total: string };
	rssPages: string;
}

export interface LinuxProcessTreeGap {
	kind:
		| "proc_directory_read_failed"
		| "stat_read_failed"
		| "stat_truncated"
		| "stat_invalid"
		| "executable_read_failed"
		| "executable_truncated"
		| "root_identity_mismatch"
		| "known_role_identity_mismatch"
		| "known_role_identity_not_observed"
		| "identity_revalidation_failed"
		| "executable_invalid"
		| "total_sample_bytes_exhausted";
	pid?: number;
	role?: LinuxKnownProcessRole;
}

export interface LinuxProcessTreeTruncation {
	kind:
		| "proc_entries_visited"
		| "processes_retained"
		| "known_role_identities"
		| "bytes_per_proc"
		| "total_sample_bytes"
		| "sample_bytes";
	limit: number;
	pid?: number;
}

export interface LinuxRelevantProcessTreeSample {
	schemaVersion: 1;
	provider: "linux_proc_relevant_process_tree";
	target: { pid: number; processStartId: string };
	targetIdentityValidated: boolean;
	bounds: LinuxProcessTreeBounds;
	usage: { procEntriesVisited: number; processesRetained: number; totalSampleBytes: number };
	processes: LinuxRelevantProcess[];
	gaps: LinuxProcessTreeGap[];
	truncations: LinuxProcessTreeTruncation[];
}

export interface LinuxRelevantProcessTreeOptions {
	supervisor: { pid: number; processStartId: string };
	knownRoles?: readonly LinuxKnownRoleIdentity[];
	bounds?: Partial<LinuxProcessTreeBounds>;
	reader?: LinuxProcessTreeProcReader;
}

interface ParsedProcStat {
	pid: number;
	ppid: number;
	processStartId: string;
	state: string;
	userTicks: string;
	systemTicks: string;
	rssPages: string;
}

function boundedProcRead(path: string, maximum: number): LinuxProcReadResult {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const before = fstatSync(descriptor, { bigint: true });
		if (!before.isFile()) return { bytesRead: 0, error: "not_file" };
		if (before.size < 0n || before.size > BigInt(maximum)) return { bytesRead: 0, truncated: true };
		const buffer = Buffer.alloc(maximum);
		const count = readSync(descriptor, buffer, 0, buffer.length, 0);
		const after = fstatSync(descriptor, { bigint: true });
		if (after.dev !== before.dev || after.ino !== before.ino) return { bytesRead: count, error: "changed" };
		if (count === maximum) return { bytesRead: count, truncated: true };
		return { value: buffer.subarray(0, count).toString("utf8"), bytesRead: count };
	} catch {
		return { bytesRead: 0, error: "read_failed" };
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

const defaultLinuxProcReader: LinuxProcessTreeProcReader = {
	listPids(maxEntriesVisited) {
		let directory: ReturnType<typeof opendirSync> | undefined;
		const pids: number[] = [];
		let entriesVisited = 0;
		try {
			directory = opendirSync("/proc");
			while (entriesVisited < maxEntriesVisited) {
				const entry = directory.readSync();
				if (!entry) return { pids, entriesVisited, truncated: false };
				entriesVisited += 1;
				if (/^[1-9][0-9]*$/.test(entry.name)) pids.push(Number(entry.name));
			}
			return { pids, entriesVisited, truncated: true };
		} catch {
			return { pids, entriesVisited, truncated: false, error: "read_failed" };
		} finally {
			directory?.closeSync();
		}
	},
	readStat(pid, maxBytes) {
		return boundedProcRead(`/proc/${pid}/stat`, maxBytes);
	},
	readExecutable(pid, maxBytes) {
		try {
			const executable = statSync(`/proc/${pid}/exe`, { bigint: true });
			const dev = executable.dev.toString(16);
			const ino = executable.ino.toString(16);
			if (!/^[0-9a-f]{1,16}$/.test(dev) || !/^[0-9a-f]{1,16}$/.test(ino))
				return { bytesRead: 0, error: "read_failed" };
			const value = `dev:${dev.padStart(16, "0")}:ino:${ino.padStart(16, "0")}`;
			const bytes = Buffer.byteLength(value);
			return bytes >= maxBytes ? { bytesRead: maxBytes, truncated: true } : { value, bytesRead: bytes };
		} catch {
			return { bytesRead: 0, error: "read_failed" };
		}
	},
};

function effectiveBound(name: keyof LinuxProcessTreeBounds, value: number | undefined): number {
	const hardMaximum = DEFAULT_LINUX_PROCESS_TREE_BOUNDS[name];
	if (value === undefined) return hardMaximum;
	if (!Number.isSafeInteger(value) || value <= 0) throw new RangeError(`${name} must be a positive safe integer`);
	return Math.min(value, hardMaximum);
}

const PROCESS_START_ID = /^proc:\d{1,32}$/;
const EXECUTABLE_IDENTITY = /^dev:[0-9a-f]{16}:ino:[0-9a-f]{16}$/;
const DECIMAL_FIELD = /^\d{1,32}$/;

function parseProcStat(value: string, expectedPid: number): ParsedProcStat | undefined {
	const commandStart = value.indexOf("(");
	const commandEnd = value.lastIndexOf(")");
	if (commandStart < 1 || commandEnd <= commandStart) return undefined;
	if (Number(value.slice(0, commandStart).trim()) !== expectedPid) return undefined;
	const fields = value
		.slice(commandEnd + 1)
		.trim()
		.split(/\s+/);
	const [state, rawPpid] = fields;
	const ppid = Number(rawPpid);
	const userTicks = fields[11];
	const systemTicks = fields[12];
	const startTicks = fields[19];
	const rssPages = fields[21];
	if (
		!state ||
		!/^[A-Z]$/.test(state) ||
		!Number.isSafeInteger(ppid) ||
		ppid < 0 ||
		![userTicks, systemTicks, startTicks, rssPages].every((field) => field !== undefined && DECIMAL_FIELD.test(field))
	)
		return undefined;
	return { pid: expectedPid, ppid, processStartId: `proc:${startTicks}`, state, userTicks, systemTicks, rssPages };
}

function serializedBytes(value: unknown): number {
	return Buffer.byteLength(JSON.stringify(value));
}

export function sampleRelevantLinuxProcessTree(
	options: LinuxRelevantProcessTreeOptions,
): LinuxRelevantProcessTreeSample {
	const bounds: LinuxProcessTreeBounds = {
		maxProcEntriesVisited: effectiveBound("maxProcEntriesVisited", options.bounds?.maxProcEntriesVisited),
		maxProcessesRetained: effectiveBound("maxProcessesRetained", options.bounds?.maxProcessesRetained),
		maxBytesPerProc: effectiveBound("maxBytesPerProc", options.bounds?.maxBytesPerProc),
		maxTotalSampleBytes: effectiveBound("maxTotalSampleBytes", options.bounds?.maxTotalSampleBytes),
	};
	if (!Number.isSafeInteger(options.supervisor.pid) || options.supervisor.pid <= 0)
		throw new RangeError("supervisor pid must be a positive safe integer");
	if (
		typeof options.supervisor.processStartId !== "string" ||
		!PROCESS_START_ID.test(options.supervisor.processStartId)
	)
		throw new RangeError("supervisor processStartId must be a bounded proc start identity");
	const target = { pid: options.supervisor.pid, processStartId: options.supervisor.processStartId };
	const reader = options.reader ?? defaultLinuxProcReader;
	const gaps: LinuxProcessTreeGap[] = [];
	const truncations: LinuxProcessTreeTruncation[] = [];
	let totalReadBytes = 0;
	const perProcBytes = new Map<number, number>();

	const emptySample = (): LinuxRelevantProcessTreeSample => ({
		schemaVersion: 1,
		provider: "linux_proc_relevant_process_tree",
		target,
		targetIdentityValidated: false,
		bounds,
		usage: { procEntriesVisited: 0, processesRetained: 0, totalSampleBytes: 0 },
		processes: [],
		gaps: [],
		truncations: [],
	});
	if (serializedBytes(emptySample()) > bounds.maxTotalSampleBytes)
		throw new RangeError("maxTotalSampleBytes cannot fit the minimal process-tree sample schema");

	function boundedRead(
		pid: number,
		kind: "stat" | "executable",
	): { result?: LinuxProcReadResult; maximum: number; validAccounting: boolean } {
		const used = perProcBytes.get(pid) ?? 0;
		const maximum = Math.min(bounds.maxBytesPerProc - used, bounds.maxTotalSampleBytes - totalReadBytes);
		if (maximum <= 0) return { maximum: 0, validAccounting: false };
		let result: LinuxProcReadResult;
		try {
			result = kind === "stat" ? reader.readStat(pid, maximum) : reader.readExecutable(pid, maximum);
		} catch {
			result = { bytesRead: 0, error: "read_failed" };
		}
		const boundedValue =
			result.value === undefined || (typeof result.value === "string" && result.value.length <= maximum);
		const valueBytes = typeof result.value === "string" && boundedValue ? Buffer.byteLength(result.value) : undefined;
		const validAccounting =
			Number.isSafeInteger(result.bytesRead) &&
			result.bytesRead >= 0 &&
			result.bytesRead <= maximum &&
			boundedValue &&
			(valueBytes === undefined || valueBytes === result.bytesRead);
		const charged = validAccounting ? result.bytesRead : maximum;
		totalReadBytes += charged;
		perProcBytes.set(pid, used + charged);
		return { result, maximum, validAccounting };
	}

	let listed: LinuxProcEntriesResult;
	try {
		listed = reader.listPids(bounds.maxProcEntriesVisited);
	} catch {
		listed = { pids: [], entriesVisited: 0, truncated: false, error: "read_failed" };
	}
	if (listed.error) gaps.push({ kind: "proc_directory_read_failed" });
	if (listed.truncated) truncations.push({ kind: "proc_entries_visited", limit: bounds.maxProcEntriesVisited });
	const listedPids = Array.isArray(listed.pids)
		? listed.pids.slice(0, bounds.maxProcEntriesVisited).filter((pid) => Number.isSafeInteger(pid) && pid > 0)
		: [];
	const procEntriesVisited = Number.isSafeInteger(listed.entriesVisited)
		? Math.max(0, Math.min(listed.entriesVisited, bounds.maxProcEntriesVisited))
		: 0;
	const stats = new Map<number, ParsedProcStat>();
	for (const pid of listedPids) {
		const read = boundedRead(pid, "stat");
		if (!read.result) {
			gaps.push({ kind: "total_sample_bytes_exhausted", pid });
			truncations.push({ kind: "total_sample_bytes", limit: bounds.maxTotalSampleBytes, pid });
			break;
		}
		const { result } = read;
		if (!read.validAccounting || (result.value !== undefined && typeof result.value !== "string")) {
			gaps.push({ kind: "stat_invalid", pid });
			continue;
		}
		if (result.truncated) {
			gaps.push({ kind: "stat_truncated", pid });
			truncations.push({
				kind:
					read.maximum === bounds.maxTotalSampleBytes - (totalReadBytes - result.bytesRead)
						? "total_sample_bytes"
						: "bytes_per_proc",
				limit:
					read.maximum === bounds.maxTotalSampleBytes - (totalReadBytes - result.bytesRead)
						? bounds.maxTotalSampleBytes
						: bounds.maxBytesPerProc,
				pid,
			});
			continue;
		}
		if (result.value === undefined) {
			gaps.push({ kind: "stat_read_failed", pid });
			continue;
		}
		const parsed = parseProcStat(result.value, pid);
		if (parsed) stats.set(pid, parsed);
		else gaps.push({ kind: "stat_invalid", pid });
	}

	const root = stats.get(target.pid);
	const rootInitiallyValid = root?.processStartId === target.processStartId;
	if (!rootInitiallyValid) gaps.push({ kind: "root_identity_mismatch", pid: target.pid });
	const descendants = new Set<number>();
	if (rootInitiallyValid && root) {
		descendants.add(root.pid);
		let changed = true;
		while (changed) {
			changed = false;
			for (const proc of stats.values()) {
				if (!descendants.has(proc.pid) && descendants.has(proc.ppid)) {
					descendants.add(proc.pid);
					changed = true;
				}
			}
		}
	}

	const rawKnownRoles = Array.isArray(options.knownRoles) ? options.knownRoles : [];
	if (rawKnownRoles.length > bounds.maxProcessesRetained)
		truncations.push({ kind: "known_role_identities", limit: bounds.maxProcessesRetained });
	const knownByPid = new Map<number, LinuxKnownRoleIdentity>();
	for (const identity of rawKnownRoles.slice(0, bounds.maxProcessesRetained)) {
		if (
			Number.isSafeInteger(identity.pid) &&
			identity.pid > 0 &&
			typeof identity.processStartId === "string" &&
			PROCESS_START_ID.test(identity.processStartId) &&
			["worker", "forkserver", "kernel"].includes(identity.role)
		)
			knownByPid.set(identity.pid, {
				pid: identity.pid,
				processStartId: identity.processStartId,
				role: identity.role,
			});
	}

	interface Candidate {
		stat: ParsedProcStat;
		role: LinuxRelevantProcessRole;
		executableIdentity?: string;
	}
	const candidates: Candidate[] = [];
	const observedKnown = new Set<number>();
	for (const pid of [...descendants].sort((left, right) => left - right)) {
		if (candidates.length >= bounds.maxProcessesRetained) {
			truncations.push({ kind: "processes_retained", limit: bounds.maxProcessesRetained, pid });
			break;
		}
		const stat = stats.get(pid)!;
		const known = knownByPid.get(pid);
		let role: LinuxRelevantProcessRole = pid === target.pid ? "supervisor" : "relevant_descendant";
		if (known) {
			if (known.processStartId === stat.processStartId) role = known.role;
			else gaps.push({ kind: "known_role_identity_mismatch", pid, role: known.role });
		}
		let executableIdentity: string | undefined;
		const read = boundedRead(pid, "executable");
		if (!read.result) {
			gaps.push({ kind: "total_sample_bytes_exhausted", pid });
			truncations.push({ kind: "total_sample_bytes", limit: bounds.maxTotalSampleBytes, pid });
		} else {
			const { result } = read;
			if (
				!read.validAccounting ||
				(result.value !== undefined &&
					(typeof result.value !== "string" || !EXECUTABLE_IDENTITY.test(result.value)))
			)
				gaps.push({ kind: "executable_invalid", pid });
			else if (result.truncated) {
				gaps.push({ kind: "executable_truncated", pid });
				truncations.push({ kind: "bytes_per_proc", limit: bounds.maxBytesPerProc, pid });
			} else if (result.value === undefined) gaps.push({ kind: "executable_read_failed", pid });
			else executableIdentity = result.value;
		}
		candidates.push({ stat, role, executableIdentity });
	}

	// Re-read every candidate only after all auxiliary executable reads. Validate the root last.
	const validationOrder = [...candidates].sort((left, right) => {
		if (left.stat.pid === target.pid) return 1;
		if (right.stat.pid === target.pid) return -1;
		return left.stat.pid - right.stat.pid;
	});
	const validated = new Map<number, Candidate>();
	let rootFinallyValid = false;
	for (const candidate of validationOrder) {
		const pid = candidate.stat.pid;
		const read = boundedRead(pid, "stat");
		let current: ParsedProcStat | undefined;
		if (read.result && read.validAccounting && typeof read.result.value === "string") {
			const actualBytes = Buffer.byteLength(read.result.value);
			if (!read.result.truncated && actualBytes === read.result.bytesRead)
				current = parseProcStat(read.result.value, pid);
		}
		if (!current || current.processStartId !== candidate.stat.processStartId) {
			gaps.push({ kind: "identity_revalidation_failed", pid });
			if (pid === target.pid) gaps.push({ kind: "root_identity_mismatch", pid });
			continue;
		}
		if (pid === target.pid) rootFinallyValid = current.processStartId === target.processStartId;
		validated.set(pid, candidate);
	}

	const processes: LinuxRelevantProcess[] = [];
	if (rootInitiallyValid && rootFinallyValid) {
		for (const candidate of candidates) {
			if (!validated.has(candidate.stat.pid)) continue;
			if (candidate.role !== "supervisor" && candidate.role !== "relevant_descendant")
				observedKnown.add(candidate.stat.pid);
			processes.push({
				pid: candidate.stat.pid,
				ppid: candidate.stat.ppid,
				processStartId: candidate.stat.processStartId,
				role: candidate.role,
				state: candidate.stat.state,
				executableIdentity: candidate.executableIdentity,
				cpuTicks: {
					user: candidate.stat.userTicks,
					system: candidate.stat.systemTicks,
					total: (BigInt(candidate.stat.userTicks) + BigInt(candidate.stat.systemTicks)).toString(),
				},
				rssPages: candidate.stat.rssPages,
			});
		}
	}
	for (const identity of knownByPid.values()) {
		if (
			!observedKnown.has(identity.pid) &&
			!gaps.some((gap) => gap.kind === "known_role_identity_mismatch" && gap.pid === identity.pid)
		)
			gaps.push({ kind: "known_role_identity_not_observed", pid: identity.pid, role: identity.role });
	}

	const sample: LinuxRelevantProcessTreeSample = {
		schemaVersion: 1,
		provider: "linux_proc_relevant_process_tree",
		target,
		targetIdentityValidated: rootInitiallyValid && rootFinallyValid,
		bounds,
		usage: { procEntriesVisited, processesRetained: processes.length, totalSampleBytes: totalReadBytes },
		processes,
		gaps,
		truncations,
	};
	if (serializedBytes(sample) > bounds.maxTotalSampleBytes) {
		const gapPriority: Partial<Record<LinuxProcessTreeGap["kind"], number>> = {
			root_identity_mismatch: 0,
			identity_revalidation_failed: 1,
			known_role_identity_mismatch: 2,
			executable_invalid: 3,
		};
		sample.gaps.sort((left, right) => {
			const priority = (gapPriority[left.kind] ?? 10) - (gapPriority[right.kind] ?? 10);
			if (priority !== 0) return priority;
			return (left.pid ?? 0) - (right.pid ?? 0);
		});
		const marker: LinuxProcessTreeTruncation = { kind: "sample_bytes", limit: bounds.maxTotalSampleBytes };
		if (!sample.truncations.some((item) => item.kind === "sample_bytes")) sample.truncations.push(marker);
		while (serializedBytes(sample) > bounds.maxTotalSampleBytes && sample.gaps.length > 0) sample.gaps.pop();
		while (serializedBytes(sample) > bounds.maxTotalSampleBytes && sample.processes.length > 0)
			sample.processes.pop();
		while (serializedBytes(sample) > bounds.maxTotalSampleBytes && sample.truncations.length > 1)
			sample.truncations.splice(sample.truncations.length - 2, 1);
		sample.usage.processesRetained = sample.processes.length;
		if (serializedBytes(sample) > bounds.maxTotalSampleBytes)
			throw new RangeError("maxTotalSampleBytes cannot fit the bounded sample_bytes truncation schema");
	}
	return sample;
}

export interface LinuxCgroupOomKillMatch {
	matched: boolean;
	signal?: NodeJS.Signals | null;
	baseline?: number;
	latest?: number;
	delta?: number;
}

export function hasPositiveLinuxCgroupOomKillDelta(
	runDir: string,
	signal?: NodeJS.Signals | null,
): LinuxCgroupOomKillMatch {
	const summary = readJson<LinuxMemorySummary>(join(runDir, SUMMARY_FILE));
	const baseline = summary?.baseline?.eventsLocal.oom_kill ?? summary?.baseline?.events.oom_kill;
	const latest = summary?.latest?.eventsLocal.oom_kill ?? summary?.latest?.events.oom_kill;
	const delta = baseline !== undefined && latest !== undefined ? latest - baseline : undefined;
	return { matched: delta !== undefined && delta > 0, signal, baseline, latest, delta };
}

export interface LinuxIncidentEvidenceCorrelation {
	environmentClassification?: "kernel_oom_kill";
	applicationEvidence: false;
	environmentEvidence: boolean;
	oomKill: LinuxCgroupOomKillMatch;
}

export function readLinuxIncidentEvidenceCorrelation(runDir: string): LinuxIncidentEvidenceCorrelation {
	const oomKill = hasPositiveLinuxCgroupOomKillDelta(runDir);
	return {
		environmentClassification: oomKill.matched ? "kernel_oom_kill" : undefined,
		applicationEvidence: false,
		environmentEvidence: oomKill.matched,
		oomKill,
	};
}
