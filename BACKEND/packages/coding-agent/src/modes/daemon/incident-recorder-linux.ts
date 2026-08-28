import { randomUUID } from "node:crypto";
import {
	closeSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	lstatSync,
	mkdirSync,
	openSync,
	readSync,
	realpathSync,
	renameSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { getProcessStartId } from "../../core/session-lease.js";

const SUMMARY_FILE = "linux-causal-resource.json";
const MONITOR_FILE = "linux-causal-monitor.json";
const MAX_FILE_BYTES = 256 * 1024;
const MAX_SAMPLES = 32;

export interface LinuxRawSourceOccurrence {
	source: "procfs" | "cgroupfs" | "kernel-tracing" | "system-journal-export" | "journal-query-error";
	sourcePath: string;
	bytes: Buffer;
	encoding: string;
	phase: "baseline" | "periodic" | "anomaly" | "incident-pin" | "service" | "final";
	wallTime: string;
	monotonicNs: string;
	identity?: Record<string, unknown>;
	bounds?: Record<string, unknown>;
}

export interface LinuxPressureValues {
	some?: { avg10: number; avg60: number; avg300: number; total: number };
	full?: { avg10: number; avg60: number; avg300: number; total: number };
}

export interface LinuxMemorySample {
	phase: "baseline" | "periodic" | "service" | "anomaly" | "final";
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
	recordRawSource?: (occurrence: LinuxRawSourceOccurrence) => unknown;
}

export interface LinuxIncidentTargetOptions {
	runDir: string;
	pid: number;
	processStartId: string;
	dependencies?: LinuxIncidentCollectorDependencies;
}

export type LinuxMemorySamplePhase = "baseline" | "periodic" | "service" | "anomaly" | "final";
export interface LinuxIncidentSampleOptions {
	runDir: string;
	phase: LinuxMemorySamplePhase;
	captureBroadRaw?: boolean;
	skipMemorySample?: boolean;
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
	if (!summary || !monitor || options.skipMemorySample) return summary;
	const next = sample(monitor, options.phase, options.dependencies?.now?.() ?? new Date());
	if (!next) return summary;
	summary.latest = next;
	summary.recent = [...summary.recent, next].slice(-MAX_SAMPLES);
	writeJson(summaryPath, summary);
	return summary;
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
