import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	baselineLinuxIncidentEvidence,
	hasPositiveLinuxCgroupOomKillDelta,
	type LinuxProcessTreeProcReader,
	readLinuxIncidentEvidenceCorrelation,
	sampleLinuxIncidentEvidence,
	sampleRelevantLinuxProcessTree,
} from "../src/modes/daemon/incident-recorder-linux.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function runDir(): string {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-linux-causal-"));
	roots.push(root);
	mkdirSync(root, { recursive: true });
	return root;
}

describe("minimal Linux causal resource evidence", () => {
	it("binds bounded cgroup samples to the exact process identity", () => {
		const run = runDir();
		const processStartId = getProcessStartId(process.pid);
		expect(processStartId).toBeTruthy();
		const baseline = baselineLinuxIncidentEvidence({
			runDir: run,
			pid: process.pid,
			processStartId: processStartId!,
		});
		expect(baseline).toMatchObject({ targetIdentityValidated: true });
		for (let index = 0; index < 40; index += 1) sampleLinuxIncidentEvidence({ runDir: run, phase: "periodic" });
		const persistedBytes = readFileSync(join(run, "linux-causal-resource.json"));
		const persisted = JSON.parse(persistedBytes.toString("utf8")) as {
			capability: { status: string; reason?: string };
			recent: unknown[];
			latest?: { events: Record<string, number>; eventsLocal: Record<string, number> };
		};
		expect(persistedBytes.length).toBeLessThanOrEqual(256 * 1024);
		if (persisted.capability.status === "available") {
			expect(persisted.recent).toHaveLength(32);
			expect(persisted.latest?.events).toBeTypeOf("object");
			expect(persisted.latest?.eventsLocal).toBeTypeOf("object");
		} else {
			expect(persisted.capability.reason).toBe("sample_unavailable");
		}
	});

	it("fails closed for a mismatched target identity", () => {
		const run = runDir();
		const summary = baselineLinuxIncidentEvidence({ runDir: run, pid: process.pid, processStartId: "proc:1" });
		expect(summary).toMatchObject({
			targetIdentityValidated: false,
			capability: { status: "unavailable", reason: "target_identity_unavailable" },
		});
	});

	it("attributes kernel OOM only from a positive exact cgroup counter delta", () => {
		const run = runDir();
		writeFileSync(
			join(run, "linux-causal-resource.json"),
			JSON.stringify({
				schemaVersion: 2,
				provider: "linux_cgroup_v2",
				target: { pid: 123, processStartId: "proc:1" },
				targetIdentityValidated: true,
				capability: { status: "available" },
				baseline: { events: { oom_kill: 4 }, eventsLocal: { oom_kill: 4 } },
				latest: { events: { oom_kill: 5 }, eventsLocal: { oom_kill: 5 } },
				recent: [],
			}),
		);
		expect(hasPositiveLinuxCgroupOomKillDelta(run, "SIGKILL")).toMatchObject({
			matched: true,
			baseline: 4,
			latest: 5,
			delta: 1,
		});
		expect(readLinuxIncidentEvidenceCorrelation(run)).toMatchObject({
			environmentClassification: "kernel_oom_kill",
			environmentEvidence: true,
			applicationEvidence: false,
		});
	});
});

function procStat(
	pid: number,
	ppid: number,
	start: number,
	options?: { user?: number; system?: number; rss?: number },
): string {
	const fields = Array.from({ length: 22 }, () => "0");
	fields[0] = "S";
	fields[1] = String(ppid);
	fields[11] = String(options?.user ?? 3);
	fields[12] = String(options?.system ?? 4);
	fields[19] = String(start);
	fields[21] = String(options?.rss ?? 5);
	return `${pid} (fixture process) ${fields.join(" ")}`;
}

function fixtureReader(
	processes: Readonly<Record<number, { stat?: string; executable?: string }>>,
	extraEntries = 0,
): LinuxProcessTreeProcReader {
	return {
		listPids(maxEntriesVisited) {
			const pids = Object.keys(processes)
				.map(Number)
				.sort((left, right) => left - right);
			const entries = [...pids, ...Array.from({ length: extraEntries }, (_, index) => 90_000 + index)];
			return {
				pids: entries.slice(0, maxEntriesVisited),
				entriesVisited: Math.min(entries.length, maxEntriesVisited),
				truncated: entries.length > maxEntriesVisited,
			};
		},
		readStat(pid, maxBytes) {
			const value = processes[pid]?.stat;
			if (value === undefined) return { bytesRead: 0, error: "missing" };
			const bytesRead = Buffer.byteLength(value);
			return bytesRead >= maxBytes ? { bytesRead: maxBytes, truncated: true } : { value, bytesRead };
		},
		readExecutable(pid, maxBytes) {
			const value = processes[pid]?.executable;
			if (value === undefined) return { bytesRead: 0, error: "missing" };
			const bytesRead = Buffer.byteLength(value);
			return bytesRead >= maxBytes ? { bytesRead: maxBytes, truncated: true } : { value, bytesRead };
		},
	};
}

describe("bounded relevant Linux process tree sampling", () => {
	const executable = "dev:0000000000000002:ino:000000000000000b";

	it("retains only the exact supervisor lineage and applies exact known-role identities", () => {
		const reader = fixtureReader({
			10: { stat: procStat(10, 1, 100), executable },
			11: { stat: procStat(11, 10, 110), executable },
			12: { stat: procStat(12, 11, 120), executable },
			13: { stat: procStat(13, 10, 130), executable },
			14: { stat: procStat(14, 10, 140), executable },
			20: { stat: procStat(20, 1, 200), executable },
			21: { stat: procStat(21, 20, 210), executable },
		});
		const sample = sampleRelevantLinuxProcessTree({
			supervisor: { pid: 10, processStartId: "proc:100" },
			knownRoles: [
				{ pid: 11, processStartId: "proc:110", role: "worker" },
				{ pid: 12, processStartId: "proc:120", role: "kernel" },
				{ pid: 14, processStartId: "proc:140", role: "forkserver" },
			],
			reader,
		});
		expect(sample.targetIdentityValidated).toBe(true);
		expect(sample.processes.map(({ pid, role }) => ({ pid, role }))).toEqual([
			{ pid: 10, role: "supervisor" },
			{ pid: 11, role: "worker" },
			{ pid: 12, role: "kernel" },
			{ pid: 13, role: "relevant_descendant" },
			{ pid: 14, role: "forkserver" },
		]);
		expect(sample.processes[1]).toMatchObject({
			ppid: 10,
			state: "S",
			executableIdentity: executable,
			cpuTicks: { user: "3", system: "4", total: "7" },
			rssPages: "5",
		});
	});

	it("clears a root lineage reused mid-sample and excludes a role reused mid-sample", () => {
		const mutableReader = (changedPid: number): LinuxProcessTreeProcReader => {
			const reads = new Map<number, number>();
			return {
				listPids: () => ({ pids: [10, 11], entriesVisited: 2, truncated: false }),
				readStat(pid, maximum) {
					const count = (reads.get(pid) ?? 0) + 1;
					reads.set(pid, count);
					const start = pid === changedPid && count > 1 ? 999 : pid === 10 ? 100 : 110;
					const value = procStat(pid, pid === 10 ? 1 : 10, start);
					const bytesRead = Buffer.byteLength(value);
					return bytesRead >= maximum ? { bytesRead: maximum, truncated: true } : { value, bytesRead };
				},
				readExecutable: () => ({ value: executable, bytesRead: Buffer.byteLength(executable) }),
			};
		};
		const reusedRoot = sampleRelevantLinuxProcessTree({
			supervisor: { pid: 10, processStartId: "proc:100" },
			reader: mutableReader(10),
		});
		expect(reusedRoot.targetIdentityValidated).toBe(false);
		expect(reusedRoot.processes).toEqual([]);
		expect(reusedRoot.gaps).toContainEqual({ kind: "identity_revalidation_failed", pid: 10 });
		expect(reusedRoot.gaps).toContainEqual({ kind: "root_identity_mismatch", pid: 10 });

		const reusedWorker = sampleRelevantLinuxProcessTree({
			supervisor: { pid: 10, processStartId: "proc:100" },
			knownRoles: [{ pid: 11, processStartId: "proc:110", role: "worker" }],
			reader: mutableReader(11),
		});
		expect(reusedWorker.targetIdentityValidated).toBe(true);
		expect(reusedWorker.processes.map((process) => process.pid)).toEqual([10]);
		expect(reusedWorker.gaps).toContainEqual({ kind: "identity_revalidation_failed", pid: 11 });
	});

	it("retains only fixed executable identities and rejects lying byte counts", () => {
		const pathSample = sampleRelevantLinuxProcessTree({
			supervisor: { pid: 10, processStartId: "proc:100" },
			reader: fixtureReader({ 10: { stat: procStat(10, 1, 100), executable: "/bin/private-path" } }),
		});
		expect(pathSample.processes[0]?.executableIdentity).toBeUndefined();
		expect(pathSample.gaps).toContainEqual({ kind: "executable_invalid", pid: 10 });

		const stat = procStat(10, 1, 100);
		const lyingReader: LinuxProcessTreeProcReader = {
			listPids: () => ({ pids: [10], entriesVisited: 1, truncated: false }),
			readStat: () => ({ value: stat, bytesRead: Buffer.byteLength(stat) }),
			readExecutable: () => ({ value: executable, bytesRead: 1 }),
		};
		const lyingSample = sampleRelevantLinuxProcessTree({
			supervisor: { pid: 10, processStartId: "proc:100" },
			reader: lyingReader,
		});
		expect(lyingSample.processes[0]?.executableIdentity).toBeUndefined();
		expect(lyingSample.gaps).toContainEqual({ kind: "executable_invalid", pid: 10 });
	});

	it("rejects malformed reader values without trusting their byte accounting", () => {
		const malformedValues: Array<{ value: unknown; bytesRead: number }> = [
			{ value: 42, bytesRead: 2 },
			{ value: procStat(10, 1, 100), bytesRead: -1 },
			{ value: procStat(10, 1, 100), bytesRead: 2048 },
		];
		for (const malformed of malformedValues) {
			const reader: LinuxProcessTreeProcReader = {
				listPids: () => ({ pids: [10], entriesVisited: 1, truncated: false }),
				readStat: () =>
					({ value: malformed.value, bytesRead: malformed.bytesRead }) as ReturnType<
						LinuxProcessTreeProcReader["readStat"]
					>,
				readExecutable: () => ({ value: executable, bytesRead: Buffer.byteLength(executable) }),
			};
			const sample = sampleRelevantLinuxProcessTree({
				supervisor: { pid: 10, processStartId: "proc:100" },
				bounds: { maxTotalSampleBytes: 1024 },
				reader,
			});
			expect(sample.processes).toEqual([]);
			expect(sample.gaps).toContainEqual({ kind: "stat_invalid", pid: 10 });
			expect(sample.usage.totalSampleBytes).toBe(1024);
			expect(Buffer.byteLength(JSON.stringify(sample))).toBeLessThanOrEqual(1024);
		}
	});

	it("rejects invalid, zero, and unrepresentable caps instead of widening them", () => {
		const base = { supervisor: { pid: 10, processStartId: "proc:100" }, reader: fixtureReader({}) };
		for (const maxProcessesRetained of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1.5]) {
			expect(() => sampleRelevantLinuxProcessTree({ ...base, bounds: { maxProcessesRetained } })).toThrow(
				RangeError,
			);
		}
		expect(() => sampleRelevantLinuxProcessTree({ ...base, bounds: { maxTotalSampleBytes: 1 } })).toThrow(
			"cannot fit",
		);
		expect(() => sampleRelevantLinuxProcessTree({ ...base, bounds: { maxTotalSampleBytes: 400 } })).toThrow(
			"sample_bytes",
		);
	});

	it("accounts identity re-reads inside exact per-process and total request budgets", () => {
		const stat = procStat(10, 1, 100);
		const statBytes = Buffer.byteLength(stat);
		const executableBytes = Buffer.byteLength(executable);
		const requests: Array<{ maximum: number; bytesRead: number }> = [];
		const reader: LinuxProcessTreeProcReader = {
			listPids: () => ({ pids: [10], entriesVisited: 1, truncated: false }),
			readStat(_pid, maximum) {
				requests.push({ maximum, bytesRead: statBytes });
				return { value: stat, bytesRead: statBytes };
			},
			readExecutable(_pid, maximum) {
				requests.push({ maximum, bytesRead: executableBytes });
				return { value: executable, bytesRead: executableBytes };
			},
		};
		const maxBytesPerProc = statBytes * 2 + executableBytes;
		const maxTotalSampleBytes = 1024;
		const sample = sampleRelevantLinuxProcessTree({
			supervisor: { pid: 10, processStartId: "proc:100" },
			bounds: { maxBytesPerProc, maxTotalSampleBytes },
			reader,
		});
		expect(requests).toHaveLength(3);
		let accounted = 0;
		for (const request of requests) {
			expect(request.maximum).toBeLessThanOrEqual(maxTotalSampleBytes - accounted);
			expect(request.maximum).toBeLessThanOrEqual(maxBytesPerProc - accounted);
			accounted += request.bytesRead;
		}
		expect(sample.targetIdentityValidated).toBe(true);
		expect(sample.usage.totalSampleBytes).toBe(accounted);
	});

	it("bounds many gaps and every serialized sample with explicit sample-byte truncation", () => {
		const pids = Array.from({ length: 500 }, (_, index) => index + 10);
		const reader: LinuxProcessTreeProcReader = {
			listPids: () => ({ pids, entriesVisited: pids.length, truncated: false }),
			readStat: () => ({ bytesRead: 0, error: "missing" }),
			readExecutable: () => ({ bytesRead: 0, error: "missing" }),
		};
		const maxTotalSampleBytes = 700;
		const sample = sampleRelevantLinuxProcessTree({
			supervisor: { pid: 10, processStartId: "proc:100" },
			bounds: { maxTotalSampleBytes },
			reader,
		});
		expect(sample.truncations).toContainEqual({ kind: "sample_bytes", limit: maxTotalSampleBytes });
		expect(Buffer.byteLength(JSON.stringify(sample))).toBeLessThanOrEqual(maxTotalSampleBytes);
	});
});
