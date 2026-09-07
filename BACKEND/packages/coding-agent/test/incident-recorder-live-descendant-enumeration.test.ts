import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	enumerateIncidentRecorderLiveDescendants,
	INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DIRECTORY_ENTRIES,
	INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS,
	type IncidentRecorderLiveDescendantEnumerationFileSystem,
} from "../src/modes/daemon/incident-recorder-live-descendant-enumeration.js";

function stat(pid: number, startTicks: bigint, parentPid: number, comm = "worker"): Buffer {
	const fields = Array<string>(20).fill("0");
	fields[0] = "S";
	fields[1] = String(parentPid);
	fields[19] = startTicks.toString();
	return Buffer.from(`${pid} (${comm}) ${fields.join(" ")}\n`);
}

type DirectoryEntries = readonly string[] | (() => string | undefined);

class MapFileSystem implements IncidentRecorderLiveDescendantEnumerationFileSystem {
	private readonly values = new Map<string, Buffer | readonly Buffer[]>();
	private readonly descriptors = new Map<number, { path: string; offset: number }>();
	private nextDescriptor = 10;
	private nextDirectory = 1;
	readonly opened: number[] = [];
	readonly closed: number[] = [];
	readonly openedDirectories: number[] = [];
	readonly closedDirectories: number[] = [];
	readonly nonRegular = new Set<string>();
	readonly openErrors = new Set<string>();
	readonly readErrors = new Set<string>();
	directoryReadError = false;
	readonly readCalls = new Map<string, number>();

	constructor(readonly entries: DirectoryEntries) {}

	set(path: string, value: Buffer | readonly Buffer[]): void {
		this.values.set(path, value);
	}

	opendirSync(): { readSync(): { name: string } | null; closeSync(): void } {
		let index = 0;
		let closed = false;
		const directory = this.nextDirectory++;
		this.openedDirectories.push(directory);
		return {
			readSync: () => {
				if (closed) throw new Error("directory closed");
				if (this.directoryReadError) throw new Error("directory read failed");
				const name = typeof this.entries === "function" ? this.entries() : this.entries[index++];
				return name === undefined ? null : { name };
			},
			closeSync: () => {
				closed = true;
				this.closedDirectories.push(directory);
			},
		};
	}

	openSync(path: string): number {
		if (this.openErrors.has(path)) throw new Error(`open failed for ${path}`);
		if (!this.values.has(path)) {
			const error = new Error(`missing ${path}`) as NodeJS.ErrnoException;
			error.code = "ENOENT";
			throw error;
		}
		const fd = this.nextDescriptor++;
		this.opened.push(fd);
		this.descriptors.set(fd, { path, offset: 0 });
		return fd;
	}

	fstatSync(fd: number): { isFile(): boolean } {
		const descriptor = this.descriptors.get(fd);
		return { isFile: () => descriptor !== undefined && !this.nonRegular.has(descriptor.path) };
	}

	readSync(fd: number, buffer: Buffer, offset: number, length: number): number {
		const descriptor = this.descriptors.get(fd);
		if (!descriptor) throw new Error("unknown descriptor");
		const count = (this.readCalls.get(descriptor.path) ?? 0) + 1;
		this.readCalls.set(descriptor.path, count);
		if (this.readErrors.has(descriptor.path)) throw new Error(`read failed for ${descriptor.path}`);
		const configured = this.values.get(descriptor.path);
		if (!configured) throw new Error("missing fixture");
		const value = Array.isArray(configured) ? (configured[count - 1] ?? configured.at(-1)) : configured;
		if (!value) return 0;
		if (descriptor.offset >= value.length) return 0;
		const actual = Math.min(length, value.length - descriptor.offset);
		value.copy(buffer, offset, descriptor.offset, descriptor.offset + actual);
		descriptor.offset += actual;
		return actual;
	}

	closeSync(fd: number): void {
		this.closed.push(fd);
		this.descriptors.delete(fd);
	}
}

function fixture(entries: readonly string[] = ["1", "2", "3", "4", "not-a-pid"]): MapFileSystem {
	const fs = new MapFileSystem(entries);
	fs.set("/proc/1/stat", stat(1, 100n, 99, "root"));
	return fs;
}

function enumerate(fs: MapFileSystem, now: () => number = () => 0) {
	return enumerateIncidentRecorderLiveDescendants({
		captureId: "capture-1",
		targetPid: 1,
		targetProcessStartId: "proc:100",
		fileSystem: fs,
		now,
	});
}

function readLinuxParentPid(pid: number): number | undefined {
	try {
		const statText = readFileSync(`/proc/${pid}/stat`, "utf8");
		const closingParen = statText.lastIndexOf(")");
		const fields = statText
			.slice(closingParen + 2)
			.trim()
			.split(/\s+/);
		const parentPid = Number(fields[1]);
		return Number.isSafeInteger(parentPid) && parentPid > 0 ? parentPid : undefined;
	} catch {
		return undefined;
	}
}

function waitForExit(child: ReturnType<typeof spawn>, timeoutMs: number): Promise<boolean> {
	if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
	return new Promise((resolve) => {
		let settled = false;
		const finish = (exited: boolean) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			child.removeListener("exit", onExit);
			resolve(exited);
		};
		const onExit = () => finish(true);
		const timer = setTimeout(() => finish(false), timeoutMs);
		child.once("exit", onExit);
	});
}

async function waitForFixturePidExit(pid: number, startId: string, timeoutMs: number): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (getProcessStartId(pid) !== startId) return true;
		await new Promise<void>((resolve) => setTimeout(resolve, 25));
	}
	return getProcessStartId(pid) !== startId;
}

interface LinuxFixtureInfo {
	rootPID: number;
	nativeTID: number;
	childPID: number;
}

async function terminateFixtureChild(info: LinuxFixtureInfo, expectedStartId: string): Promise<void> {
	const pid = info.childPID;
	if (!Number.isSafeInteger(pid) || pid <= 0) return;
	for (const signal of ["SIGTERM", "SIGKILL"] as const) {
		if (getProcessStartId(pid) !== expectedStartId || readLinuxParentPid(pid) === undefined) return;
		try {
			// The child may be reparented after Python exits; its captured start identity remains the ownership proof.
			process.kill(pid, signal);
		} catch {
			return;
		}
		if (await waitForFixturePidExit(pid, expectedStartId, 1_000)) return;
	}
}

async function cleanupLinuxFixture(
	child: ReturnType<typeof spawn>,
	fixtureInfo: LinuxFixtureInfo | undefined,
	childStartId: string | undefined,
): Promise<boolean> {
	if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
	let parentExited = await waitForExit(child, 5_000);
	if (!parentExited && fixtureInfo && childStartId) {
		await terminateFixtureChild(fixtureInfo, childStartId);
		if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
		parentExited = await waitForExit(child, 1_000);
	}
	if (!fixtureInfo || !childStartId) return parentExited;
	let childExited = await waitForFixturePidExit(fixtureInfo.childPID, childStartId, 2_000);
	if (!childExited) {
		await terminateFixtureChild(fixtureInfo, childStartId);
		childExited = await waitForFixturePidExit(fixtureInfo.childPID, childStartId, 1_000);
	}
	return parentExited && childExited;
}

describe("bounded live descendant enumeration", () => {
	it("returns a stable target and BFS/PID-sorted descendants with same-pass parent identities", () => {
		const fs = fixture();
		fs.set("/proc/2/stat", stat(2, 200n, 1));
		fs.set("/proc/3/stat", stat(3, 150n, 1));
		fs.set("/proc/4/stat", stat(4, 300n, 2, "a)b)"));
		fs.set("/proc/9/stat", stat(9, 900n, 999));

		const result = enumerate(fs);

		expect(result.passState).toBe("complete");
		expect(result.observationalPassComplete).toBe(true);
		expect(result.treeCompleteness).toBe("not_claimed");
		expect(result.target).toMatchObject({ pid: 1, processStartId: "proc:100", state: "stable" });
		expect(result.descendants.map((item) => [item.pid, item.depth])).toEqual([
			[2, 1],
			[3, 1],
			[4, 2],
		]);
		expect(result.descendants[0]?.parent).toMatchObject({
			pid: 1,
			processStartId: "proc:100",
			identityMatch: "same_pass_stable_stat",
		});
		expect(result.descendants[2]?.parent).toMatchObject({
			pid: 2,
			processStartId: "proc:200",
			identityMatch: "same_pass_stable_stat",
		});
		expect(result.descendants.every((item) => item.rawReads.length === 2)).toBe(true);
		expect(fs.opened).toHaveLength(fs.closed.length);
		expect(result.receipts).toHaveLength(3);
	});

	it("keeps typed receipts for vanished, malformed, identity-changed, and parent-changed candidates", () => {
		const fs = fixture(["1", "2", "5", "6", "7", "9"]);
		fs.set("/proc/2/stat", stat(2, 200n, 1));
		fs.set("/proc/5/stat", [stat(5, 500n, 1), stat(5, 501n, 1)]);
		fs.set("/proc/6/stat", [stat(6, 600n, 1), stat(6, 600n, 2)]);
		fs.set("/proc/7/stat", Buffer.from("malformed\n"));

		const result = enumerate(fs);

		expect(result.receipts.find((receipt) => receipt.pid === 2)?.state).toBe("admitted");
		expect(result.receipts.find((receipt) => receipt.pid === 5)?.state).toBe("identity_changed");
		expect(result.receipts.find((receipt) => receipt.pid === 6)?.state).toBe("parent_changed");
		expect(result.receipts.find((receipt) => receipt.pid === 7)?.state).toBe("malformed");
		expect(result.receipts.find((receipt) => receipt.pid === 999)?.state).toBeUndefined();
		const vanished = result.receipts.find((receipt) => receipt.pid === 9);
		expect(vanished?.state).toBe("vanished");
	});

	it("does not admit descendants when the final target identity changes and always closes descriptors", () => {
		const fs = fixture(["1", "2"]);
		fs.set("/proc/1/stat", [stat(1, 100n, 99), stat(1, 101n, 99)]);
		fs.set("/proc/2/stat", stat(2, 200n, 1));

		const result = enumerate(fs);

		expect(result.target.state).toBe("unverified");
		expect(result.reason).toBe("target_identity_changed");
		expect(result.descendants).toEqual([]);
		expect(result.observationalPassComplete).toBe(false);
		expect(result.target.rawReads?.map((read) => read.readOrdinal)).toEqual([1, 2]);
		expect(fs.opened).toHaveLength(fs.closed.length);
	});

	it("rejects an initial target identity mismatch before scanning the population", () => {
		const fs = fixture(["1", "2"]);
		fs.set("/proc/1/stat", stat(1, 101n, 99));
		fs.set("/proc/2/stat", stat(2, 200n, 1));

		const result = enumerate(fs);

		expect(result.target.state).toBe("unverified");
		expect(result.reason).toBe("target_identity_changed");
		expect(result.descendants).toEqual([]);
		expect(fs.opened).toHaveLength(1);
	});

	it("does not infer unresolved or temporally impossible parent edges", () => {
		const fs = fixture(["1", "2", "3", "4"]);
		fs.set("/proc/2/stat", stat(2, 200n, 99));
		fs.set("/proc/3/stat", stat(3, 50n, 1));
		fs.set("/proc/4/stat", stat(4, 300n, 2));

		const result = enumerate(fs);

		expect(result.descendants).toEqual([]);
		expect(result.receipts.find((receipt) => receipt.pid === 2)).toMatchObject({
			state: "parent_identity_unresolved",
			reason: "parent_identity_unresolved",
		});
		expect(result.receipts.find((receipt) => receipt.pid === 3)).toMatchObject({
			state: "temporally_impossible_parent",
			reason: "temporally_impossible_parent",
		});
		expect(result.receipts.find((receipt) => receipt.pid === 4)?.state).toBe("not_transitive");
	});

	it("bounds total directory entries and numeric PIDs with an incremental fixture", () => {
		let nextPid = 1;
		const fs = new MapFileSystem(() =>
			nextPid <= INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DIRECTORY_ENTRIES + 1
				? String(nextPid++)
				: undefined,
		);
		fs.set("/proc/1/stat", stat(1, 100n, 99, "root"));

		const result = enumerate(fs);

		expect(result.directoryEntriesSeen).toBe(INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DIRECTORY_ENTRIES);
		expect(result.numericPidsSeen).toBe(INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DIRECTORY_ENTRIES);
		expect(result.attemptedPids.length).toBeLessThanOrEqual(
			INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS,
		);
		expect(result.attemptedPids).toHaveLength(INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS - 1);
		expect(result.attemptedPids.every((pid) => pid > 0 && Number.isSafeInteger(pid))).toBe(true);
		expect(result.reason).toBe("directory_population_limit");
		expect(result.observationalPassComplete).toBe(false);
		expect(result.subjectCoverage).toBe("truncated");
		expect(result.passState).toBe("truncated");
		expect(result.treeCompleteness).toBe("not_claimed");
	});

	it("reports numeric PID population truncation without retaining an unbounded candidate list", () => {
		let nextPid = 1;
		const fs = new MapFileSystem(() =>
			nextPid <= INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS + 1 ? String(nextPid++) : undefined,
		);
		fs.set("/proc/1/stat", stat(1, 100n, 99, "root"));

		const result = enumerate(fs);

		expect(result.directoryEntriesSeen).toBe(INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS + 1);
		expect(result.numericPidsSeen).toBe(INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS + 1);
		expect(result.attemptedPids.length).toBeLessThanOrEqual(
			INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS,
		);
		expect(result.attemptedPids).toHaveLength(INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS - 1);
		expect(result.reason).toBe("numeric_population_limit");
		expect(result.observationalPassComplete).toBe(false);
		expect(result.subjectCoverage).toBe("truncated");
		expect(result.passState).toBe("truncated");
		expect(result.treeCompleteness).toBe("not_claimed");
	});

	it.each(["nonregular", "open", "read", "directory"] as const)(
		"closes all descriptors and keeps %s errors typed without admitting a false child",
		(kind) => {
			const fs = fixture(["1", "2"]);
			fs.set("/proc/2/stat", stat(2, 200n, 1));
			if (kind === "nonregular") fs.nonRegular.add("/proc/2/stat");
			if (kind === "open") fs.openErrors.add("/proc/2/stat");
			if (kind === "read") fs.readErrors.add("/proc/2/stat");
			if (kind === "directory") fs.directoryReadError = true;

			const result = enumerate(fs);

			expect(result.descendants).toEqual([]);
			expect(fs.opened).toEqual(fs.closed);
			expect(fs.openedDirectories).toEqual(fs.closedDirectories);
			if (kind === "directory") {
				expect(result.passState).toBe("unavailable");
				expect(result.reason).toBe("stat_unavailable");
				expect(result.receipts).toEqual([]);
			} else {
				expect(result.receipts.find((receipt) => receipt.pid === 2)).toMatchObject({
					pid: 2,
					state: "unavailable",
					reason: "stat_unavailable",
				});
			}
		},
	);

	it("keeps direct BFS cycle candidates non-transitive and relation claims observational", () => {
		const fs = fixture(["1", "2", "3", "4"]);
		fs.set("/proc/2/stat", stat(2, 200n, 3));
		fs.set("/proc/3/stat", stat(3, 200n, 2));
		fs.set("/proc/4/stat", stat(4, 150n, 1));

		const result = enumerate(fs);

		expect(result.descendants.map((item) => [item.pid, item.depth])).toEqual([[4, 1]]);
		expect(result.descendants[0]?.relation).toEqual({
			kind: "observed_ppid_graph_match",
			childPpidStableAcrossReads: true,
			causalParentageProven: false,
		});
		expect(result.receipts.filter((receipt) => receipt.pid === 2 || receipt.pid === 3)).toMatchObject([
			{ pid: 2, state: "not_transitive", reason: "parent_not_transitive" },
			{ pid: 3, state: "not_transitive", reason: "parent_not_transitive" },
		]);
		expect(result.treeCompleteness).toBe("not_claimed");
	});

	it("rejects a direct child whose independent start graph makes its parent impossible", () => {
		const fs = fixture(["1", "2", "3"]);
		fs.set("/proc/2/stat", stat(2, 50n, 1));
		fs.set("/proc/3/stat", stat(3, 150n, 1));

		const result = enumerate(fs);

		expect(result.descendants.map((item) => item.pid)).toEqual([3]);
		expect(result.receipts.find((receipt) => receipt.pid === 2)).toMatchObject({
			state: "temporally_impossible_parent",
			reason: "temporally_impossible_parent",
		});
		expect(result.passState).toBe("truncated");
		expect(result.observationalPassComplete).toBe(false);
		expect(result.treeCompleteness).toBe("not_claimed");
	});

	it("stops at bounded population and byte/frontier limits without claiming no children", () => {
		const fs = fixture(["1", "2", "3", "4"]);
		fs.set("/proc/2/stat", stat(2, 200n, 1));
		fs.set("/proc/3/stat", stat(3, 300n, 1));
		fs.set("/proc/4/stat", stat(4, 400n, 1));

		const population = enumerateIncidentRecorderLiveDescendants({
			captureId: "capture-2",
			targetPid: 1,
			targetProcessStartId: "proc:100",
			fileSystem: fs,
			subjectLimit: 2,
		});
		expect(population.subjectCoverage).toBe("truncated");
		expect(population.passState).toBe("truncated");
		expect(population.descendants).toHaveLength(1);

		const insufficient = enumerateIncidentRecorderLiveDescendants({
			captureId: "capture-3",
			targetPid: 1,
			targetProcessStartId: "proc:100",
			fileSystem: fs,
			byteBudget: 128 * 1024,
		});
		expect(insufficient.reason).toBe("insufficient_identity_budget");
		expect(insufficient.target.state).toBe("unverified");
		expect(insufficient.descendants).toEqual([]);
	});

	it("counts the one-byte lookahead without exceeding the global byte budget", () => {
		const fs = fixture(["1"]);
		const oversized = Buffer.alloc(128 * 1024 + 32, 65);
		fs.set("/proc/1/stat", oversized);

		const result = enumerateIncidentRecorderLiveDescendants({
			captureId: "capture-4",
			targetPid: 1,
			targetProcessStartId: "proc:100",
			fileSystem: fs,
			byteBudget: 200_000,
		});

		expect(result.reason).toBe("target_initial_truncated");
		expect(result.bytesRead).toBe(128 * 1024 + 1);
		expect(result.bytesRead).toBeLessThanOrEqual(200_000);
		expect(result.target.rawReads?.[0]?.bytes.length).toBe(128 * 1024);
	});

	it("observes a direct descendant of a non-leader thread in an isolated Linux process", async () => {
		if (process.platform !== "linux") return;
		const script = [
			"import json, os, signal, subprocess, threading",
			"stop = threading.Event()",
			"def request_stop(_signum, _frame):",
			" stop.set()",
			"signal.signal(signal.SIGTERM, request_stop)",
			"signal.signal(signal.SIGINT, request_stop)",
			"def launch():",
			" p=subprocess.Popen(['sleep','10'])",
			" try:",
			"  print(json.dumps({'rootPID':os.getpid(),'nativeTID':threading.get_native_id(),'childPID':p.pid}), flush=True)",
			"  stop.wait(10)",
			" finally:",
			"  if p.poll() is None:",
			"   p.terminate()",
			"   try:",
			"    p.wait(timeout=5)",
			"   except subprocess.TimeoutExpired:",
			"    p.kill()",
			"    p.wait()",
			"worker=threading.Thread(target=launch)",
			"worker.start()",
			"stop.wait(10)",
			"worker.join()",
		].join("\n");
		const child = spawn("python3", ["-c", script]);
		let fixtureInfo: LinuxFixtureInfo | undefined;
		let fixtureChildStartId: string | undefined;
		let fixtureChildStopped = true;
		try {
			const line = await new Promise<string>((resolve, reject) => {
				let output = "";
				child.stdout.on("data", (chunk: Buffer) => {
					output += chunk.toString();
					const first = output.split("\n")[0];
					if (first) resolve(first);
				});
				child.once("error", reject);
				child.once("close", (code) =>
					reject(new Error(`Linux fixture exited before startup: ${code ?? "unknown"}`)),
				);
			});
			const liveFixtureInfo = JSON.parse(line) as LinuxFixtureInfo;
			fixtureInfo = liveFixtureInfo;
			fixtureChildStartId = getProcessStartId(liveFixtureInfo.childPID);
			expect(fixtureChildStartId).toBeDefined();
			expect(liveFixtureInfo.nativeTID).not.toBe(liveFixtureInfo.rootPID);
			const start = getProcessStartId(liveFixtureInfo.rootPID);
			expect(start).toBeDefined();
			const result = enumerateIncidentRecorderLiveDescendants({
				captureId: "linux-live",
				targetPid: liveFixtureInfo.rootPID,
				targetProcessStartId: start ?? "proc:0",
			});
			expect(result.descendants.some((item) => item.pid === liveFixtureInfo.childPID)).toBe(true);
		} finally {
			fixtureChildStopped = await cleanupLinuxFixture(child, fixtureInfo, fixtureChildStartId);
		}
		expect(fixtureChildStopped).toBe(true);
	});
});
