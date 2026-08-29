import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type ForkedKernelHandle, ForkServer, ForkServerUnavailable } from "../src/core/kernel/fork-server.js";
import { ORPHAN_PROCESS_JOURNAL_ENV } from "../src/core/orphan-process-journal.js";
import { getProcessStartId } from "../src/core/session-lease.js";
import { sanitizeIncidentCausalFields } from "../src/modes/daemon/incident-recorder-writer.js";

const incidentRecorder = vi.hoisted(() => ({
	emitIncidentDerived: vi.fn(
		(
			_source: string,
			_type: string,
			_fields: Record<string, unknown>,
		): { accepted: boolean; occurrenceId: string; reason?: string } => ({
			accepted: true,
			occurrenceId: "test-occurrence",
		}),
	),
}));

vi.mock("../src/modes/daemon/incident-recorder-writer.js", async (importOriginal) => {
	const original = await importOriginal<typeof import("../src/modes/daemon/incident-recorder-writer.js")>();
	return { ...original, emitIncidentDerived: incidentRecorder.emitIncidentDerived };
});

// Drives the REAL Python forkserver script through the REAL ForkServer class.
// Stub Python modules stand in for IPython/ipykernel so the forked child stays
// alive without a real kernel — fork itself is safe here even on macOS because
// the child never touches the frameworks that make fork-without-exec unsafe.
const STUB_KERNELAPP = [
	"import os",
	"import time",
	"",
	"",
	"class IPKernelApp:",
	"    @classmethod",
	"    def clear_instance(cls):",
	"        pass",
	"",
	"    @classmethod",
	"    def instance(cls, **_kwargs):",
	"        return cls()",
	"",
	"    def initialize(self, _argv):",
	"        pass",
	"",
	"    def start(self):",
	"        # Env knob: lets tests fork a child that exits immediately (the",
	"        # per-kernel env is applied in the child before start()).",
	"        if os.environ.get('STUB_KERNEL_EXIT'):",
	"            return",
	"        while True:",
	"            time.sleep(1)",
	"",
].join("\n");

function writeStubModules(dir: string): void {
	writeFileSync(join(dir, "IPython.py"), "");
	writeFileSync(join(dir, "jupyter_client.py"), "");
	writeFileSync(join(dir, "nest_asyncio.py"), "");
	const ipykernelDir = join(dir, "ipykernel");
	mkdirSync(ipykernelDir);
	writeFileSync(join(ipykernelDir, "__init__.py"), "");
	writeFileSync(join(ipykernelDir, "kernelapp.py"), STUB_KERNELAPP);
}

function killQuietly(pid: number | undefined): void {
	if (pid === undefined) return;
	try {
		process.kill(pid, "SIGKILL");
	} catch {
		// Already exited.
	}
}

const havePython3 = process.platform !== "win32" && spawnSync("python3", ["-V"]).status === 0;
const describeIf = havePython3 ? describe : describe.skip;

describeIf("forkserver kill/liveness protocol (stub python)", () => {
	let tempDir = "";
	let server: ForkServer | undefined;
	let savedPythonPath: string | undefined;
	const leakedPids: number[] = [];

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "prime-agent-forkserver-proto-"));
		const stubDir = join(tempDir, "stubs");
		mkdirSync(stubDir);
		writeStubModules(stubDir);
		// launchEnv is snapshotted at ForkServer construction, so the template
		// imports the stubs.
		savedPythonPath = process.env.PYTHONPATH;
		process.env.PYTHONPATH = stubDir;
		server = new ForkServer({ python: "python3" });
	});

	afterEach(() => {
		if (savedPythonPath === undefined) delete process.env.PYTHONPATH;
		else process.env.PYTHONPATH = savedPythonPath;
		server?.dispose();
		server = undefined;
		// The stub app ignores parent_handle, so leak-proof the test itself.
		for (const pid of leakedPids.splice(0)) killQuietly(pid);
		rmSync(tempDir, { recursive: true, force: true });
	});

	async function spawnStubKernel(
		target: ForkServer = server!,
		env?: Record<string, string | undefined>,
	): Promise<ForkedKernelHandle> {
		const handle = await target.spawnKernel({ connectionPath: join(tempDir, "conn.json"), env });
		leakedPids.push(handle.pid);
		return handle;
	}

	it("kills its own child through the protocol and observes the reap", async () => {
		const handle = await spawnStubKernel();
		expect(await handle.isAlive()).toBe(true);
		expect(await handle.kill("TERM")).toBe("signaled");
		await vi.waitFor(async () => {
			expect(await handle.isAlive()).toBe(false);
		});
		// OS-level confirmation (test-side observation only, never a signal path).
		await vi.waitFor(() => {
			expect(() => process.kill(handle.pid, 0)).toThrow();
		});
	}, 15_000);

	it("reports already-exited after reap and fails closed on an unknown fork id", async () => {
		const handle = await spawnStubKernel();
		expect(await handle.kill("TERM")).toBe("signaled");
		await vi.waitFor(async () => {
			expect(await handle.kill("TERM")).toBe("already-exited");
		});
		// A fork id the forkserver never issued: nothing may be signaled.
		expect(await server!.killChild(999_999, "TERM")).toBe("unknown-pid");
		expect(await server!.isChildAlive(999_999)).toBe(false);
	}, 15_000);

	it("liveness reflects the reap table on external child death", async () => {
		const handle = await spawnStubKernel();
		expect(await handle.isAlive()).toBe(true);
		// External death (not via the protocol): proves the SIGCHLD reaper drives
		// the registry independently of the kill path.
		process.kill(handle.pid, "SIGTERM");
		await vi.waitFor(async () => {
			expect(await handle.isAlive()).toBe(false);
		});
	}, 15_000);

	it("kill outcomes stay correct while sibling children churn and get reaped", async () => {
		// Regression for the SIGCHLD-in-watcher-thread race: external deaths storm
		// the reaper while kill requests are in flight; every reply must still match
		// the child's true state (no false "signaled" for a freed pid).
		const keep = await Promise.all([spawnStubKernel(), spawnStubKernel(), spawnStubKernel()]);
		const churn = await Promise.all([spawnStubKernel(), spawnStubKernel(), spawnStubKernel()]);
		for (const handle of churn) process.kill(handle.pid, "SIGKILL");
		const outcomes = await Promise.all(keep.map((handle) => handle.kill("TERM")));
		expect(outcomes).toEqual(["signaled", "signaled", "signaled"]);
		for (const handle of churn) {
			await vi.waitFor(async () => {
				expect(await handle.kill("TERM")).toBe("already-exited");
			});
		}
	}, 15_000);

	it("a fast-exiting child never lands alive; its handle stays already-exited across new forks", async () => {
		// STUB_KERNEL_EXIT makes the forked child return from start() immediately,
		// so it can be reaped as early as the OS allows relative to the parent-side
		// registry insertion — the SIGCHLD-blocked fork bookkeeping must still
		// record it under its own id and mark exactly that entry not-alive.
		const fast = await spawnStubKernel(server!, { STUB_KERNEL_EXIT: "1" });
		await vi.waitFor(async () => {
			expect(await fast.isAlive()).toBe(false);
		});
		expect(await fast.kill("TERM")).toBe("already-exited");
		// Id-keying invariant: a later fork gets a fresh id (even if the OS reuses
		// the pid, which we can't force), and the old handle's answers don't change.
		const next = await spawnStubKernel();
		expect(await next.isAlive()).toBe(true);
		expect(await fast.isAlive()).toBe(false);
		expect(await fast.kill("TERM")).toBe("already-exited");
		expect(await next.kill("TERM")).toBe("signaled");
	}, 15_000);

	it("evicted registry entries fail closed (unknown-pid/false), recent ones stay answerable", async () => {
		// A tiny history bound (argv[2] to the script) makes FIFO eviction reachable.
		const bounded = new ForkServer({ python: "python3", historyBound: 2 });
		try {
			const oldest = await spawnStubKernel(bounded, { STUB_KERNEL_EXIT: "1" });
			await vi.waitFor(async () => {
				expect(await oldest.kill("TERM")).toBe("already-exited");
			});
			const middle = await spawnStubKernel(bounded, { STUB_KERNEL_EXIT: "1" });
			const newest = await spawnStubKernel(bounded, { STUB_KERNEL_EXIT: "1" });
			// Three entries against a bound of 2: the oldest id has been evicted.
			expect(await oldest.kill("TERM")).toBe("unknown-pid");
			expect(await oldest.isAlive()).toBe(false);
			for (const handle of [middle, newest]) {
				await vi.waitFor(async () => {
					expect(await handle.kill("TERM")).toBe("already-exited");
				});
				expect(await handle.isAlive()).toBe(false);
			}
		} finally {
			bounded.dispose();
		}
	}, 15_000);

	it("keeps live entries answerable past the history bound and evicts only exited ones", async () => {
		// A live child must never be evicted: an evicted-live entry would read
		// dead to the liveness monitor and be unroutable for kill — the exact
		// orphan leak this forkserver exists to prevent.
		const bounded = new ForkServer({ python: "python3", historyBound: 2 });
		try {
			const oldest = await spawnStubKernel(bounded);
			expect(await oldest.isAlive()).toBe(true);
			const middle = await spawnStubKernel(bounded);
			const newest = await spawnStubKernel(bounded);
			// Three live entries against a bound of 2: none may be evicted.
			expect(await oldest.isAlive()).toBe(true);
			expect(await middle.isAlive()).toBe(true);
			expect(await newest.isAlive()).toBe(true);
			// Once dead entries exist, the next fork sweeps them out instead.
			expect(await oldest.kill("TERM")).toBe("signaled");
			expect(await middle.kill("TERM")).toBe("signaled");
			await vi.waitFor(async () => {
				expect(await oldest.isAlive()).toBe(false);
				expect(await middle.isAlive()).toBe(false);
			});
			const extra = await spawnStubKernel(bounded);
			// Bound 2 with two dead entries: both are evicted, the live ones stay.
			expect(await oldest.kill("TERM")).toBe("unknown-pid");
			expect(await middle.kill("TERM")).toBe("unknown-pid");
			expect(await newest.isAlive()).toBe(true);
			expect(await extra.isAlive()).toBe(true);
			expect(await newest.kill("TERM")).toBe("signaled");
			expect(await extra.kill("TERM")).toBe("signaled");
		} finally {
			bounded.dispose();
		}
	}, 15_000);

	it("handle kill/isAlive reject with ForkServerUnavailable when the server is dead", async () => {
		const handle = await spawnStubKernel();
		server!.dispose();
		await expect(handle.kill("TERM")).rejects.toBeInstanceOf(ForkServerUnavailable);
		await expect(handle.isAlive()).rejects.toBeInstanceOf(ForkServerUnavailable);
	}, 15_000);

	describe("forkserver orphan journal", () => {
		let journalPath = "";
		const savedJournal = process.env[ORPHAN_PROCESS_JOURNAL_ENV];

		interface JournalRecord {
			pid: number;
			active: boolean;
		}

		function readJournal(): JournalRecord[] {
			if (!existsSync(journalPath)) return [];
			return readFileSync(journalPath, "utf8")
				.split("\n")
				.filter(Boolean)
				.map((line) => JSON.parse(line) as JournalRecord);
		}

		beforeEach(() => {
			journalPath = join(tempDir, "orphans.jsonl");
			process.env[ORPHAN_PROCESS_JOURNAL_ENV] = journalPath;
		});

		afterEach(() => {
			if (savedJournal === undefined) delete process.env[ORPHAN_PROCESS_JOURNAL_ENV];
			else process.env[ORPHAN_PROCESS_JOURNAL_ENV] = savedJournal;
		});

		it("disposing a live forkserver delivers the kill and writes inactive", async () => {
			await spawnStubKernel();
			const records = readJournal();
			expect(records).toHaveLength(1);
			expect(records[0]).toMatchObject({ active: true });
			server!.dispose();
			const after = readJournal();
			expect(after).toHaveLength(2);
			expect(after[1]).toMatchObject({ pid: records[0]!.pid, active: false });
		}, 15_000);

		it("a forkserver exit observed by the handle writes inactive", async () => {
			await spawnStubKernel();
			const forkserverPid = readJournal()[0]!.pid;
			process.kill(forkserverPid, "SIGKILL");
			// The exit event drives markDead → dispose with the exit already observed.
			await vi.waitFor(() => {
				const records = readJournal();
				expect(records).toHaveLength(2);
				expect(records[1]).toMatchObject({ pid: forkserverPid, active: false });
			});
		}, 15_000);

		it("a never-started forkserver writes no journal records on dispose", () => {
			const idle = new ForkServer({ python: "python3" });
			idle.dispose();
			expect(readJournal()).toHaveLength(0);
		});

		it("an unconfirmed kill with no observed exit leaves no inactive record", () => {
			const unconfirmed = new ForkServer({ python: "python3" });
			const internals = unconfirmed as unknown as {
				proc?: { pid?: number; exitCode: number | null; signalCode: string | null; kill(): boolean };
			};
			internals.proc = { pid: 424242, exitCode: null, signalCode: null, kill: () => false };
			unconfirmed.dispose();
			expect(readJournal().some((r) => r.pid === 424242)).toBe(false);
		});
	});
});

describeIf("forkserver authoritative parent exit observation", () => {
	let tempDir = "";

	interface CapturedObservation extends Record<string, unknown> {
		type: string;
	}

	interface ForkServerInternals {
		proc?: import("node:child_process").ChildProcess;
		socketDir?: string;
		pending: Map<number, unknown>;
		workerProcessStartId: string | undefined;
		emitForkServerParentWaitObservation(
			code: number | null,
			signal: NodeJS.Signals | null,
			forkserverPid: number | undefined,
			forkserverProcessStartId: string | undefined,
		): void;
	}

	function writeFakeInterpreter(name: string, lines: string[]): string {
		const executable = join(tempDir, name);
		writeFileSync(executable, `${lines.join("\n")}\n`);
		chmodSync(executable, 0o755);
		return executable;
	}

	function expectCapturedProcessStartId(
		observation: CapturedObservation,
		field: string,
		expected: string | undefined,
	): void {
		if (expected === undefined) expect(observation).not.toHaveProperty(field);
		else expect(observation).toHaveProperty(field, expected);
	}

	function captureSanitizedObservations(): CapturedObservation[] {
		const observations: CapturedObservation[] = [];
		incidentRecorder.emitIncidentDerived.mockReset();
		incidentRecorder.emitIncidentDerived.mockImplementation((_source, type, fields) => {
			observations.push({ type, ...sanitizeIncidentCausalFields(fields) });
			return { accepted: true, occurrenceId: "forkserver-exit" };
		});
		return observations;
	}

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "prime-agent-forkserver-exit-"));
		incidentRecorder.emitIncidentDerived.mockReset();
		incidentRecorder.emitIncidentDerived.mockReturnValue({
			accepted: true,
			occurrenceId: "forkserver-exit",
		});
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
		tempDir = "";
	});

	it("offers exact natural exit 23 before the existing same-stack teardown", async () => {
		const observations: CapturedObservation[] = [];
		const gatePath = join(tempDir, "exit-23.go");
		const target = new ForkServer({
			python: writeFakeInterpreter("exit-23", [
				"#!/bin/sh",
				`while [ ! -f ${JSON.stringify(gatePath)} ]; do sleep 0.01; done`,
				"exit 23",
			]),
		});
		const internals = target as unknown as ForkServerInternals;
		const dispose = vi.spyOn(target, "dispose");
		let readinessRejected = false;
		incidentRecorder.emitIncidentDerived.mockImplementation((_source, type, fields) => {
			if (type === "process_terminal_disposition") {
				expect(target.isDead).toBe(false);
				expect(readinessRejected).toBe(false);
				expect(dispose).not.toHaveBeenCalled();
				observations.push({ type, ...sanitizeIncidentCausalFields(fields) });
			}
			return { accepted: true, occurrenceId: "exit-23" };
		});

		try {
			const readiness = target.spawnKernel({ connectionPath: join(tempDir, "unused-exit-23.json") });
			void readiness.catch(() => {
				readinessRejected = true;
			});
			await vi.waitFor(() => expect(internals.proc?.pid).toBeTypeOf("number"));
			const expectedForkserverStartId = getProcessStartId(internals.proc!.pid!);
			const expectedWorkerStartId = getProcessStartId(process.pid);
			writeFileSync(gatePath, "go");
			await expect(readiness).rejects.toThrow(/forkserver died/);
			await vi.waitFor(() => expect(observations).toHaveLength(1));

			expect(observations[0]).toMatchObject({
				type: "process_terminal_disposition",
				classification: "authoritative_parent_wait",
				origin: "node_callback",
				role: "forkserver",
				code: 23,
				signal: null,
				disposition: "exited",
				forkserverPid: expect.any(Number),
				workerPid: process.pid,
			});
			expectCapturedProcessStartId(observations[0]!, "forkserverProcessStartId", expectedForkserverStartId);
			expectCapturedProcessStartId(observations[0]!, "workerProcessStartId", expectedWorkerStartId);
			expect(observations[0]).not.toHaveProperty("rawWaitWord");
			expect(observations[0]).not.toHaveProperty("coreDumped");
			for (const forbidden of [
				"sessionId",
				"activeSessionId",
				"toolCallId",
				"kernelPid",
				"forkRequestId",
				"cwd",
				"env",
				"argv",
				"python",
				"stderr",
				"application",
				"data",
			]) {
				expect(observations[0]).not.toHaveProperty(forbidden);
			}
			expect(target.isDead).toBe(true);
			expect(internals.pending.size).toBe(0);
			expect(internals.socketDir).toBeUndefined();
			target.dispose();
			expect(observations).toHaveLength(1);
		} finally {
			target.dispose();
			const proc = internals.proc;
			if (proc && proc.exitCode === null && proc.signalCode === null) {
				await new Promise<void>((resolve) => proc.once("exit", () => resolve()));
			}
		}
	});

	it("preserves the exact SIGTERM callback pair through the real sanitizer", async () => {
		const observations = captureSanitizedObservations();
		const gatePath = join(tempDir, "signal-term.go");
		const target = new ForkServer({
			python: writeFakeInterpreter("signal-term", [
				"#!/bin/sh",
				`while [ ! -f ${JSON.stringify(gatePath)} ]; do sleep 0.01; done`,
				"kill -TERM $$",
			]),
		});
		const internals = target as unknown as ForkServerInternals;
		try {
			const readiness = target.spawnKernel({ connectionPath: join(tempDir, "unused-term.json") });
			void readiness.catch(() => {});
			await vi.waitFor(() => expect(internals.proc?.pid).toBeTypeOf("number"));
			const expectedForkserverStartId = getProcessStartId(internals.proc!.pid!);
			const expectedWorkerStartId = getProcessStartId(process.pid);
			writeFileSync(gatePath, "go");
			await expect(readiness).rejects.toThrow(/forkserver died/);
			await vi.waitFor(() => expect(observations).toHaveLength(1));
			expect(observations[0]).toMatchObject({
				type: "process_terminal_disposition",
				classification: "authoritative_parent_wait",
				origin: "node_callback",
				role: "forkserver",
				code: null,
				signal: "SIGTERM",
				disposition: "signaled",
				forkserverPid: expect.any(Number),
				workerPid: process.pid,
			});
			expectCapturedProcessStartId(observations[0]!, "forkserverProcessStartId", expectedForkserverStartId);
			expectCapturedProcessStartId(observations[0]!, "workerProcessStartId", expectedWorkerStartId);
			expect(observations[0]).not.toHaveProperty("rawWaitWord");
			expect(observations[0]).not.toHaveProperty("coreDumped");
		} finally {
			target.dispose();
			const proc = internals.proc;
			if (proc && proc.exitCode === null && proc.signalCode === null) {
				await new Promise<void>((resolve) => proc.once("exit", () => resolve()));
			}
		}
	});

	it("types an ambiguous callback pair as invalid without fabricating terminal evidence or identity", () => {
		const observations = captureSanitizedObservations();
		const target = new ForkServer({ python: "unused" });
		const internals = target as unknown as ForkServerInternals;
		internals.workerProcessStartId = undefined;

		internals.emitForkServerParentWaitObservation(0, "SIGTERM", 424_242, undefined);

		expect(observations).toEqual([
			{
				type: "process_terminal_observation_invalid",
				classification: "authoritative_parent_wait_invalid",
				origin: "node_callback",
				role: "forkserver",
				forkserverPid: 424_242,
				code: 0,
				signal: "SIGTERM",
				reason: "ambiguous_pair",
				workerPid: process.pid,
			},
		]);
		expect(observations[0]).not.toHaveProperty("forkserverProcessStartId");
		expect(observations[0]).not.toHaveProperty("workerProcessStartId");
		expect(observations[0]).not.toHaveProperty("disposition");
		expect(observations[0]).not.toHaveProperty("rawWaitWord");
		expect(observations[0]).not.toHaveProperty("coreDumped");
		expect(observations.filter((event) => event.type === "process_terminal_disposition")).toHaveLength(0);
		target.dispose();
	});

	it.each([
		["accepted", { accepted: true, occurrenceId: "accepted" }],
		["not-configured", { accepted: false, occurrenceId: "missing", reason: "capture_not_configured" }],
		["full", { accepted: false, occurrenceId: "full", reason: "bounded_queue_full" }],
		["serialization-rejected", { accepted: false, occurrenceId: "serialization", reason: "capture_failed_open" }],
		["rejected", { accepted: false, occurrenceId: "rejected", reason: "non_causal_event" }],
	] as const)(
		"keeps forkserver exit lifecycle and journal outcomes unchanged when capture is %s",
		async (mode, result) => {
			const journalPath = join(tempDir, `forkserver-${mode}.jsonl`);
			const savedJournal = process.env[ORPHAN_PROCESS_JOURNAL_ENV];
			process.env[ORPHAN_PROCESS_JOURNAL_ENV] = journalPath;
			const observedTypes: string[] = [];
			incidentRecorder.emitIncidentDerived.mockReset();
			incidentRecorder.emitIncidentDerived.mockImplementation((_source, type) => {
				observedTypes.push(type);
				return result;
			});
			const target = new ForkServer({
				python: writeFakeInterpreter(`exit-${mode}`, ["#!/bin/sh", "sleep 0.15", "exit 23"]),
			});
			const internals = target as unknown as ForkServerInternals;
			try {
				const readiness = target.spawnKernel({ connectionPath: join(tempDir, `unused-${mode}.json`) });
				void readiness.catch(() => {});
				await vi.waitFor(() => expect(internals.proc).toBeDefined());
				const kill = vi.spyOn(internals.proc!, "kill");
				await expect(readiness).rejects.toThrow(/forkserver died/);
				await vi.waitFor(() => expect(observedTypes).toEqual(["process_terminal_disposition"]));
				expect(target.isDead).toBe(true);
				expect(internals.pending.size).toBe(0);
				expect(internals.socketDir).toBeUndefined();
				expect(kill).toHaveBeenCalledTimes(1);
				expect(kill).toHaveBeenCalledWith("SIGTERM");
				const journalBeforeIdempotentDispose = readFileSync(journalPath, "utf8");
				const journalRecords = journalBeforeIdempotentDispose
					.trim()
					.split("\n")
					.map((line) => JSON.parse(line) as { pid: number; active: boolean });
				expect(journalRecords).toEqual([
					expect.objectContaining({ pid: internals.proc!.pid, active: true }),
					expect.objectContaining({ pid: internals.proc!.pid, active: false }),
				]);
				target.dispose();
				expect(readFileSync(journalPath, "utf8")).toBe(journalBeforeIdempotentDispose);
				expect(observedTypes).toEqual(["process_terminal_disposition"]);
			} finally {
				target.dispose();
				if (savedJournal === undefined) delete process.env[ORPHAN_PROCESS_JOURNAL_ENV];
				else process.env[ORPHAN_PROCESS_JOURNAL_ENV] = savedJournal;
			}
		},
		15_000,
	);

	it("contains recorder throws and still completes the same exit-driven lifecycle", async () => {
		incidentRecorder.emitIncidentDerived.mockReset();
		incidentRecorder.emitIncidentDerived.mockImplementation(() => {
			throw new Error("synthetic forkserver recorder throw");
		});
		const target = new ForkServer({
			python: writeFakeInterpreter("exit-recorder-throw", ["#!/bin/sh", "sleep 0.1", "exit 23"]),
		});
		const internals = target as unknown as ForkServerInternals;
		await expect(target.spawnKernel({ connectionPath: join(tempDir, "unused-throw.json") })).rejects.toThrow(
			/forkserver died/,
		);
		expect(target.isDead).toBe(true);
		expect(internals.pending.size).toBe(0);
		expect(internals.socketDir).toBeUndefined();
		expect(incidentRecorder.emitIncidentDerived).toHaveBeenCalledTimes(1);
		target.dispose();
	});

	it("still records the one later real exit callback after an earlier error marked the server dead", async () => {
		const observations = captureSanitizedObservations();
		const target = new ForkServer({
			python: writeFakeInterpreter("error-then-exit", ["#!/bin/sh", "exec sleep 60"]),
		});
		const internals = target as unknown as ForkServerInternals;
		const readiness = target.spawnKernel({ connectionPath: join(tempDir, "unused-error.json") });
		void readiness.catch(() => {});
		await vi.waitFor(() => expect(internals.proc).toBeDefined());

		internals.proc!.emit("error", new Error("synthetic earlier child-process error"));
		await expect(readiness).rejects.toThrow(/forkserver died/);
		expect(target.isDead).toBe(true);
		await vi.waitFor(() => expect(observations).toHaveLength(1));
		expect(observations[0]).toMatchObject({
			type: "process_terminal_disposition",
			classification: "authoritative_parent_wait",
			origin: "node_callback",
			role: "forkserver",
			code: null,
			signal: "SIGTERM",
			disposition: "signaled",
		});
		await new Promise((resolve) => setTimeout(resolve, 25));
		expect(observations).toHaveLength(1);
		target.dispose();
	}, 15_000);

	it("has no source consumer that prefix-matches invalid observations as dispositions", () => {
		function readTree(dir: string): string {
			let source = "";
			for (const entry of readdirSync(dir, { withFileTypes: true })) {
				const path = join(dir, entry.name);
				if (entry.isDirectory()) source += readTree(path);
				else if (entry.isFile() && /\.[cm]?[jt]sx?$/.test(entry.name)) source += readFileSync(path, "utf8");
			}
			return source;
		}
		const source = readTree(join(import.meta.dirname, "..", "src"));
		expect(source).not.toMatch(/(?:startsWith|includes)\(\s*["'`]process_terminal_/);
		expect(source).not.toMatch(/\/\^?process_terminal_[^/]*\//);
		expect(source).not.toMatch(/new RegExp\(\s*["'`]\^?process_terminal_/);
	});
});

function resolveKernelPython(): string | null {
	const candidates = [
		process.env.PRIME_AGENT_KERNEL_PYTHON,
		join(homedir(), ".prime", "agent", "kernel-venv", "bin", "python"),
	].filter((p): p is string => Boolean(p));
	for (const python of candidates) {
		if (!existsSync(python)) continue;
		const check = spawnSync(python, ["-c", "import ipykernel"], { encoding: "utf8" });
		if (check.status === 0) return python;
	}
	return null;
}

const kernelPython = resolveKernelPython();
// Real ipykernel fork round-trip is linux-only: on darwin the forked child dies
// immediately (fork-without-exec is unsafe there), matching isForkServerEnabled.
const describeIfRealKernel = process.platform === "linux" && kernelPython ? describe : describe.skip;

describeIfRealKernel("forkserver kill/liveness protocol (real kernel)", { tags: ["kernel-heavy"] }, () => {
	it("forks a real ipykernel, resolves ports, kills it via the protocol", async () => {
		const dir = mkdtempSync(join(tmpdir(), "prime-agent-forkserver-real-"));
		const connectionPath = join(dir, "connection.json");
		writeFileSync(
			connectionPath,
			JSON.stringify({
				ip: "127.0.0.1",
				transport: "tcp",
				shell_port: 0,
				iopub_port: 0,
				stdin_port: 0,
				control_port: 0,
				hb_port: 0,
				signature_scheme: "hmac-sha256",
				key: "test-key",
				kernel_name: "python3",
			}),
			{ mode: 0o600 },
		);
		const server = new ForkServer({ python: kernelPython! });
		let pid: number | undefined;
		try {
			const handle = await server.spawnKernel({ connectionPath });
			pid = handle.pid;
			await vi.waitFor(
				() => {
					const info = JSON.parse(readFileSync(connectionPath, "utf8")) as { shell_port: number };
					expect(info.shell_port).toBeGreaterThan(0);
				},
				{ timeout: 20_000, interval: 250 },
			);
			expect(await handle.isAlive()).toBe(true);
			expect(await handle.kill("TERM")).toBe("signaled");
			await vi.waitFor(
				async () => {
					expect(await handle.isAlive()).toBe(false);
				},
				{ timeout: 20_000, interval: 250 },
			);
		} finally {
			server.dispose();
			killQuietly(pid);
			rmSync(dir, { recursive: true, force: true });
		}
	}, 60_000);
});
