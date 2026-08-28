import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import { DaemonWorkerClient } from "../src/modes/daemon/daemon-worker-client.js";
import { DAEMON_WORKER_ACTIVE_SESSION_ID_ENV } from "../src/modes/daemon/daemon-worker-protocol.js";
import {
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
	INCIDENT_RECORDER_WORKER_ID_ENV,
	inspectIncidentRecorderRuns,
	type RecordedProcessResult,
	recordIncidentRecorderCausalEvent,
	recordSupervisorProcess,
	shouldRecordSupervisorLaunch,
} from "../src/modes/daemon/incident-recorder.js";
import {
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	runIncidentRetentionPass,
} from "../src/modes/daemon/incident-recorder-retention.js";

const roots: string[] = [];
const livePids = new Map<number, string>();
const pendingRecords = new Set<Promise<RecordedProcessResult>>();

function signalFixture(pid: number, signal: NodeJS.Signals | 0): void {
	const expectedStartId = livePids.get(pid);
	if (!expectedStartId || getProcessStartId(pid) !== expectedStartId) {
		throw new Error(`Refusing to signal fixture without matching process identity: ${pid}`);
	}
	process.kill(pid, signal);
}

afterEach(async () => {
	for (const [pid, expectedStartId] of livePids) {
		try {
			if (getProcessStartId(pid) === expectedStartId) process.kill(pid, "SIGKILL");
		} catch {}
	}
	livePids.clear();
	await Promise.allSettled([...pendingRecords]);
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(source: string): { root: string; agentDir: string; socketPath: string; script: string } {
	const root = mkdtempSync(process.platform === "linux" ? "/tmp/pa-ir-" : join(tmpdir(), "pa-ir-"));
	roots.push(root);
	const socketPath = join(root, "isolated.sock");
	if (process.platform === "linux" && Buffer.byteLength(socketPath) >= 108)
		throw new Error(`isolated Unix socket path exceeds sun_path: ${socketPath}`);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { mode: 0o700 });
	const script = join(root, "fault.cjs");
	writeFileSync(script, source, { mode: 0o600 });
	return { root, agentDir, socketPath, script };
}

function record(target: ReturnType<typeof fixture>): Promise<RecordedProcessResult> {
	const pending = recordSupervisorProcess({
		agentDir: target.agentDir,
		socketPath: target.socketPath,
		launch: { command: process.execPath, args: [target.script] },
		environment: {},
		cwd: target.root,
	});
	pendingRecords.add(pending);
	pending.then(
		() => pendingRecords.delete(pending),
		() => pendingRecords.delete(pending),
	);
	return pending;
}

function onlyRunDir(agentDir: string): string {
	const runsRoot = join(agentDir, "incident-recorder", "runs");
	const runName = readdirSync(runsRoot)[0];
	if (!runName) throw new Error("isolated fixture has no recorder run");
	return join(runsRoot, runName);
}

function recordedStructuredEvents(runDir: string, fileName = "timeline.jsonl"): Array<Record<string, unknown>> {
	const timeline = join(runDir, fileName);
	if (!existsSync(timeline)) return [];
	return readFileSync(timeline, "utf8")
		.split("\n")
		.filter(Boolean)
		.flatMap((line) => {
			try {
				const event = JSON.parse(line) as unknown;
				return event && typeof event === "object" && !Array.isArray(event)
					? [event as Record<string, unknown>]
					: [];
			} catch {
				return [];
			}
		});
}

function recordedStructuredTypes(runDir: string): string[] {
	return recordedStructuredEvents(runDir).flatMap((event) => (typeof event.type === "string" ? [event.type] : []));
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
				if (identity.processStartId && getProcessStartId(identity.pid) === identity.processStartId) {
					livePids.set(identity.pid, identity.processStartId);
					return identity.pid;
				}
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

describe("incident recorder isolated fault evidence", () => {
	it("wraps every non-worker daemon launch once", () => {
		const daemonArgs = ["--mode", "daemon", "--daemon-socket", "/tmp/isolated.sock"];
		expect(shouldRecordSupervisorLaunch(daemonArgs, {}, false)).toBe(true);
		expect(shouldRecordSupervisorLaunch(daemonArgs, { [INCIDENT_RECORDER_CHILD_ENV]: "1" }, false)).toBe(false);
		expect(shouldRecordSupervisorLaunch(daemonArgs, {}, true)).toBe(false);
		expect(shouldRecordSupervisorLaunch([...daemonArgs, "--incident-recorder-service"], {}, false)).toBe(false);
		expect(shouldRecordSupervisorLaunch(daemonArgs, { [INCIDENT_RECORDER_SERVICE_ENV]: "1" }, false)).toBe(false);
		expect(shouldRecordSupervisorLaunch(["--mode", "json"], {}, false)).toBe(false);
	});

	it("records only a causal environment allowlist", async () => {
		const target = fixture("process.exit(0);");
		const result = await recordSupervisorProcess({
			agentDir: target.agentDir,
			socketPath: target.socketPath,
			launch: { command: process.execPath, args: [target.script, "--token", "must-not-be-recorded"] },
			environment: {
				SECRET_ACCESS_TOKEN: "must-not-be-recorded",
				INVOCATION_ID: "a".repeat(32),
				WSL_DISTRO_NAME: "Ubuntu",
			},
			cwd: target.root,
		});
		const launchText = readFileSync(join(result.runDir, "launch.json"), "utf8");
		expect(launchText).not.toContain("must-not-be-recorded");
		expect(launchText).not.toContain("SECRET_ACCESS_TOKEN");
		expect(JSON.parse(launchText)).toMatchObject({
			environment: { INVOCATION_ID: "a".repeat(32), WSL_DISTRO_NAME: "Ubuntu" },
			commandSummary: { redactedValueCount: 2 },
		});
	});

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
		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: Date.now() + INCIDENT_DIAGNOSTIC_RETENTION_MS + 1 });
		expect(existsSync(runDir)).toBe(false);
	});

	it("classifies an uncaught exception and preserves its Node report", async () => {
		const result = await record(fixture('throw new Error("isolated uncaught fault");'));
		expect(result).toMatchObject({ code: 1, signal: null, classification: "uncaught_exception" });
		expect(readdirSync(join(result.runDir, "raw-reports")).some((name) => name.endsWith(".json"))).toBe(true);
	});

	it("keeps repeated worker fatal summaries bounded in the supervisor recorder run", async () => {
		const target = fixture("");
		const workerScript = join(target.root, "worker-fault.mts");
		const flagsPath = join(target.root, "worker-flags.json");
		const workerSocketPath = join(target.root, "worker.sock");
		const recorderModule = new URL("../src/modes/daemon/daemon-mode.ts", import.meta.url).href;
		const workerReportAttempts = 80;
		writeFileSync(
			workerScript,
			`import { writeFileSync } from "node:fs";
import { runDaemonMode } from ${JSON.stringify(recorderModule)};
const running = runDaemonMode({
  socketPath: ${JSON.stringify(workerSocketPath)},
  defaultSessionConfig: { agentDir: ${JSON.stringify(target.agentDir)} },
  createRuntime: async () => { throw new Error("fixture runtime must stay unused"); },
  worker: { authenticationToken: "fixture-worker-token" },
});
setTimeout(() => {
  writeFileSync(${JSON.stringify(flagsPath)}, JSON.stringify({
    execArgv: process.execArgv,
    nodeReportDirectory: process.env.NODE_REPORT_DIRECTORY,
    nodeReportOnFatalError: process.report?.reportOnFatalError,
    nodeReportOnUncaughtException: process.report?.reportOnUncaughtException,
    pid: process.pid,
    runDir: process.env.PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_RUN_DIR,
  }));
  for (let attempt = 0; attempt < ${workerReportAttempts}; attempt += 1) {
    process.emit("uncaughtExceptionMonitor", new Error("isolated worker uncaught fault " + attempt), "uncaughtException");
  }
  setTimeout(() => { throw new Error("isolated final worker uncaught fault"); }, 250);
}, 100);
await running;
`,
			{ mode: 0o600 },
		);
		writeFileSync(
			target.script,
			`const { spawn } = require("node:child_process");
const child = spawn(process.execPath, [...process.execArgv, ${JSON.stringify(workerScript)}], {
  env: {
    ...process.env,
    ${JSON.stringify(INCIDENT_RECORDER_WORKER_ID_ENV)}: "fixture-worker-1",
    ${JSON.stringify(DAEMON_WORKER_ACTIVE_SESSION_ID_ENV)}: "fixture-active-session-1",
  },
  stdio: "ignore",
});
child.once("error", () => process.exit(2));
child.once("close", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 1);
});
`,
			{ mode: 0o600 },
		);
		const tsxImport = createRequire(import.meta.url).resolve("tsx");
		const result = await recordSupervisorProcess({
			agentDir: target.agentDir,
			socketPath: target.socketPath,
			launch: { command: process.execPath, args: ["--import", tsxImport, target.script] },
			environment: {},
			cwd: target.root,
		});
		const flags = JSON.parse(readFileSync(flagsPath, "utf8")) as {
			execArgv: string[];
			nodeReportDirectory: string;
			nodeReportOnFatalError: boolean;
			nodeReportOnUncaughtException: boolean;
			pid: number;
			runDir: string;
		};
		expect(flags.runDir).toBe(result.runDir);
		expect(flags.nodeReportDirectory).toBe(join(result.runDir, "raw-reports"));
		expect(flags.execArgv).toEqual(expect.arrayContaining(["--report-on-fatalerror", "--report-uncaught-exception"]));
		expect(flags.execArgv).toContain(`--report-directory=${join(result.runDir, "raw-reports")}`);
		expect(flags.nodeReportOnFatalError).toBe(true);
		expect(flags.nodeReportOnUncaughtException).toBe(false);
		expect(readdirSync(join(result.runDir, "raw-reports")).filter((name) => name.endsWith(".json"))).toEqual([]);

		const supervisorTimelineNames = readdirSync(result.runDir).filter((name) =>
			/^supervisor-timeline(?:\.previous)?\.jsonl$/.test(name),
		);
		expect(supervisorTimelineNames.length).toBeLessThanOrEqual(2);
		for (const name of supervisorTimelineNames) {
			expect(readFileSync(join(result.runDir, name)).length).toBeLessThanOrEqual(1024 * 1024);
		}
		const supervisorEvents = ["supervisor-timeline.previous.jsonl", "supervisor-timeline.jsonl"].flatMap((name) =>
			recordedStructuredEvents(result.runDir, name),
		);
		const workerStarted = supervisorEvents.find((event) => event.type === "worker_started");
		expect(workerStarted).toMatchObject({
			role: "worker",
			workerId: "fixture-worker-1",
			activeSessionId: "fixture-active-session-1",
			pid: flags.pid,
			producerPid: flags.pid,
		});
		expect(workerStarted?.producerProcessStartId).toEqual(expect.any(String));
		const workerReports = supervisorEvents.filter((event) => event.type === "worker_fatal_report");
		expect(workerReports.length).toBeGreaterThan(0);
		expect(workerReports.length).toBeLessThanOrEqual(64);
		expect(workerReports[0]).toMatchObject({
			role: "worker",
			workerId: "fixture-worker-1",
			activeSessionId: "fixture-active-session-1",
			pid: flags.pid,
			report: { header: { processId: flags.pid } },
			exception: { name: "Error" },
		});
		const gapEvents = recordedStructuredEvents(result.runDir).filter(
			(event) => event.type === "worker_fatal_evidence_gap",
		);
		expect(gapEvents).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					role: "worker",
					workerId: "fixture-worker-1",
					activeSessionId: "fixture-active-session-1",
					phase: "fatal_report_summary",
					reason: "bounded_queue_full",
				}),
			]),
		);
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

	it("detects a live event-loop heartbeat stall from a structured causal heartbeat without recovering the process", async () => {
		const target = fixture("Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);");
		const pending = record(target);
		const pid = await waitForPid(target.agentDir);
		recordIncidentRecorderCausalEvent(onlyRunDir(target.agentDir), "supervisor_heartbeat", { socketExists: false });
		await new Promise((resolve) => setTimeout(resolve, 100));
		const incidents = await inspectIncidentRecorderRuns(target.agentDir, Date.now() + 20_000);
		expect(incidents).toEqual([]);
		expect(recordedStructuredTypes(onlyRunDir(target.agentDir))).toContain("heartbeat_stalled");
		expect(() => signalFixture(pid, 0)).not.toThrow();
		signalFixture(pid, "SIGKILL");
		const result = await pending;
		livePids.delete(pid);
		expect(result.classification).toBe("signal_sigkill");
	});

	it("detects loss of an isolated live supervisor socket from structured causal state", async () => {
		const target = fixture(
			'const fs=require("node:fs");const net=require("node:net");const socket=process.env.PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_SOCKET;const server=net.createServer();server.listen(socket,()=>{try{fs.unlinkSync(socket)}catch(error){if(error?.code!=="ENOENT")throw error}});setInterval(()=>{},1000);',
		);
		const pending = record(target);
		const pid = await waitForPid(target.agentDir);
		recordIncidentRecorderCausalEvent(onlyRunDir(target.agentDir), "supervisor_heartbeat", { socketExists: true });
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(await inspectIncidentRecorderRuns(target.agentDir)).toEqual([]);
		expect(recordedStructuredTypes(onlyRunDir(target.agentDir))).toContain("socket_lost");
		expect(() => signalFixture(pid, 0)).not.toThrow();
		signalFixture(pid, "SIGKILL");
		const result = await pending;
		livePids.delete(pid);
		expect(result.classification).toBe("signal_sigkill");
	});

	it("records a real isolated worker request timeout", async () => {
		const target = fixture("process.exit(0)");
		const workerSocket = join(target.root, "worker.sock");
		const server = createServer((socket) => socket.resume());
		await new Promise<void>((resolveListen, rejectListen) => {
			server.once("error", rejectListen);
			server.listen(workerSocket, resolveListen);
		});
		const previousRunDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
		process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = target.root;
		const client = new DaemonWorkerClient(workerSocket);
		try {
			await client.connect();
			const started = Date.now();
			await expect(client.request({ type: "list" }, 25)).rejects.toThrow("Timed out");
			expect(Date.now() - started).toBeLessThan(1_000);
		} finally {
			client.close();
			await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
			if (previousRunDir === undefined) delete process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
			else process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = previousRunDir;
		}
	});

	it("finalizes a live worker response hang from a structured timeout event without recovering the process", async () => {
		const target = fixture("setInterval(()=>{},1000);");
		const pending = record(target);
		const pid = await waitForPid(target.agentDir);
		recordIncidentRecorderCausalEvent(onlyRunDir(target.agentDir), "worker_request_end", {
			requestType: "get_state",
			durationMs: 25,
			outcome: "timeout",
		});
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(await inspectIncidentRecorderRuns(target.agentDir)).toEqual([]);
		expect(recordedStructuredTypes(onlyRunDir(target.agentDir))).toContain("worker_hang_detected");
		expect(() => signalFixture(pid, 0)).not.toThrow();
		signalFixture(pid, "SIGKILL");
		const result = await pending;
		livePids.delete(pid);
		expect(result.classification).toBe("signal_sigkill");
	});
});
