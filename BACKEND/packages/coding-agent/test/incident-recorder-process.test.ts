import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	closeSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import { DaemonWorkerClient } from "../src/modes/daemon/daemon-worker-client.js";
import {
	INCIDENT_RECORDER_CHILD_ENV,
	INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	INCIDENT_RECORDER_SERVICE_ENV,
  inspectIncidentRecorderRuns,
  finalizeIncidentRecorderRun,
  isIncidentRecorderExcludedApplicationPath,
	type RecordedProcessResult,
	recordSupervisorProcess,
	shouldRecordSupervisorLaunch,
} from "../src/modes/daemon/incident-recorder.js";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
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

async function initializeStorageAccounting(compactor: IncidentRecorderCompactor): Promise<void> {
	const controller = new AbortController();
	await compactor.initializeStorageAccounting(controller.signal);
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
		const secretPath = join(
			descriptorSource,
			`worker-1${INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX}`,
		);
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

	it.skip("detects a live event-loop heartbeat stall without recovering the process (legacy timeline injector; replace with journal-backed service fixture)", async () => {
		const target = fixture(
			`${appendEventScript({ type: "supervisor_heartbeat", socketExists: false })}Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);`,
		);
		const pending = record(target);
		const pid = await waitForPid(target.agentDir);
		await new Promise((resolve) => setTimeout(resolve, 100));
		const incidents = await inspectIncidentRecorderRuns(target.agentDir, Date.now() + 20_000);
		expect(incidents).toHaveLength(1);
		expect(() => signalFixture(pid, 0)).not.toThrow();
		signalFixture(pid, "SIGKILL");
		const result = await pending;
		livePids.delete(pid);
		expect(result.classification).toBe("event_loop_hang");
	});

	it.skip("detects loss of an isolated live supervisor socket (legacy timeline injector; replace with journal-backed service fixture)", async () => {
		const socketEvidence = appendEventScript({ type: "supervisor_heartbeat", socketExists: true });
		const target = fixture(
			`const fs=require("node:fs");const net=require("node:net");const socket=process.env.PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_SOCKET;const server=net.createServer();server.listen(socket,()=>{${socketEvidence}fs.unlinkSync(socket)});setInterval(()=>{},1000);`,
		);
		const pending = record(target);
		const pid = await waitForPid(target.agentDir);
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(await inspectIncidentRecorderRuns(target.agentDir)).toHaveLength(1);
		expect(() => signalFixture(pid, 0)).not.toThrow();
		signalFixture(pid, "SIGKILL");
		const result = await pending;
		livePids.delete(pid);
		expect(result.classification).toBe("socket_loss");
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

	it.skip("finalizes a live worker response hang without recovering the process (legacy timeline injector; replace with journal-backed service fixture)", async () => {
		const target = fixture(
			`${appendEventScript({ type: "worker_request_end", requestType: "get_state", durationMs: 25, outcome: "timeout" })}setInterval(()=>{},1000);`,
		);
		const pending = record(target);
		const pid = await waitForPid(target.agentDir);
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(await inspectIncidentRecorderRuns(target.agentDir)).toHaveLength(1);
		expect(() => signalFixture(pid, 0)).not.toThrow();
		signalFixture(pid, "SIGKILL");
		const result = await pending;
		livePids.delete(pid);
		expect(result.classification).toBe("worker_response_hang");
	});
});
