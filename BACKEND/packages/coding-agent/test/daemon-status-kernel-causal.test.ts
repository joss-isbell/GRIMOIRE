import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { ENV_AGENT_DIR } from "../src/config.js";
import { DaemonClient } from "../src/modes/daemon/daemon-client.js";
import type { DaemonListResult } from "../src/modes/daemon/daemon-protocol.js";
import type { SessionSummary } from "../src/modes/daemon/daemon-session-list.js";

const cliPath = resolve(__dirname, "../src/cli.ts");
const tsxPath = resolve(__dirname, "../../../node_modules/tsx/dist/cli.mjs");
const extensionPath = resolve(__dirname, "fixtures/daemon-status-kernel-causal.ts");
const python = process.env.PRIME_AGENT_CAUSAL_PYTHON;

interface ProcessIdentity {
	pid: number;
	parentPid: number;
	startTicks: string;
}

interface KernelIdentity extends ProcessIdentity {
	sentinel: string;
	workerPid: number;
}

function processIdentity(pid: number): ProcessIdentity {
	const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
	const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
	return { pid, parentPid: Number(fields[1]), startTicks: fields[19]! };
}

function signalOwned(identity: ProcessIdentity, signal: NodeJS.Signals): void {
	try {
		if (processIdentity(identity.pid).startTicks === identity.startTicks) process.kill(identity.pid, signal);
	} catch {
		// A process that exited or whose identity changed is no longer a cleanup target.
	}
}

function assertNamespaceIsolation(): void {
	// Public status discovers all listening daemons, so a socket flag cannot isolate this test.
	expect(process.platform).toBe("linux");
	expect(readFileSync("/proc/1/cmdline", "utf8")).toContain("vitest/dist/cli.js");
	expect(readlinkSync("/proc/self/ns/net")).toBe(readlinkSync("/proc/1/ns/net"));
	expect(readFileSync("/proc/self/uid_map", "utf8").trim()).toMatch(/^0\s+\d+\s+1$/);
	expect(process.env.TMPDIR).toBeTruthy();
	expect(tmpdir()).not.toBe("/tmp");
	if (!python) throw new Error("Set PRIME_AGENT_CAUSAL_PYTHON to an existing bootstrapped Linux Python");
	expect(spawnSync("/usr/sbin/ip", ["link", "set", "lo", "up"], { encoding: "utf8" }).status).toBe(0);
}

function isolatedEnvironment(root: string): NodeJS.ProcessEnv {
	return {
		PATH: `${process.execPath.slice(0, process.execPath.lastIndexOf("/"))}:/usr/sbin:/usr/bin:/bin`,
		HOME: join(root, "home"),
		TMPDIR: tmpdir(),
		LANG: "C.UTF-8",
		[ENV_AGENT_DIR]: join(root, "agent"),
		PRIME_AGENT_SESSION_DIR: join(root, "sessions"),
		PRIME_AGENT_KERNEL_PYTHON: python,
		PRIME_AGENT_KERNEL_FORKSERVER: "1",
		PRIME_AGENT_CAUSAL_EVIDENCE_DIR: root,
		TSX_TSCONFIG_PATH: resolve(__dirname, "../../../tsconfig.json"),
		PI_OFFLINE: "1",
		PI_SKIP_VERSION_CHECK: "1",
		PRIME_AGENT_INSTALL_UV: "0",
		RLM_DEPTH: "0",
	};
}

async function waitFor<T>(read: () => T | undefined, description: string, timeoutMs = 30_000): Promise<T> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const result = read();
		if (result !== undefined) return result;
		await delay(25);
	}
	throw new Error(`Timed out: ${description}`);
}

async function connect(socketPath: string, child: ChildProcess): Promise<DaemonClient> {
	const deadline = Date.now() + 30_000;
	while (Date.now() < deadline) {
		if (child.exitCode !== null || child.signalCode !== null) throw new Error("Supervisor exited before readiness");
		const client = new DaemonClient(socketPath);
		try {
			await client.connect(250);
			await client.waitForHello(1000);
			return client;
		} catch {
			client.close();
			await delay(25);
		}
	}
	throw new Error("Supervisor readiness timed out");
}

function readJson<T>(path: string): T | undefined {
	if (!existsSync(path)) return undefined;
	try {
		return JSON.parse(readFileSync(path, "utf8")) as T;
	} catch {
		return undefined;
	}
}

function workerIdForPid(root: string, pid: number): string {
	const descriptorsRoot = join(root, "agent", "daemon-workers");
	for (const scope of readdirSync(descriptorsRoot, { withFileTypes: true })) {
		if (!scope.isDirectory()) continue;
		for (const name of readdirSync(join(descriptorsRoot, scope.name))) {
			if (!name.endsWith(".json")) continue;
			const descriptor = readJson<{ pid?: number; workerId?: string }>(join(descriptorsRoot, scope.name, name));
			if (descriptor?.pid === pid && typeof descriptor.workerId === "string") return descriptor.workerId;
		}
	}
	throw new Error(`Missing fixture-owned worker descriptor for pid ${pid}`);
}

function diagnosticEvents(
	root: string,
): Array<{ at: string; workerPid: number; workerId?: string; event: Record<string, unknown> }> {
	return readdirSync(root)
		.filter((name) => /^worker-\d+\.jsonl$/.test(name))
		.flatMap((name) =>
			readFileSync(join(root, name), "utf8")
				.trim()
				.split("\n")
				.filter(Boolean)
				.map((line) => JSON.parse(line)),
		);
}

async function cell(client: DaemonClient, activeSessionId: string, code: string): Promise<void> {
	const response = await client.request(
		{ type: "prompt_and_wait", activeSessionId, message: JSON.stringify({ code }), expandPromptTemplates: false },
		60_000,
	);
	if (!response.success) throw new Error(response.error);
}

function writePythonJson(path: string, expression: string): string {
	return `Path(${JSON.stringify(path)}).write_text(json.dumps(${expression}))`;
}

describe("public status from executing IPython through real daemon workers", { tags: ["kernel-heavy"] }, () => {
	it("retains three original kernels and state during reentrant and concurrent observation", async () => {
		assertNamespaceIsolation();
		const root = mkdtempSync(join(tmpdir(), "causal-"));
		const socketPath = join(root, "daemon.sock");
		for (const directory of ["home", "agent", "project", "sessions"]) mkdirSync(join(root, directory));
		writeFileSync(join(root, "agent", "settings.json"), JSON.stringify({ autoRefine: { enabled: false } }));
		const child = spawn(
			process.execPath,
			[tsxPath, cliPath, "--mode", "daemon", "--daemon-socket", socketPath, "--offline"],
			{
				cwd: join(root, "project"),
				env: isolatedEnvironment(root),
				stdio: ["ignore", "pipe", "pipe"],
			},
		);
		let output = "";
		for (const stream of [child.stdout, child.stderr])
			stream?.on("data", (chunk: Buffer) => {
				output = (output + chunk.toString("utf8")).slice(-128 * 1024);
			});
		child.on("exit", (code, signal) =>
			writeFileSync(join(root, "supervisor-exit.json"), JSON.stringify({ code, signal, at: Date.now() })),
		);
		const clients: DaemonClient[] = [];
		const workers: ProcessIdentity[] = [];
		let stoppedWorker: ProcessIdentity | undefined;
		let succeeded = false;
		try {
			const client = await connect(socketPath, child);
			clients.push(client);
			expect(client.supportsServerCapability("list_observation")).toBe(true);
			const sessions: SessionSummary[] = [];
			for (let index = 0; index < 3; index++) {
				const response = await client.request(
					{
						type: "create",
						name: `causal-${index}`,
						config: {
							cwd: join(root, "project"),
							agentDir: join(root, "agent"),
							sessionDir: join(root, "sessions"),
							provider: "causal-faux",
							model: "kernel",
							extensions: [extensionPath],
							tools: ["ipython"],
							noSkills: true,
							noPromptTemplates: true,
							noThemes: true,
							noContextFiles: true,
							telemetryDisabled: true,
						},
					},
					60_000,
				);
				if (!response.success) throw new Error(response.error);
				const summary = response.data as SessionSummary;
				if (!summary.activeSessionId || !summary.workerPid) throw new Error("Missing real worker identity");
				sessions.push(summary);
				workers.push(processIdentity(summary.workerPid));
				const init = [
					"import os, json, time, subprocess",
					"from pathlib import Path",
					`sentinel = ${JSON.stringify(`sentinel-${index}-${root}`)}`,
					"progress = 0",
					writePythonJson(
						join(root, `kernel-${index}.json`),
						"{'pid': os.getpid(), 'parentPid': os.getppid(), 'sentinel': sentinel}",
					),
				].join("\n");
				await cell(client, summary.activeSessionId, init);
				await waitFor(() => readJson(join(root, `kernel-${index}.json`)), "real kernel initialized");
			}
			const before = sessions.map((session, index): KernelIdentity => {
				const data = readJson<{ pid: number; sentinel: string }>(join(root, `kernel-${index}.json`))!;
				return { ...processIdentity(data.pid), sentinel: data.sentinel, workerPid: session.workerPid! };
			});
			const forkservers = before.map((kernel) => processIdentity(kernel.parentPid));
			const workerIds = workers.map((worker) => workerIdForPid(root, worker.pid));
			writeFileSync(
				join(root, "before.json"),
				JSON.stringify(
					{
						kernels: before,
						workers,
						workerIds,
						forkservers,
						events: diagnosticEvents(root),
					},
					null,
					2,
				),
			);
			writeFileSync(
				join(root, "listeners-before.txt"),
				spawnSync("/usr/bin/ss", ["-lxp"], { encoding: "utf8" }).stdout,
			);
			expect(new Set(before.map((kernel) => kernel.pid)).size).toBe(3);
			const command = JSON.stringify([process.execPath, tsxPath, cliPath, "status", "--json"]);
			const busy = sessions.slice(1).map(async (session, offset) => {
				const sibling = await connect(socketPath, child);
				clients.push(sibling);
				await cell(
					sibling,
					session.activeSessionId!,
					[
						`Path(${JSON.stringify(join(root, `busy-${offset}.ready`))}).touch()`,
						"deadline = time.monotonic() + 12",
						"while time.monotonic() < deadline:",
						"    progress += sum(range(1000))",
						"    time.sleep(0.01)",
					].join("\n"),
				);
			});
			await waitFor(
				() => [0, 1].every((index) => existsSync(join(root, `busy-${index}.ready`))) || undefined,
				"both sibling cells executing",
			);
			await cell(
				client,
				sessions[0]!.activeSessionId!,
				[
					`status_command = ${command}`,
					"status_results = []",
					"for attempt in range(3):",
					`    stdout_path = Path(${JSON.stringify(root)}) / f'status-{attempt}.stdout'`,
					`    stderr_path = Path(${JSON.stringify(root)}) / f'status-{attempt}.stderr'`,
					"    with stdout_path.open('w') as out, stderr_path.open('w') as err:",
					"        result = subprocess.run(status_command, stdout=out, stderr=err, text=True, timeout=15)",
					"    status_results.append({'returncode': result.returncode, 'stdout': stdout_path.read_text(), 'stderr': stderr_path.read_text()})",
					writePythonJson(join(root, "reentrant-status.json"), "status_results"),
				].join("\n"),
			);
			await Promise.all(busy);
			expect(
				diagnosticEvents(root).filter(({ event }) => event.type === "kernel_unexpected_exit"),
				`Original kernel died; causal evidence: ${root}`,
			).toEqual([]);
			const statuses = readJson<Array<{ returncode: number; stdout: string }>>(join(root, "reentrant-status.json"));
			expect(statuses).toHaveLength(3);
			for (const status of statuses!) {
				expect(status.returncode).toBe(0);
				const discovered = JSON.parse(status.stdout) as Array<{ socketPath: string; sessionCount: number }>;
				expect(discovered).toEqual([expect.objectContaining({ socketPath, sessionCount: 3 })]);
			}

			await delay(1100);
			stoppedWorker = workers[2]!;
			const stoppedWorkerId = workerIds[2]!;
			process.kill(stoppedWorker.pid, "SIGSTOP");
			const stormStarted = Date.now();
			const storm = Array.from({ length: 8 }, async () => {
				const observer = await connect(socketPath, child);
				clients.push(observer);
				try {
					return await observer.request({ type: "list" }, 3000);
				} catch (error) {
					return { error: String(error) };
				} finally {
					observer.close();
				}
			});
			const stormResults = await Promise.all(storm);
			writeFileSync(
				join(root, "stalled-observation.json"),
				JSON.stringify({ durationMs: Date.now() - stormStarted, results: stormResults }, null, 2),
			);
			for (const result of stormResults) {
				expect(result).toMatchObject({ success: true, data: { sessions: expect.any(Array) } });
				if ("success" in result && result.success) {
					const data = result.data as DaemonListResult;
					expect(data.sessions).toHaveLength(3);
					expect(data.observation).toMatchObject({
						status: "stale",
						workers: expect.arrayContaining([
							expect.objectContaining({ workerId: stoppedWorkerId, status: "stale" }),
						]),
					});
				}
			}
			expect(processIdentity(stoppedWorker.pid)).toEqual(stoppedWorker);
			process.kill(stoppedWorker.pid, "SIGCONT");
			stoppedWorker = undefined;
			await delay(6000);
			for (const [index, session] of sessions.entries()) {
				await cell(
					client,
					session.activeSessionId!,
					writePythonJson(
						join(root, `after-${index}.json`),
						"{'pid': os.getpid(), 'sentinel': sentinel, 'progress': progress}",
					),
				);
				const after = readJson<{ pid: number; sentinel: string; progress: number }>(
					join(root, `after-${index}.json`),
				);
				expect(after).toMatchObject({ pid: before[index]!.pid, sentinel: before[index]!.sentinel });
				expect(processIdentity(before[index]!.pid)).toEqual({
					pid: before[index]!.pid,
					parentPid: before[index]!.parentPid,
					startTicks: before[index]!.startTicks,
				});
				expect(processIdentity(workers[index]!.pid)).toEqual(workers[index]);
				expect(processIdentity(forkservers[index]!.pid)).toEqual(forkservers[index]);
				if (index > 0) expect(after!.progress).toBeGreaterThan(0);
			}
			const events = diagnosticEvents(root);
			writeFileSync(join(root, "pre-cleanup-events.json"), JSON.stringify(events, null, 2));
			expect(events.filter(({ event }) => event.type === "kernel_process_started")).toHaveLength(3);
			expect(
				events.filter(
					({ event }) => event.type === "kernel_lifecycle_intent" || event.type === "kernel_process_exit_observed",
				),
			).toEqual([]);
			expect(
				events.filter(({ event }) => event.type === "forkserver_lifecycle" && event.phase === "peer_authenticated"),
			).toHaveLength(3);
			expect(
				events.filter(
					({ event }) => event.type === "kernel_unexpected_exit" || event.type === "kernel_channel_fault",
				),
			).toEqual([]);
			expect(events.filter(({ event }) => event.type === "tool_execution_end" && event.isError === true)).toEqual(
				[],
			);
			succeeded = true;
		} finally {
			writeFileSync(
				join(root, "cleanup-start.json"),
				JSON.stringify({ at: new Date().toISOString(), events: diagnosticEvents(root) }, null, 2),
			);
			writeFileSync(join(root, "supervisor-output.txt"), output);
			if (stoppedWorker) signalOwned(stoppedWorker, "SIGCONT");
			const cleanup = new DaemonClient(socketPath);
			try {
				await cleanup.connect(500);
				await cleanup.request({ type: "shutdown", force: true }, 15_000);
			} catch {
				if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
			} finally {
				cleanup.close();
				for (const client of clients) client.close();
			}
			await waitFor(
				() => (child.exitCode !== null || child.signalCode !== null ? true : undefined),
				"owned supervisor shutdown",
				15_000,
			).catch(() => child.kill("SIGKILL"));
			for (const worker of workers) {
				signalOwned(worker, "SIGTERM");
			}
			console.log(JSON.stringify({ causalEvidence: root, succeeded }));
			if (succeeded && process.env.PRIME_AGENT_CAUSAL_KEEP_EVIDENCE !== "1")
				rmSync(root, { recursive: true, force: true });
		}
	}, 180_000);
});
