import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { readFileSync, readlinkSync } from "node:fs";
import { access, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "../../src/core/kernel/diagnostics.js";
import { disposeAllForkServers } from "../../src/core/kernel/fork-server.js";
import { KernelManager } from "../../src/core/kernel/index.js";
import { DaemonClient } from "../../src/modes/daemon/daemon-client.js";
import type { SessionSummary } from "../../src/modes/daemon/daemon-session-list.js";
import {
	flushSupervisorDiagnosticCapture,
	installSupervisorDiagnosticHooks,
} from "../../src/modes/daemon/incident-recorder.js";

const [root, python, mode] = process.argv.slice(2);
if (
	!root ||
	!python ||
	!["forkserver", "worker", "worker-shutdown", "worker-interrupted-shutdown", "worker-socket-loss"].includes(
		mode ?? "",
	)
)
	throw new Error("Invalid fixture arguments");
if (
	process.platform !== "linux" ||
	process.pid !== 1 ||
	!readFileSync("/proc/1/cmdline", "utf8").includes("diagnostic-native-parent-faults.ts") ||
	!/^0\s+\d+\s+1$/.test(readFileSync("/proc/self/uid_map", "utf8").trim()) ||
	readlinkSync("/proc/self/ns/pid") !== readlinkSync("/proc/1/ns/pid")
)
	throw new Error("The parent-fault fixture requires its own PID and user namespaces");
if (spawnSync("/usr/sbin/ip", ["link", "set", "lo", "up"]).status !== 0)
	throw new Error("Isolated network loopback could not start");

interface Identity {
	pid: number;
	parentPid: number;
	startTicks: string;
	state: string;
}

function identity(pid: number): Identity {
	const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
	const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
	return { pid, parentPid: Number(fields[1]), startTicks: fields[19]!, state: fields[0]! };
}

function alive(original: Identity): boolean {
	try {
		const current = identity(original.pid);
		return current.startTicks === original.startTicks && !["Z", "X"].includes(current.state);
	} catch {
		return false;
	}
}

function signalOwned(original: Identity, signal: NodeJS.Signals): void {
	if (original.pid <= 1 || !alive(original))
		throw new Error("Refusing to signal a changed or unowned fixture process");
	process.kill(original.pid, signal);
}

async function state(name: string, value: unknown): Promise<void> {
	const destination = join(root, `${name}.json`);
	await writeFile(`${destination}.pending`, JSON.stringify(value, null, 2), { mode: 0o600 });
	await rename(`${destination}.pending`, destination);
}

async function waitFor(
	check: () => boolean | Promise<boolean>,
	description: string,
	timeoutMs = 30_000,
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (await check()) return;
		await delay(25);
	}
	throw new Error(`Fixture timeout: ${description}`);
}

async function waitCommand(expected: string): Promise<void> {
	await waitFor(
		async () => (await readFile(join(root, "command"), "utf8").catch(() => "")) === expected,
		expected,
		60_000,
	);
}

const managers: KernelManager[] = [];
const clients: DaemonClient[] = [];
const events: KernelDiagnosticEvent[] = [];
const unsubscribe = subscribeKernelDiagnostics((event) => events.push(event));
const uninstall = mode === "forkserver" ? installSupervisorDiagnosticHooks(join(root, "unused.sock")) : () => {};
let supervisor: ChildProcess | undefined;

try {
	for (const name of ["home", "agent", "sessions", "project"]) await mkdir(join(root, name), { recursive: true });
	if (mode === "forkserver") {
		const kernels: Array<Identity & { kernelInstanceId: string; sessionId: string }> = [];
		for (let index = 0; index < 2; index++) {
			const sessionId = `parent-fault-${index}`;
			const manager = new KernelManager({ python, cwd: root, sessionId });
			managers.push(manager);
			const result = await manager.execute(
				`import os, time\nfrom pathlib import Path\nsentinel = ${JSON.stringify(`private-parent-sentinel-${index}`)}\nprint(os.getpid())`,
			);
			if (result.status !== "ok") throw new Error("Sentinel initialization failed");
			const started = events.find(
				(event) => event.type === "kernel_process_started" && event.sessionId === sessionId,
			);
			if (!started || started.launchMode !== "fork" || Number(result.stdout.trim()) !== started.kernelPid)
				throw new Error("Expected a real forked kernel identity");
			kernels.push({ ...identity(started.kernelPid), kernelInstanceId: started.kernelInstanceId, sessionId });
		}
		if (kernels[0]!.parentPid !== kernels[1]!.parentPid) throw new Error("Kernels do not share a forkserver");
		const parent = identity(kernels[0]!.parentPid);
		if (parent.parentPid !== process.pid) throw new Error("Shared parent is not owned by this observer");
		const execution = managers.map((manager, index) =>
			manager
				.execute(
					`assert sentinel == ${JSON.stringify(`private-parent-sentinel-${index}`)}\nPath(${JSON.stringify(join(root, `busy-${index}`))}).touch()\ntime.sleep(60)`,
				)
				.then(
					(result) => ({ status: result.status }),
					(error: unknown) => ({ rejected: String(error) }),
				),
		);
		await waitFor(
			async () =>
				(
					await Promise.all(
						[0, 1].map((index) =>
							access(join(root, `busy-${index}`)).then(
								() => true,
								() => false,
							),
						),
					)
				).every(Boolean),
			"both sentinel kernels executing",
		);
		await flushSupervisorDiagnosticCapture();
		await state("ready", {
			observer: identity(process.pid),
			parent,
			kernels,
			namespace: readlinkSync("/proc/self/ns/pid"),
		});
		await waitCommand("inject");
		signalOwned(parent, "SIGKILL");
		await waitFor(() => kernels.every((kernel) => !alive(kernel)), "both original kernels no longer running");
		const results = await Promise.all(execution);
		await flushSupervisorDiagnosticCapture();
		await state("observed", {
			observer: identity(process.pid),
			parentAlive: alive(parent),
			kernelsAlive: kernels.map(alive),
			results,
			events,
		});
	} else {
		const socketPath = join(root, "daemon.sock");
		const loader = fileURLToPath(new URL("../../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
		const cli = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));
		const extension = fileURLToPath(new URL("./daemon-status-kernel-causal.ts", import.meta.url));
		await writeFile(join(root, "agent", "settings.json"), JSON.stringify({ autoRefine: { enabled: false } }));
		supervisor = spawn(
			process.execPath,
			[
				"--import",
				loader,
				...(mode === "worker-socket-loss"
					? ["--import", fileURLToPath(new URL("./diagnostic-worker-socket-loss.ts", import.meta.url))]
					: []),
				cli,
				"--mode",
				"daemon",
				"--daemon-socket",
				socketPath,
				"--offline",
			],
			{
				cwd: join(root, "project"),
				stdio: ["ignore", "inherit", "inherit"],
				env: {
					...process.env,
					PRIME_AGENT_KERNEL_PYTHON: python,
					PRIME_AGENT_CAUSAL_EVIDENCE_DIR: root,
					...(mode === "worker-socket-loss" ? { PRIME_AGENT_SOCKET_LOSS_TEST_ROOT: root } : {}),
					PI_OFFLINE: "1",
					PI_SKIP_VERSION_CHECK: "1",
					PRIME_AGENT_INSTALL_UV: "0",
					RLM_DEPTH: "0",
				},
			},
		);
		let connected: DaemonClient | undefined;
		await waitFor(async () => {
			if (supervisor!.exitCode !== null) throw new Error("Supervisor exited before readiness");
			const candidate = new DaemonClient(socketPath);
			try {
				await candidate.connect(250);
				await candidate.waitForHello(1000);
				connected = candidate;
				clients.push(candidate);
				return true;
			} catch {
				candidate.close();
				return false;
			}
		}, "real supervisor readiness");
		if (!connected) throw new Error("Supervisor client unavailable");
		const client = connected;
		const created = await client.request(
			{
				type: "create",
				name: "parent-evidence",
				config: {
					cwd: join(root, "project"),
					agentDir: join(root, "agent"),
					sessionDir: join(root, "sessions"),
					provider: "causal-faux",
					model: "kernel",
					extensions: [extension],
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
		if (!created.success) throw new Error(created.error);
		const session = created.data as SessionSummary;
		if (!session.workerPid || !session.activeSessionId) throw new Error("Missing worker/session identity");
		const result = await client.request(
			{
				type: "prompt_and_wait",
				activeSessionId: session.activeSessionId,
				message: JSON.stringify({
					code: `import os, json\nfrom pathlib import Path\nsentinel = 'private-worker-sentinel'\nPath(${JSON.stringify(join(root, "kernel.json"))}).write_text(json.dumps({'pid': os.getpid(), 'parentPid': os.getppid()}))`,
				}),
				expandPromptTemplates: false,
			},
			60_000,
		);
		if (!result.success) throw new Error(result.error);
		const kernel = identity((JSON.parse(await readFile(join(root, "kernel.json"), "utf8")) as { pid: number }).pid);
		const parent = identity(session.workerPid);
		const owner = identity(supervisor.pid!);
		const forkserver = identity(kernel.parentPid);
		if (parent.parentPid !== owner.pid || forkserver.parentPid !== parent.pid)
			throw new Error("Worker ownership chain mismatch");
		await state("ready", {
			observer: identity(process.pid),
			supervisor: owner,
			parent,
			forkserver,
			kernels: [kernel],
			session,
			namespace: readlinkSync("/proc/self/ns/pid"),
		});
		await waitCommand("inject");
		let stopPendingAtSignal: boolean | undefined;
		let workerStateAtSignal: string | undefined;
		if (mode === "worker-socket-loss") {
			await writeFile(join(root, "socket-command"), "close", { mode: 0o600 });
			await waitFor(async () => {
				const error = await readFile(join(root, "error.json"), "utf8").catch(() => "");
				if (error) throw new Error(error);
				return access(join(root, "socket-injected")).then(
					() => true,
					() => false,
				);
			}, "owned worker socket closed");
			await delay(3000);
			const checked = await client.request(
				{
					type: "prompt_and_wait",
					activeSessionId: session.activeSessionId,
					expandPromptTemplates: false,
					message: JSON.stringify({
						code: `assert sentinel == 'private-worker-sentinel'\nassert os.getpid() == ${kernel.pid}\nPath(${JSON.stringify(join(root, "sentinel-verified"))}).touch()`,
					}),
				},
				30_000,
			);
			if (!checked.success) throw new Error(checked.error);
			await access(join(root, "sentinel-verified"));
			if (![parent, forkserver, kernel].every(alive))
				throw new Error("Socket loss changed an original process identity");
		} else if (mode === "worker-shutdown") {
			const stopped = await client.request({ type: "kill", activeSessionId: session.activeSessionId }, 10_000);
			if (!stopped.success) throw new Error(stopped.error);
		} else if (mode === "worker-interrupted-shutdown") {
			signalOwned(parent, "SIGSTOP");
			await waitFor(() => identity(parent.pid).state === "T", "owned worker paused before graceful stop");
			let stopPending = true;
			const stop = client.request({ type: "kill", activeSessionId: session.activeSessionId }, 15_000).then(
				(response) => {
					stopPending = false;
					return response;
				},
				(error: unknown) => {
					stopPending = false;
					return { error: String(error) };
				},
			);
			await state("stopping", { worker: identity(parent.pid), stopPending });
			await waitCommand("kill-during-stop");
			stopPendingAtSignal = stopPending;
			workerStateAtSignal = identity(parent.pid).state;
			if (!stopPendingAtSignal || workerStateAtSignal !== "T")
				throw new Error("Graceful stop was no longer pending at fault injection");
			signalOwned(parent, "SIGKILL");
			await stop;
		} else signalOwned(parent, "SIGKILL");
		if (mode !== "worker-socket-loss") await waitFor(() => !alive(parent), "worker exit");
		await delay(3000);
		await state("observed", {
			observer: identity(process.pid),
			supervisor: identity(owner.pid),
			parentAlive: alive(parent),
			forkserverAlive: alive(forkserver),
			kernelsAlive: [alive(kernel)],
			stopPendingAtSignal,
			workerStateAtSignal,
			list: await client.request({ type: "list" }, 3000),
		});
	}
	await waitCommand("stop");
} catch (error) {
	await state("error", { error: String(error), stack: error instanceof Error ? error.stack : undefined });
	process.exitCode = 1;
} finally {
	await state("cleanup", { observedAt: new Date().toISOString() });
	for (const client of clients) client.close();
	for (const manager of managers) await manager.dispose();
	disposeAllForkServers();
	if (supervisor?.pid && supervisor.exitCode === null && supervisor.signalCode === null) {
		supervisor.kill("SIGTERM");
		await Promise.race([new Promise<void>((resolve) => supervisor!.once("close", () => resolve())), delay(5000)]);
	}
	await flushSupervisorDiagnosticCapture();
	uninstall();
	unsubscribe();
}
