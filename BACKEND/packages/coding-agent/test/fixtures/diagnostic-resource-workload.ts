import { type ChildProcess, spawn } from "node:child_process";
import { appendFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { DaemonClient } from "../../src/modes/daemon/daemon-client.js";
import type { SessionSummary } from "../../src/modes/daemon/daemon-session-list.js";

interface Config {
	root: string;
	node: string;
	cli: string;
	extension: string;
	python: string;
	packageRoot: string;
	namespace?: string;
	warmupSeconds: number;
	measureSeconds: number;
	diagnostics: boolean;
}
interface Identity {
	pid: number;
	parentPid: number;
	startTicks: string;
}
const config = JSON.parse(await readFile(process.argv[2], "utf8")) as Config;
if (process.platform !== "linux" || process.getuid?.() === 0 || process.ppid !== 1)
	throw new Error("Expected unprivileged namespace-owned workload");
process.title = "prime-agent";
const root = config.root;
const socketPath = join(root, "daemon.sock");
const clients: DaemonClient[] = [];
let supervisor: ChildProcess | undefined;
const identities: Identity[] = [];
const samples: Array<{ phase: string; kind: string; elapsedMs: number; ok: boolean }> = [];
const state = async (name: string, value: unknown) => {
	const path = join(root, `${name}.json`);
	await writeFile(`${path}.pending`, JSON.stringify(value), { mode: 0o600 });
	await rename(`${path}.pending`, path);
};
async function until<T>(read: () => Promise<T | undefined>, name: string, timeoutMs = 30_000): Promise<T> {
	const deadline = performance.now() + timeoutMs;
	while (performance.now() < deadline) {
		const value = await read();
		if (value !== undefined) return value;
		await delay(20);
	}
	throw new Error(`Timed out: ${name}`);
}
async function identity(pid: number): Promise<Identity> {
	if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error("Invalid owned PID");
	const stat = await readFile(`/proc/${pid}/stat`, "utf8");
	const fields = stat
		.slice(stat.lastIndexOf(")") + 2)
		.trim()
		.split(/\s+/);
	return { pid, parentPid: Number(fields[1]), startTicks: fields[19] };
}
async function connect(): Promise<DaemonClient> {
	return until(async () => {
		if (supervisor?.exitCode !== null || supervisor?.signalCode !== null) throw new Error("Owned supervisor exited");
		const client = new DaemonClient(socketPath);
		try {
			await client.connect(250);
			await client.waitForHello(1000);
			clients.push(client);
			return client;
		} catch {
			client.close();
			return undefined;
		}
	}, "supervisor ready");
}
async function cell(client: DaemonClient, session: SessionSummary, code: string): Promise<void> {
	const response = await client.request(
		{
			type: "prompt_and_wait",
			activeSessionId: session.activeSessionId!,
			message: JSON.stringify({ code }),
			expandPromptTemplates: false,
		},
		30_000,
	);
	if (!response.success) throw new Error(response.error);
}
async function measured(phase: string, kind: string, action: () => Promise<void>): Promise<void> {
	if (samples.length >= 49_984) throw new Error("Admission sample bound exceeded");
	const started = performance.now();
	let ok = false;
	try {
		await action();
		ok = true;
	} finally {
		samples.push({ phase, kind, elapsedMs: performance.now() - started, ok });
	}
}
function status(): Promise<void> {
	return new Promise((resolve, reject) => {
		const child = spawn(config.node, [config.cli, "status", "--json"], {
			env: process.env,
			stdio: ["ignore", "pipe", "pipe"],
		});
		let output = "";
		child.stdout.on("data", (chunk: Buffer) => {
			output = (output + chunk.toString()).slice(-64 * 1024);
		});
		child.stderr.resume();
		const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
		child.once("error", reject);
		child.once("close", (code) => {
			clearTimeout(timeout);
			try {
				if (code !== 0) throw new Error(`Public status failed: ${code}`);
				const found = JSON.parse(output) as Array<{ socketPath: string; sessionCount: number }>;
				if (found.length !== 1 || found[0].socketPath !== socketPath || found[0].sessionCount !== 3)
					throw new Error("Public status escaped the isolated supervisor");
				resolve();
			} catch (error) {
				reject(error);
			}
		});
	});
}
try {
	await state("owner", { pid: process.pid });
	await until(async () => await readFile(join(root, "release"), "utf8").catch(() => undefined), "probe release");
	process.getuid?.();
	for (const directory of ["home", "agent", "project", "sessions"]) await mkdir(join(root, directory));
	await writeFile(join(root, "agent", "settings.json"), JSON.stringify({ autoRefine: { enabled: false } }));
	const launched = performance.now();
	const command = [config.node, config.cli, "--mode", "daemon", "--daemon-socket", socketPath, "--offline"];
	supervisor = spawn(
		config.namespace ? "/usr/bin/systemd-cat" : command.shift()!,
		config.namespace
			? ["--namespace", config.namespace, "--identifier", "admission-daemon", "--level-prefix=false", ...command]
			: command,
		{ cwd: join(root, "project"), env: process.env, stdio: ["ignore", "pipe", "pipe"] },
	);
	let output = "";
	for (const stream of [supervisor.stdout, supervisor.stderr])
		stream?.on("data", (chunk: Buffer) => {
			output = (output + chunk.toString()).slice(-128 * 1024);
		});
	const client = await connect();
	const supervisorReadyMs = performance.now() - launched;
	identities.push(await identity(supervisor.pid!));
	const sessions: SessionSummary[] = [];
	for (let index = 0; index < 3; index++) {
		const response = await client.request(
			{
				type: "create",
				name: `admission-${index}`,
				config: {
					cwd: join(root, "project"),
					agentDir: join(root, "agent"),
					sessionDir: join(root, "sessions"),
					provider: "admission-faux",
					model: "kernel",
					extensions: [config.extension],
					tools: ["ipython"],
					noSkills: true,
					noPromptTemplates: true,
					noThemes: true,
					noContextFiles: true,
					telemetryDisabled: true,
				},
			},
			30_000,
		);
		if (!response.success) throw new Error(response.error);
		const session = response.data as SessionSummary;
		if (!session.activeSessionId || !session.workerPid) throw new Error("Missing real worker identity");
		sessions.push(session);
		identities.push(await identity(session.workerPid));
		await cell(
			client,
			session,
			`import os, time, json, subprocess\nfrom pathlib import Path\noriginal_pid = os.getpid()\nsentinel = 'admission-${index}'\nprogress = 0\nPath(${JSON.stringify(join(root, `kernel-${index}.json`))}).write_text(json.dumps({'pid': original_pid, 'parentPid': os.getppid(), 'sentinel': sentinel}))`,
		);
		const kernel = JSON.parse(await readFile(join(root, `kernel-${index}.json`), "utf8")) as {
			pid: number;
			parentPid: number;
		};
		identities.push(await identity(kernel.pid), await identity(kernel.parentPid));
	}
	await state("prepared", { supervisorReadyMs, identities });
	await until(async () => await readFile(join(root, "go"), "utf8").catch(() => undefined), "measurement start");
	const laneClients = await Promise.all(sessions.map(() => connect()));
	const observer = await connect();
	const phaseDurations: Record<string, number> = {};
	for (const [phase, seconds] of [
		["warmup", config.warmupSeconds],
		["measure", config.measureSeconds],
	] as const) {
		await state("phase", { phase, observedAtMs: Date.now() });
		const started = performance.now();
		const deadline = started + seconds * 1000;
		const lanes = sessions.map(async (session, index) => {
			for (let iteration = 0; performance.now() < deadline; iteration++) {
				const reentrant = index === 0 && iteration % 12 === 0;
				const long = index === 2 && iteration % 30 === 0;
				const code = reentrant
					? `r = subprocess.run(${JSON.stringify([config.node, config.cli, "status", "--json"])}, capture_output=True, text=True, timeout=10)\nassert r.returncode == 0, r.stderr\nassert len(json.loads(r.stdout)) == 1`
					: long
						? "time.sleep(2)"
						: "progress += sum(i*i for i in range(40000))\ntime.sleep(0.04)";
				await measured(phase, reentrant ? "reentrant_cell" : long ? "long_cell" : "short_cell", () =>
					cell(
						laneClients[index],
						session,
						`assert os.getpid() == original_pid\nassert sentinel == 'admission-${index}'\n${code}`,
					),
				);
			}
		});
		const lists = async () => {
			for (let iteration = 0; performance.now() < deadline; iteration++) {
				await Promise.all(
					Array.from({ length: iteration % 50 === 0 ? 8 : 1 }, () =>
						measured(phase, "list", async () => {
							const result = await observer.request({ type: "list" }, 5000);
							if (!result.success) throw new Error(result.error);
						}),
					),
				);
				await delay(200);
			}
		};
		const statuses = async () => {
			while (performance.now() < deadline) {
				await measured(phase, "public_status", status);
				await delay(1000);
			}
		};
		await Promise.all([...lanes, lists(), statuses()]);
		phaseDurations[phase] = performance.now() - started;
	}
	for (const [index, session] of sessions.entries())
		await cell(client, session, `assert os.getpid() == original_pid\nassert sentinel == 'admission-${index}'`);
	for (const before of identities) {
		const after = await identity(before.pid);
		if (JSON.stringify(after) !== JSON.stringify(before)) throw new Error("Original process identity changed");
	}
	await appendFile(join(root, "samples.jsonl"), `${samples.map((sample) => JSON.stringify(sample)).join("\n")}\n`, {
		mode: 0o600,
	});
	await state("result", {
		supervisorReadyMs,
		phaseDurations,
		samples: samples.length,
		originalIdentitiesRetained: true,
		identities,
	});
	await until(
		async () => await readFile(join(root, "stop"), "utf8").catch(() => undefined),
		"recorder stop before workload teardown",
	);
	await writeFile(join(root, "supervisor-output.txt"), output, { mode: 0o600 });
} catch (error) {
	await state("error", { error: String(error) });
	process.exitCode = 1;
} finally {
	if (supervisor?.pid && supervisor.exitCode === null && supervisor.signalCode === null) {
		const cleanup = new DaemonClient(socketPath);
		try {
			await cleanup.connect(500);
			await cleanup.request({ type: "shutdown", force: true }, 15_000);
		} catch {
			supervisor.kill("SIGTERM");
		} finally {
			cleanup.close();
		}
	}
	for (const client of clients) client.close();
}
