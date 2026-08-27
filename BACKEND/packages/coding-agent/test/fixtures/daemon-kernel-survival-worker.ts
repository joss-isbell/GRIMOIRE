import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { disposeAllForkServers } from "../../src/core/kernel/fork-server.js";
import { KernelManager } from "../../src/core/kernel/index.js";
import type { SessionSummary } from "../../src/modes/daemon/daemon-session-list.js";

const root = process.argv[2];
if (!root) throw new Error("Missing isolated worker root");
const readyPath = `${root}/active.ready`;
const stopPath = `${root}/active.stop`;
const managers = ["active-tool-session", "sibling-a-session", "sibling-b-session"].map(
	(sessionId) => new KernelManager({ cwd: root, sessionId }),
);
const [active, siblingA, siblingB] = managers;

function kernelPid(manager: KernelManager): number {
	const runtime = manager as unknown as {
		forkedKernel?: { pid: number };
		kernel?: { pid?: number };
	};
	const pid = runtime.forkedKernel?.pid ?? runtime.kernel?.pid;
	if (!pid) throw new Error("Kernel did not expose a process id");
	return pid;
}

function processParentPid(pid: number): number {
	const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
	const close = stat.lastIndexOf(")");
	const fields = stat
		.slice(close + 2)
		.trim()
		.split(/\s+/);
	const ppid = Number(fields[1]);
	if (!Number.isSafeInteger(ppid) || ppid <= 0) throw new Error(`Invalid parent pid for ${pid}`);
	return ppid;
}

function assertAlive(pid: number): void {
	process.kill(pid, 0);
}

function summary(index: number, pid: number): SessionSummary {
	const workerId = `isolated-session-${index + 1}`;
	const activeSessionId = `${workerId}-active`;
	return {
		id: activeSessionId,
		activeSessionId,
		sessionId: `${workerId}-session`,
		sessionName: workerId,
		lifecycle: "live",
		activity: index === 0 ? "running_tool" : "idle",
		isSessionActive: true,
		lastActivityAt: new Date().toISOString(),
		cwd: root,
		isStreaming: index === 0,
		isCompacting: false,
		attachedClients: 0,
		messageCount: 1,
		sessionFile: `${root}/${workerId}.jsonl`,
		sessionActions: { queuedCount: 0, steering: [], followUps: [] },
		workerPid: pid,
	};
}

function send(value: unknown): void {
	process.stdout.write(`${JSON.stringify(value)}\n`);
}

function sendAndExit(value: unknown): void {
	process.stdout.write(`${JSON.stringify(value)}\n`, () => process.exit(0));
}

let activeExecution: ReturnType<KernelManager["execute"]> | undefined;
let stopping = false;

async function stop(): Promise<void> {
	if (stopping) return;
	stopping = true;
	writeFileSync(stopPath, "stop\n");
	await activeExecution;
	await Promise.allSettled(managers.map((manager) => manager.dispose()));
	disposeAllForkServers();
}

async function main(): Promise<void> {
	const before = await Promise.all([
		siblingA.execute("sentinel = 'sibling-a-before'; print(sentinel)"),
		siblingB.execute("sentinel = 'sibling-b-before'; print(sentinel)"),
	]);
	if (before.some((result) => result.status !== "ok")) throw new Error("Sibling kernel bootstrap failed");
	activeExecution = active.execute(
		[
			"from pathlib import Path",
			"import os, time",
			`Path(${JSON.stringify(readyPath)}).write_text(str(os.getpid()))`,
			`while not Path(${JSON.stringify(stopPath)}).exists():`,
			"    time.sleep(0.02)",
			"print('active-tool-finished')",
		].join("\n"),
	);
	while (!existsSync(readyPath)) await new Promise((resolve) => setTimeout(resolve, 20));
	const kernelPids = managers.map(kernelPid);
	const forkserverPids = kernelPids.map(processParentPid);
	if (new Set(forkserverPids).size !== 1) throw new Error("Kernels did not share one forkserver");
	const summaries = kernelPids.map((pid, index) => summary(index, pid));
	send({ type: "ready", workerPid: process.pid, kernelPids, forkserverPid: forkserverPids[0], summaries });

	const lines = createInterface({ input: process.stdin, crlfDelay: Number.POSITIVE_INFINITY });
	for await (const line of lines) {
		const command = JSON.parse(line) as { id: string; type: "list" | "probe" | "stop" };
		try {
			if (command.type === "list") {
				for (const pid of [...kernelPids, forkserverPids[0]]) assertAlive(pid);
				send({ id: command.id, success: true, summaries });
				continue;
			}
			if (command.type === "probe") {
				const after = await Promise.all([
					siblingA.execute("sentinel = sentinel.replace('before', 'after'); print(sentinel)"),
					siblingB.execute("sentinel = sentinel.replace('before', 'after'); print(sentinel)"),
				]);
				for (const pid of [...kernelPids, forkserverPids[0]]) assertAlive(pid);
				send({ id: command.id, success: true, stdout: after.map((result) => result.stdout.trim()) });
				continue;
			}
			await stop();
			sendAndExit({ id: command.id, success: true });
			return;
		} catch (error) {
			send({ id: command.id, success: false, error: error instanceof Error ? error.message : String(error) });
		}
	}
}

void main().catch(async (error) => {
	process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
	await stop().catch(() => {});
	process.exitCode = 1;
});
