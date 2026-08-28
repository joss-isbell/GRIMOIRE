import { type ChildProcess, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { afterEach, describe, expect, it, vi } from "vitest";
import { success } from "../src/modes/daemon/daemon-protocol.js";
import type { SessionSummary } from "../src/modes/daemon/daemon-session-list.js";
import { DaemonSupervisor } from "../src/modes/daemon/daemon-supervisor.js";

interface WorkerReady {
	type: "ready";
	workerPid: number;
	kernelPids: number[];
	forkserverPid: number;
	summaries: SessionSummary[];
}

interface WorkerReply {
	id: string;
	success: boolean;
	error?: string;
	summaries?: SessionSummary[];
	stdout?: string[];
}

const tsxPath = resolve(__dirname, "../../../node_modules/tsx/dist/cli.mjs");
const workerFixture = resolve(__dirname, "fixtures/daemon-kernel-survival-worker.ts");
const roots = new Set<string>();
const children = new Set<ChildProcess>();

afterEach(async () => {
	for (const child of children) {
		if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
	}
	children.clear();
	for (const root of roots) rmSync(root, { recursive: true, force: true });
	roots.clear();
});

function assertAlive(pid: number): void {
	process.kill(pid, 0);
}

function waitForExit(child: ChildProcess): Promise<void> {
	if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
	return new Promise((resolveExit, reject) => {
		const timeout = setTimeout(() => reject(new Error("Isolated worker did not exit")), 15_000);
		child.once("exit", () => {
			clearTimeout(timeout);
			resolveExit();
		});
	});
}

function spawnKernelWorker(root: string) {
	const environment = { ...process.env };
	environment.PRIME_AGENT_DIR = join(root, "agent");
	environment.PRIME_AGENT_KERNEL_FORKSERVER = "1";
	environment.TSX_TSCONFIG_PATH = resolve(__dirname, "../../../tsconfig.json");
	const child = spawn(process.execPath, [tsxPath, workerFixture, root], {
		cwd: root,
		env: environment,
		stdio: ["pipe", "pipe", "pipe"],
	});
	children.add(child);
	let stderr = "";
	child.stderr?.on("data", (chunk: Buffer) => {
		stderr += chunk.toString("utf8");
	});
	let readyResolve!: (value: WorkerReady) => void;
	let readyReject!: (error: Error) => void;
	const ready = new Promise<WorkerReady>((resolveReady, rejectReady) => {
		readyResolve = resolveReady;
		readyReject = rejectReady;
	});
	const pending = new Map<string, { resolve: (value: WorkerReply) => void; reject: (error: Error) => void }>();
	const lines = createInterface({ input: child.stdout!, crlfDelay: Number.POSITIVE_INFINITY });
	lines.on("line", (line) => {
		const message = JSON.parse(line) as WorkerReady | WorkerReply;
		if ("type" in message && message.type === "ready") {
			readyResolve(message);
			return;
		}
		const waiter = pending.get(message.id);
		if (!waiter) return;
		pending.delete(message.id);
		waiter.resolve(message);
	});
	child.once("exit", (code, signal) => {
		const error = new Error(
			`Isolated kernel worker exited early (code ${code}, signal ${signal})\nstderr:\n${stderr}`,
		);
		readyReject(error);
		for (const waiter of pending.values()) waiter.reject(error);
		pending.clear();
	});
	let sequence = 0;
	const request = (type: "list" | "probe" | "stop") => {
		const id = `worker-request-${++sequence}`;
		const response = new Promise<WorkerReply>((resolveReply, rejectReply) => {
			pending.set(id, { resolve: resolveReply, reject: rejectReply });
		});
		child.stdin?.write(`${JSON.stringify({ id, type })}\n`);
		return response;
	};
	return { child, ready, request };
}

describe("isolated status/list kernel survival", () => {
	it("keeps a worker-owned active IPython tool, sibling kernels, and shared forkserver alive", async () => {
		if (process.platform !== "linux") return;
		const root = mkdtempSync(join(tmpdir(), "prime-status-kernel-survival-"));
		roots.add(root);
		const workerRoot = join(root, "worker-root");
		mkdirSync(workerRoot, { recursive: true });
		const workerProcess = spawnKernelWorker(workerRoot);
		const ready = await workerProcess.ready;
		expect(ready.kernelPids).toHaveLength(3);
		expect(new Set(ready.kernelPids).size).toBe(3);
		for (const pid of [ready.workerPid, ...ready.kernelPids, ready.forkserverPid]) assertAlive(pid);

		const first = ready.summaries[0]!;
		const worker = {
			descriptor: {
				workerId: "isolated-worker",
				lifecycle: "ready",
				rootActiveSessionId: first.activeSessionId ?? first.id,
				rootSessionId: first.sessionId,
				pid: ready.workerPid,
				createCommand: { type: "create", sessionPath: first.sessionFile },
				sessionFile: first.sessionFile,
			},
			descriptorPath: join(root, "isolated-worker.json"),
			client: {
				request: vi.fn(async () => {
					const reply = await workerProcess.request("list");
					if (!reply.success) throw new Error(reply.error);
					return success(undefined, "list", { sessions: reply.summaries });
				}),
				requestWorker: vi.fn(async () => success(undefined, "list")),
				close: vi.fn(),
			},
			summaries: new Map(ready.summaries.map((item) => [item.activeSessionId ?? item.id, item])),
			snapshotCache: new Map(),
			transcriptCaches: new Map(),
			snapshotGenerations: new Map(),
			snapshotLoads: new Map(),
			intentionalStop: false,
			stopRevision: 0,
		};
		const supervisor = new DaemonSupervisor(join(root, "unused-supervisor.sock"), {
			descriptorDir: join(root, "supervisor-root"),
			defaultSessionConfig: { cwd: root, agentDir: join(root, "agent") },
		}) as unknown as {
			workers: Map<string, typeof worker>;
			clients: Set<{ attachedActiveSessionIds: Set<string> }>;
			shuttingDown: boolean;
			streamReconstructor: { seed: ReturnType<typeof vi.fn>; clear: ReturnType<typeof vi.fn> };
			persistWorker: ReturnType<typeof vi.fn>;
			log: ReturnType<typeof vi.fn>;
			handleList(
				client: { attachedActiveSessionIds: Set<string> },
				command: { id: string; type: "list"; all: boolean },
			): Promise<{ success: boolean; data?: { sessions?: SessionSummary[] } }>;
		};
		supervisor.workers = new Map([[worker.descriptor.workerId, worker]]);
		supervisor.clients = new Set();
		supervisor.shuttingDown = false;
		supervisor.streamReconstructor = { seed: vi.fn(), clear: vi.fn() };
		supervisor.persistWorker = vi.fn();
		supervisor.log = vi.fn();
		const caller = { attachedActiveSessionIds: new Set<string>() };

		const responses = await Promise.all(
			Array.from({ length: 1_000 }, (_, index) =>
				supervisor.handleList(caller, { id: `isolated-status-${index}`, type: "list", all: false }),
			),
		);
		expect(responses.every((response) => response.success && response.data?.sessions?.length === 3)).toBe(true);
		expect(worker.client.request).toHaveBeenCalledTimes(1);
		for (const pid of [ready.workerPid, ...ready.kernelPids, ready.forkserverPid]) assertAlive(pid);

		const probe = await workerProcess.request("probe");
		expect(probe).toMatchObject({
			success: true,
			stdout: ["sibling-a-after", "sibling-b-after"],
		});
		for (const pid of [ready.workerPid, ...ready.kernelPids, ready.forkserverPid]) assertAlive(pid);

		const stopped = await workerProcess.request("stop");
		expect(stopped.success).toBe(true);
		await waitForExit(workerProcess.child);
		children.delete(workerProcess.child);
	}, 60_000);
});
