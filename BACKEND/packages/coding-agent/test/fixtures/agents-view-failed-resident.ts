import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import type { AgentSessionRuntimeConfig } from "../../src/core/agent-session-config.js";
import { getProcessStartId } from "../../src/core/session-lease.js";
import {
	AgentsViewMode,
	type AgentsViewModeOptions,
	openAgentsViewSession,
} from "../../src/modes/agents-view/agents-view-mode.js";
import { isDaemonCatalogProcess, runDaemonCatalogProcess } from "../../src/modes/daemon/daemon-catalog-process.js";
import { DaemonClient } from "../../src/modes/daemon/daemon-client.js";
import { collectDaemonLaunchEnv } from "../../src/modes/daemon/daemon-protocol.js";
import type { SessionSummary } from "../../src/modes/daemon/daemon-session-list.js";
import { DaemonSupervisor } from "../../src/modes/daemon/daemon-supervisor.js";

const fixturePath = fileURLToPath(import.meta.url);
const root = process.env.AGENTS_VIEW_RESUME_ROOT;
assert(root, "Fixture requires its own root");
const socketPath = join(root, "daemon.sock");
const tsxPath = resolve(dirname(fixturePath), "../../../../node_modules/tsx/dist/cli.mjs");

interface WorkerIdentity {
	workerId: string;
	pid: number;
	processStartId?: string;
	lifecycle: string;
	rootActiveSessionId: string;
	ownerClientId?: string;
}

interface FaultWorker {
	descriptor: WorkerIdentity;
	client?: { close(): void };
	recovery?: Promise<void>;
	intentionalStop: boolean;
}

interface ControlReply {
	id: number;
	error?: string;
	workers?: WorkerIdentity[];
}

async function runSupervisor(): Promise<never> {
	// Worker/catalog launch specifications resolve the real production CLI.
	process.argv[1] = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));
	const supervisor = new DaemonSupervisor(socketPath, {
		descriptorDir: join(root!, "descriptors"),
		defaultSessionConfig: { agentDir: join(root!, "agent"), cwd: join(root!, "project"), noContextFiles: true },
	});
	await supervisor.start();
	process.send?.({ id: 0 });
	process.on("message", (message: unknown) => {
		const command = message as { id: number; action: string; activeSessionId?: string; processStartId?: string };
		try {
			const workers = Reflect.get(supervisor, "workers") as Map<string, FaultWorker>;
			if (
				command.action === "fail" ||
				command.action === "forget_identity" ||
				command.action === "restore_identity"
			) {
				const worker = [...workers.values()].find(
					(candidate) => candidate.descriptor.rootActiveSessionId === command.activeSessionId,
				);
				assert(worker, "Fault injection may target only a fixture-owned registration");
				if (command.action === "fail") {
					assert.equal(worker.descriptor.lifecycle, "ready");
					assert.equal(worker.descriptor.ownerClientId, undefined);
					assert.equal(worker.recovery, undefined);
					assert(worker.client);
					assert.equal(getProcessStartId(worker.descriptor.pid), worker.descriptor.processStartId);
					// Explicit fault setup only. Creation, attachment, replacement, and
					// prompts below still cross the real supervisor and worker sockets.
					worker.intentionalStop = true;
					worker.client.close();
					worker.client = undefined;
					worker.descriptor.lifecycle = "failed";
					worker.intentionalStop = false;
				} else {
					worker.descriptor.processStartId =
						command.action === "restore_identity" ? command.processStartId : undefined;
				}
				Reflect.apply(Reflect.get(supervisor, "persistWorker"), supervisor, [worker]);
			}
			process.send?.({
				id: command.id,
				workers: [...workers.values()].map(({ descriptor }) => ({
					workerId: descriptor.workerId,
					pid: descriptor.pid,
					processStartId: descriptor.processStartId,
					lifecycle: descriptor.lifecycle,
					rootActiveSessionId: descriptor.rootActiveSessionId,
					ownerClientId: descriptor.ownerClientId,
				})),
			});
		} catch (error) {
			process.send?.({ id: command.id, error: String(error) });
		}
	});
	return new Promise<never>(() => {});
}

function control(child: ChildProcess) {
	let nextId = 1;
	const replies = new Map<number, ControlReply>();
	child.on("message", (message: unknown) => {
		const reply = message as ControlReply;
		replies.set(reply.id, reply);
	});
	async function receive(id: number): Promise<ControlReply> {
		const deadline = Date.now() + 30_000;
		while (Date.now() < deadline) {
			const reply = replies.get(id);
			if (reply) {
				replies.delete(id);
				assert.equal(reply.error, undefined);
				return reply;
			}
			assert.equal(child.exitCode, null, "Fixture supervisor exited");
			assert.equal(child.signalCode, null, "Fixture supervisor was signalled");
			await delay(10);
		}
		throw new Error(`Control reply ${id} timed out`);
	}
	return {
		ready: () => receive(0),
		request: async (action: string, activeSessionId?: string, processStartId?: string) => {
			const id = nextId++;
			child.send({ id, action, activeSessionId, processStartId });
			return (await receive(id)).workers!;
		},
	};
}

function savedSummary(summary: SessionSummary): SessionSummary {
	const { activeSessionId: _activeSessionId, workerPid: _workerPid, workerState: _workerState, ...saved } = summary;
	return { ...saved, id: summary.sessionId, isSessionActive: false, attachedClients: 0 };
}

function invoke(name: string, self: object, ...args: unknown[]): unknown {
	return Reflect.apply(Reflect.get(AgentsViewMode.prototype, name), self, args);
}

function replyHarness(options: AgentsViewModeOptions, client: DaemonClient, summary: SessionSummary) {
	const target = { key: `file:${summary.sessionFile}`, summary };
	const statuses: string[] = [];
	let selected: SessionSummary | undefined;
	const self = {
		options,
		replyTarget: target,
		inactiveAgentIdentities: new Set([target.key]),
		requireClient: () => client,
		requireSocketPath: () => socketPath,
		findSummaryByActiveSessionId: () => undefined,
		setStatusMessage: (message: string) => statuses.push(message),
		selectSummary: (value: SessionSummary) => {
			selected = value;
		},
		refreshSessions: async () => true,
		connectDedicatedClient: () => invoke("connectDedicatedClient", self),
		sendPrompt: (...args: unknown[]) => invoke("sendPrompt", self, ...args),
	};
	return {
		send: (text: string) => invoke("sendReply", self, target, text) as Promise<boolean>,
		statuses,
		selected: () => selected,
	};
}

async function waitFor(read: () => boolean, description: string): Promise<void> {
	const deadline = Date.now() + 15_000;
	while (Date.now() < deadline) {
		if (read()) return;
		await delay(20);
	}
	throw new Error(`Timed out: ${description}`);
}

function assistantCount(path: string): number {
	return readFileSync(path, "utf8")
		.trim()
		.split("\n")
		.map((line) => JSON.parse(line))
		.filter((entry) => entry.type === "message" && entry.message?.role === "assistant").length;
}

async function runScenario(scenario: string): Promise<void> {
	const child = spawn(process.execPath, [tsxPath, fixturePath, "supervisor"], {
		cwd: join(root!, "project"),
		env: process.env,
		stdio: ["ignore", "pipe", "pipe", "ipc"],
	});
	let output = "";
	for (const stream of [child.stdout, child.stderr])
		stream?.on("data", (chunk: Buffer) => {
			output = (output + chunk.toString("utf8")).slice(-64 * 1024);
		});
	const controls = control(child);
	const client = new DaemonClient(socketPath);
	const owned = new Map<number, string>();
	const config: AgentSessionRuntimeConfig = {
		cwd: join(root!, "project"),
		agentDir: join(root!, "agent"),
		sessionDir: join(root!, "sessions"),
		provider: "faux",
		model: "faux",
		extensions: [fileURLToPath(new URL("eng-4600-faux-extension.ts", import.meta.url))],
		noTools: true,
		noSkills: true,
		noPromptTemplates: true,
		noThemes: true,
		noContextFiles: true,
		telemetryDisabled: true,
	};
	// These production transport helpers never access UI services. Only the
	// terminal rendering boundary is absent; no DaemonClient method is replaced.
	const options = { socketPath, config } as AgentsViewModeOptions;
	const connections: Array<{ dispose(): Promise<void> }> = [];
	let original: WorkerIdentity | undefined;
	function rememberOwnedWorkers(): void {
		for (const name of readdirSync(join(root!, "descriptors"))) {
			if (!name.endsWith(".json")) continue;
			try {
				const descriptor = JSON.parse(readFileSync(join(root!, "descriptors", name), "utf8")) as WorkerIdentity;
				if (descriptor.processStartId && Number.isInteger(descriptor.pid))
					owned.set(descriptor.pid, descriptor.processStartId);
			} catch {
				/* A descriptor can be removed by normal stop finalization. */
			}
		}
	}
	function killOwnedWorkers(): void {
		rememberOwnedWorkers();
		for (const [pid, identity] of owned) {
			try {
				if (getProcessStartId(pid) === identity) process.kill(pid, "SIGKILL");
			} catch {
				/* Already exited. */
			}
		}
	}
	const onTermination = () => {
		// A parent test deadline still cleans up detached worker children using
		// only identities from this fixture's private descriptor directory.
		killOwnedWorkers();
		child.kill("SIGKILL");
		process.exit(143);
	};
	process.once("SIGTERM", onTermination);
	try {
		await controls.ready();
		await client.connect();
		await client.waitForHello();
		const created = await client.request({ type: "create", config, launchEnv: collectDaemonLaunchEnv() }, 60_000);
		assert(created.success, created.success ? undefined : created.error);
		const summary = created.data as SessionSummary;
		assert(summary.activeSessionId && summary.workerPid && summary.sessionFile);
		const sessionFile = summary.sessionFile;
		assert.equal(summary.workerState, "ready");
		original = (await controls.request("state")).find((worker) => worker.pid === summary.workerPid);
		assert(original?.processStartId);
		assert.equal(getProcessStartId(original.pid), original.processStartId);
		owned.set(original.pid, original.processStartId);
		const seedText = `saved prefix sentinel ${scenario}`;
		const seeded = await client.request(
			{ type: "prompt_and_wait", activeSessionId: summary.activeSessionId, message: seedText },
			30_000,
		);
		assert(seeded.success, seeded.success ? undefined : seeded.error);
		const prefix = readFileSync(summary.sessionFile);
		assert(prefix.includes(seedText));
		assert(prefix.includes("upgrade response 1"));
		assert.equal(assistantCount(sessionFile), 1);
		const failed = await controls.request("fail", summary.activeSessionId);
		assert.equal(failed.length, 1);
		assert.equal(failed[0]!.lifecycle, "failed");
		assert.equal(getProcessStartId(original.pid), original.processStartId);
		const saved = savedSummary(summary);
		// Upstream can reconnect a verified surviving worker without launch context.
		// Preserve that recovery, then inject the fault again for explicit replacement.
		const rejected = await client.request({ type: "create", config, sessionPath: saved.sessionFile });
		assert(rejected.success, rejected.success ? undefined : rejected.error);
		assert.deepEqual(readFileSync(summary.sessionFile), prefix);
		assert.equal(getProcessStartId(original.pid), original.processStartId);
		assert.equal((await controls.request("state"))[0]!.pid, original.pid);
		await controls.request("fail", summary.activeSessionId);

		if (scenario === "unknown-identity") {
			await controls.request("forget_identity", summary.activeSessionId);
			await assert.rejects(
				openAgentsViewSession(options, saved),
				/failed worker that could not be safely reclaimed/,
			);
			const reply = replyHarness(options, client, saved);
			assert.equal(await reply.send("must not be delivered"), false);
			assert.match(reply.statuses.at(-1)!, /failed worker that could not be safely reclaimed/);
			assert.equal(reply.selected(), undefined);
			assert.deepEqual(readFileSync(summary.sessionFile), prefix);
			assert.equal(getProcessStartId(original.pid), original.processStartId);
			const workers = await controls.request("state");
			assert.equal(workers.length, 1);
			assert.equal(workers[0]!.pid, original.pid);
			assert.equal(workers[0]!.lifecycle, "failed");
			await controls.request("restore_identity", summary.activeSessionId, original.processStartId);
		}
		if (scenario === "failed-launch-retry") {
			await assert.rejects(async () => {
				// A regular file cannot be the replacement worker's agent directory.
				const unexpected = await openAgentsViewSession(
					{
						...options,
						config: { ...config, agentDir: join(root!, "agent", "settings.json") },
					},
					saved,
				);
				connections.push(unexpected.connection);
			}, /ENOTDIR|not a directory|EEXIST/);
			assert.equal(
				(await controls.request("state")).length,
				0,
				"Failed launch must release its registration before retry",
			);
			assert.deepEqual(readFileSync(sessionFile).subarray(0, prefix.length), prefix);
		}
		{
			let resumed: SessionSummary;
			if (scenario === "inactive-reply") {
				const reply = replyHarness(options, client, saved);
				assert.equal(await reply.send("real inactive reply"), true, reply.statuses.join(" | "));
				resumed = reply.selected()!;
				assert(resumed);
				assert.equal(reply.statuses.at(-1), "Reply sent");
				await waitFor(
					() => readFileSync(sessionFile).includes("real inactive reply") && assistantCount(sessionFile) === 2,
					"replacement completed the actual inactive reply",
				);
			} else if (scenario === "concurrent-open") {
				const results = await Promise.allSettled([
					openAgentsViewSession(options, saved),
					openAgentsViewSession(options, saved),
				]);
				for (const result of results) if (result.status === "fulfilled") connections.push(result.value.connection);
				assert.equal(
					results.filter((result) => result.status === "fulfilled").length,
					2,
					results.map((result) => (result.status === "rejected" ? String(result.reason) : "opened")).join(" | "),
				);
				const opened = results.map(
					(result) => (result as PromiseFulfilledResult<Awaited<ReturnType<typeof openAgentsViewSession>>>).value,
				);
				assert.equal(opened[0]!.summary.activeSessionId, opened[1]!.summary.activeSessionId);
				assert.equal(opened[0]!.summary.workerPid, opened[1]!.summary.workerPid);
				resumed = opened[0]!.summary;
			} else {
				const opened = await openAgentsViewSession(options, saved);
				connections.push(opened.connection);
				resumed = opened.summary;
				await opened.connection.prompt("real saved open reply");
				await waitFor(
					() => readFileSync(sessionFile).includes("real saved open reply") && assistantCount(sessionFile) === 2,
					"opened connection completed a real provider response",
				);
			}
			assert(resumed.activeSessionId && resumed.workerPid);
			assert.notEqual(resumed.workerPid, original.pid);
			assert.notEqual(resumed.activeSessionId, summary.activeSessionId);
			assert.equal(resumed.sessionId, summary.sessionId);
			assert.equal(resumed.sessionFile, summary.sessionFile);
			assert.equal(resumed.workerState, "ready");
			const workers = await controls.request("state");
			assert.equal(workers.length, 1, "No duplicate resident may survive explicit resume");
			const replacement = workers[0]!;
			assert.equal(replacement.pid, resumed.workerPid);
			assert(replacement.processStartId);
			owned.set(replacement.pid, replacement.processStartId);
			assert.equal(getProcessStartId(replacement.pid), replacement.processStartId);
			await waitFor(
				() => getProcessStartId(original!.pid) !== original!.processStartId,
				"old verified worker exited",
			);
			assert.deepEqual(readFileSync(summary.sessionFile).subarray(0, prefix.length), prefix);
		}
		process.stdout.write(`AGENTS_VIEW_RESUME_PASS ${scenario}\n`);
	} catch (error) {
		process.stderr.write(output);
		throw error;
	} finally {
		for (const connection of connections) await connection.dispose().catch(() => undefined);
		// Only the fixture's exact socket receives shutdown; no public discovery.
		rememberOwnedWorkers();
		await client.request({ type: "shutdown", force: true }, 10_000).catch(() => undefined);
		client.close();
		await waitFor(() => child.exitCode !== null || child.signalCode !== null, "owned supervisor shutdown").catch(() =>
			child.kill("SIGKILL"),
		);
		killOwnedWorkers();
		process.off("SIGTERM", onTermination);
	}
}

async function main(): Promise<void> {
	if (isDaemonCatalogProcess()) return runDaemonCatalogProcess();
	if (process.argv[2] === "supervisor") return runSupervisor();
	await runScenario(process.argv[2]!);
}

void main().catch((error) => {
	process.stderr.write(`${error instanceof Error ? error.stack : error}\n`);
	process.exitCode = 1;
});
