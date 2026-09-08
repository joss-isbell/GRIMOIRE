import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonicalSessionPath } from "../src/core/session-lease.js";
import type { AgentRoster } from "../src/modes/daemon/agent-roster.js";
import type { DaemonCommand } from "../src/modes/daemon/daemon-protocol.js";
import { DaemonSupervisor } from "../src/modes/daemon/daemon-supervisor.js";

interface TestWorker {
	client?: object;
	descriptor: { workerId: string; lifecycle: string; ownerClientId?: string; rootActiveSessionId: string };
}

interface OpenInternals {
	openingWorkers: Map<string, Promise<TestWorker>>;
	createOrReuseWorker(clientId: string, command: Extract<DaemonCommand, { type: "create" }>): Promise<TestWorker>;
}

const directories: string[] = [];
afterEach(() => {
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function setup() {
	const directory = mkdtempSync(join(tmpdir(), "supervisor-open-reservation-"));
	directories.push(directory);
	const supervisor = new DaemonSupervisor(join(directory, "daemon.sock"), {
		defaultSessionConfig: { agentDir: directory, cwd: directory },
		descriptorDir: join(directory, "workers"),
	}) as unknown as OpenInternals;
	return { supervisor, sessionPath: join(directory, "saved.jsonl") };
}

describe("saved session opening reservation fences", () => {
	it("pins a resolved active alias to its saved file before another mutation can rename it", async () => {
		const { supervisor, sessionPath } = setup();
		const original: TestWorker = {
			descriptor: { workerId: "original", lifecycle: "ready", rootActiveSessionId: "original-active" },
			client: {},
		};
		const other: TestWorker = {
			descriptor: { workerId: "other", lifecycle: "ready", rootActiveSessionId: "other-active" },
		};
		(Reflect.get(supervisor, "workers") as Map<string, TestWorker>).set("original", original);
		const roster = Reflect.apply(Reflect.get(supervisor, "roster"), supervisor, []) as AgentRoster;
		roster.write(
			{
				agentId: "original",
				summary: {
					sessionId: "original",
					activeSessionId: "original-active",
					id: "original-active",
					cwd: "/tmp",
					lifecycle: "live",
					activity: "idle",
					isSessionActive: false,
					isStreaming: false,
					isCompacting: false,
					attachedClients: 0,
					messageCount: 0,
				},
			},
			"original",
		);
		let namedWorker = original;
		const reclaim = vi.fn(async () => false);
		Object.assign(supervisor, {
			matchWorkers: (selector: string) =>
				selector === "named" ? [{ worker: namedWorker, summary: { sessionFile: sessionPath } }] : [],
			findWorkerBySessionFile: (path: string) => (path === sessionPath ? original : undefined),
			reclaimStaleWorkerRegistration: reclaim,
		});
		const opening = supervisor.createOrReuseWorker("client", { type: "create", sessionPath: "named" });
		namedWorker = other;
		await expect(opening).resolves.toBe(original);
		expect(reclaim).toHaveBeenCalledExactlyOnceWith(original, false);
	});

	it.each(["cleared", "replaced"])(
		"does not launch from a %s reservation after reclamation awaits",
		async (change) => {
			const { supervisor, sessionPath } = setup();
			const oldWorker: TestWorker = {
				descriptor: { workerId: "old", lifecycle: "failed", rootActiveSessionId: "old-active" },
			};
			let release!: () => void;
			const gate = new Promise<void>((resolve) => {
				release = resolve;
			});
			const reclaim = vi.fn(async () => {
				await gate;
				return true;
			});
			const launch = vi.fn();
			Object.assign(supervisor, {
				findWorkerBySessionFile: () => oldWorker,
				reclaimStaleWorkerRegistration: reclaim,
				launchWorker: launch,
			});
			const opening = supervisor.createOrReuseWorker("client", { type: "create", sessionPath, launchEnv: {} });
			const rejected = expect(opening).rejects.toThrow("Session opening was superseded");
			await vi.waitFor(() => expect(reclaim).toHaveBeenCalledOnce());
			const key = canonicalSessionPath(sessionPath);
			expect(supervisor.openingWorkers.has(key)).toBe(true);
			const newer = Promise.resolve(oldWorker);
			if (change === "replaced") supervisor.openingWorkers.set(key, newer);
			else supervisor.openingWorkers.clear();
			release();
			await rejected;
			expect(launch).not.toHaveBeenCalled();
			expect(supervisor.openingWorkers.get(key)).toBe(change === "replaced" ? newer : undefined);
		},
	);

	it("checks the waiting client's ownership when it joins an opening", async () => {
		const { supervisor, sessionPath } = setup();
		let release!: () => void;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const worker: TestWorker = {
			descriptor: {
				workerId: "owned",
				lifecycle: "ready",
				ownerClientId: "owner",
				rootActiveSessionId: "owned-active",
			},
		};
		const launch = vi.fn(async () => {
			await gate;
			return worker;
		});
		Object.assign(supervisor, { launchWorker: launch });
		const first = supervisor.createOrReuseWorker("owner", { type: "create", sessionPath, lifecycle: "client_owned" });
		const other = supervisor.createOrReuseWorker("other", { type: "create", sessionPath, lifecycle: "client_owned" });
		const refused = expect(other).rejects.toThrow(/already active/);
		release();
		await expect(first).resolves.toBe(worker);
		await refused;
		expect(launch).toHaveBeenCalledOnce();
		expect(supervisor.openingWorkers.size).toBe(0);
	});
});
