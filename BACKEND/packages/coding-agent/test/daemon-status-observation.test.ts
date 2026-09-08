import { mkdtempSync, rmSync } from "node:fs";
import { createConnection, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DaemonSocketClient } from "../src/modes/daemon/active-session-state.js";
import { workerRosterEntryFromSummary } from "../src/modes/daemon/agent-roster.js";
import { DaemonClient } from "../src/modes/daemon/daemon-client.js";
import {
	DAEMON_COMMAND_COMPATIBILITY,
	DAEMON_DEFAULT_SERVER_CAPABILITIES,
	DAEMON_OUTBOUND_COMPATIBILITY,
	DAEMON_PROTOCOL_INFO,
	DAEMON_SCHEMA_REVISION,
	type DaemonCommand,
	type DaemonListResult,
	type DaemonResponse,
	success,
} from "../src/modes/daemon/daemon-protocol.js";
import type { SessionSummary } from "../src/modes/daemon/daemon-session-list.js";
import { DaemonSupervisor } from "../src/modes/daemon/daemon-supervisor.js";
import { attachJsonlLineReader } from "../src/modes/rpc/jsonl.js";

function summary(id: string, busy = false): SessionSummary {
	return {
		id,
		activeSessionId: id,
		sessionId: `${id}-session`,
		cwd: "/tmp",
		lifecycle: "live",
		activity: busy ? "working" : "idle",
		isSessionActive: busy,
		isStreaming: busy,
		isCompacting: false,
		attachedClients: 0,
		messageCount: 1,
		sessionActions: { queuedCount: 0, steering: [], followUps: [] },
	};
}

function worker(id: string, busy = false) {
	const row = summary(id, busy);
	return {
		descriptor: {
			workerId: id,
			rootActiveSessionId: id,
			pid: 123,
			lifecycle: "ready",
			ownerClientId: undefined as string | undefined,
			stopRequestedAt: undefined as string | undefined,
			createCommand: { type: "create" },
		},
		client: {
			request: vi.fn(
				async (_command: unknown, _timeout?: number): Promise<DaemonResponse> =>
					success(undefined, "list", { sessions: [row] }),
			),
			requestWorker: vi.fn(async (): Promise<DaemonResponse> => success(undefined, "list")),
			close: vi.fn(),
		},
		summaries: new Map([[id, row]]),
		snapshotCache: new Map(),
		transcriptCaches: new Map(),
		snapshotLoads: new Map(),
		snapshotGenerations: new Map(),
		intentionalStop: false,
		stopRevision: 0,
		lastFrameAt: Date.now(),
		rosterStale: false,
		rosterApplyChain: undefined as Promise<void> | undefined,
	};
}

type Worker = ReturnType<typeof worker>;
interface SupervisorHarness {
	workers: Map<string, Worker>;
	handleList(client: DaemonSocketClient, command: Extract<DaemonCommand, { type: "list" }>): Promise<DaemonResponse>;
	writeRosterEntry(entry: ReturnType<typeof workerRosterEntryFromSummary>, worker: Worker): void;
	persistWorker: ReturnType<typeof vi.fn>;
	connectWorker: ReturnType<typeof vi.fn>;
	stopWorker: ReturnType<typeof vi.fn>;
	recoverWorker: ReturnType<typeof vi.fn>;
}

const directories: string[] = [];
function harness(): SupervisorHarness {
	const dir = mkdtempSync(join(tmpdir(), "daemon-status-observation-"));
	directories.push(dir);
	const supervisor = new DaemonSupervisor(join(dir, "daemon.sock"), {
		defaultSessionConfig: { agentDir: dir, cwd: dir },
	}) as unknown as SupervisorHarness;
	supervisor.persistWorker = vi.fn();
	supervisor.connectWorker = vi.fn();
	supervisor.stopWorker = vi.fn();
	supervisor.recoverWorker = vi.fn();
	return supervisor;
}

const viewer = { id: "viewer" } as DaemonSocketClient;
afterEach(() => {
	vi.useRealTimers();
	for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function register(supervisor: SupervisorHarness, target: Worker): void {
	supervisor.workers.set(target.descriptor.workerId, target);
	for (const row of target.summaries.values()) supervisor.writeRosterEntry(workerRosterEntryFromSummary(row), target);
}

describe("observational daemon lists", () => {
	it("keeps failed roster repair stale across heartbeats until a complete snapshot applies", async () => {
		const supervisor = harness();
		const target = worker("root");
		register(supervisor, target);
		const liveEdges = vi.fn(async () => {
			throw new Error("ledger unavailable");
		});
		Object.assign(supervisor, { rlmSpawnLedger: () => ({ liveEdges }) });
		target.client.request.mockRejectedValue(new Error("repair unavailable"));
		const apply = (delta: object) =>
			Reflect.apply(Reflect.get(supervisor, "applyWorkerRosterSnapshot"), supervisor, [
				target,
				delta,
				target.client,
			]) as Promise<void>;
		const snapshot = {
			type: "roster_delta",
			snapshot: true,
			entries: [workerRosterEntryFromSummary(summary("root"))],
		};
		await apply(snapshot);
		await Reflect.get(target, "rosterRepairPull");
		target.lastFrameAt = Date.now();
		Reflect.apply(Reflect.get(supervisor, "clearRosterStaleness"), supervisor, [target]);
		const count = target.client.request.mock.calls.length;
		expect(await supervisor.handleList(viewer, { type: "list" })).toMatchObject({
			data: { observation: { status: "stale" } },
		});
		expect(target.client.request).toHaveBeenCalledTimes(count);
		Object.assign(supervisor, { rlmSpawnLedger: () => ({ liveEdges: async () => [] }) });
		await apply(snapshot);
		expect(await supervisor.handleList(viewer, { type: "list" })).toMatchObject({
			data: { observation: { status: "fresh" } },
		});
	});

	it("serves repeated public status locally while workers cannot answer, preserving both siblings", async () => {
		const supervisor = harness();
		const first = worker("first", true);
		const second = worker("second", true);
		for (const target of [first, second]) {
			target.client.request.mockImplementation(() => new Promise(() => {}));
			register(supervisor, target);
		}
		const descriptors = [structuredClone(first.descriptor), structuredClone(second.descriptor)];
		const started = performance.now();
		const results = await Promise.all(
			Array.from({ length: 100 }, () => supervisor.handleList(viewer, { type: "list" })),
		);
		expect(performance.now() - started).toBeLessThan(1000);
		for (const response of results)
			expect(response).toMatchObject({
				success: true,
				data: { sessions: [{ id: "first" }, { id: "second" }], observation: { status: "fresh" } },
			});
		expect([first.descriptor, second.descriptor]).toEqual(descriptors);
		for (const effect of [
			supervisor.persistWorker,
			supervisor.connectWorker,
			supervisor.stopWorker,
			supervisor.recoverWorker,
			first.client.request,
			second.client.request,
			first.client.requestWorker,
			second.client.requestWorker,
			first.client.close,
			second.client.close,
		])
			expect(effect).not.toHaveBeenCalled();
	});

	it.each(["old frame", "disconnected", "pending roster", "failed lifecycle"])(
		"does not report an empty hidden worker as idle with %s",
		async (fault) => {
			const supervisor = harness();
			const target = worker("hidden");
			target.descriptor.ownerClientId = "other";
			target.summaries.clear();
			if (fault === "old frame") target.lastFrameAt = 0;
			if (fault === "disconnected") Reflect.set(target, "client", undefined);
			if (fault === "pending roster") target.rosterApplyChain = new Promise(() => {});
			if (fault === "failed lifecycle") target.descriptor.lifecycle = "failed";
			register(supervisor, target);
			expect(await supervisor.handleList(viewer, { type: "list", includeClientOwned: true })).toMatchObject({
				success: true,
				data: { sessions: [], observation: { status: "stale", workers: [] } },
			});
		},
	);

	it("reports an empty daemon fresh and an unobserved worker unavailable", async () => {
		const supervisor = harness();
		expect(await supervisor.handleList(viewer, { type: "list" })).toMatchObject({
			data: { observation: { status: "fresh" } },
		});
		const target = worker("unknown");
		Reflect.set(target, "lastFrameAt", undefined);
		register(supervisor, target);
		expect(await supervisor.handleList(viewer, { type: "list" })).toMatchObject({
			data: { observation: { status: "unavailable" } },
		});
	});
	it("keeps new clients compatible with old daemon list responses", async () => {
		const dir = mkdtempSync(join(tmpdir(), "daemon-observation-old-server-"));
		directories.push(dir);
		const socketPath = join(dir, "daemon.sock");
		const server = createServer((socket) => {
			socket.write(
				`${JSON.stringify({ type: "daemon_hello", socketPath, protocol: DAEMON_PROTOCOL_INFO, schemaRevision: 22, clientId: "old-client", serverCapabilities: [] })}\n`,
			);
			attachJsonlLineReader(socket, (line) => {
				const envelope = JSON.parse(line) as { id: string; command: DaemonCommand };
				socket.write(`${JSON.stringify(success(envelope.id, "list", { sessions: [summary("legacy")] }))}\n`);
			});
		});
		await new Promise<void>((resolve) => server.listen(socketPath, resolve));
		const client = new DaemonClient(socketPath);
		try {
			await client.connect();
			await client.waitForHello();
			expect(client.supportsServerCapability("list_observation")).toBe(false);
			const response = await client.request({ type: "list" });
			expect(response).toMatchObject({ success: true, data: { sessions: [{ id: "legacy" }] } });
			if (!response.success) throw new Error(response.error);
			expect((response.data as DaemonListResult).observation).toBeUndefined();
		} finally {
			client.close();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});

	it("accepts old client list commands and preserves their session rows in new responses", async () => {
		const supervisor = harness();
		register(supervisor, worker("root"));
		const dir = mkdtempSync(join(tmpdir(), "daemon-observation-old-client-"));
		directories.push(dir);
		const socketPath = join(dir, "daemon.sock");
		const server = createServer((socket) => {
			attachJsonlLineReader(socket, (line) => {
				const command = JSON.parse(line) as Extract<DaemonCommand, { type: "list" }>;
				void supervisor
					.handleList(viewer, command)
					.then((response) => socket.write(`${JSON.stringify(response)}\n`));
			});
		});
		await new Promise<void>((resolve) => server.listen(socketPath, resolve));
		const socket = createConnection(socketPath);
		try {
			const received = new Promise<{ success: boolean; data: { sessions: SessionSummary[] } }>((resolve) => {
				attachJsonlLineReader(socket, (line) => resolve(JSON.parse(line)));
			});
			socket.write(`${JSON.stringify({ type: "list", id: "legacy" })}\n`);
			expect(await received).toMatchObject({ success: true, data: { sessions: [{ id: "root" }] } });
			expect(DAEMON_SCHEMA_REVISION).toBe(28);
			expect(DAEMON_DEFAULT_SERVER_CAPABILITIES).toContain("list_observation");
			expect(DAEMON_COMMAND_COMPATIBILITY.list).toEqual({ minProtocol: 7 });
			expect(DAEMON_OUTBOUND_COMPATIBILITY.response).toEqual({ minProtocol: 7 });
		} finally {
			socket.destroy();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});
});
