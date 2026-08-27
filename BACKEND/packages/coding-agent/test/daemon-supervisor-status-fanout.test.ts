import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { success } from "../src/modes/daemon/daemon-protocol.js";
import type { SessionSummary } from "../src/modes/daemon/daemon-session-list.js";
import { DaemonSupervisor } from "../src/modes/daemon/daemon-supervisor.js";

type Priority = "bounded" | "urgent";
type Cause = Record<string, unknown>;

interface Deferred<T> {
	promise: Promise<T>;
	resolve(value: T): void;
	reject(error: unknown): void;
}

interface FakeClient {
	attachedActiveSessionIds: Set<string>;
}

interface FakeWorkerClient {
	request: ReturnType<typeof vi.fn>;
	requestWorker: ReturnType<typeof vi.fn>;
	close: ReturnType<typeof vi.fn>;
}

interface FakeWorker {
	descriptor: {
		workerId: string;
		lifecycle: "ready";
		rootActiveSessionId: string;
		rootSessionId: string;
		pid: number;
		createCommand: { type: "create"; sessionPath?: string; noSession?: boolean };
		sessionFile?: string;
		stopRequestedAt?: string;
	};
	descriptorPath: string;
	client: FakeWorkerClient;
	summaries: Map<string, SessionSummary>;
	snapshotCache: Map<string, unknown>;
	transcriptCaches: Map<string, unknown>;
	snapshotGenerations: Map<string, unknown>;
	snapshotLoads: Map<string, Promise<unknown>>;
	intentionalStop: boolean;
	stopRevision: number;
	eventSummaryRefresh?: {
		active: boolean;
		pending?: {
			coalescedCount: number;
			coalescedCountSaturated?: boolean;
		};
	};
}

interface SupervisorRuntime {
	workers: Map<string, FakeWorker>;
	clients: Set<FakeClient>;
	shuttingDown: boolean;
	streamReconstructor: { seed: ReturnType<typeof vi.fn>; clear: ReturnType<typeof vi.fn> };
	handleList(
		client: FakeClient,
		command: { id: string; type: "list"; all: boolean },
	): Promise<{
		success: boolean;
		data?: { sessions?: SessionSummary[] };
	}>;
	refreshWorkerSummaries(worker: FakeWorker, ...args: unknown[]): Promise<boolean>;
	refreshWorkerSummariesForObservation(worker: FakeWorker, cause: Cause, priority: Priority): Promise<boolean>;
	scheduleWorkerEventSummaryRefresh(worker: FakeWorker, cause: Cause, priority: Priority): void;
	syncAgentPeers(cause?: Cause): Promise<void>;
	persistWorker: ReturnType<typeof vi.fn>;
	log: ReturnType<typeof vi.fn>;
	[key: string]: unknown;
}

const roots = new Set<string>();

function deferred<T>(): Deferred<T> {
	let resolve!: (value: T) => void;
	let reject!: (error: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

async function settle(): Promise<void> {
	await Promise.resolve();
	await Promise.resolve();
	await Promise.resolve();
	await Promise.resolve();
}

function summary(workerId: string, suffix = "cached"): SessionSummary {
	const activeSessionId = `${workerId}-active`;
	return {
		id: activeSessionId,
		activeSessionId,
		sessionId: `${workerId}-session-${suffix}`,
		sessionName: `${workerId}-${suffix}`,
		lifecycle: "live",
		activity: "idle",
		isSessionActive: false,
		lastActivityAt: new Date(0).toISOString(),
		cwd: "/tmp/pure-fixture",
		isStreaming: false,
		isCompacting: false,
		attachedClients: 0,
		messageCount: 1,
		sessionFile: `/tmp/pure-fixture/${workerId}.jsonl`,
		sessionActions: { queuedCount: 0, steering: [], followUps: [] },
	};
}

function workerListResponse(summaries: SessionSummary[]) {
	return success(undefined, "list", { sessions: summaries });
}

function fakeCaller(): FakeClient {
	return Object.assign(Object.create(null), { attachedActiveSessionIds: new Set<string>() }) as FakeClient;
}

function makeWorker(root: string, workerId: string): FakeWorker {
	const cached = summary(workerId);
	return {
		descriptor: {
			workerId,
			lifecycle: "ready",
			rootActiveSessionId: cached.activeSessionId ?? cached.id,
			rootSessionId: cached.sessionId,
			pid: 100,
			createCommand: { type: "create", sessionPath: cached.sessionFile },
			sessionFile: cached.sessionFile,
		},
		descriptorPath: join(root, `${workerId}.json`),
		client: {
			request: vi.fn(async () => workerListResponse([cached])),
			requestWorker: vi.fn(async () => success(undefined, "list")),
			close: vi.fn(),
		},
		summaries: new Map([[cached.activeSessionId ?? cached.id, cached]]),
		snapshotCache: new Map(),
		transcriptCaches: new Map(),
		snapshotGenerations: new Map(),
		snapshotLoads: new Map(),
		intentionalStop: false,
		stopRevision: 0,
	};
}

function makeHarness(workerCount = 2) {
	const root = mkdtempSync(join(tmpdir(), "prime-status-fanout-"));
	roots.add(root);
	// Construction initializes the production scheduler fields but does not start or connect a socket.
	const runtime = new DaemonSupervisor(join(root, "unused.sock"), {
		descriptorDir: join(root, "descriptors"),
		defaultSessionConfig: { cwd: root, agentDir: root },
	}) as unknown as SupervisorRuntime;
	const workers = Array.from({ length: workerCount }, (_, index) => makeWorker(root, `worker-${index + 1}`));
	runtime.workers = new Map(workers.map((worker) => [worker.descriptor.workerId, worker]));
	runtime.clients = new Set();
	runtime.shuttingDown = false;
	runtime.streamReconstructor = { seed: vi.fn(), clear: vi.fn() };
	runtime.persistWorker = vi.fn();
	runtime.log = vi.fn();
	return { root, runtime, workers };
}

function publicList(runtime: SupervisorRuntime, client = fakeCaller(), id = "status") {
	return runtime.handleList(client, { id, type: "list", all: false });
}

function expectBoundedState(runtime: SupervisorRuntime, workerCount: number): void {
	for (const [key, value] of Object.entries(runtime)) {
		if (!/(summary.*refresh|refresh.*summary|peer.*sync|sync.*peer)/i.test(key)) continue;
		if (value instanceof Map || value instanceof Set) expect(value.size).toBeLessThanOrEqual(workerCount);
		if (Array.isArray(value)) expect(value.length).toBeLessThanOrEqual(workerCount);
	}
	expect(vi.getTimerCount()).toBeLessThanOrEqual(workerCount);
}

beforeEach(() => {
	vi.useFakeTimers();
	vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
});

afterEach(() => {
	vi.useRealTimers();
	for (const root of roots) rmSync(root, { recursive: true, force: true });
	roots.clear();
});

describe("DaemonSupervisor public status/list observation fan-out", () => {
	it("shares 10,000 concurrent public lists across clients and workers", async () => {
		const { runtime, workers } = makeHarness();
		const callers = Array.from({ length: 32 }, () => fakeCaller());
		const responses = await Promise.all(
			Array.from({ length: 10_000 }, (_, index) =>
				publicList(runtime, callers[index % callers.length], `list-${index}`),
			),
		);

		expect(workers.map((worker) => worker.client.request.mock.calls.length)).toEqual([1, 1]);
		expect(responses.every((response) => response.success && response.data?.sessions?.length === 2)).toBe(true);
		expectBoundedState(runtime, workers.length);
	}, 30_000);

	it("keeps sequential public status refreshes bounded for 60 fake seconds", async () => {
		const { runtime, workers } = makeHarness();
		const starts = new Map(workers.map((worker) => [worker.descriptor.workerId, [] as number[]]));
		for (const worker of workers) {
			worker.client.request.mockImplementation(async () => {
				starts.get(worker.descriptor.workerId)?.push(Date.now());
				return workerListResponse([...worker.summaries.values()]);
			});
		}

		for (let second = 0; second <= 60; second++) {
			await publicList(runtime, fakeCaller(), `status-${second}`);
			if (second < 60) await vi.advanceTimersByTimeAsync(1_000);
		}

		for (const workerStarts of starts.values()) {
			expect(workerStarts.length).toBeLessThanOrEqual(13);
			for (let index = 1; index < workerStarts.length; index++) {
				expect(workerStarts[index] - workerStarts[index - 1]).toBeGreaterThanOrEqual(5_000);
			}
		}
		expectBoundedState(runtime, workers.length);
		expect(vi.getTimerCount()).toBe(0);
	});

	it.each(["event-first", "public-first"] as const)(
		"shares an active %s request and runs one urgent structural trailing request",
		async (order) => {
			const { runtime, workers } = makeHarness(1);
			const worker = workers[0]!;
			const first = deferred<ReturnType<typeof workerListResponse>>();
			let active = 0;
			let maxActive = 0;
			worker.client.request.mockImplementationOnce(async () => {
				active++;
				maxActive = Math.max(maxActive, active);
				const response = await first.promise;
				active--;
				return response;
			});
			worker.client.request.mockImplementation(async () => {
				active++;
				maxActive = Math.max(maxActive, active);
				active--;
				return workerListResponse([...worker.summaries.values()]);
			});

			let list: Promise<unknown>;
			if (order === "event-first") {
				runtime.scheduleWorkerEventSummaryRefresh(worker, { causeOutboundType: "child_update" }, "bounded");
				list = publicList(runtime);
			} else {
				list = publicList(runtime);
				runtime.scheduleWorkerEventSummaryRefresh(worker, { causeOutboundType: "session_replaced" }, "urgent");
			}
			expect(worker.client.request).toHaveBeenCalledTimes(1);
			first.resolve(workerListResponse([...worker.summaries.values()]));
			await list;
			await settle();
			expect(worker.client.request).toHaveBeenCalledTimes(order === "event-first" ? 1 : 2);
			expect(maxActive).toBe(1);
			expectBoundedState(runtime, 1);
		},
	);

	it("fingerprints unchanged peers, coalesces changed syncs, and fences a reconnected client generation", async () => {
		const { runtime, workers } = makeHarness();
		await runtime.syncAgentPeers({ causeKind: "fixture_warmup" });
		for (const worker of workers) worker.client.requestWorker.mockClear();

		await Promise.all(Array.from({ length: 100_000 }, () => publicList(runtime)));
		for (const worker of workers) expect(worker.client.requestWorker).not.toHaveBeenCalled();

		const held = deferred<ReturnType<typeof success>>();
		workers[0]!.client.requestWorker.mockImplementationOnce(() => held.promise);
		const changed = summary("worker-2", "changed");
		workers[1]!.summaries = new Map([[changed.activeSessionId ?? changed.id, changed]]);
		const syncs = Array.from({ length: 100_000 }, (_, index) =>
			runtime.syncAgentPeers({ causeKind: "changed_burst", index }),
		);
		await settle();
		for (const worker of workers) expect(worker.client.requestWorker.mock.calls.length).toBeLessThanOrEqual(1);
		held.resolve(success(undefined, "list"));
		await Promise.all(syncs);
		for (const worker of workers) expect(worker.client.requestWorker.mock.calls.length).toBeLessThanOrEqual(2);
		expectBoundedState(runtime, workers.length);

		const replacementClient: FakeWorkerClient = {
			request: vi.fn(async () => workerListResponse([...workers[0]!.summaries.values()])),
			requestWorker: vi.fn(async () => success(undefined, "list")),
			close: vi.fn(),
		};
		workers[0]!.client = replacementClient;
		for (const worker of workers) worker.client.requestWorker.mockClear();
		await runtime.syncAgentPeers({ causeKind: "client_reconnected" });
		expect(replacementClient.requestWorker).toHaveBeenCalledTimes(1);
		expect(workers[1]!.client.requestWorker).toHaveBeenCalledTimes(1);
	}, 30_000);

	it.each(["stop-intent", "shutdown", "replacement", "stop-revision", "client-replacement"] as const)(
		"discards a summary response after %s without any observable mutation",
		async (mode) => {
			const { runtime, workers } = makeHarness(1);
			const worker = workers[0]!;
			const oldSummaries = worker.summaries;
			const oldDescriptor = structuredClone(worker.descriptor);
			const response = deferred<ReturnType<typeof workerListResponse>>();
			worker.client.request.mockReturnValueOnce(response.promise);
			const observation = runtime
				.refreshWorkerSummariesForObservation(worker, { causeKind: "public_list" }, "bounded")
				.catch(() => false);
			await settle();

			if (mode === "stop-intent") worker.intentionalStop = true;
			if (mode === "shutdown") runtime.shuttingDown = true;
			if (mode === "replacement")
				runtime.workers.set(worker.descriptor.workerId, makeWorker(runtime.descriptorDir as string, "worker-1"));
			if (mode === "stop-revision") worker.stopRevision++;
			if (mode === "client-replacement") worker.client = makeWorker(runtime.descriptorDir as string, "other").client;
			response.resolve(workerListResponse([summary("worker-1", "late")]));
			await observation;
			await settle();

			expect(worker.summaries).toBe(oldSummaries);
			expect(worker.descriptor).toEqual(oldDescriptor);
			expect(runtime.streamReconstructor.seed).not.toHaveBeenCalled();
			expect(runtime.streamReconstructor.clear).not.toHaveBeenCalled();
			expect(runtime.persistWorker).not.toHaveBeenCalled();
			expect(worker.client.requestWorker).not.toHaveBeenCalled();
		},
	);

	it("rolls back when persistence throws and retries the still-visible change exactly once", async () => {
		const { runtime, workers } = makeHarness(2);
		const worker = workers[0]!;
		await runtime.syncAgentPeers({ causeKind: "fixture_warmup" });
		for (const candidate of workers) candidate.client.requestWorker.mockClear();
		const oldSummaries = worker.summaries;
		const oldDescriptor = structuredClone(worker.descriptor);
		const changed = summary(worker.descriptor.workerId, "changed");
		worker.client.request.mockResolvedValue(workerListResponse([changed]));
		runtime.persistWorker.mockImplementationOnce(() => {
			throw new Error("fixture persist failure");
		});

		const failedResponse = await publicList(runtime, fakeCaller(), "failed-persist");
		expect(failedResponse.success).toBe(true);
		expect(worker.summaries).toBe(oldSummaries);
		expect(worker.descriptor).toEqual(oldDescriptor);
		expect(worker.client.requestWorker).not.toHaveBeenCalled();

		await vi.advanceTimersByTimeAsync(5_000);
		const retryResponse = await publicList(runtime, fakeCaller(), "retry-persist");
		expect(retryResponse.success).toBe(true);
		expect(worker.summaries.get(changed.activeSessionId ?? changed.id)?.sessionName).toBe(changed.sessionName);
		expect(runtime.persistWorker.mock.calls.filter(([candidate]) => candidate === worker)).toHaveLength(2);
		for (const candidate of workers) expect(candidate.client.requestWorker).toHaveBeenCalledTimes(1);
	});

	it.each(["failure", "timeout"] as const)(
		"returns cached summaries after public worker request %s without a loop or poisoned freshness",
		async (shape) => {
			const { runtime, workers } = makeHarness(1);
			const worker = workers[0]!;
			worker.client.request.mockRejectedValue(
				new Error(shape === "timeout" ? "Timed out refreshing worker summaries" : "fixture request failed"),
			);

			const first = await publicList(runtime, fakeCaller(), `${shape}-1`);
			expect(first.success).toBe(true);
			expect(first.data?.sessions?.[0]?.sessionName).toBe("worker-1-cached");
			expect(worker.client.request).toHaveBeenCalledTimes(1);
			expect(vi.getTimerCount()).toBe(0);
			const backedOff = await publicList(runtime, fakeCaller(), `${shape}-backoff`);
			expect(backedOff.success).toBe(true);
			expect(worker.client.request).toHaveBeenCalledTimes(1);
			await vi.advanceTimersByTimeAsync(5_000);
			const retry = await publicList(runtime, fakeCaller(), `${shape}-retry`);
			expect(retry.success).toBe(true);
			expect(worker.client.request).toHaveBeenCalledTimes(2);
			expect(vi.getTimerCount()).toBe(0);
		},
	);

	it("saturates event cause counts while retaining only bounded initial/latest causes", async () => {
		const { runtime, workers } = makeHarness(1);
		const worker = workers[0]!;
		const first = deferred<ReturnType<typeof workerListResponse>>();
		worker.client.request.mockReturnValueOnce(first.promise);
		runtime.scheduleWorkerEventSummaryRefresh(worker, { sequence: 0 }, "bounded");
		runtime.scheduleWorkerEventSummaryRefresh(worker, { sequence: 1 }, "bounded");
		const pending = worker.eventSummaryRefresh?.pending;
		expect(pending).toBeDefined();
		pending!.coalescedCount = Number.MAX_SAFE_INTEGER - 1;
		for (let sequence = 2; sequence <= 4; sequence++) {
			runtime.scheduleWorkerEventSummaryRefresh(worker, { sequence }, "urgent");
		}
		expect(pending?.coalescedCount).toBe(Number.MAX_SAFE_INTEGER);
		expect(pending?.coalescedCountSaturated).toBe(true);

		first.resolve(workerListResponse([...worker.summaries.values()]));
		await settle();
		expect(worker.client.request).toHaveBeenCalledTimes(2);
		const cause = worker.client.request.mock.calls[1]?.[2] as Cause;
		expect(cause.causeCoalescedCount).toBe(Number.MAX_SAFE_INTEGER);
		expect(cause.causeCoalescedCountSaturated).toBe(true);
		expect(cause.sequence).toBe(1);
		expect(cause.causeLatestEvent).toMatchObject({ sequence: 4 });
		expect(Object.keys(cause).length).toBeLessThanOrEqual(8);
	});

	it("keeps public status/list paths read-only with respect to worker lifecycle", async () => {
		const { runtime } = makeHarness();
		const forbidden = [
			"stopWorker",
			"stopWorkerUntracked",
			"recoverWorker",
			"adoptOrRecoverWorker",
			"deferWorkerRecovery",
			"resumeDeferredWorkerRecovery",
			"launchWorker",
			"prepareUpdateRestart",
			"persistWorkerStopTombstone",
			"acquireWorkerStopOwnership",
			"electWorker",
			"restartWorker",
		] as const;
		const guards = forbidden.map((name) => {
			const guard = vi.fn(() => {
				throw new Error(`public observation called forbidden helper ${name}`);
			});
			runtime[name] = guard;
			return guard;
		});

		const responses = await Promise.all([
			publicList(runtime, fakeCaller(), "status"),
			publicList(runtime, fakeCaller(), "list"),
		]);
		expect(responses.every((response) => response.success)).toBe(true);
		for (const guard of guards) expect(guard).not.toHaveBeenCalled();
	});
});
