import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DaemonSupervisor } from "../src/modes/daemon/daemon-supervisor.js";

interface Deferred<T> {
	promise: Promise<T>;
	resolve(value: T): void;
	reject(error: unknown): void;
}

interface FixtureWorker {
	descriptor: {
		workerId: string;
		rootActiveSessionId: string;
		lifecycle: string;
		stopRequestedAt?: number;
	};
}

type Priority = "bounded" | "urgent";
type Cause = Record<string, unknown>;
type SchedulerRuntime = {
	workers: Map<string, FixtureWorker>;
	shuttingDown: boolean;
	scheduleWorkerEventSummaryRefresh(worker: FixtureWorker, cause: Cause, priority: Priority): void;
	refreshWorkerSummaries(worker: FixtureWorker, diagnosticCause?: Cause): Promise<boolean>;
	syncAgentPeers(cause?: Cause): Promise<void>;
	[key: string]: unknown;
};

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
}

function makeHarness() {
	const root = mkdtempSync(join(tmpdir(), "prime-list-fanout-"));
	const supervisor = new DaemonSupervisor(join(root, "supervisor.sock"), {
		descriptorDir: join(root, "descriptors"),
		defaultSessionConfig: { cwd: root, agentDir: root },
	}) as unknown as SchedulerRuntime;
	const worker: FixtureWorker = {
		descriptor: { workerId: "worker-1", rootActiveSessionId: "root-1", lifecycle: "ready" },
	};
	supervisor.workers = new Map([[worker.descriptor.workerId, worker]]);
	supervisor.shuttingDown = false;
	const refresh = vi.fn<() => Promise<boolean>>();
	const sync = vi.fn(async () => undefined);
	supervisor.refreshWorkerSummaries = refresh;
	supervisor.syncAgentPeers = sync;
	return { root, supervisor, worker, refresh, sync };
}

function schedule(runtime: SchedulerRuntime, worker: FixtureWorker, n: number, priority: Priority = "bounded") {
	for (let index = 0; index < n; index++) {
		runtime.scheduleWorkerEventSummaryRefresh(
			worker,
			{ causeKind: "worker_outbound_frame", causeSessionEventType: "rlm_child_update", sequence: index },
			priority,
		);
	}
}

/** White-box guard only: scheduler-owned containers must stay O(workers), not O(events). */
function expectBoundedSchedulerContainers(runtime: SchedulerRuntime): void {
	const candidates = Object.entries(runtime).filter(([key]) => /summary.*refresh|refresh.*summary/i.test(key));
	for (const [, value] of candidates) {
		if (value instanceof Map || value instanceof Set) expect(value.size).toBeLessThanOrEqual(1);
		if (Array.isArray(value)) expect(value.length).toBeLessThanOrEqual(1);
	}
	expect(vi.getTimerCount()).toBeLessThanOrEqual(1);
}

describe("DaemonSupervisor high-rate list fan-out scheduling", () => {
	const roots = new Set<string>();

	beforeEach(() => vi.useFakeTimers());
	afterEach(() => {
		vi.useRealTimers();
		for (const root of roots) rmSync(root, { recursive: true, force: true });
		roots.clear();
	});

	it("coalesces 100,000 child updates into one active and one trailing refresh", async () => {
		const h = makeHarness();
		roots.add(h.root);
		const first = deferred<boolean>();
		const second = deferred<boolean>();
		h.refresh.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);

		schedule(h.supervisor, h.worker, 100_000);
		expect(h.refresh).toHaveBeenCalledTimes(1);
		expectBoundedSchedulerContainers(h.supervisor);
		first.resolve(false);
		await settle();
		await vi.advanceTimersByTimeAsync(5_000);
		expect(h.refresh).toHaveBeenCalledTimes(2);
		second.resolve(false);
		await settle();
		expect(h.refresh).toHaveBeenCalledTimes(2);
		expectBoundedSchedulerContainers(h.supervisor);
	});

	it("limits continuous bounded events to 13 starts in 60 seconds with 5 second spacing", async () => {
		const h = makeHarness();
		roots.add(h.root);
		const starts: number[] = [];
		h.refresh.mockImplementation(async () => {
			starts.push(Date.now());
			return false;
		});
		for (let second = 0; second <= 60; second++) {
			schedule(h.supervisor, h.worker, 20);
			await settle();
			if (second < 60) await vi.advanceTimersByTimeAsync(1_000);
		}
		expect(starts.length).toBeLessThanOrEqual(13);
		for (let index = 1; index < starts.length; index++)
			expect(starts[index] - starts[index - 1]).toBeGreaterThanOrEqual(5_000);
	});

	it.each(["late success", "failure", "timeout-shaped rejection"])("stays bounded after %s", async (shape) => {
		const h = makeHarness();
		roots.add(h.root);
		const first = deferred<boolean>();
		h.refresh.mockReturnValueOnce(first.promise).mockResolvedValue(false);
		schedule(h.supervisor, h.worker, 10_000);
		if (shape === "late success") first.resolve(false);
		else first.reject(new Error(shape === "failure" ? "refresh failed" : "Timed out refreshing summaries"));
		await settle();
		await vi.advanceTimersByTimeAsync(4_999);
		expect(h.refresh).toHaveBeenCalledTimes(1);
		await vi.advanceTimersByTimeAsync(1);
		expect(h.refresh).toHaveBeenCalledTimes(2);
		await vi.advanceTimersByTimeAsync(30_000);
		expect(h.refresh).toHaveBeenCalledTimes(2);
	});

	it("syncs peers only for a changed projection and coalesces that sync", async () => {
		const h = makeHarness();
		roots.add(h.root);
		h.refresh.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
		schedule(h.supervisor, h.worker, 100);
		await settle();
		expect(h.sync).not.toHaveBeenCalled();
		await vi.advanceTimersByTimeAsync(5_000);
		await settle();
		expect(h.sync).toHaveBeenCalledTimes(1);
	});

	it("runs a structural burst as one non-overlapping urgent trailing attempt", async () => {
		const h = makeHarness();
		roots.add(h.root);
		const first = deferred<boolean>();
		let active = 0;
		let maxActive = 0;
		h.refresh
			.mockImplementationOnce(async () => {
				active++;
				maxActive = Math.max(maxActive, active);
				const result = await first.promise;
				active--;
				return result;
			})
			.mockImplementation(async () => {
				active++;
				maxActive = Math.max(maxActive, active);
				active--;
				return false;
			});
		schedule(h.supervisor, h.worker, 1);
		for (let index = 0; index < 1_000; index++) {
			h.supervisor.scheduleWorkerEventSummaryRefresh(h.worker, { causeOutboundType: "session_replaced" }, "urgent");
		}
		expect(h.refresh).toHaveBeenCalledTimes(1);
		first.resolve(false);
		await settle();
		expect(h.refresh).toHaveBeenCalledTimes(2);
		expect(maxActive).toBe(1);
	});

	it.each(["replacement", "removal", "stopping", "shutdown"])(
		"does not run stale work after worker %s",
		async (mode) => {
			const h = makeHarness();
			roots.add(h.root);
			h.refresh.mockResolvedValue(false);
			schedule(h.supervisor, h.worker, 2);
			await settle();
			if (mode === "replacement") h.supervisor.workers.set(h.worker.descriptor.workerId, { ...h.worker });
			if (mode === "removal") h.supervisor.workers.delete(h.worker.descriptor.workerId);
			if (mode === "stopping") h.worker.descriptor.stopRequestedAt = Date.now();
			if (mode === "shutdown") h.supervisor.shuttingDown = true;
			await vi.advanceTimersByTimeAsync(60_000);
			expect(h.refresh).toHaveBeenCalledTimes(1);
		},
	);
});
