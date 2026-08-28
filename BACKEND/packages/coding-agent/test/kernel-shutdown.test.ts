import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

const incidentRecorder = vi.hoisted(() => ({
	emitIncidentDerived: vi.fn(() => ({ accepted: true as const, occurrenceId: "test-occurrence" })),
}));
vi.mock("../src/modes/daemon/incident-recorder-writer.js", () => incidentRecorder);

import { KernelManager } from "../src/core/kernel/index.js";

type TestMessage = {
	header: { msg_type: string };
	parent_header: { msg_id: string };
	metadata: Record<string, unknown>;
	content: Record<string, unknown>;
};

type ShutdownInternals = {
	state: "idle" | "running" | "shutdown";
	startGeneration: number;
	kernelStderr: string;
	connection: { key: string };
	control: { send: (frames: Buffer[]) => Promise<void>; close: () => void };
	kernel: EventEmitter & {
		exitCode: number | null;
		signalCode: NodeJS.Signals | null;
		kill: (signal?: NodeJS.Signals | number) => boolean;
	};
	pendingControlReplies: Map<string, (message: TestMessage) => void>;
};

function shutdownReply(parentMessageId: string, msgType = "shutdown_reply"): TestMessage {
	return {
		header: { msg_type: msgType },
		parent_header: { msg_id: parentMessageId },
		metadata: {},
		content: { status: "ok", restart: false },
	};
}

function configuredManager(onSend: (internals: ShutdownInternals) => void | Promise<void>): {
	manager: KernelManager;
	internals: ShutdownInternals;
} {
	const manager = new KernelManager({ cwd: process.cwd() });
	const internals = manager as unknown as ShutdownInternals;
	const kernel = Object.assign(new EventEmitter(), {
		exitCode: null,
		signalCode: null,
		kill: vi.fn(() => true),
	});
	Object.assign(internals, {
		state: "running",
		connection: { key: "test-key" },
		control: {
			send: vi.fn(async () => onSend(internals)),
			close: vi.fn(),
		},
		kernel,
	});
	return { manager, internals };
}

describe("KernelManager graceful shutdown", () => {
	it("bounds a stuck control send with the aggregate shutdown deadline", async () => {
		vi.useFakeTimers();
		try {
			const { manager, internals } = configuredManager(() => new Promise<void>(() => {}));
			const shutdown = manager.shutdown();
			await vi.advanceTimersByTimeAsync(5_000);
			await shutdown;
			expect(internals.kernel).toBeUndefined();
		} finally {
			vi.useRealTimers();
		}
	});

	it("does not finish shutdown before the control send settles", async () => {
		let finishSend: (() => void) | undefined;
		const sendBlocked = new Promise<void>((resolve) => {
			finishSend = resolve;
		});
		const { manager, internals } = configuredManager(async (state) => {
			const [requestMessageId, dispatch] = [...state.pendingControlReplies.entries()][0] ?? [];
			if (!requestMessageId || !dispatch) throw new Error("missing shutdown reply listener");
			dispatch(shutdownReply(requestMessageId));
			await sendBlocked;
			state.kernel.exitCode = 0;
			state.kernel.emit("exit", 0, null);
		});

		let finished = false;
		const shutdown = manager.shutdown().then(() => {
			finished = true;
		});
		await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
		expect(finished).toBe(false);
		finishSend?.();
		await shutdown;
		expect(internals.pendingControlReplies.size).toBe(0);
	});

	it("finishes promptly when the kernel exits without sending shutdown_reply", async () => {
		const { manager, internals } = configuredManager((state) => {
			state.kernel.exitCode = 0;
			state.kernel.emit("exit", 0, null);
		});
		vi.useFakeTimers();
		try {
			const shutdown = manager.shutdown();
			await vi.advanceTimersByTimeAsync(100);
			// True = this call performed the cleanup: startup-failure recovery relies on it to resurrect to idle.
			await expect(shutdown).resolves.toBe(true);
			expect(internals.kernel).toBeUndefined();
		} finally {
			vi.useRealTimers();
		}
	});

	it("waits for the matching shutdown reply and removes its listener", async () => {
		const { manager, internals } = configuredManager(async (state) => {
			const [requestMessageId, dispatch] = [...state.pendingControlReplies.entries()][0] ?? [];
			expect(requestMessageId).toBeTypeOf("string");
			expect(dispatch).toBeTypeOf("function");
			if (!requestMessageId || !dispatch) throw new Error("missing shutdown reply listener");
			dispatch(shutdownReply("unrelated"));
			dispatch(shutdownReply(requestMessageId, "interrupt_reply"));
			expect(state.pendingControlReplies.size).toBe(1);
			dispatch(shutdownReply(requestMessageId));
			queueMicrotask(() => {
				state.kernel.exitCode = 0;
				state.kernel.emit("exit", 0, null);
			});
		});

		await manager.shutdown();

		expect(internals.pendingControlReplies.size).toBe(0);
		expect(internals.kernel).toBeUndefined();
	});

	it("keeps the kernel MCP close budget strictly inside the host shutdown deadline", () => {
		const source = readFileSync(resolve(__dirname, "../../../prime-agent-runtime/src/rlm/mcp.py"), "utf8");
		const match = source.match(/^_SHUTDOWN_TIMEOUT = ([\d.]+)$/m);
		expect(match).not.toBeNull();
		// +1s dispatch slack in mcp.py close(); the sum must undercut the host's 5s kill deadline.
		expect((Number(match![1]) + 1) * 1000).toBeLessThan(5000);
	});
});

describe("KernelManager programmatic shutdown transitions", () => {
	it("observes each shutdown without changing repeated cleanup or return behavior", async () => {
		incidentRecorder.emitIncidentDerived.mockClear();
		const { manager, internals } = configuredManager((state) => {
			state.kernel.exitCode = 0;
			state.kernel.emit("exit", 0, null);
		});
		const kernel = internals.kernel;
		incidentRecorder.emitIncidentDerived.mockImplementationOnce((_source, _type, fields) => {
			expect(internals.state).toBe("running");
			expect(internals.kernel).toBe(kernel);
			expect(fields).toMatchObject({
				reason: "shutdown",
				callerCategory: "programmatic_api",
				oldState: "running",
				newState: "shutdown",
				sessionId: "unavailable",
				activeSessionId: "unavailable",
				toolCallId: "unavailable",
				workerPid: process.pid,
				startGeneration: 0,
				requestedKillSignal: "SIGTERM",
			});
			return { accepted: true, occurrenceId: "first" };
		});

		await expect(manager.shutdown()).resolves.toBe(true);
		await expect(manager.shutdown()).resolves.toBe(true);

		expect(internals.startGeneration).toBe(2);
		expect(kernel.kill).toHaveBeenCalledTimes(1);
		expect(kernel.kill).toHaveBeenCalledWith("SIGTERM");
		expect(incidentRecorder.emitIncidentDerived).toHaveBeenCalledTimes(2);
		expect(incidentRecorder.emitIncidentDerived.mock.calls[1]?.[2]).toMatchObject({
			reason: "shutdown",
			oldState: "shutdown",
			newState: "shutdown",
			startGeneration: 1,
		});
	});

	it("preserves concurrent shutdown generation ownership and cleanup result", async () => {
		incidentRecorder.emitIncidentDerived.mockClear();
		let finishSend: (() => void) | undefined;
		const sendBlocked = new Promise<void>((resolve) => {
			finishSend = resolve;
		});
		const { manager, internals } = configuredManager(() => sendBlocked);
		const kernel = internals.kernel;

		const firstShutdown = manager.shutdown();
		await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
		await expect(manager.shutdown()).resolves.toBe(true);
		finishSend?.();
		kernel.exitCode = 0;
		kernel.emit("exit", 0, null);
		await expect(firstShutdown).resolves.toBe(false);

		expect(internals.startGeneration).toBe(1);
		expect(kernel.kill).toHaveBeenCalledTimes(1);
		expect(incidentRecorder.emitIncidentDerived).toHaveBeenCalledTimes(2);
		expect(incidentRecorder.emitIncidentDerived.mock.calls.map((call) => call[2])).toEqual([
			expect.objectContaining({ reason: "shutdown", oldState: "running", startGeneration: 0 }),
			expect.objectContaining({ reason: "shutdown", oldState: "shutdown", startGeneration: 0 }),
		]);
	});

	it("does not observe a snapshot shutdown superseded before its transition", async () => {
		incidentRecorder.emitIncidentDerived.mockClear();
		const { manager, internals } = configuredManager(() => {});
		const mutable = internals as ShutdownInternals & { flushSnapshotForDispose: () => Promise<void> };
		mutable.flushSnapshotForDispose = vi.fn(async () => {
			mutable.startGeneration++;
		});

		await expect(manager.shutdown({ snapshot: true })).resolves.toBe(false);

		expect(internals.state).toBe("running");
		expect(incidentRecorder.emitIncidentDerived).not.toHaveBeenCalled();
	});

	it("preserves restart shutdown-reset-start sequencing with a restart observation", async () => {
		incidentRecorder.emitIncidentDerived.mockClear();
		const { manager, internals } = configuredManager((state) => {
			state.kernel.exitCode = 0;
			state.kernel.emit("exit", 0, null);
		});
		internals.kernelStderr = "prior stderr";
		const start = vi.spyOn(manager, "start").mockImplementation(async () => {
			expect(internals.state).toBe("idle");
			expect(internals.kernelStderr).toBe("");
			expect(internals.startGeneration).toBe(1);
		});

		await manager.restart();

		expect(start).toHaveBeenCalledTimes(1);
		expect(incidentRecorder.emitIncidentDerived).toHaveBeenCalledTimes(1);
		expect(incidentRecorder.emitIncidentDerived.mock.calls[0]?.[2]).toMatchObject({
			reason: "restart",
			oldState: "running",
			requestedKillSignal: "SIGTERM",
		});
	});

	it("observes kill without changing repeated cleanup or signal behavior", async () => {
		incidentRecorder.emitIncidentDerived.mockClear();
		const { manager, internals } = configuredManager(() => {});
		const kernel = internals.kernel;

		await manager.kill();
		await manager.kill();

		expect(internals.startGeneration).toBe(2);
		expect(kernel.kill).toHaveBeenCalledTimes(1);
		expect(kernel.kill).toHaveBeenCalledWith("SIGKILL");
		expect(incidentRecorder.emitIncidentDerived.mock.calls.map((call) => call[2])).toEqual([
			expect.objectContaining({ reason: "kill", oldState: "running", requestedKillSignal: "SIGKILL" }),
			expect.objectContaining({ reason: "kill", oldState: "shutdown", requestedKillSignal: "SIGKILL" }),
		]);
	});

	it("observes dispose and disposeSync without changing repeated cleanup or signals", async () => {
		incidentRecorder.emitIncidentDerived.mockClear();
		const asyncFixture = configuredManager(() => {});
		const syncFixture = configuredManager(() => {});
		const asyncKernel = asyncFixture.internals.kernel;
		const syncKernel = syncFixture.internals.kernel;

		await asyncFixture.manager.dispose();
		await asyncFixture.manager.dispose();
		syncFixture.manager.disposeSync();
		syncFixture.manager.disposeSync();

		expect(asyncFixture.internals.startGeneration).toBe(2);
		expect(syncFixture.internals.startGeneration).toBe(2);
		expect(asyncKernel.kill).toHaveBeenCalledTimes(1);
		expect(asyncKernel.kill).toHaveBeenCalledWith("SIGTERM");
		expect(syncKernel.kill).toHaveBeenCalledTimes(1);
		expect(syncKernel.kill).toHaveBeenCalledWith("SIGTERM");
		expect(incidentRecorder.emitIncidentDerived.mock.calls.map((call) => call[2])).toEqual([
			expect.objectContaining({ reason: "dispose", oldState: "running", requestedKillSignal: "SIGTERM" }),
			expect.objectContaining({ reason: "dispose", oldState: "shutdown", requestedKillSignal: "SIGTERM" }),
			expect.objectContaining({ reason: "dispose_sync", oldState: "running", requestedKillSignal: "SIGTERM" }),
			expect.objectContaining({ reason: "dispose_sync", oldState: "shutdown", requestedKillSignal: "SIGTERM" }),
		]);
	});
});
