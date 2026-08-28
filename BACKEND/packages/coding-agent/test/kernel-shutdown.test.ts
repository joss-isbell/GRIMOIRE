import { EventEmitter } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

const incidentRecorder = vi.hoisted(() => ({
	emitIncidentDerived: vi.fn((_source: string, _type: string, _fields: Record<string, unknown>) => ({
		accepted: true as const,
		occurrenceId: "test-occurrence",
	})),
}));
const sessionResourceRegistry = vi.hoisted(() => ({
	cleanup: undefined as ((sessionId?: string) => void) | undefined,
}));
vi.mock("../src/modes/daemon/incident-recorder-writer.js", () => incidentRecorder);
vi.mock("@earendil-works/pi-ai", async (importOriginal) => {
	const original = await importOriginal<typeof import("@earendil-works/pi-ai")>();
	return {
		...original,
		registerSessionResourceCleanup: vi.fn((cleanup: (sessionId?: string) => void) => {
			sessionResourceRegistry.cleanup = cleanup;
			return () => {
				if (sessionResourceRegistry.cleanup === cleanup) sessionResourceRegistry.cleanup = undefined;
			};
		}),
	};
});

import { KernelManager } from "../src/core/kernel/index.js";

const kernelLifecycleEvents = ["beforeExit", "SIGINT", "SIGTERM", "exit"] as const;
const listenersBeforeKernelStart = new Map(
	kernelLifecycleEvents.map((event) => [event, new Set(process.listeners(event))]),
);

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

describe("KernelManager session resource cleanup transition", () => {
	it("uses the registered callback without changing snapshot, stale ownership, or cleanup", async () => {
		incidentRecorder.emitIncidentDerived.mockClear();
		expect(sessionResourceRegistry.cleanup).toBeTypeOf("function");
		const previousForkserver = process.env.PRIME_AGENT_KERNEL_FORKSERVER;
		process.env.PRIME_AGENT_KERNEL_FORKSERVER = "0";
		const directory = mkdtempSync(join(tmpdir(), "prime-kernel-session-cleanup-"));
		const python = join(directory, "fake-python");
		writeFileSync(python, "#!/bin/sh\nexec sleep 60\n", { mode: 0o700 });
		const managers: KernelManager[] = [];
		type SessionInternals = ShutdownInternals & {
			waitForResolvedConnection(path: string): Promise<never>;
			flushSnapshotForDispose(): Promise<void>;
			cleanupResources(): void;
		};
		const trackedManager = (sessionId: string): { manager: KernelManager; internals: SessionInternals } => {
			const manager = new KernelManager({ python, cwd: directory, sessionId });
			managers.push(manager);
			const internals = manager as unknown as SessionInternals;
			internals.waitForResolvedConnection = vi.fn(() => new Promise<never>(() => {}));
			void manager.start();
			expect(internals.state).toBe("starting");
			internals.state = "running";
			return { manager, internals };
		};

		try {
			const { internals } = trackedManager("owned-session");
			const kernel = internals.kernel;
			const kill = vi.spyOn(kernel, "kill");
			const flush = vi.spyOn(internals, "flushSnapshotForDispose").mockResolvedValue();
			const cleanup = vi.spyOn(internals, "cleanupResources");
			incidentRecorder.emitIncidentDerived.mockImplementation((_source, type, fields) => {
				if (type === "kernel_shutdown_transition" && fields.reason === "session_resource_cleanup") {
					expect(flush).toHaveBeenCalledTimes(1);
					expect(internals.state).toBe("running");
					expect(cleanup).not.toHaveBeenCalled();
					expect(fields).toMatchObject({
						callerCategory: "session_resource_cleanup",
						oldState: "running",
						newState: "shutdown",
						requestedKillSignal: "SIGTERM",
						observedSignal: "unavailable",
					});
				}
				return { accepted: true, occurrenceId: "session-cleanup" };
			});

			sessionResourceRegistry.cleanup?.("other-session");
			expect(flush).not.toHaveBeenCalled();
			sessionResourceRegistry.cleanup?.("owned-session");
			await vi.waitFor(() => expect(cleanup).toHaveBeenCalledTimes(1));
			expect(internals.state).toBe("shutdown");
			expect(internals.startGeneration).toBe(2);
			expect(kill).toHaveBeenCalledWith("SIGTERM");

			incidentRecorder.emitIncidentDerived.mockClear();
			const staleFixture = trackedManager("stale-session");
			const staleCleanup = vi.spyOn(staleFixture.internals, "cleanupResources");
			vi.spyOn(staleFixture.internals, "flushSnapshotForDispose").mockImplementation(async () => {
				staleFixture.internals.startGeneration++;
			});
			sessionResourceRegistry.cleanup?.("stale-session");
			await vi.waitFor(() => expect(staleFixture.internals.startGeneration).toBe(2));
			expect(staleFixture.internals.state).toBe("running");
			expect(staleCleanup).not.toHaveBeenCalled();
			expect(incidentRecorder.emitIncidentDerived).not.toHaveBeenCalled();
			staleFixture.internals.flushSnapshotForDispose = vi.fn(async () => {});
			await staleFixture.manager.dispose();
		} finally {
			await Promise.allSettled(managers.map((manager) => manager.dispose()));
			if (previousForkserver === undefined) delete process.env.PRIME_AGENT_KERNEL_FORKSERVER;
			else process.env.PRIME_AGENT_KERNEL_FORKSERVER = previousForkserver;
			rmSync(directory, { recursive: true, force: true });
		}
	});
});

describe("KernelManager installed process cleanup transitions", () => {
	it("keeps real hook cleanup, exit codes, signals, and transition evidence", async () => {
		incidentRecorder.emitIncidentDerived.mockClear();
		const previousForkserver = process.env.PRIME_AGENT_KERNEL_FORKSERVER;
		process.env.PRIME_AGENT_KERNEL_FORKSERVER = "0";
		const directory = mkdtempSync(join(tmpdir(), "prime-kernel-hooks-"));
		const python = join(directory, "fake-python");
		writeFileSync(python, "#!/bin/sh\nexec sleep 60\n", { mode: 0o700 });
		const events = kernelLifecycleEvents;
		const exit = vi
			.spyOn(process, "exit")
			.mockImplementation((_code?: string | number | null): never => undefined as never);
		const managers: KernelManager[] = [];

		const startTrackedManager = (): {
			manager: KernelManager;
			internals: ShutdownInternals & { waitForResolvedConnection(path: string): Promise<never> };
			kernel: ShutdownInternals["kernel"];
			kill: ReturnType<typeof vi.spyOn>;
			cleanup: ReturnType<typeof vi.spyOn>;
		} => {
			const manager = new KernelManager({ python, cwd: directory });
			managers.push(manager);
			const internals = manager as unknown as ShutdownInternals & {
				waitForResolvedConnection(path: string): Promise<never>;
				cleanupResources(): void;
			};
			internals.waitForResolvedConnection = vi.fn(() => new Promise<never>(() => {}));
			const cleanup = vi.spyOn(internals, "cleanupResources");
			void manager.start();
			expect(internals.state).toBe("starting");
			expect(internals.kernel).toBeDefined();
			const kernel = internals.kernel;
			const kill = vi.spyOn(kernel, "kill");
			return { manager, internals, kernel, kill, cleanup };
		};

		try {
			const beforeExitFixture = startTrackedManager();
			const installed = new Map(
				events.map((event) => [
					event,
					process.listeners(event).filter((listener) => !listenersBeforeKernelStart.get(event)?.has(listener)),
				]),
			);
			for (const event of events) expect(installed.get(event)).toHaveLength(1);
			const invoke = (event: (typeof events)[number]): void => {
				const listener = installed.get(event)?.[0];
				if (!listener) throw new Error(`missing installed ${event} handler`);
				listener(0);
			};

			invoke("beforeExit");
			await vi.waitFor(() => expect(beforeExitFixture.cleanup).toHaveBeenCalledTimes(1));
			expect(beforeExitFixture.kill).toHaveBeenCalledWith("SIGTERM");

			const sigintFixture = startTrackedManager();
			invoke("SIGINT");
			await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(130));
			expect(sigintFixture.cleanup).toHaveBeenCalledTimes(1);
			expect(sigintFixture.kill).toHaveBeenCalledWith("SIGTERM");

			const sigtermFixture = startTrackedManager();
			invoke("SIGTERM");
			await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(143));
			expect(sigtermFixture.cleanup).toHaveBeenCalledTimes(1);
			expect(sigtermFixture.kill).toHaveBeenCalledWith("SIGTERM");

			const processExitFixture = startTrackedManager();
			invoke("exit");
			expect(processExitFixture.cleanup).toHaveBeenCalledTimes(1);
			expect(processExitFixture.kill).toHaveBeenCalledWith("SIGTERM");

			const transitions = incidentRecorder.emitIncidentDerived.mock.calls
				.filter((call) => call[1] === "kernel_shutdown_transition")
				.map((call) => call[2])
				.filter((fields) => ["before_exit", "sigint", "sigterm", "process_exit"].includes(String(fields.reason)));
			expect(transitions).toEqual([
				expect.objectContaining({
					reason: "before_exit",
					callerCategory: "process_lifecycle",
					requestedKillSignal: "SIGTERM",
					observedSignal: "unavailable",
				}),
				expect.objectContaining({
					reason: "sigint",
					callerCategory: "process_signal",
					requestedKillSignal: "SIGTERM",
					observedSignal: "SIGINT",
				}),
				expect.objectContaining({
					reason: "sigterm",
					callerCategory: "process_signal",
					requestedKillSignal: "SIGTERM",
					observedSignal: "SIGTERM",
				}),
				expect.objectContaining({
					reason: "process_exit",
					callerCategory: "process_lifecycle",
					requestedKillSignal: "SIGTERM",
					observedSignal: "unavailable",
				}),
			]);
		} finally {
			for (const event of events) {
				for (const listener of process.listeners(event)) {
					if (!listenersBeforeKernelStart.get(event)?.has(listener)) process.removeListener(event, listener);
				}
			}
			exit.mockRestore();
			await Promise.allSettled(managers.map((manager) => manager.dispose()));
			if (previousForkserver === undefined) delete process.env.PRIME_AGENT_KERNEL_FORKSERVER;
			else process.env.PRIME_AGENT_KERNEL_FORKSERVER = previousForkserver;
			rmSync(directory, { recursive: true, force: true });
		}
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
