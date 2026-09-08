import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanupSessionResources } from "@earendil-works/pi-ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "../src/core/kernel/diagnostics.js";
import { KernelManager } from "../src/core/kernel/index.js";

type Internals = {
	state: "idle" | "running" | "shutdown";
	kernel?: ChildProcess;
	kernelDiagnosticIdentity?: { kernelInstanceId: string };
	kernelCrashPhase: "idle" | "executing";
	activeExecution?: { requestMsgId: string; reject(error: Error): void };
	connection?: { key: string };
	control?: { send(frames: Buffer[]): Promise<void>; close(): void };
	startKernelDiagnostics(mode: "direct", pid: number, startId: string): void;
	attachKernelProcessExitObserver(kernel: ChildProcess): void;
	interrupt(): Promise<void>;
	flushSnapshotForDispose(): Promise<void>;
};

const unsubscribers: Array<() => void> = [];
afterEach(() => {
	for (const unsubscribe of unsubscribers.splice(0)) unsubscribe();
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
});

function configuredManager() {
	const events: KernelDiagnosticEvent[] = [];
	unsubscribers.push(subscribeKernelDiagnostics((event) => events.push(event)));
	const manager = new KernelManager({ sessionId: "lifecycle-session" });
	const internals = manager as unknown as Internals;
	const effects: string[] = [];
	const child = Object.assign(new EventEmitter(), {
		pid: 5301,
		exitCode: 0,
		signalCode: null,
		kill: vi.fn(() => {
			effects.push("kill");
			return false;
		}),
	}) as unknown as ChildProcess;
	internals.state = "running";
	internals.kernel = child;
	internals.startKernelDiagnostics("direct", 5301, "proc:5301-start");
	internals.kernelCrashPhase = "executing";
	internals.activeExecution = { requestMsgId: "original-request", reject: () => effects.push("reject") };
	internals.connection = { key: "secret-connection-key" };
	internals.control = {
		send: async () => {
			effects.push("send");
		},
		close: () => effects.push("close"),
	};
	return { manager, internals, child, events, effects };
}

describe("kernel lifecycle causal evidence", () => {
	it.each(["session_cleanup", "unexpected_exit"] as const)(
		"observes a real direct child after %s without changing classification",
		async (scenario) => {
			vi.stubEnv("PRIME_AGENT_KERNEL_FORKSERVER", "0");
			const directory = mkdtempSync(join(tmpdir(), "kernel-lifecycle-causal-"));
			const python = join(directory, "python");
			writeFileSync(
				python,
				scenario === "session_cleanup" ? "#!/bin/sh\nexec /bin/sleep 60\n" : "#!/bin/sh\nexit 42\n",
				{ mode: 0o700 },
			);
			const sessionId = `causal-${scenario}`;
			const manager = new KernelManager({ python, cwd: directory, sessionId });
			const events: KernelDiagnosticEvent[] = [];
			unsubscribers.push(
				subscribeKernelDiagnostics((event) => {
					if (event.sessionId === sessionId) events.push(event);
				}),
			);
			const startup = manager.start().catch((error: unknown) => error);
			try {
				await vi.waitFor(() => expect(events.some((event) => event.type === "kernel_process_started")).toBe(true));
				if (scenario === "session_cleanup") cleanupSessionResources(sessionId);
				await vi.waitFor(() =>
					expect(events.some((event) => event.type === "kernel_process_exit_observed")).toBe(true),
				);
				await startup;
				const start = events.find((event) => event.type === "kernel_process_started")!;
				const observed = events.find((event) => event.type === "kernel_process_exit_observed")!;
				expect(observed).toMatchObject({
					kernelInstanceId: start.kernelInstanceId,
					kernelPid: start.kernelPid,
					kernelProcessStartId: start.kernelProcessStartId,
				});
				if (scenario === "session_cleanup") {
					expect(events.find((event) => event.type === "kernel_lifecycle_intent")).toMatchObject({
						caller: "session_resource_cleanup",
						reason: "session_cleanup",
						operation: "dispose",
					});
					expect(observed).toMatchObject({ signal: "SIGTERM", code: null, lifecycleState: "shutdown" });
					expect(events.filter((event) => event.type === "kernel_unexpected_exit")).toEqual([]);
				} else {
					expect(observed).toMatchObject({ signal: null, code: 42, lifecycleState: "starting" });
					await vi.waitFor(() =>
						expect(events.filter((event) => event.type === "kernel_unexpected_exit")).toHaveLength(1),
					);
				}
			} finally {
				await manager.kill();
				await startup;
				rmSync(directory, { recursive: true, force: true });
			}
		},
	);

	it.each(["shutdown", "kill", "dispose", "disposeSync"] as const)(
		"publishes %s intent synchronously before the existing effect",
		async (operation) => {
			const { manager, internals, events, effects } = configuredManager();
			const order: string[] = [];
			unsubscribers.push(
				subscribeKernelDiagnostics((event) => {
					if (event.type === "kernel_lifecycle_intent") {
						if (order.length === 0) expect(effects).toEqual([]);
						order.push(event.operation);
					}
				}),
			);
			vi.spyOn(internals, "flushSnapshotForDispose").mockImplementation(async () => {
				expect(order[0]).toBe(operation === "disposeSync" ? "dispose_sync" : operation);
			});
			await manager[operation]();
			const expectedOperation = operation === "disposeSync" ? "dispose_sync" : operation;
			expect(order[0]).toBe(expectedOperation);
			expect(events.find((event) => event.type === "kernel_lifecycle_intent")).toMatchObject({
				type: "kernel_lifecycle_intent",
				operation: expectedOperation,
				caller: `KernelManager.${operation}`,
				reason: "requested",
				sessionId: "lifecycle-session",
				kernelPid: 5301,
				kernelProcessStartId: "proc:5301-start",
				requestMsgId: "original-request",
				crashPhase: "executing",
				ownerPid: process.pid,
				ownerProcessStartId: expect.stringMatching(/^proc:\d+$/),
				kernelGeneration: expect.any(Number),
				observedAt: expect.stringMatching(/^\d{4}-\d\d-\d\dT/),
				monotonicNs: expect.stringMatching(/^\d+$/),
				callerStack: expect.arrayContaining([expect.stringContaining("kernel-lifecycle-causal.test.ts:")]),
			});
			expect(events.filter((event) => event.type === "kernel_unexpected_exit")).toEqual([]);
			expect(effects).toContain("kill");
		},
	);

	it("publishes interrupt intent before sending the existing control message", async () => {
		const { internals, events, effects } = configuredManager();
		internals.control!.send = async (frames) => {
			expect(events.at(-1)).toMatchObject({ type: "kernel_lifecycle_intent", operation: "interrupt" });
			expect(JSON.parse(frames[2].toString()).msg_type).toBe("interrupt_request");
			effects.push("send");
		};
		await internals.interrupt();
		expect(effects).toEqual(["send"]);
		expect(events.filter((event) => event.type === "kernel_lifecycle_intent")).toHaveLength(1);
	});

	it("retains the exited child's identity and request after cleanup and replacement", async () => {
		const { manager, internals, child, events } = configuredManager();
		const originalInstance = internals.kernelDiagnosticIdentity!.kernelInstanceId;
		internals.attachKernelProcessExitObserver(child);
		await manager.kill();
		expect(internals.kernelDiagnosticIdentity).toBeUndefined();
		internals.state = "running";
		internals.startKernelDiagnostics("direct", 5302, "proc:5302-start");
		internals.activeExecution = { requestMsgId: "replacement-request", reject: vi.fn() };
		child.emit("exit", null, "SIGKILL");
		const observed = events.filter((event) => event.type === "kernel_process_exit_observed");
		expect(observed).toEqual([
			expect.objectContaining({
				kernelInstanceId: originalInstance,
				kernelPid: 5301,
				kernelProcessStartId: "proc:5301-start",
				requestMsgId: "original-request",
				crashPhase: "executing",
				lifecycleState: "shutdown",
				code: null,
				signal: "SIGKILL",
				ownerPid: process.pid,
			}),
		]);
		expect(internals.kernelDiagnosticIdentity!.kernelInstanceId).not.toBe(originalInstance);
		expect(internals.state).toBe("running");
		expect(events.filter((event) => event.type === "kernel_unexpected_exit")).toEqual([]);
	});

	it("observes an unexpected exit without introducing a second crash classifier", () => {
		const { internals, child, events } = configuredManager();
		internals.attachKernelProcessExitObserver(child);
		child.emit("exit", 19, null);
		expect(events.at(-1)).toMatchObject({
			type: "kernel_process_exit_observed",
			code: 19,
			signal: null,
			lifecycleState: "running",
			requestMsgId: "original-request",
		});
		expect(internals.state).toBe("running");
		expect(events.filter((event) => event.type === "kernel_unexpected_exit")).toEqual([]);
	});
});
