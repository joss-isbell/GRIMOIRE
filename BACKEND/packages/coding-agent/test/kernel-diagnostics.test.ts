import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "../src/core/kernel/diagnostics.js";
import type { ForkedKernelHandle } from "../src/core/kernel/fork-server.js";
import { KernelManager } from "../src/core/kernel/index.js";

const roots: string[] = [];
const savedForkFlag = process.env.PRIME_AGENT_KERNEL_FORKSERVER;

afterEach(() => {
	if (savedForkFlag === undefined) delete process.env.PRIME_AGENT_KERNEL_FORKSERVER;
	else process.env.PRIME_AGENT_KERNEL_FORKSERVER = savedForkFlag;
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function captureKernelDiagnostics(): { events: KernelDiagnosticEvent[]; unsubscribe: () => void } {
	const events: KernelDiagnosticEvent[] = [];
	return {
		events,
		unsubscribe: subscribeKernelDiagnostics((event) => events.push(event)),
	};
}

const describeIfLinux = process.platform === "linux" ? describe : describe.skip;

describeIfLinux("KernelManager causal diagnostics", () => {
	it("records an exact direct-start collapse before port resolution", async () => {
		process.env.PRIME_AGENT_KERNEL_FORKSERVER = "0";
		const root = mkdtempSync(join(tmpdir(), "prime-agent-kernel-diagnostic-"));
		roots.push(root);
		const python = join(root, "python");
		writeFileSync(python, ["#!/bin/sh", 'echo "direct kernel fatal marker" >&2', "kill -ABRT $$", ""].join("\n"), {
			mode: 0o700,
		});
		chmodSync(python, 0o700);
		const capture = captureKernelDiagnostics();
		const manager = new KernelManager({ python, cwd: root, sessionId: "session-direct" });

		try {
			await expect(manager.execute("print(1)")).rejects.toThrow(/Kernel exited before resolving ports/);
			await vi.waitFor(() => {
				expect(capture.events.some((event) => event.type === "kernel_unexpected_exit")).toBe(true);
			});
			const started = capture.events.find((event) => event.type === "kernel_process_started");
			const exited = capture.events.find((event) => event.type === "kernel_unexpected_exit");
			expect(started).toMatchObject({
				type: "kernel_process_started",
				sessionId: "session-direct",
				launchMode: "direct",
				kernelPid: expect.any(Number),
				kernelProcessStartId: expect.stringMatching(/^proc:\d+$/),
			});
			expect(exited).toMatchObject({
				type: "kernel_unexpected_exit",
				sessionId: "session-direct",
				kernelInstanceId: started?.kernelInstanceId,
				kernelPid: started?.kernelPid,
				kernelProcessStartId: started?.kernelProcessStartId,
				launchMode: "direct",
				crashPhase: "resolving_ports",
				code: null,
				signal: "SIGABRT",
				reason: "process_exit",
				stderrCaptureStatus: "available",
			});
			if (!exited || exited.type !== "kernel_unexpected_exit") throw new Error("missing direct exit event");
			expect(Buffer.from(exited.stderrTail ?? []).toString()).toContain("direct kernel fatal marker");
			expect(exited.stderrBytes).toBeGreaterThan(0);
			expect(exited.sourceTruncated).toBe(false);
		} finally {
			capture.unsubscribe();
			await manager.dispose();
		}
	});

	it("bounds direct stderr bytes while retaining the exact multibyte tail and total source size", () => {
		const capture = captureKernelDiagnostics();
		const manager = new KernelManager({ sessionId: "session-stderr-bound" });
		const internals = manager as unknown as {
			kernelDiagnosticIdentity: {
				sessionId?: string;
				kernelInstanceId: string;
				kernelPid: number;
				kernelProcessStartId?: string;
				launchMode: "direct";
			};
			kernelCrashPhase: "resolving_ports";
			kernelStderr: string;
			kernelStderrTail: Buffer;
			kernelStderrBytes: number;
			appendKernelStderr(chunk: Buffer | string): void;
			reportUnexpectedKernelExit(code: number | null, signal: NodeJS.Signals | null, reason: "process_exit"): void;
		};
		internals.kernelDiagnosticIdentity = {
			sessionId: "session-stderr-bound",
			kernelInstanceId: "kernel-instance-stderr-bound",
			kernelPid: 4545,
			kernelProcessStartId: "proc:stderr-bound",
			launchMode: "direct",
		};
		internals.kernelCrashPhase = "resolving_ports";
		const maxTailBytes = 16 * 1024;
		const splitEmoji = Buffer.from("🙂");
		const chunks = [
			Buffer.alloc(maxTailBytes + 257, 0x61),
			splitEmoji.subarray(0, 2),
			splitEmoji.subarray(2),
			Buffer.from("tail漢"),
		];
		const source = Buffer.concat(chunks);

		try {
			for (const chunk of chunks) {
				internals.appendKernelStderr(chunk);
				expect(internals.kernelStderrTail.byteLength).toBeLessThanOrEqual(maxTailBytes);
			}
			expect(internals.kernelStderrBytes).toBe(source.byteLength);
			expect(internals.kernelStderr).toContain("🙂tail漢");

			internals.reportUnexpectedKernelExit(null, "SIGABRT", "process_exit");
			const exited = capture.events.find((event) => event.type === "kernel_unexpected_exit");
			if (!exited || exited.type !== "kernel_unexpected_exit") throw new Error("missing bounded stderr event");
			expect(exited.stderrBytes).toBe(source.byteLength);
			expect(exited.sourceTruncated).toBe(true);
			expect(Buffer.from(exited.stderrTail ?? [])).toEqual(source.subarray(-maxTailBytes));
		} finally {
			capture.unsubscribe();
		}
	});

	it("preserves fork pid/start/instance/request correlation through an unexpected exit", async () => {
		const capture = captureKernelDiagnostics();
		const reject = vi.fn();
		const kill = vi.fn(async (): Promise<"already-exited"> => "already-exited");
		const handle: ForkedKernelHandle = {
			pid: 4242,
			processStartId: "proc:fork-start",
			isAlive: async () => false,
			exitStatus: async () => ({ state: "exited", code: null, signal: "SIGKILL" }),
			kill,
		};
		const manager = new KernelManager({ sessionId: "session-fork" });
		const internals = manager as unknown as {
			state: "running";
			forkedKernel?: ForkedKernelHandle;
			kernelDiagnosticIdentity: {
				sessionId?: string;
				kernelInstanceId: string;
				kernelPid: number;
				kernelProcessStartId?: string;
				launchMode: "fork";
			};
			kernelCrashPhase: "executing";
			activeExecution: { requestMsgId: string; reject(error: Error): void };
			checkForkedKernelDeath(): Promise<void>;
		};
		internals.state = "running";
		internals.forkedKernel = handle;
		internals.kernelDiagnosticIdentity = {
			sessionId: "session-fork",
			kernelInstanceId: "kernel-instance-fork",
			kernelPid: handle.pid,
			kernelProcessStartId: handle.processStartId,
			launchMode: "fork",
		};
		internals.kernelCrashPhase = "executing";
		internals.activeExecution = { requestMsgId: "execute-request-7", reject };

		try {
			await internals.checkForkedKernelDeath();
			const exits = capture.events.filter((event) => event.type === "kernel_unexpected_exit");
			expect(exits).toEqual([
				expect.objectContaining({
					type: "kernel_unexpected_exit",
					sessionId: "session-fork",
					kernelInstanceId: "kernel-instance-fork",
					kernelPid: 4242,
					kernelProcessStartId: "proc:fork-start",
					launchMode: "fork",
					requestMsgId: "execute-request-7",
					crashPhase: "executing",
					code: null,
					signal: "SIGKILL",
					reason: "process_exit",
					stderrCaptureStatus: "unavailable_fork",
				}),
			]);
			expect(reject).toHaveBeenCalledWith(expect.objectContaining({ message: "Kernel has been shut down" }));
			expect(internals.state).toBe("shutdown");
		} finally {
			capture.unsubscribe();
			internals.forkedKernel = undefined;
		}
	});

	it("preserves ready and request identity through an execution channel fault", async () => {
		const capture = captureKernelDiagnostics();
		const manager = new KernelManager({ sessionId: "session-channel" });
		const internals = manager as unknown as {
			state: "running";
			connection: { key: string };
			shell: { send(): Promise<void> };
			kernelDiagnosticIdentity: {
				sessionId?: string;
				kernelInstanceId: string;
				kernelPid: number;
				kernelProcessStartId?: string;
				launchMode: "direct";
			};
			kernelCrashPhase: "idle" | "executing";
			markKernelReady(): void;
			executeInner(code: string, options: Record<string, never>, started: number): Promise<unknown>;
		};
		internals.state = "running";
		internals.connection = { key: "test-key" };
		internals.shell = { send: async () => Promise.reject(new Error("shell diagnostic failure")) };
		internals.kernelDiagnosticIdentity = {
			sessionId: "session-channel",
			kernelInstanceId: "kernel-instance-channel",
			kernelPid: 4444,
			kernelProcessStartId: "proc:channel-start",
			launchMode: "direct",
		};
		internals.kernelCrashPhase = "idle";

		try {
			internals.markKernelReady();
			await expect(internals.executeInner("print(1)", {}, Date.now())).rejects.toThrow("shell diagnostic failure");
			const ready = capture.events.find((event) => event.type === "kernel_ready");
			const executing = capture.events.find((event) => event.type === "kernel_execute_started");
			const fault = capture.events.find((event) => event.type === "kernel_channel_fault");
			expect(ready).toMatchObject({
				type: "kernel_ready",
				sessionId: "session-channel",
				kernelInstanceId: "kernel-instance-channel",
				kernelPid: 4444,
				kernelProcessStartId: "proc:channel-start",
				phase: "idle",
			});
			expect(executing).toMatchObject({
				type: "kernel_execute_started",
				kernelInstanceId: "kernel-instance-channel",
				requestMsgId: expect.any(String),
				phase: "executing",
			});
			expect(fault).toMatchObject({
				type: "kernel_channel_fault",
				kernelInstanceId: "kernel-instance-channel",
				requestMsgId: executing?.type === "kernel_execute_started" ? executing.requestMsgId : undefined,
				channel: "shell",
				crashPhase: "executing",
				reason: "shell diagnostic failure",
			});
			expect(internals.kernelCrashPhase).toBe("idle");
		} finally {
			capture.unsubscribe();
		}
	});

	it("does not report an explicit fork shutdown as an unexpected exit", async () => {
		const capture = captureKernelDiagnostics();
		const handle: ForkedKernelHandle = {
			pid: 4343,
			processStartId: "proc:explicit-stop",
			isAlive: async () => true,
			exitStatus: async () => ({ state: "alive" }),
			kill: async () => "signaled",
		};
		const manager = new KernelManager({ sessionId: "session-stop" });
		const internals = manager as unknown as {
			state: "running";
			forkedKernel?: ForkedKernelHandle;
			kernelDiagnosticIdentity: {
				sessionId?: string;
				kernelInstanceId: string;
				kernelPid: number;
				kernelProcessStartId?: string;
				launchMode: "fork";
			};
		};
		internals.state = "running";
		internals.forkedKernel = handle;
		internals.kernelDiagnosticIdentity = {
			sessionId: "session-stop",
			kernelInstanceId: "kernel-instance-stop",
			kernelPid: handle.pid,
			kernelProcessStartId: handle.processStartId,
			launchMode: "fork",
		};
		try {
			await manager.kill();
			expect(capture.events.filter((event) => event.type === "kernel_unexpected_exit")).toEqual([]);
		} finally {
			capture.unsubscribe();
		}
	});
});
