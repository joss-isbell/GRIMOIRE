import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "../src/core/kernel/diagnostics.js";
import type { ForkedKernelHandle } from "../src/core/kernel/fork-server.js";
import { KernelManager } from "../src/core/kernel/index.js";
import {
	KERNEL_STDERR_TAIL_BYTES,
	type KernelStderrCapture,
	KernelStderrCollector,
} from "../src/core/kernel/kernel-stderr-collector.js";

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
				stderrCaptureComplete: true,
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

	it("bounds one exited child's exact binary stderr tail and observed byte count", async () => {
		const stderr = new PassThrough();
		const child = new EventEmitter() as EventEmitter & { stderr: PassThrough };
		child.stderr = stderr;
		const process = child as unknown as ChildProcess;
		const splitEmoji = Buffer.from("🙂");
		const source = Buffer.concat([
			Buffer.alloc(KERNEL_STDERR_TAIL_BYTES + 257, 0x61),
			splitEmoji.subarray(0, 2),
			splitEmoji.subarray(2),
			Buffer.from("tail漢"),
		]);
		const snapshot = {
			kernelInstanceId: "kernel-instance-stderr-bound",
			kernelPid: 4545,
			launchMode: "direct" as const,
			crashPhase: "resolving_ports" as const,
			code: null,
			signal: "SIGABRT" as const,
			reason: "process_exit" as const,
		};
		let receivedSnapshot: Readonly<typeof snapshot> | undefined;
		const capturePromise = new Promise<KernelStderrCapture>((resolve) => {
			const collector = new KernelStderrCollector<typeof snapshot>(process);
			collector.markExit(snapshot, (exitSnapshot, capture) => {
				receivedSnapshot = exitSnapshot;
				resolve(capture);
			});
		});
		snapshot.kernelPid = 4546;
		stderr.write(source.subarray(0, KERNEL_STDERR_TAIL_BYTES + 257));
		stderr.write(source.subarray(KERNEL_STDERR_TAIL_BYTES + 257, -Buffer.byteLength("tail漢")));
		stderr.write(Buffer.from("tail漢"));
		const drained = new Promise<void>((resolve, reject) => {
			stderr.once("end", resolve);
			stderr.once("error", reject);
		});
		stderr.end();
		await drained;
		const capture = await capturePromise;
		expect(receivedSnapshot).toMatchObject({ kernelPid: 4545, kernelInstanceId: "kernel-instance-stderr-bound" });
		expect(capture.stderrBytes).toBe(source.byteLength);
		expect(capture.stderrCaptureComplete).toBe(true);
		expect(capture.sourceTruncated).toBe(true);
		expect(capture.stderrTail).toEqual(source.subarray(-KERNEL_STDERR_TAIL_BYTES));
		stderr.destroy();
	});

	it("reports an incomplete capture when stderr closes without end", async () => {
		const stderr = new PassThrough();
		const child = new EventEmitter() as EventEmitter & { stderr: PassThrough };
		child.stderr = stderr;
		const captures: KernelStderrCapture[] = [];
		const collector = new KernelStderrCollector(child as unknown as ChildProcess);
		collector.markExit({}, (_snapshot, capture) => captures.push(capture));
		stderr.write(Buffer.from("premature stderr"));
		stderr.destroy();
		await vi.waitFor(() => expect(captures).toHaveLength(1));
		expect(captures[0].stderrCaptureComplete).toBe(false);
		expect(stderr.readableEnded).toBe(false);
	});

	it("reports an incomplete capture when the child closes before stderr end", async () => {
		const stderr = new PassThrough();
		const child = new EventEmitter() as EventEmitter & { stderr: PassThrough };
		child.stderr = stderr;
		const captures: KernelStderrCapture[] = [];
		const collector = new KernelStderrCollector(child as unknown as ChildProcess);
		collector.markExit({}, (_snapshot, capture) => captures.push(capture));
		stderr.write(Buffer.from("child closed first"));
		child.emit("close");
		await vi.waitFor(() => expect(captures).toHaveLength(1));
		expect(captures[0].stderrCaptureComplete).toBe(false);
		expect(collector.isFinalized).toBe(true);
	});

	it("publishes an incomplete bounded capture after an exited child misses the drain deadline", async () => {
		vi.useFakeTimers();
		try {
			const stderr = new PassThrough();
			const child = new EventEmitter() as EventEmitter & { stderr: PassThrough };
			child.stderr = stderr;
			const process = child as unknown as ChildProcess;
			const captures: KernelStderrCapture[] = [];
			const collector = new KernelStderrCollector<Record<string, unknown>>(process);
			collector.markExit(
				{
					kernelInstanceId: "kernel-instance-timeout",
					kernelPid: 4546,
					launchMode: "direct",
					crashPhase: "executing",
					requestMsgId: "request-timeout",
					code: null,
					signal: "SIGKILL",
					reason: "process_exit",
				},
				(_snapshot, capture) => captures.push(capture),
			);
			stderr.write(Buffer.from([0x00, 0xff, 0x41]));
			expect(captures).toHaveLength(0);
			await vi.advanceTimersByTimeAsync(99);
			expect(captures).toHaveLength(0);
			await vi.advanceTimersByTimeAsync(1);
			expect(captures).toHaveLength(1);
			expect(captures[0]).toMatchObject({
				stderrBytes: 3,
				stderrCaptureComplete: false,
				sourceTruncated: false,
			});
			expect(collector.isExitOwned).toBe(false);
			expect(collector.isFinalized).toBe(true);
			expect(child.listenerCount("close")).toBe(0);
			expect(stderr.listenerCount("data")).toBe(0);
			expect(stderr.listenerCount("end")).toBe(0);
			expect(stderr.listenerCount("error")).toBe(0);
			collector.dispose();
		} finally {
			vi.useRealTimers();
		}
	});

	it("keeps direct stderr diagnostics tied to each child across rapid replacement", async () => {
		const capture = captureKernelDiagnostics();
		const manager = new KernelManager({ sessionId: "session-rapid-replacement" });
		const aStderr = new PassThrough();
		const aKill = vi.fn(() => false);
		const aChild = new EventEmitter() as EventEmitter & {
			stderr: PassThrough;
			pid: number;
			kill: (signal?: NodeJS.Signals) => boolean;
		};
		aChild.stderr = aStderr;
		aChild.pid = 5101;
		aChild.kill = aKill;
		const aProcess = aChild as unknown as ChildProcess;
		const bStderr = new PassThrough();
		const bKill = vi.fn(() => false);
		const bChild = new EventEmitter() as EventEmitter & {
			stderr: PassThrough;
			pid: number;
			kill: (signal?: NodeJS.Signals) => boolean;
		};
		bChild.stderr = bStderr;
		bChild.pid = 5102;
		bChild.kill = bKill;
		const bProcess = bChild as unknown as ChildProcess;
		const aReject = vi.fn();
		const bReject = vi.fn();
		const aIdentity = {
			sessionId: "session-rapid-replacement",
			kernelInstanceId: "kernel-instance-a",
			kernelPid: 5101,
			kernelProcessStartId: "proc:a-start",
			launchMode: "direct" as const,
		};
		const bIdentity = {
			sessionId: "session-rapid-replacement",
			kernelInstanceId: "kernel-instance-b",
			kernelPid: 5102,
			kernelProcessStartId: "proc:b-start",
			launchMode: "direct" as const,
		};
		const internals = manager as unknown as {
			state: "idle" | "running" | "shutdown";
			kernel?: ChildProcess;
			kernelDiagnosticIdentity?: typeof aIdentity;
			kernelCrashPhase: "resolving_ports" | "ready_probe" | "idle" | "executing";
			activeExecution?: { requestMsgId: string; reject(error: Error): void };
			kernelStderr: string;
			attachKernelStderrCollector(kernel: ChildProcess): void;
			reportUnexpectedKernelExit(
				code: number | null,
				signal: NodeJS.Signals | null,
				reason: "process_exit" | "forkserver_unavailable",
				child?: ChildProcess,
			): void;
			appendKernelDiagnostic(message: string): void;
			cleanupResources(killSignal?: NodeJS.Signals): void;
		};

		try {
			internals.state = "running";
			internals.kernel = aProcess;
			internals.kernelDiagnosticIdentity = aIdentity;
			internals.kernelCrashPhase = "executing";
			internals.activeExecution = { requestMsgId: "request-a", reject: aReject };
			internals.attachKernelStderrCollector(aProcess);
			aStderr.write(Buffer.from("A-before-exit\0"));
			internals.reportUnexpectedKernelExit(null, "SIGABRT", "process_exit", aProcess);
			internals.state = "shutdown";
			internals.cleanupResources("SIGKILL");
			expect(internals.kernel).toBeUndefined();
			expect(aReject).toHaveBeenCalledWith(expect.objectContaining({ message: "Kernel has been shut down" }));
			expect(aStderr.readableEnded).toBe(false);

			// Match restart's clean human-readable view before the replacement starts.
			internals.state = "idle";
			internals.kernelStderr = "";
			internals.state = "running";
			internals.kernel = bProcess;
			internals.kernelDiagnosticIdentity = bIdentity;
			internals.kernelCrashPhase = "executing";
			internals.activeExecution = { requestMsgId: "request-b", reject: bReject };
			internals.attachKernelStderrCollector(bProcess);
			internals.appendKernelDiagnostic("parent diagnostic must not enter raw stderr evidence");
			const aLate = Buffer.concat([Buffer.from("A-late\0"), Buffer.from([0xff])]);
			const bOnly = Buffer.concat([Buffer.from("B-only\0"), Buffer.from([0xfe])]);
			aStderr.write(aLate);
			bStderr.write(bOnly);
			expect(internals.kernelStderr).toContain("B-only");
			expect(internals.kernelStderr).not.toContain("A-before-exit");
			expect(internals.kernelStderr).not.toContain("A-late");

			internals.reportUnexpectedKernelExit(1, null, "process_exit", bProcess);
			const aDrained = new Promise<void>((resolve, reject) => {
				aStderr.once("end", resolve);
				aStderr.once("error", reject);
			});
			const bDrained = new Promise<void>((resolve, reject) => {
				bStderr.once("end", resolve);
				bStderr.once("error", reject);
			});
			aStderr.end();
			bStderr.end();
			await Promise.all([aDrained, bDrained]);

			const exits = capture.events.filter((event) => event.type === "kernel_unexpected_exit");
			expect(exits).toHaveLength(2);
			const aExit = exits.find((event) => event.type === "kernel_unexpected_exit" && event.kernelPid === 5101);
			const bExit = exits.find((event) => event.type === "kernel_unexpected_exit" && event.kernelPid === 5102);
			expect(aExit).toMatchObject({
				type: "kernel_unexpected_exit",
				sessionId: "session-rapid-replacement",
				kernelInstanceId: "kernel-instance-a",
				kernelPid: 5101,
				kernelProcessStartId: "proc:a-start",
				requestMsgId: "request-a",
				crashPhase: "executing",
				stderrCaptureComplete: true,
			});
			expect(bExit).toMatchObject({
				type: "kernel_unexpected_exit",
				sessionId: "session-rapid-replacement",
				kernelInstanceId: "kernel-instance-b",
				kernelPid: 5102,
				kernelProcessStartId: "proc:b-start",
				requestMsgId: "request-b",
				crashPhase: "executing",
				stderrCaptureComplete: true,
			});
			if (!aExit || aExit.type !== "kernel_unexpected_exit") throw new Error("missing A exit event");
			if (!bExit || bExit.type !== "kernel_unexpected_exit") throw new Error("missing B exit event");
			expect(Buffer.from(aExit.stderrTail ?? [])).toEqual(Buffer.concat([Buffer.from("A-before-exit\0"), aLate]));
			expect(aExit.stderrBytes).toBe(Buffer.byteLength("A-before-exit\0") + aLate.byteLength);
			expect(Buffer.from(bExit.stderrTail ?? [])).toEqual(bOnly);
			expect(bExit.stderrBytes).toBe(bOnly.byteLength);
			expect(Buffer.from(bExit.stderrTail ?? []).toString()).not.toContain("[kernel]");
			expect(Buffer.from(bExit.stderrTail ?? []).toString()).not.toContain("A-late");
		} finally {
			aStderr.destroy();
			bStderr.destroy();
			capture.unsubscribe();
			await manager.kill();
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
