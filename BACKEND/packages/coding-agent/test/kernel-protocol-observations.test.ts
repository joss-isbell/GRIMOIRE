import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Dealer, Router } from "zeromq";
import { ensureKernelPython } from "../src/core/kernel/bootstrap.js";
import {
	encodeKernelDiagnosticBridgeEvent,
	KernelDiagnosticBridgeDecoder,
	KernelDiagnosticBridgeWriter,
} from "../src/core/kernel/diagnostic-bridge.js";
import {
	type KernelDiagnosticEvent,
	type KernelProtocolDetail,
	subscribeKernelDiagnostics,
} from "../src/core/kernel/diagnostics.js";
import { KernelManager } from "../src/core/kernel/index.js";

type ProtocolInternals = {
	state: "running";
	shell: Dealer;
	connection: { key: string; transport: string; ip: string; hb_port: number };
	startKernelDiagnostics(mode: "direct", pid: number, startId: string): void;
	startProtocolObservers(): void;
	probeHeartbeat(): Promise<void>;
	probeReady(): Promise<void>;
	markKernelExecutionStarted(requestMsgId: string): void;
	pendingShellObservations: Map<string, unknown>;
	heartbeatTimer?: ReturnType<typeof setTimeout>;
	heartbeat?: unknown;
	handleExecutionMessage(incoming: ReturnType<typeof message>): void;
};

function message(type: string, requestMsgId: string, content: Record<string, unknown> = {}) {
	return {
		header: { msg_type: type, msg_id: `reply-${requestMsgId}-${type}` },
		parent_header: { msg_id: requestMsgId },
		metadata: {},
		content,
	};
}

function progress(events: KernelDiagnosticEvent[]) {
	return events.filter((event) => event.type === "kernel_protocol_observation");
}

async function harness() {
	const shell = new Router({ linger: 0 });
	const heartbeat = new Router({ linger: 0 });
	await shell.bind("tcp://127.0.0.1:*");
	await heartbeat.bind("tcp://127.0.0.1:*");
	let echo = true;
	let closed = false;
	let heldHeartbeat: Buffer[] | undefined;
	const heartbeatPump = (async () => {
		try {
			for await (const frames of heartbeat) {
				if (echo) await heartbeat.send(frames);
				else heldHeartbeat = frames;
			}
		} catch (error) {
			if (!closed) throw error;
		}
	})();
	const dealer = new Dealer({ linger: 0 });
	dealer.connect(shell.lastEndpoint!);
	const manager = new KernelManager({ sessionId: "protocol-unit-session" });
	const internals = manager as unknown as ProtocolInternals;
	Object.assign(internals, {
		state: "running",
		shell: dealer,
		connection: {
			key: "test-key",
			transport: "tcp",
			ip: "127.0.0.1",
			hb_port: Number(heartbeat.lastEndpoint!.split(":").at(-1)),
		},
	});
	vi.spyOn(manager, "start").mockResolvedValue();
	const events: KernelDiagnosticEvent[] = [];
	const unsubscribe = subscribeKernelDiagnostics((event) => events.push(event));
	internals.startKernelDiagnostics("direct", 5151, "proc:unit");
	const receive = async () => {
		const frames = await shell.receive();
		const delimiter = frames.findIndex((frame) => frame.toString() === "<IDS|MSG>");
		const header = JSON.parse(frames[delimiter + 2].toString()) as { msg_id: string; msg_type: string };
		return {
			header,
			reply: async (type: string, content: Record<string, unknown> = {}) => {
				const incoming = message(type, header.msg_id, content);
				await shell.send([
					frames[0],
					Buffer.from("<IDS|MSG>"),
					Buffer.alloc(0),
					...[incoming.header, incoming.parent_header, incoming.metadata, incoming.content].map((value) =>
						Buffer.from(JSON.stringify(value)),
					),
				]);
			},
		};
	};
	return {
		manager,
		internals,
		events,
		receive,
		setEcho(value: boolean) {
			echo = value;
		},
		async deliverHeldHeartbeat() {
			if (heldHeartbeat) await heartbeat.send(heldHeartbeat);
		},
		async close() {
			closed = true;
			manager.disposeSync();
			unsubscribe();
			shell.close();
			heartbeat.close();
			await heartbeatPump;
		},
	};
}

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
});

describe("kernel protocol observations", () => {
	it("retains unavailable channels and completion through bridge pressure and close", async () => {
		const capability = randomBytes(32).toString("base64url");
		const writes: Buffer[] = [];
		const releases: Array<() => void> = [];
		const stream = new Writable({
			highWaterMark: 1,
			write(chunk, _encoding, callback) {
				writes.push(Buffer.from(chunk));
				releases.push(callback);
			},
		});
		const writer = new KernelDiagnosticBridgeWriter(stream, capability, 4000);
		const identity = {
			kernelInstanceId: "protocol-pressure",
			kernelPid: 1,
			launchMode: "direct" as const,
			ownerPid: 2,
			kernelGeneration: 1,
			observedAt: "2026-09-08T00:00:00.000Z",
			monotonicNs: "123",
			crashPhase: "executing" as const,
			requestMsgId: "request",
		};
		for (let i = 0; i < 100; i++)
			writer.publish({
				...identity,
				type: "kernel_protocol_observation",
				observation: "heartbeat_echo",
				probeId: String(i),
				durationMs: 1,
			});
		const details: KernelProtocolDetail[] = [
			{ observation: "heartbeat_unavailable", probeId: "failed", durationMs: 1000, reason: "timeout" },
			{ observation: "shell_reply_unavailable", requestMsgId: "request", reason: "not_observed_after_idle" },
			{ observation: "shell_unavailable", reason: "receive_failed" },
			{
				observation: "execution_completed",
				requestMsgId: "request",
				status: "ok",
				completionSource: "iopub_idle",
				durationMs: 1000,
			},
		];
		const expected = details.map(
			(detail): KernelDiagnosticEvent => ({ ...identity, ...detail, type: "kernel_protocol_observation" }),
		);
		for (const event of expected) writer.publish(event);
		expect(writer.bufferedBytes).toBeLessThanOrEqual(4000);
		writer.close();
		while (releases.length) {
			releases.shift()!();
			await new Promise<void>((resolve) => setImmediate(resolve));
		}
		const events: KernelDiagnosticEvent[] = [];
		const losses: unknown[] = [];
		let evicted = 0;
		const decoder = new KernelDiagnosticBridgeDecoder({
			capability,
			onEvent: (event) => events.push(event),
			onDrop: (counts) => {
				evicted += counts.evictedNormal;
			},
			onLoss: (loss) => losses.push(loss),
		});
		decoder.push(Buffer.concat(writes));
		decoder.end();
		expect(events).toEqual(expect.arrayContaining(expected));
		expect(losses).toEqual([]);
		expect(evicted).toBeGreaterThan(0);
	});
	it("round-trips protocol metadata and rejects malformed observations without exposing message bodies", () => {
		const capability = randomBytes(32).toString("base64url");
		const identity = {
			kernelInstanceId: "kernel-protocol",
			kernelPid: 1,
			launchMode: "direct" as const,
			ownerPid: 2,
			kernelGeneration: 1,
			observedAt: "2026-09-08T00:00:00.000Z",
			monotonicNs: "12345",
			crashPhase: "executing" as const,
			requestMsgId: "request",
		};
		const details: KernelProtocolDetail[] = [
			{ observation: "heartbeat_echo", probeId: "probe", durationMs: 3 },
			{ observation: "heartbeat_unavailable", probeId: "probe", durationMs: 1000, reason: "timeout" },
			{ observation: "shell_reply", requestMsgId: "request", protocolMsgId: "reply", status: "ok" },
			{ observation: "iopub_busy", requestMsgId: "request", protocolMsgId: "busy" },
			{ observation: "iopub_idle", requestMsgId: "request", protocolMsgId: "idle" },
			{
				observation: "execution_completed",
				requestMsgId: "request",
				durationMs: 2000,
				status: "ok",
				completionSource: "iopub_idle",
			},
			{
				observation: "execution_completed",
				requestMsgId: "request",
				durationMs: 2000,
				status: "aborted",
				completionSource: "abort_grace",
			},
			{ observation: "shell_reply_unavailable", requestMsgId: "request", reason: "not_observed_after_idle" },
			{ observation: "shell_unavailable", reason: "receive_failed" },
		];
		for (const detail of details) {
			const expected: KernelDiagnosticEvent = { ...identity, ...detail, type: "kernel_protocol_observation" };
			const events: KernelDiagnosticEvent[] = [];
			const losses: unknown[] = [];
			const decoder = new KernelDiagnosticBridgeDecoder({
				capability,
				onEvent: (event) => events.push(event),
				onDrop: () => {},
				onLoss: (loss) => losses.push(loss),
			});
			decoder.push(
				encodeKernelDiagnosticBridgeEvent(
					{ ...expected, content: "secret-protocol-content" } as unknown as KernelDiagnosticEvent,
					capability,
				)!,
			);
			decoder.end();
			expect(events).toEqual([expected]);
			expect(losses).toEqual([]);
		}
		for (const invalid of [
			{ observation: "heartbeat_echo", probeId: "probe", durationMs: -1 },
			{ observation: "shell_reply", status: "invented" },
			{ observation: "shell_reply_unavailable", reason: "kernel_dead" },
			{ observation: "execution_completed", status: "ok", completionSource: "heartbeat_echo", durationMs: 1 },
		]) {
			const payload = Buffer.from(
				JSON.stringify({
					version: 1,
					kind: "event",
					sequence: 1,
					event: { ...identity, ...invalid, type: "kernel_protocol_observation" },
				}),
			);
			const mac = createHmac("sha256", Buffer.from(capability, "base64url")).update(payload).digest("base64url");
			const losses: unknown[] = [];
			const decoder = new KernelDiagnosticBridgeDecoder({
				capability,
				onEvent: () => {
					throw new Error("accepted invalid observation");
				},
				onDrop: () => {},
				onLoss: (loss) => losses.push(loss),
			});
			decoder.push(Buffer.from(`GKD1.${payload.toString("base64url")}.${mac}\n`));
			expect(losses).toEqual([{ reason: "invalid_payload" }]);
		}
	});

	it("leaves the startup reply to probeReady, then observes shell replies without settling execution", async () => {
		const h = await harness();
		try {
			const ready = h.internals.probeReady();
			const probe = await h.receive();
			expect(probe.header.msg_type).toBe("kernel_info_request");
			await probe.reply("kernel_info_reply");
			await ready;
			h.internals.startProtocolObservers();
			let completed = false;
			const execution = h.manager.execute("secret-cell-source").then((result) => {
				completed = true;
				return result;
			});
			const request = await h.receive();
			h.internals.handleExecutionMessage(message("status", request.header.msg_id, { execution_state: "busy" }));
			await request.reply("execute_reply", { status: "ok", payload: "secret-reply-payload" });
			await vi.waitFor(() =>
				expect(progress(h.events).some((event) => event.observation === "shell_reply")).toBe(true),
			);
			await delay(1100);
			expect(completed).toBe(false);
			expect(h.manager.isRunning).toBe(true);
			expect(
				progress(h.events).some(
					(event) =>
						event.observation === "execution_completed" || event.observation === "shell_reply_unavailable",
				),
			).toBe(false);
			h.internals.handleExecutionMessage(message("status", request.header.msg_id, { execution_state: "idle" }));
			await expect(execution).resolves.toMatchObject({ status: "ok" });
			expect(progress(h.events)).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ observation: "iopub_busy", requestMsgId: request.header.msg_id }),
					expect.objectContaining({
						observation: "shell_reply",
						requestMsgId: request.header.msg_id,
						status: "ok",
					}),
					expect.objectContaining({ observation: "iopub_idle", requestMsgId: request.header.msg_id }),
					expect.objectContaining({
						observation: "execution_completed",
						requestMsgId: request.header.msg_id,
						status: "ok",
						completionSource: "iopub_idle",
					}),
				]),
			);
			expect(JSON.stringify(h.events)).not.toContain("secret-");
			expect(h.internals.pendingShellObservations.size).toBe(0);
		} finally {
			await h.close();
		}
	});

	it("reports a missing shell reply only after idle, while heartbeat remains independent", async () => {
		const h = await harness();
		try {
			h.internals.startProtocolObservers();
			const execution = h.manager.execute("still-running");
			const request = await h.receive();
			h.internals.handleExecutionMessage(message("status", request.header.msg_id, { execution_state: "busy" }));
			await delay(1100);
			expect(progress(h.events).some((event) => event.observation === "shell_reply_unavailable")).toBe(false);
			expect(progress(h.events).some((event) => event.observation === "heartbeat_echo")).toBe(true);
			h.internals.handleExecutionMessage(message("status", request.header.msg_id, { execution_state: "idle" }));
			await execution;
			await vi.waitFor(
				() =>
					expect(progress(h.events)).toContainEqual(
						expect.objectContaining({
							observation: "shell_reply_unavailable",
							requestMsgId: request.header.msg_id,
							reason: "not_observed_after_idle",
						}),
					),
				{ timeout: 2000 },
			);
			expect(h.manager.isRunning).toBe(true);
			expect(
				h.events.some(
					(event) => event.type === "kernel_lifecycle_intent" || event.type === "kernel_unexpected_exit",
				),
			).toBe(false);
		} finally {
			await h.close();
		}
	});

	it("recovers only the heartbeat observation after timeout without changing kernel lifecycle", async () => {
		const h = await harness();
		try {
			h.setEcho(false);
			h.internals.startProtocolObservers();
			await vi.waitFor(
				() =>
					expect(progress(h.events)).toContainEqual(
						expect.objectContaining({ observation: "heartbeat_unavailable", reason: "timeout" }),
					),
				{ timeout: 2500 },
			);
			h.setEcho(true);
			const recovered = h.internals.probeHeartbeat();
			await h.deliverHeldHeartbeat();
			await recovered;
			expect(progress(h.events)).toEqual([
				expect.objectContaining({ observation: "heartbeat_unavailable", reason: "timeout" }),
				expect.objectContaining({ observation: "heartbeat_echo" }),
			]);
			expect(h.manager.isRunning).toBe(true);
			expect(
				h.events.some(
					(event) => event.type === "kernel_lifecycle_intent" || event.type === "kernel_unexpected_exit",
				),
			).toBe(false);
		} finally {
			await h.close();
		}
	});

	it("cancels a pending heartbeat and reply grace on cleanup without late observations", async () => {
		const h = await harness();
		try {
			h.setEcho(false);
			h.internals.startProtocolObservers();
			h.internals.markKernelExecutionStarted("cleanup-request");
			h.internals.handleExecutionMessage(message("status", "cleanup-request", { execution_state: "idle" }));
			h.manager.disposeSync();
			const count = progress(h.events).length;
			await delay(1100);
			expect(progress(h.events)).toHaveLength(count);
			expect(h.internals.pendingShellObservations.size).toBe(0);
			expect(h.internals.heartbeatTimer).toBeUndefined();
			expect(h.internals.heartbeat).toBeUndefined();
		} finally {
			await h.close();
		}
	});

	it("bounds pending reply identity and exposes an eviction gap", async () => {
		const h = await harness();
		try {
			for (let i = 0; i < 130; i++) h.internals.markKernelExecutionStarted(`request-${i}`);
			expect(h.internals.pendingShellObservations.size).toBe(128);
			expect(
				progress(h.events).filter(
					(event) => event.observation === "shell_reply_unavailable" && event.reason === "tracking_capacity",
				),
			).toHaveLength(2);
			h.manager.disposeSync();
			expect(h.internals.pendingShellObservations.size).toBe(0);
			expect(h.internals.heartbeatTimer).toBeUndefined();
			expect(h.internals.heartbeat).toBeUndefined();
		} finally {
			await h.close();
		}
	});

	it("retains the execution generation when cleanup rejects its pending result", async () => {
		const h = await harness();
		try {
			const execution = h.manager.execute("waiting").catch((error: unknown) => error);
			const request = await h.receive();
			h.manager.disposeSync();
			expect(await execution).toBeInstanceOf(Error);
			expect(progress(h.events)).toContainEqual(
				expect.objectContaining({
					observation: "execution_completed",
					status: "rejected",
					completionSource: "rejected",
					kernelGeneration: 0,
					requestMsgId: request.header.msg_id,
				}),
			);
		} finally {
			await h.close();
		}
	});
});

describe("real IPython protocol observations", { tags: ["kernel-heavy"] }, () => {
	it("keeps heartbeat and original state during a healthy cell longer than the reply grace", async () => {
		const python = process.env.PRIME_AGENT_CAUSAL_PYTHON ?? (await ensureKernelPython());
		vi.stubEnv("PRIME_AGENT_KERNEL_FORKSERVER", "0");
		const directory = mkdtempSync(join(tmpdir(), "kernel-protocol-live-"));
		const manager = new KernelManager({ python, cwd: directory, sessionId: "protocol-live-session" });
		const events: KernelDiagnosticEvent[] = [];
		const unsubscribe = subscribeKernelDiagnostics((event) => {
			if (event.sessionId === "protocol-live-session") events.push(event);
		});
		try {
			await manager.execute("import os, time\nsentinel = 'private-protocol-sentinel'\noriginal_pid = os.getpid()");
			const original = events.find((event) => event.type === "kernel_process_started")!;
			const execution = manager.execute("time.sleep(6)");
			await vi.waitFor(() =>
				expect(events.filter((event) => event.type === "kernel_execute_started")).toHaveLength(2),
			);
			const busyRequest = events.filter((event) => event.type === "kernel_execute_started").at(-1)!;
			if (busyRequest.type !== "kernel_execute_started") throw new Error("missing execution identity");
			await vi.waitFor(() =>
				expect(progress(events)).toContainEqual(
					expect.objectContaining({ observation: "iopub_busy", requestMsgId: busyRequest.requestMsgId }),
				),
			);
			await vi.waitFor(
				() =>
					expect(progress(events)).toContainEqual(
						expect.objectContaining({ observation: "heartbeat_echo", requestMsgId: busyRequest.requestMsgId }),
					),
				{ timeout: 6500 },
			);
			await expect(execution).resolves.toMatchObject({ status: "ok" });
			await vi.waitFor(() =>
				expect(progress(events)).toContainEqual(
					expect.objectContaining({ observation: "shell_reply", requestMsgId: busyRequest.requestMsgId }),
				),
			);
			expect(
				progress(events).filter(
					(event) =>
						event.observation === "shell_reply_unavailable" || event.observation === "heartbeat_unavailable",
				),
			).toEqual([]);
			expect(events.filter((event) => event.type === "kernel_process_started")).toHaveLength(1);
			expect(
				events.some((event) => event.type === "kernel_lifecycle_intent" || event.type === "kernel_unexpected_exit"),
			).toBe(false);
			const retained = await manager.execute(
				"assert os.getpid() == original_pid\nassert sentinel == 'private-protocol-sentinel'\nprint(original_pid)",
			);
			expect(retained.stdout.trim()).toBe(String(original.kernelPid));
			expect(JSON.stringify(events)).not.toContain("private-protocol-sentinel");
		} finally {
			await manager.dispose();
			unsubscribe();
			rmSync(directory, { recursive: true, force: true });
		}
	}, 30_000);
});
