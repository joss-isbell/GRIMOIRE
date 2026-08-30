import { spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { once } from "node:events";
import { chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PassThrough, Readable, Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import {
	encodeKernelDiagnosticBridgeEvent,
	KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES,
	ReconnectableKernelDiagnosticBridgeWriter,
	type KernelDiagnosticBridgeDropCounts,
} from "../src/core/kernel/diagnostic-bridge.js";
import type { KernelDiagnosticEvent } from "../src/core/kernel/diagnostics.js";
import {
	attachDaemonWorkerKernelDiagnosticCapture,
	connectDaemonWorkerKernelDiagnostic,
	daemonWorkerKernelDiagnosticSocketPath,
	DAEMON_WORKER_KERNEL_DIAGNOSTIC_SOCKET_MAX_PATH_BYTES,
	DaemonWorkerKernelDiagnosticServer,
	type DaemonWorkerDiagnosticSupervisorClaim,
	mayCloseInvalidDaemonWorkerKernelDiagnosticFd,
	type DaemonWorkerKernelDiagnosticCaptureSinks,
} from "../src/modes/daemon/daemon-worker-kernel-diagnostics.js";
import {
	isDaemonWorkerDescriptor,
	sanitizeDaemonWorkerDiagnosticMetadata,
} from "../src/modes/daemon/daemon-supervisor.js";
import { INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX } from "../src/modes/daemon/incident-recorder.js";
import {
	DAEMON_WORKER_KERNEL_DIAGNOSTIC_CAPABILITY_ENV,
	DAEMON_WORKER_KERNEL_DIAGNOSTIC_FD_ENV,
	DAEMON_WORKER_STARTUP_GATE_FD_ENV,
} from "../src/modes/daemon/daemon-worker-protocol.js";

function capability(): string {
	return randomBytes(32).toString("base64url");
}

function unexpectedExit(stderrTail: Buffer): KernelDiagnosticEvent {
	return {
		type: "kernel_unexpected_exit",
		sessionId: "root-reconnect-session",
		kernelInstanceId: "kernel-reconnect-crash",
		kernelPid: 3131,
		kernelProcessStartId: "kernel-reconnect-start",
		launchMode: "direct",
		crashPhase: "executing",
		requestMsgId: "request-reconnect-crash",
		code: 137,
		signal: "SIGKILL",
		reason: "process_exit",
		stderrTail,
		stderrBytes: stderrTail.byteLength,
		sourceTruncated: false,
	};
}

function signedPayload(payload: unknown, secret: string): Buffer {
	const bytes = Buffer.from(JSON.stringify(payload));
	const mac = createHmac("sha256", Buffer.from(secret, "base64url")).update(bytes).digest("base64url");
	return Buffer.from(`GKD1.${bytes.toString("base64url")}.${mac}\n`, "ascii");
}

async function waitFor(predicate: () => boolean, timeoutMs = 2500): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error("Timed out waiting for diagnostic bridge state");
		await new Promise<void>((resolve) => setTimeout(resolve, 10));
	}
}

function captureSinks(): {
	sinks: DaemonWorkerKernelDiagnosticCaptureSinks;
	transport: Buffer[];
	events: Array<{ type: string; fields: Record<string, unknown> }>;
	kernels: KernelDiagnosticEvent[];
	kernelCorrelations: Array<Record<string, unknown>>;
	order: string[];
} {
	const transport: Buffer[] = [];
	const events: Array<{ type: string; fields: Record<string, unknown> }> = [];
	const kernels: KernelDiagnosticEvent[] = [];
	const kernelCorrelations: Array<Record<string, unknown>> = [];
	const order: string[] = [];
	return {
		transport,
		events,
		kernels,
		kernelCorrelations,
		order,
		sinks: {
			appendBytes: (type, value) => {
				order.push(`bytes:${type}`);
				transport.push(Buffer.from(value));
			},
			appendEvent: (type, fields) => {
				order.push(`event:${type}`);
				events.push({ type, fields });
			},
			appendKernel: (event, correlation) => {
				order.push(`kernel:${event.type}`);
				kernels.push(event);
				kernelCorrelations.push(correlation);
			},
		},
	};
}

describe("daemon worker kernel diagnostic bridge", () => {
	it("correlates a crash across a real inherited worker pipe without leaking fd6 or its capability", async () => {
		const secret = capability();
		const fixture = fileURLToPath(
			new URL("./fixtures/daemon-worker-kernel-diagnostic-bridge.ts", import.meta.url),
		);
		const child = spawn(process.execPath, ["--import", "tsx", fixture], {
			cwd: process.cwd(),
			env: {
				...process.env,
				[DAEMON_WORKER_STARTUP_GATE_FD_ENV]: "3",
				[DAEMON_WORKER_KERNEL_DIAGNOSTIC_FD_ENV]: "6",
				[DAEMON_WORKER_KERNEL_DIAGNOSTIC_CAPABILITY_ENV]: secret,
				GRIMOIRE_TEST_SESSION_ID: "real-worker-session",
			},
			stdio: ["ignore", "pipe", "pipe", "pipe", "ignore", "ignore", "pipe"],
		});
		const childStdio = child.stdio as ReadonlyArray<Readable | Writable | null | undefined>;
		const startupGate = childStdio[3];
		const diagnosticPipe = childStdio[6];
		expect(startupGate).toBeInstanceOf(Writable);
		expect(diagnosticPipe).toBeInstanceOf(Readable);
		const capture = captureSinks();
		const detach = attachDaemonWorkerKernelDiagnosticCapture(
			diagnosticPipe as Readable,
			secret,
			{
				workerId: "worker-real-boundary",
				rootActiveSessionId: "real-worker-session",
				socketPath: "/tmp/worker-real-boundary.sock",
				childPid: child.pid,
			},
			capture.sinks,
		);
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		child.stdout?.on("data", (chunk: Buffer) => stdout.push(Buffer.from(chunk)));
		child.stderr?.on("data", (chunk: Buffer) => stderr.push(Buffer.from(chunk)));
		(startupGate as Writable).end("start\n");
		const [code, signal] = (await once(child, "close")) as [number | null, NodeJS.Signals | null];
		detach();

		expect({ code, signal, stderr: Buffer.concat(stderr).toString("utf8") }).toMatchObject({
			code: 0,
			signal: null,
			stderr: "",
		});
		expect(JSON.parse(Buffer.concat(stdout).toString("utf8"))).toEqual({
			capabilityPresent: false,
			fdEnvPresent: false,
			sameBridgeFd: false,
		});
		expect(capture.transport.length).toBeGreaterThan(0);
		expect(capture.kernels).toHaveLength(1);
		expect(capture.kernelCorrelations).toEqual([
			expect.objectContaining({ workerId: "worker-real-boundary" }),
		]);
		expect(capture.kernels[0]).toMatchObject({
			type: "kernel_unexpected_exit",
			sessionId: "real-worker-session",
			kernelInstanceId: "worker-kernel-instance",
			requestMsgId: "worker-request-id",
			code: 137,
			signal: "SIGKILL",
		});
		if (capture.kernels[0]?.type !== "kernel_unexpected_exit") throw new Error("Expected crash event");
		expect(Buffer.from(capture.kernels[0].stderrTail ?? [])).toEqual(
			Buffer.from([0x00, 0xff, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x0a]),
		);
		expect(capture.order[0]).toBe("bytes:worker_transport_kernel_diagnostic");
		expect(capture.order.indexOf("bytes:worker_transport_kernel_diagnostic")).toBeLessThan(
			capture.order.indexOf("kernel:kernel_unexpected_exit"),
		);
	});

	it("captures malformed and oversize bytes exactly and reports authenticated drops before resuming", async () => {
		const secret = capability();
		const stream = new PassThrough();
		const capture = captureSinks();
		const detach = attachDaemonWorkerKernelDiagnosticCapture(
			stream,
			secret,
			{
				workerId: "worker-malformed",
				rootActiveSessionId: "session-malformed",
				socketPath: "/tmp/worker-malformed.sock",
			},
			capture.sinks,
		);
		const malformed = Buffer.from("not-a-frame\n");
		const oversize = Buffer.concat([
			Buffer.alloc(KERNEL_DIAGNOSTIC_BRIDGE_MAX_LINE_BYTES + 1, 0x78),
			Buffer.from("\n"),
		]);
		const counts: KernelDiagnosticBridgeDropCounts = {
			queueOverflow: 3,
			evictedNormal: 2,
			criticalOverflow: 0,
			oversize: 0,
			encodeFailure: 0,
			transportError: 0,
			shutdown: 0,
		};
		const drop = signedPayload({ version: 1, kind: "drop", sequence: 1, counts }, secret);
		const valid = encodeKernelDiagnosticBridgeEvent(
			{
				type: "kernel_ready",
				sessionId: "session-malformed",
				kernelInstanceId: "kernel-after-corruption",
				kernelPid: 99,
				launchMode: "fork",
				phase: "idle",
			},
			secret,
			2,
		)!;
		for (const value of [malformed, oversize, drop, valid]) stream.write(value);
		stream.end();
		await once(stream, "close");
		detach();

		expect(Buffer.concat(capture.transport)).toEqual(Buffer.concat([malformed, oversize, drop, valid]));
		expect(capture.events.filter((event) => event.type === "worker_kernel_diagnostic_transport_loss"))
			.toHaveLength(2);
		expect(capture.events.find((event) => event.type === "worker_kernel_diagnostic_drop")?.fields)
			.toMatchObject(counts);
		expect(capture.events.find((event) => event.type === "worker_kernel_diagnostic_drop")?.fields)
			.not.toHaveProperty("counts");
		expect(capture.kernels).toHaveLength(1);
		expect(capture.kernels[0]).toMatchObject({
			type: "kernel_ready",
			kernelInstanceId: "kernel-after-corruption",
		});
		expect(
			capture.events.filter((event) => event.type === "worker_kernel_diagnostic_transport_closed"),
		).toHaveLength(1);
	});

	it("never treats fd3, fd4, or fd5 as closable invalid diagnostic descriptors", () => {
		expect([3, 4, 5].map(mayCloseInvalidDaemonWorkerKernelDiagnosticFd)).toEqual([false, false, false]);
		expect(mayCloseInvalidDaemonWorkerKernelDiagnosticFd(6)).toBe(true);
	});

	it("uses a bounded runtime socket path for default and deliberately long agent directories", async () => {
		if (process.platform === "win32") return;
		const root = mkdtempSync(join(tmpdir(), "grimoire-kernel-runtime-"));
		const runtimeDirectory = join(root, "diagnostics");
		mkdirSync(runtimeDirectory, { mode: 0o700 });
		const agentDirectories = [
			"/home/joss/.prime-agent/agents/default",
			join("/home/joss", "deliberately-long-agent-directory".repeat(12), "agents", "default"),
		];
		try {
			for (const [index, agentDir] of agentDirectories.entries()) {
				const supervisorSocketPath = join(agentDir, "runtime", "daemon.sock");
				const workerId = `worker-path-${index}`;
				const socketPath = daemonWorkerKernelDiagnosticSocketPath(
					runtimeDirectory,
					supervisorSocketPath,
					workerId,
					`path-salt-${index}`,
				);
				expect(Buffer.byteLength(socketPath, "utf8")).toBeLessThanOrEqual(
					DAEMON_WORKER_KERNEL_DIAGNOSTIC_SOCKET_MAX_PATH_BYTES,
				);
				expect(socketPath).not.toContain(workerId);
				expect(socketPath).not.toContain(agentDir);
				const secret = capability();
				const initialPipe = new PassThrough();
				const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret);
				writer.attach(initialPipe);
				const server = new DaemonWorkerKernelDiagnosticServer({
					socketPath,
					workerId,
					workerPid: process.pid,
					workerProcessStartId: `worker-path-start-${index}`,
					capability: secret,
					installation: { writer, close: () => writer.close() },
					validateSupervisor: async () => `path-owner-${index}`,
				});
				try {
					const identity = await server.start();
					writer.publish({
						type: "kernel_ready",
						kernelInstanceId: `kernel-path-${index}`,
						kernelPid: 7000 + index,
						launchMode: "direct",
						phase: "idle",
					});
					const connection = await connectDaemonWorkerKernelDiagnostic({
						socketPath,
						expectedSocketDevice: identity.device,
						expectedSocketInode: identity.inode,
						workerId,
						workerPid: process.pid,
						workerProcessStartId: `worker-path-start-${index}`,
						capability: secret,
						mode: "launch_handoff",
						afterSequence: 0,
						supervisor: {
							supervisorGeneration: `path-generation-${index}`,
							supervisorPid: process.pid,
							supervisorSocketPath,
						},
					});
					expect(connection.afterSequence).toBe(1);
					connection.socket.destroy();
				} finally {
					await server.close();
					writer.close();
					await writer.whenClosed;
				}
			}

			const overlongPath = join("/tmp", "x".repeat(DAEMON_WORKER_KERNEL_DIAGNOSTIC_SOCKET_MAX_PATH_BYTES));
			const overlongSecret = capability();
			const overlongWriter = new ReconnectableKernelDiagnosticBridgeWriter(overlongSecret);
			const overlongServer = new DaemonWorkerKernelDiagnosticServer({
				socketPath: overlongPath,
				workerId: "worker-overlong",
				workerPid: process.pid,
				capability: overlongSecret,
				installation: { writer: overlongWriter, close: () => overlongWriter.close() },
				validateSupervisor: async () => "overlong-owner",
			});
			await expect(overlongServer.start()).rejects.toThrow("sockaddr_un");
			await expect(
				connectDaemonWorkerKernelDiagnostic({
					socketPath: overlongPath,
					workerId: "worker-overlong",
					workerPid: process.pid,
					capability: overlongSecret,
					mode: "reconnect",
					afterSequence: 0,
					supervisor: {
						supervisorGeneration: "overlong-owner",
						supervisorPid: process.pid,
						supervisorSocketPath: "/tmp/supervisor.sock",
					},
				}),
			).rejects.toThrow("sockaddr_un");
			overlongWriter.close();
			await overlongWriter.whenClosed;
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	it("keeps product descriptors adoptable while stripping malformed diagnostic metadata", () => {
		const supervisorSocketPath = "/tmp/grimoire-product-supervisor.sock";
		const descriptorDir = "/tmp/grimoire-descriptors";
		const diagnosticSocketDir = "/tmp/grimoire-runtime/diagnostics";
		const base: Record<string, unknown> = {
			version: 2,
			workerId: "worker-adoption-metadata",
			pid: 4242,
			processStartId: "worker-start",
			socketPath: "/tmp/grimoire-product-worker.sock",
			recoveryJournalPath: "/tmp/worker.recovery.jsonl",
			supervisorSocketPath,
			authenticationToken: "product-token",
			rootActiveSessionId: "root-session",
			createdAt: new Date(0).toISOString(),
			updatedAt: new Date(0).toISOString(),
			lifecycle: "recovering",
			createCommand: { type: "create" },
			consecutiveFailures: 0,
		};
		const validDiagnostic = {
			diagnosticProtocolVersion: 1,
			diagnosticSocketPath: join(diagnosticSocketDir, "0123456789abcdef.sock"),
			diagnosticSecretPath: join(
				descriptorDir,
				`worker${INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX}`,
			),
			diagnosticSecretDevice: "1",
			diagnosticSecretInode: "2",
		};
		const invalidVariants: Array<Record<string, unknown>> = [
			{ ...validDiagnostic, diagnosticProtocolVersion: 99 },
			{ diagnosticProtocolVersion: 1, diagnosticSocketPath: validDiagnostic.diagnosticSocketPath },
			{
				...validDiagnostic,
				diagnosticSecretPath: join(
					descriptorDir,
					"..",
					`escaped${INCIDENT_RECORDER_EXCLUDED_DIAGNOSTIC_CAPABILITY_SUFFIX}`,
				),
			},
			{ ...validDiagnostic, diagnosticSocketPath: "/tmp/escaped-diagnostic.sock" },
		];
		for (const invalidDiagnostic of invalidVariants) {
			const descriptor = { ...base, ...invalidDiagnostic };
			expect(isDaemonWorkerDescriptor(descriptor, supervisorSocketPath)).toBe(true);
			expect(
				sanitizeDaemonWorkerDiagnosticMetadata(descriptor, descriptorDir, diagnosticSocketDir),
			).toBe(false);
			expect(descriptor).toMatchObject({
				workerId: base.workerId,
				authenticationToken: base.authenticationToken,
				createCommand: base.createCommand,
			});
			for (const key of Object.keys(validDiagnostic)) expect(descriptor).not.toHaveProperty(key);
		}
		const valid = { ...base, ...validDiagnostic };
		expect(sanitizeDaemonWorkerDiagnosticMetadata(valid, descriptorDir, diagnosticSocketDir)).toBe(true);
		expect(valid).toMatchObject(validDiagnostic);
	});

	it("finalizes once when error, close, and detach converge", async () => {
		const stream = new PassThrough();
		const capture = captureSinks();
		const detach = attachDaemonWorkerKernelDiagnosticCapture(
			stream,
			capability(),
			{
				workerId: "worker-error-finalize",
				rootActiveSessionId: "session-error-finalize",
				socketPath: "/tmp/worker-error-finalize.sock",
			},
			capture.sinks,
		);
		stream.write("partial-frame");
		const closed = new Promise<void>((resolve) => stream.once("close", () => resolve()));
		stream.destroy(new Error("diagnostic pipe failed"));
		await closed;
		detach();

		expect(
			capture.events.filter((event) => event.type === "worker_kernel_diagnostic_transport_closed"),
		).toHaveLength(1);
		expect(
			capture.events.filter(
				(event) =>
					event.type === "worker_kernel_diagnostic_transport_loss" &&
					event.fields.reason === "trailing_partial_frame",
			),
		).toHaveLength(1);
	});

	it("hands fd6 off to the dedicated socket, replays across adoption, and fences a stale supervisor", async () => {
		if (process.platform === "win32") return;
		const directory = mkdtempSync(join(tmpdir(), "grimoire-kernel-diagnostic-"));
		const socketPath = join(directory, "worker.sock");
		const secret = capability();
		const workerId = "worker-reconnect-boundary";
		const workerProcessStartId = "worker-start-77";
		let currentGeneration = "supervisor-generation-1";
		const claim = (generation: string): DaemonWorkerDiagnosticSupervisorClaim => ({
			supervisorGeneration: generation,
			supervisorPid: process.pid,
			supervisorProcessStartId: `start-${generation}`,
			supervisorSocketPath: "/tmp/grimoire-product-supervisor.sock",
		});
		const validateSupervisor = async (
			candidate: DaemonWorkerDiagnosticSupervisorClaim,
			validatedFingerprint?: string,
		): Promise<string> => {
			if (candidate.supervisorGeneration !== currentGeneration) {
				throw new Error("stale supervisor generation");
			}
			const fingerprint = `${candidate.supervisorGeneration}:${candidate.supervisorProcessStartId}`;
			if (validatedFingerprint !== undefined && validatedFingerprint !== fingerprint) {
				throw new Error("supervisor fingerprint changed");
			}
			return fingerprint;
		};
		const initialPipe = new PassThrough();
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret);
		writer.attach(initialPipe);
		const installation = { writer, close: () => writer.close() };
		const server = new DaemonWorkerKernelDiagnosticServer({
			socketPath,
			workerId,
			workerPid: process.pid,
			workerProcessStartId,
			capability: secret,
			installation,
			validateSupervisor,
		});
		const initialCapture = captureSinks();
		const detachInitial = attachDaemonWorkerKernelDiagnosticCapture(
			initialPipe,
			secret,
			{
				workerId,
				rootActiveSessionId: "root-reconnect-session",
				socketPath: "/tmp/grimoire-product-worker.sock",
				childPid: process.pid,
			},
			initialCapture.sinks,
		);

		let firstSocket: import("node:net").Socket | undefined;
		let secondSocket: import("node:net").Socket | undefined;
		let thirdSocket: import("node:net").Socket | undefined;
		try {
			const socketIdentity = await server.start();
			writer.publish({
				type: "kernel_ready",
				sessionId: "root-reconnect-session",
				kernelInstanceId: "kernel-before-handoff",
				kernelPid: 3131,
				launchMode: "direct",
				phase: "idle",
			});
			await waitFor(() => initialCapture.kernels.length === 1);

			const first = await connectDaemonWorkerKernelDiagnostic({
				socketPath,
				expectedSocketDevice: socketIdentity.device,
				expectedSocketInode: socketIdentity.inode,
				workerId,
				workerPid: process.pid,
				workerProcessStartId,
				capability: secret,
				mode: "launch_handoff",
				afterSequence: 0,
				supervisor: claim(currentGeneration),
			});
			firstSocket = first.socket;
			expect(first.afterSequence).toBe(1);
			const firstCapture = captureSinks();
			attachDaemonWorkerKernelDiagnosticCapture(
				first.socket,
				secret,
				{
					workerId,
					rootActiveSessionId: "root-reconnect-session",
					socketPath: "/tmp/grimoire-product-worker.sock",
					childPid: process.pid,
				},
				firstCapture.sinks,
				{ initialSequence: first.afterSequence, initialBytes: first.initialBytes },
			);
			first.socket.resume();
			writer.publish(unexpectedExit(Buffer.from([0x00, 0xff, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x79])));
			await waitFor(() => firstCapture.kernels.length === 1);
			expect(firstCapture.kernelCorrelations).toEqual([
				expect.objectContaining({ workerId }),
			]);
			const capturedSocketBytes = Buffer.concat(firstCapture.transport).toString("ascii");
			expect(capturedSocketBytes).toMatch(/^GKD1\./);
			expect(capturedSocketBytes).not.toContain("GKDA1");

			const firstClosed = once(first.socket, "close");
			first.socket.destroy();
			await firstClosed;
			writer.publish({
				type: "kernel_channel_fault",
				sessionId: "root-reconnect-session",
				kernelInstanceId: "kernel-after-supervisor-crash",
				kernelPid: 3131,
				launchMode: "direct",
				channel: "iopub",
				crashPhase: "executing",
				reason: "channel closed during execution",
			});

			const second = await connectDaemonWorkerKernelDiagnostic({
				socketPath,
				expectedSocketDevice: socketIdentity.device,
				expectedSocketInode: socketIdentity.inode,
				workerId,
				workerPid: process.pid,
				workerProcessStartId,
				capability: secret,
				mode: "reconnect",
				afterSequence: 2,
				supervisor: claim(currentGeneration),
			});
			secondSocket = second.socket;
			let secondLastSequence = second.afterSequence;
			const secondCapture = captureSinks();
			attachDaemonWorkerKernelDiagnosticCapture(
				second.socket,
				secret,
				{
					workerId,
					rootActiveSessionId: "root-reconnect-session",
					socketPath: "/tmp/grimoire-product-worker.sock",
					childPid: process.pid,
				},
				secondCapture.sinks,
				{
					initialSequence: second.afterSequence,
					initialBytes: second.initialBytes,
					onSequence: (sequence) => {
						secondLastSequence = sequence;
					},
				},
			);
			second.socket.resume();
			await waitFor(() =>
				secondCapture.kernels.some((event) => event.type === "kernel_channel_fault"),
			);

			currentGeneration = "supervisor-generation-2";
			await waitFor(() => second.socket.destroyed);
			await expect(
				connectDaemonWorkerKernelDiagnostic({
					socketPath,
					workerId,
					workerPid: process.pid,
					workerProcessStartId,
					capability: secret,
					mode: "reconnect",
					afterSequence: secondLastSequence,
					supervisor: claim("supervisor-generation-1"),
				}),
			).rejects.toThrow();
			const third = await connectDaemonWorkerKernelDiagnostic({
				socketPath,
				workerId,
				workerPid: process.pid,
				workerProcessStartId,
				capability: secret,
				mode: "reconnect",
				afterSequence: secondLastSequence,
				supervisor: claim(currentGeneration),
			});
			thirdSocket = third.socket;
			expect(third.latestSequence).toBeGreaterThanOrEqual(secondLastSequence);
			third.socket.resume();
		} finally {
			firstSocket?.destroy();
			secondSocket?.destroy();
			thirdSocket?.destroy();
			detachInitial();
			await server.close();
			writer.close();
			await writer.whenClosed;
			rmSync(directory, { recursive: true, force: true });
		}
	});

	it("reclaims an identity-stable stale diagnostic socket without following a replacement", async () => {
		if (process.platform === "win32") return;
		const directory = mkdtempSync(join(tmpdir(), "grimoire-kernel-stale-"));
		const socketPath = join(directory, "stale.sock");
		const stale = spawn(
			process.execPath,
			[
				"-e",
				"const net=require('node:net');const server=net.createServer();server.listen(process.argv[1],()=>process.stdout.write('ready'));setInterval(()=>{},1000);",
				socketPath,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		await once(stale.stdout!, "data");
		chmodSync(socketPath, 0o600);
		expect(lstatSync(socketPath, { bigint: true }).isSocket()).toBe(true);
		const staleClosed = once(stale, "close");
		stale.kill("SIGKILL");
		await staleClosed;

		const secret = capability();
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret);
		const server = new DaemonWorkerKernelDiagnosticServer({
			socketPath,
			workerId: "worker-stale-socket",
			workerPid: process.pid,
			workerProcessStartId: "stale-test-start",
			capability: secret,
			installation: { writer, close: () => writer.close() },
			validateSupervisor: async () => "current-owner",
		});
		try {
			const identity = await server.start();
			expect(lstatSync(socketPath, { bigint: true }).isSocket()).toBe(true);
			const connection = await connectDaemonWorkerKernelDiagnostic({
				socketPath,
				expectedSocketDevice: identity.device,
				expectedSocketInode: identity.inode,
				workerId: "worker-stale-socket",
				workerPid: process.pid,
				workerProcessStartId: "stale-test-start",
				capability: secret,
				mode: "reconnect",
				afterSequence: 0,
				supervisor: {
					supervisorGeneration: "current-owner",
					supervisorPid: process.pid,
					supervisorSocketPath: "/tmp/grimoire-stale-test-supervisor.sock",
				},
			});
			connection.socket.destroy();
		} finally {
			await server.close();
			writer.close();
			await writer.whenClosed;
			rmSync(directory, { recursive: true, force: true });
		}
	});

	it("rejects a live diagnostic socket whose inode has another hard link", async () => {
		if (process.platform === "win32") return;
		const directory = mkdtempSync(join(tmpdir(), "grimoire-kernel-hardlink-"));
		const socketPath = join(directory, "worker.sock");
		const linkedPath = join(directory, "linked.sock");
		const secret = capability();
		const writer = new ReconnectableKernelDiagnosticBridgeWriter(secret);
		const server = new DaemonWorkerKernelDiagnosticServer({
			socketPath,
			workerId: "worker-hardlink-socket",
			workerPid: process.pid,
			workerProcessStartId: "hardlink-test-start",
			capability: secret,
			installation: { writer, close: () => writer.close() },
			validateSupervisor: async () => "hardlink-owner",
		});
		let linked = false;
		try {
			const identity = await server.start();
			linkSync(socketPath, linkedPath);
			linked = true;
			expect(lstatSync(socketPath, { bigint: true }).nlink).toBe(2n);
			await expect(
				connectDaemonWorkerKernelDiagnostic({
					socketPath,
					expectedSocketDevice: identity.device,
					expectedSocketInode: identity.inode,
					workerId: "worker-hardlink-socket",
					workerPid: process.pid,
					workerProcessStartId: "hardlink-test-start",
					capability: secret,
					mode: "reconnect",
					afterSequence: 0,
					supervisor: {
						supervisorGeneration: "hardlink-owner",
						supervisorPid: process.pid,
						supervisorSocketPath: "/tmp/grimoire-hardlink-supervisor.sock",
					},
				}),
			).rejects.toThrow("non-symlink socket");
		} finally {
			if (linked) unlinkSync(linkedPath);
			await server.close();
			writer.close();
			await writer.whenClosed;
			rmSync(directory, { recursive: true, force: true });
		}
	});
});
