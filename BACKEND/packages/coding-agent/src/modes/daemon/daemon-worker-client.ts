import { createConnection, type Socket } from "node:net";
import { serializeJsonLine } from "../rpc/jsonl.js";
import { type PrivateFrame, PrivateFramedChannel } from "../session-worker/private-framing.js";
import type { DaemonCommand, DaemonOutbound, DaemonResponse } from "./daemon-protocol.js";
import {
	type DaemonWorkerCommand,
	type DaemonWorkerCommandBody,
	type DaemonWorkerFrameHeader,
	isDaemonWorkerFrameHeader,
} from "./daemon-worker-protocol.js";
import { appendSupervisorDiagnosticBytes, appendSupervisorDiagnosticEvent } from "./incident-recorder.js";

type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never;
type DaemonCommandBody = DistributiveOmit<DaemonCommand, "id">;
type DaemonWorkerWireCommandBody = DaemonCommandBody | DaemonWorkerCommandBody;
type DaemonWorkerWireCommand = DaemonCommand | DaemonWorkerCommand;
type DaemonWorkerAuthentication = Omit<Extract<DaemonWorkerCommand, { type: "worker_auth" }>, "id" | "type" | "token">;

export type DaemonWorkerFrameListener = (frame: PrivateFrame<DaemonWorkerFrameHeader>) => void;
export type DaemonWorkerCloseListener = (error: Error) => void;
type DaemonHello = Extract<DaemonOutbound, { type: "daemon_hello" }>;

export class DaemonWorkerClient {
	private socket?: Socket;
	private channel?: PrivateFramedChannel<DaemonWorkerFrameHeader>;
	private readonly frameListeners = new Set<DaemonWorkerFrameListener>();
	private readonly closeListeners = new Set<DaemonWorkerCloseListener>();
	private readonly pending = new Map<
		string,
		{
			resolve: (response: DaemonResponse) => void;
			reject: (error: Error) => void;
			timeout: ReturnType<typeof setTimeout>;
		}
	>();
	private requestId = 0;
	private hello?: DaemonHello;
	private readonly helloWaiters = new Set<{
		resolve: (hello: DaemonHello) => void;
		reject: (error: Error) => void;
		timeout: ReturnType<typeof setTimeout>;
	}>();

	constructor(
		private readonly socketPath: string,
		private readonly diagnosticContext: Record<string, unknown> = {},
	) {}

	async connect(timeoutMs = 3000): Promise<void> {
		if (this.socket) {
			throw new Error("Daemon worker client is already connected");
		}
		appendSupervisorDiagnosticEvent("worker_socket_connect_start", {
			...this.diagnosticContext,
			socketPath: this.socketPath,
			timeoutMs,
		});
		const socket = createConnection(this.socketPath);
		this.socket = socket;
		this.channel = new PrivateFramedChannel(socket, isDaemonWorkerFrameHeader, undefined, {
			onInboundBytes: (bytes) =>
				appendSupervisorDiagnosticBytes("worker_transport_inbound", bytes, {
					...this.diagnosticContext,
					socketPath: this.socketPath,
					transportFraming: "exact-private-frame-stream-bytes",
				}),
			onOutboundBytes: (bytes) =>
				appendSupervisorDiagnosticBytes("worker_transport_outbound", bytes, {
					...this.diagnosticContext,
					socketPath: this.socketPath,
					transportFraming: "exact-private-frame-stream-bytes",
				}),
			onOutboundWriteOutcome: (bytes, outcome) =>
				appendSupervisorDiagnosticEvent("worker_transport_outbound_write_outcome", {
					...this.diagnosticContext,
					socketPath: this.socketPath,
					outcome,
					attemptedBytes: bytes.length,
				}),
		});
		this.channel.onFrame((frame) => this.handleFrame(frame));

		await new Promise<void>((resolve, reject) => {
			const timeout = setTimeout(() => {
				cleanup();
				const error = new Error(`Timed out connecting to daemon worker socket: ${this.socketPath}`);
				appendSupervisorDiagnosticEvent("worker_socket_connect_timeout", {
					...this.diagnosticContext,
					socketPath: this.socketPath,
					timeoutMs,
					error,
				});
				socket.destroy();
				reject(error);
			}, timeoutMs);
			const cleanup = () => {
				clearTimeout(timeout);
				socket.off("connect", onConnect);
				socket.off("error", onError);
			};
			const onConnect = () => {
				cleanup();
				appendSupervisorDiagnosticEvent("worker_socket_connected", {
					...this.diagnosticContext,
					socketPath: this.socketPath,
					localAddress: socket.localAddress,
					localPort: socket.localPort,
					remoteAddress: socket.remoteAddress,
					remotePort: socket.remotePort,
				});
				resolve();
			};
			const onError = (error: Error) => {
				cleanup();
				appendSupervisorDiagnosticEvent("worker_socket_connect_error", {
					...this.diagnosticContext,
					socketPath: this.socketPath,
					error,
				});
				reject(error);
			};
			socket.once("connect", onConnect);
			socket.once("error", onError);
		});

		socket.on("error", (error) => this.notifyClosed(socket, error));
		socket.on("close", () => this.notifyClosed(socket, new Error("Daemon worker socket closed")));
	}

	waitForHello(timeoutMs = 3000): Promise<DaemonHello> {
		if (this.hello) {
			return Promise.resolve(this.hello);
		}
		if (!this.socket || this.socket.destroyed) {
			return Promise.reject(new Error("Daemon worker client is not connected"));
		}
		return new Promise((resolve, reject) => {
			const waiter = {
				resolve,
				reject,
				timeout: setTimeout(() => {
					this.helloWaiters.delete(waiter);
					reject(new Error("Timed out waiting for daemon worker hello"));
				}, timeoutMs),
			};
			this.helloWaiters.add(waiter);
		});
	}

	onFrame(listener: DaemonWorkerFrameListener): () => void {
		this.frameListeners.add(listener);
		return () => this.frameListeners.delete(listener);
	}

	onClose(listener: DaemonWorkerCloseListener): () => void {
		this.closeListeners.add(listener);
		return () => this.closeListeners.delete(listener);
	}

	request(command: DaemonCommandBody, timeoutMs = 30_000): Promise<DaemonResponse> {
		return this.requestWire(command, timeoutMs);
	}

	requestWorker(command: DaemonWorkerCommandBody, timeoutMs = 30_000): Promise<DaemonResponse> {
		return this.requestWire(command, timeoutMs);
	}

	async authenticateWorker(token: string, owner: DaemonWorkerAuthentication, timeoutMs = 3000): Promise<void> {
		const response = await this.requestWorker({ type: "worker_auth", token, ...owner }, timeoutMs);
		if (!response.success) {
			throw new Error(response.error);
		}
	}

	close(): void {
		this.rejectAll(new Error("Daemon worker client closed"));
		this.channel?.close();
		this.channel = undefined;
		this.socket?.destroy();
		this.socket = undefined;
	}

	private async requestWire(command: DaemonWorkerWireCommandBody, timeoutMs: number): Promise<DaemonResponse> {
		if (!this.channel || !this.socket || this.socket.destroyed) {
			const error = new Error("Daemon worker client is not connected");
			appendSupervisorDiagnosticEvent("worker_request_unavailable", {
				...this.diagnosticContext,
				socketPath: this.socketPath,
				command,
				timeoutMs,
				error,
			});
			throw error;
		}
		const diagnosticStarted = process.hrtime.bigint();
		const id = `worker_${++this.requestId}`;
		const fullCommand = { ...command, id } as DaemonWorkerWireCommand;
		const frameHeader = { kind: "command" as const, requestId: id, commandType: command.type };
		const wirePayload = Buffer.from(serializeJsonLine(fullCommand));
		const diagnosticRequest = {
			...this.diagnosticContext,
			socketPath: this.socketPath,
			requestId: id,
			requestType: command.type,
			timeoutMs,
		};
		appendSupervisorDiagnosticEvent("worker_request_start", diagnosticRequest);
		const response = new Promise<DaemonResponse>((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.pending.delete(id);
				const error = new Error(`Timed out waiting for daemon worker response to ${command.type}`);
				appendSupervisorDiagnosticEvent("worker_request_timeout", { ...diagnosticRequest, error });
				reject(error);
			}, timeoutMs);
			this.pending.set(id, { resolve, reject, timeout });
		});
		try {
			await this.channel.send(frameHeader, wirePayload);
		} catch (error) {
			appendSupervisorDiagnosticEvent("worker_request_send_error", { ...diagnosticRequest, error });
			const pending = this.pending.get(id);
			if (pending) {
				clearTimeout(pending.timeout);
				this.pending.delete(id);
				pending.reject(error instanceof Error ? error : new Error(String(error)));
			}
		}
		try {
			const result = await response;
			const durationMs = Number(process.hrtime.bigint() - diagnosticStarted) / 1_000_000;
			const completed = {
				...diagnosticRequest,
				durationMs,
				outcome: result.success ? "success" : "failure",
			};
			appendSupervisorDiagnosticEvent("worker_request_end", completed);
			if (
				durationMs > 250 &&
				(command.type === "list" || command.type === "get_state" || command.type === "get_connection_state")
			) {
				appendSupervisorDiagnosticEvent("list_status_latency_trigger", {
					...completed,
					thresholdMs: 250,
					providerBurstDeferred: true,
				});
			}
			return result;
		} catch (error) {
			appendSupervisorDiagnosticEvent("worker_request_end", {
				...diagnosticRequest,
				durationMs: Number(process.hrtime.bigint() - diagnosticStarted) / 1_000_000,
				outcome: error instanceof Error && error.message.startsWith("Timed out") ? "timeout" : "error",
				error,
			});
			throw error;
		}
	}

	private handleFrame(frame: PrivateFrame<DaemonWorkerFrameHeader>): void {
		if (frame.header.kind !== "outbound") {
			return;
		}
		if (frame.header.outboundType === "response" && frame.header.requestId) {
			const pending = this.pending.get(frame.header.requestId);
			if (pending) {
				let response: unknown;
				try {
					response = JSON.parse(frame.payload.toString("utf8"));
				} catch (error) {
					appendSupervisorDiagnosticEvent("worker_response_parse_error", {
						...this.diagnosticContext,
						socketPath: this.socketPath,
						header: frame.header,
						error,
					});
					clearTimeout(pending.timeout);
					this.pending.delete(frame.header.requestId);
					pending.reject(new Error(`Invalid daemon worker response: ${String(error)}`));
					return;
				}
				if (isDaemonResponse(response)) {
					clearTimeout(pending.timeout);
					this.pending.delete(frame.header.requestId);
					pending.resolve(response);
					return;
				}
			}
		}
		if (frame.header.outboundType === "daemon_hello") {
			try {
				const parsed = JSON.parse(frame.payload.toString("utf8")) as DaemonOutbound;
				if (parsed.type === "daemon_hello") {
					this.hello = parsed;
					for (const waiter of [...this.helloWaiters]) {
						clearTimeout(waiter.timeout);
						this.helloWaiters.delete(waiter);
						waiter.resolve(parsed);
					}
				}
			} catch (error) {
				appendSupervisorDiagnosticEvent("worker_hello_parse_error", {
					...this.diagnosticContext,
					socketPath: this.socketPath,
					header: frame.header,
					error,
				});
				// Invalid hello payloads are rejected by the timeout.
			}
		}
		for (const listener of this.frameListeners) {
			listener(frame);
		}
	}

	private rejectAll(error: Error): void {
		for (const [id, pending] of this.pending) {
			clearTimeout(pending.timeout);
			pending.reject(error);
			this.pending.delete(id);
		}
		for (const waiter of [...this.helloWaiters]) {
			clearTimeout(waiter.timeout);
			this.helloWaiters.delete(waiter);
			waiter.reject(error);
		}
	}

	private notifyClosed(socket: Socket, error: Error): void {
		if (this.socket !== socket) {
			return;
		}
		this.socket = undefined;
		this.channel = undefined;
		appendSupervisorDiagnosticEvent("worker_socket_closed", {
			...this.diagnosticContext,
			socketPath: this.socketPath,
			error,
			pendingRequestIds: [...this.pending.keys()],
			helloWaiterCount: this.helloWaiters.size,
		});
		this.rejectAll(error);
		for (const listener of [...this.closeListeners]) {
			listener(error);
		}
	}
}

function isDaemonResponse(value: unknown): value is DaemonResponse {
	if (!value || typeof value !== "object") {
		return false;
	}
	const candidate = value as { type?: unknown; command?: unknown; success?: unknown };
	return (
		candidate.type === "response" && typeof candidate.command === "string" && typeof candidate.success === "boolean"
	);
}
