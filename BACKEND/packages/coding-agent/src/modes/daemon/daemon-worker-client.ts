import { randomUUID } from "node:crypto";
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
import { appendSupervisorDiagnosticEvent } from "./incident-recorder.js";
import { sanitizeIncidentCausalFields } from "./incident-recorder-writer.js";

type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never;
type DaemonCommandBody = DistributiveOmit<DaemonCommand, "id">;
type DaemonWorkerWireCommandBody = DaemonCommandBody | DaemonWorkerCommandBody;
type DaemonWorkerWireCommand = DaemonCommand | DaemonWorkerCommand;
type DaemonWorkerAuthentication = Omit<Extract<DaemonWorkerCommand, { type: "worker_auth" }>, "id" | "type" | "token">;

export type DaemonWorkerFrameListener = (frame: PrivateFrame<DaemonWorkerFrameHeader>) => void;
export type DaemonWorkerRecoveryTriggerContext =
	| { readonly triggerRequestId: string; readonly triggerUnavailableReason?: never }
	| { readonly triggerRequestId?: never; readonly triggerUnavailableReason: "none" | "multiple" };
export type DaemonWorkerCloseListener = (error: Error, trigger: DaemonWorkerRecoveryTriggerContext) => void;
type DaemonHello = Extract<DaemonOutbound, { type: "daemon_hello" }>;
type WorkerRequestOutcome =
	| "success"
	| "failure"
	| "timeout"
	| "send_error"
	| "socket_closed"
	| "response_parse_error"
	| "error";

interface WorkerRequestDiagnostic {
	readonly correlation: Readonly<Record<string, unknown>>;
	readonly started: bigint;
	terminalOutcome?: WorkerRequestOutcome;
}

interface PendingWorkerRequest {
	resolve: (response: DaemonResponse) => void;
	reject: (error: Error) => void;
	timeout: ReturnType<typeof setTimeout>;
	diagnostic: WorkerRequestDiagnostic;
}

export class DaemonWorkerClient {
	private socket?: Socket;
	private channel?: PrivateFramedChannel<DaemonWorkerFrameHeader>;
	private readonly frameListeners = new Set<DaemonWorkerFrameListener>();
	private readonly closeListeners = new Set<DaemonWorkerCloseListener>();
	private readonly pending = new Map<string, PendingWorkerRequest>();
	private requestId = 0;
	private clientGeneration?: string;
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
		const clientGeneration = randomUUID();
		this.clientGeneration = clientGeneration;
		const connectionDiagnostic = {
			...this.diagnosticContext,
			clientGeneration,
			socketPath: this.socketPath,
		};
		appendSupervisorDiagnosticEvent("worker_socket_connect_start", {
			...connectionDiagnostic,
			timeoutMs,
		});
		const socket = createConnection(this.socketPath);
		this.socket = socket;
		this.channel = new PrivateFramedChannel(socket, isDaemonWorkerFrameHeader);
		this.channel.onFrame((frame) => this.handleFrame(frame));

		await new Promise<void>((resolve, reject) => {
			const timeout = setTimeout(() => {
				cleanup();
				const error = new Error(`Timed out connecting to daemon worker socket: ${this.socketPath}`);
				appendSupervisorDiagnosticEvent("worker_socket_connect_timeout", {
					...connectionDiagnostic,
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
					...connectionDiagnostic,
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
					...connectionDiagnostic,
					error,
				});
				reject(error);
			};
			socket.once("connect", onConnect);
			socket.once("error", onError);
		});

		socket.on("error", (error) => this.notifyClosed(socket, clientGeneration, error));
		socket.on("close", () => this.notifyClosed(socket, clientGeneration, new Error("Daemon worker socket closed")));
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

	request(
		command: DaemonCommandBody,
		timeoutMs = 30_000,
		diagnosticCause: Record<string, unknown> = {},
	): Promise<DaemonResponse> {
		return this.requestWire(command, timeoutMs, diagnosticCause);
	}

	requestWorker(
		command: DaemonWorkerCommandBody,
		timeoutMs = 30_000,
		diagnosticCause: Record<string, unknown> = {},
	): Promise<DaemonResponse> {
		return this.requestWire(command, timeoutMs, diagnosticCause);
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

	private async requestWire(
		command: DaemonWorkerWireCommandBody,
		timeoutMs: number,
		diagnosticCause: Record<string, unknown>,
	): Promise<DaemonResponse> {
		const clientGeneration = this.clientGeneration;
		if (!this.channel || !this.socket || this.socket.destroyed || !clientGeneration) {
			const error = new Error("Daemon worker client is not connected");
			appendSupervisorDiagnosticEvent("worker_request_unavailable", {
				...this.diagnosticContext,
				clientGeneration,
				socketPath: this.socketPath,
				command,
				timeoutMs,
				error,
			});
			throw error;
		}
		const diagnosticStarted = process.hrtime.bigint();
		const id = `worker_${clientGeneration}_${++this.requestId}`;
		const fullCommand = { ...command, id } as DaemonWorkerWireCommand;
		const frameHeader = { kind: "command" as const, requestId: id, commandType: command.type };
		const wirePayload = Buffer.from(serializeJsonLine(fullCommand));
		const diagnosticRequest = sanitizeIncidentCausalFields({
			...diagnosticCause,
			...this.diagnosticContext,
			clientGeneration,
			socketPath: this.socketPath,
			requestId: id,
			requestType: command.type,
			timeoutMs,
		});
		const diagnostic: WorkerRequestDiagnostic = {
			correlation: diagnosticRequest,
			started: diagnosticStarted,
		};
		appendSupervisorDiagnosticEvent("worker_request_start", diagnostic.correlation);
		const response = new Promise<DaemonResponse>((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.pending.delete(id);
				diagnostic.terminalOutcome = "timeout";
				const error = new Error(`Timed out waiting for daemon worker response to ${command.type}`);
				appendSupervisorDiagnosticEvent("worker_request_timeout", {
					...diagnostic.correlation,
					durationMs: requestDurationMs(diagnostic.started),
					outcome: diagnostic.terminalOutcome,
					error,
				});
				reject(error);
			}, timeoutMs);
			this.pending.set(id, { resolve, reject, timeout, diagnostic });
		});
		try {
			await this.channel.send(frameHeader, wirePayload);
		} catch (error) {
			const normalizedError = error instanceof Error ? error : new Error(String(error));
			appendSupervisorDiagnosticEvent("worker_request_send_error", {
				...diagnostic.correlation,
				durationMs: requestDurationMs(diagnostic.started),
				outcome: "send_error",
				error: normalizedError,
			});
			const pending = this.pending.get(id);
			if (pending) {
				pending.diagnostic.terminalOutcome = "send_error";
				clearTimeout(pending.timeout);
				this.pending.delete(id);
				pending.reject(normalizedError);
			}
		}
		try {
			const result = await response;
			const durationMs = requestDurationMs(diagnostic.started);
			diagnostic.terminalOutcome = result.success ? "success" : "failure";
			const completed = {
				...diagnostic.correlation,
				durationMs,
				outcome: diagnostic.terminalOutcome,
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
				...diagnostic.correlation,
				durationMs: requestDurationMs(diagnostic.started),
				outcome:
					diagnostic.terminalOutcome ??
					(error instanceof Error && error.message.startsWith("Timed out") ? "timeout" : "error"),
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
					pending.diagnostic.terminalOutcome = "response_parse_error";
					appendSupervisorDiagnosticEvent("worker_response_parse_error", {
						...pending.diagnostic.correlation,
						durationMs: requestDurationMs(pending.diagnostic.started),
						outcome: pending.diagnostic.terminalOutcome,
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

	private notifyClosed(socket: Socket, clientGeneration: string, error: Error): void {
		if (this.socket !== socket) {
			return;
		}
		this.socket = undefined;
		this.channel = undefined;
		this.clientGeneration = undefined;
		const pendingRequestIds = [...this.pending.keys()];
		const trigger: DaemonWorkerRecoveryTriggerContext =
			pendingRequestIds.length === 1
				? { triggerRequestId: pendingRequestIds[0] }
				: { triggerUnavailableReason: pendingRequestIds.length === 0 ? "none" : "multiple" };
		for (const pending of this.pending.values()) {
			pending.diagnostic.terminalOutcome = "socket_closed";
			appendSupervisorDiagnosticEvent("worker_request_socket_closed", {
				...pending.diagnostic.correlation,
				durationMs: requestDurationMs(pending.diagnostic.started),
				outcome: pending.diagnostic.terminalOutcome,
				error,
			});
		}
		appendSupervisorDiagnosticEvent("worker_socket_closed", {
			...this.diagnosticContext,
			clientGeneration,
			socketPath: this.socketPath,
			error,
			pendingRequestIds,
			...trigger,
			helloWaiterCount: this.helloWaiters.size,
		});
		this.rejectAll(error);
		for (const listener of [...this.closeListeners]) {
			listener(error, trigger);
		}
	}
}

function requestDurationMs(started: bigint): number {
	return Number(process.hrtime.bigint() - started) / 1_000_000;
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
