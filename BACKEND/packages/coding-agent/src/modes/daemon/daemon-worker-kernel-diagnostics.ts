import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, closeSync, lstatSync, mkdirSync, unlinkSync } from "node:fs";
import { createConnection, createServer, type Server, Socket } from "node:net";
import { dirname, join } from "node:path";
import type { Readable } from "node:stream";
import type { KernelDiagnosticEvent } from "../../core/kernel/diagnostics.js";
import {
	KERNEL_DIAGNOSTIC_BRIDGE_CLOSE_TIMEOUT_MS,
	installReconnectableKernelDiagnosticBridgeWriter,
	isKernelDiagnosticBridgeCapability,
	KernelDiagnosticBridgeDecoder,
	type KernelDiagnosticBridgeHandoffMode,
	type ReconnectableKernelDiagnosticBridgeInstallation,
} from "../../core/kernel/diagnostic-bridge.js";
import { getProcessStartId } from "../../core/session-lease.js";
import {
	appendKernelDiagnosticCapture,
	appendSupervisorDiagnosticBytes,
	appendSupervisorDiagnosticEvent,
} from "./incident-recorder.js";
import {
	DAEMON_WORKER_KERNEL_DIAGNOSTIC_CAPABILITY_ENV,
	DAEMON_WORKER_KERNEL_DIAGNOSTIC_FD_ENV,
	DAEMON_WORKER_KERNEL_DIAGNOSTIC_SOCKET_ENV,
	DAEMON_WORKER_ID_ENV,
} from "./daemon-worker-protocol.js";

export interface DaemonWorkerKernelDiagnosticCorrelation extends Record<string, unknown> {
	workerId: string;
	rootActiveSessionId: string;
	socketPath: string;
	childPid?: number;
}

export interface DaemonWorkerKernelDiagnosticCaptureSinks {
	appendBytes(type: string, value: Uint8Array, fields: Record<string, unknown>): void;
	appendEvent(type: string, fields: Record<string, unknown>): void;
	appendKernel(event: KernelDiagnosticEvent, correlation: Record<string, unknown>): void;
}

export interface DaemonWorkerKernelDiagnosticCaptureOptions {
	initialSequence?: number;
	initialBytes?: Uint8Array;
	onSequence?(sequence: number): void;
}

export interface DaemonWorkerKernelDiagnosticBridgeCleanup {
	(): Promise<void>;
	readonly finished: Promise<void>;
	startReconnectServer(
		validateSupervisor: DaemonWorkerDiagnosticSupervisorValidator,
	): Promise<DaemonWorkerDiagnosticSocketIdentity | undefined>;
}

export interface DaemonWorkerDiagnosticSupervisorClaim {
	supervisorGeneration: string;
	supervisorPid: number;
	supervisorProcessStartId?: string;
	supervisorSocketPath: string;
}

export type DaemonWorkerDiagnosticSupervisorValidator = (
	claim: DaemonWorkerDiagnosticSupervisorClaim,
	validatedFingerprint?: string,
) => Promise<string>;

export interface DaemonWorkerDiagnosticSocketIdentity {
	device: string;
	inode: string;
}

const defaultCaptureSinks: DaemonWorkerKernelDiagnosticCaptureSinks = {
	appendBytes: appendSupervisorDiagnosticBytes,
	appendEvent: appendSupervisorDiagnosticEvent,
	appendKernel: appendKernelDiagnosticCapture,
};

export function mayCloseInvalidDaemonWorkerKernelDiagnosticFd(fd: number): boolean {
	return Number.isInteger(fd) && fd >= 6;
}

export function installDaemonWorkerKernelDiagnosticBridge(
	environment: NodeJS.ProcessEnv = process.env,
): DaemonWorkerKernelDiagnosticBridgeCleanup {
	const noBridge = (): DaemonWorkerKernelDiagnosticBridgeCleanup => {
		const cleanup = (async () => {}) as DaemonWorkerKernelDiagnosticBridgeCleanup;
		Object.defineProperty(cleanup, "finished", { value: Promise.resolve(), enumerable: true });
		Object.defineProperty(cleanup, "startReconnectServer", {
			value: async () => undefined,
			enumerable: true,
		});
		return cleanup;
	};
	const rawFd = environment[DAEMON_WORKER_KERNEL_DIAGNOSTIC_FD_ENV];
	const capability = environment[DAEMON_WORKER_KERNEL_DIAGNOSTIC_CAPABILITY_ENV];
	const reconnectSocketPath = environment[DAEMON_WORKER_KERNEL_DIAGNOSTIC_SOCKET_ENV];
	const workerId = environment[DAEMON_WORKER_ID_ENV];
	delete environment[DAEMON_WORKER_KERNEL_DIAGNOSTIC_FD_ENV];
	delete environment[DAEMON_WORKER_KERNEL_DIAGNOSTIC_CAPABILITY_ENV];
	delete environment[DAEMON_WORKER_KERNEL_DIAGNOSTIC_SOCKET_ENV];
	delete environment[DAEMON_WORKER_ID_ENV];
	if (rawFd === undefined) return noBridge();
	const fd = Number(rawFd);
	if (!Number.isInteger(fd) || fd < 6 || !isKernelDiagnosticBridgeCapability(capability)) {
		if (mayCloseInvalidDaemonWorkerKernelDiagnosticFd(fd)) {
			try {
				closeSync(fd);
			} catch {
				// The bridge is optional and an invalid inherited fd cannot fail startup.
			}
		}
		return noBridge();
	}
	try {
		const stream = new Socket({ fd, readable: false, writable: true });
		stream.unref();
		const installation = installReconnectableKernelDiagnosticBridgeWriter(stream, capability);
		const finished = installation.writer.whenClosed;
		let reconnectServer: DaemonWorkerKernelDiagnosticServer | undefined;
		let closePromise: Promise<void> | undefined;
		const cleanup = (() => {
			if (closePromise) return closePromise;
			installation.close();
			closePromise = new Promise<void>((resolve) => {
				const timeout = setTimeout(() => {
					try {
						reconnectServer?.forceClose();
						stream.destroy();
					} catch {
						// The bounded close is best-effort and cannot block worker shutdown.
					}
					resolve();
				}, KERNEL_DIAGNOSTIC_BRIDGE_CLOSE_TIMEOUT_MS);
				void finished.then(() => {
					void (async () => {
						await reconnectServer?.close();
						clearTimeout(timeout);
						resolve();
					})();
				});
			});
			return closePromise;
		}) as DaemonWorkerKernelDiagnosticBridgeCleanup;
		Object.defineProperty(cleanup, "finished", { value: finished, enumerable: true });
		Object.defineProperty(cleanup, "startReconnectServer", {
			value: async (validateSupervisor: DaemonWorkerDiagnosticSupervisorValidator) => {
				if (
					process.platform === "win32" ||
					!reconnectSocketPath ||
					!workerId ||
					reconnectServer
				) {
					return undefined;
				}
				const server = new DaemonWorkerKernelDiagnosticServer({
					socketPath: reconnectSocketPath,
					workerId,
					workerPid: process.pid,
					workerProcessStartId: getProcessStartId(process.pid),
					capability,
					installation,
					validateSupervisor,
				});
				reconnectServer = server;
				try {
					return await server.start();
				} catch (error) {
					reconnectServer = undefined;
					server.forceClose();
					throw error;
				}
			},
			enumerable: true,
		});
		return cleanup;
	} catch {
		try {
			closeSync(fd);
		} catch {
			// The descriptor may already have been consumed by the failed Socket.
		}
		return noBridge();
	}
}

export function attachDaemonWorkerKernelDiagnosticCapture(
	stream: Readable,
	capability: string,
	correlation: DaemonWorkerKernelDiagnosticCorrelation,
	sinks: DaemonWorkerKernelDiagnosticCaptureSinks = defaultCaptureSinks,
	options: DaemonWorkerKernelDiagnosticCaptureOptions = {},
): () => void {
	const decoder = new KernelDiagnosticBridgeDecoder({
		capability,
		initialSequence: options.initialSequence,
		onEvent: (event) => sinks.appendKernel(event, correlation),
		onDrop: (counts) => {
			sinks.appendEvent("worker_kernel_diagnostic_drop", {
				...correlation,
				...counts,
			});
		},
		onLoss: (loss) => {
			sinks.appendEvent("worker_kernel_diagnostic_transport_loss", {
				...correlation,
				...loss,
			});
		},
		onSequence: options.onSequence,
	});
	let finalized = false;
	const onData = (chunk: Buffer | string): void => {
		const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
		sinks.appendBytes("worker_transport_kernel_diagnostic", bytes, correlation);
		decoder.push(bytes);
	};
	const finalize = (reason: "end" | "error" | "close" | "detach"): void => {
		if (finalized) return;
		finalized = true;
		decoder.end();
		sinks.appendEvent("worker_kernel_diagnostic_transport_closed", { ...correlation, reason });
	};
	const onEnd = (): void => finalize("end");
	const onError = (error: Error): void => {
		if (finalized) return;
		sinks.appendEvent("worker_kernel_diagnostic_transport_loss", {
			...correlation,
			reason: "transport_error",
			error,
		});
		finalize("error");
	};
	const onClose = (): void => finalize("close");
	stream.on("data", onData);
	stream.once("end", onEnd);
	stream.on("error", onError);
	stream.once("close", onClose);
	if (options.initialBytes && options.initialBytes.byteLength > 0) {
		onData(Buffer.from(options.initialBytes));
	}
	return () => {
		finalize("detach");
		stream.off("data", onData);
		stream.off("end", onEnd);
		stream.off("error", onError);
		stream.off("close", onClose);
	};
}

const DIAGNOSTIC_HANDSHAKE_VERSION = 1;
const DIAGNOSTIC_HANDSHAKE_MAX_BYTES = 8192;
const DIAGNOSTIC_HANDSHAKE_TIMEOUT_MS = 1000;
const DIAGNOSTIC_FENCE_INTERVAL_MS = 1000;
export const DAEMON_WORKER_KERNEL_DIAGNOSTIC_SOCKET_MAX_PATH_BYTES = 107;

export function isDaemonWorkerKernelDiagnosticSocketClosed(socket: Socket): boolean {
  return (
    socket.destroyed ||
    (socket as Socket & { closed?: boolean }).closed === true ||
    !socket.readable ||
    !socket.writable
  );
}

export function assertDaemonWorkerKernelDiagnosticSocketPath(path: string): void {
	if (
		process.platform !== "win32" &&
		(path.includes("\0") || Buffer.byteLength(path, "utf8") > DAEMON_WORKER_KERNEL_DIAGNOSTIC_SOCKET_MAX_PATH_BYTES)
	) {
		throw new Error("Kernel diagnostic socket path exceeds the Linux sockaddr_un limit");
	}
}

export function daemonWorkerKernelDiagnosticSocketPath(
	runtimeDirectory: string,
	supervisorSocketPath: string,
	workerId: string,
	salt: string,
): string {
	const name = `${createHash("sha256")
		.update(supervisorSocketPath)
		.update("\0")
		.update(workerId)
		.update("\0")
		.update(salt)
		.digest("hex")
		.slice(0, 32)}.sock`;
	const path = join(runtimeDirectory, name);
	assertDaemonWorkerKernelDiagnosticSocketPath(path);
	return path;
}

interface DiagnosticConnectPayload {
	version: 1;
	type: "diagnostic_connect";
	mode: KernelDiagnosticBridgeHandoffMode;
	workerId: string;
	workerPid: number;
	workerProcessStartId?: string;
	afterSequence: number;
	supervisor: DaemonWorkerDiagnosticSupervisorClaim;
	supervisorNonce: string;
}

interface DiagnosticAcceptPayload {
	version: 1;
	type: "diagnostic_accept";
	workerId: string;
	workerPid: number;
	workerProcessStartId?: string;
	supervisor: DaemonWorkerDiagnosticSupervisorClaim;
	supervisorNonce: string;
	workerNonce: string;
	afterSequence: number;
	latestSequence: number;
	oldestReplaySequence?: number;
	socketDevice: string;
	socketInode: string;
}

export interface DaemonWorkerKernelDiagnosticServerOptions {
	socketPath: string;
	workerId: string;
	workerPid: number;
	workerProcessStartId?: string;
	capability: string;
	installation: ReconnectableKernelDiagnosticBridgeInstallation;
	validateSupervisor: DaemonWorkerDiagnosticSupervisorValidator;
}

export interface ConnectDaemonWorkerKernelDiagnosticOptions {
	socketPath: string;
	expectedSocketDevice?: string;
	expectedSocketInode?: string;
	workerId: string;
	workerPid: number;
	workerProcessStartId?: string;
	capability: string;
	mode: KernelDiagnosticBridgeHandoffMode;
	afterSequence: number;
	supervisor: DaemonWorkerDiagnosticSupervisorClaim;
}

export interface DaemonWorkerKernelDiagnosticConnection {
	socket: Socket;
	initialBytes: Buffer;
	afterSequence: number;
	latestSequence: number;
	oldestReplaySequence?: number;
	socketIdentity: DaemonWorkerDiagnosticSocketIdentity;
}

function signedHandshakeLine(prefix: "GKDC1" | "GKDA1", payload: unknown, capability: string): Buffer {
	const payloadBytes = Buffer.from(JSON.stringify(payload));
	if (payloadBytes.byteLength > DIAGNOSTIC_HANDSHAKE_MAX_BYTES) {
		throw new Error("Kernel diagnostic handshake payload is oversized");
	}
	const mac = createHmac("sha256", Buffer.from(capability, "base64url")).update(payloadBytes).digest("base64url");
	return Buffer.from(`${prefix}.${payloadBytes.toString("base64url")}.${mac}\n`, "ascii");
}

function decodeSignedHandshake(
	line: Buffer,
	prefix: "GKDC1" | "GKDA1",
	capability: string,
): unknown {
	if (line.byteLength > DIAGNOSTIC_HANDSHAKE_MAX_BYTES || !isKernelDiagnosticBridgeCapability(capability)) {
		throw new Error("Invalid kernel diagnostic handshake");
	}
	const parts = line.toString("ascii").split(".");
	if (
		parts.length !== 3 ||
		parts[0] !== prefix ||
		!/^[A-Za-z0-9_-]+$/.test(parts[1] ?? "") ||
		!/^[A-Za-z0-9_-]{43}$/.test(parts[2] ?? "")
	) {
		throw new Error("Malformed kernel diagnostic handshake");
	}
	const payloadBytes = Buffer.from(parts[1], "base64url");
	const suppliedMac = Buffer.from(parts[2], "base64url");
	if (
		payloadBytes.toString("base64url") !== parts[1] ||
		suppliedMac.toString("base64url") !== parts[2]
	) {
		throw new Error("Non-canonical kernel diagnostic handshake");
	}
	const expectedMac = createHmac("sha256", Buffer.from(capability, "base64url")).update(payloadBytes).digest();
	if (suppliedMac.byteLength !== expectedMac.byteLength || !timingSafeEqual(suppliedMac, expectedMac)) {
		throw new Error("Kernel diagnostic handshake authentication failed");
	}
	try {
		return JSON.parse(payloadBytes.toString("utf8"));
	} catch {
		throw new Error("Kernel diagnostic handshake payload is invalid");
	}
}

function isBoundedHandshakeString(value: unknown, maxBytes = 4096): value is string {
	return typeof value === "string" && value.length > 0 && Buffer.byteLength(value) <= maxBytes;
}

function isDiagnosticSupervisorClaim(value: unknown): value is DaemonWorkerDiagnosticSupervisorClaim {
	if (!value || typeof value !== "object") return false;
	const claim = value as Record<string, unknown>;
	return (
		isBoundedHandshakeString(claim.supervisorGeneration, 128) &&
		typeof claim.supervisorPid === "number" &&
		Number.isSafeInteger(claim.supervisorPid) &&
		claim.supervisorPid > 0 &&
		(claim.supervisorProcessStartId === undefined ||
			isBoundedHandshakeString(claim.supervisorProcessStartId, 256)) &&
		isBoundedHandshakeString(claim.supervisorSocketPath)
	);
}

function isCanonicalNonce(value: unknown): value is string {
	if (typeof value !== "string" || !/^[A-Za-z0-9_-]{24}$/.test(value)) return false;
	const decoded = Buffer.from(value, "base64url");
	return decoded.byteLength === 18 && decoded.toString("base64url") === value;
}

function isDiagnosticConnectPayload(value: unknown): value is DiagnosticConnectPayload {
	if (!value || typeof value !== "object") return false;
	const payload = value as Record<string, unknown>;
	return (
		payload.version === DIAGNOSTIC_HANDSHAKE_VERSION &&
		payload.type === "diagnostic_connect" &&
		(payload.mode === "launch_handoff" || payload.mode === "reconnect") &&
		isBoundedHandshakeString(payload.workerId, 256) &&
		typeof payload.workerPid === "number" &&
		Number.isSafeInteger(payload.workerPid) &&
		payload.workerPid > 0 &&
		(payload.workerProcessStartId === undefined ||
			isBoundedHandshakeString(payload.workerProcessStartId, 256)) &&
		typeof payload.afterSequence === "number" &&
		Number.isSafeInteger(payload.afterSequence) &&
		payload.afterSequence >= 0 &&
		isDiagnosticSupervisorClaim(payload.supervisor) &&
		isCanonicalNonce(payload.supervisorNonce)
	);
}

function isDiagnosticAcceptPayload(value: unknown): value is DiagnosticAcceptPayload {
	if (!value || typeof value !== "object") return false;
	const payload = value as Record<string, unknown>;
	return (
		payload.version === DIAGNOSTIC_HANDSHAKE_VERSION &&
		payload.type === "diagnostic_accept" &&
		isBoundedHandshakeString(payload.workerId, 256) &&
		typeof payload.workerPid === "number" &&
		Number.isSafeInteger(payload.workerPid) &&
		payload.workerPid > 0 &&
		(payload.workerProcessStartId === undefined ||
			isBoundedHandshakeString(payload.workerProcessStartId, 256)) &&
		isDiagnosticSupervisorClaim(payload.supervisor) &&
		isCanonicalNonce(payload.supervisorNonce) &&
		isCanonicalNonce(payload.workerNonce) &&
		typeof payload.afterSequence === "number" &&
		Number.isSafeInteger(payload.afterSequence) &&
		payload.afterSequence >= 0 &&
		typeof payload.latestSequence === "number" &&
		Number.isSafeInteger(payload.latestSequence) &&
		payload.latestSequence >= payload.afterSequence &&
		(payload.oldestReplaySequence === undefined ||
			(typeof payload.oldestReplaySequence === "number" &&
				Number.isSafeInteger(payload.oldestReplaySequence) &&
				payload.oldestReplaySequence >= 1)) &&
		typeof payload.socketDevice === "string" &&
		/^[0-9]+$/.test(payload.socketDevice) &&
		typeof payload.socketInode === "string" &&
		/^[0-9]+$/.test(payload.socketInode)
	);
}

function diagnosticSocketIdentity(path: string): DaemonWorkerDiagnosticSocketIdentity {
	assertDaemonWorkerKernelDiagnosticSocketPath(path);
	const stats = lstatSync(path, { bigint: true });
	if (
		stats.isSymbolicLink() ||
		!stats.isSocket() ||
		stats.nlink !== 1n ||
		(stats.mode & 0o777n) !== 0o600n
	) {
		throw new Error("Kernel diagnostic path is not a non-symlink socket");
	}
	if (typeof process.getuid === "function" && stats.uid !== BigInt(process.getuid())) {
		throw new Error("Kernel diagnostic socket has an unexpected owner");
	}
	return { device: stats.dev.toString(), inode: stats.ino.toString() };
}

function sameSocketIdentity(
	left: DaemonWorkerDiagnosticSocketIdentity,
	right: DaemonWorkerDiagnosticSocketIdentity,
): boolean {
	return left.device === right.device && left.inode === right.inode;
}

function sameSupervisorClaim(
	left: DaemonWorkerDiagnosticSupervisorClaim,
	right: DaemonWorkerDiagnosticSupervisorClaim,
): boolean {
	return (
		left.supervisorGeneration === right.supervisorGeneration &&
		left.supervisorPid === right.supervisorPid &&
		left.supervisorProcessStartId === right.supervisorProcessStartId &&
		left.supervisorSocketPath === right.supervisorSocketPath
	);
}

function readSignedHandshake(
	socket: Socket,
	prefix: "GKDC1" | "GKDA1",
	capability: string,
): Promise<{ payload: unknown; remainder: Buffer }> {
	return new Promise((resolve, reject) => {
		let segments: Buffer[] = [];
		let length = 0;
		let settled = false;
		let timeout: ReturnType<typeof setTimeout> | undefined;
		const cleanup = (): void => {
			if (timeout) clearTimeout(timeout);
			socket.off("data", onData);
			socket.off("error", onError);
			socket.off("close", onClose);
		};
		const finish = (error?: Error, line?: Buffer, remainder = Buffer.alloc(0)): void => {
			if (settled) return;
			settled = true;
			cleanup();
			if (error) {
				reject(error);
				return;
			}
			try {
				resolve({ payload: decodeSignedHandshake(line ?? Buffer.alloc(0), prefix, capability), remainder });
			} catch (decodeError) {
				reject(decodeError);
			}
		};
		const onData = (value: Buffer | string): void => {
			const chunk = typeof value === "string" ? Buffer.from(value) : value;
			const newline = chunk.indexOf(0x0a);
			if (newline === -1) {
				if (length + chunk.byteLength > DIAGNOSTIC_HANDSHAKE_MAX_BYTES) {
					finish(new Error("Kernel diagnostic handshake line is oversized"));
					return;
				}
				segments.push(Buffer.from(chunk));
				length += chunk.byteLength;
				return;
			}
			if (length + newline > DIAGNOSTIC_HANDSHAKE_MAX_BYTES) {
				finish(new Error("Kernel diagnostic handshake line is oversized"));
				return;
			}
			segments.push(Buffer.from(chunk.subarray(0, newline)));
			length += newline;
			socket.pause();
			finish(undefined, Buffer.concat(segments, length), Buffer.from(chunk.subarray(newline + 1)));
			segments = [];
			length = 0;
		};
		const onError = (error: Error): void => finish(error);
		const onClose = (): void => finish(new Error("Kernel diagnostic handshake closed"));
		timeout = setTimeout(
			() => finish(new Error("Kernel diagnostic handshake timed out")),
			DIAGNOSTIC_HANDSHAKE_TIMEOUT_MS,
		);
		timeout.unref();
		socket.on("data", onData);
		socket.once("error", onError);
		socket.once("close", onClose);
	});
}

function writeSocketBytes(socket: Socket, value: Buffer): Promise<void> {
	return new Promise((resolve, reject) => {
		try {
			socket.write(value, (error?: Error | null) => (error ? reject(error) : resolve()));
		} catch (error) {
			reject(error);
		}
	});
}

async function socketAcceptsConnections(path: string): Promise<boolean> {
	return new Promise((resolve) => {
		const socket = createConnection(path);
		let settled = false;
		const finish = (accepted: boolean): void => {
			if (settled) return;
			settled = true;
			socket.destroy();
			resolve(accepted);
		};
		const timeout = setTimeout(() => finish(false), 100);
		timeout.unref();
		socket.once("connect", () => {
			clearTimeout(timeout);
			finish(true);
		});
		socket.once("error", () => {
			clearTimeout(timeout);
			finish(false);
		});
	});
}

export class DaemonWorkerKernelDiagnosticServer {
	private server?: Server;
	private identity?: DaemonWorkerDiagnosticSocketIdentity;
	private current?: { socket: Socket; fence: ReturnType<typeof setInterval> };
	private closing = false;

	constructor(private readonly options: DaemonWorkerKernelDiagnosticServerOptions) {}

	async start(): Promise<DaemonWorkerDiagnosticSocketIdentity> {
		assertDaemonWorkerKernelDiagnosticSocketPath(this.options.socketPath);
		const parentPath = dirname(this.options.socketPath);
		mkdirSync(parentPath, { recursive: true, mode: 0o700 });
		const parentStats = lstatSync(parentPath, { bigint: true });
		if (
			parentStats.isSymbolicLink() ||
			!parentStats.isDirectory() ||
			parentStats.nlink < 2n ||
			(parentStats.mode & 0o777n) !== 0o700n ||
			(typeof process.getuid === "function" && parentStats.uid !== BigInt(process.getuid()))
		) {
			throw new Error("Kernel diagnostic socket parent is unsafe");
		}
		chmodSync(parentPath, 0o700);
		try {
			const observed = diagnosticSocketIdentity(this.options.socketPath);
			if (await socketAcceptsConnections(this.options.socketPath)) {
				throw new Error("A live kernel diagnostic socket already owns the worker path");
			}
			const current = diagnosticSocketIdentity(this.options.socketPath);
			if (!sameSocketIdentity(observed, current)) {
				throw new Error("Kernel diagnostic socket changed during stale-path validation");
			}
			unlinkSync(this.options.socketPath);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		const server = createServer((socket) => void this.handleConnection(socket));
		this.server = server;
		await new Promise<void>((resolve, reject) => {
			const onError = (error: Error): void => {
				server.off("listening", onListening);
				reject(error);
			};
			const onListening = (): void => {
				server.off("error", onError);
				resolve();
			};
			server.once("error", onError);
			server.once("listening", onListening);
			server.listen(this.options.socketPath);
		});
		server.unref();
		chmodSync(this.options.socketPath, 0o600);
		this.identity = diagnosticSocketIdentity(this.options.socketPath);
		return this.identity;
	}

	async close(): Promise<void> {
		if (this.closing) return;
		this.closing = true;
		this.closeCurrent();
		const server = this.server;
		this.server = undefined;
		if (server) {
			await new Promise<void>((resolve) => {
				try {
					server.close(() => resolve());
				} catch {
					resolve();
				}
			});
		}
		this.unlinkOwnedSocket();
	}

	forceClose(): void {
		this.closing = true;
		this.closeCurrent();
		try {
			this.server?.close();
		} catch {
			// Bounded shutdown proceeds even if the diagnostic listener is wedged.
		}
		this.server = undefined;
		this.unlinkOwnedSocket();
	}

	private async handleConnection(socket: Socket): Promise<void> {
		socket.unref();
		// The diagnostic channel is observational; a peer reset must never become
		// an uncaught worker error between handshake and writer attachment.
		socket.on("error", () => {});
		let prepared: Awaited<ReturnType<ReconnectableKernelDiagnosticBridgeInstallation["writer"]["prepareHandoff"]>> | undefined;
		try {
			const requestFrame = await readSignedHandshake(socket, "GKDC1", this.options.capability);
			if (requestFrame.remainder.byteLength > 0 || !isDiagnosticConnectPayload(requestFrame.payload)) {
				throw new Error("Kernel diagnostic connect request is invalid");
			}
			const request = requestFrame.payload;
			if (
				request.workerId !== this.options.workerId ||
				request.workerPid !== this.options.workerPid ||
				request.workerProcessStartId !== this.options.workerProcessStartId
			) {
				throw new Error("Kernel diagnostic connect request targets another worker");
			}
			let fingerprint = await this.options.validateSupervisor(request.supervisor);
			prepared = await this.options.installation.writer.prepareHandoff(request.mode, request.afterSequence);
			const identity = this.identity;
			if (!identity) throw new Error("Kernel diagnostic server identity is unavailable");
			const response: DiagnosticAcceptPayload = {
				version: DIAGNOSTIC_HANDSHAKE_VERSION,
				type: "diagnostic_accept",
				workerId: this.options.workerId,
				workerPid: this.options.workerPid,
				...(this.options.workerProcessStartId
					? { workerProcessStartId: this.options.workerProcessStartId }
					: {}),
				supervisor: request.supervisor,
				supervisorNonce: request.supervisorNonce,
				workerNonce: randomBytes(18).toString("base64url"),
				afterSequence: prepared.afterSequence,
				latestSequence: prepared.latestSequence,
				...(prepared.oldestReplaySequence !== undefined
					? { oldestReplaySequence: prepared.oldestReplaySequence }
					: {}),
				socketDevice: identity.device,
				socketInode: identity.inode,
			};
			await writeSocketBytes(socket, signedHandshakeLine("GKDA1", response, this.options.capability));
			this.closeCurrent();
			prepared.commit(socket);
			prepared = undefined;
			let fenceInFlight = false;
			const fence = setInterval(() => {
				if (fenceInFlight || socket.destroyed) return;
				fenceInFlight = true;
				void this.options
					.validateSupervisor(request.supervisor, fingerprint)
					.then((validated) => {
						fingerprint = validated;
					})
					.catch(() => socket.destroy())
					.finally(() => {
						fenceInFlight = false;
					});
			}, DIAGNOSTIC_FENCE_INTERVAL_MS);
			fence.unref();
			this.current = { socket, fence };
			socket.once("close", () => {
				if (this.current?.socket !== socket) return;
				clearInterval(fence);
				this.current = undefined;
			});
			socket.once("data", () => socket.destroy());
			socket.resume();
		} catch {
			prepared?.abort();
			socket.destroy();
		}
	}

	private closeCurrent(): void {
		const current = this.current;
		this.current = undefined;
		if (!current) return;
		clearInterval(current.fence);
		current.socket.destroy();
	}

	private unlinkOwnedSocket(): void {
		const expected = this.identity;
		this.identity = undefined;
		if (!expected) return;
		try {
			const current = diagnosticSocketIdentity(this.options.socketPath);
			if (sameSocketIdentity(expected, current)) unlinkSync(this.options.socketPath);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
				// Identity mismatch is intentionally fail-closed.
			}
		}
	}
}

export async function connectDaemonWorkerKernelDiagnostic(
	options: ConnectDaemonWorkerKernelDiagnosticOptions,
): Promise<DaemonWorkerKernelDiagnosticConnection> {
	if (process.platform === "win32" || !isKernelDiagnosticBridgeCapability(options.capability)) {
		throw new Error("Reconnectable kernel diagnostics are unavailable");
	}
	assertDaemonWorkerKernelDiagnosticSocketPath(options.socketPath);
	const observedIdentity = diagnosticSocketIdentity(options.socketPath);
	if (
		(options.expectedSocketDevice !== undefined && options.expectedSocketDevice !== observedIdentity.device) ||
		(options.expectedSocketInode !== undefined && options.expectedSocketInode !== observedIdentity.inode)
	) {
		throw new Error("Kernel diagnostic socket identity does not match the worker descriptor");
	}
	const socket = createConnection(options.socketPath);
	socket.unref();
	socket.on("error", () => {});
	await new Promise<void>((resolve, reject) => {
		let timeout: ReturnType<typeof setTimeout> | undefined;
		const finish = (error?: Error): void => {
			if (timeout) clearTimeout(timeout);
			socket.off("connect", onConnect);
			socket.off("error", onError);
			if (error) reject(error);
			else resolve();
		};
		const onConnect = (): void => finish();
		const onError = (error: Error): void => finish(error);
		timeout = setTimeout(
			() => finish(new Error("Kernel diagnostic connection timed out")),
			DIAGNOSTIC_HANDSHAKE_TIMEOUT_MS,
		);
		timeout.unref();
		socket.once("connect", onConnect);
		socket.once("error", onError);
	});
	const supervisorNonce = randomBytes(18).toString("base64url");
	const request: DiagnosticConnectPayload = {
		version: DIAGNOSTIC_HANDSHAKE_VERSION,
		type: "diagnostic_connect",
		mode: options.mode,
		workerId: options.workerId,
		workerPid: options.workerPid,
		...(options.workerProcessStartId ? { workerProcessStartId: options.workerProcessStartId } : {}),
		afterSequence: options.afterSequence,
		supervisor: options.supervisor,
		supervisorNonce,
	};
	try {
		await writeSocketBytes(socket, signedHandshakeLine("GKDC1", request, options.capability));
		const responseFrame = await readSignedHandshake(socket, "GKDA1", options.capability);
		if (!isDiagnosticAcceptPayload(responseFrame.payload)) {
			throw new Error("Kernel diagnostic accept response is invalid");
		}
		const response = responseFrame.payload;
		if (
			response.workerId !== options.workerId ||
			response.workerPid !== options.workerPid ||
			response.workerProcessStartId !== options.workerProcessStartId ||
			!sameSupervisorClaim(response.supervisor, options.supervisor) ||
			response.supervisorNonce !== supervisorNonce ||
			response.socketDevice !== observedIdentity.device ||
			response.socketInode !== observedIdentity.inode
		) {
			throw new Error("Kernel diagnostic accept response identity is invalid");
		}
		return {
			socket,
			initialBytes: responseFrame.remainder,
			afterSequence: response.afterSequence,
			latestSequence: response.latestSequence,
			...(response.oldestReplaySequence !== undefined
				? { oldestReplaySequence: response.oldestReplaySequence }
				: {}),
			socketIdentity: observedIdentity,
		};
	} catch (error) {
		socket.destroy();
		throw error;
	}
}
