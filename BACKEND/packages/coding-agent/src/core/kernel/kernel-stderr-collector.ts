import type { ChildProcess } from "node:child_process";
import type { Readable } from "node:stream";
import { EXIT_STDIO_GRACE_MS } from "../../utils/child-process.js";

export const KERNEL_STDERR_TAIL_BYTES = 16 * 1024;

export interface KernelStderrCapture {
	readonly stderrTail: Buffer<ArrayBufferLike>;
	readonly stderrBytes: number;
	readonly stderrCaptureComplete: boolean;
	readonly sourceTruncated: boolean;
}

export type KernelStderrExitHandler<T extends object> = (snapshot: Readonly<T>, capture: KernelStderrCapture) => void;

function appendTail(previous: Buffer<ArrayBufferLike>, chunk: Uint8Array): Buffer<ArrayBufferLike> {
	if (chunk.byteLength >= KERNEL_STDERR_TAIL_BYTES) {
		return Buffer.from(chunk.subarray(chunk.byteLength - KERNEL_STDERR_TAIL_BYTES));
	}
	if (previous.byteLength + chunk.byteLength <= KERNEL_STDERR_TAIL_BYTES) {
		return Buffer.concat([previous, chunk]);
	}
	return Buffer.concat([previous, chunk]).subarray(-KERNEL_STDERR_TAIL_BYTES);
}

/** Owns one direct child's stderr until its exit evidence is safely published. */
export class KernelStderrCollector<T extends object = Record<string, never>> {
	private readonly child: ChildProcess;
	private readonly stderr: Readable | null;
	private readonly onData = (chunk: Buffer | string | Uint8Array): void => {
		const bytes = Buffer.from(chunk);
		this.stderrBytes += bytes.byteLength;
		this.stderrTail = appendTail(this.stderrTail, bytes);
		this.onLiveData?.(bytes);
	};
	private readonly onEnd = (): void => {
		this.stderrComplete = true;
		this.maybeFinish(this.hasCompleteStderr());
	};
	private readonly onClose = (): void => {
		this.stderrClosed = true;
		this.stderrComplete ||= this.stderr?.readableEnded === true;
		this.maybeFinish(this.hasCompleteStderr() && !this.stderrError);
	};
	private readonly onError = (): void => {
		this.stderrError = true;
		this.maybeFinish(false);
	};
	private readonly onChildClose = (): void => {
		this.childClosed = true;
		this.maybeFinish(this.hasCompleteStderr() && !this.stderrError);
	};
	private stderrTail: Buffer<ArrayBufferLike> = Buffer.alloc(0);
	private stderrBytes = 0;
	private stderrComplete: boolean;
	private stderrClosed = false;
	private stderrError = false;
	private childClosed = false;
	private exited = false;
	private finalized = false;
	private exitSnapshot?: Readonly<T>;
	private exitHandler?: KernelStderrExitHandler<T>;
	private exitTimer?: ReturnType<typeof globalThis.setTimeout>;

	constructor(
		child: ChildProcess,
		private readonly onLiveData?: (chunk: Buffer) => void,
	) {
		this.child = child;
		this.stderr = child.stderr;
		this.stderrComplete = this.stderr === null || this.stderr.readableEnded === true;
		this.stderr?.on("data", this.onData);
		this.stderr?.once("end", this.onEnd);
		this.stderr?.once("close", this.onClose);
		this.stderr?.once("error", this.onError);
		this.child.once("close", this.onChildClose);
	}

	get isExitOwned(): boolean {
		return this.exited && !this.finalized;
	}

	get isFinalized(): boolean {
		return this.finalized;
	}

	/** Transfers this collector to the exited-child publication path. */
	markExit(snapshot: T, handler: KernelStderrExitHandler<T>): void {
		if (this.finalized || this.exited) return;
		this.exited = true;
		this.exitSnapshot = Object.freeze({ ...snapshot });
		this.exitHandler = handler;
		if (this.stderrComplete || this.stderrClosed || this.childClosed || this.stderrError) {
			this.finish(this.hasCompleteStderr() && !this.stderrError);
			return;
		}
		this.exitTimer = globalThis.setTimeout(() => this.finish(false), EXIT_STDIO_GRACE_MS);
		this.exitTimer.unref?.();
	}

	/** Detaches an active collector without destroying a still-running stream. */
	dispose(): void {
		if (this.finalized) return;
		this.finalized = true;
		this.clearTimer();
		this.detachListeners();
	}

	private maybeFinish(complete: boolean): void {
		if (this.exited && !this.finalized) this.finish(complete);
	}

	private hasCompleteStderr(): boolean {
		return this.stderr === null || this.stderrComplete || this.stderr.readableEnded === true;
	}

	private finish(complete: boolean): void {
		if (this.finalized || !this.exitSnapshot || !this.exitHandler) return;
		this.finalized = true;
		this.clearTimer();
		this.detachListeners();
		if (!complete && this.exited) this.stderr?.destroy();
		const capture: KernelStderrCapture = {
			stderrTail: Buffer.from(this.stderrTail),
			stderrBytes: this.stderrBytes,
			stderrCaptureComplete: complete,
			sourceTruncated: this.stderrBytes > this.stderrTail.byteLength,
		};
		const snapshot = this.exitSnapshot;
		const handler = this.exitHandler;
		this.exitSnapshot = undefined;
		this.exitHandler = undefined;
		handler(snapshot, capture);
	}

	private clearTimer(): void {
		if (!this.exitTimer) return;
		globalThis.clearTimeout(this.exitTimer);
		this.exitTimer = undefined;
	}

	private detachListeners(): void {
		this.stderr?.off("data", this.onData);
		this.stderr?.off("end", this.onEnd);
		this.stderr?.off("close", this.onClose);
		this.stderr?.off("error", this.onError);
		this.child.off("close", this.onChildClose);
	}
}
