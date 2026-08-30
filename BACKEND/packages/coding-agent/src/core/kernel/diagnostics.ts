import { channel } from "node:diagnostics_channel";

export type KernelLaunchMode = "direct" | "fork";
export type KernelCrashPhase = "resolving_ports" | "ready_probe" | "idle" | "executing";

export interface KernelDiagnosticIdentity {
	sessionId?: string;
	kernelInstanceId: string;
	kernelPid: number;
	kernelProcessStartId?: string;
	launchMode: KernelLaunchMode;
}

export type KernelDiagnosticEvent =
	| (KernelDiagnosticIdentity & {
			type: "kernel_process_started";
			phase: "resolving_ports";
	  })
	| (KernelDiagnosticIdentity & {
			type: "kernel_ready";
			phase: "idle";
	  })
	| (KernelDiagnosticIdentity & {
			type: "kernel_execute_started";
			phase: "executing";
			requestMsgId: string;
	  })
	| (KernelDiagnosticIdentity & {
			type: "kernel_channel_fault";
			channel: "shell" | "iopub" | "control";
			crashPhase: KernelCrashPhase;
			requestMsgId?: string;
			reason: string;
	  })
	| (KernelDiagnosticIdentity & {
			type: "kernel_unexpected_exit";
			crashPhase: KernelCrashPhase;
			requestMsgId?: string;
			code: number | null;
			signal: NodeJS.Signals | null;
			reason: "process_exit" | "forkserver_unavailable";
			stderrTail?: Uint8Array;
			stderrBytes: number;
			sourceTruncated: boolean;
	  });

const KERNEL_DIAGNOSTIC_CHANNEL_NAME = "grimoire.kernel.lifecycle.v1";
const kernelDiagnosticChannel = channel(KERNEL_DIAGNOSTIC_CHANNEL_NAME);
const KERNEL_DIAGNOSTIC_EVENT_TYPES = new Set<KernelDiagnosticEvent["type"]>([
	"kernel_process_started",
	"kernel_ready",
	"kernel_execute_started",
	"kernel_channel_fault",
	"kernel_unexpected_exit",
]);

function isKernelDiagnosticEvent(value: unknown): value is KernelDiagnosticEvent {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof (value as { type?: unknown }).type === "string" &&
		KERNEL_DIAGNOSTIC_EVENT_TYPES.has((value as { type: KernelDiagnosticEvent["type"] }).type)
	);
}

export function publishKernelDiagnostic(event: KernelDiagnosticEvent): void {
	try {
		kernelDiagnosticChannel.publish(event);
	} catch {
		// Diagnostics are observational and must never change kernel lifecycle.
	}
}

export function subscribeKernelDiagnostics(listener: (event: KernelDiagnosticEvent) => void): () => void {
	const receive = (message: unknown): void => {
		if (isKernelDiagnosticEvent(message)) listener(message);
	};
	kernelDiagnosticChannel.subscribe(receive);
	return () => kernelDiagnosticChannel.unsubscribe(receive);
}
