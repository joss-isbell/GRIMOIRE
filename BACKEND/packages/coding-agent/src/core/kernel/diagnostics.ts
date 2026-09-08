import { channel } from "node:diagnostics_channel";
import { readFileSync, readlinkSync } from "node:fs";

export type KernelLaunchMode = "direct" | "fork";
export type KernelCrashPhase = "resolving_ports" | "ready_probe" | "idle" | "executing";
export type KernelLifecycleOperation =
	| "shutdown"
	| "interrupt"
	| "kill"
	| "dispose"
	| "dispose_sync"
	| "cleanup_resources";
export type KernelLifecycleState = "idle" | "starting" | "running" | "shutdown";

export interface KernelLifecycleContext {
	caller: string;
	reason: string;
}

export interface KernelCausalObservation {
	ownerPid: number;
	ownerProcessStartId?: string;
	kernelGeneration: number;
	observedAt: string;
	monotonicNs: string;
	crashPhase: KernelCrashPhase;
	requestMsgId?: string;
}

export type KernelProtocolDetail =
	| { observation: "heartbeat_echo"; probeId: string; durationMs: number }
	| {
			observation: "heartbeat_unavailable";
			probeId: string;
			durationMs: number;
			reason: "timeout" | "mismatched_echo" | "transport_error" | "setup_failed";
	  }
	| {
			observation: "shell_reply";
			requestMsgId: string;
			protocolMsgId?: string;
			status: "ok" | "error" | "aborted" | "unknown";
	  }
	| { observation: "iopub_busy" | "iopub_idle"; requestMsgId: string; protocolMsgId?: string }
	| {
			observation: "execution_completed";
			requestMsgId: string;
			status: "ok" | "error" | "aborted" | "rejected";
			completionSource: "iopub_idle" | "abort_grace" | "rejected";
			durationMs: number;
	  }
	| {
			observation: "shell_reply_unavailable";
			requestMsgId: string;
			reason: "not_observed_after_idle" | "tracking_capacity" | "execution_send_failed";
	  }
	| { observation: "shell_unavailable"; reason: "receive_failed" };

export interface KernelDiagnosticIdentity {
	sessionId?: string;
	kernelInstanceId: string;
	kernelPid: number;
	kernelProcessStartId?: string;
	launchMode: KernelLaunchMode;
}

export interface ForkServerDiagnosticEvent {
	type: "forkserver_lifecycle";
	forkserverInstanceId: string;
	forkserverPid?: number;
	forkserverProcessStartId?: string;
	ownerPid: number;
	ownerProcessStartId?: string;
	observedAt: string;
	monotonicNs: string;
	phase:
		| "peer_rejected"
		| "peer_authenticated"
		| "control_closed"
		| "control_error"
		| "process_error"
		| "process_exit"
		| "shutdown_requested"
		| "disposed";
	reason?: string;
	connectionId?: string;
	code?: number | null;
	signal?: NodeJS.Signals | null;
	// A shared forkserver has no individual kernel or session identity.
	sessionId?: never;
	kernelInstanceId?: never;
	kernelPid?: never;
	kernelProcessStartId?: never;
	launchMode?: never;
}

interface KernelObservationProcess {
	observerPid?: number;
	observerProcessStartId?: string;
	observerPidNamespace?: string;
	observerBoottimeOffsetNs?: string;
}

export type KernelDiagnosticEvent = KernelObservationProcess &
	(
		| ForkServerDiagnosticEvent
		| (KernelDiagnosticIdentity &
				KernelCausalObservation &
				KernelProtocolDetail & { type: "kernel_protocol_observation" })
		| (KernelDiagnosticIdentity &
				KernelCausalObservation &
				KernelLifecycleContext & {
					type: "kernel_lifecycle_intent";
					operation: KernelLifecycleOperation;
					/** Bounded code locations only; never argument values or cell source. */
					callerStack?: string[];
				})
		| (KernelDiagnosticIdentity &
				KernelCausalObservation & {
					type: "kernel_process_exit_observed";
					lifecycleState: KernelLifecycleState;
					code: number | null;
					signal: NodeJS.Signals | null;
				})
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
		| (KernelDiagnosticIdentity &
				Partial<KernelCausalObservation> & {
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
				/** Omission denotes an older producer whose capture availability is unknown. */
				stderrCaptureStatus?: "available" | "unavailable_fork" | "unknown";
				/** Omission denotes an older producer or a fork where completion is unknown. */
				stderrCaptureComplete?: boolean;
				stderrBytes: number;
				sourceTruncated: boolean;
		  })
	);

const KERNEL_DIAGNOSTIC_CHANNEL_NAME = "grimoire.kernel.lifecycle.v1";
const kernelDiagnosticChannel = channel(KERNEL_DIAGNOSTIC_CHANNEL_NAME);
const KERNEL_DIAGNOSTIC_EVENT_TYPES = new Set<KernelDiagnosticEvent["type"]>([
	"kernel_protocol_observation",
	"forkserver_lifecycle",
	"kernel_lifecycle_intent",
	"kernel_process_exit_observed",
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

let observationProcess: Readonly<KernelObservationProcess> | undefined;
function getObservationProcess(): Readonly<KernelObservationProcess> {
	if (observationProcess) return observationProcess;
	const identity: KernelObservationProcess = { observerPid: process.pid };
	try {
		const stat = readFileSync("/proc/self/stat", "utf8");
		identity.observerProcessStartId = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19];
		identity.observerPidNamespace = readlinkSync("/proc/self/ns/pid");
		const offset = /^boottime\s+(-?\d+)\s+(\d+)\s*$/m.exec(readFileSync("/proc/self/timens_offsets", "utf8"));
		if (offset && BigInt(offset[2]!) < 1_000_000_000n)
			identity.observerBoottimeOffsetNs = String(BigInt(offset[1]!) * 1_000_000_000n + BigInt(offset[2]!));
	} catch {
		// Missing process/namespace metadata stays unknown.
	}
	observationProcess = Object.freeze(identity);
	return observationProcess;
}

export function publishKernelDiagnostic(event: KernelDiagnosticEvent): void {
	try {
		// The source observer's namespace survives worker-to-supervisor forwarding.
		kernelDiagnosticChannel.publish({ ...event, ...getObservationProcess() });
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
