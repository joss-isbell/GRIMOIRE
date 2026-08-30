import { publishKernelDiagnostic } from "../../src/core/kernel/diagnostics.js";
import { getProcessStartId } from "../../src/core/session-lease.js";
import {
	flushSupervisorDiagnosticCapture,
	installSupervisorDiagnosticHooks,
} from "../../src/modes/daemon/incident-recorder.js";

const identity = {
	sessionId: "session-kernel-capture",
	kernelInstanceId: "kernel-instance-capture",
	kernelPid: 42424,
	kernelProcessStartId: "proc:kernel-capture",
	launchMode: "direct" as const,
};
const stderrTail = Buffer.from([0x00, 0xff, 0x4b, 0x45, 0x52, 0x4e, 0x45, 0x4c]);

const cleanup = installSupervisorDiagnosticHooks("/tmp/grimoire-kernel-capture.sock");
publishKernelDiagnostic({ ...identity, type: "kernel_process_started", phase: "resolving_ports" });
publishKernelDiagnostic({ ...identity, type: "kernel_ready", phase: "idle" });
publishKernelDiagnostic({
	...identity,
	type: "kernel_execute_started",
	phase: "executing",
	requestMsgId: "request-message-capture",
});
publishKernelDiagnostic({
	...identity,
	type: "kernel_channel_fault",
	channel: "iopub",
	crashPhase: "executing",
	requestMsgId: "request-message-capture",
	reason: "iopub fixture fault",
});
publishKernelDiagnostic({
	...identity,
	type: "kernel_unexpected_exit",
	crashPhase: "executing",
	requestMsgId: "request-message-capture",
	code: null,
	signal: "SIGKILL",
	reason: "process_exit",
	stderrTail,
	stderrBytes: 64 * 1024,
	sourceTruncated: true,
});
cleanup();
await flushSupervisorDiagnosticCapture();

process.stdout.write(
	`${JSON.stringify({
		pid: process.pid,
		processStartId: getProcessStartId(process.pid),
		stderrTail: stderrTail.toString("hex"),
	})}\n`,
);
