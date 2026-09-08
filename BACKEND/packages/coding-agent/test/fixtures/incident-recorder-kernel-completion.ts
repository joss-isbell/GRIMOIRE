import { writeFileSync } from "node:fs";
import {
	appendKernelDiagnosticCapture,
	appendSupervisorDiagnosticEvent,
	flushSupervisorDiagnosticCapture,
	INCIDENT_RECORDER_RUN_DIR_ENV,
	installSupervisorDiagnosticHooks,
} from "../../src/modes/daemon/incident-recorder.js";
import { emitIncidentControl } from "../../src/modes/daemon/incident-recorder-writer.js";

const identity = {
	sessionId: "session-kernel-completion",
	kernelInstanceId: "kernel-instance-completion",
	kernelPid: 42425,
	kernelProcessStartId: "proc:kernel-completion",
	launchMode: "direct" as const,
};

function unexpectedExit(stderrTail?: Uint8Array) {
	return {
		...identity,
		type: "kernel_unexpected_exit" as const,
		crashPhase: "executing" as const,
		requestMsgId: "request-message-completion",
		code: null,
		signal: "SIGKILL" as const,
		reason: "process_exit" as const,
		...(stderrTail === undefined ? {} : { stderrTail }),
		stderrBytes: stderrTail?.byteLength ?? 0,
		sourceTruncated: false,
	};
}

const cleanup = installSupervisorDiagnosticHooks("/tmp/grimoire-kernel-completion.sock");
const scenario = process.argv[2] ?? "ordered";

if (scenario === "ordered") {
	appendKernelDiagnosticCapture(unexpectedExit(Buffer.from([0x00, 0xff, 0x4b, 0x45, 0x4e, 0x45, 0x4c, 0x21])), {
		workerId: "worker-kernel-completion",
		type: "bridge-cannot-overwrite",
		exitOccurrenceId: "bridge-exit-id",
		tailOccurrenceId: "bridge-tail-id",
		exitAdmissionReason: "bridge-exit-reason",
		tailAdmissionReason: "bridge-tail-reason",
		tailCaptureStatus: "bridge-tail-status",
		sourceBytes: 99,
		retainedBytes: 99,
	});
	appendSupervisorDiagnosticEvent("ordinary_after_kernel_completion", { marker: "accepted-after-completion" });
} else if (scenario === "tail-rejected") {
	const tail = Buffer.alloc(512 * 1024, 0x5a);
	appendKernelDiagnosticCapture(unexpectedExit(tail), {
		workerId: "worker-kernel-completion",
		type: "bridge-cannot-overwrite-rejected-tail",
		exitOccurrenceId: "bridge-rejected-exit-id",
		tailOccurrenceId: "bridge-rejected-tail-id",
		exitAdmissionReason: "bridge-rejected-exit-reason",
		tailAdmissionReason: "bridge-rejected-tail-reason",
		tailCaptureStatus: "bridge-rejected-tail-status",
		sourceBytes: 99,
		retainedBytes: 99,
	});
} else if (scenario === "no-tail") {
	appendKernelDiagnosticCapture(
		{
			...unexpectedExit(),
			stderrCaptureStatus: "unavailable_fork" as const,
		},
		{
			workerId: "worker-kernel-completion",
			type: "bridge-cannot-overwrite-no-tail",
			exitOccurrenceId: "bridge-no-tail-exit-id",
			tailOccurrenceId: "bridge-no-tail-tail-id",
			exitAdmissionReason: "bridge-no-tail-exit-reason",
			tailAdmissionReason: "bridge-no-tail-tail-reason",
			tailCaptureStatus: "bridge-no-tail-status",
			sourceBytes: 99,
			retainedBytes: 99,
		},
	);
} else if (scenario === "completion-rejected") {
	await flushSupervisorDiagnosticCapture();
	appendKernelDiagnosticCapture(unexpectedExit(Buffer.from("tail")));
} else if (scenario === "control-saturated") {
	for (let index = 0; index < 1_000; index += 1) {
		if (!emitIncidentControl(`reserved_fill_${index}`, {}).accepted) break;
	}
	appendKernelDiagnosticCapture(unexpectedExit(Buffer.from("tail")));
} else if (scenario === "sealed") {
	const runDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
	if (!runDir) throw new Error("Missing incident-recorder run directory");
	writeFileSync(`${runDir}/service-finalization-seal-intent.json`, "{}\n", {
		mode: 0o600,
	});
	appendKernelDiagnosticCapture(unexpectedExit(Buffer.from("tail")));
}

cleanup();
await flushSupervisorDiagnosticCapture();
