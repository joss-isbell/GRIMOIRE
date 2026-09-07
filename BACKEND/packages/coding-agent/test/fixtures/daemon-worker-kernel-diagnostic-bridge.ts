import { spawn } from "node:child_process";
import { once } from "node:events";
import { readlinkSync } from "node:fs";
import { publishKernelDiagnostic } from "../../src/core/kernel/diagnostics.js";
import { installDaemonWorkerKernelDiagnosticBridge } from "../../src/modes/daemon/daemon-worker-kernel-diagnostics.js";
import {
	DAEMON_WORKER_KERNEL_DIAGNOSTIC_CAPABILITY_ENV,
	DAEMON_WORKER_KERNEL_DIAGNOSTIC_FD_ENV,
	waitForDaemonWorkerStartupGate,
} from "../../src/modes/daemon/daemon-worker-protocol.js";

waitForDaemonWorkerStartupGate();
const cleanup = installDaemonWorkerKernelDiagnosticBridge();
const expectedBridgeTarget = readlinkSync("/proc/self/fd/6");
const descendantScript = `
const { readlinkSync } = require("node:fs");
let sameBridgeFd = false;
try { sameBridgeFd = readlinkSync("/proc/self/fd/6") === process.env.EXPECTED_BRIDGE_TARGET; } catch {}
process.stdout.write(JSON.stringify({
  capabilityPresent: process.env.${DAEMON_WORKER_KERNEL_DIAGNOSTIC_CAPABILITY_ENV} !== undefined,
  fdEnvPresent: process.env.${DAEMON_WORKER_KERNEL_DIAGNOSTIC_FD_ENV} !== undefined,
  sameBridgeFd,
}));
`;
const descendant = spawn(process.execPath, ["-e", descendantScript], {
	env: { ...process.env, EXPECTED_BRIDGE_TARGET: expectedBridgeTarget },
	stdio: ["ignore", "pipe", "pipe"],
});
const stdout: Buffer[] = [];
descendant.stdout.on("data", (chunk: Buffer) => stdout.push(Buffer.from(chunk)));
await once(descendant, "close");

publishKernelDiagnostic({
	type: "kernel_unexpected_exit",
	sessionId: process.env.GRIMOIRE_TEST_SESSION_ID ?? "worker-session",
	kernelInstanceId: "worker-kernel-instance",
	kernelPid: process.pid + 1,
	kernelProcessStartId: "worker-kernel-start-id",
	launchMode: "direct",
	crashPhase: "executing",
	requestMsgId: "worker-request-id",
	code: 137,
	signal: "SIGKILL",
	reason: "process_exit",
	stderrTail: Buffer.from([0x00, 0xff, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x0a]),
	stderrBytes: 4096,
	stderrCaptureComplete: true,
	sourceTruncated: true,
});

await cleanup();
process.stdout.write(`${Buffer.concat(stdout).toString("utf8")}\n`);
