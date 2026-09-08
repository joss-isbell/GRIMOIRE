import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const directory = mkdtempSync(join(tmpdir(), "worker-deadline-"));
for (const key of Object.keys(process.env)) {
	if (key.startsWith("PRIME_AGENT_INCIDENT_")) delete process.env[key];
}
process.env.PRIME_AGENT_CODING_AGENT_DIR = join(directory, "agent");
process.env.PRIME_AGENT_SESSION_DIR = join(directory, "sessions");
const { DaemonWorkerClient } = await import("../../src/modes/daemon/daemon-worker-client.js");
const { PrivateFramedChannel } = await import("../../src/modes/session-worker/private-framing.js");
const { isDaemonWorkerFrameHeader } = await import("../../src/modes/daemon/daemon-worker-protocol.js");
const unhandled: string[] = [];
process.on("unhandledRejection", (error) => unhandled.push(String(error)));
// The baseline attaches the rejection handler late, after the stalled write.
process.on("rejectionHandled", () => {});
let peer: Socket | undefined;
let closed = 0;
const received: string[] = [];
const server = createServer((socket) => {
	peer = socket;
	const channel = new PrivateFramedChannel(socket, isDaemonWorkerFrameHeader);
	channel.onFrame((frame) => {
		if (frame.header.kind !== "command") return;
		received.push(frame.header.requestId);
		void channel
			.send(
				{ kind: "outbound", outboundType: "response", requestId: frame.header.requestId },
				Buffer.from(
					JSON.stringify({
						type: "response",
						command: frame.header.commandType,
						success: true,
					}),
				),
			)
			.catch(() => {});
	});
	socket.pause();
});
const socketPath = join(directory, "worker.sock");
await new Promise<void>((resolve) => server.listen(socketPath, resolve));
const client = new DaemonWorkerClient(socketPath);
try {
	await client.connect();
	client.onClose(() => closed++);
	const started = performance.now();
	const settled: { elapsed: number; error: string }[] = [];
	const observe = (promise: Promise<unknown>) =>
		promise.then(
			() => settled.push({ elapsed: performance.now() - started, error: "unexpected success" }),
			(error) => settled.push({ elapsed: performance.now() - started, error: String(error) }),
		);
	// Exceed the Unix socket buffer, then queue a list behind the blocked frame.
	const requests = [
		observe(
			client.request({ type: "prompt", activeSessionId: "backpressure", message: "x".repeat(4 * 1024 * 1024) }, 100),
		),
		observe(client.request({ type: "list" }, 100)),
	];
	await delay(500);
	const settledBeforeResume = settled.length;
	const repeatErrors: string[] = [];
	for (let index = 0; index < 20; index++) {
		try {
			await client.request({ type: "list" }, 20);
		} catch (error) {
			repeatErrors.push(String(error));
		}
	}
	const disconnect = process.argv.includes("--disconnect");
	if (disconnect) peer?.destroy();
	else peer?.resume();
	await Promise.all(requests);
	if (!disconnect) {
		const deadline = Date.now() + 2000;
		while (received.length < 2 && Date.now() < deadline) await delay(5);
		if (received.length !== 2) throw new Error("Original frames did not drain after resume");
	}
	const fresh = disconnect ? undefined : await client.request({ type: "list" }, 2000);
	await delay(20);
	console.log(
		JSON.stringify({
			settledBeforeResume,
			settled,
			unhandled,
			closed,
			fresh: fresh?.success,
			received,
			repeatErrors,
		}),
	);
} finally {
	client.close();
	peer?.destroy();
	await new Promise<void>((resolve) => server.close(() => resolve()));
	rmSync(directory, { recursive: true, force: true });
}
