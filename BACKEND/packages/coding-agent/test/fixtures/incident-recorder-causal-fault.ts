import { existsSync, unlinkSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { join } from "node:path";
import { DaemonWorkerClient } from "../../src/modes/daemon/daemon-worker-client.js";
import {
	appendSupervisorDiagnosticEvent,
	flushSupervisorDiagnosticCapture,
} from "../../src/modes/daemon/incident-recorder.js";
import { configureIncidentCaptureEmitter } from "../../src/modes/daemon/incident-recorder-writer.js";

type Fault = "event_loop_hang" | "socket_loss" | "worker_response_hang";

const fault = process.env.PRIME_TEST_INCIDENT_RECORDER_FAULT as Fault | undefined;
if (!fault || !configureIncidentCaptureEmitter())
	throw new Error("causal fault fixture recorder transport unavailable");

if (fault === "event_loop_hang") {
	const realNow = Date.now;
	Date.now = () => realNow() - 60_000;
	appendSupervisorDiagnosticEvent("supervisor_heartbeat", {
		socketExists: false,
	});
	Date.now = realNow;
	await flushSupervisorDiagnosticCapture();
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
}

if (fault === "socket_loss") {
	const socketPath = process.env.PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_SOCKET;
	if (!socketPath) throw new Error("causal socket-loss fixture socket path unavailable");
	const server = createServer((socket) => socket.resume());
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(socketPath, resolve);
	});
	appendSupervisorDiagnosticEvent("supervisor_heartbeat", {
		socketExists: true,
	});
	await flushSupervisorDiagnosticCapture();
	unlinkSync(socketPath);
	setInterval(() => {}, 1_000);
}

if (fault === "worker_response_hang") {
	const workerSocket = join(process.cwd(), "worker-response-hang.sock");
	let connection: Socket | undefined;
	const server = createServer((socket) => {
		connection = socket;
		socket.resume();
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(workerSocket, resolve);
	});
	const client = new DaemonWorkerClient(workerSocket);
	try {
		await client.connect();
		try {
			await client.request({ type: "list" }, 25);
			throw new Error("Worker response fixture unexpectedly received a response");
		} catch (error) {
			if (!(error instanceof Error && error.message === "Timed out waiting for daemon worker response to list")) {
				throw error;
			}
		}
	} finally {
		client.close();
	}
	connection?.destroy();
	if (server.listening) {
		await new Promise<void>((resolve, reject) => {
			server.close((error) => (error ? reject(error) : resolve()));
		});
	}
	if (existsSync(workerSocket)) unlinkSync(workerSocket);
	await flushSupervisorDiagnosticCapture();
	setInterval(() => {}, 1_000);
}
