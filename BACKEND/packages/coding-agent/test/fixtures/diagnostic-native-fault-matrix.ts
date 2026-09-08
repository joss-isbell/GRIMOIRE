import { readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "../../src/core/kernel/diagnostics.js";
import { KernelManager } from "../../src/core/kernel/index.js";
import {
	flushSupervisorDiagnosticCapture,
	installSupervisorDiagnosticHooks,
} from "../../src/modes/daemon/incident-recorder.js";

const [root, python, sessionId] = process.argv.slice(2);
if (!root || !python || !sessionId) throw new Error("Expected private root, Python and session identity");
process.title = "prime-agent";
const manager = new KernelManager({ python, cwd: root, sessionId });
const events: KernelDiagnosticEvent[] = [];
const unsubscribe = subscribeKernelDiagnostics((event) => {
	if (event.sessionId === sessionId) events.push(event);
});
const uninstall = installSupervisorDiagnosticHooks(join(root, "unused.sock"));
let stopping = false;
process.once("SIGTERM", () => {
	stopping = true;
	manager.disposeSync();
});

async function state(name: string, value: Record<string, unknown>): Promise<void> {
	const destination = join(root, `${name}.json`);
	await writeFile(`${destination}.pending`, JSON.stringify(value), { mode: 0o600 });
	await rename(`${destination}.pending`, destination);
}

async function until(predicate: () => boolean, timeoutMs = 10_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) throw new Error("Required kernel observation was not received");
		await delay(25);
	}
}

try {
	const ready = await manager.execute(
		"import os, time, resource\nresource.setrlimit(resource.RLIMIT_CORE, (0, 0))\nos.setpgid(0, 0)\nsentinel = 'matrix-private-sentinel'\noriginal_pid = os.getpid()\nprint(original_pid)",
	);
	const identity = events.find((event) => event.type === "kernel_process_started");
	if (!identity || ready.status !== "ok" || ready.stdout.trim() !== String(identity.kernelPid))
		throw new Error("Initial kernel identity or readiness execution failed");
	await state("ready", {
		producerPid: process.pid,
		kernelPid: identity.kernelPid,
		kernelInstanceId: identity.kernelInstanceId,
		kernelProcessStartId: identity.kernelProcessStartId,
	});
	let previous = "";
	while (!stopping) {
		const command = await readFile(join(root, "command"), "utf8").catch((error: NodeJS.ErrnoException) => {
			if (error.code !== "ENOENT") throw error;
			return "";
		});
		if (command === "stop") break;
		if (command && command !== previous) {
			previous = command;
			if (command === "shutdown") {
				await manager.shutdown({
					diagnosticContext: { caller: "nativeFixture.shutdown", reason: "session_closed" },
				});
				await until(() => events.some((event) => event.type === "kernel_process_exit_observed"));
				await flushSupervisorDiagnosticCapture();
				await state("completed", { producerPid: process.pid });
			} else if (command === "sentinel") {
				const result = await manager.execute(
					"assert os.getpid() == original_pid\nassert sentinel == 'matrix-private-sentinel'\nprint(original_pid)",
				);
				await flushSupervisorDiagnosticCapture();
				await state("retained", { status: result.status, stdout: result.stdout.trim() });
			} else {
				const code =
					command === "native-crash"
						? "import ctypes\nctypes.string_at(0)"
						: command === "close-shell"
							? "stream = get_ipython().kernel.shell_stream\nstream.io_loop.add_callback(stream.close)\ntime.sleep(1)"
							: command === "healthy"
								? "time.sleep(7)"
								: "time.sleep(14)";
				const offset = events.length;
				const execution = manager.execute(code).then(
					(result) => ({ status: result.status }),
					(error: unknown) => ({ status: "rejected", error: String(error) }),
				);
				await until(() => events.slice(offset).some((event) => event.type === "kernel_execute_started"));
				const request = events.slice(offset).find((event) => event.type === "kernel_execute_started");
				if (request?.type !== "kernel_execute_started") throw new Error("Execution identity unavailable");
				await state("executing", { requestMsgId: request.requestMsgId });
				const result = await Promise.race([execution, delay(25_000, { status: "pending" }, { ref: false })]);
				if (result.status === "rejected")
					await until(() => events.some((event) => event.type === "kernel_unexpected_exit"));
				if (command === "close-shell") await delay(1500);
				await flushSupervisorDiagnosticCapture();
				await state("completed", { ...result, requestMsgId: request.requestMsgId, producerPid: process.pid });
			}
		}
		await delay(25);
	}
} catch (error) {
	await state("error", { error: String(error) });
	process.exitCode = 1;
} finally {
	manager.disposeSync();
	await flushSupervisorDiagnosticCapture();
	uninstall();
	unsubscribe();
}
