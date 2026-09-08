import { readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "../../src/core/kernel/diagnostics.js";
import { KernelManager } from "../../src/core/kernel/index.js";
import {
	flushSupervisorDiagnosticCapture,
	installSupervisorDiagnosticHooks,
} from "../../src/modes/daemon/incident-recorder.js";

const [root, python] = process.argv.slice(2);
if (!root || !python) throw new Error("Expected a private fixture root and Python executable");
const sessionId = "native-kernel-evidence-session";
const manager = new KernelManager({ python, cwd: root, sessionId });
const events: KernelDiagnosticEvent[] = [];
const unsubscribe = subscribeKernelDiagnostics((event) => {
	if (event.sessionId === sessionId) events.push(event);
});
const uninstall = installSupervisorDiagnosticHooks(join(root, "unused-fixture.sock"));
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

try {
	const result = await manager.execute("import os\nsentinel = 'native-evidence-sentinel'\nprint(os.getpid())");
	if (result.status !== "ok") throw new Error("Kernel failed the readiness execution");
	const original = events.find((event) => event.type === "kernel_process_started");
	if (!original || result.stdout.trim() !== String(original.kernelPid)) throw new Error("Kernel identity unavailable");
	await state("ready", {
		producerPid: process.pid,
		kernelPid: original.kernelPid,
		kernelInstanceId: original.kernelInstanceId,
		kernelProcessStartId: original.kernelProcessStartId,
	});
	let injected = false;
	while (!stopping) {
		const command = await readFile(join(root, "command"), "utf8").catch((error: NodeJS.ErrnoException) => {
			if (error.code !== "ENOENT") throw error;
			return "";
		});
		if (command === "stop") break;
		if (!injected && command === "exit-kernel") {
			injected = true;
			const failure = await manager.execute("assert sentinel == 'native-evidence-sentinel'\nos._exit(23)").then(
				() => undefined,
				(error: unknown) => String(error),
			);
			if (!failure) throw new Error("Kernel exit did not reject the active execution");
			const deadline = Date.now() + 5000;
			while (!events.some((event) => event.type === "kernel_unexpected_exit") && Date.now() < deadline) {
				await delay(25);
			}
			if (!events.some((event) => event.type === "kernel_unexpected_exit")) {
				throw new Error("Kernel exit diagnostic was not observed");
			}
			await flushSupervisorDiagnosticCapture();
			await state("failed", { producerPid: process.pid, executionRejected: true });
		}
		await delay(50);
	}
} catch (error) {
	await state("error", { error: String(error) });
	process.exitCode = 1;
} finally {
	await manager.dispose();
	await flushSupervisorDiagnosticCapture();
	uninstall();
	unsubscribe();
}
