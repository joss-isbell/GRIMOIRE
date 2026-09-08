import { readFileSync, readlinkSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import type { Socket } from "node:net";
import { join } from "node:path";
import { DaemonSupervisor } from "../../src/modes/daemon/daemon-supervisor.js";

// A test-only preload on the real supervisor. Workers inheriting execArgv never
// install this hook: only the private PID-1 fixture's direct child is eligible.
const root = process.env.PRIME_AGENT_SOCKET_LOSS_TEST_ROOT;
if (root && process.ppid === 1 && process.platform === "linux") {
	if (
		!readFileSync("/proc/1/cmdline", "utf8").includes("diagnostic-native-parent-faults.ts") ||
		!/^0\s+\d+\s+1$/.test(readFileSync("/proc/self/uid_map", "utf8").trim())
	)
		throw new Error("Socket fault requires the isolated parent fixture");
	const original = DaemonSupervisor.prototype.start;
	DaemonSupervisor.prototype.start = async function () {
		await original.call(this);
		let inspecting = false;
		const timer = setInterval(async () => {
			if (inspecting) return;
			inspecting = true;
			try {
				if ((await readFile(join(root, "socket-command"), "utf8").catch(() => "")) !== "close") return;
				clearInterval(timer);
				const workers = [
					...(
						this as unknown as {
							workers: Map<
								string,
								{
									descriptor: { pid: number; processStartId?: string; workerId: string };
									client?: { socket?: Socket };
								}
							>;
						}
					).workers.values(),
				];
				if (workers.length !== 1) throw new Error("Socket fault requires exactly one owned worker");
				const worker = workers[0];
				const fields = readFileSync(`/proc/${worker.descriptor.pid}/stat`, "utf8").split(") ").at(-1)!.split(" ");
				if (Number(fields[1]) !== process.pid || worker.descriptor.processStartId !== `proc:${fields[19]}`)
					throw new Error("Socket fault worker identity changed");
				const socket = worker.client?.socket;
				const fd = (socket as unknown as { _handle?: { fd?: number } })?._handle?.fd;
				if (!socket || socket.destroyed || !Number.isInteger(fd) || fd! < 0)
					throw new Error("Owned live worker transport unavailable");
				const socketIdentity = readlinkSync(`/proc/self/fd/${fd}`);
				if (!/^socket:\[\d+\]$/.test(socketIdentity)) throw new Error("Selected handle is not a socket");
				await writeFile(
					join(root, "socket-injection.json"),
					JSON.stringify({
						supervisorPid: process.pid,
						worker: {
							pid: worker.descriptor.pid,
							processStartId: worker.descriptor.processStartId,
							workerId: worker.descriptor.workerId,
						},
						socketIdentity,
						fd,
						time: Date.now(),
					}),
					{ mode: 0o600 },
				);
				if (
					worker.client?.socket !== socket ||
					socket.destroyed ||
					readlinkSync(`/proc/self/fd/${fd}`) !== socketIdentity
				)
					throw new Error("Owned transport changed before injection");
				socket.destroy();
				await writeFile(join(root, "socket-injected"), "done", { mode: 0o600 });
			} catch (error) {
				clearInterval(timer);
				await writeFile(join(root, "error.json"), JSON.stringify({ error: String(error) }), { mode: 0o600 });
			} finally {
				inspecting = false;
			}
		}, 25);
		timer.unref();
	};
}
