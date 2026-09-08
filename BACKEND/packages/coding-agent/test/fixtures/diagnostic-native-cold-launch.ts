import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ensureInteractiveDaemonRunning } from "../../src/cli/daemon-launch.js";
import { DaemonClient } from "../../src/modes/daemon/daemon-client.js";

const [root] = process.argv.slice(2);
if (!root) throw new Error("Expected a private cold-launch fixture root");
process.argv[1] = fileURLToPath(new URL("../../src/cli.ts", import.meta.url));
const socketPath = join(root, "daemon.sock");
await ensureInteractiveDaemonRunning(socketPath, root);
const client = new DaemonClient(socketPath);
try {
	await client.connect(2000);
	const hello = await client.waitForHello(2000);
	await writeFile(join(root, "launched.json"), JSON.stringify({ launcherPid: process.pid, hello }), { mode: 0o600 });
} finally {
	client.close();
}
