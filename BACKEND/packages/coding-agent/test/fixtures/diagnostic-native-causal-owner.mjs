import { spawn } from "node:child_process";
import { readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

// This owner runs only under the privileged test driver's private PID namespace.
// It holds before creating descendants so strict root admission precedes forks.
const [root, loader, fixture, python] = process.argv.slice(2);
if (!root || !loader || !fixture || !python || process.getuid() === 0 || process.ppid !== 1)
	throw new Error("Expected an unprivileged namespace-owned fixture");
process.title = "prime-agent";
const state = async (name, value) => {
	const path = join(root, `${name}.json`);
	await writeFile(`${path}.pending`, JSON.stringify(value), { mode: 0o600 });
	await rename(`${path}.pending`, path);
};
const read = async (name) =>
	JSON.parse(await readFile(join(root, `${name}.json`), "utf8").catch(() => "null"));
await state("owner", { pid: process.pid });
while (!(await read("release"))) await delay(20);
// The maintained probe admits this exact named root on getuid, then descendants.
process.getuid();
await state("released", { pid: process.pid });
for (let sequence = 0; ; sequence++) {
	let command;
	while (!(command = await read(`launch-${sequence}`))) await delay(20);
	if (command.stop) break;
	const child = spawn(
		"/usr/bin/systemd-cat",
		["--identifier", command.identifier, "--level-prefix=false", process.execPath, "--import", loader, fixture,
			command.root, python, command.session],
		{ cwd: command.root, env: { ...process.env, HOME: command.root, TMPDIR: command.root,
			PRIME_AGENT_CODING_AGENT_DIR: join(command.root, "config"),
			PRIME_AGENT_SESSION_DIR: join(command.root, "sessions") }, stdio: "ignore" },
	);
	const exited = new Promise((resolve, reject) => {
		child.once("error", reject);
		child.once("exit", (code, signal) => resolve({ code, signal }));
	});
	await state(`spawned-${sequence}`, { pid: child.pid });
	await state(`exited-${sequence}`, await exited);
}
