import { spawn } from "node:child_process";
import { accessSync, constants, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux") {
	throw new Error("The causal kernel test requires Linux user, PID, mount, and network namespaces.");
}

const backend = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const python = resolve(
	process.env.PRIME_AGENT_CAUSAL_PYTHON ??
		process.env.PRIME_AGENT_KERNEL_PYTHON ??
		join(homedir(), ".prime", "agent", "kernel-venv", "bin", "python"),
);
for (const executable of [python, "/usr/bin/unshare", "/usr/sbin/ip", "/usr/bin/ss"]) {
	try {
		accessSync(executable, constants.X_OK);
	} catch {
		throw new Error(
			`Required executable unavailable: ${executable}. Set PRIME_AGENT_CAUSAL_PYTHON to an existing bootstrapped Python; this test does not install dependencies.`,
		);
	}
}

const tempRoot = mkdtempSync("/tmp/prime-causal-");
const keepEvidence = process.env.PRIME_AGENT_CAUSAL_KEEP_EVIDENCE === "1";
let succeeded = false;
try {
	const child = spawn(
		"/usr/bin/unshare",
		[
			"--user",
			"--map-root-user",
			"--pid",
			"--fork",
			"--kill-child=SIGKILL",
			"--mount-proc",
			"--net",
			process.execPath,
			join(backend, "node_modules", "tsx", "dist", "cli.mjs"),
			join(backend, "node_modules", "vitest", "dist", "cli.js"),
			"--run",
			"--no-file-parallelism",
			"--tagsFilter",
			"kernel-heavy",
			"test/daemon-status-kernel-causal.test.ts",
			"test/kernel-protocol-observations.test.ts",
		],
		{
			cwd: join(backend, "packages", "coding-agent"),
			env: {
				PATH: `${dirname(process.execPath)}:/usr/sbin:/usr/bin:/bin`,
				HOME: homedir(),
				LANG: "C.UTF-8",
				TMPDIR: tempRoot,
				PRIME_AGENT_CAUSAL_PYTHON: python,
				PRIME_AGENT_CAUSAL_KEEP_EVIDENCE: keepEvidence ? "1" : "0",
			},
			stdio: "inherit",
		},
	);
	const interrupt = () => child.kill("SIGTERM");
	process.once("SIGINT", interrupt);
	process.once("SIGTERM", interrupt);
	const timeout = setTimeout(interrupt, 240_000);
	try {
		const code = await new Promise((resolveExit, reject) => {
			child.once("error", reject);
			child.once("close", (exitCode) => resolveExit(exitCode ?? 1));
		});
		succeeded = code === 0;
		process.exitCode = code;
	} finally {
		clearTimeout(timeout);
		process.off("SIGINT", interrupt);
		process.off("SIGTERM", interrupt);
	}
} finally {
	if (succeeded && !keepEvidence) {
		if (dirname(tempRoot) !== "/tmp" || !basename(tempRoot).startsWith("prime-causal-") || realpathSync(tempRoot) !== tempRoot) {
			throw new Error(`Refusing cleanup of changed temporary directory: ${tempRoot}`);
		}
		rmSync(tempRoot, { recursive: true, force: true });
	} else {
		console.error(`Causal test evidence preserved in ${tempRoot}`);
	}
}
