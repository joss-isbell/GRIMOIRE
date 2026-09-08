import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { accessSync, constants, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux") throw new Error("Native diagnostic acceptance requires Linux and journald.");
const node = realpathSync(process.execPath);
if (Number(process.versions.node.split(".")[0]) < 22)
	throw new Error("Native diagnostic acceptance requires Node >=22.");
const database = new DatabaseSync(":memory:");
let sqlite;
try {
	sqlite = database.prepare("SELECT sqlite_version() AS version").get().version;
} finally {
	database.close();
}
const minimum = [3, 51, 3];
const version = sqlite.split(".").map(Number);
const comparison = minimum.map((part, index) => version[index] - part).find((part) => part !== 0) ?? 0;
if (comparison < 0) throw new Error(`SQLite >=3.51.3 is required; ${node} supplies ${sqlite}.`);

const backend = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageRoot = join(backend, "packages", "coding-agent");
const python = resolve(
	process.env.PRIME_AGENT_CAUSAL_PYTHON ??
		process.env.PRIME_AGENT_KERNEL_PYTHON ??
		join(homedir(), ".prime", "agent", "kernel-venv", "bin", "python"),
);
const loader = join(backend, "node_modules", "tsx", "dist", "cli.mjs");
const vitest = join(backend, "node_modules", "vitest", "dist", "cli.js");
for (const executable of [
	node,
	python,
	"/usr/bin/python3",
	"/usr/bin/systemd-cat",
	"/usr/bin/journalctl",
	"/usr/bin/cat",
	"/usr/bin/unshare",
	"/usr/bin/atop",
	"/usr/bin/atopcat",
	"/usr/bin/bash",
	"/usr/bin/prlimit",
	"/usr/sbin/ip",
]) {
	try {
		accessSync(executable, constants.X_OK);
	} catch {
		throw new Error(
			`Required executable unavailable: ${executable}. This acceptance command does not install dependencies.`,
		);
	}
}
for (const dependency of [loader, vitest]) accessSync(dependency, constants.R_OK);

const files = [
	"diagnostic-evidence-store.test.ts",
	"diagnostic-evidence-artifacts.test.ts",
	"diagnostic-evidence-pipeline.test.ts",
	"diagnostic-journal-replay.test.ts",
	"diagnostic-kernel-channel-episodes.test.ts",
	"kernel-channel-termination.test.ts",
	"daemon-worker-close-observation.test.ts",
	"daemon-supervisor-relaunch-diagnostics.test.ts",
	"diagnostic-runtime-identity.test.ts",
	"diagnostic-journal-emitter.test.ts",
	"diagnostic-native-journal.test.ts",
	"diagnostic-native-atop.test.ts",
	"diagnostic-native-kernel.test.ts",
	"diagnostic-native-fault-matrix.test.ts",
	"diagnostic-native-cold-launch.test.ts",
	"diagnostic-native-parent-faults.test.ts",
	"diagnostic-incident-analysis.test.ts",
	"kernel-diagnostic-bridge.test.ts",
	"diagnostic-causal-platform.test.ts",
	"diagnostic-evidence-service.test.ts",
];
// Leave room for nested real Unix sockets below Linux's sockaddr_un ceiling.
const root = mkdtempSync("/tmp/pdn-");
const keepEvidence = process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_KEEP_EVIDENCE === "1";
const env = {
	PATH: `${dirname(node)}:/usr/sbin:/usr/bin:/bin`,
	HOME: homedir(),
	LANG: "C.UTF-8",
	TMPDIR: root,
	PRIME_AGENT_CAUSAL_PYTHON: python,
	PRIME_AGENT_NATIVE_DIAGNOSTIC_TESTS: "1",
	PRIME_AGENT_NATIVE_DIAGNOSTIC_KEEP_EVIDENCE: keepEvidence ? "1" : "0",
	PRIME_AGENT_JOURNAL_REPLAY_PAIRS: join(root, "journal-replay-pairs.json"),
};
function probe(executable, args, input) {
	const result = spawnSync(executable, args, { env, encoding: "utf8", input, timeout: 5000, maxBuffer: 1024 * 1024 });
	if (result.error || result.status !== 0)
		throw new Error(
			`Native diagnostic prerequisite failed: ${executable}: ${result.error ?? result.stderr ?? result.status}`,
		);
	return result.stdout;
}
let succeeded = false;
try {
	probe("/usr/bin/unshare", ["--user", "--map-root-user", "--pid", "--fork", "--mount-proc", "/usr/bin/true"]);
	probe(python, ["-c", "import sys, IPython, ipykernel, zmq; assert sys.version_info >= (3, 11), sys.version"]);
	const identifier = `prime-native-prerequisite-${randomUUID()}`;
	const message = randomUUID();
	const since = Math.floor(Date.now() / 1000) - 1;
	probe("/usr/bin/systemd-cat", [`--identifier=${identifier}`, "--level-prefix=false", "/usr/bin/cat"], `${message}\n`);
	const deadline = Date.now() + 5000;
	let observed = false;
	let firstSerialization;
	const readPrerequisite = () => probe("/usr/bin/journalctl", [
		"--no-pager", "--quiet", `--identifier=${identifier}`, `--since=@${since}`, "--output=json",
	]).split("\n").filter(Boolean).find((line) => JSON.parse(line).MESSAGE === message);
	while (!observed && Date.now() < deadline) {
		firstSerialization = readPrerequisite();
		observed = firstSerialization !== undefined;
		if (!observed) await delay(100);
	}
	if (!observed)
		throw new Error("Native journal write/read round trip failed; check journald availability and read access.");
	const replaySerialization = readPrerequisite();
	if (replaySerialization === undefined) throw new Error("Native journal prerequisite disappeared before replay.");
	writeFileSync(env.PRIME_AGENT_JOURNAL_REPLAY_PAIRS,
		JSON.stringify([{ first: firstSerialization, replay: replaySerialization }]), { mode: 0o600 });
	console.log(`Native diagnostic acceptance: Node ${process.versions.node}, SQLite ${sqlite}, Python ${python}`);
	const report = join(root, "vitest.json");
	const child = spawn(
		"/usr/bin/unshare",
		[
			"--user",
			"--map-root-user",
			"--pid",
			"--fork",
			"--kill-child=SIGKILL",
			"--mount-proc",
			node,
			loader,
			vitest,
			"--run",
			"--no-file-parallelism",
			"--maxWorkers=1",
			"--reporter=default",
			"--reporter=json",
			`--outputFile.json=${report}`,
			...files.map((file) => `test/${file}`),
		],
		{ cwd: packageRoot, env, stdio: "inherit", detached: true },
	);
	let interrupted = false;
	let escalation;
	const signalGroup = (signal) => {
		if (!child.pid) return;
		try {
			process.kill(-child.pid, signal);
		} catch (error) {
			if (error.code !== "ESRCH") throw error;
		}
	};
	const interrupt = () => {
		if (interrupted) return;
		interrupted = true;
		signalGroup("SIGTERM");
		escalation = setTimeout(() => signalGroup("SIGKILL"), 5000);
	};
	process.once("SIGINT", interrupt);
	process.once("SIGTERM", interrupt);
	const timeout = setTimeout(interrupt, 300_000);
	try {
		const code = await new Promise((resolveExit, reject) => {
			child.once("error", reject);
			child.once("close", (exitCode) => resolveExit(exitCode ?? 1));
		});
		if (interrupted || code !== 0)
			throw new Error(
				`Native diagnostic acceptance failed (${interrupted ? "interrupted or timed out" : `exit ${code}`}).`,
			);
		const result = JSON.parse(readFileSync(report, "utf8"));
		for (const file of files) {
			const suite = result.testResults.find((entry) => entry.name === join(packageRoot, "test", file));
			if (
				!suite ||
				suite.status !== "passed" ||
				!suite.assertionResults.length ||
				suite.assertionResults.some((test) => test.status !== "passed")
			)
				throw new Error(`Required acceptance cases were missing, skipped, or failed: ${file}`);
		}
		if (!result.success || result.numPendingTests || result.numTodoTests)
			throw new Error("Native diagnostic acceptance contained incomplete tests.");
		console.log(`Native diagnostic acceptance passed: ${result.numPassedTests} tests; no skipped cases.`);
		succeeded = true;
	} finally {
		clearTimeout(timeout);
		clearTimeout(escalation);
		process.off("SIGINT", interrupt);
		process.off("SIGTERM", interrupt);
	}
} finally {
	if (succeeded && !keepEvidence) {
		if (
			dirname(root) !== "/tmp" ||
			!basename(root).startsWith("pdn-") ||
			realpathSync(root) !== root
		)
			throw new Error(`Refusing cleanup of changed temporary directory: ${root}`);
		rmSync(root, { recursive: true, force: true });
	} else console.error(`Native diagnostic acceptance evidence preserved in ${root}`);
}
