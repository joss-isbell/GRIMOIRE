import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { ENV_AGENT_DIR } from "../src/config.js";

const fixturePath = resolve(__dirname, "fixtures/agents-view-failed-resident.ts");
const tsxPath = resolve(__dirname, "../../../node_modules/tsx/dist/cli.mjs");

describe.skipIf(process.platform !== "linux")("Agents View failed resident integration", () => {
	it.each(["saved-open", "inactive-reply", "unknown-identity", "concurrent-open", "failed-launch-retry"])(
		"%s uses real supervisor and worker transports without changing the saved prefix",
		async (scenario) => {
			const root = mkdtempSync(join(tmpdir(), "av-resume-"));
			for (const directory of ["home", "agent", "project", "sessions", "tmp", "descriptors"])
				mkdirSync(join(root, directory));
			writeFileSync(join(root, "agent", "settings.json"), JSON.stringify({ autoRefine: { enabled: false } }));
			// Run even the UI helper in an isolated process: collectDaemonLaunchEnv must
			// never send the test runner's ambient credentials into the fixture worker.
			const child = spawn(process.execPath, [tsxPath, fixturePath, scenario], {
				cwd: join(root, "project"),
				env: {
					PATH: `${dirname(process.execPath)}:/usr/sbin:/usr/bin:/bin`,
					HOME: join(root, "home"),
					TMPDIR: join(root, "tmp"),
					LANG: "C.UTF-8",
					[ENV_AGENT_DIR]: join(root, "agent"),
					PRIME_AGENT_SESSION_DIR: join(root, "sessions"),
					AGENTS_VIEW_RESUME_ROOT: root,
					TSX_TSCONFIG_PATH: resolve(__dirname, "../../../tsconfig.json"),
					PI_OFFLINE: "1",
					PI_SKIP_VERSION_CHECK: "1",
					PRIME_AGENT_INSTALL_UV: "0",
					RLM_DEPTH: "0",
				},
				stdio: ["ignore", "pipe", "pipe"],
			});
			let output = "";
			for (const stream of [child.stdout, child.stderr])
				stream.on("data", (chunk: Buffer) => {
					output = (output + chunk.toString("utf8")).slice(-128 * 1024);
				});
			const timeout = setTimeout(() => child.kill("SIGTERM"), 100_000);
			try {
				const code = await new Promise<number | null>((resolveExit, reject) => {
					child.once("error", reject);
					child.once("exit", resolveExit);
				});
				expect(code, output).toBe(0);
				expect(output).toContain(`AGENTS_VIEW_RESUME_PASS ${scenario}`);
			} finally {
				clearTimeout(timeout);
				if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
				rmSync(root, { recursive: true, force: true });
			}
		},
		110_000,
	);
});
