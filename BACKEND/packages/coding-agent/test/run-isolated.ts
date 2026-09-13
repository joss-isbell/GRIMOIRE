import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { isolatedTestEnvironment } from "./isolated-environment.js";

const packageDir = fileURLToPath(new URL("..", import.meta.url));
const isolation = isolatedTestEnvironment();
const args = process.argv.slice(2);
const bootstrapIndex = args.indexOf("--bootstrap");
const bootstrap = bootstrapIndex !== -1;
if (bootstrap) args.splice(bootstrapIndex, 1);

async function run(commandArgs: string[]): Promise<number> {
	return new Promise((resolve, reject) => {
		const child = spawn(process.execPath, commandArgs, { cwd: packageDir, env: isolation.env, stdio: "inherit" });
		let forceKill: ReturnType<typeof setTimeout> | undefined;
		const forward = (signal: NodeJS.Signals) => {
			child.kill(signal);
			forceKill ??= setTimeout(() => child.kill("SIGKILL"), 10_000);
			forceKill.unref();
		};
		const interrupt = () => forward("SIGINT");
		const terminate = () => forward("SIGTERM");
		process.on("SIGINT", interrupt);
		process.on("SIGTERM", terminate);
		const cleanup = () => {
			if (forceKill) clearTimeout(forceKill);
			process.off("SIGINT", interrupt);
			process.off("SIGTERM", terminate);
		};
		child.once("error", (error) => {
			cleanup();
			reject(error);
		});
		child.once("close", (code, signal) => {
			cleanup();
			resolve(code ?? (signal === "SIGINT" ? 130 : 143));
		});
	});
}

try {
	let code = bootstrap ? await run(["--import", "tsx", "src/core/kernel/bootstrap-cli.ts"]) : 0;
	if (code === 0) code = await run(["--import", "tsx", "../../node_modules/vitest/dist/cli.js", "--run", ...args]);
	process.exitCode = code;
} catch (error) {
	console.error(error instanceof Error ? error.message : String(error));
	process.exitCode = 1;
} finally {
	isolation.cleanup();
}
