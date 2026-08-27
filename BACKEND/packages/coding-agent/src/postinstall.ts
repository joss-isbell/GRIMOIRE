import { realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { getAgentDir } from "./config.js";
import { ensureKernelPython } from "./core/kernel/bootstrap.js";
import { installIncidentRecorderSystemdService } from "./modes/daemon/incident-recorder.js";
import { ensureTool } from "./utils/tools-manager.js";

const bootstrapKernel = process.env.PRIME_AGENT_BOOTSTRAP_KERNEL_ON_INSTALL === "1";
const bootstrapTools = process.env.PRIME_AGENT_BOOTSTRAP_TOOLS_ON_INSTALL === "1";
const globalInstall =
	process.env.npm_config_global === "true" ||
	bootstrapTools ||
	process.env.PRIME_AGENT_INSTALL_INCIDENT_RECORDER === "1";

if (bootstrapKernel && process.env.PRIME_AGENT_INSTALL_UV === undefined) {
	process.env.PRIME_AGENT_INSTALL_UV = "1";
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function oneLine(message: string): string {
	return message.replace(/\s+/g, " ").trim();
}

try {
	if (bootstrapTools) {
		await Promise.all([ensureTool("fd", true), ensureTool("rg", true)]);
	}
	if (bootstrapKernel) {
		await ensureKernelPython();
	}
	if (globalInstall) {
		const distDir = fileURLToPath(new URL(".", import.meta.url));
		const result = installIncidentRecorderSystemdService({
			nodePath: realpathSync(process.execPath),
			entrypointPath: realpathSync(join(distDir, "bundle", "cli.js")),
			agentDir: getAgentDir(),
		});
		if (result.status === "failed" || result.status === "unavailable") {
			console.error(
				`prime-agent: incident recorder capture setup unavailable; Agent launch remains fail-open: ${oneLine(result.message ?? "unknown error")}`,
			);
		}
	}
} catch (error) {
	console.error(`prime-agent: postinstall setup skipped: ${oneLine(errorMessage(error))}`);
}
