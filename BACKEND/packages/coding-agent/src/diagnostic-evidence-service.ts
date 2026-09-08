import { readFile, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import {
	type DiagnosticEvidenceServiceConfig,
	runDiagnosticEvidenceService,
} from "./modes/daemon/diagnostic-evidence-service.js";

const controller = new AbortController();
let lastStatus: string | undefined;
let stopping = false;
let shutdown: ReturnType<typeof setTimeout> | undefined;
const stop = () => {
	if (stopping) return;
	stopping = true;
	controller.abort();
	shutdown = setTimeout(() => process.exit(1), 15_000);
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
const startup = setTimeout(() => {
	process.stderr.write("diagnostic_service_startup_timeout\n");
	process.exitCode = 1;
	stop();
}, 30_000);
try {
	const [flag, path, ...extra] = process.argv.slice(2);
	if (flag !== "--config" || !path || !isAbsolute(path) || extra.length)
		throw new Error("usage: diagnostic-evidence-service --config /absolute/config.json");
	if ((await stat(path)).size > 64 * 1024) throw new Error("diagnostic_configuration_too_large");
	const config: unknown = JSON.parse(await readFile(path, "utf8"));
	if (!config || typeof config !== "object" || Array.isArray(config))
		throw new Error("diagnostic_configuration_invalid");
	for (const key of Object.keys(config))
		if (
			![
				"stateRoot",
				"journal",
				"atop",
				"causalTrace",
				"nativeHistoryDirectories",
				"totalBudgetBytes",
				"freeReserveBytes",
				"maxArtifactBytes",
			].includes(key)
		)
			throw new Error(`diagnostic_configuration_unknown: ${key}`);
	await runDiagnosticEvidenceService(config as DiagnosticEvidenceServiceConfig, {
		signal: controller.signal,
		onReady: (status) => {
			controller.signal.throwIfAborted();
			clearTimeout(startup);
			process.stdout.write(`${JSON.stringify({ type: "ready", ...status })}\n`);
		},
		onStatus: (status) => {
			const change = JSON.stringify({
				provider: status.provider,
				admitted: status.capacity?.admitted,
				error: status.lastError,
			});
			if (change === lastStatus) return;
			lastStatus = change;
			process.stdout.write(`${JSON.stringify({ type: "status", ...status })}\n`);
		},
	});
} catch (error) {
	process.stderr.write(`${String(error instanceof Error ? error.message : error).slice(0, 4096)}\n`);
	process.exitCode = 1;
} finally {
	clearTimeout(startup);
	clearTimeout(shutdown);
	process.removeListener("SIGTERM", stop);
	process.removeListener("SIGINT", stop);
}
