#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { parseIncidentRecorderBootstrapArgs } from "./cli/incident-recorder-bootstrap-args.js";
import { assertNodeVersion } from "./cli/node-version-check.js";

if (assertNodeVersion({ version: process.versions.node, log: console.error, exit: (code) => process.exit(code) })) {
	try {
		const { agentDir } = parseIncidentRecorderBootstrapArgs(process.argv.slice(2));
		const { runIncidentRecorderBootstrap } = await import("./modes/daemon/incident-recorder-bootstrap.js");
		runIncidentRecorderBootstrap({
			agentDir,
			nodePath: realpathSync.native(process.execPath),
			bootstrapEntrypointPath: realpathSync.native(process.argv[1] ?? ""),
		});
	} catch (error) {
		console.error(`Incident recorder bootstrap failed: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
}
