#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { parseIncidentRecorderServiceArgs } from "./cli/incident-recorder-service-args.js";
import { assertNodeVersion } from "./cli/node-version-check.js";

if (assertNodeVersion({ version: process.versions.node, log: console.error, exit: (code) => process.exit(code) })) {
	try {
		const { agentDir } = parseIncidentRecorderServiceArgs(process.argv.slice(2));
		const { readIncidentRecorderServiceTarget, openIncidentRecorderServiceActivation } = await import(
			"./modes/daemon/incident-recorder-service-activation.js"
		);
		const target = readIncidentRecorderServiceTarget({
			nodePath: realpathSync.native(process.execPath),
			entrypointPath: realpathSync.native(process.argv[1]),
			agentDir,
		});
		const activation = openIncidentRecorderServiceActivation(target);
		try {
			const { runIncidentRecorderService } = await import("./modes/daemon/incident-recorder.js");
			await runIncidentRecorderService(agentDir, { writerLifecycleContract: activation.contract });
		} finally {
			activation.close();
		}
	} catch (error) {
		console.error(`Incident recorder v2 service failed: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
}
