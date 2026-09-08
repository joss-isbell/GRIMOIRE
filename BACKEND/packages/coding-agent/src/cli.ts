#!/usr/bin/env node
// The Node 22+ module graph fails at link time on older Node, so it must load
// behind the dynamic import, after the dependency-free guard runs.
import { assertNodeVersion } from "./cli/node-version-check.js";

const supported = assertNodeVersion({
	version: process.versions.node,
	log: console.error,
	exit: (code) => process.exit(code),
});

if (supported) {
	// Keep the generation boundary ahead of daemon probing and all CLI imports.
	if (process.argv.slice(2).includes("--incident-recorder-service")) {
		console.error(
			"GRIMOIRE_INCIDENT_CAS_V2_REJECTS_LEGACY_SELECTOR: The incident recorder requires its dedicated v2 service entrypoint.",
		);
		process.exitCode = 1;
	} else {
		const { runCli } = await import("./cli-main.js");
		await runCli();
	}
}
