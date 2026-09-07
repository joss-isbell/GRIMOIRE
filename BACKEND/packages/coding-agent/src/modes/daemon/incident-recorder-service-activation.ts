import { closeSync, constants, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { parseIncidentRecorderServiceArgs } from "../../cli/incident-recorder-service-args.js";
import {
	INCIDENT_CAS_V2_SERVICE_ENTRYPOINT,
	INCIDENT_CAS_V2_SYSTEMD_UNIT,
	type IncidentCasV2CutoverTarget,
	openIncidentCasV2Activation,
} from "./incident-recorder-cas-cutover.js";
import { acquireIncidentRecorderNamespaceCas } from "./incident-recorder-namespace-admission.js";
import type { IncidentRecorderWriterLifecycleAdmissionContract } from "./incident-recorder-writer-lifecycle.js";

export interface IncidentRecorderServiceActivation {
	readonly contract: IncidentRecorderWriterLifecycleAdmissionContract;
	close(): void;
}

/** Read only the installed unit; cutover admission independently binds its identity and manager state. */
export function readIncidentRecorderServiceTarget(options: {
	nodePath: string;
	entrypointPath: string;
	agentDir: string;
	configHomeDir?: string;
}): IncidentCasV2CutoverTarget {
	parseIncidentRecorderServiceArgs(["--agent-dir", options.agentDir]);
	const nodePath = realpathSync.native(options.nodePath);
	const entrypointPath = realpathSync.native(options.entrypointPath);
	const packageRoot = dirname(dirname(dirname(entrypointPath)));
	if (entrypointPath !== join(packageRoot, INCIDENT_CAS_V2_SERVICE_ENTRYPOINT))
		throw new Error("Incident recorder must run from its dedicated installed v2 entrypoint");
	const configHome = options.configHomeDir ?? (process.env.XDG_CONFIG_HOME || join(homedir(), ".config"));
	const unitPath = join(configHome, "systemd", "user", INCIDENT_CAS_V2_SYSTEMD_UNIT);
	const descriptor = openSync(unitPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
	let unitContents: string;
	try {
		const before = fstatSync(descriptor, { bigint: true });
		if (!before.isFile() || before.size < 1n || before.size > 64n * 1024n)
			throw new Error("Incident recorder installed unit is not a bounded regular file");
		const bytes = Buffer.alloc(Number(before.size));
		let offset = 0;
		while (offset < bytes.length) {
			const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
			if (count === 0) throw new Error("Incident recorder installed unit changed during inspection");
			offset += count;
		}
		const after = fstatSync(descriptor, { bigint: true });
		if (before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs)
			throw new Error("Incident recorder installed unit changed during inspection");
		unitContents = bytes.toString("utf8");
	} finally {
		closeSync(descriptor);
	}
	return {
		agentDir: options.agentDir,
		packageRoot,
		launcher: { unitPath, unitContents, argv: [nodePath, entrypointPath, "--agent-dir", options.agentDir] },
	};
}

/** Generation identity is never used without the retained activation's revalidation. */
export function openIncidentRecorderServiceActivation(
	target: IncidentCasV2CutoverTarget,
): IncidentRecorderServiceActivation {
	const opened = openIncidentCasV2Activation(target);
	if (opened.state !== "active") throw new Error(`Incident recorder v2 activation unavailable: ${opened.reason}`);
	const activation = opened.activation;
	return Object.freeze({
		contract: Object.freeze({
			activationGenerationDigest: activation.activationGenerationDigest,
			revalidateActivation: () => activation.revalidate(),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		}),
		close: () => activation.close(),
	});
}
