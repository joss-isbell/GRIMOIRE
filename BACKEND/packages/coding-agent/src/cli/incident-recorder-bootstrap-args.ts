import { posix } from "node:path";

/**
 * The bootstrap runner has no mode switches or defaults. Keeping this parser
 * deliberately small also lets the entrypoint reject bad input before the
 * recorder, systemd, or package graph is loaded.
 */
export function parseIncidentRecorderBootstrapArgs(args: readonly string[]): { agentDir: string } {
	const agentDir = args[1];
	if (
		args.length !== 2 ||
		args[0] !== "--agent-dir" ||
		typeof agentDir !== "string" ||
		!posix.isAbsolute(agentDir) ||
		posix.resolve(agentDir) !== agentDir ||
		agentDir === "/" ||
		/[\u0000-\u001f\u007f]/.test(agentDir)
	) {
		throw new Error(
			"Incident recorder bootstrap requires exactly --agent-dir followed by its canonical absolute directory",
		);
	}
	return { agentDir };
}
