import { posix } from "node:path";

/** The dedicated Linux service has no CLI modes, positional arguments, or defaults. */
export function parseIncidentRecorderServiceArgs(args: readonly string[]): { agentDir: string } {
	if (
		args.length !== 2 ||
		args[0] !== "--agent-dir" ||
		!posix.isAbsolute(args[1]) ||
		posix.resolve(args[1]) !== args[1] ||
		args[1] === "/" ||
		/[\u0000-\u001f\u007f]/.test(args[1])
	) {
		throw new Error("Incident recorder v2 requires exactly --agent-dir followed by its canonical absolute directory");
	}
	return { agentDir: args[1] };
}
