import { describe, expect, it } from "vitest";
import { parseIncidentRecorderBootstrapArgs } from "../src/cli/incident-recorder-bootstrap-args.js";

describe("incident recorder bootstrap arguments", () => {
	it("accepts one canonical absolute agent directory", () => {
		expect(parseIncidentRecorderBootstrapArgs(["--agent-dir", "/private/agent data"])).toEqual({
			agentDir: "/private/agent data",
		});
	});

	it.each([
		[],
		["--agent-dir"],
		["--agent-dir", "relative"],
		["--agent-dir", "/private/../agent"],
		["--agent-dir", "/private/agent/"],
		["--agent-dir", "/private/agent/."],
		["--agent-dir", "/"],
		["--agent-dir", "/private/agent\nother"],
		["--agent-dir", "/private/agent\u0000other"],
		["--agent-dir", "/private/agent", "--help"],
		["--incident-recorder-bootstrap", "--agent-dir", "/private/agent"],
	])("rejects ambiguous bootstrap arguments: %j", (...args) => {
		expect(() => parseIncidentRecorderBootstrapArgs(args)).toThrow(/requires exactly --agent-dir/);
	});
});
