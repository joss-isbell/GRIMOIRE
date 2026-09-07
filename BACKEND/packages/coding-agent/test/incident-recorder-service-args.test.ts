import { describe, expect, it } from "vitest";
import { parseIncidentRecorderServiceArgs } from "../src/cli/incident-recorder-service-args.js";

describe("dedicated recorder service arguments", () => {
	it("accepts one explicit canonical Linux agent directory, including spaces", () => {
		expect(parseIncidentRecorderServiceArgs(["--agent-dir", "/private/agent data"])).toEqual({
			agentDir: "/private/agent data",
		});
	});

	it.each([
		[],
		["--agent-dir"],
		["--incident-recorder-service", "--agent-dir", "/private/agent"],
		["--agent-dir", "/private/agent", "--mode", "daemon"],
		["--agent-dir", "relative"],
		["--agent-dir", "/private/../agent"],
		["--agent-dir", "/private/agent/"],
		["--agent-dir", "/"],
		["--agent-dir", "/private/agent\nother"],
		["--agent-dir", "/private/agent\0other"],
		["--agent-dir", "C:\\personal\\agent"],
	])("rejects ambiguous or legacy service arguments: %j", (...args) => {
		expect(() => parseIncidentRecorderServiceArgs(args)).toThrow("requires exactly --agent-dir");
	});
});
