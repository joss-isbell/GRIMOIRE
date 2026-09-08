import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { INCIDENT_CAS_V2_LEGACY_SELECTOR_REJECTION_MARKER } from "../src/modes/daemon/incident-recorder-cas-cutover.js";

const cli = vi.hoisted(() => ({ imported: vi.fn(), run: vi.fn() }));
vi.mock("../src/cli-main.js", () => {
	cli.imported();
	return { runCli: cli.run };
});

const originalArgv = process.argv;
const originalExitCode = process.exitCode;

beforeEach(() => {
	vi.resetModules();
	vi.clearAllMocks();
	process.exitCode = undefined;
	vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
	process.argv = originalArgv;
	process.exitCode = originalExitCode;
	vi.restoreAllMocks();
});

describe("incident recorder CLI generation boundary", () => {
	test.each([
		["--incident-recorder-service"],
		["--agent-dir", "/unused/agent", "--incident-recorder-service"],
		["--incident-recorder-service", "--help"],
	])("rejects legacy service arguments before loading the CLI graph: %j", async (...args) => {
		process.argv = [process.execPath, "/unused/cli.js", ...args];
		await import("../src/cli.js");
		expect(process.exitCode).toBe(1);
		expect(cli.imported).not.toHaveBeenCalled();
		expect(cli.run).not.toHaveBeenCalled();
		expect(console.error).toHaveBeenCalledWith(
			expect.stringContaining(INCIDENT_CAS_V2_LEGACY_SELECTOR_REJECTION_MARKER),
		);
	});

	test("preserves ordinary CLI dispatch", async () => {
		process.argv = [process.execPath, "/unused/cli.js", "--help"];
		await import("../src/cli.js");
		expect(cli.run).toHaveBeenCalledOnce();
		expect(process.exitCode).toBeUndefined();
		expect(console.error).not.toHaveBeenCalled();
	});
});
