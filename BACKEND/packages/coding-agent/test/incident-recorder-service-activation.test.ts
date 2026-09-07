import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const admission = vi.hoisted(() => ({ open: vi.fn() }));
vi.mock("../src/modes/daemon/incident-recorder-cas-cutover.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/modes/daemon/incident-recorder-cas-cutover.js")>()),
	openIncidentCasV2Activation: admission.open,
}));

import {
	openIncidentRecorderServiceActivation,
	readIncidentRecorderServiceTarget,
} from "../src/modes/daemon/incident-recorder-service-activation.js";

const directories: string[] = [];
afterEach(() => {
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
	vi.resetAllMocks();
});
function fixture() {
	const directory = mkdtempSync(join(tmpdir(), "recorder-service-activation-"));
	directories.push(directory);
	const packageRoot = join(directory, "installed package");
	const entrypointPath = join(packageRoot, "dist/bundle/incident-recorder-service-v2.js");
	const configHomeDir = join(directory, "config");
	const unitPath = join(configHomeDir, "systemd/user/prime-agent-incident-recorder.service");
	mkdirSync(dirname(entrypointPath), { recursive: true });
	mkdirSync(dirname(unitPath), { recursive: true });
	writeFileSync(entrypointPath, "export {};\n");
	writeFileSync(unitPath, "[Service]\nExecStart=fixture\n", { mode: 0o600 });
	const options = { nodePath: process.execPath, entrypointPath, agentDir: join(directory, "agent"), configHomeDir };
	return { directory, packageRoot, unitPath, options };
}
describe("dedicated recorder activation wiring", () => {
	it("derives only the fixed v2 installed target and exact four-argument launcher", () => {
		const input = fixture();
		expect(readIncidentRecorderServiceTarget(input.options)).toEqual({
			agentDir: input.options.agentDir,
			packageRoot: input.packageRoot,
			launcher: {
				unitPath: input.unitPath,
				unitContents: "[Service]\nExecStart=fixture\n",
				argv: [realpathSync(process.execPath), input.options.entrypointPath, "--agent-dir", input.options.agentDir],
			},
		});
	});
	it("rejects an ordinary CLI before opening activation", () => {
		const input = fixture();
		const legacy = join(input.packageRoot, "dist/bundle/cli.js");
		writeFileSync(legacy, "export {};\n");
		expect(() => readIncidentRecorderServiceTarget({ ...input.options, entrypointPath: legacy })).toThrow(
			/dedicated/,
		);
		expect(admission.open).not.toHaveBeenCalled();
	});
	it.each(["symlink", "oversized", "empty"])("rejects a %s installed unit", (kind) => {
		const input = fixture();
		if (kind === "symlink") {
			rmSync(input.unitPath);
			symlinkSync(input.options.entrypointPath, input.unitPath);
		} else writeFileSync(input.unitPath, kind === "empty" ? "" : "x".repeat(65537));
		expect(() => readIncidentRecorderServiceTarget(input.options)).toThrow();
	});
	it("does not manufacture admission when cutover is unavailable", () => {
		const input = fixture();
		admission.open.mockReturnValue({ state: "unavailable", reason: "generation_changed" });
		expect(() => openIncidentRecorderServiceActivation(readIncidentRecorderServiceTarget(input.options))).toThrow(
			/generation_changed/,
		);
	});
	it("binds each revalidation and close to the actual retained activation", () => {
		const input = fixture();
		let closed = false;
		const revalidate = vi.fn(() =>
			closed ? { state: "invalid", reason: "generation_changed" } : { state: "valid" },
		);
		const close = vi.fn(() => {
			closed = true;
		});
		admission.open.mockReturnValue({
			state: "active",
			activation: { activationGenerationDigest: "a".repeat(64), revalidate, close },
		});
		const handle = openIncidentRecorderServiceActivation(readIncidentRecorderServiceTarget(input.options));
		expect(Object.isFrozen(handle.contract)).toBe(true);
		expect(handle.contract.activationGenerationDigest).toBe("a".repeat(64));
		expect(handle.contract.revalidateActivation()).toEqual({ state: "valid" });
		expect(handle.contract.acquireCas(undefined as never, "namespace")).toEqual({
			state: "unavailable",
			reason: "namespace_changed",
		});
		handle.close();
		expect(close).toHaveBeenCalledOnce();
		expect(handle.contract.revalidateActivation()).toEqual({ state: "invalid", reason: "generation_changed" });
	});
});
