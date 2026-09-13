import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { kernelPythonEnvironment } from "../src/core/kernel/python-environment.js";
import { isolatedTestEnvironment } from "./isolated-environment.js";

describe("isolated test environments", () => {
	it("strips live agent overrides and credentials without changing the caller", () => {
		const base = {
			HOME: "/live",
			PRIME_AGENT_KERNEL_PYTHON: "/live/python",
			PRIME_AGENT_INTERNAL_DAEMON_SOCKET: "/live/socket",
			PRIME_AGENT_SESSION_DIR: "/live/sessions",
			PYTHONPATH: "/live/modules",
			ANTHROPIC_API_KEY: "secret",
			AWS_PROFILE: "live",
			SSH_AUTH_SOCK: "/live/ssh",
			PRIME_AGENT_CODING_AGENT_DIR: "/live/agent",
		};
		const original = { ...base };
		const sandbox = isolatedTestEnvironment(base);
		try {
			expect(base).toEqual(original);
			for (const name of [
				"PRIME_AGENT_KERNEL_PYTHON",
				"PRIME_AGENT_INTERNAL_DAEMON_SOCKET",
				"PYTHONPATH",
				"ANTHROPIC_API_KEY",
				"AWS_PROFILE",
				"SSH_AUTH_SOCK",
			])
				expect(sandbox.env[name]).toBeUndefined();
			for (const name of [
				"HOME",
				"PRIME_AGENT_SESSION_DIR",
				"PRIME_AGENT_CODING_AGENT_DIR",
				"PRIME_AGENT_KERNEL_VENV",
				"XDG_RUNTIME_DIR",
				"APPDATA",
				"LOCALAPPDATA",
				"UV_CACHE_DIR",
				"UV_PYTHON_INSTALL_DIR",
				"TMPDIR",
			])
				expect(sandbox.env[name]).toContain(sandbox.root);
		} finally {
			sandbox.cleanup();
		}
	});
	it("isolates a child before it imports application modules", () => {
		const sandbox = isolatedTestEnvironment({ ...process.env, PRIME_AGENT_KERNEL_PYTHON: "/live/python" });
		try {
			const result = spawnSync(
				process.execPath,
				[
					"-e",
					'console.log(JSON.stringify({home:require("node:os").homedir(),kernel:process.env.PRIME_AGENT_KERNEL_VENV,override:process.env.PRIME_AGENT_KERNEL_PYTHON}))',
				],
				{ env: sandbox.env, encoding: "utf8" },
			);
			expect(result.status).toBe(0);
			expect(JSON.parse(result.stdout)).toEqual({
				home: sandbox.env.HOME,
				kernel: sandbox.env.PRIME_AGENT_KERNEL_VENV,
			});
		} finally {
			sandbox.cleanup();
		}
	});
	it("allows child reuse but only the owner may delete the environment", () => {
		const owner = isolatedTestEnvironment({});
		const sentinel = join(owner.root, "keep");
		writeFileSync(sentinel, "owned");
		const child = isolatedTestEnvironment(owner.env);
		expect(child.root).toBe(owner.root);
		expect(child.owned).toBe(false);
		child.cleanup();
		expect(existsSync(sentinel)).toBe(true);
		owner.cleanup();
		expect(existsSync(owner.root)).toBe(false);
	});
	it("rejects a forged inherited root without deleting it", () => {
		const owner = isolatedTestEnvironment({});
		const child = isolatedTestEnvironment({ ...owner.env, GRIMOIRE_TEST_ENV_TOKEN: "wrong" });
		try {
			expect(child.root).not.toBe(owner.root);
			child.cleanup();
			expect(existsSync(owner.root)).toBe(true);
		} finally {
			child.cleanup();
			owner.cleanup();
		}
	});
	it("gives separate invocations distinct kernels and homes", () => {
		const first = isolatedTestEnvironment({});
		const second = isolatedTestEnvironment({});
		try {
			expect(first.root).not.toBe(second.root);
			expect(first.env.HOME).not.toBe(second.env.HOME);
			expect(first.env.PRIME_AGENT_KERNEL_VENV).not.toBe(second.env.PRIME_AGENT_KERNEL_VENV);
		} finally {
			first.cleanup();
			second.cleanup();
		}
	});
	it("also isolates direct Vitest invocation", () => {
		expect(process.env.GRIMOIRE_TEST_ENV_ROOT).toBeTruthy();
		expect(process.env.PRIME_AGENT_KERNEL_VENV).toContain(process.env.GRIMOIRE_TEST_ENV_ROOT);
		expect(process.env.HOME).toContain(process.env.GRIMOIRE_TEST_ENV_ROOT);
	});
	it("removes ambient Python injection from managed processes", () => {
		const base = { PYTHONHOME: "/bad/home", PYTHONPATH: "/bad/path", PATH: "/bin" };
		expect(kernelPythonEnvironment(base)).toEqual({
			PATH: "/bin",
			PYTHONUTF8: "1",
			PYTHONNOUSERSITE: "1",
			PYTHONSAFEPATH: "1",
		});
		expect(base.PYTHONPATH).toBe("/bad/path");
	});
});
