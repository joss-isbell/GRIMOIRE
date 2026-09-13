import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { describe, expect, it } from "vitest";
import { ensureKernelPython, getKernelVenvDir } from "../src/core/kernel/bootstrap.js";
import { ReplKernelManager } from "../src/core/kernel/index.js";
import { kernelPythonEnvironment } from "../src/core/kernel/python-environment.js";

function fixturePath(path: string, root: string): string {
	const child = relative(root, path);
	if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) {
		throw new Error(`Repair fixture must remain inside its disposable environment: ${path}`);
	}
	return path;
}

describe("managed kernel repair with real packages", { tags: ["kernel-heavy"] }, () => {
	it.each(["dill", "rlm.repl"])(
		"repairs missing %s files on the same manager's restart",
		async (moduleName) => {
			const root = process.env.GRIMOIRE_TEST_ENV_ROOT;
			if (!root) throw new Error("Run this test through test/run-isolated.ts --bootstrap");
			const venv = fixturePath(getKernelVenvDir(), root);
			const python = await ensureKernelPython();
			fixturePath(python, venv);
			const locate = spawnSync(python, ["-c", `import ${moduleName}; print(${moduleName}.__file__)`], {
				encoding: "utf8",
				env: kernelPythonEnvironment(),
			});
			expect(locate.status, locate.stderr).toBe(0);
			const moduleFile = fixturePath(locate.stdout.trim(), venv);
			const target = moduleName === "dill" ? dirname(moduleFile) : moduleFile;
			const backup = `${target}.repair-fixture`;
			const sentinel = join(venv, "repair-test-sentinel");
			writeFileSync(sentinel, "preserve this environment");
			const inode = statSync(python).ino;
			const manager = new ReplKernelManager({ cwd: root });
			let moved = false;
			try {
				await manager.start();
				expect((await manager.execute("print(6 * 7)")).stdout.trim()).toBe("42");
				await manager.shutdown({ snapshot: false });
				// Leave package metadata installed, as happens with an incomplete environment.
				renameSync(target, backup);
				moved = true;
				await manager.restart();
				const result = await manager.execute("print(6 * 7)");
				expect(result.status).toBe("ok");
				expect(result.stdout.trim()).toBe("42");
				expect(existsSync(target)).toBe(true);
				expect(readFileSync(sentinel, "utf8")).toBe("preserve this environment");
				expect(statSync(python).ino).toBe(inode);
			} finally {
				await manager.shutdown({ snapshot: false });
				if (moved && !existsSync(target)) renameSync(backup, target);
				else if (moved) rmSync(backup, { recursive: true, force: true });
				rmSync(sentinel, { force: true });
			}
		},
		120_000,
	);
});
