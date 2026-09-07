import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const directories: string[] = [];

afterEach(() => {
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("incident recorder bootstrap entrypoint", () => {
	const invalidArguments = [[], ["--help"], ["--agent-dir"], ["--agent-dir", "relative"], ["--agent-dir", "/"]];
	it.each(invalidArguments.map((args) => ({ args })))(
		"rejects invalid arguments before loading the runner: %j",
		({ args }) => {
			const directory = mkdtempSync(join(tmpdir(), "incident-recorder-bootstrap-entrypoint-"));
			directories.push(directory);
			const result = spawnSync(
				process.execPath,
				[
					"--import",
					import.meta.resolve("tsx"),
					fileURLToPath(new URL("../src/incident-recorder-bootstrap.ts", import.meta.url)),
					...args,
				],
				{ cwd: directory, encoding: "utf8", timeout: 10_000, maxBuffer: 64 * 1024 },
			);
			expect(result.error).toBeUndefined();
			expect(result.status).toBe(1);
			expect(result.stderr).toContain("requires exactly --agent-dir");
			expect(readdirSync(directory)).toEqual([]);
		},
	);
});
