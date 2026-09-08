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

describe("dedicated recorder service entrypoint", () => {
	for (const args of [[], ["--incident-recorder-service"], ["--help"], ["--agent-dir", "/"]]) {
		it(`rejects non-service arguments before loading runtime state: ${JSON.stringify(args)}`, () => {
			const directory = mkdtempSync(join(tmpdir(), "recorder-entrypoint-"));
			directories.push(directory);
			const result = spawnSync(
				process.execPath,
				[
					"--import",
					import.meta.resolve("tsx"),
					fileURLToPath(new URL("../src/incident-recorder-service-v2.ts", import.meta.url)),
					...args,
				],
				{ cwd: directory, encoding: "utf8", timeout: 10_000, maxBuffer: 64 * 1024 },
			);
			expect(result.error).toBeUndefined();
			expect(result.status).toBe(1);
			expect(result.stderr).toContain("requires exactly --agent-dir");
			expect(readdirSync(directory)).toEqual([]);
		});
	}
});
