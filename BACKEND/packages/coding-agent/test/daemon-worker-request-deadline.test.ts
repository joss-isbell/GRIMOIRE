import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, it } from "vitest";

it.runIf(process.platform !== "win32")(
	"bounds response deadlines under real socket backpressure without closing the worker",
	async () => {
		const { stdout } = await promisify(execFile)(
			process.execPath,
			["--import", "tsx", fileURLToPath(new URL("./fixtures/daemon-worker-request-deadline.ts", import.meta.url))],
			{ timeout: 15_000 },
		);
		const result = JSON.parse(stdout.trim().split("\n").at(-1)!);
		expect(result.settledBeforeResume).toBe(2);
		expect(result.unhandled).toEqual([]);
		expect(result.settled).toHaveLength(2);
		for (const item of result.settled) {
			expect(item.error).toContain("Timed out waiting for daemon worker response");
			expect(item.elapsed).toBeLessThan(450);
		}
		expect(result.closed).toBe(0);
		expect(result.fresh).toBe(true);
		expect(result.received).toEqual(["worker_1", "worker_2", "worker_3"]);
		expect(result.repeatErrors).toHaveLength(20);
		expect(result.repeatErrors.every((error: string) => error.includes("earlier list write is still blocked"))).toBe(
			true,
		);
	},
);

it.runIf(process.platform !== "win32")(
	"handles a late failed write after requests have already timed out",
	async () => {
		const { stdout } = await promisify(execFile)(
			process.execPath,
			[
				"--import",
				"tsx",
				fileURLToPath(new URL("./fixtures/daemon-worker-request-deadline.ts", import.meta.url)),
				"--disconnect",
			],
			{ timeout: 15_000 },
		);
		const result = JSON.parse(stdout.trim().split("\n").at(-1)!);
		expect(result.settledBeforeResume).toBe(2);
		expect(result.unhandled).toEqual([]);
		expect(result.closed).toBe(1);
		expect(result.received).toEqual([]);
	},
);
