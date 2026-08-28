import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { KernelManager } from "../src/core/kernel/index.js";
import { INCIDENT_RECORDER_RUN_DIR_ENV } from "../src/modes/daemon/incident-recorder-env.js";
import {
	configureIncidentCaptureEmitter,
	stopIncidentCaptureEmitter,
} from "../src/modes/daemon/incident-recorder-writer.js";

const runtimePython = resolve("../../prime-agent-runtime/.venv/bin/python");
const fallbackPython = join(homedir(), ".prime", "agent", "kernel-venv", "bin", "python");

function resolveKernelPython(): string | null {
	for (const python of [process.env.PRIME_AGENT_KERNEL_PYTHON, runtimePython, fallbackPython]) {
		if (!python || !existsSync(python)) continue;
		const check = spawnSync(python, ["-c", "import ipykernel, mcp, rlm"], { encoding: "utf8" });
		if (check.status === 0) return python;
	}
	return null;
}

const python = resolveKernelPython();
const describeIfKernel = python ? describe : describe.skip;

const MCP_SERVER = `import asyncio, json, os, sys
from pathlib import Path
Path(sys.argv[1]).write_text(str(os.getpid()))
async def main():
    while line := await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline):
        request = json.loads(line)
        if request.get("id") is None:
            continue
        if request["method"] == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "shutdown-fixture", "version": "1"}}
        elif request["method"] == "tools/list":
            result = {"tools": [{"name": "fixture.echo", "description": "echo", "inputSchema": {"type": "object"}}]}
        else:
            result = {"content": [{"type": "text", "text": "ok"}]}
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
asyncio.run(main())
`;

function pidExists(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

async function waitForExit(pid: number, timeoutMs: number): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (!pidExists(pid)) return true;
		await new Promise((resolveWait) => globalThis.setTimeout(resolveWait, 25));
	}
	return !pidExists(pid);
}

async function captureKernelTransitions(operation: () => Promise<void>): Promise<Array<Record<string, unknown>>> {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-kernel-context-"));
	const originalRunDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
	try {
		mkdirSync(root, { recursive: true, mode: 0o700 });
		process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = root;
		expect(configureIncidentCaptureEmitter()).toBe(true);
		await operation();
		await stopIncidentCaptureEmitter();
		const path = join(root, "supervisor-timeline.jsonl");
		return readFileSync(path, "utf8")
			.split("\n")
			.filter(Boolean)
			.map((line) => JSON.parse(line) as Record<string, unknown>)
			.filter((event) => event.type === "kernel_shutdown_transition");
	} finally {
		await stopIncidentCaptureEmitter();
		if (originalRunDir === undefined) delete process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
		else process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = originalRunDir;
		rmSync(root, { recursive: true, force: true });
	}
}

describe("kernel Agent context lineage", () => {
	it("keeps stable session context while tool ownership stays async-local and bounded", async () => {
		const manager = new KernelManager({ sessionId: "agent-session", activeSessionId: "active-session" });
		let releaseFirst: () => void = () => {};
		let releaseSecond: () => void = () => {};
		const firstGate = new Promise<void>((resolveGate) => {
			releaseFirst = resolveGate;
		});
		const secondGate = new Promise<void>((resolveGate) => {
			releaseSecond = resolveGate;
		});

		const transitions = await captureKernelTransitions(async () => {
			const first = manager.withToolCallContext("tool-first", async () => {
				await firstGate;
				await manager.kill();
			});
			const second = manager.withToolCallContext("tool-second", async () => {
				await secondGate;
				await manager.kill();
			});
			releaseSecond();
			await second;
			releaseFirst();
			await first;

			await manager.withToolCallContext("tool-success", async () => {});
			await expect(
				manager.withToolCallContext("tool-error", async () => {
					throw new Error("fixture failure");
				}),
			).rejects.toThrow("fixture failure");
			await manager.kill();
		});

		expect(transitions.map((event) => event.toolCallId)).toEqual(["tool-second", "tool-first", "unavailable"]);
		for (const event of transitions) {
			expect(event).toMatchObject({ sessionId: "agent-session", activeSessionId: "active-session" });
		}
	});

	it("marks absent, invalid, and detached-later context unavailable", async () => {
		const manager = new KernelManager({
			sessionId: "not valid session",
			activeSessionId: "a".repeat(257),
		});
		let releaseDetached: () => void = () => {};
		const detachedGate = new Promise<void>((resolveGate) => {
			releaseDetached = resolveGate;
		});
		let detached: Promise<void> | undefined;

		const transitions = await captureKernelTransitions(async () => {
			await manager.withToolCallContext("tool-owned", async () => {
				detached = (async () => {
					await detachedGate;
					await manager.kill();
				})();
			});
			releaseDetached();
			await detached;
			await manager.withToolCallContext("not valid tool", () => manager.kill());
		});

		expect(transitions).toHaveLength(2);
		expect(transitions[0]?.toolCallId).toBe("unavailable");
		for (const event of transitions) {
			expect(event).toMatchObject({
				sessionId: "unavailable",
				activeSessionId: "unavailable",
				toolCallId: "unavailable",
			});
		}
	});
});

describeIfKernel("real IPython MCP shutdown", { tags: ["kernel-heavy"] }, () => {
	let dir = "";
	let fixture = "";
	let pidFile = "";

	beforeAll(() => {
		dir = mkdtempSync(join(tmpdir(), "prime-agent-mcp-shutdown-"));
		fixture = join(dir, "stdio_server.py");
		pidFile = join(dir, "stdio.pid");
		writeFileSync(fixture, MCP_SERVER);
	});

	afterAll(() => {
		if (dir) rmSync(dir, { recursive: true, force: true });
	});

	it("closes a stdio MCP child on control-channel shutdown without an AnyIO cross-task error", async () => {
		let manager: KernelManager | undefined = new KernelManager({
			python: python as string,
			cwd: resolve("../../prime-agent-runtime"),
			hostHandlers: {
				"mcp.config": async () => ({
					type: "stdio",
					command: python as string,
					args: [fixture, pidFile],
				}),
			},
		});
		try {
			const opened = await manager.execute(
				"import rlm.mcp as mcp; mcp.install_shutdown_hook(); tools = await mcp.list_tools('fixture'); [t['name'] for t in tools]",
			);
			expect(opened.status, opened.stderr || opened.error?.traceback.join("\n")).toBe("ok");
			expect(opened.result).toContain("fixture.echo");
			const childPid = Number(await import("node:fs/promises").then(({ readFile }) => readFile(pidFile, "utf8")));
			expect(pidExists(childPid)).toBe(true);

			await manager.shutdown();
			expect(await waitForExit(childPid, 2_000)).toBe(true);
			manager = undefined;
		} finally {
			await manager?.kill();
		}
	});
});
