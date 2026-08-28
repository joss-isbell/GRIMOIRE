import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	installIncidentRecorderSystemdService,
	renderIncidentRecorderSystemdUnit,
} from "../src/modes/daemon/incident-recorder.js";

const roots: string[] = [];

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function tempHome(): string {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-recorder-install-"));
	roots.push(root);
	return root;
}

describe("incident recorder systemd user service", () => {
	it("renders an absolute private recorder service without daemon ownership", () => {
		const unit = renderIncidentRecorderSystemdUnit({
			nodePath: "/stable/node",
			entrypointPath: "/stable/prime agent/cli.js",
			agentDir: "/private/agent",
		});
		expect(unit).toContain(
			'ExecStart="/stable/node" "/stable/prime agent/cli.js" "--incident-recorder-service" "--agent-dir" "/private/agent"',
		);
		expect(unit).toContain("KillMode=control-group");
		expect(unit).toContain("MemoryHigh=192M");
		expect(unit).toContain("MemoryMax=256M");
		expect(unit).toContain("MemorySwapMax=0");
		expect(unit).toContain("IOSchedulingClass=idle");
		expect(unit).toContain("UMask=0077");
		expect(unit).not.toContain('--mode" "daemon');
		expect(unit).not.toContain("journal.grimoire");
		expect(unit).not.toContain("journalctl");
		expect(unit).not.toContain("systemd-cat");
	});

	it("installs and activates idempotently with an isolated fake systemctl", () => {
		const homeDir = tempHome();
		const calls: Array<{ command: string; args: string[] }> = [];
		const fakeSystemctl = (command: string, args: readonly string[]) => {
			calls.push({ command, args: [...args] });
			return { status: 0, error: undefined, stderr: "" };
		};
		const options = {
			nodePath: "/stable/node",
			entrypointPath: "/stable/cli.js",
			homeDir,
			platform: "linux" as const,
			spawnSyncImpl: fakeSystemctl,
			privilegedInstallFile: () => {
				throw new Error("automatic install must not request root");
			},
			privilegedReadFile: () => {
				throw new Error("automatic install must not inspect root-owned journald configuration");
			},
		};
		const first = installIncidentRecorderSystemdService(options);
		expect(first.status).toBe("installed");
		expect(calls).toEqual([
			{ command: "systemctl", args: ["--user", "show-environment"] },
			{ command: "systemctl", args: ["--user", "daemon-reload"] },
			{ command: "systemctl", args: ["--user", "enable", "prime-agent-incident-recorder.service"] },
			{ command: "systemctl", args: ["--user", "restart", "prime-agent-incident-recorder.service"] },
			{ command: "systemctl", args: ["--user", "is-active", "--quiet", "prime-agent-incident-recorder.service"] },
		]);
		const unitPath = join(homeDir, ".config/systemd/user/prime-agent-incident-recorder.service");
		expect(statSync(unitPath).mode & 0o777).toBe(0o600);
		const firstContent = readFileSync(unitPath, "utf8");
		calls.length = 0;
		const second = installIncidentRecorderSystemdService(options);
		expect(second.status).toBe("unchanged");
		expect(readFileSync(unitPath, "utf8")).toBe(firstContent);
		expect(calls).toEqual([
			{ command: "systemctl", args: ["--user", "show-environment"] },
			{ command: "systemctl", args: ["--user", "enable", "prime-agent-incident-recorder.service"] },
			{ command: "systemctl", args: ["--user", "start", "prime-agent-incident-recorder.service"] },
			{ command: "systemctl", args: ["--user", "is-active", "--quiet", "prime-agent-incident-recorder.service"] },
		]);
	});

	it("is explicit and non-destructive without Linux systemd", () => {
		const homeDir = tempHome();
		const unsupported = installIncidentRecorderSystemdService({
			nodePath: "/node",
			entrypointPath: "/cli.js",
			homeDir,
			platform: "darwin",
		});
		expect(unsupported.status).toBe("unsupported");
		expect(existsSync(join(homeDir, ".config"))).toBe(false);

		const unavailable = installIncidentRecorderSystemdService({
			nodePath: "/node",
			entrypointPath: "/cli.js",
			homeDir,
			platform: "linux",
			spawnSyncImpl: () => ({ status: 1, error: undefined, stderr: "no user bus" }),
		});
		expect(unavailable).toMatchObject({ status: "unavailable" });
		expect(existsSync(join(homeDir, ".config"))).toBe(false);
	});
});
