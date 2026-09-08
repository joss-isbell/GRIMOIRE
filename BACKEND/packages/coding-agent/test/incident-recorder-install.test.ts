import { execFileSync, spawnSync as spawnSyncProcess } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const cutover = vi.hoisted(() => ({
	begin: vi.fn(),
	prove: vi.fn(),
	publish: vi.fn(),
	close: vi.fn(),
	open: vi.fn(),
	activationClose: vi.fn(),
}));
vi.mock("../src/modes/daemon/incident-recorder-cas-cutover.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/modes/daemon/incident-recorder-cas-cutover.js")>()),
	beginIncidentCasV2Cutover: cutover.begin,
	proveIncidentCasV1Quiescence: cutover.prove,
	publishIncidentCasV2: cutover.publish,
	openIncidentCasV2Activation: cutover.open,
}));

import {
	deriveIncidentRecorderBootstrapEntrypointPath,
	INCIDENT_RECORDER_BOOTSTRAP_ENTRYPOINT,
	INCIDENT_RECORDER_BOOTSTRAP_SYSTEMD_UNIT,
	INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT,
	installIncidentRecorderSystemdService,
	renderIncidentRecorderBootstrapSystemdTimer,
	renderIncidentRecorderBootstrapSystemdUnit,
	renderIncidentRecorderJournaldNamespaceConfig,
	renderIncidentRecorderSystemdUnit,
} from "../src/modes/daemon/incident-recorder.js";
import { INCIDENT_CAS_V2_SYSTEMD_UNIT } from "../src/modes/daemon/incident-recorder-cas-cutover.js";

const roots: string[] = [];

beforeEach(() => {
	vi.clearAllMocks();
	cutover.begin.mockReturnValue({ state: "draining", cutover: { close: cutover.close } });
	cutover.prove.mockReturnValue({ state: "proved", witness: {} });
	cutover.publish.mockReturnValue({ state: "published" });
	cutover.open.mockReturnValue({ state: "active", activation: { close: cutover.activationClose } });
});

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function tempHome(): string {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-recorder-install-"));
	roots.push(root);
	return root;
}

type InstallerFixtureBootstrap = "valid" | "missing" | "directory" | "outside-package";

function makeInstallerFixture(homeDir: string, bootstrap: InstallerFixtureBootstrap = "valid") {
	const packageRoot = join(homeDir, "fixture-package");
	const bundleDir = join(packageRoot, "dist", "bundle");
	const entrypointPath = join(bundleDir, "incident-recorder-service-v2.js");
	const bootstrapEntrypointPath = join(bundleDir, INCIDENT_RECORDER_BOOTSTRAP_ENTRYPOINT.split("/").pop() ?? "");
	mkdirSync(bundleDir, { recursive: true });
	writeFileSync(entrypointPath, "service fixture\n");
	if (bootstrap === "valid") writeFileSync(bootstrapEntrypointPath, "bootstrap fixture\n");
	if (bootstrap === "directory") mkdirSync(bootstrapEntrypointPath);
	if (bootstrap === "outside-package") {
		const outsideBootstrapPath = join(homeDir, "outside-package", "incident-recorder-bootstrap.js");
		mkdirSync(join(homeDir, "outside-package"), { recursive: true });
		writeFileSync(outsideBootstrapPath, "outside bootstrap fixture\n");
		symlinkSync(outsideBootstrapPath, bootstrapEntrypointPath);
	}
	return {
		nodePath: process.execPath,
		entrypointPath,
		bootstrapEntrypointPath,
		agentDir: join(homeDir, "agent"),
	};
}

describe("incident recorder systemd user service", () => {
	it("renders an exact bounded bootstrap service and retry timer", () => {
		const bootstrap = renderIncidentRecorderBootstrapSystemdUnit({
			nodePath: "/stable/node",
			bootstrapEntrypointPath: "/stable/dist/bundle/incident-recorder-bootstrap.js",
			agentDir: "/private/agent",
		});
		expect(bootstrap).toBe(
			"[Unit]\n" +
				"Description=GRIMOIRE incident recorder bootstrap and recovery\n" +
				"StartLimitIntervalSec=0\n\n" +
				"[Service]\n" +
				"Type=oneshot\n" +
				"WorkingDirectory=/\n" +
				'ExecStart="/stable/node" "/stable/dist/bundle/incident-recorder-bootstrap.js" "--agent-dir" "/private/agent"\n' +
				"TimeoutStartSec=30s\n",
		);
		expect(bootstrap).not.toMatch(/Restart|RemainAfterExit|StartLimitBurst/);
		expect(renderIncidentRecorderBootstrapSystemdTimer()).toBe(
			"[Unit]\n" +
				"Description=Retry GRIMOIRE incident recorder bootstrap\n\n" +
				"[Timer]\n" +
				"OnActiveSec=60s\n" +
				"OnUnitInactiveSec=60s\n" +
				"AccuracySec=1s\n" +
				`Unit=${INCIDENT_RECORDER_BOOTSTRAP_SYSTEMD_UNIT}\n\n` +
				"[Install]\n" +
				"WantedBy=timers.target\n",
		);
		expect(renderIncidentRecorderBootstrapSystemdTimer()).not.toMatch(/Persistent|RandomizedDelaySec|Restart/);
		expect(deriveIncidentRecorderBootstrapEntrypointPath("/stable/dist/bundle/incident-recorder-service-v2.js")).toBe(
			`/stable/${INCIDENT_RECORDER_BOOTSTRAP_ENTRYPOINT}`,
		);
		expect(() =>
			deriveIncidentRecorderBootstrapEntrypointPath("/stable/../dist/bundle/incident-recorder-service-v2.js"),
		).toThrow();
	});

	it("renders an absolute private recorder service without daemon ownership", () => {
		const unit = renderIncidentRecorderSystemdUnit({
			nodePath: "/stable/node",
			entrypointPath: "/stable/prime agent/dist/bundle/incident-recorder-service-v2.js",
			agentDir: "/private/agent",
		});
		expect(unit).toContain(
			'ExecStart="/stable/node" "/stable/prime agent/dist/bundle/incident-recorder-service-v2.js" "--agent-dir" "/private/agent"',
		);
		expect(unit).toContain("Type=notify");
		expect(unit).toContain("NotifyAccess=all");
		expect(unit).toContain("KillMode=mixed");
		expect(unit).toContain("KillSignal=SIGTERM");
		expect(unit).toContain("TimeoutStartSec=30s");
		expect(unit).toContain("TimeoutStopSec=15s");
		expect(unit).toContain("Restart=on-failure");
		expect(unit).toContain("RestartSec=30s");
		expect(unit).toContain("StartLimitIntervalSec=600s");
		expect(unit).toContain("StartLimitBurst=3");
		expect(unit).toContain("MemoryHigh=192M");
		expect(unit).toContain("MemoryMax=256M");
		expect(unit).toContain("MemorySwapMax=0");
		expect(unit).toContain("CPUQuota=25%");
		expect(unit).toContain("IOWeight=25");
		expect(unit).toContain("Nice=10");
		expect(unit).toContain("TasksMax=64");
		expect(unit).toContain("LimitNOFILE=4096");
		expect(unit).toContain("OOMPolicy=stop");
		expect(unit).toContain("UMask=0077");
		expect(unit).not.toContain('--mode" "daemon');
		expect(unit).not.toContain("--incident-recorder-service");
	});

	it.each([
		{ entrypointPath: "/stable/cli.js" },
		{ entrypointPath: "/stable/../dist/bundle/incident-recorder-service-v2.js" },
		{ nodePath: "/stable/$NODE" },
		{ nodePath: "/stable/%h/node" },
		{ agentDir: "/private/agent\nEnvironment=EXTRA=1" },
		{ agentDir: "/" },
	])("rejects ambiguous or legacy launcher paths: %j", (override) => {
		expect(() =>
			renderIncidentRecorderSystemdUnit({
				nodePath: "/stable/node",
				entrypointPath: "/stable/dist/bundle/incident-recorder-service-v2.js",
				agentDir: "/private/agent",
				...override,
			}),
		).toThrow();
	});

	it("renders a bounded persistent journal namespace with backpressure", () => {
		const config = renderIncidentRecorderJournaldNamespaceConfig();
		expect(config).toContain("Storage=persistent");
		expect(config).toContain("SystemMaxUse=2G");
		expect(config).toContain("SystemKeepFree=8G");
		expect(config).toContain("SystemMaxFileSize=64M");
		expect(config).toContain("MaxFileSec=1h");
		expect(config).toContain("MaxRetentionSec=3d");
		expect(config).toContain("RateLimitIntervalSec=30s");
		expect(config).toContain("RateLimitBurst=2000");
		expect(config).toContain("Seal=yes");
		expect(config).toContain("SyncIntervalSec=30s");
	});

	it("installs and activates idempotently with an isolated fake systemctl", () => {
		const homeDir = tempHome();
		const fixture = makeInstallerFixture(homeDir);
		const calls: Array<{ command: string; args: string[] }> = [];
		const privilegedFiles = new Map<string, string>();
		const fakeSystemctl = (command: string, args: readonly string[]) => {
			calls.push({ command, args: [...args] });
			return { status: 0, error: undefined, stderr: "" };
		};
		const options = {
			nodePath: fixture.nodePath,
			entrypointPath: fixture.entrypointPath,
			agentDir: fixture.agentDir,
			homeDir,
			platform: "linux" as const,
			spawnSyncImpl: fakeSystemctl,
			privilegedInstallFile: (path: string, contents: string) => {
				privilegedFiles.set(path, contents);
				return { status: 0 };
			},
			privilegedReadFile: (path: string) => privilegedFiles.get(path),
		};
		const first = installIncidentRecorderSystemdService(options);
		expect(first.status).toBe("installed");
		expect(cutover.prove).toHaveBeenCalledOnce();
		expect(cutover.publish).toHaveBeenCalledOnce();
		expect(cutover.close).toHaveBeenCalledOnce();
		expect(calls).toEqual([
			{ command: "sudo", args: ["-n", "systemctl", "daemon-reload"] },
			{ command: "sudo", args: ["-n", "systemctl", "enable", "--now", "systemd-journald@grimoire.socket"] },
			{ command: "sudo", args: ["-n", "systemctl", "restart", "systemd-journald@grimoire.service"] },
			{ command: "sudo", args: ["-n", "systemctl", "is-active", "--quiet", "systemd-journald@grimoire.service"] },
			{ command: "sudo", args: ["-n", "systemctl", "is-active", "--quiet", "systemd-journald@grimoire.socket"] },
			{ command: "systemctl", args: ["--user", "show-environment"] },
			{ command: "systemctl", args: ["--user", "daemon-reload"] },
			{ command: "systemctl", args: ["--user", "enable", "--now", INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT] },
			{ command: "systemctl", args: ["--user", "stop", "prime-agent-incident-recorder.service"] },
			{ command: "systemctl", args: ["--user", "enable", "prime-agent-incident-recorder.service"] },
			{ command: "systemctl", args: ["--user", "start", "prime-agent-incident-recorder.service"] },
			{ command: "systemctl", args: ["--user", "is-active", "--quiet", "prime-agent-incident-recorder.service"] },
		]);
		const unitPath = join(homeDir, ".config/systemd/user/prime-agent-incident-recorder.service");
		expect(statSync(unitPath).mode & 0o777).toBe(0o600);
		const firstContent = readFileSync(unitPath, "utf8");
		calls.length = 0;
		cutover.begin.mockReturnValue({ state: "v2" });
		const second = installIncidentRecorderSystemdService(options);
		expect(second.status).toBe("unchanged");
		expect(readFileSync(unitPath, "utf8")).toBe(firstContent);
		expect(calls).toEqual([
			{ command: "sudo", args: ["-n", "systemctl", "enable", "--now", "systemd-journald@grimoire.socket"] },
			{ command: "sudo", args: ["-n", "systemctl", "start", "systemd-journald@grimoire.service"] },
			{ command: "sudo", args: ["-n", "systemctl", "is-active", "--quiet", "systemd-journald@grimoire.service"] },
			{ command: "sudo", args: ["-n", "systemctl", "is-active", "--quiet", "systemd-journald@grimoire.socket"] },
			{ command: "systemctl", args: ["--user", "show-environment"] },
			{ command: "systemctl", args: ["--user", "daemon-reload"] },
			{ command: "systemctl", args: ["--user", "enable", "--now", INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT] },
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
			...makeInstallerFixture(homeDir),
			homeDir,
			platform: "linux",
			spawnSyncImpl: () => ({ status: 1, error: undefined, stderr: "no user bus" }),
		});
		expect(unavailable).toMatchObject({ status: "unavailable" });
		expect(existsSync(join(homeDir, ".config"))).toBe(false);
	});

	it.each([
		{ bootstrap: "missing" as const, description: "a missing bootstrap companion" },
		{ bootstrap: "directory" as const, description: "a bootstrap companion directory" },
		{ bootstrap: "outside-package" as const, description: "a bootstrap symlink outside the service package" },
	])("rejects $description before any installer mutation", ({ bootstrap }) => {
		const homeDir = tempHome();
		const fixture = makeInstallerFixture(homeDir, bootstrap);
		const calls: string[][] = [];
		const privilegedFiles = new Map<string, string>();
		const result = installIncidentRecorderSystemdService({
			nodePath: fixture.nodePath,
			entrypointPath: fixture.entrypointPath,
			agentDir: fixture.agentDir,
			homeDir,
			platform: "linux",
			spawnSyncImpl: (_command, args) => {
				calls.push([...args]);
				return { status: 0, error: undefined, stderr: "" };
			},
			privilegedInstallFile: (path, contents) => {
				privilegedFiles.set(path, contents);
				return { status: 0 };
			},
			privilegedReadFile: (path) => privilegedFiles.get(path),
		});
		const unitDir = join(homeDir, ".config/systemd/user");
		expect(result.status).toBe("failed");
		expect(result.message).toMatch(/bootstrap/i);
		expect(calls).toEqual([]);
		expect(privilegedFiles).toEqual(new Map());
		expect(existsSync(unitDir)).toBe(false);
		expect(existsSync(fixture.agentDir)).toBe(false);
		expect(cutover.begin).not.toHaveBeenCalled();
	});

	it("rejects an existing FIFO unit without blocking or replacing it", () => {
		const homeDir = tempHome();
		const fixture = makeInstallerFixture(homeDir);
		const unitPath = join(homeDir, ".config/systemd/user/prime-agent-incident-recorder.service");
		mkdirSync(join(homeDir, ".config/systemd/user"), { recursive: true });
		const fifo = spawnSyncProcess("mkfifo", [unitPath], { encoding: "utf8" });
		expect(fifo.status).toBe(0);

		const recorderModule = resolve(process.cwd(), "src/modes/daemon/incident-recorder.ts");
		const childSource = `
			import { installIncidentRecorderSystemdService } from ${JSON.stringify(pathToFileURL(recorderModule).href)};
			const files = new Map();
			const result = installIncidentRecorderSystemdService({
				nodePath: ${JSON.stringify(fixture.nodePath)},
				entrypointPath: ${JSON.stringify(fixture.entrypointPath)},
				agentDir: ${JSON.stringify(fixture.agentDir)},
				homeDir: ${JSON.stringify(homeDir)},
				platform: "linux",
				spawnSyncImpl: () => ({ status: 0, error: undefined, stderr: "" }),
				privilegedInstallFile: (path, contents) => { files.set(path, contents); return { status: 0 }; },
				privilegedReadFile: (path) => files.get(path),
			});
			console.log(JSON.stringify(result));
		`;
		const output = execFileSync(
			process.execPath,
			["--import", resolve(process.cwd(), "../../node_modules/tsx/dist/loader.mjs"), "--eval", childSource],
			{ cwd: process.cwd(), encoding: "utf8", timeout: 2_000 },
		);
		const result = JSON.parse(output) as { status: string; unitPath?: string; message?: string };
		expect(result).toMatchObject({ status: "failed", unitPath });
		expect(result.message).toContain("regular file");
		expect(statSync(unitPath).isFIFO()).toBe(true);
	});

	it("preflights the bootstrap timer before any privileged namespace or recorder mutation", () => {
		const homeDir = tempHome();
		const fixture = makeInstallerFixture(homeDir);
		const timerPath = join(homeDir, ".config/systemd/user/prime-agent-incident-recorder-bootstrap.timer");
		mkdirSync(join(homeDir, ".config/systemd/user"), { recursive: true });
		expect(spawnSyncProcess("mkfifo", [timerPath], { encoding: "utf8" }).status).toBe(0);
		const calls: string[][] = [];
		const privilegedFiles = new Map<string, string>();
		const result = installIncidentRecorderSystemdService({
			nodePath: fixture.nodePath,
			entrypointPath: fixture.entrypointPath,
			agentDir: fixture.agentDir,
			homeDir,
			platform: "linux",
			spawnSyncImpl: (_command, args) => {
				calls.push([...args]);
				return { status: 0, error: undefined, stderr: "" };
			},
			privilegedInstallFile: (path, contents) => {
				privilegedFiles.set(path, contents);
				return { status: 0 };
			},
			privilegedReadFile: (path) => privilegedFiles.get(path),
		});
		expect(result).toMatchObject({ status: "failed", unitPath: timerPath });
		expect(result.message).toContain("regular file");
		expect(calls).toEqual([]);
		expect(privilegedFiles).toEqual(new Map());
		expect(cutover.begin).not.toHaveBeenCalled();
	});

	it("arms the retry timer before a blocked CAS attempt", () => {
		const homeDir = tempHome();
		const fixture = makeInstallerFixture(homeDir);
		const sequence: string[] = [];
		const files = new Map<string, string>();
		cutover.begin.mockImplementation(() => {
			sequence.push("begin");
			return { state: "draining", cutover: { close: cutover.close } };
		});
		cutover.prove.mockReturnValue({ state: "unavailable", reason: "v1_processes_live" });
		const result = installIncidentRecorderSystemdService({
			nodePath: fixture.nodePath,
			entrypointPath: fixture.entrypointPath,
			agentDir: fixture.agentDir,
			homeDir,
			platform: "linux",
			spawnSyncImpl: (_command, args) => {
				if (args[0] === "--user") sequence.push(args.slice(1).join(" "));
				return { status: 0, error: undefined, stderr: "" };
			},
			privilegedInstallFile: (path, contents) => {
				files.set(path, contents);
				return { status: 0 };
			},
			privilegedReadFile: (path) => files.get(path),
		});
		expect(result).toMatchObject({ status: "unavailable" });
		const timerIndex = sequence.indexOf(`enable --now ${INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT}`);
		const beginIndex = sequence.indexOf("begin");
		expect(timerIndex).toBeGreaterThanOrEqual(0);
		expect(beginIndex).toBeGreaterThan(timerIndex);
		expect(sequence).not.toContain(`start ${INCIDENT_RECORDER_BOOTSTRAP_SYSTEMD_UNIT}`);
		expect(sequence).not.toContain(`enable ${INCIDENT_RECORDER_BOOTSTRAP_SYSTEMD_UNIT}`);
	});

	it("keeps the retry timer armed across a failed attempt and an idempotent retry", () => {
		const homeDir = tempHome();
		const fixture = makeInstallerFixture(homeDir);
		expect(INCIDENT_CAS_V2_SYSTEMD_UNIT).toBe("prime-agent-incident-recorder.service");
		const calls: string[][] = [];
		const files = new Map<string, string>();
		let attempts = 0;
		cutover.begin.mockImplementation(() => {
			attempts += 1;
			return attempts === 1 ? { state: "unavailable", reason: "target_mismatch" } : { state: "v2" };
		});
		const options = {
			nodePath: fixture.nodePath,
			entrypointPath: fixture.entrypointPath,
			agentDir: fixture.agentDir,
			homeDir,
			platform: "linux" as const,
			spawnSyncImpl: (_command: string, args: readonly string[]) => {
				calls.push([...args]);
				return { status: 0, error: undefined, stderr: "" };
			},
			privilegedInstallFile: (path: string, contents: string) => {
				files.set(path, contents);
				return { status: 0 };
			},
			privilegedReadFile: (path: string) => files.get(path),
		};
		const first = installIncidentRecorderSystemdService(options);
		expect(first).toMatchObject({ status: "unavailable" });
		const second = installIncidentRecorderSystemdService(options);
		expect(second.status).toBe("unchanged");
		expect(
			calls.filter(
				(args) =>
					args[0] === "--user" &&
					args[1] === "enable" &&
					args[2] === "--now" &&
					args[3] === INCIDENT_RECORDER_BOOTSTRAP_TIMER_UNIT,
			),
		).toHaveLength(2);
		expect(calls).not.toContainEqual(["--user", "start", "prime-agent-incident-recorder-bootstrap.service"]);
		expect(calls).toContainEqual(["--user", "enable", "prime-agent-incident-recorder.service"]);
		expect(calls).toContainEqual(["--user", "start", "prime-agent-incident-recorder.service"]);
	});

	it("bundles and postinstall-bind the bootstrap beside the v2 service", () => {
		const bundle = readFileSync(resolve(process.cwd(), "scripts/bundle.mjs"), "utf8");
		const postinstall = readFileSync(resolve(process.cwd(), "src/postinstall.ts"), "utf8");
		expect(bundle).toContain('join(packageDir, "dist", "incident-recorder-bootstrap.js")');
		expect(bundle).toContain('chmodSync(join(outdir, "incident-recorder-bootstrap.js"), 0o755)');
		expect(postinstall).toContain("INCIDENT_CAS_V2_SERVICE_ENTRYPOINT");
		expect(postinstall).toContain("join(dirname(distDir), INCIDENT_CAS_V2_SERVICE_ENTRYPOINT)");
	});

	it("does not activate when old writers prevent cutover, and preserves live Agents", () => {
		const homeDir = tempHome();
		const fixture = makeInstallerFixture(homeDir);
		const calls: string[][] = [];
		const files = new Map<string, string>();
		cutover.prove.mockReturnValue({ state: "unavailable", reason: "v1_processes_live", blockingPids: [4242] });
		const result = installIncidentRecorderSystemdService({
			nodePath: fixture.nodePath,
			entrypointPath: fixture.entrypointPath,
			agentDir: fixture.agentDir,
			homeDir,
			platform: "linux",
			spawnSyncImpl: (_command, args) => {
				calls.push([...args]);
				return { status: 0, error: undefined, stderr: "" };
			},
			privilegedInstallFile: (path, contents) => {
				files.set(path, contents);
				return { status: 0 };
			},
			privilegedReadFile: (path) => files.get(path),
		});
		expect(result).toMatchObject({ status: "unavailable" });
		expect(result.message).toContain("v1_processes_live");
		expect(cutover.publish).not.toHaveBeenCalled();
		expect(cutover.close).toHaveBeenCalledOnce();
		expect(
			calls.filter(
				(args) =>
					args[0] === "--user" &&
					args.includes("prime-agent-incident-recorder.service") &&
					["enable", "start", "restart", "kill"].includes(args[1]),
			),
		).toEqual([]);
	});

	it.each(["begin", "publish", "activation"])("does not enable or start after %s admission fails", (boundary) => {
		const homeDir = tempHome();
		const fixture = makeInstallerFixture(homeDir);
		const calls: string[][] = [];
		const files = new Map<string, string>();
		if (boundary === "begin") cutover.begin.mockReturnValue({ state: "unavailable", reason: "target_mismatch" });
		if (boundary === "publish") cutover.publish.mockReturnValue({ state: "unavailable", reason: "witness_stale" });
		if (boundary === "activation")
			cutover.open.mockReturnValue({ state: "unavailable", reason: "generation_changed" });
		const result = installIncidentRecorderSystemdService({
			nodePath: fixture.nodePath,
			entrypointPath: fixture.entrypointPath,
			agentDir: fixture.agentDir,
			homeDir,
			platform: "linux",
			spawnSyncImpl: (_command, args) => {
				calls.push([...args]);
				return { status: 0, error: undefined, stderr: "" };
			},
			privilegedInstallFile: (path, contents) => {
				files.set(path, contents);
				return { status: 0 };
			},
			privilegedReadFile: (path) => files.get(path),
		});
		expect(result).toMatchObject({ status: "unavailable" });
		expect(
			calls.filter(
				(args) =>
					args[0] === "--user" &&
					args.includes("prime-agent-incident-recorder.service") &&
					["enable", "start", "restart"].includes(args[1]),
			),
		).toEqual([]);
		expect(cutover.close).toHaveBeenCalledTimes(boundary === "begin" ? 0 : 1);
	});
});
