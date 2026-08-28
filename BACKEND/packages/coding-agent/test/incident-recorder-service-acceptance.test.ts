import { type ChildProcess, spawn } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	installIncidentRecorderSystemdService,
	renderIncidentRecorderSystemdUnit,
} from "../src/modes/daemon/incident-recorder.js";
import { INCIDENT_RECORDER_SERVICE_ENV } from "../src/modes/daemon/incident-recorder-env.js";

const roots: string[] = [];
interface TrackedServiceChild {
	child: ChildProcess;
	pid?: number;
	processStartId?: string;
	exited: Promise<void>;
}
interface OwnedService extends TrackedServiceChild {
	pid: number;
	processStartId: string;
}
const ownedServices = new Set<TrackedServiceChild>();
let service: OwnedService | undefined;

function privateRoot(): string {
	const root = mkdtempSync(join(tmpdir(), "pa-causal-service-"));
	roots.push(root);
	return root;
}

async function waitFor(predicate: () => boolean, attempts: number, delayMs: number): Promise<boolean> {
	for (let attempt = 0; attempt < attempts; attempt += 1) {
		if (predicate()) return true;
		await new Promise((resolveDelay) => setTimeout(resolveDelay, delayMs));
	}
	return false;
}

async function stopOwnedService(owned: TrackedServiceChild | undefined = service): Promise<void> {
	if (!owned) return;
	const exitWithin = async (milliseconds: number): Promise<boolean> =>
		Promise.race([
			owned.exited.then(() => true),
			new Promise<boolean>((resolveDelay) => setTimeout(() => resolveDelay(false), milliseconds)),
		]);
	const identityMatches = (): boolean =>
		typeof owned.pid === "number" &&
		typeof owned.processStartId === "string" &&
		getProcessStartId(owned.pid) === owned.processStartId;
	const childIsLive = (): boolean => owned.child.exitCode === null && owned.child.signalCode === null;
	if (childIsLive() && (owned.processStartId === undefined || identityMatches())) owned.child.kill("SIGTERM");
	let settled = await exitWithin(1_000);
	if (!settled && childIsLive() && (owned.processStartId === undefined || identityMatches())) {
		owned.child.kill("SIGKILL");
		settled = await exitWithin(1_000);
	}
	if (!settled || childIsLive() || identityMatches()) {
		throw new Error(`Private causal service did not exit: ${owned.pid ?? "unassigned"}`);
	}
	ownedServices.delete(owned);
	if (service === owned) service = undefined;
}

afterEach(async () => {
	for (const owned of [...ownedServices]) await stopOwnedService(owned);
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("isolated automatic causal recorder service", () => {
	it("enables the private unit, starts the real service, inspects once, and stops its exact identity", async () => {
		const root = privateRoot();
		const configHome = join(root, "config");
		const agentDir = join(root, "agent");
		const fakeState = join(root, "fake-manager");
		const wantsDir = join(fakeState, "default.target.wants");
		mkdirSync(wantsDir, { recursive: true, mode: 0o700 });
		const runDir = join(agentDir, "incident-recorder", "runs", "acceptance-run");
		mkdirSync(runDir, { recursive: true, mode: 0o700 });
		const machineId = readFileSync("/etc/machine-id", "utf8").trim();
		const bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
		const absentPid = Number(readFileSync("/proc/sys/kernel/pid_max", "utf8").trim()) + 1;
		const observed = { wallTime: new Date().toISOString(), monotonicNs: process.hrtime.bigint().toString() };
		writeFileSync(join(runDir, "launch.json"), `${JSON.stringify({ socketPath: join(root, "absent.sock") })}\n`, {
			mode: 0o600,
		});
		writeFileSync(
			join(runDir, "process.json"),
			`${JSON.stringify({ machineId, bootId, pid: absentPid, processStartId: "1" })}\n`,
			{ mode: 0o600 },
		);
		writeFileSync(
			join(runDir, "timeline.jsonl"),
			`${JSON.stringify({
				type: "supervisor_exit",
				...observed,
				pid: absentPid,
				occurrenceId: "ab8bbfce-a9bf-44e4-8fbf-611c78ecb1d1",
				code: 0,
				signal: null,
			})}\n`,
			{ mode: 0o600 },
		);
		writeFileSync(
			join(runDir, ".retention-terminal.json"),
			`${JSON.stringify({ completed: observed, exitCode: 0, exitSignal: null })}\n`,
			{ mode: 0o600 },
		);

		const nodePath = process.execPath;
		const entrypointPath = resolve("dist/bundle/cli.js");
		const fakeSystemctl = join(root, "fake-systemctl");
		const calls: string[][] = [];
		let installedUnitPath: string | undefined;
		const result = installIncidentRecorderSystemdService({
			nodePath,
			entrypointPath,
			agentDir,
			configHomeDir: configHome,
			systemctlPath: fakeSystemctl,
			spawnSyncImpl: (command, args) => {
				calls.push([command, ...args]);
				const operation = args[1];
				if (operation === "show-environment") return { status: 0, stderr: "" };
				installedUnitPath = join(configHome, "systemd", "user", "prime-agent-incident-recorder.service");
				if (operation === "daemon-reload") {
					return { status: existsSync(installedUnitPath) ? 0 : 1, stderr: "" };
				}
				if (operation === "enable") {
					const link = join(wantsDir, "prime-agent-incident-recorder.service");
					rmSync(link, { force: true });
					symlinkSync(installedUnitPath, link);
					return { status: 0, stderr: "" };
				}
				if (operation === "restart" || operation === "start") {
					const child = spawn(nodePath, [entrypointPath, "--incident-recorder-service", "--agent-dir", agentDir], {
						cwd: resolve("."),
						detached: false,
						stdio: "ignore",
						env: {
							...process.env,
							HOME: root,
							XDG_CONFIG_HOME: configHome,
							[INCIDENT_RECORDER_SERVICE_ENV]: "1",
						},
					});
					const tracked: TrackedServiceChild = {
						child,
						pid: child.pid,
						exited:
							child.exitCode !== null
								? Promise.resolve()
								: new Promise<void>((resolveExit) => {
										const settled = () => resolveExit();
										child.once("exit", settled);
										child.once("error", settled);
									}),
					};
					ownedServices.add(tracked);
					const pid = tracked.pid;
					if (!pid) {
						if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
						return { status: 1, stderr: "service child has no pid" };
					}
					const firstStartId = getProcessStartId(pid);
					const secondStartId = getProcessStartId(pid);
					if (
						!firstStartId ||
						secondStartId !== firstStartId ||
						child.exitCode !== null ||
						child.signalCode !== null
					) {
						child.kill("SIGTERM");
						return { status: 1, stderr: "stable service identity unavailable" };
					}
					const accepted: OwnedService = { ...tracked, pid, processStartId: firstStartId };
					ownedServices.delete(tracked);
					ownedServices.add(accepted);
					service = accepted;
					return { status: 0, stderr: "" };
				}
				if (operation === "is-active") {
					return {
						status: service && getProcessStartId(service.pid) === service.processStartId ? 0 : 1,
						stderr: "",
					};
				}
				return { status: 1, stderr: `unexpected fake systemctl operation: ${operation}` };
			},
		});
		expect(result.status).toBe("installed");
		expect(installedUnitPath).toBeTypeOf("string");
		if (!installedUnitPath) throw new Error("private unit path unavailable");
		expect(statSync(installedUnitPath).mode & 0o777).toBe(0o600);
		const unit = readFileSync(installedUnitPath, "utf8");
		for (const directive of [
			"MemoryHigh=192M",
			"MemoryMax=256M",
			"MemorySwapMax=0",
			"CPUQuota=10%",
			"IOWeight=10",
			"IOSchedulingClass=idle",
			"KillMode=control-group",
			"Restart=on-failure",
			"[Install]",
			"WantedBy=default.target",
		])
			expect(unit).toContain(directive);
		expect(unit).toBe(renderIncidentRecorderSystemdUnit({ nodePath, entrypointPath, agentDir }));
		expect(calls.map((call) => call.slice(1))).toEqual([
			["--user", "show-environment"],
			["--user", "daemon-reload"],
			["--user", "enable", "prime-agent-incident-recorder.service"],
			["--user", "restart", "prime-agent-incident-recorder.service"],
			["--user", "is-active", "--quiet", "prime-agent-incident-recorder.service"],
		]);
		const enableLink = join(wantsDir, "prime-agent-incident-recorder.service");
		expect(realpathSync(enableLink)).toBe(realpathSync(installedUnitPath));
		expect(service).toBeDefined();
		if (!service) throw new Error("private service was not started");
		expect(getProcessStartId(service.pid)).toBe(service.processStartId);
		const cmdline = readFileSync(`/proc/${service.pid}/cmdline`, "utf8").split("\0").filter(Boolean);
		const expectedLaunchCmdline = [nodePath, entrypointPath, "--incident-recorder-service", "--agent-dir", agentDir];
		const launchedWithServiceArgs =
			cmdline.length === expectedLaunchCmdline.length &&
			cmdline.every((arg, index) => arg === expectedLaunchCmdline[index]);
		const titleRewritten = cmdline.length === 1 && cmdline[0] === "pi";
		expect(launchedWithServiceArgs || titleRewritten).toBe(true);
		const completionPath = join(runDir, ".service-finalization-complete");
		expect(await waitFor(() => existsSync(completionPath), 40, 50)).toBe(true);
		expect(JSON.parse(readFileSync(completionPath, "utf8"))).toMatchObject({ classification: "normal" });
		const servicePid = service.pid;
		await stopOwnedService();
		expect(getProcessStartId(servicePid)).toBeUndefined();
	}, 10_000);
});
