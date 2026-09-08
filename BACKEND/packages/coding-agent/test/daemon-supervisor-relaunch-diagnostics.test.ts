import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createCliSubprocessLaunchSpec } from "../src/cli/subprocess-launch.js";
import { DaemonSupervisor } from "../src/modes/daemon/daemon-supervisor.js";

const replacement = vi.hoisted(() => ({ unref: vi.fn() }));

vi.mock("node:child_process", async (importOriginal) => ({
	...(await importOriginal<Record<string, unknown>>()),
	spawn: vi.fn(() => replacement),
}));

vi.mock("../src/modes/daemon/incident-recorder.js", async (importOriginal) => ({
	...(await importOriginal<Record<string, unknown>>()),
	appendSupervisorDiagnosticEvent: vi.fn(),
	flushSupervisorDiagnosticCapture: vi.fn(async () => undefined),
}));

const directories: string[] = [];

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	vi.clearAllMocks();
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe.skipIf(process.platform !== "linux")("supervisor relaunch diagnostic routing", () => {
	it.each([
		{ name: "native default namespace", mode: "native", namespace: undefined, native: true },
		{ name: "native selected namespace", mode: "native", namespace: "isolated-relaunch", native: true },
		{ name: "native default journal", mode: "native", namespace: "", native: true },
		{ name: "non-native diagnostics", mode: undefined, namespace: undefined, native: false },
	])("preserves diagnostics and sanitized launch environment for $name", async ({ mode, namespace, native }) => {
		vi.stubEnv("PRIME_AGENT_DIAGNOSTICS", mode);
		vi.stubEnv("PRIME_AGENT_DIAGNOSTIC_JOURNAL_NAMESPACE", namespace);
		vi.stubEnv("PRIME_AGENT_DIAGNOSTIC_JOURNAL_IDENTIFIER", "relaunch-test");
		const inheritedRoles = [
			"PRIME_AGENT_INTERNAL_DAEMON_WORKER",
			"PRIME_AGENT_INTERNAL_DAEMON_WORKER_TOKEN",
			"PRIME_AGENT_INTERNAL_DAEMON_CATALOG",
			"PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_CHILD",
			"PRIME_INCIDENT_RECORDER_CAPTURE_FD",
		];
		for (const key of inheritedRoles) vi.stubEnv(key, "inherited-role");
		const directory = mkdtempSync(join(tmpdir(), "prime-relaunch-route-"));
		directories.push(directory);
		const socketPath = join(directory, "daemon.sock");
		// Bypass constructor watchers; exercise the real shutdown/relaunch branch without a process launch.
		const supervisor = Object.assign(Object.create(DaemonSupervisor.prototype), {
			shuttingDown: false,
			workers: new Map(),
			clients: new Set(),
			signalCleanupHandlers: [],
			catalog: { stop: vi.fn(async () => undefined) },
			cleanupSocket: vi.fn(),
			snapshotCacheRoot: join(directory, "cache"),
			defaultSessionConfig: { cwd: directory },
			socketPath,
			generation: "previous-generation",
		}) as { shutdown(exitCode: number, stopWorkers: boolean, relaunch: boolean): Promise<never> };
		vi.spyOn(process, "exit").mockImplementation((): never => {
			throw new Error("captured supervisor exit");
		});
		const launch = createCliSubprocessLaunchSpec(["--mode", "daemon", "--daemon-socket", socketPath]);

		await expect(supervisor.shutdown(0, false, true)).rejects.toThrow("captured supervisor exit");

		const effectiveNamespace = namespace ?? "grimoire";
		expect(spawn).toHaveBeenCalledOnce();
		const [command, args, options] = vi.mocked(spawn).mock.calls[0]!;
		expect(command).toBe(native ? "/usr/bin/systemd-cat" : launch.command);
		expect(args).toEqual(
			native
				? [
						...(effectiveNamespace ? [`--namespace=${effectiveNamespace}`] : []),
						"--identifier=relaunch-test",
						"--level-prefix=false",
						launch.command,
						...launch.args,
					]
				: launch.args,
		);
		expect(options?.cwd).toBe(directory);
		expect(options?.detached).toBe(true);
		expect(options?.stdio).toBe("ignore");
		const environment = options?.env;
		expect(environment).toBeDefined();
		expect(environment?.PRIME_AGENT_DIAGNOSTICS).toBe(mode);
		for (const key of inheritedRoles) {
			expect(environment?.[key]).toBeUndefined();
			expect(process.env[key]).toBe("inherited-role");
		}
		expect(replacement.unref).toHaveBeenCalledOnce();
		expect(process.exit).toHaveBeenCalledWith(0);
	});
});
