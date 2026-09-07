import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const cutover = vi.hoisted(() => ({
	begin: vi.fn(),
	prove: vi.fn(),
	publish: vi.fn(),
	open: vi.fn(),
	close: vi.fn(),
	activationClose: vi.fn(),
}));
const service = vi.hoisted(() => ({ readTarget: vi.fn() }));

vi.mock("../src/modes/daemon/incident-recorder-cas-cutover.js", () => ({
	beginIncidentCasV2Cutover: cutover.begin,
	proveIncidentCasV1Quiescence: cutover.prove,
	publishIncidentCasV2: cutover.publish,
	openIncidentCasV2Activation: cutover.open,
	INCIDENT_CAS_V2_SERVICE_ENTRYPOINT: "dist/bundle/incident-recorder-service-v2.js",
	INCIDENT_CAS_V2_SYSTEMD_UNIT: "prime-agent-incident-recorder.service",
}));
vi.mock("../src/modes/daemon/incident-recorder-service-activation.js", () => ({
	readIncidentRecorderServiceTarget: service.readTarget,
}));

import {
	type IncidentRecorderBootstrapOptions,
	type IncidentRecorderBootstrapSystemctlResult,
	resolveIncidentRecorderBootstrapPaths,
	runIncidentRecorderBootstrap,
} from "../src/modes/daemon/incident-recorder-bootstrap.js";

const roots: string[] = [];

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "incident-recorder-bootstrap-"));
	const packageRoot = join(root, "installed-package");
	const bundleDir = join(packageRoot, "dist", "bundle");
	const agentDir = join(root, "agent");
	mkdirSync(bundleDir, { recursive: true });
	writeFileSync(join(bundleDir, "incident-recorder-bootstrap.js"), "export {};\n", { mode: 0o700 });
	writeFileSync(join(bundleDir, "incident-recorder-service-v2.js"), "export {};\n", { mode: 0o700 });
	roots.push(root);
	const target = {
		agentDir,
		packageRoot,
		launcher: {
			unitPath: join(root, "config", "systemd", "user", "prime-agent-incident-recorder.service"),
			unitContents: "[Service]\nExecStart=fixture\n",
			argv: [process.execPath, join(bundleDir, "incident-recorder-service-v2.js"), "--agent-dir", agentDir],
		},
	};
	service.readTarget.mockReturnValue(target);
	return { root, packageRoot, agentDir, bootstrapPath: join(bundleDir, "incident-recorder-bootstrap.js"), target };
}

function systemctl(
	statuses: readonly (number | null)[],
	callLog: string[][],
): NonNullable<IncidentRecorderBootstrapOptions["spawnSystemctl"]> {
	let index = 0;
	return (_command, args) => {
		callLog.push([...args]);
		const status = statuses[index++];
		return { status, error: undefined, stderr: "" } satisfies IncidentRecorderBootstrapSystemctlResult;
	};
}

function options(
	input: ReturnType<typeof fixture>,
	callLog: string[][],
	statuses: readonly (number | null)[] = [],
): IncidentRecorderBootstrapOptions {
	return {
		agentDir: input.agentDir,
		nodePath: process.execPath,
		bootstrapEntrypointPath: input.bootstrapPath,
		spawnSystemctl: systemctl(statuses, callLog),
	};
}

beforeEach(() => {
	vi.clearAllMocks();
	cutover.begin.mockReturnValue({ state: "v2" });
	cutover.prove.mockReturnValue({ state: "proved", witness: {} });
	cutover.publish.mockReturnValue({ state: "published" });
	cutover.open.mockReturnValue({ state: "active", activation: { close: cutover.activationClose } });
});

describe("incident recorder bootstrap runner", () => {
	it("binds the service target to the canonical service bundle beside its own bundle", () => {
		const input = fixture();
		const paths = resolveIncidentRecorderBootstrapPaths({
			nodePath: process.execPath,
			bootstrapEntrypointPath: input.bootstrapPath,
		});
		const calls: string[][] = [];
		runIncidentRecorderBootstrap(options(input, calls, [0]));
		expect(paths.serviceEntrypointPath).toBe(join(input.packageRoot, "dist/bundle/incident-recorder-service-v2.js"));
		expect(service.readTarget).toHaveBeenCalledWith({
			nodePath: paths.nodePath,
			entrypointPath: paths.serviceEntrypointPath,
			agentDir: input.agentDir,
		});
		expect(readdirSync(input.agentDir).sort()).toEqual(["incident-recorder", "incidents"]);
	});

	it("does not start an already healthy normal service", () => {
		const input = fixture();
		const calls: string[][] = [];
		runIncidentRecorderBootstrap(options(input, calls, [0]));
		expect(calls).toEqual([["--user", "is-active", "--quiet", "prime-agent-incident-recorder.service"]]);
	});

	it("queues only the normal service when v2 is active but the service is inactive", () => {
		const input = fixture();
		const calls: string[][] = [];
		runIncidentRecorderBootstrap(options(input, calls, [3, 0]));
		expect(calls).toEqual([
			["--user", "is-active", "--quiet", "prime-agent-incident-recorder.service"],
			["--user", "--no-block", "start", "prime-agent-incident-recorder.service"],
		]);
	});

	it("stops, proves, publishes, activates, closes, then queues the normal service", () => {
		const input = fixture();
		const calls: string[][] = [];
		const order: string[] = [];
		cutover.begin.mockReturnValue({ state: "draining", cutover: { close: cutover.close } });
		cutover.prove.mockImplementation(() => {
			order.push("prove");
			return { state: "proved", witness: {} };
		});
		cutover.publish.mockImplementation(() => {
			order.push("publish");
			return { state: "published" };
		});
		cutover.open.mockImplementation(() => {
			order.push("open");
			return { state: "active", activation: { close: cutover.activationClose } };
		});
		const base = options(input, calls, [0, 0]);
		const run: IncidentRecorderBootstrapOptions = {
			...base,
			spawnSystemctl: (command, args, spawnOptions) => {
				order.push(args[1] === "stop" ? "stop" : "start");
				return systemctl([0, 0], calls)(command, args, spawnOptions);
			},
		};
		runIncidentRecorderBootstrap(run);
		expect(order).toEqual(["stop", "prove", "publish", "open", "start"]);
		expect(cutover.close).toHaveBeenCalledOnce();
		expect(cutover.activationClose).toHaveBeenCalledOnce();
		expect(calls).toEqual([
			["--user", "stop", "prime-agent-incident-recorder.service"],
			["--user", "--no-block", "start", "prime-agent-incident-recorder.service"],
		]);
	});

	it.each(["begin", "stop", "prove", "publish", "activation"] as const)(
		"does not queue a start when %s fails",
		(boundary) => {
			const input = fixture();
			const calls: string[][] = [];
			if (boundary === "begin") cutover.begin.mockReturnValue({ state: "unavailable", reason: "target_mismatch" });
			if (boundary === "stop") calls.push(["stop-failure"]);
			if (boundary === "prove") cutover.prove.mockReturnValue({ state: "unavailable", reason: "claim_lost" });
			if (boundary === "publish") cutover.publish.mockReturnValue({ state: "unavailable", reason: "witness_stale" });
			if (boundary === "activation")
				cutover.open.mockReturnValue({ state: "unavailable", reason: "generation_changed" });
			cutover.begin.mockReturnValue(
				boundary === "begin"
					? { state: "unavailable", reason: "target_mismatch" }
					: { state: "draining", cutover: { close: cutover.close } },
			);
			const base = options(input, calls, [0]);
			const run: IncidentRecorderBootstrapOptions =
				boundary === "stop" ? { ...base, spawnSystemctl: systemctl([1], calls) } : base;
			expect(() => runIncidentRecorderBootstrap(run)).toThrow();
			expect(calls.some((args) => args.includes("--no-block"))).toBe(false);
			if (boundary !== "begin") expect(cutover.close).toHaveBeenCalledOnce();
		},
	);

	it("closes the cutover handle when proof throws", () => {
		const input = fixture();
		const calls: string[][] = [];
		cutover.begin.mockReturnValue({ state: "draining", cutover: { close: cutover.close } });
		cutover.prove.mockImplementation(() => {
			throw new Error("proof failure");
		});
		expect(() => runIncidentRecorderBootstrap(options(input, calls, [0]))).toThrow("proof failure");
		expect(cutover.close).toHaveBeenCalledOnce();
	});
});
