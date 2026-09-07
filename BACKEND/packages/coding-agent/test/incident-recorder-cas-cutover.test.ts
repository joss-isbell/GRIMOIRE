import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	readSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	symlinkSync,
	unlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return { ...actual, readSync: vi.fn(actual.readSync) };
});

vi.mock("node:child_process", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:child_process")>();
	return { ...actual, spawnSync: vi.fn(actual.spawnSync) };
});

const testRuntimeBridge = vi.hoisted(() => {
	let registrar: ((runtime: unknown) => unknown) | undefined;
	const symbol = Symbol.for("grimoire.incident-cas-v2.test-runtime-bridge.v1");
	const host = globalThis as unknown as Record<PropertyKey, unknown>;
	host[symbol] = (installed: (runtime: unknown) => unknown) => {
		registrar = installed;
	};
	return {
		register(runtime: unknown): unknown {
			if (!registrar) throw new Error("incident CAS v2 test runtime bridge was not installed");
			return registrar(runtime);
		},
	};
});

import {
	beginIncidentCasV2Cutover,
	INCIDENT_CAS_V2_CLI_ENTRYPOINT,
	INCIDENT_CAS_V2_LEGACY_SELECTOR_REJECTION_MARKER,
	INCIDENT_CAS_V2_SERVICE_ENTRYPOINT,
	INCIDENT_CAS_V2_SYSTEMD_UNIT,
	type IncidentCasV1QuiescenceWitness,
	type IncidentCasV2Cutover,
	type IncidentCasV2CutoverRuntime,
	type IncidentCasV2CutoverStep,
	type IncidentCasV2CutoverTarget,
	type IncidentCasV2LauncherObservation,
	type IncidentCasV2ObservedFile,
	type IncidentCasV2ObservedIdentity,
	type IncidentCasV2ObservedProcess,
	type IncidentCasV2ProcessIdentity,
	type IncidentCasV2TestRuntimeHandle,
	openIncidentCasV2Activation,
	proveIncidentCasV1Quiescence,
	publishIncidentCasV2,
	registerIncidentCasV2CleanupTestSynchronization,
} from "../src/modes/daemon/incident-recorder-cas-cutover.js";

function registerTestRuntime(runtime: IncidentCasV2CutoverRuntime): IncidentCasV2TestRuntimeHandle {
	return testRuntimeBridge.register(runtime) as IncidentCasV2TestRuntimeHandle;
}

const cleanupPaths: string[] = [];

afterEach(() => {
	vi.mocked(spawnSync).mockClear();
	for (const path of cleanupPaths.splice(0).reverse()) rmSync(path, { recursive: true, force: true });
});

it("bounds unavailable systemd inspection before admitting a cutover", () => {
	const f = fixture();
	vi.mocked(spawnSync).mockReturnValueOnce({
		pid: 0,
		output: [],
		stdout: "",
		stderr: "",
		status: null,
		signal: "SIGKILL",
		error: Object.assign(new Error("systemctl timed out"), { code: "ETIMEDOUT" }),
	});
	expect(beginIncidentCasV2Cutover(f.target)).toMatchObject({ state: "unavailable", reason: "launcher_unavailable" });
	expect(spawnSync).toHaveBeenCalledWith(
		"/usr/bin/systemctl",
		expect.any(Array),
		expect.objectContaining({
			timeout: 1_000,
			killSignal: "SIGKILL",
			maxBuffer: expect.any(Number),
		}),
	);
});

function sha256(value: string | Uint8Array): string {
	return createHash("sha256").update(value).digest("hex");
}

it("resumes the original target after retiring an abandoned upgrade claim", () => {
	const f = fixture();
	publish(f);
	const targetB = successorTarget(f);
	const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
	if (started.state !== "draining") throw new Error("expected upgrade");
	started.cutover.close();
	writeFileSync(f.unitPath, f.unitContents, { mode: 0o600 });
	cloneLauncher(f, { fragment: observedFile(f.unitPath) });
	const resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
	if (resumed.state === "draining") resumed.cutover.close();
	expect(resumed).toEqual({ state: "v2" });
});

it.each(["current", "stale", "live", "unknown"] as const)(
	"classifies an abandoned upgrade claim before resuming the original target for a %s owner",
	(disposition) => {
		const f = fixture();
		publish(f);
		const targetB = successorTarget(f);
		const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		if (started.state !== "draining") throw new Error("expected upgrade");
		started.cutover.close();

		const paths = artifactPaths(f.agentDir);
		const generationBefore = readFileSync(paths.generation);
		const claimBefore = readFileSync(paths.claim);
		writeFileSync(f.unitPath, f.unitContents, { mode: 0o600 });
		cloneLauncher(f, { fragment: observedFile(f.unitPath) });
		const retryOwner: IncidentCasV2ProcessIdentity = {
			...f.owner,
			pid: f.owner.pid + 4,
			startId: "606",
		};
		const retryRuntime: IncidentCasV2CutoverRuntime = {
			...f.runtime,
			readCurrentProcessIdentity: () =>
				disposition === "current"
					? { state: "present", identity: f.owner }
					: { state: "present", identity: retryOwner },
			readProcessIdentity: () =>
				disposition === "stale"
					? { state: "absent" }
					: disposition === "live"
						? { state: "present", identity: f.owner }
						: { state: "unavailable", code: "proc_unavailable" },
		};
		const result =
			disposition === "current"
				? beginIncidentCasV2Cutover(f.target, f.runtimeHandle)
				: beginIncidentCasV2Cutover(f.target, registerTestRuntime(retryRuntime));

		expect(readFileSync(paths.generation)).toEqual(generationBefore);
		if (disposition === "current" || disposition === "stale") {
			expect(result).toEqual({ state: "v2" });
			expect(existsSync(paths.claim)).toBe(false);
			expect(existsSync(paths.prepare)).toBe(false);
			const activation = openIncidentCasV2Activation(f.target, f.runtimeHandle);
			expect(activation).toMatchObject({ state: "active" });
			if (activation.state === "active") {
				expect(activation.activation.revalidate()).toEqual({ state: "valid" });
				activation.activation.close();
			}
		} else {
			expect(result).toEqual({
				state: "unavailable",
				reason: disposition === "live" ? "orchestration_in_progress" : "orchestration_owner_unknown",
			});
			expect(readFileSync(paths.claim)).toEqual(claimBefore);
			expect(existsSync(paths.prepare)).toBe(false);
		}
	},
);

it.each(["current", "stale"] as const)(
	"recovers the original target after an abandoned partial upgrade prepare for a %s owner",
	(disposition) => {
		const f = fixture();
		publish(f);
		const targetB = successorTarget(f, "fixture-successor-b-partial");
		const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		if (started.state !== "draining") throw new Error("expected upgrade cutover");
		const witness = prove(started.cutover);
		f.setStepFault("v2_scratch_partially_written");
		expect(publishIncidentCasV2(started.cutover, witness)).toEqual({
			state: "unavailable",
			reason: "io_error",
		});
		started.cutover.close();

		const paths = artifactPaths(f.agentDir);
		const generationBefore = readFileSync(paths.generation);
		const claimBefore = readFileSync(paths.claim);
		expect(existsSync(paths.prepare)).toBe(true);
		writeFileSync(f.unitPath, f.unitContents, { mode: 0o600 });
		cloneLauncher(f, { fragment: observedFile(f.unitPath) });
		const retryOwner: IncidentCasV2ProcessIdentity = {
			...f.owner,
			pid: f.owner.pid + 5,
			startId: "707",
		};
		const retryRuntime: IncidentCasV2CutoverRuntime = {
			...f.runtime,
			readCurrentProcessIdentity: () => ({
				state: "present",
				identity: disposition === "current" ? f.owner : retryOwner,
			}),
			readProcessIdentity: () =>
				disposition === "stale" ? { state: "absent" } : { state: "present", identity: f.owner },
		};
		const retryHandle = disposition === "current" ? f.runtimeHandle : registerTestRuntime(retryRuntime);

		expect(beginIncidentCasV2Cutover(f.target, retryHandle)).toEqual({
			state: "unavailable",
			reason: "orchestration_in_progress",
		});
		expect(readFileSync(paths.generation)).toEqual(generationBefore);
		expect(readFileSync(paths.claim)).toEqual(claimBefore);
		expect(existsSync(paths.prepare)).toBe(true);

		f.monotonicMs += 1_001;
		const resumed = beginIncidentCasV2Cutover(f.target, retryHandle);
		expect(readFileSync(paths.generation)).toEqual(generationBefore);
		expect(resumed).toEqual({ state: "v2" });
		expect(existsSync(paths.claim)).toBe(false);
		expect(existsSync(paths.prepare)).toBe(false);
		const activation = openIncidentCasV2Activation(f.target, retryHandle);
		expect(activation).toMatchObject({ state: "active" });
		if (activation.state === "active") {
			expect(activation.activation.revalidate()).toEqual({ state: "valid" });
			activation.activation.close();
		}
	},
);

function quote(value: string): string {
	return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function observedIdentity(path: string): IncidentCasV2ObservedIdentity {
	const stats = lstatSync(path, { bigint: true });
	return {
		path,
		dev: stats.dev.toString(),
		ino: stats.ino.toString(),
		uid: Number(stats.uid),
		gid: Number(stats.gid),
		mode: Number(stats.mode),
		nlink: Number(stats.nlink),
	};
}

function observedFile(path: string): IncidentCasV2ObservedFile {
	const bytes = readFileSync(path);
	return {
		...observedIdentity(path),
		size: bytes.length,
		sha256: sha256(bytes),
	};
}

function observedPopulation(processes: readonly IncidentCasV2ObservedProcess[]) {
	return {
		state: "observed" as const,
		processes,
		finalSameUidProcesses: processes.map((process) => ({ ...process, argv: [...process.argv] })),
	};
}

interface Fixture {
	base: string;
	agentDir: string;
	recorder: string;
	incidents: string;
	packageRoot: string;
	nodePath: string;
	entrypoint: string;
	cliEntrypoint: string;
	unitPath: string;
	unitContents: string;
	target: IncidentCasV2CutoverTarget;
	owner: IncidentCasV2ProcessIdentity;
	launcher: IncidentCasV2LauncherObservation;
	processes: IncidentCasV2ObservedProcess[];
	monotonicMs: number;
	runtime: IncidentCasV2CutoverRuntime;
	runtimeHandle: IncidentCasV2TestRuntimeHandle;
	setStepFault(step: IncidentCasV2CutoverStep | undefined): void;
	setStepObserver(observer: ((step: IncidentCasV2CutoverStep) => void) | undefined): void;
	setIdentityReader(reader: (pid: number) => ReturnType<IncidentCasV2CutoverRuntime["readProcessIdentity"]>): void;
}

function fixture(): Fixture {
	const base = mkdtempSync(join(tmpdir(), "grimoire-cas-cutover-"));
	cleanupPaths.push(base);
	const agentDir = join(base, "agent");
	const recorder = join(agentDir, "incident-recorder");
	const incidents = join(agentDir, "incidents");
	mkdirSync(agentDir, { mode: 0o700 });
	mkdirSync(recorder, { mode: 0o700 });
	mkdirSync(incidents, { mode: 0o700 });
	const packageRoot = join(base, "installed-coding-agent");
	const entrypoint = join(packageRoot, INCIDENT_CAS_V2_SERVICE_ENTRYPOINT);
	mkdirSync(dirname(entrypoint), { recursive: true, mode: 0o700 });
	writeFileSync(entrypoint, "export {};\n", { mode: 0o600 });
	const cliEntrypoint = join(packageRoot, INCIDENT_CAS_V2_CLI_ENTRYPOINT);
	writeFileSync(
		cliEntrypoint,
		`export const legacySelectorFence = "${INCIDENT_CAS_V2_LEGACY_SELECTOR_REJECTION_MARKER}";\n`,
		{ mode: 0o600 },
	);
	const nodePath = join(base, "node");
	writeFileSync(nodePath, "#!/bin/sh\n", { mode: 0o700 });
	const unitPath = join(base, INCIDENT_CAS_V2_SYSTEMD_UNIT);
	const argv = [nodePath, entrypoint, "--agent-dir", agentDir];
	const unitContents = `[Unit]\nDescription=fixture\n\n[Service]\nExecStart=${argv.map(quote).join(" ")}\n`;
	writeFileSync(unitPath, unitContents, { mode: 0o600 });
	const target: IncidentCasV2CutoverTarget = {
		agentDir,
		packageRoot,
		launcher: { unitPath, unitContents, argv },
	};
	const uid = process.getuid?.() ?? 1000;
	const gid = process.getgid?.() ?? 1000;
	const owner: IncidentCasV2ProcessIdentity = {
		machineId: "fixture-machine",
		bootId: "fixture-boot",
		pid: 42_424,
		startId: "101",
		uid,
		gid,
	};
	let launcher: IncidentCasV2LauncherObservation = {
		state: "observed",
		unitName: INCIDENT_CAS_V2_SYSTEMD_UNIT,
		loadState: "loaded",
		activeState: "inactive",
		subState: "dead",
		needDaemonReload: "no",
		mainPid: 0,
		execMainPid: 0,
		controlPid: 0,
		observationGeneration: "100",
		fragment: observedFile(unitPath),
		node: observedIdentity(argv[0] ?? ""),
		entrypoint: observedFile(entrypoint),
		managerExecStartArgv: argv,
	};
	const processes: IncidentCasV2ObservedProcess[] = [
		{
			pid: owner.pid,
			parentPid: 1,
			uid,
			startId: owner.startId,
			processState: "R",
			inspection: "complete",
			argv: [argv[0] ?? "", entrypoint],
			cwd: packageRoot,
			executable: argv[0] ?? null,
		},
	];
	let monotonicMs = 1_000;
	let fault: IncidentCasV2CutoverStep | undefined;
	let stepObserver: ((step: IncidentCasV2CutoverStep) => void) | undefined;
	let identityReader = (pid: number): ReturnType<IncidentCasV2CutoverRuntime["readProcessIdentity"]> =>
		pid === owner.pid ? { state: "present", identity: owner } : { state: "absent" };
	const runtime: IncidentCasV2CutoverRuntime = {
		kind: "incident_cas_v2_structured_test_runtime",
		readLauncher: () => launcher,
		readProcessPopulation: () => observedPopulation(processes),
		readCurrentProcessIdentity: () => ({ state: "present", identity: owner }),
		readProcessIdentity: (pid) => identityReader(pid),
		monotonicTimeMs: () => monotonicMs,
		onStep: (step) => {
			stepObserver?.(step);
			if (step === fault) {
				fault = undefined;
				throw new Error(`fault:${step}`);
			}
		},
	};
	const runtimeHandle = registerTestRuntime(runtime);
	const result: Fixture = {
		base,
		agentDir,
		recorder,
		incidents,
		packageRoot,
		nodePath,
		entrypoint,
		cliEntrypoint,
		unitPath,
		unitContents,
		target,
		owner,
		get launcher() {
			return launcher;
		},
		set launcher(value: IncidentCasV2LauncherObservation) {
			launcher = value;
		},
		processes,
		get monotonicMs() {
			return monotonicMs;
		},
		set monotonicMs(value: number) {
			monotonicMs = value;
		},
		runtime,
		runtimeHandle,
		setStepFault(step) {
			fault = step;
		},
		setStepObserver(observer) {
			stepObserver = observer;
		},
		setIdentityReader(reader) {
			identityReader = reader;
		},
	};
	return result;
}

function artifactPaths(agentDir: string): { generation: string; prepare: string; claim: string; baseName: string } {
	const canonical = realpathSync.native(agentDir);
	const baseName = `.grimoire-incident-cas-v2-${sha256(canonical).slice(0, 32)}`;
	const parent = dirname(canonical);
	return {
		baseName,
		generation: join(parent, `${baseName}.generation.json`),
		prepare: join(parent, `${baseName}.generation.prepare`),
		claim: join(parent, `${baseName}.generation.claim`),
	};
}

function begin(f: Fixture): IncidentCasV2Cutover {
	const result = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
	expect(result).toMatchObject({ state: "draining" });
	if (result.state !== "draining") throw new Error(`cutover did not begin: ${result.state}`);
	return result.cutover;
}

function prove(cutover: IncidentCasV2Cutover): IncidentCasV1QuiescenceWitness {
	const result = proveIncidentCasV1Quiescence(cutover);
	expect(result).toMatchObject({ state: "proved" });
	if (result.state !== "proved") throw new Error(`quiescence not proved: ${result.state}`);
	return result.witness;
}

function publish(f: Fixture): void {
	const cutover = begin(f);
	const witness = prove(cutover);
	expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "published" });
}

function cloneLauncher(
	f: Fixture,
	change: Partial<Extract<IncidentCasV2LauncherObservation, { state: "observed" }>>,
): void {
	if (f.launcher.state !== "observed") throw new Error("fixture launcher is unavailable");
	f.launcher = { ...f.launcher, ...change };
}

function successorTarget(f: Fixture, description = "fixture-successor"): IncidentCasV2CutoverTarget {
	const unitContents = `[Unit]\nDescription=${description}\n\n[Service]\nExecStart=${f.target.launcher.argv.map(quote).join(" ")}\n`;
	writeFileSync(f.unitPath, unitContents, { mode: 0o600 });
	if (f.launcher.state !== "observed") throw new Error("fixture launcher is unavailable");
	f.launcher = { ...f.launcher, fragment: observedFile(f.unitPath) };
	return {
		...f.target,
		launcher: { ...f.target.launcher, unitContents },
	};
}

function rewriteAsLegacyRecord(path: string): Buffer {
	const record = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
	delete record.transitionKind;
	delete record.predecessorGenerationDigest;
	const bytes = Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
	writeFileSync(path, bytes, { mode: 0o600 });
	return bytes;
}

function replaceAgentDir(f: Fixture, suffix: string): void {
	renameSync(f.agentDir, `${f.agentDir}.${suffix}`);
	mkdirSync(f.agentDir, { mode: 0o700 });
	mkdirSync(f.recorder, { mode: 0o700 });
	mkdirSync(f.incidents, { mode: 0o700 });
}

describe("incident recorder CAS v2 cutover", () => {
	it("creates a fixed, private draining journal and orchestration claim outside the recorder root", () => {
		const f = fixture();
		const first = begin(f);
		const paths = artifactPaths(f.agentDir);
		expect(existsSync(paths.generation)).toBe(true);
		expect(existsSync(paths.claim)).toBe(true);
		expect(existsSync(paths.prepare)).toBe(false);
		expect(readdirSync(f.recorder)).toEqual([]);
		expect(statSync(paths.generation).mode & 0o777).toBe(0o600);
		expect(statSync(paths.claim).mode & 0o777).toBe(0o600);
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({
			schemaVersion: 1,
			kind: "incident_cas_v2_generation",
			state: "draining",
			canonicalAgentDirPath: realpathSync.native(f.agentDir),
			incidentRecorderPath: realpathSync.native(f.recorder),
			incidentsPath: realpathSync.native(f.incidents),
			historicalCopyBoundary: "arbitrary_historical_copies_outside_controlled_package_are_cooperative",
		});
		const second = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
		expect(second).toMatchObject({ state: "draining" });
		expect(readdirSync(f.base).filter((name) => name.startsWith(paths.baseName))).toHaveLength(2);
		first.close();
		if (second.state === "draining") second.cutover.close();
	});

	it("preserves and blocks unrecognized residue in the canonical agentDir generation namespace", () => {
		const f = fixture();
		const paths = artifactPaths(f.agentDir);
		const unknown = join(f.base, `${paths.baseName}.generation.v1-unknown`);
		writeFileSync(unknown, "preserve unknown authority\n", { mode: 0o600 });
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "invalid_control_artifact",
		});
		expect(readFileSync(unknown, "utf8")).toBe("preserve unknown authority\n");
		expect(existsSync(paths.generation)).toBe(false);
		expect(existsSync(paths.claim)).toBe(false);
	});

	it("keeps the cutover journal disjoint from legitimate same-base CAS authority siblings", () => {
		const f = fixture();
		const paths = artifactPaths(f.agentDir);
		mkdirSync(join(f.base, paths.baseName), { mode: 0o700 });
		writeFileSync(join(f.base, `${paths.baseName}.stage`), "CAS-owned residue\n", { mode: 0o600 });
		const cutover = begin(f);
		expect(existsSync(paths.generation)).toBe(true);
		expect(existsSync(paths.claim)).toBe(true);
		cutover.close();
	});

	it("publishes v2 with a single-use witness and opens a revalidating read-only activation", () => {
		const f = fixture();
		const cutover = begin(f);
		const witness = prove(cutover);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "published" });
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "witness_invalid" });
		const paths = artifactPaths(f.agentDir);
		expect(existsSync(paths.claim)).toBe(false);
		expect(existsSync(paths.prepare)).toBe(false);
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({ state: "v2" });
		const activation = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		expect(activation).toMatchObject({ state: "active" });
		if (activation.state !== "active") return;
		const digest = createHash("sha256").update(readFileSync(paths.generation)).digest("hex");
		expect(activation.activation.activationGenerationDigest).toBe(digest);
		expect(activation.activation.revalidate()).toEqual({ state: "valid" });
		expect(activation.activation.activationGenerationDigest).toBe(digest);
		expect(Object.isFrozen(activation.activation)).toBe(true);
		activation.activation.close();
		expect(activation.activation.revalidate()).toEqual({ state: "invalid", reason: "generation_changed" });
		expect(activation.activation.activationGenerationDigest).toBe(digest);
	});

	it("claims a changed target as a predecessor-bound successor and publishes it atomically", () => {
		const f = fixture();
		const initial = begin(f);
		const paths = artifactPaths(f.agentDir);
		const initialClaim = JSON.parse(readFileSync(paths.claim, "utf8")) as Record<string, unknown>;
		const initialWitness = prove(initial);
		expect(publishIncidentCasV2(initial, initialWitness)).toEqual({ state: "published" });
		const initialGeneration = readFileSync(paths.generation);
		const initialGenerationRecord = JSON.parse(initialGeneration.toString("utf8")) as Record<string, unknown>;
		const predecessorDigest = sha256(initialGeneration);
		const initialCutoverId = initialGenerationRecord.cutoverId;
		const targetB = successorTarget(f);

		const successor = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		expect(successor).toMatchObject({ state: "draining" });
		if (successor.state !== "draining") return;
		expect(readFileSync(paths.generation)).toEqual(initialGeneration);
		const successorClaim = JSON.parse(readFileSync(paths.claim, "utf8")) as Record<string, unknown>;
		expect(successorClaim).toMatchObject({
			cutoverId: initialCutoverId,
			transitionKind: "upgrade",
			predecessorGenerationDigest: predecessorDigest,
		});
		expect(successorClaim.claimId).not.toBe(initialClaim.claimId);

		const witness = prove(successor.cutover);
		expect(publishIncidentCasV2(successor.cutover, witness)).toEqual({ state: "published" });
		const published = JSON.parse(readFileSync(paths.generation, "utf8")) as Record<string, unknown>;
		expect(published).toMatchObject({
			state: "v2",
			cutoverId: initialCutoverId,
			transitionKind: "upgrade",
			predecessorGenerationDigest: predecessorDigest,
		});
		expect(published.launcherConfigurationDigest).not.toBe(initialGenerationRecord.launcherConfigurationDigest);
		expect(existsSync(paths.claim)).toBe(false);
		expect(beginIncidentCasV2Cutover(targetB, f.runtimeHandle)).toEqual({ state: "v2" });
		initial.close();
	});

	it.each([
		"v2_prepared",
		"before_v2_publish",
		"after_final_quiescence",
		"v2_published",
		"v2_directory_fsynced",
		"claim_retirement_linked",
		"claim_unlinked",
		"cleanup_directory_fsynced",
	] satisfies IncidentCasV2CutoverStep[])("recovers an upgrade through the fixed slots after %s", (step) => {
		const f = fixture();
		publish(f);
		const targetB = successorTarget(f);
		const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		if (started.state !== "draining") throw new Error("expected upgrade cutover");
		const witness = prove(started.cutover);
		f.setStepFault(step);
		expect(publishIncidentCasV2(started.cutover, witness)).toEqual({ state: "unavailable", reason: "io_error" });
		started.cutover.close();
		const resumed = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		if (step === "v2_prepared" || step === "before_v2_publish" || step === "after_final_quiescence") {
			expect(resumed).toMatchObject({ state: "draining" });
			if (resumed.state === "draining") {
				const fresh = prove(resumed.cutover);
				expect(publishIncidentCasV2(resumed.cutover, fresh)).toEqual({ state: "published" });
			}
		} else expect(resumed).toEqual({ state: "v2" });
		const paths = artifactPaths(f.agentDir);
		expect(existsSync(paths.prepare)).toBe(false);
		expect(existsSync(paths.claim)).toBe(false);
	});

	it.each(["live", "unknown"] as const)("rejects a %s claimant while an upgrade is pending", (disposition) => {
		const f = fixture();
		publish(f);
		const targetB = successorTarget(f);
		const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		if (started.state !== "draining") throw new Error("expected upgrade cutover");
		started.cutover.close();
		const successorOwner: IncidentCasV2ProcessIdentity = {
			...f.owner,
			pid: f.owner.pid + 1,
			startId: "303",
		};
		const successorRuntime: IncidentCasV2CutoverRuntime = {
			...f.runtime,
			readCurrentProcessIdentity: () => ({ state: "present", identity: successorOwner }),
			readProcessIdentity: () =>
				disposition === "live"
					? { state: "present", identity: f.owner }
					: { state: "unavailable", code: "proc_unavailable" },
		};
		expect(beginIncidentCasV2Cutover(targetB, registerTestRuntime(successorRuntime))).toEqual({
			state: "unavailable",
			reason: disposition === "live" ? "orchestration_in_progress" : "orchestration_owner_unknown",
		});
	});

	it.each(["stale", "live", "unknown"] as const)(
		"handles target-C retry after published target-B residue owned by a %s claimant",
		(disposition) => {
			const f = fixture();
			publish(f);
			const targetB = successorTarget(f);
			const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
			if (started.state !== "draining") throw new Error("expected upgrade cutover");
			const witness = prove(started.cutover);
			f.setStepFault("claim_retirement_linked");
			expect(publishIncidentCasV2(started.cutover, witness)).toEqual({ state: "unavailable", reason: "io_error" });
			started.cutover.close();

			const paths = artifactPaths(f.agentDir);
			const publishedB = readFileSync(paths.generation);
			const targetC = successorTarget(f, "fixture-successor-c");
			const retryOwner: IncidentCasV2ProcessIdentity = { ...f.owner, pid: f.owner.pid + 2, startId: "404" };
			const retryRuntime: IncidentCasV2CutoverRuntime = {
				...f.runtime,
				readCurrentProcessIdentity: () => ({ state: "present", identity: retryOwner }),
				readProcessIdentity: () =>
					disposition === "stale"
						? { state: "absent" }
						: disposition === "live"
							? { state: "present", identity: f.owner }
							: { state: "unavailable", code: "proc_unavailable" },
			};
			const result = beginIncidentCasV2Cutover(targetC, registerTestRuntime(retryRuntime));
			if (disposition === "stale") {
				expect(result).toMatchObject({ state: "draining" });
				expect(readFileSync(paths.generation)).toEqual(publishedB);
				if (result.state === "draining") {
					const claim = JSON.parse(readFileSync(paths.claim, "utf8")) as Record<string, unknown>;
					expect(claim).toMatchObject({
						transitionKind: "upgrade",
						predecessorGenerationDigest: sha256(publishedB),
					});
					result.cutover.close();
				}
			} else {
				expect(result).toEqual({
					state: "unavailable",
					reason: disposition === "live" ? "orchestration_in_progress" : "orchestration_owner_unknown",
				});
				expect(readFileSync(paths.generation)).toEqual(publishedB);
				expect(existsSync(paths.claim)).toBe(true);
			}
		},
	);

	it("rejects a mixed bootstrap claim instead of adopting it as an upgrade", () => {
		const f = fixture();
		publish(f);
		const targetB = successorTarget(f);
		const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		if (started.state !== "draining") throw new Error("expected upgrade cutover");
		started.cutover.close();
		const paths = artifactPaths(f.agentDir);
		const claim = JSON.parse(readFileSync(paths.claim, "utf8")) as Record<string, unknown>;
		writeFileSync(
			paths.claim,
			`${JSON.stringify({ ...claim, transitionKind: "bootstrap", predecessorGenerationDigest: null })}\n`,
			{ mode: 0o600 },
		);
		expect(beginIncidentCasV2Cutover(targetB, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "invalid_control_artifact",
		});
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({ state: "v2" });
	});

	it("accepts exact legacy generation and claim bytes as implicit bootstrap records", () => {
		const f = fixture();
		const cutover = begin(f);
		cutover.close();
		const paths = artifactPaths(f.agentDir);
		const legacyGeneration = rewriteAsLegacyRecord(paths.generation);
		const legacyClaim = rewriteAsLegacyRecord(paths.claim);
		expect(JSON.parse(legacyGeneration.toString("utf8"))).not.toHaveProperty("transitionKind");
		expect(JSON.parse(legacyClaim.toString("utf8"))).not.toHaveProperty("predecessorGenerationDigest");

		const resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
		expect(resumed).toMatchObject({ state: "draining" });
		expect(readFileSync(paths.generation)).toEqual(legacyGeneration);
		expect(readFileSync(paths.claim)).toEqual(legacyClaim);
		if (resumed.state === "draining") resumed.cutover.close();
	});

	it("publishes and activates a legacy draining generation with canonical successor bytes", () => {
		const f = fixture();
		const initial = begin(f);
		initial.close();
		const paths = artifactPaths(f.agentDir);
		const legacyGeneration = rewriteAsLegacyRecord(paths.generation);
		rewriteAsLegacyRecord(paths.claim);

		const resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
		expect(resumed).toMatchObject({ state: "draining" });
		if (resumed.state !== "draining") return;
		const witness = prove(resumed.cutover);
		expect(publishIncidentCasV2(resumed.cutover, witness)).toEqual({ state: "published" });
		const publishedBytes = readFileSync(paths.generation);
		const published = JSON.parse(publishedBytes.toString("utf8")) as Record<string, unknown>;
		expect(Object.keys(published)).toEqual([
			"schemaVersion",
			"kind",
			"state",
			"cutoverId",
			"transitionKind",
			"predecessorGenerationDigest",
			"canonicalAgentDirPath",
			"incidentRecorderPath",
			"incidentsPath",
			"historicalCopyBoundary",
			"control",
			"launcherConfigurationDigest",
		]);
		expect(published.state).toBe("v2");
		expect(published.predecessorGenerationDigest).toBeNull();
		expect(sha256(publishedBytes)).not.toBe(sha256(legacyGeneration));
		expect(existsSync(paths.claim)).toBe(false);
		expect(existsSync(paths.prepare)).toBe(false);
		expect(openIncidentCasV2Activation(f.target, f.runtimeHandle)).toMatchObject({ state: "active" });
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({ state: "v2" });
	});

	it("retains raw legacy generation bytes when binding an upgrade predecessor", () => {
		const f = fixture();
		publish(f);
		const paths = artifactPaths(f.agentDir);
		const legacyGeneration = rewriteAsLegacyRecord(paths.generation);
		const targetB = successorTarget(f);

		const resumed = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		expect(resumed).toMatchObject({ state: "draining" });
		expect(readFileSync(paths.generation)).toEqual(legacyGeneration);
		const claim = JSON.parse(readFileSync(paths.claim, "utf8")) as Record<string, unknown>;
		expect(claim).toMatchObject({
			transitionKind: "upgrade",
			predecessorGenerationDigest: sha256(legacyGeneration),
		});
		if (resumed.state === "draining") resumed.cutover.close();
	});

	it("publishes and activates an upgrade from a legacy v2 generation with canonical successor bytes", () => {
		const f = fixture();
		publish(f);
		const paths = artifactPaths(f.agentDir);
		const legacyGeneration = rewriteAsLegacyRecord(paths.generation);
		const targetB = successorTarget(f);
		const resumed = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
		expect(resumed).toMatchObject({ state: "draining" });
		if (resumed.state !== "draining") return;
		const witness = prove(resumed.cutover);
		expect(publishIncidentCasV2(resumed.cutover, witness)).toEqual({ state: "published" });
		const publishedBytes = readFileSync(paths.generation);
		const published = JSON.parse(publishedBytes.toString("utf8")) as Record<string, unknown>;
		expect(Object.keys(published)).toEqual([
			"schemaVersion",
			"kind",
			"state",
			"cutoverId",
			"transitionKind",
			"predecessorGenerationDigest",
			"canonicalAgentDirPath",
			"incidentRecorderPath",
			"incidentsPath",
			"historicalCopyBoundary",
			"control",
			"launcherConfigurationDigest",
		]);
		expect(published).toMatchObject({
			state: "v2",
			transitionKind: "upgrade",
			predecessorGenerationDigest: sha256(legacyGeneration),
		});
		expect(existsSync(paths.claim)).toBe(false);
		expect(existsSync(paths.prepare)).toBe(false);
		expect(openIncidentCasV2Activation(targetB, f.runtimeHandle)).toMatchObject({ state: "active" });
		expect(beginIncidentCasV2Cutover(targetB, f.runtimeHandle)).toEqual({ state: "v2" });
	});

	it.each([
		"v2_prepared",
		"before_v2_publish",
		"after_final_quiescence",
		"claim_unlinked",
	] satisfies IncidentCasV2CutoverStep[])(
		"recovers target C from target B residue at %s and publishes a readable successor",
		(step) => {
			const f = fixture();
			publish(f);
			const targetB = successorTarget(f, "fixture-successor-b");
			const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
			expect(started).toMatchObject({ state: "draining" });
			if (started.state !== "draining") return;
			const witness = prove(started.cutover);
			f.setStepFault(step);
			expect(publishIncidentCasV2(started.cutover, witness)).toEqual({ state: "unavailable", reason: "io_error" });
			started.cutover.close();

			const paths = artifactPaths(f.agentDir);
			const targetBGeneration = readFileSync(paths.generation);
			const targetC = successorTarget(f, "fixture-successor-c");
			const recovered = beginIncidentCasV2Cutover(targetC, f.runtimeHandle);
			expect(recovered).toMatchObject({ state: "draining" });
			if (recovered.state !== "draining") return;
			const recoveredWitness = prove(recovered.cutover);
			expect(publishIncidentCasV2(recovered.cutover, recoveredWitness)).toEqual({ state: "published" });
			const published = JSON.parse(readFileSync(paths.generation, "utf8")) as Record<string, unknown>;
			expect(published).toMatchObject({ state: "v2", transitionKind: "upgrade" });
			expect(published.predecessorGenerationDigest).toBe(sha256(targetBGeneration));
			expect(existsSync(paths.prepare)).toBe(false);
			expect(existsSync(paths.claim)).toBe(false);
			expect(openIncidentCasV2Activation(targetC, f.runtimeHandle)).toMatchObject({ state: "active" });
			expect(beginIncidentCasV2Cutover(targetC, f.runtimeHandle)).toEqual({ state: "v2" });
		},
	);

	it("rejects a wrong target for a draining generation before creating a replacement claim", () => {
		const f = fixture();
		const cutover = begin(f);
		cutover.close();
		const paths = artifactPaths(f.agentDir);
		const generationBefore = readFileSync(paths.generation);
		unlinkSync(paths.claim);
		const targetB = successorTarget(f, "fixture-wrong-draining-target");

		expect(beginIncidentCasV2Cutover(targetB, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "target_mismatch",
		});
		expect(readFileSync(paths.generation)).toEqual(generationBefore);
		expect(existsSync(paths.claim)).toBe(false);
		expect(existsSync(paths.prepare)).toBe(false);
	});

	it.each([
		["missing transition metadata", (record: Record<string, unknown>) => delete record.transitionKind],
		["missing predecessor metadata", (record: Record<string, unknown>) => delete record.predecessorGenerationDigest],
		[
			"bootstrap with a predecessor digest",
			(record: Record<string, unknown>) => {
				record.transitionKind = "bootstrap";
				record.predecessorGenerationDigest = "a".repeat(64);
			},
		],
		[
			"upgrade without a predecessor digest",
			(record: Record<string, unknown>) => {
				record.transitionKind = "upgrade";
				record.predecessorGenerationDigest = null;
			},
		],
	] as const)("rejects %s generation metadata", (_name, mutate) => {
		const f = fixture();
		publish(f);
		const path = artifactPaths(f.agentDir).generation;
		const record = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
		mutate(record);
		writeFileSync(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "invalid_control_artifact",
		});
	});

	it("keeps the admitted digest stable while permanently rejecting a replaced generation", () => {
		const f = fixture();
		publish(f);
		const opened = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		if (opened.state !== "active") throw new Error("expected active generation");
		const path = artifactPaths(f.agentDir).generation;
		const original = readFileSync(path);
		const digest = opened.activation.activationGenerationDigest;
		writeFileSync(path, Buffer.concat([original, Buffer.from("\n")]), { mode: 0o600 });
		expect(opened.activation.revalidate()).toEqual({ state: "invalid", reason: "generation_changed" });
		writeFileSync(path, original, { mode: 0o600 });
		expect(opened.activation.activationGenerationDigest).toBe(digest);
		expect(opened.activation.revalidate()).toEqual({ state: "invalid", reason: "generation_changed" });
		opened.activation.close();
	});

	it("keeps the outer claim and activation across a private same-path agentDir replacement", () => {
		const f = fixture();
		const cutover = begin(f);
		const claimBefore = statSync(artifactPaths(f.agentDir).claim, { bigint: true });
		replaceAgentDir(f, "first-root");
		const contenderOwner: IncidentCasV2ProcessIdentity = { ...f.owner, pid: f.owner.pid + 7, startId: "707" };
		const contenderRuntime: IncidentCasV2CutoverRuntime = {
			...f.runtime,
			readCurrentProcessIdentity: () => ({ state: "present", identity: contenderOwner }),
			readProcessIdentity: (pid) =>
				pid === f.owner.pid
					? { state: "present", identity: f.owner }
					: { state: "present", identity: contenderOwner },
		};
		const contenderHandle = registerTestRuntime(contenderRuntime);
		expect(beginIncidentCasV2Cutover(f.target, contenderHandle)).toEqual({
			state: "unavailable",
			reason: "orchestration_in_progress",
		});
		const claimAfter = statSync(artifactPaths(f.agentDir).claim, { bigint: true });
		expect([claimAfter.dev, claimAfter.ino]).toEqual([claimBefore.dev, claimBefore.ino]);
		const witness = prove(cutover);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "published" });
		const opened = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		expect(opened).toMatchObject({ state: "active" });
		if (opened.state !== "active") return;
		replaceAgentDir(f, "second-root");
		expect(opened.activation.revalidate()).toEqual({ state: "valid" });
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({ state: "v2" });
		opened.activation.close();
	});

	it("preserves and blocks on every exact legacy v1 authority shape", () => {
		for (const kind of ["directory", "file", "symlink"] as const) {
			const f = fixture();
			const legacy = join(f.recorder, ".cas-transaction");
			const sentinel = join(f.base, `sentinel-${kind}`);
			writeFileSync(sentinel, `${kind}\n`, { mode: 0o600 });
			if (kind === "directory") {
				mkdirSync(legacy, { mode: 0o700 });
				writeFileSync(join(legacy, "owner.json"), `${kind}\n`, { mode: 0o600 });
			} else if (kind === "file") writeFileSync(legacy, `${kind}\n`, { mode: 0o600 });
			else symlinkSync(sentinel, legacy);
			expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
				state: "unavailable",
				reason: "legacy_v1_authority_present",
			});
			expect(
				lstatSync(legacy)[kind === "directory" ? "isDirectory" : kind === "file" ? "isFile" : "isSymbolicLink"](),
			).toBe(true);
		}
	});

	it("consumes the witness and preserves a legacy artifact that appears before publish", () => {
		const f = fixture();
		const cutover = begin(f);
		const witness = prove(cutover);
		const legacy = join(f.recorder, ".cas-transaction");
		mkdirSync(legacy, { mode: 0o700 });
		expect(publishIncidentCasV2(cutover, witness)).toEqual({
			state: "unavailable",
			reason: "legacy_v1_authority_present",
		});
		expect(existsSync(legacy)).toBe(true);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "witness_invalid" });
		cutover.close();
	});

	it("consumes the witness and preserves unknown keyed residue that appears before publish", () => {
		const f = fixture();
		const cutover = begin(f);
		const witness = prove(cutover);
		const paths = artifactPaths(f.agentDir);
		const unknown = join(f.base, `${paths.baseName}.generation.unknown-authority`);
		writeFileSync(unknown, "preserve unknown authority\n", { mode: 0o600 });
		expect(publishIncidentCasV2(cutover, witness)).toEqual({
			state: "unavailable",
			reason: "invalid_control_artifact",
		});
		expect(readFileSync(unknown, "utf8")).toBe("preserve unknown authority\n");
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({ state: "draining" });
		expect(existsSync(paths.claim)).toBe(true);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "witness_invalid" });
		cutover.close();
	});

	it("rejects a legacy-selector launcher instead of treating an ignored extra argument as v2", () => {
		const f = fixture();
		const argv = [realpathSync.native(process.execPath), f.entrypoint, "--incident-recorder-service"];
		const target: IncidentCasV2CutoverTarget = {
			...f.target,
			launcher: {
				...f.target.launcher,
				argv,
				unitContents: `[Service]\nExecStart=${argv.map(quote).join(" ")}\n`,
			},
		};
		expect(beginIncidentCasV2Cutover(target, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "invalid_target",
		});
		expect(readdirSync(f.base).filter((name) => name.includes(".generation."))).toEqual([]);
	});

	it("requires an exact stopped launcher around both process scans", () => {
		const f = fixture();
		const cutover = begin(f);
		cloneLauncher(f, { activeState: "active", subState: "running", mainPid: 81, execMainPid: 81 });
		expect(proveIncidentCasV1Quiescence(cutover)).toEqual({
			state: "unavailable",
			reason: "launcher_not_stopped",
		});
		cutover.close();
	});

	it("blocks an ambiguous owned process population", () => {
		const f = fixture();
		const cutover = begin(f);
		f.processes.push({
			pid: 51_001,
			parentPid: 1,
			uid: f.owner.uid,
			startId: "202",
			processState: "S",
			inspection: "ambiguous",
			argv: [],
			cwd: null,
			executable: null,
		});
		expect(proveIncidentCasV1Quiescence(cutover)).toEqual({
			state: "unavailable",
			reason: "process_population_ambiguous",
		});
		cutover.close();
	});

	it("blocks PID reuse observed by the closing same-UID process pass", () => {
		const f = fixture();
		const reusedPid = 51_006;
		f.processes.push({
			pid: reusedPid,
			parentPid: 1,
			uid: f.owner.uid,
			startId: "207",
			processState: "S",
			inspection: "complete",
			argv: ["/usr/bin/python3", "/tmp/unrelated.py"],
			cwd: "/tmp",
			executable: "/usr/bin/python3",
		});
		f.runtime.readProcessPopulation = () => {
			const population = observedPopulation(f.processes);
			return {
				...population,
				finalSameUidProcesses: population.finalSameUidProcesses.map((identity) =>
					identity.pid === reusedPid ? { ...identity, startId: "208" } : identity,
				),
			};
		};
		const cutover = begin(f);
		expect(proveIncidentCasV1Quiescence(cutover)).toEqual({
			state: "unavailable",
			reason: "process_population_ambiguous",
		});
		cutover.close();
	});

	it("blocks a stable same-UID PID that execs into the controlled product scope during the closing pass", () => {
		const f = fixture();
		const changedPid = 51_007;
		f.processes.push({
			pid: changedPid,
			parentPid: 1,
			uid: f.owner.uid,
			startId: "209",
			processState: "S",
			inspection: "complete",
			argv: ["/usr/bin/python3", "/tmp/unrelated.py"],
			cwd: "/tmp",
			executable: "/usr/bin/python3",
		});
		f.runtime.readProcessPopulation = () => {
			const population = observedPopulation(f.processes);
			return {
				...population,
				finalSameUidProcesses: population.finalSameUidProcesses.map((observed) =>
					observed.pid === changedPid
						? {
								...observed,
								argv: [realpathSync.native(process.execPath), f.entrypoint],
								cwd: f.packageRoot,
								executable: realpathSync.native(process.execPath),
							}
						: observed,
				),
			};
		};
		const cutover = begin(f);
		expect(proveIncidentCasV1Quiescence(cutover)).toEqual({
			state: "unavailable",
			reason: "controlled_processes_present",
			blockingPids: [changedPid],
		});
		cutover.close();
	});

	it("reports every controlled current-package process while ignoring an exact unrelated process", () => {
		const f = fixture();
		const cutover = begin(f);
		f.processes.push(
			{
				pid: 51_002,
				parentPid: 1,
				uid: f.owner.uid,
				startId: "203",
				processState: "S",
				inspection: "complete",
				argv: [realpathSync.native(process.execPath), join(f.packageRoot, "dist/bundle/worker.js")],
				cwd: "/tmp",
				executable: realpathSync.native(process.execPath),
			},
			{
				pid: 51_003,
				parentPid: 1,
				uid: f.owner.uid,
				startId: "204",
				processState: "S",
				inspection: "complete",
				argv: ["/usr/bin/python3", "/tmp/unrelated.py"],
				cwd: "/tmp",
				executable: "/usr/bin/python3",
			},
			{
				pid: 51_004,
				parentPid: 51_002,
				uid: f.owner.uid,
				startId: "205",
				processState: "S",
				inspection: "complete",
				argv: ["/usr/bin/python3", "-m", "ipykernel_launcher"],
				cwd: "/tmp",
				executable: "/usr/bin/python3",
			},
		);
		expect(proveIncidentCasV1Quiescence(cutover)).toEqual({
			state: "unavailable",
			reason: "controlled_processes_present",
			blockingPids: [51_002, 51_004],
		});
		cutover.close();
	});

	it("runs the decisive launcher and population scan after the v2 prepare is durable", () => {
		const f = fixture();
		let scans = 0;
		const original = f.runtime.readProcessPopulation;
		f.runtime.readProcessPopulation = () => {
			scans += 1;
			if (scans < 3) return original();
			return observedPopulation([
				...f.processes,
				{
					pid: 51_005,
					parentPid: 1,
					uid: f.owner.uid,
					startId: "206",
					processState: "S",
					inspection: "complete",
					argv: [realpathSync.native(process.execPath), f.entrypoint],
					cwd: f.packageRoot,
					executable: realpathSync.native(process.execPath),
				},
			]);
		};
		const cutover = begin(f);
		const witness = prove(cutover);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({
			state: "unavailable",
			reason: "controlled_processes_present",
			blockingPids: [51_005],
		});
		const paths = artifactPaths(f.agentDir);
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({ state: "draining" });
		expect(existsSync(paths.prepare)).toBe(false);
		cutover.close();
	});

	it("blocks a legacy selector launched through the controlled package after the earlier publish scan", () => {
		const f = fixture();
		const latePid = 51_008;
		f.setStepObserver((step) => {
			if (step !== "before_v2_publish") return;
			f.processes.push({
				pid: latePid,
				parentPid: 1,
				uid: f.owner.uid,
				startId: "210",
				processState: "S",
				inspection: "complete",
				argv: [f.nodePath, f.cliEntrypoint, "--incident-recorder-service"],
				cwd: f.packageRoot,
				executable: f.nodePath,
			});
		});
		const cutover = begin(f);
		const witness = prove(cutover);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({
			state: "unavailable",
			reason: "controlled_processes_present",
			blockingPids: [latePid],
		});
		const paths = artifactPaths(f.agentDir);
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({ state: "draining" });
		expect(existsSync(paths.prepare)).toBe(false);
		cutover.close();
	});

	it.each([
		["installed current main", "target_mismatch"],
		["controlled unit readback", "launcher_mismatch"],
	] as const)("blocks a post-final-scan legacy launch attempt through the %s", (component, reason) => {
		const f = fixture();
		const latePid = 51_009;
		f.setStepObserver((step) => {
			if (step !== "after_final_quiescence") return;
			if (component === "installed current main") writeFileSync(f.cliEntrypoint, "export {};\n", { mode: 0o600 });
			else
				cloneLauncher(f, {
					managerExecStartArgv: [f.nodePath, f.cliEntrypoint, "--incident-recorder-service"],
				});
			f.processes.push({
				pid: latePid,
				parentPid: 1,
				uid: f.owner.uid,
				startId: "211",
				processState: "S",
				inspection: "complete",
				argv: [f.nodePath, f.cliEntrypoint, "--incident-recorder-service"],
				cwd: f.packageRoot,
				executable: f.nodePath,
			});
		});
		const cutover = begin(f);
		const witness = prove(cutover);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason });
		const paths = artifactPaths(f.agentDir);
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({ state: "draining" });
		expect(existsSync(paths.prepare)).toBe(true);
		cutover.close();
	});

	it("rechecks the keyed control namespace after the final verifier seam and immediately before publish", () => {
		const f = fixture();
		const paths = artifactPaths(f.agentDir);
		const unknown = join(f.base, `${paths.baseName}.generation.late-unknown-authority`);
		f.setStepObserver((step) => {
			if (step === "before_v2_publish") writeFileSync(unknown, "preserve late unknown authority\n", { mode: 0o600 });
		});
		const cutover = begin(f);
		const witness = prove(cutover);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({
			state: "unavailable",
			reason: "invalid_control_artifact",
		});
		expect(readFileSync(unknown, "utf8")).toBe("preserve late unknown authority\n");
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({ state: "draining" });
		cutover.close();
	});

	it("rejects forgeable verifier objects even when they carry the public test-runtime discriminator", () => {
		const f = fixture();
		const { kind: _kind, ...unmarked } = f.runtime;
		expect(_kind).toBe("incident_cas_v2_structured_test_runtime");
		expect(beginIncidentCasV2Cutover(f.target, unmarked as unknown as IncidentCasV2TestRuntimeHandle)).toEqual({
			state: "unavailable",
			reason: "invalid_target",
		});
		expect(beginIncidentCasV2Cutover(f.target, f.runtime as unknown as IncidentCasV2TestRuntimeHandle)).toEqual({
			state: "unavailable",
			reason: "invalid_target",
		});
		expect(existsSync(artifactPaths(f.agentDir).generation)).toBe(false);
	});

	it("requires the current package CLI to carry the bound legacy-selector rejection", () => {
		const f = fixture();
		writeFileSync(f.cliEntrypoint, "export {}\n", { mode: 0o600 });
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "invalid_target",
		});
		expect(existsSync(artifactPaths(f.agentDir).generation)).toBe(false);
	});

	it.each(["node", "dedicated-entrypoint", "current-main"] as const)(
		"rejects a closed activation reopen after same-path %s replacement",
		(component) => {
			const f = fixture();
			publish(f);
			if (component === "node") writeFileSync(f.nodePath, "#!/bin/sh\n# replacement\n", { mode: 0o700 });
			if (component === "dedicated-entrypoint")
				writeFileSync(f.entrypoint, "export const replacement = true;\n", { mode: 0o600 });
			if (component === "current-main")
				writeFileSync(
					f.cliEntrypoint,
					`export const replacement = "${INCIDENT_CAS_V2_LEGACY_SELECTOR_REJECTION_MARKER}";\n`,
					{ mode: 0o600 },
				);
			expect(openIncidentCasV2Activation(f.target, f.runtimeHandle)).toEqual({
				state: "unavailable",
				reason: "target_mismatch",
			});
		},
	);

	it("prevents a delayed same-claim handle from publishing over the v2 successor", () => {
		const f = fixture();
		const first = begin(f);
		const second = begin(f);
		const firstWitness = prove(first);
		const secondWitness = prove(second);
		expect(publishIncidentCasV2(first, firstWitness)).toEqual({ state: "published" });
		expect(publishIncidentCasV2(second, secondWitness)).toEqual({ state: "unavailable", reason: "claim_lost" });
		expect(JSON.parse(readFileSync(artifactPaths(f.agentDir).generation, "utf8"))).toMatchObject({ state: "v2" });
		second.close();
	});

	it("requires the exact observation generation and launcher identity at final publish", () => {
		const f = fixture();
		const cutover = begin(f);
		const witness = prove(cutover);
		cloneLauncher(f, { observationGeneration: "101" });
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "witness_stale" });
		cutover.close();
	});

	it("expires witnesses and never permits reuse after a failed publish", () => {
		const f = fixture();
		const cutover = begin(f);
		const witness = prove(cutover);
		f.monotonicMs += 5_001;
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "witness_stale" });
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "witness_invalid" });
		cutover.close();
	});

	it.each(["malformed", "mode", "symlink", "hardlink"] as const)(
		"preserves and blocks a %s generation artifact",
		(kind) => {
			const f = fixture();
			const cutover = begin(f);
			cutover.close();
			const paths = artifactPaths(f.agentDir);
			if (kind === "malformed") writeFileSync(paths.generation, '{"state":"draining"}\n', { mode: 0o600 });
			if (kind === "mode") chmodSync(paths.generation, 0o644);
			if (kind === "symlink") {
				const preserved = `${paths.generation}.preserved`;
				unlinkSync(paths.generation);
				writeFileSync(preserved, "outside\n", { mode: 0o600 });
				symlinkSync(preserved, paths.generation);
			}
			if (kind === "hardlink") linkSync(paths.generation, `${paths.generation}.unexpected-link`);
			expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
				state: "unavailable",
				reason: "invalid_control_artifact",
			});
			expect(existsSync(paths.generation)).toBe(true);
		},
	);

	it.each(["mode", "symlink", "hardlink"] as const)("rejects a launcher fragment with invalid %s identity", (kind) => {
		const f = fixture();
		if (f.launcher.state !== "observed") return;
		const fragment = { ...f.launcher.fragment };
		if (kind === "mode") fragment.mode = (fragment.mode & ~0o777) | 0o644;
		if (kind === "symlink") fragment.mode = (fragment.mode & ~0o170000) | 0o120000;
		if (kind === "hardlink") fragment.nlink = 2;
		cloneLauncher(f, { fragment });
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "launcher_mismatch",
		});
	});

	it("preserves a successor when delayed scratch recovery races after validation", () => {
		const f = fixture();
		f.setStepFault("claim_scratch_partially_written");
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "io_error",
		});
		const paths = artifactPaths(f.agentDir);
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "orchestration_in_progress",
		});
		f.monotonicMs += 1_001;
		const successorBytes = "successor prepare\n";
		let invoked = false;
		const unregister = registerIncidentCasV2CleanupTestSynchronization(f.runtime, () => {
			invoked = true;
			unlinkSync(paths.prepare);
			writeFileSync(paths.prepare, successorBytes, { mode: 0o600 });
		});
		let resumed: ReturnType<typeof beginIncidentCasV2Cutover>;
		try {
			resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
		} finally {
			unregister();
		}
		expect(invoked).toBe(true);
		expect(resumed).toEqual({
			state: "unavailable",
			reason: "orchestration_in_progress",
		});
		expect(readFileSync(paths.prepare, "utf8")).toBe(successorBytes);
		expect(readdirSync(f.base).filter((name) => name.startsWith(paths.baseName))).toHaveLength(1);
	});

	it("preserves a successor when delayed prepare discard races after validation", () => {
		const f = fixture();
		f.setStepObserver((step) => {
			if (step !== "before_v2_publish") return;
			f.processes.push({
				pid: 51_010,
				parentPid: 1,
				uid: f.owner.uid,
				startId: "212",
				processState: "S",
				inspection: "complete",
				argv: [realpathSync.native(process.execPath), f.entrypoint],
				cwd: f.packageRoot,
				executable: realpathSync.native(process.execPath),
			});
		});
		const cutover = begin(f);
		const witness = prove(cutover);
		const paths = artifactPaths(f.agentDir);
		const successorBytes = "successor prepare\n";
		let invoked = false;
		const unregister = registerIncidentCasV2CleanupTestSynchronization(
			f.runtime,
			() => {
				invoked = true;
				unlinkSync(paths.prepare);
				writeFileSync(paths.prepare, successorBytes, { mode: 0o600 });
			},
			"prepare-discard",
		);
		let result: ReturnType<typeof publishIncidentCasV2>;
		try {
			result = publishIncidentCasV2(cutover, witness);
		} finally {
			unregister();
		}
		expect(invoked).toBe(true);
		expect(result.state).toBe("unavailable");
		expect(readFileSync(paths.prepare, "utf8")).toBe(successorBytes);
		expect(existsSync(paths.claim)).toBe(true);
		expect(JSON.parse(readFileSync(paths.generation, "utf8"))).toMatchObject({ state: "draining" });
		cutover.close();
	});

	it("preserves a successor when delayed claim retirement races after validation", () => {
		const f = fixture();
		const cutover = begin(f);
		const witness = prove(cutover);
		f.setStepFault("claim_retirement_linked");
		expect(publishIncidentCasV2(cutover, witness)).toEqual({
			state: "unavailable",
			reason: "io_error",
		});
		cutover.close();
		const paths = artifactPaths(f.agentDir);
		expect(existsSync(paths.prepare)).toBe(true);
		const successorBytes = "successor claim\n";
		let invoked = false;
		const unregister = registerIncidentCasV2CleanupTestSynchronization(
			f.runtime,
			() => {
				invoked = true;
				unlinkSync(paths.claim);
				writeFileSync(paths.claim, successorBytes, { mode: 0o600 });
			},
			"claim-retirement",
		);
		let resumed: ReturnType<typeof beginIncidentCasV2Cutover>;
		try {
			resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
		} finally {
			unregister();
		}
		expect(invoked).toBe(true);
		expect(resumed).toEqual({
			state: "unavailable",
			reason: "claim_lost",
		});
		expect(readFileSync(paths.claim, "utf8")).toBe(successorBytes);
		expect(existsSync(paths.prepare)).toBe(false);
	});

	it.each([
		"claim_scratch_opened",
		"claim_scratch_chmodded",
		"claim_scratch_partially_written",
		"draining_scratch_opened",
		"draining_scratch_chmodded",
		"draining_scratch_partially_written",
		"v2_scratch_opened",
		"v2_scratch_chmodded",
		"v2_scratch_partially_written",
	] satisfies IncidentCasV2CutoverStep[])(
		"repairs and reclaims a stable private scratch interrupted at %s",
		(step) => {
			const f = fixture();
			if (step.startsWith("v2_")) {
				const cutover = begin(f);
				const witness = prove(cutover);
				f.setStepFault(step);
				expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "io_error" });
				cutover.close();
			} else {
				f.setStepFault(step);
				expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
					state: "unavailable",
					reason: "io_error",
				});
			}
			const paths = artifactPaths(f.agentDir);
			expect(existsSync(paths.prepare)).toBe(true);
			expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
				state: "unavailable",
				reason: "orchestration_in_progress",
			});
			expect(statSync(paths.prepare).mode & 0o777).toBe(0o600);
			f.monotonicMs += 1_001;
			const resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
			expect(resumed).toMatchObject({ state: "draining" });
			expect(existsSync(paths.prepare)).toBe(false);
			expect(readdirSync(f.base).filter((name) => name.startsWith(paths.baseName)).length).toBeLessThanOrEqual(2);
			if (resumed.state === "draining") resumed.cutover.close();
		},
	);

	it.each(["v2_prepared", "claim_unlinked"] satisfies IncidentCasV2CutoverStep[])(
		"preserves target B standalone residue when its owner is %s",
		(step) => {
			for (const disposition of ["live", "unknown"] as const) {
				const f = fixture();
				publish(f);
				const targetB = successorTarget(f, "fixture-successor-b");
				const started = beginIncidentCasV2Cutover(targetB, f.runtimeHandle);
				if (started.state !== "draining") throw new Error("expected upgrade cutover");
				const witness = prove(started.cutover);
				f.setStepFault(step);
				expect(publishIncidentCasV2(started.cutover, witness)).toEqual({
					state: "unavailable",
					reason: "io_error",
				});
				started.cutover.close();

				const paths = artifactPaths(f.agentDir);
				const before = readdirSync(f.base)
					.filter((name) => name.startsWith(paths.baseName))
					.sort()
					.map((name) => [name, readFileSync(join(f.base, name))] as const);
				const targetC = successorTarget(f, "fixture-successor-c");
				const currentOwner: IncidentCasV2ProcessIdentity = {
					...f.owner,
					pid: f.owner.pid + 3,
					startId: "505",
				};
				const retryRuntime: IncidentCasV2CutoverRuntime = {
					...f.runtime,
					readCurrentProcessIdentity: () => ({ state: "present", identity: currentOwner }),
					readProcessIdentity: () =>
						disposition === "live"
							? { state: "present", identity: f.owner }
							: { state: "unavailable", code: "proc_unavailable" },
				};
				expect(beginIncidentCasV2Cutover(targetC, registerTestRuntime(retryRuntime))).toEqual({
					state: "unavailable",
					reason: disposition === "live" ? "orchestration_in_progress" : "orchestration_owner_unknown",
				});
				expect(
					readdirSync(f.base)
						.filter((name) => name.startsWith(paths.baseName))
						.sort()
						.map((name) => [name, readFileSync(join(f.base, name))] as const),
				).toEqual(before);
			}
		},
	);

	it.each([
		"claim_scratch_written",
		"draining_scratch_written",
		"v2_scratch_written",
	] satisfies IncidentCasV2CutoverStep[])("resumes a complete fixed scratch interrupted at %s", (step) => {
		const f = fixture();
		if (step === "v2_scratch_written") {
			const cutover = begin(f);
			const witness = prove(cutover);
			f.setStepFault(step);
			expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "io_error" });
			cutover.close();
		} else {
			f.setStepFault(step);
			expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
				state: "unavailable",
				reason: "io_error",
			});
		}
		const resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
		expect(resumed).toMatchObject({ state: "draining" });
		const paths = artifactPaths(f.agentDir);
		expect(existsSync(paths.prepare)).toBe(false);
		expect(readdirSync(f.base).filter((name) => name.startsWith(paths.baseName))).toHaveLength(2);
		if (resumed.state === "draining") resumed.cutover.close();
	});

	it.each([
		"claim_prepared",
		"claim_linked",
		"claim_directory_fsynced",
		"claim_prepare_unlinked",
		"draining_prepared",
		"draining_linked",
		"draining_directory_fsynced",
		"draining_prepare_unlinked",
	] satisfies IncidentCasV2CutoverStep[])("resumes a bounded begin after %s", (step) => {
		const f = fixture();
		f.setStepFault(step);
		expect(beginIncidentCasV2Cutover(f.target, f.runtimeHandle)).toEqual({
			state: "unavailable",
			reason: "io_error",
		});
		const resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
		expect(resumed).toMatchObject({ state: "draining" });
		const paths = artifactPaths(f.agentDir);
		expect(existsSync(paths.prepare)).toBe(false);
		expect(readdirSync(f.base).filter((name) => name.startsWith(paths.baseName))).toHaveLength(2);
		if (resumed.state === "draining") resumed.cutover.close();
	});

	it.each([
		"v2_prepared",
		"before_v2_publish",
		"after_final_quiescence",
		"v2_published",
		"v2_directory_fsynced",
		"claim_retirement_linked",
		"claim_unlinked",
		"cleanup_directory_fsynced",
	] satisfies IncidentCasV2CutoverStep[])("recovers through fixed slots after %s", (step) => {
		const f = fixture();
		const cutover = begin(f);
		const witness = prove(cutover);
		f.setStepFault(step);
		expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "io_error" });
		cutover.close();
		const resumed = beginIncidentCasV2Cutover(f.target, f.runtimeHandle);
		if (step === "v2_prepared" || step === "before_v2_publish" || step === "after_final_quiescence") {
			expect(resumed).toMatchObject({ state: "draining" });
			if (resumed.state === "draining") {
				const fresh = prove(resumed.cutover);
				expect(publishIncidentCasV2(resumed.cutover, fresh)).toEqual({ state: "published" });
			}
		} else expect(resumed).toEqual({ state: "v2" });
		const paths = artifactPaths(f.agentDir);
		expect(existsSync(paths.prepare)).toBe(false);
		expect(existsSync(paths.claim)).toBe(false);
		expect(readdirSync(f.base).filter((name) => name.startsWith(paths.baseName))).toHaveLength(1);
	});

	it("keeps repeated failed publication residue bounded to the three fixed slots", () => {
		const f = fixture();
		for (let attempt = 0; attempt < 16; attempt += 1) {
			const cutover = begin(f);
			const witness = prove(cutover);
			f.setStepFault("v2_prepared");
			expect(publishIncidentCasV2(cutover, witness)).toEqual({ state: "unavailable", reason: "io_error" });
			cutover.close();
			const paths = artifactPaths(f.agentDir);
			expect(readdirSync(f.base).filter((name) => name.startsWith(paths.baseName)).length).toBeLessThanOrEqual(3);
		}
		publish(f);
		const paths = artifactPaths(f.agentDir);
		expect(readdirSync(f.base).filter((name) => name.startsWith(paths.baseName))).toHaveLength(1);
	});

	it("serializes a live orchestration claim and reclaims it only after exact absence", () => {
		const f = fixture();
		const first = begin(f);
		first.close();
		const secondOwner: IncidentCasV2ProcessIdentity = { ...f.owner, pid: f.owner.pid + 1, startId: "303" };
		const secondRuntime: IncidentCasV2CutoverRuntime = {
			...f.runtime,
			readCurrentProcessIdentity: () => ({ state: "present", identity: secondOwner }),
			readProcessIdentity: (pid) =>
				pid === f.owner.pid ? { state: "present", identity: f.owner } : { state: "present", identity: secondOwner },
		};
		const secondHandle = registerTestRuntime(secondRuntime);
		expect(beginIncidentCasV2Cutover(f.target, secondHandle)).toEqual({
			state: "unavailable",
			reason: "orchestration_in_progress",
		});
		secondRuntime.readProcessIdentity = (pid) =>
			pid === f.owner.pid ? { state: "absent" } : { state: "present", identity: secondOwner };
		const reclaimed = beginIncidentCasV2Cutover(f.target, secondHandle);
		expect(reclaimed).toMatchObject({ state: "draining" });
		const claim = JSON.parse(readFileSync(artifactPaths(f.agentDir).claim, "utf8"));
		expect(claim.owner).toEqual(secondOwner);
		if (reclaimed.state === "draining") reclaimed.cutover.close();
	});

	it("blocks an ambiguous claimant identity without rewriting its evidence", () => {
		const f = fixture();
		const first = begin(f);
		first.close();
		const before = readFileSync(artifactPaths(f.agentDir).claim);
		const other = { ...f.owner, pid: f.owner.pid + 1, startId: "404" };
		const runtime: IncidentCasV2CutoverRuntime = {
			...f.runtime,
			readCurrentProcessIdentity: () => ({ state: "present", identity: other }),
			readProcessIdentity: () => ({ state: "unavailable", code: "proc_unavailable" }),
		};
		expect(beginIncidentCasV2Cutover(f.target, registerTestRuntime(runtime))).toEqual({
			state: "unavailable",
			reason: "orchestration_owner_unknown",
		});
		expect(readFileSync(artifactPaths(f.agentDir).claim)).toEqual(before);
	});

	it("reuses unchanged executable fingerprints without repeatedly reading their contents", () => {
		const f = fixture();
		writeFileSync(f.nodePath, Buffer.alloc(4 * 1024 * 1024, 1));
		publish(f);
		const opened = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		if (opened.state !== "active") throw new Error("expected active fixture");
		try {
			vi.mocked(readSync).mockClear();
			expect(opened.activation.revalidate()).toEqual({ state: "valid" });
			expect(
				vi
					.mocked(readSync)
					.mock.calls.some((call) => Buffer.isBuffer(call[1]) && call[1].byteLength >= 4 * 1024 * 1024),
			).toBe(false);
		} finally {
			opened.activation.close();
		}
	});

	it("does not reuse a fingerprint after same-inode same-size content changes with restored mtime", () => {
		const f = fixture();
		utimesSync(f.nodePath, 1_700_000_000, 1_700_000_000);
		publish(f);
		const opened = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		if (opened.state !== "active") throw new Error("expected active fixture");
		try {
			const before = statSync(f.nodePath);
			writeFileSync(f.nodePath, "#!/bin/zz\n");
			utimesSync(f.nodePath, before.atime, before.mtime);
			expect(statSync(f.nodePath).size).toBe(before.size);
			expect(opened.activation.revalidate()).toEqual({ state: "invalid", reason: "target_mismatch" });
		} finally {
			opened.activation.close();
		}
	});

	it("invalidates activation when legacy evidence or launcher identity appears", () => {
		const f = fixture();
		publish(f);
		const opened = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		expect(opened).toMatchObject({ state: "active" });
		if (opened.state !== "active") return;
		mkdirSync(join(f.recorder, ".cas-transaction"), { mode: 0o700 });
		expect(opened.activation.revalidate()).toEqual({
			state: "invalid",
			reason: "legacy_v1_authority_present",
		});
		rmSync(join(f.recorder, ".cas-transaction"), { recursive: true });
		expect(opened.activation.revalidate()).toEqual({
			state: "invalid",
			reason: "legacy_v1_authority_present",
		});
		opened.activation.close();

		const second = fixture();
		publish(second);
		const secondOpened = openIncidentCasV2Activation(second.target, second.runtimeHandle);
		expect(secondOpened).toMatchObject({ state: "active" });
		if (secondOpened.state !== "active") return;
		writeFileSync(second.entrypoint, "export const changed = true;\n", { mode: 0o600 });
		if (second.launcher.state !== "observed") return;
		cloneLauncher(second, { entrypoint: observedFile(second.entrypoint) });
		expect(secondOpened.activation.revalidate()).toEqual({ state: "invalid", reason: "target_mismatch" });
		secondOpened.activation.close();
	});

	it("irreversibly invalidates activation when the controlled current main loses its legacy-selector fence", () => {
		const f = fixture();
		publish(f);
		const opened = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		expect(opened).toMatchObject({ state: "active" });
		if (opened.state !== "active") return;
		writeFileSync(f.cliEntrypoint, "export {};\n", { mode: 0o600 });
		expect(opened.activation.revalidate()).toEqual({ state: "invalid", reason: "target_mismatch" });
		writeFileSync(
			f.cliEntrypoint,
			`export const legacySelectorFence = "${INCIDENT_CAS_V2_LEGACY_SELECTOR_REJECTION_MARKER}";\n`,
			{ mode: 0o600 },
		);
		expect(opened.activation.revalidate()).toEqual({ state: "invalid", reason: "target_mismatch" });
	});

	it("irreversibly invalidates activation when unknown keyed control residue appears", () => {
		const f = fixture();
		publish(f);
		const opened = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		expect(opened).toMatchObject({ state: "active" });
		if (opened.state !== "active") return;
		const paths = artifactPaths(f.agentDir);
		const unknown = join(f.base, `${paths.baseName}.generation.unknown-authority`);
		writeFileSync(unknown, "preserve unknown authority\n", { mode: 0o600 });
		expect(opened.activation.revalidate()).toEqual({
			state: "invalid",
			reason: "invalid_control_artifact",
		});
		unlinkSync(unknown);
		expect(opened.activation.revalidate()).toEqual({
			state: "invalid",
			reason: "invalid_control_artifact",
		});
	});

	it("allows service state transitions while retaining the exact activation configuration", () => {
		const f = fixture();
		publish(f);
		const opened = openIncidentCasV2Activation(f.target, f.runtimeHandle);
		expect(opened).toMatchObject({ state: "active" });
		if (opened.state !== "active") return;
		cloneLauncher(f, {
			activeState: "active",
			subState: "running",
			mainPid: 61_000,
			execMainPid: 61_000,
			observationGeneration: "999",
		});
		expect(opened.activation.revalidate()).toEqual({ state: "valid" });
		opened.activation.close();
	});
});
