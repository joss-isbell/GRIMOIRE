import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const testRuntimeBridge = vi.hoisted(() => {
	let registrar: ((runtime: unknown) => unknown) | undefined;
	const symbol = Symbol.for("grimoire.incident-writer-lifecycle.test-runtime-bridge.v1");
	const host = globalThis as unknown as Record<PropertyKey, unknown>;
	host[symbol] = (installed: (runtime: unknown) => unknown) => {
		registrar = installed;
	};
	return {
		register(runtime: unknown): unknown {
			if (!registrar) throw new Error("writer lifecycle test runtime bridge was not installed");
			return registrar(runtime);
		},
	};
});

import type {
	CasTransaction,
	IncidentCasFileMutation,
	IncidentCasRelativePath,
	IncidentCasRootMutation,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	acquireIncidentRecorderWriterRecoveryLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleArtifact,
	type IncidentRecorderWriterLifecycleFaultStep,
	type IncidentRecorderWriterLifecycleProcessIdentity,
	type IncidentRecorderWriterLifecycleProcessIdentityObservation,
	type IncidentRecorderWriterLifecycleProof,
	type IncidentRecorderWriterLifecycleRuntime,
	type IncidentRecorderWriterLifecycleTestRuntimeHandle,
	inspectIncidentRecorderWriterLifecycleProof,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const GENERATION_A = "a".repeat(64);
const GENERATION_B = "b".repeat(64);
const cleanupPaths: string[] = [];
const children = new Set<ChildProcessWithoutNullStreams>();

afterEach(async () => {
	for (const child of children) {
		if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
	}
	await Promise.all([...children].map((child) => waitForExit(child).catch(() => undefined)));
	children.clear();
	for (const path of cleanupPaths.splice(0).reverse()) rmSync(path, { recursive: true, force: true });
});

interface Fixture {
	base: string;
	agentDir: string;
	recorder: string;
	incidents: string;
}

function makeAgentDir(parent: string, name: string): Fixture {
	const agentDir = join(parent, name);
	const recorder = join(agentDir, "incident-recorder");
	const incidents = join(agentDir, "incidents");
	mkdirSync(recorder, { recursive: true, mode: 0o700 });
	mkdirSync(incidents, { mode: 0o700 });
	return { base: parent, agentDir, recorder, incidents };
}

function fixture(): Fixture {
	const base = mkdtempSync(join(tmpdir(), "grimoire-writer-lifecycle-"));
	cleanupPaths.push(base);
	return makeAgentDir(base, "agent");
}

function registerTestRuntime(
	runtime: IncidentRecorderWriterLifecycleRuntime,
): IncidentRecorderWriterLifecycleTestRuntimeHandle {
	return testRuntimeBridge.register(runtime) as IncidentRecorderWriterLifecycleTestRuntimeHandle;
}

function identity(
	pid: number,
	processStartId = `proc:${pid * 10}`,
	bootId = "00000000-0000-4000-8000-000000000001",
): IncidentRecorderWriterLifecycleProcessIdentity {
	return {
		bootId,
		pid,
		processStartId,
		uid: process.getuid?.() ?? 1000,
	};
}

function runtimeFor(
	current: IncidentRecorderWriterLifecycleProcessIdentity,
	readIdentity: (pid: number) => IncidentRecorderWriterLifecycleProcessIdentityObservation = (pid) =>
		pid === current.pid ? { state: "present", identity: current } : { state: "absent" },
	onStep?: (step: IncidentRecorderWriterLifecycleFaultStep, artifact: IncidentRecorderWriterLifecycleArtifact) => void,
): IncidentRecorderWriterLifecycleRuntime {
	return {
		readCurrentProcessIdentity: () => ({ state: "present", identity: current }),
		readProcessIdentity: readIdentity,
		wallTimeMs: () => Date.now(),
		onStep,
	};
}

function unexpected(message: string): never {
	throw new Error(message);
}

function fakeRoot(recorder: string): IncidentCasRootMutation {
	const relativePaths = new WeakMap<object, string>();
	const file: IncidentCasFileMutation = Object.freeze({
		stat: () => unexpected("fake file stat was not configured"),
		read: () => unexpected("fake file read was not configured"),
		write: () => unexpected("fake file write was not configured"),
		writeText: () => unexpected("fake file writeText was not configured"),
		truncate: () => unexpected("fake file truncate was not configured"),
		chmod: () => unexpected("fake file chmod was not configured"),
		sync: () => undefined,
	});
	let root: IncidentCasRootMutation;
	root = Object.freeze({
		relative(...components: string[]): IncidentCasRelativePath {
			const token = Object.freeze({}) as IncidentCasRelativePath;
			relativePaths.set(token, join(...components));
			return token;
		},
		publicPath(path: IncidentCasRelativePath): string {
			return join(recorder, relativePaths.get(path as object) ?? "unknown");
		},
		exists: () => true,
		lstat: () => undefined,
		stat: () => unexpected("fake root stat was not configured"),
		statfs: () => unexpected("fake root statfs was not configured"),
		readFile: () => Buffer.alloc(0),
		readlink: () => "",
		realpath: (path: IncidentCasRelativePath) => path,
		writeFileExclusive: () => undefined,
		mkdirPrivate: () => undefined,
		chmod: () => undefined,
		unlinkFile: () => undefined,
		rmdir: () => undefined,
		rename: () => undefined,
		hardLink: () => undefined,
		fsyncFile: () => undefined,
		fsyncDirectory: () => undefined,
		withFile: <T>(
			_path: IncidentCasRelativePath,
			_options: Parameters<IncidentCasRootMutation["withFile"]>[1],
			operation: (value: IncidentCasFileMutation) => T,
		): T => operation(file),
		withDirectory: <T>(_path: IncidentCasRelativePath, operation: (value: IncidentCasRootMutation) => T): T =>
			operation(root),
		directoryPage: () => ({
			entries: [],
			complete: true,
			cursorFound: true,
			scanLimitReached: false,
		}),
	});
	return root;
}

interface ContractHarness {
	contract: IncidentRecorderWriterLifecycleAdmissionContract;
	activationCalls: number;
	acquireCalls: number;
	releaseCalls: number;
	lastProof?: IncidentRecorderWriterLifecycleProof;
	root: IncidentCasRootMutation;
}

function contractHarness(
	fixtureValue: Fixture,
	options: {
		generationDigest?: string;
		activationValid?: boolean;
		casState?: "acquired" | "unavailable";
		rootResult?: "committed" | "malformed" | "root_detached" | "thenable";
		releasePending?: boolean;
	} = {},
): ContractHarness {
	const root = fakeRoot(fixtureValue.recorder);
	const harness: ContractHarness = {
		contract: undefined as never,
		activationCalls: 0,
		acquireCalls: 0,
		releaseCalls: 0,
		root,
	};
	const contract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: options.generationDigest ?? GENERATION_A,
		revalidateActivation: () => {
			harness.activationCalls += 1;
			return options.activationValid === false
				? { state: "invalid", reason: "generation_changed" }
				: { state: "valid" };
		},
		acquireCas: (proof) => {
			harness.acquireCalls += 1;
			harness.lastProof = proof;
			if (options.casState === "unavailable") return { state: "unavailable", reason: "control_artifact_busy" };
			const transaction: CasTransaction = {
				withRoot: <T>(operation: (capability: IncidentCasRootMutation) => T) => {
					if (options.rootResult === "root_detached") return { state: "root_detached", evidence: "durable" };
					const value = operation(root);
					if (options.rootResult === "thenable") {
						const thenable = {};
						const thenKey = String.fromCharCode(116, 104, 101, 110);
						const defined = Reflect.defineProperty(thenable, thenKey, {
							enumerable: true,
							value: () => undefined,
						});
						if (!defined || typeof Reflect.get(thenable, thenKey) !== "function")
							throw new Error("thenable fixture construction failed");
						return Object.freeze(thenable) as never;
					}
					if (options.rootResult === "malformed") return { state: "not_committed", value } as never;
					return { state: "committed", value };
				},
				release: () => {
					harness.releaseCalls += 1;
					return options.releasePending
						? { state: "pending", reason: "io_error" }
						: { state: "released", cleanupPending: false };
				},
			};
			return { state: "acquired", transaction };
		},
	};
	harness.contract = contract;
	return harness;
}

function expectAcquired<T extends { state: string }>(result: T): asserts result is Extract<T, { state: "acquired" }> {
	expect(result.state).toBe("acquired");
}

function lifecycleControlDirectory(base: string): string {
	const names = readdirSync(base).filter((name) => name.startsWith(".grimoire-incident-writer-lifecycle-v1-"));
	expect(names).toHaveLength(1);
	return join(base, names[0] as string);
}

function waitForLine(child: ChildProcessWithoutNullStreams, expected: string): Promise<void> {
	return new Promise((resolve, reject) => {
		let stdout = "";
		let stderr = "";
		const finish = (error?: Error): void => {
			child.stdout.off("data", onStdout);
			child.stderr.off("data", onStderr);
			child.off("exit", onExit);
			error ? reject(error) : resolve();
		};
		const onStdout = (chunk: Buffer): void => {
			stdout += chunk.toString("utf8");
			if (stdout.split(/\r?\n/).includes(expected)) finish();
		};
		const onStderr = (chunk: Buffer): void => {
			stderr += chunk.toString("utf8");
		};
		const onExit = (code: number | null, signal: NodeJS.Signals | null): void =>
			finish(new Error(`child exited before ${expected}: code=${code} signal=${signal} stderr=${stderr}`));
		child.stdout.on("data", onStdout);
		child.stderr.on("data", onStderr);
		child.once("exit", onExit);
	});
}

function waitForExit(child: ChildProcessWithoutNullStreams): Promise<void> {
	if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
	return new Promise((resolve) => child.once("exit", () => resolve()));
}

describe("incident recorder writer lifecycle", () => {
	it("admits multiple normal holders and atomically fences new launches while recovery drains them", () => {
		const f = fixture();
		const harness = contractHarness(f);
		const first = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		const second = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(first);
		expectAcquired(second);

		const draining = acquireIncidentRecorderWriterRecoveryLease({ agentDir: f.agentDir }, harness.contract);
		expect(draining).toEqual({ state: "pending", reason: "normal_holders_active" });
		expect(acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract)).toEqual({
			state: "unavailable",
			reason: "recovery_pending",
		});

		expect(first.lease.release()).toEqual({ state: "released", cleanupPending: false });
		expect(second.lease.release()).toEqual({ state: "released", cleanupPending: false });
		const recovery = acquireIncidentRecorderWriterRecoveryLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(recovery);
		expect(acquireIncidentRecorderWriterRecoveryLease({ agentDir: f.agentDir }, harness.contract)).toEqual({
			state: "unavailable",
			reason: "recovery_active",
		});
		expect(acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract)).toEqual({
			state: "unavailable",
			reason: "recovery_active",
		});
		expect(recovery.lease.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it("freezes the injected activation and CAS admission contract", () => {
		const f = fixture();
		const harness = contractHarness(f);
		const originalActivation = harness.contract.revalidateActivation;
		const originalAcquire = harness.contract.acquireCas;
		const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(result);
		harness.contract.revalidateActivation = () => ({ state: "invalid", reason: "mutated" });
		harness.contract.acquireCas = () => ({ state: "unavailable", reason: "creation_failed" });

		expect(result.lease.withRoot((root) => root.exists(root.relative("cas", "value")))).toEqual({
			state: "committed",
			value: true,
		});
		expect(harness.activationCalls).toBeGreaterThanOrEqual(3);
		expect(harness.acquireCalls).toBe(1);
		expect(originalActivation).not.toBe(harness.contract.revalidateActivation);
		expect(originalAcquire).not.toBe(harness.contract.acquireCas);
		expect(result.lease.release().state).toBe("released");
	});

	it("issues an unforgeable callback-scoped proof and revokes captured filesystem capabilities", () => {
		const f = fixture();
		const harness = contractHarness(f);
		const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(result);
		let capturedRoot: IncidentCasRootMutation | undefined;
		let bindingDigest: string | undefined;
		let serializedBinding: string | undefined;
		const mutation = result.lease.withRoot((root) => {
			capturedRoot = root;
			const binding = inspectIncidentRecorderWriterLifecycleProof(harness.lastProof);
			bindingDigest = binding?.digest;
			serializedBinding = JSON.stringify(binding);
			return root.publicPath(root.relative("cas", "object"));
		});
		expect(mutation).toEqual({ state: "committed", value: join(f.recorder, "cas", "object") });
		expect(bindingDigest).toMatch(/^[0-9a-f]{64}$/);
		expect(inspectIncidentRecorderWriterLifecycleProof(harness.lastProof)).toBeUndefined();
		expect(
			inspectIncidentRecorderWriterLifecycleProof(Object.freeze({}) as IncidentRecorderWriterLifecycleProof),
		).toBeUndefined();
		expect(() => capturedRoot?.exists(capturedRoot.relative("late"))).toThrow(/no longer active/);
		expect(Object.keys(result.lease).some((key) => /fd|descriptor/i.test(key))).toBe(false);
		expect(serializedBinding).not.toContain("/proc/self/fd");
		expect(result.lease.release().state).toBe("released");
	});

	it("rejects thenables from synchronous mutation callbacks", () => {
		const f = fixture();
		const harness = contractHarness(f);
		const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(result);
		expect(() => result.lease.withRoot(() => Promise.resolve("late"))).toThrow(/synchronously/);
		expect(inspectIncidentRecorderWriterLifecycleProof(harness.lastProof)).toBeUndefined();
		expect(result.lease.release().state).toBe("released");
	});

	it("releases CAS before rejecting thenable or malformed root results", () => {
		for (const rootResult of ["thenable", "malformed"] as const) {
			const f = fixture();
			const harness = contractHarness(f, { rootResult });
			const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
			expectAcquired(result);
			expect(result.lease.withRoot(() => "value")).toEqual({
				state: "unavailable",
				reason: "admission_contract_invalid",
			});
			expect(harness.releaseCalls).toBe(1);
			expect(inspectIncidentRecorderWriterLifecycleProof(harness.lastProof)).toBeUndefined();
			expect(result.lease.release().state).toBe("released");
		}
	});

	it("fails closed before lifecycle publication when activation is invalid", () => {
		const f = fixture();
		const harness = contractHarness(f, { activationValid: false });
		expect(acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract)).toEqual({
			state: "unavailable",
			reason: "activation_invalid",
		});
		expect(readdirSync(f.base).some((name) => name.startsWith(".grimoire-incident-writer-lifecycle"))).toBe(false);
	});

	it("maps CAS admission, detachment, and release uncertainty to explicit non-commit outcomes", () => {
		for (const [options, reason] of [
			[{ casState: "unavailable" as const }, "cas_unavailable"],
			[{ rootResult: "root_detached" as const }, "root_detached"],
			[{ releasePending: true }, "cas_release_pending"],
		] as const) {
			const f = fixture();
			const harness = contractHarness(f, options);
			const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
			expectAcquired(result);
			expect(result.lease.withRoot(() => "value")).toEqual({ state: "unavailable", reason });
			expect(result.lease.release().state).toBe("released");
		}
	});

	it("invalidates an old lease before admission when a bound namespace member is replaced", () => {
		const f = fixture();
		const harness = contractHarness(f);
		const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(result);
		const displaced = `${f.recorder}.old`;
		renameSync(f.recorder, displaced);
		mkdirSync(f.recorder, { mode: 0o700 });
		expect(result.lease.withRoot(() => "must-not-run")).toEqual({
			state: "unavailable",
			reason: "namespace_changed",
		});
		expect(harness.acquireCalls).toBe(0);
		expect(result.lease.release().state).toBe("released");
		expect(acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract)).toEqual({
			state: "unavailable",
			reason: "namespace_detached",
		});
		const recovery = acquireIncidentRecorderWriterRecoveryLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(recovery);
		expect(recovery.lease.release().state).toBe("released");
		const successor = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(successor);
		expect(successor.lease.release().state).toBe("released");
	});

	it("treats replacement during the callback as non-commit and revokes the scoped root", () => {
		const f = fixture();
		const harness = contractHarness(f);
		const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(result);
		let captured: IncidentCasRootMutation | undefined;
		const outcome = result.lease.withRoot((root) => {
			captured = root;
			renameSync(f.incidents, `${f.incidents}.old`);
			mkdirSync(f.incidents, { mode: 0o700 });
			return "written-to-displaced-root";
		});
		expect(outcome).toEqual({ state: "unavailable", reason: "namespace_changed" });
		expect(() => captured?.exists(captured.relative("late"))).toThrow(/no longer active/);
		expect(result.lease.release().state).toBe("released");
	});

	it("blocks a generation replacement contender while an exact live holder remains", () => {
		const f = fixture();
		const firstHarness = contractHarness(f, { generationDigest: GENERATION_A });
		const secondHarness = contractHarness(f, { generationDigest: GENERATION_B });
		const first = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, firstHarness.contract);
		expectAcquired(first);
		expect(acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, secondHarness.contract)).toEqual({
			state: "unavailable",
			reason: "namespace_transition_blocked",
		});
		expect(first.lease.release().state).toBe("released");
		const successor = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, secondHarness.contract);
		expectAcquired(successor);
		expect(successor.lease.release().state).toBe("released");
	});

	it("reaps an exact dead owner automatically and makes the displaced handle unusable", () => {
		const f = fixture();
		const firstIdentity = identity(10_001);
		const secondIdentity = identity(10_002);
		const firstRuntime = registerTestRuntime(runtimeFor(firstIdentity));
		const secondRuntime = registerTestRuntime(runtimeFor(secondIdentity));
		const harness = contractHarness(f);
		const first = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract, firstRuntime);
		expectAcquired(first);
		const second = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: f.agentDir },
			harness.contract,
			secondRuntime,
		);
		expectAcquired(second);
		expect(first.lease.withRoot(() => "stale")).toEqual({
			state: "unavailable",
			reason: "lease_lost",
		});
		expect(first.lease.release().state).toBe("released");
		expect(second.lease.release().state).toBe("released");
	});

	it("preserves a crashed holder's old binding as durable detachment after namespace replacement", () => {
		const f = fixture();
		const crashedIdentity = identity(10_101);
		const successorIdentity = identity(10_102);
		const crashedRuntime = registerTestRuntime(runtimeFor(crashedIdentity));
		const successorRuntime = registerTestRuntime(runtimeFor(successorIdentity));
		const harness = contractHarness(f);
		const crashed = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: f.agentDir },
			harness.contract,
			crashedRuntime,
		);
		expectAcquired(crashed);
		renameSync(f.incidents, `${f.incidents}.crashed`);
		mkdirSync(f.incidents, { mode: 0o700 });

		expect(
			acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract, successorRuntime),
		).toEqual({ state: "unavailable", reason: "namespace_detached" });
		const recovery = acquireIncidentRecorderWriterRecoveryLease(
			{ agentDir: f.agentDir },
			harness.contract,
			successorRuntime,
		);
		expectAcquired(recovery);
		expect(recovery.lease.release()).toEqual({ state: "released", cleanupPending: false });
		const successor = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: f.agentDir },
			harness.contract,
			successorRuntime,
		);
		expectAcquired(successor);
		expect(successor.lease.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it("distinguishes PID reuse by exact process-start and uid identity", () => {
		const f = fixture();
		const firstIdentity = identity(11_001, "proc:111");
		const secondIdentity = identity(11_002, "proc:222");
		const firstRuntime = registerTestRuntime(runtimeFor(firstIdentity));
		const reusedRuntime = registerTestRuntime(
			runtimeFor(secondIdentity, (pid) =>
				pid === firstIdentity.pid
					? { state: "present", identity: { ...firstIdentity, processStartId: "proc:999" } }
					: pid === secondIdentity.pid
						? { state: "present", identity: secondIdentity }
						: { state: "absent" },
			),
		);
		const harness = contractHarness(f);
		const first = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract, firstRuntime);
		expectAcquired(first);
		const successor = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: f.agentDir },
			harness.contract,
			reusedRuntime,
		);
		expectAcquired(successor);
		expect(successor.lease.release().state).toBe("released");
		expect(first.lease.release().state).toBe("released");
	});

	it("fails closed when a holder's exact process identity cannot be observed", () => {
		const f = fixture();
		const firstIdentity = identity(12_001);
		const secondIdentity = identity(12_002);
		const firstRuntime = registerTestRuntime(runtimeFor(firstIdentity));
		const unknownRuntime = registerTestRuntime(
			runtimeFor(secondIdentity, (pid) =>
				pid === firstIdentity.pid
					? { state: "unavailable", reason: "proc_unavailable" }
					: { state: "present", identity: secondIdentity },
			),
		);
		const harness = contractHarness(f);
		const first = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract, firstRuntime);
		expectAcquired(first);
		expect(
			acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract, unknownRuntime),
		).toEqual({ state: "unavailable", reason: "owner_liveness_unknown" });
		expect(first.lease.release().state).toBe("released");
	});

	it("repairs bounded fixed crash residue at every publication role", () => {
		for (const artifact of ["gate", "normal", "recovery_pending", "recovery"] as const) {
			const f = fixture();
			const crashingIdentity = identity(20_000 + artifact.length);
			const recoveringIdentity = identity(30_000 + artifact.length);
			const faultRuntime = registerTestRuntime(
				runtimeFor(crashingIdentity, undefined, (step, currentArtifact) => {
					if (step === "record_linked" && currentArtifact === artifact) throw new Error(`crash:${artifact}`);
				}),
			);
			const recoveryRuntime = registerTestRuntime(runtimeFor(recoveringIdentity));
			const harness = contractHarness(f);
			const action =
				artifact === "gate" || artifact === "normal"
					? acquireIncidentRecorderWriterNormalLease
					: acquireIncidentRecorderWriterRecoveryLease;
			expect(() => action({ agentDir: f.agentDir }, harness.contract, faultRuntime)).toThrow(`crash:${artifact}`);
			const repaired = acquireIncidentRecorderWriterNormalLease(
				{ agentDir: f.agentDir },
				harness.contract,
				recoveryRuntime,
			);
			expectAcquired(repaired);
			expect(repaired.lease.release().state).toBe("released");
			const entries = readdirSync(lifecycleControlDirectory(f.base));
			expect(
				entries.every((name) =>
					/^(?:gate|detachment|recovery|recovery-pending|normal-[0-3][0-9])(?:\.json|\.prepare)$/.test(name),
				),
			).toBe(true);
		}
	});

	it("preserves the primary acquisition failure when gate release also fails", () => {
		const f = fixture();
		const crashingIdentity = identity(24_001);
		const recoveringIdentity = identity(24_002);
		const faultRuntime = registerTestRuntime(
			runtimeFor(crashingIdentity, undefined, (step, artifact) => {
				if (step === "record_linked" && artifact === "normal") throw new Error("primary-normal-fault");
				if (step === "before_record_release" && artifact === "gate")
					throw new Error("secondary-gate-release-fault");
			}),
		);
		const recoveryRuntime = registerTestRuntime(runtimeFor(recoveringIdentity));
		const harness = contractHarness(f);
		expect(() =>
			acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract, faultRuntime),
		).toThrow("primary-normal-fault");
		const repaired = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: f.agentDir },
			harness.contract,
			recoveryRuntime,
		);
		expectAcquired(repaired);
		expect(repaired.lease.release().state).toBe("released");
	});

	it("fails closed on unknown control residue without unbounded discovery", () => {
		const f = fixture();
		const harness = contractHarness(f);
		const initial = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract);
		expectAcquired(initial);
		expect(initial.lease.release().state).toBe("released");
		writeFileSync(join(lifecycleControlDirectory(f.base), "unbounded-surprise"), "x", { mode: 0o600 });
		expect(acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, harness.contract)).toEqual({
			state: "unavailable",
			reason: "invalid_control_artifact",
		});
	});

	it("keys independent agent directories under one stable parent without coupling their holders", () => {
		const base = mkdtempSync(join(tmpdir(), "grimoire-writer-lifecycle-shared-"));
		cleanupPaths.push(base);
		const firstFixture = makeAgentDir(base, "agent-a");
		const secondFixture = makeAgentDir(base, "agent-b");
		const firstHarness = contractHarness(firstFixture);
		const secondHarness = contractHarness(secondFixture);
		const first = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: firstFixture.agentDir },
			firstHarness.contract,
		);
		const second = acquireIncidentRecorderWriterNormalLease(
			{ agentDir: secondFixture.agentDir },
			secondHarness.contract,
		);
		expectAcquired(first);
		expectAcquired(second);
		expect(
			readdirSync(base).filter((name) => name.startsWith(".grimoire-incident-writer-lifecycle-v1-")),
		).toHaveLength(2);
		expect(first.lease.release().state).toBe("released");
		expect(second.lease.release().state).toBe("released");
	});

	it("rejects a forged test runtime handle", () => {
		const f = fixture();
		const harness = contractHarness(f);
		expect(() =>
			acquireIncidentRecorderWriterNormalLease(
				{ agentDir: f.agentDir },
				harness.contract,
				Object.freeze({}) as IncidentRecorderWriterLifecycleTestRuntimeHandle,
			),
		).toThrow(/unregistered writer lifecycle test runtime/);
	});

	it.runIf(process.platform === "linux")(
		"blocks a cross-process replacement contender without delegating a diagnostic directory fd",
		async () => {
			const f = fixture();
			const moduleUrl = new URL("../src/modes/daemon/incident-recorder-writer-lifecycle.ts", import.meta.url).href;
			const script = `
				import { acquireIncidentRecorderWriterNormalLease } from ${JSON.stringify(moduleUrl)};
				const contract = {
					activationGenerationDigest: ${JSON.stringify(GENERATION_A)},
					revalidateActivation: () => ({ state: "valid" }),
					acquireCas: () => { throw new Error("CAS must not be entered by the holder fixture"); },
				};
				const result = acquireIncidentRecorderWriterNormalLease(
					{ agentDir: ${JSON.stringify(f.agentDir)} },
					contract,
				);
				if (result.state !== "acquired") throw new Error(JSON.stringify(result));
				if (Object.keys(result.lease).some((key) => /fd|descriptor/i.test(key))) throw new Error("fd exposed");
				process.stdout.write("READY\\n");
				process.on("SIGTERM", () => {
					const released = result.lease.release();
					process.stdout.write("RELEASED:" + released.state + "\\n");
					process.exit(released.state === "released" ? 0 : 2);
				});
				setInterval(() => {}, 1_000);
			`;
			const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", script], {
				env: { ...process.env },
				stdio: ["pipe", "pipe", "pipe"],
			});
			children.add(child);
			await waitForLine(child, "READY");

			const displaced = `${f.agentDir}.old`;
			renameSync(f.agentDir, displaced);
			makeAgentDir(f.base, "agent");
			const contenderHarness = contractHarness(f);
			expect(acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, contenderHarness.contract)).toEqual({
				state: "unavailable",
				reason: "namespace_transition_blocked",
			});

			child.kill("SIGTERM");
			await waitForExit(child);
			expect(child.exitCode).toBe(0);
			children.delete(child);
			expect(acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, contenderHarness.contract)).toEqual({
				state: "unavailable",
				reason: "namespace_detached",
			});
			const recovery = acquireIncidentRecorderWriterRecoveryLease(
				{ agentDir: f.agentDir },
				contenderHarness.contract,
			);
			expectAcquired(recovery);
			expect(recovery.lease.release().state).toBe("released");
			const successor = acquireIncidentRecorderWriterNormalLease(
				{ agentDir: f.agentDir },
				contenderHarness.contract,
			);
			expectAcquired(successor);
			expect(successor.lease.release().state).toBe("released");
		},
	);
});
