import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	chmodSync,
	existsSync,
	linkSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	symlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	acquireIncidentCasTransaction,
	acquireIncidentCasTransactionDetailed,
	type IncidentCasRelativePath,
	type IncidentCasRootMutation,
	type IncidentCasTransactionStep,
	registerIncidentCasDetachmentRecoveryTestSynchronization,
	registerIncidentCasPrepareRetirementTestSynchronization,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";

const cleanupPaths: string[] = [];
const children: ChildProcess[] = [];
const moduleUrl = pathToFileURL(
	fileURLToPath(new URL("../src/modes/daemon/incident-recorder-cas-transaction.ts", import.meta.url)),
).href;
const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));

function fixture(): { base: string; recorder: string } {
	const base = mkdtempSync(join(tmpdir(), "grimoire-cas-v2-"));
	cleanupPaths.push(base);
	const recorder = join(base, "recorder");
	mkdirSync(recorder, { mode: 0o700 });
	return { base, recorder };
}

afterEach(() => {
	for (const child of children.splice(0)) {
		if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
	}
	for (const path of cleanupPaths.splice(0).reverse()) rmSync(path, { recursive: true, force: true });
});

function currentIdentity(): {
	machineId: string;
	bootId: string;
	pid: number;
	processStartId: string;
} {
	const processStartId = getProcessStartId(process.pid);
	if (!processStartId) throw new Error("test process has no stable start identity");
	return {
		machineId: readFileSync("/etc/machine-id", "utf8").trim(),
		bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
		pid: process.pid,
		processStartId,
	};
}

function controlName(recorder: string): string {
	const canonical = realpathSync.native(recorder);
	return `.grimoire-incident-cas-v2-${createHash("sha256").update(canonical).digest("hex").slice(0, 32)}`;
}

function authorityPath(recorder: string): string {
	return join(dirname(realpathSync.native(recorder)), controlName(recorder));
}

function detachedEvidencePath(recorder: string): string {
	return `${authorityPath(recorder)}.detached-slot`;
}

function detachmentPreparePath(recorder: string): string {
	return `${authorityPath(recorder)}.prepare-detachment`;
}

function controlEntries(recorder: string, suffix: string): string[] {
	const name = controlName(recorder);
	return readdirSync(dirname(realpathSync.native(recorder))).filter((entry) => entry.startsWith(`${name}.${suffix}`));
}

function ownerBytes(lock: string, recorder: string, overrides: Record<string, unknown> = {}): string {
	const stats = statSync(lock, { bigint: true });
	const root = statSync(recorder, { bigint: true });
	return `${JSON.stringify({
		type: "incident-recorder-cas-decision",
		version: 2,
		kind: "owner",
		lockId: randomUUID(),
		lockDev: stats.dev.toString(),
		lockIno: stats.ino.toString(),
		rootDev: root.dev.toString(),
		rootIno: root.ino.toString(),
		rootPath: realpathSync.native(recorder),
		...currentIdentity(),
		...overrides,
	})}\n`;
}

function legacyOwnerBytes(overrides: Record<string, unknown> = {}): string {
	return `${JSON.stringify({ version: 1, ...currentIdentity(), ...overrides })}\n`;
}

function completeErrorDisclosure(value: unknown): string {
	const seen = new Set<object>();
	const visit = (candidate: unknown, depth: number): string => {
		if (candidate === null || typeof candidate !== "object") return String(candidate);
		if (seen.has(candidate) || depth > 8) return "[seen]";
		seen.add(candidate);
		const details: string[] = [];
		for (const key of Object.getOwnPropertyNames(candidate)) {
			try {
				details.push(`${key}=${visit(Reflect.get(candidate, key), depth + 1)}`);
			} catch {
				details.push(`${key}=[unreadable]`);
			}
		}
		return `${String(candidate)} {${details.join(",")}}`;
	};
	return visit(value, 0);
}

function childEval(script: string): ChildProcess {
	const child = spawn(process.execPath, ["--import", tsxLoader, "--input-type=module", "--eval", script], {
		stdio: ["pipe", "pipe", "pipe"],
	});
	children.push(child);
	return child;
}

async function waitForOutput(child: ChildProcess, expected: string, timeoutMs = 5_000): Promise<string> {
	let stdout = "";
	let stderr = "";
	child.stdout?.setEncoding("utf8");
	child.stderr?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		stdout += chunk;
	});
	child.stderr?.on("data", (chunk: string) => {
		stderr += chunk;
	});
	const deadline = Date.now() + timeoutMs;
	while (!stdout.includes(expected)) {
		if (child.exitCode !== null || child.signalCode !== null)
			throw new Error(`child exited before ${expected}: ${stdout}\n${stderr}`);
		if (Date.now() >= deadline) throw new Error(`timed out waiting for ${expected}: ${stdout}\n${stderr}`);
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	return stdout;
}

async function waitUntil(predicate: () => boolean, description: string, timeoutMs = 5_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error(`timed out waiting for ${description}`);
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

async function startHolder(recorder: string): Promise<ChildProcess> {
	const script = `
		import { acquireIncidentCasTransactionDetailed } from ${JSON.stringify(moduleUrl)};
		const admission = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)});
		if (admission.state !== "acquired") {
			process.stderr.write(JSON.stringify(admission));
			process.exit(20);
		}
		process.stdout.write("ready\\n");
		process.stdin.setEncoding("utf8");
		process.stdin.once("data", () => {
			process.stdout.write(JSON.stringify(admission.transaction.release()) + "\\n", () => process.exit(0));
		});
	`;
	const child = childEval(script);
	await waitForOutput(child, "ready\n");
	return child;
}

function crashAt(recorder: string, boundary: IncidentCasTransactionStep, mode: "create" | "release"): void {
	const script = `
		import { acquireIncidentCasTransactionDetailed } from ${JSON.stringify(moduleUrl)};
		const admission = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
			onStep(step) {
				if (step === ${JSON.stringify(boundary)}) process.kill(process.pid, "SIGKILL");
			},
		});
		if (admission.state !== "acquired") process.exit(31);
		if (${JSON.stringify(mode)} === "release") admission.transaction.release();
		process.exit(32);
	`;
	const result = spawnSync(process.execPath, ["--import", tsxLoader, "--input-type=module", "--eval", script], {
		encoding: "utf8",
		timeout: 5_000,
	});
	expect(result.signal, `${boundary}: ${result.stdout}\n${result.stderr}`).toBe("SIGKILL");
}

function crashDetachmentAt(recorder: string, boundary: IncidentCasTransactionStep): void {
	const displaced = `${recorder}-detached`;
	const script = `
		import { mkdirSync, renameSync } from "node:fs";
		import { acquireIncidentCasTransactionDetailed } from ${JSON.stringify(moduleUrl)};
		const admission = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
			onStep(step) {
				if (step === ${JSON.stringify(boundary)}) process.kill(process.pid, "SIGKILL");
			},
		});
		if (admission.state !== "acquired") process.exit(71);
		admission.transaction.withRoot(() => {
			renameSync(${JSON.stringify(recorder)}, ${JSON.stringify(displaced)});
			mkdirSync(${JSON.stringify(recorder)}, { mode: 0o700 });
		});
		process.exit(72);
	`;
	const result = spawnSync(process.execPath, ["--import", tsxLoader, "--input-type=module", "--eval", script], {
		encoding: "utf8",
		timeout: 5_000,
	});
	expect(result.signal, `${boundary}: ${result.stdout}\n${result.stderr}`).toBe("SIGKILL");
}

function probeAdmissionInChild(recorder: string): unknown {
	const script = `
		import { acquireIncidentCasTransactionDetailed } from ${JSON.stringify(moduleUrl)};
		const admission = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)});
		if (admission.state === "acquired") admission.transaction.release();
		process.stdout.write(JSON.stringify(admission.state === "acquired" ? { state: "acquired" } : admission));
	`;
	const result = spawnSync(process.execPath, ["--import", tsxLoader, "--input-type=module", "--eval", script], {
		encoding: "utf8",
		timeout: 5_000,
	});
	if (result.status !== 0) throw new Error(`child admission failed: ${result.stdout}\n${result.stderr}`);
	return JSON.parse(result.stdout);
}

function crashQuarantineAt(recorder: string, boundary: IncidentCasTransactionStep): void {
	const script = `
		import { acquireIncidentCasTransactionDetailed } from ${JSON.stringify(moduleUrl)};
		let monotonic = 0;
		const first = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
			monotonicTimeMs: () => monotonic,
		});
		if (first.state !== "unavailable" || first.reason !== "invalid_owner_grace") process.exit(51);
		monotonic = 5_001;
		const admission = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
			monotonicTimeMs: () => monotonic,
			onStep(step) {
				if (step === ${JSON.stringify(boundary)}) process.kill(process.pid, "SIGKILL");
			},
		});
		if (admission.state === "acquired") admission.transaction.release();
		process.exit(52);
	`;
	const result = spawnSync(process.execPath, ["--import", tsxLoader, "--input-type=module", "--eval", script], {
		encoding: "utf8",
		timeout: 5_000,
	});
	expect(result.signal, `${boundary}: ${result.stdout}\n${result.stderr}`).toBe("SIGKILL");
}

function recoverAfterCrash(recorder: string): void {
	let monotonic = 0;
	let admission = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => monotonic });
	if (
		admission.state === "unavailable" &&
		(admission.reason === "invalid_owner_grace" || admission.reason === "control_artifact_grace")
	) {
		monotonic = 5_001;
		admission = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => monotonic });
	}
	expect(admission).toMatchObject({ state: "acquired" });
	if (admission.state === "acquired") expect(admission.transaction.release()).toMatchObject({ state: "released" });
}

function startPausedReaper(recorder: string, marker: string): ChildProcess {
	const script = `
		import { writeFileSync } from "node:fs";
		import {
			acquireIncidentCasTransaction,
			acquireIncidentCasTransactionDetailed,
		} from ${JSON.stringify(moduleUrl)};
		const admission = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
			onStep(step) {
				if (step === "before_quarantine_move") {
					writeFileSync(${JSON.stringify(marker)}, "ready\\n", { mode: 0o600 });
					process.kill(process.pid, "SIGSTOP");
				}
			},
		});
		if (admission.state !== "acquired") {
			process.stdout.write(JSON.stringify(admission) + "\\n", () => process.exit(0));
		} else {
			const nested = acquireIncidentCasTransaction(${JSON.stringify(recorder)});
			if (!nested) process.exit(40);
			process.stdout.write("acquired\\nnested\\n");
			process.stdin.setEncoding("utf8");
			process.stdin.once("data", () => {
				nested.release();
				process.stdout.write(JSON.stringify(admission.transaction.release()) + "\\n", () => process.exit(0));
			});
		}
	`;
	return childEval(script);
}

function admissionResultTail(recorder: string): string {
	return `
		if (admission.state !== "acquired") {
			process.stdout.write(JSON.stringify(admission) + "\\n", () => process.exit(0));
		} else {
			const nested = acquireIncidentCasTransaction(${JSON.stringify(recorder)});
			if (!nested) process.exit(40);
			process.stdout.write("acquired\\nnested\\n");
			process.stdin.setEncoding("utf8");
			process.stdin.once("data", () => {
				nested.release();
				process.stdout.write(JSON.stringify(admission.transaction.release()) + "\\n", () => process.exit(0));
			});
		}
	`;
}

function startPausedCreator(recorder: string, marker: string): ChildProcess {
	const script = `
		import { writeFileSync } from "node:fs";
		import {
			acquireIncidentCasTransaction,
			acquireIncidentCasTransactionDetailed,
		} from ${JSON.stringify(moduleUrl)};
		const admission = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
			onStep(step) {
				if (step === "owner_fsynced") {
					writeFileSync(${JSON.stringify(marker)}, "ready\\n", { mode: 0o600 });
					process.kill(process.pid, "SIGSTOP");
				}
			},
		});
		${admissionResultTail(recorder)}
	`;
	return childEval(script);
}

describe.runIf(process.platform === "linux")("incident recorder CAS v2", () => {
	it("acquires an empty root, reenters through a canonical alias, and retires on the final release", () => {
		const { base, recorder } = fixture();
		const alias = join(base, "recorder-alias");
		symlinkSync(recorder, alias, "dir");
		const steps: IncidentCasTransactionStep[] = [];
		const firstAdmission = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => steps.push(step),
		});
		expect(firstAdmission, JSON.stringify({ firstAdmission, steps })).toMatchObject({ state: "acquired" });
		if (firstAdmission.state !== "acquired") return;
		const nested = acquireIncidentCasTransaction(alias);
		expect(nested).toBeDefined();
		const lock = authorityPath(recorder);
		expect(statSync(lock).mode & 0o777).toBe(0o700);
		expect(firstAdmission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		expect(existsSync(lock)).toBe(true);
		expect(nested?.release()).toEqual({ state: "released", cleanupPending: false });
		expect(existsSync(lock)).toBe(false);
	});

	it("blocks renewal through a replaced canonical root until the old authority is safely released", () => {
		const { base, recorder } = fixture();
		const original = acquireIncidentCasTransactionDetailed(recorder);
		expect(original).toMatchObject({ state: "acquired" });
		if (original.state !== "acquired") return;
		const displacedRoot = join(base, "displaced-recorder-root");
		renameSync(recorder, displacedRoot);
		mkdirSync(recorder, { mode: 0o700 });
		const renewal = acquireIncidentCasTransactionDetailed(recorder);
		if (renewal.state === "acquired") renewal.transaction.release();
		expect(renewal).toEqual({ state: "unavailable", reason: "local_ownership_changed" });
		expect(existsSync(authorityPath(recorder))).toBe(true);
		expect(original.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		const afterRelease = acquireIncidentCasTransactionDetailed(recorder);
		expect(afterRelease).toMatchObject({ state: "acquired" });
		if (afterRelease.state === "acquired") afterRelease.transaction.release();
	});

	it("blocks a replacement-root contender and poisons a descriptor-rooted mutation that observes detachment", async () => {
		const { base, recorder } = fixture();
		const original = acquireIncidentCasTransactionDetailed(recorder);
		expect(original).toMatchObject({ state: "acquired" });
		if (original.state !== "acquired") return;
		const displacedRoot = join(base, "displaced-recorder-root");
		let contenderAdmission: unknown;
		const mutation = original.transaction.withRoot((root) => {
			renameSync(recorder, displacedRoot);
			mkdirSync(recorder, { mode: 0o700 });
			contenderAdmission = probeAdmissionInChild(recorder);
			root.writeFileExclusive(root.relative("holder-only"), "old-root\n");
		});
		expect(mutation).toEqual({ state: "root_detached", evidence: "durable" });
		expect(contenderAdmission).toEqual({ state: "unavailable", reason: "live_owner" });
		let detachedCallbackInvoked = false;
		expect(
			original.transaction.withRoot(() => {
				detachedCallbackInvoked = true;
			}),
		).toEqual({ state: "root_detached", evidence: "durable" });
		expect(detachedCallbackInvoked).toBe(false);
		expect(existsSync(join(displacedRoot, "holder-only"))).toBe(false);
		expect(existsSync(join(recorder, "holder-only"))).toBe(false);
		expect(controlEntries(recorder, "detached-")).toHaveLength(1);
		expect(original.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		expect(() => original.transaction.withRoot(() => undefined)).toThrow(/released/i);
		const contender = await startHolder(recorder);
		contender.stdin?.write("release\n");
		await new Promise<void>((resolve) => contender.once("exit", () => resolve()));
	});

	it.each(["root_detachment_linked", "root_detachment_root_fsynced"] satisfies IncidentCasTransactionStep[])(
		"recovers after a real detachment-evidence SIGKILL at %s",
		(boundary) => {
			const { recorder } = fixture();
			crashDetachmentAt(recorder, boundary);
			expect(controlEntries(recorder, "detached-")).toHaveLength(1);
			recoverAfterCrash(recorder);
		},
	);

	it("retires a dead owner's pre-link detachment prepare before admitting a detachable successor", () => {
		const { base, recorder } = fixture();
		crashDetachmentAt(recorder, "before_root_detachment_link");
		expect(existsSync(detachmentPreparePath(recorder))).toBe(true);
		expect(existsSync(detachedEvidencePath(recorder))).toBe(false);

		const successor = acquireIncidentCasTransactionDetailed(recorder);
		expect(successor).toMatchObject({ state: "acquired" });
		if (successor.state !== "acquired") return;
		const displacedSuccessorRoot = join(base, "successor-detached-root");
		const mutation = successor.transaction.withRoot(() => {
			renameSync(recorder, displacedSuccessorRoot);
			mkdirSync(recorder, { mode: 0o700 });
		});
		expect(mutation).toEqual({ state: "root_detached", evidence: "durable" });
		expect(probeAdmissionInChild(recorder)).toEqual({ state: "unavailable", reason: "live_owner" });
		expect(successor.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		expect(existsSync(detachmentPreparePath(recorder))).toBe(false);
		expect(existsSync(detachedEvidencePath(recorder))).toBe(false);
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);

		const recovered = acquireIncidentCasTransactionDetailed(recorder);
		expect(recovered).toMatchObject({ state: "acquired" });
		if (recovered.state === "acquired") {
			expect(recovered.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		}
	});

	it("does not let a delayed stale-prepare cleaner unlink a successor prepare at the same-inode endpoint", () => {
		const { recorder } = fixture();
		crashDetachmentAt(recorder, "before_root_detachment_link");
		const prepare = detachmentPreparePath(recorder);
		const retainedClaim = `${prepare}.retire-claim`;
		const fixed = authorityPath(recorder);
		expect(existsSync(prepare)).toBe(true);
		const runtime = {};
		let raceInjected = false;
		let successorOwnerBytes = "";
		let successorPrepareBytes = "";
		const unregister = registerIncidentCasPrepareRetirementTestSynchronization(runtime, () => {
			raceInjected = true;
			mkdirSync(fixed, { mode: 0o700 });
			successorOwnerBytes = ownerBytes(fixed, recorder);
			writeFileSync(join(fixed, "owner.json"), successorOwnerBytes, { mode: 0o600 });
			const successorOwner = JSON.parse(successorOwnerBytes) as Record<string, unknown>;
			successorPrepareBytes = `${JSON.stringify({
				type: "incident-recorder-cas-root-detachment",
				version: 2,
				detachId: randomUUID(),
				lockId: successorOwner.lockId,
				lockDev: successorOwner.lockDev,
				lockIno: successorOwner.lockIno,
				rootDev: successorOwner.rootDev,
				rootIno: successorOwner.rootIno,
				rootPath: successorOwner.rootPath,
				machineId: successorOwner.machineId,
				bootId: successorOwner.bootId,
				pid: successorOwner.pid,
				processStartId: successorOwner.processStartId,
			})}\n`;
			// Rewriting the already validated inode models the same-numeric-inode
			// endpoint after an intervening unlink and filesystem inode reuse.
			writeFileSync(prepare, successorPrepareBytes, { mode: 0o600 });
		});
		let admission: ReturnType<typeof acquireIncidentCasTransactionDetailed>;
		try {
			admission = acquireIncidentCasTransactionDetailed(recorder, runtime);
		} finally {
			unregister();
		}

		expect(raceInjected).toBe(true);
		expect(admission.state).toBe("unavailable");
		if (admission.state === "unavailable") {
			expect(["control_artifact_busy", "same_process_owner_untracked"]).toContain(admission.reason);
		}
		expect(readFileSync(join(fixed, "owner.json"), "utf8")).toBe(successorOwnerBytes);
		expect(existsSync(prepare)).toBe(true);
		expect(readFileSync(prepare, "utf8")).toBe(successorPrepareBytes);
		expect(existsSync(detachedEvidencePath(recorder))).toBe(false);
		expect(existsSync(retainedClaim)).toBe(false);
	});

	it("fails closed when the validated control parent pathname is replaced", () => {
		const { base, recorder } = fixture();
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		const displacedParent = `${base}-displaced-${randomUUID()}`;
		renameSync(base, displacedParent);
		mkdirSync(base, { mode: 0o700 });
		mkdirSync(recorder, { mode: 0o700 });
		let invoked = false;
		expect(
			admission.transaction.withRoot(() => {
				invoked = true;
			}),
		).toEqual({ state: "root_detached", evidence: "pending" });
		expect(invoked).toBe(false);
		expect(admission.transaction.release()).toEqual({ state: "pending", reason: "root_identity_changed" });
		rmSync(base, { recursive: true, force: true });
		renameSync(displacedParent, base);
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it.each(["root_detachment_linked", "root_detachment_root_fsynced"] satisfies IncidentCasTransactionStep[])(
		"keeps exclusion across a %s persistence failure and retires the fixed detachment slot",
		(boundary) => {
			const { base, recorder } = fixture();
			let failPersistence = true;
			const admission = acquireIncidentCasTransactionDetailed(recorder, {
				onStep: (step) => {
					if (
						failPersistence &&
						(step === boundary ||
							(boundary === "root_detachment_linked" && step === "root_detachment_root_fsynced"))
					) {
						throw new Error(`injected ${boundary} persistence failure`);
					}
				},
			});
			expect(admission).toMatchObject({ state: "acquired" });
			if (admission.state !== "acquired") return;
			const displacedRoot = join(base, "detachment-persistence-old-root");
			expect(
				admission.transaction.withRoot(() => {
					renameSync(recorder, displacedRoot);
					mkdirSync(recorder, { mode: 0o700 });
				}),
			).toEqual({ state: "root_detached", evidence: "pending" });
			expect(admission.transaction.release()).toEqual({ state: "pending", reason: "io_error" });
			expect(controlEntries(recorder, "detached-")).toHaveLength(1);
			expect(probeAdmissionInChild(recorder)).toEqual({ state: "unavailable", reason: "live_owner" });
			failPersistence = false;
			expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
			expect(controlEntries(recorder, "detached-")).toHaveLength(0);
			const successor = acquireIncidentCasTransactionDetailed(recorder);
			expect(successor).toMatchObject({ state: "acquired" });
			if (successor.state === "acquired") successor.transaction.release();
		},
	);

	it("binds durable detachment evidence to the exact authority and owner process", () => {
		const { base, recorder } = fixture();
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		const owner = JSON.parse(readFileSync(join(authorityPath(recorder), "owner.json"), "utf8")) as Record<
			string,
			unknown
		>;
		const displacedRoot = join(base, "bound-detachment-old-root");
		expect(
			admission.transaction.withRoot(() => {
				renameSync(recorder, displacedRoot);
				mkdirSync(recorder, { mode: 0o700 });
			}),
		).toEqual({ state: "root_detached", evidence: "durable" });
		const evidence = JSON.parse(readFileSync(detachedEvidencePath(recorder), "utf8")) as Record<string, unknown>;
		expect(evidence).toMatchObject({
			lockId: owner.lockId,
			lockDev: owner.lockDev,
			lockIno: owner.lockIno,
			machineId: owner.machineId,
			bootId: owner.bootId,
			pid: owner.pid,
			processStartId: owner.processStartId,
		});
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it.each([
		"root_detachment_fsynced" as IncidentCasTransactionStep,
		"before_root_detachment_link" as IncidentCasTransactionStep,
		"root_detachment_linked",
		"before_root_detachment_prepare_unlink" as IncidentCasTransactionStep,
	])("resumes an exact detachment prepare after a %s persistence failure and failed cleanup", (boundary) => {
		const { base, recorder } = fixture();
		let injected = false;
		const admission = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step !== boundary || injected) return;
				injected = true;
				chmodSync(base, 0o500);
				throw new Error(`injected ${boundary} failure with prepare unlink denied`);
			},
		});
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		const displacedRoot = join(base, `prepare-recovery-old-root-${boundary}`);
		const mutation = (() => {
			try {
				return admission.transaction.withRoot(() => {
					renameSync(recorder, displacedRoot);
					mkdirSync(recorder, { mode: 0o700 });
				});
			} finally {
				chmodSync(base, 0o700);
			}
		})();
		expect(injected).toBe(true);
		expect(mutation).toEqual({ state: "root_detached", evidence: "pending" });
		expect(existsSync(detachmentPreparePath(recorder)) || existsSync(detachedEvidencePath(recorder))).toBe(true);
		expect(probeAdmissionInChild(recorder)).toEqual({ state: "unavailable", reason: "live_owner" });
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		expect(existsSync(detachmentPreparePath(recorder))).toBe(false);
		expect(existsSync(detachedEvidencePath(recorder))).toBe(false);
		recoverAfterCrash(recorder);
	});

	it("resumes a crashed detachment prepare retirement with an existing claim", () => {
		const { recorder } = fixture();
		crashDetachmentAt(recorder, "before_root_detachment_prepare_unlink");
		const prepare = detachmentPreparePath(recorder);
		const detached = detachedEvidencePath(recorder);
		const claim = `${prepare}.retire-claim`;
		expect(statSync(prepare, { bigint: true }).nlink).toBe(2n);
		linkSync(prepare, claim);
		expect(statSync(prepare, { bigint: true }).nlink).toBe(3n);
		expect(existsSync(detached)).toBe(true);

		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state === "acquired") {
			expect(admission.transaction.release()).toMatchObject({
				state: "released",
			});
		}
		expect(existsSync(prepare)).toBe(false);
		expect(existsSync(claim)).toBe(false);
		expect(existsSync(detached)).toBe(false);
	});

	it.each(["empty", "oversized"] as const)(
		"keeps a successor when unknown prepare recovery races a %s artifact",
		(kind) => {
			const { recorder } = fixture();
			const prepare = detachmentPreparePath(recorder);
			writeFileSync(prepare, kind === "empty" ? "" : "x".repeat(4_097), {
				mode: 0o600,
			});
			let monotonic = 0;
			const runtime = { monotonicTimeMs: () => monotonic };
			expect(acquireIncidentCasTransactionDetailed(recorder, runtime)).toEqual({
				state: "unavailable",
				reason: "control_artifact_grace",
			});
			monotonic = 5_001;
			const successorBytes = kind === "empty" ? "successor\n" : "y".repeat(4_097);
			let invoked = false;
			const unregister = registerIncidentCasPrepareRetirementTestSynchronization(runtime, () => {
				invoked = true;
				writeFileSync(prepare, successorBytes, { mode: 0o600 });
			});
			let admission: ReturnType<typeof acquireIncidentCasTransactionDetailed>;
			try {
				admission = acquireIncidentCasTransactionDetailed(recorder, runtime);
			} finally {
				unregister();
			}
			expect(invoked).toBe(true);
			expect(admission).toEqual({
				state: "unavailable",
				reason: "control_artifact_busy",
			});
			expect(readFileSync(prepare, "utf8")).toBe(successorBytes);
		},
	);

	it.each(["empty", "oversized"] as const)(
		"keeps a successor when unknown detachment recovery races a %s artifact",
		(kind) => {
			const { recorder } = fixture();
			const detachment = detachedEvidencePath(recorder);
			writeFileSync(detachment, kind === "empty" ? "" : "x".repeat(4_097), {
				mode: 0o600,
			});
			let monotonic = 0;
			const runtime = { monotonicTimeMs: () => monotonic };
			expect(acquireIncidentCasTransactionDetailed(recorder, runtime)).toEqual({
				state: "unavailable",
				reason: "control_artifact_grace",
			});
			monotonic = 5_001;
			const successorBytes = kind === "empty" ? "successor\n" : "y".repeat(4_097);
			let invoked = false;
			const unregister = registerIncidentCasDetachmentRecoveryTestSynchronization(runtime, () => {
				invoked = true;
				writeFileSync(detachment, successorBytes, { mode: 0o600 });
			});
			let admission: ReturnType<typeof acquireIncidentCasTransactionDetailed>;
			try {
				admission = acquireIncidentCasTransactionDetailed(recorder, runtime);
			} finally {
				unregister();
			}
			expect(invoked).toBe(true);
			expect(admission).toEqual({
				state: "unavailable",
				reason: "control_artifact_busy",
			});
			expect(readFileSync(detachment, "utf8")).toBe(successorBytes);
		},
	);

	it.each([
		["prepare", "empty"],
		["prepare", "oversized"],
		["detachment", "empty"],
		["detachment", "oversized"],
	] as const)("retires a source-deleted orphan %s claim with %s bytes after grace", (slot, kind) => {
		const { recorder } = fixture();
		const source = slot === "prepare" ? detachmentPreparePath(recorder) : detachedEvidencePath(recorder);
		const claim = `${source}.retire-claim`;
		writeFileSync(source, kind === "empty" ? "" : "x".repeat(4_097), { mode: 0o600 });
		linkSync(source, claim);
		rmSync(source);
		let monotonic = 0;
		const runtime = { monotonicTimeMs: () => monotonic };
		expect(acquireIncidentCasTransactionDetailed(recorder, runtime)).toEqual({
			state: "unavailable",
			reason: "control_artifact_grace",
		});
		monotonic = 5_001;
		const admission = acquireIncidentCasTransactionDetailed(recorder, runtime);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state === "acquired") admission.transaction.release();
		expect(existsSync(claim)).toBe(false);
	});

	it.each(["prepare", "detachment"] as const)(
		"preserves an in-place rewrite of a source-deleted orphan %s claim",
		(slot) => {
			const { recorder } = fixture();
			const source = slot === "prepare" ? detachmentPreparePath(recorder) : detachedEvidencePath(recorder);
			const claim = `${source}.retire-claim`;
			writeFileSync(source, "", { mode: 0o600 });
			linkSync(source, claim);
			rmSync(source);
			let monotonic = 0;
			const runtime = { monotonicTimeMs: () => monotonic };
			expect(acquireIncidentCasTransactionDetailed(recorder, runtime)).toMatchObject({
				state: "unavailable",
				reason: "control_artifact_grace",
			});
			monotonic = 5_001;
			const successorBytes = "y".repeat(4_097);
			let invoked = false;
			const unregister = registerIncidentCasPrepareRetirementTestSynchronization(runtime, () => {
				invoked = true;
				writeFileSync(claim, successorBytes, { mode: 0o600 });
			});
			let admission: ReturnType<typeof acquireIncidentCasTransactionDetailed>;
			try {
				admission = acquireIncidentCasTransactionDetailed(recorder, runtime);
			} finally {
				unregister();
			}
			expect(invoked).toBe(true);
			expect(admission).toEqual({ state: "unavailable", reason: "control_artifact_busy" });
			expect(readFileSync(claim, "utf8")).toBe(successorBytes);
		},
	);

	it.each(["prepare", "detachment"] as const)(
		"preserves a successor replacing a source-deleted orphan %s claim",
		(slot) => {
			const { recorder } = fixture();
			const source = slot === "prepare" ? detachmentPreparePath(recorder) : detachedEvidencePath(recorder);
			const claim = `${source}.retire-claim`;
			writeFileSync(source, "x".repeat(4_097), { mode: 0o600 });
			linkSync(source, claim);
			rmSync(source);
			let monotonic = 0;
			const runtime = { monotonicTimeMs: () => monotonic };
			expect(acquireIncidentCasTransactionDetailed(recorder, runtime)).toMatchObject({
				state: "unavailable",
				reason: "control_artifact_grace",
			});
			monotonic = 5_001;
			rmSync(claim);
			const successorBytes = "successor\n";
			writeFileSync(claim, successorBytes, { mode: 0o600 });
			expect(acquireIncidentCasTransactionDetailed(recorder, runtime)).toEqual({
				state: "unavailable",
				reason: "control_artifact_grace",
			});
			expect(readFileSync(claim, "utf8")).toBe(successorBytes);
		},
	);

	it("does not let a delayed detachment retire unlink a successor claim on a reused inode", () => {
		const { base, recorder } = fixture();
		let successorBytes = "";
		let replacedAtRetirement = false;
		const retirementBoundary = "before_root_detachment_retire" as IncidentCasTransactionStep;
		const admission = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step !== retirementBoundary || replacedAtRetirement) return;
				replacedAtRetirement = true;
				const path = detachedEvidencePath(recorder);
				const prior = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
				successorBytes = `${JSON.stringify({
					...prior,
					detachId: randomUUID(),
					lockId: randomUUID(),
					processStartId: `${String(prior.processStartId)}-successor`,
				})}\n`;
				// Rewriting the fixed slot preserves dev/ino while changing the logical
				// claimant, modelling the same-inode endpoint of unlink/reuse ABA.
				writeFileSync(path, successorBytes, { mode: 0o600 });
			},
		});
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		const displacedRoot = join(base, "delayed-detachment-old-root");
		expect(
			admission.transaction.withRoot(() => {
				renameSync(recorder, displacedRoot);
				mkdirSync(recorder, { mode: 0o700 });
			}),
		).toEqual({ state: "root_detached", evidence: "durable" });
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: true });
		expect(replacedAtRetirement).toBe(true);
		expect(readFileSync(detachedEvidencePath(recorder), "utf8")).toBe(successorBytes);
		recoverAfterCrash(recorder);
	});

	it("does not let delayed detachment recovery unlink successor evidence at the same-inode endpoint", () => {
		const { base, recorder } = fixture();
		let failInitialRetirement = true;
		const original = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step !== "before_root_detachment_retire" || !failInitialRetirement) return;
				failInitialRetirement = false;
				throw new Error("retain old detachment evidence for recovery");
			},
		});
		expect(original).toMatchObject({ state: "acquired" });
		if (original.state !== "acquired") return;
		const displacedRoot = join(base, "detachment-recovery-old-root");
		expect(
			original.transaction.withRoot(() => {
				renameSync(recorder, displacedRoot);
				mkdirSync(recorder, { mode: 0o700 });
			}),
		).toEqual({ state: "root_detached", evidence: "durable" });
		expect(original.transaction.release()).toEqual({ state: "released", cleanupPending: true });
		const detachment = detachedEvidencePath(recorder);
		expect(existsSync(detachment)).toBe(true);

		const runtime = {};
		let raceInjected = false;
		let successorOwnerBytes = "";
		let successorEvidenceBytes = "";
		const unregister = registerIncidentCasDetachmentRecoveryTestSynchronization(runtime, () => {
			raceInjected = true;
			const fixed = authorityPath(recorder);
			mkdirSync(fixed, { mode: 0o700 });
			successorOwnerBytes = ownerBytes(fixed, recorder);
			writeFileSync(join(fixed, "owner.json"), successorOwnerBytes, { mode: 0o600 });
			const successorOwner = JSON.parse(successorOwnerBytes) as Record<string, unknown>;
			successorEvidenceBytes = `${JSON.stringify({
				type: "incident-recorder-cas-root-detachment",
				version: 2,
				detachId: randomUUID(),
				lockId: successorOwner.lockId,
				lockDev: successorOwner.lockDev,
				lockIno: successorOwner.lockIno,
				rootDev: successorOwner.rootDev,
				rootIno: successorOwner.rootIno,
				rootPath: successorOwner.rootPath,
				machineId: successorOwner.machineId,
				bootId: successorOwner.bootId,
				pid: successorOwner.pid,
				processStartId: successorOwner.processStartId,
			})}\n`;
			writeFileSync(detachment, successorEvidenceBytes, { mode: 0o600 });
		});
		let admission: ReturnType<typeof acquireIncidentCasTransactionDetailed>;
		try {
			admission = acquireIncidentCasTransactionDetailed(recorder, runtime);
		} finally {
			unregister();
		}
		expect(raceInjected).toBe(true);
		expect(admission.state).toBe("unavailable");
		if (admission.state === "unavailable") {
			expect(["control_artifact_busy", "same_process_owner_untracked"]).toContain(admission.reason);
		}
		expect(readFileSync(join(authorityPath(recorder), "owner.json"), "utf8")).toBe(successorOwnerBytes);
		expect(existsSync(detachment)).toBe(true);
		expect(readFileSync(detachment, "utf8")).toBe(successorEvidenceBytes);
	});

	it("keeps successor prepare evidence when a creator fails after closing its descriptor", () => {
		const { recorder } = fixture();
		const prepare = `${authorityPath(recorder)}.prepare-owner`;
		let closed = false;
		let successorBytes = "";
		const admission = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step !== "prepare_closed" || closed) return;
				closed = true;
				const prior = JSON.parse(readFileSync(prepare, "utf8")) as Record<string, unknown>;
				successorBytes = `${JSON.stringify({ ...prior, lockId: randomUUID() })}\n`;
				writeFileSync(prepare, successorBytes, { mode: 0o600 });
			},
		});
		expect(closed).toBe(true);
		expect(admission.state).toBe("unavailable");
		expect(existsSync(prepare)).toBe(true);
		expect(readFileSync(prepare, "utf8")).toBe(successorBytes);
	});

	it("keeps successor evidence when malformed detachment recovery races its cleanup", () => {
		const { recorder } = fixture();
		const detachment = detachedEvidencePath(recorder);
		const malformedBytes = '{"corrupt":true}\n';
		writeFileSync(detachment, malformedBytes, { mode: 0o600 });
		let monotonic = 0;
		const runtime = { monotonicTimeMs: () => monotonic };
		expect(acquireIncidentCasTransactionDetailed(recorder, runtime)).toEqual({
			state: "unavailable",
			reason: "control_artifact_grace",
		});
		monotonic = 5_001;
		let successorBytes = "";
		const unregister = registerIncidentCasDetachmentRecoveryTestSynchronization(runtime, () => {
			successorBytes = '{"successor":true}\n';
			writeFileSync(detachment, successorBytes, { mode: 0o600 });
		});
		let admission: ReturnType<typeof acquireIncidentCasTransactionDetailed>;
		try {
			admission = acquireIncidentCasTransactionDetailed(recorder, runtime);
		} finally {
			unregister();
		}
		expect(admission).toEqual({ state: "unavailable", reason: "control_artifact_busy" });
		expect(readFileSync(detachment, "utf8")).toBe(successorBytes);
	});

	it("rejects a recorder or control parent writable by another uid", () => {
		const { base, recorder } = fixture();
		chmodSync(base, 0o777);
		expect(acquireIncidentCasTransactionDetailed(recorder)).toEqual({
			state: "unavailable",
			reason: "root_unavailable",
		});
		chmodSync(base, 0o700);
		chmodSync(recorder, 0o777);
		expect(acquireIncidentCasTransactionDetailed(recorder)).toEqual({
			state: "unavailable",
			reason: "root_unavailable",
		});
	});

	it("runs a reentrant alias handle against the same descriptor-rooted namespace", () => {
		const { base, recorder } = fixture();
		const alias = join(base, "recorder-alias");
		symlinkSync(recorder, alias, "dir");
		const original = acquireIncidentCasTransactionDetailed(recorder);
		expect(original).toMatchObject({ state: "acquired" });
		if (original.state !== "acquired") return;
		const nested = acquireIncidentCasTransaction(alias);
		expect(nested).toBeDefined();
		if (!nested) return;
		expect(
			nested.withRoot((root) => root.writeFileExclusive(root.relative("through-alias"), "alias-root\n")),
		).toMatchObject({ state: "committed" });
		expect(readFileSync(join(recorder, "through-alias"), "utf8")).toBe("alias-root\n");
		expect(nested.release()).toEqual({ state: "released", cleanupPending: false });
		expect(original.transaction.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it("preserves one pending final release across alias refcounts and lets acquisition finish it", () => {
		const { base, recorder } = fixture();
		const alias = join(base, "recorder-alias");
		symlinkSync(recorder, alias, "dir");
		let failRetirement = true;
		const original = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step === "before_lock_retire" && failRetirement) {
					failRetirement = false;
					throw new Error("injected final-release failure");
				}
			},
		});
		expect(original).toMatchObject({ state: "acquired" });
		if (original.state !== "acquired") return;
		const nested = acquireIncidentCasTransaction(alias);
		expect(nested).toBeDefined();
		if (!nested) return;
		expect(original.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		expect(nested.release()).toEqual({ state: "pending", reason: "io_error" });
		expect(original.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		const successor = acquireIncidentCasTransactionDetailed(recorder);
		expect(successor).toMatchObject({ state: "acquired" });
		if (successor.state === "acquired") successor.transaction.release();
		expect(nested.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it("rejects an asynchronous callback from the transaction-scoped root capability", () => {
		const { recorder } = fixture();
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		expect(() => admission.transaction.withRoot(() => Promise.resolve("late"))).toThrow(/complete synchronously/i);
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it("revokes captured root and file capabilities before deferred work can use them", async () => {
		const { recorder } = fixture();
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		let capturedRoot: IncidentCasRootMutation | undefined;
		let capturedPath: IncidentCasRelativePath | undefined;
		let capturedFile: { sync(): void } | undefined;
		let deferredError: unknown;
		let finishDeferred: (() => void) | undefined;
		const deferred = new Promise<void>((resolve) => {
			finishDeferred = resolve;
		});
		const mutation = admission.transaction.withRoot((root) => {
			capturedRoot = root;
			capturedPath = root.relative("deferred-write");
			root.withFile(capturedPath, { access: "write", create: "exclusive", mode: 0o600 }, (file) => {
				capturedFile = file;
			});
			queueMicrotask(() => {
				try {
					capturedRoot?.writeFileExclusive(capturedPath as IncidentCasRelativePath, "late\n");
				} catch (error) {
					deferredError = error;
				} finally {
					finishDeferred?.();
				}
			});
			return root.publicPath(capturedPath);
		});
		expect(mutation).toMatchObject({ state: "committed", value: join(recorder, "deferred-write") });
		expect(() => capturedRoot?.exists(capturedPath as IncidentCasRelativePath)).toThrow(/no longer active/i);
		expect(() => capturedFile?.sync()).toThrow(/no longer active/i);
		await deferred;
		expect(deferredError).toBeInstanceOf(Error);
		expect(String(deferredError)).toMatch(/no longer active/i);
		expect(readFileSync(join(recorder, "deferred-write"), "utf8")).toBe("");
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it("rejects absolute, traversal, separator, NUL, foreign-token, and nested-async capability misuse", () => {
		const { recorder } = fixture();
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		let retainedToken: IncidentCasRelativePath | undefined;
		const result = admission.transaction.withRoot((root) => {
			expect(() => root.relative("/absolute")).toThrow(/component/i);
			expect(() => root.relative("..")).toThrow(/component/i);
			expect(() => root.relative("nested/name")).toThrow(/component/i);
			expect(() => root.relative("nul\0name")).toThrow(/component/i);
			retainedToken = root.relative("private-file");
			expect(root.publicPath(retainedToken)).not.toContain("/proc/self/fd");
			root.writeFileExclusive(retainedToken, "private\n");
			expect(() =>
				root.withFile(retainedToken as IncidentCasRelativePath, { access: "read" }, () => Promise.resolve()),
			).toThrow(/complete synchronously/i);
			expect(() => root.withDirectory(root.relative(), () => Promise.resolve())).toThrow(/complete synchronously/i);
			return "done";
		});
		expect(result).toEqual({ state: "committed", value: "done" });
		const nested = acquireIncidentCasTransaction(recorder);
		expect(nested).toBeDefined();
		if (nested && retainedToken) {
			expect(() => nested.withRoot((root) => root.exists(retainedToken as IncidentCasRelativePath))).toThrow(
				/another capability/i,
			);
			nested.release();
		}
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it("confines descriptor-rooted file, link, rename, directory-page, and realpath operations", () => {
		const { base, recorder } = fixture();
		const outside = join(base, "outside");
		mkdirSync(outside, { mode: 0o700 });
		writeFileSync(join(outside, "sentinel"), "outside\n", { mode: 0o600 });
		symlinkSync(outside, join(recorder, "escape"), "dir");
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		const mutation = admission.transaction.withRoot((root) => {
			expect(() => root.writeFileExclusive(root.relative("escape", "clobber"), "bad\n")).toThrow();
			expect(() => root.realpath(root.relative("escape"))).toThrow(/escaped/i);
			expect(root.readlink(root.relative("escape"))).toBe(outside);
			const directory = root.relative("nested", "leaf");
			root.mkdirPrivate(directory, true);
			const original = root.relative("nested", "leaf", "original");
			const linked = root.relative("nested", "leaf", "linked");
			const renamed = root.relative("nested", "leaf", "renamed");
			root.writeFileExclusive(original, "alpha\n");
			root.withFile(original, { access: "read_write" }, (file) => {
				expect(file.writeText("A", 0)).toBe(1);
				file.sync();
			});
			root.hardLink(original, linked);
			root.rename(linked, renamed);
			expect(root.readFile(renamed, 64).toString("utf8")).toBe("Alpha\n");
			expect(root.stat(original).ino).toBe(root.stat(renamed).ino);
			expect(root.statfs(original).blocks).toBeGreaterThan(0n);
			root.fsyncFile(renamed);
			root.fsyncDirectory(directory);
			const page = root.directoryPage(directory, { limit: 1, scanLimit: 8 });
			expect(page.entries).toHaveLength(1);
			expect(page.cursorFound).toBe(true);
			expect(page.scanLimitReached).toBe(false);
			return page.nextAfterName;
		});
		expect(mutation).toMatchObject({ state: "committed" });
		expect(readFileSync(join(outside, "sentinel"), "utf8")).toBe("outside\n");
		expect(existsSync(join(outside, "clobber"))).toBe(false);
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
	});

	it("sanitizes all capability-originated filesystem errors without leaking descriptor paths", () => {
		const { recorder } = fixture();
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		try {
			const mutation = admission.transaction.withRoot((root) => {
				const capture = (name: string, operation: () => void): { name: string; error: NodeJS.ErrnoException } => {
					let captured: unknown;
					try {
						operation();
					} catch (error) {
						captured = error;
					}
					expect(captured, `${name} must fail`).toBeInstanceOf(Error);
					return { name, error: captured as NodeJS.ErrnoException };
				};

				const failures = [
					capture("bounded read ENOENT", () => {
						root.readFile(root.relative("missing-read"), 64);
					}),
				];
				const denied = root.relative("denied-read");
				root.writeFileExclusive(denied, "denied\n");
				root.chmod(denied, 0o000);
				failures.push(
					capture("bounded read EACCES", () => {
						root.readFile(denied, 64);
					}),
				);
				const linkSource = root.relative("link-source");
				const linkDestination = root.relative("link-destination");
				root.writeFileExclusive(linkSource, "source\n");
				root.writeFileExclusive(linkDestination, "destination\n");
				failures.push(
					capture("hard-link EEXIST", () => {
						root.hardLink(linkSource, linkDestination);
					}),
				);
				const renameSource = root.relative("rename-source");
				const renameDestination = root.relative("rename-destination");
				root.writeFileExclusive(renameSource, "source\n");
				root.mkdirPrivate(renameDestination);
				root.writeFileExclusive(root.relative("rename-destination", "occupant"), "occupied\n");
				failures.push(
					capture("rename destination failure", () => {
						root.rename(renameSource, renameDestination);
					}),
					capture("direct open ENOENT", () => {
						root.withFile(root.relative("missing-open"), { access: "read" }, () => undefined);
					}),
				);

				for (const { name, error } of failures) {
					expect(typeof error.code, `${name} should preserve an errno code`).toBe("string");
					expect(completeErrorDisclosure(error), name).not.toContain("/proc/self/fd/");
					expect(JSON.stringify(error), `${name} JSON projection`).not.toContain("/proc/self/fd/");
				}
				return failures.length;
			});
			expect(mutation).toEqual({ state: "committed", value: 5 });
		} finally {
			admission.transaction.release();
		}
	});

	it.each([
		"directory_created",
		"owner_written",
		"owner_fsynced",
		"owner_linked",
		"owner_directory_fsynced",
		"prepare_unlinked",
		"authority_published",
		"creation_root_fsynced",
	] satisfies IncidentCasTransactionStep[])(
		"converges after a transient %s fault without self-stranding",
		(boundary) => {
			const { recorder } = fixture();
			let injected = false;
			const admission = acquireIncidentCasTransactionDetailed(recorder, {
				onStep: (step) => {
					if (step === boundary && !injected) {
						injected = true;
						throw new Error(`transient ${boundary} fault`);
					}
				},
			});
			expect(admission).toMatchObject({ state: "acquired" });
			if (admission.state !== "acquired") return;
			const nested = acquireIncidentCasTransaction(recorder);
			expect(nested).toBeDefined();
			nested?.release();
			expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		},
	);

	it("tracks and autonomously retires a published owner after recorder-root replacement", () => {
		const { base, recorder } = fixture();
		const displacedRoot = join(base, "published-owner-old-root");
		let replaced = false;
		let failPersistence = true;
		const first = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step === "authority_published" && !replaced) {
					replaced = true;
					renameSync(recorder, displacedRoot);
					mkdirSync(recorder, { mode: 0o700 });
				}
				if (step === "root_detachment_root_fsynced" && failPersistence) {
					throw new Error("injected published-owner retirement failure");
				}
			},
		});
		expect(first).toEqual({ state: "unavailable", reason: "creation_failed" });
		expect(probeAdmissionInChild(recorder)).toEqual({ state: "unavailable", reason: "live_owner" });
		failPersistence = false;
		const recovered = acquireIncidentCasTransactionDetailed(recorder);
		expect(recovered).toMatchObject({ state: "acquired" });
		if (recovered.state === "acquired") recovered.transaction.release();
		expect(controlEntries(recorder, "released-")).toHaveLength(0);
		expect(controlEntries(recorder, "detached-")).toHaveLength(0);
	});

	it("tracks publication before the first post-rename hook can fail and detach the recorder root", () => {
		const { base, recorder } = fixture();
		const publicationBoundary = "authority_fixed_name_published" as IncidentCasTransactionStep;
		const displacedRoot = join(base, "linearized-publication-old-root");
		let injected = false;
		let failDetachmentPersistence = true;
		const first = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step === publicationBoundary && !injected) {
					injected = true;
					renameSync(recorder, displacedRoot);
					mkdirSync(recorder, { mode: 0o700 });
					throw new Error("injected fault at the fixed-name publication linearization point");
				}
				if (step === "root_detachment_root_fsynced" && failDetachmentPersistence) {
					throw new Error("retain published owner for tracked retirement retry");
				}
			},
		});
		if (first.state === "acquired") first.transaction.release();
		expect(injected).toBe(true);
		expect(first).toEqual({ state: "unavailable", reason: "creation_failed" });
		expect(probeAdmissionInChild(recorder)).toEqual({ state: "unavailable", reason: "live_owner" });
		failDetachmentPersistence = false;
		const recovered = acquireIncidentCasTransactionDetailed(recorder);
		expect(recovered).toMatchObject({ state: "acquired" });
		if (recovered.state === "acquired") recovered.transaction.release();
	});

	it("retains a tracked published owner when its first strict readback is unavailable", () => {
		const { recorder } = fixture();
		const publicationBoundary = "authority_fixed_name_published" as IncidentCasTransactionStep;
		let readbackBlocked = false;
		const first = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step !== publicationBoundary || readbackBlocked) return;
				readbackBlocked = true;
				chmodSync(authorityPath(recorder), 0o000);
			},
		});
		if (first.state === "acquired") first.transaction.release();
		expect(readbackBlocked).toBe(true);
		expect(first).toEqual({ state: "unavailable", reason: "creation_failed" });
		chmodSync(authorityPath(recorder), 0o700);
		const recovered = acquireIncidentCasTransactionDetailed(recorder);
		expect(recovered).toMatchObject({ state: "acquired" });
		if (recovered.state === "acquired") recovered.transaction.release();
	});

	it("pretracks publication and adopts the exact self-owner when rename takes effect before reporting failure", () => {
		const { base, recorder } = fixture();
		const publicationAttempt = "before_authority_publish" as IncidentCasTransactionStep;
		const fixed = authorityPath(recorder);
		const stage = `${fixed}.stage`;
		const displacedRoot = join(base, "ambiguous-rename-old-root");
		let injected = false;
		let nestedAdmission: unknown;
		let failDetachmentPersistence = true;
		const first = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step === publicationAttempt && !injected) {
					injected = true;
					nestedAdmission = acquireIncidentCasTransactionDetailed(recorder);
					renameSync(stage, fixed);
					renameSync(recorder, displacedRoot);
					mkdirSync(recorder, { mode: 0o700 });
					throw new Error("rename side effect completed before the injected failure");
				}
				if (step === "root_detachment_root_fsynced" && failDetachmentPersistence) {
					throw new Error("retain ambiguously published owner for retirement retry");
				}
			},
		});
		if (first.state === "acquired") first.transaction.release();
		expect(injected).toBe(true);
		expect(nestedAdmission).toEqual({ state: "unavailable", reason: "control_artifact_busy" });
		expect(first).toEqual({ state: "unavailable", reason: "creation_failed" });
		expect(probeAdmissionInChild(recorder)).toEqual({ state: "unavailable", reason: "live_owner" });
		failDetachmentPersistence = false;
		const recovered = acquireIncidentCasTransactionDetailed(recorder);
		expect(recovered).toMatchObject({ state: "acquired" });
		if (recovered.state === "acquired") recovered.transaction.release();
	});

	it("writes an exact v2 descriptor and fails closed on an untracked same-process owner", () => {
		const { recorder } = fixture();
		const lock = authorityPath(recorder);
		mkdirSync(lock, { mode: 0o700 });
		const bytes = ownerBytes(lock, recorder);
		writeFileSync(join(lock, "owner.json"), bytes, { mode: 0o600 });
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toEqual({ state: "unavailable", reason: "same_process_owner_untracked" });
		expect(readFileSync(join(lock, "owner.json"), "utf8")).toBe(bytes);
		expect(existsSync(lock)).toBe(true);
	});

	it("does not launder a noncanonical live-looking owner", () => {
		const { recorder } = fixture();
		const lock = authorityPath(recorder);
		mkdirSync(lock, { mode: 0o700 });
		const bytes = ownerBytes(lock, recorder).replace(/}\n$/, ',"unexpected":true}\n');
		writeFileSync(join(lock, "owner.json"), bytes, { mode: 0o600 });
		const admission = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 10_000 });
		expect(admission).toEqual({ state: "unavailable", reason: "same_process_owner_untracked" });
		expect(readFileSync(join(lock, "owner.json"), "utf8")).toBe(bytes);
	});

	it.each([
		{
			name: "wrong mode",
			mutate: (lock: string, bytes: string) => {
				const owner = join(lock, "owner.json");
				writeFileSync(owner, bytes, { mode: 0o600 });
				chmodSync(owner, 0o644);
			},
		},
		{
			name: "duplicate key",
			mutate: (lock: string, bytes: string) => {
				const duplicate = bytes.replace(`"pid":${process.pid}`, `"pid":${process.pid},"pid":${process.pid}`);
				writeFileSync(join(lock, "owner.json"), duplicate, { mode: 0o600 });
			},
		},
		{
			name: "wrong authority-directory mode",
			mutate: (lock: string, bytes: string) => {
				writeFileSync(join(lock, "owner.json"), bytes, { mode: 0o600 });
				chmodSync(lock, 0o755);
			},
		},
	])("fails closed without laundering a live-looking owner with $name", ({ mutate }) => {
		const { recorder } = fixture();
		const lock = authorityPath(recorder);
		mkdirSync(lock, { mode: 0o700 });
		mutate(lock, ownerBytes(lock, recorder));
		const original = readFileSync(join(lock, "owner.json"), "utf8");
		expect(acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 20_000 })).toEqual({
			state: "unavailable",
			reason: "same_process_owner_untracked",
		});
		expect(readFileSync(join(lock, "owner.json"), "utf8")).toBe(original);
	});

	it("quarantines the fixed authority symlink itself without touching its target", () => {
		const { base, recorder } = fixture();
		const target = join(base, "outside-authority");
		mkdirSync(target, { mode: 0o700 });
		writeFileSync(join(target, "sentinel"), "outside\n", { mode: 0o600 });
		const fixed = authorityPath(recorder);
		symlinkSync(target, fixed, "dir");
		expect(acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 0 })).toEqual({
			state: "unavailable",
			reason: "invalid_owner_grace",
		});
		const recovered = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 5_001 });
		expect(recovered).toMatchObject({ state: "acquired" });
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);
		expect(readFileSync(join(target, "sentinel"), "utf8")).toBe("outside\n");
		if (recovered.state === "acquired") recovered.transaction.release();
	});

	it("creates authority and quarantine directories with private modes under a restrictive umask", () => {
		const { recorder } = fixture();
		const fixed = authorityPath(recorder);
		const controlParent = dirname(fixed);
		const quarantinePrefix = `${controlName(recorder)}.quarantine-`;
		mkdirSync(fixed, { mode: 0o700 });
		const script = `
			import { readdirSync, statSync } from "node:fs";
			import { join } from "node:path";
			import { acquireIncidentCasTransactionDetailed } from ${JSON.stringify(moduleUrl)};
			process.umask(0o777);
			let monotonic = 0;
			let quarantineMode;
			const first = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
				monotonicTimeMs: () => monotonic,
			});
			if (first.state !== "unavailable" || first.reason !== "invalid_owner_grace") process.exit(61);
			monotonic = 5_001;
			const admission = acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
				monotonicTimeMs: () => monotonic,
				onStep(step) {
					if (step !== "quarantine_claim_linked") return;
					const quarantine = readdirSync(${JSON.stringify(controlParent)}).find((name) =>
						name.startsWith(${JSON.stringify(quarantinePrefix)}),
					);
					if (quarantine) quarantineMode = statSync(join(${JSON.stringify(controlParent)}, quarantine)).mode & 0o777;
				},
			});
			if (admission.state !== "acquired") process.exit(62);
			const names = readdirSync(${JSON.stringify(controlParent)});
			const result = {
				lock: statSync(${JSON.stringify(fixed)}).mode & 0o777,
				quarantine: quarantineMode,
				residualQuarantines: names.filter((name) => name.startsWith(${JSON.stringify(quarantinePrefix)})).length,
			};
			admission.transaction.release();
			process.stdout.write(JSON.stringify(result));
		`;
		const result = spawnSync(process.execPath, ["--import", tsxLoader, "--input-type=module", "--eval", script], {
			encoding: "utf8",
			timeout: 5_000,
		});
		expect(result.status, result.stderr).toBe(0);
		expect(JSON.parse(result.stdout)).toEqual({ lock: 0o700, quarantine: 0o700, residualQuarantines: 0 });
	});

	it("publishes no fixed authority before a restrictive-umask staging directory is private and durable", () => {
		const { recorder } = fixture();
		const fixed = authorityPath(recorder);
		const stage = `${fixed}.stage`;
		const script = `
			import { acquireIncidentCasTransactionDetailed } from ${JSON.stringify(moduleUrl)};
			process.umask(0o777);
			acquireIncidentCasTransactionDetailed(${JSON.stringify(recorder)}, {
				onStep(step) {
					if (step === "directory_created") process.kill(process.pid, "SIGKILL");
				},
			});
			process.exit(64);
		`;
		const result = spawnSync(process.execPath, ["--import", tsxLoader, "--input-type=module", "--eval", script], {
			encoding: "utf8",
			timeout: 5_000,
		});
		expect(result.signal, result.stderr).toBe("SIGKILL");
		expect(existsSync(fixed)).toBe(false);
		expect(statSync(stage).mode & 0o777).toBe(0o700);
		recoverAfterCrash(recorder);
	});

	it("rejects an unexpected hard-link topology without adopting the descriptor", () => {
		const { recorder } = fixture();
		const lock = authorityPath(recorder);
		mkdirSync(lock, { mode: 0o700 });
		const owner = join(lock, "owner.json");
		writeFileSync(owner, ownerBytes(lock, recorder), { mode: 0o600 });
		linkSync(owner, join(dirname(lock), "unexpected-owner-link"));
		expect(acquireIncidentCasTransactionDetailed(recorder)).toEqual({
			state: "unavailable",
			reason: "same_process_owner_untracked",
		});
		expect(statSync(owner).nlink).toBe(2);
	});

	it("quarantines an orphan owner symlink without following or rewriting its target", () => {
		const { base, recorder } = fixture();
		const lock = authorityPath(recorder);
		const target = join(base, "outside-owner");
		mkdirSync(lock, { mode: 0o700 });
		writeFileSync(target, "outside-evidence\n", { mode: 0o600 });
		symlinkSync(target, join(lock, "owner.json"));
		expect(acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 0 })).toEqual({
			state: "unavailable",
			reason: "invalid_owner_grace",
		});
		const recovered = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 5_001 });
		expect(recovered).toMatchObject({ state: "acquired" });
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);
		expect(readFileSync(target, "utf8")).toBe("outside-evidence\n");
		if (recovered.state === "acquired") recovered.transaction.release();
	});

	it("ages a future-dated invalid v2 owner and retires its bounded quarantine slot", () => {
		const { recorder } = fixture();
		const lock = authorityPath(recorder);
		mkdirSync(lock, { mode: 0o700 });
		const invalidBytes = '{"corrupt":true}\n';
		writeFileSync(join(lock, "owner.json"), invalidBytes, { mode: 0o600 });
		const future = new Date("2099-01-01T00:00:00.000Z");
		utimesSync(join(lock, "owner.json"), future, future);
		expect(acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 0 })).toEqual({
			state: "unavailable",
			reason: "invalid_owner_grace",
		});
		const recovered = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 5_001 });
		expect(recovered).toMatchObject({ state: "acquired" });
		if (recovered.state !== "acquired") return;
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);
		expect(recovered.transaction.release()).toMatchObject({ state: "released" });
	});

	it("rejects and preserves exact legacy v1 authority evidence during cutover", () => {
		const { recorder } = fixture();
		const legacy = join(recorder, ".cas-transaction");
		mkdirSync(legacy, { mode: 0o700 });
		const staleBytes = legacyOwnerBytes({ bootId: "00000000-0000-0000-0000-000000000000" });
		writeFileSync(join(legacy, "owner.json"), staleBytes, { mode: 0o600 });
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toEqual({ state: "unavailable", reason: "legacy_v1_authority_present" });
		expect(readFileSync(join(legacy, "owner.json"), "utf8")).toBe(staleBytes);
	});

	it("revalidates the owner and directory together before quarantine", () => {
		const { recorder } = fixture();
		const fixed = authorityPath(recorder);
		const displaced = `${fixed}.displaced-test`;
		mkdirSync(fixed, { mode: 0o700 });
		writeFileSync(
			join(fixed, "owner.json"),
			ownerBytes(fixed, recorder, { bootId: "00000000-0000-0000-0000-000000000000" }),
			{
				mode: 0o600,
			},
		);
		let swapped = false;
		let replacementBytes = "";
		const admission = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step !== "before_quarantine_revalidation" || swapped) return;
				swapped = true;
				renameSync(fixed, displaced);
				mkdirSync(fixed, { mode: 0o700 });
				replacementBytes = ownerBytes(fixed, recorder);
				writeFileSync(join(fixed, "owner.json"), replacementBytes, { mode: 0o600 });
			},
		});
		expect(admission).toEqual({ state: "unavailable", reason: "same_process_owner_untracked" });
		expect(existsSync(displaced)).toBe(true);
		expect(readFileSync(join(fixed, "owner.json"), "utf8")).toBe(replacementBytes);
	});

	it("never steals from a live owner and recovers after that process dies", async () => {
		const { recorder } = fixture();
		const child = await startHolder(recorder);
		expect(acquireIncidentCasTransactionDetailed(recorder)).toEqual({ state: "unavailable", reason: "live_owner" });
		child.kill("SIGKILL");
		await new Promise<void>((resolve) => child.once("exit", () => resolve()));
		const recovered = acquireIncidentCasTransactionDetailed(recorder);
		expect(recovered).toMatchObject({ state: "acquired" });
		if (recovered.state === "acquired") expect(recovered.transaction.release()).toMatchObject({ state: "released" });
	});

	it("retains a detached release for retry and never touches a successor authority", async () => {
		const { recorder } = fixture();
		let injectFault = true;
		const admission = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step === "lock_retired" && injectFault) {
					injectFault = false;
					throw new Error("injected post-retirement fault");
				}
			},
		});
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		expect(admission.transaction.release()).toEqual({ state: "pending", reason: "io_error" });
		const fixed = authorityPath(recorder);
		expect(existsSync(fixed)).toBe(false);
		const successor = await startHolder(recorder);
		const successorStats = statSync(fixed, { bigint: true });
		const successorOwner = readFileSync(join(fixed, "owner.json"), "utf8");
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: false });
		const afterRetry = statSync(fixed, { bigint: true });
		expect([afterRetry.dev, afterRetry.ino]).toEqual([successorStats.dev, successorStats.ino]);
		expect(readFileSync(join(fixed, "owner.json"), "utf8")).toBe(successorOwner);
		successor.stdin?.write("release\n");
		await new Promise<void>((resolve) => successor.once("exit", () => resolve()));
	});

	it("sweeps a prior empty released authority after cleanup returned pending", () => {
		const { recorder } = fixture();
		let injectFault = true;
		const admission = acquireIncidentCasTransactionDetailed(recorder, {
			onStep: (step) => {
				if (step === "released_owner_unlinked" && injectFault) {
					injectFault = false;
					throw new Error("injected cleanup fault");
				}
			},
		});
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		expect(admission.transaction.release()).toEqual({ state: "released", cleanupPending: true });
		expect(controlEntries(recorder, "released-")).toHaveLength(1);
		const successor = acquireIncidentCasTransactionDetailed(recorder);
		expect(successor).toMatchObject({ state: "acquired" });
		if (successor.state === "acquired") successor.transaction.release();
		expect(controlEntries(recorder, "released-")).toHaveLength(0);
	});

	it("clears a malformed retired slot through the bounded quarantine lifecycle", () => {
		const { recorder } = fixture();
		const fixed = authorityPath(recorder);
		const released = `${fixed}.released-slot`;
		mkdirSync(released, { mode: 0o700 });
		writeFileSync(join(released, "owner.json"), '{"corrupt":true}\n', { mode: 0o600 });
		const admission = acquireIncidentCasTransactionDetailed(recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		expect(existsSync(released)).toBe(false);
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);
		if (admission.state === "acquired") admission.transaction.release();
	});

	it("reuses one fixed quarantine slot across repeated invalid authorities without residue growth", () => {
		const { recorder } = fixture();
		const fixed = authorityPath(recorder);
		for (let index = 0; index < 12; index += 1) {
			mkdirSync(fixed, { mode: 0o700 });
			writeFileSync(join(fixed, "owner.json"), `${JSON.stringify({ corrupt: index })}\n`, { mode: 0o600 });
			const firstSeen = index * 10_000;
			expect(acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => firstSeen })).toEqual({
				state: "unavailable",
				reason: "invalid_owner_grace",
			});
			const admission = acquireIncidentCasTransactionDetailed(recorder, {
				monotonicTimeMs: () => firstSeen + 5_001,
			});
			expect(admission).toMatchObject({ state: "acquired" });
			if (admission.state === "acquired") admission.transaction.release();
			expect(controlEntries(recorder, "quarantine-").length).toBeLessThanOrEqual(1);
		}
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);
	});

	it("retires an oversized quarantine occupant through bounded autonomous passes", () => {
		const { recorder } = fixture();
		const fixed = authorityPath(recorder);
		mkdirSync(fixed, { mode: 0o700 });
		for (let index = 0; index < 96; index += 1) {
			writeFileSync(join(fixed, `unexpected-${index}`), `${index}\n`, { mode: 0o600 });
		}
		expect(acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 0 })).toEqual({
			state: "unavailable",
			reason: "invalid_owner_grace",
		});
		let admission = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 5_001 });
		expect(admission).toEqual({ state: "unavailable", reason: "quarantine_failed" });
		for (let pass = 0; pass < 6 && admission.state !== "acquired"; pass += 1) {
			admission = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 5_001 });
		}
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state === "acquired") admission.transaction.release();
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);
	});

	it("ages and sweeps an abandoned private prepare artifact with bounded acquisition work", () => {
		const { recorder } = fixture();
		const prepare = join(dirname(authorityPath(recorder)), `${controlName(recorder)}.prepare-owner`);
		writeFileSync(prepare, '{"partial":true}\n', { mode: 0o600 });
		chmodSync(prepare, 0o000);
		const first = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 0 });
		expect(first).toEqual({ state: "unavailable", reason: "control_artifact_grace" });
		expect(existsSync(prepare)).toBe(true);
		expect(statSync(prepare).mode & 0o777).toBe(0o600);
		const second = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 5_001 });
		expect(second).toMatchObject({ state: "acquired" });
		if (second.state === "acquired") second.transaction.release();
		expect(existsSync(prepare)).toBe(false);
	});

	it("repairs and ages an abandoned mode-zero staging directory without publishing it", () => {
		const { recorder } = fixture();
		const fixed = authorityPath(recorder);
		const stage = `${fixed}.stage`;
		mkdirSync(stage, { mode: 0o700 });
		chmodSync(stage, 0o000);
		expect(acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 0 })).toEqual({
			state: "unavailable",
			reason: "control_artifact_grace",
		});
		expect(existsSync(fixed)).toBe(false);
		expect(statSync(stage).mode & 0o777).toBe(0o700);
		const recovered = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => 5_001 });
		expect(recovered).toMatchObject({ state: "acquired" });
		if (recovered.state === "acquired") recovered.transaction.release();
	});

	it.each([
		"directory_created",
		"owner_written",
		"owner_fsynced",
		"owner_linked",
		"owner_directory_fsynced",
		"prepare_unlinked",
		"authority_published",
		"creation_root_fsynced",
	] satisfies IncidentCasTransactionStep[])("recovers after a real creator SIGKILL at %s", (boundary) => {
		const { recorder } = fixture();
		crashAt(recorder, boundary, "create");
		recoverAfterCrash(recorder);
	});

	it.each([
		"before_lock_retire",
		"lock_retired",
		"retirement_root_fsynced",
		"released_owner_unlinked",
		"released_directory_removed",
		"cleanup_root_fsynced",
	] satisfies IncidentCasTransactionStep[])("recovers after a real release SIGKILL at %s", (boundary) => {
		const { recorder } = fixture();
		crashAt(recorder, boundary, "release");
		recoverAfterCrash(recorder);
	});

	it.each([
		"before_quarantine_decision_link",
		"quarantine_decision_linked",
		"quarantine_claim_linked",
		"before_quarantine_revalidation",
		"before_quarantine_move",
		"lock_quarantined",
		"quarantine_root_fsynced",
	] satisfies IncidentCasTransactionStep[])("recovers after a real quarantine SIGKILL at %s", (boundary) => {
		const { recorder } = fixture();
		mkdirSync(authorityPath(recorder), { mode: 0o700 });
		crashQuarantineAt(recorder, boundary);
		recoverAfterCrash(recorder);
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);
	});

	it("keeps a successor intact when two delayed reapers share one retired fixed quarantine slot", async () => {
		const { base, recorder } = fixture();
		crashAt(recorder, "creation_root_fsynced", "create");
		const fixed = authorityPath(recorder);
		const oldAuthority = statSync(fixed, { bigint: true });
		const markerOne = join(base, "reaper-one-ready");
		const markerTwo = join(base, "reaper-two-ready");
		const reaperOne = startPausedReaper(recorder, markerOne);
		await waitUntil(() => existsSync(markerOne), "first reaper at the final move boundary");
		const reaperTwo = startPausedReaper(recorder, markerTwo);
		await waitUntil(() => existsSync(markerTwo), "second reaper at the final move boundary");
		const beforeMove = statSync(fixed, { bigint: true });
		expect([beforeMove.dev, beforeMove.ino]).toEqual([oldAuthority.dev, oldAuthority.ino]);
		const firstOutput = waitForOutput(reaperOne, "nested\n");
		reaperOne.kill("SIGCONT");
		await firstOutput;
		const successor = statSync(fixed, { bigint: true });
		const successorBytes = readFileSync(join(fixed, "owner.json"), "utf8");
		expect([successor.dev, successor.ino]).not.toEqual([oldAuthority.dev, oldAuthority.ino]);
		const secondOutput = waitForOutput(reaperTwo, '"reason":"live_owner"');
		reaperTwo.kill("SIGCONT");
		await secondOutput;
		const afterDelayedMove = statSync(fixed, { bigint: true });
		expect([afterDelayedMove.dev, afterDelayedMove.ino]).toEqual([successor.dev, successor.ino]);
		expect(readFileSync(join(fixed, "owner.json"), "utf8")).toBe(successorBytes);
		expect(controlEntries(recorder, "quarantine-")).toHaveLength(0);
		reaperOne.stdin?.write("release\n");
		await new Promise<void>((resolve) => reaperOne.once("exit", () => resolve()));
	});

	it("preempts a paused unpublished creator after grace without touching its published successor", async () => {
		const { base, recorder } = fixture();
		const creatorMarker = join(base, "creator-ready");
		const creator = startPausedCreator(recorder, creatorMarker);
		await waitUntil(() => existsSync(creatorMarker), "creator after staging its owner");
		const fixed = authorityPath(recorder);
		expect(existsSync(fixed)).toBe(false);
		let monotonic = 0;
		expect(acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => monotonic })).toEqual({
			state: "unavailable",
			reason: "control_artifact_grace",
		});
		monotonic = 5_001;
		const successor = acquireIncidentCasTransactionDetailed(recorder, { monotonicTimeMs: () => monotonic });
		expect(successor).toMatchObject({ state: "acquired" });
		if (successor.state !== "acquired") return;
		const successorStats = statSync(fixed, { bigint: true });
		const successorOwner = readFileSync(join(fixed, "owner.json"), "utf8");
		const creatorOutput = waitForOutput(creator, '"reason":"live_owner"');
		creator.kill("SIGCONT");
		await creatorOutput;
		const afterDelayedCreator = statSync(fixed, { bigint: true });
		expect([afterDelayedCreator.dev, afterDelayedCreator.ino]).toEqual([successorStats.dev, successorStats.ino]);
		expect(readFileSync(join(fixed, "owner.json"), "utf8")).toBe(successorOwner);
		expect(successor.transaction.release()).toMatchObject({ state: "released" });
		expect(probeAdmissionInChild(recorder)).toEqual({ state: "acquired" });
	});
});
