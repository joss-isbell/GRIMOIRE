import { mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	acquireIncidentCasTransactionDetailed,
	type IncidentCasTransactionRuntime,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";
import {
	acquireIncidentRecorderNamespaceCas,
	type IncidentRecorderNamespaceCasTarget,
	type IncidentRecorderNamespaceRoots,
} from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const cleanupPaths: string[] = [];

afterEach(() => {
	for (const path of cleanupPaths.splice(0).reverse()) rmSync(path, { recursive: true, force: true });
});

function fixture(): { base: string; agentDir: string } {
	const base = mkdtempSync(join(tmpdir(), "grimoire-namespace-admission-"));
	cleanupPaths.push(base);
	const agentDir = join(base, "agent");
	mkdirSync(join(agentDir, "incident-recorder"), { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { mode: 0o700 });
	return { base, agentDir };
}

function contract(runtime: IncidentCasTransactionRuntime = {}): IncidentRecorderWriterLifecycleAdmissionContract {
	return {
		activationGenerationDigest: "a".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: (proof, target: IncidentRecorderNamespaceCasTarget) =>
			acquireIncidentRecorderNamespaceCas(proof, target, runtime),
	};
}

describe("incident recorder namespace admission", () => {
	it("admits fixed recorder and incidents capabilities through one lease", () => {
		const f = fixture();
		const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, contract());
		expect(result.state).toBe("acquired");
		if (result.state !== "acquired") return;

		expect(
			result.lease.withRoot((root) => {
				root.writeFileExclusive(root.relative("recorder-marker"), "recorder");
				return "recorder";
			}),
		).toEqual({ state: "committed", value: "recorder" });
		expect(
			result.lease.withIncidents((root) => {
				root.writeFileExclusive(root.relative("incidents-marker"), "incidents");
				return "incidents";
			}),
		).toEqual({ state: "committed", value: "incidents" });
		let capturedRoots: IncidentRecorderNamespaceRoots | undefined;
		expect(
			result.lease.withNamespace((roots) => {
				capturedRoots = roots;
				roots.recorder.writeFileExclusive(roots.recorder.relative("pair-recorder"), "recorder");
				roots.incidents.writeFileExclusive(roots.incidents.relative("pair-incidents"), "incidents");
				return "pair";
			}),
		).toEqual({ state: "committed", value: "pair" });
		expect(() => capturedRoots?.recorder.exists(capturedRoots.recorder.relative("late"))).toThrow(/no longer active/);
		expect(readFileSync(join(f.agentDir, "incident-recorder", "recorder-marker"), "utf8")).toBe("recorder");
		expect(readFileSync(join(f.agentDir, "incidents", "incidents-marker"), "utf8")).toBe("incidents");
		expect(result.lease.release().state).toBe("released");
	});

	it("rejects an absent or forged proof before CAS admission", () => {
		expect(acquireIncidentRecorderNamespaceCas(undefined, "recorder")).toEqual({
			state: "unavailable",
			reason: "namespace_changed",
		});
	});

	it("rejects nested lease mutation without taking another lock", () => {
		const f = fixture();
		const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, contract());
		expect(result.state).toBe("acquired");
		if (result.state !== "acquired") return;
		expect(() =>
			result.lease.withNamespace(() => {
				result.lease.withIncidents(() => "nested");
				return "outer";
			}),
		).toThrow(/not reentrant/);
		expect(result.lease.release().state).toBe("released");
	});

	it("classifies a replaced namespace member as namespace_changed and persists lifecycle detachment after pending CAS release", () => {
		const f = fixture();
		const recorder = join(f.agentDir, "incident-recorder");
		const displacedRecorder = join(f.base, "recorder-displaced");
		const replacementRecorder = join(f.base, "recorder-replacement");
		let replaced = false;
		let releaseFaulted = false;
		const runtime: IncidentCasTransactionRuntime = {
			onStep: (step) => {
				if (step === "authority_published" && !replaced) {
					replaced = true;
					renameSync(recorder, displacedRecorder);
					mkdirSync(recorder, { mode: 0o700 });
				}
				if (step === "before_lock_retire" && replaced && !releaseFaulted) {
					releaseFaulted = true;
					throw new Error("injected CAS release fault");
				}
			},
		};
		const result = acquireIncidentRecorderWriterNormalLease({ agentDir: f.agentDir }, contract(runtime));
		expect(result.state).toBe("acquired");
		if (result.state !== "acquired") return;

		const first = result.lease.withRoot(() => "must-not-commit");
		expect(first).toEqual({ state: "unavailable", reason: "namespace_changed" });
		expect(replaced).toBe(true);
		expect(releaseFaulted).toBe(true);

		const controlName = readdirSync(f.base).find((name) =>
			name.startsWith(".grimoire-incident-writer-lifecycle-v1-"),
		);
		expect(controlName).toBeDefined();
		const detachment = JSON.parse(readFileSync(join(f.base, controlName as string, "detachment.json"), "utf8")) as {
			kind?: unknown;
		};
		expect(detachment).toMatchObject({ kind: "detachment" });

		// Restore the original binding so the second call proves the lease stayed poisoned.
		renameSync(recorder, replacementRecorder);
		renameSync(displacedRecorder, recorder);
		expect(result.lease.withRoot(() => "must-remain-poisoned")).toEqual({
			state: "unavailable",
			reason: "namespace_changed",
		});
		expect(result.lease.release()).toEqual({ state: "released", cleanupPending: false });

		const casCleanup = acquireIncidentCasTransactionDetailed(f.agentDir);
		if (casCleanup.state === "acquired") casCleanup.transaction.release();
	});
});
