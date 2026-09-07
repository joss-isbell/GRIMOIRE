import { createHash } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	acquireIncidentCasTransactionDetailed,
	type IncidentCasRootMutation,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";
import {
	persistIncidentFinalizationSealWithinRoot,
	prepareIncidentFinalizationSeal,
} from "../src/modes/daemon/incident-recorder-finalizer.js";

const cleanupPaths: string[] = [];

afterEach(() => {
	for (const path of cleanupPaths.splice(0).reverse()) rmSync(path, { recursive: true, force: true });
});

function fixture(): { base: string; recorder: string; run: string } {
	const base = mkdtempSync(join(tmpdir(), "grimoire-root-control-"));
	const recorder = join(base, "recorder");
	const run = join(recorder, "run");
	mkdirSync(run, { recursive: true, mode: 0o700 });
	cleanupPaths.push(base);
	return { base, recorder, run };
}

function withRunRoot<T>(fixtureValue: ReturnType<typeof fixture>, operation: (root: IncidentCasRootMutation) => T): T {
	const admission = acquireIncidentCasTransactionDetailed(fixtureValue.recorder);
	expect(admission).toMatchObject({ state: "acquired" });
	if (admission.state !== "acquired") throw new Error(`CAS admission failed: ${admission.reason}`);
	try {
		const result = admission.transaction.withRoot((root) => root.withDirectory(root.relative("run"), operation));
		expect(result).toMatchObject({ state: "committed" });
		if (result.state !== "committed") throw new Error("CAS root detached during fixture operation");
		return result.value;
	} finally {
		expect(admission.transaction.release()).toMatchObject({ state: "released" });
	}
}

function stagingName(name: string, value: string): string {
	const digest = createHash("sha256").update(value).digest("hex");
	return `.${name}.${digest}.tmp`;
}

describe("root-native service-control seal persistence", () => {
	it("prepares canonical bytes and rejects oversize payloads before root mutation", () => {
		const value = { state: "sealed", runId: "run-1" };
		const prepared = prepareIncidentFinalizationSeal(value);
		expect(prepared.bytes).toBe(`${JSON.stringify(value)}\n`);
		expect(prepared.byteLength).toBe(Buffer.byteLength(prepared.bytes, "utf8"));
		expect(prepared.peakStorageFootprint).toEqual({
			payloadBytes: prepared.byteLength,
			metadataBlocks: 2,
			entries: 2,
			inodes: 1,
		});
		expect(() => prepareIncidentFinalizationSeal("x".repeat(16 * 1024 * 1024 + 1))).toThrow(/bound/i);
	});

	it("publishes exact bytes with private modes, peak footprint, and concrete effects", () => {
		const fixtureValue = fixture();
		const value = { schemaVersion: 1, state: "sealed", runId: "run-1" };
		const prepared = prepareIncidentFinalizationSeal(value);
		const result = withRunRoot(fixtureValue, (root) =>
			persistIncidentFinalizationSealWithinRoot(root, "service-finalization-seal.json", prepared),
		);

		expect(result.state).toBe("applied");
		expect(result.authoritativeBytesMatch).toBe(true);
		expect(result.peakStorageBytes).toBeGreaterThanOrEqual(prepared.byteLength);
		expect(result.effects.filter((effect) => effect.kind === "account")).toHaveLength(5);
		expect(result.effects.filter((effect) => effect.kind === "remove")).toHaveLength(1);
		const destination = join(fixtureValue.run, "service-finalization-seal.json");
		expect(readFileSync(destination, "utf8")).toBe(prepared.bytes);
		expect(statSync(destination).mode & 0o777).toBe(0o600);
		expect(readdirSync(fixtureValue.run)).toEqual(["service-finalization-seal.json"]);
	});

	it("is idempotent and never clobbers a conflicting destination", () => {
		const fixtureValue = fixture();
		const name = "service-finalization-seal.json";
		const prepared = prepareIncidentFinalizationSeal({ state: "sealed" });
		const first = withRunRoot(fixtureValue, (root) =>
			persistIncidentFinalizationSealWithinRoot(root, name, prepared),
		);
		expect(first.state).toBe("applied");
		const second = withRunRoot(fixtureValue, (root) =>
			persistIncidentFinalizationSealWithinRoot(root, name, prepared),
		);
		expect(second).toMatchObject({ state: "noop", authoritativeBytesMatch: true, effects: [] });

		const conflictPrepared = prepareIncidentFinalizationSeal({ state: "different" });
		const conflict = withRunRoot(fixtureValue, (root) =>
			persistIncidentFinalizationSealWithinRoot(root, name, conflictPrepared),
		);
		expect(conflict).toMatchObject({ state: "conflict", authoritativeBytesMatch: false, effects: [] });
		expect(readFileSync(join(fixtureValue.run, name), "utf8")).toBe(prepared.bytes);
	});

	it("cleans an exact leftover stage without replacing the destination", () => {
		const fixtureValue = fixture();
		const name = "service-finalization-seal.json";
		const prepared = prepareIncidentFinalizationSeal({ state: "sealed" });
		writeFileSync(join(fixtureValue.run, name), prepared.bytes, { mode: 0o600 });
		writeFileSync(join(fixtureValue.run, stagingName(name, prepared.bytes)), prepared.bytes, { mode: 0o600 });

		const result = withRunRoot(fixtureValue, (root) =>
			persistIncidentFinalizationSealWithinRoot(root, name, prepared),
		);
		expect(result).toMatchObject({ state: "noop", authoritativeBytesMatch: true });
		expect(result.effects.filter((effect) => effect.kind === "remove")).toHaveLength(1);
		expect(existsSync(join(fixtureValue.run, stagingName(name, prepared.bytes)))).toBe(false);
	});

	it("reports an injected post-publication durability failure with root-only readback", () => {
		const fixtureValue = fixture();
		const name = "service-finalization-seal.json";
		const prepared = prepareIncidentFinalizationSeal({ state: "sealed" });
		const result = withRunRoot(fixtureValue, (root) => {
			let syncs = 0;
			const injected = Object.freeze({
				...root,
				fsyncDirectory(path: Parameters<IncidentCasRootMutation["fsyncDirectory"]>[0]): void {
					syncs += 1;
					if (syncs === 2) throw new Error("injected post-publication durability failure");
					root.fsyncDirectory(path);
				},
			});
			return persistIncidentFinalizationSealWithinRoot(injected, name, prepared);
		});

		expect(result).toMatchObject({ state: "ambiguous", authoritativeBytesMatch: true, effects: [] });
		expect(readFileSync(join(fixtureValue.run, name), "utf8")).toBe(prepared.bytes);
	});

	it("recovers a hardlink residue on the next root invocation", () => {
		const fixtureValue = fixture();
		const name = "service-finalization-seal.json";
		const prepared = prepareIncidentFinalizationSeal({ state: "sealed" });
		const first = withRunRoot(fixtureValue, (root) => {
			const injected = Object.freeze({
				...root,
				unlinkFile(path: Parameters<IncidentCasRootMutation["unlinkFile"]>[0]): void {
					if (root.lstat(path)?.nlink === 2n) throw new Error("injected crash after hardlink before unlink");
					root.unlinkFile(path);
				},
			});
			return persistIncidentFinalizationSealWithinRoot(injected, name, prepared);
		});
		expect(first).toMatchObject({ state: "ambiguous", authoritativeBytesMatch: true, effects: [] });

		const staging = join(fixtureValue.run, stagingName(name, prepared.bytes));
		expect(readFileSync(join(fixtureValue.run, name), "utf8")).toBe(prepared.bytes);
		expect(statSync(join(fixtureValue.run, name)).nlink).toBe(2);
		expect(existsSync(staging)).toBe(true);

		const recovered = withRunRoot(fixtureValue, (root) =>
			persistIncidentFinalizationSealWithinRoot(root, name, prepared),
		);
		expect(recovered).toMatchObject({ state: "noop", authoritativeBytesMatch: true });
		expect(readFileSync(join(fixtureValue.run, name), "utf8")).toBe(prepared.bytes);
		expect(statSync(join(fixtureValue.run, name)).nlink).toBe(1);
		expect(existsSync(staging)).toBe(false);
		expect(readdirSync(fixtureValue.run)).toEqual([name]);
	});

	it("does not write through a revoked root capability", () => {
		const fixtureValue = fixture();
		let capturedRunRoot: IncidentCasRootMutation | undefined;
		const admission = acquireIncidentCasTransactionDetailed(fixtureValue.recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		const committed = admission.transaction.withRoot((root) => {
			return root.withDirectory(root.relative("run"), (runRoot) => {
				capturedRunRoot = runRoot;
				return readdirSync(fixtureValue.run);
			});
		});
		expect(committed).toMatchObject({ state: "committed", value: [] });
		expect(admission.transaction.release()).toMatchObject({ state: "released" });
		if (!capturedRunRoot) throw new Error("fixture did not capture run root");
		const recorderBefore = readdirSync(fixtureValue.recorder);
		const runBefore = readdirSync(fixtureValue.run);
		const prepared = prepareIncidentFinalizationSeal({ state: "sealed" });

		const result = persistIncidentFinalizationSealWithinRoot(
			capturedRunRoot,
			"service-finalization-seal.json",
			prepared,
		);
		expect(result).toMatchObject({ state: "ambiguous", authoritativeBytesMatch: false, effects: [] });
		expect(readdirSync(fixtureValue.run)).toEqual(runBefore);
		expect(readdirSync(fixtureValue.recorder)).toEqual(recorderBefore);
		expect(existsSync(join(fixtureValue.run, "service-finalization-seal.json"))).toBe(false);
		expect(existsSync(join(fixtureValue.run, stagingName("service-finalization-seal.json", prepared.bytes)))).toBe(
			false,
		);
	});

	it("fails closed when the retained recorder root is replaced, without successor writes", () => {
		const fixtureValue = fixture();
		const name = "service-finalization-seal.json";
		const prepared = prepareIncidentFinalizationSeal({ state: "sealed" });
		const displacedRecorder = `${fixtureValue.recorder}-displaced`;
		const successorRun = join(fixtureValue.recorder, "run");
		const admission = acquireIncidentCasTransactionDetailed(fixtureValue.recorder);
		expect(admission).toMatchObject({ state: "acquired" });
		if (admission.state !== "acquired") return;
		let helperResult: unknown;
		let replaced = false;
		let mutation:
			| { state: "committed"; value: unknown }
			| { state: "root_detached"; evidence: "durable" | "pending" };
		try {
			mutation = admission.transaction.withRoot((root) =>
				root.withDirectory(root.relative("run"), (runRoot) => {
					// Replace the canonical parent while the descriptor-bound root remains captured.
					// The capability guard must reject before any successor path is touched.
					renameSync(fixtureValue.recorder, displacedRecorder);
					replaced = true;
					mkdirSync(fixtureValue.recorder, { mode: 0o700 });
					mkdirSync(successorRun, { mode: 0o700 });
					helperResult = persistIncidentFinalizationSealWithinRoot(runRoot, name, prepared);
					return helperResult;
				}),
			);
			expect(mutation).toMatchObject({ state: "root_detached" });
			expect(helperResult).toMatchObject({ state: "ambiguous", authoritativeBytesMatch: false, effects: [] });
			expect(readdirSync(successorRun)).toEqual([]);
			expect(existsSync(join(fixtureValue.recorder, name))).toBe(false);
			expect(existsSync(join(fixtureValue.recorder, stagingName(name, prepared.bytes)))).toBe(false);
		} finally {
			if (replaced) {
				rmSync(fixtureValue.recorder, { recursive: true, force: true });
				renameSync(displacedRecorder, fixtureValue.recorder);
			}
		}
		expect(admission.transaction.release()).toMatchObject({ state: "released" });
		expect(readdirSync(fixtureValue.run)).toEqual([]);
		expect(existsSync(join(fixtureValue.recorder, name))).toBe(false);
		expect(existsSync(join(fixtureValue.recorder, stagingName(name, prepared.bytes)))).toBe(false);
	});

	it("rejects an unsafe control name without touching the root", () => {
		const fixtureValue = fixture();
		const before = readdirSync(fixtureValue.run);
		expect(() =>
			withRunRoot(fixtureValue, (root) =>
				persistIncidentFinalizationSealWithinRoot(
					root,
					"../service-finalization-seal.json",
					prepareIncidentFinalizationSeal({ state: "sealed" }),
				),
			),
		).toThrow(/name|relative|control/i);
		expect(readdirSync(fixtureValue.run)).toEqual(before);
	});
});
