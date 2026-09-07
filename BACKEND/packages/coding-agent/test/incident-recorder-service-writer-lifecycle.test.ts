import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import { IncidentRecorderServiceWriterLifecycle } from "../src/modes/daemon/incident-recorder-service-writer-lifecycle.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	acquireIncidentRecorderWriterRecoveryLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const directories: string[] = [];
afterEach(() => {
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});
function fixture() {
	const directory = mkdtempSync(join(tmpdir(), "recorder-service-lifecycle-"));
	directories.push(directory);
	const agentDir = join(directory, "agent");
	mkdirSync(join(agentDir, "incident-recorder"), { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { mode: 0o700 });
	const contract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: "a".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: acquireIncidentRecorderNamespaceCas,
	};
	return { agentDir, contract };
}

describe("service writer lifecycle sequencing", () => {
	it("does not announce normal mode when activation is lost while writers start", async () => {
		const f = fixture();
		let active = true;
		let stopped = false;
		f.contract.revalidateActivation = () => ({ state: active ? "valid" : "invalid" });
		const lifecycle = new IncidentRecorderServiceWriterLifecycle(f.agentDir, f.contract, {
			startNormalWriters: async () => {
				active = false;
			},
			stopNormalWriters: async () => {
				stopped = true;
			},
		});
		await expect(lifecycle.enterNormal()).rejects.toThrow(/lease.*startup/);
		expect(stopped).toBe(true);
		expect(lifecycle.normalLease).toBeUndefined();
		await lifecycle.close();
	});

	it("cleans a partially started writer before releasing its normal lease", async () => {
		const f = fixture();
		const events: string[] = [];
		const lifecycle = new IncidentRecorderServiceWriterLifecycle(f.agentDir, f.contract, {
			startNormalWriters: async () => {
				events.push("partial-start");
				throw new Error("start failed");
			},
			stopNormalWriters: async () => {
				expect(lifecycle.normalLease).toBeDefined();
				events.push("cleanup");
			},
		});
		await expect(lifecycle.enterNormal()).rejects.toThrow("start failed");
		expect(events).toEqual(["partial-start", "cleanup"]);
		expect(lifecycle.normalLease).toBeUndefined();
		expect(await lifecycle.enterRecovery()).toEqual({ state: "recovery" });
		await lifecycle.close();
		expect(await lifecycle.enterNormal()).toEqual({ state: "unavailable", reason: "closed" });
	});

	it("closes writers before recovery exclusion and releases recovery before restarting writers", async () => {
		const f = fixture();
		const events: string[] = [];
		const lifecycle = new IncidentRecorderServiceWriterLifecycle(f.agentDir, f.contract, {
			startNormalWriters: async () => {
				expect(lifecycle.normalLease).toBeDefined();
				expect(lifecycle.recoveryLease).toBeUndefined();
				events.push("start");
			},
			stopNormalWriters: async () => {
				expect(lifecycle.normalLease).toBeDefined();
				expect(lifecycle.recoveryLease).toBeUndefined();
				events.push("stop");
			},
		});
		expect(await lifecycle.enterNormal()).toEqual({ state: "normal" });
		expect(await lifecycle.enterRecovery()).toEqual({ state: "recovery" });
		expect(lifecycle.normalLease).toBeUndefined();
		expect(lifecycle.recoveryLease).toBeDefined();
		expect(acquireIncidentRecorderWriterNormalLease(f, f.contract).state).toBe("unavailable");
		expect(await lifecycle.enterNormal()).toEqual({ state: "normal" });
		expect(events).toEqual(["start", "stop", "start"]);
		await lifecycle.close();
		expect(events).toEqual(["start", "stop", "start", "stop"]);
		expect(lifecycle.normalLease).toBeUndefined();
		expect(lifecycle.recoveryLease).toBeUndefined();
		const recovery = acquireIncidentRecorderWriterRecoveryLease(f, f.contract);
		expect(recovery.state).toBe("acquired");
		if (recovery.state === "acquired") recovery.lease.release();
	});

	it("does not release normal exclusion when writer shutdown fails", async () => {
		const f = fixture();
		let failStop = true;
		const lifecycle = new IncidentRecorderServiceWriterLifecycle(f.agentDir, f.contract, {
			startNormalWriters: async () => {},
			stopNormalWriters: async () => {
				if (failStop) throw new Error("writer still open");
			},
		});
		expect(await lifecycle.enterNormal()).toEqual({ state: "normal" });
		await expect(lifecycle.enterRecovery()).rejects.toThrow("writer still open");
		expect(acquireIncidentRecorderWriterRecoveryLease(f, f.contract)).toEqual({
			state: "pending",
			reason: "normal_holders_active",
		});
		failStop = false;
		await lifecycle.close();
	});

	it("retries recovery exclusion without reopening writers while another normal holder remains", async () => {
		const f = fixture();
		const other = acquireIncidentRecorderWriterNormalLease(f, f.contract);
		expect(other.state).toBe("acquired");
		const lifecycle = new IncidentRecorderServiceWriterLifecycle(f.agentDir, f.contract, {
			startNormalWriters: async () => {
				throw new Error("must not start during recovery");
			},
			stopNormalWriters: async () => {
				throw new Error("no writer was started");
			},
		});
		expect(await lifecycle.enterRecovery()).toEqual({ state: "pending", reason: "normal_holders_active" });
		expect(lifecycle.normalLease).toBeUndefined();
		if (other.state === "acquired") other.lease.release();
		expect(await lifecycle.enterRecovery()).toEqual({ state: "recovery" });
		await lifecycle.close();
	});
});
