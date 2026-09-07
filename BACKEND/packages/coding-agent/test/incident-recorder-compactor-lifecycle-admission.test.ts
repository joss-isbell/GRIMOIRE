import { describe, expect, it } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";

function admissionHarness(recovering: boolean) {
	const compactor = Object.create(IncidentRecorderCompactor.prototype) as IncidentRecorderCompactor;
	Object.assign(compactor, {
		storageModeState: recovering ? "recovery-only" : "normal",
		storageAccountingReadyState: true,
		pausedUntilMs: 0,
	});
	return compactor as unknown as {
		waitUntilAdmitted(
			signal: AbortSignal,
			options: {
				onRecoveryPass?: () => Promise<boolean>;
				onNormalWriterAdmission?: () => Promise<boolean>;
			},
		): Promise<void>;
	};
}

describe("compactor writer lifecycle admission ordering", () => {
	it("awaits writer shutdown and recovery before a storage rescan can reopen admission", async () => {
		const compactor = admissionHarness(true);
		const events: string[] = [];
		Object.assign(compactor, {
			abortableDelay: async () => {
				events.push("delay");
			},
			initializeStorageAccounting: async () => {
				events.push("scan");
				Object.assign(compactor, { storageModeState: "normal" });
			},
		});
		await compactor.waitUntilAdmitted(new AbortController().signal, {
			onRecoveryPass: async () => {
				events.push("closing");
				await Promise.resolve();
				events.push("recovery-owned");
				return false;
			},
			onNormalWriterAdmission: async () => {
				events.push("normal-owned");
				return true;
			},
		});
		expect(events).toEqual(["closing", "recovery-owned", "delay", "scan", "normal-owned"]);
	});

	it("does not admit journal mutation until normal writer ownership is reacquired", async () => {
		const compactor = admissionHarness(false);
		const events: string[] = [];
		let attempts = 0;
		Object.assign(compactor, {
			abortableDelay: async () => {
				events.push("delay");
			},
		});
		await compactor.waitUntilAdmitted(new AbortController().signal, {
			onNormalWriterAdmission: async () => {
				events.push("admit");
				return ++attempts === 2;
			},
		});
		expect(events).toEqual(["admit", "delay", "admit"]);
	});
});
