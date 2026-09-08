import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "grim16-pin-maintenance-"));
	roots.push(root);
	const compactor = new IncidentRecorderCompactor({ agentDir: join(root, "agent") });
	const discovery = vi.fn(() => []);
	Object.assign(compactor, {
		storageAccountingReadyState: true,
		storageModeState: "normal",
		pausedUntilMs: 0,
		discoverPendingPinDirectoryNames: discovery,
	});
	return { compactor, discovery };
}

it("prevents new pin discovery across awaited retention work and resumes afterward", async () => {
	const { compactor, discovery } = fixture();
	expect(compactor.beginPinRetentionMaintenance()).toBe(true);
	compactor.processPendingPins();
	await Promise.resolve();
	compactor.processPendingPins();
	expect(compactor.beginPinRetentionMaintenance()).toBe(true);
	expect(discovery).not.toHaveBeenCalled();
	compactor.endPinRetentionMaintenance();
	compactor.processPendingPins();
	expect(discovery).toHaveBeenCalledOnce();
});

it.each(["activePinTraversal", "journalManifestValidation", "sysdigSourceCapture", "sysdigSegmentVerification"])(
	"does not admit retention while %s may still publish",
	(field) => {
		const { compactor } = fixture();
		Object.assign(compactor, { [field]: {} });
		expect(compactor.beginPinRetentionMaintenance()).toBe(false);
		Object.assign(compactor, { [field]: undefined });
		expect(compactor.beginPinRetentionMaintenance()).toBe(true);
		compactor.endPinRetentionMaintenance();
	},
);

it("does not admit retention while a child pin scan can still publish", () => {
	const { compactor } = fixture();
	const scans = new Map([["scan", {}]]);
	Object.assign(compactor, { activePinScans: scans });
	expect(compactor.beginPinRetentionMaintenance()).toBe(false);
	scans.clear();
	expect(compactor.beginPinRetentionMaintenance()).toBe(true);
	compactor.endPinRetentionMaintenance();
});
