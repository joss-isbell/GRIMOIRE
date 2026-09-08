import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runIncidentRecorderService } from "../src/modes/daemon/incident-recorder.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

const directories: string[] = [];
afterEach(() => {
	vi.restoreAllMocks();
	for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("recorder service activation admission", () => {
	it("refuses an unactivated service before opening writers or creating recorder state", async () => {
		const directory = mkdtempSync(join(tmpdir(), "recorder-service-admission-"));
		directories.push(directory);
		const start = vi.spyOn(IncidentRecorderWriter.prototype, "start").mockRejectedValue(new Error("unexpected writer start"));
		await expect(runIncidentRecorderService(directory, { notify: () => {} })).rejects.toThrow(/activation contract/);
		expect(start).not.toHaveBeenCalled();
		expect(existsSync(join(directory, "incident-recorder"))).toBe(false);
	});
});
