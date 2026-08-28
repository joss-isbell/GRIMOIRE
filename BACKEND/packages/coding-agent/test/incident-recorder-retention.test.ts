import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	runIncidentRetentionPass,
} from "../src/modes/daemon/incident-recorder-retention.js";

const roots: string[] = [];
const NOW = Date.parse("2026-08-28T00:00:00.000Z");

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { agentDir: string; runs: string; incidents: string } {
	const agentDir = mkdtempSync(join(tmpdir(), "prime-agent-causal-retention-"));
	roots.push(agentDir);
	const runs = join(agentDir, "incident-recorder", "runs");
	const incidents = join(agentDir, "incidents");
	mkdirSync(runs, { recursive: true });
	mkdirSync(incidents, { recursive: true });
	return { agentDir, runs, incidents };
}

function terminalRun(runs: string, name: string, completedMs: number): string {
	const path = join(runs, name);
	mkdirSync(path);
	writeFileSync(
		join(path, ".retention-terminal.json"),
		JSON.stringify({ completed: { wallTime: new Date(completedMs).toISOString(), monotonicNs: "1" } }),
	);
	return path;
}

function completedIncident(incidents: string, name: string, completedMs: number): string {
	const path = join(incidents, name);
	mkdirSync(path);
	writeFileSync(
		join(path, "summary.json"),
		JSON.stringify({ finalized: { wallTime: new Date(completedMs).toISOString() } }),
	);
	return path;
}

describe("simple causal-evidence retention", () => {
	it("keeps terminal runs and incidents for three days, then removes their whole private directories", () => {
		const target = fixture();
		const recent = terminalRun(target.runs, "recent-run", NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS + 1);
		const old = terminalRun(target.runs, "old-run", NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS - 1);
		const incident = completedIncident(target.incidents, "old-incident", NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS - 1);
		mkdirSync(join(old, "evidence"));
		writeFileSync(join(old, "evidence", "causal.json"), "evidence");

		const result = runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW });
		expect(existsSync(recent)).toBe(true);
		expect(existsSync(old)).toBe(false);
		expect(existsSync(incident)).toBe(false);
		expect(result.deletedEntries).toBe(2);
	});

	it("fails closed for active, incomplete, malformed, and symlink entries", () => {
		const target = fixture();
		const active = terminalRun(target.runs, "active-run", NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS - 1);
		writeFileSync(join(active, ".recorder-active"), "active");
		const incomplete = join(target.runs, "incomplete-run");
		mkdirSync(incomplete);
		const malformed = join(target.incidents, "malformed-incident");
		mkdirSync(malformed);
		writeFileSync(join(malformed, "summary.json"), "not-json");
		const outside = mkdtempSync(join(tmpdir(), "prime-agent-causal-retention-outside-"));
		roots.push(outside);
		writeFileSync(join(outside, "must-survive"), "safe");
		symlinkSync(outside, join(target.runs, "linked-run"));

		const result = runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW });
		expect(existsSync(active)).toBe(true);
		expect(existsSync(incomplete)).toBe(true);
		expect(existsSync(malformed)).toBe(true);
		expect(existsSync(join(outside, "must-survive"))).toBe(true);
		expect(result.protectedActiveRuns).toContain(active);
		expect(result.pendingIncident).toBe(true);
		expect(result.uncertainties.some((value) => value.includes("linked-run"))).toBe(true);
	});

	it("honors hard per-pass scan and delete limits and converges across passes", () => {
		const target = fixture();
		const paths = Array.from({ length: 25 }, (_, index) =>
			terminalRun(target.runs, `old-${String(index).padStart(3, "0")}`, NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS - 1),
		);
		let passes = 0;
		while (paths.some((path) => existsSync(path)) && passes < 20) {
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 5,
				maxDeletes: 2,
			});
			expect(result.scannedEntries).toBeLessThanOrEqual(5);
			expect(result.deletedEntries).toBeLessThanOrEqual(2);
			passes += 1;
		}
		expect(paths.every((path) => !existsSync(path))).toBe(true);
		expect(passes).toBeLessThan(20);
	});
});
