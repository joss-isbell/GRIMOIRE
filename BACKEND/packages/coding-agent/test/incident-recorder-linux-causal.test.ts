import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	baselineLinuxIncidentEvidence,
	hasPositiveLinuxCgroupOomKillDelta,
	readLinuxIncidentEvidenceCorrelation,
	sampleLinuxIncidentEvidence,
} from "../src/modes/daemon/incident-recorder-linux.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function runDir(): string {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-linux-causal-"));
	roots.push(root);
	mkdirSync(root, { recursive: true });
	return root;
}

describe("minimal Linux causal resource evidence", () => {
	it("binds bounded cgroup samples to the exact process identity", () => {
		const run = runDir();
		const processStartId = getProcessStartId(process.pid);
		expect(processStartId).toBeTruthy();
		const baseline = baselineLinuxIncidentEvidence({
			runDir: run,
			pid: process.pid,
			processStartId: processStartId!,
		});
		expect(baseline).toMatchObject({ targetIdentityValidated: true });
		for (let index = 0; index < 40; index += 1) sampleLinuxIncidentEvidence({ runDir: run, phase: "periodic" });
		const persistedBytes = readFileSync(join(run, "linux-causal-resource.json"));
		const persisted = JSON.parse(persistedBytes.toString("utf8")) as {
			capability: { status: string; reason?: string };
			recent: unknown[];
			latest?: { events: Record<string, number>; eventsLocal: Record<string, number> };
		};
		expect(persistedBytes.length).toBeLessThanOrEqual(256 * 1024);
		if (persisted.capability.status === "available") {
			expect(persisted.recent).toHaveLength(32);
			expect(persisted.latest?.events).toBeTypeOf("object");
			expect(persisted.latest?.eventsLocal).toBeTypeOf("object");
		} else {
			expect(persisted.capability.reason).toBe("sample_unavailable");
		}
	});

	it("fails closed for a mismatched target identity", () => {
		const run = runDir();
		const summary = baselineLinuxIncidentEvidence({ runDir: run, pid: process.pid, processStartId: "proc:1" });
		expect(summary).toMatchObject({
			targetIdentityValidated: false,
			capability: { status: "unavailable", reason: "target_identity_unavailable" },
		});
	});

	it("attributes kernel OOM only from a positive exact cgroup counter delta", () => {
		const run = runDir();
		writeFileSync(
			join(run, "linux-causal-resource.json"),
			JSON.stringify({
				schemaVersion: 2,
				provider: "linux_cgroup_v2",
				target: { pid: 123, processStartId: "proc:1" },
				targetIdentityValidated: true,
				capability: { status: "available" },
				baseline: { events: { oom_kill: 4 }, eventsLocal: { oom_kill: 4 } },
				latest: { events: { oom_kill: 5 }, eventsLocal: { oom_kill: 5 } },
				recent: [],
			}),
		);
		expect(hasPositiveLinuxCgroupOomKillDelta(run, "SIGKILL")).toMatchObject({
			matched: true,
			baseline: 4,
			latest: 5,
			delta: 1,
		});
		expect(readLinuxIncidentEvidenceCorrelation(run)).toMatchObject({
			environmentClassification: "kernel_oom_kill",
			environmentEvidence: true,
			applicationEvidence: false,
		});
	});
});
