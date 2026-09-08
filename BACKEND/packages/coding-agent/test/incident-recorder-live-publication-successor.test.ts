import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";

interface FixtureRun {
	pid: number;
	code: number | null;
	signal: NodeJS.Signals | null;
	stdout: string;
	stderr: string;
	summary: Record<string, unknown>;
}

const roots: string[] = [];

async function runFixture(role: "A" | "B", agentDir: string): Promise<FixtureRun> {
	const script = fileURLToPath(new URL("./fixtures/incident-recorder-publication-successor.ts", import.meta.url));
	const loader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	const child = spawn(process.execPath, ["--import", loader, script, role, agentDir], {
		stdio: ["ignore", "pipe", "pipe"],
	});
	if (child.pid === undefined) throw new Error(`fixture ${role} did not expose a pid`);
	let stdout = "";
	let stderr = "";
	child.stdout?.setEncoding("utf8");
	child.stderr?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => (stdout += chunk));
	child.stderr?.on("data", (chunk: string) => (stderr += chunk));
	const pid = child.pid;
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
			child.once("error", reject);
			child.once("close", (code, signal) => resolve({ code, signal }));
			timer = setTimeout(() => {
				child.kill("SIGKILL");
				reject(new Error(`fixture ${role} timed out (pid ${pid})`));
			}, 30_000);
		});
		const line = stdout.trim().split(/\r?\n/).at(-1);
		if (!line) throw new Error(`fixture ${role} emitted no summary: ${stderr}`);
		return { pid, ...exit, stdout, stderr, summary: JSON.parse(line) as Record<string, unknown> };
	} finally {
		if (timer) clearTimeout(timer);
		if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
	}
}

function ownerPath(agentDir: string): string {
	return join(agentDir, "incident-recorder", "segments", ".writer-owner.json");
}

describe("live incident publication successor recovery", () => {
	afterEach(() => {
		for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
	});

	it("recovers a faulted root publication in a fresh successor process", async () => {
		const root = mkdtempSync(join(tmpdir(), "prime-agent-publication-successor-"));
		roots.push(root);
		const agentDir = join(root, "agent");

		const first = await runFixture("A", agentDir);
		expect({ code: first.code, signal: first.signal }).toEqual({ code: 1, signal: null });
		expect(first.summary).toMatchObject({ role: "A", pid: first.pid, faultTriggered: true });
		const firstError = first.summary.serviceError as Record<string, unknown>;
		expect(firstError).toMatchObject({
			name: "IncidentRecorderSegmentOwnershipUncertainError",
			reason: "live_publication_partial_filesystem_failure",
		});
		expect(Buffer.byteLength(String(firstError.message))).toBeLessThanOrEqual(256);
		expect(first.stderr).toContain("IncidentRecorderSegmentOwnershipUncertainError");
		const firstOwner = first.summary.owner as Record<string, unknown>;
		expect(firstOwner).toMatchObject({ pid: first.pid, version: 1 });
		expect(firstOwner.startTime).toEqual(expect.any(String));
		expect((first.summary as Record<string, unknown>).ownerLiveInProcess).toBe(true);
		expect(getProcessStartId(first.pid)).toBeUndefined();
		expect(existsSync(ownerPath(agentDir))).toBe(true);
		expect(JSON.parse(readFileSync(ownerPath(agentDir), "utf8"))).toEqual(firstOwner);

		const contender = first.summary.contender as Record<string, unknown>;
		expect(contender).toMatchObject({ state: "unavailable", pageState: "incomplete" });
		expect(String(contender.reason)).toContain("could not acquire unique incident recorder writer ownership");
		const staged = first.summary.stagedPage as Record<string, unknown>;
		expect(staged).toMatchObject({ nlink: 2, temporaryCount: 1 });
		expect(typeof staged.sha256).toBe("string");
		expect((first.summary.accounting as Record<string, unknown>).storageMode).toBe("recovery-only");
		expect((first.summary.accounting as Record<string, unknown>).storageAccountingReady).toBe(false);

		const second = await runFixture("B", agentDir);
		expect({ code: second.code, signal: second.signal }).toEqual({ code: 0, signal: null });
		expect(second.summary).toMatchObject({
			role: "B",
			pid: second.pid,
			staleOwnerLive: false,
			ownerAfterCleanup: false,
		});
		const staleOwner = second.summary.staleOwner as Record<string, unknown>;
		expect(staleOwner).toEqual(firstOwner);
		expect(second.summary.ownerAfterOpen).toMatchObject({ pid: second.pid, version: 1 });

		const published = second.summary.first as Record<string, unknown>;
		const replayed = second.summary.second as Record<string, unknown>;
		expect(published).toMatchObject({ state: "published", noOp: false });
		expect(replayed).toMatchObject({ state: "published", noOp: true });
		expect(published.incidentId).toBeDefined();
		expect(published.publicationId).toBeDefined();
		const artifactHashes = second.summary.artifactTreeHash as Record<string, unknown>;
		expect(artifactHashes.first).toBe(artifactHashes.second);
		expect(second.summary.stagedPageSha256).toBe(staged.sha256);

		expect(second.summary.pages).toBe(1);
		expect(second.summary.eventCount).toBe(2);
		expect(second.summary.eventIdentities).toEqual([
			{
				runId: "55555555-5555-4555-8555-555555555555",
				runToken: "66666666-6666-4666-8666-666666666666",
				producerId: "77777777-7777-4777-8777-777777777777",
				occurrenceId: "00000000-0000-4000-8000-000000000001",
			},
			{
				runId: "55555555-5555-4555-8555-555555555555",
				runToken: "66666666-6666-4666-8666-666666666666",
				producerId: "88888888-8888-4888-8888-888888888888",
				occurrenceId: "00000000-0000-4000-8000-000000000002",
			},
		]);
		const references = second.summary.exactReferences as Array<Record<string, unknown>>;
		expect(references).toHaveLength(2);
		expect(references.every((reference) => reference.kind === "segment")).toBe(true);
		expect(references.map((reference) => (reference.locator as Record<string, unknown>).ordinal)).toEqual([1, 2]);
		expect(
			references.every((reference) => (reference.locator as Record<string, unknown>).segmentSequence === 1),
		).toBe(true);
		expect((second.summary.targetSnapshot as Record<string, unknown>).ordinal).toBe(2);
		expect((second.summary.targetSnapshot as Record<string, unknown>).segmentSequence).toBe(1);

		expect(second.summary.segmentFileNlinks).toEqual([1]);
		expect(second.summary.controlledResidue).toEqual([]);
		const accounting = second.summary.accounting as Record<string, unknown>;
		expect(accounting.reported).toEqual(accounting.actual);
		expect(accounting.reservations).toEqual({ bytes: 0, entries: 0, inodes: 0 });
		expect(second.summary.segmentControlledResidue).toEqual([]);
		const artifactPath = String(replayed.artifactPath);
		expect(readdirSync(join(artifactPath, "evidence")).filter((name) => name.startsWith(".")).length).toBe(0);
		expect(statSync(join(artifactPath, "evidence", "page-000000000001.json")).nlink).toBe(1);
		expect(statSync(join(artifactPath, "live-observation.json")).nlink).toBe(1);
		expect(existsSync(ownerPath(agentDir))).toBe(false);
	}, 45_000);
});
