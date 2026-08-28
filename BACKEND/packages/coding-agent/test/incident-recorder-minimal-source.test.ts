import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

function source(relative: string): string {
	return readFileSync(fileURLToPath(new URL(`../src/modes/daemon/${relative}`, import.meta.url)), "utf8");
}

describe("minimal automatic causal recorder source boundary", () => {
	it("has no framed transport, journal replay, CAS, or output-warehouse machinery", () => {
		const runtime = [
			"incident-recorder.ts",
			"incident-recorder-writer.ts",
			"incident-recorder-linux.ts",
			"daemon-mode.ts",
			"daemon-supervisor.ts",
			"daemon-worker-client.ts",
			"daemon-catalog-process.ts",
		]
			.map(source)
			.join("\n");
		for (const forbidden of [
			"journalctl",
			"systemd-cat",
			"raw-application",
			"incident-recorder-protocol",
			"IncidentRecorderWriter",
			"appendSupervisorDiagnosticBytes",
			"PRIME_INCIDENT_RECORDER_CAPTURE",
			"PRIME_INCIDENT_RECORDER_RUN_TOKEN",
			"recordExactBytes",
			"refs/occurrences",
			"cas/sha256",
		])
			expect(runtime).not.toContain(forbidden);
		const supervisor = source("daemon-supervisor.ts");
		expect(supervisor).not.toContain("application_source_reference");
		expect(supervisor).not.toContain("supervisor_log_record");
		expect(supervisor).toContain("[INCIDENT_RECORDER_WORKER_ID_ENV]: workerId");
		for (const recorderEnvironment of [
			"INCIDENT_RECORDER_CHILD_ENV",
			"INCIDENT_RECORDER_RUN_DIR_ENV",
			"INCIDENT_RECORDER_SOCKET_ENV",
		])
			expect(supervisor).not.toContain(`delete workerEnvironment[${recorderEnvironment}]`);
		for (const deleted of ["incident-recorder-protocol.ts", "incident-recorder-transport.ts"])
			expect(existsSync(fileURLToPath(new URL(`../src/modes/daemon/${deleted}`, import.meta.url)))).toBe(false);
	});

	it("retains only exact identity and cgroup proc access plus bounded causal bundle inputs", () => {
		const recorder = source("incident-recorder.ts");
		const linux = source("incident-recorder-linux.ts");
		expect(recorder).not.toMatch(/\/proc\/\$\{pid\}\//);
		expect(linux).toContain(["`/proc/", "{pid}/cgroup`"].join("$"));
		expect(linux).not.toMatch(/`\/proc\/\$\{pid\}\/(?!cgroup`)/);
		expect(recorder).toContain('const causalResourceName = "linux-causal-resource.json"');
		expect(recorder).toContain('[...CAUSAL_TIMELINE_FILES, "reports"]');
		expect(recorder).toContain("sanitizeIncidentCausalFields");
		expect(recorder).toContain("source: CausalEventSource");
		expect(recorder).not.toContain("process.report.writeReport");
		expect(recorder).toContain("nodeReport?.getReport(error)");
		expect(recorder).not.toContain("nodeReport.reportOnFatalError = false");
		expect(recorder).toContain("nodeReport.reportOnUncaughtException = false");
		expect(recorder).toContain('"worker_fatal_evidence_gap"');
		const writer = source("incident-recorder-writer.ts");
		expect(writer).toContain("const MAX_EVENT_FILE_BYTES = 1024 * 1024");
		expect(writer).toContain("const MAX_EVENT_BYTES = 3584");
		expect(writer).toContain("const MAX_QUEUE_EVENTS = 64");
		expect(writer).toContain("fieldsTruncated?: true");
	});
});
