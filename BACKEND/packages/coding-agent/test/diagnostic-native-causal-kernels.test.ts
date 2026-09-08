import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import {
	type CausalOccurrence,
	type CausalPlatformIdentity,
	type CausalTarget,
	classifyCausalCapture,
} from "../src/modes/daemon/diagnostic-causal-classifier.js";

const native = process.env.PRIME_AGENT_NATIVE_CAUSAL_TESTS === "1";
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cases = ["shutdown", "kill", "group-kill", "pidfd", "native-crash", "healthy-stop", "close-shell"];
const replay = process.env.PRIME_AGENT_NATIVE_CAUSAL_REPLAY;
const evidence =
	replay ?? join(process.env.PRIME_AGENT_NATIVE_CAUSAL_EVIDENCE ?? tmpdir(), `native-causal-${randomUUID()}`);
type Capture = {
	target: CausalTarget;
	platform: CausalPlatformIdentity;
	producerAliveAtCapture: boolean;
	probeSha256: string;
};
const captures = new Map<string, { directory: string; capture: Capture; occurrences: CausalOccurrence[] }>();
let providerWarnings: string[] = [];

describe.skipIf(!native)("real IPython with the maintained native causal probe", () => {
	beforeAll(async () => {
		await mkdir(dirname(evidence), { recursive: true, mode: 0o700 });
		const selected = process.env.PRIME_AGENT_NATIVE_CAUSAL_CASES ?? cases.join(",");
		const arguments_ = [
			join(packageRoot, "scripts/test-diagnostic-native-causal-kernels.py"),
			"--evidence",
			evidence,
			"--node",
			process.execPath,
			"--python",
			process.env.PRIME_AGENT_KERNEL_PYTHON ?? join(homedir(), ".prime", "agent", "kernel-venv", "bin", "python"),
			"--cases",
			selected,
		];
		if (process.env.PRIME_AGENT_NATIVE_CAUSAL_WITHOUT_PROBE === "1") arguments_.push("--without-probe");
		if (process.env.PRIME_AGENT_NATIVE_CAUSAL_PROBE)
			arguments_.push("--probe", process.env.PRIME_AGENT_NATIVE_CAUSAL_PROBE);
		if (!replay)
			await new Promise<void>((resolveRun, reject) => {
				const child = spawn("/usr/bin/python3", arguments_, { stdio: ["ignore", "pipe", "pipe"] });
				let output = "";
				const collect = (chunk: Buffer) => {
					output = (output + chunk.toString()).slice(-32_768);
				};
				child.stdout.on("data", collect);
				child.stderr.on("data", collect);
				child.once("error", reject);
				child.once("exit", (code, signal) => {
					if (code === 0) resolveRun();
					else
						reject(
							new Error(`Isolated causal capture failed (${code}/${signal}): ${output}\nEvidence: ${evidence}`),
						);
				});
			});
		const stderr = await readFile(join(evidence, "probe.stderr"), "utf8");
		providerWarnings = stderr.split("\n").filter((line) => /WARNING|ERROR/.test(line));
		for (const name of (await readdir(evidence)).filter((entry) => /^capture-\d+$/.test(entry))) {
			const directory = join(evidence, name);
			const capture = JSON.parse(await readFile(join(directory, "capture.json"), "utf8")) as Capture;
			const oracle = JSON.parse(await readFile(join(directory, "oracle.json"), "utf8")) as { case: string };
			const occurrences: CausalOccurrence[] = [];
			for (const source of ["journal", "probe"] as const) {
				const lines = (await readFile(join(directory, `${source}.jsonl`), "utf8"))
					.trim()
					.split("\n")
					.filter(Boolean);
				lines.forEach((payload, index) => {
					if (source === "journal") {
						const message = JSON.parse(payload).MESSAGE;
						try {
							if (JSON.parse(message).schema !== "prime-agent.diagnostic.v1") return;
						} catch {
							return;
						}
					}
					occurrences.push({ id: `${source}:${index}`, source, bootId: capture.platform.bootId, payload });
				});
			}
			if (providerWarnings.length)
				occurrences.push({
					id: "provider:stderr-warning",
					source: "probe",
					bootId: capture.platform.bootId,
					payload: JSON.stringify({
						event: "coverage_gap",
						kind: "probe_stderr_warning",
						warnings: providerWarnings,
					}),
				});
			captures.set(oracle.case, { directory, capture, occurrences });
			// This classifier receives only captured payloads and observed identities.
			await writeFile(
				join(directory, "classification.json"),
				JSON.stringify(
					classifyCausalCapture({
						target: capture.target,
						platform: capture.platform,
						occurrences,
					}),
					null,
					2,
				),
				{ mode: 0o600 },
			);
		}
		console.info(`Native causal evidence: ${evidence}${replay ? " (capture replay)" : ""}`);
	}, 310_000);

	function observed(name: string) {
		const row = captures.get(name);
		if (!row) throw new Error(`Missing captured case ${name}: ${evidence}`);
		expect(row.capture.producerAliveAtCapture).toBe(true);
		expect(row.capture.platform.procReaderBoottimeOffsetNs).toBe("0");
		const application = row.occurrences
			.filter((occurrence) => occurrence.source === "journal")
			.map((occurrence) => JSON.parse(JSON.parse(String(occurrence.payload)).MESSAGE));
		expect(application.filter((event) => event.type === "kernel_process_started")).toHaveLength(1);
		for (const event of application.filter((event) => event.kernelPid !== undefined)) {
			expect(event.kernelPid).toBe(row.capture.target.pid);
			expect(event.kernelInstanceId).toBe(row.capture.target.kernelInstanceId);
			expect(event.kernelProcessStartId).toBe(`proc:${row.capture.target.processStartTicks}`);
		}
		const result = classifyCausalCapture({
			target: row.capture.target,
			platform: row.capture.platform,
			occurrences: row.occurrences,
		});
		expect(result.coverageComplete).toBe(false);
		expect(result.missingEvidence).not.toContain("input_row_limit");
		expect(result.missingEvidence).not.toContain("output_fact_limit");
		expect(providerWarnings).toEqual([]);
		return { ...row, result };
	}

	it("attributes an ordinary signal only from matching native call, generation, delivery and exit", () => {
		const { capture, occurrences, result } = observed("kill");
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("user_signal");
		expect(result.initiator?.syscallKind).toBe(1);
		expect(
			result.facts
				.filter((fact) => result.supportingOccurrenceIds.includes(fact.occurrenceId))
				.map((fact) => fact.event),
		).toEqual(
			expect.arrayContaining(["signal_call", "signal_generate", "signal_return", "signal_deliver", "process_exit"]),
		);
		for (const removed of ["signal_call", "signal_generate", "signal_return", "signal_deliver"]) {
			const incomplete = classifyCausalCapture({
				target: capture.target,
				platform: capture.platform,
				occurrences: occurrences.filter(
					(row) => row.source !== "probe" || JSON.parse(String(row.payload)).event !== removed,
				),
			});
			expect(incomplete.cause).toBe("unresolved");
		}
		const journalOnly = classifyCausalCapture({
			target: capture.target,
			platform: capture.platform,
			occurrences: occurrences.filter((row) => row.source === "journal"),
		});
		expect(journalOnly.status).toBe("process_exited");
		expect(journalOnly.cause).toBe("unresolved");
	});

	it("retains a negative process-group target as an observed syscall argument", () => {
		const { capture, result } = observed("group-kill");
		expect(result.cause).toBe("user_signal");
		expect(result.initiator?.syscallKind).toBe(1);
		expect(
			result.facts.some(
				(fact) => fact.event === "signal_call" && fact.fields.target_argument === -Number(capture.target.pid),
			),
		).toBe(true);
	});

	it("attributes pidfd signaling without treating the descriptor as a target PID", () => {
		const { result } = observed("pidfd");
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("user_signal");
		expect(result.initiator?.syscallKind).toBe(4);
	});

	it("identifies the native SIGSEGV from positive-code generation, delivery and process death", () => {
		const { result } = observed("native-crash");
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("native_fault");
		expect(result.initiator).toBeUndefined();
		expect(
			result.facts.some(
				(fact) =>
					fact.event === "signal_generate" && Number(fact.fields.code) > 0 && fact.fields.call_time_ns === "0",
			),
		).toBe(true);
	});

	it("keeps explicit application shutdown sequencing distinct from an unknown native mechanism", () => {
		const { result } = observed("shutdown");
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("application_shutdown_sequence");
		expect(result.initiator).toEqual({ caller: "nativeFixture.shutdown", reason: "session_closed" });
		expect(result.missingEvidence).toContain("native_shutdown_mechanism_unresolved");
	});

	it("retains sentinel state through STOP/CONT while reporting the observed heartbeat gap", async () => {
		const { directory, result } = observed("healthy-stop");
		const oracle = JSON.parse(await readFile(join(directory, "oracle.json"), "utf8"));
		expect(oracle.retained).toEqual({ status: "ok", stdout: String(oracle.observedKernel.pid) });
		expect(result.status).toBe("channel_unavailable");
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("process_exit_not_observed");
		expect(result.facts.some((fact) => fact.event === "process_exit")).toBe(false);
	});

	it("captures native socket closure and missing shell reply without inventing a process death", () => {
		const { result } = observed("close-shell");
		expect(result.status).toBe("channel_unavailable");
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("socket_close_does_not_establish_remote_channel_loss");
		expect(result.facts.some((fact) => fact.event === "socket_close")).toBe(true);
		expect(result.facts.some((fact) => fact.event === "process_exit")).toBe(false);
	});
});
