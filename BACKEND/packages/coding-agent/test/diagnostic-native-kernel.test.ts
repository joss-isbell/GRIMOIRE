import { type ChildProcess, spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { DiagnosticArtifactOperations } from "../src/modes/daemon/diagnostic-evidence-artifacts.js";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";
import { exportNativeJournal, readNativeJournal } from "../src/modes/daemon/diagnostic-native-journal.js";

const enabled = process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_TESTS === "1";
const fixture = fileURLToPath(new URL("./fixtures/diagnostic-native-kernel.ts", import.meta.url));
const loader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));

interface Ready {
	producerPid: number;
	kernelPid: number;
	kernelInstanceId: string;
	kernelProcessStartId: string;
}
interface JournalEntry {
	__CURSOR: string;
	__REALTIME_TIMESTAMP: string;
	__MONOTONIC_TIMESTAMP: string;
	_BOOT_ID: string;
	_PID: string;
	SYSLOG_IDENTIFIER: string;
	MESSAGE: string;
}

function diagnostic(raw: Buffer): Record<string, unknown> | undefined {
	try {
		const message: unknown = JSON.parse((JSON.parse(raw.toString("utf8")) as JournalEntry).MESSAGE);
		if (
			message &&
			typeof message === "object" &&
			"schema" in message &&
			message.schema === "prime-agent.diagnostic.v1"
		) {
			return message as Record<string, unknown>;
		}
	} catch {
		return undefined;
	}
	return undefined;
}

async function state<T>(root: string, name: string, producer: ChildProcess): Promise<T> {
	const deadline = Date.now() + 35_000;
	while (Date.now() < deadline) {
		const error = await readFile(join(root, "error.json"), "utf8").catch(() => undefined);
		if (error) throw new Error(`native_kernel_fixture_failed: ${error}`);
		const value = await readFile(join(root, `${name}.json`), "utf8").catch(() => undefined);
		if (value) return JSON.parse(value) as T;
		if (producer.exitCode !== null || producer.signalCode !== null) {
			throw new Error(`native_kernel_fixture_exited: ${producer.exitCode ?? producer.signalCode}`);
		}
		await delay(50);
	}
	throw new Error(`native_kernel_fixture_timeout: ${name}`);
}

it.skipIf(!enabled)(
	"captures a real kernel exit through native journald, SQLite and export while the owning producer stays alive",
	async () => {
		if (process.platform !== "linux") throw new Error("native_diagnostic_prerequisite: Linux is required");
		const python = process.env.PRIME_AGENT_CAUSAL_PYTHON ?? "/home/joss/.prime/agent/kernel-venv/bin/python";
		for (const path of ["/usr/bin/systemd-cat", "/usr/bin/journalctl", python, loader]) {
			await access(path).catch(() => {
				throw new Error(`native_diagnostic_prerequisite: executable or loader unavailable: ${path}`);
			});
		}
		const root = await mkdtemp(join(tmpdir(), "diagnostic-native-kernel-"));
		const identifier = `prime-native-test-${randomUUID()}`;
		const source = `journal:${identifier}`;
		const sinceMs = Date.now() - 1000;
		const producer = spawn(
			"/usr/bin/systemd-cat",
			[
				`--identifier=${identifier}`,
				"--level-prefix=false",
				process.execPath,
				"--import",
				loader,
				fixture,
				root,
				python,
			],
			{
				cwd: root,
				stdio: ["ignore", "pipe", "pipe"],
				env: {
					PATH: `${dirname(process.execPath)}:/usr/sbin:/usr/bin:/bin`,
					HOME: root,
					TMPDIR: root,
					LANG: "C.UTF-8",
					PRIME_AGENT_CODING_AGENT_DIR: join(root, "config"),
					PRIME_AGENT_SESSION_DIR: join(root, "sessions"),
					PRIME_AGENT_KERNEL_FORKSERVER: "0",
					PRIME_AGENT_DIAGNOSTICS: "native",
				},
			},
		);
		let startupError = "";
		producer.on("error", (error) => {
			startupError = String(error);
		});
		producer.stderr!.on("data", (chunk: Buffer) => {
			startupError = (startupError + chunk.toString("utf8")).slice(-8192);
		});
		producer.stdout!.resume();
		const closed = new Promise<void>((resolve) => producer.once("close", () => resolve()));
		let store: DiagnosticEvidenceStore | undefined;
		try {
			store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
			const ready = await state<Ready>(root, "ready", producer).catch((error: unknown) => {
				throw new Error(`${String(error)}; systemd-cat stderr: ${startupError}`);
			});
			expect(ready.producerPid).toBe(producer.pid);
			expect(ready.kernelPid).not.toBe(ready.producerPid);
			await writeFile(join(root, "command"), "exit-kernel", { mode: 0o600 });
			expect(await state(root, "failed", producer)).toMatchObject({
				producerPid: ready.producerPid,
				executionRejected: true,
			});
			const rawByCursor = new Map<string, Buffer>();
			const journalOptions = { identifier };
			const deadline = Date.now() + 10_000;
			while (Date.now() < deadline) {
				for await (const raw of readNativeJournal(journalOptions, { sinceMs }, AbortSignal.timeout(5000))) {
					rawByCursor.set((JSON.parse(raw.toString("utf8")) as JournalEntry).__CURSOR, raw);
				}
				if ([...rawByCursor.values()].some((raw) => diagnostic(raw)?.type === "kernel_diagnostic_capture_complete"))
					break;
				await delay(100);
			}
			const records = [...rawByCursor.values()];
			await writeFile(
				join(root, "observed-journal.jsonl"),
				Buffer.concat(records.flatMap((raw) => [raw, Buffer.from("\n")])),
			);
			const events = records.map(diagnostic).filter((event) => event !== undefined);
			expect(JSON.stringify(events)).not.toContain("native-evidence-sentinel");
			expect(events.filter((event) => event.type === "kernel_process_started")).toHaveLength(1);
			const exit = events.find((event) => event.type === "kernel_process_exit_observed");
			expect(exit).toMatchObject({
				producerPid: ready.producerPid,
				kernelPid: ready.kernelPid,
				kernelInstanceId: ready.kernelInstanceId,
				kernelProcessStartId: ready.kernelProcessStartId,
				ownerPid: ready.producerPid,
				code: 23,
				signal: null,
				lifecycleState: "running",
				delivery: "queue_accepted",
			});
			expect(exit?.senderPid).toBeUndefined();
			expect(events.find((event) => event.type === "kernel_unexpected_exit")).toMatchObject({
				kernelInstanceId: ready.kernelInstanceId,
				code: 23,
				signal: null,
				reason: "process_exit",
			});
			const teardown = events.filter((event) => event.type === "kernel_lifecycle_intent");
			for (const intent of teardown) {
				expect(intent.operation).toBe("cleanup_resources");
				expect(Number(intent.sequence)).toBeGreaterThan(Number(exit?.sequence));
			}
			const pipeline = new DiagnosticEvidencePipeline(store);
			expect(await store.listIncidents()).toEqual([]);
			for (const raw of records) {
				const entry = JSON.parse(raw.toString("utf8")) as JournalEntry;
				expect(entry.SYSLOG_IDENTIFIER).toBe(identifier);
				expect(entry.__CURSOR).toEqual(expect.any(String));
				expect(entry.__MONOTONIC_TIMESTAMP).toMatch(/^\d+$/);
				expect(entry._BOOT_ID).toMatch(/^[a-f\d]{32}$/);
				expect(await pipeline.ingestJournal(source, raw)).toEqual({
					journalObserved: true,
					durablyStored: true,
					cursor: entry.__CURSOR,
				});
			}
			expect(await pipeline.publishPending()).toBeGreaterThan(0);
			const incidents = await store.listIncidents();
			const incident = incidents.find(
				(entry) => (entry.coverage.trigger as { type?: string }).type === "kernel_unexpected_exit",
			);
			expect(incident).toMatchObject({
				state: "published",
				coverage: { cause: { status: "unresolved" }, durableTriggerObserved: true, exportComplete: false },
			});
			if (!incident) throw new Error("Kernel failure incident was not published");
			expect(incident.windowStartMs).toBe(incident.triggerTimeMs - 30 * 60_000);
			expect(incident.windowEndMs).toBe(incident.triggerTimeMs + 15 * 60_000);
			expect(incident.limitations).toContain("The post-trigger window is still being captured.");
			process.kill(ready.producerPid, 0);
			expect(producer.exitCode).toBeNull();
			const stored = await store.readWindow({ startMs: sinceMs, endMs: Date.now() });
			expect(stored.occurrences).toHaveLength(records.length);
			for (const occurrence of stored.occurrences) {
				const entry = JSON.parse(Buffer.from(occurrence.payload).toString("utf8")) as JournalEntry;
				expect(Buffer.from(occurrence.payload)).toEqual(rawByCursor.get(entry.__CURSOR));
				expect(occurrence.monotonicNs).toBe(String(BigInt(entry.__MONOTONIC_TIMESTAMP) * 1000n));
			}
			const artifactsRoot = join(root, "artifacts");
			const artifacts = await DiagnosticArtifactOperations.open({
				store,
				root: artifactsRoot,
				exportArtifact: (_operation, signal) =>
					exportNativeJournal(journalOptions, { sinceMs: incident.windowStartMs, untilMs: Date.now() }, signal),
			});
			const exportResult = await artifacts.reconcile();
			expect(exportResult.failures).toEqual([]);
			expect(exportResult.pending).toBe(0);
			const [artifact] = await store.listArtifacts(incident.id);
			if (!artifact) throw new Error("Native journal artifact was not recorded");
			const bytes = await readFile(join(artifactsRoot, artifact.path));
			expect(artifact.format).toBe("journal.export");
			expect(artifact.bytes).toBe(bytes.length);
			expect(artifact.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
			expect(bytes.toString("utf8")).toContain("kernel_process_exit_observed");
			expect(bytes.toString("utf8")).toContain("kernel_unexpected_exit");
			for (const cursor of rawByCursor.keys()) expect(bytes.toString("utf8")).toContain(`__CURSOR=${cursor}\n`);
			process.kill(ready.producerPid, 0);
			expect(producer.exitCode).toBeNull();
			await expect(access(join(root, "config", "incident-recorder"))).rejects.toMatchObject({ code: "ENOENT" });
			await writeFile(
				join(root, "receipt.json"),
				JSON.stringify({
					identifier,
					ready,
					incident,
					artifact,
					occurrences: records.length,
					producerAliveAfterExport: true,
				}),
				{ mode: 0o600 },
			);
		} finally {
			await writeFile(join(root, "command"), "stop");
			await Promise.race([closed, delay(5000, undefined, { ref: false })]);
			if (producer.exitCode === null && producer.signalCode === null) producer.kill("SIGTERM");
			await Promise.race([closed, delay(5000, undefined, { ref: false })]);
			if (producer.exitCode === null && producer.signalCode === null) producer.kill("SIGKILL");
			await closed;
			await store?.close();
			if (process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_KEEP_EVIDENCE === "1")
				console.info(`Native kernel evidence: ${root}`);
			else await rm(root, { recursive: true, force: true });
		}
	},
	60_000,
);
