import { type ChildProcess, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
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
const fixture = fileURLToPath(new URL("./fixtures/diagnostic-native-parent-faults.ts", import.meta.url));
const loader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
interface Identity {
	pid: number;
	parentPid: number;
	startTicks: string;
	state: string;
}
interface Ready {
	observer: Identity;
	supervisor?: Identity;
	parent: Identity;
	forkserver?: Identity;
	kernels: Array<Identity & { kernelInstanceId?: string; sessionId?: string }>;
	namespace: string;
}

async function state<T>(root: string, name: string, producer: ChildProcess): Promise<T> {
	const deadline = Date.now() + 45_000;
	while (Date.now() < deadline) {
		const error = await readFile(join(root, "error.json"), "utf8").catch(() => undefined);
		if (error) throw new Error(`parent_fault_fixture_failed: ${error}`);
		const value = await readFile(join(root, `${name}.json`), "utf8").catch(() => undefined);
		if (value) return JSON.parse(value) as T;
		if (producer.exitCode !== null || producer.signalCode !== null)
			throw new Error(`parent_fault_fixture_exited: ${producer.exitCode ?? producer.signalCode}`);
		await delay(50);
	}
	throw new Error(`parent_fault_fixture_timeout: ${name}`);
}

function diagnostic(raw: Buffer): Record<string, unknown> | undefined {
	try {
		const event: unknown = JSON.parse((JSON.parse(raw.toString("utf8")) as { MESSAGE: string }).MESSAGE);
		return event && typeof event === "object" && "schema" in event && event.schema === "prime-agent.diagnostic.v1"
			? (event as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	}
}

for (const mode of [
	"forkserver",
	"worker",
	"worker-shutdown",
	"worker-interrupted-shutdown",
	"worker-socket-loss",
] as const) {
	it.skipIf(!enabled)(
		mode === "worker-shutdown"
			? "records requested worker shutdown without publishing a crash incident"
			: mode === "worker-socket-loss"
				? "publishes real worker socket loss while original worker, forkserver, and kernel state survive"
				: `publishes native evidence of actual ${mode} death while its observer remains alive`,
		async () => {
			if (process.platform !== "linux") throw new Error("Native parent fault acceptance requires Linux");
			const python = process.env.PRIME_AGENT_CAUSAL_PYTHON;
			if (!python) throw new Error("PRIME_AGENT_CAUSAL_PYTHON must select a verified Linux Python");
			for (const path of [
				"/usr/bin/unshare",
				"/usr/bin/systemd-cat",
				"/usr/bin/journalctl",
				"/usr/sbin/ip",
				python,
				loader,
			])
				await access(path);
			const root = await mkdtemp(join(tmpdir(), "parent-"));
			const identifier = `prime-parent-test-${randomUUID()}`;
			const sinceMs = Date.now() - 1000;
			const producer = spawn(
				"/usr/bin/systemd-cat",
				[
					`--identifier=${identifier}`,
					"--level-prefix=false",
					"/usr/bin/unshare",
					"--user",
					"--map-root-user",
					"--mount",
					"--pid",
					"--fork",
					"--kill-child=SIGKILL",
					"--mount-proc",
					"--net",
					process.execPath,
					"--import",
					loader,
					fixture,
					root,
					python,
					mode,
				],
				{
					cwd: root,
					stdio: ["ignore", "pipe", "pipe"],
					env: {
						PATH: `${dirname(process.execPath)}:/usr/sbin:/usr/bin:/bin`,
						HOME: join(root, "home"),
						TMPDIR: root,
						LANG: "C.UTF-8",
						PRIME_AGENT_CODING_AGENT_DIR: join(root, "agent"),
						PRIME_AGENT_SESSION_DIR: join(root, "sessions"),
						PRIME_AGENT_KERNEL_FORKSERVER: "1",
						PRIME_AGENT_DIAGNOSTICS: "native",
					},
				},
			);
			let stderr = "";
			producer.on("error", (error) => {
				stderr = String(error);
			});
			producer.stderr!.on("data", (chunk: Buffer) => {
				stderr = (stderr + chunk.toString("utf8")).slice(-8192);
			});
			producer.stdout!.resume();
			const closed = new Promise<void>((resolve) => producer.once("close", () => resolve()));
			let store: DiagnosticEvidenceStore | undefined;
			let succeeded = false;
			try {
				store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
				const ready = await state<Ready>(root, "ready", producer).catch((error: unknown) => {
					throw new Error(`${String(error)}; startup stderr: ${stderr}`);
				});
				expect(ready.observer.pid).toBe(1);
				expect(ready.namespace).toMatch(/^pid:\[\d+\]$/);
				// The deliberately requested fault is a test control record, never diagnostic input.
				await writeFile(
					join(root, "injection-control.json"),
					JSON.stringify({
						target: ready.parent,
						signal: mode === "worker-shutdown" || mode === "worker-socket-loss" ? null : "SIGKILL",
						command:
							mode === "worker-shutdown" ? "kill" : mode === "worker-socket-loss" ? "close-transport" : null,
						at: Date.now(),
					}),
					{ mode: 0o600 },
				);
				await writeFile(join(root, "command"), "inject", { mode: 0o600 });
				if (mode === "worker-interrupted-shutdown") {
					expect(await state(root, "stopping", producer)).toMatchObject({
						worker: { pid: ready.parent.pid, state: "T" },
						stopPending: true,
					});
					let stopIntent: Buffer | undefined;
					const stopDeadline = Date.now() + 5000;
					while (!stopIntent && Date.now() < stopDeadline) {
						for await (const raw of readNativeJournal({ identifier }, { sinceMs }, AbortSignal.timeout(3000))) {
							const event = diagnostic(raw);
							if (
								event?.type === "worker_lifecycle_intent" &&
								event.operation === "shutdown" &&
								event.workerPid === ready.parent.pid
							)
								stopIntent = raw;
						}
						if (!stopIntent) await delay(50);
					}
					if (!stopIntent)
						throw new Error("Graceful stop intent was not observed before independent signal injection");
					await writeFile(join(root, "stop-intent-journal.json"), stopIntent);
					await writeFile(join(root, "command"), "kill-during-stop", { mode: 0o600 });
				}
				const observed = await state<{
					parentAlive: boolean;
					kernelsAlive: boolean[];
					supervisor?: Identity;
					results?: Array<{ rejected?: string }>;
					stopPendingAtSignal?: boolean;
					workerStateAtSignal?: string;
				}>(root, "observed", producer);
				expect(observed.parentAlive).toBe(mode === "worker-socket-loss");
				const records: Buffer[] = [];
				const deadline = Date.now() + 5000;
				while (Date.now() < deadline) {
					records.length = 0;
					for await (const raw of readNativeJournal({ identifier }, { sinceMs }, AbortSignal.timeout(3000)))
						records.push(raw);
					const events = records.map(diagnostic).filter((event) => event !== undefined);
					if (
						mode === "forkserver"
							? events.filter((event) => event.type === "kernel_unexpected_exit").length === 2
							: mode === "worker-socket-loss"
								? events.some((event) => event.type === "worker_connection_closed")
								: events.some((event) => event.type === "worker_process_exit_observed")
					)
						break;
					await delay(100);
				}
				await writeFile(
					join(root, "observed-journal.jsonl"),
					Buffer.concat(records.flatMap((raw) => [raw, Buffer.from("\n")])),
				);
				const events = records.map(diagnostic).filter((event) => event !== undefined);
				const originalObserver = mode === "forkserver" ? ready.observer : ready.parent;
				expect(events).toContainEqual(
					expect.objectContaining({
						type: "kernel_process_started",
						observerPid: originalObserver.pid,
						observerProcessStartId: originalObserver.startTicks,
						observerPidNamespace: ready.namespace,
						observerBoottimeOffsetNs: "0",
					}),
				);
				const pipeline = new DiagnosticEvidencePipeline(store);
				for (const raw of records) await pipeline.ingestJournal(`journal:${identifier}`, raw);
				for (let page = 0; page < 16; page++) {
					const before = await store.getCursor("internal:incident-detector-v1");
					await pipeline.publishPending();
					if ((await store.getCursor("internal:incident-detector-v1")) === before) break;
					if (page === 15) throw new Error("Fixture capture exceeded the bounded detector drain");
				}
				const incidents = await store.listIncidents();
				await writeFile(
					join(root, "capture-summary.json"),
					JSON.stringify({ ready, observed, events, incidents }, null, 2),
				);
				expect(producer.exitCode).toBeNull();
				if (mode === "forkserver") {
					expect(ready.kernels).toHaveLength(2);
					expect(observed.kernelsAlive).toEqual([false, false]);
					expect(observed.results).toHaveLength(2);
					for (const result of observed.results!) expect(result.rejected).toEqual(expect.any(String));
					expect(
						events.find((event) => event.type === "forkserver_lifecycle" && event.phase === "process_exit"),
					).toMatchObject({
						forkserverPid: ready.parent.pid,
						forkserverProcessStartId: `proc:${ready.parent.startTicks}`,
						ownerPid: ready.observer.pid,
						code: null,
						signal: "SIGKILL",
					});
					for (const kernel of ready.kernels) {
						expect(
							events.find(
								(event) =>
									event.type === "kernel_unexpected_exit" &&
									event.kernelInstanceId === kernel.kernelInstanceId,
							),
						).toMatchObject({
							kernelPid: kernel.pid,
							kernelProcessStartId: `proc:${kernel.startTicks}`,
							code: null,
							signal: null,
							reason: "forkserver_unavailable",
						});
					}
					expect(events.filter((event) => event.type === "kernel_process_started")).toHaveLength(2);
					expect(JSON.stringify(events)).not.toContain("private-parent-sentinel");
				} else if (mode === "worker-socket-loss") {
					expect(observed.supervisor?.startTicks).toBe(ready.supervisor?.startTicks);
					expect(observed.kernelsAlive).toEqual([true]);
					await access(join(root, "sentinel-verified"));
					expect(events.filter((event) => event.type === "kernel_process_started")).toHaveLength(1);
					expect(events.filter((event) => event.type === "worker_process_spawned")).toHaveLength(1);
					expect(events.some((event) => event.type === "worker_process_exit_observed")).toBe(false);
					expect(events.find((event) => event.type === "worker_connection_closed")).toMatchObject({
						status: "unexpected",
						reason: "worker_transport_closed",
						workerPid: ready.parent.pid,
						workerProcessStartId: `proc:${ready.parent.startTicks}`,
						ownerPid: ready.supervisor!.pid,
					});
					expect(incidents).toHaveLength(1);
					expect(incidents[0].coverage.trigger).toMatchObject({ type: "worker_connection_closed" });
				} else {
					expect(observed.supervisor?.startTicks).toBe(ready.supervisor?.startTicks);
					expect(events.filter((event) => event.type === "worker_process_spawned")).toHaveLength(1);
					expect(events.filter((event) => event.type === "kernel_process_started")).toHaveLength(1);
					const exit = events.find((event) => event.type === "worker_process_exit_observed");
					expect(exit, `Missing actual worker exit capture: ${root}`).toMatchObject({
						workerPid: ready.parent.pid,
						workerProcessStartId: `proc:${ready.parent.startTicks}`,
						ownerPid: ready.supervisor!.pid,
						ownerProcessStartId: `proc:${ready.supervisor!.startTicks}`,
						status: mode === "worker-shutdown" ? "expected" : "unexpected",
						reason: "child_exit_observed",
					});
					if (mode === "worker" || mode === "worker-interrupted-shutdown") {
						expect(exit).toMatchObject({ code: null, signal: "SIGKILL" });
						if (mode === "worker") expect(exit?.expectedExitReason).toBeUndefined();
						else {
							expect(observed).toMatchObject({ stopPendingAtSignal: true, workerStateAtSignal: "T" });
							expect(exit?.expectedExitReason).toBe("application_requested_stop");
							expect(
								events.some(
									(event) =>
										event.type === "worker_lifecycle_intent" &&
										event.operation === "shutdown" &&
										Number(event.sequence) < Number(exit?.sequence),
								),
							).toBe(true);
						}
					} else {
						expect(
							events.some(
								(event) =>
									event.type === "worker_lifecycle_intent" &&
									event.operation === "shutdown" &&
									Number(event.sequence) < Number(exit?.sequence),
							),
						).toBe(true);
						expect(incidents).toEqual([]);
						await writeFile(
							join(root, "receipt.json"),
							JSON.stringify(
								{ identifier, ready, observed, incidents, entries: records.length, observerAlive: true },
								null,
								2,
							),
						);
						succeeded = true;
						return;
					}
				}
				expect(incidents.length, `Parent failure produced no live incident: ${root}`).toBeGreaterThan(0);
				for (const incident of incidents) {
					expect(incident.state).toBe("published");
					expect(incident.coverage.cause).toMatchObject({ status: "unresolved" });
				}
				const operations = await DiagnosticArtifactOperations.open({
					store,
					root: join(root, "artifacts"),
					exportArtifact: (operation, signal) => {
						const incident = incidents.find((entry) => entry.id === operation.incidentId)!;
						return exportNativeJournal(
							{ identifier },
							{ sinceMs: incident.windowStartMs, untilMs: Date.now() },
							signal,
						);
					},
				});
				expect((await operations.reconcile()).failures).toEqual([]);
				expect(producer.exitCode).toBeNull();
				await writeFile(
					join(root, "receipt.json"),
					JSON.stringify(
						{ identifier, ready, observed, incidents, entries: records.length, observerAliveAfterExport: true },
						null,
						2,
					),
				);
				succeeded = true;
			} finally {
				await writeFile(join(root, "command"), "stop");
				await Promise.race([closed, delay(7000, undefined, { ref: false })]);
				if (producer.exitCode === null && producer.signalCode === null) producer.kill("SIGTERM");
				await Promise.race([closed, delay(2000, undefined, { ref: false })]);
				if (producer.exitCode === null && producer.signalCode === null) producer.kill("SIGKILL");
				await closed;
				await store?.close();
				if (!succeeded || process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_KEEP_EVIDENCE === "1")
					console.info(`Native parent evidence: ${root}`);
				else await rm(root, { recursive: true, force: true });
			}
		},
		90_000,
	);
}
