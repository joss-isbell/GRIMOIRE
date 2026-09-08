import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { DiagnosticArtifactOperations } from "../src/modes/daemon/diagnostic-evidence-artifacts.js";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";
import type { EvidenceIncident } from "../src/modes/daemon/diagnostic-evidence-store-protocol.js";
import { analyzeStoredIncident } from "../src/modes/daemon/diagnostic-incident-analysis.js";
import { exportNativeJournal, readNativeJournal } from "../src/modes/daemon/diagnostic-native-journal.js";

const enabled = process.env.PRIME_AGENT_NATIVE_PIPELINE_TESTS === "1";
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
type Identity = { pid: number; startTicks: string; pidNamespace: string };
type Capture = {
	producer: Identity;
	owner: Identity;
	platform: { clockTicksPerSecond: number; bootId: string; procReaderBoottimeOffsetNs: string };
	probeSha256: string;
	ownerAliveAtCapture?: boolean;
	probeAliveAtCapture?: boolean;
};

it.skipIf(!enabled)(
	"publishes and exports a trusted native supervisor exit without an application failure event",
	async () => {
		if (process.platform !== "linux") throw new Error("Native pipeline acceptance requires Linux");
		const root = join(
			process.env.PRIME_AGENT_NATIVE_PIPELINE_EVIDENCE ?? tmpdir(),
			`native-pipeline-${randomUUID()}`,
		);
		await mkdir(root, { recursive: false, mode: 0o700 });
		const captureRoot = join(root, "capture");
		const nativeIdentifier = `prime-pipe-native-${randomUUID()}`;
		const applicationIdentifier = `prime-pipe-app-${randomUUID()}`;
		const probe = process.env.PRIME_AGENT_NATIVE_CAUSAL_PROBE ?? join(packageRoot, "scripts/diagnostic-causal.bt");
		const started = Date.now() - 1000;
		const driver = spawn(
			"/usr/bin/python3",
			[
				join(packageRoot, "scripts/test-diagnostic-native-pipeline.py"),
				"--evidence",
				captureRoot,
				"--node",
				process.execPath,
				"--python",
				process.env.PRIME_AGENT_KERNEL_PYTHON ?? join(homedir(), ".prime", "agent", "kernel-venv", "bin", "python"),
				"--probe",
				probe,
				"--native-identifier",
				nativeIdentifier,
				"--application-identifier",
				applicationIdentifier,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		let output = "";
		driver.on("error", (error) => {
			output += String(error);
		});
		for (const stream of [driver.stdout, driver.stderr])
			stream.on("data", (chunk: Buffer) => {
				output = (output + chunk.toString()).slice(-32_768);
			});
		const closed = new Promise<void>((resolveClosed) => driver.once("close", () => resolveClosed()));
		let store: DiagnosticEvidenceStore | undefined;
		const sources = [
			{
				source: "journal:native",
				identifier: nativeIdentifier,
				path: "native.jsonl",
				seen: new Map<string, Buffer>(),
			},
			{
				source: "journal:application",
				identifier: applicationIdentifier,
				path: "application.jsonl",
				seen: new Map<string, Buffer>(),
			},
		];
		const waitState = async (name: string): Promise<Capture> => {
			const deadline = Date.now() + 45_000;
			for (;;) {
				const failure = await readFile(join(captureRoot, "driver-error.json"), "utf8").catch(() => undefined);
				if (failure) throw new Error(failure);
				const state = await readFile(join(captureRoot, `${name}.json`), "utf8").catch(() => undefined);
				if (state) return JSON.parse(state) as Capture;
				if (driver.exitCode !== null || driver.signalCode !== null || Date.now() > deadline)
					throw new Error(`Driver did not reach ${name}: ${output}`);
				await delay(50);
			}
		};
		try {
			const ready = await waitState("ready");
			expect(ready.platform.procReaderBoottimeOffsetNs).toBe("0");
			store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
			const provider = { identifier: nativeIdentifier, clockTicksPerSecond: ready.platform.clockTicksPerSecond };
			const pipeline = new DiagnosticEvidencePipeline(store, provider);
			const publish = async () => {
				let published = 0;
				let previous: string | null | undefined;
				for (let page = 0; page < 16; page++) {
					published += await pipeline.publishPending(512);
					const cursor = await store!.getCursor("internal:incident-detector-v1");
					if (cursor === previous) return published;
					previous = cursor;
				}
				throw new Error("Native capture exceeded the bounded detector scan");
			};
			const ingest = async () => {
				for (const source of sources) {
					const fresh: Buffer[] = [];
					for await (const raw of readNativeJournal(
						{ identifier: source.identifier },
						{ sinceMs: started },
						AbortSignal.timeout(3000),
					)) {
						const entry = JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
						expect(entry.SYSLOG_IDENTIFIER).toBe(source.identifier);
						expect(entry._BOOT_ID).toBe(ready.platform.bootId);
						const cursor = String(entry.__CURSOR);
						if (source.seen.has(cursor)) continue;
						source.seen.set(cursor, raw);
						fresh.push(raw);
					}
					for (let offset = 0; offset < fresh.length; offset += 128)
						await pipeline.ingestJournalBatch(source.source, fresh.slice(offset, offset + 128));
					await writeFile(
						join(root, source.path),
						Buffer.concat([...source.seen.values()].flatMap((raw) => [raw, Buffer.from("\n")])),
					);
				}
			};
			await ingest();
			expect(await publish()).toBe(0);
			expect(await store.listIncidents()).toEqual([]);
			await writeFile(join(captureRoot, "release-fault.json"), JSON.stringify({ release: true }), { mode: 0o600 });
			const captured = await waitState("captured");
			expect(captured.ownerAliveAtCapture).toBe(true);
			expect(captured.probeAliveAtCapture).toBe(true);
			await ingest();
			const messages = (index: number) =>
				[...sources[index]!.seen.values()].map((raw) => {
					const entry = JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
					let message: Record<string, unknown> | undefined;
					try {
						message = JSON.parse(String(entry.MESSAGE));
					} catch {
						/* Retain plain provider bytes too. */
					}
					return { entry, message };
				});
			const native = messages(0);
			for (const { entry } of native) {
				expect(entry._UID).toBe("0");
				expect(entry._EXE).toBe("/usr/bin/bpftrace");
			}
			const application = messages(1)
				.map(({ message }) => message)
				.filter(Boolean);
			expect(
				application.some(
					(event) => event?.type === "supervisor_started" && event.producerPid === ready.producer.pid,
				),
			).toBe(true);
			expect(
				application.some((event) =>
					[
						"kernel_unexpected_exit",
						"fatal_exception",
						"unhandled_rejection",
						"worker_process_exit_observed",
					].includes(String(event?.type)),
				),
			).toBe(false);
			const targetExit = native.find(
				({ message }) =>
					message?.event === "process_exit" &&
					message.subject_pid === ready.producer.pid &&
					message.group_dead === 1,
			);
			expect(targetExit?.message?.raw_exit_code).toBe(9);
			expect(await publish()).toBeGreaterThan(0);
			let selected: EvidenceIncident | undefined;
			for (const incident of await store.listIncidents()) {
				const trigger = incident.coverage.trigger as { source: string; occurrenceId: string };
				const occurrence = await store.getOccurrence(trigger.source, trigger.occurrenceId);
				if (
					occurrence &&
					JSON.parse(Buffer.from(occurrence.payload).toString()).__CURSOR === targetExit!.entry.__CURSOR
				)
					selected = incident;
			}
			expect(selected?.state).toBe("published");
			if (!selected) throw new Error("Target native exit incident was not published");
			const analysis = await analyzeStoredIncident(store, selected, {
				identifier: nativeIdentifier,
				clockTicksPerSecond: ready.platform.clockTicksPerSecond,
			});
			await writeFile(join(root, "analysis.json"), JSON.stringify(analysis, null, 2));
			expect(analysis.classification.status).toBe("process_exited");
			expect(analysis.classification.cause).toBe("user_signal");
			expect(analysis.classification.initiator?.syscallKind).toBe(4);
			expect(analysis.truncated).toBe(false);
			expect(analysis.classification.coverageComplete).toBe(false);
			const artifacts = await DiagnosticArtifactOperations.open({
				root: join(root, "artifacts"),
				store,
				exportArtifact: async function* (_operation, signal) {
					for (const source of sources)
						yield* exportNativeJournal(
							{ identifier: source.identifier },
							{ sinceMs: selected!.windowStartMs, untilMs: Date.now() + 1000 },
							signal,
						);
				},
			});
			expect((await artifacts.reconcile()).completed).toBeGreaterThan(0);
			const [artifact] = await store.listArtifacts(selected.id);
			expect(artifact?.sha256).toMatch(/^[a-f0-9]{64}$/);
			expect(artifact?.bytes).toBeGreaterThan(0);
			const exported = await readFile(join(root, "artifacts", artifact!.path));
			expect(exported.toString()).toContain(`__CURSOR=${targetExit!.entry.__CURSOR}\n`);
			expect(exported.toString()).toContain(`MESSAGE=${String(targetExit!.entry.MESSAGE)}\n`);
			expect(exported.toString()).toContain(`SYSLOG_IDENTIFIER=${applicationIdentifier}\n`);
			await store.close();
			store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
			const persisted = await store.getIncident(selected.id);
			expect(persisted?.state).toBe("published");
			let afterSequence: number | undefined;
			let verifiedBytes = 0;
			for (;;) {
				const stored = await store.readOccurrences({ afterSequence, limit: 512 });
				for (const occurrence of stored.occurrences.filter((row) => row.kind === "journal.json")) {
					const cursor = JSON.parse(Buffer.from(occurrence.payload).toString()).__CURSOR as string;
					const original = sources.find((source) => source.source === occurrence.source)?.seen.get(cursor);
					expect(Buffer.from(occurrence.payload).equals(original!)).toBe(true);
					verifiedBytes++;
				}
				if (stored.nextSequence === undefined) break;
				afterSequence = stored.nextSequence;
			}
			expect(verifiedBytes).toBe(sources.reduce((count, source) => count + source.seen.size, 0));
			expect(driver.exitCode).toBeNull();
			await writeFile(join(captureRoot, "stop.json"), JSON.stringify({ stop: true }), { mode: 0o600 });
			await closed;
			expect(driver.exitCode, output).toBe(0);
			const alive = JSON.parse(await readFile(join(captureRoot, "publication-observer-alive.json"), "utf8"));
			expect(alive.owner).toMatchObject(ready.owner);
			expect(alive.probeAlive).toBe(true);
			await writeFile(
				join(root, "result.json"),
				JSON.stringify(
					{
						incidentId: selected.id,
						analysis,
						nativeRows: sources[0]!.seen.size,
						applicationRows: sources[1]!.seen.size,
						artifactId: artifact!.id,
						exportedBytes: exported.byteLength,
						ownerAliveThroughExport: true,
						probeSha256: captured.probeSha256,
					},
					null,
					2,
				),
			);
			console.info(`Native pipeline evidence: ${root}`);
		} finally {
			await writeFile(join(root, "driver.log"), output);
			await writeFile(join(captureRoot, "abort.json"), JSON.stringify({ abort: true }), { mode: 0o600 }).catch(
				() => {},
			);
			await writeFile(join(captureRoot, "stop.json"), JSON.stringify({ stop: true }), { mode: 0o600 }).catch(
				() => {},
			);
			await Promise.race([closed, delay(2000)]);
			await store?.close();
		}
	},
	85_000,
);
