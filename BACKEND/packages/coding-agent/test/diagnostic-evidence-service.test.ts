import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it, vi } from "vitest";
import { captureCausalPlatform } from "../src/modes/daemon/diagnostic-causal-platform.js";
import { DiagnosticArtifactOperations } from "../src/modes/daemon/diagnostic-evidence-artifacts.js";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import {
	type DiagnosticEvidenceServiceConfig,
	type DiagnosticEvidenceServiceStatus,
	measureDiagnosticCapacity,
	runDiagnosticEvidenceService,
	selectNativeAtopSources,
} from "../src/modes/daemon/diagnostic-evidence-service.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";

const roots: string[] = [];
afterEach(async () => {
	for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});
async function setup() {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-service-"));
	roots.push(root);
	const executable = join(root, "journalctl");
	await copyFile(fileURLToPath(new URL("./fixtures/diagnostic-journal-provider.py", import.meta.url)), executable);
	await chmod(executable, 0o700);
	await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [] }));
	const config: DiagnosticEvidenceServiceConfig = {
		stateRoot: join(root, "state"),
		journal: { identifier: `service-${randomUUID()}`, journalctlPath: executable },
		nativeHistoryDirectories: [],
	};
	return { root, config };
}
function entry(cursor: string, time = Date.now(), trigger = true) {
	return JSON.stringify({
		__CURSOR: cursor,
		__REALTIME_TIMESTAMP: String(time * 1000),
		MESSAGE: JSON.stringify({
			schema: "prime-agent.diagnostic.v1",
			type: trigger ? "fatal_exception" : "sample",
		}),
	});
}
async function until(condition: () => boolean | Promise<boolean>, timeout = 8000) {
	const end = Date.now() + timeout;
	while (!(await condition())) {
		if (Date.now() > end) throw new Error("condition_timeout");
		await delay(50);
	}
}
function query(root: string, sql: string): Record<string, unknown>[] {
	const db = new DatabaseSync(join(root, "evidence.sqlite"), { readOnly: true });
	try {
		return db.prepare(sql).all();
	} finally {
		db.close();
	}
}

it("accounts for pending staging and rejects unknown native history without recursive traversal", async () => {
	const { root, config } = await setup();
	await mkdir(config.stateRoot, { mode: 0o700 });
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	try {
		const history = join(root, "native");
		await mkdir(history);
		await writeFile(join(history, "native.raw"), Buffer.alloc(8192));
		const stats = { ...(await store.stats()), artifactAllocatedBytes: 4096, reservedArtifactBytes: 8192 };
		const capacity = await measureDiagnosticCapacity({ ...config, nativeHistoryDirectories: [history] }, stats);
		expect(capacity.nativeBytes).toBeGreaterThanOrEqual(8192);
		expect(capacity.reservedArtifactBytes).toBe(8192);
		expect(capacity.usedBytes).toBeGreaterThan(capacity.reservedArtifactBytes + 8192);
		await mkdir(join(history, "unexpected-directory"));
		await expect(
			measureDiagnosticCapacity({ ...config, nativeHistoryDirectories: [history] }, stats),
		).rejects.toThrow(/native_history_unknown/);
	} finally {
		await store.close();
	}
});

it("refuses inadequate admission before creating the database", async () => {
	const { config } = await setup();
	await expect(
		runDiagnosticEvidenceService({ ...config, totalBudgetBytes: 1 }, { signal: AbortSignal.timeout(3000) }),
	).rejects.toThrow(/diagnostic_capacity/);
	await expect(readFile(join(config.stateRoot, "evidence.sqlite"))).rejects.toThrow(/ENOENT/);
});

it.skipIf(process.platform !== "linux")(
	"records the current causal platform before readiness and rejects a mismatched tick configuration",
	async () => {
		const captured = await captureCausalPlatform();
		const { config } = await setup();
		config.journal = { namespace: "isolated-platform-test", journalctlPath: config.journal.journalctlPath };
		config.causalTrace = {
			identifier: "test-native-provider",
			clockTicksPerSecond: captured.platform.clockTicksPerSecond,
		};
		const stop = new AbortController();
		let ready = false;
		const run = runDiagnosticEvidenceService(config, {
			signal: stop.signal,
			onReady: () => {
				ready = true;
			},
		});
		try {
			await until(() => ready);
			const receipt = query(
				config.stateRoot,
				"SELECT cursor FROM sources WHERE source LIKE 'internal:causal-platform-v1:%'",
			);
			expect(JSON.parse(String(receipt[0]?.cursor)).platform).toEqual(captured.platform);
			const runtimeBoot = query(
				config.stateRoot,
				"SELECT cursor FROM sources WHERE source='internal:runtime-current-boot-v1'",
			);
			expect(JSON.parse(String(runtimeBoot[0]?.cursor))).toMatchObject({ bootId: captured.platform.bootId });
		} finally {
			stop.abort();
			await run;
		}
		const other = await setup();
		other.config.journal = {
			namespace: "isolated-platform-test",
			journalctlPath: other.config.journal.journalctlPath,
		};
		other.config.causalTrace = {
			...config.causalTrace,
			clockTicksPerSecond: captured.platform.clockTicksPerSecond + 1,
		};
		await expect(
			runDiagnosticEvidenceService(other.config, {
				signal: AbortSignal.timeout(3000),
				onReady: () => {
					throw new Error("incorrect readiness");
				},
			}),
		).rejects.toThrow("causal_clock_configuration_mismatch");
	},
);

it("refreshes an ended incident when late journal evidence arrives inside its window", async () => {
	const { root, config } = await setup();
	let now = Date.now();
	const triggerTime = now - 20 * 60_000;
	const kernel = {
		schema: "prime-agent.diagnostic.v1",
		producerId: "late-producer",
		producerPid: 2,
		producerStartId: "100",
		observerPid: 2,
		observerProcessStartId: "100",
		observerPidNamespace: "pid:[500]",
		observerBoottimeOffsetNs: "0",
		kernelInstanceId: "late-kernel",
		kernelGeneration: 1,
		kernelPid: 3,
		kernelProcessStartId: "proc:101",
	};
	const observed = (cursor: string, type: string, time: number) =>
		JSON.stringify({
			__CURSOR: cursor,
			__REALTIME_TIMESTAMP: String(time * 1000),
			_BOOT_ID: "late-boot",
			MESSAGE: JSON.stringify({
				...kernel,
				type,
				monotonicNs: type === "kernel_unexpected_exit" ? "3000" : "2000",
				code: 23,
				signal: null,
				lifecycleState: "running",
			}),
		});
	const first = observed("before-catchup", "kernel_unexpected_exit", triggerTime);
	await mkdir(config.stateRoot, { mode: 0o700 });
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	const pipeline = new DiagnosticEvidencePipeline(store);
	await pipeline.ingestJournal("journal:service", Buffer.from(first));
	await pipeline.publishPending();
	await store.close();
	await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [first] }));
	const controller = new AbortController();
	const run = runDiagnosticEvidenceService(config, { signal: controller.signal, now: () => now });
	const coverage = () =>
		JSON.parse(String(query(config.stateRoot, "SELECT coverage FROM incidents LIMIT 1")[0]?.coverage ?? "{}"));
	try {
		await until(() => coverage().causalAnalysis?.windowEnded === true);
		expect(coverage().cause.status).toBe("unresolved");
		const before = coverage().causalAnalysis.analysisOccurrenceId;
		await writeFile(
			join(root, "provider.json"),
			JSON.stringify({ entries: [first, observed("late-exit", "kernel_process_exit_observed", triggerTime + 1)] }),
		);
		now += 11_000;
		await until(() => coverage().cause?.status === "process_exited");
		expect(coverage().causalAnalysis.analysisOccurrenceId).not.toBe(before);
		expect(coverage().causalAnalysis.sourceCursor).toBe("late-exit");
		expect(coverage().causalAnalysis.windowEnded).toBe(true);
		const stable = coverage().causalAnalysis;
		const reports = query(config.stateRoot, "SELECT id FROM occurrences WHERE kind='incident.analysis'").length;
		await writeFile(
			join(root, "provider.json"),
			JSON.stringify({
				entries: [
					first,
					observed("late-exit", "kernel_process_exit_observed", triggerTime + 1),
					entry("outside-window", now, false),
				],
			}),
		);
		now += 11_000;
		await until(
			() =>
				query(config.stateRoot, "SELECT cursor FROM sources WHERE source='journal:service'")[0]?.cursor ===
				"outside-window",
		);
		await delay(1200);
		expect(coverage().causalAnalysis).toEqual(stable);
		expect(query(config.stateRoot, "SELECT id FROM occurrences WHERE kind='incident.analysis'")).toHaveLength(
			reports,
		);
	} finally {
		controller.abort();
		await run;
	}
});

it("does not announce readiness after startup cancellation", async () => {
	const { config } = await setup();
	const controller = new AbortController();
	let ready = false;
	await runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onStatus: () => controller.abort(new Error("startup deadline")),
		onReady: () => {
			ready = true;
		},
	});
	expect(ready).toBe(false);
});

it("exits unsuccessfully when the CLI startup deadline expires", async () => {
	const { root, config } = await setup();
	const path = join(root, "config.json");
	await writeFile(path, JSON.stringify(config));
	const cli = fileURLToPath(new URL("../src/diagnostic-evidence-service.ts", import.meta.url));
	const deadline = fileURLToPath(new URL("./fixtures/diagnostic-startup-deadline.mjs", import.meta.url));
	const child = spawn(process.execPath, ["--import", "tsx", "--import", deadline, cli, "--config", path], {
		stdio: ["ignore", "pipe", "pipe"],
	});
	let output = "";
	for (const stream of [child.stdout, child.stderr])
		stream.on("data", (chunk: Buffer) => {
			output = (output + chunk.toString()).slice(-16_384);
		});
	const closed = new Promise<void>((resolve) => child.once("close", () => resolve()));
	const cleanup = setTimeout(() => child.kill("SIGKILL"), 10_000);
	try {
		await closed;
		expect(output).toContain("diagnostic_service_startup_timeout");
		expect(output).not.toContain('"type":"ready"');
		expect(child.exitCode).toBe(1);
		expect(child.signalCode).toBeNull();
	} finally {
		clearTimeout(cleanup);
	}
});

it("recovers already staged evidence under capacity pressure while new intake stays paused", async () => {
	const { config } = await setup();
	await mkdir(config.stateRoot, { mode: 0o700 });
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	await new DiagnosticEvidencePipeline(store).ingestJournal("journal:service", Buffer.from(entry("funded")));
	await new DiagnosticEvidencePipeline(store).publishPending();
	const interrupted = vi.spyOn(store, "markOperationReady").mockRejectedValue(new Error("recorder interrupted"));
	try {
		const artifacts = await DiagnosticArtifactOperations.open({
			store,
			root: join(config.stateRoot, "artifacts"),
			exportArtifact: async function* () {
				yield Buffer.from("captured before pressure");
			},
		});
		expect((await artifacts.reconcile()).failures[0]?.error).toMatch(/recorder interrupted/);
	} finally {
		interrupted.mockRestore();
		await store.close();
	}
	config.totalBudgetBytes = 1;
	const controller = new AbortController();
	let ready: DiagnosticEvidenceServiceStatus | undefined;
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onReady: (status) => {
			ready = status;
		},
	});
	try {
		await until(() => ready !== undefined);
		expect(ready!.capacity?.admitted).toBe(false);
		await until(() => query(config.stateRoot, "SELECT * FROM operations WHERE state='ready'").length === 1);
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE state='ready'")).toHaveLength(1);
		const [artifact] = query(config.stateRoot, "SELECT * FROM artifacts");
		expect(await readFile(join(config.stateRoot, "artifacts", String(artifact.path)), "utf8")).toBe(
			"captured before pressure",
		);
		expect(query(config.stateRoot, "SELECT * FROM occurrences WHERE kind='journal.json'")).toHaveLength(1);
	} finally {
		controller.abort();
		await run;
	}
});

it("exports a queued trigger storm and continues on restart without speculative capacity lockout", async () => {
	const { root, config } = await setup();
	await writeFile(
		join(root, "provider.json"),
		JSON.stringify({
			entries: Array.from({ length: 33 }, (_, index) => entry(`trigger-${index}`)),
		}),
	);
	let controller = new AbortController();
	let run = runDiagnosticEvidenceService(config, { signal: controller.signal });
	let completed = 0;
	try {
		await until(() => {
			try {
				return query(config.stateRoot, "SELECT * FROM incidents").length === 33;
			} catch {
				return false;
			}
		});
		await until(() => query(config.stateRoot, "SELECT * FROM operations WHERE state='ready'").length >= 2);
		completed = query(config.stateRoot, "SELECT * FROM operations WHERE state='ready'").length;
		expect(
			Number(query(config.stateRoot, "SELECT reserved_artifact_bytes FROM counts")[0].reserved_artifact_bytes),
		).toBeLessThanOrEqual(256 * 1024 * 1024);
	} finally {
		controller.abort();
		await run;
	}
	controller = new AbortController();
	let ready = false;
	run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onReady: () => {
			ready = true;
		},
	});
	try {
		await until(
			() => ready && query(config.stateRoot, "SELECT * FROM operations WHERE state='ready'").length > completed,
		);
		expect(query(config.stateRoot, "SELECT * FROM incidents")).toHaveLength(33);
	} finally {
		controller.abort();
		await run;
	}
}, 20_000);

it("publishes old durable triggers on an empty restart and finishes the canonical window without a new entry", async () => {
	const { config } = await setup();
	await mkdir(config.stateRoot, { mode: 0o700 });
	let store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	const pipeline = new DiagnosticEvidencePipeline(store);
	const trigger = Date.now();
	await pipeline.ingestJournal("journal:service", Buffer.from(entry("old", trigger)));
	await store.close();
	const controller = new AbortController();
	let now = trigger;
	let ready = false;
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		now: () => now,
		onReady: () => {
			ready = true;
		},
	});
	try {
		await until(
			() => ready && query(config.stateRoot, "SELECT * FROM incidents WHERE state = 'published'").length === 1,
		);
		await until(() => query(config.stateRoot, "SELECT * FROM operations WHERE state = 'ready'").length === 1);
		now = trigger + 15 * 60_000 + 1;
		await until(() => query(config.stateRoot, "SELECT * FROM operations WHERE state = 'ready'").length === 2);
		await until(() => query(config.stateRoot, "SELECT * FROM incidents WHERE state = 'limited'").length === 1);
		const [incident] = query(config.stateRoot, "SELECT * FROM incidents");
		expect(incident.state).toBe("limited");
	} finally {
		controller.abort();
		await run;
	}
	store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	try {
		expect((await store.listIncidents())[0]).toMatchObject({
			windowStartMs: trigger - 30 * 60_000,
			windowEndMs: trigger + 15 * 60_000,
		});
	} finally {
		await store.close();
	}
});

it("records unavailable provider as a durable gap and replays available history without trusting a failed cursor", async () => {
	const { root, config } = await setup();
	await mkdir(config.stateRoot, { mode: 0o700 });
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	await new DiagnosticEvidencePipeline(store).ingestJournal("journal:service", Buffer.from(entry("gone")));
	await store.close();
	await writeFile(join(root, "provider.json"), JSON.stringify({ unavailable: true, entries: [] }));
	const controller = new AbortController();
	const statuses: DiagnosticEvidenceServiceStatus[] = [];
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onStatus: (status) => statuses.push(status),
	});
	try {
		await until(() => statuses.some((status) => status.provider === "unavailable"));
		await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [entry("surviving")] }));
		await until(() => query(config.stateRoot, "SELECT * FROM occurrences WHERE kind = 'journal.json'").length === 2);
		expect(
			query(config.stateRoot, "SELECT * FROM occurrences WHERE kind = 'diagnostic.gap'").length,
		).toBeGreaterThanOrEqual(1);
	} finally {
		controller.abort();
		await run;
	}
});

it("bounds the read stream, publishes during a storm, and stops its own provider promptly", async () => {
	const { root, config } = await setup();
	await writeFile(
		join(root, "provider.json"),
		JSON.stringify({
			entries: Array.from({ length: 700 }, (_, index) => entry(`c${index}`, Date.now(), index === 0)),
		}),
	);
	const controller = new AbortController();
	let ready = false;
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onReady: () => {
			ready = true;
		},
	});
	try {
		await until(() => ready);
		await until(() => query(config.stateRoot, "SELECT * FROM incidents").length === 1);
		await until(
			() => query(config.stateRoot, "SELECT * FROM occurrences WHERE kind = 'journal.json'").length === 700,
		);
	} finally {
		const start = Date.now();
		controller.abort();
		await run;
		expect(Date.now() - start).toBeLessThan(15_000);
	}
});

it("records exact cursor loss separately from provider unavailability", async () => {
	const { config } = await setup();
	await mkdir(config.stateRoot, { mode: 0o700 });
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	await new DiagnosticEvidencePipeline(store).ingestJournal("journal:service", Buffer.from(entry("missing")));
	await store.close();
	const controller = new AbortController();
	let lost = false;
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onStatus: (status) => {
			if (status.provider === "cursor_lost") lost = true;
		},
	});
	try {
		await until(() => lost);
	} finally {
		controller.abort();
		await run;
	}
	expect(query(config.stateRoot, "SELECT * FROM occurrences WHERE kind = 'diagnostic.gap'")).toHaveLength(1);
});

it("allows later exports to complete when the first pending provider is unavailable", async () => {
	const { config } = await setup();
	await mkdir(config.stateRoot, { mode: 0o700 });
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	const now = Date.now();
	for (const id of ["first", "later"]) {
		await store.openIncident({
			id,
			triggerTimeMs: now,
			windowStartMs: now - 30 * 60_000,
			windowEndMs: now + 15 * 60_000,
			coverage: {},
			limitations: ["A prior provider gap remains unresolved."],
		});
		await store.prepareOperation({
			id: id === "first" ? "a" : "z",
			incidentId: id,
			kind: "export",
			artifact: { id, path: `${id}.journal`, format: id === "first" ? "unavailable.provider" : "journal.export" },
		});
	}
	await store.close();
	const controller = new AbortController();
	let ready = false;
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onReady: () => {
			ready = true;
		},
	});
	try {
		await until(
			() =>
				ready &&
				query(config.stateRoot, "SELECT * FROM operations WHERE id = 'z' AND state = 'ready'").length === 1,
		);
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE id = 'a' AND state = 'pending'")).toHaveLength(1);
	} finally {
		controller.abort();
		await run;
	}
	const reopened = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	try {
		expect((await reopened.getIncident("later"))!.limitations).toContain("A prior provider gap remains unresolved.");
	} finally {
		await reopened.close();
	}
});

it("exposes a capacity deficit after a trigger without shortening its window or writing exports", async () => {
	const { root, config } = await setup();
	config.totalBudgetBytes = 12 * 1024 * 1024;
	const native = join(root, "native");
	await mkdir(native);
	config.nativeHistoryDirectories = [native];
	await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [entry("capacity-trigger")] }));
	const controller = new AbortController();
	let deficit: DiagnosticEvidenceServiceStatus | undefined;
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onStatus: (status) => {
			if (status.capacity?.admitted === false) deficit = status;
		},
	});
	try {
		await until(() => {
			try {
				return query(config.stateRoot, "SELECT * FROM incidents").length === 1;
			} catch {
				return false;
			}
		});
		await writeFile(join(native, "pressure.raw"), Buffer.alloc(8 * 1024 * 1024));
		await until(() => deficit !== undefined);
		expect(deficit!.lastError).toMatch(/capacity/);
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE state = 'ready'")).toHaveLength(0);
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE state = 'pending'")).toHaveLength(1);
	} finally {
		controller.abort();
		await run;
	}
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	try {
		const [incident] = await store.listIncidents();
		expect(incident.windowEndMs - incident.windowStartMs).toBe(45 * 60_000);
		expect(incident.expiresAtMs - incident.triggerTimeMs).toBe(14 * 86_400_000);
	} finally {
		await store.close();
	}
});

it("restarts the CLI after a real recorder crash during export using only pending SQL operations", async () => {
	const { root, config } = await setup();
	config.stateRoot = join(root, "new-parent", "new-child", "state");
	await writeFile(
		join(root, "provider.json"),
		JSON.stringify({ entries: [entry("crash-trigger")], exportPause: true }),
	);
	const path = join(root, "config.json");
	await writeFile(path, JSON.stringify(config));
	const cli = fileURLToPath(new URL("../src/diagnostic-evidence-service.ts", import.meta.url));
	const launch = () => {
		const child = spawn(process.execPath, ["--import", "tsx", cli, "--config", path], {
			detached: true,
			stdio: ["ignore", "pipe", "pipe"],
		});
		let output = "";
		child.stdout.on("data", (chunk: Buffer) => {
			if (output.length < 16384) output += chunk.toString();
		});
		child.stderr.on("data", (chunk: Buffer) => {
			if (output.length < 16384) output += chunk.toString();
		});
		const closed = new Promise<void>((resolve) => child.once("close", () => resolve()));
		return { child, closed, output: () => output };
	};
	const first = launch();
	try {
		await until(() => first.output().includes('"type":"ready"'));
		await until(async () => {
			try {
				await readFile(join(root, "export-started"));
				return true;
			} catch {
				return false;
			}
		});
		// Only this fixture's newly created process group, including its journal readers.
		process.kill(-first.child.pid!, "SIGKILL");
		await first.closed;
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE state = 'pending'")).toHaveLength(1);
		await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [] }));
		const second = launch();
		try {
			await until(() => second.output().includes('"type":"ready"'));
			await until(() => query(config.stateRoot, "SELECT * FROM operations WHERE state = 'ready'").length === 1);
			expect(query(config.stateRoot, "SELECT * FROM incidents")).toHaveLength(1);
			const start = Date.now();
			second.child.kill("SIGTERM");
			await second.closed;
			expect(second.child.exitCode).toBe(0);
			expect(Date.now() - start).toBeLessThan(15_000);
		} finally {
			if (second.child.exitCode === null && second.child.signalCode === null)
				process.kill(-second.child.pid!, "SIGKILL");
			await second.closed;
		}
	} finally {
		if (first.child.exitCode === null && first.child.signalCode === null) process.kill(-first.child.pid!, "SIGKILL");
		await first.closed;
	}
}, 20_000);

it("keeps readiness and incoming incident publication live while an artifact provider is blocked", async () => {
	const { root, config } = await setup();
	await mkdir(config.stateRoot, { mode: 0o700 });
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	await new DiagnosticEvidencePipeline(store).ingestJournal("journal:service", Buffer.from(entry("old-blocked")));
	await store.close();
	await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [entry("new-live")], exportPause: true }));
	const controller = new AbortController();
	let readyAt: number | undefined;
	const started = Date.now();
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		onReady: () => {
			readyAt = Date.now();
		},
	});
	try {
		await until(() => readyAt !== undefined);
		expect(readyAt! - started).toBeLessThan(750);
		await until(() => query(config.stateRoot, "SELECT * FROM incidents").length === 2);
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE state = 'ready'")).toHaveLength(0);
	} finally {
		controller.abort();
		await run;
	}
});

it("selects separate atop daily files across the producer timezone midnight", async () => {
	const { root } = await setup();
	for (const day of ["20260907", "20260908", "20260909"]) await writeFile(join(root, `atop_${day}`), day);
	const selected = await selectNativeAtopSources(
		{ directory: root, timeZone: "America/Vancouver" },
		{
			sinceMs: Date.parse("2026-09-08T06:55:00Z"),
			untilMs: Date.parse("2026-09-08T07:10:00Z"),
		},
	);
	expect(selected.sources.map((source) => source.day)).toEqual(["20260907", "20260908"]);
	expect(selected.missingDays).toEqual([]);
	await expect(
		selectNativeAtopSources(
			{ directory: root, timeZone: "invalid-zone" },
			{ sinceMs: Date.now(), untilMs: Date.now() },
		),
	).rejects.toThrow();
});

it("keeps intake live through a blocked atop export and durably exposes partial sample receipts", async () => {
	const { root, config } = await setup();
	const directory = join(root, "atop-history");
	await mkdir(directory);
	const binary = join(root, "atop");
	await copyFile(fileURLToPath(new URL("./fixtures/diagnostic-atop-provider.py", import.meta.url)), binary);
	await chmod(binary, 0o700);
	config.atop = { directory, timeZone: "UTC", atopPath: binary };
	config.nativeHistoryDirectories = [directory];
	const trigger = Date.now();
	let now = trigger;
	const day = new Date(trigger).toISOString().slice(0, 10).replaceAll("-", "");
	const source = join(directory, `atop_${day}`);
	const pidFile = join(root, "atop.pid");
	const release = join(root, "release");
	await writeFile(
		source,
		JSON.stringify({ timestamp: Math.floor(trigger / 1000), holdFile: release, pidFile, truncated: true }),
	);
	await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [entry("atop-first", trigger)] }));
	const controller = new AbortController();
	let ready = false;
	const run = runDiagnosticEvidenceService(config, {
		signal: controller.signal,
		now: () => now,
		onReady: () => {
			ready = true;
		},
	});
	try {
		await until(() => ready);
		await until(async () => {
			try {
				await readFile(pidFile);
				return true;
			} catch {
				return false;
			}
		});
		const owned = JSON.parse(await readFile(pidFile, "utf8")) as { pid: number };
		process.kill(owned.pid, 0);
		const started = Date.now();
		await writeFile(
			join(root, "provider.next"),
			JSON.stringify({ entries: [entry("atop-first", trigger), entry("during-atop", trigger + 1)] }),
		);
		await rename(join(root, "provider.next"), join(root, "provider.json"));
		await until(() => query(config.stateRoot, "SELECT * FROM incidents").length === 2);
		expect(Date.now() - started).toBeLessThan(2000);
		process.kill(owned.pid, 0);
		await writeFile(release, "ready");
		now = trigger + 15 * 60_000 + 10;
		await until(
			() => query(config.stateRoot, "SELECT * FROM artifacts WHERE format='atop.native'").length >= 2,
			15_000,
		);
		await until(() => query(config.stateRoot, "SELECT * FROM incidents WHERE state='limited'").length === 2, 15_000);
		const snapshot = new DatabaseSync(join(config.stateRoot, "evidence.sqlite"), { readOnly: true });
		try {
			const row = snapshot.prepare("SELECT coverage FROM incidents LIMIT 1").get()!;
			const coverage = JSON.parse(String(row.coverage));
			expect(coverage.exportComplete).toBe(false);
			expect(coverage.providers.atop.status).toBe("partial");
			expect(coverage.providers.atop.receiptIds.length).toBeGreaterThan(0);
		} finally {
			snapshot.close();
		}
		expect(query(config.stateRoot, "SELECT * FROM occurrences WHERE kind='artifact.receipt'").length).toBeGreaterThan(
			0,
		);
	} finally {
		controller.abort();
		await run;
	}
	expect(JSON.parse(await readFile(source, "utf8")).truncated).toBe(true);
}, 30_000);

it("cancels an owned atop process group promptly and releases incomplete staging reservations", async () => {
	const { root, config } = await setup();
	const directory = join(root, "atop-history");
	await mkdir(directory);
	const binary = join(root, "atop");
	await copyFile(fileURLToPath(new URL("./fixtures/diagnostic-atop-provider.py", import.meta.url)), binary);
	await chmod(binary, 0o700);
	config.atop = { directory, timeZone: "UTC", atopPath: binary };
	config.nativeHistoryDirectories = [directory];
	const trigger = Date.now();
	const day = new Date(trigger).toISOString().slice(0, 10).replaceAll("-", "");
	const pidFile = join(root, "atop.pid");
	await writeFile(
		join(directory, `atop_${day}`),
		JSON.stringify({
			timestamp: Math.floor(trigger / 1000),
			holdFile: join(root, "never-release"),
			pidFile,
			ignoreTerm: true,
		}),
	);
	await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [entry("cancel-atop", trigger)] }));
	const controller = new AbortController();
	const run = runDiagnosticEvidenceService(config, { signal: controller.signal });
	try {
		await until(async () => {
			try {
				await readFile(pidFile);
				return true;
			} catch {
				return false;
			}
		});
		const { pid } = JSON.parse(await readFile(pidFile, "utf8")) as { pid: number };
		const start = Date.now();
		controller.abort();
		await run;
		expect(Date.now() - start).toBeLessThan(3000);
		const remaining = await readFile(`/proc/${pid}/stat`, "utf8").catch((error: NodeJS.ErrnoException) => {
			if (error.code !== "ENOENT") throw error;
			return undefined;
		});
		if (remaining) {
			// A PID-namespace test runner may retain an adopted zombie until the
			// namespace closes. It must already have exited from the forced signal.
			const fields = remaining.slice(remaining.lastIndexOf(")") + 2).split(" ");
			expect(fields[0]).toBe("Z");
			expect(Number(fields[49]) & 0x7f).toBe(9);
		}
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE reservation_bytes > 0")).toHaveLength(0);
	} finally {
		controller.abort();
		await run;
	}
});

it("restarts after a recorder crash with partial atop bytes and a durable reservation", async () => {
	const { root, config } = await setup();
	const directory = join(root, "atop-history");
	await mkdir(directory);
	const binary = join(root, "atop");
	await copyFile(fileURLToPath(new URL("./fixtures/diagnostic-atop-provider.py", import.meta.url)), binary);
	await chmod(binary, 0o700);
	config.atop = { directory, timeZone: "UTC", atopPath: binary };
	config.nativeHistoryDirectories = [directory];
	const trigger = Date.now();
	const day = new Date(trigger).toISOString().slice(0, 10).replaceAll("-", "");
	const pidFile = join(root, "atop.pid");
	const release = join(root, "release");
	await writeFile(
		join(directory, `atop_${day}`),
		JSON.stringify({ timestamp: Math.floor(trigger / 1000), holdFile: release, pidFile }),
	);
	await writeFile(join(root, "provider.json"), JSON.stringify({ entries: [entry("crash-atop", trigger)] }));
	const path = join(root, "config.json");
	await writeFile(path, JSON.stringify(config));
	const cli = fileURLToPath(new URL("../src/diagnostic-evidence-service.ts", import.meta.url));
	const child = spawn(process.execPath, ["--import", "tsx", cli, "--config", path], {
		detached: true,
		stdio: "ignore",
	});
	const closed = new Promise<void>((resolve) => child.once("close", () => resolve()));
	let group: number | undefined;
	try {
		await until(async () => {
			try {
				await readFile(pidFile);
				return true;
			} catch {
				return false;
			}
		});
		group = (JSON.parse(await readFile(pidFile, "utf8")) as { group: number }).group;
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE reservation_bytes > 0").length).toBeGreaterThan(0);
		// A service-cgroup crash removes only this recorder and its explicitly owned helper group.
		process.kill(-child.pid!, "SIGKILL");
		process.kill(-group!, "SIGKILL");
		await closed;
		group = undefined;
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE reservation_bytes > 0").length).toBeGreaterThan(0);
		await writeFile(release, "ready");
		const controller = new AbortController();
		const run = runDiagnosticEvidenceService(config, { signal: controller.signal });
		try {
			await until(() => query(config.stateRoot, "SELECT * FROM artifacts WHERE format='atop.native'").length === 1);
			expect(query(config.stateRoot, "SELECT * FROM occurrences WHERE kind='artifact.receipt'")).toHaveLength(1);
		} finally {
			controller.abort();
			await run;
		}
		expect(query(config.stateRoot, "SELECT * FROM operations WHERE reservation_bytes > 0")).toHaveLength(0);
	} finally {
		if (group) {
			try {
				process.kill(-group, "SIGKILL");
			} catch {}
		}
		if (child.exitCode === null && child.signalCode === null) process.kill(-child.pid!, "SIGKILL");
		await closed;
	}
}, 15_000);

it.skipIf(process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_TESTS !== "1")(
	"runs the service against native journald and atop while the journal producer remains alive",
	async () => {
		const { root, config } = await setup();
		config.journal.journalctlPath = "/usr/bin/journalctl";
		const directory = join(root, "native-atop");
		await mkdir(directory);
		const day = new Date().toISOString().slice(0, 10).replaceAll("-", "");
		const sampled = spawn("/usr/bin/atop", ["-w", join(directory, `atop_${day}`), "1", "4"], {
			stdio: "ignore",
			env: { PATH: "/usr/sbin:/usr/bin:/bin", TZ: "UTC" },
		});
		await new Promise<void>((resolve, reject) => {
			sampled.once("error", reject);
			sampled.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`atop fixture exited ${code}`))));
		});
		config.atop = { directory, timeZone: "UTC" };
		config.nativeHistoryDirectories = [directory];
		const producer = spawn("/usr/bin/systemd-cat", ["--identifier", config.journal.identifier!, "/usr/bin/cat"], {
			stdio: ["pipe", "ignore", "pipe"],
		});
		const closed = new Promise<void>((resolve) => producer.once("close", () => resolve()));
		const controller = new AbortController();
		let ready = false;
		const start = Date.now();
		const run = runDiagnosticEvidenceService(config, {
			signal: controller.signal,
			onReady: () => {
				ready = true;
			},
		});
		try {
			await until(() => ready);
			expect(Date.now() - start).toBeLessThan(30_000);
			producer.stdin.write(`${JSON.parse(entry("unused")).MESSAGE}\n`);
			await until(
				() => query(config.stateRoot, "SELECT * FROM artifacts WHERE format='journal.export'").length === 1,
			);
			await until(() => query(config.stateRoot, "SELECT * FROM artifacts WHERE format='atop.native'").length === 1);
			expect(producer.exitCode).toBeNull();
			process.kill(producer.pid!, 0);
			const [artifact] = query(config.stateRoot, "SELECT * FROM artifacts WHERE format='journal.export'");
			expect(await readFile(join(config.stateRoot, "artifacts", artifact.path as string), "utf8")).toContain(
				"fatal_exception",
			);
			const [atop] = query(config.stateRoot, "SELECT * FROM artifacts WHERE format='atop.native'");
			const verify = spawn("/usr/bin/atopcat", ["-d", join(config.stateRoot, "artifacts", String(atop.path))], {
				stdio: "ignore",
			});
			await new Promise<void>((resolve, reject) => {
				verify.once("error", reject);
				verify.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`atop readback failed ${code}`))));
			});
		} finally {
			controller.abort();
			await run;
			producer.stdin.end();
			producer.kill("SIGTERM");
			await closed;
		}
	},
);
