import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { IncidentRecorderCompactor as ProductionCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import { IncidentRecorderSegmentStore } from "../src/modes/daemon/incident-recorder-segment-store.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const roots: string[] = [];
const leases: IncidentRecorderWriterLifecycleLease[] = [];

class IncidentRecorderCompactor extends ProductionCompactor {
	constructor(options: ConstructorParameters<typeof ProductionCompactor>[0]) {
		let lease: IncidentRecorderWriterLifecycleLease | undefined;
		super({
			...options,
			writerLifecycleLease:
				options.writerLifecycleLease ??
				(() => {
					if (!lease) {
						const result = acquireIncidentRecorderWriterNormalLease(
							{ agentDir: options.agentDir },
							{
								activationGenerationDigest: "a".repeat(64),
								revalidateActivation: () => ({ state: "valid" }),
								acquireCas: acquireIncidentRecorderNamespaceCas,
							},
						);
						if (result.state !== "acquired") throw new Error(`fixture writer lease: ${result.reason}`);
						lease = result.lease;
						leases.push(lease);
					}
					return lease;
				}),
		});
	}
}

afterEach(() => {
	for (const lease of leases.splice(0)) lease.release();
	delete process.env.PRIME_TEST_STORAGE_LINES;
	delete process.env.PRIME_TEST_STORAGE_MARKER;
	delete process.env.PRIME_TEST_JOURNAL_LOG;
	delete process.env.PRIME_TEST_JOURNAL_ENTRY;
	delete process.env.PRIME_TEST_JOURNAL_GATE;
	delete process.env.NOTIFY_SOCKET;
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function executable(root: string, name: string, source: string): string {
	const path = join(root, name);
	writeFileSync(path, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
	chmodSync(path, 0o700);
	return path;
}

function fixture(): { root: string; agentDir: string; scanner: string; journal: string; journalLog: string } {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-compactor-recovery-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const scanner = executable(
		root,
		"storage-scanner.cjs",
		'const fs=require("node:fs");if(process.env.PRIME_TEST_STORAGE_MARKER)fs.writeFileSync(process.env.PRIME_TEST_STORAGE_MARKER,JSON.stringify({args:process.argv.slice(2),notifySocket:process.env.NOTIFY_SOCKET??null,pid:process.pid}));process.stdout.write(process.env.PRIME_TEST_STORAGE_LINES??"1\\t1\\t0\\t0\\n");',
	);
	const journalLog = join(root, "journal-args.jsonl");
	const journal = executable(
		root,
		"journalctl.cjs",
		'const fs=require("node:fs");const record={args:process.argv.slice(2),notifySocket:process.env.NOTIFY_SOCKET??null,pid:process.pid};fs.appendFileSync(process.env.PRIME_TEST_JOURNAL_LOG,JSON.stringify(record)+"\\n");if(process.argv.some((arg)=>arg==="--after-cursor=stale-cursor")){process.stderr.write("Failed to seek to cursor: cursor not found\\n");process.exit(1);}if(!process.argv.includes("--follow"))process.exit(0);const emit=()=>{if(process.env.PRIME_TEST_JOURNAL_ENTRY)process.stdout.write(process.env.PRIME_TEST_JOURNAL_ENTRY);};const gate=process.env.PRIME_TEST_JOURNAL_GATE;if(gate&&!fs.existsSync(gate)){const gateTimer=setInterval(()=>{if(fs.existsSync(gate)){clearInterval(gateTimer);emit();}},5);}else emit();process.once("SIGTERM",()=>process.exit(0));setInterval(()=>{},1000);',
	);
	return { root, agentDir, scanner, journal, journalLog };
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error("timed out waiting for isolated compactor fixture");
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

function jsonLines(path: string): Array<Record<string, unknown>> {
	return readFileSync(path, "utf8")
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

function gapReasons(agentDir: string): string[] {
	const store = new IncidentRecorderSegmentStore({
		directory: join(agentDir, "incident-recorder", "segments"),
	});
	try {
		return store
			.queryRunWindow({
				runId: "__recorder__",
				sourceId: "gap",
				fromObservedAtMs: 0,
				throughObservedAtMs: Number.MAX_SAFE_INTEGER,
			})
			.map((record) => {
				const value = JSON.parse(record.payload.toString("utf8")) as {
					evidence?: { reason?: unknown };
				};
				return String(value.evidence?.reason ?? "");
			});
	} finally {
		store.close();
	}
}

describe("incident recorder compactor recovery bounds", () => {
	it("keeps construction O(1), deduplicates allocated storage, and makes saturation recovery-only", async () => {
		const target = fixture();
		const marker = join(target.root, "storage-marker.json");
		process.env.PRIME_TEST_STORAGE_MARKER = marker;
		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t1\t8\n1\t10\t1\t8\n1\t11\t2\t8\n";
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: target.scanner,
			freeReserveBytes: 0,
		});

		expect(compactor.storageAccountingReady).toBe(false);
		expect(compactor.admitObservation(0)).toBe(false);
		expect(() => readFileSync(marker)).toThrow();

		await compactor.initializeStorageAccounting(new AbortController().signal);
		expect(compactor.storageAccountingReady).toBe(true);
		expect(compactor.accountedStorageBytes).toBe(8 * 1024);
		expect(compactor.admitObservation(0)).toBe(true);
		const scan = JSON.parse(readFileSync(marker, "utf8")) as { notifySocket: unknown };
		expect(scan.notifySocket).toBeNull();

		const saturated = new IncidentRecorderCompactor({
			agentDir: join(target.root, "saturated-agent"),
			storageScannerPath: target.scanner,
			storageAccountingMaxInodes: 1,
			freeReserveBytes: 0,
		});
		await saturated.initializeStorageAccounting(new AbortController().signal);
		expect(saturated.storageAccountingReady).toBe(false);
		expect(saturated.storageMode).toBe("recovery-only");
		expect(saturated.storageRecoveryReason).toBe("inode_bound_exceeded");
		expect(saturated.admitObservation(0)).toBe(false);
	});

	it("aborts an in-progress storage scan without declaring accounting ready", async () => {
		const target = fixture();
		const marker = join(target.root, "storage-abort.log");
		process.env.PRIME_TEST_STORAGE_MARKER = marker;
		const blockingScanner = executable(
			target.root,
			"blocking-storage-scanner.cjs",
			'const fs=require("node:fs");const marker=process.env.PRIME_TEST_STORAGE_MARKER;fs.appendFileSync(marker,"started\\n");process.once("SIGTERM",()=>{fs.appendFileSync(marker,"term\\n");process.exit(0);});setInterval(()=>{},1000);',
		);
		const controller = new AbortController();
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: blockingScanner,
			freeReserveBytes: 0,
		});
		const pending = compactor.initializeStorageAccounting(controller.signal);
		await waitFor(() => {
			try {
				return readFileSync(marker, "utf8").includes("started");
			} catch {
				return false;
			}
		});
		controller.abort();
		await expect(pending).rejects.toMatchObject({ name: "AbortError" });
		expect(readFileSync(marker, "utf8")).toContain("term");
		expect(compactor.storageAccountingReady).toBe(false);
		expect(compactor.admitObservation(0)).toBe(false);
	});

	it("pauses at storage high water and resumes only after a low-water rescan", async () => {
		const target = fixture();
		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t1\t8\n1\t11\t1\t8\n1\t12\t1\t8\n";
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: target.scanner,
			storageAccountingMaxInodes: 4,
			storageHighWaterInodes: 3,
			storageLowWaterInodes: 2,
			storageHighWaterEntries: 4,
			storageLowWaterEntries: 2,
			storageHighWaterBytes: 64 * 1024,
			storageLowWaterBytes: 32 * 1024,
			freeReserveBytes: 0,
		});

		await compactor.initializeStorageAccounting(new AbortController().signal);
		expect(compactor.storageAccountingReady).toBe(true);
		expect(compactor.storageMode).toBe("recovery-only");
		expect(compactor.storageRecoveryReason).toBe("inode_high_water");
		expect(compactor.admitObservation(0)).toBe(false);

		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t1\t8\n1\t11\t1\t8\n";
		await compactor.initializeStorageAccounting(new AbortController().signal);
		expect(compactor.storageMode).toBe("recovery-only");

		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t1\t8\n";
		await compactor.initializeStorageAccounting(new AbortController().signal);
		expect(compactor.storageMode).toBe("normal");
		expect(compactor.storageRecoveryReason).toBeUndefined();
		expect(compactor.admitObservation(0)).toBe(true);

		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t1\t8\n1\t11\t1\t8\n1\t12\t1\t8\n1\t13\t1\t8\n1\t14\t1\t8\n";
		await compactor.initializeStorageAccounting(new AbortController().signal);
		expect(compactor.storageAccountingReady).toBe(true);
		expect(compactor.storageMode).toBe("recovery-only");
		expect(compactor.storageRecoveryReason).toBe("inode_bound_exceeded");
		expect(compactor.admitObservation(0)).toBe(false);
	});

	it("fails closed on an unclassified refresh failure after a trusted baseline", async () => {
		const target = fixture();
		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t1\t8\n";
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: target.scanner,
			freeReserveBytes: 0,
		});

		await compactor.initializeStorageAccounting(new AbortController().signal);
		expect(compactor.storageMode).toBe("normal");

		process.env.PRIME_TEST_STORAGE_LINES = "not-a-storage-record\n";
		await compactor.initializeStorageAccounting(new AbortController().signal);
		expect(compactor.storageAccountingReady).toBe(true);
		expect(compactor.storageMode).toBe("recovery-only");
		expect(compactor.storageRecoveryReason).toBe("scan_failed");
		expect(compactor.admitObservation(0)).toBe(false);
	});

	it("reserves aggregate stopped-artifact capacity and aborts staging on pressure", async () => {
		const target = fixture();
		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t0\t0\n";
		const first = join(target.root, "first.bin");
		const second = join(target.root, "second.bin");
		writeFileSync(first, Buffer.alloc(600 * 1024, 1));
		writeFileSync(second, Buffer.alloc(600 * 1024, 2));
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: target.scanner,
			storageByteCeiling: 3 * 1024 * 1024,
			storageHighWaterBytes: 1536 * 1024,
			storageLowWaterBytes: 768 * 1024,
			storageHighWaterInodes: 100,
			storageLowWaterInodes: 50,
			storageHighWaterEntries: 100,
			storageLowWaterEntries: 50,
			freeReserveBytes: 0,
		});
		await compactor.initializeStorageAccounting(new AbortController().signal);

		expect(
			compactor.streamStoppedTargetArtifact("run-a", first, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 1,
			}),
		).toMatchObject({ state: "pending", reason: "work_budget", copiedBytes: 1 });
		expect(
			compactor.streamStoppedTargetArtifact("run-b", second, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 1,
			}),
		).toMatchObject({ state: "pending", reason: "storage_paused" });
		expect(compactor.storageMode).toBe("recovery-only");
		expect(readdirSync(join(target.agentDir, "incident-recorder", "cas", "sha256", "staging"))).toEqual([]);
	});

	it("uses a bounded no-checkpoint tail, records the unknown prefix, strips NOTIFY_SOCKET, and aborts its reader", async () => {
		const target = fixture();
		process.env.PRIME_TEST_STORAGE_LINES = "1\t1\t0\t0\n";
		process.env.PRIME_TEST_JOURNAL_LOG = target.journalLog;
		process.env.NOTIFY_SOCKET = "/tmp/must-not-reach-child";
		const controller = new AbortController();
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: target.scanner,
			journalctlPath: target.journal,
			journalCatchupMaxEntries: 2,
			journalCatchupSliceMs: 2_000,
			freeReserveBytes: 0,
		});

		await compactor.run({
			signal: controller.signal,
			onReaderReady: () => setTimeout(() => controller.abort(), 50),
		});

		const invocations = jsonLines(target.journalLog);
		expect(invocations).toHaveLength(2);
		expect(invocations[0]?.args).toContain("--lines=2");
		expect(invocations[0]?.args).not.toContain("--follow");
		expect(invocations[0]?.args).not.toContain("--no-tail");
		expect(invocations[0]?.notifySocket).toBeNull();
		expect(invocations[1]?.args).toContain("--follow");
		expect(invocations[1]?.args).toContain("--lines=0");
		expect(invocations[1]?.args).not.toContain("--no-tail");
		expect(invocations[1]?.notifySocket).toBeNull();
		expect(gapReasons(target.agentDir)).toContain("journal_history_before_bounded_start_not_asserted");
	});

	it("runs cleanup on runtime pressure and replays the unpersisted follow entry", async () => {
		const target = fixture();
		const journalGate = join(target.root, "release-journal-entry");
		process.env.PRIME_TEST_STORAGE_LINES = "1\t10\t0\t0\n";
		process.env.PRIME_TEST_JOURNAL_LOG = target.journalLog;
		process.env.PRIME_TEST_JOURNAL_GATE = journalGate;
		process.env.PRIME_TEST_JOURNAL_ENTRY = [
			"__CURSOR=s=runtime-pressure",
			"_MACHINE_ID=11111111111111111111111111111111",
			"_BOOT_ID=22222222222222222222222222222222",
			"_STREAM_ID=stream-1",
			"__REALTIME_TIMESTAMP=1000",
			"__MONOTONIC_TIMESTAMP=2000",
			"_PID=123",
			"_UID=1000",
			"SYSLOG_IDENTIFIER=prime-agent-raw-v1",
			"_TRANSPORT=stdout",
			"MESSAGE={}",
			"",
			"",
		].join("\n");
		const controller = new AbortController();
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: target.scanner,
			journalctlPath: target.journal,
			storageHighWaterEntries: 10,
			storageLowWaterEntries: 2,
			storageHighWaterInodes: 100,
			storageLowWaterInodes: 50,
			storageHighWaterBytes: 64 * 1024 * 1024,
			storageLowWaterBytes: 32 * 1024 * 1024,
			journalCatchupMaxEntries: 2,
			journalCatchupSliceMs: 2_000,
			freeReserveBytes: 0,
		});
		let recoveryPasses = 0;
		const running = compactor.run({
			signal: controller.signal,
			storageRecoveryCadenceMs: 5,
			onRecoveryPass: () => {
				recoveryPasses += 1;
				process.env.PRIME_TEST_STORAGE_LINES = "";
				return false;
			},
		});
		try {
			await waitFor(() => {
				try {
					return jsonLines(target.journalLog).some((entry) => (entry.args as string[]).includes("--follow"));
				} catch {
					return false;
				}
			});
			process.env.PRIME_TEST_STORAGE_LINES =
				[
					"1\t20\t0\t0",
					"1\t21\t0\t0",
					"1\t22\t0\t0",
					"1\t23\t0\t0",
					"1\t24\t0\t0",
					"1\t25\t0\t0",
					"1\t26\t0\t0",
					"1\t27\t0\t0",
					"1\t28\t0\t0",
					"1\t29\t0\t0",
				].join("\n") + "\n";
			await compactor.initializeStorageAccounting(controller.signal);
			expect(compactor.storageMode).toBe("recovery-only");
			writeFileSync(journalGate, "release\n", { mode: 0o600 });
			await waitFor(() => {
				try {
					const checkpoint = JSON.parse(
						readFileSync(join(target.agentDir, "incident-recorder", "compactor-cursor.json"), "utf8"),
					) as { cursor?: unknown };
					return checkpoint.cursor === "s=runtime-pressure";
				} catch {
					return false;
				}
			});
		} finally {
			controller.abort();
			await running;
		}

		expect(recoveryPasses).toBeGreaterThan(0);
		const invocations = jsonLines(target.journalLog);
		expect(invocations.filter((entry) => (entry.args as string[]).includes("--follow"))).toHaveLength(2);
		expect(invocations.some((entry) => (entry.args as string[]).includes("--after-cursor=s=runtime-pressure"))).toBe(
			false,
		);
	});

	it("does not checkpoint a poisoned journal entry when its durable gap append fails", () => {
		const target = fixture();
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: target.scanner,
			freeReserveBytes: 0,
		});
		const internal = compactor as unknown as {
			writeGap(value: unknown): void;
			recoverPoisonedJournalEntry(outcome: {
				parserError: Error;
				poisonFields: Readonly<Record<string, Buffer>>;
			}): string | undefined;
		};
		internal.writeGap = () => {
			throw new Error("injected durable gap failure");
		};
		expect(() =>
			internal.recoverPoisonedJournalEntry({
				parserError: new Error("truncated journal export"),
				poisonFields: {
					__CURSOR: Buffer.from("s=poisoned"),
					_MACHINE_ID: Buffer.from("machine"),
					_BOOT_ID: Buffer.from("boot"),
					__REALTIME_TIMESTAMP: Buffer.from("1000"),
				},
			}),
		).toThrow("injected durable gap failure");
		expect(existsSync(join(target.agentDir, "incident-recorder", "compactor-cursor.json"))).toBe(false);
	});

	it("turns an unseekable checkpoint into explicit evidence before falling back to a bounded tail", async () => {
		const target = fixture();
		const recorder = join(target.agentDir, "incident-recorder");
		mkdirSync(recorder, { recursive: true, mode: 0o700 });
		writeFileSync(
			join(recorder, "compactor-cursor.json"),
			`${JSON.stringify({
				version: 1,
				cursor: "stale-cursor",
				machineId: "machine",
				bootId: "boot",
				invocationId: null,
				lastRealtimeUs: "1",
				wrapperSequences: {},
				producerSequences: {},
			})}\n`,
			{ mode: 0o600 },
		);
		process.env.PRIME_TEST_STORAGE_LINES = "1\t1\t4096\t8\n";
		process.env.PRIME_TEST_JOURNAL_LOG = target.journalLog;
		const controller = new AbortController();
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			storageScannerPath: target.scanner,
			journalctlPath: target.journal,
			journalCatchupMaxEntries: 2,
			journalCatchupSliceMs: 2_000,
			freeReserveBytes: 0,
		});
		const running = compactor.run({ signal: controller.signal });
		await waitFor(() => {
			try {
				return jsonLines(target.journalLog).length >= 3;
			} catch {
				return false;
			}
		});
		controller.abort();
		await running;

		const invocations = jsonLines(target.journalLog);
		expect(invocations[0]?.args).toContain("--after-cursor=stale-cursor");
		expect(invocations[0]?.args).toContain("--lines=+2");
		expect(invocations[1]?.args).toContain("--lines=2");
		expect(invocations[1]?.args).not.toContain("--no-tail");
		expect(invocations[2]?.args).toContain("--follow");
		expect(invocations[2]?.args).toContain("--lines=0");
		expect(invocations[2]?.args).not.toContain("--no-tail");
		expect(gapReasons(target.agentDir)).toEqual(
			expect.arrayContaining([
				"journal_cursor_removed_or_unseekable",
				"journal_history_before_bounded_start_not_asserted",
			]),
		);
	});
});
