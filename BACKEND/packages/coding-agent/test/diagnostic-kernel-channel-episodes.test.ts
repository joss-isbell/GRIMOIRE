import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { expect, it, vi } from "vitest";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";

it("publishes one live channel episode across restart, then rearms only on a later matching observation", async () => {
	const root = await mkdtemp(join(tmpdir(), "kernel-channel-episode-"));
	const path = join(root, "evidence.sqlite");
	let store = await DiagnosticEvidenceStore.open({ path });
	let pipeline = new DiagnosticEvidencePipeline(store);
	let sequence = 0;
	const now = Date.now();
	const put = async (observation: string, overrides: Record<string, unknown> = {}) => {
		sequence++;
		await pipeline.ingestJournal(
			"application-journal",
			Buffer.from(
				JSON.stringify({
					__CURSOR: String(sequence),
					__REALTIME_TIMESTAMP: String((now + sequence) * 1000),
					_BOOT_ID: "boot",
					MESSAGE: JSON.stringify({
						schema: "prime-agent.diagnostic.v1",
						type: "kernel_protocol_observation",
						observation,
						kernelInstanceId: "original",
						kernelPid: 10,
						kernelProcessStartId: "proc:100",
						kernelGeneration: 1,
						observerPid: 20,
						observerProcessStartId: "200",
						observerPidNamespace: "pid:[123]",
						observerBoottimeOffsetNs: "0",
						monotonicNs: String(sequence * 100),
						...overrides,
					}),
				}),
			),
		);
	};
	try {
		await put("heartbeat_unavailable");
		expect(await pipeline.publishPending()).toBe(1);
		await put("heartbeat_unavailable", { monotonicNs: "100" });
		expect(await pipeline.publishPending()).toBe(0);
		const [first] = await store.listIncidents();
		expect(first).toMatchObject({ state: "published", coverage: { cause: { status: "unresolved" } } });
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		pipeline = new DiagnosticEvidencePipeline(store);
		await put("heartbeat_unavailable");
		await put("heartbeat_echo", { kernelGeneration: 2 });
		await put("heartbeat_echo", { observerPid: 21 });
		await put("heartbeat_echo", { monotonicNs: "50" });
		await put("heartbeat_echo", {
			monotonicNs: "9999999",
			details: { schemaVersion: 2, value: { $diagnosticType: "object", properties: [["monotonicNs", "50"]] } },
		});
		await put("heartbeat_echo", {
			monotonicNs: "9999999",
			details: { schemaVersion: 2, value: { $diagnosticType: "object", properties: [] } },
		});
		await put("heartbeat_unavailable");
		expect(await pipeline.publishPending()).toBe(0);
		expect(await store.listIncidents()).toHaveLength(1);
		await put("heartbeat_echo");
		await put("heartbeat_unavailable");
		expect(await pipeline.publishPending()).toBe(1);
		expect(await store.listIncidents()).toHaveLength(2);
		await put("shell_unavailable");
		await put("heartbeat_echo");
		await put("shell_unavailable");
		expect(await pipeline.publishPending()).toBe(1);
		expect(await store.listIncidents()).toHaveLength(3);
		await put("shell_reply");
		await put("shell_unavailable");
		expect(await pipeline.publishPending()).toBe(1);
		await put("heartbeat_unavailable", { kernelGeneration: 2 });
		expect(await pipeline.publishPending()).toBe(1);
		expect(await store.listIncidents()).toHaveLength(5);
		expect((await store.readOccurrences()).occurrences.filter((row) => row.kind === "journal.json")).toHaveLength(
			sequence,
		);
	} finally {
		await store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it("does not pin an active episode's first payload or expired incident and retires old boots without inventing recovery", async () => {
	const root = await mkdtemp(join(tmpdir(), "kernel-channel-retention-"));
	const store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
	const boot = "a".repeat(32);
	const now = Date.now();
	try {
		const put = async (id: string, time: number) => {
			const before = await store.getCursor("journal");
			await store.ingest({
				batchId: id,
				source: "journal",
				expectedCursor: before,
				cursor: id,
				occurrences: [
					{
						id,
						wallTimeMs: time,
						kind: "journal.json",
						payload: Buffer.from(
							JSON.stringify({
								_BOOT_ID: boot,
								MESSAGE: JSON.stringify({
									schema: "prime-agent.diagnostic.v1",
									type: "kernel_protocol_observation",
									observation: "heartbeat_unavailable",
									kernelInstanceId: "original",
									kernelPid: 10,
									kernelProcessStartId: "100",
									kernelGeneration: 1,
									observerPid: 20,
									observerProcessStartId: "200",
									observerPidNamespace: "pid:[123]",
									observerBoottimeOffsetNs: "0",
									monotonicNs: String(time),
								}),
							}),
						),
					},
				],
			});
			return store.observeKernelChannel(
				{ source: "journal", occurrenceId: id },
				{
					id,
					triggerTimeMs: time,
					windowStartMs: time - 30 * 60_000,
					windowEndMs: time + 15 * 60_000,
					coverage: { cause: { status: "unresolved" } },
					limitations: ["Channel unavailable; cause unresolved."],
				},
			);
		};
		expect(await put("first", now)).toMatchObject({ status: "incident" });
		await store.retain({ nowMs: now + 15 * 86_400_000 });
		expect(await store.getIncident("first")).toBeUndefined();
		expect(await store.getOccurrence("journal", "first")).toBeUndefined();
		expect(await put("later", now + 15 * 86_400_000)).toMatchObject({
			status: "incident",
			incident: { id: "later" },
		});
		expect(
			await store.recordRuntimeBoot({ bootId: "b".repeat(32), observedAtMs: now + 15 * 86_400_000, limit: 1 }),
		).toEqual({ retired: 0, more: true });
		expect(
			await store.recordRuntimeBoot({ bootId: "b".repeat(32), observedAtMs: now + 16 * 86_400_000, limit: 1 }),
		).toEqual({ retired: 0, more: false });
		const inspect = new DatabaseSync(join(root, "evidence.sqlite"), { readOnly: true });
		expect(inspect.prepare("SELECT unavailable,observed_at_ms FROM kernel_channel_episodes").get()).toEqual({
			unavailable: 0,
			observed_at_ms: now + 15 * 86_400_000,
		});
		inspect.close();
		await store.retain({ nowMs: now + 31 * 86_400_000 });
		expect((await store.readOccurrences()).occurrences).toEqual([]);
		expect(await store.listIncidents()).toEqual([]);
	} finally {
		await store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it("preserves every overflow observation as a gap without evicting an active episode or opening an incident storm", async () => {
	const root = await mkdtemp(join(tmpdir(), "kernel-channel-capacity-"));
	const path = join(root, "evidence.sqlite");
	let store = await DiagnosticEvidenceStore.open({ path });
	try {
		await store.close();
		const fixture = new DatabaseSync(path);
		fixture.exec("BEGIN IMMEDIATE");
		const insert = fixture.prepare("INSERT INTO kernel_channel_episodes VALUES(?,'boot','1',1,1,NULL,?)");
		for (let i = 0; i < 4096; i++) insert.run(`fixture-active-${i}`, Date.now());
		fixture.exec("COMMIT");
		fixture.close();
		store = await DiagnosticEvidenceStore.open({ path });
		const pipeline = new DiagnosticEvidencePipeline(store);
		for (let i = 0; i < 2; i++)
			await pipeline.ingestJournal(
				"journal",
				Buffer.from(
					JSON.stringify({
						__CURSOR: String(i),
						__REALTIME_TIMESTAMP: String(Date.now() * 1000),
						_BOOT_ID: "boot",
						MESSAGE: JSON.stringify({
							schema: "prime-agent.diagnostic.v1",
							type: "kernel_protocol_observation",
							observation: "heartbeat_unavailable",
							kernelInstanceId: "original",
							kernelPid: 10,
							kernelProcessStartId: "100",
							kernelGeneration: 1,
							observerPid: 20,
							observerProcessStartId: "200",
							observerPidNamespace: "pid:[123]",
							observerBoottimeOffsetNs: "0",
							monotonicNs: String(i + 1),
						}),
					}),
				),
			);
		expect(await pipeline.publishPending()).toBe(0);
		expect(await store.listIncidents()).toEqual([]);
		const rows = (await store.readOccurrences()).occurrences;
		expect(rows.filter((row) => row.kind === "diagnostic.gap")).toHaveLength(2);
		expect(rows.filter((row) => row.kind === "journal.json")).toHaveLength(2);
		const inspect = new DatabaseSync(path, { readOnly: true });
		expect(inspect.prepare("SELECT count(*) AS count FROM kernel_channel_episodes").get()?.count).toBe(4096);
		inspect.close();
	} finally {
		await store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it("replays an atomic episode opening interrupted before publication and exposes missing identity as gaps", async () => {
	const root = await mkdtemp(join(tmpdir(), "kernel-channel-crash-"));
	const path = join(root, "evidence.sqlite");
	let store = await DiagnosticEvidenceStore.open({ path });
	try {
		const pipeline = new DiagnosticEvidencePipeline(store);
		const now = Date.now();
		for (let n = 1; n <= 3; n++)
			await pipeline.ingestJournal(
				"application-journal",
				Buffer.from(
					JSON.stringify({
						__CURSOR: String(n),
						__REALTIME_TIMESTAMP: String(now * 1000),
						_BOOT_ID: "boot",
						MESSAGE: JSON.stringify({
							schema: "prime-agent.diagnostic.v1",
							type: "kernel_protocol_observation",
							observation: "heartbeat_unavailable",
							monotonicNs: String(n),
							kernelInstanceId: "original",
							kernelPid: 10,
							kernelProcessStartId: "100",
							kernelGeneration: 1,
							...(n === 1
								? {
										observerPid: 20,
										observerProcessStartId: "200",
										observerPidNamespace: "pid:[123]",
										observerBoottimeOffsetNs: "0",
									}
								: {}),
						}),
					}),
				),
			);
		vi.spyOn(store, "prepareOperation").mockRejectedValueOnce(new Error("interrupted before export"));
		await expect(pipeline.publishPending()).rejects.toThrow("interrupted before export");
		expect(await store.listIncidents()).toHaveLength(1);
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path });
		expect(await new DiagnosticEvidencePipeline(store).publishPending()).toBe(1);
		expect(await store.listIncidents()).toHaveLength(1);
		const rows = (await store.readOccurrences()).occurrences;
		expect(rows.filter((row) => row.kind === "diagnostic.gap")).toHaveLength(2);
		expect(rows.filter((row) => row.kind === "journal.json")).toHaveLength(3);
	} finally {
		await store.close();
		await rm(root, { recursive: true, force: true });
	}
});
