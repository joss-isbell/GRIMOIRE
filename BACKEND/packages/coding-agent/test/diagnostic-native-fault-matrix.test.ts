import { spawn, spawnSync } from "node:child_process";
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
const fixture = fileURLToPath(new URL("./fixtures/diagnostic-native-fault-matrix.ts", import.meta.url));
const loader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
type Event = Record<string, unknown>;
interface Ready {
	producerPid: number;
	kernelPid: number;
	kernelInstanceId: string;
	kernelProcessStartId: string;
}
interface ProcessIdentity {
	pid: number;
	parent: number;
	group: number;
	start: string;
	state: string;
}
interface Entry {
	__CURSOR: string;
	__REALTIME_TIMESTAMP: string;
	SYSLOG_IDENTIFIER: string;
	MESSAGE: string;
}

async function identity(pid: number): Promise<ProcessIdentity> {
	const stat = await readFile(`/proc/${pid}/stat`, "utf8");
	const fields = stat
		.slice(stat.lastIndexOf(")") + 2)
		.trim()
		.split(/\s+/);
	return { pid, state: fields[0], parent: Number(fields[1]), group: Number(fields[2]), start: fields[19] };
}

function event(raw: Buffer): Event | undefined {
	try {
		const value = JSON.parse((JSON.parse(raw.toString()) as Entry).MESSAGE) as Event;
		return value.schema === "prime-agent.diagnostic.v1" ? value : undefined;
	} catch {
		return undefined;
	}
}

async function setup() {
	if (process.platform !== "linux") throw new Error("Native fault matrix requires Linux");
	const python = process.env.PRIME_AGENT_CAUSAL_PYTHON ?? "/home/joss/.prime/agent/kernel-venv/bin/python";
	for (const path of ["/usr/bin/systemd-cat", "/usr/bin/journalctl", python, loader]) await access(path);
	const root = await mkdtemp(join(tmpdir(), "diagnostic-native-matrix-"));
	const identifier = `prime-matrix-${randomUUID()}`;
	const session = randomUUID();
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
			session,
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
	let stderr = "";
	producer.once("error", (error) => {
		stderr = String(error);
	});
	producer.stderr!.on("data", (chunk: Buffer) => {
		stderr = (stderr + chunk.toString()).slice(-8192);
	});
	producer.stdout!.resume();
	const closed = new Promise<void>((resolve) => producer.once("close", () => resolve()));
	const records = new Map<string, Buffer>();
	let latestRecords: Buffer[] = [];
	let kernel: ProcessIdentity | undefined;
	let owner: ProcessIdentity | undefined;
	let store: DiagnosticEvidenceStore | undefined;
	async function state<T>(name: string): Promise<T> {
		const deadline = Date.now() + 35_000;
		while (Date.now() < deadline) {
			const failure = await readFile(join(root, "error.json"), "utf8").catch(() => undefined);
			if (failure) throw new Error(`Native matrix fixture: ${failure}`);
			const raw = await readFile(join(root, `${name}.json`), "utf8").catch(() => undefined);
			if (raw) return JSON.parse(raw) as T;
			if (producer.exitCode !== null || producer.signalCode !== null)
				throw new Error(`Native matrix producer exited: ${producer.exitCode ?? producer.signalCode}; ${stderr}`);
			await delay(25);
		}
		throw new Error(`Native matrix state timeout: ${name}; ${stderr}`);
	}
	async function read(): Promise<Event[]> {
		latestRecords = [];
		for await (const raw of readNativeJournal({ identifier }, { sinceMs }, AbortSignal.timeout(5000))) {
			const entry = JSON.parse(raw.toString()) as Entry;
			expect(entry.SYSLOG_IDENTIFIER).toBe(identifier);
			if (!records.has(entry.__CURSOR)) records.set(entry.__CURSOR, raw);
			latestRecords.push(raw);
		}
		return [...records.values()].map(event).filter((value) => value !== undefined);
	}
	async function observe(predicate: (events: Event[]) => boolean, timeoutMs = 10_000): Promise<Event[]> {
		const deadline = Date.now() + timeoutMs;
		while (Date.now() < deadline) {
			const events = await read();
			if (predicate(events)) return events;
			await delay(100);
		}
		throw new Error(`Required native journal evidence unavailable: ${JSON.stringify(await read())}`);
	}
	async function signal(signal: NodeJS.Signals, group = false): Promise<void> {
		if (!kernel || !owner) throw new Error("Missing owned process identity");
		const current = await identity(kernel.pid);
		const currentOwner = await identity(owner.pid);
		if (current.start !== kernel.start || current.parent !== owner.pid || currentOwner.start !== owner.start)
			throw new Error("Refusing signal after owned process identity changed");
		if (group && (current.group !== kernel.pid || current.group === currentOwner.group))
			throw new Error("Refusing signal outside the private kernel process group");
		process.kill(group ? -kernel.pid : kernel.pid, signal);
	}
	async function close(): Promise<void> {
		if (kernel && owner) {
			const current = await identity(kernel.pid).catch(() => undefined);
			if (current?.start === kernel.start && current.parent === owner.pid && current.state === "T")
				await signal("SIGCONT");
		}
		await writeFile(join(root, "command"), "stop");
		await Promise.race([closed, delay(2500, undefined, { ref: false })]);
		for (const sig of ["SIGTERM", "SIGKILL"] as const) {
			if (producer.exitCode === null && producer.signalCode === null) producer.kill(sig);
			await Promise.race([closed, delay(2500, undefined, { ref: false })]);
		}
		await closed;
		if (kernel) {
			const current = await identity(kernel.pid).catch(() => undefined);
			if (current?.start === kernel.start && current.state !== "Z") {
				process.kill(kernel.pid, "SIGKILL");
				throw new Error("Fixture teardown left its original kernel running");
			}
		}
		await store?.close();
		if (process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_KEEP_EVIDENCE === "1")
			console.info(`Native matrix evidence: ${root}`);
		else await rm(root, { recursive: true, force: true });
	}
	try {
		const ready = await state<Ready>("ready");
		expect(ready.producerPid).toBe(producer.pid);
		owner = await identity(ready.producerPid);
		kernel = await identity(ready.kernelPid);
		expect(kernel.parent).toBe(owner.pid);
		expect(kernel.group).toBe(kernel.pid);
		store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
		const evidenceStore = store;
		const storedRecords = new Map<string, Buffer>();
		let changedReplaySerializations = 0;
		const publish = async () => {
			await read();
			const pipeline = new DiagnosticEvidencePipeline(evidenceStore);
			for (const raw of latestRecords) {
				const cursor = (JSON.parse(raw.toString()) as Entry).__CURSOR;
				const first = storedRecords.get(cursor);
				await pipeline.ingestJournal(`journal:${identifier}`, raw);
				if (!first) storedRecords.set(cursor, raw);
				else if (!first.equals(raw)) changedReplaySerializations++;
			}
			await pipeline.publishPending();
			return evidenceStore.listIncidents();
		};
		return {
			root,
			ready,
			producer,
			state,
			read,
			observe,
			signal,
			close,
			publish,
			command: (command: string) => writeFile(join(root, "command"), command),
			async pidfdSignal(): Promise<void> {
				if (!kernel) throw new Error("Kernel identity unavailable");
				const code = [
					"import os, signal, sys",
					"pid, owner, start = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]",
					"fd = os.pidfd_open(pid)",
					"try:",
					"    fields = open('/proc/%d/stat' % pid).read().rsplit(')', 1)[1].split()",
					"    assert fields[19] == start and int(fields[1]) == owner",
					"    signal.pidfd_send_signal(fd, signal.SIGTERM)",
					"finally: os.close(fd)",
				].join("\n");
				const result = spawnSync(
					python,
					["-c", code, String(kernel.pid), String(ready.producerPid), kernel.start],
					{
						timeout: 5000,
						encoding: "utf8",
						maxBuffer: 8192,
					},
				);
				if (result.error || result.status !== 0)
					throw new Error(`pidfd signal failed: ${result.error ?? result.stderr}`);
			},
			async persist(expectIncident: boolean | number) {
				const incidents = await publish();
				if (typeof expectIncident === "number") expect(incidents).toHaveLength(expectIncident);
				else expect(incidents.length > 0).toBe(expectIncident);
				const artifacts = await DiagnosticArtifactOperations.open({
					store: evidenceStore,
					root: join(root, "artifacts"),
					exportArtifact: (_op, signal) =>
						exportNativeJournal({ identifier }, { sinceMs, untilMs: Date.now() }, signal),
				});
				expect((await artifacts.reconcile()).failures).toEqual([]);
				for (const incident of incidents) {
					expect(incident).toMatchObject({ state: "published", coverage: { cause: { status: "unresolved" } } });
					const [artifact] = await evidenceStore.listArtifacts(incident.id);
					expect(artifact).toBeDefined();
					const bytes = await readFile(join(root, "artifacts", artifact.path));
					expect(artifact.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
					expect(artifact.bytes).toBe(bytes.length);
					for (const cursor of records.keys()) expect(bytes.toString()).toContain(`__CURSOR=${cursor}\n`);
				}
				const retained = await evidenceStore.readWindow({ startMs: sinceMs, endMs: Date.now() });
				expect(retained.occurrences).toHaveLength(storedRecords.size);
				for (const occurrence of retained.occurrences) {
					const raw = Buffer.from(occurrence.payload);
					expect(raw).toEqual(storedRecords.get((JSON.parse(raw.toString()) as Entry).__CURSOR));
				}
				const current = await identity(ready.producerPid);
				expect(current.start).toBe(owner!.start);
				expect(producer.exitCode).toBeNull();
				await writeFile(
					join(root, "observed-journal.jsonl"),
					Buffer.concat([...storedRecords.values()].flatMap((raw) => [raw, Buffer.from("\n")])),
				);
				await writeFile(
					join(root, "receipt.json"),
					JSON.stringify({
						ready,
						identifier,
						incidents,
						producerAliveAfterExport: true,
						changedReplaySerializations,
					}),
				);
				await expect(access(join(root, "config", "incident-recorder"))).rejects.toMatchObject({ code: "ENOENT" });
			},
		};
	} catch (error) {
		await close();
		throw error;
	}
}

function originalOnly(events: Event[], ready: Ready): void {
	expect(events.filter((entry) => entry.type === "kernel_process_started")).toHaveLength(1);
	for (const entry of events.filter((entry) => entry.kernelPid !== undefined)) {
		expect(entry.kernelPid).toBe(ready.kernelPid);
		expect(entry.kernelInstanceId).toBe(ready.kernelInstanceId);
		expect(entry.kernelProcessStartId).toBe(ready.kernelProcessStartId);
	}
	expect(JSON.stringify(events)).not.toContain("matrix-private-sentinel");
}

it.skipIf(!enabled)(
	"records application shutdown intent before exit without publishing a false failure",
	async () => {
		const h = await setup();
		try {
			await h.command("shutdown");
			await h.state("completed");
			const events = await h.observe((events) =>
				events.some((entry) => entry.type === "kernel_process_exit_observed"),
			);
			originalOnly(events, h.ready);
			const shutdown = events.find(
				(entry) => entry.type === "kernel_lifecycle_intent" && entry.operation === "shutdown",
			);
			const exit = events.find((entry) => entry.type === "kernel_process_exit_observed");
			expect(shutdown).toMatchObject({
				caller: "nativeFixture.shutdown",
				reason: "session_closed",
				ownerPid: h.ready.producerPid,
			});
			expect(exit).toMatchObject({ lifecycleState: "shutdown", ownerPid: h.ready.producerPid });
			expect(Number(shutdown?.sequence)).toBeLessThan(Number(exit?.sequence));
			expect(events.some((entry) => entry.type === "kernel_unexpected_exit")).toBe(false);
			await h.persist(false);
		} finally {
			await h.close();
		}
	},
	50_000,
);

it.skipIf(!enabled).each(["ordinary signal", "process-group signal", "pidfd signal", "native crash"])(
	"captures %s and publishes native evidence before the owning producer stops",
	async (fault) => {
		const h = await setup();
		try {
			await h.command(fault === "native crash" ? "native-crash" : "sleep");
			const request = await h.state<{ requestMsgId: string }>("executing");
			if (fault === "ordinary signal") await h.signal("SIGTERM");
			if (fault === "process-group signal") await h.signal("SIGTERM", true);
			if (fault === "pidfd signal") await h.pidfdSignal();
			expect(await h.state("completed")).toMatchObject({ status: "rejected" });
			const events = await h.observe((events) =>
				events.some((entry) => entry.type === "kernel_diagnostic_capture_complete"),
			);
			originalOnly(events, h.ready);
			const exit = events.find((entry) => entry.type === "kernel_process_exit_observed");
			expect(exit).toMatchObject({
				code: null,
				signal: fault === "native crash" ? "SIGSEGV" : "SIGTERM",
				lifecycleState: "running",
				requestMsgId: request.requestMsgId,
			});
			expect(events.find((entry) => entry.type === "kernel_unexpected_exit")).toMatchObject({
				reason: "process_exit",
				requestMsgId: request.requestMsgId,
			});
			expect(exit?.senderPid).toBeUndefined();
			for (const intent of events.filter((entry) => entry.type === "kernel_lifecycle_intent")) {
				expect(intent.operation).toBe("cleanup_resources");
				expect(Number(intent.sequence)).toBeGreaterThan(Number(exit?.sequence));
			}
			await h.persist(true);
		} finally {
			await h.close();
		}
	},
	50_000,
);

it.skipIf(!enabled)(
	"distinguishes a healthy long execution from a stopped heartbeat and retains the original state after continuation",
	async () => {
		const h = await setup();
		try {
			await h.command("healthy");
			const healthy = await h.state<{ requestMsgId: string }>("executing");
			expect(await h.state("completed")).toMatchObject({ status: "ok" });
			const healthyEvents = await h.observe((events) =>
				events.some((entry) => entry.observation === "shell_reply" && entry.requestMsgId === healthy.requestMsgId),
			);
			expect(
				healthyEvents.some(
					(entry) => entry.observation === "heartbeat_echo" && entry.requestMsgId === healthy.requestMsgId,
				),
			).toBe(true);
			expect(
				healthyEvents.some(
					(entry) =>
						entry.observation === "heartbeat_unavailable" || entry.observation === "shell_reply_unavailable",
				),
			).toBe(false);
			expect(await h.publish()).toHaveLength(0);
			await rm(join(h.root, "executing.json"));
			await rm(join(h.root, "completed.json"));
			await h.command("sleep");
			const stopped = await h.state<{ requestMsgId: string }>("executing");
			await h.observe((events) =>
				events.some((entry) => entry.observation === "iopub_busy" && entry.requestMsgId === stopped.requestMsgId),
			);
			await h.signal("SIGSTOP");
			const stalled = await h.observe((events) =>
				events.some(
					(entry) => entry.observation === "heartbeat_unavailable" && entry.requestMsgId === stopped.requestMsgId,
				),
			);
			expect((await identity(h.ready.kernelPid)).state).toBe("T");
			expect(
				stalled.some(
					(entry) => entry.type === "kernel_lifecycle_intent" || entry.type === "kernel_process_exit_observed",
				),
			).toBe(false);
			const [incident] = await h.publish();
			expect(incident).toMatchObject({ state: "published", coverage: { cause: { status: "unresolved" } } });
			expect(h.producer.exitCode).toBeNull();
			expect((await identity(h.ready.kernelPid)).state).toBe("T");
			await h.observe(
				(events) => events.filter((entry) => entry.observation === "heartbeat_unavailable").length >= 2,
			);
			expect(await h.publish()).toHaveLength(1);
			await h.signal("SIGCONT");
			expect(await h.state("completed")).toMatchObject({ status: "ok" });
			await h.command("sentinel");
			expect(await h.state("retained")).toEqual({ status: "ok", stdout: String(h.ready.kernelPid) });
			const events = await h.observe((observed) => {
				const unavailable = observed.filter((entry) => entry.observation === "heartbeat_unavailable").at(-1)!;
				return observed.some(
					(entry) =>
						entry.observation === "heartbeat_echo" && Number(entry.sequence) > Number(unavailable.sequence),
				);
			});
			originalOnly(events, h.ready);
			expect(
				events.some(
					(entry) => entry.type === "kernel_lifecycle_intent" || entry.type === "kernel_process_exit_observed",
				),
			).toBe(false);
			await h.persist(1);
		} finally {
			await h.close();
		}
	},
	60_000,
);

it.skipIf(!enabled)(
	"preserves heartbeat and the missing reply after an actual IPython shell socket closes",
	async () => {
		const h = await setup();
		try {
			await h.command("close-shell");
			const request = await h.state<{ requestMsgId: string }>("executing");
			expect(await h.state("completed")).toMatchObject({ status: "ok" });
			const events = await h.observe((events) =>
				events.some(
					(entry) =>
						entry.observation === "shell_reply_unavailable" && entry.requestMsgId === request.requestMsgId,
				),
			);
			originalOnly(events, h.ready);
			expect(
				events.some((entry) => entry.observation === "iopub_idle" && entry.requestMsgId === request.requestMsgId),
			).toBe(true);
			expect(
				events.some(
					(entry) => entry.type === "kernel_process_exit_observed" || entry.type === "kernel_lifecycle_intent",
				),
			).toBe(false);
			await h.observe((events) =>
				events.some(
					(entry) =>
						entry.observation === "heartbeat_echo" &&
						entry.requestMsgId === undefined &&
						Number(entry.sequence) >
							Number(events.find((item) => item.observation === "shell_reply_unavailable")?.sequence),
				),
			);
			await h.persist(true);
		} finally {
			await h.close();
		}
	},
	50_000,
);
