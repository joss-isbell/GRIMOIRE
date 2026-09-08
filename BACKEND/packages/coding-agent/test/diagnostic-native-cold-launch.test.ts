import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { shutdownDaemonAndWait } from "../src/cli/daemon-launch.js";
import { routeDetachedDaemonDiagnostics } from "../src/cli/subprocess-launch.js";
import { DaemonClient, type DaemonHello } from "../src/modes/daemon/daemon-client.js";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";
import { readNativeJournal } from "../src/modes/daemon/diagnostic-native-journal.js";

it.skipIf(process.platform !== "linux")("rejects invalid journal routing before launching a daemon", () => {
	expect(() =>
		routeDetachedDaemonDiagnostics(
			{ command: process.execPath, args: [] },
			{ PRIME_AGENT_DIAGNOSTICS: "native", PRIME_AGENT_DIAGNOSTIC_JOURNAL_IDENTIFIER: "bad\nidentifier" },
		),
	).toThrow(/Invalid native diagnostic journal/);
});

it.skipIf(process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_TESTS !== "1")(
	"records a real cold daemon launch and later public requests after its launcher exits",
	async () => {
		const root = await mkdtemp(join(tmpdir(), "diagnostic-native-cold-"));
		const socketPath = join(root, "daemon.sock");
		const identifier = `prime-cold-test-${randomUUID()}`;
		const sinceMs = Date.now() - 1000;
		const loader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
		const fixture = fileURLToPath(new URL("./fixtures/diagnostic-native-cold-launch.ts", import.meta.url));
		const launcher = spawn(process.execPath, ["--import", loader, fixture, root], {
			cwd: root,
			stdio: ["ignore", "pipe", "pipe"],
			env: {
				PATH: `${dirname(process.execPath)}:/usr/sbin:/usr/bin:/bin`,
				HOME: root,
				LANG: "C.UTF-8",
				PRIME_AGENT_CODING_AGENT_DIR: join(root, "config"),
				PRIME_AGENT_SESSION_DIR: join(root, "sessions"),
				PRIME_AGENT_DIAGNOSTICS: "native",
				PRIME_AGENT_DIAGNOSTIC_JOURNAL_NAMESPACE: "",
				PRIME_AGENT_DIAGNOSTIC_JOURNAL_IDENTIFIER: identifier,
				PI_OFFLINE: "1",
				PI_SKIP_VERSION_CHECK: "1",
			},
		});
		let stderr = "";
		launcher.stderr.on("data", (chunk: Buffer) => {
			stderr = (stderr + chunk.toString()).slice(-8192);
		});
		launcher.stdout.resume();
		const closed = new Promise<number | null>((resolve, reject) => {
			launcher.once("error", reject);
			launcher.once("close", resolve);
		});
		const timeout = setTimeout(() => launcher.kill("SIGKILL"), 35_000);
		let store: DiagnosticEvidenceStore | undefined;
		const client = new DaemonClient(socketPath);
		try {
			expect(await closed, stderr).toBe(0);
			const launched = JSON.parse(await readFile(join(root, "launched.json"), "utf8")) as {
				launcherPid: number;
				hello: DaemonHello;
			};
			expect(() => process.kill(launched.launcherPid, 0)).toThrow();
			await client.connect(2000);
			const hello = await client.waitForHello(2000);
			expect(hello.supervisorPid).toBe(launched.hello.supervisorPid);
			expect(hello.supervisorPid).not.toBe(launched.launcherPid);
			expect(await client.request({ type: "list" }, 2000)).toMatchObject({ success: true });
			const records = new Map<string, Buffer>();
			const events: Record<string, unknown>[] = [];
			const deadline = Date.now() + 5000;
			while (Date.now() < deadline) {
				for await (const raw of readNativeJournal({ identifier }, { sinceMs }, AbortSignal.timeout(2000))) {
					const row = JSON.parse(raw.toString()) as { __CURSOR: string; MESSAGE: string };
					if (records.has(row.__CURSOR)) continue;
					records.set(row.__CURSOR, raw);
					try {
						const event = JSON.parse(row.MESSAGE) as Record<string, unknown>;
						if (event.schema === "prime-agent.diagnostic.v1") events.push(event);
					} catch {
						// Ordinary daemon output is retained as a raw journal record.
					}
				}
				if (events.some((event) => event.type === "command_completed")) break;
				await delay(50);
			}
			expect(events).toContainEqual(
				expect.objectContaining({ type: "supervisor_ready", producerPid: hello.supervisorPid }),
			);
			expect(events).toContainEqual(
				expect.objectContaining({ type: "command_completed", producerPid: hello.supervisorPid }),
			);
			expect(() => process.kill(hello.supervisorPid!, 0)).not.toThrow();
			store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
			const pipeline = new DiagnosticEvidencePipeline(store);
			await pipeline.ingestJournalBatch(`journal:${identifier}`, [...records.values()]);
			expect((await store.stats()).occurrences).toBe(records.size);
			await writeFile(
				join(root, "journal.jsonl"),
				Buffer.concat([...records.values()].flatMap((raw) => [raw, Buffer.from("\n")])),
			);
		} finally {
			clearTimeout(timeout);
			client.close();
			await shutdownDaemonAndWait(socketPath).catch(() => false);
			if (launcher.exitCode === null && launcher.signalCode === null) launcher.kill("SIGKILL");
			await store?.close();
			if (process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_KEEP_EVIDENCE !== "1")
				await rm(root, { recursive: true, force: true });
		}
	},
	45_000,
);
