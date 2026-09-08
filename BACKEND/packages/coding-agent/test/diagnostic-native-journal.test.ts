import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { expect, it } from "vitest";
import { DiagnosticArtifactOperations } from "../src/modes/daemon/diagnostic-evidence-artifacts.js";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";
import {
	exportNativeJournal,
	readNativeJournal,
	verifyNativeJournalCursor,
} from "../src/modes/daemon/diagnostic-native-journal.js";

const enabled = process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_TESTS === "1";
it.skipIf(process.platform !== "linux")("bounds shutdown when its owned journal reader ignores SIGTERM", async () => {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-reader-stop-"));
	const executable = join(root, "reader");
	const pidFile = join(root, "reader.pid");
	await writeFile(executable, `#!${process.execPath}\nconst fs = require('node:fs');\nprocess.on('SIGTERM', () => {});\nfs.writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));\nprocess.stdout.write('{}\\n');\nsetInterval(() => {}, 1000);\n`);
	await chmod(executable, 0o700);
	const stop = new AbortController();
	const iterator = readNativeJournal({ journalctlPath: executable }, { sinceMs: Date.now(), follow: true }, stop.signal);
	try {
		expect((await iterator.next()).done).toBe(false);
		const pid = Number(await readFile(pidFile, "utf8"));
		const started = performance.now();
		stop.abort();
		await expect(iterator.next()).rejects.toThrow();
		expect(performance.now() - started).toBeLessThan(2000);
		expect(() => process.kill(pid, 0)).toThrow();
	} finally {
		stop.abort();
		await iterator.return(undefined).catch(() => {});
		await rm(root, { recursive: true, force: true });
	}
}, 5000);
it.skipIf(!enabled)(
	"captures native journald bytes and publishes an incident without terminating the producer",
	async () => {
		if (process.platform !== "linux") throw new Error("Native journal acceptance requires Linux");
		const root = await mkdtemp(join(tmpdir(), "diagnostic-journal-"));
		const store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
		const identifier = `prime-evidence-test-${randomUUID()}`;
		const options = { identifier };
		const started = Date.now() - 1000;
		const producer = spawn("/usr/bin/systemd-cat", ["--identifier", identifier, "/usr/bin/cat"], {
			stdio: ["pipe", "ignore", "pipe"],
		});
		const closed = new Promise<void>((resolve) => producer.once("close", () => resolve()));
		try {
			const event = {
				schema: "prime-agent.diagnostic.v1",
				type: "kernel_channel_fault",
				channel: "shell",
				kernelInstanceId: "native-publication-fixture",
				requestMsgId: "original",
				reason: "receive_failed",
			};
			producer.stdin.write(`${JSON.stringify(event)}\n`);
			let entries: Buffer[] = [];
			for (let attempt = 0; attempt < 30; attempt++) {
				entries = [];
				for await (const raw of readNativeJournal(options, { sinceMs: started }, AbortSignal.timeout(2000)))
					entries.push(raw);
				if (entries.length > 0) break;
				await delay(100);
			}
			expect(entries).toHaveLength(1);
			const pipeline = new DiagnosticEvidencePipeline(store);
			const receipt = await pipeline.ingestJournal("test-journal", entries[0]!);
			await verifyNativeJournalCursor(options, receipt.cursor, AbortSignal.timeout(2000));
			expect(await pipeline.publishPending()).toBe(1);
			const [incident] = await store.listIncidents();
			const operations = await DiagnosticArtifactOperations.open({
				root: join(root, "artifacts"),
				store,
				exportArtifact: (_operation, signal) =>
					exportNativeJournal(
						options,
						{ sinceMs: incident!.windowStartMs, untilMs: incident!.triggerTimeMs + 1000 },
						signal,
					),
			});
			expect((await operations.reconcile()).completed).toBe(1);
			const [artifact] = await store.listArtifacts(incident!.id);
			const native = await readFile(join(root, "artifacts", artifact!.path), "utf8");
			expect(native).toContain(`__CURSOR=${receipt.cursor}\n`);
			expect(native).toContain(`MESSAGE=${JSON.stringify(event)}\n`);
			expect(producer.exitCode).toBeNull();
			process.kill(producer.pid!, 0);
			// Missing cursor is explicit uncertainty, never continuous coverage.
			await expect(
				verifyNativeJournalCursor(
					options,
					"s=00000000000000000000000000000000;i=1;b=00000000000000000000000000000000;m=1;t=1;x=1",
					AbortSignal.timeout(2000),
				),
			).rejects.toThrow(/journal_cursor_lost|journal_provider_unavailable/);
		} finally {
			producer.stdin.end();
			producer.kill("SIGTERM");
			await closed;
			await store.close();
			await rm(root, { recursive: true, force: true });
		}
	},
	15_000,
);
