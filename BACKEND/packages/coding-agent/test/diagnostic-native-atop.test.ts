import { spawn } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { expect, it } from "vitest";
import { exportNativeAtopWindow, type NativeAtopReceipt } from "../src/modes/daemon/diagnostic-native-atop.js";

const native = process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_TESTS === "1";

async function collect(
	iterator: AsyncGenerator<Buffer, NativeAtopReceipt>,
): Promise<{ bytes: Buffer; receipt: NativeAtopReceipt }> {
	const chunks: Buffer[] = [];
	for (;;) {
		const next = await iterator.next();
		if (next.done) return { bytes: Buffer.concat(chunks), receipt: next.value };
		chunks.push(next.value);
	}
}

async function fixture(code: string) {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-atop-"));
	const executable = join(root, "atop");
	await writeFile(executable, `#!${process.execPath}\n${code}`);
	await chmod(executable, 0o700);
	const source = join(root, "source.raw");
	await writeFile(source, "source prefix");
	return { root, executable, source };
}

it.skipIf(process.platform !== "linux")(
	"keeps a pinned source descriptor and reports actual sample coverage and append uncertainty",
	async () => {
		const f = await fixture(`
const fs = require('node:fs');
const args = process.argv.slice(2);
const source = args[args.indexOf('-r') + 1];
const output = args[args.indexOf('-w') + 1];
if (fs.readFileSync(source, 'utf8') !== 'source prefix') process.exit(4);
fs.appendFileSync(source, ' appended');
fs.writeFileSync(output, 'native raw');
process.stdout.write('discarded screen output\\n');
process.stdout.write(JSON.stringify({timestamp: 1788764395, elapsed: 1, CPU: {}}) + '\\n');
process.stdout.write(JSON.stringify({timestamp: 1788764398, elapsed: 1, CPU: {}}) + '\\n');
`);
		try {
			const result = await collect(
				exportNativeAtopWindow(
					{ sourcePath: f.source, atopPath: f.executable, maxAddressSpaceBytes: 2 * 1024 ** 3 },
					{ sinceMs: 1788764394000, untilMs: 1788764400000 },
					AbortSignal.timeout(5000),
				),
			);
			expect(result.bytes.toString()).toBe("native raw");
			expect(result.receipt.bytes).toBe(10);
			expect(result.receipt.sha256).toMatch(/^[a-f0-9]{64}$/);
			expect(result.receipt.source.after.bytes).toBeGreaterThan(result.receipt.source.before.bytes);
			expect(result.receipt.coverage.samples).toBe(2);
			expect(result.receipt.coverage.gaps).toContainEqual({ sinceMs: 1788764395000, untilMs: 1788764397000 });
			expect(result.receipt.coverage.limitations).toContain("source_changed_during_export");
			expect(result.receipt.coverage.limitations).toContain("sampled_metrics_are_not_continuous_causal_evidence");
		} finally {
			await rm(f.root, { recursive: true, force: true });
		}
	},
);

it.skipIf(process.platform !== "linux")("preserves provider failure through the stock pipeline", async () => {
	const f = await fixture("process.stderr.write('intentional provider failure\\n'); process.exit(7);");
	try {
		await expect(
			collect(
				exportNativeAtopWindow(
					{ sourcePath: f.source, atopPath: f.executable, maxAddressSpaceBytes: 2 * 1024 ** 3 },
					{ sinceMs: 1788764394000, untilMs: 1788764400000 },
					AbortSignal.timeout(5000),
				),
			),
		).rejects.toThrow(/atop_provider_failed: 7/);
	} finally {
		await rm(f.root, { recursive: true, force: true });
	}
});

it.skipIf(process.platform !== "linux")(
	"cancels only its owned process group even when the provider ignores SIGTERM",
	async () => {
		const f = await fixture(
			"const fs=require('node:fs'); process.on('SIGTERM',()=>{}); fs.writeFileSync(process.argv[process.argv.indexOf('-w')+1], String(process.pid)); setInterval(()=>{},1000);",
		);
		const stop = new AbortController();
		const iterator = exportNativeAtopWindow(
			{ sourcePath: f.source, atopPath: f.executable, maxAddressSpaceBytes: 2 * 1024 ** 3 },
			{ sinceMs: 1788764394000, untilMs: 1788764400000 },
			stop.signal,
		);
		try {
			const first = await iterator.next();
			if (first.done) throw new Error("fixture did not run");
			const pid = Number(first.value.toString());
			const started = performance.now();
			stop.abort();
			await expect(iterator.next()).rejects.toThrow();
			expect(performance.now() - started).toBeLessThan(2000);
			const remaining = await readFile(`/proc/${pid}/stat`, "utf8").catch((error: NodeJS.ErrnoException) => {
				if (error.code !== "ENOENT") throw error;
				return undefined;
			});
			if (remaining) {
				// An isolated PID namespace may retain an adopted zombie until exit.
				const fields = remaining.slice(remaining.lastIndexOf(")") + 2).split(" ");
				expect(fields[0]).toBe("Z");
				expect(Number(fields[49]) & 0x7f).toBe(9);
			}
			expect(await readFile(f.source, "utf8")).toBe("source prefix");
		} finally {
			stop.abort();
			await iterator.return(undefined as never).catch(() => {});
			await rm(f.root, { recursive: true, force: true });
		}
	},
	5000,
);

it.skipIf(process.platform !== "linux")("refuses source symlinks", async () => {
	const f = await fixture("process.exit(0);");
	try {
		await symlink(f.source, join(f.root, "link"));
		const window = { sinceMs: 1788764394000, untilMs: 1788764400000 };
		await expect(
			collect(exportNativeAtopWindow({ sourcePath: join(f.root, "link") }, window, AbortSignal.timeout(2000))),
		).rejects.toThrow();
	} finally {
		await rm(f.root, { recursive: true, force: true });
	}
});

it.skipIf(process.platform !== "linux")(
	"cancels an owned stderr holder after the bridge parent exits",
	async () => {
		const f = await fixture(`
const fs = require('node:fs');
const {spawn} = require('node:child_process');
const holder = spawn(process.execPath, ['-e', "setInterval(()=>{},1000)"], {stdio:['ignore','ignore','inherit']});
holder.unref();
fs.writeFileSync(process.argv[process.argv.indexOf('-w')+1], JSON.stringify({holder:holder.pid, bridge:process.ppid}));
process.stdout.write(JSON.stringify({timestamp:1788764395,elapsed:1,CPU:{}})+'\\n');
process.exit(0);
`);
		const stop = new AbortController();
		const iterator = exportNativeAtopWindow(
			{ sourcePath: f.source, atopPath: f.executable, maxAddressSpaceBytes: 2 * 1024 ** 3 },
			{ sinceMs: 1788764394000, untilMs: 1788764400000 },
			stop.signal,
		);
		let holder: number | undefined;
		let holderStart: string | undefined;
		let next: Promise<unknown> | undefined;
		try {
			const first = await iterator.next();
			if (first.done) throw new Error("fixture did not run");
			const ids = JSON.parse(first.value.toString()) as { holder: number; bridge: number };
			holder = ids.holder;
			const fields = (await readFile(`/proc/${holder}/stat`, "utf8")).split(") ")[1].split(" ");
			holderStart = fields[19];
			expect(Number(fields[2])).toBe(ids.bridge);
			const deadline = Date.now() + 2000;
			while (
				await readFile(`/proc/${ids.bridge}/stat`, "utf8").then(
					() => true,
					() => false,
				)
			) {
				if (Date.now() > deadline) throw new Error("bridge did not exit");
				await delay(10);
			}
			next = iterator.next().then(
				() => "completed",
				() => "rejected",
			);
			stop.abort();
			expect(await Promise.race([next, delay(1800, "hung", { ref: false })])).toBe("rejected");
		} finally {
			stop.abort();
			if (holder !== undefined) {
				const fields = await readFile(`/proc/${holder}/stat`, "utf8").then(
					(value) => value.split(") ")[1].split(" "),
					() => undefined,
				);
				if (fields?.[19] === holderStart) {
					try {
						process.kill(holder, "SIGKILL");
					} catch {}
				}
			}
			await next;
			await iterator.return(undefined as never).catch(() => {});
			await rm(f.root, { recursive: true, force: true });
		}
	},
	5000,
);

it.skipIf(process.platform !== "linux")(
	"enforces a native output size limit and keeps the producer untouched",
	async () => {
		const f = await fixture(
			"const fs=require('node:fs'); const args=process.argv.slice(2); const fd=fs.openSync(args[args.indexOf('-w')+1], 'w'); for(let i=0;i<20;i++)fs.writeSync(fd, Buffer.alloc(1024));",
		);
		try {
			await expect(
				collect(
					exportNativeAtopWindow(
						{
							sourcePath: f.source,
							atopPath: f.executable,
							maxArtifactBytes: 4096,
							maxAddressSpaceBytes: 2 * 1024 ** 3,
						},
						{ sinceMs: 1788764394000, untilMs: 1788764400000 },
						AbortSignal.timeout(5000),
					),
				),
			).rejects.toThrow(/atop_artifact_budget/);
			expect(await readFile(f.source, "utf8")).toBe("source prefix");
		} finally {
			await rm(f.root, { recursive: true, force: true });
		}
	},
);

it.skipIf(!native)(
	"uses stock atop to export a native time window that stock atop can read",
	async () => {
		const root = await mkdtemp(join(tmpdir(), "diagnostic-atop-native-"));
		const source = join(root, "source.raw");
		const output = join(root, "window.raw");
		const producer = spawn("/usr/bin/atop", ["-w", source, "1", "4"], { stdio: "ignore" });
		try {
			await new Promise<void>((resolve, reject) => {
				producer.once("error", reject);
				producer.once("exit", (code) =>
					code === 0 ? resolve() : reject(new Error(`atop fixture exited ${code}`)),
				);
			});
			const result = await collect(
				exportNativeAtopWindow(
					{ sourcePath: source },
					{ sinceMs: Date.now() - 2000, untilMs: Date.now() + 1000 },
					AbortSignal.timeout(5000),
				),
			);
			expect(result.receipt.coverage.samples).toBeGreaterThan(0);
			expect(result.receipt.coverage.samples).toBeLessThan(4);
			expect(result.receipt.bytes).toBeGreaterThan(512);
			await writeFile(output, result.bytes, { mode: 0o600 });
			const reader = spawn("/usr/bin/atopcat", ["-d", output], { stdio: "ignore" });
			await new Promise<void>((resolve, reject) =>
				reader.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`native read failed ${code}`)))),
			);
			const truncated = join(root, "trailing-incomplete.raw");
			const original = await readFile(source);
			await writeFile(truncated, original.subarray(0, original.length - 1));
			const incomplete = await collect(
				exportNativeAtopWindow(
					{ sourcePath: truncated },
					{ sinceMs: Date.now() - 10_000, untilMs: Date.now() + 1000 },
					AbortSignal.timeout(5000),
				),
			);
			expect(incomplete.receipt.coverage.samples).toBe(3);
			expect(incomplete.receipt.providerExitCode).toBe(9);
			expect(incomplete.receipt.coverage.gaps.length).toBeGreaterThan(0);
			expect(incomplete.receipt.coverage.limitations).toContain("source_trailing_sample_incomplete");
			const repaired = join(root, "available-prefix.raw");
			await writeFile(repaired, incomplete.bytes);
			const prefixReader = spawn("/usr/bin/atopcat", ["-d", repaired], { stdio: "ignore" });
			await new Promise<void>((resolve, reject) =>
				prefixReader.once("exit", (code) =>
					code === 0 ? resolve() : reject(new Error(`partial native read failed ${code}`)),
				),
			);
		} finally {
			if (producer.exitCode === null) producer.kill("SIGTERM");
			await rm(root, { recursive: true, force: true });
		}
	},
	10_000,
);
