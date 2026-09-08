import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { type BigIntStats, constants } from "node:fs";
import { open } from "node:fs/promises";

export interface NativeAtopOptions {
	sourcePath: string;
	atopPath?: string;
	maxArtifactBytes?: number;
	/** Bounds stock atop's decompression, independently of the recorder heap. */
	maxAddressSpaceBytes?: number;
	onComplete?: (receipt: NativeAtopReceipt) => void | Promise<void>;
}

interface SourceStat {
	device: string;
	inode: string;
	bytes: number;
	mtimeMs: number;
	ctimeMs: number;
}

export interface NativeAtopReceipt {
	format: "atop-native-reencoded";
	providerExitCode: 0 | 9;
	bytes: number;
	sha256: string;
	source: { path: string; before: SourceStat; after: SourceStat };
	coverage: {
		requested: { sinceMs: number; untilMs: number };
		selected: { sinceMs: number; untilMs: number };
		samples: number;
		firstSampleMs?: number;
		lastSampleMs?: number;
		maxIntervalMs: number;
		gaps: { sinceMs: number; untilMs: number }[];
		limitations: string[];
	};
}

function sourceStat(stat: BigIntStats): SourceStat {
	if (stat.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("atop_source_size_unavailable");
	return {
		device: String(stat.dev),
		inode: String(stat.ino),
		bytes: Number(stat.size),
		mtimeMs: Number(stat.mtimeMs),
		ctimeMs: Number(stat.ctimeMs),
	};
}

function timestamp(ms: number): string {
	if (!Number.isSafeInteger(ms) || ms < 86_400_000 || ms > 253_402_300_799_000) throw new Error("atop_window_invalid");
	return new Date(ms).toISOString().replace(/[-:T]/g, "").slice(0, 14);
}

/** Stock atop selects and re-encodes samples; no raw binary layout is interpreted here. */
export async function* exportNativeAtopWindow(
	options: NativeAtopOptions,
	window: { sinceMs: number; untilMs: number },
	requestSignal: AbortSignal,
): AsyncGenerator<Buffer, NativeAtopReceipt> {
	const signal = AbortSignal.any([requestSignal, AbortSignal.timeout(60_000)]);
	signal.throwIfAborted();
	if (window.untilMs < window.sinceMs || window.untilMs - window.sinceMs > 3_600_000)
		throw new Error("atop_window_invalid");
	const selected = {
		sinceMs: Math.floor(window.sinceMs / 1000) * 1000,
		untilMs: Math.ceil(window.untilMs / 1000) * 1000,
	};
	const begin = timestamp(selected.sinceMs);
	const end = timestamp(selected.untilMs);
	const maxBytes = options.maxArtifactBytes ?? 256 * 1024 * 1024;
	const maxAddressSpace = options.maxAddressSpaceBytes ?? 256 * 1024 * 1024;
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || !Number.isSafeInteger(maxAddressSpace) || maxAddressSpace < 1)
		throw new Error("atop_budget_invalid");
	const source = await open(options.sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
	try {
		const initial = await source.stat({ bigint: true });
		if (!initial.isFile()) throw new Error("atop_source_not_regular");
		const coverage: NativeAtopReceipt["coverage"] = {
			requested: { ...window },
			selected,
			samples: 0,
			maxIntervalMs: 0,
			gaps: [],
			limitations: [
				"sampled_metrics_are_not_continuous_causal_evidence",
				"unlocked_source_may_have_an_incomplete_trailing_sample",
			],
		};
		let coveredThrough = selected.sinceMs;
		let lastSample = -1;
		const gap = (sinceMs: number, untilMs: number) => {
			if (untilMs <= sinceMs) return;
			if (coverage.gaps.length < 128) coverage.gaps.push({ sinceMs, untilMs });
			else if (!coverage.limitations.includes("gap_detail_limit")) coverage.limitations.push("gap_detail_limit");
		};
		// Node's child stdio pipes are sockets. This constant bridge supplies the real
		// pipe that stock atop can reopen, while pipefail preserves either exit failure.
		const child = spawn(
			"/usr/bin/bash",
			[
				"-o",
				"pipefail",
				"-c",
				'"$@" 3>&1 1>&2 | /usr/bin/cat',
				"--",
				"/usr/bin/prlimit",
				`--as=${maxAddressSpace}`,
				"--",
				options.atopPath ?? "/usr/bin/atop",
				"-r",
				"/proc/self/fd/4",
				"-b",
				begin,
				"-e",
				end,
				"-JCPU",
				"-w",
				"/proc/self/fd/3",
			],
			{
				stdio: ["ignore", "pipe", "pipe", "ignore", source.fd],
				detached: true,
				env: { PATH: "/usr/sbin:/usr/bin:/bin", LANG: "C.UTF-8", TZ: "UTC", HOME: "/nonexistent" },
			},
		);
		let spawnError: Error | undefined;
		child.on("error", (error) => {
			spawnError = error;
		});
		let closed = false;
		const exited = new Promise<void>((resolve) =>
			child.once("close", () => {
				closed = true;
				resolve();
			}),
		);
		let killTimer: ReturnType<typeof setTimeout> | undefined;
		const killGroup = (name: NodeJS.Signals) => {
			if (!child.pid) return;
			try {
				process.kill(-child.pid, name);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
			}
		};
		const terminate = () => {
			if (closed) return;
			killGroup("SIGTERM");
			killTimer ??= setTimeout(() => killGroup("SIGKILL"), 1000);
			killTimer.unref();
		};
		signal.addEventListener("abort", terminate, { once: true });
		if (signal.aborted) terminate();
		let parseError: Error | undefined;
		let diagnostic = "";
		let trailingIncomplete = false;
		const readMetadata = (async () => {
			let partial = "";
			for await (const chunk of child.stderr!) {
				partial += (chunk as Buffer).toString("utf8");
				for (;;) {
					const newline = partial.indexOf("\n");
					if (newline < 0) break;
					const line = partial.slice(0, newline);
					partial = partial.slice(newline + 1);
					if (line.length > 128 * 1024) throw new Error("atop_metadata_line_limit");
					if (!line.startsWith("{")) {
						if (line.trim() === "raw file is incomplete!") trailingIncomplete = true;
						diagnostic = `${diagnostic}${line}\n`.slice(-4096);
						continue;
					}
					const sample = JSON.parse(line) as { timestamp?: unknown; elapsed?: unknown; CPU?: unknown };
					if (
						typeof sample.timestamp !== "number" ||
						typeof sample.elapsed !== "number" ||
						!sample.CPU ||
						!Number.isSafeInteger(sample.timestamp) ||
						!Number.isSafeInteger(sample.elapsed) ||
						sample.elapsed < 0
					)
						throw new Error("atop_sample_metadata_invalid");
					const at = sample.timestamp * 1000;
					const interval = sample.elapsed * 1000;
					if (at < selected.sinceMs || at > selected.untilMs || at < lastSample || ++coverage.samples > 10_000)
						throw new Error("atop_sample_order_or_limit");
					gap(coveredThrough, Math.max(selected.sinceMs, at - interval));
					coveredThrough = Math.max(coveredThrough, at);
					coverage.firstSampleMs ??= at;
					coverage.lastSampleMs = at;
					coverage.maxIntervalMs = Math.max(coverage.maxIntervalMs, interval);
					lastSample = at;
				}
				if (partial.length > 128 * 1024) throw new Error("atop_metadata_line_limit");
			}
			if (partial.trim()) throw new Error("atop_metadata_incomplete");
		})().catch((error: unknown) => {
			parseError = error instanceof Error ? error : new Error(String(error));
			terminate();
		});
		const hash = createHash("sha256");
		let bytes = 0;
		try {
			for await (const chunk of child.stdout!) {
				signal.throwIfAborted();
				const buffer = chunk as Buffer;
				if (buffer.byteLength > maxBytes - bytes) throw new Error("atop_artifact_budget");
				bytes += buffer.byteLength;
				hash.update(buffer);
				yield buffer;
			}
			await exited;
			await readMetadata;
			signal.throwIfAborted();
			if (spawnError) throw spawnError;
			if (parseError) throw parseError;
			if (child.exitCode !== 0 && !(child.exitCode === 9 && trailingIncomplete))
				throw new Error(`atop_provider_failed: ${child.exitCode ?? child.signalCode}: ${diagnostic}`);
			if (!bytes || !coverage.samples) throw new Error("atop_no_samples");
			if (trailingIncomplete) coverage.limitations.push("source_trailing_sample_incomplete");
			gap(coveredThrough, selected.untilMs);
			const final = await source.stat({ bigint: true });
			if (initial.size !== final.size || initial.mtimeMs !== final.mtimeMs || initial.ctimeMs !== final.ctimeMs)
				coverage.limitations.push("source_changed_during_export");
			const receipt: NativeAtopReceipt = {
				format: "atop-native-reencoded",
				providerExitCode: child.exitCode as 0 | 9,
				bytes,
				sha256: hash.digest("hex"),
				source: { path: options.sourcePath, before: sourceStat(initial), after: sourceStat(final) },
				coverage,
			};
			await options.onComplete?.(receipt);
			return receipt;
		} finally {
			terminate();
			await exited;
			await readMetadata;
			clearTimeout(killTimer);
			signal.removeEventListener("abort", terminate);
		}
	} finally {
		await source.close();
	}
}
