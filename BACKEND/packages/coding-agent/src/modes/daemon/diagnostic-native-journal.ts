import { spawn } from "node:child_process";

export interface NativeJournalOptions {
	namespace?: string;
	identifier?: string;
	userUnit?: string;
	journalctlPath?: string;
}

function selector(options: NativeJournalOptions): string[] {
	const args = ["--no-pager", "--quiet", "--all"];
	if (options.namespace) args.push(`--namespace=${options.namespace}`);
	if (options.identifier) args.push(`--identifier=${options.identifier}`);
	if (options.userUnit) args.push(`--user-unit=${options.userUnit}`);
	return args;
}

function timestamp(value: number): string {
	if (!Number.isSafeInteger(value) || value < 0) throw new Error("journal_time_invalid");
	return `@${(value / 1000).toFixed(3)}`;
}

/** Only the journalctl reader is owned here; cancellation never signals the producer. */
async function* command(options: NativeJournalOptions, args: string[], signal: AbortSignal): AsyncGenerator<Buffer> {
	signal.throwIfAborted();
	const child = spawn(options.journalctlPath ?? "/usr/bin/journalctl", [...selector(options), ...args], {
		stdio: ["ignore", "pipe", "pipe"],
		signal,
		killSignal: "SIGTERM",
		env: { PATH: "/usr/sbin:/usr/bin:/bin", LANG: "C.UTF-8", SYSTEMD_COLORS: "0" },
	});
	let stderr = "";
	let failure: Error | undefined;
	child.stderr.on("data", (chunk: Buffer) => {
		if (stderr.length < 8192) stderr += chunk.toString("utf8").slice(0, 8192 - stderr.length);
	});
	child.on("error", (error) => {
		failure = error;
	});
	const exited = new Promise<void>((resolve) => child.once("close", () => resolve()));
	let killTimer: ReturnType<typeof setTimeout> | undefined;
	const terminate = () => {
		if (child.exitCode !== null || child.signalCode !== null) return;
		child.kill("SIGTERM");
		killTimer ??= setTimeout(() => child.kill("SIGKILL"), 1000);
		killTimer.unref();
	};
	signal.addEventListener("abort", terminate, { once: true });
	if (signal.aborted) terminate();
	try {
		for await (const chunk of child.stdout) {
			signal.throwIfAborted();
			yield chunk as Buffer;
		}
		await exited;
		signal.throwIfAborted();
		if (failure) throw failure;
		if (child.exitCode !== 0)
			throw new Error(`journal_provider_unavailable: ${child.exitCode ?? child.signalCode}: ${stderr.trim()}`);
	} finally {
		terminate();
		await exited;
		signal.removeEventListener("abort", terminate);
		clearTimeout(killTimer);
	}
}

async function* lines(chunks: AsyncIterable<Buffer>): AsyncGenerator<Buffer> {
	let partial = Buffer.alloc(0);
	for await (const chunk of chunks) {
		let offset = 0;
		for (;;) {
			const end = chunk.indexOf(10, offset);
			const piece = chunk.subarray(offset, end < 0 ? chunk.length : end);
			if (partial.length + piece.length > 1024 * 1024) throw new Error("journal_entry_too_large");
			partial = partial.length ? Buffer.concat([partial, piece]) : Buffer.from(piece);
			if (end < 0) break;
			if (partial.length) yield partial;
			partial = Buffer.alloc(0);
			offset = end + 1;
		}
	}
	if (partial.length) throw new Error("journal_entry_incomplete");
}

export async function verifyNativeJournalCursor(
	options: NativeJournalOptions,
	cursor: string,
	signal: AbortSignal,
): Promise<void> {
	// journalctl may seek to a nearby surviving entry when a cursor was vacuumed.
	// Verify equality instead of equating a successful seek with continuous coverage.
	let matched = false;
	for await (const line of lines(command(options, ["--output=json", `--cursor=${cursor}`, "--lines=1"], signal))) {
		const entry = JSON.parse(line.toString("utf8")) as { __CURSOR?: unknown };
		matched = entry.__CURSOR === cursor;
		break;
	}
	if (!matched) throw new Error("journal_cursor_lost");
}

export async function* readNativeJournal(
	options: NativeJournalOptions,
	window: { sinceMs: number; untilMs?: number; afterCursor?: string; follow?: boolean },
	signal: AbortSignal,
): AsyncGenerator<Buffer> {
	if (window.afterCursor) await verifyNativeJournalCursor(options, window.afterCursor, signal);
	const args = ["--output=json", "--lines=all", `--since=${timestamp(window.sinceMs)}`];
	if (window.untilMs !== undefined) args.push(`--until=${timestamp(window.untilMs)}`);
	if (window.afterCursor) args.push(`--after-cursor=${window.afterCursor}`);
	if (window.follow) args.push("--follow");
	yield* lines(command(options, args, signal));
}

export function exportNativeJournal(
	options: NativeJournalOptions,
	window: { sinceMs: number; untilMs: number },
	signal: AbortSignal,
): AsyncIterable<Uint8Array> {
	return command(
		options,
		["--output=export", `--since=${timestamp(window.sinceMs)}`, `--until=${timestamp(window.untilMs)}`],
		signal,
	);
}
