import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { open } from "node:fs/promises";
import { machine, release } from "node:os";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import type { CausalPlatformIdentity } from "./diagnostic-causal-classifier.js";
import type { DiagnosticEvidenceStore } from "./diagnostic-evidence-store.js";

const SOURCE_PREFIX = "internal:causal-platform-v1:";
const execute = promisify(execFile);
const decompress = promisify(gunzip);

async function boundedRead(path: string, maximum: number): Promise<Buffer> {
	const file = await open(path, "r");
	try {
		const bytes = Buffer.alloc(maximum + 1);
		let used = 0;
		while (used < bytes.length) {
			const read = await file.read(bytes, used, bytes.length - used, null);
			if (!read.bytesRead) break;
			used += read.bytesRead;
		}
		if (used > maximum) throw new Error("causal_platform_read_limit");
		return bytes.subarray(0, used);
	} finally {
		await file.close();
	}
}

export function inspectOomContextContract(input: {
	machine: string;
	kernelRelease: string;
	kernelConfig: Buffer;
}): CausalPlatformIdentity["oomContextContract"] {
	if (input.kernelConfig.byteLength > 2 * 1024 * 1024) return undefined;
	const lines = new Set(input.kernelConfig.toString("utf8").split("\n"));
	if (
		input.machine !== "x86_64" ||
		!input.kernelRelease.trim() ||
		input.kernelRelease.length > 256 ||
		!lines.has("CONFIG_PREEMPT_COUNT=y") ||
		!lines.has("# CONFIG_PREEMPT_RT is not set")
	)
		return undefined;
	return {
		verified: true,
		kind: "x86_non_rt_preempt_count",
		machine: input.machine,
		kernelRelease: input.kernelRelease,
		kernelConfigSha256: createHash("sha256").update(input.kernelConfig).digest("hex"),
		preemptCount: true,
		preemptRt: false,
	};
}

/** Read the running kernel's own configuration; caller-supplied flags are not verification. */
export async function captureCausalPlatform(): Promise<{
	platform: CausalPlatformIdentity;
	rawKernelConfig?: Buffer;
	limitations: string[];
}> {
	if (process.platform !== "linux") throw new Error("causal_platform_requires_linux");
	const boot = (await boundedRead("/proc/sys/kernel/random/boot_id", 64)).toString().trim().replaceAll("-", "");
	if (!/^[a-f0-9]{32}$/.test(boot)) throw new Error("causal_platform_boot_unavailable");
	const clock = await execute("/usr/bin/getconf", ["CLK_TCK"], { timeout: 1000, maxBuffer: 1024 });
	const ticks = Number(clock.stdout.trim());
	if (!Number.isSafeInteger(ticks) || ticks < 1 || ticks > 1_000_000)
		throw new Error("causal_platform_clock_unavailable");
	const limitations: string[] = [];
	let offset = "unverified";
	try {
		const raw = (await boundedRead("/proc/self/timens_offsets", 1024)).toString();
		const match = /^boottime\s+(-?\d{1,20})\s+(-?\d{1,10})\s*$/m.exec(raw);
		if (match) offset = String(BigInt(match[1]) * 1_000_000_000n + BigInt(match[2]));
	} catch {
		limitations.push("reader_time_namespace_unavailable");
	}
	if (offset !== "0") limitations.push("reader_time_namespace_not_verified_zero");
	let rawKernelConfig: Buffer | undefined;
	let contract: CausalPlatformIdentity["oomContextContract"];
	try {
		rawKernelConfig = await boundedRead("/proc/config.gz", 512 * 1024);
		const decoded = await decompress(rawKernelConfig, { maxOutputLength: 2 * 1024 * 1024 });
		contract = inspectOomContextContract({ machine: machine(), kernelRelease: release(), kernelConfig: decoded });
	} catch {
		limitations.push("running_kernel_configuration_unavailable");
	}
	if (!contract) limitations.push("oom_context_contract_unverified");
	const after = (await boundedRead("/proc/sys/kernel/random/boot_id", 64)).toString().trim().replaceAll("-", "");
	if (after !== boot) throw new Error("causal_platform_boot_changed");
	return {
		platform: {
			bootId: boot,
			clockTicksPerSecond: ticks,
			procReaderBoottimeOffsetNs: offset,
			...(contract ? { oomContextContract: contract } : {}),
		},
		rawKernelConfig,
		limitations,
	};
}

/** Immutable observations plus the latest verified contract for each boot. */
export async function recordCausalPlatform(
	store: DiagnosticEvidenceStore,
	captured: Awaited<ReturnType<typeof captureCausalPlatform>>,
): Promise<void> {
	const source = `${SOURCE_PREFIX}${captured.platform.bootId}`;
	const receipt = Buffer.from(JSON.stringify({ platform: captured.platform, limitations: captured.limitations }));
	const id = randomUUID();
	const previous = await store.getCursor(source);
	if (previous !== null) {
		if (previous === receipt.toString()) return;
		const old = (JSON.parse(previous) as { platform: CausalPlatformIdentity }).platform;
		if (
			old.oomContextContract &&
			captured.platform.oomContextContract &&
			old.oomContextContract.kernelConfigSha256 !== captured.platform.oomContextContract.kernelConfigSha256
		)
			throw new Error("causal_platform_contract_conflict_within_boot");
		// A transient inability to re-read a kernel file does not erase a prior
		// verified contract for this same boot. The new observation stays explicit.
		if (old.oomContextContract && !captured.platform.oomContextContract)
			captured = { ...captured, platform: { ...captured.platform, oomContextContract: old.oomContextContract } };
	}
	const currentReceipt = JSON.stringify({ platform: captured.platform, limitations: captured.limitations });
	if (previous === currentReceipt) return;
	const wallTimeMs = Date.now();
	await store.ingest({
		batchId: id,
		source,
		expectedCursor: previous,
		cursor: currentReceipt,
		occurrences: [
			{ id, kind: "platform.contract", wallTimeMs, payload: receipt },
			...(captured.rawKernelConfig
				? [{ id: `${id}:config`, kind: "platform.kernel-config.gz", wallTimeMs, payload: captured.rawKernelConfig }]
				: []),
		],
	});
}

export async function loadCausalPlatform(
	store: DiagnosticEvidenceStore,
	bootId: string,
): Promise<CausalPlatformIdentity | undefined> {
	if (!/^[a-f0-9]{32}$/.test(bootId)) return undefined;
	const receipt = await store.getCursor(`${SOURCE_PREFIX}${bootId}`);
	return receipt === null ? undefined : (JSON.parse(receipt) as { platform: CausalPlatformIdentity }).platform;
}
