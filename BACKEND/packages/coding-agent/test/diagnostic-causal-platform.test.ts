import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { expect, it } from "vitest";
import {
	captureCausalPlatform,
	inspectOomContextContract,
	loadCausalPlatform,
	recordCausalPlatform,
} from "../src/modes/daemon/diagnostic-causal-platform.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";

const config = Buffer.from("CONFIG_PREEMPT_COUNT=y\n# CONFIG_PREEMPT_RT is not set\n");
const input = { machine: "x86_64", kernelRelease: "6.18.test", kernelConfig: config };

it("requires the actual supported architecture and explicit kernel configuration", () => {
	expect(inspectOomContextContract(input)).toMatchObject({
		verified: true,
		kernelConfigSha256: createHash("sha256").update(config).digest("hex"),
	});
	for (const invalid of [
		{ machine: "aarch64" },
		{ kernelRelease: "" },
		{ kernelConfig: Buffer.from("CONFIG_PREEMPT_COUNT=y\nCONFIG_PREEMPT_RT=y\n") },
		{ kernelConfig: Buffer.from("# CONFIG_PREEMPT_RT is not set\n") },
		{ kernelConfig: Buffer.alloc(2 * 1024 * 1024 + 1) },
	])
		expect(inspectOomContextContract({ ...input, ...invalid })).toBeUndefined();
});

it("retains exact configuration and same-boot verified proof across temporary read failure and restart", async () => {
	const root = await mkdtemp(join(tmpdir(), "causal-platform-"));
	let store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
	try {
		const bootId = "a".repeat(32);
		const base = { bootId, clockTicksPerSecond: 100, procReaderBoottimeOffsetNs: "0" };
		const unavailable = { platform: base, limitations: ["running_kernel_configuration_unavailable"] };
		await recordCausalPlatform(store, unavailable);
		expect((await loadCausalPlatform(store, bootId))?.oomContextContract).toBeUndefined();
		const rawKernelConfig = gzipSync(config);
		const verified = {
			platform: { ...base, oomContextContract: inspectOomContextContract(input) },
			rawKernelConfig,
			limitations: [],
		};
		await recordCausalPlatform(store, verified);
		await recordCausalPlatform(store, unavailable);
		await recordCausalPlatform(store, unavailable);
		await recordCausalPlatform(store, verified);
		expect((await loadCausalPlatform(store, bootId))?.oomContextContract).toEqual(
			verified.platform.oomContextContract,
		);
		expect(await loadCausalPlatform(store, "b".repeat(32))).toBeUndefined();
		const rows = (await store.readOccurrences({ limit: 20 })).occurrences;
		const configs = rows.filter((row) => row.kind === "platform.kernel-config.gz");
		expect(configs).toHaveLength(2);
		for (const row of configs) expect(Buffer.from(row.payload)).toEqual(rawKernelConfig);
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path: join(root, "evidence.sqlite") });
		expect(await loadCausalPlatform(store, bootId)).toEqual(verified.platform);
		await expect(
			recordCausalPlatform(store, {
				...verified,
				platform: {
					...verified.platform,
					oomContextContract: { ...verified.platform.oomContextContract!, kernelConfigSha256: "f".repeat(64) },
				},
			}),
		).rejects.toThrow(/conflict_within_boot/);
	} finally {
		await store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it.skipIf(process.env.PRIME_AGENT_NATIVE_DIAGNOSTIC_TESTS !== "1")(
	"captures the running Linux boot, tick resolution and bounded kernel configuration",
	async () => {
		const captured = await captureCausalPlatform();
		expect(captured.platform.bootId).toMatch(/^[a-f0-9]{32}$/);
		expect(captured.platform.clockTicksPerSecond).toBeGreaterThan(0);
		expect(captured.platform.procReaderBoottimeOffsetNs).toBe("0");
		// This admission host promises the scoped OOM hooks; unavailable evidence fails.
		expect(captured.platform.oomContextContract?.verified).toBe(true);
		expect(captured.rawKernelConfig?.byteLength).toBeGreaterThan(0);
		expect(captured.limitations).toEqual([]);
	},
);
