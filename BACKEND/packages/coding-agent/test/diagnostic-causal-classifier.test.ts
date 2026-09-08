import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	type CausalOccurrence,
	type CausalPlatformIdentity,
	type CausalTarget,
	classifyCausalCapture,
} from "../src/modes/daemon/diagnostic-causal-classifier.js";

const bootId = "observed-boot";
const target: CausalTarget = { bootId, initPid: 3130, processStartBoottimeNs: "28478275484975" };
const platform = {
	bootId,
	clockTicksPerSecond: 100,
	procReaderBoottimeOffsetNs: "0",
	appMonotonicToBoottimeOffsetNs: "0",
};
const probe = (id: string, value: Record<string, unknown>, boot = bootId): CausalOccurrence => ({
	id,
	bootId: boot,
	source: "probe",
	payload: JSON.stringify(value),
});
// These four metadata records are from a retained stock-probe capture, unmodified.
const nativeFault = [
	{
		event: "task_identity",
		time_ns: "28478275519564",
		init_pid: 3130,
		init_tid: 3130,
		subject_pid: 12,
		subject_tid: 12,
		pidns_inode: 4026532290,
		start_boottime_ns: "28478275484975",
		process_start_boottime_ns: "28478275484975",
	},
	{
		event: "signal_generate",
		time_ns: "28478276103119",
		context_init_pid: 3130,
		context_init_tid: 3130,
		context_start_boottime_ns: "28478275484975",
		target_init_pid: 3130,
		target_init_tid: 3130,
		target_start_boottime_ns: "28478275484975",
		signal: 11,
		code: 1,
		group: 0,
		result: 0,
		call_time_ns: "0",
	},
	{
		event: "signal_deliver",
		time_ns: "28478276142549",
		pid: 12,
		tid: 12,
		init_pid: 3130,
		init_tid: 3130,
		start_boottime_ns: "28478275484975",
		signal: 11,
		code: 1,
	},
	{
		event: "process_exit",
		time_ns: "28478276174058",
		pid: 12,
		tid: 12,
		init_pid: 3130,
		init_tid: 3130,
		start_boottime_ns: "28478275484975",
		raw_exit_code: 11,
		group_dead: 1,
	},
];
const capture = () => nativeFault.map((value, i) => probe(`p${i}`, value));
it.each([true, false])("uses direct group identity for a final nonleader exit (valid=%s)", (valid) => {
	const rows = nativeFault
		.filter((row) => row.event !== "task_identity")
		.map((row) =>
			row.event === "process_exit"
				? {
						...row,
						init_tid: 3131,
						start_boottime_ns: "28478275500000",
						subject_pid: 12,
						pidns_inode: 4026532290,
						process_start_boottime_ns: valid ? target.processStartBoottimeNs : "28478275484976",
					}
				: row,
		);
	const result = classifyCausalCapture({ target, occurrences: rows.map((row, i) => probe(`direct${i}`, row)) });
	expect(result.status).toBe(valid ? "process_exited" : "unresolved");
	expect(result.cause).toBe(valid ? "native_fault" : "unresolved");
});
const appTarget: CausalTarget = {
	bootId,
	kernelInstanceId: "kernel",
	kernelGeneration: 1,
	pid: 12,
	pidNamespace: "4026532290",
	processStartTicks: "2847827",
};
function app(id: string, fields: Record<string, unknown>): CausalOccurrence {
	return {
		id,
		source: "journal",
		payload: JSON.stringify({
			_BOOT_ID: bootId,
			MESSAGE: JSON.stringify({
				schema: "prime-agent.diagnostic.v1",
				producerId: "producer",
				producerPid: 2,
				producerStartId: "2847633",
				producerPidNamespace: "pid:[4026532290]",
				producerBoottimeOffsetNs: "0",
				ownerPid: 2,
				ownerProcessStartId: "proc:2847633",
				kernelInstanceId: "kernel",
				kernelGeneration: 1,
				kernelPid: 12,
				kernelProcessStartId: "proc:2847827",
				monotonicNs: "28478276100000",
				...fields,
			}),
		}),
	};
}
function signalCapture(kind = 1, targetArgument = 12): CausalOccurrence[] {
	const sender = { context_init_pid: 999, context_init_tid: 999, context_start_boottime_ns: "28000000000000" };
	return [
		probe("identity", nativeFault[0]),
		probe("call", {
			event: "signal_call",
			time_ns: "28478276100000",
			...sender,
			kind,
			target_argument: targetArgument,
			signal: 15,
			group_argument: 0,
		}),
		probe("generate", {
			event: "signal_generate",
			time_ns: "28478276103119",
			...sender,
			target_init_pid: 3130,
			target_init_tid: 3130,
			target_start_boottime_ns: target.processStartBoottimeNs,
			signal: 15,
			code: 0,
			group: 1,
			result: 0,
			call_time_ns: "28478276100000",
		}),
		probe("return", {
			event: "signal_return",
			time_ns: "28478276104000",
			...sender,
			call_time_ns: "28478276100000",
			kind,
			result: 0,
		}),
		probe("deliver", { ...nativeFault[2], signal: 15, code: 0 }),
		probe("exit", { ...nativeFault[3], raw_exit_code: 15 }),
	];
}

// Unmodified metadata from a real IPython fatal-group exit capture.
const fatalGroupMetadata = [
	{
		event: "task_identity",
		time_ns: "30750049130610",
		init_pid: 25310,
		init_tid: 25310,
		subject_pid: 48,
		subject_tid: 48,
		pidns_inode: 4026532290,
		start_boottime_ns: "30750049098220",
		process_start_boottime_ns: "30750049098220",
	},
	{
		event: "task_identity",
		time_ns: "30750470854643",
		init_pid: 25310,
		init_tid: 25326,
		subject_pid: 48,
		subject_tid: 63,
		pidns_inode: 4026532290,
		start_boottime_ns: "30750470834203",
		process_start_boottime_ns: "30750049098220",
	},
	{
		event: "signal_call",
		time_ns: "30750549872075",
		context_pid: 1,
		context_tid: 1,
		context_init_pid: 25258,
		context_init_tid: 25258,
		context_start_boottime_ns: "30747275134801",
		kind: 1,
		target_argument: 48,
		signal: 15,
		group_argument: 0,
	},
	{
		event: "signal_generate",
		time_ns: "30750550036544",
		context_init_pid: 25258,
		context_init_tid: 25258,
		context_start_boottime_ns: "30747275134801",
		target_init_pid: 25310,
		target_init_tid: 25310,
		target_start_boottime_ns: "30750049098220",
		signal: 15,
		code: 0,
		group: 1,
		result: 0,
		call_time_ns: "30750549872075",
	},
	{
		event: "signal_deliver",
		time_ns: "30750550039204",
		pid: 48,
		tid: 48,
		init_pid: 25310,
		init_tid: 25310,
		start_boottime_ns: "30750049098220",
		signal: 9,
		code: 0,
	},
	{
		event: "signal_return",
		time_ns: "30750550051454",
		call_time_ns: "30750549872075",
		context_init_tid: 25258,
		context_start_boottime_ns: "30747275134801",
		kind: 1,
		result: 0,
	},
	{
		event: "signal_deliver",
		time_ns: "30750550079039",
		pid: 48,
		tid: 63,
		init_pid: 25310,
		init_tid: 25326,
		start_boottime_ns: "30750470834203",
		signal: 9,
		code: 0,
	},
	{
		event: "process_exit",
		time_ns: "30750550087954",
		pid: 48,
		tid: 48,
		init_pid: 25310,
		init_tid: 25310,
		start_boottime_ns: "30750049098220",
		raw_exit_code: 15,
		group_dead: 0,
	},
	{
		event: "process_exit",
		time_ns: "30750550100139",
		pid: 48,
		tid: 63,
		init_pid: 25310,
		init_tid: 25326,
		start_boottime_ns: "30750470834203",
		raw_exit_code: 15,
		group_dead: 1,
	},
];
const fatalGroupTarget: CausalTarget = { bootId, initPid: 25310, processStartBoottimeNs: "30750049098220" };
const fatalGroupCapture = () => fatalGroupMetadata.map((row, i) => probe(`group:${i}`, row));

const oomTarget: CausalTarget = { bootId, initPid: 4219, processStartBoottimeNs: "31277765690642" };
const oomPlatform = {
	...platform,
	oomContextContract: {
		verified: true,
		kind: "x86_non_rt_preempt_count",
		machine: "x86_64",
		kernelRelease: "6.18.33.2-microsoft-standard-WSL2",
		kernelConfigSha256: "11d9efe4a3a081ca548551f91091bd0b18c35ad391650b85eacc3d48230f94d9",
		preemptCount: true,
		preemptRt: false,
	},
};
// Raw metadata from the isolated allocator capture; expected causes are separate.
const oomMetadata = [
	{
		event: "task_identity",
		time_ns: "31280006046024",
		init_pid: 4219,
		init_tid: 4219,
		subject_pid: 2,
		subject_tid: 2,
		pidns_inode: 4026532289,
		start_boottime_ns: "31277765690642",
		process_start_boottime_ns: "31277765690642",
	},
	{
		event: "oom_kill_enter",
		time_ns: "31280084829903",
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		selected_init_pid: 4219,
		selected_process_start_boottime_ns: "31277765690642",
		scope: "selected_thread_group",
		context_contract: "x86_non_rt_preempt_count",
	},
	{
		event: "oom_signal_enter",
		time_ns: "31280084885542",
		oom_call_time_ns: "31280084829903",
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		target_init_pid: 4219,
		target_init_tid: 4219,
		target_start_boottime_ns: "31277765690642",
		signal: 9,
		code: 128,
		pid_type: 1,
		preempt_count: 1,
	},
	{
		event: "signal_generate",
		time_ns: "31280084891622",
		context_init_pid: 4219,
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		target_init_pid: 4219,
		target_init_tid: 4219,
		target_start_boottime_ns: "31277765690642",
		signal: 9,
		code: 128,
		group: 1,
		result: 0,
		call_time_ns: "0",
		oom_call_time_ns: "31280084829903",
		oom_send_time_ns: "31280084885542",
		oom_preempt_count: 3,
	},
	{
		event: "oom_signal_return",
		time_ns: "31280084893042",
		call_time_ns: "31280084885542",
		oom_call_time_ns: "31280084829903",
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		context_valid: 1,
		result: 0,
	},
	{
		event: "oom_victim",
		time_ns: "31280084896702",
		init_pid: 4219,
		init_tid: 4219,
		start_boottime_ns: "31277765690642",
	},
	{
		event: "oom_kill_return",
		time_ns: "31280085797404",
		call_time_ns: "31280084829903",
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		context_valid: 1,
	},
	{
		event: "oom_kill_enter",
		time_ns: "31280085823064",
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		selected_init_pid: 4219,
		selected_process_start_boottime_ns: "31277765690642",
		scope: "selected_thread_group",
		context_contract: "x86_non_rt_preempt_count",
	},
	{
		event: "oom_signal_enter",
		time_ns: "31280085824554",
		oom_call_time_ns: "31280085823064",
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		target_init_pid: 4219,
		target_init_tid: 4219,
		target_start_boottime_ns: "31277765690642",
		signal: 9,
		code: 128,
		pid_type: 1,
		preempt_count: 1,
	},
	{
		event: "signal_generate",
		time_ns: "31280085826124",
		context_init_pid: 4219,
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		target_init_pid: 4219,
		target_init_tid: 4219,
		target_start_boottime_ns: "31277765690642",
		signal: 9,
		code: 128,
		group: 1,
		result: 1,
		call_time_ns: "0",
		oom_call_time_ns: "31280085823064",
		oom_send_time_ns: "31280085824554",
		oom_preempt_count: 3,
	},
	{
		event: "oom_signal_return",
		time_ns: "31280085826714",
		call_time_ns: "31280085824554",
		oom_call_time_ns: "31280085823064",
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		context_valid: 1,
		result: 0,
	},
	{
		event: "oom_kill_return",
		time_ns: "31280086449078",
		call_time_ns: "31280085823064",
		context_init_tid: 4219,
		context_start_boottime_ns: "31277765690642",
		context_valid: 1,
	},
	{
		event: "signal_deliver",
		time_ns: "31280086613786",
		pid: 2,
		tid: 2,
		init_pid: 4219,
		init_tid: 4219,
		start_boottime_ns: "31277765690642",
		signal: 9,
		code: 0,
	},
	{
		event: "process_exit",
		time_ns: "31280086638926",
		pid: 2,
		tid: 2,
		init_pid: 4219,
		init_tid: 4219,
		start_boottime_ns: "31277765690642",
		raw_exit_code: 9,
		group_dead: 1,
	},
];
const oomCapture = () => oomMetadata.map((row, i) => probe(`oom:${i}`, row));

describe("causal capture classification", () => {
	it("classifies the complete observed OOM-origin chain and retains the ignored retry occurrence", () => {
		const result = classifyCausalCapture({ target: oomTarget, platform: oomPlatform, occurrences: oomCapture() });
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("oom_kill");
		expect(result.initiator).toBeUndefined();
		expect(result.supportingOccurrenceIds).toEqual(
			expect.arrayContaining(["oom:1", "oom:2", "oom:3", "oom:4", "oom:6", "oom:13"]),
		);
		expect(result.facts.find((fact) => fact.occurrenceId === "oom:9")?.fields.result).toBe(1);
		expect(result.facts.find((fact) => fact.occurrenceId === "oom:3")?.fields.oom_preempt_count).toBe(3);
	});
	it.each([1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 13])(
		"withholds OOM attribution when required occurrence %s is missing",
		(index) => {
			const result = classifyCausalCapture({
				target: oomTarget,
				platform: oomPlatform,
				occurrences: oomCapture().filter((_, i) => i !== index),
			});
			expect(result.cause).toBe("unresolved");
		},
	);
	it("does not require a victim mark when the originating kill chain and fatal exit are captured", () => {
		expect(
			classifyCausalCapture({
				target: oomTarget,
				platform: oomPlatform,
				occurrences: oomCapture().filter((_, i) => i !== 5),
			}).cause,
		).toBe("oom_kill");
	});
	it.each([1, 2])("retains a later nonfresh signal result %s without treating it as a second kill", (result) => {
		const rows = oomCapture();
		rows[9] = probe("retry", { ...oomMetadata[9], result });
		expect(classifyCausalCapture({ target: oomTarget, platform: oomPlatform, occurrences: rows }).cause).toBe(
			"oom_kill",
		);
	});
	it("accepts bottom-half-disable depth with preemption disabled under the verified non-RT contract", () => {
		const rows = oomCapture();
		rows[2] = probe("send", { ...oomMetadata[2], preempt_count: 513 });
		rows[3] = probe("generate", { ...oomMetadata[3], oom_preempt_count: 515 });
		expect(classifyCausalCapture({ target: oomTarget, platform: oomPlatform, occurrences: rows }).cause).toBe(
			"oom_kill",
		);
	});
	it.each(["duplicate return", "nested context", "competing user kill", "different boot"])(
		"withholds OOM attribution with %s",
		(conflict) => {
			const rows = oomCapture();
			if (conflict === "duplicate return") rows.push(probe("duplicate", oomMetadata[4]));
			if (conflict === "nested context")
				rows.push(probe("nested", { ...oomMetadata[1], selected_init_pid: 99, time_ns: "31280084829904" }));
			if (conflict === "competing user kill")
				rows.push(
					probe("competing", {
						...oomMetadata[3],
						time_ns: "31280084891623",
						code: 0,
						call_time_ns: "31280084829902",
						oom_call_time_ns: "0",
						oom_send_time_ns: "0",
					}),
				);
			if (conflict === "different boot") rows[3] = { ...rows[3], bootId: "previous" };
			const result = classifyCausalCapture({ target: oomTarget, platform: oomPlatform, occurrences: rows });
			expect(result.status).toBe("process_exited");
			expect(result.cause).toBe("unresolved");
			expect(result.initiator).toBeUndefined();
		},
	);
	it.skipIf(!process.env.PRIME_AGENT_CAUSAL_OOM_CAPTURE_FILE)(
		"replays the retained OOM records with an explicit caller contract and no outcome labels",
		() => {
			const occurrences: CausalOccurrence[] = readFileSync(process.env.PRIME_AGENT_CAUSAL_OOM_CAPTURE_FILE!, "utf8")
				.split("\n")
				.filter((line) => line.startsWith("{"))
				.map((payload, i) => ({ id: `oom-raw:${i}`, source: "probe", bootId, payload }));
			// The raw fixture lacks boot metadata. This replay uses the explicit test
			// boot binding; production must supply its own observed, verified contract.
			const result = classifyCausalCapture({ target: oomTarget, platform: oomPlatform, occurrences });
			expect(result.cause).toBe("oom_kill");
			expect(
				result.facts.filter((fact) => fact.event === "signal_generate").map((fact) => fact.fields.result),
			).toEqual([0, 1]);
			expect(classifyCausalCapture({ target: oomTarget, occurrences }).cause).toBe("unresolved");
		},
	);
	it.each([0, 256, 257, 65537, 65793, 1048577, -1, 1.5, 2147483649])(
		"rejects zero, invalid or interrupt preempt count %s",
		(count) => {
			for (const [index, key] of [
				[2, "preempt_count"],
				[3, "oom_preempt_count"],
			] as const) {
				const rows = oomCapture();
				rows[index] = probe(`invalid:${index}`, { ...oomMetadata[index], [key]: count });
				expect(classifyCausalCapture({ target: oomTarget, platform: oomPlatform, occurrences: rows }).cause).toBe(
					"unresolved",
				);
			}
		},
	);
	it.each([
		{ verified: false },
		{ kind: "other" },
		{ machine: "aarch64" },
		{ kernelRelease: "" },
		{ kernelRelease: " " },
		{ kernelRelease: "x".repeat(257) },
		{ kernelConfigSha256: "unverified" },
		{ preemptCount: false },
		{ preemptRt: true },
	])("refuses an unverified or incompatible platform contract %j", (change) => {
		const changed = { ...oomPlatform, oomContextContract: { ...oomPlatform.oomContextContract, ...change } };
		expect(classifyCausalCapture({ target: oomTarget, platform: changed, occurrences: oomCapture() }).cause).toBe(
			"unresolved",
		);
	});
	it("never activates OOM proof from the probe self-assertion or another boot's contract", () => {
		expect(classifyCausalCapture({ target: oomTarget, occurrences: oomCapture() }).cause).toBe("unresolved");
		expect(classifyCausalCapture({ target: oomTarget, platform, occurrences: oomCapture() }).cause).toBe(
			"unresolved",
		);
		expect(
			classifyCausalCapture({
				target: oomTarget,
				platform: { ...oomPlatform, bootId: "other" },
				occurrences: oomCapture(),
			}).cause,
		).toBe("unresolved");
	});
	it.each([
		[1, { selected_process_start_boottime_ns: "31277765690643" }],
		[1, { scope: "shared_mm" }],
		[1, { context_contract: "other" }],
		[2, { target_start_boottime_ns: "31277765690643" }],
		[2, { pid_type: 0 }],
		[3, { context_start_boottime_ns: "31277765690643" }],
		[3, { oom_call_time_ns: "0" }],
		[3, { oom_send_time_ns: "0" }],
		[3, { code: 0 }],
		[3, { group: 0 }],
		[4, { context_valid: 0 }],
		[4, { result: -1 }],
		[4, { time_ns: "31280084891621" }],
		[6, { context_valid: 0 }],
		[6, { call_time_ns: "1" }],
		[9, { result: 0 }],
		[9, { result: 3 }],
		[13, { raw_exit_code: 15 }],
	] as const)("rejects mismatched OOM context or signal evidence at %s", (index, change) => {
		const rows = oomCapture();
		rows[index] = probe(`wrong:${index}`, { ...oomMetadata[index], ...change });
		expect(classifyCausalCapture({ target: oomTarget, platform: oomPlatform, occurrences: rows }).cause).toBe(
			"unresolved",
		);
	});
	it("withholds OOM attribution when provider loss could hide a competing cause", () => {
		expect(
			classifyCausalCapture({
				target: oomTarget,
				platform: oomPlatform,
				occurrences: [...oomCapture(), probe("loss", { event: "coverage_gap", kind: "oom_nested_context" })],
			}).cause,
		).toBe("unresolved");
	});
	it("attributes a real SIGTERM group exit without inventing a SIGTERM delivery event", () => {
		const result = classifyCausalCapture({ target: fatalGroupTarget, occurrences: fatalGroupCapture() });
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("user_signal");
		expect(result.initiator).toEqual({
			initPid: 25258,
			initTid: 25258,
			startBoottimeNs: "30747275134801",
			syscallKind: 1,
		});
		expect(result.facts.filter((fact) => fact.event === "signal_deliver").map((fact) => fact.fields.signal)).toEqual([
			9, 9,
		]);
		expect(result.missingEvidence).toContain("signal_delivery_not_observed");
		expect(result.missingEvidence).toContain("sigterm_group_exit_inferred_from_thread_observations");
		expect(result.supportingOccurrenceIds).toEqual(
			expect.arrayContaining(["group:1", "group:2", "group:3", "group:5", "group:8"]),
		);
	});
	it.each(["call", "return", "thread identity", "thread exit", "group exit"])(
		"keeps the group-exit sender unresolved without %s evidence",
		(missing) => {
			const index = { call: 2, return: 5, "thread identity": 1, "thread exit": 7, "group exit": 8 }[missing]!;
			const rows = fatalGroupCapture().filter((_, i) => i !== index);
			expect(classifyCausalCapture({ target: fatalGroupTarget, occurrences: rows }).cause).toBe("unresolved");
		},
	);
	it.each([
		"another fatal generation",
		"other generated signal",
		"provider loss",
		"wrong boot",
		"wrong generation",
		"wrong delivery code",
	])("withholds the group-exit sender with %s", (conflict) => {
		const rows = fatalGroupCapture();
		if (conflict === "another fatal generation")
			rows.push(probe("second", { ...fatalGroupMetadata[3], time_ns: "30750550038000" }));
		if (conflict === "other generated signal")
			rows.push(probe("other", { ...fatalGroupMetadata[3], time_ns: "30750550038000", signal: 1 }));
		if (conflict === "provider loss") rows.push(probe("loss", { event: "lost_events", count: 1 }));
		if (conflict === "wrong boot") rows[3] = { ...rows[3], bootId: "different" };
		if (conflict === "wrong generation")
			rows[3] = probe("wrong", { ...fatalGroupMetadata[3], target_start_boottime_ns: "30750049098221" });
		if (conflict === "wrong delivery code") rows[4] = probe("wrong", { ...fatalGroupMetadata[4], code: 128 });
		const result = classifyCausalCapture({ target: fatalGroupTarget, occurrences: rows });
		expect(result.cause).toBe("unresolved");
		expect(result.initiator).toBeUndefined();
	});
	it.skipIf(!process.env.PRIME_AGENT_CAUSAL_GROUP_CAPTURE_DIR)(
		"replays the full real-IPython group-exit capture without fixture outcome metadata",
		() => {
			const directory = process.env.PRIME_AGENT_CAUSAL_GROUP_CAPTURE_DIR!;
			const { target: observedTarget, platform: observedPlatform } = JSON.parse(
				readFileSync(join(directory, "capture.json"), "utf8"),
			) as { target: CausalTarget; platform: CausalPlatformIdentity };
			const occurrences: CausalOccurrence[] = readFileSync(join(directory, "probe.jsonl"), "utf8")
				.trim()
				.split("\n")
				.map((payload, i) => ({ id: `group-full:${i}`, source: "probe", bootId: observedTarget.bootId, payload }));
			const result = classifyCausalCapture({ target: observedTarget, platform: observedPlatform, occurrences });
			expect(result.status).toBe("process_exited");
			expect(result.cause).toBe("user_signal");
			expect(
				result.facts.filter((fact) => fact.event === "signal_deliver").every((fact) => fact.fields.signal === 9),
			).toBe(true);
			expect(result.missingEvidence).toContain("signal_delivery_not_observed");
		},
	);
	it.each([null, [], "text", 3, true])(
		"withholds attribution when a selected journal body is nonobject %j",
		(body) => {
			const occurrence: CausalOccurrence = {
				id: "nonobject-journal-body",
				source: "journal",
				payload: JSON.stringify({ _BOOT_ID: bootId, MESSAGE: JSON.stringify(body) }),
			};
			const result = classifyCausalCapture({ target, occurrences: [...capture(), occurrence] });
			expect(result.status).toBe("process_exited");
			expect(result.cause).toBe("unresolved");
			expect(result.initiator).toBeUndefined();
			expect(result.missingEvidence).toContain("malformed_record");
		},
	);
	it("identifies an observed native fault from exact capture records", () => {
		const result = classifyCausalCapture({ target, occurrences: capture() });
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("native_fault");
		expect(result.supportingOccurrenceIds).toEqual(expect.arrayContaining(["p1", "p2", "p3"]));
		expect(result.facts.find((f) => f.occurrenceId === "p1")?.fields.time_ns).toBe("28478276103119");
	});
	it.each(["generation", "boot", "time", "delivery", "positive code"])(
		"does not invent native-fault attribution with conflicting %s",
		(missing) => {
			const rows = capture();
			if (missing === "generation")
				rows[1] = probe("wrong", { ...nativeFault[1], target_start_boottime_ns: "28478275484976" });
			if (missing === "boot") rows[1] = probe("wrong", nativeFault[1], "previous-boot");
			if (missing === "time") rows[1] = probe("wrong", { ...nativeFault[1], time_ns: "28478276174059" });
			if (missing === "delivery") rows.splice(2, 1);
			if (missing === "positive code") rows[1] = probe("wrong", { ...nativeFault[1], code: 0 });
			expect(classifyCausalCapture({ target, occurrences: rows }).cause).toBe("unresolved");
		},
	);
	it("maps app namespace/start ticks only using the observed platform clock", () => {
		expect(classifyCausalCapture({ target: appTarget, occurrences: capture(), platform }).cause).toBe("native_fault");
		expect(classifyCausalCapture({ target: appTarget, occurrences: capture() }).cause).toBe("unresolved");
		expect(
			classifyCausalCapture({
				target: appTarget,
				occurrences: capture(),
				platform: { ...platform, procReaderBoottimeOffsetNs: "1" },
			}).cause,
		).toBe("unresolved");
	});
	it("correlates a forwarded application exit using the original observer namespace", () => {
		const forwarded = app("forwarded-exit", {
			type: "kernel_process_exit_observed",
			code: null,
			signal: "SIGSEGV",
			producerPidNamespace: "pid:[4026532999]",
			observerPid: 2,
			observerProcessStartId: "2847633",
			observerPidNamespace: "pid:[4026532290]",
			observerBoottimeOffsetNs: "0",
			workerProcessStartId: "2847600",
		});
		const result = classifyCausalCapture({ target: appTarget, platform, occurrences: [...capture(), forwarded] });
		expect(result.cause).toBe("native_fault");
		expect(result.supportingOccurrenceIds).toContain("forwarded-exit");
		expect(result.facts.find((fact) => fact.occurrenceId === "forwarded-exit")?.fields).toMatchObject({
			observerPid: 2,
			observerProcessStartId: "2847633",
			observerPidNamespace: "pid:[4026532290]",
			observerBoottimeOffsetNs: "0",
			workerProcessStartId: "2847600",
			producerPidNamespace: "pid:[4026532999]",
		});
	});
	it("does not use the forwarder namespace to override a conflicting original observer", () => {
		const forwarded = app("wrong-observer", {
			type: "kernel_process_exit_observed",
			observerPidNamespace: "pid:[4026532999]",
		});
		const result = classifyCausalCapture({ target: appTarget, platform, occurrences: [...capture(), forwarded] });
		expect(result.cause).toBe("native_fault");
		expect(result.supportingOccurrenceIds).not.toContain("wrong-observer");
	});
	it("refuses namespace mismatches and same-tick PID-generation ambiguity", () => {
		const wrongNamespace = { ...appTarget, pidNamespace: "4026532999" };
		expect(classifyCausalCapture({ target: wrongNamespace, platform, occurrences: capture() }).cause).toBe(
			"unresolved",
		);
		const ambiguous = [
			...capture(),
			probe("reused", {
				...nativeFault[0],
				process_start_boottime_ns: "28478275484976",
				start_boottime_ns: "28478275484976",
			}),
		];
		const result = classifyCausalCapture({ target: appTarget, platform, occurrences: ambiguous });
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("process_generation_ambiguous");
	});
	it("does not treat a thread exit as a process exit", () => {
		const rows = capture();
		rows[3] = probe("thread-exit", { ...nativeFault[3], group_dead: 0 });
		expect(classifyCausalCapture({ target, occurrences: rows }).status).toBe("unresolved");
	});
	it("refuses observations before the supplied task generation began", () => {
		const rows = capture().map((row) => probe(row.id, { ...JSON.parse(row.payload as string), time_ns: "1" }));
		expect(classifyCausalCapture({ target, occurrences: rows }).status).toBe("unresolved");
	});
	it("does not choose between conflicting delivered causes", () => {
		const rows = [...capture(), probe("other-delivery", { ...nativeFault[2], code: 0, time_ns: "28478276142550" })];
		expect(classifyCausalCapture({ target, occurrences: rows }).cause).toBe("unresolved");
	});
	it("does not treat post-exit cleanup as its cause", () => {
		const result = classifyCausalCapture({
			target: appTarget,
			occurrences: [
				app("exit", { type: "kernel_process_exit_observed", code: 23, signal: null, lifecycleState: "running" }),
				app("cleanup", {
					type: "kernel_lifecycle_intent",
					operation: "cleanup_resources",
					reason: "SIGTERM",
					caller: "cleanup",
					monotonicNs: "28478276100001",
				}),
			],
		});
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("unresolved");
		expect(result.facts.some((f) => f.occurrenceId === "cleanup")).toBe(true);
	});
	it.each([
		[1, 12],
		[1, -12],
		[2, 12],
		[3, 12],
		[4, 7],
	])(
		"attributes kind %s target argument %s using the selected target, not the argument namespace",
		(kind, argument) => {
			const result = classifyCausalCapture({ target, occurrences: signalCapture(kind, argument) });
			expect(result.cause).toBe("user_signal");
			expect(result.initiator).toEqual({
				initPid: 999,
				initTid: 999,
				startBoottimeNs: "28000000000000",
				syscallKind: kind,
			});
			expect(result.supportingOccurrenceIds).toEqual(
				expect.arrayContaining(["call", "generate", "return", "deliver", "exit"]),
			);
		},
	);
	it.each(["call", "return", "deliver"])("does not infer a sender without the %s observation", (missing) => {
		expect(
			classifyCausalCapture({ target, occurrences: signalCapture().filter((row) => row.id !== missing) }).cause,
		).toBe("unresolved");
	});
	it("never calls current signal-generation context the sender without its matching syscall", () => {
		const rows = signalCapture();
		const value = JSON.parse(rows[2].payload as string);
		rows[2] = probe("generate", { ...value, call_time_ns: "0" });
		expect(classifyCausalCapture({ target, occurrences: rows }).initiator).toBeUndefined();
	});
	it("keeps already-pending generations ambiguous even when one delivery and fatal exit follow", () => {
		const rows = signalCapture();
		rows.push(probe("coalesced", { ...JSON.parse(rows[2].payload as string), time_ns: "28478276104100", result: 2 }));
		const result = classifyCausalCapture({ target, occurrences: rows });
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("signal_generation_ambiguous_or_coalesced");
	});
	it("retains an OOM victim mark and SIGKILL exit without inventing the kill origin", () => {
		const victim = {
			event: "oom_victim",
			time_ns: "28478276100000",
			init_pid: 3130,
			init_tid: 3130,
			start_boottime_ns: target.processStartBoottimeNs,
		};
		const exit = probe("exit", { ...nativeFault[3], raw_exit_code: 9 });
		const marked = classifyCausalCapture({ target, occurrences: [probe("oom", victim), exit] });
		expect(marked.cause).toBe("unresolved");
		expect(marked.status).toBe("process_exited");
		expect(marked.facts.some((fact) => fact.occurrenceId === "oom")).toBe(true);
		expect(marked.missingEvidence).toContain("oom_victim_mark_does_not_establish_kill_origin");
		expect(classifyCausalCapture({ target, occurrences: [probe("oom", victim)] }).cause).toBe("unresolved");
		expect(
			classifyCausalCapture({ target, occurrences: [probe("oom", { ...victim, start_boottime_ns: "1" }), exit] })
				.cause,
		).toBe("unresolved");
		expect(
			classifyCausalCapture({
				target,
				occurrences: [probe("oom", victim), probe("exit", { ...nativeFault[3], raw_exit_code: 15 })],
			}).cause,
		).toBe("unresolved");
	});
	it("does not attribute privileged SIGKILL generation to OOM from its siginfo code", () => {
		const rows = [
			probe("privileged-kill", { ...nativeFault[1], signal: 9, code: 128 }),
			probe("mark", {
				event: "oom_victim",
				time_ns: "28478276104100",
				init_pid: 3130,
				init_tid: 3130,
				start_boottime_ns: target.processStartBoottimeNs,
			}),
			probe("exit", { ...nativeFault[3], raw_exit_code: 9 }),
		];
		expect(classifyCausalCapture({ target, occurrences: rows }).cause).toBe("unresolved");
	});
	it.each([
		["lost event", { event: "lost_events", time_ns: "28478276174057", count: 1 }],
		["stock loss framing", { type: "lost_events", count: 1 }],
		["unknown provider gap", { event: "coverage_gap", time_ns: "28478276174057", kind: "unknown" }],
	] as const)("withdraws native attribution after a %s while retaining exit facts", (_name, loss) => {
		const result = classifyCausalCapture({ target, occurrences: [...capture(), probe("loss", loss)] });
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("unresolved");
		expect(result.initiator).toBeUndefined();
		expect(result.facts.some((fact) => fact.occurrenceId === "p3")).toBe(true);
		expect(result.missingEvidence).toContain("causal_coverage_incomplete");
	});
	it("withdraws a previous signal sender when a later fatal generation could have been lost", () => {
		const result = classifyCausalCapture({
			target,
			occurrences: [
				...signalCapture(),
				probe("loss", { event: "lost_events", time_ns: "28478276174057", count: 1 }),
			],
		});
		expect(result.cause).toBe("unresolved");
		expect(result.initiator).toBeUndefined();
		expect(result.status).toBe("process_exited");
		expect(result.facts.some((fact) => fact.occurrenceId === "call")).toBe(true);
	});
	it.each(["malformed", "missing boot", "conflicting boot", "invalid occurrence ID"])(
		"withdraws attribution when %s evidence was omitted",
		(kind) => {
			const missing: CausalOccurrence =
				kind === "malformed"
					? { id: "bad", source: "probe", bootId, payload: "{" }
					: kind === "missing boot"
						? { id: "bad", source: "probe", payload: JSON.stringify(nativeFault[1]) }
						: kind === "conflicting boot"
							? {
									id: "bad",
									source: "journal",
									bootId,
									payload: JSON.stringify({ _BOOT_ID: "different", MESSAGE: JSON.stringify(nativeFault[1]) }),
								}
							: { ...probe("", nativeFault[1]) };
			const result = classifyCausalCapture({ target, occurrences: [...capture(), missing] });
			expect(result.status).toBe("process_exited");
			expect(result.cause).toBe("unresolved");
		},
	);
	it("does not classify through an invalid target boot fence", () => {
		const invalidBoot = "x".repeat(129);
		const result = classifyCausalCapture({
			target: { ...target, bootId: invalidBoot },
			occurrences: capture().map((row) => ({ ...row, bootId: invalidBoot })),
		});
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("target_boot_identity_unavailable");
	});
	it("withdraws application attribution when the producer reports dropped records", () => {
		const rows = [
			app("intent", {
				type: "kernel_lifecycle_intent",
				operation: "shutdown",
				caller: "shutdown",
				reason: "requested",
			}),
			app("exit", {
				type: "kernel_process_exit_observed",
				code: 0,
				signal: null,
				lifecycleState: "shutdown",
				monotonicNs: "28478276200000",
				loss: { droppedRecords: 1 },
			}),
		];
		const result = classifyCausalCapture({ target: appTarget, occurrences: rows });
		expect(result.status).toBe("process_exited");
		expect(result.cause).toBe("unresolved");
		expect(result.initiator).toBeUndefined();
	});
	it.each(["socket_capacity", "socket_call_capacity"])(
		"keeps explicitly scoped %s gaps separate from signal evidence",
		(kind) => {
			const result = classifyCausalCapture({
				target,
				occurrences: [...capture(), probe("gap", { event: "coverage_gap", time_ns: "28478276174057", kind })],
			});
			expect(result.cause).toBe("native_fault");
			expect(result.missingEvidence).toContain("provider_socket_coverage_gap");
		},
	);
	it("reports a parent/child exit sequence without manufacturing its initiating caller", () => {
		const rows = [
			probe("fork", {
				event: "process_fork",
				time_ns: "28478276000000",
				parent_init_pid: 3000,
				parent_init_tid: 3000,
				parent_start_boottime_ns: "28000000000000",
				child_init_pid: 3130,
				child_init_tid: 3130,
				child_start_boottime_ns: target.processStartBoottimeNs,
			}),
			probe("parent-exit", {
				event: "process_exit",
				time_ns: "28478276100000",
				init_pid: 3000,
				init_tid: 3000,
				start_boottime_ns: "28000000000000",
				group_dead: 1,
				raw_exit_code: 9,
			}),
			probe("exit", nativeFault[3]),
		];
		const result = classifyCausalCapture({ target, occurrences: rows });
		expect(result.mechanism).toBe("parent_exit_preceded_child_exit");
		expect(result.cause).toBe("unresolved");
		expect(result.initiator).toBeUndefined();
	});
	it("describes a proven direct-observer shutdown sequence with caller and mechanism uncertainty", () => {
		const rows = [
			app("intent", {
				type: "kernel_lifecycle_intent",
				operation: "shutdown",
				caller: "KernelManager.shutdown",
				reason: "requested",
			}),
			app("exit", {
				type: "kernel_process_exit_observed",
				code: 0,
				signal: null,
				lifecycleState: "shutdown",
				monotonicNs: "28478276200000",
			}),
		];
		const result = classifyCausalCapture({ target: appTarget, occurrences: rows });
		expect(result.cause).toBe("application_shutdown_sequence");
		expect(result.initiator).toEqual({ caller: "KernelManager.shutdown", reason: "requested" });
		expect(result.missingEvidence).toContain("native_shutdown_mechanism_unresolved");
		rows[0] = app("intent", {
			type: "kernel_lifecycle_intent",
			operation: "shutdown",
			caller: "other",
			reason: "other",
			producerId: "other-producer",
			producerPid: 3,
			ownerPid: 3,
		});
		expect(classifyCausalCapture({ target: appTarget, occurrences: rows }).cause).toBe("unresolved");
	});
	it.each([
		{ observerPid: 3, observerProcessStartId: "proc:2847634" },
		{ observerBoottimeOffsetNs: "1000000000" },
		{ observerBoottimeOffsetNs: undefined },
		{ observerProcessStartId: undefined },
		{ observerPid: undefined },
	])("does not join forwarded application events across unknown or different original clocks %j", (change) => {
		const observer = {
			producerId: "shared-forwarder",
			producerPid: 999,
			observerPid: 2,
			observerProcessStartId: "proc:2847633",
			observerPidNamespace: "pid:[4026532290]",
			observerBoottimeOffsetNs: "0",
		};
		const intent = app("intent", {
			...observer,
			type: "kernel_lifecycle_intent",
			operation: "shutdown",
			caller: "actual-caller",
			reason: "requested",
		});
		const exit = app("exit", {
			...observer,
			...change,
			type: "kernel_process_exit_observed",
			code: 0,
			signal: null,
			lifecycleState: "shutdown",
			monotonicNs: "28478276200000",
		});
		const result = classifyCausalCapture({ target: appTarget, occurrences: [intent, exit] });
		expect(result.cause).toBe("unresolved");
		expect(result.initiator).toBeUndefined();
		expect(result.missingEvidence.some((item) => item.startsWith("application_observer_clock_"))).toBe(true);
		const health = classifyCausalCapture({
			target: appTarget,
			occurrences: [
				app("busy", { ...observer, type: "kernel_protocol_observation", observation: "iopub_busy" }),
				app("heartbeat", {
					...observer,
					...change,
					type: "kernel_protocol_observation",
					observation: "heartbeat_echo",
					monotonicNs: "28478276200000",
				}),
			],
		});
		expect(health.status).not.toBe("execution_observed_healthy");
	});
	it("correlates one original observer across forwarders and declines an unproven legacy owner", () => {
		const observer = {
			observerPid: 2,
			observerProcessStartId: "proc:2847633",
			observerPidNamespace: "pid:[4026532290]",
			observerBoottimeOffsetNs: "0",
		};
		const intent = app("intent", {
			...observer,
			producerId: "one-forwarder",
			type: "kernel_lifecycle_intent",
			operation: "shutdown",
			caller: "caller",
			reason: "requested",
		});
		const exit = app("exit", {
			...observer,
			producerId: "another-forwarder",
			type: "kernel_process_exit_observed",
			code: 0,
			signal: null,
			lifecycleState: "shutdown",
			monotonicNs: "28478276200000",
		});
		expect(classifyCausalCapture({ target: appTarget, occurrences: [intent, exit] }).cause).toBe(
			"application_shutdown_sequence",
		);
		for (const row of [intent, exit]) {
			const envelope = JSON.parse(row.payload as string);
			const data = JSON.parse(envelope.MESSAGE);
			for (const key of Object.keys(observer)) delete data[key];
			delete data.ownerProcessStartId;
			envelope.MESSAGE = JSON.stringify(data);
			row.payload = JSON.stringify(envelope);
		}
		const result = classifyCausalCapture({ target: appTarget, occurrences: [intent, exit] });
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("application_observer_clock_unavailable");
	});
	it("does not replace the original source clock with delayed journal-queue time", () => {
		const intent = app("intent", {
			type: "kernel_lifecycle_intent",
			operation: "shutdown",
			caller: "shutdown",
			reason: "requested",
			monotonicNs: "28478279999999",
			details: { value: { $diagnosticType: "object", properties: [["monotonicNs", "28478276100000"]] } },
		});
		const exit = app("exit", {
			type: "kernel_process_exit_observed",
			code: 0,
			signal: null,
			lifecycleState: "shutdown",
			monotonicNs: "28478276200000",
		});
		expect(classifyCausalCapture({ target: appTarget, occurrences: [exit, intent] }).cause).toBe(
			"application_shutdown_sequence",
		);
	});
	it("preserves nanoseconds beyond the safe integer range", () => {
		const offset = 9_007_199_254_740_992n;
		const rows = nativeFault.map((row, i) =>
			probe(
				`exact:${i}`,
				Object.fromEntries(
					Object.entries(row).map(([key, value]) => [
						key,
						key.endsWith("_ns") && value !== "0" ? String(BigInt(value as string) + offset) : value,
					]),
				),
			),
		);
		const result = classifyCausalCapture({
			target: { ...target, processStartBoottimeNs: String(BigInt(target.processStartBoottimeNs!) + offset) },
			occurrences: rows,
		});
		expect(result.cause).toBe("native_fault");
		expect(result.facts.find((row) => row.occurrenceId === "exact:1")?.fields.time_ns).toBe("9035677530844111");
	});
	it("keeps heartbeat misses and missing replies distinct from death", () => {
		const result = classifyCausalCapture({
			target: appTarget,
			occurrences: [
				app("miss", {
					type: "kernel_protocol_observation",
					observation: "heartbeat_unavailable",
					reason: "timeout",
				}),
			],
		});
		expect(result.status).toBe("channel_unavailable");
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("process_exit_not_observed");
	});
	it("does not infer a missing shell reply from a long busy execution with a heartbeat", () => {
		const result = classifyCausalCapture({
			target: appTarget,
			occurrences: [
				app("busy", { type: "kernel_protocol_observation", observation: "iopub_busy", requestMsgId: "request" }),
				app("hb", {
					type: "kernel_protocol_observation",
					observation: "heartbeat_echo",
					monotonicNs: "29978276100000",
				}),
			],
		});
		expect(result.status).toBe("execution_observed_healthy");
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).not.toContain("shell_reply_not_observed_after_idle");
	});
	it("does not relabel diagnostic tracking capacity as a stalled channel", () => {
		const result = classifyCausalCapture({
			target: appTarget,
			occurrences: [
				app("capacity", {
					type: "kernel_protocol_observation",
					observation: "shell_reply_unavailable",
					reason: "tracking_capacity",
				}),
			],
		});
		expect(result.status).toBe("unresolved");
		expect(result.missingEvidence).toContain("protocol_tracking_capacity");
	});
	it("keeps a reported forkserver loss distinct from a kernel process exit", () => {
		const result = classifyCausalCapture({
			target: appTarget,
			occurrences: [
				app("parent-loss", {
					type: "kernel_unexpected_exit",
					reason: "forkserver_unavailable",
					code: null,
					signal: null,
				}),
			],
		});
		expect(result.status).toBe("parent_unavailable");
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("process_exit_not_observed");
	});
	it("does not mistake socket-close metadata for process death or remote socket loss", () => {
		const result = classifyCausalCapture({
			target,
			occurrences: [
				probe("close", {
					event: "socket_close",
					time_ns: "28478276100000",
					init_pid: 3130,
					init_tid: 3130,
					start_boottime_ns: target.processStartBoottimeNs,
					fd: 4,
					inode: "123",
				}),
			],
		});
		expect(result.status).toBe("unresolved");
		expect(result.cause).toBe("unresolved");
	});
	it("does not exhaust its fact budget on routine heartbeat history", () => {
		const heartbeats = Array.from({ length: 1000 }, (_, i) =>
			app(`heartbeat:${i}`, { type: "kernel_protocol_observation", observation: "heartbeat_echo" }),
		);
		const result = classifyCausalCapture({ target: appTarget, platform, occurrences: [...heartbeats, ...capture()] });
		expect(result.cause).toBe("native_fault");
		expect(result.facts.length).toBeLessThan(10);
	});
	it("refuses conflicting occurrence identities and bounds input rows", () => {
		const conflict = capture();
		conflict.push(probe("p1", { ...nativeFault[1], code: 0 }));
		expect(classifyCausalCapture({ target, occurrences: conflict }).missingEvidence).toContain(
			"occurrence_identity_conflict",
		);
		const result = classifyCausalCapture({
			target,
			occurrences: [
				...capture(),
				...Array.from({ length: 4096 }, (_, i) => probe(`ignored:${i}`, { event: "probe_health", time_ns: "1" })),
			],
		});
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("input_row_limit");
	});
	it("rejects oversized input before parsing and leaves explicit uncertainty", () => {
		const result = classifyCausalCapture({ target, occurrences: [probe("large", { ignored: "x".repeat(140_000) })] });
		expect(result.cause).toBe("unresolved");
		expect(result.missingEvidence).toContain("input_payload_limit");
	});
	it.skipIf(!process.env.PRIME_AGENT_CAUSAL_CAPTURE_FILE)(
		"classifies retained raw stock-probe output without fixture outcome labels",
		() => {
			const rows = readFileSync(process.env.PRIME_AGENT_CAUSAL_CAPTURE_FILE!, "utf8")
				.split("\n")
				.filter((line) => line.startsWith("{"));
			const occurrences = rows.map(
				(payload, i): CausalOccurrence => ({ id: `retained:${i}`, source: "probe", bootId, payload }),
			);
			const exits = rows
				.map((line) => JSON.parse(line) as Record<string, unknown>)
				.filter((row) => row.event === "process_exit");
			const results = exits.map((exit) =>
				classifyCausalCapture({
					target: {
						bootId,
						initPid: Number(exit.init_pid),
						processStartBoottimeNs: String(exit.start_boottime_ns),
					},
					occurrences,
				}),
			);
			expect(results.filter((result) => result.cause === "native_fault")).toHaveLength(1);
			expect(results.every((result) => result.status === "process_exited")).toBe(true);
		},
	);
	it.skipIf(!process.env.PRIME_AGENT_CAUSAL_JOURNAL_CAPTURE_FILE)(
		"replays retained native journal evidence without importing injection labels",
		() => {
			const lines = readFileSync(process.env.PRIME_AGENT_CAUSAL_JOURNAL_CAPTURE_FILE!, "utf8").trim().split("\n");
			const entries = lines.map((line) => JSON.parse(line) as { _BOOT_ID: string; MESSAGE: string });
			const observed = entries.map((entry) => ({
				boot: entry._BOOT_ID,
				event: JSON.parse(entry.MESSAGE) as Record<string, unknown>,
			}));
			const kernels = new Map(
				observed
					.filter(({ event }) => typeof event.kernelInstanceId === "string")
					.map((item) => [String(item.event.kernelInstanceId), item]),
			);
			expect(kernels.size).toBeGreaterThan(0);
			for (const { boot, event } of kernels.values()) {
				const result = classifyCausalCapture({
					target: {
						bootId: boot,
						kernelInstanceId: String(event.kernelInstanceId),
						pid: Number(event.kernelPid),
						processStartTicks: String(event.kernelProcessStartId).replace(/^proc:/, ""),
						pidNamespace: typeof event.producerPidNamespace === "string" ? event.producerPidNamespace : undefined,
					},
					occurrences: lines.map((payload, i) => ({ id: `journal:${i}`, source: "journal", payload })),
				});
				expect(["process_exited", "parent_unavailable"]).toContain(result.status);
				expect(result.cause).toBe("unresolved");
				expect(result.initiator).toBeUndefined();
				expect(result.supportingOccurrenceIds.length).toBeGreaterThan(0);
			}
		},
	);
});
