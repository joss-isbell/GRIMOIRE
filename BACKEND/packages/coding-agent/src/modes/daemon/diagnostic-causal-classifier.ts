export interface CausalOccurrence {
	id: string;
	bootId?: string;
	source: "journal" | "probe" | "application";
	payload: string | Uint8Array;
}

export interface CausalTarget {
	bootId: string;
	kernelInstanceId?: string;
	kernelGeneration?: number;
	pid?: number;
	pidNamespace?: string;
	processStartTicks?: string;
	initPid?: number;
	processStartBoottimeNs?: string;
}

export interface CausalPlatformIdentity {
	bootId: string;
	clockTicksPerSecond: number;
	/** Only a verified zero reader offset is currently supported. */
	procReaderBoottimeOffsetNs: string;
	/** Reserved for callers; this classifier never cross-orders the two clocks. */
	appMonotonicToBoottimeOffsetNs?: string;
	/** Caller-verified kernel config for this exact boot; probe output cannot admit it. */
	oomContextContract?: {
		verified: boolean;
		kind: string;
		machine: string;
		kernelRelease: string;
		kernelConfigSha256: string;
		preemptCount: boolean;
		preemptRt: boolean;
	};
}

export interface CausalFact {
	occurrenceId: string;
	event: string;
	fields: Record<string, string | number | boolean | null>;
}

export interface CausalClassification {
	status:
		| "process_exited"
		| "parent_unavailable"
		| "channel_unavailable"
		| "execution_observed_healthy"
		| "execution_completed"
		| "unresolved";
	cause: "native_fault" | "oom_kill" | "user_signal" | "application_shutdown_sequence" | "unresolved";
	mechanism?: "signal_exit" | "exit_status" | "parent_exit_preceded_child_exit";
	initiator?: {
		initPid?: number;
		initTid?: number;
		startBoottimeNs?: string;
		caller?: string;
		reason?: string;
		syscallKind?: number;
	};
	supportingOccurrenceIds: string[];
	facts: CausalFact[];
	missingEvidence: string[];
	/** A bounded capture never establishes the absence of uncaptured events. */
	coverageComplete: false;
}

interface Row {
	id: string;
	source: "probe" | "application";
	data: Record<string, unknown>;
	time?: bigint;
	event: string;
}
interface ProcessIdentity {
	initPid: number;
	start: string;
}
const MAX_ROWS = 4096;
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD = 128 * 1024;
const MAX_FACTS = 256;
const CAUSAL_COVERAGE_GAPS = new Set([
	"input_row_limit",
	"input_byte_limit",
	"input_payload_limit",
	"output_fact_limit",
	"occurrence_identity_conflict",
	"occurrence_identity_unavailable",
	"target_boot_identity_unavailable",
	"record_boot_identity_conflict",
	"record_boot_identity_unavailable",
	"malformed_record",
	"provider_coverage_gap",
	"application_records_dropped",
]);
const FACT_FIELDS = new Set([
	"time_ns",
	"call_time_ns",
	"oom_call_time_ns",
	"oom_send_time_ns",
	"oom_preempt_count",
	"selected_init_pid",
	"selected_process_start_boottime_ns",
	"scope",
	"context_contract",
	"pid_type",
	"preempt_count",
	"context_valid",
	"monotonicNs",
	"observedAt",
	"init_pid",
	"init_tid",
	"start_boottime_ns",
	"process_start_boottime_ns",
	"subject_pid",
	"subject_tid",
	"pidns_inode",
	"context_init_pid",
	"context_init_tid",
	"context_start_boottime_ns",
	"target_init_pid",
	"target_init_tid",
	"target_start_boottime_ns",
	"signal",
	"code",
	"group",
	"result",
	"kind",
	"target_argument",
	"group_argument",
	"raw_exit_code",
	"group_dead",
	"parent_init_pid",
	"parent_init_tid",
	"parent_start_boottime_ns",
	"child_init_pid",
	"child_init_tid",
	"child_start_boottime_ns",
	"producerId",
	"producerPid",
	"producerStartId",
	"producerPidNamespace",
	"observerPid",
	"observerProcessStartId",
	"observerPidNamespace",
	"observerBoottimeOffsetNs",
	"kernelInstanceId",
	"kernelGeneration",
	"kernelPid",
	"kernelProcessStartId",
	"ownerPid",
	"ownerProcessStartId",
	"forkserverPid",
	"forkserverProcessStartId",
	"forkserverInstanceId",
	"workerPid",
	"workerProcessStartId",
	"workerId",
	"requestMsgId",
	"protocolMsgId",
	"observation",
	"probeId",
	"caller",
	"operation",
	"reason",
	"phase",
	"lifecycleState",
	"channel",
	"status",
	"completionSource",
	"fd",
	"inode",
	"count",
]);

function record(value: unknown): Record<string, unknown> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}
function text(value: unknown): string | undefined {
	return typeof value === "string" && value.length <= 1024 ? value : undefined;
}
function integer(value: unknown): number | undefined {
	return typeof value === "number" && Number.isSafeInteger(value) ? value : undefined;
}
function decimal(value: unknown): string | undefined {
	return typeof value === "string" && /^(0|[1-9]\d{0,19})$/.test(value) ? value : undefined;
}
function ns(value: unknown): bigint | undefined {
	const valid = decimal(value);
	return valid === undefined || BigInt(valid) > 18_446_744_073_709_551_615n ? undefined : BigInt(valid);
}
function namespace(value: unknown): string | undefined {
	if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return String(value);
	if (typeof value !== "string") return undefined;
	return /^[1-9]\d{0,19}$/.test(value) ? value : /^pid:\[([1-9]\d{0,19})\]$/.exec(value)?.[1];
}
function ticks(value: unknown): string | undefined {
	return typeof value === "string" ? decimal(value.replace(/^proc:/, "")) : undefined;
}
function before(a: Row, b: Row): boolean {
	if (a.source !== b.source) return false;
	if (a.source === "application") {
		const observer = applicationClock(a);
		if (observer === undefined || observer !== applicationClock(b)) return false;
	}
	return a.time !== undefined && b.time !== undefined && a.time < b.time;
}
function applicationClock(row: Row): string | undefined {
	const data = row.data;
	const original = ["observerPid", "observerProcessStartId", "observerPidNamespace", "observerBoottimeOffsetNs"].some(
		(key) => data[key] !== undefined,
	);
	if (
		!original &&
		!(
			integer(data.ownerPid) === integer(data.producerPid) &&
			integer(data.ownerPid) !== undefined &&
			ticks(data.ownerProcessStartId) !== undefined &&
			ticks(data.ownerProcessStartId) === ticks(data.producerStartId)
		)
	)
		return undefined;
	const pid = integer(original ? data.observerPid : data.producerPid);
	const start = ticks(original ? data.observerProcessStartId : data.producerStartId);
	const pidNamespace = namespace(original ? data.observerPidNamespace : data.producerPidNamespace);
	const offset = original ? data.observerBoottimeOffsetNs : data.producerBoottimeOffsetNs;
	if (
		pid === undefined ||
		pid <= 0 ||
		start === undefined ||
		!pidNamespace ||
		typeof offset !== "string" ||
		!/^-?(0|[1-9]\d{0,19})$/.test(offset)
	)
		return undefined;
	return JSON.stringify([pid, start, pidNamespace, String(BigInt(offset))]);
}
function sameTask(row: Row, tid: unknown, start: unknown, prefix = ""): boolean {
	return row.data[`${prefix}init_tid`] === tid && row.data[`${prefix}start_boottime_ns`] === start;
}

function admittedOomContract(platform: CausalPlatformIdentity | undefined, bootId: string): boolean {
	const contract = record(platform?.oomContextContract);
	return (
		platform?.bootId === bootId &&
		contract?.verified === true &&
		contract.kind === "x86_non_rt_preempt_count" &&
		contract.machine === "x86_64" &&
		typeof contract.kernelRelease === "string" &&
		contract.kernelRelease.trim().length > 0 &&
		contract.kernelRelease.length <= 256 &&
		typeof contract.kernelConfigSha256 === "string" &&
		/^[a-fA-F0-9]{64}$/.test(contract.kernelConfigSha256) &&
		contract.preemptCount === true &&
		contract.preemptRt === false &&
		Object.keys(contract).length === 7
	);
}

function oomTaskContext(value: unknown): boolean {
	const count = integer(value);
	// Linux non-RT x86 PREEMPT_COUNT: low byte must show preemption disabled;
	// reject NMI, hard IRQ and serving-softirq contexts, not bottom-half disable.
	return count !== undefined && count > 0 && count <= 0x7fffffff && (count & 0xff) !== 0 && (count & 0xff0100) === 0;
}

function oomOriginChain(
	probes: Row[],
	generations: Row[],
	identity: ProcessIdentity,
	exit: Row,
	taskMatches: (row: Row, prefix?: string) => boolean,
): Row[] | undefined {
	const fresh = generations.filter((row) => row.data.result === 0);
	if (fresh.length !== 1) return undefined;
	const evidence = new Set<Row>();
	for (const generation of generations) {
		const d = generation.data;
		// Trace result 1 is ignored; 2 is already pending. Neither is a new kill.
		if (
			d.signal !== 9 ||
			d.code !== 128 ||
			d.group !== 1 ||
			d.call_time_ns !== "0" ||
			![0, 1, 2].includes(integer(d.result) ?? -1) ||
			(generation !== fresh[0] && !before(fresh[0], generation)) ||
			!oomTaskContext(d.oom_preempt_count)
		)
			return undefined;
		const sameContext = (row: Row) => sameTask(row, d.context_init_tid, d.context_start_boottime_ns, "context_");
		const entries = probes.filter((row) => row.event === "oom_kill_enter" && row.data.time_ns === d.oom_call_time_ns);
		const sends = probes.filter((row) => row.event === "oom_signal_enter" && row.data.time_ns === d.oom_send_time_ns);
		if (entries.length !== 1 || sends.length !== 1) return undefined;
		const entry = entries[0];
		const send = sends[0];
		if (
			!sameContext(entry) ||
			!sameContext(send) ||
			(integer(d.context_init_tid) ?? 0) <= 0 ||
			(ns(d.context_start_boottime_ns) ?? 0n) <= 0n ||
			entry.time === undefined ||
			entry.time < ns(d.context_start_boottime_ns)! ||
			entry.data.selected_init_pid !== identity.initPid ||
			entry.data.selected_process_start_boottime_ns !== identity.start ||
			entry.data.scope !== "selected_thread_group" ||
			entry.data.context_contract !== "x86_non_rt_preempt_count" ||
			send.data.oom_call_time_ns !== entry.data.time_ns ||
			!taskMatches(send, "target_") ||
			!sameTask(send, d.target_init_tid, d.target_start_boottime_ns, "target_") ||
			send.data.signal !== 9 ||
			send.data.code !== 128 ||
			send.data.pid_type !== 1 ||
			!oomTaskContext(send.data.preempt_count) ||
			!before(entry, send) ||
			!before(send, generation)
		)
			return undefined;
		const sendReturns = probes.filter(
			(row) => row.event === "oom_signal_return" && row.data.call_time_ns === send.data.time_ns && sameContext(row),
		);
		const returns = probes.filter(
			(row) => row.event === "oom_kill_return" && row.data.call_time_ns === entry.data.time_ns && sameContext(row),
		);
		if (sendReturns.length !== 1 || returns.length !== 1) return undefined;
		const sendReturn = sendReturns[0];
		const returned = returns[0];
		if (
			sendReturn.data.oom_call_time_ns !== entry.data.time_ns ||
			sendReturn.data.context_valid !== 1 ||
			sendReturn.data.result !== 0 ||
			returned.data.context_valid !== 1 ||
			!before(generation, sendReturn) ||
			!before(sendReturn, returned)
		)
			return undefined;
		if (
			probes.some(
				(row) => row.event === "oom_kill_enter" && sameContext(row) && before(entry, row) && before(row, returned),
			)
		)
			return undefined;
		for (const row of [entry, send, generation, sendReturn, returned]) evidence.add(row);
	}
	// An orphaned selected call/send can hide another generation. Do not accept
	// just the intact first sequence when a later OOM sequence is incomplete.
	if (
		probes.some(
			(row) =>
				before(row, exit) &&
				!evidence.has(row) &&
				((row.event === "oom_kill_enter" &&
					row.data.selected_init_pid === identity.initPid &&
					row.data.selected_process_start_boottime_ns === identity.start) ||
					(row.event === "oom_signal_enter" && taskMatches(row, "target_"))),
		)
	)
		return undefined;
	return [...evidence];
}

function originalFields(data: Record<string, unknown>): Record<string, unknown> {
	// The envelope clock is journal-queue time. The serialized event retains its
	// source observation clock; never substitute journal reception time for it.
	const value = record(record(data.details)?.value);
	const properties = value?.$diagnosticType === "object" ? value.properties : undefined;
	if (!Array.isArray(properties) || properties.length > 128) return data;
	const result = { ...data };
	for (const property of properties) {
		if (Array.isArray(property) && property.length === 2 && FACT_FIELDS.has(property[0])) {
			const field = property[1];
			if (typeof field === "string" || typeof field === "number" || typeof field === "boolean" || field === null)
				result[property[0]] = field;
		}
	}
	return result;
}

/** Pure, bounded analysis of observed records. No lifecycle or filesystem actions. */
export function classifyCausalCapture(input: {
	target: CausalTarget;
	occurrences: readonly CausalOccurrence[];
	platform?: CausalPlatformIdentity;
}): CausalClassification {
	const { target, platform } = input;
	const gaps = new Set<string>();
	const facts = new Map<string, CausalFact>();
	const support = new Set<string>();
	const rows: Row[] = [];
	const seen = new Map<string, string>();
	const conflicts = new Set<string>();
	let bytes = 0;
	const add = (row: Row, supporting = false) => {
		if (facts.size >= MAX_FACTS && !facts.has(row.id)) {
			gaps.add("output_fact_limit");
			return;
		}
		const fields: CausalFact["fields"] = {};
		for (const key of FACT_FIELDS) {
			const value = row.data[key];
			if (
				(typeof value === "string" && value.length <= 1024) ||
				(typeof value === "number" && Number.isSafeInteger(value)) ||
				typeof value === "boolean" ||
				value === null
			)
				fields[key] = value;
		}
		facts.set(row.id, { occurrenceId: row.id, event: row.event, fields });
		if (supporting) support.add(row.id);
	};
	if (!target.bootId || target.bootId.length > 128) gaps.add("target_boot_identity_unavailable");
	if (input.occurrences.length > MAX_ROWS) gaps.add("input_row_limit");
	for (const occurrence of input.occurrences.slice(0, MAX_ROWS)) {
		if (!occurrence.id || occurrence.id.length > 512) {
			gaps.add("occurrence_identity_unavailable");
			continue;
		}
		const length =
			typeof occurrence.payload === "string" ? Buffer.byteLength(occurrence.payload) : occurrence.payload.byteLength;
		if (length > MAX_PAYLOAD) {
			gaps.add("input_payload_limit");
			continue;
		}
		bytes += length;
		if (bytes > MAX_BYTES) {
			gaps.add("input_byte_limit");
			break;
		}
		try {
			const raw =
				typeof occurrence.payload === "string"
					? occurrence.payload
					: Buffer.from(occurrence.payload).toString("utf8");
			const occurrenceIdentity = JSON.stringify([occurrence.source, occurrence.bootId, raw]);
			const prior = seen.get(occurrence.id);
			if (prior !== undefined) {
				if (prior !== occurrenceIdentity) {
					conflicts.add(occurrence.id);
					gaps.add("occurrence_identity_conflict");
				}
				continue;
			}
			seen.set(occurrence.id, occurrenceIdentity);
			let data = record(JSON.parse(raw));
			if (!data) {
				gaps.add("malformed_record");
				continue;
			}
			let boot = occurrence.bootId;
			if (occurrence.source === "journal") {
				if (boot !== undefined && boot !== data._BOOT_ID) {
					gaps.add("record_boot_identity_conflict");
					continue;
				}
				boot = text(data._BOOT_ID);
				data = typeof data.MESSAGE === "string" ? record(JSON.parse(data.MESSAGE)) : undefined;
			}
			if (!boot) {
				gaps.add("record_boot_identity_unavailable");
				continue;
			}
			if (boot !== target.bootId) continue;
			if (!data) {
				gaps.add("malformed_record");
				continue;
			}
			const source =
				occurrence.source === "probe" || typeof data.event === "string" || data.type === "lost_events"
					? "probe"
					: "application";
			if (source === "application") {
				if (data.schema !== "prime-agent.diagnostic.v1") continue;
				data = originalFields(data);
				if ((integer(record(data.loss)?.droppedRecords) ?? 0) > 0) gaps.add("application_records_dropped");
			}
			const event = text(
				source === "probe" ? (data.event ?? (data.type === "lost_events" ? data.type : undefined)) : data.type,
			);
			if (!event) continue;
			const row: Row = {
				id: occurrence.id,
				source,
				data,
				event,
				time: ns(source === "probe" ? data.time_ns : data.monotonicNs),
			};
			if (event === "coverage_gap" || event === "lost_events") {
				const socketOnly =
					event === "coverage_gap" && (data.kind === "socket_capacity" || data.kind === "socket_call_capacity");
				gaps.add(socketOnly ? "provider_socket_coverage_gap" : "provider_coverage_gap");
				add(row);
			}
			if (event === "ancestry_admitted") gaps.add("pre_admission_history_unavailable");
			rows.push(row);
		} catch {
			gaps.add("malformed_record");
		}
	}
	const valid = rows.filter((row) => !conflicts.has(row.id));
	const probes = valid.filter((row) => row.source === "probe");
	const identities = probes.filter((row) => row.event === "task_identity");
	let identity: ProcessIdentity | undefined;
	if (integer(target.initPid) !== undefined && target.initPid! > 0 && (ns(target.processStartBoottimeNs) ?? 0n) > 0n) {
		identity = { initPid: target.initPid!, start: target.processStartBoottimeNs! };
	} else if (target.pid !== undefined && namespace(target.pidNamespace) && ticks(target.processStartTicks)) {
		if (
			platform?.bootId !== target.bootId ||
			platform.procReaderBoottimeOffsetNs !== "0" ||
			!Number.isSafeInteger(platform.clockTicksPerSecond) ||
			platform.clockTicksPerSecond <= 0 ||
			platform.clockTicksPerSecond > 1_000_000
		) {
			gaps.add("process_clock_identity_unavailable");
		} else {
			const matches = identities.filter((row) => {
				const start = ns(row.data.process_start_boottime_ns);
				return (
					row.data.subject_pid === target.pid &&
					namespace(row.data.pidns_inode) === namespace(target.pidNamespace) &&
					start !== undefined &&
					String((start * BigInt(platform.clockTicksPerSecond)) / 1_000_000_000n) ===
						ticks(target.processStartTicks)
				);
			});
			const candidates = new Map(
				matches
					.filter((row) => integer(row.data.init_pid) !== undefined)
					.map((row) => [`${row.data.init_pid}:${row.data.process_start_boottime_ns}`, row]),
			);
			if (candidates.size === 1) {
				const row = [...candidates.values()][0];
				identity = { initPid: Number(row.data.init_pid), start: String(row.data.process_start_boottime_ns) };
				add(row, true);
			} else gaps.add(candidates.size ? "process_generation_ambiguous" : "process_identity_not_observed");
		}
	}
	const taskMatches = (row: Row, prefix = ""): boolean => {
		if (!identity || row.data[`${prefix}init_pid`] !== identity.initPid) return false;
		const tid = row.data[`${prefix}init_tid`];
		const start = row.data[`${prefix}start_boottime_ns`];
		const startNs = ns(start);
		if (startNs === undefined || row.time === undefined || row.time < startNs) return false;
		// A final nonleader can outlive its original task_identity window. New
		// exit records carry the group leader generation directly from task_struct.
		if (prefix === "" && row.event === "process_exit" && row.data.process_start_boottime_ns !== undefined) {
			return (
				row.data.process_start_boottime_ns === identity.start &&
				startNs >= BigInt(identity.start) &&
				(integer(tid) ?? 0) > 0 &&
				(integer(row.data.subject_pid) ?? 0) > 0 &&
				namespace(row.data.pidns_inode) !== undefined &&
				(tid !== identity.initPid || start === identity.start)
			);
		}
		if (tid === identity.initPid && start === identity.start) return true;
		return identities.some(
			(item) =>
				item.data.init_pid === identity.initPid &&
				item.data.init_tid === tid &&
				item.data.start_boottime_ns === start &&
				item.data.process_start_boottime_ns === identity.start &&
				item.time !== undefined &&
				row.time !== undefined &&
				item.time <= row.time,
		);
	};
	const appRows = valid.filter((row) => {
		if (row.source !== "application") return false;
		const d = row.data;
		if (target.kernelInstanceId !== undefined) {
			if (
				d.kernelInstanceId !== target.kernelInstanceId ||
				(target.kernelGeneration !== undefined &&
					d.kernelGeneration !== undefined &&
					d.kernelGeneration !== target.kernelGeneration)
			)
				return false;
			if (target.pid !== undefined && d.kernelPid !== target.pid) return false;
			if (
				target.processStartTicks !== undefined &&
				ticks(d.kernelProcessStartId) !== ticks(target.processStartTicks)
			)
				return false;
			const observerNamespace = d.observerPidNamespace ?? d.producerPidNamespace;
			if (
				observerNamespace !== undefined &&
				target.pidNamespace !== undefined &&
				namespace(observerNamespace) !== namespace(target.pidNamespace)
			)
				return false;
			return true;
		}
		return false;
	});
	const applicationClocks = new Set(appRows.map(applicationClock));
	if (applicationClocks.delete(undefined)) gaps.add("application_observer_clock_unavailable");
	if (applicationClocks.size > 1) gaps.add("application_observer_clock_conflict");
	for (const row of appRows.filter((row) => row.event === "kernel_lifecycle_intent")) add(row);
	const nativeExits = probes.filter(
		(row) =>
			row.event === "process_exit" &&
			row.data.group_dead === 1 &&
			taskMatches(row) &&
			row.time !== undefined &&
			integer(row.data.raw_exit_code) !== undefined &&
			Number(row.data.raw_exit_code) >= 0,
	);
	const appExits = appRows.filter(
		(row) =>
			row.event === "kernel_process_exit_observed" ||
			(row.event === "kernel_unexpected_exit" && row.data.reason === "process_exit"),
	);
	const parentUnavailable = appRows.filter(
		(row) => row.event === "kernel_unexpected_exit" && row.data.reason === "forkserver_unavailable",
	);
	for (const unavailable of parentUnavailable) {
		add(unavailable, true);
		gaps.add("forkserver_dependency_unavailable");
		gaps.add("forkserver_kernel_relationship_not_observed");
		for (const row of valid.filter(
			(row) =>
				row.source === "application" &&
				row.event === "forkserver_lifecycle" &&
				row.data.producerId === unavailable.data.producerId &&
				typeof row.data.producerId === "string",
		))
			add(row);
	}
	const result: CausalClassification = {
		status: nativeExits.length || appExits.length ? "process_exited" : "unresolved",
		cause: "unresolved",
		supportingOccurrenceIds: [],
		facts: [],
		missingEvidence: [],
		coverageComplete: false,
	};
	for (const row of [...nativeExits, ...appExits]) add(row, true);
	if (nativeExits.length > 1) gaps.add("multiple_process_exits_observed");
	const exit = nativeExits.length === 1 ? nativeExits[0] : undefined;
	if (exit) {
		const rawExit = Number(exit.data.raw_exit_code);
		const signal = rawExit & 0x7f;
		result.mechanism = signal > 0 && signal < 0x7f ? "signal_exit" : "exit_status";
		const processGenerations = probes.filter(
			(row) => row.event === "signal_generate" && taskMatches(row, "target_") && before(row, exit),
		);
		const generates = processGenerations.filter((row) => row.data.signal === signal);
		const processDeliveries = probes.filter(
			(row) => row.event === "signal_deliver" && taskMatches(row) && before(row, exit),
		);
		const deliveries = processDeliveries.filter((row) => row.data.signal === signal);
		for (const row of [...generates, ...processDeliveries]) add(row);
		const generation = generates.length === 1 ? generates[0] : undefined;
		// Linux complete_signal can store SIGTERM as group_exit_code, then queue
		// SIGKILL to threads. get_signal traces 9; do_group_exit preserves 15.
		// Require multiple observed thread pairs instead of fabricating delivery 15.
		const groupExitPairs =
			rawExit === 15 &&
			generation?.data.group === 1 &&
			deliveries.length === 0 &&
			!processGenerations.some((row) => row !== generation && before(generation, row))
				? processDeliveries.flatMap((delivery) => {
						if (delivery.data.signal !== 9 || delivery.data.code !== 0 || !before(generation, delivery))
							return [];
						const threadExit = probes.find(
							(row) =>
								row.event === "process_exit" &&
								taskMatches(row) &&
								row.data.raw_exit_code === 15 &&
								sameTask(row, delivery.data.init_tid, delivery.data.start_boottime_ns) &&
								before(delivery, row) &&
								row.time! <= exit.time!,
						);
						return threadExit ? [{ delivery, threadExit }] : [];
					})
				: [];
		const inferredGroupExit =
			new Set(groupExitPairs.map(({ delivery }) => `${delivery.data.init_tid}:${delivery.data.start_boottime_ns}`))
				.size >= 2;
		const victims = probes.filter((row) => row.event === "oom_victim" && taskMatches(row) && before(row, exit));
		for (const victim of victims) add(victim, true);
		const oomCalls = new Set(
			generates.map((row) => row.data.oom_call_time_ns).filter((value) => (ns(value) ?? 0n) > 0n),
		);
		const oomSends = new Set(
			generates.map((row) => row.data.oom_send_time_ns).filter((value) => (ns(value) ?? 0n) > 0n),
		);
		for (const row of probes.filter(
			(row) =>
				row.event.startsWith("oom_") &&
				((row.data.selected_init_pid === identity?.initPid &&
					row.data.selected_process_start_boottime_ns === identity?.start) ||
					taskMatches(row, "target_") ||
					oomCalls.has(row.data.time_ns) ||
					oomCalls.has(row.data.call_time_ns) ||
					oomCalls.has(row.data.oom_call_time_ns) ||
					oomSends.has(row.data.call_time_ns)),
		))
			add(row);
		const oomObserved = victims.length > 0 || oomCalls.size > 0;
		const oomContract = admittedOomContract(platform, target.bootId);
		const oomChain =
			rawExit === 9 && identity && oomContract
				? oomOriginChain(probes, generates, identity, exit, taskMatches)
				: undefined;
		if (oomObserved && !oomContract) gaps.add("oom_platform_contract_unverified");
		// Linux can also mark a task already exiting or with SIGKILL pending.
		if (victims.length && !oomChain) gaps.add("oom_victim_mark_does_not_establish_kill_origin");
		if (oomObserved && !oomChain) gaps.add("oom_origin_chain_unresolved");
		if (signal > 0 && signal < 0x7f) {
			const delivered = generates.filter(
				(generation) =>
					generation.data.result === 0 &&
					deliveries.some(
						(delivery) =>
							before(generation, delivery) &&
							delivery.data.code === generation.data.code &&
							sameTask(delivery, generation.data.target_init_tid, generation.data.target_start_boottime_ns),
					),
			);
			const faults = delivered.filter(
				(row) =>
					[4, 5, 7, 8, 11, 31].includes(signal) &&
					(integer(row.data.code) ?? 0) > 0 &&
					row.data.call_time_ns === "0",
			);
			if (oomChain) {
				result.cause = "oom_kill";
				for (const row of oomChain) add(row, true);
				for (const row of deliveries) add(row, true);
				if (!deliveries.length) gaps.add("signal_delivery_not_observed");
			} else if (faults.length === 1 && generates.length === 1 && deliveries.length === 1) {
				result.cause = "native_fault";
				add(faults[0], true);
				for (const row of deliveries) add(row, true);
			} else if (
				generates.length === 1 &&
				generates[0].data.result === 0 &&
				(integer(generates[0].data.code) ?? 1) <= 0 &&
				(signal === 9 || (delivered.length === 1 && deliveries.length === 1) || inferredGroupExit) &&
				!victims.length
			) {
				const generation = generates[0];
				const calls = probes.filter(
					(row) =>
						row.event === "signal_call" &&
						[1, 2, 3, 4].includes(integer(row.data.kind) ?? 0) &&
						(integer(row.data.context_init_pid) ?? 0) > 0 &&
						(integer(row.data.context_init_tid) ?? 0) > 0 &&
						(ns(row.data.context_start_boottime_ns) ?? 0n) > 0n &&
						row.data.time_ns === generation.data.call_time_ns &&
						sameTask(
							row,
							generation.data.context_init_tid,
							generation.data.context_start_boottime_ns,
							"context_",
						) &&
						row.data.context_init_pid === generation.data.context_init_pid &&
						row.data.signal === signal &&
						before(row, generation),
				);
				const call = calls.length === 1 ? calls[0] : undefined;
				const returned =
					call &&
					probes.find(
						(row) =>
							row.event === "signal_return" &&
							row.data.call_time_ns === call.data.time_ns &&
							sameTask(row, call.data.context_init_tid, call.data.context_start_boottime_ns, "context_") &&
							row.data.kind === call.data.kind &&
							row.data.result === 0 &&
							before(generation, row),
					);
				if (call && returned) {
					result.cause = "user_signal";
					result.initiator = {
						initPid: integer(call.data.context_init_pid),
						initTid: integer(call.data.context_init_tid),
						startBoottimeNs: decimal(call.data.context_start_boottime_ns),
						syscallKind: integer(call.data.kind),
					};
					for (const row of [call, generation, returned, ...deliveries]) add(row, true);
					if (inferredGroupExit) {
						gaps.add("sigterm_group_exit_inferred_from_thread_observations");
						for (const { delivery, threadExit } of groupExitPairs) {
							add(delivery, true);
							add(threadExit, true);
							const threadIdentity = identities.find(
								(row) =>
									sameTask(row, delivery.data.init_tid, delivery.data.start_boottime_ns) &&
									row.data.init_pid === identity?.initPid &&
									row.data.process_start_boottime_ns === identity?.start &&
									before(row, delivery),
							);
							if (threadIdentity) add(threadIdentity, true);
						}
					}
				} else gaps.add("signal_sender_syscall_chain_unavailable");
				if (!deliveries.length) gaps.add("signal_delivery_not_observed");
			} else {
				if (victims.length && generates.some((row) => row.data.call_time_ns !== "0"))
					gaps.add("competing_oom_and_user_signal");
				if (deliveries.length > 1) gaps.add("multiple_signal_deliveries_unresolved");
				if (generates.length > 1 || generates.some((row) => row.data.result !== 0))
					gaps.add("signal_generation_ambiguous_or_coalesced");
				if (!deliveries.length) gaps.add("signal_delivery_not_observed");
			}
		}
		const forks = probes.filter(
			(row) =>
				row.event === "process_fork" &&
				row.data.child_init_pid === identity?.initPid &&
				row.data.child_init_tid === identity?.initPid &&
				row.data.child_start_boottime_ns === identity?.start &&
				before(row, exit),
		);
		for (const fork of forks) {
			const parentExit = probes.find(
				(row) =>
					row.event === "process_exit" &&
					row.data.group_dead === 1 &&
					row.data.init_pid === fork.data.parent_init_pid &&
					sameTask(row, fork.data.parent_init_tid, fork.data.parent_start_boottime_ns) &&
					before(fork, row) &&
					before(row, exit),
			);
			if (parentExit) {
				add(fork, true);
				add(parentExit, true);
				if (result.cause === "unresolved") result.mechanism = "parent_exit_preceded_child_exit";
				gaps.add("parent_exit_does_not_establish_child_teardown_initiator");
			}
		}
	}
	for (const close of probes.filter((row) => row.event === "socket_close" && taskMatches(row))) {
		add(close);
		const completed = probes.find(
			(row) =>
				row.event === "socket_lifecycle_result" &&
				row.data.kind === 5 &&
				row.data.init_pid === close.data.init_pid &&
				row.data.init_tid === close.data.init_tid &&
				row.data.fd === close.data.fd &&
				row.data.call_time_ns === close.data.time_ns &&
				before(close, row),
		);
		if (completed) add(completed);
		gaps.add("socket_close_does_not_establish_remote_channel_loss");
	}
	// App sequence ordering is confined to the original observer clock and kernel.
	// It describes a recorded shutdown sequence, not a guessed native mechanism.
	if (result.cause === "unresolved" && appExits.length) {
		for (const observedExit of appExits) {
			const intent = appRows.find(
				(row) =>
					row.event === "kernel_lifecycle_intent" &&
					["shutdown", "kill", "dispose", "dispose_sync"].includes(String(row.data.operation)) &&
					row.data.kernelGeneration === observedExit.data.kernelGeneration &&
					row.data.kernelGeneration !== undefined &&
					text(row.data.caller) &&
					text(row.data.reason) &&
					before(row, observedExit) &&
					observedExit.data.lifecycleState === "shutdown",
			);
			if (intent) {
				result.cause = "application_shutdown_sequence";
				result.initiator = { caller: text(intent.data.caller), reason: text(intent.data.reason) };
				gaps.add("native_shutdown_mechanism_unresolved");
				add(intent, true);
				add(observedExit, true);
				break;
			}
		}
	}
	if (result.status !== "process_exited") {
		gaps.add("process_exit_not_observed");
		const trackingLoss = appRows.filter(
			(row) => row.data.observation === "shell_reply_unavailable" && row.data.reason === "tracking_capacity",
		);
		if (trackingLoss.length) {
			gaps.add("protocol_tracking_capacity");
			for (const row of trackingLoss) add(row);
		}
		const unavailable = appRows.filter(
			(row) =>
				row.event === "kernel_channel_fault" ||
				(row.event === "kernel_protocol_observation" &&
					["heartbeat_unavailable", "shell_unavailable", "shell_reply_unavailable"].includes(
						String(row.data.observation),
					) &&
					row.data.reason !== "tracking_capacity"),
		);
		const complete = appRows.find(
			(row) => row.data.observation === "execution_completed" && row.data.completionSource === "iopub_idle",
		);
		const busy = appRows.find((row) => row.data.observation === "iopub_busy");
		const heartbeat =
			busy &&
			appRows.find(
				(row) =>
					row.data.observation === "heartbeat_echo" &&
					row.data.kernelGeneration === busy.data.kernelGeneration &&
					before(busy, row),
			);
		if (parentUnavailable.length) {
			result.status = "parent_unavailable";
		} else if (unavailable.length) {
			result.status = "channel_unavailable";
			for (const row of unavailable) add(row, true);
			gaps.add("channel_unavailability_cause_unresolved");
		} else if (complete) {
			result.status = "execution_completed";
			add(complete, true);
		} else if (busy && heartbeat) {
			result.status = "execution_observed_healthy";
			add(busy, true);
			add(heartbeat, true);
			gaps.add("liveness_only_at_observed_protocol_events");
		}
	}
	if ([...gaps].some((gap) => CAUSAL_COVERAGE_GAPS.has(gap))) {
		result.cause = "unresolved";
		delete result.initiator;
		gaps.add("causal_coverage_incomplete");
		gaps.add("bounded_capture_cannot_exclude_competing_evidence");
	}
	if (result.cause === "unresolved") gaps.add("causal_chain_incomplete");
	result.facts = [...facts.values()];
	result.supportingOccurrenceIds = [...support];
	result.missingEvidence = [...gaps].sort();
	return result;
}
