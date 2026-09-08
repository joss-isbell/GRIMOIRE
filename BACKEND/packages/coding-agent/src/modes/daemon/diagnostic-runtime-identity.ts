import type {
	EvidenceOccurrence,
	EvidenceRuntimeProvider,
	EvidenceRuntimeRole,
} from "./diagnostic-evidence-store-protocol.js";

function record(value: unknown): Record<string, unknown> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}
function text(value: unknown, max = 128): string | undefined {
	return typeof value === "string" && value.length > 0 && Buffer.byteLength(value) <= max && !value.includes("\0")
		? value
		: undefined;
}
function positive(value: unknown): value is number {
	return Number.isSafeInteger(value) && Number(value) > 0;
}
function decimal(value: unknown): string | undefined {
	return typeof value === "string" && /^(0|[1-9]\d{0,19})$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n
		? value
		: undefined;
}
export function validRuntimeClock(value: number): boolean {
	return Number.isSafeInteger(value) && value > 0 && value <= 1_000_000;
}
export function runtimeJournal(occurrence: EvidenceOccurrence):
	| {
			row: Record<string, unknown>;
			event: Record<string, unknown>;
	  }
	| undefined {
	if (occurrence.kind !== "journal.json") return undefined;
	try {
		const row = record(JSON.parse(Buffer.from(occurrence.payload).toString("utf8")));
		const event = typeof row?.MESSAGE === "string" ? record(JSON.parse(row.MESSAGE)) : undefined;
		return row && event ? { row, event } : undefined;
	} catch {
		return undefined;
	}
}

/** Sparse role evidence only. A name or descendant relationship never establishes a runtime role. */
export function runtimeRoleFromOccurrence(
	occurrence: EvidenceOccurrence,
	clockTicksPerSecond: number,
): EvidenceRuntimeRole | "invalid_anchor" | undefined {
	const parsed = runtimeJournal(occurrence);
	if (!parsed || parsed.event.schema !== "prime-agent.diagnostic.v1" || typeof parsed.event.event === "string")
		return undefined;
	const { row, event } = parsed;
	let role: EvidenceRuntimeRole["role"];
	let instance: unknown;
	let pid: unknown;
	let start: unknown;
	let namespace: unknown;
	let offset: unknown;
	if (event.type === "supervisor_started") {
		role = "supervisor";
		instance = event.producerId;
		pid = event.producerPid;
		start = event.producerStartId;
		namespace = event.producerPidNamespace;
		offset = event.producerBoottimeOffsetNs;
	} else if (event.type === "worker_process_spawned") {
		role = "worker";
		instance = event.workerId;
		pid = event.workerPid;
		start = event.workerProcessStartId;
		namespace = event.producerPidNamespace;
		offset = event.producerBoottimeOffsetNs;
	} else if (event.type === "kernel_process_started") {
		role = "kernel";
		instance = event.kernelInstanceId;
		pid = event.kernelPid;
		start = event.kernelProcessStartId;
		namespace = event.observerPidNamespace;
		offset = event.observerBoottimeOffsetNs;
	} else if (event.type === "forkserver_lifecycle" && event.phase === "peer_authenticated") {
		role = "forkserver";
		instance = event.forkserverInstanceId;
		pid = event.forkserverPid;
		start = event.forkserverProcessStartId;
		namespace = event.observerPidNamespace;
		offset = event.observerBoottimeOffsetNs;
	} else return undefined;
	const bootId = text(row._BOOT_ID);
	const roleInstanceId = text(instance);
	const pidNamespace = text(namespace, 64);
	const processStartTicks = decimal(typeof start === "string" ? start.replace(/^proc:/, "") : start);
	if (
		!validRuntimeClock(clockTicksPerSecond) ||
		!bootId ||
		!roleInstanceId ||
		!positive(pid) ||
		!pidNamespace ||
		!/^pid:\[[1-9]\d{0,19}\]$/.test(pidNamespace) ||
		!processStartTicks ||
		BigInt(processStartTicks) === 0n ||
		offset !== "0"
	)
		return "invalid_anchor";
	return {
		role,
		roleInstanceId,
		bootId,
		pidNamespace,
		pid,
		processStartTicks,
		clockTicksPerSecond,
		observerBoottimeOffsetNs: "0",
		proof: { source: occurrence.source, occurrenceId: occurrence.id },
	};
}

/** Direct exit identity is required even for a final nonleader thread. */
export function runtimeExitFromOccurrence(occurrence: EvidenceOccurrence, provider: EvidenceRuntimeProvider) {
	const parsed = runtimeJournal(occurrence);
	if (
		!parsed ||
		parsed.row.SYSLOG_IDENTIFIER !== provider.identifier ||
		parsed.row._UID !== "0" ||
		parsed.row._EXE !== "/usr/bin/bpftrace" ||
		parsed.event.event !== "process_exit" ||
		parsed.event.group_dead !== 1
	)
		return undefined;
	const { row, event } = parsed;
	const bootId = text(row._BOOT_ID);
	const processStart = decimal(event.process_start_boottime_ns);
	const taskStart = decimal(event.start_boottime_ns);
	const time = decimal(event.time_ns);
	if (
		!validRuntimeClock(provider.clockTicksPerSecond) ||
		!bootId ||
		!positive(event.init_pid) ||
		!positive(event.init_tid) ||
		!positive(event.subject_pid) ||
		!positive(event.pidns_inode) ||
		!processStart ||
		BigInt(processStart) === 0n ||
		!taskStart ||
		!time ||
		BigInt(processStart) > BigInt(taskStart) ||
		BigInt(taskStart) > BigInt(time) ||
		(event.init_pid === event.init_tid && processStart !== taskStart) ||
		!Number.isSafeInteger(event.raw_exit_code) ||
		Number(event.raw_exit_code) < 0 ||
		Number(event.raw_exit_code) > 65535
	)
		return { invalid: true as const, bootId };
	return {
		invalid: false as const,
		bootId,
		pidNamespace: `pid:[${event.pidns_inode}]`,
		pid: event.subject_pid,
		processStartTicks: String((BigInt(processStart) * BigInt(provider.clockTicksPerSecond)) / 1_000_000_000n),
		initPid: event.init_pid,
		processStartBoottimeNs: processStart,
		rawExitCode: Number(event.raw_exit_code),
	};
}
