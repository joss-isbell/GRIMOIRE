import { closeSync, constants as fsConstants, fstatSync, opendirSync, openSync, readSync } from "node:fs";
import { performance } from "node:perf_hooks";

export const INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DEADLINE_MS = 40;
export const INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_BYTE_BUDGET = 4 * 1024 * 1024;
export const INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_STAT_BYTES = 128 * 1024;
export const INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DIRECTORY_ENTRIES = 65_536;
export const INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS = 4_096;
export const INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_SUBJECTS = 256;
export const INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_TARGET_RECHECK_RESERVE =
	INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_STAT_BYTES + 1;

const READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
const PROCESS_START_ID = /^proc:([0-9]+)$/;
const POSITIVE_PID = /^[1-9][0-9]*$/;

export type IncidentRecorderLiveDescendantEnumerationReason =
	| "insufficient_identity_budget"
	| "target_initial_deadline"
	| "target_initial_unavailable"
	| "target_initial_truncated"
	| "target_initial_malformed"
	| "target_recheck_deadline"
	| "target_recheck_unavailable"
	| "target_recheck_truncated"
	| "target_identity_changed"
	| "deadline"
	| "byte_budget"
	| "directory_population_limit"
	| "numeric_population_limit"
	| "subject_limit"
	| "stat_unavailable"
	| "stat_truncated"
	| "stat_malformed"
	| "identity_changed"
	| "candidate_identity_changed"
	| "parent_changed"
	| "parent_identity_unresolved"
	| "temporally_impossible_parent"
	| "parent_not_transitive";

export type IncidentRecorderLiveDescendantReceiptState =
	| "admitted"
	| "vanished"
	| "unavailable"
	| "malformed"
	| "identity_changed"
	| "parent_changed"
	| "parent_identity_unresolved"
	| "temporally_impossible_parent"
	| "not_transitive";

export interface IncidentRecorderLiveDescendantEnumerationFileSystem {
	opendirSync(path: string): {
		readSync(): { name: string } | null;
		closeSync(): void;
	};
	openSync(path: string, flags: number): number;
	fstatSync(fd: number): { isFile(): boolean };
	readSync(fd: number, buffer: Buffer, offset: number, length: number, position: number | null): number;
	closeSync(fd: number): void;
}

export interface IncidentRecorderLiveDescendantEnumerationInput {
	captureId: string;
	targetPid: number;
	targetProcessStartId: string;
	deadlineMs?: number;
	byteBudget?: number;
	subjectLimit?: number;
	fileSystem?: IncidentRecorderLiveDescendantEnumerationFileSystem;
	now?: () => number;
}

export interface IncidentRecorderLiveDescendantRawRead {
	sourcePath: string;
	bytes: Buffer;
	readOrdinal: 1 | 2;
}

export interface IncidentRecorderLiveDescendantTarget {
	pid: number;
	processStartId: string;
	state: "stable" | "unverified";
	rawReads?: readonly IncidentRecorderLiveDescendantRawRead[];
}

export interface IncidentRecorderLiveDescendantParent {
	pid: number;
	processStartId: string;
	identityMatch: "same_pass_stable_stat";
}

export interface IncidentRecorderLiveDescendantRelation {
	kind: "observed_ppid_graph_match";
	childPpidStableAcrossReads: true;
	causalParentageProven: false;
}

export interface IncidentRecorderLiveDescendant {
	pid: number;
	processStartId: string;
	parent: IncidentRecorderLiveDescendantParent;
	depth: number;
	relation: IncidentRecorderLiveDescendantRelation;
	rawReads: readonly IncidentRecorderLiveDescendantRawRead[];
}

export interface IncidentRecorderLiveDescendantReceipt {
	pid: number;
	state: IncidentRecorderLiveDescendantReceiptState;
	reason?: IncidentRecorderLiveDescendantEnumerationReason;
	rawReads?: readonly IncidentRecorderLiveDescendantRawRead[];
}

export interface IncidentRecorderLiveDescendantEnumerationResult {
	captureId: string;
	target: IncidentRecorderLiveDescendantTarget;
	descendants: readonly IncidentRecorderLiveDescendant[];
	method: "proc_stat_ppid";
	passState: "complete" | "truncated" | "unavailable";
	reason?: IncidentRecorderLiveDescendantEnumerationReason;
	observationalPassComplete: boolean;
	treeCompleteness: "not_claimed";
	subjectCoverage: "complete_within_observed_population" | "truncated";
	bytesRead: number;
	directoryEntriesSeen: number;
	numericPidsSeen: number;
	attemptedPids: readonly number[];
	receipts: readonly IncidentRecorderLiveDescendantReceipt[];
	nextCursor: null;
}

interface ProcessStat {
	pid: number;
	parentPid: number;
	startTicks: bigint;
}

interface ReadStatResult {
	bytes: Buffer;
	actualBytes: number;
	complete: boolean;
	truncated: boolean;
	deadline: boolean;
	budget: boolean;
	vanished: boolean;
	unavailable: boolean;
}

interface Candidate {
	pid: number;
	parentPid: number;
	startTicks: bigint;
	rawReads: readonly IncidentRecorderLiveDescendantRawRead[];
}

const defaultFileSystem: IncidentRecorderLiveDescendantEnumerationFileSystem = {
	opendirSync,
	openSync,
	fstatSync,
	readSync,
	closeSync,
};

function clamp(value: number | undefined, fallback: number, maximum: number, minimum = 0): number {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	return Math.min(maximum, Math.max(minimum, Math.floor(value)));
}

function assertPid(value: number, field: string): void {
	if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${field} must be a positive PID`);
}

function parseProcessStartId(value: string, field: string): bigint {
	const match = PROCESS_START_ID.exec(value);
	if (!match) throw new TypeError(`${field} must use proc:<ticks>`);
	try {
		return BigInt(match[1]);
	} catch {
		throw new TypeError(`${field} must use safe process start ticks`);
	}
}

function processStartId(ticks: bigint): string {
	return `proc:${ticks.toString()}`;
}

function parseStat(bytes: Buffer): ProcessStat | undefined {
	const text = bytes.toString("utf8");
	const openingParen = text.indexOf("(");
	const closingParen = text.lastIndexOf(")");
	if (openingParen <= 0 || closingParen <= openingParen) return undefined;
	const pidText = text.slice(0, openingParen).trim();
	if (!/^[1-9][0-9]*$/.test(pidText)) return undefined;
	const pid = Number(pidText);
	if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
	const fields = text
		.slice(closingParen + 1)
		.trim()
		.split(/\s+/);
	if (fields.length <= 19 || fields[0]?.length !== 1) return undefined;
	const parentText = fields[1];
	const startText = fields[19];
	if (!parentText || !startText || !/^[0-9]+$/.test(parentText) || !/^[0-9]+$/.test(startText)) return undefined;
	const parentPid = Number(parentText);
	if (!Number.isSafeInteger(parentPid) || parentPid < 0) return undefined;
	try {
		return { pid, parentPid, startTicks: BigInt(startText) };
	} catch {
		return undefined;
	}
}

function sourcePath(pid: number): string {
	return `/proc/${pid}/stat`;
}

function classifyReadError(error: unknown): "vanished" | "unavailable" {
	const code = (error as NodeJS.ErrnoException | undefined)?.code;
	return code === "ENOENT" || code === "ESRCH" ? "vanished" : "unavailable";
}

function readBoundedStat(
	path: string,
	fileSystem: IncidentRecorderLiveDescendantEnumerationFileSystem,
	bytesRead: { value: number },
	byteLimit: number,
	deadlineAt: number,
	now: () => number,
): ReadStatResult {
	const empty: ReadStatResult = {
		bytes: Buffer.alloc(0),
		actualBytes: 0,
		complete: false,
		truncated: false,
		deadline: false,
		budget: false,
		vanished: false,
		unavailable: false,
	};
	if (now() >= deadlineAt) return { ...empty, deadline: true };
	if (bytesRead.value >= byteLimit) return { ...empty, budget: true };

	let fd: number | undefined;
	let primary: ReadStatResult | undefined;
	try {
		fd = fileSystem.openSync(path, READ_FLAGS);
		if (!fileSystem.fstatSync(fd).isFile()) return { ...empty, unavailable: true };
		const parts: Buffer[] = [];
		let actualTotal = 0;
		let exactEof = false;
		let truncated = false;
		let budget = false;
		let deadline = false;
		while (actualTotal < INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_STAT_BYTES + 1) {
			if (now() >= deadlineAt) {
				deadline = true;
				break;
			}
			const remainingBudget = byteLimit - bytesRead.value;
			if (remainingBudget <= 0) {
				budget = true;
				break;
			}
			const requested = Math.min(
				INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_STAT_BYTES + 1 - actualTotal,
				remainingBudget,
			);
			if (requested <= 0) {
				budget = true;
				break;
			}
			const buffer = Buffer.allocUnsafe(requested);
			let actual: number;
			try {
				actual = fileSystem.readSync(fd, buffer, 0, requested, null);
			} catch (error) {
				const kind = classifyReadError(error);
				return {
					...empty,
					bytes: Buffer.concat(parts),
					actualBytes: actualTotal,
					vanished: kind === "vanished",
					unavailable: kind === "unavailable",
				};
			}
			if (!Number.isSafeInteger(actual) || actual < 0 || actual > requested) return { ...empty, unavailable: true };
			if (actual === 0) {
				deadline = now() >= deadlineAt;
				if (deadline) break;
				exactEof = true;
				break;
			}
			bytesRead.value += actual;
			actualTotal += actual;
			parts.push(Buffer.from(buffer.subarray(0, actual)));
			deadline = now() >= deadlineAt;
			if (actualTotal > INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_STAT_BYTES) {
				truncated = true;
				break;
			}
			if (deadline) {
				break;
			}
			if (
				bytesRead.value >= byteLimit &&
				actualTotal < INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_STAT_BYTES + 1
			) {
				budget = true;
				break;
			}
		}
		const bytes = Buffer.concat(
			parts,
			Math.min(actualTotal, INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_STAT_BYTES),
		);
		primary = {
			bytes,
			actualBytes: actualTotal,
			complete: exactEof && !truncated && !budget && !deadline,
			truncated: truncated || budget,
			deadline,
			budget,
			vanished: false,
			unavailable: false,
		};
		return primary;
	} catch (error) {
		const kind = classifyReadError(error);
		return { ...empty, vanished: kind === "vanished", unavailable: kind === "unavailable" };
	} finally {
		if (fd !== undefined) {
			try {
				fileSystem.closeSync(fd);
			} catch {
				// Closing is best effort after the observation; the descriptor is never reused.
			}
		}
	}
}

function rawRead(path: string, bytes: Buffer, readOrdinal: 1 | 2): IncidentRecorderLiveDescendantRawRead {
	return { sourcePath: path, bytes: Buffer.from(bytes), readOrdinal };
}

interface DirectoryScan {
	entries: readonly number[];
	directoryEntriesSeen: number;
	numericPidsSeen: number;
	procEof: boolean;
	reason?: IncidentRecorderLiveDescendantEnumerationReason;
}

function retainBoundedPid(entries: number[], pid: number): void {
	if (entries.length < INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS) {
		entries.push(pid);
		return;
	}
	let largestIndex = 0;
	for (let index = 1; index < entries.length; index += 1) {
		if (entries[index] > entries[largestIndex]) largestIndex = index;
	}
	if (pid < entries[largestIndex]) entries[largestIndex] = pid;
}

function scanDirectory(
	fileSystem: IncidentRecorderLiveDescendantEnumerationFileSystem,
	deadlineAt: number,
	now: () => number,
): DirectoryScan {
	let directory: ReturnType<IncidentRecorderLiveDescendantEnumerationFileSystem["opendirSync"]> | undefined;
	const entries: number[] = [];
	let directoryEntriesSeen = 0;
	let numericPidsSeen = 0;
	let procEof = false;
	let reason: IncidentRecorderLiveDescendantEnumerationReason | undefined;
	try {
		directory = fileSystem.opendirSync("/proc");
		while (directoryEntriesSeen < INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DIRECTORY_ENTRIES) {
			if (now() >= deadlineAt) {
				reason = "deadline";
				break;
			}
			const entry = directory.readSync();
			if (!entry) {
				procEof = true;
				break;
			}
			directoryEntriesSeen += 1;
			if (!POSITIVE_PID.test(entry.name)) continue;
			const pid = Number(entry.name);
			if (!Number.isSafeInteger(pid) || pid <= 0) continue;
			numericPidsSeen += 1;
			retainBoundedPid(entries, pid);
		}
		if (!procEof && !reason) reason = "directory_population_limit";
		if (numericPidsSeen > INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_NUMERIC_PIDS && !reason)
			reason = "numeric_population_limit";
	} catch {
		reason = "stat_unavailable";
	} finally {
		if (directory) {
			try {
				directory.closeSync();
			} catch {
				if (!reason) reason = "stat_unavailable";
			}
		}
	}
	entries.sort((left, right) => left - right);
	return { entries, directoryEntriesSeen, numericPidsSeen, procEof, reason };
}

function baseResult(
	input: IncidentRecorderLiveDescendantEnumerationInput,
	target: IncidentRecorderLiveDescendantTarget,
	values: Pick<
		IncidentRecorderLiveDescendantEnumerationResult,
		"bytesRead" | "directoryEntriesSeen" | "numericPidsSeen" | "attemptedPids" | "receipts"
	>,
	passState: IncidentRecorderLiveDescendantEnumerationResult["passState"],
	reason?: IncidentRecorderLiveDescendantEnumerationReason,
): IncidentRecorderLiveDescendantEnumerationResult {
	return {
		captureId: input.captureId,
		target,
		descendants: [],
		method: "proc_stat_ppid",
		passState,
		reason,
		observationalPassComplete: false,
		treeCompleteness: "not_claimed",
		subjectCoverage: "truncated",
		bytesRead: values.bytesRead,
		directoryEntriesSeen: values.directoryEntriesSeen,
		numericPidsSeen: values.numericPidsSeen,
		attemptedPids: values.attemptedPids,
		receipts: values.receipts,
		nextCursor: null,
	};
}

function receiptForReadFailure(
	pid: number,
	read: ReadStatResult,
	rawReads: readonly IncidentRecorderLiveDescendantRawRead[],
): IncidentRecorderLiveDescendantReceipt {
	if (read.deadline) return { pid, state: "unavailable", reason: "deadline", rawReads };
	if (read.budget) return { pid, state: "unavailable", reason: "byte_budget", rawReads };
	if (read.vanished) return { pid, state: "vanished", reason: "stat_unavailable", rawReads };
	if (read.truncated) return { pid, state: "unavailable", reason: "stat_truncated", rawReads };
	return { pid, state: "unavailable", reason: "stat_unavailable", rawReads };
}

function deadlineReadResult(): ReadStatResult {
	return {
		bytes: Buffer.alloc(0),
		actualBytes: 0,
		complete: false,
		truncated: false,
		deadline: true,
		budget: false,
		vanished: false,
		unavailable: false,
	};
}

/**
 * Performs one bounded observational `/proc` pass. This is supplemental
 * evidence only: the result deliberately never claims a complete live tree.
 */
export function enumerateIncidentRecorderLiveDescendants(
	input: IncidentRecorderLiveDescendantEnumerationInput,
): IncidentRecorderLiveDescendantEnumerationResult {
	assertPid(input.targetPid, "targetPid");
	if (typeof input.captureId !== "string" || input.captureId.length === 0)
		throw new TypeError("captureId must be a non-empty string");
	const expectedStartTicks = parseProcessStartId(input.targetProcessStartId, "targetProcessStartId");
	const deadlineMs = clamp(
		input.deadlineMs,
		INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DEADLINE_MS,
		INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_DEADLINE_MS,
	);
	const byteBudget = clamp(
		input.byteBudget,
		INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_BYTE_BUDGET,
		INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_BYTE_BUDGET,
	);
	const subjectLimit = clamp(
		input.subjectLimit,
		INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_SUBJECTS,
		INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_MAX_SUBJECTS,
		1,
	);
	const fileSystem = input.fileSystem ?? defaultFileSystem;
	const now = input.now ?? (() => performance.now());
	const deadlineAt = now() + deadlineMs;
	const bytesRead = { value: 0 };
	const attemptedPids: number[] = [];
	const receipts: IncidentRecorderLiveDescendantReceipt[] = [];
	if (byteBudget < INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_TARGET_RECHECK_RESERVE) {
		return baseResult(
			input,
			{
				pid: input.targetPid,
				processStartId: processStartId(expectedStartTicks),
				state: "unverified",
			},
			{ bytesRead: 0, directoryEntriesSeen: 0, numericPidsSeen: 0, attemptedPids, receipts },
			"unavailable",
			"insufficient_identity_budget",
		);
	}
	const targetPath = sourcePath(input.targetPid);
	const initial = readBoundedStat(targetPath, fileSystem, bytesRead, byteBudget, deadlineAt, now);
	const initialRawReads = initial.actualBytes > 0 ? [rawRead(targetPath, initial.bytes, 1)] : [];
	const initialStat =
		!initial.deadline && !initial.budget && !initial.unavailable && !initial.vanished && initial.complete
			? parseStat(initial.bytes)
			: undefined;
	const initialTargetStable =
		initialStat !== undefined && initialStat.pid === input.targetPid && initialStat.startTicks === expectedStartTicks;
	const initialTarget: IncidentRecorderLiveDescendantTarget = {
		pid: input.targetPid,
		processStartId: processStartId(expectedStartTicks),
		state: initialTargetStable ? "stable" : "unverified",
		...(initialRawReads.length > 0 ? { rawReads: initialRawReads } : {}),
	};

	if (
		initial.deadline ||
		initial.budget ||
		initial.unavailable ||
		initial.vanished ||
		initial.truncated ||
		!initialStat
	) {
		const reason = initial.deadline
			? "target_initial_deadline"
			: initial.truncated || initial.budget
				? "target_initial_truncated"
				: initial.unavailable || initial.vanished
					? "target_initial_unavailable"
					: "target_initial_malformed";
		return baseResult(
			input,
			initialTarget,
			{ bytesRead: bytesRead.value, directoryEntriesSeen: 0, numericPidsSeen: 0, attemptedPids, receipts },
			"unavailable",
			reason,
		);
	}

	if (bytesRead.value + INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_TARGET_RECHECK_RESERVE > byteBudget) {
		return baseResult(
			input,
			{ ...initialTarget, state: "unverified" },
			{ bytesRead: bytesRead.value, directoryEntriesSeen: 0, numericPidsSeen: 0, attemptedPids, receipts },
			"unavailable",
			"insufficient_identity_budget",
		);
	}

	if (!initialTargetStable) {
		return baseResult(
			input,
			initialTarget,
			{ bytesRead: bytesRead.value, directoryEntriesSeen: 0, numericPidsSeen: 0, attemptedPids, receipts },
			"unavailable",
			"target_identity_changed",
		);
	}

	const scan = scanDirectory(fileSystem, deadlineAt, now);
	const candidatePids = scan.entries.filter((pid) => pid !== input.targetPid);
	const candidates = new Map<number, Candidate>();
	let passReason = scan.reason;
	let frontierComplete = scan.procEof && scan.reason === undefined;

	for (const pid of candidatePids) {
		if (now() >= deadlineAt) {
			passReason ??= "deadline";
			frontierComplete = false;
			break;
		}
		if (bytesRead.value >= byteBudget - INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_TARGET_RECHECK_RESERVE) {
			passReason ??= "byte_budget";
			frontierComplete = false;
			break;
		}
		attemptedPids.push(pid);
		const path = sourcePath(pid);
		const rawReads: IncidentRecorderLiveDescendantRawRead[] = [];
		const first = readBoundedStat(
			path,
			fileSystem,
			bytesRead,
			byteBudget - INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_TARGET_RECHECK_RESERVE,
			deadlineAt,
			now,
		);
		if (first.actualBytes > 0) rawReads.push(rawRead(path, first.bytes, 1));
		const second = readBoundedStat(
			path,
			fileSystem,
			bytesRead,
			byteBudget - INCIDENT_RECORDER_LIVE_DESCENDANT_ENUMERATION_TARGET_RECHECK_RESERVE,
			deadlineAt,
			now,
		);
		if (second.actualBytes > 0) rawReads.push(rawRead(path, second.bytes, 2));
		const firstStat =
			!first.deadline && !first.budget && !first.unavailable && !first.vanished && first.complete
				? parseStat(first.bytes)
				: undefined;
		const secondStat =
			!second.deadline && !second.budget && !second.unavailable && !second.vanished && second.complete
				? parseStat(second.bytes)
				: undefined;
		if (
			!first.deadline &&
			!first.budget &&
			!first.unavailable &&
			!first.vanished &&
			first.complete &&
			(!firstStat || firstStat.pid !== pid)
		) {
			receipts.push({ pid, state: "malformed", reason: "stat_malformed", rawReads });
			frontierComplete = false;
			passReason ??= "stat_malformed";
			continue;
		}
		if (
			!second.deadline &&
			!second.budget &&
			!second.unavailable &&
			!second.vanished &&
			second.complete &&
			(!secondStat || secondStat.pid !== pid)
		) {
			receipts.push({ pid, state: "malformed", reason: "stat_malformed", rawReads });
			frontierComplete = false;
			passReason ??= "stat_malformed";
			continue;
		}
		if (!firstStat || !secondStat || first.deadline || second.deadline || first.budget || second.budget) {
			const failed =
				first.deadline || first.budget || first.unavailable || first.vanished || first.truncated ? first : second;
			receipts.push(receiptForReadFailure(pid, failed, rawReads));
			frontierComplete = false;
			passReason ??= failed.deadline
				? "deadline"
				: failed.budget
					? "byte_budget"
					: failed.truncated
						? "stat_truncated"
						: "stat_unavailable";
			continue;
		}
		if (firstStat.startTicks !== secondStat.startTicks) {
			receipts.push({ pid, state: "identity_changed", reason: "identity_changed", rawReads });
			frontierComplete = false;
			passReason ??= "candidate_identity_changed";
			continue;
		}
		if (firstStat.parentPid !== secondStat.parentPid) {
			receipts.push({ pid, state: "parent_changed", reason: "parent_changed", rawReads });
			frontierComplete = false;
			passReason ??= "parent_changed";
			continue;
		}
		candidates.set(pid, { pid, parentPid: firstStat.parentPid, startTicks: firstStat.startTicks, rawReads });
		receipts.push({ pid, state: "admitted", rawReads });
	}

	const final =
		now() >= deadlineAt
			? deadlineReadResult()
			: readBoundedStat(targetPath, fileSystem, bytesRead, byteBudget, deadlineAt, now);
	const finalRawReads = final.actualBytes > 0 ? rawRead(targetPath, final.bytes, 2) : undefined;
	const finalStat =
		!final.deadline && !final.budget && !final.unavailable && !final.vanished && final.complete
			? parseStat(final.bytes)
			: undefined;
	const finalStable =
		finalStat !== undefined && finalStat.pid === input.targetPid && finalStat.startTicks === expectedStartTicks;
	const targetRawReads = [
		...(initialRawReads.length > 0 ? initialRawReads : []),
		...(finalRawReads ? [finalRawReads] : []),
	];
	const target: IncidentRecorderLiveDescendantTarget = {
		pid: input.targetPid,
		processStartId: processStartId(expectedStartTicks),
		state: initialTargetStable && finalStable ? "stable" : "unverified",
		...(targetRawReads.length > 0 ? { rawReads: targetRawReads } : {}),
	};
	if (!finalStable || target.state !== "stable") {
		const reason = final.deadline
			? "target_recheck_deadline"
			: final.truncated || final.budget
				? "target_recheck_truncated"
				: final.unavailable || final.vanished || !finalStat
					? "target_recheck_unavailable"
					: "target_identity_changed";
		return {
			...baseResult(
				input,
				target,
				{
					bytesRead: bytesRead.value,
					directoryEntriesSeen: scan.directoryEntriesSeen,
					numericPidsSeen: scan.numericPidsSeen,
					attemptedPids,
					receipts,
				},
				final.deadline || final.budget ? "truncated" : "unavailable",
				reason,
			),
			subjectCoverage: "truncated",
		};
	}

	const childrenByParent = new Map<number, Candidate[]>();
	for (const candidate of candidates.values()) {
		const parent = candidate.parentPid === input.targetPid ? undefined : candidates.get(candidate.parentPid);
		const parentTicks = candidate.parentPid === input.targetPid ? expectedStartTicks : parent?.startTicks;
		if (parentTicks === undefined) {
			const receipt = receipts.find((item) => item.pid === candidate.pid);
			if (receipt) {
				receipt.state = "parent_identity_unresolved";
				receipt.reason = "parent_identity_unresolved";
			}
			frontierComplete = false;
			passReason ??= "parent_identity_unresolved";
			continue;
		}
		if (parentTicks > candidate.startTicks) {
			const receipt = receipts.find((item) => item.pid === candidate.pid);
			if (receipt) {
				receipt.state = "temporally_impossible_parent";
				receipt.reason = "temporally_impossible_parent";
			}
			frontierComplete = false;
			passReason ??= "temporally_impossible_parent";
			continue;
		}
		const children = childrenByParent.get(candidate.parentPid) ?? [];
		children.push(candidate);
		childrenByParent.set(candidate.parentPid, children);
	}
	for (const children of childrenByParent.values()) children.sort((left, right) => left.pid - right.pid);

	const descendants: IncidentRecorderLiveDescendant[] = [];
	const visited = new Set<number>([input.targetPid]);
	const queue: Array<{ pid: number; depth: number }> = [{ pid: input.targetPid, depth: 0 }];
	let subjectTruncated = false;
	while (queue.length > 0) {
		const parent = queue.shift();
		if (!parent) break;
		for (const child of childrenByParent.get(parent.pid) ?? []) {
			if (visited.has(child.pid)) continue;
			visited.add(child.pid);
			if (descendants.length >= subjectLimit - 1) {
				subjectTruncated = true;
				continue;
			}
			const parentCandidate = child.parentPid === input.targetPid ? undefined : candidates.get(child.parentPid);
			const parentStartTicks =
				child.parentPid === input.targetPid ? expectedStartTicks : parentCandidate?.startTicks;
			if (parentStartTicks === undefined) continue;
			descendants.push({
				pid: child.pid,
				processStartId: processStartId(child.startTicks),
				parent: {
					pid: child.parentPid,
					processStartId: processStartId(parentStartTicks),
					identityMatch: "same_pass_stable_stat",
				},
				depth: parent.depth + 1,
				relation: {
					kind: "observed_ppid_graph_match",
					childPpidStableAcrossReads: true,
					causalParentageProven: false,
				},
				rawReads: child.rawReads,
			});
			queue.push({ pid: child.pid, depth: parent.depth + 1 });
		}
	}
	for (const candidate of candidates.values()) {
		if (visited.has(candidate.pid)) continue;
		const receipt = receipts.find((item) => item.pid === candidate.pid);
		if (receipt?.state === "admitted") {
			receipt.state = "not_transitive";
			receipt.reason = "parent_not_transitive";
		}
	}
	if (subjectTruncated) {
		frontierComplete = false;
		passReason ??= "subject_limit";
	}
	const observationalPassComplete = frontierComplete && target.state === "stable" && !subjectTruncated;
	const finalPassState = observationalPassComplete
		? "complete"
		: passReason === "stat_unavailable"
			? "unavailable"
			: "truncated";
	return {
		captureId: input.captureId,
		target,
		descendants,
		method: "proc_stat_ppid",
		passState: finalPassState,
		...(passReason ? { reason: passReason } : {}),
		observationalPassComplete,
		treeCompleteness: "not_claimed",
		subjectCoverage: subjectTruncated
			? "truncated"
			: frontierComplete
				? "complete_within_observed_population"
				: "truncated",
		bytesRead: bytesRead.value,
		directoryEntriesSeen: scan.directoryEntriesSeen,
		numericPidsSeen: scan.numericPidsSeen,
		attemptedPids,
		receipts,
		nextCursor: null,
	};
}
