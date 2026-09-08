import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { getProcessStartId } from "../../core/session-lease.js";
import type { IncidentRecorderAdmission, IncidentRecorderWriter } from "./incident-recorder-writer.js";

/** The live capture pass is deliberately small enough to be safe in a service writer. */
export const INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_DEADLINE_MS = 40;
export const INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_BYTE_BUDGET = 4 * 1024 * 1024;
export const INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCES = 10;
export const INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES = 64 * 1024;

// The writer's service emitter is bounded below the wire protocol's maximum
// occurrence size. Keeping a source below this bound means ordinary process
// metadata can enter the service queue while maps/environ remain explicitly
// bounded and truthful when they are larger.
export const INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES = 128 * 1024;

export const INCIDENT_RECORDER_LIVE_PROC_CAPTURE_SOURCE_NAMES = [
	"status",
	"stat",
	"io",
	"limits",
	"smaps_rollup",
	"cgroup",
	"cmdline",
	"environ",
	"maps",
	"task/{pid}/children",
] as const;

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);

export type IncidentRecorderLiveProcCaptureReason =
	| "read_failed"
	| "identity_changed"
	| "deadline"
	| "byte_budget"
	| "queue_rejection"
	| "truncated";

export type IncidentRecorderLiveProcCaptureCoverageState = "complete" | "truncated" | "unavailable";

/** A narrow, ordinary service-writer dependency for this leaf. */
export type IncidentRecorderLiveProcCaptureWriter = Pick<IncidentRecorderWriter, "recordExactBytesForRun">;

/** Read-only synchronous operations used by this leaf. Tests may provide a map-backed implementation. */
export interface IncidentRecorderLiveProcCaptureFileSystem {
	openSync(path: string, flags: number): number;
	fstatSync(fd: number): { isFile(): boolean };
	readSync(fd: number, buffer: Buffer, offset: number, length: number, position: number | null): number;
	closeSync(fd: number): void;
}

export interface IncidentRecorderLiveProcCaptureInput {
	runId: string;
	runToken: string;
	targetPid: number;
	targetProcessStartId: string;
	pid: number;
	processStartId: string;
	triggerOccurrenceId: string;
	captureId: string;
	nextSourceIndex?: number;
	/** Maximum cooperative duration for this pass. Values above 40ms are clamped. */
	deadlineMs?: number;
	/** Shared byte budget for this pass. Values above 4MiB are clamped. */
	byteBudget?: number;
	writer: IncidentRecorderLiveProcCaptureWriter;
	/** Dependency-injection seam for deterministic bounded-read tests. */
	fileSystem?: IncidentRecorderLiveProcCaptureFileSystem;
	/** Dependency-injection seam for process identity rechecks. */
	processStartIdReader?: typeof getProcessStartId;
	/** Dependency-injection seam for cooperative deadline checks; values must be monotonic milliseconds. */
	now?: () => number;
}

export interface IncidentRecorderLiveProcCaptureCoverageReceipt {
	state: IncidentRecorderLiveProcCaptureCoverageState;
	retainedBytes: number;
	sourceBytes?: number;
	truncated: boolean;
	reason?: IncidentRecorderLiveProcCaptureReason;
}

export interface IncidentRecorderLiveProcCaptureAdmissionReceipt {
	accepted: boolean;
	disposition: "locally_admitted" | "rejected" | "not_attempted";
	occurrenceId?: string;
	reason?: IncidentRecorderLiveProcCaptureReason;
	writerReason?: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"];
}

export interface IncidentRecorderLiveProcCaptureSourceReceipt {
	sourceIndex: number;
	sourceName: string;
	sourcePath: string;
	bytesRead: number;
	retainedBytes: number;
	sourceBytes?: number;
	truncated: boolean;
	coverageState: IncidentRecorderLiveProcCaptureCoverageState;
	coverage: IncidentRecorderLiveProcCaptureCoverageReceipt;
	admitted: boolean;
	admission: IncidentRecorderLiveProcCaptureAdmissionReceipt;
	reason?: IncidentRecorderLiveProcCaptureReason;
}

export interface IncidentRecorderLiveProcCaptureResult {
	runId: string;
	runToken: string;
	targetPid: number;
	targetProcessStartId: string;
	pid: number;
	processStartId: string;
	triggerOccurrenceId: string;
	captureId: string;
	nextSourceIndex: number;
	bytesRead: number;
	retainedBytes: number;
	completedSources: number;
	complete: boolean;
	reason?: IncidentRecorderLiveProcCaptureReason;
	receipts: readonly IncidentRecorderLiveProcCaptureSourceReceipt[];
}

interface BoundedReadResult {
	bytes: Buffer;
	bytesRead: number;
	complete: boolean;
	reason?: IncidentRecorderLiveProcCaptureReason;
}

const defaultFileSystem: IncidentRecorderLiveProcCaptureFileSystem = {
	openSync,
	fstatSync,
	readSync,
	closeSync,
};

function boundedInteger(value: number | undefined, fallback: number, maximum: number): number {
	if (value === undefined) return fallback;
	if (!Number.isFinite(value)) return fallback;
	return Math.min(maximum, Math.max(0, Math.floor(value)));
}

function assertPositivePid(pid: number, field: string): void {
	if (!Number.isSafeInteger(pid) || pid <= 0) throw new TypeError(`${field} must be a positive PID`);
}

function assertIdentity(value: string, field: string): void {
	if (typeof value !== "string" || value.length === 0) throw new TypeError(`${field} must be a non-empty identity`);
}

function assertUuid(value: string, field: string): void {
	if (!CANONICAL_UUID.test(value)) throw new TypeError(`${field} must be a canonical UUID`);
}

function sourcePath(pid: number, sourceName: string): string {
	return `/proc/${pid}/${sourceName.replace("{pid}", String(pid))}`;
}

function captureMetadata(
	input: IncidentRecorderLiveProcCaptureInput,
	path: string,
	read: BoundedReadResult,
	coverageState: IncidentRecorderLiveProcCaptureCoverageState,
	truncated: boolean,
): Record<string, unknown> {
	return {
		pid: input.pid,
		processStartId: input.processStartId,
		targetPid: input.targetPid,
		targetProcessStartId: input.targetProcessStartId,
		triggerOccurrenceId: input.triggerOccurrenceId,
		captureId: input.captureId,
		sourcePath: path,
		...(read.complete ? { sourceBytes: read.bytes.length } : {}),
		retainedBytes: read.bytes.length,
		sourceTruncated: truncated,
		state: coverageState,
		...(read.reason ? { reason: read.reason } : {}),
	};
}

function readBoundedSource(
	path: string,
	fileSystem: IncidentRecorderLiveProcCaptureFileSystem,
	byteBudget: number,
	deadlineAt: number,
	now: () => number,
): BoundedReadResult {
	let descriptor: number | undefined;
	let bytesRead = 0;
	const parts: Buffer[] = [];
	let complete = false;
	let reason: IncidentRecorderLiveProcCaptureReason | undefined;

	try {
		descriptor = fileSystem.openSync(path, READ_FLAGS);
		if (!fileSystem.fstatSync(descriptor).isFile()) throw new Error("proc source is not a regular file");
		while (
			parts.reduce((total, part) => total + part.length, 0) < INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES
		) {
			const retainedBytes = parts.reduce((total, part) => total + part.length, 0);
			if (now() >= deadlineAt) {
				reason = "deadline";
				break;
			}
			if (bytesRead >= byteBudget) {
				reason = "byte_budget";
				break;
			}
			const requested = Math.min(
				INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES,
				INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES - retainedBytes,
				byteBudget - bytesRead,
			);
			if (requested <= 0) {
				reason = bytesRead >= byteBudget ? "byte_budget" : "truncated";
				break;
			}
			const chunk = Buffer.allocUnsafe(requested);
			const count = fileSystem.readSync(descriptor, chunk, 0, requested, null);
			if (!Number.isSafeInteger(count) || count < 0 || count > requested)
				throw new Error("invalid bounded proc read count");
			bytesRead += count;
			if (count > 0) parts.push(Buffer.from(chunk.subarray(0, count)));
			if (count === 0) {
				complete = true;
				break;
			}
		}

		const retainedBytes = parts.reduce((total, part) => total + part.length, 0);
		if (!complete && retainedBytes >= INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES) {
			// One-byte lookahead is intentional: proc pseudo-files report size zero,
			// so a bounded prefix is only called truncated when the lookahead proves it.
			if (now() >= deadlineAt) reason = reason ?? "deadline";
			else if (bytesRead >= byteBudget) reason = reason ?? "byte_budget";
			else {
				const lookahead = Buffer.allocUnsafe(1);
				const count = fileSystem.readSync(descriptor, lookahead, 0, 1, null);
				if (!Number.isSafeInteger(count) || count < 0 || count > 1)
					throw new Error("invalid bounded proc lookahead count");
				bytesRead += count;
				if (count === 0) complete = true;
				else reason = "truncated";
			}
		}
	} catch {
		reason = reason ?? "read_failed";
	} finally {
		if (descriptor !== undefined) {
			try {
				fileSystem.closeSync(descriptor);
			} catch {
				reason = reason ?? "read_failed";
				complete = false;
			}
		}
	}

	return { bytes: Buffer.concat(parts), bytesRead, complete, ...(reason ? { reason } : {}) };
}

function noAdmission(reason?: IncidentRecorderLiveProcCaptureReason): IncidentRecorderLiveProcCaptureAdmissionReceipt {
	return {
		accepted: false,
		disposition: "not_attempted",
		...(reason ? { reason } : {}),
	};
}

function sourceReceipt(
	index: number,
	name: string,
	path: string,
	readBytes: number,
	retainedBytes: number,
	coverageState: IncidentRecorderLiveProcCaptureCoverageState,
	sourceBytes: number | undefined,
	truncated: boolean,
	reason: IncidentRecorderLiveProcCaptureReason | undefined,
	admission: IncidentRecorderLiveProcCaptureAdmissionReceipt,
): IncidentRecorderLiveProcCaptureSourceReceipt {
	return {
		sourceIndex: index,
		sourceName: name,
		sourcePath: path,
		bytesRead: readBytes,
		retainedBytes,
		...(sourceBytes === undefined ? {} : { sourceBytes }),
		truncated,
		coverageState,
		coverage: {
			state: coverageState,
			retainedBytes,
			...(sourceBytes === undefined ? {} : { sourceBytes }),
			truncated,
			...(reason ? { reason } : {}),
		},
		admitted: admission.accepted,
		admission,
		...(reason ? { reason } : {}),
	};
}

/**
 * Capture one subject's fixed proc source set into the ordinary service writer.
 *
 * This function is intentionally synchronous. The deadline is cooperative: a
 * kernel read cannot be preempted by synchronous JavaScript, so the pass checks
 * the deadline between bounded reads and before every admission. If the
 * deadline is reached after a bounded read has produced bytes, that already-read
 * source receives one bounded admission so useful evidence is not discarded;
 * no new source is admitted after the deadline.
 */
export function captureIncidentRecorderLiveProc(
	input: IncidentRecorderLiveProcCaptureInput,
): IncidentRecorderLiveProcCaptureResult {
	assertUuid(input.runId, "runId");
	assertUuid(input.runToken, "runToken");
	assertPositivePid(input.targetPid, "targetPid");
	assertPositivePid(input.pid, "pid");
	assertIdentity(input.targetProcessStartId, "targetProcessStartId");
	assertIdentity(input.processStartId, "processStartId");
	assertUuid(input.triggerOccurrenceId, "triggerOccurrenceId");
	assertUuid(input.captureId, "captureId");

	const startIndex = boundedInteger(input.nextSourceIndex, 0, INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCES);
	const deadlineMs = boundedInteger(
		input.deadlineMs,
		INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_DEADLINE_MS,
		INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_DEADLINE_MS,
	);
	const byteBudget = boundedInteger(
		input.byteBudget,
		INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_BYTE_BUDGET,
		INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_BYTE_BUDGET,
	);
	const now = input.now ?? (() => performance.now());
	const deadlineAt = now() + deadlineMs;
	const fileSystem = input.fileSystem ?? defaultFileSystem;
	const processStartIdReader = input.processStartIdReader ?? getProcessStartId;
	const receipts: IncidentRecorderLiveProcCaptureSourceReceipt[] = [];
	let bytesRead = 0;
	let retainedBytes = 0;
	let nextSourceIndex = startIndex;
	let firstReason: IncidentRecorderLiveProcCaptureReason | undefined;

	if (process.platform !== "linux") {
		return {
			runId: input.runId,
			runToken: input.runToken,
			targetPid: input.targetPid,
			targetProcessStartId: input.targetProcessStartId,
			pid: input.pid,
			processStartId: input.processStartId,
			triggerOccurrenceId: input.triggerOccurrenceId,
			captureId: input.captureId,
			nextSourceIndex: startIndex,
			bytesRead: 0,
			retainedBytes: 0,
			completedSources: 0,
			complete: false,
			reason: "read_failed",
			receipts,
		};
	}

	for (let index = startIndex; index < INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCES; index += 1) {
		const name = INCIDENT_RECORDER_LIVE_PROC_CAPTURE_SOURCE_NAMES[index];
		const path = sourcePath(input.pid, name);
		if (now() >= deadlineAt) {
			firstReason = firstReason ?? "deadline";
			receipts.push(
				sourceReceipt(
					index,
					name,
					path,
					0,
					0,
					"unavailable",
					undefined,
					false,
					"deadline",
					noAdmission("deadline"),
				),
			);
			nextSourceIndex = index;
			break;
		}
		if (bytesRead >= byteBudget) {
			firstReason = firstReason ?? "byte_budget";
			receipts.push(
				sourceReceipt(
					index,
					name,
					path,
					0,
					0,
					"unavailable",
					undefined,
					false,
					"byte_budget",
					noAdmission("byte_budget"),
				),
			);
			nextSourceIndex = index;
			break;
		}

		let beforeIdentity: string | undefined;
		try {
			beforeIdentity = processStartIdReader(input.pid);
		} catch {
			beforeIdentity = undefined;
		}
		if (beforeIdentity !== input.processStartId) {
			firstReason = firstReason ?? "identity_changed";
			receipts.push(
				sourceReceipt(
					index,
					name,
					path,
					0,
					0,
					"unavailable",
					undefined,
					false,
					"identity_changed",
					noAdmission("identity_changed"),
				),
			);
			nextSourceIndex = index;
			break;
		}

		const read = readBoundedSource(path, fileSystem, byteBudget - bytesRead, deadlineAt, now);
		bytesRead += read.bytesRead;
		let afterIdentity: string | undefined;
		try {
			afterIdentity = processStartIdReader(input.pid);
		} catch {
			afterIdentity = undefined;
		}
		if (afterIdentity !== input.processStartId) {
			firstReason = firstReason ?? "identity_changed";
			receipts.push(
				sourceReceipt(
					index,
					name,
					path,
					read.bytesRead,
					0,
					"unavailable",
					undefined,
					false,
					"identity_changed",
					noAdmission("identity_changed"),
				),
			);
			nextSourceIndex = index;
			break;
		}

		const unavailable = !read.complete && read.reason === "read_failed" && read.bytes.length === 0;
		const truncated = !read.complete && !unavailable;
		const coverageState: IncidentRecorderLiveProcCaptureCoverageState = read.complete
			? "complete"
			: unavailable
				? "unavailable"
				: "truncated";
		const sourceBytes = read.complete ? read.bytes.length : undefined;
		let admission = noAdmission(read.reason);
		let reason = read.reason;
		if (read.complete || read.bytes.length > 0) {
			const deadlineReachedBeforeAdmission = now() >= deadlineAt;
			if (deadlineReachedBeforeAdmission && read.bytes.length === 0) {
				reason = "deadline";
				firstReason = firstReason ?? reason;
				admission = noAdmission(reason);
			} else {
				let beforeAdmissionIdentity: string | undefined;
				try {
					beforeAdmissionIdentity = processStartIdReader(input.pid);
				} catch {
					beforeAdmissionIdentity = undefined;
				}
				if (beforeAdmissionIdentity !== input.processStartId) {
					reason = "identity_changed";
					firstReason = firstReason ?? reason;
					admission = noAdmission("identity_changed");
					receipts.push(
						sourceReceipt(
							index,
							name,
							path,
							read.bytesRead,
							0,
							"unavailable",
							undefined,
							false,
							reason,
							admission,
						),
					);
					nextSourceIndex = index;
					break;
				}
				try {
					const writerAdmission = input.writer.recordExactBytesForRun(
						{ runId: input.runId, runToken: input.runToken },
						"linux-raw-source",
						"live_proc_source_snapshot",
						read.bytes,
						"exact-file-bytes",
						captureMetadata(input, path, read, coverageState, truncated),
					);
					if (writerAdmission.accepted) {
						admission = {
							accepted: true,
							disposition: "locally_admitted",
							occurrenceId: writerAdmission.occurrenceId,
							...(reason ? { reason } : {}),
						};
					} else {
						reason = "queue_rejection";
						firstReason = firstReason ?? reason;
						admission = {
							accepted: false,
							disposition: "rejected",
							reason,
							writerReason: writerAdmission.reason,
						};
					}
				} catch {
					reason = "queue_rejection";
					firstReason = firstReason ?? reason;
					admission = { accepted: false, disposition: "rejected", reason };
				}
			}
		}

		if (reason) firstReason = firstReason ?? reason;
		retainedBytes += read.bytes.length;
		receipts.push(
			sourceReceipt(
				index,
				name,
				path,
				read.bytesRead,
				read.bytes.length,
				coverageState,
				sourceBytes,
				truncated,
				reason,
				admission,
			),
		);

		if (read.reason === "deadline" || read.reason === "byte_budget") {
			nextSourceIndex = index;
			break;
		}
		nextSourceIndex = index + 1;
	}

	const completedSources = receipts.filter((receipt) => receipt.coverageState === "complete").length;
	const complete =
		nextSourceIndex >= INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCES &&
		receipts.length === INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCES &&
		receipts.every((receipt) => receipt.coverageState === "complete" && receipt.admitted);
	return {
		runId: input.runId,
		runToken: input.runToken,
		targetPid: input.targetPid,
		targetProcessStartId: input.targetProcessStartId,
		pid: input.pid,
		processStartId: input.processStartId,
		triggerOccurrenceId: input.triggerOccurrenceId,
		captureId: input.captureId,
		nextSourceIndex,
		bytesRead,
		retainedBytes,
		completedSources,
		complete,
		...(complete ? {} : { reason: firstReason ?? "truncated" }),
		receipts,
	};
}
