import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { getProcessStartId } from "../../core/session-lease.js";
import {
	defaultLinuxCgroupV2ResolutionDependencies,
	type LinuxCgroupV2ResolutionDependencies,
	type ResolvedLinuxCgroupV2Directory,
	resolveCgroupDirectory,
} from "./incident-recorder-linux.js";
import type { IncidentRecorderAdmission, IncidentRecorderWriter } from "./incident-recorder-writer.js";

/** The cgroup pass is deliberately bounded for the ordinary service-writer path. */
export const INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_DEADLINE_MS = 40;
export const INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_BYTE_BUDGET = 4 * 1024 * 1024;
export const INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES = 128 * 1024;
export const INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_CHUNK_BYTES = 64 * 1024;
export const INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_LOOKAHEAD_BYTES = 1;

export const INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES = [
	"cgroup.procs",
	"memory.events.local",
	"memory.events",
	"memory.current",
	"memory.peak",
	"memory.max",
	"memory.pressure",
	"memory.stat",
	"memory.swap.current",
	"memory.swap.max",
	"memory.low",
	"memory.high",
	"memory.min",
	"memory.oom.group",
] as const;
export const INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCES =
	INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES.length;

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0);

export type IncidentRecorderLiveCgroupV2CaptureReason =
	| "resolution_failed"
	| "identity_changed"
	| "deadline"
	| "byte_budget"
	| "read_failed"
	| "not_regular_file"
	| "truncated"
	| "queue_rejection"
	| "unsupported_platform";

export type IncidentRecorderLiveCgroupV2CaptureCoverageState = "complete" | "truncated" | "unavailable";

export type IncidentRecorderLiveCgroupV2CaptureWriter = Pick<IncidentRecorderWriter, "recordExactBytesForRun">;

/** Synchronous cgroup-file operations are injectable for deterministic bounded-read tests. */
export interface IncidentRecorderLiveCgroupV2CaptureFileSystem {
	openSync(path: string, flags: number): number;
	fstatSync(fd: number): { isFile(): boolean };
	readSync(fd: number, buffer: Buffer, offset: number, length: number, position: number | null): number;
	closeSync(fd: number): void;
}

export interface IncidentRecorderLiveCgroupV2CaptureInput {
	runId: string;
	runToken: string;
	rootPid: number;
	rootProcessStartId: string;
	triggerOccurrenceId: string;
	captureId: string;
	nextSourceIndex?: number;
	/** Alias for nextSourceIndex used by callers that persist the selected index directly. */
	sourceIndex?: number;
	/** Maximum cooperative duration for this pass. Values above 40ms are clamped. */
	deadlineMs?: number;
	/** Shared raw-byte budget for this pass. Values above 4MiB are clamped. */
	byteBudget?: number;
	writer: IncidentRecorderLiveCgroupV2CaptureWriter;
	fileSystem?: IncidentRecorderLiveCgroupV2CaptureFileSystem;
	/** Narrow resolver dependencies; only bounded reads and identity stats are needed. */
	resolutionDependencies?: LinuxCgroupV2ResolutionDependencies;
	/** Alias retained for callers that use the generic dependency name. */
	dependencies?: LinuxCgroupV2ResolutionDependencies;
	/** Alias retained for callers that name the resolver seam explicitly. */
	resolverDependencies?: LinuxCgroupV2ResolutionDependencies;
	/** Process identity seam. It must return the current start identity or undefined. */
	processStartIdReader?: (pid: number) => string | undefined;
	/** Monotonic milliseconds used for cooperative deadline checks. */
	now?: () => number;
	/** Alias for now, retained for callers that name the seam by its contract. */
	monotonic?: () => number;
}

export interface IncidentRecorderLiveCgroupV2CaptureAdmission {
	accepted: boolean;
	disposition: "locally_admitted" | "rejected" | "not_attempted";
	occurrenceId?: string;
	reason?: IncidentRecorderLiveCgroupV2CaptureReason;
	writerReason?: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"];
}

export interface IncidentRecorderLiveCgroupV2CaptureReceipt {
	sourceIndex: number;
	sourceName: string;
	sourcePath: string;
	bytesRead: number;
	retainedBytes: number;
	sourceBytes?: number;
	sourceTruncated: boolean;
	truncated: boolean;
	coverageState: IncidentRecorderLiveCgroupV2CaptureCoverageState;
	coverage: {
		state: IncidentRecorderLiveCgroupV2CaptureCoverageState;
		retainedBytes: number;
		sourceBytes?: number;
		truncated: boolean;
		reason?: IncidentRecorderLiveCgroupV2CaptureReason;
	};
	livePopulation: true;
	coherentSnapshot: false;
	admitted: boolean;
	admission: IncidentRecorderLiveCgroupV2CaptureAdmission;
	errorCode?: string;
	reason?: IncidentRecorderLiveCgroupV2CaptureReason;
}

export interface IncidentRecorderLiveCgroupV2CaptureResult {
	runId: string;
	runToken: string;
	rootPid: number;
	rootProcessStartId: string;
	triggerOccurrenceId: string;
	captureId: string;
	sourceIndex?: number;
	nextSourceIndex: number;
	bytesRead: number;
	retainedBytes: number;
	complete: boolean;
	terminalCoverage: "complete" | "incomplete";
	resolved?: ResolvedLinuxCgroupV2Directory;
	/** The exact resolver observation, for a later ordinary raw commit or durable reference. */
	membershipRaw?: Buffer;
	receipt?: IncidentRecorderLiveCgroupV2CaptureReceipt;
	/** The one selected source receipt, exposed as a one-element tuple for callers using proc-style results. */
	receipts: readonly IncidentRecorderLiveCgroupV2CaptureReceipt[];
	reason?: IncidentRecorderLiveCgroupV2CaptureReason;
}

interface BoundedRead {
	bytes: Buffer;
	bytesRead: number;
	complete: boolean;
	reason?: IncidentRecorderLiveCgroupV2CaptureReason;
	errorCode?: string;
}

const defaultFileSystem: IncidentRecorderLiveCgroupV2CaptureFileSystem = {
	openSync,
	fstatSync,
	readSync,
	closeSync,
};

function boundedInteger(value: number | undefined, fallback: number, maximum: number): number {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	return Math.min(maximum, Math.max(0, Math.floor(value)));
}

function assertUuid(value: string, field: string): void {
	if (!CANONICAL_UUID.test(value)) throw new TypeError(`${field} must be a canonical UUID`);
}

function assertPositivePid(value: number): void {
	if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError("rootPid must be a positive PID");
}

function assertIdentity(value: string, field: string): void {
	if (typeof value !== "string" || value.length === 0) throw new TypeError(`${field} must be non-empty`);
}

function errnoCode(error: unknown): string | undefined {
	const code = (error as NodeJS.ErrnoException | undefined)?.code;
	return typeof code === "string" && /^[A-Za-z0-9_]{1,32}$/.test(code) ? code.toUpperCase() : undefined;
}

function sameMembership(left: ResolvedLinuxCgroupV2Directory, right: ResolvedLinuxCgroupV2Directory): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.identityHash === right.identityHash &&
		left.membershipSourcePath === right.membershipSourcePath &&
		left.membershipRaw.equals(right.membershipRaw)
	);
}

function noAdmission(reason?: IncidentRecorderLiveCgroupV2CaptureReason): IncidentRecorderLiveCgroupV2CaptureAdmission {
	return { accepted: false, disposition: "not_attempted", ...(reason ? { reason } : {}) };
}

function sourcePath(directory: string, sourceName: string): string {
	return join(directory, sourceName);
}

function readBoundedSource(
	path: string,
	fileSystem: IncidentRecorderLiveCgroupV2CaptureFileSystem,
	byteBudget: number,
	deadlineAt: number,
	now: () => number,
): BoundedRead {
	let descriptor: number | undefined;
	let bytesRead = 0;
	let complete = false;
	let reason: IncidentRecorderLiveCgroupV2CaptureReason | undefined;
	let errorCode: string | undefined;
	const parts: Buffer[] = [];
	let retainedBytes = 0;

	try {
		descriptor = fileSystem.openSync(path, READ_FLAGS);
		if (!fileSystem.fstatSync(descriptor).isFile()) {
			return { bytes: Buffer.alloc(0), bytesRead, complete: false, reason: "not_regular_file" };
		}
		while (retainedBytes < INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES) {
			if (now() >= deadlineAt) {
				reason = "deadline";
				break;
			}
			if (bytesRead >= byteBudget) {
				reason = "byte_budget";
				break;
			}
			const requested = Math.min(
				INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_CHUNK_BYTES,
				INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES - retainedBytes,
				byteBudget - bytesRead,
			);
			if (requested <= 0) {
				reason = bytesRead >= byteBudget ? "byte_budget" : "truncated";
				break;
			}
			const chunk = Buffer.allocUnsafe(requested);
			const count = fileSystem.readSync(descriptor, chunk, 0, requested, null);
			if (!Number.isSafeInteger(count) || count < 0 || count > requested)
				throw new Error("invalid bounded cgroup read count");
			bytesRead += count;
			if (count > 0) {
				parts.push(Buffer.from(chunk.subarray(0, count)));
				retainedBytes += count;
			}
			if (count === 0) {
				complete = true;
				break;
			}
		}

		if (!complete && retainedBytes >= INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES) {
			// cgroupfs pseudo-files commonly report size zero; only a charged lookahead proves truncation.
			if (now() >= deadlineAt) reason = reason ?? "deadline";
			else if (bytesRead >= byteBudget) reason = reason ?? "byte_budget";
			else {
				const lookahead = Buffer.allocUnsafe(INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_LOOKAHEAD_BYTES);
				const count = fileSystem.readSync(
					descriptor,
					lookahead,
					0,
					INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_LOOKAHEAD_BYTES,
					null,
				);
				if (!Number.isSafeInteger(count) || count < 0 || count > 1)
					throw new Error("invalid bounded cgroup lookahead count");
				bytesRead += count;
				if (count === 0) complete = true;
				else reason = "truncated";
			}
		}
	} catch (error) {
		reason = reason ?? "read_failed";
		errorCode = errnoCode(error);
	} finally {
		if (descriptor !== undefined) {
			try {
				fileSystem.closeSync(descriptor);
			} catch (error) {
				reason = reason ?? "read_failed";
				errorCode = errorCode ?? errnoCode(error);
				complete = false;
			}
		}
	}

	return {
		bytes: Buffer.concat(parts),
		bytesRead,
		complete,
		...(reason ? { reason } : {}),
		...(errorCode ? { errorCode } : {}),
	};
}

function baseMetadata(
	input: IncidentRecorderLiveCgroupV2CaptureInput,
	resolved: ResolvedLinuxCgroupV2Directory,
	index: number,
	path: string,
	retainedBytes: number,
	state: IncidentRecorderLiveCgroupV2CaptureCoverageState,
	truncated: boolean,
	reason?: IncidentRecorderLiveCgroupV2CaptureReason,
): Record<string, unknown> {
	return {
		rootPid: input.rootPid,
		rootProcessStartId: input.rootProcessStartId,
		triggerOccurrenceId: input.triggerOccurrenceId,
		captureId: input.captureId,
		sourcePath: path,
		sourceIndex: index,
		membershipSourcePath: resolved.membershipSourcePath,
		membershipSha256: resolved.membershipSha256,
		cgroupDirectory: resolved.directory,
		cgroupDev: resolved.dev,
		cgroupIno: resolved.ino,
		livePopulation: true,
		coherentSnapshot: false,
		state,
		retainedBytes,
		sourceTruncated: truncated,
		...(reason ? { reason } : {}),
	};
}

function sourceReceipt(
	index: number,
	name: string,
	path: string,
	read: BoundedRead,
	coverageState: IncidentRecorderLiveCgroupV2CaptureCoverageState,
	retainedBytes: number,
	admission: IncidentRecorderLiveCgroupV2CaptureAdmission,
	reason: IncidentRecorderLiveCgroupV2CaptureReason | undefined,
): IncidentRecorderLiveCgroupV2CaptureReceipt {
	const truncated = coverageState === "truncated";
	return {
		sourceIndex: index,
		sourceName: name,
		sourcePath: path,
		bytesRead: read.bytesRead,
		retainedBytes,
		...(coverageState === "complete" ? { sourceBytes: read.bytes.length } : {}),
		sourceTruncated: truncated,
		truncated,
		coverageState,
		coverage: {
			state: coverageState,
			retainedBytes,
			...(coverageState === "complete" ? { sourceBytes: read.bytes.length } : {}),
			truncated,
			...(reason ? { reason } : {}),
		},
		livePopulation: true,
		coherentSnapshot: false,
		admitted: admission.accepted,
		admission,
		...(read.errorCode ? { errorCode: read.errorCode } : {}),
		...(reason ? { reason } : {}),
	};
}

function noResolutionResult(
	input: IncidentRecorderLiveCgroupV2CaptureInput,
	index: number,
	reason: IncidentRecorderLiveCgroupV2CaptureReason,
): IncidentRecorderLiveCgroupV2CaptureResult {
	const name = INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES[index] ?? "";
	const receipt = sourceReceipt(
		index,
		name,
		"",
		{ bytes: Buffer.alloc(0), bytesRead: 0, complete: false },
		"unavailable",
		0,
		noAdmission(reason),
		reason,
	);
	return {
		runId: input.runId,
		runToken: input.runToken,
		rootPid: input.rootPid,
		rootProcessStartId: input.rootProcessStartId,
		triggerOccurrenceId: input.triggerOccurrenceId,
		captureId: input.captureId,
		sourceIndex: index,
		nextSourceIndex: index,
		bytesRead: 0,
		retainedBytes: 0,
		complete: false,
		terminalCoverage: "incomplete",
		reason,
		receipt,
		receipts: [receipt],
	};
}

/** Capture one source from the fixed live cgroup v2 source set. */
export function captureIncidentRecorderLiveCgroupV2(
	input: IncidentRecorderLiveCgroupV2CaptureInput,
): IncidentRecorderLiveCgroupV2CaptureResult {
	assertUuid(input.runId, "runId");
	assertUuid(input.runToken, "runToken");
	assertPositivePid(input.rootPid);
	assertIdentity(input.rootProcessStartId, "rootProcessStartId");
	assertUuid(input.triggerOccurrenceId, "triggerOccurrenceId");
	assertUuid(input.captureId, "captureId");
	const requestedSourceIndex = input.nextSourceIndex ?? input.sourceIndex ?? 0;
	if (!Number.isSafeInteger(requestedSourceIndex) || requestedSourceIndex < 0)
		throw new TypeError("nextSourceIndex must be a non-negative integer");

	const sourceCount = INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES.length;
	const index = Math.min(requestedSourceIndex, sourceCount);
	const common = {
		runId: input.runId,
		runToken: input.runToken,
		rootPid: input.rootPid,
		rootProcessStartId: input.rootProcessStartId,
		triggerOccurrenceId: input.triggerOccurrenceId,
		captureId: input.captureId,
		sourceIndex: index,
	};
	if (index >= sourceCount)
		return {
			...common,
			nextSourceIndex: sourceCount,
			bytesRead: 0,
			retainedBytes: 0,
			complete: true,
			terminalCoverage: "complete",
			receipts: [],
		};

	const deadlineMs = boundedInteger(
		input.deadlineMs,
		INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_DEADLINE_MS,
		INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_DEADLINE_MS,
	);
	const byteBudget = boundedInteger(
		input.byteBudget,
		INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_BYTE_BUDGET,
		INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_BYTE_BUDGET,
	);
	const now = input.now ?? input.monotonic ?? (() => performance.now());
	const deadlineAt = now() + deadlineMs;
	if (process.platform !== "linux") return noResolutionResult(input, index, "unsupported_platform");
	if (now() >= deadlineAt) return noResolutionResult(input, index, "deadline");
	if (byteBudget <= 0) return noResolutionResult(input, index, "byte_budget");

	const processStartIdReader = input.processStartIdReader ?? getProcessStartId;
	const identityMatches = (): boolean => {
		try {
			return processStartIdReader(input.rootPid) === input.rootProcessStartId;
		} catch {
			return false;
		}
	};
	if (!identityMatches()) return noResolutionResult(input, index, "identity_changed");

	const resolutionDependencies =
		input.resolutionDependencies ??
		input.dependencies ??
		input.resolverDependencies ??
		defaultLinuxCgroupV2ResolutionDependencies();
	const resolved = resolveCgroupDirectory(input.rootPid, resolutionDependencies);
	if (!resolved || !identityMatches())
		return noResolutionResult(input, index, resolved ? "identity_changed" : "resolution_failed");
	if (now() >= deadlineAt) return noResolutionResult(input, index, "deadline");

	const name = INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES[index];
	const path = sourcePath(resolved.directory, name);
	const fileSystem = input.fileSystem ?? defaultFileSystem;
	const read = readBoundedSource(path, fileSystem, byteBudget, deadlineAt, now);
	const after = resolveCgroupDirectory(input.rootPid, resolutionDependencies);
	if (!after) return noResolutionResult(input, index, "resolution_failed");
	if (!identityMatches() || !sameMembership(resolved, after))
		return noResolutionResult(input, index, "identity_changed");

	const failedWithoutBytes = !read.complete && read.bytes.length === 0;
	const coverageState: IncidentRecorderLiveCgroupV2CaptureCoverageState = read.complete
		? "complete"
		: failedWithoutBytes
			? "unavailable"
			: "truncated";
	const reason = read.reason;
	let admission: IncidentRecorderLiveCgroupV2CaptureAdmission = noAdmission(reason);
	let admittedBytes = 0;
	if (read.complete || read.bytes.length > 0) {
		if (now() >= deadlineAt) admission = noAdmission("deadline");
		else if (read.reason === "deadline" || read.reason === "byte_budget") admission = noAdmission(read.reason);
		else if (!identityMatches()) admission = noAdmission("identity_changed");
		else {
			try {
				const writerAdmission = input.writer.recordExactBytesForRun(
					{ runId: input.runId, runToken: input.runToken },
					"linux-raw-source",
					"live_cgroup_v2_source_snapshot",
					read.bytes,
					"exact-file-bytes",
					{
						...baseMetadata(
							input,
							resolved,
							index,
							path,
							read.bytes.length,
							coverageState,
							coverageState === "truncated",
							reason,
						),
						...(read.complete ? { sourceBytes: read.bytes.length } : {}),
					},
				);
				if (writerAdmission.accepted) {
					admittedBytes = read.bytes.length;
					admission = {
						accepted: true,
						disposition: "locally_admitted",
						occurrenceId: writerAdmission.occurrenceId,
						...(reason ? { reason } : {}),
					};
				} else {
					admission = {
						accepted: false,
						disposition: "rejected",
						reason: "queue_rejection",
						writerReason: writerAdmission.reason,
					};
				}
			} catch {
				admission = { accepted: false, disposition: "rejected", reason: "queue_rejection" };
			}
		}
	}

	if (failedWithoutBytes && now() < deadlineAt && identityMatches()) {
		const failureReason = read.reason ?? "read_failed";
		try {
			const writerAdmission = input.writer.recordExactBytesForRun(
				{ runId: input.runId, runToken: input.runToken },
				"linux-raw-source",
				"live_cgroup_v2_source_unavailable",
				Buffer.alloc(0),
				"none",
				{
					...baseMetadata(input, resolved, index, path, 0, "unavailable", false, failureReason),
					category: "source_unavailable",
					code: read.errorCode ?? "UNKNOWN",
					provenance: "live_cgroup_v2",
				},
			);
			if (writerAdmission.accepted) {
				admission = {
					accepted: true,
					disposition: "locally_admitted",
					occurrenceId: writerAdmission.occurrenceId,
					reason: failureReason,
				};
			} else {
				admission = {
					accepted: false,
					disposition: "rejected",
					reason: "queue_rejection",
					writerReason: writerAdmission.reason,
				};
			}
		} catch {
			admission = { accepted: false, disposition: "rejected", reason: "queue_rejection" };
		}
	}

	const receipt = sourceReceipt(
		index,
		name,
		path,
		read,
		coverageState,
		admittedBytes,
		admission,
		admission.reason ?? reason ?? (failedWithoutBytes ? "read_failed" : undefined),
	);
	const advances = admission.accepted;
	const nextSourceIndex = advances ? index + 1 : index;
	return {
		...common,
		nextSourceIndex,
		bytesRead: read.bytesRead,
		retainedBytes: admittedBytes,
		complete: advances && nextSourceIndex >= sourceCount,
		terminalCoverage: advances && nextSourceIndex >= sourceCount ? "complete" : "incomplete",
		resolved,
		membershipRaw: resolved.membershipRaw,
		receipt,
		receipts: [receipt],
		...(receipt.reason ? { reason: receipt.reason } : {}),
	};
}
