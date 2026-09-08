import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { getProcessStartId } from "../../core/session-lease.js";
import type { IncidentRecorderAdmission, IncidentRecorderWriter } from "./incident-recorder-writer.js";

/** The provider pass is intentionally smaller than the ordinary service writer window. */
export const INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_DEADLINE_MS = 40;
export const INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_BYTE_BUDGET = 4 * 1024 * 1024;
export const INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_ARTIFACTS = 64;
export const INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES = 128 * 1024;
export const INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_LOOKAHEAD_BYTES = 1;
export const INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_CHUNK_BYTES = 64 * 1024;

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0);
const MAX_ARTIFACT_TEXT_BYTES = 512;

export type IncidentRecorderLiveProviderPrefixCaptureReason =
	| "read_failed"
	| "not_regular_file"
	| "invalid_artifact"
	| "identity_changed"
	| "deadline"
	| "byte_budget"
	| "truncated"
	| "changed_during_read"
	| "queue_rejection"
	| "artifact_cap"
	| "unsupported_platform";

export type IncidentRecorderLiveProviderPrefixCaptureCoverageState = "complete" | "truncated" | "unavailable";
export type IncidentRecorderLiveProviderPrefixCaptureTerminalCoverage = "complete" | "incomplete" | "capped";

/** Only the ordinary service-writer operation is needed by this bounded leaf. */
export type IncidentRecorderLiveProviderPrefixCaptureWriter = Pick<IncidentRecorderWriter, "recordExactBytesForRun">;

export interface IncidentRecorderLiveProviderArtifact {
	provider: string;
	path: string;
	format: string;
}

export interface IncidentRecorderLiveProviderPrefixCaptureStat {
	readonly dev: bigint;
	readonly ino: bigint;
	readonly size: bigint;
	readonly mtimeNs: bigint;
	isFile(): boolean;
}

/** Synchronous operations are injectable so bounded-read behavior can be tested without provider data. */
export interface IncidentRecorderLiveProviderPrefixCaptureFileSystem {
	openSync(path: string, flags: number): number;
	fstatSync(fd: number): IncidentRecorderLiveProviderPrefixCaptureStat;
	readSync(fd: number, buffer: Buffer, offset: number, length: number, position: number | null): number;
	closeSync(fd: number): void;
}

export interface IncidentRecorderLiveProviderPrefixCaptureInput {
	runId: string;
	runToken: string;
	targetPid: number;
	targetProcessStartId: string;
	triggerOccurrenceId: string;
	captureId: string;
	artifacts: readonly IncidentRecorderLiveProviderArtifact[];
	nextArtifactIndex?: number;
	/** Maximum cooperative duration for this pass. Values above 40ms are clamped. */
	deadlineMs?: number;
	/** Shared byte budget for this pass. Values above 4MiB are clamped. */
	byteBudget?: number;
	writer: IncidentRecorderLiveProviderPrefixCaptureWriter;
	fileSystem?: IncidentRecorderLiveProviderPrefixCaptureFileSystem;
	processStartIdReader?: (pid: number) => string | undefined;
	/** Must be a monotonic millisecond clock. */
	now?: () => number;
}

export interface IncidentRecorderLiveProviderPrefixCaptureAdmission {
	accepted: boolean;
	disposition: "locally_admitted" | "rejected" | "not_attempted";
	occurrenceId?: string;
	reason?: IncidentRecorderLiveProviderPrefixCaptureReason;
	writerReason?: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"];
}

export interface IncidentRecorderLiveProviderPrefixCaptureReceipt {
	artifactIndex: number;
	provider: string;
	format: string;
	sourcePath: string;
	bytesRead: number;
	retainedBytes: number;
	sourceBytes?: number | string;
	sourceTruncated: boolean;
	truncated: boolean;
	coverageState: IncidentRecorderLiveProviderPrefixCaptureCoverageState;
	coverage: IncidentRecorderLiveProviderPrefixCaptureCoverage;
	before?: IncidentRecorderLiveProviderPrefixCaptureStatReceipt;
	after?: IncidentRecorderLiveProviderPrefixCaptureStatReceipt;
	grew: boolean;
	shrank: boolean;
	changedDuringRead: boolean;
	admitted: boolean;
	admission: IncidentRecorderLiveProviderPrefixCaptureAdmission;
	reason?: IncidentRecorderLiveProviderPrefixCaptureReason;
}

export interface IncidentRecorderLiveProviderPrefixCaptureCoverage {
	state: IncidentRecorderLiveProviderPrefixCaptureCoverageState;
	retainedBytes: number;
	sourceBytes?: number | string;
	truncated: boolean;
	reason?: IncidentRecorderLiveProviderPrefixCaptureReason;
}

export interface IncidentRecorderLiveProviderPrefixCaptureStatReceipt {
	dev: string;
	ino: string;
	size: string;
	mtimeNs: string;
}

export interface IncidentRecorderLiveProviderPrefixCaptureResult {
	runId: string;
	runToken: string;
	targetPid: number;
	targetProcessStartId: string;
	triggerOccurrenceId: string;
	captureId: string;
	bytesRead: number;
	receipt?: IncidentRecorderLiveProviderPrefixCaptureReceipt;
	nextArtifactIndex: number;
	terminalCoverage: IncidentRecorderLiveProviderPrefixCaptureTerminalCoverage;
	artifactLimitReached: boolean;
}

interface BoundedRead {
	bytes: Buffer;
	bytesRead: number;
	exactEof: boolean;
	readFailed: boolean;
	reason?: IncidentRecorderLiveProviderPrefixCaptureReason;
}

const defaultFileSystem: IncidentRecorderLiveProviderPrefixCaptureFileSystem = {
	openSync,
	fstatSync(fd) {
		return fstatSync(fd, { bigint: true });
	},
	readSync,
	closeSync,
};

function boundedInteger(value: number | undefined, fallback: number, maximum: number): number {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	return Math.min(maximum, Math.max(0, Math.floor(value)));
}

function assertPositivePid(pid: number): void {
	if (!Number.isSafeInteger(pid) || pid <= 0) throw new TypeError("targetPid must be a positive PID");
}

function assertIdentity(value: string, field: string): void {
	if (typeof value !== "string" || value.length === 0) throw new TypeError(`${field} must be non-empty`);
}

function assertUuid(value: string, field: string): void {
	if (!CANONICAL_UUID.test(value)) throw new TypeError(`${field} must be a canonical UUID`);
}

function isBoundedText(value: string): boolean {
	return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= MAX_ARTIFACT_TEXT_BYTES;
}

function isSafeArtifactPath(path: string): boolean {
	if (!path.startsWith("/") || path.includes("\0") || Buffer.byteLength(path, "utf8") > MAX_ARTIFACT_TEXT_BYTES)
		return false;
	return !path.split("/").some((component) => component === "..");
}

function validArtifact(artifact: IncidentRecorderLiveProviderArtifact): boolean {
	return (
		artifact !== null &&
		typeof artifact === "object" &&
		isBoundedText(artifact.provider) &&
		isBoundedText(artifact.format) &&
		typeof artifact.path === "string" &&
		isSafeArtifactPath(artifact.path)
	);
}

function validStat(value: IncidentRecorderLiveProviderPrefixCaptureStat): boolean {
	try {
		return (
			typeof value.isFile === "function" &&
			typeof value.dev === "bigint" &&
			value.dev >= 0n &&
			typeof value.ino === "bigint" &&
			value.ino >= 0n &&
			typeof value.size === "bigint" &&
			value.size >= 0n &&
			typeof value.mtimeNs === "bigint" &&
			value.mtimeNs >= 0n
		);
	} catch {
		return false;
	}
}

function statReceipt(
	stat: IncidentRecorderLiveProviderPrefixCaptureStat,
): IncidentRecorderLiveProviderPrefixCaptureStatReceipt {
	return {
		dev: stat.dev.toString(10),
		ino: stat.ino.toString(10),
		size: stat.size.toString(10),
		mtimeNs: stat.mtimeNs.toString(10),
	};
}

function sameStat(
	left: IncidentRecorderLiveProviderPrefixCaptureStat,
	right: IncidentRecorderLiveProviderPrefixCaptureStat,
): boolean {
	return (
		left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeNs === right.mtimeNs
	);
}

function scalarSize(value: bigint): number | string {
	return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString(10);
}

function identityMatches(
	input: IncidentRecorderLiveProviderPrefixCaptureInput,
	reader: (pid: number) => string | undefined,
): boolean {
	try {
		return reader(input.targetPid) === input.targetProcessStartId;
	} catch {
		return false;
	}
}

function readBoundedPrefix(
	path: string,
	fileSystem: IncidentRecorderLiveProviderPrefixCaptureFileSystem,
	byteBudget: number,
	deadlineAt: number,
	now: () => number,
): {
	before?: IncidentRecorderLiveProviderPrefixCaptureStat;
	after?: IncidentRecorderLiveProviderPrefixCaptureStat;
	read: BoundedRead;
} {
	let descriptor: number | undefined;
	let before: IncidentRecorderLiveProviderPrefixCaptureStat | undefined;
	let after: IncidentRecorderLiveProviderPrefixCaptureStat | undefined;
	let bytesRead = 0;
	let readFailed = false;
	let reason: IncidentRecorderLiveProviderPrefixCaptureReason | undefined;
	let exactEof = false;
	const parts: Buffer[] = [];

	try {
		descriptor = fileSystem.openSync(path, READ_FLAGS);
		const opened = fileSystem.fstatSync(descriptor);
		if (!validStat(opened)) throw new Error("invalid provider prefix stat");
		before = opened;
		if (!before.isFile()) {
			reason = "not_regular_file";
			return { before, read: { bytes: Buffer.alloc(0), bytesRead, exactEof, readFailed, reason } };
		}
		const prefixLimit = BigInt(INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES);
		const targetBytes =
			before.size < prefixLimit
				? Number(before.size)
				: INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES;
		while (parts.reduce((total, part) => total + part.length, 0) < targetBytes) {
			if (now() >= deadlineAt) {
				reason = "deadline";
				break;
			}
			if (bytesRead >= byteBudget) {
				reason = "byte_budget";
				break;
			}
			const retained = parts.reduce((total, part) => total + part.length, 0);
			const requested = Math.min(
				INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_CHUNK_BYTES,
				targetBytes - retained,
				byteBudget - bytesRead,
			);
			if (requested <= 0) {
				reason = bytesRead >= byteBudget ? "byte_budget" : "truncated";
				break;
			}
			const chunk = Buffer.allocUnsafe(requested);
			const count = fileSystem.readSync(descriptor, chunk, 0, requested, null);
			if (!Number.isSafeInteger(count) || count < 0 || count > requested)
				throw new Error("invalid provider prefix read count");
			bytesRead += count;
			if (count > 0) parts.push(Buffer.from(chunk.subarray(0, count)));
			if (count === 0) break;
		}

		const retained = parts.reduce((total, part) => total + part.length, 0);
		if (reason === undefined && retained >= targetBytes) {
			if (targetBytes < INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES) {
				exactEof = true;
			} else if (now() >= deadlineAt) {
				reason = "deadline";
			} else if (bytesRead >= byteBudget) {
				reason = "byte_budget";
			} else {
				const lookahead = Buffer.allocUnsafe(INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_LOOKAHEAD_BYTES);
				const count = fileSystem.readSync(
					descriptor,
					lookahead,
					0,
					INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_LOOKAHEAD_BYTES,
					null,
				);
				if (!Number.isSafeInteger(count) || count < 0 || count > 1)
					throw new Error("invalid provider prefix lookahead count");
				bytesRead += count;
				if (count === 0) exactEof = true;
				else reason = "truncated";
			}
		} else if (reason === undefined && retained === targetBytes) {
			exactEof = true;
		}
	} catch {
		readFailed = true;
		reason = reason ?? "read_failed";
		exactEof = false;
	} finally {
		if (descriptor !== undefined) {
			try {
				const observedAfter = fileSystem.fstatSync(descriptor);
				if (!validStat(observedAfter)) {
					readFailed = true;
					reason = reason ?? "read_failed";
					exactEof = false;
				} else after = observedAfter;
			} catch {
				readFailed = true;
				reason = reason ?? "read_failed";
				exactEof = false;
			}
			try {
				fileSystem.closeSync(descriptor);
			} catch {
				readFailed = true;
				reason = reason ?? "read_failed";
				exactEof = false;
			}
		}
	}

	return {
		before,
		after,
		read: { bytes: Buffer.concat(parts), bytesRead, exactEof, readFailed, ...(reason ? { reason } : {}) },
	};
}

function baseResult(
	input: IncidentRecorderLiveProviderPrefixCaptureInput,
	nextArtifactIndex: number,
	terminalCoverage: IncidentRecorderLiveProviderPrefixCaptureTerminalCoverage,
	artifactLimitReached: boolean,
	receipt?: IncidentRecorderLiveProviderPrefixCaptureReceipt,
): IncidentRecorderLiveProviderPrefixCaptureResult {
	return {
		runId: input.runId,
		runToken: input.runToken,
		targetPid: input.targetPid,
		targetProcessStartId: input.targetProcessStartId,
		triggerOccurrenceId: input.triggerOccurrenceId,
		captureId: input.captureId,
		bytesRead: receipt?.bytesRead ?? 0,
		...(receipt ? { receipt } : {}),
		nextArtifactIndex,
		terminalCoverage,
		artifactLimitReached,
	};
}

function admissionNotAttempted(
	reason?: IncidentRecorderLiveProviderPrefixCaptureReason,
): IncidentRecorderLiveProviderPrefixCaptureAdmission {
	return { accepted: false, disposition: "not_attempted", ...(reason ? { reason } : {}) };
}

/** Capture one already-registered provider artifact prefix into the ordinary service writer. */
export function captureIncidentRecorderLiveProviderPrefix(
	input: IncidentRecorderLiveProviderPrefixCaptureInput,
): IncidentRecorderLiveProviderPrefixCaptureResult {
	assertUuid(input.runId, "runId");
	assertUuid(input.runToken, "runToken");
	assertPositivePid(input.targetPid);
	assertIdentity(input.targetProcessStartId, "targetProcessStartId");
	assertUuid(input.triggerOccurrenceId, "triggerOccurrenceId");
	assertUuid(input.captureId, "captureId");
	if (!Number.isSafeInteger(input.nextArtifactIndex ?? 0) || (input.nextArtifactIndex ?? 0) < 0)
		throw new TypeError("nextArtifactIndex must be a non-negative integer");

	const index = Math.min(input.nextArtifactIndex ?? 0, INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_ARTIFACTS);
	const artifactLimitReached = input.artifacts.length > INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_ARTIFACTS;
	const artifactCount = Math.min(input.artifacts.length, INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_ARTIFACTS);
	if (index >= artifactCount) {
		return baseResult(input, artifactCount, artifactLimitReached ? "capped" : "complete", artifactLimitReached);
	}
	const terminalForCurrent = (
		nextIndex: number,
		currentComplete: boolean,
	): IncidentRecorderLiveProviderPrefixCaptureTerminalCoverage => {
		if (nextIndex < artifactCount) return currentComplete ? "incomplete" : "incomplete";
		return artifactLimitReached ? "capped" : currentComplete ? "complete" : "incomplete";
	};

	const artifact = input.artifacts[index];
	if (!validArtifact(artifact)) {
		const receipt: IncidentRecorderLiveProviderPrefixCaptureReceipt = {
			artifactIndex: index,
			provider: typeof artifact?.provider === "string" ? artifact.provider : "unknown",
			format: typeof artifact?.format === "string" ? artifact.format : "unknown",
			sourcePath: typeof artifact?.path === "string" ? artifact.path : "",
			bytesRead: 0,
			retainedBytes: 0,
			sourceTruncated: false,
			truncated: false,
			coverageState: "unavailable",
			coverage: { state: "unavailable", retainedBytes: 0, truncated: false, reason: "invalid_artifact" },
			grew: false,
			shrank: false,
			changedDuringRead: false,
			admitted: false,
			admission: admissionNotAttempted("invalid_artifact"),
			reason: "invalid_artifact",
		};
		return baseResult(input, index, "incomplete", artifactLimitReached, receipt);
	}

	const deadlineMs = boundedInteger(
		input.deadlineMs,
		INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_DEADLINE_MS,
		INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_DEADLINE_MS,
	);
	const byteBudget = boundedInteger(
		input.byteBudget,
		INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_BYTE_BUDGET,
		INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_BYTE_BUDGET,
	);
	const now = input.now ?? (() => performance.now());
	const deadlineAt = now() + deadlineMs;
	const processStartIdReader = input.processStartIdReader ?? getProcessStartId;
	const unavailableReceipt = (reason: IncidentRecorderLiveProviderPrefixCaptureReason) =>
		baseResult(input, index, "incomplete", artifactLimitReached, {
			artifactIndex: index,
			provider: artifact.provider,
			format: artifact.format,
			sourcePath: artifact.path,
			bytesRead: 0,
			retainedBytes: 0,
			sourceTruncated: false,
			truncated: false,
			coverageState: "unavailable",
			coverage: { state: "unavailable", retainedBytes: 0, truncated: false, reason },
			grew: false,
			shrank: false,
			changedDuringRead: false,
			admitted: false,
			admission: admissionNotAttempted(reason),
			reason,
		});

	if (process.platform !== "linux") return unavailableReceipt("unsupported_platform");
	if (now() >= deadlineAt) return unavailableReceipt("deadline");
	if (byteBudget <= 0) return unavailableReceipt("byte_budget");
	if (!identityMatches(input, processStartIdReader)) return unavailableReceipt("identity_changed");

	const fileSystem = input.fileSystem ?? defaultFileSystem;
	const observed = readBoundedPrefix(artifact.path, fileSystem, byteBudget, deadlineAt, now);
	const read = observed.read;
	const before = observed.before;
	const after = observed.after;
	const changedDuringRead = before !== undefined && after !== undefined && !sameStat(before, after);
	const grew = before !== undefined && after !== undefined && after.size > before.size;
	const shrank = before !== undefined && after !== undefined && after.size < before.size;
	let sourceTruncated = read.bytes.length > 0 && (!read.exactEof || read.readFailed || grew || shrank);
	let reason = read.reason;
	if (changedDuringRead) reason = reason ?? "changed_during_read";
	if (!read.exactEof && reason === undefined) reason = "truncated";
	const stableMetadata = before !== undefined && after !== undefined && sameStat(before, after);
	let coverageState: IncidentRecorderLiveProviderPrefixCaptureCoverageState =
		before === undefined ||
		(after === undefined && read.bytes.length === 0) ||
		read.reason === "not_regular_file" ||
		(read.readFailed && read.bytes.length === 0)
			? "unavailable"
			: read.exactEof && !changedDuringRead && !read.readFailed
				? "complete"
				: "truncated";
	let admission = admissionNotAttempted(reason);
	let retainedBytes = 0;
	let admitted = false;
	const stableEmptyFileRead =
		read.bytes.length === 0 &&
		before !== undefined &&
		after !== undefined &&
		before.size === 0n &&
		stableMetadata &&
		read.exactEof &&
		!read.readFailed &&
		read.reason === undefined;

	if (
		before !== undefined &&
		(after !== undefined || read.bytes.length > 0) &&
		(read.bytes.length > 0 || stableEmptyFileRead)
	) {
		if (!identityMatches(input, processStartIdReader)) {
			reason = "identity_changed";
			sourceTruncated = false;
			coverageState = "unavailable";
		} else {
			const metadata: Record<string, string | number | boolean> = {
				rootPid: input.targetPid,
				rootProcessStartId: input.targetProcessStartId,
				targetPid: input.targetPid,
				targetProcessStartId: input.targetProcessStartId,
				triggerOccurrenceId: input.triggerOccurrenceId,
				captureId: input.captureId,
				provider: artifact.provider,
				format: artifact.format,
				sourcePath: artifact.path,
				beforeDev: before.dev.toString(10),
				beforeIno: before.ino.toString(10),
				beforeSize: before.size.toString(10),
				beforeMtimeNs: before.mtimeNs.toString(10),
				...(after
					? {
							afterDev: after.dev.toString(10),
							afterIno: after.ino.toString(10),
							afterSize: after.size.toString(10),
							afterMtimeNs: after.mtimeNs.toString(10),
						}
					: {}),
				retainedBytes: read.bytes.length,
				sourceTruncated,
				state: coverageState === "complete" ? "complete" : "incomplete",
				grew,
				shrank,
				changedDuringRead,
				additiveOnly: true,
			};
			if (stableMetadata && after !== undefined) metadata.sourceBytes = scalarSize(after.size);
			if (reason !== undefined) metadata.reason = reason;
			try {
				const writerAdmission = input.writer.recordExactBytesForRun(
					{ runId: input.runId, runToken: input.runToken },
					"provider-raw-source",
					"live_provider_prefix_snapshot",
					read.bytes,
					"exact-file-bytes",
					metadata,
				);
				if (writerAdmission.accepted) {
					admitted = true;
					retainedBytes = read.bytes.length;
					admission = {
						accepted: true,
						disposition: "locally_admitted",
						occurrenceId: writerAdmission.occurrenceId,
						...(reason ? { reason } : {}),
					};
				} else {
					reason = "queue_rejection";
					admission = {
						accepted: false,
						disposition: "rejected",
						reason,
						writerReason: writerAdmission.reason,
					};
				}
			} catch {
				reason = "queue_rejection";
				admission = { accepted: false, disposition: "rejected", reason };
			}
		}
	}

	if (!admitted && admission.disposition === "not_attempted" && reason === undefined) reason = "read_failed";
	const receipt: IncidentRecorderLiveProviderPrefixCaptureReceipt = {
		artifactIndex: index,
		provider: artifact.provider,
		format: artifact.format,
		sourcePath: artifact.path,
		bytesRead: read.bytesRead,
		retainedBytes,
		...(stableMetadata && after ? { sourceBytes: scalarSize(after.size) } : {}),
		sourceTruncated,
		truncated: coverageState === "truncated",
		coverageState,
		coverage: {
			state: coverageState,
			retainedBytes,
			...(stableMetadata && after ? { sourceBytes: scalarSize(after.size) } : {}),
			truncated: coverageState === "truncated",
			...(reason ? { reason } : {}),
		},
		...(before ? { before: statReceipt(before) } : {}),
		...(after ? { after: statReceipt(after) } : {}),
		grew,
		shrank,
		changedDuringRead,
		admitted,
		admission,
		...(reason ? { reason } : {}),
	};
	const nextIndex = admitted ? index + 1 : index;
	const currentComplete = admitted && coverageState === "complete";
	return baseResult(input, nextIndex, terminalForCurrent(nextIndex, currentComplete), artifactLimitReached, receipt);
}
