import { createHash, randomUUID } from "node:crypto";
import { opendirSync, readlinkSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { getProcessStartId } from "../../core/session-lease.js";
import type { IncidentRecorderAdmission, IncidentRecorderWriter } from "./incident-recorder-writer.js";

/** The fd-link pass is deliberately bounded for the service-writer hot path. */
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DEADLINE_MS = 40;
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_BYTE_BUDGET = 4 * 1024 * 1024;
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_SUBJECTS = 256;
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DIRECTORY_ENTRIES = 256;
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_LINK_ATTEMPTS = 256;
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_TARGET_BYTES = 128 * 1024;
/** This is the complete UTF-8 JSON body, including its JSON/base64 overhead. */
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_BATCH_BYTES = 128 * 1024;
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_DESCRIPTOR_LIMIT = 256;
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_ROOT_SOURCE_PATH = "/proc/{rootPid}/fd";
export const INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_BODY_PER_RECORD_PATH = "/proc/{pid}/fd/{fd}";

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CANONICAL_FD = /^(?:0|[1-9][0-9]*)$/;

export type IncidentRecorderLiveFdLinkCaptureCoverage =
	| "complete_within_selected_live_pass"
	| "truncated"
	| "unavailable";

export type IncidentRecorderLiveFdLinkCaptureReason =
	| "deadline"
	| "byte_budget"
	| "directory_entry_limit"
	| "link_attempt_limit"
	| "batch_limit"
	| "unobserved_rest"
	| "identity_changed"
	| "identity_unavailable"
	| "root_identity_changed"
	| "invalid_subject"
	| "duplicate_subject"
	| "subject_limit"
	| "directory_unavailable"
	| "directory_read_failed"
	| "directory_close_failed"
	| "malformed_fd"
	| "readlink_unavailable"
	| "readlink_non_buffer"
	| "link_too_large"
	| "queue_rejection"
	| "unsupported_platform";

export type IncidentRecorderLiveFdLinkCaptureErrno =
	| "enoent"
	| "esrch"
	| "eacces"
	| "eperm"
	| "enotdir"
	| "emfile"
	| "enfile"
	| "einval"
	| "eio"
	| "ebadf"
	| "unknown";

export type IncidentRecorderLiveFdLinkCaptureWriter = Pick<IncidentRecorderWriter, "recordExactBytesForRun">;

export interface IncidentRecorderLiveFdLinkCaptureDirectoryEntry {
	name: string;
}

export interface IncidentRecorderLiveFdLinkCaptureDirectory {
	readSync(): IncidentRecorderLiveFdLinkCaptureDirectoryEntry | null;
	closeSync(): void;
}

/** Only directory enumeration and Buffer-preserving readlink are needed. */
export interface IncidentRecorderLiveFdLinkCaptureFileSystem {
	opendirSync?(path: string): IncidentRecorderLiveFdLinkCaptureDirectory;
	opendir?(path: string): IncidentRecorderLiveFdLinkCaptureDirectory;
	readlinkBuffer(path: string): Buffer;
}

export interface IncidentRecorderLiveFdLinkCaptureSubject {
	pid: number;
	/** The accepted live subject identity. `start` is accepted as a compatibility alias. */
	processStartId?: string;
	start?: string;
}

export interface IncidentRecorderLiveFdLinkCaptureInput {
	runId: string;
	runToken: string;
	rootPid: number;
	rootProcessStartId: string;
	triggerOccurrenceId: string;
	captureId: string;
	subjects: readonly IncidentRecorderLiveFdLinkCaptureSubject[];
	deadlineMs?: number;
	byteBudget?: number;
	writer: IncidentRecorderLiveFdLinkCaptureWriter;
	fileSystem?: IncidentRecorderLiveFdLinkCaptureFileSystem;
	/** Process identity seam. It must return the current start identity or undefined. */
	identity?: (pid: number) => string | undefined;
	processStartIdReader?: (pid: number) => string | undefined;
	/** Monotonic milliseconds used for cooperative deadline checks. */
	now?: () => number;
	/** Alias for `now`, retained for callers that name the seam by its contract. */
	monotonic?: () => number;
}

export interface IncidentRecorderLiveFdLinkCaptureAdmission {
	accepted: boolean;
	disposition: "locally_admitted" | "rejected" | "not_attempted";
	occurrenceId?: string;
	reason?: IncidentRecorderLiveFdLinkCaptureReason;
	writerReason?: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"];
}

export type IncidentRecorderLiveFdLinkCaptureEntryState =
	| "admitted"
	| "retained"
	| "malformed"
	| "unavailable"
	| "identity_changed"
	| "not_attempted"
	| "batch_limit";

export interface IncidentRecorderLiveFdLinkCaptureEntryReceipt {
	pid: number;
	subjectPid: number;
	fd?: number;
	state: IncidentRecorderLiveFdLinkCaptureEntryState;
	sourcePath: string;
	bytesRead: number;
	retainedBytes: number;
	targetBytes?: number;
	targetSha256?: string;
	admitted: boolean;
	admission: IncidentRecorderLiveFdLinkCaptureAdmission;
	errorCode?: IncidentRecorderLiveFdLinkCaptureErrno;
	reason?: IncidentRecorderLiveFdLinkCaptureReason;
}

export type IncidentRecorderLiveFdLinkCaptureSubjectState =
	| "admitted"
	| "empty"
	| "unavailable"
	| "identity_changed"
	| "not_attempted"
	| "truncated";

export interface IncidentRecorderLiveFdLinkCaptureSubjectReceipt {
	pid: number;
	processStartId?: string;
	state: IncidentRecorderLiveFdLinkCaptureSubjectState;
	beforeProcessStartId?: string;
	afterProcessStartId?: string;
	directoryEntriesSeen: number;
	linkAttempts: number;
	recordCount: number;
	errorCount: number;
	entries: readonly IncidentRecorderLiveFdLinkCaptureEntryReceipt[];
	reason?: IncidentRecorderLiveFdLinkCaptureReason;
	errorCode?: IncidentRecorderLiveFdLinkCaptureErrno;
}

export interface IncidentRecorderLiveFdLinkCaptureResult {
	runId: string;
	runToken: string;
	rootPid: number;
	rootProcessStartId: string;
	triggerOccurrenceId: string;
	captureId: string;
	selectedSubjects: readonly IncidentRecorderLiveFdLinkCaptureSubject[];
	selectedSubjectsSha256: string;
	subjectCount: number;
	recordCount: number;
	errorCount: number;
	directoryEntriesSeen: number;
	linkAttempts: number;
	descriptorLimit: number;
	bytesRead: number;
	retainedBytes: number;
	batchBytes: number;
	deadlineMs: number;
	byteBudget: number;
	coverage: IncidentRecorderLiveFdLinkCaptureCoverage;
	coverageState: IncidentRecorderLiveFdLinkCaptureCoverage;
	passState: IncidentRecorderLiveFdLinkCaptureCoverage;
	state: IncidentRecorderLiveFdLinkCaptureCoverage;
	sourceTruncated: boolean;
	treeCompleteness: "not_claimed";
	livePopulation: true;
	coherentSnapshot: false;
	additiveOnly: true;
	nextCursor: null;
	rootSourcePath: string;
	bodyPerRecordPath: string;
	subjectReceipts: readonly IncidentRecorderLiveFdLinkCaptureSubjectReceipt[];
	receipts: readonly IncidentRecorderLiveFdLinkCaptureEntryReceipt[];
	admission: IncidentRecorderLiveFdLinkCaptureAdmission;
	writerReason?: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"];
	reason?: IncidentRecorderLiveFdLinkCaptureReason;
	retryDisposition?: "fresh_capture_required";
	retryCaptureId?: string;
	rescanRequired?: boolean;
}

interface NormalizedSubject {
	pid: number;
	processStartId: string;
}

interface PendingRecord {
	pid: number;
	fd: number;
	targetEncoding: "base64";
	targetBytes: number;
	targetSha256: string;
	targetBase64: string;
}

interface ScanState {
	bytesRead: number;
	directoryEntriesSeen: number;
	linkAttempts: number;
	errorCount: number;
	firstReason?: IncidentRecorderLiveFdLinkCaptureReason;
	firstErrno?: IncidentRecorderLiveFdLinkCaptureErrno;
	truncated: boolean;
	unavailable: boolean;
	stop: boolean;
}

const defaultFileSystem: IncidentRecorderLiveFdLinkCaptureFileSystem = {
	opendirSync,
	readlinkBuffer(path: string): Buffer {
		const value = readlinkSync(path, { encoding: "buffer" });
		if (!Buffer.isBuffer(value)) throw new TypeError("readlink did not return a Buffer");
		return value;
	},
};

function boundedInteger(value: number | undefined, fallback: number, maximum: number): number {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	return Math.min(maximum, Math.max(0, Math.floor(value)));
}

function assertUuid(value: string, field: string): void {
	if (!CANONICAL_UUID.test(value)) throw new TypeError(`${field} must be a canonical UUID`);
}

function assertPid(value: number, field: string): void {
	if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${field} must be a positive PID`);
}

function assertIdentity(value: string, field: string): void {
	if (typeof value !== "string" || value.length === 0) throw new TypeError(`${field} must be non-empty`);
}

function classifyErrno(error: unknown): IncidentRecorderLiveFdLinkCaptureErrno {
	const code = (error as NodeJS.ErrnoException | undefined)?.code?.toLowerCase();
	if (
		code === "enoent" ||
		code === "esrch" ||
		code === "eacces" ||
		code === "eperm" ||
		code === "enotdir" ||
		code === "emfile" ||
		code === "enfile" ||
		code === "einval" ||
		code === "eio" ||
		code === "ebadf"
	)
		return code;
	return "unknown";
}

function rememberReason(
	state: ScanState,
	reason: IncidentRecorderLiveFdLinkCaptureReason,
	errno?: IncidentRecorderLiveFdLinkCaptureErrno,
): void {
	state.firstReason ??= reason;
	state.firstErrno ??= errno;
	if (
		reason === "deadline" ||
		reason === "byte_budget" ||
		reason === "directory_entry_limit" ||
		reason === "link_attempt_limit" ||
		reason === "batch_limit" ||
		reason === "unobserved_rest" ||
		reason === "subject_limit"
	)
		state.truncated = true;
	if (
		reason === "directory_unavailable" ||
		reason === "directory_read_failed" ||
		reason === "directory_close_failed" ||
		reason === "readlink_unavailable" ||
		reason === "readlink_non_buffer" ||
		reason === "identity_unavailable" ||
		reason === "invalid_subject" ||
		reason === "duplicate_subject" ||
		reason === "malformed_fd" ||
		reason === "link_too_large" ||
		reason === "root_identity_changed" ||
		reason === "identity_changed"
	)
		state.unavailable = true;
}

function readIdentity(reader: (pid: number) => string | undefined, pid: number): string | undefined {
	try {
		const value = reader(pid);
		return typeof value === "string" && value.length > 0 ? value : undefined;
	} catch {
		return undefined;
	}
}

function subjectIdentity(subject: IncidentRecorderLiveFdLinkCaptureSubject): string | undefined {
	const value = subject.processStartId ?? subject.start;
	return typeof value === "string" && value.length > 0 ? value : undefined;
}

function selectionDigest(subjects: readonly NormalizedSubject[]): string {
	return createHash("sha256")
		.update(
			JSON.stringify(subjects.map((subject) => ({ pid: subject.pid, processStartId: subject.processStartId }))),
			"utf8",
		)
		.digest("hex");
}

function sourcePath(pid: number): string {
	return `/proc/${pid}/fd`;
}

function linkPath(pid: number, fd: number): string {
	return `/proc/${pid}/fd/${fd}`;
}

function admissionNotAttempted(
	reason?: IncidentRecorderLiveFdLinkCaptureReason,
): IncidentRecorderLiveFdLinkCaptureAdmission {
	return { accepted: false, disposition: "not_attempted", ...(reason ? { reason } : {}) };
}

function serializeBatch(records: readonly PendingRecord[]): Buffer {
	return Buffer.from(JSON.stringify({ schema: "incident-fd-link-batch-v1", records }), "utf8");
}

function resultBase(
	input: IncidentRecorderLiveFdLinkCaptureInput,
	values: {
		rootProcessStartId: string;
		selectedSubjects: readonly NormalizedSubject[];
		deadlineMs: number;
		byteBudget: number;
		state: IncidentRecorderLiveFdLinkCaptureCoverage;
		bytesRead: number;
		retainedBytes: number;
		directoryEntriesSeen: number;
		linkAttempts: number;
		errorCount: number;
		batchBytes: number;
		subjectReceipts: readonly IncidentRecorderLiveFdLinkCaptureSubjectReceipt[];
		receipts: readonly IncidentRecorderLiveFdLinkCaptureEntryReceipt[];
		admission: IncidentRecorderLiveFdLinkCaptureAdmission;
		reason?: IncidentRecorderLiveFdLinkCaptureReason;
		writerReason?: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"];
		retryCaptureId?: string;
	},
): IncidentRecorderLiveFdLinkCaptureResult {
	const source = sourcePath(input.rootPid);
	return {
		runId: input.runId,
		runToken: input.runToken,
		rootPid: input.rootPid,
		rootProcessStartId: values.rootProcessStartId,
		triggerOccurrenceId: input.triggerOccurrenceId,
		captureId: input.captureId,
		selectedSubjects: values.selectedSubjects,
		selectedSubjectsSha256: selectionDigest(values.selectedSubjects),
		subjectCount: values.selectedSubjects.length,
		recordCount:
			values.retainedBytes > 0 || values.batchBytes > 0
				? values.receipts.filter((receipt) => receipt.state === "admitted" || receipt.state === "retained").length
				: 0,
		errorCount: values.errorCount,
		directoryEntriesSeen: values.directoryEntriesSeen,
		linkAttempts: values.linkAttempts,
		descriptorLimit: INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_DESCRIPTOR_LIMIT,
		bytesRead: values.bytesRead,
		retainedBytes: values.retainedBytes,
		batchBytes: values.batchBytes,
		deadlineMs: values.deadlineMs,
		byteBudget: values.byteBudget,
		coverage: values.state,
		coverageState: values.state,
		passState: values.state,
		state: values.state,
		sourceTruncated: values.state !== "complete_within_selected_live_pass",
		treeCompleteness: "not_claimed",
		livePopulation: true,
		coherentSnapshot: false,
		additiveOnly: true,
		nextCursor: null,
		rootSourcePath: source,
		bodyPerRecordPath: INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_BODY_PER_RECORD_PATH,
		subjectReceipts: values.subjectReceipts,
		receipts: values.receipts,
		admission: values.admission,
		...(values.writerReason ? { writerReason: values.writerReason } : {}),
		...(values.reason ? { reason: values.reason } : {}),
		...(values.retryCaptureId
			? {
					retryDisposition: "fresh_capture_required" as const,
					retryCaptureId: values.retryCaptureId,
					rescanRequired: true,
				}
			: {}),
	};
}

function malformedSubjectReceipt(
	pid: number,
	reason: IncidentRecorderLiveFdLinkCaptureReason,
): IncidentRecorderLiveFdLinkCaptureSubjectReceipt {
	return {
		pid,
		state: "unavailable",
		directoryEntriesSeen: 0,
		linkAttempts: 0,
		recordCount: 0,
		errorCount: 1,
		entries: [],
		reason,
	};
}

function normalizeRootIdentityFailure(
	subjectReceipts: IncidentRecorderLiveFdLinkCaptureSubjectReceipt[],
	entryReceipts: IncidentRecorderLiveFdLinkCaptureEntryReceipt[],
): void {
	for (const entry of entryReceipts) {
		if (entry.state !== "retained" && entry.state !== "admitted") continue;
		entry.state = "identity_changed";
		entry.retainedBytes = 0;
		entry.admitted = false;
		entry.admission = admissionNotAttempted("root_identity_changed");
		entry.reason = "root_identity_changed";
	}
	for (const subject of subjectReceipts) {
		if (subject.state !== "admitted" && subject.recordCount === 0) continue;
		subject.state = "identity_changed";
		subject.recordCount = 0;
		subject.reason = "root_identity_changed";
	}
}

/**
 * Capture one bounded live `/proc/<pid>/fd` pass. This is observational
 * evidence: the selected population is intentionally never described as a
 * coherent or complete process tree.
 */
export function captureIncidentRecorderLiveFdLinks(
	input: IncidentRecorderLiveFdLinkCaptureInput,
): IncidentRecorderLiveFdLinkCaptureResult {
	assertUuid(input.runId, "runId");
	assertUuid(input.runToken, "runToken");
	assertPid(input.rootPid, "rootPid");
	assertIdentity(input.rootProcessStartId, "rootProcessStartId");
	assertUuid(input.triggerOccurrenceId, "triggerOccurrenceId");
	assertUuid(input.captureId, "captureId");
	if (!Array.isArray(input.subjects)) throw new TypeError("subjects must be an array");

	const deadlineMs = boundedInteger(
		input.deadlineMs,
		INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DEADLINE_MS,
		INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DEADLINE_MS,
	);
	const byteBudget = boundedInteger(
		input.byteBudget,
		INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_BYTE_BUDGET,
		INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_BYTE_BUDGET,
	);
	if (input.subjects.length > INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_SUBJECTS) {
		const subjectReceipts = [malformedSubjectReceipt(0, "subject_limit")];
		return resultBase(input, {
			rootProcessStartId: input.rootProcessStartId,
			selectedSubjects: [],
			deadlineMs,
			byteBudget,
			state: "unavailable",
			bytesRead: 0,
			retainedBytes: 0,
			directoryEntriesSeen: 0,
			linkAttempts: 0,
			errorCount: 1,
			batchBytes: 0,
			subjectReceipts,
			receipts: [],
			admission: admissionNotAttempted("subject_limit"),
			reason: "subject_limit",
		});
	}
	const now = input.now ?? input.monotonic ?? (() => performance.now());
	const deadlineAt = now() + deadlineMs;
	const reader = input.identity ?? input.processStartIdReader ?? getProcessStartId;
	const fs = input.fileSystem ?? defaultFileSystem;
	const state: ScanState = {
		bytesRead: 0,
		directoryEntriesSeen: 0,
		linkAttempts: 0,
		errorCount: 0,
		truncated: false,
		unavailable: false,
		stop: false,
	};
	const subjectReceipts: IncidentRecorderLiveFdLinkCaptureSubjectReceipt[] = [];
	const entryReceipts: IncidentRecorderLiveFdLinkCaptureEntryReceipt[] = [];
	const records: PendingRecord[] = [];

	if (process.platform !== "linux") {
		return resultBase(input, {
			rootProcessStartId: input.rootProcessStartId,
			selectedSubjects: [],
			deadlineMs,
			byteBudget,
			state: "unavailable",
			bytesRead: 0,
			retainedBytes: 0,
			directoryEntriesSeen: 0,
			linkAttempts: 0,
			errorCount: 1,
			batchBytes: 0,
			subjectReceipts: [],
			receipts: [],
			admission: admissionNotAttempted("unsupported_platform"),
			reason: "unsupported_platform",
		});
	}

	const selectedSubjects: NormalizedSubject[] = [];
	const seenPids = new Set<number>();
	let selectionInvalid = false;
	for (let index = 0; index < input.subjects.length; index += 1) {
		const raw = input.subjects[index];
		const pid = raw && typeof raw === "object" && "pid" in raw ? raw.pid : Number.NaN;
		const start = raw && typeof raw === "object" ? subjectIdentity(raw) : undefined;
		if (!Number.isSafeInteger(pid) || pid <= 0 || start === undefined) {
			selectionInvalid = true;
			state.errorCount += 1;
			recordSubjectGap(
				subjectReceipts,
				typeof pid === "number" && Number.isSafeInteger(pid) ? pid : 0,
				"invalid_subject",
			);
			continue;
		}
		if (seenPids.has(pid)) {
			selectionInvalid = true;
			state.errorCount += 1;
			recordSubjectGap(subjectReceipts, pid, "duplicate_subject");
			continue;
		}
		if (selectedSubjects.length >= INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_SUBJECTS) {
			rememberReason(state, "subject_limit");
			recordSubjectGap(subjectReceipts, pid, "subject_limit");
			continue;
		}
		seenPids.add(pid);
		selectedSubjects.push({ pid, processStartId: start });
	}
	if (
		selectedSubjects.length === 0 ||
		selectedSubjects[0]?.pid !== input.rootPid ||
		selectedSubjects[0]?.processStartId !== input.rootProcessStartId
	) {
		selectionInvalid = true;
		state.errorCount += 1;
		rememberReason(state, "invalid_subject");
	}

	const initialRootIdentity = readIdentity(reader, input.rootPid);
	if (initialRootIdentity !== input.rootProcessStartId) {
		state.errorCount += 1;
		rememberReason(state, "root_identity_changed");
		return resultBase(input, {
			rootProcessStartId: input.rootProcessStartId,
			selectedSubjects,
			deadlineMs,
			byteBudget,
			state: "unavailable",
			bytesRead: 0,
			retainedBytes: 0,
			directoryEntriesSeen: 0,
			linkAttempts: 0,
			errorCount: state.errorCount,
			batchBytes: 0,
			subjectReceipts,
			receipts: entryReceipts,
			admission: admissionNotAttempted("root_identity_changed"),
			reason: "root_identity_changed",
		});
	}

	if (selectionInvalid) {
		return resultBase(input, {
			rootProcessStartId: input.rootProcessStartId,
			selectedSubjects,
			deadlineMs,
			byteBudget,
			state: "unavailable",
			bytesRead: 0,
			retainedBytes: 0,
			directoryEntriesSeen: 0,
			linkAttempts: 0,
			errorCount: state.errorCount,
			batchBytes: 0,
			subjectReceipts,
			receipts: entryReceipts,
			admission: admissionNotAttempted(state.firstReason ?? "invalid_subject"),
			reason: state.firstReason ?? "invalid_subject",
		});
	}

	for (let subjectIndex = 0; subjectIndex < selectedSubjects.length; subjectIndex += 1) {
		const subject = selectedSubjects[subjectIndex];
		const subjectEntries: IncidentRecorderLiveFdLinkCaptureEntryReceipt[] = [];
		const subjectRecordStart = records.length;
		const subjectEntryStart = entryReceipts.length;
		const subjectDirectoryEntriesStart = state.directoryEntriesSeen;
		const subjectLinkAttemptsStart = state.linkAttempts;
		let subjectErrorCount = 0;
		let subjectReason: IncidentRecorderLiveFdLinkCaptureReason | undefined;
		const beforeIdentity = readIdentity(reader, subject.pid);
		if (beforeIdentity !== subject.processStartId) {
			state.errorCount += 1;
			subjectErrorCount += 1;
			rememberReason(state, beforeIdentity === undefined ? "identity_unavailable" : "identity_changed");
			subjectReason = beforeIdentity === undefined ? "identity_unavailable" : "identity_changed";
			subjectReceipts.push({
				pid: subject.pid,
				processStartId: subject.processStartId,
				state: "identity_changed",
				beforeProcessStartId: beforeIdentity,
				directoryEntriesSeen: 0,
				linkAttempts: 0,
				recordCount: 0,
				errorCount: subjectErrorCount,
				entries: [],
				reason: subjectReason,
			});
			continue;
		}

		let directory: IncidentRecorderLiveFdLinkCaptureDirectory | undefined;
		const fds: number[] = [];
		let directoryComplete = false;
		try {
			if (now() >= deadlineAt) {
				state.stop = true;
				rememberReason(state, "deadline");
				subjectReason = "deadline";
			} else if (state.bytesRead >= byteBudget) {
				state.stop = true;
				rememberReason(state, "byte_budget");
				subjectReason = "byte_budget";
			} else {
				directory = fs.opendirSync?.(sourcePath(subject.pid)) ?? fs.opendir?.(sourcePath(subject.pid));
				if (!directory) throw new Error("directory seam unavailable");
				while (state.directoryEntriesSeen < INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DIRECTORY_ENTRIES) {
					if (now() >= deadlineAt) {
						state.stop = true;
						rememberReason(state, "deadline");
						subjectReason ??= "deadline";
						break;
					}
					const entry = directory.readSync();
					if (entry == null) {
						directoryComplete = true;
						break;
					}
					state.directoryEntriesSeen += 1;
					if (!entry || typeof entry.name !== "string" || !CANONICAL_FD.test(entry.name)) {
						state.errorCount += 1;
						subjectErrorCount += 1;
						rememberReason(state, "malformed_fd");
						const malformedPath = `${sourcePath(subject.pid)}/${typeof entry?.name === "string" ? entry.name : "?"}`;
						const malformed: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
							pid: subject.pid,
							subjectPid: subject.pid,
							state: "malformed",
							sourcePath: malformedPath,
							bytesRead: 0,
							retainedBytes: 0,
							admitted: false,
							admission: admissionNotAttempted("malformed_fd"),
							reason: "malformed_fd",
						};
						subjectEntries.push(malformed);
						entryReceipts.push(malformed);
						continue;
					}
					const fd = Number(entry.name);
					if (!Number.isSafeInteger(fd) || fd < 0) {
						state.errorCount += 1;
						subjectErrorCount += 1;
						rememberReason(state, "malformed_fd");
						const malformed: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
							pid: subject.pid,
							subjectPid: subject.pid,
							state: "malformed",
							sourcePath: `${sourcePath(subject.pid)}/${entry.name}`,
							bytesRead: 0,
							retainedBytes: 0,
							admitted: false,
							admission: admissionNotAttempted("malformed_fd"),
							reason: "malformed_fd",
						};
						subjectEntries.push(malformed);
						entryReceipts.push(malformed);
						continue;
					}
					fds.push(fd);
				}
				if (
					!directoryComplete &&
					!state.stop &&
					state.directoryEntriesSeen >= INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DIRECTORY_ENTRIES
				) {
					rememberReason(state, "directory_entry_limit");
					subjectReason ??= "directory_entry_limit";
				}
			}
		} catch (error) {
			state.errorCount += 1;
			subjectErrorCount += 1;
			const errno = classifyErrno(error);
			state.firstErrno ??= errno;
			rememberReason(state, directory ? "directory_read_failed" : "directory_unavailable", errno);
			subjectReason ??= directory ? "directory_read_failed" : "directory_unavailable";
			const failure: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
				pid: subject.pid,
				subjectPid: subject.pid,
				state: "unavailable",
				sourcePath: sourcePath(subject.pid),
				bytesRead: 0,
				retainedBytes: 0,
				admitted: false,
				admission: admissionNotAttempted(subjectReason),
				errorCode: errno,
				reason: subjectReason,
			};
			subjectEntries.push(failure);
			entryReceipts.push(failure);
		} finally {
			if (directory) {
				try {
					directory.closeSync();
				} catch {
					state.errorCount += 1;
					subjectErrorCount += 1;
					rememberReason(state, "directory_close_failed");
					subjectReason ??= "directory_close_failed";
				}
			}
		}

		fds.sort((left, right) => left - right);
		let nextFdIndex = 0;
		for (; nextFdIndex < fds.length; nextFdIndex += 1) {
			const fd = fds[nextFdIndex];
			if (state.stop) break;
			if (now() >= deadlineAt) {
				state.stop = true;
				rememberReason(state, "deadline");
				subjectReason ??= "deadline";
				break;
			}
			if (state.bytesRead >= byteBudget) {
				state.stop = true;
				rememberReason(state, "byte_budget");
				subjectReason ??= "byte_budget";
				break;
			}
			if (state.linkAttempts >= INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_LINK_ATTEMPTS) {
				state.stop = true;
				rememberReason(state, "link_attempt_limit");
				subjectReason ??= "link_attempt_limit";
				break;
			}
			state.linkAttempts += 1;
			const path = linkPath(subject.pid, fd);
			let target: Buffer;
			try {
				const observed = fs.readlinkBuffer(path);
				if (!Buffer.isBuffer(observed)) throw new TypeError("readlink did not return a Buffer");
				target = Buffer.from(observed);
			} catch (error) {
				state.errorCount += 1;
				subjectErrorCount += 1;
				const errno = classifyErrno(error);
				const reason: IncidentRecorderLiveFdLinkCaptureReason =
					error instanceof TypeError ? "readlink_non_buffer" : "readlink_unavailable";
				rememberReason(state, reason, errno);
				const failure: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
					pid: subject.pid,
					subjectPid: subject.pid,
					fd,
					state: "unavailable",
					sourcePath: path,
					bytesRead: 0,
					retainedBytes: 0,
					admitted: false,
					admission: admissionNotAttempted(reason),
					errorCode: errno,
					reason,
				};
				subjectEntries.push(failure);
				entryReceipts.push(failure);
				continue;
			}

			const actualBytes = target.byteLength;
			state.bytesRead += actualBytes;
			if (actualBytes > INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_TARGET_BYTES) {
				state.errorCount += 1;
				subjectErrorCount += 1;
				rememberReason(state, "link_too_large");
				const oversized: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
					pid: subject.pid,
					subjectPid: subject.pid,
					fd,
					state: "unavailable",
					sourcePath: path,
					bytesRead: actualBytes,
					retainedBytes: 0,
					targetBytes: actualBytes,
					admitted: false,
					admission: admissionNotAttempted("link_too_large"),
					reason: "link_too_large",
				};
				subjectEntries.push(oversized);
				entryReceipts.push(oversized);
				continue;
			}
			if (state.bytesRead > byteBudget) {
				state.stop = true;
				rememberReason(state, "byte_budget");
				subjectReason ??= "byte_budget";
				const overBudget: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
					pid: subject.pid,
					subjectPid: subject.pid,
					fd,
					state: "unavailable",
					sourcePath: path,
					bytesRead: actualBytes,
					retainedBytes: 0,
					targetBytes: actualBytes,
					admitted: false,
					admission: admissionNotAttempted("byte_budget"),
					reason: "byte_budget",
				};
				subjectEntries.push(overBudget);
				entryReceipts.push(overBudget);
				nextFdIndex += 1;
				break;
			}

			const targetSha256 = createHash("sha256").update(target).digest("hex");
			const pending: PendingRecord = {
				pid: subject.pid,
				fd,
				targetEncoding: "base64",
				targetBytes: actualBytes,
				targetSha256,
				targetBase64: target.toString("base64"),
			};
			const candidatePayload = serializeBatch([...records, pending]);
			if (candidatePayload.length > INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_BATCH_BYTES) {
				state.stop = true;
				rememberReason(state, "batch_limit");
				subjectReason ??= "batch_limit";
				const limit: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
					pid: subject.pid,
					subjectPid: subject.pid,
					fd,
					state: "batch_limit",
					sourcePath: path,
					bytesRead: actualBytes,
					retainedBytes: 0,
					targetBytes: actualBytes,
					targetSha256,
					admitted: false,
					admission: admissionNotAttempted("batch_limit"),
					reason: "batch_limit",
				};
				subjectEntries.push(limit);
				entryReceipts.push(limit);
				nextFdIndex += 1;
				break;
			}
			records.push(pending);
			const retained: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
				pid: subject.pid,
				subjectPid: subject.pid,
				fd,
				state: "retained",
				sourcePath: path,
				bytesRead: actualBytes,
				retainedBytes: actualBytes,
				targetBytes: actualBytes,
				targetSha256,
				admitted: false,
				admission: admissionNotAttempted(),
			};
			subjectEntries.push(retained);
			entryReceipts.push(retained);
		}
		if (state.stop) {
			const gapReason = subjectReason ?? "unobserved_rest";
			for (; nextFdIndex < fds.length; nextFdIndex += 1) {
				const fd = fds[nextFdIndex];
				const gap: IncidentRecorderLiveFdLinkCaptureEntryReceipt = {
					pid: subject.pid,
					subjectPid: subject.pid,
					fd,
					state: "not_attempted",
					sourcePath: linkPath(subject.pid, fd),
					bytesRead: 0,
					retainedBytes: 0,
					admitted: false,
					admission: admissionNotAttempted(gapReason),
					reason: gapReason,
				};
				subjectEntries.push(gap);
				entryReceipts.push(gap);
			}
		}

		const afterIdentity = readIdentity(reader, subject.pid);
		const subjectChanged = afterIdentity !== subject.processStartId;
		if (subjectChanged) {
			const dropCount = records.length - subjectRecordStart;
			if (dropCount > 0) records.splice(subjectRecordStart, dropCount);
			for (let index = subjectEntryStart; index < entryReceipts.length; index += 1) {
				const entry = entryReceipts[index];
				if (entry.state === "retained") {
					entry.state = "identity_changed";
					entry.retainedBytes = 0;
					entry.admission = admissionNotAttempted("identity_changed");
					entry.reason = "identity_changed";
				}
			}
			state.errorCount += 1;
			subjectErrorCount += 1;
			rememberReason(state, afterIdentity === undefined ? "identity_unavailable" : "identity_changed");
			subjectReason = afterIdentity === undefined ? "identity_unavailable" : "identity_changed";
		}
		const subjectRecordCount = records.length - subjectRecordStart;
		const stateForSubject: IncidentRecorderLiveFdLinkCaptureSubjectState = subjectReason
			? subjectReason === "identity_changed"
				? "identity_changed"
				: subjectReason === "deadline" ||
						subjectReason === "byte_budget" ||
						subjectReason === "batch_limit" ||
						subjectReason === "directory_entry_limit" ||
						subjectReason === "link_attempt_limit"
					? "truncated"
					: "unavailable"
			: subjectRecordCount > 0
				? "admitted"
				: "empty";
		for (const entry of subjectEntries) {
			if (entry.state === "retained" && subjectChanged) {
				entry.state = "identity_changed";
				entry.retainedBytes = 0;
				entry.reason = "identity_changed";
			}
		}
		subjectReceipts.push({
			pid: subject.pid,
			processStartId: subject.processStartId,
			state: stateForSubject,
			beforeProcessStartId: beforeIdentity,
			afterProcessStartId: afterIdentity,
			directoryEntriesSeen: state.directoryEntriesSeen - subjectDirectoryEntriesStart,
			linkAttempts: state.linkAttempts - subjectLinkAttemptsStart,
			recordCount: subjectRecordCount,
			errorCount: subjectErrorCount,
			entries: subjectEntries,
			...(subjectReason ? { reason: subjectReason } : {}),
		});
		if (subjectReason === "directory_entry_limit") state.stop = true;
		if (state.stop) {
			rememberReason(state, "unobserved_rest");
			for (let remainingIndex = subjectIndex + 1; remainingIndex < selectedSubjects.length; remainingIndex += 1) {
				const remaining = selectedSubjects[remainingIndex];
				subjectReceipts.push({
					pid: remaining.pid,
					processStartId: remaining.processStartId,
					state: "not_attempted",
					directoryEntriesSeen: 0,
					linkAttempts: 0,
					recordCount: 0,
					errorCount: 0,
					entries: [],
					reason: "unobserved_rest",
				});
			}
			break;
		}
	}

	if (state.stop && state.firstReason !== "unobserved_rest") rememberReason(state, "unobserved_rest");
	const finalRootIdentity = readIdentity(reader, input.rootPid);
	if (finalRootIdentity !== input.rootProcessStartId) {
		state.errorCount += 1;
		rememberReason(state, "root_identity_changed");
		normalizeRootIdentityFailure(subjectReceipts, entryReceipts);
		return resultBase(input, {
			rootProcessStartId: input.rootProcessStartId,
			selectedSubjects,
			deadlineMs,
			byteBudget,
			state: "unavailable",
			bytesRead: state.bytesRead,
			retainedBytes: 0,
			directoryEntriesSeen: state.directoryEntriesSeen,
			linkAttempts: state.linkAttempts,
			errorCount: state.errorCount,
			batchBytes: 0,
			subjectReceipts,
			receipts: entryReceipts,
			admission: admissionNotAttempted("root_identity_changed"),
			reason: "root_identity_changed",
		});
	}

	const immediateRootIdentity = readIdentity(reader, input.rootPid);
	if (immediateRootIdentity !== input.rootProcessStartId) {
		state.errorCount += 1;
		rememberReason(state, "root_identity_changed");
		normalizeRootIdentityFailure(subjectReceipts, entryReceipts);
		return resultBase(input, {
			rootProcessStartId: input.rootProcessStartId,
			selectedSubjects,
			deadlineMs,
			byteBudget,
			state: "unavailable",
			bytesRead: state.bytesRead,
			retainedBytes: 0,
			directoryEntriesSeen: state.directoryEntriesSeen,
			linkAttempts: state.linkAttempts,
			errorCount: state.errorCount,
			batchBytes: 0,
			subjectReceipts,
			receipts: entryReceipts,
			admission: admissionNotAttempted("root_identity_changed"),
			reason: "root_identity_changed",
		});
	}

	const coverage: IncidentRecorderLiveFdLinkCaptureCoverage = state.unavailable
		? "unavailable"
		: state.truncated || subjectReceipts.length !== selectedSubjects.length
			? "truncated"
			: "complete_within_selected_live_pass";
	const payload = serializeBatch(records);
	const metadata: Record<string, unknown> = {
		rootPid: input.rootPid,
		rootProcessStartId: input.rootProcessStartId,
		selectedSubjectsSha256: selectionDigest(selectedSubjects),
		subjectCount: selectedSubjects.length,
		recordCount: records.length,
		errorCount: state.errorCount,
		directoryEntriesSeen: state.directoryEntriesSeen,
		linkAttempts: state.linkAttempts,
		descriptorLimit: INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_DESCRIPTOR_LIMIT,
		deadlineMs,
		byteBudget,
		bytesRead: state.bytesRead,
		batchBytes: payload.length,
		batchLimit: INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_BATCH_BYTES,
		retainedBytes: payload.length,
		state: coverage,
		sourceTruncated: coverage !== "complete_within_selected_live_pass",
		treeCompleteness: "not_claimed",
		livePopulation: true,
		coherentSnapshot: false,
		additiveOnly: true,
		triggerOccurrenceId: input.triggerOccurrenceId,
		captureId: input.captureId,
		rootSourcePath: sourcePath(input.rootPid),
		bodyPerRecordPath: INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_BODY_PER_RECORD_PATH,
		sourcePath: sourcePath(input.rootPid),
		sourceBytes: payload.length,
		...(state.firstReason ? { reason: state.firstReason } : {}),
	};

	// A zero-record body is evidence only when every selected directory was
	// observed to be stably empty. Error-only observations remain typed gaps;
	// they must not be emitted as an apparently complete empty batch.
	const stableEmptyBatch =
		records.length === 0 &&
		state.errorCount === 0 &&
		!state.stop &&
		subjectReceipts.length === selectedSubjects.length &&
		subjectReceipts.every((receipt) => receipt.state === "empty");
	const attemptWriter = records.length > 0 || stableEmptyBatch;
	let admission: IncidentRecorderLiveFdLinkCaptureAdmission = admissionNotAttempted(
		attemptWriter ? undefined : state.firstReason,
	);
	let writerReason: Extract<IncidentRecorderAdmission, { accepted: false }>["reason"] | undefined;
	let retryCaptureId: string | undefined;
	if (attemptWriter) {
		const preWriterRootIdentity = readIdentity(reader, input.rootPid);
		if (preWriterRootIdentity !== input.rootProcessStartId) {
			state.errorCount += 1;
			rememberReason(state, "root_identity_changed");
			normalizeRootIdentityFailure(subjectReceipts, entryReceipts);
			return resultBase(input, {
				rootProcessStartId: input.rootProcessStartId,
				selectedSubjects,
				deadlineMs,
				byteBudget,
				state: "unavailable",
				bytesRead: state.bytesRead,
				retainedBytes: 0,
				directoryEntriesSeen: state.directoryEntriesSeen,
				linkAttempts: state.linkAttempts,
				errorCount: state.errorCount,
				batchBytes: 0,
				subjectReceipts,
				receipts: entryReceipts,
				admission: admissionNotAttempted("root_identity_changed"),
				reason: "root_identity_changed",
			});
		}
		try {
			const writerAdmission = input.writer.recordExactBytesForRun(
				{ runId: input.runId, runToken: input.runToken },
				"linux-raw-source",
				"live_fd_link_batch_snapshot",
				payload,
				"utf8-json/incident-fd-link-batch-v1",
				metadata,
			);
			if (writerAdmission.accepted) {
				admission = { accepted: true, disposition: "locally_admitted", occurrenceId: writerAdmission.occurrenceId };
				for (const entry of entryReceipts) {
					if (entry.state === "retained") {
						entry.state = "admitted";
						entry.admitted = true;
						entry.admission = admission;
					}
				}
			} else {
				writerReason = writerAdmission.reason;
				retryCaptureId = randomUUID();
				admission = { accepted: false, disposition: "rejected", reason: "queue_rejection", writerReason };
				for (const entry of entryReceipts) {
					if (entry.state === "retained") {
						entry.state = "not_attempted";
						entry.retainedBytes = 0;
						entry.admission = admission;
					}
				}
			}
		} catch {
			writerReason = "encoding_failed";
			retryCaptureId = randomUUID();
			admission = { accepted: false, disposition: "rejected", reason: "queue_rejection", writerReason };
			for (const entry of entryReceipts) {
				if (entry.state === "retained") {
					entry.state = "not_attempted";
					entry.retainedBytes = 0;
					entry.admission = admission;
				}
			}
		}
		if (admission.disposition === "rejected") {
			for (const subject of subjectReceipts) {
				if (subject.state === "admitted") {
					subject.state = "not_attempted";
					subject.recordCount = 0;
					subject.reason = "queue_rejection";
				}
			}
		}
	}

	const admitted = admission.accepted;
	const finalCoverage = admission.disposition === "rejected" ? "unavailable" : coverage;
	return resultBase(input, {
		rootProcessStartId: input.rootProcessStartId,
		selectedSubjects,
		deadlineMs,
		byteBudget,
		state: finalCoverage,
		bytesRead: state.bytesRead,
		retainedBytes: admitted ? payload.length : 0,
		directoryEntriesSeen: state.directoryEntriesSeen,
		linkAttempts: state.linkAttempts,
		errorCount: state.errorCount,
		batchBytes: admitted ? payload.length : 0,
		subjectReceipts,
		receipts: entryReceipts,
		admission,
		...(admission.disposition === "rejected"
			? { reason: "queue_rejection" as const }
			: state.firstReason
				? { reason: state.firstReason }
				: {}),
		...(writerReason ? { writerReason } : {}),
		...(retryCaptureId ? { retryCaptureId } : {}),
	});
}

function recordSubjectGap(
	receipts: IncidentRecorderLiveFdLinkCaptureSubjectReceipt[],
	pid: number,
	reason: IncidentRecorderLiveFdLinkCaptureReason,
): void {
	receipts.push(malformedSubjectReceipt(pid, reason));
}
