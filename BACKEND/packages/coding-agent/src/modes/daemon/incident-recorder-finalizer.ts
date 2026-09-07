import { createHash } from "node:crypto";
import {
	type BigIntStats,
	closeSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	linkSync,
	lstatSync,
	mkdirSync,
	openSync,
	readdirSync,
	readSync,
	rmdirSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import type {
	IncidentRecorderRunHistoryEvent,
	IncidentRecorderRunHistoryResult,
} from "./incident-recorder-compactor.js";

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const UNSIGNED_SEQUENCE = /^(?:0|[1-9][0-9]{0,19})$/;
const SAFE_INCIDENT_ID = /^[A-Za-z0-9_.+-]{1,200}$/;
const MAX_FINALIZATION_FILE_BYTES = 16 * 1024 * 1024;
const MAX_FINALIZATION_TOTAL_BYTES = 40 * 1024 * 1024;
const MAX_FINALIZATION_CONFLICT_RECORD_BYTES = 64 * 1024;
const MAX_RETENTION_AUTHORITY_BYTES = 8 * 1024;
const IMMUTABLE_STAGING_SLOT_COUNT = 8;
const STANDARD_FINALIZATION_FILE_NAMES = [
	"finalization-intent.json",
	"run-history.json",
	"finalization-descriptor.json",
	"summary.json",
] as const;
const FINALIZATION_AUTHORITY_FILE_NAMES = [
	"finalization-authority.json",
	"finalization-authority-1.json",
	"finalization-authority-2.json",
	"finalization-authority-3.json",
	"finalization-authority-4.json",
	"finalization-authority-5.json",
	"finalization-authority-6.json",
	"finalization-authority-7.json",
] as const;
const FINALIZATION_PRIVATE_AUTHORITY_DIRECTORY_NAME = ".finalization-authority-root";
const FINALIZATION_PRIVATE_AUTHORITY_CLAIM_NAME = "finalization-claim.json";
const FINALIZATION_PRIVATE_AUTHORITY_SELECTOR_NAME = "finalization-authority.json";
const RETENTION_AUTHORITY_INTENDED_NAME = "retention-authority-intended.json";
const RETENTION_AUTHORITY_CONFLICT_NAME = "retention-authority-conflict.json";
const RETENTION_AUTHORITY_MANIFEST_NAME = "retention-authority-manifest.json";
const PUBLICATION_CONFLICT_REASON_PREFIX = "published_finalization_file_conflict:";

export const INCIDENT_RECORDER_FINALIZATION_FAULT_BOUNDARIES = [
	"after_stopped_capture_before_seal",
	"after_seal_before_terminal_frontier",
	"after_projection_lease_acquired",
	"after_partial_mkdir_before_parent_fsync",
	"after_intent_durable_before_history",
	"after_history_write_before_fsync",
	"after_history_fsync_before_rename",
	"after_history_rename_before_directory_fsync",
	"after_descriptor_write_before_fsync",
	"after_descriptor_fsync_before_rename",
	"after_descriptor_rename_before_directory_fsync",
	"after_prepared_directory_fsync_before_lease_release",
	"after_projection_lease_release_before_publish",
	"after_manifest_fsync_before_rename",
	"after_manifest_rename_before_directory_fsync",
	"after_staging_directory_fsync_before_publish",
	"after_publish_rename_before_parent_fsync",
	"after_publish_parent_fsync_before_source_release",
	"after_source_marker_before_reclaim_complete",
] as const;

export type IncidentRecorderFinalizationFaultBoundary =
	(typeof INCIDENT_RECORDER_FINALIZATION_FAULT_BOUNDARIES)[number];

export const INCIDENT_RECORDER_FINALIZATION_ORCHESTRATION_FAULT_BOUNDARIES = [
	"after_stopped_capture_before_seal",
	"after_seal_before_terminal_frontier",
	"after_source_marker_before_reclaim_complete",
] as const satisfies readonly IncidentRecorderFinalizationFaultBoundary[];

export type IncidentRecorderFinalizationOrchestrationFaultBoundary =
	(typeof INCIDENT_RECORDER_FINALIZATION_ORCHESTRATION_FAULT_BOUNDARIES)[number];

export const INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES = [
	"after_projection_lease_acquired",
	"after_partial_mkdir_before_parent_fsync",
	"after_intent_durable_before_history",
	"after_history_write_before_fsync",
	"after_history_fsync_before_rename",
	"after_history_rename_before_directory_fsync",
	"after_descriptor_write_before_fsync",
	"after_descriptor_fsync_before_rename",
	"after_descriptor_rename_before_directory_fsync",
	"after_prepared_directory_fsync_before_lease_release",
	"after_projection_lease_release_before_publish",
	"after_manifest_fsync_before_rename",
	"after_manifest_rename_before_directory_fsync",
	"after_staging_directory_fsync_before_publish",
	"after_publish_rename_before_parent_fsync",
	"after_publish_parent_fsync_before_source_release",
] as const satisfies readonly IncidentRecorderFinalizationFaultBoundary[];

export type IncidentRecorderFinalizationComponentFaultBoundary =
	(typeof INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES)[number];

export const INCIDENT_RECORDER_RETENTION_AUTHORITY_FAULT_BOUNDARIES = [
	"after_retention_intended_authority_link_before_directory_fsync",
	"after_retention_intended_authority_durable",
	"after_retention_conflict_evidence_link_before_directory_fsync",
	"after_retention_conflict_evidence_durable",
	"after_retention_manifest_link_before_directory_fsync",
	"after_retention_manifest_durable_before_readback",
] as const;

export type IncidentRecorderRetentionAuthorityFaultBoundary =
	(typeof INCIDENT_RECORDER_RETENTION_AUTHORITY_FAULT_BOUNDARIES)[number];

export interface IncidentRecorderRelayFrontierExpectation {
	type: "supervisor_exit" | "capture_channel_terminal";
	occurrenceId: string;
	producerId: string;
	firstProducerSequence: string;
	lastProducerSequence: string;
	firstWrapperSequence: string;
	lastWrapperSequence: string;
}

export type IncidentRecorderTerminalExpectation =
	| { state: "available"; frontier: IncidentRecorderRelayFrontierExpectation }
	| { state: "unavailable"; reason: string };

export interface IncidentRecorderFinalizationInput {
	incidentsDirectory: string;
	incidentId: string;
	runIdentity: { runId: string; runToken: string };
	runHistory: IncidentRecorderRunHistoryResult;
	terminalExpectations: {
		supervisorExit: IncidentRecorderTerminalExpectation;
		wrapperTerminal: IncidentRecorderTerminalExpectation;
		serviceTerminal: IncidentRecorderTerminalExpectation;
	};
	classification: { value: string; causeLayer: string };
	exit: { code: number | null; signal: string | null };
	retentionAnchorWallTimeMs?: number;
	stoppedTarget: {
		captureState: "complete" | "incomplete" | "unavailable" | string;
		artifacts: Array<{
			state: "complete" | "incomplete" | "unavailable" | string;
			role: string;
			required: boolean;
			algorithm: string;
			digest: string;
			bytes: number;
			encoding: string;
			path: string;
		}>;
	};
	wrapperLoss: {
		finalQueuedTailLoss: { records: number; bytes: number };
		emitterFinalTailLoss: { records: number; bytes: number };
	};
	serviceSeal: {
		terminalRelayDisposition: string;
		emitterLoss: { records: number; bytes: number };
		drainTimeoutLoss: {
			definite: { records: number; bytes: number };
			uncertain: { records: number; bytes: number };
		};
		terminalRelayLoss: {
			definite: { records: number; bytes: number };
			uncertain: { records: number; bytes: number };
		};
	};
	assertProjectionLeaseUsable?: () => void;
	releaseProjectionLease?: () => void;
}

export interface IncidentRecorderFinalizationFileSystem {
	mkdir: typeof mkdirSync;
	open: typeof openSync;
	write: typeof writeSync;
	fsync: typeof fsyncSync;
	close: typeof closeSync;
	link: typeof linkSync;
	read: typeof readSync;
	lstat: typeof lstatSync;
	fstat: typeof fstatSync;
	readdir: typeof readdirSync;
	unlink: typeof unlinkSync;
	rmdir: typeof rmdirSync;
}

const defaultFileSystem: IncidentRecorderFinalizationFileSystem = {
	mkdir: mkdirSync,
	open: openSync,
	write: writeSync,
	fsync: fsyncSync,
	close: closeSync,
	link: linkSync,
	read: readSync,
	lstat: lstatSync,
	fstat: fstatSync,
	readdir: readdirSync,
	unlink: unlinkSync,
	rmdir: rmdirSync,
};

export interface IncidentRecorderFinalizerOptions {
	fs?: Partial<IncidentRecorderFinalizationFileSystem>;
	onFaultBoundary?: (boundary: IncidentRecorderFinalizationComponentFaultBoundary) => void;
}

export interface IncidentRecorderRetentionAuthorityPersistenceOptions extends IncidentRecorderFinalizerOptions {
	onRetentionAuthorityFaultBoundary?: (boundary: IncidentRecorderRetentionAuthorityFaultBoundary) => void;
}

interface FinalizationAnalysis {
	state: "pending" | "complete" | "incomplete" | "corrupt";
	finalizationId: string;
	reasons: string[];
	supervisorExitAnchorWallTimeMs: number | null;
	retentionAnchorWallTimeMs: number | null;
}

interface FinalizationFileRecord {
	name: string;
	bytes: number;
	sha256: string;
}

interface FinalizationManifestBase {
	schemaVersion: 1;
	finalizationId: string;
	state: "complete" | "incomplete" | "corrupt";
	reasons: string[];
	runIdentity: { runId: string; runToken: string };
	supervisorExitAnchorWallTimeMs: number | null;
	retentionAnchorWallTimeMs: number | null;
	files: FinalizationFileRecord[];
}

interface StandardFinalizationManifest extends FinalizationManifestBase {
	kind: "incident_recorder_finalization_manifest";
}

interface ConflictFinalizationManifest extends FinalizationManifestBase {
	kind: "incident_recorder_finalization_conflict_manifest";
	state: "corrupt";
	conflictRecord: FinalizationFileRecord;
}

type FinalizationManifest = StandardFinalizationManifest | ConflictFinalizationManifest;

interface FinalizationConflictFile {
	logicalName: (typeof STANDARD_FINALIZATION_FILE_NAMES)[number];
	prepared: FinalizationFileRecord;
	observed?: FinalizationConflictObserved;
}

interface FinalizationConflictNamespaceOccupant {
	disposition:
		| "directory"
		| "hardlinked_file"
		| "lstat_unavailable"
		| "non_private_file"
		| "non_regular"
		| "owner_mismatch"
		| "oversized_file"
		| "read_unavailable_or_changed"
		| "symlink";
	fileType: "directory" | "file" | "other" | "symlink" | "unknown";
	dev: string | null;
	ino: string | null;
	size: string | null;
	mode: string | null;
	nlink: string | null;
	uid: string | null;
	mtimeNs: string | null;
	ctimeNs: string | null;
	errno: string | null;
}

type FinalizationConflictObserved =
	| { disposition: "exact_private_bytes"; evidence: FinalizationFileRecord }
	| FinalizationConflictNamespaceOccupant;

interface FinalizationManifestConflict {
	logicalName: "finalization-manifest.json";
	prepared: FinalizationFileRecord;
	observed: FinalizationConflictObserved;
}

interface FinalizationConflictRecord {
	schemaVersion: 1;
	kind: "incident_recorder_finalization_publication_conflict";
	finalizationId: string;
	runIdentity: { runId: string; runToken: string };
	intendedState: "complete" | "incomplete" | "corrupt";
	intendedReasons: string[];
	supervisorExitAnchorWallTimeMs: number | null;
	retentionAnchorWallTimeMs: number | null;
	intendedManifest: FinalizationFileRecord;
	files: FinalizationConflictFile[];
	manifestConflict?: FinalizationManifestConflict;
}

interface FinalizationAuthoritySelector {
	schemaVersion: 1;
	kind: "incident_recorder_finalization_authority_selector";
	finalizationId: string;
	runIdentity: { runId: string; runToken: string };
	state: "corrupt";
	manifest: FinalizationFileRecord;
}

interface FinalizationAuthorityClaim {
	schemaVersion: 1;
	kind: "incident_recorder_finalization_authority_claim";
	finalizationId: string;
	runIdentity: { runId: string; runToken: string };
	preparedManifest: { bytes: number; sha256: string };
}

export type IncidentRecorderPublishedFinalizationInspection =
	| { state: "pending"; reason: string }
	| {
			state: "complete" | "incomplete" | "corrupt";
			finalizationId: string;
			runId: string;
			supervisorExitAnchorWallTimeMs: number | null;
			retentionAnchorWallTimeMs: number | null;
			authorityDirectory: string;
			serviceTerminalRelayDisposition: string;
			manifest: FinalizationManifest;
	  };

export interface IncidentRecorderRetentionAuthority {
	schemaVersion: 1;
	kind: "incident_retention_authority";
	finalizationId: string;
	runId: string;
	outcome: "complete" | "incomplete" | "corrupt";
	retentionAnchorWallTimeMs: number;
}

export type IncidentRecorderRetentionClass = "diagnostic" | "corrupt";

type IncidentRecorderAuthorizedRetentionAuthority = { state: "authorized" } & IncidentRecorderRetentionAuthority & {
		authoritySource: "primary" | "conflict";
		retentionClass: IncidentRecorderRetentionClass;
	};

export type IncidentRecorderRetentionAuthorityInspection =
	| { state: "absent"; reason: string }
	| { state: "invalid"; reason: string }
	| IncidentRecorderAuthorizedRetentionAuthority;

export type IncidentRecorderRetentionAuthorityPersistenceResult =
	| (IncidentRecorderAuthorizedRetentionAuthority & { publication: "applied" | "noop" })
	| { state: "pending"; reason: string };

type RetentionAuthorityConflictReason =
	| "retention_authority_finalization_mismatch"
	| "retention_authority_identity_invalid"
	| "retention_authority_invalid_json"
	| "retention_authority_schema_invalid";

interface RetentionAuthorityObservedIdentity {
	fileType: "directory" | "file" | "other" | "symlink";
	dev: string;
	ino: string;
	size: string;
	mode: string;
	nlink: string;
	uid: string;
	mtimeNs: string;
	ctimeNs: string;
	errno: null;
}

type RetentionAuthorityObservedPrimary =
	| ({
			disposition: "exact_private_bytes";
			bytes: number;
			sha256: string;
			bytesBase64: string;
	  } & RetentionAuthorityObservedIdentity)
	| ({
			disposition:
				| "directory"
				| "hardlinked_file"
				| "non_private_file"
				| "non_regular"
				| "owner_mismatch"
				| "oversized_file"
				| "symlink";
	  } & RetentionAuthorityObservedIdentity);

interface RetentionAuthorityConflictRecord {
	schemaVersion: 1;
	kind: "incident_retention_authority_conflict";
	finalizationId: string;
	runId: string;
	outcome: "complete" | "incomplete" | "corrupt";
	retentionAnchorWallTimeMs: number;
	primaryName: "retention-authority.json";
	reason: RetentionAuthorityConflictReason;
	intendedAuthority: FinalizationFileRecord;
	observedPrimary: RetentionAuthorityObservedPrimary;
}

interface RetentionAuthorityConflictManifest {
	schemaVersion: 1;
	kind: "incident_retention_authority_conflict_manifest";
	finalizationId: string;
	runId: string;
	outcome: "complete" | "incomplete" | "corrupt";
	retentionAnchorWallTimeMs: number;
	retentionClass: "corrupt";
	authority: FinalizationFileRecord;
	conflict: FinalizationFileRecord;
}

export type IncidentRecorderFinalizationResult =
	| (FinalizationAnalysis & {
			publication: "applied" | "noop";
			incidentDirectory: string;
			reason?: string;
	  })
	| {
			state: "ambiguous";
			publication: "ambiguous";
			finalizationId: string;
			reasons: string[];
			incidentDirectory: string;
			supervisorExitAnchorWallTimeMs: number | null;
			retentionAnchorWallTimeMs: number | null;
	  };

function sha256(value: Uint8Array | string): string {
	return createHash("sha256").update(value).digest("hex");
}

function incidentAddressBinding(incidentId: string): { runId: string; finalizationId?: string } | undefined {
	const partial = /^\.(.+)\.partial-([0-9a-f]{64})$/.exec(incidentId);
	if (partial && SHA256.test(partial[2])) {
		const published = incidentAddressBinding(partial[1]);
		if (published && published.finalizationId === undefined) {
			return { runId: published.runId, finalizationId: partial[2] };
		}
	}
	const runId = incidentId.slice(-36);
	if (CANONICAL_UUID.test(runId) && (incidentId.length === 36 || incidentId.at(-37) === "-")) return { runId };
	return undefined;
}

function jsonBytes(value: unknown): Buffer {
	return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function errno(error: unknown): string | undefined {
	return error && typeof error === "object" && "code" in error
		? String((error as NodeJS.ErrnoException).code)
		: undefined;
}

function safeCount(value: { records: number; bytes: number }): boolean {
	return (
		Number.isSafeInteger(value.records) && value.records >= 0 && Number.isSafeInteger(value.bytes) && value.bytes >= 0
	);
}

function positive(value: { records: number; bytes: number }): boolean {
	return value.records > 0 || value.bytes > 0;
}

function canonicalFrontier(value: IncidentRecorderRelayFrontierExpectation): boolean {
	return (
		CANONICAL_UUID.test(value.occurrenceId) &&
		CANONICAL_UUID.test(value.producerId) &&
		["supervisor_exit", "capture_channel_terminal"].includes(value.type) &&
		[
			value.firstProducerSequence,
			value.lastProducerSequence,
			value.firstWrapperSequence,
			value.lastWrapperSequence,
		].every((sequence) => UNSIGNED_SEQUENCE.test(sequence))
	);
}

function eventMatchesFrontier(
	event: IncidentRecorderRunHistoryEvent,
	frontier: IncidentRecorderRelayFrontierExpectation,
): boolean {
	return (
		event.identity.occurrenceId === frontier.occurrenceId &&
		event.identity.producerId === frontier.producerId &&
		event.type === frontier.type &&
		event.producerOrder.at(0) === frontier.firstProducerSequence &&
		event.producerOrder.at(-1) === frontier.lastProducerSequence &&
		event.wrapperOrder.at(0) === frontier.firstWrapperSequence &&
		event.wrapperOrder.at(-1) === frontier.lastWrapperSequence
	);
}

function semanticMetadata(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(semanticMetadata);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value as Record<string, unknown>)
			.filter(
				([key]) =>
					!/(?:path|cursor|stream|invocation|machine|boot|pid|startid|device|inode|mount|temporary)/i.test(key),
			)
			.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
			.map(([key, nested]) => [key, semanticMetadata(nested)]),
	);
}

function semanticEvent(event: IncidentRecorderRunHistoryEvent): Record<string, unknown> {
	return {
		identityKey: event.identityKey,
		identity: event.identity,
		source: event.source,
		type: event.type,
		encoding: event.encoding,
		payloadKind: event.payloadKind,
		terminal: event.terminal,
		metadata: semanticMetadata(event.metadata),
		eventWallTimeMs: event.eventWallTimeMs,
		eventMonotonicNs: event.eventMonotonicNs,
		wrapperOrder: event.wrapperOrder,
		producerOrder: event.producerOrder,
		cas: { digest: event.cas.digest, bytes: event.cas.bytes },
	};
}

function semanticFinalizationInput(
	input: IncidentRecorderFinalizationInput,
	state: FinalizationAnalysis["state"],
	reasons: readonly string[],
	retentionAnchorWallTimeMs: number | null,
): Record<string, unknown> {
	const runHistory = objectValue(input.runHistory);
	const projectionValue = objectValue(runHistory?.projection);
	const projection =
		validateRunHistoryNested(input.runHistory, input.runIdentity).structureValid && projectionValue
			? projectionValue
			: undefined;
	return {
		schemaVersion: 1,
		runIdentity: input.runIdentity,
		state,
		reasons,
		classification: input.classification,
		exit: input.exit,
		retentionAnchorWallTimeMs,
		terminalExpectations: input.terminalExpectations,
		projection: projection
			? {
					version: projection.version,
					runId: projection.runId,
					fromWallTimeMs: projection.fromWallTimeMs,
					throughWallTimeMs: projection.throughWallTimeMs,
					events: (projection.events as IncidentRecorderRunHistoryEvent[]).map(semanticEvent),
					terminalEvents: projection.terminalEvents,
					finalizationCandidates: projection.finalizationCandidates,
					ordering: projection.ordering,
					evidence: (
						projection.evidence as Array<{
							kind: string;
							reason: string;
						}>
					).map(({ kind, reason }) => ({ kind, reason })),
				}
			: { schema: "invalid" },
		stoppedTarget: {
			captureState: input.stoppedTarget.captureState,
			artifacts: input.stoppedTarget.artifacts.map(({ path: _path, ...artifact }) => artifact),
		},
		wrapperLoss: input.wrapperLoss,
		serviceSeal: input.serviceSeal,
	};
}

export function analyzeIncidentRecorderFinalization(input: IncidentRecorderFinalizationInput): FinalizationAnalysis {
	const incomplete = new Set<string>();
	const corrupt = new Set<string>();
	let pending = false;
	let supervisorExitAnchorWallTimeMs: number | null = null;
	let retentionAnchorWallTimeMs: number | null = null;
	if (input.retentionAnchorWallTimeMs !== undefined) {
		if (!Number.isSafeInteger(input.retentionAnchorWallTimeMs) || input.retentionAnchorWallTimeMs < 0) {
			corrupt.add("retention_anchor_wall_time_invalid");
		} else {
			retentionAnchorWallTimeMs = input.retentionAnchorWallTimeMs;
		}
	}

	if (!CANONICAL_UUID.test(input.runIdentity.runId) || !CANONICAL_UUID.test(input.runIdentity.runToken)) {
		corrupt.add("invalid_run_identity");
	}
	if (!SAFE_INCIDENT_ID.test(input.incidentId) || input.incidentId === "." || input.incidentId === "..") {
		corrupt.add("invalid_incident_id");
	}
	const runHistoryValidation = validateRunHistoryNested(input.runHistory, input.runIdentity);
	if (!runHistoryValidation.structureValid) corrupt.add("run_history_schema_invalid");
	if (input.runHistory.state === "pending") {
		pending = true;
		incomplete.add("run_history_projection_pending");
	} else if (input.runHistory.state === "incomplete") {
		incomplete.add(`run_history_incomplete:${input.runHistory.reason}`);
	}
	const projection = objectValue(input.runHistory.projection);
	if (projection) {
		if (projection.runId !== input.runIdentity.runId) corrupt.add("run_history_run_identity_conflict");
		const ordering = objectValue(projection.ordering);
		if (ordering?.scope !== "complete_snapshot") incomplete.add("run_history_snapshot_not_complete");
		const evidence = Array.isArray(projection.evidence) ? projection.evidence : [];
		for (const value of evidence) {
			const entry = objectValue(value);
			if (!entry || typeof entry.kind !== "string" || typeof entry.reason !== "string") continue;
			if (entry.kind === "corrupt") corrupt.add(`run_history_corrupt:${entry.reason}`);
			else incomplete.add(`run_history_${entry.kind}:${entry.reason}`);
		}
	}
	if (input.runHistory.state === "complete") {
		if (!runHistoryValidation.snapshotValid) {
			incomplete.add("run_history_snapshot_invalid");
		} else if (input.runHistory.snapshot.segmentRecoveryGapCount > 0) {
			incomplete.add("run_history_segment_recovery_gaps");
		}
	}
	const occurrences = new Map<string, IncidentRecorderRunHistoryEvent[]>();
	const events = projection && Array.isArray(projection.events) ? projection.events : [];
	for (const value of events) {
		if (!validRunHistoryEvent(value, input.runIdentity)) {
			corrupt.add("run_history_event_schema_or_identity_conflict");
			continue;
		}
		const event = value as IncidentRecorderRunHistoryEvent;
		if (
			event.identity.runId !== input.runIdentity.runId ||
			event.identity.runToken !== input.runIdentity.runToken ||
			!SHA256.test(event.identityKey) ||
			!SHA256.test(event.cas.digest) ||
			!Number.isSafeInteger(event.cas.bytes) ||
			event.cas.bytes < 0
		) {
			corrupt.add("run_history_event_schema_or_identity_conflict");
		}
		const bucket = occurrences.get(event.identity.occurrenceId) ?? [];
		bucket.push(event);
		occurrences.set(event.identity.occurrenceId, bucket);
	}

	for (const [role, expectation] of Object.entries(input.terminalExpectations) as Array<
		[keyof IncidentRecorderFinalizationInput["terminalExpectations"], IncidentRecorderTerminalExpectation]
	>) {
		if (expectation.state === "unavailable") {
			incomplete.add(
				`${role.replace(/[A-Z]/g, (value) => `_${value.toLowerCase()}`)}_unavailable:${expectation.reason}`,
			);
			continue;
		}
		if (!canonicalFrontier(expectation.frontier)) {
			corrupt.add(`${role}_frontier_invalid`);
			continue;
		}
		const candidates = occurrences.get(expectation.frontier.occurrenceId) ?? [];
		const exact = candidates.filter((event) => eventMatchesFrontier(event, expectation.frontier));
		if (exact.length !== 1 || candidates.length !== 1) {
			if (candidates.length > 0) corrupt.add(`${role}_frontier_conflict`);
			else incomplete.add(`${role}_frontier_missing`);
			continue;
		}
		if (role === "supervisorExit") {
			const parsed = Number(exact[0].eventWallTimeMs);
			if (!Number.isSafeInteger(parsed) || parsed < 0) corrupt.add("supervisor_exit_wall_time_invalid");
			else supervisorExitAnchorWallTimeMs = parsed;
		}
	}

	if (input.stoppedTarget.captureState !== "complete") incomplete.add("stopped_target_capture_incomplete");
	for (const artifact of input.stoppedTarget.artifacts) {
		if (
			!artifact.role ||
			!artifact.algorithm ||
			!SHA256.test(artifact.digest) ||
			!Number.isSafeInteger(artifact.bytes) ||
			artifact.bytes < 0
		) {
			corrupt.add("stopped_target_artifact_schema_invalid");
		} else if (artifact.required && artifact.state !== "complete") {
			incomplete.add(`required_stopped_target_artifact_incomplete:${artifact.role}`);
		}
	}
	for (const [reason, count] of [
		["wrapper_final_queued_tail_loss", input.wrapperLoss.finalQueuedTailLoss],
		["wrapper_emitter_final_tail_loss", input.wrapperLoss.emitterFinalTailLoss],
		["service_emitter_loss", input.serviceSeal.emitterLoss],
		["service_drain_timeout_loss", input.serviceSeal.drainTimeoutLoss.definite],
		["service_drain_timeout_uncertainty", input.serviceSeal.drainTimeoutLoss.uncertain],
		["service_terminal_relay_loss", input.serviceSeal.terminalRelayLoss.definite],
		["service_terminal_relay_uncertainty", input.serviceSeal.terminalRelayLoss.uncertain],
	] as const) {
		if (!safeCount(count)) corrupt.add(`${reason}_counter_invalid`);
		else if (positive(count)) incomplete.add(reason);
	}
	if (input.serviceSeal.terminalRelayDisposition !== "relayed") {
		incomplete.add(`service_terminal_relay_disposition:${input.serviceSeal.terminalRelayDisposition}`);
	}
	retentionAnchorWallTimeMs ??= supervisorExitAnchorWallTimeMs;
	if (supervisorExitAnchorWallTimeMs === null) incomplete.add("supervisor_exit_anchor_unavailable");
	if (retentionAnchorWallTimeMs === null) incomplete.add("retention_anchor_unavailable");
	if (
		corrupt.size === 0 &&
		incomplete.size === 0 &&
		(!input.assertProjectionLeaseUsable || !input.releaseProjectionLease)
	) {
		incomplete.add("complete_projection_lease_unavailable");
	}

	const state: FinalizationAnalysis["state"] =
		corrupt.size > 0 ? "corrupt" : pending ? "pending" : incomplete.size > 0 ? "incomplete" : "complete";
	const reasons = [...(corrupt.size > 0 ? corrupt : incomplete)].sort();
	const finalizationId = sha256(
		JSON.stringify(semanticFinalizationInput(input, state, reasons, retentionAnchorWallTimeMs)),
	);
	return {
		state,
		finalizationId,
		reasons,
		supervisorExitAnchorWallTimeMs,
		retentionAnchorWallTimeMs,
	};
}

function combinedFileSystem(options?: IncidentRecorderFinalizerOptions): IncidentRecorderFinalizationFileSystem {
	return { ...defaultFileSystem, ...options?.fs };
}

interface PinnedFinalizationDirectory {
	canonicalPath: string;
	operationPath: string;
	descriptor: number;
	identity: BigIntStats;
}

interface PinnedIncidentDirectorySet {
	parent: PinnedFinalizationDirectory;
	member?: PinnedFinalizationDirectory;
	memberOperationPath: string;
	canonicalMemberPath: string;
	memberState: "missing" | "present" | "invalid";
}

class FinalizationDirectoryBindingError extends Error {
	readonly reason: string;

	constructor(reason: string) {
		super(reason);
		this.name = "FinalizationDirectoryBindingError";
		this.reason = reason;
	}
}

function descriptorDirectoryPath(descriptor: number): string {
	return `/proc/self/fd/${descriptor}`;
}

function sameDirectoryBindingIdentity(left: BigIntStats, right: BigIntStats): boolean {
	return (
		left.isDirectory() &&
		right.isDirectory() &&
		!left.isSymbolicLink() &&
		!right.isSymbolicLink() &&
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.mode === right.mode &&
		left.uid === right.uid &&
		left.gid === right.gid
	);
}

function closePinnedFinalizationDirectory(
	fs: IncidentRecorderFinalizationFileSystem,
	pinned: PinnedFinalizationDirectory | undefined,
): void {
	if (!pinned) return;
	try {
		fs.close(pinned.descriptor);
	} catch {}
}

function pinFinalizationDirectory(
	fs: IncidentRecorderFinalizationFileSystem,
	canonicalPath: string,
	operationPath = canonicalPath,
): PinnedFinalizationDirectory | undefined {
	let descriptor: number | undefined;
	try {
		const before = fs.lstat(canonicalPath, { bigint: true });
		if (!before.isDirectory() || before.isSymbolicLink()) return undefined;
		descriptor = fs.open(operationPath, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
		const opened = fs.fstat(descriptor, { bigint: true });
		const after = fs.lstat(canonicalPath, { bigint: true });
		if (!sameDirectoryBindingIdentity(before, opened) || !sameDirectoryBindingIdentity(opened, after)) {
			return undefined;
		}
		const result: PinnedFinalizationDirectory = {
			canonicalPath,
			operationPath: descriptorDirectoryPath(descriptor),
			descriptor,
			identity: opened,
		};
		descriptor = undefined;
		return result;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) {
			try {
				fs.close(descriptor);
			} catch {}
		}
	}
}

function pinFinalizationIncidentDirectorySet(
	fs: IncidentRecorderFinalizationFileSystem,
	incidentsDirectory: string,
	incidentId: string,
): PinnedIncidentDirectorySet | undefined {
	const parent = pinFinalizationDirectory(fs, incidentsDirectory);
	if (!parent) return undefined;
	const canonicalMemberPath = join(parent.canonicalPath, incidentId);
	const memberOperationPath = join(parent.operationPath, incidentId);
	let memberState: PinnedIncidentDirectorySet["memberState"] = "missing";
	let member: PinnedFinalizationDirectory | undefined;
	try {
		const stat = fs.lstat(canonicalMemberPath, { bigint: true });
		if (!stat.isDirectory() || stat.isSymbolicLink()) {
			memberState = "invalid";
		} else {
			member = pinFinalizationDirectory(fs, canonicalMemberPath, memberOperationPath);
			memberState = member ? "present" : "invalid";
		}
	} catch (error) {
		memberState = errno(error) === "ENOENT" ? "missing" : "invalid";
	}
	return {
		parent,
		member,
		memberOperationPath: member?.operationPath ?? memberOperationPath,
		canonicalMemberPath,
		memberState,
	};
}

function validatePinnedFinalizationDirectory(
	fs: IncidentRecorderFinalizationFileSystem,
	pinned: PinnedFinalizationDirectory,
	reason: string,
): void {
	try {
		const opened = fs.fstat(pinned.descriptor, { bigint: true });
		const currentPath = fs.lstat(pinned.canonicalPath, { bigint: true });
		if (
			!sameDirectoryBindingIdentity(pinned.identity, opened) ||
			!sameDirectoryBindingIdentity(opened, currentPath)
		) {
			throw new FinalizationDirectoryBindingError(reason);
		}
	} catch (error) {
		if (error instanceof FinalizationDirectoryBindingError) throw error;
		throw new FinalizationDirectoryBindingError(reason);
	}
}

function validatePinnedFinalizationDirectorySet(
	fs: IncidentRecorderFinalizationFileSystem,
	set: PinnedIncidentDirectorySet,
): void {
	validatePinnedFinalizationDirectory(fs, set.parent, "finalization_incidents_directory_detached");
	if (set.member) {
		validatePinnedFinalizationDirectory(fs, set.member, "finalization_incident_directory_detached");
	}
}

function exposePinnedInspectionDirectory(
	inspection: IncidentRecorderPublishedFinalizationInspection,
	set: PinnedIncidentDirectorySet,
): IncidentRecorderPublishedFinalizationInspection {
	if (inspection.state === "pending") return inspection;
	const privateOperationPath = join(set.memberOperationPath, FINALIZATION_PRIVATE_AUTHORITY_DIRECTORY_NAME);
	return {
		...inspection,
		authorityDirectory:
			inspection.authorityDirectory === privateOperationPath
				? join(set.canonicalMemberPath, FINALIZATION_PRIVATE_AUTHORITY_DIRECTORY_NAME)
				: set.canonicalMemberPath,
	};
}

function closeChecked(fs: IncidentRecorderFinalizationFileSystem, descriptor: number): void {
	fs.close(descriptor);
}

function fsyncDirectory(fs: IncidentRecorderFinalizationFileSystem, path: string): void {
	const descriptorPath = /^\/proc\/self\/fd\/([0-9]+)$/.exec(path);
	if (descriptorPath) {
		const descriptor = Number(descriptorPath[1]);
		const stat = fs.fstat(descriptor);
		if (!stat.isDirectory()) throw new Error(`Expected directory while syncing ${path}`);
		fs.fsync(descriptor);
		return;
	}
	const descriptor = fs.open(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
	let operationError: unknown;
	let failed = false;
	try {
		const stat = fs.fstat(descriptor);
		if (!stat.isDirectory()) throw new Error(`Expected directory while syncing ${path}`);
		fs.fsync(descriptor);
	} catch (error) {
		failed = true;
		operationError = error;
	}
	try {
		closeChecked(fs, descriptor);
	} catch (error) {
		if (!failed) throw error;
	}
	if (failed) throw operationError;
}

function readBoundedExact(
	fs: IncidentRecorderFinalizationFileSystem,
	path: string,
	maximum = MAX_FINALIZATION_FILE_BYTES,
): Buffer | undefined {
	return readDescriptorBoundedExact(fs, path, maximum, (stat) => stat.isFile());
}

function sameStableFileIdentity(left: BigIntStats, right: BigIntStats): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.mode === right.mode &&
		left.nlink === right.nlink &&
		left.uid === right.uid &&
		left.gid === right.gid &&
		left.size === right.size &&
		left.mtimeNs === right.mtimeNs &&
		left.ctimeNs === right.ctimeNs
	);
}

function readDescriptorBoundedExact(
	fs: IncidentRecorderFinalizationFileSystem,
	path: string,
	maximum: number,
	acceptable: (stat: BigIntStats) => boolean,
	afterRead?: (bytes: Buffer, stat: BigIntStats, descriptor: number) => boolean,
): Buffer | undefined {
	let descriptor: number | undefined;
	let closeAttempted = false;
	try {
		descriptor = fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const before = fs.fstat(descriptor, { bigint: true });
		if (before.size < 0n || before.size > BigInt(maximum) || !acceptable(before)) return undefined;
		const bytes = Buffer.alloc(Number(before.size));
		let offset = 0;
		while (offset < bytes.length) {
			const count = fs.read(descriptor, bytes, offset, bytes.length - offset, null);
			if (!Number.isSafeInteger(count) || count <= 0 || count > bytes.length - offset) return undefined;
			offset += count;
		}
		const after = fs.fstat(descriptor, { bigint: true });
		if (!sameStableFileIdentity(before, after) || !acceptable(after)) return undefined;
		const pathname = fs.lstat(path, { bigint: true });
		if (!sameStableFileIdentity(after, pathname) || !acceptable(pathname)) return undefined;
		if (afterRead && !afterRead(bytes, after, descriptor)) return undefined;
		closeAttempted = true;
		fs.close(descriptor);
		descriptor = undefined;
		return bytes;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined && !closeAttempted) {
			try {
				fs.close(descriptor);
			} catch {}
		}
	}
}

function immutableStagingFileNames(name: string, bytes: Buffer): string[] {
	const contentHash = sha256(bytes);
	return Array.from({ length: IMMUTABLE_STAGING_SLOT_COUNT }, (_, index) =>
		index === 0 ? `.${name}.${contentHash}.tmp` : `.${name}.${contentHash}.${index}.tmp`,
	);
}

function immutableStagingPaths(destination: string, bytes: Buffer): string[] {
	return immutableStagingFileNames(basename(destination), bytes).map((name) => join(dirname(destination), name));
}

function privateRegularFile(stat: BigIntStats, maximum: number, allowedLinks: readonly bigint[]): boolean {
	return (
		stat.isFile() &&
		allowedLinks.includes(stat.nlink) &&
		stat.size >= 0n &&
		stat.size <= BigInt(maximum) &&
		(typeof process.getuid !== "function" || stat.uid === BigInt(process.getuid())) &&
		(stat.mode & 0o077n) === 0n
	);
}

function readPrivatePublishedExact(
	fs: IncidentRecorderFinalizationFileSystem,
	path: string,
	maximum = MAX_FINALIZATION_FILE_BYTES,
): Buffer | undefined {
	return readDescriptorBoundedExact(
		fs,
		path,
		maximum,
		(stat) => privateRegularFile(stat, maximum, [1n, 2n]),
		(bytes, stat) => {
			if (stat.nlink === 1n) return true;
			for (const temporaryPath of immutableStagingPaths(path, bytes)) {
				try {
					const temporary = fs.lstat(temporaryPath, { bigint: true });
					if (
						privateRegularFile(temporary, maximum, [2n]) &&
						temporary.dev === stat.dev &&
						temporary.ino === stat.ino
					) {
						return true;
					}
				} catch {}
			}
			return false;
		},
	);
}

function readPrivateSingleLinkExact(
	fs: IncidentRecorderFinalizationFileSystem,
	path: string,
	maximum = MAX_FINALIZATION_FILE_BYTES,
	allowEmpty = true,
): Buffer | undefined {
	return readDescriptorBoundedExact(
		fs,
		path,
		maximum,
		(stat) => privateRegularFile(stat, maximum, [1n]) && (allowEmpty || stat.size > 0n),
	);
}

function readPrivateStagingExact(
	fs: IncidentRecorderFinalizationFileSystem,
	temporaryPath: string,
	destinationPath: string,
	maximum = MAX_FINALIZATION_FILE_BYTES,
	makeDurable = false,
): Buffer | undefined {
	return readDescriptorBoundedExact(
		fs,
		temporaryPath,
		maximum,
		(stat) => privateRegularFile(stat, maximum, [1n, 2n]),
		(_bytes, stat, descriptor) => {
			if (stat.nlink === 1n) {
				if (makeDurable) fs.fsync(descriptor);
				return true;
			}
			try {
				const destination = fs.lstat(destinationPath, { bigint: true });
				const matches =
					privateRegularFile(destination, maximum, [2n]) &&
					destination.dev === stat.dev &&
					destination.ino === stat.ino;
				if (!matches) return false;
				if (makeDurable) fs.fsync(descriptor);
				return true;
			} catch {
				return false;
			}
		},
	);
}

function namespaceOccupantMetadata(
	fs: IncidentRecorderFinalizationFileSystem,
	path: string,
): { observed: FinalizationConflictObserved; bytes?: Buffer } {
	let stat: BigIntStats;
	try {
		stat = fs.lstat(path, { bigint: true });
	} catch (error) {
		return {
			observed: {
				disposition: "lstat_unavailable",
				fileType: "unknown",
				dev: null,
				ino: null,
				size: null,
				mode: null,
				nlink: null,
				uid: null,
				mtimeNs: null,
				ctimeNs: null,
				errno: errno(error) ?? "UNKNOWN",
			},
		};
	}
	const metadata = {
		fileType: stat.isSymbolicLink()
			? ("symlink" as const)
			: stat.isDirectory()
				? ("directory" as const)
				: stat.isFile()
					? ("file" as const)
					: ("other" as const),
		dev: stat.dev.toString(),
		ino: stat.ino.toString(),
		size: stat.size.toString(),
		mode: (stat.mode & 0o7777n).toString(8).padStart(4, "0"),
		nlink: stat.nlink.toString(),
		uid: stat.uid.toString(),
		mtimeNs: stat.mtimeNs.toString(),
		ctimeNs: stat.ctimeNs.toString(),
		errno: null,
	};
	const disposition: FinalizationConflictNamespaceOccupant["disposition"] | undefined = stat.isSymbolicLink()
		? "symlink"
		: stat.isDirectory()
			? "directory"
			: !stat.isFile()
				? "non_regular"
				: stat.nlink !== 1n
					? "hardlinked_file"
					: stat.size < 0n || stat.size > BigInt(MAX_FINALIZATION_FILE_BYTES)
						? "oversized_file"
						: typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())
							? "owner_mismatch"
							: (stat.mode & 0o077n) !== 0n
								? "non_private_file"
								: undefined;
	if (disposition) return { observed: { disposition, ...metadata } };
	const bytes = readPrivatePublishedExact(fs, path);
	if (!bytes) return { observed: { disposition: "read_unavailable_or_changed", ...metadata } };
	return {
		observed: {
			disposition: "exact_private_bytes",
			evidence: fileRecord("placeholder.json", bytes),
		},
		bytes,
	};
}

function writeAll(
	fs: IncidentRecorderFinalizationFileSystem,
	descriptor: number,
	bytes: Buffer,
	onWritten?: () => void,
): void {
	let offset = 0;
	while (offset < bytes.length) {
		const count = fs.write(descriptor, bytes, offset, bytes.length - offset, offset);
		if (!Number.isSafeInteger(count) || count <= 0) throw new Error("Incident finalization write made no progress");
		offset += count;
	}
	onWritten?.();
}

type ImmutableWriteResult = "applied" | "noop" | "conflict";

function publishImmutableFile(
	fs: IncidentRecorderFinalizationFileSystem,
	directory: string,
	name: string,
	bytes: Buffer,
	hooks: {
		afterWrite?: () => void;
		afterFsync?: () => void;
		afterLink?: () => void;
		afterDirectoryFsync?: () => void;
		onConflict?: (existing: Buffer | undefined) => void;
	} = {},
): ImmutableWriteResult {
	if (bytes.length > MAX_FINALIZATION_FILE_BYTES) throw new Error(`Incident finalization file exceeds bound: ${name}`);
	const destination = join(directory, name);
	const temporaryCandidates = immutableStagingPaths(destination, bytes);
	let destinationOccupied = false;
	try {
		fs.lstat(destination, { bigint: true });
		destinationOccupied = true;
	} catch (error) {
		if (errno(error) !== "ENOENT") throw error;
	}
	if (destinationOccupied) {
		const existing = readPrivatePublishedExact(fs, destination);
		if (!existing?.equals(bytes)) {
			hooks.onConflict?.(existing);
			return "conflict";
		}
		fsyncDirectory(fs, directory);
		let cleaned = false;
		for (const temporary of temporaryCandidates) {
			const exactStage = readPrivateStagingExact(fs, temporary, destination);
			if (!exactStage?.equals(bytes)) continue;
			fs.unlink(temporary);
			cleaned = true;
		}
		if (cleaned) fsyncDirectory(fs, directory);
		return "noop";
	}
	let temporary: string | undefined;
	for (const candidate of temporaryCandidates) {
		let descriptor: number | undefined;
		try {
			descriptor = fs.open(
				candidate,
				fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
				0o600,
			);
			writeAll(fs, descriptor, bytes, hooks.afterWrite);
			fs.fsync(descriptor);
			hooks.afterFsync?.();
			closeChecked(fs, descriptor);
			descriptor = undefined;
			temporary = candidate;
			break;
		} catch (error) {
			if (descriptor !== undefined) {
				try {
					closeChecked(fs, descriptor);
				} catch {}
			}
			if (errno(error) !== "EEXIST") throw error;
			const existingStage = readPrivateStagingExact(fs, candidate, destination, MAX_FINALIZATION_FILE_BYTES, true);
			if (!existingStage?.equals(bytes)) continue;
			temporary = candidate;
			break;
		}
	}
	if (!temporary) {
		hooks.onConflict?.(undefined);
		return "conflict";
	}
	try {
		fs.link(temporary, destination);
		hooks.afterLink?.();
		const stagedStat = fs.lstat(temporary, { bigint: true });
		const finalStat = fs.lstat(destination, { bigint: true });
		if (
			!stagedStat.isFile() ||
			!finalStat.isFile() ||
			stagedStat.isSymbolicLink() ||
			finalStat.isSymbolicLink() ||
			stagedStat.dev !== finalStat.dev ||
			stagedStat.ino !== finalStat.ino
		) {
			throw new Error(`Incident finalization publication identity conflict: ${name}`);
		}
		fsyncDirectory(fs, directory);
		hooks.afterDirectoryFsync?.();
		fs.unlink(temporary);
		fsyncDirectory(fs, directory);
		return "applied";
	} catch (error) {
		if (errno(error) !== "EEXIST") throw error;
		const existing = readPrivatePublishedExact(fs, destination);
		if (!existing?.equals(bytes)) {
			hooks.onConflict?.(existing);
			fs.unlink(temporary);
			fsyncDirectory(fs, directory);
			return "conflict";
		}
		fsyncDirectory(fs, directory);
		try {
			fs.unlink(temporary);
			fsyncDirectory(fs, directory);
		} catch (cleanupError) {
			if (errno(cleanupError) !== "ENOENT") throw cleanupError;
		}
		return "noop";
	}
}

function validFileRecord(value: unknown): value is FinalizationFileRecord {
	if (!value || typeof value !== "object") return false;
	const record = value as Partial<FinalizationFileRecord>;
	return (
		typeof record.name === "string" &&
		/^[a-z0-9-]+\.json$/.test(record.name) &&
		record.name !== "finalization-manifest.json" &&
		Number.isSafeInteger(record.bytes) &&
		Number(record.bytes) >= 0 &&
		Number(record.bytes) <= MAX_FINALIZATION_FILE_BYTES &&
		typeof record.sha256 === "string" &&
		SHA256.test(record.sha256)
	);
}

function sameFileRecord(left: FinalizationFileRecord, right: FinalizationFileRecord): boolean {
	return left.name === right.name && left.bytes === right.bytes && left.sha256 === right.sha256;
}

function canonicalReasons(value: unknown): value is string[] {
	if (!Array.isArray(value) || !value.every((reason) => typeof reason === "string")) return false;
	return JSON.stringify(value) === JSON.stringify([...new Set(value)].sort());
}

function parseManifest(bytes: Buffer): FinalizationManifest | undefined {
	try {
		const value = JSON.parse(bytes.toString("utf8")) as Partial<FinalizationManifestBase> & {
			kind?: unknown;
			conflictRecord?: unknown;
		};
		if (
			value.schemaVersion !== 1 ||
			!["incident_recorder_finalization_manifest", "incident_recorder_finalization_conflict_manifest"].includes(
				String(value.kind),
			) ||
			!value.finalizationId ||
			!SHA256.test(value.finalizationId) ||
			!value.runIdentity ||
			!CANONICAL_UUID.test(value.runIdentity.runId) ||
			!CANONICAL_UUID.test(value.runIdentity.runToken) ||
			!["complete", "incomplete", "corrupt"].includes(String(value.state)) ||
			!Array.isArray(value.reasons) ||
			!value.reasons.every((reason) => typeof reason === "string") ||
			!(
				value.supervisorExitAnchorWallTimeMs === null ||
				(Number.isSafeInteger(value.supervisorExitAnchorWallTimeMs) &&
					Number(value.supervisorExitAnchorWallTimeMs) >= 0)
			) ||
			!(
				value.retentionAnchorWallTimeMs === null ||
				(Number.isSafeInteger(value.retentionAnchorWallTimeMs) && Number(value.retentionAnchorWallTimeMs) >= 0)
			) ||
			!Array.isArray(value.files) ||
			!value.files.every(validFileRecord)
		) {
			return undefined;
		}
		if (value.kind === "incident_recorder_finalization_manifest") {
			if (
				!exactObjectKeys(value, [
					"schemaVersion",
					"kind",
					"finalizationId",
					"state",
					"reasons",
					"runIdentity",
					"supervisorExitAnchorWallTimeMs",
					"retentionAnchorWallTimeMs",
					"files",
				]) ||
				!exactObjectKeys(value.runIdentity, ["runId", "runToken"]) ||
				!canonicalReasons(value.reasons) ||
				value.files.length !== STANDARD_FINALIZATION_FILE_NAMES.length ||
				value.files.some(
					(record, index) => !strictFileRecord(record) || record.name !== STANDARD_FINALIZATION_FILE_NAMES[index],
				) ||
				!jsonBytes(value).equals(bytes)
			) {
				return undefined;
			}
			return value as StandardFinalizationManifest;
		}
		if (
			value.state !== "corrupt" ||
			!canonicalReasons(value.reasons) ||
			!exactObjectKeys(value.runIdentity, ["runId", "runToken"]) ||
			!exactObjectKeys(value, [
				"schemaVersion",
				"kind",
				"finalizationId",
				"state",
				"reasons",
				"runIdentity",
				"supervisorExitAnchorWallTimeMs",
				"retentionAnchorWallTimeMs",
				"files",
				"conflictRecord",
			]) ||
			!strictFileRecord(value.conflictRecord) ||
			value.conflictRecord.name !== `finalization-conflict-${value.conflictRecord.sha256}.json` ||
			!value.files.every(strictFileRecord) ||
			!value.files.some((record) => sameFileRecord(record, value.conflictRecord as FinalizationFileRecord)) ||
			!jsonBytes(value).equals(bytes)
		) {
			return undefined;
		}
		return value as ConflictFinalizationManifest;
	} catch {
		return undefined;
	}
}

function fileRecord(name: string, bytes: Buffer): FinalizationFileRecord {
	return { name, bytes: bytes.length, sha256: sha256(bytes) };
}

function conflictEvidenceName(side: "prepared" | "observed", logicalName: string, digest: string): string {
	const role = logicalName.endsWith(".json") ? logicalName.slice(0, -5) : logicalName;
	return `conflict-${side}-${role}-${digest}.json`;
}

function exactObjectKeys(value: object, expected: readonly string[]): boolean {
	return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function strictFileRecord(value: unknown): value is FinalizationFileRecord {
	return (
		!!value &&
		typeof value === "object" &&
		exactObjectKeys(value, ["name", "bytes", "sha256"]) &&
		validFileRecord(value)
	);
}

function validConflictObserved(value: unknown): value is FinalizationConflictObserved {
	if (!value || typeof value !== "object" || typeof (value as { disposition?: unknown }).disposition !== "string")
		return false;
	const observed = value as Partial<FinalizationConflictObserved> & { disposition: string };
	if (observed.disposition === "exact_private_bytes") {
		return exactObjectKeys(value, ["disposition", "evidence"]) && strictFileRecord(observed.evidence);
	}
	if (
		![
			"directory",
			"hardlinked_file",
			"lstat_unavailable",
			"non_private_file",
			"non_regular",
			"owner_mismatch",
			"oversized_file",
			"read_unavailable_or_changed",
			"symlink",
		].includes(observed.disposition) ||
		!exactObjectKeys(value, [
			"disposition",
			"fileType",
			"dev",
			"ino",
			"size",
			"mode",
			"nlink",
			"uid",
			"mtimeNs",
			"ctimeNs",
			"errno",
		])
	) {
		return false;
	}
	const occupant = value as Partial<FinalizationConflictNamespaceOccupant>;
	return (
		["directory", "file", "other", "symlink", "unknown"].includes(String(occupant.fileType)) &&
		[
			occupant.dev,
			occupant.ino,
			occupant.size,
			occupant.nlink,
			occupant.uid,
			occupant.mtimeNs,
			occupant.ctimeNs,
		].every((field) => field === null || (typeof field === "string" && /^(?:0|-?[1-9][0-9]{0,39})$/.test(field))) &&
		(occupant.mode === null || (typeof occupant.mode === "string" && /^[0-7]{4}$/.test(occupant.mode))) &&
		(occupant.errno === null || (typeof occupant.errno === "string" && /^[A-Z0-9_]{1,64}$/.test(occupant.errno)))
	);
}

function parseAuthoritySelector(bytes: Buffer): FinalizationAuthoritySelector | undefined {
	try {
		const value = JSON.parse(bytes.toString("utf8")) as Partial<FinalizationAuthoritySelector>;
		if (
			!exactObjectKeys(value, ["schemaVersion", "kind", "finalizationId", "runIdentity", "state", "manifest"]) ||
			value.schemaVersion !== 1 ||
			value.kind !== "incident_recorder_finalization_authority_selector" ||
			!value.finalizationId ||
			!SHA256.test(value.finalizationId) ||
			!value.runIdentity ||
			!exactObjectKeys(value.runIdentity, ["runId", "runToken"]) ||
			!CANONICAL_UUID.test(value.runIdentity.runId) ||
			!CANONICAL_UUID.test(value.runIdentity.runToken) ||
			value.state !== "corrupt" ||
			!strictFileRecord(value.manifest) ||
			value.manifest.name !== `finalization-conflict-manifest-${value.manifest.sha256}.json` ||
			!jsonBytes(value).equals(bytes)
		) {
			return undefined;
		}
		return value as FinalizationAuthoritySelector;
	} catch {
		return undefined;
	}
}

function parseAuthorityClaim(bytes: Buffer): FinalizationAuthorityClaim | undefined {
	try {
		const value = JSON.parse(bytes.toString("utf8")) as Partial<FinalizationAuthorityClaim>;
		if (
			!exactObjectKeys(value, ["schemaVersion", "kind", "finalizationId", "runIdentity", "preparedManifest"]) ||
			value.schemaVersion !== 1 ||
			value.kind !== "incident_recorder_finalization_authority_claim" ||
			!value.finalizationId ||
			!SHA256.test(value.finalizationId) ||
			!value.runIdentity ||
			!exactObjectKeys(value.runIdentity, ["runId", "runToken"]) ||
			!CANONICAL_UUID.test(value.runIdentity.runId) ||
			!CANONICAL_UUID.test(value.runIdentity.runToken) ||
			!value.preparedManifest ||
			!exactObjectKeys(value.preparedManifest, ["bytes", "sha256"]) ||
			!Number.isSafeInteger(value.preparedManifest.bytes) ||
			value.preparedManifest.bytes < 0 ||
			value.preparedManifest.bytes > MAX_FINALIZATION_FILE_BYTES ||
			!SHA256.test(value.preparedManifest.sha256) ||
			!jsonBytes(value).equals(bytes)
		) {
			return undefined;
		}
		return value as FinalizationAuthorityClaim;
	} catch {
		return undefined;
	}
}

function parseConflictRecord(bytes: Buffer): FinalizationConflictRecord | undefined {
	try {
		const value = JSON.parse(bytes.toString("utf8")) as Partial<FinalizationConflictRecord>;
		if (
			!exactObjectKeys(value, [
				"schemaVersion",
				"kind",
				"finalizationId",
				"runIdentity",
				"intendedState",
				"intendedReasons",
				"supervisorExitAnchorWallTimeMs",
				"retentionAnchorWallTimeMs",
				"intendedManifest",
				"files",
				...(value.manifestConflict ? ["manifestConflict"] : []),
			]) ||
			value.schemaVersion !== 1 ||
			value.kind !== "incident_recorder_finalization_publication_conflict" ||
			!value.finalizationId ||
			!SHA256.test(value.finalizationId) ||
			!value.runIdentity ||
			!exactObjectKeys(value.runIdentity, ["runId", "runToken"]) ||
			!CANONICAL_UUID.test(value.runIdentity.runId) ||
			!CANONICAL_UUID.test(value.runIdentity.runToken) ||
			!["complete", "incomplete", "corrupt"].includes(String(value.intendedState)) ||
			!canonicalReasons(value.intendedReasons) ||
			!(
				value.supervisorExitAnchorWallTimeMs === null ||
				(Number.isSafeInteger(value.supervisorExitAnchorWallTimeMs) &&
					Number(value.supervisorExitAnchorWallTimeMs) >= 0)
			) ||
			!(
				value.retentionAnchorWallTimeMs === null ||
				(Number.isSafeInteger(value.retentionAnchorWallTimeMs) && Number(value.retentionAnchorWallTimeMs) >= 0)
			) ||
			!strictFileRecord(value.intendedManifest) ||
			!Array.isArray(value.files) ||
			value.files.length !== STANDARD_FINALIZATION_FILE_NAMES.length ||
			!value.files.every((entry) => {
				if (!entry || typeof entry !== "object") return false;
				if (
					!exactObjectKeys(
						entry,
						entry.observed ? ["logicalName", "prepared", "observed"] : ["logicalName", "prepared"],
					)
				)
					return false;
				return (
					STANDARD_FINALIZATION_FILE_NAMES.includes(entry.logicalName as never) &&
					strictFileRecord(entry.prepared) &&
					(entry.observed === undefined || validConflictObserved(entry.observed))
				);
			}) ||
			(value.manifestConflict !== undefined &&
				(!exactObjectKeys(value.manifestConflict, ["logicalName", "prepared", "observed"]) ||
					value.manifestConflict.logicalName !== "finalization-manifest.json" ||
					!strictFileRecord(value.manifestConflict.prepared) ||
					!validConflictObserved(value.manifestConflict.observed))) ||
			!jsonBytes(value).equals(bytes)
		) {
			return undefined;
		}
		return value as FinalizationConflictRecord;
	} catch {
		return undefined;
	}
}

function validateObservedConflict(
	fs: IncidentRecorderFinalizationFileSystem,
	directory: string,
	logicalName: string,
	observed: FinalizationConflictObserved,
): boolean {
	if (observed.disposition === "exact_private_bytes") {
		if (observed.evidence.name !== conflictEvidenceName("observed", logicalName, observed.evidence.sha256)) {
			return false;
		}
		const bytes = readPrivatePublishedExact(fs, join(directory, observed.evidence.name));
		return !!bytes && sameFileRecord(observed.evidence, fileRecord(observed.evidence.name, bytes));
	}
	return validConflictObserved(observed);
}

function validateConflictFinalization(
	fs: IncidentRecorderFinalizationFileSystem,
	directory: string,
	manifest: ConflictFinalizationManifest,
	listedBytes: ReadonlyMap<string, Buffer>,
): FinalizationConflictRecord | undefined {
	const conflictBytes = listedBytes.get(manifest.conflictRecord.name);
	if (!conflictBytes) return undefined;
	const conflict = parseConflictRecord(conflictBytes);
	if (!conflict) return undefined;
	if (
		conflict.finalizationId !== manifest.finalizationId ||
		conflict.runIdentity.runId !== manifest.runIdentity.runId ||
		conflict.runIdentity.runToken !== manifest.runIdentity.runToken ||
		conflict.supervisorExitAnchorWallTimeMs !== manifest.supervisorExitAnchorWallTimeMs ||
		conflict.retentionAnchorWallTimeMs !== manifest.retentionAnchorWallTimeMs ||
		!sameFileRecord(manifest.conflictRecord, fileRecord(manifest.conflictRecord.name, conflictBytes)) ||
		manifest.conflictRecord.name !== `finalization-conflict-${manifest.conflictRecord.sha256}.json`
	) {
		return undefined;
	}
	const intendedManifestBytes = listedBytes.get(conflict.intendedManifest.name);
	if (
		!intendedManifestBytes ||
		!sameFileRecord(conflict.intendedManifest, fileRecord(conflict.intendedManifest.name, intendedManifestBytes))
	)
		return undefined;
	const intendedManifest = parseManifest(intendedManifestBytes);
	if (
		!intendedManifest ||
		intendedManifest.kind !== "incident_recorder_finalization_manifest" ||
		!jsonBytes(intendedManifest).equals(intendedManifestBytes) ||
		intendedManifest.finalizationId !== manifest.finalizationId ||
		intendedManifest.runIdentity.runId !== manifest.runIdentity.runId ||
		intendedManifest.runIdentity.runToken !== manifest.runIdentity.runToken ||
		intendedManifest.state !== conflict.intendedState ||
		JSON.stringify(intendedManifest.reasons) !== JSON.stringify(conflict.intendedReasons) ||
		intendedManifest.supervisorExitAnchorWallTimeMs !== manifest.supervisorExitAnchorWallTimeMs ||
		intendedManifest.retentionAnchorWallTimeMs !== manifest.retentionAnchorWallTimeMs ||
		conflict.intendedManifest.name !==
			conflictEvidenceName("prepared", "finalization-manifest.json", conflict.intendedManifest.sha256)
	) {
		return undefined;
	}
	const expectedReasons = [
		...new Set([
			...intendedManifest.reasons,
			...conflict.files
				.filter((entry) => entry.observed !== undefined)
				.map((entry) => PUBLICATION_CONFLICT_REASON_PREFIX + entry.logicalName),
			...(conflict.manifestConflict
				? [PUBLICATION_CONFLICT_REASON_PREFIX + conflict.manifestConflict.logicalName]
				: []),
		]),
	].sort();
	if (JSON.stringify(manifest.reasons) !== JSON.stringify(expectedReasons)) return undefined;
	const listedRecords = new Map(manifest.files.map((record) => [record.name, record]));
	const expectedListedNames = new Set<string>([conflict.intendedManifest.name, manifest.conflictRecord.name]);
	const logicalPreparedBytes = new Map<string, Buffer>();
	let observedCount = 0;
	for (let index = 0; index < intendedManifest.files.length; index += 1) {
		const intended = intendedManifest.files[index];
		const mapping = conflict.files[index];
		if (!intended || !mapping || mapping.logicalName !== intended.name) return undefined;
		if (mapping.prepared.bytes !== intended.bytes || mapping.prepared.sha256 !== intended.sha256) return undefined;
		if (mapping.observed) {
			observedCount += 1;
			if (
				mapping.prepared.name !== conflictEvidenceName("prepared", mapping.logicalName, mapping.prepared.sha256) ||
				!validateObservedConflict(fs, directory, mapping.logicalName, mapping.observed) ||
				(mapping.observed.disposition === "exact_private_bytes" &&
					mapping.observed.evidence.sha256 === mapping.prepared.sha256)
			) {
				return undefined;
			}
			if (mapping.observed.disposition === "exact_private_bytes") {
				expectedListedNames.add(mapping.observed.evidence.name);
			}
		} else if (mapping.prepared.name !== mapping.logicalName) {
			return undefined;
		}
		const preparedBytes = listedBytes.get(mapping.prepared.name);
		if (!preparedBytes || !sameFileRecord(mapping.prepared, fileRecord(mapping.prepared.name, preparedBytes)))
			return undefined;
		logicalPreparedBytes.set(intended.name, preparedBytes);
		expectedListedNames.add(mapping.prepared.name);
	}
	if (conflict.manifestConflict) {
		observedCount += 1;
		if (
			!sameFileRecord(conflict.manifestConflict.prepared, conflict.intendedManifest) ||
			!validateObservedConflict(
				fs,
				directory,
				conflict.manifestConflict.logicalName,
				conflict.manifestConflict.observed,
			) ||
			(conflict.manifestConflict.observed.disposition === "exact_private_bytes" &&
				conflict.manifestConflict.observed.evidence.sha256 === conflict.intendedManifest.sha256)
		) {
			return undefined;
		}
		if (conflict.manifestConflict.observed.disposition === "exact_private_bytes") {
			expectedListedNames.add(conflict.manifestConflict.observed.evidence.name);
		}
	}
	if (
		observedCount === 0 ||
		listedRecords.size !== expectedListedNames.size ||
		[...expectedListedNames].some((name) => !listedRecords.has(name)) ||
		!validateStandardFinalizationFiles(intendedManifest, logicalPreparedBytes)
	) {
		return undefined;
	}
	return conflict;
}

function canonicalJsonObject(bytes: Buffer): Record<string, unknown> | undefined {
	try {
		const value = JSON.parse(bytes.toString("utf8")) as unknown;
		if (!value || typeof value !== "object" || Array.isArray(value) || !jsonBytes(value).equals(bytes)) {
			return undefined;
		}
		return value as Record<string, unknown>;
	} catch {
		return undefined;
	}
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
	return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

const RUN_HISTORY_PAYLOAD_KINDS = ["exact-bytes", "derived-scalar", "loss", "control"] as const;
const RUN_HISTORY_EVIDENCE_KINDS = ["gap", "incomplete", "corrupt", "truncated"] as const;

function nonEmptyString(value: unknown): value is string {
	return typeof value === "string" && value.length > 0;
}

function safeNonNegativeInteger(value: unknown): value is number {
	return Number.isSafeInteger(value) && Number(value) >= 0;
}

function unsignedSequence(value: unknown): value is string {
	if (typeof value !== "string" || !UNSIGNED_SEQUENCE.test(value)) return false;
	try {
		return BigInt(value) <= (1n << 64n) - 1n;
	} catch {
		return false;
	}
}

function contiguousUnsignedSequence(value: unknown): value is string[] {
	if (!strictStringArray(value, 1) || !value.every(unsignedSequence)) return false;
	try {
		const first = BigInt(value[0]);
		return value.every((entry, index) => BigInt(entry) === first + BigInt(index));
	} catch {
		return false;
	}
}

function strictStringArray(value: unknown, minimumLength = 0): value is string[] {
	return Array.isArray(value) && value.length >= minimumLength && value.every((entry) => typeof entry === "string");
}

function validRunHistoryScalarMetadata(value: unknown): boolean {
	const metadata = objectValue(value);
	return (
		!!metadata &&
		Object.entries(metadata).every(
			([key, child]) =>
				/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(key) &&
				(child === null ||
					typeof child === "string" ||
					typeof child === "boolean" ||
					(typeof child === "number" && Number.isFinite(child))),
		) &&
		Buffer.byteLength(JSON.stringify(metadata)) <= 4 * 1024
	);
}

function validRunHistorySegmentLocator(value: unknown): boolean {
	const locator = objectValue(value);
	return (
		!!locator &&
		exactObjectKeys(locator, [
			"version",
			"segmentId",
			"segmentSequence",
			"ordinal",
			"offset",
			"frameBytes",
			"payloadBytes",
			"payloadSha256",
		]) &&
		locator.version === 1 &&
		typeof locator.segmentId === "string" &&
		/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(locator.segmentId) &&
		safeNonNegativeInteger(locator.segmentSequence) &&
		safeNonNegativeInteger(locator.ordinal) &&
		safeNonNegativeInteger(locator.offset) &&
		safeNonNegativeInteger(locator.frameBytes) &&
		safeNonNegativeInteger(locator.payloadBytes) &&
		Number(locator.payloadBytes) <= Number(locator.frameBytes) &&
		typeof locator.payloadSha256 === "string" &&
		SHA256.test(locator.payloadSha256)
	);
}

function validRunHistoryOccurrenceReference(value: unknown): boolean {
	if (typeof value === "string") return value.length > 0;
	const reference = objectValue(value);
	return (
		!!reference &&
		exactObjectKeys(reference, ["kind", "locator"]) &&
		reference.kind === "segment" &&
		validRunHistorySegmentLocator(reference.locator)
	);
}

function validRunHistoryEvidenceReference(value: unknown): boolean {
	if (validRunHistorySegmentLocator(value)) return true;
	if (validRunHistoryOccurrenceReference(value)) return true;
	const reference = objectValue(value);
	if (!reference) return false;
	return (
		exactObjectKeys(reference, [
			"version",
			"segmentId",
			"segmentSequence",
			"ordinal",
			"reason",
			"observedAtMs",
			"invalidOffset",
			"discardedBytes",
			"discardedSha256",
		]) &&
		reference.version === 1 &&
		typeof reference.segmentId === "string" &&
		/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(reference.segmentId) &&
		safeNonNegativeInteger(reference.segmentSequence) &&
		safeNonNegativeInteger(reference.ordinal) &&
		reference.reason === "invalid_or_torn_active_tail" &&
		safeNonNegativeInteger(reference.observedAtMs) &&
		safeNonNegativeInteger(reference.invalidOffset) &&
		safeNonNegativeInteger(reference.discardedBytes) &&
		typeof reference.discardedSha256 === "string" &&
		SHA256.test(reference.discardedSha256)
	);
}

function validRunHistoryEvent(value: unknown, runIdentity: { runId: string; runToken: string }): boolean {
	const event = objectValue(value);
	if (!event) return false;
	const identity = objectValue(event.identity);
	const cas = objectValue(event.cas);
	return (
		exactObjectKeys(event, [
			"identityKey",
			"identity",
			"semanticFingerprint",
			"occurrenceReference",
			"source",
			"type",
			"encoding",
			"payloadKind",
			"terminal",
			"metadata",
			"eventWallTimeMs",
			"eventMonotonicNs",
			"wrapperOrder",
			"producerOrder",
			"cursors",
			"transportIdentity",
			"cas",
		]) &&
		typeof event.identityKey === "string" &&
		SHA256.test(event.identityKey) &&
		!!identity &&
		exactObjectKeys(identity, ["runId", "runToken", "producerId", "occurrenceId"]) &&
		identity.runId === runIdentity.runId &&
		identity.runToken === runIdentity.runToken &&
		CANONICAL_UUID.test(String(identity.producerId)) &&
		CANONICAL_UUID.test(String(identity.occurrenceId)) &&
		typeof event.semanticFingerprint === "string" &&
		SHA256.test(event.semanticFingerprint) &&
		validRunHistoryOccurrenceReference(event.occurrenceReference) &&
		nonEmptyString(event.source) &&
		Buffer.byteLength(event.source) <= 255 &&
		nonEmptyString(event.type) &&
		Buffer.byteLength(event.type) <= 255 &&
		nonEmptyString(event.encoding) &&
		Buffer.byteLength(event.encoding) <= 255 &&
		RUN_HISTORY_PAYLOAD_KINDS.includes(event.payloadKind as (typeof RUN_HISTORY_PAYLOAD_KINDS)[number]) &&
		typeof event.terminal === "boolean" &&
		validRunHistoryScalarMetadata(event.metadata) &&
		unsignedSequence(event.eventWallTimeMs) &&
		unsignedSequence(event.eventMonotonicNs) &&
		contiguousUnsignedSequence(event.wrapperOrder) &&
		contiguousUnsignedSequence(event.producerOrder) &&
		strictStringArray(event.cursors, 1) &&
		event.cursors.length <= 16_384 &&
		event.cursors.reduce((total, cursor) => total + Buffer.byteLength(cursor), 0) <= 1024 * 1024 &&
		event.wrapperOrder.length === event.producerOrder.length &&
		event.wrapperOrder.length === event.cursors.length &&
		!!objectValue(event.transportIdentity) &&
		Buffer.byteLength(JSON.stringify(event.transportIdentity)) <= 16 * 1024 &&
		!!cas &&
		exactObjectKeys(cas, ["digest", "bytes", "path"]) &&
		typeof cas.digest === "string" &&
		SHA256.test(cas.digest) &&
		safeNonNegativeInteger(cas.bytes) &&
		cas.bytes <= 983_040 &&
		nonEmptyString(cas.path)
	);
}

function validRunHistoryProjection(value: unknown, runIdentity: { runId: string; runToken: string }): boolean {
	const projection = objectValue(value);
	if (!projection) return false;
	const ordering = objectValue(projection.ordering);
	return (
		exactObjectKeys(projection, [
			"version",
			"runId",
			"fromWallTimeMs",
			"throughWallTimeMs",
			"events",
			"terminalEvents",
			"finalizationCandidates",
			"ordering",
			"evidence",
		]) &&
		projection.version === 1 &&
		projection.runId === runIdentity.runId &&
		safeNonNegativeInteger(projection.fromWallTimeMs) &&
		safeNonNegativeInteger(projection.throughWallTimeMs) &&
		Number(projection.throughWallTimeMs) >= Number(projection.fromWallTimeMs) &&
		Array.isArray(projection.events) &&
		projection.events.every((event) => validRunHistoryEvent(event, runIdentity)) &&
		Array.isArray(projection.terminalEvents) &&
		projection.terminalEvents.every((event) => {
			const terminal = objectValue(event);
			return (
				!!terminal &&
				exactObjectKeys(terminal, ["identityKey", "type", "source", "eventWallTimeMs", "basis"]) &&
				typeof terminal.identityKey === "string" &&
				SHA256.test(terminal.identityKey) &&
				nonEmptyString(terminal.type) &&
				nonEmptyString(terminal.source) &&
				unsignedSequence(terminal.eventWallTimeMs) &&
				terminal.basis === "terminal_flag"
			);
		}) &&
		Array.isArray(projection.finalizationCandidates) &&
		projection.finalizationCandidates.every((candidate) => {
			const value = objectValue(candidate);
			return (
				!!value &&
				exactObjectKeys(value, ["role", "identityKey", "basis", "qualification"]) &&
				["supervisor_exit", "capture_channel_terminal"].includes(String(value.role)) &&
				typeof value.identityKey === "string" &&
				SHA256.test(value.identityKey) &&
				["type_and_source_candidate", "type_source_and_terminal_flag_candidate"].includes(String(value.basis)) &&
				((value.role === "supervisor_exit" && value.basis === "type_and_source_candidate") ||
					(value.role === "capture_channel_terminal" &&
						value.basis === "type_source_and_terminal_flag_candidate")) &&
				value.qualification === "candidate_requires_expectation_match"
			);
		}) &&
		!!ordering &&
		exactObjectKeys(ordering, [
			"semantics",
			"causalRelations",
			"presentationTieBreak",
			"unrelatedPresentationOrderIsCausal",
			"scope",
		]) &&
		ordering.semantics === "partial_order" &&
		ordering.presentationTieBreak === "wall_time_then_identity_key" &&
		ordering.unrelatedPresentationOrderIsCausal === false &&
		["observed_events_only", "complete_snapshot"].includes(String(ordering.scope)) &&
		Array.isArray(ordering.causalRelations) &&
		ordering.causalRelations.every((relation) => {
			const value = objectValue(relation);
			return (
				!!value &&
				exactObjectKeys(value, ["beforeIdentityKey", "afterIdentityKey", "basis", "streamKeyHash"]) &&
				typeof value.beforeIdentityKey === "string" &&
				SHA256.test(value.beforeIdentityKey) &&
				typeof value.afterIdentityKey === "string" &&
				SHA256.test(value.afterIdentityKey) &&
				["producer_sequence", "wrapper_sequence"].includes(String(value.basis)) &&
				typeof value.streamKeyHash === "string" &&
				SHA256.test(value.streamKeyHash)
			);
		}) &&
		Array.isArray(projection.evidence) &&
		projection.evidence.every((evidence) => {
			const value = objectValue(evidence);
			if (
				!value ||
				!exactObjectKeys(
					value,
					["kind", "reason", "reference"].filter((key) => key in value),
				)
			)
				return false;
			return (
				exactObjectKeys(value, Object.keys(value)) &&
				RUN_HISTORY_EVIDENCE_KINDS.includes(value.kind as (typeof RUN_HISTORY_EVIDENCE_KINDS)[number]) &&
				nonEmptyString(value.reason) &&
				(!("reference" in value) || validRunHistoryEvidenceReference(value.reference))
			);
		})
	);
}

function validRunHistorySnapshot(value: unknown): boolean {
	const snapshot = objectValue(value);
	if (!snapshot) return false;
	return (
		exactObjectKeys(snapshot, [
			"version",
			"fingerprint",
			"segmentRecordCount",
			"segmentRecoveryGapCount",
			"segmentScannedSegments",
			"segmentScannedRecords",
			"segmentScannedIndexBytes",
			"legacyOccurrenceCount",
			"validatedCasDigestCount",
		]) &&
		snapshot.version === 1 &&
		typeof snapshot.fingerprint === "string" &&
		SHA256.test(snapshot.fingerprint) &&
		[
			snapshot.segmentRecordCount,
			snapshot.segmentRecoveryGapCount,
			snapshot.segmentScannedSegments,
			snapshot.segmentScannedRecords,
			snapshot.segmentScannedIndexBytes,
			snapshot.legacyOccurrenceCount,
			snapshot.validatedCasDigestCount,
		].every(safeNonNegativeInteger) &&
		Number(snapshot.segmentRecordCount) + Number(snapshot.segmentRecoveryGapCount) <=
			Number(snapshot.segmentScannedRecords) &&
		Number(snapshot.validatedCasDigestCount) <=
			Number(snapshot.segmentRecordCount) + Number(snapshot.legacyOccurrenceCount)
	);
}

interface RunHistoryNestedValidation {
	structureValid: boolean;
	snapshotValid: boolean;
}

function validateRunHistoryNested(
	value: unknown,
	runIdentity: { runId: string; runToken: string },
): RunHistoryNestedValidation {
	const runHistory = objectValue(value);
	if (
		!runHistory ||
		typeof runHistory.state !== "string" ||
		!["pending", "complete", "incomplete"].includes(runHistory.state)
	) {
		return { structureValid: false, snapshotValid: false };
	}
	const projectionValid = validRunHistoryProjection(runHistory.projection, runIdentity);
	if (!projectionValid) return { structureValid: false, snapshotValid: false };
	if (runHistory.state === "pending") {
		const cursor = objectValue(runHistory.cursor);
		return {
			structureValid:
				exactObjectKeys(runHistory, ["state", "cursor", "projection"]) &&
				!!cursor &&
				exactObjectKeys(cursor, ["version", "token", "requestFingerprint"]) &&
				cursor.version === 1 &&
				typeof cursor.token === "string" &&
				SHA256.test(cursor.token) &&
				typeof cursor.requestFingerprint === "string" &&
				SHA256.test(cursor.requestFingerprint),
			snapshotValid: true,
		};
	}
	if (runHistory.state === "incomplete") {
		return {
			structureValid:
				exactObjectKeys(runHistory, ["state", "reason", "projection"]) && nonEmptyString(runHistory.reason),
			snapshotValid: true,
		};
	}
	return {
		structureValid:
			Object.keys(runHistory).every((key) => ["state", "projection", "snapshot"].includes(key)) &&
			["state", "projection"].every((key) => key in runHistory),
		snapshotValid: validRunHistorySnapshot(runHistory.snapshot),
	};
}

function manifestRunIdentityMatches(value: unknown, manifest: StandardFinalizationManifest): boolean {
	const identity = objectValue(value);
	return (
		!!identity &&
		exactObjectKeys(identity, ["runId", "runToken"]) &&
		identity.runId === manifest.runIdentity.runId &&
		identity.runToken === manifest.runIdentity.runToken
	);
}

function validateStandardFinalizationFiles(
	manifest: StandardFinalizationManifest,
	listedBytes: ReadonlyMap<string, Buffer>,
): boolean {
	const intent = canonicalJsonObject(listedBytes.get("finalization-intent.json") ?? Buffer.alloc(0));
	const history = canonicalJsonObject(listedBytes.get("run-history.json") ?? Buffer.alloc(0));
	const descriptor = canonicalJsonObject(listedBytes.get("finalization-descriptor.json") ?? Buffer.alloc(0));
	const summary = canonicalJsonObject(listedBytes.get("summary.json") ?? Buffer.alloc(0));
	if (!intent || !history || !descriptor || !summary) return false;
	if (
		!exactObjectKeys(intent, ["schemaVersion", "kind", "operationId", "finalizationId", "runIdentity", "state"]) ||
		intent.schemaVersion !== 1 ||
		intent.kind !== "incident_recorder_finalization_intent" ||
		intent.operationId !== sha256(`${manifest.finalizationId}\0publish-v1`) ||
		intent.finalizationId !== manifest.finalizationId ||
		intent.state !== manifest.state ||
		!manifestRunIdentityMatches(intent.runIdentity, manifest)
	) {
		return false;
	}
	if (
		!exactObjectKeys(history, ["schemaVersion", "kind", "finalizationId", "runHistory"]) ||
		history.schemaVersion !== 1 ||
		history.kind !== "incident_recorder_run_history" ||
		history.finalizationId !== manifest.finalizationId
	) {
		return false;
	}
	const runHistory = objectValue(history.runHistory);
	if (!runHistory || !["complete", "incomplete"].includes(String(runHistory.state))) return false;
	const runHistoryValidation = validateRunHistoryNested(runHistory, manifest.runIdentity);
	if (!runHistoryValidation.structureValid && manifest.state === "complete") return false;
	if (runHistory.state === "complete" && manifest.state === "complete" && !runHistoryValidation.snapshotValid)
		return false;
	const projection = objectValue(runHistory.projection);
	if (
		runHistoryValidation.structureValid &&
		(!projection ||
			!exactObjectKeys(projection, [
				"version",
				"runId",
				"fromWallTimeMs",
				"throughWallTimeMs",
				"events",
				"terminalEvents",
				"finalizationCandidates",
				"ordering",
				"evidence",
			]) ||
			projection.version !== 1 ||
			projection.runId !== manifest.runIdentity.runId ||
			!Number.isSafeInteger(projection.fromWallTimeMs) ||
			!Number.isSafeInteger(projection.throughWallTimeMs) ||
			!Array.isArray(projection.events) ||
			!Array.isArray(projection.terminalEvents) ||
			!Array.isArray(projection.finalizationCandidates) ||
			!Array.isArray(projection.evidence) ||
			!objectValue(projection.ordering))
	) {
		return false;
	}
	if (
		!exactObjectKeys(descriptor, [
			"schemaVersion",
			"kind",
			"finalizationId",
			"state",
			"reasons",
			"runIdentity",
			"classification",
			"exit",
			"supervisorExitAnchorWallTimeMs",
			"retentionAnchorWallTimeMs",
			"terminalExpectations",
			"completeProjectionLeaseAvailable",
			"stoppedTarget",
			"wrapperLoss",
			"serviceSeal",
		]) ||
		descriptor.schemaVersion !== 1 ||
		descriptor.kind !== "incident_recorder_finalization_descriptor" ||
		descriptor.finalizationId !== manifest.finalizationId ||
		descriptor.state !== manifest.state ||
		JSON.stringify(descriptor.reasons) !== JSON.stringify(manifest.reasons) ||
		!manifestRunIdentityMatches(descriptor.runIdentity, manifest) ||
		descriptor.supervisorExitAnchorWallTimeMs !== manifest.supervisorExitAnchorWallTimeMs ||
		descriptor.retentionAnchorWallTimeMs !== manifest.retentionAnchorWallTimeMs
	) {
		return false;
	}
	const classification = objectValue(descriptor.classification);
	const exit = objectValue(descriptor.exit);
	const stoppedTarget = objectValue(descriptor.stoppedTarget);
	const terminalExpectations = objectValue(descriptor.terminalExpectations);
	const serviceSeal = objectValue(descriptor.serviceSeal);
	if (
		!classification ||
		!exactObjectKeys(classification, ["value", "causeLayer"]) ||
		typeof classification.value !== "string" ||
		typeof classification.causeLayer !== "string" ||
		!exit ||
		!exactObjectKeys(exit, ["code", "signal"]) ||
		!(exit.code === null || Number.isSafeInteger(exit.code)) ||
		!(exit.signal === null || typeof exit.signal === "string") ||
		!stoppedTarget ||
		typeof stoppedTarget.captureState !== "string" ||
		typeof descriptor.completeProjectionLeaseAvailable !== "boolean" ||
		!terminalExpectations ||
		!exactObjectKeys(terminalExpectations, ["supervisorExit", "wrapperTerminal", "serviceTerminal"]) ||
		!objectValue(descriptor.wrapperLoss) ||
		!serviceSeal ||
		typeof serviceSeal.terminalRelayDisposition !== "string"
	) {
		return false;
	}
	if (
		!exactObjectKeys(summary, [
			"schemaVersion",
			"finalizationId",
			"runId",
			"runToken",
			"classification",
			"causeLayer",
			"code",
			"signal",
			"state",
			"stoppedTargetCaptureComplete",
			"finalized",
			"supervisorExitAnchorWallTimeMs",
			"retentionAnchorWallTimeMs",
		]) ||
		summary.schemaVersion !== 1 ||
		summary.finalizationId !== manifest.finalizationId ||
		summary.runId !== manifest.runIdentity.runId ||
		summary.runToken !== manifest.runIdentity.runToken ||
		summary.classification !== classification.value ||
		summary.causeLayer !== classification.causeLayer ||
		summary.code !== exit.code ||
		summary.signal !== exit.signal ||
		summary.state !== manifest.state ||
		summary.stoppedTargetCaptureComplete !== (stoppedTarget.captureState === "complete") ||
		summary.supervisorExitAnchorWallTimeMs !== manifest.supervisorExitAnchorWallTimeMs ||
		summary.retentionAnchorWallTimeMs !== manifest.retentionAnchorWallTimeMs
	) {
		return false;
	}
	let expectedFinalized: string | null = null;
	try {
		expectedFinalized =
			manifest.retentionAnchorWallTimeMs === null
				? null
				: new Date(manifest.retentionAnchorWallTimeMs).toISOString();
	} catch {
		return false;
	}
	if (summary.finalized !== expectedFinalized) return false;
	try {
		const reconstructed: IncidentRecorderFinalizationInput = {
			incidentsDirectory: ".",
			incidentId: `run-${manifest.runIdentity.runId}`,
			runIdentity: manifest.runIdentity,
			runHistory: runHistory as unknown as IncidentRecorderRunHistoryResult,
			terminalExpectations:
				descriptor.terminalExpectations as IncidentRecorderFinalizationInput["terminalExpectations"],
			classification: classification as unknown as IncidentRecorderFinalizationInput["classification"],
			exit: exit as unknown as IncidentRecorderFinalizationInput["exit"],
			retentionAnchorWallTimeMs: manifest.retentionAnchorWallTimeMs ?? undefined,
			stoppedTarget: stoppedTarget as unknown as IncidentRecorderFinalizationInput["stoppedTarget"],
			wrapperLoss: descriptor.wrapperLoss as unknown as IncidentRecorderFinalizationInput["wrapperLoss"],
			serviceSeal: descriptor.serviceSeal as unknown as IncidentRecorderFinalizationInput["serviceSeal"],
			...(descriptor.completeProjectionLeaseAvailable
				? { assertProjectionLeaseUsable: () => {}, releaseProjectionLease: () => {} }
				: {}),
		};
		const analysis = analyzeIncidentRecorderFinalization(reconstructed);
		return (
			analysis.state === manifest.state &&
			analysis.finalizationId === manifest.finalizationId &&
			JSON.stringify(analysis.reasons) === JSON.stringify(manifest.reasons) &&
			analysis.supervisorExitAnchorWallTimeMs === manifest.supervisorExitAnchorWallTimeMs &&
			analysis.retentionAnchorWallTimeMs === manifest.retentionAnchorWallTimeMs
		);
	} catch {
		return false;
	}
}

function inspectManifestAuthority(
	fs: IncidentRecorderFinalizationFileSystem,
	incidentDirectory: string,
	manifestBytes: Buffer,
): IncidentRecorderPublishedFinalizationInspection {
	const manifest = parseManifest(manifestBytes);
	if (!manifest) return { state: "pending", reason: "finalization_manifest_invalid" };
	let listedTotal = 0;
	const names = new Set<string>();
	const listedBytes = new Map<string, Buffer>();
	let validatedConflict: FinalizationConflictRecord | undefined;
	for (const file of manifest.files) {
		if (names.has(file.name)) return { state: "pending", reason: "finalization_manifest_duplicate_file" };
		names.add(file.name);
		const bytes = readPrivatePublishedExact(fs, join(incidentDirectory, file.name));
		if (!bytes || bytes.length !== file.bytes || sha256(bytes) !== file.sha256) {
			return { state: "pending", reason: `finalization_file_mismatch:${file.name}` };
		}
		listedBytes.set(file.name, bytes);
		listedTotal += bytes.length;
	}
	if (manifest.kind === "incident_recorder_finalization_manifest") {
		if (listedTotal + manifestBytes.length > MAX_FINALIZATION_TOTAL_BYTES)
			return { state: "pending", reason: "finalization_total_bound_exceeded" };
		for (const required of STANDARD_FINALIZATION_FILE_NAMES) {
			if (!names.has(required))
				return { state: "pending", reason: `finalization_required_file_missing:${required}` };
		}
		if (!validateStandardFinalizationFiles(manifest, listedBytes)) {
			return { state: "pending", reason: "finalization_standard_semantics_invalid" };
		}
	} else {
		if (
			manifestBytes.length > MAX_FINALIZATION_CONFLICT_RECORD_BYTES ||
			manifest.conflictRecord.bytes > MAX_FINALIZATION_CONFLICT_RECORD_BYTES ||
			listedTotal - manifest.conflictRecord.bytes > MAX_FINALIZATION_TOTAL_BYTES
		) {
			return { state: "pending", reason: "finalization_conflict_bound_exceeded" };
		}
		validatedConflict = validateConflictFinalization(fs, incidentDirectory, manifest, listedBytes);
		if (!validatedConflict) {
			return { state: "pending", reason: "finalization_conflict_evidence_invalid" };
		}
	}
	const descriptorRecordName =
		manifest.kind === "incident_recorder_finalization_manifest"
			? "finalization-descriptor.json"
			: validatedConflict?.files.find((entry) => entry.logicalName === "finalization-descriptor.json")?.prepared
					.name;
	const descriptorBytes = descriptorRecordName ? listedBytes.get(descriptorRecordName) : undefined;
	const descriptor = descriptorBytes ? canonicalJsonObject(descriptorBytes) : undefined;
	const serviceSeal = descriptor ? objectValue(descriptor.serviceSeal) : undefined;
	if (!serviceSeal || typeof serviceSeal.terminalRelayDisposition !== "string") {
		return { state: "pending", reason: "finalization_descriptor_terminal_disposition_invalid" };
	}
	return {
		state: manifest.state,
		finalizationId: manifest.finalizationId,
		runId: manifest.runIdentity.runId,
		supervisorExitAnchorWallTimeMs: manifest.supervisorExitAnchorWallTimeMs,
		retentionAnchorWallTimeMs: manifest.retentionAnchorWallTimeMs,
		authorityDirectory: incidentDirectory,
		serviceTerminalRelayDisposition: serviceSeal.terminalRelayDisposition,
		manifest,
	};
}

function inspectPublishedIncidentFinalizationBound(
	input: {
		incidentsDirectory: string;
		incidentId: string;
	},
	fs: IncidentRecorderFinalizationFileSystem,
	set: PinnedIncidentDirectorySet,
): IncidentRecorderPublishedFinalizationInspection {
	if (!SAFE_INCIDENT_ID.test(input.incidentId) || input.incidentId === "." || input.incidentId === "..") {
		return { state: "pending", reason: "invalid_incident_id" };
	}
	if (set.memberState === "invalid") {
		return { state: "pending", reason: "finalization_incident_directory_invalid" };
	}
	const addressBinding = incidentAddressBinding(input.incidentId);
	const incidentDirectory = set.memberOperationPath;
	const privateAuthorityDirectory = join(incidentDirectory, FINALIZATION_PRIVATE_AUTHORITY_DIRECTORY_NAME);
	let privateAuthorityOccupant = false;
	try {
		fs.lstat(privateAuthorityDirectory, { bigint: true });
		privateAuthorityOccupant = true;
	} catch {}
	if (privateAuthorityOccupant && !privateDirectoryIsUsable(fs, privateAuthorityDirectory)) {
		return { state: "pending", reason: "finalization_private_authority_root_invalid" };
	}
	let authorityClaim: FinalizationAuthorityClaim | undefined;
	let authorityClaimOccupant = false;
	if (privateDirectoryIsUsable(fs, privateAuthorityDirectory)) {
		const claimPath = join(privateAuthorityDirectory, FINALIZATION_PRIVATE_AUTHORITY_CLAIM_NAME);
		try {
			fs.lstat(claimPath, { bigint: true });
			authorityClaimOccupant = true;
		} catch {}
		const claimBytes = readPrivatePublishedExact(fs, claimPath, MAX_FINALIZATION_CONFLICT_RECORD_BYTES);
		authorityClaim = claimBytes ? parseAuthorityClaim(claimBytes) : undefined;
	}
	if (authorityClaimOccupant && !authorityClaim) {
		return { state: "pending", reason: "finalization_authority_claim_invalid" };
	}
	if (
		authorityClaim &&
		addressBinding &&
		(authorityClaim.runIdentity.runId !== addressBinding.runId ||
			(addressBinding.finalizationId !== undefined &&
				authorityClaim.finalizationId !== addressBinding.finalizationId))
	) {
		return { state: "pending", reason: "finalization_authority_claim_incident_address_mismatch" };
	}
	const matchesIncidentAddress = (inspection: ProvenPublishedFinalization): boolean =>
		!addressBinding ||
		(inspection.runId === addressBinding.runId &&
			(addressBinding.finalizationId === undefined || inspection.finalizationId === addressBinding.finalizationId));
	const matchesClaim = (inspection: ProvenPublishedFinalization): boolean => {
		if (!authorityClaim) return true;
		if (
			inspection.finalizationId !== authorityClaim.finalizationId ||
			inspection.runId !== authorityClaim.runIdentity.runId ||
			inspection.manifest.runIdentity.runToken !== authorityClaim.runIdentity.runToken
		) {
			return false;
		}
		if (inspection.manifest.kind === "incident_recorder_finalization_manifest") {
			const bytes = jsonBytes(inspection.manifest);
			return (
				bytes.length === authorityClaim.preparedManifest.bytes &&
				sha256(bytes) === authorityClaim.preparedManifest.sha256
			);
		}
		const bytes = readPrivatePublishedExact(
			fs,
			join(inspection.authorityDirectory, inspection.manifest.conflictRecord.name),
		);
		if (
			!bytes ||
			!sameFileRecord(inspection.manifest.conflictRecord, fileRecord(inspection.manifest.conflictRecord.name, bytes))
		) {
			return false;
		}
		const conflict = parseConflictRecord(bytes);
		return (
			!!conflict &&
			conflict.intendedManifest.bytes === authorityClaim.preparedManifest.bytes &&
			conflict.intendedManifest.sha256 === authorityClaim.preparedManifest.sha256
		);
	};
	const manifestBytes = readPrivatePublishedExact(fs, join(incidentDirectory, "finalization-manifest.json"));
	let canonicalResult: IncidentRecorderPublishedFinalizationInspection = {
		state: "pending",
		reason: "finalization_manifest_missing_or_unreadable",
	};
	if (manifestBytes) {
		canonicalResult = inspectManifestAuthority(fs, incidentDirectory, manifestBytes);
	}
	let selectorOccupantObserved = false;
	for (const selectorName of FINALIZATION_AUTHORITY_FILE_NAMES) {
		const selectorPath = join(incidentDirectory, selectorName);
		try {
			fs.lstat(selectorPath, { bigint: true });
			selectorOccupantObserved = true;
		} catch {}
		const selectorBytes = readPrivatePublishedExact(fs, selectorPath, MAX_FINALIZATION_CONFLICT_RECORD_BYTES);
		if (!selectorBytes) continue;
		const selector = parseAuthoritySelector(selectorBytes);
		if (!selector) continue;
		const selectedManifestBytes = readPrivatePublishedExact(
			fs,
			join(incidentDirectory, selector.manifest.name),
			MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
		);
		if (
			!selectedManifestBytes ||
			!sameFileRecord(selector.manifest, fileRecord(selector.manifest.name, selectedManifestBytes))
		) {
			continue;
		}
		const selected = inspectManifestAuthority(fs, incidentDirectory, selectedManifestBytes);
		if (
			selected.state === "pending" ||
			selected.manifest.kind !== "incident_recorder_finalization_conflict_manifest" ||
			selected.finalizationId !== selector.finalizationId ||
			selected.runId !== selector.runIdentity.runId ||
			selected.manifest.runIdentity.runToken !== selector.runIdentity.runToken ||
			selected.state !== selector.state
		) {
			continue;
		}
		if (matchesIncidentAddress(selected) && matchesClaim(selected)) return selected;
	}
	if (privateDirectoryIsUsable(fs, privateAuthorityDirectory)) {
		const privateSelectorPath = join(privateAuthorityDirectory, FINALIZATION_PRIVATE_AUTHORITY_SELECTOR_NAME);
		let privateSelectorOccupant = false;
		try {
			fs.lstat(privateSelectorPath, { bigint: true });
			privateSelectorOccupant = true;
		} catch {}
		const selectorBytes = readPrivatePublishedExact(fs, privateSelectorPath, MAX_FINALIZATION_CONFLICT_RECORD_BYTES);
		const selector = selectorBytes ? parseAuthoritySelector(selectorBytes) : undefined;
		if (privateSelectorOccupant && !selector) {
			return { state: "pending", reason: "finalization_private_authority_selector_invalid" };
		}
		if (selector) {
			const selectedManifestBytes = readPrivatePublishedExact(
				fs,
				join(privateAuthorityDirectory, selector.manifest.name),
				MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
			);
			if (
				selectedManifestBytes &&
				sameFileRecord(selector.manifest, fileRecord(selector.manifest.name, selectedManifestBytes))
			) {
				const selected = inspectManifestAuthority(fs, privateAuthorityDirectory, selectedManifestBytes);
				if (
					selected.state !== "pending" &&
					selected.manifest.kind === "incident_recorder_finalization_conflict_manifest" &&
					selected.finalizationId === selector.finalizationId &&
					selected.runId === selector.runIdentity.runId &&
					selected.manifest.runIdentity.runToken === selector.runIdentity.runToken &&
					selected.state === selector.state
				) {
					if (matchesIncidentAddress(selected) && matchesClaim(selected)) return selected;
				}
			}
			return { state: "pending", reason: "finalization_private_authority_target_invalid" };
		}
	}
	if (
		canonicalResult.state !== "pending" &&
		matchesIncidentAddress(canonicalResult) &&
		matchesClaim(canonicalResult)
	) {
		return canonicalResult;
	}
	if (canonicalResult.state !== "pending" && !matchesIncidentAddress(canonicalResult)) {
		return { state: "pending", reason: "finalization_incident_address_mismatch" };
	}
	if (canonicalResult.state !== "pending" && authorityClaim) {
		return { state: "pending", reason: "finalization_authority_claim_terminal_mismatch" };
	}
	if (authorityClaim) return { state: "pending", reason: "finalization_authority_claim_pending" };
	return selectorOccupantObserved
		? { state: "pending", reason: "finalization_authority_slots_have_no_valid_selector" }
		: canonicalResult;
}

export function inspectPublishedIncidentFinalization(
	input: {
		incidentsDirectory: string;
		incidentId: string;
	},
	options: IncidentRecorderFinalizerOptions = {},
): IncidentRecorderPublishedFinalizationInspection {
	if (!SAFE_INCIDENT_ID.test(input.incidentId) || input.incidentId === "." || input.incidentId === "..") {
		return { state: "pending", reason: "invalid_incident_id" };
	}
	const fs = combinedFileSystem(options);
	const set = pinFinalizationIncidentDirectorySet(fs, input.incidentsDirectory, input.incidentId);
	if (!set) {
		return { state: "pending", reason: "finalization_incidents_directory_invalid" };
	}
	try {
		validatePinnedFinalizationDirectorySet(fs, set);
		const inspection = inspectPublishedIncidentFinalizationBound(input, fs, set);
		validatePinnedFinalizationDirectorySet(fs, set);
		return exposePinnedInspectionDirectory(inspection, set);
	} catch (error) {
		if (error instanceof FinalizationDirectoryBindingError) {
			return { state: "pending", reason: error.reason };
		}
		return { state: "pending", reason: "finalization_inspection_ambiguous" };
	} finally {
		closePinnedFinalizationDirectory(fs, set.member);
		closePinnedFinalizationDirectory(fs, set.parent);
	}
}

function parseRetentionAuthority(bytes: Buffer): IncidentRecorderRetentionAuthority | undefined {
	try {
		const value = JSON.parse(bytes.toString("utf8")) as Partial<IncidentRecorderRetentionAuthority>;
		if (
			!exactObjectKeys(value, [
				"schemaVersion",
				"kind",
				"finalizationId",
				"runId",
				"outcome",
				"retentionAnchorWallTimeMs",
			]) ||
			value.schemaVersion !== 1 ||
			value.kind !== "incident_retention_authority" ||
			!value.finalizationId ||
			!SHA256.test(value.finalizationId) ||
			!value.runId ||
			!CANONICAL_UUID.test(value.runId) ||
			!["complete", "incomplete", "corrupt"].includes(String(value.outcome)) ||
			!Number.isSafeInteger(value.retentionAnchorWallTimeMs) ||
			Number(value.retentionAnchorWallTimeMs) < 0 ||
			!jsonBytes(value).equals(bytes)
		) {
			return undefined;
		}
		return value as IncidentRecorderRetentionAuthority;
	} catch {
		return undefined;
	}
}

function retentionAuthorityMatchesPublished(
	authority: IncidentRecorderRetentionAuthority,
	published: Exclude<IncidentRecorderPublishedFinalizationInspection, { state: "pending" }>,
): boolean {
	return (
		authority.finalizationId === published.finalizationId &&
		authority.runId === published.runId &&
		authority.outcome === published.state &&
		authority.retentionAnchorWallTimeMs === published.retentionAnchorWallTimeMs
	);
}

function retentionClassForAuthority(authority: IncidentRecorderRetentionAuthority): IncidentRecorderRetentionClass {
	return authority.outcome === "corrupt" ? "corrupt" : "diagnostic";
}

function retentionAuthorityConflictReason(
	bytes: Buffer,
	intended: IncidentRecorderRetentionAuthority,
): Exclude<RetentionAuthorityConflictReason, "retention_authority_identity_invalid"> | undefined {
	try {
		JSON.parse(bytes.toString("utf8"));
	} catch {
		return "retention_authority_invalid_json";
	}
	const authority = parseRetentionAuthority(bytes);
	if (!authority) return "retention_authority_schema_invalid";
	return jsonBytes(intended).equals(bytes) ? undefined : "retention_authority_finalization_mismatch";
}

function retentionObservedIdentity(stat: BigIntStats): RetentionAuthorityObservedIdentity {
	return {
		fileType: stat.isSymbolicLink() ? "symlink" : stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "other",
		dev: stat.dev.toString(),
		ino: stat.ino.toString(),
		size: stat.size.toString(),
		mode: (stat.mode & 0o7777n).toString(8).padStart(4, "0"),
		nlink: stat.nlink.toString(),
		uid: stat.uid.toString(),
		mtimeNs: stat.mtimeNs.toString(),
		ctimeNs: stat.ctimeNs.toString(),
		errno: null,
	};
}

function validRetentionObservedIdentity(value: unknown): value is RetentionAuthorityObservedIdentity {
	if (!value || typeof value !== "object") return false;
	const identity = value as Partial<RetentionAuthorityObservedIdentity>;
	return (
		["directory", "file", "other", "symlink"].includes(String(identity.fileType)) &&
		[identity.dev, identity.ino, identity.size, identity.nlink, identity.uid].every(
			(field) => typeof field === "string" && /^(?:0|[1-9][0-9]{0,39})$/.test(field),
		) &&
		[identity.mtimeNs, identity.ctimeNs].every(
			(field) => typeof field === "string" && /^(?:0|-?[1-9][0-9]{0,39})$/.test(field),
		) &&
		typeof identity.mode === "string" &&
		/^[0-7]{4}$/.test(identity.mode) &&
		identity.errno === null
	);
}

function expectedRetentionIdentityDisposition(
	identity: RetentionAuthorityObservedIdentity,
): Exclude<RetentionAuthorityObservedPrimary["disposition"], "exact_private_bytes"> | undefined {
	if (identity.fileType === "symlink") return "symlink";
	if (identity.fileType === "directory") return "directory";
	if (identity.fileType !== "file") return "non_regular";
	let size: bigint;
	let links: bigint;
	let owner: bigint;
	try {
		size = BigInt(identity.size);
		links = BigInt(identity.nlink);
		owner = BigInt(identity.uid);
	} catch {
		return undefined;
	}
	if (links !== 1n) return "hardlinked_file";
	if (size > BigInt(MAX_RETENTION_AUTHORITY_BYTES)) return "oversized_file";
	if (typeof process.getuid === "function" && owner !== BigInt(process.getuid())) return "owner_mismatch";
	if ((Number.parseInt(identity.mode, 8) & 0o077) !== 0) return "non_private_file";
	return undefined;
}

function validRetentionObservedPrimary(value: unknown): value is RetentionAuthorityObservedPrimary {
	if (!value || typeof value !== "object") return false;
	const observed = value as { disposition?: unknown };
	const identityKeys = ["fileType", "dev", "ino", "size", "mode", "nlink", "uid", "mtimeNs", "ctimeNs", "errno"];
	if (observed.disposition === "exact_private_bytes") {
		if (
			!exactObjectKeys(value, ["disposition", "bytes", "sha256", "bytesBase64", ...identityKeys]) ||
			!validRetentionObservedIdentity(value)
		) {
			return false;
		}
		const exact = value as RetentionAuthorityObservedIdentity & {
			disposition: "exact_private_bytes";
			bytes: unknown;
			sha256: unknown;
			bytesBase64: unknown;
		};
		if (
			exact.fileType !== "file" ||
			exact.nlink !== "1" ||
			(Number.parseInt(exact.mode, 8) & 0o077) !== 0 ||
			(typeof process.getuid === "function" && exact.uid !== String(process.getuid())) ||
			typeof exact.bytes !== "number" ||
			!Number.isSafeInteger(exact.bytes) ||
			exact.bytes < 0 ||
			exact.bytes > MAX_RETENTION_AUTHORITY_BYTES ||
			String(exact.bytes) !== exact.size ||
			typeof exact.sha256 !== "string" ||
			!SHA256.test(exact.sha256) ||
			typeof exact.bytesBase64 !== "string"
		) {
			return false;
		}
		const bytes = Buffer.from(exact.bytesBase64, "base64");
		return (
			bytes.length === exact.bytes &&
			bytes.toString("base64") === exact.bytesBase64 &&
			sha256(bytes) === exact.sha256
		);
	}
	if (
		![
			"directory",
			"hardlinked_file",
			"non_private_file",
			"non_regular",
			"owner_mismatch",
			"oversized_file",
			"symlink",
		].includes(String(observed.disposition)) ||
		!exactObjectKeys(value, ["disposition", ...identityKeys]) ||
		!validRetentionObservedIdentity(value)
	) {
		return false;
	}
	return expectedRetentionIdentityDisposition(value) === observed.disposition;
}

function observeRetentionAuthorityPrimary(
	fs: IncidentRecorderFinalizationFileSystem,
	path: string,
	intended: IncidentRecorderRetentionAuthority,
):
	| { state: "observed"; observed: RetentionAuthorityObservedPrimary; reason: RetentionAuthorityConflictReason }
	| { state: "pending"; reason: string } {
	let initial: BigIntStats;
	try {
		initial = fs.lstat(path, { bigint: true });
	} catch {
		return { state: "pending", reason: "retention_authority_observation_unstable" };
	}
	const identity = retentionObservedIdentity(initial);
	const disposition = expectedRetentionIdentityDisposition(identity);
	if (disposition) {
		return {
			state: "observed",
			observed: { disposition, ...identity },
			reason: "retention_authority_identity_invalid",
		};
	}
	let observedStat: BigIntStats | undefined;
	const bytes = readDescriptorBoundedExact(
		fs,
		path,
		MAX_RETENTION_AUTHORITY_BYTES,
		(stat) => privateRegularFile(stat, MAX_RETENTION_AUTHORITY_BYTES, [1n]),
		(_bytes, stat) => {
			observedStat = stat;
			return true;
		},
	);
	if (!bytes || !observedStat) {
		return { state: "pending", reason: "retention_authority_observation_unstable" };
	}
	const reason = retentionAuthorityConflictReason(bytes, intended);
	if (!reason) return { state: "pending", reason: "retention_authority_primary_became_intended" };
	return {
		state: "observed",
		observed: {
			disposition: "exact_private_bytes",
			...retentionObservedIdentity(observedStat),
			bytes: bytes.length,
			sha256: sha256(bytes),
			bytesBase64: bytes.toString("base64"),
		},
		reason,
	};
}

function strictRetentionFileRecord(value: unknown, name: string, maximum: number): value is FinalizationFileRecord {
	return strictFileRecord(value) && value.name === name && value.bytes <= maximum;
}

function parseRetentionAuthorityConflictRecord(bytes: Buffer): RetentionAuthorityConflictRecord | undefined {
	try {
		const value = JSON.parse(bytes.toString("utf8")) as Partial<RetentionAuthorityConflictRecord>;
		if (
			!exactObjectKeys(value, [
				"schemaVersion",
				"kind",
				"finalizationId",
				"runId",
				"outcome",
				"retentionAnchorWallTimeMs",
				"primaryName",
				"reason",
				"intendedAuthority",
				"observedPrimary",
			]) ||
			value.schemaVersion !== 1 ||
			value.kind !== "incident_retention_authority_conflict" ||
			!value.finalizationId ||
			!SHA256.test(value.finalizationId) ||
			!value.runId ||
			!CANONICAL_UUID.test(value.runId) ||
			!["complete", "incomplete", "corrupt"].includes(String(value.outcome)) ||
			!Number.isSafeInteger(value.retentionAnchorWallTimeMs) ||
			Number(value.retentionAnchorWallTimeMs) < 0 ||
			value.primaryName !== "retention-authority.json" ||
			![
				"retention_authority_finalization_mismatch",
				"retention_authority_identity_invalid",
				"retention_authority_invalid_json",
				"retention_authority_schema_invalid",
			].includes(String(value.reason)) ||
			!strictRetentionFileRecord(
				value.intendedAuthority,
				RETENTION_AUTHORITY_INTENDED_NAME,
				MAX_RETENTION_AUTHORITY_BYTES,
			) ||
			!validRetentionObservedPrimary(value.observedPrimary) ||
			!jsonBytes(value).equals(bytes)
		) {
			return undefined;
		}
		return value as RetentionAuthorityConflictRecord;
	} catch {
		return undefined;
	}
}

function parseRetentionAuthorityConflictManifest(bytes: Buffer): RetentionAuthorityConflictManifest | undefined {
	try {
		const value = JSON.parse(bytes.toString("utf8")) as Partial<RetentionAuthorityConflictManifest>;
		if (
			!exactObjectKeys(value, [
				"schemaVersion",
				"kind",
				"finalizationId",
				"runId",
				"outcome",
				"retentionAnchorWallTimeMs",
				"retentionClass",
				"authority",
				"conflict",
			]) ||
			value.schemaVersion !== 1 ||
			value.kind !== "incident_retention_authority_conflict_manifest" ||
			!value.finalizationId ||
			!SHA256.test(value.finalizationId) ||
			!value.runId ||
			!CANONICAL_UUID.test(value.runId) ||
			!["complete", "incomplete", "corrupt"].includes(String(value.outcome)) ||
			!Number.isSafeInteger(value.retentionAnchorWallTimeMs) ||
			Number(value.retentionAnchorWallTimeMs) < 0 ||
			value.retentionClass !== "corrupt" ||
			!strictRetentionFileRecord(
				value.authority,
				RETENTION_AUTHORITY_INTENDED_NAME,
				MAX_RETENTION_AUTHORITY_BYTES,
			) ||
			!strictRetentionFileRecord(
				value.conflict,
				RETENTION_AUTHORITY_CONFLICT_NAME,
				MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
			) ||
			!jsonBytes(value).equals(bytes)
		) {
			return undefined;
		}
		return value as RetentionAuthorityConflictManifest;
	} catch {
		return undefined;
	}
}

function validateRetentionAuthorityConflictRecord(
	bytes: Buffer,
	intendedBytes: Buffer,
	intended: IncidentRecorderRetentionAuthority,
): RetentionAuthorityConflictRecord | undefined {
	const conflict = parseRetentionAuthorityConflictRecord(bytes);
	if (
		!conflict ||
		conflict.finalizationId !== intended.finalizationId ||
		conflict.runId !== intended.runId ||
		conflict.outcome !== intended.outcome ||
		conflict.retentionAnchorWallTimeMs !== intended.retentionAnchorWallTimeMs ||
		!sameFileRecord(conflict.intendedAuthority, fileRecord(RETENTION_AUTHORITY_INTENDED_NAME, intendedBytes))
	) {
		return undefined;
	}
	if (conflict.observedPrimary.disposition === "exact_private_bytes") {
		const observedBytes = Buffer.from(conflict.observedPrimary.bytesBase64, "base64");
		if (retentionAuthorityConflictReason(observedBytes, intended) !== conflict.reason) return undefined;
	} else if (conflict.reason !== "retention_authority_identity_invalid") {
		return undefined;
	}
	return conflict;
}

function pathOccupantState(
	fs: IncidentRecorderFinalizationFileSystem,
	path: string,
): "absent" | "present" | "unreadable" {
	try {
		fs.lstat(path, { bigint: true });
		return "present";
	} catch (error) {
		return errno(error) === "ENOENT" ? "absent" : "unreadable";
	}
}

function inspectConflictRetentionAuthority(
	fs: IncidentRecorderFinalizationFileSystem,
	authorityDirectory: string,
	manifestBytes: Buffer,
	published: Exclude<IncidentRecorderPublishedFinalizationInspection, { state: "pending" }>,
): IncidentRecorderRetentionAuthorityInspection {
	const manifest = parseRetentionAuthorityConflictManifest(manifestBytes);
	if (!manifest) return { state: "invalid", reason: "retention_authority_manifest_invalid" };
	if (
		manifest.finalizationId !== published.finalizationId ||
		manifest.runId !== published.runId ||
		manifest.outcome !== published.state ||
		manifest.retentionAnchorWallTimeMs !== published.retentionAnchorWallTimeMs
	) {
		return { state: "invalid", reason: "retention_authority_manifest_finalization_mismatch" };
	}
	const intendedBytes = readPrivateSingleLinkExact(
		fs,
		join(authorityDirectory, RETENTION_AUTHORITY_INTENDED_NAME),
		MAX_RETENTION_AUTHORITY_BYTES,
		false,
	);
	if (
		!intendedBytes ||
		!sameFileRecord(manifest.authority, fileRecord(RETENTION_AUTHORITY_INTENDED_NAME, intendedBytes))
	) {
		return { state: "invalid", reason: "retention_authority_intended_invalid" };
	}
	const authority = parseRetentionAuthority(intendedBytes);
	if (!authority || !retentionAuthorityMatchesPublished(authority, published)) {
		return { state: "invalid", reason: "retention_authority_intended_finalization_mismatch" };
	}
	const conflictBytes = readPrivateSingleLinkExact(
		fs,
		join(authorityDirectory, RETENTION_AUTHORITY_CONFLICT_NAME),
		MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
		false,
	);
	if (
		!conflictBytes ||
		!sameFileRecord(manifest.conflict, fileRecord(RETENTION_AUTHORITY_CONFLICT_NAME, conflictBytes)) ||
		!validateRetentionAuthorityConflictRecord(conflictBytes, intendedBytes, authority)
	) {
		return { state: "invalid", reason: "retention_authority_conflict_evidence_invalid" };
	}
	return {
		state: "authorized",
		...authority,
		authoritySource: "conflict",
		retentionClass: "corrupt",
	};
}

function inspectIncidentRetentionAuthorityBound(
	_input: { incidentsDirectory: string; incidentId: string },
	fs: IncidentRecorderFinalizationFileSystem,
	set: PinnedIncidentDirectorySet,
	published: Exclude<IncidentRecorderPublishedFinalizationInspection, { state: "pending" }>,
): IncidentRecorderRetentionAuthorityInspection {
	if (set.memberState !== "present" || !set.member) {
		return { state: "invalid", reason: "published_finalization_unconfirmed:finalization_incident_directory_invalid" };
	}
	const incidentDirectory = set.member.operationPath;
	const authorityDirectory = join(incidentDirectory, FINALIZATION_PRIVATE_AUTHORITY_DIRECTORY_NAME);
	const authorityDirectoryState = pathOccupantState(fs, authorityDirectory);
	let intendedControlState: "absent" | "present" | "unreadable" = "absent";
	if (authorityDirectoryState === "unreadable") {
		return { state: "invalid", reason: "retention_authority_private_root_unreadable" };
	}
	if (authorityDirectoryState === "present") {
		if (!privateDirectoryIsUsable(fs, authorityDirectory)) {
			return { state: "invalid", reason: "retention_authority_private_root_invalid" };
		}
		const manifestPath = join(authorityDirectory, RETENTION_AUTHORITY_MANIFEST_NAME);
		const manifestState = pathOccupantState(fs, manifestPath);
		if (manifestState === "unreadable") {
			return { state: "invalid", reason: "retention_authority_manifest_unreadable" };
		}
		if (manifestState === "present") {
			const manifestBytes = readPrivateSingleLinkExact(
				fs,
				manifestPath,
				MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
				false,
			);
			return manifestBytes
				? inspectConflictRetentionAuthority(fs, authorityDirectory, manifestBytes, published)
				: { state: "invalid", reason: "retention_authority_manifest_identity_invalid" };
		}
		const conflictState = pathOccupantState(fs, join(authorityDirectory, RETENTION_AUTHORITY_CONFLICT_NAME));
		if (conflictState !== "absent") {
			return {
				state: "invalid",
				reason:
					conflictState === "present"
						? "retention_authority_conflict_resolution_pending"
						: "retention_authority_conflict_control_unreadable",
			};
		}
		intendedControlState = pathOccupantState(fs, join(authorityDirectory, RETENTION_AUTHORITY_INTENDED_NAME));
		if (intendedControlState === "unreadable") {
			return { state: "invalid", reason: "retention_authority_intended_unreadable" };
		}
	}
	const authorityPath = join(incidentDirectory, "retention-authority.json");
	const bytes = readPrivateSingleLinkExact(fs, authorityPath, MAX_RETENTION_AUTHORITY_BYTES, false);
	if (!bytes) {
		try {
			const observed = fs.lstat(authorityPath, { bigint: true });
			return privateRegularFile(observed, MAX_RETENTION_AUTHORITY_BYTES, [1n]) && observed.size > 0n
				? { state: "invalid", reason: "retention_authority_unreadable" }
				: { state: "invalid", reason: "retention_authority_identity_invalid" };
		} catch (error) {
			return errno(error) === "ENOENT"
				? { state: "absent", reason: "retention_authority_missing" }
				: { state: "invalid", reason: "retention_authority_unreadable" };
		}
	}
	let parsedJson = true;
	try {
		JSON.parse(bytes.toString("utf8"));
	} catch {
		parsedJson = false;
	}
	const authority = parseRetentionAuthority(bytes);
	if (!authority) {
		return {
			state: "invalid",
			reason: parsedJson ? "retention_authority_schema_invalid" : "retention_authority_invalid_json",
		};
	}
	if (!retentionAuthorityMatchesPublished(authority, published)) {
		return { state: "invalid", reason: "retention_authority_finalization_mismatch" };
	}
	if (intendedControlState === "present") {
		const intendedBytes = readPrivateSingleLinkExact(
			fs,
			join(authorityDirectory, RETENTION_AUTHORITY_INTENDED_NAME),
			MAX_RETENTION_AUTHORITY_BYTES,
			false,
		);
		if (!intendedBytes?.equals(bytes)) {
			return { state: "invalid", reason: "retention_authority_intended_control_conflict" };
		}
	}
	return {
		state: "authorized",
		...authority,
		authoritySource: "primary",
		retentionClass: retentionClassForAuthority(authority),
	};
}

export function inspectIncidentRetentionAuthority(
	input: { incidentsDirectory: string; incidentId: string },
	options: IncidentRecorderFinalizerOptions = {},
): IncidentRecorderRetentionAuthorityInspection {
	if (!SAFE_INCIDENT_ID.test(input.incidentId) || input.incidentId === "." || input.incidentId === "..") {
		return { state: "invalid", reason: "invalid_incident_id" };
	}
	const fs = combinedFileSystem(options);
	const set = pinFinalizationIncidentDirectorySet(fs, input.incidentsDirectory, input.incidentId);
	if (!set) {
		return {
			state: "invalid",
			reason: "published_finalization_unconfirmed:finalization_incidents_directory_invalid",
		};
	}
	try {
		validatePinnedFinalizationDirectorySet(fs, set);
		const published = inspectPublishedIncidentFinalizationBound(input, fs, set);
		if (published.state === "pending") {
			return {
				state: "invalid",
				reason: `published_finalization_unconfirmed:${published.reason}`,
			};
		}
		const inspection = inspectIncidentRetentionAuthorityBound(input, fs, set, published);
		validatePinnedFinalizationDirectorySet(fs, set);
		return inspection;
	} catch (error) {
		if (error instanceof FinalizationDirectoryBindingError) {
			return { state: "invalid", reason: `published_finalization_unconfirmed:${error.reason}` };
		}
		return { state: "invalid", reason: "retention_authority_inspection_ambiguous" };
	} finally {
		closePinnedFinalizationDirectory(fs, set.member);
		closePinnedFinalizationDirectory(fs, set.parent);
	}
}

function ensureDirectory(fs: IncidentRecorderFinalizationFileSystem, path: string): void {
	try {
		fs.mkdir(path, { recursive: false, mode: 0o700 });
	} catch (error) {
		if (errno(error) !== "EEXIST") throw error;
		const stat = fs.lstat(path, { bigint: true });
		if (!stat.isDirectory() || stat.isSymbolicLink()) throw error;
	}
}

function privateDirectoryIsUsable(fs: IncidentRecorderFinalizationFileSystem, path: string): boolean {
	try {
		const stat = fs.lstat(path, { bigint: true });
		return (
			stat.isDirectory() &&
			!stat.isSymbolicLink() &&
			(typeof process.getuid !== "function" || stat.uid === BigInt(process.getuid())) &&
			(stat.mode & 0o077n) === 0n
		);
	} catch {
		return false;
	}
}

function ensurePrivateAuthorityDirectory(
	fs: IncidentRecorderFinalizationFileSystem,
	incidentDirectory: string,
): string {
	const path = join(incidentDirectory, FINALIZATION_PRIVATE_AUTHORITY_DIRECTORY_NAME);
	ensureDirectory(fs, path);
	if (!privateDirectoryIsUsable(fs, path)) {
		throw new Error("Incident finalization private authority root is not a private directory");
	}
	fsyncDirectory(fs, path);
	fsyncDirectory(fs, incidentDirectory);
	return path;
}

function retentionAuthorityConflictManifestBytes(
	authority: IncidentRecorderRetentionAuthority,
	intendedBytes: Buffer,
	conflictBytes: Buffer,
): Buffer {
	const manifest: RetentionAuthorityConflictManifest = {
		schemaVersion: 1,
		kind: "incident_retention_authority_conflict_manifest",
		finalizationId: authority.finalizationId,
		runId: authority.runId,
		outcome: authority.outcome,
		retentionAnchorWallTimeMs: authority.retentionAnchorWallTimeMs,
		retentionClass: "corrupt",
		authority: fileRecord(RETENTION_AUTHORITY_INTENDED_NAME, intendedBytes),
		conflict: fileRecord(RETENTION_AUTHORITY_CONFLICT_NAME, conflictBytes),
	};
	return jsonBytes(manifest);
}

export function persistIncidentRetentionAuthority(
	input: {
		incidentDirectory: string;
		finalizationId: string;
		runId: string;
		outcome: "complete" | "incomplete" | "corrupt";
		retentionAnchorWallTimeMs: number;
	},
	options: IncidentRecorderRetentionAuthorityPersistenceOptions = {},
): IncidentRecorderRetentionAuthorityPersistenceResult {
	const incidentId = basename(input.incidentDirectory);
	const incidentsDirectory = dirname(input.incidentDirectory);
	if (
		!SAFE_INCIDENT_ID.test(incidentId) ||
		incidentId === "." ||
		incidentId === ".." ||
		!SHA256.test(input.finalizationId) ||
		!CANONICAL_UUID.test(input.runId) ||
		!["complete", "incomplete", "corrupt"].includes(input.outcome) ||
		!Number.isSafeInteger(input.retentionAnchorWallTimeMs) ||
		input.retentionAnchorWallTimeMs < 0
	) {
		return { state: "pending", reason: "retention_authority_persistence_input_invalid" };
	}
	const fs = combinedFileSystem(options);
	const set = pinFinalizationIncidentDirectorySet(fs, incidentsDirectory, incidentId);
	if (!set || set.memberState !== "present" || !set.member) {
		if (set) {
			closePinnedFinalizationDirectory(fs, set.member);
			closePinnedFinalizationDirectory(fs, set.parent);
		}
		return { state: "pending", reason: "retention_authority_incident_directory_invalid" };
	}
	const operationIncidentDirectory = set.member.operationPath;
	const operationIncidentsDirectory = set.parent.operationPath;
	const fault = (boundary: IncidentRecorderRetentionAuthorityFaultBoundary): void => {
		validatePinnedFinalizationDirectorySet(fs, set);
		options.onRetentionAuthorityFaultBoundary?.(boundary);
		validatePinnedFinalizationDirectorySet(fs, set);
	};
	const authority: IncidentRecorderRetentionAuthority = {
		schemaVersion: 1,
		kind: "incident_retention_authority",
		finalizationId: input.finalizationId,
		runId: input.runId,
		outcome: input.outcome,
		retentionAnchorWallTimeMs: input.retentionAnchorWallTimeMs,
	};
	const intendedBytes = jsonBytes(authority);
	try {
		validatePinnedFinalizationDirectorySet(fs, set);
		const published = inspectPublishedIncidentFinalizationBound({ incidentsDirectory, incidentId }, fs, set);
		if (published.state === "pending") {
			return {
				state: "pending",
				reason: `retention_authority_published_finalization_unconfirmed:${published.reason}`,
			};
		}
		if (!retentionAuthorityMatchesPublished(authority, published)) {
			return { state: "pending", reason: "retention_authority_persistence_finalization_mismatch" };
		}

		const authorityDirectory = join(operationIncidentDirectory, FINALIZATION_PRIVATE_AUTHORITY_DIRECTORY_NAME);
		const authorityDirectoryState = pathOccupantState(fs, authorityDirectory);
		if (authorityDirectoryState === "unreadable") {
			return { state: "pending", reason: "retention_authority_private_root_unreadable" };
		}
		let intendedControlBytes: Buffer | undefined;
		let conflictControlBytes: Buffer | undefined;
		let manifestControlBytes: Buffer | undefined;
		if (authorityDirectoryState === "present") {
			if (!privateDirectoryIsUsable(fs, authorityDirectory)) {
				return { state: "pending", reason: "retention_authority_private_root_invalid" };
			}
			const intendedPath = join(authorityDirectory, RETENTION_AUTHORITY_INTENDED_NAME);
			const conflictPath = join(authorityDirectory, RETENTION_AUTHORITY_CONFLICT_NAME);
			const manifestPath = join(authorityDirectory, RETENTION_AUTHORITY_MANIFEST_NAME);
			const intendedState = pathOccupantState(fs, intendedPath);
			const conflictState = pathOccupantState(fs, conflictPath);
			const manifestState = pathOccupantState(fs, manifestPath);
			if ([intendedState, conflictState, manifestState].includes("unreadable")) {
				return { state: "pending", reason: "retention_authority_control_unreadable" };
			}
			if (intendedState === "present") {
				intendedControlBytes = readPrivatePublishedExact(fs, intendedPath, MAX_RETENTION_AUTHORITY_BYTES);
				if (!intendedControlBytes?.equals(intendedBytes)) {
					return { state: "pending", reason: "retention_authority_intended_control_conflict" };
				}
			}
			if (conflictState === "present") {
				conflictControlBytes = readPrivatePublishedExact(fs, conflictPath, MAX_FINALIZATION_CONFLICT_RECORD_BYTES);
				if (
					!conflictControlBytes ||
					!validateRetentionAuthorityConflictRecord(conflictControlBytes, intendedBytes, authority)
				) {
					return { state: "pending", reason: "retention_authority_conflict_control_conflict" };
				}
			}
			if (manifestState === "present") {
				manifestControlBytes = readPrivatePublishedExact(fs, manifestPath, MAX_FINALIZATION_CONFLICT_RECORD_BYTES);
				if (!conflictControlBytes || !intendedControlBytes || !manifestControlBytes) {
					return { state: "pending", reason: "retention_authority_manifest_control_conflict" };
				}
				const expectedManifestBytes = retentionAuthorityConflictManifestBytes(
					authority,
					intendedControlBytes,
					conflictControlBytes,
				);
				if (!manifestControlBytes.equals(expectedManifestBytes)) {
					return { state: "pending", reason: "retention_authority_manifest_control_conflict" };
				}
			}
		}
		if (intendedControlBytes) {
			const normalized = publishImmutableFile(
				fs,
				authorityDirectory,
				RETENTION_AUTHORITY_INTENDED_NAME,
				intendedControlBytes,
			);
			if (normalized === "conflict") {
				return { state: "pending", reason: "retention_authority_intended_control_conflict" };
			}
		}
		if (conflictControlBytes) {
			const normalized = publishImmutableFile(
				fs,
				authorityDirectory,
				RETENTION_AUTHORITY_CONFLICT_NAME,
				conflictControlBytes,
			);
			if (normalized === "conflict") {
				return { state: "pending", reason: "retention_authority_conflict_control_conflict" };
			}
		}

		let primaryPublication: ImmutableWriteResult | undefined;
		if (!conflictControlBytes) {
			primaryPublication = publishImmutableFile(
				fs,
				operationIncidentDirectory,
				"retention-authority.json",
				intendedBytes,
			);
			if (primaryPublication !== "conflict") {
				fsyncDirectory(fs, operationIncidentDirectory);
				fsyncDirectory(fs, operationIncidentsDirectory);
				const readbackPublished = inspectPublishedIncidentFinalizationBound(
					{ incidentsDirectory, incidentId },
					fs,
					set,
				);
				if (readbackPublished.state === "pending") {
					return {
						state: "pending",
						reason: `retention_authority_published_finalization_unconfirmed:${readbackPublished.reason}`,
					};
				}
				const readback = inspectIncidentRetentionAuthorityBound(
					{ incidentsDirectory, incidentId },
					fs,
					set,
					readbackPublished,
				);
				if (
					readback.state !== "authorized" ||
					readback.authoritySource !== "primary" ||
					!retentionAuthorityMatchesPublished(readback, published)
				) {
					return { state: "pending", reason: "retention_authority_primary_readback_unconfirmed" };
				}
				validatePinnedFinalizationDirectorySet(fs, set);
				return { ...readback, publication: primaryPublication };
			}
		}

		const privateAuthorityDirectory = ensurePrivateAuthorityDirectory(fs, operationIncidentDirectory);
		if (!intendedControlBytes) {
			const intendedPublication = publishImmutableFile(
				fs,
				privateAuthorityDirectory,
				RETENTION_AUTHORITY_INTENDED_NAME,
				intendedBytes,
				{
					afterLink: () => fault("after_retention_intended_authority_link_before_directory_fsync"),
				},
			);
			if (intendedPublication === "conflict") {
				return { state: "pending", reason: "retention_authority_intended_control_conflict" };
			}
			intendedControlBytes = intendedBytes;
		}
		fault("after_retention_intended_authority_durable");

		if (!conflictControlBytes) {
			const observation = observeRetentionAuthorityPrimary(
				fs,
				join(operationIncidentDirectory, "retention-authority.json"),
				authority,
			);
			if (observation.state === "pending") return observation;
			const conflict: RetentionAuthorityConflictRecord = {
				schemaVersion: 1,
				kind: "incident_retention_authority_conflict",
				finalizationId: authority.finalizationId,
				runId: authority.runId,
				outcome: authority.outcome,
				retentionAnchorWallTimeMs: authority.retentionAnchorWallTimeMs,
				primaryName: "retention-authority.json",
				reason: observation.reason,
				intendedAuthority: fileRecord(RETENTION_AUTHORITY_INTENDED_NAME, intendedBytes),
				observedPrimary: observation.observed,
			};
			conflictControlBytes = jsonBytes(conflict);
			if (conflictControlBytes.length > MAX_FINALIZATION_CONFLICT_RECORD_BYTES) {
				return { state: "pending", reason: "retention_authority_conflict_evidence_bound_exceeded" };
			}
			const conflictPublication = publishImmutableFile(
				fs,
				privateAuthorityDirectory,
				RETENTION_AUTHORITY_CONFLICT_NAME,
				conflictControlBytes,
				{
					afterLink: () => fault("after_retention_conflict_evidence_link_before_directory_fsync"),
				},
			);
			if (conflictPublication === "conflict") {
				return { state: "pending", reason: "retention_authority_conflict_control_conflict" };
			}
		}
		fault("after_retention_conflict_evidence_durable");

		const terminalBytes = retentionAuthorityConflictManifestBytes(
			authority,
			intendedControlBytes,
			conflictControlBytes,
		);
		if (manifestControlBytes && !manifestControlBytes.equals(terminalBytes)) {
			return { state: "pending", reason: "retention_authority_manifest_control_conflict" };
		}
		const terminalPublication = publishImmutableFile(
			fs,
			privateAuthorityDirectory,
			RETENTION_AUTHORITY_MANIFEST_NAME,
			terminalBytes,
			{
				afterLink: () => fault("after_retention_manifest_link_before_directory_fsync"),
			},
		);
		if (terminalPublication === "conflict") {
			return { state: "pending", reason: "retention_authority_manifest_control_conflict" };
		}
		fsyncDirectory(fs, privateAuthorityDirectory);
		fsyncDirectory(fs, operationIncidentDirectory);
		fsyncDirectory(fs, operationIncidentsDirectory);
		fault("after_retention_manifest_durable_before_readback");
		const readbackPublished = inspectPublishedIncidentFinalizationBound({ incidentsDirectory, incidentId }, fs, set);
		if (readbackPublished.state === "pending") {
			return {
				state: "pending",
				reason: `retention_authority_published_finalization_unconfirmed:${readbackPublished.reason}`,
			};
		}
		const readback = inspectIncidentRetentionAuthorityBound(
			{ incidentsDirectory, incidentId },
			fs,
			set,
			readbackPublished,
		);
		if (
			readback.state !== "authorized" ||
			readback.authoritySource !== "conflict" ||
			readback.retentionClass !== "corrupt" ||
			!retentionAuthorityMatchesPublished(readback, published)
		) {
			return { state: "pending", reason: "retention_authority_conflict_readback_unconfirmed" };
		}
		validatePinnedFinalizationDirectorySet(fs, set);
		return { ...readback, publication: terminalPublication };
	} catch (error) {
		if (error instanceof FinalizationDirectoryBindingError) {
			return { state: "pending", reason: error.reason };
		}
		return { state: "pending", reason: "retention_authority_persistence_ambiguous" };
	} finally {
		closePinnedFinalizationDirectory(fs, set.member);
		closePinnedFinalizationDirectory(fs, set.parent);
	}
}

function releaseLease(input: IncidentRecorderFinalizationInput): void {
	input.releaseProjectionLease?.();
}

function ambiguousResult(
	analysis: FinalizationAnalysis,
	incidentDirectory: string,
): IncidentRecorderFinalizationResult {
	return {
		state: "ambiguous",
		publication: "ambiguous",
		finalizationId: analysis.finalizationId,
		reasons: analysis.reasons,
		incidentDirectory,
		supervisorExitAnchorWallTimeMs: analysis.supervisorExitAnchorWallTimeMs,
		retentionAnchorWallTimeMs: analysis.retentionAnchorWallTimeMs,
	};
}

type ProvenPublishedFinalization = Exclude<IncidentRecorderPublishedFinalizationInspection, { state: "pending" }>;

interface PreparedPublicationHooks {
	afterManifestLink?: () => void;
	afterParentFsync?: () => void;
}

interface PreparedPublicationDirectoryBindings {
	parent: PinnedFinalizationDirectory;
	incident: PinnedFinalizationDirectory;
	partial?: PinnedFinalizationDirectory;
}

function validatePreparedPublicationDirectoryBindings(
	fs: IncidentRecorderFinalizationFileSystem,
	bindings: PreparedPublicationDirectoryBindings,
): void {
	validatePinnedFinalizationDirectory(fs, bindings.parent, "finalization_incidents_directory_detached");
	validatePinnedFinalizationDirectory(fs, bindings.incident, "finalization_incident_directory_detached");
	if (bindings.partial) {
		validatePinnedFinalizationDirectory(fs, bindings.partial, "finalization_partial_directory_detached");
	}
}

function boundChildOperationPath(parent: PinnedFinalizationDirectory, canonicalChildPath: string): string {
	return join(parent.operationPath, basename(canonicalChildPath));
}

interface PreparedCleanupCandidate {
	bytes: Buffer;
	destinationPath: string;
	staging: boolean;
}

type PreparedStageCleanupResult = "complete" | "pending";

function inspectUnboundPreparedStage(
	fs: IncidentRecorderFinalizationFileSystem,
	bindings: PreparedPublicationDirectoryBindings,
	partialDirectory: string,
): PreparedStageCleanupResult {
	try {
		fs.lstat(join(bindings.parent.operationPath, basename(partialDirectory)), { bigint: true });
		return "pending";
	} catch (error) {
		return errno(error) === "ENOENT" ? "complete" : "pending";
	}
}

function bindExistingPreparedStage(
	fs: IncidentRecorderFinalizationFileSystem,
	bindings: PreparedPublicationDirectoryBindings,
	partialDirectory: string,
): {
	bindings: PreparedPublicationDirectoryBindings;
	partial?: PinnedFinalizationDirectory;
} {
	if (bindings.partial) return { bindings };
	const candidateName = basename(partialDirectory);
	const partial = pinFinalizationDirectory(
		fs,
		join(bindings.parent.canonicalPath, candidateName),
		join(bindings.parent.operationPath, candidateName),
	);
	return partial ? { bindings: { ...bindings, partial }, partial } : { bindings };
}

function statPreparedCleanupDirectory(fs: IncidentRecorderFinalizationFileSystem, directory: string): BigIntStats {
	const descriptorPath = /^\/proc\/self\/fd\/([0-9]+)$/.exec(directory);
	return descriptorPath
		? fs.fstat(Number(descriptorPath[1]), { bigint: true })
		: fs.lstat(directory, { bigint: true });
}

function cleanupExactImmutableStagingFiles(
	fs: IncidentRecorderFinalizationFileSystem,
	destinationPath: string,
	bytes: Buffer,
	maximum = MAX_FINALIZATION_FILE_BYTES,
): boolean {
	let removed = false;
	for (const temporaryPath of immutableStagingPaths(destinationPath, bytes)) {
		const temporary = readPrivateStagingExact(fs, temporaryPath, destinationPath, maximum);
		if (!temporary?.equals(bytes)) continue;
		fs.unlink(temporaryPath);
		removed = true;
	}
	return removed;
}

function preflightPreparedDirectoryCleanup(
	fs: IncidentRecorderFinalizationFileSystem,
	directory: string,
	expected: ReadonlyMap<string, Buffer>,
): string[] | undefined {
	let before: BigIntStats;
	try {
		before = statPreparedCleanupDirectory(fs, directory);
	} catch {
		return undefined;
	}
	if (
		!before.isDirectory() ||
		before.isSymbolicLink() ||
		(typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) ||
		(before.mode & 0o077n) !== 0n
	) {
		return undefined;
	}
	const candidates = new Map<string, PreparedCleanupCandidate>();
	for (const [name, bytes] of expected) {
		const destinationPath = join(directory, name);
		candidates.set(name, { bytes, destinationPath, staging: false });
		for (const stagingName of immutableStagingFileNames(name, bytes)) {
			candidates.set(stagingName, { bytes, destinationPath, staging: true });
		}
	}
	let names: string[];
	try {
		names = fs.readdir(directory).sort();
	} catch {
		return undefined;
	}
	for (const name of names) {
		const candidate = candidates.get(name);
		if (!candidate) return undefined;
		const path = join(directory, name);
		const observed = candidate.staging
			? readPrivateStagingExact(fs, path, candidate.destinationPath)
			: readPrivatePublishedExact(fs, path);
		if (!observed?.equals(candidate.bytes)) return undefined;
	}
	try {
		const after = statPreparedCleanupDirectory(fs, directory);
		if (!sameStableFileIdentity(before, after)) return undefined;
	} catch {
		return undefined;
	}
	return names;
}

function cleanupSupersededPreparedDirectory(
	fs: IncidentRecorderFinalizationFileSystem,
	incidentsDirectory: string,
	partialDirectory: string,
	prepared: ProvenPublishedFinalization,
	bindings?: PreparedPublicationDirectoryBindings,
): PreparedStageCleanupResult {
	if (prepared.manifest.kind !== "incident_recorder_finalization_manifest") return "complete";
	if (bindings) {
		validatePreparedPublicationDirectoryBindings(fs, bindings);
		if (!bindings.partial) return inspectUnboundPreparedStage(fs, bindings, partialDirectory);
	}
	const expected = new Map<string, Buffer>();
	for (const record of prepared.manifest.files) {
		const bytes = readPrivatePublishedExact(fs, join(partialDirectory, record.name));
		if (!bytes || !sameFileRecord(record, fileRecord(record.name, bytes))) return "complete";
		expected.set(record.name, bytes);
	}
	const manifest = readPrivatePublishedExact(fs, join(partialDirectory, "finalization-manifest.json"));
	if (!manifest || !manifest.equals(jsonBytes(prepared.manifest))) return "complete";
	expected.set("finalization-manifest.json", manifest);
	const cleanupDirectory = bindings ? bindings.partial?.operationPath : partialDirectory;
	if (!cleanupDirectory) return "pending";
	const removableNames = preflightPreparedDirectoryCleanup(fs, cleanupDirectory, expected);
	if (!removableNames) return "complete";
	try {
		for (const name of removableNames) fs.unlink(join(cleanupDirectory, name));
		fsyncDirectory(fs, cleanupDirectory);
		if (bindings?.partial) {
			validatePreparedPublicationDirectoryBindings(fs, bindings);
			fs.rmdir(boundChildOperationPath(bindings.parent, bindings.partial.canonicalPath));
		} else {
			fs.rmdir(cleanupDirectory);
		}
		fsyncDirectory(fs, incidentsDirectory);
		if (bindings) {
			validatePinnedFinalizationDirectory(fs, bindings.parent, "finalization_incidents_directory_detached");
			validatePinnedFinalizationDirectory(fs, bindings.incident, "finalization_incident_directory_detached");
		}
	} catch (error) {
		if (error instanceof FinalizationDirectoryBindingError) return "pending";
		// Unknown or different evidence keeps the exact stage protected.
	}
	return "complete";
}

function publishPreparedIncidentFinalization(
	fs: IncidentRecorderFinalizationFileSystem,
	input: { incidentsDirectory: string; incidentId: string },
	partialDirectory: string,
	prepared: ProvenPublishedFinalization,
	hooks: PreparedPublicationHooks = {},
	bindings?: PreparedPublicationDirectoryBindings,
): { inspection: ProvenPublishedFinalization; publication: "applied" | "noop" } {
	if (prepared.manifest.kind !== "incident_recorder_finalization_manifest") {
		throw new Error("Expected a standard prepared finalization manifest");
	}
	if (
		prepared.manifest.files.length !== STANDARD_FINALIZATION_FILE_NAMES.length ||
		prepared.manifest.files.some((record, index) => record.name !== STANDARD_FINALIZATION_FILE_NAMES[index])
	) {
		throw new Error("Prepared finalization file set is not canonical");
	}
	const incidentDirectory = bindings?.incident.operationPath ?? join(input.incidentsDirectory, input.incidentId);
	const operationIncidentsDirectory = bindings?.parent.operationPath ?? input.incidentsDirectory;
	const operationPartialDirectory = bindings?.partial?.operationPath ?? partialDirectory;
	if (bindings) validatePreparedPublicationDirectoryBindings(fs, bindings);
	const afterManifestLink = (): void => {
		if (bindings) validatePreparedPublicationDirectoryBindings(fs, bindings);
		hooks.afterManifestLink?.();
		if (bindings) validatePreparedPublicationDirectoryBindings(fs, bindings);
	};
	const afterParentFsync = (): void => {
		if (bindings) validatePreparedPublicationDirectoryBindings(fs, bindings);
		hooks.afterParentFsync?.();
		if (bindings) validatePreparedPublicationDirectoryBindings(fs, bindings);
	};
	const alreadyPublished = bindings
		? inspectPublishedIncidentFinalizationBound(input, fs, {
				parent: bindings.parent,
				member: bindings.incident,
				memberOperationPath: bindings.incident.operationPath,
				canonicalMemberPath: bindings.incident.canonicalPath,
				memberState: "present",
			})
		: inspectPublishedIncidentFinalization(input, { fs });
	if (alreadyPublished.state !== "pending") {
		if (
			cleanupSupersededPreparedDirectory(
				fs,
				operationIncidentsDirectory,
				operationPartialDirectory,
				prepared,
				bindings,
			) === "pending"
		) {
			throw new FinalizationDirectoryBindingError("finalization_partial_directory_detached");
		}
		if (bindings) validatePreparedPublicationDirectoryBindings(fs, bindings);
		return { inspection: alreadyPublished, publication: "noop" };
	}
	if (!bindings) ensureDirectory(fs, incidentDirectory);
	fsyncDirectory(fs, operationIncidentsDirectory);
	const preparedManifestBytes = readPrivatePublishedExact(
		fs,
		join(operationPartialDirectory, "finalization-manifest.json"),
	);
	if (!preparedManifestBytes || !preparedManifestBytes.equals(jsonBytes(prepared.manifest))) {
		throw new Error("Prepared finalization manifest changed before authority claim");
	}
	const privateAuthorityDirectory = ensurePrivateAuthorityDirectory(fs, incidentDirectory);
	const claim: FinalizationAuthorityClaim = {
		schemaVersion: 1,
		kind: "incident_recorder_finalization_authority_claim",
		finalizationId: prepared.finalizationId,
		runIdentity: prepared.manifest.runIdentity,
		preparedManifest: {
			bytes: preparedManifestBytes.length,
			sha256: sha256(preparedManifestBytes),
		},
	};
	const claimBytes = jsonBytes(claim);
	const claimResult = publishImmutableFile(
		fs,
		privateAuthorityDirectory,
		FINALIZATION_PRIVATE_AUTHORITY_CLAIM_NAME,
		claimBytes,
	);
	if (claimResult === "conflict") {
		throw new Error("Incident finalization authority is claimed by another prepared finalization");
	}
	fsyncDirectory(fs, privateAuthorityDirectory);
	fsyncDirectory(fs, incidentDirectory);
	fsyncDirectory(fs, operationIncidentsDirectory);
	const conflictSupport = new Map<string, Buffer>();
	let conflictAuthorityDirectory = incidentDirectory;
	const moveConflictAuthorityToPrivateRoot = (): void => {
		if (conflictAuthorityDirectory === privateAuthorityDirectory) return;
		conflictAuthorityDirectory = privateAuthorityDirectory;
		for (const [name, bytes] of conflictSupport) {
			if (publishImmutableFile(fs, conflictAuthorityDirectory, name, bytes) === "conflict") {
				throw new Error(`Private incident finalization authority root invariant violated: ${name}`);
			}
		}
	};
	const publishConflictSupport = (name: string, bytes: Buffer, alreadyCanonical = false): void => {
		const remembered = conflictSupport.get(name);
		if (remembered && !remembered.equals(bytes)) {
			throw new Error(`Incident finalization conflict support name reused with different bytes: ${name}`);
		}
		conflictSupport.set(name, bytes);
		if (alreadyCanonical && conflictAuthorityDirectory === incidentDirectory) return;
		if (publishImmutableFile(fs, conflictAuthorityDirectory, name, bytes) !== "conflict") return;
		if (conflictAuthorityDirectory !== incidentDirectory) {
			throw new Error(`Private incident finalization conflict support collided: ${name}`);
		}
		moveConflictAuthorityToPrivateRoot();
	};
	const mappings: FinalizationConflictFile[] = [];
	let conflictCount = 0;
	for (const record of prepared.manifest.files) {
		const preparedBytes = readBoundedExact(fs, join(operationPartialDirectory, record.name));
		if (!preparedBytes || !sameFileRecord(record, fileRecord(record.name, preparedBytes))) {
			throw new Error(`Prepared incident finalization file changed before publication: ${record.name}`);
		}
		let collisionBytes: Buffer | undefined;
		const result = publishImmutableFile(fs, incidentDirectory, record.name, preparedBytes, {
			onConflict: (existing) => {
				collisionBytes = existing;
			},
		});
		const privatePublished =
			result === "conflict" ? undefined : readPrivatePublishedExact(fs, join(incidentDirectory, record.name));
		if (result !== "conflict" && privatePublished?.equals(preparedBytes)) {
			mappings.push({
				logicalName: record.name as FinalizationConflictFile["logicalName"],
				prepared: record,
			});
			publishConflictSupport(record.name, preparedBytes, true);
			continue;
		}
		if (result === "applied") {
			throw new Error(`Applied incident finalization file failed private readback: ${record.name}`);
		}
		conflictCount += 1;
		const preparedEvidence = fileRecord(conflictEvidenceName("prepared", record.name, record.sha256), preparedBytes);
		publishConflictSupport(preparedEvidence.name, preparedBytes);
		const occupant = namespaceOccupantMetadata(fs, join(incidentDirectory, record.name));
		let observed = occupant.observed;
		if (occupant.observed.disposition === "exact_private_bytes") {
			const bytes = collisionBytes ?? occupant.bytes;
			if (!bytes || bytes.equals(preparedBytes)) {
				throw new Error(`Prepared incident finalization conflict changed during observation: ${record.name}`);
			}
			const evidence = fileRecord(conflictEvidenceName("observed", record.name, sha256(bytes)), bytes);
			publishConflictSupport(evidence.name, bytes);
			observed = { disposition: "exact_private_bytes", evidence };
		}
		mappings.push({
			logicalName: record.name as FinalizationConflictFile["logicalName"],
			prepared: preparedEvidence,
			observed,
		});
	}
	const intendedManifestBytes = readBoundedExact(fs, join(operationPartialDirectory, "finalization-manifest.json"));
	const intendedManifest = intendedManifestBytes ? parseManifest(intendedManifestBytes) : undefined;
	if (
		!intendedManifestBytes ||
		!intendedManifest ||
		intendedManifest.kind !== "incident_recorder_finalization_manifest" ||
		intendedManifest.finalizationId !== prepared.finalizationId
	) {
		throw new Error("Prepared incident finalization manifest changed before publication");
	}
	let terminalManifestResult: ImmutableWriteResult | undefined;
	let manifestCollisionBytes: Buffer | undefined;
	let manifestConflictObserved: FinalizationConflictObserved | undefined;
	if (conflictCount === 0) {
		terminalManifestResult = publishImmutableFile(
			fs,
			incidentDirectory,
			"finalization-manifest.json",
			intendedManifestBytes,
			{
				afterLink: afterManifestLink,
				onConflict: (existing) => {
					manifestCollisionBytes = existing;
				},
			},
		);
		const privateManifest =
			terminalManifestResult === "conflict"
				? undefined
				: readPrivatePublishedExact(fs, join(incidentDirectory, "finalization-manifest.json"));
		if (terminalManifestResult !== "conflict" && privateManifest?.equals(intendedManifestBytes)) {
			fsyncDirectory(fs, incidentDirectory);
			fsyncDirectory(fs, operationIncidentsDirectory);
			afterParentFsync();
			const inspection = bindings
				? inspectPublishedIncidentFinalizationBound(input, fs, {
						parent: bindings.parent,
						member: bindings.incident,
						memberOperationPath: bindings.incident.operationPath,
						canonicalMemberPath: bindings.incident.canonicalPath,
						memberState: "present",
					})
				: inspectPublishedIncidentFinalization(input, { fs });
			if (inspection.state === "pending" || inspection.finalizationId !== prepared.finalizationId) {
				throw new Error("Published incident finalization readback did not match prepared finalization");
			}
			return { inspection, publication: terminalManifestResult };
		}
		if (terminalManifestResult === "applied") {
			throw new Error("Applied finalization manifest failed private readback");
		}
		terminalManifestResult = "conflict";
	}
	const intendedManifestEvidence = fileRecord(
		conflictEvidenceName("prepared", "finalization-manifest.json", sha256(intendedManifestBytes)),
		intendedManifestBytes,
	);
	publishConflictSupport(intendedManifestEvidence.name, intendedManifestBytes);
	const manifestPath = join(incidentDirectory, "finalization-manifest.json");
	let manifestExists = true;
	try {
		fs.lstat(manifestPath, { bigint: true });
	} catch (error) {
		if (errno(error) === "ENOENT") manifestExists = false;
	}
	if (terminalManifestResult === "conflict" || (conflictCount > 0 && manifestExists)) {
		const occupant = namespaceOccupantMetadata(fs, manifestPath);
		if (
			occupant.observed.disposition !== "exact_private_bytes" ||
			!(occupant.bytes ?? manifestCollisionBytes)?.equals(intendedManifestBytes)
		) {
			if (occupant.observed.disposition === "exact_private_bytes") {
				const bytes = manifestCollisionBytes ?? occupant.bytes;
				if (!bytes) throw new Error("Manifest conflict changed during observation");
				const evidence = fileRecord(
					conflictEvidenceName("observed", "finalization-manifest.json", sha256(bytes)),
					bytes,
				);
				publishConflictSupport(evidence.name, bytes);
				manifestConflictObserved = { disposition: "exact_private_bytes", evidence };
			} else {
				manifestConflictObserved = occupant.observed;
			}
		}
	}
	const reasons = [
		...new Set([
			...prepared.manifest.reasons,
			...mappings
				.filter((mapping) => mapping.observed !== undefined)
				.map((mapping) => PUBLICATION_CONFLICT_REASON_PREFIX + mapping.logicalName),
			...(manifestConflictObserved ? [`${PUBLICATION_CONFLICT_REASON_PREFIX}finalization-manifest.json`] : []),
		]),
	].sort();
	const conflictValue: FinalizationConflictRecord = {
		schemaVersion: 1,
		kind: "incident_recorder_finalization_publication_conflict",
		finalizationId: prepared.finalizationId,
		runIdentity: prepared.manifest.runIdentity,
		intendedState: prepared.state,
		intendedReasons: [...prepared.manifest.reasons],
		supervisorExitAnchorWallTimeMs: prepared.supervisorExitAnchorWallTimeMs,
		retentionAnchorWallTimeMs: prepared.retentionAnchorWallTimeMs,
		intendedManifest: intendedManifestEvidence,
		files: mappings,
		...(manifestConflictObserved
			? {
					manifestConflict: {
						logicalName: "finalization-manifest.json" as const,
						prepared: intendedManifestEvidence,
						observed: manifestConflictObserved,
					},
				}
			: {}),
	};
	const conflictBytes = jsonBytes(conflictValue);
	if (conflictBytes.length > MAX_FINALIZATION_CONFLICT_RECORD_BYTES) {
		throw new Error("Incident finalization conflict record exceeds bound");
	}
	const conflictRecord = fileRecord(`finalization-conflict-${sha256(conflictBytes)}.json`, conflictBytes);
	publishConflictSupport(conflictRecord.name, conflictBytes);
	const conflictManifest: ConflictFinalizationManifest = {
		schemaVersion: 1,
		kind: "incident_recorder_finalization_conflict_manifest",
		finalizationId: prepared.finalizationId,
		state: "corrupt",
		reasons,
		runIdentity: prepared.manifest.runIdentity,
		supervisorExitAnchorWallTimeMs: prepared.supervisorExitAnchorWallTimeMs,
		retentionAnchorWallTimeMs: prepared.retentionAnchorWallTimeMs,
		files: [
			...mappings.map((mapping) => mapping.prepared),
			...mappings.flatMap((mapping) =>
				mapping.observed?.disposition === "exact_private_bytes" ? [mapping.observed.evidence] : [],
			),
			...(manifestConflictObserved?.disposition === "exact_private_bytes"
				? [manifestConflictObserved.evidence]
				: []),
			intendedManifestEvidence,
			conflictRecord,
		],
		conflictRecord,
	};
	const conflictManifestBytes = jsonBytes(conflictManifest);
	if (conflictManifestBytes.length > MAX_FINALIZATION_CONFLICT_RECORD_BYTES) {
		throw new Error("Incident finalization conflict manifest exceeds bound");
	}
	const conflictManifestRecord = fileRecord(
		`finalization-conflict-manifest-${sha256(conflictManifestBytes)}.json`,
		conflictManifestBytes,
	);
	publishConflictSupport(conflictManifestRecord.name, conflictManifestBytes);
	const selector: FinalizationAuthoritySelector = {
		schemaVersion: 1,
		kind: "incident_recorder_finalization_authority_selector",
		finalizationId: prepared.finalizationId,
		runIdentity: prepared.manifest.runIdentity,
		state: "corrupt",
		manifest: conflictManifestRecord,
	};
	const selectorBytes = jsonBytes(selector);
	terminalManifestResult = undefined;
	if (conflictAuthorityDirectory === incidentDirectory) {
		for (const selectorName of FINALIZATION_AUTHORITY_FILE_NAMES) {
			const result = publishImmutableFile(fs, incidentDirectory, selectorName, selectorBytes, {
				afterLink: afterManifestLink,
			});
			if (result !== "conflict") {
				terminalManifestResult = result;
				break;
			}
			const selected = bindings
				? inspectPublishedIncidentFinalizationBound(input, fs, {
						parent: bindings.parent,
						member: bindings.incident,
						memberOperationPath: bindings.incident.operationPath,
						canonicalMemberPath: bindings.incident.canonicalPath,
						memberState: "present",
					})
				: inspectPublishedIncidentFinalization(input, { fs });
			if (selected.state !== "pending") {
				fsyncDirectory(fs, incidentDirectory);
				fsyncDirectory(fs, operationIncidentsDirectory);
				if (
					cleanupSupersededPreparedDirectory(
						fs,
						operationIncidentsDirectory,
						operationPartialDirectory,
						prepared,
						bindings,
					) === "pending"
				) {
					throw new FinalizationDirectoryBindingError("finalization_partial_directory_detached");
				}
				if (bindings) validatePreparedPublicationDirectoryBindings(fs, bindings);
				afterParentFsync();
				return { inspection: selected, publication: "noop" };
			}
		}
		if (!terminalManifestResult) moveConflictAuthorityToPrivateRoot();
	}
	if (conflictAuthorityDirectory === privateAuthorityDirectory) {
		terminalManifestResult = publishImmutableFile(
			fs,
			privateAuthorityDirectory,
			FINALIZATION_PRIVATE_AUTHORITY_SELECTOR_NAME,
			selectorBytes,
			{ afterLink: afterManifestLink },
		);
		if (terminalManifestResult === "conflict") {
			throw new Error("Private incident finalization authority selector invariant violated");
		}
		fsyncDirectory(fs, privateAuthorityDirectory);
	}
	if (!terminalManifestResult) throw new Error("Incident finalization authority publication did not converge");
	fsyncDirectory(fs, incidentDirectory);
	fsyncDirectory(fs, operationIncidentsDirectory);
	afterParentFsync();
	const inspection = bindings
		? inspectPublishedIncidentFinalizationBound(input, fs, {
				parent: bindings.parent,
				member: bindings.incident,
				memberOperationPath: bindings.incident.operationPath,
				canonicalMemberPath: bindings.incident.canonicalPath,
				memberState: "present",
			})
		: inspectPublishedIncidentFinalization(input, { fs });
	if (inspection.state === "pending") {
		throw new Error("Published incident finalization readback did not match prepared finalization");
	}
	if (inspection.finalizationId !== prepared.finalizationId) {
		const superseded = inspectManifestAuthority(fs, incidentDirectory, conflictManifestBytes);
		if (superseded.state !== "pending") {
			if (cleanupExactPreparedStage(fs, input, superseded, selectorBytes, bindings) === "pending") {
				throw new FinalizationDirectoryBindingError("finalization_partial_directory_detached");
			}
		}
		return { inspection, publication: "noop" };
	}
	if (bindings) validatePreparedPublicationDirectoryBindings(fs, bindings);
	return { inspection, publication: terminalManifestResult };
}

function cleanupExactPreparedStage(
	fs: IncidentRecorderFinalizationFileSystem,
	input: { incidentsDirectory: string; incidentId: string },
	inspection: ProvenPublishedFinalization,
	authoritySelectorBytes?: Buffer,
	bindings?: PreparedPublicationDirectoryBindings,
): PreparedStageCleanupResult {
	const incidentDirectory = bindings?.incident.operationPath ?? join(input.incidentsDirectory, input.incidentId);
	const operationIncidentsDirectory = bindings?.parent.operationPath ?? input.incidentsDirectory;
	const authorityDirectory = inspection.authorityDirectory;
	const fallbackPartialDirectory = join(
		operationIncidentsDirectory,
		`.${input.incidentId}.partial-${inspection.finalizationId}`,
	);
	if (bindings) {
		validatePreparedPublicationDirectoryBindings(fs, bindings);
		if (!bindings.partial) return inspectUnboundPreparedStage(fs, bindings, fallbackPartialDirectory);
	}
	const expected = new Map<string, Buffer>();
	let conflict: FinalizationConflictRecord | undefined;
	if (inspection.manifest.kind === "incident_recorder_finalization_manifest") {
		for (const record of inspection.manifest.files) {
			const bytes = readPrivatePublishedExact(fs, join(incidentDirectory, record.name));
			if (!bytes || !sameFileRecord(record, fileRecord(record.name, bytes))) return "complete";
			expected.set(record.name, bytes);
		}
		const manifest = readPrivatePublishedExact(fs, join(incidentDirectory, "finalization-manifest.json"));
		if (!manifest) return "complete";
		expected.set("finalization-manifest.json", manifest);
	} else {
		const conflictBytes = readPrivatePublishedExact(
			fs,
			join(authorityDirectory, inspection.manifest.conflictRecord.name),
		);
		if (!conflictBytes) return "complete";
		conflict = parseConflictRecord(conflictBytes);
		if (!conflict) return "complete";
		for (const mapping of conflict.files) {
			const bytes = readPrivatePublishedExact(fs, join(authorityDirectory, mapping.prepared.name));
			if (!bytes || !sameFileRecord(mapping.prepared, fileRecord(mapping.prepared.name, bytes))) return "complete";
			expected.set(mapping.logicalName, bytes);
		}
		const intendedManifest = readPrivatePublishedExact(fs, join(authorityDirectory, conflict.intendedManifest.name));
		if (!intendedManifest) return "complete";
		expected.set("finalization-manifest.json", intendedManifest);
	}
	const partialDirectory = bindings?.partial?.operationPath ?? fallbackPartialDirectory;
	const partialCleanupDirectory = bindings ? bindings.partial?.operationPath : partialDirectory;
	if (!partialCleanupDirectory) return "pending";
	const removableNames = preflightPreparedDirectoryCleanup(fs, partialCleanupDirectory, expected);
	if (removableNames) {
		try {
			for (const name of removableNames) {
				fs.unlink(join(partialCleanupDirectory, name));
			}
			fsyncDirectory(fs, partialCleanupDirectory);
			if (bindings?.partial) {
				validatePreparedPublicationDirectoryBindings(fs, bindings);
				fs.rmdir(boundChildOperationPath(bindings.parent, bindings.partial.canonicalPath));
			} else {
				fs.rmdir(partialCleanupDirectory);
			}
			fsyncDirectory(fs, operationIncidentsDirectory);
			if (bindings) {
				validatePinnedFinalizationDirectory(fs, bindings.parent, "finalization_incidents_directory_detached");
				validatePinnedFinalizationDirectory(fs, bindings.incident, "finalization_incident_directory_detached");
			}
		} catch (error) {
			if (error instanceof FinalizationDirectoryBindingError) return "pending";
			return "complete";
		}
	}
	if (!conflict) {
		const manifest = expected.get("finalization-manifest.json");
		if (!manifest) return "complete";
		try {
			if (cleanupExactImmutableStagingFiles(fs, join(incidentDirectory, "finalization-manifest.json"), manifest)) {
				fsyncDirectory(fs, incidentDirectory);
			}
		} catch {
			return "complete";
		}
		return "complete";
	}
	let removedTemporary = false;
	for (const mapping of conflict.files) {
		if (!mapping.observed) continue;
		const prepared = expected.get(mapping.logicalName);
		if (!prepared) continue;
		try {
			removedTemporary =
				cleanupExactImmutableStagingFiles(fs, join(incidentDirectory, mapping.logicalName), prepared) ||
				removedTemporary;
		} catch {
			return "complete";
		}
	}
	if (conflict.manifestConflict) {
		const intendedManifest = expected.get("finalization-manifest.json");
		if (intendedManifest) {
			try {
				removedTemporary =
					cleanupExactImmutableStagingFiles(
						fs,
						join(incidentDirectory, "finalization-manifest.json"),
						intendedManifest,
					) || removedTemporary;
			} catch {
				return "complete";
			}
		}
	}
	let selectorBytes = authoritySelectorBytes;
	if (!selectorBytes) {
		for (const selectorName of FINALIZATION_AUTHORITY_FILE_NAMES) {
			const candidate = readPrivatePublishedExact(
				fs,
				join(incidentDirectory, selectorName),
				MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
			);
			if (!candidate) continue;
			const selector = parseAuthoritySelector(candidate);
			if (
				selector &&
				selector.finalizationId === inspection.finalizationId &&
				selector.manifest.sha256 === sha256(jsonBytes(inspection.manifest))
			) {
				selectorBytes = candidate;
				break;
			}
		}
		if (!selectorBytes && authorityDirectory !== incidentDirectory) {
			const candidate = readPrivatePublishedExact(
				fs,
				join(authorityDirectory, FINALIZATION_PRIVATE_AUTHORITY_SELECTOR_NAME),
				MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
			);
			const selector = candidate ? parseAuthoritySelector(candidate) : undefined;
			if (
				selector &&
				selector.finalizationId === inspection.finalizationId &&
				selector.manifest.sha256 === sha256(jsonBytes(inspection.manifest))
			) {
				selectorBytes = candidate;
			}
		}
	}
	if (selectorBytes) {
		for (const selectorName of FINALIZATION_AUTHORITY_FILE_NAMES) {
			try {
				removedTemporary =
					cleanupExactImmutableStagingFiles(
						fs,
						join(incidentDirectory, selectorName),
						selectorBytes,
						MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
					) || removedTemporary;
			} catch {
				return "complete";
			}
		}
		if (authorityDirectory !== incidentDirectory) {
			try {
				if (
					cleanupExactImmutableStagingFiles(
						fs,
						join(authorityDirectory, FINALIZATION_PRIVATE_AUTHORITY_SELECTOR_NAME),
						selectorBytes,
						MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
					)
				) {
					fsyncDirectory(fs, authorityDirectory);
				}
			} catch {
				return "complete";
			}
		}
	}
	if (removedTemporary) fsyncDirectory(fs, incidentDirectory);
	return "complete";
}

export function finalizeIncidentRecorderProjection(
	input: IncidentRecorderFinalizationInput,
	options: IncidentRecorderFinalizerOptions = {},
): IncidentRecorderFinalizationResult {
	const analysis = analyzeIncidentRecorderFinalization(input);
	const incidentDirectory = join(input.incidentsDirectory, input.incidentId);
	if (analysis.state === "pending") return ambiguousResult(analysis, incidentDirectory);
	const fs = combinedFileSystem(options);
	let directorySet: PinnedIncidentDirectorySet | undefined;
	let publicationBindings: PreparedPublicationDirectoryBindings | undefined;
	try {
		ensureDirectory(fs, input.incidentsDirectory);
		directorySet = pinFinalizationIncidentDirectorySet(fs, input.incidentsDirectory, input.incidentId);
		if (!directorySet) return ambiguousResult(analysis, incidentDirectory);
		validatePinnedFinalizationDirectorySet(fs, directorySet);
		const fault = (boundary: IncidentRecorderFinalizationComponentFaultBoundary): void => {
			validatePinnedFinalizationDirectorySet(fs, directorySet!);
			if (publicationBindings) validatePreparedPublicationDirectoryBindings(fs, publicationBindings);
			options.onFaultBoundary?.(boundary);
			validatePinnedFinalizationDirectorySet(fs, directorySet!);
			if (publicationBindings) validatePreparedPublicationDirectoryBindings(fs, publicationBindings);
		};
		const existing = inspectPublishedIncidentFinalizationBound(
			{ incidentsDirectory: input.incidentsDirectory, incidentId: input.incidentId },
			fs,
			directorySet,
		);
		validatePinnedFinalizationDirectorySet(fs, directorySet);
		if (existing.state !== "pending") {
			if (existing.finalizationId !== analysis.finalizationId) {
				try {
					input.assertProjectionLeaseUsable?.();
					releaseLease(input);
				} catch {
					return ambiguousResult(analysis, incidentDirectory);
				}
				if (
					cleanupExactPreparedStage(
						fs,
						{ incidentsDirectory: input.incidentsDirectory, incidentId: input.incidentId },
						existing,
						undefined,
						directorySet.member
							? {
									parent: directorySet.parent,
									incident: directorySet.member,
								}
							: undefined,
					) === "pending"
				) {
					return ambiguousResult(analysis, incidentDirectory);
				}
				validatePinnedFinalizationDirectorySet(fs, directorySet);
				return {
					state: existing.state,
					finalizationId: existing.finalizationId,
					reasons: existing.manifest.reasons,
					supervisorExitAnchorWallTimeMs: existing.supervisorExitAnchorWallTimeMs,
					retentionAnchorWallTimeMs: existing.retentionAnchorWallTimeMs,
					reason: "published_finalization_conflict",
					publication: "noop",
					incidentDirectory,
				};
			}
			try {
				input.assertProjectionLeaseUsable?.();
				releaseLease(input);
			} catch {
				return ambiguousResult(analysis, incidentDirectory);
			}
			if (
				cleanupExactPreparedStage(
					fs,
					{ incidentsDirectory: input.incidentsDirectory, incidentId: input.incidentId },
					existing,
					undefined,
					directorySet.member
						? {
								parent: directorySet.parent,
								incident: directorySet.member,
							}
						: undefined,
				) === "pending"
			) {
				return ambiguousResult(analysis, incidentDirectory);
			}
			validatePinnedFinalizationDirectorySet(fs, directorySet);
			return {
				state: existing.state,
				finalizationId: existing.finalizationId,
				reasons: existing.manifest.reasons,
				supervisorExitAnchorWallTimeMs: existing.supervisorExitAnchorWallTimeMs,
				retentionAnchorWallTimeMs: existing.retentionAnchorWallTimeMs,
				publication: "noop",
				incidentDirectory,
				...(existing.manifest.kind === "incident_recorder_finalization_conflict_manifest"
					? { reason: "prepared_publication_conflict" }
					: {}),
			};
		}

		const operationIncidentsDirectory = directorySet.parent.operationPath;
		let operationIncidentDirectory = directorySet.member?.operationPath ?? directorySet.memberOperationPath;
		let leaseHeld = false;
		try {
			if (
				input.runHistory.state === "complete" &&
				input.assertProjectionLeaseUsable &&
				input.releaseProjectionLease
			) {
				input.assertProjectionLeaseUsable?.();
				leaseHeld = true;
				fault("after_projection_lease_acquired");
			}
			if (!directorySet.member) {
				ensureDirectory(fs, operationIncidentDirectory);
			}
			if (!directorySet.member) {
				const member = pinFinalizationDirectory(fs, directorySet.canonicalMemberPath, operationIncidentDirectory);
				if (!member) throw new Error("Incident directory binding changed before publication");
				directorySet = {
					...directorySet,
					member,
					memberOperationPath: member.operationPath,
					memberState: "present",
				};
				operationIncidentDirectory = member.operationPath;
			}
			validatePinnedFinalizationDirectorySet(fs, directorySet);
			fsyncDirectory(fs, dirname(input.incidentsDirectory));
			const partialDirectory = join(
				operationIncidentsDirectory,
				`.${input.incidentId}.partial-${analysis.finalizationId}`,
			);
			ensureDirectory(fs, partialDirectory);
			const partialBinding = pinFinalizationDirectory(
				fs,
				join(directorySet.parent.canonicalPath, `.${input.incidentId}.partial-${analysis.finalizationId}`),
				partialDirectory,
			);
			if (!partialBinding) throw new Error("Partial finalization directory binding changed");
			const incidentBinding = directorySet.member;
			if (!incidentBinding) throw new Error("Incident directory binding changed");
			publicationBindings = {
				parent: directorySet.parent,
				incident: incidentBinding,
				partial: partialBinding,
			};
			fault("after_partial_mkdir_before_parent_fsync");
			fsyncDirectory(fs, operationIncidentsDirectory);

			const intent = jsonBytes({
				schemaVersion: 1,
				kind: "incident_recorder_finalization_intent",
				operationId: sha256(`${analysis.finalizationId}\0publish-v1`),
				finalizationId: analysis.finalizationId,
				runIdentity: input.runIdentity,
				state: analysis.state,
			});
			if (publishImmutableFile(fs, partialDirectory, "finalization-intent.json", intent) === "conflict") {
				throw new Error("Incident finalization intent conflict");
			}
			fault("after_intent_durable_before_history");

			const history = jsonBytes({
				schemaVersion: 1,
				kind: "incident_recorder_run_history",
				finalizationId: analysis.finalizationId,
				runHistory: input.runHistory,
			});
			if (
				publishImmutableFile(fs, partialDirectory, "run-history.json", history, {
					afterWrite: () => fault("after_history_write_before_fsync"),
					afterFsync: () => fault("after_history_fsync_before_rename"),
					afterLink: () => fault("after_history_rename_before_directory_fsync"),
				}) === "conflict"
			) {
				throw new Error("Incident finalization history conflict");
			}

			const descriptorValue = {
				schemaVersion: 1,
				kind: "incident_recorder_finalization_descriptor",
				finalizationId: analysis.finalizationId,
				state: analysis.state,
				reasons: analysis.reasons,
				runIdentity: input.runIdentity,
				classification: input.classification,
				exit: input.exit,
				supervisorExitAnchorWallTimeMs: analysis.supervisorExitAnchorWallTimeMs,
				retentionAnchorWallTimeMs: analysis.retentionAnchorWallTimeMs,
				terminalExpectations: input.terminalExpectations,
				completeProjectionLeaseAvailable: Boolean(
					input.assertProjectionLeaseUsable && input.releaseProjectionLease,
				),
				stoppedTarget: input.stoppedTarget,
				wrapperLoss: input.wrapperLoss,
				serviceSeal: input.serviceSeal,
			};
			const descriptor = jsonBytes(descriptorValue);
			if (
				publishImmutableFile(fs, partialDirectory, "finalization-descriptor.json", descriptor, {
					afterWrite: () => fault("after_descriptor_write_before_fsync"),
					afterFsync: () => fault("after_descriptor_fsync_before_rename"),
					afterLink: () => fault("after_descriptor_rename_before_directory_fsync"),
				}) === "conflict"
			) {
				throw new Error("Incident finalization descriptor conflict");
			}
			const summary = jsonBytes({
				schemaVersion: 1,
				finalizationId: analysis.finalizationId,
				runId: input.runIdentity.runId,
				runToken: input.runIdentity.runToken,
				classification: input.classification.value,
				causeLayer: input.classification.causeLayer,
				code: input.exit.code,
				signal: input.exit.signal,
				state: analysis.state,
				stoppedTargetCaptureComplete: input.stoppedTarget.captureState === "complete",
				finalized:
					analysis.retentionAnchorWallTimeMs === null
						? null
						: new Date(analysis.retentionAnchorWallTimeMs).toISOString(),
				supervisorExitAnchorWallTimeMs: analysis.supervisorExitAnchorWallTimeMs,
				retentionAnchorWallTimeMs: analysis.retentionAnchorWallTimeMs,
			});
			if (publishImmutableFile(fs, partialDirectory, "summary.json", summary) === "conflict") {
				throw new Error("Incident finalization summary conflict");
			}
			const prepared = [
				["finalization-intent.json", intent],
				["run-history.json", history],
				["finalization-descriptor.json", descriptor],
				["summary.json", summary],
			] as const;
			const manifestValue: FinalizationManifest = {
				schemaVersion: 1,
				kind: "incident_recorder_finalization_manifest",
				finalizationId: analysis.finalizationId,
				state: analysis.state,
				reasons: analysis.reasons,
				runIdentity: input.runIdentity,
				supervisorExitAnchorWallTimeMs: analysis.supervisorExitAnchorWallTimeMs,
				retentionAnchorWallTimeMs: analysis.retentionAnchorWallTimeMs,
				files: prepared.map(([name, bytes]) => ({ name, bytes: bytes.length, sha256: sha256(bytes) })),
			};
			const manifest = jsonBytes(manifestValue);
			if (
				publishImmutableFile(fs, partialDirectory, "finalization-manifest.json", manifest, {
					afterFsync: () => fault("after_manifest_fsync_before_rename"),
					afterLink: () => fault("after_manifest_rename_before_directory_fsync"),
				}) === "conflict"
			) {
				throw new Error("Incident finalization manifest conflict");
			}
			fsyncDirectory(fs, partialDirectory);
			fault("after_prepared_directory_fsync_before_lease_release");
			if (leaseHeld) {
				releaseLease(input);
				leaseHeld = false;
			}
			fault("after_projection_lease_release_before_publish");
			fault("after_staging_directory_fsync_before_publish");

			const preparedPartialBinding = publicationBindings?.partial;
			if (!preparedPartialBinding) {
				throw new Error("Prepared incident finalization directory binding changed");
			}
			const preparedDirectorySet: PinnedIncidentDirectorySet = {
				parent: directorySet.parent,
				member: preparedPartialBinding,
				memberOperationPath: preparedPartialBinding.operationPath,
				canonicalMemberPath: join(directorySet.parent.canonicalPath, basename(partialDirectory)),
				memberState: "present",
			};
			validatePinnedFinalizationDirectorySet(fs, preparedDirectorySet);
			const preparedInspection = inspectPublishedIncidentFinalizationBound(
				{ incidentsDirectory: input.incidentsDirectory, incidentId: basename(partialDirectory) },
				fs,
				preparedDirectorySet,
			);
			validatePinnedFinalizationDirectorySet(fs, preparedDirectorySet);
			if (preparedInspection.state === "pending" || preparedInspection.finalizationId !== analysis.finalizationId) {
				throw new Error("Prepared incident finalization readback did not match");
			}
			const published = publishPreparedIncidentFinalization(
				fs,
				{ incidentsDirectory: input.incidentsDirectory, incidentId: input.incidentId },
				partialDirectory,
				preparedInspection,
				{
					afterManifestLink: () => fault("after_publish_rename_before_parent_fsync"),
					afterParentFsync: () => fault("after_publish_parent_fsync_before_source_release"),
				},
				publicationBindings,
			);
			if (
				cleanupExactPreparedStage(
					fs,
					{ incidentsDirectory: input.incidentsDirectory, incidentId: input.incidentId },
					published.inspection,
					undefined,
					publicationBindings,
				) === "pending"
			) {
				throw new FinalizationDirectoryBindingError("finalization_partial_directory_detached");
			}
			validatePinnedFinalizationDirectorySet(fs, directorySet);
			return {
				state: published.inspection.state,
				finalizationId: published.inspection.finalizationId,
				reasons: published.inspection.manifest.reasons,
				supervisorExitAnchorWallTimeMs: published.inspection.supervisorExitAnchorWallTimeMs,
				retentionAnchorWallTimeMs: published.inspection.retentionAnchorWallTimeMs,
				publication: published.publication,
				incidentDirectory,
				...(published.inspection.manifest.kind === "incident_recorder_finalization_conflict_manifest"
					? { reason: "prepared_publication_conflict" }
					: {}),
			};
		} catch {
			return ambiguousResult(analysis, incidentDirectory);
		}
	} catch {
		return ambiguousResult(analysis, incidentDirectory);
	} finally {
		closePinnedFinalizationDirectory(fs, publicationBindings?.partial);
		closePinnedFinalizationDirectory(fs, directorySet?.member);
		closePinnedFinalizationDirectory(fs, directorySet?.parent);
	}
}

function recoverPublishedIncidentFinalizationBound(
	input: { incidentsDirectory: string; incidentId: string; expectedFinalizationId?: string },
	fs: IncidentRecorderFinalizationFileSystem,
	directorySet: PinnedIncidentDirectorySet,
): IncidentRecorderPublishedFinalizationInspection {
	let preexistingPreparedStageNames = new Set<string>();
	try {
		preexistingPreparedStageNames = new Set(fs.readdir(directorySet.parent.operationPath));
	} catch {}
	let inspected = inspectPublishedIncidentFinalizationBound(input, fs, directorySet);
	let recoveryFinalizationId = input.expectedFinalizationId;
	let recoveryFromClaim = false;
	const inspectCandidate = (
		candidate: string,
	):
		| {
				binding: PinnedFinalizationDirectory;
				inspection: ProvenPublishedFinalization;
		  }
		| undefined => {
		const canonicalPath = join(directorySet.parent.canonicalPath, candidate);
		const operationPath = join(directorySet.parent.operationPath, candidate);
		const binding = pinFinalizationDirectory(fs, canonicalPath, operationPath);
		if (!binding) return undefined;
		const preparedSet: PinnedIncidentDirectorySet = {
			parent: directorySet.parent,
			member: binding,
			memberOperationPath: binding.operationPath,
			canonicalMemberPath: canonicalPath,
			memberState: "present",
		};
		const inspection = inspectPublishedIncidentFinalizationBound(
			{ incidentsDirectory: input.incidentsDirectory, incidentId: candidate },
			fs,
			preparedSet,
		);
		if (inspection.state === "pending") {
			closePinnedFinalizationDirectory(fs, binding);
			return undefined;
		}
		return { binding, inspection };
	};
	if (
		inspected.state !== "pending" &&
		input.expectedFinalizationId !== undefined &&
		SHA256.test(input.expectedFinalizationId) &&
		input.expectedFinalizationId !== inspected.finalizationId
	) {
		const expectedRunId = input.incidentId.slice(-36);
		const candidate = `.${input.incidentId}.partial-${input.expectedFinalizationId}`;
		const prepared = inspectCandidate(candidate);
		if (
			prepared &&
			prepared.inspection.finalizationId === input.expectedFinalizationId &&
			CANONICAL_UUID.test(expectedRunId) &&
			prepared.inspection.runId === expectedRunId &&
			directorySet.member
		) {
			if (
				cleanupSupersededPreparedDirectory(
					fs,
					directorySet.parent.operationPath,
					prepared.binding.operationPath,
					prepared.inspection,
					{
						parent: directorySet.parent,
						incident: directorySet.member,
						partial: prepared.binding,
					},
				) === "pending"
			) {
				return { state: "pending", reason: "finalization_partial_directory_detached" };
			}
		}
		if (prepared) closePinnedFinalizationDirectory(fs, prepared.binding);
		return inspected;
	}
	if (inspected.state === "pending") {
		if (directorySet.member) {
			const privateAuthorityDirectory = join(
				directorySet.member.operationPath,
				FINALIZATION_PRIVATE_AUTHORITY_DIRECTORY_NAME,
			);
			if (privateDirectoryIsUsable(fs, privateAuthorityDirectory)) {
				const claimBytes = readPrivatePublishedExact(
					fs,
					join(privateAuthorityDirectory, FINALIZATION_PRIVATE_AUTHORITY_CLAIM_NAME),
					MAX_FINALIZATION_CONFLICT_RECORD_BYTES,
				);
				const claim = claimBytes ? parseAuthorityClaim(claimBytes) : undefined;
				if (claim && claim.runIdentity.runId === input.incidentId.slice(-36)) {
					recoveryFinalizationId = claim.finalizationId;
					recoveryFromClaim = true;
				}
			}
		}
		if (recoveryFinalizationId === undefined) return inspected;
		if (!SHA256.test(recoveryFinalizationId)) {
			return { state: "pending", reason: "expected_finalization_id_invalid" };
		}
		const expectedRunId = input.incidentId.slice(-36);
		const prefix = `.${input.incidentId}.partial-`;
		const candidate = `${prefix}${recoveryFinalizationId}`;
		const prepared = inspectCandidate(candidate);
		if (
			!prepared ||
			prepared.inspection.finalizationId !== candidate.slice(prefix.length) ||
			!CANONICAL_UUID.test(expectedRunId) ||
			prepared.inspection.runId !== expectedRunId
		) {
			if (prepared) closePinnedFinalizationDirectory(fs, prepared.binding);
			return recoveryFromClaim
				? { state: "pending", reason: "finalization_claimed_prepared_stage_missing_or_invalid" }
				: inspected;
		}
		try {
			if (!directorySet.member) {
				ensureDirectory(fs, directorySet.memberOperationPath);
				const member = pinFinalizationDirectory(
					fs,
					directorySet.canonicalMemberPath,
					directorySet.memberOperationPath,
				);
				if (!member) {
					closePinnedFinalizationDirectory(fs, prepared.binding);
					return {
						state: "pending",
						reason: "finalization_incident_directory_detached",
					};
				}
				directorySet.member = member;
				directorySet.memberOperationPath = member.operationPath;
				directorySet.memberState = "present";
			}
			validatePinnedFinalizationDirectorySet(fs, directorySet);
			const published = publishPreparedIncidentFinalization(
				fs,
				{ incidentsDirectory: input.incidentsDirectory, incidentId: input.incidentId },
				prepared.binding.operationPath,
				prepared.inspection,
				{},
				{
					parent: directorySet.parent,
					incident: directorySet.member,
					partial: prepared.binding,
				},
			);
			inspected = published.inspection;
		} catch (error) {
			if (error instanceof FinalizationDirectoryBindingError) {
				closePinnedFinalizationDirectory(fs, prepared.binding);
				return { state: "pending", reason: error.reason };
			}
			const refreshed = inspectPublishedIncidentFinalizationBound(input, fs, directorySet);
			if (refreshed.state !== "pending") {
				inspected = refreshed;
			} else if (refreshed.reason === "finalization_authority_claim_pending") {
				closePinnedFinalizationDirectory(fs, prepared.binding);
				return {
					state: "pending",
					reason: "finalization_claimed_prepared_publication_ambiguous",
				};
			} else {
				inspected = refreshed;
			}
		}
		closePinnedFinalizationDirectory(fs, prepared.binding);
	}
	if (inspected.state === "pending") return inspected;
	if (!directorySet.member) {
		return {
			state: "pending",
			reason: "finalization_incident_directory_invalid",
		};
	}
	try {
		validatePinnedFinalizationDirectorySet(fs, directorySet);
		fsyncDirectory(fs, directorySet.member.operationPath);
		fsyncDirectory(fs, directorySet.parent.operationPath);
		validatePinnedFinalizationDirectorySet(fs, directorySet);
	} catch {
		return { state: "pending", reason: "published_finalization_durability_unconfirmed" };
	}
	const cleanupBindings: PreparedPublicationDirectoryBindings = {
		parent: directorySet.parent,
		incident: directorySet.member,
	};
	const fallbackPartialDirectory = join(
		directorySet.parent.operationPath,
		`.${input.incidentId}.partial-${inspected.finalizationId}`,
	);
	const retained = preexistingPreparedStageNames.has(basename(fallbackPartialDirectory))
		? bindExistingPreparedStage(fs, cleanupBindings, fallbackPartialDirectory)
		: { bindings: cleanupBindings };
	try {
		if (cleanupExactPreparedStage(fs, input, inspected, undefined, retained.bindings) === "pending") {
			return { state: "pending", reason: "finalization_partial_directory_detached" };
		}
	} catch {
	} finally {
		closePinnedFinalizationDirectory(fs, retained.partial);
	}
	return inspected;
}

export function recoverPublishedIncidentFinalization(
	input: { incidentsDirectory: string; incidentId: string; expectedFinalizationId?: string },
	options: IncidentRecorderFinalizerOptions = {},
): IncidentRecorderPublishedFinalizationInspection {
	const fs = combinedFileSystem(options);
	const set = pinFinalizationIncidentDirectorySet(fs, input.incidentsDirectory, input.incidentId);
	if (!set) return inspectPublishedIncidentFinalization(input, { fs });
	try {
		validatePinnedFinalizationDirectorySet(fs, set);
		const inspected = recoverPublishedIncidentFinalizationBound(input, fs, set);
		validatePinnedFinalizationDirectorySet(fs, set);
		return exposePinnedInspectionDirectory(inspected, set);
	} catch (error) {
		if (error instanceof FinalizationDirectoryBindingError) {
			return { state: "pending", reason: error.reason };
		}
		try {
			const refreshed = inspectPublishedIncidentFinalizationBound(input, fs, set);
			return exposePinnedInspectionDirectory(refreshed, set);
		} catch {
			return { state: "pending", reason: "published_finalization_recovery_ambiguous" };
		}
	} finally {
		closePinnedFinalizationDirectory(fs, set.member);
		closePinnedFinalizationDirectory(fs, set.parent);
	}
}

export type IncidentFinalizationSealPersistenceResult =
	| { state: "applied" | "noop"; authoritativeBytesMatch: true }
	| { state: "conflict"; authoritativeBytesMatch: false }
	| { state: "ambiguous"; authoritativeBytesMatch: boolean };

export function persistIncidentFinalizationSeal(
	input: { path: string; value: unknown },
	options: IncidentRecorderFinalizerOptions = {},
): IncidentFinalizationSealPersistenceResult {
	const fs = combinedFileSystem(options);
	const bytes = jsonBytes(input.value);
	const parent = dirname(input.path);
	try {
		ensureDirectory(fs, parent);
		fsyncDirectory(fs, dirname(parent));
		const result = publishImmutableFile(fs, parent, basename(input.path), bytes);
		if (result === "conflict") return { state: "conflict", authoritativeBytesMatch: false };
		return { state: result, authoritativeBytesMatch: true };
	} catch {
		return {
			state: "ambiguous",
			authoritativeBytesMatch: readBoundedExact(fs, input.path)?.equals(bytes) === true,
		};
	}
}
