export const EVIDENCE_BATCH_ROWS = 256;
export const EVIDENCE_BATCH_BYTES = 1024 * 1024;
export const EVIDENCE_PAGE_ROWS = 1000;
export const EVIDENCE_HISTORY_MS = 3 * 86_400_000;
export const EVIDENCE_INCIDENT_MS = 14 * 86_400_000;
export const EVIDENCE_RUNTIME_ROLE_LIMIT = 4096;

export interface EvidenceReference {
	source: string;
	occurrenceId: string;
}
export type EvidenceChannelResult =
	| { status: "incident"; incident: EvidenceIncident }
	| { status: "ignored" | "identity_unavailable" | "capacity" };
export interface EvidenceRuntimeProvider {
	identifier: string;
	clockTicksPerSecond: number;
}
export interface EvidenceRuntimeBoot {
	/** Caller must obtain this from the running kernel, not journal history. */
	bootId: string;
	observedAtMs: number;
	limit?: number;
}
export interface EvidenceRuntimeRole {
	role: "supervisor" | "worker" | "forkserver" | "kernel";
	roleInstanceId: string;
	bootId: string;
	pidNamespace: string;
	pid: number;
	processStartTicks: string;
	clockTicksPerSecond: number;
	observerBoottimeOffsetNs: "0";
	proof: EvidenceReference;
}
export interface EvidenceRuntimeExit {
	source: string;
	occurrenceId: string;
	initPid: number;
	processStartBoottimeNs: string;
}
export type EvidenceRuntimeClaimResult =
	| { status: "registered" | "replayed"; claim: EvidenceRuntimeRole }
	| { status: "not_anchor" | "invalid_anchor" | "capacity" | "conflict" };
export type EvidenceRuntimeExitResult =
	| { status: "matched"; runtimeRole: EvidenceRuntimeRole & { exit: EvidenceRuntimeExit }; rawExitCode: number }
	| { status: "not_exit" | "invalid_exit" | "unregistered" | "conflict"; bootId?: string };

export interface EvidenceOccurrenceInput {
	id: string;
	wallTimeMs: number;
	monotonicNs?: string;
	kind: string;
	payload: Uint8Array;
}
export interface EvidenceOccurrence extends EvidenceOccurrenceInput {
	source: string;
	sequence: number;
}
export interface EvidenceBatch {
	batchId: string;
	source: string;
	expectedCursor: string | null;
	cursor: string;
	occurrences: EvidenceOccurrenceInput[];
}
export interface EvidenceIngestResult {
	inserted: number;
	cursor: string;
	replayed: boolean;
}
export interface EvidenceWindow {
	startMs: number;
	endMs: number;
	/** Indexed raw journal/gap input only; excludes reports and artifact metadata. */
	causalOnly?: boolean;
	/** Opaque keyset cursor; pages are ordered by wall time, then ingestion sequence. */
	afterSequence?: number;
	limit?: number;
}
export interface EvidencePage {
	occurrences: EvidenceOccurrence[];
	nextSequence?: number;
	/** readOccurrences only: sequences no longer available to the consumer. */
	missingRanges?: Array<{ firstSequence: number; lastSequence: number }>;
	/** readOccurrences only: acknowledge after durably recording events and missing ranges. */
	throughSequence?: number;
}
export interface EvidenceIncidentInput {
	id: string;
	triggerTimeMs: number;
	windowStartMs: number;
	windowEndMs: number;
	coverage: Record<string, unknown>;
	limitations: string[];
}
export type EvidenceIncidentState = "capturing" | "published" | "complete" | "limited";
export interface EvidenceIncident extends EvidenceIncidentInput {
	/** Advances transactionally when causal input changes inside this window. */
	evidenceRevision: number;
	state: EvidenceIncidentState;
	createdAtMs: number;
	expiresAtMs: number;
}
export interface EvidenceIncidentUpdate {
	state?: EvidenceIncidentState;
	coverage?: Record<string, unknown>;
	limitations?: string[];
}
export interface EvidenceArtifact {
	id: string;
	/** Relative to the recorder's artifact root; never a native provider history path. */
	path: string;
	format: string;
	bytes?: number;
	sha256?: string;
	allocatedBytes?: number;
	contentId?: number;
}
export interface EvidenceFileIdentity {
	device: string;
	inode: string;
	size: number;
	mtimeNs: string;
}
export interface EvidenceArtifactCandidate extends EvidenceArtifact {
	contentId: number;
}
export interface EvidenceArtifactSelection {
	kind: "unique" | "reuse";
	/** Stable file identity observed after exact comparison; hard links retain it. */
	identity: EvidenceFileIdentity;
}
export interface EvidenceArtifactCompletion {
	bytes: number;
	sha256: string;
	/** Measured max(content length, filesystem allocated blocks in bytes). */
	allocatedBytes: number;
	/** The executor records the staged inode after fsync; recovery must preserve replacements. */
	fileIdentity?: EvidenceFileIdentity;
}
export interface EvidenceOperationInput {
	id: string;
	incidentId: string;
	kind: "export" | "pin" | "delete";
	artifact: EvidenceArtifact;
}
export interface EvidenceOperation extends EvidenceOperationInput {
	state: "pending" | "ready";
	createdAtMs: number;
	/** Caller recorded complete staging bytes after file and directory fsync, before rename. */
	stagedAtMs?: number;
	stagingIdentity?: EvidenceFileIdentity;
	reservationBytes: number;
	/** One SQL-pinned alias at a time, never an unbounded candidate list. */
	candidate?: EvidenceArtifactCandidate;
	candidatesExhausted?: boolean;
	selection?: EvidenceArtifactSelection;
	reuseLimitations?: string[];
}
export interface EvidenceListOptions {
	afterId?: string;
	limit?: number;
}
export interface EvidenceRetentionResult {
	occurrences: number;
	payloads: number;
	receipts: number;
	incidents: number;
	operationsQueued: number;
	/** A full batch was consumed; call again to continue bounded maintenance. */
	more: boolean;
	maintenance?: { vacuumedPages: number; remainingFreePages: number; checkpointBusy: boolean };
}
export interface EvidenceStoreStats {
	occurrences: number;
	payloads: number;
	payloadBytes: number;
	incidents: number;
	operations: number;
	artifactBytes: number;
	artifactAllocatedBytes: number;
	reservedArtifactBytes: number;
	pendingArtifactOperations: number;
	sqliteVersion: string;
}
export interface EvidenceWorkerRequest {
	id: number;
	method: string;
	args: unknown[];
}
export interface EvidenceWorkerReply {
	id: number;
	result?: unknown;
	error?: string;
}
