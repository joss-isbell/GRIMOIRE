import { createHash, randomUUID } from "node:crypto";
import type { BigIntStats } from "node:fs";
import type { IncidentCasRootMutation } from "./incident-recorder-cas-transaction.js";
import type {
	IncidentRecorderLiveRunEventsCursor,
	IncidentRecorderRunHistoryEvent,
	IncidentRecorderStorageAccountingEffect,
	JournalOccurrenceReference,
	SegmentOccurrenceReference,
} from "./incident-recorder-compactor.js";
import {
	type IncidentFinalizationSealPrepared,
	persistIncidentFinalizationSealWithinRoot,
	prepareIncidentFinalizationSeal,
} from "./incident-recorder-finalizer.js";

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const UNSIGNED_64 = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_INTENT_BYTES = 16 * 1024 * 1024;
const MAX_STRING_BYTES = 256;
const MAX_EVENT_TEXT_BYTES = 255;
const MAX_REFERENCE_BYTES = 4096;
const MAX_CURSOR_BYTES = 1024;

export const INCIDENT_RECORDER_LIVE_TRIGGER_INTENT_SCHEMA_VERSION = 1 as const;
export const INCIDENT_RECORDER_LIVE_TRIGGER_INTENT_KIND = "live_incident_trigger_intent" as const;

export type IncidentRecorderLiveTriggerIntentClassification = "worker_response_hang" | "kernel_unexpected_exit";

export interface IncidentRecorderLiveTriggerIntentWorkerCause {
	requestId: string | null;
	requestType: string | null;
	durationMs: number | null;
}

export interface IncidentRecorderLiveTriggerIntentKernelCause {
	sessionId: string | null;
	kernelInstanceId: string | null;
	kernelPid: number | null;
	kernelProcessStartId: string | null;
	launchMode: "direct" | "fork" | null;
	crashPhase: "resolving_ports" | "ready_probe" | "idle" | "executing" | null;
	requestMsgId: string | null;
	code: number | null;
	signal: string | null;
	reason: "process_exit" | "forkserver_unavailable" | null;
}

export type IncidentRecorderLiveTriggerIntentCause =
	| IncidentRecorderLiveTriggerIntentWorkerCause
	| IncidentRecorderLiveTriggerIntentKernelCause;

export interface IncidentRecorderLiveTriggerIntentTrigger {
	producerId: string;
	occurrenceId: string;
	eventType: "worker_request_end" | "kernel_unexpected_exit";
	source: string;
	semanticFingerprint: string;
	occurrenceReference: JournalOccurrenceReference;
	anchorWallTimeMs: number;
	eventMonotonicNs: string;
	producerOrder: string[];
	wrapperOrder: string[];
}

export interface IncidentRecorderLiveTriggerIntentTarget {
	pid: number;
	processStartId: string;
}

export interface IncidentRecorderLiveTriggerIntentReservedOccurrenceIds {
	captureCompletionOccurrenceId: string;
	committedFenceOccurrenceId: string;
}

export interface IncidentRecorderLiveTriggerIntent {
	schemaVersion: typeof INCIDENT_RECORDER_LIVE_TRIGGER_INTENT_SCHEMA_VERSION;
	kind: typeof INCIDENT_RECORDER_LIVE_TRIGGER_INTENT_KIND;
	runId: string;
	runToken: string;
	trigger: IncidentRecorderLiveTriggerIntentTrigger;
	classification: IncidentRecorderLiveTriggerIntentClassification;
	cause: IncidentRecorderLiveTriggerIntentCause;
	target: IncidentRecorderLiveTriggerIntentTarget;
	scanStartCursor: IncidentRecorderLiveRunEventsCursor | null;
	reservedOccurrenceIds: IncidentRecorderLiveTriggerIntentReservedOccurrenceIds;
}

export interface IncidentRecorderLiveTriggerIntentContext {
	runId: string;
	runToken: string;
	targetPid: number;
	targetProcessStartId: string;
	scanStartCursor?: IncidentRecorderLiveRunEventsCursor | null;
}

export interface IncidentRecorderLiveTriggerIntentCandidate {
	runId: string;
	runToken: string;
	trigger: IncidentRecorderLiveTriggerIntentTrigger;
	classification: IncidentRecorderLiveTriggerIntentClassification;
	cause: IncidentRecorderLiveTriggerIntentCause;
	target: IncidentRecorderLiveTriggerIntentTarget;
	scanStartCursor: IncidentRecorderLiveRunEventsCursor | null;
}

export interface IncidentRecorderLiveTriggerIntentStorageContext {
	reserve(bytes: number, entries: number, inodes: number): unknown;
	effects: IncidentRecorderStorageAccountingEffect[];
}

export type IncidentRecorderLiveTriggerIntentPersistenceResult =
	| {
			state: "applied" | "replayed";
			fileName: string;
			intent: IncidentRecorderLiveTriggerIntent;
			peakStorageBytes: number;
			effects: readonly IncidentRecorderStorageAccountingEffect[];
	  }
	| {
			state: "conflict" | "ambiguous";
			fileName: string;
			reason: string;
			peakStorageBytes: number;
			effects: readonly IncidentRecorderStorageAccountingEffect[];
	  };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	const actual = Object.keys(value);
	return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function isCanonicalUuid(value: unknown): value is string {
	return typeof value === "string" && CANONICAL_UUID.test(value);
}

function isCanonicalV4(value: unknown): value is string {
	return typeof value === "string" && UUID_V4.test(value);
}

function isBoundedString(value: unknown, maximumBytes = MAX_STRING_BYTES): value is string {
	return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= maximumBytes;
}

function isUnsigned64(value: unknown): value is string {
	if (typeof value !== "string" || !UNSIGNED_64.test(value)) return false;
	try {
		return BigInt(value) <= (1n << 64n) - 1n;
	} catch {
		return false;
	}
}

function isSafeNonNegativeInteger(value: unknown): value is number {
	return Number.isSafeInteger(value) && Number(value) >= 0;
}

function isPositivePid(value: unknown): value is number {
	return Number.isSafeInteger(value) && Number(value) > 0;
}

function isSequenceArray(value: unknown): value is string[] {
	return Array.isArray(value) && value.length > 0 && value.every((sequence) => isUnsigned64(sequence));
}

function cloneOccurrenceReference(value: JournalOccurrenceReference): JournalOccurrenceReference {
	if (typeof value === "string") return value;
	return {
		kind: "segment",
		locator: { ...value.locator },
	};
}

function isSegmentLocator(value: unknown): value is SegmentOccurrenceReference["locator"] {
	if (!isRecord(value)) return false;
	return (
		exactKeys(value, [
			"version",
			"segmentId",
			"segmentSequence",
			"ordinal",
			"offset",
			"frameBytes",
			"payloadBytes",
			"payloadSha256",
		]) &&
		value.version === 1 &&
		isBoundedString(value.segmentId, 128) &&
		/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value.segmentId) &&
		isSafeNonNegativeInteger(value.segmentSequence) &&
		isSafeNonNegativeInteger(value.ordinal) &&
		isSafeNonNegativeInteger(value.offset) &&
		isSafeNonNegativeInteger(value.frameBytes) &&
		isSafeNonNegativeInteger(value.payloadBytes) &&
		value.payloadBytes <= value.frameBytes &&
		typeof value.payloadSha256 === "string" &&
		SHA256.test(value.payloadSha256)
	);
}

function isOccurrenceReference(value: unknown): value is JournalOccurrenceReference {
	if (typeof value === "string") return value.length > 0 && Buffer.byteLength(value, "utf8") <= MAX_REFERENCE_BYTES;
	if (!isRecord(value)) return false;
	return exactKeys(value, ["kind", "locator"]) && value.kind === "segment" && isSegmentLocator(value.locator);
}

function isCursor(value: unknown, runId: string): value is IncidentRecorderLiveRunEventsCursor {
	if (!isRecord(value)) return false;
	return (
		exactKeys(value, ["version", "runId", "filterSha256", "segmentSequence", "ordinal"]) &&
		value.version === 1 &&
		value.runId === runId &&
		isCanonicalUuid(value.runId) &&
		typeof value.filterSha256 === "string" &&
		SHA256.test(value.filterSha256) &&
		isSafeNonNegativeInteger(value.segmentSequence) &&
		isSafeNonNegativeInteger(value.ordinal) &&
		Buffer.byteLength(JSON.stringify(value), "utf8") <= MAX_CURSOR_BYTES
	);
}

function isWorkerCause(value: unknown): value is IncidentRecorderLiveTriggerIntentWorkerCause {
	if (!isRecord(value) || !exactKeys(value, ["requestId", "requestType", "durationMs"])) return false;
	return (
		(value.requestId === null || isBoundedString(value.requestId)) &&
		(value.requestType === null || isBoundedString(value.requestType)) &&
		(value.durationMs === null ||
			(typeof value.durationMs === "number" && Number.isFinite(value.durationMs) && value.durationMs >= 0))
	);
}

function isKernelCause(value: unknown): value is IncidentRecorderLiveTriggerIntentKernelCause {
	if (
		!isRecord(value) ||
		!exactKeys(value, [
			"sessionId",
			"kernelInstanceId",
			"kernelPid",
			"kernelProcessStartId",
			"launchMode",
			"crashPhase",
			"requestMsgId",
			"code",
			"signal",
			"reason",
		])
	)
		return false;
	return (
		(value.sessionId === null || isBoundedString(value.sessionId)) &&
		(value.kernelInstanceId === null || isBoundedString(value.kernelInstanceId)) &&
		(value.kernelPid === null || isPositivePid(value.kernelPid)) &&
		(value.kernelProcessStartId === null || isBoundedString(value.kernelProcessStartId)) &&
		(value.launchMode === null || value.launchMode === "direct" || value.launchMode === "fork") &&
		(value.crashPhase === null ||
			value.crashPhase === "resolving_ports" ||
			value.crashPhase === "ready_probe" ||
			value.crashPhase === "idle" ||
			value.crashPhase === "executing") &&
		(value.requestMsgId === null || isBoundedString(value.requestMsgId)) &&
		(value.code === null || Number.isSafeInteger(value.code)) &&
		(value.signal === null || isBoundedString(value.signal)) &&
		(value.reason === null || value.reason === "process_exit" || value.reason === "forkserver_unavailable")
	);
}

function isIntentTrigger(value: unknown): value is IncidentRecorderLiveTriggerIntentTrigger {
	if (
		!isRecord(value) ||
		!exactKeys(value, [
			"producerId",
			"occurrenceId",
			"eventType",
			"source",
			"semanticFingerprint",
			"occurrenceReference",
			"anchorWallTimeMs",
			"eventMonotonicNs",
			"producerOrder",
			"wrapperOrder",
		])
	)
		return false;
	return (
		isCanonicalUuid(value.producerId) &&
		isCanonicalUuid(value.occurrenceId) &&
		(value.eventType === "worker_request_end" || value.eventType === "kernel_unexpected_exit") &&
		isBoundedString(value.source, MAX_EVENT_TEXT_BYTES) &&
		typeof value.semanticFingerprint === "string" &&
		SHA256.test(value.semanticFingerprint) &&
		isOccurrenceReference(value.occurrenceReference) &&
		isSafeNonNegativeInteger(value.anchorWallTimeMs) &&
		isUnsigned64(value.eventMonotonicNs) &&
		isSequenceArray(value.producerOrder) &&
		isSequenceArray(value.wrapperOrder) &&
		value.producerOrder.length === value.wrapperOrder.length
	);
}

function isIntentTarget(value: unknown): value is IncidentRecorderLiveTriggerIntentTarget {
	if (!isRecord(value) || !exactKeys(value, ["pid", "processStartId"])) return false;
	return isPositivePid(value.pid) && isBoundedString(value.processStartId);
}

function isReservedOccurrenceIds(value: unknown): value is IncidentRecorderLiveTriggerIntentReservedOccurrenceIds {
	if (!isRecord(value) || !exactKeys(value, ["captureCompletionOccurrenceId", "committedFenceOccurrenceId"]))
		return false;
	return (
		isCanonicalV4(value.captureCompletionOccurrenceId) &&
		isCanonicalV4(value.committedFenceOccurrenceId) &&
		value.captureCompletionOccurrenceId !== value.committedFenceOccurrenceId
	);
}

function intentClassificationForTrigger(eventType: string): IncidentRecorderLiveTriggerIntentClassification {
	return eventType === "worker_request_end" ? "worker_response_hang" : "kernel_unexpected_exit";
}

/** Validate the complete closed on-disk intent schema without mutating the value. */
export function isIncidentRecorderLiveTriggerIntent(value: unknown): value is IncidentRecorderLiveTriggerIntent {
	if (
		!isRecord(value) ||
		!exactKeys(value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"trigger",
			"classification",
			"cause",
			"target",
			"scanStartCursor",
			"reservedOccurrenceIds",
		])
	)
		return false;
	if (
		value.schemaVersion !== INCIDENT_RECORDER_LIVE_TRIGGER_INTENT_SCHEMA_VERSION ||
		value.kind !== INCIDENT_RECORDER_LIVE_TRIGGER_INTENT_KIND ||
		!isCanonicalUuid(value.runId) ||
		!isCanonicalUuid(value.runToken) ||
		!isIntentTrigger(value.trigger) ||
		!isIntentTarget(value.target) ||
		(value.scanStartCursor !== null && !isCursor(value.scanStartCursor, value.runId)) ||
		!isReservedOccurrenceIds(value.reservedOccurrenceIds) ||
		value.classification !== intentClassificationForTrigger(value.trigger.eventType)
	)
		return false;
	return value.classification === "worker_response_hang" ? isWorkerCause(value.cause) : isKernelCause(value.cause);
}

export function validateIncidentRecorderLiveTriggerIntent(
	value: unknown,
): asserts value is IncidentRecorderLiveTriggerIntent {
	if (!isIncidentRecorderLiveTriggerIntent(value))
		throw new TypeError("Invalid incident recorder live trigger intent");
}

export function isIncidentRecorderLiveTriggerIntentCandidate(
	value: unknown,
): value is IncidentRecorderLiveTriggerIntentCandidate {
	if (
		!isRecord(value) ||
		!exactKeys(value, ["runId", "runToken", "trigger", "classification", "cause", "target", "scanStartCursor"])
	)
		return false;
	if (
		!isCanonicalUuid(value.runId) ||
		!isCanonicalUuid(value.runToken) ||
		!isIntentTrigger(value.trigger) ||
		!isIntentTarget(value.target) ||
		(value.scanStartCursor !== null && !isCursor(value.scanStartCursor, value.runId)) ||
		value.classification !== intentClassificationForTrigger(value.trigger.eventType)
	)
		return false;
	return value.classification === "worker_response_hang" ? isWorkerCause(value.cause) : isKernelCause(value.cause);
}

export function validateIncidentRecorderLiveTriggerIntentCandidate(
	value: unknown,
): asserts value is IncidentRecorderLiveTriggerIntentCandidate {
	if (!isIncidentRecorderLiveTriggerIntentCandidate(value))
		throw new TypeError("Invalid incident recorder live trigger intent candidate");
}

export function parseIncidentRecorderLiveTriggerIntent(value: string | Uint8Array): IncidentRecorderLiveTriggerIntent {
	const bytes = Buffer.from(value);
	if (!Buffer.from(bytes.toString("utf8"), "utf8").equals(bytes))
		throw new TypeError("Invalid incident recorder live trigger intent UTF-8");
	let parsed: unknown;
	try {
		parsed = JSON.parse(bytes.toString("utf8"));
	} catch {
		throw new TypeError("Invalid incident recorder live trigger intent JSON");
	}
	validateIncidentRecorderLiveTriggerIntent(parsed);
	return deepFreeze(parsed);
}

function normalizeOptionalString(metadata: Record<string, unknown>, key: string): string | null {
	const value = metadata[key];
	return isBoundedString(value) ? value : null;
}

function normalizeOptionalDuration(metadata: Record<string, unknown>, key: string): number | null {
	const value = metadata[key];
	return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function normalizeOptionalPid(metadata: Record<string, unknown>, key: string): number | null {
	const value = metadata[key];
	return isPositivePid(value) ? value : null;
}

function normalizeOptionalCode(metadata: Record<string, unknown>, key: string): number | null {
	const value = metadata[key];
	return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function workerCause(metadata: Record<string, unknown>): IncidentRecorderLiveTriggerIntentWorkerCause {
	return Object.freeze({
		requestId: normalizeOptionalString(metadata, "requestId"),
		requestType: normalizeOptionalString(metadata, "requestType"),
		durationMs: normalizeOptionalDuration(metadata, "durationMs"),
	});
}

function kernelCause(metadata: Record<string, unknown>): IncidentRecorderLiveTriggerIntentKernelCause {
	const launchMode = metadata.launchMode === "direct" || metadata.launchMode === "fork" ? metadata.launchMode : null;
	const crashPhase =
		metadata.crashPhase === "resolving_ports" ||
		metadata.crashPhase === "ready_probe" ||
		metadata.crashPhase === "idle" ||
		metadata.crashPhase === "executing"
			? metadata.crashPhase
			: null;
	const reason =
		metadata.reason === "process_exit" || metadata.reason === "forkserver_unavailable" ? metadata.reason : null;
	return Object.freeze({
		sessionId: normalizeOptionalString(metadata, "sessionId"),
		kernelInstanceId: normalizeOptionalString(metadata, "kernelInstanceId"),
		kernelPid: normalizeOptionalPid(metadata, "kernelPid"),
		kernelProcessStartId: normalizeOptionalString(metadata, "kernelProcessStartId"),
		launchMode,
		crashPhase,
		requestMsgId: normalizeOptionalString(metadata, "requestMsgId"),
		code: normalizeOptionalCode(metadata, "code"),
		signal: normalizeOptionalString(metadata, "signal"),
		reason,
	});
}

function validEventIdentityAndTimestamp(
	event: IncidentRecorderRunHistoryEvent,
	context: IncidentRecorderLiveTriggerIntentContext,
): void {
	if (!isCanonicalUuid(context.runId) || !isCanonicalUuid(context.runToken))
		throw new TypeError("Live trigger intent context run identity is invalid");
	if (!isPositivePid(context.targetPid) || !isBoundedString(context.targetProcessStartId))
		throw new TypeError("Live trigger intent target identity is invalid");
	if (
		!isRecord(event.identity) ||
		!isCanonicalUuid(event.identity.runId) ||
		!isCanonicalUuid(event.identity.runToken) ||
		!isCanonicalUuid(event.identity.producerId) ||
		!isCanonicalUuid(event.identity.occurrenceId) ||
		event.identity.runId !== context.runId ||
		event.identity.runToken !== context.runToken
	)
		throw new TypeError("Live trigger intent event identity does not match its context");
	const expectedIdentityKey = createHash("sha256")
		.update(
			`${event.identity.runId}\0${event.identity.runToken}\0${event.identity.producerId}\0${event.identity.occurrenceId}`,
			"utf8",
		)
		.digest("hex");
	if (event.identityKey !== expectedIdentityKey)
		throw new TypeError("Live trigger intent event identity key does not match its identity");
	if (
		typeof event.eventWallTimeMs !== "string" ||
		!isUnsigned64(event.eventWallTimeMs) ||
		BigInt(event.eventWallTimeMs) > BigInt(Number.MAX_SAFE_INTEGER) ||
		typeof event.eventMonotonicNs !== "string" ||
		!isUnsigned64(event.eventMonotonicNs)
	)
		throw new TypeError("Live trigger intent event timestamp is invalid");
	if (
		!isBoundedString(event.source, MAX_EVENT_TEXT_BYTES) ||
		!isBoundedString(event.semanticFingerprint, 64) ||
		!SHA256.test(event.semanticFingerprint)
	)
		throw new TypeError("Live trigger intent event binding is invalid");
	if (!isOccurrenceReference(event.occurrenceReference))
		throw new TypeError("Live trigger intent occurrence reference is invalid");
	if (
		!isSequenceArray(event.producerOrder) ||
		!isSequenceArray(event.wrapperOrder) ||
		event.producerOrder.length !== event.wrapperOrder.length
	)
		throw new TypeError("Live trigger intent event order is invalid");
}

function normalizedCursor(
	cursor: IncidentRecorderLiveRunEventsCursor | null | undefined,
	runId: string,
): IncidentRecorderLiveRunEventsCursor | null {
	if (cursor === undefined || cursor === null) return null;
	if (!isCursor(cursor, runId)) throw new TypeError("Live trigger intent scan cursor is invalid");
	return Object.freeze({ ...cursor });
}

function candidateFromEvent(
	event: IncidentRecorderRunHistoryEvent,
	context: IncidentRecorderLiveTriggerIntentContext,
): IncidentRecorderLiveTriggerIntentCandidate {
	validEventIdentityAndTimestamp(event, context);
	const metadata = isRecord(event.metadata) ? event.metadata : {};
	const eventType =
		event.type === "worker_request_end" || event.type === "kernel_unexpected_exit" ? event.type : undefined;
	if (!eventType) throw new TypeError("Live trigger intent event type is unsupported");
	const classification = intentClassificationForTrigger(event.type);
	const trigger: IncidentRecorderLiveTriggerIntentTrigger = Object.freeze({
		producerId: event.identity.producerId,
		occurrenceId: event.identity.occurrenceId,
		eventType,
		source: event.source,
		semanticFingerprint: event.semanticFingerprint,
		occurrenceReference: cloneOccurrenceReference(event.occurrenceReference),
		anchorWallTimeMs: Number(event.eventWallTimeMs),
		eventMonotonicNs: event.eventMonotonicNs,
		producerOrder: [...event.producerOrder],
		wrapperOrder: [...event.wrapperOrder],
	});
	return Object.freeze({
		runId: context.runId,
		runToken: context.runToken,
		trigger,
		classification,
		cause: classification === "worker_response_hang" ? workerCause(metadata) : kernelCause(metadata),
		target: Object.freeze({ pid: context.targetPid, processStartId: context.targetProcessStartId }),
		scanStartCursor: normalizedCursor(context.scanStartCursor, context.runId),
	});
}

/** Extract only committed worker-timeout and kernel-exit events; other events are not candidates. */
export function extractIncidentRecorderLiveTriggerIntentCandidate(
	event: IncidentRecorderRunHistoryEvent,
	context: IncidentRecorderLiveTriggerIntentContext,
): IncidentRecorderLiveTriggerIntentCandidate | undefined {
	if (event.type === "worker_request_end") {
		if (!isRecord(event.metadata) || event.metadata.outcome !== "timeout") return undefined;
	} else if (event.type !== "kernel_unexpected_exit") {
		return undefined;
	}
	return candidateFromEvent(event, context);
}

function deepFreeze<T>(value: T): T {
	if (!value || typeof value !== "object") return value;
	for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
	return Object.freeze(value);
}

function intentFromCandidate(
	candidate: IncidentRecorderLiveTriggerIntentCandidate,
	reservedOccurrenceIds: IncidentRecorderLiveTriggerIntentReservedOccurrenceIds,
): IncidentRecorderLiveTriggerIntent {
	const intent = {
		schemaVersion: INCIDENT_RECORDER_LIVE_TRIGGER_INTENT_SCHEMA_VERSION,
		kind: INCIDENT_RECORDER_LIVE_TRIGGER_INTENT_KIND,
		runId: candidate.runId,
		runToken: candidate.runToken,
		trigger: {
			...candidate.trigger,
			producerOrder: [...candidate.trigger.producerOrder],
			wrapperOrder: [...candidate.trigger.wrapperOrder],
			occurrenceReference: cloneOccurrenceReference(candidate.trigger.occurrenceReference),
		},
		classification: candidate.classification,
		cause: { ...candidate.cause },
		target: { ...candidate.target },
		scanStartCursor: candidate.scanStartCursor ? { ...candidate.scanStartCursor } : null,
		reservedOccurrenceIds: { ...reservedOccurrenceIds },
	} satisfies IncidentRecorderLiveTriggerIntent;
	validateIncidentRecorderLiveTriggerIntent(intent);
	return deepFreeze(intent);
}

function intentSemanticProjection(value: IncidentRecorderLiveTriggerIntent): unknown {
	return {
		runId: value.runId,
		runToken: value.runToken,
		trigger: value.trigger,
		classification: value.classification,
		cause: value.cause,
		target: value.target,
	};
}

function canonicalJson(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map((child) => canonicalJson(child)).join(",")}]`;
	if (isRecord(value))
		return `{${Object.keys(value)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
			.join(",")}}`;
	return JSON.stringify(value);
}

function sameCandidate(
	existing: IncidentRecorderLiveTriggerIntent,
	candidate: IncidentRecorderLiveTriggerIntentCandidate,
): boolean {
	const candidateIntent = {
		runId: candidate.runId,
		runToken: candidate.runToken,
		trigger: candidate.trigger,
		classification: candidate.classification,
		cause: candidate.cause,
		target: candidate.target,
	};
	return canonicalJson(intentSemanticProjection(existing)) === canonicalJson(candidateIntent);
}

function intentFileNameForIdentity(runId: string, runToken: string, producerId: string, occurrenceId: string): string {
	if (![runId, runToken, producerId, occurrenceId].every(isCanonicalUuid))
		throw new TypeError("Live trigger intent filename identity is invalid");
	const digest = createHash("sha256")
		.update(`${runId}\0${runToken}\0${producerId}\0${occurrenceId}`, "utf8")
		.digest("hex");
	return `live-trigger-intent-v1-${digest}.json`;
}

export function incidentRecorderLiveTriggerIntentFileName(
	value: Pick<IncidentRecorderLiveTriggerIntentCandidate, "runId" | "runToken" | "trigger">,
): string {
	return intentFileNameForIdentity(value.runId, value.runToken, value.trigger.producerId, value.trigger.occurrenceId);
}

function privateRegularIntentFile(stat: BigIntStats): boolean {
	return (
		stat.isFile() &&
		(stat.nlink === 1n || stat.nlink === 2n) &&
		stat.size >= 0n &&
		stat.size <= BigInt(MAX_INTENT_BYTES) &&
		(typeof process.getuid !== "function" || stat.uid === BigInt(process.getuid())) &&
		(stat.mode & 0o077n) === 0n
	);
}

function sameFileIdentity(left: BigIntStats, right: BigIntStats): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.mode === right.mode &&
		left.uid === right.uid &&
		left.gid === right.gid &&
		left.size === right.size &&
		left.nlink === right.nlink &&
		left.mtimeNs === right.mtimeNs &&
		left.ctimeNs === right.ctimeNs
	);
}

function readExistingIntent(
	runRoot: IncidentCasRootMutation,
	name: string,
): { state: "absent" | "invalid" | "valid"; bytes?: Buffer; intent?: IncidentRecorderLiveTriggerIntent } {
	const path = runRoot.relative(name);
	const before = runRoot.lstat(path);
	if (!before) return { state: "absent" };
	if (!privateRegularIntentFile(before)) return { state: "invalid" };
	let bytes: Buffer;
	try {
		bytes = runRoot.readFile(path, MAX_INTENT_BYTES);
	} catch {
		return { state: "invalid" };
	}
	const after = runRoot.lstat(path);
	if (!after || !sameFileIdentity(before, after)) return { state: "invalid" };
	if (!Buffer.from(bytes.toString("utf8"), "utf8").equals(bytes)) return { state: "invalid" };
	let parsed: unknown;
	try {
		parsed = JSON.parse(bytes.toString("utf8"));
	} catch {
		return { state: "invalid" };
	}
	if (!isIncidentRecorderLiveTriggerIntent(parsed)) return { state: "invalid" };
	return { state: "valid", bytes, intent: deepFreeze(parsed) };
}

function preparedOriginalBytes(bytes: Buffer): IncidentFinalizationSealPrepared {
	return Object.freeze({
		bytes: bytes.toString("utf8"),
		byteLength: bytes.length,
		peakStorageFootprint: Object.freeze({
			payloadBytes: bytes.length,
			metadataBlocks: 2,
			entries: 2,
			inodes: 1,
		}),
	});
}

function preparedPeakStorageBytes(
	runRoot: IncidentCasRootMutation,
	prepared: IncidentFinalizationSealPrepared,
): number {
	const observed = Number(runRoot.statfs(runRoot.relative()).bsize);
	if (!Number.isSafeInteger(observed) || observed <= 0)
		throw new Error("Live trigger intent filesystem block size is invalid");
	const blockSize = Math.max(4096, observed);
	const payloadBlocks = Math.ceil(prepared.byteLength / blockSize);
	const result = payloadBlocks * blockSize + 2 * blockSize;
	if (!Number.isSafeInteger(result)) throw new Error("Live trigger intent storage footprint exceeded safe bounds");
	return result;
}

function storageResult(
	state: "conflict" | "ambiguous",
	fileName: string,
	reason: string,
	peakStorageBytes: number,
	effects: readonly IncidentRecorderStorageAccountingEffect[] = [],
): IncidentRecorderLiveTriggerIntentPersistenceResult {
	return { state, fileName, reason, peakStorageBytes, effects: Object.freeze([...effects]) };
}

/** Publish/replay one intent using only the already-admitted descriptor-bound run root. */
export function persistIncidentRecorderLiveTriggerIntentWithinRoot(
	runRoot: IncidentCasRootMutation,
	candidate: IncidentRecorderLiveTriggerIntentCandidate,
	storage: IncidentRecorderLiveTriggerIntentStorageContext,
): IncidentRecorderLiveTriggerIntentPersistenceResult {
	validateIncidentRecorderLiveTriggerIntentCandidate(candidate);
	const fileName = incidentRecorderLiveTriggerIntentFileName(candidate);
	let existing: ReturnType<typeof readExistingIntent>;
	try {
		existing = readExistingIntent(runRoot, fileName);
	} catch {
		return storageResult("ambiguous", fileName, "run_root_unavailable", 0);
	}
	if (existing.state === "invalid")
		return storageResult("conflict", fileName, "existing_intent_invalid_or_mismatched", 0);
	if (existing.state === "valid") {
		if (!existing.intent || !existing.bytes)
			return storageResult("conflict", fileName, "existing_intent_invalid_or_mismatched", 0);
		if (!sameCandidate(existing.intent, candidate))
			return storageResult("conflict", fileName, "existing_intent_semantic_conflict", 0);
	}

	let prepared: IncidentFinalizationSealPrepared;
	let intent: IncidentRecorderLiveTriggerIntent | undefined;
	if (existing.state === "valid") {
		if (!existing.intent || !existing.bytes)
			return storageResult("conflict", fileName, "existing_intent_invalid_or_mismatched", 0);
		prepared = preparedOriginalBytes(existing.bytes);
		intent = existing.intent;
	} else {
		const reservedOccurrenceIds: IncidentRecorderLiveTriggerIntentReservedOccurrenceIds = {
			captureCompletionOccurrenceId: randomUUID(),
			committedFenceOccurrenceId: randomUUID(),
		};
		intent = intentFromCandidate(candidate, reservedOccurrenceIds);
		prepared = prepareIncidentFinalizationSeal(intent);
	}

	let peakStorageBytes: number;
	try {
		peakStorageBytes = preparedPeakStorageBytes(runRoot, prepared);
	} catch {
		return storageResult("ambiguous", fileName, "run_root_storage_footprint_unavailable", 0);
	}
	try {
		const reservation = storage.reserve(peakStorageBytes, 2, 1);
		if (reservation === false || (isRecord(reservation) && reservation.accepted === false))
			return storageResult("ambiguous", fileName, "storage_reservation_denied", peakStorageBytes);
	} catch {
		return storageResult("ambiguous", fileName, "storage_reservation_unavailable", peakStorageBytes);
	}

	let persisted: ReturnType<typeof persistIncidentFinalizationSealWithinRoot>;
	try {
		persisted = persistIncidentFinalizationSealWithinRoot(runRoot, fileName, prepared);
	} catch {
		return storageResult("ambiguous", fileName, "finalization_helper_failed", peakStorageBytes);
	}
	const effects = [...persisted.effects];
	try {
		storage.effects.push(...effects);
	} catch {
		return storageResult("ambiguous", fileName, "storage_effect_application_failed", peakStorageBytes, effects);
	}
	if (persisted.state === "applied" && persisted.authoritativeBytesMatch && intent)
		return {
			state: "applied",
			fileName,
			intent,
			peakStorageBytes: persisted.peakStorageBytes,
			effects: Object.freeze(effects),
		};
	if (persisted.state === "noop" && persisted.authoritativeBytesMatch && intent)
		return {
			state: "replayed",
			fileName,
			intent,
			peakStorageBytes: persisted.peakStorageBytes,
			effects: Object.freeze(effects),
		};
	if (persisted.state === "conflict")
		return storageResult("conflict", fileName, "finalization_helper_conflict", persisted.peakStorageBytes, effects);
	return storageResult("ambiguous", fileName, "finalization_helper_ambiguous", persisted.peakStorageBytes, effects);
}
