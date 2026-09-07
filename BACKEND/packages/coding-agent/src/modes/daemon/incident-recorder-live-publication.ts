import { createHash } from "node:crypto";
import {
	closeSync,
	constants as fsConstants,
	fstatSync,
	fsyncSync,
	linkSync,
	lstatSync,
	mkdirSync,
	opendirSync,
	openSync,
	readSync,
	renameSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import type {
	IncidentRecorderCompactor,
	IncidentRecorderLiveRunEventsCursor,
	IncidentRecorderLiveRunEventsPage,
	IncidentRecorderRunHistoryEvent,
} from "./incident-recorder-compactor.js";
import type { IncidentRecorderSegmentLocator } from "./incident-recorder-segment-store.js";

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_INCIDENT_ID = /^[A-Za-z0-9_.+-]{1,200}$/;
const LIVE_INCIDENT_ID = /^live-([0-9a-f-]{36})-([0-9a-f-]{36})-([0-9a-f-]{36})$/;
const LIVE_STAGE = /^\.(live-[A-Za-z0-9_.+-]{1,200})\.partial-([0-9a-f]{64})$/;
const MAX_REASON_BYTES = 4 * 1024;
const MAX_CLASSIFICATION_BYTES = 256;
const MAX_PAGES_PER_PASS = 8;
const MAX_VALIDATION_PAGES_PER_PASS = 8;
const MAX_PAGE_BYTES = 8 * 1024 * 1024;
const MAX_STAGE_NAMES_PER_PASS = 256;
const LIVE_PROGRESS_VERSION = 2;
const LIVE_EVIDENCE_PAGE_VERSION = 1;
const LIVE_OBSERVATION_VERSION = 1;

export interface IncidentRecorderLiveOccurrenceIdentity {
	runId: string;
	runToken: string;
	producerId: string;
	occurrenceId: string;
	identityKey?: string;
}

export interface IncidentRecorderLiveTriggerIdentity extends IncidentRecorderLiveOccurrenceIdentity {
	acceptedAtWallTimeMs: number;
	type?: string;
}

export interface IncidentRecorderLiveIncidentPublicationInput {
	/** Directory containing the incident artifact directories. */
	incidentsDirectory: string;
	compactor: IncidentRecorderCompactor;
	trigger: IncidentRecorderLiveTriggerIdentity | IncidentRecorderRunHistoryEvent;
	fence: IncidentRecorderLiveOccurrenceIdentity | IncidentRecorderRunHistoryEvent;
	classification: { value: string; causeLayer: string };
	/** Maximum number of physical pages consumed by this call. */
	maxPagesPerPass?: number;
	/** Maximum number of page-chain validations consumed by this call. */
	maxValidationPagesPerPass?: number;
	/** Absolute wall-clock deadline for this call. */
	deadlineMs?: number;
	/** Independent readback state returned by a prior bounded inspection. */
	validationCheckpoint?: IncidentRecorderLiveObservationValidationCheckpoint;
}

export interface IncidentRecorderLiveObservationIdentity {
	triggerProducerId: string;
	triggerOccurrenceId: string;
	fenceProducerId: string;
	fenceOccurrenceId: string;
}

export interface IncidentRecorderLiveObservationRun {
	runId: string;
	runToken: string;
}

export interface IncidentRecorderLiveObservationTargetSnapshot {
	kind: "physical_fence";
	runId: string;
	filterSha256: string;
	segmentSequence: number;
	ordinal: number;
	fenceProducerId: string;
	fenceOccurrenceId: string;
}

export interface IncidentRecorderLiveObservationCoverage {
	scope: "live-run-prefix";
	fence: "physical";
	chainHeadSha256: string;
	pageCount: number;
	eventCount: number;
	state: "complete";
	reason: "physical_fence_reached";
}

export interface IncidentRecorderLiveObservation {
	version: typeof LIVE_OBSERVATION_VERSION;
	kind: "live_incident_observation";
	state: "published";
	diagnosticOnly: true;
	terminal: false;
	identity: IncidentRecorderLiveObservationIdentity;
	run: IncidentRecorderLiveObservationRun;
	classification: string;
	causeLayer: string;
	trigger: {
		producerId: string;
		occurrenceId: string;
		type: string;
		acceptedAtWallTimeMs: number;
	};
	anchorWallTimeMs: number;
	targetSnapshot: IncidentRecorderLiveObservationTargetSnapshot;
	coverage: IncidentRecorderLiveObservationCoverage;
}

export interface IncidentRecorderLiveObservationCursor {
	version: 1;
	runId: string;
	filterSha256: string;
	segmentSequence: number;
	ordinal: number;
}

export interface IncidentRecorderLiveEvidencePage {
	version: typeof LIVE_EVIDENCE_PAGE_VERSION;
	kind: "live_incident_evidence_page";
	identity: IncidentRecorderLiveObservationIdentity;
	runId: string;
	sequence: number;
	beforeCursor: IncidentRecorderLiveObservationCursor | null;
	afterCursor: IncidentRecorderLiveObservationCursor;
	events: IncidentRecorderRunHistoryEvent[];
	readState: "complete" | "pending" | "incomplete";
	reason?: string;
	scannedSegments: number;
	scannedRecords: number;
	scannedIndexBytes: number;
	previousPageSha256: string | null;
	pageSha256: string;
}

export interface IncidentRecorderLiveFenceProof {
	version: 1;
	kind: "physical_fence";
	runId: string;
	runToken: string;
	filterSha256: string;
	fenceProducerId: string;
	fenceOccurrenceId: string;
	locator: IncidentRecorderSegmentLocator;
}

export interface IncidentRecorderLiveObservationValidationCheckpoint {
	version: 1;
	kind: "live_incident_observation_validation_checkpoint";
	publicationId: string;
	descriptorSha256: string;
	evidenceDirectoryRoot: string;
	identity: IncidentRecorderLiveObservationIdentity;
	run: IncidentRecorderLiveObservationRun;
	/** Number of evidence pages independently validated by the caller. */
	pageCount: number;
	chainHeadSha256: string | null;
	cursor: IncidentRecorderLiveObservationCursor | null;
	eventCount: number;
	bytes: number;
	triggerSeen: boolean;
	fenceSeen: boolean;
	fenceProof: IncidentRecorderLiveFenceProof | null;
}

interface LiveProgress {
	version: typeof LIVE_PROGRESS_VERSION;
	kind: "live_incident_evidence_progress";
	identity: IncidentRecorderLiveObservationIdentity;
	run: IncidentRecorderLiveObservationRun;
	cursor: IncidentRecorderLiveObservationCursor | null;
	pageCount: number;
	eventCount: number;
	bytes: number;
	chainHeadSha256: string | null;
	triggerSeen: boolean;
	fenceSeen: boolean;
	fenceProof: IncidentRecorderLiveFenceProof | null;
	state: "pending" | "incomplete" | "published";
	reason?: string;
	validatedPageCount: number;
	validatedChainHeadSha256: string | null;
}

export type IncidentRecorderLiveIncidentPublicationResult =
	| {
			state: "pending" | "incomplete";
			incidentId: string;
			publicationId: string;
			progress: LiveProgress;
			reason: string;
			validationCheckpoint?: IncidentRecorderLiveObservationValidationCheckpoint;
	  }
	| {
			state: "published";
			incidentId: string;
			publicationId: string;
			artifactPath: string;
			observation: IncidentRecorderLiveObservation;
			noOp: boolean;
	  }
	| {
			state: "uncertain" | "conflict";
			incidentId: string;
			publicationId: string;
			reason: string;
	  };

export type IncidentRecorderLiveIncidentInspection =
	| { state: "missing" }
	| {
			state: "pending" | "incomplete" | "uncertain";
			incidentId: string;
			reason: string;
			validationCheckpoint?: IncidentRecorderLiveObservationValidationCheckpoint;
	  }
	| {
			state: "published";
			incidentId: string;
			publicationId: string;
			artifactPath: string;
			observation: IncidentRecorderLiveObservation;
	  };

type JsonRecord = { [key: string]: JsonValue };
type JsonValue = null | boolean | number | string | JsonValue[] | JsonRecord;

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalJson(value: unknown, depth = 0): string {
	if (depth > 32) throw new Error("live observation canonical JSON depth exceeded");
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
	if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item, depth + 1)).join(",")}]`;
	if (!isRecord(value)) throw new Error("live observation value is not canonical JSON");
	return `{${Object.keys(value)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`)
		.join(",")}}`;
}

function sha256(value: Uint8Array | string): string {
	return createHash("sha256").update(value).digest("hex");
}

function bytes(value: unknown): Buffer {
	return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	const expected = new Set(keys);
	return Object.keys(value).length === expected.size && Object.keys(value).every((key) => expected.has(key));
}

function sameCursor(
	left: IncidentRecorderLiveObservationCursor | null | undefined,
	right: IncidentRecorderLiveObservationCursor | null | undefined,
): boolean {
	return left === null || left === undefined
		? right === null || right === undefined
		: right !== null && right !== undefined && canonicalJson(left) === canonicalJson(right);
}

function uuid(value: unknown): value is string {
	return typeof value === "string" && CANONICAL_UUID.test(value);
}

function cursor(value: unknown, runId: string): value is IncidentRecorderLiveObservationCursor {
	return (
		isRecord(value) &&
		exactKeys(value, ["version", "runId", "filterSha256", "segmentSequence", "ordinal"]) &&
		value.version === 1 &&
		value.runId === runId &&
		typeof value.filterSha256 === "string" &&
		SHA256.test(value.filterSha256) &&
		Number.isSafeInteger(value.segmentSequence) &&
		Number(value.segmentSequence) >= 0 &&
		Number.isSafeInteger(value.ordinal) &&
		Number(value.ordinal) >= 0
	);
}

function identityKey(identity: IncidentRecorderLiveOccurrenceIdentity): string {
	return sha256(`${identity.runId}\0${identity.runToken}\0${identity.producerId}\0${identity.occurrenceId}`);
}

function occurrenceIdentity(
	value:
		| IncidentRecorderLiveTriggerIdentity
		| IncidentRecorderLiveOccurrenceIdentity
		| IncidentRecorderRunHistoryEvent,
	acceptedAtWallTimeMs?: number,
): IncidentRecorderLiveTriggerIdentity | IncidentRecorderLiveOccurrenceIdentity {
	if ("identity" in value) {
		const event = value as IncidentRecorderRunHistoryEvent;
		return {
			...event.identity,
			identityKey: event.identityKey,
			...(acceptedAtWallTimeMs === undefined ? {} : { acceptedAtWallTimeMs, type: event.type }),
		};
	}
	return value;
}

function normalizeTrigger(
	value: IncidentRecorderLiveTriggerIdentity | IncidentRecorderRunHistoryEvent,
): IncidentRecorderLiveTriggerIdentity {
	const event = "identity" in value ? value : undefined;
	const identity = occurrenceIdentity(value, event ? Number(event.eventWallTimeMs) : undefined);
	const acceptedAtWallTimeMs = "acceptedAtWallTimeMs" in identity ? identity.acceptedAtWallTimeMs : undefined;
	const type = "type" in identity ? identity.type : undefined;
	if (!Number.isSafeInteger(acceptedAtWallTimeMs) || Number(acceptedAtWallTimeMs) < 0)
		throw new Error("Invalid accepted trigger wall time");
	if (type === undefined) throw new Error("Invalid live trigger type");
	return { ...identity, acceptedAtWallTimeMs: Number(acceptedAtWallTimeMs), type };
}

function normalizeIdentity(
	value: IncidentRecorderLiveOccurrenceIdentity | IncidentRecorderRunHistoryEvent,
): IncidentRecorderLiveOccurrenceIdentity {
	const identity = occurrenceIdentity(value);
	if (!uuid(identity.runId) || !uuid(identity.runToken) || !uuid(identity.producerId) || !uuid(identity.occurrenceId))
		throw new Error("Invalid live occurrence identity");
	const expected = identityKey(identity);
	if (identity.identityKey !== undefined && identity.identityKey !== expected)
		throw new Error("Live occurrence identity key mismatch");
	return { ...identity, identityKey: expected };
}

function incidentId(trigger: IncidentRecorderLiveTriggerIdentity, runId: string): string {
	const value = `live-${trigger.producerId}-${trigger.occurrenceId}-${runId}`;
	if (value.length !== 115 || !SAFE_INCIDENT_ID.test(value)) throw new Error("Invalid live incident id");
	return value;
}

function publicationId(
	trigger: IncidentRecorderLiveTriggerIdentity,
	fence: IncidentRecorderLiveOccurrenceIdentity,
	classification: { value: string; causeLayer: string },
): string {
	return sha256(
		canonicalJson({
			version: 1,
			trigger: {
				runId: trigger.runId,
				runToken: trigger.runToken,
				producerId: trigger.producerId,
				occurrenceId: trigger.occurrenceId,
				acceptedAtWallTimeMs: trigger.acceptedAtWallTimeMs,
			},
			fence: {
				runId: fence.runId,
				runToken: fence.runToken,
				producerId: fence.producerId,
				occurrenceId: fence.occurrenceId,
			},
			classification,
		}),
	);
}

function pagePath(stagePath: string, sequence: number): string {
	return join(stagePath, "evidence", `page-${sequence.toString().padStart(12, "0")}.json`);
}

function progressPath(stagePath: string): string {
	return join(stagePath, "progress.json");
}

function observationPath(directory: string): string {
	return join(directory, "live-observation.json");
}

function fsyncDirectory(path: string): void {
	const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
	try {
		fsyncSync(descriptor);
	} finally {
		closeSync(descriptor);
	}
}

function privateDirectory(path: string): boolean {
	try {
		const stat = lstatSync(path, { bigint: true });
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

function directoryRoot(path: string): string | undefined {
	try {
		const stat = lstatSync(path, { bigint: true });
		if (
			!stat.isDirectory() ||
			stat.isSymbolicLink() ||
			(typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) ||
			(stat.mode & 0o077n) !== 0n
		)
			return undefined;
		return sha256(`${stat.dev}\0${stat.ino}\0${stat.mtimeNs}\0${stat.ctimeNs}`);
	} catch {
		return undefined;
	}
}

function writeImmutable(path: string, content: Buffer): "applied" | "noop" | "conflict" {
	const parent = dirname(path);
	mkdirSync(parent, { recursive: true, mode: 0o700 });
	let existing: Buffer | undefined;
	try {
		const stat = lstatSync(path, { bigint: true });
		if (
			!stat.isFile() ||
			stat.isSymbolicLink() ||
			stat.nlink !== 1n ||
			(typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) ||
			(stat.mode & 0o077n) !== 0n
		)
			return "conflict";
		if (stat.size > BigInt(Math.max(MAX_PAGE_BYTES, content.length))) return "conflict";
		const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		try {
			const value = Buffer.alloc(Number(stat.size));
			let offset = 0;
			while (offset < value.length) {
				const count = readSync(descriptor, value, offset, value.length - offset, offset);
				if (count <= 0) return "conflict";
				offset += count;
			}
			existing = value;
		} finally {
			closeSync(descriptor);
		}
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") return "conflict";
	}
	if (existing) return existing.equals(content) ? "noop" : "conflict";
	const temporary = `${path}.tmp-${process.pid}-${process.hrtime.bigint()}`;
	let descriptor: number | undefined;
	try {
		descriptor = openSync(
			temporary,
			fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
			0o600,
		);
		let offset = 0;
		while (offset < content.length) {
			const count = writeSync(descriptor, content, offset, content.length - offset, offset);
			if (count <= 0) throw new Error("live observation write made no progress");
			offset += count;
		}
		fsyncSync(descriptor);
		closeSync(descriptor);
		descriptor = undefined;
		try {
			// A hard link gives the same no-overwrite publication semantics on Linux
			// that an exchange-free same-parent rename is intended to provide.
			linkSync(temporary, path);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			const readback = readImmutable(path);
			if (!readback || !readback.equals(content)) return "conflict";
			return "noop";
		}
		unlinkSync(temporary);
		fsyncDirectory(parent);
		return "applied";
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
		try {
			const stat = lstatSync(temporary);
			if (stat.isFile() && !stat.isSymbolicLink()) unlinkSync(temporary);
		} catch {}
	}
}

function writeProgress(path: string, progress: LiveProgress): void {
	const temporary = `${path}.tmp-${process.pid}-${process.hrtime.bigint()}`;
	const descriptor = openSync(
		temporary,
		fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
		0o600,
	);
	try {
		const content = bytes(progress);
		let offset = 0;
		while (offset < content.length) {
			const count = writeSync(descriptor, content, offset, content.length - offset, offset);
			if (count <= 0) throw new Error("live observation progress write made no progress");
			offset += count;
		}
		fsyncSync(descriptor);
	} finally {
		closeSync(descriptor);
	}
	renameSync(temporary, path);
	fsyncDirectory(dirname(path));
}

function readImmutable(path: string, maximum = MAX_PAGE_BYTES): Buffer | undefined {
	let descriptor: number | undefined;
	try {
		const before = lstatSync(path, { bigint: true });
		if (
			!before.isFile() ||
			before.isSymbolicLink() ||
			before.nlink !== 1n ||
			(typeof process.getuid === "function" && before.uid !== BigInt(process.getuid())) ||
			(before.mode & 0o077n) !== 0n ||
			before.size > BigInt(maximum)
		)
			return undefined;
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const opened = fstatSync(descriptor, { bigint: true });
		if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) return undefined;
		const value = Buffer.alloc(Number(opened.size));
		let offset = 0;
		while (offset < value.length) {
			const count = readSync(descriptor, value, offset, value.length - offset, offset);
			if (count <= 0) return undefined;
			offset += count;
		}
		const after = fstatSync(descriptor, { bigint: true });
		return after.dev === opened.dev && after.ino === opened.ino && after.size === opened.size ? value : undefined;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

function parseJson(path: string, maximum = MAX_PAGE_BYTES): unknown {
	const value = readImmutable(path, maximum);
	if (!value || !value.toString("utf8").endsWith("\n")) return undefined;
	try {
		return JSON.parse(value.toString("utf8"));
	} catch {
		return undefined;
	}
}

function observationIdentity(
	trigger: IncidentRecorderLiveTriggerIdentity,
	fence: IncidentRecorderLiveOccurrenceIdentity,
) {
	return {
		triggerProducerId: trigger.producerId,
		triggerOccurrenceId: trigger.occurrenceId,
		fenceProducerId: fence.producerId,
		fenceOccurrenceId: fence.occurrenceId,
	};
}

function sameIdentity(
	left: IncidentRecorderLiveOccurrenceIdentity,
	right: IncidentRecorderLiveOccurrenceIdentity,
): boolean {
	return (
		left.runId === right.runId &&
		left.runToken === right.runToken &&
		left.producerId === right.producerId &&
		left.occurrenceId === right.occurrenceId
	);
}

function eventMatches(
	event: IncidentRecorderRunHistoryEvent,
	expected: IncidentRecorderLiveOccurrenceIdentity,
): boolean {
	return sameIdentity(event.identity, expected) && event.identityKey === identityKey(expected);
}

function segmentLocator(event: IncidentRecorderRunHistoryEvent): IncidentRecorderSegmentLocator | undefined {
	if (!isRecord(event.occurrenceReference) || event.occurrenceReference.kind !== "segment") return undefined;
	const locator = event.occurrenceReference.locator;
	if (
		!isRecord(locator) ||
		!exactKeys(locator, [
			"version",
			"segmentId",
			"segmentSequence",
			"ordinal",
			"offset",
			"frameBytes",
			"payloadBytes",
			"payloadSha256",
		]) ||
		locator.version !== 1 ||
		typeof locator.segmentId !== "string" ||
		!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(locator.segmentId) ||
		!Number.isSafeInteger(locator.segmentSequence) ||
		Number(locator.segmentSequence) < 0 ||
		!Number.isSafeInteger(locator.ordinal) ||
		Number(locator.ordinal) <= 0 ||
		!Number.isSafeInteger(locator.offset) ||
		Number(locator.offset) < 0 ||
		!Number.isSafeInteger(locator.frameBytes) ||
		Number(locator.frameBytes) < 1 ||
		!Number.isSafeInteger(locator.payloadBytes) ||
		Number(locator.payloadBytes) < 0 ||
		typeof locator.payloadSha256 !== "string" ||
		!SHA256.test(locator.payloadSha256)
	)
		return undefined;
	return locator as unknown as IncidentRecorderSegmentLocator;
}

function toCursor(value: IncidentRecorderLiveRunEventsCursor): IncidentRecorderLiveObservationCursor {
	return {
		version: 1,
		runId: value.runId,
		filterSha256: value.filterSha256,
		segmentSequence: value.segmentSequence,
		ordinal: value.ordinal,
	};
}

function comparePhysicalPosition(
	left: Pick<IncidentRecorderLiveObservationCursor, "segmentSequence" | "ordinal">,
	right: Pick<IncidentRecorderLiveObservationCursor, "segmentSequence" | "ordinal">,
): number {
	if (left.segmentSequence !== right.segmentSequence) return left.segmentSequence - right.segmentSequence;
	return left.ordinal - right.ordinal;
}

function cursorFromLocator(
	locator: IncidentRecorderSegmentLocator,
	runId: string,
	filterSha256: string,
): IncidentRecorderLiveObservationCursor {
	return {
		version: 1,
		runId,
		filterSha256,
		segmentSequence: locator.segmentSequence,
		ordinal: locator.ordinal,
	};
}

function validReaderPage(value: unknown, runId: string): value is IncidentRecorderLiveRunEventsPage {
	if (!isRecord(value)) return false;
	const keys = [
		"version",
		"runId",
		"state",
		"events",
		"cursor",
		...(value.reason === undefined ? [] : ["reason"]),
		"scannedSegments",
		"scannedRecords",
		"scannedIndexBytes",
	];
	return (
		exactKeys(value, keys) &&
		value.version === 1 &&
		value.runId === runId &&
		(["complete", "pending", "incomplete"] as readonly unknown[]).includes(value.state) &&
		Array.isArray(value.events) &&
		cursor(value.cursor, runId) &&
		(value.reason === undefined ||
			(typeof value.reason === "string" && Buffer.byteLength(value.reason, "utf8") <= MAX_REASON_BYTES)) &&
		Number.isSafeInteger(value.scannedSegments) &&
		Number(value.scannedSegments) >= 0 &&
		Number.isSafeInteger(value.scannedRecords) &&
		Number(value.scannedRecords) >= 0 &&
		Number.isSafeInteger(value.scannedIndexBytes) &&
		Number(value.scannedIndexBytes) >= 0
	);
}

function validFenceProof(value: unknown, runId: string): value is IncidentRecorderLiveFenceProof {
	if (!isRecord(value)) return false;
	return (
		exactKeys(value, [
			"version",
			"kind",
			"runId",
			"runToken",
			"filterSha256",
			"fenceProducerId",
			"fenceOccurrenceId",
			"locator",
		]) &&
		value.version === 1 &&
		value.kind === "physical_fence" &&
		value.runId === runId &&
		uuid(value.runToken) &&
		typeof value.filterSha256 === "string" &&
		SHA256.test(value.filterSha256) &&
		uuid(value.fenceProducerId) &&
		uuid(value.fenceOccurrenceId) &&
		isRecord(value.locator) &&
		segmentLocator({
			occurrenceReference: { kind: "segment", locator: value.locator },
		} as unknown as IncidentRecorderRunHistoryEvent) !== undefined
	);
}

function makeValidationCheckpoint(input: {
	publicationId: string;
	descriptorSha256: string;
	evidenceDirectoryRoot: string;
	identity: IncidentRecorderLiveObservationIdentity;
	run: IncidentRecorderLiveObservationRun;
	pageCount: number;
	chainHeadSha256: string | null;
	cursor: IncidentRecorderLiveObservationCursor | null;
	eventCount: number;
	bytes: number;
	triggerSeen: boolean;
	fenceSeen: boolean;
	fenceProof: IncidentRecorderLiveFenceProof | null;
}): IncidentRecorderLiveObservationValidationCheckpoint {
	return {
		version: 1,
		kind: "live_incident_observation_validation_checkpoint",
		publicationId: input.publicationId,
		descriptorSha256: input.descriptorSha256,
		evidenceDirectoryRoot: input.evidenceDirectoryRoot,
		identity: input.identity,
		run: input.run,
		pageCount: input.pageCount,
		chainHeadSha256: input.chainHeadSha256,
		cursor: input.cursor,
		eventCount: input.eventCount,
		bytes: input.bytes,
		triggerSeen: input.triggerSeen,
		fenceSeen: input.fenceSeen,
		fenceProof: input.fenceProof,
	};
}

function validValidationCheckpoint(
	value: unknown,
	expectedIdentity: IncidentRecorderLiveObservationIdentity,
	expectedRun: IncidentRecorderLiveObservationRun,
	expectedPublicationId: string,
	expectedDescriptorSha256: string,
	expectedEvidenceDirectoryRoot: string,
	maxPageCount: number,
): value is IncidentRecorderLiveObservationValidationCheckpoint {
	if (!isRecord(value)) return false;
	if (
		!exactKeys(value, [
			"version",
			"kind",
			"publicationId",
			"descriptorSha256",
			"evidenceDirectoryRoot",
			"identity",
			"run",
			"pageCount",
			"chainHeadSha256",
			"cursor",
			"eventCount",
			"bytes",
			"triggerSeen",
			"fenceSeen",
			"fenceProof",
		]) ||
		value.version !== 1 ||
		value.kind !== "live_incident_observation_validation_checkpoint" ||
		value.publicationId !== expectedPublicationId ||
		value.descriptorSha256 !== expectedDescriptorSha256 ||
		typeof value.evidenceDirectoryRoot !== "string" ||
		!SHA256.test(value.evidenceDirectoryRoot) ||
		value.evidenceDirectoryRoot !== expectedEvidenceDirectoryRoot ||
		!SHA256.test(String(value.publicationId)) ||
		!SHA256.test(String(value.descriptorSha256)) ||
		!isRecord(value.identity) ||
		!exactKeys(value.identity, [
			"triggerProducerId",
			"triggerOccurrenceId",
			"fenceProducerId",
			"fenceOccurrenceId",
		]) ||
		value.identity.triggerProducerId !== expectedIdentity.triggerProducerId ||
		value.identity.triggerOccurrenceId !== expectedIdentity.triggerOccurrenceId ||
		value.identity.fenceProducerId !== expectedIdentity.fenceProducerId ||
		value.identity.fenceOccurrenceId !== expectedIdentity.fenceOccurrenceId ||
		!isRecord(value.run) ||
		!exactKeys(value.run, ["runId", "runToken"]) ||
		value.run.runId !== expectedRun.runId ||
		value.run.runToken !== expectedRun.runToken ||
		!Number.isSafeInteger(value.pageCount) ||
		Number(value.pageCount) < 0 ||
		Number(value.pageCount) > maxPageCount ||
		(value.chainHeadSha256 !== null &&
			(typeof value.chainHeadSha256 !== "string" || !SHA256.test(value.chainHeadSha256))) ||
		(value.cursor !== null && !cursor(value.cursor, expectedRun.runId)) ||
		!Number.isSafeInteger(value.eventCount) ||
		Number(value.eventCount) < 0 ||
		!Number.isSafeInteger(value.bytes) ||
		Number(value.bytes) < 0 ||
		typeof value.triggerSeen !== "boolean" ||
		typeof value.fenceSeen !== "boolean" ||
		(value.fenceProof !== null && !validFenceProof(value.fenceProof, expectedRun.runId))
	)
		return false;
	if (value.pageCount === 0 && (value.chainHeadSha256 !== null || value.cursor !== null)) return false;
	if (Number(value.pageCount) > 0 && (value.chainHeadSha256 === null || value.cursor === null)) return false;
	if (
		value.pageCount === 0 &&
		(value.eventCount !== 0 || value.bytes !== 0 || value.triggerSeen || value.fenceSeen || value.fenceProof !== null)
	)
		return false;
	if (value.fenceSeen && Number(value.pageCount) !== maxPageCount) return false;
	if (value.fenceSeen !== (value.fenceProof !== null)) return false;
	if (value.fenceProof !== null) {
		if (
			value.fenceProof.runToken !== expectedRun.runToken ||
			value.fenceProof.fenceProducerId !== expectedIdentity.fenceProducerId ||
			value.fenceProof.fenceOccurrenceId !== expectedIdentity.fenceOccurrenceId ||
			value.fenceProof.filterSha256 !== value.cursor?.filterSha256 ||
			(value.cursor !== null && comparePhysicalPosition(value.cursor, value.fenceProof.locator) < 0)
		)
			return false;
	}
	return true;
}

function fenceProofFromEvent(
	event: IncidentRecorderRunHistoryEvent,
	fence: IncidentRecorderLiveOccurrenceIdentity,
	filterSha256: string,
): IncidentRecorderLiveFenceProof | undefined {
	const locator = segmentLocator(event);
	if (!locator || !eventMatches(event, fence) || event.type !== "live_incident_high_water_fence") return undefined;
	return {
		version: 1,
		kind: "physical_fence",
		runId: fence.runId,
		runToken: fence.runToken,
		filterSha256,
		fenceProducerId: fence.producerId,
		fenceOccurrenceId: fence.occurrenceId,
		locator,
	};
}

function pageWithoutHash(page: IncidentRecorderLiveEvidencePage): Omit<IncidentRecorderLiveEvidencePage, "pageSha256"> {
	const { pageSha256: _pageSha256, ...withoutHash } = page;
	return withoutHash;
}

function pageHash(page: Omit<IncidentRecorderLiveEvidencePage, "pageSha256">): string {
	return sha256(bytes(page));
}

function validPage(
	value: unknown,
	expectedIdentity: IncidentRecorderLiveObservationIdentity,
	runId: string,
): value is IncidentRecorderLiveEvidencePage {
	if (!isRecord(value)) return false;
	const keys = [
		"version",
		"kind",
		"identity",
		"runId",
		"sequence",
		"beforeCursor",
		"afterCursor",
		"events",
		"readState",
		"scannedSegments",
		"scannedRecords",
		"scannedIndexBytes",
		"previousPageSha256",
		"pageSha256",
		...(value.reason === undefined ? [] : ["reason"]),
	];
	if (
		!exactKeys(value, keys) ||
		value.version !== LIVE_EVIDENCE_PAGE_VERSION ||
		value.kind !== "live_incident_evidence_page" ||
		canonicalJson(value.identity) !== canonicalJson(expectedIdentity) ||
		value.runId !== runId ||
		!Number.isSafeInteger(value.sequence) ||
		Number(value.sequence) < 1 ||
		(value.beforeCursor !== null && !cursor(value.beforeCursor, runId)) ||
		!cursor(value.afterCursor, runId) ||
		!Array.isArray(value.events) ||
		!value.events.every((event) => validRunHistoryEvent(event, runId)) ||
		!(["complete", "pending", "incomplete"] as readonly unknown[]).includes(value.readState) ||
		!Number.isSafeInteger(value.scannedSegments) ||
		Number(value.scannedSegments) < 0 ||
		!Number.isSafeInteger(value.scannedRecords) ||
		Number(value.scannedRecords) < 0 ||
		!Number.isSafeInteger(value.scannedIndexBytes) ||
		Number(value.scannedIndexBytes) < 0 ||
		(value.previousPageSha256 !== null &&
			(typeof value.previousPageSha256 !== "string" || !SHA256.test(value.previousPageSha256))) ||
		typeof value.pageSha256 !== "string" ||
		!SHA256.test(value.pageSha256)
	)
		return false;
	if (
		value.reason !== undefined &&
		(typeof value.reason !== "string" || Buffer.byteLength(value.reason) > MAX_REASON_BYTES)
	)
		return false;
	try {
		if (pageHash(pageWithoutHash(value as unknown as IncidentRecorderLiveEvidencePage)) !== value.pageSha256)
			return false;
	} catch {
		return false;
	}
	return true;
}

function validRunHistoryEvent(value: unknown, runId: string): value is IncidentRecorderRunHistoryEvent {
	if (
		!isRecord(value) ||
		!exactKeys(value, [
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
		])
	)
		return false;
	const identity = value.identity;
	const cas = value.cas;
	if (
		!isRecord(identity) ||
		!exactKeys(identity, ["runId", "runToken", "producerId", "occurrenceId"]) ||
		!uuid(identity.runId) ||
		identity.runId !== runId ||
		!uuid(identity.runToken) ||
		!uuid(identity.producerId) ||
		!uuid(identity.occurrenceId) ||
		typeof value.identityKey !== "string" ||
		value.identityKey !== identityKey(identity as unknown as IncidentRecorderLiveOccurrenceIdentity) ||
		typeof value.semanticFingerprint !== "string" ||
		!SHA256.test(value.semanticFingerprint) ||
		typeof value.source !== "string" ||
		value.source.length === 0 ||
		Buffer.byteLength(value.source) > 255 ||
		typeof value.type !== "string" ||
		value.type.length === 0 ||
		Buffer.byteLength(value.type) > 255 ||
		typeof value.encoding !== "string" ||
		value.encoding.length === 0 ||
		Buffer.byteLength(value.encoding) > 255 ||
		!(
			typeof value.payloadKind === "string" &&
			["exact-bytes", "derived-scalar", "loss", "control"].includes(value.payloadKind)
		) ||
		typeof value.terminal !== "boolean" ||
		!isRecord(value.metadata) ||
		!isRecord(value.transportIdentity) ||
		typeof value.eventWallTimeMs !== "string" ||
		!/^(?:0|[1-9][0-9]{0,19})$/.test(value.eventWallTimeMs) ||
		typeof value.eventMonotonicNs !== "string" ||
		!/^(?:0|[1-9][0-9]{0,19})$/.test(value.eventMonotonicNs) ||
		!Array.isArray(value.wrapperOrder) ||
		!value.wrapperOrder.every((order) => typeof order === "string" && /^(?:0|[1-9][0-9]{0,19})$/.test(order)) ||
		!Array.isArray(value.producerOrder) ||
		!value.producerOrder.every((order) => typeof order === "string" && /^(?:0|[1-9][0-9]{0,19})$/.test(order)) ||
		!Array.isArray(value.cursors) ||
		!value.cursors.every((value) => typeof value === "string") ||
		!cas ||
		!isRecord(cas) ||
		!exactKeys(cas, ["digest", "bytes", "path"]) ||
		typeof cas.digest !== "string" ||
		!SHA256.test(cas.digest) ||
		!Number.isSafeInteger(cas.bytes) ||
		Number(cas.bytes) < 0 ||
		typeof cas.path !== "string"
	)
		return false;
	if (typeof value.occurrenceReference === "string") return value.occurrenceReference.length > 0;
	return (
		isRecord(value.occurrenceReference) &&
		value.occurrenceReference.kind === "segment" &&
		segmentLocator(value as unknown as IncidentRecorderRunHistoryEvent) !== undefined
	);
}

function validObservation(value: unknown): value is IncidentRecorderLiveObservation {
	if (!isRecord(value)) return false;
	if (
		!exactKeys(value, [
			"version",
			"kind",
			"state",
			"diagnosticOnly",
			"terminal",
			"identity",
			"run",
			"classification",
			"causeLayer",
			"trigger",
			"anchorWallTimeMs",
			"targetSnapshot",
			"coverage",
		]) ||
		value.version !== LIVE_OBSERVATION_VERSION ||
		value.kind !== "live_incident_observation" ||
		value.state !== "published" ||
		value.diagnosticOnly !== true ||
		value.terminal !== false ||
		!isRecord(value.identity) ||
		!exactKeys(value.identity, [
			"triggerProducerId",
			"triggerOccurrenceId",
			"fenceProducerId",
			"fenceOccurrenceId",
		]) ||
		!uuid(value.identity.triggerProducerId) ||
		!uuid(value.identity.triggerOccurrenceId) ||
		!uuid(value.identity.fenceProducerId) ||
		!uuid(value.identity.fenceOccurrenceId) ||
		!isRecord(value.run) ||
		!exactKeys(value.run, ["runId", "runToken"]) ||
		!uuid(value.run.runId) ||
		!uuid(value.run.runToken) ||
		typeof value.classification !== "string" ||
		Buffer.byteLength(value.classification) > MAX_CLASSIFICATION_BYTES ||
		typeof value.causeLayer !== "string" ||
		Buffer.byteLength(value.causeLayer) > MAX_CLASSIFICATION_BYTES ||
		!isRecord(value.trigger) ||
		!exactKeys(value.trigger, ["producerId", "occurrenceId", "type", "acceptedAtWallTimeMs"]) ||
		!uuid(value.trigger.producerId) ||
		!uuid(value.trigger.occurrenceId) ||
		typeof value.trigger.type !== "string" ||
		Buffer.byteLength(value.trigger.type) > MAX_CLASSIFICATION_BYTES ||
		!Number.isSafeInteger(value.trigger.acceptedAtWallTimeMs) ||
		Number(value.trigger.acceptedAtWallTimeMs) < 0 ||
		!Number.isSafeInteger(value.anchorWallTimeMs) ||
		Number(value.anchorWallTimeMs) < 0 ||
		!isRecord(value.targetSnapshot) ||
		!exactKeys(value.targetSnapshot, [
			"kind",
			"runId",
			"filterSha256",
			"segmentSequence",
			"ordinal",
			"fenceProducerId",
			"fenceOccurrenceId",
		]) ||
		value.targetSnapshot.kind !== "physical_fence" ||
		value.targetSnapshot.runId !== value.run.runId ||
		typeof value.targetSnapshot.filterSha256 !== "string" ||
		!SHA256.test(value.targetSnapshot.filterSha256) ||
		!Number.isSafeInteger(value.targetSnapshot.segmentSequence) ||
		Number(value.targetSnapshot.segmentSequence) < 0 ||
		!Number.isSafeInteger(value.targetSnapshot.ordinal) ||
		Number(value.targetSnapshot.ordinal) < 0 ||
		!uuid(value.targetSnapshot.fenceProducerId) ||
		!uuid(value.targetSnapshot.fenceOccurrenceId) ||
		!isRecord(value.coverage) ||
		!exactKeys(value.coverage, ["scope", "fence", "chainHeadSha256", "pageCount", "eventCount", "state", "reason"]) ||
		value.coverage.scope !== "live-run-prefix" ||
		value.coverage.fence !== "physical" ||
		typeof value.coverage.chainHeadSha256 !== "string" ||
		!SHA256.test(value.coverage.chainHeadSha256) ||
		!Number.isSafeInteger(value.coverage.pageCount) ||
		Number(value.coverage.pageCount) < 1 ||
		!Number.isSafeInteger(value.coverage.eventCount) ||
		Number(value.coverage.eventCount) < 1 ||
		value.coverage.state !== "complete" ||
		value.coverage.reason !== "physical_fence_reached"
	)
		return false;
	return (
		value.trigger.producerId === value.identity.triggerProducerId &&
		value.trigger.occurrenceId === value.identity.triggerOccurrenceId &&
		value.targetSnapshot.fenceProducerId === value.identity.fenceProducerId &&
		value.targetSnapshot.fenceOccurrenceId === value.identity.fenceOccurrenceId &&
		value.anchorWallTimeMs === value.trigger.acceptedAtWallTimeMs
	);
}

function stageNames(incidentsDirectory: string, incidentId: string): { state: "ok" | "unavailable"; names: string[] } {
	let directory: ReturnType<typeof opendirSync> | undefined;
	try {
		directory = opendirSync(incidentsDirectory);
		const names: string[] = [];
		while (names.length <= MAX_STAGE_NAMES_PER_PASS) {
			const entry = directory.readSync();
			if (!entry) break;
			names.push(entry.name);
		}
		if (names.length > MAX_STAGE_NAMES_PER_PASS) return { state: "unavailable", names: [] };
		return {
			state: "ok",
			names: names.filter((name) => {
				const match = LIVE_STAGE.exec(name);
				return match?.[1] === incidentId;
			}),
		};
	} catch {
		return { state: "unavailable", names: [] };
	} finally {
		directory?.closeSync();
	}
}

function validateIdentityInput(
	triggerInput: IncidentRecorderLiveTriggerIdentity | IncidentRecorderRunHistoryEvent,
	fenceInput: IncidentRecorderLiveOccurrenceIdentity | IncidentRecorderRunHistoryEvent,
	classification: { value: string; causeLayer: string },
): {
	trigger: IncidentRecorderLiveTriggerIdentity;
	fence: IncidentRecorderLiveOccurrenceIdentity;
	incidentId: string;
	publicationId: string;
} {
	const trigger = normalizeTrigger(triggerInput);
	const fence = normalizeIdentity(fenceInput);
	if (!uuid(trigger.runId) || !uuid(trigger.runToken) || !uuid(trigger.producerId) || !uuid(trigger.occurrenceId))
		throw new Error("Invalid live trigger identity");
	if (trigger.runId !== fence.runId || trigger.runToken !== fence.runToken)
		throw new Error("Live trigger/fence run mismatch");
	if (
		typeof trigger.type !== "string" ||
		trigger.type.length === 0 ||
		Buffer.byteLength(trigger.type) > MAX_CLASSIFICATION_BYTES ||
		typeof classification.value !== "string" ||
		classification.value.length === 0 ||
		Buffer.byteLength(classification.value) > MAX_CLASSIFICATION_BYTES ||
		typeof classification.causeLayer !== "string" ||
		classification.causeLayer.length === 0 ||
		Buffer.byteLength(classification.causeLayer) > MAX_CLASSIFICATION_BYTES
	)
		throw new Error("Invalid live observation classification");
	return {
		trigger,
		fence,
		incidentId: incidentId(trigger, trigger.runId),
		publicationId: publicationId(trigger, fence, classification),
	};
}

function loadProgress(stagePath: string): LiveProgress | undefined {
	const parsed = parseJson(progressPath(stagePath), MAX_PAGE_BYTES);
	if (!isRecord(parsed)) return undefined;
	const keys = [
		"version",
		"kind",
		"identity",
		"run",
		"cursor",
		"pageCount",
		"eventCount",
		"bytes",
		"chainHeadSha256",
		"triggerSeen",
		"fenceSeen",
		"fenceProof",
		"state",
		"validatedPageCount",
		"validatedChainHeadSha256",
		...(parsed.reason === undefined ? [] : ["reason"]),
	];
	if (
		!exactKeys(parsed, keys) ||
		parsed.version !== LIVE_PROGRESS_VERSION ||
		parsed.kind !== "live_incident_evidence_progress" ||
		!isRecord(parsed.identity) ||
		!exactKeys(parsed.identity, [
			"triggerProducerId",
			"triggerOccurrenceId",
			"fenceProducerId",
			"fenceOccurrenceId",
		]) ||
		!uuid(parsed.identity.triggerProducerId) ||
		!uuid(parsed.identity.triggerOccurrenceId) ||
		!uuid(parsed.identity.fenceProducerId) ||
		!uuid(parsed.identity.fenceOccurrenceId) ||
		!isRecord(parsed.run) ||
		!exactKeys(parsed.run, ["runId", "runToken"]) ||
		!uuid(parsed.run.runId) ||
		!uuid(parsed.run.runToken) ||
		(parsed.cursor !== null && !cursor(parsed.cursor, String(parsed.run.runId))) ||
		(parsed.fenceProof !== null && !validFenceProof(parsed.fenceProof, String(parsed.run.runId))) ||
		!Number.isSafeInteger(parsed.pageCount) ||
		Number(parsed.pageCount) < 0 ||
		!Number.isSafeInteger(parsed.eventCount) ||
		Number(parsed.eventCount) < 0 ||
		!Number.isSafeInteger(parsed.bytes) ||
		Number(parsed.bytes) < 0 ||
		(parsed.chainHeadSha256 !== null &&
			(typeof parsed.chainHeadSha256 !== "string" || !SHA256.test(parsed.chainHeadSha256))) ||
		typeof parsed.triggerSeen !== "boolean" ||
		typeof parsed.fenceSeen !== "boolean" ||
		!(["pending", "incomplete", "published"] as readonly unknown[]).includes(parsed.state) ||
		!Number.isSafeInteger(parsed.validatedPageCount) ||
		Number(parsed.validatedPageCount) < 0 ||
		(parsed.validatedChainHeadSha256 !== null &&
			(typeof parsed.validatedChainHeadSha256 !== "string" || !SHA256.test(parsed.validatedChainHeadSha256))) ||
		(parsed.reason !== undefined &&
			(typeof parsed.reason !== "string" || Buffer.byteLength(parsed.reason) > MAX_REASON_BYTES))
	)
		return undefined;
	if (parsed.fenceSeen !== (parsed.fenceProof !== null)) return undefined;
	if (
		parsed.fenceProof !== null &&
		(parsed.fenceProof.runToken !== parsed.run.runToken ||
			parsed.fenceProof.fenceProducerId !== parsed.identity.fenceProducerId ||
			parsed.fenceProof.fenceOccurrenceId !== parsed.identity.fenceOccurrenceId ||
			(parsed.cursor !== null &&
				(parsed.cursor.filterSha256 !== parsed.fenceProof.filterSha256 ||
					comparePhysicalPosition(parsed.cursor, parsed.fenceProof.locator) < 0)))
	)
		return undefined;
	return parsed as unknown as LiveProgress;
}

type ProgressReadResult =
	| { state: "missing" }
	| { state: "invalid"; reason: string }
	| { state: "valid"; value: LiveProgress };

function readProgress(stagePath: string): ProgressReadResult {
	const path = progressPath(stagePath);
	let exists = false;
	try {
		const stat = lstatSync(path, { bigint: true });
		exists = true;
		if (
			!stat.isFile() ||
			stat.isSymbolicLink() ||
			stat.nlink !== 1n ||
			(typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) ||
			(stat.mode & 0o077n) !== 0n
		)
			return { state: "invalid", reason: "live_observation_progress_file_invalid" };
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT")
			return { state: "invalid", reason: "live_observation_progress_unavailable" };
	}
	if (!exists) return { state: "missing" };
	const value = loadProgress(stagePath);
	return value
		? { state: "valid", value }
		: { state: "invalid", reason: "live_observation_progress_legacy_or_unprovable" };
}

function progressFor(
	trigger: IncidentRecorderLiveTriggerIdentity,
	fence: IncidentRecorderLiveOccurrenceIdentity,
	state: LiveProgress["state"] = "pending",
): LiveProgress {
	return {
		version: LIVE_PROGRESS_VERSION,
		kind: "live_incident_evidence_progress",
		identity: observationIdentity(trigger, fence),
		run: { runId: trigger.runId, runToken: trigger.runToken },
		cursor: null,
		pageCount: 0,
		eventCount: 0,
		bytes: 0,
		chainHeadSha256: null,
		triggerSeen: false,
		fenceSeen: false,
		fenceProof: null,
		state,
		validatedPageCount: 0,
		validatedChainHeadSha256: null,
	};
}

function progressMatches(
	progress: LiveProgress,
	trigger: IncidentRecorderLiveTriggerIdentity,
	fence: IncidentRecorderLiveOccurrenceIdentity,
): boolean {
	return (
		canonicalJson(progress.identity) === canonicalJson(observationIdentity(trigger, fence)) &&
		progress.run.runId === trigger.runId &&
		progress.run.runToken === trigger.runToken &&
		progress.pageCount >= 0
	);
}

type PageReadResult =
	| { state: "missing" }
	| { state: "unavailable"; reason: string }
	| { state: "present"; value: unknown };

function readPage(stagePath: string, sequence: number): PageReadResult {
	const path = pagePath(stagePath, sequence);
	try {
		const stat = lstatSync(path, { bigint: true });
		if (
			!stat.isFile() ||
			stat.isSymbolicLink() ||
			stat.nlink !== 1n ||
			(typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) ||
			(stat.mode & 0o077n) !== 0n
		)
			return { state: "unavailable", reason: "live_observation_page_file_invalid" };
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: "missing" };
		return { state: "unavailable", reason: "live_observation_page_file_unavailable" };
	}
	const value = parseJson(path, MAX_PAGE_BYTES);
	return value === undefined
		? { state: "unavailable", reason: "live_observation_page_readback_failed" }
		: { state: "present", value };
}

function progressWithReason(progress: LiveProgress, reason: string | undefined): LiveProgress {
	const { reason: _reason, ...withoutReason } = progress;
	return reason === undefined ? withoutReason : { ...withoutReason, reason };
}

interface StoredPageValidation {
	triggerSeen: boolean;
	fenceProof: IncidentRecorderLiveFenceProof | null;
}

function validateStoredPage(
	page: IncidentRecorderLiveEvidencePage,
	trigger: IncidentRecorderLiveTriggerIdentity,
	fence: IncidentRecorderLiveOccurrenceIdentity,
	before: IncidentRecorderLiveObservationCursor | null,
	filterSha256: string,
	triggerSeen: boolean,
	fenceProof: IncidentRecorderLiveFenceProof | null,
): { state: "valid" | "invalid"; value?: StoredPageValidation; reason?: string } {
	if (!sameCursor(page.beforeCursor, before)) return { state: "invalid", reason: "page_before_cursor_mismatch" };
	if (page.afterCursor.filterSha256 !== filterSha256)
		return { state: "invalid", reason: "page_filter_identity_mismatch" };
	const beforePosition = before ?? { segmentSequence: 0, ordinal: 0 };
	if (comparePhysicalPosition(page.afterCursor, beforePosition) <= 0)
		return { state: "invalid", reason: "page_after_cursor_did_not_advance" };
	let previousPosition = beforePosition;
	let nextTriggerSeen = triggerSeen;
	let nextFenceProof = fenceProof;
	for (const event of page.events) {
		if (!validRunHistoryEvent(event, trigger.runId)) return { state: "invalid", reason: "page_event_invalid" };
		if (event.identity.runToken !== trigger.runToken)
			return { state: "invalid", reason: "page_event_run_token_mismatch" };
		const locator = segmentLocator(event);
		if (!locator) return { state: "invalid", reason: "page_event_locator_missing" };
		const eventPosition = cursorFromLocator(locator, trigger.runId, filterSha256);
		if (comparePhysicalPosition(eventPosition, previousPosition) <= 0)
			return { state: "invalid", reason: "page_event_physical_order_invalid" };
		previousPosition = eventPosition;
		if (nextFenceProof !== null) return { state: "invalid", reason: "page_event_after_fence" };
		if (eventMatches(event, trigger)) nextTriggerSeen = true;
		if (eventMatches(event, fence)) {
			if (!nextTriggerSeen) return { state: "invalid", reason: "page_fence_before_trigger" };
			if (event.type !== "live_incident_high_water_fence")
				return { state: "invalid", reason: "page_fence_type_invalid" };
			const proof = fenceProofFromEvent(event, fence, filterSha256);
			if (!proof) return { state: "invalid", reason: "page_fence_proof_invalid" };
			nextFenceProof = proof;
		}
	}
	if (nextFenceProof !== null) {
		if (
			page.afterCursor.segmentSequence !== nextFenceProof.locator.segmentSequence ||
			page.afterCursor.ordinal !== nextFenceProof.locator.ordinal
		)
			return { state: "invalid", reason: "page_fence_after_cursor_mismatch" };
	} else if (page.events.length > 0 && comparePhysicalPosition(page.afterCursor, previousPosition) < 0) {
		return { state: "invalid", reason: "page_after_cursor_before_last_event" };
	}
	return { state: "valid", value: { triggerSeen: nextTriggerSeen, fenceProof: nextFenceProof } };
}

function validateStagePages(
	stagePath: string,
	trigger: IncidentRecorderLiveTriggerIdentity,
	fence: IncidentRecorderLiveOccurrenceIdentity,
	progress: LiveProgress,
	maxPages: number,
): { state: "valid" | "pending" | "uncertain"; progress: LiveProgress; reason?: string } {
	const identity = observationIdentity(trigger, fence);
	let validated = progress.validatedPageCount;
	let chain = progress.validatedChainHeadSha256;
	let used = 0;
	let before: IncidentRecorderLiveObservationCursor | null = null;
	let filterSha256 = progress.cursor?.filterSha256 ?? progress.fenceProof?.filterSha256;
	let triggerSeen = progress.validatedPageCount > 0 ? progress.triggerSeen : false;
	let fenceProof: IncidentRecorderLiveFenceProof | null = progress.validatedPageCount > 0 ? progress.fenceProof : null;
	if (
		validated > progress.pageCount ||
		(validated === 0 && chain !== null) ||
		(validated > 0 && chain === null) ||
		progress.fenceSeen !== (progress.fenceProof !== null)
	)
		return { state: "uncertain", progress, reason: "live_observation_progress_validation_invalid" };
	if (progress.fenceProof !== null) {
		if (!validFenceProof(progress.fenceProof, trigger.runId))
			return { state: "uncertain", progress, reason: "live_observation_fence_proof_invalid" };
		filterSha256 ??= progress.fenceProof.filterSha256;
	}
	if (validated > 0) {
		const priorPageResult = readPage(stagePath, validated);
		if (priorPageResult.state !== "present" || !validPage(priorPageResult.value, identity, trigger.runId))
			return { state: "uncertain", progress, reason: `live_observation_validated_page_missing:${validated}` };
		const priorPage = priorPageResult.value as IncidentRecorderLiveEvidencePage;
		if (priorPage.sequence !== validated || priorPage.pageSha256 !== chain)
			return { state: "uncertain", progress, reason: "live_observation_validated_chain_mismatch" };
		before = priorPage.afterCursor;
		filterSha256 ??= priorPage.afterCursor.filterSha256;
	}
	while (validated < progress.pageCount) {
		if (used >= maxPages)
			return {
				state: "pending",
				progress: { ...progress, validatedPageCount: validated, validatedChainHeadSha256: chain },
			};
		const sequence = validated + 1;
		const pageResult = readPage(stagePath, sequence);
		if (pageResult.state === "missing")
			return { state: "uncertain", progress, reason: `live_observation_page_missing:${sequence}` };
		if (pageResult.state === "unavailable")
			return { state: "uncertain", progress, reason: `${pageResult.reason}:${sequence}` };
		const value = pageResult.value;
		if (!validPage(value, identity, trigger.runId))
			return { state: "uncertain", progress, reason: `live_observation_page_invalid:${sequence}` };
		const page = value as IncidentRecorderLiveEvidencePage;
		if (page.sequence !== sequence)
			return { state: "uncertain", progress, reason: `live_observation_page_sequence_invalid:${sequence}` };
		if (sequence === 1) {
			if (page.previousPageSha256 !== null || page.beforeCursor !== null)
				return { state: "uncertain", progress, reason: "live_observation_first_page_chain_invalid" };
		} else if (page.previousPageSha256 !== chain) {
			return { state: "uncertain", progress, reason: `live_observation_page_chain_invalid:${sequence}` };
		}
		filterSha256 ??= page.afterCursor.filterSha256;
		if (!filterSha256) return { state: "uncertain", progress, reason: "live_observation_filter_identity_missing" };
		const pageValidation = validateStoredPage(page, trigger, fence, before, filterSha256, triggerSeen, fenceProof);
		if (pageValidation.state === "invalid")
			return { state: "uncertain", progress, reason: `${pageValidation.reason}:${sequence}` };
		triggerSeen = pageValidation.value?.triggerSeen ?? triggerSeen;
		fenceProof = pageValidation.value?.fenceProof ?? fenceProof;
		before = page.afterCursor;
		chain = page.pageSha256;
		validated = sequence;
		used += 1;
	}
	const result = {
		...progress,
		validatedPageCount: validated,
		validatedChainHeadSha256: chain,
		triggerSeen,
		fenceSeen: fenceProof !== null,
		fenceProof,
	};
	if (result.cursor !== null && (before === null || !sameCursor(result.cursor, before)))
		return { state: "uncertain", progress: result, reason: "live_observation_progress_cursor_mismatch" };
	if (
		result.fenceProof !== null &&
		(result.fenceProof.filterSha256 !== filterSha256 ||
			result.fenceProof.fenceProducerId !== fence.producerId ||
			result.fenceProof.fenceOccurrenceId !== fence.occurrenceId)
	)
		return { state: "uncertain", progress: result, reason: "live_observation_fence_proof_mismatch" };
	if (
		result.fenceSeen !== progress.fenceSeen ||
		(result.fenceProof !== null &&
			progress.fenceProof !== null &&
			canonicalJson(result.fenceProof) !== canonicalJson(progress.fenceProof))
	) {
		// A durable page is enough to recover a crash between page and progress
		// commits; the caller persists this recovered proof before publication.
		return { state: "valid", progress: result };
	}
	const stalePage = readPage(stagePath, progress.pageCount + 1);
	if (stalePage.state === "unavailable")
		return { state: "uncertain", progress: result, reason: `${stalePage.reason}:${progress.pageCount + 1}` };
	if (stalePage.state === "present") {
		if (!validPage(stalePage.value, identity, trigger.runId))
			return { state: "uncertain", progress: result, reason: "live_observation_stale_page_invalid" };
		const page = stalePage.value as IncidentRecorderLiveEvidencePage;
		if (page.sequence !== progress.pageCount + 1 || page.previousPageSha256 !== chain)
			return { state: "uncertain", progress: result, reason: "live_observation_stale_progress_conflict" };
		if (!filterSha256) filterSha256 = page.afterCursor.filterSha256;
		const pageValidation = validateStoredPage(
			page,
			trigger,
			fence,
			progress.cursor,
			filterSha256,
			triggerSeen,
			fenceProof,
		);
		if (pageValidation.state === "invalid")
			return {
				state: "uncertain",
				progress: result,
				reason: `live_observation_stale_page_invalid:${pageValidation.reason}`,
			};
		const recoveredFenceProof = pageValidation.value?.fenceProof ?? fenceProof;
		const recovered = {
			...result,
			cursor: page.afterCursor,
			pageCount: page.sequence,
			eventCount: result.eventCount + page.events.length,
			bytes: result.bytes + bytes(page).length,
			chainHeadSha256: page.pageSha256,
			triggerSeen: pageValidation.value?.triggerSeen ?? triggerSeen,
			fenceSeen: recoveredFenceProof !== null,
			fenceProof: recoveredFenceProof,
			validatedPageCount: page.sequence,
			validatedChainHeadSha256: page.pageSha256,
		};
		return { state: "valid", progress: recovered };
	}
	return { state: "valid", progress: result };
}

function observationFrom(
	trigger: IncidentRecorderLiveTriggerIdentity,
	fence: IncidentRecorderLiveOccurrenceIdentity,
	classification: { value: string; causeLayer: string },
	locator: IncidentRecorderSegmentLocator,
	filterSha256: string,
	progress: LiveProgress,
): IncidentRecorderLiveObservation {
	return {
		version: LIVE_OBSERVATION_VERSION,
		kind: "live_incident_observation",
		state: "published",
		diagnosticOnly: true,
		terminal: false,
		identity: observationIdentity(trigger, fence),
		run: { runId: trigger.runId, runToken: trigger.runToken },
		classification: classification.value,
		causeLayer: classification.causeLayer,
		trigger: {
			producerId: trigger.producerId,
			occurrenceId: trigger.occurrenceId,
			type: trigger.type as string,
			acceptedAtWallTimeMs: trigger.acceptedAtWallTimeMs,
		},
		anchorWallTimeMs: trigger.acceptedAtWallTimeMs,
		targetSnapshot: {
			kind: "physical_fence",
			runId: trigger.runId,
			filterSha256,
			segmentSequence: locator.segmentSequence,
			ordinal: locator.ordinal,
			fenceProducerId: fence.producerId,
			fenceOccurrenceId: fence.occurrenceId,
		},
		coverage: {
			scope: "live-run-prefix",
			fence: "physical",
			chainHeadSha256: progress.chainHeadSha256 as string,
			pageCount: progress.pageCount,
			eventCount: progress.eventCount,
			state: "complete",
			reason: "physical_fence_reached",
		},
	};
}

function resultReason(reason: string): string {
	if (Buffer.byteLength(reason, "utf8") <= MAX_REASON_BYTES) return reason;
	let result = "";
	let resultBytes = 0;
	for (const character of reason) {
		const characterBytes = Buffer.byteLength(character, "utf8");
		if (resultBytes + characterBytes > MAX_REASON_BYTES) break;
		result += character;
		resultBytes += characterBytes;
	}
	return result;
}

function pendingPublicationResult(
	incidentId: string,
	publicationId: string,
	inspection: {
		state: "pending" | "incomplete" | "uncertain";
		reason: string;
		validationCheckpoint?: IncidentRecorderLiveObservationValidationCheckpoint;
	},
	progressPathValue: string,
	progressFallback: LiveProgress,
): IncidentRecorderLiveIncidentPublicationResult {
	if (inspection.state === "uncertain")
		return { state: "uncertain", incidentId, publicationId, reason: inspection.reason };
	const progressRead = readProgress(progressPathValue);
	const progress = progressRead.state === "valid" ? progressRead.value : progressFallback;
	return {
		state: "pending",
		incidentId,
		publicationId,
		progress,
		reason: inspection.reason,
		...(inspection.validationCheckpoint === undefined
			? {}
			: { validationCheckpoint: inspection.validationCheckpoint }),
	};
}

export function inspectLiveIncidentObservation(input: {
	incidentsDirectory: string;
	incidentId: string;
	maxValidationPagesPerPass?: number;
	validationCheckpoint?: IncidentRecorderLiveObservationValidationCheckpoint;
}): IncidentRecorderLiveIncidentInspection {
	if (!SAFE_INCIDENT_ID.test(input.incidentId))
		return { state: "uncertain", incidentId: input.incidentId, reason: "live_observation_incident_id_invalid" };
	const match = LIVE_INCIDENT_ID.exec(input.incidentId);
	if (!match || !match.slice(1).every((part) => uuid(part))) return { state: "missing" };
	const directory = join(input.incidentsDirectory, input.incidentId);
	try {
		const directoryStat = lstatSync(directory, { bigint: true });
		if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink())
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: "live_observation_artifact_directory_invalid",
			};
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: "missing" };
		return {
			state: "uncertain",
			incidentId: input.incidentId,
			reason: "live_observation_artifact_directory_unavailable",
		};
	}
	const descriptor = parseJson(observationPath(directory), MAX_PAGE_BYTES);
	if (!validObservation(descriptor)) {
		return { state: "uncertain", incidentId: input.incidentId, reason: "live_observation_descriptor_invalid" };
	}
	if (
		descriptor.identity.triggerProducerId !== match[1] ||
		descriptor.identity.triggerOccurrenceId !== match[2] ||
		descriptor.run.runId !== match[3] ||
		descriptor.targetSnapshot.runId !== match[3]
	) {
		return {
			state: "uncertain",
			incidentId: input.incidentId,
			reason: "live_observation_descriptor_identity_mismatch",
		};
	}
	const stagePublication = sha256(
		canonicalJson({
			version: 1,
			trigger: {
				producerId: descriptor.trigger.producerId,
				occurrenceId: descriptor.trigger.occurrenceId,
				acceptedAtWallTimeMs: descriptor.trigger.acceptedAtWallTimeMs,
				runId: descriptor.run.runId,
				runToken: descriptor.run.runToken,
			},
			fence: {
				producerId: descriptor.targetSnapshot.fenceProducerId,
				occurrenceId: descriptor.targetSnapshot.fenceOccurrenceId,
				runId: descriptor.run.runId,
				runToken: descriptor.run.runToken,
			},
			classification: { value: descriptor.classification, causeLayer: descriptor.causeLayer },
		}),
	);
	const descriptorSha256 = sha256(bytes(descriptor));
	const evidenceDirectory = join(directory, "evidence");
	const evidenceDirectoryRoot = directoryRoot(evidenceDirectory);
	if (!evidenceDirectoryRoot)
		return {
			state: "uncertain",
			incidentId: input.incidentId,
			reason: "live_observation_evidence_directory_invalid",
		};
	const progress = loadProgress(directory);
	if (
		!progress ||
		canonicalJson(progress.identity) !== canonicalJson(descriptor.identity) ||
		canonicalJson(progress.run) !== canonicalJson(descriptor.run) ||
		progress.state !== "published" ||
		progress.pageCount !== descriptor.coverage.pageCount ||
		progress.eventCount !== descriptor.coverage.eventCount ||
		progress.chainHeadSha256 !== descriptor.coverage.chainHeadSha256
	)
		return { state: "uncertain", incidentId: input.incidentId, reason: "live_observation_progress_mismatch" };
	const identity = descriptor.identity;
	const run = descriptor.run;
	const trigger: IncidentRecorderLiveTriggerIdentity = {
		runId: run.runId,
		runToken: run.runToken,
		producerId: descriptor.trigger.producerId,
		occurrenceId: descriptor.trigger.occurrenceId,
		acceptedAtWallTimeMs: descriptor.trigger.acceptedAtWallTimeMs,
		type: descriptor.trigger.type,
	};
	const fence: IncidentRecorderLiveOccurrenceIdentity = {
		runId: run.runId,
		runToken: run.runToken,
		producerId: descriptor.targetSnapshot.fenceProducerId,
		occurrenceId: descriptor.targetSnapshot.fenceOccurrenceId,
	};
	const suppliedCheckpoint = input.validationCheckpoint;
	if (
		suppliedCheckpoint !== undefined &&
		!validValidationCheckpoint(
			suppliedCheckpoint,
			identity,
			run,
			stagePublication,
			descriptorSha256,
			evidenceDirectoryRoot,
			descriptor.coverage.pageCount,
		)
	)
		return {
			state: "uncertain",
			incidentId: input.incidentId,
			reason: "live_observation_validation_checkpoint_invalid",
		};
	let checkpoint =
		suppliedCheckpoint ??
		makeValidationCheckpoint({
			publicationId: stagePublication,
			descriptorSha256,
			evidenceDirectoryRoot,
			identity,
			run,
			pageCount: 0,
			chainHeadSha256: null,
			cursor: null,
			eventCount: 0,
			bytes: 0,
			triggerSeen: false,
			fenceSeen: false,
			fenceProof: null,
		});
	const maxPages = Math.max(
		1,
		Math.min(input.maxValidationPagesPerPass ?? MAX_VALIDATION_PAGES_PER_PASS, MAX_VALIDATION_PAGES_PER_PASS),
	);
	let previous = checkpoint.chainHeadSha256;
	let beforeCursor = checkpoint.cursor;
	let eventCount = checkpoint.eventCount;
	let totalBytes = checkpoint.bytes;
	let triggerSeen = checkpoint.triggerSeen;
	let fenceProof = checkpoint.fenceProof;
	if (checkpoint.pageCount > 0) {
		const priorPageResult = readPage(directory, checkpoint.pageCount);
		if (priorPageResult.state === "missing")
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: `live_observation_page_missing:${checkpoint.pageCount}`,
			};
		if (priorPageResult.state === "unavailable")
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: `${priorPageResult.reason}:${checkpoint.pageCount}`,
			};
		const priorPage = priorPageResult.value;
		if (!validPage(priorPage, identity, run.runId))
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: `live_observation_page_invalid:${checkpoint.pageCount}`,
			};
		const typedPriorPage = priorPage as IncidentRecorderLiveEvidencePage;
		if (
			typedPriorPage.sequence !== checkpoint.pageCount ||
			typedPriorPage.pageSha256 !== checkpoint.chainHeadSha256 ||
			!sameCursor(typedPriorPage.afterCursor, checkpoint.cursor)
		)
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: "live_observation_validation_checkpoint_boundary_mismatch",
			};
	}
	let used = 0;
	while (checkpoint.pageCount < descriptor.coverage.pageCount) {
		if (used >= maxPages)
			return {
				state: "pending",
				incidentId: input.incidentId,
				reason: "live_observation_validation_budget",
				validationCheckpoint: checkpoint,
			};
		const sequence = checkpoint.pageCount + 1;
		const pageResult = readPage(directory, sequence);
		if (pageResult.state === "missing")
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: `live_observation_page_missing:${sequence}`,
			};
		if (pageResult.state === "unavailable")
			return { state: "uncertain", incidentId: input.incidentId, reason: `${pageResult.reason}:${sequence}` };
		const page = pageResult.value;
		if (!validPage(page, identity, run.runId))
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: `live_observation_page_invalid:${sequence}`,
			};
		const typed = page as IncidentRecorderLiveEvidencePage;
		if (
			typed.sequence !== sequence ||
			typed.previousPageSha256 !== previous ||
			(sequence === 1 && typed.beforeCursor !== null) ||
			(sequence > 1 && typed.beforeCursor === null)
		)
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: `live_observation_page_chain_invalid:${sequence}`,
			};
		const pageValidation = validateStoredPage(
			typed,
			trigger,
			fence,
			beforeCursor,
			descriptor.targetSnapshot.filterSha256,
			triggerSeen,
			fenceProof,
		);
		if (pageValidation.state === "invalid")
			return {
				state: "uncertain",
				incidentId: input.incidentId,
				reason: `${pageValidation.reason}:${sequence}`,
			};
		triggerSeen = pageValidation.value?.triggerSeen ?? triggerSeen;
		const nextFenceProof = pageValidation.value?.fenceProof ?? fenceProof;
		if (nextFenceProof !== null && fenceProof === null) {
			if (
				nextFenceProof.locator.segmentSequence !== descriptor.targetSnapshot.segmentSequence ||
				nextFenceProof.locator.ordinal !== descriptor.targetSnapshot.ordinal ||
				typed.afterCursor.segmentSequence !== nextFenceProof.locator.segmentSequence ||
				typed.afterCursor.ordinal !== nextFenceProof.locator.ordinal
			)
				return {
					state: "uncertain",
					incidentId: input.incidentId,
					reason: "live_observation_fence_locator_mismatch",
				};
		}
		beforeCursor = typed.afterCursor;
		previous = typed.pageSha256;
		eventCount += typed.events.length;
		totalBytes += bytes(typed).length;
		fenceProof = nextFenceProof;
		checkpoint = makeValidationCheckpoint({
			publicationId: stagePublication,
			descriptorSha256,
			evidenceDirectoryRoot,
			identity,
			run,
			pageCount: sequence,
			chainHeadSha256: previous,
			cursor: beforeCursor,
			eventCount,
			bytes: totalBytes,
			triggerSeen,
			fenceSeen: fenceProof !== null,
			fenceProof,
		});
		used += 1;
	}
	if (directoryRoot(evidenceDirectory) !== checkpoint.evidenceDirectoryRoot)
		return {
			state: "uncertain",
			incidentId: input.incidentId,
			reason: "live_observation_evidence_directory_changed",
		};
	const extraPage = readPage(directory, descriptor.coverage.pageCount + 1);
	if (extraPage.state === "unavailable")
		return {
			state: "uncertain",
			incidentId: input.incidentId,
			reason: `${extraPage.reason}:${descriptor.coverage.pageCount + 1}`,
		};
	if (extraPage.state === "present")
		return { state: "uncertain", incidentId: input.incidentId, reason: "live_observation_extra_page" };
	if (directoryRoot(evidenceDirectory) !== checkpoint.evidenceDirectoryRoot)
		return {
			state: "uncertain",
			incidentId: input.incidentId,
			reason: "live_observation_evidence_directory_changed",
		};
	if (
		!checkpoint.triggerSeen ||
		!checkpoint.fenceSeen ||
		beforeCursor === null ||
		!sameCursor(checkpoint.cursor, beforeCursor) ||
		progress.cursor === null ||
		!sameCursor(progress.cursor, checkpoint.cursor) ||
		progress.triggerSeen !== checkpoint.triggerSeen ||
		progress.fenceSeen !== checkpoint.fenceSeen ||
		fenceProof === null ||
		progress.fenceProof === null ||
		canonicalJson(progress.fenceProof) !== canonicalJson(fenceProof) ||
		progress.fenceProof.filterSha256 !== descriptor.targetSnapshot.filterSha256 ||
		previous !== descriptor.coverage.chainHeadSha256 ||
		eventCount !== descriptor.coverage.eventCount ||
		totalBytes !== checkpoint.bytes ||
		progress.bytes !== checkpoint.bytes ||
		progress.validatedPageCount !== descriptor.coverage.pageCount ||
		progress.validatedChainHeadSha256 !== descriptor.coverage.chainHeadSha256 ||
		!SHA256.test(stagePublication)
	)
		return { state: "uncertain", incidentId: input.incidentId, reason: "live_observation_descriptor_chain_mismatch" };
	return {
		state: "published",
		incidentId: input.incidentId,
		publicationId: stagePublication,
		artifactPath: directory,
		observation: descriptor,
	};
}

export function publishLiveIncidentObservation(
	input: IncidentRecorderLiveIncidentPublicationInput,
): IncidentRecorderLiveIncidentPublicationResult {
	const normalized = validateIdentityInput(input.trigger, input.fence, input.classification);
	const { trigger, fence, incidentId: id, publicationId: pub } = normalized;
	const incidentsDirectory = resolve(input.incidentsDirectory);
	const finalDirectory = join(incidentsDirectory, id);
	const existing = inspectLiveIncidentObservation({
		incidentsDirectory,
		incidentId: id,
		maxValidationPagesPerPass: input.maxValidationPagesPerPass,
		validationCheckpoint: input.validationCheckpoint,
	});
	if (existing.state === "published" && existing.publicationId === pub)
		return {
			state: "published",
			incidentId: id,
			publicationId: existing.publicationId,
			artifactPath: existing.artifactPath,
			observation: existing.observation,
			noOp: true,
		};
	if (existing.state === "published")
		return {
			state: "conflict",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_existing_trigger_conflict",
		};
	if (existing.state === "uncertain")
		return { state: "uncertain", incidentId: id, publicationId: pub, reason: existing.reason };
	if (existing.state === "pending" || existing.state === "incomplete")
		return pendingPublicationResult(id, pub, existing, progressPath(finalDirectory), progressFor(trigger, fence));
	try {
		mkdirSync(incidentsDirectory, { recursive: true, mode: 0o700 });
	} catch {
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_incidents_directory_unavailable",
		};
	}
	if (!privateDirectory(incidentsDirectory))
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_incidents_directory_invalid",
		};
	const stages = stageNames(incidentsDirectory, id);
	if (stages.state === "unavailable")
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_stage_listing_unavailable",
		};
	if (stages.names.some((name) => name !== `.${id}.partial-${pub}`))
		return {
			state: "conflict",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_conflicting_partial_stage",
		};
	const stageDirectory = join(incidentsDirectory, `.${id}.partial-${pub}`);
	try {
		mkdirSync(stageDirectory, { recursive: true, mode: 0o700 });
	} catch {
		return { state: "uncertain", incidentId: id, publicationId: pub, reason: "live_observation_stage_unavailable" };
	}
	if (!privateDirectory(stageDirectory))
		return { state: "uncertain", incidentId: id, publicationId: pub, reason: "live_observation_stage_invalid" };
	try {
		mkdirSync(join(stageDirectory, "evidence"), { recursive: true, mode: 0o700 });
	} catch {
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_evidence_directory_unavailable",
		};
	}
	if (!privateDirectory(join(stageDirectory, "evidence")))
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_evidence_directory_invalid",
		};
	const progressRead = readProgress(stageDirectory);
	if (progressRead.state === "invalid")
		return { state: "uncertain", incidentId: id, publicationId: pub, reason: progressRead.reason };
	if (progressRead.state === "missing" && readPage(stageDirectory, 1).state !== "missing")
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_progress_missing_for_durable_pages",
		};
	let progress = progressRead.state === "valid" ? progressRead.value : progressFor(trigger, fence);
	if (!progressMatches(progress, trigger, fence))
		return {
			state: "conflict",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_stage_identity_conflict",
		};
	const validation = validateStagePages(
		stageDirectory,
		trigger,
		fence,
		progress,
		Math.max(
			1,
			Math.min(input.maxValidationPagesPerPass ?? MAX_VALIDATION_PAGES_PER_PASS, MAX_VALIDATION_PAGES_PER_PASS),
		),
	);
	if (validation.state === "uncertain")
		return { state: "uncertain", incidentId: id, publicationId: pub, reason: validation.reason as string };
	const loadedProgress = progress;
	progress = validation.progress;
	if (validation.state === "pending") {
		const pendingProgress = progressWithReason(
			{ ...progress, state: "pending" },
			"live_observation_validation_budget",
		);
		try {
			if (canonicalJson(pendingProgress) !== canonicalJson(loadedProgress))
				writeProgress(progressPath(stageDirectory), pendingProgress);
		} catch {
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_progress_write_failed",
			};
		}
		return {
			state: "pending",
			incidentId: id,
			publicationId: pub,
			progress: pendingProgress,
			reason: "live_observation_validation_budget",
		};
	}
	if (canonicalJson(progress) !== canonicalJson(loadedProgress)) {
		try {
			writeProgress(progressPath(stageDirectory), progress);
		} catch {
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_progress_write_failed",
			};
		}
	}
	const maxPages = Math.max(1, Math.min(input.maxPagesPerPass ?? MAX_PAGES_PER_PASS, MAX_PAGES_PER_PASS));
	const deadline = input.deadlineMs ?? Number.POSITIVE_INFINITY;
	if (deadline !== Number.POSITIVE_INFINITY && (!Number.isSafeInteger(deadline) || deadline < 0))
		throw new Error("Invalid live observation deadline");
	let pagesRead = 0;
	let filterSha256 = progress.cursor?.filterSha256 ?? progress.fenceProof?.filterSha256;
	const persistProgressOnly = (next: LiveProgress): boolean => {
		try {
			writeProgress(progressPath(stageDirectory), next);
			return true;
		} catch {
			return false;
		}
	};
	while (!progress.fenceSeen && pagesRead < maxPages && Date.now() < deadline) {
		let page: IncidentRecorderLiveRunEventsPage;
		try {
			page = input.compactor.readLiveRunEvents({
				runId: trigger.runId,
				...(progress.cursor ? { cursor: progress.cursor } : {}),
			});
		} catch (error) {
			progress = {
				...progressWithReason(
					{ ...progress, state: "incomplete" },
					resultReason(
						`live_run_event_query_unavailable:${error instanceof Error ? error.message : String(error)}`,
					),
				),
			};
			if (!persistProgressOnly(progress))
				return {
					state: "uncertain",
					incidentId: id,
					publicationId: pub,
					reason: "live_observation_progress_write_failed",
				};
			return {
				state: "incomplete",
				incidentId: id,
				publicationId: pub,
				progress,
				reason: progress.reason as string,
			};
		}
		pagesRead += 1;
		if (!validReaderPage(page, trigger.runId)) {
			progress = progressWithReason({ ...progress, state: "incomplete" }, "live_observation_reader_page_invalid");
			if (!persistProgressOnly(progress))
				return {
					state: "uncertain",
					incidentId: id,
					publicationId: pub,
					reason: "live_observation_progress_write_failed",
				};
			return {
				state: "incomplete",
				incidentId: id,
				publicationId: pub,
				progress,
				reason: progress.reason as string,
			};
		}
		if (filterSha256 === undefined) filterSha256 = page.cursor.filterSha256;
		if (page.cursor.filterSha256 !== filterSha256)
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_filter_identity_mismatch",
			};
		const beforeCursor = progress.cursor;
		const beforePosition = beforeCursor ?? { segmentSequence: 0, ordinal: 0 };
		if (page.state === "incomplete" && comparePhysicalPosition(page.cursor, beforePosition) !== 0)
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_incomplete_cursor_advanced",
			};
		const selected: IncidentRecorderRunHistoryEvent[] = [];
		let triggerSeen = progress.triggerSeen;
		let fenceProof: IncidentRecorderLiveFenceProof | null = progress.fenceProof;
		let previousPosition = beforePosition;
		let pageFailureReason: string | undefined;
		for (const event of page.events) {
			if (!validRunHistoryEvent(event, trigger.runId)) {
				pageFailureReason = "live_observation_reader_event_invalid";
				break;
			}
			if (event.identity.runToken !== trigger.runToken) {
				pageFailureReason = "live_observation_reader_event_run_token_mismatch";
				break;
			}
			const locator = segmentLocator(event);
			if (!locator) {
				pageFailureReason = "live_observation_reader_event_locator_missing";
				break;
			}
			const eventPosition = cursorFromLocator(locator, trigger.runId, filterSha256);
			if (comparePhysicalPosition(eventPosition, previousPosition) <= 0) {
				pageFailureReason = "live_observation_reader_event_physical_order_invalid";
				break;
			}
			const matchesTrigger = eventMatches(event, trigger);
			const matchesFence = eventMatches(event, fence);
			if (matchesTrigger) triggerSeen = true;
			if (matchesFence) {
				if (!triggerSeen) {
					pageFailureReason = "live_incident_high_water_fence_before_trigger";
					break;
				}
				if (event.type !== "live_incident_high_water_fence") {
					pageFailureReason = "live_incident_high_water_fence_type_invalid";
					break;
				}
				const proof = fenceProofFromEvent(event, fence, filterSha256);
				if (!proof) {
					pageFailureReason = "live_incident_high_water_fence_locator_invalid";
					break;
				}
				selected.push(event);
				previousPosition = eventPosition;
				fenceProof = proof;
				break;
			}
			selected.push(event);
			previousPosition = eventPosition;
		}
		const fenceSeen = fenceProof !== null;
		if (
			page.state !== "incomplete" &&
			fenceSeen &&
			(fenceProof === null ||
				page.cursor.segmentSequence < fenceProof.locator.segmentSequence ||
				(page.cursor.segmentSequence === fenceProof.locator.segmentSequence &&
					page.cursor.ordinal < fenceProof.locator.ordinal))
		)
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_fence_cursor_invalid",
			};
		if (pageFailureReason && selected.length === 0) {
			progress = progressWithReason({ ...progress, state: "incomplete" }, pageFailureReason);
			if (!persistProgressOnly(progress))
				return {
					state: "uncertain",
					incidentId: id,
					publicationId: pub,
					reason: "live_observation_progress_write_failed",
				};
			return { state: "incomplete", incidentId: id, publicationId: pub, progress, reason: pageFailureReason };
		}
		let afterCursor: IncidentRecorderLiveObservationCursor | null = null;
		let durableReadState: IncidentRecorderLiveEvidencePage["readState"] = page.state;
		let durableReason: string | undefined;
		if (fenceProof !== null) {
			afterCursor = cursorFromLocator(fenceProof.locator, trigger.runId, filterSha256);
			durableReadState = "complete";
			durableReason = "physical_fence_reached";
		} else if (pageFailureReason) {
			if (selected.length === 0) {
				progress = progressWithReason({ ...progress, state: "incomplete", triggerSeen }, pageFailureReason);
				if (!persistProgressOnly(progress))
					return {
						state: "uncertain",
						incidentId: id,
						publicationId: pub,
						reason: "live_observation_progress_write_failed",
					};
				return { state: "incomplete", incidentId: id, publicationId: pub, progress, reason: pageFailureReason };
			}
			afterCursor =
				previousPosition === beforePosition
					? null
					: cursorFromLocator(
							segmentLocator(
								selected[selected.length - 1] as IncidentRecorderRunHistoryEvent,
							) as IncidentRecorderSegmentLocator,
							trigger.runId,
							filterSha256,
						);
			durableReadState = "incomplete";
			durableReason = pageFailureReason;
		} else if (page.state === "incomplete") {
			if (selected.length === 0) {
				progress = progressWithReason(
					{ ...progress, state: "incomplete", triggerSeen },
					resultReason(page.reason ?? "live_incident_high_water_fence_unavailable"),
				);
				if (!persistProgressOnly(progress))
					return {
						state: "uncertain",
						incidentId: id,
						publicationId: pub,
						reason: "live_observation_progress_write_failed",
					};
				return {
					state: "incomplete",
					incidentId: id,
					publicationId: pub,
					progress,
					reason: progress.reason as string,
				};
			}
			afterCursor = cursorFromLocator(
				segmentLocator(
					selected[selected.length - 1] as IncidentRecorderRunHistoryEvent,
				) as IncidentRecorderSegmentLocator,
				trigger.runId,
				filterSha256,
			);
			durableReadState = "incomplete";
			durableReason = page.reason ? resultReason(page.reason) : "live_incident_high_water_fence_unavailable";
		} else {
			const readerAfter = toCursor(page.cursor);
			if (comparePhysicalPosition(readerAfter, beforePosition) <= 0) {
				progress = progressWithReason(
					{ ...progress, state: "incomplete", triggerSeen },
					"live_observation_reader_page_made_no_progress",
				);
				if (!persistProgressOnly(progress))
					return {
						state: "uncertain",
						incidentId: id,
						publicationId: pub,
						reason: "live_observation_progress_write_failed",
					};
				return {
					state: "incomplete",
					incidentId: id,
					publicationId: pub,
					progress,
					reason: "live_observation_reader_page_made_no_progress",
				};
			}
			afterCursor = readerAfter;
			durableReason = page.reason ? resultReason(page.reason) : undefined;
		}
		if (
			afterCursor !== null &&
			fenceProof === null &&
			selected.length > 0 &&
			comparePhysicalPosition(afterCursor, previousPosition) < 0
		)
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_reader_cursor_before_last_event",
			};
		if (afterCursor === null || comparePhysicalPosition(afterCursor, beforePosition) <= 0) {
			progress = progressWithReason(
				{ ...progress, state: "incomplete", triggerSeen },
				"live_observation_valid_prefix_made_no_progress",
			);
			if (!persistProgressOnly(progress))
				return {
					state: "uncertain",
					incidentId: id,
					publicationId: pub,
					reason: "live_observation_progress_write_failed",
				};
			return {
				state: "incomplete",
				incidentId: id,
				publicationId: pub,
				progress,
				reason: "live_observation_valid_prefix_made_no_progress",
			};
		}
		const body: Omit<IncidentRecorderLiveEvidencePage, "pageSha256"> = {
			version: LIVE_EVIDENCE_PAGE_VERSION,
			kind: "live_incident_evidence_page",
			identity: observationIdentity(trigger, fence),
			runId: trigger.runId,
			sequence: progress.pageCount + 1,
			beforeCursor,
			afterCursor,
			events: selected,
			readState: durableReadState,
			...(durableReason === undefined ? {} : { reason: durableReason }),
			scannedSegments: page.scannedSegments,
			scannedRecords: page.scannedRecords,
			scannedIndexBytes: page.scannedIndexBytes,
			previousPageSha256: progress.chainHeadSha256,
		};
		const durable: IncidentRecorderLiveEvidencePage = { ...body, pageSha256: pageHash(body) };
		const durableBytes = bytes(durable);
		if (durableBytes.length > MAX_PAGE_BYTES) {
			progress = progressWithReason(
				{ ...progress, state: "incomplete" },
				"live_observation_page_size_bound_exceeded",
			);
			if (!persistProgressOnly(progress))
				return {
					state: "uncertain",
					incidentId: id,
					publicationId: pub,
					reason: "live_observation_progress_write_failed",
				};
			return {
				state: "incomplete",
				incidentId: id,
				publicationId: pub,
				progress,
				reason: "live_observation_page_size_bound_exceeded",
			};
		}
		let writeResult: "applied" | "noop" | "conflict";
		try {
			writeResult = writeImmutable(pagePath(stageDirectory, durable.sequence), durableBytes);
		} catch {
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_page_write_failed",
			};
		}
		if (writeResult === "conflict")
			return {
				state: "conflict",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_page_identity_conflict",
			};
		const nextState: LiveProgress["state"] = fenceSeen
			? "published"
			: durableReadState === "incomplete"
				? "incomplete"
				: "pending";
		progress = progressWithReason(
			{
				...progress,
				cursor: afterCursor,
				pageCount: durable.sequence,
				eventCount: progress.eventCount + durable.events.length,
				bytes: progress.bytes + durableBytes.length,
				chainHeadSha256: durable.pageSha256,
				triggerSeen,
				fenceSeen,
				fenceProof,
				state: nextState,
				validatedPageCount: durable.sequence,
				validatedChainHeadSha256: durable.pageSha256,
			},
			durableReason,
		);
		try {
			writeProgress(progressPath(stageDirectory), progress);
			// writeImmutable() fsyncs the page and evidence directory. The
			// progress rename is fsynced by writeProgress(); repeat the directory
			// syncs here to make the commit ordering explicit at this boundary.
			fsyncDirectory(join(stageDirectory, "evidence"));
			fsyncDirectory(stageDirectory);
		} catch {
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_progress_write_failed",
			};
		}
		if (progress.fenceSeen || durableReadState === "incomplete") break;
		if (page.state === "complete") break;
	}
	if (!progress.fenceSeen) {
		progress = progressWithReason(
			{ ...progress, state: "incomplete" },
			resultReason(
				progress.reason ??
					(pagesRead >= maxPages
						? "live_incident_high_water_fence_page_budget"
						: "live_incident_high_water_fence_unavailable"),
			),
		);
		if (!persistProgressOnly(progress))
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_progress_write_failed",
			};
		return { state: "incomplete", incidentId: id, publicationId: pub, progress, reason: progress.reason as string };
	}
	const fenceProof = progress.fenceProof;
	if (!fenceProof || progress.chainHeadSha256 === null) {
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_fence_readback_missing",
		};
	}
	const observation = observationFrom(
		trigger,
		fence,
		input.classification,
		fenceProof.locator,
		fenceProof.filterSha256,
		progress,
	);
	if (!validObservation(observation))
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_descriptor_generation_invalid",
		};
	const descriptorWrite = writeImmutable(observationPath(stageDirectory), bytes(observation));
	if (descriptorWrite === "conflict")
		return { state: "conflict", incidentId: id, publicationId: pub, reason: "live_observation_descriptor_conflict" };
	fsyncDirectory(stageDirectory);
	try {
		lstatSync(finalDirectory);
		const readback = inspectLiveIncidentObservation({
			incidentsDirectory,
			incidentId: id,
			maxValidationPagesPerPass: input.maxValidationPagesPerPass,
			validationCheckpoint: input.validationCheckpoint,
		});
		if (readback.state === "published")
			return {
				state: "published",
				incidentId: id,
				publicationId: readback.publicationId,
				artifactPath: readback.artifactPath,
				observation: readback.observation,
				noOp: true,
			};
		if (readback.state === "pending" || readback.state === "incomplete")
			return pendingPublicationResult(id, pub, readback, progressPath(finalDirectory), progress);
		return {
			state: "conflict",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_final_directory_conflict",
		};
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT")
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_final_directory_unavailable",
			};
	}
	try {
		renameSync(stageDirectory, finalDirectory);
		fsyncDirectory(incidentsDirectory);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST")
			return {
				state: "uncertain",
				incidentId: id,
				publicationId: pub,
				reason: "live_observation_publish_rename_failed",
			};
		const readback = inspectLiveIncidentObservation({
			incidentsDirectory,
			incidentId: id,
			maxValidationPagesPerPass: input.maxValidationPagesPerPass,
			validationCheckpoint: input.validationCheckpoint,
		});
		if (readback.state === "published")
			return {
				state: "published",
				incidentId: id,
				publicationId: readback.publicationId,
				artifactPath: readback.artifactPath,
				observation: readback.observation,
				noOp: true,
			};
		if (readback.state === "pending" || readback.state === "incomplete")
			return pendingPublicationResult(id, pub, readback, progressPath(finalDirectory), progress);
		return {
			state: "conflict",
			incidentId: id,
			publicationId: pub,
			reason: "live_observation_publish_identity_conflict",
		};
	}
	const readback = inspectLiveIncidentObservation({
		incidentsDirectory,
		incidentId: id,
		maxValidationPagesPerPass: input.maxValidationPagesPerPass,
		validationCheckpoint: input.validationCheckpoint,
	});
	if (readback.state === "pending" || readback.state === "incomplete")
		return pendingPublicationResult(id, pub, readback, progressPath(finalDirectory), progress);
	if (readback.state !== "published")
		return {
			state: "uncertain",
			incidentId: id,
			publicationId: pub,
			reason: `live_observation_publish_readback_failed:${readback.state}:${"reason" in readback ? readback.reason : "none"}`,
		};
	return {
		state: "published",
		incidentId: id,
		publicationId: readback.publicationId,
		artifactPath: readback.artifactPath,
		observation: readback.observation,
		noOp: false,
	};
}

export function isLiveIncidentArtifactName(value: string): boolean {
	return LIVE_INCIDENT_ID.test(value);
}

export function isLiveIncidentStageName(value: string): boolean {
	return LIVE_STAGE.test(value);
}
