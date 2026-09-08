import { createHash, type Hash } from "node:crypto";
import {
	type BigIntStats,
	closeSync,
	type Dir,
	constants as fsConstants,
	fstatSync,
	lstatSync,
	opendirSync,
	openSync,
	readSync,
	realpathSync,
	type Stats,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import type { IncidentCasRelativePath, IncidentCasRootMutation } from "./incident-recorder-cas-transaction.js";
import {
	type IncidentRecorderPublishedFinalizationInspection,
	inspectIncidentRetentionAuthority,
	inspectPublishedIncidentFinalization,
} from "./incident-recorder-finalizer.js";
import {
	type IncidentRecorderLiveObservationValidationCheckpoint,
	inspectLiveIncidentObservation,
	isLiveIncidentArtifactName,
	isLiveIncidentStageName,
} from "./incident-recorder-live-publication.js";
import {
	createIncidentRecorderSegmentPruneProtection,
	type IncidentRecorderSegmentPruneProtection,
} from "./incident-recorder-segment-store.js";
import { parseIncidentRecorderRunIdentitySeal } from "./incident-recorder-writer.js";
import {
	type IncidentRecorderWriterLifecycleLease,
	inspectIncidentRecorderWriterLifecycleLeaseMode,
} from "./incident-recorder-writer-lifecycle.js";

export const INCIDENT_DIAGNOSTIC_RETENTION_MS = 3 * 24 * 60 * 60 * 1_000;
export const INCIDENT_CORRUPTION_QUARANTINE_MS = 14 * 24 * 60 * 60 * 1_000;
export const INCIDENT_RETENTION_SERVICE_BUDGET = { maxEntries: 512, maxDeletes: 128 } as const;
const INCIDENT_RETENTION_IDLE_DELAY_MS = 60_000;
const INCIDENT_PIN_BEFORE_MS = 30 * 60 * 1_000;
const INCIDENT_PIN_AFTER_MS = 15 * 60 * 1_000;
const ACTIVE_MARKER = ".recorder-active";
const GC_PREFIX = ".retention-gc-";
const MAX_METADATA_BYTES = 1024 * 1024;
const SERVICE_CONTROL_MAX_BYTES = 64 * 1024;
const PIN_REQUEST_MAX_BYTES = 64 * 1024;
const PIN_MANIFEST_MAX_BYTES = 8 * 1024 * 1024;
const PIN_ARTIFACT_HASH_BYTES_PER_PASS = 4 * 1024 * 1024;
const PIN_ARTIFACTS_PER_PASS = 256;
const PIN_HASH_BUFFER_BYTES = 64 * 1024;
const MAX_LIVE_OBSERVATION_VALIDATION_CHECKPOINTS = 128;
const JOURNAL_PIN_MAX_COUNT = 8_192;
const JOURNAL_PIN_CURSOR_MAX_COUNT = 16_384;
const JOURNAL_PIN_CURSOR_MAX_BYTES = 1024 * 1024;
const JOURNAL_PIN_MAX_ARTIFACT_BYTES = 983_040;
const SYSDIG_PIN_MAX_DISCOVERY_ENTRIES = 256;
const SYSDIG_PIN_MAX_COUNT = 32;
const SYSDIG_PIN_MAX_ARTIFACT_BYTES = 384 * 1024 * 1024;
const PROVIDER_PIN_MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024;
const CAS_NAME = /^([0-9a-f]{64})(?:\.collision-[A-Za-z0-9_.+-]+)?\.blob$/;
const FINALIZATION_ID = /^[0-9a-f]{64}$/;
const HIDDEN_INCIDENT_STAGE = /^\.(.+)\.(?:partial|projection|prepared|publishing)(?:-[A-Za-z0-9_.+-]+)?$/;

export function incidentRetentionNextDelayMs(moreWork: boolean, serviceCadenceMs: number): number {
	if (!Number.isSafeInteger(serviceCadenceMs) || serviceCadenceMs < 1)
		throw new Error("Invalid incident retention service cadence");
	return moreWork ? serviceCadenceMs : INCIDENT_RETENTION_IDLE_DELAY_MS;
}

export interface IncidentRetentionOptions {
	agentDir: string;
	/** The lifecycle lease is the only authority permitted to mutate retention state. */
	writerLifecycleLease?: IncidentRecorderWriterLifecycleLease;
	/** Caller-owned continuation state for bounded live-observation validation. */
	liveObservationValidationCheckpoints?: Map<string, IncidentRecorderLiveObservationValidationCheckpoint>;
	nowMs?: number;
	/** Absolute wall-clock deadline for this bounded pass. */
	deadlineMs?: number;
	maxEntries?: number;
	maxDeletes?: number;
	machineId?: string;
	bootId?: string;
	processIdentity?: (pid: number) => { state: "live"; startId: string } | { state: "dead" } | { state: "uncertain" };
	/** Deletion-only pressure recovery: never creates protocol, mark, or transaction files. */
	recoveryOnly?: boolean;
}

export interface IncidentRetentionResult {
	state: "completed" | "unavailable";
	unavailableReason?:
		| "writer_lifecycle_lease_required"
		| "writer_lifecycle_lease_released"
		| "writer_lifecycle_lease_lost"
		| "writer_lifecycle_namespace_changed"
		| "writer_lifecycle_recovery_conflict"
		| "writer_lifecycle_unavailable";
	scannedEntries: number;
	deletedEntries: number;
	moreWork: boolean;
	uncertainties: string[];
	protectedActiveRuns: string[];
	pendingIncident: boolean;
	segmentPruneProtection: IncidentRecorderSegmentPruneProtection;
}

interface RetentionMutationContext {
	readonly recorder: IncidentCasRootMutation;
	readonly incidents: IncidentCasRootMutation;
	readonly recorderRoot: string;
	readonly incidentsRoot: string;
}

function relativeMutationPath(
	path: string,
	context: RetentionMutationContext,
): { root: IncidentCasRootMutation; relative: IncidentCasRelativePath } | undefined {
	const canonicalPath = resolve(path);
	const canonicalRecorderRoot = resolve(context.recorderRoot);
	const canonicalIncidentsRoot = resolve(context.incidentsRoot);
	const canonicalRoot =
		canonicalPath === canonicalRecorderRoot || canonicalPath.startsWith(`${canonicalRecorderRoot}/`)
			? canonicalRecorderRoot
			: canonicalPath === canonicalIncidentsRoot || canonicalPath.startsWith(`${canonicalIncidentsRoot}/`)
				? canonicalIncidentsRoot
				: undefined;
	if (!canonicalRoot) return undefined;
	let capability: IncidentCasRootMutation;
	if (canonicalRoot === canonicalRecorderRoot) capability = context.recorder;
	else capability = context.incidents;
	if (canonicalPath !== canonicalRoot && !canonicalPath.startsWith(`${canonicalRoot}/`)) return undefined;
	const suffix = canonicalPath.slice(canonicalRoot.length).replace(/^\//, "");
	const components = suffix ? suffix.split("/") : [];
	if (
		components.some((component) => !component || component === "." || component === ".." || component.includes("\\"))
	)
		return undefined;
	return { root: capability, relative: capability.relative(...components) };
}

function sameRetentionIdentity(left: Stats, right: BigIntStats | undefined): boolean {
	return (
		right !== undefined &&
		String(left.dev) === right.dev.toString() &&
		String(left.ino) === right.ino.toString() &&
		left.isDirectory() === right.isDirectory() &&
		left.isFile() === right.isFile() &&
		left.isSymbolicLink() === right.isSymbolicLink() &&
		left.nlink === Number(right.nlink) &&
		left.size === Number(right.size)
	);
}

function fsyncMutationParent(path: string, mutation: RetentionMutationContext): void {
	const parent = relativeMutationPath(dirname(path), mutation);
	if (!parent) throw new Error("retention mutation parent outside namespace");
	parent.root.fsyncDirectory(parent.relative);
}

function canonicalPath(path: string): string | undefined {
	try {
		return realpathSync.native(resolve(path));
	} catch {
		return undefined;
	}
}

function capabilityRootPath(capability: IncidentCasRootMutation): string | undefined {
	try {
		return canonicalPath(capability.publicPath(capability.relative()));
	} catch {
		return undefined;
	}
}

interface Budget {
	scanned: number;
	deleted: number;
	maxEntries: number;
	maxDeletes: number;
	deadlineMs: number;
	liveObservationValidationCheckpoints?: Map<string, IncidentRecorderLiveObservationValidationCheckpoint>;
	pinArtifactHashBytesRemaining: number;
	pinArtifactsRemaining: number;
	moreWork: boolean;
	uncertainties: string[];
}

interface SegmentProtectionAccumulator {
	protectedRunIds: Set<string>;
	uncertain: boolean;
}

interface SegmentProtectionGenerationState {
	generation: number;
	protectedRunIdsKey?: string;
}

const CANONICAL_RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function canonicalRunId(value: unknown): string | undefined {
	if (typeof value !== "string" || !CANONICAL_RUN_ID.test(value)) return undefined;
	return value.toLowerCase();
}

function canonicalRunIdFromArtifactName(value: string): string | undefined {
	return canonicalRunId(value.slice(-36));
}

function hiddenIncidentArtifactName(value: string): string | undefined {
	const match = HIDDEN_INCIDENT_STAGE.exec(value);
	return match?.[1] || undefined;
}

function deadlineReached(budget: Budget): boolean {
	if (Date.now() < budget.deadlineMs) return false;
	budget.moreWork = true;
	return true;
}

interface SmallRead {
	state: "ok" | "missing" | "uncertain";
	bytes?: Buffer;
}

function boundedRead(path: string, maximum = MAX_METADATA_BYTES): SmallRead {
	let descriptor: number | undefined;
	try {
		const beforeOpen = lstatSync(path);
		if (!beforeOpen.isFile() || beforeOpen.isSymbolicLink()) return { state: "uncertain" };
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const stat = fstatSync(descriptor);
		if (
			stat.dev !== beforeOpen.dev ||
			stat.ino !== beforeOpen.ino ||
			!stat.isFile() ||
			!Number.isSafeInteger(stat.size) ||
			stat.size < 0 ||
			stat.size > maximum
		)
			return { state: "uncertain" };
		const value = Buffer.alloc(stat.size);
		let offset = 0;
		while (offset < value.length) {
			const count = readSync(descriptor, value, offset, value.length - offset, offset);
			if (count <= 0) return { state: "uncertain" };
			offset += count;
		}
		const after = fstatSync(descriptor);
		if (
			after.dev !== stat.dev ||
			after.ino !== stat.ino ||
			after.size !== stat.size ||
			after.mtimeMs !== stat.mtimeMs
		)
			return { state: "uncertain" };
		return { state: "ok", bytes: value };
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "ENOENT" ? { state: "missing" } : { state: "uncertain" };
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

function smallJson(
	path: string,
	maximum = MAX_METADATA_BYTES,
): { state: SmallRead["state"]; value?: Record<string, unknown> } {
	const read = boundedRead(path, maximum);
	if (read.state !== "ok" || !read.bytes) return { state: read.state };
	try {
		const value = JSON.parse(read.bytes.toString("utf8")) as unknown;
		return value !== null && typeof value === "object" && !Array.isArray(value)
			? { state: "ok", value: value as Record<string, unknown> }
			: { state: "uncertain" };
	} catch {
		return { state: "uncertain" };
	}
}

function defaultMachineId(): string {
	const value = boundedRead("/etc/machine-id", 4096);
	return value.state === "ok" ? (value.bytes?.toString("utf8").trim() ?? "") : "";
}

function defaultBootId(): string {
	let descriptor: number | undefined;
	try {
		descriptor = openSync("/proc/sys/kernel/random/boot_id", "r");
		const buffer = Buffer.alloc(4097);
		const count = readSync(descriptor, buffer, 0, buffer.length, null);
		return count > 0 && count <= 4096 ? buffer.subarray(0, count).toString("utf8").trim() : "";
	} catch {
		return "";
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

function defaultProcessIdentity(pid: number): ReturnType<NonNullable<IncidentRetentionOptions["processIdentity"]>> {
	let descriptor: number | undefined;
	let bytes: Buffer;
	try {
		descriptor = openSync(`/proc/${pid}/stat`, "r");
		const chunks: Buffer[] = [];
		let total = 0;
		for (;;) {
			const chunk = Buffer.allocUnsafe(Math.min(4096, 64 * 1024 + 1 - total));
			const count = readSync(descriptor, chunk, 0, chunk.length, null);
			if (count === 0) break;
			total += count;
			if (total > 64 * 1024) return { state: "uncertain" };
			chunks.push(chunk.subarray(0, count));
		}
		bytes = Buffer.concat(chunks, total);
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "ENOENT" ? { state: "dead" } : { state: "uncertain" };
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
	const text = bytes.toString("utf8").trim();
	const commandEnd = text.lastIndexOf(")");
	if (commandEnd < 0) return { state: "uncertain" };
	const fields = text.slice(commandEnd + 2).split(" ");
	const startId = fields[19];
	return startId && /^[0-9]+$/.test(startId) ? { state: "live", startId: `proc:${startId}` } : { state: "uncertain" };
}

const resumableDirectories = new Map<string, Dir>();
const incidentScanStates = new Map<
	string,
	{
		protectedRuns: Set<string>;
		pending: boolean;
		segmentProtection: SegmentProtectionAccumulator;
	}
>();
const runScanStates = new Map<
	string,
	{
		hashes: Set<string>;
		activeRuns: Set<string>;
		unsafeForCas: boolean;
		segmentProtection: SegmentProtectionAccumulator;
	}
>();
const segmentProtectionGenerations = new Map<string, SegmentProtectionGenerationState>();

interface TreeWalkState {
	root: string;
	stack: Array<{ path: string; directory: Dir }>;
	complete: boolean;
}
interface CasMarkState extends TreeWalkState {
	marked: Set<string>;
	uncertain: boolean;
	currentFile?: {
		path: string;
		descriptor: number;
		offset: number;
		size: number;
		dev: number;
		ino: number;
		mtimeMs: number;
		carry: string;
	};
	leaseBoundaryMs: number;
}
const referenceWalkStates = new Map<string, TreeWalkState>();
const completedReferencePrunes = new Set<string>();
const completedRunOwnerPrunes = new Set<string>();
const casMarkStates = new Map<string, CasMarkState>();
const casSweepStates = new Map<string, TreeWalkState>();
const completedCasMarks = new Map<string, Set<string>>();

function invalidateCompletedReferencePruneGeneration(root: string): void {
	if (!completedReferencePrunes.has(root)) return;
	completedReferencePrunes.delete(root);
	completedRunOwnerPrunes.delete(root);
}

function createTreeWalk(root: string): TreeWalkState {
	try {
		return { root, stack: [{ path: root, directory: opendirSync(root) }], complete: false };
	} catch (error) {
		return { root, stack: [], complete: (error as NodeJS.ErrnoException).code === "ENOENT" };
	}
}

function nextTreeFile(state: TreeWalkState, budget: Budget): { path: string; stat: Stats } | undefined {
	while (state.stack.length > 0) {
		if (budget.scanned >= budget.maxEntries || deadlineReached(budget)) {
			budget.moreWork = true;
			return undefined;
		}
		const frame = state.stack.at(-1);
		if (!frame) break;
		let entry: ReturnType<Dir["readSync"]>;
		try {
			entry = frame.directory.readSync();
		} catch {
			budget.uncertainties.push(`walk-directory:${frame.path}`);
			state.complete = true;
			return undefined;
		}
		if (!entry) {
			try {
				frame.directory.closeSync();
			} catch {}
			state.stack.pop();
			continue;
		}
		budget.scanned += 1;
		const path = join(frame.path, entry.name);
		let stat: Stats;
		try {
			stat = lstatSync(path);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`walk-stat:${path}`);
			continue;
		}
		if (stat.isSymbolicLink()) {
			budget.uncertainties.push(`walk-symlink:${path}`);
			continue;
		}
		if (stat.isDirectory()) {
			try {
				state.stack.push({ path, directory: opendirSync(path) });
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`walk-open:${path}`);
			}
			continue;
		}
		return { path, stat };
	}
	state.complete = true;
	return undefined;
}

function readDirResumable(path: string, budget: Budget, visit: (name: string, stat: Stats) => void): void {
	let directory = resumableDirectories.get(path);
	try {
		if (!directory) {
			directory = opendirSync(path);
			resumableDirectories.set(path, directory);
		}
		for (;;) {
			if (budget.scanned >= budget.maxEntries || budget.deleted >= budget.maxDeletes || deadlineReached(budget)) {
				budget.moreWork = true;
				return;
			}
			const entry = directory.readSync();
			if (!entry) {
				directory.closeSync();
				resumableDirectories.delete(path);
				return;
			}
			budget.scanned += 1;
			let stat: Stats;
			try {
				stat = lstatSync(join(path, entry.name));
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT")
					budget.uncertainties.push(`stat:${path}/${entry.name}`);
				continue;
			}
			visit(entry.name, stat);
		}
	} catch (error) {
		try {
			directory?.closeSync();
		} catch {}
		resumableDirectories.delete(path);
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`directory:${path}`);
	}
}

function expired(stat: Stats, nowMs: number): boolean {
	return Number.isFinite(stat.mtimeMs) && nowMs - stat.mtimeMs >= INCIDENT_DIAGNOSTIC_RETENTION_MS;
}

function exactWallTime(value: unknown): number | undefined {
	return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : undefined;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
	const actual = Object.keys(value).sort();
	const sortedExpected = [...expected].sort();
	return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function exactServiceTimestamp(value: unknown): number | undefined {
	const timestamp = recordValue(value);
	if (
		!timestamp ||
		!exactKeys(timestamp, ["wallTime", "monotonicNs"]) ||
		typeof timestamp.wallTime !== "string" ||
		typeof timestamp.monotonicNs !== "string" ||
		!/^(?:0|[1-9][0-9]{0,29})$/.test(timestamp.monotonicNs)
	) {
		return undefined;
	}
	const wallTimeMs = Date.parse(timestamp.wallTime);
	return Number.isFinite(wallTimeMs) && new Date(wallTimeMs).toISOString() === timestamp.wallTime
		? wallTimeMs
		: undefined;
}

function recordValue(value: unknown): Record<string, unknown> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function canonicalControlJson(value: unknown, depth = 0): string {
	if (depth > 32) throw new Error("Retention control exceeded its canonical JSON nesting bound");
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
	if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map((child) => canonicalControlJson(child, depth + 1)).join(",")}]`;
	const record = recordValue(value);
	if (!record) throw new Error("Retention control is not canonical JSON");
	return `{${Object.keys(record)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalControlJson(record[key], depth + 1)}`)
		.join(",")}}`;
}

function controlFingerprint(value: unknown): string {
	return createHash("sha256").update(canonicalControlJson(value)).digest("hex");
}

function validSysdigInitialRingSnapshot(value: unknown, ringBasePath: string): boolean {
	const snapshot = recordValue(value);
	if (
		!snapshot ||
		!exactKeys(snapshot, ["observedAtWallTimeMs", "candidates", "issues"]) ||
		!Number.isSafeInteger(snapshot.observedAtWallTimeMs) ||
		Number(snapshot.observedAtWallTimeMs) < 0 ||
		!Array.isArray(snapshot.candidates) ||
		snapshot.candidates.length > SYSDIG_PIN_MAX_COUNT ||
		!Array.isArray(snapshot.issues) ||
		snapshot.issues.length > SYSDIG_PIN_MAX_DISCOVERY_ENTRIES ||
		snapshot.issues.some((issue) => typeof issue !== "string" || Buffer.byteLength(issue, "utf8") > 4 * 1024) ||
		Buffer.byteLength(JSON.stringify(snapshot), "utf8") > PIN_REQUEST_MAX_BYTES
	)
		return false;
	const ringDirectory = dirname(ringBasePath);
	const ringName = basename(ringBasePath);
	if (!ringName || Buffer.byteLength(ringName, "utf8") > 255) return false;
	const observedPaths = new Set<string>();
	const observedIds = new Set<string>();
	let totalBytes = 0;
	let previous: { mtimeMs: number; sourceName: string } | undefined;
	for (const [index, candidateValue] of snapshot.candidates.entries()) {
		const candidate = recordValue(candidateValue);
		const source = recordValue(candidate?.source);
		if (
			!candidate ||
			!source ||
			!exactKeys(candidate, ["id", "sourcePath", "sourceName", "activeAtRequest", "source"]) ||
			!exactKeys(source, ["dev", "ino", "bytes", "mtimeMs", "ctimeMs"]) ||
			typeof candidate.id !== "string" ||
			!/^[0-9a-f]{64}$/.test(candidate.id) ||
			typeof candidate.sourcePath !== "string" ||
			typeof candidate.sourceName !== "string" ||
			candidate.sourceName.length === 0 ||
			Buffer.byteLength(candidate.sourceName, "utf8") > 255 ||
			basename(candidate.sourceName) !== candidate.sourceName ||
			!candidate.sourceName.startsWith(ringName) ||
			Buffer.byteLength(candidate.sourcePath, "utf8") > 4 * 1024 ||
			resolve(candidate.sourcePath) !== resolve(join(ringDirectory, candidate.sourceName)) ||
			candidate.activeAtRequest !== (index === 0) ||
			typeof source.dev !== "string" ||
			Buffer.byteLength(source.dev, "utf8") > 32 ||
			!/^(?:0|[1-9]\d*)$/.test(source.dev) ||
			typeof source.ino !== "string" ||
			Buffer.byteLength(source.ino, "utf8") > 32 ||
			!/^(?:0|[1-9]\d*)$/.test(source.ino) ||
			!Number.isSafeInteger(source.bytes) ||
			Number(source.bytes) < 0 ||
			Number(source.bytes) > SYSDIG_PIN_MAX_ARTIFACT_BYTES ||
			!Number.isFinite(source.mtimeMs) ||
			Number(source.mtimeMs) < 0 ||
			!Number.isFinite(source.ctimeMs) ||
			Number(source.ctimeMs) < 0
		)
			return false;
		const expectedId = createHash("sha256")
			.update(
				`${source.dev}\0${source.ino}\0${String(source.bytes)}\0${String(source.mtimeMs)}\0${String(source.ctimeMs)}`,
			)
			.digest("hex");
		if (
			candidate.id !== expectedId ||
			observedIds.has(candidate.id) ||
			observedPaths.has(resolve(candidate.sourcePath))
		)
			return false;
		if (
			previous &&
			(Number(source.mtimeMs) > previous.mtimeMs ||
				(Number(source.mtimeMs) === previous.mtimeMs && candidate.sourceName > previous.sourceName))
		)
			return false;
		observedIds.add(candidate.id);
		observedPaths.add(resolve(candidate.sourcePath));
		previous = { mtimeMs: Number(source.mtimeMs), sourceName: candidate.sourceName };
		totalBytes += Number(source.bytes);
		if (!Number.isSafeInteger(totalBytes) || totalBytes > PROVIDER_PIN_MAX_TOTAL_BYTES) return false;
	}
	return true;
}

function validServiceBoundedCount(value: unknown): boolean {
	const count = recordValue(value);
	return Boolean(
		count &&
			exactKeys(count, ["records", "bytes"]) &&
			Number.isSafeInteger(count.records) &&
			Number(count.records) >= 0 &&
			Number.isSafeInteger(count.bytes) &&
			Number(count.bytes) >= 0,
	);
}

function validServiceProcessStartId(value: unknown): boolean {
	return (
		typeof value === "string" &&
		(/^(?:proc|win):\d+$/.test(value) ||
			/^ps:[A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}$/.test(value))
	);
}

function validServiceRelayFrontier(value: unknown, type: "supervisor_exit" | "capture_channel_terminal"): boolean {
	const frontier = recordValue(value);
	if (
		!frontier ||
		!exactKeys(frontier, [
			"occurrenceId",
			"producerId",
			"type",
			"firstProducerSequence",
			"lastProducerSequence",
			"firstWrapperSequence",
			"lastWrapperSequence",
		]) ||
		frontier.type !== type ||
		canonicalRunId(frontier.occurrenceId) !== frontier.occurrenceId ||
		canonicalRunId(frontier.producerId) !== frontier.producerId
	)
		return false;
	const sequences = [
		frontier.firstProducerSequence,
		frontier.lastProducerSequence,
		frontier.firstWrapperSequence,
		frontier.lastWrapperSequence,
	];
	if (sequences.some((entry) => typeof entry !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/.test(entry))) return false;
	try {
		const maximum = (1n << 64n) - 1n;
		const firstProducer = BigInt(frontier.firstProducerSequence as string);
		const lastProducer = BigInt(frontier.lastProducerSequence as string);
		const firstWrapper = BigInt(frontier.firstWrapperSequence as string);
		const lastWrapper = BigInt(frontier.lastWrapperSequence as string);
		return (
			lastProducer <= maximum &&
			lastWrapper <= maximum &&
			firstProducer <= lastProducer &&
			firstWrapper <= lastWrapper
		);
	} catch {
		return false;
	}
}

function validServiceBarrierExpectation(value: unknown, runId: string, runToken: string): boolean {
	const barrier = recordValue(value);
	if (!barrier) return false;
	const keys = [
		"version",
		"runId",
		"runToken",
		"wrapperPid",
		"wrapperStartId",
		"finalQueuedTailLoss",
		"emitterFinalTailLoss",
		"exitCode",
		"exitSignal",
		...(barrier.supervisorExit === undefined ? [] : ["supervisorExit"]),
		...(barrier.wrapperTerminal === undefined ? [] : ["wrapperTerminal"]),
	];
	return (
		exactKeys(barrier, keys) &&
		barrier.version === 1 &&
		barrier.runId === runId &&
		barrier.runToken === runToken &&
		Number.isSafeInteger(barrier.wrapperPid) &&
		Number(barrier.wrapperPid) > 0 &&
		(barrier.wrapperStartId === null || validServiceProcessStartId(barrier.wrapperStartId)) &&
		validServiceBoundedCount(barrier.finalQueuedTailLoss) &&
		validServiceBoundedCount(barrier.emitterFinalTailLoss) &&
		(barrier.exitCode === "unavailable" ||
			(Number.isSafeInteger(barrier.exitCode) &&
				Number(barrier.exitCode) >= 0 &&
				Number(barrier.exitCode) <= 255)) &&
		(barrier.exitSignal === "unavailable" ||
			(typeof barrier.exitSignal === "string" && /^SIG[A-Z0-9]+$/.test(barrier.exitSignal))) &&
		(barrier.supervisorExit === undefined || validServiceRelayFrontier(barrier.supervisorExit, "supervisor_exit")) &&
		(barrier.wrapperTerminal === undefined ||
			validServiceRelayFrontier(barrier.wrapperTerminal, "capture_channel_terminal"))
	);
}

function canonicalServiceSeal(
	value: unknown,
	runId: string,
	runToken: string,
): { terminalOccurrenceId?: string; lossFree: boolean } | undefined {
	const seal = parseIncidentRecorderRunIdentitySeal(value);
	if (!seal || seal.runId !== runId || seal.runToken !== runToken) return undefined;
	const terminalOccurrenceId =
		seal.terminal.admission?.accepted === true
			? seal.terminal.admission.occurrenceId
			: seal.terminal.frontier?.occurrenceId;
	const counts = [
		seal.loss.emitter,
		seal.loss.drainTimeout.definite,
		seal.loss.drainTimeout.uncertain,
		seal.loss.terminalRelay.definite,
		seal.loss.terminalRelay.uncertain,
	];
	return {
		...(terminalOccurrenceId ? { terminalOccurrenceId } : {}),
		lossFree: counts.every((count) => count.records === 0 && count.bytes === 0),
	};
}

function validServiceProcessControl(value: unknown): value is Record<string, unknown> {
	const processControl = recordValue(value);
	if (!processControl) return false;
	const optionalKeys = [
		...(processControl.machineId === undefined ? [] : ["machineId"]),
		...(processControl.bootId === undefined ? [] : ["bootId"]),
		...(processControl.processStartId === undefined ? [] : ["processStartId"]),
	];
	return (
		exactKeys(processControl, [
			"runToken",
			"systemdInvocationId",
			"pid",
			"observed",
			"runtimeCategory",
			"nodeFatalReportsEnabled",
			"orphanPolicy",
			"wrapperDeathSignalsSupervisor",
			...optionalKeys,
		]) &&
		canonicalRunId(processControl.runToken) === processControl.runToken &&
		(processControl.machineId === undefined ||
			(typeof processControl.machineId === "string" && /^[0-9a-f]{32}$/.test(processControl.machineId))) &&
		(processControl.bootId === undefined ||
			(typeof processControl.bootId === "string" &&
				/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(processControl.bootId))) &&
		(processControl.systemdInvocationId === null ||
			(typeof processControl.systemdInvocationId === "string" &&
				Buffer.byteLength(processControl.systemdInvocationId, "utf8") <= 4 * 1024)) &&
		Number.isSafeInteger(processControl.pid) &&
		Number(processControl.pid) > 0 &&
		(processControl.processStartId === undefined || validServiceProcessStartId(processControl.processStartId)) &&
		exactServiceTimestamp(processControl.observed) !== undefined &&
		(processControl.runtimeCategory === "node" || processControl.runtimeCategory === "foreign") &&
		typeof processControl.nodeFatalReportsEnabled === "boolean" &&
		(processControl.runtimeCategory === "node") === processControl.nodeFatalReportsEnabled &&
		processControl.orphanPolicy === "fail-open" &&
		processControl.wrapperDeathSignalsSupervisor === false
	);
}

function currentServiceSealChain(path: string):
	| {
			runId: string;
			runToken: string;
			anchorWallTimeMs: number;
			stoppedDisposition: "exact_first_observation" | "recovered_after_invalid_control";
			terminalOccurrenceId: string;
			sealTerminalOccurrenceId?: string;
			terminalBoundByReplay: boolean;
			replayReason?:
				| "seal_intent_without_seal_observed"
				| "seal_observed_without_intent"
				| "seal_namespace_invalid_or_unbound";
			lossFree: boolean;
			controls: Array<{ path: string; identity: RetentionFileIdentity }>;
			absentControls: string[];
	  }
	| undefined {
	const runId = canonicalRunIdFromArtifactName(basename(path));
	if (!runId) return undefined;
	const processIdentityPath = join(path, "process.json");
	const barrierExpectationPath = join(path, "finalization-barrier-expectation.json");
	const sourceControls: Array<{ path: string; identity: RetentionFileIdentity }> = [];
	const absentControls: string[] = [];
	const stoppedPath = join(path, "service-finalization-stopped-observation.json");
	const stoppedRepairPath = join(path, "service-finalization-stopped-observation-repair.json");
	const intentPath = join(path, "service-finalization-seal-intent.json");
	const sealPath = join(path, "service-finalization-seal.json");
	const fallbackAdmissionLossPath = join(path, "service-finalization-fallback-admission-loss.json");
	const stopped = serviceDecisionJson(stoppedPath);
	const intent = serviceDecisionJson(intentPath);
	const seal = serviceDecisionJson(sealPath);
	if (
		stopped.state !== "ok" ||
		!stopped.value ||
		intent.state !== "ok" ||
		!intent.value ||
		seal.state !== "ok" ||
		!seal.value ||
		!stopped.identity ||
		!intent.identity ||
		!seal.identity ||
		!exactKeys(stopped.value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"firstObservedStoppedWallTimeMs",
			"disposition",
		]) ||
		stopped.value.schemaVersion !== 1 ||
		stopped.value.kind !== "service_stopped_observation" ||
		stopped.value.runId !== runId ||
		canonicalRunId(stopped.value.runToken) !== stopped.value.runToken ||
		exactWallTime(stopped.value.firstObservedStoppedWallTimeMs) === undefined ||
		!(
			stopped.value.disposition === "exact_first_observation" ||
			stopped.value.disposition === "recovered_after_invalid_control"
		)
	)
		return undefined;
	const stoppedRepair = serviceDecisionJson(stoppedRepairPath);
	let sourceRunToken: string;
	if (stopped.value.disposition === "exact_first_observation") {
		if (stoppedRepair.state !== "missing") return undefined;
		absentControls.push(stoppedRepairPath);
		const processIdentity = decisionJson(processIdentityPath, SERVICE_CONTROL_MAX_BYTES);
		if (
			processIdentity.state !== "ok" ||
			!processIdentity.value ||
			!processIdentity.identity ||
			!validServiceProcessControl(processIdentity.value) ||
			processIdentity.value.runToken !== stopped.value.runToken
		)
			return undefined;
		sourceRunToken = processIdentity.value.runToken as string;
		sourceControls.push({ path: processIdentityPath, identity: processIdentity.identity });
	} else {
		if (
			stoppedRepair.state !== "ok" ||
			!stoppedRepair.value ||
			!stoppedRepair.identity ||
			!exactKeys(stoppedRepair.value, ["schemaVersion", "kind", "runId", "runToken", "reason"]) ||
			stoppedRepair.value.schemaVersion !== 1 ||
			stoppedRepair.value.kind !== "service_stopped_observation_repair" ||
			stoppedRepair.value.runId !== runId ||
			canonicalRunId(stoppedRepair.value.runToken) !== stoppedRepair.value.runToken ||
			stoppedRepair.value.runToken !== stopped.value.runToken ||
			stoppedRepair.value.reason !== "invalid_control_observed"
		)
			return undefined;
		sourceRunToken = stoppedRepair.value.runToken as string;
		sourceControls.push({ path: stoppedRepairPath, identity: stoppedRepair.identity });
		const processIdentity = decisionJson(processIdentityPath, SERVICE_CONTROL_MAX_BYTES);
		if (processIdentity.state === "missing") {
			absentControls.push(processIdentityPath);
		} else if (
			processIdentity.state === "ok" &&
			processIdentity.value &&
			processIdentity.identity &&
			validServiceProcessControl(processIdentity.value) &&
			processIdentity.value.runToken === sourceRunToken
		) {
			sourceControls.push({ path: processIdentityPath, identity: processIdentity.identity });
		} else {
			return undefined;
		}
	}
	if (
		!exactKeys(intent.value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"terminalOccurrenceId",
			"retentionAnchorWallTimeMs",
			"stoppedObservationDisposition",
		]) ||
		intent.value.schemaVersion !== 1 ||
		intent.value.kind !== "service_run_seal_intent" ||
		intent.value.runId !== runId ||
		intent.value.runToken !== stopped.value.runToken ||
		canonicalRunId(intent.value.terminalOccurrenceId) !== intent.value.terminalOccurrenceId ||
		exactWallTime(intent.value.retentionAnchorWallTimeMs) !== stopped.value.firstObservedStoppedWallTimeMs ||
		intent.value.stoppedObservationDisposition !== stopped.value.disposition
	)
		return undefined;
	const barrierExpectation = decisionJson(barrierExpectationPath, SERVICE_CONTROL_MAX_BYTES);
	if (barrierExpectation.state === "uncertain") return undefined;
	if (barrierExpectation.state === "ok") {
		if (
			!barrierExpectation.value ||
			!barrierExpectation.identity ||
			!validServiceBarrierExpectation(barrierExpectation.value, runId, sourceRunToken)
		)
			return undefined;
		sourceControls.push({ path: barrierExpectationPath, identity: barrierExpectation.identity });
	} else {
		absentControls.push(barrierExpectationPath);
	}
	const inspectedSeal = canonicalServiceSeal(seal.value, runId, stopped.value.runToken as string);
	if (!inspectedSeal) return undefined;
	const fallbackAdmissionLoss = serviceDecisionJson(fallbackAdmissionLossPath);
	if (fallbackAdmissionLoss.state === "uncertain") return undefined;
	let fallbackAdmissionLossRecords = 0;
	if (fallbackAdmissionLoss.state === "ok") {
		const value = fallbackAdmissionLoss.value;
		if (
			!value ||
			!fallbackAdmissionLoss.identity ||
			!exactKeys(value, [
				"schemaVersion",
				"kind",
				"runId",
				"lostAdmissions",
				"firstObservedWallTimeMs",
				"lastObservedWallTimeMs",
				"synchronousAttemptLimit",
				"synchronousWaitIntervalMs",
				"asynchronousRetryAttempts",
			]) ||
			value.schemaVersion !== 1 ||
			value.kind !== "service_fallback_admission_loss" ||
			value.runId !== runId ||
			!Number.isSafeInteger(value.lostAdmissions) ||
			Number(value.lostAdmissions) <= 0 ||
			exactWallTime(value.firstObservedWallTimeMs) === undefined ||
			exactWallTime(value.lastObservedWallTimeMs) === undefined ||
			Number(value.lastObservedWallTimeMs) < Number(value.firstObservedWallTimeMs) ||
			value.synchronousAttemptLimit !== 3 ||
			value.synchronousWaitIntervalMs !== 5 ||
			!Number.isSafeInteger(value.asynchronousRetryAttempts) ||
			Number(value.asynchronousRetryAttempts) < 0
		) {
			return undefined;
		}
		fallbackAdmissionLossRecords = Number(value.lostAdmissions);
		sourceControls.push({ path: fallbackAdmissionLossPath, identity: fallbackAdmissionLoss.identity });
	} else {
		absentControls.push(fallbackAdmissionLossPath);
	}
	const terminalMatchesIntent = inspectedSeal.terminalOccurrenceId === intent.value.terminalOccurrenceId;
	const replayPath = join(path, "service-finalization-seal-replay-ambiguity.json");
	const replay = serviceDecisionJson(replayPath);
	if (replay.state === "uncertain") return undefined;
	let replayReason:
		| "seal_intent_without_seal_observed"
		| "seal_observed_without_intent"
		| "seal_namespace_invalid_or_unbound"
		| undefined;
	if (replay.state === "ok") {
		if (
			!replay.value ||
			!replay.identity ||
			!exactKeys(replay.value, ["schemaVersion", "kind", "runId", "runToken", "terminalOccurrenceId", "reason"]) ||
			replay.value.schemaVersion !== 1 ||
			replay.value.kind !== "service_run_seal_replay_ambiguity" ||
			replay.value.runId !== runId ||
			replay.value.runToken !== stopped.value.runToken ||
			replay.value.terminalOccurrenceId !== intent.value.terminalOccurrenceId ||
			!(
				[
					"seal_intent_without_seal_observed",
					"seal_observed_without_intent",
					"seal_namespace_invalid_or_unbound",
				] as const
			).includes(
				replay.value.reason as
					| "seal_intent_without_seal_observed"
					| "seal_observed_without_intent"
					| "seal_namespace_invalid_or_unbound",
			)
		)
			return undefined;
		replayReason = replay.value.reason as typeof replayReason;
	}
	if (!terminalMatchesIntent) {
		if (!replayReason) return undefined;
		if (
			inspectedSeal.terminalOccurrenceId === undefined
				? !(
						[
							"seal_intent_without_seal_observed",
							"seal_observed_without_intent",
							"seal_namespace_invalid_or_unbound",
						] as const
					).includes(
						replayReason as
							| "seal_intent_without_seal_observed"
							| "seal_observed_without_intent"
							| "seal_namespace_invalid_or_unbound",
					)
				: replayReason !== "seal_namespace_invalid_or_unbound"
		)
			return undefined;
	}
	return {
		runId,
		runToken: stopped.value.runToken as string,
		anchorWallTimeMs: Number(stopped.value.firstObservedStoppedWallTimeMs),
		stoppedDisposition: stopped.value.disposition as "exact_first_observation" | "recovered_after_invalid_control",
		terminalOccurrenceId: intent.value.terminalOccurrenceId as string,
		...(inspectedSeal.terminalOccurrenceId ? { sealTerminalOccurrenceId: inspectedSeal.terminalOccurrenceId } : {}),
		terminalBoundByReplay: replayReason !== undefined,
		...(replayReason ? { replayReason } : {}),
		lossFree: inspectedSeal.lossFree && fallbackAdmissionLossRecords === 0,
		controls: [
			...sourceControls,
			{ path: stoppedPath, identity: stopped.identity },
			{ path: intentPath, identity: intent.identity },
			{ path: sealPath, identity: seal.identity },
			...(replay.identity ? [{ path: replayPath, identity: replay.identity }] : []),
		],
		absentControls: [...absentControls, ...(replay.state === "missing" ? [replayPath] : [])],
	};
}

function publishedServiceSealDisposition(
	published: Exclude<IncidentRecorderPublishedFinalizationInspection, { state: "pending" }>,
): { disposition: string } | undefined {
	return typeof published.serviceTerminalRelayDisposition === "string"
		? { disposition: published.serviceTerminalRelayDisposition }
		: undefined;
}

function serviceFinalizationSemanticsValid(
	chain: NonNullable<ReturnType<typeof currentServiceSealChain>>,
	outcome: "complete" | "incomplete" | "corrupt",
	disposition: string,
): boolean {
	if (chain.terminalBoundByReplay) {
		return outcome !== "complete" && disposition === "replayed_after_ambiguous_seal_attempt";
	}
	if (disposition === "replayed_after_ambiguous_seal_attempt") return false;
	if (outcome !== "complete") return true;
	return (
		disposition === "relayed" &&
		chain.stoppedDisposition === "exact_first_observation" &&
		chain.sealTerminalOccurrenceId === chain.terminalOccurrenceId &&
		chain.lossFree
	);
}

interface ServiceFinalizationPublicationConflict {
	schemaVersion: 1;
	kind: "service_finalization_publication_conflict";
	runId: string;
	runToken: string;
	publishedFinalizationId: string;
	publishedState: "complete" | "incomplete" | "corrupt";
	publishedRetentionAnchorWallTimeMs: number;
	publishedServiceTerminalRelayDisposition: string;
	intendedFinalizationId: string;
	intendedState: "complete" | "incomplete" | "corrupt";
	intendedRetentionAnchorWallTimeMs: number;
	intendedServiceTerminalRelayDisposition: string;
	reason: "published_finalization_conflict";
}

function canonicalServiceFinalizationPublicationConflict(
	value: Record<string, unknown>,
): ServiceFinalizationPublicationConflict | undefined {
	if (
		!exactKeys(value, [
			"schemaVersion",
			"kind",
			"runId",
			"runToken",
			"publishedFinalizationId",
			"publishedState",
			"publishedRetentionAnchorWallTimeMs",
			"publishedServiceTerminalRelayDisposition",
			"intendedFinalizationId",
			"intendedState",
			"intendedRetentionAnchorWallTimeMs",
			"intendedServiceTerminalRelayDisposition",
			"reason",
		]) ||
		value.schemaVersion !== 1 ||
		value.kind !== "service_finalization_publication_conflict" ||
		canonicalRunId(value.runId) !== value.runId ||
		canonicalRunId(value.runToken) !== value.runToken ||
		typeof value.publishedFinalizationId !== "string" ||
		!FINALIZATION_ID.test(value.publishedFinalizationId) ||
		typeof value.intendedFinalizationId !== "string" ||
		!FINALIZATION_ID.test(value.intendedFinalizationId) ||
		value.publishedFinalizationId === value.intendedFinalizationId ||
		!(["complete", "incomplete", "corrupt"] as const).includes(
			value.publishedState as "complete" | "incomplete" | "corrupt",
		) ||
		!(["complete", "incomplete", "corrupt"] as const).includes(
			value.intendedState as "complete" | "incomplete" | "corrupt",
		) ||
		exactWallTime(value.publishedRetentionAnchorWallTimeMs) === undefined ||
		exactWallTime(value.intendedRetentionAnchorWallTimeMs) === undefined ||
		typeof value.publishedServiceTerminalRelayDisposition !== "string" ||
		value.publishedServiceTerminalRelayDisposition.length === 0 ||
		Buffer.byteLength(value.publishedServiceTerminalRelayDisposition, "utf8") > 4 * 1024 ||
		typeof value.intendedServiceTerminalRelayDisposition !== "string" ||
		value.intendedServiceTerminalRelayDisposition.length === 0 ||
		Buffer.byteLength(value.intendedServiceTerminalRelayDisposition, "utf8") > 4 * 1024 ||
		value.reason !== "published_finalization_conflict"
	) {
		return undefined;
	}
	return value as unknown as ServiceFinalizationPublicationConflict;
}

function serviceFinalizationPublicationConflictDigest(value: ServiceFinalizationPublicationConflict): string {
	return createHash("sha256")
		.update(`${JSON.stringify(value)}\n`, "utf8")
		.digest("hex");
}

function publishedManifestControl(
	published: Exclude<IncidentRecorderPublishedFinalizationInspection, { state: "pending" }>,
): { path: string; identity: RetentionFileIdentity } | undefined {
	const bytes = Buffer.from(`${JSON.stringify(published.manifest)}\n`, "utf8");
	const name =
		published.manifest.kind === "incident_recorder_finalization_manifest"
			? "finalization-manifest.json"
			: `finalization-conflict-manifest-${createHash("sha256").update(bytes).digest("hex")}.json`;
	const path = join(published.authorityDirectory, name);
	const manifest = decisionJson(path, MAX_METADATA_BYTES, "compact");
	if (manifest.state !== "ok" || !manifest.identity || !manifest.bytes?.equals(bytes)) return undefined;
	return { path, identity: manifest.identity };
}

function controlPathMissing(path: string): boolean {
	try {
		lstatSync(path);
		return false;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "ENOENT";
	}
}

function serviceFinalizationCompletion(
	path: string,
	completion: ReturnType<typeof serviceDecisionJson>,
):
	| {
			anchorWallTimeMs: number;
			retentionMilliseconds: number;
			publicationConflictPublishedFinalizationId?: string;
	  }
	| undefined {
	const completionPath = join(path, ".service-finalization-complete");
	if (completion.state !== "ok" || !completion.value || !completion.identity) return undefined;
	const value = completion.value;
	const chain = currentServiceSealChain(path);
	const anchor = exactWallTime(value.retentionAnchorWallTimeMs);
	if (!chain || value.schemaVersion !== 2 || value.runId !== chain.runId || anchor === undefined) return undefined;
	if (value.state === "publication_conflict_reclaimable") {
		if (
			!exactKeys(value, [
				"schemaVersion",
				"state",
				"runId",
				"publishedFinalizationId",
				"intendedFinalizationId",
				"conflictProofSha256",
				"retentionAnchorWallTimeMs",
			]) ||
			typeof value.publishedFinalizationId !== "string" ||
			!FINALIZATION_ID.test(value.publishedFinalizationId) ||
			typeof value.intendedFinalizationId !== "string" ||
			!FINALIZATION_ID.test(value.intendedFinalizationId) ||
			value.publishedFinalizationId === value.intendedFinalizationId ||
			typeof value.conflictProofSha256 !== "string" ||
			!FINALIZATION_ID.test(value.conflictProofSha256)
		) {
			return undefined;
		}
		const conflictPath = join(path, "service-finalization-publication-conflict.json");
		const conflictRead = serviceDecisionJson(conflictPath);
		const conflict = conflictRead.value
			? canonicalServiceFinalizationPublicationConflict(conflictRead.value)
			: undefined;
		if (
			conflictRead.state !== "ok" ||
			!conflictRead.identity ||
			!conflict ||
			conflict.runId !== chain.runId ||
			conflict.runToken !== chain.runToken ||
			conflict.publishedFinalizationId !== value.publishedFinalizationId ||
			conflict.intendedFinalizationId !== value.intendedFinalizationId ||
			conflict.publishedRetentionAnchorWallTimeMs !== conflict.intendedRetentionAnchorWallTimeMs ||
			conflict.intendedRetentionAnchorWallTimeMs !== chain.anchorWallTimeMs ||
			anchor !== Math.max(conflict.publishedRetentionAnchorWallTimeMs, conflict.intendedRetentionAnchorWallTimeMs) ||
			serviceFinalizationPublicationConflictDigest(conflict) !== value.conflictProofSha256
		) {
			return undefined;
		}
		const publicationIntentPath = join(
			path,
			`service-finalization-publication-intent-${conflict.intendedFinalizationId}.json`,
		);
		const publicationIntent = serviceDecisionJson(publicationIntentPath);
		if (
			publicationIntent.state !== "ok" ||
			!publicationIntent.value ||
			!publicationIntent.identity ||
			!exactKeys(publicationIntent.value, ["schemaVersion", "kind", "runId", "finalizationId"]) ||
			publicationIntent.value.schemaVersion !== 1 ||
			publicationIntent.value.kind !== "service_finalization_publication_intent" ||
			publicationIntent.value.runId !== chain.runId ||
			publicationIntent.value.finalizationId !== conflict.intendedFinalizationId
		) {
			return undefined;
		}
		const agentDir = dirname(dirname(dirname(path)));
		const incidentInput = { incidentsDirectory: join(agentDir, "incidents"), incidentId: basename(path) };
		const published = inspectPublishedIncidentFinalization(incidentInput);
		const retentionAuthority = inspectIncidentRetentionAuthority(incidentInput);
		if (
			published.state === "pending" ||
			retentionAuthority.state !== "authorized" ||
			published.runId !== chain.runId ||
			published.manifest.runIdentity.runToken !== chain.runToken ||
			published.finalizationId !== conflict.publishedFinalizationId ||
			published.state !== conflict.publishedState ||
			published.retentionAnchorWallTimeMs !== conflict.publishedRetentionAnchorWallTimeMs ||
			published.serviceTerminalRelayDisposition !== conflict.publishedServiceTerminalRelayDisposition ||
			retentionAuthority.finalizationId !== published.finalizationId ||
			retentionAuthority.runId !== published.runId ||
			retentionAuthority.outcome !== published.state ||
			retentionAuthority.retentionAnchorWallTimeMs !== published.retentionAnchorWallTimeMs ||
			serviceFinalizationSemanticsValid(chain, published.state, published.serviceTerminalRelayDisposition) ||
			!serviceFinalizationSemanticsValid(
				chain,
				conflict.intendedState,
				conflict.intendedServiceTerminalRelayDisposition,
			)
		) {
			return undefined;
		}
		const publishedManifest = publishedManifestControl(published);
		let publishedManifestFingerprint: string;
		try {
			publishedManifestFingerprint = controlFingerprint(published.manifest);
		} catch {
			return undefined;
		}
		if (
			!publishedManifest ||
			![
				...chain.controls,
				{ path: completionPath, identity: completion.identity },
				{ path: conflictPath, identity: conflictRead.identity },
				{ path: publicationIntentPath, identity: publicationIntent.identity },
				publishedManifest,
			].every((control) =>
				sameRetentionFileIdentity(control.identity, retentionFileIdentity(control.path, MAX_METADATA_BYTES)),
			) ||
			!chain.absentControls.every(controlPathMissing)
		) {
			return undefined;
		}
		const finalConflictRead = serviceDecisionJson(conflictPath);
		const finalPublicationIntent = serviceDecisionJson(publicationIntentPath);
		const finalPublished = inspectPublishedIncidentFinalization(incidentInput);
		const finalRetentionAuthority = inspectIncidentRetentionAuthority(incidentInput);
		let finalManifestFingerprint: string | undefined;
		if (finalPublished.state !== "pending")
			try {
				finalManifestFingerprint = controlFingerprint(finalPublished.manifest);
			} catch {}
		if (
			finalConflictRead.state !== "ok" ||
			!finalConflictRead.identity ||
			!sameRetentionFileIdentity(conflictRead.identity, finalConflictRead.identity) ||
			!finalConflictRead.bytes?.equals(conflictRead.bytes ?? Buffer.alloc(0)) ||
			finalPublicationIntent.state !== "ok" ||
			!finalPublicationIntent.identity ||
			!sameRetentionFileIdentity(publicationIntent.identity, finalPublicationIntent.identity) ||
			!finalPublicationIntent.bytes?.equals(publicationIntent.bytes ?? Buffer.alloc(0)) ||
			finalPublished.state === "pending" ||
			finalRetentionAuthority.state !== "authorized" ||
			finalPublished.state !== published.state ||
			finalPublished.finalizationId !== published.finalizationId ||
			finalPublished.runId !== published.runId ||
			finalPublished.manifest.runIdentity.runToken !== published.manifest.runIdentity.runToken ||
			finalPublished.retentionAnchorWallTimeMs !== published.retentionAnchorWallTimeMs ||
			finalPublished.authorityDirectory !== published.authorityDirectory ||
			finalPublished.serviceTerminalRelayDisposition !== published.serviceTerminalRelayDisposition ||
			finalManifestFingerprint !== publishedManifestFingerprint ||
			!sameRetentionFileIdentity(
				publishedManifest.identity,
				retentionFileIdentity(publishedManifest.path, MAX_METADATA_BYTES),
			) ||
			finalRetentionAuthority.finalizationId !== retentionAuthority.finalizationId ||
			finalRetentionAuthority.runId !== retentionAuthority.runId ||
			finalRetentionAuthority.outcome !== retentionAuthority.outcome ||
			finalRetentionAuthority.retentionAnchorWallTimeMs !== retentionAuthority.retentionAnchorWallTimeMs ||
			finalRetentionAuthority.authoritySource !== retentionAuthority.authoritySource ||
			finalRetentionAuthority.retentionClass !== retentionAuthority.retentionClass ||
			![...chain.controls, { path: completionPath, identity: completion.identity }].every((control) =>
				sameRetentionFileIdentity(control.identity, retentionFileIdentity(control.path, MAX_METADATA_BYTES)),
			) ||
			!chain.absentControls.every(controlPathMissing)
		) {
			return undefined;
		}
		return {
			anchorWallTimeMs: anchor,
			retentionMilliseconds: INCIDENT_CORRUPTION_QUARANTINE_MS,
			publicationConflictPublishedFinalizationId: conflict.publishedFinalizationId,
		};
	}
	if (
		anchor !== chain.anchorWallTimeMs ||
		typeof value.finalizationId !== "string" ||
		!FINALIZATION_ID.test(value.finalizationId)
	) {
		return undefined;
	}
	if (value.state === "normal_reclaimable") {
		if (
			!exactKeys(value, [
				"schemaVersion",
				"state",
				"runId",
				"finalizationId",
				"classification",
				"retentionAnchorWallTimeMs",
			]) ||
			value.classification !== "normal" ||
			chain.stoppedDisposition !== "exact_first_observation" ||
			chain.sealTerminalOccurrenceId !== chain.terminalOccurrenceId ||
			chain.terminalBoundByReplay ||
			!chain.lossFree
		)
			return undefined;
		const authorityPath = join(path, `service-finalization-normal-authority-${value.finalizationId}.json`);
		const authority = serviceDecisionJson(authorityPath);
		if (
			authority.state !== "ok" ||
			!authority.value ||
			!authority.identity ||
			!exactKeys(authority.value, [
				"schemaVersion",
				"kind",
				"runId",
				"runToken",
				"finalizationId",
				"classification",
				"analysisState",
				"retentionAnchorWallTimeMs",
				"terminalOccurrenceId",
			]) ||
			authority.value.schemaVersion !== 1 ||
			authority.value.kind !== "service_normal_retention_authority" ||
			authority.value.runId !== chain.runId ||
			authority.value.runToken !== chain.runToken ||
			authority.value.finalizationId !== value.finalizationId ||
			authority.value.classification !== "normal" ||
			authority.value.analysisState !== "complete" ||
			exactWallTime(authority.value.retentionAnchorWallTimeMs) !== anchor ||
			authority.value.terminalOccurrenceId !== chain.terminalOccurrenceId
		)
			return undefined;
		if (
			![
				...chain.controls,
				{ path: completionPath, identity: completion.identity },
				{ path: authorityPath, identity: authority.identity },
			].every((control) =>
				sameRetentionFileIdentity(control.identity, retentionFileIdentity(control.path, MAX_METADATA_BYTES)),
			) ||
			!chain.absentControls.every(controlPathMissing)
		)
			return undefined;
		return { anchorWallTimeMs: anchor, retentionMilliseconds: INCIDENT_DIAGNOSTIC_RETENTION_MS };
	}
	if (
		value.state !== "incident_reclaimable" ||
		!exactKeys(value, [
			"schemaVersion",
			"state",
			"runId",
			"finalizationId",
			"outcome",
			"retentionAnchorWallTimeMs",
		]) ||
		!["complete", "incomplete", "corrupt"].includes(String(value.outcome))
	)
		return undefined;
	const publicationIntentPath = join(path, `service-finalization-publication-intent-${value.finalizationId}.json`);
	const publicationIntent = serviceDecisionJson(publicationIntentPath);
	if (
		publicationIntent.state !== "ok" ||
		!publicationIntent.value ||
		!publicationIntent.identity ||
		!exactKeys(publicationIntent.value, ["schemaVersion", "kind", "runId", "finalizationId"]) ||
		publicationIntent.value.schemaVersion !== 1 ||
		publicationIntent.value.kind !== "service_finalization_publication_intent" ||
		publicationIntent.value.runId !== chain.runId ||
		publicationIntent.value.finalizationId !== value.finalizationId
	)
		return undefined;
	const agentDir = dirname(dirname(dirname(path)));
	const incidentInput = { incidentsDirectory: join(agentDir, "incidents"), incidentId: basename(path) };
	const published = inspectPublishedIncidentFinalization(incidentInput);
	const retentionAuthority = inspectIncidentRetentionAuthority(incidentInput);
	if (
		published.state === "pending" ||
		retentionAuthority.state !== "authorized" ||
		published.runId !== chain.runId ||
		published.manifest.runIdentity.runToken !== chain.runToken ||
		published.finalizationId !== value.finalizationId ||
		published.state !== value.outcome ||
		published.retentionAnchorWallTimeMs !== anchor ||
		retentionAuthority.finalizationId !== published.finalizationId ||
		retentionAuthority.runId !== published.runId ||
		retentionAuthority.outcome !== published.state ||
		retentionAuthority.retentionAnchorWallTimeMs !== anchor
	)
		return undefined;
	const publishedSeal = publishedServiceSealDisposition(published);
	const publishedManifest = publishedManifestControl(published);
	let publishedManifestFingerprint: string;
	try {
		publishedManifestFingerprint = controlFingerprint(published.manifest);
	} catch {
		return undefined;
	}
	if (
		!publishedSeal ||
		!publishedManifest ||
		!serviceFinalizationSemanticsValid(
			chain,
			value.outcome as "complete" | "incomplete" | "corrupt",
			publishedSeal.disposition,
		)
	)
		return undefined;
	if (
		![
			...chain.controls,
			{ path: completionPath, identity: completion.identity },
			{ path: publicationIntentPath, identity: publicationIntent.identity },
			publishedManifest,
		].every((control) =>
			sameRetentionFileIdentity(control.identity, retentionFileIdentity(control.path, MAX_METADATA_BYTES)),
		) ||
		!chain.absentControls.every(controlPathMissing)
	)
		return undefined;
	const finalPublished = inspectPublishedIncidentFinalization(incidentInput);
	const finalRetentionAuthority = inspectIncidentRetentionAuthority(incidentInput);
	let finalManifestFingerprint: string | undefined;
	if (finalPublished.state !== "pending")
		try {
			finalManifestFingerprint = controlFingerprint(finalPublished.manifest);
		} catch {}
	if (
		finalPublished.state === "pending" ||
		finalRetentionAuthority.state !== "authorized" ||
		finalPublished.state !== published.state ||
		finalPublished.finalizationId !== published.finalizationId ||
		finalPublished.runId !== published.runId ||
		finalPublished.manifest.runIdentity.runToken !== published.manifest.runIdentity.runToken ||
		finalPublished.retentionAnchorWallTimeMs !== published.retentionAnchorWallTimeMs ||
		finalPublished.authorityDirectory !== published.authorityDirectory ||
		finalPublished.serviceTerminalRelayDisposition !== publishedSeal.disposition ||
		finalManifestFingerprint !== publishedManifestFingerprint ||
		!sameRetentionFileIdentity(
			publishedManifest.identity,
			retentionFileIdentity(publishedManifest.path, MAX_METADATA_BYTES),
		) ||
		finalRetentionAuthority.finalizationId !== retentionAuthority.finalizationId ||
		finalRetentionAuthority.runId !== retentionAuthority.runId ||
		finalRetentionAuthority.outcome !== retentionAuthority.outcome ||
		finalRetentionAuthority.retentionAnchorWallTimeMs !== retentionAuthority.retentionAnchorWallTimeMs ||
		finalRetentionAuthority.authoritySource !== retentionAuthority.authoritySource ||
		finalRetentionAuthority.retentionClass !== retentionAuthority.retentionClass
	)
		return undefined;
	return {
		anchorWallTimeMs: anchor,
		retentionMilliseconds:
			retentionAuthority.retentionClass === "corrupt" ||
			chain.stoppedDisposition === "recovered_after_invalid_control"
				? INCIDENT_CORRUPTION_QUARANTINE_MS
				: INCIDENT_DIAGNOSTIC_RETENTION_MS,
	};
}

function serviceTerminalAuthority(
	path: string,
):
	| { state: "spawn_failure"; anchorWallTimeMs: number }
	| { state: "stopped_pending" }
	| { state: "missing" | "uncertain" } {
	const terminal = decisionJson(join(path, ".retention-terminal.json"), SERVICE_CONTROL_MAX_BYTES);
	if (terminal.state !== "ok") return { state: terminal.state };
	const value = terminal.value;
	if (!value || !terminal.identity) return { state: "uncertain" };
	const terminalIdentity = terminal.identity;
	const anchorWallTimeMs = exactServiceTimestamp(value.completed);
	if (anchorWallTimeMs === undefined) return { state: "uncertain" };
	const stableReadback = (): boolean => {
		const readback = decisionJson(join(path, ".retention-terminal.json"), SERVICE_CONTROL_MAX_BYTES);
		return Boolean(
			readback.state === "ok" &&
				readback.identity &&
				sameRetentionFileIdentity(terminalIdentity, readback.identity) &&
				readback.bytes?.equals(terminal.bytes ?? Buffer.alloc(0)),
		);
	};
	if (
		exactKeys(value, ["completed", "exitCode", "exitSignal"]) &&
		(value.exitCode === null ||
			(Number.isSafeInteger(value.exitCode) && Number(value.exitCode) >= 0 && Number(value.exitCode) <= 255)) &&
		(value.exitSignal === null || (typeof value.exitSignal === "string" && /^SIG[A-Z0-9]+$/.test(value.exitSignal)))
	) {
		return stableReadback() ? { state: "stopped_pending" } : { state: "uncertain" };
	}
	const hasSpawnError = value.spawnError !== undefined;
	const spawnError = hasSpawnError ? recordValue(value.spawnError) : undefined;
	if (
		!exactKeys(value, [
			"completed",
			"disposition",
			"exitCode",
			"exitSignal",
			...(hasSpawnError ? ["spawnError"] : []),
		]) ||
		value.disposition !== "spawn_failed_before_target_identity" ||
		value.exitCode !== null ||
		value.exitSignal !== null ||
		(hasSpawnError &&
			(!spawnError ||
				!exactKeys(spawnError, [
					"name",
					"message",
					...(spawnError.stack === undefined ? [] : ["stack"]),
					"cause",
					"ownProperties",
				]) ||
				typeof spawnError.name !== "string" ||
				typeof spawnError.message !== "string" ||
				(spawnError.stack !== undefined && typeof spawnError.stack !== "string") ||
				!recordValue(spawnError.ownProperties)))
	) {
		return { state: "uncertain" };
	}
	return stableReadback() ? { state: "spawn_failure", anchorWallTimeMs } : { state: "uncertain" };
}

function runProtection(
	path: string,
	machineId: string,
	bootId: string,
	identity: NonNullable<IncidentRetentionOptions["processIdentity"]>,
): "active" | "pending" | "inactive" | "uncertain" {
	const marker = decisionJson(join(path, ACTIVE_MARKER));
	if (marker.state === "uncertain") return "uncertain";
	if (marker.state === "ok") {
		const value = marker.value ?? {};
		if (
			value.role !== "wrapper-proxy" ||
			typeof value.machineId !== "string" ||
			!value.machineId ||
			typeof value.bootId !== "string" ||
			!value.bootId ||
			!Number.isSafeInteger(value.pid) ||
			Number(value.pid) <= 0 ||
			typeof value.processStartId !== "string" ||
			!value.processStartId
		)
			return "uncertain";
		if (!machineId || !bootId) return "uncertain";
		if (value.machineId !== machineId) return "uncertain";
		if (value.bootId === bootId) {
			const observed = identity(Number(value.pid));
			if (observed.state === "uncertain") return "uncertain";
			if (observed.state === "live" && observed.startId === value.processStartId) return "active";
		}
	}
	const process = decisionJson(join(path, "process.json"));
	if (process.state === "uncertain") return "uncertain";
	if (process.state === "ok") {
		const value = process.value ?? {};
		if (
			typeof value.machineId === "string" &&
			value.machineId &&
			typeof value.bootId === "string" &&
			value.bootId &&
			Number.isSafeInteger(value.pid) &&
			Number(value.pid) > 0 &&
			typeof value.processStartId === "string" &&
			value.processStartId
		) {
			if (!machineId || !bootId) return "uncertain";
			if (value.machineId !== machineId) return "uncertain";
			if (value.bootId === bootId) {
				const observed = identity(Number(value.pid));
				if (observed.state === "uncertain") return "uncertain";
				if (observed.state === "live" && observed.startId === value.processStartId) return "active";
			}
		}
	}
	const finalized = serviceDecisionJson(join(path, ".service-finalization-complete"));
	if (finalized.state === "uncertain") return "uncertain";
	if (finalized.state === "ok") return serviceFinalizationCompletion(path, finalized) ? "inactive" : "uncertain";
	const terminal = serviceTerminalAuthority(path);
	if (terminal.state === "uncertain") return "uncertain";
	if (terminal.state === "spawn_failure") return "inactive";
	return "pending";
}

function runExpired(path: string, nowMs: number): boolean | undefined {
	const finalized = serviceDecisionJson(join(path, ".service-finalization-complete"));
	if (finalized.state === "uncertain") return undefined;
	if (finalized.state === "ok") {
		const completion = serviceFinalizationCompletion(path, finalized);
		return completion === undefined
			? undefined
			: nowMs - completion.anchorWallTimeMs >= completion.retentionMilliseconds;
	}
	const terminal = serviceTerminalAuthority(path);
	if (terminal.state !== "spawn_failure") return undefined;
	return nowMs - terminal.anchorWallTimeMs >= INCIDENT_DIAGNOSTIC_RETENTION_MS;
}

function privateDecisionMetadata(path: string): boolean {
	try {
		const stat = lstatSync(path);
		const expectedUid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
		return (
			stat.isFile() &&
			!stat.isSymbolicLink() &&
			stat.nlink === 1 &&
			stat.uid === expectedUid &&
			(stat.mode & 0o077) === 0
		);
	} catch {
		return false;
	}
}

function decisionJson(
	path: string,
	maximum = MAX_METADATA_BYTES,
	encoding: "compact" | "compact-or-pretty" = "compact-or-pretty",
): { state: SmallRead["state"]; value?: Record<string, unknown>; identity?: RetentionFileIdentity; bytes?: Buffer } {
	let descriptor: number | undefined;
	try {
		const before = lstatSync(path);
		if (!before.isFile() || before.isSymbolicLink()) return { state: "uncertain" };
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const opened = fstatSync(descriptor);
		const expectedUid = typeof process.getuid === "function" ? process.getuid() : opened.uid;
		const sameIdentity = (left: Stats, right: Stats): boolean =>
			left.dev === right.dev &&
			left.ino === right.ino &&
			left.size === right.size &&
			left.mtimeMs === right.mtimeMs &&
			left.ctimeMs === right.ctimeMs &&
			left.mode === right.mode &&
			left.uid === right.uid &&
			left.nlink === right.nlink;
		if (
			!sameIdentity(before, opened) ||
			!opened.isFile() ||
			opened.nlink !== 1 ||
			opened.uid !== expectedUid ||
			(opened.mode & 0o077) !== 0 ||
			!Number.isSafeInteger(opened.size) ||
			opened.size < 0 ||
			opened.size > maximum
		)
			return { state: "uncertain" };
		const bytes = Buffer.alloc(opened.size);
		let offset = 0;
		while (offset < bytes.length) {
			const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
			if (count <= 0) return { state: "uncertain" };
			offset += count;
		}
		const after = fstatSync(descriptor);
		const pathAfter = lstatSync(path);
		if (!sameIdentity(opened, after) || !sameIdentity(opened, pathAfter)) return { state: "uncertain" };
		const parsed = JSON.parse(bytes.toString("utf8")) as unknown;
		if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return { state: "uncertain" };
		const value = parsed as Record<string, unknown>;
		const compact = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
		const pretty = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
		if (!bytes.equals(compact) && (encoding === "compact" || !bytes.equals(pretty))) return { state: "uncertain" };
		return {
			state: "ok",
			value,
			bytes,
			identity: {
				dev: opened.dev,
				ino: opened.ino,
				size: opened.size,
				mtimeMs: opened.mtimeMs,
				ctimeMs: opened.ctimeMs,
				mode: opened.mode,
				uid: opened.uid,
				nlink: opened.nlink,
			},
		};
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "ENOENT" ? { state: "missing" } : { state: "uncertain" };
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

function serviceDecisionJson(
	path: string,
	maximum = SERVICE_CONTROL_MAX_BYTES,
): { state: SmallRead["state"]; value?: Record<string, unknown>; identity?: RetentionFileIdentity; bytes?: Buffer } {
	return decisionJson(path, maximum, "compact");
}

function collectIncidentProtectedRunIds(
	path: string,
	artifactName: string,
	budget: Budget,
	protection: SegmentProtectionAccumulator,
	inspection?: IncidentRecorderPublishedFinalizationInspection,
): Set<string> {
	const observed = new Set<string>();
	const artifactRunId = canonicalRunIdFromArtifactName(artifactName);
	if (artifactRunId) observed.add(artifactRunId);
	// Live artifacts are governed by their descriptor and must not be routed
	// through stopped finalization inspection just to collect run protection.
	if (!isLiveIncidentArtifactName(artifactName)) {
		const finalization =
			inspection ??
			inspectPublishedIncidentFinalization({
				incidentsDirectory: dirname(path),
				incidentId: basename(path),
			});
		if (finalization.state !== "pending") observed.add(finalization.runId);
	}
	for (const name of ["journal-pin-request.json", "sysdig-pin-request.json"] as const) {
		if (deadlineReached(budget)) return observed;
		const record = decisionJson(join(path, name), PIN_REQUEST_MAX_BYTES);
		if (record.state === "uncertain") {
			protection.uncertain = true;
			budget.uncertainties.push(`incident-run-identity:${path}/${name}`);
			continue;
		}
		if (record.state === "missing") continue;
		const value = record.value ?? {};
		if (!("runId" in value)) {
			protection.uncertain = true;
			budget.uncertainties.push(`incident-run-identity:${path}/${name}`);
			continue;
		}
		const runId = canonicalRunId(value.runId);
		if (!runId) {
			protection.uncertain = true;
			budget.uncertainties.push(`incident-run-identity:${path}/${name}`);
			continue;
		}
		observed.add(runId);
	}
	if (observed.size !== 1) {
		protection.uncertain = true;
		budget.uncertainties.push(`incident-run-identity:${path}`);
	}
	for (const runId of observed) protection.protectedRunIds.add(runId);
	return observed;
}

function buildingSegmentProtection(root: string): IncidentRecorderSegmentPruneProtection {
	return {
		state: "building",
		generation: segmentProtectionGenerations.get(root)?.generation ?? 0,
	};
}

function completeSegmentProtection(
	root: string,
	protectedRunIds: ReadonlySet<string>,
): IncidentRecorderSegmentPruneProtection {
	const sortedRunIds = [...protectedRunIds].sort();
	const protectedRunIdsKey = JSON.stringify(sortedRunIds);
	let generation = segmentProtectionGenerations.get(root);
	if (!generation) {
		generation = { generation: 1, protectedRunIdsKey };
		segmentProtectionGenerations.set(root, generation);
	} else if (generation.protectedRunIdsKey !== protectedRunIdsKey) {
		generation.generation += 1;
		generation.protectedRunIdsKey = protectedRunIdsKey;
	}
	return createIncidentRecorderSegmentPruneProtection(generation.generation, sortedRunIds);
}

function retentionIdentityMatches(path: string, value: unknown, directory: boolean): boolean {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const expected = value as Record<string, unknown>;
	try {
		const stat = lstatSync(path);
		if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) return false;
		if (!directory && stat.nlink !== 1) return false;
		return (
			expected.dev === String(stat.dev) &&
			expected.ino === String(stat.ino) &&
			(directory || expected.size === stat.size) &&
			expected.mtimeMs === stat.mtimeMs &&
			expected.ctimeMs === stat.ctimeMs &&
			(directory || expected.nlink === stat.nlink)
		);
	} catch {
		return false;
	}
}

interface RetentionFileIdentity {
	dev: number;
	ino: number;
	size: number;
	mtimeMs: number;
	ctimeMs: number;
	mode: number;
	uid: number;
	nlink: number;
}

interface PinArtifactExpectation {
	path: string;
	bytes: number;
	digest: string;
	sealed: {
		generationId: string;
		dev: string;
		ino: string;
		mtimeMs: number;
		ctimeMs: number;
		mode: number;
		nlink: number;
	};
}

interface PinArtifactPlan {
	generationId: string;
	recordCount: number;
	artifacts: PinArtifactExpectation[];
	captureOutcome?: "complete" | "incomplete";
	capturePhases?: { initial: "complete" | "incomplete"; final: "complete" | "incomplete" };
}

interface ActivePinArtifactHash {
	descriptor: number;
	expectation: PinArtifactExpectation;
	offset: number;
	hash: Hash;
	identity: RetentionFileIdentity;
}

interface PinArtifactValidationState {
	key: string;
	incidentPath: string;
	provider: "journal" | "sysdig";
	manifestPath: string;
	manifestIdentity: RetentionFileIdentity;
	pinDirectoryPath: string;
	pinDirectoryIdentity: RetentionFileIdentity;
	remainingArtifactNames: Set<string>;
	directory?: Dir;
	directoryComplete: boolean;
	artifacts: PinArtifactExpectation[];
	index: number;
	active?: ActivePinArtifactHash;
}

let pinArtifactValidationState: PinArtifactValidationState | undefined;

function privateEnough(stat: Stats): boolean {
	const expectedUid = typeof process.getuid === "function" ? process.getuid() : stat.uid;
	return stat.uid === expectedUid && (stat.mode & 0o077) === 0;
}

function retentionFileIdentity(path: string, maximumBytes: number): RetentionFileIdentity | undefined {
	try {
		const stat = lstatSync(path);
		if (
			!stat.isFile() ||
			stat.isSymbolicLink() ||
			stat.nlink !== 1 ||
			!privateEnough(stat) ||
			!Number.isSafeInteger(stat.size) ||
			stat.size < 0 ||
			stat.size > maximumBytes
		)
			return undefined;
		return {
			dev: stat.dev,
			ino: stat.ino,
			size: stat.size,
			mtimeMs: stat.mtimeMs,
			ctimeMs: stat.ctimeMs,
			mode: stat.mode,
			uid: stat.uid,
			nlink: stat.nlink,
		};
	} catch {
		return undefined;
	}
}

function retentionDirectoryIdentity(path: string): RetentionFileIdentity | undefined {
	try {
		const stat = lstatSync(path);
		if (!stat.isDirectory() || stat.isSymbolicLink() || !privateEnough(stat)) return undefined;
		return {
			dev: stat.dev,
			ino: stat.ino,
			size: stat.size,
			mtimeMs: stat.mtimeMs,
			ctimeMs: stat.ctimeMs,
			mode: stat.mode,
			uid: stat.uid,
			nlink: stat.nlink,
		};
	} catch {
		return undefined;
	}
}

function sameRetentionFileIdentity(left: RetentionFileIdentity, right: RetentionFileIdentity | undefined): boolean {
	return (
		right !== undefined &&
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.size === right.size &&
		left.mtimeMs === right.mtimeMs &&
		left.ctimeMs === right.ctimeMs &&
		left.mode === right.mode &&
		left.uid === right.uid &&
		left.nlink === right.nlink
	);
}

function privatePinDirectory(path: string): boolean {
	try {
		const stat = lstatSync(path);
		return stat.isDirectory() && !stat.isSymbolicLink() && privateEnough(stat);
	} catch {
		return false;
	}
}

function pinArtifactIdentity(expectation: PinArtifactExpectation): RetentionFileIdentity | undefined {
	try {
		const stat = lstatSync(expectation.path);
		if (
			!stat.isFile() ||
			stat.isSymbolicLink() ||
			!privateEnough(stat) ||
			stat.nlink !== 1 ||
			(stat.mode & 0o777) !== 0o400 ||
			stat.size !== expectation.bytes ||
			String(stat.dev) !== expectation.sealed.dev ||
			String(stat.ino) !== expectation.sealed.ino ||
			stat.mtimeMs !== expectation.sealed.mtimeMs ||
			stat.ctimeMs !== expectation.sealed.ctimeMs ||
			(stat.mode & 0o777) !== expectation.sealed.mode ||
			stat.nlink !== expectation.sealed.nlink
		)
			return undefined;
		return {
			dev: stat.dev,
			ino: stat.ino,
			size: stat.size,
			mtimeMs: stat.mtimeMs,
			ctimeMs: stat.ctimeMs,
			mode: stat.mode,
			uid: stat.uid,
			nlink: stat.nlink,
		};
	} catch {
		return undefined;
	}
}

function providerPinArtifactPlan(
	provider: "journal" | "sysdig",
	manifest: Record<string, unknown>,
	incidentPath: string,
	pinDirectoryPath: string,
	runId: unknown,
	anchor: number,
	from: number,
	through: number,
	retainUntil: number,
	expectedGenerationId: string,
	ringBasePath?: string,
): PinArtifactPlan | undefined {
	const artifacts = new Map<string, PinArtifactExpectation>();
	let totalBytes = 0;
	const generationId = manifest.artifactGenerationId;
	if (
		typeof generationId !== "string" ||
		!/^[0-9a-f]{64}$/.test(generationId) ||
		generationId !== expectedGenerationId
	)
		return undefined;
	const addArtifact = (
		pathValue: unknown,
		bytesValue: unknown,
		digestValue: unknown,
		sealedValue: unknown,
		maximumBytes: number,
	): boolean => {
		const sealed = recordValue(sealedValue);
		if (
			!sealed ||
			!exactKeys(sealed, [
				"version",
				"state",
				"generationId",
				"dev",
				"ino",
				"bytes",
				"mtimeMs",
				"ctimeMs",
				"mode",
				"nlink",
				"sha256",
			]) ||
			sealed.version !== 1 ||
			sealed.state !== "sealed_private_copy" ||
			sealed.generationId !== generationId ||
			typeof sealed.dev !== "string" ||
			!/^(?:0|[1-9]\d*)$/.test(sealed.dev) ||
			Buffer.byteLength(sealed.dev, "utf8") > 32 ||
			typeof sealed.ino !== "string" ||
			!/^(?:0|[1-9]\d*)$/.test(sealed.ino) ||
			Buffer.byteLength(sealed.ino, "utf8") > 32 ||
			!Number.isFinite(sealed.mtimeMs) ||
			Number(sealed.mtimeMs) < 0 ||
			!Number.isFinite(sealed.ctimeMs) ||
			Number(sealed.ctimeMs) < 0 ||
			sealed.mode !== 0o400 ||
			sealed.nlink !== 1 ||
			typeof pathValue !== "string" ||
			Buffer.byteLength(pathValue, "utf8") > 4 * 1024 ||
			typeof digestValue !== "string" ||
			!/^[0-9a-f]{64}$/.test(digestValue) ||
			!Number.isSafeInteger(bytesValue) ||
			Number(bytesValue) < 0 ||
			Number(bytesValue) > maximumBytes ||
			sealed.bytes !== bytesValue ||
			sealed.sha256 !== digestValue
		)
			return false;
		const resolvedPath = resolve(pathValue);
		if (pathValue !== resolvedPath || dirname(resolvedPath) !== resolve(pinDirectoryPath)) return false;
		const expectation = {
			path: pathValue,
			bytes: Number(bytesValue),
			digest: digestValue,
			sealed: {
				generationId,
				dev: sealed.dev,
				ino: sealed.ino,
				mtimeMs: Number(sealed.mtimeMs),
				ctimeMs: Number(sealed.ctimeMs),
				mode: Number(sealed.mode),
				nlink: Number(sealed.nlink),
			},
		};
		const previous = artifacts.get(resolvedPath);
		if (previous)
			return (
				previous.bytes === expectation.bytes &&
				previous.digest === expectation.digest &&
				JSON.stringify(previous.sealed) === JSON.stringify(expectation.sealed)
			);
		totalBytes += expectation.bytes;
		if (!Number.isSafeInteger(totalBytes) || totalBytes > PROVIDER_PIN_MAX_TOTAL_BYTES) return false;
		artifacts.set(resolvedPath, expectation);
		return true;
	};
	if (provider === "journal") {
		const occurrences = manifest.occurrences;
		let cursorBytes = 0;
		if (
			!exactKeys(manifest, [
				"version",
				"state",
				"runId",
				"fromWallTimeMs",
				"throughWallTimeMs",
				"artifactGenerationId",
				"occurrences",
			]) ||
			manifest.version !== 2 ||
			manifest.state !== "complete_through_requested_window" ||
			manifest.runId !== runId ||
			exactWallTime(manifest.fromWallTimeMs) !== from ||
			exactWallTime(manifest.throughWallTimeMs) !== through ||
			!Array.isArray(occurrences) ||
			occurrences.length > JOURNAL_PIN_MAX_COUNT
		)
			return undefined;
		for (const occurrence of occurrences) {
			const record = recordValue(occurrence);
			const cas = recordValue(record?.cas);
			const occurrenceReference = recordValue(record?.occurrenceReference);
			const locator = recordValue(occurrenceReference?.locator);
			if (
				!record ||
				!cas ||
				!occurrenceReference ||
				!locator ||
				!exactKeys(record, [
					"occurrenceReference",
					"semanticFingerprint",
					"cursors",
					"cas",
					"eventWallTimeMs",
					"pinnedCasPath",
					"sealedArtifact",
				]) ||
				!exactKeys(cas, ["digest", "bytes", "path"]) ||
				!exactKeys(occurrenceReference, ["kind", "locator"]) ||
				occurrenceReference.kind !== "segment" ||
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
				!["segmentSequence", "ordinal", "offset", "frameBytes", "payloadBytes"].every(
					(key) => Number.isSafeInteger(locator[key]) && Number(locator[key]) >= 0,
				) ||
				typeof locator.payloadSha256 !== "string" ||
				!/^[0-9a-f]{64}$/.test(locator.payloadSha256) ||
				typeof record.semanticFingerprint !== "string" ||
				!/^[0-9a-f]{64}$/.test(record.semanticFingerprint) ||
				!Array.isArray(record.cursors) ||
				record.cursors.length > JOURNAL_PIN_CURSOR_MAX_COUNT ||
				record.cursors.some((cursor) => typeof cursor !== "string") ||
				typeof record.eventWallTimeMs !== "string" ||
				Buffer.byteLength(record.eventWallTimeMs, "utf8") > 128 ||
				typeof cas.path !== "string" ||
				Buffer.byteLength(cas.path, "utf8") > 4 * 1024 ||
				cas.path !==
					join(
						dirname(dirname(incidentPath)),
						"incident-recorder",
						"cas",
						"sha256",
						String(cas.digest).slice(0, 2),
						`${String(cas.digest)}.blob`,
					) ||
				record.pinnedCasPath !== join(pinDirectoryPath, `${String(cas.digest)}.blob`) ||
				!addArtifact(
					record.pinnedCasPath,
					cas.bytes,
					cas.digest,
					record.sealedArtifact,
					JOURNAL_PIN_MAX_ARTIFACT_BYTES,
				)
			)
				return undefined;
			for (const cursor of record.cursors as string[]) {
				cursorBytes += Buffer.byteLength(cursor, "utf8");
				if (!Number.isSafeInteger(cursorBytes) || cursorBytes > JOURNAL_PIN_CURSOR_MAX_BYTES) return undefined;
			}
		}
		return { generationId, recordCount: occurrences.length, artifacts: [...artifacts.values()] };
	}
	const requestedWindow = recordValue(manifest.requestedWindow);
	const retention = recordValue(manifest.retention);
	const capturePhases = recordValue(manifest.capturePhases);
	const sourceRing = recordValue(manifest.sourceRing);
	const coverage = recordValue(manifest.coverage);
	const segments = manifest.segments;
	if (
		!exactKeys(manifest, [
			"version",
			"state",
			"diagnosticOnly",
			"captureOutcome",
			"capturePhases",
			"runId",
			"requestedWindow",
			"captureFinalizedAtWallTimeMs",
			"retention",
			"sourceRing",
			"coverage",
			"artifactGenerationId",
			"segments",
		]) ||
		manifest.version !== 1 ||
		manifest.state !== "finalized_with_observed_coverage" ||
		manifest.diagnosticOnly !== true ||
		(manifest.captureOutcome !== "complete" && manifest.captureOutcome !== "incomplete") ||
		!capturePhases ||
		!exactKeys(capturePhases, ["initial", "final"]) ||
		!(["complete", "incomplete"] as const).includes(capturePhases.initial as "complete" | "incomplete") ||
		!(["complete", "incomplete"] as const).includes(capturePhases.final as "complete" | "incomplete") ||
		(manifest.captureOutcome === "complete") !==
			(capturePhases.initial === "complete" && capturePhases.final === "complete") ||
		manifest.runId !== runId ||
		!requestedWindow ||
		!exactKeys(requestedWindow, ["fromWallTimeMs", "anchorWallTimeMs", "throughWallTimeMs"]) ||
		exactWallTime(requestedWindow.anchorWallTimeMs) !== anchor ||
		exactWallTime(requestedWindow.fromWallTimeMs) !== from ||
		exactWallTime(requestedWindow.throughWallTimeMs) !== through ||
		exactWallTime(manifest.captureFinalizedAtWallTimeMs) !== through ||
		!retention ||
		!exactKeys(retention, ["milliseconds", "retainUntilWallTimeMs"]) ||
		!Number.isSafeInteger(retention.milliseconds) ||
		retention.milliseconds !== INCIDENT_DIAGNOSTIC_RETENTION_MS ||
		exactWallTime(retention.retainUntilWallTimeMs) !== retainUntil ||
		!sourceRing ||
		!exactKeys(sourceRing, ["basePath", "configuredSegments", "rotationBytes", "compression"]) ||
		typeof ringBasePath !== "string" ||
		sourceRing.basePath !== ringBasePath ||
		sourceRing.configuredSegments !== 12 ||
		sourceRing.rotationBytes !== 320 * 1024 * 1024 ||
		sourceRing.compression !== true ||
		!coverage ||
		!exactKeys(coverage, ["method", "historicalAvailability", "eventTimeBounds", "gaps"]) ||
		coverage.method !==
			"all_observed_ring_segments_at_incident_finalization_plus_rotated_segments_observed_through_requested_end" ||
		coverage.historicalAvailability !== "bounded_by_bytes_present_in_the_stock_ring_at_finalization" ||
		coverage.eventTimeBounds !== "unknown_without_offline_scap_event_parsing" ||
		!Array.isArray(coverage.gaps) ||
		coverage.gaps.length > 1_024 ||
		coverage.gaps.some((gap) => typeof gap !== "string" || Buffer.byteLength(gap, "utf8") > 4 * 1024) ||
		!Array.isArray(segments) ||
		segments.length > SYSDIG_PIN_MAX_COUNT
	)
		return undefined;
	for (const segment of segments) {
		const record = recordValue(segment);
		const exactBytes = recordValue(record?.exactBytes);
		const source = recordValue(record?.source);
		const artifactAtCapture = recordValue(record?.artifactAtCapture);
		const sealedArtifact = recordValue(record?.sealedArtifact);
		const segmentKeys = [
			"version",
			"id",
			"sourcePath",
			"sourceName",
			"observedAtWallTimeMs",
			"phase",
			"source",
			"pinnedPath",
			"captureMethod",
			"captureReason",
			"bytesAtCapture",
			"artifactAtCapture",
			"exactBytes",
			"changedAfterCapture",
			"sealedArtifact",
		];
		if (
			!record ||
			!exactBytes ||
			!source ||
			!artifactAtCapture ||
			!sealedArtifact ||
			!exactKeys(record, segmentKeys) ||
			!exactKeys(exactBytes, ["bytes", "sha256"]) ||
			!exactKeys(source, ["dev", "ino", "bytes", "mtimeMs", "ctimeMs"]) ||
			!exactKeys(artifactAtCapture, ["dev", "ino", "bytes", "mtimeMs", "ctimeMs", "mode", "nlink"]) ||
			record.version !== 1 ||
			typeof record.id !== "string" ||
			!/^[0-9a-f]{64}$/.test(record.id) ||
			typeof record.sourcePath !== "string" ||
			Buffer.byteLength(record.sourcePath, "utf8") > 4 * 1024 ||
			typeof record.sourceName !== "string" ||
			record.sourceName.length === 0 ||
			Buffer.byteLength(record.sourceName, "utf8") > 255 ||
			basename(record.sourceName) !== record.sourceName ||
			!record.sourceName.startsWith(basename(ringBasePath)) ||
			record.sourcePath !== join(dirname(ringBasePath), record.sourceName) ||
			!Number.isSafeInteger(record.observedAtWallTimeMs) ||
			Number(record.observedAtWallTimeMs) < 0 ||
			!(["initial", "rotated", "final"] as const).includes(record.phase as "initial" | "rotated" | "final") ||
			typeof source.dev !== "string" ||
			Buffer.byteLength(source.dev, "utf8") > 32 ||
			!/^(?:0|[1-9]\d*)$/.test(source.dev) ||
			typeof source.ino !== "string" ||
			Buffer.byteLength(source.ino, "utf8") > 32 ||
			!/^(?:0|[1-9]\d*)$/.test(source.ino) ||
			!Number.isSafeInteger(source.bytes) ||
			Number(source.bytes) < 0 ||
			Number(source.bytes) > SYSDIG_PIN_MAX_ARTIFACT_BYTES ||
			!Number.isFinite(source.mtimeMs) ||
			Number(source.mtimeMs) < 0 ||
			!Number.isFinite(source.ctimeMs) ||
			Number(source.ctimeMs) < 0 ||
			record.captureMethod !== "bounded_copy" ||
			!(
				record.captureReason === "closed_segment_private_snapshot" ||
				record.captureReason === "active_segment_snapshot"
			) ||
			!Number.isSafeInteger(record.bytesAtCapture) ||
			Number(record.bytesAtCapture) < 0 ||
			Number(record.bytesAtCapture) > SYSDIG_PIN_MAX_ARTIFACT_BYTES ||
			Number(record.bytesAtCapture) !== Number(source.bytes) ||
			Number(exactBytes.bytes) !== Number(record.bytesAtCapture) ||
			typeof artifactAtCapture.dev !== "string" ||
			Buffer.byteLength(artifactAtCapture.dev, "utf8") > 32 ||
			!/^(?:0|[1-9]\d*)$/.test(artifactAtCapture.dev) ||
			typeof artifactAtCapture.ino !== "string" ||
			Buffer.byteLength(artifactAtCapture.ino, "utf8") > 32 ||
			!/^(?:0|[1-9]\d*)$/.test(artifactAtCapture.ino) ||
			!Number.isSafeInteger(artifactAtCapture.bytes) ||
			Number(artifactAtCapture.bytes) !== Number(record.bytesAtCapture) ||
			!Number.isFinite(artifactAtCapture.mtimeMs) ||
			Number(artifactAtCapture.mtimeMs) < 0 ||
			!Number.isFinite(artifactAtCapture.ctimeMs) ||
			Number(artifactAtCapture.ctimeMs) < 0 ||
			artifactAtCapture.mode !== 0o600 ||
			artifactAtCapture.nlink !== 1 ||
			artifactAtCapture.dev !== sealedArtifact.dev ||
			artifactAtCapture.ino !== sealedArtifact.ino ||
			artifactAtCapture.bytes !== sealedArtifact.bytes ||
			artifactAtCapture.mtimeMs !== sealedArtifact.mtimeMs ||
			Number(artifactAtCapture.ctimeMs) > Number(sealedArtifact.ctimeMs) ||
			record.changedAfterCapture !== false ||
			record.id !==
				createHash("sha256")
					.update(
						`${source.dev}\0${source.ino}\0${String(source.bytes)}\0${String(source.mtimeMs)}\0${String(source.ctimeMs)}`,
					)
					.digest("hex") ||
			record.pinnedPath !== join(pinDirectoryPath, `${record.id}.scap`) ||
			!addArtifact(
				record.pinnedPath,
				exactBytes.bytes,
				exactBytes.sha256,
				record.sealedArtifact,
				SYSDIG_PIN_MAX_ARTIFACT_BYTES,
			)
		)
			return undefined;
	}
	return {
		generationId,
		recordCount: segments.length,
		artifacts: [...artifacts.values()],
		captureOutcome: manifest.captureOutcome as "complete" | "incomplete",
		capturePhases: {
			initial: capturePhases.initial as "complete" | "incomplete",
			final: capturePhases.final as "complete" | "incomplete",
		},
	};
}

function discardPinArtifactValidation(): void {
	const state = pinArtifactValidationState;
	if (!state) return;
	if (state.active)
		try {
			closeSync(state.active.descriptor);
		} catch {}
	if (state.directory)
		try {
			state.directory.closeSync();
		} catch {}
	pinArtifactValidationState = undefined;
}

function discardPinArtifactValidationForIncident(path: string): void {
	if (pinArtifactValidationState?.incidentPath === path) discardPinArtifactValidation();
}

function discardPinArtifactValidationForProvider(path: string, provider: "journal" | "sysdig"): void {
	if (pinArtifactValidationState?.incidentPath === path && pinArtifactValidationState.provider === provider)
		discardPinArtifactValidation();
}

function pinArtifactValidationCurrent(state: PinArtifactValidationState): boolean {
	return (
		sameRetentionFileIdentity(
			state.manifestIdentity,
			retentionFileIdentity(state.manifestPath, PIN_MANIFEST_MAX_BYTES),
		) && sameRetentionFileIdentity(state.pinDirectoryIdentity, retentionDirectoryIdentity(state.pinDirectoryPath))
	);
}

function advancePinDirectoryValidation(
	state: PinArtifactValidationState,
	budget: Budget,
): "complete" | "pending" | "invalid" {
	if (state.directoryComplete) return "complete";
	try {
		if (!state.directory) {
			if (!sameRetentionFileIdentity(state.pinDirectoryIdentity, retentionDirectoryIdentity(state.pinDirectoryPath)))
				return "invalid";
			state.directory = opendirSync(state.pinDirectoryPath);
			if (!sameRetentionFileIdentity(state.pinDirectoryIdentity, retentionDirectoryIdentity(state.pinDirectoryPath)))
				return "invalid";
		}
		for (;;) {
			if (budget.scanned >= budget.maxEntries || deadlineReached(budget)) {
				budget.moreWork = true;
				return "pending";
			}
			const entry = state.directory.readSync();
			if (!entry) {
				state.directory.closeSync();
				state.directory = undefined;
				state.directoryComplete = true;
				return state.remainingArtifactNames.size === 0 && pinArtifactValidationCurrent(state)
					? "complete"
					: "invalid";
			}
			budget.scanned += 1;
			if (!entry.isFile() || !state.remainingArtifactNames.delete(entry.name)) return "invalid";
		}
	} catch {
		return "invalid";
	}
}

function openPinArtifactHash(expectation: PinArtifactExpectation): ActivePinArtifactHash | undefined {
	let descriptor: number | undefined;
	try {
		const before = pinArtifactIdentity(expectation);
		if (!before) return undefined;
		descriptor = openSync(expectation.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const opened = fstatSync(descriptor);
		if (
			!opened.isFile() ||
			opened.dev !== before.dev ||
			opened.ino !== before.ino ||
			opened.size !== before.size ||
			opened.mtimeMs !== before.mtimeMs ||
			opened.ctimeMs !== before.ctimeMs ||
			opened.mode !== before.mode ||
			opened.uid !== before.uid ||
			opened.nlink !== before.nlink
		)
			return undefined;
		const active = {
			descriptor,
			expectation,
			offset: 0,
			hash: createHash("sha256"),
			identity: {
				dev: opened.dev,
				ino: opened.ino,
				size: opened.size,
				mtimeMs: opened.mtimeMs,
				ctimeMs: opened.ctimeMs,
				mode: opened.mode,
				uid: opened.uid,
				nlink: opened.nlink,
			},
		};
		descriptor = undefined;
		return active;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

function advancePinArtifactValidation(
	state: PinArtifactValidationState,
	budget: Budget,
): "complete" | "pending" | "invalid" {
	try {
		const directory = advancePinDirectoryValidation(state, budget);
		if (directory !== "complete") return directory;
		while (state.index < state.artifacts.length) {
			if (deadlineReached(budget) || budget.pinArtifactsRemaining <= 0) return "pending";
			state.active ??= openPinArtifactHash(state.artifacts[state.index]);
			if (!state.active) return "invalid";
			const active = state.active;
			if (active.offset < active.expectation.bytes) {
				if (budget.pinArtifactHashBytesRemaining <= 0) {
					budget.moreWork = true;
					return "pending";
				}
				const maximum = Math.min(
					PIN_HASH_BUFFER_BYTES,
					active.expectation.bytes - active.offset,
					budget.pinArtifactHashBytesRemaining,
				);
				const buffer = Buffer.allocUnsafe(maximum);
				const count = readSync(active.descriptor, buffer, 0, buffer.length, active.offset);
				if (count <= 0) return "invalid";
				active.hash.update(buffer.subarray(0, count));
				active.offset += count;
				budget.pinArtifactHashBytesRemaining -= count;
				continue;
			}
			const after = fstatSync(active.descriptor);
			closeSync(active.descriptor);
			state.active = undefined;
			if (
				!after.isFile() ||
				after.dev !== active.identity.dev ||
				after.ino !== active.identity.ino ||
				after.size !== active.identity.size ||
				after.mtimeMs !== active.identity.mtimeMs ||
				after.ctimeMs !== active.identity.ctimeMs ||
				after.mode !== active.identity.mode ||
				after.uid !== active.identity.uid ||
				after.nlink !== active.identity.nlink ||
				active.hash.digest("hex") !== active.expectation.digest
			)
				return "invalid";
			state.index += 1;
			budget.pinArtifactsRemaining -= 1;
		}
		return "complete";
	} catch {
		return "invalid";
	}
}

function validateProviderPinManifest(
	provider: "journal" | "sysdig",
	incidentPath: string,
	manifestPath: string,
	pinDirectoryPath: string,
	runId: unknown,
	anchor: number,
	from: number,
	through: number,
	retainUntil: number,
	budget: Budget,
	expectedGenerationId: string,
	ringBasePath?: string,
	proof?: {
		generationId: string;
		recordCount: number;
		manifestIdentity: unknown;
		pinDirectoryIdentity: unknown;
		captureOutcome?: "complete" | "incomplete";
		capturePhases?: { initial: "complete" | "incomplete"; final: "complete" | "incomplete" };
	},
): "complete" | "pending" | "invalid" {
	const manifestIdentity = retentionFileIdentity(manifestPath, PIN_MANIFEST_MAX_BYTES);
	if (!manifestIdentity) {
		discardPinArtifactValidationForIncident(incidentPath);
		return "invalid";
	}
	if (
		proof &&
		(!retentionIdentityMatches(manifestPath, proof.manifestIdentity, false) ||
			!retentionIdentityMatches(pinDirectoryPath, proof.pinDirectoryIdentity, true) ||
			!privatePinDirectory(pinDirectoryPath))
	) {
		discardPinArtifactValidationForIncident(incidentPath);
		return "invalid";
	}
	const key = createHash("sha256")
		.update(
			JSON.stringify({
				provider,
				incidentPath: resolve(incidentPath),
				runId,
				anchor,
				from,
				through,
				retainUntil,
				expectedGenerationId,
				ringBasePath,
				manifestIdentity,
				proof,
			}),
		)
		.digest("hex");
	let state = pinArtifactValidationState;
	if (state && state.key !== key) {
		if (state.incidentPath === incidentPath || !pinArtifactValidationCurrent(state)) discardPinArtifactValidation();
		else {
			budget.moreWork = true;
			return "pending";
		}
		state = pinArtifactValidationState;
	}
	if (!state) {
		const manifest = decisionJson(manifestPath, PIN_MANIFEST_MAX_BYTES);
		if (manifest.state !== "ok" || !manifest.value) return "invalid";
		const pinDirectoryIdentity = retentionDirectoryIdentity(pinDirectoryPath);
		const plan = providerPinArtifactPlan(
			provider,
			manifest.value,
			incidentPath,
			pinDirectoryPath,
			runId,
			anchor,
			from,
			through,
			retainUntil,
			expectedGenerationId,
			ringBasePath,
		);
		if (
			!plan ||
			!pinDirectoryIdentity ||
			(proof !== undefined && proof.generationId !== plan.generationId) ||
			(proof !== undefined && proof.recordCount !== plan.recordCount) ||
			(proof !== undefined &&
				provider === "sysdig" &&
				(proof.captureOutcome !== plan.captureOutcome ||
					JSON.stringify(proof.capturePhases) !== JSON.stringify(plan.capturePhases))) ||
			!sameRetentionFileIdentity(manifestIdentity, retentionFileIdentity(manifestPath, PIN_MANIFEST_MAX_BYTES))
		)
			return "invalid";
		state = {
			key,
			incidentPath,
			provider,
			manifestPath,
			manifestIdentity,
			pinDirectoryPath,
			pinDirectoryIdentity,
			remainingArtifactNames: new Set(plan.artifacts.map((artifact) => basename(artifact.path))),
			directoryComplete: false,
			artifacts: plan.artifacts,
			index: 0,
		};
		pinArtifactValidationState = state;
	}
	const result = advancePinArtifactValidation(state, budget);
	if (result === "pending") {
		budget.moreWork = true;
		return result;
	}
	const complete =
		result === "complete" &&
		pinArtifactValidationCurrent(state) &&
		privatePinDirectory(pinDirectoryPath) &&
		(!proof ||
			(retentionIdentityMatches(manifestPath, proof.manifestIdentity, false) &&
				retentionIdentityMatches(pinDirectoryPath, proof.pinDirectoryIdentity, true) &&
				privatePinDirectory(pinDirectoryPath)));
	discardPinArtifactValidation();
	return complete ? "complete" : "invalid";
}

function canonicalProofFileIdentity(value: unknown): value is Record<string, unknown> {
	const identity = recordValue(value);
	return Boolean(
		identity &&
			exactKeys(identity, ["dev", "ino", "size", "mtimeMs", "ctimeMs", "nlink"]) &&
			typeof identity.dev === "string" &&
			/^(?:0|[1-9]\d*)$/.test(identity.dev) &&
			Buffer.byteLength(identity.dev, "utf8") <= 32 &&
			typeof identity.ino === "string" &&
			/^(?:0|[1-9]\d*)$/.test(identity.ino) &&
			Buffer.byteLength(identity.ino, "utf8") <= 32 &&
			Number.isSafeInteger(identity.size) &&
			Number(identity.size) >= 0 &&
			Number(identity.size) <= PIN_MANIFEST_MAX_BYTES &&
			Number.isFinite(identity.mtimeMs) &&
			Number(identity.mtimeMs) >= 0 &&
			Number.isFinite(identity.ctimeMs) &&
			Number(identity.ctimeMs) >= 0 &&
			Number.isSafeInteger(identity.nlink) &&
			Number(identity.nlink) === 1,
	);
}

function canonicalProofDirectoryIdentity(
	value: unknown,
	expectedPath: "journal-pins/cas" | "sysdig-pins/segments",
): value is Record<string, unknown> {
	const identity = recordValue(value);
	return Boolean(
		identity &&
			exactKeys(identity, ["path", "dev", "ino", "mtimeMs", "ctimeMs"]) &&
			identity.path === expectedPath &&
			typeof identity.dev === "string" &&
			/^(?:0|[1-9]\d*)$/.test(identity.dev) &&
			Buffer.byteLength(identity.dev, "utf8") <= 32 &&
			typeof identity.ino === "string" &&
			/^(?:0|[1-9]\d*)$/.test(identity.ino) &&
			Buffer.byteLength(identity.ino, "utf8") <= 32 &&
			Number.isFinite(identity.mtimeMs) &&
			Number(identity.mtimeMs) >= 0 &&
			Number.isFinite(identity.ctimeMs) &&
			Number(identity.ctimeMs) >= 0,
	);
}

function canonicalProviderPinProof(
	value: Record<string, unknown>,
	provider: "journal" | "sysdig",
	runId: unknown,
	from: number,
	through: number,
	retainUntil: number,
):
	| {
			generationId: string;
			recordCount: number;
			manifestIdentity: Record<string, unknown>;
			pinDirectoryIdentity: Record<string, unknown>;
			captureOutcome?: "complete" | "incomplete";
			capturePhases?: { initial: "complete" | "incomplete"; final: "complete" | "incomplete" };
	  }
	| undefined {
	const manifestIdentity = value.manifestIdentity;
	const pinDirectoryIdentity = value.pinDirectoryIdentity;
	const baseKeys = [
		"version",
		"state",
		"provider",
		"artifactGenerationId",
		"manifestValidated",
		"runId",
		"fromWallTimeMs",
		"throughWallTimeMs",
		"retainUntilWallTimeMs",
		"retentionMilliseconds",
		"manifestIdentity",
		"pinDirectoryIdentity",
	];
	const providerKeys =
		provider === "journal"
			? ["occurrenceReferencesResolved", "occurrenceCount"]
			: ["captureOutcome", "capturePhases", "segmentCount"];
	const expectedPinPath = provider === "journal" ? "journal-pins/cas" : "sysdig-pins/segments";
	if (
		!exactKeys(value, [...baseKeys, ...providerKeys]) ||
		value.version !== 1 ||
		value.state !== "producer_verified_complete" ||
		value.provider !== provider ||
		typeof value.artifactGenerationId !== "string" ||
		!/^[0-9a-f]{64}$/.test(value.artifactGenerationId) ||
		value.manifestValidated !== true ||
		value.runId !== runId ||
		exactWallTime(value.fromWallTimeMs) !== from ||
		exactWallTime(value.throughWallTimeMs) !== through ||
		exactWallTime(value.retainUntilWallTimeMs) !== retainUntil ||
		value.retentionMilliseconds !== INCIDENT_DIAGNOSTIC_RETENTION_MS ||
		!canonicalProofFileIdentity(manifestIdentity) ||
		!canonicalProofDirectoryIdentity(pinDirectoryIdentity, expectedPinPath)
	)
		return undefined;
	if (provider === "journal") {
		if (
			value.occurrenceReferencesResolved !== true ||
			!Number.isSafeInteger(value.occurrenceCount) ||
			Number(value.occurrenceCount) < 0 ||
			Number(value.occurrenceCount) > JOURNAL_PIN_MAX_COUNT
		)
			return undefined;
		return {
			generationId: value.artifactGenerationId,
			recordCount: Number(value.occurrenceCount),
			manifestIdentity,
			pinDirectoryIdentity,
		};
	}
	const capturePhases = recordValue(value.capturePhases);
	if (
		(value.captureOutcome !== "complete" && value.captureOutcome !== "incomplete") ||
		!capturePhases ||
		!exactKeys(capturePhases, ["initial", "final"]) ||
		!(["complete", "incomplete"] as const).includes(capturePhases.initial as "complete" | "incomplete") ||
		!(["complete", "incomplete"] as const).includes(capturePhases.final as "complete" | "incomplete") ||
		(value.captureOutcome === "complete") !==
			(capturePhases.initial === "complete" && capturePhases.final === "complete") ||
		!Number.isSafeInteger(value.segmentCount) ||
		Number(value.segmentCount) < 0 ||
		Number(value.segmentCount) > SYSDIG_PIN_MAX_COUNT
	)
		return undefined;
	return {
		generationId: value.artifactGenerationId as string,
		recordCount: Number(value.segmentCount),
		manifestIdentity,
		pinDirectoryIdentity,
		captureOutcome: value.captureOutcome as "complete" | "incomplete",
		capturePhases: {
			initial: capturePhases.initial as "complete" | "incomplete",
			final: capturePhases.final as "complete" | "incomplete",
		},
	};
}

function canonicalProviderPinIncomplete(
	value: Record<string, unknown>,
	provider: "journal" | "sysdig",
	runId: unknown,
	anchor: number,
	from: number,
	through: number,
): boolean {
	return (
		exactKeys(value, [
			"version",
			"state",
			"provider",
			"reason",
			"runId",
			"anchorWallTimeMs",
			"fromWallTimeMs",
			"throughWallTimeMs",
		]) &&
		value.version === 1 &&
		value.state === "pending_or_incomplete" &&
		value.provider === provider &&
		typeof value.reason === "string" &&
		value.reason.length > 0 &&
		Buffer.byteLength(value.reason, "utf8") <= 4 * 1024 &&
		value.runId === runId &&
		exactWallTime(value.anchorWallTimeMs) === anchor &&
		exactWallTime(value.fromWallTimeMs) === from &&
		exactWallTime(value.throughWallTimeMs) === through
	);
}

interface LiveProviderRetentionRequest {
	provider: "journal" | "sysdig";
	runId: string;
	from: number;
	through: number;
	resolveAfter: number;
	retainUntil: number;
	generationId: string;
	ringBasePath?: string;
}

interface LiveProviderRetentionRequests {
	authority: Record<string, unknown>;
	sysdig: Record<string, unknown>;
	journal: Record<string, unknown>;
	providers: LiveProviderRetentionRequest[];
}

type LiveProviderRetentionRequestsRead =
	| { state: "missing" }
	| { state: "invalid" }
	| ({ state: "valid" } & LiveProviderRetentionRequests);

function readLiveProviderRetentionRequests(
	path: string,
	runId: string,
	anchor: number,
): LiveProviderRetentionRequestsRead {
	const authorityPath = join(path, "incident-pin-authority.json");
	const sysdigPath = join(path, "sysdig-pin-request.json");
	const journalPath = join(path, "journal-pin-request.json");
	const authority = decisionJson(authorityPath, PIN_REQUEST_MAX_BYTES);
	const sysdig = decisionJson(sysdigPath, PIN_REQUEST_MAX_BYTES);
	const journal = decisionJson(journalPath, PIN_REQUEST_MAX_BYTES);
	if (authority.state === "missing" && sysdig.state === "missing" && journal.state === "missing")
		return { state: "missing" };
	if (
		authority.state !== "ok" ||
		sysdig.state !== "ok" ||
		journal.state !== "ok" ||
		!authority.value ||
		!sysdig.value ||
		!journal.value ||
		!privateDecisionMetadata(authorityPath) ||
		!privateDecisionMetadata(sysdigPath) ||
		!privateDecisionMetadata(journalPath)
	)
		return { state: "invalid" };
	const authorityValue = authority.value;
	const sysdigValue = sysdig.value;
	const journalValue = journal.value;
	const sysdigKeys = [
		"version",
		"runId",
		"anchorWallTimeMs",
		"fromWallTimeMs",
		"throughWallTimeMs",
		"resolveAfterWallTimeMs",
		"requestedAtWallTimeMs",
		"retainUntilWallTimeMs",
		"ringBasePath",
		"initialRingSnapshot",
	];
	const journalKeys = [
		"version",
		"state",
		"runId",
		"anchorWallTimeMs",
		"fromWallTimeMs",
		"throughWallTimeMs",
		"resolveAfterWallTimeMs",
		"retainUntilWallTimeMs",
	];
	const from = anchor - INCIDENT_PIN_BEFORE_MS;
	const through = anchor + INCIDENT_PIN_AFTER_MS;
	const retainUntil = anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS;
	const requestAnchor = exactWallTime(sysdigValue.anchorWallTimeMs);
	const requestFrom = exactWallTime(sysdigValue.fromWallTimeMs);
	const requestThrough = exactWallTime(sysdigValue.throughWallTimeMs);
	const resolveAfter = exactWallTime(sysdigValue.resolveAfterWallTimeMs);
	const explicitRetainUntil = exactWallTime(sysdigValue.retainUntilWallTimeMs);
	if (
		!exactKeys(authorityValue, sysdigKeys) ||
		!exactKeys(sysdigValue, sysdigKeys) ||
		!exactKeys(journalValue, journalKeys) ||
		canonicalControlJson(authorityValue) !== canonicalControlJson(sysdigValue) ||
		sysdigValue.version !== 1 ||
		typeof sysdigValue.runId !== "string" ||
		sysdigValue.runId !== runId ||
		canonicalRunId(sysdigValue.runId) !== sysdigValue.runId ||
		requestAnchor !== anchor ||
		requestFrom !== from ||
		requestThrough !== through ||
		resolveAfter !== through ||
		explicitRetainUntil !== retainUntil ||
		typeof sysdigValue.requestedAtWallTimeMs !== "number" ||
		exactWallTime(sysdigValue.requestedAtWallTimeMs) !== anchor ||
		typeof sysdigValue.ringBasePath !== "string" ||
		sysdigValue.ringBasePath.length === 0 ||
		Buffer.byteLength(sysdigValue.ringBasePath, "utf8") > 4 * 1024 ||
		!validSysdigInitialRingSnapshot(sysdigValue.initialRingSnapshot, sysdigValue.ringBasePath) ||
		journalValue.version !== 1 ||
		journalValue.state !== "pending" ||
		journalValue.runId !== runId ||
		canonicalRunId(journalValue.runId) !== journalValue.runId ||
		exactWallTime(journalValue.anchorWallTimeMs) !== anchor ||
		exactWallTime(journalValue.fromWallTimeMs) !== from ||
		exactWallTime(journalValue.throughWallTimeMs) !== through ||
		exactWallTime(journalValue.resolveAfterWallTimeMs) !== through ||
		exactWallTime(journalValue.retainUntilWallTimeMs) !== retainUntil
	)
		return { state: "invalid" };
	const journalGenerationId = controlFingerprint({
		provider: "journal",
		runId,
		anchorWallTimeMs: anchor,
		fromWallTimeMs: from,
		throughWallTimeMs: through,
	});
	const sysdigGenerationId = controlFingerprint({
		provider: "sysdig",
		requestFingerprint: controlFingerprint({
			version: sysdigValue.version,
			runId,
			anchorWallTimeMs: requestAnchor,
			fromWallTimeMs: requestFrom,
			throughWallTimeMs: requestThrough,
			resolveAfterWallTimeMs: resolveAfter,
			retainUntilWallTimeMs: explicitRetainUntil,
			ringBasePath: sysdigValue.ringBasePath,
			requestedAtWallTimeMs: sysdigValue.requestedAtWallTimeMs,
			initialRingSnapshot: sysdigValue.initialRingSnapshot,
		}),
	});
	return {
		state: "valid",
		authority: authorityValue,
		sysdig: sysdigValue,
		journal: journalValue,
		providers: [
			{
				provider: "journal",
				runId,
				from,
				through,
				resolveAfter: through,
				retainUntil,
				generationId: journalGenerationId,
			},
			{
				provider: "sysdig",
				runId,
				from,
				through,
				resolveAfter: through,
				retainUntil,
				generationId: sysdigGenerationId,
				ringBasePath: sysdigValue.ringBasePath,
			},
		],
	};
}

function incidentDisposition(
	path: string,
	nowMs: number,
	budget: Budget,
): "retain" | "delete" | "pending" | "uncertain" {
	const liveCheckpointKey = resolve(path);
	const liveCheckpoints = budget.liveObservationValidationCheckpoints;
	const failClosed = (): "uncertain" => {
		discardPinArtifactValidationForIncident(path);
		return "uncertain";
	};
	// Live observations have their own authority and provider-retention protocol.
	// This branch is intentionally before stopped-finalization inspection: live
	// retention must never depend on stopped liveness or finalization authority.
	if (isLiveIncidentArtifactName(basename(path))) {
		const incomingValidationCheckpoint = liveCheckpoints?.get(liveCheckpointKey);
		const live = inspectLiveIncidentObservation({
			incidentsDirectory: dirname(path),
			incidentId: basename(path),
			maxValidationPagesPerPass: 8,
			validationCheckpoint: incomingValidationCheckpoint,
		});
		if (live.state === "pending" || live.state === "incomplete") {
			const checkpoint = live.validationCheckpoint;
			if (
				checkpoint !== undefined &&
				liveCheckpoints !== undefined &&
				(liveCheckpoints.has(liveCheckpointKey) ||
					liveCheckpoints.size < MAX_LIVE_OBSERVATION_VALIDATION_CHECKPOINTS)
			)
				liveCheckpoints.set(liveCheckpointKey, checkpoint);
			return "pending";
		}
		liveCheckpoints?.delete(liveCheckpointKey);
		if (live.state !== "published") return failClosed();
		const runId = live.observation.run.runId;
		const anchor = exactWallTime(live.observation.anchorWallTimeMs);
		if (anchor === undefined) return failClosed();
		const providerRequests = readLiveProviderRetentionRequests(path, runId, anchor);
		if (providerRequests.state === "missing") {
			discardPinArtifactValidationForIncident(path);
			return "pending";
		}
		if (providerRequests.state === "invalid") return failClosed();
		const retainUntil = anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS;
		if (!Number.isSafeInteger(retainUntil)) return failClosed();
		if (nowMs < retainUntil) {
			discardPinArtifactValidationForIncident(path);
			return nowMs < providerRequests.providers[0].resolveAfter ? "pending" : "retain";
		}
		for (const {
			provider,
			runId: providerRunId,
			from,
			through,
			retainUntil: providerRetainUntil,
			generationId,
			ringBasePath,
		} of providerRequests.providers) {
			const proofPath = join(path, `${provider}-pin-retention-proof.json`);
			const proof = decisionJson(proofPath, PIN_REQUEST_MAX_BYTES);
			if (proof.state === "uncertain") return failClosed();
			if (proof.state === "ok") {
				if (!privateDecisionMetadata(proofPath) || !proof.value) return failClosed();
				const canonicalProof = canonicalProviderPinProof(
					proof.value,
					provider,
					providerRunId,
					from,
					through,
					providerRetainUntil,
				);
				if (!canonicalProof) return failClosed();
				const manifestPath = join(path, `${provider}-pin-manifest.json`);
				const pinDirectoryPath = join(path, provider === "journal" ? "journal-pins/cas" : "sysdig-pins/segments");
				const validation = validateProviderPinManifest(
					provider,
					path,
					manifestPath,
					pinDirectoryPath,
					providerRunId,
					anchor,
					from,
					through,
					providerRetainUntil,
					budget,
					generationId,
					ringBasePath,
					canonicalProof,
				);
				if (validation === "pending") return "pending";
				if (validation === "invalid") return failClosed();
				continue;
			}
			const incomplete = decisionJson(join(path, `${provider}-pin-incomplete.json`), PIN_REQUEST_MAX_BYTES);
			if (incomplete.state === "uncertain") return failClosed();
			if (
				incomplete.state !== "ok" ||
				!incomplete.value ||
				!canonicalProviderPinIncomplete(incomplete.value, provider, providerRunId, anchor, from, through)
			)
				return failClosed();
			discardPinArtifactValidationForProvider(path, provider);
		}
		const finalLive = inspectLiveIncidentObservation({
			incidentsDirectory: dirname(path),
			incidentId: basename(path),
			maxValidationPagesPerPass: 8,
			validationCheckpoint: incomingValidationCheckpoint,
		});
		if (finalLive.state !== "published") {
			if (finalLive.state === "pending" || finalLive.state === "incomplete") {
				const checkpoint = finalLive.validationCheckpoint;
				if (
					checkpoint !== undefined &&
					liveCheckpoints !== undefined &&
					(liveCheckpoints.has(liveCheckpointKey) ||
						liveCheckpoints.size < MAX_LIVE_OBSERVATION_VALIDATION_CHECKPOINTS)
				)
					liveCheckpoints.set(liveCheckpointKey, checkpoint);
			}
			return finalLive.state === "pending" || finalLive.state === "incomplete" ? "pending" : failClosed();
		}
		if (canonicalControlJson(finalLive.observation) !== canonicalControlJson(live.observation)) return failClosed();
		const finalProviderRequests = readLiveProviderRetentionRequests(path, runId, anchor);
		if (
			finalProviderRequests.state !== "valid" ||
			canonicalControlJson(finalProviderRequests.authority) !== canonicalControlJson(providerRequests.authority) ||
			canonicalControlJson(finalProviderRequests.sysdig) !== canonicalControlJson(providerRequests.sysdig) ||
			canonicalControlJson(finalProviderRequests.journal) !== canonicalControlJson(providerRequests.journal)
		)
			return failClosed();
		discardPinArtifactValidationForIncident(path);
		return "delete";
	}
	const inspectionInput = {
		incidentsDirectory: dirname(path),
		incidentId: basename(path),
	};
	const finalization = inspectPublishedIncidentFinalization(inspectionInput);
	if (finalization.state === "pending") return failClosed();
	const authority = inspectIncidentRetentionAuthority(inspectionInput);
	if (authority.state !== "authorized") return failClosed();
	if (
		authority.finalizationId !== finalization.finalizationId ||
		authority.runId !== finalization.runId ||
		authority.outcome !== finalization.state ||
		authority.retentionAnchorWallTimeMs !== finalization.retentionAnchorWallTimeMs
	)
		return failClosed();
	let finalizationManifestFingerprint: string;
	try {
		finalizationManifestFingerprint = controlFingerprint(finalization.manifest);
	} catch {
		return failClosed();
	}
	const anchor = authority.retentionAnchorWallTimeMs;
	const finalizationRetention =
		authority.retentionClass === "corrupt" ? INCIDENT_CORRUPTION_QUARANTINE_MS : INCIDENT_DIAGNOSTIC_RETENTION_MS;
	let retainUntil = anchor + finalizationRetention;
	if (!Number.isSafeInteger(retainUntil)) return failClosed();
	const sourceRunPath = join(dirname(dirname(path)), "incident-recorder", "runs", basename(path));
	try {
		const sourceRun = lstatSync(sourceRunPath);
		if (!sourceRun.isDirectory() || sourceRun.isSymbolicLink()) return failClosed();
		const conflict = serviceDecisionJson(join(sourceRunPath, "service-finalization-publication-conflict.json"));
		if (conflict.state === "uncertain") return failClosed();
		if (conflict.state === "ok") {
			const completion = serviceDecisionJson(join(sourceRunPath, ".service-finalization-complete"));
			const completionAuthority = serviceFinalizationCompletion(sourceRunPath, completion);
			if (
				!completionAuthority?.publicationConflictPublishedFinalizationId ||
				completionAuthority.publicationConflictPublishedFinalizationId !== finalization.finalizationId
			) {
				return failClosed();
			}
			const conflictRetainUntil = completionAuthority.anchorWallTimeMs + completionAuthority.retentionMilliseconds;
			if (!Number.isSafeInteger(conflictRetainUntil)) return failClosed();
			retainUntil = Math.max(retainUntil, conflictRetainUntil);
		}
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") return failClosed();
	}
	const providerRequests: Array<{
		provider: "journal" | "sysdig";
		runId: string;
		from: number;
		through: number;
		resolveAfter: number;
		retainUntil: number;
		generationId: string;
		ringBasePath?: string;
	}> = [];
	for (const provider of ["journal", "sysdig"] as const) {
		const request = decisionJson(join(path, `${provider}-pin-request.json`), PIN_REQUEST_MAX_BYTES);
		if (request.state !== "ok") return failClosed();
		const requestValue = request.value;
		if (!requestValue) return failClosed();
		const runId = requestValue.runId;
		const requestAnchor = exactWallTime(requestValue.anchorWallTimeMs);
		const from = exactWallTime(requestValue.fromWallTimeMs);
		const through = exactWallTime(requestValue.throughWallTimeMs);
		const resolveAfter = exactWallTime(requestValue.resolveAfterWallTimeMs);
		const explicitRetainUntil = exactWallTime(requestValue.retainUntilWallTimeMs);
		const sysdigRequestKeys = [
			"version",
			"runId",
			"anchorWallTimeMs",
			"fromWallTimeMs",
			"throughWallTimeMs",
			"resolveAfterWallTimeMs",
			"requestedAtWallTimeMs",
			"retainUntilWallTimeMs",
			"ringBasePath",
			"initialRingSnapshot",
		];
		const policyRetainUntil =
			requestAnchor === undefined ? undefined : requestAnchor + INCIDENT_DIAGNOSTIC_RETENTION_MS;
		if (
			requestValue.version !== 1 ||
			(provider === "journal"
				? requestValue.state !== "pending" ||
					!exactKeys(requestValue, [
						"version",
						"state",
						"runId",
						"anchorWallTimeMs",
						"fromWallTimeMs",
						"throughWallTimeMs",
						"resolveAfterWallTimeMs",
						"retainUntilWallTimeMs",
					])
				: !exactKeys(requestValue, sysdigRequestKeys) ||
					exactWallTime(requestValue.requestedAtWallTimeMs) !== anchor ||
					typeof requestValue.ringBasePath !== "string" ||
					requestValue.ringBasePath.length === 0 ||
					Buffer.byteLength(requestValue.ringBasePath, "utf8") > 4 * 1024 ||
					!validSysdigInitialRingSnapshot(requestValue.initialRingSnapshot, requestValue.ringBasePath)) ||
			typeof runId !== "string" ||
			runId !== finalization.runId ||
			canonicalRunId(runId) !== runId ||
			requestAnchor !== anchor ||
			from === undefined ||
			through === undefined ||
			resolveAfter === undefined ||
			policyRetainUntil === undefined ||
			!Number.isSafeInteger(policyRetainUntil) ||
			from !== anchor - INCIDENT_PIN_BEFORE_MS ||
			through !== anchor + INCIDENT_PIN_AFTER_MS ||
			resolveAfter !== through ||
			explicitRetainUntil !== anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS
		)
			return failClosed();
		const generationId =
			provider === "journal"
				? controlFingerprint({
						provider,
						runId,
						anchorWallTimeMs: anchor,
						fromWallTimeMs: from,
						throughWallTimeMs: through,
					})
				: controlFingerprint({
						provider,
						requestFingerprint: controlFingerprint({
							version: requestValue.version,
							runId,
							anchorWallTimeMs: requestAnchor,
							fromWallTimeMs: from,
							throughWallTimeMs: through,
							resolveAfterWallTimeMs: resolveAfter,
							retainUntilWallTimeMs: explicitRetainUntil,
							ringBasePath: requestValue.ringBasePath,
							requestedAtWallTimeMs: requestValue.requestedAtWallTimeMs,
							initialRingSnapshot: requestValue.initialRingSnapshot,
						}),
					});
		retainUntil = Math.max(retainUntil, policyRetainUntil);
		providerRequests.push({
			provider,
			runId,
			from,
			through,
			resolveAfter,
			retainUntil: explicitRetainUntil,
			generationId,
			...(provider === "sysdig" ? { ringBasePath: requestValue.ringBasePath as string } : {}),
		});
	}
	if (nowMs < retainUntil) {
		discardPinArtifactValidationForIncident(path);
		const disposition = providerRequests.some((request) => nowMs < request.resolveAfter) ? "pending" : "retain";
		return disposition;
	}
	for (const {
		provider,
		runId,
		from,
		through,
		retainUntil: providerRetainUntil,
		generationId,
		ringBasePath,
	} of providerRequests) {
		const proofPath = join(path, `${provider}-pin-retention-proof.json`);
		const proof = decisionJson(proofPath, PIN_REQUEST_MAX_BYTES);
		if (proof.state === "uncertain") return failClosed();
		if (proof.state === "ok") {
			if (!privateDecisionMetadata(proofPath) || !proof.value) return failClosed();
			const canonicalProof = canonicalProviderPinProof(
				proof.value,
				provider,
				runId,
				from,
				through,
				providerRetainUntil,
			);
			if (!canonicalProof) return failClosed();
			const manifestPath = join(path, `${provider}-pin-manifest.json`);
			const pinDirectoryPath = join(path, provider === "journal" ? "journal-pins/cas" : "sysdig-pins/segments");
			const validation = validateProviderPinManifest(
				provider,
				path,
				manifestPath,
				pinDirectoryPath,
				runId,
				anchor,
				from,
				through,
				providerRetainUntil,
				budget,
				generationId,
				ringBasePath,
				canonicalProof,
			);
			if (validation === "pending") return "pending";
			if (validation === "invalid") return failClosed();
			continue;
		}
		const incomplete = decisionJson(join(path, `${provider}-pin-incomplete.json`), PIN_REQUEST_MAX_BYTES);
		if (incomplete.state === "uncertain") return failClosed();
		if (incomplete.state === "ok") {
			if (
				!incomplete.value ||
				!canonicalProviderPinIncomplete(incomplete.value, provider, runId, anchor, from, through)
			)
				return failClosed();
			// A terminal outcome for one provider must not erase resumable proof
			// work for the other provider. In particular, Journal is visited first;
			// clearing incident-wide state here would restart every Sysdig artifact
			// larger than the per-pass hash budget on every pass.
			discardPinArtifactValidationForProvider(path, provider);
			continue;
		}
		// A bare manifest is not producer authority. In particular, only the
		// Journal producer proof attests that every occurrence reference was
		// resolved before publication. Hold the source until producer recovery
		// reconstructs a canonical proof or records a canonical incomplete result.
		return failClosed();
	}
	const finalFinalization = inspectPublishedIncidentFinalization(inspectionInput);
	const finalAuthority = inspectIncidentRetentionAuthority(inspectionInput);
	let finalManifestFingerprint: string | undefined;
	if (finalFinalization.state !== "pending")
		try {
			finalManifestFingerprint = controlFingerprint(finalFinalization.manifest);
		} catch {}
	if (
		finalFinalization.state === "pending" ||
		finalAuthority.state !== "authorized" ||
		finalFinalization.state !== finalization.state ||
		finalFinalization.finalizationId !== finalization.finalizationId ||
		finalFinalization.runId !== finalization.runId ||
		finalFinalization.manifest.runIdentity.runToken !== finalization.manifest.runIdentity.runToken ||
		finalFinalization.retentionAnchorWallTimeMs !== finalization.retentionAnchorWallTimeMs ||
		finalFinalization.authorityDirectory !== finalization.authorityDirectory ||
		finalFinalization.serviceTerminalRelayDisposition !== finalization.serviceTerminalRelayDisposition ||
		finalManifestFingerprint !== finalizationManifestFingerprint ||
		finalAuthority.finalizationId !== authority.finalizationId ||
		finalAuthority.runId !== authority.runId ||
		finalAuthority.outcome !== authority.outcome ||
		finalAuthority.retentionAnchorWallTimeMs !== authority.retentionAnchorWallTimeMs ||
		finalAuthority.authoritySource !== authority.authoritySource ||
		finalAuthority.retentionClass !== authority.retentionClass
	)
		return failClosed();
	discardPinArtifactValidationForIncident(path);
	return "delete";
}

function tombstone(path: string, mutation: RetentionMutationContext, expected?: Stats): string | undefined {
	const target = join(join(path, ".."), `${GC_PREFIX}${basename(path)}`);
	const sourceCapability = relativeMutationPath(path, mutation);
	const targetCapability = relativeMutationPath(target, mutation);
	if (!sourceCapability || !targetCapability || sourceCapability.root !== targetCapability.root) return undefined;
	try {
		const current = sourceCapability.root.lstat(sourceCapability.relative);
		if ((expected && !sameRetentionIdentity(expected, current)) || !current) return undefined;
		sourceCapability.root.rename(sourceCapability.relative, targetCapability.relative);
		const parentCapability = relativeMutationPath(dirname(target), mutation);
		if (parentCapability) parentCapability.root.fsyncDirectory(parentCapability.relative);
		return target;
	} catch {
		return undefined;
	}
}

function removeTreeIncremental(path: string, budget: Budget, mutation: RetentionMutationContext, depth = 0): void {
	if (depth > 16) {
		budget.uncertainties.push(`delete-depth:${path}`);
		return;
	}
	if (budget.deleted >= budget.maxDeletes || budget.scanned >= budget.maxEntries || deadlineReached(budget)) {
		budget.moreWork = true;
		return;
	}
	let stat: Stats;
	try {
		stat = lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`delete-stat:${path}`);
		return;
	}
	budget.scanned += 1;
	const capability = relativeMutationPath(path, mutation);
	if (!capability) {
		budget.uncertainties.push(`delete-path:${path}`);
		return;
	}
	const current = capability.root.lstat(capability.relative);
	if (!sameRetentionIdentity(stat, current)) {
		budget.uncertainties.push(`delete-identity:${path}`);
		return;
	}
	if (!stat.isDirectory()) {
		try {
			capability.root.unlinkFile(capability.relative);
			fsyncMutationParent(path, mutation);
			budget.deleted += 1;
		} catch {
			budget.uncertainties.push(`delete-file:${path}`);
		}
		return;
	}
	let directory: Dir | undefined;
	try {
		directory = opendirSync(path);
		for (;;) {
			if (budget.deleted >= budget.maxDeletes || budget.scanned >= budget.maxEntries || deadlineReached(budget)) {
				budget.moreWork = true;
				return;
			}
			const entry = directory.readSync();
			if (!entry) break;
			removeTreeIncremental(join(path, entry.name), budget, mutation, depth + 1);
		}
	} catch {
		budget.uncertainties.push(`delete-directory:${path}`);
		return;
	} finally {
		try {
			directory?.closeSync();
		} catch {}
	}
	if (budget.deleted >= budget.maxDeletes) {
		budget.moreWork = true;
		return;
	}
	try {
		capability.root.rmdir(capability.relative);
		fsyncMutationParent(path, mutation);
		budget.deleted += 1;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOTEMPTY") budget.moreWork = true;
		else if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`delete-rmdir:${path}`);
	}
}

function pruneArtifactDirectories(
	root: string,
	kind: "run" | "incident",
	nowMs: number,
	budget: Budget,
	machineId: string,
	bootId: string,
	identity: NonNullable<IncidentRetentionOptions["processIdentity"]>,
	activeRunHashes: Set<string>,
	protectedActiveRuns: string[],
	incidentProtectedRuns: Set<string>,
	runSafety: { activeRuns: Set<string>; unsafeForCas: boolean },
	segmentProtection: SegmentProtectionAccumulator,
	mutation: RetentionMutationContext,
): boolean {
	let pendingIncident = false;
	readDirResumable(root, budget, (name, stat) => {
		if (budget.deleted >= budget.maxDeletes) {
			budget.moreWork = true;
			return;
		}
		const path = join(root, name);
		if (!stat.isDirectory()) {
			budget.uncertainties.push(`unexpected-artifact:${path}`);
			return;
		}
		if (name.startsWith(GC_PREFIX)) {
			removeTreeIncremental(path, budget, mutation);
			return;
		}
		const hiddenIncidentName = kind === "incident" ? hiddenIncidentArtifactName(name) : undefined;
		if (hiddenIncidentName) {
			const liveStage = name.startsWith(".live-");
			if (liveStage) {
				if (!isLiveIncidentStageName(name)) {
					pendingIncident = true;
					segmentProtection.uncertain = true;
					budget.uncertainties.push(`live-incident-stage:${path}`);
					return;
				}
				pendingIncident = true;
				incidentProtectedRuns.add(hiddenIncidentName);
				const liveRunId = canonicalRunIdFromArtifactName(hiddenIncidentName);
				if (liveRunId) {
					incidentProtectedRuns.add(liveRunId);
					segmentProtection.protectedRunIds.add(liveRunId);
				} else {
					segmentProtection.uncertain = true;
					budget.uncertainties.push(`incident-run-identity:${path}`);
				}
				return;
			}
			const published = inspectPublishedIncidentFinalization({
				incidentsDirectory: root,
				incidentId: hiddenIncidentName,
			});
			if (published.state !== "pending") {
				const obsoleteStage = tombstone(path, mutation, stat);
				if (obsoleteStage) {
					removeTreeIncremental(obsoleteStage, budget, mutation);
					return;
				}
			}
			pendingIncident = true;
			incidentProtectedRuns.add(hiddenIncidentName);
			const runId = canonicalRunIdFromArtifactName(hiddenIncidentName);
			if (runId) {
				incidentProtectedRuns.add(runId);
				segmentProtection.protectedRunIds.add(runId);
			} else {
				segmentProtection.uncertain = true;
				budget.uncertainties.push(`incident-run-identity:${path}`);
			}
			return;
		}
		const liveArtifact = kind === "incident" && isLiveIncidentArtifactName(name);
		if (liveArtifact) {
			const liveRunId = canonicalRunIdFromArtifactName(name);
			if (liveRunId) {
				// Keep the descriptor's run owner protected for the whole pass. The
				// live same-named source check below is intentionally bypassed, but
				// run protection must still prevent supervisor/source reclamation.
				incidentProtectedRuns.add(liveRunId);
				segmentProtection.protectedRunIds.add(liveRunId);
			} else {
				segmentProtection.uncertain = true;
				budget.uncertainties.push(`incident-run-identity:${path}`);
			}
		}
		if (kind === "run") {
			const runId = canonicalRunIdFromArtifactName(name);
			if (!runId) {
				segmentProtection.uncertain = true;
				runSafety.unsafeForCas = true;
				budget.uncertainties.push(`run-id:${path}`);
				return;
			}
			const runHash = createHash("sha256").update(runId).digest("hex");
			if (runHash) activeRunHashes.add(runHash);
			const protection = runProtection(path, machineId, bootId, identity);
			if (protection === "active") {
				protectedActiveRuns.push(name);
				runSafety.activeRuns.add(name);
				segmentProtection.protectedRunIds.add(runId);
				return;
			}
			if (protection === "pending") {
				segmentProtection.protectedRunIds.add(runId);
				return;
			}
			if (incidentProtectedRuns.has(name) || incidentProtectedRuns.has(runId)) {
				segmentProtection.protectedRunIds.add(runId);
				if (protection === "uncertain") {
					runSafety.unsafeForCas = true;
					segmentProtection.uncertain = true;
					budget.uncertainties.push(`run-identity:${path}`);
				}
				return;
			}
			if (protection === "uncertain") {
				runSafety.unsafeForCas = true;
				segmentProtection.uncertain = true;
				segmentProtection.protectedRunIds.add(runId);
				budget.uncertainties.push(`run-identity:${path}`);
				return;
			}
			const isExpired = runExpired(path, nowMs);
			if (isExpired === undefined) {
				segmentProtection.uncertain = true;
				segmentProtection.protectedRunIds.add(runId);
				budget.uncertainties.push(`run-terminal:${path}`);
				return;
			}
			if (!isExpired) {
				segmentProtection.protectedRunIds.add(runId);
				return;
			}
		} else {
			const disposition = incidentDisposition(path, nowMs, budget);
			if (disposition === "pending") {
				pendingIncident = true;
				incidentProtectedRuns.add(name);
				for (const runId of collectIncidentProtectedRunIds(path, name, budget, segmentProtection))
					incidentProtectedRuns.add(runId);
				return;
			}
			if (disposition === "uncertain") {
				incidentProtectedRuns.add(name);
				segmentProtection.uncertain = true;
				for (const runId of collectIncidentProtectedRunIds(path, name, budget, segmentProtection))
					incidentProtectedRuns.add(runId);
				budget.uncertainties.push(`incident-state:${path}`);
				return;
			}
			if (disposition === "retain") {
				incidentProtectedRuns.add(name);
				for (const runId of collectIncidentProtectedRunIds(path, name, budget, segmentProtection))
					incidentProtectedRuns.add(runId);
				return;
			}
			// Incident authority must remain durable until its same-named source run
			// has left the live namespace.  Do not add run protection here: this
			// deliberate two-pass order lets the run reclaim first and prevents a
			// crash between incident/run scans from stranding an unverifiable run.
			if (budget.scanned >= budget.maxEntries || deadlineReached(budget)) {
				budget.moreWork = true;
				return;
			}
			budget.scanned += 1;
			if (liveArtifact) {
				const renamed = tombstone(path, mutation, stat);
				if (!renamed) {
					budget.uncertainties.push(`rename-for-delete:${path}`);
					return;
				}
				removeTreeIncremental(renamed, budget, mutation);
				return;
			}
			const sourceRunPath = join(dirname(root), "incident-recorder", "runs", name);
			try {
				const sourceRun = lstatSync(sourceRunPath);
				if (sourceRun.isDirectory() && !sourceRun.isSymbolicLink()) return;
				segmentProtection.uncertain = true;
				budget.uncertainties.push(`incident-source-run:${sourceRunPath}`);
				return;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
					segmentProtection.uncertain = true;
					budget.uncertainties.push(`incident-source-run:${sourceRunPath}`);
					return;
				}
			}
		}
		if (kind === "run") {
			const runId = canonicalRunIdFromArtifactName(name);
			if (runId) activeRunHashes.delete(createHash("sha256").update(runId).digest("hex"));
		}
		const renamed = tombstone(path, mutation, stat);
		if (!renamed) {
			budget.uncertainties.push(`rename-for-delete:${path}`);
			return;
		}
		removeTreeIncremental(renamed, budget, mutation);
	});
	return pendingIncident;
}

function pruneRunReferenceOwners(
	root: string,
	nowMs: number,
	budget: Budget,
	retainedRunHashes: Set<string>,
	mutation: RetentionMutationContext,
): void {
	const ownersRoot = join(root, "runs");
	readDirResumable(ownersRoot, budget, (name, stat) => {
		if (budget.deleted >= budget.maxDeletes) {
			budget.moreWork = true;
			return;
		}
		const path = join(ownersRoot, name);
		if (!stat.isDirectory()) {
			budget.uncertainties.push(`unexpected-run-ref-owner:${path}`);
			return;
		}
		if (name.startsWith(GC_PREFIX)) {
			removeTreeIncremental(path, budget, mutation);
			return;
		}
		if (retainedRunHashes.has(name) || !expired(stat, nowMs)) return;
		const renamed = tombstone(path, mutation, stat);
		if (!renamed) {
			budget.uncertainties.push(`rename-run-ref-owner:${path}`);
			return;
		}
		removeTreeIncremental(renamed, budget, mutation);
	});
	if (!resumableDirectories.has(ownersRoot)) completedRunOwnerPrunes.add(root);
}

function pruneReferences(root: string, nowMs: number, budget: Budget, mutation: RetentionMutationContext): void {
	let state = referenceWalkStates.get(root);
	if (!state || state.complete) {
		state = createTreeWalk(root);
		referenceWalkStates.set(root, state);
	}
	while (
		!state.complete &&
		budget.deleted < budget.maxDeletes &&
		budget.scanned < budget.maxEntries &&
		!deadlineReached(budget)
	) {
		const entry = nextTreeFile(state, budget);
		if (!entry) break;
		if (!entry.stat.isFile() || !expired(entry.stat, nowMs)) continue;
		const relative = entry.path.slice(root.length + 1).split("/");
		if (relative[0] === "runs") continue;
		try {
			const capability = relativeMutationPath(entry.path, mutation);
			if (!capability || !sameRetentionIdentity(entry.stat, capability.root.lstat(capability.relative))) {
				budget.uncertainties.push(`ref-identity:${entry.path}`);
				continue;
			}
			capability.root.unlinkFile(capability.relative);
			fsyncMutationParent(entry.path, mutation);
			budget.deleted += 1;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`ref-delete:${entry.path}`);
		}
	}
	if (state.complete) {
		referenceWalkStates.delete(root);
		completedReferencePrunes.add(root);
	}
}

function addCasMarks(state: CasMarkState, budget: Budget, text: string): void {
	for (const match of text.matchAll(/\b[0-9a-f]{64}\b/g)) {
		if (state.marked.size >= 65_536) {
			state.uncertain = true;
			budget.uncertainties.push("cas-mark-count-bound");
			return;
		}
		state.marked.add(match[0]);
	}
}

function advanceLargeMarkFile(state: CasMarkState, budget: Budget): void {
	const file = state.currentFile;
	if (!file || budget.scanned >= budget.maxEntries || deadlineReached(budget)) return;
	const buffer = Buffer.allocUnsafe(64 * 1024);
	try {
		const count = readSync(file.descriptor, buffer, 0, buffer.length, file.offset);
		budget.scanned += 1;
		if (count === 0) {
			const after = fstatSync(file.descriptor);
			if (
				after.dev !== file.dev ||
				after.ino !== file.ino ||
				after.size !== file.size ||
				after.mtimeMs !== file.mtimeMs
			) {
				state.uncertain = true;
				budget.uncertainties.push(`reference-changed:${file.path}`);
			}
			closeSync(file.descriptor);
			state.currentFile = undefined;
			return;
		}
		const chunk = file.carry + buffer.subarray(0, count).toString("utf8");
		addCasMarks(state, budget, chunk);
		file.carry = chunk.slice(-80);
		file.offset += count;
	} catch {
		try {
			closeSync(file.descriptor);
		} catch {}
		state.currentFile = undefined;
		state.uncertain = true;
		budget.uncertainties.push(`reference-read:${file.path}`);
	}
}

function advanceCasMark(
	key: string,
	roots: readonly string[],
	budget: Budget,
	leaseBoundaryMs: number,
): { complete: boolean; marked?: Set<string>; uncertain: boolean } {
	let state = casMarkStates.get(key);
	if (!state) {
		const first = roots[0] ?? key;
		state = { ...createTreeWalk(first), marked: new Set<string>(), uncertain: false, leaseBoundaryMs };
		casMarkStates.set(key, state);
		(state as CasMarkState & { roots?: string[]; rootIndex?: number }).roots = [...roots];
		(state as CasMarkState & { roots?: string[]; rootIndex?: number }).rootIndex = 0;
	}
	const extended = state as CasMarkState & { roots: string[]; rootIndex: number };
	if (state.leaseBoundaryMs !== leaseBoundaryMs) {
		state.uncertain = true;
		budget.uncertainties.push("lease-protocol-boundary-changed");
	}
	while (budget.scanned < budget.maxEntries && !deadlineReached(budget)) {
		if (state.currentFile) {
			advanceLargeMarkFile(state, budget);
			if (state.uncertain) break;
			continue;
		}
		const uncertaintyCount = budget.uncertainties.length;
		const entry = nextTreeFile(state, budget);
		if (budget.uncertainties.length > uncertaintyCount) state.uncertain = true;
		if (!entry) {
			if (!state.complete) break;
			extended.rootIndex += 1;
			if (extended.rootIndex >= extended.roots.length) {
				casMarkStates.delete(key);
				return { complete: true, marked: state.marked, uncertain: state.uncertain };
			}
			const next = createTreeWalk(extended.roots[extended.rootIndex]);
			state.root = next.root;
			state.stack = next.stack;
			state.complete = next.complete;
			continue;
		}
		if (!entry.stat.isFile()) continue;
		const name = basename(entry.path);
		const blob = CAS_NAME.exec(name);
		// Leases/pins are hard links. The sweep's fresh nlink===1 check is their
		// authoritative protection, so they never consume legacy mark cardinality.
		if (blob) continue;
		// Current-protocol references are published only after their hard-link
		// lease. Mark only immutable path-only references created before activation.
		if (entry.stat.mtimeMs > state.leaseBoundaryMs) continue;
		if (name === "journal-pin-manifest.json" || name === "sysdig-pin-manifest.json") continue;
		if (!/\.(?:json|jsonl)$/i.test(name)) continue;
		if (entry.stat.size > 64 * 1024) {
			try {
				const descriptor = openSync(entry.path, "r");
				const opened = fstatSync(descriptor);
				if (opened.dev !== entry.stat.dev || opened.ino !== entry.stat.ino || !opened.isFile())
					throw new Error("reference_identity_changed");
				state.currentFile = {
					path: entry.path,
					descriptor,
					offset: 0,
					size: opened.size,
					dev: opened.dev,
					ino: opened.ino,
					mtimeMs: opened.mtimeMs,
					carry: "",
				};
			} catch {
				state.uncertain = true;
				budget.uncertainties.push(`reference-read:${entry.path}`);
				break;
			}
			continue;
		}
		const read = boundedRead(entry.path, 64 * 1024);
		if (read.state !== "ok" || !read.bytes) {
			state.uncertain = true;
			budget.uncertainties.push(`reference-read:${entry.path}`);
			break;
		}
		addCasMarks(state, budget, read.bytes.toString("utf8"));
		if (state.uncertain) break;
	}
	return { complete: false, uncertain: state.uncertain };
}

function advanceCasSweep(
	root: string,
	nowMs: number,
	budget: Budget,
	marked: Set<string>,
	mutation: RetentionMutationContext,
): boolean {
	let state = casSweepStates.get(root);
	if (!state || state.complete) {
		state = createTreeWalk(root);
		casSweepStates.set(root, state);
	}
	while (
		!state.complete &&
		budget.deleted < budget.maxDeletes &&
		budget.scanned < budget.maxEntries &&
		!deadlineReached(budget)
	) {
		const entry = nextTreeFile(state, budget);
		if (!entry) break;
		const match = CAS_NAME.exec(basename(entry.path));
		if (
			!entry.stat.isFile() ||
			!match ||
			!expired(entry.stat, nowMs) ||
			marked.has(match[1]) ||
			entry.stat.nlink > 1 ||
			entry.path.includes("/staging/")
		)
			continue;
		try {
			const capability = relativeMutationPath(entry.path, mutation);
			if (!capability) throw new Error("cas_path_outside_namespace");
			const current = capability.root.lstat(capability.relative);
			if (
				!sameRetentionIdentity(entry.stat, current) ||
				!current?.isFile() ||
				Number(current.nlink) !== 1 ||
				!expired(entry.stat, nowMs)
			)
				continue;
			capability.root.unlinkFile(capability.relative);
			fsyncMutationParent(entry.path, mutation);
			budget.deleted += 1;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`cas-delete:${entry.path}`);
		}
	}
	if (state.complete) casSweepStates.delete(root);
	return state.complete;
}

function leaseProtocolBoundary(root: string): number | undefined {
	const path = join(root, "lease-protocol-v1.json");
	const record = decisionJson(path);
	const activated = record.state === "ok" ? record.value?.activatedAtWallTimeMs : undefined;
	return record.state === "ok" &&
		record.value?.version === 1 &&
		record.value.state === "active" &&
		record.value.protocol === "cas-hard-link-lease-before-reference" &&
		Number.isSafeInteger(activated)
		? Number(activated)
		: undefined;
}

function ensureLeaseProtocolBoundary(
	root: string,
	nowMs: number,
	mutation: RetentionMutationContext,
): number | undefined {
	const path = join(root, "lease-protocol-v1.json");
	const record = decisionJson(path);
	if (record.state === "missing") {
		const rootCapability = relativeMutationPath(root, mutation);
		const pathCapability = relativeMutationPath(path, mutation);
		if (!rootCapability || !pathCapability) return undefined;
		rootCapability.root.mkdirPrivate(rootCapability.relative, true);
		const temporary = `${path}.tmp-${process.pid}-${process.hrtime.bigint()}`;
		const temporaryCapability = relativeMutationPath(temporary, mutation);
		if (!temporaryCapability) return undefined;
		try {
			temporaryCapability.root.writeFileExclusive(
				temporaryCapability.relative,
				`${JSON.stringify({ version: 1, state: "active", activatedAtWallTimeMs: nowMs, protocol: "cas-hard-link-lease-before-reference" })}
`,
				0o600,
			);
			temporaryCapability.root.fsyncFile(temporaryCapability.relative);
			try {
				pathCapability.root.hardLink(temporaryCapability.relative, pathCapability.relative);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			}
			pathCapability.root.fsyncDirectory(rootCapability.relative);
		} finally {
			try {
				temporaryCapability.root.unlinkFile(temporaryCapability.relative);
			} catch {}
		}
		// A completed mark from a pre-lease implementation cannot classify the
		// new protocol boundary. Discard it; incomplete generations never sweep.
		removePersistedMark(root, mutation);
	}
	return leaseProtocolBoundary(root);
}

function persistedMarkPaths(root: string): { directory: string; log: string; proof: string } {
	const directory = join(root, "retention");
	return {
		directory,
		log: join(directory, "legacy-marks-v1.log"),
		proof: join(directory, "legacy-marks-v1-complete.json"),
	};
}

function persistCompletedMark(root: string, marked: Set<string>, mutation: RetentionMutationContext): void {
	const paths = persistedMarkPaths(root);
	const directoryCapability = relativeMutationPath(paths.directory, mutation);
	const logCapability = relativeMutationPath(paths.log, mutation);
	const proofCapability = relativeMutationPath(paths.proof, mutation);
	if (!directoryCapability || !logCapability || !proofCapability) throw new Error("retention mark outside namespace");
	directoryCapability.root.mkdirPrivate(directoryCapability.relative, true);
	const logBytes = Buffer.from(`${[...marked].sort().join("\n")}\n`, "utf8");
	const suffix = `${process.pid}-${process.hrtime.bigint()}`;
	const temporaryLog = `${paths.log}.tmp-${suffix}`;
	const temporaryProof = `${paths.proof}.tmp-${suffix}`;
	const temporaryLogCapability = relativeMutationPath(temporaryLog, mutation);
	const temporaryProofCapability = relativeMutationPath(temporaryProof, mutation);
	if (!temporaryLogCapability || !temporaryProofCapability)
		throw new Error("retention mark temporary outside namespace");
	temporaryLogCapability.root.writeFileExclusive(temporaryLogCapability.relative, logBytes, 0o600);
	temporaryLogCapability.root.fsyncFile(temporaryLogCapability.relative);
	temporaryLogCapability.root.rename(temporaryLogCapability.relative, logCapability.relative);
	directoryCapability.root.fsyncDirectory(directoryCapability.relative);
	temporaryProofCapability.root.writeFileExclusive(
		temporaryProofCapability.relative,
		`${JSON.stringify({
			version: 1,
			state: "complete",
			count: marked.size,
			bytes: logBytes.length,
			sha256: createHash("sha256").update(logBytes).digest("hex"),
		})}\n`,
		0o600,
	);
	temporaryProofCapability.root.fsyncFile(temporaryProofCapability.relative);
	temporaryProofCapability.root.rename(temporaryProofCapability.relative, proofCapability.relative);
	directoryCapability.root.fsyncDirectory(directoryCapability.relative);
}

function loadPersistedMark(root: string): Set<string> | undefined {
	const paths = persistedMarkPaths(root);
	const proof = smallJson(paths.proof);
	if (
		proof.state !== "ok" ||
		proof.value?.version !== 1 ||
		proof.value.state !== "complete" ||
		!Number.isSafeInteger(proof.value.count) ||
		Number(proof.value.count) < 0 ||
		Number(proof.value.count) > 65_536 ||
		!Number.isSafeInteger(proof.value.bytes) ||
		Number(proof.value.bytes) < 0 ||
		Number(proof.value.bytes) > 5 * 1024 * 1024 ||
		typeof proof.value.sha256 !== "string" ||
		!/^[0-9a-f]{64}$/.test(proof.value.sha256)
	)
		return undefined;
	const log = boundedRead(paths.log, 5 * 1024 * 1024);
	if (
		log.state !== "ok" ||
		!log.bytes ||
		log.bytes.length !== proof.value.bytes ||
		createHash("sha256").update(log.bytes).digest("hex") !== proof.value.sha256
	)
		return undefined;
	const values = log.bytes.toString("utf8").trim().split("\n").filter(Boolean);
	if (values.length !== proof.value.count || values.some((value) => !/^[0-9a-f]{64}$/.test(value))) return undefined;
	return new Set(values);
}

function removePersistedMark(root: string, mutation: RetentionMutationContext): void {
	const paths = persistedMarkPaths(root);
	for (const path of [paths.proof, paths.log])
		try {
			const capability = relativeMutationPath(path, mutation);
			if (capability) capability.root.unlinkFile(capability.relative);
		} catch {}
}

function runIncidentRetentionPassOwned(
	options: IncidentRetentionOptions,
	mutation: RetentionMutationContext,
): IncidentRetentionResult {
	const nowMs = options.nowMs ?? Date.now();
	const deadlineMs = options.deadlineMs ?? Number.POSITIVE_INFINITY;
	if (deadlineMs !== Number.POSITIVE_INFINITY && (!Number.isFinite(deadlineMs) || deadlineMs < 0))
		throw new Error("Invalid incident retention deadline");
	const budget: Budget = {
		scanned: 0,
		deleted: 0,
		maxEntries: Math.max(1, Math.min(options.maxEntries ?? 16_384, 65_536)),
		maxDeletes: Math.max(1, Math.min(options.maxDeletes ?? 256, 1024)),
		deadlineMs,
		liveObservationValidationCheckpoints: options.liveObservationValidationCheckpoints,
		pinArtifactHashBytesRemaining: PIN_ARTIFACT_HASH_BYTES_PER_PASS,
		pinArtifactsRemaining: PIN_ARTIFACTS_PER_PASS,
		moreWork: false,
		uncertainties: [],
	};
	const root = mutation.recorderRoot;
	const machineId = options.machineId ?? defaultMachineId();
	const bootId = options.bootId ?? defaultBootId();
	const identity = options.processIdentity ?? defaultProcessIdentity;
	const leaseBoundaryMs = options.recoveryOnly
		? leaseProtocolBoundary(root)
		: ensureLeaseProtocolBoundary(root, nowMs, mutation);
	if (leaseBoundaryMs === undefined) budget.uncertainties.push("lease-protocol-boundary-unavailable");
	const protectedActiveRuns: string[] = [];
	const incidentRoot = mutation.incidentsRoot;
	let incidentState = incidentScanStates.get(incidentRoot);
	if (!incidentState || !resumableDirectories.has(incidentRoot)) {
		incidentState = {
			protectedRuns: new Set<string>(),
			pending: false,
			segmentProtection: { protectedRunIds: new Set<string>(), uncertain: false },
		};
		incidentScanStates.set(incidentRoot, incidentState);
	}
	const incidentSafety = { activeRuns: new Set<string>(), unsafeForCas: false };
	const incidentUncertaintyCount = budget.uncertainties.length;
	incidentState.pending =
		pruneArtifactDirectories(
			incidentRoot,
			"incident",
			nowMs,
			budget,
			machineId,
			bootId,
			identity,
			new Set<string>(),
			protectedActiveRuns,
			incidentState.protectedRuns,
			incidentSafety,
			incidentState.segmentProtection,
			mutation,
		) || incidentState.pending;
	if (budget.uncertainties.length > incidentUncertaintyCount) incidentState.segmentProtection.uncertain = true;
	const incidentScanComplete = !resumableDirectories.has(incidentRoot);
	const pendingIncident = incidentState.pending;
	const runRoot = join(root, "runs");
	let runState = runScanStates.get(runRoot);
	if (incidentScanComplete && (!runState || !resumableDirectories.has(runRoot))) {
		runState = {
			hashes: new Set<string>(),
			activeRuns: new Set<string>(),
			unsafeForCas: false,
			segmentProtection: { protectedRunIds: new Set<string>(), uncertain: false },
		};
		runScanStates.set(runRoot, runState);
	}
	if (incidentScanComplete && runState) {
		const runUncertaintyCount = budget.uncertainties.length;
		pruneArtifactDirectories(
			runRoot,
			"run",
			nowMs,
			budget,
			machineId,
			bootId,
			identity,
			runState.hashes,
			protectedActiveRuns,
			incidentState.protectedRuns,
			runState,
			runState.segmentProtection,
			mutation,
		);
		if (budget.uncertainties.length > runUncertaintyCount) runState.segmentProtection.uncertain = true;
	}
	const runScanComplete = incidentScanComplete && !resumableDirectories.has(runRoot);
	if (runScanComplete && runState) protectedActiveRuns.splice(0, protectedActiveRuns.length, ...runState.activeRuns);
	if (runScanComplete && runState && budget.deleted < budget.maxDeletes && budget.scanned < budget.maxEntries) {
		const refsRoot = join(root, "refs");
		if (!completedRunOwnerPrunes.has(refsRoot))
			pruneRunReferenceOwners(refsRoot, nowMs, budget, runState.hashes, mutation);
		if (
			completedRunOwnerPrunes.has(refsRoot) &&
			!completedReferencePrunes.has(refsRoot) &&
			budget.deleted < budget.maxDeletes &&
			budget.scanned < budget.maxEntries
		)
			pruneReferences(refsRoot, nowMs, budget, mutation);
	}
	if (
		runScanComplete &&
		runState &&
		!runState.unsafeForCas &&
		budget.uncertainties.length === 0 &&
		budget.deleted < budget.maxDeletes &&
		budget.scanned < budget.maxEntries
	) {
		const markKey = join(root, "retention-mark-v1");
		let marked = completedCasMarks.get(markKey) ?? loadPersistedMark(root);
		if (marked && !completedCasMarks.has(markKey)) completedCasMarks.set(markKey, marked);
		if (!marked) {
			const mark = advanceCasMark(
				markKey,
				[runRoot, incidentRoot, join(root, "refs")],
				budget,
				leaseBoundaryMs ?? Number.POSITIVE_INFINITY,
			);
			if (mark.complete && !mark.uncertain && mark.marked) {
				marked = mark.marked;
				if (!options.recoveryOnly) persistCompletedMark(root, marked, mutation);
				completedCasMarks.set(markKey, marked);
			}
		}
		if (
			marked &&
			budget.uncertainties.length === 0 &&
			budget.deleted < budget.maxDeletes &&
			budget.scanned < budget.maxEntries
		) {
			if (advanceCasSweep(join(root, "cas", "sha256"), nowMs, budget, marked, mutation)) {
				completedCasMarks.delete(markKey);
				if (!options.recoveryOnly) removePersistedMark(root, mutation);
				const refsRoot = join(root, "refs");
				completedReferencePrunes.delete(refsRoot);
				completedRunOwnerPrunes.delete(refsRoot);
			}
		}
	}
	if (runScanComplete && runState && (runState.unsafeForCas || budget.uncertainties.length > 0))
		invalidateCompletedReferencePruneGeneration(join(root, "refs"));
	let segmentPruneProtection = buildingSegmentProtection(root);
	if (
		incidentScanComplete &&
		runScanComplete &&
		runState &&
		!incidentState.segmentProtection.uncertain &&
		!runState.segmentProtection.uncertain &&
		!budget.moreWork &&
		budget.deleted < budget.maxDeletes &&
		budget.scanned < budget.maxEntries &&
		budget.uncertainties.length === 0
	) {
		const protectedRunIds = new Set<string>(incidentState.segmentProtection.protectedRunIds);
		for (const runId of runState.segmentProtection.protectedRunIds) protectedRunIds.add(runId);
		segmentPruneProtection = completeSegmentProtection(root, protectedRunIds);
	}
	return {
		state: "completed",
		scannedEntries: budget.scanned,
		deletedEntries: budget.deleted,
		moreWork: budget.moreWork || budget.deleted >= budget.maxDeletes || budget.scanned >= budget.maxEntries,
		uncertainties: [...new Set(budget.uncertainties)],
		protectedActiveRuns,
		pendingIncident,
		segmentPruneProtection,
	};
}

export function runIncidentRetentionPass(options: IncidentRetentionOptions): IncidentRetentionResult {
	const root = join(options.agentDir, "incident-recorder");
	const unavailable = (reason: IncidentRetentionResult["unavailableReason"]): IncidentRetentionResult => ({
		state: "unavailable",
		unavailableReason: reason,
		scannedEntries: 0,
		deletedEntries: 0,
		moreWork: true,
		uncertainties: reason ? [reason] : [],
		protectedActiveRuns: [],
		pendingIncident: false,
		segmentPruneProtection: buildingSegmentProtection(root),
	});
	if (!options.writerLifecycleLease) return unavailable("writer_lifecycle_lease_required");
	const leaseMode = inspectIncidentRecorderWriterLifecycleLeaseMode(options.writerLifecycleLease);
	if (!leaseMode) return unavailable("writer_lifecycle_lease_released");
	if (options.recoveryOnly && leaseMode !== "recovery") return unavailable("writer_lifecycle_recovery_conflict");
	if (!options.recoveryOnly && leaseMode !== "normal") return unavailable("writer_lifecycle_recovery_conflict");
	if (options.deadlineMs !== undefined) {
		if (!Number.isFinite(options.deadlineMs) || options.deadlineMs < 0)
			throw new Error("Invalid incident retention deadline");
		if (Date.now() >= options.deadlineMs)
			return {
				state: "completed",
				scannedEntries: 0,
				deletedEntries: 0,
				moreWork: true,
				uncertainties: [],
				protectedActiveRuns: [],
				pendingIncident: false,
				segmentPruneProtection: buildingSegmentProtection(root),
			};
	}
	const mutationResult = options.writerLifecycleLease.withNamespace((roots) => {
		const expectedRecorderRoot = canonicalPath(root);
		const expectedIncidentsRoot = canonicalPath(join(options.agentDir, "incidents"));
		const scopedRecorderRoot = capabilityRootPath(roots.recorder);
		const scopedIncidentsRoot = capabilityRootPath(roots.incidents);
		if (
			expectedRecorderRoot === undefined ||
			expectedIncidentsRoot === undefined ||
			scopedRecorderRoot !== expectedRecorderRoot ||
			scopedIncidentsRoot !== expectedIncidentsRoot
		)
			return unavailable("writer_lifecycle_namespace_changed");
		return runIncidentRetentionPassOwned(options, {
			recorder: roots.recorder,
			incidents: roots.incidents,
			recorderRoot: scopedRecorderRoot,
			incidentsRoot: scopedIncidentsRoot,
		});
	});
	if (mutationResult.state === "committed") return mutationResult.value;
	if (mutationResult.reason === "released") return unavailable("writer_lifecycle_lease_released");
	if (mutationResult.reason === "lease_lost") return unavailable("writer_lifecycle_lease_lost");
	if (mutationResult.reason === "namespace_changed" || mutationResult.reason === "root_detached")
		return unavailable("writer_lifecycle_namespace_changed");
	return unavailable("writer_lifecycle_unavailable");
}
