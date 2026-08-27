import { createHash } from "node:crypto";
import {
	closeSync,
	type Dir,
	existsSync,
	constants as fsConstants,
	fstatSync,
	linkSync,
	lstatSync,
	mkdirSync,
	opendirSync,
	openSync,
	readSync,
	renameSync,
	rmdirSync,
	type Stats,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { acquireIncidentCasTransaction } from "./incident-recorder-cas-transaction.js";

export const INCIDENT_DIAGNOSTIC_RETENTION_MS = 3 * 24 * 60 * 60 * 1_000;
export const INCIDENT_RETENTION_SERVICE_BUDGET = { maxEntries: 64, maxDeletes: 16 } as const;
const ACTIVE_MARKER = ".recorder-active";
const TERMINAL_MARKER = ".retention-terminal.json";
const GC_PREFIX = ".retention-gc-";
const MAX_METADATA_BYTES = 1024 * 1024;
const CAS_NAME = /^([0-9a-f]{64})(?:\.collision-[A-Za-z0-9_.+-]+)?\.blob$/;

export interface IncidentRetentionOptions {
	agentDir: string;
	nowMs?: number;
	maxEntries?: number;
	maxDeletes?: number;
	machineId?: string;
	bootId?: string;
	processIdentity?: (pid: number) => { state: "live"; startId: string } | { state: "dead" } | { state: "uncertain" };
}

export interface IncidentRetentionResult {
	scannedEntries: number;
	deletedEntries: number;
	moreWork: boolean;
	uncertainties: string[];
	protectedActiveRuns: string[];
	pendingIncident: boolean;
}

interface Budget {
	scanned: number;
	deleted: number;
	maxEntries: number;
	maxDeletes: number;
	moreWork: boolean;
	uncertainties: string[];
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

function smallJson(path: string): { state: SmallRead["state"]; value?: Record<string, unknown> } {
	const read = boundedRead(path);
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

function readDirBounded(path: string, budget: Budget, visit: (name: string, stat: Stats) => void): void {
	let directory: Dir | undefined;
	try {
		directory = opendirSync(path);
		for (;;) {
			if (budget.scanned >= budget.maxEntries) {
				budget.moreWork = true;
				return;
			}
			const entry = directory.readSync();
			if (!entry) return;
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
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`directory:${path}`);
	} finally {
		try {
			directory?.closeSync();
		} catch {}
	}
}

const resumableDirectories = new Map<string, Dir>();
const incidentScanStates = new Map<string, { protectedRuns: Set<string>; pending: boolean }>();
const runScanStates = new Map<string, { hashes: Set<string>; activeRuns: Set<string>; unsafeForCas: boolean }>();

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

function createTreeWalk(root: string): TreeWalkState {
	try {
		return { root, stack: [{ path: root, directory: opendirSync(root) }], complete: false };
	} catch (error) {
		return { root, stack: [], complete: (error as NodeJS.ErrnoException).code === "ENOENT" };
	}
}

function nextTreeFile(state: TreeWalkState, budget: Budget): { path: string; stat: Stats } | undefined {
	while (state.stack.length > 0) {
		if (budget.scanned >= budget.maxEntries) {
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
			if (budget.scanned >= budget.maxEntries || budget.deleted >= budget.maxDeletes) {
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

function parseWallTime(value: unknown): number | undefined {
	if (typeof value === "number" && Number.isSafeInteger(value)) return value;
	if (typeof value === "string") {
		const parsed = Date.parse(value);
		if (Number.isFinite(parsed)) return parsed;
	}
	if (value && typeof value === "object" && !Array.isArray(value))
		return parseWallTime((value as Record<string, unknown>).wallTime);
	return undefined;
}

function runProtection(
	path: string,
	machineId: string,
	bootId: string,
	identity: NonNullable<IncidentRetentionOptions["processIdentity"]>,
): "active" | "inactive" | "uncertain" {
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
	const finalized = decisionJson(join(path, ".service-finalization-complete"));
	if (finalized.state === "uncertain") return "uncertain";
	if (finalized.state === "ok")
		return parseWallTime(finalized.value?.completed) === undefined ? "uncertain" : "inactive";
	const terminal = decisionJson(join(path, TERMINAL_MARKER));
	if (terminal.state !== "ok") return "uncertain";
	const completeWithoutIncident =
		(terminal.value?.exitCode === 0 && terminal.value.exitSignal === null) ||
		terminal.value?.disposition === "spawn_failed_before_target_identity";
	return completeWithoutIncident && parseWallTime(terminal.value?.completed) !== undefined ? "inactive" : "uncertain";
}

function runExpired(path: string, nowMs: number): boolean | undefined {
	const finalized = decisionJson(join(path, ".service-finalization-complete"));
	if (finalized.state === "uncertain") return undefined;
	if (finalized.state === "ok") {
		const completed = parseWallTime(finalized.value?.completed);
		return completed === undefined ? undefined : nowMs - completed >= INCIDENT_DIAGNOSTIC_RETENTION_MS;
	}
	const terminal = decisionJson(join(path, TERMINAL_MARKER));
	if (terminal.state !== "ok") return undefined;
	const completeWithoutIncident =
		(terminal.value?.exitCode === 0 && terminal.value.exitSignal === null) ||
		terminal.value?.disposition === "spawn_failed_before_target_identity";
	if (!completeWithoutIncident) return undefined;
	const completed = parseWallTime(terminal.value?.completed);
	return completed === undefined ? undefined : nowMs - completed >= INCIDENT_DIAGNOSTIC_RETENTION_MS;
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

function decisionJson(path: string): { state: SmallRead["state"]; value?: Record<string, unknown> } {
	const result = smallJson(path);
	if (result.state === "ok" && !privateDecisionMetadata(path)) return { state: "uncertain" };
	return result;
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

function incidentDisposition(path: string, nowMs: number): "retain" | "delete" | "pending" | "uncertain" {
	const summary = decisionJson(join(path, "summary.json"));
	if (summary.state !== "ok") return summary.state === "missing" ? "pending" : "uncertain";
	if (summary.value?.stoppedTargetCaptureComplete !== true) return "pending";
	const finalized = parseWallTime(summary.value.finalized);
	if (finalized === undefined) return "uncertain";
	let retainUntil = finalized + INCIDENT_DIAGNOSTIC_RETENTION_MS;
	for (const provider of ["journal", "sysdig"] as const) {
		const request = decisionJson(join(path, `${provider}-pin-request.json`));
		if (request.state === "uncertain") return "uncertain";
		if (request.state === "missing") continue;
		const runId = request.value?.runId;
		const anchor = parseWallTime(request.value?.anchorWallTimeMs);
		const from = parseWallTime(request.value?.fromWallTimeMs);
		const through = parseWallTime(request.value?.throughWallTimeMs);
		const resolveAfter = parseWallTime(request.value?.resolveAfterWallTimeMs);
		const explicitRetainUntil = parseWallTime(request.value?.retainUntilWallTimeMs);
		const policyRetainUntil = anchor === undefined ? undefined : anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS;
		const requestedRetainUntil =
			policyRetainUntil === undefined
				? undefined
				: explicitRetainUntil === undefined
					? policyRetainUntil
					: Math.min(explicitRetainUntil, policyRetainUntil);
		if (
			typeof runId !== "string" ||
			!runId ||
			anchor === undefined ||
			from === undefined ||
			through === undefined ||
			resolveAfter === undefined ||
			requestedRetainUntil === undefined ||
			through !== resolveAfter
		)
			return "uncertain";
		retainUntil = Math.max(retainUntil, requestedRetainUntil);
		if (nowMs < resolveAfter) return "pending";
		const proofPath = join(path, `${provider}-pin-retention-proof.json`);
		const proof = decisionJson(proofPath);
		if (proof.state === "uncertain") return "uncertain";
		if (proof.state === "ok") {
			if (!privateDecisionMetadata(proofPath)) return "uncertain";
			if (
				proof.value?.version !== 1 ||
				proof.value.state !== "producer_verified_complete" ||
				proof.value.provider !== provider ||
				proof.value.manifestValidated !== true ||
				proof.value.runId !== runId ||
				parseWallTime(proof.value.fromWallTimeMs) !== from ||
				parseWallTime(proof.value.throughWallTimeMs) !== through ||
				parseWallTime(proof.value.retainUntilWallTimeMs) !== (explicitRetainUntil ?? requestedRetainUntil) ||
				![INCIDENT_DIAGNOSTIC_RETENTION_MS, 14 * 24 * 60 * 60 * 1_000].includes(
					Number(proof.value.retentionMilliseconds),
				) ||
				(provider === "journal" &&
					(!Number.isSafeInteger(proof.value.occurrenceCount) ||
						Number(proof.value.occurrenceCount) < 0 ||
						Number(proof.value.occurrenceCount) > 8_192)) ||
				(provider === "sysdig" &&
					(!Number.isSafeInteger(proof.value.segmentCount) ||
						Number(proof.value.segmentCount) < 0 ||
						Number(proof.value.segmentCount) > 32))
			)
				return "uncertain";
			const manifestPath = join(path, `${provider}-pin-manifest.json`);
			const pinDirectoryPath = join(path, provider === "journal" ? "journal-pins/cas" : "sysdig-pins/segments");
			const pinDirectoryIdentity = proof.value.pinDirectoryIdentity;
			if (
				!retentionIdentityMatches(manifestPath, proof.value.manifestIdentity, false) ||
				!retentionIdentityMatches(pinDirectoryPath, pinDirectoryIdentity, true) ||
				!pinDirectoryIdentity ||
				typeof pinDirectoryIdentity !== "object" ||
				Array.isArray(pinDirectoryIdentity) ||
				(pinDirectoryIdentity as Record<string, unknown>).path !==
					(provider === "journal" ? "journal-pins/cas" : "sysdig-pins/segments")
			)
				return "uncertain";
			continue;
		}
		const incomplete = decisionJson(join(path, `${provider}-pin-incomplete.json`));
		if (incomplete.state === "uncertain") return "uncertain";
		if (incomplete.state === "ok") {
			if (nowMs >= retainUntil) continue;
			return "pending";
		}
		const manifest = decisionJson(join(path, `${provider}-pin-manifest.json`));
		if (manifest.state === "missing") {
			if (nowMs >= retainUntil) continue;
			return "pending";
		}
		if (manifest.state !== "ok") return "uncertain";
		if (manifest.value?.runId !== runId) return "uncertain";
		if (provider === "journal") {
			const occurrences = manifest.value.occurrences;
			if (
				manifest.value.state !== "complete_through_requested_window" ||
				parseWallTime(manifest.value.fromWallTimeMs) !== from ||
				parseWallTime(manifest.value.throughWallTimeMs) !== through ||
				!Array.isArray(occurrences) ||
				!occurrences.every((occurrence) => {
					if (!occurrence || typeof occurrence !== "object" || Array.isArray(occurrence)) return false;
					const record = occurrence as Record<string, unknown>;
					const cas = record.cas;
					if (!cas || typeof cas !== "object" || Array.isArray(cas) || typeof record.pinnedCasPath !== "string")
						return false;
					const digest = (cas as Record<string, unknown>).digest;
					const bytes = (cas as Record<string, unknown>).bytes;
					if (
						typeof digest !== "string" ||
						!/^[0-9a-f]{64}$/.test(digest) ||
						!Number.isSafeInteger(bytes) ||
						Number(bytes) < 0
					)
						return false;
					try {
						const stat = statSync(record.pinnedCasPath);
						return stat.isFile() && stat.size === bytes;
					} catch {
						return false;
					}
				})
			)
				return "uncertain";
		} else {
			const retention = manifest.value.retention;
			const segments = manifest.value.segments;
			if (
				manifest.value.state !== "finalized_with_observed_coverage" ||
				!Array.isArray(segments) ||
				!retention ||
				typeof retention !== "object" ||
				Array.isArray(retention) ||
				![INCIDENT_DIAGNOSTIC_RETENTION_MS, 14 * 24 * 60 * 60 * 1_000].includes(
					Number((retention as Record<string, unknown>).milliseconds),
				) ||
				parseWallTime((retention as Record<string, unknown>).retainUntilWallTimeMs) !==
					(explicitRetainUntil ?? requestedRetainUntil) ||
				!segments.every((segment) => {
					if (!segment || typeof segment !== "object" || Array.isArray(segment)) return false;
					const record = segment as Record<string, unknown>;
					const exact = record.exactBytes;
					if (typeof record.pinnedPath !== "string" || !exact || typeof exact !== "object" || Array.isArray(exact))
						return false;
					const bytes = (exact as Record<string, unknown>).bytes;
					const digest = (exact as Record<string, unknown>).sha256;
					if (
						!Number.isSafeInteger(bytes) ||
						Number(bytes) < 0 ||
						typeof digest !== "string" ||
						!/^[0-9a-f]{64}$/.test(digest)
					)
						return false;
					try {
						const stat = statSync(record.pinnedPath);
						return stat.isFile() && stat.size === bytes;
					} catch {
						return false;
					}
				})
			)
				return "uncertain";
		}
	}
	return nowMs >= retainUntil ? "delete" : "retain";
}

function tombstone(path: string): string | undefined {
	const target = join(join(path, ".."), `${GC_PREFIX}${basename(path)}`);
	try {
		renameSync(path, target);
		return target;
	} catch {
		return undefined;
	}
}

function removeTreeIncremental(path: string, budget: Budget, depth = 0): void {
	if (depth > 16) {
		budget.uncertainties.push(`delete-depth:${path}`);
		return;
	}
	if (budget.deleted >= budget.maxDeletes || budget.scanned >= budget.maxEntries) {
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
	if (!stat.isDirectory()) {
		try {
			unlinkSync(path);
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
			if (budget.deleted >= budget.maxDeletes || budget.scanned >= budget.maxEntries) {
				budget.moreWork = true;
				return;
			}
			const entry = directory.readSync();
			if (!entry) break;
			removeTreeIncremental(join(path, entry.name), budget, depth + 1);
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
		rmdirSync(path);
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
			removeTreeIncremental(path, budget);
			return;
		}
		if (kind === "incident" && name.startsWith(".") && name.endsWith(".partial")) {
			pendingIncident = true;
			incidentProtectedRuns.add(name.slice(1, -".partial".length));
			return;
		}
		if (kind === "run") {
			const runId = name.slice(-36);
			const runHash = /^[0-9a-f-]{36}$/i.test(runId) ? createHash("sha256").update(runId).digest("hex") : undefined;
			if (runHash) activeRunHashes.add(runHash);
			const protection = runProtection(path, machineId, bootId, identity);
			if (protection === "active") {
				protectedActiveRuns.push(name);
				runSafety.activeRuns.add(name);
				return;
			}
			if (incidentProtectedRuns.has(name)) {
				if (protection === "uncertain") {
					runSafety.unsafeForCas = true;
					budget.uncertainties.push(`run-identity:${path}`);
				}
				return;
			}
			if (protection === "uncertain") {
				runSafety.unsafeForCas = true;
				budget.uncertainties.push(`run-identity:${path}`);
				return;
			}
			const isExpired = runExpired(path, nowMs);
			if (isExpired === undefined) {
				budget.uncertainties.push(`run-terminal:${path}`);
				return;
			}
			if (!isExpired) return;
		} else {
			const disposition = incidentDisposition(path, nowMs);
			if (disposition === "pending") {
				pendingIncident = true;
				incidentProtectedRuns.add(name);
				return;
			}
			if (disposition === "uncertain") {
				incidentProtectedRuns.add(name);
				budget.uncertainties.push(`incident-state:${path}`);
				return;
			}
			if (disposition === "retain") {
				incidentProtectedRuns.add(name);
				return;
			}
		}
		if (kind === "run") {
			const runId = name.slice(-36);
			if (/^[0-9a-f-]{36}$/i.test(runId)) activeRunHashes.delete(createHash("sha256").update(runId).digest("hex"));
		}
		const renamed = tombstone(path);
		if (!renamed) {
			budget.uncertainties.push(`rename-for-delete:${path}`);
			return;
		}
		removeTreeIncremental(renamed, budget);
	});
	return pendingIncident;
}

function pruneRunReferenceOwners(root: string, nowMs: number, budget: Budget, retainedRunHashes: Set<string>): void {
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
			removeTreeIncremental(path, budget);
			return;
		}
		if (retainedRunHashes.has(name) || !expired(stat, nowMs)) return;
		const renamed = tombstone(path);
		if (!renamed) {
			budget.uncertainties.push(`rename-run-ref-owner:${path}`);
			return;
		}
		removeTreeIncremental(renamed, budget);
	});
	if (!resumableDirectories.has(ownersRoot)) completedRunOwnerPrunes.add(root);
}

function pruneReferences(root: string, nowMs: number, budget: Budget, activeRunHashes: Set<string>): void {
	let state = referenceWalkStates.get(root);
	if (!state || state.complete) {
		state = createTreeWalk(root);
		referenceWalkStates.set(root, state);
	}
	while (!state.complete && budget.deleted < budget.maxDeletes && budget.scanned < budget.maxEntries) {
		const entry = nextTreeFile(state, budget);
		if (!entry) break;
		if (!entry.stat.isFile() || !expired(entry.stat, nowMs)) continue;
		const relative = entry.path.slice(root.length + 1).split("/");
		if (relative[0] === "runs") continue;
		try {
			unlinkSync(entry.path);
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
	if (!file || budget.scanned >= budget.maxEntries) return;
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
	while (budget.scanned < budget.maxEntries) {
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

function advanceCasSweep(root: string, nowMs: number, budget: Budget, marked: Set<string>): boolean {
	let state = casSweepStates.get(root);
	if (!state || state.complete) {
		state = createTreeWalk(root);
		casSweepStates.set(root, state);
	}
	while (!state.complete && budget.deleted < budget.maxDeletes && budget.scanned < budget.maxEntries) {
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
		let descriptor: number | undefined;
		let parentDescriptor: number | undefined;
		try {
			const parentPath = dirname(entry.path);
			const parentBefore = lstatSync(parentPath);
			if (!parentBefore.isDirectory() || parentBefore.isSymbolicLink())
				throw new Error("cas_parent_not_stable_directory");
			parentDescriptor = openSync(
				parentPath,
				fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
			);
			const openedParent = fstatSync(parentDescriptor);
			if (openedParent.dev !== parentBefore.dev || openedParent.ino !== parentBefore.ino)
				throw new Error("cas_parent_identity_changed");
			const boundPath = `/proc/self/fd/${parentDescriptor}/${basename(entry.path)}`;
			descriptor = openSync(boundPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
			const current = fstatSync(descriptor);
			const parentNow = lstatSync(parentPath);
			if (
				!current.isFile() ||
				current.dev !== entry.stat.dev ||
				current.ino !== entry.stat.ino ||
				current.nlink !== 1 ||
				parentNow.dev !== openedParent.dev ||
				parentNow.ino !== openedParent.ino ||
				!expired(current, nowMs)
			)
				continue;
			unlinkSync(boundPath);
			budget.deleted += 1;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`cas-delete:${entry.path}`);
		} finally {
			if (descriptor !== undefined)
				try {
					closeSync(descriptor);
				} catch {}
			if (parentDescriptor !== undefined)
				try {
					closeSync(parentDescriptor);
				} catch {}
		}
	}
	if (state.complete) casSweepStates.delete(root);
	return state.complete;
}

function ensureLeaseProtocolBoundary(root: string, nowMs: number): number | undefined {
	const path = join(root, "lease-protocol-v1.json");
	let record = decisionJson(path);
	if (record.state === "missing") {
		mkdirSync(root, { recursive: true, mode: 0o700 });
		const temporary = `${path}.tmp-${process.pid}-${process.hrtime.bigint()}`;
		try {
			writeFileSync(
				temporary,
				`${JSON.stringify({ version: 1, state: "active", activatedAtWallTimeMs: nowMs, protocol: "cas-hard-link-lease-before-reference" })}
`,
				{ mode: 0o600, flag: "wx" },
			);
			try {
				linkSync(temporary, path);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			}
		} finally {
			try {
				unlinkSync(temporary);
			} catch {}
		}
		// A completed mark from a pre-lease implementation cannot classify the
		// new protocol boundary. Discard it; incomplete generations never sweep.
		removePersistedMark(root);
		record = decisionJson(path);
	}
	const activated = record.state === "ok" ? record.value?.activatedAtWallTimeMs : undefined;
	return record.state === "ok" &&
		record.value?.version === 1 &&
		record.value.state === "active" &&
		record.value.protocol === "cas-hard-link-lease-before-reference" &&
		Number.isSafeInteger(activated)
		? Number(activated)
		: undefined;
}

function persistedMarkPaths(root: string): { directory: string; log: string; proof: string } {
	const directory = join(root, "retention");
	return {
		directory,
		log: join(directory, "legacy-marks-v1.log"),
		proof: join(directory, "legacy-marks-v1-complete.json"),
	};
}

function persistCompletedMark(root: string, marked: Set<string>): void {
	const paths = persistedMarkPaths(root);
	mkdirSync(paths.directory, { recursive: true, mode: 0o700 });
	const logBytes = Buffer.from(`${[...marked].sort().join("\n")}\n`, "utf8");
	const suffix = `${process.pid}-${process.hrtime.bigint()}`;
	const temporaryLog = `${paths.log}.tmp-${suffix}`;
	const temporaryProof = `${paths.proof}.tmp-${suffix}`;
	writeFileSync(temporaryLog, logBytes, { mode: 0o600, flag: "wx" });
	renameSync(temporaryLog, paths.log);
	writeFileSync(
		temporaryProof,
		`${JSON.stringify({
			version: 1,
			state: "complete",
			count: marked.size,
			bytes: logBytes.length,
			sha256: createHash("sha256").update(logBytes).digest("hex"),
		})}\n`,
		{ mode: 0o600, flag: "wx" },
	);
	renameSync(temporaryProof, paths.proof);
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

function removePersistedMark(root: string): void {
	const paths = persistedMarkPaths(root);
	for (const path of [paths.proof, paths.log])
		try {
			unlinkSync(path);
		} catch {}
}

function runIncidentRetentionPassOwned(options: IncidentRetentionOptions): IncidentRetentionResult {
	const nowMs = options.nowMs ?? Date.now();
	const budget: Budget = {
		scanned: 0,
		deleted: 0,
		maxEntries: Math.max(1, Math.min(options.maxEntries ?? 16_384, 65_536)),
		maxDeletes: Math.max(1, Math.min(options.maxDeletes ?? 256, 1024)),
		moreWork: false,
		uncertainties: [],
	};
	const root = join(options.agentDir, "incident-recorder");
	const machineId = options.machineId ?? defaultMachineId();
	const bootId = options.bootId ?? defaultBootId();
	const identity = options.processIdentity ?? defaultProcessIdentity;
	const leaseBoundaryMs = ensureLeaseProtocolBoundary(root, nowMs);
	if (leaseBoundaryMs === undefined) budget.uncertainties.push("lease-protocol-boundary-unavailable");
	const protectedActiveRuns: string[] = [];
	const incidentRoot = join(options.agentDir, "incidents");
	let incidentState = incidentScanStates.get(incidentRoot);
	if (!incidentState || !resumableDirectories.has(incidentRoot)) {
		incidentState = { protectedRuns: new Set<string>(), pending: false };
		incidentScanStates.set(incidentRoot, incidentState);
	}
	const incidentSafety = { activeRuns: new Set<string>(), unsafeForCas: false };
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
		) || incidentState.pending;
	const incidentScanComplete = !resumableDirectories.has(incidentRoot);
	const pendingIncident = incidentState.pending;
	const runRoot = join(root, "runs");
	let runState = runScanStates.get(runRoot);
	if (incidentScanComplete && (!runState || !resumableDirectories.has(runRoot))) {
		runState = { hashes: new Set<string>(), activeRuns: new Set<string>(), unsafeForCas: false };
		runScanStates.set(runRoot, runState);
	}
	if (incidentScanComplete && runState) {
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
		);
	}
	const runScanComplete = incidentScanComplete && !resumableDirectories.has(runRoot);
	if (runScanComplete && runState) protectedActiveRuns.splice(0, protectedActiveRuns.length, ...runState.activeRuns);
	if (runScanComplete && runState && budget.deleted < budget.maxDeletes && budget.scanned < budget.maxEntries) {
		const refsRoot = join(root, "refs");
		if (!completedRunOwnerPrunes.has(refsRoot)) pruneRunReferenceOwners(refsRoot, nowMs, budget, runState.hashes);
		if (
			completedRunOwnerPrunes.has(refsRoot) &&
			!completedReferencePrunes.has(refsRoot) &&
			budget.deleted < budget.maxDeletes &&
			budget.scanned < budget.maxEntries
		)
			pruneReferences(refsRoot, nowMs, budget, runState.hashes);
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
				persistCompletedMark(root, marked);
				completedCasMarks.set(markKey, marked);
			}
		}
		if (
			marked &&
			budget.uncertainties.length === 0 &&
			budget.deleted < budget.maxDeletes &&
			budget.scanned < budget.maxEntries
		) {
			if (advanceCasSweep(join(root, "cas", "sha256"), nowMs, budget, marked)) {
				completedCasMarks.delete(markKey);
				removePersistedMark(root);
				const refsRoot = join(root, "refs");
				completedReferencePrunes.delete(refsRoot);
				completedRunOwnerPrunes.delete(refsRoot);
			}
		}
	}
	return {
		scannedEntries: budget.scanned,
		deletedEntries: budget.deleted,
		moreWork: budget.moreWork || budget.deleted >= budget.maxDeletes || budget.scanned >= budget.maxEntries,
		uncertainties: [...new Set(budget.uncertainties)],
		protectedActiveRuns,
		pendingIncident,
	};
}

export function runIncidentRetentionPass(options: IncidentRetentionOptions): IncidentRetentionResult {
	const transaction = acquireIncidentCasTransaction(join(options.agentDir, "incident-recorder"));
	if (!transaction)
		return {
			scannedEntries: 0,
			deletedEntries: 0,
			moreWork: true,
			uncertainties: ["cas-transaction-unavailable"],
			protectedActiveRuns: [],
			pendingIncident: false,
		};
	try {
		return runIncidentRetentionPassOwned(options);
	} finally {
		transaction.release();
	}
}
