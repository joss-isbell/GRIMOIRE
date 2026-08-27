import { createHash } from "node:crypto";
import {
	closeSync,
	type Dir,
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
const RETENTION_TREE_MAX_DEPTH = 64;
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
		const beforeOpen = lstatSync(path, { bigint: true });
		if (!beforeOpen.isFile() || beforeOpen.isSymbolicLink()) return { state: "uncertain" };
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const stat = fstatSync(descriptor, { bigint: true });
		if (
			stat.dev !== beforeOpen.dev ||
			stat.ino !== beforeOpen.ino ||
			stat.size !== beforeOpen.size ||
			stat.mtimeNs !== beforeOpen.mtimeNs ||
			stat.ctimeNs !== beforeOpen.ctimeNs ||
			!stat.isFile() ||
			stat.size < 0n ||
			stat.size > BigInt(maximum)
		)
			return { state: "uncertain" };
		const value = Buffer.alloc(Number(stat.size));
		let offset = 0;
		while (offset < value.length) {
			const count = readSync(descriptor, value, offset, value.length - offset, offset);
			if (count <= 0) return { state: "uncertain" };
			offset += count;
		}
		const after = fstatSync(descriptor, { bigint: true });
		if (
			after.dev !== stat.dev ||
			after.ino !== stat.ino ||
			after.size !== stat.size ||
			after.mtimeNs !== stat.mtimeNs ||
			after.ctimeNs !== stat.ctimeNs
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

interface BoundDirectoryFrame {
	path: string;
	descriptor: number;
	directory: Dir;
}

const resumableDirectories = new Map<string, BoundDirectoryFrame>();
const incidentScanStates = new Map<string, { protectedRuns: Set<string>; pending: boolean }>();
const runScanStates = new Map<string, { hashes: Set<string>; activeRuns: Set<string>; unsafeForCas: boolean }>();

interface TreeWalkState {
	root: string;
	stack: BoundDirectoryFrame[];
	complete: boolean;
	openUncertain?: boolean;
}
interface CasMarkState extends TreeWalkState {
	marked: Set<string>;
	uncertain: boolean;
	currentFile?: {
		path: string;
		descriptor: number;
		offset: number;
		size: bigint;
		dev: bigint;
		ino: bigint;
		mtimeNs: bigint;
		ctimeNs: bigint;
		carry: string;
	};
	leaseBoundaryMs: number;
}
const referenceWalkStates = new Map<string, TreeWalkState>();
const completedReferencePrunes = new Set<string>();
const completedRunOwnerPrunes = new Set<string>();
const casMarkStates = new Map<string, CasMarkState>();
const casSweepStates = new Map<string, TreeWalkState>();
const legacySysdigOwnerSweepStates = new Map<string, TreeWalkState>();

function createBoundDirectoryFrame(openPath: string, displayPath = openPath, expected?: Stats): BoundDirectoryFrame {
	const descriptor = openStableDirectory(openPath, expected);
	try {
		return { path: displayPath, descriptor, directory: opendirSync(`/proc/self/fd/${descriptor}`) };
	} catch (error) {
		closeSync(descriptor);
		throw error;
	}
}

function closeBoundDirectoryFrame(frame: BoundDirectoryFrame): void {
	try {
		frame.directory.closeSync();
	} catch {}
	try {
		closeSync(frame.descriptor);
	} catch {}
}

function closeTreeWalkState(state: TreeWalkState): void {
	for (const frame of state.stack.splice(0)) closeBoundDirectoryFrame(frame);
}

function discardTreeWalk(map: Map<string, TreeWalkState>, key: string): void {
	const state = map.get(key);
	if (state) closeTreeWalkState(state);
	map.delete(key);
}

function createTreeWalk(root: string): TreeWalkState {
	try {
		return { root, stack: [createBoundDirectoryFrame(root)], complete: false };
	} catch (error) {
		return {
			root,
			stack: [],
			complete: (error as NodeJS.ErrnoException).code === "ENOENT",
			openUncertain: (error as NodeJS.ErrnoException).code !== "ENOENT",
		};
	}
}

function nextTreeFile(
	state: TreeWalkState,
	budget: Budget,
): { path: string; name: string; parentDescriptor: number; stat: Stats } | undefined {
	if (state.openUncertain) {
		state.openUncertain = false;
		state.complete = true;
		budget.uncertainties.push(`walk-open:${state.root}`);
		return undefined;
	}
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
			closeTreeWalkState(state);
			state.complete = true;
			return undefined;
		}
		if (!entry) {
			closeBoundDirectoryFrame(frame);
			state.stack.pop();
			continue;
		}
		budget.scanned += 1;
		const path = join(frame.path, entry.name);
		let boundPath: string;
		let stat: Stats;
		try {
			boundPath = boundEntryPath(frame.descriptor, entry.name);
			stat = lstatSync(boundPath);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`walk-stat:${path}`);
			continue;
		}
		if (stat.isSymbolicLink()) {
			budget.uncertainties.push(`walk-symlink:${path}`);
			continue;
		}
		if (stat.isDirectory()) {
			if (state.stack.length >= RETENTION_TREE_MAX_DEPTH) {
				budget.uncertainties.push(`walk-depth:${path}`);
				return undefined;
			}
			try {
				state.stack.push(createBoundDirectoryFrame(boundPath, path, stat));
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`walk-open:${path}`);
			}
			continue;
		}
		return { path, name: entry.name, parentDescriptor: frame.descriptor, stat };
	}
	state.complete = true;
	return undefined;
}

function readDirResumable(
	path: string,
	budget: Budget,
	visit: (name: string, stat: Stats, parentDescriptor: number) => void,
): void {
	let frame = resumableDirectories.get(path);
	try {
		if (!frame) {
			frame = createBoundDirectoryFrame(path);
			resumableDirectories.set(path, frame);
		}
		for (;;) {
			if (budget.scanned >= budget.maxEntries || budget.deleted >= budget.maxDeletes) {
				budget.moreWork = true;
				return;
			}
			const entry = frame.directory.readSync();
			if (!entry) {
				closeBoundDirectoryFrame(frame);
				resumableDirectories.delete(path);
				return;
			}
			budget.scanned += 1;
			let stat: Stats;
			try {
				stat = lstatSync(boundEntryPath(frame.descriptor, entry.name));
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT")
					budget.uncertainties.push(`stat:${path}/${entry.name}`);
				continue;
			}
			const uncertaintyCount = budget.uncertainties.length;
			visit(entry.name, stat, frame.descriptor);
			if (budget.uncertainties.length > uncertaintyCount) {
				closeBoundDirectoryFrame(frame);
				resumableDirectories.delete(path);
				budget.moreWork = true;
				return;
			}
		}
	} catch (error) {
		if (frame) closeBoundDirectoryFrame(frame);
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

function safeEntryName(name: string): boolean {
	return name.length > 0 && name !== "." && name !== ".." && basename(name) === name && !name.includes("\0");
}

function sameIdentity(left: Stats, right: Stats): boolean {
	return left.dev === right.dev && left.ino === right.ino;
}

function openStableDirectory(path: string, expected?: Stats): number {
	const before = lstatSync(path);
	if (!before.isDirectory() || before.isSymbolicLink() || (expected && !sameIdentity(before, expected)))
		throw new Error("directory_identity_invalid");
	const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
	const opened = fstatSync(descriptor);
	if (!opened.isDirectory() || !sameIdentity(opened, before)) {
		closeSync(descriptor);
		throw new Error("directory_identity_changed");
	}
	return descriptor;
}

// Node does not expose unlinkat(2). On Linux/WSL, /proc/self/fd keeps every
// retention lookup and mutation relative to the directory descriptor we opened.
function boundEntryPath(parentDescriptor: number, name: string): string {
	if (!safeEntryName(name)) throw new Error("entry_name_invalid");
	return `/proc/self/fd/${parentDescriptor}/${name}`;
}

function tombstone(
	path: string,
	expected: Stats,
	budget: Budget,
	retainedParentDescriptor?: number,
): string | undefined {
	const parentPath = dirname(path);
	const name = basename(path);
	const boundName = /^\.retention-gc-(\d+)-(\d+)-[0-9a-f]{16}$/.exec(name);
	const alreadyBound = boundName?.[1] === String(expected.dev) && boundName[2] === String(expected.ino);
	const identityToken = createHash("sha256").update(name).digest("hex").slice(0, 16);
	const targetName = alreadyBound ? name : `${GC_PREFIX}${expected.dev}-${expected.ino}-${identityToken}`;
	let parentDescriptor = retainedParentDescriptor;
	let ownsParentDescriptor = false;
	try {
		if (parentDescriptor === undefined) {
			parentDescriptor = openStableDirectory(parentPath);
			ownsParentDescriptor = true;
		}
		const source = boundEntryPath(parentDescriptor, name);
		const target = boundEntryPath(parentDescriptor, targetName);
		const current = lstatSync(source);
		if (!sameIdentity(current, expected) || !current.isDirectory() || current.isSymbolicLink())
			throw new Error("tombstone_source_identity_changed");
		if (name === targetName) return path;
		try {
			lstatSync(target);
			throw new Error("tombstone_target_exists");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		renameSync(source, target);
		const renamed = lstatSync(target);
		if (!sameIdentity(renamed, expected)) throw new Error("tombstone_identity_changed");
		return join(parentPath, targetName);
	} catch {
		budget.uncertainties.push(`rename-for-delete:${path}`);
		return undefined;
	} finally {
		if (ownsParentDescriptor && parentDescriptor !== undefined)
			try {
				closeSync(parentDescriptor);
			} catch {}
	}
}

function removeBoundTreeEntry(
	parentDescriptor: number,
	parentDisplayPath: string,
	name: string,
	budget: Budget,
	depth: number,
	expected?: Stats,
): void {
	const displayPath = join(parentDisplayPath, name);
	if (depth > 16) {
		budget.uncertainties.push(`delete-depth:${displayPath}`);
		return;
	}
	if (budget.deleted >= budget.maxDeletes || budget.scanned >= budget.maxEntries) {
		budget.moreWork = true;
		return;
	}
	let path: string;
	let stat: Stats;
	try {
		path = boundEntryPath(parentDescriptor, name);
		stat = lstatSync(path);
		if (expected && !sameIdentity(stat, expected)) throw new Error("delete_entry_identity_changed");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`delete-stat:${displayPath}`);
		return;
	}
	budget.scanned += 1;
	if (!stat.isDirectory() || stat.isSymbolicLink()) {
		try {
			const current = lstatSync(path);
			if (!sameIdentity(current, stat)) throw new Error("delete_file_identity_changed");
			unlinkSync(path);
			budget.deleted += 1;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT")
				budget.uncertainties.push(`delete-file:${displayPath}`);
		}
		return;
	}
	let childDescriptor: number | undefined;
	let directory: Dir | undefined;
	try {
		childDescriptor = openStableDirectory(path, stat);
		directory = opendirSync(`/proc/self/fd/${childDescriptor}`);
		for (;;) {
			if (budget.deleted >= budget.maxDeletes || budget.scanned >= budget.maxEntries) {
				budget.moreWork = true;
				return;
			}
			const entry = directory.readSync();
			if (!entry) break;
			if (!safeEntryName(entry.name)) {
				budget.uncertainties.push(`delete-name:${displayPath}`);
				continue;
			}
			removeBoundTreeEntry(childDescriptor, displayPath, entry.name, budget, depth + 1);
		}
	} catch {
		budget.uncertainties.push(`delete-directory:${displayPath}`);
		return;
	} finally {
		try {
			directory?.closeSync();
		} catch {}
		if (childDescriptor !== undefined)
			try {
				closeSync(childDescriptor);
			} catch {}
	}
	if (budget.deleted >= budget.maxDeletes) {
		budget.moreWork = true;
		return;
	}
	try {
		const current = lstatSync(path);
		if (!sameIdentity(current, stat)) throw new Error("delete_directory_identity_changed");
		rmdirSync(path);
		budget.deleted += 1;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOTEMPTY") budget.moreWork = true;
		else if ((error as NodeJS.ErrnoException).code !== "ENOENT")
			budget.uncertainties.push(`delete-rmdir:${displayPath}`);
	}
}

function unlinkBoundPath(
	path: string,
	expected: Stats,
	budget: Budget,
	label: string,
	retainedParentDescriptor?: number,
): boolean {
	let parentDescriptor = retainedParentDescriptor;
	let ownsParentDescriptor = false;
	let descriptor: number | undefined;
	try {
		if (parentDescriptor === undefined) {
			parentDescriptor = openStableDirectory(dirname(path));
			ownsParentDescriptor = true;
		}
		const bound = boundEntryPath(parentDescriptor, basename(path));
		descriptor = openSync(bound, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const current = fstatSync(descriptor);
		if (!current.isFile() || !sameIdentity(current, expected)) throw new Error("unlink_identity_changed");
		const named = lstatSync(bound);
		if (!sameIdentity(named, current)) throw new Error("unlink_name_identity_changed");
		unlinkSync(bound);
		budget.deleted += 1;
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`${label}:${path}`);
		return false;
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
		if (ownsParentDescriptor && parentDescriptor !== undefined)
			try {
				closeSync(parentDescriptor);
			} catch {}
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
	readDirResumable(root, budget, (name, stat, parentDescriptor) => {
		if (budget.deleted >= budget.maxDeletes) {
			budget.moreWork = true;
			return;
		}
		const path = join(root, name);
		const decisionPath = boundEntryPath(parentDescriptor, name);
		if (!stat.isDirectory()) {
			budget.uncertainties.push(`unexpected-artifact:${path}`);
			return;
		}
		if (name.startsWith(GC_PREFIX)) {
			const rebound = tombstone(path, stat, budget, parentDescriptor);
			if (rebound) removeBoundTreeEntry(parentDescriptor, root, basename(rebound), budget, 0, stat);
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
			const protection = runProtection(decisionPath, machineId, bootId, identity);
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
			const isExpired = runExpired(decisionPath, nowMs);
			if (isExpired === undefined) {
				budget.uncertainties.push(`run-terminal:${path}`);
				return;
			}
			if (!isExpired) return;
		} else {
			const disposition = incidentDisposition(decisionPath, nowMs);
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
		const renamed = tombstone(path, stat, budget, parentDescriptor);
		if (!renamed) return;
		removeBoundTreeEntry(parentDescriptor, root, basename(renamed), budget, 0, stat);
	});
	return pendingIncident;
}

function pruneRunReferenceOwners(root: string, nowMs: number, budget: Budget, retainedRunHashes: Set<string>): void {
	const ownersRoot = join(root, "runs");
	readDirResumable(ownersRoot, budget, (name, stat, parentDescriptor) => {
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
			const rebound = tombstone(path, stat, budget, parentDescriptor);
			if (rebound) removeBoundTreeEntry(parentDescriptor, ownersRoot, basename(rebound), budget, 0, stat);
			return;
		}
		if (retainedRunHashes.has(name) || !expired(stat, nowMs)) return;
		const renamed = tombstone(path, stat, budget, parentDescriptor);
		if (!renamed) return;
		removeBoundTreeEntry(parentDescriptor, ownersRoot, basename(renamed), budget, 0, stat);
	});
	if (!resumableDirectories.has(ownersRoot)) completedRunOwnerPrunes.add(root);
}

function pruneReferences(root: string, nowMs: number, budget: Budget): void {
	let state = referenceWalkStates.get(root);
	if (!state || state.complete) {
		state = createTreeWalk(root);
		referenceWalkStates.set(root, state);
	}
	while (!state.complete && budget.deleted < budget.maxDeletes && budget.scanned < budget.maxEntries) {
		const uncertaintyCount = budget.uncertainties.length;
		const entry = nextTreeFile(state, budget);
		if (budget.uncertainties.length > uncertaintyCount) {
			discardTreeWalk(referenceWalkStates, root);
			return;
		}
		if (!entry) break;
		if (!entry.stat.isFile() || !expired(entry.stat, nowMs)) continue;
		const relative = entry.path.slice(root.length + 1).split("/");
		if (relative[0] === "runs") continue;
		unlinkBoundPath(entry.path, entry.stat, budget, "ref-delete", entry.parentDescriptor);
		if (budget.uncertainties.length > uncertaintyCount) {
			discardTreeWalk(referenceWalkStates, root);
			return;
		}
	}
	if (state.complete) {
		referenceWalkStates.delete(root);
		completedReferencePrunes.add(root);
	}
}

function advanceLegacySysdigOwnerSweep(root: string, budget: Budget): void {
	let state = legacySysdigOwnerSweepStates.get(root);
	if (!state || state.complete) {
		state = createTreeWalk(root);
		legacySysdigOwnerSweepStates.set(root, state);
	}
	while (!state.complete && budget.deleted < budget.maxDeletes && budget.scanned < budget.maxEntries) {
		const uncertaintyCount = budget.uncertainties.length;
		const entry = nextTreeFile(state, budget);
		if (budget.uncertainties.length > uncertaintyCount) {
			discardTreeWalk(legacySysdigOwnerSweepStates, root);
			return;
		}
		if (!entry) break;
		if (!entry.stat.isFile() || !/^[0-9a-f]{64}\.scap$/.test(entry.name)) {
			budget.uncertainties.push(`legacy-sysdig-owner-shape:${entry.path}`);
			discardTreeWalk(legacySysdigOwnerSweepStates, root);
			return;
		}
		if (entry.stat.nlink !== 1) continue;
		let descriptor: number | undefined;
		try {
			const bound = boundEntryPath(entry.parentDescriptor, entry.name);
			descriptor = openSync(bound, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
			const current = fstatSync(descriptor);
			const named = lstatSync(bound);
			if (!current.isFile() || !sameIdentity(current, entry.stat) || !sameIdentity(named, current))
				throw new Error("legacy_sysdig_owner_identity_changed");
			if (current.nlink !== 1) continue;
			unlinkSync(bound);
			budget.deleted += 1;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT")
				budget.uncertainties.push(`legacy-sysdig-owner-delete:${entry.path}`);
		} finally {
			if (descriptor !== undefined)
				try {
					closeSync(descriptor);
				} catch {}
		}
		if (budget.uncertainties.length > uncertaintyCount) {
			discardTreeWalk(legacySysdigOwnerSweepStates, root);
			return;
		}
	}
	if (state.complete) legacySysdigOwnerSweepStates.delete(root);
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
			const after = fstatSync(file.descriptor, { bigint: true });
			if (
				after.dev !== file.dev ||
				after.ino !== file.ino ||
				after.size !== file.size ||
				after.mtimeNs !== file.mtimeNs ||
				after.ctimeNs !== file.ctimeNs
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
		if (state.uncertain) break;
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
			state.openUncertain = next.openUncertain;
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
			let descriptor: number | undefined;
			try {
				const bound = boundEntryPath(entry.parentDescriptor, entry.name);
				const before = lstatSync(bound, { bigint: true });
				descriptor = openSync(bound, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
				const opened = fstatSync(descriptor, { bigint: true });
				if (
					!before.isFile() ||
					before.isSymbolicLink() ||
					opened.dev !== before.dev ||
					opened.ino !== before.ino ||
					opened.size !== before.size ||
					opened.mtimeNs !== before.mtimeNs ||
					opened.ctimeNs !== before.ctimeNs ||
					Number(before.dev) !== entry.stat.dev ||
					Number(before.ino) !== entry.stat.ino ||
					Number(before.size) !== entry.stat.size ||
					Number(before.mtimeNs) / 1_000_000 !== entry.stat.mtimeMs ||
					Number(before.ctimeNs) / 1_000_000 !== entry.stat.ctimeMs ||
					!opened.isFile()
				)
					throw new Error("reference_identity_changed");
				state.currentFile = {
					path: entry.path,
					descriptor,
					offset: 0,
					size: opened.size,
					dev: opened.dev,
					ino: opened.ino,
					mtimeNs: opened.mtimeNs,
					ctimeNs: opened.ctimeNs,
					carry: "",
				};
				descriptor = undefined;
			} catch {
				if (descriptor !== undefined)
					try {
						closeSync(descriptor);
					} catch {}
				state.uncertain = true;
				budget.uncertainties.push(`reference-read:${entry.path}`);
				break;
			}
			continue;
		}
		const read = boundedRead(boundEntryPath(entry.parentDescriptor, entry.name), 64 * 1024);
		if (read.state !== "ok" || !read.bytes) {
			state.uncertain = true;
			budget.uncertainties.push(`reference-read:${entry.path}`);
			break;
		}
		addCasMarks(state, budget, read.bytes.toString("utf8"));
		if (state.uncertain) break;
	}
	if (state.uncertain) {
		if (state.currentFile)
			try {
				closeSync(state.currentFile.descriptor);
			} catch {}
		state.currentFile = undefined;
		closeTreeWalkState(state);
		casMarkStates.delete(key);
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
		const uncertaintyCount = budget.uncertainties.length;
		const entry = nextTreeFile(state, budget);
		if (budget.uncertainties.length > uncertaintyCount) {
			discardTreeWalk(casSweepStates, root);
			return false;
		}
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
		try {
			const boundPath = boundEntryPath(entry.parentDescriptor, entry.name);
			descriptor = openSync(boundPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
			const current = fstatSync(descriptor);
			const named = lstatSync(boundPath);
			if (
				!current.isFile() ||
				current.dev !== entry.stat.dev ||
				current.ino !== entry.stat.ino ||
				!sameIdentity(named, current)
			)
				throw new Error("cas_delete_identity_changed");
			if (current.nlink !== 1 || !expired(current, nowMs)) continue;
			unlinkSync(boundPath);
			budget.deleted += 1;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") budget.uncertainties.push(`cas-delete:${entry.path}`);
		} finally {
			if (descriptor !== undefined)
				try {
					closeSync(descriptor);
				} catch {}
		}
		if (budget.uncertainties.length > uncertaintyCount) {
			discardTreeWalk(casSweepStates, root);
			return false;
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
		let boundaryDescriptor: number | undefined;
		let rootDescriptor: number | undefined;
		try {
			boundaryDescriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
			if (!fstatSync(boundaryDescriptor).isFile()) throw new Error("lease_boundary_not_regular_file");
			fsyncSync(boundaryDescriptor);
			rootDescriptor = openStableDirectory(root);
			fsyncSync(rootDescriptor);
		} catch {
			return undefined;
		} finally {
			if (boundaryDescriptor !== undefined)
				try {
					closeSync(boundaryDescriptor);
				} catch {}
			if (rootDescriptor !== undefined)
				try {
					closeSync(rootDescriptor);
				} catch {}
		}
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

function persistedMarkPaths(root: string): {
	directory: string;
	logName: string;
	proofName: string;
} {
	return {
		directory: join(root, "retention"),
		logName: "legacy-marks-v2.log",
		proofName: "legacy-marks-v2-complete.json",
	};
}

function fsyncBoundFile(path: string): void {
	const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
	try {
		const metadata = fstatSync(descriptor);
		if (!metadata.isFile()) throw new Error("mark_publication_not_regular_file");
		fsyncSync(descriptor);
	} finally {
		closeSync(descriptor);
	}
}

// Publish data first, fsync it and its directory, then publish the proof.
// A crash can leave no proof or a hash mismatch, neither of which may sweep CAS.
function persistCompletedMark(
	root: string,
	marked: Set<string>,
	roots: readonly string[],
	leaseBoundaryMs: number,
): void {
	const paths = persistedMarkPaths(root);
	mkdirSync(paths.directory, { recursive: true, mode: 0o700 });
	const rootDescriptor = openStableDirectory(root);
	try {
		fsyncSync(rootDescriptor);
	} finally {
		closeSync(rootDescriptor);
	}
	const directory = openStableDirectory(paths.directory);
	const generation = `${process.pid}-${process.hrtime.bigint()}`;
	const temporaryLogName = `.${paths.logName}.tmp-${generation}`;
	const temporaryProofName = `.${paths.proofName}.tmp-${generation}`;
	const logBytes = Buffer.from(`${[...marked].sort().join("\n")}\n`, "utf8");
	const proofBytes = Buffer.from(
		`${JSON.stringify({
			version: 2,
			state: "complete",
			protocol: "cas-hard-link-lease-before-reference",
			generation,
			leaseBoundaryMs,
			roots: [...roots],
			count: marked.size,
			bytes: logBytes.length,
			sha256: createHash("sha256").update(logBytes).digest("hex"),
		})}\n`,
		"utf8",
	);
	try {
		const temporaryLog = boundEntryPath(directory, temporaryLogName);
		const temporaryProof = boundEntryPath(directory, temporaryProofName);
		const log = boundEntryPath(directory, paths.logName);
		const proof = boundEntryPath(directory, paths.proofName);
		writeFileSync(temporaryLog, logBytes, { mode: 0o600, flag: "wx" });
		fsyncBoundFile(temporaryLog);
		renameSync(temporaryLog, log);
		fsyncSync(directory);
		writeFileSync(temporaryProof, proofBytes, { mode: 0o600, flag: "wx" });
		fsyncBoundFile(temporaryProof);
		renameSync(temporaryProof, proof);
		fsyncSync(directory);
	} finally {
		for (const name of [temporaryProofName, temporaryLogName])
			try {
				unlinkSync(boundEntryPath(directory, name));
			} catch {}
		closeSync(directory);
	}
}

function loadPersistedMark(root: string, roots: readonly string[], leaseBoundaryMs: number): Set<string> | undefined {
	const paths = persistedMarkPaths(root);
	let directory: number | undefined;
	try {
		directory = openStableDirectory(paths.directory);
		const proof = smallJson(boundEntryPath(directory, paths.proofName));
		if (
			proof.state !== "ok" ||
			proof.value?.version !== 2 ||
			proof.value.state !== "complete" ||
			proof.value.protocol !== "cas-hard-link-lease-before-reference" ||
			typeof proof.value.generation !== "string" ||
			!/^\d+-\d+$/.test(proof.value.generation) ||
			proof.value.leaseBoundaryMs !== leaseBoundaryMs ||
			!Array.isArray(proof.value.roots) ||
			proof.value.roots.length !== roots.length ||
			!proof.value.roots.every((value, index) => value === roots[index]) ||
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
		const log = boundedRead(boundEntryPath(directory, paths.logName), 5 * 1024 * 1024);
		if (
			log.state !== "ok" ||
			!log.bytes ||
			log.bytes.length !== proof.value.bytes ||
			createHash("sha256").update(log.bytes).digest("hex") !== proof.value.sha256
		)
			return undefined;
		const values = log.bytes.toString("utf8").trim().split("\n").filter(Boolean);
		if (values.length !== proof.value.count || values.some((value) => !/^[0-9a-f]{64}$/.test(value)))
			return undefined;
		return new Set(values);
	} catch {
		return undefined;
	} finally {
		if (directory !== undefined)
			try {
				closeSync(directory);
			} catch {}
	}
}

function removePersistedMark(root: string): void {
	const paths = persistedMarkPaths(root);
	let directory: number | undefined;
	try {
		directory = openStableDirectory(paths.directory);
		for (const name of [paths.proofName, paths.logName, "legacy-marks-v1-complete.json", "legacy-marks-v1.log"])
			try {
				const bound = boundEntryPath(directory, name);
				const metadata = lstatSync(bound);
				if (!metadata.isFile() || metadata.isSymbolicLink()) continue;
				unlinkSync(bound);
			} catch {}
		fsyncSync(directory);
	} catch {
		// Missing or substituted proof storage blocks sweep but needs no cleanup.
	} finally {
		if (directory !== undefined)
			try {
				closeSync(directory);
			} catch {}
	}
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
	if (incidentScanComplete && runState && budget.uncertainties.length === 0) {
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
	if (
		runScanComplete &&
		runState &&
		budget.uncertainties.length === 0 &&
		budget.deleted < budget.maxDeletes &&
		budget.scanned < budget.maxEntries
	) {
		const refsRoot = join(root, "refs");
		if (!completedRunOwnerPrunes.has(refsRoot)) pruneRunReferenceOwners(refsRoot, nowMs, budget, runState.hashes);
		if (
			completedRunOwnerPrunes.has(refsRoot) &&
			!completedReferencePrunes.has(refsRoot) &&
			budget.deleted < budget.maxDeletes &&
			budget.scanned < budget.maxEntries
		)
			pruneReferences(refsRoot, nowMs, budget);
	}
	if (
		runScanComplete &&
		budget.uncertainties.length === 0 &&
		budget.deleted < budget.maxDeletes &&
		budget.scanned < budget.maxEntries
	)
		advanceLegacySysdigOwnerSweep(join(root, "sysdig-pins", "owners"), budget);
	if (
		runScanComplete &&
		runState &&
		!runState.unsafeForCas &&
		budget.uncertainties.length === 0 &&
		budget.deleted < budget.maxDeletes &&
		budget.scanned < budget.maxEntries
	) {
		const markKey = join(root, "retention-mark-v2");
		const markRoots = [runRoot, incidentRoot, join(root, "refs")];
		const casRoot = join(root, "cas", "sha256");
		if (leaseBoundaryMs !== undefined) {
			let marked = loadPersistedMark(root, markRoots, leaseBoundaryMs);
			if (!marked) {
				discardTreeWalk(casSweepStates, casRoot);
				const mark = advanceCasMark(markKey, markRoots, budget, leaseBoundaryMs);
				if (mark.complete && !mark.uncertain && mark.marked) {
					try {
						persistCompletedMark(root, mark.marked, markRoots, leaseBoundaryMs);
						marked = loadPersistedMark(root, markRoots, leaseBoundaryMs);
						if (!marked) budget.uncertainties.push("durable-cas-mark-proof-unavailable");
					} catch {
						budget.uncertainties.push("durable-cas-mark-proof-publication-failed");
					}
				}
			}
			if (
				marked &&
				budget.uncertainties.length === 0 &&
				budget.deleted < budget.maxDeletes &&
				budget.scanned < budget.maxEntries
			) {
				if (advanceCasSweep(casRoot, nowMs, budget, marked)) {
					removePersistedMark(root);
					const refsRoot = join(root, "refs");
					completedReferencePrunes.delete(refsRoot);
					completedRunOwnerPrunes.delete(refsRoot);
				}
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
