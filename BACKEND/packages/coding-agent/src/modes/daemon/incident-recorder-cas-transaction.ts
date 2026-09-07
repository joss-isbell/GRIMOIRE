import { createHash, randomUUID } from "node:crypto";
import {
	type BigIntStats,
	type BigIntStatsFs,
	chmodSync,
	closeSync,
	constants,
	fchmodSync,
	fstatSync,
	fsyncSync,
	ftruncateSync,
	linkSync,
	lstatSync,
	mkdirSync,
	opendirSync,
	openSync,
	readFileSync,
	readlinkSync,
	readSync,
	realpathSync,
	renameSync,
	rmdirSync,
	statfsSync,
	unlinkSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative as relativePath, resolve } from "node:path";
import { getProcessStartId } from "../../core/session-lease.js";

/**
 * Descriptor-bound v2 CAS admission for recorder namespace mutations.
 *
 * The fixed v2 authority is a directory. Its owner/quarantine decision is
 * published as one complete, fsynced hard link. Recovery moves one authority
 * at a time through a fixed quarantine slot, drains it in bounded passes, and
 * unlinks the slot directory while delayed reapers still retain only stale
 * descriptors. A delayed reaper therefore cannot address a later slot.
 *
 * This protocol is v2-only. Activation must prove that no v1 binary is still
 * running; evidence from a v1 authority is preserved and rejected rather than
 * being migrated while an arbitrarily paused v1 actor could still resume.
 * The recorder and its stable control parent must be owned by the same uid/gid
 * and not writable by another uid. That private parent is the cooperative
 * same-uid boundary for the sidecar protocol.
 */

export type IncidentCasTransactionStep =
	| "directory_created"
	| "owner_written"
	| "owner_fsynced"
	| "prepare_closed"
	| "owner_linked"
	| "owner_directory_fsynced"
	| "prepare_unlinked"
	| "before_authority_publish"
	| "authority_fixed_name_published"
	| "authority_published"
	| "creation_root_fsynced"
	| "before_quarantine_decision_link"
	| "quarantine_decision_linked"
	| "quarantine_claim_linked"
	| "before_quarantine_revalidation"
	| "before_quarantine_move"
	| "lock_quarantined"
	| "quarantine_root_fsynced"
	| "before_lock_retire"
	| "lock_retired"
	| "retirement_root_fsynced"
	| "released_owner_unlinked"
	| "released_directory_removed"
	| "cleanup_root_fsynced"
	| "root_detachment_written"
	| "root_detachment_fsynced"
	| "before_root_detachment_link"
	| "root_detachment_linked"
	| "before_root_detachment_prepare_unlink"
	| "root_detachment_root_fsynced"
	| "before_root_detachment_retire"
	| "root_detachment_unlinked"
	| "root_detachment_retirement_fsynced";

export interface IncidentCasTransactionRuntime {
	onStep?(step: IncidentCasTransactionStep): void;
	monotonicTimeMs?(): number;
}

interface PrepareRetirementTestSynchronization {
	hook(): void;
}

interface DetachmentRecoveryTestSynchronization {
	hook(): void;
}

const prepareRetirementTestSynchronizations = new WeakMap<
	IncidentCasTransactionRuntime,
	PrepareRetirementTestSynchronization
>();
const detachmentRecoveryTestSynchronizations = new WeakMap<
	IncidentCasTransactionRuntime,
	DetachmentRecoveryTestSynchronization
>();

/** @internal One-shot synchronization for deterministic crash-race tests. */
export function registerIncidentCasPrepareRetirementTestSynchronization(
	runtime: IncidentCasTransactionRuntime,
	hook: () => void,
): () => void {
	if (process.env.NODE_ENV !== "test") throw new Error("CAS test synchronization is unavailable outside tests");
	if (prepareRetirementTestSynchronizations.has(runtime))
		throw new Error("CAS prepare-retirement test synchronization is already registered");
	const synchronization = Object.freeze({ hook });
	prepareRetirementTestSynchronizations.set(runtime, synchronization);
	return () => {
		if (prepareRetirementTestSynchronizations.get(runtime) === synchronization)
			prepareRetirementTestSynchronizations.delete(runtime);
	};
}

function runPrepareRetirementTestSynchronization(runtime: IncidentCasTransactionRuntime): void {
	const synchronization = prepareRetirementTestSynchronizations.get(runtime);
	if (!synchronization) return;
	prepareRetirementTestSynchronizations.delete(runtime);
	synchronization.hook();
}

/** @internal One-shot synchronization for deterministic detachment recovery races. */
export function registerIncidentCasDetachmentRecoveryTestSynchronization(
	runtime: IncidentCasTransactionRuntime,
	hook: () => void,
): () => void {
	if (process.env.NODE_ENV !== "test") throw new Error("CAS test synchronization is unavailable outside tests");
	if (detachmentRecoveryTestSynchronizations.has(runtime))
		throw new Error("CAS detachment-recovery test synchronization is already registered");
	const synchronization = Object.freeze({ hook });
	detachmentRecoveryTestSynchronizations.set(runtime, synchronization);
	return () => {
		if (detachmentRecoveryTestSynchronizations.get(runtime) === synchronization)
			detachmentRecoveryTestSynchronizations.delete(runtime);
	};
}

function runDetachmentRecoveryTestSynchronization(runtime: IncidentCasTransactionRuntime): void {
	const synchronization = detachmentRecoveryTestSynchronizations.get(runtime);
	if (!synchronization) return;
	detachmentRecoveryTestSynchronizations.delete(runtime);
	synchronization.hook();
}

export type IncidentCasTransactionReleaseResult =
	| { state: "released"; cleanupPending: boolean }
	| {
			state: "pending";
			reason: "io_error" | "ownership_changed" | "root_identity_changed";
	  };

export type IncidentCasRootMutationResult<T> =
	| { state: "committed"; value: T }
	| { state: "root_detached"; evidence: "durable" | "pending" };

declare const incidentCasRelativePathBrand: unique symbol;

/** An opaque path usable only by the synchronous capability that created it. */
export interface IncidentCasRelativePath {
	readonly [incidentCasRelativePathBrand]: true;
}

export type IncidentCasFileAccess = "read" | "read_write" | "write";

export interface IncidentCasFileOpenOptions {
	access: IncidentCasFileAccess;
	create?: "exclusive";
	mode?: number;
	truncate?: boolean;
}

export interface IncidentCasFileMutation {
	stat(): BigIntStats;
	read(target: Uint8Array, offset: number, length: number, position: number | null): number;
	write(source: Uint8Array, offset: number, length: number, position: number | null): number;
	writeText(value: string, position: number | null): number;
	truncate(length: number): void;
	chmod(mode: number): void;
	sync(): void;
}

export type IncidentCasDirectoryEntryKind =
	| "block_device"
	| "character_device"
	| "directory"
	| "fifo"
	| "file"
	| "socket"
	| "symbolic_link"
	| "unknown";

export interface IncidentCasDirectoryPageEntry {
	name: string;
	kind: IncidentCasDirectoryEntryKind;
}

export interface IncidentCasDirectoryPage {
	entries: IncidentCasDirectoryPageEntry[];
	nextAfterName?: string;
	complete: boolean;
	cursorFound: boolean;
	scanLimitReached: boolean;
}

/**
 * Revocable synchronous filesystem authority rooted at the retained recorder
 * descriptor. Neither raw paths nor descriptors cross this interface.
 */
export interface IncidentCasRootMutation {
	relative(...components: string[]): IncidentCasRelativePath;
	/** A stable canonical address for durable records, never filesystem authority. */
	publicPath(path: IncidentCasRelativePath): string;
	exists(path: IncidentCasRelativePath): boolean;
	lstat(path: IncidentCasRelativePath): BigIntStats | undefined;
	stat(path: IncidentCasRelativePath): BigIntStats;
	statfs(path: IncidentCasRelativePath): BigIntStatsFs;
	readFile(path: IncidentCasRelativePath, maxBytes: number): Buffer;
	readlink(path: IncidentCasRelativePath): string;
	realpath(path: IncidentCasRelativePath): IncidentCasRelativePath;
	writeFileExclusive(path: IncidentCasRelativePath, value: string | Uint8Array, mode?: number): void;
	mkdirPrivate(path: IncidentCasRelativePath, recursive?: boolean): void;
	chmod(path: IncidentCasRelativePath, mode: number): void;
	unlinkFile(path: IncidentCasRelativePath): void;
	rmdir(path: IncidentCasRelativePath): void;
	rename(source: IncidentCasRelativePath, destination: IncidentCasRelativePath): void;
	hardLink(source: IncidentCasRelativePath, destination: IncidentCasRelativePath): void;
	fsyncFile(path: IncidentCasRelativePath): void;
	fsyncDirectory(path: IncidentCasRelativePath): void;
	withFile<T>(
		path: IncidentCasRelativePath,
		options: IncidentCasFileOpenOptions,
		operation: (file: IncidentCasFileMutation) => T,
	): T;
	withDirectory<T>(path: IncidentCasRelativePath, operation: (directory: IncidentCasRootMutation) => T): T;
	directoryPage(
		path: IncidentCasRelativePath,
		options: { afterName?: string; limit: number; scanLimit?: number },
	): IncidentCasDirectoryPage;
}

export interface CasTransaction {
	/**
	 * Run one synchronous mutation against the retained recorder-root descriptor.
	 * The guard and public root are checked before and after the callback.
	 */
	withRoot<T>(operation: (root: IncidentCasRootMutation) => T): IncidentCasRootMutationResult<T>;
	release(): IncidentCasTransactionReleaseResult;
}

export type IncidentCasTransactionUnavailableReason =
	| "creation_failed"
	| "control_artifact_busy"
	| "control_artifact_grace"
	| "foreign_machine_owner"
	| "identity_unavailable"
	| "invalid_owner_grace"
	| "legacy_v1_authority_present"
	| "live_owner"
	| "local_ownership_changed"
	| "owner_liveness_unknown"
	| "quarantine_conflict"
	| "quarantine_failed"
	| "release_pending"
	| "root_unavailable"
	| "same_process_owner_untracked"
	| "unstable_lock_namespace";

export type IncidentCasTransactionAdmission =
	| { state: "acquired"; transaction: CasTransaction }
	| { state: "unavailable"; reason: IncidentCasTransactionUnavailableReason };

interface ProcessIdentity {
	machineId: string;
	bootId: string;
	pid: number;
	processStartId: string;
}

interface OwnerDecision extends ProcessIdentity {
	type: "incident-recorder-cas-decision";
	version: 2;
	kind: "owner";
	lockId: string;
	lockDev: string;
	lockIno: string;
	rootDev: string;
	rootIno: string;
	rootPath: string;
}

interface QuarantineDecision extends ProcessIdentity {
	type: "incident-recorder-cas-decision";
	version: 2;
	kind: "quarantine";
	recordId: string;
	lockDev: string;
	lockIno: string;
	reason: "owner-missing";
}

interface QuarantineClaim extends ProcessIdentity {
	type: "incident-recorder-cas-quarantine-claim";
	version: 2;
	claimId: string;
	lockDev: string;
	lockIno: string;
	lockMode: string;
	lockUid: string;
	lockGid: string;
}

interface RootDetachEvidence extends ProcessIdentity {
	type: "incident-recorder-cas-root-detachment";
	version: 2;
	detachId: string;
	lockId: string;
	lockDev: string;
	lockIno: string;
	rootDev: string;
	rootIno: string;
	rootPath: string;
}

type Decision = OwnerDecision | QuarantineDecision;
type CanonicalRecord = Decision | QuarantineClaim | RootDetachEvidence;

interface Fingerprint {
	dev: bigint;
	ino: bigint;
	file: boolean;
	directory: boolean;
	symbolicLink: boolean;
	mode: bigint;
	nlink: bigint;
	size: bigint;
	mtimeMs: bigint;
	ctimeMs: bigint;
	uid: bigint;
	gid: bigint;
}

interface RootIdentity {
	canonicalPath: string;
	descriptor: number;
	key: string;
	dev: bigint;
	ino: bigint;
	mode: bigint;
	uid: bigint;
	gid: bigint;
	controlCanonicalPath: string;
	controlDescriptor: number;
	controlName: string;
	controlDev: bigint;
	controlIno: bigint;
	controlMode: bigint;
	controlUid: bigint;
	controlGid: bigint;
}

interface StableFile {
	bytes: string;
	fingerprint: Fingerprint;
}

interface RecordEvidence extends StableFile {
	record?: CanonicalRecord;
}

type V2ObservationState = "owner" | "quarantine" | "missing" | "invalid";

interface V2Observation {
	state: V2ObservationState;
	lock: Fingerprint;
	owner?: Fingerprint;
	decision?: Decision;
	ownerActivityHint?: OwnerActivity;
	publicationProvisional?: true;
}

interface OwnedTransaction {
	withRoot<T>(operation: (root: IncidentCasRootMutation) => T): IncidentCasRootMutationResult<T>;
	owns(): boolean;
	release(): IncidentCasTransactionReleaseResult;
}

interface HeldEntry {
	count: number;
	publishing: boolean;
	transaction: OwnedTransaction;
}

interface InvalidObservation {
	signature: string;
	firstSeenMonotonicMs: number;
}

interface RelativePathState {
	owner: symbol;
	components: readonly string[];
}

type OwnerActivity = "foreign" | "live" | "self" | "stale" | "unknown";
type CreateAttempt =
	| { state: "acquired"; observation: V2Observation }
	| { state: "published"; observation: V2Observation }
	| { state: "occupied" }
	| { state: "retry" }
	| { state: "failed" };
type QuarantineOutcome = "completed" | "changed" | "conflict" | "failed";

const CONTROL_PREFIX = ".grimoire-incident-cas-v2-";
const OWNER_NAME = "owner.json";
const CLAIM_NAME = "claim.json";
const OCCUPANT_NAME = "occupant";
const ORPHAN_LOCK_GRACE_MS = 5_000;
const LOCK_STABILITY_RECHECK_MS = 10;
const MAX_RECORD_BYTES = 4096;
const held = new Map<string, HeldEntry>();
const heldPaths = new Map<string, HeldEntry>();
const invalidObservations = new Map<string, InvalidObservation>();
const artifactObservations = new Map<string, InvalidObservation>();
const relativePathStates = new WeakMap<object, RelativePathState>();
const lockStabilityWait = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
const MAX_DIRECTORY_PAGE_LIMIT = 1024;
const MAX_DIRECTORY_SCAN_LIMIT = 65_536;
const MAX_QUARANTINE_CLEANUP_ENTRIES = 32;
const MACHINE_ID = /^[0-9a-f]{32}$/;
const BOOT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RECORD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function runtimeMonotonicTimeMs(runtime: IncidentCasTransactionRuntime): number {
	return runtime.monotonicTimeMs?.() ?? Number(process.hrtime.bigint() / 1_000_000n);
}

function smallSystemText(path: string): string {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		return readFileSync(descriptor, "utf8").trim();
	} catch {
		return "";
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function validProcessStartId(value: string): boolean {
	return /^(?:proc|win):\d+$/.test(value) || /^ps:[^\r\n]{1,256}$/.test(value);
}

function validDecimal(value: unknown): value is string {
	return typeof value === "string" && /^(?:0|[1-9]\d*)$/.test(value);
}

function parseIdentity(value: Record<string, unknown>): ProcessIdentity | undefined {
	if (
		typeof value.machineId !== "string" ||
		!MACHINE_ID.test(value.machineId) ||
		typeof value.bootId !== "string" ||
		!BOOT_ID.test(value.bootId) ||
		!Number.isSafeInteger(value.pid) ||
		(value.pid as number) <= 0 ||
		typeof value.processStartId !== "string" ||
		!validProcessStartId(value.processStartId)
	) {
		return undefined;
	}
	return {
		machineId: value.machineId,
		bootId: value.bootId,
		pid: value.pid as number,
		processStartId: value.processStartId,
	};
}

function currentProcessIdentity(): ProcessIdentity | undefined {
	const machineId = smallSystemText("/etc/machine-id");
	const bootId = smallSystemText("/proc/sys/kernel/random/boot_id");
	const processStartId = getProcessStartId(process.pid);
	return MACHINE_ID.test(machineId) &&
		BOOT_ID.test(bootId) &&
		processStartId !== undefined &&
		validProcessStartId(processStartId)
		? { machineId, bootId, pid: process.pid, processStartId }
		: undefined;
}

function canonicalRecordBytes(record: CanonicalRecord): string {
	if (record.type === "incident-recorder-cas-quarantine-claim") {
		return `${JSON.stringify({
			type: record.type,
			version: record.version,
			claimId: record.claimId,
			lockDev: record.lockDev,
			lockIno: record.lockIno,
			lockMode: record.lockMode,
			lockUid: record.lockUid,
			lockGid: record.lockGid,
			machineId: record.machineId,
			bootId: record.bootId,
			pid: record.pid,
			processStartId: record.processStartId,
		})}\n`;
	}
	if (record.type === "incident-recorder-cas-root-detachment") {
		return `${JSON.stringify({
			type: record.type,
			version: record.version,
			detachId: record.detachId,
			lockId: record.lockId,
			lockDev: record.lockDev,
			lockIno: record.lockIno,
			rootDev: record.rootDev,
			rootIno: record.rootIno,
			rootPath: record.rootPath,
			machineId: record.machineId,
			bootId: record.bootId,
			pid: record.pid,
			processStartId: record.processStartId,
		})}\n`;
	}
	if (record.kind === "owner") {
		return `${JSON.stringify({
			type: record.type,
			version: record.version,
			kind: record.kind,
			lockId: record.lockId,
			lockDev: record.lockDev,
			lockIno: record.lockIno,
			rootDev: record.rootDev,
			rootIno: record.rootIno,
			rootPath: record.rootPath,
			machineId: record.machineId,
			bootId: record.bootId,
			pid: record.pid,
			processStartId: record.processStartId,
		})}\n`;
	}
	return `${JSON.stringify({
		type: record.type,
		version: record.version,
		kind: record.kind,
		recordId: record.recordId,
		lockDev: record.lockDev,
		lockIno: record.lockIno,
		reason: record.reason,
		machineId: record.machineId,
		bootId: record.bootId,
		pid: record.pid,
		processStartId: record.processStartId,
	})}\n`;
}

function parseCanonicalRecord(bytes: string): CanonicalRecord | undefined {
	try {
		const parsed: unknown = JSON.parse(bytes);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
		const value = parsed as Record<string, unknown>;
		let record: CanonicalRecord;
		if (value.type === "incident-recorder-cas-quarantine-claim") {
			const identity = parseIdentity(value);
			if (
				value.version !== 2 ||
				typeof value.claimId !== "string" ||
				!RECORD_ID.test(value.claimId) ||
				!validDecimal(value.lockDev) ||
				!validDecimal(value.lockIno) ||
				!validDecimal(value.lockMode) ||
				!validDecimal(value.lockUid) ||
				!validDecimal(value.lockGid) ||
				!identity
			) {
				return undefined;
			}
			record = {
				type: value.type,
				version: 2,
				claimId: value.claimId,
				lockDev: value.lockDev,
				lockIno: value.lockIno,
				lockMode: value.lockMode,
				lockUid: value.lockUid,
				lockGid: value.lockGid,
				...identity,
			};
		} else if (value.type === "incident-recorder-cas-root-detachment") {
			const identity = parseIdentity(value);
			if (
				value.version !== 2 ||
				typeof value.detachId !== "string" ||
				!RECORD_ID.test(value.detachId) ||
				typeof value.lockId !== "string" ||
				!RECORD_ID.test(value.lockId) ||
				!validDecimal(value.lockDev) ||
				!validDecimal(value.lockIno) ||
				!validDecimal(value.rootDev) ||
				!validDecimal(value.rootIno) ||
				typeof value.rootPath !== "string" ||
				resolve(value.rootPath) !== value.rootPath ||
				!identity
			) {
				return undefined;
			}
			record = {
				type: value.type,
				version: 2,
				detachId: value.detachId,
				lockId: value.lockId,
				lockDev: value.lockDev,
				lockIno: value.lockIno,
				rootDev: value.rootDev,
				rootIno: value.rootIno,
				rootPath: value.rootPath,
				...identity,
			};
		} else if (value.type === "incident-recorder-cas-decision" && value.kind === "owner") {
			const identity = parseIdentity(value);
			if (
				value.version !== 2 ||
				typeof value.lockId !== "string" ||
				!RECORD_ID.test(value.lockId) ||
				!validDecimal(value.lockDev) ||
				!validDecimal(value.lockIno) ||
				!validDecimal(value.rootDev) ||
				!validDecimal(value.rootIno) ||
				typeof value.rootPath !== "string" ||
				resolve(value.rootPath) !== value.rootPath ||
				!identity
			) {
				return undefined;
			}
			record = {
				type: value.type,
				version: 2,
				kind: "owner",
				lockId: value.lockId,
				lockDev: value.lockDev,
				lockIno: value.lockIno,
				rootDev: value.rootDev,
				rootIno: value.rootIno,
				rootPath: value.rootPath,
				...identity,
			};
		} else if (value.type === "incident-recorder-cas-decision" && value.kind === "quarantine") {
			const identity = parseIdentity(value);
			if (
				value.version !== 2 ||
				typeof value.recordId !== "string" ||
				!RECORD_ID.test(value.recordId) ||
				!validDecimal(value.lockDev) ||
				!validDecimal(value.lockIno) ||
				value.reason !== "owner-missing" ||
				!identity
			) {
				return undefined;
			}
			record = {
				type: value.type,
				version: 2,
				kind: "quarantine",
				recordId: value.recordId,
				lockDev: value.lockDev,
				lockIno: value.lockIno,
				reason: value.reason,
				...identity,
			};
		} else {
			return undefined;
		}
		return bytes === canonicalRecordBytes(record) ? record : undefined;
	} catch {
		return undefined;
	}
}

function parseIdentityHint(bytes: string): ProcessIdentity | undefined {
	try {
		const parsed: unknown = JSON.parse(bytes);
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? parseIdentity(parsed as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	}
}

function fingerprintFromStat(value: BigIntStats): Fingerprint {
	return {
		dev: value.dev,
		ino: value.ino,
		file: value.isFile(),
		directory: value.isDirectory(),
		symbolicLink: value.isSymbolicLink(),
		mode: value.mode,
		nlink: value.nlink,
		size: value.size,
		mtimeMs: value.mtimeMs,
		ctimeMs: value.ctimeMs,
		uid: value.uid,
		gid: value.gid,
	};
}

function pathFingerprint(path: string): Fingerprint | undefined {
	try {
		return fingerprintFromStat(lstatSync(path, { bigint: true }));
	} catch {
		return undefined;
	}
}

function fingerprintEquals(left: Fingerprint | undefined, right: Fingerprint | undefined): boolean {
	return (
		left === right ||
		(left !== undefined &&
			right !== undefined &&
			left.dev === right.dev &&
			left.ino === right.ino &&
			left.file === right.file &&
			left.directory === right.directory &&
			left.symbolicLink === right.symbolicLink &&
			left.mode === right.mode &&
			left.nlink === right.nlink &&
			left.size === right.size &&
			left.mtimeMs === right.mtimeMs &&
			left.ctimeMs === right.ctimeMs &&
			left.uid === right.uid &&
			left.gid === right.gid)
	);
}

function sameInode(left: Fingerprint | undefined, right: Fingerprint | undefined): boolean {
	return left !== undefined && right !== undefined && left.dev === right.dev && left.ino === right.ino;
}

function rootStatsEqual(left: BigIntStats, right: BigIntStats): boolean {
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

function canonicalRoot(recorderRoot: string): RootIdentity | undefined {
	let descriptor: number | undefined;
	let controlDescriptor: number | undefined;
	try {
		const lexicalPath = resolve(recorderRoot);
		const canonicalPath = realpathSync.native(lexicalPath);
		const controlCanonicalPath = dirname(canonicalPath);
		const before = lstatSync(canonicalPath, { bigint: true });
		descriptor = openSync(canonicalPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const opened = fstatSync(descriptor, { bigint: true });
		const after = lstatSync(canonicalPath, { bigint: true });
		if (!rootStatsEqual(before, opened) || !rootStatsEqual(opened, after)) return undefined;
		const controlBefore = lstatSync(controlCanonicalPath, { bigint: true });
		controlDescriptor = openSync(
			controlCanonicalPath,
			constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
		);
		const controlOpened = fstatSync(controlDescriptor, { bigint: true });
		const controlAfter = lstatSync(controlCanonicalPath, { bigint: true });
		if (
			!rootStatsEqual(controlBefore, controlOpened) ||
			!rootStatsEqual(controlOpened, controlAfter) ||
			controlOpened.uid !== opened.uid ||
			controlOpened.gid !== opened.gid ||
			(opened.mode & 0o022n) !== 0n ||
			(controlOpened.mode & 0o022n) !== 0n
		) {
			return undefined;
		}
		const controlName = `${CONTROL_PREFIX}${createHash("sha256").update(canonicalPath).digest("hex").slice(0, 32)}`;
		const root: RootIdentity = {
			canonicalPath,
			descriptor,
			key: `${opened.dev}:${opened.ino}`,
			dev: opened.dev,
			ino: opened.ino,
			mode: opened.mode,
			uid: opened.uid,
			gid: opened.gid,
			controlCanonicalPath,
			controlDescriptor,
			controlName,
			controlDev: controlOpened.dev,
			controlIno: controlOpened.ino,
			controlMode: controlOpened.mode,
			controlUid: controlOpened.uid,
			controlGid: controlOpened.gid,
		};
		descriptor = undefined;
		controlDescriptor = undefined;
		return root;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
		if (controlDescriptor !== undefined) {
			try {
				closeSync(controlDescriptor);
			} catch {}
		}
	}
}

function rootDescriptorValid(root: RootIdentity): boolean {
	try {
		const current = fstatSync(root.descriptor, { bigint: true });
		return (
			current.isDirectory() &&
			current.dev === root.dev &&
			current.ino === root.ino &&
			current.mode === root.mode &&
			current.uid === root.uid &&
			current.gid === root.gid
		);
	} catch {
		return false;
	}
}

function rootPathCurrent(root: RootIdentity): boolean {
	try {
		const opened = fstatSync(root.descriptor, { bigint: true });
		const currentPath = lstatSync(root.canonicalPath, { bigint: true });
		return rootStatsEqual(opened, currentPath);
	} catch {
		return false;
	}
}

function rootDescriptorCurrent(root: RootIdentity): boolean {
	return rootDescriptorValid(root) && rootPathCurrent(root);
}

function controlDescriptorValid(root: RootIdentity): boolean {
	try {
		const current = fstatSync(root.controlDescriptor, { bigint: true });
		return (
			current.isDirectory() &&
			current.dev === root.controlDev &&
			current.ino === root.controlIno &&
			current.mode === root.controlMode &&
			current.uid === root.controlUid &&
			current.gid === root.controlGid
		);
	} catch {
		return false;
	}
}

function controlPathCurrent(root: RootIdentity): boolean {
	try {
		const opened = fstatSync(root.controlDescriptor, { bigint: true });
		const currentPath = lstatSync(root.controlCanonicalPath, { bigint: true });
		return rootStatsEqual(opened, currentPath);
	} catch {
		return false;
	}
}

function controlDescriptorCurrent(root: RootIdentity): boolean {
	return controlDescriptorValid(root) && controlPathCurrent(root);
}

function closeRoot(root: RootIdentity): void {
	try {
		closeSync(root.descriptor);
	} catch {}
	try {
		closeSync(root.controlDescriptor);
	} catch {}
}

function rootChild(root: RootIdentity, name: string): string {
	return join(`/proc/self/fd/${root.controlDescriptor}`, name);
}

function fsyncRoot(root: RootIdentity, requireCurrentPath = true): void {
	if (!rootDescriptorValid(root) || !controlDescriptorCurrent(root) || (requireCurrentPath && !rootPathCurrent(root)))
		throw new Error("CAS recorder or control-parent identity changed");
	fsyncSync(root.controlDescriptor);
}

function stableFile(path: string): StableFile | undefined {
	let descriptor: number | undefined;
	try {
		const before = pathFingerprint(path);
		if (!before?.file || before.symbolicLink || before.size <= 0n || before.size > BigInt(MAX_RECORD_BYTES)) {
			return undefined;
		}
		descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (!fingerprintEquals(before, opened)) return undefined;
		const expectedSize = Number(opened.size);
		const buffer = Buffer.alloc(expectedSize + 1);
		let bytesRead = 0;
		while (bytesRead < buffer.length) {
			const count = readSync(descriptor, buffer, bytesRead, buffer.length - bytesRead, bytesRead);
			if (count === 0) break;
			bytesRead += count;
		}
		if (bytesRead !== expectedSize) return undefined;
		const afterRead = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		const afterPath = pathFingerprint(path);
		if (!fingerprintEquals(opened, afterRead) || !fingerprintEquals(afterRead, afterPath)) return undefined;
		return { bytes: buffer.subarray(0, bytesRead).toString("utf8"), fingerprint: afterRead };
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function boundedStableFile(path: string): StableFile | undefined {
	let descriptor: number | undefined;
	try {
		const before = pathFingerprint(path);
		if (!before?.file || before.symbolicLink) return undefined;
		descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (!fingerprintEquals(before, opened)) return undefined;
		const sampleSize = opened.size > BigInt(MAX_RECORD_BYTES) ? MAX_RECORD_BYTES + 1 : Number(opened.size);
		const buffer = Buffer.alloc(sampleSize);
		let bytesRead = 0;
		while (bytesRead < buffer.length) {
			const count = readSync(descriptor, buffer, bytesRead, buffer.length - bytesRead, bytesRead);
			if (count === 0) break;
			bytesRead += count;
		}
		if (bytesRead !== sampleSize) return undefined;
		const afterRead = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		const afterPath = pathFingerprint(path);
		if (!fingerprintEquals(opened, afterRead) || !fingerprintEquals(afterRead, afterPath)) {
			return undefined;
		}
		const marker = [
			afterRead.dev,
			afterRead.ino,
			afterRead.mode,
			afterRead.size,
			afterRead.mtimeMs,
			afterRead.uid,
			afterRead.gid,
			createHash("sha256").update(buffer.subarray(0, bytesRead)).digest("hex"),
		].join(":");
		return { bytes: marker, fingerprint: afterRead };
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function prepareSlot(record: CanonicalRecord): "claim" | "detachment" | "owner" | "quarantine" {
	return record.type === "incident-recorder-cas-quarantine-claim"
		? "claim"
		: record.type === "incident-recorder-cas-root-detachment"
			? "detachment"
			: record.kind === "owner"
				? "owner"
				: "quarantine";
}

function preparedPath(root: RootIdentity, record: CanonicalRecord): string {
	return rootChild(root, `${root.controlName}.prepare-${prepareSlot(record)}`);
}

function exactPrivateRecordFile(root: RootIdentity, fingerprint: Fingerprint): boolean {
	return (
		fingerprint.file &&
		!fingerprint.symbolicLink &&
		(fingerprint.mode & 0o777n) === 0o600n &&
		fingerprint.uid === root.controlUid &&
		fingerprint.gid === root.controlGid &&
		fingerprint.size > 0n &&
		fingerprint.size <= BigInt(MAX_RECORD_BYTES)
	);
}

function recordEvidence(root: RootIdentity, path: string): RecordEvidence | undefined {
	const file = stableFile(path);
	if (!file) return undefined;
	const parsed = parseCanonicalRecord(file.bytes);
	if (!parsed || !exactPrivateRecordFile(root, file.fingerprint)) return file;
	const prepare = pathFingerprint(preparedPath(root, parsed));
	const topologyValid =
		(file.fingerprint.nlink === 1n && prepare === undefined) ||
		(file.fingerprint.nlink === 2n &&
			prepare !== undefined &&
			exactPrivateRecordFile(root, prepare) &&
			sameInode(file.fingerprint, prepare));
	return topologyValid ? { ...file, record: parsed } : file;
}

function exactPrivateDirectory(root: RootIdentity, fingerprint: Fingerprint): boolean {
	return (
		fingerprint.directory &&
		!fingerprint.symbolicLink &&
		(fingerprint.mode & 0o777n) === 0o700n &&
		fingerprint.uid === root.controlUid &&
		fingerprint.gid === root.controlGid
	);
}

function processExists(pid: number): "dead" | "present" | "unknown" {
	try {
		process.kill(pid, 0);
		return "present";
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		return code === "ESRCH" ? "dead" : code === "EPERM" ? "present" : "unknown";
	}
}

function ownerActivity(owner: ProcessIdentity, current: ProcessIdentity): OwnerActivity {
	if (owner.machineId !== current.machineId) return "foreign";
	if (owner.bootId !== current.bootId) return "stale";
	if (owner.pid === current.pid && owner.processStartId === current.processStartId) return "self";
	const startId = getProcessStartId(owner.pid);
	if (startId === owner.processStartId) return "live";
	if (startId !== undefined) return "stale";
	const exists = processExists(owner.pid);
	return exists === "dead" ? "stale" : "unknown";
}

function decisionBoundToLock(decision: Decision, lock: Fingerprint): boolean {
	return decision.lockDev === lock.dev.toString() && decision.lockIno === lock.ino.toString();
}

function ownerBoundToRoot(owner: OwnerDecision, root: RootIdentity): boolean {
	return (
		owner.rootDev === root.dev.toString() &&
		owner.rootIno === root.ino.toString() &&
		owner.rootPath === root.canonicalPath
	);
}

function processIdentityEquals(left: ProcessIdentity, right: ProcessIdentity): boolean {
	return (
		left.machineId === right.machineId &&
		left.bootId === right.bootId &&
		left.pid === right.pid &&
		left.processStartId === right.processStartId
	);
}

function rootDetachmentForOwner(owner: OwnerDecision): RootDetachEvidence {
	return {
		type: "incident-recorder-cas-root-detachment",
		version: 2,
		detachId: owner.lockId,
		lockId: owner.lockId,
		lockDev: owner.lockDev,
		lockIno: owner.lockIno,
		rootDev: owner.rootDev,
		rootIno: owner.rootIno,
		rootPath: owner.rootPath,
		machineId: owner.machineId,
		bootId: owner.bootId,
		pid: owner.pid,
		processStartId: owner.processStartId,
	};
}

function rootDetachmentBoundToOwner(evidence: RootDetachEvidence, owner: OwnerDecision): boolean {
	return (
		evidence.detachId === owner.lockId &&
		evidence.lockId === owner.lockId &&
		evidence.lockDev === owner.lockDev &&
		evidence.lockIno === owner.lockIno &&
		evidence.rootDev === owner.rootDev &&
		evidence.rootIno === owner.rootIno &&
		evidence.rootPath === owner.rootPath &&
		processIdentityEquals(evidence, owner)
	);
}

function observeV2AtPath(
	root: RootIdentity,
	path: string,
	current: ProcessIdentity,
	requireCurrentRootPath = true,
): V2Observation | undefined {
	if (
		!rootDescriptorValid(root) ||
		!controlDescriptorCurrent(root) ||
		(requireCurrentRootPath && !rootPathCurrent(root))
	)
		return undefined;
	const firstLock = pathFingerprint(path);
	if (!firstLock) return undefined;
	if (!firstLock.directory || firstLock.symbolicLink) {
		return { state: "invalid", lock: firstLock };
	}
	let directoryDescriptor: number | undefined;
	try {
		directoryDescriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(directoryDescriptor, { bigint: true }));
		if (!fingerprintEquals(firstLock, opened)) return undefined;
		const ownerPath = `/proc/self/fd/${directoryDescriptor}/${OWNER_NAME}`;
		const firstOwner = pathFingerprint(ownerPath);
		const evidence = recordEvidence(root, ownerPath);
		const secondOwner = pathFingerprint(ownerPath);
		const afterDirectory = fingerprintFromStat(fstatSync(directoryDescriptor, { bigint: true }));
		const pathAfter = pathFingerprint(path);
		if (
			!fingerprintEquals(firstLock, afterDirectory) ||
			!fingerprintEquals(afterDirectory, pathAfter) ||
			!fingerprintEquals(firstOwner, secondOwner)
		) {
			return undefined;
		}
		const record = evidence?.record;
		const exactDirectory = exactPrivateDirectory(root, afterDirectory);
		if (
			exactDirectory &&
			evidence !== undefined &&
			record?.type === "incident-recorder-cas-decision" &&
			decisionBoundToLock(record, afterDirectory) &&
			fingerprintEquals(evidence.fingerprint, secondOwner)
		) {
			return {
				state: record.kind,
				lock: afterDirectory,
				owner: secondOwner,
				decision: record,
			};
		}
		if (secondOwner === undefined) {
			return { state: "missing", lock: afterDirectory };
		}
		const hint = evidence ? parseIdentityHint(evidence.bytes) : undefined;
		return {
			state: "invalid",
			lock: afterDirectory,
			owner: secondOwner,
			ownerActivityHint: hint ? ownerActivity(hint, current) : undefined,
		};
	} catch {
		return undefined;
	} finally {
		if (directoryDescriptor !== undefined) {
			try {
				closeSync(directoryDescriptor);
			} catch {}
		}
	}
}

function observeV2(root: RootIdentity, current: ProcessIdentity): V2Observation | undefined {
	return observeV2AtPath(root, rootChild(root, root.controlName), current);
}

function observeOwnedV2(root: RootIdentity, current: ProcessIdentity): V2Observation | undefined {
	return observeV2AtPath(root, rootChild(root, root.controlName), current, false);
}

function decisionEquals(left: Decision | undefined, right: Decision | undefined): boolean {
	return (
		left === right ||
		(left !== undefined && right !== undefined && canonicalRecordBytes(left) === canonicalRecordBytes(right))
	);
}

function observationEquals(left: V2Observation | undefined, right: V2Observation | undefined): boolean {
	return (
		left !== undefined &&
		right !== undefined &&
		left.state === right.state &&
		fingerprintEquals(left.lock, right.lock) &&
		fingerprintEquals(left.owner, right.owner) &&
		decisionEquals(left.decision, right.decision) &&
		left.ownerActivityHint === right.ownerActivityHint
	);
}

function observationSignature(observation: V2Observation): string {
	const fingerprint = (value: Fingerprint | undefined): string =>
		value
			? [
					value.dev,
					value.ino,
					value.file,
					value.directory,
					value.symbolicLink,
					value.mode,
					value.nlink,
					value.size,
					value.mtimeMs,
					value.ctimeMs,
					value.uid,
					value.gid,
				].join(":")
			: "missing";
	return `${observation.state}|${fingerprint(observation.lock)}|${fingerprint(observation.owner)}|${
		observation.decision ? canonicalRecordBytes(observation.decision) : "invalid"
	}|${observation.ownerActivityHint ?? "none"}`;
}

function unavailableReason(activity: OwnerActivity): IncidentCasTransactionUnavailableReason {
	return activity === "self"
		? "same_process_owner_untracked"
		: activity === "live"
			? "live_owner"
			: activity === "foreign"
				? "foreign_machine_owner"
				: "owner_liveness_unknown";
}

function unlinkExactFile(path: string, expected: Fingerprint | undefined): boolean {
	const current = pathFingerprint(path);
	if (!current) return true;
	if (!sameInode(current, expected) || !current.file || current.symbolicLink) return false;
	try {
		unlinkSync(path);
		return true;
	} catch {
		return false;
	}
}

function unlinkExactStableFile(path: string, expected: Fingerprint | undefined): boolean {
	const current = pathFingerprint(path);
	if (!fingerprintEquals(current, expected) || !current?.file || current.symbolicLink) return false;
	try {
		unlinkSync(path);
		return true;
	} catch {
		return false;
	}
}

function createPreparedRecord(
	root: RootIdentity,
	record: CanonicalRecord,
	runtime: IncidentCasTransactionRuntime,
	writtenStep?: IncidentCasTransactionStep,
	fsyncedStep?: IncidentCasTransactionStep,
): { path: string; fingerprint: Fingerprint } {
	const path = preparedPath(root, record);
	let descriptor: number | undefined;
	let created: Fingerprint | undefined;
	let preparedBytes: string | undefined;
	let completed = false;
	try {
		descriptor = openSync(
			path,
			constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
			0o600,
		);
		created = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		fchmodSync(descriptor, 0o600);
		preparedBytes = canonicalRecordBytes(record);
		writeFileSync(descriptor, preparedBytes);
		if (writtenStep) runtime.onStep?.(writtenStep);
		fsyncSync(descriptor);
		if (fsyncedStep) runtime.onStep?.(fsyncedStep);
		closeSync(descriptor);
		descriptor = undefined;
		runtime.onStep?.("prepare_closed");
		const file = stableFile(path);
		if (
			!file ||
			file.bytes !== canonicalRecordBytes(record) ||
			!exactPrivateRecordFile(root, file.fingerprint) ||
			file.fingerprint.nlink !== 1n
		) {
			throw new Error("CAS prepared record changed before publication");
		}
		completed = true;
		return { path, fingerprint: file.fingerprint };
	} finally {
		if (!completed && created) retireFileWithClaim(root, path, created, preparedBytes, runtime);
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function resumePublishedOwner(
	root: RootIdentity,
	current: ProcessIdentity,
	owner: OwnerDecision,
	runtime: IncidentCasTransactionRuntime,
): V2Observation | undefined {
	let directoryDescriptor: number | undefined;
	try {
		if (!rootDescriptorCurrent(root)) return undefined;
		const lockPath = rootChild(root, root.controlName);
		directoryDescriptor = openSync(lockPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const directory = fingerprintFromStat(fstatSync(directoryDescriptor, { bigint: true }));
		if (
			!exactPrivateDirectory(root, directory) ||
			!decisionBoundToLock(owner, directory) ||
			!ownerBoundToRoot(owner, root) ||
			!sameDirectoryIdentity(directory, pathFingerprint(lockPath))
		) {
			return undefined;
		}
		const evidence = recordEvidence(root, `/proc/self/fd/${directoryDescriptor}/${OWNER_NAME}`);
		if (
			evidence?.record?.type !== "incident-recorder-cas-decision" ||
			evidence.record.kind !== "owner" ||
			canonicalRecordBytes(evidence.record) !== canonicalRecordBytes(owner)
		) {
			return undefined;
		}
		fsyncSync(directoryDescriptor);
		const preparePath = preparedPath(root, owner);
		const prepare = pathFingerprint(preparePath);
		if (
			prepare &&
			(!sameInode(prepare, evidence.fingerprint) ||
				!retirePreparedEvidence(
					root,
					preparePath,
					{ bytes: canonicalRecordBytes(owner), fingerprint: prepare, record: owner },
					runtime,
				))
		)
			return undefined;
		fsyncRoot(root);
		const observation = observeV2(root, current);
		return observation?.state === "owner" &&
			observation.decision?.kind === "owner" &&
			canonicalRecordBytes(observation.decision) === canonicalRecordBytes(owner)
			? observation
			: undefined;
	} catch {
		return undefined;
	} finally {
		if (directoryDescriptor !== undefined) {
			try {
				closeSync(directoryDescriptor);
			} catch {}
		}
	}
}

function tryCreateV2(
	root: RootIdentity,
	current: ProcessIdentity,
	runtime: IncidentCasTransactionRuntime,
	trackPublished: (observation: V2Observation) => void,
): CreateAttempt {
	const lockPath = rootChild(root, root.controlName);
	const stagePath = rootChild(root, `${root.controlName}.stage`);
	let directoryDescriptor: number | undefined;
	let prepared: { path: string; fingerprint: Fingerprint } | undefined;
	let owner: OwnerDecision | undefined;
	let directory: Fingerprint | undefined;
	let published = false;
	let publishedObservation: V2Observation | undefined;
	try {
		try {
			mkdirSync(stagePath, { mode: 0o700 });
		} catch (error) {
			return (error as NodeJS.ErrnoException).code === "EEXIST" ? { state: "retry" } : { state: "failed" };
		}
		chmodSync(stagePath, 0o700);
		directoryDescriptor = openSync(stagePath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		fchmodSync(directoryDescriptor, 0o700);
		directory = fingerprintFromStat(fstatSync(directoryDescriptor, { bigint: true }));
		if (!exactPrivateDirectory(root, directory) || !fingerprintEquals(directory, pathFingerprint(stagePath)))
			throw new Error("CAS staged authority directory changed during creation");
		runtime.onStep?.("directory_created");
		owner = {
			type: "incident-recorder-cas-decision",
			version: 2,
			kind: "owner",
			lockId: randomUUID(),
			lockDev: directory.dev.toString(),
			lockIno: directory.ino.toString(),
			rootDev: root.dev.toString(),
			rootIno: root.ino.toString(),
			rootPath: root.canonicalPath,
			...current,
		};
		prepared = createPreparedRecord(root, owner, runtime, "owner_written", "owner_fsynced");
		try {
			linkSync(prepared.path, `/proc/self/fd/${directoryDescriptor}/${OWNER_NAME}`);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "EEXIST") {
				return { state: "retry" };
			}
			throw error;
		}
		runtime.onStep?.("owner_linked");
		const evidence = recordEvidence(root, `/proc/self/fd/${directoryDescriptor}/${OWNER_NAME}`);
		if (
			evidence?.record?.type !== "incident-recorder-cas-decision" ||
			evidence.record.kind !== "owner" ||
			canonicalRecordBytes(evidence.record) !== canonicalRecordBytes(owner) ||
			!sameDirectoryIdentity(directory, fingerprintFromStat(fstatSync(directoryDescriptor, { bigint: true }))) ||
			!sameDirectoryIdentity(directory, pathFingerprint(stagePath))
		) {
			throw new Error("CAS staged owner changed before publication");
		}
		fsyncSync(directoryDescriptor);
		runtime.onStep?.("owner_directory_fsynced");
		if (
			!retirePreparedEvidence(
				root,
				prepared.path,
				{ bytes: canonicalRecordBytes(owner), fingerprint: prepared.fingerprint, record: owner },
				runtime,
			)
		)
			throw new Error("CAS prepared owner could not be retired");
		runtime.onStep?.("prepare_unlinked");
		const publicationSeed = observeV2AtPath(root, stagePath, current, false);
		if (
			publicationSeed?.state !== "owner" ||
			publicationSeed.decision?.kind !== "owner" ||
			canonicalRecordBytes(publicationSeed.decision) !== canonicalRecordBytes(owner) ||
			!sameDirectoryIdentity(directory, publicationSeed.lock)
		) {
			throw new Error("CAS staged owner failed final pre-publication readback");
		}
		if (!rootDescriptorCurrent(root) || !controlDescriptorCurrent(root))
			throw new Error("CAS root changed before authority publication");
		const trackedPublicationSeed: V2Observation = { ...publicationSeed, publicationProvisional: true };
		publishedObservation = trackedPublicationSeed;
		trackPublished(trackedPublicationSeed);
		try {
			runtime.onStep?.("before_authority_publish");
			renameSync(stagePath, lockPath);
		} catch (error) {
			const fixed = observeOwnedV2(root, current);
			if (
				fixed?.state === "owner" &&
				fixed.decision?.kind === "owner" &&
				canonicalRecordBytes(fixed.decision) === canonicalRecordBytes(owner) &&
				sameDirectoryIdentity(directory, fixed.lock)
			) {
				published = true;
				publishedObservation = fixed;
				trackPublished(fixed);
			} else {
				const staged = observeV2AtPath(root, stagePath, current, false);
				if (observationEquals(publicationSeed, staged)) {
					publishedObservation = undefined;
					return pathFingerprint(lockPath) ? { state: "occupied" } : { state: "retry" };
				}
				// Neither name could prove where the staged inode landed. Preserve the
				// provisional self-owner in the same-process registry so a retry must
				// retire or reconcile it instead of silently admitting a contender.
				published = true;
				throw error;
			}
		}
		published = true;
		runtime.onStep?.("authority_fixed_name_published");
		const strictPublishedObservation = observeOwnedV2(root, current);
		if (
			strictPublishedObservation?.state !== "owner" ||
			strictPublishedObservation.decision?.kind !== "owner" ||
			canonicalRecordBytes(strictPublishedObservation.decision) !== canonicalRecordBytes(owner)
		) {
			throw new Error("CAS published owner failed pre-hook readback");
		}
		publishedObservation = strictPublishedObservation;
		trackPublished(strictPublishedObservation);
		runtime.onStep?.("authority_published");
		if (!sameDirectoryIdentity(directory, pathFingerprint(lockPath)))
			throw new Error("CAS authority publication changed before root fsync");
		fsyncRoot(root);
		runtime.onStep?.("creation_root_fsynced");
		const observation = observeV2(root, current);
		if (
			observation?.state !== "owner" ||
			observation.decision?.kind !== "owner" ||
			canonicalRecordBytes(observation.decision) !== canonicalRecordBytes(owner)
		) {
			throw new Error("CAS committed owner failed strict readback");
		}
		return { state: "acquired", observation };
	} catch {
		if (published && owner) {
			const resumed = resumePublishedOwner(root, current, owner, runtime);
			if (resumed) return { state: "acquired", observation: resumed };
			const observation = observeOwnedV2(root, current);
			if (
				observation?.state === "owner" &&
				observation.decision?.kind === "owner" &&
				canonicalRecordBytes(observation.decision) === canonicalRecordBytes(owner)
			) {
				return { state: "published", observation };
			}
		}
		return publishedObservation
			? { state: "published", observation: publishedObservation }
			: published
				? { state: "failed" }
				: { state: "retry" };
	} finally {
		if (directoryDescriptor !== undefined) {
			try {
				closeSync(directoryDescriptor);
			} catch {}
		}
		if (!published) {
			if (prepared && owner) {
				retirePreparedEvidence(
					root,
					prepared.path,
					{ bytes: canonicalRecordBytes(owner), fingerprint: prepared.fingerprint, record: owner },
					runtime,
				);
			}
			const staged = pathFingerprint(stagePath);
			if (directory && sameInode(staged, directory)) {
				try {
					const ownerPath = join(stagePath, OWNER_NAME);
					const ownerFile = pathFingerprint(ownerPath);
					if (ownerFile) unlinkExactFile(ownerPath, ownerFile);
					rmdirSync(stagePath);
					fsyncRoot(root);
				} catch {}
			}
		}
	}
}

function matureInvalidObservation(
	root: RootIdentity,
	observation: V2Observation,
	runtime: IncidentCasTransactionRuntime,
): boolean {
	const signature = observationSignature(observation);
	const key = `${root.key}|${observation.lock.dev}:${observation.lock.ino}`;
	const monotonicNow = runtimeMonotonicTimeMs(runtime);
	const prior = invalidObservations.get(key);
	if (!prior || prior.signature !== signature || monotonicNow < prior.firstSeenMonotonicMs) {
		invalidObservations.set(key, { signature, firstSeenMonotonicMs: monotonicNow });
		return false;
	}
	return monotonicNow - prior.firstSeenMonotonicMs >= ORPHAN_LOCK_GRACE_MS;
}

function stableInvalidObservation(
	root: RootIdentity,
	current: ProcessIdentity,
	observation: V2Observation,
): V2Observation | undefined {
	Atomics.wait(lockStabilityWait, 0, 0, LOCK_STABILITY_RECHECK_MS);
	const second = observeV2(root, current);
	return observationEquals(observation, second) ? second : undefined;
}

function sameDirectoryIdentity(left: Fingerprint | undefined, right: Fingerprint | undefined): boolean {
	return (
		sameInode(left, right) &&
		left?.directory === true &&
		right?.directory === true &&
		left.symbolicLink === false &&
		right.symbolicLink === false &&
		left.mode === right.mode &&
		left.uid === right.uid &&
		left.gid === right.gid
	);
}

function recoveryStillAllowed(observation: V2Observation, current: ProcessIdentity): boolean {
	if (observation.state === "quarantine") return true;
	if (observation.state === "owner") {
		return observation.decision?.kind === "owner" && ownerActivity(observation.decision, current) === "stale";
	}
	return observation.ownerActivityHint === undefined || observation.ownerActivityHint === "stale";
}

function installMissingOwnerDecision(
	root: RootIdentity,
	current: ProcessIdentity,
	expected: V2Observation,
	runtime: IncidentCasTransactionRuntime,
): V2Observation | "changed" | "failed" {
	if (expected.state !== "missing") return expected;
	const decision: QuarantineDecision = {
		type: "incident-recorder-cas-decision",
		version: 2,
		kind: "quarantine",
		recordId: randomUUID(),
		lockDev: expected.lock.dev.toString(),
		lockIno: expected.lock.ino.toString(),
		reason: "owner-missing",
		...current,
	};
	let prepared: { path: string; fingerprint: Fingerprint } | undefined;
	let directoryDescriptor: number | undefined;
	let published = false;
	try {
		prepared = createPreparedRecord(root, decision, runtime);
		const fresh = observeV2(root, current);
		if (!observationEquals(expected, fresh)) return "changed";
		const lockPath = rootChild(root, root.controlName);
		directoryDescriptor = openSync(lockPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(directoryDescriptor, { bigint: true }));
		if (
			!fingerprintEquals(expected.lock, opened) ||
			pathFingerprint(`/proc/self/fd/${directoryDescriptor}/${OWNER_NAME}`)
		)
			return "changed";
		runtime.onStep?.("before_quarantine_decision_link");
		try {
			linkSync(prepared.path, `/proc/self/fd/${directoryDescriptor}/${OWNER_NAME}`);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "EEXIST") return "changed";
			throw error;
		}
		published = true;
		runtime.onStep?.("quarantine_decision_linked");
		fsyncSync(directoryDescriptor);
		if (
			!retirePreparedEvidence(
				root,
				prepared.path,
				{ bytes: canonicalRecordBytes(decision), fingerprint: prepared.fingerprint, record: decision },
				runtime,
			)
		)
			throw new Error("CAS quarantine decision prepare link could not be retired");
		fsyncRoot(root);
		const observation = observeV2(root, current);
		return observation?.state === "quarantine" && decisionEquals(observation.decision, decision)
			? observation
			: "changed";
	} catch {
		return "failed";
	} finally {
		if (!published && prepared) {
			retirePreparedEvidence(
				root,
				prepared.path,
				{ bytes: canonicalRecordBytes(decision), fingerprint: prepared.fingerprint, record: decision },
				runtime,
			);
			try {
				fsyncRoot(root);
			} catch {}
		}
		if (directoryDescriptor !== undefined) {
			try {
				closeSync(directoryDescriptor);
			} catch {}
		}
	}
}

function quarantineContainerName(root: RootIdentity): string {
	return `${root.controlName}.quarantine-slot`;
}

function claimMatchesSource(claim: QuarantineClaim, source: Fingerprint): boolean {
	return (
		claim.lockDev === source.dev.toString() &&
		claim.lockIno === source.ino.toString() &&
		claim.lockMode === source.mode.toString() &&
		claim.lockUid === source.uid.toString() &&
		claim.lockGid === source.gid.toString()
	);
}

function claimMatchesRetainedSource(claim: QuarantineClaim, source: Fingerprint): boolean {
	if (claimMatchesSource(claim, source)) return true;
	const claimedMode = BigInt(claim.lockMode);
	return (
		claim.lockDev === source.dev.toString() &&
		claim.lockIno === source.ino.toString() &&
		claim.lockUid === source.uid.toString() &&
		claim.lockGid === source.gid.toString() &&
		source.directory &&
		!source.symbolicLink &&
		(source.mode & 0o777n) === 0o700n &&
		(claimedMode & ~0o777n) === (source.mode & ~0o777n)
	);
}

function ensureQuarantineContainer(
	root: RootIdentity,
	current: ProcessIdentity,
	source: Fingerprint,
	runtime: IncidentCasTransactionRuntime,
): { descriptor: number; path: string; fingerprint: Fingerprint } | undefined {
	const path = rootChild(root, quarantineContainerName(root));
	let descriptor: number | undefined;
	let prepared: { path: string; fingerprint: Fingerprint } | undefined;
	let preparedRecord: QuarantineClaim | undefined;
	let published = false;
	try {
		try {
			mkdirSync(path, { mode: 0o700 });
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
		}
		const beforeOpen = pathFingerprint(path);
		if (
			!beforeOpen?.directory ||
			beforeOpen.symbolicLink ||
			beforeOpen.uid !== root.controlUid ||
			beforeOpen.gid !== root.controlGid
		)
			return undefined;
		if ((beforeOpen.mode & 0o777n) !== 0o700n) chmodSync(path, 0o700);
		descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		fchmodSync(descriptor, 0o700);
		const directory = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (!exactPrivateDirectory(root, directory) || !sameDirectoryIdentity(directory, pathFingerprint(path)))
			return undefined;
		fsyncSync(descriptor);
		const claimPath = `/proc/self/fd/${descriptor}/${CLAIM_NAME}`;
		let evidence = recordEvidence(root, claimPath);
		if (!evidence) {
			const claim: QuarantineClaim = {
				type: "incident-recorder-cas-quarantine-claim",
				version: 2,
				claimId: randomUUID(),
				lockDev: source.dev.toString(),
				lockIno: source.ino.toString(),
				lockMode: source.mode.toString(),
				lockUid: source.uid.toString(),
				lockGid: source.gid.toString(),
				...current,
			};
			preparedRecord = claim;
			prepared = createPreparedRecord(root, claim, runtime);
			try {
				linkSync(prepared.path, claimPath);
				published = true;
				runtime.onStep?.("quarantine_claim_linked");
				fsyncSync(descriptor);
				if (
					!retirePreparedEvidence(
						root,
						prepared.path,
						{ bytes: canonicalRecordBytes(claim), fingerprint: prepared.fingerprint, record: claim },
						runtime,
					)
				)
					throw new Error("CAS quarantine claim prepare link could not be retired");
				fsyncRoot(root);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			}
			evidence = recordEvidence(root, claimPath);
		}
		const record = evidence?.record;
		if (
			record?.type !== "incident-recorder-cas-quarantine-claim" ||
			!claimMatchesSource(record, source) ||
			!sameDirectoryIdentity(directory, pathFingerprint(path))
		) {
			return undefined;
		}
		const result = { descriptor, path, fingerprint: directory };
		descriptor = undefined;
		return result;
	} catch {
		return undefined;
	} finally {
		if (!published && prepared) {
			if (preparedRecord) {
				retirePreparedEvidence(
					root,
					prepared.path,
					{
						bytes: canonicalRecordBytes(preparedRecord),
						fingerprint: prepared.fingerprint,
						record: preparedRecord,
					},
					runtime,
				);
			} else {
				retireFileWithClaim(root, prepared.path, prepared.fingerprint, undefined, runtime);
			}
			try {
				fsyncRoot(root);
			} catch {}
		}
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

type QuarantineRetirement = "blocked" | "pending" | "retired";

function quarantineClaimAt(
	root: RootIdentity,
	containerDescriptor: number,
): { evidence: RecordEvidence | undefined; fingerprint: Fingerprint | undefined } {
	const path = `/proc/self/fd/${containerDescriptor}/${CLAIM_NAME}`;
	return { evidence: recordEvidence(root, path), fingerprint: pathFingerprint(path) };
}

function retireQuarantineContainer(
	root: RootIdentity,
	container: { descriptor: number; path: string; fingerprint: Fingerprint },
	requireValidClaim: boolean,
): QuarantineRetirement {
	const claimPath = `/proc/self/fd/${container.descriptor}/${CLAIM_NAME}`;
	const occupantPath = `/proc/self/fd/${container.descriptor}/${OCCUPANT_NAME}`;
	try {
		const openedContainer = fingerprintFromStat(fstatSync(container.descriptor, { bigint: true }));
		if (
			!sameDirectoryIdentity(openedContainer, container.fingerprint) ||
			!sameDirectoryIdentity(openedContainer, pathFingerprint(container.path)) ||
			!exactPrivateDirectory(root, openedContainer)
		)
			return "blocked";
		const initialClaim = quarantineClaimAt(root, container.descriptor);
		const claim = initialClaim.evidence?.record;
		if (requireValidClaim && claim?.type !== "incident-recorder-cas-quarantine-claim") return "blocked";
		let occupant = pathFingerprint(occupantPath);
		if (
			requireValidClaim &&
			occupant &&
			(claim?.type !== "incident-recorder-cas-quarantine-claim" || !claimMatchesRetainedSource(claim, occupant))
		)
			return "blocked";

		if (occupant?.directory && !occupant.symbolicLink) {
			if (occupant.uid !== root.controlUid || occupant.gid !== root.controlGid) return "blocked";
			if ((occupant.mode & 0o777n) !== 0o700n) chmodSync(occupantPath, 0o700);
			let occupantDescriptor: number | undefined;
			let directory: ReturnType<typeof opendirSync> | undefined;
			let exhausted = false;
			let unsupportedNestedEntry = false;
			try {
				occupantDescriptor = openSync(
					occupantPath,
					constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
				);
				fchmodSync(occupantDescriptor, 0o700);
				const openedOccupant = fingerprintFromStat(fstatSync(occupantDescriptor, { bigint: true }));
				if (!sameInode(openedOccupant, occupant) || !sameInode(openedOccupant, pathFingerprint(occupantPath)))
					return "blocked";
				directory = opendirSync(`/proc/self/fd/${occupantDescriptor}`);
				let examined = 0;
				while (examined < MAX_QUARANTINE_CLEANUP_ENTRIES) {
					const entry = directory.readSync();
					if (!entry) {
						exhausted = true;
						break;
					}
					examined += 1;
					const entryPath = `/proc/self/fd/${occupantDescriptor}/${entry.name}`;
					const entryFingerprint = pathFingerprint(entryPath);
					if (!entryFingerprint) continue;
					if (entryFingerprint.directory && !entryFingerprint.symbolicLink) {
						try {
							rmdirSync(entryPath);
						} catch {
							unsupportedNestedEntry = true;
						}
					} else if (!unlinkExactNonDirectory(entryPath, entryFingerprint)) {
						return "blocked";
					}
				}
				fsyncSync(occupantDescriptor);
			} finally {
				if (directory) {
					try {
						directory.closeSync();
					} catch {}
				}
				if (occupantDescriptor !== undefined) {
					try {
						closeSync(occupantDescriptor);
					} catch {}
				}
			}
			if (unsupportedNestedEntry) return "blocked";
			if (!exhausted) return "pending";
			occupant = pathFingerprint(occupantPath);
			if (!occupant?.directory || occupant.symbolicLink) return "blocked";
			try {
				rmdirSync(occupantPath);
			} catch (error) {
				return (error as NodeJS.ErrnoException).code === "ENOTEMPTY" ? "pending" : "blocked";
			}
		} else if (occupant) {
			if (!unlinkExactNonDirectory(occupantPath, occupant)) return "blocked";
		}

		fsyncSync(container.descriptor);
		const stableClaim = quarantineClaimAt(root, container.descriptor);
		if (stableClaim.fingerprint) {
			if (stableClaim.fingerprint.directory) return "blocked";
			if (requireValidClaim) {
				const record = stableClaim.evidence?.record;
				if (
					record?.type !== "incident-recorder-cas-quarantine-claim" ||
					claim?.type !== "incident-recorder-cas-quarantine-claim" ||
					canonicalRecordBytes(record) !== canonicalRecordBytes(claim) ||
					!fingerprintEquals(stableClaim.evidence?.fingerprint, stableClaim.fingerprint)
				)
					return "blocked";
			}
			if (!unlinkExactNonDirectory(claimPath, stableClaim.fingerprint)) return "blocked";
		}
		fsyncSync(container.descriptor);
		if (pathFingerprint(occupantPath) || pathFingerprint(claimPath)) return "blocked";
		if (!sameDirectoryIdentity(openedContainer, pathFingerprint(container.path))) return "blocked";
		try {
			rmdirSync(container.path);
		} catch (error) {
			return (error as NodeJS.ErrnoException).code === "ENOTEMPTY" ? "pending" : "blocked";
		}
		fsyncRoot(root, false);
		forgetArtifact(root, container.path);
		return "retired";
	} catch {
		return "blocked";
	}
}

function quarantineObservation(
	root: RootIdentity,
	current: ProcessIdentity,
	expectedInput: V2Observation,
	runtime: IncidentCasTransactionRuntime,
): QuarantineOutcome {
	let expected = expectedInput;
	if (expected.state === "missing") {
		const installed = installMissingOwnerDecision(root, current, expected, runtime);
		if (installed === "changed" || installed === "failed") return installed;
		expected = installed;
	}
	if (!recoveryStillAllowed(expected, current)) return "changed";
	const container = ensureQuarantineContainer(root, current, expected.lock, runtime);
	if (!container) return "conflict";
	try {
		const occupantPath = `/proc/self/fd/${container.descriptor}/${OCCUPANT_NAME}`;
		const existingOccupant = pathFingerprint(occupantPath);
		if (existingOccupant) {
			if (!sameInode(existingOccupant, expected.lock)) return "conflict";
			fsyncSync(container.descriptor);
			fsyncRoot(root);
			runtime.onStep?.("quarantine_root_fsynced");
			return retireQuarantineContainer(root, container, true) === "retired" ? "completed" : "failed";
		}
		runtime.onStep?.("before_quarantine_revalidation");
		const fresh = observeV2(root, current);
		if (!observationEquals(expected, fresh) || !fresh || !recoveryStillAllowed(fresh, current)) return "changed";
		runtime.onStep?.("before_quarantine_move");
		try {
			renameSync(rootChild(root, root.controlName), occupantPath);
		} catch {
			const moved = pathFingerprint(occupantPath);
			if (sameInode(moved, expected.lock)) {
				fsyncSync(container.descriptor);
				fsyncRoot(root);
				runtime.onStep?.("quarantine_root_fsynced");
				return retireQuarantineContainer(root, container, true) === "retired" ? "completed" : "failed";
			}
			const changed = observeV2(root, current);
			return changed && !observationEquals(expected, changed) ? "changed" : "failed";
		}
		runtime.onStep?.("lock_quarantined");
		if (!sameInode(pathFingerprint(occupantPath), expected.lock)) return "conflict";
		fsyncSync(container.descriptor);
		fsyncRoot(root);
		runtime.onStep?.("quarantine_root_fsynced");
		return retireQuarantineContainer(root, container, true) === "retired" ? "completed" : "failed";
	} catch {
		return "failed";
	} finally {
		try {
			closeSync(container.descriptor);
		} catch {}
	}
}

function ownedObservationMatches(
	root: RootIdentity,
	expected: V2Observation,
	current: V2Observation | undefined,
): boolean {
	if (expected.state !== "owner" || expected.decision?.kind !== "owner" || !ownerBoundToRoot(expected.decision, root))
		return false;
	if (expected.publicationProvisional !== true) return observationEquals(expected, current);
	return (
		current?.state === "owner" &&
		current.decision?.kind === "owner" &&
		canonicalRecordBytes(current.decision) === canonicalRecordBytes(expected.decision) &&
		sameDirectoryIdentity(expected.lock, current.lock) &&
		exactPrivateDirectory(root, current.lock) &&
		sameInode(expected.owner, current.owner) &&
		current.owner !== undefined &&
		exactPrivateRecordFile(root, current.owner) &&
		current.owner.nlink === 1n &&
		decisionBoundToLock(current.decision, current.lock)
	);
}

function persistRootDetachment(
	root: RootIdentity,
	expected: V2Observation,
	runtime: IncidentCasTransactionRuntime,
): boolean {
	const owner = expected.decision?.kind === "owner" ? expected.decision : undefined;
	if (!owner || !ownerBoundToRoot(owner, root) || !rootDescriptorValid(root) || !controlDescriptorCurrent(root))
		return false;
	const evidence = rootDetachmentForOwner(owner);
	const evidenceBytes = canonicalRecordBytes(evidence);
	const path = rootChild(root, `${root.controlName}.detached-slot`);
	const preparePath = preparedPath(root, evidence);
	let prepared: { path: string; fingerprint: Fingerprint } | undefined;
	let fixedEstablished = false;
	try {
		let current = recordEvidence(root, path);
		if (current) {
			if (
				current.record?.type !== "incident-recorder-cas-root-detachment" ||
				canonicalRecordBytes(current.record) !== evidenceBytes ||
				!rootDetachmentBoundToOwner(current.record, owner)
			)
				return false;
			fixedEstablished = true;
		} else {
			if (pathFingerprint(path)) return false;
			const resumable = directRecordEvidence(root, preparePath);
			if (resumable) {
				if (
					resumable.record?.type !== "incident-recorder-cas-root-detachment" ||
					canonicalRecordBytes(resumable.record) !== evidenceBytes ||
					!rootDetachmentBoundToOwner(resumable.record, owner) ||
					resumable.fingerprint.nlink !== 1n
				)
					return false;
				prepared = { path: preparePath, fingerprint: resumable.fingerprint };
			} else {
				if (pathFingerprint(preparePath)) return false;
				prepared = createPreparedRecord(
					root,
					evidence,
					runtime,
					"root_detachment_written",
					"root_detachment_fsynced",
				);
			}
			runtime.onStep?.("before_root_detachment_link");
			try {
				linkSync(prepared.path, path);
				fixedEstablished = true;
				runtime.onStep?.("root_detachment_linked");
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			}
			current = recordEvidence(root, path);
		}
		if (
			current?.record?.type !== "incident-recorder-cas-root-detachment" ||
			canonicalRecordBytes(current.record) !== evidenceBytes ||
			!rootDetachmentBoundToOwner(current.record, owner)
		)
			return false;
		fsyncRoot(root, false);
		const prepareFingerprint = pathFingerprint(preparePath);
		if (prepareFingerprint) {
			if (!sameInode(prepareFingerprint, current.fingerprint)) return false;
			runtime.onStep?.("before_root_detachment_prepare_unlink");
			if (!retireFileWithClaim(root, preparePath, prepareFingerprint, evidenceBytes, runtime, undefined, false))
				return false;
		}
		fsyncRoot(root, false);
		const durable = recordEvidence(root, path);
		if (
			durable?.record?.type !== "incident-recorder-cas-root-detachment" ||
			canonicalRecordBytes(durable.record) !== evidenceBytes ||
			!rootDetachmentBoundToOwner(durable.record, owner) ||
			durable.fingerprint.nlink !== 1n
		)
			return false;
		runtime.onStep?.("root_detachment_root_fsynced");
		return true;
	} catch {
		return false;
	} finally {
		if (!fixedEstablished && prepared) {
			retirePreparedEvidence(
				root,
				prepared.path,
				{ bytes: evidenceBytes, fingerprint: prepared.fingerprint, record: evidence },
				runtime,
				undefined,
				false,
			);
			try {
				fsyncRoot(root, false);
			} catch {}
		}
	}
}

function retireRootDetachment(
	root: RootIdentity,
	expected: V2Observation,
	runtime: IncidentCasTransactionRuntime,
): boolean {
	const owner = expected.decision?.kind === "owner" ? expected.decision : undefined;
	if (!owner) return false;
	const path = rootChild(root, `${root.controlName}.detached-slot`);
	const expectedEvidence = rootDetachmentForOwner(owner);
	const expectedBytes = canonicalRecordBytes(expectedEvidence);
	const claimPath = preparedPath(root, expectedEvidence);
	let claimCreated = false;
	let completed = false;
	try {
		let evidence = recordEvidence(root, path);
		if (!evidence) {
			if (pathFingerprint(path)) return false;
			const remainingClaim = directRecordEvidence(root, claimPath);
			if (remainingClaim) {
				if (
					remainingClaim.record?.type !== "incident-recorder-cas-root-detachment" ||
					canonicalRecordBytes(remainingClaim.record) !== expectedBytes ||
					!rootDetachmentBoundToOwner(remainingClaim.record, owner) ||
					remainingClaim.fingerprint.nlink !== 1n ||
					!unlinkExactStableFile(claimPath, remainingClaim.fingerprint)
				)
					return false;
			} else if (pathFingerprint(claimPath)) {
				return false;
			}
			fsyncRoot(root, false);
			completed = true;
			return pathFingerprint(path) === undefined && pathFingerprint(claimPath) === undefined;
		}
		if (
			evidence.record?.type !== "incident-recorder-cas-root-detachment" ||
			canonicalRecordBytes(evidence.record) !== expectedBytes ||
			!rootDetachmentBoundToOwner(evidence.record, owner)
		)
			return false;
		runtime.onStep?.("before_root_detachment_retire");
		let claim = directRecordEvidence(root, claimPath);
		if (!claim) {
			if (pathFingerprint(claimPath)) return false;
			try {
				linkSync(path, claimPath);
				claimCreated = true;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			}
			claim = directRecordEvidence(root, claimPath);
		}
		evidence = recordEvidence(root, path);
		if (
			claim?.record?.type !== "incident-recorder-cas-root-detachment" ||
			canonicalRecordBytes(claim.record) !== expectedBytes ||
			!rootDetachmentBoundToOwner(claim.record, owner) ||
			evidence?.record?.type !== "incident-recorder-cas-root-detachment" ||
			canonicalRecordBytes(evidence.record) !== expectedBytes ||
			!rootDetachmentBoundToOwner(evidence.record, owner) ||
			!sameInode(claim.fingerprint, evidence.fingerprint) ||
			claim.fingerprint.nlink !== 2n ||
			evidence.fingerprint.nlink !== 2n
		)
			return false;
		fsyncRoot(root, false);
		if (!unlinkExactStableFile(path, evidence.fingerprint)) return false;
		runtime.onStep?.("root_detachment_unlinked");
		fsyncRoot(root, false);
		const remainingClaim = directRecordEvidence(root, claimPath);
		if (
			remainingClaim?.record?.type !== "incident-recorder-cas-root-detachment" ||
			canonicalRecordBytes(remainingClaim.record) !== expectedBytes ||
			!rootDetachmentBoundToOwner(remainingClaim.record, owner) ||
			remainingClaim.fingerprint.nlink !== 1n ||
			!unlinkExactStableFile(claimPath, remainingClaim.fingerprint)
		)
			return false;
		fsyncRoot(root, false);
		runtime.onStep?.("root_detachment_retirement_fsynced");
		completed = true;
		return pathFingerprint(path) === undefined && pathFingerprint(claimPath) === undefined;
	} catch {
		return false;
	} finally {
		if (!completed && claimCreated) {
			const claim = pathFingerprint(claimPath);
			const fixed = pathFingerprint(path);
			if (claim && fixed && sameInode(claim, fixed) && unlinkExactFile(claimPath, claim)) {
				try {
					fsyncRoot(root, false);
				} catch {}
			}
		}
	}
}

function cleanupRetiredAuthority(
	root: RootIdentity,
	retiredPath: string,
	expected: V2Observation,
	runtime: IncidentCasTransactionRuntime,
): boolean {
	let descriptor: number | undefined;
	try {
		const retired = pathFingerprint(retiredPath);
		if (!retired) {
			fsyncRoot(root, false);
			runtime.onStep?.("cleanup_root_fsynced");
			return true;
		}
		if (!sameInode(retired, expected.lock) || !retired.directory || retired.symbolicLink) return false;
		descriptor = openSync(retiredPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (!sameInode(opened, expected.lock) || !sameInode(opened, pathFingerprint(retiredPath))) return false;
		const ownerPath = `/proc/self/fd/${descriptor}/${OWNER_NAME}`;
		const ownerFingerprint = pathFingerprint(ownerPath);
		if (ownerFingerprint) {
			const evidence = recordEvidence(root, ownerPath);
			if (
				evidence?.record?.type !== "incident-recorder-cas-decision" ||
				evidence.record.kind !== "owner" ||
				expected.decision?.kind !== "owner" ||
				canonicalRecordBytes(evidence.record) !== canonicalRecordBytes(expected.decision) ||
				!unlinkExactFile(ownerPath, evidence.fingerprint)
			) {
				return false;
			}
			runtime.onStep?.("released_owner_unlinked");
			fsyncSync(descriptor);
		}
		closeSync(descriptor);
		descriptor = undefined;
		rmdirSync(retiredPath);
		runtime.onStep?.("released_directory_removed");
		fsyncRoot(root, false);
		runtime.onStep?.("cleanup_root_fsynced");
		return true;
	} catch {
		return false;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function isPromiseLike(value: unknown): boolean {
	try {
		return (
			value !== null &&
			(typeof value === "object" || typeof value === "function") &&
			typeof (value as { then?: unknown }).then === "function"
		);
	} catch {
		return true;
	}
}

function safeRelativeComponent(component: string): boolean {
	return (
		component.length > 0 &&
		component !== "." &&
		component !== ".." &&
		!component.includes("/") &&
		!component.includes("\\") &&
		!component.includes("\0") &&
		!isAbsolute(component)
	);
}

function safeMode(mode: number): number {
	if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) throw new TypeError("CAS capability mode is invalid");
	return mode;
}

function safeNonnegativeInteger(value: number, label: string): number {
	if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`CAS capability ${label} is invalid`);
	return value;
}

function descriptorDirectoryPath(descriptor: number): string {
	return `/proc/self/fd/${descriptor}`;
}

function duplicateDirectoryDescriptor(descriptor: number): number {
	return openSync(
		`${descriptorDirectoryPath(descriptor)}/.`,
		constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
	);
}

function withRelativeParent<T>(
	baseDescriptor: number,
	components: readonly string[],
	operation: (path: string, parentDescriptor: number) => T,
): T {
	let descriptor = duplicateDirectoryDescriptor(baseDescriptor);
	try {
		for (const component of components.slice(0, -1)) {
			const next = openSync(
				`${descriptorDirectoryPath(descriptor)}/${component}`,
				constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
			);
			closeSync(descriptor);
			descriptor = next;
		}
		const path =
			components.length === 0
				? `${descriptorDirectoryPath(descriptor)}/.`
				: `${descriptorDirectoryPath(descriptor)}/${components[components.length - 1]}`;
		return operation(path, descriptor);
	} finally {
		try {
			closeSync(descriptor);
		} catch {}
	}
}

function directoryEntryKind(entry: {
	isBlockDevice(): boolean;
	isCharacterDevice(): boolean;
	isDirectory(): boolean;
	isFIFO(): boolean;
	isFile(): boolean;
	isSocket(): boolean;
	isSymbolicLink(): boolean;
}): IncidentCasDirectoryEntryKind {
	if (entry.isFile()) return "file";
	if (entry.isDirectory()) return "directory";
	if (entry.isSymbolicLink()) return "symbolic_link";
	if (entry.isBlockDevice()) return "block_device";
	if (entry.isCharacterDevice()) return "character_device";
	if (entry.isFIFO()) return "fifo";
	if (entry.isSocket()) return "socket";
	return "unknown";
}

function fileOpenFlags(options: IncidentCasFileOpenOptions): number {
	let flags = constants.O_NOFOLLOW | constants.O_NONBLOCK;
	flags |=
		options.access === "read"
			? constants.O_RDONLY
			: options.access === "write"
				? constants.O_WRONLY
				: constants.O_RDWR;
	if (options.create === "exclusive") flags |= constants.O_CREAT | constants.O_EXCL;
	if (options.truncate) {
		if (options.access === "read") throw new TypeError("CAS read-only file cannot be truncated");
		flags |= constants.O_TRUNC;
	}
	return flags;
}

function sanitizeCapabilityFilesystemError(error: unknown): unknown {
	if (!error || typeof error !== "object") return error;
	const candidate = error as {
		code?: unknown;
		dest?: unknown;
		message?: unknown;
		path?: unknown;
		stack?: unknown;
	};
	const code = typeof candidate.code === "string" ? candidate.code : undefined;
	const exposesDescriptorPath = [candidate.message, candidate.stack, candidate.path, candidate.dest].some(
		(value) => typeof value === "string" && value.includes("/proc/self/fd/"),
	);
	if (!code && !exposesDescriptorPath) return error;
	const sanitized = new Error(
		code ? `CAS capability filesystem operation failed (${code})` : "CAS capability filesystem operation failed",
	);
	sanitized.name = "IncidentCasCapabilityFilesystemError";
	if (code) {
		Object.defineProperty(sanitized, "code", {
			configurable: false,
			enumerable: true,
			value: code,
			writable: false,
		});
	}
	return sanitized;
}

function makeRootMutationCapability(
	root: RootIdentity,
	baseDescriptor: number,
	publicBasePath: string,
	assertActive: () => void,
): IncidentCasRootMutation {
	const owner = Symbol("incident-cas-root-capability");
	const checked = <T>(operation: () => T): T => {
		try {
			assertActive();
			const value = operation();
			assertActive();
			return value;
		} catch (error) {
			throw sanitizeCapabilityFilesystemError(error);
		}
	};
	const createRelative = (components: readonly string[]): IncidentCasRelativePath => {
		if (!components.every(safeRelativeComponent)) throw new TypeError("CAS relative path component is invalid");
		const token = Object.freeze({}) as IncidentCasRelativePath;
		relativePathStates.set(token, { owner, components: Object.freeze([...components]) });
		return token;
	};
	const tokenComponents = (path: IncidentCasRelativePath): readonly string[] => {
		assertActive();
		const state = relativePathStates.get(path);
		if (!state || state.owner !== owner) throw new TypeError("CAS relative path belongs to another capability");
		return state.components;
	};
	const withOpened = <T>(
		components: readonly string[],
		flags: number,
		mode: number | undefined,
		operation: (descriptor: number) => T,
	): T =>
		withRelativeParent(baseDescriptor, components, (path) => {
			let descriptor: number | undefined;
			try {
				descriptor = mode === undefined ? openSync(path, flags) : openSync(path, flags, mode);
				return operation(descriptor);
			} finally {
				if (descriptor !== undefined) {
					try {
						closeSync(descriptor);
					} catch {}
				}
			}
		});
	const statComponents = (components: readonly string[]): BigIntStats => {
		const lexical = withRelativeParent(baseDescriptor, components, (path) => lstatSync(path, { bigint: true }));
		if (lexical.isSymbolicLink()) throw new Error("CAS capability refuses to follow a symbolic link");
		const flags =
			constants.O_RDONLY |
			constants.O_NOFOLLOW |
			constants.O_NONBLOCK |
			(lexical.isDirectory() ? constants.O_DIRECTORY : 0);
		return withOpened(components, flags, undefined, (descriptor) => fstatSync(descriptor, { bigint: true }));
	};
	const withFile = <T>(
		path: IncidentCasRelativePath,
		options: IncidentCasFileOpenOptions,
		operation: (file: IncidentCasFileMutation) => T,
	): T => {
		const components = tokenComponents(path);
		const mode = safeMode(options.mode ?? 0o600);
		return checked(() =>
			withOpened(
				components,
				fileOpenFlags(options),
				options.create === "exclusive" ? mode : undefined,
				(descriptor) => {
					if (options.create === "exclusive") fchmodSync(descriptor, mode);
					const opened = fstatSync(descriptor, { bigint: true });
					if (!opened.isFile()) throw new Error("CAS file capability requires a regular file");
					let fileActive = true;
					const assertFileActive = (): void => {
						if (!fileActive) throw new TypeError("CAS file capability is no longer active");
						assertActive();
					};
					const fileChecked = <V>(fileOperation: () => V): V => {
						try {
							assertFileActive();
							const value = fileOperation();
							assertFileActive();
							return value;
						} catch (error) {
							throw sanitizeCapabilityFilesystemError(error);
						}
					};
					const file = Object.freeze({
						stat: () => fileChecked(() => fstatSync(descriptor, { bigint: true })),
						read: (target: Uint8Array, offset: number, length: number, position: number | null) =>
							fileChecked(() => {
								const checkedOffset = safeNonnegativeInteger(offset, "read offset");
								const checkedLength = safeNonnegativeInteger(length, "read length");
								if (checkedOffset + checkedLength > target.byteLength)
									throw new RangeError("CAS file read exceeds the target buffer");
								if (position !== null) safeNonnegativeInteger(position, "read position");
								const buffer = Buffer.from(target.buffer, target.byteOffset, target.byteLength);
								return readSync(descriptor, buffer, checkedOffset, checkedLength, position);
							}),
						write: (source: Uint8Array, offset: number, length: number, position: number | null) =>
							fileChecked(() => {
								const checkedOffset = safeNonnegativeInteger(offset, "write offset");
								const checkedLength = safeNonnegativeInteger(length, "write length");
								if (checkedOffset + checkedLength > source.byteLength)
									throw new RangeError("CAS file write exceeds the source buffer");
								if (position !== null) safeNonnegativeInteger(position, "write position");
								const buffer = Buffer.from(source.buffer, source.byteOffset, source.byteLength);
								return writeSync(descriptor, buffer, checkedOffset, checkedLength, position);
							}),
						writeText: (value: string, position: number | null) =>
							fileChecked(() => {
								if (position !== null) safeNonnegativeInteger(position, "write position");
								return writeSync(descriptor, value, position, "utf8");
							}),
						truncate: (length: number) =>
							fileChecked(() => ftruncateSync(descriptor, safeNonnegativeInteger(length, "truncate length"))),
						chmod: (nextMode: number) => fileChecked(() => fchmodSync(descriptor, safeMode(nextMode))),
						sync: () => fileChecked(() => fsyncSync(descriptor)),
					}) satisfies IncidentCasFileMutation;
					let value: T | undefined;
					let callbackError: unknown;
					try {
						value = operation(file);
					} catch (error) {
						callbackError = error;
					} finally {
						fileActive = false;
					}
					if (callbackError !== undefined) throw callbackError;
					if (isPromiseLike(value)) throw new TypeError("CAS file operation must complete synchronously");
					return value as T;
				},
			),
		);
	};
	const withDirectory = <T>(path: IncidentCasRelativePath, operation: (directory: IncidentCasRootMutation) => T): T =>
		checked(() => {
			const components = tokenComponents(path);
			return withOpened(
				components,
				constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
				undefined,
				(descriptor) => {
					let directoryActive = true;
					const nested = makeRootMutationCapability(root, descriptor, join(publicBasePath, ...components), () => {
						if (!directoryActive) throw new TypeError("CAS directory capability is no longer active");
						assertActive();
					});
					let value: T | undefined;
					let callbackError: unknown;
					try {
						value = operation(nested);
					} catch (error) {
						callbackError = error;
					} finally {
						directoryActive = false;
					}
					if (callbackError !== undefined) throw callbackError;
					if (isPromiseLike(value)) throw new TypeError("CAS directory operation must complete synchronously");
					return value as T;
				},
			);
		});
	const capability: IncidentCasRootMutation = {
		relative: (...components) => checked(() => createRelative(components)),
		publicPath: (path) =>
			checked(() => {
				const value = join(publicBasePath, ...tokenComponents(path));
				if (value.includes("/proc/self/fd/")) throw new Error("CAS public path is not canonical");
				return value;
			}),
		exists: (path) =>
			checked(() =>
				withRelativeParent(baseDescriptor, tokenComponents(path), (target) => {
					try {
						lstatSync(target);
						return true;
					} catch (error) {
						if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
						throw error;
					}
				}),
			),
		lstat: (path) =>
			checked(() =>
				withRelativeParent(baseDescriptor, tokenComponents(path), (target) => {
					try {
						return lstatSync(target, { bigint: true });
					} catch (error) {
						if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
						throw error;
					}
				}),
			),
		stat: (path) => checked(() => statComponents(tokenComponents(path))),
		statfs: (path) =>
			checked(() => {
				const components = tokenComponents(path);
				const stats = statComponents(components);
				const flags =
					constants.O_RDONLY |
					constants.O_NOFOLLOW |
					constants.O_NONBLOCK |
					(stats.isDirectory() ? constants.O_DIRECTORY : 0);
				return withOpened(components, flags, undefined, (descriptor) =>
					statfsSync(descriptorDirectoryPath(descriptor), { bigint: true }),
				);
			}),
		readFile: (path, maxBytes) => {
			const cap = safeNonnegativeInteger(maxBytes, "read byte cap");
			return withFile(path, { access: "read" }, (file) => {
				const before = file.stat();
				if (before.size > BigInt(cap)) throw new Error("CAS file exceeds the configured byte cap");
				const buffer = Buffer.alloc(Number(before.size));
				let offset = 0;
				while (offset < buffer.length) {
					const count = file.read(buffer, offset, buffer.length - offset, offset);
					if (count === 0) break;
					offset += count;
				}
				const after = file.stat();
				if (
					offset !== buffer.length ||
					before.dev !== after.dev ||
					before.ino !== after.ino ||
					before.size !== after.size ||
					before.mtimeMs !== after.mtimeMs ||
					before.ctimeMs !== after.ctimeMs
				)
					throw new Error("CAS file changed during bounded read");
				return buffer;
			});
		},
		readlink: (path) =>
			checked(() =>
				withRelativeParent(baseDescriptor, tokenComponents(path), (target) => {
					const stats = lstatSync(target, { bigint: true });
					if (!stats.isSymbolicLink()) throw new Error("CAS readlink target is not a symbolic link");
					return readlinkSync(target, "utf8");
				}),
			),
		realpath: (path) =>
			checked(() => {
				const resolved = withRelativeParent(baseDescriptor, tokenComponents(path), (target) =>
					realpathSync.native(target),
				);
				const base = realpathSync.native(`${descriptorDirectoryPath(baseDescriptor)}/.`);
				const relative = relativePath(base, resolved);
				if (relative === "") return createRelative([]);
				if (isAbsolute(relative) || relative === ".." || relative.startsWith("../"))
					throw new Error("CAS realpath escaped the retained root");
				return createRelative(relative.split("/"));
			}),
		writeFileExclusive: (path, value, mode = 0o600) => {
			withFile(path, { access: "write", create: "exclusive", mode }, (file) => {
				const bytes = typeof value === "string" ? Buffer.from(value) : Buffer.from(value);
				let offset = 0;
				while (offset < bytes.length) {
					const count = file.write(bytes, offset, bytes.length - offset, offset);
					if (count <= 0) throw new Error("CAS exclusive write made no progress");
					offset += count;
				}
				file.sync();
			});
		},
		mkdirPrivate: (path, recursive = false) =>
			checked(() => {
				const components = tokenComponents(path);
				if (components.length === 0) return;
				if (!recursive) {
					withRelativeParent(baseDescriptor, components, (target, parent) => {
						mkdirSync(target, { mode: 0o700 });
						const created = lstatSync(target, { bigint: true });
						if (
							!created.isDirectory() ||
							created.isSymbolicLink() ||
							created.uid !== root.uid ||
							created.gid !== root.gid
						)
							throw new Error("CAS private directory identity is invalid");
						chmodSync(target, 0o700);
						let descriptor: number | undefined;
						try {
							descriptor = openSync(target, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
							fchmodSync(descriptor, 0o700);
							fsyncSync(descriptor);
							fsyncSync(parent);
						} finally {
							if (descriptor !== undefined) closeSync(descriptor);
						}
					});
					return;
				}
				let descriptor = duplicateDirectoryDescriptor(baseDescriptor);
				try {
					for (const component of components) {
						const target = `${descriptorDirectoryPath(descriptor)}/${component}`;
						try {
							mkdirSync(target, { mode: 0o700 });
							fsyncSync(descriptor);
						} catch (error) {
							if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
						}
						const beforeOpen = lstatSync(target, { bigint: true });
						if (
							!beforeOpen.isDirectory() ||
							beforeOpen.isSymbolicLink() ||
							beforeOpen.uid !== root.uid ||
							beforeOpen.gid !== root.gid
						)
							throw new Error("CAS recursive directory identity is invalid");
						chmodSync(target, 0o700);
						const next = openSync(target, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
						const opened = fstatSync(next, { bigint: true });
						if (
							opened.dev !== beforeOpen.dev ||
							opened.ino !== beforeOpen.ino ||
							opened.uid !== root.uid ||
							opened.gid !== root.gid
						) {
							closeSync(next);
							throw new Error("CAS recursive directory changed while opening");
						}
						fchmodSync(next, 0o700);
						fsyncSync(next);
						closeSync(descriptor);
						descriptor = next;
					}
				} finally {
					try {
						closeSync(descriptor);
					} catch {}
				}
			}),
		chmod: (path, mode) =>
			checked(() => {
				const components = tokenComponents(path);
				const stats = withRelativeParent(baseDescriptor, components, (target) =>
					lstatSync(target, { bigint: true }),
				);
				if (stats.isSymbolicLink()) throw new Error("CAS chmod refuses a symbolic link");
				const flags =
					constants.O_RDONLY |
					constants.O_NOFOLLOW |
					constants.O_NONBLOCK |
					(stats.isDirectory() ? constants.O_DIRECTORY : 0);
				withOpened(components, flags, undefined, (descriptor) => fchmodSync(descriptor, safeMode(mode)));
			}),
		unlinkFile: (path) =>
			checked(() =>
				withRelativeParent(baseDescriptor, tokenComponents(path), (target) => {
					if (lstatSync(target, { bigint: true }).isDirectory())
						throw new Error("CAS unlinkFile refuses a directory");
					unlinkSync(target);
				}),
			),
		rmdir: (path) =>
			checked(() =>
				withRelativeParent(baseDescriptor, tokenComponents(path), (target) => {
					const stats = lstatSync(target, { bigint: true });
					if (!stats.isDirectory() || stats.isSymbolicLink()) throw new Error("CAS rmdir requires a directory");
					rmdirSync(target);
				}),
			),
		rename: (source, destination) =>
			checked(() => {
				const sourceComponents = tokenComponents(source);
				const destinationComponents = tokenComponents(destination);
				withRelativeParent(baseDescriptor, sourceComponents, (sourcePath) => {
					lstatSync(sourcePath, { bigint: true });
					withRelativeParent(baseDescriptor, destinationComponents, (destinationPath) =>
						renameSync(sourcePath, destinationPath),
					);
				});
			}),
		hardLink: (source, destination) =>
			checked(() => {
				const sourceComponents = tokenComponents(source);
				const destinationComponents = tokenComponents(destination);
				withRelativeParent(baseDescriptor, sourceComponents, (sourcePath) => {
					const before = lstatSync(sourcePath, { bigint: true });
					if (!before.isFile() || before.isSymbolicLink()) throw new Error("CAS hard-link source must be a file");
					withRelativeParent(baseDescriptor, destinationComponents, (destinationPath) => {
						linkSync(sourcePath, destinationPath);
						const sourceAfter = lstatSync(sourcePath, { bigint: true });
						const destinationAfter = lstatSync(destinationPath, { bigint: true });
						if (
							!sourceAfter.isFile() ||
							sourceAfter.isSymbolicLink() ||
							!destinationAfter.isFile() ||
							destinationAfter.isSymbolicLink() ||
							before.dev !== sourceAfter.dev ||
							before.ino !== sourceAfter.ino ||
							sourceAfter.dev !== destinationAfter.dev ||
							sourceAfter.ino !== destinationAfter.ino
						) {
							try {
								unlinkSync(destinationPath);
							} catch {}
							throw new Error("CAS hard-link identity changed during publication");
						}
					});
				});
			}),
		fsyncFile: (path) =>
			withFile(path, { access: "read" }, (file) => {
				file.sync();
			}),
		fsyncDirectory: (path) =>
			checked(() =>
				withOpened(
					tokenComponents(path),
					constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
					undefined,
					(descriptor) => fsyncSync(descriptor),
				),
			),
		withFile,
		withDirectory,
		directoryPage: (path, options) =>
			checked(() => {
				const limit = safeNonnegativeInteger(options.limit, "directory page limit");
				if (limit < 1 || limit > MAX_DIRECTORY_PAGE_LIMIT)
					throw new RangeError("CAS directory page limit is out of bounds");
				const scanLimit = safeNonnegativeInteger(
					options.scanLimit ?? MAX_DIRECTORY_SCAN_LIMIT,
					"directory scan limit",
				);
				if (scanLimit < limit || scanLimit > MAX_DIRECTORY_SCAN_LIMIT)
					throw new RangeError("CAS directory scan limit is out of bounds");
				return withOpened(
					tokenComponents(path),
					constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
					undefined,
					(descriptor) => {
						const directory = opendirSync(descriptorDirectoryPath(descriptor));
						try {
							const entries: IncidentCasDirectoryPageEntry[] = [];
							let cursorFound = options.afterName === undefined;
							let complete = false;
							let scanned = 0;
							while (scanned < scanLimit && entries.length < limit) {
								const entry = directory.readSync();
								if (!entry) {
									complete = true;
									break;
								}
								scanned += 1;
								if (!cursorFound) {
									if (entry.name === options.afterName) cursorFound = true;
									continue;
								}
								entries.push({ name: entry.name, kind: directoryEntryKind(entry) });
							}
							const scanLimitReached = scanned >= scanLimit && !complete;
							const result: IncidentCasDirectoryPage = {
								entries,
								complete,
								cursorFound,
								scanLimitReached,
							};
							const next = entries[entries.length - 1]?.name;
							if (next !== undefined) result.nextAfterName = next;
							return result;
						} finally {
							try {
								directory.closeSync();
							} catch {}
						}
					},
				);
			}),
	};
	return Object.freeze(capability);
}

function makeOwnedTransaction(
	root: RootIdentity,
	current: ProcessIdentity,
	expected: V2Observation,
	runtime: IncidentCasTransactionRuntime,
): OwnedTransaction {
	const retiredPath = rootChild(root, `${root.controlName}.released-slot`);
	let detached = false;
	let namespaceDurable = false;
	let released = false;
	let rootClosed = false;
	let poisoned = false;
	let detachmentDurable = false;
	const guardCurrent = (): boolean =>
		!released &&
		!detached &&
		!poisoned &&
		rootDescriptorCurrent(root) &&
		controlDescriptorCurrent(root) &&
		ownedObservationMatches(root, expected, observeV2(root, current));
	const markRootDetached = (): IncidentCasRootMutationResult<never> => {
		poisoned = true;
		if (!detachmentDurable) detachmentDurable = persistRootDetachment(root, expected, runtime);
		return { state: "root_detached", evidence: detachmentDurable ? "durable" : "pending" };
	};

	const finish = (cleanupPending: boolean): IncidentCasTransactionReleaseResult => {
		released = true;
		if (!rootClosed) {
			rootClosed = true;
			closeRoot(root);
		}
		return { state: "released", cleanupPending };
	};

	return {
		withRoot: <T>(operation: (root: IncidentCasRootMutation) => T): IncidentCasRootMutationResult<T> => {
			if (!guardCurrent()) return markRootDetached();
			let scopeActive = true;
			const assertScopeActive = (): void => {
				if (!scopeActive) throw new TypeError("CAS root capability is no longer active");
				if (!guardCurrent()) {
					markRootDetached();
					throw new Error("CAS recorder root detached during mutation");
				}
			};
			const capability = makeRootMutationCapability(root, root.descriptor, root.canonicalPath, assertScopeActive);
			let value: T | undefined;
			let operationError: unknown;
			try {
				value = operation(capability);
			} catch (error) {
				operationError = error;
			} finally {
				scopeActive = false;
			}
			if (operationError === undefined && isPromiseLike(value))
				operationError = new TypeError("CAS withRoot operation must complete synchronously");
			if (!guardCurrent()) return markRootDetached();
			if (operationError !== undefined) throw operationError;
			return { state: "committed", value: value as T };
		},
		owns: guardCurrent,
		release: () => {
			if (released) return { state: "released", cleanupPending: false };
			if (!rootDescriptorValid(root) || !controlDescriptorCurrent(root))
				return { state: "pending", reason: "root_identity_changed" };
			if (!rootPathCurrent(root)) poisoned = true;
			if (poisoned && !detachmentDurable) {
				detachmentDurable = persistRootDetachment(root, expected, runtime);
				if (!detachmentDurable) return { state: "pending", reason: "io_error" };
			}
			if (!detached) {
				try {
					const retired = pathFingerprint(retiredPath);
					const fixed = observeOwnedV2(root, current);
					if (sameInode(retired, expected.lock) && fixed === undefined) {
						detached = true;
					} else {
						if (retired) return { state: "pending", reason: "ownership_changed" };
						if (!ownedObservationMatches(root, expected, fixed))
							return { state: "pending", reason: "ownership_changed" };
						runtime.onStep?.("before_lock_retire");
						const confirmed = observeOwnedV2(root, current);
						if (!ownedObservationMatches(root, expected, confirmed))
							return { state: "pending", reason: "ownership_changed" };
						try {
							renameSync(rootChild(root, root.controlName), retiredPath);
							detached = true;
						} catch {
							const moved = pathFingerprint(retiredPath);
							if (sameInode(moved, expected.lock)) detached = true;
							else if (ownedObservationMatches(root, expected, observeOwnedV2(root, current)))
								return { state: "pending", reason: "io_error" };
							else return { state: "pending", reason: "ownership_changed" };
						}
						runtime.onStep?.("lock_retired");
					}
				} catch {
					return { state: "pending", reason: "io_error" };
				}
			}
			if (!namespaceDurable) {
				try {
					fsyncRoot(root, false);
					namespaceDurable = true;
					runtime.onStep?.("retirement_root_fsynced");
				} catch {
					if (!namespaceDurable) return { state: "pending", reason: "io_error" };
				}
			}
			const authorityCleanup = cleanupRetiredAuthority(root, retiredPath, expected, runtime);
			const detachmentCleanup = !detachmentDurable || retireRootDetachment(root, expected, runtime);
			return finish(!authorityCleanup || !detachmentCleanup);
		},
	};
}

function removeHeldEntry(rootKey: string, entry: HeldEntry): void {
	if (held.get(rootKey) === entry) held.delete(rootKey);
	for (const [path, pathEntry] of heldPaths) {
		if (pathEntry === entry) heldPaths.delete(path);
	}
}

function removeHeldEntryEverywhere(entry: HeldEntry): void {
	for (const [rootKey, candidate] of held) {
		if (candidate === entry) held.delete(rootKey);
	}
	for (const [path, candidate] of heldPaths) {
		if (candidate === entry) heldPaths.delete(path);
	}
}

function transactionHandle(rootKey: string, entry: HeldEntry): CasTransaction {
	let state: "active" | "pending" | "released" = "active";
	const assertActive = (): void => {
		if (state !== "active") throw new Error("CAS transaction handle has been released");
	};
	return {
		withRoot: <T>(operation: (root: IncidentCasRootMutation) => T) => {
			assertActive();
			return entry.transaction.withRoot(operation);
		},
		release: () => {
			if (state === "released") return { state: "released", cleanupPending: false };
			const current = held.get(rootKey);
			if (current !== entry) {
				state = "released";
				return { state: "released", cleanupPending: false };
			}
			if (state === "active") {
				entry.count = Math.max(0, entry.count - 1);
				if (entry.count > 0) {
					state = "released";
					return { state: "released", cleanupPending: false };
				}
				state = "pending";
			}
			const result = entry.transaction.release();
			if (result.state === "released") {
				removeHeldEntry(rootKey, entry);
				state = "released";
			}
			return result;
		},
	};
}

function closeAndReturn(
	root: RootIdentity,
	reason: IncidentCasTransactionUnavailableReason,
): IncidentCasTransactionAdmission {
	closeRoot(root);
	return { state: "unavailable", reason };
}

function clearInvalidObservations(root: RootIdentity): void {
	for (const key of invalidObservations.keys()) {
		if (key.startsWith(`${root.key}|`)) invalidObservations.delete(key);
	}
}

type ControlArtifactRecovery = "blocked" | "grace" | "ready";

function artifactSignature(file: StableFile): string {
	const fingerprint = file.fingerprint;
	return [
		fingerprint.dev,
		fingerprint.ino,
		fingerprint.mode,
		fingerprint.nlink,
		fingerprint.size,
		fingerprint.mtimeMs,
		fingerprint.ctimeMs,
		fingerprint.uid,
		fingerprint.gid,
		file.bytes,
	].join(":");
}

function matureArtifact(
	root: RootIdentity,
	path: string,
	file: StableFile,
	runtime: IncidentCasTransactionRuntime,
): boolean {
	const key = `${root.key}|artifact|${path}`;
	const signature = artifactSignature(file);
	const now = runtimeMonotonicTimeMs(runtime);
	const prior = artifactObservations.get(key);
	if (!prior || prior.signature !== signature || now < prior.firstSeenMonotonicMs) {
		artifactObservations.set(key, { signature, firstSeenMonotonicMs: now });
		return false;
	}
	return now - prior.firstSeenMonotonicMs >= ORPHAN_LOCK_GRACE_MS;
}

function forgetArtifact(root: RootIdentity, path: string): void {
	artifactObservations.delete(`${root.key}|artifact|${path}`);
}

function directRecordEvidence(root: RootIdentity, path: string): RecordEvidence | undefined {
	const file = stableFile(path);
	if (!file) return undefined;
	if (!exactPrivateRecordFile(root, file.fingerprint)) return file;
	const record = parseCanonicalRecord(file.bytes);
	return record ? { ...file, record } : file;
}

function repairScratchFile(root: RootIdentity, path: string, expected: Fingerprint): Fingerprint | undefined {
	if (!expected.file || expected.symbolicLink || expected.uid !== root.controlUid || expected.gid !== root.controlGid)
		return undefined;
	let descriptor: number | undefined;
	try {
		if ((expected.mode & 0o777n) !== 0o600n) chmodSync(path, 0o600);
		descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (
			!sameInode(expected, opened) ||
			!opened.file ||
			opened.symbolicLink ||
			opened.uid !== root.controlUid ||
			opened.gid !== root.controlGid
		)
			return undefined;
		if ((opened.mode & 0o777n) !== 0o600n) fchmodSync(descriptor, 0o600);
		fsyncSync(descriptor);
		const repaired = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		return sameInode(repaired, pathFingerprint(path)) && (repaired.mode & 0o777n) === 0o600n ? repaired : undefined;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function repairScratchDirectory(root: RootIdentity, path: string, expected: Fingerprint): Fingerprint | undefined {
	if (
		!expected.directory ||
		expected.symbolicLink ||
		expected.uid !== root.controlUid ||
		expected.gid !== root.controlGid
	)
		return undefined;
	let descriptor: number | undefined;
	try {
		if ((expected.mode & 0o777n) !== 0o700n) chmodSync(path, 0o700);
		descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (
			!sameInode(expected, opened) ||
			!opened.directory ||
			opened.symbolicLink ||
			opened.uid !== root.controlUid ||
			opened.gid !== root.controlGid
		)
			return undefined;
		if ((opened.mode & 0o777n) !== 0o700n) fchmodSync(descriptor, 0o700);
		fsyncSync(descriptor);
		const repaired = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		return sameInode(repaired, pathFingerprint(path)) && (repaired.mode & 0o777n) === 0o700n ? repaired : undefined;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function prepareRetirementClaimPath(path: string): string {
	return `${path}.retire-claim`;
}

function recoverOrphanPrepareRetirementClaim(
	root: RootIdentity,
	current: ProcessIdentity,
	path: string,
	runtime: IncidentCasTransactionRuntime,
): ControlArtifactRecovery {
	const claimPath = prepareRetirementClaimPath(path);
	const initial = pathFingerprint(claimPath);
	if (!initial) {
		forgetArtifact(root, claimPath);
		return "ready";
	}
	const fingerprint = repairScratchFile(root, claimPath, initial);
	if (!fingerprint) return "blocked";
	if (sameInode(fingerprint, pathFingerprint(path))) return "ready";
	const directEvidence = directRecordEvidence(root, claimPath);
	const evidence = directEvidence ?? boundedStableFile(claimPath);
	if (!evidence || fingerprint.nlink !== 1n) return "blocked";
	if (!fingerprintEquals(fingerprint, evidence.fingerprint)) return "blocked";
	const hint = directEvidence?.record ?? (directEvidence ? parseIdentityHint(directEvidence.bytes) : undefined);
	if ((!hint || ownerActivity(hint, current) !== "stale") && !matureArtifact(root, claimPath, evidence, runtime))
		return "grace";
	let descriptor: number | undefined;
	try {
		descriptor = openSync(claimPath, constants.O_RDONLY | constants.O_NOFOLLOW);
		const pinned = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		runPrepareRetirementTestSynchronization(runtime);
		const stable = directEvidence ? directRecordEvidence(root, claimPath) : boundedStableFile(claimPath);
		if (
			!stable ||
			stable.bytes !== evidence.bytes ||
			!fingerprintEquals(stable.fingerprint, evidence.fingerprint) ||
			!sameInode(pinned, stable.fingerprint)
		)
			return "blocked";
		if (!unlinkExactStableFile(claimPath, stable.fingerprint)) return "blocked";
		fsyncRoot(root);
		forgetArtifact(root, claimPath);
		return "ready";
	} catch {
		return "blocked";
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

type RetirableEvidence = StableFile | Fingerprint;
type RetirementSynchronization = (runtime: IncidentCasTransactionRuntime) => void;
type RetirementEvidenceReader = (path: string) => RetirableEvidence | undefined;

function retirableFingerprint(value: RetirableEvidence | undefined): Fingerprint | undefined {
	return value && "fingerprint" in value ? value.fingerprint : value;
}

function retirableBytes(value: RetirableEvidence): string | undefined {
	return "bytes" in value ? value.bytes : undefined;
}

function retirableEvidenceMatches(
	value: RetirableEvidence | undefined,
	expected: Fingerprint,
	expectedBytes: string | undefined,
): boolean {
	if (!value) return false;
	const fingerprint = retirableFingerprint(value);
	if (!fingerprint) return false;
	return (
		fingerprint.file &&
		!fingerprint.symbolicLink &&
		sameInode(fingerprint, expected) &&
		(expectedBytes === undefined || retirableBytes(value) === expectedBytes)
	);
}

function retirableSnapshotsMatch(left: RetirableEvidence | undefined, right: RetirableEvidence | undefined): boolean {
	const leftFingerprint = retirableFingerprint(left);
	const rightFingerprint = retirableFingerprint(right);
	return (
		leftFingerprint !== undefined &&
		rightFingerprint !== undefined &&
		sameInode(leftFingerprint, rightFingerprint) &&
		leftFingerprint.file === rightFingerprint.file &&
		leftFingerprint.directory === rightFingerprint.directory &&
		leftFingerprint.symbolicLink === rightFingerprint.symbolicLink &&
		leftFingerprint.mode === rightFingerprint.mode &&
		leftFingerprint.size === rightFingerprint.size &&
		leftFingerprint.mtimeMs === rightFingerprint.mtimeMs &&
		leftFingerprint.ctimeMs === rightFingerprint.ctimeMs &&
		leftFingerprint.uid === rightFingerprint.uid &&
		leftFingerprint.gid === rightFingerprint.gid
	);
}

function retireFileWithClaim(
	root: RootIdentity,
	path: string,
	expected: Fingerprint,
	expectedBytes: string | undefined,
	runtime: IncidentCasTransactionRuntime,
	synchronization?: RetirementSynchronization,
	requireCurrentRootPath = true,
	evidenceReader?: RetirementEvidenceReader,
): boolean {
	const claimPath = prepareRetirementClaimPath(path);
	let descriptor: number | undefined;
	let pinned: Fingerprint | undefined;
	let claimCreated = false;
	const readEvidence: RetirementEvidenceReader =
		evidenceReader ?? (expectedBytes === undefined ? pathFingerprint : stableFile);
	const syncRoot = (): void => fsyncRoot(root, requireCurrentRootPath);
	const discardClaim = (): void => {
		if (pinned && sameInode(pathFingerprint(claimPath), pinned)) {
			if (unlinkExactFile(claimPath, pinned)) {
				try {
					syncRoot();
				} catch {}
			}
		}
	};
	try {
		descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const initiallyPinned = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (
			!sameInode(initiallyPinned, expected) ||
			!initiallyPinned.file ||
			initiallyPinned.symbolicLink ||
			!sameInode(initiallyPinned, pathFingerprint(path))
		)
			return false;
		pinned = initiallyPinned;
		try {
			linkSync(path, claimPath);
			claimCreated = true;
			syncRoot();
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
		}
		const initialLinks = initiallyPinned.nlink;
		const expectedLinks = initialLinks + (claimCreated ? 1n : 0n);
		const beforePath = readEvidence(path);
		const beforeClaim = readEvidence(claimPath);
		const afterLink = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (
			!retirableEvidenceMatches(beforePath, afterLink, expectedBytes) ||
			!retirableEvidenceMatches(beforeClaim, afterLink, expectedBytes) ||
			afterLink.nlink !== expectedLinks
		) {
			discardClaim();
			return false;
		}
		synchronization?.(runtime);
		const afterPath = readEvidence(path);
		const afterClaim = readEvidence(claimPath);
		const afterPinned = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (
			!retirableEvidenceMatches(afterPath, afterPinned, expectedBytes) ||
			!retirableEvidenceMatches(afterClaim, afterPinned, expectedBytes) ||
			!retirableSnapshotsMatch(beforePath, afterPath) ||
			!retirableSnapshotsMatch(beforeClaim, afterClaim) ||
			afterPinned.nlink !== expectedLinks
		) {
			discardClaim();
			return false;
		}
		if (!unlinkExactStableFile(path, retirableFingerprint(afterPath))) {
			discardClaim();
			return false;
		}
		syncRoot();
		const remainingClaim = readEvidence(claimPath);
		const remainingPinned = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (
			!retirableEvidenceMatches(remainingClaim, remainingPinned, expectedBytes) ||
			remainingPinned.nlink !== expectedLinks - 1n ||
			pathFingerprint(path)
		)
			return false;
		if (!unlinkExactStableFile(claimPath, retirableFingerprint(remainingClaim))) return false;
		syncRoot();
		forgetArtifact(root, claimPath);
		return pathFingerprint(path) === undefined && pathFingerprint(claimPath) === undefined;
	} catch {
		discardClaim();
		return false;
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function retirePreparedEvidence(
	root: RootIdentity,
	path: string,
	evidence: RecordEvidence,
	runtime: IncidentCasTransactionRuntime,
	synchronization?: RetirementSynchronization,
	requireCurrentRootPath = true,
): boolean {
	const defaultSynchronization =
		evidence.record?.type === "incident-recorder-cas-root-detachment"
			? runPrepareRetirementTestSynchronization
			: undefined;
	return retireFileWithClaim(
		root,
		path,
		evidence.fingerprint,
		evidence.bytes,
		runtime,
		synchronization ?? defaultSynchronization,
		requireCurrentRootPath,
	);
}

function recoverPrepareSlot(
	root: RootIdentity,
	current: ProcessIdentity,
	path: string,
	runtime: IncidentCasTransactionRuntime,
): ControlArtifactRecovery {
	const claimRecovery = recoverOrphanPrepareRetirementClaim(root, current, path, runtime);
	if (claimRecovery !== "ready") return claimRecovery;
	const initial = pathFingerprint(path);
	if (!initial) {
		forgetArtifact(root, path);
		return "ready";
	}
	const fingerprint = repairScratchFile(root, path, initial);
	if (!fingerprint) return "blocked";
	const evidence = directRecordEvidence(root, path);
	if (!evidence) {
		const marker = boundedStableFile(path);
		if (!marker) return "blocked";
		if (!matureArtifact(root, path, marker, runtime)) return "grace";
		const stable = boundedStableFile(path);
		if (
			!stable ||
			!fingerprintEquals(fingerprint, stable.fingerprint) ||
			!retireFileWithClaim(
				root,
				path,
				stable.fingerprint,
				stable.bytes,
				runtime,
				runPrepareRetirementTestSynchronization,
				true,
				boundedStableFile,
			)
		)
			return "blocked";
		fsyncRoot(root);
		forgetArtifact(root, path);
		return "ready";
	}
	if (!fingerprintEquals(fingerprint, evidence.fingerprint)) return "blocked";
	const record = evidence.record;
	if (record && preparedPath(root, record) !== path) return "blocked";
	const retirementClaimPath = prepareRetirementClaimPath(path);
	const retirementClaim = directRecordEvidence(root, retirementClaimPath);
	const hasRetirementClaim =
		retirementClaim !== undefined &&
		retirementClaim.bytes === evidence.bytes &&
		sameInode(retirementClaim.fingerprint, evidence.fingerprint);
	if (pathFingerprint(retirementClaimPath) && !hasRetirementClaim) return "blocked";
	if (record && hasRetirementClaim && evidence.fingerprint.nlink === 3n) {
		if (!retirePreparedEvidence(root, path, evidence, runtime)) return "blocked";
		fsyncRoot(root);
		forgetArtifact(root, path);
		return "ready";
	}
	if (record && evidence.fingerprint.nlink === 2n && !hasRetirementClaim) {
		if (!retirePreparedEvidence(root, path, evidence, runtime)) return "blocked";
		fsyncRoot(root);
		forgetArtifact(root, path);
		return "ready";
	}
	if (evidence.fingerprint.nlink !== (hasRetirementClaim ? 2n : 1n)) return "blocked";
	if (record?.type === "incident-recorder-cas-root-detachment") {
		const fixed = observeV2(root, current);
		const owner = fixed?.decision?.kind === "owner" ? fixed.decision : undefined;
		if (owner && rootDetachmentBoundToOwner(record, owner)) {
			forgetArtifact(root, path);
			return "ready";
		}
	}
	const hint = record ?? parseIdentityHint(evidence.bytes);
	if ((!hint || ownerActivity(hint, current) !== "stale") && !matureArtifact(root, path, evidence, runtime)) {
		return "grace";
	}
	const stable = directRecordEvidence(root, path);
	if (!stable || stable.bytes !== evidence.bytes || !fingerprintEquals(stable.fingerprint, evidence.fingerprint))
		return "blocked";
	if (!retirePreparedEvidence(root, path, stable, runtime)) return "blocked";
	forgetArtifact(root, path);
	return "ready";
}

function unlinkExactNonDirectory(path: string, expected: Fingerprint | undefined): boolean {
	const current = pathFingerprint(path);
	if (!current) return true;
	if (!fingerprintEquals(current, expected) || current.directory) return false;
	try {
		unlinkSync(path);
		return true;
	} catch {
		return false;
	}
}

function recoverStageSlot(
	root: RootIdentity,
	current: ProcessIdentity,
	runtime: IncidentCasTransactionRuntime,
): ControlArtifactRecovery {
	const path = rootChild(root, `${root.controlName}.stage`);
	const initial = pathFingerprint(path);
	if (!initial) {
		forgetArtifact(root, path);
		return "ready";
	}
	const fingerprint = repairScratchDirectory(root, path, initial);
	if (!fingerprint) return "blocked";
	const observation = observeV2AtPath(root, path, current);
	if (!observation || !sameInode(observation.lock, fingerprint)) return "blocked";
	const preparedOwnerPath = rootChild(root, `${root.controlName}.prepare-owner`);
	const preparedOwner = directRecordEvidence(root, preparedOwnerPath);
	let stale = false;
	if (observation.state === "owner" || observation.state === "quarantine") {
		stale = observation.decision !== undefined && ownerActivity(observation.decision, current) === "stale";
	} else if (observation.ownerActivityHint) {
		stale = observation.ownerActivityHint === "stale";
	} else {
		const preparedRecord = preparedOwner?.record;
		if (
			preparedRecord?.type === "incident-recorder-cas-decision" &&
			preparedRecord.kind === "owner" &&
			decisionBoundToLock(preparedRecord, observation.lock)
		) {
			stale = ownerActivity(preparedRecord, current) === "stale";
		}
	}
	const marker: StableFile = {
		bytes: `${observationSignature(observation)}|${preparedOwner ? artifactSignature(preparedOwner) : "no-prepare"}`,
		fingerprint: observation.lock,
	};
	if (!stale && !matureArtifact(root, path, marker, runtime)) return "grace";
	const fresh = observeV2AtPath(root, path, current);
	if (!observationEquals(observation, fresh)) return "blocked";
	const freshPreparedOwner = directRecordEvidence(root, preparedOwnerPath);
	if (
		(preparedOwner === undefined) !== (freshPreparedOwner === undefined) ||
		(preparedOwner !== undefined &&
			freshPreparedOwner !== undefined &&
			(preparedOwner.bytes !== freshPreparedOwner.bytes ||
				!fingerprintEquals(preparedOwner.fingerprint, freshPreparedOwner.fingerprint)))
	)
		return "blocked";
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (!sameDirectoryIdentity(observation.lock, opened) || !sameDirectoryIdentity(opened, pathFingerprint(path)))
			return "blocked";
		const ownerPath = `/proc/self/fd/${descriptor}/${OWNER_NAME}`;
		const owner = pathFingerprint(ownerPath);
		if (owner && !unlinkExactNonDirectory(ownerPath, owner)) return "blocked";
		fsyncSync(descriptor);
		closeSync(descriptor);
		descriptor = undefined;
		rmdirSync(path);
		const preparedRecord = preparedOwner?.record;
		if (
			preparedOwner &&
			preparedRecord?.type === "incident-recorder-cas-decision" &&
			preparedRecord.kind === "owner" &&
			decisionBoundToLock(preparedRecord, observation.lock)
		) {
			unlinkExactNonDirectory(preparedOwnerPath, preparedOwner.fingerprint);
		}
		fsyncRoot(root);
		forgetArtifact(root, path);
		return "ready";
	} catch {
		return "blocked";
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function recoverQuarantineSlot(
	root: RootIdentity,
	_current: ProcessIdentity,
	runtime: IncidentCasTransactionRuntime,
): ControlArtifactRecovery {
	const path = rootChild(root, quarantineContainerName(root));
	const initial = pathFingerprint(path);
	if (!initial) {
		forgetArtifact(root, path);
		return "ready";
	}
	const fingerprint = repairScratchDirectory(root, path, initial);
	if (!fingerprint) return "blocked";
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		const opened = fingerprintFromStat(fstatSync(descriptor, { bigint: true }));
		if (!sameDirectoryIdentity(opened, fingerprint) || !sameDirectoryIdentity(opened, pathFingerprint(path)))
			return "blocked";
		const container = { descriptor, path, fingerprint: opened };
		const claimState = quarantineClaimAt(root, descriptor);
		const claim = claimState.evidence?.record;
		const occupantPath = `/proc/self/fd/${descriptor}/${OCCUPANT_NAME}`;
		const occupant = pathFingerprint(occupantPath);
		if (claim?.type === "incident-recorder-cas-quarantine-claim") {
			if (occupant) {
				if (!claimMatchesRetainedSource(claim, occupant)) return "blocked";
				return retireQuarantineContainer(root, container, true) === "retired" ? "ready" : "blocked";
			}
			const fixed = pathFingerprint(rootChild(root, root.controlName));
			if (fixed && claimMatchesSource(claim, fixed)) {
				forgetArtifact(root, path);
				return "ready";
			}
			return retireQuarantineContainer(root, container, true) === "retired" ? "ready" : "blocked";
		}

		const marker: StableFile = {
			bytes: [
				claimState.evidence
					? artifactSignature(claimState.evidence)
					: claimState.fingerprint
						? artifactSignature({ bytes: "invalid-claim", fingerprint: claimState.fingerprint })
						: "no-claim",
				occupant ? artifactSignature({ bytes: "occupant", fingerprint: occupant }) : "no-occupant",
			].join("|"),
			fingerprint: opened,
		};
		if (!matureArtifact(root, path, marker, runtime)) return "grace";
		const stableClaim = quarantineClaimAt(root, descriptor);
		const stableOccupant = pathFingerprint(occupantPath);
		const stableMarker = [
			stableClaim.evidence
				? artifactSignature(stableClaim.evidence)
				: stableClaim.fingerprint
					? artifactSignature({ bytes: "invalid-claim", fingerprint: stableClaim.fingerprint })
					: "no-claim",
			stableOccupant ? artifactSignature({ bytes: "occupant", fingerprint: stableOccupant }) : "no-occupant",
		].join("|");
		if (stableMarker !== marker.bytes || !sameDirectoryIdentity(opened, pathFingerprint(path))) return "blocked";
		return retireQuarantineContainer(root, container, false) === "retired" ? "ready" : "blocked";
	} catch {
		return "blocked";
	} finally {
		if (descriptor !== undefined) {
			try {
				closeSync(descriptor);
			} catch {}
		}
	}
}

function recoverReleasedSlot(
	root: RootIdentity,
	current: ProcessIdentity,
	runtime: IncidentCasTransactionRuntime,
): ControlArtifactRecovery {
	const path = rootChild(root, `${root.controlName}.released-slot`);
	const observation = observeV2AtPath(root, path, current);
	if (!observation) return pathFingerprint(path) ? "blocked" : "ready";
	// The fixed released slot is outside the authority name. Its presence proves
	// retirement has already happened, so any actor may finish exact cleanup even
	// while the former owner process is alive. Exact inode checks prevent a
	// delayed cleaner from touching a later occupant of the slot.
	if (observation.state === "owner" || observation.state === "missing") {
		return cleanupRetiredAuthority(root, path, observation, runtime) ? "ready" : "blocked";
	}
	Atomics.wait(lockStabilityWait, 0, 0, LOCK_STABILITY_RECHECK_MS);
	const stable = observeV2AtPath(root, path, current);
	if (!observationEquals(observation, stable)) return "blocked";
	const container = ensureQuarantineContainer(root, current, observation.lock, runtime);
	if (!container) return "blocked";
	try {
		const occupantPath = `/proc/self/fd/${container.descriptor}/${OCCUPANT_NAME}`;
		const occupant = pathFingerprint(occupantPath);
		if (occupant) {
			if (!sameInode(occupant, observation.lock) || pathFingerprint(path)) return "blocked";
			fsyncSync(container.descriptor);
			fsyncRoot(root);
			return retireQuarantineContainer(root, container, true) === "retired" ? "ready" : "blocked";
		}
		const fresh = observeV2AtPath(root, path, current);
		if (!observationEquals(observation, fresh)) return "blocked";
		try {
			renameSync(path, occupantPath);
		} catch {
			if (!sameInode(pathFingerprint(occupantPath), observation.lock) || pathFingerprint(path)) return "blocked";
		}
		if (!sameInode(pathFingerprint(occupantPath), observation.lock)) return "blocked";
		fsyncSync(container.descriptor);
		fsyncRoot(root);
		return retireQuarantineContainer(root, container, true) === "retired" ? "ready" : "blocked";
	} catch {
		return "blocked";
	} finally {
		try {
			closeSync(container.descriptor);
		} catch {}
	}
}

function recoverDetachmentSlot(
	root: RootIdentity,
	current: ProcessIdentity,
	runtime: IncidentCasTransactionRuntime,
): ControlArtifactRecovery {
	const path = rootChild(root, `${root.controlName}.detached-slot`);
	const claimRecovery = recoverOrphanPrepareRetirementClaim(root, current, path, runtime);
	if (claimRecovery !== "ready") return claimRecovery;
	const initial = pathFingerprint(path);
	if (!initial) {
		forgetArtifact(root, path);
		return "ready";
	}
	const repaired = repairScratchFile(root, path, initial);
	if (!repaired) return "blocked";
	const evidence = recordEvidence(root, path);
	if (
		evidence?.record?.type === "incident-recorder-cas-root-detachment" &&
		fingerprintEquals(evidence.fingerprint, repaired) &&
		evidence.fingerprint.nlink === 1n
	) {
		const fixed = observeV2(root, current);
		const owner = fixed?.decision?.kind === "owner" ? fixed.decision : undefined;
		if (owner && rootDetachmentBoundToOwner(evidence.record, owner)) {
			forgetArtifact(root, path);
			return "ready";
		}
		const stable = recordEvidence(root, path);
		if (
			stable?.record?.type !== "incident-recorder-cas-root-detachment" ||
			canonicalRecordBytes(stable.record) !== canonicalRecordBytes(evidence.record) ||
			!fingerprintEquals(stable.fingerprint, evidence.fingerprint)
		)
			return "blocked";
		if (!retirePreparedEvidence(root, path, stable, runtime, runDetachmentRecoveryTestSynchronization))
			return "blocked";
		fsyncRoot(root);
		forgetArtifact(root, path);
		return "ready";
	}
	const file = directRecordEvidence(root, path) ?? boundedStableFile(path);
	if (!file) return "blocked";
	if (!matureArtifact(root, path, file, runtime)) return "grace";
	const stable = directRecordEvidence(root, path);
	if (stable) {
		if (
			!fingerprintEquals(repaired, stable.fingerprint) ||
			!retirePreparedEvidence(root, path, stable, runtime, runDetachmentRecoveryTestSynchronization)
		)
			return "blocked";
	} else {
		const stable = boundedStableFile(path);
		if (
			!stable ||
			!fingerprintEquals(repaired, stable.fingerprint) ||
			!retireFileWithClaim(
				root,
				path,
				stable.fingerprint,
				stable.bytes,
				runtime,
				runDetachmentRecoveryTestSynchronization,
				true,
				boundedStableFile,
			)
		)
			return "blocked";
	}
	fsyncRoot(root);
	forgetArtifact(root, path);
	return "ready";
}

function recoverBoundedControlArtifacts(
	root: RootIdentity,
	current: ProcessIdentity,
	runtime: IncidentCasTransactionRuntime,
): ControlArtifactRecovery {
	const quarantine = recoverQuarantineSlot(root, current, runtime);
	if (quarantine !== "ready") return quarantine;
	const released = recoverReleasedSlot(root, current, runtime);
	if (released !== "ready") return released;
	const stage = recoverStageSlot(root, current, runtime);
	if (stage !== "ready") return stage;
	for (const slot of ["claim", "detachment", "owner", "quarantine"] as const) {
		const recovered = recoverPrepareSlot(
			root,
			current,
			rootChild(root, `${root.controlName}.prepare-${slot}`),
			runtime,
		);
		if (recovered !== "ready") return recovered;
	}
	return recoverDetachmentSlot(root, current, runtime);
}

function legacyV1AuthorityPresent(root: RootIdentity): boolean {
	const path = join(`/proc/self/fd/${root.descriptor}`, ".cas-transaction");
	return pathFingerprint(path) !== undefined;
}

export function acquireIncidentCasTransactionDetailed(
	recorderRoot: string,
	runtime: IncidentCasTransactionRuntime = {},
): IncidentCasTransactionAdmission {
	const root = canonicalRoot(recorderRoot);
	if (!root) return { state: "unavailable", reason: "root_unavailable" };
	const current = currentProcessIdentity();
	if (!current) return closeAndReturn(root, "identity_unavailable");
	if (legacyV1AuthorityPresent(root)) return closeAndReturn(root, "legacy_v1_authority_present");
	let existing = held.get(root.key);
	const pathOwner = heldPaths.get(root.canonicalPath);
	if (pathOwner && pathOwner !== existing) {
		if (pathOwner.publishing || pathOwner.count > 0) return closeAndReturn(root, "local_ownership_changed");
		const retirement = pathOwner.transaction.release();
		if (retirement.state === "pending") return closeAndReturn(root, "release_pending");
		removeHeldEntryEverywhere(pathOwner);
		existing = held.get(root.key);
	}
	if (existing) {
		if (existing.publishing) return closeAndReturn(root, "control_artifact_busy");
		if (existing.count > 0) {
			closeRoot(root);
			if (!existing.transaction.owns()) return { state: "unavailable", reason: "local_ownership_changed" };
			heldPaths.set(root.canonicalPath, existing);
			existing.count += 1;
			return { state: "acquired", transaction: transactionHandle(root.key, existing) };
		}
		const retirement = existing.transaction.release();
		if (retirement.state === "pending") return closeAndReturn(root, "release_pending");
		removeHeldEntry(root.key, existing);
	}
	const artifactRecovery = recoverBoundedControlArtifacts(root, current, runtime);
	if (artifactRecovery === "grace") return closeAndReturn(root, "control_artifact_grace");
	if (artifactRecovery === "blocked") return closeAndReturn(root, "control_artifact_busy");
	for (let attempt = 0; attempt < 8; attempt += 1) {
		const detachmentPrepareRecovery = recoverPrepareSlot(
			root,
			current,
			rootChild(root, `${root.controlName}.prepare-detachment`),
			runtime,
		);
		if (detachmentPrepareRecovery === "grace") return closeAndReturn(root, "control_artifact_grace");
		if (detachmentPrepareRecovery === "blocked") return closeAndReturn(root, "control_artifact_busy");
		const detachmentRecovery = recoverDetachmentSlot(root, current, runtime);
		if (detachmentRecovery === "grace") return closeAndReturn(root, "control_artifact_grace");
		if (detachmentRecovery === "blocked") return closeAndReturn(root, "control_artifact_busy");
		const observation = observeV2(root, current);
		if (!observation) {
			let tracked: HeldEntry | undefined;
			const creation = tryCreateV2(root, current, runtime, (publishedObservation) => {
				if (tracked) {
					tracked.transaction = makeOwnedTransaction(root, current, publishedObservation, runtime);
					return;
				}
				if (held.has(root.key) || heldPaths.has(root.canonicalPath))
					throw new Error("CAS publication tracking conflict");
				tracked = {
					count: 0,
					publishing: true,
					transaction: makeOwnedTransaction(root, current, publishedObservation, runtime),
				};
				held.set(root.key, tracked);
				heldPaths.set(root.canonicalPath, tracked);
			});
			if (creation.state === "acquired") {
				clearInvalidObservations(root);
				const entry =
					tracked ??
					({
						count: 0,
						publishing: true,
						transaction: makeOwnedTransaction(root, current, creation.observation, runtime),
					} satisfies HeldEntry);
				if (!tracked) {
					held.set(root.key, entry);
					heldPaths.set(root.canonicalPath, entry);
				} else {
					entry.transaction = makeOwnedTransaction(root, current, creation.observation, runtime);
				}
				entry.publishing = false;
				entry.count = 1;
				return { state: "acquired", transaction: transactionHandle(root.key, entry) };
			}
			if (creation.state === "published") {
				const entry =
					tracked ??
					({
						count: 0,
						publishing: false,
						transaction: makeOwnedTransaction(root, current, creation.observation, runtime),
					} satisfies HeldEntry);
				if (!tracked) {
					held.set(root.key, entry);
					heldPaths.set(root.canonicalPath, entry);
				} else {
					entry.transaction = makeOwnedTransaction(root, current, creation.observation, runtime);
				}
				entry.publishing = false;
				const retirement = entry.transaction.release();
				if (retirement.state === "released") removeHeldEntry(root.key, entry);
				return { state: "unavailable", reason: "creation_failed" };
			}
			if (tracked) {
				removeHeldEntry(root.key, tracked);
				tracked = undefined;
			}
			if (creation.state === "failed") return closeAndReturn(root, "creation_failed");
			continue;
		}
		if (observation.state === "owner") {
			if (observation.decision?.kind !== "owner") return closeAndReturn(root, "unstable_lock_namespace");
			const activity = ownerActivity(observation.decision, current);
			if (activity !== "stale") return closeAndReturn(root, unavailableReason(activity));
		} else if (observation.state !== "quarantine") {
			if (observation.ownerActivityHint && observation.ownerActivityHint !== "stale")
				return closeAndReturn(root, unavailableReason(observation.ownerActivityHint));
			if (!matureInvalidObservation(root, observation, runtime)) return closeAndReturn(root, "invalid_owner_grace");
			const stable = stableInvalidObservation(root, current, observation);
			if (!stable) return closeAndReturn(root, "unstable_lock_namespace");
		}
		const outcome = quarantineObservation(root, current, observation, runtime);
		if (outcome === "completed" || outcome === "changed") continue;
		return closeAndReturn(root, outcome === "conflict" ? "quarantine_conflict" : "quarantine_failed");
	}
	return closeAndReturn(root, "unstable_lock_namespace");
}

export function acquireIncidentCasTransaction(
	recorderRoot: string,
	runtime: IncidentCasTransactionRuntime = {},
): CasTransaction | undefined {
	const admission = acquireIncidentCasTransactionDetailed(recorderRoot, runtime);
	return admission.state === "acquired" ? admission.transaction : undefined;
}
