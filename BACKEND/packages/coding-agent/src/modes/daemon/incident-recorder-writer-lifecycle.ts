import { createHash, randomUUID } from "node:crypto";
import {
	type BigIntStats,
	closeSync,
	constants,
	fchmodSync,
	fstatSync,
	fsyncSync,
	linkSync,
	lstatSync,
	mkdirSync,
	opendirSync,
	openSync,
	readFileSync,
	readSync,
	realpathSync,
	statSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import type {
	CasTransaction,
	IncidentCasFileMutation,
	IncidentCasFileOpenOptions,
	IncidentCasRootMutation,
	IncidentCasRootMutationResult,
	IncidentCasTransactionAdmission,
	IncidentCasTransactionReleaseResult,
} from "./incident-recorder-cas-transaction.js";

const CONTROL_PREFIX = ".grimoire-incident-writer-lifecycle-v1-";
const TEST_RUNTIME_BRIDGE_SYMBOL = Symbol.for("grimoire.incident-writer-lifecycle.test-runtime-bridge.v1");
const SCHEMA_VERSION = 1;
const NORMAL_SLOT_COUNT = 32;
const RECORD_MAX_BYTES = 8 * 1024;
const INVALID_ARTIFACT_GRACE_MS = 1_000;
const SHA256 = /^[0-9a-f]{64}$/;
const BOOT_ID = /^[0-9A-Za-z][0-9A-Za-z._:-]{0,127}$/;
const PROCESS_START_ID = /^proc:[0-9]+$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type IncidentRecorderWriterLifecycleArtifact =
	| "gate"
	| "normal"
	| "recovery_pending"
	| "recovery"
	| "detachment";

export type IncidentRecorderWriterLifecycleFaultStep =
	| "prepare_opened"
	| "prepare_chmodded"
	| "prepare_written"
	| "prepare_fsynced"
	| "record_linked"
	| "directory_fsynced"
	| "prepare_unlinked"
	| "cleanup_fsynced"
	| "before_record_reap"
	| "record_reaped"
	| "before_record_release"
	| "record_released";

export interface IncidentRecorderWriterLifecycleProcessIdentity {
	bootId: string;
	pid: number;
	processStartId: string;
	uid: number;
}

export type IncidentRecorderWriterLifecycleProcessIdentityObservation =
	| { state: "present"; identity: IncidentRecorderWriterLifecycleProcessIdentity }
	| { state: "absent" }
	| { state: "unavailable"; reason: "proc_unavailable" | "identity_malformed" };

/** Read-only Linux observation and deterministic crash seams used through an opaque test handle. */
export interface IncidentRecorderWriterLifecycleRuntime {
	readCurrentProcessIdentity(): IncidentRecorderWriterLifecycleProcessIdentityObservation;
	readProcessIdentity(pid: number): IncidentRecorderWriterLifecycleProcessIdentityObservation;
	wallTimeMs?(): number;
	onStep?(step: IncidentRecorderWriterLifecycleFaultStep, artifact: IncidentRecorderWriterLifecycleArtifact): void;
}

declare const testRuntimeHandleBrand: unique symbol;

/** Opaque handle issued only by the module-owned Vitest bootstrap bridge. */
export interface IncidentRecorderWriterLifecycleTestRuntimeHandle {
	readonly [testRuntimeHandleBrand]: true;
}

export interface IncidentRecorderWriterLifecycleTarget {
	agentDir: string;
}

export interface IncidentRecorderWriterLifecycleActivationResult {
	state: "valid" | "invalid";
	reason?: string;
}

/**
 * The integration layer supplies one activation generation and its accepted CAS
 * admission. The lifecycle snapshots these data properties and functions, then
 * calls them without exposing its retained directory descriptors.
 */
export interface IncidentRecorderWriterLifecycleAdmissionContract {
	activationGenerationDigest: string;
	revalidateActivation(): IncidentRecorderWriterLifecycleActivationResult;
	acquireCas(proof: IncidentRecorderWriterLifecycleProof, recorderRoot: string): IncidentCasTransactionAdmission;
}

export interface IncidentRecorderWriterLifecycleNamespaceIdentity {
	path: string;
	dev: string;
	ino: string;
	uid: number;
	gid: number;
	mode: number;
}

export interface IncidentRecorderWriterLifecycleNamespaceBinding {
	digest: string;
	activationGenerationDigest: string;
	stableParent: IncidentRecorderWriterLifecycleNamespaceIdentity;
	agentDir: IncidentRecorderWriterLifecycleNamespaceIdentity;
	recorder: IncidentRecorderWriterLifecycleNamespaceIdentity;
	incidents: IncidentRecorderWriterLifecycleNamespaceIdentity;
}

declare const lifecycleProofBrand: unique symbol;

/** Unforgeable, callback-scoped evidence that an exact normal or recovery lease is current. */
export interface IncidentRecorderWriterLifecycleProof {
	readonly [lifecycleProofBrand]: true;
}

export type IncidentRecorderWriterLifecycleMutationUnavailableReason =
	| "activation_invalid"
	| "admission_contract_invalid"
	| "cas_release_pending"
	| "cas_unavailable"
	| "lease_lost"
	| "namespace_changed"
	| "released"
	| "root_detached";

export type IncidentRecorderWriterLifecycleMutationResult<T> =
	| { state: "committed"; value: T }
	| { state: "unavailable"; reason: IncidentRecorderWriterLifecycleMutationUnavailableReason };

export type IncidentRecorderWriterLifecycleReleaseResult =
	| { state: "released"; cleanupPending: boolean }
	| { state: "pending"; reason: "control_artifact_busy" | "io_error" };

export interface IncidentRecorderWriterLifecycleLease {
	withRoot<T>(operation: (root: IncidentCasRootMutation) => T): IncidentRecorderWriterLifecycleMutationResult<T>;
	release(): IncidentRecorderWriterLifecycleReleaseResult;
}

export type IncidentRecorderWriterLifecycleUnavailableReason =
	| "activation_invalid"
	| "control_artifact_busy"
	| "control_artifact_grace"
	| "holder_capacity"
	| "identity_unavailable"
	| "invalid_control_artifact"
	| "invalid_target"
	| "io_error"
	| "namespace_detached"
	| "namespace_transition_blocked"
	| "namespace_unavailable"
	| "owner_liveness_unknown"
	| "platform_unsupported"
	| "recovery_active"
	| "recovery_pending";

export type AcquireIncidentRecorderWriterNormalLeaseResult =
	| { state: "acquired"; lease: IncidentRecorderWriterLifecycleLease }
	| { state: "unavailable"; reason: IncidentRecorderWriterLifecycleUnavailableReason };

export type AcquireIncidentRecorderWriterRecoveryLeaseResult =
	| { state: "acquired"; lease: IncidentRecorderWriterLifecycleLease }
	| { state: "pending"; reason: "normal_holders_active" }
	| { state: "unavailable"; reason: IncidentRecorderWriterLifecycleUnavailableReason };

interface FrozenAdmissionContract {
	readonly activationGenerationDigest: string;
	readonly revalidateActivation: () => IncidentRecorderWriterLifecycleActivationResult;
	readonly acquireCas: (
		proof: IncidentRecorderWriterLifecycleProof,
		recorderRoot: string,
	) => IncidentCasTransactionAdmission;
}

interface RuntimeBinding {
	readCurrentProcessIdentity(): IncidentRecorderWriterLifecycleProcessIdentityObservation;
	readProcessIdentity(pid: number): IncidentRecorderWriterLifecycleProcessIdentityObservation;
	wallTimeMs(): number;
	onStep?(step: IncidentRecorderWriterLifecycleFaultStep, artifact: IncidentRecorderWriterLifecycleArtifact): void;
}

type DirectoryIdentity = IncidentRecorderWriterLifecycleNamespaceIdentity;

interface FileFingerprint {
	dev: bigint;
	ino: bigint;
	nlink: bigint;
	size: bigint;
	uid: bigint;
	mode: bigint;
	mtimeNs: bigint;
	ctimeNs: bigint;
}

interface LifecycleRecord {
	schemaVersion: 1;
	kind: IncidentRecorderWriterLifecycleArtifact;
	binding: IncidentRecorderWriterLifecycleNamespaceBinding;
	owner: IncidentRecorderWriterLifecycleProcessIdentity;
	nonce: string;
	slot: number | null;
}

interface RecordObservation {
	name: string;
	fingerprint: FileFingerprint;
	record?: LifecycleRecord;
}

interface RecordPair {
	artifact: IncidentRecorderWriterLifecycleArtifact;
	finalName: string;
	prepareName: string;
	slot: number | null;
}

interface LifecycleContext {
	parentPath: string;
	parentFd: number;
	agentName: string;
	controlName: string;
	controlFd: number;
	controlIdentity: DirectoryIdentity;
	binding: IncidentRecorderWriterLifecycleNamespaceBinding;
	current: IncidentRecorderWriterLifecycleProcessIdentity;
	runtime: RuntimeBinding;
	contract: FrozenAdmissionContract;
	closed: boolean;
}

interface GateHandle {
	observation: RecordObservation;
	record: LifecycleRecord;
	release(): boolean;
}

interface LeaseState {
	context: LifecycleContext;
	record: LifecycleRecord;
	observation: RecordObservation;
	artifact: "normal" | "recovery";
	consumeDetachment?: RecordObservation;
	recoveryPending?: RecordObservation;
	released: boolean;
	poisoned: boolean;
}

interface ProofState {
	active: boolean;
	binding: IncidentRecorderWriterLifecycleNamespaceBinding;
	assertCurrent(): boolean;
}

type PairState =
	| { state: "absent" }
	| { state: "present"; observation: RecordObservation; record: LifecycleRecord }
	| { state: "grace" }
	| { state: "invalid" }
	| { state: "unknown" };

class LifecycleFailure extends Error {
	readonly reason: IncidentRecorderWriterLifecycleUnavailableReason;

	constructor(reason: IncidentRecorderWriterLifecycleUnavailableReason) {
		super(reason);
		this.reason = reason;
	}
}

const registeredTestRuntimes = new WeakMap<object, IncidentRecorderWriterLifecycleRuntime>();
const proofStates = new WeakMap<object, ProofState>();

type TestRuntimeRegistrar = (
	runtime: IncidentRecorderWriterLifecycleRuntime,
) => IncidentRecorderWriterLifecycleTestRuntimeHandle;

function installTestRuntimeBridge(): void {
	if (process.env.VITEST_WORKER_ID === undefined) return;
	const host = globalThis as unknown as Record<PropertyKey, unknown>;
	const bridge = host[TEST_RUNTIME_BRIDGE_SYMBOL];
	delete host[TEST_RUNTIME_BRIDGE_SYMBOL];
	if (typeof bridge !== "function") return;
	(bridge as (registrar: TestRuntimeRegistrar) => void)((runtime) => {
		if (
			!isPlainObject(runtime) ||
			typeof runtime.readCurrentProcessIdentity !== "function" ||
			typeof runtime.readProcessIdentity !== "function"
		)
			throw new TypeError("invalid writer lifecycle test runtime");
		const handle = Object.freeze({}) as IncidentRecorderWriterLifecycleTestRuntimeHandle;
		registeredTestRuntimes.set(handle, runtime);
		return handle;
	});
}

installTestRuntimeBridge();

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (value === null || typeof value !== "object") return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: object, keys: readonly string[]): boolean {
	return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function ownDataProperty(value: object, name: string): unknown {
	const descriptor = Object.getOwnPropertyDescriptor(value, name);
	return descriptor && "value" in descriptor ? descriptor.value : undefined;
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
	if ((typeof value !== "object" || value === null) && typeof value !== "function") return false;
	try {
		return typeof (value as { then?: unknown }).then === "function";
	} catch {
		return true;
	}
}

function sha256(value: string | Uint8Array): string {
	return createHash("sha256").update(value).digest("hex");
}

function freezeAdmissionContract(contract: IncidentRecorderWriterLifecycleAdmissionContract): FrozenAdmissionContract {
	if (!isPlainObject(contract)) throw new LifecycleFailure("invalid_target");
	const activationGenerationDigest = ownDataProperty(contract, "activationGenerationDigest");
	const revalidateActivation = ownDataProperty(contract, "revalidateActivation");
	const acquireCas = ownDataProperty(contract, "acquireCas");
	if (
		typeof activationGenerationDigest !== "string" ||
		!SHA256.test(activationGenerationDigest) ||
		typeof revalidateActivation !== "function" ||
		typeof acquireCas !== "function"
	)
		throw new LifecycleFailure("invalid_target");
	return Object.freeze({
		activationGenerationDigest,
		revalidateActivation: () =>
			Reflect.apply(revalidateActivation as () => IncidentRecorderWriterLifecycleActivationResult, undefined, []),
		acquireCas: (proof: IncidentRecorderWriterLifecycleProof, recorderRoot: string) =>
			Reflect.apply(
				acquireCas as (
					proofValue: IncidentRecorderWriterLifecycleProof,
					root: string,
				) => IncidentCasTransactionAdmission,
				undefined,
				[proof, recorderRoot],
			),
	});
}

function validIdentity(value: unknown): value is IncidentRecorderWriterLifecycleProcessIdentity {
	return (
		isPlainObject(value) &&
		exactKeys(value, ["bootId", "pid", "processStartId", "uid"]) &&
		typeof value.bootId === "string" &&
		BOOT_ID.test(value.bootId) &&
		Number.isSafeInteger(value.pid) &&
		(value.pid as number) > 0 &&
		typeof value.processStartId === "string" &&
		PROCESS_START_ID.test(value.processStartId) &&
		Number.isSafeInteger(value.uid) &&
		(value.uid as number) >= 0
	);
}

function sameIdentity(
	left: IncidentRecorderWriterLifecycleProcessIdentity,
	right: IncidentRecorderWriterLifecycleProcessIdentity,
): boolean {
	return (
		left.bootId === right.bootId &&
		left.pid === right.pid &&
		left.processStartId === right.processStartId &&
		left.uid === right.uid
	);
}

function procStartId(pid: number): string | undefined {
	if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
	try {
		const value = readFileSync(`/proc/${pid}/stat`, "utf8");
		if (Buffer.byteLength(value) > 16 * 1024) return undefined;
		const commandEnd = value.lastIndexOf(")");
		if (commandEnd < 0) return undefined;
		const start = value.slice(commandEnd + 2).split(" ")[19];
		return start && /^[0-9]+$/.test(start) ? `proc:${start}` : undefined;
	} catch {
		return undefined;
	}
}

function bootId(): string | undefined {
	try {
		const value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
		return BOOT_ID.test(value) ? value : undefined;
	} catch {
		return undefined;
	}
}

function defaultCurrentIdentity(): IncidentRecorderWriterLifecycleProcessIdentityObservation {
	const currentBootId = bootId();
	const processStartId = procStartId(process.pid);
	const uid = process.getuid?.();
	return currentBootId && processStartId && uid !== undefined
		? { state: "present", identity: { bootId: currentBootId, pid: process.pid, processStartId, uid } }
		: { state: "unavailable", reason: "identity_malformed" };
}

function isMissing(error: unknown): boolean {
	return (
		error instanceof Error &&
		"code" in error &&
		((error as Error & { code?: string }).code === "ENOENT" || (error as Error & { code?: string }).code === "ESRCH")
	);
}

function defaultReadIdentity(pid: number): IncidentRecorderWriterLifecycleProcessIdentityObservation {
	if (!Number.isSafeInteger(pid) || pid <= 0) return { state: "unavailable", reason: "identity_malformed" };
	try {
		const firstStart = procStartId(pid);
		if (!firstStart) {
			try {
				statSync(`/proc/${pid}`);
				return { state: "unavailable", reason: "identity_malformed" };
			} catch (error) {
				return isMissing(error) ? { state: "absent" } : { state: "unavailable", reason: "proc_unavailable" };
			}
		}
		const uid = Number(statSync(`/proc/${pid}`, { bigint: true }).uid);
		const secondStart = procStartId(pid);
		const currentBootId = bootId();
		if (!secondStart || secondStart !== firstStart || !currentBootId || !Number.isSafeInteger(uid) || uid < 0)
			return { state: "unavailable", reason: "identity_malformed" };
		return {
			state: "present",
			identity: { bootId: currentBootId, pid, processStartId: firstStart, uid },
		};
	} catch (error) {
		return isMissing(error) ? { state: "absent" } : { state: "unavailable", reason: "proc_unavailable" };
	}
}

function bindRuntime(handle?: IncidentRecorderWriterLifecycleTestRuntimeHandle): RuntimeBinding {
	if (!handle) {
		return {
			readCurrentProcessIdentity: defaultCurrentIdentity,
			readProcessIdentity: defaultReadIdentity,
			wallTimeMs: Date.now,
		};
	}
	const runtime = registeredTestRuntimes.get(handle);
	if (!runtime) throw new TypeError("unregistered writer lifecycle test runtime");
	return Object.freeze({
		readCurrentProcessIdentity: runtime.readCurrentProcessIdentity.bind(runtime),
		readProcessIdentity: runtime.readProcessIdentity.bind(runtime),
		wallTimeMs: runtime.wallTimeMs?.bind(runtime) ?? Date.now,
		onStep: runtime.onStep?.bind(runtime),
	});
}

function isAlreadyExists(error: unknown): boolean {
	return error instanceof Error && "code" in error && (error as Error & { code?: string }).code === "EEXIST";
}

function sameStatIdentity(left: BigIntStats, right: BigIntStats): boolean {
	return left.dev === right.dev && left.ino === right.ino;
}

function directoryIdentity(path: string, stat: BigIntStats): DirectoryIdentity {
	return {
		path,
		dev: stat.dev.toString(),
		ino: stat.ino.toString(),
		uid: Number(stat.uid),
		gid: Number(stat.gid),
		mode: Number(stat.mode & 0o7777n),
	};
}

function publicIdentity(identity: DirectoryIdentity): IncidentRecorderWriterLifecycleNamespaceIdentity {
	return Object.freeze({
		path: identity.path,
		dev: identity.dev,
		ino: identity.ino,
		uid: identity.uid,
		gid: identity.gid,
		mode: identity.mode,
	});
}

function directoryIsPrivate(stat: BigIntStats, uid: number, exactMode?: bigint): boolean {
	if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(uid)) return false;
	const permissions = stat.mode & 0o777n;
	return exactMode === undefined ? (permissions & 0o022n) === 0n : permissions === exactMode;
}

function openPinnedDirectory(
	path: string,
	uid: number,
	exactMode?: bigint,
): {
	fd: number;
	identity: DirectoryIdentity;
} {
	const before = lstatSync(path, { bigint: true });
	if (!directoryIsPrivate(before, uid, exactMode)) throw new LifecycleFailure("namespace_unavailable");
	const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
	try {
		const opened = fstatSync(fd, { bigint: true });
		const after = lstatSync(path, { bigint: true });
		if (
			!directoryIsPrivate(opened, uid, exactMode) ||
			!sameStatIdentity(before, opened) ||
			!sameStatIdentity(opened, after) ||
			(opened.mode & 0o7777n) !== (after.mode & 0o7777n) ||
			opened.uid !== after.uid ||
			opened.gid !== after.gid
		)
			throw new LifecycleFailure("namespace_unavailable");
		return { fd, identity: directoryIdentity(path, opened) };
	} catch (error) {
		closeSync(fd);
		throw error;
	}
}

function descriptorChild(parentFd: number, name: string): string {
	return `/proc/self/fd/${parentFd}/${name}`;
}

function openPinnedChildDirectory(
	parentFd: number,
	name: string,
	publicPath: string,
	uid: number,
	exactMode?: bigint,
): { fd: number; identity: DirectoryIdentity } {
	if (!name || name === "." || name === ".." || name.includes("/") || name.includes("\0"))
		throw new LifecycleFailure("invalid_target");
	const path = descriptorChild(parentFd, name);
	const before = lstatSync(path, { bigint: true });
	if (!directoryIsPrivate(before, uid, exactMode)) throw new LifecycleFailure("namespace_unavailable");
	const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
	try {
		const opened = fstatSync(fd, { bigint: true });
		const after = lstatSync(path, { bigint: true });
		if (
			!directoryIsPrivate(opened, uid, exactMode) ||
			!sameStatIdentity(before, opened) ||
			!sameStatIdentity(opened, after) ||
			(opened.mode & 0o7777n) !== (after.mode & 0o7777n) ||
			opened.uid !== after.uid ||
			opened.gid !== after.gid
		)
			throw new LifecycleFailure("namespace_unavailable");
		return { fd, identity: directoryIdentity(publicPath, opened) };
	} catch (error) {
		closeSync(fd);
		throw error;
	}
}

function sameDirectoryIdentity(
	actual: DirectoryIdentity,
	expected: IncidentRecorderWriterLifecycleNamespaceIdentity,
): boolean {
	return (
		actual.dev === expected.dev &&
		actual.ino === expected.ino &&
		actual.uid === expected.uid &&
		actual.gid === expected.gid &&
		actual.mode === expected.mode
	);
}

function freezeBinding(
	activationGenerationDigest: string,
	stableParent: DirectoryIdentity,
	agentDir: DirectoryIdentity,
	recorder: DirectoryIdentity,
	incidents: DirectoryIdentity,
): IncidentRecorderWriterLifecycleNamespaceBinding {
	const value = {
		activationGenerationDigest,
		stableParent: publicIdentity(stableParent),
		agentDir: publicIdentity(agentDir),
		recorder: publicIdentity(recorder),
		incidents: publicIdentity(incidents),
	};
	const digest = sha256(JSON.stringify(value));
	return Object.freeze({ digest, ...value });
}

function activationValid(contract: FrozenAdmissionContract): boolean {
	try {
		const result = contract.revalidateActivation();
		return isPlainObject(result) && result.state === "valid";
	} catch {
		return false;
	}
}

function readCurrentIdentity(runtime: RuntimeBinding): IncidentRecorderWriterLifecycleProcessIdentity {
	let observation: IncidentRecorderWriterLifecycleProcessIdentityObservation;
	try {
		observation = runtime.readCurrentProcessIdentity();
	} catch {
		throw new LifecycleFailure("identity_unavailable");
	}
	if (!isPlainObject(observation) || observation.state !== "present" || !validIdentity(observation.identity))
		throw new LifecycleFailure("identity_unavailable");
	return Object.freeze({ ...observation.identity });
}

function createContext(
	target: IncidentRecorderWriterLifecycleTarget,
	contract: FrozenAdmissionContract,
	runtime: RuntimeBinding,
	current: IncidentRecorderWriterLifecycleProcessIdentity,
): LifecycleContext {
	if (!isPlainObject(target) || typeof ownDataProperty(target, "agentDir") !== "string")
		throw new LifecycleFailure("invalid_target");
	const input = ownDataProperty(target, "agentDir") as string;
	if (!isAbsolute(input) || input.includes("\0")) throw new LifecycleFailure("invalid_target");
	const requested = resolve(input);
	let canonicalAgentDir: string;
	try {
		canonicalAgentDir = realpathSync(requested);
	} catch {
		throw new LifecycleFailure("namespace_unavailable");
	}
	if (requested !== canonicalAgentDir) throw new LifecycleFailure("invalid_target");
	const parentPath = dirname(canonicalAgentDir);
	const agentName = basename(canonicalAgentDir);
	const parent = openPinnedDirectory(parentPath, current.uid);
	let agent: { fd: number; identity: DirectoryIdentity } | undefined;
	let recorder: { fd: number; identity: DirectoryIdentity } | undefined;
	let incidents: { fd: number; identity: DirectoryIdentity } | undefined;
	let control: { fd: number; identity: DirectoryIdentity } | undefined;
	let transferred = false;
	try {
		agent = openPinnedChildDirectory(parent.fd, agentName, canonicalAgentDir, current.uid);
		recorder = openPinnedChildDirectory(
			agent.fd,
			"incident-recorder",
			join(canonicalAgentDir, "incident-recorder"),
			current.uid,
		);
		incidents = openPinnedChildDirectory(agent.fd, "incidents", join(canonicalAgentDir, "incidents"), current.uid);
		const controlName = `${CONTROL_PREFIX}${sha256(canonicalAgentDir)}`;
		const controlPath = descriptorChild(parent.fd, controlName);
		try {
			mkdirSync(controlPath, { mode: 0o700 });
		} catch (error) {
			if (!isAlreadyExists(error)) throw error;
		}
		control = openPinnedChildDirectory(parent.fd, controlName, join(parentPath, controlName), current.uid, 0o700n);
		const binding = freezeBinding(
			contract.activationGenerationDigest,
			parent.identity,
			agent.identity,
			recorder.identity,
			incidents.identity,
		);
		const context: LifecycleContext = {
			parentPath,
			parentFd: parent.fd,
			agentName,
			controlName,
			controlFd: control.fd,
			controlIdentity: control.identity,
			binding,
			current,
			runtime,
			contract,
			closed: false,
		};
		control = undefined;
		transferred = true;
		return context;
	} finally {
		if (agent) closeSync(agent.fd);
		if (recorder) closeSync(recorder.fd);
		if (incidents) closeSync(incidents.fd);
		if (control) closeSync(control.fd);
		if (!transferred) closeSync(parent.fd);
	}
}

function closeContext(context: LifecycleContext): void {
	if (context.closed) return;
	context.closed = true;
	try {
		closeSync(context.controlFd);
	} catch {}
	try {
		closeSync(context.parentFd);
	} catch {}
}

function currentChildIdentity(
	parentFd: number,
	name: string,
	path: string,
	uid: number,
): DirectoryIdentity | undefined {
	let child: { fd: number; identity: DirectoryIdentity } | undefined;
	try {
		child = openPinnedChildDirectory(parentFd, name, path, uid);
		return child.identity;
	} catch {
		return undefined;
	} finally {
		if (child) closeSync(child.fd);
	}
}

function bindingCurrent(context: LifecycleContext): boolean {
	if (context.closed) return false;
	let agent: { fd: number; identity: DirectoryIdentity } | undefined;
	let recorder: { fd: number; identity: DirectoryIdentity } | undefined;
	let incidents: { fd: number; identity: DirectoryIdentity } | undefined;
	try {
		const retainedParent = directoryIdentity(context.parentPath, fstatSync(context.parentFd, { bigint: true }));
		const publicParent = openPinnedDirectory(context.parentPath, context.current.uid);
		try {
			if (
				!sameDirectoryIdentity(retainedParent, context.binding.stableParent) ||
				!sameDirectoryIdentity(publicParent.identity, context.binding.stableParent)
			)
				return false;
		} finally {
			closeSync(publicParent.fd);
		}
		const control = currentChildIdentity(
			context.parentFd,
			context.controlName,
			context.controlIdentity.path,
			context.current.uid,
		);
		const retainedControl = directoryIdentity(
			context.controlIdentity.path,
			fstatSync(context.controlFd, { bigint: true }),
		);
		if (
			!control ||
			!sameDirectoryIdentity(control, context.controlIdentity) ||
			!sameDirectoryIdentity(retainedControl, context.controlIdentity)
		)
			return false;
		agent = openPinnedChildDirectory(
			context.parentFd,
			context.agentName,
			context.binding.agentDir.path,
			context.current.uid,
		);
		if (!sameDirectoryIdentity(agent.identity, context.binding.agentDir)) return false;
		recorder = openPinnedChildDirectory(
			agent.fd,
			"incident-recorder",
			context.binding.recorder.path,
			context.current.uid,
		);
		incidents = openPinnedChildDirectory(agent.fd, "incidents", context.binding.incidents.path, context.current.uid);
		return (
			sameDirectoryIdentity(recorder.identity, context.binding.recorder) &&
			sameDirectoryIdentity(incidents.identity, context.binding.incidents)
		);
	} catch {
		return false;
	} finally {
		if (agent) closeSync(agent.fd);
		if (recorder) closeSync(recorder.fd);
		if (incidents) closeSync(incidents.fd);
	}
}

function pairFor(artifact: IncidentRecorderWriterLifecycleArtifact, slot: number | null = null): RecordPair {
	if (artifact === "normal") {
		if (slot === null || !Number.isInteger(slot) || slot < 0 || slot >= NORMAL_SLOT_COUNT)
			throw new LifecycleFailure("invalid_target");
		const stem = `normal-${String(slot).padStart(2, "0")}`;
		return { artifact, finalName: `${stem}.json`, prepareName: `${stem}.prepare`, slot };
	}
	const stem = artifact.replace("_", "-");
	return { artifact, finalName: `${stem}.json`, prepareName: `${stem}.prepare`, slot: null };
}

const CONTROL_PAIRS: readonly RecordPair[] = Object.freeze([
	pairFor("gate"),
	pairFor("detachment"),
	pairFor("recovery_pending"),
	pairFor("recovery"),
	...Array.from({ length: NORMAL_SLOT_COUNT }, (_value, slot) => pairFor("normal", slot)),
]);
const KNOWN_CONTROL_NAMES = new Set(CONTROL_PAIRS.flatMap((pair) => [pair.finalName, pair.prepareName]));

function controlChild(context: LifecycleContext, name: string): string {
	return descriptorChild(context.controlFd, name);
}

function fingerprint(stat: BigIntStats): FileFingerprint {
	return {
		dev: stat.dev,
		ino: stat.ino,
		nlink: stat.nlink,
		size: stat.size,
		uid: stat.uid,
		mode: stat.mode,
		mtimeNs: stat.mtimeNs,
		ctimeNs: stat.ctimeNs,
	};
}

function sameInode(left: FileFingerprint | undefined, right: FileFingerprint | undefined): boolean {
	return left !== undefined && right !== undefined && left.dev === right.dev && left.ino === right.ino;
}

function normalizedNamespaceIdentity(value: unknown): IncidentRecorderWriterLifecycleNamespaceIdentity | undefined {
	if (
		!isPlainObject(value) ||
		!exactKeys(value, ["dev", "gid", "ino", "mode", "path", "uid"]) ||
		typeof value.path !== "string" ||
		!isAbsolute(value.path) ||
		value.path.includes("\0") ||
		resolve(value.path) !== value.path ||
		typeof value.dev !== "string" ||
		!/^[0-9]+$/.test(value.dev) ||
		typeof value.ino !== "string" ||
		!/^[0-9]+$/.test(value.ino) ||
		!Number.isSafeInteger(value.uid) ||
		(value.uid as number) < 0 ||
		!Number.isSafeInteger(value.gid) ||
		(value.gid as number) < 0 ||
		!Number.isSafeInteger(value.mode) ||
		(value.mode as number) < 0 ||
		(value.mode as number) > 0o7777
	)
		return undefined;
	return Object.freeze({
		path: value.path,
		dev: value.dev,
		ino: value.ino,
		uid: value.uid as number,
		gid: value.gid as number,
		mode: value.mode as number,
	});
}

function normalizedBinding(value: unknown): IncidentRecorderWriterLifecycleNamespaceBinding | undefined {
	if (
		!isPlainObject(value) ||
		!exactKeys(value, [
			"activationGenerationDigest",
			"agentDir",
			"digest",
			"incidents",
			"recorder",
			"stableParent",
		]) ||
		typeof value.activationGenerationDigest !== "string" ||
		!SHA256.test(value.activationGenerationDigest) ||
		typeof value.digest !== "string" ||
		!SHA256.test(value.digest)
	)
		return undefined;
	const stableParent = normalizedNamespaceIdentity(value.stableParent);
	const agentDir = normalizedNamespaceIdentity(value.agentDir);
	const recorder = normalizedNamespaceIdentity(value.recorder);
	const incidents = normalizedNamespaceIdentity(value.incidents);
	if (
		!stableParent ||
		!agentDir ||
		!recorder ||
		!incidents ||
		dirname(agentDir.path) !== stableParent.path ||
		recorder.path !== join(agentDir.path, "incident-recorder") ||
		incidents.path !== join(agentDir.path, "incidents")
	)
		return undefined;
	const normalized = freezeBinding(value.activationGenerationDigest, stableParent, agentDir, recorder, incidents);
	return normalized.digest === value.digest ? normalized : undefined;
}

function normalizedRecord(value: unknown, uid: number): LifecycleRecord | undefined {
	if (
		!isPlainObject(value) ||
		!exactKeys(value, ["binding", "kind", "nonce", "owner", "schemaVersion", "slot"]) ||
		value.schemaVersion !== SCHEMA_VERSION ||
		!(["gate", "normal", "recovery_pending", "recovery", "detachment"] as const).includes(
			value.kind as IncidentRecorderWriterLifecycleArtifact,
		) ||
		!validIdentity(value.owner) ||
		value.owner.uid !== uid ||
		typeof value.nonce !== "string" ||
		!UUID_V4.test(value.nonce)
	)
		return undefined;
	const binding = normalizedBinding(value.binding);
	if (!binding) return undefined;
	if (
		!(
			value.slot === null ||
			(Number.isInteger(value.slot) && (value.slot as number) >= 0 && (value.slot as number) < NORMAL_SLOT_COUNT)
		)
	)
		return undefined;
	return Object.freeze({
		schemaVersion: SCHEMA_VERSION,
		kind: value.kind as IncidentRecorderWriterLifecycleArtifact,
		binding,
		owner: Object.freeze({ ...(value.owner as IncidentRecorderWriterLifecycleProcessIdentity) }),
		nonce: value.nonce,
		slot: value.slot as number | null,
	});
}

function recordMatchesPair(record: LifecycleRecord, pair: RecordPair): boolean {
	return record.kind === pair.artifact && record.slot === pair.slot;
}

function readRecordObservation(context: LifecycleContext, name: string): RecordObservation | undefined {
	const path = controlChild(context, name);
	let before: BigIntStats;
	try {
		before = lstatSync(path, { bigint: true });
	} catch (error) {
		if (isMissing(error)) return undefined;
		throw error;
	}
	const observed: RecordObservation = { name, fingerprint: fingerprint(before) };
	if (
		!before.isFile() ||
		before.isSymbolicLink() ||
		before.uid !== BigInt(context.current.uid) ||
		(before.mode & 0o077n) !== 0n ||
		before.nlink < 1n ||
		before.nlink > 2n ||
		before.size <= 0n ||
		before.size > BigInt(RECORD_MAX_BYTES)
	)
		return observed;
	let fd: number | undefined;
	try {
		fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const opened = fstatSync(fd, { bigint: true });
		if (
			!opened.isFile() ||
			opened.uid !== before.uid ||
			(opened.mode & 0o077n) !== 0n ||
			!sameStatIdentity(before, opened) ||
			opened.size !== before.size ||
			opened.nlink < 1n ||
			opened.nlink > 2n
		)
			return observed;
		const bytes = Buffer.alloc(Number(opened.size) + 1);
		let offset = 0;
		while (offset < bytes.length) {
			const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
			if (count === 0) break;
			offset += count;
		}
		const after = fstatSync(fd, { bigint: true });
		const pathAfter = lstatSync(path, { bigint: true });
		if (
			offset !== Number(opened.size) ||
			!sameStatIdentity(opened, after) ||
			!sameStatIdentity(after, pathAfter) ||
			after.size !== opened.size ||
			after.mtimeNs !== opened.mtimeNs ||
			after.ctimeNs !== opened.ctimeNs
		)
			return observed;
		const parsed = JSON.parse(bytes.subarray(0, offset).toString("utf8")) as unknown;
		const record = normalizedRecord(parsed, context.current.uid);
		if (record) observed.record = record;
		return observed;
	} catch {
		return observed;
	} finally {
		if (fd !== undefined) {
			try {
				closeSync(fd);
			} catch {}
		}
	}
}

function observationCurrent(context: LifecycleContext, observation: RecordObservation): boolean {
	try {
		const current = lstatSync(controlChild(context, observation.name), { bigint: true });
		return current.dev === observation.fingerprint.dev && current.ino === observation.fingerprint.ino;
	} catch {
		return false;
	}
}

function unlinkObservation(context: LifecycleContext, observation: RecordObservation): boolean {
	if (!observationCurrent(context, observation)) return false;
	try {
		unlinkSync(controlChild(context, observation.name));
		return true;
	} catch (error) {
		return isMissing(error);
	}
}

function artifactMature(context: LifecycleContext, observation: RecordObservation): boolean {
	const age = context.runtime.wallTimeMs() - Number(observation.fingerprint.mtimeNs / 1_000_000n);
	return Number.isFinite(age) && age >= INVALID_ARTIFACT_GRACE_MS;
}

function ownerDisposition(context: LifecycleContext, record: LifecycleRecord): "live" | "stale" | "unknown" {
	if (record.owner.bootId !== context.current.bootId) return "stale";
	let observed: IncidentRecorderWriterLifecycleProcessIdentityObservation;
	try {
		observed = context.runtime.readProcessIdentity(record.owner.pid);
	} catch {
		return "unknown";
	}
	if (!isPlainObject(observed)) return "unknown";
	if (observed.state === "absent") return "stale";
	if (observed.state !== "present" || !validIdentity(observed.identity)) return "unknown";
	return sameIdentity(observed.identity, record.owner) ? "live" : "stale";
}

function fsyncControl(context: LifecycleContext): void {
	fsyncSync(context.controlFd);
}

function reapObservation(
	context: LifecycleContext,
	observation: RecordObservation,
	artifact: IncidentRecorderWriterLifecycleArtifact,
): boolean {
	context.runtime.onStep?.("before_record_reap", artifact);
	if (!unlinkObservation(context, observation)) return false;
	context.runtime.onStep?.("record_reaped", artifact);
	return true;
}

function preserveStaleBindingDetachment(context: LifecycleContext, pair: RecordPair, record: LifecycleRecord): void {
	if (pair.artifact === "gate" || pair.artifact === "detachment" || record.binding.digest === context.binding.digest)
		return;
	ensureDetachmentUnderGate(context, record.binding);
}

function repairPair(context: LifecycleContext, pair: RecordPair): PairState {
	let final = readRecordObservation(context, pair.finalName);
	let prepare = readRecordObservation(context, pair.prepareName);
	if (final && prepare && sameInode(final.fingerprint, prepare.fingerprint)) {
		if (!unlinkObservation(context, prepare)) return { state: "invalid" };
		fsyncControl(context);
		context.runtime.onStep?.("cleanup_fsynced", pair.artifact);
		prepare = undefined;
		final = readRecordObservation(context, pair.finalName);
	}
	if (final && prepare) return { state: "invalid" };
	if (final) {
		if (!final.record || !recordMatchesPair(final.record, pair)) {
			if (!artifactMature(context, final)) return { state: "grace" };
			if (!reapObservation(context, final, pair.artifact)) return { state: "invalid" };
			fsyncControl(context);
			return { state: "absent" };
		}
		if (pair.artifact === "detachment") return { state: "present", observation: final, record: final.record };
		const disposition = ownerDisposition(context, final.record);
		if (disposition === "unknown") return { state: "unknown" };
		if (disposition === "live") return { state: "present", observation: final, record: final.record };
		preserveStaleBindingDetachment(context, pair, final.record);
		if (!reapObservation(context, final, pair.artifact)) return { state: "invalid" };
		fsyncControl(context);
		return { state: "absent" };
	}
	if (!prepare) return { state: "absent" };
	if (!prepare.record || !recordMatchesPair(prepare.record, pair)) {
		if (!artifactMature(context, prepare)) return { state: "grace" };
		if (!reapObservation(context, prepare, pair.artifact)) return { state: "invalid" };
		fsyncControl(context);
		return { state: "absent" };
	}
	const disposition = ownerDisposition(context, prepare.record);
	if (disposition === "unknown") return { state: "unknown" };
	if (disposition === "live") return { state: "present", observation: prepare, record: prepare.record };
	preserveStaleBindingDetachment(context, pair, prepare.record);
	if (!reapObservation(context, prepare, pair.artifact)) return { state: "invalid" };
	fsyncControl(context);
	return { state: "absent" };
}

function knownControlNamespace(context: LifecycleContext): boolean {
	let directory: ReturnType<typeof opendirSync> | undefined;
	try {
		directory = opendirSync(`/proc/self/fd/${context.controlFd}`);
		let count = 0;
		for (;;) {
			const entry = directory.readSync();
			if (!entry) return true;
			count += 1;
			if (count > KNOWN_CONTROL_NAMES.size || !KNOWN_CONTROL_NAMES.has(entry.name)) return false;
		}
	} catch {
		return false;
	} finally {
		try {
			directory?.closeSync();
		} catch {}
	}
}

function writeAll(fd: number, bytes: Buffer): void {
	let offset = 0;
	while (offset < bytes.length) {
		const written = writeSync(fd, bytes, offset, bytes.length - offset, offset);
		if (written <= 0) throw new Error("writer lifecycle record write made no progress");
		offset += written;
	}
}

function makeRecord(context: LifecycleContext, pair: RecordPair, binding = context.binding): LifecycleRecord {
	return Object.freeze({
		schemaVersion: SCHEMA_VERSION,
		kind: pair.artifact,
		binding,
		owner: context.current,
		nonce: randomUUID(),
		slot: pair.slot,
	});
}

function publishRecord(
	context: LifecycleContext,
	pair: RecordPair,
	record: LifecycleRecord = makeRecord(context, pair),
): RecordObservation {
	if (readRecordObservation(context, pair.finalName) || readRecordObservation(context, pair.prepareName))
		throw new LifecycleFailure("control_artifact_busy");
	const preparePath = controlChild(context, pair.prepareName);
	let fd: number | undefined;
	try {
		fd = openSync(
			preparePath,
			constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
			0o600,
		);
		context.runtime.onStep?.("prepare_opened", pair.artifact);
		fchmodSync(fd, 0o600);
		context.runtime.onStep?.("prepare_chmodded", pair.artifact);
		const bytes = Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
		if (bytes.length > RECORD_MAX_BYTES) throw new Error("writer lifecycle record exceeded bound");
		writeAll(fd, bytes);
		context.runtime.onStep?.("prepare_written", pair.artifact);
		fsyncSync(fd);
		context.runtime.onStep?.("prepare_fsynced", pair.artifact);
	} finally {
		if (fd !== undefined) closeSync(fd);
	}
	linkSync(preparePath, controlChild(context, pair.finalName));
	context.runtime.onStep?.("record_linked", pair.artifact);
	fsyncControl(context);
	context.runtime.onStep?.("directory_fsynced", pair.artifact);
	const published = readRecordObservation(context, pair.finalName);
	const prepared = readRecordObservation(context, pair.prepareName);
	if (
		!published?.record ||
		!prepared ||
		!prepared.record ||
		!sameInode(published.fingerprint, prepared.fingerprint) ||
		JSON.stringify(published.record) !== JSON.stringify(record)
	)
		throw new Error("writer lifecycle publication did not read back exactly");
	unlinkSync(preparePath);
	context.runtime.onStep?.("prepare_unlinked", pair.artifact);
	fsyncControl(context);
	context.runtime.onStep?.("cleanup_fsynced", pair.artifact);
	const final = readRecordObservation(context, pair.finalName);
	if (!final?.record || JSON.stringify(final.record) !== JSON.stringify(record))
		throw new Error("writer lifecycle record changed after publication");
	return final;
}

function releaseRecord(
	context: LifecycleContext,
	observation: RecordObservation,
	artifact: IncidentRecorderWriterLifecycleArtifact,
): boolean {
	context.runtime.onStep?.("before_record_release", artifact);
	if (!unlinkObservation(context, observation)) return false;
	context.runtime.onStep?.("record_released", artifact);
	fsyncControl(context);
	return true;
}

function acquireGate(context: LifecycleContext): GateHandle {
	if (!knownControlNamespace(context)) throw new LifecycleFailure("invalid_control_artifact");
	const pair = pairFor("gate");
	for (let attempt = 0; attempt < 4; attempt += 1) {
		const state = repairPair(context, pair);
		if (state.state === "grace") throw new LifecycleFailure("control_artifact_grace");
		if (state.state === "invalid") throw new LifecycleFailure("invalid_control_artifact");
		if (state.state === "unknown") throw new LifecycleFailure("owner_liveness_unknown");
		if (state.state === "present") throw new LifecycleFailure("control_artifact_busy");
		const record = makeRecord(context, pair);
		try {
			const observation = publishRecord(context, pair, record);
			return {
				observation,
				record,
				release: () => releaseRecord(context, observation, "gate"),
			};
		} catch (error) {
			if (error instanceof LifecycleFailure && error.reason === "control_artifact_busy") continue;
			throw error;
		}
	}
	throw new LifecycleFailure("control_artifact_busy");
}

function requirePairState(
	state: PairState,
): asserts state is
	| { state: "absent" }
	| { state: "present"; observation: RecordObservation; record: LifecycleRecord } {
	if (state.state === "grace") throw new LifecycleFailure("control_artifact_grace");
	if (state.state === "invalid") throw new LifecycleFailure("invalid_control_artifact");
	if (state.state === "unknown") throw new LifecycleFailure("owner_liveness_unknown");
}

function ensureDetachmentUnderGate(
	context: LifecycleContext,
	binding: IncidentRecorderWriterLifecycleNamespaceBinding = context.binding,
): RecordObservation {
	const pair = pairFor("detachment");
	const state = repairPair(context, pair);
	requirePairState(state);
	if (state.state === "present") return state.observation;
	return publishRecord(context, pair, makeRecord(context, pair, binding));
}

function persistDetachment(context: LifecycleContext): RecordObservation | undefined {
	let gate: GateHandle | undefined;
	try {
		gate = acquireGate(context);
		return ensureDetachmentUnderGate(context);
	} catch {
		return undefined;
	} finally {
		try {
			gate?.release();
		} catch {}
	}
}

function recordCurrent(state: LeaseState): boolean {
	if (state.released || state.context.closed) return false;
	const pair = pairFor(state.artifact, state.record.slot);
	const observed = readRecordObservation(state.context, pair.finalName);
	return (
		observed?.record !== undefined &&
		sameInode(observed.fingerprint, state.observation.fingerprint) &&
		JSON.stringify(observed.record) === JSON.stringify(state.record)
	);
}

function makeScopedFile(file: IncidentCasFileMutation, assertActive: () => void): IncidentCasFileMutation {
	return Object.freeze({
		stat: () => {
			assertActive();
			return file.stat();
		},
		read: (target: Uint8Array, offset: number, length: number, position: number | null) => {
			assertActive();
			return file.read(target, offset, length, position);
		},
		write: (source: Uint8Array, offset: number, length: number, position: number | null) => {
			assertActive();
			return file.write(source, offset, length, position);
		},
		writeText: (value: string, position: number | null) => {
			assertActive();
			return file.writeText(value, position);
		},
		truncate: (length: number) => {
			assertActive();
			file.truncate(length);
		},
		chmod: (mode: number) => {
			assertActive();
			file.chmod(mode);
		},
		sync: () => {
			assertActive();
			file.sync();
		},
	});
}

function synchronousCallback<T>(operation: () => T, message: string): T {
	const value = operation();
	if (isPromiseLike(value)) throw new TypeError(message);
	return value;
}

function makeScopedRoot(root: IncidentCasRootMutation, assertActive: () => void): IncidentCasRootMutation {
	const capability: IncidentCasRootMutation = {
		relative: (...components) => {
			assertActive();
			return root.relative(...components);
		},
		publicPath: (path) => {
			assertActive();
			return root.publicPath(path);
		},
		exists: (path) => {
			assertActive();
			return root.exists(path);
		},
		lstat: (path) => {
			assertActive();
			return root.lstat(path);
		},
		stat: (path) => {
			assertActive();
			return root.stat(path);
		},
		statfs: (path) => {
			assertActive();
			return root.statfs(path);
		},
		readFile: (path, maxBytes) => {
			assertActive();
			return root.readFile(path, maxBytes);
		},
		readlink: (path) => {
			assertActive();
			return root.readlink(path);
		},
		realpath: (path) => {
			assertActive();
			return root.realpath(path);
		},
		writeFileExclusive: (path, value, mode) => {
			assertActive();
			root.writeFileExclusive(path, value, mode);
		},
		mkdirPrivate: (path, recursive) => {
			assertActive();
			root.mkdirPrivate(path, recursive);
		},
		chmod: (path, mode) => {
			assertActive();
			root.chmod(path, mode);
		},
		unlinkFile: (path) => {
			assertActive();
			root.unlinkFile(path);
		},
		rmdir: (path) => {
			assertActive();
			root.rmdir(path);
		},
		rename: (source, destination) => {
			assertActive();
			root.rename(source, destination);
		},
		hardLink: (source, destination) => {
			assertActive();
			root.hardLink(source, destination);
		},
		fsyncFile: (path) => {
			assertActive();
			root.fsyncFile(path);
		},
		fsyncDirectory: (path) => {
			assertActive();
			root.fsyncDirectory(path);
		},
		withFile: <T>(
			path: Parameters<IncidentCasRootMutation["withFile"]>[0],
			options: IncidentCasFileOpenOptions,
			operation: (file: IncidentCasFileMutation) => T,
		): T => {
			assertActive();
			return root.withFile(path, options, (file) => {
				let nestedActive = true;
				const scoped = makeScopedFile(file, () => {
					assertActive();
					if (!nestedActive) throw new TypeError("CAS file capability is no longer active");
				});
				try {
					return synchronousCallback(() => operation(scoped), "CAS file callback must complete synchronously");
				} finally {
					nestedActive = false;
				}
			});
		},
		withDirectory: <T>(
			path: Parameters<IncidentCasRootMutation["withDirectory"]>[0],
			operation: (directory: IncidentCasRootMutation) => T,
		): T => {
			assertActive();
			return root.withDirectory(path, (directory) => {
				let nestedActive = true;
				const scoped = makeScopedRoot(directory, () => {
					assertActive();
					if (!nestedActive) throw new TypeError("CAS directory capability is no longer active");
				});
				try {
					return synchronousCallback(
						() => operation(scoped),
						"CAS directory callback must complete synchronously",
					);
				} finally {
					nestedActive = false;
				}
			});
		},
		directoryPage: (path, options) => {
			assertActive();
			return root.directoryPage(path, options);
		},
	};
	return Object.freeze(capability);
}

function makeProof(state: LeaseState): {
	proof: IncidentRecorderWriterLifecycleProof;
	revoke(): void;
} {
	const proof = Object.freeze({}) as IncidentRecorderWriterLifecycleProof;
	const proofState: ProofState = {
		active: true,
		binding: state.context.binding,
		assertCurrent: () => !state.released && !state.poisoned && recordCurrent(state) && bindingCurrent(state.context),
	};
	proofStates.set(proof, proofState);
	return {
		proof,
		revoke: () => {
			proofState.active = false;
			proofStates.delete(proof);
		},
	};
}

export function inspectIncidentRecorderWriterLifecycleProof(
	proof: IncidentRecorderWriterLifecycleProof | undefined,
): IncidentRecorderWriterLifecycleNamespaceBinding | undefined {
	if (!proof) return undefined;
	const state = proofStates.get(proof);
	if (!state?.active) return undefined;
	try {
		return state.assertCurrent() ? state.binding : undefined;
	} catch {
		return undefined;
	}
}

function validCasAdmission(value: unknown): value is IncidentCasTransactionAdmission {
	if (!isPlainObject(value)) return false;
	if (value.state === "unavailable") return typeof value.reason === "string";
	return (
		value.state === "acquired" &&
		isPlainObject(value.transaction) &&
		typeof value.transaction.withRoot === "function" &&
		typeof value.transaction.release === "function"
	);
}

function validCasRootResult(value: unknown): value is IncidentCasRootMutationResult<unknown> {
	if (!isPlainObject(value)) return false;
	if (value.state === "committed") return exactKeys(value, ["state", "value"]);
	return (
		value.state === "root_detached" &&
		exactKeys(value, ["state", "evidence"]) &&
		(value.evidence === "durable" || value.evidence === "pending")
	);
}

function releaseCas(transaction: CasTransaction): IncidentCasTransactionReleaseResult | undefined {
	try {
		const result = transaction.release();
		return isPlainObject(result) && (result.state === "released" || result.state === "pending") ? result : undefined;
	} catch {
		return undefined;
	}
}

function markNamespaceChanged(state: LeaseState): void {
	state.poisoned = true;
	persistDetachment(state.context);
}

function mutateThroughLease<T>(
	state: LeaseState,
	operation: (root: IncidentCasRootMutation) => T,
): IncidentRecorderWriterLifecycleMutationResult<T> {
	if (state.released) return { state: "unavailable", reason: "released" };
	if (state.poisoned) return { state: "unavailable", reason: "namespace_changed" };
	if (!bindingCurrent(state.context)) {
		markNamespaceChanged(state);
		return { state: "unavailable", reason: "namespace_changed" };
	}
	if (!recordCurrent(state)) return { state: "unavailable", reason: "lease_lost" };
	if (!activationValid(state.context.contract)) return { state: "unavailable", reason: "activation_invalid" };

	const scopedProof = makeProof(state);
	let transaction: CasTransaction | undefined;
	let rootResult: ReturnType<CasTransaction["withRoot"]> | undefined;
	let operationError: unknown;
	let callbackInvoked = false;
	let callbackValue: T | undefined;
	let rootResultThenable = false;
	try {
		let admission: IncidentCasTransactionAdmission;
		try {
			admission = state.context.contract.acquireCas(scopedProof.proof, state.context.binding.recorder.path);
		} catch (error) {
			operationError = error;
			admission = { state: "unavailable", reason: "creation_failed" };
		}
		if (!validCasAdmission(admission)) return { state: "unavailable", reason: "admission_contract_invalid" };
		if (operationError !== undefined) throw operationError;
		if (admission.state === "unavailable") return { state: "unavailable", reason: "cas_unavailable" };
		transaction = admission.transaction;
		rootResult = transaction.withRoot((root) => {
			if (callbackInvoked) throw new TypeError("CAS admission invoked the lifecycle callback more than once");
			callbackInvoked = true;
			let scopeActive = true;
			const scopedRoot = makeScopedRoot(root, () => {
				if (!scopeActive) throw new TypeError("writer lifecycle root capability is no longer active");
				if (!proofStates.get(scopedProof.proof)?.active)
					throw new TypeError("writer lifecycle proof is no longer active");
			});
			try {
				callbackValue = synchronousCallback(
					() => operation(scopedRoot),
					"writer lifecycle mutation must complete synchronously",
				);
				return callbackValue;
			} finally {
				scopeActive = false;
			}
		});
		rootResultThenable = isPromiseLike(rootResult);
	} catch (error) {
		operationError = error;
	} finally {
		scopedProof.revoke();
	}
	const casRelease = transaction ? releaseCas(transaction) : undefined;
	if (operationError !== undefined) throw operationError;
	if (!transaction) return { state: "unavailable", reason: "admission_contract_invalid" };
	if (!casRelease || casRelease.state === "pending") return { state: "unavailable", reason: "cas_release_pending" };
	if (rootResultThenable || !validCasRootResult(rootResult))
		return { state: "unavailable", reason: "admission_contract_invalid" };
	if (rootResult.state === "root_detached") return { state: "unavailable", reason: "root_detached" };
	if (!callbackInvoked) return { state: "unavailable", reason: "admission_contract_invalid" };
	if (!activationValid(state.context.contract)) return { state: "unavailable", reason: "activation_invalid" };
	if (!bindingCurrent(state.context)) {
		markNamespaceChanged(state);
		return { state: "unavailable", reason: "namespace_changed" };
	}
	if (!recordCurrent(state)) return { state: "unavailable", reason: "lease_lost" };
	if (!Object.is(rootResult.value, callbackValue))
		return { state: "unavailable", reason: "admission_contract_invalid" };
	return { state: "committed", value: callbackValue as T };
}

function closeReleasedLease(state: LeaseState, cleanupPending: boolean): IncidentRecorderWriterLifecycleReleaseResult {
	state.released = true;
	closeContext(state.context);
	return { state: "released", cleanupPending };
}

function removePairIfExact(
	context: LifecycleContext,
	observation: RecordObservation | undefined,
	artifact: IncidentRecorderWriterLifecycleArtifact,
): boolean {
	if (!observation) return true;
	if (!observationCurrent(context, observation)) return true;
	return releaseRecord(context, observation, artifact);
}

function releaseLease(state: LeaseState): IncidentRecorderWriterLifecycleReleaseResult {
	if (state.released) return { state: "released", cleanupPending: false };
	if (!recordCurrent(state)) {
		if (!bindingCurrent(state.context)) markNamespaceChanged(state);
		return closeReleasedLease(state, state.poisoned);
	}
	let gate: GateHandle | undefined;
	let completed = false;
	try {
		gate = acquireGate(state.context);
		const namespaceStillCurrent = bindingCurrent(state.context);
		if (!namespaceStillCurrent) {
			state.poisoned = true;
			ensureDetachmentUnderGate(state.context);
		}
		if (!removePairIfExact(state.context, state.observation, state.artifact))
			return { state: "pending", reason: "io_error" };
		if (state.artifact === "recovery") {
			if (!removePairIfExact(state.context, state.recoveryPending, "recovery_pending"))
				return { state: "pending", reason: "io_error" };
			if (
				!state.poisoned &&
				namespaceStillCurrent &&
				!removePairIfExact(state.context, state.consumeDetachment, "detachment")
			)
				return { state: "pending", reason: "io_error" };
		}
		completed = true;
	} catch (error) {
		if (error instanceof LifecycleFailure && error.reason === "control_artifact_busy")
			return { state: "pending", reason: "control_artifact_busy" };
		return { state: "pending", reason: "io_error" };
	} finally {
		if (gate) {
			try {
				if (!gate.release()) completed = false;
			} catch {
				completed = false;
			}
		}
	}
	return completed ? closeReleasedLease(state, false) : { state: "pending", reason: "io_error" };
}

function makeLease(state: LeaseState): IncidentRecorderWriterLifecycleLease {
	return Object.freeze({
		withRoot: <T>(operation: (root: IncidentCasRootMutation) => T) => mutateThroughLease(state, operation),
		release: () => releaseLease(state),
	});
}

function assertNamespaceReady(context: LifecycleContext): void {
	if (!knownControlNamespace(context)) throw new LifecycleFailure("invalid_control_artifact");
	if (!bindingCurrent(context)) throw new LifecycleFailure("namespace_unavailable");
	if (!activationValid(context.contract)) throw new LifecycleFailure("activation_invalid");
}

function withGate<T>(context: LifecycleContext, operation: () => T): T {
	const gate = acquireGate(context);
	let primary: { state: "returned"; value: T } | { state: "threw"; error: unknown };
	try {
		primary = { state: "returned", value: operation() };
	} catch (error) {
		primary = { state: "threw", error };
	}
	let releaseError: unknown;
	try {
		if (!gate.release()) releaseError = new LifecycleFailure("io_error");
	} catch (error) {
		releaseError = error;
	}
	if (primary.state === "threw") throw primary.error;
	if (releaseError !== undefined)
		throw releaseError instanceof LifecycleFailure ? releaseError : new LifecycleFailure("io_error");
	return primary.value;
}

function acquireNormalInContext(context: LifecycleContext): {
	record: LifecycleRecord;
	observation: RecordObservation;
} {
	return withGate(context, () => {
		assertNamespaceReady(context);
		const detachment = repairPair(context, pairFor("detachment"));
		requirePairState(detachment);
		if (detachment.state === "present") throw new LifecycleFailure("namespace_detached");

		const recovery = repairPair(context, pairFor("recovery"));
		requirePairState(recovery);
		if (recovery.state === "present") {
			throw new LifecycleFailure(
				recovery.record.binding.digest === context.binding.digest
					? "recovery_active"
					: "namespace_transition_blocked",
			);
		}
		const pending = repairPair(context, pairFor("recovery_pending"));
		requirePairState(pending);
		if (pending.state === "present") {
			throw new LifecycleFailure(
				pending.record.binding.digest === context.binding.digest
					? "recovery_pending"
					: "namespace_transition_blocked",
			);
		}

		let available: RecordPair | undefined;
		for (let slot = 0; slot < NORMAL_SLOT_COUNT; slot += 1) {
			const pair = pairFor("normal", slot);
			const holder = repairPair(context, pair);
			requirePairState(holder);
			if (holder.state === "absent") {
				available ??= pair;
				continue;
			}
			if (holder.record.binding.digest !== context.binding.digest)
				throw new LifecycleFailure("namespace_transition_blocked");
		}
		const promotedDetachment = repairPair(context, pairFor("detachment"));
		requirePairState(promotedDetachment);
		if (promotedDetachment.state === "present") throw new LifecycleFailure("namespace_detached");
		if (!available) throw new LifecycleFailure("holder_capacity");
		const record = makeRecord(context, available);
		const observation = publishRecord(context, available, record);
		if (!bindingCurrent(context) || !activationValid(context.contract)) {
			ensureDetachmentUnderGate(context);
			releaseRecord(context, observation, "normal");
			throw new LifecycleFailure("namespace_unavailable");
		}
		return { record, observation };
	});
}

function acquireRecoveryInContext(context: LifecycleContext):
	| {
			state: "acquired";
			record: LifecycleRecord;
			observation: RecordObservation;
			pending: RecordObservation;
			detachment?: RecordObservation;
	  }
	| { state: "pending" } {
	return withGate(context, () => {
		assertNamespaceReady(context);
		const detachmentState = repairPair(context, pairFor("detachment"));
		requirePairState(detachmentState);
		let detachment = detachmentState.state === "present" ? detachmentState.observation : undefined;

		const recoveryState = repairPair(context, pairFor("recovery"));
		requirePairState(recoveryState);
		if (recoveryState.state === "present") {
			throw new LifecycleFailure(
				recoveryState.record.binding.digest === context.binding.digest
					? "recovery_active"
					: "namespace_transition_blocked",
			);
		}

		const pendingPair = pairFor("recovery_pending");
		const pendingState = repairPair(context, pendingPair);
		requirePairState(pendingState);
		let pending: RecordObservation;
		if (pendingState.state === "present") {
			if (pendingState.record.binding.digest !== context.binding.digest)
				throw new LifecycleFailure("namespace_transition_blocked");
			if (!sameIdentity(pendingState.record.owner, context.current)) throw new LifecycleFailure("recovery_pending");
			pending = pendingState.observation;
		} else {
			pending = publishRecord(context, pendingPair);
		}

		let holdersActive = false;
		for (let slot = 0; slot < NORMAL_SLOT_COUNT; slot += 1) {
			const holder = repairPair(context, pairFor("normal", slot));
			requirePairState(holder);
			if (holder.state === "absent") continue;
			if (holder.record.binding.digest !== context.binding.digest)
				throw new LifecycleFailure("namespace_transition_blocked");
			holdersActive = true;
		}
		const promotedDetachment = repairPair(context, pairFor("detachment"));
		requirePairState(promotedDetachment);
		if (promotedDetachment.state === "present") detachment = promotedDetachment.observation;
		if (holdersActive) return { state: "pending" };

		const recoveryPair = pairFor("recovery");
		const record = makeRecord(context, recoveryPair);
		const observation = publishRecord(context, recoveryPair, record);
		if (!bindingCurrent(context) || !activationValid(context.contract)) {
			ensureDetachmentUnderGate(context);
			throw new LifecycleFailure("namespace_unavailable");
		}
		if (!releaseRecord(context, pending, "recovery_pending")) throw new LifecycleFailure("io_error");
		return { state: "acquired", record, observation, pending, detachment };
	});
}

function initialContext(
	target: IncidentRecorderWriterLifecycleTarget,
	contractInput: IncidentRecorderWriterLifecycleAdmissionContract,
	testRuntimeHandle?: IncidentRecorderWriterLifecycleTestRuntimeHandle,
): LifecycleContext {
	if (process.platform !== "linux" && !testRuntimeHandle) throw new LifecycleFailure("platform_unsupported");
	const runtime = bindRuntime(testRuntimeHandle);
	const contract = freezeAdmissionContract(contractInput);
	if (!activationValid(contract)) throw new LifecycleFailure("activation_invalid");
	const current = readCurrentIdentity(runtime);
	return createContext(target, contract, runtime, current);
}

function acquisitionFailure(
	error: unknown,
	testRuntimeHandle?: IncidentRecorderWriterLifecycleTestRuntimeHandle,
): { state: "unavailable"; reason: IncidentRecorderWriterLifecycleUnavailableReason } {
	if (error instanceof LifecycleFailure) return { state: "unavailable", reason: error.reason };
	if (testRuntimeHandle) throw error;
	return { state: "unavailable", reason: "io_error" };
}

export function acquireIncidentRecorderWriterNormalLease(
	target: IncidentRecorderWriterLifecycleTarget,
	contract: IncidentRecorderWriterLifecycleAdmissionContract,
	testRuntimeHandle?: IncidentRecorderWriterLifecycleTestRuntimeHandle,
): AcquireIncidentRecorderWriterNormalLeaseResult {
	let context: LifecycleContext | undefined;
	try {
		context = initialContext(target, contract, testRuntimeHandle);
		const acquired = acquireNormalInContext(context);
		const state: LeaseState = {
			context,
			record: acquired.record,
			observation: acquired.observation,
			artifact: "normal",
			released: false,
			poisoned: false,
		};
		context = undefined;
		return { state: "acquired", lease: makeLease(state) };
	} catch (error) {
		return acquisitionFailure(error, testRuntimeHandle);
	} finally {
		if (context) closeContext(context);
	}
}

export function acquireIncidentRecorderWriterRecoveryLease(
	target: IncidentRecorderWriterLifecycleTarget,
	contract: IncidentRecorderWriterLifecycleAdmissionContract,
	testRuntimeHandle?: IncidentRecorderWriterLifecycleTestRuntimeHandle,
): AcquireIncidentRecorderWriterRecoveryLeaseResult {
	let context: LifecycleContext | undefined;
	try {
		context = initialContext(target, contract, testRuntimeHandle);
		const acquired = acquireRecoveryInContext(context);
		if (acquired.state === "pending") return { state: "pending", reason: "normal_holders_active" };
		const state: LeaseState = {
			context,
			record: acquired.record,
			observation: acquired.observation,
			artifact: "recovery",
			consumeDetachment: acquired.detachment,
			recoveryPending: acquired.pending,
			released: false,
			poisoned: false,
		};
		context = undefined;
		return { state: "acquired", lease: makeLease(state) };
	} catch (error) {
		return acquisitionFailure(error, testRuntimeHandle);
	} finally {
		if (context) closeContext(context);
	}
}
