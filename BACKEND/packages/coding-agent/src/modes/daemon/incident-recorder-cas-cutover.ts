import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	type BigIntStats,
	chmodSync,
	closeSync,
	constants,
	fchmodSync,
	fstatSync,
	fsyncSync,
	linkSync,
	lstatSync,
	opendirSync,
	openSync,
	readFileSync,
	readlinkSync,
	readSync,
	realpathSync,
	renameSync,
	statSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

/**
 * The v2 service has a dedicated entrypoint. Frozen v1 only dispatches through
 * the legacy CLI selector, so adding another argument to that selector would
 * not establish a generation boundary.
 */
export const INCIDENT_CAS_V2_SERVICE_ENTRYPOINT = "dist/bundle/incident-recorder-service-v2.js";
export const INCIDENT_CAS_V2_SYSTEMD_UNIT = "prime-agent-incident-recorder.service";
export const INCIDENT_CAS_V2_CLI_ENTRYPOINT = "dist/bundle/cli.js";
export const INCIDENT_CAS_V2_LEGACY_SELECTOR_REJECTION_MARKER = "GRIMOIRE_INCIDENT_CAS_V2_REJECTS_LEGACY_SELECTOR";

const CONTROL_PREFIX = ".grimoire-incident-cas-v2-";
const TEST_RUNTIME_BRIDGE_SYMBOL = Symbol.for("grimoire.incident-cas-v2.test-runtime-bridge.v1");
const GENERATION_SUFFIX = ".generation.json";
const PREPARE_SUFFIX = ".generation.prepare";
const CLAIM_SUFFIX = ".generation.claim";
const LEGACY_AUTHORITY = ".cas-transaction";
const SCHEMA_VERSION = 1;
const RECORD_MAX_BYTES = 16 * 1024;
const PROC_FILE_MAX_BYTES = 1024 * 1024;
const DIRECTORY_SCAN_MAX_ENTRIES = 65_536;
const SCRATCH_GRACE_MS = 1_000;
const SCRATCH_OBSERVATION_MAX = 256;
/**
 * The durable admission boundary covers the installed package named by the
 * target and its controlled systemd unit. Historical arbitrary copies outside
 * that package are a cooperative trust boundary, not a universally fenced
 * process-launch namespace.
 */
const HISTORICAL_COPY_BOUNDARY = "arbitrary_historical_copies_outside_controlled_package_are_cooperative";
const SYSTEMD_OUTPUT_MAX_BYTES = 256 * 1024;
const WITNESS_MAX_AGE_MS = 5_000;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HOST_ID = /^[0-9A-Za-z][0-9A-Za-z._:-]{0,127}$/;
const PROCESS_START_ID = /^[0-9]+$/;
const SYSTEMD_MONOTONIC = /^[1-9][0-9]*$/;

export interface IncidentCasV2CutoverTarget {
	/** Replaceable common root containing the two fixed incident namespaces. */
	agentDir: string;
	/** Canonical installed `@earendil-works/pi-coding-agent` package root. */
	packageRoot: string;
	launcher: {
		unitPath: string;
		unitContents: string;
		argv: readonly string[];
	};
}

export interface IncidentCasV2ObservedFile {
	path: string;
	dev: string;
	ino: string;
	uid: number;
	gid: number;
	mode: number;
	nlink: number;
	size: number;
	sha256: string;
}

export interface IncidentCasV2ObservedIdentity {
	path: string;
	dev: string;
	ino: string;
	uid: number;
	gid: number;
	mode: number;
	nlink: number;
}

export type IncidentCasV2LauncherObservation =
	| {
			state: "observed";
			unitName: string;
			loadState: string;
			activeState: string;
			subState: string;
			needDaemonReload: string;
			mainPid: number;
			execMainPid: number;
			controlPid: number;
			observationGeneration: string;
			fragment: IncidentCasV2ObservedFile;
			node: IncidentCasV2ObservedIdentity;
			entrypoint: IncidentCasV2ObservedFile;
			managerExecStartArgv: readonly string[];
	  }
	| {
			state: "unavailable";
			code:
				| "systemctl_failed"
				| "systemctl_malformed"
				| "fragment_unavailable"
				| "entrypoint_unavailable"
				| "node_unavailable";
	  };

export interface IncidentCasV2ObservedProcess {
	pid: number;
	parentPid: number;
	uid: number;
	startId: string;
	processState: string;
	inspection: "complete" | "ambiguous";
	argv: readonly string[];
	cwd: string | null;
	executable: string | null;
}

export type IncidentCasV2ProcessPopulationObservation =
	| {
			state: "observed";
			processes: readonly IncidentCasV2ObservedProcess[];
			/** Complete observations for every same-UID process in a closing `/proc` pass. */
			finalSameUidProcesses: readonly IncidentCasV2ObservedProcess[];
	  }
	| { state: "unavailable"; code: "proc_unavailable" | "population_limit" | "population_changed" };

export interface IncidentCasV2ProcessIdentity {
	machineId: string;
	bootId: string;
	pid: number;
	startId: string;
	uid: number;
	gid: number;
}

export type IncidentCasV2ProcessIdentityObservation =
	| { state: "present"; identity: IncidentCasV2ProcessIdentity }
	| { state: "absent" }
	| { state: "unavailable"; code: "proc_unavailable" | "identity_malformed" };

/**
 * Read-only observation seams. Production callers omit this object and use the
 * module-owned Linux verifier. Tests may inject raw observations; there is no
 * Boolean or free-form quiescence override.
 */
export interface IncidentCasV2CutoverRuntime {
	/** Makes test-only verifier injection conspicuous at every call site. */
	readonly kind: "incident_cas_v2_structured_test_runtime";
	readLauncher(unitName: string): IncidentCasV2LauncherObservation;
	readProcessPopulation(): IncidentCasV2ProcessPopulationObservation;
	readCurrentProcessIdentity(): IncidentCasV2ProcessIdentityObservation;
	readProcessIdentity(pid: number): IncidentCasV2ProcessIdentityObservation;
	monotonicTimeMs?(): number;
	onStep?(step: IncidentCasV2CutoverStep): void;
}

declare const testRuntimeHandleBrand: unique symbol;

/** Opaque verifier handle issued only by the module's Vitest bootstrap bridge. */
export interface IncidentCasV2TestRuntimeHandle {
	readonly [testRuntimeHandleBrand]: true;
}

export type IncidentCasV2CutoverStep =
	| "claim_scratch_opened"
	| "claim_scratch_chmodded"
	| "claim_scratch_partially_written"
	| "claim_scratch_written"
	| "claim_prepared"
	| "claim_linked"
	| "claim_directory_fsynced"
	| "claim_prepare_unlinked"
	| "draining_scratch_opened"
	| "draining_scratch_chmodded"
	| "draining_scratch_partially_written"
	| "draining_scratch_written"
	| "draining_prepared"
	| "draining_linked"
	| "draining_directory_fsynced"
	| "draining_prepare_unlinked"
	| "quiescence_observed"
	| "v2_scratch_opened"
	| "v2_scratch_chmodded"
	| "v2_scratch_partially_written"
	| "v2_scratch_written"
	| "v2_prepared"
	| "before_v2_publish"
	| "after_final_quiescence"
	| "v2_published"
	| "v2_directory_fsynced"
	| "claim_retirement_linked"
	| "claim_unlinked"
	| "cleanup_directory_fsynced";

export type IncidentCasV2UnavailableReason =
	| "platform_unsupported"
	| "invalid_target"
	| "root_unavailable"
	| "control_identity_changed"
	| "invalid_control_artifact"
	| "target_mismatch"
	| "legacy_v1_authority_present"
	| "launcher_unavailable"
	| "launcher_mismatch"
	| "launcher_not_stopped"
	| "process_population_ambiguous"
	| "controlled_processes_present"
	| "orchestration_in_progress"
	| "orchestration_owner_unknown"
	| "claim_lost"
	| "generation_changed"
	| "witness_invalid"
	| "witness_stale"
	| "activation_cleanup_pending"
	| "io_error";

declare const cutoverBrand: unique symbol;
declare const witnessBrand: unique symbol;
declare const activationBrand: unique symbol;

export interface IncidentCasV2Cutover {
	readonly [cutoverBrand]: true;
	/** Closes retained descriptors without removing the durable draining claim. */
	close(): void;
}

export interface IncidentCasV1QuiescenceWitness {
	readonly [witnessBrand]: true;
}

export interface IncidentCasV2Activation {
	readonly [activationBrand]: true;
	/** Identity of the retained generation, not proof that admission is still valid. */
	readonly activationGenerationDigest: string;
	revalidate(): { state: "valid" } | { state: "invalid"; reason: IncidentCasV2UnavailableReason };
	close(): void;
}

export type BeginIncidentCasV2CutoverResult =
	| { state: "draining"; cutover: IncidentCasV2Cutover }
	| { state: "v2" }
	| { state: "unavailable"; reason: IncidentCasV2UnavailableReason };

export type ProveIncidentCasV1QuiescenceResult =
	| { state: "proved"; witness: IncidentCasV1QuiescenceWitness }
	| { state: "unavailable"; reason: IncidentCasV2UnavailableReason; blockingPids?: readonly number[] };

export type PublishIncidentCasV2Result =
	| { state: "published" }
	| { state: "unavailable"; reason: IncidentCasV2UnavailableReason; blockingPids?: readonly number[] };

export type OpenIncidentCasV2ActivationResult =
	| { state: "active"; activation: IncidentCasV2Activation }
	| { state: "unavailable"; reason: IncidentCasV2UnavailableReason };

interface FileIdentity {
	dev: bigint;
	ino: bigint;
	mode: bigint;
	uid: bigint;
	gid: bigint;
	nlink: bigint;
	size: bigint;
	mtimeNs: bigint;
	ctimeNs: bigint;
}

interface ControlBinding {
	path: string;
	dev: string;
	ino: string;
	uid: string;
	gid: string;
	mode: number;
}

interface GenerationRecord {
	schemaVersion: 1;
	kind: "incident_cas_v2_generation";
	state: "draining" | "v2";
	cutoverId: string;
	canonicalAgentDirPath: string;
	incidentRecorderPath: string;
	incidentsPath: string;
	historicalCopyBoundary: typeof HISTORICAL_COPY_BOUNDARY;
	control: ControlBinding;
	launcherConfigurationDigest: string;
}

interface ClaimRecord {
	schemaVersion: 1;
	kind: "incident_cas_v2_orchestration_claim";
	cutoverId: string;
	claimId: string;
	canonicalAgentDirPath: string;
	incidentRecorderPath: string;
	incidentsPath: string;
	historicalCopyBoundary: typeof HISTORICAL_COPY_BOUNDARY;
	control: ControlBinding;
	launcherConfigurationDigest: string;
	owner: IncidentCasV2ProcessIdentity;
}

type ControlRecord = GenerationRecord | ClaimRecord;

interface ArtifactSnapshot {
	record: ControlRecord;
	bytes: Buffer;
	identity: FileIdentity;
}

interface ArtifactState {
	generation?: ArtifactSnapshot;
	prepare?: ArtifactSnapshot;
	claim?: ArtifactSnapshot;
}

interface PinnedFile {
	descriptor: number;
	identity: FileIdentity;
	bytes: Buffer;
}

interface RootContext {
	canonicalAgentDirPath: string;
	agentDirName: string;
	incidentRecorderPath: string;
	incidentsPath: string;
	controlPath: string;
	controlDescriptor: number;
	controlIdentity: FileIdentity;
	controlBinding: ControlBinding;
	baseName: string;
	generationPath: string;
	preparePath: string;
	claimPath: string;
	closed: boolean;
}

interface NormalizedTarget {
	agentDir: string;
	incidentRecorderPath: string;
	incidentsPath: string;
	packageRoot: string;
	processScopeRoot: string;
	unitPath: string;
	unitContents: string;
	unitSha256: string;
	expectedArgv: readonly string[];
	nodePath: string;
	entrypointPath: string;
	launcherConfigurationDigest: string;
}

interface RuntimeBinding {
	readLauncher(unitName: string): IncidentCasV2LauncherObservation;
	readProcessPopulation(): IncidentCasV2ProcessPopulationObservation;
	readCurrentProcessIdentity(): IncidentCasV2ProcessIdentityObservation;
	readProcessIdentity(pid: number): IncidentCasV2ProcessIdentityObservation;
	monotonicTimeMs(): number;
	onStep?(step: IncidentCasV2CutoverStep): void;
	testRuntime?: IncidentCasV2CutoverRuntime;
}

interface CutoverState {
	context: RootContext;
	target: NormalizedTarget;
	runtime: RuntimeBinding;
	claim: ArtifactSnapshot;
	generation: ArtifactSnapshot;
	closed: boolean;
}

interface WitnessState {
	cutover: CutoverState;
	used: boolean;
	issuedAtMs: number;
	observationGeneration: string;
	launcherEvidenceDigest: string;
	claimIdentity: FileIdentity;
	generationIdentity: FileIdentity;
}

interface ActivationState {
	context: RootContext;
	target: NormalizedTarget;
	runtime: RuntimeBinding;
	generation: ArtifactSnapshot;
	launcherEvidenceDigest: string;
	closed: boolean;
	revokedReason?: IncidentCasV2UnavailableReason;
}

interface LauncherEvidence {
	observationGeneration: string;
	digest: string;
}

type QuiescenceEvidence =
	| { state: "proved"; launcher: LauncherEvidence }
	| {
			state: "unavailable";
			reason: IncidentCasV2UnavailableReason;
			blockingPids?: readonly number[];
	  };

const cutovers = new WeakMap<object, CutoverState>();
const witnesses = new WeakMap<object, WitnessState>();
const activations = new WeakMap<object, ActivationState>();
const registeredTestRuntimes = new WeakMap<object, IncidentCasV2CutoverRuntime>();
interface CleanupTestSynchronization {
	hook(): void;
}

export type IncidentCasV2CleanupTestBoundary = "scratch-recovery" | "prepare-discard" | "claim-retirement";

const cleanupTestSynchronizations = new WeakMap<
	IncidentCasV2CutoverRuntime,
	Map<IncidentCasV2CleanupTestBoundary, CleanupTestSynchronization>
>();

/** @internal One-shot synchronization for deterministic cutover cleanup races. */
export function registerIncidentCasV2CleanupTestSynchronization(
	runtime: IncidentCasV2CutoverRuntime,
	hook: () => void,
	boundary: IncidentCasV2CleanupTestBoundary = "scratch-recovery",
): () => void {
	if (process.env.NODE_ENV !== "test" || process.env.VITEST_WORKER_ID === undefined)
		throw new Error("incident CAS v2 cleanup synchronization is unavailable outside tests");
	const synchronizations =
		cleanupTestSynchronizations.get(runtime) ??
		new Map<IncidentCasV2CleanupTestBoundary, CleanupTestSynchronization>();
	if (synchronizations.has(boundary)) throw new Error("incident CAS v2 cleanup synchronization is already registered");
	const synchronization = Object.freeze({ hook });
	synchronizations.set(boundary, synchronization);
	cleanupTestSynchronizations.set(runtime, synchronizations);
	return () => {
		if (synchronizations.get(boundary) !== synchronization) return;
		synchronizations.delete(boundary);
		if (synchronizations.size === 0) cleanupTestSynchronizations.delete(runtime);
	};
}

function runCleanupTestSynchronization(runtime: RuntimeBinding, boundary: IncidentCasV2CleanupTestBoundary): void {
	const key = runtime.testRuntime;
	if (!key) return;
	const synchronizations = cleanupTestSynchronizations.get(key);
	const synchronization = synchronizations?.get(boundary);
	if (!synchronization) return;
	synchronizations?.delete(boundary);
	if (synchronizations?.size === 0) cleanupTestSynchronizations.delete(key);
	synchronization.hook();
}
const scratchObservations = new Map<string, { signature: string; firstSeenMs: number }>();

type TestRuntimeRegistrar = (runtime: IncidentCasV2CutoverRuntime) => IncidentCasV2TestRuntimeHandle;

function installTestRuntimeBridge(): void {
	if (process.env.VITEST_WORKER_ID === undefined) return;
	const host = globalThis as unknown as Record<PropertyKey, unknown>;
	const bridge = host[TEST_RUNTIME_BRIDGE_SYMBOL];
	delete host[TEST_RUNTIME_BRIDGE_SYMBOL];
	if (typeof bridge !== "function") return;
	(bridge as (registrar: TestRuntimeRegistrar) => void)((runtime) => {
		if (!isPlainObject(runtime) || runtime.kind !== "incident_cas_v2_structured_test_runtime")
			throw new Error("invalid incident CAS v2 test runtime");
		const handle = Object.freeze({}) as IncidentCasV2TestRuntimeHandle;
		registeredTestRuntimes.set(handle, runtime);
		return handle;
	});
}

installTestRuntimeBridge();

class CutoverFailure extends Error {
	constructor(readonly reason: IncidentCasV2UnavailableReason) {
		super(reason);
	}
}

function sha256(value: string | Uint8Array): string {
	return createHash("sha256").update(value).digest("hex");
}

function exactKeys(value: object, keys: readonly string[]): boolean {
	const actual = Object.keys(value);
	return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeInteger(value: unknown, minimum = 0): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
}

function isDecimal(value: unknown): value is string {
	return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

function isDigest(value: unknown): value is string {
	return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function identity(stats: BigIntStats): FileIdentity {
	return {
		dev: stats.dev,
		ino: stats.ino,
		mode: stats.mode,
		uid: stats.uid,
		gid: stats.gid,
		nlink: stats.nlink,
		size: stats.size,
		mtimeNs: stats.mtimeNs,
		ctimeNs: stats.ctimeNs,
	};
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.mode === right.mode &&
		left.uid === right.uid &&
		left.gid === right.gid &&
		left.nlink === right.nlink &&
		left.size === right.size &&
		left.mtimeNs === right.mtimeNs &&
		left.ctimeNs === right.ctimeNs
	);
}

function sameDirectoryIdentity(left: FileIdentity, right: FileIdentity): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.mode === right.mode &&
		left.uid === right.uid &&
		left.gid === right.gid
	);
}

function sameObject(left: FileIdentity, right: FileIdentity): boolean {
	return left.dev === right.dev && left.ino === right.ino;
}

function controlBinding(path: string, stats: FileIdentity): ControlBinding {
	return {
		path,
		dev: stats.dev.toString(),
		ino: stats.ino.toString(),
		uid: stats.uid.toString(),
		gid: stats.gid.toString(),
		mode: Number(stats.mode & 0o7777n),
	};
}

function sameControlBinding(left: ControlBinding, right: ControlBinding): boolean {
	return (
		left.path === right.path &&
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.uid === right.uid &&
		left.gid === right.gid &&
		left.mode === right.mode
	);
}

function validControlBinding(value: unknown): value is ControlBinding {
	return (
		isPlainObject(value) &&
		exactKeys(value, ["path", "dev", "ino", "uid", "gid", "mode"]) &&
		typeof value.path === "string" &&
		isAbsolute(value.path) &&
		resolve(value.path) === value.path &&
		isDecimal(value.dev) &&
		isDecimal(value.ino) &&
		isDecimal(value.uid) &&
		isDecimal(value.gid) &&
		isSafeInteger(value.mode) &&
		value.mode <= 0o7777
	);
}

function validOwner(value: unknown): value is IncidentCasV2ProcessIdentity {
	return (
		isPlainObject(value) &&
		exactKeys(value, ["machineId", "bootId", "pid", "startId", "uid", "gid"]) &&
		typeof value.machineId === "string" &&
		HOST_ID.test(value.machineId) &&
		typeof value.bootId === "string" &&
		HOST_ID.test(value.bootId) &&
		isSafeInteger(value.pid, 1) &&
		typeof value.startId === "string" &&
		PROCESS_START_ID.test(value.startId) &&
		isSafeInteger(value.uid) &&
		isSafeInteger(value.gid)
	);
}

function validGenerationRecord(value: unknown): value is GenerationRecord {
	return (
		isPlainObject(value) &&
		exactKeys(value, [
			"schemaVersion",
			"kind",
			"state",
			"cutoverId",
			"canonicalAgentDirPath",
			"incidentRecorderPath",
			"incidentsPath",
			"historicalCopyBoundary",
			"control",
			"launcherConfigurationDigest",
		]) &&
		value.schemaVersion === SCHEMA_VERSION &&
		value.kind === "incident_cas_v2_generation" &&
		(value.state === "draining" || value.state === "v2") &&
		typeof value.cutoverId === "string" &&
		UUID_V4.test(value.cutoverId) &&
		typeof value.canonicalAgentDirPath === "string" &&
		isAbsolute(value.canonicalAgentDirPath) &&
		resolve(value.canonicalAgentDirPath) === value.canonicalAgentDirPath &&
		typeof value.incidentRecorderPath === "string" &&
		value.incidentRecorderPath === join(value.canonicalAgentDirPath, "incident-recorder") &&
		typeof value.incidentsPath === "string" &&
		value.incidentsPath === join(value.canonicalAgentDirPath, "incidents") &&
		value.historicalCopyBoundary === HISTORICAL_COPY_BOUNDARY &&
		validControlBinding(value.control) &&
		isDigest(value.launcherConfigurationDigest)
	);
}

function validClaimRecord(value: unknown): value is ClaimRecord {
	return (
		isPlainObject(value) &&
		exactKeys(value, [
			"schemaVersion",
			"kind",
			"cutoverId",
			"claimId",
			"canonicalAgentDirPath",
			"incidentRecorderPath",
			"incidentsPath",
			"historicalCopyBoundary",
			"control",
			"launcherConfigurationDigest",
			"owner",
		]) &&
		value.schemaVersion === SCHEMA_VERSION &&
		value.kind === "incident_cas_v2_orchestration_claim" &&
		typeof value.cutoverId === "string" &&
		UUID_V4.test(value.cutoverId) &&
		typeof value.claimId === "string" &&
		UUID_V4.test(value.claimId) &&
		typeof value.canonicalAgentDirPath === "string" &&
		isAbsolute(value.canonicalAgentDirPath) &&
		resolve(value.canonicalAgentDirPath) === value.canonicalAgentDirPath &&
		typeof value.incidentRecorderPath === "string" &&
		value.incidentRecorderPath === join(value.canonicalAgentDirPath, "incident-recorder") &&
		typeof value.incidentsPath === "string" &&
		value.incidentsPath === join(value.canonicalAgentDirPath, "incidents") &&
		value.historicalCopyBoundary === HISTORICAL_COPY_BOUNDARY &&
		validControlBinding(value.control) &&
		isDigest(value.launcherConfigurationDigest) &&
		validOwner(value.owner)
	);
}

function serializeRecord(record: ControlRecord): Buffer {
	return Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
}

function parseRecord(bytes: Buffer): ControlRecord | undefined {
	let value: unknown;
	try {
		value = JSON.parse(bytes.toString("utf8"));
	} catch {
		return undefined;
	}
	if (!validGenerationRecord(value) && !validClaimRecord(value)) return undefined;
	return serializeRecord(value).equals(bytes) ? value : undefined;
}

function noFollowDirectoryFlags(): number {
	return constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
}

function noFollowReadFlags(): number {
	return constants.O_RDONLY | constants.O_NOFOLLOW;
}

function descriptorPath(descriptor: number, name?: string): string {
	const base = `/proc/self/fd/${descriptor}`;
	return name === undefined ? base : join(base, name);
}

function openStableDirectory(path: string): { descriptor: number; identity: FileIdentity } {
	const before = identity(lstatSync(path, { bigint: true }));
	if ((before.mode & 0o170000n) !== 0o040000n) throw new CutoverFailure("root_unavailable");
	const descriptor = openSync(path, noFollowDirectoryFlags());
	try {
		const opened = identity(fstatSync(descriptor, { bigint: true }));
		const after = identity(lstatSync(path, { bigint: true }));
		if (!sameDirectoryIdentity(before, opened) || !sameDirectoryIdentity(opened, after))
			throw new CutoverFailure("root_unavailable");
		return { descriptor, identity: opened };
	} catch (error) {
		closeSync(descriptor);
		throw error;
	}
}

function createRootContext(agentDir: string): RootContext {
	let controlDescriptor: number | undefined;
	try {
		const canonicalAgentDirPath = realpathSync.native(resolve(agentDir));
		if (canonicalAgentDirPath !== resolve(agentDir)) throw new CutoverFailure("root_unavailable");
		const controlPath = dirname(canonicalAgentDirPath);
		const control = openStableDirectory(controlPath);
		controlDescriptor = control.descriptor;
		if ((control.identity.mode & 0o022n) !== 0n) throw new CutoverFailure("root_unavailable");
		const agentDirName = basename(canonicalAgentDirPath);
		if (!agentDirName || agentDirName === "." || agentDirName === "..") throw new CutoverFailure("root_unavailable");
		const incidentRecorderPath = join(canonicalAgentDirPath, "incident-recorder");
		const incidentsPath = join(canonicalAgentDirPath, "incidents");
		const baseName = `${CONTROL_PREFIX}${sha256(canonicalAgentDirPath).slice(0, 32)}`;
		const context: RootContext = {
			canonicalAgentDirPath,
			agentDirName,
			incidentRecorderPath,
			incidentsPath,
			controlPath,
			controlDescriptor,
			controlIdentity: control.identity,
			controlBinding: controlBinding(controlPath, control.identity),
			baseName,
			generationPath: descriptorPath(controlDescriptor, `${baseName}${GENERATION_SUFFIX}`),
			preparePath: descriptorPath(controlDescriptor, `${baseName}${PREPARE_SUFFIX}`),
			claimPath: descriptorPath(controlDescriptor, `${baseName}${CLAIM_SUFFIX}`),
			closed: false,
		};
		if (!contextCurrent(context)) throw new CutoverFailure("root_unavailable");
		controlDescriptor = undefined;
		return context;
	} catch (error) {
		if (controlDescriptor !== undefined) closeSync(controlDescriptor);
		if (error instanceof CutoverFailure) throw error;
		throw new CutoverFailure("root_unavailable");
	}
}

function closeContext(context: RootContext): void {
	if (context.closed) return;
	context.closed = true;
	closeSync(context.controlDescriptor);
}

function currentPrivateDirectory(context: RootContext, descriptorRelativePath: string, publicPath: string): boolean {
	let descriptor: number | undefined;
	try {
		if (realpathSync.native(publicPath) !== publicPath) return false;
		const descriptorBoundPath = descriptorPath(context.controlDescriptor, descriptorRelativePath);
		const relativeBefore = identity(lstatSync(descriptorBoundPath, { bigint: true }));
		const publicBefore = identity(lstatSync(publicPath, { bigint: true }));
		descriptor = openSync(descriptorBoundPath, noFollowDirectoryFlags());
		const opened = identity(fstatSync(descriptor, { bigint: true }));
		const relativeAfter = identity(lstatSync(descriptorBoundPath, { bigint: true }));
		const publicAfter = identity(lstatSync(publicPath, { bigint: true }));
		return (
			(relativeBefore.mode & 0o170000n) === 0o040000n &&
			sameDirectoryIdentity(relativeBefore, publicBefore) &&
			sameDirectoryIdentity(publicBefore, opened) &&
			sameDirectoryIdentity(opened, relativeAfter) &&
			sameDirectoryIdentity(relativeAfter, publicAfter) &&
			opened.uid === context.controlIdentity.uid &&
			opened.gid === context.controlIdentity.gid &&
			(opened.mode & 0o022n) === 0n
		);
	} catch {
		return false;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function contextCurrent(context: RootContext): boolean {
	if (context.closed) return false;
	try {
		const controlFd = identity(fstatSync(context.controlDescriptor, { bigint: true }));
		const controlPath = identity(lstatSync(context.controlPath, { bigint: true }));
		return (
			sameDirectoryIdentity(controlFd, context.controlIdentity) &&
			sameDirectoryIdentity(controlPath, context.controlIdentity) &&
			currentPrivateDirectory(context, context.agentDirName, context.canonicalAgentDirPath) &&
			currentPrivateDirectory(
				context,
				join(context.agentDirName, "incident-recorder"),
				context.incidentRecorderPath,
			) &&
			currentPrivateDirectory(context, join(context.agentDirName, "incidents"), context.incidentsPath)
		);
	} catch {
		return false;
	}
}

function assertContextCurrent(context: RootContext): void {
	if (!contextCurrent(context)) throw new CutoverFailure("control_identity_changed");
}

function assertKnownControlNamespace(context: RootContext): void {
	assertContextCurrent(context);
	const cutoverPrefix = `${context.baseName}.generation`;
	const allowed = new Set([
		`${context.baseName}${GENERATION_SUFFIX}`,
		`${context.baseName}${PREPARE_SUFFIX}`,
		`${context.baseName}${CLAIM_SUFFIX}`,
	]);
	let directory: ReturnType<typeof opendirSync> | undefined;
	try {
		directory = opendirSync(descriptorPath(context.controlDescriptor));
		let count = 0;
		while (true) {
			const entry = directory.readSync();
			if (!entry) break;
			count += 1;
			if (count > DIRECTORY_SCAN_MAX_ENTRIES) throw new CutoverFailure("invalid_control_artifact");
			if (entry.name.startsWith(cutoverPrefix) && !allowed.has(entry.name))
				throw new CutoverFailure("invalid_control_artifact");
		}
		directory.closeSync();
		directory = undefined;
	} catch (error) {
		if (error instanceof CutoverFailure) throw error;
		throw new CutoverFailure("invalid_control_artifact");
	} finally {
		if (directory) {
			try {
				directory.closeSync();
			} catch {
				// The operation is already failing closed; do not disclose a raw close error.
			}
		}
	}
	assertContextCurrent(context);
}

function pathExistsNoFollow(path: string): boolean {
	try {
		lstatSync(path);
		return true;
	} catch (error) {
		if (isErrno(error, "ENOENT")) return false;
		throw error;
	}
}

function assertLegacyAbsent(context: RootContext): void {
	assertContextCurrent(context);
	const legacyPath = descriptorPath(
		context.controlDescriptor,
		join(context.agentDirName, "incident-recorder", LEGACY_AUTHORITY),
	);
	if (pathExistsNoFollow(legacyPath)) throw new CutoverFailure("legacy_v1_authority_present");
	assertContextCurrent(context);
}

function isErrno(error: unknown, code: string): boolean {
	return isPlainObject(error) && error.code === code;
}

function readDescriptorBoundFile(descriptor: number, maxBytes: number): Buffer {
	const initial = identity(fstatSync(descriptor, { bigint: true }));
	if (initial.size < 1n || initial.size > BigInt(maxBytes) || initial.size > BigInt(Number.MAX_SAFE_INTEGER))
		throw new Error("bounded file size invalid");
	const output = Buffer.alloc(Number(initial.size));
	let offset = 0;
	while (offset < output.length) {
		const count = readSync(descriptor, output, offset, output.length - offset, offset);
		if (count === 0) throw new Error("short file read");
		offset += count;
	}
	const after = identity(fstatSync(descriptor, { bigint: true }));
	if (!sameIdentity(initial, after)) throw new Error("file changed during read");
	return output;
}

function readArtifact(path: string, context: RootContext): ArtifactSnapshot | undefined {
	let before: FileIdentity;
	try {
		before = identity(lstatSync(path, { bigint: true }));
	} catch (error) {
		if (isErrno(error, "ENOENT")) return undefined;
		throw new CutoverFailure("invalid_control_artifact");
	}
	if (
		(before.mode & 0o170000n) !== 0o100000n ||
		(before.mode & 0o7777n) !== 0o600n ||
		before.uid !== context.controlIdentity.uid ||
		before.gid !== context.controlIdentity.gid ||
		(before.nlink !== 1n && before.nlink !== 2n) ||
		before.size < 1n ||
		before.size > BigInt(RECORD_MAX_BYTES)
	)
		throw new CutoverFailure("invalid_control_artifact");
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, noFollowReadFlags());
		const opened = identity(fstatSync(descriptor, { bigint: true }));
		const bytes = readDescriptorBoundFile(descriptor, RECORD_MAX_BYTES);
		const after = identity(lstatSync(path, { bigint: true }));
		if (!sameIdentity(before, opened) || !sameIdentity(opened, after))
			throw new CutoverFailure("invalid_control_artifact");
		const record = parseRecord(bytes);
		if (!record) throw new CutoverFailure("invalid_control_artifact");
		return { record, bytes, identity: opened };
	} catch (error) {
		if (error instanceof CutoverFailure) throw error;
		throw new CutoverFailure("invalid_control_artifact");
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function samePinnedFile(left: FileIdentity, right: FileIdentity): boolean {
	return (
		left.dev === right.dev &&
		left.ino === right.ino &&
		left.mode === right.mode &&
		left.uid === right.uid &&
		left.gid === right.gid &&
		left.size === right.size &&
		left.mtimeNs === right.mtimeNs
	);
}

function readDescriptorBoundFileAllowEmpty(descriptor: number, maxBytes: number): Buffer {
	const initial = identity(fstatSync(descriptor, { bigint: true }));
	if (initial.size > BigInt(maxBytes) || initial.size > BigInt(Number.MAX_SAFE_INTEGER))
		throw new Error("bounded file size invalid");
	const output = Buffer.alloc(Number(initial.size));
	let offset = 0;
	while (offset < output.length) {
		const count = readSync(descriptor, output, offset, output.length - offset, offset);
		if (count === 0) throw new Error("short file read");
		offset += count;
	}
	const after = identity(fstatSync(descriptor, { bigint: true }));
	if (!sameIdentity(initial, after)) throw new Error("file changed during read");
	return output;
}

function readRawPath(path: string, maxBytes: number): { identity: FileIdentity; bytes: Buffer } | undefined {
	let before: FileIdentity;
	try {
		before = identity(lstatSync(path, { bigint: true }));
	} catch (error) {
		if (isErrno(error, "ENOENT")) return undefined;
		throw error;
	}
	if ((before.mode & 0o170000n) !== 0o100000n) return undefined;
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, noFollowReadFlags());
		const opened = identity(fstatSync(descriptor, { bigint: true }));
		const bytes = readDescriptorBoundFileAllowEmpty(descriptor, maxBytes);
		const after = identity(lstatSync(path, { bigint: true }));
		if (!sameIdentity(before, opened) || !sameIdentity(opened, after)) throw new Error("file changed during read");
		return { identity: opened, bytes };
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function pinFile(path: string, expectedIdentity?: FileIdentity, expectedBytes?: Buffer): PinnedFile | undefined {
	let descriptor: number | undefined;
	try {
		const before = identity(lstatSync(path, { bigint: true }));
		if ((before.mode & 0o170000n) !== 0o100000n) return undefined;
		if (expectedIdentity && !sameIdentity(before, expectedIdentity)) return undefined;
		descriptor = openSync(path, noFollowReadFlags());
		const opened = identity(fstatSync(descriptor, { bigint: true }));
		const bytes = readDescriptorBoundFileAllowEmpty(descriptor, RECORD_MAX_BYTES);
		const after = identity(lstatSync(path, { bigint: true }));
		if (
			!sameIdentity(before, opened) ||
			!sameIdentity(opened, after) ||
			(expectedIdentity && !sameIdentity(opened, expectedIdentity)) ||
			(expectedBytes && !bytes.equals(expectedBytes))
		)
			return undefined;
		const pinned = { descriptor, identity: opened, bytes };
		descriptor = undefined;
		return pinned;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function unlinkPinnedFile(path: string, pinned: PinnedFile, expectedNlink: bigint): boolean {
	try {
		const currentPinned = identity(fstatSync(pinned.descriptor, { bigint: true }));
		if (currentPinned.nlink !== expectedNlink || !samePinnedFile(currentPinned, pinned.identity)) return false;
		const currentPath = readRawPath(path, RECORD_MAX_BYTES);
		if (!currentPath || !sameIdentity(currentPath.identity, currentPinned) || !currentPath.bytes.equals(pinned.bytes))
			return false;
		unlinkSync(path);
		return true;
	} catch {
		return false;
	}
}

function scratchObservationKey(context: RootContext): string {
	return `${context.controlBinding.dev}:${context.controlBinding.ino}:${context.baseName}`;
}

function scratchSignature(value: FileIdentity): string {
	return [
		value.dev,
		value.ino,
		value.mode,
		value.uid,
		value.gid,
		value.nlink,
		value.size,
		value.mtimeNs,
		value.ctimeNs,
	].join(":");
}

function recoverPrepareScratch(context: RootContext, runtime: RuntimeBinding): void {
	const key = scratchObservationKey(context);
	assertKnownControlNamespace(context);
	assertLegacyAbsent(context);
	let observed: FileIdentity;
	try {
		observed = identity(lstatSync(context.preparePath, { bigint: true }));
	} catch (error) {
		if (!isErrno(error, "ENOENT")) throw new CutoverFailure("invalid_control_artifact");
		scratchObservations.delete(key);
		return;
	}
	if (
		(observed.mode & 0o170000n) !== 0o100000n ||
		observed.uid !== context.controlIdentity.uid ||
		observed.gid !== context.controlIdentity.gid ||
		(observed.nlink !== 1n && observed.nlink !== 2n) ||
		observed.size > BigInt(RECORD_MAX_BYTES)
	)
		throw new CutoverFailure("invalid_control_artifact");
	if ((observed.mode & 0o7777n) !== 0o600n) {
		try {
			chmodSync(context.preparePath, 0o600);
			const repaired = identity(lstatSync(context.preparePath, { bigint: true }));
			if (!sameObject(observed, repaired)) throw new CutoverFailure("invalid_control_artifact");
			const descriptor = openSync(context.preparePath, noFollowReadFlags());
			try {
				const opened = identity(fstatSync(descriptor, { bigint: true }));
				if (!sameObject(repaired, opened)) throw new CutoverFailure("invalid_control_artifact");
				fchmodSync(descriptor, 0o600);
				fsyncSync(descriptor);
			} finally {
				closeSync(descriptor);
			}
			observed = identity(lstatSync(context.preparePath, { bigint: true }));
			if ((observed.mode & 0o7777n) !== 0o600n) throw new CutoverFailure("invalid_control_artifact");
		} catch (error) {
			if (error instanceof CutoverFailure) throw error;
			throw new CutoverFailure("invalid_control_artifact");
		}
	}
	try {
		if (readArtifact(context.preparePath, context)) {
			scratchObservations.delete(key);
			return;
		}
	} catch {
		// A private, unlinked, stable partial record is eligible for grace-based scratch recovery below.
	}
	if (observed.nlink !== 1n) throw new CutoverFailure("invalid_control_artifact");
	const now = runtime.monotonicTimeMs();
	if (!Number.isFinite(now) || now < 0) throw new CutoverFailure("orchestration_owner_unknown");
	const signature = scratchSignature(observed);
	const prior = scratchObservations.get(key);
	if (!prior || prior.signature !== signature || now < prior.firstSeenMs) {
		if (!prior && scratchObservations.size >= SCRATCH_OBSERVATION_MAX)
			throw new CutoverFailure("invalid_control_artifact");
		scratchObservations.set(key, { signature, firstSeenMs: now });
		throw new CutoverFailure("orchestration_in_progress");
	}
	if (now - prior.firstSeenMs < SCRATCH_GRACE_MS) throw new CutoverFailure("orchestration_in_progress");
	assertKnownControlNamespace(context);
	assertLegacyAbsent(context);
	const current = identity(lstatSync(context.preparePath, { bigint: true }));
	if (!sameIdentity(observed, current)) throw new CutoverFailure("orchestration_in_progress");
	const pinned = pinFile(context.preparePath, observed);
	if (!pinned) throw new CutoverFailure("orchestration_in_progress");
	try {
		runCleanupTestSynchronization(runtime, "scratch-recovery");
		if (!unlinkPinnedFile(context.preparePath, pinned, 1n)) throw new CutoverFailure("orchestration_in_progress");
		fsyncControl(context);
		scratchObservations.delete(key);
	} finally {
		closeSync(pinned.descriptor);
	}
}

function readArtifacts(context: RootContext): ArtifactState {
	assertKnownControlNamespace(context);
	const artifacts: ArtifactState = {
		generation: readArtifact(context.generationPath, context),
		prepare: readArtifact(context.preparePath, context),
		claim: readArtifact(context.claimPath, context),
	};
	for (const [name, snapshot] of Object.entries(artifacts)) {
		if (!snapshot || snapshot.identity.nlink === 1n) continue;
		const peers = Object.entries(artifacts).filter(
			([peerName, peer]) => peerName !== name && peer && sameObject(snapshot.identity, peer.identity),
		);
		if (
			snapshot.identity.nlink !== 2n ||
			peers.length !== 1 ||
			(name !== "prepare" && peers[0]?.[0] !== "prepare") ||
			(name === "prepare" && peers[0]?.[0] !== "generation" && peers[0]?.[0] !== "claim") ||
			!snapshot.bytes.equals(peers[0]?.[1]?.bytes ?? Buffer.alloc(0))
		)
			throw new CutoverFailure("invalid_control_artifact");
	}
	assertKnownControlNamespace(context);
	return artifacts;
}

function assertRecordMatchesContext(record: ControlRecord, context: RootContext, target: NormalizedTarget): void {
	if (
		record.canonicalAgentDirPath !== context.canonicalAgentDirPath ||
		record.incidentRecorderPath !== context.incidentRecorderPath ||
		record.incidentsPath !== context.incidentsPath ||
		!sameControlBinding(record.control, context.controlBinding)
	)
		throw new CutoverFailure("invalid_control_artifact");
	if (record.launcherConfigurationDigest !== target.launcherConfigurationDigest)
		throw new CutoverFailure("target_mismatch");
	if (
		record.kind === "incident_cas_v2_orchestration_claim" &&
		(record.owner.uid.toString() !== context.controlBinding.uid ||
			record.owner.gid.toString() !== context.controlBinding.gid)
	)
		throw new CutoverFailure("invalid_control_artifact");
}

function fsyncControl(context: RootContext): void {
	assertContextCurrent(context);
	fsyncSync(context.controlDescriptor);
	assertContextCurrent(context);
}

function writeAll(descriptor: number, bytes: Buffer, onPartialWrite: () => void): void {
	let offset = 0;
	const partialBoundary = Math.max(1, Math.floor(bytes.length / 2));
	let partialReported = false;
	while (offset < bytes.length) {
		const target = partialReported ? bytes.length : partialBoundary;
		const count = writeSync(descriptor, bytes, offset, target - offset, offset);
		if (count < 1) throw new Error("short control record write");
		offset += count;
		if (!partialReported && offset === partialBoundary && offset < bytes.length) {
			partialReported = true;
			onPartialWrite();
		}
	}
}

const scratchSteps = {
	claim: {
		opened: "claim_scratch_opened",
		chmodded: "claim_scratch_chmodded",
		partiallyWritten: "claim_scratch_partially_written",
		written: "claim_scratch_written",
	},
	draining: {
		opened: "draining_scratch_opened",
		chmodded: "draining_scratch_chmodded",
		partiallyWritten: "draining_scratch_partially_written",
		written: "draining_scratch_written",
	},
	v2: {
		opened: "v2_scratch_opened",
		chmodded: "v2_scratch_chmodded",
		partiallyWritten: "v2_scratch_partially_written",
		written: "v2_scratch_written",
	},
} as const satisfies Record<
	"claim" | "draining" | "v2",
	Record<"opened" | "chmodded" | "partiallyWritten" | "written", IncidentCasV2CutoverStep>
>;

function prepareRecord(
	context: RootContext,
	record: ControlRecord,
	runtime: RuntimeBinding,
	phase: keyof typeof scratchSteps,
): ArtifactSnapshot {
	assertContextCurrent(context);
	const bytes = serializeRecord(record);
	const steps = scratchSteps[phase];
	let descriptor: number | undefined;
	try {
		descriptor = openSync(
			context.preparePath,
			constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
			0o600,
		);
		runtime.onStep?.(steps.opened);
		fchmodSync(descriptor, 0o600);
		runtime.onStep?.(steps.chmodded);
		writeAll(descriptor, bytes, () => runtime.onStep?.(steps.partiallyWritten));
		runtime.onStep?.(steps.written);
		fsyncSync(descriptor);
		const preparedIdentity = identity(fstatSync(descriptor, { bigint: true }));
		if (
			(preparedIdentity.mode & 0o170000n) !== 0o100000n ||
			(preparedIdentity.mode & 0o7777n) !== 0o600n ||
			preparedIdentity.uid !== context.controlIdentity.uid ||
			preparedIdentity.gid !== context.controlIdentity.gid ||
			preparedIdentity.nlink !== 1n
		)
			throw new Error("prepared control record identity invalid");
		return { record, bytes, identity: preparedIdentity };
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function finishExclusiveLink(
	context: RootContext,
	destination: string,
	prepared: ArtifactSnapshot,
	steps: {
		prepared: IncidentCasV2CutoverStep;
		linked: IncidentCasV2CutoverStep;
		durable: IncidentCasV2CutoverStep;
		prepareUnlinked: IncidentCasV2CutoverStep;
	},
	runtime: RuntimeBinding,
): ArtifactSnapshot {
	runtime.onStep?.(steps.prepared);
	assertContextCurrent(context);
	linkSync(context.preparePath, destination);
	runtime.onStep?.(steps.linked);
	fsyncControl(context);
	runtime.onStep?.(steps.durable);
	unlinkSync(context.preparePath);
	fsyncControl(context);
	runtime.onStep?.(steps.prepareUnlinked);
	const result = readArtifact(destination, context);
	if (!result || result.identity.nlink !== 1n || !result.bytes.equals(prepared.bytes))
		throw new CutoverFailure("invalid_control_artifact");
	return result;
}

function createClaim(
	context: RootContext,
	target: NormalizedTarget,
	runtime: RuntimeBinding,
	cutoverId: string,
	owner: IncidentCasV2ProcessIdentity,
): ArtifactSnapshot {
	const record: ClaimRecord = {
		schemaVersion: SCHEMA_VERSION,
		kind: "incident_cas_v2_orchestration_claim",
		cutoverId,
		claimId: randomUUID(),
		canonicalAgentDirPath: context.canonicalAgentDirPath,
		incidentRecorderPath: context.incidentRecorderPath,
		incidentsPath: context.incidentsPath,
		historicalCopyBoundary: HISTORICAL_COPY_BOUNDARY,
		control: context.controlBinding,
		launcherConfigurationDigest: target.launcherConfigurationDigest,
		owner,
	};
	const prepared = prepareRecord(context, record, runtime, "claim");
	return finishExclusiveLink(
		context,
		context.claimPath,
		prepared,
		{
			prepared: "claim_prepared",
			linked: "claim_linked",
			durable: "claim_directory_fsynced",
			prepareUnlinked: "claim_prepare_unlinked",
		},
		runtime,
	);
}

function createDrainingGeneration(
	context: RootContext,
	target: NormalizedTarget,
	runtime: RuntimeBinding,
	cutoverId: string,
): ArtifactSnapshot {
	const record: GenerationRecord = {
		schemaVersion: SCHEMA_VERSION,
		kind: "incident_cas_v2_generation",
		state: "draining",
		cutoverId,
		canonicalAgentDirPath: context.canonicalAgentDirPath,
		incidentRecorderPath: context.incidentRecorderPath,
		incidentsPath: context.incidentsPath,
		historicalCopyBoundary: HISTORICAL_COPY_BOUNDARY,
		control: context.controlBinding,
		launcherConfigurationDigest: target.launcherConfigurationDigest,
	};
	const prepared = prepareRecord(context, record, runtime, "draining");
	return finishExclusiveLink(
		context,
		context.generationPath,
		prepared,
		{
			prepared: "draining_prepared",
			linked: "draining_linked",
			durable: "draining_directory_fsynced",
			prepareUnlinked: "draining_prepare_unlinked",
		},
		runtime,
	);
}

function cleanupRetirementPin(context: RootContext, pinned: PinnedFile): void {
	for (const path of [context.claimPath, context.preparePath]) {
		try {
			const current = identity(fstatSync(pinned.descriptor, { bigint: true }));
			if (
				current.nlink < 1n ||
				!samePinnedFile(current, pinned.identity) ||
				!unlinkPinnedFile(path, pinned, current.nlink)
			)
				continue;
			fsyncControl(context);
		} catch {
			// Preserve a successor when exact cleanup cannot be proved.
		}
	}
}

function retireClaimBound(context: RootContext, expected: ArtifactSnapshot, runtime: RuntimeBinding): void {
	if (expected.record.kind !== "incident_cas_v2_orchestration_claim" || expected.identity.nlink !== 1n)
		throw new CutoverFailure("invalid_control_artifact");
	assertContextCurrent(context);
	let descriptor: number | undefined;
	try {
		descriptor = openSync(context.claimPath, noFollowReadFlags());
		const initiallyPinned = identity(fstatSync(descriptor, { bigint: true }));
		const initialPath = readRawPath(context.claimPath, RECORD_MAX_BYTES);
		if (
			!sameIdentity(initiallyPinned, expected.identity) ||
			!initialPath ||
			!sameIdentity(initialPath.identity, initiallyPinned) ||
			!initialPath.bytes.equals(expected.bytes)
		)
			throw new CutoverFailure("claim_lost");
		linkSync(context.claimPath, context.preparePath);
		runtime.onStep?.("claim_retirement_linked");
		fsyncControl(context);
		const artifacts = readArtifacts(context);
		const pinned: PinnedFile = {
			descriptor,
			identity: initiallyPinned,
			bytes: expected.bytes,
		};
		const linkedPinned = identity(fstatSync(descriptor, { bigint: true }));
		if (
			!artifacts.claim ||
			!artifacts.prepare ||
			linkedPinned.nlink !== 2n ||
			!samePinnedFile(linkedPinned, initiallyPinned) ||
			!sameObject(artifacts.claim.identity, linkedPinned) ||
			!sameObject(artifacts.prepare.identity, linkedPinned) ||
			!artifacts.claim.bytes.equals(expected.bytes) ||
			!artifacts.prepare.bytes.equals(expected.bytes)
		) {
			cleanupRetirementPin(context, pinned);
			throw new CutoverFailure("claim_lost");
		}
		runCleanupTestSynchronization(runtime, "claim-retirement");
		const beforeClaim = readRawPath(context.claimPath, RECORD_MAX_BYTES);
		const beforePrepare = readRawPath(context.preparePath, RECORD_MAX_BYTES);
		const beforeUnlink = identity(fstatSync(descriptor, { bigint: true }));
		if (
			beforeUnlink.nlink !== 2n ||
			!samePinnedFile(beforeUnlink, initiallyPinned) ||
			!beforeClaim ||
			!beforePrepare ||
			!sameIdentity(beforeClaim.identity, beforeUnlink) ||
			!sameIdentity(beforePrepare.identity, beforeUnlink) ||
			!beforeClaim.bytes.equals(expected.bytes) ||
			!beforePrepare.bytes.equals(expected.bytes)
		) {
			cleanupRetirementPin(context, pinned);
			throw new CutoverFailure("claim_lost");
		}
		if (!unlinkPinnedFile(context.claimPath, pinned, 2n)) {
			cleanupRetirementPin(context, pinned);
			throw new CutoverFailure("claim_lost");
		}
		fsyncControl(context);
		runtime.onStep?.("claim_unlinked");
		const afterClaimUnlink = identity(fstatSync(descriptor, { bigint: true }));
		const remainingPrepare = readRawPath(context.preparePath, RECORD_MAX_BYTES);
		if (
			afterClaimUnlink.nlink !== 1n ||
			!remainingPrepare ||
			!sameIdentity(remainingPrepare.identity, afterClaimUnlink) ||
			!remainingPrepare.bytes.equals(expected.bytes)
		) {
			cleanupRetirementPin(context, pinned);
			throw new CutoverFailure("claim_lost");
		}
		if (!unlinkPinnedFile(context.preparePath, pinned, 1n)) {
			cleanupRetirementPin(context, pinned);
			throw new CutoverFailure("claim_lost");
		}
		fsyncControl(context);
		runtime.onStep?.("cleanup_directory_fsynced");
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

function validIdentityObservation(
	observation: IncidentCasV2ProcessIdentityObservation,
): observation is { state: "present"; identity: IncidentCasV2ProcessIdentity } {
	return observation.state === "present" && validOwner(observation.identity);
}

function readCurrentOwner(runtime: RuntimeBinding): IncidentCasV2ProcessIdentity {
	const observation = runtime.readCurrentProcessIdentity();
	if (!validIdentityObservation(observation)) throw new CutoverFailure("orchestration_owner_unknown");
	return observation.identity;
}

function sameOwner(left: IncidentCasV2ProcessIdentity, right: IncidentCasV2ProcessIdentity): boolean {
	return (
		left.machineId === right.machineId &&
		left.bootId === right.bootId &&
		left.pid === right.pid &&
		left.startId === right.startId &&
		left.uid === right.uid &&
		left.gid === right.gid
	);
}

function claimDisposition(
	claim: ClaimRecord,
	current: IncidentCasV2ProcessIdentity,
	runtime: RuntimeBinding,
): "current" | "live" | "stale" | "unknown" {
	if (claim.owner.machineId !== current.machineId) return "unknown";
	if (claim.owner.bootId !== current.bootId) return "stale";
	if (sameOwner(claim.owner, current)) return "current";
	const observed = runtime.readProcessIdentity(claim.owner.pid);
	if (observed.state === "absent") return "stale";
	if (!validIdentityObservation(observed)) return "unknown";
	return sameOwner(observed.identity, claim.owner) ? "live" : "stale";
}

function discardPrepare(context: RootContext, expected: ArtifactSnapshot, runtime: RuntimeBinding): void {
	if (!pathExistsNoFollow(context.preparePath)) return;
	const pinned = pinFile(context.preparePath, expected.identity, expected.bytes);
	if (!pinned) throw new CutoverFailure("invalid_control_artifact");
	try {
		runCleanupTestSynchronization(runtime, "prepare-discard");
		if (!unlinkPinnedFile(context.preparePath, pinned, expected.identity.nlink))
			throw new CutoverFailure("invalid_control_artifact");
		fsyncControl(context);
	} finally {
		closeSync(pinned.descriptor);
	}
}

function recoverKnownLinkedPrepare(
	context: RootContext,
	artifacts: ArtifactState,
	runtime: RuntimeBinding,
): ArtifactState {
	const prepare = artifacts.prepare;
	if (!prepare || prepare.identity.nlink !== 2n) return artifacts;
	const peer =
		artifacts.generation && sameObject(prepare.identity, artifacts.generation.identity)
			? artifacts.generation
			: artifacts.claim && sameObject(prepare.identity, artifacts.claim.identity)
				? artifacts.claim
				: undefined;
	if (!peer || !prepare.bytes.equals(peer.bytes)) throw new CutoverFailure("invalid_control_artifact");
	discardPrepare(context, prepare, runtime);
	return readArtifacts(context);
}

function validateClaimGenerationPair(claim: ArtifactSnapshot, generation: ArtifactSnapshot): void {
	if (claim.record.kind !== "incident_cas_v2_orchestration_claim")
		throw new CutoverFailure("invalid_control_artifact");
	if (generation.record.kind !== "incident_cas_v2_generation") throw new CutoverFailure("invalid_control_artifact");
	if (claim.record.cutoverId !== generation.record.cutoverId) throw new CutoverFailure("invalid_control_artifact");
}

function recoverStandalonePrepare(
	context: RootContext,
	target: NormalizedTarget,
	runtime: RuntimeBinding,
	artifacts: ArtifactState,
	current: IncidentCasV2ProcessIdentity,
): ArtifactState {
	const prepare = artifacts.prepare;
	if (!prepare) return artifacts;
	if (prepare.identity.nlink !== 1n) throw new CutoverFailure("invalid_control_artifact");
	assertRecordMatchesContext(prepare.record, context, target);
	if (prepare.record.kind === "incident_cas_v2_orchestration_claim") {
		if (artifacts.claim) throw new CutoverFailure("invalid_control_artifact");
		if (
			artifacts.generation &&
			(artifacts.generation.record.kind !== "incident_cas_v2_generation" ||
				artifacts.generation.record.cutoverId !== prepare.record.cutoverId)
		)
			throw new CutoverFailure("invalid_control_artifact");
		if (
			artifacts.generation?.record.kind === "incident_cas_v2_generation" &&
			artifacts.generation.record.state === "v2"
		) {
			// Publication is authoritative; this is a bounded claim-retirement seam.
			discardPrepare(context, prepare, runtime);
			return readArtifacts(context);
		}
		const disposition = claimDisposition(prepare.record, current, runtime);
		if (disposition === "live") throw new CutoverFailure("orchestration_in_progress");
		if (disposition === "unknown") throw new CutoverFailure("orchestration_owner_unknown");
		if (disposition === "stale") {
			discardPrepare(context, prepare, runtime);
			return readArtifacts(context);
		}
		linkSync(context.preparePath, context.claimPath);
		fsyncControl(context);
		const linkedPrepare = readArtifact(context.preparePath, context);
		if (!linkedPrepare) throw new CutoverFailure("invalid_control_artifact");
		discardPrepare(context, linkedPrepare, runtime);
		return readArtifacts(context);
	}
	if (prepare.record.state === "v2") {
		if (
			!artifacts.generation ||
			artifacts.generation.record.kind !== "incident_cas_v2_generation" ||
			artifacts.generation.record.state !== "draining" ||
			artifacts.generation.record.cutoverId !== prepare.record.cutoverId ||
			!artifacts.claim
		)
			throw new CutoverFailure("invalid_control_artifact");
		validateClaimGenerationPair(artifacts.claim, artifacts.generation);
		if (artifacts.claim.record.kind !== "incident_cas_v2_orchestration_claim")
			throw new CutoverFailure("invalid_control_artifact");
		const disposition = claimDisposition(artifacts.claim.record, current, runtime);
		if (disposition === "live") throw new CutoverFailure("orchestration_in_progress");
		if (disposition === "unknown") throw new CutoverFailure("orchestration_owner_unknown");
		// A v2 prepare was never published. A fresh proof is required.
		discardPrepare(context, prepare, runtime);
		return readArtifacts(context);
	}
	if (artifacts.generation || !artifacts.claim) throw new CutoverFailure("invalid_control_artifact");
	if (
		artifacts.claim.record.kind !== "incident_cas_v2_orchestration_claim" ||
		artifacts.claim.record.cutoverId !== prepare.record.cutoverId
	)
		throw new CutoverFailure("invalid_control_artifact");
	const disposition = claimDisposition(artifacts.claim.record, current, runtime);
	if (disposition === "live") throw new CutoverFailure("orchestration_in_progress");
	if (disposition === "unknown") throw new CutoverFailure("orchestration_owner_unknown");
	linkSync(context.preparePath, context.generationPath);
	fsyncControl(context);
	const linkedPrepare = readArtifact(context.preparePath, context);
	if (!linkedPrepare) throw new CutoverFailure("invalid_control_artifact");
	discardPrepare(context, linkedPrepare, runtime);
	return readArtifacts(context);
}

function cleanupPublishedResidue(
	context: RootContext,
	target: NormalizedTarget,
	artifacts: ArtifactState,
	runtime: RuntimeBinding,
): ArtifactState {
	const generation = artifacts.generation;
	if (!generation || generation.record.kind !== "incident_cas_v2_generation" || generation.record.state !== "v2")
		return artifacts;
	assertRecordMatchesContext(generation.record, context, target);
	if (artifacts.prepare) throw new CutoverFailure("invalid_control_artifact");
	if (artifacts.claim) {
		if (
			artifacts.claim.record.kind !== "incident_cas_v2_orchestration_claim" ||
			artifacts.claim.record.cutoverId !== generation.record.cutoverId
		)
			throw new CutoverFailure("invalid_control_artifact");
		assertRecordMatchesContext(artifacts.claim.record, context, target);
		retireClaimBound(context, artifacts.claim, runtime);
	}
	return readArtifacts(context);
}

function systemdUnescape(value: string): string | undefined {
	let result = "";
	for (let index = 0; index < value.length; index += 1) {
		const character = value[index];
		if (character !== "\\") {
			result += character;
			continue;
		}
		const next = value[index + 1];
		if (next === undefined) return undefined;
		if (next === "x") {
			const hex = value.slice(index + 2, index + 4);
			if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return undefined;
			result += String.fromCodePoint(Number.parseInt(hex, 16));
			index += 3;
			continue;
		}
		if (next === "u" || next === "U") {
			const length = next === "u" ? 4 : 8;
			const hex = value.slice(index + 2, index + 2 + length);
			if (hex.length !== length || !/^[0-9A-Fa-f]+$/.test(hex)) return undefined;
			const point = Number.parseInt(hex, 16);
			if (point > 0x10ffff) return undefined;
			result += String.fromCodePoint(point);
			index += length + 1;
			continue;
		}
		const escapes: Record<string, string> = {
			a: "\u0007",
			b: "\b",
			f: "\f",
			n: "\n",
			r: "\r",
			s: " ",
			t: "\t",
			v: "\v",
			"\\": "\\",
			'"': '"',
			"'": "'",
		};
		result += escapes[next] ?? next;
		index += 1;
	}
	return result;
}

function parseSystemdWords(value: string): string[] | undefined {
	const words: string[] = [];
	let word = "";
	let quote: '"' | "'" | undefined;
	let escaped = false;
	let present = false;
	for (let index = 0; index < value.length; index += 1) {
		const character = value[index];
		if (escaped) {
			word += `\\${character}`;
			escaped = false;
			present = true;
			continue;
		}
		if (character === "\\") {
			escaped = true;
			continue;
		}
		if (quote) {
			if (character === quote) quote = undefined;
			else word += character;
			present = true;
			continue;
		}
		if (character === '"' || character === "'") {
			quote = character;
			present = true;
			continue;
		}
		if (/\s/.test(character)) {
			if (present) {
				const decoded = systemdUnescape(word);
				if (decoded === undefined) return undefined;
				words.push(decoded);
				word = "";
				present = false;
			}
			continue;
		}
		word += character;
		present = true;
	}
	if (escaped || quote) return undefined;
	if (present) {
		const decoded = systemdUnescape(word);
		if (decoded === undefined) return undefined;
		words.push(decoded);
	}
	return words;
}

function unitExecStart(contents: string): string[] | undefined {
	let section = "";
	let found: string[] | undefined;
	for (const rawLine of contents.split("\n")) {
		const line = rawLine.trim();
		if (!line || line.startsWith("#") || line.startsWith(";")) continue;
		const sectionMatch = /^\[([^\]]+)\]$/.exec(line);
		if (sectionMatch) {
			section = sectionMatch[1] ?? "";
			continue;
		}
		if (section !== "Service" || !line.startsWith("ExecStart=")) continue;
		if (found) return undefined;
		const parsed = parseSystemdWords(line.slice("ExecStart=".length));
		if (!parsed || parsed.length < 2) return undefined;
		found = parsed;
	}
	return found;
}

function canonicalExistingPath(path: string, kind: "directory" | "file"): string {
	if (!isAbsolute(path) || resolve(path) !== path) throw new CutoverFailure("invalid_target");
	const canonical = realpathSync.native(path);
	if (canonical !== path) throw new CutoverFailure("invalid_target");
	const stats = lstatSync(path, { bigint: true });
	if (kind === "directory" ? !stats.isDirectory() : !stats.isFile()) throw new CutoverFailure("invalid_target");
	return canonical;
}

function exactArray(left: readonly string[], right: readonly string[]): boolean {
	return left.length === right.length && left.every((value, index) => value === right[index]);
}

function deriveProcessScope(packageRoot: string): string {
	const normalized = packageRoot.split(sep).join("/");
	const suffix = "/BACKEND/packages/coding-agent";
	if (normalized.endsWith(suffix)) return packageRoot.slice(0, packageRoot.length - suffix.length);
	return packageRoot;
}

function normalizeTarget(target: IncidentCasV2CutoverTarget): NormalizedTarget {
	try {
		if (!isPlainObject(target) || !isPlainObject(target.launcher)) throw new CutoverFailure("invalid_target");
		const agentDir = canonicalExistingPath(target.agentDir, "directory");
		const incidentRecorderPath = canonicalExistingPath(join(agentDir, "incident-recorder"), "directory");
		const incidentsPath = canonicalExistingPath(join(agentDir, "incidents"), "directory");
		const packageRoot = canonicalExistingPath(target.packageRoot, "directory");
		const entrypointPath = join(packageRoot, INCIDENT_CAS_V2_SERVICE_ENTRYPOINT);
		canonicalExistingPath(entrypointPath, "file");
		const cliEntrypointPath = join(packageRoot, INCIDENT_CAS_V2_CLI_ENTRYPOINT);
		canonicalExistingPath(cliEntrypointPath, "file");
		if (
			!isAbsolute(target.launcher.unitPath) ||
			resolve(target.launcher.unitPath) !== target.launcher.unitPath ||
			basename(target.launcher.unitPath) !== INCIDENT_CAS_V2_SYSTEMD_UNIT ||
			typeof target.launcher.unitContents !== "string" ||
			Buffer.byteLength(target.launcher.unitContents) < 1 ||
			Buffer.byteLength(target.launcher.unitContents) > 64 * 1024 ||
			target.launcher.unitContents.includes("\u0000") ||
			target.launcher.unitContents.includes("--incident-recorder-service") ||
			!Array.isArray(target.launcher.argv)
		)
			throw new CutoverFailure("invalid_target");
		const argv = [...target.launcher.argv];
		if (
			argv.length !== 4 ||
			argv.some((argument) => typeof argument !== "string" || argument.length < 1 || argument.includes("\u0000"))
		)
			throw new CutoverFailure("invalid_target");
		const nodePath = canonicalExistingPath(argv[0] ?? "", "file");
		if ((statSync(nodePath).mode & 0o111) === 0) throw new CutoverFailure("invalid_target");
		const nodeFingerprint = observeRegularFile(nodePath, 256 * 1024 * 1024);
		const entrypointFingerprint = observeRegularFile(entrypointPath, 64 * 1024 * 1024);
		const cliEntrypointFingerprint = observeRegularFile(
			cliEntrypointPath,
			64 * 1024 * 1024,
			INCIDENT_CAS_V2_LEGACY_SELECTOR_REJECTION_MARKER,
		);
		if (
			(nodeFingerprint.mode & 0o170000) !== 0o100000 ||
			(nodeFingerprint.mode & 0o022) !== 0 ||
			(nodeFingerprint.mode & 0o111) === 0 ||
			nodeFingerprint.nlink !== 1 ||
			(entrypointFingerprint.mode & 0o170000) !== 0o100000 ||
			(entrypointFingerprint.mode & 0o022) !== 0 ||
			entrypointFingerprint.nlink !== 1 ||
			(cliEntrypointFingerprint.mode & 0o170000) !== 0o100000 ||
			(cliEntrypointFingerprint.mode & 0o022) !== 0 ||
			cliEntrypointFingerprint.nlink !== 1 ||
			cliEntrypointFingerprint.uid !== entrypointFingerprint.uid ||
			cliEntrypointFingerprint.gid !== entrypointFingerprint.gid
		)
			throw new CutoverFailure("invalid_target");
		if (
			argv[1] !== entrypointPath ||
			argv[2] !== "--agent-dir" ||
			argv[3] !== agentDir ||
			argv.includes("--incident-recorder-service")
		)
			throw new CutoverFailure("invalid_target");
		const parsedExecStart = unitExecStart(target.launcher.unitContents);
		if (!parsedExecStart || !exactArray(parsedExecStart, argv)) throw new CutoverFailure("invalid_target");
		const unitSha256 = sha256(target.launcher.unitContents);
		const unitPath = target.launcher.unitPath;
		const processScopeRoot = deriveProcessScope(packageRoot);
		const launcherConfigurationDigest = sha256(
			JSON.stringify({
				schemaVersion: SCHEMA_VERSION,
				unitName: INCIDENT_CAS_V2_SYSTEMD_UNIT,
				unitPath,
				unitSha256,
				packageRoot,
				processScopeRoot,
				agentDir,
				incidentRecorderPath,
				incidentsPath,
				argv,
				node: {
					...observedIdentityDigest(nodeFingerprint),
					size: nodeFingerprint.size,
					sha256: nodeFingerprint.sha256,
				},
				entrypoint: {
					...observedIdentityDigest(entrypointFingerprint),
					size: entrypointFingerprint.size,
					sha256: entrypointFingerprint.sha256,
				},
				cliEntrypoint: {
					...observedIdentityDigest(cliEntrypointFingerprint),
					size: cliEntrypointFingerprint.size,
					sha256: cliEntrypointFingerprint.sha256,
				},
			}),
		);
		return {
			agentDir,
			incidentRecorderPath,
			incidentsPath,
			packageRoot,
			processScopeRoot,
			unitPath,
			unitContents: target.launcher.unitContents,
			unitSha256,
			expectedArgv: Object.freeze(argv),
			nodePath,
			entrypointPath,
			launcherConfigurationDigest,
		};
	} catch (error) {
		if (error instanceof CutoverFailure) throw error;
		throw new CutoverFailure("invalid_target");
	}
}

function assertTargetConfigurationCurrent(target: NormalizedTarget): void {
	try {
		const current = normalizeTarget({
			agentDir: target.agentDir,
			packageRoot: target.packageRoot,
			launcher: {
				unitPath: target.unitPath,
				unitContents: target.unitContents,
				argv: target.expectedArgv,
			},
		});
		if (current.launcherConfigurationDigest !== target.launcherConfigurationDigest)
			throw new CutoverFailure("target_mismatch");
	} catch (error) {
		if (error instanceof CutoverFailure && error.reason === "target_mismatch") throw error;
		throw new CutoverFailure("target_mismatch");
	}
}

function validObservedIdentity(value: IncidentCasV2ObservedIdentity): boolean {
	return (
		isPlainObject(value) &&
		typeof value.path === "string" &&
		isAbsolute(value.path) &&
		resolve(value.path) === value.path &&
		isDecimal(value.dev) &&
		isDecimal(value.ino) &&
		isSafeInteger(value.uid) &&
		isSafeInteger(value.gid) &&
		isSafeInteger(value.mode) &&
		isSafeInteger(value.nlink, 1)
	);
}

function validObservedFile(value: IncidentCasV2ObservedFile): boolean {
	return validObservedIdentity(value) && isSafeInteger(value.size) && isDigest(value.sha256);
}

function observedIdentityDigest(value: IncidentCasV2ObservedIdentity): object {
	return {
		path: value.path,
		dev: value.dev,
		ino: value.ino,
		uid: value.uid,
		gid: value.gid,
		mode: value.mode,
		nlink: value.nlink,
	};
}

function launcherEvidence(
	target: NormalizedTarget,
	observation: IncidentCasV2LauncherObservation,
	requireStopped: boolean,
	expectedUid: bigint,
	expectedGid: bigint,
): LauncherEvidence {
	if (observation.state !== "observed") throw new CutoverFailure("launcher_unavailable");
	if (
		observation.unitName !== INCIDENT_CAS_V2_SYSTEMD_UNIT ||
		observation.loadState !== "loaded" ||
		observation.needDaemonReload !== "no" ||
		!isSafeInteger(observation.mainPid) ||
		!isSafeInteger(observation.execMainPid) ||
		!isSafeInteger(observation.controlPid) ||
		!SYSTEMD_MONOTONIC.test(observation.observationGeneration) ||
		!validObservedFile(observation.fragment) ||
		!validObservedIdentity(observation.node) ||
		!validObservedFile(observation.entrypoint) ||
		!Array.isArray(observation.managerExecStartArgv) ||
		!observation.managerExecStartArgv.every((argument) => typeof argument === "string")
	)
		throw new CutoverFailure("launcher_mismatch");
	if (
		observation.fragment.path !== target.unitPath ||
		observation.fragment.sha256 !== target.unitSha256 ||
		(observation.fragment.mode & 0o170000) !== 0o100000 ||
		(observation.fragment.mode & 0o7777) !== 0o600 ||
		observation.fragment.nlink !== 1 ||
		observation.entrypoint.path !== target.entrypointPath ||
		(observation.entrypoint.mode & 0o170000) !== 0o100000 ||
		(observation.entrypoint.mode & 0o022) !== 0 ||
		observation.entrypoint.nlink !== 1 ||
		observation.node.path !== target.nodePath ||
		(observation.node.mode & 0o170000) !== 0o100000 ||
		(observation.node.mode & 0o022) !== 0 ||
		(observation.node.mode & 0o111) === 0 ||
		!exactArray(observation.managerExecStartArgv, target.expectedArgv)
	)
		throw new CutoverFailure("launcher_mismatch");
	if (
		observation.fragment.uid !== Number(expectedUid) ||
		observation.fragment.gid !== Number(expectedGid) ||
		(observation.entrypoint.uid !== Number(expectedUid) && observation.entrypoint.uid !== 0)
	)
		throw new CutoverFailure("launcher_mismatch");
	if (
		requireStopped &&
		(observation.activeState !== "inactive" ||
			observation.subState !== "dead" ||
			observation.mainPid !== 0 ||
			observation.execMainPid !== 0 ||
			observation.controlPid !== 0)
	)
		throw new CutoverFailure("launcher_not_stopped");
	return {
		observationGeneration: observation.observationGeneration,
		digest: sha256(
			JSON.stringify({
				unitName: observation.unitName,
				fragment: { ...observedIdentityDigest(observation.fragment), sha256: observation.fragment.sha256 },
				node: observedIdentityDigest(observation.node),
				entrypoint: { ...observedIdentityDigest(observation.entrypoint), sha256: observation.entrypoint.sha256 },
				argv: observation.managerExecStartArgv,
			}),
		),
	};
}

function pathWithin(path: string, root: string): boolean {
	const child = relative(root, path);
	return child === "" || (!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child));
}

function candidateReferencesScope(candidate: string, scope: string): boolean {
	if (!isAbsolute(candidate)) return false;
	const lexical = candidate.endsWith(" (deleted)") ? candidate.slice(0, -" (deleted)".length) : candidate;
	if (pathWithin(resolve(lexical), scope)) return true;
	try {
		return pathWithin(realpathSync.native(lexical), scope);
	} catch {
		return false;
	}
}

function processReferencesScope(process: IncidentCasV2ObservedProcess, scope: string): boolean {
	if (process.cwd && candidateReferencesScope(process.cwd, scope)) return true;
	if (process.executable && candidateReferencesScope(process.executable, scope)) return true;
	for (const argument of process.argv) {
		if (candidateReferencesScope(argument, scope)) return true;
		if (process.cwd && argument.includes(sep) && candidateReferencesScope(resolve(process.cwd, argument), scope))
			return true;
	}
	return false;
}

function validObservedProcess(process: IncidentCasV2ObservedProcess): boolean {
	return (
		isPlainObject(process) &&
		isSafeInteger(process.pid, 1) &&
		isSafeInteger(process.parentPid) &&
		isSafeInteger(process.uid) &&
		typeof process.startId === "string" &&
		PROCESS_START_ID.test(process.startId) &&
		typeof process.processState === "string" &&
		process.processState.length === 1 &&
		(process.inspection === "complete" || process.inspection === "ambiguous") &&
		Array.isArray(process.argv) &&
		process.argv.every((argument) => typeof argument === "string" && !argument.includes("\u0000")) &&
		(process.cwd === null || (typeof process.cwd === "string" && isAbsolute(process.cwd))) &&
		(process.executable === null || (typeof process.executable === "string" && isAbsolute(process.executable)))
	);
}

function evaluatePopulation(
	observation: IncidentCasV2ProcessPopulationObservation,
	claim: ClaimRecord,
	target: NormalizedTarget,
): { state: "clear" } | { state: "ambiguous" } | { state: "blocked"; pids: readonly number[] } {
	if (
		observation.state !== "observed" ||
		!Array.isArray(observation.processes) ||
		!Array.isArray(observation.finalSameUidProcesses)
	)
		return { state: "ambiguous" };
	const seen = new Set<number>();
	let claimantSeen = false;
	let claimantFinallySeen = false;
	const owned = new Map<number, IncidentCasV2ObservedProcess>();
	const initialSameUid = new Map<number, IncidentCasV2ObservedProcess>();
	const controlled = new Set<number>();
	for (const process of observation.processes) {
		if (!validObservedProcess(process) || seen.has(process.pid)) return { state: "ambiguous" };
		seen.add(process.pid);
		if (process.uid !== claim.owner.uid) continue;
		initialSameUid.set(process.pid, process);
		if (process.processState === "Z") continue;
		if (process.inspection !== "complete") return { state: "ambiguous" };
		if (process.pid === claim.owner.pid && process.startId === claim.owner.startId) {
			claimantSeen = true;
			continue;
		}
		owned.set(process.pid, process);
		if (processReferencesScope(process, target.processScopeRoot)) controlled.add(process.pid);
	}
	const finalSeen = new Set<number>();
	for (const process of observation.finalSameUidProcesses) {
		if (!validObservedProcess(process) || process.uid !== claim.owner.uid || finalSeen.has(process.pid))
			return { state: "ambiguous" };
		finalSeen.add(process.pid);
		const initial = initialSameUid.get(process.pid);
		if (
			!initial ||
			initial.parentPid !== process.parentPid ||
			initial.uid !== process.uid ||
			initial.startId !== process.startId ||
			(initial.processState === "Z" && process.processState !== "Z")
		)
			return { state: "ambiguous" };
		if (process.processState === "Z") continue;
		if (process.inspection !== "complete") return { state: "ambiguous" };
		if (process.pid === claim.owner.pid && process.startId === claim.owner.startId) claimantFinallySeen = true;
		else {
			owned.set(process.pid, process);
			if (processReferencesScope(process, target.processScopeRoot)) controlled.add(process.pid);
		}
	}
	if (!claimantSeen || !claimantFinallySeen) return { state: "ambiguous" };
	let changed = true;
	while (changed) {
		changed = false;
		for (const process of owned.values()) {
			if (!controlled.has(process.pid) && controlled.has(process.parentPid)) {
				controlled.add(process.pid);
				changed = true;
			}
		}
	}
	const blocked = [...controlled];
	return blocked.length === 0
		? { state: "clear" }
		: { state: "blocked", pids: Object.freeze(blocked.sort((a, b) => a - b)) };
}

function observeQuiescence(state: CutoverState): QuiescenceEvidence {
	try {
		const before = launcherEvidence(
			state.target,
			state.runtime.readLauncher(INCIDENT_CAS_V2_SYSTEMD_UNIT),
			true,
			state.context.controlIdentity.uid,
			state.context.controlIdentity.gid,
		);
		const population = state.runtime.readProcessPopulation();
		const after = launcherEvidence(
			state.target,
			state.runtime.readLauncher(INCIDENT_CAS_V2_SYSTEMD_UNIT),
			true,
			state.context.controlIdentity.uid,
			state.context.controlIdentity.gid,
		);
		if (before.digest !== after.digest || before.observationGeneration !== after.observationGeneration)
			return { state: "unavailable", reason: "launcher_mismatch" };
		if (state.claim.record.kind !== "incident_cas_v2_orchestration_claim")
			return { state: "unavailable", reason: "claim_lost" };
		const evaluated = evaluatePopulation(population, state.claim.record, state.target);
		if (evaluated.state === "ambiguous") return { state: "unavailable", reason: "process_population_ambiguous" };
		if (evaluated.state === "blocked")
			return { state: "unavailable", reason: "controlled_processes_present", blockingPids: evaluated.pids };
		return { state: "proved", launcher: after };
	} catch (error) {
		if (error instanceof CutoverFailure) return { state: "unavailable", reason: error.reason };
		return { state: "unavailable", reason: "io_error" };
	}
}

function sameSnapshot(path: string, expected: ArtifactSnapshot, context: RootContext): boolean {
	try {
		const current = readArtifact(path, context);
		return Boolean(
			current &&
				current.identity.nlink === 1n &&
				sameIdentity(current.identity, expected.identity) &&
				current.bytes.equals(expected.bytes),
		);
	} catch {
		return false;
	}
}

function assertCutoverCurrent(state: CutoverState, allowPrepare = false): void {
	if (state.closed) throw new CutoverFailure("claim_lost");
	assertContextCurrent(state.context);
	assertTargetConfigurationCurrent(state.target);
	assertKnownControlNamespace(state.context);
	assertLegacyAbsent(state.context);
	if (!sameSnapshot(state.context.claimPath, state.claim, state.context)) throw new CutoverFailure("claim_lost");
	if (!sameSnapshot(state.context.generationPath, state.generation, state.context))
		throw new CutoverFailure("generation_changed");
	if (!allowPrepare && pathExistsNoFollow(state.context.preparePath))
		throw new CutoverFailure("invalid_control_artifact");
}

function makeCutover(state: CutoverState): IncidentCasV2Cutover {
	const cutover = Object.freeze({
		close(): void {
			const current = cutovers.get(cutover);
			if (!current || current.closed) return;
			current.closed = true;
			closeContext(current.context);
		},
	}) as IncidentCasV2Cutover;
	cutovers.set(cutover, state);
	return cutover;
}

function makeWitness(state: WitnessState): IncidentCasV1QuiescenceWitness {
	const witness = Object.freeze({}) as IncidentCasV1QuiescenceWitness;
	witnesses.set(witness, state);
	return witness;
}

function closeCutoverState(state: CutoverState): void {
	if (state.closed) return;
	state.closed = true;
	closeContext(state.context);
}

function defaultMonotonicTimeMs(): number {
	return Number(process.hrtime.bigint() / 1_000_000n);
}

function boundedRead(path: string, maxBytes: number): Buffer {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, noFollowReadFlags());
		const chunks: Buffer[] = [];
		let total = 0;
		while (true) {
			const chunk = Buffer.alloc(Math.min(64 * 1024, maxBytes + 1 - total));
			const count = readSync(descriptor, chunk, 0, chunk.length, null);
			if (count === 0) break;
			total += count;
			if (total > maxBytes) throw new Error("bounded read limit exceeded");
			chunks.push(chunk.subarray(0, count));
		}
		return Buffer.concat(chunks, total);
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

const observedFileFingerprints = new Map<string, { identity: FileIdentity; observed: IncidentCasV2ObservedFile }>();
const OBSERVED_FILE_FINGERPRINT_MAX_ENTRIES = 16;

function observeRegularFile(path: string, maxBytes: number, requiredMarker?: string): IncidentCasV2ObservedFile {
	const canonical = realpathSync.native(path);
	if (canonical !== path) throw new Error("observed file path is not canonical");
	const before = identity(lstatSync(path, { bigint: true }));
	if ((before.mode & 0o170000n) !== 0o100000n) throw new Error("observed path is not regular");
	const descriptor = openSync(path, noFollowReadFlags());
	try {
		const opened = identity(fstatSync(descriptor, { bigint: true }));
		if (!sameIdentity(before, opened)) throw new Error("observed file changed before open");
		const cacheKey = JSON.stringify([path, maxBytes, requiredMarker ?? null]);
		const cached = observedFileFingerprints.get(cacheKey);
		// Reuse content only while the descriptor and pathname retain the full
		// nanosecond identity, including ctime. No file bytes or descriptors are cached.
		if (cached && sameIdentity(cached.identity, opened)) {
			const after = identity(lstatSync(path, { bigint: true }));
			if (!sameIdentity(opened, after)) throw new Error("observed file changed");
			return { ...cached.observed };
		}
		observedFileFingerprints.delete(cacheKey);
		const bytes = readDescriptorBoundFile(descriptor, maxBytes);
		if (requiredMarker && !bytes.includes(Buffer.from(requiredMarker, "utf8")))
			throw new Error("required file marker is absent");
		const after = identity(lstatSync(path, { bigint: true }));
		if (!sameIdentity(before, opened) || !sameIdentity(opened, after) || after.size !== BigInt(bytes.length))
			throw new Error("observed file changed");
		const observed: IncidentCasV2ObservedFile = {
			path,
			dev: after.dev.toString(),
			ino: after.ino.toString(),
			uid: Number(after.uid),
			gid: Number(after.gid),
			mode: Number(after.mode),
			nlink: Number(after.nlink),
			size: bytes.length,
			sha256: sha256(bytes),
		};
		if (observedFileFingerprints.size >= OBSERVED_FILE_FINGERPRINT_MAX_ENTRIES) {
			const oldest = observedFileFingerprints.keys().next().value;
			if (oldest !== undefined) observedFileFingerprints.delete(oldest);
		}
		observedFileFingerprints.set(cacheKey, { identity: after, observed });
		return { ...observed };
	} finally {
		closeSync(descriptor);
	}
}

function observeFileIdentity(path: string): IncidentCasV2ObservedIdentity {
	const canonical = realpathSync.native(path);
	if (canonical !== path) throw new Error("observed identity path is not canonical");
	const before = identity(lstatSync(path, { bigint: true }));
	const descriptor = openSync(path, noFollowReadFlags());
	try {
		const opened = identity(fstatSync(descriptor, { bigint: true }));
		const after = identity(lstatSync(path, { bigint: true }));
		if (!sameIdentity(before, opened) || !sameIdentity(opened, after)) throw new Error("identity changed");
		return {
			path,
			dev: after.dev.toString(),
			ino: after.ino.toString(),
			uid: Number(after.uid),
			gid: Number(after.gid),
			mode: Number(after.mode),
			nlink: Number(after.nlink),
		};
	} finally {
		closeSync(descriptor);
	}
}

function parseSystemdShowExecStart(value: string): string[] | undefined {
	const marker = "argv[]=";
	const start = value.indexOf(marker);
	if (start < 0) return undefined;
	const rest = value.slice(start + marker.length);
	const end = rest.indexOf(" ; ignore_errors=");
	if (end < 0) return undefined;
	return parseSystemdWords(rest.slice(0, end));
}

function parseSystemdProperties(stdout: string, names: readonly string[]): Map<string, string> | undefined {
	const values = new Map<string, string>();
	for (const line of stdout.split("\n")) {
		if (!line) continue;
		const separator = line.indexOf("=");
		if (separator < 1) return undefined;
		const key = line.slice(0, separator);
		if (!names.includes(key) || values.has(key)) return undefined;
		values.set(key, line.slice(separator + 1));
	}
	return values.size === names.length ? values : undefined;
}

function numericSystemdProperty(value: string | undefined): number | undefined {
	if (!value || !/^(0|[1-9][0-9]*)$/.test(value)) return undefined;
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function defaultReadLauncher(unitName: string): IncidentCasV2LauncherObservation {
	const properties = [
		"LoadState",
		"ActiveState",
		"SubState",
		"NeedDaemonReload",
		"MainPID",
		"ExecMainPID",
		"ControlPID",
		"StateChangeTimestampMonotonic",
		"FragmentPath",
		"ExecStart",
	] as const;
	const result = spawnSync(
		"/usr/bin/systemctl",
		["--user", "show", unitName, "--no-pager", ...properties.map((property) => `--property=${property}`)],
		{
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
			maxBuffer: SYSTEMD_OUTPUT_MAX_BYTES,
			timeout: 1_000,
			killSignal: "SIGKILL",
		},
	);
	if (result.error || result.status !== 0) return { state: "unavailable", code: "systemctl_failed" };
	const values = parseSystemdProperties(result.stdout, properties);
	if (!values) return { state: "unavailable", code: "systemctl_malformed" };
	const mainPid = numericSystemdProperty(values.get("MainPID"));
	const execMainPid = numericSystemdProperty(values.get("ExecMainPID"));
	const controlPid = numericSystemdProperty(values.get("ControlPID"));
	const managerExecStartArgv = parseSystemdShowExecStart(values.get("ExecStart") ?? "");
	if (mainPid === undefined || execMainPid === undefined || controlPid === undefined || !managerExecStartArgv)
		return { state: "unavailable", code: "systemctl_malformed" };
	const fragmentPath = values.get("FragmentPath") ?? "";
	let fragment: IncidentCasV2ObservedFile;
	try {
		fragment = observeRegularFile(fragmentPath, 64 * 1024);
	} catch {
		return { state: "unavailable", code: "fragment_unavailable" };
	}
	const nodePath = managerExecStartArgv[0];
	const entrypointPath = managerExecStartArgv[1];
	if (!nodePath || !entrypointPath) return { state: "unavailable", code: "systemctl_malformed" };
	let node: IncidentCasV2ObservedIdentity;
	try {
		node = observeFileIdentity(nodePath);
	} catch {
		return { state: "unavailable", code: "node_unavailable" };
	}
	let entrypoint: IncidentCasV2ObservedFile;
	try {
		entrypoint = observeRegularFile(entrypointPath, 64 * 1024 * 1024);
	} catch {
		return { state: "unavailable", code: "entrypoint_unavailable" };
	}
	return {
		state: "observed",
		unitName,
		loadState: values.get("LoadState") ?? "",
		activeState: values.get("ActiveState") ?? "",
		subState: values.get("SubState") ?? "",
		needDaemonReload: values.get("NeedDaemonReload") ?? "",
		mainPid,
		execMainPid,
		controlPid,
		observationGeneration: values.get("StateChangeTimestampMonotonic") ?? "",
		fragment,
		node,
		entrypoint,
		managerExecStartArgv,
	};
}

function readHostId(path: string): string {
	const value = readFileSync(path, "utf8").trim();
	if (!HOST_ID.test(value)) throw new Error("host identity malformed");
	return value;
}

function parseProcStat(value: string): { state: string; parentPid: number; startId: string } | undefined {
	const end = value.lastIndexOf(")");
	if (end < 0) return undefined;
	const fields = value
		.slice(end + 1)
		.trim()
		.split(/\s+/);
	const state = fields[0];
	const parentPid = Number(fields[1]);
	const startId = fields[19];
	return state?.length === 1 &&
		Number.isSafeInteger(parentPid) &&
		parentPid >= 0 &&
		startId &&
		PROCESS_START_ID.test(startId)
		? { state, parentPid, startId }
		: undefined;
}

function parseProcUid(value: string): number | undefined {
	const match = /^Uid:\s+([0-9]+)\s/m.exec(value);
	if (!match) return undefined;
	const uid = Number(match[1]);
	return Number.isSafeInteger(uid) ? uid : undefined;
}

function defaultCurrentIdentity(): IncidentCasV2ProcessIdentityObservation {
	if (!process.getuid || !process.getgid) return { state: "unavailable", code: "identity_malformed" };
	try {
		const parsed = parseProcStat(boundedRead("/proc/self/stat", 64 * 1024).toString("utf8"));
		if (!parsed) return { state: "unavailable", code: "identity_malformed" };
		return {
			state: "present",
			identity: {
				machineId: readHostId("/etc/machine-id"),
				bootId: readHostId("/proc/sys/kernel/random/boot_id"),
				pid: process.pid,
				startId: parsed.startId,
				uid: process.getuid(),
				gid: process.getgid(),
			},
		};
	} catch {
		return { state: "unavailable", code: "proc_unavailable" };
	}
}

function defaultProcessIdentity(pid: number): IncidentCasV2ProcessIdentityObservation {
	try {
		const parsed = parseProcStat(boundedRead(`/proc/${pid}/stat`, 64 * 1024).toString("utf8"));
		const status = boundedRead(`/proc/${pid}/status`, 64 * 1024).toString("utf8");
		const uid = parseProcUid(status);
		const gidMatch = /^Gid:\s+([0-9]+)\s/m.exec(status);
		const gid = gidMatch ? Number(gidMatch[1]) : undefined;
		if (!parsed || uid === undefined || gid === undefined || !Number.isSafeInteger(gid))
			return { state: "unavailable", code: "identity_malformed" };
		return {
			state: "present",
			identity: {
				machineId: readHostId("/etc/machine-id"),
				bootId: readHostId("/proc/sys/kernel/random/boot_id"),
				pid,
				startId: parsed.startId,
				uid,
				gid,
			},
		};
	} catch (error) {
		if (isErrno(error, "ENOENT") || isErrno(error, "ESRCH")) return { state: "absent" };
		return { state: "unavailable", code: "proc_unavailable" };
	}
}

function readProcLink(path: string): string | null {
	try {
		return readlinkSync(path);
	} catch (error) {
		if (isErrno(error, "ENOENT") || isErrno(error, "ESRCH")) return null;
		throw error;
	}
}

function readProcEntriesBounded():
	| { state: "observed"; entries: readonly string[] }
	| { state: "unavailable"; code: "proc_unavailable" | "population_limit" } {
	let directory: ReturnType<typeof opendirSync> | undefined;
	try {
		directory = opendirSync("/proc");
		const entries: string[] = [];
		while (true) {
			const entry = directory.readSync();
			if (!entry) break;
			if (!/^[1-9][0-9]*$/.test(entry.name)) continue;
			if (entries.length >= DIRECTORY_SCAN_MAX_ENTRIES) {
				directory.closeSync();
				directory = undefined;
				return { state: "unavailable", code: "population_limit" };
			}
			entries.push(entry.name);
		}
		directory.closeSync();
		directory = undefined;
		return { state: "observed", entries };
	} catch {
		return { state: "unavailable", code: "proc_unavailable" };
	} finally {
		if (directory) {
			try {
				directory.closeSync();
			} catch {
				// The observation is already unavailable; do not disclose a raw close error.
			}
		}
	}
}

function defaultProcessPopulation(): IncidentCasV2ProcessPopulationObservation {
	if (!process.getuid) return { state: "unavailable", code: "proc_unavailable" };
	const currentUid = process.getuid();
	const initialEntries = readProcEntriesBounded();
	if (initialEntries.state === "unavailable") return initialEntries;
	const entries = initialEntries.entries;
	const processes: IncidentCasV2ObservedProcess[] = [];
	for (const entry of entries) {
		const pid = Number(entry);
		try {
			const statusBytes = boundedRead(`/proc/${entry}/status`, 64 * 1024);
			const uid = parseProcUid(statusBytes.toString("utf8"));
			if (uid === undefined) return { state: "unavailable", code: "population_changed" };
			if (uid !== currentUid) continue;
			const parsed = parseProcStat(boundedRead(`/proc/${entry}/stat`, 64 * 1024).toString("utf8"));
			if (!parsed) return { state: "unavailable", code: "population_changed" };
			if (parsed.state === "Z") {
				processes.push({
					pid,
					parentPid: parsed.parentPid,
					uid,
					startId: parsed.startId,
					processState: parsed.state,
					inspection: "complete",
					argv: [],
					cwd: null,
					executable: null,
				});
				continue;
			}
			const cmdline = boundedRead(`/proc/${entry}/cmdline`, PROC_FILE_MAX_BYTES);
			const argv =
				cmdline.length === 0
					? []
					: cmdline
							.toString("utf8")
							.split("\u0000")
							.filter((argument, index, values) => argument.length > 0 || index < values.length - 1);
			const cwd = readProcLink(`/proc/${entry}/cwd`);
			const executable = readProcLink(`/proc/${entry}/exe`);
			const after = parseProcStat(boundedRead(`/proc/${entry}/stat`, 64 * 1024).toString("utf8"));
			if (!after || after.startId !== parsed.startId || after.parentPid !== parsed.parentPid)
				return { state: "unavailable", code: "population_changed" };
			processes.push({
				pid,
				parentPid: parsed.parentPid,
				uid,
				startId: parsed.startId,
				processState: parsed.state,
				inspection: cwd && executable && argv.length > 0 ? "complete" : "ambiguous",
				argv,
				cwd,
				executable,
			});
		} catch (error) {
			if (isErrno(error, "ENOENT") || isErrno(error, "ESRCH")) continue;
			return { state: "unavailable", code: "proc_unavailable" };
		}
	}
	const finalSameUidProcesses: IncidentCasV2ObservedProcess[] = [];
	const closingEntries = readProcEntriesBounded();
	if (closingEntries.state === "unavailable") return closingEntries;
	for (const entry of closingEntries.entries) {
		try {
			const before = parseProcStat(boundedRead(`/proc/${entry}/stat`, 64 * 1024).toString("utf8"));
			const uid = parseProcUid(boundedRead(`/proc/${entry}/status`, 64 * 1024).toString("utf8"));
			if (!before || uid === undefined) return { state: "unavailable", code: "population_changed" };
			if (uid !== currentUid) {
				const after = parseProcStat(boundedRead(`/proc/${entry}/stat`, 64 * 1024).toString("utf8"));
				if (!after || before.startId !== after.startId || before.parentPid !== after.parentPid)
					return { state: "unavailable", code: "population_changed" };
				continue;
			}
			if (before.state === "Z") {
				const after = parseProcStat(boundedRead(`/proc/${entry}/stat`, 64 * 1024).toString("utf8"));
				if (!after || before.startId !== after.startId || before.parentPid !== after.parentPid)
					return { state: "unavailable", code: "population_changed" };
				finalSameUidProcesses.push({
					pid: Number(entry),
					parentPid: after.parentPid,
					uid,
					startId: after.startId,
					processState: after.state,
					inspection: "complete",
					argv: [],
					cwd: null,
					executable: null,
				});
				continue;
			}
			const cmdline = boundedRead(`/proc/${entry}/cmdline`, PROC_FILE_MAX_BYTES);
			const argv =
				cmdline.length === 0
					? []
					: cmdline
							.toString("utf8")
							.split("\u0000")
							.filter((argument, index, values) => argument.length > 0 || index < values.length - 1);
			const cwd = readProcLink(`/proc/${entry}/cwd`);
			const executable = readProcLink(`/proc/${entry}/exe`);
			const closingCmdline = boundedRead(`/proc/${entry}/cmdline`, PROC_FILE_MAX_BYTES);
			const closingArgv =
				closingCmdline.length === 0
					? []
					: closingCmdline
							.toString("utf8")
							.split("\u0000")
							.filter((argument, index, values) => argument.length > 0 || index < values.length - 1);
			const closingCwd = readProcLink(`/proc/${entry}/cwd`);
			const closingExecutable = readProcLink(`/proc/${entry}/exe`);
			const after = parseProcStat(boundedRead(`/proc/${entry}/stat`, 64 * 1024).toString("utf8"));
			if (
				!after ||
				before.startId !== after.startId ||
				before.parentPid !== after.parentPid ||
				!exactArray(argv, closingArgv) ||
				cwd !== closingCwd ||
				executable !== closingExecutable
			)
				return { state: "unavailable", code: "population_changed" };
			finalSameUidProcesses.push({
				pid: Number(entry),
				parentPid: after.parentPid,
				uid,
				startId: after.startId,
				processState: after.state,
				inspection: closingCwd && closingExecutable && closingArgv.length > 0 ? "complete" : "ambiguous",
				argv: closingArgv,
				cwd: closingCwd,
				executable: closingExecutable,
			});
		} catch (error) {
			if (isErrno(error, "ENOENT") || isErrno(error, "ESRCH")) continue;
			return { state: "unavailable", code: "proc_unavailable" };
		}
	}
	return { state: "observed", processes, finalSameUidProcesses };
}

function bindRuntime(handle?: IncidentCasV2TestRuntimeHandle): RuntimeBinding {
	if (!handle) {
		return {
			readLauncher: defaultReadLauncher,
			readProcessPopulation: defaultProcessPopulation,
			readCurrentProcessIdentity: defaultCurrentIdentity,
			readProcessIdentity: defaultProcessIdentity,
			monotonicTimeMs: defaultMonotonicTimeMs,
		};
	}
	const runtime = registeredTestRuntimes.get(handle);
	if (
		!runtime ||
		runtime.kind !== "incident_cas_v2_structured_test_runtime" ||
		typeof runtime.readLauncher !== "function" ||
		typeof runtime.readProcessPopulation !== "function" ||
		typeof runtime.readCurrentProcessIdentity !== "function" ||
		typeof runtime.readProcessIdentity !== "function"
	)
		throw new CutoverFailure("invalid_target");
	return {
		readLauncher: runtime.readLauncher.bind(runtime),
		readProcessPopulation: runtime.readProcessPopulation.bind(runtime),
		readCurrentProcessIdentity: runtime.readCurrentProcessIdentity.bind(runtime),
		readProcessIdentity: runtime.readProcessIdentity.bind(runtime),
		monotonicTimeMs: runtime.monotonicTimeMs?.bind(runtime) ?? defaultMonotonicTimeMs,
		testRuntime: runtime,
		...(runtime.onStep ? { onStep: runtime.onStep.bind(runtime) } : {}),
	};
}

function recoverAndClaim(
	context: RootContext,
	target: NormalizedTarget,
	runtime: RuntimeBinding,
): { state: "v2" } | { state: "draining"; claim: ArtifactSnapshot; generation: ArtifactSnapshot } {
	const current = readCurrentOwner(runtime);
	if (current.uid.toString() !== context.controlBinding.uid || current.gid.toString() !== context.controlBinding.gid)
		throw new CutoverFailure("orchestration_owner_unknown");
	recoverPrepareScratch(context, runtime);
	let artifacts = recoverKnownLinkedPrepare(context, readArtifacts(context), runtime);
	artifacts = recoverStandalonePrepare(context, target, runtime, artifacts, current);
	artifacts = cleanupPublishedResidue(context, target, artifacts, runtime);
	if (artifacts.generation) assertRecordMatchesContext(artifacts.generation.record, context, target);
	if (artifacts.claim) assertRecordMatchesContext(artifacts.claim.record, context, target);
	if (artifacts.generation?.record.kind !== "incident_cas_v2_generation" && artifacts.generation)
		throw new CutoverFailure("invalid_control_artifact");
	if (
		artifacts.generation?.record.kind === "incident_cas_v2_generation" &&
		artifacts.generation.record.state === "v2"
	) {
		if (artifacts.claim || artifacts.prepare) throw new CutoverFailure("invalid_control_artifact");
		return { state: "v2" };
	}
	let cutoverId =
		artifacts.generation?.record.kind === "incident_cas_v2_generation"
			? artifacts.generation.record.cutoverId
			: randomUUID();
	let claim = artifacts.claim;
	if (claim) {
		if (claim.record.kind !== "incident_cas_v2_orchestration_claim")
			throw new CutoverFailure("invalid_control_artifact");
		if (artifacts.generation) validateClaimGenerationPair(claim, artifacts.generation);
		else cutoverId = claim.record.cutoverId;
		const disposition = claimDisposition(claim.record, current, runtime);
		if (disposition === "live") throw new CutoverFailure("orchestration_in_progress");
		if (disposition === "unknown") throw new CutoverFailure("orchestration_owner_unknown");
		if (disposition === "stale") {
			retireClaimBound(context, claim, runtime);
			claim = undefined;
		}
	}
	if (!claim) claim = createClaim(context, target, runtime, cutoverId, current);
	let generation = artifacts.generation;
	if (!generation) generation = createDrainingGeneration(context, target, runtime, cutoverId);
	validateClaimGenerationPair(claim, generation);
	if (generation.record.kind !== "incident_cas_v2_generation" || generation.record.state !== "draining")
		throw new CutoverFailure("invalid_control_artifact");
	return { state: "draining", claim, generation };
}

export function beginIncidentCasV2Cutover(
	targetInput: IncidentCasV2CutoverTarget,
	testRuntimeHandle?: IncidentCasV2TestRuntimeHandle,
): BeginIncidentCasV2CutoverResult {
	if (process.platform !== "linux" && !testRuntimeHandle)
		return { state: "unavailable", reason: "platform_unsupported" };
	let context: RootContext | undefined;
	try {
		const target = normalizeTarget(targetInput);
		const runtime = bindRuntime(testRuntimeHandle);
		context = createRootContext(target.agentDir);
		assertLegacyAbsent(context);
		launcherEvidence(
			target,
			runtime.readLauncher(INCIDENT_CAS_V2_SYSTEMD_UNIT),
			false,
			context.controlIdentity.uid,
			context.controlIdentity.gid,
		);
		const claimed = recoverAndClaim(context, target, runtime);
		assertLegacyAbsent(context);
		if (claimed.state === "v2") {
			closeContext(context);
			return { state: "v2" };
		}
		const state: CutoverState = {
			context,
			target,
			runtime,
			claim: claimed.claim,
			generation: claimed.generation,
			closed: false,
		};
		context = undefined;
		return { state: "draining", cutover: makeCutover(state) };
	} catch (error) {
		if (context) closeContext(context);
		return { state: "unavailable", reason: error instanceof CutoverFailure ? error.reason : "io_error" };
	}
}

export function proveIncidentCasV1Quiescence(cutover: IncidentCasV2Cutover): ProveIncidentCasV1QuiescenceResult {
	const state = cutovers.get(cutover);
	if (!state || state.closed) return { state: "unavailable", reason: "claim_lost" };
	try {
		assertCutoverCurrent(state);
		const evidence = observeQuiescence(state);
		if (evidence.state === "unavailable") return evidence;
		assertCutoverCurrent(state);
		state.runtime.onStep?.("quiescence_observed");
		const issuedAtMs = state.runtime.monotonicTimeMs();
		if (!Number.isFinite(issuedAtMs) || issuedAtMs < 0) return { state: "unavailable", reason: "witness_invalid" };
		return {
			state: "proved",
			witness: makeWitness({
				cutover: state,
				used: false,
				issuedAtMs,
				observationGeneration: evidence.launcher.observationGeneration,
				launcherEvidenceDigest: evidence.launcher.digest,
				claimIdentity: state.claim.identity,
				generationIdentity: state.generation.identity,
			}),
		};
	} catch (error) {
		return { state: "unavailable", reason: error instanceof CutoverFailure ? error.reason : "io_error" };
	}
}

function prepareV2(state: CutoverState, record: GenerationRecord): ArtifactSnapshot {
	const prepared = prepareRecord(state.context, record, state.runtime, "v2");
	state.runtime.onStep?.("v2_prepared");
	return prepared;
}

function commitPreparedV2(state: CutoverState, prepared: ArtifactSnapshot, expectedLauncher: LauncherEvidence): void {
	assertCutoverCurrent(state, true);
	const launcher = launcherEvidence(
		state.target,
		state.runtime.readLauncher(INCIDENT_CAS_V2_SYSTEMD_UNIT),
		true,
		state.context.controlIdentity.uid,
		state.context.controlIdentity.gid,
	);
	if (
		launcher.observationGeneration !== expectedLauncher.observationGeneration ||
		launcher.digest !== expectedLauncher.digest
	)
		throw new CutoverFailure("witness_stale");
	assertCutoverCurrent(state, true);
	renameSync(state.context.preparePath, state.context.generationPath);
	state.runtime.onStep?.("v2_published");
	fsyncControl(state.context);
	state.runtime.onStep?.("v2_directory_fsynced");
	const published = readArtifact(state.context.generationPath, state.context);
	if (!published || published.identity.nlink !== 1n || !published.bytes.equals(prepared.bytes))
		throw new CutoverFailure("generation_changed");
	retireClaimBound(state.context, state.claim, state.runtime);
}

export function publishIncidentCasV2(
	cutover: IncidentCasV2Cutover,
	witness: IncidentCasV1QuiescenceWitness,
): PublishIncidentCasV2Result {
	const state = cutovers.get(cutover);
	const proof = witnesses.get(witness);
	if (!state || state.closed || !proof || proof.cutover !== state || proof.used)
		return { state: "unavailable", reason: "witness_invalid" };
	proof.used = true;
	try {
		const now = state.runtime.monotonicTimeMs();
		if (!Number.isFinite(now) || now < proof.issuedAtMs || now - proof.issuedAtMs > WITNESS_MAX_AGE_MS)
			return { state: "unavailable", reason: "witness_stale" };
		assertCutoverCurrent(state);
		if (
			!sameIdentity(state.claim.identity, proof.claimIdentity) ||
			!sameIdentity(state.generation.identity, proof.generationIdentity)
		)
			return { state: "unavailable", reason: "witness_invalid" };
		const evidence = observeQuiescence(state);
		if (evidence.state === "unavailable") return evidence;
		if (
			evidence.launcher.observationGeneration !== proof.observationGeneration ||
			evidence.launcher.digest !== proof.launcherEvidenceDigest
		)
			return { state: "unavailable", reason: "witness_stale" };
		assertCutoverCurrent(state);
		if (state.generation.record.kind !== "incident_cas_v2_generation")
			return { state: "unavailable", reason: "generation_changed" };
		const v2: GenerationRecord = { ...state.generation.record, state: "v2" };
		const prepared = prepareV2(state, v2);
		state.runtime.onStep?.("before_v2_publish");
		const finalEvidence = observeQuiescence(state);
		if (finalEvidence.state === "unavailable") {
			discardPrepare(state.context, prepared, state.runtime);
			return finalEvidence;
		}
		if (
			finalEvidence.launcher.observationGeneration !== proof.observationGeneration ||
			finalEvidence.launcher.digest !== proof.launcherEvidenceDigest
		) {
			discardPrepare(state.context, prepared, state.runtime);
			return { state: "unavailable", reason: "witness_stale" };
		}
		state.runtime.onStep?.("after_final_quiescence");
		commitPreparedV2(state, prepared, finalEvidence.launcher);
		closeCutoverState(state);
		return { state: "published" };
	} catch (error) {
		return { state: "unavailable", reason: error instanceof CutoverFailure ? error.reason : "io_error" };
	}
}

function revokeActivation(
	state: ActivationState,
	reason: IncidentCasV2UnavailableReason,
): { state: "invalid"; reason: IncidentCasV2UnavailableReason } {
	state.revokedReason = reason;
	if (!state.closed) {
		state.closed = true;
		closeContext(state.context);
	}
	return { state: "invalid", reason };
}

function activationStillValid(
	state: ActivationState,
): { state: "valid" } | { state: "invalid"; reason: IncidentCasV2UnavailableReason } {
	if (state.revokedReason) return { state: "invalid", reason: state.revokedReason };
	if (state.closed) return { state: "invalid", reason: "generation_changed" };
	try {
		assertContextCurrent(state.context);
		assertTargetConfigurationCurrent(state.target);
		assertKnownControlNamespace(state.context);
		assertLegacyAbsent(state.context);
		if (pathExistsNoFollow(state.context.preparePath) || pathExistsNoFollow(state.context.claimPath))
			return revokeActivation(state, "activation_cleanup_pending");
		if (!sameSnapshot(state.context.generationPath, state.generation, state.context))
			return revokeActivation(state, "generation_changed");
		const launcher = launcherEvidence(
			state.target,
			state.runtime.readLauncher(INCIDENT_CAS_V2_SYSTEMD_UNIT),
			false,
			state.context.controlIdentity.uid,
			state.context.controlIdentity.gid,
		);
		if (launcher.digest !== state.launcherEvidenceDigest) return revokeActivation(state, "launcher_mismatch");
		assertLegacyAbsent(state.context);
		assertTargetConfigurationCurrent(state.target);
		if (!sameSnapshot(state.context.generationPath, state.generation, state.context))
			return revokeActivation(state, "generation_changed");
		return { state: "valid" };
	} catch (error) {
		return revokeActivation(state, error instanceof CutoverFailure ? error.reason : "io_error");
	}
}

function makeActivation(state: ActivationState): IncidentCasV2Activation {
	const activation = Object.freeze({
		activationGenerationDigest: sha256(state.generation.bytes),
		revalidate(): { state: "valid" } | { state: "invalid"; reason: IncidentCasV2UnavailableReason } {
			const current = activations.get(activation);
			return current ? activationStillValid(current) : { state: "invalid", reason: "generation_changed" };
		},
		close(): void {
			const current = activations.get(activation);
			if (!current || current.closed) return;
			current.closed = true;
			closeContext(current.context);
		},
	}) as IncidentCasV2Activation;
	activations.set(activation, state);
	return activation;
}

export function openIncidentCasV2Activation(
	targetInput: IncidentCasV2CutoverTarget,
	testRuntimeHandle?: IncidentCasV2TestRuntimeHandle,
): OpenIncidentCasV2ActivationResult {
	if (process.platform !== "linux" && !testRuntimeHandle)
		return { state: "unavailable", reason: "platform_unsupported" };
	let context: RootContext | undefined;
	try {
		const target = normalizeTarget(targetInput);
		const runtime = bindRuntime(testRuntimeHandle);
		context = createRootContext(target.agentDir);
		assertLegacyAbsent(context);
		const artifacts = readArtifacts(context);
		if (artifacts.prepare || artifacts.claim) throw new CutoverFailure("activation_cleanup_pending");
		if (!artifacts.generation) throw new CutoverFailure("generation_changed");
		assertRecordMatchesContext(artifacts.generation.record, context, target);
		if (
			artifacts.generation.record.kind !== "incident_cas_v2_generation" ||
			artifacts.generation.record.state !== "v2" ||
			artifacts.generation.identity.nlink !== 1n
		)
			throw new CutoverFailure("generation_changed");
		const launcher = launcherEvidence(
			target,
			runtime.readLauncher(INCIDENT_CAS_V2_SYSTEMD_UNIT),
			false,
			context.controlIdentity.uid,
			context.controlIdentity.gid,
		);
		assertLegacyAbsent(context);
		assertTargetConfigurationCurrent(target);
		if (!sameSnapshot(context.generationPath, artifacts.generation, context))
			throw new CutoverFailure("generation_changed");
		const state: ActivationState = {
			context,
			target,
			runtime,
			generation: artifacts.generation,
			launcherEvidenceDigest: launcher.digest,
			closed: false,
			revokedReason: undefined,
		};
		context = undefined;
		return { state: "active", activation: makeActivation(state) };
	} catch (error) {
		if (context) closeContext(context);
		return { state: "unavailable", reason: error instanceof CutoverFailure ? error.reason : "io_error" };
	}
}
