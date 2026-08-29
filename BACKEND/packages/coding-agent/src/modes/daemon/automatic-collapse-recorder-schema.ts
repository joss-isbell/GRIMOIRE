export const AUTOMATIC_COLLAPSE_EVIDENCE_SCHEMA_VERSION = 1 as const;

function frozenCopy<const T extends readonly string[]>(values: T): T {
	return Object.freeze([...values]) as unknown as T;
}

function immutableMembership<const T extends readonly string[]>(values: T): Readonly<Record<T[number], true>> {
	const table = Object.create(null) as Record<string, true>;
	for (const value of values) table[value] = true;
	return Object.freeze(table) as Readonly<Record<T[number], true>>;
}

function immutableIndex<const T extends readonly string[]>(values: T): Readonly<Record<T[number], number>> {
	const table = Object.create(null) as Record<string, number>;
	for (const [index, value] of values.entries()) table[value] = index;
	return Object.freeze(table) as Readonly<Record<T[number], number>>;
}

const CANONICAL_AUTOMATIC_COLLAPSE_ROLES = Object.freeze([
	"recorder_wrapper",
	"supervisor",
	"worker",
	"forkserver",
	"direct_kernel",
	"forked_kernel",
] as const);
export const AUTOMATIC_COLLAPSE_ROLES = frozenCopy(CANONICAL_AUTOMATIC_COLLAPSE_ROLES);
export type AutomaticCollapseRole = (typeof AUTOMATIC_COLLAPSE_ROLES)[number];
const AUTOMATIC_COLLAPSE_ROLE_MEMBERS = immutableMembership(CANONICAL_AUTOMATIC_COLLAPSE_ROLES);

const CANONICAL_EVIDENCE_PROVIDERS = Object.freeze([
	"application_transition",
	"linux_kernel",
	"authoritative_parent",
] as const);
export const EVIDENCE_PROVIDERS = frozenCopy(CANONICAL_EVIDENCE_PROVIDERS);
export type EvidenceProvider = (typeof EVIDENCE_PROVIDERS)[number];
const EVIDENCE_PROVIDER_MEMBERS = immutableMembership(CANONICAL_EVIDENCE_PROVIDERS);

const CANONICAL_APPLICATION_STATES = Object.freeze(["starting", "running", "stopping", "stopped"] as const);
export const APPLICATION_STATES = frozenCopy(CANONICAL_APPLICATION_STATES);
export type ApplicationState = (typeof APPLICATION_STATES)[number];
const APPLICATION_STATE_MEMBERS = immutableMembership(CANONICAL_APPLICATION_STATES);

const CANONICAL_EVIDENCE_CUSTODY_STATES = Object.freeze([
	"kernel_produced",
	"linux_received",
	"host_published",
	"windows_committed",
] as const);
export const EVIDENCE_CUSTODY_STATES = frozenCopy(CANONICAL_EVIDENCE_CUSTODY_STATES);
export type EvidenceCustodyState = (typeof EVIDENCE_CUSTODY_STATES)[number];
const EVIDENCE_CUSTODY_MEMBERS = immutableMembership(CANONICAL_EVIDENCE_CUSTODY_STATES);
const EVIDENCE_CUSTODY_INDEX = immutableIndex(CANONICAL_EVIDENCE_CUSTODY_STATES);

const CANONICAL_LINUX_SIGNAL_NAMES = Object.freeze([
	"SIGHUP",
	"SIGINT",
	"SIGQUIT",
	"SIGILL",
	"SIGTRAP",
	"SIGABRT",
	"SIGBUS",
	"SIGFPE",
	"SIGKILL",
	"SIGUSR1",
	"SIGSEGV",
	"SIGUSR2",
	"SIGPIPE",
	"SIGALRM",
	"SIGTERM",
	"SIGSTKFLT",
	"SIGCHLD",
	"SIGCONT",
	"SIGSTOP",
	"SIGTSTP",
	"SIGTTIN",
	"SIGTTOU",
	"SIGURG",
	"SIGXCPU",
	"SIGXFSZ",
	"SIGVTALRM",
	"SIGPROF",
	"SIGWINCH",
	"SIGIO",
	"SIGPWR",
	"SIGSYS",
	"SIG32",
	"SIG33",
	"SIGRTMIN",
	"SIGRTMIN+1",
	"SIGRTMIN+2",
	"SIGRTMIN+3",
	"SIGRTMIN+4",
	"SIGRTMIN+5",
	"SIGRTMIN+6",
	"SIGRTMIN+7",
	"SIGRTMIN+8",
	"SIGRTMIN+9",
	"SIGRTMIN+10",
	"SIGRTMIN+11",
	"SIGRTMIN+12",
	"SIGRTMIN+13",
	"SIGRTMIN+14",
	"SIGRTMIN+15",
	"SIGRTMIN+16",
	"SIGRTMIN+17",
	"SIGRTMIN+18",
	"SIGRTMIN+19",
	"SIGRTMIN+20",
	"SIGRTMIN+21",
	"SIGRTMIN+22",
	"SIGRTMIN+23",
	"SIGRTMIN+24",
	"SIGRTMIN+25",
	"SIGRTMIN+26",
	"SIGRTMIN+27",
	"SIGRTMIN+28",
	"SIGRTMIN+29",
	"SIGRTMAX",
] as const);
export const LINUX_SIGNAL_NAMES = frozenCopy(CANONICAL_LINUX_SIGNAL_NAMES);
export type LinuxSignalName = (typeof LINUX_SIGNAL_NAMES)[number];
const LINUX_SIGNAL_MEMBERS = immutableMembership(CANONICAL_LINUX_SIGNAL_NAMES);

const CANONICAL_NODE_CALLBACK_SIGNAL_NAMES = Object.freeze([
	"SIGHUP",
	"SIGINT",
	"SIGQUIT",
	"SIGILL",
	"SIGTRAP",
	"SIGABRT",
	"SIGBUS",
	"SIGFPE",
	"SIGKILL",
	"SIGUSR1",
	"SIGSEGV",
	"SIGUSR2",
	"SIGPIPE",
	"SIGALRM",
	"SIGTERM",
	"SIGSTKFLT",
	"SIGCHLD",
	"SIGCONT",
	"SIGSTOP",
	"SIGTSTP",
	"SIGTTIN",
	"SIGTTOU",
	"SIGURG",
	"SIGXCPU",
	"SIGXFSZ",
	"SIGVTALRM",
	"SIGPROF",
	"SIGWINCH",
	"SIGIO",
	"SIGPWR",
	"SIGSYS",
] as const);
export const NODE_CALLBACK_SIGNAL_NAMES = frozenCopy(CANONICAL_NODE_CALLBACK_SIGNAL_NAMES);
export type NodeCallbackSignalName = (typeof NODE_CALLBACK_SIGNAL_NAMES)[number];
const NODE_CALLBACK_SIGNAL_MEMBERS = immutableMembership(CANONICAL_NODE_CALLBACK_SIGNAL_NAMES);
const NODE_CALLBACK_SIGNAL_NUMBER_BY_NAME = Object.freeze(
	Object.fromEntries(CANONICAL_NODE_CALLBACK_SIGNAL_NAMES.map((name, index) => [name, index + 1])),
) as Readonly<Record<NodeCallbackSignalName, number>>;

export interface InstallationRunIdentity {
	readonly installationId: string;
	readonly runId: string;
}

export interface LinuxProcessKey {
	readonly linuxBootId: string;
	readonly pidNamespaceInode: string;
	readonly distroPid: number;
	readonly procStartTicks: string;
}

export interface KernelTaskKey {
	readonly linuxBootId: string;
	readonly initialTgid: number;
	readonly taskStartBootNs: string;
}

export interface ProcessAnchor {
	readonly processAnchorId: string;
	readonly installationRun: InstallationRunIdentity;
	readonly linuxProcessKey: LinuxProcessKey;
	readonly kernelTaskKey: KernelTaskKey;
}

export interface RoleAssignment {
	readonly assignmentId: string;
	readonly role: AutomaticCollapseRole;
	readonly processAnchorId: string;
	readonly expectedExecutableId: string;
	readonly expectedBuildId: string;
}

export interface SpawnOccurrence {
	readonly occurrenceId: string;
	readonly ordinal: number;
	readonly parentProcessAnchorId: string;
	readonly childProcessAnchorId: string;
}

export interface EvidenceSourcePosition {
	readonly provider: EvidenceProvider;
	readonly epoch: string;
	readonly strictSequence: number;
}

export interface AgentProfileProvenance {
	readonly agentId: string;
	readonly profileVersion: string;
}

export type ApplicationTransitionClaim =
	| {
			readonly kind: "application_transition";
			readonly observation: "state_transition";
			readonly from: ApplicationState;
			readonly to: ApplicationState;
	  }
	| {
			readonly kind: "application_transition";
			readonly observation: "signal_requested";
			readonly requestedSignal: LinuxSignalName;
	  }
	| {
			readonly kind: "application_transition";
			readonly observation: "silence_observed";
			readonly silenceMs: number;
	  };

export interface KernelExitClaim {
	readonly kind: "kernel_exit";
	readonly groupDead: true;
	readonly rawWaitWord: number;
}

export type AuthoritativeParentWaitClaim =
	| {
			readonly kind: "parent_wait";
			readonly observation: "linux_wait_word";
			readonly rawWaitWord: number;
	  }
	| {
			readonly kind: "parent_wait";
			readonly observation: "node_callback";
			readonly code: number;
			readonly signal: null;
	  }
	| {
			readonly kind: "parent_wait";
			readonly observation: "node_callback";
			readonly code: null;
			readonly signal: NodeCallbackSignalName;
	  };

export type AutomaticCollapseEvidenceClaim =
	| ApplicationTransitionClaim
	| KernelExitClaim
	| AuthoritativeParentWaitClaim;

export interface AutomaticCollapseEvidenceEnvelope {
	readonly schemaVersion: typeof AUTOMATIC_COLLAPSE_EVIDENCE_SCHEMA_VERSION;
	readonly evidenceId: string;
	readonly processAnchor: ProcessAnchor;
	readonly roleAssignment: RoleAssignment;
	readonly spawnOccurrence: SpawnOccurrence;
	readonly source: EvidenceSourcePosition;
	readonly agentProfile: AgentProfileProvenance;
	readonly observedAtMonotonicNs: string;
	readonly custody: EvidenceCustodyState;
	readonly claim: AutomaticCollapseEvidenceClaim;
}

export type LinuxWaitDecode =
	| { readonly kind: "exited"; readonly rawWaitWord: number; readonly exitCode: number }
	| {
			readonly kind: "signaled";
			readonly rawWaitWord: number;
			readonly signalNumber: number;
			readonly signalName: LinuxSignalName;
			readonly coreDumped: boolean;
	  }
	| {
			readonly kind: "stopped";
			readonly rawWaitWord: number;
			readonly stopSignalNumber: number;
			readonly stopSignalName: LinuxSignalName;
	  }
	| { readonly kind: "continued"; readonly rawWaitWord: number }
	| {
			readonly kind: "invalid";
			readonly reason:
				| "raw_wait_word_not_integer"
				| "raw_wait_word_out_of_range"
				| "invalid_signal_number"
				| "invalid_stop_signal_number";
	  };

export type NodeExitCallbackNormalization =
	| { readonly kind: "exited"; readonly exitCode: number; readonly source: "node_callback" }
	| {
			readonly kind: "signaled";
			readonly signalNumber: number;
			readonly signalName: NodeCallbackSignalName;
			readonly coreDumped: "unknown";
			readonly source: "node_callback";
	  }
	| {
			readonly kind: "invalid";
			readonly reason: "ambiguous_pair" | "missing_code_and_signal" | "invalid_exit_code" | "invalid_signal_name";
	  };

export type TerminalDisposition =
	| { readonly kind: "exited"; readonly exitCode: number }
	| {
			readonly kind: "signaled";
			readonly signalNumber: number;
			readonly signalName: LinuxSignalName;
			readonly coreDumped: boolean | "unknown";
	  };

export function decodeLinuxWaitWord(rawWaitWord: unknown): LinuxWaitDecode {
	if (typeof rawWaitWord !== "number" || !Number.isInteger(rawWaitWord))
		return { kind: "invalid", reason: "raw_wait_word_not_integer" };
	if (rawWaitWord < 0 || rawWaitWord > 0xffff) return { kind: "invalid", reason: "raw_wait_word_out_of_range" };
	if (rawWaitWord === 0xffff) return { kind: "continued", rawWaitWord };

	const lowByte = rawWaitWord & 0xff;
	const lowSevenBits = rawWaitWord & 0x7f;
	if (lowSevenBits === 0) return { kind: "exited", rawWaitWord, exitCode: (rawWaitWord >>> 8) & 0xff };
	if (lowByte === 0x7f) {
		const stopSignalNumber = (rawWaitWord >>> 8) & 0xff;
		const stopSignalName = CANONICAL_LINUX_SIGNAL_NAMES[stopSignalNumber - 1];
		if (!stopSignalName) return { kind: "invalid", reason: "invalid_stop_signal_number" };
		return { kind: "stopped", rawWaitWord, stopSignalNumber, stopSignalName };
	}
	const signalName = CANONICAL_LINUX_SIGNAL_NAMES[lowSevenBits - 1];
	if (!signalName) return { kind: "invalid", reason: "invalid_signal_number" };
	return {
		kind: "signaled",
		rawWaitWord,
		signalNumber: lowSevenBits,
		signalName,
		coreDumped: (rawWaitWord & 0x80) !== 0,
	};
}

export function normalizeNodeExitCallback(code: unknown, signal: unknown): NodeExitCallbackNormalization {
	if (code === null && signal === null) return { kind: "invalid", reason: "missing_code_and_signal" };
	if (code !== null && signal !== null) return { kind: "invalid", reason: "ambiguous_pair" };
	if (code !== null) {
		if (typeof code !== "number" || !Number.isSafeInteger(code) || code < 0 || code > 255)
			return { kind: "invalid", reason: "invalid_exit_code" };
		return { kind: "exited", exitCode: code, source: "node_callback" };
	}
	if (typeof signal !== "string" || !Object.hasOwn(NODE_CALLBACK_SIGNAL_MEMBERS, signal))
		return { kind: "invalid", reason: "invalid_signal_name" };
	const signalName = signal as NodeCallbackSignalName;
	return {
		kind: "signaled",
		signalNumber: NODE_CALLBACK_SIGNAL_NUMBER_BY_NAME[signalName],
		signalName,
		coreDumped: "unknown",
		source: "node_callback",
	};
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$/;
const POSITIVE_DECIMAL_PATTERN = /^[1-9][0-9]{0,29}$/;
const NONNEGATIVE_DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,29})$/;
const MAX_DISTRO_PID = 4_194_304;
const MAX_SILENCE_MS = 86_400_000;
const MAX_VALIDATION_ERRORS = 16;
const MAX_VALIDATION_NODES = 256;
const MAX_VALIDATION_DEPTH = 12;
const MAX_OWN_KEY_LENGTH = 128;
const FORBIDDEN_PRIVACY_KEY_FRAGMENTS = Object.freeze([
	"argv",
	"environment",
	"stdout",
	"stderr",
	"applicationlog",
	"applog",
	"applicationcontent",
	"appcontent",
	"content",
	"payload",
	"body",
	"memory",
	"credential",
	"secret",
	"token",
	"cookie",
	"authorization",
] as const);

class ValidationIssues {
	readonly values: string[] = [];

	add(issue: string): void {
		if (this.values.length < MAX_VALIDATION_ERRORS) this.values.push(issue);
	}
}

function normalizedKey(key: string): string {
	return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function hasForbiddenPrivacyTerm(key: string): boolean {
	const normalized = normalizedKey(key);
	return FORBIDDEN_PRIVACY_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment));
}

/**
 * Captures one bounded descriptor-derived snapshot. It never invokes an input
 * getter and validation never reads the caller-owned graph after this returns.
 */
function captureDataSnapshot(value: unknown, issues: ValidationIssues): unknown {
	const seen = new WeakSet<object>();
	let nodes = 0;

	function capture(current: unknown, path: string, depth: number): unknown {
		nodes += 1;
		if (nodes > MAX_VALIDATION_NODES) {
			issues.add(`${path}: validation node bound exceeded`);
			return undefined;
		}
		if (depth > MAX_VALIDATION_DEPTH) {
			issues.add(`${path}: validation depth exceeded`);
			return undefined;
		}
		if (current === null || ["string", "number", "boolean", "undefined"].includes(typeof current)) return current;
		if (typeof current !== "object") {
			issues.add(`${path}: non-data value rejected`);
			return undefined;
		}
		if (seen.has(current)) {
			issues.add(`${path}: cyclic or aliased value rejected`);
			return undefined;
		}
		seen.add(current);
		const prototype = Object.getPrototypeOf(current);
		if (prototype !== Object.prototype && prototype !== null) {
			issues.add(`${path}: expected plain data object`);
			return undefined;
		}

		const snapshot: Record<string, unknown> = {};
		for (const key of Reflect.ownKeys(current)) {
			if (issues.values.length >= MAX_VALIDATION_ERRORS) break;
			if (typeof key === "symbol") {
				issues.add(`${path}: symbol own key rejected`);
				continue;
			}
			const childPath = `${path}.${key}`;
			if (key.length > MAX_OWN_KEY_LENGTH) {
				issues.add(`${childPath.slice(0, path.length + 33)}: own key length exceeded`);
				continue;
			}
			if (hasForbiddenPrivacyTerm(key)) {
				issues.add(`${childPath}: forbidden privacy field`);
				continue;
			}
			const descriptor = Object.getOwnPropertyDescriptor(current, key);
			if (!descriptor) {
				issues.add(`${childPath}: unstable own property rejected`);
				continue;
			}
			if (descriptor.enumerable !== true) {
				issues.add(`${childPath}: non-enumerable own field rejected`);
				continue;
			}
			if (!Object.hasOwn(descriptor, "value")) {
				issues.add(`${childPath}: accessor properties rejected`);
				continue;
			}
			const captured = capture(descriptor.value, childPath, depth + 1);
			Object.defineProperty(snapshot, key, {
				value: captured,
				enumerable: true,
				writable: true,
				configurable: true,
			});
		}
		return Object.freeze(snapshot);
	}

	return capture(value, "$", 0);
}

function asRecord(value: unknown, path: string, issues: ValidationIssues): Record<string, unknown> | undefined {
	if (value === null || typeof value !== "object" || Array.isArray(value)) {
		issues.add(`${path}: expected object`);
		return undefined;
	}
	const prototype = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null) {
		issues.add(`${path}: expected plain object`);
		return undefined;
	}
	return value as Record<string, unknown>;
}

function exactKeys(
	record: Record<string, unknown>,
	required: readonly string[],
	path: string,
	issues: ValidationIssues,
): void {
	const allowed = new Set(required);
	for (const key of required) if (!Object.hasOwn(record, key)) issues.add(`${path}.${key}: required field missing`);
	for (const key of Reflect.ownKeys(record)) {
		if (typeof key === "symbol") issues.add(`${path}: symbol own key rejected`);
		else if (!allowed.has(key)) issues.add(`${path}.${key}: extra field rejected`);
		const descriptor = Object.getOwnPropertyDescriptor(record, key);
		if (descriptor?.enumerable !== true) issues.add(`${path}.${String(key)}: non-enumerable own field rejected`);
	}
}

function boundedId(value: unknown, path: string, issues: ValidationIssues): value is string {
	if (typeof value !== "string" || !ID_PATTERN.test(value)) {
		issues.add(`${path}: invalid bounded identifier`);
		return false;
	}
	return true;
}

function exactMember<T extends string>(
	value: unknown,
	membership: Readonly<Record<T, true>>,
	path: string,
	issues: ValidationIssues,
): value is T {
	if (typeof value !== "string" || !Object.hasOwn(membership, value)) {
		issues.add(`${path}: value is not allowlisted`);
		return false;
	}
	return true;
}

function boundedSafeInteger(
	value: unknown,
	minimum: number,
	maximum: number,
	path: string,
	issues: ValidationIssues,
): value is number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
		issues.add(`${path}: invalid bounded safe integer`);
		return false;
	}
	return true;
}

function decimalString(value: unknown, positive: boolean, path: string, issues: ValidationIssues): value is string {
	const pattern = positive ? POSITIVE_DECIMAL_PATTERN : NONNEGATIVE_DECIMAL_PATTERN;
	if (typeof value !== "string" || !pattern.test(value)) {
		issues.add(`${path}: invalid bounded decimal string`);
		return false;
	}
	return true;
}

function validateInstallationRun(value: unknown, path: string, issues: ValidationIssues): void {
	const record = asRecord(value, path, issues);
	if (!record) return;
	exactKeys(record, ["installationId", "runId"], path, issues);
	boundedId(record.installationId, `${path}.installationId`, issues);
	boundedId(record.runId, `${path}.runId`, issues);
}

function validateLinuxProcessKey(value: unknown, path: string, issues: ValidationIssues): void {
	const record = asRecord(value, path, issues);
	if (!record) return;
	exactKeys(record, ["linuxBootId", "pidNamespaceInode", "distroPid", "procStartTicks"], path, issues);
	boundedId(record.linuxBootId, `${path}.linuxBootId`, issues);
	decimalString(record.pidNamespaceInode, true, `${path}.pidNamespaceInode`, issues);
	boundedSafeInteger(record.distroPid, 1, MAX_DISTRO_PID, `${path}.distroPid`, issues);
	decimalString(record.procStartTicks, true, `${path}.procStartTicks`, issues);
}

function validateKernelTaskKey(value: unknown, path: string, issues: ValidationIssues): void {
	const record = asRecord(value, path, issues);
	if (!record) return;
	exactKeys(record, ["linuxBootId", "initialTgid", "taskStartBootNs"], path, issues);
	boundedId(record.linuxBootId, `${path}.linuxBootId`, issues);
	boundedSafeInteger(record.initialTgid, 1, MAX_DISTRO_PID, `${path}.initialTgid`, issues);
	decimalString(record.taskStartBootNs, true, `${path}.taskStartBootNs`, issues);
}

function validateProcessAnchor(value: unknown, path: string, issues: ValidationIssues): void {
	const record = asRecord(value, path, issues);
	if (!record) return;
	exactKeys(record, ["processAnchorId", "installationRun", "linuxProcessKey", "kernelTaskKey"], path, issues);
	boundedId(record.processAnchorId, `${path}.processAnchorId`, issues);
	validateInstallationRun(record.installationRun, `${path}.installationRun`, issues);
	validateLinuxProcessKey(record.linuxProcessKey, `${path}.linuxProcessKey`, issues);
	validateKernelTaskKey(record.kernelTaskKey, `${path}.kernelTaskKey`, issues);
	const linuxProcessKey = asRecord(record.linuxProcessKey, `${path}.linuxProcessKey`, issues);
	const kernelTaskKey = asRecord(record.kernelTaskKey, `${path}.kernelTaskKey`, issues);
	if (linuxProcessKey && kernelTaskKey && linuxProcessKey.linuxBootId !== kernelTaskKey.linuxBootId)
		issues.add(`${path}: Linux process and kernel task boot identities differ`);
}

function validateRoleAssignment(value: unknown, path: string, issues: ValidationIssues): void {
	const record = asRecord(value, path, issues);
	if (!record) return;
	exactKeys(
		record,
		["assignmentId", "role", "processAnchorId", "expectedExecutableId", "expectedBuildId"],
		path,
		issues,
	);
	boundedId(record.assignmentId, `${path}.assignmentId`, issues);
	exactMember(record.role, AUTOMATIC_COLLAPSE_ROLE_MEMBERS, `${path}.role`, issues);
	boundedId(record.processAnchorId, `${path}.processAnchorId`, issues);
	boundedId(record.expectedExecutableId, `${path}.expectedExecutableId`, issues);
	boundedId(record.expectedBuildId, `${path}.expectedBuildId`, issues);
}

function validateSpawnOccurrence(value: unknown, path: string, issues: ValidationIssues): void {
	const record = asRecord(value, path, issues);
	if (!record) return;
	exactKeys(record, ["occurrenceId", "ordinal", "parentProcessAnchorId", "childProcessAnchorId"], path, issues);
	boundedId(record.occurrenceId, `${path}.occurrenceId`, issues);
	boundedSafeInteger(record.ordinal, 0, Number.MAX_SAFE_INTEGER, `${path}.ordinal`, issues);
	boundedId(record.parentProcessAnchorId, `${path}.parentProcessAnchorId`, issues);
	boundedId(record.childProcessAnchorId, `${path}.childProcessAnchorId`, issues);
}

function validateSource(value: unknown, path: string, issues: ValidationIssues): void {
	const record = asRecord(value, path, issues);
	if (!record) return;
	exactKeys(record, ["provider", "epoch", "strictSequence"], path, issues);
	exactMember(record.provider, EVIDENCE_PROVIDER_MEMBERS, `${path}.provider`, issues);
	boundedId(record.epoch, `${path}.epoch`, issues);
	boundedSafeInteger(record.strictSequence, 0, Number.MAX_SAFE_INTEGER, `${path}.strictSequence`, issues);
}

function validateAgentProfile(value: unknown, path: string, issues: ValidationIssues): void {
	const record = asRecord(value, path, issues);
	if (!record) return;
	exactKeys(record, ["agentId", "profileVersion"], path, issues);
	boundedId(record.agentId, `${path}.agentId`, issues);
	boundedId(record.profileVersion, `${path}.profileVersion`, issues);
}

function validateApplicationClaim(record: Record<string, unknown>, path: string, issues: ValidationIssues): void {
	if (record.observation === "state_transition") {
		exactKeys(record, ["kind", "observation", "from", "to"], path, issues);
		exactMember(record.from, APPLICATION_STATE_MEMBERS, `${path}.from`, issues);
		exactMember(record.to, APPLICATION_STATE_MEMBERS, `${path}.to`, issues);
		return;
	}
	if (record.observation === "signal_requested") {
		exactKeys(record, ["kind", "observation", "requestedSignal"], path, issues);
		exactMember(record.requestedSignal, LINUX_SIGNAL_MEMBERS, `${path}.requestedSignal`, issues);
		return;
	}
	if (record.observation === "silence_observed") {
		exactKeys(record, ["kind", "observation", "silenceMs"], path, issues);
		boundedSafeInteger(record.silenceMs, 0, MAX_SILENCE_MS, `${path}.silenceMs`, issues);
		return;
	}
	issues.add(`${path}.observation: value is not allowlisted`);
}

function terminalWaitWord(rawWaitWord: unknown): boolean {
	const decoded = decodeLinuxWaitWord(rawWaitWord);
	return decoded.kind === "exited" || decoded.kind === "signaled";
}

function validateClaim(value: unknown, path: string, issues: ValidationIssues): EvidenceProvider | undefined {
	const record = asRecord(value, path, issues);
	if (!record) return undefined;
	if (record.kind === "application_transition") {
		validateApplicationClaim(record, path, issues);
		return "application_transition";
	}
	if (record.kind === "kernel_exit") {
		exactKeys(record, ["kind", "groupDead", "rawWaitWord"], path, issues);
		if (record.groupDead !== true) issues.add(`${path}.groupDead: process-terminal proof requires true`);
		if (!terminalWaitWord(record.rawWaitWord)) issues.add(`${path}.rawWaitWord: kernel exit must be terminal`);
		return "linux_kernel";
	}
	if (record.kind === "parent_wait") {
		if (record.observation === "linux_wait_word") {
			exactKeys(record, ["kind", "observation", "rawWaitWord"], path, issues);
			if (!terminalWaitWord(record.rawWaitWord)) issues.add(`${path}.rawWaitWord: parent wait must be terminal`);
		} else if (record.observation === "node_callback") {
			exactKeys(record, ["kind", "observation", "code", "signal"], path, issues);
			if (normalizeNodeExitCallback(record.code, record.signal).kind === "invalid")
				issues.add(`${path}: invalid Node callback pair`);
		} else {
			issues.add(`${path}.observation: value is not allowlisted`);
		}
		return "authoritative_parent";
	}
	issues.add(`${path}.kind: value is not allowlisted`);
	return undefined;
}

export type AutomaticCollapseEvidenceValidation =
	| { readonly ok: true; readonly value: AutomaticCollapseEvidenceEnvelope }
	| { readonly ok: false; readonly errors: readonly string[] };

function validationFailure(errors: readonly string[]): AutomaticCollapseEvidenceValidation {
	return Object.freeze({ ok: false, errors: Object.freeze([...errors]) });
}

export function validateAutomaticCollapseEvidence(value: unknown): AutomaticCollapseEvidenceValidation {
	const issues = new ValidationIssues();
	try {
		const snapshot = captureDataSnapshot(value, issues);
		if (issues.values.length > 0) return validationFailure(issues.values);
		const record = asRecord(snapshot, "$", issues);
		if (!record) return validationFailure(issues.values);
		exactKeys(
			record,
			[
				"schemaVersion",
				"evidenceId",
				"processAnchor",
				"roleAssignment",
				"spawnOccurrence",
				"source",
				"agentProfile",
				"observedAtMonotonicNs",
				"custody",
				"claim",
			],
			"$",
			issues,
		);
		if (record.schemaVersion !== AUTOMATIC_COLLAPSE_EVIDENCE_SCHEMA_VERSION)
			issues.add("$.schemaVersion: unsupported schema version");
		boundedId(record.evidenceId, "$.evidenceId", issues);
		validateProcessAnchor(record.processAnchor, "$.processAnchor", issues);
		validateRoleAssignment(record.roleAssignment, "$.roleAssignment", issues);
		validateSpawnOccurrence(record.spawnOccurrence, "$.spawnOccurrence", issues);
		validateSource(record.source, "$.source", issues);
		validateAgentProfile(record.agentProfile, "$.agentProfile", issues);
		decimalString(record.observedAtMonotonicNs, false, "$.observedAtMonotonicNs", issues);
		exactMember(record.custody, EVIDENCE_CUSTODY_MEMBERS, "$.custody", issues);
		const expectedProvider = validateClaim(record.claim, "$.claim", issues);

		const anchor = asRecord(record.processAnchor, "$.processAnchor", issues);
		const role = asRecord(record.roleAssignment, "$.roleAssignment", issues);
		const spawn = asRecord(record.spawnOccurrence, "$.spawnOccurrence", issues);
		const source = asRecord(record.source, "$.source", issues);
		if (anchor && role && role.processAnchorId !== anchor.processAnchorId)
			issues.add("$.roleAssignment.processAnchorId: process anchor mismatch");
		if (anchor && spawn && spawn.childProcessAnchorId !== anchor.processAnchorId)
			issues.add("$.spawnOccurrence.childProcessAnchorId: process anchor mismatch");
		if (spawn && spawn.parentProcessAnchorId === spawn.childProcessAnchorId)
			issues.add("$.spawnOccurrence: parent and child anchors must differ");
		if (source && expectedProvider && source.provider !== expectedProvider)
			issues.add("$.source.provider: claim/provider mismatch");

		if (issues.values.length > 0) return validationFailure(issues.values);
		return Object.freeze({ ok: true, value: record as unknown as AutomaticCollapseEvidenceEnvelope });
	} catch {
		return validationFailure(["$: validation failed safely"]);
	}
}

function dispositionFromRawWait(rawWaitWord: unknown): TerminalDisposition | undefined {
	const decoded = decodeLinuxWaitWord(rawWaitWord);
	if (decoded.kind === "exited") return { kind: "exited", exitCode: decoded.exitCode };
	if (decoded.kind === "signaled") {
		return {
			kind: "signaled",
			signalNumber: decoded.signalNumber,
			signalName: decoded.signalName,
			coreDumped: decoded.coreDumped,
		};
	}
	return undefined;
}

function terminalFromKernel(evidence: AutomaticCollapseEvidenceEnvelope | undefined): TerminalDisposition | undefined {
	if (!evidence || evidence.claim.kind !== "kernel_exit" || evidence.claim.groupDead !== true) return undefined;
	return dispositionFromRawWait(evidence.claim.rawWaitWord);
}

function terminalFromParent(evidence: AutomaticCollapseEvidenceEnvelope | undefined): TerminalDisposition | undefined {
	if (!evidence || evidence.claim.kind !== "parent_wait") return undefined;
	if (evidence.claim.observation === "linux_wait_word") return dispositionFromRawWait(evidence.claim.rawWaitWord);
	const normalized = normalizeNodeExitCallback(evidence.claim.code, evidence.claim.signal);
	if (normalized.kind === "exited") return { kind: "exited", exitCode: normalized.exitCode };
	if (normalized.kind === "signaled") {
		return {
			kind: "signaled",
			signalNumber: normalized.signalNumber,
			signalName: normalized.signalName,
			coreDumped: normalized.coreDumped,
		};
	}
	return undefined;
}

function sameProcessAnchor(left: ProcessAnchor, right: ProcessAnchor): boolean {
	return (
		left.processAnchorId === right.processAnchorId &&
		left.installationRun.installationId === right.installationRun.installationId &&
		left.installationRun.runId === right.installationRun.runId &&
		left.linuxProcessKey.linuxBootId === right.linuxProcessKey.linuxBootId &&
		left.linuxProcessKey.pidNamespaceInode === right.linuxProcessKey.pidNamespaceInode &&
		left.linuxProcessKey.distroPid === right.linuxProcessKey.distroPid &&
		left.linuxProcessKey.procStartTicks === right.linuxProcessKey.procStartTicks &&
		left.kernelTaskKey.linuxBootId === right.kernelTaskKey.linuxBootId &&
		left.kernelTaskKey.initialTgid === right.kernelTaskKey.initialTgid &&
		left.kernelTaskKey.taskStartBootNs === right.kernelTaskKey.taskStartBootNs
	);
}

function sameRoleAssignment(left: RoleAssignment, right: RoleAssignment): boolean {
	return (
		left.assignmentId === right.assignmentId &&
		left.role === right.role &&
		left.processAnchorId === right.processAnchorId &&
		left.expectedExecutableId === right.expectedExecutableId &&
		left.expectedBuildId === right.expectedBuildId
	);
}

function sameSpawnOccurrence(left: SpawnOccurrence, right: SpawnOccurrence): boolean {
	return (
		left.occurrenceId === right.occurrenceId &&
		left.ordinal === right.ordinal &&
		left.parentProcessAnchorId === right.parentProcessAnchorId &&
		left.childProcessAnchorId === right.childProcessAnchorId
	);
}

function sameEvidenceIdentity(
	left: AutomaticCollapseEvidenceEnvelope,
	right: AutomaticCollapseEvidenceEnvelope,
): boolean {
	return (
		sameProcessAnchor(left.processAnchor, right.processAnchor) &&
		sameRoleAssignment(left.roleAssignment, right.roleAssignment) &&
		sameSpawnOccurrence(left.spawnOccurrence, right.spawnOccurrence)
	);
}

function sameDisposition(left: TerminalDisposition, right: TerminalDisposition): boolean {
	if (left.kind !== right.kind) return false;
	if (left.kind === "exited" && right.kind === "exited") return left.exitCode === right.exitCode;
	if (left.kind !== "signaled" || right.kind !== "signaled") return false;
	if (left.signalNumber !== right.signalNumber || left.signalName !== right.signalName) return false;
	return left.coreDumped === "unknown" || right.coreDumped === "unknown" || left.coreDumped === right.coreDumped;
}

export type TerminalEvidenceSlot = "kernel" | "parent" | "application";

export interface InvalidTerminalEvidence {
	readonly slot: TerminalEvidenceSlot;
	readonly errors: readonly string[];
}

export type TerminalCorrelation =
	| { readonly kind: "no_terminal_claim" }
	| {
			readonly kind: "invalid_evidence";
			readonly invalid: readonly InvalidTerminalEvidence[];
	  }
	| {
			readonly kind: "kernel_only";
			readonly disposition: TerminalDisposition;
			readonly kernel: AutomaticCollapseEvidenceEnvelope;
			readonly gap: { readonly kind: "authoritative_parent_wait_missing" };
	  }
	| {
			readonly kind: "parent_only";
			readonly disposition: TerminalDisposition;
			readonly parent: AutomaticCollapseEvidenceEnvelope;
			readonly gap: { readonly kind: "kernel_provider_missing" };
	  }
	| {
			readonly kind: "matching_parent_kernel_dual";
			readonly disposition: TerminalDisposition;
			readonly kernel: AutomaticCollapseEvidenceEnvelope;
			readonly parent: AutomaticCollapseEvidenceEnvelope;
	  }
	| {
			readonly kind: "conflict";
			readonly reason: "identity_mismatch" | "terminal_disposition_mismatch";
			readonly kernelDisposition: TerminalDisposition;
			readonly parentDisposition: TerminalDisposition;
			readonly kernel: AutomaticCollapseEvidenceEnvelope;
			readonly parent: AutomaticCollapseEvidenceEnvelope;
	  };

export interface TerminalCorrelationInput {
	readonly kernel?: unknown;
	readonly parent?: unknown;
	readonly application?: unknown;
}

function freezeOutput<T>(value: T): T {
	if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
	for (const key of Reflect.ownKeys(value)) {
		const descriptor = Object.getOwnPropertyDescriptor(value, key);
		if (descriptor && Object.hasOwn(descriptor, "value")) freezeOutput(descriptor.value);
	}
	return Object.freeze(value);
}

function validateCorrelationSlot(
	slot: TerminalEvidenceSlot,
	supplied: unknown,
	expectedKind: AutomaticCollapseEvidenceClaim["kind"],
): { readonly value?: AutomaticCollapseEvidenceEnvelope; readonly invalid?: InvalidTerminalEvidence } {
	if (supplied === undefined) return {};
	const validated = validateAutomaticCollapseEvidence(supplied);
	if (!validated.ok) {
		return {
			invalid: Object.freeze({ slot, errors: Object.freeze([...validated.errors]) }),
		};
	}
	if (validated.value.claim.kind !== expectedKind) {
		return {
			invalid: Object.freeze({
				slot,
				errors: Object.freeze([`$.claim.kind: ${slot} slot requires ${expectedKind}`]),
			}),
		};
	}
	return { value: validated.value };
}

export function correlateTerminalEvidence(input: TerminalCorrelationInput): TerminalCorrelation {
	// Read each caller-owned slot once. All later work uses detached validation snapshots.
	const suppliedKernel = input.kernel;
	const suppliedParent = input.parent;
	const suppliedApplication = input.application;
	const kernelResult = validateCorrelationSlot("kernel", suppliedKernel, "kernel_exit");
	const parentResult = validateCorrelationSlot("parent", suppliedParent, "parent_wait");
	const applicationResult = validateCorrelationSlot("application", suppliedApplication, "application_transition");
	const invalid = [kernelResult.invalid, parentResult.invalid, applicationResult.invalid].filter(
		(value): value is InvalidTerminalEvidence => value !== undefined,
	);
	if (invalid.length > 0) return freezeOutput({ kind: "invalid_evidence", invalid });

	const kernel = kernelResult.value;
	const parent = parentResult.value;
	const kernelDisposition = terminalFromKernel(kernel);
	const parentDisposition = terminalFromParent(parent);
	if (!kernelDisposition && !parentDisposition) return freezeOutput({ kind: "no_terminal_claim" });
	if (kernelDisposition && !parentDisposition) {
		return freezeOutput({
			kind: "kernel_only",
			disposition: kernelDisposition,
			kernel: kernel!,
			gap: { kind: "authoritative_parent_wait_missing" },
		});
	}
	if (!kernelDisposition && parentDisposition) {
		return freezeOutput({
			kind: "parent_only",
			disposition: parentDisposition,
			parent: parent!,
			gap: { kind: "kernel_provider_missing" },
		});
	}
	if (!sameEvidenceIdentity(kernel!, parent!)) {
		return freezeOutput({
			kind: "conflict",
			reason: "identity_mismatch",
			kernelDisposition: kernelDisposition!,
			parentDisposition: parentDisposition!,
			kernel: kernel!,
			parent: parent!,
		});
	}
	if (!sameDisposition(kernelDisposition!, parentDisposition!)) {
		return freezeOutput({
			kind: "conflict",
			reason: "terminal_disposition_mismatch",
			kernelDisposition: kernelDisposition!,
			parentDisposition: parentDisposition!,
			kernel: kernel!,
			parent: parent!,
		});
	}
	return freezeOutput({
		kind: "matching_parent_kernel_dual",
		disposition: kernelDisposition!,
		kernel: kernel!,
		parent: parent!,
	});
}

/**
 * Checks structural pipeline adjacency only. Custody stages are non-authoritative
 * labels. Windows survival requires the later validated Windows-anchor receipt
 * and commit authority; no stage string in this slice proves survival.
 */
export function advanceEvidenceCustody(from: EvidenceCustodyState, to: EvidenceCustodyState): boolean {
	if (!Object.hasOwn(EVIDENCE_CUSTODY_INDEX, from) || !Object.hasOwn(EVIDENCE_CUSTODY_INDEX, to)) return false;
	return EVIDENCE_CUSTODY_INDEX[to] === EVIDENCE_CUSTODY_INDEX[from] + 1;
}
