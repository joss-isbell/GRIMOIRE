export const AUTOMATIC_COLLAPSE_EVIDENCE_SCHEMA_VERSION = 1 as const;

export const AUTOMATIC_COLLAPSE_ROLES = [
	"recorder_wrapper",
	"supervisor",
	"worker",
	"forkserver",
	"direct_kernel",
	"forked_kernel",
] as const;
export type AutomaticCollapseRole = (typeof AUTOMATIC_COLLAPSE_ROLES)[number];

export const EVIDENCE_PROVIDERS = ["application_transition", "linux_kernel", "authoritative_parent"] as const;
export type EvidenceProvider = (typeof EVIDENCE_PROVIDERS)[number];

export const APPLICATION_STATES = ["starting", "running", "stopping", "stopped"] as const;
export type ApplicationState = (typeof APPLICATION_STATES)[number];

export const EVIDENCE_CUSTODY_STATES = [
	"kernel_produced",
	"linux_received",
	"host_published",
	"windows_committed",
] as const;
export type EvidenceCustodyState = (typeof EVIDENCE_CUSTODY_STATES)[number];

export const LINUX_SIGNAL_NAMES = [
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
] as const;
export type LinuxSignalName = (typeof LINUX_SIGNAL_NAMES)[number];

const SIGNAL_NAME_BY_NUMBER = new Map<number, LinuxSignalName>(
	LINUX_SIGNAL_NAMES.map((name, index) => [index + 1, name]),
);
const SIGNAL_NUMBER_BY_NAME = new Map<LinuxSignalName, number>(
	LINUX_SIGNAL_NAMES.map((name, index) => [name, index + 1]),
);

export interface InstallationRunIdentity {
	installationId: string;
	runId: string;
}

export interface LinuxProcessKey {
	linuxBootId: string;
	pidNamespaceInode: string;
	distroPid: number;
	procStartTicks: string;
}

export interface KernelTaskKey {
	linuxBootId: string;
	initialTgid: number;
	taskStartBootNs: string;
}

export interface ProcessAnchor {
	processAnchorId: string;
	installationRun: InstallationRunIdentity;
	linuxProcessKey: LinuxProcessKey;
	kernelTaskKey: KernelTaskKey;
}

export interface RoleAssignment {
	assignmentId: string;
	role: AutomaticCollapseRole;
	processAnchorId: string;
	expectedExecutableId: string;
	expectedBuildId: string;
}

export interface SpawnOccurrence {
	occurrenceId: string;
	ordinal: number;
	parentProcessAnchorId: string;
	childProcessAnchorId: string;
}

export interface EvidenceSourcePosition {
	provider: EvidenceProvider;
	epoch: string;
	strictSequence: number;
}

export interface AgentProfileProvenance {
	agentId: string;
	profileVersion: string;
}

export type ApplicationTransitionClaim =
	| {
			kind: "application_transition";
			observation: "state_transition";
			from: ApplicationState;
			to: ApplicationState;
	  }
	| {
			kind: "application_transition";
			observation: "signal_requested";
			requestedSignal: LinuxSignalName;
	  }
	| {
			kind: "application_transition";
			observation: "silence_observed";
			silenceMs: number;
	  };

export interface KernelExitClaim {
	kind: "kernel_exit";
	groupDead: true;
	rawWaitWord: number;
}

export type AuthoritativeParentWaitClaim =
	| {
			kind: "parent_wait";
			observation: "linux_wait_word";
			rawWaitWord: number;
	  }
	| {
			kind: "parent_wait";
			observation: "node_callback";
			code: number;
			signal: null;
	  }
	| {
			kind: "parent_wait";
			observation: "node_callback";
			code: null;
			signal: LinuxSignalName;
	  };

export type AutomaticCollapseEvidenceClaim =
	| ApplicationTransitionClaim
	| KernelExitClaim
	| AuthoritativeParentWaitClaim;

export interface AutomaticCollapseEvidenceEnvelope {
	schemaVersion: typeof AUTOMATIC_COLLAPSE_EVIDENCE_SCHEMA_VERSION;
	evidenceId: string;
	processAnchor: ProcessAnchor;
	roleAssignment: RoleAssignment;
	spawnOccurrence: SpawnOccurrence;
	source: EvidenceSourcePosition;
	agentProfile: AgentProfileProvenance;
	observedAtMonotonicNs: string;
	custody: EvidenceCustodyState;
	claim: AutomaticCollapseEvidenceClaim;
}

export type LinuxWaitDecode =
	| { kind: "exited"; rawWaitWord: number; exitCode: number }
	| {
			kind: "signaled";
			rawWaitWord: number;
			signalNumber: number;
			signalName: LinuxSignalName;
			coreDumped: boolean;
	  }
	| {
			kind: "stopped";
			rawWaitWord: number;
			stopSignalNumber: number;
			stopSignalName: LinuxSignalName;
	  }
	| { kind: "continued"; rawWaitWord: number }
	| {
			kind: "invalid";
			reason:
				| "raw_wait_word_not_integer"
				| "raw_wait_word_out_of_range"
				| "invalid_signal_number"
				| "invalid_stop_signal_number";
	  };

export type NodeExitCallbackNormalization =
	| { kind: "exited"; exitCode: number; source: "node_callback" }
	| {
			kind: "signaled";
			signalNumber: number;
			signalName: LinuxSignalName;
			coreDumped: "unknown";
			source: "node_callback";
	  }
	| {
			kind: "invalid";
			reason: "ambiguous_pair" | "missing_code_and_signal" | "invalid_exit_code" | "invalid_signal_name";
	  };

export type TerminalDisposition =
	| { kind: "exited"; exitCode: number }
	| {
			kind: "signaled";
			signalNumber: number;
			signalName: LinuxSignalName;
			coreDumped: boolean | "unknown";
	  };

export function decodeLinuxWaitWord(rawWaitWord: unknown): LinuxWaitDecode {
	if (typeof rawWaitWord !== "number" || !Number.isInteger(rawWaitWord))
		return { kind: "invalid", reason: "raw_wait_word_not_integer" };
	if (rawWaitWord < 0 || rawWaitWord > 0xffff) return { kind: "invalid", reason: "raw_wait_word_out_of_range" };
	if (rawWaitWord === 0xffff) return { kind: "continued", rawWaitWord };

	const lowSevenBits = rawWaitWord & 0x7f;
	if (lowSevenBits === 0) return { kind: "exited", rawWaitWord, exitCode: (rawWaitWord >>> 8) & 0xff };
	if (lowSevenBits === 0x7f) {
		const stopSignalNumber = (rawWaitWord >>> 8) & 0xff;
		const stopSignalName = SIGNAL_NAME_BY_NUMBER.get(stopSignalNumber);
		if (!stopSignalName) return { kind: "invalid", reason: "invalid_stop_signal_number" };
		return { kind: "stopped", rawWaitWord, stopSignalNumber, stopSignalName };
	}
	const signalName = SIGNAL_NAME_BY_NUMBER.get(lowSevenBits);
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
	if (typeof signal !== "string" || !SIGNAL_NUMBER_BY_NAME.has(signal as LinuxSignalName))
		return { kind: "invalid", reason: "invalid_signal_name" };
	const signalName = signal as LinuxSignalName;
	return {
		kind: "signaled",
		signalNumber: SIGNAL_NUMBER_BY_NAME.get(signalName)!,
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
const FORBIDDEN_PRIVACY_KEY_FRAGMENTS = [
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
] as const;

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

function inspectObjectGraph(value: unknown, issues: ValidationIssues): void {
	const seen = new WeakSet<object>();
	let nodes = 0;

	function visit(current: unknown, path: string, depth: number): void {
		if (current === null || typeof current !== "object" || issues.values.length >= MAX_VALIDATION_ERRORS) return;
		if (depth > MAX_VALIDATION_DEPTH) {
			issues.add(`${path}: validation depth exceeded`);
			return;
		}
		if (seen.has(current)) {
			issues.add(`${path}: cyclic value rejected`);
			return;
		}
		seen.add(current);
		nodes += 1;
		if (nodes > MAX_VALIDATION_NODES) {
			issues.add(`${path}: validation node bound exceeded`);
			return;
		}
		const descriptors = Object.getOwnPropertyDescriptors(current);
		for (const [key, descriptor] of Object.entries(descriptors)) {
			if (hasForbiddenPrivacyTerm(key)) issues.add(`${path}.${key}: forbidden privacy field`);
			if (!Object.hasOwn(descriptor, "value")) {
				issues.add(`${path}.${key}: accessor properties rejected`);
				continue;
			}
			visit(descriptor.value, `${path}.${key}`, depth + 1);
		}
	}

	visit(value, "$", 0);
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
	for (const key of Object.keys(record)) if (!allowed.has(key)) issues.add(`${path}.${key}: extra field rejected`);
}

function boundedId(value: unknown, path: string, issues: ValidationIssues): value is string {
	if (typeof value !== "string" || !ID_PATTERN.test(value)) {
		issues.add(`${path}: invalid bounded identifier`);
		return false;
	}
	return true;
}

function exactMember<const T extends readonly string[]>(
	value: unknown,
	allowlist: T,
	path: string,
	issues: ValidationIssues,
): value is T[number] {
	if (typeof value !== "string" || !allowlist.includes(value)) {
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
	exactMember(record.role, AUTOMATIC_COLLAPSE_ROLES, `${path}.role`, issues);
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
	exactMember(record.provider, EVIDENCE_PROVIDERS, `${path}.provider`, issues);
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
		exactMember(record.from, APPLICATION_STATES, `${path}.from`, issues);
		exactMember(record.to, APPLICATION_STATES, `${path}.to`, issues);
		return;
	}
	if (record.observation === "signal_requested") {
		exactKeys(record, ["kind", "observation", "requestedSignal"], path, issues);
		exactMember(record.requestedSignal, LINUX_SIGNAL_NAMES, `${path}.requestedSignal`, issues);
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
	| { ok: true; value: AutomaticCollapseEvidenceEnvelope }
	| { ok: false; errors: readonly string[] };

export function validateAutomaticCollapseEvidence(value: unknown): AutomaticCollapseEvidenceValidation {
	const issues = new ValidationIssues();
	try {
		inspectObjectGraph(value, issues);
		if (issues.values.length > 0) return { ok: false, errors: issues.values };
		const record = asRecord(value, "$", issues);
		if (!record) return { ok: false, errors: issues.values };
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
		exactMember(record.custody, EVIDENCE_CUSTODY_STATES, "$.custody", issues);
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

		if (issues.values.length > 0) return { ok: false, errors: issues.values };
		return { ok: true, value: record as unknown as AutomaticCollapseEvidenceEnvelope };
	} catch {
		return { ok: false, errors: ["$: validation failed safely"] };
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
	if (!evidence || !validateAutomaticCollapseEvidence(evidence).ok) return undefined;
	if (evidence.claim.kind !== "kernel_exit" || evidence.claim.groupDead !== true) return undefined;
	return dispositionFromRawWait(evidence.claim.rawWaitWord);
}

function terminalFromParent(evidence: AutomaticCollapseEvidenceEnvelope | undefined): TerminalDisposition | undefined {
	if (!evidence || !validateAutomaticCollapseEvidence(evidence).ok) return undefined;
	if (evidence.claim.kind !== "parent_wait") return undefined;
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

export type TerminalCorrelation =
	| { kind: "no_terminal_claim" }
	| {
			kind: "kernel_only";
			disposition: TerminalDisposition;
			kernel: AutomaticCollapseEvidenceEnvelope;
			gap: { kind: "authoritative_parent_wait_missing" };
	  }
	| {
			kind: "parent_only";
			disposition: TerminalDisposition;
			parent: AutomaticCollapseEvidenceEnvelope;
			gap: { kind: "kernel_provider_missing" };
	  }
	| {
			kind: "matching_parent_kernel_dual";
			disposition: TerminalDisposition;
			kernel: AutomaticCollapseEvidenceEnvelope;
			parent: AutomaticCollapseEvidenceEnvelope;
	  }
	| {
			kind: "conflict";
			reason: "identity_mismatch" | "terminal_disposition_mismatch";
			kernelDisposition: TerminalDisposition;
			parentDisposition: TerminalDisposition;
			kernel: AutomaticCollapseEvidenceEnvelope;
			parent: AutomaticCollapseEvidenceEnvelope;
	  };

export interface TerminalCorrelationInput {
	kernel?: AutomaticCollapseEvidenceEnvelope;
	parent?: AutomaticCollapseEvidenceEnvelope;
	application?: AutomaticCollapseEvidenceEnvelope;
}

export function correlateTerminalEvidence(input: TerminalCorrelationInput): TerminalCorrelation {
	const kernelDisposition = terminalFromKernel(input.kernel);
	const parentDisposition = terminalFromParent(input.parent);
	if (!kernelDisposition && !parentDisposition) return { kind: "no_terminal_claim" };
	if (kernelDisposition && !parentDisposition) {
		return {
			kind: "kernel_only",
			disposition: kernelDisposition,
			kernel: input.kernel!,
			gap: { kind: "authoritative_parent_wait_missing" },
		};
	}
	if (!kernelDisposition && parentDisposition) {
		return {
			kind: "parent_only",
			disposition: parentDisposition,
			parent: input.parent!,
			gap: { kind: "kernel_provider_missing" },
		};
	}
	const kernel = input.kernel!;
	const parent = input.parent!;
	if (!sameEvidenceIdentity(kernel, parent)) {
		return {
			kind: "conflict",
			reason: "identity_mismatch",
			kernelDisposition: kernelDisposition!,
			parentDisposition: parentDisposition!,
			kernel,
			parent,
		};
	}
	if (!sameDisposition(kernelDisposition!, parentDisposition!)) {
		return {
			kind: "conflict",
			reason: "terminal_disposition_mismatch",
			kernelDisposition: kernelDisposition!,
			parentDisposition: parentDisposition!,
			kernel,
			parent,
		};
	}
	return {
		kind: "matching_parent_kernel_dual",
		disposition: kernelDisposition!,
		kernel,
		parent,
	};
}

export function advanceEvidenceCustody(from: EvidenceCustodyState, to: EvidenceCustodyState): boolean {
	const fromIndex = EVIDENCE_CUSTODY_STATES.indexOf(from);
	return fromIndex >= 0 && EVIDENCE_CUSTODY_STATES.indexOf(to) === fromIndex + 1;
}

export function windowsSurvivingCustody(state: EvidenceCustodyState): boolean {
	return state === "windows_committed";
}
