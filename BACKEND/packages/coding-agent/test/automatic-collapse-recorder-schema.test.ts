import { describe, expect, it } from "vitest";
import * as recorderSchema from "../src/modes/daemon/automatic-collapse-recorder-schema.js";
import {
	APPLICATION_STATES,
	AUTOMATIC_COLLAPSE_EVIDENCE_SCHEMA_VERSION,
	AUTOMATIC_COLLAPSE_ROLES,
	type AutomaticCollapseEvidenceEnvelope,
	advanceEvidenceCustody,
	correlateTerminalEvidence,
	decodeLinuxWaitWord,
	EVIDENCE_CUSTODY_STATES,
	EVIDENCE_PROVIDERS,
	LINUX_SIGNAL_NAMES,
	NODE_CALLBACK_SIGNAL_NAMES,
	normalizeNodeExitCallback,
	validateAutomaticCollapseEvidence,
} from "../src/modes/daemon/automatic-collapse-recorder-schema.js";

type DeepMutable<T> = { -readonly [Key in keyof T]: DeepMutable<T[Key]> };
type MutableEvidenceEnvelope = DeepMutable<AutomaticCollapseEvidenceEnvelope>;

function envelope(
	claim: AutomaticCollapseEvidenceEnvelope["claim"],
	overrides: Partial<AutomaticCollapseEvidenceEnvelope> = {},
): MutableEvidenceEnvelope {
	const provider =
		claim.kind === "kernel_exit"
			? "linux_kernel"
			: claim.kind === "parent_wait"
				? "authoritative_parent"
				: "application_transition";
	return {
		schemaVersion: AUTOMATIC_COLLAPSE_EVIDENCE_SCHEMA_VERSION,
		evidenceId: "evidence-1",
		processAnchor: {
			processAnchorId: "anchor-child-1",
			installationRun: { installationId: "install-1", runId: "run-1" },
			linuxProcessKey: {
				linuxBootId: "11111111-2222-3333-4444-555555555555",
				pidNamespaceInode: "4026533001",
				distroPid: 321,
				procStartTicks: "987654321",
			},
			kernelTaskKey: {
				linuxBootId: "11111111-2222-3333-4444-555555555555",
				initialTgid: 321,
				taskStartBootNs: "1234567890123",
			},
		},
		roleAssignment: {
			assignmentId: "assignment-1",
			role: "worker",
			processAnchorId: "anchor-child-1",
			expectedExecutableId: "executable-prime-agent",
			expectedBuildId: "build-b0741dca",
		},
		spawnOccurrence: {
			occurrenceId: "spawn-1",
			ordinal: 7,
			parentProcessAnchorId: "anchor-parent-1",
			childProcessAnchorId: "anchor-child-1",
		},
		source: { provider, epoch: "epoch-1", strictSequence: 1 },
		agentProfile: { agentId: "agent-1", profileVersion: "profile-v3.2.1" },
		observedAtMonotonicNs: "123456789012345",
		custody: "kernel_produced",
		claim,
		...overrides,
	} as MutableEvidenceEnvelope;
}

const kernel = () => envelope({ kind: "kernel_exit", groupDead: true, rawWaitWord: 5888 });
const parentRaw = () =>
	envelope(
		{ kind: "parent_wait", observation: "linux_wait_word", rawWaitWord: 5888 },
		{
			evidenceId: "evidence-parent-1",
			source: { provider: "authoritative_parent", epoch: "parent-epoch-1", strictSequence: 9 },
		},
	);

function expectInvalid(value: unknown): void {
	const result = validateAutomaticCollapseEvidence(value);
	expect(result.ok).toBe(false);
}

describe("exact Linux wait decoding", () => {
	it("decodes exit, signal, core, stop, continue, and invalid words", () => {
		expect(decodeLinuxWaitWord(5888)).toEqual({
			kind: "exited",
			rawWaitWord: 5888,
			exitCode: 23,
		});
		expect(decodeLinuxWaitWord(10)).toEqual({
			kind: "signaled",
			rawWaitWord: 10,
			signalNumber: 10,
			signalName: "SIGUSR1",
			coreDumped: false,
		});
		expect(decodeLinuxWaitWord(10 | 0x80)).toMatchObject({
			kind: "signaled",
			signalNumber: 10,
			coreDumped: true,
		});
		expect(decodeLinuxWaitWord((19 << 8) | 0x7f)).toEqual({
			kind: "stopped",
			rawWaitWord: 4991,
			stopSignalNumber: 19,
			stopSignalName: "SIGSTOP",
		});
		expect(decodeLinuxWaitWord(0xffff)).toEqual({ kind: "continued", rawWaitWord: 0xffff });
		expect(decodeLinuxWaitWord(-1)).toEqual({ kind: "invalid", reason: "raw_wait_word_out_of_range" });
		expect(decodeLinuxWaitWord(1.5)).toEqual({ kind: "invalid", reason: "raw_wait_word_not_integer" });
		expect(decodeLinuxWaitWord(65)).toEqual({ kind: "invalid", reason: "invalid_signal_number" });
	});
});

describe("Node callback normalization", () => {
	it("normalizes valid code or signal without creating a raw wait word", () => {
		expect(normalizeNodeExitCallback(23, null)).toEqual({
			kind: "exited",
			exitCode: 23,
			source: "node_callback",
		});
		expect(normalizeNodeExitCallback(null, "SIGUSR1")).toEqual({
			kind: "signaled",
			signalNumber: 10,
			signalName: "SIGUSR1",
			coreDumped: "unknown",
			source: "node_callback",
		});
		expect(normalizeNodeExitCallback(null, "SIGUSR1")).not.toHaveProperty("rawWaitWord");
	});

	it("rejects ambiguous, absent, and malformed callback pairs", () => {
		expect(normalizeNodeExitCallback(0, "SIGTERM")).toEqual({ kind: "invalid", reason: "ambiguous_pair" });
		expect(normalizeNodeExitCallback(null, null)).toEqual({ kind: "invalid", reason: "missing_code_and_signal" });
		expect(normalizeNodeExitCallback(256, null)).toEqual({ kind: "invalid", reason: "invalid_exit_code" });
		expect(normalizeNodeExitCallback(null, "SIG_NOT_REAL")).toEqual({
			kind: "invalid",
			reason: "invalid_signal_name",
		});
	});
});

describe("deterministic terminal correlation", () => {
	it("returns a matching parent+kernel dual", () => {
		expect(correlateTerminalEvidence({ kernel: kernel(), parent: parentRaw() })).toMatchObject({
			kind: "matching_parent_kernel_dual",
			disposition: { kind: "exited", exitCode: 23 },
		});
	});

	it("returns typed gaps for either one-sided outcome and none for neither", () => {
		expect(correlateTerminalEvidence({ kernel: kernel() })).toMatchObject({
			kind: "kernel_only",
			gap: { kind: "authoritative_parent_wait_missing" },
		});
		expect(correlateTerminalEvidence({ parent: parentRaw() })).toMatchObject({
			kind: "parent_only",
			gap: { kind: "kernel_provider_missing" },
		});
		expect(correlateTerminalEvidence({})).toEqual({ kind: "no_terminal_claim" });
	});

	it("retains both sides for status conflict and identity mismatch", () => {
		const differentStatus = parentRaw();
		differentStatus.claim = { kind: "parent_wait", observation: "node_callback", code: null, signal: "SIGTERM" };
		const conflict = correlateTerminalEvidence({ kernel: kernel(), parent: differentStatus });
		expect(conflict).toMatchObject({ kind: "conflict", reason: "terminal_disposition_mismatch" });
		if (conflict.kind !== "conflict") throw new Error("expected conflict");
		expect(conflict.kernel.claim.kind).toBe("kernel_exit");
		expect(conflict.parent.claim.kind).toBe("parent_wait");

		const differentIdentity = parentRaw();
		differentIdentity.processAnchor = {
			...differentIdentity.processAnchor,
			linuxProcessKey: {
				...differentIdentity.processAnchor.linuxProcessKey,
				procStartTicks: "987654322",
			},
		};
		expect(correlateTerminalEvidence({ kernel: kernel(), parent: differentIdentity })).toMatchObject({
			kind: "conflict",
			reason: "identity_mismatch",
		});

		const differentRoleAssignment = parentRaw();
		differentRoleAssignment.roleAssignment = {
			...differentRoleAssignment.roleAssignment,
			expectedBuildId: "build-other",
		};
		expect(correlateTerminalEvidence({ kernel: kernel(), parent: differentRoleAssignment })).toMatchObject({
			kind: "conflict",
			reason: "identity_mismatch",
		});

		const differentExecutable = parentRaw();
		differentExecutable.roleAssignment = {
			...differentExecutable.roleAssignment,
			expectedExecutableId: "executable-other",
		};
		expect(correlateTerminalEvidence({ kernel: kernel(), parent: differentExecutable })).toMatchObject({
			kind: "conflict",
			reason: "identity_mismatch",
		});

		const differentSpawnOccurrence = parentRaw();
		differentSpawnOccurrence.spawnOccurrence = {
			...differentSpawnOccurrence.spawnOccurrence,
			ordinal: 8,
		};
		expect(correlateTerminalEvidence({ kernel: kernel(), parent: differentSpawnOccurrence })).toMatchObject({
			kind: "conflict",
			reason: "identity_mismatch",
		});
	});

	it("never promotes transitions, requested signals, silence, or nonterminal waits", () => {
		const transition = envelope({
			kind: "application_transition",
			observation: "state_transition",
			from: "running",
			to: "stopped",
		});
		const requested = envelope({
			kind: "application_transition",
			observation: "signal_requested",
			requestedSignal: "SIGKILL",
		});
		const silence = envelope({
			kind: "application_transition",
			observation: "silence_observed",
			silenceMs: 10_000,
		});
		const stoppedKernel = envelope({ kind: "kernel_exit", groupDead: true, rawWaitWord: (19 << 8) | 0x7f });
		for (const application of [transition, requested, silence])
			expect(correlateTerminalEvidence({ application })).toEqual({ kind: "no_terminal_claim" });
		expect(correlateTerminalEvidence({ kernel: stoppedKernel })).toMatchObject({
			kind: "invalid_evidence",
			invalid: [{ slot: "kernel" }],
		});
	});
});

describe("strict evidence schema and privacy boundary", () => {
	it("accepts the bounded versioned envelope and requires Agent-profile provenance", () => {
		const valid = kernel();
		expect(validateAutomaticCollapseEvidence(valid)).toEqual({ ok: true, value: valid });
		const wrapper = structuredClone(valid);
		wrapper.roleAssignment.role = "recorder_wrapper";
		expect(validateAutomaticCollapseEvidence(wrapper)).toEqual({ ok: true, value: wrapper });
		const missingProfile = { ...valid } as Record<string, unknown>;
		delete missingProfile.agentProfile;
		expectInvalid(missingProfile);
		expectInvalid({ ...valid, agentProfile: { agentId: "agent-1", profileVersion: "" } });
	});

	it("requires source epoch and a bounded safe strict sequence", () => {
		const valid = kernel();
		expectInvalid({ ...valid, source: { provider: "linux_kernel", strictSequence: 1 } });
		expectInvalid({ ...valid, source: { provider: "linux_kernel", epoch: "epoch-1", strictSequence: 1.5 } });
		expectInvalid({
			...valid,
			source: { provider: "linux_kernel", epoch: "epoch-1", strictSequence: Number.MAX_SAFE_INTEGER + 1 },
		});
	});

	it("requires group-dead kernel proof and never promotes a thread-only exit", () => {
		const valid = kernel();
		const missing = { ...valid, claim: { kind: "kernel_exit", rawWaitWord: 5888 } };
		const threadOnly = { ...valid, claim: { kind: "kernel_exit", groupDead: false, rawWaitWord: 5888 } };
		expectInvalid(missing);
		expectInvalid(threadOnly);
		expect(correlateTerminalEvidence({ kernel: threadOnly })).toMatchObject({
			kind: "invalid_evidence",
			invalid: [{ slot: "kernel" }],
		});
	});

	it("requires the full Linux process and kernel task keys with one matching boot identity", () => {
		const valid = kernel();
		const missingNamespace = structuredClone(valid);
		delete (
			missingNamespace.processAnchor.linuxProcessKey as Partial<
				typeof missingNamespace.processAnchor.linuxProcessKey
			>
		).pidNamespaceInode;
		expectInvalid(missingNamespace);
		const missingStart = structuredClone(valid);
		delete (missingStart.processAnchor.linuxProcessKey as Partial<typeof missingStart.processAnchor.linuxProcessKey>)
			.procStartTicks;
		expectInvalid(missingStart);
		const missingInitialTgid = structuredClone(valid);
		delete (
			missingInitialTgid.processAnchor.kernelTaskKey as Partial<
				typeof missingInitialTgid.processAnchor.kernelTaskKey
			>
		).initialTgid;
		expectInvalid(missingInitialTgid);
		expectInvalid({
			...valid,
			processAnchor: {
				...valid.processAnchor,
				kernelTaskKey: { ...valid.processAnchor.kernelTaskKey, linuxBootId: "different-boot-id" },
			},
		});
		const missingExecutableId = structuredClone(valid);
		delete (missingExecutableId.roleAssignment as Partial<typeof missingExecutableId.roleAssignment>)
			.expectedExecutableId;
		expectInvalid(missingExecutableId);
		const missingBuildId = structuredClone(valid);
		delete (missingBuildId.roleAssignment as Partial<typeof missingBuildId.roleAssignment>).expectedBuildId;
		expectInvalid(missingBuildId);
	});

	it("rejects distro-PID-only, mismatched anchors, unbounded fields, and non-allowlisted values", () => {
		const valid = kernel();
		expectInvalid({
			...valid,
			processAnchor: { processAnchorId: "distro-pid-only", linuxProcessKey: { distroPid: 321 } },
		});
		expectInvalid({
			...valid,
			roleAssignment: { ...valid.roleAssignment, processAnchorId: "another-anchor" },
		});
		expectInvalid({ ...valid, evidenceId: "x".repeat(129) });
		expectInvalid({
			...valid,
			processAnchor: {
				...valid.processAnchor,
				linuxProcessKey: { ...valid.processAnchor.linuxProcessKey, distroPid: 0 },
			},
		});
		expectInvalid({ ...valid, roleAssignment: { ...valid.roleAssignment, role: "unbounded-role" } });
		expectInvalid({ ...valid, source: { ...valid.source, provider: "untrusted-provider" } });
	});

	it("rejects extra fields and forbidden privacy keys recursively", () => {
		const valid = kernel();
		expectInvalid({ ...valid, metadata: {} });
		for (const forbidden of [
			"argv",
			"environment",
			"stdout",
			"stderr",
			"applicationLogs",
			"applicationContent",
			"payload",
			"body",
			"arbitraryMemory",
			"credentials",
			"secrets",
			"tokens",
			"cookies",
			"authorization",
		]) {
			const adversarial = structuredClone(valid) as unknown as Record<string, unknown>;
			(adversarial.claim as Record<string, unknown>).extra = { nested: { [forbidden]: "private" } };
			expectInvalid(adversarial);
		}
	});

	it("rejects mixed claim schemas and provider/claim mismatches", () => {
		const valid = kernel();
		expectInvalid({
			...valid,
			claim: { kind: "kernel_exit", groupDead: true, rawWaitWord: 5888, requestedSignal: "SIGKILL" },
		});
		expectInvalid({ ...valid, source: { ...valid.source, provider: "authoritative_parent" } });
		expectInvalid({ ...valid, claim: { kind: "kernel_exit", groupDead: true, rawWaitWord: (19 << 8) | 0x7f } });
	});
});

describe("custody stages", () => {
	it("keeps adjacency structural and exposes no bare-label Windows survival truth", () => {
		expect(advanceEvidenceCustody("kernel_produced", "linux_received")).toBe(true);
		expect(advanceEvidenceCustody("linux_received", "host_published")).toBe(true);
		expect(advanceEvidenceCustody("host_published", "windows_committed")).toBe(true);
		expect(advanceEvidenceCustody("kernel_produced", "windows_committed")).toBe(false);
		expect("windowsSurvivingCustody" in recorderSchema).toBe(false);
	});
});

describe("T007-A adversarial repair regressions", () => {
	it("captures one detached, deeply frozen descriptor snapshot and never re-reads input", () => {
		const original = kernel();
		let rawReads = 0;
		original.claim = new Proxy(original.claim, {
			get(target, property, receiver) {
				if (property === "rawWaitWord") {
					rawReads += 1;
					return rawReads === 1 ? 5888 : 9;
				}
				return Reflect.get(target, property, receiver);
			},
		});
		const correlation = correlateTerminalEvidence({ kernel: original });
		expect(correlation).toMatchObject({
			kind: "kernel_only",
			disposition: { kind: "exited", exitCode: 23 },
			kernel: { claim: { rawWaitWord: 5888 } },
		});
		expect(rawReads).toBe(0);
		if (correlation.kind !== "kernel_only") throw new Error("expected stable kernel correlation");
		expect(correlation.kernel).not.toBe(original);
		expect(Object.isFrozen(correlation)).toBe(true);
		expect(Object.isFrozen(correlation.kernel)).toBe(true);
		expect(Object.isFrozen(correlation.kernel.processAnchor.linuxProcessKey)).toBe(true);

		const mutable = kernel();
		const validated = validateAutomaticCollapseEvidence(mutable);
		expect(validated.ok).toBe(true);
		if (!validated.ok) throw new Error("expected valid snapshot");
		mutable.claim = { kind: "kernel_exit", groupDead: true, rawWaitWord: 9 };
		mutable.processAnchor.linuxProcessKey.procStartTicks = "999";
		expect(validated.value.claim).toMatchObject({ rawWaitWord: 5888 });
		expect(validated.value.processAnchor.linuxProcessKey.procStartTicks).toBe("987654321");
		expect(validated.value).not.toBe(mutable);
		expect(Object.isFrozen(validated.value)).toBe(true);
		expect(Object.isFrozen(validated.value.claim)).toBe(true);
		expect(() => {
			(validated.value.claim as unknown as { rawWaitWord: number }).rawWaitWord = 1;
		}).toThrow();
		expect(validated.value.claim).toMatchObject({ rawWaitWord: 5888 });
	});

	it("uses frozen exports and private canonical membership and custody ordering", () => {
		for (const list of [
			AUTOMATIC_COLLAPSE_ROLES,
			EVIDENCE_PROVIDERS,
			APPLICATION_STATES,
			EVIDENCE_CUSTODY_STATES,
			LINUX_SIGNAL_NAMES,
			NODE_CALLBACK_SIGNAL_NAMES,
		]) {
			const mutable = list as unknown as string[];
			const before = [...mutable];
			let threw = false;
			try {
				mutable.push("attacker_value");
			} catch {
				threw = true;
			}
			if (mutable.length !== before.length) mutable.splice(0, mutable.length, ...before);
			expect(threw).toBe(true);
			expect(list).toEqual(before);
			expect(Object.isFrozen(list)).toBe(true);
		}

		const roleList = AUTOMATIC_COLLAPSE_ROLES as unknown as string[];
		const rolesBefore = [...roleList];
		let roleAccepted = false;
		try {
			roleList.push("attacker_role");
			const adversarial = kernel() as unknown as { roleAssignment: { role: string } };
			adversarial.roleAssignment.role = "attacker_role";
			roleAccepted = validateAutomaticCollapseEvidence(adversarial).ok;
		} catch {
			// Frozen export is the expected path.
		} finally {
			if (roleList.length !== rolesBefore.length) roleList.splice(0, roleList.length, ...rolesBefore);
		}
		expect(roleAccepted).toBe(false);

		const custodyList = EVIDENCE_CUSTODY_STATES as unknown as string[];
		const custodyBefore = [...custodyList];
		let skipAllowed = false;
		try {
			custodyList.splice(
				0,
				custodyList.length,
				"kernel_produced",
				"windows_committed",
				"linux_received",
				"host_published",
			);
			skipAllowed = advanceEvidenceCustody("kernel_produced", "windows_committed");
		} catch {
			// Frozen export is the expected path.
		} finally {
			if (custodyList.join() !== custodyBefore.join()) custodyList.splice(0, custodyList.length, ...custodyBefore);
		}
		expect(skipAllowed).toBe(false);

		const invalidRole = kernel() as unknown as { roleAssignment: { role: string } };
		invalidRole.roleAssignment.role = "attacker_value";
		expectInvalid(invalidRole);
		const invalidProvider = kernel() as unknown as { source: { provider: string } };
		invalidProvider.source.provider = "attacker_value";
		expectInvalid(invalidProvider);
		const invalidState = envelope({
			kind: "application_transition",
			observation: "state_transition",
			from: "running",
			to: "stopped",
		}) as unknown as { claim: { to: string } };
		invalidState.claim.to = "attacker_value";
		expectInvalid(invalidState);
		const invalidRequestedSignal = envelope({
			kind: "application_transition",
			observation: "signal_requested",
			requestedSignal: "SIGTERM",
		}) as unknown as { claim: { requestedSignal: string } };
		invalidRequestedSignal.claim.requestedSignal = "attacker_value";
		expectInvalid(invalidRequestedSignal);
		const invalidCustody = kernel() as unknown as { custody: string };
		invalidCustody.custody = "attacker_value";
		expectInvalid(invalidCustody);
		expect(normalizeNodeExitCallback(null, "attacker_value")).toEqual({
			kind: "invalid",
			reason: "invalid_signal_name",
		});
	});

	it("rejects every hidden or opaque own-key path without invoking getters", () => {
		const nonenumerable = kernel();
		Object.defineProperty(nonenumerable, "evidenceId", {
			value: nonenumerable.evidenceId,
			enumerable: false,
		});
		expectInvalid(nonenumerable);

		const symbolExtra = kernel() as AutomaticCollapseEvidenceEnvelope & Record<PropertyKey, unknown>;
		symbolExtra[Symbol("secretPayload")] = new Map([["credentials", "private"]]);
		expectInvalid(symbolExtra);

		const opaque = kernel() as unknown as { processAnchor: { installationRun: unknown } };
		opaque.processAnchor.installationRun = new Map([["installationId", "install-1"]]);
		expectInvalid(opaque);

		let getterCalls = 0;
		const getter = kernel();
		Object.defineProperty(getter.claim, "payload", {
			get() {
				getterCalls += 1;
				return "private";
			},
			enumerable: true,
		});
		expectInvalid(getter);
		expect(getterCalls).toBe(0);

		const cyclic = kernel() as AutomaticCollapseEvidenceEnvelope & { cycle?: unknown };
		cyclic.cycle = cyclic;
		expectInvalid(cyclic);
		const throwing = new Proxy(kernel(), {
			ownKeys() {
				throw new Error("trap");
			},
		});
		expectInvalid(throwing);
	});

	it("uses the exact low-byte stopped boundary and rejects unmatched wait encodings", () => {
		for (const malformed of [0x13ff, 0xff, 65, (65 << 8) | 0x7f])
			expect(decodeLinuxWaitWord(malformed).kind).toBe("invalid");
		expect(decodeLinuxWaitWord((19 << 8) | 0x7f)).toMatchObject({
			kind: "stopped",
			stopSignalNumber: 19,
		});
	});

	it("distinguishes every present-invalid or wrong-kind slot from absence", () => {
		const invalidKernel = kernel() as unknown as { claim: { groupDead: boolean } };
		invalidKernel.claim.groupDead = false;
		const invalidParent = parentRaw() as unknown as { claim: { rawWaitWord: number } };
		invalidParent.claim.rawWaitWord = (19 << 8) | 0x7f;
		const invalidApplication = envelope({
			kind: "application_transition",
			observation: "state_transition",
			from: "running",
			to: "stopped",
		}) as unknown as { claim: { to: string } };
		invalidApplication.claim.to = "invented";

		const cases: Array<["kernel" | "parent" | "application", unknown]> = [
			["kernel", invalidKernel],
			["parent", invalidParent],
			["application", invalidApplication],
			["kernel", parentRaw()],
			["parent", kernel()],
			["application", kernel()],
		];
		for (const [slot, supplied] of cases) {
			const result = correlateTerminalEvidence({ [slot]: supplied });
			expect(result).toMatchObject({
				kind: "invalid_evidence",
				invalid: [{ slot }],
			});
			if (result.kind !== "invalid_evidence") throw new Error(`expected invalid ${slot} evidence`);
			expect(result.invalid[0]?.errors.length).toBeGreaterThan(0);
			expect(result.invalid[0]?.errors.length).toBeLessThanOrEqual(16);
		}
	});

	it("preserves the full kernel mapping but admits only canonical Node callback signals 1 through 31", () => {
		for (let signalNumber = 1; signalNumber <= 64; signalNumber += 1) {
			expect(decodeLinuxWaitWord(signalNumber)).toMatchObject({
				kind: "signaled",
				signalNumber,
				signalName: LINUX_SIGNAL_NAMES[signalNumber - 1],
			});
		}
		expect(NODE_CALLBACK_SIGNAL_NAMES).toEqual(LINUX_SIGNAL_NAMES.slice(0, 31));
		for (let signalNumber = 1; signalNumber <= 31; signalNumber += 1) {
			const signalName = NODE_CALLBACK_SIGNAL_NAMES[signalNumber - 1];
			expect(normalizeNodeExitCallback(null, signalName)).toMatchObject({
				kind: "signaled",
				signalNumber,
				signalName,
			});
		}
		for (const rejected of ["SIG32", "SIG33", "SIGRTMIN", "SIGRTMIN+1", "SIGRTMAX", "SIGIOT", "SIGPOLL", "SIGBREAK"])
			expect(normalizeNodeExitCallback(null, rejected)).toEqual({
				kind: "invalid",
				reason: "invalid_signal_name",
			});
	});
});
