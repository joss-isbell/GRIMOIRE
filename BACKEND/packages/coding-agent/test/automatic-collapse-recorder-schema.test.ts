import { describe, expect, it } from "vitest";
import {
	AUTOMATIC_COLLAPSE_EVIDENCE_SCHEMA_VERSION,
	type AutomaticCollapseEvidenceEnvelope,
	advanceEvidenceCustody,
	correlateTerminalEvidence,
	decodeLinuxWaitWord,
	normalizeNodeExitCallback,
	validateAutomaticCollapseEvidence,
	windowsSurvivingCustody,
} from "../src/modes/daemon/automatic-collapse-recorder-schema.js";

function envelope(
	claim: AutomaticCollapseEvidenceEnvelope["claim"],
	overrides: Partial<AutomaticCollapseEvidenceEnvelope> = {},
): AutomaticCollapseEvidenceEnvelope {
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
	} as AutomaticCollapseEvidenceEnvelope;
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
		expect(correlateTerminalEvidence({ kernel: stoppedKernel })).toEqual({ kind: "no_terminal_claim" });
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
		expect(correlateTerminalEvidence({ kernel: threadOnly as unknown as AutomaticCollapseEvidenceEnvelope })).toEqual(
			{ kind: "no_terminal_claim" },
		);
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

describe("custody truth", () => {
	it("allows only the ordered custody progression and only trusts Windows commit", () => {
		expect(advanceEvidenceCustody("kernel_produced", "linux_received")).toBe(true);
		expect(advanceEvidenceCustody("linux_received", "host_published")).toBe(true);
		expect(advanceEvidenceCustody("host_published", "windows_committed")).toBe(true);
		expect(advanceEvidenceCustody("kernel_produced", "windows_committed")).toBe(false);
		for (const state of ["kernel_produced", "linux_received", "host_published"] as const)
			expect(windowsSurvivingCustody(state)).toBe(false);
		expect(windowsSurvivingCustody("windows_committed")).toBe(true);
	});
});
