import {
	existsSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type {
	IncidentRecorderRunHistoryEvent,
	IncidentRecorderRunHistoryResult,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	analyzeIncidentRecorderFinalization,
	finalizeIncidentRecorderProjection,
	INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES,
	INCIDENT_RECORDER_FINALIZATION_ORCHESTRATION_FAULT_BOUNDARIES,
	INCIDENT_RECORDER_RETENTION_AUTHORITY_FAULT_BOUNDARIES,
	type IncidentRecorderFinalizationFileSystem,
	type IncidentRecorderFinalizationInput,
	type IncidentRecorderRelayFrontierExpectation,
	inspectIncidentRetentionAuthority,
	inspectPublishedIncidentFinalization,
	persistIncidentRetentionAuthority,
	recoverPublishedIncidentFinalization,
} from "../src/modes/daemon/incident-recorder-finalizer.js";

const roots: string[] = [];
const runId = "11111111-1111-4111-8111-111111111111";
const runToken = "22222222-2222-4222-8222-222222222222";
const wrapperProducer = "33333333-3333-4333-8333-333333333333";
const serviceProducer = "44444444-4444-4444-8444-444444444444";

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
	const value = mkdtempSync(join(tmpdir(), "prime-agent-finalizer-crash-matrix-"));
	roots.push(value);
	return value;
}

function frontier(
	type: "supervisor_exit" | "capture_channel_terminal",
	occurrenceId: string,
	producerId: string,
	sequence: string,
): IncidentRecorderRelayFrontierExpectation {
	return {
		type,
		occurrenceId,
		producerId,
		firstProducerSequence: sequence,
		lastProducerSequence: sequence,
		firstWrapperSequence: sequence,
		lastWrapperSequence: sequence,
	};
}

function event(
	type: "supervisor_exit" | "capture_channel_terminal",
	occurrenceId: string,
	producerId: string,
	sequence: string,
	wallTimeMs: string,
	physicalRoot: string,
): IncidentRecorderRunHistoryEvent {
	const identityKey = occurrenceId.replaceAll("-", "").padEnd(64, "0").slice(0, 64);
	return {
		identityKey,
		identity: { runId, runToken, producerId, occurrenceId },
		semanticFingerprint: identityKey.split("").reverse().join(""),
		occurrenceReference: join(physicalRoot, `${occurrenceId}.json`),
		source: type === "supervisor_exit" ? "recorder-events" : "recorder-control",
		type,
		encoding: "derived-scalar-json-v1",
		payloadKind: type === "supervisor_exit" ? "derived-scalar" : "control",
		terminal: type === "capture_channel_terminal",
		metadata:
			type === "supervisor_exit"
				? { code: null, signal: "SIGABRT", producerPid: 10, sourcePath: physicalRoot }
				: { producerPid: 10, phase: "terminal" },
		eventWallTimeMs: wallTimeMs,
		eventMonotonicNs: sequence,
		wrapperOrder: [sequence],
		producerOrder: [sequence],
		cursors: [`cursor:${physicalRoot}:${sequence}`],
		transportIdentity: {
			wrapperPid: 10,
			wrapperStartId: "100",
			targetPid: 20,
			targetStartId: "200",
			machineId: "machine",
			bootId: "boot",
			journalStreamId: "stream",
			journalInvocationId: null,
			invocationIdentityDisposition: "trusted_journal_invocation_absent",
			systemdCatPid: 30,
			systemdCatStartId: "300",
			journalPresence: "journal_export_observed",
		},
		cas: {
			digest: identityKey,
			bytes: 16,
			path: join(physicalRoot, "cas", identityKey),
		},
	};
}

function history(physicalRoot: string): IncidentRecorderRunHistoryResult {
	const supervisor = event(
		"supervisor_exit",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		wrapperProducer,
		"1",
		"1000",
		physicalRoot,
	);
	const wrapper = event(
		"capture_channel_terminal",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		wrapperProducer,
		"2",
		"1001",
		physicalRoot,
	);
	const service = event(
		"capture_channel_terminal",
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		serviceProducer,
		"1",
		"1002",
		physicalRoot,
	);
	return {
		state: "complete",
		projection: {
			version: 1,
			runId,
			fromWallTimeMs: 0,
			throughWallTimeMs: 2000,
			events: [supervisor, wrapper, service],
			terminalEvents: [wrapper, service].map((value) => ({
				identityKey: value.identityKey,
				type: value.type,
				source: value.source,
				eventWallTimeMs: value.eventWallTimeMs,
				basis: "terminal_flag" as const,
			})),
			finalizationCandidates: [
				{
					role: "supervisor_exit",
					identityKey: supervisor.identityKey,
					basis: "type_and_source_candidate",
					qualification: "candidate_requires_expectation_match",
				},
				...([wrapper, service].map((value) => ({
					role: "capture_channel_terminal" as const,
					identityKey: value.identityKey,
					basis: "type_source_and_terminal_flag_candidate" as const,
					qualification: "candidate_requires_expectation_match" as const,
				})) satisfies Array<
					(IncidentRecorderRunHistoryResult & {
						state: "complete";
					})["projection"]["finalizationCandidates"][number]
				>),
			],
			ordering: {
				semantics: "partial_order",
				causalRelations: [],
				presentationTieBreak: "wall_time_then_identity_key",
				unrelatedPresentationOrderIsCausal: false,
				scope: "complete_snapshot",
			},
			evidence: [],
		},
		snapshot: {
			version: 1,
			fingerprint: "f".repeat(64),
			segmentRecordCount: 3,
			segmentRecoveryGapCount: 0,
			segmentScannedSegments: 1,
			segmentScannedRecords: 3,
			segmentScannedIndexBytes: 1024,
			legacyOccurrenceCount: 0,
			validatedCasDigestCount: 3,
		},
	};
}

function input(
	incidentsDirectory: string,
	physicalRoot: string,
	leaseEvents: string[] = [],
): IncidentRecorderFinalizationInput {
	return {
		incidentsDirectory,
		incidentId: `run-${runId}`,
		runIdentity: { runId, runToken },
		runHistory: history(physicalRoot),
		terminalExpectations: {
			supervisorExit: {
				state: "available",
				frontier: frontier("supervisor_exit", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", wrapperProducer, "1"),
			},
			wrapperTerminal: {
				state: "available",
				frontier: frontier(
					"capture_channel_terminal",
					"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
					wrapperProducer,
					"2",
				),
			},
			serviceTerminal: {
				state: "available",
				frontier: frontier(
					"capture_channel_terminal",
					"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
					serviceProducer,
					"1",
				),
			},
		},
		classification: { value: "native_abort", causeLayer: "application" },
		exit: { code: null, signal: "SIGABRT" },
		stoppedTarget: {
			captureState: "complete",
			artifacts: [
				{
					state: "complete",
					role: "node-report",
					required: true,
					algorithm: "sha256",
					digest: "d".repeat(64),
					bytes: 32,
					encoding: "exact-file-bytes",
					path: join(physicalRoot, "report.json"),
				},
			],
		},
		wrapperLoss: {
			finalQueuedTailLoss: { records: 0, bytes: 0 },
			emitterFinalTailLoss: { records: 0, bytes: 0 },
		},
		serviceSeal: {
			terminalRelayDisposition: "relayed",
			emitterLoss: { records: 0, bytes: 0 },
			drainTimeoutLoss: {
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 0, bytes: 0 },
			},
			terminalRelayLoss: {
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 0, bytes: 0 },
			},
		},
		assertProjectionLeaseUsable: () => leaseEvents.push("assert"),
		releaseProjectionLease: () => leaseEvents.push("release"),
	};
}

function expectNoReclaimAuthority(incidentsDirectory: string, incidentId: string): void {
	expect(inspectIncidentRetentionAuthority({ incidentsDirectory, incidentId }).state).not.toBe("authorized");
	expect(existsSync(join(incidentsDirectory, incidentId, "retention-authority.json"))).toBe(false);
}

function snapshotDirectory(directory: string): Record<string, string> {
	const snapshot: Record<string, string> = {};
	const visit = (current: string, prefix: string): void => {
		for (const name of readdirSync(current).sort()) {
			const path = join(current, name);
			const relative = prefix ? `${prefix}/${name}` : name;
			const stat = lstatSync(path, { bigint: true });
			if (stat.isDirectory() && !stat.isSymbolicLink()) {
				snapshot[`${relative}/`] = `directory:${(stat.mode & 0o7777n).toString(8)}`;
				visit(path, relative);
			} else if (stat.isFile() && !stat.isSymbolicLink()) {
				snapshot[relative] = `file:${(stat.mode & 0o7777n).toString(8)}:${readFileSync(path).toString("base64")}`;
			} else {
				snapshot[relative] = `other:${(stat.mode & 0o7777n).toString(8)}:${stat.size.toString()}`;
			}
		}
	};
	visit(directory, "");
	return snapshot;
}

function canonicalLinkDestination(destination: string): string {
	const match = /^\/proc\/self\/fd\/(\d+)(\/.*)?$/.exec(destination);
	if (!match) return destination;
	return `${readlinkSync(`/proc/self/fd/${match[1]}`)}${match[2] ?? ""}`;
}

describe("incident recorder finalization crash convergence", () => {
	it("keeps the crash matrix synchronized with the component fault vocabulary", () => {
		expect(INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES).toHaveLength(16);
	});

	it("records orchestration fault vocabulary without executing it as a component seam", () => {
		expect(INCIDENT_RECORDER_FINALIZATION_ORCHESTRATION_FAULT_BOUNDARIES).toEqual([
			"after_stopped_capture_before_seal",
			"after_seal_before_terminal_frontier",
			"after_source_marker_before_reclaim_complete",
		]);
	});

	it.each(
		INCIDENT_RECORDER_RETENTION_AUTHORITY_FAULT_BOUNDARIES.filter(
			(boundary) => boundary.endsWith("_link_before_directory_fsync") && !boundary.includes("manifest"),
		),
	)("normalizes the exact retention control after a process crash at %s", (boundary) => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const primaryPath = join(published.incidentDirectory, "retention-authority.json");
		writeFileSync(primaryPath, "malformed\n", { mode: 0o600 });
		const persistenceInput = {
			incidentDirectory: published.incidentDirectory,
			finalizationId: published.finalizationId,
			runId,
			outcome: "complete" as const,
			retentionAnchorWallTimeMs: 1000,
		};

		expect(
			persistIncidentRetentionAuthority(persistenceInput, {
				onRetentionAuthorityFaultBoundary: (observed) => {
					if (observed === boundary) throw new Error(`simulated process crash at ${boundary}`);
				},
			}),
		).toEqual({ state: "pending", reason: "retention_authority_persistence_ambiguous" });
		const authorityRoot = join(published.incidentDirectory, ".finalization-authority-root");
		const controlName = boundary.includes("intended")
			? "retention-authority-intended.json"
			: "retention-authority-conflict.json";
		const controlPath = join(authorityRoot, controlName);
		const controlIdentity = lstatSync(controlPath, { bigint: true });
		expect(controlIdentity.nlink).toBe(2n);
		const linkedTemp = readdirSync(authorityRoot).find((name) => name.startsWith(`.${controlName}.`));
		if (!linkedTemp) throw new Error("Expected retention control publication temp");
		const tempIdentity = lstatSync(join(authorityRoot, linkedTemp), { bigint: true });
		expect({ dev: tempIdentity.dev, ino: tempIdentity.ino }).toEqual({
			dev: controlIdentity.dev,
			ino: controlIdentity.ino,
		});

		expect(persistIncidentRetentionAuthority(persistenceInput)).toMatchObject({
			state: "authorized",
			authoritySource: "conflict",
			retentionClass: "corrupt",
		});
		expect(lstatSync(controlPath, { bigint: true }).nlink).toBe(1n);
		expect(readdirSync(authorityRoot).some((name) => name.endsWith(".tmp"))).toBe(false);
	});

	it.each(INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES)(
		"converges after a process crash at %s without granting reclaim authority",
		(boundary) => {
			const target = root();
			const incidentsDirectory = join(target, "incidents");
			const incidentId = `run-${runId}`;
			const incidentDirectory = join(incidentsDirectory, incidentId);
			const firstLeaseEvents: string[] = [];
			const firstInput = input(incidentsDirectory, "/physical", firstLeaseEvents);
			const analysis = analyzeIncidentRecorderFinalization(firstInput);
			expect(analysis.state).toBe("complete");
			const stagingDirectory = join(incidentsDirectory, `.${incidentId}.partial-${analysis.finalizationId}`);
			const publishedLinks: string[] = [];
			const trackedLink: IncidentRecorderFinalizationFileSystem["link"] = (source, destination) => {
				linkSync(source, destination);
				const destinationPath = canonicalLinkDestination(destination.toString());
				if (dirname(destinationPath) === incidentDirectory) {
					publishedLinks.push(basename(destinationPath));
				}
			};
			const fs = { link: trackedLink };
			let crashCount = 0;

			const interrupted = finalizeIncidentRecorderProjection(firstInput, {
				fs,
				onFaultBoundary: (observed) => {
					if (observed !== boundary) return;
					crashCount += 1;
					throw new Error(`simulated process crash at ${boundary}`);
				},
			});

			expect(crashCount).toBe(1);
			expect(interrupted).toMatchObject({
				state: "ambiguous",
				publication: "ambiguous",
				finalizationId: analysis.finalizationId,
			});
			const stageCreationIndex = INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES.indexOf(
				"after_partial_mkdir_before_parent_fsync",
			);
			expect(existsSync(stagingDirectory)).toBe(
				INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES.indexOf(boundary) >= stageCreationIndex,
			);
			expectNoReclaimAuthority(incidentsDirectory, incidentId);

			let recovered = recoverPublishedIncidentFinalization(
				{
					incidentsDirectory,
					incidentId,
					expectedFinalizationId: analysis.finalizationId,
				},
				{ fs },
			);
			expectNoReclaimAuthority(incidentsDirectory, incidentId);
			if (recovered.state === "pending") {
				const restartLeaseEvents: string[] = [];
				const restarted = finalizeIncidentRecorderProjection(
					input(incidentsDirectory, "/physical", restartLeaseEvents),
					{ fs },
				);
				expect(restarted).toMatchObject({
					state: "complete",
					publication: "applied",
					finalizationId: analysis.finalizationId,
				});
				expect(restartLeaseEvents.filter((event) => event === "release")).toHaveLength(1);
				recovered = recoverPublishedIncidentFinalization(
					{
						incidentsDirectory,
						incidentId,
						expectedFinalizationId: analysis.finalizationId,
					},
					{ fs },
				);
			}

			expect(recovered).toMatchObject({
				state: "complete",
				finalizationId: analysis.finalizationId,
				runId,
			});
			expect(existsSync(stagingDirectory)).toBe(false);
			expectNoReclaimAuthority(incidentsDirectory, incidentId);

			const published = inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId });
			expect(published).toMatchObject({
				state: "complete",
				finalizationId: analysis.finalizationId,
				runId,
			});
			if (published.state === "pending") throw new Error("Expected a published finalization");
			const authoritativeNames = published.manifest.files.map((file) => file.name);
			expect(publishedLinks).toEqual([...authoritativeNames, "finalization-manifest.json"]);
			for (const file of published.manifest.files) {
				expect(readFileSync(join(incidentDirectory, file.name))).toHaveLength(file.bytes);
			}

			const convergedBytes = snapshotDirectory(incidentDirectory);
			const exactReplayLeaseEvents: string[] = [];
			const exactReplay = finalizeIncidentRecorderProjection(
				input(incidentsDirectory, "/physical", exactReplayLeaseEvents),
				{ fs },
			);
			expect(exactReplay).toMatchObject({
				state: "complete",
				publication: "noop",
				finalizationId: analysis.finalizationId,
			});
			expect(exactReplayLeaseEvents.filter((event) => event === "release")).toHaveLength(1);
			expect(snapshotDirectory(incidentDirectory)).toEqual(convergedBytes);

			const conflictingInput = input(incidentsDirectory, "/physical-conflict");
			conflictingInput.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
			expect(finalizeIncidentRecorderProjection(conflictingInput, { fs })).toMatchObject({
				state: "complete",
				publication: "noop",
				finalizationId: analysis.finalizationId,
				reason: "published_finalization_conflict",
			});
			expect(snapshotDirectory(incidentDirectory)).toEqual(convergedBytes);
			expectNoReclaimAuthority(incidentsDirectory, incidentId);
		},
	);

	it("converges after a crash immediately after linking a terminal conflict authority selector", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") {
					throw new Error("simulated restart after prepared durability");
				}
			},
		});
		expect(interrupted).toMatchObject({ state: "ambiguous", publication: "ambiguous" });
		const stagingDirectory = join(incidentsDirectory, `.${incidentId}.partial-${interrupted.finalizationId}`);
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		const conflictingBytes = Buffer.from('{"conflicting":"projection"}\n', "utf8");
		writeFileSync(join(incidentDirectory, "run-history.json"), conflictingBytes, { mode: 0o600 });
		let injected = false;
		const firstPass = recoverPublishedIncidentFinalization(
			{
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: interrupted.finalizationId,
			},
			{
				fs: {
					link: (source, destination) => {
						linkSync(source, destination);
						if (
							!injected &&
							canonicalLinkDestination(destination.toString()) ===
								join(incidentDirectory, "finalization-authority.json")
						) {
							injected = true;
							throw undefined;
						}
					},
				},
			},
		);
		expect(injected).toBe(true);
		expect(firstPass).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
			runId,
		});
		expect(existsSync(stagingDirectory)).toBe(false);
		expect(readFileSync(join(incidentDirectory, "run-history.json"))).toEqual(conflictingBytes);
		expectNoReclaimAuthority(incidentsDirectory, incidentId);

		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: interrupted.finalizationId,
		});
		expect(recovered).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
			runId,
		});
		expect(existsSync(stagingDirectory)).toBe(false);
		expect(readFileSync(join(incidentDirectory, "run-history.json"))).toEqual(conflictingBytes);
		expect(
			readdirSync(incidentDirectory).some((name) =>
				/^\.finalization-authority\.json\.[0-9a-f]{64}\.tmp$/.test(name),
			),
		).toBe(false);
		expectNoReclaimAuthority(incidentsDirectory, incidentId);
		const convergedBytes = snapshotDirectory(incidentDirectory);
		expect(
			recoverPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: interrupted.finalizationId,
			}),
		).toMatchObject({ state: "corrupt", finalizationId: interrupted.finalizationId });
		expect(snapshotDirectory(incidentDirectory)).toEqual(convergedBytes);
	});

	it("preserves a preoccupied canonical manifest and converges after selector-link crash", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const stagingDirectory = join(incidentsDirectory, `.${incidentId}.partial-${interrupted.finalizationId}`);
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		const occupiedManifest = Buffer.from('{"foreign":"terminal-manifest"}\n', "utf8");
		writeFileSync(join(incidentDirectory, "finalization-manifest.json"), occupiedManifest, { mode: 0o600 });
		let injected = false;
		const first = recoverPublishedIncidentFinalization(
			{
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: interrupted.finalizationId,
			},
			{
				fs: {
					link: (source, destination) => {
						linkSync(source, destination);
						if (
							!injected &&
							canonicalLinkDestination(destination.toString()) ===
								join(incidentDirectory, "finalization-authority.json")
						) {
							injected = true;
							throw undefined;
						}
					},
				},
			},
		);
		expect(first).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
			runId,
		});
		expect(injected).toBe(true);
		expect(readFileSync(join(incidentDirectory, "finalization-manifest.json"))).toEqual(occupiedManifest);
		expect(existsSync(stagingDirectory)).toBe(false);

		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: interrupted.finalizationId,
		});
		expect(recovered).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
			runId,
		});
		expect(readFileSync(join(incidentDirectory, "finalization-manifest.json"))).toEqual(occupiedManifest);
		expect(existsSync(stagingDirectory)).toBe(false);
		expect(
			readdirSync(incidentDirectory).some((name) =>
				/^\.finalization-authority\.json\.[0-9a-f]{64}\.tmp$/.test(name),
			),
		).toBe(false);
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
		});
		expectNoReclaimAuthority(incidentsDirectory, incidentId);
	});

	it("finishes the exact conflict intent after a content-record crash before adopting a changed intent", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const firstInput = input(incidentsDirectory, "/physical");
		const firstAnalysis = analyzeIncidentRecorderFinalization(firstInput);
		const interrupted = finalizeIncidentRecorderProjection(firstInput, {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared A");
			},
		});
		const firstStage = join(incidentsDirectory, `.${incidentId}.partial-${firstAnalysis.finalizationId}`);
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(join(incidentDirectory, "run-history.json"), "conflicting history", { mode: 0o600 });
		let injected = false;
		const crashed = recoverPublishedIncidentFinalization(
			{
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: interrupted.finalizationId,
			},
			{
				fs: {
					link: (source, destination) => {
						linkSync(source, destination);
						if (
							!injected &&
							/^finalization-conflict-[0-9a-f]{64}\.json$/.test(basename(destination.toString()))
						) {
							injected = true;
							throw undefined;
						}
					},
				},
			},
		);
		expect(crashed.state).toBe("pending");
		expect(injected).toBe(true);
		expect(existsSync(firstStage)).toBe(true);
		const changed = input(incidentsDirectory, "/changed");
		changed.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
		const changedAnalysis = analyzeIncidentRecorderFinalization(changed);
		expect(changedAnalysis.finalizationId).not.toBe(firstAnalysis.finalizationId);
		const changedInterrupted = finalizeIncidentRecorderProjection(changed, {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared B");
			},
		});
		expect(changedInterrupted).toMatchObject({
			state: "ambiguous",
			finalizationId: changedAnalysis.finalizationId,
		});
		const changedStage = join(incidentsDirectory, `.${incidentId}.partial-${changedAnalysis.finalizationId}`);
		expect(existsSync(changedStage)).toBe(true);

		const selected = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: firstAnalysis.finalizationId,
		});
		expect(selected).toMatchObject({ state: "corrupt", finalizationId: firstAnalysis.finalizationId });
		expect(existsSync(firstStage)).toBe(false);
		expect(
			readdirSync(incidentDirectory).some((name) =>
				/^\.finalization-conflict-[0-9a-f]{64}\.json\.[0-9a-f]{64}\.tmp$/.test(name),
			),
		).toBe(false);
		expect(
			recoverPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: changedAnalysis.finalizationId,
			}),
		).toMatchObject({ state: "corrupt", finalizationId: firstAnalysis.finalizationId });
		expect(existsSync(changedStage)).toBe(false);
		expect(finalizeIncidentRecorderProjection(changed)).toMatchObject({
			state: "corrupt",
			publication: "noop",
			finalizationId: firstAnalysis.finalizationId,
		});
		expect(existsSync(changedStage)).toBe(false);
	});
});
