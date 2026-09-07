import { createHash } from "node:crypto";
import {
	chmodSync,
	closeSync,
	cpSync,
	existsSync,
	fstatSync,
	fsyncSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	readSync,
	renameSync,
	rmdirSync,
	rmSync,
	symlinkSync,
	unlinkSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type {
	IncidentRecorderRunHistoryEvent,
	IncidentRecorderRunHistoryResult,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	analyzeIncidentRecorderFinalization,
	finalizeIncidentRecorderProjection,
	INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES,
	INCIDENT_RECORDER_FINALIZATION_FAULT_BOUNDARIES,
	INCIDENT_RECORDER_FINALIZATION_ORCHESTRATION_FAULT_BOUNDARIES,
	INCIDENT_RECORDER_RETENTION_AUTHORITY_FAULT_BOUNDARIES,
	type IncidentRecorderFinalizationFileSystem,
	type IncidentRecorderFinalizationInput,
	type IncidentRecorderRelayFrontierExpectation,
	type IncidentRecorderRetentionAuthority,
	inspectIncidentRetentionAuthority,
	inspectPublishedIncidentFinalization,
	persistIncidentFinalizationSeal,
	persistIncidentRetentionAuthority,
	recoverPublishedIncidentFinalization,
} from "../src/modes/daemon/incident-recorder-finalizer.js";

const roots: string[] = [];
const runId = "11111111-1111-4111-8111-111111111111";
const runToken = "22222222-2222-4222-8222-222222222222";
const wrapperProducer = "33333333-3333-4333-8333-333333333333";
const serviceProducer = "44444444-4444-4444-8444-444444444444";
const finalizationClaimName = "finalization-claim.json";
const resolvedRetentionAuthorityRootEntries = [
	finalizationClaimName,
	"retention-authority-conflict.json",
	"retention-authority-intended.json",
	"retention-authority-manifest.json",
] as const;

function digest(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
	const value = mkdtempSync(join(tmpdir(), "prime-agent-finalizer-"));
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
	lease: string[] = [],
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
		assertProjectionLeaseUsable: () => lease.push("assert"),
		releaseProjectionLease: () => lease.push("release"),
	};
}

function selectedConflictRecord(incidentDirectory: string): {
	files: Array<{ logicalName: string; observed?: { disposition: string } }>;
	manifestConflict?: { observed: { disposition: string } };
} {
	let authorityDirectory = incidentDirectory;
	let selector: { manifest: { name: string } } | undefined;
	for (const name of [
		"finalization-authority.json",
		"finalization-authority-1.json",
		"finalization-authority-2.json",
		"finalization-authority-3.json",
		"finalization-authority-4.json",
		"finalization-authority-5.json",
		"finalization-authority-6.json",
		"finalization-authority-7.json",
	]) {
		try {
			const candidate = JSON.parse(readFileSync(join(incidentDirectory, name), "utf8")) as {
				kind?: string;
				manifest?: { name: string };
			};
			if (candidate.kind === "incident_recorder_finalization_authority_selector" && candidate.manifest) {
				selector = { manifest: candidate.manifest };
				break;
			}
		} catch {}
	}
	if (!selector) {
		authorityDirectory = join(incidentDirectory, ".finalization-authority-root");
		selector = JSON.parse(readFileSync(join(authorityDirectory, "finalization-authority.json"), "utf8")) as {
			manifest: { name: string };
		};
	}
	const manifest = JSON.parse(readFileSync(join(authorityDirectory, selector.manifest.name), "utf8")) as {
		conflictRecord: { name: string };
	};
	return JSON.parse(readFileSync(join(authorityDirectory, manifest.conflictRecord.name), "utf8")) as {
		files: Array<{ logicalName: string; observed?: { disposition: string } }>;
		manifestConflict?: { observed: { disposition: string } };
	};
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

function snapshotPathIdentity(path: string): Record<string, string | null> {
	const stat = lstatSync(path, { bigint: true });
	return {
		dev: stat.dev.toString(),
		ino: stat.ino.toString(),
		mode: stat.mode.toString(),
		nlink: stat.nlink.toString(),
		size: stat.size.toString(),
		mtimeNs: stat.mtimeNs.toString(),
		ctimeNs: stat.ctimeNs.toString(),
		contentSha256: stat.isFile() && !stat.isSymbolicLink() ? digest(readFileSync(path)) : null,
		linkTarget: stat.isSymbolicLink() ? readlinkSync(path) : null,
	};
}

function retentionPersistenceInput(
	incidentDirectory: string,
	finalizationId: string,
	overrides: Partial<{
		runId: string;
		outcome: "complete" | "incomplete" | "corrupt";
		retentionAnchorWallTimeMs: number;
	}> = {},
): {
	incidentDirectory: string;
	finalizationId: string;
	runId: string;
	outcome: "complete" | "incomplete" | "corrupt";
	retentionAnchorWallTimeMs: number;
} {
	return {
		incidentDirectory,
		finalizationId,
		runId,
		outcome: "complete",
		retentionAnchorWallTimeMs: 1000,
		...overrides,
	};
}

describe("incident recorder durable finalizer", () => {
	it("uses the exact bounded fault-boundary vocabulary", () => {
		expect(INCIDENT_RECORDER_FINALIZATION_FAULT_BOUNDARIES).toEqual([
			"after_stopped_capture_before_seal",
			"after_seal_before_terminal_frontier",
			"after_projection_lease_acquired",
			"after_partial_mkdir_before_parent_fsync",
			"after_intent_durable_before_history",
			"after_history_write_before_fsync",
			"after_history_fsync_before_rename",
			"after_history_rename_before_directory_fsync",
			"after_descriptor_write_before_fsync",
			"after_descriptor_fsync_before_rename",
			"after_descriptor_rename_before_directory_fsync",
			"after_prepared_directory_fsync_before_lease_release",
			"after_projection_lease_release_before_publish",
			"after_manifest_fsync_before_rename",
			"after_manifest_rename_before_directory_fsync",
			"after_staging_directory_fsync_before_publish",
			"after_publish_rename_before_parent_fsync",
			"after_publish_parent_fsync_before_source_release",
			"after_source_marker_before_reclaim_complete",
		]);
		expect(INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES).toHaveLength(16);
	});

	it("keeps orchestration-only fault boundaries out of component execution", () => {
		expect(INCIDENT_RECORDER_FINALIZATION_ORCHESTRATION_FAULT_BOUNDARIES).toEqual([
			"after_stopped_capture_before_seal",
			"after_seal_before_terminal_frontier",
			"after_source_marker_before_reclaim_complete",
		]);
		expect(
			INCIDENT_RECORDER_FINALIZATION_COMPONENT_FAULT_BOUNDARIES.filter((boundary) =>
				INCIDENT_RECORDER_FINALIZATION_ORCHESTRATION_FAULT_BOUNDARIES.includes(boundary as never),
			),
		).toEqual([]);
	});

	it("fsyncs an exact interrupted temp before reusing it for publication", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const finalizationInput = input(incidentsDirectory, "/physical");
		const interrupted = finalizeIncidentRecorderProjection(finalizationInput, {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_history_write_before_fsync") throw new Error("crash before temp fsync");
			},
		});
		expect(interrupted).toMatchObject({ state: "ambiguous", publication: "ambiguous" });
		const partialDirectory = join(
			incidentsDirectory,
			`.${finalizationInput.incidentId}.partial-${interrupted.finalizationId}`,
		);
		const historyTempName = readdirSync(partialDirectory).find((name) =>
			/^\.run-history\.json\.[0-9a-f]{64}(?:\.[1-7])?\.tmp$/.test(name),
		);
		if (!historyTempName) throw new Error("Expected interrupted run-history temp");
		const historyTempIdentity = lstatSync(join(partialDirectory, historyTempName), { bigint: true });
		let reusedTempFsynced = false;

		const replayed = finalizeIncidentRecorderProjection(finalizationInput, {
			fs: {
				fsync: (descriptor) => {
					const identity = fstatSync(descriptor, { bigint: true });
					if (identity.dev === historyTempIdentity.dev && identity.ino === historyTempIdentity.ino) {
						reusedTempFsynced = true;
					}
					fsyncSync(descriptor);
				},
			},
		});
		expect(replayed).toMatchObject({ state: "complete", finalizationId: interrupted.finalizationId });
		expect(reusedTempFsynced).toBe(true);
	});

	it("keeps the semantic ID stable across roots and physical projection fields", () => {
		const firstRoot = root();
		const secondRoot = root();
		const first = analyzeIncidentRecorderFinalization(input(join(firstRoot, "incidents"), "/one"));
		const secondInput = input(join(secondRoot, "other-incidents"), "/two");
		if (secondInput.runHistory.state === "complete") {
			secondInput.runHistory.snapshot.fingerprint = "e".repeat(64);
		}
		const second = analyzeIncidentRecorderFinalization(secondInput);
		expect(first.state).toBe("complete");
		expect(second.state).toBe("complete");
		expect(second.finalizationId).toBe(first.finalizationId);

		secondInput.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
		expect(analyzeIncidentRecorderFinalization(secondInput).finalizationId).not.toBe(first.finalizationId);
	});

	it.each([
		{
			name: "empty snapshot",
			mutate: (snapshot: Record<string, unknown>) => {
				for (const key of Object.keys(snapshot)) delete snapshot[key];
			},
		},
		{
			name: "missing recovery-gap counter",
			mutate: (snapshot: Record<string, unknown>) => {
				delete snapshot.segmentRecoveryGapCount;
			},
		},
		{
			name: "negative recovery-gap counter",
			mutate: (snapshot: Record<string, unknown>) => {
				snapshot.segmentRecoveryGapCount = -1;
			},
		},
		{
			name: "string recovery-gap counter",
			mutate: (snapshot: Record<string, unknown>) => {
				snapshot.segmentRecoveryGapCount = "0";
			},
		},
	])("retains $name as incomplete diagnostic evidence", ({ mutate }) => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const finalizationInput = input(incidentsDirectory, "/physical");
		if (finalizationInput.runHistory.state !== "complete") throw new Error("Expected complete run history fixture");
		mutate(finalizationInput.runHistory.snapshot as unknown as Record<string, unknown>);

		const finalized = finalizeIncidentRecorderProjection(finalizationInput);
		expect(finalized).toMatchObject({ state: "incomplete" });
		expect(finalized.reasons).toContain("run_history_snapshot_invalid");
		const inspected = inspectPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId: finalizationInput.incidentId,
		});
		expect(inspected).toMatchObject({ state: "incomplete" });
		expect(
			persistIncidentRetentionAuthority({
				incidentDirectory: finalized.incidentDirectory,
				finalizationId: finalized.finalizationId,
				runId,
				outcome: "complete",
				retentionAnchorWallTimeMs: 1000,
			}),
		).toMatchObject({ state: "pending", reason: "retention_authority_persistence_finalization_mismatch" });
		expect(
			persistIncidentRetentionAuthority({
				incidentDirectory: finalized.incidentDirectory,
				finalizationId: finalized.finalizationId,
				runId,
				outcome: "incomplete",
				retentionAnchorWallTimeMs: 1000,
			}),
		).toMatchObject({ state: "authorized", retentionClass: "diagnostic" });
	});

	it("rejects a complete publication whose nested snapshot accounting is invalidated", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const historyPath = join(published.incidentDirectory, "run-history.json");
		const manifestPath = join(published.incidentDirectory, "finalization-manifest.json");
		unlinkSync(join(published.incidentDirectory, ".finalization-authority-root", finalizationClaimName));
		const historyValue = JSON.parse(readFileSync(historyPath, "utf8")) as {
			runHistory: { snapshot: Record<string, unknown> };
		};
		historyValue.runHistory.snapshot.segmentRecoveryGapCount = "0";
		const historyBytes = Buffer.from(`${JSON.stringify(historyValue)}\n`, "utf8");
		writeFileSync(historyPath, historyBytes, { mode: 0o600 });
		const manifestValue = JSON.parse(readFileSync(manifestPath, "utf8")) as {
			files: Array<{ name: string; bytes: number; sha256: string }>;
		};
		manifestValue.files = manifestValue.files.map((record) =>
			record.name === "run-history.json"
				? { name: record.name, bytes: historyBytes.length, sha256: digest(historyBytes) }
				: record,
		);
		writeFileSync(manifestPath, `${JSON.stringify(manifestValue)}\n`, { mode: 0o600 });

		expect(
			inspectPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId: `run-${runId}`,
			}),
		).toEqual({ state: "pending", reason: "finalization_standard_semantics_invalid" });
	});

	it("classifies a malformed run-history projection without throwing", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const malformed = input(incidentsDirectory, "/physical");
		malformed.runHistory = {
			state: "complete",
			projection: {},
		} as unknown as IncidentRecorderRunHistoryResult;

		const finalized = finalizeIncidentRecorderProjection(malformed);
		expect(finalized).toMatchObject({ state: "corrupt" });
		expect(finalized.reasons).toContain("run_history_schema_invalid");
		expect(
			inspectPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId: malformed.incidentId,
			}),
		).toMatchObject({ state: "corrupt" });
	});

	it("rejects noncanonical and semantically inconsistent standard publication packages", () => {
		const target = root();
		const sourceIncidents = join(target, "source-incidents");
		const source = finalizeIncidentRecorderProjection(input(sourceIncidents, "/physical"));
		const sourceManifestBytes = readFileSync(join(source.incidentDirectory, "finalization-manifest.json"));
		const sourceManifest = JSON.parse(sourceManifestBytes.toString("utf8")) as {
			files: Array<{ name: string; bytes: number; sha256: string }>;
			[key: string]: unknown;
		};
		const arbitraryBytes = Buffer.from("{}\n");
		const cases: Array<{
			name: string;
			manifestBytes: () => Buffer;
			extra?: { name: string; bytes: Buffer };
		}> = [
			{
				name: "extra key",
				manifestBytes: () => Buffer.from(`${JSON.stringify({ ...sourceManifest, unexpected: true })}\n`),
			},
			{
				name: "duplicate reasons",
				manifestBytes: () => Buffer.from(`${JSON.stringify({ ...sourceManifest, reasons: ["x", "x"] })}\n`),
			},
			{
				name: "reordered files",
				manifestBytes: () =>
					Buffer.from(`${JSON.stringify({ ...sourceManifest, files: [...sourceManifest.files].reverse() })}\n`),
			},
			{
				name: "noncanonical whitespace",
				manifestBytes: () => Buffer.from(`${JSON.stringify(sourceManifest, null, 2)}\n`),
			},
			{
				name: "arbitrary fifth file",
				extra: { name: "arbitrary.json", bytes: arbitraryBytes },
				manifestBytes: () =>
					Buffer.from(
						`${JSON.stringify({
							...sourceManifest,
							files: [
								...sourceManifest.files,
								{ name: "arbitrary.json", bytes: arbitraryBytes.length, sha256: digest(arbitraryBytes) },
							],
						})}\n`,
					),
			},
		];
		for (const testCase of cases) {
			const incidentsDirectory = join(target, testCase.name.replaceAll(" ", "-"));
			const incidentDirectory = join(incidentsDirectory, `run-${runId}`);
			mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
			for (const record of sourceManifest.files) {
				writeFileSync(
					join(incidentDirectory, record.name),
					readFileSync(join(source.incidentDirectory, record.name)),
					{
						mode: 0o600,
					},
				);
			}
			if (testCase.extra)
				writeFileSync(join(incidentDirectory, testCase.extra.name), testCase.extra.bytes, { mode: 0o600 });
			writeFileSync(join(incidentDirectory, "finalization-manifest.json"), testCase.manifestBytes(), {
				mode: 0o600,
			});
			expect(
				inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId: `run-${runId}` }),
				testCase.name,
			).toMatchObject({ state: "pending" });
		}

		const incidentsDirectory = join(target, "semantic-mismatch");
		const incidentDirectory = join(incidentsDirectory, `run-${runId}`);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		for (const record of sourceManifest.files) {
			const sourceBytes = readFileSync(join(source.incidentDirectory, record.name));
			if (record.name !== "finalization-descriptor.json") {
				writeFileSync(join(incidentDirectory, record.name), sourceBytes, { mode: 0o600 });
				continue;
			}
			const descriptor = JSON.parse(sourceBytes.toString("utf8")) as {
				serviceSeal: { emitterLoss: { records: number; bytes: number } };
			};
			descriptor.serviceSeal.emitterLoss.records = 1;
			const changed = Buffer.from(`${JSON.stringify(descriptor)}\n`);
			writeFileSync(join(incidentDirectory, record.name), changed, { mode: 0o600 });
			record.bytes = changed.length;
			record.sha256 = digest(changed);
		}
		writeFileSync(
			join(incidentDirectory, "finalization-manifest.json"),
			Buffer.from(`${JSON.stringify(sourceManifest)}\n`),
			{ mode: 0o600 },
		);
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId: `run-${runId}` })).toMatchObject({
			state: "pending",
			reason: "finalization_standard_semantics_invalid",
		});
	});

	it("rejects a valid terminal package copied under a different run-addressed incident name", () => {
		const target = root();
		const sourceIncidents = join(target, "source");
		const source = finalizeIncidentRecorderProjection(input(sourceIncidents, "/physical"));
		const incidentsDirectory = join(target, "target");
		const wrongIncidentId = "run-55555555-5555-4555-8555-555555555555";
		const wrongDirectory = join(incidentsDirectory, wrongIncidentId);
		mkdirSync(wrongDirectory, { recursive: true, mode: 0o700 });
		for (const name of [
			"finalization-intent.json",
			"run-history.json",
			"finalization-descriptor.json",
			"summary.json",
			"finalization-manifest.json",
		]) {
			writeFileSync(join(wrongDirectory, name), readFileSync(join(source.incidentDirectory, name)), { mode: 0o600 });
		}
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId: wrongIncidentId })).toEqual({
			state: "pending",
			reason: "finalization_incident_address_mismatch",
		});
	});

	it("publishes immutable files with the manifest last and releases the lease after prepared durability", () => {
		const target = root();
		const lease: string[] = [];
		const linked: string[] = [];
		const boundaries: string[] = [];
		const result = finalizeIncidentRecorderProjection(input(join(target, "incidents"), "/physical", lease), {
			fs: {
				link: (source, destination) => {
					linked.push(destination.toString());
					linkSync(source, destination);
				},
			},
			onFaultBoundary: (boundary) => boundaries.push(boundary),
		});

		expect(result.state).toBe("complete");
		expect(result.publication).toBe("applied");
		expect(result.supervisorExitAnchorWallTimeMs).toBe(1000);
		expect(lease.at(-1)).toBe("release");
		expect(lease.filter((value) => value === "release")).toHaveLength(1);
		expect(boundaries.indexOf("after_manifest_rename_before_directory_fsync")).toBeLessThan(
			boundaries.indexOf("after_prepared_directory_fsync_before_lease_release"),
		);
		expect(boundaries.indexOf("after_prepared_directory_fsync_before_lease_release")).toBeLessThan(
			boundaries.indexOf("after_projection_lease_release_before_publish"),
		);
		const published = linked.filter((path) => path.endsWith("/finalization-manifest.json"));
		expect(published.length).toBeGreaterThan(0);
		expect(published.at(-1)?.endsWith("/finalization-manifest.json")).toBe(true);
		expect(existsSync(join(result.incidentDirectory, "finalization-intent.json"))).toBe(true);
		expect(existsSync(join(result.incidentDirectory, "run-history.json"))).toBe(true);
		expect(existsSync(join(result.incidentDirectory, "finalization-descriptor.json"))).toBe(true);
		expect(existsSync(join(result.incidentDirectory, "summary.json"))).toBe(true);
		expect(
			inspectPublishedIncidentFinalization({
				incidentsDirectory: join(target, "incidents"),
				incidentId: `run-${runId}`,
			}),
		).toMatchObject({
			state: "complete",
			finalizationId: result.finalizationId,
			serviceTerminalRelayDisposition: "relayed",
		});
	});

	it("replays exact bytes as a no-op and never overwrites a different semantic publication", () => {
		const target = root();
		const first = finalizeIncidentRecorderProjection(input(join(target, "incidents"), "/one"));
		const lease: string[] = [];
		const replay = finalizeIncidentRecorderProjection(input(join(target, "incidents"), "/two", lease));
		expect(first.state).toBe("complete");
		expect(replay).toMatchObject({ state: "complete", publication: "noop" });
		expect(lease.filter((value) => value === "release")).toHaveLength(1);

		const conflictInput = input(join(target, "incidents"), "/three");
		conflictInput.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
		const conflict = finalizeIncidentRecorderProjection(conflictInput);
		expect(conflict).toMatchObject({
			state: "complete",
			finalizationId: first.finalizationId,
			reason: "published_finalization_conflict",
		});
		const manifest = JSON.parse(
			readFileSync(join(first.incidentDirectory, "finalization-manifest.json"), "utf8"),
		) as { finalizationId: string };
		expect(manifest.finalizationId).toBe(first.finalizationId);
	});

	it("distinguishes absent, invalid, and exact authorized retention authority", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		expect(published).toMatchObject({
			state: "complete",
			retentionAnchorWallTimeMs: 1000,
		});
		const inspectionInput = { incidentsDirectory, incidentId };
		expect(inspectIncidentRetentionAuthority(inspectionInput)).toEqual({
			state: "absent",
			reason: "retention_authority_missing",
		});

		const authority: IncidentRecorderRetentionAuthority = {
			schemaVersion: 1,
			kind: "incident_retention_authority",
			finalizationId: published.finalizationId,
			runId,
			outcome: "complete",
			retentionAnchorWallTimeMs: 1000,
		};
		const authorityPath = join(incidentsDirectory, incidentId, "retention-authority.json");
		writeFileSync(authorityPath, `${JSON.stringify({ ...authority, retentionAnchorWallTimeMs: 1001 })}\n`, {
			mode: 0o600,
		});
		expect(inspectIncidentRetentionAuthority(inspectionInput)).toEqual({
			state: "invalid",
			reason: "retention_authority_finalization_mismatch",
		});

		writeFileSync(authorityPath, `${JSON.stringify(authority)}\n`, { mode: 0o600 });
		expect(inspectIncidentRetentionAuthority(inspectionInput)).toEqual({
			state: "authorized",
			...authority,
			authoritySource: "primary",
			retentionClass: "diagnostic",
		});
	});

	it("never follows a terminal-manifest pathname swapped to a symlink before open", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const manifestPath = join(published.incidentDirectory, "finalization-manifest.json");
		const backing = join(target, "manifest-backing.json");
		writeFileSync(backing, readFileSync(manifestPath), { mode: 0o600 });
		let swapped = false;
		const inspection = inspectPublishedIncidentFinalization(
			{ incidentsDirectory, incidentId },
			{
				fs: {
					open: (path, flags, mode) => {
						if (
							!swapped &&
							(path.toString() === manifestPath || path.toString().endsWith("/finalization-manifest.json"))
						) {
							swapped = true;
							unlinkSync(manifestPath);
							symlinkSync(backing, manifestPath);
						}
						return openSync(path, flags, mode);
					},
				},
			},
		);
		expect(swapped).toBe(true);
		expect(inspection).toMatchObject({ state: "pending" });
	});

	it("fails closed when the incident directory is replaced between binding and mutation", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const incidentDirectory = join(incidentsDirectory, incidentId);
		const detachedDirectory = join(target, "detached-incident");
		const successorDirectory = join(target, "successor-incident");
		mkdirSync(successorDirectory, { recursive: true, mode: 0o700 });
		let swapped = false;

		const result = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (!swapped && boundary === "after_partial_mkdir_before_parent_fsync") {
					swapped = true;
					renameSync(incidentDirectory, detachedDirectory);
					symlinkSync(successorDirectory, incidentDirectory);
				}
			},
		});

		expect(swapped).toBe(true);
		expect(result).toMatchObject({
			state: "ambiguous",
			publication: "ambiguous",
		});
		expect(snapshotDirectory(successorDirectory)).toEqual({});
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toEqual({
			state: "pending",
			reason: "finalization_incident_directory_invalid",
		});
	});

	it("reports retention persistence as pending when its bound incident is replaced", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const incidentDirectory = published.incidentDirectory;
		const detachedDirectory = join(target, "detached-retention-incident");
		const successorDirectory = join(target, "successor-retention-incident");
		mkdirSync(successorDirectory, { recursive: true, mode: 0o700 });
		const primaryPath = join(incidentDirectory, "retention-authority.json");
		writeFileSync(primaryPath, "foreign-primary\n", { mode: 0o600 });
		let swapped = false;

		const result = persistIncidentRetentionAuthority(
			retentionPersistenceInput(incidentDirectory, published.finalizationId),
			{
				onRetentionAuthorityFaultBoundary: (boundary) => {
					if (!swapped && boundary === "after_retention_intended_authority_durable") {
						swapped = true;
						renameSync(incidentDirectory, detachedDirectory);
						symlinkSync(successorDirectory, incidentDirectory);
					}
				},
			},
		);

		expect(swapped).toBe(true);
		expect(result).toEqual({
			state: "pending",
			reason: "finalization_incident_directory_detached",
		});
		expect(snapshotDirectory(successorDirectory)).toEqual({});
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toEqual({
			state: "pending",
			reason: "finalization_incident_directory_invalid",
		});
	});

	it("rejects a retention authority pathname replaced during descriptor-bound read", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const authority: IncidentRecorderRetentionAuthority = {
			schemaVersion: 1,
			kind: "incident_retention_authority",
			finalizationId: published.finalizationId,
			runId,
			outcome: "complete",
			retentionAnchorWallTimeMs: 1000,
		};
		const authorityPath = join(published.incidentDirectory, "retention-authority.json");
		const authorityBytes = Buffer.from(`${JSON.stringify(authority)}\n`);
		writeFileSync(authorityPath, authorityBytes, { mode: 0o600 });
		const authorityStat = lstatSync(authorityPath, { bigint: true });
		let swapped = false;
		const injectedRead = ((
			descriptor: number,
			buffer: Buffer,
			offset: number,
			length: number,
			position: number | null,
		) => {
			const opened = fstatSync(descriptor, { bigint: true });
			const count = readSync(descriptor, buffer, offset, length, position);
			if (!swapped && opened.dev === authorityStat.dev && opened.ino === authorityStat.ino) {
				swapped = true;
				unlinkSync(authorityPath);
				writeFileSync(authorityPath, authorityBytes, { mode: 0o600 });
				chmodSync(authorityPath, 0o644);
			}
			return count;
		}) as typeof readSync;
		expect(
			inspectIncidentRetentionAuthority({ incidentsDirectory, incidentId }, { fs: { read: injectedRead } }),
		).toMatchObject({ state: "invalid" });
		expect(swapped).toBe(true);
	});

	it("persists and replays an exact primary retention authority through the exported protocol", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const persistenceInput = retentionPersistenceInput(published.incidentDirectory, published.finalizationId);
		const authorityRoot = join(published.incidentDirectory, ".finalization-authority-root");
		const claimPath = join(authorityRoot, finalizationClaimName);
		const claimBefore = snapshotPathIdentity(claimPath);

		expect(persistIncidentRetentionAuthority(persistenceInput)).toMatchObject({
			state: "authorized",
			publication: "applied",
			authoritySource: "primary",
			retentionClass: "diagnostic",
			finalizationId: published.finalizationId,
		});
		expect(persistIncidentRetentionAuthority(persistenceInput)).toMatchObject({
			state: "authorized",
			publication: "noop",
			authoritySource: "primary",
			retentionClass: "diagnostic",
		});
		expect(inspectIncidentRetentionAuthority({ incidentsDirectory, incidentId })).toMatchObject({
			state: "authorized",
			authoritySource: "primary",
			retentionClass: "diagnostic",
		});
		expect(readdirSync(authorityRoot).sort()).toEqual([finalizationClaimName]);
		expect(snapshotPathIdentity(claimPath)).toEqual(claimBefore);
	});

	it("persists authority for a production-style safe incident name bound by the published manifest", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const productionIncidentId = `expired-1756684800000-service-${runId}`;
		const finalizationInput = input(incidentsDirectory, "/physical");
		finalizationInput.incidentId = productionIncidentId;
		const published = finalizeIncidentRecorderProjection(finalizationInput);
		const authorityRoot = join(published.incidentDirectory, ".finalization-authority-root");
		const claimPath = join(authorityRoot, finalizationClaimName);
		const claimBefore = snapshotPathIdentity(claimPath);

		expect(
			persistIncidentRetentionAuthority(
				retentionPersistenceInput(published.incidentDirectory, published.finalizationId),
			),
		).toMatchObject({
			state: "authorized",
			publication: "applied",
			authoritySource: "primary",
			finalizationId: published.finalizationId,
			runId,
		});
		expect(inspectIncidentRetentionAuthority({ incidentsDirectory, incidentId: productionIncidentId })).toMatchObject(
			{
				state: "authorized",
				authoritySource: "primary",
				finalizationId: published.finalizationId,
				runId,
			},
		);
		expect(snapshotPathIdentity(claimPath)).toEqual(claimBefore);
	});

	it("rejects relocated standard packages at production and partial incident basenames", () => {
		const target = root();
		const sourceIncidents = join(target, "source-incidents");
		const sourceIncidentId = `service-1756684800000-${runId}`;
		const finalizationInput = input(sourceIncidents, "/physical");
		finalizationInput.incidentId = sourceIncidentId;
		const published = finalizeIncidentRecorderProjection(finalizationInput);
		const foreignRunId = "55555555-5555-4555-8555-555555555555";
		const destinationIncidents = join(target, "destination-incidents");
		mkdirSync(destinationIncidents, { recursive: true, mode: 0o700 });
		for (const destinationIncidentId of [
			`service-1756684800001-${foreignRunId}`,
			`.service-1756684800001-${foreignRunId}.partial-${published.finalizationId}`,
		]) {
			const destination = join(destinationIncidents, destinationIncidentId);
			mkdirSync(destination, { mode: 0o700 });
			for (const name of [
				"finalization-intent.json",
				"run-history.json",
				"finalization-descriptor.json",
				"summary.json",
				"finalization-manifest.json",
			]) {
				cpSync(join(published.incidentDirectory, name), join(destination, name));
			}
			expect(
				inspectPublishedIncidentFinalization({
					incidentsDirectory: destinationIncidents,
					incidentId: destinationIncidentId,
				}),
			).toEqual({ state: "pending", reason: "finalization_incident_address_mismatch" });
		}
	});

	it("rejects caller run and finalization tuples that do not match a production-style publication", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const productionIncidentId = `service-1756684800000-${runId}`;
		const finalizationInput = input(incidentsDirectory, "/physical");
		finalizationInput.incidentId = productionIncidentId;
		const published = finalizeIncidentRecorderProjection(finalizationInput);
		const exactInput = retentionPersistenceInput(published.incidentDirectory, published.finalizationId);
		const authorityRoot = join(published.incidentDirectory, ".finalization-authority-root");
		const claimPath = join(authorityRoot, finalizationClaimName);
		const claimBefore = snapshotPathIdentity(claimPath);

		expect(
			persistIncidentRetentionAuthority({
				...exactInput,
				runId: "55555555-5555-4555-8555-555555555555",
			}),
		).toEqual({
			state: "pending",
			reason: "retention_authority_persistence_finalization_mismatch",
		});
		expect(
			persistIncidentRetentionAuthority({
				...exactInput,
				finalizationId: "0".repeat(64),
			}),
		).toEqual({
			state: "pending",
			reason: "retention_authority_persistence_finalization_mismatch",
		});
		expect(existsSync(join(published.incidentDirectory, "retention-authority.json"))).toBe(false);
		expect(readdirSync(authorityRoot).sort()).toEqual([finalizationClaimName]);
		expect(snapshotPathIdentity(claimPath)).toEqual(claimBefore);
	});

	it.each([
		{
			name: "malformed private bytes",
			disposition: "exact_private_bytes",
			reason: "retention_authority_invalid_json",
			setup: (path: string) => writeFileSync(path, "not-json\n", { mode: 0o600 }),
		},
		{
			name: "tuple-mismatched private authority",
			disposition: "exact_private_bytes",
			reason: "retention_authority_finalization_mismatch",
			setup: (path: string, _target: string, _intended: Buffer, finalizationId: string) =>
				writeFileSync(
					path,
					`${JSON.stringify({
						schemaVersion: 1,
						kind: "incident_retention_authority",
						finalizationId,
						runId,
						outcome: "complete",
						retentionAnchorWallTimeMs: 1001,
					})}\n`,
					{ mode: 0o600 },
				),
		},
		{
			name: "symlink",
			disposition: "symlink",
			reason: "retention_authority_identity_invalid",
			setup: (path: string, target: string) => {
				const backing = join(target, "retention-symlink-backing.json");
				writeFileSync(backing, "outside\n", { mode: 0o600 });
				symlinkSync(backing, path);
			},
		},
		{
			name: "unrelated hardlink",
			disposition: "hardlinked_file",
			reason: "retention_authority_identity_invalid",
			setup: (path: string, target: string) => {
				const backing = join(target, "retention-hardlink-backing.json");
				writeFileSync(backing, "hardlinked\n", { mode: 0o600 });
				linkSync(backing, path);
			},
		},
		{
			name: "public exact authority",
			disposition: "non_private_file",
			reason: "retention_authority_identity_invalid",
			setup: (path: string, _target: string, intended: Buffer) => {
				writeFileSync(path, intended, { mode: 0o600 });
				chmodSync(path, 0o644);
			},
		},
		{
			name: "oversized authority",
			disposition: "oversized_file",
			reason: "retention_authority_identity_invalid",
			setup: (path: string) => writeFileSync(path, Buffer.alloc(8 * 1024 + 1, 0x61), { mode: 0o600 }),
		},
	] satisfies Array<{
		name: string;
		disposition: string;
		reason: string;
		setup: (path: string, target: string, intended: Buffer, finalizationId: string) => void;
	}>)("terminalizes a $name primary conflict without changing the primary inode or bytes", (testCase) => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const persistenceInput = retentionPersistenceInput(published.incidentDirectory, published.finalizationId);
		const intended = Buffer.from(
			`${JSON.stringify({
				schemaVersion: 1,
				kind: "incident_retention_authority",
				finalizationId: published.finalizationId,
				runId,
				outcome: "complete",
				retentionAnchorWallTimeMs: 1000,
			})}\n`,
		);
		const primaryPath = join(published.incidentDirectory, "retention-authority.json");
		const authorityRoot = join(published.incidentDirectory, ".finalization-authority-root");
		const claimPath = join(authorityRoot, finalizationClaimName);
		const claimBefore = snapshotPathIdentity(claimPath);
		testCase.setup(primaryPath, target, intended, published.finalizationId);
		const primaryBefore = snapshotPathIdentity(primaryPath);

		expect(persistIncidentRetentionAuthority(persistenceInput), testCase.name).toMatchObject({
			state: "authorized",
			publication: "applied",
			authoritySource: "conflict",
			retentionClass: "corrupt",
			finalizationId: published.finalizationId,
			runId,
			outcome: "complete",
			retentionAnchorWallTimeMs: 1000,
		});
		expect(snapshotPathIdentity(primaryPath), testCase.name).toEqual(primaryBefore);
		expect(readdirSync(authorityRoot).sort(), testCase.name).toEqual(resolvedRetentionAuthorityRootEntries);
		expect(snapshotPathIdentity(claimPath), testCase.name).toEqual(claimBefore);
		const conflict = JSON.parse(readFileSync(join(authorityRoot, "retention-authority-conflict.json"), "utf8")) as {
			reason: string;
			observedPrimary: { disposition: string; bytesBase64?: string };
		};
		expect(conflict.reason, testCase.name).toBe(testCase.reason);
		expect(conflict.observedPrimary.disposition, testCase.name).toBe(testCase.disposition);
		if (testCase.disposition === "exact_private_bytes") {
			expect(Buffer.from(conflict.observedPrimary.bytesBase64 ?? "", "base64"), testCase.name).toEqual(
				readFileSync(primaryPath),
			);
		} else {
			expect(conflict.observedPrimary).not.toHaveProperty("bytesBase64");
		}
		expect(inspectIncidentRetentionAuthority({ incidentsDirectory, incidentId }), testCase.name).toMatchObject({
			state: "authorized",
			authoritySource: "conflict",
			retentionClass: "corrupt",
			finalizationId: published.finalizationId,
		});
		const resolvedSnapshot = snapshotDirectory(published.incidentDirectory);
		expect(persistIncidentRetentionAuthority(persistenceInput), testCase.name).toMatchObject({
			state: "authorized",
			publication: "noop",
			authoritySource: "conflict",
			retentionClass: "corrupt",
		});
		expect(snapshotDirectory(published.incidentDirectory), testCase.name).toEqual(resolvedSnapshot);
		expect(snapshotPathIdentity(primaryPath), testCase.name).toEqual(primaryBefore);
		expect(snapshotPathIdentity(claimPath), testCase.name).toEqual(claimBefore);
	});

	it("retries a raced primary observation using only bounded fixed control names", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const persistenceInput = retentionPersistenceInput(published.incidentDirectory, published.finalizationId);
		const primaryPath = join(published.incidentDirectory, "retention-authority.json");
		const authorityRoot = join(published.incidentDirectory, ".finalization-authority-root");
		const claimPath = join(authorityRoot, finalizationClaimName);
		const claimBefore = snapshotPathIdentity(claimPath);
		writeFileSync(primaryPath, "first-malformed\n", { mode: 0o600 });
		const firstIdentity = lstatSync(primaryPath, { bigint: true });
		let primaryReads = 0;
		let swapped = false;
		const racedRead = ((
			descriptor: number,
			buffer: Buffer,
			offset: number,
			length: number,
			position: number | null,
		) => {
			const opened = fstatSync(descriptor, { bigint: true });
			const count = readSync(descriptor, buffer, offset, length, position);
			if (opened.dev === firstIdentity.dev && opened.ino === firstIdentity.ino) {
				primaryReads += 1;
				if (primaryReads === 2) {
					unlinkSync(primaryPath);
					writeFileSync(primaryPath, "second-malformed\n", { mode: 0o600 });
					swapped = true;
				}
			}
			return count;
		}) as typeof readSync;

		expect(persistIncidentRetentionAuthority(persistenceInput, { fs: { read: racedRead } })).toEqual({
			state: "pending",
			reason: "retention_authority_observation_unstable",
		});
		expect(swapped).toBe(true);
		expect(readdirSync(authorityRoot).sort()).toEqual([finalizationClaimName, "retention-authority-intended.json"]);
		expect(snapshotPathIdentity(claimPath)).toEqual(claimBefore);
		const racedPrimary = snapshotPathIdentity(primaryPath);
		expect(persistIncidentRetentionAuthority(persistenceInput)).toMatchObject({
			state: "authorized",
			authoritySource: "conflict",
			retentionClass: "corrupt",
		});
		expect(snapshotPathIdentity(primaryPath)).toEqual(racedPrimary);
		expect(readdirSync(authorityRoot).sort()).toEqual(resolvedRetentionAuthorityRootEntries);
		expect(snapshotPathIdentity(claimPath)).toEqual(claimBefore);
	});

	it.each(INCIDENT_RECORDER_RETENTION_AUTHORITY_FAULT_BOUNDARIES)(
		"converges after the %s conflict-publication fault boundary",
		(boundary) => {
			const target = root();
			const incidentsDirectory = join(target, "incidents");
			const incidentId = `run-${runId}`;
			const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
			const persistenceInput = retentionPersistenceInput(published.incidentDirectory, published.finalizationId);
			const primaryPath = join(published.incidentDirectory, "retention-authority.json");
			const authorityRoot = join(published.incidentDirectory, ".finalization-authority-root");
			const claimPath = join(authorityRoot, finalizationClaimName);
			const claimBefore = snapshotPathIdentity(claimPath);
			writeFileSync(primaryPath, "malformed\n", { mode: 0o600 });
			const primaryBefore = snapshotPathIdentity(primaryPath);

			expect(
				persistIncidentRetentionAuthority(persistenceInput, {
					onRetentionAuthorityFaultBoundary: (observed) => {
						if (observed === boundary) throw new Error(`fault:${boundary}`);
					},
				}),
			).toMatchObject({ state: "pending" });
			expect(snapshotPathIdentity(primaryPath)).toEqual(primaryBefore);
			expect(snapshotPathIdentity(claimPath)).toEqual(claimBefore);
			const interruptedInspection = inspectIncidentRetentionAuthority({ incidentsDirectory, incidentId });
			if (boundary === "after_retention_manifest_durable_before_readback") {
				expect(interruptedInspection).toMatchObject({
					state: "authorized",
					authoritySource: "conflict",
					retentionClass: "corrupt",
				});
			} else {
				expect(interruptedInspection.state).not.toBe("authorized");
			}

			expect(persistIncidentRetentionAuthority(persistenceInput)).toMatchObject({
				state: "authorized",
				authoritySource: "conflict",
				retentionClass: "corrupt",
			});
			expect(snapshotPathIdentity(primaryPath)).toEqual(primaryBefore);
			expect(snapshotPathIdentity(claimPath)).toEqual(claimBefore);
			expect(readdirSync(authorityRoot).sort()).toEqual(resolvedRetentionAuthorityRootEntries);
			for (const name of resolvedRetentionAuthorityRootEntries) {
				expect(lstatSync(join(authorityRoot, name), { bigint: true }).nlink, name).toBe(1n);
			}
			expect(readdirSync(authorityRoot).some((name) => name.endsWith(".tmp"))).toBe(false);
		},
	);

	it("uses a bounded alternate temp while preserving a poisoned canonical retention temp", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const persistenceInput = retentionPersistenceInput(published.incidentDirectory, published.finalizationId);
		const intendedBytes = Buffer.from(
			`${JSON.stringify({
				schemaVersion: 1,
				kind: "incident_retention_authority",
				finalizationId: persistenceInput.finalizationId,
				runId: persistenceInput.runId,
				outcome: persistenceInput.outcome,
				retentionAnchorWallTimeMs: persistenceInput.retentionAnchorWallTimeMs,
			})}\n`,
		);
		const poisoned = join(published.incidentDirectory, `.retention-authority.json.${digest(intendedBytes)}.tmp`);
		writeFileSync(poisoned, "poisoned canonical staging occupant", { mode: 0o600 });
		const poisonBefore = snapshotPathIdentity(poisoned);

		expect(persistIncidentRetentionAuthority(persistenceInput)).toMatchObject({
			state: "authorized",
			authoritySource: "primary",
			publication: "applied",
		});
		expect(snapshotPathIdentity(poisoned)).toEqual(poisonBefore);
		expect(
			readdirSync(published.incidentDirectory).some((name) =>
				/^\.retention-authority\.json\.[0-9a-f]{64}\.[1-7]\.tmp$/.test(name),
			),
		).toBe(false);
	});

	it("fails closed after all bounded retention staging slots are poisoned", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const persistenceInput = retentionPersistenceInput(published.incidentDirectory, published.finalizationId);
		const intendedBytes = Buffer.from(
			`${JSON.stringify({
				schemaVersion: 1,
				kind: "incident_retention_authority",
				finalizationId: persistenceInput.finalizationId,
				runId: persistenceInput.runId,
				outcome: persistenceInput.outcome,
				retentionAnchorWallTimeMs: persistenceInput.retentionAnchorWallTimeMs,
			})}\n`,
		);
		const contentHash = digest(intendedBytes);
		const poisonedPaths = Array.from({ length: 8 }, (_, index) =>
			join(
				published.incidentDirectory,
				index === 0
					? `.retention-authority.json.${contentHash}.tmp`
					: `.retention-authority.json.${contentHash}.${index}.tmp`,
			),
		);
		for (const [index, path] of poisonedPaths.entries()) {
			writeFileSync(path, `poison-${index}`, { mode: 0o600 });
		}
		const before = poisonedPaths.map(snapshotPathIdentity);

		expect(persistIncidentRetentionAuthority(persistenceInput)).toEqual({
			state: "pending",
			reason: "retention_authority_observation_unstable",
		});
		expect(persistIncidentRetentionAuthority(persistenceInput)).toEqual({
			state: "pending",
			reason: "retention_authority_observation_unstable",
		});
		expect(poisonedPaths.map(snapshotPathIdentity)).toEqual(before);
		expect(existsSync(join(published.incidentDirectory, "retention-authority.json"))).toBe(false);
	});

	it.each([
		"retention-authority-intended.json",
		"retention-authority-conflict.json",
		"retention-authority-manifest.json",
	])("fails closed without changing a second-order %s conflict", (controlName) => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const persistenceInput = retentionPersistenceInput(published.incidentDirectory, published.finalizationId);
		const primaryPath = join(published.incidentDirectory, "retention-authority.json");
		writeFileSync(primaryPath, "malformed\n", { mode: 0o600 });
		const authorityRoot = join(published.incidentDirectory, ".finalization-authority-root");
		const claimPath = join(authorityRoot, finalizationClaimName);
		const claimBefore = snapshotPathIdentity(claimPath);
		const poisonedPath = join(authorityRoot, controlName);
		writeFileSync(poisonedPath, "second-order-poison\n", { mode: 0o600 });
		const primaryBefore = snapshotPathIdentity(primaryPath);
		const poisonBefore = snapshotPathIdentity(poisonedPath);
		const rootBefore = snapshotDirectory(authorityRoot);

		expect(persistIncidentRetentionAuthority(persistenceInput)).toMatchObject({ state: "pending" });
		expect(persistIncidentRetentionAuthority(persistenceInput)).toMatchObject({ state: "pending" });
		expect(snapshotPathIdentity(primaryPath)).toEqual(primaryBefore);
		expect(snapshotPathIdentity(poisonedPath)).toEqual(poisonBefore);
		expect(snapshotPathIdentity(claimPath)).toEqual(claimBefore);
		expect(snapshotDirectory(authorityRoot)).toEqual(rootBefore);
	});

	it("durably classifies tail loss and unavailable service terminal as incomplete", () => {
		const target = root();
		const lossy = input(join(target, "lossy"), "/physical");
		lossy.wrapperLoss.finalQueuedTailLoss.records = 1;
		const lossResult = finalizeIncidentRecorderProjection(lossy);
		expect(lossResult.state).toBe("incomplete");
		expect(lossResult.reasons).toContain("wrapper_final_queued_tail_loss");

		const unavailable = input(join(target, "unavailable"), "/physical");
		unavailable.terminalExpectations.serviceTerminal = {
			state: "unavailable",
			reason: "service_crashed_before_seal",
		};
		unavailable.assertProjectionLeaseUsable = undefined;
		unavailable.releaseProjectionLease = undefined;
		const unavailableResult = finalizeIncidentRecorderProjection(unavailable);
		expect(unavailableResult.state).toBe("incomplete");
		expect(unavailableResult.reasons).toContain("service_terminal_unavailable:service_crashed_before_seal");
	});

	it("classifies contradictory projection evidence as corrupt", () => {
		const target = root();
		const corrupt = input(join(target, "incidents"), "/physical");
		if (corrupt.runHistory.state === "complete") {
			corrupt.runHistory.projection.evidence.push({ kind: "corrupt", reason: "semantic_conflict" });
		}
		expect(finalizeIncidentRecorderProjection(corrupt)).toMatchObject({
			state: "corrupt",
			reasons: ["run_history_corrupt:semantic_conflict"],
		});
	});

	it("returns ambiguous after a published parent-fsync failure and recovers without reprojection", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		let publishedManifestLinked = false;
		let injected = false;
		let manifestLinks = 0;
		const lease: string[] = [];
		const ambiguous = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical", lease), {
			fs: {
				link: (source, destination) => {
					linkSync(source, destination);
					if (
						destination === join(incidentsDirectory, `run-${runId}`, "finalization-manifest.json") ||
						(destination.toString().endsWith("/finalization-manifest.json") && manifestLinks++ === 1)
					) {
						publishedManifestLinked = true;
					}
				},
				fsync: (descriptor) => {
					fsyncSync(descriptor);
					const stat = fstatSync(descriptor);
					if (stat.isDirectory() && publishedManifestLinked && !injected) {
						injected = true;
						throw undefined;
					}
				},
			},
		});
		expect(ambiguous.state).toBe("ambiguous");
		expect(lease).toContain("release");
		expect(
			inspectPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId: `run-${runId}`,
			}).state,
		).toBe("complete");
		expect(
			recoverPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId: `run-${runId}`,
			}).state,
		).toBe("complete");
	});

	it("recovers a close/fsync ambiguity on a second exact pass and releases only then", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		let closes = 0;
		const firstLease: string[] = [];
		const first = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical", firstLease), {
			fs: {
				close: (descriptor) => {
					closeSync(descriptor);
					closes += 1;
					if (closes === 1) throw undefined;
				},
			},
		});
		expect(first.state).toBe("ambiguous");
		expect(firstLease).not.toContain("release");

		const secondLease: string[] = [];
		const second = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/other", secondLease));
		expect(second.state).toBe("complete");
		expect(secondLease.filter((value) => value === "release")).toHaveLength(1);
	});

	it("publishes a durable prepared finalization idempotently after restart", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const lease: string[] = [];
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical", lease), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") {
					throw new Error("simulated restart after prepared finalization");
				}
			},
		});
		expect(interrupted).toMatchObject({ state: "ambiguous", publication: "ambiguous" });
		expect(lease.filter((value) => value === "release")).toHaveLength(1);
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${interrupted.finalizationId}`);
		expect(existsSync(join(partialDirectory, "finalization-manifest.json"))).toBe(true);
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId }).state).toBe("pending");

		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: interrupted.finalizationId,
		});
		expect(recovered).toMatchObject({
			state: "complete",
			finalizationId: interrupted.finalizationId,
		});
		expect(existsSync(partialDirectory)).toBe(false);
		const manifestPath = join(incidentsDirectory, incidentId, "finalization-manifest.json");
		const manifest = readFileSync(manifestPath);

		expect(
			recoverPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: interrupted.finalizationId,
			}),
		).toMatchObject({
			state: "complete",
			finalizationId: interrupted.finalizationId,
		});
		expect(readFileSync(manifestPath)).toEqual(manifest);
	});

	it("terminalizes a prepared destination collision as durable corrupt evidence without overwriting either side", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") {
					throw new Error("simulated restart with a durable prepared finalization");
				}
			},
		});
		expect(interrupted).toMatchObject({ state: "ambiguous", publication: "ambiguous" });
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${interrupted.finalizationId}`);
		const intendedHistory = readFileSync(join(partialDirectory, "run-history.json"));
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		const observedHistory = Buffer.from('{"foreign":"history"}\n', "utf8");
		writeFileSync(join(incidentDirectory, "run-history.json"), observedHistory, { mode: 0o600 });

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
		expect(readFileSync(join(incidentDirectory, "run-history.json"))).toEqual(observedHistory);
		expect(existsSync(partialDirectory)).toBe(false);
		const selector = JSON.parse(readFileSync(join(incidentDirectory, "finalization-authority.json"), "utf8")) as {
			kind: string;
			manifest: { name: string };
		};
		expect(selector.kind).toBe("incident_recorder_finalization_authority_selector");
		const manifest = JSON.parse(readFileSync(join(incidentDirectory, selector.manifest.name), "utf8")) as {
			kind: string;
			state: string;
			reasons: string[];
			conflictRecord: { name: string };
		};
		expect(manifest).toMatchObject({
			kind: "incident_recorder_finalization_conflict_manifest",
			state: "corrupt",
		});
		expect(manifest.reasons).toContain("published_finalization_file_conflict:run-history.json");
		expect(manifest.conflictRecord.name).toMatch(/^finalization-conflict-[0-9a-f]{64}\.json$/);
		const conflict = JSON.parse(readFileSync(join(incidentDirectory, manifest.conflictRecord.name), "utf8")) as {
			files: Array<{
				logicalName: string;
				prepared: { name: string; bytes: number; sha256: string };
				observed?: {
					disposition: string;
					evidence?: { name: string; bytes: number; sha256: string };
				};
			}>;
			intendedManifest: { name: string };
		};
		const historyConflict = conflict.files.find((entry) => entry.logicalName === "run-history.json");
		expect(historyConflict?.prepared.name).toMatch(/^conflict-prepared-run-history-[0-9a-f]{64}\.json$/);
		expect(historyConflict?.observed?.disposition).toBe("exact_private_bytes");
		expect(historyConflict?.observed?.evidence?.name).toMatch(/^conflict-observed-run-history-[0-9a-f]{64}\.json$/);
		if (!historyConflict?.observed?.evidence) throw new Error("Expected exact run-history conflict evidence");
		expect(readFileSync(join(incidentDirectory, historyConflict.prepared.name))).toEqual(intendedHistory);
		expect(readFileSync(join(incidentDirectory, historyConflict.observed.evidence.name))).toEqual(observedHistory);
		expect(conflict.intendedManifest.name).toMatch(/^conflict-prepared-finalization-manifest-[0-9a-f]{64}\.json$/);

		const beforeReplay = snapshotDirectory(incidentDirectory);
		expect(
			recoverPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: interrupted.finalizationId,
			}),
		).toMatchObject({ state: "corrupt", finalizationId: interrupted.finalizationId });
		expect(snapshotDirectory(incidentDirectory)).toEqual(beforeReplay);
		const directReplayLease: string[] = [];
		expect(
			finalizeIncidentRecorderProjection(input(incidentsDirectory, "/different-physical-root", directReplayLease)),
		).toMatchObject({
			state: "corrupt",
			publication: "noop",
			finalizationId: interrupted.finalizationId,
			reason: "prepared_publication_conflict",
		});
		expect(directReplayLease.filter((event) => event === "release")).toHaveLength(1);
		expect(readFileSync(join(incidentDirectory, "run-history.json"))).toEqual(observedHistory);

		const authority: IncidentRecorderRetentionAuthority = {
			schemaVersion: 1,
			kind: "incident_retention_authority",
			finalizationId: interrupted.finalizationId,
			runId,
			outcome: "corrupt",
			retentionAnchorWallTimeMs: 1000,
		};
		writeFileSync(join(incidentDirectory, "retention-authority.json"), `${JSON.stringify(authority)}\n`, {
			mode: 0o600,
		});
		expect(inspectIncidentRetentionAuthority({ incidentsDirectory, incidentId })).toEqual({
			state: "authorized",
			...authority,
			authoritySource: "primary",
			retentionClass: "corrupt",
		});
	});

	it.each([
		{
			name: "symlink",
			logicalName: "run-history.json",
			disposition: "symlink",
			setup: (path: string, target: string) => {
				const backing = join(target, "symlink-target.json");
				writeFileSync(backing, "symlink target", { mode: 0o600 });
				symlinkSync(backing, path);
			},
		},
		{
			name: "directory",
			logicalName: "run-history.json",
			disposition: "directory",
			setup: (path: string) => mkdirSync(path, { mode: 0o700 }),
		},
		{
			name: "hardlinked file",
			logicalName: "run-history.json",
			disposition: "hardlinked_file",
			setup: (path: string, target: string) => {
				const backing = join(target, "hardlink-source.json");
				writeFileSync(backing, "hardlinked bytes", { mode: 0o600 });
				linkSync(backing, path);
			},
		},
		{
			name: "non-private file",
			logicalName: "run-history.json",
			disposition: "non_private_file",
			setup: (path: string) => {
				writeFileSync(path, "public bytes", { mode: 0o600 });
				chmodSync(path, 0o644);
			},
		},
		{
			name: "oversized file",
			logicalName: "run-history.json",
			disposition: "oversized_file",
			setup: (path: string) => writeFileSync(path, Buffer.alloc(16 * 1024 * 1024 + 1), { mode: 0o600 }),
		},
		{
			name: "manifest directory",
			logicalName: "finalization-manifest.json",
			disposition: "directory",
			setup: (path: string) => mkdirSync(path, { mode: 0o700 }),
		},
	])("terminalizes a $name namespace occupant without following, removing, or overwriting it", (testCase) => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${interrupted.finalizationId}`);
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		const occupantPath = join(incidentDirectory, testCase.logicalName);
		testCase.setup(occupantPath, target);
		const before = lstatSync(occupantPath, { bigint: true });

		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: interrupted.finalizationId,
		});
		expect(recovered).toMatchObject({ state: "corrupt", finalizationId: interrupted.finalizationId });
		expect(existsSync(partialDirectory)).toBe(false);
		const after = lstatSync(occupantPath, { bigint: true });
		expect({
			isDirectory: after.isDirectory(),
			isSymbolicLink: after.isSymbolicLink(),
			size: after.size,
			mode: after.mode,
			nlink: after.nlink,
		}).toEqual({
			isDirectory: before.isDirectory(),
			isSymbolicLink: before.isSymbolicLink(),
			size: before.size,
			mode: before.mode,
			nlink: before.nlink,
		});
		const conflict = selectedConflictRecord(incidentDirectory);
		const disposition =
			testCase.logicalName === "finalization-manifest.json"
				? conflict.manifestConflict?.observed.disposition
				: conflict.files.find((entry) => entry.logicalName === testCase.logicalName)?.observed?.disposition;
		expect(disposition).toBe(testCase.disposition);
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
		});
	});

	it("terminalizes an unreadable private canonical occupant with stable bounded lstat evidence", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		const occupantPath = join(incidentDirectory, "run-history.json");
		writeFileSync(occupantPath, "unreadable bytes", { mode: 0o600 });
		const occupant = lstatSync(occupantPath, { bigint: true });
		const injectedRead = ((
			descriptor: number,
			buffer: Buffer,
			offset: number,
			length: number,
			position: number | null,
		) => {
			const opened = fstatSync(descriptor, { bigint: true });
			if (opened.dev === occupant.dev && opened.ino === occupant.ino) {
				const error = new Error("injected unreadable occupant") as NodeJS.ErrnoException;
				error.code = "EACCES";
				throw error;
			}
			return readSync(descriptor, buffer, offset, length, position);
		}) as typeof readSync;
		const recovered = recoverPublishedIncidentFinalization(
			{
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: interrupted.finalizationId,
			},
			{ fs: { read: injectedRead } },
		);
		expect(recovered).toMatchObject({ state: "corrupt", finalizationId: interrupted.finalizationId });
		expect(readFileSync(occupantPath, "utf8")).toBe("unreadable bytes");
		const conflict = selectedConflictRecord(incidentDirectory);
		expect(conflict.files.find((entry) => entry.logicalName === "run-history.json")?.observed?.disposition).toBe(
			"read_unavailable_or_changed",
		);
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
		});
	});

	it("keeps opaque conflict authority valid after the foreign occupant changes or disappears", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		const occupantPath = join(incidentDirectory, "run-history.json");
		writeFileSync(occupantPath, "foreign insecure bytes", { mode: 0o600 });
		chmodSync(occupantPath, 0o644);
		expect(
			recoverPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: interrupted.finalizationId,
			}),
		).toMatchObject({ state: "corrupt", finalizationId: interrupted.finalizationId });
		unlinkSync(occupantPath);
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
		});
		writeFileSync(occupantPath, "different replacement", { mode: 0o600 });
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
		});
	});

	it.each([
		{
			name: "invalid bytes",
			setup: (path: string) => writeFileSync(path, "invalid selector", { mode: 0o600 }),
		},
		{
			name: "directory",
			setup: (path: string) => mkdirSync(path, { mode: 0o700 }),
		},
		{
			name: "symlink",
			setup: (path: string, target: string) => {
				const backing = join(target, "selector-symlink-target");
				writeFileSync(backing, "selector target", { mode: 0o600 });
				symlinkSync(backing, path);
			},
		},
		{
			name: "non-private file",
			setup: (path: string) => {
				writeFileSync(path, "insecure selector", { mode: 0o600 });
				chmodSync(path, 0o644);
			},
		},
	])("uses the next bounded authority slot when the primary selector is a $name occupant", (testCase) => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${interrupted.finalizationId}`);
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(join(incidentDirectory, "run-history.json"), "conflicting history", { mode: 0o600 });
		const primarySelector = join(incidentDirectory, "finalization-authority.json");
		testCase.setup(primarySelector, target);
		const before = lstatSync(primarySelector, { bigint: true });

		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: interrupted.finalizationId,
		});
		expect(recovered).toMatchObject({ state: "corrupt", finalizationId: interrupted.finalizationId });
		expect(existsSync(partialDirectory)).toBe(false);
		const after = lstatSync(primarySelector, { bigint: true });
		expect({
			isDirectory: after.isDirectory(),
			isSymbolicLink: after.isSymbolicLink(),
			size: after.size,
			mode: after.mode,
			nlink: after.nlink,
		}).toEqual({
			isDirectory: before.isDirectory(),
			isSymbolicLink: before.isSymbolicLink(),
			size: before.size,
			mode: before.mode,
			nlink: before.nlink,
		});
		expect(existsSync(join(incidentDirectory, "finalization-authority-1.json"))).toBe(true);
		expect(
			readdirSync(incidentDirectory).some((name) =>
				/^\.finalization-authority\.json\.[0-9a-f]{64}\.tmp$/.test(name),
			),
		).toBe(false);
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
		});
	});

	it("skips an exact selector byte occupant whose metadata is not private", () => {
		const reference = root();
		const referenceIncidents = join(reference, "incidents");
		const referenceIncident = join(referenceIncidents, `run-${runId}`);
		const referencePrepared = finalizeIncidentRecorderProjection(input(referenceIncidents, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		mkdirSync(referenceIncident, { recursive: true, mode: 0o700 });
		writeFileSync(join(referenceIncident, "run-history.json"), "conflicting history", { mode: 0o600 });
		expect(
			recoverPublishedIncidentFinalization({
				incidentsDirectory: referenceIncidents,
				incidentId: `run-${runId}`,
				expectedFinalizationId: referencePrepared.finalizationId,
			}),
		).toMatchObject({ state: "corrupt" });
		const selectorBytes = readFileSync(join(referenceIncident, "finalization-authority.json"));

		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const prepared = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		expect(prepared.finalizationId).toBe(referencePrepared.finalizationId);
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(join(incidentDirectory, "run-history.json"), "conflicting history", { mode: 0o600 });
		writeFileSync(join(incidentDirectory, "finalization-authority.json"), selectorBytes, { mode: 0o600 });
		chmodSync(join(incidentDirectory, "finalization-authority.json"), 0o644);
		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: prepared.finalizationId,
		});
		expect(recovered).toMatchObject({ state: "corrupt", finalizationId: prepared.finalizationId });
		expect(readFileSync(join(incidentDirectory, "finalization-authority.json"))).toEqual(selectorBytes);
		expect(
			lstatSync(join(incidentDirectory, "finalization-authority.json"), { bigint: true }).mode & 0o077n,
		).not.toBe(0n);
		expect(existsSync(join(incidentDirectory, "finalization-authority-1.json"))).toBe(true);
		expect(existsSync(join(incidentDirectory, `.finalization-authority.json.${digest(selectorBytes)}.tmp`))).toBe(
			false,
		);
	});

	it("uses alternate selector staging paths without overwriting poisoned occupants", () => {
		const reference = root();
		const referenceIncidents = join(reference, "incidents");
		const referenceIncident = join(referenceIncidents, `run-${runId}`);
		const referencePrepared = finalizeIncidentRecorderProjection(input(referenceIncidents, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		mkdirSync(referenceIncident, { recursive: true, mode: 0o700 });
		writeFileSync(join(referenceIncident, "run-history.json"), "conflicting history", { mode: 0o600 });
		recoverPublishedIncidentFinalization({
			incidentsDirectory: referenceIncidents,
			incidentId: `run-${runId}`,
			expectedFinalizationId: referencePrepared.finalizationId,
		});
		const selectorBytes = readFileSync(join(referenceIncident, "finalization-authority.json"));
		const cases: Array<{ name: string; setup: (path: string, target: string) => void }> = [
			{ name: "different bytes", setup: (path) => writeFileSync(path, "poison", { mode: 0o600 }) },
			{ name: "directory", setup: (path) => mkdirSync(path, { mode: 0o700 }) },
			{
				name: "symlink",
				setup: (path, target) => {
					const backing = join(target, "symlink-backing");
					writeFileSync(backing, "poison", { mode: 0o600 });
					symlinkSync(backing, path);
				},
			},
			{
				name: "non-private exact bytes",
				setup: (path) => {
					writeFileSync(path, selectorBytes, { mode: 0o600 });
					chmodSync(path, 0o644);
				},
			},
			{
				name: "hardlink",
				setup: (path, target) => {
					const backing = join(target, "hardlink-backing");
					writeFileSync(backing, selectorBytes, { mode: 0o600 });
					linkSync(backing, path);
				},
			},
		];
		for (const testCase of cases) {
			const target = root();
			const incidentsDirectory = join(target, "incidents");
			const incidentId = `run-${runId}`;
			const prepared = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
				onFaultBoundary: (boundary) => {
					if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
				},
			});
			const incidentDirectory = join(incidentsDirectory, incidentId);
			mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
			writeFileSync(join(incidentDirectory, "run-history.json"), "conflicting history", { mode: 0o600 });
			const poisoned = join(incidentDirectory, `.finalization-authority.json.${digest(selectorBytes)}.tmp`);
			testCase.setup(poisoned, target);
			const before = lstatSync(poisoned, { bigint: true });
			const beforeBytes = before.isFile() && !before.isSymbolicLink() ? readFileSync(poisoned) : undefined;
			expect(
				recoverPublishedIncidentFinalization({
					incidentsDirectory,
					incidentId,
					expectedFinalizationId: prepared.finalizationId,
				}),
				testCase.name,
			).toMatchObject({ state: "corrupt", finalizationId: prepared.finalizationId });
			const after = lstatSync(poisoned, { bigint: true });
			expect(
				{
					dev: after.dev,
					ino: after.ino,
					mode: after.mode,
					size: after.size,
					nlink: after.nlink,
					directory: after.isDirectory(),
					symlink: after.isSymbolicLink(),
				},
				testCase.name,
			).toEqual({
				dev: before.dev,
				ino: before.ino,
				mode: before.mode,
				size: before.size,
				nlink: before.nlink,
				directory: before.isDirectory(),
				symlink: before.isSymbolicLink(),
			});
			if (beforeBytes) expect(readFileSync(poisoned), testCase.name).toEqual(beforeBytes);
			expect(existsSync(join(incidentDirectory, "finalization-authority.json"))).toBe(true);
			expect(existsSync(join(incidentDirectory, "finalization-authority-1.json"))).toBe(false);
			expect(
				readdirSync(incidentDirectory).some((name) =>
					/^\.finalization-authority\.json\.[0-9a-f]{64}\.[1-7]\.tmp$/.test(name),
				),
			).toBe(false);
		}
	});

	it("falls back to the private authority root when all bounded public selector slots are occupied", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(join(incidentDirectory, "run-history.json"), "conflicting history", { mode: 0o600 });
		const occupants: Buffer[] = [];
		for (let index = 0; index < 8; index += 1) {
			const bytes = Buffer.from(`invalid selector ${index}`);
			occupants.push(bytes);
			writeFileSync(
				join(
					incidentDirectory,
					index === 0 ? "finalization-authority.json" : `finalization-authority-${index}.json`,
				),
				bytes,
				{ mode: 0o600 },
			);
		}
		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: interrupted.finalizationId,
		});
		expect(recovered).toMatchObject({
			state: "corrupt",
			finalizationId: interrupted.finalizationId,
			authorityDirectory: join(incidentDirectory, ".finalization-authority-root"),
		});
		for (let index = 0; index < 8; index += 1) {
			expect(
				readFileSync(
					join(
						incidentDirectory,
						index === 0 ? "finalization-authority.json" : `finalization-authority-${index}.json`,
					),
				),
			).toEqual(occupants[index]);
		}
		expect(existsSync(join(incidentDirectory, ".finalization-authority-root", "finalization-authority.json"))).toBe(
			true,
		);
		expect(existsSync(join(incidentsDirectory, `.${incidentId}.partial-${interrupted.finalizationId}`))).toBe(false);
	});

	it("reports a bounded fail-closed reason when the reserved private selector is corrupt", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(join(incidentDirectory, "run-history.json"), "conflicting history", { mode: 0o600 });
		for (let index = 0; index < 8; index += 1) {
			writeFileSync(
				join(
					incidentDirectory,
					index === 0 ? "finalization-authority.json" : `finalization-authority-${index}.json`,
				),
				`invalid public selector ${index}`,
				{ mode: 0o600 },
			);
		}
		const privateRoot = join(incidentDirectory, ".finalization-authority-root");
		mkdirSync(privateRoot, { mode: 0o700 });
		const privateSelector = join(privateRoot, "finalization-authority.json");
		writeFileSync(privateSelector, "invalid private selector", { mode: 0o600 });
		for (let pass = 0; pass < 2; pass += 1) {
			expect(
				recoverPublishedIncidentFinalization({
					incidentsDirectory,
					incidentId,
					expectedFinalizationId: interrupted.finalizationId,
				}),
			).toEqual({ state: "pending", reason: "finalization_private_authority_selector_invalid" });
			expect(readFileSync(privateSelector, "utf8")).toBe("invalid private selector");
			expect(
				readdirSync(privateRoot).some((name) => /^\.finalization-authority\.json\.[0-9a-f]{64}\.tmp$/.test(name)),
			).toBe(false);
		}
	});

	it("moves conflict support to the private root when an exact public support name is insecure", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${interrupted.finalizationId}`);
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(join(incidentDirectory, "run-history.json"), "conflicting history", { mode: 0o600 });
		const preparedHistory = readFileSync(join(partialDirectory, "run-history.json"));
		const supportName = `conflict-prepared-run-history-${digest(preparedHistory)}.json`;
		writeFileSync(join(incidentDirectory, supportName), preparedHistory, { mode: 0o600 });
		chmodSync(join(incidentDirectory, supportName), 0o644);
		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: interrupted.finalizationId,
		});
		expect(recovered).toMatchObject({
			state: "corrupt",
			authorityDirectory: join(incidentDirectory, ".finalization-authority-root"),
		});
		expect(readFileSync(join(incidentDirectory, supportName))).toEqual(preparedHistory);
		expect(lstatSync(join(incidentDirectory, supportName), { bigint: true }).mode & 0o077n).not.toBe(0n);
		expect(existsSync(join(incidentDirectory, `.${supportName}.${digest(preparedHistory)}.tmp`))).toBe(false);
	});

	it("never lets stale prepared recovery supersede an already selected conflict authority", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const firstPrepared = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/first"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared A");
			},
		});
		const incidentDirectory = join(incidentsDirectory, incidentId);
		const blockedManifest = join(incidentDirectory, "finalization-manifest.json");
		expect(
			recoverPublishedIncidentFinalization(
				{
					incidentsDirectory,
					incidentId,
					expectedFinalizationId: firstPrepared.finalizationId,
				},
				{
					fs: {
						link: (source, destination) => {
							if (
								destination.toString() === blockedManifest ||
								destination.toString().endsWith("/finalization-manifest.json")
							) {
								const error = new Error("pre-manifest crash") as NodeJS.ErrnoException;
								error.code = "EIO";
								throw error;
							}
							linkSync(source, destination);
						},
					},
				},
			),
		).toEqual({ state: "pending", reason: "finalization_claimed_prepared_publication_ambiguous" });
		for (const name of [
			"finalization-intent.json",
			"run-history.json",
			"finalization-descriptor.json",
			"summary.json",
		]) {
			expect(existsSync(join(incidentDirectory, name))).toBe(true);
		}
		expect(existsSync(blockedManifest)).toBe(false);

		// Recreate the legacy pre-claim crash shape that motivated the regression.
		const privateRoot = join(incidentDirectory, ".finalization-authority-root");
		unlinkSync(join(privateRoot, "finalization-claim.json"));
		rmdirSync(privateRoot);
		const secondInput = input(incidentsDirectory, "/second");
		secondInput.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
		const selected = finalizeIncidentRecorderProjection(secondInput);
		expect(selected).toMatchObject({ state: "corrupt", reason: "prepared_publication_conflict" });
		expect(selected.finalizationId).not.toBe(firstPrepared.finalizationId);
		expect(existsSync(blockedManifest)).toBe(false);

		const replay = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: firstPrepared.finalizationId,
		});
		expect(replay).toMatchObject({ state: "corrupt", finalizationId: selected.finalizationId });
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "corrupt",
			finalizationId: selected.finalizationId,
		});
		expect(existsSync(blockedManifest)).toBe(false);
		expect(existsSync(join(incidentsDirectory, `.${incidentId}.partial-${firstPrepared.finalizationId}`))).toBe(
			false,
		);
	});

	it("lets the durable claim override a stale expected-id hint and recover its exact stage", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const prepared = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/first"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const incidentDirectory = join(incidentsDirectory, incidentId);
		expect(
			recoverPublishedIncidentFinalization(
				{ incidentsDirectory, incidentId, expectedFinalizationId: prepared.finalizationId },
				{
					fs: {
						link: (source, destination) => {
							if (
								destination.toString() === join(incidentDirectory, "finalization-manifest.json") ||
								destination.toString().endsWith("/finalization-manifest.json")
							) {
								const error = new Error("pre-manifest crash") as NodeJS.ErrnoException;
								error.code = "EIO";
								throw error;
							}
							linkSync(source, destination);
						},
					},
				},
			),
		).toEqual({ state: "pending", reason: "finalization_claimed_prepared_publication_ambiguous" });
		const changed = input(incidentsDirectory, "/changed");
		changed.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
		const staleExpected = analyzeIncidentRecorderFinalization(changed).finalizationId;
		expect(staleExpected).not.toBe(prepared.finalizationId);
		expect(
			recoverPublishedIncidentFinalization({
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: staleExpected,
			}),
		).toMatchObject({ state: "complete", finalizationId: prepared.finalizationId });
		expect(existsSync(join(incidentsDirectory, `.${incidentId}.partial-${prepared.finalizationId}`))).toBe(false);
	});

	it("returns the selected standard tuple and cleans a different stale prepared stage", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const selected = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/selected"));
		expect(selected.state).toBe("complete");

		const stagingIncidents = join(target, "staging-incidents");
		const changed = input(stagingIncidents, "/stale");
		changed.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
		const stale = finalizeIncidentRecorderProjection(changed, {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared B");
			},
		});
		const staleName = `.${incidentId}.partial-${stale.finalizationId}`;
		cpSync(join(stagingIncidents, staleName), join(incidentsDirectory, staleName), { recursive: true });
		chmodSync(join(incidentsDirectory, staleName), 0o700);
		const recovered = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: stale.finalizationId,
		});
		expect(recovered).toMatchObject({
			state: "complete",
			finalizationId: selected.finalizationId,
			authorityDirectory: selected.incidentDirectory,
		});
		expect(existsSync(join(incidentsDirectory, staleName))).toBe(false);
		expect(inspectPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "complete",
			finalizationId: selected.finalizationId,
		});
	});

	it("preserves a replaced stale prepared successor during cleanup", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const selected = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/selected"));
		expect(selected.state).toBe("complete");

		const stagingIncidents = join(target, "staging-incidents");
		const changed = input(stagingIncidents, "/stale");
		changed.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
		const stale = finalizeIncidentRecorderProjection(changed, {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared stale");
			},
		});
		const staleName = `.${incidentId}.partial-${stale.finalizationId}`;
		const partialPath = join(incidentsDirectory, staleName);
		cpSync(join(stagingIncidents, staleName), partialPath, { recursive: true });
		chmodSync(partialPath, 0o700);
		const detachedPath = join(target, "detached-stale");
		let swapped = false;
		let foreignSuccessorBefore: Record<string, string> | undefined;
		const recovered = recoverPublishedIncidentFinalization(
			{
				incidentsDirectory,
				incidentId,
				expectedFinalizationId: stale.finalizationId,
			},
			{
				fs: {
					unlink: (path) => {
						if (!swapped && path.toString().endsWith("/finalization-intent.json")) {
							renameSync(partialPath, detachedPath);
							cpSync(detachedPath, partialPath, { recursive: true });
							chmodSync(partialPath, 0o700);
							foreignSuccessorBefore = snapshotDirectory(partialPath);
							swapped = true;
						}
						unlinkSync(path);
					},
				},
			},
		);

		expect(swapped).toBe(true);
		expect(recovered).toEqual({ state: "pending", reason: "finalization_partial_directory_detached" });
		expect(existsSync(partialPath)).toBe(true);
		expect(snapshotDirectory(partialPath)).toEqual(foreignSuccessorBefore);
	});

	it("preserves a matching stage that appears without a retained binding", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const selected = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/selected"));
		expect(selected.state).toBe("complete");
		const partialName = `.${incidentId}.partial-${selected.finalizationId}`;
		const partialPath = join(incidentsDirectory, partialName);
		let appeared = false;
		const result = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/replay"), {
			fs: {
				lstat: ((path, options) => {
					if (!appeared && path.toString().endsWith(`/${partialName}`)) {
						mkdirSync(partialPath, { mode: 0o700 });
						for (const name of [
							"finalization-intent.json",
							"run-history.json",
							"finalization-descriptor.json",
							"summary.json",
							"finalization-manifest.json",
						]) {
							cpSync(join(selected.incidentDirectory, name), join(partialPath, name));
						}
						appeared = true;
					}
					return lstatSync(path, options);
				}) as IncidentRecorderFinalizationFileSystem["lstat"],
			},
		});

		expect(appeared).toBe(true);
		expect(result).toMatchObject({ state: "ambiguous", publication: "ambiguous" });
		expect(existsSync(partialPath)).toBe(true);
		expect(snapshotDirectory(partialPath)).toEqual({
			"finalization-descriptor.json": expect.any(String),
			"finalization-intent.json": expect.any(String),
			"finalization-manifest.json": expect.any(String),
			"run-history.json": expect.any(String),
			"summary.json": expect.any(String),
		});
	});

	it("adopts the first valid conflict selector when a changed finalization intent arrives", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const interrupted = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"), {
			onFaultBoundary: (boundary) => {
				if (boundary === "after_projection_lease_release_before_publish") throw new Error("prepared");
			},
		});
		const incidentDirectory = join(incidentsDirectory, incidentId);
		mkdirSync(incidentDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(join(incidentDirectory, "run-history.json"), "conflicting history", { mode: 0o600 });
		const selected = recoverPublishedIncidentFinalization({
			incidentsDirectory,
			incidentId,
			expectedFinalizationId: interrupted.finalizationId,
		});
		expect(selected).toMatchObject({ state: "corrupt", finalizationId: interrupted.finalizationId });
		const selectorBytes = readFileSync(join(incidentDirectory, "finalization-authority.json"));

		const changed = input(incidentsDirectory, "/other");
		changed.classification = { value: "kernel_oom_kill", causeLayer: "environment" };
		const changedId = analyzeIncidentRecorderFinalization(changed).finalizationId;
		expect(changedId).not.toBe(interrupted.finalizationId);
		expect(finalizeIncidentRecorderProjection(changed)).toMatchObject({
			state: "corrupt",
			publication: "noop",
			finalizationId: interrupted.finalizationId,
			reason: "published_finalization_conflict",
		});
		expect(readFileSync(join(incidentDirectory, "finalization-authority.json"))).toEqual(selectorBytes);
		expect(existsSync(join(incidentsDirectory, `.${incidentId}.partial-${changedId}`))).toBe(false);
	});

	it("removes exact known temporary bytes while recovering a published finalization", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		expect(published.state).toBe("complete");
		const incidentDirectory = join(incidentsDirectory, incidentId);
		const manifest = JSON.parse(readFileSync(join(incidentDirectory, "finalization-manifest.json"), "utf8")) as {
			files: Array<{ name: string; sha256: string }>;
		};
		const record = manifest.files.find((candidate) => candidate.name === "summary.json");
		if (!record) throw new Error("Expected summary record in finalization manifest");
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${published.finalizationId}`);
		mkdirSync(partialDirectory, { mode: 0o700 });
		const stagedName = `.${record.name}.${record.sha256}.tmp`;
		writeFileSync(join(partialDirectory, stagedName), readFileSync(join(incidentDirectory, record.name)), {
			mode: 0o600,
		});

		expect(recoverPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "complete",
			finalizationId: published.finalizationId,
		});
		expect(existsSync(partialDirectory)).toBe(false);
	});

	it("preserves an exact-byte public occupant in the prepared cleanup namespace", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const incidentDirectory = join(incidentsDirectory, incidentId);
		const manifest = JSON.parse(readFileSync(join(incidentDirectory, "finalization-manifest.json"), "utf8")) as {
			files: Array<{ name: string; sha256: string }>;
		};
		const record = manifest.files.find((candidate) => candidate.name === "summary.json");
		if (!record) throw new Error("Expected summary record in finalization manifest");
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${published.finalizationId}`);
		mkdirSync(partialDirectory, { mode: 0o700 });
		const occupantPath = join(partialDirectory, record.name);
		writeFileSync(occupantPath, readFileSync(join(incidentDirectory, record.name)), { mode: 0o600 });
		chmodSync(occupantPath, 0o644);
		const before = snapshotPathIdentity(occupantPath);

		expect(recoverPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "complete",
			finalizationId: published.finalizationId,
		});
		expect(snapshotPathIdentity(occupantPath)).toEqual(before);
		expect(existsSync(partialDirectory)).toBe(true);
	});

	it("preserves an unrelated hardlink at an exact prepared temporary pathname", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		const incidentDirectory = join(incidentsDirectory, incidentId);
		const manifest = JSON.parse(readFileSync(join(incidentDirectory, "finalization-manifest.json"), "utf8")) as {
			files: Array<{ name: string; sha256: string }>;
		};
		const record = manifest.files.find((candidate) => candidate.name === "summary.json");
		if (!record) throw new Error("Expected summary record in finalization manifest");
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${published.finalizationId}`);
		mkdirSync(partialDirectory, { mode: 0o700 });
		const backingPath = join(target, "unrelated-prepared-backing.json");
		writeFileSync(backingPath, readFileSync(join(incidentDirectory, record.name)), { mode: 0o600 });
		const occupantPath = join(partialDirectory, `.${record.name}.${record.sha256}.tmp`);
		linkSync(backingPath, occupantPath);
		const occupantBefore = snapshotPathIdentity(occupantPath);
		const backingBefore = snapshotPathIdentity(backingPath);

		expect(recoverPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "complete",
			finalizationId: published.finalizationId,
		});
		expect(snapshotPathIdentity(occupantPath)).toEqual(occupantBefore);
		expect(snapshotPathIdentity(backingPath)).toEqual(backingBefore);
		expect(existsSync(partialDirectory)).toBe(true);
	});

	it("returns the proven publication while leaving unknown partial bytes protected", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		expect(published.state).toBe("complete");
		const incidentDirectory = join(incidentsDirectory, incidentId);
		const manifest = JSON.parse(readFileSync(join(incidentDirectory, "finalization-manifest.json"), "utf8")) as {
			files: Array<{ name: string }>;
		};
		const record = manifest.files.find((candidate) => candidate.name === "summary.json");
		if (!record) throw new Error("Expected summary record in finalization manifest");
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${published.finalizationId}`);
		mkdirSync(partialDirectory, { mode: 0o700 });
		const exactPath = join(partialDirectory, record.name);
		cpSync(join(incidentDirectory, record.name), exactPath);
		const exactBefore = snapshotPathIdentity(exactPath);
		const unknownPath = join(partialDirectory, "unknown.tmp");
		writeFileSync(unknownPath, "unknown bytes", { mode: 0o600 });

		expect(recoverPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "complete",
			finalizationId: published.finalizationId,
		});
		expect(snapshotPathIdentity(exactPath)).toEqual(exactBefore);
		expect(readFileSync(unknownPath, "utf8")).toBe("unknown bytes");
		expect(existsSync(partialDirectory)).toBe(true);
	});

	it("returns the proven publication while leaving conflicting temporary bytes protected", () => {
		const target = root();
		const incidentsDirectory = join(target, "incidents");
		const incidentId = `run-${runId}`;
		const published = finalizeIncidentRecorderProjection(input(incidentsDirectory, "/physical"));
		expect(published.state).toBe("complete");
		const incidentDirectory = join(incidentsDirectory, incidentId);
		const manifest = JSON.parse(readFileSync(join(incidentDirectory, "finalization-manifest.json"), "utf8")) as {
			files: Array<{ name: string; sha256: string }>;
		};
		const record = manifest.files.find((candidate) => candidate.name === "summary.json");
		if (!record) throw new Error("Expected summary record in finalization manifest");
		const partialDirectory = join(incidentsDirectory, `.${incidentId}.partial-${published.finalizationId}`);
		mkdirSync(partialDirectory, { mode: 0o700 });
		const stagedName = `.${record.name}.${record.sha256}.tmp`;
		const conflictingPath = join(partialDirectory, stagedName);
		writeFileSync(conflictingPath, "conflicting bytes", { mode: 0o600 });

		expect(recoverPublishedIncidentFinalization({ incidentsDirectory, incidentId })).toMatchObject({
			state: "complete",
			finalizationId: published.finalizationId,
		});
		expect(readFileSync(conflictingPath, "utf8")).toBe("conflicting bytes");
		expect(existsSync(partialDirectory)).toBe(true);
	});

	it("persists an exact no-clobber service seal and reports conflicts and ambiguous durability", () => {
		const target = root();
		const path = join(target, "run", "service-finalization-seal.json");
		const value = { schemaVersion: 1, state: "sealed", runId };
		expect(persistIncidentFinalizationSeal({ path, value })).toMatchObject({ state: "applied" });
		expect(persistIncidentFinalizationSeal({ path, value })).toMatchObject({ state: "noop" });
		expect(persistIncidentFinalizationSeal({ path, value: { ...value, state: "different" } })).toMatchObject({
			state: "conflict",
		});

		const ambiguousPath = join(target, "other", "service-finalization-seal.json");
		let linked = false;
		const result = persistIncidentFinalizationSeal(
			{ path: ambiguousPath, value },
			{
				fs: {
					link: (source, destination) => {
						linkSync(source, destination);
						linked = true;
					},
					fsync: (descriptor) => {
						fsyncSync(descriptor);
						if (linked) throw undefined;
					},
				},
			},
		);
		expect(result).toMatchObject({ state: "ambiguous", authoritativeBytesMatch: true });
		expect(readFileSync(ambiguousPath, "utf8")).toBe(`${JSON.stringify(value)}\n`);
	});

	it("accepts a fully injected synchronous fs seam", () => {
		const required: IncidentRecorderFinalizationFileSystem = {
			mkdir: mkdirSync,
			open: openSync,
			write: writeSync,
			fsync: fsyncSync,
			close: closeSync,
			link: linkSync,
			read: readSync,
			lstat: lstatSync,
			fstat: fstatSync,
			readdir: readdirSync,
			unlink: unlinkSync,
			rmdir: rmdirSync,
		};
		expect(Object.keys(required).sort()).toEqual([
			"close",
			"fstat",
			"fsync",
			"link",
			"lstat",
			"mkdir",
			"open",
			"read",
			"readdir",
			"rmdir",
			"unlink",
			"write",
		]);
	});
});
