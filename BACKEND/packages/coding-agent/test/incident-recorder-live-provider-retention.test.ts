import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	linkSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderLiveRunEventsPage,
	type IncidentRecorderRunHistoryEvent,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import type { IncidentRecorderLiveObservationValidationCheckpoint } from "../src/modes/daemon/incident-recorder-live-publication.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	runIncidentRetentionPass,
} from "../src/modes/daemon/incident-recorder-retention.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const roots: string[] = [];
const fixtureLeases = new Set<IncidentRecorderWriterLifecycleLease>();
const MINUTE = 60 * 1_000;
const DAY = 24 * 60 * 60 * 1_000;
const PIN_BEFORE_MS = 30 * MINUTE;
const PIN_AFTER_MS = 15 * MINUTE;

type LiveFixture = {
	root: string;
	agentDir: string;
	recorder: string;
	incidents: string;
	casPath: string;
	runPath: string;
	incidentPath: string;
	compactor: IncidentRecorderCompactor;
	lease: IncidentRecorderWriterLifecycleLease;
};

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const TRIGGER_PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const FENCE_PRODUCER_ID = "44444444-4444-4444-8444-444444444444";
const TRIGGER_OCCURRENCE_ID = "55555555-5555-4555-8555-555555555555";
const FENCE_OCCURRENCE_ID = "66666666-6666-4666-8666-666666666666";
const FILLER_PRODUCER_ID = "77777777-7777-4777-8777-777777777777";

function fillerOccurrenceId(ordinal: number): string {
	return `88888888-8888-4888-8888-${ordinal.toString(16).padStart(12, "0")}`;
}

function canonicalJson(value: unknown): string {
	if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number")
		return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	const record = value as Record<string, unknown>;
	return `{${Object.keys(record)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
		.join(",")}}`;
}

function digest(value: unknown): string {
	return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function writeJson(path: string, value: unknown): void {
	mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
	writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function event(
	producerId: string,
	occurrenceId: string,
	type: string,
	anchor: number,
	casPath: string,
	casDigest: string,
	casBytes: number,
	ordinal: number,
): IncidentRecorderRunHistoryEvent {
	const identity = { runId: RUN_ID, runToken: RUN_TOKEN, producerId, occurrenceId };
	const identityKey = createHash("sha256")
		.update(`${RUN_ID}\0${RUN_TOKEN}\0${producerId}\0${occurrenceId}`)
		.digest("hex");
	return {
		identityKey,
		identity,
		semanticFingerprint: "a".repeat(64),
		occurrenceReference: {
			kind: "segment",
			locator: {
				version: 1,
				segmentId: "b".repeat(64),
				segmentSequence: 1,
				ordinal,
				offset: ordinal,
				frameBytes: 100,
				payloadBytes: casBytes,
				payloadSha256: casDigest,
			},
		},
		source: "recorder-control",
		type,
		encoding: "json",
		payloadKind: "control",
		terminal: false,
		metadata: { producerPid: 1 },
		eventWallTimeMs: String(anchor),
		eventMonotonicNs: String(ordinal),
		wrapperOrder: [String(ordinal)],
		producerOrder: [String(ordinal)],
		cursors: [`live:${ordinal}`],
		transportIdentity: { fixture: true },
		cas: { digest: casDigest, bytes: casBytes, path: casPath },
	};
}

async function createFixture(anchor: number, pageCount = 1): Promise<LiveFixture> {
	if (!Number.isSafeInteger(pageCount) || pageCount < 1) throw new Error(`invalid fixture page count: ${pageCount}`);
	const root = mkdtempSync(join(tmpdir(), "prime-agent-live-provider-retention-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const recorder = join(agentDir, "incident-recorder");
	const incidents = join(agentDir, "incidents");
	const runPath = join(recorder, "runs", `2026-08-01T00-00-00.000Z-${RUN_ID}`);
	const referencedCas = Buffer.from("referenced-cas", "utf8");
	const casDigest = createHash("sha256").update(referencedCas).digest("hex");
	const casPath = join(recorder, "cas", "sha256", casDigest.slice(0, 2), `${casDigest}.blob`);
	for (const path of [join(recorder, "runs"), join(recorder, "refs"), dirnamePath(casPath), incidents, runPath])
		mkdirSync(path, { recursive: true, mode: 0o700 });
	writeFileSync(casPath, referencedCas, { mode: 0o600 });
	writeFileSync(join(runPath, "reference.json"), `${JSON.stringify({ casDigest, casPath })}\n`, { mode: 0o600 });
	linkSync(casPath, join(runPath, "cas-reference.blob"));
	utimesSync(casPath, (anchor - 2 * DAY) / 1_000, (anchor - 2 * DAY) / 1_000);
	const ringDirectory = join(root, "sysdig");
	mkdirSync(ringDirectory, { recursive: true, mode: 0o700 });
	const ringBasePath = join(ringDirectory, "ring.scap");
	const pages = Array.from({ length: pageCount }, (_, index): IncidentRecorderLiveRunEventsPage => {
		const sequence = index + 1;
		const last = sequence === pageCount;
		const events =
			pageCount === 1
				? [
						event(
							TRIGGER_PRODUCER_ID,
							TRIGGER_OCCURRENCE_ID,
							"latency_trigger",
							anchor,
							casPath,
							casDigest,
							referencedCas.length,
							1,
						),
						event(
							FENCE_PRODUCER_ID,
							FENCE_OCCURRENCE_ID,
							"live_incident_high_water_fence",
							anchor,
							casPath,
							casDigest,
							referencedCas.length,
							2,
						),
					]
				: [
						event(
							sequence === 1 ? TRIGGER_PRODUCER_ID : last ? FENCE_PRODUCER_ID : FILLER_PRODUCER_ID,
							sequence === 1 ? TRIGGER_OCCURRENCE_ID : last ? FENCE_OCCURRENCE_ID : fillerOccurrenceId(sequence),
							sequence === 1
								? "latency_trigger"
								: last
									? "live_incident_high_water_fence"
									: "live_observation_event",
							anchor,
							casPath,
							casDigest,
							referencedCas.length,
							sequence,
						),
					];
		return {
			version: 1,
			runId: RUN_ID,
			state: last ? "complete" : "pending",
			events,
			cursor: {
				version: 1,
				runId: RUN_ID,
				filterSha256: "e".repeat(64),
				segmentSequence: 1,
				ordinal: pageCount === 1 ? 2 : sequence,
			},
			scannedSegments: 1,
			scannedRecords: sequence,
			scannedIndexBytes: 256,
		};
	});
	const admission = acquireIncidentRecorderWriterNormalLease(
		{ agentDir },
		{
			activationGenerationDigest: "f".repeat(64),
			revalidateActivation: () => ({ state: "valid" as const }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		},
	);
	if (admission.state !== "acquired") throw new Error(`fixture writer lease unavailable: ${admission.reason}`);
	const lease = admission.lease;
	fixtureLeases.add(lease);
	try {
		const compactor = new IncidentRecorderCompactor({
			agentDir,
			freeReserveBytes: 0,
			sysdigRingBasePath: ringBasePath,
			writerLifecycleLease: () => lease,
		});
		await compactor.initializeStorageAccounting(new AbortController().signal);
		(
			compactor as unknown as {
				readLiveRunEventsWithinRoot: (
					input: { runId: string; cursor?: unknown },
					root: unknown,
					store: unknown,
				) => IncidentRecorderLiveRunEventsPage;
			}
		).readLiveRunEventsWithinRoot = (input) => {
			const cursor = input.cursor as { ordinal?: number } | undefined;
			const pageIndex = Math.max(0, Math.min(pageCount - 1, Number(cursor?.ordinal ?? 0)));
			return pages[pageIndex] as IncidentRecorderLiveRunEventsPage;
		};
		const publicationInput = {
			incidentsDirectory: incidents,
			trigger: {
				runId: RUN_ID,
				runToken: RUN_TOKEN,
				producerId: TRIGGER_PRODUCER_ID,
				occurrenceId: TRIGGER_OCCURRENCE_ID,
				acceptedAtWallTimeMs: anchor,
				type: "latency_trigger",
			},
			fence: {
				runId: RUN_ID,
				runToken: RUN_TOKEN,
				producerId: FENCE_PRODUCER_ID,
				occurrenceId: FENCE_OCCURRENCE_ID,
			},
			classification: { value: "latency", causeLayer: "service" },
		};
		let publication = compactor.publishLiveIncidentObservation(publicationInput);
		let validationCheckpoint = "validationCheckpoint" in publication ? publication.validationCheckpoint : undefined;
		for (
			let attempt = 0;
			attempt < 16 && (publication.state === "pending" || publication.state === "incomplete");
			attempt += 1
		) {
			publication = compactor.publishLiveIncidentObservation({
				...publicationInput,
				...(validationCheckpoint === undefined ? {} : { validationCheckpoint }),
			});
			if ("validationCheckpoint" in publication) validationCheckpoint = publication.validationCheckpoint;
		}
		if (publication.state !== "published") throw new Error(`live fixture publication failed: ${publication.state}`);
		return {
			root,
			agentDir,
			recorder,
			incidents,
			casPath,
			runPath,
			incidentPath: publication.artifactPath,
			compactor,
			lease,
		};
	} catch (error) {
		fixtureLeases.delete(lease);
		lease.release();
		throw error;
	}
}

function releaseFixtureLease(fixture: LiveFixture) {
	const result = fixture.lease.release();
	fixtureLeases.delete(fixture.lease);
	return result;
}

function dirnamePath(path: string): string {
	const index = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
	return index < 0 ? "." : path.slice(0, index);
}

function finishProviderOutcomes(fixture: LiveFixture, anchor: number): void {
	fixture.compactor.requestPin(RUN_ID, fixture.incidentPath, anchor);
	const journalRequest = JSON.parse(
		readFileSync(join(fixture.incidentPath, "journal-pin-request.json"), "utf8"),
	) as Record<string, unknown>;
	const journalGenerationId = digest({
		provider: "journal",
		runId: RUN_ID,
		anchorWallTimeMs: anchor,
		fromWallTimeMs: anchor - PIN_BEFORE_MS,
		throughWallTimeMs: anchor + PIN_AFTER_MS,
	});
	const payload = Buffer.from("pinned-journal-cas", "utf8");
	const payloadDigest = createHash("sha256").update(payload).digest("hex");
	const pinDirectory = join(fixture.incidentPath, "journal-pins", "cas");
	mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
	const pinnedPath = join(pinDirectory, `${payloadDigest}.blob`);
	writeFileSync(pinnedPath, payload, { mode: 0o600 });
	chmodSync(pinnedPath, 0o400);
	const pinnedStat = statSync(pinnedPath);
	const sealedArtifact = {
		version: 1,
		state: "sealed_private_copy",
		generationId: journalGenerationId,
		dev: String(pinnedStat.dev),
		ino: String(pinnedStat.ino),
		bytes: pinnedStat.size,
		mtimeMs: pinnedStat.mtimeMs,
		ctimeMs: pinnedStat.ctimeMs,
		mode: pinnedStat.mode & 0o777,
		nlink: pinnedStat.nlink,
		sha256: payloadDigest,
	};
	writeJson(join(fixture.incidentPath, "journal-pin-manifest.json"), {
		version: 2,
		state: "complete_through_requested_window",
		runId: RUN_ID,
		fromWallTimeMs: journalRequest.fromWallTimeMs,
		throughWallTimeMs: journalRequest.throughWallTimeMs,
		artifactGenerationId: journalGenerationId,
		occurrences: [
			{
				occurrenceReference: {
					kind: "segment",
					locator: {
						version: 1,
						segmentId: "1".repeat(64),
						segmentSequence: 1,
						ordinal: 0,
						offset: 0,
						frameBytes: payload.length,
						payloadBytes: payload.length,
						payloadSha256: payloadDigest,
					},
				},
				semanticFingerprint: "2".repeat(64),
				cursors: [],
				cas: {
					digest: payloadDigest,
					bytes: payload.length,
					path: join(fixture.recorder, "cas", "sha256", payloadDigest.slice(0, 2), `${payloadDigest}.blob`),
				},
				eventWallTimeMs: String(anchor),
				pinnedCasPath: pinnedPath,
				sealedArtifact,
			},
		],
	});
	const manifestStat = statSync(join(fixture.incidentPath, "journal-pin-manifest.json"));
	const pinDirectoryStat = statSync(pinDirectory);
	writeJson(join(fixture.incidentPath, "journal-pin-retention-proof.json"), {
		version: 1,
		state: "producer_verified_complete",
		provider: "journal",
		artifactGenerationId: journalGenerationId,
		manifestValidated: true,
		occurrenceReferencesResolved: true,
		runId: RUN_ID,
		fromWallTimeMs: anchor - PIN_BEFORE_MS,
		throughWallTimeMs: anchor + PIN_AFTER_MS,
		retainUntilWallTimeMs: anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS,
		retentionMilliseconds: INCIDENT_DIAGNOSTIC_RETENTION_MS,
		occurrenceCount: 1,
		manifestIdentity: {
			dev: String(manifestStat.dev),
			ino: String(manifestStat.ino),
			size: manifestStat.size,
			mtimeMs: manifestStat.mtimeMs,
			ctimeMs: manifestStat.ctimeMs,
			nlink: manifestStat.nlink,
		},
		pinDirectoryIdentity: {
			path: "journal-pins/cas",
			dev: String(pinDirectoryStat.dev),
			ino: String(pinDirectoryStat.ino),
			mtimeMs: pinDirectoryStat.mtimeMs,
			ctimeMs: pinDirectoryStat.ctimeMs,
		},
	});
	writeJson(join(fixture.incidentPath, "sysdig-pin-incomplete.json"), {
		version: 1,
		state: "pending_or_incomplete",
		provider: "sysdig",
		reason: "fixture_no_sysdig_source",
		runId: RUN_ID,
		anchorWallTimeMs: anchor,
		fromWallTimeMs: anchor - PIN_BEFORE_MS,
		throughWallTimeMs: anchor + PIN_AFTER_MS,
	});
}

function runRetention(
	fixture: LiveFixture,
	nowMs: number,
	validationCheckpoints?: Map<string, IncidentRecorderLiveObservationValidationCheckpoint>,
) {
	const admission = acquireIncidentRecorderWriterNormalLease(
		{ agentDir: fixture.agentDir },
		{
			activationGenerationDigest: "a".repeat(64),
			revalidateActivation: () => ({ state: "valid" as const }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		},
	);
	if (admission.state !== "acquired") throw new Error(`retention writer lease unavailable: ${admission.reason}`);
	try {
		return runIncidentRetentionPass({
			agentDir: fixture.agentDir,
			writerLifecycleLease: admission.lease,
			liveObservationValidationCheckpoints: validationCheckpoints,
			nowMs,
			maxEntries: 8_192,
			maxDeletes: 8_192,
		});
	} finally {
		admission.lease.release();
	}
}

afterEach(() => {
	for (const lease of fixtureLeases) lease.release();
	fixtureLeases.clear();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("live incident provider retention", () => {
	it("keeps the live artifact pending before its window and retained before expiry", async () => {
		const anchor = Date.now() - 4 * DAY;
		const fixture = await createFixture(anchor);
		finishProviderOutcomes(fixture, anchor);
		expect(releaseFixtureLease(fixture).state).toBe("released");
		const beforeWindow = runRetention(fixture, anchor + PIN_AFTER_MS - 1);
		expect(beforeWindow.pendingIncident).toBe(true);
		expect(beforeWindow.deletedEntries).toBe(0);
		expect(existsSync(fixture.incidentPath)).toBe(true);
		const preexpiry = runRetention(fixture, anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS - 1);
		expect(preexpiry.deletedEntries).toBe(0);
		expect(existsSync(fixture.incidentPath)).toBe(true);
	});

	it("deletes an expired live artifact after requestPin proof/incomplete outcomes and preserves its run and CAS", async () => {
		const anchor = Date.now() - 4 * DAY;
		const fixture = await createFixture(anchor);
		finishProviderOutcomes(fixture, anchor);
		expect(releaseFixtureLease(fixture).state).toBe("released");
		const result = runRetention(fixture, anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS + 1);
		expect(result.state).toBe("completed");
		expect(result.pendingIncident).toBe(false);
		expect(result.uncertainties.some((value) => value.includes(fixture.incidentPath))).toBe(false);
		expect(existsSync(fixture.incidentPath)).toBe(false);
		expect(existsSync(fixture.runPath)).toBe(true);
		expect(existsSync(fixture.casPath)).toBe(true);
	});

	it("continues live validation across bounded retention passes for a long page chain", async () => {
		const anchor = Date.now() - 4 * DAY;
		const fixture = await createFixture(anchor, 10);
		finishProviderOutcomes(fixture, anchor);
		expect(releaseFixtureLease(fixture).state).toBe("released");
		const validationCheckpoints = new Map<string, IncidentRecorderLiveObservationValidationCheckpoint>();
		const firstPass = runRetention(fixture, anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS + 1, validationCheckpoints);
		expect(firstPass.pendingIncident).toBe(true);
		expect(firstPass.deletedEntries).toBe(0);
		expect(existsSync(fixture.incidentPath)).toBe(true);
		const secondPass = runRetention(fixture, anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS + 1, validationCheckpoints);
		expect(secondPass.pendingIncident).toBe(false);
		expect(secondPass.uncertainties.some((value) => value.includes(fixture.incidentPath))).toBe(false);
		expect(existsSync(fixture.incidentPath)).toBe(false);
		expect(existsSync(fixture.runPath)).toBe(true);
		expect(existsSync(fixture.casPath)).toBe(true);
	});

	for (const variant of ["authority", "window", "generation", "proof"] as const) {
		it(`fails closed for malformed live ${variant} state`, async () => {
			const anchor = Date.now() - 4 * DAY;
			const fixture = await createFixture(anchor);
			finishProviderOutcomes(fixture, anchor);
			expect(releaseFixtureLease(fixture).state).toBe("released");
			const authorityPath = join(fixture.incidentPath, "incident-pin-authority.json");
			const journalRequestPath = join(fixture.incidentPath, "journal-pin-request.json");
			const proofPath = join(fixture.incidentPath, "journal-pin-retention-proof.json");
			if (variant === "authority") {
				const authority = JSON.parse(readFileSync(authorityPath, "utf8")) as Record<string, unknown>;
				authority.runId = RUN_TOKEN;
				writeJson(authorityPath, authority);
			} else if (variant === "window") {
				const request = JSON.parse(readFileSync(journalRequestPath, "utf8")) as Record<string, unknown>;
				request.throughWallTimeMs = Number(request.throughWallTimeMs) + 1;
				writeJson(journalRequestPath, request);
			} else {
				const proof = JSON.parse(readFileSync(proofPath, "utf8")) as Record<string, unknown>;
				if (variant === "generation") proof.artifactGenerationId = "0".repeat(64);
				else proof.manifestValidated = false;
				writeJson(proofPath, proof);
			}
			const result = runRetention(fixture, anchor + INCIDENT_DIAGNOSTIC_RETENTION_MS + 1);
			expect(result.state).toBe("completed");
			expect(result.pendingIncident).toBe(false);
			expect(result.deletedEntries).toBe(0);
			expect(result.uncertainties.some((value) => value.includes(fixture.incidentPath))).toBe(true);
			expect(existsSync(fixture.incidentPath)).toBe(true);
			expect(existsSync(fixture.runPath)).toBe(true);
			expect(existsSync(fixture.casPath)).toBe(true);
		});
	}
});
