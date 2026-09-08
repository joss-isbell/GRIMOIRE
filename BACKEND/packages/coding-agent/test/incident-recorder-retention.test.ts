import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	linkSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	statSync,
	symlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderLiveRunEventsPage,
	type IncidentRecorderRunHistoryEvent,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	finalizeIncidentRecorderProjection,
	type IncidentRecorderFinalizationInput,
	type IncidentRecorderRelayFrontierExpectation,
	inspectPublishedIncidentFinalization,
	persistIncidentRetentionAuthority,
	recoverPublishedIncidentFinalization,
} from "../src/modes/daemon/incident-recorder-finalizer.js";
import type {
	IncidentRecorderLiveIncidentPublicationInput,
	IncidentRecorderLiveObservationValidationCheckpoint,
} from "../src/modes/daemon/incident-recorder-live-publication.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	INCIDENT_CORRUPTION_QUARANTINE_MS,
	INCIDENT_DIAGNOSTIC_RETENTION_MS,
	INCIDENT_RETENTION_SERVICE_BUDGET,
	type IncidentRetentionOptions,
	incidentRetentionNextDelayMs,
	runIncidentRetentionPass as runIncidentRetentionPassWithLease,
} from "../src/modes/daemon/incident-recorder-retention.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	acquireIncidentRecorderWriterRecoveryLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const roots: string[] = [];
const compactorLeaseReleases: Array<() => void> = [];
const MINUTE = 60 * 1_000;
const DAY = 24 * 60 * 60 * 1_000;
const INCIDENT_PIN_BEFORE_MS = 30 * MINUTE;
const INCIDENT_PIN_AFTER_MS = 15 * MINUTE;
const NOW = Date.parse("2026-08-25T12:00:00.000Z");
const DEFAULT_FINALIZATION_RUN_ID = "10101010-1010-4010-8010-101010101010";
const DEFAULT_FINALIZATION_RUN_TOKEN = "20202020-2020-4020-8020-202020202020";

function fixtureLifecycleContract() {
	return {
		activationGenerationDigest: "a".repeat(64),
		revalidateActivation: () => ({ state: "valid" as const }),
		acquireCas: acquireIncidentRecorderNamespaceCas,
	};
}

function acquireFixtureRetentionLease(target: ReturnType<typeof fixture>) {
	const contract = fixtureLifecycleContract();
	return acquireIncidentRecorderWriterNormalLease({ agentDir: target.agentDir }, contract);
}

function acquireFixtureRecoveryLease(target: ReturnType<typeof fixture>) {
	const contract = fixtureLifecycleContract();
	return acquireIncidentRecorderWriterRecoveryLease({ agentDir: target.agentDir }, contract);
}

function compactorLifecycleLease(target: ReturnType<typeof fixture>) {
	const acquired = acquireFixtureRetentionLease(target);
	if (acquired.state !== "acquired") throw new Error("compactor fixture normal lease unavailable");
	compactorLeaseReleases.push(() => {
		expect(acquired.lease.release().state).toBe("released");
	});
	return () => acquired.lease;
}

function runIncidentRetentionPass(options: IncidentRetentionOptions) {
	const contract = fixtureLifecycleContract();
	const acquired = options.recoveryOnly
		? acquireIncidentRecorderWriterRecoveryLease({ agentDir: options.agentDir }, contract)
		: acquireIncidentRecorderWriterNormalLease({ agentDir: options.agentDir }, contract);
	if (acquired.state !== "acquired") throw new Error(`retention fixture lease unavailable: ${acquired.reason}`);
	let result: ReturnType<typeof runIncidentRetentionPassWithLease> | undefined;
	let released: ReturnType<typeof acquired.lease.release> | undefined;
	try {
		result = runIncidentRetentionPassWithLease({ ...options, writerLifecycleLease: acquired.lease });
	} finally {
		released = acquired.lease.release();
	}
	if (released?.state !== "released") throw new Error("retention fixture lease release pending");
	if (!result) throw new Error("retention fixture pass did not produce a result");
	return result;
}

function fixture(prefix = "prime-agent-retention-"): {
	root: string;
	agentDir: string;
	recorder: string;
	incidents: string;
} {
	const root = mkdtempSync(join(tmpdir(), prefix));
	roots.push(root);
	const agentDir = join(root, "agent");
	const recorder = join(agentDir, "incident-recorder");
	const incidents = join(agentDir, "incidents");
	for (const path of [join(recorder, "runs"), join(recorder, "refs"), join(recorder, "cas", "sha256"), incidents]) {
		mkdirSync(path, { recursive: true, mode: 0o700 });
	}
	return { root, agentDir, recorder, incidents };
}

function json(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function rewriteControlEncoding(path: string, encoding: "reordered" | "pretty" | "whitespace"): void {
	const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
	const value = encoding === "reordered" ? Object.fromEntries(Object.entries(parsed).reverse()) : parsed;
	const bytes =
		encoding === "pretty"
			? `${JSON.stringify(value, null, 2)}\n`
			: encoding === "whitespace"
				? `${JSON.stringify(value)} \n`
				: `${JSON.stringify(value)}\n`;
	writeFileSync(path, bytes, { mode: 0o600 });
}

function canonicalFixtureJson(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean" || typeof value === "number")
		return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonicalFixtureJson).join(",")}]`;
	const record = value as Record<string, unknown>;
	return `{${Object.keys(record)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalFixtureJson(record[key])}`)
		.join(",")}}`;
}

function fixtureFingerprint(value: unknown): string {
	return createHash("sha256").update(canonicalFixtureJson(value)).digest("hex");
}

function journalArtifactGenerationId(runId: string, anchorWallTimeMs: number): string {
	return fixtureFingerprint({
		provider: "journal",
		runId,
		anchorWallTimeMs,
		fromWallTimeMs: anchorWallTimeMs - INCIDENT_PIN_BEFORE_MS,
		throughWallTimeMs: anchorWallTimeMs + INCIDENT_PIN_AFTER_MS,
	});
}

function journalSegmentLocator(payloadBytes: number, payloadSha256: string): Record<string, unknown> {
	return {
		version: 1,
		segmentId: "a".repeat(64),
		segmentSequence: 1,
		ordinal: 0,
		offset: 0,
		frameBytes: payloadBytes,
		payloadBytes,
		payloadSha256,
	};
}

function sysdigArtifactGenerationId(request: Record<string, unknown>): string {
	const requestFingerprint = fixtureFingerprint({
		version: request.version,
		runId: request.runId,
		anchorWallTimeMs: request.anchorWallTimeMs,
		fromWallTimeMs: request.fromWallTimeMs,
		throughWallTimeMs: request.throughWallTimeMs,
		resolveAfterWallTimeMs: request.resolveAfterWallTimeMs,
		retainUntilWallTimeMs: request.retainUntilWallTimeMs,
		ringBasePath: request.ringBasePath,
		requestedAtWallTimeMs: request.requestedAtWallTimeMs,
		initialRingSnapshot: request.initialRingSnapshot,
	});
	return fixtureFingerprint({ provider: "sysdig", requestFingerprint });
}

function old(path: string, ageMs = INCIDENT_DIAGNOSTIC_RETENTION_MS + 1): void {
	utimesSync(path, (NOW - ageMs) / 1_000, (NOW - ageMs) / 1_000);
}

function runPath(target: ReturnType<typeof fixture>, id = "11111111-1111-4111-8111-111111111111"): string {
	const path = join(target.recorder, "runs", `2026-08-01T00-00-00.000Z-${id}`);
	mkdirSync(path, { recursive: true, mode: 0o700 });
	return path;
}

async function initializeStorageAccounting(compactor: IncidentRecorderCompactor): Promise<void> {
	const controller = new AbortController();
	await compactor.initializeStorageAccounting(controller.signal);
}

async function livePublicationCompactor(
	target: ReturnType<typeof fixture>,
	readPage: (input: { runId: string; cursor?: unknown }) => IncidentRecorderLiveRunEventsPage,
): Promise<IncidentRecorderCompactor> {
	const compactor = new IncidentRecorderCompactor({
		agentDir: target.agentDir,
		freeReserveBytes: 0,
		writerLifecycleLease: compactorLifecycleLease(target),
	});
	await initializeStorageAccounting(compactor);
	const internal = compactor as unknown as {
		readLiveRunEventsWithinRoot: (
			input: { runId: string; cursor?: unknown },
			root: unknown,
			store: unknown,
		) => IncidentRecorderLiveRunEventsPage;
	};
	internal.readLiveRunEventsWithinRoot = (input) => readPage(input);
	return compactor;
}

function publishLiveIncidentObservation(input: IncidentRecorderLiveIncidentPublicationInput) {
	const { compactor, ...request } = input;
	return compactor.publishLiveIncidentObservation(request);
}

async function startRetentionCasHolder(recorderRoot: string): Promise<{ release: () => Promise<void> }> {
	const script = fileURLToPath(new URL("./fixtures/incident-recorder-cas-holder.ts", import.meta.url));
	const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	const child = spawn(process.execPath, ["--import", tsxLoader, script, recorderRoot], {
		stdio: ["pipe", "pipe", "pipe"],
	});
	let stdout = "";
	let stderr = "";
	child.stdout?.setEncoding("utf8");
	child.stderr?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		stdout += chunk;
	});
	child.stderr?.on("data", (chunk: string) => {
		stderr += chunk;
	});
	const waitFor = async (expected: string): Promise<void> => {
		const deadline = Date.now() + 5_000;
		while (!stdout.includes(expected)) {
			if (child.exitCode !== null || child.signalCode !== null)
				throw new Error(`retention CAS holder exited before ${expected}: ${stderr}`);
			if (Date.now() >= deadline)
				throw new Error(`timed out waiting for retention CAS holder ${expected}: ${stderr}`);
			await new Promise<void>((resolve) => setTimeout(resolve, 10));
		}
	};
	await waitFor("ready\n");
	return {
		release: async () => {
			child.stdin?.end("release\n");
			await waitFor("released\n");
			if (child.exitCode === null && child.signalCode === null)
				await new Promise<void>((resolve) => child.once("close", () => resolve()));
		},
	};
}

type PublishedFinalizationState = "complete" | "incomplete" | "corrupt";

function authorityV1PinRequests(
	runId: string,
	retentionAnchorWallTimeMs: number,
	ringBasePath: string,
): { journal: Record<string, unknown>; sysdig: Record<string, unknown> } {
	const fromWallTimeMs = retentionAnchorWallTimeMs - INCIDENT_PIN_BEFORE_MS;
	const throughWallTimeMs = retentionAnchorWallTimeMs + INCIDENT_PIN_AFTER_MS;
	const retainUntilWallTimeMs = retentionAnchorWallTimeMs + INCIDENT_DIAGNOSTIC_RETENTION_MS;
	return {
		journal: {
			version: 1,
			state: "pending",
			runId,
			anchorWallTimeMs: retentionAnchorWallTimeMs,
			fromWallTimeMs,
			throughWallTimeMs,
			resolveAfterWallTimeMs: throughWallTimeMs,
			retainUntilWallTimeMs,
		},
		sysdig: {
			version: 1,
			runId,
			anchorWallTimeMs: retentionAnchorWallTimeMs,
			fromWallTimeMs,
			throughWallTimeMs,
			resolveAfterWallTimeMs: throughWallTimeMs,
			requestedAtWallTimeMs: retentionAnchorWallTimeMs,
			retainUntilWallTimeMs,
			ringBasePath,
			initialRingSnapshot: {
				observedAtWallTimeMs: retentionAnchorWallTimeMs,
				candidates: [],
				issues: [],
			},
		},
	};
}

function writeAuthorityV1PinRequests(path: string, runId: string, retentionAnchorWallTimeMs: number): void {
	const requests = authorityV1PinRequests(runId, retentionAnchorWallTimeMs, join(path, ".fixture-sysdig-ring"));
	json(join(path, "journal-pin-request.json"), requests.journal);
	json(join(path, "sysdig-pin-request.json"), requests.sysdig);
}

function providerPinIncomplete(
	provider: "journal" | "sysdig",
	runId: string,
	anchorWallTimeMs: number,
	reason = "storage_paused",
): Record<string, unknown> {
	return {
		version: 1,
		state: "pending_or_incomplete",
		provider,
		reason,
		runId,
		anchorWallTimeMs,
		fromWallTimeMs: anchorWallTimeMs - INCIDENT_PIN_BEFORE_MS,
		throughWallTimeMs: anchorWallTimeMs + INCIDENT_PIN_AFTER_MS,
	};
}

function writeProviderPinIncomplete(
	path: string,
	provider: "journal" | "sysdig",
	runId: string,
	anchorWallTimeMs: number,
	reason?: string,
): void {
	json(
		join(path, `${provider}-pin-incomplete.json`),
		providerPinIncomplete(provider, runId, anchorWallTimeMs, reason),
	);
}

function writeCanonicalIncompleteProviderOutcomes(path: string, runId: string, anchorWallTimeMs: number): void {
	writeProviderPinIncomplete(path, "journal", runId, anchorWallTimeMs);
	writeProviderPinIncomplete(path, "sysdig", runId, anchorWallTimeMs);
}

function sealFixtureArtifact(path: string, generationId: string, sha256: string): Record<string, unknown> {
	chmodSync(path, 0o400);
	const stat = statSync(path);
	return {
		version: 1,
		state: "sealed_private_copy",
		generationId,
		dev: String(stat.dev),
		ino: String(stat.ino),
		bytes: stat.size,
		mtimeMs: stat.mtimeMs,
		ctimeMs: stat.ctimeMs,
		mode: stat.mode & 0o777,
		nlink: stat.nlink,
		sha256,
	};
}

function refreshProviderProofManifestIdentity(incident: string, provider: "journal" | "sysdig"): void {
	const manifestPath = join(incident, `${provider}-pin-manifest.json`);
	const proofPath = join(incident, `${provider}-pin-retention-proof.json`);
	const proof = JSON.parse(readFileSync(proofPath, "utf8")) as Record<string, unknown>;
	const stat = statSync(manifestPath);
	proof.manifestIdentity = {
		dev: String(stat.dev),
		ino: String(stat.ino),
		size: stat.size,
		mtimeMs: stat.mtimeMs,
		ctimeMs: stat.ctimeMs,
		nlink: stat.nlink,
	};
	json(proofPath, proof);
}

function writeJournalProducerProof(incident: string, runId: string, anchorWallTimeMs: number, payload: Buffer): string {
	rmSync(join(incident, "journal-pin-incomplete.json"), { force: true });
	writeProviderPinIncomplete(incident, "sysdig", runId, anchorWallTimeMs);
	const pinDirectory = join(incident, "journal-pins", "cas");
	mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
	const digest = createHash("sha256").update(payload).digest("hex");
	const generationId = journalArtifactGenerationId(runId, anchorWallTimeMs);
	const pinnedPath = join(pinDirectory, `${digest}.blob`);
	writeFileSync(pinnedPath, payload, { mode: 0o600 });
	const sealedArtifact = sealFixtureArtifact(pinnedPath, generationId, digest);
	const manifestPath = join(incident, "journal-pin-manifest.json");
	json(manifestPath, {
		version: 2,
		state: "complete_through_requested_window",
		runId,
		fromWallTimeMs: anchorWallTimeMs - INCIDENT_PIN_BEFORE_MS,
		throughWallTimeMs: anchorWallTimeMs + INCIDENT_PIN_AFTER_MS,
		artifactGenerationId: generationId,
		occurrences: [
			{
				occurrenceReference: {
					kind: "segment",
					locator: journalSegmentLocator(payload.length, digest),
				},
				semanticFingerprint: "b".repeat(64),
				cursors: [],
				cas: {
					digest,
					bytes: payload.length,
					path: join(
						dirname(dirname(incident)),
						"incident-recorder",
						"cas",
						"sha256",
						digest.slice(0, 2),
						`${digest}.blob`,
					),
				},
				eventWallTimeMs: String(anchorWallTimeMs),
				pinnedCasPath: pinnedPath,
				sealedArtifact,
			},
		],
	});
	const manifestStat = statSync(manifestPath);
	const pinStat = statSync(pinDirectory);
	json(join(incident, "journal-pin-retention-proof.json"), {
		version: 1,
		state: "producer_verified_complete",
		provider: "journal",
		artifactGenerationId: generationId,
		manifestValidated: true,
		occurrenceReferencesResolved: true,
		runId,
		fromWallTimeMs: anchorWallTimeMs - INCIDENT_PIN_BEFORE_MS,
		throughWallTimeMs: anchorWallTimeMs + INCIDENT_PIN_AFTER_MS,
		retainUntilWallTimeMs: anchorWallTimeMs + INCIDENT_DIAGNOSTIC_RETENTION_MS,
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
			dev: String(pinStat.dev),
			ino: String(pinStat.ino),
			mtimeMs: pinStat.mtimeMs,
			ctimeMs: pinStat.ctimeMs,
		},
	});
	return pinnedPath;
}

function writeSysdigProducerProof(
	incident: string,
	runId: string,
	anchorWallTimeMs: number,
	payloads: readonly Buffer[],
): string[] {
	rmSync(join(incident, "sysdig-pin-incomplete.json"), { force: true });
	writeProviderPinIncomplete(incident, "journal", runId, anchorWallTimeMs);
	const pinDirectory = join(incident, "sysdig-pins", "segments");
	mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
	const sysdigRequest = JSON.parse(readFileSync(join(incident, "sysdig-pin-request.json"), "utf8")) as Record<
		string,
		unknown
	>;
	const generationId = sysdigArtifactGenerationId(sysdigRequest);
	const segments = payloads.map((payload, index) => {
		const digest = createHash("sha256").update(payload).digest("hex");
		const sourceName = `.fixture-sysdig-ring.${index}`;
		const source = {
			dev: "1",
			ino: String(index + 1),
			bytes: payload.length,
			mtimeMs: anchorWallTimeMs,
			ctimeMs: anchorWallTimeMs + index,
		};
		const id = createHash("sha256")
			.update(`${source.dev}\0${source.ino}\0${source.bytes}\0${source.mtimeMs}\0${source.ctimeMs}`)
			.digest("hex");
		const pinnedPath = join(pinDirectory, `${id}.scap`);
		writeFileSync(pinnedPath, payload, { mode: 0o600 });
		const captured = statSync(pinnedPath);
		const artifactAtCapture = {
			dev: String(captured.dev),
			ino: String(captured.ino),
			bytes: captured.size,
			mtimeMs: captured.mtimeMs,
			ctimeMs: captured.ctimeMs,
			mode: captured.mode & 0o777,
			nlink: captured.nlink,
		};
		const sealedArtifact = sealFixtureArtifact(pinnedPath, generationId, digest);
		return {
			version: 1,
			id,
			sourcePath: join(incident, sourceName),
			sourceName,
			observedAtWallTimeMs: anchorWallTimeMs,
			phase: "final",
			source,
			pinnedPath,
			captureMethod: "bounded_copy",
			captureReason: "active_segment_snapshot",
			bytesAtCapture: payload.length,
			artifactAtCapture,
			exactBytes: { bytes: payload.length, sha256: digest },
			changedAfterCapture: false,
			sealedArtifact,
		};
	});
	const manifestPath = join(incident, "sysdig-pin-manifest.json");
	json(manifestPath, {
		version: 1,
		state: "finalized_with_observed_coverage",
		diagnosticOnly: true,
		captureOutcome: "complete",
		capturePhases: { initial: "complete", final: "complete" },
		runId,
		requestedWindow: {
			fromWallTimeMs: anchorWallTimeMs - INCIDENT_PIN_BEFORE_MS,
			anchorWallTimeMs,
			throughWallTimeMs: anchorWallTimeMs + INCIDENT_PIN_AFTER_MS,
		},
		captureFinalizedAtWallTimeMs: anchorWallTimeMs + INCIDENT_PIN_AFTER_MS,
		retention: {
			milliseconds: INCIDENT_DIAGNOSTIC_RETENTION_MS,
			retainUntilWallTimeMs: anchorWallTimeMs + INCIDENT_DIAGNOSTIC_RETENTION_MS,
		},
		sourceRing: {
			basePath: sysdigRequest.ringBasePath,
			configuredSegments: 12,
			rotationBytes: 320 * 1024 * 1024,
			compression: true,
		},
		coverage: {
			method:
				"all_observed_ring_segments_at_incident_finalization_plus_rotated_segments_observed_through_requested_end",
			historicalAvailability: "bounded_by_bytes_present_in_the_stock_ring_at_finalization",
			eventTimeBounds: "unknown_without_offline_scap_event_parsing",
			gaps: [],
		},
		artifactGenerationId: generationId,
		segments,
	});
	const manifestStat = statSync(manifestPath);
	const pinStat = statSync(pinDirectory);
	json(join(incident, "sysdig-pin-retention-proof.json"), {
		version: 1,
		state: "producer_verified_complete",
		provider: "sysdig",
		artifactGenerationId: generationId,
		manifestValidated: true,
		captureOutcome: "complete",
		capturePhases: { initial: "complete", final: "complete" },
		runId,
		fromWallTimeMs: anchorWallTimeMs - INCIDENT_PIN_BEFORE_MS,
		throughWallTimeMs: anchorWallTimeMs + INCIDENT_PIN_AFTER_MS,
		retainUntilWallTimeMs: anchorWallTimeMs + INCIDENT_DIAGNOSTIC_RETENTION_MS,
		retentionMilliseconds: INCIDENT_DIAGNOSTIC_RETENTION_MS,
		segmentCount: segments.length,
		manifestIdentity: {
			dev: String(manifestStat.dev),
			ino: String(manifestStat.ino),
			size: manifestStat.size,
			mtimeMs: manifestStat.mtimeMs,
			ctimeMs: manifestStat.ctimeMs,
			nlink: manifestStat.nlink,
		},
		pinDirectoryIdentity: {
			path: "sysdig-pins/segments",
			dev: String(pinStat.dev),
			ino: String(pinStat.ino),
			mtimeMs: pinStat.mtimeMs,
			ctimeMs: pinStat.ctimeMs,
		},
	});
	return segments.map((segment) => segment.pinnedPath);
}

function finalizationFile(path: string, value: unknown): { name: string; bytes: number; sha256: string } {
	const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
	writeFileSync(path, bytes, { mode: 0o600 });
	return {
		name: basename(path),
		bytes: bytes.length,
		sha256: createHash("sha256").update(bytes).digest("hex"),
	};
}

function finalizedIncident(
	target: ReturnType<typeof fixture>,
	name: string,
	retentionAnchorWallTimeMs: number,
	options: {
		state?: PublishedFinalizationState;
		runId?: string;
		runToken?: string;
		supervisorExitAnchorWallTimeMs?: number | null;
		serviceTerminalRelayDisposition?: string;
	} = {},
): string {
	const state = options.state ?? "complete";
	const runId = options.runId ?? DEFAULT_FINALIZATION_RUN_ID;
	const runToken = options.runToken ?? DEFAULT_FINALIZATION_RUN_TOKEN;
	const supervisorExitAnchorWallTimeMs =
		options.supervisorExitAnchorWallTimeMs === undefined
			? retentionAnchorWallTimeMs
			: options.supervisorExitAnchorWallTimeMs;
	const path = join(target.incidents, name);
	const wrapperProducerId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
	const serviceProducerId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
	const supervisorOccurrenceId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
	const wrapperOccurrenceId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
	const serviceOccurrenceId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
	const physicalRoot = join(target.root, "fixture-finalization-evidence");
	const event = (
		type: "supervisor_exit" | "capture_channel_terminal",
		occurrenceId: string,
		producerId: string,
		sequence: string,
		wallTimeMs: number,
	): IncidentRecorderRunHistoryEvent => {
		const identityKey = createHash("sha256")
			.update(`${runId}\0${runToken}\0${producerId}\0${occurrenceId}`)
			.digest("hex");
		return {
			identityKey,
			identity: { runId, runToken, producerId, occurrenceId },
			semanticFingerprint: createHash("sha256").update(`semantic\0${identityKey}`).digest("hex"),
			occurrenceReference: join(physicalRoot, `${occurrenceId}.json`),
			source: type === "supervisor_exit" ? "recorder-events" : "recorder-control",
			type,
			encoding: "derived-scalar-json-v1",
			payloadKind: type === "supervisor_exit" ? ("derived-scalar" as const) : ("control" as const),
			terminal: type === "capture_channel_terminal",
			metadata:
				type === "supervisor_exit"
					? { code: 1, signal: null, producerPid: 10, sourcePath: physicalRoot }
					: { producerPid: 10, phase: "terminal" },
			eventWallTimeMs: String(wallTimeMs),
			eventMonotonicNs: sequence,
			wrapperOrder: [sequence],
			producerOrder: [sequence],
			cursors: [`cursor:${sequence}`],
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
			cas: { digest: identityKey, bytes: 16, path: join(physicalRoot, "cas", identityKey) },
		};
	};
	const supervisorEvent = event(
		"supervisor_exit",
		supervisorOccurrenceId,
		wrapperProducerId,
		"1",
		supervisorExitAnchorWallTimeMs ?? retentionAnchorWallTimeMs,
	);
	const wrapperEvent = event(
		"capture_channel_terminal",
		wrapperOccurrenceId,
		wrapperProducerId,
		"2",
		retentionAnchorWallTimeMs,
	);
	const serviceEvent = event(
		"capture_channel_terminal",
		serviceOccurrenceId,
		serviceProducerId,
		"1",
		retentionAnchorWallTimeMs,
	);
	const projection = {
		version: 1 as const,
		runId,
		fromWallTimeMs: 0,
		throughWallTimeMs: Math.max(retentionAnchorWallTimeMs, supervisorExitAnchorWallTimeMs ?? 0),
		events: [supervisorEvent, wrapperEvent, serviceEvent],
		terminalEvents: [wrapperEvent, serviceEvent].map((value) => ({
			identityKey: value.identityKey,
			type: value.type,
			source: value.source,
			eventWallTimeMs: value.eventWallTimeMs,
			basis: "terminal_flag" as const,
		})),
		finalizationCandidates: [
			{
				role: "supervisor_exit" as const,
				identityKey: supervisorEvent.identityKey,
				basis: "type_and_source_candidate" as const,
				qualification: "candidate_requires_expectation_match" as const,
			},
			...[wrapperEvent, serviceEvent].map((value) => ({
				role: "capture_channel_terminal" as const,
				identityKey: value.identityKey,
				basis: "type_source_and_terminal_flag_candidate" as const,
				qualification: "candidate_requires_expectation_match" as const,
			})),
		],
		ordering: {
			semantics: "partial_order" as const,
			causalRelations: [],
			presentationTieBreak: "wall_time_then_identity_key" as const,
			unrelatedPresentationOrderIsCausal: false as const,
			scope: "complete_snapshot" as const,
		},
		evidence: state === "corrupt" ? [{ kind: "corrupt" as const, reason: "fixture_corrupt" }] : [],
	};
	const runHistory: IncidentRecorderFinalizationInput["runHistory"] =
		state === "incomplete"
			? { state: "incomplete", reason: "fixture_incomplete", projection }
			: {
					state: "complete",
					projection,
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
	const frontier = (eventValue: typeof supervisorEvent): IncidentRecorderRelayFrontierExpectation => {
		if (eventValue.type !== "supervisor_exit" && eventValue.type !== "capture_channel_terminal") {
			throw new Error(`unsupported fixture frontier type: ${eventValue.type}`);
		}
		return {
			type: eventValue.type,
			occurrenceId: eventValue.identity.occurrenceId,
			producerId: eventValue.identity.producerId,
			firstProducerSequence: eventValue.producerOrder[0] ?? "0",
			lastProducerSequence: eventValue.producerOrder[0] ?? "0",
			firstWrapperSequence: eventValue.wrapperOrder[0] ?? "0",
			lastWrapperSequence: eventValue.wrapperOrder[0] ?? "0",
		};
	};
	const requestedDisposition = options.serviceTerminalRelayDisposition ?? "relayed";
	const generatedDisposition = state === "complete" ? "relayed" : requestedDisposition;
	const result = finalizeIncidentRecorderProjection({
		incidentsDirectory: target.incidents,
		incidentId: name,
		runIdentity: { runId, runToken },
		runHistory,
		terminalExpectations: {
			supervisorExit:
				supervisorExitAnchorWallTimeMs === null
					? { state: "unavailable", reason: "fixture" }
					: { state: "available", frontier: frontier(supervisorEvent) },
			wrapperTerminal: { state: "available", frontier: frontier(wrapperEvent) },
			serviceTerminal: { state: "available", frontier: frontier(serviceEvent) },
		},
		classification: { value: "fixture", causeLayer: "fixture" },
		exit: { code: 1, signal: null },
		retentionAnchorWallTimeMs,
		stoppedTarget: { captureState: "complete", artifacts: [] },
		wrapperLoss: {
			finalQueuedTailLoss: { records: 0, bytes: 0 },
			emitterFinalTailLoss: { records: 0, bytes: 0 },
		},
		serviceSeal: {
			terminalRelayDisposition: generatedDisposition,
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
		assertProjectionLeaseUsable: () => {},
		releaseProjectionLease: () => {},
	});
	if (result.state !== state || result.retentionAnchorWallTimeMs !== retentionAnchorWallTimeMs)
		throw new Error(`Fixture finalization state mismatch: expected ${state}, received ${result.state}`);
	json(join(path, "retention-authority.json"), {
		schemaVersion: 1,
		kind: "incident_retention_authority",
		finalizationId: result.finalizationId,
		runId,
		outcome: result.state,
		retentionAnchorWallTimeMs,
	});
	writeAuthorityV1PinRequests(path, runId, retentionAnchorWallTimeMs);
	if (requestedDisposition !== generatedDisposition)
		rewritePublishedDescriptor(path, (descriptor) => {
			const serviceSeal = descriptor.serviceSeal as Record<string, unknown>;
			serviceSeal.terminalRelayDisposition = requestedDisposition;
		});
	return path;
}

function rewritePublishedDescriptor(incident: string, mutate: (descriptor: Record<string, unknown>) => void): void {
	const descriptorPath = join(incident, "finalization-descriptor.json");
	const descriptor = JSON.parse(readFileSync(descriptorPath, "utf8")) as Record<string, unknown>;
	mutate(descriptor);
	const record = finalizationFile(descriptorPath, descriptor);
	const manifestPath = join(incident, "finalization-manifest.json");
	const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
		files: Array<{ name: string; bytes: number; sha256: string }>;
	};
	manifest.files = manifest.files.map((entry) => (entry.name === record.name ? record : entry));
	json(manifestPath, manifest);
}

function writeServiceSealChain(
	run: string,
	runId: string,
	retentionAnchorWallTimeMs: number,
	options: {
		runToken?: string;
		terminalOccurrenceId?: string;
		sealTerminalOccurrenceId?: string | null;
		lossRecords?: number;
		stoppedDisposition?: "exact_first_observation" | "recovered_after_invalid_control";
	} = {},
): { runToken: string; terminalOccurrenceId: string } {
	const runToken = options.runToken ?? "30303030-3030-4030-8030-303030303030";
	const terminalOccurrenceId = options.terminalOccurrenceId ?? "40404040-4040-4040-8040-404040404040";
	const sealedTerminalOccurrenceId =
		options.sealTerminalOccurrenceId === undefined ? terminalOccurrenceId : options.sealTerminalOccurrenceId;
	const stoppedDisposition = options.stoppedDisposition ?? "exact_first_observation";
	json(join(run, "process.json"), {
		runToken,
		systemdInvocationId: null,
		pid: 123,
		processStartId: "proc:123",
		observed: { wallTime: "2026-08-25T12:00:00.000Z", monotonicNs: "1" },
		runtimeCategory: "foreign",
		nodeFatalReportsEnabled: false,
		orphanPolicy: "fail-open",
		wrapperDeathSignalsSupervisor: false,
	});
	if (stoppedDisposition === "recovered_after_invalid_control")
		json(join(run, "service-finalization-stopped-observation-repair.json"), {
			schemaVersion: 1,
			kind: "service_stopped_observation_repair",
			runId,
			runToken,
			reason: "invalid_control_observed",
		});
	json(join(run, "service-finalization-stopped-observation.json"), {
		schemaVersion: 1,
		kind: "service_stopped_observation",
		runId,
		runToken,
		firstObservedStoppedWallTimeMs: retentionAnchorWallTimeMs,
		disposition: stoppedDisposition,
	});
	json(join(run, "service-finalization-seal-intent.json"), {
		schemaVersion: 1,
		kind: "service_run_seal_intent",
		runId,
		runToken,
		terminalOccurrenceId,
		retentionAnchorWallTimeMs,
		stoppedObservationDisposition: stoppedDisposition,
	});
	const frontier =
		sealedTerminalOccurrenceId === null
			? null
			: {
					occurrenceId: sealedTerminalOccurrenceId,
					producerId: "50505050-5050-4050-8050-505050505050",
					type: "capture_channel_terminal",
					firstProducerSequence: "1",
					lastProducerSequence: "1",
					firstWrapperSequence: "1",
					lastWrapperSequence: "1",
				};
	const count = (records = 0) => ({ records, bytes: records });
	json(join(run, "service-finalization-seal.json"), {
		schemaVersion: 1,
		state: "sealed",
		runId,
		runToken,
		terminal: {
			type: "capture_channel_terminal",
			admission:
				sealedTerminalOccurrenceId === null
					? null
					: { accepted: true, occurrenceId: sealedTerminalOccurrenceId, disposition: "locally_admitted" },
			frontier,
		},
		loss: {
			emitter: count(options.lossRecords ?? 0),
			drainTimeout: { definite: count(), uncertain: count() },
			terminalRelay: { definite: count(), uncertain: count() },
		},
	});
	if (sealedTerminalOccurrenceId !== terminalOccurrenceId) {
		json(join(run, "service-finalization-seal-replay-ambiguity.json"), {
			schemaVersion: 1,
			kind: "service_run_seal_replay_ambiguity",
			runId,
			runToken,
			terminalOccurrenceId,
			reason:
				sealedTerminalOccurrenceId === null
					? "seal_intent_without_seal_observed"
					: "seal_namespace_invalid_or_unbound",
		});
	}
	return { runToken, terminalOccurrenceId };
}

function writeServiceReplayMarker(
	run: string,
	reason: "seal_intent_without_seal_observed" | "seal_observed_without_intent" | "seal_namespace_invalid_or_unbound",
): void {
	const intent = JSON.parse(readFileSync(join(run, "service-finalization-seal-intent.json"), "utf8")) as {
		runId: string;
		runToken: string;
		terminalOccurrenceId: string;
	};
	json(join(run, "service-finalization-seal-replay-ambiguity.json"), {
		schemaVersion: 1,
		kind: "service_run_seal_replay_ambiguity",
		runId: intent.runId,
		runToken: intent.runToken,
		terminalOccurrenceId: intent.terminalOccurrenceId,
		reason,
	});
}

function writeNormalServiceCompletion(
	run: string,
	runId: string,
	retentionAnchorWallTimeMs: number,
	options: Parameters<typeof writeServiceSealChain>[3] = {},
): string {
	const finalizationId = createHash("sha256").update(`normal\0${runId}\0${retentionAnchorWallTimeMs}`).digest("hex");
	const chain = writeServiceSealChain(run, runId, retentionAnchorWallTimeMs, options);
	json(join(run, `service-finalization-normal-authority-${finalizationId}.json`), {
		schemaVersion: 1,
		kind: "service_normal_retention_authority",
		runId,
		runToken: chain.runToken,
		finalizationId,
		classification: "normal",
		analysisState: "complete",
		retentionAnchorWallTimeMs,
		terminalOccurrenceId: chain.terminalOccurrenceId,
	});
	json(join(run, ".service-finalization-complete"), {
		schemaVersion: 2,
		state: "normal_reclaimable",
		runId,
		finalizationId,
		classification: "normal",
		retentionAnchorWallTimeMs,
	});
	return finalizationId;
}

function writeIncidentServiceCompletion(
	target: ReturnType<typeof fixture>,
	run: string,
	runId: string,
	retentionAnchorWallTimeMs: number,
	state: PublishedFinalizationState,
	options: {
		sealTerminalOccurrenceId?: string | null;
		lossRecords?: number;
		stoppedDisposition?: "exact_first_observation" | "recovered_after_invalid_control";
		serviceTerminalRelayDisposition?: string;
	} = {},
): string {
	const chain = writeServiceSealChain(run, runId, retentionAnchorWallTimeMs, {
		sealTerminalOccurrenceId:
			options.sealTerminalOccurrenceId === undefined
				? state === "complete"
					? undefined
					: null
				: options.sealTerminalOccurrenceId,
		...(options.lossRecords === undefined ? {} : { lossRecords: options.lossRecords }),
		...(options.stoppedDisposition === undefined ? {} : { stoppedDisposition: options.stoppedDisposition }),
	});
	const incident = finalizedIncident(target, basename(run), retentionAnchorWallTimeMs, {
		state,
		runId,
		runToken: chain.runToken,
		serviceTerminalRelayDisposition:
			options.serviceTerminalRelayDisposition ??
			(state === "complete" ? "relayed" : "replayed_after_ambiguous_seal_attempt"),
	});
	writeCanonicalIncompleteProviderOutcomes(incident, runId, retentionAnchorWallTimeMs);
	const manifest = JSON.parse(readFileSync(join(incident, "finalization-manifest.json"), "utf8")) as {
		finalizationId: string;
	};
	json(join(run, `service-finalization-publication-intent-${manifest.finalizationId}.json`), {
		schemaVersion: 1,
		kind: "service_finalization_publication_intent",
		runId,
		finalizationId: manifest.finalizationId,
	});
	json(join(run, ".service-finalization-complete"), {
		schemaVersion: 2,
		state: "incident_reclaimable",
		runId,
		finalizationId: manifest.finalizationId,
		outcome: state,
		retentionAnchorWallTimeMs,
	});
	return incident;
}

function writePublicationConflictServiceCompletion(
	target: ReturnType<typeof fixture>,
	run: string,
	runId: string,
	retentionAnchorWallTimeMs: number,
): {
	incident: string;
	publishedFinalizationId: string;
	intendedFinalizationId: string;
	conflictPath: string;
	completionPath: string;
} {
	const incident = writeIncidentServiceCompletion(target, run, runId, retentionAnchorWallTimeMs, "complete");
	const published = inspectPublishedIncidentFinalization({
		incidentsDirectory: target.incidents,
		incidentId: basename(run),
	});
	if (published.state === "pending" || published.retentionAnchorWallTimeMs === null)
		throw new Error("publication-conflict fixture lacks a published finalization");
	writeServiceReplayMarker(run, "seal_observed_without_intent");
	const intendedFinalizationId = createHash("sha256")
		.update(`publication-conflict\0${runId}\0${retentionAnchorWallTimeMs}`)
		.digest("hex");
	json(join(run, `service-finalization-publication-intent-${intendedFinalizationId}.json`), {
		schemaVersion: 1,
		kind: "service_finalization_publication_intent",
		runId,
		finalizationId: intendedFinalizationId,
	});
	const sealIntent = JSON.parse(readFileSync(join(run, "service-finalization-seal-intent.json"), "utf8")) as {
		runToken: string;
	};
	const conflict = {
		schemaVersion: 1,
		kind: "service_finalization_publication_conflict",
		runId,
		runToken: sealIntent.runToken,
		publishedFinalizationId: published.finalizationId,
		publishedState: published.state,
		publishedRetentionAnchorWallTimeMs: published.retentionAnchorWallTimeMs,
		publishedServiceTerminalRelayDisposition: published.serviceTerminalRelayDisposition,
		intendedFinalizationId,
		intendedState: "incomplete",
		intendedRetentionAnchorWallTimeMs: retentionAnchorWallTimeMs,
		intendedServiceTerminalRelayDisposition: "replayed_after_ambiguous_seal_attempt",
		reason: "published_finalization_conflict",
	};
	const conflictPath = join(run, "service-finalization-publication-conflict.json");
	json(conflictPath, conflict);
	const completionPath = join(run, ".service-finalization-complete");
	json(completionPath, {
		schemaVersion: 2,
		state: "publication_conflict_reclaimable",
		runId,
		publishedFinalizationId: published.finalizationId,
		intendedFinalizationId,
		conflictProofSha256: createHash("sha256")
			.update(`${JSON.stringify(conflict)}\n`)
			.digest("hex"),
		retentionAnchorWallTimeMs,
	});
	return {
		incident,
		publishedFinalizationId: published.finalizationId,
		intendedFinalizationId,
		conflictPath,
		completionPath,
	};
}

function writePrivateRootCorruptServiceCompletion(
	target: ReturnType<typeof fixture>,
	run: string,
	runId: string,
	retentionAnchorWallTimeMs: number,
): { incident: string; privateRoot: string; finalizationId: string } {
	const chain = writeServiceSealChain(run, runId, retentionAnchorWallTimeMs, {
		sealTerminalOccurrenceId: null,
	});
	const incidentId = basename(run);
	const input: IncidentRecorderFinalizationInput = {
		incidentsDirectory: target.incidents,
		incidentId,
		runIdentity: { runId, runToken: chain.runToken },
		runHistory: {
			state: "incomplete",
			reason: "fixture_private_root",
			projection: {
				version: 1,
				runId,
				fromWallTimeMs: 0,
				throughWallTimeMs: retentionAnchorWallTimeMs,
				events: [],
				terminalEvents: [],
				finalizationCandidates: [],
				ordering: {
					semantics: "partial_order",
					causalRelations: [],
					presentationTieBreak: "wall_time_then_identity_key",
					unrelatedPresentationOrderIsCausal: false,
					scope: "complete_snapshot",
				},
				evidence: [],
			},
		},
		terminalExpectations: {
			supervisorExit: { state: "unavailable", reason: "fixture" },
			wrapperTerminal: { state: "unavailable", reason: "fixture" },
			serviceTerminal: { state: "unavailable", reason: "fixture" },
		},
		classification: { value: "fixture", causeLayer: "fixture" },
		exit: { code: 1, signal: null },
		retentionAnchorWallTimeMs,
		stoppedTarget: { captureState: "complete", artifacts: [] },
		wrapperLoss: {
			finalQueuedTailLoss: { records: 0, bytes: 0 },
			emitterFinalTailLoss: { records: 0, bytes: 0 },
		},
		serviceSeal: {
			terminalRelayDisposition: "replayed_after_ambiguous_seal_attempt",
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
		assertProjectionLeaseUsable: () => {},
		releaseProjectionLease: () => {},
	};
	const interrupted = finalizeIncidentRecorderProjection(input, {
		onFaultBoundary: (boundary) => {
			if (boundary === "after_projection_lease_release_before_publish") throw new Error("fixture interruption");
		},
	});
	const incident = join(target.incidents, incidentId);
	mkdirSync(incident, { recursive: true, mode: 0o700 });
	writeFileSync(join(incident, "run-history.json"), "conflicting history", { mode: 0o600 });
	for (let index = 0; index < 8; index += 1)
		writeFileSync(
			join(incident, index === 0 ? "finalization-authority.json" : `finalization-authority-${index}.json`),
			`invalid selector ${index}`,
			{ mode: 0o600 },
		);
	const recovered = recoverPublishedIncidentFinalization({
		incidentsDirectory: target.incidents,
		incidentId,
		expectedFinalizationId: interrupted.finalizationId,
	});
	if (recovered.state !== "corrupt") throw new Error("Expected private-root conflict recovery");
	const privateRoot = join(incident, ".finalization-authority-root");
	json(join(incident, "retention-authority.json"), {
		schemaVersion: 1,
		kind: "incident_retention_authority",
		finalizationId: recovered.finalizationId,
		runId,
		outcome: "corrupt",
		retentionAnchorWallTimeMs,
	});
	writeAuthorityV1PinRequests(incident, runId, retentionAnchorWallTimeMs);
	writeCanonicalIncompleteProviderOutcomes(incident, runId, retentionAnchorWallTimeMs);
	json(join(run, `service-finalization-publication-intent-${recovered.finalizationId}.json`), {
		schemaVersion: 1,
		kind: "service_finalization_publication_intent",
		runId,
		finalizationId: recovered.finalizationId,
	});
	json(join(run, ".service-finalization-complete"), {
		schemaVersion: 2,
		state: "incident_reclaimable",
		runId,
		finalizationId: recovered.finalizationId,
		outcome: "corrupt",
		retentionAnchorWallTimeMs,
	});
	return { incident, privateRoot, finalizationId: recovered.finalizationId };
}

afterEach(() => {
	for (const release of compactorLeaseReleases.splice(0)) release();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("three-day diagnostic retention", () => {
	it("uses a bounded backlog-capable service cleanup budget", () => {
		expect(INCIDENT_RETENTION_SERVICE_BUDGET).toEqual({ maxEntries: 512, maxDeletes: 128 });
		expect(incidentRetentionNextDelayMs(true, 250)).toBe(250);
		expect(incidentRetentionNextDelayMs(false, 250)).toBe(60_000);
	});

	it("performs recovery cleanup without allocating protocol or mark files", () => {
		const target = fixture();
		const before = readdirSync(target.recorder).sort();
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
			recoveryOnly: true,
		});

		expect(result.uncertainties).toContain("lease-protocol-boundary-unavailable");
		expect(result.segmentPruneProtection).toEqual({ state: "building", generation: 0 });
		expect(readdirSync(target.recorder).sort()).toEqual(before);
		expect(existsSync(join(target.recorder, "lease-protocol-v1.json"))).toBe(false);
		expect(existsSync(join(target.recorder, "retention"))).toBe(false);
		const deadlineResult = runIncidentRetentionPass({
			agentDir: target.agentDir,
			deadlineMs: 0,
			recoveryOnly: true,
		});
		expect(deadlineResult).toMatchObject({ scannedEntries: 0, deletedEntries: 0, moreWork: true });
		expect(deadlineResult.segmentPruneProtection.state).toBe("building");
		expect(readdirSync(target.recorder).sort()).toEqual(before);
	});

	it("protects an old active run only with exact nonempty boot/PID/start identity", () => {
		const target = fixture();
		const path = runPath(target);
		json(join(path, ".recorder-active"), {
			role: "wrapper-proxy",
			machineId: "machine",
			bootId: "boot",
			pid: 4242,
			processStartId: "99",
		});
		old(path);
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
			processIdentity: (pid) => (pid === 4242 ? { state: "live", startId: "99" } : { state: "dead" }),
		});
		expect(existsSync(path)).toBe(true);
		expect(result.protectedActiveRuns).toEqual([expect.stringContaining("11111111-1111-4111-8111-111111111111")]);
		expect(result.segmentPruneProtection).toMatchObject({
			state: "complete",
			protectedRunIds: ["11111111-1111-4111-8111-111111111111"],
		});
	});

	it("protects canonical run IDs from retained v1 and v2 journal incidents", () => {
		const target = fixture();
		const anchor = NOW - DAY;
		const variants = [
			{
				name: "retained-v1",
				runId: "21212121-2121-4212-8212-212121212121",
				occurrenceReference: join(target.recorder, "refs", "legacy-occurrence.json"),
			},
			{
				name: "retained-v2",
				runId: "31313131-3131-4313-8313-313131313131",
				occurrenceReference: {
					kind: "segment",
					locator: journalSegmentLocator(1, "b".repeat(64)),
				},
			},
		] as const;
		const digest = createHash("sha256").update("x").digest("hex");
		for (const [index, variant] of variants.entries()) {
			const incident = finalizedIncident(target, variant.name, anchor, { runId: variant.runId });
			const generationId = journalArtifactGenerationId(variant.runId, anchor);
			const pinnedCasPath = join(incident, "journal-pins", "cas", `${digest}.blob`);
			mkdirSync(dirname(pinnedCasPath), { recursive: true, mode: 0o700 });
			writeFileSync(pinnedCasPath, "x", { mode: 0o600 });
			const sealedArtifact = sealFixtureArtifact(pinnedCasPath, generationId, digest);
			json(join(incident, "journal-pin-manifest.json"), {
				version: index + 1,
				state: "complete_through_requested_window",
				runId: variant.runId,
				fromWallTimeMs: anchor - 30 * 60 * 1_000,
				throughWallTimeMs: anchor + 15 * 60 * 1_000,
				artifactGenerationId: generationId,
				occurrences: [
					{
						occurrenceReference: variant.occurrenceReference,
						pinnedCasPath,
						cas: {
							digest,
							bytes: 1,
							path: join(target.recorder, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`),
						},
						cursors: [],
						eventWallTimeMs: String(anchor),
						sealedArtifact,
						...(index === 1 ? { semanticFingerprint: "c".repeat(64) } : {}),
					},
				],
			});
		}
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		expect(result.segmentPruneProtection).toMatchObject({
			state: "complete",
			protectedRunIds: variants.map((variant) => variant.runId),
		});
	});

	it("prefers the validated finalization manifest for protected-run identity", () => {
		const target = fixture();
		const runId = "32323232-3232-4323-8323-323232323232";
		const run = runPath(target, runId);
		json(join(run, ".retention-terminal.json"), {
			completed: { wallTime: new Date(NOW - 4 * DAY).toISOString(), monotonicNs: "1" },
			exitCode: 0,
			exitSignal: null,
		});
		finalizedIncident(target, "manifest-identified-incident", NOW - DAY, { runId });

		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});

		expect(existsSync(run)).toBe(true);
		expect(result.segmentPruneProtection).toMatchObject({ state: "complete", protectedRunIds: [runId] });
	});

	it("protects a pending run without treating missing terminal state as uncertain", () => {
		const target = fixture();
		const runId = "41414141-4141-4414-8414-414141414141";
		const path = runPath(target, runId);
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(path)).toBe(true);
		expect(result.uncertainties).not.toContain(`run-identity:${path}`);
		expect(result.segmentPruneProtection).toMatchObject({ state: "complete", protectedRunIds: [runId] });
	});

	it("keeps protection building for a malformed retained incident run identity", () => {
		const target = fixture();
		const anchor = NOW - DAY;
		const incident = finalizedIncident(target, "malformed-run-request", anchor);
		json(
			join(incident, "journal-pin-request.json"),
			authorityV1PinRequests("not-a-run-id", anchor, join(incident, ".fixture-sysdig-ring")).journal,
		);
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(incident)).toBe(true);
		expect(result.segmentPruneProtection.state).toBe("building");
		expect(result.uncertainties).toContain(`incident-run-identity:${incident}/journal-pin-request.json`);
	});

	it("protects hidden partial, projection, prepared, and publishing incidents and their runs", () => {
		const target = fixture();
		const stages = [
			{ stage: "partial", runId: "1a111111-1111-4111-8111-111111111111" },
			{ stage: "projection-attempt", runId: "2a222222-2222-4222-8222-222222222222" },
			{ stage: "prepared", runId: "3a333333-3333-4333-8333-333333333333" },
			{ stage: "publishing-attempt", runId: "4a444444-4444-4444-8444-444444444444" },
		] as const;
		const runPaths: string[] = [];
		const incidentPaths: string[] = [];
		for (const { stage, runId } of stages) {
			const run = runPath(target, runId);
			runPaths.push(run);
			json(join(run, ".retention-terminal.json"), {
				completed: { wallTime: new Date(NOW - 4 * DAY).toISOString(), monotonicNs: "1" },
				exitCode: 0,
				exitSignal: null,
			});
			const artifactName = basename(run);
			const incident = join(target.incidents, `.${artifactName}.${stage}`);
			mkdirSync(incident, { mode: 0o700 });
			incidentPaths.push(incident);
		}

		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});

		expect(result.pendingIncident).toBe(true);
		expect(incidentPaths.every((path) => existsSync(path))).toBe(true);
		expect(runPaths.every((path) => existsSync(path))).toBe(true);
		expect(result.segmentPruneProtection).toMatchObject({
			state: "complete",
			protectedRunIds: stages.map(({ runId }) => runId).sort(),
		});
	});

	it("does not remove a completed incident before three days or a pending +15m incident", () => {
		const target = fixture();
		const completed = finalizedIncident(target, "completed", NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS + 1);
		const pending = finalizedIncident(target, "pending", NOW, {
			runId: "11111111-1111-4111-8111-111111111111",
		});
		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(completed)).toBe(true);
		expect(existsSync(pending)).toBe(true);
	});

	it("never lets a forged summary authorize incident deletion without the finalization manifest", () => {
		const target = fixture();
		const incident = join(target.incidents, "forged-summary");
		mkdirSync(incident, { mode: 0o700 });
		json(join(incident, "summary.json"), {
			stoppedTargetCaptureComplete: true,
			finalized: { wallTime: new Date(NOW - 30 * DAY).toISOString(), monotonicNs: "1" },
		});

		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});

		expect(existsSync(incident)).toBe(true);
		expect(result.segmentPruneProtection.state).toBe("building");
	});

	it("requires the retention authority's exact compact schema", () => {
		const target = fixture();
		const anchor = NOW - 4 * DAY;
		const incident = finalizedIncident(target, "retention-authority-extra-key", anchor);
		writeCanonicalIncompleteProviderOutcomes(incident, DEFAULT_FINALIZATION_RUN_ID, anchor);
		const authorityPath = join(incident, "retention-authority.json");
		const authority = JSON.parse(readFileSync(authorityPath, "utf8")) as Record<string, unknown>;
		json(authorityPath, { ...authority, extra: true });
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(incident)).toBe(true);
		expect(result.uncertainties).toContain(`incident-state:${incident}`);
		expect(result.segmentPruneProtection.state).toBe("building");
	});

	it("honors a finalizer-resolved retention-authority conflict as corrupt quarantine and rejects tampering", () => {
		for (const tampered of [false, true]) {
			const target = fixture();
			const runId = tampered ? "51515151-5151-4515-8515-515151515151" : "50505050-5050-4505-8505-505050505050";
			const anchor = NOW - 4 * DAY;
			const incident = finalizedIncident(target, `run-${runId}`, anchor, { runId });
			writeCanonicalIncompleteProviderOutcomes(incident, runId, anchor);
			const published = JSON.parse(readFileSync(join(incident, "finalization-manifest.json"), "utf8")) as {
				finalizationId: string;
			};
			writeFileSync(join(incident, "retention-authority.json"), "{malformed\n", { mode: 0o600 });
			const persisted = persistIncidentRetentionAuthority({
				incidentDirectory: incident,
				finalizationId: published.finalizationId,
				runId,
				outcome: "complete",
				retentionAnchorWallTimeMs: anchor,
			});
			expect(persisted.state, tampered ? "tampered" : "valid").toBe("authorized");
			if (persisted.state !== "authorized") throw new Error("Expected conflict retention authority");
			expect(persisted.authoritySource).toBe("conflict");
			expect(persisted.retentionClass).toBe("corrupt");
			const privateManifest = join(incident, ".finalization-authority-root", "retention-authority-manifest.json");
			if (tampered) writeFileSync(privateManifest, "tampered", { mode: 0o600 });

			const quarantined = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), tampered ? "tampered" : "corrupt quarantine").toBe(true);
			if (tampered) expect(quarantined.uncertainties).toContain(`incident-state:${incident}`);

			if (!tampered) {
				runIncidentRetentionPass({
					agentDir: target.agentDir,
					nowMs: anchor + INCIDENT_CORRUPTION_QUARANTINE_MS + 1,
					maxEntries: 128,
					maxDeletes: 32,
					machineId: "machine",
					bootId: "boot",
				});
				expect(existsSync(incident)).toBe(false);
			}
		}
	});

	it("treats the manifest as the last publication authority and verifies its exact summary digest", () => {
		for (const variant of ["manifest-missing", "summary-changed", "retention-anchor-missing"] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const incident = finalizedIncident(target, variant, anchor);
			writeCanonicalIncompleteProviderOutcomes(incident, DEFAULT_FINALIZATION_RUN_ID, anchor);
			const manifestPath = join(incident, "finalization-manifest.json");
			const manifestBytes = readFileSync(manifestPath);
			if (variant === "manifest-missing") rmSync(manifestPath);
			else if (variant === "summary-changed")
				json(join(incident, "summary.json"), {
					stoppedTargetCaptureComplete: true,
					finalized: { wallTime: new Date(NOW - 30 * DAY).toISOString(), monotonicNs: "forged" },
				});
			else {
				const manifest = JSON.parse(manifestBytes.toString("utf8")) as Record<string, unknown>;
				delete manifest.retentionAnchorWallTimeMs;
				json(manifestPath, manifest);
			}

			const protectedResult = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident)).toBe(true);
			expect(protectedResult.segmentPruneProtection.state).toBe("building");

			if (variant === "manifest-missing") {
				writeFileSync(manifestPath, manifestBytes, { mode: 0o600 });
				runIncidentRetentionPass({
					agentDir: target.agentDir,
					nowMs: NOW,
					machineId: "machine",
					bootId: "boot",
				});
				expect(existsSync(incident)).toBe(false);
			}
		}
	});

	it("requires exact post-release retention authority before an expired incident can be reclaimed", () => {
		for (const variant of ["missing", "invalid", "run-mismatched", "anchor-mismatched"] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const incident = finalizedIncident(target, `authority-${variant}`, anchor);
			writeCanonicalIncompleteProviderOutcomes(incident, DEFAULT_FINALIZATION_RUN_ID, anchor);
			const authorityPath = join(incident, "retention-authority.json");
			const authorityBytes = readFileSync(authorityPath);
			if (variant === "missing") {
				rmSync(authorityPath);
			} else if (variant === "invalid") {
				writeFileSync(authorityPath, "{", { mode: 0o600 });
			} else if (variant === "run-mismatched") {
				const authority = JSON.parse(authorityBytes.toString("utf8")) as Record<string, unknown>;
				json(authorityPath, {
					...authority,
					runId: "30303030-3030-4030-8030-303030303030",
				});
			} else {
				const authority = JSON.parse(authorityBytes.toString("utf8")) as Record<string, unknown>;
				json(authorityPath, {
					...authority,
					retentionAnchorWallTimeMs: NOW - 4 * DAY + 1,
				});
			}

			const protectedResult = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident)).toBe(true);
			expect(protectedResult.segmentPruneProtection.state).toBe("building");

			writeFileSync(authorityPath, authorityBytes, { mode: 0o600 });
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident)).toBe(false);
		}
	});

	it("fails closed unless both provider requests satisfy the exact authority-v1 policy", () => {
		const anchor = NOW - 4 * DAY;
		const runId = "25252525-2525-4525-8525-252525252525";
		const expectedJournalKeys = [
			"anchorWallTimeMs",
			"fromWallTimeMs",
			"resolveAfterWallTimeMs",
			"retainUntilWallTimeMs",
			"runId",
			"state",
			"throughWallTimeMs",
			"version",
		];
		const expectedSysdigKeys = [
			"anchorWallTimeMs",
			"fromWallTimeMs",
			"initialRingSnapshot",
			"requestedAtWallTimeMs",
			"resolveAfterWallTimeMs",
			"retainUntilWallTimeMs",
			"ringBasePath",
			"runId",
			"throughWallTimeMs",
			"version",
		];
		const valid = authorityV1PinRequests(runId, anchor, "fixture-sysdig-ring");
		expect(Object.keys(valid.journal).sort()).toEqual(expectedJournalKeys);
		expect(Object.keys(valid.sysdig).sort()).toEqual(expectedSysdigKeys);
		expect(valid.journal).toMatchObject({
			version: 1,
			state: "pending",
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * MINUTE,
			throughWallTimeMs: anchor + 15 * MINUTE,
			resolveAfterWallTimeMs: anchor + 15 * MINUTE,
			retainUntilWallTimeMs: anchor + 3 * DAY,
		});
		expect(valid.sysdig).toMatchObject({
			version: 1,
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * MINUTE,
			throughWallTimeMs: anchor + 15 * MINUTE,
			resolveAfterWallTimeMs: anchor + 15 * MINUTE,
			requestedAtWallTimeMs: anchor,
			retainUntilWallTimeMs: anchor + 3 * DAY,
			initialRingSnapshot: { observedAtWallTimeMs: anchor, candidates: [], issues: [] },
		});

		const variants: Array<{
			name: string;
			invalidate: (incident: string, requests: ReturnType<typeof authorityV1PinRequests>) => void;
		}> = [
			{
				name: "wrong-anchor",
				invalidate: (incident, requests) =>
					json(join(incident, "journal-pin-request.json"), {
						...requests.journal,
						anchorWallTimeMs: anchor + 1,
					}),
			},
			{
				name: "string-anchor",
				invalidate: (incident, requests) =>
					json(join(incident, "journal-pin-request.json"), {
						...requests.journal,
						anchorWallTimeMs: String(anchor),
					}),
			},
			{
				name: "object-window",
				invalidate: (incident, requests) =>
					json(join(incident, "sysdig-pin-request.json"), {
						...requests.sysdig,
						throughWallTimeMs: { wallTime: anchor + 15 * MINUTE },
					}),
			},
			{
				name: "narrow-window",
				invalidate: (incident, requests) =>
					json(join(incident, "sysdig-pin-request.json"), {
						...requests.sysdig,
						fromWallTimeMs: anchor - 30 * MINUTE + 1,
					}),
			},
			{
				name: "missing-journal",
				invalidate: (incident) => rmSync(join(incident, "journal-pin-request.json")),
			},
			{
				name: "missing-sysdig",
				invalidate: (incident) => rmSync(join(incident, "sysdig-pin-request.json")),
			},
			{
				name: "journal-version",
				invalidate: (incident, requests) =>
					json(join(incident, "journal-pin-request.json"), { ...requests.journal, version: 2 }),
			},
			{
				name: "journal-state",
				invalidate: (incident, requests) =>
					json(join(incident, "journal-pin-request.json"), { ...requests.journal, state: "complete" }),
			},
			{
				name: "sysdig-version",
				invalidate: (incident, requests) =>
					json(join(incident, "sysdig-pin-request.json"), { ...requests.sysdig, version: 2 }),
			},
			{
				name: "sysdig-unexpected-state",
				invalidate: (incident, requests) =>
					json(join(incident, "sysdig-pin-request.json"), { ...requests.sysdig, state: "pending" }),
			},
			{
				name: "sysdig-snapshot-extra-key",
				invalidate: (incident, requests) =>
					json(join(incident, "sysdig-pin-request.json"), {
						...requests.sysdig,
						initialRingSnapshot: {
							...(requests.sysdig.initialRingSnapshot as Record<string, unknown>),
							extra: true,
						},
					}),
			},
			{
				name: "sysdig-snapshot-path-escape",
				invalidate: (incident, requests) => {
					const source = { dev: "1", ino: "2", bytes: 1, mtimeMs: anchor, ctimeMs: anchor };
					json(join(incident, "sysdig-pin-request.json"), {
						...requests.sysdig,
						initialRingSnapshot: {
							observedAtWallTimeMs: anchor,
							candidates: [
								{
									id: createHash("sha256")
										.update(
											`${source.dev}\0${source.ino}\0${source.bytes}\0${source.mtimeMs}\0${source.ctimeMs}`,
										)
										.digest("hex"),
									sourcePath: join(incident, "escaped.scap"),
									sourceName: ".fixture-sysdig-ring.0",
									activeAtRequest: true,
									source,
								},
							],
							issues: [],
						},
					});
				},
			},
			{
				name: "journal-extra-key",
				invalidate: (incident, requests) =>
					json(join(incident, "journal-pin-request.json"), { ...requests.journal, extra: true }),
			},
		];

		for (const variant of variants) {
			const target = fixture();
			const incident = finalizedIncident(target, `pin-request-${variant.name}`, anchor, { runId });
			writeCanonicalIncompleteProviderOutcomes(incident, runId, anchor);
			variant.invalidate(incident, authorityV1PinRequests(runId, anchor, join(incident, ".fixture-sysdig-ring")));

			const protectedResult = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), variant.name).toBe(true);
			expect(protectedResult.segmentPruneProtection.state, variant.name).toBe("building");

			writeAuthorityV1PinRequests(incident, runId, anchor);
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), `${variant.name} restored`).toBe(false);
		}
	});

	it("applies explicit three-day complete and incomplete retention boundaries", () => {
		for (const state of ["complete", "incomplete"] as const) {
			const target = fixture();
			const retained = finalizedIncident(target, `${state}-retained`, NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS + 1, {
				state,
			});
			const expired = finalizedIncident(target, `${state}-expired`, NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS, {
				state,
			});
			writeCanonicalIncompleteProviderOutcomes(
				retained,
				DEFAULT_FINALIZATION_RUN_ID,
				NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS + 1,
			);
			writeCanonicalIncompleteProviderOutcomes(
				expired,
				DEFAULT_FINALIZATION_RUN_ID,
				NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS,
			);

			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});

			expect(existsSync(retained)).toBe(true);
			expect(existsSync(expired)).toBe(false);
		}
	});

	it("uses the generic retention anchor independently of the exact supervisor-exit anchor", () => {
		const target = fixture();
		const retained = finalizedIncident(
			target,
			"retention-anchor-retained",
			NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS + 1,
			{ supervisorExitAnchorWallTimeMs: NOW - 30 * DAY },
		);
		const expired = finalizedIncident(target, "retention-anchor-expired", NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS, {
			supervisorExitAnchorWallTimeMs: NOW - DAY,
		});
		writeCanonicalIncompleteProviderOutcomes(
			retained,
			DEFAULT_FINALIZATION_RUN_ID,
			NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS + 1,
		);
		writeCanonicalIncompleteProviderOutcomes(
			expired,
			DEFAULT_FINALIZATION_RUN_ID,
			NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS,
		);

		runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});

		expect(existsSync(retained)).toBe(true);
		expect(existsSync(expired)).toBe(false);
	});

	it("quarantines validated corruption for fourteen days before bounded reclamation", () => {
		const target = fixture();
		const retained = finalizedIncident(target, "corrupt-retained", NOW - INCIDENT_CORRUPTION_QUARANTINE_MS + 1, {
			state: "corrupt",
		});
		const expired = finalizedIncident(target, "corrupt-expired", NOW - INCIDENT_CORRUPTION_QUARANTINE_MS, {
			state: "corrupt",
		});
		writeCanonicalIncompleteProviderOutcomes(
			retained,
			DEFAULT_FINALIZATION_RUN_ID,
			NOW - INCIDENT_CORRUPTION_QUARANTINE_MS + 1,
		);
		writeCanonicalIncompleteProviderOutcomes(
			expired,
			DEFAULT_FINALIZATION_RUN_ID,
			NOW - INCIDENT_CORRUPTION_QUARANTINE_MS,
		);

		runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});

		expect(existsSync(retained)).toBe(true);
		expect(existsSync(expired)).toBe(false);
	});

	it("removes a finalized incident after three days", () => {
		const target = fixture();
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS - 1;
		const path = finalizedIncident(target, "expired", anchor);
		writeCanonicalIncompleteProviderOutcomes(path, DEFAULT_FINALIZATION_RUN_ID, anchor);
		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(path)).toBe(false);
	});

	it("keeps generation and fingerprint stable, changes them with protection, and releases only after expiry", () => {
		const target = fixture();
		const incidentRunId = "51515151-5151-4515-8515-515151515151";
		const pendingRunId = "61616161-6161-4616-8616-616161616161";
		const anchor = NOW - DAY;
		const incident = finalizedIncident(target, "generation-retained", anchor, { runId: incidentRunId });
		writeCanonicalIncompleteProviderOutcomes(incident, incidentRunId, anchor);
		const pass = (nowMs: number) =>
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
		const first = pass(NOW).segmentPruneProtection;
		const stable = pass(NOW).segmentPruneProtection;
		expect(first.state).toBe("complete");
		expect(stable).toEqual(first);
		if (first.state !== "complete") return;
		runPath(target, pendingRunId);
		const changed = pass(NOW).segmentPruneProtection;
		expect(changed).toMatchObject({
			state: "complete",
			generation: first.generation + 1,
			protectedRunIds: [incidentRunId, pendingRunId],
		});
		if (changed.state !== "complete") return;
		expect(changed.fingerprint).not.toBe(first.fingerprint);
		const released = pass(anchor + 4 * DAY).segmentPruneProtection;
		expect(existsSync(incident)).toBe(false);
		expect(released).toMatchObject({
			state: "complete",
			generation: changed.generation + 1,
			protectedRunIds: [pendingRunId],
		});
	});

	it("resumes a recovery-only protection generation without filesystem allocation", () => {
		const target = fixture();
		runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		const runIds = [
			"71717171-7171-4717-8717-717171717171",
			"81818181-8181-4818-8818-818181818181",
			"91919191-9191-4919-8919-919191919191",
		];
		const runPaths = runIds.map((runId) => runPath(target, runId));
		const beforeRecorder = readdirSync(target.recorder).sort();
		let sawBuilding = false;
		let complete: ReturnType<typeof runIncidentRetentionPass>["segmentPruneProtection"] = {
			state: "building",
			generation: 0,
		};
		for (let pass = 0; pass < 256 && complete.state !== "complete"; pass += 1) {
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 1,
				maxDeletes: 1,
				machineId: "machine",
				bootId: "boot",
				recoveryOnly: true,
			});
			expect(result.scannedEntries).toBeLessThanOrEqual(1);
			if (result.segmentPruneProtection.state === "building") sawBuilding = true;
			complete = result.segmentPruneProtection;
		}
		expect(sawBuilding).toBe(true);
		expect(complete).toMatchObject({ state: "complete", protectedRunIds: runIds });
		expect(readdirSync(target.recorder).sort()).toEqual(beforeRecorder);
		for (const path of runPaths) expect(readdirSync(path)).toEqual([]);
	});

	it("keeps referenced CAS and removes unreferenced old CAS and refs", () => {
		const target = fixture();
		const keptDigest = "a".repeat(64);
		const removedDigest = "b".repeat(64);
		const keptBlob = join(target.recorder, "cas", "sha256", "aa", `${keptDigest}.blob`);
		const removedBlob = join(target.recorder, "cas", "sha256", "bb", `${removedDigest}.blob`);
		for (const [path, value] of [
			[keptBlob, "kept"],
			[removedBlob, "removed"],
		] as const) {
			mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
			writeFileSync(path, value, { mode: 0o600 });
			old(path);
		}
		const occurrence = join(target.recorder, "refs", "occurrences", "sha256", "aa", `${"c".repeat(64)}.json`);
		json(occurrence, { state: "complete", cas: { digest: keptDigest, path: keptBlob, bytes: 4 } });
		old(occurrence, DAY);
		const expiredRef = join(target.recorder, "refs", "gaps", `${"d".repeat(64)}.json`);
		json(expiredRef, { state: "gap_or_uncertainty" });
		old(expiredRef);

		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(keptBlob)).toBe(true);
		expect(existsSync(removedBlob)).toBe(false);
		expect(existsSync(expiredRef)).toBe(false);
		expect(existsSync(occurrence)).toBe(true);
	});

	it("preserves a CAS blob pinned by a retained hard link", () => {
		const target = fixture();
		const digest = "e".repeat(64);
		const blob = join(target.recorder, "cas", "sha256", "ee", `${digest}.blob`);
		mkdirSync(dirname(blob), { recursive: true, mode: 0o700 });
		writeFileSync(blob, "pinned", { mode: 0o600 });
		old(blob);
		const incident = finalizedIncident(target, "retained-pin", NOW - DAY);
		const pin = join(incident, "journal-pins", "cas", `${digest}.blob`);
		mkdirSync(dirname(pin), { recursive: true, mode: 0o700 });
		linkSync(blob, pin);
		runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW, machineId: "machine", bootId: "boot" });
		expect(existsSync(blob)).toBe(true);
		expect(statSync(blob).nlink).toBe(2);
	});

	it("fails closed when run identity metadata is uncertain", () => {
		const target = fixture();
		const path = runPath(target);
		writeFileSync(join(path, ".recorder-active"), "not-json", { mode: 0o600 });
		old(path);
		const digest = "f".repeat(64);
		const blob = join(target.recorder, "cas", "sha256", "ff", `${digest}.blob`);
		mkdirSync(dirname(blob), { recursive: true, mode: 0o700 });
		writeFileSync(blob, "uncertain", { mode: 0o600 });
		old(blob);
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(path)).toBe(true);
		expect(existsSync(blob)).toBe(true);
		expect(result.uncertainties).toContain(`run-identity:${path}`);
		expect(result.segmentPruneProtection.state).toBe("building");
	});

	it("bounds deletion work and makes progress over repeated passes", () => {
		const target = fixture();
		const paths = Array.from({ length: 4 }, (_value, index) => {
			const path = finalizedIncident(target, `expired-${index}`, NOW - 4 * DAY);
			writeCanonicalIncompleteProviderOutcomes(path, DEFAULT_FINALIZATION_RUN_ID, NOW - 4 * DAY);
			return path;
		});
		let previous = paths.length;
		let visibleProgressPasses = 0;
		for (let pass = 0; pass < 64 && previous > 0; pass += 1) {
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxDeletes: 2,
				maxEntries: 128,
				machineId: "machine",
				bootId: "boot",
			});
			expect(result.deletedEntries).toBeLessThanOrEqual(2);
			const remaining = paths.filter((path) => existsSync(path)).length;
			expect(remaining).toBeLessThanOrEqual(previous);
			if (remaining < previous) visibleProgressPasses += 1;
			previous = remaining;
		}
		expect(previous).toBe(0);
		expect(visibleProgressPasses).toBeGreaterThan(0);
		expect(readdirSync(target.incidents).filter((name) => !name.startsWith(".retention-gc-"))).toHaveLength(0);
	});

	it("resumes directory discovery when a scan batch ends before expired entries", () => {
		const target = fixture();
		for (let index = 0; index < 4; index += 1) finalizedIncident(target, `fresh-${index}`, NOW - DAY);
		const expired = Array.from({ length: 3 }, (_value, index) => {
			const path = finalizedIncident(target, `late-expired-${index}`, NOW - 4 * DAY);
			writeCanonicalIncompleteProviderOutcomes(path, DEFAULT_FINALIZATION_RUN_ID, NOW - 4 * DAY);
			return path;
		});
		for (let pass = 0; pass < 64 && expired.some((path) => existsSync(path)); pass += 1) {
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxDeletes: 4,
				maxEntries: 3,
				machineId: "machine",
				bootId: "boot",
			});
			expect(result.scannedEntries).toBeLessThanOrEqual(3);
		}
		expect(expired.every((path) => !existsSync(path))).toBe(true);
		for (let index = 0; index < 4; index += 1)
			expect(existsSync(join(target.incidents, `fresh-${index}`))).toBe(true);
	});

	it("matches the production proc:<start-ticks> identity format", () => {
		const target = fixture();
		const path = runPath(target, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
		const processStartId = getProcessStartId(process.pid);
		expect(processStartId).toMatch(/^proc:[0-9]+$/);
		json(join(path, ".recorder-active"), {
			role: "wrapper-proxy",
			machineId: readFileSync("/etc/machine-id", "utf8").trim(),
			bootId: readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim(),
			pid: process.pid,
			processStartId,
		});
		old(path);
		const result = runIncidentRetentionPass({ agentDir: target.agentDir, nowMs: NOW });
		expect(existsSync(path)).toBe(true);
		expect(result.protectedActiveRuns.some((name) => name.includes("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))).toBe(
			true,
		);
	});

	it("protects an abnormal stopped run until service finalization completes", () => {
		const target = fixture();
		const path = runPath(target, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
		json(join(path, ".retention-terminal.json"), {
			completed: { wallTime: new Date(NOW - 4 * DAY).toISOString(), monotonicNs: "1" },
			exitCode: 1,
			exitSignal: null,
		});
		old(path, 4 * DAY);
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(path)).toBe(true);
		expect(result.uncertainties).not.toContain(`run-identity:${path}`);
		expect(result.segmentPruneProtection).toMatchObject({
			state: "complete",
			protectedRunIds: ["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"],
		});
	});

	it("binds v2 service completion to durable authority and reclaims incident runs before incidents", () => {
		const target = fixture();
		const normalRunId = "b1b1b1b1-b1b1-4b1b-8b1b-b1b1b1b1b1b1";
		const completeRunId = "b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2";
		const corruptRunId = "b3b3b3b3-b3b3-4b3b-8b3b-b3b3b3b3b3b3";
		const normal = runPath(target, normalRunId);
		const complete = runPath(target, completeRunId);
		const corrupt = runPath(target, corruptRunId);
		writeNormalServiceCompletion(normal, normalRunId, NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS);
		const completeIncident = writeIncidentServiceCompletion(
			target,
			complete,
			completeRunId,
			NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS,
			"complete",
		);
		const corruptIncident = writeIncidentServiceCompletion(
			target,
			corrupt,
			corruptRunId,
			NOW - INCIDENT_CORRUPTION_QUARANTINE_MS,
			"corrupt",
		);
		const pass = () =>
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 512,
				maxDeletes: 128,
				machineId: "machine",
				bootId: "boot",
			});

		pass();
		expect(existsSync(normal)).toBe(false);
		expect(existsSync(complete)).toBe(false);
		expect(existsSync(corrupt)).toBe(false);
		expect(existsSync(completeIncident)).toBe(true);
		expect(existsSync(corruptIncident)).toBe(true);

		pass();
		expect(existsSync(completeIncident)).toBe(false);
		expect(existsSync(corruptIncident)).toBe(false);
	});

	it("fails closed for every malformed v2 service-finalization authority field", () => {
		const runId = "b4b4b4b4-b4b4-4b4b-8b4b-b4b4b4b4b4b4";
		const anchor = NOW - 30 * DAY;
		const incidentVariants: Array<[string, (marker: Record<string, unknown>) => void]> = [
			["schema-version", (marker) => (marker.schemaVersion = 3)],
			["state", (marker) => (marker.state = "published")],
			["run-id", (marker) => (marker.runId = "b5b5b5b5-b5b5-4b5b-8b5b-b5b5b5b5b5b5")],
			["finalization-id", (marker) => (marker.finalizationId = "not-a-finalization-id")],
			["outcome", (marker) => (marker.outcome = "unknown")],
			["anchor", (marker) => (marker.retentionAnchorWallTimeMs = -1)],
			["extra-key", (marker) => (marker.completed = { wallTime: new Date(anchor).toISOString() })],
			[
				"missing-anchor",
				(marker) => {
					delete marker.retentionAnchorWallTimeMs;
					marker.supervisorExitAnchorWallTimeMs = anchor;
				},
			],
		];
		for (const [name, mutate] of incidentVariants) {
			const target = fixture();
			const path = runPath(target, runId);
			writeIncidentServiceCompletion(target, path, runId, anchor, "complete");
			const markerPath = join(path, ".service-finalization-complete");
			const marker = JSON.parse(readFileSync(markerPath, "utf8")) as Record<string, unknown>;
			mutate(marker);
			json(markerPath, marker);
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(path), name).toBe(true);
			expect(result.uncertainties).toContain(`run-identity:${path}`);
			expect(result.segmentPruneProtection.state).toBe("building");
		}
		for (const [name, mutate] of [
			["classification", (marker: Record<string, unknown>) => (marker.classification = "abnormal")],
			["extra-outcome", (marker: Record<string, unknown>) => (marker.outcome = "complete")],
			[
				"missing-finalization-id",
				(marker: Record<string, unknown>) => {
					delete marker.finalizationId;
				},
			],
		] as const) {
			const target = fixture();
			const path = runPath(target, runId);
			writeNormalServiceCompletion(path, runId, anchor);
			const markerPath = join(path, ".service-finalization-complete");
			const marker = JSON.parse(readFileSync(markerPath, "utf8")) as Record<string, unknown>;
			mutate(marker);
			json(markerPath, marker);
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(path), name).toBe(true);
			expect(result.uncertainties).toContain(`run-identity:${path}`);
		}
	});

	it("retains a publication conflict through the exact fourteen-day boundary and reclaims run before incident", () => {
		const target = fixture();
		const runId = "b5b5b5b5-b5b5-4b5b-8b5b-b5b5b5b5b5b5";
		const run = runPath(target, runId);
		const anchor = NOW - INCIDENT_CORRUPTION_QUARANTINE_MS;
		const conflict = writePublicationConflictServiceCompletion(target, run, runId, anchor);
		const pass = (nowMs: number) =>
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs,
				maxEntries: 512,
				maxDeletes: 128,
				machineId: "machine",
				bootId: "boot",
			});

		pass(NOW - 1);
		expect(existsSync(run)).toBe(true);
		expect(existsSync(conflict.incident)).toBe(true);

		pass(NOW);
		expect(existsSync(run)).toBe(false);
		expect(existsSync(conflict.incident)).toBe(true);

		pass(NOW);
		expect(existsSync(conflict.incident)).toBe(false);
	});

	it("fails closed for malformed, mismatched, and noncanonical publication-conflict authority", () => {
		const variants: Array<{
			name: string;
			runId: string;
			mutate: (fixture: ReturnType<typeof writePublicationConflictServiceCompletion>) => void;
		}> = [
			{
				name: "reordered-proof",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b1",
				mutate: ({ conflictPath }) => rewriteControlEncoding(conflictPath, "reordered"),
			},
			{
				name: "extra-proof-field",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b2",
				mutate: ({ conflictPath }) => {
					const value = JSON.parse(readFileSync(conflictPath, "utf8")) as Record<string, unknown>;
					json(conflictPath, { ...value, extra: true });
				},
			},
			{
				name: "published-id-mismatch",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b3",
				mutate: ({ conflictPath, completionPath }) => {
					const value = JSON.parse(readFileSync(conflictPath, "utf8")) as Record<string, unknown>;
					value.publishedFinalizationId = "f".repeat(64);
					json(conflictPath, value);
					const completion = JSON.parse(readFileSync(completionPath, "utf8")) as Record<string, unknown>;
					completion.publishedFinalizationId = value.publishedFinalizationId;
					completion.conflictProofSha256 = createHash("sha256")
						.update(`${JSON.stringify(value)}\n`)
						.digest("hex");
					json(completionPath, completion);
				},
			},
			{
				name: "published-state-mismatch",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b4",
				mutate: ({ conflictPath, completionPath }) => {
					const value = JSON.parse(readFileSync(conflictPath, "utf8")) as Record<string, unknown>;
					value.publishedState = "incomplete";
					json(conflictPath, value);
					const completion = JSON.parse(readFileSync(completionPath, "utf8")) as Record<string, unknown>;
					completion.conflictProofSha256 = createHash("sha256")
						.update(`${JSON.stringify(value)}\n`)
						.digest("hex");
					json(completionPath, completion);
				},
			},
			{
				name: "published-anchor-mismatch",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b5",
				mutate: ({ conflictPath, completionPath }) => {
					const value = JSON.parse(readFileSync(conflictPath, "utf8")) as Record<string, unknown>;
					value.publishedRetentionAnchorWallTimeMs = Number(value.publishedRetentionAnchorWallTimeMs) + 1;
					json(conflictPath, value);
					const completion = JSON.parse(readFileSync(completionPath, "utf8")) as Record<string, unknown>;
					completion.retentionAnchorWallTimeMs = value.publishedRetentionAnchorWallTimeMs;
					completion.conflictProofSha256 = createHash("sha256")
						.update(`${JSON.stringify(value)}\n`)
						.digest("hex");
					json(completionPath, completion);
				},
			},
			{
				name: "completion-proof-mismatch",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b6",
				mutate: ({ completionPath }) => {
					const completion = JSON.parse(readFileSync(completionPath, "utf8")) as Record<string, unknown>;
					completion.intendedFinalizationId = "e".repeat(64);
					json(completionPath, completion);
				},
			},
			{
				name: "missing-proof-field",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b7",
				mutate: ({ conflictPath, completionPath }) => {
					const value = JSON.parse(readFileSync(conflictPath, "utf8")) as Record<string, unknown>;
					delete value.runToken;
					json(conflictPath, value);
					const completion = JSON.parse(readFileSync(completionPath, "utf8")) as Record<string, unknown>;
					completion.conflictProofSha256 = createHash("sha256")
						.update(`${JSON.stringify(value)}\n`)
						.digest("hex");
					json(completionPath, completion);
				},
			},
			{
				name: "public-proof",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b8",
				mutate: ({ conflictPath }) => chmodSync(conflictPath, 0o644),
			},
			{
				name: "hardlinked-proof",
				runId: "b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b9",
				mutate: ({ conflictPath }) => linkSync(conflictPath, join(dirname(conflictPath), "conflict-proof-link")),
			},
		];
		for (const variant of variants) {
			const target = fixture();
			const run = runPath(target, variant.runId);
			const conflict = writePublicationConflictServiceCompletion(target, run, variant.runId, NOW - 30 * DAY);
			variant.mutate(conflict);
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 512,
				maxDeletes: 128,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(run), variant.name).toBe(true);
			expect(existsSync(conflict.incident), variant.name).toBe(true);
			expect(result.uncertainties, variant.name).toContain(`run-identity:${run}`);
			expect(result.uncertainties, variant.name).toContain(`incident-state:${conflict.incident}`);
		}
	});

	it("rejects shape-valid but unbound completion markers and legacy terminal-only authority", () => {
		const variants = ["normal", "incident", "legacy-terminal"] as const;
		for (const variant of variants) {
			const target = fixture();
			const runId = `b6b6b6b6-b6b6-4b6b-8b6b-b6b6b6b6b6b${variant === "normal" ? "1" : variant === "incident" ? "2" : "3"}`;
			const run = runPath(target, runId);
			const anchor = NOW - 30 * DAY;
			if (variant === "normal") {
				json(join(run, ".service-finalization-complete"), {
					schemaVersion: 2,
					state: "normal_reclaimable",
					runId,
					finalizationId: "d".repeat(64),
					classification: "normal",
					retentionAnchorWallTimeMs: anchor,
				});
			} else if (variant === "incident") {
				json(join(run, ".service-finalization-complete"), {
					schemaVersion: 2,
					state: "incident_reclaimable",
					runId,
					finalizationId: "e".repeat(64),
					outcome: "complete",
					retentionAnchorWallTimeMs: anchor,
				});
			} else {
				json(join(run, ".retention-terminal.json"), {
					completed: { wallTime: new Date(anchor).toISOString(), monotonicNs: "1" },
					exitCode: 0,
					exitSignal: null,
				});
			}
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(run), variant).toBe(true);
			expect(result.segmentPruneProtection.state, variant).toBe(
				variant === "legacy-terminal" ? "complete" : "building",
			);
		}
	});

	it("requires exact replay evidence for a fence-only incident seal", () => {
		const target = fixture();
		const runId = "b7b7b7b7-b7b7-4b7b-8b7b-b7b7b7b7b7b7";
		const run = runPath(target, runId);
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
		writeIncidentServiceCompletion(target, run, runId, anchor, "incomplete");
		const replayPath = join(run, "service-finalization-seal-replay-ambiguity.json");
		const replay = JSON.parse(readFileSync(replayPath, "utf8")) as Record<string, unknown>;
		json(replayPath, { ...replay, extra: true });
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(run)).toBe(true);
		expect(result.uncertainties).toContain(`run-identity:${run}`);
	});

	it("rejects complete authority for every replay ambiguity and accepts the same canonical incomplete chains", () => {
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
		const terminalOccurrenceId = "40404040-4040-4040-8040-404040404040";
		const cases = [
			{
				name: "matching-replay",
				sealTerminalOccurrenceId: terminalOccurrenceId,
				replayReason: "seal_observed_without_intent" as const,
			},
			{
				name: "namespace-mismatch",
				sealTerminalOccurrenceId: "41414141-4141-4141-8141-414141414141",
			},
			{ name: "fence-only", sealTerminalOccurrenceId: null },
			{
				name: "fence-observed-without-intent",
				sealTerminalOccurrenceId: null,
				replayReason: "seal_observed_without_intent" as const,
			},
		] as const;
		for (const [index, testCase] of cases.entries()) {
			for (const state of ["complete", "incomplete"] as const) {
				const target = fixture();
				const runId = `b8b8b8b8-b8b8-4b8b-8b8b-b8b8b8b8b8${index}${state === "complete" ? "0" : "1"}`;
				const run = runPath(target, runId);
				writeIncidentServiceCompletion(target, run, runId, anchor, state, {
					sealTerminalOccurrenceId: testCase.sealTerminalOccurrenceId,
					...(state === "incomplete"
						? { serviceTerminalRelayDisposition: "replayed_after_ambiguous_seal_attempt" }
						: {}),
				});
				if ("replayReason" in testCase) writeServiceReplayMarker(run, testCase.replayReason);
				const result = runIncidentRetentionPass({
					agentDir: target.agentDir,
					nowMs: NOW,
					maxEntries: 256,
					maxDeletes: 64,
					machineId: "machine",
					bootId: "boot",
				});
				expect(existsSync(run), `${testCase.name}:${state}`).toBe(state === "complete");
				if (state === "complete") {
					expect(result.uncertainties).toContain(`run-identity:${run}`);
					expect(result.segmentPruneProtection.state).toBe("building");
				}
			}
		}
	});

	it("requires exact-first and loss-free source evidence, and defensively rejects forged non-relayed complete publication", () => {
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
		const cases: Array<{
			name: string;
			runId: string;
			options?: Parameters<typeof writeIncidentServiceCompletion>[5];
			deletes: boolean;
		}> = [
			{
				name: "valid",
				runId: "c1c1c1c1-c1c1-4c1c-8c1c-c1c1c1c1c1c1",
				deletes: true,
			},
			{
				name: "recovered-stopped",
				runId: "c2c2c2c2-c2c2-4c2c-8c2c-c2c2c2c2c2c2",
				options: { stoppedDisposition: "recovered_after_invalid_control" },
				deletes: false,
			},
			{
				name: "lossful",
				runId: "c3c3c3c3-c3c3-4c3c-8c3c-c3c3c3c3c3c3",
				options: { lossRecords: 1 },
				deletes: false,
			},
			{
				name: "unavailable-relay",
				runId: "c4c4c4c4-c4c4-4c4c-8c4c-c4c4c4c4c4c4",
				options: { serviceTerminalRelayDisposition: "unavailable" },
				deletes: false,
			},
			{
				name: "recovered-relay",
				runId: "c5c5c5c5-c5c5-4c5c-8c5c-c5c5c5c5c5c5",
				options: { serviceTerminalRelayDisposition: "recovered_after_invalid_stopped_observation" },
				deletes: false,
			},
		];
		for (const testCase of cases) {
			const target = fixture();
			const run = runPath(target, testCase.runId);
			writeIncidentServiceCompletion(target, run, testCase.runId, anchor, "complete", testCase.options);
			if (testCase.options?.serviceTerminalRelayDisposition) {
				const inspection = inspectPublishedIncidentFinalization({
					incidentsDirectory: target.incidents,
					incidentId: basename(run),
				});
				expect(inspection.state, `${testCase.name}:forward-inspector`).toBe("pending");
			}
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 256,
				maxDeletes: 64,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(run), testCase.name).toBe(!testCase.deletes);
			if (!testCase.deletes) expect(result.uncertainties).toContain(`run-identity:${run}`);
		}
	});

	it("matches the recorder compact-byte contract for every normal service authority control", () => {
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
		for (const control of ["stopped", "intent", "seal", "completion", "normal-authority"] as const) {
			for (const encoding of ["reordered", "pretty", "whitespace"] as const) {
				const target = fixture();
				const runId = "c6c6c6c6-c6c6-4c6c-8c6c-c6c6c6c6c6c6";
				const run = runPath(target, runId);
				const finalizationId = writeNormalServiceCompletion(run, runId, anchor);
				const controlPath =
					control === "stopped"
						? join(run, "service-finalization-stopped-observation.json")
						: control === "intent"
							? join(run, "service-finalization-seal-intent.json")
							: control === "seal"
								? join(run, "service-finalization-seal.json")
								: control === "completion"
									? join(run, ".service-finalization-complete")
									: join(run, `service-finalization-normal-authority-${finalizationId}.json`);
				rewriteControlEncoding(controlPath, encoding);
				runIncidentRetentionPass({
					agentDir: target.agentDir,
					nowMs: NOW,
					maxEntries: 256,
					maxDeletes: 64,
					machineId: "machine",
					bootId: "boot",
				});
				expect(existsSync(run), `${control}:${encoding}`).toBe(encoding !== "reordered");
			}
		}
	});

	it("matches the recorder's strict process identity and present barrier schema", () => {
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
		for (const variant of [
			"valid-barrier",
			"minimal-process",
			"malformed-barrier",
			"mismatched-barrier",
			"uppercase-token",
		] as const) {
			const target = fixture();
			const runId = "c7c7c7c7-c7c7-4c7c-8c7c-c7c7c7c7c7c7";
			const run = runPath(target, runId);
			const uppercaseToken = "ABABABAB-ABAB-4BAB-8BAB-ABABABABABAB";
			writeNormalServiceCompletion(
				run,
				runId,
				anchor,
				variant === "uppercase-token" ? { runToken: uppercaseToken } : {},
			);
			const processPath = join(run, "process.json");
			const processIdentity = JSON.parse(readFileSync(processPath, "utf8")) as { runToken: string };
			if (variant === "minimal-process") {
				json(processPath, { runToken: processIdentity.runToken });
			} else if (variant === "valid-barrier" || variant === "mismatched-barrier") {
				json(join(run, "finalization-barrier-expectation.json"), {
					version: 1,
					runId,
					runToken:
						variant === "mismatched-barrier" ? "90909090-9090-4090-8090-909090909090" : processIdentity.runToken,
					wrapperPid: 123,
					wrapperStartId: "proc:123",
					finalQueuedTailLoss: { records: 0, bytes: 0 },
					emitterFinalTailLoss: { records: 0, bytes: 0 },
					exitCode: 0,
					exitSignal: "unavailable",
				});
			} else if (variant === "malformed-barrier") {
				json(join(run, "finalization-barrier-expectation.json"), { malformed: true });
			}
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 256,
				maxDeletes: 64,
				machineId: "machine",
				bootId: "boot",
			});
			const deletes = variant === "valid-barrier";
			expect(existsSync(run), variant).toBe(!deletes);
			if (!deletes) expect(result.uncertainties).toContain(`run-identity:${run}`);
		}
	});

	it("fences the stopped-observation repair crash window and accepts only canonical recovered provenance", () => {
		for (const variant of ["exact-crash-window", "recovered-valid", "recovered-malformed"] as const) {
			const anchor =
				variant === "recovered-valid"
					? NOW - INCIDENT_CORRUPTION_QUARANTINE_MS
					: NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
			const target = fixture();
			const runId =
				variant === "exact-crash-window"
					? "d1d1d1d1-d1d1-4d1d-8d1d-d1d1d1d1d1d1"
					: variant === "recovered-valid"
						? "d2d2d2d2-d2d2-4d2d-8d2d-d2d2d2d2d2d2"
						: "d3d3d3d3-d3d3-4d3d-8d3d-d3d3d3d3d3d3";
			const run = runPath(target, runId);
			if (variant === "exact-crash-window") {
				writeNormalServiceCompletion(run, runId, anchor);
				const processIdentity = JSON.parse(readFileSync(join(run, "process.json"), "utf8")) as {
					runToken: string;
				};
				json(join(run, "service-finalization-stopped-observation-repair.json"), {
					schemaVersion: 1,
					kind: "service_stopped_observation_repair",
					runId,
					runToken: processIdentity.runToken,
					reason: "invalid_control_observed",
				});
			} else {
				writeIncidentServiceCompletion(target, run, runId, anchor, "incomplete", {
					stoppedDisposition: "recovered_after_invalid_control",
				});
				if (variant === "recovered-malformed") {
					const repairPath = join(run, "service-finalization-stopped-observation-repair.json");
					const repair = JSON.parse(readFileSync(repairPath, "utf8")) as Record<string, unknown>;
					json(repairPath, { ...repair, extra: true });
				}
			}
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 256,
				maxDeletes: 64,
				machineId: "machine",
				bootId: "boot",
			});
			const deletes = variant === "recovered-valid";
			expect(existsSync(run), variant).toBe(!deletes);
			if (!deletes) expect(result.uncertainties).toContain(`run-identity:${run}`);
		}
	});

	it("rejects normal authority when stopped evidence is recovered, lossful, or replay-ambiguous", () => {
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
		for (const variant of ["recovered-stopped", "lossful", "matching-replay"] as const) {
			const target = fixture();
			const runId = "c8c8c8c8-c8c8-4c8c-8c8c-c8c8c8c8c8c8";
			const run = runPath(target, runId);
			writeNormalServiceCompletion(
				run,
				runId,
				anchor,
				variant === "recovered-stopped"
					? { stoppedDisposition: "recovered_after_invalid_control" }
					: variant === "lossful"
						? { lossRecords: 1 }
						: {},
			);
			if (variant === "matching-replay") writeServiceReplayMarker(run, "seal_observed_without_intent");
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 256,
				maxDeletes: 64,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(run), variant).toBe(true);
			expect(result.uncertainties).toContain(`run-identity:${run}`);
		}
	});

	it("uses the writer's exact nested seal parser and admission-frontier invariants", () => {
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
		for (const variant of [
			"nested-extra",
			"unknown-rejection",
			"rejected-with-frontier",
			"frontier-mismatch",
		] as const) {
			const target = fixture();
			const runId = "c9c9c9c9-c9c9-4c9c-8c9c-c9c9c9c9c9c9";
			const run = runPath(target, runId);
			writeNormalServiceCompletion(run, runId, anchor);
			const sealPath = join(run, "service-finalization-seal.json");
			const seal = JSON.parse(readFileSync(sealPath, "utf8")) as {
				terminal: { admission: Record<string, unknown>; frontier: Record<string, unknown> | null };
				loss: { emitter: Record<string, unknown> };
			};
			if (variant === "nested-extra") seal.loss.emitter.extra = true;
			else if (variant === "unknown-rejection") {
				seal.terminal.admission = { accepted: false, disposition: "rejected", reason: "arbitrary" };
				seal.terminal.frontier = null;
			} else if (variant === "rejected-with-frontier") {
				seal.terminal.admission = { accepted: false, disposition: "rejected", reason: "stopped" };
			} else if (seal.terminal.frontier) {
				seal.terminal.frontier.occurrenceId = "42424242-4242-4242-8242-424242424242";
			}
			json(sealPath, seal);
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 256,
				maxDeletes: 64,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(run), variant).toBe(true);
			expect(result.uncertainties).toContain(`run-identity:${run}`);
		}
	});

	it("matches compact-byte parsing for replay, publication-intent, and retention authority controls", () => {
		const anchor = NOW - INCIDENT_DIAGNOSTIC_RETENTION_MS;
		for (const control of ["replay", "publication-intent", "retention-authority"] as const) {
			for (const encoding of ["reordered", "pretty", "whitespace"] as const) {
				const target = fixture();
				const runId = "c7c7c7c7-c7c7-4c7c-8c7c-c7c7c7c7c7c7";
				const run = runPath(target, runId);
				const incident = writeIncidentServiceCompletion(target, run, runId, anchor, "incomplete");
				const manifest = JSON.parse(readFileSync(join(incident, "finalization-manifest.json"), "utf8")) as {
					finalizationId: string;
				};
				const controlPath =
					control === "replay"
						? join(run, "service-finalization-seal-replay-ambiguity.json")
						: control === "publication-intent"
							? join(run, `service-finalization-publication-intent-${manifest.finalizationId}.json`)
							: join(incident, "retention-authority.json");
				rewriteControlEncoding(controlPath, encoding);
				runIncidentRetentionPass({
					agentDir: target.agentDir,
					nowMs: NOW,
					maxEntries: 256,
					maxDeletes: 64,
					machineId: "machine",
					bootId: "boot",
				});
				expect(existsSync(run), `${control}:${encoding}`).toBe(encoding !== "reordered");
			}
		}
	});

	it("uses the finalizer-resolved private authority root and fails closed after private descriptor tampering", () => {
		for (const tampered of [false, true]) {
			const target = fixture();
			const anchor = NOW - INCIDENT_CORRUPTION_QUARANTINE_MS;
			const runId = tampered ? "cacacaca-caca-4aca-8aca-cacacacacaca" : "cbcbcbcb-cbcb-4bcb-8bcb-cbcbcbcbcbcb";
			const run = runPath(target, runId);
			const authority = writePrivateRootCorruptServiceCompletion(target, run, runId, anchor);
			if (tampered) {
				const selector = JSON.parse(
					readFileSync(join(authority.privateRoot, "finalization-authority.json"), "utf8"),
				) as { manifest: { name: string } };
				const manifest = JSON.parse(readFileSync(join(authority.privateRoot, selector.manifest.name), "utf8")) as {
					conflictRecord: { name: string };
				};
				const conflict = JSON.parse(
					readFileSync(join(authority.privateRoot, manifest.conflictRecord.name), "utf8"),
				) as { files: Array<{ logicalName: string; prepared: { name: string } }> };
				const descriptor = conflict.files.find((file) => file.logicalName === "finalization-descriptor.json");
				if (!descriptor) throw new Error("Expected private-root descriptor mapping");
				writeFileSync(join(authority.privateRoot, descriptor.prepared.name), "tampered", { mode: 0o600 });
			}
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 512,
				maxDeletes: 128,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(run), tampered ? "tampered" : "valid").toBe(tampered);
			if (tampered) {
				expect(result.uncertainties).toContain(`run-identity:${run}`);
			} else {
				expect(existsSync(authority.incident)).toBe(true);
				runIncidentRetentionPass({
					agentDir: target.agentDir,
					nowMs: NOW,
					maxEntries: 512,
					maxDeletes: 128,
					machineId: "machine",
					bootId: "boot",
				});
				expect(existsSync(authority.incident)).toBe(false);
			}
		}
	});

	it("fails closed for a legacy fourteen-day Sysdig request", () => {
		const target = fixture();
		const anchor = NOW - 4 * DAY;
		const path = finalizedIncident(target, "legacy-sysdig", anchor, {
			runId: "11111111-1111-4111-8111-111111111111",
		});
		json(join(path, "sysdig-pin-request.json"), {
			version: 1,
			runId: "11111111-1111-4111-8111-111111111111",
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
			requestedAtWallTimeMs: anchor,
			retainUntilWallTimeMs: anchor + 14 * DAY,
			ringBasePath: "/var/lib/grimoire/sysdig-ring",
		});
		json(join(path, "sysdig-pin-manifest.json"), {
			state: "finalized_with_observed_coverage",
			runId: "11111111-1111-4111-8111-111111111111",
			retention: { milliseconds: 14 * DAY, retainUntilWallTimeMs: anchor + 14 * DAY },
			segments: [],
		});
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(path)).toBe(true);
		expect(result.segmentPruneProtection.state).toBe("building");
	});

	it("keeps active-run refs protected throughout a multi-pass run scan", () => {
		const target = fixture();
		const activeId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
		for (const id of ["dddddddd-dddd-4ddd-8ddd-dddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]) {
			const path = runPath(target, id);
			json(join(path, ".retention-terminal.json"), {
				completed: { wallTime: new Date(NOW - DAY).toISOString() },
				exitCode: 0,
				exitSignal: null,
			});
		}
		const active = runPath(target, activeId);
		json(join(active, ".recorder-active"), {
			role: "wrapper-proxy",
			machineId: "machine",
			bootId: "boot",
			pid: 1234,
			processStartId: "proc:88",
		});
		old(active, 4 * DAY);
		const runHash = createHash("sha256").update(activeId).digest("hex");
		const ref = join(target.recorder, "refs", "runs", runHash, "seq-old.json");
		json(ref, { runId: activeId, cas: { digest: "a".repeat(64) } });
		old(ref, 4 * DAY);
		for (let pass = 0; pass < 8; pass += 1) {
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 2,
				maxDeletes: 2,
				machineId: "machine",
				bootId: "boot",
				processIdentity: (pid) => (pid === 1234 ? { state: "live", startId: "proc:88" } : { state: "dead" }),
			});
			expect(existsSync(ref)).toBe(true);
		}
	});

	it("reconsiders new expired refs after a completed prune despite persistent CAS uncertainty", () => {
		const target = fixture();
		const uncertainRun = runPath(target, "abababab-abab-4bab-8bab-abababababab");
		writeFileSync(join(uncertainRun, ".recorder-active"), "not-json", { mode: 0o600 });
		old(uncertainRun, 4 * DAY);

		const first = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		expect(first.uncertainties).toContain(`run-identity:${uncertainRun}`);

		const lateRef = join(target.recorder, "refs", "gaps", "late-expired.json");
		json(lateRef, { state: "expired-after-prune" });
		old(lateRef, 4 * DAY);

		const second = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		expect(second.uncertainties).toContain(`run-identity:${uncertainRun}`);
		expect(existsSync(lateRef)).toBe(false);
	});

	it("sweeps an old unreferenced CAS while an exact-active run protects its referenced CAS", () => {
		const target = fixture();
		const run = runPath(target, "12121212-1212-4212-8212-121212121212");
		json(join(run, ".recorder-active"), {
			role: "wrapper-proxy",
			machineId: "machine",
			bootId: "boot",
			pid: 777,
			processStartId: "proc:7",
		});
		const keptDigest = "1".repeat(64);
		const removedDigest = "2".repeat(64);
		const kept = join(target.recorder, "cas", "sha256", "11", `${keptDigest}.blob`);
		const removed = join(target.recorder, "cas", "sha256", "22", `${removedDigest}.blob`);
		for (const path of [kept, removed]) {
			mkdirSync(dirname(path), { recursive: true });
			writeFileSync(path, path === kept ? "kept" : "removed");
			old(path, 4 * DAY);
		}
		const legacyReference = join(run, "legacy-reference.json");
		json(legacyReference, { cas: { digest: keptDigest, path: kept, bytes: 4 } });
		old(legacyReference, DAY);
		for (let pass = 0; pass < 8 && existsSync(removed); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
				processIdentity: (pid) => (pid === 777 ? { state: "live", startId: "proc:7" } : { state: "dead" }),
			});
		expect(existsSync(kept)).toBe(true);
		expect(existsSync(removed)).toBe(false);
	});

	it("fails closed behind a live cross-process CAS owner, then commits canonical path plus lease after release", async () => {
		const target = fixture();
		const writerLifecycleLease = compactorLifecycleLease(target);
		const owner = await startRetentionCasHolder(target.recorder);
		const source = join(target.root, "stopped.bin");
		writeFileSync(source, "transactional-bytes", { mode: 0o600 });
		const runId = "92929292-9292-4292-8292-929292929292";
		let compactor: IncidentRecorderCompactor | undefined;
		try {
			compactor = new IncidentRecorderCompactor({
				agentDir: target.agentDir,
				freeReserveBytes: 0,
				writerLifecycleLease,
			});
			await initializeStorageAccounting(compactor);
			let admission = compactor.streamStoppedTargetArtifact(runId, source, "binary", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 1024,
			});
			if (admission.state === "pending" && admission.reason === "work_budget")
				admission = compactor.streamStoppedTargetArtifact(runId, source, "binary", {
					deadlineMs: Date.now() + 1_000,
					byteBudget: 1024,
				});
			expect(admission).toMatchObject({ state: "pending", reason: "writer_lifecycle_unavailable", copiedBytes: 0 });
			expect(existsSync(join(target.recorder, "cas", "sha256", "staging"))).toBe(false);
		} finally {
			await owner.release();
		}
		if (!compactor) throw new Error("Expected initialized compactor");
		const completed = compactor.streamStoppedTargetArtifact(runId, source, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1024,
		});
		expect(completed.state).toBe("complete");
		if (completed.state !== "complete") return;
		expect(existsSync(completed.artifact.path)).toBe(true);
		const lease = join(
			target.recorder,
			"refs",
			"runs",
			createHash("sha256").update(runId).digest("hex"),
			`cas-${completed.artifact.digest}.blob`,
		);
		expect(statSync(lease).ino).toBe(statSync(completed.artifact.path).ino);
	});

	it("never follows a CAS shard symlink to delete an outside victim", () => {
		const target = fixture();
		const outside = join(target.root, "outside");
		mkdirSync(outside, { mode: 0o700 });
		const victim = join(outside, `${"d".repeat(64)}.blob`);
		writeFileSync(victim, "victim", { mode: 0o600 });
		old(victim, 4 * DAY);
		symlinkSync(outside, join(target.recorder, "cas", "sha256", "malicious-shard"));
		for (let pass = 0; pass < 8; pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(readFileSync(victim, "utf8")).toBe("victim");
	});

	it("does not follow a fixed persisted-mark temp symlink", () => {
		const target = fixture();
		const victim = join(target.root, "mark-victim");
		writeFileSync(victim, "safe", { mode: 0o600 });
		const retentionDir = join(target.recorder, "retention");
		mkdirSync(retentionDir, { recursive: true, mode: 0o700 });
		symlinkSync(victim, join(retentionDir, "legacy-marks-v1.log.tmp"));
		runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		expect(readFileSync(victim, "utf8")).toBe("safe");
	});

	it("rejects an EEXIST lease symlink instead of accepting its target contents", async () => {
		const target = fixture();
		const source = join(target.root, "lease-source.bin");
		writeFileSync(source, "lease-source", { mode: 0o600 });
		const digest = createHash("sha256").update("lease-source").digest("hex");
		const runId = "94949494-9494-4494-8494-949494949494";
		const owner = join(target.recorder, "refs", "runs", createHash("sha256").update(runId).digest("hex"));
		mkdirSync(owner, { recursive: true, mode: 0o700 });
		const victim = join(target.root, "lease-victim");
		writeFileSync(victim, "lease-source", { mode: 0o600 });
		symlinkSync(victim, join(owner, `cas-${digest}.blob`));
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			writerLifecycleLease: compactorLifecycleLease(target),
		});
		await initializeStorageAccounting(compactor);
		const result = compactor.streamStoppedTargetArtifact(runId, source, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 1024,
		});
		expect(result.state).toBe("error");
		expect(readFileSync(victim, "utf8")).toBe("lease-source");
	});

	it("rejects a stopped artifact changed in already-read bytes even when size and mtime are restored", async () => {
		const target = fixture();
		const source = join(target.root, "mutable.bin");
		writeFileSync(source, "abcdefgh", { mode: 0o600 });
		const original = statSync(source);
		const compactor = new IncidentRecorderCompactor({
			agentDir: target.agentDir,
			freeReserveBytes: 0,
			writerLifecycleLease: compactorLifecycleLease(target),
		});
		await initializeStorageAccounting(compactor);
		const first = compactor.streamStoppedTargetArtifact("93939393-9393-4393-8393-939393939393", source, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 4,
		});
		expect(first).toMatchObject({ state: "pending", copiedBytes: 4 });
		writeFileSync(source, "WXYZefgh", { mode: 0o600 });
		utimesSync(source, original.atime, original.mtime);
		const second = compactor.streamStoppedTargetArtifact("93939393-9393-4393-8393-939393939393", source, "binary", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 64,
		});
		expect(second).toMatchObject({ state: "error", reason: "artifact_source_changed_during_capture" });
	});

	it("skips more than 65,536 post-boundary leased refs while marking only legacy path refs", () => {
		const target = fixture();
		// Establish the durable lease-protocol boundary before current-protocol refs.
		runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		const leasedDigest = createHash("sha256").update("leased").digest("hex");
		const leasedBlob = join(target.recorder, "cas", "sha256", leasedDigest.slice(0, 2), `${leasedDigest}.blob`);
		mkdirSync(dirname(leasedBlob), { recursive: true, mode: 0o700 });
		writeFileSync(leasedBlob, "leased", { mode: 0o600 });
		const owner = join(target.recorder, "refs", "runs", "c".repeat(64));
		mkdirSync(owner, { recursive: true, mode: 0o700 });
		linkSync(leasedBlob, join(owner, `cas-${leasedDigest}.blob`));
		const bulk = join(target.recorder, "refs", "occurrences", "post-boundary-bulk");
		mkdirSync(bulk, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 65_537; index += 1) {
			const token = index.toString(16).padStart(64, "0");
			writeFileSync(join(bulk, `${index}.json`), `{"cas":{"digest":"${token}"}}\n`, { mode: 0o600 });
		}
		const legacyDigest = "a".repeat(64);
		const legacyBlob = join(target.recorder, "cas", "sha256", "aa", `${legacyDigest}.blob`);
		mkdirSync(dirname(legacyBlob), { recursive: true, mode: 0o700 });
		writeFileSync(legacyBlob, "legacy", { mode: 0o600 });
		old(legacyBlob, 4 * DAY);
		const legacyRef = join(target.recorder, "refs", "legacy-path.json");
		json(legacyRef, { cas: { digest: legacyDigest, path: legacyBlob } });
		old(legacyRef, DAY);
		const unreferencedDigest = "b".repeat(64);
		const unreferenced = join(target.recorder, "cas", "sha256", "bb", `${unreferencedDigest}.blob`);
		mkdirSync(dirname(unreferenced), { recursive: true, mode: 0o700 });
		writeFileSync(unreferenced, "old", { mode: 0o600 });
		old(unreferenced, 4 * DAY);
		for (let pass = 0; pass < 6_000 && existsSync(unreferenced); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(existsSync(unreferenced)).toBe(false);
		expect(existsSync(legacyBlob)).toBe(true);
		expect(existsSync(leasedBlob)).toBe(true);
	});

	it("resumes past 100 empty ref and CAS shards and converges on late entries", () => {
		const target = fixture();
		for (let index = 0; index < 100; index += 1) {
			const retainedShard = join(target.recorder, "refs", "plateau", String(index).padStart(3, "0"));
			mkdirSync(retainedShard, { recursive: true });
			json(join(retainedShard, "retained.json"), { state: "retained-prefix" });
			mkdirSync(join(target.recorder, "cas", "sha256", `empty-${String(index).padStart(3, "0")}`), {
				recursive: true,
			});
		}
		const lateRef = join(target.recorder, "refs", "plateau", "zzz", "late.json");
		json(lateRef, { state: "expired" });
		old(lateRef, 4 * DAY);
		const digest = "3".repeat(64);
		const lateBlob = join(target.recorder, "cas", "sha256", "zz", `${digest}.blob`);
		mkdirSync(dirname(lateBlob), { recursive: true });
		writeFileSync(lateBlob, "late");
		old(lateBlob, 4 * DAY);
		for (let pass = 0; pass < 20 && (existsSync(lateRef) || existsSync(lateBlob)); pass += 1) {
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
			expect(result.scannedEntries).toBeLessThanOrEqual(64);
		}
		expect(existsSync(lateRef)).toBe(false);
		expect(existsSync(lateBlob)).toBe(false);
	});

	it("finishes a late mark across budget passes before sweeping", () => {
		const target = fixture();
		for (let index = 0; index < 100; index += 1)
			mkdirSync(join(target.recorder, "refs", "occurrences", String(index).padStart(3, "0")), { recursive: true });
		const keptDigest = "4".repeat(64);
		const removedDigest = "5".repeat(64);
		const kept = join(target.recorder, "cas", "sha256", "44", `${keptDigest}.blob`);
		const removed = join(target.recorder, "cas", "sha256", "55", `${removedDigest}.blob`);
		for (const path of [kept, removed]) {
			mkdirSync(dirname(path), { recursive: true });
			writeFileSync(path, path === kept ? "kept" : "gone");
			old(path, 4 * DAY);
		}
		const lateReference = join(target.recorder, "refs", "occurrences", "zzz", "late.json");
		json(lateReference, { cas: { digest: keptDigest, path: kept, bytes: 4 } });
		old(lateReference, DAY);
		for (let pass = 0; pass < 24 && existsSync(removed); pass += 1) {
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(kept)).toBe(true);
		}
		expect(existsSync(removed)).toBe(false);
		expect(existsSync(kept)).toBe(true);
	});

	it("keeps a durable incomplete pin local while unrelated cleanup progresses", () => {
		const target = fixture();
		const anchor = NOW - 2 * DAY;
		const incident = finalizedIncident(target, "locally-incomplete", anchor, {
			runId: "67676767-6767-4767-8767-676767676767",
		});
		writeProviderPinIncomplete(incident, "journal", "67676767-6767-4767-8767-676767676767", anchor);
		const ref = join(target.recorder, "refs", "gaps", "unrelated.json");
		json(ref, { state: "old" });
		old(ref, 4 * DAY);
		const digest = "6".repeat(64);
		const blob = join(target.recorder, "cas", "sha256", "66", `${digest}.blob`);
		mkdirSync(dirname(blob), { recursive: true });
		writeFileSync(blob, "old");
		old(blob, 4 * DAY);
		for (let pass = 0; pass < 10 && (existsSync(ref) || existsSync(blob)); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(existsSync(incident)).toBe(true);
		expect(existsSync(ref)).toBe(false);
		expect(existsSync(blob)).toBe(false);
	});

	it("expires only with terminal outcomes from both requested providers", () => {
		for (const state of ["both-incomplete", "missing-journal", "missing-sysdig", "missing-both"] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const incident = finalizedIncident(target, `expired-${state}-pin`, anchor, {
				runId: "89898989-8989-4989-8989-898989898989",
			});
			if (state !== "missing-journal" && state !== "missing-both")
				writeProviderPinIncomplete(incident, "journal", "89898989-8989-4989-8989-898989898989", anchor);
			if (state !== "missing-sysdig" && state !== "missing-both")
				writeProviderPinIncomplete(incident, "sysdig", "89898989-8989-4989-8989-898989898989", anchor);
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), state).toBe(state !== "both-incomplete");
		}
	});

	it("fails closed for malformed or request-unbound provider incomplete outcomes", () => {
		const anchor = NOW - 4 * DAY;
		const runId = "96969696-9696-4969-8969-969696969696";
		const canonical = providerPinIncomplete("journal", runId, anchor);
		const variants: Array<{ name: string; provider: "journal" | "sysdig"; value: Record<string, unknown> }> = [
			{ name: "version", provider: "journal", value: { ...canonical, version: 2 } },
			{ name: "state", provider: "journal", value: { ...canonical, state: "complete" } },
			{
				name: "wrong-run",
				provider: "journal",
				value: { ...canonical, runId: "97979797-9797-4979-8979-979797979797" },
			},
			{ name: "wrong-anchor", provider: "journal", value: { ...canonical, anchorWallTimeMs: anchor + 1 } },
			{
				name: "string-anchor",
				provider: "journal",
				value: { ...canonical, anchorWallTimeMs: new Date(anchor).toISOString() },
			},
			{
				name: "object-anchor",
				provider: "journal",
				value: { ...canonical, anchorWallTimeMs: { wallTime: anchor } },
			},
			{
				name: "wrong-window",
				provider: "journal",
				value: { ...canonical, throughWallTimeMs: anchor + INCIDENT_PIN_AFTER_MS - 1 },
			},
			{
				name: "string-window",
				provider: "journal",
				value: { ...canonical, fromWallTimeMs: String(anchor - INCIDENT_PIN_BEFORE_MS) },
			},
			{ name: "empty-reason", provider: "journal", value: { ...canonical, reason: "" } },
			{ name: "oversized-reason", provider: "journal", value: { ...canonical, reason: "é".repeat(2_049) } },
			{ name: "wrong-provider", provider: "journal", value: { ...canonical, provider: "sysdig" } },
			{ name: "extra-key", provider: "journal", value: { ...canonical, retainedOccurrenceCount: 0 } },
			{
				name: "stray-sysdig",
				provider: "sysdig",
				value: { version: 1, state: "pending_or_incomplete", reason: "unbound", runId },
			},
		];
		for (const variant of variants) {
			const target = fixture();
			const incident = finalizedIncident(target, `incomplete-${variant.name}`, anchor, { runId });
			writeCanonicalIncompleteProviderOutcomes(incident, runId, anchor);
			json(join(incident, `${variant.provider}-pin-incomplete.json`), variant.value);
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), variant.name).toBe(true);
			expect(result.segmentPruneProtection.state, variant.name).toBe("building");
		}
	});

	it("prunes an expired run owner lease by owner-directory age, not renewed CAS inode mtime", () => {
		const target = fixture();
		const digest = "7".repeat(64);
		const blob = join(target.recorder, "cas", "sha256", "77", `${digest}.blob`);
		mkdirSync(dirname(blob), { recursive: true });
		writeFileSync(blob, "recurring");
		const owners = join(target.recorder, "refs", "runs");
		const oldOwner = join(owners, "a".repeat(64));
		const newerOwner = join(owners, "b".repeat(64));
		mkdirSync(oldOwner, { recursive: true });
		linkSync(blob, join(oldOwner, `cas-${digest}.blob`));
		old(oldOwner, 4 * DAY);
		// A newer exact duplicate renews the shared inode, including the old hard link.
		utimesSync(blob, (NOW - DAY) / 1_000, (NOW - DAY) / 1_000);
		mkdirSync(newerOwner, { recursive: true });
		linkSync(blob, join(newerOwner, `cas-${digest}.blob`));
		for (let pass = 0; pass < 8 && existsSync(oldOwner); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(existsSync(oldOwner)).toBe(false);
		expect(existsSync(blob)).toBe(true);
		// End the newer owner's lifecycle, then allow its own three-day window to pass.
		old(newerOwner, 4 * DAY);
		for (let pass = 0; pass < 16 && existsSync(blob); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW + 4 * DAY,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
		expect(existsSync(newerOwner)).toBe(false);
		expect(existsSync(blob)).toBe(false);
	});

	it("resumably backfills a proof for a proofless legacy producer manifest larger than one MiB", async () => {
		const target = fixture();
		const anchor = NOW - DAY;
		const runId = "90909090-9090-4090-8090-909090909090";
		const incident = finalizedIncident(target, "proofless-large-manifest", anchor, { runId });
		json(join(incident, "journal-pin-request.json"), {
			version: 1,
			state: "pending",
			runId,
			anchorWallTimeMs: anchor,
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
			retainUntilWallTimeMs: anchor + 3 * DAY,
		});
		const pinDirectory = join(incident, "journal-pins", "cas");
		mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
		const digest = createHash("sha256").update("x").digest("hex");
		const globalPath = join(target.recorder, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
		mkdirSync(dirname(globalPath), { recursive: true, mode: 0o700 });
		writeFileSync(globalPath, "x", { mode: 0o600 });
		const pinnedPath = join(pinDirectory, `${digest}.blob`);
		// Version 1 manifests are the legacy hard-link contract. A private
		// single-link sealed copy is a v2 artifact and must not be accepted as a
		// hybrid v1/v2 manifest during proof backfill.
		linkSync(globalPath, pinnedPath);
		const runToken = "80808080-8080-4080-8080-808080808080";
		const producerId = "70707070-7070-4070-8070-707070707070";
		const occurrenceId = "60606060-6060-4060-8060-606060606060";
		const identityKey = createHash("sha256")
			.update(`${runId}\0${runToken}\0${producerId}\0${occurrenceId}`)
			.digest("hex");
		const legacyDirectory = join(target.recorder, "refs", "runs", createHash("sha256").update(runId).digest("hex"));
		mkdirSync(legacyDirectory, { recursive: true, mode: 0o700 });
		const occurrenceReference = join(legacyDirectory, `seq-${"1".padStart(20, "0")}-${identityKey}.json`);
		json(occurrenceReference, {
			version: 1,
			state: "complete",
			identity: { runId, runToken, producerId, occurrenceId },
			source: "kernel",
			type: "kernel_unexpected_exit",
			encoding: "binary",
			payloadKind: "exact-bytes",
			terminal: true,
			metadata: {},
			eventWallTimeMs: String(anchor),
			eventMonotonicNs: "1",
			transportIdentity: {},
			wrapperOrder: ["1"],
			producerOrder: ["1"],
			cursors: ["cursor-0"],
			journalReferences: [],
			cas: {
				algorithm: "sha256",
				digest,
				bytes: 1,
				path: globalPath,
				compression: "none",
				resolution: "verified",
			},
			compactionDisposition: "compacted_and_cas_resolved",
			journalCanonicalUntilCompactionCommit: true,
		});
		const occurrence = {
			occurrenceReference,
			cursors: ["cursor-0"],
			cas: { digest, bytes: 1, path: globalPath },
			eventWallTimeMs: String(anchor),
			pinnedCasPath: pinnedPath,
		};
		const occurrences = Array.from({ length: 8192 }, () => occurrence);
		writeFileSync(
			join(incident, "journal-pin-manifest.json"),
			JSON.stringify({
				version: 1,
				state: "complete_through_requested_window",
				runId,
				fromWallTimeMs: anchor - 30 * 60 * 1_000,
				throughWallTimeMs: anchor + 15 * 60 * 1_000,
				occurrences,
			}),
			{ mode: 0o600 },
		);
		const manifestSize = statSync(join(incident, "journal-pin-manifest.json")).size;
		expect(manifestSize).toBeGreaterThan(1024 * 1024);
		expect(manifestSize).toBeLessThanOrEqual(8 * 1024 * 1024);
		const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
		await initializeStorageAccounting(compactor);
		for (let pass = 0; pass < 400 && !existsSync(join(incident, "journal-pin-retention-proof.json")); pass += 1)
			compactor.processPendingPins(NOW);
		const proof = JSON.parse(readFileSync(join(incident, "journal-pin-retention-proof.json"), "utf8")) as Record<
			string,
			unknown
		>;
		expect(proof).toMatchObject({ state: "producer_verified_complete", occurrenceCount: 8192, runId });
	});

	it("rejects proofless manifests that are truncated or have missing, wrong-content, or wrong-path pins", async () => {
		for (const variant of ["truncated", "missing", "wrong-digest", "wrong-path"] as const) {
			const target = fixture();
			const anchor = NOW - DAY;
			const runId = "91919191-9191-4191-8191-919191919191";
			const incident = finalizedIncident(target, `invalid-proofless-${variant}`, anchor, { runId });
			json(join(incident, "journal-pin-request.json"), {
				version: 1,
				state: "pending",
				runId,
				anchorWallTimeMs: anchor,
				fromWallTimeMs: anchor - 30 * 60 * 1_000,
				throughWallTimeMs: anchor + 15 * 60 * 1_000,
				resolveAfterWallTimeMs: anchor + 15 * 60 * 1_000,
				retainUntilWallTimeMs: anchor + 3 * DAY,
			});
			const digest = variant === "wrong-digest" ? "0".repeat(64) : createHash("sha256").update("x").digest("hex");
			const globalPath = join(target.recorder, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
			mkdirSync(dirname(globalPath), { recursive: true, mode: 0o700 });
			writeFileSync(globalPath, "x", { mode: 0o600 });
			const pinDirectory = join(incident, "journal-pins", "cas");
			mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
			const expectedPinnedPath = join(pinDirectory, `${digest}.blob`);
			if (variant !== "missing") linkSync(globalPath, expectedPinnedPath);
			const occurrence = {
				occurrenceReference: `${join(target.recorder, "refs")}/invalid`,
				cursors: ["cursor"],
				cas: { digest, bytes: 1, path: globalPath },
				eventWallTimeMs: String(anchor),
				pinnedCasPath: variant === "wrong-path" ? join(incident, "outside-pin.blob") : expectedPinnedPath,
			};
			const manifestPath = join(incident, "journal-pin-manifest.json");
			if (variant === "truncated")
				writeFileSync(
					manifestPath,
					`{"version":1,"state":"complete_through_requested_window","runId":"${runId}","fromWallTimeMs":${anchor - 30 * 60 * 1_000},"throughWallTimeMs":${anchor + 15 * 60 * 1_000},"occurrences":[`,
					{ mode: 0o600 },
				);
			else
				writeFileSync(
					manifestPath,
					JSON.stringify({
						version: 1,
						state: "complete_through_requested_window",
						runId,
						fromWallTimeMs: anchor - 30 * 60 * 1_000,
						throughWallTimeMs: anchor + 15 * 60 * 1_000,
						occurrences: [occurrence],
					}),
					{ mode: 0o600 },
				);
			const compactor = new IncidentRecorderCompactor({ agentDir: target.agentDir, freeReserveBytes: 0 });
			await initializeStorageAccounting(compactor);
			for (let pass = 0; pass < 40 && !existsSync(join(incident, "journal-pin-manifest-invalid.json")); pass += 1)
				compactor.processPendingPins(NOW);
			expect(existsSync(join(incident, "journal-pin-retention-proof.json"))).toBe(false);
			expect(existsSync(join(incident, "journal-pin-manifest-invalid.json"))).toBe(true);
		}
	});

	it("requires an explicit resolved-occurrence attestation on journal producer proofs", () => {
		for (const occurrenceReferencesResolved of [undefined, false, true] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const runId = "73737373-7373-4737-8737-737373737373";
			const incident = finalizedIncident(target, `producer-proof-${String(occurrenceReferencesResolved)}`, anchor, {
				runId,
			});
			writeProviderPinIncomplete(incident, "sysdig", runId, anchor);
			const manifestPath = join(incident, "journal-pin-manifest.json");
			const generationId = journalArtifactGenerationId(runId, anchor);
			json(manifestPath, {
				version: 2,
				state: "complete_through_requested_window",
				runId,
				fromWallTimeMs: anchor - 30 * MINUTE,
				throughWallTimeMs: anchor + 15 * MINUTE,
				artifactGenerationId: generationId,
				occurrences: [],
			});
			const pinDirectory = join(incident, "journal-pins", "cas");
			mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
			const manifestStat = statSync(manifestPath);
			const pinStat = statSync(pinDirectory);
			json(join(incident, "journal-pin-retention-proof.json"), {
				version: 1,
				state: "producer_verified_complete",
				provider: "journal",
				artifactGenerationId: generationId,
				manifestValidated: true,
				...(occurrenceReferencesResolved === undefined ? {} : { occurrenceReferencesResolved }),
				runId,
				fromWallTimeMs: anchor - 30 * 60 * 1_000,
				throughWallTimeMs: anchor + 15 * 60 * 1_000,
				retainUntilWallTimeMs: anchor + 3 * DAY,
				retentionMilliseconds: 3 * DAY,
				occurrenceCount: 0,
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
					dev: String(pinStat.dev),
					ino: String(pinStat.ino),
					mtimeMs: pinStat.mtimeMs,
					ctimeMs: pinStat.ctimeMs,
				},
			});
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 64,
				maxDeletes: 16,
				machineId: "machine",
				bootId: "boot",
			});
			if (occurrenceReferencesResolved === true) {
				expect(existsSync(incident)).toBe(false);
			} else {
				expect(existsSync(incident)).toBe(true);
				expect(result.uncertainties).toContain(`incident-state:${incident}`);
				expect(result.segmentPruneProtection.state).toBe("building");
			}
		}
	});

	it("holds an otherwise valid bare provider manifest until producer recovery restores proof authority", () => {
		const target = fixture();
		const anchor = NOW - 4 * DAY;
		const runId = "72727272-7272-4727-8727-727272727272";
		const incident = finalizedIncident(target, "valid-bare-journal-manifest", anchor, { runId });
		writeJournalProducerProof(incident, runId, anchor, Buffer.from("proof-required"));
		rmSync(join(incident, "journal-pin-retention-proof.json"));
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});
		expect(existsSync(incident)).toBe(true);
		expect(result.uncertainties).toContain(`incident-state:${incident}`);
		expect(result.segmentPruneProtection.state).toBe("building");
	});

	it("binds self-consistent proof and artifact generations to the exact request", () => {
		for (const provider of ["journal", "sysdig"] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const runId =
				provider === "journal" ? "71717171-7171-4717-8717-717171717171" : "70707070-7070-4707-8707-707070707070";
			const incident = finalizedIncident(target, `wrong-request-generation-${provider}`, anchor, { runId });
			if (provider === "journal") writeJournalProducerProof(incident, runId, anchor, Buffer.from("x"));
			else writeSysdigProducerProof(incident, runId, anchor, [Buffer.from("x")]);
			const wrongGenerationId = "f".repeat(64);
			const manifestPath = join(incident, `${provider}-pin-manifest.json`);
			const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
			manifest.artifactGenerationId = wrongGenerationId;
			const records =
				provider === "journal"
					? (manifest.occurrences as Array<Record<string, unknown>>)
					: (manifest.segments as Array<Record<string, unknown>>);
			for (const record of records)
				(record.sealedArtifact as Record<string, unknown>).generationId = wrongGenerationId;
			json(manifestPath, manifest);
			const proofPath = join(incident, `${provider}-pin-retention-proof.json`);
			const proof = JSON.parse(readFileSync(proofPath, "utf8")) as Record<string, unknown>;
			proof.artifactGenerationId = wrongGenerationId;
			json(proofPath, proof);
			refreshProviderProofManifestIdentity(incident, provider);
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), provider).toBe(true);
			expect(result.segmentPruneProtection.state, provider).toBe("building");
		}
	});

	it("rehashes journal and Sysdig artifacts instead of trusting producer proof identities", () => {
		for (const provider of ["journal", "sysdig"] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const runId =
				provider === "journal" ? "74747474-7474-4747-8747-747474747474" : "75757575-7575-4757-8757-757575757575";
			const incident = finalizedIncident(target, `mutated-${provider}-proof`, anchor, { runId });
			const pinnedPath =
				provider === "journal"
					? writeJournalProducerProof(incident, runId, anchor, Buffer.from("x"))
					: writeSysdigProducerProof(incident, runId, anchor, [Buffer.from("x")])[0];
			chmodSync(pinnedPath, 0o600);
			writeFileSync(pinnedPath, "y", { mode: 0o600 });
			chmodSync(pinnedPath, 0o400);

			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), provider).toBe(true);
			expect(result.segmentPruneProtection.state, provider).toBe("building");
		}
	});

	it("rejects escaped, linked, public, and schema-expanded pinned artifacts", () => {
		for (const variant of [
			"escaped",
			"symlink",
			"hardlink",
			"public",
			"record-extra",
			"cas-extra",
			"sealed-extra",
			"generation-mismatch",
			"stray-blob",
			"partial",
		] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const runId = "76767676-7676-4767-8767-767676767676";
			const incident = finalizedIncident(target, `invalid-journal-pin-${variant}`, anchor, { runId });
			const pinnedPath = writeJournalProducerProof(incident, runId, anchor, Buffer.from("x"));
			const manifestPath = join(incident, "journal-pin-manifest.json");
			const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
				occurrences: Array<Record<string, unknown>>;
			};
			const occurrence = manifest.occurrences[0];
			if (variant === "escaped") {
				const escaped = join(incident, "escaped.blob");
				writeFileSync(escaped, "x", { mode: 0o600 });
				occurrence.pinnedCasPath = escaped;
				json(manifestPath, manifest);
			} else if (variant === "symlink") {
				const targetPath = join(incident, "symlink-target.blob");
				writeFileSync(targetPath, "x", { mode: 0o600 });
				rmSync(pinnedPath);
				symlinkSync(targetPath, pinnedPath);
			} else if (variant === "hardlink") {
				linkSync(pinnedPath, join(incident, "second-link.blob"));
			} else if (variant === "public") {
				chmodSync(pinnedPath, 0o644);
			} else if (variant === "record-extra") {
				occurrence.extra = true;
				json(manifestPath, manifest);
			} else if (variant === "cas-extra") {
				(occurrence.cas as Record<string, unknown>).extra = true;
				json(manifestPath, manifest);
			} else if (variant === "sealed-extra") {
				(occurrence.sealedArtifact as Record<string, unknown>).extra = true;
				json(manifestPath, manifest);
			} else if (variant === "generation-mismatch") {
				(manifest as Record<string, unknown>).artifactGenerationId = "0".repeat(64);
				json(manifestPath, manifest);
			} else {
				writeFileSync(
					join(dirname(pinnedPath), variant === "stray-blob" ? `${"f".repeat(64)}.blob` : ".capture.partial"),
					"unexpected",
					{ mode: 0o400 },
				);
			}
			if (["escaped", "record-extra", "cas-extra", "sealed-extra", "generation-mismatch"].includes(variant))
				refreshProviderProofManifestIdentity(incident, "journal");

			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), variant).toBe(true);
			expect(result.segmentPruneProtection.state, variant).toBe("building");
		}

		for (const variant of [
			"exact-bytes-extra",
			"source-ctime-missing",
			"source-extra",
			"source-ctime-drift",
			"capture-missing",
			"capture-extra",
			"capture-identity-drift",
			"capture-ctime-after-seal",
			"stray-scap",
		] as const) {
			const target = fixture();
			const anchor = NOW - 4 * DAY;
			const runId = "77777777-7777-4777-8777-777777777777";
			const incident = finalizedIncident(target, `invalid-sysdig-${variant}`, anchor, { runId });
			const [pinnedPath] = writeSysdigProducerProof(incident, runId, anchor, [Buffer.from("x")]);
			const manifestPath = join(incident, "sysdig-pin-manifest.json");
			if (variant !== "stray-scap") {
				const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
					segments: Array<Record<string, unknown>>;
				};
				const segment = manifest.segments[0];
				const source = segment.source as Record<string, unknown>;
				const capture = segment.artifactAtCapture as Record<string, unknown>;
				const sealed = segment.sealedArtifact as Record<string, unknown>;
				if (variant === "exact-bytes-extra") (segment.exactBytes as Record<string, unknown>).extra = true;
				else if (variant === "source-ctime-missing") delete source.ctimeMs;
				else if (variant === "source-extra") source.extra = true;
				else if (variant === "source-ctime-drift") source.ctimeMs = Number(source.ctimeMs) + 1;
				else if (variant === "capture-missing") delete segment.artifactAtCapture;
				else if (variant === "capture-extra") capture.extra = true;
				else if (variant === "capture-identity-drift") capture.dev = "999999";
				else capture.ctimeMs = Number(sealed.ctimeMs) + 1;
				json(manifestPath, manifest);
				refreshProviderProofManifestIdentity(incident, "sysdig");
			} else {
				writeFileSync(join(dirname(pinnedPath), `${"e".repeat(64)}.scap`), "unexpected", { mode: 0o400 });
			}
			const result = runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
			expect(existsSync(incident), variant).toBe(true);
			expect(result.segmentPruneProtection.state, variant).toBe("building");
		}
	});

	it("advances large proofs across incidents without starving a same-provider traversal", () => {
		const target = fixture();
		const anchor = NOW - 4 * DAY;
		const incidents = [
			finalizedIncident(target, "large-sysdig-proof-a", anchor, {
				runId: "81818181-8181-4818-8181-818181818181",
			}),
			finalizedIncident(target, "large-sysdig-proof-b", anchor, {
				runId: "82828282-8282-4828-8282-828282828282",
			}),
		];
		writeSysdigProducerProof(incidents[0], "81818181-8181-4818-8181-818181818181", anchor, [
			Buffer.alloc(5 * 1024 * 1024, 0x61),
		]);
		writeSysdigProducerProof(incidents[1], "82828282-8282-4828-8282-828282828282", anchor, [
			Buffer.alloc(5 * 1024 * 1024, 0x62),
		]);
		const first = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});
		expect(first.moreWork).toBe(true);
		expect(incidents.every((incident) => existsSync(incident))).toBe(true);
		for (let pass = 0; pass < 12 && incidents.some((incident) => existsSync(incident)); pass += 1)
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
		expect(incidents.every((incident) => !existsSync(incident))).toBe(true);
	});

	it("accepts the producer's private single-link sealed-generation contract across bounded hash passes", () => {
		const target = fixture();
		const anchor = NOW - 4 * DAY;
		const runId = "83838383-8383-4838-8383-838383838383";
		const incident = finalizedIncident(target, "post-hash-artifact-mutation", anchor, { runId });
		const pinnedPaths = writeSysdigProducerProof(incident, runId, anchor, [
			Buffer.from("a"),
			Buffer.alloc(5 * 1024 * 1024, 0x62),
		]);
		const first = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			maxEntries: 128,
			maxDeletes: 32,
			machineId: "machine",
			bootId: "boot",
		});
		expect(first.moreWork).toBe(true);
		expect(statSync(pinnedPaths[0]).mode & 0o777).toBe(0o400);
		expect(statSync(pinnedPaths[0]).nlink).toBe(1);
		for (let pass = 0; pass < 4 && existsSync(incident); pass += 1) {
			runIncidentRetentionPass({
				agentDir: target.agentDir,
				nowMs: NOW,
				maxEntries: 128,
				maxDeletes: 32,
				machineId: "machine",
				bootId: "boot",
			});
		}
		expect(existsSync(incident)).toBe(false);
	});

	it("validates a near-maximum-byte producer manifest within a finite service deadline and bounded artifact work", () => {
		const target = fixture("r-");
		const anchor = NOW - 4 * DAY;
		const runId = "78787878-7878-4787-8787-787878787878";
		const incident = finalizedIncident(target, "i", anchor, { runId });
		writeProviderPinIncomplete(incident, "sysdig", runId, anchor);
		const pinDirectory = join(incident, "journal-pins", "cas");
		mkdirSync(pinDirectory, { recursive: true, mode: 0o700 });
		const digest = createHash("sha256").update("x").digest("hex");
		const pinnedPath = join(pinDirectory, `${digest}.blob`);
		writeFileSync(pinnedPath, "x", { mode: 0o600 });
		const generationId = journalArtifactGenerationId(runId, anchor);
		const sealedArtifact = sealFixtureArtifact(pinnedPath, generationId, digest);
		const occurrence = {
			occurrenceReference: {
				kind: "segment",
				locator: {
					...journalSegmentLocator(1, "b".repeat(64)),
					segmentId: "a",
					segmentSequence: 0,
				},
			},
			semanticFingerprint: "c".repeat(64),
			cursors: [],
			cas: {
				digest,
				bytes: 1,
				path: join(target.recorder, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`),
			},
			eventWallTimeMs: String(anchor),
			pinnedCasPath: pinnedPath,
			sealedArtifact,
		};
		const manifestPath = join(incident, "journal-pin-manifest.json");
		const manifestMaximumBytes = 8 * 1024 * 1024;
		const emptyManifest = JSON.stringify({
			version: 2,
			state: "complete_through_requested_window",
			runId,
			fromWallTimeMs: anchor - 30 * MINUTE,
			throughWallTimeMs: anchor + 15 * MINUTE,
			artifactGenerationId: generationId,
			occurrences: [],
		});
		const emptyOccurrences = '"occurrences":[]';
		const occurrenceOffset = emptyManifest.lastIndexOf(emptyOccurrences);
		if (occurrenceOffset < 0) throw new Error("Fixture manifest occurrences field unavailable");
		const manifestPrefix = `${emptyManifest.slice(0, occurrenceOffset)}"occurrences":[`;
		const manifestSuffix = `]${emptyManifest.slice(occurrenceOffset + emptyOccurrences.length)}`;
		const occurrenceJson = JSON.stringify(occurrence);
		const framingBytes = Buffer.byteLength(`${manifestPrefix}${manifestSuffix}\n`);
		const occurrenceBytes = Buffer.byteLength(occurrenceJson);
		const occurrenceCount = Math.min(
			8_192,
			Math.floor((manifestMaximumBytes - framingBytes + 1) / (occurrenceBytes + 1)),
		);
		const manifestBytes = `${manifestPrefix}${Array.from({ length: occurrenceCount }, () => occurrenceJson).join(",")}${
			manifestSuffix
		}\n`;
		writeFileSync(manifestPath, manifestBytes, { mode: 0o600 });
		const manifestSize = statSync(manifestPath).size;
		expect(occurrenceCount).toBeGreaterThan(0);
		expect(occurrenceCount).toBeLessThanOrEqual(8_192);
		expect(manifestSize).toBeLessThanOrEqual(manifestMaximumBytes);
		if (occurrenceCount < 8_192) expect(manifestSize).toBeGreaterThan(manifestMaximumBytes - occurrenceBytes - 1);
		const manifestStat = statSync(manifestPath);
		const pinStat = statSync(pinDirectory);
		json(join(incident, "journal-pin-retention-proof.json"), {
			version: 1,
			state: "producer_verified_complete",
			provider: "journal",
			artifactGenerationId: generationId,
			manifestValidated: true,
			occurrenceReferencesResolved: true,
			runId,
			fromWallTimeMs: anchor - 30 * 60 * 1_000,
			throughWallTimeMs: anchor + 15 * 60 * 1_000,
			retainUntilWallTimeMs: anchor + 3 * DAY,
			retentionMilliseconds: 3 * DAY,
			occurrenceCount,
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
				dev: String(pinStat.dev),
				ino: String(pinStat.ino),
				mtimeMs: pinStat.mtimeMs,
				ctimeMs: pinStat.ctimeMs,
			},
		});
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW,
			deadlineMs: Date.now() + 30_000,
			maxEntries: 64,
			maxDeletes: 16,
			machineId: "machine",
			bootId: "boot",
		});
		expect(result.scannedEntries).toBeLessThanOrEqual(64);
		expect(existsSync(incident)).toBe(false);
	});

	it("fails closed without a lifecycle lease and leaves retention state untouched", () => {
		const target = fixture("lease-required-");
		const run = runPath(target, "91919191-9191-4919-8919-919191919191");
		old(run);
		const result = runIncidentRetentionPassWithLease({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
		});
		expect(result.state).toBe("unavailable");
		expect(result.unavailableReason).toBe("writer_lifecycle_lease_required");
		expect(existsSync(run)).toBe(true);
		expect(existsSync(join(target.recorder, "lease-protocol-v1.json"))).toBe(false);
	});

	it("fails closed after the supplied lifecycle lease is released", () => {
		const target = fixture("lease-released-");
		const run = runPath(target, "92929292-9292-4929-8929-929292929292");
		old(run);
		const acquired = acquireFixtureRetentionLease(target);
		expect(acquired.state).toBe("acquired");
		if (acquired.state !== "acquired") return;
		expect(acquired.lease.release().state).toBe("released");
		const result = runIncidentRetentionPassWithLease({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
			writerLifecycleLease: acquired.lease,
		});
		expect(result.state).toBe("unavailable");
		expect(existsSync(run)).toBe(true);
	});

	it("preserves foreign successors when the leased namespace root is replaced", () => {
		const target = fixture("root-replacement-");
		const foreignAgentDir = join(target.root, "foreign-agent");
		const foreignRun = runPath(target, "93939393-9393-4939-8939-939393939393");
		const foreignRunAfterReplacement = join(foreignAgentDir, "incident-recorder", "runs", basename(foreignRun));
		old(foreignRun);
		const acquired = acquireFixtureRetentionLease(target);
		expect(acquired.state).toBe("acquired");
		if (acquired.state !== "acquired") return;
		renameSync(target.agentDir, foreignAgentDir);
		for (const path of [
			join(target.recorder, "runs"),
			join(target.recorder, "refs"),
			join(target.recorder, "cas", "sha256"),
			target.incidents,
		])
			mkdirSync(path, { recursive: true, mode: 0o700 });
		const successorRun = runPath(target, "94949494-9494-4949-8949-949494949494");
		old(successorRun);
		const result = runIncidentRetentionPassWithLease({
			agentDir: target.agentDir,
			nowMs: NOW,
			machineId: "machine",
			bootId: "boot",
			writerLifecycleLease: acquired.lease,
		});
		expect(result.state).toBe("unavailable");
		expect(existsSync(foreignRunAfterReplacement)).toBe(true);
		expect(existsSync(successorRun)).toBe(true);
		expect(acquired.lease.release().state).toBe("released");
	});

	it("refuses a recovery lease while a normal holder remains live", () => {
		const target = fixture("recovery-conflict-");
		const normal = acquireFixtureRetentionLease(target);
		expect(normal.state).toBe("acquired");
		if (normal.state !== "acquired") return;
		const recovery = acquireFixtureRecoveryLease(target);
		expect(recovery).toMatchObject({ state: "pending", reason: "normal_holders_active" });
		expect(normal.lease.release().state).toBe("released");
	});

	it("keeps a valid live observation pending without making unrelated retention uncertain", async () => {
		const target = fixture("live-observation-retention-");
		const liveRunId = "abababab-abab-4aba-8aba-abababababab";
		const liveRunToken = "bcbcbcbc-bcbc-4bcb-8bcb-bcbcbcbcbcbc";
		const triggerProducerId = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd";
		const fenceProducerId = "dededede-dede-4ede-8ede-dededededede";
		const triggerOccurrenceId = "01010101-0101-4101-8101-010101010101";
		const fenceOccurrenceId = "02020202-0202-4202-8202-020202020202";
		const makeEvent = (
			producerId: string,
			occurrenceId: string,
			type: string,
			ordinal: number,
		): IncidentRecorderRunHistoryEvent => {
			const identity = { runId: liveRunId, runToken: liveRunToken, producerId, occurrenceId };
			const identityKey = createHash("sha256")
				.update(`${liveRunId}\0${liveRunToken}\0${producerId}\0${occurrenceId}`)
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
						payloadBytes: 10,
						payloadSha256: "c".repeat(64),
					},
				},
				source: "recorder-control",
				type,
				encoding: "json",
				payloadKind: "control",
				terminal: false,
				metadata: { producerPid: 1 },
				eventWallTimeMs: String(1_700_000_000_000 + ordinal),
				eventMonotonicNs: String(ordinal),
				wrapperOrder: [String(ordinal)],
				producerOrder: [String(ordinal)],
				cursors: [`live:${ordinal}`],
				transportIdentity: {},
				cas: { digest: "c".repeat(64), bytes: 10, path: "/private/cas/c.blob" },
			};
		};
		const events = [
			makeEvent(triggerProducerId, triggerOccurrenceId, "latency_trigger", 1),
			makeEvent(fenceProducerId, fenceOccurrenceId, "live_incident_high_water_fence", 2),
		];
		const page: IncidentRecorderLiveRunEventsPage = {
			version: 1,
			runId: liveRunId,
			state: "complete",
			events,
			cursor: { version: 1, runId: liveRunId, filterSha256: "d".repeat(64), segmentSequence: 1, ordinal: 2 },
			scannedSegments: 1,
			scannedRecords: 2,
			scannedIndexBytes: 1,
		};
		const compactor = await livePublicationCompactor(target, () => page);
		const published = publishLiveIncidentObservation({
			incidentsDirectory: target.incidents,
			compactor,
			trigger: {
				runId: liveRunId,
				runToken: liveRunToken,
				producerId: triggerProducerId,
				occurrenceId: triggerOccurrenceId,
				acceptedAtWallTimeMs: 1_700_000_000_001,
				type: "latency_trigger",
			},
			fence: {
				runId: liveRunId,
				runToken: liveRunToken,
				producerId: fenceProducerId,
				occurrenceId: fenceOccurrenceId,
			},
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(published.state).toBe("published");
		if (published.state !== "published") return;
		const result = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW + 30 * DAY,
			maxEntries: 64,
			maxDeletes: 64,
		});
		expect(result.state).toBe("completed");
		expect(result.pendingIncident).toBe(true);
		expect(result.uncertainties.some((value) => value.includes(published.incidentId))).toBe(false);
		expect(existsSync(join(target.incidents, published.incidentId))).toBe(true);
	});

	it("resumes nine-page live validation through caller-owned retention state", async () => {
		const target = fixture("live-observation-retention-resume-");
		const liveRunId = "abababab-abab-4aba-8aba-abababababab";
		const liveRunToken = "bcbcbcbc-bcbc-4bcb-8bcb-bcbcbcbcbcbc";
		const triggerProducerId = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd";
		const fenceProducerId = "dededede-dede-4ede-8ede-dededededede";
		const triggerOccurrenceId = "01010101-0101-4101-8101-010101010101";
		const fenceOccurrenceId = "02020202-0202-4202-8202-020202020202";
		const makeEvent = (
			producerId: string,
			occurrenceId: string,
			type: string,
			ordinal: number,
		): IncidentRecorderRunHistoryEvent => {
			const identity = { runId: liveRunId, runToken: liveRunToken, producerId, occurrenceId };
			const identityKey = createHash("sha256")
				.update(`${liveRunId}\0${liveRunToken}\0${producerId}\0${occurrenceId}`)
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
						payloadBytes: 10,
						payloadSha256: "c".repeat(64),
					},
				},
				source: "recorder-control",
				type,
				encoding: "json",
				payloadKind: "control",
				terminal: false,
				metadata: { producerPid: 1 },
				eventWallTimeMs: String(1_700_000_000_000 + ordinal),
				eventMonotonicNs: String(ordinal),
				wrapperOrder: [String(ordinal)],
				producerOrder: [String(ordinal)],
				cursors: [`live:${ordinal}`],
				transportIdentity: {},
				cas: { digest: "c".repeat(64), bytes: 10, path: "/private/cas/c.blob" },
			};
		};
		const pages: IncidentRecorderLiveRunEventsPage[] = Array.from({ length: 9 }, (_, index) => {
			const occurrence =
				index === 0
					? makeEvent(triggerProducerId, triggerOccurrenceId, "latency_trigger", index + 1)
					: index === 8
						? makeEvent(fenceProducerId, fenceOccurrenceId, "live_incident_high_water_fence", index + 1)
						: makeEvent(
								triggerProducerId,
								`03030303-0303-4303-8303-${(index + 1).toString().padStart(12, "0")}`,
								"context",
								index + 1,
							);
			return {
				version: 1,
				runId: liveRunId,
				state: index === 8 ? "complete" : "pending",
				events: [occurrence],
				cursor: {
					version: 1,
					runId: liveRunId,
					filterSha256: "d".repeat(64),
					segmentSequence: 1,
					ordinal: index + 1,
				},
				scannedSegments: 1,
				scannedRecords: 1,
				scannedIndexBytes: 256,
			};
		});
		let pageIndex = 0;
		const compactor = await livePublicationCompactor(target, () => pages[Math.min(pageIndex++, pages.length - 1)]);
		const input = {
			incidentsDirectory: target.incidents,
			compactor,
			trigger: {
				runId: liveRunId,
				runToken: liveRunToken,
				producerId: triggerProducerId,
				occurrenceId: triggerOccurrenceId,
				acceptedAtWallTimeMs: 1_700_000_000_001,
				type: "latency_trigger",
			},
			fence: {
				runId: liveRunId,
				runToken: liveRunToken,
				producerId: fenceProducerId,
				occurrenceId: fenceOccurrenceId,
			},
			classification: { value: "latency", causeLayer: "service" },
			maxPagesPerPass: 8,
			maxValidationPagesPerPass: 8,
		};
		expect(publishLiveIncidentObservation(input).state).toBe("incomplete");
		const published = publishLiveIncidentObservation(input);
		expect(published.state).toBe("pending");
		if (published.state !== "pending") return;
		const artifactPath = join(target.incidents, published.incidentId);

		const checkpoints = new Map<string, IncidentRecorderLiveObservationValidationCheckpoint>();
		const first = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW + 30 * DAY,
			maxEntries: 64,
			maxDeletes: 64,
			liveObservationValidationCheckpoints: checkpoints,
		});
		expect(first.pendingIncident).toBe(true);
		expect(first.deletedEntries).toBe(0);
		expect(first.uncertainties.some((value) => value.includes(published.incidentId))).toBe(false);
		expect(checkpoints.size).toBe(1);
		const checkpoint = checkpoints.get(artifactPath);
		expect(checkpoint?.pageCount).toBe(8);
		if (!checkpoint) return;

		const second = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW + 30 * DAY,
			maxEntries: 64,
			maxDeletes: 64,
			liveObservationValidationCheckpoints: checkpoints,
		});
		expect(second.pendingIncident).toBe(true);
		expect(second.deletedEntries).toBe(0);
		expect(second.uncertainties.some((value) => value.includes(published.incidentId))).toBe(false);
		expect(checkpoints.size).toBe(0);
		expect(existsSync(artifactPath)).toBe(true);

		const full = new Map<string, IncidentRecorderLiveObservationValidationCheckpoint>();
		full.set("active-progress", checkpoint);
		for (let index = full.size; index < 128; index += 1) full.set(`other-progress-${index}`, checkpoint);
		const capacity = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW + 30 * DAY,
			maxEntries: 64,
			maxDeletes: 64,
			liveObservationValidationCheckpoints: full,
		});
		expect(capacity.pendingIncident).toBe(true);
		expect(capacity.deletedEntries).toBe(0);
		expect(capacity.uncertainties.some((value) => value.includes(published.incidentId))).toBe(false);
		expect(full.size).toBe(128);
		expect(full.has("active-progress")).toBe(true);
		expect(full.has(artifactPath)).toBe(false);

		const descriptorPath = join(artifactPath, "live-observation.json");
		const descriptor = JSON.parse(readFileSync(descriptorPath, "utf8")) as Record<string, unknown>;
		descriptor.classification = "tampered";
		writeFileSync(descriptorPath, `${JSON.stringify(descriptor)}\n`, { mode: 0o600 });
		const stale = new Map<string, IncidentRecorderLiveObservationValidationCheckpoint>();
		if (checkpoint) stale.set(artifactPath, checkpoint);
		const tampered = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW + 30 * DAY,
			maxEntries: 64,
			maxDeletes: 64,
			liveObservationValidationCheckpoints: stale,
		});
		expect(tampered.pendingIncident).toBe(false);
		expect(tampered.deletedEntries).toBe(0);
		expect(tampered.uncertainties.some((value) => value.includes(published.incidentId))).toBe(true);
		expect(stale.size).toBe(0);
		expect(existsSync(artifactPath)).toBe(true);

		const missing = new Map<string, IncidentRecorderLiveObservationValidationCheckpoint>();
		missing.set(artifactPath, checkpoint);
		const originalMissingGet = missing.get.bind(missing);
		missing.get = (key) => {
			if (key === artifactPath) rmSync(artifactPath, { recursive: true, force: true });
			return originalMissingGet(key);
		};
		const missingResult = runIncidentRetentionPass({
			agentDir: target.agentDir,
			nowMs: NOW + 30 * DAY,
			maxEntries: 64,
			maxDeletes: 64,
			liveObservationValidationCheckpoints: missing,
		});
		expect(missingResult.pendingIncident).toBe(false);
		expect(missingResult.deletedEntries).toBe(0);
		expect(missingResult.uncertainties.some((value) => value.includes(published.incidentId))).toBe(true);
		expect(missing.size).toBe(0);
		expect(existsSync(artifactPath)).toBe(false);
	});
});
