import { createHash } from "node:crypto";
import {
	chmodSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	renameSync,
	rmSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
	IncidentRecorderCompactor,
	IncidentRecorderLiveRunEventsPage,
	IncidentRecorderRunHistoryEvent,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import { IncidentRecorderCompactor as IncidentRecorderCompactorClass } from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	type IncidentRecorderLiveObservationValidationCheckpoint,
	type IncidentRecorderLiveOccurrenceIdentity,
	inspectLiveIncidentObservation,
	publishLiveIncidentObservation,
} from "../src/modes/daemon/incident-recorder-live-publication.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import type {
	IncidentRecorderSegmentAppendInput,
	IncidentRecorderSegmentLocator,
} from "../src/modes/daemon/incident-recorder-segment-store.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const runId = "11111111-1111-4111-8111-111111111111";
const runToken = "22222222-2222-4222-8222-222222222222";
const triggerProducerId = "33333333-3333-4333-8333-333333333333";
const fenceProducerId = "44444444-4444-4444-8444-444444444444";
const roots: string[] = [];

function occurrenceId(value: number): string {
	return `00000000-0000-4000-8000-${value.toString(16).padStart(12, "0")}`;
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

function hashPage(page: Record<string, unknown>): string {
	const { pageSha256: _pageSha256, ...body } = page;
	return createHash("sha256")
		.update(`${canonicalJson(body)}\n`)
		.digest("hex");
}

function identity(producerId: string, value: number): IncidentRecorderLiveOccurrenceIdentity {
	return { runId, runToken, producerId, occurrenceId: occurrenceId(value) };
}

function event(
	identityValue: IncidentRecorderLiveOccurrenceIdentity,
	type: string,
	segmentSequence: number,
	ordinal: number,
): IncidentRecorderRunHistoryEvent {
	const identityKey = createHash("sha256")
		.update(
			`${identityValue.runId}\0${identityValue.runToken}\0${identityValue.producerId}\0${identityValue.occurrenceId}`,
		)
		.digest("hex");
	const payloadSha256 = "a".repeat(64);
	return {
		identityKey,
		identity: identityValue,
		semanticFingerprint: "b".repeat(64),
		occurrenceReference: {
			kind: "segment",
			locator: {
				version: 1,
				segmentId: "c".repeat(64),
				segmentSequence,
				ordinal,
				offset: ordinal * 100,
				frameBytes: 100,
				payloadBytes: 10,
				payloadSha256,
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
		cursors: [`cursor:${ordinal}`],
		transportIdentity: { stream: "fixture" },
		cas: { digest: payloadSha256, bytes: 10, path: "/private/cas/aa.blob" },
	};
}

function page(
	state: "pending" | "complete" | "incomplete",
	events: IncidentRecorderRunHistoryEvent[],
	ordinal: number,
	reason?: string,
): IncidentRecorderLiveRunEventsPage {
	return {
		version: 1,
		runId,
		state,
		events,
		cursor: { version: 1, runId, filterSha256: "d".repeat(64), segmentSequence: 1, ordinal },
		...(reason ? { reason } : {}),
		scannedSegments: 1,
		scannedRecords: events.length,
		scannedIndexBytes: 256,
	};
}

function readerPage(
	state: "pending" | "complete" | "incomplete",
	events: IncidentRecorderRunHistoryEvent[],
	cursor: { segmentSequence: number; ordinal: number },
	filter = "d".repeat(64),
	reason?: string,
): IncidentRecorderLiveRunEventsPage {
	return {
		version: 1,
		runId,
		state,
		events,
		cursor: { version: 1, runId, filterSha256: filter, ...cursor },
		...(reason ? { reason } : {}),
		scannedSegments: 1,
		scannedRecords: events.length,
		scannedIndexBytes: 256,
	};
}

function fixture(pages: IncidentRecorderLiveRunEventsPage[]): {
	incidentsDirectory: string;
	compactor: IncidentRecorderCompactor;
} {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-live-publication-"));
	roots.push(root);
	const incidentsDirectory = join(root, "agent", "incidents");
	mkdirSync(incidentsDirectory, { recursive: true, mode: 0o700 });
	let index = 0;
	const compactor = {
		readLiveRunEvents: vi.fn(() => pages[Math.min(index++, pages.length - 1)] as IncidentRecorderLiveRunEventsPage),
	} as unknown as IncidentRecorderCompactor;
	return { incidentsDirectory, compactor };
}

const ACTUAL_RUN_ID = "55555555-5555-4555-8555-555555555555";
const ACTUAL_RUN_TOKEN = "66666666-6666-4666-8666-666666666666";
const ACTUAL_TRIGGER_PRODUCER_ID = "77777777-7777-4777-8777-777777777777";
const ACTUAL_FENCE_PRODUCER_ID = "88888888-8888-4888-8888-888888888888";
const actualLeases: IncidentRecorderWriterLifecycleLease[] = [];

interface ActualCompactorFixture {
	root: string;
	agentDir: string;
	incidentsDirectory: string;
	compactor: IncidentRecorderCompactorClass;
	internal: {
		appendSegmentRecord(input: IncidentRecorderSegmentAppendInput): unknown;
	};
}

function executable(root: string, name: string, source: string): string {
	const path = join(root, name);
	writeFileSync(path, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
	chmodSync(path, 0o700);
	return path;
}

async function actualCompactorFixture(): Promise<ActualCompactorFixture> {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-live-publication-actual-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const incidentsDirectory = join(agentDir, "incidents");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	mkdirSync(incidentsDirectory, { recursive: true, mode: 0o700 });
	const scanner = executable(root, "storage-scanner.cjs", 'process.stdout.write("1\\t1\\t0\\t0\\n");');
	let lease: IncidentRecorderWriterLifecycleLease | undefined;
	const contract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: "e".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: acquireIncidentRecorderNamespaceCas,
	};
	const acquireLease = (): IncidentRecorderWriterLifecycleLease => {
		if (lease) return lease;
		const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, contract);
		if (admission.state !== "acquired") throw new Error("actual fixture lifecycle lease unavailable");
		lease = admission.lease;
		actualLeases.push(lease);
		return lease;
	};
	const compactor = new IncidentRecorderCompactorClass({
		agentDir,
		storageScannerPath: scanner,
		freeReserveBytes: 0,
		writerLifecycleLease: acquireLease,
	});
	await compactor.initializeStorageAccounting(new AbortController().signal);
	return {
		root,
		agentDir,
		incidentsDirectory,
		compactor,
		internal: compactor as unknown as ActualCompactorFixture["internal"],
	};
}

function actualOccurrenceId(index: number): string {
	return `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function actualOccurrenceInput(
	index: number,
	anchor: number,
	digest: string,
	casPath: string,
	producerId = ACTUAL_TRIGGER_PRODUCER_ID,
	type = "context",
): IncidentRecorderSegmentAppendInput {
	const occurrenceId = actualOccurrenceId(index);
	const identity = { runId: ACTUAL_RUN_ID, runToken: ACTUAL_RUN_TOKEN, producerId, occurrenceId };
	const payload = {
		version: 1,
		state: "complete",
		identity,
		source: "fixture",
		type,
		encoding: "binary",
		payloadKind: "exact-bytes",
		terminal: false,
		metadata: { index },
		eventWallTimeMs: String(anchor + index),
		eventMonotonicNs: String(index),
		transportIdentity: { stream: "actual-fixture" },
		wrapperOrder: [String(index)],
		producerOrder: [String(index)],
		cursors: [`actual-cursor-${index}`],
		journalReferences: [],
		cas: {
			algorithm: "sha256",
			digest,
			bytes: 1,
			path: casPath,
			compression: "none",
			resolution: "verified",
		},
		compactionDisposition: "compacted_and_cas_resolved",
		journalCanonicalUntilCompactionCommit: true,
	};
	const identityKey = createHash("sha256")
		.update(`${ACTUAL_RUN_ID}\0${ACTUAL_RUN_TOKEN}\0${producerId}\0${occurrenceId}`)
		.digest("hex");
	return {
		idempotencyKey: `occurrence:${identityKey}`,
		runId: ACTUAL_RUN_ID,
		sourceId: "occurrence",
		observedAtMs: Number(payload.eventWallTimeMs),
		order: String(index),
		metadata: { version: 1, state: "complete", occurrenceIdentity: identityKey, casDigest: digest },
		payload: Buffer.from(`${JSON.stringify(payload)}\n`, "utf8"),
	};
}

afterEach(() => {
	for (const lease of actualLeases.splice(0).reverse()) lease.release();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("live incident publication", () => {
	it("publishes the trigger-through-physical-fence prefix and excludes later records", () => {
		const trigger = identity(triggerProducerId, 1);
		const fence = identity(fenceProducerId, 2);
		const target = fixture([
			page("pending", [event(trigger, "latency_trigger", 1, 1)], 1),
			page(
				"complete",
				[
					event(fence, "live_incident_high_water_fence", 1, 2),
					event(identity(triggerProducerId, 3), "later", 1, 3),
				],
				3,
			),
		]);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_001, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("published");
		if (result.state !== "published") return;
		expect(result.incidentId).toHaveLength(115);
		expect(result.observation.targetSnapshot.ordinal).toBe(2);
		const pageTwo = JSON.parse(
			readFileSync(join(result.artifactPath, "evidence", "page-000000000002.json"), "utf8"),
		) as {
			events: IncidentRecorderRunHistoryEvent[];
		};
		expect(pageTwo.events.map((item) => item.identity.occurrenceId)).toEqual([fence.occurrenceId]);
		expect(
			inspectLiveIncidentObservation({
				incidentsDirectory: target.incidentsDirectory,
				incidentId: result.incidentId,
			}).state,
		).toBe("published");
	});

	it("continues after a fence is not yet available and makes an exact retry a no-op", () => {
		const trigger = identity(triggerProducerId, 4);
		const fence = identity(fenceProducerId, 5);
		const target = fixture([
			page("complete", [event(trigger, "latency_trigger", 1, 4)], 4),
			page("complete", [event(fence, "live_incident_high_water_fence", 1, 5)], 5),
		]);
		const input = {
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_004, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		};
		const first = publishLiveIncidentObservation(input);
		expect(first.state).toBe("incomplete");
		const second = publishLiveIncidentObservation(input);
		expect(second.state).toBe("published");
		const retry = publishLiveIncidentObservation(input);
		expect(retry.state).toBe("published");
		if (retry.state === "published") expect(retry.noOp).toBe(true);
	});

	it("resumes a nine-page readback from a caller-owned bounded checkpoint", () => {
		const trigger = identity(triggerProducerId, 30);
		const fence = identity(fenceProducerId, 39);
		const pages = Array.from({ length: 9 }, (_, index) => {
			const occurrence = index === 0 ? trigger : index === 8 ? fence : identity(triggerProducerId, 30 + index);
			const type = index === 0 ? "latency_trigger" : index === 8 ? "live_incident_high_water_fence" : "context";
			return readerPage(index === 8 ? "complete" : "pending", [event(occurrence, type, 1, index + 1)], {
				segmentSequence: 1,
				ordinal: index + 1,
			});
		});
		const target = fixture(pages);
		const input = {
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_030, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
			maxPagesPerPass: 8,
			maxValidationPagesPerPass: 8,
		};
		const first = publishLiveIncidentObservation(input);
		expect(first.state).toBe("incomplete");
		const second = publishLiveIncidentObservation(input);
		expect(second.state).toBe("pending");
		if (second.state !== "pending" || !second.validationCheckpoint) return;
		const checkpoint: IncidentRecorderLiveObservationValidationCheckpoint = second.validationCheckpoint;
		const resumed = publishLiveIncidentObservation({ ...input, validationCheckpoint: checkpoint });
		expect(resumed.state).toBe("published");
		if (resumed.state !== "published") return;

		const firstInspection = inspectLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			incidentId: resumed.incidentId,
			maxValidationPagesPerPass: 8,
		});
		expect(firstInspection.state).toBe("pending");
		if (firstInspection.state !== "pending" || !firstInspection.validationCheckpoint) return;
		const completedInspection = inspectLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			incidentId: resumed.incidentId,
			maxValidationPagesPerPass: 8,
			validationCheckpoint: firstInspection.validationCheckpoint,
		});
		expect(completedInspection.state).toBe("published");

		const evidenceDirectory = join(resumed.artifactPath, "evidence");
		const extraPagePath = join(evidenceDirectory, "page-000000000010.json");
		writeFileSync(extraPagePath, "{}\n", { mode: 0o600 });
		const extraPageInspection = inspectLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			incidentId: resumed.incidentId,
			maxValidationPagesPerPass: 8,
			validationCheckpoint: firstInspection.validationCheckpoint,
		});
		expect(extraPageInspection.state).toBe("uncertain");
		unlinkSync(extraPagePath);

		const finalPagePath = join(evidenceDirectory, "page-000000000009.json");
		const tamperedPage = JSON.parse(readFileSync(finalPagePath, "utf8")) as Record<string, unknown>;
		tamperedPage.pageSha256 = "f".repeat(64);
		writeFileSync(finalPagePath, `${canonicalJson(tamperedPage)}\n`, { mode: 0o600 });
		const tamperedInspection = inspectLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			incidentId: resumed.incidentId,
			maxValidationPagesPerPass: 8,
			validationCheckpoint: firstInspection.validationCheckpoint,
		});
		expect(tamperedInspection.state).toBe("uncertain");
	});

	it("persists every advancing reader page, keeps pre-trigger objects, and stops at the physical fence", () => {
		const pretrigger = identity(triggerProducerId, 6);
		const trigger = identity(triggerProducerId, 7);
		const fence = identity(fenceProducerId, 8);
		const trailing = identity(triggerProducerId, 9);
		const target = fixture([
			readerPage("pending", [], { segmentSequence: 1, ordinal: 1 }),
			readerPage("pending", [event(pretrigger, "context", 1, 2), event(trigger, "latency_trigger", 1, 3)], {
				segmentSequence: 1,
				ordinal: 3,
			}),
			readerPage(
				"complete",
				[event(fence, "live_incident_high_water_fence", 1, 4), event(trailing, "after-fence", 1, 5)],
				{ segmentSequence: 1, ordinal: 5 },
			),
		]);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_007, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("published");
		if (result.state !== "published") return;
		const evidenceDirectory = join(result.artifactPath, "evidence");
		const storedPage1 = JSON.parse(readFileSync(join(evidenceDirectory, "page-000000000001.json"), "utf8"));
		const storedPage2 = JSON.parse(readFileSync(join(evidenceDirectory, "page-000000000002.json"), "utf8"));
		const storedPage3 = JSON.parse(readFileSync(join(evidenceDirectory, "page-000000000003.json"), "utf8"));
		expect(storedPage1.beforeCursor).toBeNull();
		expect(storedPage1.events).toEqual([]);
		expect(storedPage2.beforeCursor).toEqual(storedPage1.afterCursor);
		expect(storedPage2.events).toEqual([event(pretrigger, "context", 1, 2), event(trigger, "latency_trigger", 1, 3)]);
		expect(storedPage3.beforeCursor).toEqual(storedPage2.afterCursor);
		expect(storedPage3.events).toEqual([event(fence, "live_incident_high_water_fence", 1, 4)]);
		expect(
			storedPage3.events.some(
				(item: IncidentRecorderRunHistoryEvent) => item.identity.occurrenceId === trailing.occurrenceId,
			),
		).toBe(false);
		const progress = JSON.parse(readFileSync(join(result.artifactPath, "progress.json"), "utf8")) as {
			version: number;
			cursor: { ordinal: number };
			fenceProof: { locator: { ordinal: number }; filterSha256: string } | null;
		};
		expect(progress.version).toBe(2);
		expect(progress.cursor.ordinal).toBe(4);
		expect(progress.fenceProof?.locator.ordinal).toBe(4);
		expect(progress.fenceProof?.filterSha256).toBe("d".repeat(64));
	});

	it("persists one valid prefix from an incomplete unchanged-cursor response and resumes after it", () => {
		const trigger = identity(triggerProducerId, 10);
		const fence = identity(fenceProducerId, 11);
		const first = readerPage(
			"incomplete",
			[event(trigger, "latency_trigger", 1, 10)],
			{ segmentSequence: 0, ordinal: 0 },
			"d".repeat(64),
			"reader_timeout",
		);
		const second = readerPage("complete", [event(fence, "live_incident_high_water_fence", 1, 11)], {
			segmentSequence: 1,
			ordinal: 11,
		});
		const read = vi.fn(({ cursor }: { cursor?: unknown }) => (cursor ? second : first));
		const target = fixture([]);
		(target.compactor as unknown as { readLiveRunEvents: typeof read }).readLiveRunEvents = read;
		const input = {
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_010, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		};
		const firstResult = publishLiveIncidentObservation(input);
		expect(firstResult.state).toBe("incomplete");
		if (firstResult.state !== "incomplete") return;
		expect(firstResult.progress.pageCount).toBe(1);
		expect(firstResult.progress.cursor?.ordinal).toBe(10);
		const secondResult = publishLiveIncidentObservation(input);
		expect(secondResult.state).toBe("published");
		expect(read).toHaveBeenCalledTimes(2);
		expect(read.mock.calls[1]?.[0].cursor).toMatchObject({ segmentSequence: 1, ordinal: 10 });
		if (secondResult.state !== "published") return;
		const page1 = JSON.parse(
			readFileSync(join(secondResult.artifactPath, "evidence", "page-000000000001.json"), "utf8"),
		);
		const page2 = JSON.parse(
			readFileSync(join(secondResult.artifactPath, "evidence", "page-000000000002.json"), "utf8"),
		);
		expect(page1.events).toEqual([event(trigger, "latency_trigger", 1, 10)]);
		expect(page2.events).toEqual([event(fence, "live_incident_high_water_fence", 1, 11)]);
	});

	it("publishes a valid trigger-through-fence prefix from an incomplete unchanged-cursor response", () => {
		const trigger = identity(triggerProducerId, 18);
		const fence = identity(fenceProducerId, 19);
		const target = fixture([
			readerPage(
				"incomplete",
				[event(trigger, "latency_trigger", 1, 1), event(fence, "live_incident_high_water_fence", 1, 2)],
				{ segmentSequence: 0, ordinal: 0 },
				"d".repeat(64),
				"malformed_trailing_record",
			),
		]);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_018, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("published");
		if (result.state !== "published") return;
		const progress = JSON.parse(readFileSync(join(result.artifactPath, "progress.json"), "utf8"));
		expect(progress.cursor).toMatchObject({ segmentSequence: 1, ordinal: 2 });
	});

	it("bounds multibyte reader failures by UTF-8 bytes and resumes on retry", () => {
		const trigger = identity(triggerProducerId, 20);
		const fence = identity(fenceProducerId, 21);
		const valid = readerPage(
			"complete",
			[event(trigger, "latency_trigger", 1, 20), event(fence, "live_incident_high_water_fence", 1, 21)],
			{ segmentSequence: 1, ordinal: 21 },
		);
		const read = vi
			.fn()
			.mockImplementationOnce(() => {
				throw new Error("💥".repeat(2_000));
			})
			.mockReturnValue(valid);
		const target = fixture([]);
		(target.compactor as unknown as { readLiveRunEvents: typeof read }).readLiveRunEvents = read;
		const input = {
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_020, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		};
		const first = publishLiveIncidentObservation(input);
		expect(first.state).toBe("incomplete");
		if (first.state !== "incomplete") return;
		expect(Buffer.byteLength(first.reason, "utf8")).toBeLessThanOrEqual(4 * 1024);
		expect(publishLiveIncidentObservation(input).state).toBe("published");
	});

	it("rejects published progress whose cursor is not the last durable page cursor", () => {
		const trigger = identity(triggerProducerId, 22);
		const fence = identity(fenceProducerId, 23);
		const target = fixture([
			readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 22), event(fence, "live_incident_high_water_fence", 1, 23)],
				{ segmentSequence: 1, ordinal: 23 },
			),
		]);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_022, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("published");
		if (result.state !== "published") return;
		const progressPath = join(result.artifactPath, "progress.json");
		const progress = JSON.parse(readFileSync(progressPath, "utf8"));
		progress.cursor = null;
		writeFileSync(progressPath, `${canonicalJson(progress)}\n`, { mode: 0o600 });
		expect(
			inspectLiveIncidentObservation({
				incidentsDirectory: target.incidentsDirectory,
				incidentId: result.incidentId,
			}).state,
		).toBe("uncertain");
	});

	it("rejects rehashed cross-page cursor discontinuity", () => {
		const trigger = identity(triggerProducerId, 24);
		const fence = identity(fenceProducerId, 25);
		const target = fixture([
			readerPage("pending", [event(trigger, "latency_trigger", 1, 24)], { segmentSequence: 1, ordinal: 24 }),
			readerPage("complete", [event(fence, "live_incident_high_water_fence", 1, 25)], {
				segmentSequence: 1,
				ordinal: 25,
			}),
		]);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_024, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("published");
		if (result.state !== "published") return;
		const pagePath = join(result.artifactPath, "evidence", "page-000000000002.json");
		const pageValue = JSON.parse(readFileSync(pagePath, "utf8")) as Record<string, unknown>;
		pageValue.beforeCursor = { ...(pageValue.beforeCursor as Record<string, unknown>), ordinal: 23 };
		pageValue.pageSha256 = hashPage(pageValue);
		writeFileSync(pagePath, `${canonicalJson(pageValue)}\n`, { mode: 0o600 });
		const progressPath = join(result.artifactPath, "progress.json");
		const progress = JSON.parse(readFileSync(progressPath, "utf8"));
		progress.chainHeadSha256 = pageValue.pageSha256;
		progress.validatedChainHeadSha256 = pageValue.pageSha256;
		progress.bytes =
			Buffer.byteLength(readFileSync(join(result.artifactPath, "evidence", "page-000000000001.json"))) +
			Buffer.byteLength(readFileSync(pagePath));
		writeFileSync(progressPath, `${canonicalJson(progress)}\n`, { mode: 0o600 });
		const observationPath = join(result.artifactPath, "live-observation.json");
		const observation = JSON.parse(readFileSync(observationPath, "utf8"));
		observation.coverage.chainHeadSha256 = pageValue.pageSha256;
		writeFileSync(observationPath, `${canonicalJson(observation)}\n`, { mode: 0o600 });
		expect(
			inspectLiveIncidentObservation({
				incidentsDirectory: target.incidentsDirectory,
				incidentId: result.incidentId,
			}).state,
		).toBe("uncertain");
	});

	it("rejects a rehashed event whose run token does not bind to the publication", () => {
		const trigger = identity(triggerProducerId, 26);
		const fence = identity(fenceProducerId, 27);
		const target = fixture([
			readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 26), event(fence, "live_incident_high_water_fence", 1, 27)],
				{ segmentSequence: 1, ordinal: 27 },
			),
		]);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_026, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("published");
		if (result.state !== "published") return;
		const pagePath = join(result.artifactPath, "evidence", "page-000000000001.json");
		const pageValue = JSON.parse(readFileSync(pagePath, "utf8")) as Record<string, unknown>;
		const events = pageValue.events as IncidentRecorderRunHistoryEvent[];
		const alteredRunToken = "99999999-9999-4999-8999-999999999999";
		events[0] = {
			...events[0],
			identity: { ...events[0]?.identity, runToken: alteredRunToken },
			identityKey: createHash("sha256")
				.update(`${runId}\0${alteredRunToken}\0${triggerProducerId}\0${trigger.occurrenceId}`)
				.digest("hex"),
		};
		pageValue.pageSha256 = hashPage(pageValue);
		writeFileSync(pagePath, `${canonicalJson(pageValue)}\n`, { mode: 0o600 });
		const progressPath = join(result.artifactPath, "progress.json");
		const progress = JSON.parse(readFileSync(progressPath, "utf8"));
		progress.chainHeadSha256 = pageValue.pageSha256;
		progress.validatedChainHeadSha256 = pageValue.pageSha256;
		progress.bytes = Buffer.byteLength(readFileSync(pagePath));
		writeFileSync(progressPath, `${canonicalJson(progress)}\n`, { mode: 0o600 });
		const observationPath = join(result.artifactPath, "live-observation.json");
		const observation = JSON.parse(readFileSync(observationPath, "utf8"));
		observation.coverage.chainHeadSha256 = pageValue.pageSha256;
		writeFileSync(observationPath, `${canonicalJson(observation)}\n`, { mode: 0o600 });
		expect(
			inspectLiveIncidentObservation({
				incidentsDirectory: target.incidentsDirectory,
				incidentId: result.incidentId,
			}).state,
		).toBe("uncertain");
	});

	it("uses durable fence proof after restart even when the reader is unavailable", () => {
		const trigger = identity(triggerProducerId, 12);
		const fence = identity(fenceProducerId, 13);
		const target = fixture([
			readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 12), event(fence, "live_incident_high_water_fence", 1, 13)],
				{ segmentSequence: 1, ordinal: 13 },
			),
		]);
		const input = {
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_012, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		};
		const initial = publishLiveIncidentObservation(input);
		expect(initial.state).toBe("published");
		if (initial.state !== "published") return;
		const stagePath = join(target.incidentsDirectory, `.${initial.incidentId}.partial-${initial.publicationId}`);
		unlinkSync(join(initial.artifactPath, "live-observation.json"));
		renameSync(initial.artifactPath, stagePath);
		const unavailable = vi.fn(() => {
			throw new Error("reader unavailable after restart");
		});
		const restartedInput = {
			...input,
			compactor: { readLiveRunEvents: unavailable } as unknown as IncidentRecorderCompactor,
		};
		const resumed = publishLiveIncidentObservation(restartedInput);
		expect(resumed.state).toBe("published");
		expect(unavailable).not.toHaveBeenCalled();
		const retry = publishLiveIncidentObservation(restartedInput);
		expect(retry.state).toBe("published");
		expect(unavailable).not.toHaveBeenCalled();
		if (retry.state === "published") expect(retry.noOp).toBe(true);
	});

	it("keeps distinct artifacts for distinct trigger identities in one run", () => {
		const firstTrigger = identity(triggerProducerId, 14);
		const firstFence = identity(fenceProducerId, 15);
		const firstTarget = fixture([
			readerPage(
				"complete",
				[event(firstTrigger, "latency_trigger", 1, 14), event(firstFence, "live_incident_high_water_fence", 1, 15)],
				{
					segmentSequence: 1,
					ordinal: 15,
				},
			),
		]);
		const secondTrigger = identity(triggerProducerId, 16);
		const secondFence = identity(fenceProducerId, 17);
		const secondTarget = fixture([
			readerPage(
				"complete",
				[
					event(secondTrigger, "latency_trigger", 1, 16),
					event(secondFence, "live_incident_high_water_fence", 1, 17),
				],
				{
					segmentSequence: 1,
					ordinal: 17,
				},
			),
		]);
		const publish = (
			target: ReturnType<typeof fixture>,
			trigger: IncidentRecorderLiveOccurrenceIdentity,
			fence: IncidentRecorderLiveOccurrenceIdentity,
		) =>
			publishLiveIncidentObservation({
				incidentsDirectory: target.incidentsDirectory,
				compactor: target.compactor,
				trigger: {
					...trigger,
					acceptedAtWallTimeMs: 1_700_000_000_000 + Number.parseInt(trigger.occurrenceId.slice(-2), 16),
					type: "latency_trigger",
				},
				fence,
				classification: { value: "latency", causeLayer: "service" },
			});
		const first = publish(firstTarget, firstTrigger, firstFence);
		const second = publish(secondTarget, secondTrigger, secondFence);
		expect(first.state).toBe("published");
		expect(second.state).toBe("published");
		if (first.state !== "published" || second.state !== "published") return;
		expect(first.incidentId).not.toBe(second.incidentId);
		expect(first.artifactPath).not.toBe(second.artifactPath);
	});

	it("uses the actual compactor 64/2 page split and deep-preserves the 65-event physical prefix", async () => {
		const target = await actualCompactorFixture();
		const anchor = 1_700_100_000_000;
		const casValue = Buffer.from("actual-live-publication-cas");
		const digest = createHash("sha256").update(casValue).digest("hex");
		const casDirectory = join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2));
		const casPath = join(casDirectory, `${digest}.blob`);
		mkdirSync(casDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(casPath, casValue, { mode: 0o600 });
		for (let index = 1; index <= 66; index += 1) {
			const producerId = index === 65 ? ACTUAL_FENCE_PRODUCER_ID : ACTUAL_TRIGGER_PRODUCER_ID;
			const type = index === 64 ? "latency_trigger" : index === 65 ? "live_incident_high_water_fence" : "context";
			target.internal.appendSegmentRecord(actualOccurrenceInput(index, anchor, digest, casPath, producerId, type));
		}
		const first = target.compactor.readLiveRunEvents({ runId: ACTUAL_RUN_ID });
		const second = target.compactor.readLiveRunEvents({ runId: ACTUAL_RUN_ID, cursor: first.cursor });
		expect(first.events).toHaveLength(64);
		expect(second.events).toHaveLength(2);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: {
				runId: ACTUAL_RUN_ID,
				runToken: ACTUAL_RUN_TOKEN,
				producerId: ACTUAL_TRIGGER_PRODUCER_ID,
				occurrenceId: actualOccurrenceId(64),
				acceptedAtWallTimeMs: anchor + 64,
				type: "latency_trigger",
			},
			fence: {
				runId: ACTUAL_RUN_ID,
				runToken: ACTUAL_RUN_TOKEN,
				producerId: ACTUAL_FENCE_PRODUCER_ID,
				occurrenceId: actualOccurrenceId(65),
			},
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("published");
		if (result.state !== "published") return;
		const stored: IncidentRecorderRunHistoryEvent[] = [];
		for (let sequence = 1; sequence <= 2; sequence += 1) {
			const value = JSON.parse(
				readFileSync(
					join(result.artifactPath, "evidence", `page-${sequence.toString().padStart(12, "0")}.json`),
					"utf8",
				),
			) as { events: IncidentRecorderRunHistoryEvent[] };
			stored.push(...value.events);
		}
		expect(stored).toEqual([...first.events, second.events[0]]);
		expect(stored).toHaveLength(65);
		expect(stored.at(-1)?.identity.occurrenceId).toBe(actualOccurrenceId(65));
		expect(stored.some((item) => item.identity.occurrenceId === actualOccurrenceId(66))).toBe(false);
		expect(
			(stored.at(-1)?.occurrenceReference as { kind: "segment"; locator: IncidentRecorderSegmentLocator }).locator,
		).toEqual(
			(second.events[0]?.occurrenceReference as { kind: "segment"; locator: IncidentRecorderSegmentLocator })
				.locator,
		);
		expect(stored.at(-1)?.cas).toEqual(second.events[0]?.cas);
	});

	it("publishes the actual compactor prefix when a malformed record follows the physical fence", async () => {
		const target = await actualCompactorFixture();
		const anchor = 1_700_200_000_000;
		const casValue = Buffer.from("actual-malformed-prefix-cas");
		const digest = createHash("sha256").update(casValue).digest("hex");
		const casDirectory = join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2));
		const casPath = join(casDirectory, `${digest}.blob`);
		mkdirSync(casDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(casPath, casValue, { mode: 0o600 });
		target.internal.appendSegmentRecord(
			actualOccurrenceInput(1, anchor, digest, casPath, ACTUAL_TRIGGER_PRODUCER_ID, "latency_trigger"),
		);
		target.internal.appendSegmentRecord(
			actualOccurrenceInput(2, anchor, digest, casPath, ACTUAL_FENCE_PRODUCER_ID, "live_incident_high_water_fence"),
		);
		const malformed = actualOccurrenceInput(3, anchor, digest, casPath);
		target.internal.appendSegmentRecord({ ...malformed, payload: Buffer.from("{malformed\n", "utf8") });
		const readerResult = target.compactor.readLiveRunEvents({ runId: ACTUAL_RUN_ID });
		expect(readerResult.state).toBe("incomplete");
		expect(readerResult.events).toHaveLength(2);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: {
				runId: ACTUAL_RUN_ID,
				runToken: ACTUAL_RUN_TOKEN,
				producerId: ACTUAL_TRIGGER_PRODUCER_ID,
				occurrenceId: actualOccurrenceId(1),
				acceptedAtWallTimeMs: anchor + 1,
				type: "latency_trigger",
			},
			fence: {
				runId: ACTUAL_RUN_ID,
				runToken: ACTUAL_RUN_TOKEN,
				producerId: ACTUAL_FENCE_PRODUCER_ID,
				occurrenceId: actualOccurrenceId(2),
			},
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("published");
	});
});
