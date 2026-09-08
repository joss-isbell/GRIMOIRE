import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	statfsSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
	IncidentCasRelativePath,
	IncidentCasRootMutation,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";
import type {
	IncidentRecorderLiveRunEventsPage,
	IncidentRecorderRunHistoryEvent,
	IncidentRecorderStorageAccountingEffect,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	IncidentRecorderCompactor as IncidentRecorderCompactorClass,
	IncidentRecorderSegmentOwnershipUncertainError,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	type IncidentRecorderLiveIncidentPublicationInput,
	type IncidentRecorderLiveObservationValidationCheckpoint,
	type IncidentRecorderLiveOccurrenceIdentity,
	inspectLiveIncidentObservation,
	liveIncidentPublicationIdentity,
	publishLiveIncidentObservationWithinRoot,
} from "../src/modes/daemon/incident-recorder-live-publication.js";
import {
	acquireIncidentRecorderNamespaceCas,
	type IncidentRecorderNamespaceRoots,
} from "../src/modes/daemon/incident-recorder-namespace-admission.js";
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

const ACTUAL_RUN_ID = "55555555-5555-4555-8555-555555555555";
const ACTUAL_RUN_TOKEN = "66666666-6666-4666-8666-666666666666";
const ACTUAL_TRIGGER_PRODUCER_ID = "77777777-7777-4777-8777-777777777777";
const ACTUAL_FENCE_PRODUCER_ID = "88888888-8888-4888-8888-888888888888";
const actualLeases: IncidentRecorderWriterLifecycleLease[] = [];

interface ActualCompactorFixture {
	root: string;
	agentDir: string;
	incidentsDirectory: string;
	baselineStorage: RealStorageSnapshot;
	lease: IncidentRecorderWriterLifecycleLease;
	compactor: IncidentRecorderCompactorClass;
	internal: {
		appendSegmentRecord(input: IncidentRecorderSegmentAppendInput): unknown;
		readLiveRunEventsWithinRoot(
			input: { runId: string; cursor?: unknown },
			root: unknown,
			store: unknown,
		): IncidentRecorderLiveRunEventsPage;
		storageBytes: number;
		storageEntries: number;
		storageInodes: Map<string, number>;
		storageReservedBytes: number;
		storageReservedEntries: number;
		storageReservedInodes: number;
		incidentLivePublicationRootStorageReservation?: {
			bytes: number;
			entries: number;
			inodes: number;
			released: boolean;
		};
		segmentOwnershipUncertainError?: unknown;
		applyStorageAccountingEffects(effects: readonly IncidentRecorderStorageAccountingEffect[]): number;
	};
}

interface RealStorageSnapshot {
	bytes: number;
	entries: number;
	inodes: number;
}

interface ActualCompactorFixtureOptions {
	storageHighWaterBytes?: number | ((baseline: RealStorageSnapshot, blockSize: number) => number);
	storageHighWaterEntries?: number;
	storageHighWaterInodes?: number;
	storageByteCeiling?: number;
	namespaceRootDecorator?: (roots: IncidentRecorderNamespaceRoots) => IncidentRecorderNamespaceRoots;
}

function realStorageSnapshot(recorderDirectory: string, incidentsDirectory: string): RealStorageSnapshot {
	const scan = spawnSync("find", [recorderDirectory, incidentsDirectory, "-xdev", "-printf", "%D\t%i\t%s\t%b\n"], {
		encoding: "utf8",
	});
	if (scan.error) throw scan.error;
	if (scan.status !== 0) throw new Error(`real storage scan exited with ${scan.status ?? "unknown"}`);
	const output = String(scan.stdout ?? "");
	const inodes = new Set<string>();
	let bytes = 0;
	let entries = 0;
	for (const line of output.split("\n")) {
		if (line.length === 0) continue;
		const match = /^(\d+)\t(\d+)\t(\d+)\t(\d+)$/.exec(line);
		if (!match) throw new Error(`real storage scan emitted malformed record: ${line}`);
		entries += 1;
		const identity = `${match[1]}:${match[2]}`;
		if (inodes.has(identity)) continue;
		inodes.add(identity);
		const apparent = Number(match[3]);
		const allocated = Number(match[4]) * 512;
		const contribution = Math.max(apparent, allocated);
		if (!Number.isSafeInteger(contribution) || contribution < 0)
			throw new Error("real storage scan emitted an unsafe byte contribution");
		bytes += contribution;
		if (!Number.isSafeInteger(bytes)) throw new Error("real storage scan exceeded the safe byte range");
	}
	return { bytes, entries, inodes: inodes.size };
}

async function actualCompactorFixture(options: ActualCompactorFixtureOptions = {}): Promise<ActualCompactorFixture> {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-live-publication-actual-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	const incidentsDirectory = join(agentDir, "incidents");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	mkdirSync(incidentsDirectory, { recursive: true, mode: 0o700 });
	const recorderDirectory = join(agentDir, "incident-recorder");
	mkdirSync(recorderDirectory, { recursive: true, mode: 0o700 });
	const baselineStorage = realStorageSnapshot(recorderDirectory, incidentsDirectory);
	const blockSize = Math.max(4096, Number(statfsSync(recorderDirectory).bsize));
	const { storageHighWaterBytes, namespaceRootDecorator, ...storageOptions } = options;
	const resolvedStorageHighWaterBytes =
		typeof storageHighWaterBytes === "function"
			? storageHighWaterBytes(baselineStorage, blockSize)
			: storageHighWaterBytes;
	let lease: IncidentRecorderWriterLifecycleLease | undefined;
	const contract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: "e".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: (proof, target) => {
			const admission = acquireIncidentRecorderNamespaceCas(proof, target);
			if (admission.state !== "acquired" || namespaceRootDecorator === undefined || target !== "namespace")
				return admission;
			const transaction = admission.transaction;
			return {
				state: "acquired",
				transaction: Object.freeze({
					withRoot: transaction.withRoot.bind(transaction),
					withNamespace: <T>(operation: (roots: IncidentRecorderNamespaceRoots) => T) =>
						transaction.withNamespace((roots) => operation(namespaceRootDecorator(roots))),
					release: transaction.release.bind(transaction),
				}),
			};
		},
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
		freeReserveBytes: 0,
		...storageOptions,
		...(resolvedStorageHighWaterBytes === undefined ? {} : { storageHighWaterBytes: resolvedStorageHighWaterBytes }),
		writerLifecycleLease: acquireLease,
	});
	await compactor.initializeStorageAccounting(new AbortController().signal);
	const lifecycleLease = acquireLease();
	return {
		root,
		agentDir,
		incidentsDirectory,
		baselineStorage,
		lease: lifecycleLease,
		compactor,
		internal: compactor as unknown as ActualCompactorFixture["internal"],
	};
}

async function reopenActualCompactorFixture(target: ActualCompactorFixture): Promise<ActualCompactorFixture> {
	await target.compactor.closeWriterResourcesForLifecycle(30_000);
	if (target.lease.release().state !== "released") throw new Error("fixture lifecycle lease did not release");
	const contract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: "e".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: (proof, targetName) => acquireIncidentRecorderNamespaceCas(proof, targetName),
	};
	const admission = acquireIncidentRecorderWriterNormalLease({ agentDir: target.agentDir }, contract);
	if (admission.state !== "acquired") throw new Error("reopened fixture lifecycle lease unavailable");
	const lease = admission.lease;
	actualLeases.push(lease);
	const compactor = new IncidentRecorderCompactorClass({
		agentDir: target.agentDir,
		freeReserveBytes: 0,
		writerLifecycleLease: () => lease,
	});
	await compactor.initializeStorageAccounting(new AbortController().signal);
	return {
		...target,
		lease,
		compactor,
		internal: compactor as unknown as ActualCompactorFixture["internal"],
	};
}

async function fixture(
	pages: IncidentRecorderLiveRunEventsPage[],
	options: Parameters<typeof actualCompactorFixture>[0] = {},
): Promise<ActualCompactorFixture> {
	const target = await actualCompactorFixture(options);
	let index = 0;
	target.internal.readLiveRunEventsWithinRoot = vi.fn(
		() => pages[Math.min(index++, Math.max(0, pages.length - 1))] as IncidentRecorderLiveRunEventsPage,
	) as unknown as ActualCompactorFixture["internal"]["readLiveRunEventsWithinRoot"];
	return target;
}

function publishLiveIncidentObservation(input: IncidentRecorderLiveIncidentPublicationInput) {
	const { compactor, ...request } = input;
	return compactor.publishLiveIncidentObservation(request);
}

function publishWithinNamespaceWithPages(
	target: ActualCompactorFixture,
	publication: Omit<IncidentRecorderLiveIncidentPublicationInput, "compactor">,
	pages: IncidentRecorderLiveRunEventsPage[],
) {
	let index = 0;
	const mutation = target.lease.withNamespace((namespaceRoots) => {
		const effects: IncidentRecorderStorageAccountingEffect[] = [];
		return publishLiveIncidentObservationWithinRoot({
			...publication,
			incidents: namespaceRoots.incidents,
			readLiveRunEvents: () =>
				pages[Math.min(index++, Math.max(0, pages.length - 1))] as IncidentRecorderLiveRunEventsPage,
			storage: { reserve: () => {}, effects },
		});
	});
	if (mutation.state !== "committed") throw new Error(`namespace mutation failed: ${mutation.reason}`);
	return mutation.value;
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

function seedActualControlPair(target: ActualCompactorFixture, anchor: number): void {
	const casValue = Buffer.from(`actual-live-publication-cas-${anchor}`);
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
}

afterEach(() => {
	for (const lease of actualLeases.splice(0).reverse()) lease.release();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("live incident publication", () => {
	it("publishes the trigger-through-physical-fence prefix and excludes later records", async () => {
		const trigger = identity(triggerProducerId, 1);
		const fence = identity(fenceProducerId, 2);
		const target = await fixture([
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

	it("continues after a fence is not yet available and makes an exact retry a no-op", async () => {
		const trigger = identity(triggerProducerId, 4);
		const fence = identity(fenceProducerId, 5);
		const target = await fixture([
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
		expect(second).toEqual(expect.objectContaining({ state: "published" }));
		const retry = publishLiveIncidentObservation(input);
		expect(retry.state).toBe("published");
		if (retry.state === "published") expect(retry.noOp).toBe(true);
	});

	it("resumes a nine-page readback from a caller-owned bounded checkpoint", async () => {
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
		const target = await fixture(pages);
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

	it("persists every advancing reader page, keeps pre-trigger objects, and stops at the physical fence", async () => {
		const pretrigger = identity(triggerProducerId, 6);
		const trigger = identity(triggerProducerId, 7);
		const fence = identity(fenceProducerId, 8);
		const trailing = identity(triggerProducerId, 9);
		const target = await fixture([
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

	it("persists one valid prefix from an incomplete unchanged-cursor response and resumes after it", async () => {
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
		const target = await fixture([]);
		target.internal.readLiveRunEventsWithinRoot =
			read as unknown as ActualCompactorFixture["internal"]["readLiveRunEventsWithinRoot"];
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

	it("publishes a valid trigger-through-fence prefix from an incomplete unchanged-cursor response", async () => {
		const trigger = identity(triggerProducerId, 18);
		const fence = identity(fenceProducerId, 19);
		const target = await fixture([
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

	it("bounds multibyte reader failures by UTF-8 bytes and resumes on retry", async () => {
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
		const target = await fixture([]);
		target.internal.readLiveRunEventsWithinRoot =
			read as unknown as ActualCompactorFixture["internal"]["readLiveRunEventsWithinRoot"];
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

	it("rejects published progress whose cursor is not the last durable page cursor", async () => {
		const trigger = identity(triggerProducerId, 22);
		const fence = identity(fenceProducerId, 23);
		const target = await fixture([
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

	it("rejects rehashed cross-page cursor discontinuity", async () => {
		const trigger = identity(triggerProducerId, 24);
		const fence = identity(fenceProducerId, 25);
		const target = await fixture([
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

	it("rejects a rehashed event whose run token does not bind to the publication", async () => {
		const trigger = identity(triggerProducerId, 26);
		const fence = identity(fenceProducerId, 27);
		const target = await fixture([
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

	it("uses durable fence proof after restart even when the reader is unavailable", async () => {
		const trigger = identity(triggerProducerId, 12);
		const fence = identity(fenceProducerId, 13);
		const target = await fixture([
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
		target.internal.readLiveRunEventsWithinRoot =
			unavailable as unknown as ActualCompactorFixture["internal"]["readLiveRunEventsWithinRoot"];
		const restartedInput = { ...input };
		const resumed = publishLiveIncidentObservation(restartedInput);
		expect(resumed.state).toBe("published");
		expect(unavailable).not.toHaveBeenCalled();
		const retry = publishLiveIncidentObservation(restartedInput);
		expect(retry.state).toBe("published");
		expect(unavailable).not.toHaveBeenCalled();
		if (retry.state === "published") expect(retry.noOp).toBe(true);
	});

	it("keeps distinct artifacts for distinct trigger identities in one run", async () => {
		const firstTrigger = identity(triggerProducerId, 14);
		const firstFence = identity(fenceProducerId, 15);
		const firstTarget = await fixture([
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
		const secondTarget = await fixture([
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
			target: ActualCompactorFixture,
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
		expect(second).toEqual(expect.objectContaining({ state: "published" }));
		if (first.state !== "published" || second.state !== "published") return;
		expect(first.incidentId).not.toBe(second.incidentId);
		expect(first.artifactPath).not.toBe(second.artifactPath);
	});

	it("does not create successor files after the namespace lease is revoked", async () => {
		const trigger = identity(triggerProducerId, 40);
		const fence = identity(fenceProducerId, 41);
		const target = await fixture([
			readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 40), event(fence, "live_incident_high_water_fence", 1, 41)],
				{ segmentSequence: 1, ordinal: 41 },
			),
		]);
		expect(target.lease.release().state).toBe("released");
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_040, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("uncertain");
		expect(existsSync(join(target.incidentsDirectory, result.incidentId))).toBe(false);
		expect(existsSync(join(target.incidentsDirectory, `.${result.incidentId}.partial-${result.publicationId}`))).toBe(
			false,
		);
		expect(target.internal.storageReservedBytes).toBe(0);
		expect(target.internal.storageReservedEntries).toBe(0);
		expect(target.internal.storageReservedInodes).toBe(0);
		expect(target.compactor.storageAccountingReady).toBe(false);
		expect(target.compactor.storageMode).toBe("recovery-only");
	});

	it("does not write through a detached namespace or into its successor directory", async () => {
		const trigger = identity(triggerProducerId, 42);
		const fence = identity(fenceProducerId, 43);
		const target = await fixture([
			readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 42), event(fence, "live_incident_high_water_fence", 1, 43)],
				{ segmentSequence: 1, ordinal: 43 },
			),
		]);
		const successorAgentDir = join(target.root, "successor-agent");
		renameSync(target.agentDir, successorAgentDir);
		mkdirSync(target.agentDir, { recursive: true, mode: 0o700 });
		const replacementIncidentsDirectory = join(target.agentDir, "incidents");
		mkdirSync(replacementIncidentsDirectory, { recursive: true, mode: 0o700 });
		const successorSentinel = join(replacementIncidentsDirectory, "successor-sentinel");
		writeFileSync(successorSentinel, "successor-safe\n", { mode: 0o600 });
		const result = publishLiveIncidentObservation({
			incidentsDirectory: replacementIncidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_042, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("uncertain");
		expect(existsSync(join(successorAgentDir, "incidents", result.incidentId))).toBe(false);
		expect(readFileSync(successorSentinel, "utf8")).toBe("successor-safe\n");
		expect(existsSync(join(replacementIncidentsDirectory, result.incidentId))).toBe(false);
		expect(
			existsSync(join(successorAgentDir, "incidents", `.${result.incidentId}.partial-${result.publicationId}`)),
		).toBe(false);
		expect(target.internal.storageReservedBytes).toBe(0);
		expect(target.internal.storageReservedEntries).toBe(0);
		expect(target.internal.storageReservedInodes).toBe(0);
		expect(target.compactor.storageAccountingReady).toBe(false);
		expect(target.compactor.storageMode).toBe("recovery-only");
	});

	it("stops before the next write when the namespace detaches during a bounded read", async () => {
		const trigger = identity(triggerProducerId, 46);
		const fence = identity(fenceProducerId, 47);
		const target = await fixture([
			readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 46), event(fence, "live_incident_high_water_fence", 1, 47)],
				{ segmentSequence: 1, ordinal: 47 },
			),
		]);
		const successorAgentDir = join(target.root, "mid-callback-successor-agent");
		const replacementIncidentsDirectory = target.incidentsDirectory;
		const successorSentinel = join(replacementIncidentsDirectory, "successor-sentinel");
		let successorEntriesAtDetach: string[] | undefined;
		target.internal.readLiveRunEventsWithinRoot = vi.fn(() => {
			renameSync(target.agentDir, successorAgentDir);
			mkdirSync(target.agentDir, { recursive: true, mode: 0o700 });
			mkdirSync(replacementIncidentsDirectory, { recursive: true, mode: 0o700 });
			writeFileSync(successorSentinel, "successor-safe\n", { mode: 0o600 });
			successorEntriesAtDetach = readdirSync(join(successorAgentDir, "incidents")).sort();
			return readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 46), event(fence, "live_incident_high_water_fence", 1, 47)],
				{ segmentSequence: 1, ordinal: 47 },
			);
		}) as unknown as ActualCompactorFixture["internal"]["readLiveRunEventsWithinRoot"];
		const result = publishLiveIncidentObservation({
			incidentsDirectory: replacementIncidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_046, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("uncertain");
		expect(successorEntriesAtDetach).toBeDefined();
		expect(readdirSync(join(successorAgentDir, "incidents")).sort()).toEqual(successorEntriesAtDetach);
		expect(readFileSync(successorSentinel, "utf8")).toBe("successor-safe\n");
		expect(existsSync(join(replacementIncidentsDirectory, result.incidentId))).toBe(false);
		expect(target.internal.storageReservedBytes).toBe(0);
		expect(target.internal.storageReservedEntries).toBe(0);
		expect(target.internal.storageReservedInodes).toBe(0);
		expect(target.compactor.storageAccountingReady).toBe(false);
		expect(target.compactor.storageMode).toBe("recovery-only");
	});

	it.each([0, 7])("repairs an actual-root partial page temporary with a %i-byte prefix", async (prefixLength) => {
		let failOnce = true;
		let expectedPage: Buffer | undefined;
		const target = await actualCompactorFixture({
			namespaceRootDecorator: (namespaceRoots) => {
				const decoratedIncidents = {
					...namespaceRoots.incidents,
					writeFileExclusive: (path: IncidentCasRelativePath, value: string | Uint8Array, mode?: number): void => {
						namespaceRoots.incidents.writeFileExclusive(path, value, mode);
						const publicPath = namespaceRoots.incidents.publicPath(path);
						if (failOnce && publicPath.endsWith(".live-observation-page.tmp-page-000000000001.json")) {
							failOnce = false;
							expectedPage = Buffer.from(value);
							namespaceRoots.incidents.withFile(path, { access: "read_write" }, (file) => {
								file.truncate(prefixLength);
								file.sync();
							});
							throw new Error("injected partial page write");
						}
					},
				} as IncidentCasRootMutation;
				return { recorder: namespaceRoots.recorder, incidents: decoratedIncidents };
			},
		});
		const anchor = 1_700_300_000_000 + prefixLength;
		seedActualControlPair(target, anchor);
		const actualPage = target.compactor.readLiveRunEvents({ runId: ACTUAL_RUN_ID });
		const publication = {
			incidentsDirectory: target.incidentsDirectory,
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
		};
		const first = publishWithinNamespaceWithPages(target, publication, [actualPage]);
		expect(first.state).toBe("uncertain");
		if (first.state !== "uncertain") return;
		const stageDirectory = join(target.incidentsDirectory, `.${first.incidentId}.partial-${first.publicationId}`);
		const temporaryPagePath = join(stageDirectory, "evidence", ".live-observation-page.tmp-page-000000000001.json");
		expect(statSync(temporaryPagePath).nlink).toBe(1);
		expect(statSync(temporaryPagePath).size).toBe(prefixLength);

		const reopened = await reopenActualCompactorFixture(target);
		const second = publishLiveIncidentObservation({ ...publication, compactor: reopened.compactor });
		expect(second).toEqual(expect.objectContaining({ state: "published" }));
		if (second.state !== "published") return;
		expect(second.incidentId).toBe(liveIncidentPublicationIdentity(publication).incidentId);
		const finalPagePath = join(second.artifactPath, "evidence", "page-000000000001.json");
		expect(readFileSync(finalPagePath)).toEqual(expectedPage);
		expect(statSync(finalPagePath).nlink).toBe(1);
		expect(
			readdirSync(join(second.artifactPath, "evidence")).some((name) =>
				name.startsWith(".live-observation-page.tmp-"),
			),
		).toBe(false);
		expect(reopened.internal.storageReservedBytes).toBe(0);
		expect(reopened.internal.storageReservedEntries).toBe(0);
		expect(reopened.internal.storageReservedInodes).toBe(0);
		expect({
			bytes: reopened.internal.storageBytes,
			entries: reopened.internal.storageEntries,
			inodes: reopened.internal.storageInodes.size,
		}).toEqual(realStorageSnapshot(join(target.agentDir, "incident-recorder"), target.incidentsDirectory));
	});

	it.each([0, 7])(
		"repairs an actual-root partial descriptor temporary with a %i-byte prefix",
		async (prefixLength) => {
			let failOnce = true;
			let expectedDescriptor: Buffer | undefined;
			const target = await actualCompactorFixture({
				namespaceRootDecorator: (namespaceRoots) => {
					const decoratedIncidents = {
						...namespaceRoots.incidents,
						writeFileExclusive: (
							path: IncidentCasRelativePath,
							value: string | Uint8Array,
							mode?: number,
						): void => {
							namespaceRoots.incidents.writeFileExclusive(path, value, mode);
							const publicPath = namespaceRoots.incidents.publicPath(path);
							if (failOnce && publicPath.endsWith(".live-observation-descriptor.tmp")) {
								failOnce = false;
								expectedDescriptor = Buffer.from(value);
								namespaceRoots.incidents.withFile(path, { access: "read_write" }, (file) => {
									file.truncate(prefixLength);
									file.sync();
								});
								throw new Error("injected partial descriptor write");
							}
						},
					} as IncidentCasRootMutation;
					return { recorder: namespaceRoots.recorder, incidents: decoratedIncidents };
				},
			});
			const anchor = 1_700_400_000_000 + prefixLength;
			seedActualControlPair(target, anchor);
			const actualPage = target.compactor.readLiveRunEvents({ runId: ACTUAL_RUN_ID });
			const publication = {
				incidentsDirectory: target.incidentsDirectory,
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
			};
			expect(() => publishWithinNamespaceWithPages(target, publication, [actualPage])).toThrow(
				"injected partial descriptor write",
			);
			const publicationIdentity = liveIncidentPublicationIdentity(publication);
			const stageDirectory = join(
				target.incidentsDirectory,
				`.${publicationIdentity.incidentId}.partial-${publicationIdentity.publicationId}`,
			);
			const temporaryDescriptorPath = join(stageDirectory, ".live-observation-descriptor.tmp");
			expect(statSync(temporaryDescriptorPath).nlink).toBe(1);
			expect(statSync(temporaryDescriptorPath).size).toBe(prefixLength);

			const reopened = await reopenActualCompactorFixture(target);
			const second = publishLiveIncidentObservation({ ...publication, compactor: reopened.compactor });
			expect(second).toEqual(expect.objectContaining({ state: "published" }));
			if (second.state !== "published") return;
			const finalDescriptorPath = join(second.artifactPath, "live-observation.json");
			expect(readFileSync(finalDescriptorPath)).toEqual(expectedDescriptor);
			expect(statSync(finalDescriptorPath).nlink).toBe(1);
			expect(existsSync(temporaryDescriptorPath)).toBe(false);
			expect(reopened.internal.storageReservedBytes).toBe(0);
			expect(reopened.internal.storageReservedEntries).toBe(0);
			expect(reopened.internal.storageReservedInodes).toBe(0);
			expect({
				bytes: reopened.internal.storageBytes,
				entries: reopened.internal.storageEntries,
				inodes: reopened.internal.storageInodes.size,
			}).toEqual(realStorageSnapshot(join(target.agentDir, "incident-recorder"), target.incidentsDirectory));
		},
	);

	it("reconciles an actual-root page-2 hard-link residue after restart", async () => {
		let failOnce = true;
		const target = await actualCompactorFixture({
			namespaceRootDecorator: (namespaceRoots) => {
				const decoratedIncidents = {
					...namespaceRoots.incidents,
					hardLink: (source: IncidentCasRelativePath, destination: IncidentCasRelativePath): void => {
						namespaceRoots.incidents.hardLink(source, destination);
						const publicPath = namespaceRoots.incidents.publicPath(destination);
						if (failOnce && publicPath.endsWith("page-000000000002.json")) {
							failOnce = false;
							throw new Error("injected page-2 hard-link crash");
						}
					},
				} as IncidentCasRootMutation;
				return { recorder: namespaceRoots.recorder, incidents: decoratedIncidents };
			},
		});
		const anchor = 1_700_500_000_000;
		const casValue = Buffer.from("actual-live-publication-page-2-cas");
		const digest = createHash("sha256").update(casValue).digest("hex");
		const casDirectory = join(target.agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2));
		const casPath = join(casDirectory, `${digest}.blob`);
		mkdirSync(casDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(casPath, casValue, { mode: 0o600 });
		for (let index = 1; index <= 66; index += 1) {
			const producerId = index === 65 ? ACTUAL_FENCE_PRODUCER_ID : ACTUAL_TRIGGER_PRODUCER_ID;
			const type = index === 1 ? "latency_trigger" : index === 65 ? "live_incident_high_water_fence" : "context";
			target.internal.appendSegmentRecord(actualOccurrenceInput(index, anchor, digest, casPath, producerId, type));
		}
		const actualFirstPage = target.compactor.readLiveRunEvents({ runId: ACTUAL_RUN_ID });
		const actualSecondPage = target.compactor.readLiveRunEvents({
			runId: ACTUAL_RUN_ID,
			cursor: actualFirstPage.cursor,
		});
		const publication = {
			incidentsDirectory: target.incidentsDirectory,
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
				occurrenceId: actualOccurrenceId(65),
			},
			classification: { value: "latency", causeLayer: "service" },
		};
		const first = publishWithinNamespaceWithPages(target, publication, [actualFirstPage, actualSecondPage]);
		expect(first.state).toBe("uncertain");
		if (first.state !== "uncertain") return;
		const stageDirectory = join(target.incidentsDirectory, `.${first.incidentId}.partial-${first.publicationId}`);
		const evidenceDirectory = join(stageDirectory, "evidence");
		const pageTwoPath = join(evidenceDirectory, "page-000000000002.json");
		const pageTwoTemporaryPath = join(evidenceDirectory, ".live-observation-page.tmp-page-000000000002.json");
		expect(statSync(pageTwoPath).nlink).toBe(2);
		expect(statSync(pageTwoTemporaryPath).nlink).toBe(2);

		const reopened = await reopenActualCompactorFixture(target);
		const second = publishLiveIncidentObservation({ ...publication, compactor: reopened.compactor });
		expect(second).toEqual(expect.objectContaining({ state: "published" }));
		if (second.state !== "published") return;
		const finalEvidenceDirectory = join(second.artifactPath, "evidence");
		expect(statSync(join(finalEvidenceDirectory, "page-000000000002.json")).nlink).toBe(1);
		expect(existsSync(join(finalEvidenceDirectory, ".live-observation-page.tmp-page-000000000002.json"))).toBe(false);
		const stored: IncidentRecorderRunHistoryEvent[] = [];
		for (let sequence = 1; sequence <= 2; sequence += 1) {
			const value = JSON.parse(
				readFileSync(join(finalEvidenceDirectory, `page-${sequence.toString().padStart(12, "0")}.json`), "utf8"),
			) as { events: IncidentRecorderRunHistoryEvent[] };
			stored.push(...value.events);
		}
		expect(stored).toHaveLength(65);
		expect(stored.at(-1)?.identity.occurrenceId).toBe(actualOccurrenceId(65));
		expect(
			inspectLiveIncidentObservation({
				incidentsDirectory: target.incidentsDirectory,
				incidentId: second.incidentId,
			}).state,
		).toBe("published");
		expect({
			bytes: reopened.internal.storageBytes,
			entries: reopened.internal.storageEntries,
			inodes: reopened.internal.storageInodes.size,
		}).toEqual(realStorageSnapshot(join(target.agentDir, "incident-recorder"), target.incidentsDirectory));
		expect(reopened.internal.storageReservedBytes).toBe(0);
		expect(reopened.internal.storageReservedEntries).toBe(0);
		expect(reopened.internal.storageReservedInodes).toBe(0);
	});

	it("replays an immutable page after a hard-link crash before temporary unlink", async () => {
		const trigger = identity(triggerProducerId, 48);
		const fence = identity(fenceProducerId, 49);
		let failAfterHardLink = true;
		const target = await fixture(
			[
				readerPage(
					"complete",
					[event(trigger, "latency_trigger", 1, 48), event(fence, "live_incident_high_water_fence", 1, 49)],
					{ segmentSequence: 1, ordinal: 49 },
				),
			],
			{
				namespaceRootDecorator: (namespaceRoots) => {
					const decoratedIncidents = {
						...namespaceRoots.incidents,
						hardLink: (source: IncidentCasRelativePath, destination: IncidentCasRelativePath): void => {
							namespaceRoots.incidents.hardLink(source, destination);
							if (failAfterHardLink) {
								failAfterHardLink = false;
								throw new Error("injected hard-link crash after durable link");
							}
						},
					} as IncidentCasRootMutation;
					return { recorder: namespaceRoots.recorder, incidents: decoratedIncidents };
				},
			},
		);
		const publicationInput: IncidentRecorderLiveIncidentPublicationInput = {
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_048, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		};
		const publicationRequest: Omit<IncidentRecorderLiveIncidentPublicationInput, "compactor"> = publicationInput;
		const publishWithinNamespace = () => {
			const mutation = target.lease.withNamespace((namespaceRoots) => {
				const effects: IncidentRecorderStorageAccountingEffect[] = [];
				return publishLiveIncidentObservationWithinRoot({
					...publicationRequest,
					incidents: namespaceRoots.incidents,
					readLiveRunEvents: () =>
						readerPage(
							"complete",
							[event(trigger, "latency_trigger", 1, 48), event(fence, "live_incident_high_water_fence", 1, 49)],
							{ segmentSequence: 1, ordinal: 49 },
						),
					storage: { reserve: () => {}, effects },
				});
			});
			if (mutation.state !== "committed") throw new Error(`namespace mutation failed: ${mutation.reason}`);
			return mutation.value;
		};
		const first = publishWithinNamespace();
		expect(first.state).toBe("uncertain");
		if (first.state !== "uncertain") return;
		const stageDirectory = join(target.incidentsDirectory, `.${first.incidentId}.partial-${first.publicationId}`);
		const evidenceDirectory = join(stageDirectory, "evidence");
		const pagePath = join(evidenceDirectory, "page-000000000001.json");
		const residue = readFileSync(pagePath);
		expect(statSync(pagePath).nlink).toBe(2);
		expect(readdirSync(evidenceDirectory).some((name) => name.startsWith(".live-observation-page.tmp-"))).toBe(true);
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		expect(target.compactor.storageAccountingReady).toBe(true);
		expect(target.compactor.storageMode).toBe("normal");
		const second = publishWithinNamespace();
		expect(second.state).toBe("published");
		if (second.state !== "published") return;
		const finalPagePath = join(second.artifactPath, "evidence", "page-000000000001.json");
		const finalEvidenceDirectory = join(second.artifactPath, "evidence");
		expect(readFileSync(finalPagePath)).toEqual(residue);
		expect(statSync(finalPagePath).nlink).toBe(1);
		expect(readdirSync(finalEvidenceDirectory).some((name) => name.startsWith(".live-observation-page.tmp-"))).toBe(
			false,
		);
	});

	it("replays an immutable page after a crash before the hard-link attempt", async () => {
		const trigger = identity(triggerProducerId, 50);
		const fence = identity(fenceProducerId, 51);
		let failBeforeHardLink = true;
		const target = await fixture(
			[
				readerPage(
					"complete",
					[event(trigger, "latency_trigger", 1, 50), event(fence, "live_incident_high_water_fence", 1, 51)],
					{ segmentSequence: 1, ordinal: 51 },
				),
			],
			{
				namespaceRootDecorator: (namespaceRoots) => {
					const decoratedIncidents = {
						...namespaceRoots.incidents,
						hardLink: (source: IncidentCasRelativePath, destination: IncidentCasRelativePath): void => {
							if (failBeforeHardLink) {
								failBeforeHardLink = false;
								throw new Error("injected hard-link crash before durable link");
							}
							namespaceRoots.incidents.hardLink(source, destination);
						},
					} as IncidentCasRootMutation;
					return { recorder: namespaceRoots.recorder, incidents: decoratedIncidents };
				},
			},
		);
		const publication = {
			incidentsDirectory: target.incidentsDirectory,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_050, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		};
		const firstMutation = target.lease.withNamespace((namespaceRoots) => {
			const effects: IncidentRecorderStorageAccountingEffect[] = [];
			return publishLiveIncidentObservationWithinRoot({
				...publication,
				incidents: namespaceRoots.incidents,
				readLiveRunEvents: () =>
					readerPage(
						"complete",
						[event(trigger, "latency_trigger", 1, 50), event(fence, "live_incident_high_water_fence", 1, 51)],
						{ segmentSequence: 1, ordinal: 51 },
					),
				storage: { reserve: () => {}, effects },
			});
		});
		if (firstMutation.state !== "committed") throw new Error(`namespace mutation failed: ${firstMutation.reason}`);
		const first = firstMutation.value;
		expect(first.state).toBe("uncertain");
		if (first.state !== "uncertain") return;
		const stageDirectory = join(target.incidentsDirectory, `.${first.incidentId}.partial-${first.publicationId}`);
		const evidenceDirectory = join(stageDirectory, "evidence");
		const temporaryPagePath = join(evidenceDirectory, ".live-observation-page.tmp-page-000000000001.json");
		const residue = readFileSync(temporaryPagePath);
		expect(statSync(temporaryPagePath).nlink).toBe(1);
		expect(existsSync(join(evidenceDirectory, "page-000000000001.json"))).toBe(false);

		const reopened = await reopenActualCompactorFixture(target);
		reopened.internal.readLiveRunEventsWithinRoot = vi.fn(() =>
			readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 50), event(fence, "live_incident_high_water_fence", 1, 51)],
				{ segmentSequence: 1, ordinal: 51 },
			),
		) as unknown as ActualCompactorFixture["internal"]["readLiveRunEventsWithinRoot"];
		const second = publishLiveIncidentObservation({ ...publication, compactor: reopened.compactor });
		expect(second.state).toBe("published");
		if (second.state !== "published") return;
		const finalEvidenceDirectory = join(second.artifactPath, "evidence");
		const finalPagePath = join(finalEvidenceDirectory, "page-000000000001.json");
		expect(readFileSync(finalPagePath)).toEqual(residue);
		expect(statSync(finalPagePath).nlink).toBe(1);
		expect(readdirSync(finalEvidenceDirectory).some((name) => name.startsWith(".live-observation-page.tmp-"))).toBe(
			false,
		);
		const storedPage = JSON.parse(readFileSync(finalPagePath, "utf8")) as {
			events: IncidentRecorderRunHistoryEvent[];
		};
		expect(storedPage.events.map((item) => item.identity.occurrenceId)).toEqual([
			trigger.occurrenceId,
			fence.occurrenceId,
		]);
		const rescannedStorage = realStorageSnapshot(
			join(target.agentDir, "incident-recorder"),
			target.incidentsDirectory,
		);
		expect({
			bytes: reopened.internal.storageBytes,
			entries: reopened.internal.storageEntries,
			inodes: reopened.internal.storageInodes.size,
		}).toEqual(rescannedStorage);
		expect(reopened.internal.storageReservedBytes).toBe(0);
		expect(reopened.internal.storageReservedEntries).toBe(0);
		expect(reopened.internal.storageReservedInodes).toBe(0);
	});

	it("replays an immutable descriptor after a crash before the hard-link attempt", async () => {
		const trigger = identity(triggerProducerId, 52);
		const fence = identity(fenceProducerId, 53);
		let failBeforeDescriptorHardLink = true;
		const target = await fixture(
			[
				readerPage(
					"complete",
					[event(trigger, "latency_trigger", 1, 52), event(fence, "live_incident_high_water_fence", 1, 53)],
					{ segmentSequence: 1, ordinal: 53 },
				),
			],
			{
				namespaceRootDecorator: (namespaceRoots) => {
					const decoratedIncidents = {
						...namespaceRoots.incidents,
						hardLink: (source: IncidentCasRelativePath, destination: IncidentCasRelativePath): void => {
							const destinationPath = namespaceRoots.incidents.publicPath(destination);
							if (failBeforeDescriptorHardLink && destinationPath.endsWith("/live-observation.json")) {
								failBeforeDescriptorHardLink = false;
								throw new Error("injected descriptor hard-link crash before durable link");
							}
							namespaceRoots.incidents.hardLink(source, destination);
						},
					} as IncidentCasRootMutation;
					return { recorder: namespaceRoots.recorder, incidents: decoratedIncidents };
				},
			},
		);
		const publication = {
			incidentsDirectory: target.incidentsDirectory,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_052, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		};
		expect(() =>
			target.lease.withNamespace((namespaceRoots) => {
				const effects: IncidentRecorderStorageAccountingEffect[] = [];
				return publishLiveIncidentObservationWithinRoot({
					...publication,
					incidents: namespaceRoots.incidents,
					readLiveRunEvents: () =>
						readerPage(
							"complete",
							[event(trigger, "latency_trigger", 1, 52), event(fence, "live_incident_high_water_fence", 1, 53)],
							{ segmentSequence: 1, ordinal: 53 },
						),
					storage: { reserve: () => {}, effects },
				});
			}),
		).toThrow("injected descriptor hard-link crash before durable link");
		const { incidentId, publicationId } = liveIncidentPublicationIdentity(publication);
		const stageDirectory = join(target.incidentsDirectory, `.${incidentId}.partial-${publicationId}`);
		const temporaryDescriptorPath = join(stageDirectory, ".live-observation-descriptor.tmp");
		const residue = readFileSync(temporaryDescriptorPath);
		expect(statSync(temporaryDescriptorPath).nlink).toBe(1);
		expect(existsSync(join(stageDirectory, "live-observation.json"))).toBe(false);

		const reopened = await reopenActualCompactorFixture(target);
		const second = publishLiveIncidentObservation({ ...publication, compactor: reopened.compactor });
		expect(second.state).toBe("published");
		if (second.state !== "published") return;
		const finalDescriptorPath = join(second.artifactPath, "live-observation.json");
		expect(readFileSync(finalDescriptorPath)).toEqual(residue);
		expect(statSync(finalDescriptorPath).nlink).toBe(1);
		expect(readdirSync(second.artifactPath).some((name) => name === ".live-observation-descriptor.tmp")).toBe(false);
		const page = JSON.parse(
			readFileSync(join(second.artifactPath, "evidence", "page-000000000001.json"), "utf8"),
		) as { events: IncidentRecorderRunHistoryEvent[] };
		expect(page.events.map((item) => item.identity.occurrenceId)).toEqual([trigger.occurrenceId, fence.occurrenceId]);
		const rescannedStorage = realStorageSnapshot(
			join(target.agentDir, "incident-recorder"),
			target.incidentsDirectory,
		);
		expect({
			bytes: reopened.internal.storageBytes,
			entries: reopened.internal.storageEntries,
			inodes: reopened.internal.storageInodes.size,
		}).toEqual(rescannedStorage);
		expect(reopened.internal.storageReservedBytes).toBe(0);
		expect(reopened.internal.storageReservedEntries).toBe(0);
		expect(reopened.internal.storageReservedInodes).toBe(0);
	});

	it("fails closed without replacing a mismatching immutable temporary", async () => {
		const trigger = identity(triggerProducerId, 54);
		const fence = identity(fenceProducerId, 55);
		const target = await fixture([
			readerPage(
				"complete",
				[event(trigger, "latency_trigger", 1, 54), event(fence, "live_incident_high_water_fence", 1, 55)],
				{ segmentSequence: 1, ordinal: 55 },
			),
		]);
		const publication = {
			incidentsDirectory: target.incidentsDirectory,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_054, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		};
		const { incidentId, publicationId } = liveIncidentPublicationIdentity(publication);
		const stageDirectory = join(target.incidentsDirectory, `.${incidentId}.partial-${publicationId}`);
		const evidenceDirectory = join(stageDirectory, "evidence");
		mkdirSync(evidenceDirectory, { recursive: true, mode: 0o700 });
		const temporaryPagePath = join(evidenceDirectory, ".live-observation-page.tmp-page-000000000001.json");
		const residue = Buffer.from("mismatching temporary content\n", "utf8");
		writeFileSync(temporaryPagePath, residue, { mode: 0o600 });

		const result = publishLiveIncidentObservation({ ...publication, compactor: target.compactor });
		expect(result.state).toBe("conflict");
		expect(readFileSync(temporaryPagePath)).toEqual(residue);
		expect(existsSync(join(evidenceDirectory, "page-000000000001.json"))).toBe(false);
	});

	it("invalidates accounting and releases cumulative reservations after low-headroom page failure", async () => {
		const trigger = identity(triggerProducerId, 44);
		const fence = identity(fenceProducerId, 45);
		const target = await fixture(
			[
				readerPage(
					"complete",
					[event(trigger, "latency_trigger", 1, 44), event(fence, "live_incident_high_water_fence", 1, 45)],
					{ segmentSequence: 1, ordinal: 45 },
				),
			],
			{ storageHighWaterBytes: (baseline, blockSize) => baseline.bytes + blockSize * 20 },
		);
		const result = publishLiveIncidentObservation({
			incidentsDirectory: target.incidentsDirectory,
			compactor: target.compactor,
			trigger: { ...trigger, acceptedAtWallTimeMs: 1_700_000_000_044, type: "latency_trigger" },
			fence,
			classification: { value: "latency", causeLayer: "service" },
		});
		expect(result.state).toBe("uncertain");
		expect(existsSync(join(target.incidentsDirectory, result.incidentId))).toBe(false);
		expect(existsSync(join(target.incidentsDirectory, `.${result.incidentId}.partial-${result.publicationId}`))).toBe(
			true,
		);
		expect(target.internal.storageReservedBytes).toBe(0);
		expect(target.internal.storageReservedEntries).toBe(0);
		expect(target.internal.storageReservedInodes).toBe(0);
		expect(target.compactor.storageAccountingReady).toBe(false);
		expect(target.compactor.storageMode).toBe("recovery-only");
	});

	it("latches one bounded fatal when public publication loses an owned root-backed store", async () => {
		let failAfterHardLink = true;
		const target = await actualCompactorFixture({
			namespaceRootDecorator: (namespaceRoots) => {
				const decoratedIncidents = {
					...namespaceRoots.incidents,
					hardLink: (source: IncidentCasRelativePath, destination: IncidentCasRelativePath): void => {
						namespaceRoots.incidents.hardLink(source, destination);
						const publicPath = namespaceRoots.incidents.publicPath(destination);
						if (failAfterHardLink && publicPath.endsWith("page-000000000001.json")) {
							failAfterHardLink = false;
							throw new Error("injected public hard-link boundary");
						}
					},
				} as IncidentCasRootMutation;
				return { recorder: namespaceRoots.recorder, incidents: decoratedIncidents };
			},
		});
		const anchor = 1_700_600_000_000;
		seedActualControlPair(target, anchor);
		const publication = {
			incidentsDirectory: target.incidentsDirectory,
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
		};
		const first = publishLiveIncidentObservation({ ...publication, compactor: target.compactor });
		expect(first.state).toBe("uncertain");
		if (first.state !== "uncertain") return;
		const stageDirectory = join(target.incidentsDirectory, `.${first.incidentId}.partial-${first.publicationId}`);
		const residuePath = join(stageDirectory, "evidence", "page-000000000001.json");
		const residue = readFileSync(residuePath);
		expect(statSync(residuePath).nlink).toBe(2);
		expect(target.compactor.storageAccountingReady).toBe(false);
		expect(target.internal.storageReservedBytes).toBe(0);
		expect(target.internal.storageReservedEntries).toBe(0);
		expect(target.internal.storageReservedInodes).toBe(0);
		const fatal = target.internal.segmentOwnershipUncertainError;
		expect(fatal).toBeInstanceOf(IncidentRecorderSegmentOwnershipUncertainError);
		if (!(fatal instanceof IncidentRecorderSegmentOwnershipUncertainError)) return;
		expect(fatal.reason).toBe("live_publication_partial_filesystem_failure");
		expect(Buffer.byteLength(fatal.message)).toBeLessThanOrEqual(256);
		await expect(target.compactor.run({ signal: new AbortController().signal })).rejects.toBe(fatal);
		const second = publishLiveIncidentObservation({ ...publication, compactor: target.compactor });
		expect(second.state).toBe("uncertain");
		expect(target.internal.segmentOwnershipUncertainError).toBe(fatal);
		expect(readFileSync(residuePath)).toEqual(residue);
	});

	it("does not latch ownership fatal when publication has no store because the lifecycle callback is unavailable", async () => {
		const target = await actualCompactorFixture();
		if (target.lease.release().state !== "released") throw new Error("fixture lifecycle lease did not release");
		const publication = {
			incidentsDirectory: target.incidentsDirectory,
			trigger: {
				...identity(ACTUAL_TRIGGER_PRODUCER_ID, 3),
				acceptedAtWallTimeMs: 1_700_600_000_003,
				type: "latency_trigger",
			},
			fence: identity(ACTUAL_FENCE_PRODUCER_ID, 4),
			classification: { value: "latency", causeLayer: "service" },
		};
		const result = publishLiveIncidentObservation({ ...publication, compactor: target.compactor });
		expect(result.state).toBe("uncertain");
		expect(target.internal.segmentOwnershipUncertainError).toBeUndefined();
		expect(target.internal.storageReservedBytes).toBe(0);
		expect(target.internal.storageReservedEntries).toBe(0);
		expect(target.internal.storageReservedInodes).toBe(0);
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
		const effectSnapshots: Array<{
			effects: number;
			liveBytes: number;
			liveEntries: number;
			liveInodes: number;
			reservedBytes: number;
			reservedEntries: number;
			reservedInodes: number;
			released: boolean;
		}> = [];
		const applyStorageAccountingEffects = target.internal.applyStorageAccountingEffects.bind(target.compactor);
		target.internal.applyStorageAccountingEffects = (effects) => {
			const reservation = target.internal.incidentLivePublicationRootStorageReservation;
			effectSnapshots.push({
				effects: effects.length,
				liveBytes: reservation?.bytes ?? 0,
				liveEntries: reservation?.entries ?? 0,
				liveInodes: reservation?.inodes ?? 0,
				reservedBytes: target.internal.storageReservedBytes,
				reservedEntries: target.internal.storageReservedEntries,
				reservedInodes: target.internal.storageReservedInodes,
				released: reservation?.released ?? true,
			});
			return applyStorageAccountingEffects(effects);
		};
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
		expect(effectSnapshots).toHaveLength(1);
		expect(effectSnapshots[0]?.effects).toBeGreaterThan(0);
		expect(effectSnapshots[0]?.liveBytes).toBeGreaterThan(0);
		expect(effectSnapshots[0]?.liveEntries).toBeGreaterThan(0);
		expect(effectSnapshots[0]?.liveInodes).toBeGreaterThan(0);
		expect(effectSnapshots[0]?.reservedBytes).toBeGreaterThanOrEqual(effectSnapshots[0]?.liveBytes ?? 0);
		expect(effectSnapshots[0]?.reservedEntries).toBeGreaterThanOrEqual(effectSnapshots[0]?.liveEntries ?? 0);
		expect(effectSnapshots[0]?.reservedInodes).toBeGreaterThanOrEqual(effectSnapshots[0]?.liveInodes ?? 0);
		expect(effectSnapshots[0]?.released).toBe(false);
		expect(target.internal.incidentLivePublicationRootStorageReservation).toBeUndefined();
		expect(target.internal.storageReservedBytes).toBe(0);
		expect(target.internal.storageReservedEntries).toBe(0);
		expect(target.internal.storageReservedInodes).toBe(0);
		const rescannedStorage = realStorageSnapshot(
			join(target.agentDir, "incident-recorder"),
			target.incidentsDirectory,
		);
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		expect({
			bytes: target.internal.storageBytes,
			entries: target.internal.storageEntries,
			inodes: target.internal.storageInodes.size,
		}).toEqual(rescannedStorage);
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
