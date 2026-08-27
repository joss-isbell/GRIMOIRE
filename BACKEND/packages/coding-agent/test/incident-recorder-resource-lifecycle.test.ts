import { createHash } from "node:crypto";
import {
	existsSync,
	linkSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readlinkSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	inspectIncidentRecorderRuns,
	replaceIncidentRecorderServiceCompactor,
} from "../src/modes/daemon/incident-recorder.js";
import {
	IncidentRecorderCompactor,
	type IncidentRecorderCompactorOptions,
	type IncidentRecorderCompactorRetainedResource,
} from "../src/modes/daemon/incident-recorder-compactor.js";

const roots: string[] = [];
const RUN_ID = "11111111-1111-4111-8111-111111111111";

function streamClosedArtifact(
	compactor: IncidentRecorderCompactor,
	runId: string,
	sourcePath: string,
	encoding: string,
	work: { deadlineMs: number; byteBudget: number },
) {
	const publicationPath = `${sourcePath}.closed-publication.json`;
	if (!existsSync(publicationPath)) {
		try {
			const source = statSync(sourcePath, { bigint: true });
			writeFileSync(
				publicationPath,
				`${JSON.stringify({
					schemaVersion: 1,
					state: "closed",
					proof: "target_process_stopped",
					source: {
						path: sourcePath,
						dev: source.dev.toString(),
						ino: source.ino.toString(),
						bytes: Number(source.size),
						mtimeMs: Number(source.mtimeMs),
						ctimeMs: Number(source.ctimeMs),
					},
				})}
`,
				{ mode: 0o600 },
			);
		} catch {}
	}
	return compactor.streamStoppedTargetArtifact(runId, sourcePath, encoding, publicationPath, work);
}

type LifecycleEvent = IncidentRecorderCompactorRetainedResource & { action: "open" | "close" };

function fixture(name: string): { root: string; agentDir: string } {
	const root = mkdtempSync(join(tmpdir(), `prime-agent-resource-lifecycle-${name}-`));
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { mode: 0o700 });
	roots.push(root);
	return { root, agentDir };
}

function writeJson(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function sha256(value: Buffer | string): string {
	return createHash("sha256").update(value).digest("hex");
}

function finishStorageDiscovery(compactor: IncidentRecorderCompactor, maximumSlices = 256): void {
	for (let slice = 0; slice < maximumSlices; slice += 1) {
		const snapshot = compactor.survivalSnapshot();
		if (snapshot.storageDiscoveryComplete) return;
		if (snapshot.storageDiscoveryError) throw new Error(snapshot.storageDiscoveryError);
		compactor.advanceBoundedDiscovery();
	}
	throw new Error("storage discovery did not complete within its fixture bound");
}

function lifecycleOptions(
	agentDir: string,
	events: LifecycleEvent[],
	beforeRead?: NonNullable<IncidentRecorderCompactorOptions["resourceLifecycleHooks"]>["beforeRead"],
): IncidentRecorderCompactorOptions {
	return {
		agentDir,
		freeReserveBytes: 0,
		resourceLifecycleHooks: {
			observe: (event) => events.push(event),
			...(beforeRead ? { beforeRead } : {}),
		},
	};
}

function expectDisposeClosesExactlyOnce(compactor: IncidentRecorderCompactor, events: LifecycleEvent[]): void {
	compactor.dispose();
	const afterFirst = [...events];
	const opens = afterFirst.filter((event) => event.action === "open");
	const closes = afterFirst.filter((event) => event.action === "close");
	expect(opens.length).toBeGreaterThan(0);
	expect(closes).toHaveLength(opens.length);
	expect(compactor.survivalSnapshot()).toMatchObject({
		retainedDirectories: 0,
		retainedFileDescriptors: 0,
		disposed: true,
	});
	compactor.dispose();
	expect(events).toEqual(afterFirst);
}

function createIncidentRequest(incidentDir: string, nowMs: number): void {
	writeJson(join(incidentDir, "journal-pin-request.json"), {
		version: 1,
		state: "pending",
		runId: RUN_ID,
		fromWallTimeMs: nowMs - 1_000,
		throughWallTimeMs: nowMs + 1_000,
		resolveAfterWallTimeMs: nowMs - 1,
		retainUntilWallTimeMs: nowMs + 60_000,
	});
}

function createPartialPinTraversal(target: { agentDir: string }, nowMs: number): void {
	const incidentDir = join(target.agentDir, "incidents", "pin-traversal");
	createIncidentRequest(incidentDir, nowMs);
	writeJson(join(incidentDir, "journal-pin-scan-proof.json"), {
		state: "fixed_range_namespace_scan_complete",
		runId: RUN_ID,
		fromWallTimeMs: nowMs - 1_000,
		throughWallTimeMs: nowMs + 1_000,
		journalEntries: [],
	});
	const runReferences = join(target.agentDir, "incident-recorder", "refs", "runs", sha256(RUN_ID));
	mkdirSync(runReferences, { recursive: true, mode: 0o700 });
	for (let index = 0; index < 96; index += 1) {
		writeFileSync(join(runReferences, `noise-${String(index).padStart(3, "0")}`), "", { mode: 0o600 });
	}
}

function createPartialJournalValidation(target: { agentDir: string }, nowMs: number): void {
	const recorderRoot = join(target.agentDir, "incident-recorder");
	const incidentDir = join(target.agentDir, "incidents", "manifest-validation");
	createIncidentRequest(incidentDir, nowMs);
	const value = Buffer.alloc(512 * 1024, 0x5a);
	const digest = sha256(value);
	const canonical = join(recorderRoot, "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
	mkdirSync(dirname(canonical), { recursive: true, mode: 0o700 });
	writeFileSync(canonical, value, { mode: 0o600 });
	const pinned = join(incidentDir, "journal-pins", "cas", `${digest}.blob`);
	mkdirSync(dirname(pinned), { recursive: true, mode: 0o700 });
	linkSync(canonical, pinned);
	writeJson(join(incidentDir, "journal-pin-manifest.json"), {
		version: 1,
		state: "complete_through_requested_window",
		runId: RUN_ID,
		fromWallTimeMs: nowMs - 1_000,
		throughWallTimeMs: nowMs + 1_000,
		occurrences: [
			{
				occurrenceReference: join(recorderRoot, "refs", "occurrence.json"),
				cursors: [],
				cas: { digest, bytes: value.length, path: canonical },
				eventWallTimeMs: String(nowMs),
				pinnedCasPath: pinned,
			},
		],
	});
}

function exactDescriptorCount(path: string): number {
	// This does not compare the process-wide FD count. It selects only descriptors
	// whose /proc symlink is the private fixture directory used by this test.
	let count = 0;
	for (const name of readdirSync("/proc/self/fd")) {
		try {
			if (readlinkSync(join("/proc/self/fd", name)) === path) count += 1;
		} catch {}
	}
	return count;
}

afterEach(() => {
	replaceIncidentRecorderServiceCompactor(undefined);
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("incident recorder retained-resource lifecycle", () => {
	it("explicitly abandons every partially open resource class exactly once and fails closed afterward", async () => {
		const warnings: string[] = [];
		const warningListener = (warning: Error): void => {
			warnings.push(warning.message);
		};
		process.on("warning", warningListener);
		try {
			const observedKinds = new Set<string>();

			const storageTarget = fixture("storage");
			const backlog = join(storageTarget.agentDir, "incident-recorder", "backlog");
			mkdirSync(backlog, { recursive: true, mode: 0o700 });
			for (let index = 0; index < 800; index += 1) {
				writeFileSync(join(backlog, String(index).padStart(4, "0")), "", { mode: 0o600 });
			}
			const storageEvents: LifecycleEvent[] = [];
			const storage = new IncidentRecorderCompactor(lifecycleOptions(storageTarget.agentDir, storageEvents));
			expect(storage.survivalSnapshot().retainedDirectories).toBeGreaterThan(0);
			expectDisposeClosesExactlyOnce(storage, storageEvents);
			for (const event of storageEvents) observedKinds.add(event.kind);

			const stoppedTarget = fixture("stopped-stream");
			const stoppedSource = join(stoppedTarget.root, "source.bin");
			writeFileSync(stoppedSource, Buffer.alloc(256 * 1024, 0x33), { mode: 0o600 });
			const stoppedEvents: LifecycleEvent[] = [];
			const stopped = new IncidentRecorderCompactor(lifecycleOptions(stoppedTarget.agentDir, stoppedEvents));
			finishStorageDiscovery(stopped);
			expect(
				streamClosedArtifact(stopped, RUN_ID, stoppedSource, "exact", {
					deadlineMs: Date.now() + 1_000,
					byteBudget: 1,
				}),
			).toMatchObject({ state: "pending" });
			expect(stopped.survivalSnapshot().retainedFileDescriptors).toBe(2);
			expectDisposeClosesExactlyOnce(stopped, stoppedEvents);
			for (const event of stoppedEvents) observedKinds.add(event.kind);

			const sysdigTarget = fixture("sysdig");
			const sysdigIncident = join(sysdigTarget.agentDir, "incidents", "sysdig");
			mkdirSync(sysdigIncident, { recursive: true, mode: 0o700 });
			const ringDir = join(sysdigTarget.root, "ring");
			mkdirSync(ringDir, { recursive: true, mode: 0o700 });
			for (let index = 0; index < 96; index += 1) {
				writeFileSync(join(ringDir, `noise-${String(index).padStart(3, "0")}`), "", { mode: 0o600 });
			}
			const sysdigEvents: LifecycleEvent[] = [];
			const sysdig = new IncidentRecorderCompactor({
				...lifecycleOptions(sysdigTarget.agentDir, sysdigEvents),
				sysdigRingBasePath: join(ringDir, "ring.scap"),
			});
			finishStorageDiscovery(sysdig);
			sysdig.requestPin(RUN_ID, sysdigIncident, Date.now());
			expect(sysdig.survivalSnapshot().retainedDirectories).toBe(1);
			expectDisposeClosesExactlyOnce(sysdig, sysdigEvents);
			for (const event of sysdigEvents) observedKinds.add(event.kind);

			const incidentTarget = fixture("incident-discovery");
			for (let index = 0; index < 96; index += 1) {
				mkdirSync(join(incidentTarget.agentDir, "incidents", `noise-${String(index).padStart(3, "0")}`), {
					recursive: true,
					mode: 0o700,
				});
			}
			const incidentEvents: LifecycleEvent[] = [];
			const incident = new IncidentRecorderCompactor(lifecycleOptions(incidentTarget.agentDir, incidentEvents));
			finishStorageDiscovery(incident);
			incident.processPendingPins();
			expect(incident.survivalSnapshot().retainedDirectories).toBe(1);
			expectDisposeClosesExactlyOnce(incident, incidentEvents);
			for (const event of incidentEvents) observedKinds.add(event.kind);

			const traversalTarget = fixture("pin-traversal");
			const traversalNow = Date.now();
			createPartialPinTraversal(traversalTarget, traversalNow);
			const traversalEvents: LifecycleEvent[] = [];
			const traversal = new IncidentRecorderCompactor(lifecycleOptions(traversalTarget.agentDir, traversalEvents));
			finishStorageDiscovery(traversal);
			traversal.processPendingPins(traversalNow);
			expect(traversal.survivalSnapshot().retainedDirectories).toBe(2);
			expectDisposeClosesExactlyOnce(traversal, traversalEvents);
			for (const event of traversalEvents) observedKinds.add(event.kind);

			const validationTarget = fixture("manifest-validation");
			const validationNow = Date.now();
			createPartialJournalValidation(validationTarget, validationNow);
			const validationEvents: LifecycleEvent[] = [];
			const validation = new IncidentRecorderCompactor(
				lifecycleOptions(validationTarget.agentDir, validationEvents),
			);
			finishStorageDiscovery(validation);
			validation.processPendingPins(validationNow);
			expect(validation.survivalSnapshot()).toMatchObject({
				retainedDirectories: 1,
				retainedFileDescriptors: 2,
			});
			expectDisposeClosesExactlyOnce(validation, validationEvents);
			for (const event of validationEvents) observedKinds.add(event.kind);

			expect(observedKinds).toEqual(
				new Set([
					"storage-discovery",
					"incident-discovery",
					"sysdig-discovery",
					"pin-traversal",
					"journal-manifest",
					"journal-pin",
					"stopped-source",
					"stopped-target",
				]),
			);

			expect(storage.admitObservation()).toBe(false);
			expect(() => storage.advanceBoundedDiscovery()).toThrow("Incident recorder compactor is disposed");
			expect(() => storage.processPendingPins()).toThrow("Incident recorder compactor is disposed");
			expect(() => storage.requestPin(RUN_ID, join(storageTarget.root, "incident"), Date.now())).toThrow(
				"Incident recorder compactor is disposed",
			);
			expect(
				streamClosedArtifact(storage, RUN_ID, stoppedSource, "exact", {
					deadlineMs: Date.now() + 1_000,
					byteBudget: 1,
				}),
			).toEqual({ state: "error", reason: "compactor_disposed" });
			await expect(storage.run()).rejects.toThrow("Incident recorder compactor is disposed");
			expect(storage.survivalSnapshot()).toMatchObject({
				retainedDirectories: 0,
				retainedFileDescriptors: 0,
			});
		} finally {
			process.off("warning", warningListener);
		}
		expect(warnings.filter((warning) => warning.includes("Closing directory handle on garbage collection"))).toEqual(
			[],
		);
	});

	it("closes retained resources exactly once when bounded work completes normally", () => {
		const expectNormallyClosed = (compactor: IncidentRecorderCompactor, events: LifecycleEvent[]): void => {
			expect(compactor.survivalSnapshot()).toMatchObject({
				retainedDirectories: 0,
				retainedFileDescriptors: 0,
			});
			const beforeDispose = [...events];
			expect(beforeDispose.filter((event) => event.action === "close")).toHaveLength(
				beforeDispose.filter((event) => event.action === "open").length,
			);
			compactor.dispose();
			expect(events).toEqual(beforeDispose);
		};

		const stoppedTarget = fixture("normal-stopped");
		const stoppedSource = join(stoppedTarget.root, "source.bin");
		writeFileSync(stoppedSource, Buffer.alloc(128 * 1024, 0x22), { mode: 0o600 });
		const stoppedEvents: LifecycleEvent[] = [];
		const stopped = new IncidentRecorderCompactor(lifecycleOptions(stoppedTarget.agentDir, stoppedEvents));
		finishStorageDiscovery(stopped);
		let stoppedResult = streamClosedArtifact(stopped, RUN_ID, stoppedSource, "exact", {
			deadlineMs: Date.now() + 1_000,
			byteBudget: 64 * 1024,
		});
		for (let call = 0; call < 8 && stoppedResult.state === "pending"; call += 1) {
			stoppedResult = streamClosedArtifact(stopped, RUN_ID, stoppedSource, "exact", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 64 * 1024,
			});
		}
		expect(stoppedResult).toMatchObject({ state: "complete" });
		expectNormallyClosed(stopped, stoppedEvents);

		const sysdigTarget = fixture("normal-sysdig");
		const sysdigIncident = join(sysdigTarget.agentDir, "incidents", "one");
		const ringDir = join(sysdigTarget.root, "ring");
		mkdirSync(sysdigIncident, { recursive: true, mode: 0o700 });
		mkdirSync(ringDir, { recursive: true, mode: 0o700 });
		const sysdigEvents: LifecycleEvent[] = [];
		const sysdig = new IncidentRecorderCompactor({
			...lifecycleOptions(sysdigTarget.agentDir, sysdigEvents),
			sysdigRingBasePath: join(ringDir, "ring.scap"),
		});
		finishStorageDiscovery(sysdig);
		sysdig.requestPin(RUN_ID, sysdigIncident, Date.now());
		expectNormallyClosed(sysdig, sysdigEvents);

		const incidentTarget = fixture("normal-incident");
		mkdirSync(join(incidentTarget.agentDir, "incidents", "one"), { recursive: true, mode: 0o700 });
		const incidentEvents: LifecycleEvent[] = [];
		const incident = new IncidentRecorderCompactor(lifecycleOptions(incidentTarget.agentDir, incidentEvents));
		finishStorageDiscovery(incident);
		incident.processPendingPins();
		expectNormallyClosed(incident, incidentEvents);

		const traversalTarget = fixture("normal-traversal");
		const traversalNow = Date.now();
		createPartialPinTraversal(traversalTarget, traversalNow);
		const traversalEvents: LifecycleEvent[] = [];
		const traversal = new IncidentRecorderCompactor(lifecycleOptions(traversalTarget.agentDir, traversalEvents));
		finishStorageDiscovery(traversal);
		for (let call = 0; call < 8; call += 1) traversal.processPendingPins(traversalNow);
		expectNormallyClosed(traversal, traversalEvents);

		const validationTarget = fixture("normal-validation");
		const validationNow = Date.now();
		createPartialJournalValidation(validationTarget, validationNow);
		const validationEvents: LifecycleEvent[] = [];
		const validation = new IncidentRecorderCompactor(lifecycleOptions(validationTarget.agentDir, validationEvents));
		finishStorageDiscovery(validation);
		for (let call = 0; call < 16; call += 1) validation.processPendingPins(validationNow);
		expectNormallyClosed(validation, validationEvents);
	});

	it("closes retained resources on injected read errors without waiting for garbage collection", () => {
		const readErrorKinds = new Set<string>();
		const runReadErrorCase = (
			name: string,
			setup: (target: { root: string; agentDir: string }, nowMs: number) => void,
			failKind: string,
			work: (
				compactor: IncidentRecorderCompactor,
				target: { root: string; agentDir: string },
				nowMs: number,
			) => void,
		): void => {
			const target = fixture(`read-error-${name}`);
			const nowMs = Date.now();
			setup(target, nowMs);
			const events: LifecycleEvent[] = [];
			let armed = false;
			const compactor = new IncidentRecorderCompactor({
				...lifecycleOptions(target.agentDir, events, (resource) => {
					if (armed && resource.kind === failKind) {
						armed = false;
						readErrorKinds.add(resource.kind);
						throw new Error(`injected_${resource.kind}_read_error`);
					}
				}),
				...(name === "sysdig" ? { sysdigRingBasePath: join(target.root, "ring", "ring.scap") } : {}),
			});
			finishStorageDiscovery(compactor);
			armed = true;
			work(compactor, target, nowMs);
			expect(events.filter((event) => event.kind === failKind && event.action === "close")).toHaveLength(1);
			if (name === "stopped-source") {
				expect(events.filter((event) => event.kind === "stopped-target" && event.action === "close")).toHaveLength(
					1,
				);
			}
			compactor.dispose();
			expect(compactor.survivalSnapshot()).toMatchObject({
				retainedDirectories: 0,
				retainedFileDescriptors: 0,
			});
		};

		const storageTarget = fixture("read-error-storage");
		const storageBacklog = join(storageTarget.agentDir, "incident-recorder", "backlog");
		mkdirSync(storageBacklog, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 800; index += 1) {
			writeFileSync(join(storageBacklog, String(index).padStart(4, "0")), "", { mode: 0o600 });
		}
		const storageEvents: LifecycleEvent[] = [];
		const storage = new IncidentRecorderCompactor(
			lifecycleOptions(storageTarget.agentDir, storageEvents, (resource) => {
				if (resource.kind !== "storage-discovery" || readErrorKinds.has(resource.kind)) return;
				readErrorKinds.add(resource.kind);
				throw new Error("injected_storage-discovery_read_error");
			}),
		);
		expect(storage.survivalSnapshot()).toMatchObject({
			retainedDirectories: 0,
			retainedFileDescriptors: 0,
			storageDiscoveryError: "storage_discovery_directory_read_failed",
		});
		expect(
			storageEvents.filter((event) => event.kind === "storage-discovery" && event.action === "close"),
		).toHaveLength(1);
		storage.dispose();

		runReadErrorCase(
			"incident",
			(target) => mkdirSync(join(target.agentDir, "incidents", "one"), { recursive: true, mode: 0o700 }),
			"incident-discovery",
			(compactor) => compactor.processPendingPins(),
		);
		runReadErrorCase(
			"sysdig",
			(target) => {
				mkdirSync(join(target.agentDir, "incidents", "one"), { recursive: true, mode: 0o700 });
				mkdirSync(join(target.root, "ring"), { recursive: true, mode: 0o700 });
			},
			"sysdig-discovery",
			(compactor, target) => {
				compactor.requestPin(RUN_ID, join(target.agentDir, "incidents", "one"), Date.now());
			},
		);
		runReadErrorCase(
			"pin-traversal",
			(target, nowMs) => createPartialPinTraversal(target, nowMs),
			"pin-traversal",
			(compactor, _target, nowMs) => compactor.processPendingPins(nowMs),
		);
		runReadErrorCase(
			"journal-manifest",
			(target, nowMs) => createPartialJournalValidation(target, nowMs),
			"journal-manifest",
			(compactor, _target, nowMs) => compactor.processPendingPins(nowMs),
		);
		runReadErrorCase(
			"journal-pin",
			(target, nowMs) => createPartialJournalValidation(target, nowMs),
			"journal-pin",
			(compactor, _target, nowMs) => compactor.processPendingPins(nowMs),
		);
		runReadErrorCase(
			"stopped-source",
			(target) => writeFileSync(join(target.root, "source"), "value", { mode: 0o600 }),
			"stopped-source",
			(compactor, target) => {
				expect(
					streamClosedArtifact(compactor, RUN_ID, join(target.root, "source"), "exact", {
						deadlineMs: Date.now() + 1_000,
						byteBudget: 1,
					}),
				).toMatchObject({ state: "error" });
			},
		);
		expect(readErrorKinds).toEqual(
			new Set([
				"storage-discovery",
				"incident-discovery",
				"sysdig-discovery",
				"pin-traversal",
				"journal-manifest",
				"journal-pin",
				"stopped-source",
			]),
		);
	});

	it("disposes retained work when the compactor journal reader fails", async () => {
		const target = fixture("run-failure");
		const source = join(target.root, "source.bin");
		writeFileSync(source, Buffer.alloc(256 * 1024, 0x44), { mode: 0o600 });
		const incidentDir = join(target.agentDir, "incidents", "run-failure");
		mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
		const ringDir = join(target.root, "ring");
		mkdirSync(ringDir, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 96; index += 1) {
			writeFileSync(join(ringDir, `noise-${String(index).padStart(3, "0")}`), "", { mode: 0o600 });
		}
		const events: LifecycleEvent[] = [];
		const compactor = new IncidentRecorderCompactor({
			...lifecycleOptions(target.agentDir, events),
			journalctlPath: join(target.root, "missing-journalctl"),
			sysdigRingBasePath: join(ringDir, "ring.scap"),
		});
		finishStorageDiscovery(compactor);
		expect(
			streamClosedArtifact(compactor, RUN_ID, source, "exact", {
				deadlineMs: Date.now() + 1_000,
				byteBudget: 1,
			}),
		).toMatchObject({ state: "pending" });
		compactor.requestPin(RUN_ID, incidentDir, Date.now());
		expect(compactor.survivalSnapshot()).toMatchObject({
			retainedDirectories: 1,
			retainedFileDescriptors: 2,
		});

		await expect(compactor.run()).rejects.toThrow();
		expect(compactor.survivalSnapshot()).toMatchObject({
			disposed: true,
			retainedDirectories: 0,
			retainedFileDescriptors: 0,
		});
		expect(events.filter((event) => event.action === "close")).toHaveLength(
			events.filter((event) => event.action === "open").length,
		);
	});

	it("closes the service run directory and disposes the prior global compactor on in-process replacement", async () => {
		const firstTarget = fixture("service-first");
		const runsRoot = join(firstTarget.agentDir, "incident-recorder", "runs");
		mkdirSync(runsRoot, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 40; index += 1) {
			mkdirSync(join(runsRoot, `run-${String(index).padStart(3, "0")}`), { mode: 0o700 });
		}
		const backlog = join(firstTarget.agentDir, "incident-recorder", "backlog");
		mkdirSync(backlog, { recursive: true, mode: 0o700 });
		for (let index = 0; index < 800; index += 1) {
			writeFileSync(join(backlog, String(index).padStart(4, "0")), "", { mode: 0o600 });
		}
		const first = new IncidentRecorderCompactor({ agentDir: firstTarget.agentDir, freeReserveBytes: 0 });
		replaceIncidentRecorderServiceCompactor(first);
		await inspectIncidentRecorderRuns(firstTarget.agentDir);
		expect(exactDescriptorCount(runsRoot)).toBe(1);

		const secondTarget = fixture("service-second");
		const second = new IncidentRecorderCompactor({ agentDir: secondTarget.agentDir, freeReserveBytes: 0 });
		replaceIncidentRecorderServiceCompactor(second);
		expect(first.survivalSnapshot()).toMatchObject({
			disposed: true,
			retainedDirectories: 0,
			retainedFileDescriptors: 0,
		});
		expect(exactDescriptorCount(runsRoot)).toBe(0);

		replaceIncidentRecorderServiceCompactor(undefined);
		replaceIncidentRecorderServiceCompactor(undefined);
		expect(second.survivalSnapshot()).toMatchObject({
			disposed: true,
			retainedDirectories: 0,
			retainedFileDescriptors: 0,
		});
		expect(exactDescriptorCount(runsRoot)).toBe(0);
		expect(existsSync(runsRoot)).toBe(true);
	});
});
