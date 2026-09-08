import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, opendir, realpath, statfs } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { captureCausalPlatform, recordCausalPlatform } from "./diagnostic-causal-platform.js";
import { DiagnosticArtifactOperations, type DiagnosticArtifactResult } from "./diagnostic-evidence-artifacts.js";
import { DiagnosticEvidencePipeline } from "./diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "./diagnostic-evidence-store.js";
import {
	EVIDENCE_BATCH_BYTES,
	EVIDENCE_BATCH_ROWS,
	EVIDENCE_HISTORY_MS,
	type EvidenceIncident,
	type EvidenceIncidentUpdate,
	type EvidenceStoreStats,
} from "./diagnostic-evidence-store-protocol.js";
import { analyzeStoredIncident, type DiagnosticCausalProvider } from "./diagnostic-incident-analysis.js";
import { exportNativeAtopWindow, type NativeAtopReceipt } from "./diagnostic-native-atop.js";
import { exportNativeJournal, type NativeJournalOptions, readNativeJournal } from "./diagnostic-native-journal.js";

const GIB = 1024 ** 3;
const WRITE_RESERVE = 8 * 1024 * 1024;
const SOURCE = "journal:service";
const GAP_SOURCE = "internal:service-provider-gaps";
const CONFIG_SOURCE = "internal:service-journal-selector";
const ATOP_INPUTS = "internal:atop-inputs";
const ATOP_RECEIPTS = "internal:atop-receipts";
const COVERAGE_LIMITS = ["Provider continuity has not been established; only observed evidence is claimed."];
const TRANSIENT_LIMITS = new Set([
	"The post-trigger window is still being captured.",
	"The native journal export is pending.",
	"The final native journal export is pending.",
	"Atop window coverage is pending, partial, or unavailable; inspect its provider receipts.",
	"Native atop artifacts are not configured.",
]);

export interface DiagnosticEvidenceServiceConfig {
	stateRoot: string;
	journal: NativeJournalOptions;
	atop?: { directory: string; timeZone: string; atopPath?: string };
	/** The scoped stock bpftrace stream is included in this service's journal selector. */
	causalTrace?: DiagnosticCausalProvider;
	/** Explicit flat native history directories; they are measured, never modified. */
	nativeHistoryDirectories: string[];
	totalBudgetBytes?: number;
	freeReserveBytes?: number;
	maxArtifactBytes?: number;
}

function identity(...parts: string[]): string {
	return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

/** File dates belong to the producer timezone; each native file keeps its own header. */
export async function selectNativeAtopSources(
	options: { directory: string; timeZone: string },
	window: { sinceMs: number; untilMs: number },
): Promise<{ sources: { day: string; path: string }[]; missingDays: string[] }> {
	if (
		!Number.isSafeInteger(window.sinceMs) ||
		!Number.isSafeInteger(window.untilMs) ||
		window.untilMs < window.sinceMs ||
		window.untilMs - window.sinceMs > 3_600_000
	)
		throw new Error("atop_selection_window");
	const formatter = new Intl.DateTimeFormat("en-US", {
		timeZone: options.timeZone,
		calendar: "gregory",
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
	});
	const dayAt = (time: number) => {
		const parts = formatter.formatToParts(time);
		return ["year", "month", "day"].map((type) => parts.find((part) => part.type === type)!.value).join("");
	};
	const days = new Set<string>([dayAt(window.untilMs)]);
	for (let time = window.sinceMs; time <= window.untilMs; time += 60_000) days.add(dayAt(time));
	if ((await realpath(options.directory)) !== options.directory) throw new Error("atop_directory_invalid");
	const found = new Set<string>();
	let count = 0;
	for await (const entry of await opendir(options.directory)) {
		if (++count > 4096) throw new Error("atop_directory_entry_limit");
		const day = /^atop_(\d{8})$/.exec(entry.name)?.[1];
		if (day && days.has(day)) {
			if (!(await lstat(join(options.directory, entry.name))).isFile()) throw new Error("atop_source_not_regular");
			found.add(day);
		}
	}
	return {
		sources: [...found].sort().map((day) => ({ day, path: join(options.directory, `atop_${day}`) })),
		missingDays: [...days].filter((day) => !found.has(day)).sort(),
	};
}

interface AtopInput {
	sourcePath: string;
	day: string;
	phase: "initial" | "final";
	sinceMs: number;
	untilMs: number;
	incidentId: string;
}
interface AtopReceiptRecord {
	operationId: string;
	incidentId: string;
	observedAtMs: number;
	receipt: NativeAtopReceipt;
}
export interface DiagnosticCapacity {
	usedBytes: number;
	nativeBytes: number;
	databaseBytes: number;
	reservedArtifactBytes: number;
	availableBytes: number;
	admitted: boolean;
}
export interface DiagnosticEvidenceServiceStatus {
	ready: boolean;
	provider: "starting" | "following" | "unavailable" | "cursor_lost";
	capacity?: DiagnosticCapacity;
	occurrences: number;
	incidents: number;
	pendingArtifactOperations: number;
	lastError?: string;
}
export interface DiagnosticEvidenceServiceOptions {
	signal: AbortSignal;
	onReady?: (status: DiagnosticEvidenceServiceStatus) => void;
	onStatus?: (status: DiagnosticEvidenceServiceStatus) => void;
	/** A test clock may advance time; retention and capture durations remain canonical. */
	now?: () => number;
}

function validate(config: DiagnosticEvidenceServiceConfig): void {
	if (process.platform !== "linux") throw new Error("diagnostic_service_requires_linux");
	if (!isAbsolute(config.stateRoot) || resolve(config.stateRoot) !== config.stateRoot)
		throw new Error("diagnostic_state_root: absolute canonical path required");
	if (!Array.isArray(config.nativeHistoryDirectories) || config.nativeHistoryDirectories.length > 16)
		throw new Error("native_history_directories");
	for (const path of config.nativeHistoryDirectories)
		if (!isAbsolute(path) || resolve(path) !== path) throw new Error("native_history_path");
	if (new Set(config.nativeHistoryDirectories).size !== config.nativeHistoryDirectories.length)
		throw new Error("native_history_duplicate");
	if (
		config.causalTrace &&
		(!/^[A-Za-z0-9_.-]{1,64}$/.test(config.causalTrace.identifier) ||
			!Number.isSafeInteger(config.causalTrace.clockTicksPerSecond) ||
			config.causalTrace.clockTicksPerSecond < 1 ||
			config.causalTrace.clockTicksPerSecond > 1_000_000 ||
			!config.journal?.namespace ||
			config.journal.identifier ||
			config.journal.userUnit)
	)
		throw new Error("causal_provider_configuration");
	for (const value of [
		config.totalBudgetBytes ?? 16 * GIB,
		config.freeReserveBytes ?? 8 * GIB,
		config.maxArtifactBytes ?? 256 * 1024 * 1024,
	])
		if (!Number.isSafeInteger(value) || value < 1) throw new Error("diagnostic_capacity_configuration");
	if (!config.journal || typeof config.journal !== "object") throw new Error("journal_selector");
	for (const [key, value] of Object.entries(config.journal)) {
		if (
			!["namespace", "identifier", "userUnit", "journalctlPath"].includes(key) ||
			typeof value !== "string" ||
			!value ||
			value.length > 4096 ||
			value.includes("\0")
		)
			throw new Error("journal_selector");
	}
	if (!config.journal.namespace && !config.journal.identifier && !config.journal.userUnit)
		throw new Error("journal_selector_required");
	if (config.journal.journalctlPath && !isAbsolute(config.journal.journalctlPath))
		throw new Error("journal_executable_path");
	if (config.atop) {
		if (
			!isAbsolute(config.atop.directory) ||
			resolve(config.atop.directory) !== config.atop.directory ||
			!config.nativeHistoryDirectories.includes(config.atop.directory)
		)
			throw new Error("atop_directory_capacity_required");
		if (typeof config.atop.timeZone !== "string" || !config.atop.timeZone)
			throw new Error("atop_producer_timezone_required");
		new Intl.DateTimeFormat("en", { timeZone: config.atop.timeZone }).format(0);
		if (config.atop.atopPath && !isAbsolute(config.atop.atopPath)) throw new Error("atop_executable_path");
		if (Object.keys(config.atop).some((key) => !["directory", "timeZone", "atopPath"].includes(key)))
			throw new Error("atop_configuration_unknown");
	}
}

async function fileBytes(path: string): Promise<number> {
	const stat = await lstat(path);
	if (!stat.isFile()) throw new Error("native_history_unknown: non-regular entry");
	return Math.max(stat.size, stat.blocks * 512);
}

/** Only fixed SQLite names, SQL accounting, and explicitly bounded flat provider directories. */
export async function measureDiagnosticCapacity(
	config: DiagnosticEvidenceServiceConfig,
	stats: Pick<EvidenceStoreStats, "artifactAllocatedBytes" | "reservedArtifactBytes">,
): Promise<DiagnosticCapacity> {
	validate(config);
	let databaseBytes = 0;
	for (const suffix of ["", "-wal", "-shm"]) {
		try {
			databaseBytes += await fileBytes(join(config.stateRoot, `evidence.sqlite${suffix}`));
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
	}
	let nativeBytes = 0;
	for (const path of config.nativeHistoryDirectories) {
		if ((await realpath(path)) !== path || !(await lstat(path)).isDirectory())
			throw new Error("native_history_unknown: directory required");
		const directory = await opendir(path);
		let count = 0;
		for await (const entry of directory) {
			if (++count > 4096) throw new Error("native_history_unknown: flat entry limit");
			nativeBytes += await fileBytes(join(path, entry.name));
		}
	}
	// Reservations belong to attempts that can already have bytes on disk. Merely
	// queued work costs no allocation; hard-link publication has one underlying inode.
	const reservedArtifactBytes = stats.reservedArtifactBytes;
	const usedBytes = databaseBytes + nativeBytes + stats.artifactAllocatedBytes + reservedArtifactBytes;
	const filesystem = await statfs(config.stateRoot);
	const availableBytes = Math.min(
		(config.totalBudgetBytes ?? 16 * GIB) - usedBytes,
		filesystem.bavail * filesystem.bsize - (config.freeReserveBytes ?? 8 * GIB) - reservedArtifactBytes,
	);
	return {
		usedBytes,
		nativeBytes,
		databaseBytes,
		reservedArtifactBytes,
		availableBytes,
		admitted: availableBytes >= WRITE_RESERVE,
	};
}

async function stateDirectory(root: string): Promise<void> {
	const firstCreated = await mkdir(root, { recursive: true, mode: 0o700 });
	const stat = await lstat(root);
	if (
		!stat.isDirectory() ||
		(await realpath(root)) !== root ||
		(stat.mode & 0o077) !== 0 ||
		stat.uid !== process.getuid?.()
	)
		throw new Error("diagnostic_state_root: private owned directory required");
	const allowed = new Set([
		"evidence.sqlite",
		"evidence.sqlite-wal",
		"evidence.sqlite-shm",
		"artifacts",
		"recorder.lock",
	]);
	for await (const entry of await opendir(root))
		if (!allowed.has(entry.name))
			throw new Error("diagnostic_state_root: legacy or unknown content; use a fresh root");
	let directory = root;
	const stop = dirname(firstCreated ?? root);
	for (;;) {
		const handle = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		try {
			await handle.sync();
		} finally {
			await handle.close();
		}
		if (directory === stop) break;
		directory = dirname(directory);
	}
}

/** The launcher must hold an exclusive stock flock for this root for the whole run. */
export async function runDiagnosticEvidenceService(
	config: DiagnosticEvidenceServiceConfig,
	options: DiagnosticEvidenceServiceOptions,
): Promise<void> {
	validate(config);
	options.signal.throwIfAborted();
	await stateDirectory(config.stateRoot);
	const initial = await measureDiagnosticCapacity(config, { artifactAllocatedBytes: 0, reservedArtifactBytes: 0 });
	// An existing store must be allowed to reconcile funded operations and retention
	// under pressure. Only creation of a new store requires initial intake admission.
	let existingStore = false;
	try {
		existingStore = (await lstat(join(config.stateRoot, "evidence.sqlite"))).isFile();
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
	if (!initial.admitted && !existingStore)
		throw new Error("diagnostic_capacity: admission failed before database open");
	const store = await DiagnosticEvidenceStore.open({ path: join(config.stateRoot, "evidence.sqlite") });
	const pipeline = new DiagnosticEvidencePipeline(store, config.causalTrace);
	const now = options.now ?? Date.now;
	const status: DiagnosticEvidenceServiceStatus = {
		ready: false,
		provider: "starting",
		occurrences: 0,
		incidents: 0,
		pendingArtifactOperations: 0,
	};
	const notify = () => options.onStatus?.({ ...status });
	let reader: AsyncIterator<Buffer> | undefined;
	let next: Promise<void> | undefined;
	let readOutcome: { result?: IteratorResult<Buffer>; error?: unknown } | undefined;
	let wakeReader: (() => void) | undefined;
	let readerController: AbortController | undefined;
	let retryAt = 0;
	let retryDelay = 1000;
	let replayWithoutCursor = false;
	let readerUsedCursor = false;
	let artifactAfter: string | undefined;
	let incidentAfter: string | undefined;
	let analysisAfter: string | undefined;
	let lastMaintenance = 0;
	let lastRetention = 0;
	let lastFlush = Date.now();
	let batch: Uint8Array[] = [];
	let batchBytes = 0;
	let gapIdentity: string | null = null;
	let lastGapReason: string | undefined;
	let operations: DiagnosticArtifactOperations;
	const artifactController = new AbortController();
	let artifactTask: Promise<void> | undefined;
	let artifactOutcome: { result?: DiagnosticArtifactResult; error?: unknown } | undefined;
	let platformComplete = !config.causalTrace;
	let platformRetryAt = 0;
	let platformRevision = "unavailable";
	let runtimeBoot: { bootId: string; observedAtMs: number; more: boolean } | undefined;
	let platformLimitations = config.causalTrace ? ["Running-kernel causal contract has not been captured."] : [];
	const limitations = () => [
		...COVERAGE_LIMITS,
		...platformLimitations,
		...(!config.causalTrace ? ["Causal tracing is not configured for this recorder."] : []),
		...(!config.atop ? ["Native atop artifacts are not configured."] : []),
		...(gapIdentity ? ["Provider interruptions were observed; inspect the durable service gap occurrences."] : []),
	];

	async function recordMetadata(
		source: string,
		id: string,
		kind: string,
		time: number,
		payload: Uint8Array,
	): Promise<void> {
		if (await store.getOccurrence(source, id)) return;
		const cursor = await store.getCursor(source);
		await store.ingest({
			batchId: identity(source, id),
			source,
			expectedCursor: cursor,
			cursor: id,
			occurrences: [{ id, kind, wallTimeMs: time, payload }],
		});
	}

	async function prepareAtop(incident: EvidenceIncident, phase: "initial" | "final") {
		if (!config.atop) return { status: "unavailable", ready: true, complete: true, receiptIds: [] as string[] };
		const window = {
			sinceMs: incident.windowStartMs,
			untilMs: phase === "initial" ? incident.triggerTimeMs : incident.windowEndMs,
		};
		const selected = await selectNativeAtopSources(config.atop, window);
		const artifacts = await store.listArtifacts(incident.id);
		const receiptIds: string[] = [];
		const receipts: NativeAtopReceipt[] = [];
		let ready = true;
		for (const source of selected.sources) {
			const id = identity("atop-v1", incident.id, phase, source.day);
			const input: AtopInput = {
				sourcePath: source.path,
				day: source.day,
				phase,
				...window,
				incidentId: incident.id,
			};
			await recordMetadata(
				ATOP_INPUTS,
				id,
				"artifact.input",
				incident.triggerTimeMs,
				Buffer.from(JSON.stringify(input)),
			);
			await store.prepareOperation({
				id,
				incidentId: incident.id,
				kind: "export",
				artifact: { id, path: `${id}-${phase}.atop`, format: "atop.native" },
			});
			const artifact = artifacts.find((item) => item.id === id);
			const receiptId = artifact?.sha256 ? identity(id, artifact.sha256) : undefined;
			const occurrence = receiptId ? await store.getOccurrence(ATOP_RECEIPTS, receiptId) : undefined;
			if (!artifact || !occurrence) {
				ready = false;
				continue;
			}
			const captured = JSON.parse(Buffer.from(occurrence.payload).toString("utf8")) as AtopReceiptRecord;
			if (
				captured.operationId !== id ||
				captured.incidentId !== incident.id ||
				captured.receipt.sha256 !== artifact.sha256 ||
				captured.receipt.bytes !== artifact.bytes
			)
				throw new Error("atop_receipt_identity");
			receiptIds.push(receiptId!);
			receipts.push(captured.receipt);
		}
		const intervals: { sinceMs: number; untilMs: number }[] = [];
		for (const receipt of receipts) {
			let start = window.sinceMs;
			for (const gap of receipt.coverage.gaps) {
				if (gap.sinceMs > start) intervals.push({ sinceMs: start, untilMs: gap.sinceMs });
				start = Math.max(start, gap.untilMs);
			}
			if (start < window.untilMs) intervals.push({ sinceMs: start, untilMs: window.untilMs });
		}
		const gaps: { sinceMs: number; untilMs: number }[] = [];
		let covered = window.sinceMs;
		for (const interval of intervals.sort((a, b) => a.sinceMs - b.sinceMs)) {
			if (interval.sinceMs > covered) gaps.push({ sinceMs: covered, untilMs: interval.sinceMs });
			covered = Math.max(covered, interval.untilMs);
		}
		if (covered < window.untilMs) gaps.push({ sinceMs: covered, untilMs: window.untilMs });
		const partial =
			selected.missingDays.length > 0 ||
			gaps.length > 0 ||
			receipts.some((receipt) =>
				receipt.coverage.limitations.some(
					(limit) =>
						![
							"sampled_metrics_are_not_continuous_causal_evidence",
							"unlocked_source_may_have_an_incomplete_trailing_sample",
						].includes(limit),
				),
			);
		return {
			status: !ready ? "pending" : partial ? "partial" : "observed_only",
			ready,
			complete: ready && !partial,
			receiptIds,
			missingDays: selected.missingDays,
			gaps,
			window,
		};
	}

	async function refreshCapacity(): Promise<DiagnosticCapacity> {
		const stats = await store.stats();
		status.occurrences = stats.occurrences;
		status.incidents = stats.incidents;
		status.pendingArtifactOperations = stats.pendingArtifactOperations;
		status.capacity = await measureDiagnosticCapacity(config, stats);
		if (!status.capacity.admitted)
			status.lastError = "diagnostic_capacity: intake and exports paused; retention is unchanged";
		return status.capacity;
	}

	async function gap(reason: string): Promise<void> {
		if (lastGapReason === reason) return;
		const id = randomUUID();
		const timestamp = now();
		await store.ingest({
			batchId: id,
			source: GAP_SOURCE,
			expectedCursor: gapIdentity,
			cursor: id,
			occurrences: [
				{
					id,
					kind: "diagnostic.gap",
					wallTimeMs: timestamp,
					payload: Buffer.from(
						JSON.stringify({ provider: SOURCE, observedAtMs: timestamp, reason, coverage: "unavailable" }),
					),
				},
			],
		});
		gapIdentity = id;
		lastGapReason = reason;
	}

	async function stopReader(): Promise<void> {
		readerController?.abort();
		await next;
		await reader?.return?.();
		reader = undefined;
		next = undefined;
		readOutcome = undefined;
		readerController = undefined;
	}

	async function flush(): Promise<void> {
		if (!batch.length) return;
		const capacity = await refreshCapacity();
		if (!capacity.admitted || capacity.availableBytes < WRITE_RESERVE + batchBytes * 3) {
			status.capacity = { ...capacity, admitted: false };
			status.lastError = "diagnostic_capacity: next bounded batch cannot be admitted";
			return;
		}
		await pipeline.ingestJournalBatch(SOURCE, batch);
		batch = [];
		batchBytes = 0;
		lastFlush = Date.now();
		replayWithoutCursor = false;
		lastGapReason = undefined;
		retryDelay = 1000;
		await pipeline.publishPending();
	}

	async function openOperations(): Promise<DiagnosticArtifactOperations> {
		return DiagnosticArtifactOperations.open({
			store,
			root: join(config.stateRoot, "artifacts"),
			maxArtifactBytes: config.maxArtifactBytes,
			operationTimeoutMs: 60_000,
			availableBytes: async (operation) => {
				const capacity = await refreshCapacity();
				return Math.max(0, operation.reservationBytes + capacity.availableBytes - WRITE_RESERVE);
			},
			exportArtifact: async function* (operation, signal) {
				const incident = await store.getIncident(operation.incidentId);
				if (!incident) throw new Error("incident_missing");
				if (operation.artifact.format === "atop.native") {
					if (!config.atop) throw new Error("atop_provider_unavailable");
					const metadata = await store.getOccurrence(ATOP_INPUTS, operation.id);
					if (!metadata) throw new Error("atop_input_missing");
					const input = JSON.parse(Buffer.from(metadata.payload).toString("utf8")) as AtopInput;
					if (
						input.sourcePath !== join(config.atop.directory, `atop_${input.day}`) ||
						!/^\d{8}$/.test(input.day) ||
						input.incidentId !== incident.id
					)
						throw new Error("atop_input_identity");
					try {
						yield* exportNativeAtopWindow(
							{
								sourcePath: input.sourcePath,
								atopPath: config.atop.atopPath,
								maxArtifactBytes: config.maxArtifactBytes,
								onComplete: async (receipt) => {
									const captured: AtopReceiptRecord = {
										operationId: operation.id,
										incidentId: incident.id,
										observedAtMs: now(),
										receipt,
									};
									const payload = Buffer.from(JSON.stringify(captured));
									await recordMetadata(
										ATOP_RECEIPTS,
										identity(operation.id, receipt.sha256),
										"artifact.receipt",
										incident.triggerTimeMs,
										payload,
									);
									await recordMetadata(
										ATOP_RECEIPTS,
										randomUUID(),
										"artifact.receipt.attempt",
										incident.triggerTimeMs,
										payload,
									);
								},
							},
							{ sinceMs: input.sinceMs, untilMs: input.untilMs },
							signal,
						);
					} catch (error) {
						if (!options.signal.aborted && !artifactController.signal.aborted)
							await recordMetadata(
								"internal:artifact-failures",
								randomUUID(),
								"artifact.failure",
								incident.triggerTimeMs,
								Buffer.from(
									JSON.stringify({
										operationId: operation.id,
										incidentId: incident.id,
										observedAtMs: now(),
										error: String(error).slice(0, 1024),
									}),
								),
							);
						throw error;
					}
					return;
				}
				if (operation.artifact.format !== "journal.export") throw new Error("artifact_provider_unavailable");
				const untilMs = operation.artifact.path.endsWith("-final.journal")
					? incident.windowEndMs
					: Math.min(now(), incident.windowEndMs);
				yield* exportNativeJournal(
					config.journal,
					{ sinceMs: Math.max(0, incident.windowStartMs), untilMs },
					AbortSignal.any([signal, AbortSignal.timeout(2000)]),
				);
			},
		});
	}

	async function maintenance(): Promise<void> {
		if (now() - lastRetention >= 60_000) {
			const retained = await store.retain({ nowMs: now(), limit: 128 });
			lastRetention = retained.more ? 0 : now();
		}
		await refreshCapacity();
		if (
			config.causalTrace &&
			!platformComplete &&
			Date.now() >= platformRetryAt &&
			status.capacity?.admitted &&
			status.capacity.availableBytes >= WRITE_RESERVE + EVIDENCE_BATCH_BYTES
		) {
			platformRetryAt = Date.now() + 60_000;
			try {
				const captured = await captureCausalPlatform();
				if (captured.platform.clockTicksPerSecond !== config.causalTrace.clockTicksPerSecond)
					throw new Error("causal_clock_configuration_mismatch");
				await recordCausalPlatform(store, captured);
				runtimeBoot = { bootId: captured.platform.bootId, observedAtMs: now(), more: true };
				platformRevision = identity(JSON.stringify(captured.platform));
				platformLimitations = captured.limitations.map((item) => `Causal platform: ${item}`);
				platformComplete = captured.limitations.length === 0;
			} catch (error) {
				if (error instanceof Error && error.message === "causal_clock_configuration_mismatch") throw error;
				status.lastError = String(error).slice(0, 1024);
				platformLimitations = [
					"Running-kernel causal contract capture is unavailable; attribution remains limited.",
				];
			}
		}
		if (runtimeBoot?.more) {
			const retired = await store.recordRuntimeBoot(runtimeBoot);
			runtimeBoot.more = retired.more;
		}
		await pipeline.publishPending();
		const incidents = await store.listIncidents({ afterId: incidentAfter, limit: 32 });
		incidentAfter = incidents.length === 32 ? incidents.at(-1)!.id : undefined;
		for (const incident of incidents) {
			if (incident.state === "complete" || (incident.state === "limited" && !config.atop)) continue;
			const ended = now() >= incident.windowEndMs;
			if (ended) await pipeline.prepareJournalExport(incident, "final");
			let atop: Awaited<ReturnType<typeof prepareAtop>>;
			try {
				atop = await prepareAtop(incident, ended ? "final" : "initial");
			} catch (error) {
				atop = { status: "unavailable", ready: true, complete: false, receiptIds: [] };
				status.lastError = String(error).slice(0, 1024);
			}
			const artifacts = await store.listArtifacts(incident.id);
			const final = artifacts.some((artifact) => artifact.path.endsWith("-final.journal"));
			const update: EvidenceIncidentUpdate = {
				state: ended && final && atop.ready ? "limited" : "published",
				coverage: {
					...incident.coverage,
					windowEnded: ended,
					exportComplete: final && atop.complete,
					journalExportComplete: final,
					serviceGapCursor: gapIdentity,
					providers: {
						journal: "observed_only",
						atop,
						causalTrace:
							(incident.coverage.providers as Record<string, unknown> | undefined)?.causalTrace ?? "unavailable",
					},
				},
				limitations: [
					...new Set([
						...incident.limitations.filter((limitation) => !TRANSIENT_LIMITS.has(limitation)),
						...limitations(),
						...(config.atop && !atop.complete
							? ["Atop window coverage is pending, partial, or unavailable; inspect its provider receipts."]
							: []),
						...(!ended ? ["The post-trigger window is still being captured."] : []),
						...(!final ? ["The final native journal export is pending."] : []),
					]),
				],
			};
			if (
				incident.state !== update.state ||
				JSON.stringify(incident.coverage) !== JSON.stringify(update.coverage) ||
				JSON.stringify(incident.limitations) !== JSON.stringify(update.limitations)
			)
				await store.updateIncident(incident.id, update);
		}
		// One bounded analysis per maintenance pass; export and live ingestion do
		// not wait for every open incident's historical window to be re-read.
		const [candidate] = await store.listIncidents({ afterId: analysisAfter, limit: 1 });
		analysisAfter = candidate?.id;
		if (candidate && status.capacity?.admitted && status.capacity.availableBytes >= WRITE_RESERVE + 768 * 1024) {
			const previous = candidate.coverage.causalAnalysis as
				| { evidenceRevision?: number; platformRevision?: string; windowEnded?: boolean; analyzedAtMs?: number }
				| undefined;
			const sourceCursor = await store.getCursor(SOURCE);
			const ended = now() >= candidate.windowEndMs;
			if (
				!previous ||
				previous.platformRevision !== platformRevision ||
				previous.windowEnded !== ended ||
				(previous.evidenceRevision !== candidate.evidenceRevision && now() - (previous.analyzedAtMs ?? 0) >= 10_000)
			) {
				const analyzed = await analyzeStoredIncident(store, candidate, config.causalTrace);
				const { classification, ...receipt } = analyzed;
				await store.updateIncident(candidate.id, {
					coverage: {
						...candidate.coverage,
						cause: classification,
						causalAnalysis: {
							...receipt,
							sourceCursor,
							evidenceRevision: candidate.evidenceRevision,
							platformRevision,
							windowEnded: ended,
							analyzedAtMs: now(),
						},
						providers: {
							...(candidate.coverage.providers as Record<string, unknown> | undefined),
							causalTrace: {
								status: config.causalTrace && analyzed.traceRecords > 0 ? "observed_only" : "unavailable",
								traceRecords: analyzed.traceRecords,
							},
						},
					},
				});
			}
		}
		await refreshCapacity();
		if (artifactOutcome) {
			if (artifactOutcome.result) {
				artifactAfter = artifactOutcome.result.nextId;
				if (artifactOutcome.result.failures.length) status.lastError = artifactOutcome.result.failures[0]!.error;
			} else status.lastError = String(artifactOutcome.error).slice(0, 1024);
			artifactTask = undefined;
			artifactOutcome = undefined;
		}
		if (!artifactTask) {
			artifactTask = operations
				.reconcile({
					limit: 1,
					afterId: artifactAfter,
					signal: AbortSignal.any([options.signal, artifactController.signal]),
				})
				.then(
					(result) => {
						artifactOutcome = { result };
						wakeReader?.();
					},
					(error: unknown) => {
						artifactOutcome = { error };
						wakeReader?.();
					},
				);
		}
		lastMaintenance = Date.now();
		notify();
	}

	try {
		gapIdentity = await store.getCursor(GAP_SOURCE);
		await refreshCapacity();
		operations = await openOperations();
		if (config.atop) {
			const source = "internal:service-atop-selector";
			const selector = JSON.stringify({ directory: config.atop.directory, timeZone: config.atop.timeZone });
			const previous = await store.getCursor(source);
			if (previous !== null && previous !== selector)
				throw new Error("atop_selector_changed: use a separate fresh root");
			if (previous === null)
				await store.ingest({
					batchId: randomUUID(),
					source,
					expectedCursor: null,
					cursor: selector,
					occurrences: [],
				});
		}
		const selector = JSON.stringify({
			namespace: config.journal.namespace ?? null,
			identifier: config.journal.identifier ?? null,
			userUnit: config.journal.userUnit ?? null,
			causalTrace: config.causalTrace ?? null,
		});
		const previous = await store.getCursor(CONFIG_SOURCE);
		if (previous !== null && previous !== selector)
			throw new Error("diagnostic_journal_selector_changed: use a separate fresh root");
		if (previous === null)
			await store.ingest({
				batchId: randomUUID(),
				source: CONFIG_SOURCE,
				expectedCursor: null,
				cursor: selector,
				occurrences: [],
			});
		await maintenance();
		options.signal.throwIfAborted();
		status.ready = true;
		options.onReady?.({ ...status });
		notify();
		while (!options.signal.aborted) {
			if (Date.now() - lastMaintenance >= 1000) await maintenance();
			if (!status.capacity?.admitted) {
				await delay(100, undefined, { signal: options.signal });
				continue;
			}
			if (
				batch.length &&
				(batch.length >= EVIDENCE_BATCH_ROWS || batchBytes >= EVIDENCE_BATCH_BYTES || Date.now() - lastFlush >= 100)
			)
				await flush();
			if (batch.length >= EVIDENCE_BATCH_ROWS || batchBytes >= EVIDENCE_BATCH_BYTES) {
				await delay(100, undefined, { signal: options.signal });
				continue;
			}
			if (!reader && Date.now() >= retryAt) {
				readerController = new AbortController();
				const signal = AbortSignal.any([options.signal, readerController.signal]);
				const cursor = replayWithoutCursor ? null : await store.getCursor(SOURCE);
				readerUsedCursor = cursor !== null;
				reader = readNativeJournal(
					config.journal,
					{ sinceMs: Math.max(0, now() - EVIDENCE_HISTORY_MS), afterCursor: cursor ?? undefined, follow: true },
					signal,
				)[Symbol.asyncIterator]();
			}
			if (!reader) {
				await delay(100, undefined, { signal: options.signal });
				continue;
			}
			next ??= reader.next().then(
				(result) => {
					readOutcome = { result };
					wakeReader?.();
				},
				(error: unknown) => {
					readOutcome = { error };
					wakeReader?.();
				},
			);
			if (!readOutcome) {
				let timer: ReturnType<typeof setTimeout> | undefined;
				await new Promise<void>((resolve) => {
					wakeReader = resolve;
					timer = setTimeout(resolve, 100);
				});
				clearTimeout(timer);
				wakeReader = undefined;
			}
			if (!readOutcome) continue;
			const outcome = readOutcome;
			next = undefined;
			readOutcome = undefined;
			if (outcome.error || outcome.result?.done) {
				await flush();
				const reason = String(
					outcome.error instanceof Error ? outcome.error.message : (outcome.error ?? "journal_stream_ended"),
				).slice(0, 1024);
				status.provider = reason.includes("journal_cursor_lost") ? "cursor_lost" : "unavailable";
				status.lastError = reason;
				if (readerUsedCursor) replayWithoutCursor = true;
				await gap(reason);
				notify();
				await stopReader();
				retryAt = Date.now() + retryDelay;
				retryDelay = Math.min(30_000, retryDelay * 2);
				continue;
			}
			const raw = outcome.result!.value;
			if (raw.byteLength > EVIDENCE_BATCH_BYTES) throw new Error("journal_entry_too_large");
			if (batchBytes + raw.byteLength > EVIDENCE_BATCH_BYTES) await flush();
			if (batchBytes + raw.byteLength > EVIDENCE_BATCH_BYTES)
				throw new Error("diagnostic_capacity: batch cannot be admitted");
			batch.push(raw);
			batchBytes += raw.byteLength;
			status.provider = "following";
			// Keep replay mode until the first actual provider occurrence commits.
			if (batch.length >= EVIDENCE_BATCH_ROWS) await flush();
		}
	} catch (error) {
		if (!options.signal.aborted) throw error;
	} finally {
		artifactController.abort();
		await Promise.all([stopReader(), artifactTask]);
		await store.close();
	}
}
