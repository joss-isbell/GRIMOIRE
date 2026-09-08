import { Worker } from "node:worker_threads";
import {
	EVIDENCE_BATCH_BYTES,
	EVIDENCE_BATCH_ROWS,
	type EvidenceArtifact,
	type EvidenceArtifactCompletion,
	type EvidenceArtifactSelection,
	type EvidenceBatch,
	type EvidenceChannelResult,
	type EvidenceIncident,
	type EvidenceIncidentInput,
	type EvidenceIncidentUpdate,
	type EvidenceIngestResult,
	type EvidenceListOptions,
	type EvidenceOccurrence,
	type EvidenceOperation,
	type EvidenceOperationInput,
	type EvidencePage,
	type EvidenceReference,
	type EvidenceRetentionResult,
	type EvidenceRuntimeBoot,
	type EvidenceRuntimeClaimResult,
	type EvidenceRuntimeExitResult,
	type EvidenceRuntimeProvider,
	type EvidenceStoreStats,
	type EvidenceWindow,
	type EvidenceWorkerReply,
} from "./diagnostic-evidence-store-protocol.js";

export type * from "./diagnostic-evidence-store-protocol.js";

export interface DiagnosticEvidenceStoreOptions {
	path: string;
	workerUrl?: URL;
	maxPendingRequests?: number;
}

/** The supervisor only sends bounded messages; every SQLite call runs in the worker. */
export class DiagnosticEvidenceStore {
	private readonly worker: Worker;
	private readonly pending = new Map<
		number,
		{
			resolve(value: unknown): void;
			reject(error: Error): void;
			timer: ReturnType<typeof setTimeout>;
			bytes: number;
		}
	>();
	private pendingBytes = 0;
	private nextId = 1;
	private failure?: Error;
	private closing?: Promise<void>;
	private resolveDrain?: () => void;
	private readonly ready: Promise<void>;

	private constructor(private readonly options: DiagnosticEvidenceStoreOptions) {
		const extension = import.meta.url.endsWith(".ts") ? ".ts" : ".js";
		this.worker = new Worker(
			options.workerUrl ?? new URL(`./diagnostic-evidence-store-worker${extension}`, import.meta.url),
			{
				workerData: { path: options.path },
				resourceLimits: { maxOldGenerationSizeMb: 96 },
				...(extension === ".ts" ? { execArgv: [...process.execArgv, "--import", import.meta.resolve("tsx")] } : {}),
			},
		);
		this.ready = new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => this.fail(new Error("evidence_store_startup_timeout")), 30_000);
			this.pending.set(0, { resolve: () => resolve(), reject, timer, bytes: 0 });
		});
		this.worker.on("message", (reply: EvidenceWorkerReply) => {
			const request = this.pending.get(reply.id);
			if (!request) return;
			this.pending.delete(reply.id);
			this.pendingBytes -= request.bytes;
			clearTimeout(request.timer);
			if (reply.error) request.reject(new Error(reply.error));
			else request.resolve(reply.result);
			if (this.pending.size === 0) this.resolveDrain?.();
		});
		this.worker.on("error", (error) => this.fail(error));
		this.worker.on("exit", () =>
			this.fail(new Error("evidence_store_worker_exited; pending commit outcome unknown")),
		);
	}

	static async open(options: DiagnosticEvidenceStoreOptions): Promise<DiagnosticEvidenceStore> {
		if (
			options.maxPendingRequests !== undefined &&
			(!Number.isInteger(options.maxPendingRequests) ||
				options.maxPendingRequests < 1 ||
				options.maxPendingRequests > 32)
		)
			throw new Error("pending_request_limit");
		const store = new DiagnosticEvidenceStore(options);
		try {
			await store.ready;
			return store;
		} catch (error) {
			await store.worker.terminate();
			throw error;
		}
	}

	private fail(error: Error): void {
		if (this.failure) return;
		this.failure = error;
		for (const request of this.pending.values()) {
			clearTimeout(request.timer);
			request.reject(error);
		}
		this.pending.clear();
		this.pendingBytes = 0;
		this.resolveDrain?.();
		void this.worker.terminate();
	}

	private call<T>(method: string, args: unknown[], bytes = 0): Promise<T> {
		if (this.failure) return Promise.reject(this.failure);
		if (this.closing && method !== "close") return Promise.reject(new Error("evidence_store_closed"));
		try {
			const metadata =
				method === "ingest" || method === "ingestJournal"
					? [
							(args[0] as EvidenceBatch).occurrences.map(({ payload: _payload, ...fields }) => fields),
							{ ...(args[0] as EvidenceBatch), occurrences: undefined },
						]
					: args;
			const metadataBytes = Buffer.byteLength(JSON.stringify(metadata));
			if (metadataBytes > 256 * 1024) return Promise.reject(new Error("metadata_bytes"));
			bytes += metadataBytes;
		} catch (error) {
			return Promise.reject(error);
		}
		if (
			this.pending.size >= (this.options.maxPendingRequests ?? 32) ||
			this.pendingBytes + bytes > 8 * EVIDENCE_BATCH_BYTES
		)
			return Promise.reject(new Error("evidence_store_queue_full"));
		return new Promise<T>((resolve, reject) => {
			const id = this.nextId++;
			const timer = setTimeout(
				() => this.fail(new Error("evidence_store_request_timeout; commit outcome unknown")),
				15_000,
			);
			this.pending.set(id, { resolve: (result) => resolve(result as T), reject, timer, bytes });
			this.pendingBytes += bytes;
			try {
				this.worker.postMessage({ id, method, args });
			} catch (error) {
				this.pending.delete(id);
				this.pendingBytes -= bytes;
				clearTimeout(timer);
				reject(error);
			}
		});
	}

	ingest(batch: EvidenceBatch): Promise<EvidenceIngestResult> {
		return this.ingestCall("ingest", batch);
	}
	/** Same native cursor and field values replay once, retaining the first serialized bytes. */
	ingestJournal(batch: EvidenceBatch): Promise<EvidenceIngestResult> {
		return this.ingestCall("ingestJournal", batch);
	}
	private ingestCall(method: "ingest" | "ingestJournal", batch: EvidenceBatch): Promise<EvidenceIngestResult> {
		const bytes = batch.occurrences.reduce((total, item) => total + item.payload.byteLength, 0);
		if (bytes > EVIDENCE_BATCH_BYTES) return Promise.reject(new Error("batch_bytes"));
		if (batch.occurrences.length > EVIDENCE_BATCH_ROWS) return Promise.reject(new Error("batch_rows"));
		return this.call(method, [batch], bytes);
	}
	getCursor(source: string): Promise<string | null> {
		return this.call("getCursor", [source]);
	}
	getOccurrence(source: string, id: string): Promise<EvidenceOccurrence | undefined> {
		return this.call("getOccurrence", [source, id]);
	}
	rememberRuntimeRole(proof: EvidenceReference, clockTicksPerSecond: number): Promise<EvidenceRuntimeClaimResult> {
		return this.call("rememberRuntimeRole", [proof, clockTicksPerSecond]);
	}
	/** Only the current running-kernel observation may retire other boots. */
	recordRuntimeBoot(observation: EvidenceRuntimeBoot): Promise<{ retired: number; more: boolean }> {
		return this.call("recordRuntimeBoot", [observation]);
	}
	observeRuntimeExit(proof: EvidenceReference, provider: EvidenceRuntimeProvider): Promise<EvidenceRuntimeExitResult> {
		return this.call("observeRuntimeExit", [proof, provider]);
	}
	readWindow(window: EvidenceWindow): Promise<EvidencePage> {
		return this.call("readWindow", [window]);
	}
	readOccurrences(options: { afterSequence?: number; limit?: number } = {}): Promise<EvidencePage> {
		return this.call("readOccurrences", [options]);
	}
	openIncident(incident: EvidenceIncidentInput): Promise<EvidenceIncident> {
		return this.call("openIncident", [incident]);
	}
	/** Reads the stored observation and atomically joins it to its durable channel episode. */
	observeKernelChannel(proof: EvidenceReference, incident: EvidenceIncidentInput): Promise<EvidenceChannelResult> {
		return this.call("observeKernelChannel", [proof, incident]);
	}
	getIncident(id: string): Promise<EvidenceIncident | undefined> {
		return this.call("getIncident", [id]);
	}
	/** Defaults to 32 metadata rows; limits above 64 are rejected. */
	listIncidents(options: EvidenceListOptions = {}): Promise<EvidenceIncident[]> {
		return this.call("listIncidents", [options]);
	}
	updateIncident(id: string, update: EvidenceIncidentUpdate): Promise<EvidenceIncident> {
		return this.call("updateIncident", [id, update]);
	}
	prepareOperation(operation: EvidenceOperationInput): Promise<EvidenceOperation> {
		return this.call("prepareOperation", [operation]);
	}
	unfinishedOperations(options: EvidenceListOptions = {}): Promise<EvidenceOperation[]> {
		return this.call("unfinishedOperations", [options]);
	}
	/** Call only after the complete staging stream, file fsync and directory fsync succeed. */
	markOperationStaged(id: string, completion: EvidenceArtifactCompletion): Promise<EvidenceOperation> {
		return this.call("markOperationStaged", [id, completion]);
	}
	reserveOperationBytes(id: string, bytes: number): Promise<EvidenceOperation> {
		return this.call("reserveOperationBytes", [id, bytes]);
	}
	/** Call only after an unstaged partial file is durably removed and its directory synced. */
	releaseOperationReservation(id: string): Promise<EvidenceOperation> {
		return this.call("releaseOperationReservation", [id]);
	}
	markOperationReady(id: string, completion?: EvidenceArtifactCompletion): Promise<EvidenceOperation> {
		return this.call("markOperationReady", [id, completion]);
	}
	/** Pins the next hash/length candidate, or records that the bounded cursor reached its end. */
	selectArtifactCandidate(id: string): Promise<EvidenceOperation> {
		return this.call("selectArtifactCandidate", [id]);
	}
	rejectArtifactCandidate(id: string, candidateId: string, limitation?: string): Promise<EvidenceOperation> {
		return this.call("rejectArtifactCandidate", [id, candidateId, limitation]);
	}
	/** Call after stable file validation and, for reuse, exact byte comparison. */
	selectArtifactContent(id: string, selection: EvidenceArtifactSelection): Promise<EvidenceOperation> {
		return this.call("selectArtifactContent", [id, selection]);
	}
	listArtifacts(incidentId: string): Promise<EvidenceArtifact[]> {
		return this.call("listArtifacts", [incidentId]);
	}
	retain(options: { nowMs: number; limit?: number }): Promise<EvidenceRetentionResult> {
		return this.call("retain", [options]);
	}
	stats(): Promise<EvidenceStoreStats> {
		return this.call("stats", []);
	}
	close(): Promise<void> {
		if (!this.closing)
			this.closing = (async () => {
				if (this.pending.size > 0)
					await new Promise<void>((resolve) => {
						this.resolveDrain = resolve;
					});
				await this.call<void>("close", []);
			})().finally(async () => {
				await this.worker.terminate();
			});
		return this.closing;
	}
}
