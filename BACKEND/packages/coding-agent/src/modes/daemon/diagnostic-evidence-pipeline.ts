import { createHash } from "node:crypto";
import type { DiagnosticEvidenceStore } from "./diagnostic-evidence-store.js";
import type {
	EvidenceIncident,
	EvidenceIncidentInput,
	EvidenceOccurrence,
	EvidenceRuntimeExitResult,
	EvidenceRuntimeProvider,
} from "./diagnostic-evidence-store-protocol.js";
import { kernelChannelObservation } from "./diagnostic-kernel-channel.js";
import {
	runtimeExitFromOccurrence,
	runtimeJournal,
	runtimeRoleFromOccurrence,
	validRuntimeClock,
} from "./diagnostic-runtime-identity.js";

export const DIAGNOSTIC_PRE_TRIGGER_MS = 30 * 60_000;
export const DIAGNOSTIC_POST_TRIGGER_MS = 15 * 60_000;
const DETECTOR_SOURCE = "internal:incident-detector-v1";
const GAP_SOURCE = "internal:detector-gaps";

function identity(...parts: string[]): string {
	return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

function record(value: unknown): Record<string, unknown> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function diagnostic(raw: Uint8Array): Record<string, unknown> | undefined {
	try {
		const entry = record(JSON.parse(Buffer.from(raw).toString("utf8")));
		if (typeof entry?.MESSAGE !== "string") return undefined;
		const event = record(JSON.parse(entry.MESSAGE));
		return event?.schema === "prime-agent.diagnostic.v1" &&
			event.type !== "native_process_exit" &&
			typeof event.event !== "string"
			? event
			: undefined;
	} catch {
		return undefined;
	}
}

function isIncidentTrigger(event: Record<string, unknown>): boolean {
	return (
		event.type === "native_process_exit" ||
		event.type === "kernel_unexpected_exit" ||
		event.type === "kernel_channel_fault" ||
		event.type === "fatal_exception" ||
		event.type === "unhandled_rejection" ||
		(event.type === "kernel_protocol_observation" && event.observation === "shell_reply_unavailable") ||
		(event.type === "worker_connection_closed" && event.status === "unexpected") ||
		(event.type === "worker_process_exit_observed" && event.status === "unexpected")
	);
}

/** One durable provider cursor and one durable consumer cursor; no filesystem index. */
export class DiagnosticEvidencePipeline {
	private publishing = false;
	constructor(
		private readonly store: DiagnosticEvidenceStore,
		private readonly causalProvider?: EvidenceRuntimeProvider,
	) {
		if (
			causalProvider !== undefined &&
			(!/^[A-Za-z0-9_.-]{1,64}$/.test(causalProvider.identifier) ||
				!validRuntimeClock(causalProvider.clockTicksPerSecond))
		)
			throw new Error("causal_identifier_invalid");
	}

	async ingestJournal(
		source: string,
		raw: Uint8Array,
	): Promise<{ journalObserved: true; durablyStored: true; cursor: string }> {
		return this.ingestJournalBatch(source, [raw]);
	}

	async ingestJournalBatch(
		source: string,
		records: Uint8Array[],
	): Promise<{ journalObserved: true; durablyStored: true; cursor: string }> {
		if (source.startsWith("internal:")) throw new Error("journal_source_reserved");
		if (
			!records.length ||
			records.length > 256 ||
			records.reduce((sum, raw) => sum + raw.byteLength, 0) > 1024 * 1024
		)
			throw new Error("journal_batch_bounds");
		const occurrences = records.map((raw) => this.journalOccurrence(source, raw));
		const cursor = occurrences.at(-1)!.cursor;
		const previous = await this.store.getCursor(source);
		await this.store.ingestJournal({
			batchId: identity(
				"journal-provider-replay-v1",
				source,
				previous ?? "",
				...occurrences.map((entry) => entry.cursor),
			),
			source,
			expectedCursor: previous,
			cursor,
			occurrences: occurrences.map(({ cursor: _cursor, ...entry }) => entry),
		});
		return { journalObserved: true, durablyStored: true, cursor };
	}

	private journalOccurrence(source: string, raw: Uint8Array) {
		const entry = record(JSON.parse(Buffer.from(raw).toString("utf8")));
		const cursor = entry?.__CURSOR;
		const wall = entry?.__REALTIME_TIMESTAMP;
		const monotonic = entry?.__MONOTONIC_TIMESTAMP;
		if (
			typeof cursor !== "string" ||
			!cursor ||
			typeof wall !== "string" ||
			!/^\d+$/.test(wall) ||
			(typeof monotonic !== "undefined" && (typeof monotonic !== "string" || !/^\d+$/.test(monotonic)))
		)
			throw new Error("journal_metadata_unavailable");
		const wallTimeMs = Number(BigInt(wall) / 1000n);
		if (!Number.isSafeInteger(wallTimeMs)) throw new Error("journal_timestamp_unavailable");
		return {
			cursor,
			id: identity(source, cursor),
			wallTimeMs,
			kind: "journal.json",
			payload: raw,
			...(typeof monotonic === "string" ? { monotonicNs: String(BigInt(monotonic) * 1000n) } : {}),
		};
	}

	/** May run after a crash: provider commit never implies the trigger was published. */
	async publishPending(limit = 128): Promise<number> {
		if (this.publishing) throw new Error("incident_detector_busy");
		this.publishing = true;
		try {
			const cursor = await this.store.getCursor(DETECTOR_SOURCE);
			const page = await this.store.readOccurrences({
				afterSequence: cursor === null ? undefined : Number(cursor),
				limit,
			});
			if (page.missingRanges?.length) {
				const id = identity("detector-gap-v1", JSON.stringify(page.missingRanges));
				if (!(await this.store.getOccurrence(GAP_SOURCE, id))) {
					const previous = await this.store.getCursor(GAP_SOURCE);
					await this.store.ingest({
						batchId: identity(GAP_SOURCE, previous ?? "", id),
						source: GAP_SOURCE,
						expectedCursor: previous,
						cursor: id,
						occurrences: [
							{
								id,
								wallTimeMs: Date.now(),
								kind: "evidence.gap",
								payload: Buffer.from(
									JSON.stringify({
										reason: "occurrences_unavailable",
										missingRanges: page.missingRanges,
										cause: "unknown",
										limitation:
											"Missing sequence identities do not establish missing payload contents or a wall-time interval.",
									}),
								),
							},
						],
					});
				}
			}
			let published = 0;
			// Register sparse anchors before exits in the same bounded page. Cross-page
			// late anchors remain an explicit scope limitation, never an inferred role.
			if (this.causalProvider)
				for (const occurrence of page.occurrences) {
					if (runtimeRoleFromOccurrence(occurrence, this.causalProvider.clockTicksPerSecond) === undefined)
						continue;
					const result = await this.store.rememberRuntimeRole(
						{ source: occurrence.source, occurrenceId: occurrence.id },
						this.causalProvider.clockTicksPerSecond,
					);
					if (!["registered", "replayed", "not_anchor"].includes(result.status))
						await this.recordRuntimeLimitation(occurrence, `runtime_role_${result.status}`, true);
				}
			for (const occurrence of page.occurrences) {
				if (this.causalProvider) {
					const exit = runtimeExitFromOccurrence(occurrence, this.causalProvider);
					if (exit) {
						const result = await this.store.observeRuntimeExit(
							{ source: occurrence.source, occurrenceId: occurrence.id },
							this.causalProvider,
						);
						if (result.status === "matched" && result.rawExitCode > 0) {
							await this.publishOccurrence(occurrence, { type: "native_process_exit" }, result.runtimeRole);
							published++;
						} else if (result.status === "invalid_exit" || result.status === "conflict")
							await this.recordRuntimeLimitation(occurrence, `runtime_role_${result.status}`, true);
						else if (result.status === "unregistered" && !exit.invalid && exit.rawExitCode > 0)
							await this.recordRuntimeLimitation(occurrence, "runtime_role_unobserved", false);
						continue;
					}
				}
				const event = occurrence.kind === "journal.json" ? diagnostic(occurrence.payload) : undefined;
				if (event && kernelChannelObservation(occurrence)) {
					const result = await this.store.observeKernelChannel(
						{ source: occurrence.source, occurrenceId: occurrence.id },
						this.incidentInput(occurrence, event),
					);
					if (result.status === "incident") {
						if (result.incident.state === "capturing") {
							await this.finishPublication(result.incident);
							published++;
						}
					} else if (result.status !== "ignored") await this.recordChannelGap(occurrence, result.status);
					continue;
				}
				if (event && isIncidentTrigger(event)) {
					await this.publishOccurrence(occurrence, event);
					published += 1;
				}
			}
			const throughSequence = page.throughSequence ?? page.occurrences.at(-1)?.sequence ?? 0;
			if (throughSequence > Number(cursor ?? 0)) {
				const next = String(throughSequence);
				await this.store.ingest({
					batchId: identity(DETECTOR_SOURCE, cursor ?? "", next),
					source: DETECTOR_SOURCE,
					expectedCursor: cursor,
					cursor: next,
					occurrences: [],
				});
			}
			return published;
		} finally {
			this.publishing = false;
		}
	}
	private async recordChannelGap(occurrence: EvidenceOccurrence, reason: string): Promise<void> {
		const id = identity("kernel-channel-gap-v1", occurrence.source, occurrence.id);
		if (await this.store.getOccurrence(GAP_SOURCE, id)) return;
		const previous = await this.store.getCursor(GAP_SOURCE);
		await this.store.ingest({
			batchId: identity(GAP_SOURCE, previous ?? "", id),
			source: GAP_SOURCE,
			expectedCursor: previous,
			cursor: id,
			occurrences: [
				{
					id,
					wallTimeMs: occurrence.wallTimeMs,
					kind: "diagnostic.gap",
					payload: Buffer.from(
						JSON.stringify({
							reason: `kernel_channel_${reason}`,
							observation: { source: occurrence.source, occurrenceId: occurrence.id },
							limitation:
								"Channel observation retained, but a bounded exact kernel episode could not be established. No kernel death or recovery is inferred.",
						}),
					),
				},
			],
		});
	}

	private async recordRuntimeLimitation(
		occurrence: EvidenceOccurrence,
		reason: string,
		causalGap: boolean,
	): Promise<void> {
		const rawBootId = runtimeJournal(occurrence)?.row._BOOT_ID;
		const bootId = typeof rawBootId === "string" && Buffer.byteLength(rawBootId) <= 128 ? rawBootId : undefined;
		// Scope receipts are once per boot; ordinary child failures do not create
		// incidents or blanket causal gaps. Raw exits retain every occurrence.
		const id = identity(
			"runtime-role-limitation-v1",
			typeof bootId === "string" ? bootId : "unknown",
			reason,
			...(causalGap ? [occurrence.source, occurrence.id] : []),
		);
		if (await this.store.getOccurrence(GAP_SOURCE, id)) return;
		const previous = await this.store.getCursor(GAP_SOURCE);
		await this.store.ingest({
			batchId: identity(GAP_SOURCE, previous ?? "", id),
			source: GAP_SOURCE,
			expectedCursor: previous,
			cursor: id,
			occurrences: [
				{
					id,
					wallTimeMs: occurrence.wallTimeMs,
					kind: causalGap ? "diagnostic.gap" : "runtime.scope",
					payload: Buffer.from(
						JSON.stringify({
							reason,
							bootId,
							firstObserved: { source: occurrence.source, occurrenceId: occurrence.id },
							limitation: causalGap
								? "Runtime role evidence could not be admitted or matched; no role is inferred."
								: "Exits without an observed runtime role remain raw evidence and are not promoted to incidents. This includes ordinary descendants and may include a runtime whose role anchor was missing or arrived after its exit.",
						}),
					),
				},
			],
		});
	}

	private async publishOccurrence(
		occurrence: EvidenceOccurrence,
		event: Record<string, unknown>,
		runtimeRole?: Extract<EvidenceRuntimeExitResult, { status: "matched" }>["runtimeRole"],
	): Promise<void> {
		const input = this.incidentInput(occurrence, event, runtimeRole);
		const id = input.id;
		let incident = await this.store.getIncident(id);
		if (!incident) {
			await this.store.openIncident(input);
			incident = await this.store.getIncident(id);
		}
		if (!incident) throw new Error("incident_not_stored");
		await this.finishPublication(incident);
	}
	private incidentInput(
		occurrence: EvidenceOccurrence,
		event: Record<string, unknown>,
		runtimeRole?: Extract<EvidenceRuntimeExitResult, { status: "matched" }>["runtimeRole"],
	): EvidenceIncidentInput {
		return {
			id: identity("incident-v1", occurrence.source, occurrence.id),
			triggerTimeMs: occurrence.wallTimeMs,
			windowStartMs: occurrence.wallTimeMs - DIAGNOSTIC_PRE_TRIGGER_MS,
			windowEndMs: occurrence.wallTimeMs + DIAGNOSTIC_POST_TRIGGER_MS,
			coverage: {
				trigger: { source: occurrence.source, occurrenceId: occurrence.id, type: event.type },
				...(runtimeRole ? { runtimeRole } : {}),
				durableTriggerObserved: true,
				exportComplete: false,
				cause: { status: "unresolved" },
			},
			limitations: [
				"Provider continuity has not been established; only observed evidence is claimed.",
				"The post-trigger window is still being captured.",
				"The native journal export is pending.",
				...(kernelChannelObservation(occurrence)
					? [
							"Channel unavailability is an observation, not proof of process death. Later channel success does not establish that its cause was fixed.",
						]
					: []),
			],
		};
	}
	private async finishPublication(incident: EvidenceIncident): Promise<void> {
		await this.prepareJournalExport(incident, "initial");
		if (incident.state === "capturing") await this.store.updateIncident(incident.id, { state: "published" });
	}

	async prepareJournalExport(incident: EvidenceIncident, phase: "initial" | "final"): Promise<void> {
		const id = identity(incident.id, "journal", phase);
		await this.store.prepareOperation({
			id,
			incidentId: incident.id,
			kind: "export",
			artifact: { id, path: `${incident.id}-${phase}.journal`, format: "journal.export" },
		});
	}
}
