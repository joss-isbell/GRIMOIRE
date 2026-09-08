import { createHash } from "node:crypto";
import {
	type CausalClassification,
	type CausalOccurrence,
	type CausalTarget,
	classifyCausalCapture,
} from "./diagnostic-causal-classifier.js";
import { loadCausalPlatform } from "./diagnostic-causal-platform.js";
import type { DiagnosticEvidenceStore } from "./diagnostic-evidence-store.js";
import type { EvidenceIncident, EvidenceOccurrence } from "./diagnostic-evidence-store-protocol.js";
import { runtimeExitFromOccurrence } from "./diagnostic-runtime-identity.js";

export interface DiagnosticCausalProvider {
	identifier: string;
	/** Verified with the Linux runtime's getconf CLK_TCK during configuration. */
	clockTicksPerSecond: number;
}
export const INCIDENT_ANALYSIS_SOURCE = "internal:incident-analysis-v1";
const MAX_SCAN_ROWS = 4096;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;

function record(value: unknown): Record<string, unknown> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}
function boundedIdentity(value: unknown, maxBytes: number): string | undefined {
	return typeof value === "string" && value.length > 0 && Buffer.byteLength(value) <= maxBytes ? value : undefined;
}
function nativeDecimal(value: unknown): bigint | undefined {
	return typeof value === "string" && /^(0|[1-9]\d{0,19})$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n
		? BigInt(value)
		: undefined;
}
function verifiedProvider(row: Record<string, unknown> | undefined, provider?: DiagnosticCausalProvider): boolean {
	return (
		!!provider &&
		row?.SYSLOG_IDENTIFIER === provider.identifier &&
		row._UID === "0" &&
		row._EXE === "/usr/bin/bpftrace"
	);
}
function journal(occurrence: EvidenceOccurrence): Record<string, unknown> | undefined {
	if (occurrence.kind !== "journal.json") return undefined;
	try {
		return record(JSON.parse(Buffer.from(occurrence.payload).toString("utf8")));
	} catch {
		return undefined;
	}
}
function message(row: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
	try {
		return typeof row?.MESSAGE === "string" ? record(JSON.parse(row.MESSAGE)) : undefined;
	} catch {
		return undefined;
	}
}

/** Bounded analysis of stored evidence; raw provider history remains independently exportable. */
export async function analyzeStoredIncident(
	store: DiagnosticEvidenceStore,
	incident: EvidenceIncident,
	provider?: DiagnosticCausalProvider,
): Promise<{
	analysisOccurrenceId: string;
	classification: Omit<CausalClassification, "facts">;
	traceRecords: number;
	scannedRows: number;
	truncated: boolean;
}> {
	const triggerReference = record(incident.coverage.trigger);
	const trigger =
		typeof triggerReference?.source === "string" && typeof triggerReference.occurrenceId === "string"
			? await store.getOccurrence(triggerReference.source, triggerReference.occurrenceId)
			: undefined;
	const triggerRow = trigger ? journal(trigger) : undefined;
	const event = message(triggerRow);
	const kernelInstanceId = boundedIdentity(event?.kernelInstanceId, 128);
	const kernel = kernelInstanceId !== undefined;
	const nativeExit =
		verifiedProvider(triggerRow, provider) && event?.event === "process_exit" && event.group_dead === 1;
	const workerExit = event?.type === "worker_process_exit_observed";
	const producerFailure = event?.type === "fatal_exception" || event?.type === "unhandled_rejection";
	const directProducer =
		typeof event?.ownerPid === "number" &&
		event.ownerPid === event.producerPid &&
		typeof event.ownerProcessStartId === "string" &&
		event.ownerProcessStartId.replace(/^proc:/, "") === event.producerStartId;
	const directObserver = directProducer || workerExit || producerFailure;
	const observerNamespace = event?.observerPidNamespace ?? (directObserver ? event?.producerPidNamespace : undefined);
	const observerOffset =
		event?.observerBoottimeOffsetNs ?? (directObserver ? event?.producerBoottimeOffsetNs : undefined);
	const processPid = workerExit ? event?.workerPid : producerFailure ? event?.producerPid : event?.kernelPid;
	const processStart = workerExit
		? event?.workerProcessStartId
		: producerFailure
			? event?.producerStartId
			: event?.kernelProcessStartId;
	const target: CausalTarget = {
		bootId: boundedIdentity(triggerRow?._BOOT_ID, 128) ?? "",
		kernelInstanceId,
		kernelGeneration: typeof event?.kernelGeneration === "number" ? event.kernelGeneration : undefined,
		pid: typeof processPid === "number" ? processPid : undefined,
		pidNamespace: boundedIdentity(observerNamespace, 64),
		processStartTicks: boundedIdentity(processStart, 32),
	};
	const nativeIdentities: Record<string, unknown>[] = [];
	const occurrences: CausalOccurrence[] = [];
	const omissions = new Set<string>();
	let scannedRows = 0;
	let scannedBytes = 0;
	let traceRecords = 0;
	let afterSequence: number | undefined;
	let truncated = false;
	let triggerIncluded = false;
	for (;;) {
		const page = await store.readWindow({
			startMs: incident.windowStartMs,
			endMs: incident.windowEndMs,
			causalOnly: true,
			afterSequence,
			limit: Math.min(512, MAX_SCAN_ROWS - scannedRows),
		});
		for (const occurrence of page.occurrences) {
			scannedRows++;
			scannedBytes += occurrence.payload.byteLength;
			if (scannedBytes > MAX_SCAN_BYTES) {
				truncated = true;
				break;
			}
			if (["diagnostic.gap", "evidence.gap"].includes(occurrence.kind)) {
				omissions.add("stored_provider_gap");
				continue;
			}
			const row = journal(occurrence);
			if (!row) continue;
			const data = message(row);
			if (provider && row.SYSLOG_IDENTIFIER === provider.identifier) {
				// These trusted journal fields identify the native provider, rather
				// than accepting an application-printed JSON object as a kernel trace.
				if (row._UID !== "0" || row._EXE !== "/usr/bin/bpftrace") {
					omissions.add("causal_provider_identity_unverified");
					continue;
				}
				traceRecords++;
				if (data?.event === "task_identity" && row._BOOT_ID === target.bootId) nativeIdentities.push(data);
				if (!data || typeof data.event !== "string") omissions.add("causal_provider_unparsed_output");
			} else if (data?.schema !== "prime-agent.diagnostic.v1") {
				// Ordinary product logs are retained, but are not protocol events.
				continue;
			} else if (typeof data.event === "string" || typeof data.type !== "string") {
				omissions.add("application_causal_shape_invalid");
				continue;
			}
			occurrences.push({ id: occurrence.id, source: "journal", payload: occurrence.payload });
			if (trigger?.id === occurrence.id && trigger.source === occurrence.source) triggerIncluded = true;
		}
		if (truncated || (scannedRows === MAX_SCAN_ROWS && page.nextSequence !== undefined)) {
			truncated = true;
			break;
		}
		if (page.nextSequence === undefined) break;
		afterSequence = page.nextSequence;
	}
	if (trigger && !triggerIncluded) occurrences.push({ id: trigger.id, source: "journal", payload: trigger.payload });
	if (truncated) omissions.add("stored_analysis_scan_limit");
	if (!trigger || !event) omissions.add("stored_trigger_unavailable");
	if (nativeExit) {
		const direct = trigger && provider ? runtimeExitFromOccurrence(trigger, provider) : undefined;
		const directFieldsPresent = ["process_start_boottime_ns", "subject_pid", "pidns_inode"].some(
			(field) => event?.[field] !== undefined,
		);
		const exitTime = nativeDecimal(event?.time_ns);
		const start = nativeDecimal(event?.start_boottime_ns);
		const candidates = new Set<string>();
		if (
			Number.isSafeInteger(event?.init_pid) &&
			Number(event?.init_pid) > 0 &&
			start !== undefined &&
			start > 0n &&
			exitTime !== undefined &&
			start <= exitTime
		) {
			if (event?.init_tid === event?.init_pid) candidates.add(String(start));
			else
				for (const identity of nativeIdentities) {
					const identityTime = nativeDecimal(identity.time_ns);
					const leaderStart = nativeDecimal(identity.process_start_boottime_ns);
					if (
						identity.init_pid === event?.init_pid &&
						identity.init_tid === event?.init_tid &&
						identity.start_boottime_ns === event?.start_boottime_ns &&
						identityTime !== undefined &&
						identityTime <= exitTime &&
						leaderStart !== undefined &&
						leaderStart > 0n &&
						leaderStart <= identityTime
					)
						candidates.add(String(leaderStart));
				}
		}
		if (direct && !direct.invalid) {
			target.initPid = direct.initPid;
			target.processStartBoottimeNs = direct.processStartBoottimeNs;
		} else if (!directFieldsPresent && candidates.size === 1) {
			target.initPid = Number(event?.init_pid);
			target.processStartBoottimeNs = [...candidates][0];
		} else omissions.add("native_target_generation_unavailable");
	} else {
		if (!kernel && !workerExit && !producerFailure) omissions.add("stored_target_kernel_identity_unavailable");
		if (typeof observerNamespace !== "string") omissions.add("original_observer_identity_unavailable");
	}
	const result = classifyCausalCapture({
		target,
		occurrences,
		platform:
			provider && (typeof observerOffset === "string" || nativeExit)
				? {
						...(await loadCausalPlatform(store, target.bootId)),
						bootId: target.bootId,
						clockTicksPerSecond: provider.clockTicksPerSecond,
						procReaderBoottimeOffsetNs: nativeExit
							? "unneeded_for_native_identity"
							: typeof observerOffset === "string"
								? observerOffset
								: "unverified",
					}
				: undefined,
	});
	if (omissions.size) {
		result.cause = "unresolved";
		delete result.initiator;
		result.missingEvidence = [...new Set([...result.missingEvidence, ...omissions])];
	}
	const captured = {
		incidentId: incident.id,
		target,
		window: { startMs: incident.windowStartMs, endMs: incident.windowEndMs },
		scannedRows,
		scannedBytes,
		traceRecords,
		truncated,
		classification: result,
	};
	let payload = Buffer.from(JSON.stringify(captured));
	if (payload.byteLength > 256 * 1024) {
		result.cause = "unresolved";
		delete result.initiator;
		result.facts = [];
		result.missingEvidence.push("stored_analysis_output_limit");
		payload = Buffer.from(JSON.stringify(captured));
	}
	if (payload.byteLength > 256 * 1024) {
		result.supportingOccurrenceIds = [];
		payload = Buffer.from(JSON.stringify(captured));
	}
	if (payload.byteLength > 256 * 1024) throw new Error("stored_analysis_output_bounds");
	const id = createHash("sha256").update(payload).digest("hex");
	if (!(await store.getOccurrence(INCIDENT_ANALYSIS_SOURCE, id))) {
		const cursor = await store.getCursor(INCIDENT_ANALYSIS_SOURCE);
		await store.ingest({
			batchId: id,
			source: INCIDENT_ANALYSIS_SOURCE,
			expectedCursor: cursor,
			cursor: id,
			occurrences: [{ id, kind: "incident.analysis", wallTimeMs: incident.triggerTimeMs, payload }],
		});
	}
	const { facts: _facts, ...classification } = result;
	return { analysisOccurrenceId: id, classification, traceRecords, scannedRows, truncated };
}
