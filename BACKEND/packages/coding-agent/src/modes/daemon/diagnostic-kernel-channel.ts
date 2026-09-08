import { createHash } from "node:crypto";
import type { EvidenceOccurrence } from "./diagnostic-evidence-store-protocol.js";

function record(value: unknown): Record<string, unknown> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}
function bounded(value: unknown, pattern?: RegExp): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		Buffer.byteLength(value) <= 256 &&
		!value.includes("\0") &&
		(!pattern || pattern.test(value))
	);
}
function pid(value: unknown): boolean {
	return Number.isSafeInteger(value) && Number(value) > 0;
}
function sourceTime(event: Record<string, unknown>): unknown {
	if (event.details === undefined) return event.monotonicNs;
	const value = record(record(event.details)?.value);
	if (value?.$diagnosticType !== "object" || !Array.isArray(value.properties) || value.properties.length > 128)
		return undefined;
	const times = value.properties.filter(
		(property: unknown) => Array.isArray(property) && property.length === 2 && property[0] === "monotonicNs",
	);
	return times.length === 1 ? times[0][1] : undefined;
}

/** Only explicit channel observations participate; elapsed execution time never does. */
export function kernelChannelObservation(occurrence: EvidenceOccurrence):
	| {
			available: boolean;
			identity?: { key: string; bootId: string; channel: string; monotonicNs: string };
	  }
	| undefined {
	if (occurrence.kind !== "journal.json") return undefined;
	try {
		const row = record(JSON.parse(Buffer.from(occurrence.payload).toString("utf8")));
		if (typeof row?.MESSAGE !== "string") return undefined;
		const event = record(JSON.parse(row.MESSAGE));
		if (event?.schema !== "prime-agent.diagnostic.v1" || typeof event.event === "string") return undefined;
		let channel: string;
		let available = false;
		if (event.type === "kernel_channel_fault") {
			if (!["shell", "control", "iopub"].includes(String(event.channel))) return { available: false };
			channel = String(event.channel);
		} else if (
			event.type === "kernel_protocol_observation" &&
			["heartbeat_unavailable", "heartbeat_echo"].includes(String(event.observation))
		) {
			channel = "heartbeat";
			available = event.observation === "heartbeat_echo";
		} else if (
			event.type === "kernel_protocol_observation" &&
			["shell_unavailable", "shell_reply"].includes(String(event.observation))
		) {
			channel = "shell";
			available = event.observation === "shell_reply";
		} else return undefined;
		const monotonicNs = sourceTime(event);
		if (
			!bounded(row._BOOT_ID) ||
			!bounded(event.kernelInstanceId) ||
			!pid(event.kernelPid) ||
			!bounded(event.kernelProcessStartId, /^(?:proc:)?\d{1,20}$/) ||
			!Number.isSafeInteger(event.kernelGeneration) ||
			Number(event.kernelGeneration) < 0 ||
			!pid(event.observerPid) ||
			!bounded(event.observerProcessStartId, /^\d{1,20}$/) ||
			!bounded(event.observerPidNamespace, /^pid:\[\d{1,20}\]$/) ||
			!bounded(event.observerBoottimeOffsetNs, /^-?\d{1,20}$/) ||
			!bounded(monotonicNs, /^\d{1,20}$/)
		)
			return { available };
		const key = createHash("sha256")
			.update(
				JSON.stringify([
					row._BOOT_ID,
					event.kernelInstanceId,
					event.kernelPid,
					String(BigInt(event.kernelProcessStartId.replace(/^proc:/, ""))),
					event.kernelGeneration,
					event.observerPid,
					event.observerProcessStartId,
					event.observerPidNamespace,
					String(BigInt(event.observerBoottimeOffsetNs)),
					channel,
				]),
			)
			.digest("hex");
		return { available, identity: { key, bootId: row._BOOT_ID, channel, monotonicNs } };
	} catch {
		return undefined;
	}
}
