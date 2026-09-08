function bytes(value: unknown): boolean {
	return Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255);
}

/** Journal JSON fields are strings, null, byte arrays, or arrays of those values. */
function field(value: unknown): boolean {
	return (
		value === null ||
		typeof value === "string" ||
		bytes(value) ||
		(Array.isArray(value) && value.every((item) => item === null || typeof item === "string" || bytes(item)))
	);
}

/**
 * A provider replay identity, never a replacement for captured payload bytes.
 * journalctl may reorder fields when serializing the same native cursor.
 * Compare all fields; MESSAGE stays opaque and array ordering stays significant.
 * https://systemd.io/JOURNAL_EXPORT_FORMATS/
 */
export function journalReplayIdentity(raw: Uint8Array): {
	cursor: string;
	wallTimeMs: number;
	monotonicNs?: string;
	identity: string;
} {
	const entry: unknown = JSON.parse(Buffer.from(raw).toString("utf8"));
	if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("journal_metadata_unavailable");
	const row = entry as Record<string, unknown>;
	const { __CURSOR: cursor, __REALTIME_TIMESTAMP: wall, __MONOTONIC_TIMESTAMP: monotonic } = row;
	if (
		typeof cursor !== "string" ||
		!cursor ||
		typeof wall !== "string" ||
		!/^\d+$/.test(wall) ||
		(monotonic !== undefined && (typeof monotonic !== "string" || !/^\d+$/.test(monotonic))) ||
		!Object.values(row).every(field)
	)
		throw new Error("journal_metadata_unavailable");
	const wallTimeMs = Number(BigInt(wall) / 1000n);
	if (!Number.isSafeInteger(wallTimeMs)) throw new Error("journal_timestamp_unavailable");
	return {
		cursor,
		wallTimeMs,
		...(typeof monotonic === "string" ? { monotonicNs: String(BigInt(monotonic) * 1000n) } : {}),
		identity: JSON.stringify(
			Object.keys(row)
				.sort()
				.map((key) => [key, row[key]]),
		),
	};
}
