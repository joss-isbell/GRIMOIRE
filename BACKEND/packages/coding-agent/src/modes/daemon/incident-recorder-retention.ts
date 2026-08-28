import {
	closeSync,
	type Dir,
	constants as fsConstants,
	fstatSync,
	lstatSync,
	opendirSync,
	openSync,
	readSync,
	renameSync,
	rmSync,
} from "node:fs";
import { join } from "node:path";

export const INCIDENT_DIAGNOSTIC_RETENTION_MS = 3 * 24 * 60 * 60 * 1_000;
export const INCIDENT_RETENTION_SERVICE_BUDGET = { maxEntries: 64, maxDeletes: 16 } as const;
const ACTIVE_MARKER = ".recorder-active";
const TERMINAL_MARKER = ".retention-terminal.json";
const GC_PREFIX = ".retention-gc-";
const MAX_METADATA_BYTES = 256 * 1024;

export interface IncidentRetentionOptions {
	agentDir: string;
	nowMs?: number;
	maxEntries?: number;
	maxDeletes?: number;
	machineId?: string;
	bootId?: string;
	processIdentity?: (pid: number) => { state: "live"; startId: string } | { state: "dead" } | { state: "uncertain" };
}

export interface IncidentRetentionResult {
	scannedEntries: number;
	deletedEntries: number;
	moreWork: boolean;
	uncertainties: string[];
	protectedActiveRuns: string[];
	pendingIncident: boolean;
}

interface Cursor {
	directory: Dir;
	root: string;
}
const cursors = new Map<string, Cursor>();

function boundedJson(path: string): Record<string, unknown> | undefined {
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
		const before = fstatSync(descriptor, { bigint: true });
		if (!before.isFile() || before.size < 1n || before.size > BigInt(MAX_METADATA_BYTES)) return undefined;
		const bytes = Buffer.alloc(Number(before.size));
		let offset = 0;
		while (offset < bytes.length) {
			const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
			if (count <= 0) return undefined;
			offset += count;
		}
		const after = fstatSync(descriptor, { bigint: true });
		if (
			after.dev !== before.dev ||
			after.ino !== before.ino ||
			after.size !== before.size ||
			after.mtimeNs !== before.mtimeNs
		)
			return undefined;
		const parsed = JSON.parse(bytes.toString("utf8")) as unknown;
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

function causalCompletionMs(value: Record<string, unknown> | undefined): number | undefined {
	if (!value) return undefined;
	for (const candidate of [value.completed, value.finalized, value.created]) {
		if (typeof candidate === "string") {
			const parsed = Date.parse(candidate);
			if (Number.isFinite(parsed)) return parsed;
		}
		if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
			const wallTime = (candidate as Record<string, unknown>).wallTime;
			if (typeof wallTime === "string") {
				const parsed = Date.parse(wallTime);
				if (Number.isFinite(parsed)) return parsed;
			}
		}
	}
	return undefined;
}

function cursorFor(root: string): Cursor | undefined {
	const existing = cursors.get(root);
	if (existing) return existing;
	try {
		const cursor = { root, directory: opendirSync(root) };
		cursors.set(root, cursor);
		return cursor;
	} catch {
		return undefined;
	}
}

function closeCursor(root: string): void {
	const cursor = cursors.get(root);
	cursors.delete(root);
	try {
		cursor?.directory.closeSync();
	} catch {}
}

export function runIncidentRetentionPass(options: IncidentRetentionOptions): IncidentRetentionResult {
	const nowMs = options.nowMs ?? Date.now();
	const maxEntries = Math.max(1, Math.min(1024, options.maxEntries ?? INCIDENT_RETENTION_SERVICE_BUDGET.maxEntries));
	const maxDeletes = Math.max(0, Math.min(256, options.maxDeletes ?? INCIDENT_RETENTION_SERVICE_BUDGET.maxDeletes));
	const result: IncidentRetentionResult = {
		scannedEntries: 0,
		deletedEntries: 0,
		moreWork: false,
		uncertainties: [],
		protectedActiveRuns: [],
		pendingIncident: false,
	};
	const roots = [
		{ path: join(options.agentDir, "incident-recorder", "runs"), marker: TERMINAL_MARKER, active: true },
		{ path: join(options.agentDir, "incidents"), marker: "summary.json", active: false },
	];
	for (const root of roots) {
		if (result.scannedEntries >= maxEntries || result.deletedEntries >= maxDeletes) {
			result.moreWork = true;
			break;
		}
		const cursor = cursorFor(root.path);
		if (!cursor) continue;
		while (result.scannedEntries < maxEntries && result.deletedEntries < maxDeletes) {
			let entry: ReturnType<Dir["readSync"]> = null;
			try {
				entry = cursor.directory.readSync();
			} catch {
				entry = null;
			}
			if (!entry) {
				closeCursor(root.path);
				break;
			}
			result.scannedEntries += 1;
			if (!entry.isDirectory() || !/^[A-Za-z0-9_.+-]{1,200}$/.test(entry.name)) {
				result.uncertainties.push(`unsafe_retention_entry:${root.path}/${entry.name}`);
				continue;
			}
			const source = join(root.path, entry.name);
			if (entry.name.startsWith(GC_PREFIX)) {
				try {
					rmSync(source, { recursive: true, force: false, maxRetries: 0 });
					result.deletedEntries += 1;
				} catch {
					result.uncertainties.push(`retention_tombstone_delete_failed:${source}`);
				}
				continue;
			}
			const identity = (() => {
				try {
					const stat = lstatSync(source, { bigint: true });
					return stat.isDirectory() && !stat.isSymbolicLink() ? stat : undefined;
				} catch {
					return undefined;
				}
			})();
			if (!identity) {
				result.uncertainties.push(`retention_identity_unavailable:${source}`);
				continue;
			}
			if (root.active) {
				try {
					const marker = lstatSync(join(source, ACTIVE_MARKER));
					if (marker.isFile() && !marker.isSymbolicLink()) {
						result.protectedActiveRuns.push(source);
						continue;
					}
				} catch {}
			}
			const metadata = boundedJson(join(source, root.marker));
			const completedMs = causalCompletionMs(metadata);
			if (completedMs === undefined) {
				result.pendingIncident = true;
				continue;
			}
			if (completedMs > nowMs - INCIDENT_DIAGNOSTIC_RETENTION_MS) continue;
			const tombstone = join(root.path, `${GC_PREFIX}${entry.name}`);
			try {
				renameSync(source, tombstone);
				const moved = lstatSync(tombstone, { bigint: true });
				if (moved.dev !== identity.dev || moved.ino !== identity.ino || !moved.isDirectory()) {
					result.uncertainties.push(`retention_identity_changed:${tombstone}`);
					continue;
				}
				rmSync(tombstone, { recursive: true, force: false, maxRetries: 0 });
				result.deletedEntries += 1;
			} catch {
				result.uncertainties.push(`retention_delete_failed:${source}`);
			}
		}
	}
	if (result.scannedEntries >= maxEntries || result.deletedEntries >= maxDeletes) result.moreWork = true;
	return result;
}
