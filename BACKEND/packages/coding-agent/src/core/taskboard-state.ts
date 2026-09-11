import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { SessionEntry, SessionManager } from "./session-manager.js";

export const TASKBOARD_SNAPSHOT_DETAILS_KEY = "prime.taskboard.snapshot";
export const TASKBOARD_BASELINE_CUSTOM_TYPE = "prime.taskboard.baseline";

export interface TaskboardSnapshot {
	version: 1;
	encoding: "base64";
	content: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateSnapshot(value: unknown, entryId: string): TaskboardSnapshot {
	if (
		!isRecord(value) ||
		value.version !== 1 ||
		value.encoding !== "base64" ||
		(value.content !== null &&
			(typeof value.content !== "string" ||
				Buffer.from(value.content, "base64").toString("base64") !== value.content))
	) {
		throw new Error(`Invalid taskboard snapshot in session entry ${entryId}; taskboard was not changed`);
	}
	return { version: 1, encoding: "base64", content: value.content as string | null };
}

function hasEntrySnapshot(entry: SessionEntry): boolean {
	return (
		(entry.type === "custom" && entry.customType === TASKBOARD_BASELINE_CUSTOM_TYPE) ||
		(entry.type === "message" &&
			entry.message.role === "toolResult" &&
			entry.message.toolName === "ipython" &&
			isRecord(entry.message.details) &&
			Object.hasOwn(entry.message.details, TASKBOARD_SNAPSHOT_DETAILS_KEY))
	);
}

function entrySnapshot(entry: SessionEntry): TaskboardSnapshot | undefined {
	if (entry.type === "custom" && entry.customType === TASKBOARD_BASELINE_CUSTOM_TYPE) {
		return validateSnapshot(entry.data, entry.id);
	}
	if (entry.type === "message" && entry.message.role === "toolResult" && entry.message.toolName === "ipython") {
		const details = entry.message.details;
		if (isRecord(details) && Object.hasOwn(details, TASKBOARD_SNAPSHOT_DETAILS_KEY)) {
			return validateSnapshot(details[TASKBOARD_SNAPSHOT_DETAILS_KEY], entry.id);
		}
	}
	return undefined;
}

export function withTaskboardSnapshot(details: unknown, snapshot: TaskboardSnapshot): Record<string, unknown> {
	return {
		...(isRecord(details) ? details : details === undefined ? {} : { "prime.taskboard.toolDetails": details }),
		[TASKBOARD_SNAPSHOT_DETAILS_KEY]: { ...snapshot },
	};
}

/** Tracks only the standard taskboard file, not kernel variables or other artifacts. */
export class TaskboardState {
	private lastCaptured: string | null | undefined = null;
	private readonly pendingToolSnapshots = new Map<string, TaskboardSnapshot>();

	constructor(
		private readonly sessionManager: SessionManager,
		private readonly artifactDir: () => string | undefined,
	) {}

	initialize(): void {
		// Any checkpoint suppresses legacy re-import. Only selected ancestry governs this projection.
		const tracked = this.sessionManager.getEntries().some(hasEntrySnapshot);
		const path = this.path();
		if (!path) return; // In-memory viewers must not acquire writable artifact directories.
		if (tracked) {
			this.restoreBranch(this.sessionManager.getLeafId());
			return;
		}

		const content = this.read(path);
		if (content !== null) {
			// This is a baseline at the original startup tip, not recovered historical state.
			// The rollback append also flushes before we trust it or touch the source file.
			this.sessionManager.appendCustomEntryWithRollback(TASKBOARD_BASELINE_CUSTOM_TYPE, {
				version: 1,
				encoding: "base64",
				content,
			} satisfies TaskboardSnapshot);
		}
		this.lastCaptured = content;
	}

	/** Synchronous and detached: call at sequential ipython finalization before awaiting hooks. */
	capture(toolCallId?: string): TaskboardSnapshot | undefined {
		const path = this.path();
		if (!path) return undefined;
		const content = this.read(path);
		if (content === this.lastCaptured) return undefined;
		this.lastCaptured = content;
		const snapshot: TaskboardSnapshot = { version: 1, encoding: "base64", content };
		if (toolCallId) this.pendingToolSnapshots.set(toolCallId, snapshot);
		return snapshot;
	}

	toolResultDetails(toolCallId: string, details: unknown): unknown {
		const snapshot = this.pendingToolSnapshots.get(toolCallId);
		return snapshot ? withTaskboardSnapshot(details, snapshot) : details;
	}

	finishToolResult(toolCallId: string, persisted: boolean): void {
		if (!this.pendingToolSnapshots.delete(toolCallId)) return;
		// An observation is not a durable checkpoint. Retry even unchanged bytes after a dropped/failed append.
		if (!persisted) this.lastCaptured = undefined;
	}

	/** Project selected ancestry before its transcript commit; return an exact rollback. */
	restoreBranch(leafId: string | null): () => void {
		const path = this.path();
		if (!path) return () => {};
		let content: string | null = null;
		// getBranch walks full ancestry, including entries hidden by compaction.
		for (const entry of leafId === null ? [] : this.sessionManager.getBranch(leafId)) {
			const snapshot = entrySnapshot(entry);
			if (snapshot) content = snapshot.content;
		}
		const previousContent = this.read(path);
		const previousCaptured = this.lastCaptured;
		this.write(path, content, previousContent);
		this.lastCaptured = content;
		return () => {
			this.write(path, previousContent, this.read(path));
			this.lastCaptured = previousCaptured;
		};
	}

	private path(): string | undefined {
		const directory = this.artifactDir();
		return directory ? join(directory, "taskboard.json") : undefined;
	}

	private read(path: string): string | null {
		try {
			return readFileSync(path).toString("base64");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
			throw new Error(`Cannot read taskboard state at ${path}`, { cause: error });
		}
	}

	private write(path: string, content: string | null, previous: string | null): void {
		if (content === previous) return;
		try {
			if (content === null) {
				try {
					unlinkSync(path);
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
				}
				return;
			}
			mkdirSync(dirname(path), { recursive: true });
			const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
			try {
				writeFileSync(temporary, Buffer.from(content, "base64"), { flag: "wx", mode: 0o600 });
				renameSync(temporary, path);
			} finally {
				rmSync(temporary, { force: true });
			}
		} catch (error) {
			throw new Error(`Cannot restore taskboard state at ${path}; session branch was not switched`, {
				cause: error,
			});
		}
	}
}
