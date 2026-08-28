export const LITURGY_SKILL_NAME = "liturgy";
export const LITURGY_STATE_CUSTOM_TYPE = "liturgy_state";

export interface LiturgyState {
	schema_version: 1;
	revision: number;
	active: Record<string, unknown> | null;
	history: unknown[];
}

export function emptyLiturgyState(): LiturgyState {
	return { schema_version: 1, revision: 0, active: null, history: [] };
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const TASK_STATUSES = new Set(["pending", "in_progress", "blocked", "completed", "retired"]);

function isNullableString(value: unknown): value is string | null {
	return value === null || typeof value === "string";
}

function validateBoard(value: unknown): asserts value is Record<string, unknown> {
	if (!isJsonObject(value)) throw new Error("invalid Liturgy board");
	if (
		typeof value.id !== "string" ||
		!value.id ||
		typeof value.title !== "string" ||
		!value.title.trim() ||
		!isNullableString(value.goal_objective) ||
		typeof value.created_at !== "string" ||
		typeof value.updated_at !== "string" ||
		!Number.isSafeInteger(value.next_task_number) ||
		(value.next_task_number as number) < 1 ||
		!isNullableString(value.focused_task_id) ||
		typeof value.synthetic_default !== "boolean" ||
		!Array.isArray(value.phases) ||
		!Array.isArray(value.events)
	) {
		throw new Error("invalid Liturgy board");
	}

	const tasks = new Map<string, { parentId: string | null; phase: unknown; status: string }>();
	const phaseNames = new Set<string>();
	for (const phase of value.phases) {
		if (
			!isJsonObject(phase) ||
			typeof phase.name !== "string" ||
			!phase.name.trim() ||
			phaseNames.has(phase.name.toLocaleLowerCase()) ||
			!Array.isArray(phase.tasks)
		) {
			throw new Error("invalid Liturgy phase");
		}
		phaseNames.add(phase.name.toLocaleLowerCase());
		for (const task of phase.tasks) {
			if (
				!isJsonObject(task) ||
				typeof task.id !== "string" ||
				!task.id ||
				typeof task.text !== "string" ||
				!task.text.trim() ||
				!isNullableString(task.parent_id) ||
				typeof task.status !== "string" ||
				!TASK_STATUSES.has(task.status) ||
				!isNullableString(task.owner) ||
				!isNullableString(task.blocker) ||
				!isNullableString(task.result) ||
				!Array.isArray(task.evidence) ||
				task.evidence.some((entry) => typeof entry !== "string") ||
				typeof task.created_at !== "string" ||
				typeof task.updated_at !== "string" ||
				tasks.has(task.id)
			) {
				throw new Error("invalid Liturgy task");
			}
			tasks.set(task.id, { parentId: task.parent_id, phase, status: task.status });
		}
	}
	for (const [taskId, task] of tasks) {
		if (task.parentId === null) continue;
		const parent = tasks.get(task.parentId);
		if (!parent || task.parentId === taskId || parent.phase !== task.phase) {
			throw new Error("invalid Liturgy task parent");
		}
		const seen = new Set([taskId]);
		let cursor: string | null = task.parentId;
		while (cursor !== null) {
			if (seen.has(cursor)) throw new Error("invalid Liturgy task parent cycle");
			seen.add(cursor);
			cursor = tasks.get(cursor)?.parentId ?? null;
		}
	}
	if (value.focused_task_id !== null) {
		const focused = tasks.get(value.focused_task_id as string);
		if (!focused || !["pending", "in_progress"].includes(focused.status)) {
			throw new Error("invalid focused Liturgy task");
		}
	}
	for (const event of value.events) {
		if (
			!isJsonObject(event) ||
			typeof event.at !== "string" ||
			typeof event.action !== "string" ||
			(event.task !== undefined && typeof event.task !== "string") ||
			(event.from !== undefined && !isNullableString(event.from)) ||
			(event.to !== undefined && typeof event.to !== "string") ||
			(event.note !== undefined && typeof event.note !== "string")
		) {
			throw new Error("invalid Liturgy event");
		}
	}
}

export function parseLiturgyState(value: unknown): LiturgyState {
	if (!isJsonObject(value) || value.schema_version !== 1) {
		throw new Error("unsupported Liturgy state schema");
	}
	if (!Number.isSafeInteger(value.revision) || (value.revision as number) < 0) {
		throw new Error("invalid Liturgy state revision");
	}
	if (value.active !== null) validateBoard(value.active);
	if (!Array.isArray(value.history)) throw new Error("invalid Liturgy history");
	for (const board of value.history) validateBoard(board);
	return structuredClone(value) as unknown as LiturgyState;
}

export function loadLiturgyState(
	branch: readonly { type: string; customType?: string; data?: unknown }[],
): LiturgyState {
	for (let index = branch.length - 1; index >= 0; index--) {
		const entry = branch[index];
		if (entry.type === "custom" && entry.customType === LITURGY_STATE_CUSTOM_TYPE) {
			return parseLiturgyState(entry.data);
		}
	}
	return emptyLiturgyState();
}

export function commitLiturgyState(current: LiturgyState, expectedRevision: number, candidate: unknown): LiturgyState {
	if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
		throw new Error("liturgy.commit expected_revision must be a non-negative integer");
	}
	if (expectedRevision !== current.revision) {
		throw new Error(`stale Liturgy revision: expected ${expectedRevision}, current ${current.revision}`);
	}
	const parsed = parseLiturgyState(candidate);
	if (parsed.revision !== expectedRevision) {
		throw new Error("liturgy.commit candidate revision must equal expected_revision");
	}
	return { ...parsed, revision: expectedRevision + 1 };
}
