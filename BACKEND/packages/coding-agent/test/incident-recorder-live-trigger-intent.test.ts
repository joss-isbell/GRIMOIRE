import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	acquireIncidentCasTransactionDetailed,
	type IncidentCasRootMutation,
} from "../src/modes/daemon/incident-recorder-cas-transaction.js";
import type {
	IncidentRecorderLiveRunEventsCursor,
	IncidentRecorderRunHistoryEvent,
	IncidentRecorderStorageAccountingEffect,
} from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	extractIncidentRecorderLiveTriggerIntentCandidate,
	type IncidentRecorderLiveTriggerIntentContext,
	incidentRecorderLiveTriggerIntentFileName,
	persistIncidentRecorderLiveTriggerIntentWithinRoot,
} from "../src/modes/daemon/incident-recorder-live-trigger-intent.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const TARGET_PROCESS_START_ID = "proc:9876";
const roots: string[] = [];

afterEach(() => {
	for (const root of roots.splice(0).reverse()) rmSync(root, { recursive: true, force: true });
});

function fixture(): { base: string; recorder: string; run: string } {
	const base = mkdtempSync(join(tmpdir(), "grimoire-live-trigger-intent-"));
	const recorder = join(base, "recorder");
	const run = join(recorder, "run");
	mkdirSync(run, { recursive: true, mode: 0o700 });
	roots.push(base);
	return { base, recorder, run };
}

function withRunRoot<T>(value: ReturnType<typeof fixture>, operation: (root: IncidentCasRootMutation) => T): T {
	const admission = acquireIncidentCasTransactionDetailed(value.recorder);
	expect(admission).toMatchObject({ state: "acquired" });
	if (admission.state !== "acquired") throw new Error(`CAS admission failed: ${admission.reason}`);
	try {
		const result = admission.transaction.withRoot((root) => root.withDirectory(root.relative("run"), operation));
		expect(result).toMatchObject({ state: "committed" });
		if (result.state !== "committed") throw new Error("CAS root detached during fixture operation");
		return result.value;
	} finally {
		expect(admission.transaction.release()).toMatchObject({ state: "released" });
	}
}

function event(
	type: "worker_request_end" | "kernel_unexpected_exit" | "ordinary_event",
	overrides: Partial<IncidentRecorderRunHistoryEvent> = {},
): IncidentRecorderRunHistoryEvent {
	const occurrenceId =
		type === "ordinary_event"
			? "66666666-6666-4666-8666-666666666666"
			: type === "worker_request_end"
				? "44444444-4444-4444-8444-444444444444"
				: "55555555-5555-4555-8555-555555555555";
	const identity = { runId: RUN_ID, runToken: RUN_TOKEN, producerId: PRODUCER_ID, occurrenceId };
	const identityKey = createHash("sha256")
		.update(`${identity.runId}\0${identity.runToken}\0${identity.producerId}\0${identity.occurrenceId}`)
		.digest("hex");
	const base: IncidentRecorderRunHistoryEvent = {
		identityKey,
		identity,
		semanticFingerprint: createHash("sha256").update(`semantic:${identityKey}`).digest("hex"),
		occurrenceReference: `segment-occurrence:${occurrenceId}`,
		source: "supervisor-events",
		type,
		encoding: "json",
		payloadKind: "derived-scalar",
		terminal: false,
		metadata:
			type === "worker_request_end"
				? { outcome: "timeout", requestId: "request-1", requestType: "list", durationMs: 321.5 }
				: type === "kernel_unexpected_exit"
					? {
							sessionId: "session-1",
							kernelInstanceId: "kernel-1",
							kernelPid: 4242,
							kernelProcessStartId: "proc:4242",
							launchMode: "direct",
							crashPhase: "executing",
							requestMsgId: "request-msg-1",
							code: null,
							signal: "SIGKILL",
							reason: "process_exit",
						}
					: {},
		eventWallTimeMs: "1700000000123",
		eventMonotonicNs: "9001",
		wrapperOrder: ["41", "42"],
		producerOrder: ["7", "8"],
		cursors: ["cursor-41", "cursor-42"],
		transportIdentity: {},
		cas: { digest: "a".repeat(64), bytes: 0, path: "/private/cas/a" },
	};
	const result = { ...base, ...overrides };
	const resultIdentity = result.identity;
	const resultIdentityKey = createHash("sha256")
		.update(
			`${resultIdentity.runId}\0${resultIdentity.runToken}\0${resultIdentity.producerId}\0${resultIdentity.occurrenceId}`,
		)
		.digest("hex");
	return {
		...result,
		occurrenceReference: overrides.occurrenceReference ?? `segment-occurrence:${resultIdentity.occurrenceId}`,
		identityKey: overrides.identityKey ?? resultIdentityKey,
		semanticFingerprint:
			overrides.semanticFingerprint ?? createHash("sha256").update(`semantic:${resultIdentityKey}`).digest("hex"),
	};
}

function context(overrides: Partial<IncidentRecorderLiveTriggerIntentContext> = {}) {
	return {
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		targetPid: 4242,
		targetProcessStartId: TARGET_PROCESS_START_ID,
		...overrides,
	};
}

function candidate(overrides: Partial<IncidentRecorderRunHistoryEvent> = {}) {
	const result = extractIncidentRecorderLiveTriggerIntentCandidate(event("worker_request_end", overrides), context());
	if (!result) throw new Error("fixture did not produce a candidate");
	return result;
}

function storage(
	reserve: (bytes: number, entries: number, inodes: number) => unknown = () => {},
	effects: IncidentRecorderStorageAccountingEffect[] = [],
) {
	return { reserve, effects };
}

describe("committed live trigger intent storage", () => {
	it("extracts only qualifying events and preserves multi-chunk ordering", () => {
		const scanStartCursor: IncidentRecorderLiveRunEventsCursor = {
			version: 1,
			runId: RUN_ID,
			filterSha256: "b".repeat(64),
			segmentSequence: 4,
			ordinal: 41,
		};
		const extracted = extractIncidentRecorderLiveTriggerIntentCandidate(
			event("worker_request_end"),
			context({ scanStartCursor }),
		);
		expect(extracted).toMatchObject({
			classification: "worker_response_hang",
			cause: { requestId: "request-1", requestType: "list", durationMs: 321.5 },
			target: { pid: 4242, processStartId: TARGET_PROCESS_START_ID },
			scanStartCursor,
		});
		expect(extracted?.trigger.producerOrder).toEqual(["7", "8"]);
		expect(extracted?.trigger.wrapperOrder).toEqual(["41", "42"]);
		expect(extracted?.trigger.occurrenceReference).toBe("segment-occurrence:44444444-4444-4444-8444-444444444444");
		expect(extractIncidentRecorderLiveTriggerIntentCandidate(event("ordinary_event"), context())).toBeUndefined();
		expect(
			extractIncidentRecorderLiveTriggerIntentCandidate(
				event("worker_request_end", { metadata: { outcome: "error" } }),
				context(),
			),
		).toBeUndefined();
	});

	it("extracts a kernel exit and turns malformed optional metadata into null", () => {
		const extracted = extractIncidentRecorderLiveTriggerIntentCandidate(
			event("kernel_unexpected_exit", {
				metadata: {
					kernelPid: "not-a-pid",
					launchMode: "invalid",
					reason: "invalid",
				},
			}),
			context(),
		);
		expect(extracted).toMatchObject({
			classification: "kernel_unexpected_exit",
			cause: {
				sessionId: null,
				kernelInstanceId: null,
				kernelPid: null,
				launchMode: null,
				reason: null,
			},
		});
	});

	it("rejects qualifying events with invalid binding or unsafe timestamps", () => {
		expect(() =>
			extractIncidentRecorderLiveTriggerIntentCandidate(
				event("worker_request_end", { eventWallTimeMs: "9007199254740992" }),
				context(),
			),
		).toThrow(/timestamp/i);
		expect(() =>
			extractIncidentRecorderLiveTriggerIntentCandidate(
				event("kernel_unexpected_exit", {
					identity: { ...event("kernel_unexpected_exit").identity, runId: "66666666-6666-4666-8666-666666666666" },
				}),
				context(),
			),
		).toThrow(/identity/i);
	});

	it("rejects qualifying events with a mismatched identity key", () => {
		expect(() =>
			extractIncidentRecorderLiveTriggerIntentCandidate(
				event("worker_request_end", { identityKey: "0".repeat(64) }),
				context(),
			),
		).toThrow(/identity/i);
	});

	it("publishes once, then replays byte-identically with frozen UUIDs", () => {
		const value = fixture();
		const first = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, candidate(), storage()),
		);
		expect(first.state).toBe("applied");
		if (first.state !== "applied") return;
		const name = incidentRecorderLiveTriggerIntentFileName(first.intent);
		const bytes = readFileSync(join(value.run, name));
		const second = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, candidate({}), storage()),
		);
		expect(second.state).toBe("replayed");
		if (second.state !== "replayed") return;
		expect(second.intent.reservedOccurrenceIds).toEqual(first.intent.reservedOccurrenceIds);
		expect(readFileSync(join(value.run, name))).toEqual(bytes);
		expect(readdirSync(value.run)).toEqual([name]);
	});

	it("keeps the original scan cursor on replay and allocates distinct occurrences separately", () => {
		const value = fixture();
		const firstCandidate = candidate();
		const first = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, firstCandidate, storage()),
		);
		if (first.state !== "applied") throw new Error("first intent was not applied");
		const changedCursorCandidate = {
			...firstCandidate,
			scanStartCursor: {
				version: 1 as const,
				runId: RUN_ID,
				filterSha256: "c".repeat(64),
				segmentSequence: 99,
				ordinal: 99,
			},
		};
		const replay = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, changedCursorCandidate, storage()),
		);
		if (replay.state !== "replayed") throw new Error("changed cursor did not replay");
		expect(replay.intent.scanStartCursor).toBeNull();

		const secondEvent = event("worker_request_end", {
			identity: { ...event("worker_request_end").identity, occurrenceId: "77777777-7777-4777-8777-777777777777" },
		});
		const secondCandidate = extractIncidentRecorderLiveTriggerIntentCandidate(secondEvent, context());
		if (!secondCandidate) throw new Error("second candidate missing");
		const second = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, secondCandidate, storage()),
		);
		expect(second.state).toBe("applied");
		expect(readdirSync(value.run)).toHaveLength(2);
	});

	it("conflicts without overwriting a mismatched existing intent", () => {
		const value = fixture();
		const first = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, candidate(), storage()),
		);
		if (first.state !== "applied") throw new Error("first intent was not applied");
		const name = incidentRecorderLiveTriggerIntentFileName(first.intent);
		const before = readFileSync(join(value.run, name));
		const changed = candidate({ semanticFingerprint: "f".repeat(64) });
		const result = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, changed, storage()),
		);
		expect(result.state).toBe("conflict");
		expect(readFileSync(join(value.run, name))).toEqual(before);
	});

	it("recovers a legitimate hardlink residue through the finalizer helper", () => {
		const value = fixture();
		const first = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, candidate(), storage()),
		);
		if (first.state !== "applied") throw new Error("first intent was not applied");
		const name = incidentRecorderLiveTriggerIntentFileName(first.intent);
		const stage = `.${name}.${createHash("sha256")
			.update(readFileSync(join(value.run, name)))
			.digest("hex")}.tmp`;
		withRunRoot(value, (runRoot) => {
			const destination = runRoot.relative(name);
			const temporary = runRoot.relative(stage);
			runRoot.hardLink(destination, temporary);
		});
		const replay = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(runRoot, candidate(), storage()),
		);
		expect(replay.state).toBe("replayed");
		expect(statSync(join(value.run, name)).nlink).toBe(1);
		expect(existsSync(join(value.run, stage))).toBe(false);
	});

	it("does not write when reservation is denied and reports root ambiguity", () => {
		const value = fixture();
		const result = withRunRoot(value, (runRoot) =>
			persistIncidentRecorderLiveTriggerIntentWithinRoot(
				runRoot,
				candidate(),
				storage(() => false),
			),
		);
		expect(result.state).toBe("ambiguous");
		expect(readdirSync(value.run)).toEqual([]);
	});
});
