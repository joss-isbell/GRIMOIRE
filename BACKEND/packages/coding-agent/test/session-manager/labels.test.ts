import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage } from "@earendil-works/pi-ai";
import { describe, expect, it, vi } from "vitest";
import { type LabelEntry, SessionManager } from "../../src/core/session-manager.js";

describe("SessionManager labels", () => {
	it("sets and gets labels", () => {
		const session = SessionManager.inMemory();

		const msgId = session.appendMessage({ role: "user", content: "hello", timestamp: 1 });

		expect(session.getLabel(msgId)).toBeUndefined();

		const labelId = session.appendLabelChange(msgId, "checkpoint");
		expect(session.getLabel(msgId)).toBe("checkpoint");

		const entries = session.getEntries();
		const labelEntry = entries.find((e) => e.type === "label") as LabelEntry;
		expect(labelEntry).toBeDefined();
		expect(labelEntry.id).toBe(labelId);
		expect(labelEntry.targetId).toBe(msgId);
		expect(labelEntry.label).toBe("checkpoint");
	});

	it("clears labels with undefined", () => {
		const session = SessionManager.inMemory();

		const msgId = session.appendMessage({ role: "user", content: "hello", timestamp: 1 });

		session.appendLabelChange(msgId, "checkpoint");
		expect(session.getLabel(msgId)).toBe("checkpoint");

		session.appendLabelChange(msgId, undefined);
		expect(session.getLabel(msgId)).toBeUndefined();
	});

	it("last label wins", () => {
		const session = SessionManager.inMemory();

		const msgId = session.appendMessage({ role: "user", content: "hello", timestamp: 1 });

		session.appendLabelChange(msgId, "first");
		session.appendLabelChange(msgId, "second");
		const lastLabelId = session.appendLabelChange(msgId, "third");

		expect(session.getLabel(msgId)).toBe("third");

		const entries = session.getEntries();
		const lastLabelEntry = entries.find((e) => e.id === lastLabelId) as LabelEntry;
		const tree = session.getTree();
		const msgNode = tree.find((n) => n.entry.id === msgId);
		expect(msgNode?.labelTimestamp).toBe(lastLabelEntry.timestamp);
	});

	it("labels are included in tree nodes", () => {
		const session = SessionManager.inMemory();

		const msg1Id = session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
		const msg2Id = session.appendMessage({
			role: "assistant",
			content: [{ type: "text", text: "hi" }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "test",
			usage: {
				input: 1,
				output: 1,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 2,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: 2,
		});

		const msg1LabelId = session.appendLabelChange(msg1Id, "start");
		const msg2LabelId = session.appendLabelChange(msg2Id, "response");

		const entries = session.getEntries();
		const msg1LabelEntry = entries.find((e) => e.id === msg1LabelId) as LabelEntry;
		const msg2LabelEntry = entries.find((e) => e.id === msg2LabelId) as LabelEntry;
		const tree = session.getTree();

		const msg1Node = tree.find((n) => n.entry.id === msg1Id);
		expect(msg1Node?.label).toBe("start");
		expect(msg1Node?.labelTimestamp).toBe(msg1LabelEntry.timestamp);

		const msg2Node = msg1Node?.children.find((n) => n.entry.id === msg2Id);
		expect(msg2Node?.label).toBe("response");
		expect(msg2Node?.labelTimestamp).toBe(msg2LabelEntry.timestamp);
	});

	it("labels are preserved in createBranchedSession", () => {
		const session = SessionManager.inMemory();

		const msg1Id = session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
		const msg2Id = session.appendMessage({
			role: "assistant",
			content: [{ type: "text", text: "hi" }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "test",
			usage: {
				input: 1,
				output: 1,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 2,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: 2,
		});

		const msg1LabelId = session.appendLabelChange(msg1Id, "important");
		const msg2LabelId = session.appendLabelChange(msg2Id, "also-important");
		const originalEntries = session.getEntries();
		const msg1LabelEntry = originalEntries.find((e) => e.id === msg1LabelId) as LabelEntry;
		const msg2LabelEntry = originalEntries.find((e) => e.id === msg2LabelId) as LabelEntry;

		session.createBranchedSession(msg2Id);

		expect(session.getLabel(msg1Id)).toBe("important");
		expect(session.getLabel(msg2Id)).toBe("also-important");

		const entries = session.getEntries();
		const labelEntries = entries.filter((e) => e.type === "label") as LabelEntry[];
		expect(labelEntries).toHaveLength(2);

		const tree = session.getTree();
		const msg1Node = tree.find((n) => n.entry.id === msg1Id);
		const msg2Node = msg1Node?.children.find((n) => n.entry.id === msg2Id);
		expect(msg1Node?.labelTimestamp).toBe(msg1LabelEntry.timestamp);
		expect(msg2Node?.labelTimestamp).toBe(msg2LabelEntry.timestamp);
	});

	it.each([false, true])(
		"relinks fork ancestry across consecutive labels without mutating source entries (persist=%s)",
		(persist) => {
			const directory = mkdtempSync(join(tmpdir(), "pi-label-fork-"));
			vi.useFakeTimers({ toFake: ["Date"] });
			vi.setSystemTime(new Date("2025-01-01T00:00:00Z"));
			try {
				const session = persist
					? SessionManager.create(directory, join(directory, "sessions"))
					: SessionManager.inMemory(directory);
				const rootId = session.appendMessage({ role: "user", content: "start", timestamp: 1 });
				const checkpointId = session.appendMessage(fauxAssistantMessage("checkpoint"));
				const rootLabelId = session.appendLabelChange(rootId, "start label");
				const checkpointLabelId = session.appendLabelChange(checkpointId, "checkpoint label");
				const readId = session.appendMessage({ role: "user", content: "unchanged read", timestamp: 2 });
				const targetId = session.appendMessage(fauxAssistantMessage("unchanged"));
				vi.setSystemTime(new Date("2025-01-02T00:00:00Z"));
				// Forks retain the latest label for retained targets, even if applied after the fork point.
				const latestLabelId = session.appendLabelChange(checkpointId, "latest checkpoint label");
				const laterId = session.appendMessage({ role: "user", content: "source only", timestamp: 3 });
				session.appendLabelChange(laterId, "not inherited");
				const expectedLabels = [rootLabelId, latestLabelId].map((id) => {
					const entry = session.getEntry(id) as LabelEntry;
					return { targetId: entry.targetId, label: entry.label, timestamp: entry.timestamp };
				});
				const sourceEntries = session.getEntries();
				const sourceCopy = structuredClone(sourceEntries);
				const sourcePath = session.getBranch(targetId);
				const retained = sourcePath.filter((entry) => entry.type !== "label");
				const sourceRead = session.getEntry(readId)!;
				expect(sourceRead.parentId).toBe(checkpointLabelId);
				const sourceFile = session.getSessionFile();
				const sourceBytes = sourceFile ? readFileSync(sourceFile) : undefined;

				vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
				const forkFile = session.createBranchedSession(targetId);
				const fork = forkFile ? SessionManager.open(forkFile) : session;
				expect(Boolean(forkFile)).toBe(persist);
				expect(sourceEntries).toEqual(sourceCopy);
				expect(sourceRead.parentId).toBe(checkpointLabelId);
				if (sourceFile) {
					expect(forkFile).not.toBe(sourceFile);
					expect(readFileSync(sourceFile)).toEqual(sourceBytes);
					expect(SessionManager.open(sourceFile).getEntries()).toEqual(sourceCopy);
				}
				expect(session.getEntry(readId)?.parentId).toBe(checkpointId);
				expect(session.getEntry(readId)).not.toBe(sourceRead);
				expect(fork.getEntries().filter((entry) => entry.type !== "label")).toEqual(
					retained.map((entry, index) => ({ ...entry, parentId: retained[index - 1]?.id ?? null })),
				);
				expect(fork.getBranch()).toEqual(fork.getEntries());
				expect(session.getBranch()).toEqual(fork.getBranch());
				const relocated = fork.getEntries().filter((entry): entry is LabelEntry => entry.type === "label");
				expect(relocated.map(({ targetId, label, timestamp }) => ({ targetId, label, timestamp }))).toEqual(
					expectedLabels,
				);
				const oldIds = new Set(sourceEntries.map((entry) => entry.id));
				for (const [index, label] of relocated.entries()) {
					expect(oldIds.has(label.id)).toBe(false);
					expect(label.parentId).toBe(index === 0 ? targetId : relocated[index - 1].id);
				}
				expect(fork.getLabel(rootId)).toBe("start label");
				expect(fork.getLabel(checkpointId)).toBe("latest checkpoint label");
				expect(fork.getLabel(laterId)).toBeUndefined();
			} finally {
				vi.useRealTimers();
				rmSync(directory, { recursive: true, force: true });
			}
		},
	);

	it("labels not on path are not preserved in createBranchedSession", () => {
		const session = SessionManager.inMemory();

		const msg1Id = session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
		const msg2Id = session.appendMessage({
			role: "assistant",
			content: [{ type: "text", text: "hi" }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "test",
			usage: {
				input: 1,
				output: 1,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 2,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: 2,
		});
		const msg3Id = session.appendMessage({ role: "user", content: "followup", timestamp: 3 });

		session.appendLabelChange(msg1Id, "first");
		session.appendLabelChange(msg2Id, "second");
		session.appendLabelChange(msg3Id, "third");

		session.createBranchedSession(msg2Id);

		expect(session.getLabel(msg1Id)).toBe("first");
		expect(session.getLabel(msg2Id)).toBe("second");
		expect(session.getLabel(msg3Id)).toBeUndefined();
	});

	it("labels are not included in buildSessionContext", () => {
		const session = SessionManager.inMemory();

		const msgId = session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
		session.appendLabelChange(msgId, "checkpoint");

		const ctx = session.buildSessionContext();
		expect(ctx.messages).toHaveLength(1);
		expect(ctx.messages[0].role).toBe("user");
	});

	it("throws when labeling non-existent entry", () => {
		const session = SessionManager.inMemory();

		expect(() => session.appendLabelChange("non-existent", "label")).toThrow("Entry non-existent not found");
	});
});
