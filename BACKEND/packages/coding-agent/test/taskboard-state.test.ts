import fs, { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionManager } from "../src/core/session-manager.js";
import {
	TASKBOARD_BASELINE_CUSTOM_TYPE,
	TASKBOARD_SNAPSHOT_DETAILS_KEY,
	TaskboardState,
} from "../src/core/taskboard-state.js";

const bytes = Buffer.from('{ "schema_version": 1, "revision": 1, "active": null, "history": [] }\n');
const snapshot = { version: 1, encoding: "base64", content: bytes.toString("base64") };

describe("TaskboardState", () => {
	const directories: string[] = [];
	afterEach(() => {
		vi.restoreAllMocks();
		syncBuiltinESMExports();
		for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
	});

	function setup(persist = false) {
		const directory = mkdtempSync(join(tmpdir(), "taskboard-state-"));
		directories.push(directory);
		const manager = persist
			? SessionManager.create(directory, join(directory, "sessions"))
			: SessionManager.inMemory();
		const path = join(directory, "taskboard.json");
		const state = new TaskboardState(manager, () => directory);
		return { directory, manager, path, state };
	}

	it("keeps an unused in-memory viewer empty without allocating an artifact directory", () => {
		const manager = SessionManager.inMemory();
		const state = new TaskboardState(manager, () => undefined);
		state.initialize();
		expect(state.capture()).toBeUndefined();
		state.restoreBranch(null)();
		expect(manager.getEntries()).toEqual([]);
		expect(manager.getSessionArtifactDir()).toBeUndefined();
	});

	it.each([
		undefined,
		null,
		{},
		{ ...snapshot, version: 2 },
		{ ...snapshot, encoding: "utf8" },
		{ ...snapshot, content: "not base64" },
		{ ...snapshot, content: 3 },
	])("rejects a malformed persisted envelope (%j) before changing the source", (invalid) => {
		const { manager, path, state } = setup();
		writeFileSync(path, bytes);
		manager.appendCustomEntry(TASKBOARD_BASELINE_CUSTOM_TYPE, invalid);
		expect(() => state.initialize()).toThrow("Invalid taskboard snapshot");
		expect(readFileSync(path)).toEqual(bytes);
		const before = manager.getLeafId();
		expect(() => state.initialize()).toThrow("Invalid taskboard snapshot");
		expect(manager.getLeafId()).toBe(before);
	});

	it("allows a healthy branch to resume when an unrelated sibling snapshot is malformed", () => {
		const { manager, path, state } = setup();
		const healthy = manager.appendCustomEntry(TASKBOARD_BASELINE_CUSTOM_TYPE, snapshot);
		const malformed = manager.appendCustomEntry(TASKBOARD_BASELINE_CUSTOM_TYPE, { version: 42 });
		manager.branch(healthy);
		writeFileSync(path, "future board");
		state.initialize();
		expect(readFileSync(path)).toEqual(bytes);
		expect(() => state.restoreBranch(malformed)).toThrow("Invalid taskboard snapshot");
		expect(readFileSync(path)).toEqual(bytes);
		manager.resetLeaf();
		state.initialize();
		expect(existsSync(path)).toBe(false);
		expect(manager.getEntries()).toHaveLength(2); // Presence still suppresses legacy re-import.
	});

	it("validates malformed tool-result envelopes too", () => {
		const { manager, path, state } = setup();
		writeFileSync(path, bytes);
		manager.appendMessage({
			role: "toolResult",
			toolCallId: "bad",
			toolName: "ipython",
			content: [],
			details: { [TASKBOARD_SNAPSHOT_DETAILS_KEY]: {} },
			isError: false,
			timestamp: Date.now(),
		});
		expect(() => state.initialize()).toThrow("Invalid taskboard snapshot");
		expect(readFileSync(path)).toEqual(bytes);
	});

	it("preserves the legacy source and undoes the baseline when its forced flush fails", () => {
		const { manager, path, state } = setup(true);
		writeFileSync(path, bytes);
		const entries = manager.getEntries();
		vi.spyOn(manager, "flushNow").mockImplementationOnce(() => {
			throw new Error("flush failed");
		});
		expect(() => state.initialize()).toThrow("flush failed");
		expect(manager.getEntries()).toEqual(entries);
		expect(readFileSync(path)).toEqual(bytes);
		state.initialize();
		expect(
			manager.getEntries().filter((e) => e.type === "custom" && e.customType === TASKBOARD_BASELINE_CUSTOM_TYPE),
		).toHaveLength(1);
		const reopened = SessionManager.open(manager.getSessionFile()!);
		expect(reopened.getEntries()).toEqual(manager.getEntries());
	});

	it("preserves raw bytes and cleans temporary files if atomic restore rename fails", () => {
		const { manager, path, directory, state } = setup();
		writeFileSync(path, bytes);
		state.initialize();
		const baseline = manager.getLeafId()!;
		const newerBytes = Buffer.from([0x00, 0xff, 0xc3, 0xa9, 0x0a]);
		writeFileSync(path, newerBytes);
		const newer = state.capture()!;
		manager.appendCustomEntry(TASKBOARD_BASELINE_CUSTOM_TYPE, newer);
		const rename = vi.spyOn(fs, "renameSync").mockImplementationOnce(() => {
			throw new Error("rename failed");
		});
		syncBuiltinESMExports();
		expect(() => state.restoreBranch(baseline)).toThrow("Cannot restore taskboard state");
		expect(readFileSync(path)).toEqual(newerBytes);
		expect(readdirSync(directory)).toEqual(["taskboard.json"]);
		expect(state.capture()).toBeUndefined();
		rename.mockRestore();
		syncBuiltinESMExports();
		const rollback = state.restoreBranch(baseline);
		expect(readFileSync(path)).toEqual(bytes);
		rollback();
		expect(readFileSync(path)).toEqual(newerBytes);
	});

	it("materializes a selected snapshot into a new directory, but leaves missing unused paths absent", () => {
		const { manager, directory } = setup();
		const absent = join(directory, "unused");
		new TaskboardState(manager, () => absent).initialize();
		expect(existsSync(absent)).toBe(false);
		manager.appendCustomEntry(TASKBOARD_BASELINE_CUSTOM_TYPE, snapshot);
		const inherited = join(directory, "fork");
		new TaskboardState(manager, () => inherited).initialize();
		expect(readFileSync(join(inherited, "taskboard.json"))).toEqual(bytes);
	});

	it("does not mistake an inaccessible path for a missing board", () => {
		const { manager, path, state } = setup();
		mkdirSync(path);
		expect(() => state.initialize()).toThrow("Cannot read taskboard state");
		expect(manager.getEntries()).toEqual([]);
	});
});
