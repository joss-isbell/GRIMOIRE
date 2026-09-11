import fs, { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";
import { Agent, type AgentTool } from "@earendil-works/pi-agent-core";
import { fauxAssistantMessage, fauxToolCall } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../../src/core/agent-session.js";
import type { ExtensionFactory } from "../../src/core/extensions/types.js";
import { convertToLlm } from "../../src/core/messages.js";
import { SessionManager, type SessionMessageEntry } from "../../src/core/session-manager.js";
import { TASKBOARD_BASELINE_CUSTOM_TYPE, TASKBOARD_SNAPSHOT_DETAILS_KEY } from "../../src/core/taskboard-state.js";
import { createTestResourceLoader } from "../utilities.js";
import { createHarness, type Harness, type HarnessOptions } from "./harness.js";

// Mirror the skill's file boundary inside a sequential cell without a live kernel
// or a dependency on a locally installed skill.
function createFauxIpythonTool(path: () => string, saved?: () => void): AgentTool {
	return {
		name: "ipython",
		label: "ipython",
		description: "Save or read a taskboard fixture.",
		executionMode: "sequential",
		parameters: Type.Object({ code: Type.String() }),
		execute: async (_id, params, signal) => {
			const code = (params as { code: string }).code;
			if (code === "DELETE") {
				rmSync(path(), { force: true });
			} else if (code !== "READ") {
				const bytes = code.startsWith("RAISE ") ? code.slice(6) : code.startsWith("WAIT ") ? code.slice(5) : code;
				writeFileSync(`${path()}.skill-tmp`, bytes);
				renameSync(`${path()}.skill-tmp`, path());
				saved?.();
				if (code.startsWith("RAISE ")) throw new Error("cell raised after saving");
				if (code.startsWith("WAIT ")) {
					await new Promise<never>((_resolve, reject) => {
						const abort = () => reject(new Error("cell aborted after saving"));
						if (signal?.aborted) abort();
						else signal?.addEventListener("abort", abort, { once: true });
					});
				}
			}
			return {
				content: [
					{ type: "text", text: existsSync(path()) ? readFileSync(path(), "utf8") : "absent" },
					{ type: "image", data: "aW1hZ2U=", mimeType: "image/png" },
				],
				details: { cell: "preserved", execution: { count: 7 } },
			};
		},
	};
}

function board(status: string, revision = status === "pending" ? 1 : 2): string {
	return `${JSON.stringify(
		{
			schema_version: 1,
			revision,
			active: {
				id: "B-original",
				title: "Ship λ",
				next_task_number: 2,
				focused_task_id: "T001",
				goal_objective: "Deliver",
				created_at: "2026-01-01",
				updated_at: "2026-01-02",
				phases: [
					{
						name: "Delivery",
						tasks: [
							{
								id: "T001",
								text: "Ship",
								status,
								owner: "worker:123",
								blocker: status === "blocked" ? "waiting" : null,
								result: status === "completed" ? "verified" : null,
								evidence: ["proof", "test.log"],
								created_at: "2026-01-01",
								updated_at: "2026-01-02",
							},
						],
					},
				],
				events: [{ action: "init", at: "2026-01-01" }],
			},
			history: [],
		},
		null,
		2,
	)}\n`;
}

function results(harness: Harness): SessionMessageEntry[] {
	return harness.sessionManager
		.getEntries()
		.filter((entry): entry is SessionMessageEntry => entry.type === "message" && entry.message.role === "toolResult");
}

async function cells(harness: Harness, codes: string[]): Promise<SessionMessageEntry[]> {
	const count = results(harness).length;
	harness.setResponses([
		fauxAssistantMessage(
			codes.map((code) => fauxToolCall("ipython", { code })),
			{ stopReason: "toolUse" },
		),
		fauxAssistantMessage("Saved."),
	]);
	await harness.session.prompt("update board");
	await harness.session.waitForIdle();
	return results(harness).slice(count);
}

async function save(harness: Harness, bytes: string): Promise<string> {
	const [result] = await cells(harness, [bytes]);
	if (!result) throw new Error("missing tool result");
	return result.id;
}

function snapshots(harness: Harness): unknown[] {
	return results(harness).flatMap((entry) => {
		if (entry.message.role !== "toolResult") return [];
		const details = entry.message.details as Record<string, unknown>;
		return Object.hasOwn(details, TASKBOARD_SNAPSHOT_DETAILS_KEY) ? [details[TASKBOARD_SNAPSHOT_DETAILS_KEY]] : [];
	});
}

function deferred() {
	let resolve = () => {};
	const promise = new Promise<void>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

describe("AgentSession taskboard tree state", () => {
	const harnesses: Harness[] = [];
	afterEach(() => {
		vi.restoreAllMocks();
		syncBuiltinESMExports();
		while (harnesses.length) harnesses.pop()?.cleanup();
	});

	async function setup(options: HarnessOptions = {}, saved?: () => void) {
		let path = "";
		const harness = await createHarness({
			...options,
			persistSession: true,
			tools: [createFauxIpythonTool(() => path, saved)],
		});
		harnesses.push(harness);
		const directory = harness.sessionManager.getSessionArtifactDir()!;
		mkdirSync(directory, { recursive: true });
		path = join(directory, "taskboard.json");
		return { harness, path };
	}

	async function resume(sessionFile: string) {
		// This branch's shared harness only creates sessions. Rehydrate through the native session APIs here.
		const harness = await createHarness({ tools: [] });
		harnesses.push(harness);
		const originalSession = harness.session;
		const originalCleanup = harness.cleanup;
		originalSession.dispose();
		const sessionManager = SessionManager.open(sessionFile);
		const path = join(sessionManager.getSessionArtifactDir()!, "taskboard.json");
		const agent = new Agent({
			getApiKey: () => "faux-key",
			initialState: {
				model: harness.getModel(),
				messages: sessionManager.buildSessionContext().messages,
			},
			convertToLlm,
		});
		const session = new AgentSession({
			agent,
			sessionManager,
			settingsManager: harness.settingsManager,
			cwd: harness.tempDir,
			modelRegistry: originalSession.modelRegistry,
			resourceLoader: originalSession.resourceLoader,
			baseToolsOverride: { ipython: createFauxIpythonTool(() => path) },
		});
		harness.session = session;
		harness.sessionManager = sessionManager;
		session.subscribe((event) => harness.events.push(event));
		harness.cleanup = () => {
			session.dispose();
			originalCleanup();
		};
		return { harness, path };
	}

	it("restores pending when /tree selects the older result after completion", async () => {
		const { harness, path } = await setup();
		const pendingResult = await save(harness, board("pending"));
		await save(harness, board("completed"));
		expect(readFileSync(path, "utf8")).toBe(board("completed"));

		await harness.session.navigateTree(pendingResult, { summarize: false });

		expect(readFileSync(path, "utf8")).toBe(board("pending"));
	});

	it("includes a result's save but excludes it at the initiating assistant", async () => {
		const { harness, path } = await setup();
		const first = await save(harness, board("pending"));
		const completed = await save(harness, board("completed"));
		const assistant = harness.sessionManager.getEntry(completed)!.parentId!;
		await harness.session.navigateTree(assistant);
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
		await harness.session.navigateTree(completed);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
		await harness.session.navigateTree(harness.sessionManager.getEntry(first)!.parentId!);
		expect(existsSync(path)).toBe(false);
	});

	it("captures two cells in one response while message_end persistence is lagged", async () => {
		const blocked = deferred();
		const bothSaved = deferred();
		let didBlock = false;
		let saves = 0;
		const extension: ExtensionFactory = (pi) => {
			pi.on("message_end", async (event) => {
				if (event.message.role === "assistant" && !didBlock) {
					didBlock = true;
					await blocked.promise;
				}
			});
		};
		const { harness, path } = await setup({ extensionFactories: [extension] }, () => {
			if (++saves === 2) bothSaved.resolve();
		});
		const running = cells(harness, [board("pending"), board("completed")]);
		try {
			await bothSaved.promise;
			expect(didBlock).toBe(true);
			expect(results(harness)).toHaveLength(0);
		} finally {
			blocked.resolve();
		}
		const [first, second] = await running;
		await harness.session.navigateTree(first.id);
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
		await harness.session.navigateTree(second.id);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
	});

	it("preserves details, images, and error state while extensions replace result details", async () => {
		const extension: ExtensionFactory = (pi) => {
			pi.on("tool_result", (event) => {
				const { cell, execution } = event.details as { cell: string; execution: unknown };
				return { details: { cell, execution, extension: true } };
			});
		};
		const { harness } = await setup({ extensionFactories: [extension] });
		const [entry] = await cells(harness, [board("pending")]);
		expect(entry.message).toMatchObject({
			isError: false,
			details: { cell: "preserved", execution: { count: 7 }, extension: true },
			content: [{ type: "text" }, { type: "image", data: "aW1hZ2U=", mimeType: "image/png" }],
		});
		expect(snapshots(harness)).toEqual([
			{ version: 1, encoding: "base64", content: Buffer.from(board("pending")).toString("base64") },
		]);
	});

	it("keeps B and C branches independent and resets the change baseline on each switch", async () => {
		const { harness, path } = await setup();
		const a = await save(harness, board("pending"));
		const b = await save(harness, board("completed"));
		await harness.session.navigateTree(a);
		const unchanged = await save(harness, board("pending"));
		expect(snapshots(harness)).toHaveLength(2);
		const c = await save(harness, board("blocked", 3));
		await harness.session.navigateTree(b);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
		await harness.session.navigateTree(c);
		expect(readFileSync(path, "utf8")).toBe(board("blocked", 3));
		await harness.session.navigateTree(unchanged);
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
	});

	it("round-trips full completed, closed, and replacement board history", async () => {
		const { harness, path } = await setup();
		const pending = board("pending");
		const completed = board("completed");
		const priorBoard = JSON.parse(completed).active;
		const closed = `${JSON.stringify(
			{
				schema_version: 1,
				revision: 3,
				active: null,
				history: [{ ...priorBoard, closed_at: "2026-01-03", close_note: "verified" }],
			},
			null,
			2,
		)}\n`;
		const replacement = `${JSON.stringify(
			{
				...JSON.parse(closed),
				revision: 4,
				active: {
					...JSON.parse(pending).active,
					id: "B-second",
					focused_task_id: null,
					next_task_number: 9,
					events: [{ action: "init", note: "new board" }],
				},
			},
			null,
			2,
		)}\n`;
		const payloads = [pending, completed, closed, replacement];
		const ids: string[] = [];
		for (const payload of payloads) ids.push(await save(harness, payload));
		for (const index of [2, 0, 3, 1]) {
			await harness.session.navigateTree(ids[index]);
			expect(readFileSync(path, "utf8")).toBe(payloads[index]);
		}
	});

	it("captures a saved board even when the cell later raises", async () => {
		const { harness, path } = await setup();
		const first = await save(harness, board("pending"));
		const failed = await save(harness, `RAISE ${board("completed")}`);
		expect(harness.sessionManager.getEntry(failed)).toMatchObject({
			message: { isError: true, content: [{ type: "text", text: "cell raised after saving" }] },
		});
		await harness.session.navigateTree(first);
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
		await harness.session.navigateTree(failed);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
	});

	it.each(["cell", "tool_result hook"] as const)(
		"preserves a saved checkpoint when User aborts during the %s",
		async (stage) => {
			const saved = deferred();
			const hookStarted = deferred();
			const releaseHook = deferred();
			let saves = 0;
			const extension: ExtensionFactory = (pi) => {
				pi.on("tool_result", async (event) => {
					if (stage === "tool_result hook" && event.input.code === board("completed")) {
						hookStarted.resolve();
						await releaseHook.promise;
					}
				});
			};
			const { harness, path } = await setup({ extensionFactories: [extension] }, () => {
				if (++saves === 2) saved.resolve();
			});
			const first = await save(harness, board("pending"));
			const running = cells(harness, [`${stage === "cell" ? "WAIT " : ""}${board("completed")}`]);
			try {
				await (stage === "cell" ? saved.promise : hookStarted.promise);
				await harness.session.abort();
			} finally {
				releaseHook.resolve();
			}
			const [aborted] = await running;
			expect(aborted.message).toMatchObject({ role: "toolResult", isError: true });
			await cells(harness, ["READ"]);
			await harness.session.navigateTree(first);
			expect(readFileSync(path, "utf8")).toBe(board("pending"));
			await harness.session.navigateTree(aborted.id);
			expect(readFileSync(path, "utf8")).toBe(board("completed"));
		},
	);

	it("keeps a checkpoint when the after-tool hook fails or message_end replaces details", async () => {
		const extension: ExtensionFactory = (pi) => {
			pi.on("tool_result", () => undefined);
			pi.on("message_end", (event) =>
				event.message.role === "toolResult"
					? { message: { ...event.message, details: { replaced: true } } }
					: undefined,
			);
		};
		const { harness, path } = await setup({ extensionFactories: [extension] });
		const first = await save(harness, board("pending"));
		vi.spyOn(harness.session.extensionRunner, "emitToolResult").mockRejectedValueOnce(new Error("hook failed"));
		const failed = await save(harness, board("completed"));
		expect(harness.sessionManager.getEntry(failed)).toMatchObject({ message: { isError: true } });
		await harness.session.navigateTree(first);
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
		await harness.session.navigateTree(failed);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
	});

	it("retries the snapshot on an unchanged read after its result append fails", async () => {
		const { harness } = await setup();
		await save(harness, board("pending"));
		const append = harness.sessionManager.appendMessage.bind(harness.sessionManager);
		let failed = false;
		vi.spyOn(harness.sessionManager, "appendMessage").mockImplementation((message) => {
			if (!failed && message.role === "toolResult") {
				failed = true;
				throw new Error("result persistence failed");
			}
			return append(message);
		});
		await cells(harness, [board("completed")]);
		const [read] = await cells(harness, ["READ"]);
		expect(read.message).toMatchObject({
			details: {
				[TASKBOARD_SNAPSHOT_DETAILS_KEY]: {
					version: 1,
					encoding: "base64",
					content: Buffer.from(board("completed")).toString("base64"),
				},
			},
		});
	});

	it("records deletion tombstones but no payloads for unused sessions or unchanged reads", async () => {
		const { harness, path } = await setup();
		await cells(harness, ["READ", "READ"]);
		expect(snapshots(harness)).toEqual([]);
		expect(
			harness.sessionManager
				.getEntries()
				.some((e) => e.type === "custom" && e.customType === TASKBOARD_BASELINE_CUSTOM_TYPE),
		).toBe(false);
		const first = await save(harness, board("pending"));
		await cells(harness, ["READ", "READ"]);
		const deleted = await save(harness, "DELETE");
		expect(snapshots(harness)).toHaveLength(2);
		expect(snapshots(harness).at(-1)).toEqual({ version: 1, encoding: "base64", content: null });
		await harness.session.navigateTree(first);
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
		await harness.session.navigateTree(deleted);
		expect(existsSync(path)).toBe(false);
	});

	it("does not project for no-op, cancelled, or aborted-summary navigation", async () => {
		let cancel = true;
		const extension: ExtensionFactory = (pi) => {
			pi.on("session_before_tree", () => (cancel ? { cancel: true } : undefined));
		};
		const { harness, path } = await setup({ extensionFactories: [extension] });
		const first = await save(harness, board("pending"));
		await save(harness, board("completed"));
		const leaf = harness.sessionManager.getLeafId()!;
		await harness.session.navigateTree(leaf);
		expect(await harness.session.navigateTree(first)).toMatchObject({ cancelled: true });
		expect(harness.sessionManager.getLeafId()).toBe(leaf);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
		cancel = false;
		harness.setResponses([fauxAssistantMessage("summary")]);
		// The explicit abort API cancels summary generation under the same navigation pause.
		vi.spyOn(harness.session.extensionRunner, "emit").mockImplementationOnce(async () => {
			harness.session.abortBranchSummary();
			return undefined;
		});
		await expect(harness.session.navigateTree(first, { summarize: true })).resolves.toMatchObject({
			cancelled: true,
		});
		expect(harness.sessionManager.getLeafId()).toBe(leaf);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
	});

	it("uses the parent of user/custom targets and restores before appending a summary", async () => {
		const extension: ExtensionFactory = (pi) => {
			pi.on("session_before_tree", () => ({ summary: { summary: "abandoned branch" } }));
		};
		const { harness, path } = await setup({ extensionFactories: [extension] });
		const first = await save(harness, board("pending"));
		const user = harness.sessionManager.appendMessage({ role: "user", content: "edit me", timestamp: Date.now() });
		await save(harness, board("completed"));
		expect(await harness.session.navigateTree(user)).toMatchObject({ editorText: "edit me" });
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
		const custom = harness.sessionManager.appendCustomMessageEntry("draft", "custom text", true);
		await save(harness, board("completed"));
		expect(await harness.session.navigateTree(custom, { summarize: true, label: "branch" })).toMatchObject({
			editorText: "custom text",
			summaryEntry: { type: "branch_summary", summary: "abandoned branch" },
		});
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
		await harness.session.navigateTree(first);
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
	});

	it("resumes selected ancestry rather than the physically newest snapshot", async () => {
		const { harness, path } = await setup();
		const first = await save(harness, board("pending"));
		await save(harness, board("completed"));
		await harness.session.navigateTree(first);
		await cells(harness, ["READ"]); // Persist the selected leaf without a duplicate snapshot.
		writeFileSync(path, board("completed"));
		const resumed = await resume(harness.session.sessionFile!);
		expect(readFileSync(resumed.path, "utf8")).toBe(board("pending"));
		expect(snapshots(resumed.harness)).toHaveLength(2);
	});

	it("forks chosen ancestry into a new artifact directory without sharing the source board", async () => {
		const { harness, path } = await setup();
		const first = await save(harness, board("pending"));
		await save(harness, board("completed"));
		// This is the SessionManager path used by AgentSessionRuntime.fork(position: 'at').
		const manager = SessionManager.open(harness.session.sessionFile!);
		const forkPath = manager.createBranchedSession(first)!;
		const fork = await resume(forkPath);
		expect(fork.path).not.toBe(path);
		expect(readFileSync(fork.path, "utf8")).toBe(board("pending"));
		await save(fork.harness, board("blocked", 3));
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
		const fresh = await setup({ rlmDepth: 1 });
		expect(existsSync(fresh.path)).toBe(false);
	});

	it("forks an unchanged board through a labeled ancestor while the source keeps its newer board", async () => {
		const { harness, path } = await setup();
		const first = await save(harness, board("pending"));
		harness.sessionManager.appendLabelChange(first, "checkpoint");
		const [unchanged] = await cells(harness, ["READ"]);
		expect(snapshots(harness)).toHaveLength(1);
		await save(harness, board("completed"));
		const sourceFile = harness.session.sessionFile!;
		const sourceTranscript = readFileSync(sourceFile);
		const sourceEntries = structuredClone(harness.sessionManager.getEntries());

		const manager = SessionManager.open(sourceFile);
		const forkFile = manager.createBranchedSession(unchanged.id)!;
		const fork = await resume(forkFile);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
		expect(readFileSync(sourceFile)).toEqual(sourceTranscript);
		expect(harness.sessionManager.getEntries()).toEqual(sourceEntries);
		expect(fork.path).not.toBe(path);
		expect(existsSync(fork.path)).toBe(true);
		expect(readFileSync(fork.path, "utf8")).toBe(board("pending"));
		expect(fork.harness.sessionManager.getBranch().some((entry) => entry.id === first)).toBe(true);
		expect(fork.harness.sessionManager.getLabel(first)).toBe("checkpoint");
		const [read] = await cells(fork.harness, ["READ"]);
		expect(read.message).toMatchObject({
			content: expect.arrayContaining([{ type: "text", text: board("pending") }]),
		});
		expect(snapshots(fork.harness)).toHaveLength(1);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
	});

	it("restores pre-compaction ancestors on navigation and resume", async () => {
		const extension: ExtensionFactory = (pi) => {
			pi.on("session_before_compact", (event) => ({
				compaction: {
					summary: "compacted",
					firstKeptEntryId: event.preparation.firstKeptEntryId,
					tokensBefore: event.preparation.tokensBefore,
				},
			}));
		};
		const { harness, path } = await setup({
			settings: { compaction: { keepRecentTokens: 1 } },
			extensionFactories: [extension],
		});
		const first = await save(harness, board("pending"));
		await cells(harness, ["READ"]);
		await harness.session.compact();
		const compacted = harness.sessionManager
			.getEntries()
			.reverse()
			.find((entry) => entry.type === "compaction")!;
		expect(compacted).toBeDefined();
		expect(
			harness.session.messages.some(
				(m) => m.role === "toolResult" && (m.details as Record<string, unknown>)[TASKBOARD_SNAPSHOT_DETAILS_KEY],
			),
		).toBe(false);
		await save(harness, board("completed"));
		await harness.session.navigateTree(compacted.id);
		expect(readFileSync(path, "utf8")).toBe(board("pending"));
		await cells(harness, ["READ"]);
		writeFileSync(path, board("completed"));
		const resumed = await resume(harness.session.sessionFile!);
		expect(readFileSync(resumed.path, "utf8")).toBe(board("pending"));
		await resumed.harness.session.navigateTree(first);
		expect(readFileSync(resumed.path, "utf8")).toBe(board("pending"));
	});

	it("restores into an explicit RLM directory before runtime construction and leaves viewers read-only", async () => {
		const { harness, path } = await setup();
		await save(harness, board("pending"));
		const directory = join(harness.tempDir, "explicit-rlm");
		const session = new AgentSession({
			agent: new Agent({ initialState: { model: harness.getModel() } }),
			sessionManager: SessionManager.open(harness.session.sessionFile!),
			settingsManager: harness.settingsManager,
			modelRegistry: harness.session.modelRegistry,
			cwd: harness.tempDir,
			resourceLoader: createTestResourceLoader(),
			baseToolsOverride: {},
			rlmSessionDir: directory,
		});
		try {
			expect(readFileSync(join(directory, "taskboard.json"), "utf8")).toBe(board("pending"));
			expect(readFileSync(path, "utf8")).toBe(board("pending"));
		} finally {
			session.dispose();
		}
		const viewer = await createHarness({ tools: [] });
		harnesses.push(viewer);
		expect(viewer.sessionManager.getSessionArtifactDir()).toBeUndefined();
		expect((viewer.session as unknown as { _rlmSessionDir?: string })._rlmSessionDir).toBeUndefined();
		expect(viewer.sessionManager.getEntries()).toEqual([]);
	});

	it("does not project when an extension-provided summary finishes after cancellation", async () => {
		let abort = () => {};
		const extension: ExtensionFactory = (pi) => {
			pi.on("session_before_tree", () => {
				abort();
				return { summary: { summary: "too late" } };
			});
		};
		const { harness, path } = await setup({ extensionFactories: [extension] });
		abort = () => harness.session.abortBranchSummary();
		const first = await save(harness, board("pending"));
		await save(harness, board("completed"));
		const leaf = harness.sessionManager.getLeafId();
		expect(await harness.session.navigateTree(first, { summarize: true })).toMatchObject({
			cancelled: true,
			aborted: true,
		});
		expect(harness.sessionManager.getLeafId()).toBe(leaf);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
	});

	it("leaves the branch, transcript and file unchanged when taskboard restore fails", async () => {
		const { harness, path } = await setup();
		const first = await save(harness, board("pending"));
		await save(harness, board("completed"));
		const leaf = harness.sessionManager.getLeafId();
		const entries = structuredClone(harness.sessionManager.getEntries());
		const messages = structuredClone(harness.session.messages);
		vi.spyOn(fs, "renameSync").mockImplementationOnce(() => {
			throw new Error("taskboard rename failed");
		});
		syncBuiltinESMExports();
		await expect(harness.session.navigateTree(first)).rejects.toThrow("Cannot restore taskboard state");
		expect(harness.sessionManager.getLeafId()).toBe(leaf);
		expect(harness.sessionManager.getEntries()).toEqual(entries);
		expect(harness.session.messages).toEqual(messages);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
	});

	it("surfaces the original commit failure and a failed transcript rollback", async () => {
		const extension: ExtensionFactory = (pi) => {
			pi.on("session_before_tree", () => ({ summary: { summary: "abandoned branch" } }));
		};
		const { harness, path } = await setup({ extensionFactories: [extension] });
		const first = await save(harness, board("pending"));
		await save(harness, board("completed"));
		const leaf = harness.sessionManager.getLeafId();
		vi.spyOn(harness.sessionManager, "_persist").mockImplementationOnce(() => {
			throw new Error("commit failed");
		});
		const internals = harness.sessionManager as unknown as { _rewriteFile(): void };
		vi.spyOn(internals, "_rewriteFile").mockImplementationOnce(() => {
			throw new Error("recovery failed");
		});
		await expect(harness.session.navigateTree(first, { summarize: true })).rejects.toThrow(
			"Branch navigation failed (Error: commit failed); transcript rollback also failed (Error: recovery failed)",
		);
		expect(harness.sessionManager.getLeafId()).toBe(leaf);
		expect(readFileSync(path, "utf8")).toBe(board("completed"));
	});

	it.each(["branch_summary", "label"] as const)(
		"rolls back the file and transcript when %s persistence fails",
		async (failedType) => {
			const extension: ExtensionFactory = (pi) => {
				pi.on("session_before_tree", () => ({ summary: { summary: "abandoned branch" } }));
			};
			const { harness, path } = await setup({ extensionFactories: [extension] });
			const first = await save(harness, board("pending"));
			await save(harness, board("completed"));
			const manager = harness.sessionManager;
			const previousEntries = structuredClone(manager.getEntries());
			const previousLeaf = manager.getLeafId();
			const previousMessages = structuredClone(harness.session.messages);
			const persist = manager._persist.bind(manager);
			vi.spyOn(manager, "_persist").mockImplementation((entry) => {
				if (entry.type === failedType) {
					expect(readFileSync(path, "utf8")).toBe(board("pending"));
					throw new Error(`${failedType} persistence failed`);
				}
				persist(entry);
			});
			await expect(harness.session.navigateTree(first, { summarize: true, label: "new label" })).rejects.toThrow(
				`${failedType} persistence failed`,
			);
			expect(readFileSync(path, "utf8")).toBe(board("completed"));
			expect(manager.getLeafId()).toBe(previousLeaf);
			expect(manager.getEntries()).toEqual(previousEntries);
			expect(harness.session.messages).toEqual(previousMessages);
			const reopened = SessionManager.open(harness.session.sessionFile!);
			expect(reopened.getEntries()).toEqual(previousEntries);
			expect(reopened.getLeafId()).toBe(previousLeaf);
		},
	);

	it("imports legacy bytes once at the original startup tip, never after a rewind", async () => {
		const original = await setup();
		await cells(original.harness, ["READ"]);
		const originalTip = original.harness.sessionManager.getLeafId()!;
		writeFileSync(original.path, board("completed"));
		const resumed = await resume(original.harness.session.sessionFile!);
		const baselines = resumed.harness.sessionManager
			.getEntries()
			.filter((entry) => entry.type === "custom" && entry.customType === TASKBOARD_BASELINE_CUSTOM_TYPE);
		expect(baselines).toHaveLength(1);
		expect(baselines[0].parentId).toBe(originalTip);
		expect(readFileSync(resumed.path, "utf8")).toBe(board("completed"));
		await resumed.harness.session.navigateTree(originalTip);
		expect(existsSync(resumed.path)).toBe(false); // Older legacy history is unavailable, not retroactively recovered.
		await cells(resumed.harness, ["READ"]);
		writeFileSync(resumed.path, board("completed"));
		const restarted = await resume(resumed.harness.session.sessionFile!);
		expect(existsSync(restarted.path)).toBe(false);
		expect(
			restarted.harness.sessionManager
				.getEntries()
				.filter((entry) => entry.type === "custom" && entry.customType === TASKBOARD_BASELINE_CUSTOM_TYPE),
		).toHaveLength(1);
		await restarted.harness.session.navigateTree(baselines[0].id);
		expect(readFileSync(restarted.path, "utf8")).toBe(board("completed"));
	});
});
