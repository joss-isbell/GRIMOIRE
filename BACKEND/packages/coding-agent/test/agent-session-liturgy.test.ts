import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent, type StreamFn } from "@earendil-works/pi-agent-core";
import { getModel } from "@earendil-works/pi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AgentSession } from "../src/core/agent-session.js";
import { AuthStorage } from "../src/core/auth-storage.js";
import type { HostRequestHandlers } from "../src/core/kernel/index.js";
import { convertToLlm } from "../src/core/messages.js";
import { ModelRegistry } from "../src/core/model-registry.js";
import { SessionManager } from "../src/core/session-manager.js";
import { SettingsManager } from "../src/core/settings-manager.js";
import type { Skill } from "../src/core/skills.js";
import { createSyntheticSourceInfo } from "../src/core/source-info.js";
import { createTestResourceLoader } from "./utilities.js";

const model = getModel("anthropic", "claude-sonnet-4-5")!;
const initial = { schema_version: 1, revision: 0, active: null, history: [] };

type InspectableSession = { _createKernelHostHandlers(): HostRequestHandlers };

describe("host-controlled LITURGY session state", () => {
	let tempDir: string;
	const sessions: AgentSession[] = [];
	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-liturgy-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});
	afterEach(() => {
		for (const session of sessions) session.dispose();
		rmSync(tempDir, { recursive: true, force: true });
	});

	function createSession(name: string, visible = true, manager?: SessionManager): AgentSession {
		const cwd = join(tempDir, name);
		mkdirSync(cwd, { recursive: true });
		const auth = AuthStorage.create(join(cwd, "auth.json"));
		auth.setRuntimeApiKey("anthropic", "test-key");
		const skill: Skill = {
			kind: "python",
			name: "liturgy",
			description: "test",
			filePath: join(cwd, "SKILL.md"),
			baseDir: cwd,
			sourceInfo: createSyntheticSourceInfo(join(cwd, "SKILL.md"), { source: "test" }),
			disableModelInvocation: false,
			python: { importName: "liturgy", packagePath: cwd, pyprojectPath: join(cwd, "pyproject.toml") },
		};
		const agent = new Agent({
			convertToLlm,
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: "", tools: [], thinkingLevel: "off" },
			streamFn: (() => {
				throw new Error("unused");
			}) as StreamFn,
		});
		const session = new AgentSession({
			agent,
			sessionManager: manager ?? SessionManager.create(cwd, join(cwd, "sessions")),
			settingsManager: SettingsManager.create(cwd, cwd),
			cwd,
			modelRegistry: ModelRegistry.create(auth, join(cwd, "models.json")),
			resourceLoader: createTestResourceLoader({ skills: visible ? [skill] : [] }),
		});
		sessions.push(session);
		return session;
	}
	function handlers(session: AgentSession) {
		return (session as unknown as InspectableSession)._createKernelHostHandlers();
	}
	function board(title: string) {
		return {
			id: `L-${title}`,
			title,
			goal_objective: null,
			created_at: "2026-01-01T00:00:00+00:00",
			updated_at: "2026-01-01T00:00:00+00:00",
			next_task_number: 2,
			focused_task_id: "T001",
			phases: [
				{
					name: "Work",
					tasks: [
						{
							id: "T001",
							text: "Sentinel task",
							parent_id: null,
							status: "pending",
							owner: null,
							blocker: null,
							result: null,
							evidence: [],
							created_at: "2026-01-01T00:00:00+00:00",
							updated_at: "2026-01-01T00:00:00+00:00",
						},
					],
				},
			],
			events: [{ at: "2026-01-01T00:00:00+00:00", action: "init" }],
			synthetic_default: false,
		};
	}
	async function commit(handler: HostRequestHandlers, active: string, expected_revision = 0) {
		return handler["liturgy.commit"]!({
			expected_revision,
			state: { ...initial, revision: expected_revision, active: board(active) },
		});
	}

	it("isolates parent, child, and sibling handlers and rejects cross-target selectors", async () => {
		const parent = handlers(createSession("parent"));
		const child = handlers(createSession("child"));
		const siblingA = handlers(createSession("sibling-a"));
		const siblingB = handlers(createSession("sibling-b"));
		await commit(parent, "parent");
		await commit(child, "child");
		await commit(siblingA, "a");
		await commit(siblingB, "b");
		await expect(
			Promise.all([
				parent["liturgy.get"]!({}),
				child["liturgy.get"]!({}),
				siblingA["liturgy.get"]!({}),
				siblingB["liturgy.get"]!({}),
			]),
		).resolves.toEqual([
			{ state: { ...initial, revision: 1, active: board("parent") } },
			{ state: { ...initial, revision: 1, active: board("child") } },
			{ state: { ...initial, revision: 1, active: board("a") } },
			{ state: { ...initial, revision: 1, active: board("b") } },
		]);
		await expect(parent["liturgy.get"]!({ session_id: "child" })).rejects.toThrow(
			"unknown Liturgy request field(s): session_id",
		);
		await expect(
			parent["liturgy.commit"]!({ expected_revision: 1, state: { ...initial, revision: 1 }, target: "child" }),
		).rejects.toThrow("unknown Liturgy request field(s): target");
	});

	it("rejects a stale CAS commit", async () => {
		const host = handlers(createSession("cas"));
		await commit(host, "winner");
		await expect(commit(host, "stale", 0)).rejects.toThrow("stale Liturgy revision: expected 0, current 1");
		await expect(host["liturgy.get"]!({})).resolves.toEqual({
			state: { ...initial, revision: 1, active: board("winner") },
		});
	});

	it("rejects malformed nested boards and tasks without persistence", async () => {
		const host = handlers(createSession("invalid"));
		const malformedPhase = { ...board("bad-phase"), phases: [{ name: "Work", tasks: "not-a-list" }] };
		await expect(
			host["liturgy.commit"]!({ expected_revision: 0, state: { ...initial, active: malformedPhase } }),
		).rejects.toThrow("invalid Liturgy phase");

		const valid = board("bad-task");
		const malformedTask = {
			...valid,
			phases: [{ ...valid.phases[0], tasks: [{ ...valid.phases[0].tasks[0], evidence: [42] }] }],
		};
		await expect(
			host["liturgy.commit"]!({ expected_revision: 0, state: { ...initial, active: malformedTask } }),
		).rejects.toThrow("invalid Liturgy task");
		await expect(host["liturgy.get"]!({})).resolves.toEqual({ state: initial });
	});

	it("hydrates durable state when a persisted session resumes", async () => {
		const cwd = join(tempDir, "resume");
		mkdirSync(cwd, { recursive: true });
		const originalManager = SessionManager.create(cwd, join(cwd, "sessions"));
		const original = createSession("resume", true, originalManager);
		await commit(handlers(original), "durable");
		const sessionFile = originalManager.getSessionFile();
		expect(sessionFile).toBeDefined();
		original.dispose();
		sessions.splice(sessions.indexOf(original), 1);
		const resumed = createSession("resume", true, SessionManager.open(sessionFile!));
		await expect(handlers(resumed)["liturgy.get"]!({})).resolves.toEqual({
			state: { ...initial, revision: 1, active: board("durable") },
		});
	});

	it("does not install handlers when the LITURGY skill is not visible", () => {
		const host = handlers(createSession("hidden", false));
		expect(host["liturgy.get"]).toBeUndefined();
		expect(host["liturgy.commit"]).toBeUndefined();
	});
});
