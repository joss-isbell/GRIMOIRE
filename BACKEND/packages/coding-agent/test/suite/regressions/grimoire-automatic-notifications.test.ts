import type { AgentTool } from "@earendil-works/pi-agent-core";
import { fauxAssistantMessage, fauxToolCall } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRlmChildTerminalNoticeMessage } from "../../../src/core/messages.js";
import { createHarness, getMessageText, type Harness } from "../harness.js";
import { createDeferred } from "../scheduling.js";

function agentPrompt(id: string) {
	return `Agent-to-agent message received.\nSource: agent_message\nTo: Target\nMessage id: agentmsg_${id}\n\nnotification ${id}`;
}
function notify(harness: Harness, kind: "agent" | "terminal", id = "notice") {
	if (kind === "agent") return harness.session.queueAgentMessagePrompt(agentPrompt(id), "followUp");
	harness.session.restorePendingNextTurnMessages([
		createRlmChildTerminalNoticeMessage({ kind: "completed_without_reply", childId: id, sessionName: "child" }),
	]);
	return Promise.resolve();
}

describe("automatic notifications bypass user drafts", () => {
	const harnesses: Harness[] = [];
	afterEach(() => {
		vi.restoreAllMocks();
		for (const harness of harnesses.splice(0)) harness.cleanup();
	});
	for (const kind of ["agent", "terminal"] as const) {
		it(`delivers ${kind} while an unrelated direct shell is still running`, async () => {
			const harness = await createHarness({ tools: [] });
			harnesses.push(harness);
			const received = vi.fn();
			harness.setResponses([
				() => {
					received();
					return fauxAssistantMessage("received");
				},
			]);
			const started = createDeferred();
			const release = createDeferred();
			const shell = harness.session.executeBash("blocked shell", undefined, {
				operations: {
					exec: async () => {
						started.resolve();
						await release.promise;
						return { exitCode: 0 };
					},
				},
			});
			try {
				await started.promise;
				await notify(harness, kind);
				expect(harness.session.queuedActionCount).toBe(0);
				await vi.waitFor(() => expect(received).toHaveBeenCalledOnce());
				expect(harness.session.isBashRunning).toBe(true);
			} finally {
				release.resolve();
				await shell;
			}
			await harness.session.waitForIdle();
		});
		for (const barrier of ["pause", "abort"] as const) {
			it(`retains ${kind} through an explicit ${barrier} and editable queue clearing`, async () => {
				const harness = await createHarness({ tools: [] });
				harnesses.push(harness);
				const received = vi.fn();
				harness.setResponses([
					() => {
						received();
						return fauxAssistantMessage("received");
					},
				]);
				const pause = barrier === "pause" ? harness.session.acquireQueuedWorkPause() : undefined;
				if (barrier === "abort") harness.session.requestAbort();
				const admission = notify(harness, kind);
				if (kind !== "terminal" || barrier !== "pause") await admission;
				await new Promise<void>((resolve) => setImmediate(resolve));
				expect(received).not.toHaveBeenCalled();
				expect(harness.session.getSteeringMessages()).toEqual([]);
				expect(harness.session.getFollowUpMessages()).toEqual([]);
				expect(harness.session.clearQueue()).toEqual({ steering: [], followUp: [] });
				if (pause) pause.release();
				else harness.session.resumeQueuedWork();
				await admission;
				await vi.waitFor(() => expect(received).toHaveBeenCalledOnce());
				await harness.session.waitForIdle();
			});
		}
	}
	it("delivers automatic notices FIFO before one-at-a-time user drafts", async () => {
		const harness = await createHarness({
			tools: [],
			settings: { steeringMode: "one-at-a-time", followUpMode: "one-at-a-time" },
		});
		harnesses.push(harness);
		const pause = harness.session.acquireQueuedWorkPause();
		let requests = 0;
		harness.setResponses([
			(context) => {
				requests++;
				const texts = context.messages.map(getMessageText);
				const text = texts.join("\n");
				expect(text).toContain("notification first");
				expect(text).toContain("notification second");
				expect(text.indexOf("notification first")).toBeLessThan(text.indexOf("notification second"));
				expect(text).not.toContain("user draft");
				return fauxAssistantMessage("notices received");
			},
			(context) => {
				requests++;
				expect(context.messages.map(getMessageText).join("\n")).toContain("user draft");
				return fauxAssistantMessage("draft received");
			},
		]);
		await harness.session.steer("user draft");
		await notify(harness, "agent", "first");
		await notify(harness, "agent", "second");
		expect(harness.session.getSteeringMessages()).toEqual(["user draft"]);
		expect(harness.session.getFollowUpMessages()).toEqual([]);
		pause.release();
		await harness.session.waitForIdle();
		expect(requests).toBe(2);
	});
	it("delivers a requested agent follow-up at the next safe tool boundary", async () => {
		const started = createDeferred();
		const release = createDeferred();
		const tool: AgentTool = {
			name: "wait",
			label: "Wait",
			description: "Wait for test release",
			parameters: Type.Object({}),
			execute: async () => {
				started.resolve();
				await release.promise;
				return { content: [{ type: "text", text: "tool finished" }], details: {} };
			},
		};
		const harness = await createHarness({ tools: [tool] });
		harnesses.push(harness);
		let received = false;
		harness.setResponses([
			fauxAssistantMessage(fauxToolCall("wait", {}), { stopReason: "toolUse" }),
			(context) => {
				const text = context.messages.map(getMessageText).join("\n");
				expect(text.indexOf("tool finished")).toBeLessThan(text.indexOf("notification boundary"));
				received = true;
				return fauxAssistantMessage("received");
			},
		]);
		const original = harness.session.prompt("do work");
		try {
			await started.promise;
			await notify(harness, "agent", "boundary");
			expect(harness.session.queuedActionCount).toBe(0);
			expect(received).toBe(false);
		} finally {
			release.resolve();
			await original;
		}
		await harness.session.waitForIdle();
		expect(received).toBe(true);
		expect(harness.eventsOfType("agent_start")).toHaveLength(2);
	});
	it("normalizes recovered legacy follow-ups without losing their receipt or content", async () => {
		const original = await createHarness({ tools: [] });
		const restored = await createHarness({ tools: [] });
		harnesses.push(original, restored);
		const originalPause = original.session.acquireQueuedWorkPause();
		const restoredPause = restored.session.acquireQueuedWorkPause();
		try {
			await notify(original, "agent", "recovered");
			const snapshot = original.session.getSessionActionRecoverySnapshot();
			expect(snapshot.actions).toHaveLength(1);
			const action = snapshot.actions[0]!;
			action.delivery = "when_run_idle";
			if (action.payload.kind !== "turn") throw new Error("Expected notification turn");
			action.payload.queueVisible = true;
			expect(await restored.session.restoreSessionActions(snapshot)).toBe(1);
			const recovered = restored.session.getSessionActionRecoverySnapshot().actions[0]!;
			expect(recovered.id).toBe(action.id);
			expect(recovered.agentMessageId).toBe(action.agentMessageId);
			expect(recovered.delivery).toBe("next_turn_boundary");
			expect(restored.session.queuedActionCount).toBe(0);
			let requests = 0;
			restored.setResponses([
				(context) => {
					requests++;
					expect(context.messages.map(getMessageText).join("\n")).toContain("notification recovered");
					return fauxAssistantMessage("received");
				},
			]);
			restoredPause.release();
			await restored.session.waitForIdle();
			expect(requests).toBe(1);
		} finally {
			original.session.requestAbort();
			originalPause.release();
			restoredPause.release();
		}
	});
	it("does not classify an uncorrelated lookalike user draft as a notification", async () => {
		const harness = await createHarness({ tools: [] });
		harnesses.push(harness);
		const pause = harness.session.acquireQueuedWorkPause();
		try {
			const text = agentPrompt("lookalike");
			await harness.session.followUp(text);
			expect(harness.session.getFollowUpMessages()).toEqual([text]);
			expect(harness.session.queuedActionCount).toBe(1);
			expect(harness.session.clearQueue()).toEqual({ steering: [], followUp: [text] });
		} finally {
			pause.release();
		}
	});
});
