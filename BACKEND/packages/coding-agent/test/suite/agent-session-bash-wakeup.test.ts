import { fauxAssistantMessage } from "@earendil-works/pi-ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ExtensionRunner } from "../../src/core/extensions/runner.js";
import type { BashOperations } from "../../src/core/tools/bash.js";
import { createHarness, getUserTexts, type Harness } from "./harness.js";
import { createDeferred } from "./scheduling.js";

function agentPrompt(id: string): string {
	return `Agent-to-agent message received.\nSource: agent_message\nTo: Target, active target, session session-target\nMessage id: ${id}\n\nqueued during shell execution`;
}

function watchDelivery(harness: Harness, id: string) {
	const delivered = vi.fn();
	void harness.session.waitForAgentMessagePromptDelivery(id).then(delivered, () => undefined);
	return delivered;
}

describe("AgentSession bash queue wake-up", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		vi.restoreAllMocks();
		for (const harness of harnesses.splice(0)) harness.cleanup();
	});

	for (const schedule of ["steer", "followUp"] as const) {
		it.each(["success", "nonzero", "cancelled", "failed", "transient"] as const)(
			`delivers ${schedule} after direct shell %s without another input`,
			async (outcome) => {
				const started = createDeferred();
				const release = createDeferred();
				const operations: BashOperations = {
					exec: async (_command, _cwd, options) => {
						started.resolve();
						await release.promise;
						if (outcome === "failed") throw new Error("shell failed");
						if (options.signal?.aborted) throw new Error("shell cancelled");
						return { exitCode: outcome === "nonzero" ? 1 : 0 };
					},
				};
				const harness = await createHarness();
				harnesses.push(harness);
				harness.setResponses([fauxAssistantMessage("received")]);
				const id = `agentmsg_direct_${schedule}_${outcome}`;
				const prompt = agentPrompt(id);
				const delivered = watchDelivery(harness, id);

				const run = harness.session.executeBash("gated shell", undefined, {
					operations,
					transient: outcome === "transient",
				});
				const settled = run.catch((error: unknown) => error);
				await started.promise;
				await harness.session.queueAgentMessagePrompt(prompt, schedule);
				expect(harness.session.queuedActionCount).toBe(1);
				expect(delivered).not.toHaveBeenCalled();
				if (outcome === "cancelled") harness.session.abortBash();
				release.resolve();
				const result = await settled;
				if (outcome === "failed") expect(result).toEqual(new Error("shell failed"));
				else expect(result).toMatchObject({ cancelled: outcome === "cancelled" });

				// Session.waitForIdle() itself pumps the queue and would hide a missing wake-up.
				await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce(), { timeout: 1000 });
				await harness.session.waitForIdle();
				expect(harness.session.queuedActionCount).toBe(0);
				expect(getUserTexts(harness)).toEqual([prompt]);
				expect(harness.session.messages.filter((message) => message.role === "bashExecution")).toHaveLength(
					outcome === "transient" || outcome === "failed" ? 0 : 1,
				);
			},
		);

		it(`delivers ${schedule} when user-bash dispatch rejects before execution`, async () => {
			const started = createDeferred();
			const release = createDeferred();
			const harness = await createHarness();
			harnesses.push(harness);
			harness.setResponses([fauxAssistantMessage("received")]);
			// Infrastructure dispatch failure, not a handled user_bash extension error.
			vi.spyOn(ExtensionRunner.prototype, "emitUserBash").mockImplementationOnce(async () => {
				started.resolve();
				await release.promise;
				throw new Error("dispatch unavailable");
			});
			const id = `agentmsg_dispatch_${schedule}`;
			const delivered = watchDelivery(harness, id);
			const run = harness.session.runUserBash("never started");
			const settled = run.catch((error: unknown) => error);
			await started.promise;
			await harness.session.queueAgentMessagePrompt(agentPrompt(id), schedule);
			expect(harness.session.isBashRunning).toBe(true);
			release.resolve();
			expect(await settled).toEqual(new Error("dispatch unavailable"));
			expect(harness.session.isBashRunning).toBe(false);
			await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce(), { timeout: 1000 });
			await harness.session.waitForIdle();
			expect(harness.eventsOfType("bash_start")).toHaveLength(0);
			expect(harness.eventsOfType("bash_end")).toHaveLength(0);
		});
	}

	it.each(["pause", "abort"] as const)("does not bypass an explicit %s after shell completion", async (barrier) => {
		const started = createDeferred();
		const release = createDeferred();
		const harness = await createHarness();
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("received")]);
		const id = `agentmsg_barrier_${barrier}`;
		const delivered = watchDelivery(harness, id);
		const run = harness.session.executeBash("gated shell", undefined, {
			operations: {
				exec: async () => {
					started.resolve();
					await release.promise;
					return { exitCode: 0 };
				},
			},
		});
		await started.promise;
		await harness.session.queueAgentMessagePrompt(agentPrompt(id), "steer");
		const pause = barrier === "pause" ? harness.session.acquireQueuedWorkPause() : undefined;
		if (barrier === "abort") harness.session.requestAbort();
		release.resolve();
		await run;
		await new Promise<void>((resolve) => setImmediate(resolve));
		expect(delivered).not.toHaveBeenCalled();
		expect(harness.session.queuedActionCount).toBe(1);
		if (pause) pause.release();
		else harness.session.resumeQueuedWork();
		await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce(), { timeout: 1000 });
		await harness.session.waitForIdle();
	});

	it("emits user bash_end before delivering queued work and runs the message only once", async () => {
		const started = createDeferred();
		const release = createDeferred();
		const harness = await createHarness({
			extensionFactories: [
				(pi) => {
					pi.on("user_bash", async () => ({
						operations: {
							exec: async () => {
								started.resolve();
								await release.promise;
								return { exitCode: 0 };
							},
						},
					}));
				},
			],
		});
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("received")]);
		const id = "agentmsg_bash_end_order";
		const delivered = watchDelivery(harness, id);
		const run = harness.session.runUserBash("gated shell");
		await started.promise;
		await harness.session.queueAgentMessagePrompt(agentPrompt(id), "steer");
		release.resolve();
		await run;
		await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce(), { timeout: 1000 });
		await harness.session.waitForIdle();
		expect(harness.events.findIndex((event) => event.type === "bash_end")).toBeLessThan(
			harness.events.findIndex((event) => event.type === "message_start" && event.message.role === "user"),
		);
		expect(getUserTexts(harness)).toEqual([agentPrompt(id)]);
		expect(harness.eventsOfType("agent_start")).toHaveLength(1);
	});

	it.each([0, 1])("waits for every overlapping direct shell when command %i finishes first", async (first) => {
		const releases = [createDeferred(), createDeferred()];
		const harness = await createHarness();
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("received")]);
		const id = `agentmsg_overlap_${first}`;
		const delivered = watchDelivery(harness, id);
		const runs = releases.map((release, index) =>
			harness.session.executeBash(`shell ${index}`, undefined, {
				operations: {
					exec: async () => {
						await release.promise;
						return { exitCode: 0 };
					},
				},
			}),
		);
		await harness.session.queueAgentMessagePrompt(agentPrompt(id), "steer");
		try {
			releases[first].resolve();
			await runs[first];
			await new Promise<void>((resolve) => setImmediate(resolve));
			expect(harness.session.isBashRunning).toBe(true);
			expect(delivered).not.toHaveBeenCalled();
			expect(harness.session.queuedActionCount).toBe(1);
		} finally {
			for (const release of releases) release.resolve();
			await Promise.all(runs);
		}
		await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce(), { timeout: 1000 });
		await harness.session.waitForIdle();
		expect(harness.session.isBashRunning).toBe(false);
		expect(getUserTexts(harness)).toEqual([agentPrompt(id)]);
		expect(harness.session.messages.filter((message) => message.role === "bashExecution")).toHaveLength(2);
	});

	it("cancels every overlapping direct shell without releasing busy state early", async () => {
		const releases = [createDeferred(), createDeferred()];
		const signals: Array<AbortSignal | undefined> = [];
		const harness = await createHarness();
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("received")]);
		const id = "agentmsg_overlap_abort";
		const delivered = watchDelivery(harness, id);
		const runs = releases.map((release, index) =>
			harness.session.executeBash(`shell ${index}`, undefined, {
				operations: {
					exec: async (_command, _cwd, options) => {
						signals.push(options.signal);
						await release.promise;
						return { exitCode: 0 };
					},
				},
			}),
		);
		await harness.session.queueAgentMessagePrompt(agentPrompt(id), "steer");
		try {
			harness.session.abortBash();
			expect(signals).toHaveLength(2);
			expect(signals.every((signal) => signal?.aborted)).toBe(true);
			expect(harness.session.isBashRunning).toBe(true);
			expect(delivered).not.toHaveBeenCalled();
		} finally {
			for (const release of releases) release.resolve();
			await Promise.all(runs);
		}
		for (const result of await Promise.all(runs)) expect(result.cancelled).toBe(true);
		await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce(), { timeout: 1000 });
		await harness.session.waitForIdle();
		expect(harness.session.isBashRunning).toBe(false);
	});

	it("honors a user-shell abort during dispatch even with another direct shell running", async () => {
		const dispatchStarted = createDeferred();
		const releaseDispatch = createDeferred();
		const releaseDirect = createDeferred();
		const execUser = vi.fn(async () => ({ exitCode: 0 }));
		const harness = await createHarness({
			extensionFactories: [
				(pi) => {
					pi.on("user_bash", async () => {
						dispatchStarted.resolve();
						await releaseDispatch.promise;
						return { operations: { exec: execUser } };
					});
				},
			],
		});
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("received")]);
		const userRun = harness.session.runUserBash("must not spawn");
		await dispatchStarted.promise;
		const directRun = harness.session.executeBash("direct shell", undefined, {
			operations: {
				exec: async () => {
					await releaseDirect.promise;
					return { exitCode: 0 };
				},
			},
		});
		const id = "agentmsg_dispatch_overlap_abort";
		const delivered = watchDelivery(harness, id);
		await harness.session.queueAgentMessagePrompt(agentPrompt(id), "steer");
		try {
			harness.session.abortBash();
			releaseDispatch.resolve();
			await userRun;
			expect(execUser).not.toHaveBeenCalled();
			expect(harness.eventsOfType("bash_end")[0]).toMatchObject({ cancelled: true });
			expect(harness.session.isBashRunning).toBe(true);
			expect(delivered).not.toHaveBeenCalled();
		} finally {
			releaseDispatch.resolve();
			releaseDirect.resolve();
			await Promise.all([userRun, directRun]);
		}
		await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce(), { timeout: 1000 });
		await harness.session.waitForIdle();
	});

	it("releases the shell slot and wakes pending work when shell configuration throws", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("received")]);
		const id = "agentmsg_shell_config_failure";
		const delivered = watchDelivery(harness, id);
		await harness.session.queueAgentMessagePrompt(agentPrompt(id), "steer");
		vi.spyOn(harness.session.settingsManager, "getShellPath").mockImplementationOnce(() => {
			throw new Error("shell configuration unavailable");
		});
		await expect(harness.session.executeBash("not executed")).rejects.toThrow("shell configuration unavailable");
		expect(harness.session.isBashRunning).toBe(false);
		await vi.waitFor(() => expect(delivered).toHaveBeenCalledOnce(), { timeout: 1000 });
		await harness.session.waitForIdle();
	});
});
