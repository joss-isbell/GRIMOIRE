import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { DiagnosticJournalEmitter } from "../src/modes/daemon/diagnostic-journal-emitter.js";
import { shouldRecordSupervisorLaunch } from "../src/modes/daemon/incident-recorder.js";

describe("native diagnostic journal admission", () => {
	it("keeps native capture exclusive of the legacy recorder", () => {
		expect(shouldRecordSupervisorLaunch(["--mode", "daemon"], { PRIME_AGENT_DIAGNOSTICS: "native" })).toBe(false);
		expect(shouldRecordSupervisorLaunch(["--mode", "daemon"], {})).toBe(true);
	});
	it("bounds queued bytes and reports drops without claiming durable delivery", async () => {
		const lines: Buffer[] = [];
		const callbacks: (() => void)[] = [];
		const sink = new Writable({
			write(chunk: Buffer, _encoding, callback) {
				lines.push(Buffer.from(chunk));
				callbacks.push(callback);
			},
		});
		const emitter = new DiagnosticJournalEmitter(sink, { maxQueuedBytes: 2048 });
		try {
			let rejected = 0;
			for (let index = 0; index < 100; index++)
				if (!emitter.emit("kernel_channel_fault", { index }).accepted) rejected++;
			expect(rejected).toBeGreaterThan(0);
			expect(sink.writableLength).toBeLessThanOrEqual(2048);
			while (callbacks.length) callbacks.shift()!();
			const result = emitter.emit("kernel_ready", { kernelInstanceId: "original" });
			expect(result).toMatchObject({ accepted: true, disposition: "locally_admitted" });
			while (callbacks.length) callbacks.shift()!();
			await emitter.flush();
			const event = JSON.parse(lines.at(-1)!.toString("utf8"));
			expect(event).toMatchObject({
				schema: "prime-agent.diagnostic.v1",
				type: "kernel_ready",
				delivery: "queue_accepted",
				loss: { droppedRecords: rejected },
			});
			expect(event).not.toHaveProperty("durablyStored");
		} finally {
			emitter.close();
			sink.destroy();
		}
	});
	it("never invokes diagnostic getters and survives a failed destination", () => {
		let called = false;
		const sink = new Writable({
			write(_chunk, _encoding, callback) {
				callback(new Error("destination gone"));
			},
		});
		const emitter = new DiagnosticJournalEmitter(sink);
		const result = emitter.emit("kernel_lifecycle_intent", {
			get secret() {
				called = true;
				throw new Error("getter");
			},
		});
		expect(result.accepted).toBe(true);
		expect(called).toBe(false);
		expect(emitter.emit("kernel_ready", {}).accepted).toBe(false);
		emitter.close();
	});
});
