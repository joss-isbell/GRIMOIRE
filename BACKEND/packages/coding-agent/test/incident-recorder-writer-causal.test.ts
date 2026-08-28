import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { recordIncidentRecorderCausalEvent } from "../src/modes/daemon/incident-recorder.js";
import { INCIDENT_RECORDER_RUN_DIR_ENV } from "../src/modes/daemon/incident-recorder-env.js";
import {
	configureIncidentCaptureEmitter,
	emitIncidentDerived,
	IncidentRecorderWriter,
	stopIncidentCaptureEmitter,
} from "../src/modes/daemon/incident-recorder-writer.js";

const roots: string[] = [];
const originalRunDir = process.env[INCIDENT_RECORDER_RUN_DIR_ENV];

afterEach(async () => {
	await stopIncidentCaptureEmitter();
	if (originalRunDir === undefined) delete process.env[INCIDENT_RECORDER_RUN_DIR_ENV];
	else process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = originalRunDir;
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): string {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-causal-writer-"));
	roots.push(root);
	process.env[INCIDENT_RECORDER_RUN_DIR_ENV] = root;
	return root;
}

function timeline(root: string): Array<Record<string, unknown>> {
	const path = join(root, "timeline.jsonl");
	if (!existsSync(path)) return [];
	return readFileSync(path, "utf8")
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe("bounded causal event writer", () => {
	it("writes one bounded structured event directly without an inherited fd channel", async () => {
		const root = fixture();
		expect(configureIncidentCaptureEmitter()).toBe(true);
		const admission = emitIncidentDerived("supervisor-events", "worker_request_end", {
			requestType: "get_state",
			outcome: "timeout",
			durationMs: 25,
		});
		expect(admission.accepted).toBe(true);
		await stopIncidentCaptureEmitter();
		expect(timeline(root)).toContainEqual(
			expect.objectContaining({
				type: "worker_request_end",
				requestType: "get_state",
				outcome: "timeout",
				durationMs: 25,
				producerPid: process.pid,
			}),
		);
	});

	it("rejects raw or non-causal fields and never invokes getters", async () => {
		const root = fixture();
		expect(configureIncidentCaptureEmitter()).toBe(true);
		let getterCalls = 0;
		const fields: Record<string, unknown> = {
			message: "secret-in-innocent-field",
			SECRET_ACCESS_TOKEN: "secret-token",
			outcome: "timeout",
			pid: 1,
			producerPid: 1,
			occurrenceId: 123,
			source: true,
		};
		Object.defineProperty(fields, "dangerous", {
			enumerable: true,
			get() {
				getterCalls += 1;
				throw new Error("getter must not run");
			},
		});
		expect(emitIncidentDerived("supervisor-events", "worker_request_end", fields).accepted).toBe(true);
		expect(emitIncidentDerived("supervisor-events", "supervisor_log_record", { outcome: "ignored" }).accepted).toBe(
			false,
		);
		await stopIncidentCaptureEmitter();
		const text = readFileSync(join(root, "timeline.jsonl"), "utf8");
		expect(getterCalls).toBe(0);
		expect(text).not.toContain("secret-in-innocent-field");
		expect(text).not.toContain("secret-token");
		expect(text).not.toContain("supervisor_log_record");
		const event = timeline(root)[0];
		expect(event.pid).toBe(process.pid);
		expect(event.producerPid).toBe(process.pid);
		expect(event.source).toBe("supervisor-events");
		expect(event.occurrenceId).toBeTypeOf("string");
	});

	it("keeps trusted correlation fields in bounded fallback records", () => {
		const root = fixture();
		const occurrenceId = "458850f5-1a15-4680-9fb8-e3ee5e48ad3d";
		const largeFields = Object.fromEntries(
			Array.from({ length: 64 }, (_, index) => [`counter${index}`, Array.from({ length: 32 }, () => index)]),
		);
		expect(
			recordIncidentRecorderCausalEvent(root, "supervisor_exit", {
				...largeFields,
				occurrenceId,
				source: "supervisor-events",
			}),
		).toBe(true);
		expect(timeline(root)).toContainEqual(
			expect.objectContaining({
				type: "supervisor_exit",
				occurrenceId,
				source: "supervisor-events",
				fieldsTruncated: true,
			}),
		);
	});

	it("normalizes the source in an oversized direct-emitter fallback", async () => {
		const root = fixture();
		expect(configureIncidentCaptureEmitter()).toBe(true);
		const largeFields = Object.fromEntries(
			Array.from({ length: 64 }, (_, index) => [`counter${index}`, Array.from({ length: 16 }, () => index)]),
		);
		expect(emitIncidentDerived("untrusted-source", "worker_request_end", largeFields).accepted).toBe(true);
		await stopIncidentCaptureEmitter();
		expect(timeline(root)).toContainEqual(
			expect.objectContaining({
				type: "worker_request_end",
				source: "recorder-events",
				fieldsTruncated: true,
			}),
		);
	});

	it("fails open when the durable wrapper sink rejects or throws", () => {
		const rejectedWriter = new IncidentRecorderWriter({
			runDir: "/not-used",
			onStructuredEvent: () => false,
		});
		expect(rejectedWriter.recordDerived("recorder-events", "supervisor_exit", { signal: "SIGKILL" }).accepted).toBe(
			false,
		);
		const throwingWriter = new IncidentRecorderWriter({
			runDir: "/not-used",
			onStructuredEvent: () => {
				throw new Error("sink unavailable");
			},
		});
		expect(throwingWriter.recordDerived("recorder-events", "supervisor_exit", {}).accepted).toBe(false);
		expect(
			throwingWriter.recordExactBytes("recorder-events", "raw", Buffer.from("secret"), "binary", {}).accepted,
		).toBe(false);
	});
});
