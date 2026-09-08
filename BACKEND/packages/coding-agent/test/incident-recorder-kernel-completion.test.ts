import { spawn } from "node:child_process";
import { closeSync, mkdtempSync, openSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { INCIDENT_RECORDER_RUN_DIR_ENV } from "../src/modes/daemon/incident-recorder.js";
import {
	decodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
	INCIDENT_RECORDER_RUN_ID_ENV,
	INCIDENT_RECORDER_RUN_TOKEN_ENV,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderTransportDecoder } from "../src/modes/daemon/incident-recorder-transport.js";
import {
	INCIDENT_RECORDER_CAPTURE_FD_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV,
	INCIDENT_RECORDER_ROOT_FD_ENV,
} from "../src/modes/daemon/incident-recorder-writer.js";

const RUN_ID = "99999999-9999-4999-8999-999999999999";
const RUN_TOKEN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const roots: string[] = [];

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function decodeCaptureWire(wire: Buffer): ReturnType<typeof decodeIncidentRecorderFrame>[] {
	const packets: Buffer[] = [];
	const corruptions: unknown[] = [];
	const decoder = new IncidentRecorderTransportDecoder(
		(packet) => packets.push(packet),
		(evidence) => corruptions.push(evidence),
	);
	decoder.push(wire);
	decoder.finish();
	expect(corruptions).toEqual([]);
	return packets.map((packet) => decodeIncidentRecorderFrame(packet));
}

async function runFixture(scenario: string, maximumBytes?: number) {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-kernel-completion-"));
	roots.push(root);
	const script = fileURLToPath(new URL("./fixtures/incident-recorder-kernel-completion.ts", import.meta.url));
	const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	const environment: NodeJS.ProcessEnv = {
		...process.env,
		[INCIDENT_RECORDER_CAPTURE_FD_ENV]: "4",
		[INCIDENT_RECORDER_ROOT_FD_ENV]: "5",
		[INCIDENT_RECORDER_RUN_ID_ENV]: RUN_ID,
		[INCIDENT_RECORDER_RUN_TOKEN_ENV]: RUN_TOKEN,
		[INCIDENT_RECORDER_RUN_DIR_ENV]: root,
		PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES: String(maximumBytes ?? 256 * 1024),
	};
	delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV];
	delete environment[INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV];
	const rootFd = openSync(root, "r");
	const child = spawn(process.execPath, ["--import", tsxLoader, script, scenario], {
		env: environment,
		stdio: ["ignore", "ignore", "pipe", "ignore", "pipe", rootFd],
	});
	closeSync(rootFd);
	const chunks: Buffer[] = [];
	const errors: Buffer[] = [];
	if (child.stdio[4]) child.stdio[4].on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
	if (child.stderr) child.stderr.on("data", (chunk: Buffer) => errors.push(Buffer.from(chunk)));
	const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
		child.once("error", reject);
		child.once("close", (code, signal) => resolve({ code, signal }));
	});
	expect(result, Buffer.concat(errors).toString("utf8")).toEqual({ code: 0, signal: null });
	return decodeCaptureWire(Buffer.concat(chunks));
}

function metadata(frame: ReturnType<typeof decodeIncidentRecorderFrame>) {
	return frame.header.metadata as Record<string, unknown>;
}

describe("kernel diagnostic producer completion", () => {
	it("orders exit, exact tail, nonterminal completion, and later ordinary records with correlated IDs", async () => {
		const frames = await runFixture("ordered");
		const relevant = frames.filter((frame) =>
			[
				"kernel_unexpected_exit",
				"kernel_stderr_tail",
				"kernel_diagnostic_capture_complete",
				"ordinary_after_kernel_completion",
			].includes(frame.header.type),
		);
		expect(relevant.map((frame) => frame.header.type)).toEqual([
			"kernel_unexpected_exit",
			"kernel_stderr_tail",
			"kernel_diagnostic_capture_complete",
			"ordinary_after_kernel_completion",
		]);
		const exit = relevant[0]!;
		const tail = relevant[1]!;
		const completion = relevant[2]!;
		expect(tail.payload).toEqual(Buffer.from([0x00, 0xff, 0x4b, 0x45, 0x4e, 0x45, 0x4c, 0x21]));
		expect(metadata(exit)).toMatchObject({ type: "kernel_unexpected_exit", kernelPid: 42425 });
		expect(metadata(tail)).toMatchObject({ type: "kernel_unexpected_exit", kernelPid: 42425 });
		expect(metadata(completion)).toMatchObject({
			type: "kernel_diagnostic_capture_complete",
			tailCaptureStatus: "admitted",
			sourceBytes: 8,
			retainedBytes: 8,
		});
		expect(metadata(completion).exitAdmissionReason).toBeUndefined();
		expect(metadata(completion).tailAdmissionReason).toBeUndefined();
		expect(completion.header.payloadKind).toBe("control");
		expect(completion.header.flags & INCIDENT_RECORDER_FRAME_FLAGS.terminal).toBe(0);
		expect(metadata(completion).exitOccurrenceId).toBe(exit.header.occurrenceId);
		expect(metadata(completion).tailOccurrenceId).toBe(tail.header.occurrenceId);
	});

	it("reports a pressured tail while reserving the completion control occurrence", async () => {
		const frames = await runFixture("tail-rejected");
		const exit = frames.find((frame) => frame.header.type === "kernel_unexpected_exit");
		const completion = frames.find((frame) => frame.header.type === "kernel_diagnostic_capture_complete");
		expect(exit).toBeDefined();
		expect(completion).toBeDefined();
		expect(metadata(completion!)).toMatchObject({
			type: "kernel_diagnostic_capture_complete",
			tailCaptureStatus: "rejected",
			tailAdmissionReason: "queue_capacity",
			sourceBytes: 512 * 1024,
			retainedBytes: 512 * 1024,
		});
		expect(metadata(completion!).exitOccurrenceId).toBe(exit!.header.occurrenceId);
		expect(metadata(completion!).tailOccurrenceId).toBeUndefined();
		expect(metadata(completion!).exitAdmissionReason).toBeUndefined();
	});

	it("marks an omitted or zero-retained tail as not required", async () => {
		const frames = await runFixture("no-tail");
		const completion = frames.find((frame) => frame.header.type === "kernel_diagnostic_capture_complete");
		expect(completion).toBeDefined();
		expect(metadata(completion!)).toMatchObject({
			type: "kernel_diagnostic_capture_complete",
			tailCaptureStatus: "not_required",
			sourceBytes: 0,
			retainedBytes: 0,
		});
		expect(metadata(completion!).exitAdmissionReason).toBeUndefined();
		expect(metadata(completion!).tailOccurrenceId).toBeUndefined();
		expect(metadata(completion!).tailAdmissionReason).toBeUndefined();
	});

	it("does not emit a success record when the completion admission is rejected", async () => {
		const frames = await runFixture("completion-rejected");
		expect(frames.some((frame) => frame.header.type === "kernel_diagnostic_capture_complete")).toBe(false);
		expect(frames.some((frame) => frame.header.type === "capture_channel_terminal")).toBe(true);
	});

	it("keeps a live emitter honest when reserved control capacity is saturated", async () => {
		const frames = await runFixture("control-saturated");
		expect(frames.some((frame) => frame.header.type.startsWith("reserved_fill_"))).toBe(true);
		expect(frames.some((frame) => frame.header.type === "kernel_unexpected_exit")).toBe(false);
		expect(frames.some((frame) => frame.header.type === "kernel_diagnostic_capture_complete")).toBe(false);
		const lossCheckpoint = frames.find((frame) => frame.header.type === "capture_channel_loss_checkpoint");
		const terminal = frames.find((frame) => frame.header.type === "capture_channel_terminal");
		expect(lossCheckpoint).toBeDefined();
		expect(terminal).toBeDefined();
		expect(Number(metadata(lossCheckpoint!).lostRecords)).toBeGreaterThan(0);
		expect(Number(metadata(terminal!).lostRecords)).toBeGreaterThan(0);
		expect(Number(metadata(terminal!).droppedRecords)).toBeGreaterThan(0);
	});

	it("does not claim kernel capture completion after the durable run seal is observed", async () => {
		const frames = await runFixture("sealed");
		expect(frames.some((frame) => frame.header.type === "kernel_unexpected_exit")).toBe(false);
		expect(frames.some((frame) => frame.header.type === "kernel_stderr_tail")).toBe(false);
		expect(frames.some((frame) => frame.header.type === "kernel_diagnostic_capture_complete")).toBe(false);
	});
});
