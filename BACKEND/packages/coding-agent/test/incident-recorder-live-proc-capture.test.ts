import { spawn } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getProcessStartId } from "../src/core/session-lease.js";
import {
	captureIncidentRecorderLiveProc,
	INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES,
	INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES,
	INCIDENT_RECORDER_LIVE_PROC_CAPTURE_SOURCE_NAMES,
	type IncidentRecorderLiveProcCaptureFileSystem,
	type IncidentRecorderLiveProcCaptureWriter,
} from "../src/modes/daemon/incident-recorder-live-proc-capture.js";
import {
	decodeIncidentRecorderFrame,
	type IncidentRecorderEncodedFrame,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const TARGET_PID = 7311;
const START_ID = "proc:731100";
const TRIGGER_ID = "33333333-3333-4333-8333-333333333333";
const CAPTURE_ID = "44444444-4444-4444-8444-444444444444";

const childProcesses: ReturnType<typeof spawn>[] = [];

afterEach(() => {
	for (const child of childProcesses.splice(0)) child.kill("SIGTERM");
});

class MapProcFileSystem implements IncidentRecorderLiveProcCaptureFileSystem {
	private readonly values = new Map<string, Buffer>();
	private readonly paths = new Map<number, string>();
	private readonly offsets = new Map<number, number>();
	private nextDescriptor = 10;
	readonly opened: number[] = [];
	readonly closed: number[] = [];
	readonly failReads = new Set<string>();
	readonly failAfterReads = new Map<string, number>();
	private readonly readCounts = new Map<string, number>();

	set(path: string, value: Uint8Array): void {
		this.values.set(path, Buffer.from(value));
	}

	openSync(path: string): number {
		if (!this.values.has(path)) throw new Error(`missing mocked proc path: ${path}`);
		const descriptor = this.nextDescriptor++;
		this.opened.push(descriptor);
		this.paths.set(descriptor, path);
		this.offsets.set(descriptor, 0);
		return descriptor;
	}

	fstatSync(): { isFile(): boolean } {
		return { isFile: () => true };
	}

	readSync(descriptor: number, buffer: Buffer, offset: number, length: number): number {
		const path = this.paths.get(descriptor);
		const value = path === undefined ? undefined : this.values.get(path);
		if (!value) throw new Error("unknown mocked proc descriptor");
		const readCount = (this.readCounts.get(path ?? "") ?? 0) + 1;
		this.readCounts.set(path ?? "", readCount);
		if (
			this.failReads.has(path ?? "") ||
			readCount > (this.failAfterReads.get(path ?? "") ?? Number.POSITIVE_INFINITY)
		)
			throw new Error("mocked read failure");
		const position = this.offsets.get(descriptor) ?? 0;
		if (position >= value.length) return 0;
		const count = Math.min(length, value.length - position);
		value.copy(buffer, offset, position, position + count);
		this.offsets.set(descriptor, position + count);
		return count;
	}

	closeSync(descriptor: number): void {
		this.closed.push(descriptor);
	}
}

function sourcePath(index: number, pid = TARGET_PID): string {
	return `/proc/${pid}/${INCIDENT_RECORDER_LIVE_PROC_CAPTURE_SOURCE_NAMES[index].replace("{pid}", String(pid))}`;
}

function fixtureFs(value = Buffer.from("fixture\n")): MapProcFileSystem {
	const fs = new MapProcFileSystem();
	for (let index = 0; index < INCIDENT_RECORDER_LIVE_PROC_CAPTURE_SOURCE_NAMES.length; index += 1)
		fs.set(sourcePath(index), value);
	return fs;
}

function writerStub(
	admission: IncidentRecorderLiveProcCaptureWriter["recordExactBytesForRun"] = (_identity, _source, _type, bytes) => ({
		accepted: true,
		occurrenceId: `55555555-5555-4555-8555-${bytes.length.toString(16).padStart(12, "0")}`,
		disposition: "locally_admitted",
	}),
): IncidentRecorderLiveProcCaptureWriter {
	return { recordExactBytesForRun: admission };
}

function input(
	overrides: Partial<Parameters<typeof captureIncidentRecorderLiveProc>[0]> = {},
): Parameters<typeof captureIncidentRecorderLiveProc>[0] {
	return {
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		targetPid: TARGET_PID,
		targetProcessStartId: START_ID,
		pid: TARGET_PID,
		processStartId: START_ID,
		triggerOccurrenceId: TRIGGER_ID,
		captureId: CAPTURE_ID,
		writer: writerStub(),
		fileSystem: fixtureFs(),
		processStartIdReader: () => START_ID,
		now: () => 0,
		...overrides,
	};
}

describe("bounded live proc capture", () => {
	it("captures the fixed source set into actual service-writer frames with identity bindings", async () => {
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			serviceSink: true,
		});
		const selfStartId = getProcessStartId(process.pid);
		if (!selfStartId) throw new Error("test process has no Linux start identity");
		try {
			const result = captureIncidentRecorderLiveProc(
				input({
					pid: process.pid,
					targetPid: process.pid,
					processStartId: selfStartId,
					targetProcessStartId: selfStartId,
					writer,
					fileSystem: undefined,
					deadlineMs: 40,
					processStartIdReader: () => selfStartId,
				}),
			);
			expect(result.receipts.length).toBe(INCIDENT_RECORDER_LIVE_PROC_CAPTURE_SOURCE_NAMES.length);
			expect(result.complete).toBe(true);
			expect(result.receipts.every((receipt) => receipt.admitted)).toBe(true);
			for (let attempt = 0; attempt < 100; attempt += 1) {
				if ((writer as unknown as { relayQueue: unknown[] }).relayQueue.length > 0) break;
				await new Promise<void>((resolve) => setImmediate(resolve));
			}
			await new Promise<void>((resolve) => setTimeout(resolve, 25));

			const state = writer as unknown as { relayQueue: Array<{ frames: readonly IncidentRecorderEncodedFrame[] }> };
			const frames = state.relayQueue.flatMap((occurrence) => occurrence.frames);
			const statusFrame = frames.find((frame) => frame.header.metadata.sourcePath === `/proc/${process.pid}/status`);
			expect(statusFrame).toBeDefined();
			if (!statusFrame) throw new Error("status frame was not queued");
			const decoded = decodeIncidentRecorderFrame(Buffer.concat(statusFrame.parts));
			expect(decoded.header.source).toBe("linux-raw-source");
			expect(decoded.header.type).toBe("live_proc_source_snapshot");
			expect(decoded.header.encoding).toBe("exact-file-bytes");
			expect(decoded.header.metadata).toMatchObject({
				pid: process.pid,
				processStartId: selfStartId,
				targetPid: process.pid,
				targetProcessStartId: selfStartId,
				triggerOccurrenceId: TRIGGER_ID,
				captureId: CAPTURE_ID,
				state: "complete",
				sourceTruncated: false,
			});
			expect(decoded.payload.toString("utf8")).toContain("Name:");
		} finally {
			await writer.stop(25);
		}
	});

	it("captures a recognizable isolated child cmdline and environment without dumping test-only data", async () => {
		const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
			env: { PATH: process.env.PATH ?? "", GRIMOIRE_LIVE_PROC_CAPTURE_FIXTURE: "fixture-marker" },
		});
		childProcesses.push(child);
		await new Promise<void>((resolve, reject) => {
			child.once("spawn", () => resolve());
			child.once("error", reject);
		});
		const processStartId = getProcessStartId(child.pid ?? 0);
		expect(processStartId).toBeDefined();
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			serviceSink: true,
		});
		try {
			const result = captureIncidentRecorderLiveProc({
				...input(),
				pid: child.pid ?? 0,
				targetPid: child.pid ?? 0,
				processStartId: processStartId ?? "missing",
				targetProcessStartId: processStartId ?? "missing",
				writer,
				fileSystem: undefined,
				processStartIdReader: () => processStartId,
			});
			expect(result.complete).toBe(true);
			expect(result.receipts.find((receipt) => receipt.sourceName === "cmdline")?.admitted).toBe(true);
			expect(result.receipts.find((receipt) => receipt.sourceName === "environ")?.admitted).toBe(true);
			const state = writer as unknown as { relayQueue: Array<{ frames: readonly IncidentRecorderEncodedFrame[] }> };
			let frames: IncidentRecorderEncodedFrame[] = [];
			for (let attempt = 0; attempt < 100; attempt += 1) {
				frames = state.relayQueue.flatMap((occurrence) => occurrence.frames);
				if (
					frames.some((frame) => frame.header.metadata.sourcePath?.toString().endsWith("/cmdline")) &&
					frames.some((frame) => frame.header.metadata.sourcePath?.toString().endsWith("/environ")) &&
					frames.some((frame) => frame.header.metadata.sourcePath?.toString().endsWith("/limits"))
				)
					break;
				await new Promise<void>((resolve) => setTimeout(resolve, 1));
			}
			const decodeSource = (name: string): ReturnType<typeof decodeIncidentRecorderFrame> => {
				const frame = frames.find((candidate) =>
					candidate.header.metadata.sourcePath?.toString().endsWith(`/${name}`),
				);
				if (!frame) throw new Error(`missing actual service-writer frame for ${name}`);
				return decodeIncidentRecorderFrame(Buffer.concat(frame.parts));
			};
			const cmdline = decodeSource("cmdline");
			const environ = decodeSource("environ");
			const limits = decodeSource("limits");
			expect(cmdline.payload.toString("utf8")).toContain("-e");
			expect(environ.payload.toString("utf8")).toContain("GRIMOIRE_LIVE_PROC_CAPTURE_FIXTURE=fixture-marker");
			expect(limits.payload.toString("utf8")).toContain("Max open files");
			expect(environ.header.metadata).toMatchObject({
				pid: child.pid,
				processStartId,
				targetPid: child.pid,
				targetProcessStartId: processStartId,
				triggerOccurrenceId: TRIGGER_ID,
				captureId: CAPTURE_ID,
			});
		} finally {
			await writer.stop(25);
			child.kill("SIGTERM");
		}
	});

	it("fails closed before admission when the PID has the wrong or missing start identity", () => {
		const record = vi.fn(() => ({
			accepted: true as const,
			occurrenceId: CAPTURE_ID,
			disposition: "locally_admitted" as const,
		}));
		const result = captureIncidentRecorderLiveProc(
			input({ writer: writerStub(record), processStartIdReader: () => "proc:successor" }),
		);
		expect(result.complete).toBe(false);
		expect(result.reason).toBe("identity_changed");
		expect(result.receipts[0]).toMatchObject({ reason: "identity_changed", admitted: false });
		expect(record).not.toHaveBeenCalled();
	});

	it("discards bytes when the subject identity changes after a read", () => {
		const record = vi.fn(() => ({
			accepted: true as const,
			occurrenceId: CAPTURE_ID,
			disposition: "locally_admitted" as const,
		}));
		let identityChecks = 0;
		const result = captureIncidentRecorderLiveProc(
			input({
				writer: writerStub(record),
				processStartIdReader: () => {
					identityChecks += 1;
					return identityChecks === 1 ? START_ID : "proc:successor";
				},
			}),
		);
		expect(result.bytesRead).toBeGreaterThan(0);
		expect(result.receipts[0]).toMatchObject({
			reason: "identity_changed",
			retainedBytes: 0,
			admitted: false,
		});
		expect(record).not.toHaveBeenCalled();
	});

	it("shares one byte budget across files and returns a continuation without claiming completion", () => {
		const fs = fixtureFs(Buffer.from("0123456789"));
		const record = vi.fn(() => ({
			accepted: true as const,
			occurrenceId: CAPTURE_ID,
			disposition: "locally_admitted" as const,
		}));
		const result = captureIncidentRecorderLiveProc(
			input({ fileSystem: fs, writer: writerStub(record), byteBudget: 5 }),
		);
		expect(result.bytesRead).toBe(5);
		expect(result.nextSourceIndex).toBe(0);
		expect(result.complete).toBe(false);
		expect(result.reason).toBe("byte_budget");
		expect(result.receipts[0]).toMatchObject({
			bytesRead: 5,
			retainedBytes: 5,
			reason: "byte_budget",
			admitted: true,
		});
		expect(record).toHaveBeenCalledTimes(1);
	});

	it("checks the monotonic deadline before admission but keeps useful already-read bytes", () => {
		let clockReads = 0;
		const record = vi.fn(() => ({
			accepted: true as const,
			occurrenceId: CAPTURE_ID,
			disposition: "locally_admitted" as const,
		}));
		const result = captureIncidentRecorderLiveProc(
			input({
				writer: writerStub(record),
				deadlineMs: 40,
				now: () => {
					clockReads += 1;
					return clockReads < 4 ? 0 : 100;
				},
			}),
		);
		expect(result.complete).toBe(false);
		expect(result.nextSourceIndex).toBe(0);
		expect(result.reason).toBe("deadline");
		expect(result.receipts[0]).toMatchObject({ reason: "deadline", admitted: true, truncated: true });
		expect(clockReads).toBeGreaterThanOrEqual(5);
	});

	it("marks an oversized maps prefix truncated after bounded lookahead", async () => {
		const fs = fixtureFs();
		const mapsIndex = INCIDENT_RECORDER_LIVE_PROC_CAPTURE_SOURCE_NAMES.indexOf("maps");
		if (mapsIndex < 0) throw new Error("maps source is missing");
		fs.set(sourcePath(mapsIndex), Buffer.alloc(INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES + 1, 0x6d));
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			serviceSink: true,
		});
		try {
			const result = captureIncidentRecorderLiveProc(input({ nextSourceIndex: mapsIndex, fileSystem: fs, writer }));
			const receipt = result.receipts[0];
			expect(receipt).toMatchObject({
				sourceIndex: mapsIndex,
				sourceName: "maps",
				sourcePath: sourcePath(mapsIndex),
				retainedBytes: INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES,
				bytesRead: INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES + 1,
				truncated: true,
				coverageState: "truncated",
				reason: "truncated",
			});
			expect(result.complete).toBe(false);
			expect(result.reason).toBe("truncated");
			for (let attempt = 0; attempt < 100; attempt += 1) {
				if ((writer as unknown as { relayQueue: unknown[] }).relayQueue.length > 0) break;
				await new Promise<void>((resolve) => setImmediate(resolve));
			}
			const state = writer as unknown as { relayQueue: Array<{ frames: readonly IncidentRecorderEncodedFrame[] }> };
			const frames = state.relayQueue.flatMap((occurrence) => occurrence.frames);
			const mapsFrames = frames.filter((frame) => frame.header.metadata.sourcePath === sourcePath(mapsIndex));
			expect(mapsFrames.length).toBeGreaterThan(1);
			const decodedMapsFrames = mapsFrames.map((frame) => decodeIncidentRecorderFrame(Buffer.concat(frame.parts)));
			expect(decodedMapsFrames.every((decoded) => decoded.header.source === "linux-raw-source")).toBe(true);
			expect(decodedMapsFrames.every((decoded) => decoded.header.type === "live_proc_source_snapshot")).toBe(true);
			expect(
				decodedMapsFrames.every((decoded) => decoded.header.metadata.sourcePath === sourcePath(mapsIndex)),
			).toBe(true);
			expect(decodedMapsFrames[0]?.header.metadata).toMatchObject({
				state: "truncated",
				sourceTruncated: true,
				retainedBytes: INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES,
				reason: "truncated",
			});
			expect(Buffer.concat(decodedMapsFrames.map((decoded) => decoded.payload))).toEqual(
				Buffer.alloc(INCIDENT_RECORDER_LIVE_PROC_CAPTURE_MAX_SOURCE_BYTES, 0x6d),
			);
		} finally {
			await writer.stop(25);
		}
	});

	it("keeps queue rejection explicit and continues using the normal writer", () => {
		const record = vi
			.fn()
			.mockImplementationOnce(() => ({
				accepted: false as const,
				disposition: "rejected" as const,
				reason: "queue_capacity" as const,
			}))
			.mockImplementation(() => ({
				accepted: true as const,
				occurrenceId: CAPTURE_ID,
				disposition: "locally_admitted" as const,
			}));
		const result = captureIncidentRecorderLiveProc(input({ writer: writerStub(record) }));
		expect(record).toHaveBeenCalledTimes(INCIDENT_RECORDER_LIVE_PROC_CAPTURE_SOURCE_NAMES.length);
		expect(result.receipts[0]).toMatchObject({ admitted: false, reason: "queue_rejection" });
		expect(result.receipts[0].admission).toMatchObject({
			disposition: "rejected",
			reason: "queue_rejection",
			writerReason: "queue_capacity",
		});
		expect(result.complete).toBe(false);
	});

	it("closes every descriptor, including a read failure", () => {
		const fs = fixtureFs();
		fs.failReads.add(sourcePath(0));
		const result = captureIncidentRecorderLiveProc(input({ fileSystem: fs }));
		expect(fs.closed).toEqual(fs.opened);
		expect(result.receipts[0]).toMatchObject({
			reason: "read_failed",
			admitted: false,
			truncated: false,
			coverageState: "unavailable",
			coverage: { state: "unavailable", retainedBytes: 0, truncated: false, reason: "read_failed" },
		});
	});

	it("retains and admits a partial prefix when a later read fails", () => {
		const fs = fixtureFs();
		const path = sourcePath(0);
		fs.set(path, Buffer.alloc(INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES + 1, 0x70));
		fs.failAfterReads.set(path, 1);
		const record = vi.fn<IncidentRecorderLiveProcCaptureWriter["recordExactBytesForRun"]>(
			(_identity, _source, _type, _bytes, _encoding, _metadata) => ({
				accepted: true,
				occurrenceId: CAPTURE_ID,
				disposition: "locally_admitted",
			}),
		);
		const result = captureIncidentRecorderLiveProc(input({ fileSystem: fs, writer: writerStub(record) }));
		expect(fs.closed).toEqual(fs.opened);
		expect(result.receipts[0]).toMatchObject({
			reason: "read_failed",
			admitted: true,
			truncated: true,
			coverageState: "truncated",
			bytesRead: INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES,
			retainedBytes: INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES,
			coverage: {
				state: "truncated",
				retainedBytes: INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES,
				truncated: true,
				reason: "read_failed",
			},
		});
		expect(record).toHaveBeenCalled();
		expect(record.mock.calls[0]?.[3]).toEqual(Buffer.alloc(INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES, 0x70));
		expect(record.mock.calls[0]?.[5]).toMatchObject({
			sourcePath: path,
			state: "truncated",
			sourceTruncated: true,
			retainedBytes: INCIDENT_RECORDER_LIVE_PROC_CAPTURE_CHUNK_BYTES,
			reason: "read_failed",
		});
	});
});
