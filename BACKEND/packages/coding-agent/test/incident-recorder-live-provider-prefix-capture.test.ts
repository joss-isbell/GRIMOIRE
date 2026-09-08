import { execFileSync } from "node:child_process";
import {
	appendFileSync,
	closeSync,
	fstatSync,
	mkdtempSync,
	openSync,
	readSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	captureIncidentRecorderLiveProviderPrefix,
	INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_ARTIFACTS,
	INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES,
	type IncidentRecorderLiveProviderArtifact,
	type IncidentRecorderLiveProviderPrefixCaptureFileSystem,
	type IncidentRecorderLiveProviderPrefixCaptureStat,
	type IncidentRecorderLiveProviderPrefixCaptureWriter,
} from "../src/modes/daemon/incident-recorder-live-provider-prefix-capture.js";
import {
	decodeIncidentRecorderFrame,
	type IncidentRecorderEncodedFrame,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const TRIGGER_ID = "33333333-3333-4333-8333-333333333333";
const CAPTURE_ID = "44444444-4444-4444-8444-444444444444";
const TARGET_PID = 7311;
const TARGET_START = "proc:731100";
const roots: string[] = [];

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

type FixtureStat = IncidentRecorderLiveProviderPrefixCaptureStat;

function stat(dev: bigint, ino: bigint, size: bigint, mtimeNs: bigint, regular = true): FixtureStat {
	return { dev, ino, size, mtimeNs, isFile: () => regular };
}

class FixtureFileSystem implements IncidentRecorderLiveProviderPrefixCaptureFileSystem {
	readonly flags: number[] = [];
	readonly opened: number[] = [];
	readonly closed: number[] = [];
	readonly readCalls: number[] = [];
	private readonly values = new Map<string, Buffer>();
	private readonly paths = new Map<number, string>();
	private readonly offsets = new Map<number, number>();
	private readonly statSequences = new Map<string, FixtureStat[]>();
	private readonly statCalls = new Map<string, number>();
	private nextFd = 100;
	readFailure = false;

	set(
		path: string,
		value: Uint8Array,
		stats: readonly FixtureStat[] = [stat(1n, 2n, BigInt(value.byteLength), 3n)],
	): void {
		this.values.set(path, Buffer.from(value));
		this.statSequences.set(path, [...stats]);
	}

	openSync(path: string, flags: number): number {
		if (!this.values.has(path)) throw new Error("fixture path missing");
		this.flags.push(flags);
		const fd = this.nextFd++;
		this.opened.push(fd);
		this.paths.set(fd, path);
		this.offsets.set(fd, 0);
		return fd;
	}

	fstatSync(fd: number): FixtureStat {
		const path = this.paths.get(fd);
		if (!path) throw new Error("fixture descriptor missing");
		const sequence = this.statSequences.get(path);
		if (!sequence || sequence.length === 0) throw new Error("fixture stat missing");
		const call = this.statCalls.get(path) ?? 0;
		this.statCalls.set(path, call + 1);
		return sequence[Math.min(call, sequence.length - 1)];
	}

	readSync(fd: number, buffer: Buffer, offset: number, length: number): number {
		this.readCalls.push(length);
		if (this.readFailure) throw new Error("fixture read failure");
		const path = this.paths.get(fd);
		if (!path) throw new Error("fixture descriptor missing");
		const value = this.values.get(path);
		if (!value) throw new Error("fixture value missing");
		const position = this.offsets.get(fd) ?? 0;
		if (position >= value.length) return 0;
		const count = Math.min(length, value.length - position);
		value.copy(buffer, offset, position, position + count);
		this.offsets.set(fd, position + count);
		return count;
	}

	closeSync(fd: number): void {
		this.closed.push(fd);
	}
}

function artifact(path: string, provider = "fixture-provider", format = "jsonl"): IncidentRecorderLiveProviderArtifact {
	return { provider, path, format };
}

function writerStub(
	admit: IncidentRecorderLiveProviderPrefixCaptureWriter["recordExactBytesForRun"] = () => ({
		accepted: true,
		disposition: "locally_admitted",
		occurrenceId: CAPTURE_ID,
	}),
): IncidentRecorderLiveProviderPrefixCaptureWriter {
	return { recordExactBytesForRun: admit };
}

function input(
	path: string,
	overrides: Partial<Parameters<typeof captureIncidentRecorderLiveProviderPrefix>[0]> = {},
): Parameters<typeof captureIncidentRecorderLiveProviderPrefix>[0] {
	return {
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		targetPid: TARGET_PID,
		targetProcessStartId: TARGET_START,
		triggerOccurrenceId: TRIGGER_ID,
		captureId: CAPTURE_ID,
		artifacts: [artifact(path)],
		writer: writerStub(),
		processStartIdReader: () => TARGET_START,
		now: () => 0,
		...overrides,
	};
}

describe("bounded live provider prefix capture", () => {
	it("retains exact stable bytes and preserves flat metadata in actual service-writer frames", async () => {
		const root = mkdtempSync(join(tmpdir(), "prime-agent-provider-prefix-"));
		roots.push(root);
		const path = join(root, "provider.jsonl");
		const content = Buffer.from('{"answer":42}\n', "utf8");
		writeFileSync(path, content, { mode: 0o600 });
		const writer = new IncidentRecorderWriter({
			runDir: root,
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			serviceSink: true,
		});
		try {
			const result = captureIncidentRecorderLiveProviderPrefix({
				...input(path),
				writer,
				fileSystem: undefined,
			});
			expect(result.nextArtifactIndex).toBe(1);
			expect(result.terminalCoverage).toBe("complete");
			expect(result.receipt?.coverageState).toBe("complete");
			expect(result.receipt?.retainedBytes).toBe(content.length);
			expect(result.receipt?.sourceBytes).toBe(content.length);
			const state = writer as unknown as { relayQueue: Array<{ frames: readonly IncidentRecorderEncodedFrame[] }> };
			for (let attempt = 0; attempt < 100 && state.relayQueue.length === 0; attempt += 1)
				await new Promise<void>((resolve) => setImmediate(resolve));
			const frames = state.relayQueue.flatMap((occurrence) => occurrence.frames);
			const frame = frames.find((candidate) => candidate.header.type === "live_provider_prefix_snapshot");
			expect(frame).toBeDefined();
			if (!frame) throw new Error("provider prefix frame was not queued");
			const decoded = decodeIncidentRecorderFrame(Buffer.concat(frame.parts));
			expect(decoded.header.source).toBe("provider-raw-source");
			expect(decoded.header.encoding).toBe("exact-file-bytes");
			expect(decoded.payload).toEqual(content);
			expect(decoded.header.metadata).toMatchObject({
				rootPid: TARGET_PID,
				rootProcessStartId: TARGET_START,
				triggerOccurrenceId: TRIGGER_ID,
				captureId: CAPTURE_ID,
				provider: "fixture-provider",
				format: "jsonl",
				sourcePath: path,
				beforeDev: String(statSync(path).dev),
				beforeIno: String(statSync(path).ino),
				beforeSize: String(content.length),
				beforeMtimeNs: expect.any(String),
				afterDev: String(statSync(path).dev),
				afterIno: String(statSync(path).ino),
				afterSize: String(content.length),
				afterMtimeNs: expect.any(String),
				retainedBytes: content.length,
				sourceBytes: content.length,
				state: "complete",
				sourceTruncated: false,
				grew: false,
				shrank: false,
				changedDuringRead: false,
				additiveOnly: true,
			});
		} finally {
			await writer.stop(100);
		}
	});

	it("charges the one-byte lookahead and retains only the bounded exact prefix", () => {
		const path = "/tmp/provider-large.jsonl";
		const content = Buffer.alloc(INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES + 9, 65);
		const fileSystem = new FixtureFileSystem();
		fileSystem.set(path, content);
		const calls: Buffer[] = [];
		const result = captureIncidentRecorderLiveProviderPrefix({
			...input(path),
			fileSystem,
			writer: writerStub((_identity, _source, _type, bytes) => {
				calls.push(Buffer.from(bytes));
				return { accepted: true, disposition: "locally_admitted", occurrenceId: CAPTURE_ID };
			}),
			byteBudget: INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES + 1,
		});
		expect(result.bytesRead).toBe(INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES + 1);
		expect(result.receipt?.retainedBytes).toBe(INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES);
		expect(result.receipt?.sourceBytes).toBe(content.length);
		expect(result.receipt?.sourceTruncated).toBe(true);
		expect(result.receipt?.coverageState).toBe("truncated");
		expect(result.receipt?.reason).toBe("truncated");
		expect(result.terminalCoverage).toBe("incomplete");
		expect(result.nextArtifactIndex).toBe(1);
		expect(calls[0]).toEqual(content.subarray(0, INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_PREFIX_BYTES));
	});

	it("observes a real tempfile growing during the wrapped read", () => {
		const root = mkdtempSync(join(tmpdir(), "prime-agent-provider-prefix-growth-"));
		roots.push(root);
		const path = join(root, "growing.jsonl");
		const original = Buffer.from("provider-prefix");
		writeFileSync(path, original, { mode: 0o600 });
		let appended = false;
		const fileSystem: IncidentRecorderLiveProviderPrefixCaptureFileSystem = {
			openSync,
			fstatSync: (fd) => fstatSync(fd, { bigint: true }),
			readSync: (fd, buffer, offset, length, position) => {
				const count = readSync(fd, buffer, offset, length, position);
				if (!appended) {
					appendFileSync(path, "-growth");
					appended = true;
				}
				return count;
			},
			closeSync,
		};
		const payloads: Buffer[] = [];
		const result = captureIncidentRecorderLiveProviderPrefix({
			...input(path),
			fileSystem,
			writer: writerStub((_identity, _source, _type, bytes) => {
				payloads.push(Buffer.from(bytes));
				return { accepted: true, disposition: "locally_admitted", occurrenceId: CAPTURE_ID };
			}),
		});
		expect(result.receipt).toMatchObject({
			bytesRead: original.length,
			grew: true,
			changedDuringRead: true,
			sourceTruncated: true,
			coverageState: "truncated",
		});
		expect(result.terminalCoverage).toBe("incomplete");
		expect(payloads).toEqual([original]);
	});

	it("reports growth and mutation through before/after identities while retaining observed bytes", () => {
		const path = "/tmp/provider-growing.jsonl";
		const original = Buffer.from("before");
		const fileSystem = new FixtureFileSystem();
		fileSystem.set(path, original, [stat(7n, 8n, 6n, 10n), stat(7n, 8n, 8n, 11n)]);
		const writer = vi.fn(writerStub().recordExactBytesForRun);
		const result = captureIncidentRecorderLiveProviderPrefix({
			...input(path),
			fileSystem,
			writer: writerStub(writer),
		});
		expect(result.receipt).toMatchObject({
			bytesRead: original.length,
			retainedBytes: original.length,
			grew: true,
			shrank: false,
			changedDuringRead: true,
			sourceTruncated: true,
			coverageState: "truncated",
			reason: "changed_during_read",
		});
		expect(result.terminalCoverage).toBe("incomplete");
		expect(writer).toHaveBeenCalledTimes(1);
	});

	it("reports shrinking and same-size mutation as incomplete observations", () => {
		const path = "/tmp/provider-shrinking.jsonl";
		const fileSystem = new FixtureFileSystem();
		fileSystem.set(path, Buffer.from("before-content"), [stat(7n, 8n, 14n, 10n), stat(7n, 8n, 6n, 11n)]);
		const shrinking = captureIncidentRecorderLiveProviderPrefix({ ...input(path), fileSystem });
		expect(shrinking.receipt).toMatchObject({
			grew: false,
			shrank: true,
			changedDuringRead: true,
			sourceTruncated: true,
		});

		const mutated = new FixtureFileSystem();
		mutated.set(path, Buffer.from("same-size"), [stat(7n, 8n, 9n, 10n), stat(7n, 8n, 9n, 11n)]);
		const mutation = captureIncidentRecorderLiveProviderPrefix({ ...input(path), fileSystem: mutated });
		expect(mutation.receipt).toMatchObject({
			grew: false,
			shrank: false,
			changedDuringRead: true,
			sourceTruncated: false,
			coverageState: "truncated",
		});
	});

	it("stops before admission on PID reuse and always closes descriptors on read errors", () => {
		const path = "/tmp/provider-reused.jsonl";
		const fileSystem = new FixtureFileSystem();
		fileSystem.set(path, Buffer.from("bytes"));
		const record = vi.fn(writerStub().recordExactBytesForRun);
		let identityReads = 0;
		const result = captureIncidentRecorderLiveProviderPrefix({
			...input(path),
			fileSystem,
			writer: writerStub(record),
			processStartIdReader: () => (identityReads++ === 0 ? TARGET_START : "proc:successor"),
		});
		expect(result.receipt?.reason).toBe("identity_changed");
		expect(result.receipt?.retainedBytes).toBe(0);
		expect(result.receipt?.coverageState).toBe("unavailable");
		expect(result.nextArtifactIndex).toBe(0);
		expect(record).not.toHaveBeenCalled();
		expect(fileSystem.closed).toEqual(fileSystem.opened);

		const failed = new FixtureFileSystem();
		failed.set(path, Buffer.from("bytes"));
		failed.readFailure = true;
		const failedResult = captureIncidentRecorderLiveProviderPrefix({ ...input(path), fileSystem: failed });
		expect(failedResult.receipt?.reason).toBe("read_failed");
		expect(failed.closed).toEqual(failed.opened);
	});

	it("does not admit an unavailable zero-byte read and retries the same index", () => {
		const path = "/tmp/provider-read-failure.jsonl";
		const fileSystem = new FixtureFileSystem();
		fileSystem.set(path, Buffer.from("bytes"));
		fileSystem.readFailure = true;
		const record = vi.fn(writerStub().recordExactBytesForRun);
		const failed = captureIncidentRecorderLiveProviderPrefix({
			...input(path),
			fileSystem,
			writer: writerStub(record),
		});
		expect(failed.receipt).toMatchObject({
			admitted: false,
			admission: { accepted: false, disposition: "not_attempted", reason: "read_failed" },
			coverageState: "unavailable",
			coverage: { state: "unavailable", reason: "read_failed" },
			reason: "read_failed",
		});
		expect(failed.nextArtifactIndex).toBe(0);
		expect(record).not.toHaveBeenCalled();

		fileSystem.readFailure = false;
		const recovered = captureIncidentRecorderLiveProviderPrefix({
			...input(path),
			fileSystem,
			writer: writerStub(record),
			nextArtifactIndex: failed.nextArtifactIndex,
		});
		expect(recovered.receipt).toMatchObject({
			admitted: true,
			coverageState: "complete",
			retainedBytes: 5,
		});
		expect(recovered.nextArtifactIndex).toBe(1);
		expect(record).toHaveBeenCalledTimes(1);

		const emptyPath = "/tmp/provider-empty.jsonl";
		const emptyFileSystem = new FixtureFileSystem();
		emptyFileSystem.set(emptyPath, Buffer.alloc(0));
		const emptyRecord = vi.fn(writerStub().recordExactBytesForRun);
		const empty = captureIncidentRecorderLiveProviderPrefix({
			...input(emptyPath),
			fileSystem: emptyFileSystem,
			writer: writerStub(emptyRecord),
		});
		expect(empty.receipt).toMatchObject({
			admitted: true,
			coverageState: "complete",
			retainedBytes: 0,
			admission: { accepted: true, disposition: "locally_admitted" },
		});
		expect(empty.nextArtifactIndex).toBe(1);
		expect(emptyRecord).toHaveBeenCalledTimes(1);
	});

	it("rejects symlink and non-regular artifacts before a read", () => {
		const root = mkdtempSync(join(tmpdir(), "prime-agent-provider-prefix-files-"));
		roots.push(root);
		const regular = join(root, "regular");
		const link = join(root, "link");
		writeFileSync(regular, "regular", { mode: 0o600 });
		try {
			symlinkSync(regular, link);
		} catch {
			return;
		}
		const symlinkResult = captureIncidentRecorderLiveProviderPrefix({ ...input(link) });
		expect(symlinkResult.receipt?.admitted).toBe(false);
		expect(symlinkResult.receipt?.reason).toBe("read_failed");
		const directoryResult = captureIncidentRecorderLiveProviderPrefix({ ...input(root) });
		expect(directoryResult.receipt?.reason).toBe("not_regular_file");
		const fifo = join(root, "fifo");
		execFileSync("mkfifo", [fifo]);
		const fifoResult = captureIncidentRecorderLiveProviderPrefix({ ...input(fifo) });
		expect(fifoResult.receipt?.reason).toBe("not_regular_file");
	});

	it("holds the same index on queue rejection, then advances after admission", () => {
		const path = "/tmp/provider-queue.jsonl";
		const fileSystem = new FixtureFileSystem();
		fileSystem.set(path, Buffer.from("bytes"));
		let accepted = false;
		const writer = writerStub(() =>
			accepted
				? { accepted: true, disposition: "locally_admitted", occurrenceId: CAPTURE_ID }
				: { accepted: false, disposition: "rejected", reason: "queue_capacity" },
		);
		const rejected = captureIncidentRecorderLiveProviderPrefix({ ...input(path), fileSystem, writer });
		expect(rejected.nextArtifactIndex).toBe(0);
		expect(rejected.receipt?.reason).toBe("queue_rejection");
		expect(rejected.terminalCoverage).toBe("incomplete");
		accepted = true;
		const admitted = captureIncidentRecorderLiveProviderPrefix({
			...input(path),
			fileSystem,
			writer,
			nextArtifactIndex: rejected.nextArtifactIndex,
		});
		expect(admitted.nextArtifactIndex).toBe(1);
		expect(admitted.terminalCoverage).toBe("complete");
	});

	it("holds the index without opening when the pass budget or deadline is already exhausted", () => {
		const path = "/tmp/provider-not-attempted.jsonl";
		const fileSystem = new FixtureFileSystem();
		fileSystem.set(path, Buffer.from("bytes"));
		const byBudget = captureIncidentRecorderLiveProviderPrefix({ ...input(path), fileSystem, byteBudget: 0 });
		expect(byBudget.nextArtifactIndex).toBe(0);
		expect(byBudget.terminalCoverage).toBe("incomplete");
		expect(byBudget.receipt?.admission.disposition).toBe("not_attempted");
		expect(fileSystem.opened).toHaveLength(0);
		const byDeadline = captureIncidentRecorderLiveProviderPrefix({ ...input(path), fileSystem, deadlineMs: 0 });
		expect(byDeadline.nextArtifactIndex).toBe(0);
		expect(byDeadline.receipt?.admission.disposition).toBe("not_attempted");
		expect(fileSystem.opened).toHaveLength(0);
	});

	it("makes an over-cap manifest explicitly capped", () => {
		const artifacts = Array.from(
			{ length: INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_ARTIFACTS + 1 },
			(_, index) => artifact(`/tmp/provider-${index}.jsonl`),
		);
		const result = captureIncidentRecorderLiveProviderPrefix({
			...input(artifacts[0].path),
			artifacts,
			nextArtifactIndex: 64,
		});
		expect(result.artifactLimitReached).toBe(true);
		expect(result.terminalCoverage).toBe("capped");
		expect(result.nextArtifactIndex).toBe(INCIDENT_RECORDER_LIVE_PROVIDER_PREFIX_CAPTURE_MAX_ARTIFACTS);
		expect(result.receipt).toBeUndefined();
	});
});
