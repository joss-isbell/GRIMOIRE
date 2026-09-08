import { describe, expect, it, vi } from "vitest";
import {
	captureIncidentRecorderLiveFdLinks,
	INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_BATCH_BYTES,
	INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DIRECTORY_ENTRIES,
	INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_SUBJECTS,
	INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_TARGET_BYTES,
	type IncidentRecorderLiveFdLinkCaptureDirectory,
	type IncidentRecorderLiveFdLinkCaptureFileSystem,
	type IncidentRecorderLiveFdLinkCaptureWriter,
} from "../src/modes/daemon/incident-recorder-live-fd-link-capture.js";
import {
	decodeIncidentRecorderFrame,
	type IncidentRecorderEncodedFrame,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const TRIGGER_ID = "33333333-3333-4333-8333-333333333333";
const CAPTURE_ID = "44444444-4444-4444-8444-444444444444";
const ROOT_PID = 7311;
const CHILD_PID = 7312;
const ROOT_START = "proc:731100";
const CHILD_START = "proc:731200";

class DirectoryFixture implements IncidentRecorderLiveFdLinkCaptureDirectory {
	private index = 0;
	readonly readCalls: number[] = [];
	closed = false;

	constructor(private readonly entries: readonly string[]) {}

	readSync(): { name: string } | null {
		this.readCalls.push(this.index);
		const name = this.entries[this.index++];
		return name === undefined ? null : { name };
	}

	closeSync(): void {
		this.closed = true;
	}
}

class FixtureFileSystem implements IncidentRecorderLiveFdLinkCaptureFileSystem {
	readonly directories = new Map<number, DirectoryFixture>();
	readonly readlinkPaths: string[] = [];
	readonly openedTargets: string[] = [];
	readonly statTargets: string[] = [];
	readonly targetBytes = new Map<string, Buffer>();
	readonly targetErrors = new Map<string, NodeJS.ErrnoException>();
	private readonly directoryEntries = new Map<number, readonly string[]>();

	setDirectory(pid: number, entries: readonly string[]): void {
		this.directoryEntries.set(pid, entries);
	}

	setTarget(pid: number, fd: number, target: Uint8Array): void {
		this.targetBytes.set(`/proc/${pid}/fd/${fd}`, Buffer.from(target));
	}

	opendirSync(path: string): DirectoryFixture {
		const match = /^\/proc\/(\d+)\/fd$/.exec(path);
		if (!match) throw new Error(`unexpected directory path ${path}`);
		const pid = Number(match[1]);
		const directory = new DirectoryFixture(this.directoryEntries.get(pid) ?? []);
		this.directories.set(pid, directory);
		return directory;
	}

	readlinkBuffer(path: string): Buffer {
		this.readlinkPaths.push(path);
		const error = this.targetErrors.get(path);
		if (error) throw error;
		const value = this.targetBytes.get(path);
		if (!value) throw Object.assign(new Error("missing target"), { code: "ENOENT" });
		return Buffer.from(value);
	}
}

function input(
	fileSystem: IncidentRecorderLiveFdLinkCaptureFileSystem,
	overrides: Partial<Parameters<typeof captureIncidentRecorderLiveFdLinks>[0]> = {},
): Parameters<typeof captureIncidentRecorderLiveFdLinks>[0] {
	return {
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		rootPid: ROOT_PID,
		rootProcessStartId: ROOT_START,
		triggerOccurrenceId: TRIGGER_ID,
		captureId: CAPTURE_ID,
		subjects: [{ pid: ROOT_PID, processStartId: ROOT_START }],
		fileSystem,
		identity: () => ROOT_START,
		now: () => 0,
		writer: writerStub(),
		...overrides,
	};
}

function writerStub(
	admission: IncidentRecorderLiveFdLinkCaptureWriter["recordExactBytesForRun"] = () => ({
		accepted: true,
		disposition: "locally_admitted",
		occurrenceId: CAPTURE_ID,
	}),
): IncidentRecorderLiveFdLinkCaptureWriter {
	return { recordExactBytesForRun: admission };
}

function oneFrame(writer: IncidentRecorderWriter): Buffer {
	const state = writer as unknown as { relayQueue: Array<{ frames: readonly IncidentRecorderEncodedFrame[] }> };
	const frame = state.relayQueue.flatMap((occurrence) => occurrence.frames)[0];
	if (!frame) throw new Error("writer did not queue a frame");
	return Buffer.concat(frame.parts);
}

describe("bounded live fd-link capture", () => {
	it("emits one exact JSON batch with flat metadata and deterministic order", async () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["9", "bad", "0", "2"]);
		fileSystem.setTarget(ROOT_PID, 0, Buffer.from([0, 0xff, 0x41]));
		fileSystem.setTarget(ROOT_PID, 2, Buffer.from("/tmp/two", "utf8"));
		fileSystem.setTarget(ROOT_PID, 9, Buffer.alloc(0));
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			serviceSink: true,
		});
		try {
			const result = captureIncidentRecorderLiveFdLinks({ ...input(fileSystem), writer });
			expect(result.coverage).toBe("unavailable");
			expect(result.admission.accepted).toBe(true);
			expect(result.directoryEntriesSeen).toBe(4);
			expect(result.linkAttempts).toBe(3);
			expect(fileSystem.readlinkPaths).toEqual([
				`/proc/${ROOT_PID}/fd/0`,
				`/proc/${ROOT_PID}/fd/2`,
				`/proc/${ROOT_PID}/fd/9`,
			]);
			for (
				let attempt = 0;
				attempt < 100 && (writer as unknown as { relayQueue: unknown[] }).relayQueue.length === 0;
				attempt += 1
			)
				await new Promise<void>((resolve) => setImmediate(resolve));
			const decoded = decodeIncidentRecorderFrame(oneFrame(writer));
			expect(decoded.header.source).toBe("linux-raw-source");
			expect(decoded.header.type).toBe("live_fd_link_batch_snapshot");
			expect(decoded.header.encoding).toBe("utf8-json/incident-fd-link-batch-v1");
			expect(decoded.header.metadata).toMatchObject({
				rootPid: ROOT_PID,
				rootProcessStartId: ROOT_START,
				triggerOccurrenceId: TRIGGER_ID,
				captureId: CAPTURE_ID,
				subjectCount: 1,
				recordCount: 3,
				errorCount: 1,
				directoryEntriesSeen: 4,
				descriptorLimit: 256,
				livePopulation: true,
				coherentSnapshot: false,
				treeCompleteness: "not_claimed",
				additiveOnly: true,
			});
			const batch = JSON.parse(decoded.payload.toString("utf8")) as {
				schema: string;
				records: Array<Record<string, string | number>>;
			};
			expect(batch).toEqual({
				schema: "incident-fd-link-batch-v1",
				records: [
					{
						pid: ROOT_PID,
						fd: 0,
						targetEncoding: "base64",
						targetBytes: 3,
						targetSha256: expect.any(String),
						targetBase64: "AP9B",
					},
					{
						pid: ROOT_PID,
						fd: 2,
						targetEncoding: "base64",
						targetBytes: 8,
						targetSha256: expect.any(String),
						targetBase64: "L3RtcC90d28=",
					},
					{
						pid: ROOT_PID,
						fd: 9,
						targetEncoding: "base64",
						targetBytes: 0,
						targetSha256: expect.any(String),
						targetBase64: "",
					},
				],
			});
		} finally {
			await writer.stop(100);
		}
	});

	it("accepts a stable empty directory as a complete empty batch", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, []);
		const record = vi.fn(writerStub().recordExactBytesForRun);
		const result = captureIncidentRecorderLiveFdLinks({ ...input(fileSystem), writer: writerStub(record) });
		expect(result.coverage).toBe("complete_within_selected_live_pass");
		expect(result.recordCount).toBe(0);
		expect(result.retainedBytes).toBeGreaterThan(0);
		expect(record).toHaveBeenCalledTimes(1);
		const payload = record.mock.calls[0]?.[3];
		expect(payload).toEqual(Buffer.from('{"schema":"incident-fd-link-batch-v1","records":[]}'));
	});

	it("rejects an over-limit subject array before reading elements, identities, or the filesystem", () => {
		const accessedProperties: string[] = [];
		const subjects = new Proxy(
			[{ pid: ROOT_PID, processStartId: ROOT_START }],
			{
				get(target, property, receiver) {
					if (property === "length") return INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_SUBJECTS + 1;
					accessedProperties.push(String(property));
					throw new Error(`untrusted subject property accessed: ${String(property)}`);
				},
			},
		) as unknown as Parameters<typeof captureIncidentRecorderLiveFdLinks>[0]["subjects"];
		const fileSystem = new FixtureFileSystem();
		const record = vi.fn(writerStub().recordExactBytesForRun);
		let identityCalls = 0;
		const result = captureIncidentRecorderLiveFdLinks({
			...input(fileSystem),
			subjects,
			identity: () => {
				identityCalls += 1;
				return ROOT_START;
			},
			writer: writerStub(record),
		});

		expect(accessedProperties).toEqual([]);
		expect(identityCalls).toBe(0);
		expect(fileSystem.directories).toHaveLength(0);
		expect(record).not.toHaveBeenCalled();
		expect(result).toMatchObject({
			selectedSubjects: [],
			subjectCount: 0,
			recordCount: 0,
			errorCount: 1,
			coverage: "unavailable",
			reason: "subject_limit",
			admission: { accepted: false, disposition: "not_attempted", reason: "subject_limit" },
		});
		expect(result.subjectReceipts).toHaveLength(1);
		expect(result.subjectReceipts[0]).toMatchObject({
			pid: 0,
			state: "unavailable",
			errorCount: 1,
			recordCount: 0,
			reason: "subject_limit",
		});
		expect(result.receipts).toEqual([]);
	});

	it.each([
		["final root identity", 4],
		["pre-admission root identity", 5],
		["serialized batch boundary root identity", 6],
	] as const)("normalizes receipts when %s fails", (_boundary, failureCall) => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["0"]);
		fileSystem.setTarget(ROOT_PID, 0, Buffer.from("target"));
		const record = vi.fn(writerStub().recordExactBytesForRun);
		let identityCalls = 0;
		const result = captureIncidentRecorderLiveFdLinks({
			...input(fileSystem),
			writer: writerStub(record),
			identity: () => {
				identityCalls += 1;
				return identityCalls < failureCall ? ROOT_START : "proc:successor";
			},
		});

		expect(identityCalls).toBe(failureCall);
		expect(record).not.toHaveBeenCalled();
		expect(result).toMatchObject({
			coverage: "unavailable",
			recordCount: 0,
			retainedBytes: 0,
			batchBytes: 0,
			admission: { accepted: false, disposition: "not_attempted", reason: "root_identity_changed" },
			reason: "root_identity_changed",
		});
		expect(result.receipts).toEqual([
			expect.objectContaining({
				state: "identity_changed",
				admitted: false,
				retainedBytes: 0,
				reason: "root_identity_changed",
			}),
		]);
		expect(result.subjectReceipts).toEqual([
			expect.objectContaining({
				state: "identity_changed",
				recordCount: 0,
				reason: "root_identity_changed",
			}),
		]);
	});

	it("preserves a typed unavailable subject gap when the root later changes", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.opendirSync = () => {
			throw Object.assign(new Error("directory unavailable"), { code: "EACCES" });
		};
		const record = vi.fn(writerStub().recordExactBytesForRun);
		let identityCalls = 0;
		const result = captureIncidentRecorderLiveFdLinks({
			...input(fileSystem),
			writer: writerStub(record),
			identity: () => {
				identityCalls += 1;
				return identityCalls < 4 ? ROOT_START : "proc:successor";
			},
		});

		expect(result.reason).toBe("root_identity_changed");
		expect(result.subjectReceipts[0]).toMatchObject({
			state: "unavailable",
			recordCount: 0,
			reason: "directory_unavailable",
		});
		expect(result.receipts[0]).toMatchObject({ state: "unavailable", admitted: false, retainedBytes: 0 });
		expect(record).not.toHaveBeenCalled();
	});

	it("counts malformed entries globally and closes each directory", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(
			ROOT_PID,
			Array.from(
				{ length: INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DIRECTORY_ENTRIES + 10 },
				(_, index) => `bad-${index}`,
			),
		);
		const record = vi.fn(writerStub().recordExactBytesForRun);
		const result = captureIncidentRecorderLiveFdLinks({ ...input(fileSystem), writer: writerStub(record) });
		expect(result.directoryEntriesSeen).toBe(INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_DIRECTORY_ENTRIES);
		expect(result.coverage).toBe("unavailable");
		expect(result.reason).toBe("malformed_fd");
		expect(record).not.toHaveBeenCalled();
		expect(fileSystem.directories.get(ROOT_PID)?.closed).toBe(true);
	});

	it("drops all targets for a subject whose identity changes", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["0", "1"]);
		fileSystem.setTarget(ROOT_PID, 0, Buffer.from("zero"));
		fileSystem.setTarget(ROOT_PID, 1, Buffer.from("one"));
		let subjectChecks = 0;
		const record = vi.fn(writerStub().recordExactBytesForRun);
		const result = captureIncidentRecorderLiveFdLinks({
			...input(fileSystem),
			writer: writerStub(record),
			identity: (pid) => {
				if (pid === ROOT_PID) return subjectChecks++ < 2 ? ROOT_START : "proc:successor";
				return ROOT_START;
			},
		});
		expect(result.coverage).toBe("unavailable");
		expect(result.reason).toBe("root_identity_changed");
		expect(result.recordCount).toBe(0);
		expect(record).not.toHaveBeenCalled();
		expect(
			result.receipts.filter((receipt) => receipt.fd !== undefined).every((receipt) => receipt.retainedBytes === 0),
		).toBe(true);
	});

	it("drops only the churned subject while retaining stable subjects", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["0"]);
		fileSystem.setDirectory(CHILD_PID, ["1"]);
		fileSystem.setTarget(ROOT_PID, 0, Buffer.from("root-target"));
		fileSystem.setTarget(CHILD_PID, 1, Buffer.from("child-target"));
		let childChecks = 0;
		const record = vi.fn(writerStub().recordExactBytesForRun);
		const result = captureIncidentRecorderLiveFdLinks({
			...input(fileSystem),
			subjects: [
				{ pid: ROOT_PID, processStartId: ROOT_START },
				{ pid: CHILD_PID, processStartId: CHILD_START },
			],
			writer: writerStub(record),
			identity: (pid) => {
				if (pid === CHILD_PID) return childChecks++ < 1 ? CHILD_START : "proc:successor";
				return ROOT_START;
			},
		});
		expect(result.coverage).toBe("unavailable");
		expect(result.admission.accepted).toBe(true);
		expect(result.subjectReceipts.find((receipt) => receipt.pid === CHILD_PID)).toMatchObject({
			state: "identity_changed",
			reason: "identity_changed",
		});
		expect(result.receipts.find((receipt) => receipt.pid === CHILD_PID)).toMatchObject({
			state: "identity_changed",
			retainedBytes: 0,
		});
		expect(result.receipts.find((receipt) => receipt.pid === ROOT_PID)?.admitted).toBe(true);
		expect(record).toHaveBeenCalledTimes(1);
	});

	it("does not admit an oversized target partially and never opens returned targets", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["3", "4"]);
		fileSystem.setTarget(
			ROOT_PID,
			3,
			Buffer.alloc(INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_TARGET_BYTES + 1, 0x41),
		);
		fileSystem.setTarget(ROOT_PID, 4, Buffer.from("small"));
		const record = vi.fn(writerStub().recordExactBytesForRun);
		const result = captureIncidentRecorderLiveFdLinks({ ...input(fileSystem), writer: writerStub(record) });
		expect(result.receipts.find((receipt) => receipt.fd === 3)).toMatchObject({
			reason: "link_too_large",
			retainedBytes: 0,
		});
		expect(result.receipts.find((receipt) => receipt.fd === 4)?.admitted).toBe(true);
		expect(fileSystem.openedTargets).toEqual([]);
		expect(fileSystem.statTargets).toEqual([]);
		expect(record).toHaveBeenCalledTimes(1);
	});

	it("preflights the encoded batch and reports an unobserved remainder", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["0", "1", "2"]);
		for (const fd of [0, 1, 2]) fileSystem.setTarget(ROOT_PID, fd, Buffer.alloc(64 * 1024, fd + 65));
		const record = vi.fn(writerStub().recordExactBytesForRun);
		const result = captureIncidentRecorderLiveFdLinks({ ...input(fileSystem), writer: writerStub(record) });
		expect(result.reason).toBe("batch_limit");
		expect(result.coverage).toBe("truncated");
		expect(result.receipts.some((receipt) => receipt.reason === "batch_limit")).toBe(true);
		expect(result.receipts.filter((receipt) => receipt.state === "admitted")).toHaveLength(1);
		expect(record).toHaveBeenCalledTimes(1);
		const bytes = record.mock.calls[0]?.[3];
		expect(bytes.length).toBeLessThanOrEqual(INCIDENT_RECORDER_LIVE_FD_LINK_CAPTURE_MAX_BATCH_BYTES);
	});

	it("requires a fresh capture after queue rejection or writer throw", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["0"]);
		fileSystem.setTarget(ROOT_PID, 0, Buffer.from("target"));
		const rejected = captureIncidentRecorderLiveFdLinks({
			...input(fileSystem),
			writer: writerStub(() => ({ accepted: false, disposition: "rejected", reason: "queue_capacity" })),
		});
		expect(rejected.admission).toMatchObject({
			accepted: false,
			reason: "queue_rejection",
			writerReason: "queue_capacity",
		});
		expect(rejected.retryDisposition).toBe("fresh_capture_required");
		expect(rejected.retryCaptureId).not.toBe(CAPTURE_ID);
		expect(rejected.rescanRequired).toBe(true);
		const thrown = captureIncidentRecorderLiveFdLinks({
			...input(fileSystem),
			writer: writerStub(() => {
				throw new Error("writer");
			}),
		});
		expect(thrown.admission).toMatchObject({
			accepted: false,
			reason: "queue_rejection",
			writerReason: "encoding_failed",
		});
		expect(thrown.retryDisposition).toBe("fresh_capture_required");
	});

	it("surfaces stopped and sealed admissions as fresh-capture gaps", async () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["0"]);
		fileSystem.setTarget(ROOT_PID, 0, Buffer.from("target"));
		const stopped = captureIncidentRecorderLiveFdLinks({
			...input(fileSystem),
			writer: writerStub(() => ({ accepted: false, disposition: "rejected", reason: "stopped" })),
		});
		expect(stopped.admission).toMatchObject({
			accepted: false,
			reason: "queue_rejection",
			writerReason: "stopped",
		});
		expect(stopped.retryDisposition).toBe("fresh_capture_required");

		const sealedWriter = new IncidentRecorderWriter({
			runDir: "unused",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			serviceSink: true,
		});
		try {
			sealedWriter.fenceRunIdentity({ runId: RUN_ID, runToken: RUN_TOKEN });
			const sealed = captureIncidentRecorderLiveFdLinks({ ...input(fileSystem), writer: sealedWriter });
			expect(sealed.admission).toMatchObject({
				accepted: false,
				reason: "queue_rejection",
				writerReason: "run_identity_sealed",
			});
			expect(sealed.retryDisposition).toBe("fresh_capture_required");
		} finally {
			await sealedWriter.stop(100);
		}
	});

	it("stops before a link when the cooperative deadline or byte budget is exhausted", () => {
		const fileSystem = new FixtureFileSystem();
		fileSystem.setDirectory(ROOT_PID, ["0"]);
		fileSystem.setTarget(ROOT_PID, 0, Buffer.from("target"));
		const deadline = captureIncidentRecorderLiveFdLinks({ ...input(fileSystem), deadlineMs: 0 });
		expect(deadline.admission.disposition).toBe("not_attempted");
		expect(fileSystem.readlinkPaths).toHaveLength(0);
		const budget = captureIncidentRecorderLiveFdLinks({ ...input(fileSystem), byteBudget: 1 });
		expect(budget.coverage).toBe("truncated");
		expect(budget.bytesRead).toBe(6);
		expect(budget.receipts.find((receipt) => receipt.fd === 0)).toMatchObject({
			reason: "byte_budget",
			retainedBytes: 0,
		});
	});
});
