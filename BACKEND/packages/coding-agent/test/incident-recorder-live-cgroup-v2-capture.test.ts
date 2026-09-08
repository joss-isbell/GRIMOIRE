import { describe, expect, it, vi } from "vitest";
import {
	type BoundedText,
	type LinuxCgroupV2ResolutionDependencies,
	resolveCgroupDirectory,
} from "../src/modes/daemon/incident-recorder-linux.js";
import {
	captureIncidentRecorderLiveCgroupV2,
	INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES,
	INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES,
	type IncidentRecorderLiveCgroupV2CaptureFileSystem,
	type IncidentRecorderLiveCgroupV2CaptureWriter,
} from "../src/modes/daemon/incident-recorder-live-cgroup-v2-capture.js";
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
const ROOT_START = "proc:731100";
const CGROUP_DIRECTORY = "/sys/fs/cgroup/fixture";
const MEMBERSHIP = Buffer.from("0::/fixture\n", "utf8");
const MOUNTINFO = Buffer.from("42 24 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n", "utf8");

class FixtureFileSystem implements IncidentRecorderLiveCgroupV2CaptureFileSystem {
	private readonly values = new Map<string, Buffer>();
	private readonly paths = new Map<number, string>();
	private readonly offsets = new Map<number, number>();
	private nextFd = 100;
	readonly flags: number[] = [];
	readonly opened: number[] = [];
	readonly closed: number[] = [];
	readonly failures = new Map<string, string>();

	set(path: string, value: Uint8Array): void {
		this.values.set(path, Buffer.from(value));
	}

	openSync(path: string, flags: number): number {
		this.flags.push(flags);
		if (!this.values.has(path)) {
			const error = new Error(`missing fixture source ${path}`) as NodeJS.ErrnoException;
			error.code = this.failures.get(path) ?? "ENOENT";
			throw error;
		}
		const fd = this.nextFd++;
		this.opened.push(fd);
		this.paths.set(fd, path);
		this.offsets.set(fd, 0);
		return fd;
	}

	fstatSync(fd: number): { isFile(): boolean } {
		if (!this.paths.has(fd)) throw new Error("unknown fixture descriptor");
		return { isFile: () => true };
	}

	readSync(fd: number, buffer: Buffer, offset: number, length: number): number {
		const path = this.paths.get(fd);
		if (!path) throw new Error("unknown fixture descriptor");
		const failureCode = this.failures.get(path);
		if (failureCode) {
			const error = new Error(`fixture read ${failureCode}`) as NodeJS.ErrnoException;
			error.code = failureCode;
			throw error;
		}
		const value = this.values.get(path);
		if (!value) throw new Error("missing fixture value");
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

function bounded(value: Buffer): BoundedText {
	return { value: value.toString("utf8"), rawValue: Buffer.from(value), truncated: false };
}

function resolutionDependencies(
	overrides: {
		membership?: (count: number) => Buffer;
		mountinfo?: Buffer;
		stat?: (path: string) => { dev: number; ino: number; isDirectory: boolean } | undefined;
	} = {},
): LinuxCgroupV2ResolutionDependencies {
	let membershipReads = 0;
	return {
		readBounded(path, _limit) {
			if (path === `/proc/${ROOT_PID}/cgroup`)
				return bounded(overrides.membership?.(membershipReads++) ?? MEMBERSHIP);
			if (path === "/proc/self/mountinfo") return bounded(overrides.mountinfo ?? MOUNTINFO);
			return undefined;
		},
		stat(path) {
			return (
				overrides.stat?.(path) ?? (path === CGROUP_DIRECTORY ? { dev: 7, ino: 8, isDirectory: true } : undefined)
			);
		},
	};
}

function fixtureFileSystem(value = Buffer.from("fixture\n")): FixtureFileSystem {
	const fileSystem = new FixtureFileSystem();
	for (const source of INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES)
		fileSystem.set(`${CGROUP_DIRECTORY}/${source}`, value);
	return fileSystem;
}

function writerStub(
	admit: IncidentRecorderLiveCgroupV2CaptureWriter["recordExactBytesForRun"] = (_identity, _source, _type, bytes) => ({
		accepted: true,
		disposition: "locally_admitted",
		occurrenceId: `55555555-5555-4555-8555-${bytes.length.toString(16).padStart(12, "0")}`,
	}),
): IncidentRecorderLiveCgroupV2CaptureWriter {
	return { recordExactBytesForRun: admit };
}

function input(
	fileSystem = fixtureFileSystem(),
	overrides: Partial<Parameters<typeof captureIncidentRecorderLiveCgroupV2>[0]> = {},
): Parameters<typeof captureIncidentRecorderLiveCgroupV2>[0] {
	return {
		runId: RUN_ID,
		runToken: RUN_TOKEN,
		rootPid: ROOT_PID,
		rootProcessStartId: ROOT_START,
		triggerOccurrenceId: TRIGGER_ID,
		captureId: CAPTURE_ID,
		writer: writerStub(),
		fileSystem,
		resolutionDependencies: resolutionDependencies(),
		processStartIdReader: () => ROOT_START,
		now: () => 0,
		...overrides,
	};
}

describe("bounded live cgroup v2 capture", () => {
	it("captures all fixed sources in order and preserves exact raw bytes", () => {
		const fileSystem = fixtureFileSystem(Buffer.from([0xff, 0x00, 0x80, 0x0a]));
		const calls: Array<{ type: string; bytes: Buffer; metadata: Record<string, unknown> }> = [];
		let nextSourceIndex = 0;
		while (nextSourceIndex < INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES.length) {
			const result = captureIncidentRecorderLiveCgroupV2(
				input(fileSystem, {
					nextSourceIndex,
					writer: writerStub((_identity, _source, type, bytes, _encoding, metadata) => {
						calls.push({ type, bytes: Buffer.from(bytes), metadata });
						return { accepted: true, disposition: "locally_admitted", occurrenceId: CAPTURE_ID };
					}),
				}),
			);
			expect(result.receipt?.sourceIndex).toBe(nextSourceIndex);
			expect(result.receipt?.sourcePath).toBe(
				`${CGROUP_DIRECTORY}/${INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES[nextSourceIndex]}`,
			);
			expect(result.receipt?.admitted).toBe(true);
			nextSourceIndex = result.nextSourceIndex;
		}
		expect(calls).toHaveLength(INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES.length);
		expect(calls.map((call) => call.type)).toEqual(
			INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_SOURCE_NAMES.map(() => "live_cgroup_v2_source_snapshot"),
		);
		expect(calls.every((call) => call.bytes.equals(Buffer.from([0xff, 0x00, 0x80, 0x0a])))).toBe(true);
		expect(calls[0]?.metadata).toMatchObject({
			rootPid: ROOT_PID,
			rootProcessStartId: ROOT_START,
			membershipSourcePath: `/proc/${ROOT_PID}/cgroup`,
			membershipSha256: expect.any(String),
			cgroupDirectory: CGROUP_DIRECTORY,
			cgroupDev: 7,
			cgroupIno: 8,
			sourceIndex: 0,
			livePopulation: true,
			coherentSnapshot: false,
			state: "complete",
			sourceBytes: 4,
		});
	});

	it("emits actual writer frames with the exact-file-bytes contract", async () => {
		const writer = new IncidentRecorderWriter({
			runDir: "unused",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			serviceSink: true,
		});
		try {
			const payload = Buffer.from("cgroup-procs\n123\n123\n", "utf8");
			const fileSystem = fixtureFileSystem();
			fileSystem.set(`${CGROUP_DIRECTORY}/cgroup.procs`, payload);
			const result = captureIncidentRecorderLiveCgroupV2({
				...input(fileSystem, { writer, nextSourceIndex: 0 }),
			});
			expect(result.complete).toBe(false);
			const state = writer as unknown as { relayQueue: Array<{ frames: readonly IncidentRecorderEncodedFrame[] }> };
			for (let attempt = 0; attempt < 100 && state.relayQueue.length === 0; attempt += 1)
				await new Promise<void>((resolve) => setImmediate(resolve));
			const frames = state.relayQueue.flatMap((occurrence) => occurrence.frames);
			const frame = frames.find((candidate) => candidate.header.type === "live_cgroup_v2_source_snapshot");
			expect(frame).toBeDefined();
			if (!frame) throw new Error("missing cgroup frame");
			const decoded = decodeIncidentRecorderFrame(Buffer.concat(frame.parts));
			expect(decoded.header.source).toBe("linux-raw-source");
			expect(decoded.header.encoding).toBe("exact-file-bytes");
			expect(decoded.header.metadata).toMatchObject({
				rootPid: ROOT_PID,
				rootProcessStartId: ROOT_START,
				membershipSourcePath: `/proc/${ROOT_PID}/cgroup`,
				membershipSha256: expect.any(String),
				cgroupDirectory: CGROUP_DIRECTORY,
				cgroupDev: 7,
				cgroupIno: 8,
				sourceIndex: 0,
				livePopulation: true,
				coherentSnapshot: false,
			});
			expect(decoded.payload).toEqual(payload);
		} finally {
			await writer.stop(100);
		}
	});

	it("charges a lookahead and retains only the 128KiB raw prefix", () => {
		const payload = Buffer.alloc(INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES + 1, 0x61);
		const fileSystem = fixtureFileSystem();
		fileSystem.set(`${CGROUP_DIRECTORY}/cgroup.procs`, payload);
		const calls: Buffer[] = [];
		const result = captureIncidentRecorderLiveCgroupV2({
			...input(fileSystem, {
				writer: writerStub((_identity, _source, _type, bytes) => {
					calls.push(Buffer.from(bytes));
					return { accepted: true, disposition: "locally_admitted", occurrenceId: CAPTURE_ID };
				}),
			}),
		});
		expect(result.bytesRead).toBe(INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES + 1);
		expect(result.receipt).toMatchObject({
			retainedBytes: INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES,
			sourceTruncated: true,
			coverageState: "truncated",
			reason: "truncated",
		});
		expect(result.receipt).not.toHaveProperty("sourceBytes");
		expect(calls).toEqual([payload.subarray(0, INCIDENT_RECORDER_LIVE_CGROUP_V2_CAPTURE_MAX_SOURCE_BYTES)]);
	});

	it("distinguishes a truly empty raw snapshot from a failed source and advances explicit failure", () => {
		const fileSystem = fixtureFileSystem();
		fileSystem.set(`${CGROUP_DIRECTORY}/memory.current`, Buffer.alloc(0));
		const emptyCalls: Array<{ type: string; bytes: Buffer; encoding: string; metadata: Record<string, unknown> }> =
			[];
		const empty = captureIncidentRecorderLiveCgroupV2({
			...input(fileSystem, {
				nextSourceIndex: 3,
				writer: writerStub((_identity, _source, type, bytes, encoding, metadata) => {
					emptyCalls.push({ type, bytes: Buffer.from(bytes), encoding, metadata });
					return { accepted: true, disposition: "locally_admitted", occurrenceId: CAPTURE_ID };
				}),
			}),
		});
		expect(empty.receipt).toMatchObject({
			coverageState: "complete",
			retainedBytes: 0,
			sourceBytes: 0,
			admitted: true,
		});
		expect(empty.nextSourceIndex).toBe(4);
		expect(emptyCalls[0]).toMatchObject({
			type: "live_cgroup_v2_source_snapshot",
			bytes: Buffer.alloc(0),
			encoding: "exact-file-bytes",
		});

		const failedPath = `${CGROUP_DIRECTORY}/memory.peak`;
		fileSystem.failures.set(failedPath, "EACCES");
		const failedCalls: Array<{ type: string; bytes: Buffer; encoding: string; metadata: Record<string, unknown> }> =
			[];
		const failed = captureIncidentRecorderLiveCgroupV2({
			...input(fileSystem, {
				nextSourceIndex: 4,
				writer: writerStub((_identity, _source, type, bytes, encoding, metadata) => {
					failedCalls.push({ type, bytes: Buffer.from(bytes), encoding, metadata });
					return { accepted: true, disposition: "locally_admitted", occurrenceId: CAPTURE_ID };
				}),
			}),
		});
		expect(failed.receipt).toMatchObject({
			coverageState: "unavailable",
			retainedBytes: 0,
			admitted: true,
			reason: "read_failed",
		});
		expect(failed.nextSourceIndex).toBe(5);
		expect(failedCalls[0]).toMatchObject({
			type: "live_cgroup_v2_source_unavailable",
			bytes: Buffer.alloc(0),
			encoding: "none",
			metadata: {
				category: "source_unavailable",
				code: "EACCES",
				provenance: "live_cgroup_v2",
				state: "unavailable",
			},
		});
		expect(failedCalls[0]?.metadata).not.toHaveProperty("sourceBytes");
	});

	it("holds the same index on resolution, identity, deadline, budget, and queue failures", () => {
		const noDeps = captureIncidentRecorderLiveCgroupV2(
			input(fixtureFileSystem(), {
				dependencies: undefined,
				resolutionDependencies: { readBounded: () => undefined, stat: () => undefined },
			}),
		);
		expect(noDeps).toMatchObject({ nextSourceIndex: 0, reason: "resolution_failed", receipt: { admitted: false } });
		const wrongIdentity = captureIncidentRecorderLiveCgroupV2(
			input(fixtureFileSystem(), { processStartIdReader: () => "proc:successor" }),
		);
		expect(wrongIdentity).toMatchObject({
			nextSourceIndex: 0,
			reason: "identity_changed",
			receipt: { admitted: false },
		});
		const byBudget = captureIncidentRecorderLiveCgroupV2(input(fixtureFileSystem(), { byteBudget: 0 }));
		expect(byBudget).toMatchObject({ nextSourceIndex: 0, reason: "byte_budget", receipt: { admitted: false } });
		const byDeadline = captureIncidentRecorderLiveCgroupV2(input(fixtureFileSystem(), { deadlineMs: 0 }));
		expect(byDeadline).toMatchObject({ nextSourceIndex: 0, reason: "deadline", receipt: { admitted: false } });
		const rejected = captureIncidentRecorderLiveCgroupV2(
			input(fixtureFileSystem(), {
				writer: writerStub(() => ({ accepted: false, disposition: "rejected", reason: "queue_capacity" })),
			}),
		);
		expect(rejected).toMatchObject({ nextSourceIndex: 0, receipt: { admitted: false, reason: "queue_rejection" } });
	});

	it("rejects resolver truncation, unsafe escapes, deleted paths, non-directories, and ambiguous identities", () => {
		const truncated = resolveCgroupDirectory(ROOT_PID, {
			readBounded(path) {
				return path.includes("mountinfo")
					? { value: MOUNTINFO.toString(), rawValue: MOUNTINFO, truncated: true }
					: bounded(MEMBERSHIP);
			},
			stat: () => ({ dev: 7, ino: 8, isDirectory: true }),
		});
		expect(truncated).toBeUndefined();

		const unsafe = (membership: Buffer, mountinfo: Buffer) =>
			resolveCgroupDirectory(ROOT_PID, {
				readBounded(path) {
					return bounded(path.includes("mountinfo") ? mountinfo : membership);
				},
				stat: () => ({ dev: 7, ino: 8, isDirectory: true }),
			});
		expect(unsafe(Buffer.from("0::/fixture\\999bad\n"), MOUNTINFO)).toBeUndefined();
		expect(
			unsafe(MEMBERSHIP, Buffer.from("42 24 0:27 / /sys/fs/cgroup\\999 rw - cgroup2 cgroup rw\n")),
		).toBeUndefined();
		expect(
			unsafe(MEMBERSHIP, Buffer.from("42 24 0:27 / /sys/fs/cgroup\\040(deleted) rw - cgroup2 cgroup rw\n")),
		).toBeUndefined();
		expect(unsafe(MEMBERSHIP, MOUNTINFO)).toBeDefined();
		expect(
			resolveCgroupDirectory(ROOT_PID, {
				readBounded: (path) => bounded(path.includes("mountinfo") ? MOUNTINFO : MEMBERSHIP),
				stat: () => ({ dev: 7, ino: 8, isDirectory: false }),
			}),
		).toBeUndefined();
		expect(
			resolveCgroupDirectory(ROOT_PID, {
				readBounded: (path) =>
					bounded(
						path.includes("mountinfo")
							? Buffer.from(
									"42 24 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n43 24 0:28 / /other/cgroup rw - cgroup2 cgroup rw\n",
								)
							: MEMBERSHIP,
					),
				stat: (path) =>
					path === CGROUP_DIRECTORY
						? { dev: 7, ino: 8, isDirectory: true }
						: path === "/other/cgroup/fixture"
							? { dev: 8, ino: 9, isDirectory: true }
							: undefined,
			}),
		).toBeUndefined();
	});

	it("returns the exact resolver membership observation and rejects churn before admission", () => {
		const resolved = resolveCgroupDirectory(ROOT_PID, resolutionDependencies());
		expect(resolved).toMatchObject({
			directory: CGROUP_DIRECTORY,
			dev: 7,
			ino: 8,
			membershipSourcePath: `/proc/${ROOT_PID}/cgroup`,
			membershipRaw: MEMBERSHIP,
			membershipSha256: expect.any(String),
		});
		const record = vi.fn(writerStub().recordExactBytesForRun);
		let identityReads = 0;
		const changed = captureIncidentRecorderLiveCgroupV2(
			input(fixtureFileSystem(), {
				processStartIdReader: () => (identityReads++ < 2 ? ROOT_START : "proc:successor"),
				writer: writerStub(record),
			}),
		);
		expect(changed).toMatchObject({ nextSourceIndex: 0, reason: "identity_changed", receipt: { admitted: false } });
		expect(record).not.toHaveBeenCalled();

		const membershipChurn = captureIncidentRecorderLiveCgroupV2(
			input(fixtureFileSystem(), {
				resolutionDependencies: resolutionDependencies({
					membership: (count) => (count < 2 ? MEMBERSHIP : Buffer.from("0::/successor\n")),
				}),
				writer: writerStub(record),
			}),
		);
		expect(membershipChurn).toMatchObject({
			nextSourceIndex: 0,
			reason: "resolution_failed",
			receipt: { admitted: false },
		});
		expect(record).not.toHaveBeenCalled();
	});
});
