import { createHash } from "node:crypto";
import {
	appendFileSync,
	chmodSync,
	closeSync,
	copyFileSync,
	existsSync,
	fstatSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readdirSync,
	readFileSync,
	readlinkSync,
	readSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	assertIncidentRecorderProcFdMountIdsForTest,
	closeIncidentRecorderDescriptorsForTest,
	createIncidentRecorderSegmentPruneProtection,
	IncidentRecorderDescriptorCleanupError,
	IncidentRecorderSegmentPageBudgetExceededError,
	IncidentRecorderSegmentPruneMutationError,
	IncidentRecorderSegmentStore,
	IncidentRecorderSegmentStorePoisonedError,
	parseIncidentRecorderProcFdInfoMountIdForTest,
	planIncidentRecorderSegmentStoreOpen,
	pruneIncidentRecorderSealedHistoryForRecovery,
	runIncidentRecorderPruneExpiryCleanupForTest,
	type IncidentRecorderSegmentDurableWrite,
	type IncidentRecorderSegmentQueryCursor,
	type IncidentRecorderSegmentRecoveryGap,
	type IncidentRecorderSegmentRecoveryGapQueryCursor,
	type IncidentRecorderSegmentStoreOptions,
} from "../src/modes/daemon/incident-recorder-segment-store.js";

const roots: string[] = [];

const pruneProtection = (generation = 0, protectedRunIds: readonly string[] = []) =>
	createIncidentRecorderSegmentPruneProtection(generation, protectedRunIds);

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(options: Omit<IncidentRecorderSegmentStoreOptions, "directory"> = {}): {
	directory: string;
	store: IncidentRecorderSegmentStore;
} {
	const directory = mkdtempSync(join(tmpdir(), "prime-agent-segment-store-"));
	roots.push(directory);
	let nextId = 0;
	const createSegmentId = (): string => {
		nextId += 1;
		return `00000000-0000-4000-8000-${String(nextId).padStart(12, "0")}`;
	};
	return {
		directory,
		store: new IncidentRecorderSegmentStore({ directory, createSegmentId, ...options }),
	};
}

function regularFileCount(directory: string): number {
	let count = 0;
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		const path = join(directory, entry.name);
		if (entry.isDirectory()) count += regularFileCount(path);
		else if (entry.isFile()) count += 1;
	}
	return count;
}

interface OpenFileDescriptorIdentity {
	descriptor: number;
	target: string;
	deviceId: string;
	inodeId: string;
	mode: string;
	mountId: string;
}

function snapshotProcMountId(descriptorName: string): string {
	const text = readFileSync(join("/proc/thread-self/fdinfo", descriptorName), "utf8");
	if (text.includes("\u0000")) throw new Error("snapshot fdinfo contains an embedded NUL");
	const candidates = text.split("\n").filter((line) => line.startsWith("mnt_id"));
	if (candidates.length !== 1) throw new Error("snapshot fdinfo has no unique mnt_id");
	return parseIncidentRecorderProcFdInfoMountIdForTest(`${candidates[0]}\n`).toString();
}

function snapshotOpenFileDescriptors(): OpenFileDescriptorIdentity[] {
	if (process.platform !== "linux") throw new Error("open descriptor lifecycle tests require Linux procfs");
	return readdirSync("/proc/thread-self/fd")
		.flatMap((name): OpenFileDescriptorIdentity[] => {
			if (!/^(0|[1-9][0-9]*)$/.test(name)) return [];
			const descriptorPath = join("/proc/thread-self/fd", name);
			try {
				const descriptor = Number(name);
				const status = fstatSync(descriptor, { bigint: true });
				return [
					{
						descriptor,
						target: readlinkSync(descriptorPath),
						deviceId: status.dev.toString(),
						inodeId: status.ino.toString(),
						mode: status.mode.toString(),
						mountId: snapshotProcMountId(name),
					},
				];
			} catch (error) {
				if (["EBADF", "ENOENT"].includes((error as NodeJS.ErrnoException).code ?? "")) return [];
				throw error;
			}
		})
		.sort((left, right) => left.descriptor - right.descriptor);
}

function expectAdditionalRecoveryScopeLeases(
	baseline: readonly OpenFileDescriptorIdentity[],
	current: readonly OpenFileDescriptorIdentity[],
	directory: string,
	leaseCount: number,
): void {
	expect(current.length - baseline.length).toBe(leaseCount * 4);
	const baselineDescriptors = new Set(baseline.map((entry) => entry.descriptor));
	const added = current.filter((entry) => !baselineDescriptors.has(entry.descriptor));
	const expectedMountIds: string[] = [];
	for (const path of [directory, join(directory, "sealed"), "/proc", "/proc/thread-self/fd"]) {
		const target = realpathSync(path);
		const status = statSync(path, { bigint: true });
		const matches = added.filter(
			(entry) =>
				entry.target === target &&
				entry.deviceId === status.dev.toString() &&
				entry.inodeId === status.ino.toString() &&
				entry.mode === status.mode.toString(),
		);
		expect(matches).toHaveLength(leaseCount);
		expect(new Set(matches.map((entry) => entry.mountId)).size).toBe(1);
		expectedMountIds.push(matches[0]!.mountId);
	}
	expect(expectedMountIds[0]).toBe(expectedMountIds[1]);
	expect(expectedMountIds[2]).toBe(expectedMountIds[3]);
}

describe("incident recorder segment store", () => {
	it("strictly rejects forged, malformed, and oversized proc fdinfo mount identities", () => {
		expect(parseIncidentRecorderProcFdInfoMountIdForTest("pos:\t0\nmnt_id:\t123\n")).toBe(123n);
		expect(() => assertIncidentRecorderProcFdMountIdsForTest(123n, [123n, 123n])).not.toThrow();
		expect(() => assertIncidentRecorderProcFdMountIdsForTest(123n, [123n, 124n])).toThrow(
			/proc fd route mount identity changed/,
		);
		expect(() => assertIncidentRecorderProcFdMountIdsForTest(123n, [])).toThrow(
			/proc fd route mount identity changed/,
		);
		const invalidCases: ReadonlyArray<readonly [string, string, RegExp]> = [
			["missing", "pos:\t0\n", /unique strict mnt_id/],
			["duplicate", "mnt_id:\t1\nmnt_id:\t2\n", /unique strict mnt_id/],
			["forged field", "mnt_id:\t1\nmnt_identity:\t1\n", /unique strict mnt_id/],
			["malformed", "mnt_id:\tforged\n", /malformed/],
			["zero", "mnt_id:\t0\n", /malformed/],
			["too many digits", `mnt_id:\t1${"0".repeat(20)}\n`, /malformed/],
			["out of range", "mnt_id:\t18446744073709551616\n", /out of range/],
			["embedded NUL", "mnt_id:\t1\u0000\n", /embedded NUL/],
			["oversized", "x".repeat(4 * 1024 + 1), /fixed read bound/],
		];
		for (const [label, content, expected] of invalidCases) {
			expect(() => parseIncidentRecorderProcFdInfoMountIdForTest(content), label).toThrow(expected);
		}
	});

	it("attempts every descriptor close, preserves the primary failure, and never lets expiry cleanup escape", () => {
		const directory = mkdtempSync(join(tmpdir(), "prime-agent-segment-cleanup-"));
		roots.push(directory);
		const descriptors = ["one", "two", "three"].map((name) => {
			const path = join(directory, name);
			writeFileSync(path, name, { mode: 0o600 });
			return openSync(path, "r");
		});
		const primary = new Error("primary operation failed");
		const firstCleanup = new Error("first close observer failed");
		const secondCleanup = new Error("second close observer failed");
		const attempted: number[] = [];
		let thrown: unknown;
		try {
			closeIncidentRecorderDescriptorsForTest(descriptors, { error: primary }, (descriptor) => {
				attempted.push(descriptor);
				if (descriptor === descriptors[0]) throw firstCleanup;
				if (descriptor === descriptors[1]) throw secondCleanup;
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		const cleanup = thrown as IncidentRecorderDescriptorCleanupError;
		expect(cleanup.cause).toBe(primary);
		expect(cleanup.primaryError).toBe(primary);
		expect(cleanup.cleanupErrors).toEqual([firstCleanup, secondCleanup]);
		expect(Object.isFrozen(cleanup.cleanupErrors)).toBe(true);
		expect(attempted).toEqual(descriptors);
		for (const descriptor of descriptors) expect(() => fstatSync(descriptor)).toThrow();

		const undefinedPrimaryDescriptor = openSync(join(directory, "one"), "r");
		let undefinedPrimaryThrown = false;
		try {
			closeIncidentRecorderDescriptorsForTest(
				[undefinedPrimaryDescriptor],
				{ error: undefined },
				() => {
					throw firstCleanup;
				},
			);
		} catch (error) {
			undefinedPrimaryThrown = true;
			expect(error).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
			expect((error as IncidentRecorderDescriptorCleanupError).primaryError).toBeUndefined();
		}
		expect(undefinedPrimaryThrown).toBe(true);
		expect(() => fstatSync(undefinedPrimaryDescriptor)).toThrow();

		let expiryCleanupCalled = false;
		let expiryDiagnostic: unknown;
		expect(() =>
			runIncidentRecorderPruneExpiryCleanupForTest(
				() => {
					expiryCleanupCalled = true;
					throw new Error("injected asynchronous lease close failure");
				},
				(error) => {
					expiryDiagnostic = error;
					throw new Error("injected diagnostic observer failure");
				},
			),
		).not.toThrow();
		expect(expiryCleanupCalled).toBe(true);
		expect(expiryDiagnostic).toBeInstanceOf(Error);
	});

	it("durably round-trips exact arbitrary bytes, metadata, identity, and a stable locator", () => {
		const durableWrites: string[] = [];
		const target = fixture({
			onDurableWrite: (event) => durableWrites.push(`${event.kind}:${event.segmentId}`),
		});
		const payload = Buffer.from([0x00, 0xff, 0xc3, 0x28, 0x0a, 0x00, 0x7f]);
		const { locator } = target.store.append({
			runId: "run/exact",
			sourceId: "journal:_SYSTEMD_INVOCATION_ID=abc",
			observedAtMs: 1_700_000_000_123,
			order: "18446744073709551614",
			metadata: {
				cursor: "s=opaque;i=1",
				nested: [null, true, 42.5, { message: "kernel \u0000 died" }],
			},
			payload,
		});

		expect(durableWrites.at(-1)).toBe(`record:${locator.segmentId}`);
		target.store.seal("test");
		target.store.close();

		const reopened = new IncidentRecorderSegmentStore({ directory: target.directory });
		const records = reopened.queryRunWindow({
			runId: "run/exact",
			fromObservedAtMs: 1_700_000_000_123,
			throughObservedAtMs: 1_700_000_000_123,
		});
		expect(records).toHaveLength(1);
		expect(records[0]?.locator).toEqual(locator);
		expect(records[0]?.sourceId).toBe("journal:_SYSTEMD_INVOCATION_ID=abc");
		expect(records[0]?.order).toBe("18446744073709551614");
		expect(records[0]?.metadata).toEqual({
			cursor: "s=opaque;i=1",
			nested: [null, true, 42.5, { message: "kernel \u0000 died" }],
		});
		expect(records[0]?.payload.equals(payload)).toBe(true);
		reopened.close();

		const sealedPath = join(target.directory, "sealed", `${locator.segmentId}.segment`);
		const fileDescriptor = openSync(sealedPath, "r+");
		try {
			const checksumOffset = locator.offset + locator.frameBytes - 8 - 32;
			const checksumByte = Buffer.alloc(1);
			readSync(fileDescriptor, checksumByte, 0, 1, checksumOffset);
			checksumByte[0] = (checksumByte[0] ?? 0) ^ 0xff;
			writeSync(fileDescriptor, checksumByte, 0, 1, checksumOffset);
		} finally {
			closeSync(fileDescriptor);
		}
		const corrupted = new IncidentRecorderSegmentStore({ directory: target.directory });
		expect(() =>
			corrupted.queryRunWindow({
				runId: "run/exact",
				fromObservedAtMs: 1_700_000_000_123,
				throughObservedAtMs: 1_700_000_000_123,
			}),
		).toThrow(/checksum mismatch/);
		corrupted.close();
	});

	it("rotates independently on record count, age, and projected segment size", () => {
		const byCount = fixture({ maxRecordsPerSegment: 2, maxSegmentBytes: 1024 * 1024 });
		for (let index = 0; index < 3; index += 1) {
			byCount.store.append({
				runId: "count",
				sourceId: "source",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		expect(byCount.store.getStats()).toMatchObject({ activeSegments: 1, sealedSegments: 1, records: 3 });
		byCount.store.close();

		let now = 10_000;
		const byAge = fixture({
			maxSegmentAgeMs: 10,
			maxSegmentBytes: 1024 * 1024,
			now: () => now,
		});
		byAge.store.append({
			runId: "age",
			sourceId: "source",
			observedAtMs: now,
			order: "1",
			metadata: {},
			payload: Buffer.from("first"),
		});
		now += 11;
		byAge.store.append({
			runId: "age",
			sourceId: "source",
			observedAtMs: now,
			order: "2",
			metadata: {},
			payload: Buffer.from("second"),
		});
		expect(byAge.store.getStats()).toMatchObject({ activeSegments: 1, sealedSegments: 1, records: 2 });
		byAge.store.close();

		const bySize = fixture({ maxSegmentBytes: 2_048, maxRecordsPerSegment: 100 });
		for (let index = 0; index < 2; index += 1) {
			bySize.store.append({
				runId: "size",
				sourceId: "source",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.alloc(1_200, index),
			});
		}
		expect(bySize.store.getStats()).toMatchObject({ activeSegments: 1, sealedSegments: 1, records: 2 });
		bySize.store.close();
	});

	it("replays a retained semantic idempotency key exactly and rejects conflicting content across restart", () => {
		const durableWrites: string[] = [];
		const target = fixture({
			maxRecordsPerSegment: 1,
			onDurableWrite: (event) => durableWrites.push(event.kind),
		});
		const input = {
			idempotencyKey: "journal:boot:cursor-1",
			runId: "idempotent-run",
			sourceId: "journal",
			observedAtMs: 100,
			order: "1",
			metadata: { b: 2, a: 1 },
			payload: Buffer.from("same exact evidence"),
		};
		const appended = target.store.append(input);
		expect(appended.status).toBe("appended");
		const durableCount = durableWrites.length;
		const existing = target.store.append({ ...input, metadata: { a: 1, b: 2 } });
		expect(existing).toEqual({ status: "existing", locator: appended.locator });
		expect(durableWrites).toHaveLength(durableCount);
		expect(target.store.getStats().records).toBe(1);
		target.store.close();

		const reopened = new IncidentRecorderSegmentStore({ directory: target.directory });
		expect(reopened.append(input)).toEqual({ status: "existing", locator: appended.locator });
		expect(() => reopened.append({ ...input, payload: Buffer.from("different") })).toThrow(/different canonical content/);
		expect(reopened.getStats().records).toBe(1);
		reopened.close();
	});

	it("preflights the retained-record lookup bound before parsing a Bloom-positive index", () => {
		const target = fixture({ maxRecordsPerSegment: 2 });
		const firstInput = {
			idempotencyKey: "bounded-record-key",
			runId: "bounded-records",
			sourceId: "journal",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("first"),
		};
		target.store.append(firstInput);
		target.store.append({
			...firstInput,
			idempotencyKey: "bounded-record-key-2",
			observedAtMs: 2,
			order: "2",
			payload: Buffer.from("second"),
		});
		target.store.close();

		let indexReads = 0;
		const bounded = new IncidentRecorderSegmentStore({
			directory: target.directory,
			maxIdempotencyLookupRecords: 1,
			onIndexRead: () => {
				indexReads += 1;
			},
		});
		expect(() => bounded.append(firstInput)).toThrow(
			/cannot prove absence.*maxIdempotencyLookupRecords/,
		);
		expect(indexReads).toBe(0);
		expect(bounded.getStats().records).toBe(2);
		bounded.close();
	});

	it("rejects a checksum-valid footer Bloom that disagrees with its sealed index", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const input = {
			idempotencyKey: "bloom-consistency-key",
			runId: "bloom-consistency",
			sourceId: "journal",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("evidence"),
		};
		const appended = target.store.append(input);
		target.store.close();
		const segmentPath = join(
			target.directory,
			"sealed",
			`${appended.locator.segmentId}.segment`,
		);
		const descriptor = openSync(segmentPath, "r+");
		try {
			const fileBytes = lstatSync(segmentPath).size;
			const trailer = Buffer.alloc(8);
			readSync(descriptor, trailer, 0, trailer.byteLength, fileBytes - trailer.byteLength);
			const footerFrameBytes = trailer.readUInt32LE(0);
			const footerOffset = fileBytes - footerFrameBytes;
			const prefix = Buffer.alloc(16);
			readSync(descriptor, prefix, 0, prefix.byteLength, footerOffset);
			const contentBytes = prefix.readUInt32LE(8);
			const content = Buffer.alloc(contentBytes);
			readSync(descriptor, content, 0, content.byteLength, footerOffset + prefix.byteLength);
			const footer = JSON.parse(content.toString("utf8")) as {
				idempotencyBloomBase64: string;
			};
			footer.idempotencyBloomBase64 = Buffer.alloc(8 * 1024).toString("base64");
			const rewritten = Buffer.from(JSON.stringify(footer));
			expect(rewritten.byteLength).toBe(content.byteLength);
			const checksum = createHash("sha256").update(prefix).update(rewritten).digest();
			writeSync(descriptor, rewritten, 0, rewritten.byteLength, footerOffset + prefix.byteLength);
			writeSync(
				descriptor,
				checksum,
				0,
				checksum.byteLength,
				footerOffset + prefix.byteLength + rewritten.byteLength,
			);
		} finally {
			closeSync(descriptor);
		}

		const reopened = new IncidentRecorderSegmentStore({ directory: target.directory });
		expect(() => reopened.append(input)).toThrow(/sealed index identity or cardinality is invalid/);
		expect(reopened.getStats().records).toBe(1);
		expect(() => reopened.close()).not.toThrow();
	});

	it("fails closed when the bounded retained-history idempotency lookup cannot prove absence", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 2; index += 1) {
			target.store.append({
				idempotencyKey: "bounded-key-" + String(index),
				runId: "bounded-idempotency",
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		target.store.close();
		const bounded = new IncidentRecorderSegmentStore({
			directory: target.directory,
			maxIdempotencyLookupSegments: 1,
		});
		expect(() =>
			bounded.append({
				idempotencyKey: "not-present",
				runId: "bounded-idempotency",
				sourceId: "daemon",
				observedAtMs: 3,
				order: "3",
				metadata: {},
				payload: Buffer.from("new"),
			}),
		).toThrow(/cannot prove absence.*maxIdempotencyLookupSegments/);
		expect(bounded.getStats().records).toBe(2);
		bounded.close();
	});

	it("bounds torn-tail recovery, preserves the valid prefix, and durably records an explicit gap", () => {
		const target = fixture({ maxRecoveryBytes: 1024 * 1024, maxRecoveryFrames: 100 });
		const { locator } = target.store.append({
			runId: "run-recovery",
			sourceId: "journal",
			observedAtMs: 50,
			order: "7",
			metadata: { cursor: "last-good" },
			payload: Buffer.from("valid-prefix"),
		});
		target.store.close();
		const activeName = readdirSync(join(target.directory, "active")).at(0);
		expect(activeName).toBeDefined();
		const activePath = join(target.directory, "active", activeName ?? "missing");
		appendFileSync(activePath, Buffer.from([0x47, 0x52, 0x49, 0x4d, 0xff, 0x00, 0x01]));

		const recovered = new IncidentRecorderSegmentStore({ directory: target.directory });
		const gaps = recovered.getRecoveryGaps();
		expect(gaps).toHaveLength(1);
		expect(gaps[0]).toMatchObject({
			segmentId: locator.segmentId,
			reason: "invalid_or_torn_active_tail",
			discardedBytes: 7,
		});
		expect(gaps[0]?.discardedSha256).toMatch(/^[a-f0-9]{64}$/);
		expect(
			recovered.queryRunWindow({
				runId: "run-recovery",
				fromObservedAtMs: 0,
				throughObservedAtMs: 100,
			})[0]?.payload.toString("utf8"),
		).toBe("valid-prefix");
		recovered.close();

		const reopened = new IncidentRecorderSegmentStore({ directory: target.directory });
		expect(reopened.getRecoveryGaps()).toEqual(gaps);
		expect(lstatSync(activePath).isFile()).toBe(true);
		reopened.close();
	});

	it("answers an inclusive exact run window in append order after sealed-footer replay", () => {
		const target = fixture({ maxRecordsPerSegment: 2, maxSegmentBytes: 1024 * 1024 });
		const input = [
			{ runId: "run-a", sourceId: "daemon", observedAtMs: 10, order: "1", payload: "a1" },
			{ runId: "run-b", sourceId: "kernel", observedAtMs: 15, order: "9", payload: "b" },
			{ runId: "run-a", sourceId: "kernel", observedAtMs: 20, order: "2", payload: "a2" },
			{ runId: "run-a", sourceId: "daemon", observedAtMs: 30, order: "3", payload: "a3" },
		];
		for (const record of input) {
			target.store.append({
				...record,
				metadata: { correlation: `corr-${record.order}` },
				payload: Buffer.from(record.payload),
			});
		}
		target.store.seal("test");
		target.store.close();

		const reopened = new IncidentRecorderSegmentStore({ directory: target.directory });
		const records = reopened.queryRunWindow({
			runId: "run-a",
			fromObservedAtMs: 20,
			throughObservedAtMs: 30,
		});
		expect(records.map((record) => record.payload.toString("utf8"))).toEqual(["a2", "a3"]);
		expect(records.map((record) => record.sourceId)).toEqual(["kernel", "daemon"]);
		expect(records.map((record) => record.order)).toEqual(["2", "3"]);
		reopened.close();
	});

	it("uses segment-count inode cardinality instead of record-count cardinality", () => {
		const target = fixture({
			maxRecordsPerSegment: 25,
			maxSegmentBytes: 1024 * 1024,
			maxSegmentAgeMs: 60_000,
			now: () => 1,
		});
		for (let index = 0; index < 250; index += 1) {
			target.store.append({
				runId: `run-${index % 5}`,
				sourceId: "journal",
				observedAtMs: index,
				order: String(index),
				metadata: { occurrence: index },
				payload: Buffer.from(`payload-${index}`),
			});
		}
		const stats = target.store.getStats();
		expect(stats).toMatchObject({ activeSegments: 0, sealedSegments: 10, records: 250 });
		expect(regularFileCount(target.directory)).toBe(11);
		expect(regularFileCount(target.directory)).toBeLessThan(250 / 10);
		target.store.close();
	});

	it("keeps sealed indexes lazy and bounds every directory entry plus aggregate catalog memory", () => {
		const target = fixture({ maxRecordsPerSegment: 2, maxSegmentBytes: 1024 * 1024 });
		for (let index = 0; index < 20; index += 1) {
			target.store.append({
				runId: "lazy-run",
				sourceId: index % 2 === 0 ? "daemon" : "kernel",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		target.store.close();

		let indexReads = 0;
		const reopened = new IncidentRecorderSegmentStore({
			directory: target.directory,
			onIndexRead: () => {
				indexReads += 1;
			},
		});
		expect(reopened.getStats()).toMatchObject({ records: 20, sealedSegments: 10 });
		expect(indexReads).toBe(0);
		expect(
			reopened.queryRunWindow({
				runId: "lazy-run",
				sourceId: "kernel",
				fromObservedAtMs: 0,
				throughObservedAtMs: 100,
			}),
		).toHaveLength(10);
		expect(indexReads).toBeGreaterThan(0);
		reopened.close();

		writeFileSync(join(target.directory, "sealed", "unrelated-a"), "a", { mode: 0o600 });
		writeFileSync(join(target.directory, "sealed", "unrelated-b"), "b", { mode: 0o600 });
		expect(
			() =>
				new IncidentRecorderSegmentStore({
					directory: target.directory,
					maxStartupEntries: 11,
					maxStartupCatalogBytes: 1024 * 1024,
				}),
		).toThrow(/maxStartupEntries/);
	});

	it("bounds metadata and full-frame query memory and supports a source identity filter", () => {
		const target = fixture({ maxMetadataBytes: 128, maxQueryBytes: 256 });
		expect(() =>
			target.store.append({
				runId: "bounded",
				sourceId: "daemon",
				observedAtMs: 1,
				order: "1",
				metadata: { oversized: "x".repeat(512) },
				payload: Buffer.alloc(0),
			}),
		).toThrow(/maxMetadataBytes/);
		for (const [index, sourceId] of ["daemon", "kernel"].entries()) {
			target.store.append({
				runId: "bounded",
				sourceId,
				observedAtMs: index + 10,
				order: String(index + 10),
				metadata: {},
				payload: Buffer.alloc(32, index),
			});
		}
		expect(() =>
			target.store.queryRunWindow({
				runId: "bounded",
				fromObservedAtMs: 0,
				throughObservedAtMs: 100,
			}),
		).toThrow(/full frame bytes.*maxQueryBytes/);
		target.store.close();

		const reopened = new IncidentRecorderSegmentStore({ directory: target.directory, maxQueryBytes: 1024 * 1024 });
		const filtered = reopened.queryRunWindow({
			runId: "bounded",
			sourceId: "kernel",
			fromObservedAtMs: 0,
			throughObservedAtMs: 100,
		});
		expect(filtered.map((record) => record.sourceId)).toEqual(["kernel"]);
		reopened.close();
	});

	it("makes the recovery gap durable before truncation and stream-hashes the discarded tail", () => {
		const target = fixture();
		target.store.append({
			runId: "recovery-order",
			sourceId: "journal",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("committed"),
		});
		target.store.close();
		const activeName = readdirSync(join(target.directory, "active")).find((name) => name.endsWith(".open"));
		expect(activeName).toBeDefined();
		appendFileSync(join(target.directory, "active", activeName ?? "missing"), Buffer.alloc(200_000, 0xa5));
		let injected = false;
		expect(
			() =>
				new IncidentRecorderSegmentStore({
					directory: target.directory,
					faultInjector: (point) => {
						if (!injected && point === "after-recovery-gap-fsync-before-truncate") {
							injected = true;
							throw new Error("simulated crash after durable gap");
						}
					},
				}),
		).toThrow(/simulated crash/);

		let largestRecoveryRead = 0;
		const recovered = new IncidentRecorderSegmentStore({
			directory: target.directory,
			onRecoveryRead: (bytes) => {
				largestRecoveryRead = Math.max(largestRecoveryRead, bytes);
			},
		});
		const gaps = recovered.getRecoveryGaps();
		expect(gaps[0]).toMatchObject({ reason: "invalid_or_torn_active_tail", discardedBytes: 200_000 });
		expect(largestRecoveryRead).toBeLessThanOrEqual(64 * 1024);
		expect(
			recovered.queryRunWindow({
				runId: "recovery-order",
				fromObservedAtMs: 0,
				throughObservedAtMs: 10,
			})[0]?.payload.toString("utf8"),
		).toBe("committed");
		recovered.close();
	});

	it("publishes headers atomically, never clobbers a sealed ID, and poisons ambiguous instances", () => {
		let failHeaderPublish = true;
		const atomic = fixture({
			faultInjector: (point) => {
				if (failHeaderPublish && point === "after-header-fsync-before-publish") {
					failHeaderPublish = false;
					throw new Error("header publish interrupted");
				}
			},
		});
		expect(() =>
			atomic.store.append({
				runId: "atomic",
				sourceId: "daemon",
				observedAtMs: 1,
				order: "1",
				metadata: {},
				payload: Buffer.from("one"),
			}),
		).toThrow(/header publish interrupted/);
		expect(readdirSync(join(atomic.directory, "active")).some((name) => name.endsWith(".open"))).toBe(false);
		expect(() =>
			atomic.store.append({
				runId: "atomic",
				sourceId: "daemon",
				observedAtMs: 2,
				order: "2",
				metadata: {},
				payload: Buffer.from("two"),
			}),
		).toThrow(/poisoned/);
		atomic.store.close();

		const durable = fixture({ maxRecordsPerSegment: 1 });
		const { locator: kept } = durable.store.append({
			runId: "no-clobber",
			sourceId: "daemon",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("keep"),
		});
		durable.store.close();
		const duplicate = new IncidentRecorderSegmentStore({
			directory: durable.directory,
			createSegmentId: () => kept.segmentId,
		});
		expect(() =>
			duplicate.append({
				runId: "no-clobber",
				sourceId: "daemon",
				observedAtMs: 2,
				order: "2",
				metadata: {},
				payload: Buffer.from("replace"),
			}),
		).toThrow(/unique segment identity/);
		expect(
			duplicate.queryRunWindow({ runId: "no-clobber", fromObservedAtMs: 0, throughObservedAtMs: 10 })[0]
				?.payload.toString("utf8"),
		).toBe("keep");
		duplicate.close();

		let throwObserver = true;
		const observed = fixture({
			onDurableWrite: (event) => {
				if (throwObserver && event.kind === "record") {
					throwObserver = false;
					throw new Error("observer failed after commit");
				}
			},
		});
		expect(() =>
			observed.store.append({
				runId: "poison",
				sourceId: "daemon",
				observedAtMs: 1,
				order: "1",
				metadata: {},
				payload: Buffer.from("committed-once"),
			}),
		).toThrow(/observer failed/);
		expect(() =>
			observed.store.append({
				runId: "poison",
				sourceId: "daemon",
				observedAtMs: 2,
				order: "2",
				metadata: {},
				payload: Buffer.from("must-not-write"),
			}),
		).toThrow(/poisoned/);
		observed.store.close();
		const replayed = new IncidentRecorderSegmentStore({ directory: observed.directory });
		expect(
			replayed
				.queryRunWindow({ runId: "poison", fromObservedAtMs: 0, throughObservedAtMs: 10 })
				.map((record) => record.payload.toString("utf8")),
		).toEqual(["committed-once"]);
		replayed.close();
	});

	it("uses fixed reader maxima across stricter writer policy and holds recoverable single-writer ownership", () => {
		const target = fixture({ maxRecordBytes: 1024, maxMetadataBytes: 1024, maxRecordsPerSegment: 4 });
		target.store.append({
			runId: "reader-policy",
			sourceId: "daemon",
			observedAtMs: 1,
			order: "1",
			metadata: { policy: "old" },
			payload: Buffer.alloc(512, 0x5a),
		});
		expect(
			() =>
				new IncidentRecorderSegmentStore({
					directory: target.directory,
					ownerIdentity: { pid: 999, startTime: "live", bootId: "boot" },
					isOwnerAlive: () => true,
				}),
		).toThrow(/already owned/);
		target.store.close();

		writeFileSync(
			join(target.directory, ".writer-owner.json"),
			`${JSON.stringify({ version: 1, nonce: "stale-owner", pid: 100, startTime: "stale", bootId: "old-boot" })}\n`,
			{ mode: 0o600 },
		);
		const reopened = new IncidentRecorderSegmentStore({
			directory: target.directory,
			maxRecordBytes: 1,
			maxMetadataBytes: 2,
			maxRecordsPerSegment: 1,
			ownerIdentity: { pid: 101, startTime: "new", bootId: "new-boot" },
			isOwnerAlive: () => false,
		});
		expect(
			reopened.queryRunWindow({ runId: "reader-policy", fromObservedAtMs: 0, throughObservedAtMs: 10 })[0]
				?.payload.byteLength,
		).toBe(512);
		expect(() =>
			reopened.append({
				runId: "reader-policy",
				sourceId: "daemon",
				observedAtMs: 2,
				order: "2",
				metadata: {},
				payload: Buffer.from([1, 2]),
			}),
		).toThrow(/maxRecordBytes/);
		reopened.close();
		expect(existsSync(join(target.directory, ".writer-owner.json"))).toBe(false);
	});

	it("reads one exact retained record by stable locator and rejects forged or pruned locators", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					idempotencyKey: `locator-${String(index)}`,
					runId: `locator-run-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: { index, nested: { exact: true } },
					payload: Buffer.from([0, index, 0xff]),
				}).locator,
			);
		}
		target.store.close();
		let indexReads = 0;
		const reopened = new IncidentRecorderSegmentStore({
			directory: target.directory,
			onIndexRead: () => {
				indexReads += 1;
			},
		});
		const locator = locators[0]!;
		const record = reopened.readRecord(locator);
		expect(record).toMatchObject({
			idempotencyKey: "locator-0",
			runId: "locator-run-0",
			sourceId: "daemon",
			observedAtMs: 0,
			order: "0",
			metadata: { index: 0, nested: { exact: true } },
			locator,
		});
		expect(record?.payload).toEqual(Buffer.from([0, 0, 0xff]));
		expect(indexReads).toBe(1);
		expect(() => reopened.readRecord({ ...locator, offset: locator.offset + 1 })).toThrow(/locator/);
		expect(() =>
			reopened.readRecord({ ...locator, payloadSha256: "0".repeat(64) }),
		).toThrow(/locator/);
		expect(() =>
			reopened.readRecord({ ...locator, segmentSequence: locator.segmentSequence + 1 }),
		).toThrow(/segment identity/);
		expect(
			reopened.readRecord({ ...locator, segmentId: "cleanly-missing-or-pruned-segment" }),
		).toBeUndefined();
		const pruned = reopened.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(pruned.deletedSegmentIds).toEqual([locator.segmentId]);
		expect(reopened.readRecord(locator)).toBeUndefined();
		reopened.close();
	});

	it("throws when a locator addresses a checksum-corrupt retained record", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locator = target.store.append({
			idempotencyKey: "corrupt-locator",
			runId: "corrupt-locator-run",
			sourceId: "daemon",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("causal evidence"),
		}).locator;
		target.store.close();
		const segmentPath = join(target.directory, "sealed", `${locator.segmentId}.segment`);
		const descriptor = openSync(segmentPath, "r+");
		try {
			const checksumOffset = locator.offset + locator.frameBytes - 8 - 32;
			const value = Buffer.alloc(1);
			readSync(descriptor, value, 0, 1, checksumOffset);
			value[0] = (value[0] ?? 0) ^ 0xff;
			writeSync(descriptor, value, 0, 1, checksumOffset);
		} finally {
			closeSync(descriptor);
		}
		const reopened = new IncidentRecorderSegmentStore({ directory: target.directory });
		expect(() => reopened.readRecord(locator)).toThrow(/checksum|frame/i);
		reopened.close();
	});

	it("prunes only validated old sealed segments within bounds and honors protected IDs", () => {
		let now = 100;
		const target = fixture({ now: () => now, maxRecordsPerSegment: 100, maxSegmentBytes: 1024 * 1024 });
		const locators = [];
		for (const label of ["delete", "protect", "corrupt"] as const) {
			locators.push(
				target.store.append({
					runId: label,
					sourceId: "daemon",
					observedAtMs: now,
					order: String(now),
					metadata: {},
					payload: Buffer.from(label),
				}).locator,
			);
			target.store.seal("fixture");
			now += 100;
		}
		target.store.append({
			runId: "active",
			sourceId: "daemon",
			observedAtMs: 1_000,
			order: "1000",
			metadata: {},
			payload: Buffer.from("active"),
		});
		target.store.close();

		const corrupt = locators[2];
		expect(corrupt).toBeDefined();
		const corruptPath = join(target.directory, "sealed", `${corrupt?.segmentId}.segment`);
		const corruptDescriptor = openSync(corruptPath, "r+");
		try {
			const checksumOffset = (corrupt?.offset ?? 0) + (corrupt?.frameBytes ?? 0) - 8 - 32;
			const value = Buffer.alloc(1);
			readSync(corruptDescriptor, value, 0, 1, checksumOffset);
			value[0] = (value[0] ?? 0) ^ 0xff;
			writeSync(corruptDescriptor, value, 0, 1, checksumOffset);
		} finally {
			closeSync(corruptDescriptor);
		}

		const pruneEvents: IncidentRecorderSegmentDurableWrite[] = [];
		const reopened = new IncidentRecorderSegmentStore({
			directory: target.directory,
			onDurableWrite: (event) => pruneEvents.push(event),
		});
		const result = reopened.pruneSealedSegments({
			sealedBeforeMs: 500,
			protection: pruneProtection(),
			protectedSegmentIds: new Set([locators[1]?.segmentId ?? "missing"]),
			maxSegments: 10,
			maxBytes: 1024 * 1024,
		});
		expect(result.deletedSegmentIds).toEqual([locators[0]?.segmentId]);
		expect(result.corruptSegmentIds).toEqual([locators[2]?.segmentId]);
		expect(existsSync(join(target.directory, "sealed", `${locators[1]?.segmentId}.segment`))).toBe(true);
		expect(existsSync(corruptPath)).toBe(true);
		expect(reopened.getStats()).toMatchObject({ activeSegments: 1, sealedSegments: 2, records: 3 });
		const removed = pruneEvents.find((event) => event.kind === "pruned");
		expect(removed).toMatchObject({ entryChange: "removed", entryDelta: -1, logicalBytes: 0, allocatedBytes: 0 });
		expect(removed?.previousAllocatedBytes).toBeGreaterThan(0);
		expect(removed?.inodeId).toMatch(/^\d+$/);
		reopened.close();
	});

	it("marks a live sealed index integrity failure corrupt without deleting its path", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `live-index-corrupt-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		const corruptPath = join(target.directory, "sealed", `${locators[0]!.segmentId}.segment`);
		const segmentBytes = readFileSync(corruptPath);
		const footerFrameBytes = segmentBytes.readUInt32LE(segmentBytes.byteLength - 8);
		const footerOffset = segmentBytes.byteLength - footerFrameBytes;
		const footerContentBytes = segmentBytes.readUInt32LE(footerOffset + 8);
		const footer = JSON.parse(
			segmentBytes.subarray(footerOffset + 16, footerOffset + 16 + footerContentBytes).toString("utf8"),
		) as { indexOffset: number };
		const corruptDescriptor = openSync(corruptPath, "r+");
		try {
			const value = Buffer.alloc(1);
			readSync(corruptDescriptor, value, 0, 1, footer.indexOffset);
			value[0] = (value[0] ?? 0) ^ 0xff;
			writeSync(corruptDescriptor, value, 0, 1, footer.indexOffset);
		} finally {
			closeSync(corruptDescriptor);
		}
		const result = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			protectedSegmentIds: new Set([locators[1]!.segmentId]),
			maxSegments: 10,
			maxBytes: 1024 * 1024,
		});
		expect(result.deletedSegmentIds).toEqual([]);
		expect(result.corruptSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(existsSync(corruptPath)).toBe(true);
		expect(target.store.getStats().corruptSegments).toBe(1);
		target.store.close();
	});

	it("pages exact run windows without skips across lazy sealed indexes, source filters, and pruning", () => {
		const target = fixture({ maxRecordsPerSegment: 2, maxSegmentBytes: 1024 * 1024 });
		for (let index = 0; index < 6; index += 1) {
			target.store.append({
				runId: "paged",
				sourceId: index % 2 === 0 ? "daemon" : "kernel",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from("record-" + String(index)),
			});
		}
		const readSnapshot = target.store.createReadSnapshot();
		expect(Object.isFrozen(readSnapshot)).toBe(true);
		const first = target.store.queryRunWindowPage({
			runId: "paged",
			sourceId: "kernel",
			fromObservedAtMs: 0,
			throughObservedAtMs: 10,
			maxRecords: 1,
			maxBytes: 1024,
			readSnapshot,
		});
		expect(first.records.map((record) => record.order)).toEqual(["1"]);
		expect(first.complete).toBe(false);
		expect(first.nextCursor).toBeDefined();

		target.store.append({
			runId: "paged",
			sourceId: "kernel",
			observedAtMs: 2,
			order: "99",
			metadata: {},
			payload: Buffer.from("late-in-window"),
		});
		target.store.seal("active-to-sealed-snapshot-test");
		const observed = [...first.records];
		let cursor = first.nextCursor;
		for (;;) {
			const page = target.store.queryRunWindowPage({
				runId: "paged",
				sourceId: "kernel",
				fromObservedAtMs: 0,
				throughObservedAtMs: 10,
				maxRecords: 1,
				maxBytes: 1024,
				readSnapshot,
				after: cursor,
			});
			observed.push(...page.records);
			if (page.complete) break;
			cursor = page.nextCursor;
		}
		expect(observed.map((record) => record.order)).toEqual(["1", "3", "5"]);
		expect(new Set(observed.map((record) => `${record.locator.segmentSequence}:${record.locator.ordinal}`)).size).toBe(3);
		const otherFilter = target.store.queryRunWindowPage({
			runId: "paged",
			sourceId: "daemon",
			fromObservedAtMs: 0,
			throughObservedAtMs: 10,
			maxRecords: 3,
			maxBytes: 4 * 1024,
			readSnapshot,
		});
		expect(otherFilter.complete).toBe(true);
		expect(otherFilter.records.map((record) => record.order)).toEqual(["0", "2", "4"]);

		const staleFirst = target.store.queryRunWindowPage({
			runId: "paged",
			sourceId: "kernel",
			fromObservedAtMs: 0,
			throughObservedAtMs: 10,
			maxRecords: 1,
			maxBytes: 1024,
		});
		const prune = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(prune.deletedSegmentIds).toHaveLength(1);
		expect(() =>
			target.store.queryRunWindowPage({
				runId: "paged",
				sourceId: "kernel",
				fromObservedAtMs: 0,
				throughObservedAtMs: 10,
				maxRecords: 1,
				maxBytes: 1024,
				after: staleFirst.nextCursor!,
			}),
		).toThrow(/snapshot is stale.*restart required/);
		expect(() => target.store.assertReadSnapshotUsable(readSnapshot)).toThrow(/snapshot is stale.*restart required/);
		target.store.close();
	});

	it("protects a frozen read frontier with an exact live lease until release, expiry, or close", () => {
		let now = 1_000;
		const target = fixture({ now: () => now, maxRecordsPerSegment: 1 });
		const oldLocator = target.store.append({
			runId: "leased",
			sourceId: "daemon",
			observedAtMs: now,
			order: "1",
			metadata: {},
			payload: Buffer.from("old"),
		}).locator;
		const anchorLocator = target.store.append({
			runId: "anchor",
			sourceId: "daemon",
			observedAtMs: now + 1,
			order: "2",
			metadata: {},
			payload: Buffer.from("anchor"),
		}).locator;
		const lease = target.store.acquireReadLease(now + 100);
		expect(Object.isFrozen(lease)).toBe(true);
		target.store.append({
			runId: "leased",
			sourceId: "daemon",
			observedAtMs: now + 2,
			order: "3",
			metadata: {},
			payload: Buffer.from("late"),
		});
		expect(target.store.queryRunWindowPage({
			runId: "leased",
			fromObservedAtMs: 0,
			throughObservedAtMs: Number.MAX_SAFE_INTEGER,
			readLease: lease,
		})).toMatchObject({ complete: true, records: [{ order: "1" }] });
		expect(target.store.queryRunWindowPage({
			runId: "anchor",
			fromObservedAtMs: 0,
			throughObservedAtMs: Number.MAX_SAFE_INTEGER,
			readLease: lease,
		})).toMatchObject({ complete: true, records: [{ order: "2" }] });

		const blocked = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 10,
			maxBytes: 1024 * 1024,
		});
		expect(blocked).toMatchObject({
			deletedSegmentIds: [],
			blockedByReadSnapshot: true,
			moreWork: true,
		});
		expect(blocked.continuation).toBeUndefined();
		expect(existsSync(join(target.directory, "sealed", `${oldLocator.segmentId}.segment`))).toBe(true);

		const mismatched = Object.freeze({ ...lease, highWaterOrdinal: lease.highWaterOrdinal + 1 });
		expect(() => target.store.queryRunWindowPage({
			runId: "leased",
			fromObservedAtMs: 0,
			throughObservedAtMs: Number.MAX_SAFE_INTEGER,
			readLease: mismatched,
		})).toThrow(/exact registered object/);
		expect(target.store.releaseReadLease(lease)).toBe(true);
		expect(target.store.releaseReadLease(lease)).toBe(false);
		expect(() => target.store.assertReadLeaseUsable(lease)).toThrow(/lease.*not active/);
		expect(target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 10,
			maxBytes: 1024 * 1024,
		}).deletedSegmentIds).toEqual([oldLocator.segmentId, anchorLocator.segmentId]);

		const expiring = target.store.acquireReadLease(now + 10);
		now += 11;
		expect(() => target.store.assertReadLeaseUsable(expiring)).toThrow(/lease.*expired/);
		expect(target.store.releaseReadLease(expiring)).toBe(false);
		const closing = target.store.acquireReadLease(now + 10);
		target.store.close();
		expect(() => target.store.assertReadLeaseUsable(closing)).toThrow(/store is closed/);
		expect(target.store.releaseReadLease(closing)).toBe(false);
	});

	it("bounds the live lease registry without allocating leases for ordinary snapshots", () => {
		let now = 10;
		const target = fixture({ now: () => now });
		const leases = Array.from({ length: 8 }, () => target.store.acquireReadLease(now + 100));
		expect(() => target.store.acquireReadLease(now + 100)).toThrow(/8-lease ceiling/);
		const ordinary = target.store.createReadSnapshot();
		expect(target.store.queryRunWindowPage({
			runId: "ordinary",
			fromObservedAtMs: 0,
			throughObservedAtMs: Number.MAX_SAFE_INTEGER,
			readSnapshot: ordinary,
		})).toMatchObject({ complete: true, records: [] });
		now += 101;
		const replacement = target.store.acquireReadLease(now + 1);
		expect(replacement.acquiredAtMs).toBe(now);
		expect(target.store.releaseReadLease(replacement)).toBe(true);
		expect(leases.every((lease) => target.store.releaseReadLease(lease) === false)).toBe(true);
		target.store.close();
	});

	it("requires the exact frozen lease object and revisits an expired lease-blocked segment", () => {
		let now = 100;
		const target = fixture({ now: () => now, maxRecordsPerSegment: 1 });
		const old = target.store.append({
			runId: "expiry",
			sourceId: "daemon",
			observedAtMs: now,
			order: "1",
			metadata: {},
			payload: Buffer.from("old"),
		}).locator;
		target.store.append({
			runId: "expiry-anchor",
			sourceId: "daemon",
			observedAtMs: now,
			order: "2",
			metadata: {},
			payload: Buffer.from("anchor"),
		});
		const lease = target.store.acquireReadLease(now + 10);
		const frozenClone = Object.freeze({ ...lease });
		expect(() => target.store.assertReadLeaseUsable(frozenClone)).toThrow(/exact registered object/);
		expect(() => target.store.releaseReadLease(frozenClone)).toThrow(/exact registered object/);
		expect(target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 10,
			maxBytes: 1024 * 1024,
		})).toMatchObject({ deletedSegmentIds: [], blockedByReadSnapshot: true, moreWork: true });
		now += 11;
		expect(() => target.store.assertReadLeaseUsable(frozenClone)).toThrow(/exact registered object/);
		expect(() => target.store.releaseReadLease(frozenClone)).toThrow(/exact registered object/);
		expect(target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 10,
			maxBytes: 1024 * 1024,
		}).deletedSegmentIds).toContain(old.segmentId);
		target.store.close();
	});

	it("bounds sparse scans by examined work and advances zero-result frontiers to an exact match", () => {
		const target = fixture({ maxRecordsPerSegment: 2 });
		for (let index = 0; index < 9; index += 1) {
			target.store.append({
				runId: index === 8 ? "needle" : "irrelevant",
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from(String(index)),
			});
		}
		const readSnapshot = target.store.createReadSnapshot();
		let recordBudgetError: unknown;
		try {
			target.store.queryRunWindowPage({
				runId: "needle",
				fromObservedAtMs: 0,
				throughObservedAtMs: Number.MAX_SAFE_INTEGER,
				readSnapshot,
				maxScannedIndexBytes: 1,
			});
		} catch (error) {
			recordBudgetError = error;
		}
		expect(recordBudgetError).toBeInstanceOf(IncidentRecorderSegmentPageBudgetExceededError);
		expect(recordBudgetError).toMatchObject({
			segmentId: expect.any(String),
			frameKind: "record-index",
			requiredBytes: expect.any(Number),
			configuredBytes: 1,
		});
		expect((recordBudgetError as IncidentRecorderSegmentPageBudgetExceededError).requiredBytes).toBeGreaterThan(1);
		let cursor: IncidentRecorderSegmentQueryCursor | undefined;
		let pages = 0;
		let totalScannedRecords = 0;
		let found: string[] = [];
		do {
			const page = target.store.queryRunWindowPage({
				runId: "needle",
				fromObservedAtMs: 0,
				throughObservedAtMs: Number.MAX_SAFE_INTEGER,
				readSnapshot,
				after: cursor,
				maxScannedSegments: 1,
				maxScannedRecords: 2,
				maxScannedIndexBytes: 1024 * 1024,
			});
			pages += 1;
			totalScannedRecords += page.scannedRecords;
			found = found.concat(page.records.map((record) => record.order));
			expect(page.scannedSegments).toBeLessThanOrEqual(1);
			expect(page.scannedRecords).toBeLessThanOrEqual(2);
			expect(page.scannedIndexBytes).toBeLessThanOrEqual(1024 * 1024);
			if (page.complete) break;
			expect(page.nextCursor).toBeDefined();
			if (cursor) {
				expect(
					page.nextCursor!.segmentSequence > cursor.segmentSequence ||
						(page.nextCursor!.segmentSequence === cursor.segmentSequence &&
							page.nextCursor!.ordinal > cursor.ordinal),
				).toBe(true);
			}
			cursor = page.nextCursor;
		} while (pages < 20);
		expect(pages).toBeGreaterThan(1);
		expect(totalScannedRecords).toBe(9);
		expect(found).toEqual(["8"]);
		target.store.close();
	});

	it("binary-seeks a sparse sealed index without re-examining the cursor prefix", () => {
		const target = fixture({ maxRecordsPerSegment: 100 });
		for (let index = 0; index < 21; index += 1) {
			target.store.append({
				runId: index === 20 ? "deep-match" : "deep-irrelevant",
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from(String(index)),
			});
		}
		target.store.seal("deep-sparse");
		const readSnapshot = target.store.createReadSnapshot();
		let cursor: IncidentRecorderSegmentQueryCursor | undefined;
		let totalScannedRecords = 0;
		const found: string[] = [];
		for (let pageNumber = 0; pageNumber < 10; pageNumber += 1) {
			const page = target.store.queryRunWindowPage({
				runId: "deep-match",
				fromObservedAtMs: 0,
				throughObservedAtMs: Number.MAX_SAFE_INTEGER,
				readSnapshot,
				after: cursor,
				maxScannedSegments: 1,
				maxScannedRecords: 3,
				maxScannedIndexBytes: 1024 * 1024,
			});
			totalScannedRecords += page.scannedRecords;
			found.push(...page.records.map((record) => record.order));
			if (page.complete) break;
			cursor = page.nextCursor;
		}
		expect(totalScannedRecords).toBe(21);
		expect(found).toEqual(["20"]);
		target.store.close();
	});

	it("pages gap-only and mixed recovery evidence through the frozen high-water without record masquerading", () => {
		const target = fixture();
		const discarded = target.store.append({
			runId: "discarded",
			sourceId: "journal",
			observedAtMs: 10,
			order: "1",
			metadata: {},
			payload: Buffer.from("discarded"),
		}).locator;
		target.store.close();
		const firstActive = join(
			target.directory,
			"active",
			readdirSync(join(target.directory, "active")).find((name) => name.endsWith(".open")) ?? "missing",
		);
		const firstDescriptor = openSync(firstActive, "r+");
		try {
			writeSync(firstDescriptor, Buffer.from("BAD!"), 0, 4, discarded.offset);
		} finally {
			closeSync(firstDescriptor);
		}
		const gapOnly = new IncidentRecorderSegmentStore({ directory: target.directory, now: () => 10_000 });
		gapOnly.seal("gap-only");
		gapOnly.append({
			runId: "retained",
			sourceId: "journal",
			observedAtMs: 20,
			order: "2",
			metadata: {},
			payload: Buffer.from("retained"),
		});
		gapOnly.close();
		const secondActive = join(
			target.directory,
			"active",
			readdirSync(join(target.directory, "active")).find((name) => name.endsWith(".open")) ?? "missing",
		);
		appendFileSync(secondActive, Buffer.from("torn"));
		const mixed = new IncidentRecorderSegmentStore({ directory: target.directory, now: () => 20_000 });
		mixed.seal("mixed");
		const readSnapshot = mixed.createReadSnapshot();
		let gapBudgetError: unknown;
		try {
			mixed.queryRecoveryGapsPage({
				readSnapshot,
				maxScannedIndexBytes: 1,
			});
		} catch (error) {
			gapBudgetError = error;
		}
		expect(gapBudgetError).toBeInstanceOf(IncidentRecorderSegmentPageBudgetExceededError);
		expect(gapBudgetError).toMatchObject({
			segmentId: expect.any(String),
			frameKind: "recovery-gap-index",
			requiredBytes: expect.any(Number),
			configuredBytes: 1,
		});
		expect((gapBudgetError as IncidentRecorderSegmentPageBudgetExceededError).requiredBytes).toBeGreaterThan(1);
		let cursor: IncidentRecorderSegmentRecoveryGapQueryCursor | undefined;
		const observed: IncidentRecorderSegmentRecoveryGap[] = [];
		let totalScannedGaps = 0;
		for (let pageNumber = 0; pageNumber < 4; pageNumber += 1) {
			const page = mixed.queryRecoveryGapsPage({
				readSnapshot,
				after: cursor,
				maxGaps: 1,
				maxBytes: 1024 * 1024,
				maxScannedSegments: 1,
				maxScannedGaps: 1,
				maxScannedIndexBytes: 1024 * 1024,
			});
			totalScannedGaps += page.scannedGaps;
			observed.push(...page.gaps);
			expect(page.scannedSegments).toBeLessThanOrEqual(1);
			expect(page.scannedGaps).toBeLessThanOrEqual(1);
			expect(page.scannedIndexBytes).toBeLessThanOrEqual(1024 * 1024);
			if (page.complete) break;
			cursor = page.nextCursor;
		}
		expect(totalScannedGaps).toBe(2);
		expect(observed).toHaveLength(2);
		expect(observed.map((gap) => gap.observedAtMs)).toEqual([10_000, 20_000]);
		expect(observed.every((gap) => gap.observedAtMs > 20)).toBe(true);
		expect(observed.every((gap) => gap.reason === "invalid_or_torn_active_tail")).toBe(true);
		expect(observed.every((gap) => !("locator" in gap))).toBe(true);
		expect(mixed.queryRunWindow({
			runId: "discarded",
			fromObservedAtMs: 0,
			throughObservedAtMs: Number.MAX_SAFE_INTEGER,
		})).toEqual([]);
		expect(mixed.queryRunWindow({
			runId: "retained",
			fromObservedAtMs: 0,
			throughObservedAtMs: Number.MAX_SAFE_INTEGER,
		})[0]?.payload.toString("utf8")).toBe("retained");
		mixed.close();
	});

	it("estimates the whole synchronous append transaction without mutation and reports exact durable path effects", () => {
		const events: IncidentRecorderSegmentDurableWrite[] = [];
		const target = fixture({
			maxRecordsPerSegment: 1,
			onDurableWrite: (event) => events.push(event),
		});
		const input = {
			runId: "admission",
			sourceId: "daemon",
			observedAtMs: 1,
			order: "1",
			metadata: { exact: true },
			payload: Buffer.from("admit-whole-transaction"),
		};
		const beforeFiles = regularFileCount(target.directory);
		const openEntries = target.store.getOpenStorageEntries();
		expect(openEntries).toHaveLength(4);
		expect(openEntries.map((entry) => entry.kind)).toEqual([
			"root-directory",
			"active-directory",
			"sealed-directory",
			"owner-file",
		]);
		expect(openEntries.every((entry) => entry.deviceId.length > 0 && entry.inodeId.length > 0)).toBe(true);
		expect(openEntries.find((entry) => entry.kind === "owner-file")?.createdByOpen).toBe(true);
		const estimate = target.store.estimateAppendStorage(input);
		expect(target.store.getStats().records).toBe(0);
		expect(regularFileCount(target.directory)).toBe(beforeFiles);
		expect(estimate).toMatchObject({
			willCreateSegment: true,
			willSealAfterAppend: true,
			peakAdditionalEntries: 2,
			peakAdditionalInodes: 1,
		});
		expect(estimate.headerFrameBytes).toBeGreaterThan(0);
		expect(estimate.recordFrameBytes).toBeGreaterThan(input.payload.byteLength);
		expect(estimate.sealAfterBytes).toBeGreaterThan(0);
		expect(estimate.peakAdditionalAllocatedBytes).toBeGreaterThanOrEqual(estimate.peakAdditionalBytes);

		let admittedAllocatedBytes = 0;
		const appendPlan = target.store.planAppend(input, (planned) => {
			admittedAllocatedBytes = planned.peakAdditionalAllocatedBytes;
		});
		target.store.commitAppendPlan(appendPlan);
		expect(events.map((event) => event.kind)).toEqual(["segment-created", "record", "sealed"]);
		expect(events.map((event) => event.entryChange)).toEqual([
			"published",
			"same-inode-growth",
			"same-inode-move",
		]);
		expect(events.map((event) => [event.entryDelta, event.inodeDelta])).toEqual([
			[1, 1],
			[0, 0],
			[0, 0],
		]);
		expect(events.every((event) => event.path.startsWith(target.directory))).toBe(true);
		expect(events.every((event) => event.deviceId.length > 0 && event.inodeId.length > 0)).toBe(true);
		expect(events[1]?.previousAllocatedBytes).toBe(events[0]?.allocatedBytes);
		const sealedReceipt = events.at(-1);
		expect(sealedReceipt?.allocatedBytes).toBe(lstatSync(sealedReceipt?.path ?? "missing").blocks * 512);
		expect(sealedReceipt?.parentEffects).toHaveLength(2);
		for (const parentEffect of sealedReceipt?.parentEffects ?? []) {
			expect(parentEffect.afterAllocatedBytes).toBe(lstatSync(parentEffect.path).blocks * 512);
		}
		const parentAllocationGrowth = events.reduce(
			(total, event) =>
				total +
				event.parentEffects.reduce(
					(parentTotal, effect) =>
						parentTotal + Math.max(0, effect.afterAllocatedBytes - effect.beforeAllocatedBytes),
					0,
				),
			0,
		);
		expect(admittedAllocatedBytes).toBeGreaterThanOrEqual(
			(sealedReceipt?.allocatedBytes ?? 0) + parentAllocationGrowth,
		);
		expect(new Set(events.map((event) => event.eventId)).size).toBe(events.length);
		const fillerName = (index: number): string =>
			`f${String(index).padStart(35, "0")}.segment`;
		const probe = fixture();
		probe.store.close();
		const probeSealedDirectory = join(probe.directory, "sealed");
		const probeInitialAllocatedBytes = lstatSync(probeSealedDirectory).blocks * 512;
		let boundaryEntryCount: number | undefined;
		for (let index = 0; index < 4096; index += 1) {
			writeFileSync(join(probeSealedDirectory, fillerName(index)), "", { mode: 0o600 });
			if (lstatSync(probeSealedDirectory).blocks * 512 > probeInitialAllocatedBytes) {
				boundaryEntryCount = index + 1;
				break;
			}
		}
		if (boundaryEntryCount === undefined) {
			expect(lstatSync(probeSealedDirectory).blocks * 512).toBe(probeInitialAllocatedBytes);
		} else {
			const boundaryEvents: IncidentRecorderSegmentDurableWrite[] = [];
			const boundary = fixture({
				maxRecordsPerSegment: 1,
				onDurableWrite: (event) => boundaryEvents.push(event),
			});
			const boundarySealedDirectory = join(boundary.directory, "sealed");
			for (let index = 0; index < boundaryEntryCount - 1; index += 1) {
				writeFileSync(join(boundarySealedDirectory, fillerName(index)), "", { mode: 0o600 });
			}
			const beforeBoundaryAllocatedBytes = lstatSync(boundarySealedDirectory).blocks * 512;
			expect(beforeBoundaryAllocatedBytes).toBe(probeInitialAllocatedBytes);
			let boundaryAdmission = 0;
			const boundaryPlan = boundary.store.planAppend(input, (planned) => {
				boundaryAdmission = planned.peakAdditionalAllocatedBytes;
			});
			boundary.store.commitAppendPlan(boundaryPlan);
			const boundaryInodeGrowth = boundaryEvents.reduce(
				(total, event) =>
					total + Math.max(0, event.allocatedBytes - event.previousAllocatedBytes),
				0,
			);
			const boundaryDirectoryGrowth = boundaryEvents.reduce(
				(total, event) =>
					total +
					event.parentEffects.reduce(
					(parentTotal, effect) =>
						parentTotal + Math.max(0, effect.afterAllocatedBytes - effect.beforeAllocatedBytes),
					0,
				),
				0,
			);
			expect(boundaryDirectoryGrowth).toBeGreaterThan(0);
			expect(boundaryAdmission).toBeGreaterThanOrEqual(
				boundaryInodeGrowth + boundaryDirectoryGrowth,
			);
			boundary.store.close();
		}
		target.store.close();
	});

	it("rejects oversized protection catalogs before reading any segment index", () => {
		let indexReads = 0;
		const target = fixture({
			maxRecordsPerSegment: 1,
			onIndexRead: () => {
				indexReads += 1;
			},
		});
		target.store.append({
			runId: "protection-bounds",
			sourceId: "daemon",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("evidence"),
		});
		const overCountProof = {
			state: "complete" as const,
			generation: 0,
			protectedRunIds: Array<string>(65_537).fill("duplicate-run"),
			fingerprint: "0".repeat(64),
		};
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: overCountProof,
			}),
		).toThrow(/65,536-entry/);
		const overByteProof = {
			state: "complete" as const,
			generation: 0,
			protectedRunIds: Array<string>(65_536).fill("界".repeat(256)),
			fingerprint: "0".repeat(64),
		};
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: overByteProof,
			}),
		).toThrow(/64 MiB/);
		const oversizedSegmentIds = new Set<string>();
		for (let index = 0; index < 65_537; index += 1) {
			oversizedSegmentIds.add(`segment-${String(index)}`);
		}
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds: oversizedSegmentIds,
			}),
		).toThrow(/65,536-entry/);
		expect(indexReads).toBe(0);
		target.store.close();
	});

	it("binds bounded mixed-run pruning to a complete protection generation and fingerprint", () => {
		let indexReads = 0;
		let mutableProofRunIds: string[] | undefined;
		const target = fixture({
			maxRecordsPerSegment: 2,
			onIndexRead: () => {
				indexReads += 1;
				mutableProofRunIds?.splice(0);
			},
		});
		const protectedRunId = "00000000-0000-4000-8000-000000000001";
		const mixedLocator = target.store.append({
			runId: "unprotected-in-mixed",
			sourceId: "daemon",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("context"),
		}).locator;
		target.store.append({
			runId: protectedRunId,
			sourceId: "daemon",
			observedAtMs: 2,
			order: "2",
			metadata: {},
			payload: Buffer.from("protected cause"),
		});
		const deletableLocator = target.store.append({
			runId: "deletable-run",
			sourceId: "daemon",
			observedAtMs: 3,
			order: "3",
			metadata: {},
			payload: Buffer.from("old context"),
		}).locator;
		target.store.append({
			runId: "deletable-run",
			sourceId: "kernel",
			observedAtMs: 4,
			order: "4",
			metadata: {},
			payload: Buffer.from("old symptom"),
		});
		target.store.append({
			runId: "active-anchor",
			sourceId: "daemon",
			observedAtMs: 5,
			order: "5",
			metadata: {},
			payload: Buffer.from("active"),
		});

		const continuationProtection = pruneProtection(7, [protectedRunId]);
		mutableProofRunIds = [...continuationProtection.protectedRunIds];
		const protection = { ...continuationProtection, protectedRunIds: mutableProofRunIds };
		const indexReadsBeforePrune = indexReads;
		const first = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(first).toMatchObject({ deletedSegmentIds: [], examinedSegments: 1, moreWork: true });
		expect(first.continuation).toBeDefined();
		expect(indexReads - indexReadsBeforePrune).toBe(1);
		expect(mutableProofRunIds).toEqual([]);
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(8, [protectedRunId]),
				maxSegments: 1,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
			}),
		).toThrow(/continuation is stale/);
		const second = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: continuationProtection,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
			continuation: first.continuation!,
		});
		expect(second.deletedSegmentIds).toEqual([deletableLocator.segmentId]);
		expect(
			existsSync(join(target.directory, "sealed", `${mixedLocator.segmentId}.segment`)),
		).toBe(true);
		target.store.close();
	});

	it("snapshots caller segment protection before index callbacks and binds the continuation", () => {
		let mutableProtectedSegmentIds: Set<string> | undefined;
		const target = fixture({
			maxRecordsPerSegment: 1,
			onIndexRead: () => {
				mutableProtectedSegmentIds?.clear();
			},
		});
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `segment-snapshot-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		mutableProtectedSegmentIds = new Set([locators[1]!.segmentId]);
		const protection = pruneProtection();
		const first = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection,
			protectedSegmentIds: mutableProtectedSegmentIds,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(first.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(first.continuation).toBeDefined();
		expect(mutableProtectedSegmentIds.size).toBe(0);
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection,
				protectedSegmentIds: mutableProtectedSegmentIds,
				maxSegments: 2,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
			}),
		).toThrow(/continuation is stale/);
		const completed = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection,
			protectedSegmentIds: new Set([locators[1]!.segmentId]),
			maxSegments: 2,
			maxBytes: 1024 * 1024,
			continuation: first.continuation!,
		});
		expect(completed.deletedSegmentIds).toEqual([]);
		expect(completed.moreWork).toBe(false);
		expect(
			existsSync(join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`)),
		).toBe(true);
		target.store.close();
	});

	it("advances a bounded prune continuation past protected entries and resets after a complete pass", () => {
		let now = 10;
		const target = fixture({ now: () => now, maxRecordsPerSegment: 1 });
		const locators = [];
		const regressedTimes = [50, 10, 40, 20, 30];
		for (let index = 0; index < 5; index += 1) {
			now = regressedTimes[index] ?? 0;
			locators.push(
				target.store.append({
					runId: "fair-prune",
					sourceId: "daemon",
					observedAtMs: now,
					order: String(now),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		const protectedIds = new Set(locators.slice(0, 3).map((locator) => locator.segmentId));
		const first = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			protectedSegmentIds: protectedIds,
			maxSegments: 2,
			maxBytes: 1024 * 1024,
		});
		expect(first).toMatchObject({ deletedSegmentIds: [], examinedSegments: 2, moreWork: true });
		expect(first.continuation).toBeDefined();
		const second = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			protectedSegmentIds: protectedIds,
			maxSegments: 2,
			maxBytes: 1024 * 1024,
			continuation: first.continuation!,
		});
		expect(second.deletedSegmentIds).toEqual([locators[3]?.segmentId]);
		expect(second.moreWork).toBe(true);
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds: protectedIds,
				maxSegments: 2,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
			}),
		).toThrow(/exact registered object/);
		const completed = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			protectedSegmentIds: protectedIds,
			maxSegments: 2,
			maxBytes: 1024 * 1024,
			continuation: second.continuation!,
		});
		expect(completed.moreWork).toBe(false);
		expect(completed.continuation).toBeUndefined();

		const revisited = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(revisited.deletedSegmentIds).toEqual([locators[0]?.segmentId]);
		target.store.close();
	});

	it("binds a live prune continuation to its exact frozen high-water capability", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const initialLocators = [];
		for (let index = 0; index < 4; index += 1) {
			initialLocators.push(
				target.store.append({
					runId: `live-frozen-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		const first = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(first).toMatchObject({ deletedSegmentIds: [initialLocators[0]!.segmentId], moreWork: true });
		expect(Object.isFrozen(first.continuation)).toBe(true);
		const frozenHighWater = first.continuation!.highWaterSegmentSequence;
		const lateLocators = [];
		for (let index = 4; index < 6; index += 1) {
			lateLocators.push(
				target.store.append({
					runId: `live-late-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		const sealedBeforeForgery = readdirSync(join(target.directory, "sealed")).sort();
		const cloned = Object.freeze({ ...first.continuation! });
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: cloned,
			}),
		).toThrow(/exact registered object/);
		const forgedHighWater = Object.freeze({
			...first.continuation!,
			highWaterSegmentSequence: frozenHighWater + 100,
		});
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: forgedHighWater,
			}),
		).toThrow(/exact registered object/);
		expect(readdirSync(join(target.directory, "sealed")).sort()).toEqual(sealedBeforeForgery);
		const completed = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 10,
			maxBytes: 1024 * 1024,
			continuation: first.continuation!,
		});
		expect(completed.moreWork).toBe(false);
		const lateSealedLocators = lateLocators;
		expect(lateSealedLocators.every((locator) => locator.segmentSequence > frozenHighWater)).toBe(true);
		expect(
			lateSealedLocators.every((locator) => existsSync(join(target.directory, "sealed", `${locator.segmentId}.segment`))),
		).toBe(true);
		target.store.close();
	});

	it("bounds and expires abandoned live prune cursor capabilities", () => {
		let now = 100;
		const target = fixture({ now: () => now, maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `cursor-cap-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		const cursors = Array.from({ length: 32 }, () => {
			const page = target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(page.moreWork).toBe(true);
			return page.continuation!;
		});
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			}),
		).toThrow(/32-cursor ceiling/);
		now += 5 * 60 * 1000 + 1;
		const replacement = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			protectedSegmentIds,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(replacement.continuation).toBeDefined();
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: cursors[0]!,
			}),
		).toThrow(/not an active process-local capability/);
		target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			protectedSegmentIds,
			maxSegments: 10,
			maxBytes: 1024 * 1024,
			continuation: replacement.continuation!,
		});
		target.store.close();
	});

	it("preserves earlier live deletions when a later index observer fails", () => {
		let armed = false;
		let observedIndexes = 0;
		const target = fixture({
			maxRecordsPerSegment: 1,
			onIndexRead: () => {
				if (!armed) return;
				observedIndexes += 1;
				if (observedIndexes === 2) throw new Error("injected later index observer failure");
			},
		});
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `observer-receipt-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		armed = true;
		let thrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const mutation = (thrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.result).toMatchObject({
			deletedSegmentIds: [locators[0]!.segmentId],
			locatorsInvalidated: true,
			requiresFullReconciliation: true,
			moreWork: true,
		});
		expect(Object.isFrozen(mutation.result)).toBe(true);
		expect(existsSync(join(target.directory, "sealed", `${locators[0]!.segmentId}.segment`))).toBe(false);
		expect(existsSync(join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`))).toBe(true);
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			}),
		).toThrow(IncidentRecorderSegmentStorePoisonedError);
	});

	it("surfaces a later live index-handle cleanup failure instead of relabeling it corrupt", () => {
		let armed = false;
		let indexCloses = 0;
		const cleanupFailure = new Error("injected index descriptor cleanup failure");
		const target = fixture({
			maxRecordsPerSegment: 1,
			faultInjector: (point) => {
				if (!armed || point !== "after-prune-index-handle-close") return;
				indexCloses += 1;
				if (indexCloses === 2) throw cleanupFailure;
			},
		});
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `index-cleanup-receipt-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		armed = true;
		let thrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const mutation = (thrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(mutation.result.corruptSegmentIds).toEqual([]);
		const cleanup = mutation.cause as IncidentRecorderDescriptorCleanupError;
		expect(cleanup).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		expect(cleanup.primaryError).toBe(cleanupFailure);
		expect(cleanup.cleanupErrors).toEqual([]);
		expect(existsSync(join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`))).toBe(true);
	});

	it("preserves verifier primary and cleanup failures after an earlier live deletion", () => {
		let armed = false;
		let indexReads = 0;
		let mutatePath = "";
		let mutateOffset = 0;
		const cleanupFailure = new Error("injected verifier descriptor cleanup failure");
		const target = fixture({
			maxRecordsPerSegment: 1,
			onIndexRead: () => {
				if (!armed) return;
				indexReads += 1;
				if (indexReads !== 2) return;
				const descriptor = openSync(mutatePath, "r+");
				try {
					const byte = Buffer.alloc(1);
					readSync(descriptor, byte, 0, 1, mutateOffset);
					byte[0] = (byte[0] ?? 0) ^ 0xff;
					writeSync(descriptor, byte, 0, 1, mutateOffset);
				} finally {
					closeSync(descriptor);
				}
			},
			faultInjector: (point) => {
				if (armed && point === "after-prune-verifier-failure-handle-close") throw cleanupFailure;
			},
		});
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `verifier-cleanup-receipt-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		mutatePath = join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`);
		mutateOffset = locators[1]!.offset + 20;
		armed = true;
		let thrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const mutation = (thrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(mutation.result.corruptSegmentIds).toEqual([]);
		const cleanup = mutation.cause as IncidentRecorderDescriptorCleanupError;
		expect(cleanup).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		expect(cleanup.primaryError).toBeInstanceOf(Error);
		expect((cleanup.primaryError as Error).message).toMatch(/content checksum mismatch/);
		expect(cleanup.cleanupErrors).toEqual([cleanupFailure]);
		expect(existsSync(mutatePath)).toBe(true);
	});

	it("preserves a live mutation receipt when poisoning closes an active descriptor with a cleanup fault", () => {
		let armed = false;
		let indexReads = 0;
		const activeCloseFailure = new Error("injected active descriptor cleanup failure");
		const target = fixture({
			maxRecordsPerSegment: 2,
			onIndexRead: () => {
				if (!armed) return;
				indexReads += 1;
				if (indexReads === 2) throw new Error("injected later index observer failure");
			},
			faultInjector: (point) => {
				if (armed && point === "after-poison-active-handle-close") throw activeCloseFailure;
			},
		});
		const locators = [];
		for (let index = 0; index < 5; index += 1) {
			locators.push(
				target.store.append({
					runId: `active-cleanup-receipt-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		armed = true;
		let thrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const mutation = (thrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(mutation.result.corruptSegmentIds).toEqual([]);
		const cleanup = mutation.cause as IncidentRecorderDescriptorCleanupError;
		expect(cleanup).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		expect(cleanup.primaryError).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(cleanup.cleanupErrors).toEqual([activeCloseFailure]);
		expect(() => target.store.getStats()).toThrow(IncidentRecorderSegmentStorePoisonedError);
	});

	it("does not relabel a raw live filesystem failure as corruption after an earlier deletion", () => {
		let armed = false;
		let indexReads = 0;
		let removedPath = "";
		const target = fixture({
			maxRecordsPerSegment: 1,
			onIndexRead: () => {
				if (!armed) return;
				indexReads += 1;
				if (indexReads === 2) rmSync(removedPath);
			},
		});
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `live-errno-receipt-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		removedPath = join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`);
		armed = true;
		let thrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const mutation = (thrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(mutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(mutation.result.corruptSegmentIds).toEqual([]);
		expect((mutation.cause as NodeJS.ErrnoException).code).toBe("ENOENT");
	});

	it("consumes every live prune capability immediately when one session poisons the store", () => {
		let armed = false;
		let indexReads = 0;
		const target = fixture({
			maxRecordsPerSegment: 1,
			onIndexRead: () => {
				if (!armed) return;
				indexReads += 1;
				if (indexReads === 2) throw new Error("injected multi-session poison");
			},
		});
		const locators = [];
		for (let index = 0; index < 5; index += 1) {
			locators.push(
				target.store.append({
					runId: `multi-session-poison-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		vi.useFakeTimers();
		try {
			const timerBaseline = vi.getTimerCount();
			const first = target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			const second = target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			expect(second.continuation).toBeDefined();
			expect(vi.getTimerCount()).toBe(timerBaseline + 2);
			armed = true;
			let thrown: unknown;
			try {
				target.store.pruneSealedSegments({
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				});
			} catch (error) {
				thrown = error;
			}
			expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
			const mutation = (thrown as IncidentRecorderSegmentStorePoisonedError)
				.cause as IncidentRecorderSegmentPruneMutationError;
			expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
			expect(mutation.result.deletedSegmentIds).toEqual([locators[1]!.segmentId]);
			expect(vi.getTimerCount()).toBe(timerBaseline);
			expect(() =>
				target.store.pruneSealedSegments({
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: second.continuation!,
				}),
			).toThrow(IncidentRecorderSegmentStorePoisonedError);
			expect(vi.getTimerCount()).toBe(timerBaseline);
			target.store.close();
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("continues mandatory close cleanup when root accounting fails with a live cursor", () => {
		let armed = false;
		const accountingFailure = new Error("injected close root accounting failure");
		const target = fixture({
			maxRecordsPerSegment: 1,
			onOpenStorageResult: () => {},
			faultInjector: (point) => {
				if (armed && point === "before-close-root-accounting") throw accountingFailure;
			},
		});
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `close-accounting-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		vi.useFakeTimers();
		try {
			const timerBaseline = vi.getTimerCount();
			const page = target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds: new Set([locators[0]!.segmentId]),
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(page.continuation).toBeDefined();
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			armed = true;
			let thrown: unknown;
			try {
				target.store.close();
			} catch (error) {
				thrown = error;
			}
			expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
			expect((thrown as IncidentRecorderSegmentStorePoisonedError).cause).toBe(accountingFailure);
			expect(vi.getTimerCount()).toBe(timerBaseline);
			expect(existsSync(join(target.directory, ".writer-owner.json"))).toBe(false);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("preserves a prune receipt when poisoned close owner validation and cleanup also fail", () => {
		let pruneArmed = false;
		let malformedOwnerArmed = false;
		let indexReads = 0;
		const ownerCleanupFailure = new Error("injected live owner descriptor cleanup failure");
		const target = fixture({
			maxRecordsPerSegment: 1,
			onIndexRead: () => {
				if (!pruneArmed) return;
				indexReads += 1;
				if (indexReads === 2) throw new Error("injected poison before close");
			},
			faultInjector: (point) => {
				if (malformedOwnerArmed && point === "after-owner-claim-handle-close") throw ownerCleanupFailure;
			},
		});
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `poison-close-owner-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		pruneArmed = true;
		let pruneThrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			pruneThrown = error;
		}
		expect(pruneThrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const originalMutation = (pruneThrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(originalMutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		writeFileSync(join(target.directory, ".writer-owner.json"), "{malformed\n", { mode: 0o600 });
		malformedOwnerArmed = true;
		let closeThrown: unknown;
		try {
			target.store.close();
		} catch (error) {
			closeThrown = error;
		}
		expect(closeThrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const closeMutation = (closeThrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(closeMutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(closeMutation.directoryDurability).toBe(originalMutation.directoryDurability);
		expect(closeMutation.result).toBe(originalMutation.result);
		const closeCleanup = closeMutation.cause as IncidentRecorderDescriptorCleanupError;
		expect(closeCleanup).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		expect(closeCleanup.primaryError).toBe(originalMutation);
		expect(closeCleanup.cleanupErrors).toHaveLength(1);
		const ownerCleanup = closeCleanup.cleanupErrors[0] as IncidentRecorderDescriptorCleanupError;
		expect(ownerCleanup).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		expect(ownerCleanup.primaryError).toBeInstanceOf(Error);
		expect((ownerCleanup.primaryError as Error).message).toMatch(/writer ownership claim/);
		expect(ownerCleanup.cleanupErrors).toEqual([ownerCleanupFailure]);
	});

	it("preserves earlier live deletions when a protected handle close boundary fails", () => {
		let armed = false;
		const target = fixture({
			maxRecordsPerSegment: 1,
			faultInjector: (point) => {
				if (armed && point === "after-prune-protected-handle-close") {
					throw new Error("injected protected handle close boundary failure");
				}
			},
		});
		const runIds = ["unprotected", "protected", "later", "anchor"];
		const locators = runIds.map(
			(runId, index) =>
				target.store.append({
					runId,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
		);
		armed = true;
		let thrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(0, ["protected"]),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const mutation = (thrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(existsSync(join(target.directory, "sealed", `${locators[0]!.segmentId}.segment`))).toBe(false);
		expect(existsSync(join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`))).toBe(true);
	});

	it("fails closed when the live prune path is replaced after verification", () => {
		let armed = false;
		let targetPath = "";
		let replacementPath = "";
		let parkedPath = "";
		const target = fixture({
			maxRecordsPerSegment: 1,
			faultInjector: (point) => {
				if (point !== "before-prune-unlink-after-verify" || !armed) return;
				armed = false;
				renameSync(targetPath, parkedPath);
				copyFileSync(replacementPath, targetPath);
				chmodSync(targetPath, 0o600);
			},
		});
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `live-swap-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		targetPath = join(target.directory, "sealed", `${locators[0]!.segmentId}.segment`);
		replacementPath = join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`);
		parkedPath = join(target.directory, "sealed", `${locators[0]!.segmentId}.parked`);
		armed = true;
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			}),
		).toThrow(/prune target identity changed after verification/);
		expect(existsSync(targetPath)).toBe(true);
		expect(existsSync(replacementPath)).toBe(true);
		expect(existsSync(parkedPath)).toBe(true);
		target.store.close();
	});

	it("keeps live prune authority bound when the sealed directory is replaced with a hard link", () => {
		let armed = false;
		let targetName = "";
		let sealedDirectory = "";
		let displacedDirectory = "";
		const target = fixture({
			maxRecordsPerSegment: 1,
			faultInjector: (point) => {
				if (point !== "before-prune-unlink-after-verify" || !armed) return;
				armed = false;
				renameSync(sealedDirectory, displacedDirectory);
				mkdirSync(sealedDirectory, { mode: 0o700 });
				linkSync(join(displacedDirectory, targetName), join(sealedDirectory, targetName));
			},
		});
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `live-directory-swap-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		sealedDirectory = join(target.directory, "sealed");
		displacedDirectory = join(target.directory, "sealed.displaced");
		targetName = `${locators[0]!.segmentId}.segment`;
		armed = true;
		expect(() =>
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			}),
		).toThrow(/sealed segment directory identity changed/);
		expect(existsSync(join(displacedDirectory, targetName))).toBe(true);
		expect(existsSync(join(sealedDirectory, targetName))).toBe(true);
		target.store.close();
	});

	it("reports a definite live deletion with unknown durability when interrupted before directory fsync", () => {
		const durableWrites: IncidentRecorderSegmentDurableWrite[] = [];
		const target = fixture({
			maxRecordsPerSegment: 1,
			onDurableWrite: (event) => durableWrites.push(event),
			faultInjector: (point) => {
				if (point === "after-prune-unlink-before-directory-fsync") {
					throw new Error("injected post-unlink interruption");
				}
			},
		});
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `live-post-unlink-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		let thrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const mutation = (thrown as { cause?: unknown }).cause;
		expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		const typedMutation = mutation as IncidentRecorderSegmentPruneMutationError;
		expect(typedMutation.directoryDurability).toBe("unknown");
		expect(typedMutation.result).toMatchObject({
			deletedSegmentIds: [locators[0]!.segmentId],
			locatorsInvalidated: true,
			requiresFullReconciliation: true,
			moreWork: true,
		});
		expect(typedMutation.result.continuation).toBeUndefined();
		expect(Object.isFrozen(typedMutation.result)).toBe(true);
		expect(Object.isFrozen(typedMutation.result.deletedSegmentIds)).toBe(true);
		expect(
			existsSync(join(target.directory, "sealed", `${locators[0]!.segmentId}.segment`)),
		).toBe(false);
		expect(durableWrites.some((event) => event.kind === "pruned")).toBe(false);
		target.store.close();
	});

	it("reports a confirmed immutable live deletion when the pruned durability observer fails", () => {
		let armed = false;
		const observerFailure = new Error("injected post-fsync pruned observer failure");
		const target = fixture({
			maxRecordsPerSegment: 1,
			onDurableWrite: (event) => {
				if (armed && event.kind === "pruned") throw observerFailure;
			},
		});
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `live-pruned-observer-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		armed = true;
		let thrown: unknown;
		try {
			target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentStorePoisonedError);
		const mutation = (thrown as IncidentRecorderSegmentStorePoisonedError)
			.cause as IncidentRecorderSegmentPruneMutationError;
		expect(mutation).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.cause).toBe(observerFailure);
		expect(mutation.result).toMatchObject({
			deletedSegmentIds: [locators[0]!.segmentId],
			corruptSegmentIds: [],
			locatorsInvalidated: true,
			requiresFullReconciliation: true,
			moreWork: true,
		});
		expect(Object.isFrozen(mutation.result)).toBe(true);
		expect(Object.isFrozen(mutation.result.deletedSegmentIds)).toBe(true);
		expect(Object.isFrozen(mutation.result.corruptSegmentIds)).toBe(true);
		expect(existsSync(join(target.directory, "sealed", `${locators[0]!.segmentId}.segment`))).toBe(false);
		target.store.close();
	});

	it("commits a single-use frozen append plan across a time boundary without caller mutation or rotation TOCTOU", () => {
		let now = 0;
		const target = fixture({ now: () => now, maxSegmentAgeMs: 10, maxRecordsPerSegment: 100 });
		target.store.append({
			runId: "planned",
			sourceId: "daemon",
			observedAtMs: 0,
			order: "0",
			metadata: {},
			payload: Buffer.from("first"),
		});
		now = 9;
		const mutablePayload = Buffer.from("frozen");
		const mutableMetadata = { nested: { value: "original" } };
		let admitted = false;
		const plan = target.store.planAppend(
			{
				idempotencyKey: "planned:1",
				runId: "planned",
				sourceId: "daemon",
				observedAtMs: 1,
				order: "1",
				metadata: mutableMetadata,
				payload: mutablePayload,
			},
			() => {
				admitted = true;
			},
		);
		expect(admitted).toBe(true);
		expect(plan.estimate.willSealBeforeAppend).toBe(false);
		mutablePayload.fill(0x78);
		mutableMetadata.nested.value = "mutated";
		now = 100;
		expect(target.store.commitAppendPlan(plan).status).toBe("appended");
		expect(target.store.getStats()).toMatchObject({ activeSegments: 1, sealedSegments: 0, records: 2 });
		const frozen = target.store.queryRunWindow({ runId: "planned", fromObservedAtMs: 1, throughObservedAtMs: 1 })[0];
		expect(frozen?.payload.toString("utf8")).toBe("frozen");
		expect(frozen?.metadata).toEqual({ nested: { value: "original" } });
		expect(() => target.store.commitAppendPlan(plan)).toThrow(/already consumed/);
		target.store.close();
	});

	it("reports the exact required prune budget when the first eligible segment is oversized", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 2; index += 1) {
			target.store.append({
				runId: "oversized-prune",
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.alloc(1024, index),
			});
		}
		const blocked = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 10,
			maxBytes: 1,
		});
		expect(blocked).toMatchObject({ deletedSegmentIds: [], moreWork: true });
		expect(blocked.requiredBytes).toBeGreaterThan(1);
		expect(blocked.continuation).toBeUndefined();
		const progressed = target.store.pruneSealedSegments({
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			maxSegments: 10,
			maxBytes: blocked.requiredBytes!,
		});
		expect(progressed.deletedSegmentIds).toHaveLength(1);
		target.store.close();
	});

	it("retains the exact live continuation when a resumed page cannot afford its first segment", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `resumed-live-budget-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.alloc(1024, index),
				}).locator,
			);
		}
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		vi.useFakeTimers();
		try {
			const timerBaseline = vi.getTimerCount();
			const first = target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const blocked = target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				maxSegments: 10,
				maxBytes: 1,
				continuation: first.continuation!,
			});
			expect(blocked).toMatchObject({ deletedSegmentIds: [], moreWork: true });
			expect(blocked.requiredBytes).toBeGreaterThan(1);
			expect(blocked.continuation).toBe(first.continuation);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const completed = target.store.pruneSealedSegments({
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: blocked.continuation!,
			});
			expect(completed.moreWork).toBe(false);
			expect(completed.continuation).toBeUndefined();
			expect(vi.getTimerCount()).toBe(timerBaseline);
			target.store.close();
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("preflights a duplicate segment identity before rotation and remains usable for a later plan", () => {
		const directory = mkdtempSync(join(tmpdir(), "prime-agent-segment-store-"));
		roots.push(directory);
		let now = 0;
		let allowUnique = false;
		let first = true;
		const createSegmentId = (): string => {
			if (first) {
				first = false;
				return "first-segment";
			}
			return allowUnique ? "second-segment" : "first-segment";
		};
		const store = new IncidentRecorderSegmentStore({
			directory,
			createSegmentId,
			now: () => now,
			maxSegmentAgeMs: 10,
			maxRecordsPerSegment: 100,
		});
		store.append({
			runId: "identity-preflight",
			sourceId: "daemon",
			observedAtMs: 0,
			order: "0",
			metadata: {},
			payload: Buffer.from("first"),
		});
		now = 20;
		expect(() =>
			store.planAppend({
				runId: "identity-preflight",
				sourceId: "daemon",
				observedAtMs: 20,
				order: "20",
				metadata: {},
				payload: Buffer.from("second"),
			}),
		).toThrow(/unique segment identity/);
		expect(store.getStats()).toMatchObject({ activeSegments: 1, sealedSegments: 0, records: 1 });
		allowUnique = true;
		expect(
			store.append({
				runId: "identity-preflight",
				sourceId: "daemon",
				observedAtMs: 20,
				order: "20",
				metadata: {},
				payload: Buffer.from("second"),
			}).status,
		).toBe("appended");
		expect(store.getStats()).toMatchObject({ activeSegments: 1, sealedSegments: 1, records: 2 });
		store.close();
	});

	it("rethrows a startup catalog budget failure instead of relabeling valid segments corrupt", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 3; index += 1) {
			target.store.append({
				runId: `startup-budget-${String(index)}`,
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		target.store.close();
		const sealedBefore = readdirSync(join(target.directory, "sealed")).sort();
		const filesBefore = regularFileCount(target.directory);
		expect(() =>
			new IncidentRecorderSegmentStore({
				directory: target.directory,
				maxStartupCatalogBytes: 1000,
			}),
		).toThrow(/segment catalog exceeds maxStartupCatalogBytes/);
		expect(readdirSync(join(target.directory, "sealed")).sort()).toEqual(sealedBefore);
		expect(regularFileCount(target.directory)).toBe(filesBefore);
		expect(existsSync(join(target.directory, ".writer-owner.json"))).toBe(false);
	});

	it("snapshots recovery protection before ownership callbacks without allocating recovery state", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `recovery-snapshot-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const beforeRootEntries = readdirSync(target.directory).sort();
		const beforeInodes = regularFileCount(target.directory);
		const mutableProtectedSegmentIds = new Set([locators[1]!.segmentId]);
		const result = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: target.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			protectedSegmentIds: mutableProtectedSegmentIds,
			externalWriterExcluded: true,
			maxSegments: 3,
			maxBytes: 1024 * 1024,
			onOwnershipTransitionCheck: () => {
				mutableProtectedSegmentIds.clear();
			},
		});
		expect(result).toMatchObject({
			deletedSegmentIds: [locators[0]!.segmentId],
			requiresFullReconciliation: true,
			moreWork: false,
		});
		expect(mutableProtectedSegmentIds.size).toBe(0);
		expect(
			existsSync(join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`)),
		).toBe(true);
		expect(readdirSync(target.directory).sort()).toEqual(beforeRootEntries);
		expect(regularFileCount(target.directory)).toBe(beforeInodes - 1);
		expect(existsSync(join(target.directory, ".writer-owner.json"))).toBe(false);
	});

	it("fails closed when a recovery ownership callback replaces the verified target path", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `recovery-swap-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const sealedDirectory = join(target.directory, "sealed");
		const targetPath = join(sealedDirectory, `${locators[0]!.segmentId}.segment`);
		const replacementPath = join(sealedDirectory, `${locators[1]!.segmentId}.segment`);
		const parkedPath = join(sealedDirectory, `${locators[0]!.segmentId}.parked`);
		const sealedBefore = readdirSync(sealedDirectory)
			.filter((name) => name.endsWith(".segment"))
			.sort();
		let armed = true;
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				onOwnershipTransitionCheck: () => {
					if (!armed) return;
					armed = false;
					renameSync(targetPath, parkedPath);
					copyFileSync(replacementPath, targetPath);
					chmodSync(targetPath, 0o600);
				},
			}),
		).toThrow(/prune target identity changed after verification/);
		expect(
			readdirSync(sealedDirectory)
				.filter((name) => name.endsWith(".segment"))
				.sort(),
		).toEqual(sealedBefore);
		expect(existsSync(targetPath)).toBe(true);
		expect(existsSync(replacementPath)).toBe(true);
		expect(existsSync(parkedPath)).toBe(true);
	});

	it("reports a confirmed recovery deletion when the post-fsync ownership callback fails", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `recovery-post-fsync-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		const first = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: target.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			protectedSegmentIds,
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(first.continuation).toBeDefined();
		const filesBefore = regularFileCount(target.directory);
		let ownershipChecks = 0;
		let thrown: unknown;
		try {
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
				onOwnershipTransitionCheck: () => {
					ownershipChecks += 1;
					if (ownershipChecks === 2) throw new Error("injected post-fsync ownership failure");
				},
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		const mutation = thrown as IncidentRecorderSegmentPruneMutationError;
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.result).toMatchObject({
			deletedSegmentIds: [locators[1]!.segmentId],
			locatorsInvalidated: true,
			requiresFullReconciliation: true,
			moreWork: true,
		});
		expect(mutation.result.continuation).toBeUndefined();
		expect(Object.isFrozen(mutation.result)).toBe(true);
		expect(Object.isFrozen(mutation.result.deletedSegmentIds)).toBe(true);
		expect(ownershipChecks).toBe(2);
		expect(
			existsSync(join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`)),
		).toBe(false);
		expect(regularFileCount(target.directory)).toBe(filesBefore - 1);
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
			}),
		).toThrow(/not an active process-local capability/);
	});

	it("preserves recovery verifier primary and cleanup failures after an earlier deletion", () => {
		const cleanupFailure = new Error("injected recovery verifier cleanup failure");
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `recovery-verifier-cleanup-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const corruptPath = join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`);
		const descriptor = openSync(corruptPath, "r+");
		try {
			const byte = Buffer.alloc(1);
			const offset = locators[1]!.offset + 20;
			readSync(descriptor, byte, 0, 1, offset);
			byte[0] = (byte[0] ?? 0) ^ 0xff;
			writeSync(descriptor, byte, 0, 1, offset);
		} finally {
			closeSync(descriptor);
		}
		vi.useFakeTimers();
		try {
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const timerBaseline = vi.getTimerCount();
			let thrown: unknown;
			try {
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					faultInjector: (point) => {
						if (point === "after-prune-verifier-failure-handle-close") throw cleanupFailure;
					},
				});
			} catch (error) {
				thrown = error;
			}
			expect(thrown).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
			const mutation = thrown as IncidentRecorderSegmentPruneMutationError;
			expect(mutation.directoryDurability).toBe("confirmed");
			expect(mutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
			expect(mutation.result.corruptSegmentIds).toEqual([]);
			const cleanup = mutation.cause as IncidentRecorderDescriptorCleanupError;
			expect(cleanup).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
			expect(cleanup.primaryError).toBeInstanceOf(Error);
			expect((cleanup.primaryError as Error).message).toMatch(/index or content checksum is invalid/);
			expect(cleanup.cleanupErrors).toEqual([cleanupFailure]);
			expect(existsSync(corruptPath)).toBe(true);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("preserves a recovery catalog primary when directory cleanup also fails", () => {
		const cleanupFailure = new Error("injected recovery catalog cleanup failure");
		const target = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 3; index += 1) {
			target.store.append({
				runId: `catalog-cleanup-${String(index)}`,
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		target.store.close();
		const sealedBefore = readdirSync(join(target.directory, "sealed")).sort();
		let thrown: unknown;
		try {
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				maxStartupEntries: 3,
				faultInjector: (point) => {
					if (point === "after-recovery-catalog-directory-close") throw cleanupFailure;
				},
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		const cleanup = thrown as IncidentRecorderDescriptorCleanupError;
		expect(cleanup.primaryError).toBeInstanceOf(Error);
		expect((cleanup.primaryError as Error).message).toMatch(/maxStartupEntries/);
		expect(cleanup.cleanupErrors).toEqual([cleanupFailure]);
		expect(readdirSync(join(target.directory, "sealed")).sort()).toEqual(sealedBefore);
	});

	it("preserves a malformed recovery owner claim when its descriptor cleanup also fails", () => {
		const target = fixture();
		target.store.close();
		writeFileSync(join(target.directory, ".writer-owner.json"), "{malformed\n", { mode: 0o600 });
		const cleanupFailure = new Error("injected recovery owner descriptor cleanup failure");
		let thrown: unknown;
		try {
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				faultInjector: (point) => {
					if (point === "after-recovery-owner-claim-handle-close") throw cleanupFailure;
				},
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		const cleanup = thrown as IncidentRecorderDescriptorCleanupError;
		expect(cleanup.primaryError).toBeInstanceOf(Error);
		expect((cleanup.primaryError as Error).message).toMatch(/writer ownership claim/);
		expect(cleanup.cleanupErrors).toEqual([cleanupFailure]);
	});

	it("preserves a recovery ownership transition when root-directory cleanup also fails", () => {
		const target = fixture();
		target.store.close();
		writeFileSync(join(target.directory, ".writer-owner-transition.tmp"), "transition", { mode: 0o600 });
		const cleanupFailure = new Error("injected recovery root directory cleanup failure");
		let thrown: unknown;
		try {
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				faultInjector: (point) => {
					if (point === "after-recovery-root-directory-close") throw cleanupFailure;
				},
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		const cleanup = thrown as IncidentRecorderDescriptorCleanupError;
		expect(cleanup.primaryError).toBeInstanceOf(Error);
		expect((cleanup.primaryError as Error).message).toMatch(/ownership transition is in progress/);
		expect(cleanup.cleanupErrors).toEqual([cleanupFailure]);
	});

	it("retains a confirmed recovery receipt when post-unlink owner validation and cleanup fail", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `owner-cleanup-receipt-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const ownerPath = join(target.directory, ".writer-owner.json");
		writeFileSync(
			ownerPath,
			`${JSON.stringify({ version: 1, nonce: "stale-owner", pid: 100, startTime: "stale", bootId: "old" })}\n`,
			{ mode: 0o600 },
		);
		let ownershipChecks = 0;
		let malformedOwnerArmed = false;
		const cleanupFailure = new Error("injected post-unlink owner descriptor cleanup failure");
		let thrown: unknown;
		try {
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				isOwnerAlive: () => false,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				onOwnershipTransitionCheck: () => {
					ownershipChecks += 1;
					if (ownershipChecks !== 2) return;
					writeFileSync(ownerPath, "{malformed\n", { mode: 0o600 });
					malformedOwnerArmed = true;
				},
				faultInjector: (point) => {
					if (malformedOwnerArmed && point === "after-recovery-owner-claim-handle-close") {
						throw cleanupFailure;
					}
				},
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		const mutation = thrown as IncidentRecorderSegmentPruneMutationError;
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(mutation.result.corruptSegmentIds).toEqual([]);
		const cleanup = mutation.cause as IncidentRecorderDescriptorCleanupError;
		expect(cleanup).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
		expect(cleanup.primaryError).toBeInstanceOf(Error);
		expect((cleanup.primaryError as Error).message).toMatch(/writer ownership claim/);
		expect(cleanup.cleanupErrors).toEqual([cleanupFailure]);
		expect(existsSync(join(target.directory, "sealed", `${locators[0]!.segmentId}.segment`))).toBe(false);
	});

	it("does not relabel a raw recovery filesystem failure as corruption after an earlier deletion", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `recovery-errno-receipt-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const removedPath = join(target.directory, "sealed", `${locators[1]!.segmentId}.segment`);
		let ownershipChecks = 0;
		let thrown: unknown;
		try {
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				onOwnershipTransitionCheck: () => {
					ownershipChecks += 1;
					if (ownershipChecks === 2) rmSync(removedPath);
				},
			});
		} catch (error) {
			thrown = error;
		}
		expect(thrown).toBeInstanceOf(IncidentRecorderSegmentPruneMutationError);
		const mutation = thrown as IncidentRecorderSegmentPruneMutationError;
		expect(mutation.directoryDurability).toBe("confirmed");
		expect(mutation.result.deletedSegmentIds).toEqual([locators[0]!.segmentId]);
		expect(mutation.result.corruptSegmentIds).toEqual([]);
		expect((mutation.cause as NodeJS.ErrnoException).code).toBe("ENOENT");
	});

	it("retains the exact recovery continuation and lease when a resumed page cannot afford its first segment", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `resumed-recovery-budget-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.alloc(1024, index),
				}).locator,
			);
		}
		target.store.close();
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		vi.useFakeTimers();
		try {
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const timerBaseline = vi.getTimerCount();
			const first = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			const descriptorsWithLease = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				descriptorsWithLease,
				target.directory,
				1,
			);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const blocked = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1,
				continuation: first.continuation!,
			});
			expect(blocked).toMatchObject({ deletedSegmentIds: [], moreWork: true });
			expect(blocked.requiredBytes).toBeGreaterThan(1);
			expect(blocked.continuation).toBe(first.continuation);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsWithLease);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const completed = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: blocked.continuation!,
			});
			expect(completed.moreWork).toBe(false);
			expect(completed.continuation).toBeUndefined();
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("releases every held recovery descriptor and timer when a mutation consumes its cursor", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `recovery-mutation-lifecycle-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		vi.useFakeTimers();
		try {
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const timerBaseline = vi.getTimerCount();
			const first = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				snapshotOpenFileDescriptors(),
				target.directory,
				1,
			);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			let ownershipChecks = 0;
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
					onOwnershipTransitionCheck: () => {
						ownershipChecks += 1;
						if (ownershipChecks === 2) throw new Error("injected consumed mutation");
					},
				}),
			).toThrow(IncidentRecorderSegmentPruneMutationError);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				}),
			).toThrow(/not an active process-local capability/);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("prunes sealed history before writer allocation without creating paths and fails closed on ownership", () => {
		let now = 100;
		const target = fixture({ now: () => now, maxRecordsPerSegment: 1 });
		for (const label of ["old-a", "old-b", "anchor"]) {
			target.store.append({
				runId: label,
				sourceId: "daemon",
				observedAtMs: now,
				order: String(now),
				metadata: {},
				payload: Buffer.from(label),
			});
			now += 100;
		}
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				isOwnerAlive: () => true,
			}),
		).toThrow(/already owned/);
		target.store.close();
		const beforeRootEntries = readdirSync(target.directory).sort();
		const beforeRecoveryInodes = regularFileCount(target.directory);
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				onOwnershipTransitionCheck: () => {
					throw new Error("ownership transition detected");
				},
			}),
		).toThrow(/ownership transition detected/);
		expect(regularFileCount(target.directory)).toBe(beforeRecoveryInodes);
		const firstRecoveryPass = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: target.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(firstRecoveryPass).toMatchObject({
			locatorsInvalidated: true,
			requiresFullReconciliation: true,
			moreWork: true,
		});
		expect(firstRecoveryPass.deletedSegmentIds).toHaveLength(1);
		const secondRecoveryPass = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: target.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
			continuation: firstRecoveryPass.continuation!,
		});
		expect(secondRecoveryPass.deletedSegmentIds).toHaveLength(1);
		expect(secondRecoveryPass.moreWork).toBe(true);
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
				continuation: firstRecoveryPass.continuation!,
			}),
		).toThrow(/exact registered object/);
		const completedRecoveryPass = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: target.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
			continuation: secondRecoveryPass.continuation!,
		});
		expect(completedRecoveryPass).toMatchObject({
			deletedSegmentIds: [],
			requiresFullReconciliation: false,
			moreWork: false,
		});
		expect(completedRecoveryPass.continuation).toBeUndefined();
		expect(readdirSync(target.directory).sort()).toEqual(beforeRootEntries);
		expect(readdirSync(join(target.directory, "sealed"))).toHaveLength(1);
		expect(regularFileCount(target.directory)).toBe(beforeRecoveryInodes - 2);
		expect(existsSync(join(target.directory, ".writer-owner.json"))).toBe(false);
		expect(readdirSync(target.directory).some((name) => name.includes("recovery"))).toBe(false);

		const missing = join(target.directory, "does-not-exist");
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: missing,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
			}),
		).toThrow();
		expect(existsSync(missing)).toBe(false);
	});

	it("binds recovery pruning to the exact process-local cursor and frozen high-water mark", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const initialLocators = [];
		for (let index = 0; index < 4; index += 1) {
			initialLocators.push(
				target.store.append({
					runId: `recovery-frozen-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const first = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: target.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(first).toMatchObject({ deletedSegmentIds: [initialLocators[0]!.segmentId], moreWork: true });
		expect(Object.isFrozen(first.continuation)).toBe(true);
		const frozenHighWater = first.continuation!.highWaterSegmentSequence;

		const reopened = new IncidentRecorderSegmentStore({
			directory: target.directory,
			maxRecordsPerSegment: 1,
		});
		const lateLocators = [];
		for (let index = 4; index < 6; index += 1) {
			lateLocators.push(
				reopened.append({
					runId: `recovery-late-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		reopened.close();
		const sealedBeforeForgery = readdirSync(join(target.directory, "sealed")).sort();
		const forged = Object.freeze({
			...first.continuation!,
			highWaterSegmentSequence: frozenHighWater + 100,
		});
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: forged,
			}),
		).toThrow(/exact registered object/);
		expect(readdirSync(join(target.directory, "sealed")).sort()).toEqual(sealedBeforeForgery);
		const completed = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: target.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 10,
			maxBytes: 1024 * 1024,
			continuation: first.continuation!,
		});
		expect(completed.moreWork).toBe(false);
		const lateSealedLocators = lateLocators;
		expect(lateSealedLocators.every((locator) => locator.segmentSequence > frozenHighWater)).toBe(true);
		expect(
			lateSealedLocators.every((locator) => existsSync(join(target.directory, "sealed", `${locator.segmentId}.segment`))),
		).toBe(true);
	});

	it("fails closed on a recovery continuation catalog budget without consuming evidence", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 3; index += 1) {
			target.store.append({
				runId: `recovery-budget-${String(index)}`,
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		target.store.close();
		const first = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: target.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(first.continuation).toBeDefined();
		const sealedDirectory = join(target.directory, "sealed");
		const sealedBefore = readdirSync(sealedDirectory).sort();
		const filesBefore = regularFileCount(target.directory);
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				maxStartupCatalogBytes: 1000,
				continuation: first.continuation!,
			}),
		).toThrow(/maxStartupCatalogBytes/);
		expect(readdirSync(sealedDirectory).sort()).toEqual(sealedBefore);
		expect(regularFileCount(target.directory)).toBe(filesBefore);
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
			}),
		).toThrow(/not an active process-local capability/);
	});

	it("bounds and expires recovery prune cursor capabilities and their directory leases", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `recovery-cap-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		vi.useFakeTimers();
		try {
			vi.setSystemTime(100);
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const timerBaseline = vi.getTimerCount();
			const cursors = Array.from({ length: 32 }, () => {
				const page = pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 1,
					maxBytes: 1024 * 1024,
				});
				expect(page.moreWork).toBe(true);
				return page.continuation!;
			});
			const descriptorsAtCapacity = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(descriptorBaseline, descriptorsAtCapacity, target.directory, 32);
			expect(vi.getTimerCount()).toBe(timerBaseline + 32);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 1,
					maxBytes: 1024 * 1024,
				}),
			).toThrow(/32-cursor ceiling/);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsAtCapacity);
			expect(vi.getTimerCount()).toBe(timerBaseline + 32);
			vi.advanceTimersByTime(5 * 60 * 1000 + 1);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
			const replacement = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(replacement.continuation).toBeDefined();
			const descriptorsBeforeRotation = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				descriptorsBeforeRotation,
				target.directory,
				1,
			);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: cursors[0]!,
				}),
			).toThrow(/not an active process-local capability/);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsBeforeRotation);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const rotated = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
				continuation: replacement.continuation!,
			});
			expect(rotated.moreWork).toBe(true);
			expect(rotated.continuation).toBeDefined();
			expect(rotated.continuation).not.toBe(replacement.continuation);
			const descriptorsAfterRotation = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				descriptorsAfterRotation,
				target.directory,
				1,
			);
			expect(descriptorsAfterRotation).toEqual(descriptorsBeforeRotation);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: replacement.continuation!,
				}),
			).toThrow(/exact registered object/);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsAfterRotation);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const completed = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: rotated.continuation!,
			});
			expect(completed.moreWork).toBe(false);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("atomically transfers a recovery lease when a page crosses its TTL without running pending timers", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `cross-ttl-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		vi.useFakeTimers();
		try {
			vi.setSystemTime(100);
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const timerBaseline = vi.getTimerCount();
			const first = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			const descriptorsBeforeRotation = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				descriptorsBeforeRotation,
				target.directory,
				1,
			);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			let crossedTtl = false;
			const rotated = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
				onOwnershipTransitionCheck: () => {
					if (crossedTtl) return;
					crossedTtl = true;
					vi.setSystemTime(100 + 5 * 60 * 1000 + 1);
				},
			});
			expect(crossedTtl).toBe(true);
			expect(rotated.moreWork).toBe(true);
			expect(rotated.continuation).toBeDefined();
			expect(rotated.continuation).not.toBe(first.continuation);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsBeforeRotation);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				}),
			).toThrow(/exact registered object/);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsBeforeRotation);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const completed = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: rotated.continuation!,
			});
			expect(completed.moreWork).toBe(false);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("does not let an outer recovery callback invocation revoke a nested cursor generation", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 4; index += 1) {
			locators.push(
				target.store.append({
					runId: `nested-generation-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		vi.useFakeTimers();
		try {
			vi.setSystemTime(100);
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const timerBaseline = vi.getTimerCount();
			const first = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			const descriptorsBeforeNestedRotation = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				descriptorsBeforeNestedRotation,
				target.directory,
				1,
			);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);

			let nested:
				| ReturnType<typeof pruneIncidentRecorderSealedHistoryForRecovery>
				| undefined;
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
					onOwnershipTransitionCheck: () => {
						if (nested) return;
						nested = pruneIncidentRecorderSealedHistoryForRecovery({
							directory: target.directory,
							sealedBeforeMs: Number.MAX_SAFE_INTEGER,
							protection: pruneProtection(),
							protectedSegmentIds,
							externalWriterExcluded: true,
							maxSegments: 1,
							maxBytes: 1024 * 1024,
							continuation: first.continuation!,
						});
					},
				}),
			).toThrow();
			expect(nested?.moreWork).toBe(true);
			expect(nested?.continuation).toBeDefined();
			expect(nested?.continuation).not.toBe(first.continuation);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsBeforeNestedRotation);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				}),
			).toThrow(/exact registered object/);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsBeforeNestedRotation);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const completed = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: nested!.continuation!,
			});
			expect(completed.moreWork).toBe(false);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("preserves expiry precedence and asynchronously consumes a damaged lease without throwing", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `expiry-cleanup-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		vi.useFakeTimers();
		try {
			vi.setSystemTime(100);
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const baselineDescriptors = new Set(descriptorBaseline.map((entry) => entry.descriptor));
			const timerBaseline = vi.getTimerCount();
			const protectedSegmentIds = new Set([locators[0]!.segmentId]);
			const closeHeldSealedDescriptor = (descriptorsWithLease: readonly OpenFileDescriptorIdentity[]): void => {
				const sealedTarget = realpathSync(join(target.directory, "sealed"));
				const heldSealedDescriptor = descriptorsWithLease.find(
					(entry) => !baselineDescriptors.has(entry.descriptor) && entry.target === sealedTarget,
				)?.descriptor;
				expect(heldSealedDescriptor).toBeDefined();
				closeSync(heldSealedDescriptor!);
			};
			const first = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			const descriptorsWithLease = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				descriptorsWithLease,
				target.directory,
				1,
			);
			closeHeldSealedDescriptor(descriptorsWithLease);
			vi.setSystemTime(100 + 5 * 60 * 1000 + 1);
			let expiredThrown: unknown;
			try {
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				});
			} catch (error) {
				expiredThrown = error;
			}
			expect(expiredThrown).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
			const expiryCleanup = expiredThrown as IncidentRecorderDescriptorCleanupError;
			expect(expiryCleanup.primaryError).toBeInstanceOf(Error);
			expect((expiryCleanup.primaryError as Error).message).toMatch(/prune continuation expired/);
			expect(expiryCleanup.cleanupErrors).toHaveLength(1);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);

			const second = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(second.continuation).toBeDefined();
			const secondDescriptorsWithLease = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				secondDescriptorsWithLease,
				target.directory,
				1,
			);
			closeHeldSealedDescriptor(secondDescriptorsWithLease);
			expect(() => vi.advanceTimersByTime(5 * 60 * 1000 + 1)).not.toThrow();
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
			let asynchronousExpiryThrown: unknown;
			try {
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: second.continuation!,
				});
			} catch (error) {
				asynchronousExpiryThrown = error;
			}
			expect(asynchronousExpiryThrown).toBeInstanceOf(IncidentRecorderDescriptorCleanupError);
			const asynchronousExpiryCleanup = asynchronousExpiryThrown as IncidentRecorderDescriptorCleanupError;
			expect(asynchronousExpiryCleanup.primaryError).toBeInstanceOf(Error);
			expect((asynchronousExpiryCleanup.primaryError as Error).message).toMatch(/prune continuation expired/);
			expect(asynchronousExpiryCleanup.cleanupErrors).toHaveLength(1);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: second.continuation!,
				}),
			).toThrow(/not an active process-local capability/);

			const expiryDiagnostics: unknown[] = [];
			const third = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
				onPruneExpiryCleanupDiagnostic: (diagnostic) => {
					expiryDiagnostics.push(diagnostic);
					throw new Error("injected expiry diagnostic sink failure");
				},
			});
			expect(third.continuation).toBeDefined();
			const thirdDescriptorsWithLease = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				thirdDescriptorsWithLease,
				target.directory,
				1,
			);
			closeHeldSealedDescriptor(thirdDescriptorsWithLease);
			expect(() => vi.advanceTimersByTime(5 * 60 * 1000 + 1)).not.toThrow();
			expect(expiryDiagnostics).toHaveLength(1);
			expect(expiryDiagnostics[0]).toMatchObject({
				kind: "prune-cursor-expiry-cleanup-failed",
				cursor: third.continuation,
			});
			expect(Object.isFrozen(expiryDiagnostics[0] as object)).toBe(true);
			expect((expiryDiagnostics[0] as { error: unknown }).error).toBeInstanceOf(Error);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("starts a recovery cursor TTL when its directory lease is actually registered", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const locators = [];
		for (let index = 0; index < 3; index += 1) {
			locators.push(
				target.store.append({
					runId: `recovery-registration-time-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();
		writeFileSync(
			join(target.directory, ".writer-owner.json"),
			`${JSON.stringify({
				version: 1,
				nonce: "ttl-skew-owner",
				pid: 100,
				startTime: "stale",
				bootId: "old-boot",
			})}\n`,
			{ mode: 0o600 },
		);
		const protectedSegmentIds = new Set([locators[0]!.segmentId]);
		let ownerChecks = 0;
		const isOwnerAlive = (): boolean => {
			ownerChecks += 1;
			if (ownerChecks === 1) vi.advanceTimersByTime(5 * 60 * 1000 - 1);
			return false;
		};
		vi.useFakeTimers();
		try {
			vi.setSystemTime(100);
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const timerBaseline = vi.getTimerCount();
			const first = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				isOwnerAlive,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			const descriptorsAfterRegistration = snapshotOpenFileDescriptors();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				descriptorsAfterRegistration,
				target.directory,
				1,
			);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			vi.advanceTimersByTime(2);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorsAfterRegistration);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			const completed = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				protectedSegmentIds,
				externalWriterExcluded: true,
				isOwnerAlive,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
			});
			expect(completed.moreWork).toBe(false);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("rejects a recovery cursor after a different store replaces its lexical root", () => {
		const original = fixture({ maxRecordsPerSegment: 1 });
		const replacement = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 3; index += 1) {
			for (const [label, target] of [
				["original", original],
				["replacement", replacement],
			] as const) {
				target.store.append({
					runId: `${label}-root-swap-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				});
			}
		}
		original.store.close();
		replacement.store.close();
		const first = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: original.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		expect(first.continuation).toBeDefined();
		const replacementNames = readdirSync(join(replacement.directory, "sealed")).sort();
		const replacementFiles = regularFileCount(replacement.directory);
		const displaced = `${original.directory}.displaced`;
		renameSync(original.directory, displaced);
		renameSync(replacement.directory, original.directory);
		try {
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: original.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				}),
			).toThrow(/stale|storage identity changed/);
			expect(readdirSync(join(original.directory, "sealed")).sort()).toEqual(replacementNames);
			expect(regularFileCount(original.directory)).toBe(replacementFiles);
		} finally {
			renameSync(original.directory, replacement.directory);
			renameSync(displaced, original.directory);
		}
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: original.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
			}),
		).toThrow(/not an active process-local capability/);
	});

	it("binds recovery cursors to the sealed child identity and captured directory mode", () => {
		const original = fixture({ maxRecordsPerSegment: 1 });
		const replacement = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 3; index += 1) {
			for (const [label, target] of [
				["sealed-original", original],
				["sealed-replacement", replacement],
			] as const) {
				target.store.append({
					runId: `${label}-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				});
			}
		}
		original.store.close();
		replacement.store.close();
		const first = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: original.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		const originalSealed = join(original.directory, "sealed");
		const displacedSealed = join(original.directory, "sealed.displaced");
		const replacementSealed = join(replacement.directory, "sealed");
		const replacementNames = readdirSync(replacementSealed).sort();
		renameSync(originalSealed, displacedSealed);
		renameSync(replacementSealed, originalSealed);
		try {
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: original.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				}),
			).toThrow(/stale|storage identity changed/);
			expect(readdirSync(originalSealed).sort()).toEqual(replacementNames);
		} finally {
			renameSync(originalSealed, replacementSealed);
			renameSync(displacedSealed, originalSealed);
		}
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: original.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: first.continuation!,
			}),
		).toThrow(/not an active process-local capability/);

		const modeTarget = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 3; index += 1) {
			modeTarget.store.append({
				runId: `sealed-mode-${String(index)}`,
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		modeTarget.store.close();
		const modeFirst = pruneIncidentRecorderSealedHistoryForRecovery({
			directory: modeTarget.directory,
			sealedBeforeMs: Number.MAX_SAFE_INTEGER,
			protection: pruneProtection(),
			externalWriterExcluded: true,
			maxSegments: 1,
			maxBytes: 1024 * 1024,
		});
		const modeSealedDirectory = join(modeTarget.directory, "sealed");
		const modeNames = readdirSync(modeSealedDirectory).sort();
		chmodSync(modeSealedDirectory, 0o755);
		try {
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: modeTarget.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: modeFirst.continuation!,
				}),
			).toThrow(/stale|storage identity changed/);
			expect(readdirSync(modeSealedDirectory).sort()).toEqual(modeNames);
		} finally {
			chmodSync(modeSealedDirectory, 0o700);
		}
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: modeTarget.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				continuation: modeFirst.continuation!,
			}),
		).toThrow(/not an active process-local capability/);
	});

	it("rejects recovery root mode drift and releases the held directory and proc descriptors", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 3; index += 1) {
			target.store.append({
				runId: `root-mode-${String(index)}`,
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		target.store.close();
		const originalMode = lstatSync(target.directory).mode & 0o777;
		const changedMode = originalMode === 0o711 ? 0o700 : 0o711;
		vi.useFakeTimers();
		try {
			const descriptorBaseline = snapshotOpenFileDescriptors();
			const timerBaseline = vi.getTimerCount();
			const first = pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 1,
				maxBytes: 1024 * 1024,
			});
			expect(first.continuation).toBeDefined();
			const sealedNames = readdirSync(join(target.directory, "sealed")).sort();
			expectAdditionalRecoveryScopeLeases(
				descriptorBaseline,
				snapshotOpenFileDescriptors(),
				target.directory,
				1,
			);
			expect(vi.getTimerCount()).toBe(timerBaseline + 1);
			chmodSync(target.directory, changedMode);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				}),
			).toThrow(/stale|storage identity changed/);
			expect(readdirSync(join(target.directory, "sealed")).sort()).toEqual(sealedNames);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
			chmodSync(target.directory, originalMode);
			expect(() =>
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					continuation: first.continuation!,
				}),
			).toThrow(/not an active process-local capability/);
			expect(snapshotOpenFileDescriptors()).toEqual(descriptorBaseline);
			expect(vi.getTimerCount()).toBe(timerBaseline);
		} finally {
			chmodSync(target.directory, originalMode);
			vi.runOnlyPendingTimers();
			vi.useRealTimers();
		}
	});

	it("rejects duplicate recovery segment sequences before deleting any file", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		for (let index = 0; index < 2; index += 1) {
			target.store.append({
				runId: `duplicate-target-${String(index)}`,
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		target.store.close();

		let sourceId = 0;
		const source = fixture({
			maxRecordsPerSegment: 1,
			createSegmentId: () => {
				sourceId += 1;
				return `duplicate-source-${String(sourceId)}`;
			},
		});
		for (let index = 0; index < 2; index += 1) {
			source.store.append({
				runId: `duplicate-source-${String(index)}`,
				sourceId: "daemon",
				observedAtMs: index,
				order: String(index),
				metadata: {},
				payload: Buffer.from([index]),
			});
		}
		source.store.close();
		const sourceFile = readdirSync(join(source.directory, "sealed")).find((name) => name.endsWith(".segment"));
		expect(sourceFile).toBeDefined();
		copyFileSync(
			join(source.directory, "sealed", sourceFile!),
			join(target.directory, "sealed", sourceFile!),
		);
		const sealedBefore = readdirSync(join(target.directory, "sealed")).sort();
		const filesBefore = regularFileCount(target.directory);
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
			}),
		).toThrow(/duplicate sealed segment sequence/);
		expect(readdirSync(join(target.directory, "sealed")).sort()).toEqual(sealedBefore);
		expect(regularFileCount(target.directory)).toBe(filesBefore);
	});

	it("fails closed when a valid duplicate recovery sequence is hidden beyond the catalog budget", () => {
		const target = fixture({ maxRecordsPerSegment: 1 });
		const targetLocators = [];
		for (let index = 0; index < 2; index += 1) {
			targetLocators.push(
				target.store.append({
					runId: `budget-duplicate-target-${String(index)}`,
					sourceId: "daemon",
					observedAtMs: index,
					order: String(index),
					metadata: {},
					payload: Buffer.from([index]),
				}).locator,
			);
		}
		target.store.close();

		const source = fixture({
			maxRecordsPerSegment: 1,
			createSegmentId: () => "zz-duplicate-budget-source",
		});
		const sourceLocator = source.store.append({
			runId: "budget-duplicate-source",
			sourceId: "daemon",
			observedAtMs: 0,
			order: "0",
			metadata: {},
			payload: Buffer.from("duplicate"),
		}).locator;
		source.store.close();
		const sealedDirectory = join(target.directory, "sealed");
		const sourceName = `${sourceLocator.segmentId}.segment`;
		copyFileSync(join(source.directory, "sealed", sourceName), join(sealedDirectory, sourceName));
		const orderedNames = [
			`${targetLocators[0]!.segmentId}.segment`,
			`${targetLocators[1]!.segmentId}.segment`,
			sourceName,
		];
		const staging = join(target.directory, "catalog-order-staging");
		mkdirSync(staging, { mode: 0o700 });
		for (const name of orderedNames) renameSync(join(sealedDirectory, name), join(staging, name));
		for (const name of orderedNames) renameSync(join(staging, name), join(sealedDirectory, name));
		rmSync(staging, { recursive: true });
		expect(readdirSync(sealedDirectory).filter((name) => name.endsWith(".segment"))).toEqual(orderedNames);
		const allSegmentIds = new Set([
			targetLocators[0]!.segmentId,
			targetLocators[1]!.segmentId,
			sourceLocator.segmentId,
		]);
		const classifyBudget = (maxStartupCatalogBytes: number): "budget" | "duplicate" | "returned" => {
			try {
				pruneIncidentRecorderSealedHistoryForRecovery({
					directory: target.directory,
					sealedBeforeMs: Number.MAX_SAFE_INTEGER,
					protection: pruneProtection(),
					protectedSegmentIds: allSegmentIds,
					externalWriterExcluded: true,
					maxSegments: 10,
					maxBytes: 1024 * 1024,
					maxStartupCatalogBytes,
				});
				return "returned";
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				if (/duplicate sealed segment sequence/.test(message)) return "duplicate";
				if (/maxStartupCatalogBytes/.test(message)) return "budget";
				throw error;
			}
		};
		let low = 1;
		let high = 64 * 1024 * 1024;
		expect(classifyBudget(high)).toBe("duplicate");
		while (low < high) {
			const middle = Math.floor((low + high) / 2);
			if (classifyBudget(middle) === "duplicate") high = middle;
			else low = middle + 1;
		}
		const hiddenDuplicateBudget = low - 1;
		expect(hiddenDuplicateBudget).toBeGreaterThan(0);
		const sealedBefore = readdirSync(sealedDirectory).sort();
		const filesBefore = regularFileCount(target.directory);
		expect(() =>
			pruneIncidentRecorderSealedHistoryForRecovery({
				directory: target.directory,
				sealedBeforeMs: Number.MAX_SAFE_INTEGER,
				protection: pruneProtection(),
				externalWriterExcluded: true,
				maxSegments: 10,
				maxBytes: 1024 * 1024,
				maxStartupCatalogBytes: hiddenDuplicateBudget,
			}),
		).toThrow(/maxStartupCatalogBytes/);
		expect(readdirSync(sealedDirectory).sort()).toEqual(sealedBefore);
		expect(regularFileCount(target.directory)).toBe(filesBefore);
	});

	it("admits a single-use side-effect-free open plan and returns exact structural and parent allocation", () => {
		const parent = mkdtempSync(join(tmpdir(), "prime-agent-open-plan-"));
		roots.push(parent);
		const directory = join(parent, "store");
		const plan = planIncidentRecorderSegmentStoreOpen(directory);
		expect(existsSync(directory)).toBe(false);
		expect(plan).toMatchObject({ peakAdditionalEntries: 5, peakAdditionalInodes: 4 });
		mkdtempSync(join(parent, "unrelated-sibling-"));
		const results: Array<{
			phase: string;
			complete: boolean;
			entries: readonly { path: string; allocatedBytes: number }[];
			parentEffects: readonly { beforeAllocatedBytes: number; afterAllocatedBytes: number }[];
		}> = [];
		let admitted = false;
		const store = new IncidentRecorderSegmentStore({
			directory,
			openPlan: plan,
			onOpenAdmission: () => {
				admitted = true;
			},
			onOpenStorageResult: (result) => results.push(result),
		});
		expect(admitted).toBe(true);
		expect(results[0]).toMatchObject({ phase: "opened", complete: true });
		const opened = results[0];
		expect(opened?.entries).toHaveLength(4);
		expect(opened?.entries.reduce((total, entry) => total + entry.allocatedBytes, 0)).toBe(
			opened?.entries.reduce((total, entry) => total + lstatSync(entry.path).blocks * 512, 0),
		);
		const openedEntryBytes =
			opened?.entries.reduce((total, entry) => total + entry.allocatedBytes, 0) ?? 0;
		const openedParentGrowth =
			opened?.parentEffects.reduce(
				(total, effect) =>
					total + Math.max(0, effect.afterAllocatedBytes - effect.beforeAllocatedBytes),
				0,
			) ?? 0;
		expect(plan.peakAdditionalBytes).toBeGreaterThanOrEqual(openedEntryBytes + openedParentGrowth);
		expect(() => new IncidentRecorderSegmentStore({ directory, openPlan: plan })).toThrow(/already consumed/);
		store.close();
		expect(results.at(-1)).toMatchObject({ phase: "closed", complete: true });

		const blockedDirectory = join(parent, "blocked");
		const blockedPlan = planIncidentRecorderSegmentStoreOpen(blockedDirectory);
		expect(() =>
			new IncidentRecorderSegmentStore({
				directory: blockedDirectory,
				openPlan: blockedPlan,
				onOpenAdmission: () => {
					throw new Error("admission denied");
				},
			}),
		).toThrow(/admission denied/);
		expect(existsSync(blockedDirectory)).toBe(false);

		const existingDirectory = join(parent, "existing-store");
		const existingStore = new IncidentRecorderSegmentStore({ directory: existingDirectory });
		existingStore.close();
		const existingPlan = planIncidentRecorderSegmentStoreOpen(existingDirectory);
		mkdtempSync(join(parent, "another-unrelated-sibling-"));
		const reopenedExisting = new IncidentRecorderSegmentStore({
			directory: existingDirectory,
			openPlan: existingPlan,
		});
		reopenedExisting.close();

		const changedDirectory = join(parent, "changed-after-plan");
		const changedPlan = planIncidentRecorderSegmentStoreOpen(changedDirectory);
		mkdirSync(changedDirectory, { mode: 0o700 });
		expect(
			() => new IncidentRecorderSegmentStore({ directory: changedDirectory, openPlan: changedPlan }),
		).toThrow(/open plan is stale/);

		const parentMode = lstatSync(parent).mode & 0o777;
		const admissionChangedDirectory = join(parent, "parent-changed-during-admission");
		const admissionChangedPlan = planIncidentRecorderSegmentStoreOpen(admissionChangedDirectory);
		try {
			expect(
				() =>
					new IncidentRecorderSegmentStore({
						directory: admissionChangedDirectory,
						openPlan: admissionChangedPlan,
						onOpenAdmission: () => chmodSync(parent, parentMode === 0o711 ? 0o700 : 0o711),
					}),
			).toThrow(/open state changed during admission/);
			expect(existsSync(admissionChangedDirectory)).toBe(false);
		} finally {
			chmodSync(parent, parentMode);
		}
	});

	it("requires a full dev/inode reconciliation after successful stale owner and temporary cleanup", () => {
		const target = fixture();
		target.store.close();
		const temporaryPath = join(target.directory, "active", ".creating-stale.tmp");
		writeFileSync(temporaryPath, "stale", { mode: 0o600 });
		writeFileSync(
			join(target.directory, ".writer-owner.json"),
			`${JSON.stringify({
				version: 1,
				nonce: "stale-owner",
				pid: 100,
				startTime: "stale",
				bootId: "old-boot",
			})}\n`,
			{ mode: 0o600 },
		);
		const results: Array<{ phase: string; reconciliation: string }> = [];
		const reopened = new IncidentRecorderSegmentStore({
			directory: target.directory,
			ownerIdentity: { pid: 101, startTime: "new", bootId: "new-boot" },
			isOwnerAlive: () => false,
			onOpenStorageResult: (result) => results.push(result),
		});
		expect(results[0]).toMatchObject({
			phase: "opened",
			reconciliation: "full-dev-inode-required",
		});
		expect(existsSync(temporaryPath)).toBe(false);
		expect(
			readdirSync(target.directory).some((name) => name.startsWith(".writer-owner-stale-")),
		).toBe(false);
		reopened.close();
	});

	it("reports exact post-cleanup structural state when construction fails during recovery", () => {
		const target = fixture();
		target.store.append({
			runId: "partial-open",
			sourceId: "journal",
			observedAtMs: 1,
			order: "1",
			metadata: {},
			payload: Buffer.from("committed"),
		});
		target.store.close();
		const activeName = readdirSync(join(target.directory, "active")).find((name) => name.endsWith(".open"));
		expect(activeName).toBeDefined();
		appendFileSync(join(target.directory, "active", activeName ?? "missing"), Buffer.alloc(4096, 0xaa));
		const results: Array<{ phase: string; complete: boolean; entries: readonly { kind: string }[] }> = [];
		const plan = planIncidentRecorderSegmentStoreOpen(target.directory);
		expect(() =>
			new IncidentRecorderSegmentStore({
				directory: target.directory,
				openPlan: plan,
				faultInjector: (point) => {
					if (point === "after-recovery-gap-fsync-before-truncate") throw new Error("partial open crash");
				},
				onOpenStorageResult: (result) => results.push(result),
			}),
		).toThrow(/partial open crash/);
		expect(results.at(-1)).toMatchObject({ phase: "failed", complete: false });
		expect(results.at(-1)?.entries.some((entry) => entry.kind === "owner-file")).toBe(false);
		expect(existsSync(join(target.directory, ".writer-owner.json"))).toBe(false);
	});
});
