import { createHash } from "node:crypto";
import {
	appendFileSync,
	closeSync,
	existsSync,
	lstatSync,
	mkdtempSync,
	openSync,
	readSync,
	readdirSync,
	rmSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	createIncidentRecorderSegmentPruneProtection,
	IncidentRecorderSegmentStore,
	planIncidentRecorderSegmentStoreOpen,
	pruneIncidentRecorderSealedHistoryForRecovery,
	type IncidentRecorderSegmentDurableWrite,
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

describe("incident recorder segment store", () => {
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
		const first = target.store.queryRunWindowPage({
			runId: "paged",
			sourceId: "kernel",
			fromObservedAtMs: 0,
			throughObservedAtMs: 10,
			maxRecords: 1,
			maxBytes: 1024,
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
				after: cursor,
			});
			observed.push(...page.records);
			if (page.complete) break;
			cursor = page.nextCursor;
		}
		expect(observed.map((record) => record.order)).toEqual(["1", "3", "5"]);
		expect(new Set(observed.map((record) => `${record.locator.segmentSequence}:${record.locator.ordinal}`)).size).toBe(3);

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
		target.store.close();
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

	it("admits a single-use side-effect-free open plan and returns exact structural and parent allocation", () => {
		const parent = mkdtempSync(join(tmpdir(), "prime-agent-open-plan-"));
		roots.push(parent);
		const directory = join(parent, "store");
		const plan = planIncidentRecorderSegmentStoreOpen(directory);
		expect(existsSync(directory)).toBe(false);
		expect(plan).toMatchObject({ peakAdditionalEntries: 5, peakAdditionalInodes: 4 });
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
