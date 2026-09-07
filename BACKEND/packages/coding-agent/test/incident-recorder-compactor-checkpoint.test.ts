import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const roots: string[] = [];
const leases: IncidentRecorderWriterLifecycleLease[] = [];
afterEach(() => {
	for (const lease of leases.splice(0)) lease.release();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

interface CheckpointInternals {
	commitCursor(cursor: string, machine: string, boot: string, invocation: null, realtime: string): void;
	persistPendingPinCursor(afterName: string | undefined): void;
	advanceCheckpoint(): void;
	resetUnseekableCursor(stderr: string): void;
	closeSegmentStore(): void;
	flushAllIncomplete(reason: string): void;
	writeGap(value: unknown): void;
	checkpoint?: { cursor: string };
	pendingPinCursor?: string;
	pendingEntries: unknown[];
	pendingEntryBytes: number;
	wrapperSequences: Map<string, bigint>;
	producerSequences: Map<string, bigint>;
}

async function fixture(options: { initialize?: boolean; storageScannerPath?: string } = {}) {
	const base = mkdtempSync(join(tmpdir(), "grim16-checkpoint-"));
	roots.push(base);
	const agentDir = join(base, "agent");
	const root = join(agentDir, "incident-recorder");
	mkdirSync(root, { recursive: true, mode: 0o700 });
	mkdirSync(join(agentDir, "incidents"), { mode: 0o700 });
	const admitted = acquireIncidentRecorderWriterNormalLease(
		{ agentDir },
		{
			activationGenerationDigest: "a".repeat(64),
			revalidateActivation: () => ({ state: "valid" }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		},
	);
	if (admitted.state !== "acquired") throw new Error(admitted.reason);
	leases.push(admitted.lease);
	let available = true;
	const compactor = new IncidentRecorderCompactor({
		agentDir,
		freeReserveBytes: 0,
		storageScannerPath: options.storageScannerPath,
		writerLifecycleLease: () => (available ? admitted.lease : undefined),
	});
	if (options.initialize !== false) await compactor.initializeStorageAccounting(new AbortController().signal);
	return {
		root,
		compactor,
		internal: compactor as unknown as CheckpointInternals,
		setAvailable(value: boolean) {
			available = value;
		},
	};
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error("timed out waiting for isolated checkpoint fixture");
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

it("does not publish or remember a cursor without normal writer admission", async () => {
	const f = await fixture();
	f.setAvailable(false);
	expect(() => f.internal.commitCursor("next", "machine", "boot", null, "1")).toThrow(/writer lifecycle/i);
	expect(f.internal.checkpoint).toBeUndefined();
	expect(existsSync(join(f.root, "compactor-cursor.json"))).toBe(false);
});

it("retains the resolved frontier and sequences until its checkpoint commits", async () => {
	const f = await fixture();
	f.internal.commitCursor("old", "machine", "boot", null, "1");
	const entry = {
		resolved: true,
		cursor: "next",
		machineId: "machine",
		bootId: "boot",
		invocationId: null,
		realtimeUs: "2",
		memoryBytes: 12,
		sequenceUpdates: { wrapperKey: "wrapper", wrapper: "2", producerKey: "producer", producer: "2" },
	};
	f.internal.pendingEntries.push(entry);
	f.internal.pendingEntryBytes = 12;
	f.internal.wrapperSequences.set("wrapper", 1n);
	f.internal.producerSequences.set("producer", 1n);
	f.setAvailable(false);
	expect(() => f.internal.advanceCheckpoint()).toThrow(/writer lifecycle/i);
	expect(f.internal.pendingEntries).toEqual([entry]);
	expect(f.internal.pendingEntryBytes).toBe(12);
	expect(f.internal.wrapperSequences.get("wrapper")).toBe(1n);
	expect(f.internal.producerSequences.get("producer")).toBe(1n);
	expect(f.internal.checkpoint?.cursor).toBe("old");
	expect(JSON.parse(readFileSync(join(f.root, "compactor-cursor.json"), "utf8")).cursor).toBe("old");
	f.setAvailable(true);
	f.internal.advanceCheckpoint();
	expect(f.internal.pendingEntries).toEqual([]);
	expect(f.internal.checkpoint?.cursor).toBe("next");
	expect(JSON.parse(readFileSync(join(f.root, "compactor-cursor.json"), "utf8")).wrapperSequences).toEqual({
		wrapper: "2",
	});
	expect(readdirSync(f.root).filter((name) => name.includes(".next"))).toEqual([]);
});

it("does not advance pending-pin traversal without durable admission", async () => {
	const f = await fixture();
	f.setAvailable(false);
	expect(() => f.internal.persistPendingPinCursor("incident-next")).toThrow(/writer lifecycle/i);
	expect(f.internal.pendingPinCursor).toBeUndefined();
	expect(existsSync(join(f.root, "pending-pin-directory-cursor.json"))).toBe(false);
	f.setAvailable(true);
	f.internal.persistPendingPinCursor("incident-next");
	expect(f.internal.pendingPinCursor).toBe("incident-next");
});

it("retains an unseekable cursor until its admitted removal is durable", async () => {
	const f = await fixture();
	f.internal.commitCursor("old", "machine", "boot", null, "1");
	try {
		f.setAvailable(false);
		expect(() => f.internal.resetUnseekableCursor("cursor vacuumed")).toThrow(/writer lifecycle/i);
		expect(f.internal.checkpoint?.cursor).toBe("old");
		expect(existsSync(join(f.root, "compactor-cursor.json"))).toBe(true);
		expect(existsSync(join(f.root, "segments"))).toBe(false);
		f.setAvailable(true);
		f.internal.resetUnseekableCursor("cursor vacuumed");
		expect(f.internal.checkpoint).toBeUndefined();
		expect(existsSync(join(f.root, "compactor-cursor.json"))).toBe(false);
	} finally {
		f.setAvailable(true);
		f.internal.closeSegmentStore();
	}
});

it("reuses one interrupted scratch slot and keeps cursor replacement accounting bounded", async () => {
	const f = await fixture();
	const scratch = join(f.root, ".compactor-cursor.json.next");
	writeFileSync(scratch, "interrupted cursor bytes", { mode: 0o600 });
	await f.compactor.initializeStorageAccounting(new AbortController().signal);
	f.internal.commitCursor("cursor-0", "machine", "boot", null, "1");
	const baselineBytes = f.compactor.accountedStorageBytes;
	for (let index = 1; index <= 20; index++) f.internal.commitCursor(`cursor-${index}`, "machine", "boot", null, "1");
	expect(f.compactor.accountedStorageBytes).toBe(baselineBytes);
	expect(readdirSync(f.root)).toEqual(["compactor-cursor.json"]);
	expect(JSON.parse(readFileSync(join(f.root, "compactor-cursor.json"), "utf8")).cursor).toBe("cursor-20");
});

it("does not restore ready accounting from a stale scan after uncertain cursor publication", async () => {
	const scannerRoot = mkdtempSync(join(tmpdir(), "grim16-accounting-"));
	roots.push(scannerRoot);
	const countPath = join(scannerRoot, "scan-count");
	const markerPath = join(scannerRoot, "second-scan-started");
	const releasePath = join(scannerRoot, "release-second-scan");
	const scannerPath = join(scannerRoot, "storage-scanner.cjs");
	writeFileSync(
		scannerPath,
		`#!${process.execPath}
const fs = require("node:fs");
const countPath = ${JSON.stringify(countPath)};
const markerPath = ${JSON.stringify(markerPath)};
const releasePath = ${JSON.stringify(releasePath)};
let count = 0;
try { count = Number(fs.readFileSync(countPath, "utf8")); } catch {}
fs.writeFileSync(countPath, String(count + 1));
if (count === 0) {
  process.stdout.write("1\\t1\\t0\\t0\\n", () => process.exit(0));
} else {
  fs.writeFileSync(markerPath, "started");
  const timer = setInterval(() => {
    if (!fs.existsSync(releasePath)) return;
    clearInterval(timer);
    process.stdout.write("1\\t1\\t4096\\t8\\n", () => process.exit(0));
  }, 5);
}
`,
		{ mode: 0o700 },
	);
	chmodSync(scannerPath, 0o700);
	const f = await fixture({ initialize: false, storageScannerPath: scannerPath });
	await f.compactor.initializeStorageAccounting(new AbortController().signal);
	const baselineBytes = f.compactor.accountedStorageBytes;
	const scan = f.compactor.initializeStorageAccounting(new AbortController().signal);
	await waitFor(() => existsSync(markerPath));
	try {
		type RootMutationResult = { state: "committed"; value: unknown } | { state: "unavailable"; reason: string };
		const internals = f.compactor as unknown as {
			withRecorderRoot: (operation: (root: unknown) => unknown) => RootMutationResult;
		};
		const originalWithRecorderRoot = internals.withRecorderRoot;
		internals.withRecorderRoot = (operation) => {
			const mutation = originalWithRecorderRoot.call(f.compactor, operation);
			if (mutation.state === "committed") return { state: "unavailable", reason: "writer_lifecycle_lease_lost" };
			return mutation;
		};
		expect(() => f.internal.commitCursor("uncertain", "machine", "boot", null, "1")).toThrow(/writer lifecycle/i);
		expect(JSON.parse(readFileSync(join(f.root, "compactor-cursor.json"), "utf8")).cursor).toBe("uncertain");
		writeFileSync(releasePath, "release");
		await scan;
		expect(f.compactor.storageAccountingReady).toBe(false);
		expect(f.compactor.accountedStorageBytes).toBe(baselineBytes);
		expect(f.compactor.storageMode).toBe("recovery-only");
		expect(f.compactor.storageRecoveryReason).toBe("scan_invalidated");
		expect(f.internal.checkpoint).toBeUndefined();
		internals.withRecorderRoot = originalWithRecorderRoot;
		await f.compactor.initializeStorageAccounting(new AbortController().signal);
		expect(f.compactor.storageAccountingReady).toBe(true);
		f.internal.commitCursor("retry", "machine", "boot", null, "2");
		expect(f.internal.checkpoint?.cursor).toBe("retry");
	} finally {
		writeFileSync(releasePath, "release");
		await scan.catch(() => {});
	}
});
