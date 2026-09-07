import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_RUN_ID = "99999999-9999-4999-8999-999999999999";
const TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const roots: string[] = [];
const leases: IncidentRecorderWriterLifecycleLease[] = [];
const compactors: IncidentRecorderCompactor[] = [];

interface CompactorInternals {
	appendSegmentRecord(input: {
		idempotencyKey: string;
		runId: string;
		sourceId: string;
		observedAtMs: number;
		order: string;
		metadata: Record<string, string | number | boolean>;
		payload: Buffer;
	}): unknown;
	closeSegmentStore(): void;
}

function fixture(): {
	root: string;
	compactor: IncidentRecorderCompactor;
	internal: CompactorInternals;
	append(runId: string, sequence: number): void;
} {
	const root = mkdtempSync(join(tmpdir(), "prime-agent-live-events-"));
	roots.push(root);
	const agentDir = join(root, "agent");
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const scanner = join(root, "storage-scanner.cjs");
	writeFileSync(scanner, `#!${process.execPath}\nprocess.stdout.write("1\\t1\\t0\\t0\\n");\n`, { mode: 0o700 });
	chmodSync(scanner, 0o700);
	let lease: IncidentRecorderWriterLifecycleLease | undefined;
	const contract: IncidentRecorderWriterLifecycleAdmissionContract = {
		activationGenerationDigest: "a".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: acquireIncidentRecorderNamespaceCas,
	};
	const acquireLease = (): IncidentRecorderWriterLifecycleLease => {
		if (lease) return lease;
		const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, contract);
		if (admission.state !== "acquired") throw new Error(`fixture lease unavailable: ${admission.reason}`);
		lease = admission.lease;
		leases.push(lease);
		return lease;
	};
	const compactor = new IncidentRecorderCompactor({
		agentDir,
		storageScannerPath: scanner,
		freeReserveBytes: 0,
		writerLifecycleLease: acquireLease,
	});
	compactors.push(compactor);
	const internal = compactor as unknown as CompactorInternals;
	return {
		root,
		compactor,
		internal,
		append(runId, sequence) {
			const occurrenceId = `00000000-0000-4000-8000-${sequence.toString(16).padStart(12, "0")}`;
			const identity = { runId, runToken: TOKEN, producerId: PRODUCER_ID, occurrenceId };
			const identityKey = createHash("sha256")
				.update(`${runId}\0${TOKEN}\0${PRODUCER_ID}\0${occurrenceId}`)
				.digest("hex");
			const digest = sequence.toString(16).padStart(64, "0");
			const eventWallTimeMs = String(1_700_000_000_000 + sequence);
			const occurrence = {
				version: 1,
				state: "complete",
				identity,
				source: "supervisor-events",
				type: "supervisor_heartbeat",
				encoding: "json",
				payloadKind: "derived-scalar",
				terminal: false,
				metadata: { producerPid: 1, socketExists: true, fixtureCause: "live_event_test" },
				eventWallTimeMs,
				eventMonotonicNs: String(1_000 + sequence),
				transportIdentity: {},
				wrapperOrder: [String(sequence)],
				producerOrder: [String(sequence)],
				cursors: [`fixture:${sequence}`],
				cas: {
					algorithm: "sha256",
					digest,
					bytes: 1,
					path: join(agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2), `${digest}.blob`),
					compression: "none",
					resolution: "verified",
				},
				compactionDisposition: "compacted_and_cas_resolved",
				journalCanonicalUntilCompactionCommit: true,
			};
			internal.appendSegmentRecord({
				idempotencyKey: `occurrence:${identityKey}`,
				runId,
				sourceId: "occurrence",
				observedAtMs: Number(eventWallTimeMs),
				order: String(sequence),
				metadata: { version: 1, state: "complete", occurrenceIdentity: identityKey, casDigest: digest },
				payload: Buffer.from(`${JSON.stringify(occurrence)}\n`, "utf8"),
			});
		},
	};
}

afterEach(() => {
	for (const compactor of compactors.splice(0).reverse()) {
		try {
			(compactor as unknown as CompactorInternals).closeSegmentStore();
		} catch {}
	}
	for (const lease of leases.splice(0).reverse()) lease.release();
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("incident recorder live segment events", () => {
	it("advances a physical frontier across fresh segment snapshots", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		target.append(RUN_ID, 1);
		const first = target.compactor.readLiveRunEvents({ runId: RUN_ID });
		expect(first.state).toBe("complete");
		expect(first.events).toHaveLength(1);

		target.append(RUN_ID, 2);
		const second = target.compactor.readLiveRunEvents({ runId: RUN_ID, cursor: first.cursor });
		expect(second.state).toBe("complete");
		expect(second.events).toHaveLength(1);
		expect(second.events[0]?.identity.occurrenceId).toContain("000000000002");
	});

	it("exposes a pending page during multi-page catch-up and completes at the next frontier", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		for (let sequence = 1; sequence <= 65; sequence += 1) target.append(RUN_ID, sequence);

		const first = target.compactor.readLiveRunEvents({ runId: RUN_ID });
		expect(first.state).toBe("pending");
		expect(first.events).toHaveLength(64);

		const second = target.compactor.readLiveRunEvents({ runId: RUN_ID, cursor: first.cursor });
		expect(second.state).toBe("complete");
		expect(second.events).toHaveLength(1);
		expect(second.events[0]?.identity.occurrenceId).toContain("000000000041");
	});

	it("keeps the unread frontier and recovers after a transient segment-reader failure", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		target.append(RUN_ID, 1);
		const first = target.compactor.readLiveRunEvents({ runId: RUN_ID });

		const internals = target.compactor as unknown as {
			ensureSegmentStore(): unknown;
		};
		const readerFailure = vi.spyOn(internals, "ensureSegmentStore").mockImplementation(() => {
			throw new Error("transient segment reader failure");
		});
		const failed = target.compactor.readLiveRunEvents({ runId: RUN_ID, cursor: first.cursor });
		readerFailure.mockRestore();

		expect(failed.state).toBe("incomplete");
		expect(failed.reason).toContain("live_run_event_query_unavailable");
		expect(failed.cursor).toEqual(first.cursor);
		target.append(RUN_ID, 2);
		const recovered = target.compactor.readLiveRunEvents({ runId: RUN_ID, cursor: failed.cursor });
		expect(recovered.state).toBe("complete");
		expect(recovered.events).toHaveLength(1);
		expect(recovered.events[0]?.identity.occurrenceId).toContain("000000000002");
	});

	it("rejects a continuation cursor from another run", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		target.append(RUN_ID, 1);
		const first = target.compactor.readLiveRunEvents({ runId: RUN_ID });
		expect(() => target.compactor.readLiveRunEvents({ runId: OTHER_RUN_ID, cursor: first.cursor })).toThrow(
			"Invalid live run-event continuation cursor",
		);
	});

	it("reports an invalid occurrence without advancing past the unread evidence", async () => {
		const target = fixture();
		await target.compactor.initializeStorageAccounting(new AbortController().signal);
		target.append(RUN_ID, 1);
		const first = target.compactor.readLiveRunEvents({ runId: RUN_ID });
		target.internal.appendSegmentRecord({
			idempotencyKey: "malformed-live-occurrence",
			runId: RUN_ID,
			sourceId: "occurrence",
			observedAtMs: 1_700_000_000_002,
			order: "2",
			metadata: { version: 1, state: "complete" },
			payload: Buffer.from("{}\n", "utf8"),
		});
		const result = target.compactor.readLiveRunEvents({ runId: RUN_ID, cursor: first.cursor });
		expect(result.state).toBe("incomplete");
		expect(result.reason).toBe("live_run_event_segment_payload_invalid");
		expect(result.cursor).toEqual(first.cursor);
	});
});
