import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { IncidentRecorderCompactor } from "../src/modes/daemon/incident-recorder-compactor.js";
import {
	INCIDENT_RECORDER_DERIVED_OBSERVATION_RESERVATION_BYTES,
	INCIDENT_RECORDER_DIAGNOSTIC_MAX_DEPTH,
	INCIDENT_RECORDER_DIAGNOSTIC_MAX_NODES,
	INCIDENT_RECORDER_DIAGNOSTIC_PAYLOAD_MAX_BYTES,
	serializeIncidentRecorderDiagnostic,
} from "../src/modes/daemon/incident-recorder-diagnostic-serializer.js";
import { acquireIncidentRecorderNamespaceCas } from "../src/modes/daemon/incident-recorder-namespace-admission.js";
import type { IncidentRecorderEncodedFrame } from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
} from "../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";

type WriterInternals = {
	relayQueue: Array<{ frames: readonly IncidentRecorderEncodedFrame[] }>;
};

type CompactorInternals = {
	acceptEntry(fields: Readonly<Record<string, Buffer>>): void;
	closeSegmentStore(): void;
};

async function emittedFrame(fields: Record<string, unknown>): Promise<IncidentRecorderEncodedFrame> {
	const writer = new IncidentRecorderWriter({
		runDir: "/tmp/incident-recorder-diagnostic-payload-test",
		runId: RUN_ID,
		runToken: RUN_TOKEN,
	});
	const admission = writer.recordDerived("recorder-events", "diagnostic_payload_test", fields);
	expect(admission.accepted).toBe(true);
	const internals = writer as unknown as WriterInternals;
	for (let attempt = 0; attempt < 100 && internals.relayQueue.length === 0; attempt += 1)
		await new Promise<void>((resolve) => setImmediate(resolve));
	const frame = internals.relayQueue[0]?.frames[0];
	if (!frame) throw new Error("derived frame was not relayed");
	return frame;
}

function parsed(frame: IncidentRecorderEncodedFrame): Record<string, unknown> {
	return JSON.parse(frame.parts[frame.parts.length - 1]?.toString("utf8") ?? "") as Record<string, unknown>;
}

function executable(root: string, name: string, source: string): string {
	const path = join(root, name);
	writeFileSync(path, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
	chmodSync(path, 0o700);
	return path;
}

describe("bounded derived diagnostic payloads", () => {
	it("retains unknown nested data and error stack text without invoking accessors or toJSON", async () => {
		let getterReads = 0;
		let toJsonCalls = 0;
		const cause = { code: "cause-code", detail: { retained: true } };
		const error = new Error("outer failure");
		Object.defineProperty(error, "stack", {
			value: "OuterFailure: full stack text\n    at worker (worker.ts:42:7)",
			enumerable: true,
		});
		Object.defineProperty(error, "cause", { value: cause, enumerable: true });
		Object.defineProperty(error, "customData", { value: { marker: "custom-error-data" }, enumerable: true });
		const nested = {
			futureField: { retained: "future-value", values: [1, true, null] },
			toJSON: () => {
				toJsonCalls += 1;
				return "must-not-run";
			},
		};
		Object.defineProperty(nested, "secret", {
			enumerable: true,
			get: () => {
				getterReads += 1;
				return "must-not-read";
			},
		});

		const frame = await emittedFrame({ error, nested });
		const body = frame.parts[frame.parts.length - 1] ?? Buffer.alloc(0);
		const snapshot = parsed(frame);
		expect(frame.header.payloadKind).toBe("derived-scalar");
		expect(frame.header.encoding).toBe("utf8-json/derived-diagnostic-json-v2");
		expect(body.length).toBeGreaterThan(0);
		expect(body.length).toBeLessThanOrEqual(INCIDENT_RECORDER_DIAGNOSTIC_PAYLOAD_MAX_BYTES);
		expect(body.toString("utf8")).toContain("future-value");
		expect(body.toString("utf8")).toContain("full stack text");
		expect(body.toString("utf8")).toContain("custom-error-data");
		expect(body.toString("utf8")).toContain("cause-code");
		expect(body.toString("utf8")).not.toContain("must-not-read");
		expect(body.toString("utf8")).not.toContain("must-not-run");
		expect(snapshot.schemaVersion).toBe(2);
		expect(frame.header.metadata).toMatchObject({
			payloadState: "serialized",
			payloadBytes: body.length,
			payloadStoredBytes: body.length,
		});
		expect(getterReads).toBe(0);
		expect(toJsonCalls).toBe(0);
	});

	it("retains ordinary native Error stack text while refusing custom stack accessors", () => {
		const native = serializeIncidentRecorderDiagnostic(new Error("native-stack-sentinel"));
		const nativeSnapshot = JSON.parse(native.bytes.toString("utf8")) as {
			value?: { properties?: Array<readonly [string, unknown]> };
		};
		const nativeStack = nativeSnapshot.value?.properties?.find(([key]) => key === "stack")?.[1];
		expect(nativeStack).toEqual(expect.any(String));
		expect(nativeStack).toContain("native-stack-sentinel");
		expect(nativeStack).toMatch(/\n\s+at\s+/);

		let getterReads = 0;
		const custom = new Error("custom-stack-error");
		Object.defineProperty(custom, "stack", {
			configurable: true,
			get: () => {
				getterReads += 1;
				return "must-not-read";
			},
		});
		const customResult = serializeIncidentRecorderDiagnostic(custom);
		expect(customResult.bytes.toString("utf8")).toContain('"reason":"accessor"');
		expect(customResult.bytes.toString("utf8")).not.toContain("must-not-read");
		expect(getterReads).toBe(0);

		let messageReads = 0;
		const accessorDependency = new Error("accessor-dependency");
		Object.defineProperty(accessorDependency, "message", {
			configurable: true,
			get: () => {
				messageReads += 1;
				return "must-not-read";
			},
		});
		const dependencyResult = serializeIncidentRecorderDiagnostic(accessorDependency);
		expect(dependencyResult.bytes.toString("utf8")).toContain('"reason":"native-error-stack-accessor-dependency"');
		expect(dependencyResult.bytes.toString("utf8")).not.toContain("must-not-read");
		expect(messageReads).toBe(0);
	});

	it("serializes cycles, buffers, typed bytes, and UTF-8 deterministically", () => {
		const createValue = () => {
			const value: Record<string, unknown> = {
				nullable: null,
				text: "café 💜",
				buffer: Buffer.from([0, 1, 2, 253, 254, 255]),
				typed: new Uint8Array([3, 4, 5]),
			};
			value.bufferAgain = value.buffer;
			value.self = value;
			return value;
		};
		const first = serializeIncidentRecorderDiagnostic(createValue());
		const second = serializeIncidentRecorderDiagnostic(createValue());
		expect(first.bytes.equals(second.bytes)).toBe(true);
		expect(first.bytes.toString("utf8")).toContain("reference");
		expect(first.bytes.toString("utf8")).toContain('["nullable",null]');
		expect(first.bytes.toString("utf8")).toContain("café 💜");
		expect(first.bytes.toString("utf8")).toContain("AAEC/f7/");
		expect(first.bytes.toString("utf8")).toContain("AwQF");
		expect(first.bytes.toString("utf8")).toContain('"$diagnosticType":"buffer","id":2');
		expect(first.bytes.toString("utf8")).toContain('["bufferAgain",{"$diagnosticType":"reference","id":2}]');
		expect(first.bytes.toString("utf8")).toContain('"$diagnosticType":"typed-bytes","id":3');
		expect(first.bytes.includes(Buffer.from([0xef, 0xbf, 0xbd]))).toBe(false);
	});

	it("emits explicit depth, property, accessor, unsupported, and byte-budget markers", () => {
		const root: Record<string, unknown> = {};
		let cursor = root;
		for (let depth = 0; depth < INCIDENT_RECORDER_DIAGNOSTIC_MAX_DEPTH + 3; depth += 1) {
			const child: Record<string, unknown> = {};
			cursor.child = child;
			cursor = child;
		}
		for (let index = 0; index < 80; index += 1) root[`property${index.toString().padStart(2, "0")}`] = index;
		Object.defineProperty(root, "accessor", { enumerable: true, get: () => "no-read" });
		root.function = () => "no-source";
		root.long = "💥".repeat(20_000);

		const result = serializeIncidentRecorderDiagnostic(root);
		const text = result.bytes.toString("utf8");
		expect(result.bytes.length).toBeLessThanOrEqual(INCIDENT_RECORDER_DIAGNOSTIC_PAYLOAD_MAX_BYTES);
		expect(text).toContain('"reason":"depth"');
		expect(text).toContain('"reason":"property-budget"');
		expect(text).toContain('"reason":"accessor"');
		expect(text).toContain('"kind":"function"');
		expect(result.summary.stringTruncations).toBeGreaterThan(0);
		expect(result.summary.accessorOmissions).toBe(1);

		const makeWideTree = (depth: number): Record<string, unknown> => {
			if (depth === 0) return { leaf: true };
			return {
				a: makeWideTree(depth - 1),
				b: makeWideTree(depth - 1),
				c: makeWideTree(depth - 1),
				d: makeWideTree(depth - 1),
			};
		};
		const nodes = makeWideTree(5);
		const nodeResult = serializeIncidentRecorderDiagnostic(nodes);
		expect(nodeResult.summary.nodes).toBe(INCIDENT_RECORDER_DIAGNOSTIC_MAX_NODES);
		expect(nodeResult.summary.omissions).toBeGreaterThan(0);
		expect(nodeResult.bytes.toString("utf8")).toContain('"reason":"node-budget"');
	});

	it("returns a categorical unavailable sentinel when root inspection fails", () => {
		const hostile = new Proxy(
			{},
			{
				ownKeys: () => {
					throw new Error("must-not-cross-boundary");
				},
			},
		);
		const result = serializeIncidentRecorderDiagnostic(hostile);
		expect(result.summary.state).toBe("unavailable");
		expect(result.bytes.toString("utf8")).toBe(
			'{"schemaVersion":2,"state":"unavailable","reason":"inspection_failed"}',
		);
		expect(result.bytes.toString("utf8")).not.toContain("must-not-cross-boundary");
	});

	it("reserves the complete serialized body plus the existing observation allowance", () => {
		expect(INCIDENT_RECORDER_DERIVED_OBSERVATION_RESERVATION_BYTES).toBe(88 * 1024);
	});

	it("binds the body digest to the emitted occurrence bytes", async () => {
		const frame = await emittedFrame({ future: { reason: "worker-timeout" } });
		const body = frame.parts[frame.parts.length - 1] ?? Buffer.alloc(0);
		expect(createHash("sha256").update(body).digest("hex")).toBe(frame.header.metadata.occurrenceSha256);
		expect(frame.header.payloadLength).toBe(body.length);
	});

	it("preserves exact derived bytes from the writer journal line through compactor history and CAS", async () => {
		const root = mkdtempSync(join(tmpdir(), "incident-recorder-diagnostic-pipeline-"));
		const agentDir = join(root, "agent");
		mkdirSync(agentDir, { recursive: true, mode: 0o700 });
		const scanner = executable(root, "storage-scanner.cjs", 'process.stdout.write("1\\t1\\t0\\t0\\n");');
		let lifecycleLease: IncidentRecorderWriterLifecycleLease | undefined;
		const lifecycleContract: IncidentRecorderWriterLifecycleAdmissionContract = {
			activationGenerationDigest: "a".repeat(64),
			revalidateActivation: () => ({ state: "valid" }),
			acquireCas: acquireIncidentRecorderNamespaceCas,
		};
		const compactor = new IncidentRecorderCompactor({
			agentDir,
			storageScannerPath: scanner,
			freeReserveBytes: 0,
			writerLifecycleLease: () => {
				if (!lifecycleLease) {
					const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, lifecycleContract);
					if (admission.state !== "acquired") throw new Error(`writer lifecycle unavailable: ${admission.reason}`);
					lifecycleLease = admission.lease;
				}
				return lifecycleLease;
			},
		});
		const writer = new IncidentRecorderWriter({ runDir: root, runId: RUN_ID, runToken: RUN_TOKEN });
		try {
			await compactor.initializeStorageAccounting(new AbortController().signal);
			const admission = writer.recordDerived("recorder-events", "diagnostic_pipeline_test", {
				future: { exact: "journal-to-cas", values: [1, null, true] },
			});
			expect(admission.accepted).toBe(true);
			const writerInternal = writer as unknown as WriterInternals & {
				renderJournalLine(frame: IncidentRecorderEncodedFrame, wrapperSequence: bigint): Buffer;
			};
			for (let attempt = 0; attempt < 100 && writerInternal.relayQueue.length === 0; attempt += 1)
				await new Promise<void>((resolve) => setImmediate(resolve));
			const frame = writerInternal.relayQueue[0]?.frames[0];
			if (!frame) throw new Error("expected a queued derived frame");
			const renderedLine = writerInternal.renderJournalLine(frame, 1n);
			const line = JSON.parse(renderedLine.toString("utf8")) as Record<string, unknown>;
			line.machineId = "11111111111111111111111111111111";
			line.bootId = "22222222-2222-4222-8222-222222222222";
			line.systemdCatPid = 123;
			line.systemdCatStartId = "test-cat-start";
			const messageBytes = Buffer.from(JSON.stringify(line), "utf8");
			const eventWallTimeMs = Number(line.eventWallTimeMs);
			const fields: Record<string, Buffer> = {
				__CURSOR: Buffer.from("s=diagnostic-payload"),
				_MACHINE_ID: Buffer.from(String(line.machineId)),
				_BOOT_ID: Buffer.from(String(line.bootId)),
				_STREAM_ID: Buffer.from("diagnostic-stream"),
				__REALTIME_TIMESTAMP: Buffer.from((BigInt(String(line.eventWallTimeMs)) * 1_000n).toString()),
				__MONOTONIC_TIMESTAMP: Buffer.from("1"),
				_PID: Buffer.from("123"),
				_UID: Buffer.from("1000"),
				SYSLOG_IDENTIFIER: Buffer.from("prime-agent-raw-v1"),
				_TRANSPORT: Buffer.from("stdout"),
				MESSAGE: messageBytes,
			};
			(compactor as unknown as CompactorInternals).acceptEntry(fields);

			const payload = frame.parts.at(-1) ?? Buffer.alloc(0);
			const digest = createHash("sha256").update(payload).digest("hex");
			const casPath = join(agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2), `${digest}.blob`);
			expect(readFileSync(casPath)).toEqual(payload);

			let history = compactor.projectRunHistory({
				runId: RUN_ID,
				fromWallTimeMs: eventWallTimeMs,
				throughWallTimeMs: eventWallTimeMs + 1,
			});
			for (let pass = 0; history.state === "pending" && pass < 32; pass += 1) {
				history = compactor.projectRunHistory({
					runId: RUN_ID,
					fromWallTimeMs: eventWallTimeMs,
					throughWallTimeMs: eventWallTimeMs + 1,
					cursor: history.cursor,
				});
			}
			expect(history.state).toBe("complete");
			if (history.state !== "complete") throw new Error("expected complete derived history");
			expect(history.projection.events).toHaveLength(1);
			const event = history.projection.events[0];
			expect(event?.encoding).toBe("utf8-json/derived-diagnostic-json-v2");
			expect(event?.cas.digest).toBe(digest);
			expect(event?.cas.bytes).toBe(payload.length);
			expect(event?.cas.path).toBe(casPath);
			expect(readFileSync(event?.cas.path ?? "")).toEqual(payload);
		} finally {
			await writer.stop(10);
			(compactor as unknown as CompactorInternals).closeSegmentStore();
			lifecycleLease?.release();
			rmSync(root, { recursive: true, force: true });
		}
	});

	it("falls back to one scalar occurrence when the body queue is full and accounts discarded bytes once", async () => {
		const previousMaximum = process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES;
		process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES = String(320 * 1024);
		const writer = new IncidentRecorderWriter({
			runDir: "/tmp/incident-recorder-diagnostic-payload-queue-test",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
		});
		const large: Record<string, unknown> = {};
		for (let index = 0; index < 8; index += 1) large[`field${index}`] = "x".repeat(8 * 1024);
		try {
			expect(writer.recordDerived("recorder-events", "queue-one", large).accepted).toBe(true);
			expect(writer.recordDerived("recorder-events", "queue-two", large).accepted).toBe(true);
			expect(writer.recordDerived("recorder-events", "queue-three", large).accepted).toBe(true);
			const internals = writer as unknown as WriterInternals;
			for (let attempt = 0; attempt < 100 && internals.relayQueue.length < 3; attempt += 1)
				await new Promise<void>((resolve) => setImmediate(resolve));
			const fallback = internals.relayQueue[2]?.frames[0];
			expect(fallback?.header.encoding).toBe("none");
			expect(fallback?.header.payloadLength).toBe(0);
			expect(fallback?.header.metadata.payloadState).toBe("queue_dropped");
			expect(fallback?.header.metadata.payloadStoredBytes).toBe(0);
			expect(fallback?.header.metadata.payloadBytes).toBeGreaterThan(0);
			expect(fallback?.header.metadata.droppedBytes).toBe(fallback?.header.metadata.payloadBytes);
		} finally {
			await writer.stop(10);
			if (previousMaximum === undefined) delete process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES;
			else process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES = previousMaximum;
		}
	});

	it("rewrites a scalar-saturated body to queue_dropped without losing the complete summary", async () => {
		const previousMaximum = process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES;
		process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES = String(256 * 1024);
		const writer = new IncidentRecorderWriter({
			runDir: "/tmp/incident-recorder-diagnostic-payload-fallback-boundary-test",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
		});
		const large = Object.fromEntries(
			Array.from({ length: 8 }, (_value, index) => [`field${index}`, "x".repeat(8 * 1024)]),
		);
		const scalarFields = {
			...large,
			...Object.fromEntries(
				[
					"command",
					"descriptorDir",
					"message",
					"name",
					"originalPath",
					"reason",
					"runName",
					"socketPath",
					"sourcePath",
					"state",
				].map((key) => [key, "x".repeat(512)]),
			),
			category: "c".repeat(92),
		};
		try {
			expect(writer.recordDerived("recorder-events", "fill-one", large).accepted).toBe(true);
			expect(writer.recordDerived("recorder-events", "fill-two", large).accepted).toBe(true);
			expect(writer.recordDerived("recorder-events", "boundary", scalarFields).accepted).toBe(true);
			const internals = writer as unknown as WriterInternals;
			for (let attempt = 0; attempt < 100 && internals.relayQueue.length < 3; attempt += 1)
				await new Promise<void>((resolve) => setImmediate(resolve));
			const fallback = internals.relayQueue[2]?.frames[0];
			expect(fallback?.header.encoding).toBe("none");
			expect(fallback?.header.payloadLength).toBe(0);
			expect(fallback?.header.metadata.payloadState).toBe("queue_dropped");
			expect(fallback?.header.metadata.payloadStoredBytes).toBe(0);
			expect(fallback?.header.metadata.payloadBytes).toBeGreaterThan(0);
			expect(Buffer.byteLength(JSON.stringify(fallback?.header.metadata))).toBeLessThanOrEqual(4 * 1024);
			for (const key of [
				"payloadState",
				"payloadBytes",
				"payloadStoredBytes",
				"payloadNodes",
				"payloadProperties",
				"payloadOmissions",
				"payloadUnsupported",
				"payloadAccessorOmissions",
				"payloadDepthOmissions",
				"payloadStringTruncations",
				"payloadBinaryTruncations",
				"payloadUnavailable",
			] as const)
				expect(fallback?.header.metadata[key], key).toBeDefined();
		} finally {
			await writer.stop(10);
			if (previousMaximum === undefined) delete process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES;
			else process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES = previousMaximum;
		}
	});

	it("retains every payload omission counter when a saturated body falls back to queue_dropped metadata", async () => {
		const previousMaximum = process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES;
		process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES = String(256 * 1024);
		const writer = new IncidentRecorderWriter({
			runDir: "/tmp/incident-recorder-diagnostic-payload-summary-saturation-test",
			runId: RUN_ID,
			runToken: RUN_TOKEN,
		});
		const large: Record<string, unknown> = {};
		for (let index = 0; index < 8; index += 1) large[`field${index}`] = "x".repeat(8 * 1024);
		const diagnostic: Record<string, unknown> = {
			accessor: undefined,
			binary: Buffer.alloc(20 * 1024, 0x61),
			fn: () => "must-not-call",
			hostile: new Proxy(
				{},
				{
					ownKeys: () => {
						throw new Error("must-not-cross-boundary");
					},
				},
			),
			long: "💥".repeat(20_000),
			symbol: Symbol("unsupported"),
		};
		Object.defineProperty(diagnostic, "accessor", {
			enumerable: true,
			get: () => "must-not-read",
		});
		const deepRoot: Record<string, unknown> = {};
		let deepCursor = deepRoot;
		for (let depth = 0; depth <= INCIDENT_RECORDER_DIAGNOSTIC_MAX_DEPTH + 1; depth += 1) {
			const child: Record<string, unknown> = {};
			deepCursor.child = child;
			deepCursor = child;
		}
		diagnostic.deep = deepRoot;
		for (let index = 0; index < 80; index += 1) diagnostic[`property${index.toString().padStart(2, "0")}`] = index;
		Object.assign(diagnostic, large);
		try {
			expect(writer.recordDerived("recorder-events", "summary-saturation-one", large).accepted).toBe(true);
			expect(writer.recordDerived("recorder-events", "summary-saturation-two", large).accepted).toBe(true);
			expect(writer.recordDerived("recorder-events", "summary-saturation-three", diagnostic).accepted).toBe(true);
			const internals = writer as unknown as WriterInternals;
			for (let attempt = 0; attempt < 100 && internals.relayQueue.length < 3; attempt += 1)
				await new Promise<void>((resolve) => setImmediate(resolve));
			const fallback = internals.relayQueue[2]?.frames[0];
			expect(fallback?.header.encoding).toBe("none");
			expect(fallback?.header.metadata.payloadState).toBe("queue_dropped");
			expect(fallback?.header.metadata.payloadStoredBytes).toBe(0);
			expect(fallback?.header.metadata.payloadBytes).toBeGreaterThan(0);
			for (const key of [
				"payloadOmissions",
				"payloadUnsupported",
				"payloadAccessorOmissions",
				"payloadDepthOmissions",
				"payloadStringTruncations",
				"payloadBinaryTruncations",
				"payloadUnavailable",
			] as const)
				expect(fallback?.header.metadata[key], key).toBeGreaterThan(0);
			expect(Buffer.byteLength(JSON.stringify(fallback?.header.metadata))).toBeLessThanOrEqual(4 * 1024);
		} finally {
			await writer.stop(10);
			if (previousMaximum === undefined) delete process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES;
			else process.env.PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES = previousMaximum;
		}
	});
});
