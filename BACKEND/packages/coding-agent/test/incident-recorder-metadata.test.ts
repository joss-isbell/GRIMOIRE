import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES,
	type IncidentRecorderEncodedFrame,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import { IncidentRecorderWriter } from "../src/modes/daemon/incident-recorder-writer.js";

const TEST_RUN_ID = "11111111-1111-4111-8111-111111111111";
const TEST_RUN_TOKEN = "22222222-2222-4222-8222-222222222222";

type WriterMetadataInternals = {
	relayQueue: Array<{ frames: readonly IncidentRecorderEncodedFrame[] }>;
};

async function emittedMetadata(
	fields: Record<string, unknown>,
): Promise<Readonly<Record<string, string | number | boolean | null>>> {
	const writer = new IncidentRecorderWriter({
		runDir: "/tmp/incident-recorder-metadata-test",
		runId: TEST_RUN_ID,
		runToken: TEST_RUN_TOKEN,
	});
	const admission = writer.recordDerived("recorder-events", "diagnostic_metadata_test", fields);
	expect(admission.accepted).toBe(true);
	const internals = writer as unknown as WriterMetadataInternals;
	for (let attempt = 0; attempt < 100 && internals.relayQueue.length === 0; attempt += 1) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
	const metadata = internals.relayQueue[0]?.frames[0]?.header.metadata;
	expect(metadata).toBeDefined();
	return metadata ?? {};
}

const EMITTER_METADATA_KEYS = [
	"attemptedBytes",
	"attemptedRecords",
	"droppedBytes",
	"droppedRecords",
	"occurrenceRawBytes",
	"occurrenceSha256",
	"producerPid",
	"producerStartId",
	"queueDisposition",
	"queuedBytes",
	"queuedRecords",
] as const;

describe("incident recorder diagnostic metadata", () => {
	it("preserves optional kernel stderr capture completion and omits it for legacy/fork records", async () => {
		for (const stderrCaptureComplete of [true, false]) {
			expect(await emittedMetadata({ stderrCaptureComplete })).toMatchObject({ stderrCaptureComplete });
		}
		const legacyForkMetadata = await emittedMetadata({ stderrCaptureStatus: "unavailable_fork" });
		expect(legacyForkMetadata).toMatchObject({ stderrCaptureStatus: "unavailable_fork" });
		expect(legacyForkMetadata).not.toHaveProperty("stderrCaptureComplete");
	});

	it("retains bounded worker timeout metadata without serializing unrelated data", async () => {
		const metadata = await emittedMetadata({
			requestType: "list",
			timeoutMs: 25,
			requestId: "worker_7",
			outcome: "timeout",
			durationMs: 25,
			nested: { unbounded: "must-not-expand" },
		});

		expect(metadata).toMatchObject({
			requestType: "list",
			timeoutMs: 25,
			requestId: "worker_7",
			outcome: "timeout",
			durationMs: 25,
		});
		expect(metadata).not.toHaveProperty("nested");
	});

	it("preserves the explicit causal schema without invoking getters or walking nested data", async () => {
		let getterReads = 0;
		const error: Record<string, unknown> = {};
		Object.defineProperties(error, {
			name: { value: "KernelCollapseError", enumerable: true },
			message: { value: "kernel vanished during execute", enumerable: true },
			stack: { value: "KernelCollapseError: kernel vanished\n    at execute (kernel.ts:42:7)", enumerable: true },
			cause: {
				enumerable: true,
				get: () => {
					getterReads += 1;
					return { token: "must-not-expand" };
				},
			},
			secret: { value: "must-not-record", enumerable: true },
		});
		const fields: Record<string, unknown> = {
			origin: "unhandledRejection",
			supervisorGeneration: "supervisor-generation-7",
			workerPid: 4101,
			workerProcessStartId: "proc:worker-start",
			rootSessionId: "root-session",
			rootActiveSessionId: "root-active-session",
			sessionId: "session",
			activeSessionId: "active-session",
			kernelInstanceId: "kernel-instance",
			kernelPid: 4202,
			kernelProcessStartId: "proc:kernel-start",
			executionId: "execution-9",
			requestId: "request-10",
			requestMsgId: "request-message-11",
			crashPhase: "awaiting-shell-reply",
			launchMode: "fork",
			channel: "iopub",
			sourceBytes: 8192,
			retainedBytes: 4096,
			sourceTruncated: true,
			stderrSha256: "a".repeat(64),
			error,
			secret: "must-not-record",
			nested: { authorization: "Bearer must-not-expand" },
		};
		Object.defineProperty(fields, "agentId", {
			enumerable: true,
			get: () => {
				getterReads += 1;
				return "getter-agent";
			},
		});

		const metadata = await emittedMetadata(fields);

		expect(getterReads).toBe(0);
		expect(metadata).toMatchObject({
			origin: "unhandledRejection",
			supervisorGeneration: "supervisor-generation-7",
			workerPid: 4101,
			workerProcessStartId: "proc:worker-start",
			rootSessionId: "root-session",
			rootActiveSessionId: "root-active-session",
			sessionId: "session",
			activeSessionId: "active-session",
			kernelInstanceId: "kernel-instance",
			kernelPid: 4202,
			kernelProcessStartId: "proc:kernel-start",
			executionId: "execution-9",
			requestId: "request-10",
			requestMsgId: "request-message-11",
			crashPhase: "awaiting-shell-reply",
			errorName: "KernelCollapseError",
			errorMessage: "kernel vanished during execute",
			errorMessageTruncated: false,
			errorStackSha256: createHash("sha256")
				.update("KernelCollapseError: kernel vanished\n    at execute (kernel.ts:42:7)")
				.digest("hex"),
			errorStackDigestScope: "complete",
			errorStackTruncated: false,
			launchMode: "fork",
			channel: "iopub",
			sourceBytes: 8192,
			retainedBytes: 4096,
			sourceTruncated: true,
			stderrSha256: "a".repeat(64),
			diagnosticMetadataTruncated: false,
		});
		expect(Object.keys(metadata).sort()).toEqual(
			[
				...EMITTER_METADATA_KEYS,
				"activeSessionId",
				"crashPhase",
				"diagnosticMetadataTruncated",
				"errorMessage",
				"errorMessageTruncated",
				"errorName",
				"errorStackSha256",
				"errorStackDigestScope",
				"errorStackTruncated",
				"executionId",
				"kernelInstanceId",
				"kernelPid",
				"kernelProcessStartId",
				"launchMode",
				"channel",
				"origin",
				"payloadAccessorOmissions",
				"payloadBinaryTruncations",
				"payloadBytes",
				"payloadDepthOmissions",
				"payloadNodes",
				"payloadOmissions",
				"payloadProperties",
				"payloadState",
				"payloadStoredBytes",
				"payloadStringTruncations",
				"payloadUnavailable",
				"payloadUnsupported",
				"requestId",
				"requestMsgId",
				"rootActiveSessionId",
				"rootSessionId",
				"sessionId",
				"sourceBytes",
				"retainedBytes",
				"sourceTruncated",
				"stderrSha256",
				"supervisorGeneration",
				"workerPid",
				"workerProcessStartId",
			].sort(),
		);
	});

	it("bounds UTF-8 fields and error inspection while retaining every causal identity", async () => {
		const longText = "💥".repeat(40_000);
		const error: Record<string, unknown> = {};
		Object.defineProperties(error, {
			name: { value: longText, enumerable: true },
			message: { value: longText, enumerable: true },
			stack: { value: longText, enumerable: true },
		});
		const causalStringKeys = [
			"origin",
			"supervisorGeneration",
			"workerProcessStartId",
			"rootSessionId",
			"rootActiveSessionId",
			"sessionId",
			"activeSessionId",
			"kernelInstanceId",
			"kernelProcessStartId",
			"executionId",
			"requestId",
			"requestMsgId",
			"crashPhase",
		] as const;
		const fields: Record<string, unknown> = {
			error,
			workerPid: 5101,
			kernelPid: 5202,
			message: longText,
		};
		for (const key of causalStringKeys) fields[key] = longText;

		const metadata = await emittedMetadata(fields);

		for (const key of causalStringKeys) {
			expect(metadata[key], key).toEqual(expect.any(String));
			expect(Buffer.byteLength(String(metadata[key])), key).toBeLessThanOrEqual(96);
			expect(String(metadata[key]), key).not.toContain("�");
		}
		expect(metadata.workerPid).toBe(5101);
		expect(metadata.kernelPid).toBe(5202);
		expect(Buffer.byteLength(String(metadata.errorName))).toBeLessThanOrEqual(96);
		expect(Buffer.byteLength(String(metadata.errorMessage))).toBeLessThanOrEqual(512);
		expect(metadata.errorMessageTruncated).toBe(true);
		expect(metadata.errorStackTruncated).toBe(true);
		expect(metadata.errorStackDigestScope).toBe("retained_prefix");
		expect(metadata.errorStackSha256).toBe(
			createHash("sha256")
				.update("💥".repeat((64 * 1024) / 4))
				.digest("hex"),
		);
		expect(metadata.diagnosticMetadataTruncated).toBe(true);
		expect(Buffer.byteLength(JSON.stringify(metadata))).toBeLessThanOrEqual(
			INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES,
		);
	});

	it("retains flattened diagnostic bridge loss counters and sequence evidence", async () => {
		const metadata = await emittedMetadata({
			workerId: "worker-loss",
			queueOverflow: 11,
			evictedNormal: 7,
			criticalOverflow: 3,
			oversize: 2,
			encodeFailure: 1,
			transportError: 4,
			shutdown: 5,
			droppedFrames: 6,
			expectedSequence: 18,
			observedSequence: 24,
			counts: { queueOverflow: 999 },
		});

		expect(metadata).toMatchObject({
			workerId: "worker-loss",
			queueOverflow: 11,
			evictedNormal: 7,
			criticalOverflow: 3,
			oversize: 2,
			encodeFailure: 1,
			transportError: 4,
			shutdown: 5,
			droppedFrames: 6,
			expectedSequence: 18,
			observedSequence: 24,
		});
		expect(metadata).not.toHaveProperty("counts");
	});
});
