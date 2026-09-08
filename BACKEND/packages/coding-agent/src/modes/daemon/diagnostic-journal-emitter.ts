import { randomUUID } from "node:crypto";
import { readFileSync, readlinkSync } from "node:fs";
import type { Writable } from "node:stream";
import { serializeIncidentRecorderDiagnostic } from "./incident-recorder-diagnostic-serializer.js";
import type { IncidentRecorderAdmission } from "./incident-recorder-writer.js";

export const NATIVE_DIAGNOSTICS_ENV = "PRIME_AGENT_DIAGNOSTICS";
const MAX_LINE_BYTES = 40 * 1024;
const CAUSAL_FIELDS = [
	"observerPid",
	"observerProcessStartId",
	"observerPidNamespace",
	"observerBoottimeOffsetNs",
	"ownerPid",
	"ownerProcessStartId",
	"kernelInstanceId",
	"kernelPid",
	"kernelProcessStartId",
	"kernelGeneration",
	"sessionId",
	"workerId",
	"workerPid",
	"workerProcessStartId",
	"rootActiveSessionId",
	"expectedExitReason",
	"forkserverInstanceId",
	"forkserverPid",
	"forkserverProcessStartId",
	"requestMsgId",
	"protocolMsgId",
	"probeId",
	"observation",
	"channel",
	"caller",
	"operation",
	"reason",
	"phase",
	"crashPhase",
	"lifecycleState",
	"code",
	"signal",
	"status",
	"completionSource",
];

export function nativeDiagnosticsEnabled(environment: NodeJS.ProcessEnv = process.env): boolean {
	return environment[NATIVE_DIAGNOSTICS_ENV] === "native";
}

function processStartId(): string | undefined {
	try {
		const stat = readFileSync("/proc/self/stat", "utf8");
		return stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19];
	} catch {
		return undefined;
	}
}

function processPidNamespace(): string | undefined {
	try {
		return readlinkSync("/proc/self/ns/pid");
	} catch {
		return undefined;
	}
}

function processBoottimeOffsetNs(): string | undefined {
	try {
		const match = /^boottime\s+(-?\d+)\s+(\d+)\s*$/m.exec(readFileSync("/proc/self/timens_offsets", "utf8"));
		if (!match || BigInt(match[2]!) >= 1_000_000_000n) return undefined;
		return String(BigInt(match[1]!) * 1_000_000_000n + BigInt(match[2]!));
	} catch {
		return undefined;
	}
}

/** Admission means queued to the existing journal stream, never stored or exported. */
export class DiagnosticJournalEmitter {
	private readonly producerId = randomUUID();
	private readonly producerStartId = processStartId();
	private readonly producerPidNamespace = processPidNamespace();
	private readonly producerBoottimeOffsetNs = processBoottimeOffsetNs();
	private sequence = 0;
	private queuedBytes = 0;
	private droppedRecords = 0;
	private droppedBytes = 0;
	private stopped = false;
	private failed = false;
	private readonly waiters = new Set<() => void>();
	private readonly onError = () => {
		this.failed = true;
		this.wake();
	};
	constructor(
		private readonly sink: Writable,
		private readonly options: { maxQueuedBytes?: number } = {},
	) {
		sink.on("error", this.onError);
		sink.once("close", () => {
			this.failed = true;
			this.wake();
			sink.off("error", this.onError);
		});
	}

	emit(type: string, fields: Record<string, unknown>): IncidentRecorderAdmission {
		this.sequence += 1;
		if (this.stopped || this.failed || this.sink.destroyed || this.sink.errored || !this.sink.writable)
			return this.reject("stopped", 0);
		try {
			if (type.length > 128) return this.reject("encoding_failed", 0);
			const snapshot = serializeIncidentRecorderDiagnostic(fields);
			const scalars: Record<string, string | number | boolean | null> = {};
			for (const key of CAUSAL_FIELDS) {
				const value: unknown = Object.getOwnPropertyDescriptor(fields, key)?.value;
				if (typeof value === "string") scalars[key] = value.slice(0, 1024);
				else if (
					(typeof value === "number" && Number.isFinite(value)) ||
					typeof value === "boolean" ||
					value === null
				)
					scalars[key] = value;
			}
			const occurrenceId = `${this.producerId}:${this.sequence}`;
			const line = Buffer.from(
				`${JSON.stringify({
					...scalars,
					schema: "prime-agent.diagnostic.v1",
					type,
					producerId: this.producerId,
					producerPid: process.pid,
					producerStartId: this.producerStartId,
					producerPidNamespace: this.producerPidNamespace,
					producerBoottimeOffsetNs: this.producerBoottimeOffsetNs,
					sequence: this.sequence,
					occurrenceId,
					observedAt: new Date().toISOString(),
					monotonicNs: String(process.hrtime.bigint()),
					delivery: "queue_accepted",
					loss: { droppedRecords: this.droppedRecords, droppedBytes: this.droppedBytes },
					capture: snapshot.summary,
					details: JSON.parse(snapshot.bytes.toString("utf8")),
				})}\n`,
			);
			if (line.length > MAX_LINE_BYTES) return this.reject("occurrence_too_large", line.length);
			if (this.queuedBytes + line.length > (this.options.maxQueuedBytes ?? 256 * 1024))
				return this.reject("queue_capacity", line.length);
			this.queuedBytes += line.length;
			try {
				this.sink.write(line, (error?: Error | null) => {
					this.queuedBytes -= line.length;
					if (error) {
						this.failed = true;
						this.droppedRecords += 1;
						this.droppedBytes += line.length;
					}
					this.wake();
				});
			} catch {
				this.queuedBytes -= line.length;
				this.failed = true;
				return this.reject("stopped", line.length);
			}
			return { accepted: true, disposition: "locally_admitted", occurrenceId };
		} catch {
			return this.reject("encoding_failed", 0);
		}
	}

	private reject(
		reason: "stopped" | "encoding_failed" | "occurrence_too_large" | "queue_capacity",
		bytes: number,
	): IncidentRecorderAdmission {
		this.droppedRecords += 1;
		this.droppedBytes += bytes;
		return { accepted: false, disposition: "rejected", reason };
	}
	private wake(): void {
		for (const waiter of this.waiters) waiter();
	}
	async flush(timeoutMs = 1000): Promise<void> {
		if (this.queuedBytes === 0 || this.failed) return;
		await new Promise<void>((resolve) => {
			const done = () => {
				clearTimeout(timer);
				this.waiters.delete(changed);
				resolve();
			};
			const changed = () => {
				if (this.queuedBytes === 0 || this.failed) done();
			};
			const timer = setTimeout(done, timeoutMs);
			this.waiters.add(changed);
		});
	}
	close(): void {
		this.stopped = true;
		this.wake();
	}
}

let emitter: DiagnosticJournalEmitter | undefined;
export function emitNativeDiagnostic(type: string, fields: Record<string, unknown>): IncidentRecorderAdmission {
	// A harmless kernel boundary lets the scoped tracer discover an already-running
	// named producer after the tracer restarts. It does not imply prior coverage.
	process.getuid?.();
	emitter ??= new DiagnosticJournalEmitter(process.stderr);
	return emitter.emit(type, fields);
}
export async function flushNativeDiagnostics(): Promise<void> {
	await emitter?.flush();
}
