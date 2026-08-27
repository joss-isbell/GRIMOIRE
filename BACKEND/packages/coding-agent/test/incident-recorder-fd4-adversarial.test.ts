import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, mkdirSync, mkdtempSync, openSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	decodeIncidentRecorderFrame,
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
	INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES,
	type IncidentRecorderEncodedFrame,
} from "../src/modes/daemon/incident-recorder-protocol.js";
import {
	decodeIncidentRecorderTransportPacket,
	encodeIncidentRecorderTransportPacket,
	INCIDENT_RECORDER_TRANSPORT_MAX_ENCODED_PACKET_BYTES,
	IncidentRecorderTransportDecoder,
	IncidentRecorderTransportSequenceTracker,
} from "../src/modes/daemon/incident-recorder-transport.js";

const RUN_ID = "11111111-1111-4111-8111-111111111111";
const RUN_TOKEN = "22222222-2222-4222-8222-222222222222";
const PRODUCER_A = "33333333-3333-4333-8333-333333333333";
const PRODUCER_B = "44444444-4444-4444-8444-444444444444";

function framesForOccurrence(
	payload: Buffer,
	options: { producerId?: string; occurrenceId?: string; firstSequence?: bigint; type?: string } = {},
): IncidentRecorderEncodedFrame[] {
	const chunkCount = Math.max(1, Math.ceil(payload.length / INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES));
	const occurrenceSha256 = createHash("sha256").update(payload).digest("hex");
	return Array.from({ length: chunkCount }, (_, chunkIndex) => {
		const chunk = payload.subarray(
			chunkIndex * INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES,
			Math.min(payload.length, (chunkIndex + 1) * INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES),
		);
		return encodeIncidentRecorderFrame(
			{
				runId: RUN_ID,
				runToken: RUN_TOKEN,
				producerId: options.producerId ?? PRODUCER_A,
				occurrenceId: options.occurrenceId ?? "55555555-5555-4555-8555-555555555555",
				producerSequence: (options.firstSequence ?? 1n) + BigInt(chunkIndex),
				wallTimeMs: 1n,
				monotonicNs: 2n,
				payloadKind: "exact-bytes",
				flags:
					(chunkIndex === 0 ? INCIDENT_RECORDER_FRAME_FLAGS.firstChunk : 0) |
					(chunkIndex === chunkCount - 1 ? INCIDENT_RECORDER_FRAME_FLAGS.lastChunk : 0),
				chunkIndex,
				chunkCount,
				source: "adversarial-test",
				type: options.type ?? "multi_packet_exact",
				encoding: "exact-bytes",
				metadata: { occurrenceRawBytes: payload.length, occurrenceSha256 },
			},
			chunk,
		);
	});
}

function wireFrame(frame: IncidentRecorderEncodedFrame): Buffer {
	return encodeIncidentRecorderTransportPacket(Buffer.concat(frame.parts));
}

function decodeStream(chunks: readonly Uint8Array[]): {
	frames: ReturnType<typeof decodeIncidentRecorderFrame>[];
	corruption: Array<{ kind: string; wireBytes: number }>;
	invalidProtocolWireBytes: number[];
	finishedTail: number;
} {
	const frames: ReturnType<typeof decodeIncidentRecorderFrame>[] = [];
	const corruption: Array<{ kind: string; wireBytes: number }> = [];
	const invalidProtocolWireBytes: number[] = [];
	const decoder = new IncidentRecorderTransportDecoder(
		(packet, wireBytes) => {
			try {
				frames.push(decodeIncidentRecorderFrame(packet));
			} catch {
				invalidProtocolWireBytes.push(wireBytes);
			}
		},
		(evidence) => corruption.push(evidence),
	);
	for (const chunk of chunks) decoder.push(chunk);
	return { frames, corruption, invalidProtocolWireBytes, finishedTail: decoder.finish() };
}

interface ClaimFixtureResult {
	root: string;
	runA: string;
	runB: string;
	summary: Record<string, any>;
	frames: ReturnType<typeof decodeIncidentRecorderFrame>[];
	stderr: string;
}

let claimFixtureSerial = 0;

async function runClaimFixture(mode: string, sharedRoot?: string): Promise<ClaimFixtureResult> {
	const root = sharedRoot ?? mkdtempSync(join(tmpdir(), "prime-agent-fd5-claim-"));
	const recorderRoot = join(root, "incident-recorder");
	const serial = ++claimFixtureSerial;
	const runA = join(recorderRoot, "runs", `run-a-${serial}`);
	const runB = join(recorderRoot, "runs", `run-b-${serial}`);
	mkdirSync(runA, { recursive: true, mode: 0o700 });
	mkdirSync(runB, { recursive: true, mode: 0o700 });
	const rootDescriptor = openSync(recorderRoot, "r");
	const script = fileURLToPath(new URL("./fixtures/incident-recorder-fd5-claim.ts", import.meta.url));
	const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	const child = spawn(process.execPath, ["--import", tsxLoader, script, mode], {
		env: {
			...process.env,
			PRIME_INCIDENT_RECORDER_CAPTURE_FD: "4",
			PRIME_INCIDENT_RECORDER_ROOT_FD: "5",
			PRIME_INCIDENT_RECORDER_RUN_ID: "12345678-1234-4234-8234-123456789abc",
			PRIME_INCIDENT_RECORDER_RUN_TOKEN: "abcdefab-cdef-4def-8def-abcdefabcdef",
			PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_RUN_DIR: runA,
			PRIME_TEST_SUBSTITUTE_RUN_DIR: runB,
			PRIME_TEST_RECORDER_ROOT: recorderRoot,
			PRIME_TEST_TSX_LOADER: tsxLoader,
			...(mode === "burst" ? { PRIME_INCIDENT_RECORDER_CAPTURE_MAX_BYTES: String(256 * 1024) } : {}),
		},
		stdio: ["ignore", "pipe", "pipe", "ignore", "pipe", rootDescriptor],
	});
	closeSync(rootDescriptor);
	const capture = child.stdio[4];
	if (!(capture instanceof Readable)) throw new Error("fd5 claim fixture has no fd4 capture stream");
	const chunks: Buffer[] = [];
	let stdout = "";
	let stderr = "";
	capture.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
	child.stdout?.setEncoding("utf8");
	child.stderr?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		stdout += chunk;
	});
	child.stderr?.on("data", (chunk: string) => {
		stderr += chunk;
	});
	const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
		child.once("error", reject);
		child.once("close", (code, signal) => resolve({ code, signal }));
	});
	if (exit.code !== 0 || exit.signal !== null) {
		rmSync(root, { recursive: true, force: true });
		throw new Error(`fd5 claim fixture ${mode} failed: ${JSON.stringify(exit)} ${stderr}`);
	}
	const decoded = decodeStream(chunks);
	if (decoded.corruption.length > 0 || decoded.invalidProtocolWireBytes.length > 0 || decoded.finishedTail > 0) {
		rmSync(root, { recursive: true, force: true });
		throw new Error(`fd5 claim fixture ${mode} emitted invalid transport: ${JSON.stringify(decoded)}`);
	}
	return { root, runA, runB, summary: JSON.parse(stdout.trim()), frames: decoded.frames, stderr };
}

describe("incident recorder fd4 adversarial transport", () => {
	it("reassembles exact multi-packet bytes across every hostile stream split", () => {
		const payload = Buffer.alloc(INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES * 3 + 137);
		for (let index = 0; index < payload.length; index += 1) payload[index] = (index * 29 + 17) % 256;
		const frames = framesForOccurrence(payload);
		const wire = Buffer.concat(frames.map(wireFrame));
		const splits: Buffer[] = [];
		let offset = 0;
		const widths = [1, 2, 3, 7, 31, 257, 4093, 5, 8191];
		for (let index = 0; offset < wire.length; index += 1) {
			const end = Math.min(wire.length, offset + widths[index % widths.length]);
			splits.push(wire.subarray(offset, end));
			offset = end;
		}
		const result = decodeStream(splits);
		expect(result.corruption).toEqual([]);
		expect(result.invalidProtocolWireBytes).toEqual([]);
		expect(result.finishedTail).toBe(0);
		expect(result.frames).toHaveLength(frames.length);
		expect(result.frames.map((frame) => frame.header.chunkIndex)).toEqual([0, 1, 2, 3]);
		expect(Buffer.concat(result.frames.map((frame) => frame.payload))).toEqual(payload);
		expect(
			createHash("sha256")
				.update(Buffer.concat(result.frames.map((frame) => frame.payload)))
				.digest("hex"),
		).toBe(frames[0].header.metadata.occurrenceSha256);
	});

	it("resynchronizes after raw contender writes before, inside, and between owner packets", () => {
		const ownerBefore = wireFrame(
			framesForOccurrence(Buffer.from("owner-before"), {
				occurrenceId: "66666666-6666-4666-8666-666666666666",
				firstSequence: 1n,
				type: "owner_before",
			})[0],
		);
		const insideTarget = wireFrame(
			framesForOccurrence(Buffer.from("owner-corrupted-inside"), {
				occurrenceId: "77777777-7777-4777-8777-777777777777",
				firstSequence: 2n,
				type: "owner_inside",
			})[0],
		);
		const ownerAfter = wireFrame(
			framesForOccurrence(Buffer.from("owner-after"), {
				occurrenceId: "88888888-8888-4888-8888-888888888888",
				firstSequence: 3n,
				type: "owner_after",
			})[0],
		);

		// These byte strings model direct writeSync(4, bytes) by a process that bypasses
		// the library. The first and third writes are separately delimited garbage. The
		// second lands inside an owner's encoded packet and must not consume the next one.
		const rawBefore = Buffer.from([0x52, 0x41, 0x57, 0x00]);
		const rawBetween = Buffer.from([0x02, 0xff, 0x00]);
		const rawInside = Buffer.from([0x91, 0x92, 0x93]);
		const insideAt = Math.max(1, Math.floor((insideTarget.length - 1) / 2));
		const corruptedInside = Buffer.concat([
			insideTarget.subarray(0, insideAt),
			rawInside,
			insideTarget.subarray(insideAt),
		]);
		const stream = Buffer.concat([rawBefore, ownerBefore, rawBetween, corruptedInside, ownerAfter]);
		const result = decodeStream([stream.subarray(0, 1), stream.subarray(1, 97), stream.subarray(97)]);

		expect(result.frames.map((frame) => frame.header.type)).toEqual(["owner_before", "owner_after"]);
		expect(result.invalidProtocolWireBytes.length + result.corruption.length).toBe(3);
		expect(result.finishedTail).toBe(0);
		const accountedWireBytes =
			result.invalidProtocolWireBytes.reduce((sum, bytes) => sum + bytes, 0) +
			result.corruption.reduce((sum, evidence) => sum + evidence.wireBytes, 0) +
			ownerBefore.length +
			ownerAfter.length;
		expect(accountedWireBytes).toBe(stream.length);
	});

	it("classifies malformed, oversized, and truncated contenders with exact wire-byte counts", () => {
		const valid = wireFrame(
			framesForOccurrence(Buffer.from("survives"), {
				occurrenceId: "99999999-9999-4999-8999-999999999999",
			})[0],
		);
		const malformed = Buffer.from([5, 1, 2, 0]);
		const oversized = Buffer.concat([
			Buffer.alloc(INCIDENT_RECORDER_TRANSPORT_MAX_ENCODED_PACKET_BYTES + 11, 1),
			Buffer.from([0]),
		]);
		const truncated = Buffer.from([3, 1, 2, 4, 5]);
		const result = decodeStream([malformed, oversized.subarray(0, 17), oversized.subarray(17), valid, truncated]);
		expect(result.frames.map((frame) => frame.payload.toString())).toEqual(["survives"]);
		expect(result.corruption).toEqual([
			{ kind: "malformed-cobs", wireBytes: malformed.length },
			{ kind: "oversized-packet", wireBytes: oversized.length },
			{ kind: "truncated-packet", wireBytes: truncated.length },
		]);
		expect(result.finishedTail).toBe(truncated.length);
	});

	it("contains real inherited-SOCK_STREAM writeSync contenders before, inside, and between owner traffic", async () => {
		const script = fileURLToPath(new URL("./fixtures/incident-recorder-fd4-adversarial.ts", import.meta.url));
		const tsxLoader = fileURLToPath(new URL("../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
		const child = spawn(process.execPath, ["--import", tsxLoader, script], {
			stdio: ["ignore", "pipe", "pipe", "ignore", "pipe"],
		});
		const capture = child.stdio[4];
		if (!(capture instanceof Readable)) throw new Error("fd4 adversarial fixture has no capture stream");
		const chunks: Buffer[] = [];
		let stdout = "";
		let stderr = "";
		capture.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
		child.stdout?.setEncoding("utf8");
		child.stderr?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			stdout += chunk;
		});
		child.stderr?.on("data", (chunk: string) => {
			stderr += chunk;
		});
		const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
			child.once("error", reject);
			child.once("close", (code, signal) => resolve({ code, signal }));
		});
		expect(exit, stderr).toEqual({ code: 0, signal: null });
		const summary = JSON.parse(stdout.trim()) as {
			pid: number;
			contenders: Array<{ pid: number; code: number | null; signal: NodeJS.Signals | null }>;
		};
		expect(summary.contenders).toHaveLength(3);
		expect(new Set(summary.contenders.map((contender) => contender.pid)).size).toBe(3);
		expect(summary.contenders.every((contender) => contender.pid !== summary.pid)).toBe(true);
		expect(summary.contenders.map(({ code, signal }) => ({ code, signal }))).toEqual([
			{ code: 0, signal: null },
			{ code: 0, signal: null },
			{ code: 0, signal: null },
		]);
		const result = decodeStream(chunks);
		expect(result.frames.map((frame) => frame.header.type)).toEqual([
			"write_sync_owner_before",
			"write_sync_owner_after",
		]);
		expect(result.invalidProtocolWireBytes.length + result.corruption.length).toBe(3);
		expect(result.finishedTail).toBe(0);
	}, 15_000);

	it("anchors claims in fd5 recorder root despite run-dir substitution and removes a matching claim on stop", async () => {
		const result = await runClaimFixture("run-dir-substitution");
		try {
			expect(result.summary).toMatchObject({
				configured: true,
				envAfterConfigure: { capture: null, root: null },
				admissions: [{ accepted: true }],
			});
			expect(result.summary.claimFilesBeforeStop).toEqual([result.summary.claimName]);
			expect(result.summary.claimBeforeStop).toMatchObject({
				runId: "12345678-1234-4234-8234-123456789abc",
				runToken: "abcdefab-cdef-4def-8def-abcdefabcdef",
				pid: result.summary.pid,
				rootDevice: expect.any(String),
				rootInode: expect.any(String),
				captureDevice: expect.any(String),
				captureInode: expect.any(String),
			});
			expect(result.summary.claimFilesAfterStop).toEqual([]);
			expect(readdirSync(result.runA)).toEqual([]);
			expect(readdirSync(result.runB)).toEqual([]);
			expect(result.frames.some((frame) => frame.header.type === "run_dir_substitution_owner")).toBe(true);
		} finally {
			rmSync(result.root, { recursive: true, force: true });
		}
	});

	it.each(["pre-symlink", "pre-hardlink"])("rejects a pre-created %s claim without writing", async (mode) => {
		const result = await runClaimFixture(mode);
		try {
			expect(result.summary.configured).toBe(false);
			expect(result.summary.admission).toMatchObject({ accepted: false, reason: "stopped" });
			expect(result.frames).toEqual([]);
			expect(result.summary.claimFiles).toContain(result.summary.claimName);
		} finally {
			rmSync(result.root, { recursive: true, force: true });
		}
	});

	it.each(["post-symlink", "post-hardlink", "fork-pid-copy", "start-id-copy"])(
		"self-fences a %s claim substitution and never deletes the untrusted replacement",
		async (mode) => {
			const result = await runClaimFixture(mode);
			try {
				expect(result.summary.configured).toBe(true);
				expect(result.summary.admissions).toEqual([
					{ accepted: false, disposition: "rejected", reason: "stopped" },
				]);
				expect(result.summary.claimFilesAfterStop).toEqual([result.summary.claimName]);
				expect(result.frames).toEqual([]);
			} finally {
				rmSync(result.root, { recursive: true, force: true });
			}
		},
	);

	it("admits one owner and rejects two simultaneous library contenders on the same fd4/fd5 capabilities", async () => {
		const result = await runClaimFixture("two-contenders");
		try {
			expect(result.summary.configured).toBe(true);
			expect(result.summary.admissions).toEqual([
				expect.objectContaining({ accepted: true }),
				expect.objectContaining({ accepted: true }),
			]);
			expect(result.summary.contenders).toHaveLength(2);
			expect(
				result.summary.contenders.map((value: Record<string, any>) => ({
					configured: value.configured,
					admission: value.admission,
					exit: value.exit,
				})),
			).toEqual(
				Array.from({ length: 2 }, () => ({
					configured: false,
					admission: { accepted: false, disposition: "rejected", reason: "stopped" },
					exit: { code: 0, signal: null },
				})),
			);
			expect(result.summary.claimFilesBeforeStop).toEqual([result.summary.claimName]);
			expect(result.summary.claimFilesAfterStop).toEqual([]);
			expect(result.frames.some((frame) => frame.header.type === "library_contender")).toBe(false);
			expect(result.frames.filter((frame) => frame.header.type.startsWith("library_owner_"))).toHaveLength(2);
		} finally {
			rmSync(result.root, { recursive: true, force: true });
		}
	}, 15_000);

	it("runs two independent supervisors under one recorder root without cross-claiming or cross-stream records", async () => {
		const sharedRoot = mkdtempSync(join(tmpdir(), "prime-agent-fd5-shared-root-"));
		const [first, second] = await Promise.all([
			runClaimFixture("independent", sharedRoot),
			runClaimFixture("independent", sharedRoot),
		]);
		try {
			expect(first.summary.pid).not.toBe(second.summary.pid);
			expect(first.summary.claimName).not.toBe(second.summary.claimName);
			const claimNames = [first.summary.claimName, second.summary.claimName].sort();
			for (const result of [first, second]) {
				expect(result.summary.configured).toBe(true);
				expect([...result.summary.claimFilesBeforeStop].sort()).toEqual(claimNames);
				expect(result.summary.claimFilesAfterStop).not.toContain(result.summary.claimName);
				expect(result.summary.claimFilesAfterStop.every((name: string) => claimNames.includes(name))).toBe(true);
				expect(result.frames.filter((frame) => frame.header.type === "independent_owner")).toHaveLength(1);
				expect(new Set(result.frames.map((frame) => frame.header.metadata.producerPid))).toEqual(
					new Set([result.summary.pid]),
				);
			}
		} finally {
			rmSync(sharedRoot, { recursive: true, force: true });
		}
	}, 15_000);

	it("keeps steady 30-per-second admission bounded to one claim and closes capabilities to ordinary children", async () => {
		const [steady, cleanup] = await Promise.all([runClaimFixture("steady"), runClaimFixture("cleanup")]);
		try {
			expect(steady.summary.elapsedMs).toBeGreaterThanOrEqual(850);
			expect(steady.summary.elapsedMs).toBeLessThan(2_500);
			expect(steady.summary.admissions).toHaveLength(30);
			expect(steady.summary.admissions.every((value: Record<string, unknown>) => value.accepted === true)).toBe(
				true,
			);
			expect(steady.summary.claimFilesBeforeStop).toEqual([steady.summary.claimName]);
			expect(steady.frames.filter((frame) => frame.header.type === "steady_owner")).toHaveLength(30);
			expect(cleanup.summary.ordinaryChild).toMatchObject({
				fd4: { socket: false, directory: false },
				fd5: { socket: false, directory: false },
				capture: null,
				root: null,
				exit: { code: 0, signal: null },
			});
			expect([cleanup.summary.ordinaryChild.fd4.device, cleanup.summary.ordinaryChild.fd4.inode]).not.toEqual([
				cleanup.summary.ownerCapabilities.fd4.device,
				cleanup.summary.ownerCapabilities.fd4.inode,
			]);
			expect([cleanup.summary.ordinaryChild.fd5.device, cleanup.summary.ordinaryChild.fd5.inode]).not.toEqual([
				cleanup.summary.ownerCapabilities.fd5.device,
				cleanup.summary.ownerCapabilities.fd5.inode,
			]);
			expect(cleanup.summary.claimFilesBeforeStop).toEqual([cleanup.summary.claimName]);
			expect(cleanup.summary.claimFilesAfterStop).toEqual([]);
		} finally {
			rmSync(steady.root, { recursive: true, force: true });
			rmSync(cleanup.root, { recursive: true, force: true });
		}
	}, 15_000);

	it("emits and exactly reassembles a multi-packet library occurrence", async () => {
		const result = await runClaimFixture("multi-packet");
		try {
			const frames = result.frames.filter((frame) => frame.header.type === "multi_packet_library_owner");
			expect(frames).toHaveLength(4);
			expect(frames.map((frame) => frame.header.chunkIndex)).toEqual([0, 1, 2, 3]);
			const exact = Buffer.concat(frames.map((frame) => frame.payload));
			expect(exact).toHaveLength(24 * 1024 * 3 + 137);
			expect(exact.every((byte, index) => byte === (index * 31 + 9) % 256)).toBe(true);
			expect(createHash("sha256").update(exact).digest("hex")).toBe(frames[0].header.metadata.occurrenceSha256);
			expect(result.summary.claimFilesAfterStop).toEqual([]);
		} finally {
			rmSync(result.root, { recursive: true, force: true });
		}
	}, 15_000);

	it("bounds a 1200x24KiB burst and records emit-loop and setImmediate lag", async () => {
		const result = await runClaimFixture("burst");
		try {
			expect(result.summary.burst).toMatchObject({ attempted: 1_200 });
			expect(result.summary.burst.accepted).toBeGreaterThan(0);
			expect(result.summary.burst.rejected).toBeGreaterThan(0);
			expect(result.summary.burst.accepted + result.summary.burst.rejected).toBe(1_200);
			// These generous regression limits catch accidental unbounded synchronous
			// filesystem/encoding work without turning host load into a flaky benchmark.
			expect(result.summary.burst.emitLoopElapsedMs).toBeLessThan(5_000);
			expect(result.summary.burst.setImmediateLagMs).toBeLessThan(5_000);
			expect(result.summary.claimFilesBeforeStop).toEqual([result.summary.claimName]);
			expect(result.summary.claimFilesAfterStop).toEqual([]);
		} finally {
			rmSync(result.root, { recursive: true, force: true });
		}
	}, 15_000);

	it("round-trips all byte values and rejects delimiter-bearing encoded input", () => {
		const bytes = Buffer.from(Array.from({ length: 2048 }, (_, index) => index % 256));
		const packet = encodeIncidentRecorderTransportPacket(bytes);
		expect(packet.at(-1)).toBe(0);
		expect(packet.subarray(0, -1).includes(0)).toBe(false);
		expect(decodeIncidentRecorderTransportPacket(packet.subarray(0, -1))).toEqual(bytes);
		expect(() => decodeIncidentRecorderTransportPacket(packet)).toThrow();
	});

	it("finalizes exact gaps independently for two library producers", () => {
		const tracker = new IncidentRecorderTransportSequenceTracker(2);
		for (const [producer, sequence] of [
			[PRODUCER_A, 10n],
			[PRODUCER_B, 50n],
			[PRODUCER_A, 11n],
			[PRODUCER_B, 53n],
			[PRODUCER_A, 14n],
		] as const)
			expect(tracker.observe(producer, sequence)).toEqual({ duplicate: false, gapEvents: 0n, missingPackets: 0n });
		expect(tracker.trackedProducers).toBe(2);
		expect(tracker.finish()).toEqual({ gapEvents: 2n, missingPackets: 4n });
	});
});
