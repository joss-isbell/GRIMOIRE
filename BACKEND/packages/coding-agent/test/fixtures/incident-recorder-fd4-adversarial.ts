import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { writeSync } from "node:fs";
import {
	encodeIncidentRecorderFrame,
	INCIDENT_RECORDER_FRAME_FLAGS,
} from "../../src/modes/daemon/incident-recorder-protocol.js";
import { encodeIncidentRecorderTransportPacket } from "../../src/modes/daemon/incident-recorder-transport.js";

const runId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const runToken = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const producerId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

function ownerPacket(type: string, occurrenceId: string, sequence: bigint): Buffer {
	const payload = Buffer.from(type, "utf8");
	const frame = encodeIncidentRecorderFrame(
		{
			runId,
			runToken,
			producerId,
			occurrenceId,
			producerSequence: sequence,
			wallTimeMs: 1n,
			monotonicNs: sequence,
			payloadKind: "exact-bytes",
			flags: INCIDENT_RECORDER_FRAME_FLAGS.firstChunk | INCIDENT_RECORDER_FRAME_FLAGS.lastChunk,
			chunkIndex: 0,
			chunkCount: 1,
			source: "write-sync-owner",
			type,
			encoding: "utf8",
			metadata: {
				occurrenceRawBytes: payload.length,
				occurrenceSha256: createHash("sha256").update(payload).digest("hex"),
			},
		},
		payload,
	);
	return encodeIncidentRecorderTransportPacket(Buffer.concat(frame.parts));
}

async function rawContender(
	bytes: Buffer,
): Promise<{ pid: number; code: number | null; signal: NodeJS.Signals | null }> {
	const script = 'require("node:fs").writeSync(4,Buffer.from(process.argv[1],"hex"))';
	const child = spawn(process.execPath, ["-e", script, bytes.toString("hex")], {
		stdio: ["ignore", "ignore", "inherit", "ignore", 4],
	});
	if (!child.pid) throw new Error("raw writeSync contender has no pid");
	const pid = child.pid;
	return await new Promise((resolve, reject) => {
		child.once("error", reject);
		child.once("close", (code, signal) => resolve({ pid, code, signal }));
	});
}

const contenders: Array<{ pid: number; code: number | null; signal: NodeJS.Signals | null }> = [];
// Raw bytes before owner traffic.
contenders.push(await rawContender(Buffer.from([0x52, 0x41, 0x57, 0x00])));
const before = ownerPacket("write_sync_owner_before", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", 1n);
writeSync(4, before);
// Raw bytes between two complete owner packets.
contenders.push(await rawContender(Buffer.from([0x05, 0x01, 0x02, 0x00])));
// Force a contender inside a packet by pausing the owner between two writeSync calls.
const inside = ownerPacket("write_sync_owner_inside", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", 2n);
const split = Math.floor((inside.length - 1) / 2);
writeSync(4, inside.subarray(0, split));
contenders.push(await rawContender(Buffer.from([0x91, 0x92, 0x93])));
writeSync(4, inside.subarray(split));
const after = ownerPacket("write_sync_owner_after", "ffffffff-ffff-4fff-8fff-ffffffffffff", 3n);
writeSync(4, after);
process.stdout.write(`${JSON.stringify({ pid: process.pid, contenders })}\n`);
