import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { getProcessStartId } from "../../src/core/session-lease.js";
import {
	configureIncidentCaptureEmitter,
	emitIncidentBytes,
	INCIDENT_RECORDER_CAPTURE_FD_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV,
	INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV,
	INCIDENT_RECORDER_ROOT_FD_ENV,
	incidentRecorderCaptureOwnerClaimFileName,
	stopIncidentCaptureEmitter,
} from "../../src/modes/daemon/incident-recorder-writer.js";

const RECORD_BYTES = 24 * 1024;
const RECORDS = 1_200;

function payload(index: number): Buffer {
	const result = Buffer.alloc(RECORD_BYTES, index % 251);
	result.writeUInt32BE(index, 0);
	return result;
}

if (process.argv[2] === "contender") {
	// Recreate the exact spoof that used to bypass the environment-only owner.
	process.env[INCIDENT_RECORDER_CAPTURE_FD_ENV] = "4";
	process.env[INCIDENT_RECORDER_ROOT_FD_ENV] = "5";
	delete process.env[INCIDENT_RECORDER_CAPTURE_OWNER_PID_ENV];
	delete process.env[INCIDENT_RECORDER_CAPTURE_OWNER_START_ID_ENV];
	const configured = configureIncidentCaptureEmitter();
	const admission = emitIncidentBytes("supervisor-events", "shared_fd_contender", payload(0), { pid: process.pid });
	process.stdout.write(
		`${JSON.stringify({
			pid: process.pid,
			processStartId: getProcessStartId(process.pid),
			configured,
			admission,
		})}\n`,
	);
} else if (process.argv[2] === "stop-timeout") {
	const configured = configureIncidentCaptureEmitter();
	if (!configured) throw new Error("stop-timeout fixture could not claim capture channel");
	let accepted = 0;
	let rejected = 0;
	let rejectedBytes = 0;
	for (let index = 0; index < RECORDS; index += 1) {
		const admission = emitIncidentBytes("supervisor-events", "stop_timeout_owner", payload(index), {
			pid: process.pid,
		});
		if (admission.accepted) accepted += 1;
		else {
			rejected += 1;
			rejectedBytes += RECORD_BYTES;
		}
	}
	await stopIncidentCaptureEmitter();
	process.stdout.write(
		`${JSON.stringify({
			pid: process.pid,
			processStartId: getProcessStartId(process.pid),
			configured,
			accepted,
			rejected,
			rejectedBytes,
		})}\n`,
	);
} else if (process.argv[2] === "stop-race") {
	const configured = configureIncidentCaptureEmitter();
	if (!configured) throw new Error("stop-race fixture could not claim capture channel");
	const first = emitIncidentBytes("supervisor-events", "before_stop", payload(0), { pid: process.pid });
	const stopping = stopIncidentCaptureEmitter();
	const afterStopBegan = await new Promise<ReturnType<typeof emitIncidentBytes>>((resolve) => {
		setImmediate(() =>
			resolve(emitIncidentBytes("supervisor-events", "after_stop_began", payload(1), { pid: process.pid })),
		);
	});
	await stopping;
	process.stdout.write(
		`${JSON.stringify({
			pid: process.pid,
			processStartId: getProcessStartId(process.pid),
			configured,
			first,
			afterStopBegan,
		})}\n`,
	);
} else if (process.argv[2] === "fork-copy-identity-mismatch") {
	const configured = configureIncidentCaptureEmitter();
	if (!configured) throw new Error("fork-copy fixture could not claim capture channel");
	const claimFileName = incidentRecorderCaptureOwnerClaimFileName();
	if (!claimFileName) throw new Error("fork-copy fixture has no claim identity");
	const claimPath = join("/proc/self/fd/5", claimFileName);
	const claim = JSON.parse(readFileSync(claimPath, "utf8")) as Record<string, unknown>;
	writeFileSync(claimPath, `${JSON.stringify({ ...claim, pid: process.pid + 1 })}\n`, { mode: 0o600 });
	const admission = emitIncidentBytes("supervisor-events", "fork_copy_must_not_write", payload(0), {
		pid: process.pid,
	});
	process.stdout.write(
		`${JSON.stringify({
			pid: process.pid,
			processStartId: getProcessStartId(process.pid),
			configured,
			admission,
		})}\n`,
	);
	await stopIncidentCaptureEmitter();
} else {
	const configured = configureIncidentCaptureEmitter();
	if (!configured) throw new Error("shared fd owner could not claim capture channel");
	const tsxLoader = process.env.PRIME_TEST_TSX_LOADER;
	if (!tsxLoader) throw new Error("PRIME_TEST_TSX_LOADER is required");
	const contender = spawn(process.execPath, ["--import", tsxLoader, process.argv[1], "contender"], {
		env: process.env,
		stdio: ["ignore", "pipe", "inherit", "ignore", 4, 5],
	});
	let contenderOutput = "";
	contender.stdout?.setEncoding("utf8");
	contender.stdout?.on("data", (chunk: string) => {
		contenderOutput += chunk;
	});
	const contenderResult = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
		contender.once("error", reject);
		contender.once("close", (code, signal) => resolve({ code, signal }));
	});

	let accepted = 0;
	let rejected = 0;
	let rejectedBytes = 0;
	for (let index = 0; index < RECORDS; index += 1) {
		const admission = emitIncidentBytes("supervisor-events", "shared_fd_owner", payload(index), { index });
		if (admission.accepted) accepted += 1;
		else {
			rejected += 1;
			rejectedBytes += RECORD_BYTES;
		}
	}
	const childExit = await contenderResult;
	const contenderSummary = JSON.parse(contenderOutput.trim()) as Record<string, unknown>;
	const claimFileName = incidentRecorderCaptureOwnerClaimFileName();
	if (!claimFileName) throw new Error("shared fd owner has no claim identity");
	const ownerClaim = JSON.parse(readFileSync(join("/proc/self/fd/5", claimFileName), "utf8")) as Record<
		string,
		unknown
	>;
	process.stdout.write(
		`${JSON.stringify({
			pid: process.pid,
			processStartId: getProcessStartId(process.pid),
			configured,
			attempted: RECORDS,
			accepted,
			rejected,
			rejectedBytes,
			contender: contenderSummary,
			contenderExit: childExit,
			ownerClaim,
		})}\n`,
	);
	await stopIncidentCaptureEmitter();
}
