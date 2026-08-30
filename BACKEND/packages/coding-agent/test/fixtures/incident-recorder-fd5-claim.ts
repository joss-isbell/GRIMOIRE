import { spawn } from "node:child_process";
import {
	existsSync,
	fstatSync,
	linkSync,
	lstatSync,
	readdirSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
	configureIncidentCaptureEmitter,
	emitIncidentBytes,
	INCIDENT_RECORDER_CAPTURE_FD_ENV,
	INCIDENT_RECORDER_ROOT_FD_ENV,
	incidentRecorderCaptureOwnerClaimFileName,
	stopIncidentCaptureEmitter,
} from "../../src/modes/daemon/incident-recorder-writer.js";

const mode = process.argv[2] ?? "owner";
const configuredRoot = process.env.PRIME_TEST_RECORDER_ROOT;
if (!configuredRoot) throw new Error("PRIME_TEST_RECORDER_ROOT is required");
const root: string = configuredRoot;
const claimName = incidentRecorderCaptureOwnerClaimFileName();
if (!claimName) throw new Error("capture claim filename unavailable");
const claimPath = join(root, claimName);
const payload = Buffer.alloc(1024, 0x5a);
const fdIdentity = (fd: number): Record<string, unknown> => {
	const stat = fstatSync(fd, { bigint: true });
	return {
		device: stat.dev.toString(),
		inode: stat.ino.toString(),
		socket: stat.isSocket(),
		directory: stat.isDirectory(),
	};
};
const ownerCapabilities = { fd4: fdIdentity(4), fd5: fdIdentity(5) };

function claimFiles(): string[] {
	return readdirSync(root).filter((name) => name.startsWith(".capture-owner-v1."));
}

function readClaim(): Record<string, unknown> | null {
	try {
		if (!lstatSync(claimPath).isFile()) return null;
		return JSON.parse(readFileSync(claimPath, "utf8")) as Record<string, unknown>;
	} catch {
		return null;
	}
}

async function childResult(child: ReturnType<typeof spawn>): Promise<Record<string, unknown>> {
	let output = "";
	child.stdout?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		output += chunk;
	});
	const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
		child.once("error", reject);
		child.once("close", (code, signal) => resolve({ code, signal }));
	});
	return { ...JSON.parse(output.trim()), exit } as Record<string, unknown>;
}

if (mode === "contender") {
	const configured = configureIncidentCaptureEmitter();
	const admission = emitIncidentBytes("adversarial", "library_contender", payload, { pid: process.pid });
	process.stdout.write(`${JSON.stringify({ pid: process.pid, configured, admission })}\n`);
} else if (mode === "pre-symlink" || mode === "pre-hardlink") {
	const other = join(root, `other-${process.pid}`);
	writeFileSync(other, "not a valid claim", { mode: 0o600 });
	if (mode === "pre-symlink") symlinkSync(other, claimPath);
	else linkSync(other, claimPath);
	const configured = configureIncidentCaptureEmitter();
	const admission = emitIncidentBytes("adversarial", mode, payload, {});
	process.stdout.write(
		`${JSON.stringify({ pid: process.pid, configured, admission, claimName, claimFiles: claimFiles() })}\n`,
	);
} else {
	const configured = configureIncidentCaptureEmitter();
	if (!configured) throw new Error(`${mode} fixture could not claim capture capability`);
	const envAfterConfigure = {
		capture: process.env[INCIDENT_RECORDER_CAPTURE_FD_ENV] ?? null,
		root: process.env[INCIDENT_RECORDER_ROOT_FD_ENV] ?? null,
	};
	const admissions: unknown[] = [];
	let contenders: Record<string, unknown>[] = [];
	let ordinaryChild: Record<string, unknown> | undefined;
	let burst: Record<string, number> | undefined;
	let synchronizedClaimBeforeStop: Record<string, unknown> | null | undefined;
	let synchronizedClaimFilesBeforeStop: string[] | undefined;
	const startedAt = Date.now();
	if (mode === "post-symlink" || mode === "post-hardlink" || mode === "fork-pid-copy" || mode === "start-id-copy") {
		const exact = readFileSync(claimPath);
		if (mode === "fork-pid-copy" || mode === "start-id-copy") {
			const claim = JSON.parse(exact.toString("utf8")) as Record<string, unknown>;
			const replacement =
				mode === "fork-pid-copy" ? { ...claim, pid: process.pid + 1 } : { ...claim, processStartId: "proc:1" };
			writeFileSync(claimPath, `${JSON.stringify(replacement)}\n`, { mode: 0o600 });
		} else {
			const other = join(root, `post-other-${process.pid}`);
			writeFileSync(other, exact, { mode: 0o600 });
			rmSync(claimPath);
			if (mode === "post-symlink") symlinkSync(other, claimPath);
			else linkSync(other, claimPath);
		}
		admissions.push(emitIncidentBytes("adversarial", mode, payload, {}));
	} else if (mode === "two-contenders") {
		const loader = process.env.PRIME_TEST_TSX_LOADER;
		if (!loader) throw new Error("PRIME_TEST_TSX_LOADER is required");
		const environment = {
			...process.env,
			[INCIDENT_RECORDER_CAPTURE_FD_ENV]: "4",
			[INCIDENT_RECORDER_ROOT_FD_ENV]: "5",
		};
		const children = Array.from({ length: 2 }, () =>
			spawn(process.execPath, ["--import", loader, process.argv[1], "contender"], {
				env: environment,
				stdio: ["ignore", "pipe", "inherit", "ignore", 4, 5],
			}),
		);
		admissions.push(emitIncidentBytes("adversarial", "library_owner_before", payload, {}));
		contenders = await Promise.all(children.map(childResult));
		admissions.push(emitIncidentBytes("adversarial", "library_owner_after", payload, {}));
	} else if (mode === "run-dir-substitution") {
		process.env.PRIME_AGENT_INTERNAL_INCIDENT_RECORDER_RUN_DIR = process.env.PRIME_TEST_SUBSTITUTE_RUN_DIR;
		admissions.push(emitIncidentBytes("adversarial", "run_dir_substitution_owner", payload, {}));
	} else if (mode === "burst") {
		const burstPayload = Buffer.alloc(24 * 1024, 0xa5);
		let accepted = 0;
		let rejected = 0;
		const loopStarted = Date.now();
		let immediateAt = 0;
		const immediate = new Promise<void>((resolve) =>
			setImmediate(() => {
				immediateAt = Date.now();
				resolve();
			}),
		);
		for (let index = 0; index < 1_200; index += 1) {
			const admission = emitIncidentBytes("adversarial", "burst_owner", burstPayload, { index });
			if (admission.accepted) accepted += 1;
			else rejected += 1;
		}
		const emitLoopElapsedMs = Date.now() - loopStarted;
		await immediate;
		burst = { attempted: 1_200, accepted, rejected, emitLoopElapsedMs, setImmediateLagMs: immediateAt - loopStarted };
	} else if (mode === "multi-packet") {
		const exact = Buffer.alloc(24 * 1024 * 3 + 137);
		for (let index = 0; index < exact.length; index += 1) exact[index] = (index * 31 + 9) % 256;
		admissions.push(emitIncidentBytes("adversarial", "multi_packet_library_owner", exact, { bytes: exact.length }));
	} else if (mode === "steady") {
		for (let index = 0; index < 30; index += 1) {
			admissions.push(emitIncidentBytes("adversarial", "steady_owner", payload, { index }));
			await new Promise<void>((resolve) => setTimeout(resolve, 1000 / 30));
		}
	} else if (mode === "cleanup") {
		const child = spawn(
			process.execPath,
			[
				"-e",
				`const fs=require("node:fs");const probe=(fd)=>{try{const s=fs.fstatSync(fd);return {device:String(s.dev),inode:String(s.ino),socket:s.isSocket(),directory:s.isDirectory(),character:s.isCharacterDevice(),target:fs.readlinkSync("/proc/self/fd/"+fd)}}catch(e){return {error:e.code}}};process.stdout.write(JSON.stringify({fd4:probe(4),fd5:probe(5),capture:process.env.${INCIDENT_RECORDER_CAPTURE_FD_ENV}??null,root:process.env.${INCIDENT_RECORDER_ROOT_FD_ENV}??null}))`,
			],
			{
				env: process.env,
				stdio: ["ignore", "pipe", "inherit", "ignore", "ignore", "ignore"],
			},
		);
		ordinaryChild = await childResult(child);
		admissions.push(emitIncidentBytes("adversarial", "cleanup_owner", payload, {}));
	} else if (mode === "independent") {
		admissions.push(emitIncidentBytes("adversarial", "independent_owner", payload, {}));
		writeFileSync(join(root, `.test-ready-${process.pid}`), "ready");
		for (let attempt = 0; claimFiles().length < 2 && attempt < 500; attempt += 1) {
			await new Promise<void>((resolve) => setTimeout(resolve, 2));
		}
		synchronizedClaimBeforeStop = readClaim();
		synchronizedClaimFilesBeforeStop = claimFiles();
		writeFileSync(join(root, `.test-snapshot-${process.pid}`), "snapshotted");
		for (
			let attempt = 0;
			readdirSync(root).filter((name) => name.startsWith(".test-snapshot-")).length < 2 && attempt < 500;
			attempt += 1
		) {
			await new Promise<void>((resolve) => setTimeout(resolve, 2));
		}
	} else {
		admissions.push(emitIncidentBytes("adversarial", "independent_owner", payload, {}));
	}
	const claimBeforeStop = synchronizedClaimBeforeStop ?? readClaim();
	const claimFilesBeforeStop = synchronizedClaimFilesBeforeStop ?? claimFiles();
	await stopIncidentCaptureEmitter();
	process.stdout.write(
		`${JSON.stringify({
			pid: process.pid,
			mode,
			ownerCapabilities,
			configured,
			claimName,
			claimFilesBeforeStop,
			claimBeforeStop,
			claimFilesAfterStop: claimFiles(),
			claimAfterStop: existsSync(claimPath) ? readClaim() : null,
			envAfterConfigure,
			admissions,
			contenders,
			ordinaryChild,
			burst,
			elapsedMs: Date.now() - startedAt,
		})}\n`,
	);
}
