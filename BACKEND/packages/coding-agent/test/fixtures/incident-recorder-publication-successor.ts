import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { getProcessStartId } from "../../src/core/session-lease.js";
import { runIncidentRecorderService } from "../../src/modes/daemon/incident-recorder.js";
import type { IncidentCasRootMutation } from "../../src/modes/daemon/incident-recorder-cas-transaction.js";
import { IncidentRecorderCompactor } from "../../src/modes/daemon/incident-recorder-compactor.js";
import {
	acquireIncidentRecorderNamespaceCas,
	type IncidentRecorderNamespaceRoots,
} from "../../src/modes/daemon/incident-recorder-namespace-admission.js";
import type { IncidentRecorderSegmentAppendInput } from "../../src/modes/daemon/incident-recorder-segment-store.js";
import {
	acquireIncidentRecorderWriterNormalLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
} from "../../src/modes/daemon/incident-recorder-writer-lifecycle.js";

const RUN_ID = "55555555-5555-4555-8555-555555555555";
const RUN_TOKEN = "66666666-6666-4666-8666-666666666666";
const TRIGGER_PRODUCER_ID = "77777777-7777-4777-8777-777777777777";
const FENCE_PRODUCER_ID = "88888888-8888-4888-8888-888888888888";
const ANCHOR = 1_700_700_000_000;

interface FaultState {
	enabled: boolean;
	triggered: boolean;
}

interface CompactorInternals {
	appendSegmentRecord(input: IncidentRecorderSegmentAppendInput): unknown;
	storageBytes: number;
	storageEntries: number;
	storageInodes: Map<string, number>;
	storageReservedBytes: number;
	storageReservedEntries: number;
	storageReservedInodes: number;
}

interface OwnerClaim {
	version: 1;
	nonce: string;
	pid: number;
	startTime: string;
	bootId: string;
}

function contract(fault: FaultState): IncidentRecorderWriterLifecycleAdmissionContract {
	return {
		activationGenerationDigest: "e".repeat(64),
		revalidateActivation: () => ({ state: "valid" }),
		acquireCas: (proof, target) => {
			const admission = acquireIncidentRecorderNamespaceCas(proof, target);
			if (admission.state !== "acquired" || target !== "namespace") return admission;
			const transaction = admission.transaction;
			return {
				state: "acquired",
				transaction: Object.freeze({
					withRoot: <T>(operation: (root: IncidentCasRootMutation) => T) => transaction.withRoot(operation),
					withNamespace: <T>(operation: (roots: IncidentRecorderNamespaceRoots) => T) =>
						transaction.withNamespace((roots) => {
							const incidents: IncidentCasRootMutation = {
								...roots.incidents,
								hardLink: (source, destination) => {
									roots.incidents.hardLink(source, destination);
									const publicPath = roots.incidents.publicPath(destination);
									if (fault.enabled && !fault.triggered && publicPath.endsWith("page-000000000001.json")) {
										fault.triggered = true;
										throw new Error("successor fixture hard-link fault after durable page link");
									}
								},
							};
							return operation({ recorder: roots.recorder, incidents });
						}),
					release: () => transaction.release(),
				}),
			};
		},
	};
}

function occurrenceId(index: number): string {
	return `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function occurrenceInput(index: number, digest: string, casPath: string, producerId: string, type: string) {
	const occurrence = occurrenceId(index);
	const identity = { runId: RUN_ID, runToken: RUN_TOKEN, producerId, occurrenceId: occurrence };
	const payload = {
		version: 1,
		state: "complete",
		identity,
		source: "successor-fixture",
		type,
		encoding: "binary",
		payloadKind: "exact-bytes",
		terminal: false,
		metadata: { index },
		eventWallTimeMs: String(ANCHOR + index),
		eventMonotonicNs: String(index),
		transportIdentity: { stream: "successor-fixture" },
		wrapperOrder: [String(index)],
		producerOrder: [String(index)],
		cursors: [`successor-cursor-${index}`],
		journalReferences: [],
		cas: {
			algorithm: "sha256",
			digest,
			bytes: 1,
			path: casPath,
			compression: "none",
			resolution: "verified",
		},
		compactionDisposition: "compacted_and_cas_resolved",
		journalCanonicalUntilCompactionCommit: true,
	};
	const identityKey = createHash("sha256")
		.update(`${RUN_ID}\0${RUN_TOKEN}\0${producerId}\0${occurrence}`)
		.digest("hex");
	return {
		idempotencyKey: `occurrence:${identityKey}`,
		runId: RUN_ID,
		sourceId: "occurrence",
		observedAtMs: Number(payload.eventWallTimeMs),
		order: String(index),
		metadata: { version: 1, state: "complete", occurrenceIdentity: identityKey, casDigest: digest },
		payload: Buffer.from(`${JSON.stringify(payload)}\n`, "utf8"),
	};
}

function publication(agentDir: string) {
	return {
		incidentsDirectory: join(agentDir, "incidents"),
		trigger: {
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			producerId: TRIGGER_PRODUCER_ID,
			occurrenceId: occurrenceId(1),
			acceptedAtWallTimeMs: ANCHOR + 1,
			type: "latency_trigger",
		},
		fence: {
			runId: RUN_ID,
			runToken: RUN_TOKEN,
			producerId: FENCE_PRODUCER_ID,
			occurrenceId: occurrenceId(2),
		},
		classification: { value: "latency", causeLayer: "service" },
	};
}

function readOwner(ownerPath: string): OwnerClaim {
	return JSON.parse(readFileSync(ownerPath, "utf8")) as OwnerClaim;
}

function treeHash(root: string): string {
	const entries: string[] = [];
	const visit = (directory: string, prefix: string): void => {
		for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
			left.name.localeCompare(right.name),
		)) {
			const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
			const path = join(directory, entry.name);
			if (entry.isDirectory()) {
				entries.push(`directory:${relative}`);
				visit(path, relative);
			} else entries.push(`file:${relative}:${readFileSync(path).toString("base64")}`);
		}
	};
	visit(root, "");
	return createHash("sha256")
		.update(`${entries.join("\n")}\n`, "utf8")
		.digest("hex");
}

function storageSnapshot(recorderDirectory: string, incidentsDirectory: string) {
	const result = spawnSync("find", [recorderDirectory, incidentsDirectory, "-xdev", "-printf", "%D\t%i\t%s\t%b\n"], {
		encoding: "utf8",
	});
	if (result.error || result.status !== 0) throw result.error ?? new Error(`find exited ${result.status}`);
	const inodes = new Set<string>();
	let bytes = 0;
	let entries = 0;
	for (const line of String(result.stdout).split("\n")) {
		if (!line) continue;
		const match = /^(\d+)\t(\d+)\t(\d+)\t(\d+)$/.exec(line);
		if (!match) throw new Error(`malformed storage scan line: ${line}`);
		entries += 1;
		const identity = `${match[1]}:${match[2]}`;
		if (inodes.has(identity)) continue;
		inodes.add(identity);
		bytes += Math.max(Number(match[3]), Number(match[4]) * 512);
	}
	return { bytes, entries, inodes: inodes.size };
}

function internals(compactor: IncidentRecorderCompactor): CompactorInternals {
	return compactor as unknown as CompactorInternals;
}

function writeExecutable(path: string, body: string): void {
	writeFileSync(path, `#!${process.execPath}\n${body}\n`, { mode: 0o700 });
	chmodSync(path, 0o700);
}

function writeJournalFixtures(binDir: string): void {
	writeExecutable(
		join(binDir, "systemd-cat"),
		'process.stdin.resume(); process.stdin.on("end", () => process.exit(0)); process.on("SIGTERM", () => process.exit(0)); setInterval(() => {}, 1000);',
	);
	writeExecutable(
		join(binDir, "journalctl"),
		'if (process.argv.includes("--follow")) { process.on("SIGTERM", () => process.exit(0)); setInterval(() => {}, 1000); } else process.exit(0);',
	);
}

async function contender(agentDir: string): Promise<void> {
	const admission = acquireIncidentRecorderWriterNormalLease(
		{ agentDir },
		contract({ enabled: false, triggered: false }),
	);
	if (admission.state !== "acquired") {
		process.stdout.write(`${JSON.stringify(admission)}\n`);
		return;
	}
	const lease = admission.lease;
	try {
		const compactor = new IncidentRecorderCompactor({
			agentDir,
			freeReserveBytes: 0,
			writerLifecycleLease: () => lease,
		});
		await compactor.initializeStorageAccounting(new AbortController().signal);
		const page = compactor.readLiveRunEvents({ runId: RUN_ID });
		process.stdout.write(
			`${JSON.stringify({
				state: page.state === "incomplete" ? "unavailable" : "opened",
				reason: page.reason,
				pageState: page.state,
			})}\n`,
		);
		await compactor.closeWriterResourcesForLifecycle(5_000);
	} finally {
		lease.release();
	}
}

async function seed(agentDir: string): Promise<void> {
	const fault = { enabled: false, triggered: false };
	const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, contract(fault));
	if (admission.state !== "acquired") throw new Error(`seed lifecycle admission unavailable: ${admission.reason}`);
	const lease = admission.lease;
	let seedError: unknown;
	try {
		const compactor = new IncidentRecorderCompactor({
			agentDir,
			freeReserveBytes: 0,
			writerLifecycleLease: () => lease,
		});
		await compactor.initializeStorageAccounting(new AbortController().signal);
		const casValue = Buffer.from("x");
		const digest = createHash("sha256").update(casValue).digest("hex");
		const casDirectory = join(agentDir, "incident-recorder", "cas", "sha256", digest.slice(0, 2));
		const casPath = join(casDirectory, `${digest}.blob`);
		mkdirSync(casDirectory, { recursive: true, mode: 0o700 });
		writeFileSync(casPath, casValue, { mode: 0o600 });
		const target = internals(compactor);
		target.appendSegmentRecord(occurrenceInput(1, digest, casPath, TRIGGER_PRODUCER_ID, "latency_trigger"));
		target.appendSegmentRecord(
			occurrenceInput(2, digest, casPath, FENCE_PRODUCER_ID, "live_incident_high_water_fence"),
		);
		await compactor.closeWriterResourcesForLifecycle(5_000);
	} catch (error) {
		seedError = error;
	}
	const released = lease.release();
	if (seedError !== undefined) throw seedError;
	if (released.state !== "released") throw new Error("seed lifecycle lease did not release");
}

async function spawnContender(agentDir: string): Promise<Record<string, unknown>> {
	const script = fileURLToPath(import.meta.url);
	const loader = fileURLToPath(new URL("../../../../node_modules/tsx/dist/loader.mjs", import.meta.url));
	const child = spawn(process.execPath, ["--import", loader, script, "contender", agentDir], {
		stdio: ["ignore", "pipe", "pipe"],
	});
	let stdout = "";
	let stderr = "";
	child.stdout?.setEncoding("utf8");
	child.stderr?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => (stdout += chunk));
	child.stderr?.on("data", (chunk: string) => (stderr += chunk));
	const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
		child.once("error", reject);
		child.once("close", (code, signal) => resolve({ code, signal }));
	});
	if (exit.code !== 0 || exit.signal !== null) throw new Error(`contender failed: ${JSON.stringify(exit)} ${stderr}`);
	return { ...(JSON.parse(stdout.trim()) as Record<string, unknown>), pid: child.pid };
}

async function runA(agentDir: string): Promise<void> {
	await seed(agentDir);
	const binDir = join(agentDir, "..", "successor-bin");
	mkdirSync(binDir, { recursive: true, mode: 0o700 });
	writeJournalFixtures(binDir);
	const previousPath = process.env.PATH;
	process.env.PATH = `${binDir}:${previousPath ?? ""}`;
	const fault = { enabled: true, triggered: false };
	const originalRun = IncidentRecorderCompactor.prototype.run;
	let contenderResult: Record<string, unknown> | undefined;
	let stagedPagePath: string | undefined;
	let faultedCompactor: IncidentRecorderCompactor | undefined;
	IncidentRecorderCompactor.prototype.run = async function (this: IncidentRecorderCompactor, options) {
		const originalAdmission = options.onNormalWriterAdmission;
		return originalRun.call(this, {
			...options,
			onNormalWriterAdmission: async () => {
				const admitted = originalAdmission ? await originalAdmission() : false;
				if (admitted) {
					faultedCompactor = this;
					this.readLiveRunEvents({ runId: RUN_ID });
					const result = this.publishLiveIncidentObservation(publication(agentDir));
					if (result.state !== "uncertain") throw new Error(`faulted publication was ${result.state}`);
					stagedPagePath = join(
						agentDir,
						"incidents",
						`.${result.incidentId}.partial-${result.publicationId}`,
						"evidence",
						"page-000000000001.json",
					);
					contenderResult = await spawnContender(agentDir);
				}
				return admitted;
			},
		});
	};
	try {
		const notifications: string[][] = [];
		let serviceError: unknown;
		try {
			await runIncidentRecorderService(agentDir, {
				writerLifecycleContract: contract(fault),
				journalctlPath: join(binDir, "journalctl"),
				notify: (fields) => notifications.push([...fields]),
				writerStopDeadlineMs: 5_000,
			});
		} catch (error) {
			serviceError = error;
		}
		const ownerPath = join(agentDir, "incident-recorder", "segments", ".writer-owner.json");
		if (!(serviceError instanceof Error)) throw new Error("faulted service unexpectedly completed");
		if (!existsSync(ownerPath) || !stagedPagePath || !existsSync(stagedPagePath))
			throw new Error(
				`faulted service did not preserve owner and staged page: ${JSON.stringify({
					serviceError: {
						name: serviceError.name,
						message: serviceError.message,
						reason: (serviceError as Error & { reason?: unknown }).reason,
					},
					fault,
					ownerExists: existsSync(ownerPath),
					stagedPagePath,
					stagedExists: stagedPagePath ? existsSync(stagedPagePath) : false,
				})}`,
			);
		const owner = readOwner(ownerPath);
		const pageStat = statSync(stagedPagePath);
		if (!faultedCompactor) throw new Error("faulted compactor instance was not captured");
		const faulted = internals(faultedCompactor);
		process.stdout.write(
			JSON.stringify({
				role: "A",
				pid: process.pid,
				owner,
				ownerLiveInProcess: getProcessStartId(owner.pid) !== undefined,
				serviceError: {
					name: serviceError.name,
					message: serviceError.message,
					reason: (serviceError as Error & { reason?: unknown }).reason,
				},
				faultTriggered: fault.triggered,
				contender: contenderResult,
				notifications,
				stagedPage: {
					path: stagedPagePath,
					nlink: pageStat.nlink,
					sha256: createHash("sha256").update(readFileSync(stagedPagePath)).digest("hex"),
					temporaryCount: readdirSync(join(stagedPagePath, ".."), { withFileTypes: true }).filter((entry) =>
						entry.name.startsWith(".live-observation-page.tmp-"),
					).length,
				},
				accounting: {
					storageAccountingReady: faultedCompactor.storageAccountingReady,
					storageMode: faultedCompactor.storageMode,
					reservations: {
						bytes: faulted.storageReservedBytes,
						entries: faulted.storageReservedEntries,
						inodes: faulted.storageReservedInodes,
					},
				},
			}),
		);
		process.stderr.write(`${serviceError.name}: ${serviceError.message}\n`);
		process.exitCode = 1;
	} finally {
		IncidentRecorderCompactor.prototype.run = originalRun;
		if (previousPath === undefined) delete process.env.PATH;
		else process.env.PATH = previousPath;
	}
}

async function runB(agentDir: string): Promise<void> {
	const fault = { enabled: false, triggered: false };
	const ownerPath = join(agentDir, "incident-recorder", "segments", ".writer-owner.json");
	const staleOwner = readOwner(ownerPath);
	const staleOwnerLive = getProcessStartId(staleOwner.pid) !== undefined;
	const admission = acquireIncidentRecorderWriterNormalLease({ agentDir }, contract(fault));
	if (admission.state !== "acquired")
		throw new Error(`successor lifecycle admission unavailable: ${admission.reason}`);
	const lease = admission.lease;
	try {
		const compactor = new IncidentRecorderCompactor({
			agentDir,
			freeReserveBytes: 0,
			writerLifecycleLease: () => lease,
		});
		await compactor.initializeStorageAccounting(new AbortController().signal);
		const first = compactor.publishLiveIncidentObservation(publication(agentDir));
		if (first.state !== "published")
			throw new Error(
				`successor publication was ${first.state}: ${JSON.stringify({
					result: first,
					storageAccountingReady: compactor.storageAccountingReady,
					storageMode: compactor.storageMode,
					storageRecoveryReason: compactor.storageRecoveryReason,
				})}`,
			);
		const firstHash = treeHash(first.artifactPath);
		const second = compactor.publishLiveIncidentObservation(publication(agentDir));
		if (second.state !== "published" || second.noOp !== true)
			throw new Error("successor replay was not an idempotent no-op");
		const secondHash = treeHash(second.artifactPath);
		const evidenceDirectory = join(first.artifactPath, "evidence");
		const pages = readdirSync(evidenceDirectory)
			.filter((name) => /^page-\d{12}\.json$/.test(name))
			.sort()
			.map((name) => JSON.parse(readFileSync(join(evidenceDirectory, name), "utf8")) as { events: unknown[] });
		const events = pages.flatMap((page) => page.events) as Array<{
			identity: { occurrenceId: string; producerId: string };
			occurrenceReference: { kind: string; locator: Record<string, unknown> };
		}>;
		const segmentFiles = [
			...readdirSync(join(agentDir, "incident-recorder", "segments", "sealed")),
			...readdirSync(join(agentDir, "incident-recorder", "segments", "active")),
		].map(
			(name) =>
				statSync(
					join(agentDir, "incident-recorder", "segments", name.includes(".segment") ? "sealed" : "active", name),
				).nlink,
		);
		const controlledResidue = readdirSync(join(agentDir, "incidents")).filter((name) => name.startsWith("."));
		const internal = internals(compactor);
		const actual = storageSnapshot(join(agentDir, "incident-recorder"), join(agentDir, "incidents"));
		const reported = {
			bytes: internal.storageBytes,
			entries: internal.storageEntries,
			inodes: internal.storageInodes.size,
		};
		const ownerAfterOpen = readOwner(ownerPath);
		await compactor.closeWriterResourcesForLifecycle(5_000);
		const released = lease.release();
		if (released.state !== "released") throw new Error("successor lifecycle lease did not release");
		const segmentControlledResidue = readdirSync(join(agentDir, "incident-recorder", "segments")).filter((name) =>
			name.startsWith("."),
		);
		process.stdout.write(
			JSON.stringify({
				role: "B",
				pid: process.pid,
				staleOwner,
				staleOwnerLive,
				ownerAfterOpen,
				ownerAfterCleanup: existsSync(ownerPath),
				first: {
					state: first.state,
					noOp: first.noOp ?? false,
					incidentId: first.incidentId,
					publicationId: first.publicationId,
				},
				second: { state: second.state, noOp: second.noOp ?? false, artifactPath: second.artifactPath },
				artifactTreeHash: { first: firstHash, second: secondHash },
				stagedPageSha256: createHash("sha256")
					.update(readFileSync(join(first.artifactPath, "evidence", "page-000000000001.json")))
					.digest("hex"),
				pages: pages.length,
				eventCount: events.length,
				eventIdentities: events.map((event) => event.identity),
				exactReferences: events.map((event) => ({
					kind: event.occurrenceReference.kind,
					locator: event.occurrenceReference.locator,
				})),
				targetSnapshot: first.observation.targetSnapshot,
				segmentFileNlinks: segmentFiles,
				controlledResidue,
				segmentControlledResidue,
				accounting: {
					reported,
					actual,
					reservations: {
						bytes: internal.storageReservedBytes,
						entries: internal.storageReservedEntries,
						inodes: internal.storageReservedInodes,
					},
				},
			}),
		);
	} finally {
		if (admission.state === "acquired") lease.release();
	}
}

const role = process.argv[2];
const agentDir = process.argv[3];
if (!role || !agentDir) throw new Error("successor fixture requires role and agent directory");
mkdirSync(agentDir, { recursive: true, mode: 0o700 });
mkdirSync(join(agentDir, "incident-recorder"), { recursive: true, mode: 0o700 });
mkdirSync(join(agentDir, "incidents"), { recursive: true, mode: 0o700 });

if (role === "A") await runA(agentDir);
else if (role === "B") await runB(agentDir);
else if (role === "contender") await contender(agentDir);
else throw new Error(`unknown successor fixture role: ${role}`);
