import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, realpathSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import {
	beginIncidentCasV2Cutover,
	INCIDENT_CAS_V2_SERVICE_ENTRYPOINT,
	INCIDENT_CAS_V2_SYSTEMD_UNIT,
	type IncidentCasV2CutoverTarget,
	openIncidentCasV2Activation,
	proveIncidentCasV1Quiescence,
	publishIncidentCasV2,
} from "./incident-recorder-cas-cutover.js";
import { readIncidentRecorderServiceTarget } from "./incident-recorder-service-activation.js";

const BOOTSTRAP_ENTRYPOINT_SUFFIX = "dist/bundle/incident-recorder-bootstrap.js";
const SYSTEMCTL_TIMEOUT_MS = 1_000;
const SYSTEMCTL_MAX_BUFFER_BYTES = 256 * 1024;

export interface IncidentRecorderBootstrapSystemctlOptions {
	readonly encoding: "utf8";
	readonly stdio: ["ignore", "pipe", "pipe"];
	readonly timeout: number;
	readonly maxBuffer: number;
	readonly killSignal: "SIGKILL";
}

export type IncidentRecorderBootstrapSystemctlResult = Pick<SpawnSyncReturns<string>, "status" | "error" | "stderr">;

export type IncidentRecorderBootstrapSystemctl = (
	command: string,
	args: readonly string[],
	options: IncidentRecorderBootstrapSystemctlOptions,
) => IncidentRecorderBootstrapSystemctlResult;

export interface IncidentRecorderBootstrapOptions {
	readonly agentDir: string;
	/** Defaults to the actual executable used by this process. */
	readonly nodePath?: string;
	/** Defaults to the executable entrypoint in process.argv[1]. */
	readonly bootstrapEntrypointPath?: string;
	/** Forwarded only when explicitly supplied; service activation owns defaults. */
	readonly configHomeDir?: string;
	readonly systemctlPath?: string;
	readonly spawnSystemctl?: IncidentRecorderBootstrapSystemctl;
	/** Compatibility with the installer seam used by focused tests. */
	readonly spawnSyncImpl?: IncidentRecorderBootstrapSystemctl;
}

export interface IncidentRecorderBootstrapPaths {
	readonly nodePath: string;
	readonly bootstrapEntrypointPath: string;
	readonly serviceEntrypointPath: string;
	readonly packageRoot: string;
}

class IncidentRecorderBootstrapFailure extends Error {
	constructor(message: string) {
		super(message);
		this.name = "IncidentRecorderBootstrapFailure";
	}
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function canonicalPath(path: string, description: string): string {
	if (!isAbsolute(path) || resolve(path) !== path) {
		throw new IncidentRecorderBootstrapFailure(`${description} must be an absolute canonical path`);
	}
	try {
		return realpathSync.native(path);
	} catch (error) {
		throw new IncidentRecorderBootstrapFailure(`Unable to resolve ${description}: ${errorMessage(error)}`);
	}
}

/** Bind the runner to its own installed bundle and the service beside it. */
export function resolveIncidentRecorderBootstrapPaths(
	options: { nodePath?: string; bootstrapEntrypointPath?: string } = {},
): IncidentRecorderBootstrapPaths {
	const nodePath = canonicalPath(options.nodePath ?? process.execPath, "Node executable");
	const bootstrapPath = canonicalPath(
		options.bootstrapEntrypointPath ?? process.argv[1] ?? "",
		"bootstrap entrypoint",
	);
	const suffix = `/${BOOTSTRAP_ENTRYPOINT_SUFFIX}`;
	if (!bootstrapPath.endsWith(suffix)) {
		throw new IncidentRecorderBootstrapFailure(
			`Bootstrap runner must run from its installed ${BOOTSTRAP_ENTRYPOINT_SUFFIX} entrypoint`,
		);
	}
	try {
		if (!lstatSync(bootstrapPath, { bigint: true }).isFile()) {
			throw new IncidentRecorderBootstrapFailure("Bootstrap entrypoint must be a regular file");
		}
	} catch (error) {
		if (error instanceof IncidentRecorderBootstrapFailure) throw error;
		throw new IncidentRecorderBootstrapFailure(`Bootstrap entrypoint is unavailable: ${errorMessage(error)}`);
	}
	const packageRoot = bootstrapPath.slice(0, -suffix.length);
	if (!packageRoot || packageRoot.endsWith("/")) {
		throw new IncidentRecorderBootstrapFailure("Bootstrap entrypoint is not inside an installed package");
	}
	const serviceEntrypointPath = join(packageRoot, INCIDENT_CAS_V2_SERVICE_ENTRYPOINT);
	const canonicalServicePath = canonicalPath(serviceEntrypointPath, "service entrypoint");
	if (canonicalServicePath !== serviceEntrypointPath) {
		throw new IncidentRecorderBootstrapFailure(
			"Service entrypoint is not the dedicated file in the bootstrap package",
		);
	}
	return Object.freeze({
		nodePath,
		bootstrapEntrypointPath: bootstrapPath,
		serviceEntrypointPath,
		packageRoot,
	});
}

function currentUid(): number | undefined {
	return typeof process.getuid === "function" ? process.getuid() : undefined;
}

function isPrivateDirectory(path: string): boolean {
	try {
		const stat = lstatSync(path, { bigint: true });
		if (!stat.isDirectory() || stat.isSymbolicLink()) return false;
		const uid = currentUid();
		if (uid !== undefined && stat.uid !== BigInt(uid)) return false;
		return (stat.mode & 0o022n) === 0n && realpathSync.native(path) === path;
	} catch {
		return false;
	}
}

function ensurePrivateDirectory(path: string): void {
	try {
		lstatSync(path, { bigint: true });
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		mkdirSync(path, { recursive: true, mode: 0o700 });
	}
	if (!isPrivateDirectory(path)) {
		throw new IncidentRecorderBootstrapFailure(`Incident recorder namespace is not a private directory: ${path}`);
	}
}

function ensureIncidentRecorderNamespaces(agentDir: string): void {
	ensurePrivateDirectory(agentDir);
	ensurePrivateDirectory(join(agentDir, "incident-recorder"));
	ensurePrivateDirectory(join(agentDir, "incidents"));
}

function systemctlOptions(): IncidentRecorderBootstrapSystemctlOptions {
	return {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
		timeout: SYSTEMCTL_TIMEOUT_MS,
		maxBuffer: SYSTEMCTL_MAX_BUFFER_BYTES,
		killSignal: "SIGKILL",
	};
}

function runSystemctl(
	options: IncidentRecorderBootstrapOptions,
	args: readonly string[],
): IncidentRecorderBootstrapSystemctlResult {
	const run =
		options.spawnSystemctl ??
		options.spawnSyncImpl ??
		((command, commandArgs, spawnOptions) => spawnSync(command, commandArgs, spawnOptions));
	return run(options.systemctlPath ?? "systemctl", args, systemctlOptions());
}

function requireSystemctlSuccess(result: IncidentRecorderBootstrapSystemctlResult, action: string): void {
	if (result.error || result.status !== 0) {
		throw new IncidentRecorderBootstrapFailure(
			`systemd ${action} failed${result.stderr ? `: ${result.stderr.trim()}` : ""}`,
		);
	}
}

function stopRecorder(options: IncidentRecorderBootstrapOptions): void {
	requireSystemctlSuccess(runSystemctl(options, ["--user", "stop", INCIDENT_CAS_V2_SYSTEMD_UNIT]), "recorder stop");
}

function queueRecorderStart(options: IncidentRecorderBootstrapOptions): void {
	requireSystemctlSuccess(
		runSystemctl(options, ["--user", "--no-block", "start", INCIDENT_CAS_V2_SYSTEMD_UNIT]),
		"recorder start",
	);
}

function ensureNormalServiceStarted(options: IncidentRecorderBootstrapOptions): void {
	const active = runSystemctl(options, ["--user", "is-active", "--quiet", INCIDENT_CAS_V2_SYSTEMD_UNIT]);
	if (active.error || active.status === null || active.status === undefined) {
		throw new IncidentRecorderBootstrapFailure(
			`systemd recorder status check failed${active.stderr ? `: ${active.stderr.trim()}` : ""}`,
		);
	}
	if (active.status === 0) return;
	queueRecorderStart(options);
}

function readTarget(
	options: IncidentRecorderBootstrapOptions,
	paths: IncidentRecorderBootstrapPaths,
): IncidentCasV2CutoverTarget {
	return readIncidentRecorderServiceTarget({
		nodePath: paths.nodePath,
		entrypointPath: paths.serviceEntrypointPath,
		agentDir: options.agentDir,
		...(options.configHomeDir === undefined ? {} : { configHomeDir: options.configHomeDir }),
	});
}

/** Execute exactly one bounded bootstrap attempt. Failures leave CAS state for a later timer run. */
export function runIncidentRecorderBootstrap(options: IncidentRecorderBootstrapOptions): void {
	const paths = resolveIncidentRecorderBootstrapPaths(options);
	const target = readTarget(options, paths);
	ensureIncidentRecorderNamespaces(options.agentDir);

	const begun = beginIncidentCasV2Cutover(target);
	if (begun.state === "unavailable") {
		throw new IncidentRecorderBootstrapFailure(`recorder cutover unavailable: ${begun.reason}`);
	}
	if (begun.state === "v2") {
		ensureNormalServiceStarted(options);
		return;
	}

	try {
		stopRecorder(options);
		const proof = proveIncidentCasV1Quiescence(begun.cutover);
		if (proof.state === "unavailable") {
			throw new IncidentRecorderBootstrapFailure(`recorder quiescence unavailable: ${proof.reason}`);
		}
		const published = publishIncidentCasV2(begun.cutover, proof.witness);
		if (published.state === "unavailable") {
			throw new IncidentRecorderBootstrapFailure(`recorder cutover publication unavailable: ${published.reason}`);
		}
	} finally {
		begun.cutover.close();
	}

	const opened = openIncidentCasV2Activation(target);
	if (opened.state !== "active") {
		throw new IncidentRecorderBootstrapFailure(`recorder activation unavailable: ${opened.reason}`);
	}
	opened.activation.close();
	queueRecorderStart(options);
}

export { BOOTSTRAP_ENTRYPOINT_SUFFIX, SYSTEMCTL_MAX_BUFFER_BYTES, SYSTEMCTL_TIMEOUT_MS };
