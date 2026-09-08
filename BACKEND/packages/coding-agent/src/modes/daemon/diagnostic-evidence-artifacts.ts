import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, realpath, statfs, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { DiagnosticEvidenceStore } from "./diagnostic-evidence-store.js";
import type { EvidenceFileIdentity, EvidenceOperation } from "./diagnostic-evidence-store-protocol.js";

export interface DiagnosticArtifactOptions {
	store: DiagnosticEvidenceStore;
	root: string;
	/** Returns provider-native bytes. It must honor cancellation without killing the producer. */
	exportArtifact: (operation: EvidenceOperation, signal: AbortSignal) => AsyncIterable<Uint8Array>;
	maxArtifactBytes?: number;
	/** Remaining admitted storage, after the native history and free-space reserve. */
	availableBytes?: (operation: EvidenceOperation) => Promise<number>;
	operationTimeoutMs?: number;
	/** Limits comparison work per operation per maintenance pass; the cursor survives restart. */
	maxReuseCandidatesPerPass?: number;
}

export interface DiagnosticArtifactResult {
	completed: number;
	pending: number;
	failures: { id: string; error: string }[];
	/** Continue after this ID, including failed operations, to avoid retry starvation. */
	nextId?: string;
}

async function syncDirectory(path: string): Promise<void> {
	const directory = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
	try {
		await directory.sync();
	} finally {
		await directory.close();
	}
}

async function durableDirectory(path: string): Promise<void> {
	const firstCreated = await mkdir(path, { recursive: true, mode: 0o700 });
	if (!(await lstat(path)).isDirectory() || (await realpath(path)) !== path)
		throw new Error("artifact_directory: symlink or non-directory");
	// Persist every newly created directory entry, up through its existing parent.
	const boundary = dirname(firstCreated ?? path);
	let current = path;
	for (;;) {
		await syncDirectory(current);
		if (current === boundary) break;
		current = dirname(current);
	}
}

async function exists(path: string): Promise<boolean> {
	try {
		await lstat(path);
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw error;
	}
}

/** SQLite owns operation state; rename/fsync own files. Pending operations bridge the two. */
export class DiagnosticArtifactOperations {
	private running = false;
	private constructor(private readonly options: DiagnosticArtifactOptions) {}

	static async open(options: DiagnosticArtifactOptions): Promise<DiagnosticArtifactOperations> {
		const root = resolve(options.root);
		await durableDirectory(root);
		if (!Number.isSafeInteger(options.maxArtifactBytes ?? 256 * 1024 * 1024) || (options.maxArtifactBytes ?? 1) < 1)
			throw new Error("artifact_budget: invalid maximum");
		if (!Number.isInteger(options.maxReuseCandidatesPerPass ?? 8) || (options.maxReuseCandidatesPerPass ?? 8) < 1 || (options.maxReuseCandidatesPerPass ?? 8) > 64)
			throw new Error("artifact_candidate_limit");
		return new DiagnosticArtifactOperations({ ...options, root });
	}

	/** Bounded restart work comes exclusively from SQL, never a recursive history scan. */
	async reconcile(
		options: { limit?: number; afterId?: string; signal?: AbortSignal } = {},
	): Promise<DiagnosticArtifactResult> {
		if (this.running) throw new Error("artifact_operations_busy");
		this.running = true;
		try {
			const limit = options.limit ?? 32;
			if (!Number.isInteger(limit) || limit < 1 || limit > 256) throw new Error("artifact_operation_limit");
			const operations = await this.options.store.unfinishedOperations({ limit, afterId: options.afterId });
			const result: DiagnosticArtifactResult = { completed: 0, pending: operations.length, failures: [] };
			for (const operation of operations) {
				if (options.signal?.aborted) break;
				const timeout = AbortSignal.timeout(this.options.operationTimeoutMs ?? 30_000);
				const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;
				try {
					if (await this.execute(operation, signal)) {
						result.completed += 1;
						result.pending -= 1;
					}
				} catch (error) {
					result.failures.push({
						id: operation.id,
						error: String(error instanceof Error ? error.message : error).slice(0, 1024),
					});
				}
				if (operations.length === limit) result.nextId = operation.id;
			}
			return result;
		} finally {
			this.running = false;
		}
	}

	private async artifactPath(path: string): Promise<string> {
		if (
			!path ||
			isAbsolute(path) ||
			path.includes("\\") ||
			path.split("/").some((part) => !part || part === "." || part === "..")
		)
			throw new Error("artifact_path: invalid relative path");
		const target = resolve(this.options.root, path);
		if (relative(this.options.root, target).startsWith(`..${sep}`) || target === this.options.root)
			throw new Error("artifact_path: outside root");
		let directory = this.options.root;
		for (const part of path.split("/").slice(0, -1)) {
			directory = join(directory, part);
			await durableDirectory(directory);
		}
		return target;
	}

	private async verifyStaged(path: string, operation: EvidenceOperation, signal: AbortSignal): Promise<EvidenceFileIdentity | undefined> {
		if (!(await exists(path))) return undefined;
		const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
		try {
			const stat = await file.stat({ bigint: true });
			if (!stat.isFile() || stat.size !== BigInt(operation.artifact.bytes!))
				throw new Error("artifact_identity_conflict: preserved existing file");
			const hash = createHash("sha256");
			const buffer = Buffer.allocUnsafe(64 * 1024);
			let bytes = 0;
			for (;;) {
				signal.throwIfAborted();
				const read = await file.read(buffer, 0, buffer.length, null);
				if (!read.bytesRead) break;
				bytes += read.bytesRead;
				if (BigInt(bytes) > stat.size) throw new Error("artifact_identity_conflict: preserved growing file");
				hash.update(buffer.subarray(0, read.bytesRead));
			}
			if (bytes !== operation.artifact.bytes || hash.digest("hex") !== operation.artifact.sha256)
				throw new Error("artifact_identity_conflict: preserved existing file");
			const after = await file.stat({ bigint: true });
			if (stat.mtimeNs !== after.mtimeNs || stat.ctimeNs !== after.ctimeNs || stat.size !== after.size)
				throw new Error("artifact_identity_conflict: preserved changing file");
			await file.sync();
			return { device: String(stat.dev), inode: String(stat.ino), size: Number(stat.size), mtimeNs: String(stat.mtimeNs) };
		} finally {
			await file.close();
		}
	}

	private sameIdentity(left: EvidenceFileIdentity, right: EvidenceFileIdentity): boolean {
		return left.device === right.device && left.inode === right.inode && left.size === right.size && left.mtimeNs === right.mtimeNs;
	}

	private async exactCandidate(pending: string, candidate: string, expected: EvidenceFileIdentity, signal: AbortSignal): Promise<EvidenceFileIdentity | undefined> {
		const left = await open(pending, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
		try {
			const right = await open(candidate, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
			try {
				const a = await left.stat({ bigint: true });
				const b = await right.stat({ bigint: true });
				const identity = (s: typeof a): EvidenceFileIdentity => ({ device: String(s.dev), inode: String(s.ino), size: Number(s.size), mtimeNs: String(s.mtimeNs) });
				if (!a.isFile() || !b.isFile() || !this.sameIdentity(identity(a), expected) || a.size !== b.size)
					throw new Error("artifact_candidate_unavailable: file identity changed");
				if (a.dev !== b.dev) throw new Error("artifact_candidate_unavailable: different filesystem");
				const aBytes = Buffer.allocUnsafe(64 * 1024);
				const bBytes = Buffer.allocUnsafe(64 * 1024);
				let equal = true;
				for (let offset = 0; offset < expected.size;) {
					signal.throwIfAborted();
					const count = Math.min(aBytes.length, expected.size - offset);
					for (const [file, buffer] of [[left, aBytes], [right, bBytes]] as const) {
						let copied = 0;
						while (copied < count) {
							signal.throwIfAborted();
							const read = await file.read(buffer, copied, count - copied, offset + copied);
							if (!read.bytesRead) throw new Error("artifact_candidate_unavailable: file shortened");
							copied += read.bytesRead;
						}
					}
					if (!aBytes.subarray(0, count).equals(bBytes.subarray(0, count))) { equal = false; break; }
					offset += count;
				}
				const afterA = await left.stat({ bigint: true });
				const afterB = await right.stat({ bigint: true });
				const pathA = await lstat(pending, { bigint: true });
				const pathB = await lstat(candidate, { bigint: true });
				if (a.ctimeNs !== afterA.ctimeNs || b.ctimeNs !== afterB.ctimeNs || !this.sameIdentity(identity(a), identity(afterA)) || !this.sameIdentity(identity(b), identity(afterB)) || !pathA.isFile() || !pathB.isFile() || !this.sameIdentity(identity(a), identity(pathA)) || !this.sameIdentity(identity(b), identity(pathB)))
					throw new Error("artifact_candidate_unavailable: file changed during comparison");
				return equal ? identity(b) : undefined;
			} finally { await right.close(); }
		} finally { await left.close(); }
	}

	private async finishStaged(operation: EvidenceOperation, target: string, pending: string, signal: AbortSignal): Promise<boolean> {
		let current = operation;
		const finalIdentity = await this.verifyStaged(target, current, signal);
		const pendingIdentity = await this.verifyStaged(pending, current, signal);
		if (pendingIdentity && current.stagingIdentity && !this.sameIdentity(pendingIdentity, current.stagingIdentity))
			throw new Error("artifact_identity_conflict: preserved replacement staging file");
		if (!current.selection) {
			if (finalIdentity) throw new Error("artifact_identity_unavailable: preserved unselected final file");
			if (!pendingIdentity) throw new Error("artifact_staged_bytes_unavailable: provider replay refused");
			for (let attempt = 0; attempt < (this.options.maxReuseCandidatesPerPass ?? 8); attempt++) {
				signal.throwIfAborted();
				current = await this.options.store.selectArtifactCandidate(current.id);
				if (current.candidatesExhausted) {
					current = await this.options.store.selectArtifactContent(current.id, { kind: "unique", identity: pendingIdentity });
					break;
				}
				const candidate = current.candidate!;
				let identity: EvidenceFileIdentity | undefined;
				let limitation: string | undefined;
				try {
					identity = await this.exactCandidate(pending, await this.artifactPath(candidate.path), pendingIdentity, signal);
				} catch (error) {
					signal.throwIfAborted();
					limitation = `Candidate ${candidate.id}: ${String(error instanceof Error ? error.message : error)}`.slice(0, 512);
				}
				if (identity) {
					current = await this.options.store.selectArtifactContent(current.id, { kind: "reuse", identity });
					break;
				}
				current = await this.options.store.rejectArtifactCandidate(current.id, candidate.id, limitation);
			}
			if (!current.selection) return false;
		}
		const selected = current.selection.identity;
		if (finalIdentity && !this.sameIdentity(finalIdentity, selected))
			throw new Error("artifact_identity_conflict: preserved unrelated final file");
		if (!finalIdentity) {
			const source = current.selection.kind === "reuse" ? await this.artifactPath(current.candidate!.path) : pending;
			const identity = await this.verifyStaged(source, current, signal);
			if (!identity || !this.sameIdentity(identity, selected)) throw new Error("artifact_selection_unavailable: preserved staging evidence");
			await link(source, target);
			await syncDirectory(dirname(target));
			const published = await this.verifyStaged(target, current, signal);
			if (!published || !this.sameIdentity(published, selected)) throw new Error("artifact_identity_conflict: published alias changed");
		}
		if (pendingIdentity) await unlink(pending);
		await syncDirectory(dirname(target));
		await this.options.store.markOperationReady(current.id);
		return true;
	}

	private async execute(operation: EvidenceOperation, signal: AbortSignal): Promise<boolean> {
		signal.throwIfAborted();
		const target = await this.artifactPath(operation.artifact.path);
		if (operation.kind === "delete") {
			await unlink(target).catch((error: NodeJS.ErrnoException) => {
				if (error.code !== "ENOENT") throw error;
			});
			await syncDirectory(dirname(target));
			await this.options.store.markOperationReady(operation.id);
			return true;
		}
		const suffix = createHash("sha256").update(operation.id).digest("hex").slice(0, 24);
		const pending = `${target}.pending-${suffix}`;
		if (operation.stagedAtMs !== undefined) {
			return this.finishStaged(operation, target, pending, signal);
		}
		if (await exists(target)) throw new Error("artifact_identity_unavailable: preserved unacknowledged final file");
		const available = this.options.availableBytes
			? await this.options.availableBytes(operation)
			: Number.MAX_SAFE_INTEGER;
		const allocationUnit = (await statfs(this.options.root)).bsize;
		const budget = Math.min(
			this.options.maxArtifactBytes ?? 256 * 1024 * 1024,
			Math.floor(available / allocationUnit) * allocationUnit,
		);
		if (!Number.isFinite(budget) || budget < 1) throw new Error("artifact_budget: no admitted capacity");
		// Unstarted operations reserve no space. Persist this allocation before a write
		// can create bytes that must be accounted for after a recorder crash.
		await this.options.store.reserveOperationBytes(
			operation.id,
			Math.max(operation.reservationBytes, Math.ceil(budget / allocationUnit) * allocationUnit),
		);
		const file = await open(
			pending,
			constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
			0o600,
		);
		const hash = createHash("sha256");
		let bytes = 0;
		let failure: unknown;
		let allocatedBytes = 0;
		let fileIdentity: EvidenceFileIdentity | undefined;
		try {
			for await (const chunk of this.options.exportArtifact(operation, signal)) {
				signal.throwIfAborted();
				if (chunk.byteLength > budget - bytes) throw new Error("artifact_budget: export exceeds admitted capacity");
				let offset = 0;
				while (offset < chunk.byteLength) {
					const written = await file.write(chunk, offset, chunk.byteLength - offset);
					if (written.bytesWritten === 0) throw new Error("artifact_write: no progress");
					offset += written.bytesWritten;
				}
				bytes += chunk.byteLength;
				hash.update(chunk);
			}
			signal.throwIfAborted();
			await file.sync();
			const stat = await file.stat({ bigint: true });
			allocatedBytes = Math.max(Number(stat.size), Number(stat.blocks) * 512);
			fileIdentity = { device: String(stat.dev), inode: String(stat.ino), size: Number(stat.size), mtimeNs: String(stat.mtimeNs) };
		} catch (error) {
			failure = error;
		} finally {
			await file.close();
		}
		if (failure !== undefined) {
			// This attempt never completed the provider stream. Remove only its known
			// incomplete staging file, then release capacity after the deletion is durable.
			await unlink(pending);
			await syncDirectory(dirname(pending));
			await this.options.store.releaseOperationReservation(operation.id);
			throw failure;
		}
		// A durable filename and complete byte identity must precede publication.
		// Recovery uses these captured bytes even if the native provider has since vacuumed.
		await syncDirectory(dirname(pending));
		const staged = await this.options.store.markOperationStaged(operation.id, {
			bytes,
			sha256: hash.digest("hex"),
			allocatedBytes,
			fileIdentity,
		});
		return this.finishStaged(staged, target, pending, signal);
	}
}
