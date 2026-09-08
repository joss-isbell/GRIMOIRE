import { createHash } from "node:crypto";
import { DatabaseSync, type SQLOutputValue } from "node:sqlite";
import { parentPort, workerData } from "node:worker_threads";
import {
	EVIDENCE_BATCH_BYTES,
	EVIDENCE_BATCH_ROWS,
	EVIDENCE_HISTORY_MS,
	EVIDENCE_INCIDENT_MS,
	EVIDENCE_PAGE_ROWS,
	EVIDENCE_RUNTIME_ROLE_LIMIT,
	type EvidenceArtifact,
	type EvidenceArtifactCompletion,
	type EvidenceArtifactSelection,
	type EvidenceBatch,
	type EvidenceChannelResult,
	type EvidenceFileIdentity,
	type EvidenceIncident,
	type EvidenceIncidentInput,
	type EvidenceIncidentUpdate,
	type EvidenceListOptions,
	type EvidenceOccurrence,
	type EvidenceOperation,
	type EvidenceOperationInput,
	type EvidencePage,
	type EvidenceReference,
	type EvidenceRuntimeBoot,
	type EvidenceRuntimeClaimResult,
	type EvidenceRuntimeExitResult,
	type EvidenceRuntimeProvider,
	type EvidenceRuntimeRole,
	type EvidenceWindow,
	type EvidenceWorkerRequest,
} from "./diagnostic-evidence-store-protocol.js";
import { journalReplayIdentity } from "./diagnostic-journal-replay.js";
import { kernelChannelObservation } from "./diagnostic-kernel-channel.js";
import {
	runtimeExitFromOccurrence,
	runtimeRoleFromOccurrence,
	validRuntimeClock,
} from "./diagnostic-runtime-identity.js";

type Row = Record<string, SQLOutputValue>;
const RUNTIME_BOOT_SOURCE = "internal:runtime-current-boot-v1";
const port = parentPort!;
const db = new DatabaseSync((workerData as { path: string }).path, { timeout: 250 });
const sqliteVersion = String(db.prepare("SELECT sqlite_version() AS version").get()!.version);
const [major, minor, patch] = sqliteVersion.split(".").map(Number);
if (major < 3 || (major === 3 && (minor < 51 || (minor === 51 && patch < 3)))) {
	db.close();
	throw new Error(`SQLite ${sqliteVersion} is unsupported: require >=3.51.3 for WAL reset fix`);
}
const version = Number(db.prepare("PRAGMA user_version").get()!.user_version);
if (version !== 0 && version !== 8)
	throw new Error("unsupported_evidence_schema_capacity; use a fresh database, no migration performed");
if (version === 0) {
	if (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1").get())
		throw new Error("evidence_database_not_empty");
	db.exec("PRAGMA auto_vacuum=INCREMENTAL");
}
db.exec(
	"PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA cache_size=-8192; PRAGMA busy_timeout=250; PRAGMA temp_store=FILE;",
);
if (
	db.prepare("PRAGMA journal_mode").get()!.journal_mode !== "wal" ||
	db.prepare("PRAGMA synchronous").get()!.synchronous !== 2 ||
	db.prepare("PRAGMA foreign_keys").get()!.foreign_keys !== 1
)
	throw new Error("evidence_database_durability_unavailable");
if (db.prepare("PRAGMA auto_vacuum").get()!.auto_vacuum !== 2)
	throw new Error("unsupported_evidence_capacity; incremental vacuum required");
if (version === 0) {
	if (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1").get())
		throw new Error("evidence_database_not_empty");
	db.exec(`BEGIN IMMEDIATE;
CREATE TABLE sources (source TEXT PRIMARY KEY, cursor TEXT NOT NULL) STRICT;
CREATE TABLE payloads (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT NOT NULL, bytes BLOB NOT NULL, ref_count INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE INDEX payload_hash ON payloads(hash);
CREATE INDEX payload_unreferenced ON payloads(ref_count,id);
CREATE TABLE occurrences (sequence INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, id TEXT NOT NULL, wall_time_ms INTEGER NOT NULL, monotonic_ns TEXT, kind TEXT NOT NULL, payload_id INTEGER NOT NULL REFERENCES payloads(id), UNIQUE(source,id)) STRICT;
CREATE INDEX occurrence_window ON occurrences(wall_time_ms,sequence);
CREATE INDEX occurrence_causal_window ON occurrences(wall_time_ms,sequence) WHERE kind IN ('journal.json','diagnostic.gap','evidence.gap');
CREATE INDEX occurrence_payload ON occurrences(payload_id);
CREATE TABLE retention_progress (id INTEGER PRIMARY KEY CHECK(id=1), wall_time_ms INTEGER NOT NULL, sequence INTEGER NOT NULL) STRICT;
INSERT INTO retention_progress VALUES(1,0,0);
CREATE TABLE receipts (sequence INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT NOT NULL UNIQUE, source TEXT NOT NULL, expected_cursor TEXT, cursor TEXT NOT NULL, ids TEXT NOT NULL, digest TEXT NOT NULL, inserted INTEGER NOT NULL, created_at_ms INTEGER NOT NULL) STRICT;
CREATE INDEX receipt_age ON receipts(created_at_ms);
CREATE TABLE incidents (id TEXT PRIMARY KEY, trigger_time_ms INTEGER NOT NULL, window_start_ms INTEGER NOT NULL, window_end_ms INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('capturing','published','complete','limited')), coverage TEXT NOT NULL, limitations TEXT NOT NULL, created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, evidence_revision INTEGER NOT NULL DEFAULT 1) STRICT;
CREATE INDEX incident_expiry ON incidents(expires_at_ms);
CREATE INDEX incident_window ON incidents(window_start_ms,window_end_ms);
CREATE INDEX incident_runtime_proof ON incidents(json_extract(coverage,'$.runtimeRole.proof.source'),json_extract(coverage,'$.runtimeRole.proof.occurrenceId'));
CREATE TABLE runtime_roles (boot_id TEXT NOT NULL, pid_namespace TEXT NOT NULL, pid INTEGER NOT NULL, start_ticks TEXT NOT NULL, role TEXT NOT NULL, role_instance_id TEXT NOT NULL, clock_ticks INTEGER NOT NULL, proof_sequence INTEGER NOT NULL REFERENCES occurrences(sequence), conflicted INTEGER NOT NULL DEFAULT 0 CHECK(conflicted IN (0,1)), closed_at_ms INTEGER, close_reason TEXT CHECK(close_reason IN ('native_exit','boot_changed')), exit_sequence INTEGER REFERENCES occurrences(sequence), native_pid INTEGER, native_start TEXT, PRIMARY KEY(boot_id,pid_namespace,pid,start_ticks)) STRICT;
CREATE INDEX runtime_role_proof ON runtime_roles(proof_sequence);
CREATE INDEX runtime_role_exit ON runtime_roles(exit_sequence);
CREATE INDEX runtime_role_closed ON runtime_roles(closed_at_ms);
CREATE TABLE kernel_channel_episodes (key TEXT PRIMARY KEY, boot_id TEXT NOT NULL, monotonic_ns TEXT NOT NULL, sequence INTEGER NOT NULL, unavailable INTEGER NOT NULL CHECK(unavailable IN (0,1)), incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL, observed_at_ms INTEGER NOT NULL) STRICT;
CREATE INDEX kernel_channel_inactive ON kernel_channel_episodes(unavailable,observed_at_ms);
CREATE TABLE artifact_contents (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, allocated_bytes INTEGER NOT NULL) STRICT;
CREATE INDEX artifact_content_candidates ON artifact_contents(sha256,bytes,id);
CREATE TABLE artifacts (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, path TEXT NOT NULL UNIQUE, format TEXT NOT NULL, bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, allocated_bytes INTEGER NOT NULL, content_id INTEGER NOT NULL REFERENCES artifact_contents(id)) STRICT;
CREATE INDEX artifact_incident ON artifacts(incident_id);
CREATE INDEX artifact_content_alias ON artifacts(content_id,id);
CREATE TABLE operations (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, kind TEXT NOT NULL CHECK(kind IN ('export','pin','delete')), artifact_id TEXT NOT NULL, artifact TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','ready')), created_at_ms INTEGER NOT NULL, bytes INTEGER, sha256 TEXT, staged_at_ms INTEGER, allocated_bytes INTEGER, reservation_bytes INTEGER NOT NULL DEFAULT 0, candidate_content_cursor INTEGER NOT NULL DEFAULT 0, candidate_alias_cursor TEXT NOT NULL DEFAULT '', candidate_id TEXT REFERENCES artifacts(id), candidates_exhausted INTEGER NOT NULL DEFAULT 0, selection TEXT, reuse_limitations TEXT NOT NULL DEFAULT '[]', staging_identity TEXT) STRICT;
CREATE INDEX operation_incident ON operations(incident_id,state);
CREATE INDEX operation_pending ON operations(state,id);
CREATE UNIQUE INDEX operation_artifact_pending ON operations(artifact_id) WHERE state='pending';
CREATE UNIQUE INDEX operation_path_pending ON operations(json_extract(artifact,'$.path')) WHERE state='pending';
CREATE INDEX operation_candidate_pin ON operations(candidate_id) WHERE candidate_id IS NOT NULL;
CREATE TABLE counts (id INTEGER PRIMARY KEY CHECK(id=1), occurrences INTEGER NOT NULL, payloads INTEGER NOT NULL, payload_bytes INTEGER NOT NULL, incidents INTEGER NOT NULL, operations INTEGER NOT NULL, artifact_bytes INTEGER NOT NULL, pending_artifact_operations INTEGER NOT NULL, artifact_allocated_bytes INTEGER NOT NULL, reserved_artifact_bytes INTEGER NOT NULL) STRICT;
INSERT INTO counts VALUES(1,0,0,0,0,0,0,0,0,0);
CREATE TRIGGER count_occurrence_insert AFTER INSERT ON occurrences BEGIN UPDATE counts SET occurrences=occurrences+1; UPDATE payloads SET ref_count=ref_count+1 WHERE id=new.payload_id; END;
CREATE TRIGGER causal_input_insert AFTER INSERT ON occurrences WHEN new.kind IN ('journal.json','diagnostic.gap','evidence.gap') BEGIN UPDATE incidents SET evidence_revision=evidence_revision+1 WHERE window_start_ms<=new.wall_time_ms AND window_end_ms>=new.wall_time_ms; END;
CREATE TRIGGER count_occurrence_delete AFTER DELETE ON occurrences BEGIN UPDATE counts SET occurrences=occurrences-1; UPDATE payloads SET ref_count=ref_count-1 WHERE id=old.payload_id; END;
CREATE TRIGGER count_payload_insert AFTER INSERT ON payloads BEGIN UPDATE counts SET payloads=payloads+1,payload_bytes=payload_bytes+length(new.bytes); END;
CREATE TRIGGER count_payload_delete AFTER DELETE ON payloads BEGIN UPDATE counts SET payloads=payloads-1,payload_bytes=payload_bytes-length(old.bytes); END;
CREATE TRIGGER count_incident_insert AFTER INSERT ON incidents BEGIN UPDATE counts SET incidents=incidents+1; END;
CREATE TRIGGER count_incident_delete AFTER DELETE ON incidents BEGIN UPDATE counts SET incidents=incidents-1; END;
CREATE TRIGGER count_operation_insert AFTER INSERT ON operations BEGIN UPDATE counts SET operations=operations+1; END;
CREATE TRIGGER count_operation_delete AFTER DELETE ON operations BEGIN UPDATE counts SET operations=operations-1; END;
CREATE TRIGGER count_artifact_insert AFTER INSERT ON artifacts BEGIN UPDATE counts SET artifact_bytes=artifact_bytes+new.bytes; END;
CREATE TRIGGER count_artifact_delete AFTER DELETE ON artifacts BEGIN UPDATE counts SET artifact_bytes=artifact_bytes-old.bytes; DELETE FROM artifact_contents WHERE id=old.content_id AND NOT EXISTS(SELECT 1 FROM artifacts WHERE content_id=old.content_id); END;
CREATE TRIGGER count_content_insert AFTER INSERT ON artifact_contents BEGIN UPDATE counts SET artifact_allocated_bytes=artifact_allocated_bytes+new.allocated_bytes; END;
CREATE TRIGGER count_content_delete AFTER DELETE ON artifact_contents BEGIN UPDATE counts SET artifact_allocated_bytes=artifact_allocated_bytes-old.allocated_bytes; END;
CREATE TRIGGER count_reservation_update AFTER UPDATE OF reservation_bytes ON operations BEGIN UPDATE counts SET reserved_artifact_bytes=reserved_artifact_bytes+new.reservation_bytes-old.reservation_bytes; END;
CREATE TRIGGER count_reservation_delete AFTER DELETE ON operations BEGIN UPDATE counts SET reserved_artifact_bytes=reserved_artifact_bytes-old.reservation_bytes; END;
CREATE TRIGGER count_pending_insert AFTER INSERT ON operations WHEN new.state='pending' AND new.kind!='delete' BEGIN UPDATE counts SET pending_artifact_operations=pending_artifact_operations+1; END;
CREATE TRIGGER count_pending_ready AFTER UPDATE OF state ON operations WHEN old.state='pending' AND new.state='ready' AND new.kind!='delete' BEGIN UPDATE counts SET pending_artifact_operations=pending_artifact_operations-1; END;
CREATE TRIGGER count_pending_delete AFTER DELETE ON operations WHEN old.state='pending' AND old.kind!='delete' BEGIN UPDATE counts SET pending_artifact_operations=pending_artifact_operations-1; END;
PRAGMA user_version=8; COMMIT;`);
}

function text(value: unknown, name: string, max = 512): asserts value is string {
	if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > max || value.includes("\0"))
		throw new Error(name);
}
function integer(value: unknown, name: string): asserts value is number {
	if (!Number.isSafeInteger(value) || Number(value) < 0) throw new Error(name);
}
function limit(value = 100): number {
	integer(value, "limit");
	if (value < 1 || value > EVIDENCE_PAGE_ROWS) throw new Error("limit");
	return value;
}
function json(value: unknown): string {
	const encoded = JSON.stringify(value);
	if (encoded === undefined || Buffer.byteLength(encoded) > 64 * 1024) throw new Error("metadata_bytes");
	return encoded;
}
function coverage(value: unknown): string {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("coverage");
	return json(value);
}
function limitations(value: unknown): string {
	if (!Array.isArray(value) || value.length > 128) throw new Error("limitations");
	for (const item of value) text(item, "limitation", 4096);
	return json(value);
}
function transaction<T>(action: () => T): T {
	db.exec("BEGIN IMMEDIATE");
	try {
		const result = action();
		db.exec("COMMIT");
		return result;
	} catch (error) {
		db.exec("ROLLBACK");
		throw error;
	}
}
function getCursor(source: string): string | null {
	text(source, "source");
	return (db.prepare("SELECT cursor FROM sources WHERE source=?").get(source)?.cursor as string | undefined) ?? null;
}
function storedOccurrence(proof: EvidenceReference): EvidenceOccurrence {
	text(proof.source, "source");
	text(proof.occurrenceId, "occurrence_id");
	const row = db
		.prepare("SELECT o.*,p.bytes FROM occurrences o JOIN payloads p ON p.id=o.payload_id WHERE o.source=? AND o.id=?")
		.get(proof.source, proof.occurrenceId);
	if (!row) throw new Error("runtime_proof_unavailable");
	return {
		source: String(row.source),
		id: String(row.id),
		sequence: Number(row.sequence),
		wallTimeMs: Number(row.wall_time_ms),
		kind: String(row.kind),
		payload: row.bytes as Uint8Array,
		...(row.monotonic_ns === null ? {} : { monotonicNs: String(row.monotonic_ns) }),
	};
}
function roleRow(row: Row): EvidenceRuntimeRole {
	return {
		role: row.role as EvidenceRuntimeRole["role"],
		roleInstanceId: String(row.role_instance_id),
		bootId: String(row.boot_id),
		pidNamespace: String(row.pid_namespace),
		pid: Number(row.pid),
		processStartTicks: String(row.start_ticks),
		clockTicksPerSecond: Number(row.clock_ticks),
		observerBoottimeOffsetNs: "0",
		proof: { source: String(row.source), occurrenceId: String(row.id) },
	};
}
function currentRuntimeBoot(): EvidenceRuntimeBoot | undefined {
	const cursor = getCursor(RUNTIME_BOOT_SOURCE);
	return cursor === null ? undefined : (JSON.parse(cursor) as EvidenceRuntimeBoot);
}
function recordRuntimeBoot(observation: EvidenceRuntimeBoot): { retired: number; more: boolean } {
	if (!/^[a-f0-9]{32}$/.test(observation.bootId)) throw new Error("runtime_boot_invalid");
	integer(observation.observedAtMs, "runtime_boot_observed_at");
	const size = limit(observation.limit ?? 128);
	return transaction(() => {
		const previous = currentRuntimeBoot();
		const current =
			previous?.bootId === observation.bootId
				? previous
				: { bootId: observation.bootId, observedAtMs: observation.observedAtMs };
		if (current !== previous)
			db.prepare("INSERT INTO sources VALUES(?,?) ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor").run(
				RUNTIME_BOOT_SOURCE,
				JSON.stringify(current),
			);
		const retired = Number(
			db
				.prepare(
					"UPDATE runtime_roles SET closed_at_ms=?,close_reason='boot_changed' WHERE rowid IN (SELECT rowid FROM runtime_roles WHERE closed_at_ms IS NULL AND boot_id!=? LIMIT ?)",
				)
				.run(current.observedAtMs, current.bootId, size).changes,
		);
		const episodes = Number(
			db
				.prepare(
					"UPDATE kernel_channel_episodes SET unavailable=0,observed_at_ms=? WHERE key IN (SELECT key FROM kernel_channel_episodes WHERE unavailable=1 AND boot_id!=? LIMIT ?)",
				)
				.run(current.observedAtMs, current.bootId, size).changes,
		);
		return { retired, more: retired === size || episodes === size };
	});
}
function rememberRuntimeRole(proof: EvidenceReference, clock: number): EvidenceRuntimeClaimResult {
	if (!validRuntimeClock(clock)) throw new Error("runtime_clock_invalid");
	return transaction(() => {
		const occurrence = storedOccurrence(proof);
		const claim = runtimeRoleFromOccurrence(occurrence, clock);
		if (!claim) return { status: "not_anchor" };
		if (claim === "invalid_anchor") return { status: "invalid_anchor" };
		const key = [claim.bootId, claim.pidNamespace, claim.pid, claim.processStartTicks];
		const previous = db
			.prepare(
				"SELECT r.*,o.source,o.id FROM runtime_roles r JOIN occurrences o ON o.sequence=r.proof_sequence WHERE (boot_id,pid_namespace,pid,start_ticks)=(?,?,?,?)",
			)
			.get(...key);
		if (previous) {
			if (
				previous.conflicted ||
				previous.role !== claim.role ||
				previous.role_instance_id !== claim.roleInstanceId ||
				previous.clock_ticks !== clock
			) {
				db.prepare(
					"UPDATE runtime_roles SET conflicted=1 WHERE (boot_id,pid_namespace,pid,start_ticks)=(?,?,?,?)",
				).run(...key);
				return { status: "conflict" };
			}
			return { status: "replayed", claim: roleRow(previous) };
		}
		if (Number(db.prepare("SELECT count(*) AS count FROM runtime_roles").get()!.count) >= EVIDENCE_RUNTIME_ROLE_LIMIT)
			return { status: "capacity" };
		const currentBoot = currentRuntimeBoot();
		const retiredAt = currentBoot && currentBoot.bootId !== claim.bootId ? currentBoot.observedAtMs : null;
		db.prepare(
			"INSERT INTO runtime_roles(boot_id,pid_namespace,pid,start_ticks,role,role_instance_id,clock_ticks,proof_sequence,closed_at_ms,close_reason) VALUES(?,?,?,?,?,?,?,?,?,?)",
		).run(
			...key,
			claim.role,
			claim.roleInstanceId,
			clock,
			occurrence.sequence,
			retiredAt,
			retiredAt === null ? null : "boot_changed",
		);
		return { status: "registered", claim };
	});
}
function observeRuntimeExit(proof: EvidenceReference, provider: EvidenceRuntimeProvider): EvidenceRuntimeExitResult {
	if (!validRuntimeClock(provider.clockTicksPerSecond) || !/^[A-Za-z0-9_.-]{1,64}$/.test(provider.identifier))
		throw new Error("runtime_provider_invalid");
	return transaction(() => {
		const occurrence = storedOccurrence(proof);
		const exit = runtimeExitFromOccurrence(occurrence, provider);
		if (!exit) return { status: "not_exit" };
		if (exit.invalid) return { status: "invalid_exit", bootId: exit.bootId };
		const key = [exit.bootId, exit.pidNamespace, exit.pid, exit.processStartTicks];
		const claim = db
			.prepare(
				"SELECT r.*,o.source,o.id FROM runtime_roles r JOIN occurrences o ON o.sequence=r.proof_sequence WHERE (boot_id,pid_namespace,pid,start_ticks)=(?,?,?,?)",
			)
			.get(...key);
		if (!claim) return { status: "unregistered", bootId: exit.bootId };
		if (
			claim.conflicted ||
			claim.clock_ticks !== provider.clockTicksPerSecond ||
			(claim.native_pid !== null &&
				(claim.native_pid !== exit.initPid || claim.native_start !== exit.processStartBoottimeNs))
		) {
			db.prepare(
				"UPDATE runtime_roles SET conflicted=1 WHERE (boot_id,pid_namespace,pid,start_ticks)=(?,?,?,?)",
			).run(...key);
			return { status: "conflict", bootId: exit.bootId };
		}
		if (claim.exit_sequence === null)
			db.prepare(
				"UPDATE runtime_roles SET closed_at_ms=?,close_reason='native_exit',exit_sequence=?,native_pid=?,native_start=? WHERE (boot_id,pid_namespace,pid,start_ticks)=(?,?,?,?)",
			).run(occurrence.wallTimeMs, occurrence.sequence, exit.initPid, exit.processStartBoottimeNs, ...key);
		return {
			status: "matched",
			rawExitCode: exit.rawExitCode,
			runtimeRole: {
				...roleRow(claim),
				exit: { ...proof, initPid: exit.initPid, processStartBoottimeNs: exit.processStartBoottimeNs },
			},
		};
	});
}
function sameOccurrence(
	row: Row | undefined,
	item: EvidenceBatch["occurrences"][number],
	journalIdentity?: string,
): boolean {
	return (
		!!row &&
		row.wall_time_ms === item.wallTimeMs &&
		row.monotonic_ns === (item.monotonicNs ?? null) &&
		row.kind === item.kind &&
		(Buffer.from(row.bytes as Uint8Array).equals(item.payload) ||
			(journalIdentity !== undefined && journalReplayIdentity(row.bytes as Uint8Array).identity === journalIdentity))
	);
}
function ingest(batch: EvidenceBatch, journalReplay = false) {
	text(batch.batchId, "batch_id");
	text(batch.source, "source");
	text(batch.cursor, "cursor", 8192);
	if (batch.expectedCursor !== null) text(batch.expectedCursor, "expected_cursor", 8192);
	if (!Array.isArray(batch.occurrences) || batch.occurrences.length > EVIDENCE_BATCH_ROWS)
		throw new Error("batch_rows");
	let byteCount = 0;
	const ids = new Set<string>();
	const journalIdentities = new Map<string, string>();
	if (journalReplay && (batch.source.startsWith("internal:") || !batch.occurrences.length))
		throw new Error("journal_source_reserved_or_empty");
	const uniqueOccurrences: EvidenceBatch["occurrences"] = [];
	for (const item of batch.occurrences) {
		text(item.id, "occurrence_id");
		text(item.kind, "kind", 128);
		integer(item.wallTimeMs, "wall_time");
		if (item.monotonicNs !== undefined) {
			text(item.monotonicNs, "monotonic_ns", 32);
			if (!/^\d+$/.test(item.monotonicNs)) throw new Error("monotonic_ns");
		}
		if (!(item.payload instanceof Uint8Array)) throw new Error("payload_bytes");
		byteCount += item.payload.byteLength;
		if (byteCount > EVIDENCE_BATCH_BYTES) throw new Error("batch_bytes");
		if (journalReplay) {
			const replay = journalReplayIdentity(item.payload);
			if (
				item.kind !== "journal.json" ||
				item.id !==
					createHash("sha256")
						.update(JSON.stringify([batch.source, replay.cursor]))
						.digest("hex") ||
				item.wallTimeMs !== replay.wallTimeMs ||
				item.monotonicNs !== replay.monotonicNs
			)
				throw new Error("journal_occurrence_identity");
			const previous = journalIdentities.get(item.id);
			if (previous !== undefined && previous !== replay.identity) throw new Error("occurrence_conflict");
			journalIdentities.set(item.id, replay.identity);
			if (item === batch.occurrences.at(-1) && batch.cursor !== replay.cursor)
				throw new Error("journal_cursor_identity");
		}
		if (ids.has(item.id)) {
			if (!journalReplay) throw new Error("duplicate_batch_occurrence_id");
			continue;
		}
		ids.add(item.id);
		uniqueOccurrences.push(item);
	}
	batch = { ...batch, occurrences: uniqueOccurrences };
	const batchDigest = createHash("sha256");
	batchDigest.update(
		JSON.stringify(
			batch.occurrences.map((item) => ({
				id: item.id,
				wallTimeMs: item.wallTimeMs,
				monotonicNs: item.monotonicNs ?? null,
				kind: item.kind,
				bytes: journalReplay ? Buffer.byteLength(journalIdentities.get(item.id)!) : item.payload.byteLength,
			})),
		),
	);
	for (const item of batch.occurrences) batchDigest.update(journalIdentities.get(item.id) ?? item.payload);
	const digest = batchDigest.digest("hex");
	return transaction(() => {
		const receipt = db.prepare("SELECT * FROM receipts WHERE batch_id=?").get(batch.batchId);
		const existing = db.prepare(
			"SELECT o.*,p.bytes FROM occurrences o JOIN payloads p ON p.id=o.payload_id WHERE o.source=? AND o.id=?",
		);
		if (receipt) {
			if (
				receipt.source !== batch.source ||
				receipt.expected_cursor !== batch.expectedCursor ||
				receipt.cursor !== batch.cursor ||
				receipt.ids !== JSON.stringify([...ids]) ||
				receipt.digest !== digest
			)
				throw new Error("batch_conflict");
			return { inserted: Number(receipt.inserted), cursor: batch.cursor, replayed: true };
		}
		if (getCursor(batch.source) !== batch.expectedCursor)
			throw new Error("cursor_conflict; retry receipt may have expired");
		let inserted = 0;
		for (const item of batch.occurrences) {
			const previous = existing.get(batch.source, item.id);
			if (previous) {
				if (!sameOccurrence(previous, item, journalIdentities.get(item.id))) throw new Error("occurrence_conflict");
				continue;
			}
			const hash = createHash("sha256").update(item.payload).digest("hex");
			let payloadId: number | undefined;
			for (const candidate of db.prepare("SELECT id,bytes FROM payloads WHERE hash=?").iterate(hash)) {
				if (Buffer.from(candidate.bytes as Uint8Array).equals(item.payload)) {
					payloadId = Number(candidate.id);
					break;
				}
			}
			if (payloadId === undefined)
				payloadId = Number(
					db.prepare("INSERT INTO payloads(hash,bytes) VALUES(?,?)").run(hash, item.payload).lastInsertRowid,
				);
			db.prepare(
				"INSERT INTO occurrences(source,id,wall_time_ms,monotonic_ns,kind,payload_id) VALUES(?,?,?,?,?,?)",
			).run(batch.source, item.id, item.wallTimeMs, item.monotonicNs ?? null, item.kind, payloadId);
			inserted++;
		}
		db.prepare("INSERT INTO sources VALUES(?,?) ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor").run(
			batch.source,
			batch.cursor,
		);
		db.prepare(
			"INSERT INTO receipts(batch_id,source,expected_cursor,cursor,ids,digest,inserted,created_at_ms) VALUES(?,?,?,?,?,?,?,?)",
		).run(
			batch.batchId,
			batch.source,
			batch.expectedCursor,
			batch.cursor,
			JSON.stringify([...ids]),
			digest,
			inserted,
			Date.now(),
		);
		db.exec(
			"DELETE FROM receipts WHERE sequence < (SELECT sequence FROM receipts ORDER BY sequence DESC LIMIT 1 OFFSET 4095)",
		);
		return { inserted, cursor: batch.cursor, replayed: false };
	});
}

function readWindow(window: EvidenceWindow): EvidencePage {
	integer(window.startMs, "window_start");
	integer(window.endMs, "window_end");
	if (window.startMs > window.endMs) throw new Error("window_order");
	if (window.causalOnly !== undefined && typeof window.causalOnly !== "boolean") throw new Error("causal_only");
	const pageLimit = limit(window.limit);
	let afterTime = window.startMs;
	let afterSequence = 0;
	if (window.afterSequence !== undefined) {
		integer(window.afterSequence, "after_sequence");
		const cursor = db.prepare("SELECT wall_time_ms FROM occurrences WHERE sequence=?").get(window.afterSequence);
		if (!cursor) throw new Error("cursor_lost");
		afterTime = Number(cursor.wall_time_ms);
		afterSequence = window.afterSequence;
		if (afterTime < window.startMs || afterTime > window.endMs) throw new Error("cursor_outside_window");
	}
	const rows = db
		.prepare(
			`SELECT o.*,length(p.bytes) AS size FROM occurrences o ${window.causalOnly ? "INDEXED BY occurrence_causal_window" : ""} JOIN payloads p ON p.id=o.payload_id WHERE ${window.causalOnly ? "o.kind IN ('journal.json','diagnostic.gap','evidence.gap') AND " : ""}(o.wall_time_ms,o.sequence)>(?,?) AND o.wall_time_ms<=? ORDER BY o.wall_time_ms,o.sequence LIMIT ?`,
		)
		.all(afterTime, afterSequence, window.endMs, pageLimit + 1);
	return occurrencePage(rows, pageLimit);
}
function readOccurrences(options: { afterSequence?: number; limit?: number }): EvidencePage {
	integer(options.afterSequence ?? 0, "after_sequence");
	const pageLimit = limit(options.limit);
	const page = occurrencePage(
		db
			.prepare(
				"SELECT o.*,length(p.bytes) AS size FROM occurrences o JOIN payloads p ON p.id=o.payload_id WHERE o.sequence>? ORDER BY o.sequence LIMIT ?",
			)
			.all(options.afterSequence ?? 0, pageLimit + 1),
		pageLimit,
	);
	const missingRanges: NonNullable<EvidencePage["missingRanges"]> = [];
	let throughSequence = options.afterSequence ?? 0;
	for (const occurrence of page.occurrences) {
		if (occurrence.sequence > throughSequence + 1)
			missingRanges.push({ firstSequence: throughSequence + 1, lastSequence: occurrence.sequence - 1 });
		throughSequence = occurrence.sequence;
	}
	if (page.nextSequence === undefined) {
		const highWater = Number(db.prepare("SELECT seq FROM sqlite_sequence WHERE name='occurrences'").get()?.seq ?? 0);
		if (highWater > throughSequence) {
			missingRanges.push({ firstSequence: throughSequence + 1, lastSequence: highWater });
			throughSequence = highWater;
		}
	}
	return { ...page, throughSequence, ...(missingRanges.length ? { missingRanges } : {}) };
}
function occurrencePage(rows: Row[], pageLimit: number): EvidencePage {
	const occurrences: EvidencePage["occurrences"] = [];
	let bytes = 0;
	for (const row of rows) {
		if (occurrences.length === pageLimit || bytes + Number(row.size) > EVIDENCE_BATCH_BYTES) break;
		const payload = db.prepare("SELECT bytes FROM payloads WHERE id=?").get(row.payload_id)!;
		occurrences.push({
			id: String(row.id),
			source: String(row.source),
			sequence: Number(row.sequence),
			wallTimeMs: Number(row.wall_time_ms),
			...(row.monotonic_ns !== null ? { monotonicNs: String(row.monotonic_ns) } : {}),
			kind: String(row.kind),
			payload: payload.bytes as Uint8Array,
		});
		bytes += Number(row.size);
	}
	return {
		occurrences,
		...(rows.length > occurrences.length && occurrences.length ? { nextSequence: occurrences.at(-1)!.sequence } : {}),
	};
}
function incidentRow(row: Row): EvidenceIncident {
	return {
		id: String(row.id),
		evidenceRevision: Number(row.evidence_revision),
		triggerTimeMs: Number(row.trigger_time_ms),
		windowStartMs: Number(row.window_start_ms),
		windowEndMs: Number(row.window_end_ms),
		state: row.state as EvidenceIncident["state"],
		coverage: JSON.parse(String(row.coverage)),
		limitations: JSON.parse(String(row.limitations)),
		createdAtMs: Number(row.created_at_ms),
		expiresAtMs: Number(row.expires_at_ms),
	};
}
function getIncident(id: string): EvidenceIncident | undefined {
	text(id, "incident_id");
	const row = db.prepare("SELECT * FROM incidents WHERE id=?").get(id);
	return row ? incidentRow(row) : undefined;
}
function openIncident(input: EvidenceIncidentInput, inTransaction = false): EvidenceIncident {
	text(input.id, "incident_id");
	integer(input.triggerTimeMs, "trigger_time");
	integer(input.windowStartMs, "window_start");
	integer(input.windowEndMs, "window_end");
	if (input.windowStartMs > input.triggerTimeMs || input.windowEndMs < input.triggerTimeMs)
		throw new Error("incident_window");
	const coverageJson = coverage(input.coverage);
	const limitationsJson = limitations(input.limitations);
	integer(input.triggerTimeMs + EVIDENCE_INCIDENT_MS, "incident_expiry");
	const action = () => {
		const previous = getIncident(input.id);
		if (previous) {
			if (
				previous.triggerTimeMs !== input.triggerTimeMs ||
				previous.windowStartMs !== input.windowStartMs ||
				previous.windowEndMs !== input.windowEndMs
			)
				throw new Error("incident_conflict");
			return previous;
		}
		db.prepare("INSERT INTO incidents VALUES(?,?,?,?,'capturing',?,?,?,?,1)").run(
			input.id,
			input.triggerTimeMs,
			input.windowStartMs,
			input.windowEndMs,
			coverageJson,
			limitationsJson,
			Date.now(),
			input.triggerTimeMs + EVIDENCE_INCIDENT_MS,
		);
		return getIncident(input.id)!;
	};
	return inTransaction ? action() : transaction(action);
}
function observeKernelChannel(proof: EvidenceReference, input: EvidenceIncidentInput): EvidenceChannelResult {
	return transaction(() => {
		const occurrence = storedOccurrence(proof);
		const observation = kernelChannelObservation(occurrence);
		if (!observation) return { status: "ignored" };
		if (!observation.identity) return { status: observation.available ? "ignored" : "identity_unavailable" };
		const { key, bootId, monotonicNs } = observation.identity;
		const previous = db.prepare("SELECT * FROM kernel_channel_episodes WHERE key=?").get(key);
		if (previous && BigInt(monotonicNs) < BigInt(String(previous.monotonic_ns))) return { status: "ignored" };
		if (previous && BigInt(monotonicNs) === BigInt(String(previous.monotonic_ns))) {
			const incident = previous.incident_id !== null ? getIncident(String(previous.incident_id)) : undefined;
			if (
				previous.sequence !== occurrence.sequence &&
				observation.available !== (previous.unavailable === 0 && !incident)
			)
				return { status: "identity_unavailable" };
			return incident ? { status: "incident", incident } : { status: "ignored" };
		}
		// Successful observations with no prior outage need no registry entry.
		if (!previous && observation.available) return { status: "ignored" };
		if (!previous && Number(db.prepare("SELECT count(*) AS count FROM kernel_channel_episodes").get()!.count) >= 4096)
			return { status: "capacity" };
		let incident = previous && previous.incident_id !== null ? getIncident(String(previous.incident_id)) : undefined;
		if (!observation.available && !incident) {
			if (input.triggerTimeMs !== occurrence.wallTimeMs) throw new Error("channel_trigger_time_conflict");
			incident = openIncident(input, true);
		}
		const oldBoot = currentRuntimeBoot()?.bootId;
		db.prepare(
			"INSERT INTO kernel_channel_episodes VALUES(?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET monotonic_ns=excluded.monotonic_ns,sequence=excluded.sequence,unavailable=excluded.unavailable,incident_id=excluded.incident_id,observed_at_ms=excluded.observed_at_ms",
		).run(
			key,
			bootId,
			monotonicNs,
			occurrence.sequence,
			!observation.available && (!oldBoot || oldBoot === bootId) ? 1 : 0,
			observation.available ? null : (incident?.id ?? null),
			occurrence.wallTimeMs,
		);
		return !observation.available && incident ? { status: "incident", incident } : { status: "ignored" };
	});
}
function updateIncident(id: string, update: EvidenceIncidentUpdate): EvidenceIncident {
	return transaction(() => {
		const previous = getIncident(id);
		if (!previous) throw new Error("incident_missing");
		const state = update.state ?? previous.state;
		if (!["capturing", "published", "complete", "limited"].includes(state)) throw new Error("incident_state");
		db.prepare("UPDATE incidents SET state=?,coverage=?,limitations=? WHERE id=?").run(
			state,
			coverage(update.coverage ?? previous.coverage),
			limitations(update.limitations ?? previous.limitations),
			id,
		);
		return getIncident(id)!;
	});
}
function validateArtifact(artifact: EvidenceArtifact): void {
	text(artifact.id, "artifact_id");
	text(artifact.path, "artifact_path", 4096);
	text(artifact.format, "artifact_format", 128);
	if (
		artifact.path.startsWith("/") ||
		artifact.path.includes("\\") ||
		artifact.path.includes(":") ||
		artifact.path.split("/").some((part) => !part || part === "." || part === "..")
	)
		throw new Error("artifact_path");
	if (artifact.bytes !== undefined) integer(artifact.bytes, "artifact_bytes");
	if (artifact.allocatedBytes !== undefined) {
		integer(artifact.allocatedBytes, "artifact_allocated_bytes");
		if (artifact.bytes !== undefined && artifact.allocatedBytes < artifact.bytes)
			throw new Error("artifact_allocated_bytes");
	}
	if (artifact.sha256 !== undefined && !/^[a-f0-9]{64}$/.test(artifact.sha256)) throw new Error("artifact_sha256");
}
function artifactRow(row: Row): EvidenceArtifact {
	return {
		id: String(row.id),
		path: String(row.path),
		format: String(row.format),
		bytes: Number(row.bytes),
		sha256: String(row.sha256),
		allocatedBytes: Number(row.allocated_bytes),
		contentId: Number(row.content_id),
	};
}
function operationRow(row: Row): EvidenceOperation {
	const artifact: EvidenceArtifact = JSON.parse(String(row.artifact));
	const candidate = row.candidate_id === null ? undefined : db.prepare("SELECT * FROM artifacts WHERE id=?").get(row.candidate_id);
	return {
		id: String(row.id),
		incidentId: String(row.incident_id),
		kind: row.kind as EvidenceOperation["kind"],
		artifact: {
			...artifact,
			...(row.bytes !== null
				? { bytes: Number(row.bytes), sha256: String(row.sha256), allocatedBytes: Number(row.allocated_bytes) }
				: {}),
		},
		state: row.state as EvidenceOperation["state"],
		createdAtMs: Number(row.created_at_ms),
		...(row.staged_at_ms !== null ? { stagedAtMs: Number(row.staged_at_ms) } : {}),
		...(row.staging_identity !== null ? { stagingIdentity: JSON.parse(String(row.staging_identity)) as EvidenceFileIdentity } : {}),
		reservationBytes: Number(row.reservation_bytes),
		...(candidate ? { candidate: { ...artifactRow(candidate), contentId: Number(candidate.content_id) } } : {}),
		...(row.candidates_exhausted ? { candidatesExhausted: true } : {}),
		...(row.selection !== null ? { selection: JSON.parse(String(row.selection)) as EvidenceArtifactSelection } : {}),
		...(row.reuse_limitations !== "[]" ? { reuseLimitations: JSON.parse(String(row.reuse_limitations)) as string[] } : {}),
	};
}
function prepareOperation(input: EvidenceOperationInput): EvidenceOperation {
	text(input.id, "operation_id");
	text(input.incidentId, "incident_id");
	validateArtifact(input.artifact);
	if (!["export", "pin", "delete"].includes(input.kind)) throw new Error("operation_kind");
	const artifact = json({
		id: input.artifact.id,
		path: input.artifact.path,
		format: input.artifact.format,
		...(input.artifact.bytes !== undefined ? { bytes: input.artifact.bytes } : {}),
		...(input.artifact.sha256 !== undefined ? { sha256: input.artifact.sha256 } : {}),
		...(input.artifact.allocatedBytes !== undefined ? { allocatedBytes: input.artifact.allocatedBytes } : {}),
	});
	const previous = db.prepare("SELECT * FROM operations WHERE id=?").get(input.id);
	if (previous) {
		if (previous.incident_id !== input.incidentId || previous.kind !== input.kind || previous.artifact !== artifact)
			throw new Error("operation_conflict");
		return operationRow(previous);
	}
	if (!getIncident(input.incidentId)) throw new Error("incident_missing");
	const existing = db
		.prepare("SELECT * FROM artifacts WHERE id=? OR path=?")
		.get(input.artifact.id, input.artifact.path);
	if (
		existing &&
		(existing.id !== input.artifact.id ||
			existing.incident_id !== input.incidentId ||
			existing.path !== input.artifact.path ||
			existing.format !== input.artifact.format)
	)
		throw new Error("artifact_conflict");
	if (input.kind === "delete" && !existing) throw new Error("artifact_missing");
	if (input.kind === "delete" && db.prepare("SELECT 1 FROM operations WHERE candidate_id=? LIMIT 1").get(input.artifact.id))
		throw new Error("artifact_pinned");
	if (input.kind !== "delete" && existing) throw new Error("artifact_already_registered");
	db.prepare(
		"INSERT INTO operations(id,incident_id,kind,artifact_id,artifact,state,created_at_ms) VALUES(?,?,?,?,?,'pending',?)",
	).run(input.id, input.incidentId, input.kind, input.artifact.id, artifact, Date.now());
	return operationRow(db.prepare("SELECT * FROM operations WHERE id=?").get(input.id)!);
}
function reserveOperationBytes(id: string, bytes: number): EvidenceOperation {
	text(id, "operation_id");
	integer(bytes, "reservation_bytes");
	return transaction(() => {
		const row = db.prepare("SELECT * FROM operations WHERE id=?").get(id);
		if (!row) throw new Error("operation_missing");
		if (row.state !== "pending" || row.kind === "delete") throw new Error("reservation_not_allowed");
		if (bytes < Number(row.reservation_bytes)) throw new Error("operation_reservation_decrease");
		const total = Number(db.prepare("SELECT reserved_artifact_bytes FROM counts").get()!.reserved_artifact_bytes);
		integer(total + bytes - Number(row.reservation_bytes), "reservation_total_overflow");
		db.prepare("UPDATE operations SET reservation_bytes=? WHERE id=?").run(bytes, id);
		return operationRow(db.prepare("SELECT * FROM operations WHERE id=?").get(id)!);
	});
}
function releaseOperationReservation(id: string): EvidenceOperation {
	text(id, "operation_id");
	return transaction(() => {
		const row = db.prepare("SELECT * FROM operations WHERE id=?").get(id);
		if (!row) throw new Error("operation_missing");
		if (row.state !== "pending" || row.kind === "delete" || row.staged_at_ms !== null)
			throw new Error("reservation_release_not_allowed");
		db.prepare("UPDATE operations SET reservation_bytes=0 WHERE id=?").run(id);
		return operationRow(db.prepare("SELECT * FROM operations WHERE id=?").get(id)!);
	});
}
function markOperationStaged(id: string, completion: EvidenceArtifactCompletion): EvidenceOperation {
	text(id, "operation_id");
	integer(completion.bytes, "artifact_bytes");
	integer(completion.allocatedBytes, "artifact_allocated_bytes");
	if (completion.allocatedBytes < completion.bytes) throw new Error("artifact_allocated_bytes");
	text(completion.sha256, "artifact_sha256", 64);
	if (!/^[a-f0-9]{64}$/.test(completion.sha256)) throw new Error("artifact_sha256");
	const fileIdentity = completion.fileIdentity ? encodeFileIdentity(completion.fileIdentity) : null;
	if (completion.fileIdentity && completion.fileIdentity.size !== completion.bytes) throw new Error("artifact_file_size");
	return transaction(() => {
		const row = db.prepare("SELECT * FROM operations WHERE id=?").get(id);
		if (!row) throw new Error("operation_missing");
		if (row.kind === "delete") throw new Error("delete_operation_cannot_stage");
		if (row.staged_at_ms !== null) {
			if (
				row.bytes !== completion.bytes ||
				row.sha256 !== completion.sha256 ||
				row.allocated_bytes !== completion.allocatedBytes || row.staging_identity !== fileIdentity
			)
				throw new Error("operation_staged_identity_conflict");
			return operationRow(row);
		}
		if (Number(row.reservation_bytes) < completion.allocatedBytes) throw new Error("artifact_reservation_required");
		db.prepare(
			"UPDATE operations SET bytes=?,sha256=?,staged_at_ms=?,allocated_bytes=?,reservation_bytes=?,staging_identity=? WHERE id=?",
		).run(completion.bytes, completion.sha256, Date.now(), completion.allocatedBytes, completion.allocatedBytes, fileIdentity, id);
		return operationRow(db.prepare("SELECT * FROM operations WHERE id=?").get(id)!);
	});
}
function pendingArtifactOperation(id: string): Row {
	text(id, "operation_id");
	const row = db.prepare("SELECT * FROM operations WHERE id=?").get(id);
	if (!row) throw new Error("operation_missing");
	if (row.kind === "delete" || row.state !== "pending" || row.staged_at_ms === null)
		throw new Error("artifact_selection_not_allowed");
	return row;
}
function selectArtifactCandidate(id: string): EvidenceOperation {
	return transaction(() => {
		const row = pendingArtifactOperation(id);
		if (row.selection !== null || row.candidate_id !== null || row.candidates_exhausted) return operationRow(row);
		const candidate = db.prepare(
			"SELECT a.id,a.content_id FROM artifact_contents c JOIN artifacts a ON a.content_id=c.id WHERE c.sha256=? AND c.bytes=? AND (c.id,a.id)>(?,?) AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.artifact_id=a.id AND o.kind='delete' AND o.state='pending') ORDER BY c.id,a.id LIMIT 1",
		).get(row.sha256, row.bytes, row.candidate_content_cursor, row.candidate_alias_cursor);
		if (candidate)
			db.prepare("UPDATE operations SET candidate_id=? WHERE id=?").run(candidate.id, id);
		else db.prepare("UPDATE operations SET candidates_exhausted=1 WHERE id=?").run(id);
		return operationRow(db.prepare("SELECT * FROM operations WHERE id=?").get(id)!);
	});
}
function rejectArtifactCandidate(id: string, candidateId: string, limitation?: string): EvidenceOperation {
	text(candidateId, "candidate_id");
	if (limitation !== undefined) text(limitation, "candidate_limitation", 512);
	return transaction(() => {
		const row = pendingArtifactOperation(id);
		if (row.candidate_id !== candidateId || row.selection !== null) throw new Error("artifact_candidate_conflict");
		const candidate = db.prepare("SELECT content_id FROM artifacts WHERE id=?").get(candidateId)!;
		const gaps = JSON.parse(String(row.reuse_limitations)) as string[];
		if (limitation && gaps.length < 16) gaps.push(limitation);
		else if (limitation) gaps[15] = "Additional artifact reuse candidates unavailable; raw artifacts preserved";
		db.prepare("UPDATE operations SET candidate_content_cursor=?,candidate_alias_cursor=?,candidate_id=NULL,reuse_limitations=? WHERE id=?")
			.run(candidate.content_id, candidateId, JSON.stringify(gaps), id);
		return operationRow(db.prepare("SELECT * FROM operations WHERE id=?").get(id)!);
	});
}
function encodeFileIdentity(identity: EvidenceFileIdentity): string {
	if (!identity || !/^\d+$/.test(identity.device) || !/^\d+$/.test(identity.inode) || !/^-?\d+$/.test(identity.mtimeNs))
		throw new Error("artifact_file_identity");
	integer(identity.size, "artifact_file_size");
	return json({ device: identity.device, inode: identity.inode, size: identity.size, mtimeNs: identity.mtimeNs });
}
function selectArtifactContent(id: string, selection: EvidenceArtifactSelection): EvidenceOperation {
	if (!selection || !["unique", "reuse"].includes(selection.kind)) throw new Error("artifact_selection_kind");
	const identity = selection.identity;
	encodeFileIdentity(identity);
	const encoded = json({ kind: selection.kind, identity: { device: identity.device, inode: identity.inode, size: identity.size, mtimeNs: identity.mtimeNs } });
	return transaction(() => {
		const row = pendingArtifactOperation(id);
		if (row.selection !== null) {
			if (row.selection !== encoded) throw new Error("artifact_selection_conflict");
			return operationRow(row);
		}
		if (identity.size !== row.bytes || (selection.kind === "reuse" ? row.candidate_id === null : !row.candidates_exhausted || row.candidate_id !== null))
			throw new Error("artifact_selection_precondition");
		db.prepare("UPDATE operations SET selection=? WHERE id=?").run(encoded, id);
		return operationRow(db.prepare("SELECT * FROM operations WHERE id=?").get(id)!);
	});
}
function markOperationReady(id: string, completion?: EvidenceArtifactCompletion): EvidenceOperation {
	text(id, "operation_id");
	return transaction(() => {
		const row = db.prepare("SELECT * FROM operations WHERE id=?").get(id);
		if (!row) throw new Error("operation_missing");
		const operation = operationRow(row);
		const artifact = operation.artifact;
		validateArtifact(artifact);
		if (operation.kind !== "delete") {
			if (
				operation.stagedAtMs === undefined ||
				artifact.bytes === undefined ||
				artifact.sha256 === undefined ||
				artifact.allocatedBytes === undefined
			)
				throw new Error("artifact_stage_required");
			if (
				completion &&
				(completion.bytes !== artifact.bytes ||
					completion.sha256 !== artifact.sha256 ||
					completion.allocatedBytes !== artifact.allocatedBytes)
			)
				throw new Error("operation_completion_conflict");
		}
		if (operation.state === "ready") {
			return operation;
		}
		if (operation.kind !== "delete" && !operation.selection) throw new Error("artifact_selection_required");
		if (operation.kind === "delete")
			db.prepare("DELETE FROM artifacts WHERE id=? AND incident_id=?").run(artifact.id, operation.incidentId);
		else {
			const existing = db.prepare("SELECT * FROM artifacts WHERE id=?").get(artifact.id);
			if (
				existing &&
				(existing.incident_id !== operation.incidentId ||
					existing.path !== artifact.path ||
					existing.format !== artifact.format ||
					existing.bytes !== artifact.bytes ||
					existing.sha256 !== artifact.sha256 ||
					existing.allocated_bytes !== artifact.allocatedBytes)
			)
				throw new Error("artifact_conflict");
			if (!existing) {
				const contentId = operation.selection!.kind === "reuse"
					? operation.candidate?.contentId
					: Number(db.prepare("INSERT INTO artifact_contents(sha256,bytes,allocated_bytes) VALUES(?,?,?)").run(artifact.sha256!, artifact.bytes!, artifact.allocatedBytes!).lastInsertRowid);
				if (contentId === undefined) throw new Error("artifact_candidate_missing");
				db.prepare("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?)").run(
					artifact.id,
					operation.incidentId,
					artifact.path,
					artifact.format,
					artifact.bytes!,
					artifact.sha256!,
					artifact.allocatedBytes!,
					contentId,
				);
			}
		}
		db.prepare(
			"UPDATE operations SET state='ready',bytes=?,sha256=?,allocated_bytes=?,reservation_bytes=0,candidate_id=NULL WHERE id=?",
		).run(artifact.bytes ?? null, artifact.sha256 ?? null, artifact.allocatedBytes ?? null, id);
		return operationRow(db.prepare("SELECT * FROM operations WHERE id=?").get(id)!);
	});
}
function retain(options: { nowMs: number; limit?: number }) {
	integer(options.nowMs, "retention_time");
	const size = limit(options.limit);
	const retained = transaction(() => {
		let operationsQueued = 0;
		const expiredArtifacts = db
			.prepare(
				"SELECT a.* FROM incidents i JOIN artifacts a ON a.incident_id=i.id WHERE i.expires_at_ms<=? AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.artifact_id=a.id AND o.state='pending') AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.candidate_id=a.id) ORDER BY i.expires_at_ms,a.id LIMIT ?",
			)
			.all(options.nowMs, size);
		for (const row of expiredArtifacts) {
			prepareOperation({
				id: `retention:${createHash("sha256").update(String(row.id)).digest("hex")}`,
				incidentId: String(row.incident_id),
				kind: "delete",
				artifact: artifactRow(row),
			});
			operationsQueued++;
		}
		const incidents = Number(
			db
				.prepare(
					"DELETE FROM incidents WHERE id IN (SELECT i.id FROM incidents i WHERE expires_at_ms<=? AND NOT EXISTS(SELECT 1 FROM artifacts a WHERE a.incident_id=i.id) AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.incident_id=i.id AND o.state='pending') ORDER BY expires_at_ms LIMIT ?)",
				)
				.run(options.nowMs, size).changes,
		);
		const receipts = Number(
			db
				.prepare(
					"DELETE FROM receipts WHERE sequence IN (SELECT sequence FROM receipts WHERE created_at_ms<? ORDER BY created_at_ms LIMIT ?)",
				)
				.run(options.nowMs - EVIDENCE_HISTORY_MS, size).changes,
		);
		const runtimeRoles = Number(
			db
				.prepare(
					"DELETE FROM runtime_roles WHERE rowid IN (SELECT r.rowid FROM runtime_roles r JOIN occurrences o ON o.sequence=r.proof_sequence WHERE r.closed_at_ms<? AND NOT EXISTS(SELECT 1 FROM incidents i WHERE json_extract(i.coverage,'$.runtimeRole.proof.source')=o.source AND json_extract(i.coverage,'$.runtimeRole.proof.occurrenceId')=o.id) ORDER BY r.closed_at_ms LIMIT ?)",
				)
				.run(options.nowMs - EVIDENCE_HISTORY_MS, size).changes,
		);
		const channelEpisodes = Number(
			db
				.prepare(
					"DELETE FROM kernel_channel_episodes WHERE key IN (SELECT key FROM kernel_channel_episodes WHERE unavailable=0 AND observed_at_ms<? ORDER BY observed_at_ms LIMIT ?)",
				)
				.run(options.nowMs - EVIDENCE_HISTORY_MS, size).changes,
		);
		const progress = db.prepare("SELECT * FROM retention_progress").get()!;
		const candidates = db
			.prepare(
				"SELECT sequence,wall_time_ms FROM occurrences WHERE (wall_time_ms,sequence)>(?,?) AND wall_time_ms<? ORDER BY wall_time_ms,sequence LIMIT ?",
			)
			.all(progress.wall_time_ms, progress.sequence, options.nowMs - EVIDENCE_HISTORY_MS, size);
		let occurrences = 0;
		for (const candidate of candidates) {
			const pinned = db
				.prepare("SELECT 1 FROM incidents WHERE window_start_ms<=? AND window_end_ms>=? LIMIT 1")
				.get(candidate.wall_time_ms, candidate.wall_time_ms);
			const runtimePinned = db
				.prepare("SELECT 1 FROM runtime_roles WHERE proof_sequence=? OR exit_sequence=? LIMIT 1")
				.get(candidate.sequence, candidate.sequence);
			if (!pinned && !runtimePinned)
				occurrences += Number(
					db.prepare("DELETE FROM occurrences WHERE sequence=?").run(candidate.sequence).changes,
				);
		}
		const last = candidates.length === size ? candidates.at(-1) : undefined;
		db.prepare("UPDATE retention_progress SET wall_time_ms=?,sequence=? WHERE id=1").run(
			last?.wall_time_ms ?? 0,
			last?.sequence ?? 0,
		);
		const payloads = Number(
			db
				.prepare("DELETE FROM payloads WHERE id IN (SELECT id FROM payloads WHERE ref_count=0 ORDER BY id LIMIT ?)")
				.run(size).changes,
		);
		return {
			occurrences,
			payloads,
			receipts,
			incidents,
			operationsQueued,
			more: [candidates.length, payloads, receipts, incidents, operationsQueued, runtimeRoles, channelEpisodes].some(
				(count) => count === size,
			),
		};
	});
	const before = Number(db.prepare("PRAGMA freelist_count").get()!.freelist_count);
	// One bounded page evacuation per pass; no full database rewrite or long-lived reader.
	if (before > 0) db.exec("PRAGMA incremental_vacuum(256)");
	const remainingFreePages = Number(db.prepare("PRAGMA freelist_count").get()!.freelist_count);
	const checkpoint = db.prepare("PRAGMA wal_checkpoint(PASSIVE)").get()!;
	let checkpointBusy = Number(checkpoint.busy) !== 0 || checkpoint.log !== checkpoint.checkpointed;
	if (!checkpointBusy && Number(checkpoint.log) > 0)
		checkpointBusy = Number(db.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get()!.busy) !== 0;
	return {
		...retained,
		more: retained.more || remainingFreePages > 0,
		maintenance: { vacuumedPages: before - remainingFreePages, remainingFreePages, checkpointBusy },
	};
}
function listOptions(options: EvidenceListOptions): [string, number] {
	if (options.afterId !== undefined) text(options.afterId, "after_id");
	return [options.afterId ?? "", limit(options.limit)];
}
function handle(method: string, args: unknown[]): unknown {
	switch (method) {
		case "ingest":
			return ingest(args[0] as EvidenceBatch);
		case "ingestJournal":
			return ingest(args[0] as EvidenceBatch, true);
		case "getCursor":
			return getCursor(args[0] as string);
		case "rememberRuntimeRole":
			return rememberRuntimeRole(args[0] as EvidenceReference, args[1] as number);
		case "recordRuntimeBoot":
			return recordRuntimeBoot(args[0] as EvidenceRuntimeBoot);
		case "observeRuntimeExit":
			return observeRuntimeExit(args[0] as EvidenceReference, args[1] as EvidenceRuntimeProvider);
		case "getOccurrence": {
			text(args[0], "source");
			text(args[1], "occurrence_id");
			const row = db
				.prepare(
					"SELECT o.*,length(p.bytes) AS size FROM occurrences o JOIN payloads p ON p.id=o.payload_id WHERE o.source=? AND o.id=?",
				)
				.get(args[0], args[1]);
			return row ? occurrencePage([row], 1).occurrences[0] : undefined;
		}
		case "readWindow":
			return readWindow(args[0] as EvidenceWindow);
		case "readOccurrences":
			return readOccurrences(args[0] as { afterSequence?: number; limit?: number });
		case "openIncident":
			return openIncident(args[0] as EvidenceIncidentInput);
		case "observeKernelChannel":
			return observeKernelChannel(args[0] as EvidenceReference, args[1] as EvidenceIncidentInput);
		case "getIncident":
			return getIncident(args[0] as string);
		case "updateIncident":
			return updateIncident(args[0] as string, args[1] as EvidenceIncidentUpdate);
		case "listIncidents": {
			const options = args[0] as EvidenceListOptions;
			const pageLimit = options.limit ?? 32;
			if (pageLimit > 64) throw new Error("incident_list_limit");
			return db
				.prepare("SELECT * FROM incidents WHERE id>? ORDER BY id LIMIT ?")
				.all(...listOptions({ ...options, limit: pageLimit }))
				.map(incidentRow);
		}
		case "prepareOperation":
			return transaction(() => prepareOperation(args[0] as EvidenceOperationInput));
		case "unfinishedOperations":
			return db
				.prepare("SELECT * FROM operations WHERE state='pending' AND id>? ORDER BY id LIMIT ?")
				.all(...listOptions(args[0] as EvidenceListOptions))
				.map(operationRow);
		case "markOperationReady":
			return markOperationReady(args[0] as string, args[1] as EvidenceArtifactCompletion | undefined);
		case "selectArtifactCandidate":
			return selectArtifactCandidate(args[0] as string);
		case "rejectArtifactCandidate":
			return rejectArtifactCandidate(args[0] as string, args[1] as string, args[2] as string | undefined);
		case "selectArtifactContent":
			return selectArtifactContent(args[0] as string, args[1] as EvidenceArtifactSelection);
		case "markOperationStaged":
			return markOperationStaged(args[0] as string, args[1] as EvidenceArtifactCompletion);
		case "reserveOperationBytes":
			return reserveOperationBytes(args[0] as string, args[1] as number);
		case "releaseOperationReservation":
			return releaseOperationReservation(args[0] as string);
		case "listArtifacts": {
			text(args[0], "incident_id");
			return db
				.prepare("SELECT * FROM artifacts WHERE incident_id=? ORDER BY id LIMIT 1000")
				.all(args[0])
				.map(artifactRow);
		}
		case "retain":
			return retain(args[0] as { nowMs: number; limit?: number });
		case "stats": {
			const row = db.prepare("SELECT * FROM counts").get()!;
			return {
				occurrences: Number(row.occurrences),
				payloads: Number(row.payloads),
				payloadBytes: Number(row.payload_bytes),
				incidents: Number(row.incidents),
				operations: Number(row.operations),
				artifactBytes: Number(row.artifact_bytes),
				artifactAllocatedBytes: Number(row.artifact_allocated_bytes),
				reservedArtifactBytes: Number(row.reserved_artifact_bytes),
				pendingArtifactOperations: Number(row.pending_artifact_operations),
				sqliteVersion,
			};
		}
		case "close":
			db.close();
			return undefined;
		default:
			throw new Error("unknown_evidence_method");
	}
}
port.on("message", (request: EvidenceWorkerRequest) => {
	try {
		port.postMessage({ id: request.id, result: handle(request.method, request.args) });
	} catch (error) {
		port.postMessage({ id: request.id, error: error instanceof Error ? error.message : String(error) });
	}
	if (request.method === "close") port.close();
});
port.postMessage({ id: 0 });
