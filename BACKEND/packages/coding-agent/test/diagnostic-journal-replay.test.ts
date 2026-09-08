import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { DiagnosticEvidencePipeline } from "../src/modes/daemon/diagnostic-evidence-pipeline.js";
import { DiagnosticEvidenceStore } from "../src/modes/daemon/diagnostic-evidence-store.js";

const directories: string[] = [];
afterEach(async () => {
	await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});
function entry(cursor = "first") {
	return {
		__CURSOR: cursor,
		__REALTIME_TIMESTAMP: "1700000000000000",
		__MONOTONIC_TIMESTAMP: "123",
		_BOOT_ID: "boot",
		_UID: "1000",
		MESSAGE: '{"a":1,"b":2}',
		BINARY: [0, 13, 255],
		MULTIPLE: ["first", [0, 2], null],
		LARGE: null,
	};
}
function reordered(value: Record<string, unknown>): Buffer {
	return Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(value).reverse()), null, 2));
}
async function open() {
	const root = await mkdtemp(join(tmpdir(), "diagnostic-replay-"));
	directories.push(root);
	const path = join(root, "evidence.sqlite");
	return { path, store: await DiagnosticEvidenceStore.open({ path }) };
}

it("replays provider field order after restart and cursor loss while preserving first bytes and sequence", async () => {
	const opened = await open();
	let store = opened.store;
	try {
		const first = Buffer.from(JSON.stringify(entry()));
		await new DiagnosticEvidencePipeline(store).ingestJournal("journal:test", first);
		const original = (await store.readOccurrences()).occurrences;
		await store.close();
		store = await DiagnosticEvidenceStore.open({ path: opened.path });
		const pipeline = new DiagnosticEvidencePipeline(store);
		await pipeline.ingestJournal("journal:test", reordered(entry()));
		await pipeline.ingestJournal("journal:test", first);
		expect((await store.readOccurrences()).occurrences).toEqual(original);
		await pipeline.ingestJournalBatch("journal:test", [reordered(entry()), reordered(entry("second"))]);
		await pipeline.ingestJournalBatch("journal:test", [first, Buffer.from(JSON.stringify(entry("second")))]);
		const rows = (await store.readOccurrences()).occurrences;
		expect(rows).toHaveLength(2);
		expect(rows[0]).toEqual(original[0]);
		expect(Buffer.from(rows[1].payload)).toEqual(reordered(entry("second")));
		expect(await store.getCursor("journal:test")).toBe("second");
	} finally {
		await store.close();
	}
});

it("retains each distinct cursor but coalesces repeated rendering of one cursor within a batch", async () => {
	const { store } = await open();
	try {
		const first = Buffer.from(JSON.stringify(entry()));
		await new DiagnosticEvidencePipeline(store).ingestJournalBatch("journal:test", [
			first,
			reordered(entry()),
			first,
		]);
		const rows = (await store.readOccurrences()).occurrences;
		expect(rows).toHaveLength(1);
		expect(Buffer.from(rows[0].payload)).toEqual(first);
	} finally {
		await store.close();
	}
});

it.each([
	{ MESSAGE: '{"b":2,"a":1}' },
	{ _UID: "0" },
	{ BINARY: [0, 255, 13] },
	{ MULTIPLE: ["first", null, [0, 2]] },
	{ LARGE: "restored" },
	{ EXTRA: "new" },
	{ MESSAGE: undefined },
	{ __REALTIME_TIMESTAMP: "1700000000000001" },
])("rejects changed journal values without advancing or partially committing: %j", async (change) => {
	const { store } = await open();
	try {
		const pipeline = new DiagnosticEvidencePipeline(store);
		await pipeline.ingestJournal("journal:test", Buffer.from(JSON.stringify(entry())));
		await expect(
			pipeline.ingestJournalBatch("journal:test", [
				reordered(entry("second")),
				reordered({ ...entry(), ...change }),
			]),
		).rejects.toThrow(/occurrence_conflict|batch_conflict/);
		expect(await store.getCursor("journal:test")).toBe("first");
		expect((await store.readOccurrences()).occurrences).toHaveLength(1);
	} finally {
		await store.close();
	}
});

it("does not generalize journal replay equality to generic exact payload ingestion", async () => {
	const { store } = await open();
	try {
		const batch = {
			batchId: "a",
			source: "generic",
			expectedCursor: null,
			cursor: "first",
			occurrences: [
				{ id: "one", wallTimeMs: 1, kind: "journal.json", payload: Buffer.from(JSON.stringify(entry())) },
			],
		};
		await store.ingest(batch);
		await expect(
			store.ingest({
				...batch,
				batchId: "b",
				expectedCursor: "first",
				occurrences: [{ ...batch.occurrences[0], payload: reordered(entry()) }],
			}),
		).rejects.toThrow("occurrence_conflict");
	} finally {
		await store.close();
	}
});

it.skipIf(!process.env.PRIME_AGENT_JOURNAL_REPLAY_PAIRS)(
	"replays retained native journal serializations without changing captured bytes",
	async () => {
		const pairs = JSON.parse(await readFile(process.env.PRIME_AGENT_JOURNAL_REPLAY_PAIRS!, "utf8")) as {
			first: string;
			replay: string;
		}[];
		const { store } = await open();
		try {
			const pipeline = new DiagnosticEvidencePipeline(store);
			for (const pair of pairs) await pipeline.ingestJournal("journal:native-replay", Buffer.from(pair.first));
			const original = (await store.readOccurrences()).occurrences;
			for (const pair of pairs) await pipeline.ingestJournal("journal:native-replay", Buffer.from(pair.replay));
			expect((await store.readOccurrences()).occurrences).toEqual(original);
			expect(original).toHaveLength(pairs.length);
		} finally {
			await store.close();
		}
	},
);
