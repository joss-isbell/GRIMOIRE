import { afterEach, describe, expect, it, vi } from "vitest";
import {
	INCIDENT_RECORDER_SERVICE_SEAL_FENCE_MAX_IDENTITIES,
	type IncidentRecorderRunIdentitySealResult,
	IncidentRecorderServiceIdentitySealFenceSaturatedError,
	IncidentRecorderWriter,
	type IncidentRecorderWriterOptions,
} from "../src/modes/daemon/incident-recorder-writer.js";

const writers: IncidentRecorderWriter[] = [];

afterEach(async () => {
	await Promise.all(writers.splice(0).map((writer) => writer.stop(1)));
});

function identity(index: number, runPrefix = "11111111", tokenPrefix = "22222222") {
	const suffix = index.toString(16).padStart(12, "0");
	return {
		runId: `${runPrefix}-1111-4111-8111-${suffix}`,
		runToken: `${tokenPrefix}-2222-4222-8222-${suffix}`,
	};
}

function constantTokenIdentity(index: number) {
	const suffix = index.toString(16).padStart(12, "0");
	return {
		runId: `11111111-1111-4111-8111-${suffix}`,
		runToken: "22222222-2222-4222-8222-222222222222",
	};
}

function writer(options: Partial<IncidentRecorderWriterOptions> = {}): IncidentRecorderWriter {
	const value = new IncidentRecorderWriter({
		runDir: "unused",
		runId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		runToken: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		serviceSink: true,
		...options,
	});
	writers.push(value);
	return value;
}

function sealFor(identityValue: ReturnType<typeof identity>): IncidentRecorderRunIdentitySealResult {
	return {
		schemaVersion: 1,
		state: "sealed",
		runId: identityValue.runId,
		runToken: identityValue.runToken,
		terminal: {
			type: "capture_channel_terminal",
			admission: null,
			frontier: null,
		},
		loss: {
			emitter: { records: 0, bytes: 0 },
			drainTimeout: {
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 0, bytes: 0 },
			},
			terminalRelay: {
				definite: { records: 0, bytes: 0 },
				uncertain: { records: 1, bytes: 0 },
			},
		},
	};
}

describe("incident recorder writer identity seals", () => {
	it("uses an exact, never-evicted fence after a known Bloom collision", () => {
		const value = writer({ serviceIdentitySealFenceMaxIdentities: 4_096 });
		const fenced = Array.from({ length: 4_094 }, (_unused, index) => constantTokenIdentity(index + 1));
		for (const item of fenced) expect(value.fenceRunIdentity(item)).toBeDefined();

		const collisionCandidate = {
			runId: "11111111-1111-4111-8111-0000000070a1",
			runToken: "22222222-2222-4222-8222-222222222222",
		};
		expect(value.recordDerivedForRun(collisionCandidate, "recorder-control", "fresh", {}).accepted).toBe(true);
		for (const item of fenced)
			expect(value.recordDerivedForRun(item, "recorder-control", "old", {})).toMatchObject({
				accepted: false,
				reason: "run_identity_sealed",
			});
	});

	it("retains existing identities when the exact fence reaches injected capacity", () => {
		const onSaturated = vi.fn();
		const value = writer({
			serviceIdentitySealFenceMaxIdentities: 1,
			onServiceIdentitySealFenceSaturated: onSaturated,
		});
		const first = identity(1);
		const second = identity(2);

		value.fenceRunIdentity(first);
		expect(() => value.fenceRunIdentity(second)).toThrow(IncidentRecorderServiceIdentitySealFenceSaturatedError);
		expect(() => value.fenceRunIdentity(second)).toThrow(IncidentRecorderServiceIdentitySealFenceSaturatedError);
		expect(onSaturated).toHaveBeenCalledOnce();
		expect(onSaturated.mock.calls[0]?.[0]).toMatchObject({
			code: "INCIDENT_RECORDER_SERVICE_IDENTITY_SEAL_FENCE_SATURATED",
			identity: second,
			maxIdentities: 1,
		});
		expect(value.recordDerivedForRun(first, "recorder-control", "late", {})).toMatchObject({
			accepted: false,
			reason: "run_identity_sealed",
		});
		// Saturation is scoped to new exact fences and does not blind the writer's
		// own channel or discard a fresh identity's first admitted occurrence.
		expect(value.recordDerived("recorder-control", "fresh", {}).accepted).toBe(true);
		expect(value.recordDerivedForRun(second, "recorder-control", "fresh", {}).accepted).toBe(true);
	});

	it("reserves the fence before stopping an active emitter", () => {
		const value = writer({ serviceIdentitySealFenceMaxIdentities: 1 });
		const alreadyFenced = identity(3);
		const active = identity(4);

		value.fenceRunIdentity(alreadyFenced);
		expect(value.recordDerivedForRun(active, "recorder-control", "queued", {}).accepted).toBe(true);
		// The first identity owns the only fence slot; a second seal cannot stop or
		// otherwise alter the active identity's already-admitted emitter.
		expect(() => value.sealRunIdentity(active, 1)).toThrow(IncidentRecorderServiceIdentitySealFenceSaturatedError);
		expect(value.recordDerivedForRun(active, "recorder-control", "after_capacity", {}).accepted).toBe(true);
		expect(value.recordDerivedForRun(alreadyFenced, "recorder-control", "late", {})).toMatchObject({
			accepted: false,
			reason: "run_identity_sealed",
		});
	});

	it("keeps default adoption exact while durable replay avoids process retention", () => {
		const adopted = writer();
		const replayed = writer();
		const first = identity(5, "33333333", "44444444");
		const durableSeal = sealFor(first);

		expect(adopted.adoptRunIdentitySeal(durableSeal)).toMatchObject({ adopted: true, disposition: "adopted" });
		expect(adopted.recordDerivedForRun(first, "recorder-control", "late", {})).toMatchObject({
			accepted: false,
			reason: "run_identity_sealed",
		});
		expect(replayed.adoptRunIdentitySeal(durableSeal, { durableReplay: true })).toMatchObject({
			adopted: true,
			disposition: "adopted",
		});
		expect(replayed.recordDerivedForRun(first, "recorder-control", "replayed", {}).accepted).toBe(true);
		expect(replayed.adoptRunIdentitySeal(durableSeal, { durableReplay: true })).toMatchObject({
			adopted: true,
			disposition: "adopted",
		});
		expect(replayed.recordDerivedForRun(first, "recorder-control", "after_fence", {})).toMatchObject({
			accepted: false,
			reason: "run_identity_sealed",
		});
	});

	it("does not consume local fence or result-cache capacity for durable replay", () => {
		const value = writer({ serviceIdentitySealFenceMaxIdentities: 1 });
		const replayed = Array.from({ length: 65 }, (_unused, index) => sealFor(identity(index, "12345678", "87654321")));
		for (const seal of replayed)
			expect(value.adoptRunIdentitySeal(seal, { durableReplay: true })).toMatchObject({
				adopted: true,
				disposition: "adopted",
			});
		// Durable replay is validation-only while no local emitter exists. A replay
		// therefore cannot fill either bounded process cache or block a new run.
		expect(
			value.recordDerivedForRun(identity(10_000, "12345678", "87654321"), "recorder-control", "fresh", {}).accepted,
		).toBe(true);
	});

	it("rejects default adoption while an identity is active or stopping", () => {
		const value = writer();
		const active = identity(6, "55555555", "66666666");
		expect(value.recordDerivedForRun(active, "recorder-control", "active", {}).accepted).toBe(true);
		expect(value.adoptRunIdentitySeal(sealFor(active))).toEqual({
			adopted: false,
			disposition: "rejected",
			reason: "run_identity_active_or_stopping",
		});
	});

	it("validates durable replay identities and fences local emitters explicitly", () => {
		const value = writer();
		const local = identity(7, "77777777", "88888888");
		const localSeal = sealFor(local);
		expect(() =>
			value.fenceRunIdentity({ runId: "invalid", runToken: local.runToken }, { durableReplay: true }),
		).toThrow(/Invalid incident-recorder service identity/);
		expect(value.recordDerivedForRun(local, "recorder-control", "active", {}).accepted).toBe(true);
		expect(value.adoptRunIdentitySeal(localSeal, { durableReplay: true })).toMatchObject({ adopted: true });
		expect(value.recordDerivedForRun(local, "recorder-control", "late", {})).toMatchObject({
			accepted: false,
			reason: "run_identity_sealed",
		});
	});

	it.each([1, 2, 4, 64, 4_096])("accepts exact-fence capacity injection %d", (capacity) => {
		const value = writer({ serviceIdentitySealFenceMaxIdentities: capacity });
		const fenced = Array.from({ length: capacity }, (_unused, index) => identity(index, "99999999", "aaaaaaa1"));
		for (const item of fenced) value.fenceRunIdentity(item);
		const item = identity(capacity + 10, "99999999", "aaaaaaa2");
		expect(value.recordDerivedForRun(fenced[0]!, "recorder-control", "late", {})).toMatchObject({
			accepted: false,
			reason: "run_identity_sealed",
		});
		if (capacity < INCIDENT_RECORDER_SERVICE_SEAL_FENCE_MAX_IDENTITIES) {
			const fresh = item;
			expect(() => value.fenceRunIdentity(fresh)).toThrow(IncidentRecorderServiceIdentitySealFenceSaturatedError);
		}
	});
});
