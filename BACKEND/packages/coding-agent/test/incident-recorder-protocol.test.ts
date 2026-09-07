import { describe, expect, it, vi } from "vitest";

const fixedCanonicalUuid = "123e4567-e89b-42d3-a456-426614174000";
const randomUuid = vi.hoisted(() => vi.fn(() => fixedCanonicalUuid));

vi.mock("node:crypto", async (importOriginal) => ({
	...(await importOriginal<typeof import("node:crypto")>()),
	randomUUID: randomUuid,
}));

import { newIncidentRecorderToken } from "../src/modes/daemon/incident-recorder-protocol.js";

describe("incident recorder protocol identities", () => {
	it("delegates run-token generation to canonical RFC 4122 UUID generation", () => {
		expect(newIncidentRecorderToken()).toBe(fixedCanonicalUuid);
		expect(randomUuid).toHaveBeenCalledOnce();
	});
});
