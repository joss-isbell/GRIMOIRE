import stripAnsi from "strip-ansi";
import { describe, expect, it } from "vitest";
import type { DaemonInfo } from "../src/cli/daemon-ps.js";
import { formatDaemonListTable, formatUptime } from "../src/cli/daemon-ps-format.js";

describe("formatUptime", () => {
	it("formats seconds into a compact human duration", () => {
		expect(formatUptime(0)).toBe("0s");
		expect(formatUptime(45)).toBe("45s");
		expect(formatUptime(90)).toBe("1m");
		expect(formatUptime(3 * 3600)).toBe("3h");
		expect(formatUptime(5 * 86400)).toBe("5d");
		expect(formatUptime(14 * 86400)).toBe("2w");
	});

	it("returns empty for unknown uptime", () => {
		expect(formatUptime(undefined)).toBe("");
	});
});

describe("formatDaemonListTable", () => {
	it("distinguishes stale session observations from a current runtime build", () => {
		const table = stripAnsi(
			formatDaemonListTable([
				{
					socketPath: "/tmp/current.sock",
					status: "current",
					isDefault: false,
					sessionCount: 3,
					sessionObservation: "stale",
				},
				{ socketPath: "/tmp/missing.sock", status: "current", isDefault: false, sessionObservation: "unavailable" },
				{
					socketPath: "/tmp/legacy.sock",
					status: "stale",
					isDefault: false,
					sessionCount: 2,
					sessionObservation: "unknown",
				},
			]),
		);
		expect(table).toContain("3 (stale)");
		expect(table).toContain("? (unavailable)");
		expect(table).toContain("2 (unknown)");
		expect(table).toContain("current");
	});
	it("renders columns, marks the default daemon, and shows blanks for missing fields", () => {
		const daemons: DaemonInfo[] = [
			{
				socketPath: "/tmp/prime-agent-1000/daemon.sock",
				pid: 1234,
				uptimeSeconds: 7200,
				version: "0.1.5",
				protocolVersion: 1,
				sessionCount: 2,
				status: "current",
				isDefault: true,
			},
			{
				socketPath: "/tmp/orphan.sock",
				status: "orphan-file",
				isDefault: false,
			},
		];

		const table = stripAnsi(formatDaemonListTable(daemons));
		const lines = table.split("\n");
		expect(lines[0]!.trim().split(/\s+/)).toEqual(["socket", "pid", "version", "status", "sessions", "uptime"]);
		expect(table).toContain("/tmp/prime-agent-1000/daemon.sock *");
		expect(table).toContain("* default background service");
		expect(table).toContain("current");
		expect(table).toContain("orphan-file");
		expect(table).toContain("2h");
	});
});
