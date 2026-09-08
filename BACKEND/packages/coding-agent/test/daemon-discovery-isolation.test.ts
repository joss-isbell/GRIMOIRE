import { describe, expect, it } from "vitest";
import { parseLsofListeners, parseSsListeners } from "../src/cli/daemon-ps.js";

describe.runIf(process.platform !== "win32")("daemon discovery protocol boundaries", () => {
	const internalSockets = [
		"/tmp/prime-agent-forkserver-abcdef/control.sock",
		"/custom/tmp/prime-agent-forkserver-other/control.sock",
		"/tmp/prime-agent-1000/worker-abcd-1234.sock",
		"/other/tmp/prime-agent-42/worker-abcd-1234.sock",
		"/tmp/prime-agent-1000/diagnostics/abcdef.sock",
		"/other/tmp/prime-agent-42/diagnostics/abcdef.sock",
	];
	const publicSockets = [
		"/tmp/custom.sock",
		"/tmp/prime-agent-1000/daemon.sock",
		"/tmp/worker-custom.sock",
		"/tmp/diagnostics/service.sock",
	];
	it("never admits internal listener protocols from Linux process-name discovery", () => {
		const paths = [...internalSockets, ...publicSockets];
		const text = paths
			.map((path, index) => `u_str LISTEN 0 511 ${path} 100 * 0 users:(("prime-agent",pid=${100 + index},fd=3))`)
			.join("\n");
		expect(parseSsListeners(text, "prime-agent").map((entry) => entry.socketPath)).toEqual(publicSockets);
	});
	it("applies the same boundary to lsof fallback discovery across temp roots and users", () => {
		const text = [
			"p123",
			...internalSockets.map((path) => `n${path}`),
			...publicSockets.map((path) => `n${path}`),
		].join("\n");
		expect(parseLsofListeners(text).map((entry) => entry.socketPath)).toEqual(publicSockets);
	});
});
