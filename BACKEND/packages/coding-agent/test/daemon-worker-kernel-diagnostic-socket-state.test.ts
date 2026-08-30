import { Socket } from "node:net";
import { describe, expect, it } from "vitest";

import { isDaemonWorkerKernelDiagnosticSocketClosed } from "../src/modes/daemon/daemon-worker-kernel-diagnostics.js";

describe("daemon worker kernel diagnostic socket state", () => {
  it("detects a socket that closes before authenticated listeners can observe close", () => {
    const socket = new Socket();
    socket.destroy();

    expect(isDaemonWorkerKernelDiagnosticSocketClosed(socket)).toBe(true);
  });
});
