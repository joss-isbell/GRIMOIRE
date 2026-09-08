import { expect, it } from "vitest";
import {
	encodeKernelDiagnosticBridgeEvent,
	KernelDiagnosticBridgeDecoder,
} from "../src/core/kernel/diagnostic-bridge.js";
import { type KernelDiagnosticEvent, subscribeKernelDiagnostics } from "../src/core/kernel/diagnostics.js";
import { KernelManager } from "../src/core/kernel/index.js";

type Channel = "shell" | "control" | "iopub";
type Internals = Record<Channel, AsyncIterable<Buffer[]>> & {
	state: "starting" | "running" | "shutdown";
	startGeneration: number;
	startKernelDiagnostics(mode: "direct", pid: number, startId: string): void;
	runShellObservationPump(): Promise<void>;
	runControlPump(): Promise<void>;
	runIopubPump(): Promise<void>;
};
for (const channel of ["shell", "control", "iopub"] as const) {
	for (const state of channel === "shell" ? (["running"] as const) : (["starting", "running"] as const)) {
		for (const outcome of ["ended", "failed"] as const)
			it(`observes current ${channel} ${outcome} without changing the ${state} kernel`, async () => {
				const manager = new KernelManager({ sessionId: "channel-unit" });
				const internals = manager as unknown as Internals;
				internals.state = state;
				internals.startGeneration = 3;
				internals.startKernelDiagnostics("direct", 10, "100");
				internals[channel] = {
					async *[Symbol.asyncIterator]() {
						if (outcome === "failed") throw new Error("receive failed");
						yield* [] as Buffer[][];
					},
				};
				const events: KernelDiagnosticEvent[] = [];
				const unsubscribe = subscribeKernelDiagnostics((event) => events.push(event));
				try {
					await internals[
						channel === "shell"
							? "runShellObservationPump"
							: channel === "control"
								? "runControlPump"
								: "runIopubPump"
					]();
					expect(events).toHaveLength(1);
					expect(events[0]).toMatchObject({
						kernelGeneration: 3,
						kernelPid: 10,
						kernelProcessStartId: "100",
						observerPid: process.pid,
						monotonicNs: expect.stringMatching(/^\d+$/),
					});
					expect(events[0]).toMatchObject(
						channel === "shell" && outcome === "failed"
							? { observation: "shell_unavailable" }
							: { type: "kernel_channel_fault", channel },
					);
					expect(internals.state).toBe(state);
					const capability = Buffer.alloc(32, 7).toString("base64url");
					const decoded: KernelDiagnosticEvent[] = [];
					const decoder = new KernelDiagnosticBridgeDecoder({
						capability,
						onEvent: (event) => decoded.push(event),
						onDrop: () => {},
						onLoss: () => {
							throw new Error("bridge loss");
						},
					});
					decoder.push(encodeKernelDiagnosticBridgeEvent(events[0]!, capability)!);
					decoder.end();
					expect(decoded).toEqual(events);
				} finally {
					unsubscribe();
				}
			});
		for (const stale of ["socket", "generation", "shutdown"] as const)
			for (const outcome of ["ended", "failed"] as const)
				it(`ignores ${state} ${channel} ${outcome} after ${stale} supersedes its receive`, async () => {
					const manager = new KernelManager({ sessionId: "channel-stale-unit" });
					const internals = manager as unknown as Internals;
					internals.state = state;
					internals.startGeneration = 3;
					internals.startKernelDiagnostics("direct", 10, "100");
					let release!: () => void;
					const wait = new Promise<void>((resolve) => {
						release = resolve;
					});
					internals[channel] = {
						async *[Symbol.asyncIterator]() {
							await wait;
							if (outcome === "failed") throw new Error("old receive failed");
							yield* [] as Buffer[][];
						},
					};
					const events: KernelDiagnosticEvent[] = [];
					const unsubscribe = subscribeKernelDiagnostics((event) => events.push(event));
					try {
						const pump =
							internals[
								channel === "shell"
									? "runShellObservationPump"
									: channel === "control"
										? "runControlPump"
										: "runIopubPump"
							]();
						if (stale === "socket") internals[channel] = { async *[Symbol.asyncIterator]() {} };
						else if (stale === "generation") internals.startGeneration++;
						else internals.state = "shutdown";
						release();
						await pump;
						expect(events).toEqual([]);
					} finally {
						unsubscribe();
					}
				});
	}
}
