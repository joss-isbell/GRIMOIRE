import { afterEach, expect, it, vi } from "vitest";
import { DaemonSupervisor } from "../src/modes/daemon/daemon-supervisor.js";
import { appendSupervisorDiagnosticEvent } from "../src/modes/daemon/incident-recorder.js";

vi.mock("../src/modes/daemon/incident-recorder.js", async (importOriginal) => ({
	...(await importOriginal<Record<string, unknown>>()),
	appendSupervisorDiagnosticEvent: vi.fn(),
}));
afterEach(() => vi.clearAllMocks());

it.each([
	{ shuttingDown: false, intentionalStop: false, status: "unexpected", reason: "worker_transport_closed" },
	{ shuttingDown: true, intentionalStop: false, status: "expected", reason: "supervisor_shutdown_transport" },
	{ shuttingDown: false, intentionalStop: true, status: "expected", reason: "worker_stop_transport" },
])("records the transport close boundary separately from process death: %j", async (scenario) => {
	const client = {};
	const worker = {
		client,
		descriptor: { workerId: "original-worker", pid: 17, processStartId: "proc:101", rootActiveSessionId: "session" },
		intentionalStop: scenario.intentionalStop,
		transcriptCaches: new Map(),
	};
	const supervisor = Object.assign(Object.create(DaemonSupervisor.prototype), {
		shuttingDown: scenario.shuttingDown,
		invalidateWorkerSessionInputPauses: vi.fn(),
		assertRecoveryAllowed: vi.fn(async () => undefined),
		isWorkerRecoveryEligible: vi.fn(() => false),
	}) as { handleWorkerClose(worker: unknown, client: unknown, error: Error): Promise<void> };
	await supervisor.handleWorkerClose(worker, client, new Error("socket closed"));
	expect(appendSupervisorDiagnosticEvent).toHaveBeenCalledWith(
		"worker_connection_closed",
		expect.objectContaining({
			workerPid: 17,
			workerProcessStartId: "proc:101",
			workerId: "original-worker",
			status: scenario.status,
			reason: scenario.reason,
		}),
	);
	expect(vi.mocked(appendSupervisorDiagnosticEvent).mock.calls).not.toContainEqual(
		expect.arrayContaining(["worker_process_exit_observed"]),
	);
	vi.clearAllMocks();
	await supervisor.handleWorkerClose(worker, client, new Error("late close"));
	expect(appendSupervisorDiagnosticEvent).not.toHaveBeenCalled();
});
