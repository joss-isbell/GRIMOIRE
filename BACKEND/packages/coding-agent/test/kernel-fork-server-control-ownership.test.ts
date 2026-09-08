import { type ChildProcess, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createConnection, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type ForkServerDiagnosticEvent, subscribeKernelDiagnostics } from "../src/core/kernel/diagnostics.js";
import { type ForkedKernelHandle, ForkServer, ForkServerUnavailable } from "../src/core/kernel/fork-server.js";

const havePython = process.platform !== "win32" && spawnSync("python3", ["-V"]).status === 0;

interface ServerInternals {
	socketDir?: string;
	conn?: Socket;
	proc?: ChildProcess;
}

describe.skipIf(!havePython)("forkserver control connection ownership", () => {
	let root: string;
	let server: ForkServer;
	let pythonPath: string | undefined;
	const children: ForkedKernelHandle[] = [];
	const peers: Socket[] = [];
	const events: ForkServerDiagnosticEvent[] = [];
	let unsubscribe: () => void;

	beforeEach(() => {
		root = mkdtempSync(join(tmpdir(), "prime-forkserver-ownership-"));
		const stubs = join(root, "stubs");
		mkdirSync(join(stubs, "ipykernel"), { recursive: true });
		for (const name of ["IPython.py", "jupyter_client.py", "nest_asyncio.py", "ipykernel/__init__.py"]) {
			writeFileSync(join(stubs, name), "");
		}
		writeFileSync(
			join(stubs, "ipykernel/kernelapp.py"),
			[
				"import time",
				"class IPKernelApp:",
				"    @classmethod",
				"    def clear_instance(cls): pass",
				"    @classmethod",
				"    def instance(cls, **kwargs): return cls()",
				"    def initialize(self, argv): pass",
				"    def start(self):",
				"        while True: time.sleep(1)",
			].join("\n"),
		);
		pythonPath = process.env.PYTHONPATH;
		process.env.PYTHONPATH = stubs;
		events.length = 0;
		unsubscribe = subscribeKernelDiagnostics((event) => {
			if (event.type === "forkserver_lifecycle") events.push(event);
		});
		server = new ForkServer({ python: "python3" });
	});

	afterEach(async () => {
		for (const peer of peers.splice(0)) peer.destroy();
		server.dispose();
		const proc = (server as unknown as ServerInternals).proc;
		if (proc) {
			await vi.waitFor(() => expect(proc.exitCode !== null || proc.signalCode !== null).toBe(true));
		}
		unsubscribe();
		for (const child of children.splice(0)) {
			try {
				process.kill(child.pid, "SIGKILL");
			} catch {
				// The owned stub child may already have exited.
			}
		}
		if (pythonPath === undefined) delete process.env.PYTHONPATH;
		else process.env.PYTHONPATH = pythonPath;
		rmSync(root, { recursive: true, force: true });
	});

	async function startChild(): Promise<ForkedKernelHandle> {
		const child = await server.spawnKernel({ connectionPath: join(root, "connection.json") });
		children.push(child);
		return child;
	}

	async function connectPeer(): Promise<Socket> {
		const internals = server as unknown as ServerInternals;
		await vi.waitFor(() => expect(existsSync(join(internals.socketDir ?? root, "control.sock"))).toBe(true));
		const socket = createConnection(join(internals.socketDir!, "control.sock"));
		peers.push(socket);
		await new Promise<void>((resolve, reject) => {
			socket.once("connect", resolve);
			socket.once("error", reject);
		});
		socket.on("error", () => {});
		return socket;
	}

	it("rejects unrelated status connections without replacing or closing the live control peer", async () => {
		const child = await startChild();
		const internals = server as unknown as ServerInternals;
		const owner = internals.conn;
		const processId = internals.proc?.pid;
		for (const payload of ["", '{"type":"client_hello"}\n', '{"type":"ready"}\n']) {
			const peer = await connectPeer();
			peer.end(payload);
			await vi.waitFor(() => expect(peer.destroyed).toBe(true));
			expect(server.isDead).toBe(false);
			expect(internals.conn).toBe(owner);
			expect(internals.proc?.pid).toBe(processId);
			expect(await child.isAlive()).toBe(true);
		}
		expect(events.filter((event) => event.phase === "peer_rejected")).toHaveLength(3);
		expect(events.some((event) => event.phase === "shutdown_requested")).toBe(false);
	}, 15_000);

	it("ignores pre-start probes and incomplete or oversized greetings while the real child connects", async () => {
		server.dispose();
		const gate = join(root, "allow-python");
		const wrapper = join(root, "delayed-python");
		writeFileSync(
			wrapper,
			`#!/usr/bin/env python3\nimport os, sys, time\nwhile not os.path.exists(${JSON.stringify(gate)}): time.sleep(0.01)\nos.execvp('python3', ['python3', *sys.argv[1:]])\n`,
			{ mode: 0o700 },
		);
		server = new ForkServer({ python: wrapper });
		const starting = startChild();
		void starting.catch(() => {});
		for (const payload of [
			'{"type":"client_hello"}\n',
			'{"type":"control_hello","capability":"wrong"}\n',
			"bad-json\n",
		]) {
			const closed = await connectPeer();
			closed.end(payload);
			await vi.waitFor(() => expect(closed.destroyed).toBe(true));
			expect(server.isDead).toBe(false);
		}
		const partial = await connectPeer();
		partial.write('{"type":"');
		const oversized = await connectPeer();
		oversized.write("x".repeat(8192));
		await vi.waitFor(() => expect(oversized.destroyed).toBe(true));
		const stalled = await Promise.all(Array.from({ length: 15 }, () => connectPeer()));
		const excess = await connectPeer();
		await vi.waitFor(() => expect(excess.destroyed).toBe(true));
		expect(server.isDead).toBe(false);
		for (const peer of stalled) peer.end();
		await vi.waitFor(() => expect(stalled.every((peer) => peer.destroyed)).toBe(true));
		writeFileSync(gate, "go");
		const child = await starting;
		expect(await child.isAlive()).toBe(true);
		expect(server.isDead).toBe(false);
		await vi.waitFor(() => expect(partial.destroyed && oversized.destroyed).toBe(true));
		expect(await child.isAlive()).toBe(true);
	}, 15_000);

	it("still terminates the owned forkserver when its authenticated control connection closes", async () => {
		const child = await startChild();
		const internals = server as unknown as ServerInternals;
		internals.conn!.destroy();
		await vi.waitFor(() => expect(server.isDead).toBe(true));
		await expect(child.isAlive()).rejects.toBeInstanceOf(ForkServerUnavailable);
		await vi.waitFor(() => expect(internals.proc?.signalCode).toBe("SIGTERM"));
		expect(events).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ phase: "control_closed", reason: "authenticated_socket_closed" }),
				expect.objectContaining({ phase: "shutdown_requested", reason: "authenticated_socket_closed" }),
				expect.objectContaining({ phase: "process_exit", code: null, signal: "SIGTERM" }),
			]),
		);
		const started = events.find((event) => event.phase === "peer_authenticated")!;
		expect(events.every((event) => event.forkserverInstanceId === started.forkserverInstanceId)).toBe(true);
		expect(events.find((event) => event.phase === "process_exit")?.forkserverProcessStartId).toBe(
			started.forkserverProcessStartId,
		);
	}, 15_000);
});
