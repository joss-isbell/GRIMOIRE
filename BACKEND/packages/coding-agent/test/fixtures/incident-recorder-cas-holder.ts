import { acquireIncidentCasTransaction } from "../../src/modes/daemon/incident-recorder-cas-transaction.js";

const recorderRoot = process.argv[2];
if (!recorderRoot) throw new Error("recorder root is required");

const transaction = acquireIncidentCasTransaction(recorderRoot);
if (!transaction) throw new Error("could not acquire incident CAS transaction");

process.stdout.write("ready\n");
process.stdin.setEncoding("utf8");
await new Promise<void>((resolve) => {
	process.stdin.on("data", (chunk: string) => {
		if (chunk.split(/\r?\n/).includes("release")) resolve();
	});
});
transaction.release();
process.stdout.write("released\n");
