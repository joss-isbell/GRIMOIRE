import {
	closeSync,
	constants,
	fstatSync,
	lstatSync,
	mkdirSync,
	openSync,
	readFileSync,
	renameSync,
	rmdirSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { getProcessStartId } from "../../core/session-lease.js";

interface Owner {
	version: 1;
	machineId: string;
	bootId: string;
	pid: number;
	processStartId: string;
}
export interface CasTransaction {
	release(): void;
}
const held = new Map<string, { count: number; transaction: CasTransaction }>();

function smallSystemText(path: string): string {
	let fd: number | undefined;
	try {
		fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const value = readFileSync(fd, "utf8").trim();
		return value;
	} catch {
		return "";
	} finally {
		if (fd !== undefined)
			try {
				closeSync(fd);
			} catch {}
	}
}
function ownerIdentity(): Owner | undefined {
	const machineId = smallSystemText("/etc/machine-id");
	const bootId = smallSystemText("/proc/sys/kernel/random/boot_id");
	const processStartId = getProcessStartId(process.pid);
	return machineId && bootId && processStartId
		? { version: 1, machineId, bootId, pid: process.pid, processStartId }
		: undefined;
}
function readOwner(path: string): Owner | undefined {
	let descriptor: number | undefined;
	try {
		const stat = lstatSync(path);
		if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4096 || (stat.mode & 0o077) !== 0)
			return undefined;
		descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const opened = fstatSync(descriptor);
		if (!opened.isFile() || opened.dev !== stat.dev || opened.ino !== stat.ino) return undefined;
		const value = JSON.parse(readFileSync(descriptor, "utf8")) as Owner;
		return value.version === 1 &&
			typeof value.machineId === "string" &&
			value.machineId &&
			typeof value.bootId === "string" &&
			value.bootId &&
			Number.isSafeInteger(value.pid) &&
			value.pid > 0 &&
			typeof value.processStartId === "string" &&
			value.processStartId
			? value
			: undefined;
	} catch {
		return undefined;
	} finally {
		if (descriptor !== undefined)
			try {
				closeSync(descriptor);
			} catch {}
	}
}

export function acquireIncidentCasTransaction(recorderRoot: string): CasTransaction | undefined {
	const existing = held.get(recorderRoot);
	if (existing) {
		existing.count += 1;
		return {
			release: () => {
				const current = held.get(recorderRoot);
				if (current && --current.count === 0) {
					held.delete(recorderRoot);
					current.transaction.release();
				}
			},
		};
	}
	const owner = ownerIdentity();
	if (!owner) return undefined;
	const lockPath = join(recorderRoot, ".cas-transaction");
	const ownerPath = join(lockPath, "owner.json");
	const tryCreate = (): boolean => {
		let created = false;
		try {
			mkdirSync(lockPath, { mode: 0o700 });
			created = true;
			writeFileSync(ownerPath, `${JSON.stringify(owner)}\n`, { mode: 0o600, flag: "wx" });
			return true;
		} catch {
			if (created) {
				try {
					unlinkSync(ownerPath);
				} catch {}
				try {
					rmdirSync(lockPath);
				} catch {}
			}
			return false;
		}
	};
	if (!tryCreate()) {
		const observed = readOwner(ownerPath);
		if (!observed) return undefined;
		const sameHost = observed.machineId === owner.machineId && observed.bootId === owner.bootId;
		const live = sameHost && getProcessStartId(observed.pid) === observed.processStartId;
		if (live) return undefined;
		if (!sameHost) return undefined;
		const stale = `${lockPath}.stale-${process.pid}-${Date.now()}`;
		try {
			renameSync(lockPath, stale);
		} catch {
			return undefined;
		}
		try {
			unlinkSync(join(stale, "owner.json"));
			rmdirSync(stale);
		} catch {
			return undefined;
		}
		if (!tryCreate()) return undefined;
	}
	const lockStat = lstatSync(lockPath);
	let released = false;
	const transaction: CasTransaction = {
		release: () => {
			if (released) return;
			released = true;
			try {
				const current = lstatSync(lockPath);
				if (!current.isDirectory() || current.dev !== lockStat.dev || current.ino !== lockStat.ino) return;
				const currentOwner = readOwner(ownerPath);
				if (!currentOwner || currentOwner.pid !== owner.pid || currentOwner.processStartId !== owner.processStartId)
					return;
				unlinkSync(ownerPath);
				rmdirSync(lockPath);
			} catch {}
		},
	};
	held.set(recorderRoot, { count: 1, transaction });
	return {
		release: () => {
			const current = held.get(recorderRoot);
			if (current && --current.count === 0) {
				held.delete(recorderRoot);
				current.transaction.release();
			}
		},
	};
}
