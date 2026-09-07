import type { BigIntStats } from "node:fs";
import { lstatSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
	acquireIncidentCasTransactionDetailed,
	type CasTransaction,
	type IncidentCasRootMutation,
	type IncidentCasRootMutationResult,
	type IncidentCasTransactionReleaseResult,
	type IncidentCasTransactionRuntime,
	type IncidentCasTransactionUnavailableReason,
} from "./incident-recorder-cas-transaction.js";
import {
	type IncidentRecorderWriterLifecycleNamespaceBinding,
	type IncidentRecorderWriterLifecycleProof,
	inspectIncidentRecorderWriterLifecycleProof,
} from "./incident-recorder-writer-lifecycle.js";

export type IncidentRecorderNamespaceCasTarget = "recorder" | "incidents" | "namespace";

export interface IncidentRecorderNamespaceRoots {
	readonly recorder: IncidentCasRootMutation;
	readonly incidents: IncidentCasRootMutation;
}

export interface IncidentRecorderNamespaceCasTransaction extends CasTransaction {
	withNamespace<T>(operation: (roots: IncidentRecorderNamespaceRoots) => T): IncidentCasRootMutationResult<T>;
}

export type IncidentRecorderNamespaceCasUnavailableReason =
	| IncidentCasTransactionUnavailableReason
	| "invalid_target"
	| "namespace_changed";

export type IncidentRecorderNamespaceCasAdmission =
	| {
			state: "acquired";
			transaction: IncidentRecorderNamespaceCasTransaction;
	  }
	| {
			state: "unavailable";
			reason: IncidentRecorderNamespaceCasUnavailableReason;
	  };

const DETACHED_PENDING: IncidentCasRootMutationResult<never> = {
	state: "root_detached",
	evidence: "pending",
};

function isPromiseLike(value: unknown): boolean {
	if ((typeof value !== "object" || value === null) && typeof value !== "function") return false;
	try {
		return typeof (value as { then?: unknown }).then === "function";
	} catch {
		return true;
	}
}

function sameIdentity(
	stat: BigIntStats | undefined,
	expected: {
		dev: string;
		ino: string;
		uid: number;
		gid: number;
		mode: number;
	},
): boolean {
	return (
		stat !== undefined &&
		stat.isDirectory() &&
		!stat.isSymbolicLink() &&
		stat.dev.toString() === expected.dev &&
		stat.ino.toString() === expected.ino &&
		Number(stat.uid) === expected.uid &&
		Number(stat.gid) === expected.gid &&
		Number(stat.mode & 0o7777n) === expected.mode
	);
}

function pathIdentityMatches(
	path: string,
	expected: IncidentRecorderWriterLifecycleNamespaceBinding["agentDir"],
): boolean {
	try {
		if (!path || resolve(path) !== path || path.includes("/proc/self/fd/")) return false;
		return sameIdentity(lstatSync(path, { bigint: true }), expected);
	} catch {
		return false;
	}
}

function fixedBindingCurrent(binding: IncidentRecorderWriterLifecycleNamespaceBinding): boolean {
	const agentDir = binding.agentDir.path;
	return (
		binding.stableParent.path === dirname(agentDir) &&
		binding.recorder.path === join(agentDir, "incident-recorder") &&
		binding.incidents.path === join(agentDir, "incidents") &&
		pathIdentityMatches(binding.stableParent.path, binding.stableParent) &&
		pathIdentityMatches(agentDir, binding.agentDir) &&
		pathIdentityMatches(binding.recorder.path, binding.recorder) &&
		pathIdentityMatches(binding.incidents.path, binding.incidents)
	);
}

function fixedChildrenCurrent(
	agentRoot: IncidentCasRootMutation,
	binding: IncidentRecorderWriterLifecycleNamespaceBinding,
): boolean {
	try {
		const recorder = agentRoot.lstat(agentRoot.relative("incident-recorder"));
		const incidents = agentRoot.lstat(agentRoot.relative("incidents"));
		return sameIdentity(recorder, binding.recorder) && sameIdentity(incidents, binding.incidents);
	} catch {
		return false;
	}
}

function fixedRecorderCurrent(binding: IncidentRecorderWriterLifecycleNamespaceBinding): boolean {
	return pathIdentityMatches(binding.recorder.path, binding.recorder);
}

function releasePair(inner: CasTransaction, outer: CasTransaction): IncidentCasTransactionReleaseResult {
	let innerResult: IncidentCasTransactionReleaseResult | undefined;
	let outerResult: IncidentCasTransactionReleaseResult | undefined;
	try {
		innerResult = inner.release();
	} catch {
		innerResult = undefined;
	}
	try {
		outerResult = outer.release();
	} catch {
		outerResult = undefined;
	}
	if (!innerResult || !outerResult || innerResult.state === "pending" || outerResult.state === "pending")
		return { state: "pending", reason: "io_error" };
	return {
		state: "released",
		cleanupPending: innerResult.cleanupPending || outerResult.cleanupPending,
	};
}

function flattenRootResult<T>(
	result: IncidentCasRootMutationResult<IncidentCasRootMutationResult<T>>,
): IncidentCasRootMutationResult<T> {
	return result.state === "committed" ? result.value : result;
}

function invalidAdmission(
	reason: IncidentRecorderNamespaceCasUnavailableReason,
): IncidentRecorderNamespaceCasAdmission {
	return { state: "unavailable", reason };
}

/**
 * Acquire the v2 namespace lock pair for a lifecycle proof. The agent directory
 * CAS is always acquired first; the recorder CAS is always acquired second.
 * Incidents are a fixed child capability of the outer root, not a third lock.
 */
export function acquireIncidentRecorderNamespaceCas(
	proof: IncidentRecorderWriterLifecycleProof | undefined,
	target: IncidentRecorderNamespaceCasTarget,
	runtime: IncidentCasTransactionRuntime = {},
): IncidentRecorderNamespaceCasAdmission {
	if (target !== "recorder" && target !== "incidents" && target !== "namespace")
		return invalidAdmission("invalid_target");
	const binding = inspectIncidentRecorderWriterLifecycleProof(proof);
	if (!binding || !fixedBindingCurrent(binding)) return invalidAdmission("namespace_changed");

	const outerAdmission = acquireIncidentCasTransactionDetailed(binding.agentDir.path, runtime);
	if (outerAdmission.state === "unavailable") return invalidAdmission(outerAdmission.reason);
	const outer = outerAdmission.transaction;
	let inner: CasTransaction | undefined;
	try {
		const outerCheck = outer.withRoot(
			(agentRoot) => fixedBindingCurrent(binding) && fixedChildrenCurrent(agentRoot, binding),
		);
		if (outerCheck.state !== "committed" || outerCheck.value !== true) {
			outer.release();
			return invalidAdmission("namespace_changed");
		}
		const innerAdmission = acquireIncidentCasTransactionDetailed(binding.recorder.path, runtime);
		if (innerAdmission.state === "unavailable") {
			const release = outer.release();
			return release.state === "pending"
				? invalidAdmission("local_ownership_changed")
				: invalidAdmission(innerAdmission.reason);
		}
		inner = innerAdmission.transaction;
		const innerCheck = inner.withRoot(() => fixedRecorderCurrent(binding));
		if (innerCheck.state !== "committed" || innerCheck.value !== true) {
			releasePair(inner, outer);
			return invalidAdmission("namespace_changed");
		}
	} catch (error) {
		if (inner) releasePair(inner, outer);
		else {
			try {
				outer.release();
			} catch {}
		}
		throw error;
	}

	let released = false;
	let operationActive = false;
	const transaction: IncidentRecorderNamespaceCasTransaction = {
		withRoot: <T>(operation: (root: IncidentCasRootMutation) => T) => {
			if (target === "namespace") return DETACHED_PENDING as IncidentCasRootMutationResult<T>;
			if (operationActive) throw new TypeError("namespace CAS mutation is not reentrant");
			operationActive = true;
			let operationThrew = false;
			try {
				const result = outer.withRoot((agentRoot) => {
					if (!fixedBindingCurrent(binding) || !fixedChildrenCurrent(agentRoot, binding)) return DETACHED_PENDING;
					try {
						const invoke = (root: IncidentCasRootMutation): T => {
							try {
								const value = operation(root);
								if (isPromiseLike(value))
									throw new TypeError("namespace CAS operation must complete synchronously");
								return value;
							} catch (error) {
								operationThrew = true;
								throw error;
							}
						};
						return flattenRootResult(
							inner.withRoot((recorderRoot) =>
								target === "recorder"
									? { state: "committed", value: invoke(recorderRoot) }
									: agentRoot.withDirectory(agentRoot.relative("incidents"), (incidentsRoot) => ({
											state: "committed",
											value: invoke(incidentsRoot),
										})),
							),
						);
					} catch (error) {
						if (operationThrew) throw error;
						return DETACHED_PENDING;
					}
				});
				return flattenRootResult(result);
			} finally {
				operationActive = false;
			}
		},
		withNamespace: <T>(operation: (roots: IncidentRecorderNamespaceRoots) => T) => {
			if (target !== "namespace") return DETACHED_PENDING as IncidentCasRootMutationResult<T>;
			if (operationActive) throw new TypeError("namespace CAS mutation is not reentrant");
			operationActive = true;
			let operationThrew = false;
			try {
				const result = outer.withRoot((agentRoot) => {
					if (!fixedBindingCurrent(binding) || !fixedChildrenCurrent(agentRoot, binding)) return DETACHED_PENDING;
					try {
						return agentRoot.withDirectory(agentRoot.relative("incidents"), (incidentsRoot) =>
							inner!.withRoot((recorderRoot) => {
								try {
									const value = operation(
										Object.freeze({
											recorder: recorderRoot,
											incidents: incidentsRoot,
										}),
									);
									if (isPromiseLike(value))
										throw new TypeError("namespace CAS operation must complete synchronously");
									return value;
								} catch (error) {
									operationThrew = true;
									throw error;
								}
							}),
						);
					} catch (error) {
						if (operationThrew) throw error;
						return DETACHED_PENDING;
					}
				});
				return flattenRootResult(result);
			} finally {
				operationActive = false;
			}
		},
		release: () => {
			if (operationActive) throw new TypeError("namespace CAS release is not reentrant");
			if (released) return { state: "released", cleanupPending: false };
			const result = releasePair(inner!, outer);
			if (result.state === "released") released = true;
			return result;
		},
	};
	return { state: "acquired", transaction: Object.freeze(transaction) };
}
