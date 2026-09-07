import {
	acquireIncidentRecorderWriterNormalLease,
	acquireIncidentRecorderWriterRecoveryLease,
	type IncidentRecorderWriterLifecycleAdmissionContract,
	type IncidentRecorderWriterLifecycleLease,
	inspectIncidentRecorderWriterLifecycleLeaseMode,
} from "./incident-recorder-writer-lifecycle.js";

export type IncidentRecorderServiceWriterModeResult =
	| { state: "normal" | "recovery" }
	| { state: "pending"; reason: "normal_holders_active" }
	| { state: "unavailable"; reason: string };

/** Owns the order of writer shutdown, exclusion handoff, and writer restart. */
export class IncidentRecorderServiceWriterLifecycle {
	private heldLease?: IncidentRecorderWriterLifecycleLease;
	private heldMode?: "normal" | "recovery";
	private writersOpen = false;
	private normalReady = false;
	private transitioning = false;
	private closed = false;

	constructor(
		private readonly agentDir: string,
		private readonly contract: IncidentRecorderWriterLifecycleAdmissionContract,
		private readonly writers: {
			startNormalWriters(): Promise<void>;
			/** Must close every writer and the segment store, including on a failed start. */
			stopNormalWriters(): Promise<void>;
		},
	) {}

	get normalLease(): IncidentRecorderWriterLifecycleLease | undefined {
		return this.writersOpen && inspectIncidentRecorderWriterLifecycleLeaseMode(this.heldLease) === "normal"
			? this.heldLease
			: undefined;
	}

	get recoveryLease(): IncidentRecorderWriterLifecycleLease | undefined {
		return !this.transitioning && inspectIncidentRecorderWriterLifecycleLeaseMode(this.heldLease) === "recovery"
			? this.heldLease
			: undefined;
	}

	private async stopWriters(): Promise<void> {
		if (!this.writersOpen) return;
		this.normalReady = false;
		await this.writers.stopNormalWriters();
		this.writersOpen = false;
	}

	private heldLeaseAdmitted(): boolean {
		return this.heldLease?.withRoot(() => true).state === "committed";
	}

	private releaseHeld(): boolean {
		if (this.writersOpen) throw new Error("Recorder writers must close before their lifecycle lease is released");
		if (!this.heldLease) return true;
		const released = this.heldLease.release();
		if (released.state !== "released") return false;
		this.heldLease = undefined;
		this.heldMode = undefined;
		return true;
	}

	private async transition(
		operation: () => Promise<IncidentRecorderServiceWriterModeResult>,
	): Promise<IncidentRecorderServiceWriterModeResult> {
		if (this.closed) return { state: "unavailable", reason: "closed" };
		if (this.transitioning) throw new Error("Recorder writer lifecycle transition is already in progress");
		this.transitioning = true;
		try {
			return await operation();
		} finally {
			this.transitioning = false;
		}
	}

	async enterNormal(): Promise<IncidentRecorderServiceWriterModeResult> {
		return this.transition(async () => {
			if (this.normalReady && this.normalLease && this.heldLeaseAdmitted()) return { state: "normal" };
			await this.stopWriters();
			if (!this.releaseHeld()) return { state: "unavailable", reason: "lease_release_pending" };
			const admission = acquireIncidentRecorderWriterNormalLease({ agentDir: this.agentDir }, this.contract);
			if (admission.state !== "acquired") return admission;
			this.heldLease = admission.lease;
			this.heldMode = "normal";
			this.writersOpen = true;
			try {
				await this.writers.startNormalWriters();
				if (!this.normalLease || !this.heldLeaseAdmitted())
					throw new Error("Recorder writer lease was lost during startup");
				this.normalReady = true;
				return { state: "normal" };
			} catch (startError) {
				try {
					await this.stopWriters();
					if (!this.releaseHeld()) throw new Error("Recorder writer startup cleanup left a pending lease release");
				} catch (cleanupError) {
					throw new AggregateError([startError, cleanupError], "Recorder writer startup and cleanup failed");
				}
				throw startError;
			}
		});
	}

	async enterRecovery(): Promise<IncidentRecorderServiceWriterModeResult> {
		return this.transition(async () => {
			if (
				this.heldMode === "recovery" &&
				inspectIncidentRecorderWriterLifecycleLeaseMode(this.heldLease) === "recovery" &&
				this.heldLeaseAdmitted()
			)
				return { state: "recovery" };
			await this.stopWriters();
			if (!this.releaseHeld()) return { state: "unavailable", reason: "lease_release_pending" };
			const admission = acquireIncidentRecorderWriterRecoveryLease({ agentDir: this.agentDir }, this.contract);
			if (admission.state !== "acquired") return admission;
			this.heldLease = admission.lease;
			this.heldMode = "recovery";
			return { state: "recovery" };
		});
	}

	async close(): Promise<void> {
		if (this.closed) return;
		const result = await this.transition(async () => {
			await this.stopWriters();
			if (!this.releaseHeld()) return { state: "unavailable", reason: "lease_release_pending" };
			this.closed = true;
			return { state: "normal" };
		});
		if (result.state === "unavailable") throw new Error(`Recorder writer lifecycle close failed: ${result.reason}`);
	}
}
