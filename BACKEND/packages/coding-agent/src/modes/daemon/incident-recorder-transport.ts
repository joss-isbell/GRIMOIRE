import { INCIDENT_RECORDER_PROTOCOL_MAX_FRAME_BYTES } from "./incident-recorder-protocol.js";

/**
 * fd4 is a shared SOCK_STREAM byte stream, not a record-oriented pipe. Each
 * checksummed protocol frame is therefore COBS encoded and terminated by zero.
 * Zero never occurs inside an encoded packet, so one damaged packet cannot
 * make the reader consume a later packet while looking for an in-band magic.
 */
export const INCIDENT_RECORDER_TRANSPORT_DELIMITER = 0;
export const INCIDENT_RECORDER_TRANSPORT_MAX_DECODED_PACKET_BYTES = INCIDENT_RECORDER_PROTOCOL_MAX_FRAME_BYTES;
export const INCIDENT_RECORDER_TRANSPORT_MAX_ENCODED_PACKET_BYTES =
	INCIDENT_RECORDER_TRANSPORT_MAX_DECODED_PACKET_BYTES +
	Math.floor(INCIDENT_RECORDER_TRANSPORT_MAX_DECODED_PACKET_BYTES / 254) +
	1;

export type IncidentRecorderTransportCorruptionKind =
	| "empty-packet"
	| "malformed-cobs"
	| "oversized-packet"
	| "truncated-packet"
	| "invalid-protocol-packet";

export interface IncidentRecorderTransportCorruption {
	kind: IncidentRecorderTransportCorruptionKind;
	/** Exact number of received transport bytes, including a delimiter when present. */
	wireBytes: number;
}

export function encodeIncidentRecorderTransportPacket(frame: Uint8Array): Buffer {
	if (frame.byteLength > INCIDENT_RECORDER_TRANSPORT_MAX_DECODED_PACKET_BYTES) {
		throw new Error("Incident recorder transport packet exceeds the decoded size limit");
	}
	const output = Buffer.allocUnsafe(frame.byteLength + Math.floor(frame.byteLength / 254) + 2);
	let codeOffset = 0;
	let outputOffset = 1;
	let code = 1;
	for (let index = 0; index < frame.byteLength; index += 1) {
		const byte = frame[index];
		if (byte === 0) {
			output[codeOffset] = code;
			codeOffset = outputOffset;
			outputOffset += 1;
			code = 1;
			continue;
		}
		output[outputOffset] = byte;
		outputOffset += 1;
		code += 1;
		if (code === 0xff) {
			output[codeOffset] = code;
			codeOffset = outputOffset;
			outputOffset += 1;
			code = 1;
		}
	}
	output[codeOffset] = code;
	output[outputOffset] = INCIDENT_RECORDER_TRANSPORT_DELIMITER;
	return output.subarray(0, outputOffset + 1);
}

export function decodeIncidentRecorderTransportPacket(encoded: Uint8Array): Buffer {
	if (encoded.byteLength === 0) throw new Error("Empty incident recorder transport packet");
	if (encoded.byteLength > INCIDENT_RECORDER_TRANSPORT_MAX_ENCODED_PACKET_BYTES) {
		throw new Error("Incident recorder transport packet exceeds the encoded size limit");
	}
	const output = Buffer.allocUnsafe(
		Math.min(encoded.byteLength, INCIDENT_RECORDER_TRANSPORT_MAX_DECODED_PACKET_BYTES),
	);
	let inputOffset = 0;
	let outputOffset = 0;
	while (inputOffset < encoded.byteLength) {
		const code = encoded[inputOffset];
		if (code === 0) throw new Error("Incident recorder COBS packet contains a delimiter");
		inputOffset += 1;
		const literalBytes = code - 1;
		if (inputOffset + literalBytes > encoded.byteLength) throw new Error("Malformed incident recorder COBS packet");
		if (outputOffset + literalBytes > output.length)
			throw new Error("Decoded incident recorder transport packet is too large");
		Buffer.from(encoded.buffer, encoded.byteOffset + inputOffset, literalBytes).copy(output, outputOffset);
		inputOffset += literalBytes;
		outputOffset += literalBytes;
		if (code !== 0xff && inputOffset < encoded.byteLength) {
			if (outputOffset >= output.length) throw new Error("Decoded incident recorder transport packet is too large");
			output[outputOffset] = 0;
			outputOffset += 1;
		}
	}
	return output.subarray(0, outputOffset);
}

export class IncidentRecorderTransportDecoder {
	private readonly encoded = Buffer.allocUnsafe(INCIDENT_RECORDER_TRANSPORT_MAX_ENCODED_PACKET_BYTES);
	private encodedBytes = 0;
	private discardedBytes = 0;

	constructor(
		private readonly onPacket: (packet: Buffer, wireBytes: number) => void,
		private readonly onCorruption: (evidence: IncidentRecorderTransportCorruption) => void,
	) {}

	push(chunk: Uint8Array): void {
		for (let index = 0; index < chunk.byteLength; index += 1) {
			const byte = chunk[index];
			if (byte === INCIDENT_RECORDER_TRANSPORT_DELIMITER) {
				this.finishDelimitedPacket();
				continue;
			}
			if (this.discardedBytes > 0) {
				this.discardedBytes += 1;
				continue;
			}
			if (this.encodedBytes >= this.encoded.length) {
				this.discardedBytes = this.encodedBytes + 1;
				this.encodedBytes = 0;
				continue;
			}
			this.encoded[this.encodedBytes] = byte;
			this.encodedBytes += 1;
		}
	}

	private finishDelimitedPacket(): void {
		if (this.discardedBytes > 0) {
			this.onCorruption({ kind: "oversized-packet", wireBytes: this.discardedBytes + 1 });
			this.discardedBytes = 0;
			return;
		}
		if (this.encodedBytes === 0) {
			this.onCorruption({ kind: "empty-packet", wireBytes: 1 });
			return;
		}
		const encodedBytes = this.encodedBytes;
		this.encodedBytes = 0;
		try {
			const packet = decodeIncidentRecorderTransportPacket(this.encoded.subarray(0, encodedBytes));
			this.onPacket(Buffer.from(packet), encodedBytes + 1);
		} catch {
			this.onCorruption({ kind: "malformed-cobs", wireBytes: encodedBytes + 1 });
		}
	}

	/** Reports and clears a non-delimited tail. Returns its exact wire byte count. */
	finish(): number {
		const wireBytes = this.discardedBytes > 0 ? this.discardedBytes : this.encodedBytes;
		this.discardedBytes = 0;
		this.encodedBytes = 0;
		if (wireBytes > 0) this.onCorruption({ kind: "truncated-packet", wireBytes });
		return wireBytes;
	}

	get bufferedWireBytes(): number {
		return this.discardedBytes > 0 ? this.discardedBytes : this.encodedBytes;
	}
}

export interface IncidentRecorderTransportSequenceAccounting {
	gapEvents: bigint;
	missingPackets: bigint;
}

export interface IncidentRecorderTransportSequenceObservation extends IncidentRecorderTransportSequenceAccounting {
	/** True when this validated packet sequence was already received or fell outside the bounded reorder window. */
	duplicate: boolean;
}

interface IncidentRecorderTransportSequenceRange {
	start: bigint;
	end: bigint;
}

interface IncidentRecorderTransportProducerSequenceState {
	minimum: bigint;
	maximum: bigint;
	missing: IncidentRecorderTransportSequenceRange[];
	sealedThrough?: bigint;
}

const EMPTY_SEQUENCE_ACCOUNTING: IncidentRecorderTransportSequenceAccounting = { gapEvents: 0n, missingPackets: 0n };

function addSequenceAccounting(
	left: IncidentRecorderTransportSequenceAccounting,
	right: IncidentRecorderTransportSequenceAccounting,
): IncidentRecorderTransportSequenceAccounting {
	return { gapEvents: left.gapEvents + right.gapEvents, missingPackets: left.missingPackets + right.missingPackets };
}

/**
 * Tracks validated protocol packet sequences with a bounded reorder window.
 * Missing packets are not permanent merely because a higher sequence arrived:
 * later packets can fill pending ranges until finish(), producer eviction, or
 * bounded-range eviction makes the loss final.
 */
export class IncidentRecorderTransportSequenceTracker {
	private readonly producers = new Map<string, IncidentRecorderTransportProducerSequenceState>();
	private readonly finalizedProducerFrontiers = new Map<string, bigint>();

	constructor(
		private readonly maximumProducers = 64,
		private readonly maximumPendingRanges = 64,
	) {
		if (!Number.isSafeInteger(maximumProducers) || maximumProducers < 1) {
			throw new Error("Invalid incident recorder sequence tracker producer bound");
		}
		if (!Number.isSafeInteger(maximumPendingRanges) || maximumPendingRanges < 1) {
			throw new Error("Invalid incident recorder sequence tracker range bound");
		}
	}

	private finalizeRanges(
		ranges: readonly IncidentRecorderTransportSequenceRange[],
	): IncidentRecorderTransportSequenceAccounting {
		return {
			gapEvents: BigInt(ranges.length),
			missingPackets: ranges.reduce((total, range) => total + range.end - range.start + 1n, 0n),
		};
	}

	private compact(state: IncidentRecorderTransportProducerSequenceState): IncidentRecorderTransportSequenceAccounting {
		let accounting = EMPTY_SEQUENCE_ACCOUNTING;
		while (state.missing.length > this.maximumPendingRanges) {
			const finalized = state.missing.shift();
			if (finalized) accounting = addSequenceAccounting(accounting, this.finalizeRanges([finalized]));
		}
		return accounting;
	}

	private addMissing(
		state: IncidentRecorderTransportProducerSequenceState,
		start: bigint,
		end: bigint,
	): IncidentRecorderTransportSequenceAccounting {
		if (end < start) return EMPTY_SEQUENCE_ACCOUNTING;
		const merged: IncidentRecorderTransportSequenceRange[] = [];
		let pending = { start, end };
		let inserted = false;
		for (const range of state.missing) {
			if (range.end + 1n < pending.start) {
				merged.push(range);
				continue;
			}
			if (pending.end + 1n < range.start) {
				if (!inserted) {
					merged.push(pending);
					inserted = true;
				}
				merged.push(range);
				continue;
			}
			pending = {
				start: pending.start < range.start ? pending.start : range.start,
				end: pending.end > range.end ? pending.end : range.end,
			};
		}
		if (!inserted) merged.push(pending);
		state.missing = merged;
		return this.compact(state);
	}

	private rememberFinalizedProducer(producerId: string, maximum: bigint): void {
		this.finalizedProducerFrontiers.delete(producerId);
		this.finalizedProducerFrontiers.set(producerId, maximum);
		while (this.finalizedProducerFrontiers.size > this.maximumProducers) {
			this.finalizedProducerFrontiers.delete(this.finalizedProducerFrontiers.keys().next().value as string);
		}
	}

	private evictProducer(): IncidentRecorderTransportSequenceAccounting {
		const producerId = this.producers.keys().next().value as string | undefined;
		if (!producerId) return EMPTY_SEQUENCE_ACCOUNTING;
		const state = this.producers.get(producerId);
		this.producers.delete(producerId);
		if (!state) return EMPTY_SEQUENCE_ACCOUNTING;
		this.rememberFinalizedProducer(producerId, state.maximum);
		return this.finalizeRanges(state.missing);
	}

	private touch(producerId: string, state: IncidentRecorderTransportProducerSequenceState): void {
		this.producers.delete(producerId);
		this.producers.set(producerId, state);
	}

	/**
	 * Observes the current valid packet before any declared occurrence range is
	 * added. The current sequence is never inserted into, or finalized from, a
	 * missing range.
	 */
	observe(producerId: string, sequence: bigint): IncidentRecorderTransportSequenceObservation {
		let accounting = EMPTY_SEQUENCE_ACCOUNTING;
		let state = this.producers.get(producerId);
		if (!state) {
			const finalizedMaximum = this.finalizedProducerFrontiers.get(producerId);
			if (finalizedMaximum !== undefined && sequence <= finalizedMaximum) {
				this.finalizedProducerFrontiers.delete(producerId);
				this.finalizedProducerFrontiers.set(producerId, finalizedMaximum);
				return { ...accounting, duplicate: true };
			}
			if (this.producers.size >= this.maximumProducers)
				accounting = addSequenceAccounting(accounting, this.evictProducer());
			state = { minimum: sequence, maximum: sequence, missing: [], sealedThrough: finalizedMaximum };
			this.finalizedProducerFrontiers.delete(producerId);
			this.producers.set(producerId, state);
			if (finalizedMaximum !== undefined && sequence > finalizedMaximum + 1n) {
				accounting = addSequenceAccounting(
					accounting,
					this.addMissing(state, finalizedMaximum + 1n, sequence - 1n),
				);
			}
			return { ...accounting, duplicate: false };
		}
		this.touch(producerId, state);
		if (state.sealedThrough !== undefined && sequence <= state.sealedThrough)
			return { ...accounting, duplicate: true };
		// Fill an already-pending sequence before applying lower/upper frontier logic.
		// Reactivated producers can legitimately receive a pending value below their
		// first post-eviction observation.
		for (let index = 0; index < state.missing.length; index += 1) {
			const range = state.missing[index];
			if (sequence < range.start) break;
			if (sequence > range.end) continue;
			if (range.start === range.end) state.missing.splice(index, 1);
			else if (sequence === range.start) range.start += 1n;
			else if (sequence === range.end) range.end -= 1n;
			else {
				const tail = { start: sequence + 1n, end: range.end };
				range.end = sequence - 1n;
				state.missing.splice(index + 1, 0, tail);
				accounting = addSequenceAccounting(accounting, this.compact(state));
			}
			if (sequence < state.minimum) state.minimum = sequence;
			if (sequence > state.maximum) state.maximum = sequence;
			return { ...accounting, duplicate: false };
		}
		if (sequence < state.minimum) {
			accounting = addSequenceAccounting(accounting, this.addMissing(state, sequence + 1n, state.minimum - 1n));
			state.minimum = sequence;
			return { ...accounting, duplicate: false };
		}
		if (sequence > state.maximum) {
			accounting = addSequenceAccounting(accounting, this.addMissing(state, state.maximum + 1n, sequence - 1n));
			state.maximum = sequence;
			return { ...accounting, duplicate: false };
		}
		return { ...accounting, duplicate: true };
	}

	/** Adds expected packets only after observe() accepted the current packet. */
	expect(producerId: string, start: bigint, end: bigint): IncidentRecorderTransportSequenceAccounting {
		if (end < start) throw new Error("Invalid incident recorder expected sequence range");
		const state = this.producers.get(producerId);
		if (!state) throw new Error("Incident recorder sequence expectation requires an observed packet");
		this.touch(producerId, state);
		let accounting = EMPTY_SEQUENCE_ACCOUNTING;
		const effectiveStart =
			state.sealedThrough !== undefined && start <= state.sealedThrough ? state.sealedThrough + 1n : start;
		if (effectiveStart < state.minimum) {
			accounting = addSequenceAccounting(accounting, this.addMissing(state, effectiveStart, state.minimum - 1n));
			state.minimum = effectiveStart;
		}
		if (end > state.maximum) {
			accounting = addSequenceAccounting(accounting, this.addMissing(state, state.maximum + 1n, end));
			state.maximum = end;
		}
		return accounting;
	}

	finish(): IncidentRecorderTransportSequenceAccounting {
		let accounting = EMPTY_SEQUENCE_ACCOUNTING;
		for (const state of this.producers.values())
			accounting = addSequenceAccounting(accounting, this.finalizeRanges(state.missing));
		this.producers.clear();
		this.finalizedProducerFrontiers.clear();
		return accounting;
	}

	get trackedProducers(): number {
		return this.producers.size;
	}
}
