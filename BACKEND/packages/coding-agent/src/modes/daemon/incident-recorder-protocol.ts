import { randomBytes, randomUUID } from "node:crypto";

export const INCIDENT_RECORDER_PROTOCOL_MAGIC = 0x4752494d;
export const INCIDENT_RECORDER_PROTOCOL_VERSION = 3;
export const INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES = 128;
export const INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES = 24 * 1024;
export const INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES = 4 * 1024;
export const INCIDENT_RECORDER_PROTOCOL_MAX_TEXT_BYTES = 255;
export const INCIDENT_RECORDER_PROTOCOL_MAX_FRAME_BYTES =
	INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES +
	3 * INCIDENT_RECORDER_PROTOCOL_MAX_TEXT_BYTES +
	INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES +
	INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES;
// A raw occurrence must still fit the bounded JSON/base64 journal relay after framing.
export const INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES = 983_040;
export const INCIDENT_RECORDER_PROTOCOL_MAX_CHUNK_COUNT = Math.ceil(
	INCIDENT_RECORDER_PROTOCOL_MAX_OCCURRENCE_BYTES / INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES,
);

export const INCIDENT_RECORDER_RUN_ID_ENV = "PRIME_INCIDENT_RECORDER_RUN_ID";
export const INCIDENT_RECORDER_RUN_TOKEN_ENV = "PRIME_INCIDENT_RECORDER_RUN_TOKEN";

export type IncidentRecorderPayloadKind = "exact-bytes" | "derived-scalar" | "loss" | "control";

const PAYLOAD_KIND_TO_CODE: Record<IncidentRecorderPayloadKind, number> = {
	"exact-bytes": 1,
	"derived-scalar": 2,
	loss: 3,
	control: 4,
};
const CODE_TO_PAYLOAD_KIND = new Map(
	Object.entries(PAYLOAD_KIND_TO_CODE).map(([kind, code]) => [code, kind as IncidentRecorderPayloadKind]),
);

export const INCIDENT_RECORDER_FRAME_FLAGS = {
	critical: 1 << 0,
	terminal: 1 << 1,
	firstChunk: 1 << 2,
	lastChunk: 1 << 3,
} as const;

export function validateIncidentRecorderFrameFlags(flags: number, chunkIndex: number, chunkCount: number): void {
	if (!Number.isSafeInteger(flags) || flags < 0 || flags > 0x0f)
		throw new Error("Invalid incident recorder frame flags");
	const first = (flags & INCIDENT_RECORDER_FRAME_FLAGS.firstChunk) !== 0;
	const last = (flags & INCIDENT_RECORDER_FRAME_FLAGS.lastChunk) !== 0;
	if (first !== (chunkIndex === 0) || last !== (chunkIndex === chunkCount - 1)) {
		throw new Error("Incident recorder first/last chunk flags do not match chunk identity");
	}
}

export interface IncidentRecorderFrameHeader {
	version: 3;
	runId: string;
	runToken: string;
	producerId: string;
	occurrenceId: string;
	producerSequence: bigint;
	wallTimeMs: bigint;
	monotonicNs: bigint;
	payloadKind: IncidentRecorderPayloadKind;
	flags: number;
	chunkIndex: number;
	chunkCount: number;
	source: string;
	type: string;
	encoding: string;
	metadata: Readonly<Record<string, string | number | boolean | null>>;
	payloadLength: number;
	checksum: number;
}

export interface IncidentRecorderEncodedFrame {
	header: IncidentRecorderFrameHeader;
	parts: readonly Buffer[];
	bytes: number;
}

function uuidBytes(value: string, name: string): Buffer {
	const compact = value.replaceAll("-", "");
	if (!/^[0-9a-f]{32}$/i.test(compact)) throw new Error(`Invalid incident recorder ${name}`);
	return Buffer.from(compact, "hex");
}

function bytesUuid(bytes: Buffer, offset: number): string {
	const value = bytes.toString("hex", offset, offset + 16);
	return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

function boundedText(value: string, name: string): Buffer {
	const encoded = Buffer.from(value, "utf8");
	if (encoded.length === 0) throw new Error(`Incident recorder ${name} cannot be empty`);
	if (encoded.length > INCIDENT_RECORDER_PROTOCOL_MAX_TEXT_BYTES)
		throw new Error(`Incident recorder ${name} is too long`);
	return encoded;
}

function validateScalarMetadata(value: Readonly<Record<string, string | number | boolean | null>>): Buffer {
	for (const [key, child] of Object.entries(value)) {
		if (Buffer.byteLength(key) > 128) throw new Error("Incident recorder metadata key is too long");
		if (child !== null && typeof child !== "string" && typeof child !== "number" && typeof child !== "boolean") {
			throw new Error("Incident recorder metadata must contain only scalar values");
		}
		if (typeof child === "number" && !Number.isFinite(child))
			throw new Error("Incident recorder metadata number must be finite");
	}
	const encoded = Buffer.from(JSON.stringify(value), "utf8");
	if (encoded.length > INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES)
		throw new Error("Incident recorder metadata is too large");
	return encoded;
}

const CRC_TABLE = new Uint32Array(256);
for (let index = 0; index < 256; index += 1) {
	let value = index;
	for (let bit = 0; bit < 8; bit += 1) value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
	CRC_TABLE[index] = value >>> 0;
}

export function incidentRecorderChecksum(parts: readonly Uint8Array[]): number {
	let crc = 0xffffffff;
	for (const part of parts) {
		for (let index = 0; index < part.byteLength; index += 1)
			crc = CRC_TABLE[(crc ^ part[index]) & 0xff] ^ (crc >>> 8);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

export function newIncidentRecorderIdentity(): string {
	return randomUUID();
}

export function newIncidentRecorderToken(): string {
	const bytes = randomBytes(16);
	return bytesUuid(bytes, 0);
}

export function encodeIncidentRecorderFrame(
	header: Omit<IncidentRecorderFrameHeader, "version" | "payloadLength" | "checksum">,
	payload: Uint8Array,
): IncidentRecorderEncodedFrame {
	if (payload.byteLength > INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES)
		throw new Error("Incident recorder payload chunk is too large");
	if (
		!Number.isSafeInteger(header.chunkIndex) ||
		!Number.isSafeInteger(header.chunkCount) ||
		header.chunkIndex < 0 ||
		header.chunkCount < 1 ||
		header.chunkCount > INCIDENT_RECORDER_PROTOCOL_MAX_CHUNK_COUNT ||
		header.chunkIndex >= header.chunkCount
	)
		throw new Error("Invalid incident recorder chunk identity");
	if (!Object.hasOwn(PAYLOAD_KIND_TO_CODE, header.payloadKind))
		throw new Error("Invalid incident recorder payload kind");
	validateIncidentRecorderFrameFlags(header.flags, header.chunkIndex, header.chunkCount);
	const maximumUnsigned64 = (1n << 64n) - 1n;
	for (const [name, value] of [
		["producer sequence", header.producerSequence],
		["wall time", header.wallTimeMs],
		["monotonic time", header.monotonicNs],
	] as const) {
		if (value < 0n || value > maximumUnsigned64) throw new Error(`Invalid incident recorder ${name}`);
	}
	const source = boundedText(header.source, "source");
	const type = boundedText(header.type, "type");
	const encoding = boundedText(header.encoding, "encoding");
	const metadata = validateScalarMetadata(header.metadata);
	const bodyPayload = Buffer.isBuffer(payload)
		? payload
		: Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
	const fixed = Buffer.alloc(INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES);
	fixed.writeUInt32BE(INCIDENT_RECORDER_PROTOCOL_MAGIC, 0);
	fixed.writeUInt16BE(INCIDENT_RECORDER_PROTOCOL_VERSION, 4);
	fixed.writeUInt16BE(INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES, 6);
	fixed.writeUInt8(PAYLOAD_KIND_TO_CODE[header.payloadKind], 8);
	fixed.writeUInt8(header.flags, 9);
	fixed.writeUInt8(source.length, 10);
	fixed.writeUInt8(type.length, 11);
	fixed.writeUInt8(encoding.length, 12);
	fixed.writeUInt32BE(metadata.length, 16);
	fixed.writeUInt32BE(bodyPayload.length, 20);
	fixed.writeUInt32BE(header.chunkIndex, 24);
	fixed.writeUInt32BE(header.chunkCount, 28);
	fixed.writeBigUInt64BE(header.producerSequence, 32);
	fixed.writeBigUInt64BE(header.wallTimeMs, 40);
	fixed.writeBigUInt64BE(header.monotonicNs, 48);
	uuidBytes(header.runId, "run ID").copy(fixed, 56);
	uuidBytes(header.runToken, "run token").copy(fixed, 72);
	uuidBytes(header.producerId, "producer ID").copy(fixed, 88);
	uuidBytes(header.occurrenceId, "occurrence ID").copy(fixed, 104);
	const checksum = incidentRecorderChecksum([fixed.subarray(0, 120), source, type, encoding, metadata, bodyPayload]);
	fixed.writeUInt32BE(checksum, 120);
	const decodedHeader: IncidentRecorderFrameHeader = {
		...header,
		version: 3,
		payloadLength: bodyPayload.length,
		checksum,
	};
	const parts = [fixed, source, type, encoding, metadata, bodyPayload] as const;
	return { header: decodedHeader, parts, bytes: parts.reduce((total, part) => total + part.length, 0) };
}

function decodeStrictText(value: Buffer, name: string): string {
	if (value.length === 0) throw new Error(`Incident recorder ${name} cannot be empty`);
	const decoded = value.toString("utf8");
	if (!Buffer.from(decoded, "utf8").equals(value)) throw new Error(`Incident recorder ${name} is not valid UTF-8`);
	return decoded;
}

function parseMetadata(value: Buffer): Readonly<Record<string, string | number | boolean | null>> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(value.toString("utf8"));
	} catch {
		throw new Error("Invalid incident recorder metadata JSON");
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
		throw new Error("Invalid incident recorder metadata");
	validateScalarMetadata(parsed as Record<string, string | number | boolean | null>);
	return parsed as Readonly<Record<string, string | number | boolean | null>>;
}

export function decodeIncidentRecorderFrame(frame: Buffer): { header: IncidentRecorderFrameHeader; payload: Buffer } {
	if (frame.length < INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES)
		throw new Error("Incomplete incident recorder frame header");
	if (frame.readUInt32BE(0) !== INCIDENT_RECORDER_PROTOCOL_MAGIC)
		throw new Error("Invalid incident recorder frame magic");
	if (
		frame.readUInt16BE(4) !== INCIDENT_RECORDER_PROTOCOL_VERSION ||
		frame.readUInt16BE(6) !== INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES
	) {
		throw new Error("Unsupported incident recorder protocol version");
	}
	const payloadKind = CODE_TO_PAYLOAD_KIND.get(frame.readUInt8(8));
	if (!payloadKind) throw new Error("Invalid incident recorder payload kind");
	const flags = frame.readUInt8(9);
	const sourceLength = frame.readUInt8(10);
	const typeLength = frame.readUInt8(11);
	const encodingLength = frame.readUInt8(12);
	if (
		frame.readUInt8(13) !== 0 ||
		frame.readUInt16BE(14) !== 0 ||
		frame.subarray(124, 128).some((byte) => byte !== 0)
	) {
		throw new Error("Non-zero reserved incident recorder header bytes");
	}
	const metadataLength = frame.readUInt32BE(16);
	const payloadLength = frame.readUInt32BE(20);
	if (
		metadataLength > INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES ||
		payloadLength > INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES
	) {
		throw new Error("Incident recorder frame length exceeds protocol limits");
	}
	const chunkIndex = frame.readUInt32BE(24);
	const chunkCount = frame.readUInt32BE(28);
	if (chunkCount < 1 || chunkCount > INCIDENT_RECORDER_PROTOCOL_MAX_CHUNK_COUNT || chunkIndex >= chunkCount) {
		throw new Error("Invalid incident recorder frame chunk identity");
	}
	validateIncidentRecorderFrameFlags(flags, chunkIndex, chunkCount);
	const expected =
		INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES +
		sourceLength +
		typeLength +
		encodingLength +
		metadataLength +
		payloadLength;
	if (frame.length !== expected) throw new Error("Incident recorder frame byte length does not match header");
	let offset = INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES;
	const source = decodeStrictText(frame.subarray(offset, offset + sourceLength), "source");
	offset += sourceLength;
	const type = decodeStrictText(frame.subarray(offset, offset + typeLength), "type");
	offset += typeLength;
	const encoding = decodeStrictText(frame.subarray(offset, offset + encodingLength), "encoding");
	offset += encodingLength;
	const metadataBytes = frame.subarray(offset, offset + metadataLength);
	offset += metadataLength;
	const payload = frame.subarray(offset, offset + payloadLength);
	const checksum = frame.readUInt32BE(120);
	const actualChecksum = incidentRecorderChecksum([
		frame.subarray(0, 120),
		frame.subarray(INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES),
	]);
	if (actualChecksum !== checksum) throw new Error("Incident recorder frame checksum mismatch");
	return {
		header: {
			version: 3,
			runId: bytesUuid(frame, 56),
			runToken: bytesUuid(frame, 72),
			producerId: bytesUuid(frame, 88),
			occurrenceId: bytesUuid(frame, 104),
			producerSequence: frame.readBigUInt64BE(32),
			wallTimeMs: frame.readBigUInt64BE(40),
			monotonicNs: frame.readBigUInt64BE(48),
			payloadKind,
			flags,
			chunkIndex,
			chunkCount,
			source,
			type,
			encoding,
			metadata: parseMetadata(metadataBytes),
			payloadLength,
			checksum,
		},
		payload,
	};
}

export function incidentRecorderFrameProducerId(frame: Buffer): string {
	if (
		frame.length < INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES ||
		frame.readUInt32BE(0) !== INCIDENT_RECORDER_PROTOCOL_MAGIC
	) {
		throw new Error("Invalid incident recorder frame producer identity");
	}
	return bytesUuid(frame, 88);
}

export function incidentRecorderFrameLength(prefix: Buffer): number {
	if (prefix.length < INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES)
		throw new Error("Incomplete incident recorder frame prefix");
	if (prefix.readUInt32BE(0) !== INCIDENT_RECORDER_PROTOCOL_MAGIC)
		throw new Error("Invalid incident recorder frame magic");
	if (
		prefix.readUInt16BE(4) !== INCIDENT_RECORDER_PROTOCOL_VERSION ||
		prefix.readUInt16BE(6) !== INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES
	) {
		throw new Error("Unsupported incident recorder protocol version");
	}
	const metadataLength = prefix.readUInt32BE(16);
	const payloadLength = prefix.readUInt32BE(20);
	if (
		metadataLength > INCIDENT_RECORDER_PROTOCOL_MAX_METADATA_BYTES ||
		payloadLength > INCIDENT_RECORDER_PROTOCOL_MAX_PAYLOAD_BYTES
	) {
		throw new Error("Incident recorder frame length exceeds protocol limits");
	}
	return (
		INCIDENT_RECORDER_PROTOCOL_HEADER_BYTES +
		prefix.readUInt8(10) +
		prefix.readUInt8(11) +
		prefix.readUInt8(12) +
		metadataLength +
		payloadLength
	);
}
