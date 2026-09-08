import { Buffer } from "node:buffer";
import { types as nodeTypes } from "node:util";

/** Maximum UTF-8 body retained for one derived diagnostic occurrence. */
export const INCIDENT_RECORDER_DIAGNOSTIC_PAYLOAD_MAX_BYTES = 64 * 1024;
/** Service admission includes the existing 24 KiB observation allowance. */
export const INCIDENT_RECORDER_DERIVED_OBSERVATION_RESERVATION_BYTES =
	INCIDENT_RECORDER_DIAGNOSTIC_PAYLOAD_MAX_BYTES + 24 * 1024;
export const INCIDENT_RECORDER_DIAGNOSTIC_MAX_DEPTH = 6;
export const INCIDENT_RECORDER_DIAGNOSTIC_MAX_NODES = 256;
export const INCIDENT_RECORDER_DIAGNOSTIC_MAX_PROPERTIES = 64;
export const INCIDENT_RECORDER_DIAGNOSTIC_MAX_STRING_BYTES = 8 * 1024;
export const INCIDENT_RECORDER_DIAGNOSTIC_MAX_STACK_BYTES = 16 * 1024;
export const INCIDENT_RECORDER_DIAGNOSTIC_MAX_BINARY_BYTES = 16 * 1024;

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type IncidentRecorderDiagnosticPayloadState = "serialized" | "unavailable";

export interface IncidentRecorderDiagnosticPayloadSummary {
	readonly state: IncidentRecorderDiagnosticPayloadState;
	readonly bytes: number;
	readonly storedBytes: number;
	readonly nodes: number;
	readonly properties: number;
	readonly omissions: number;
	readonly unsupported: number;
	readonly accessorOmissions: number;
	readonly depthOmissions: number;
	readonly stringTruncations: number;
	readonly binaryTruncations: number;
	readonly unavailable: number;
}

export interface IncidentRecorderDiagnosticPayload {
	readonly bytes: Buffer;
	readonly summary: IncidentRecorderDiagnosticPayloadSummary;
}

interface Counters {
	nodes: number;
	properties: number;
	omissions: number;
	unsupported: number;
	accessorOmissions: number;
	depthOmissions: number;
	stringTruncations: number;
	binaryTruncations: number;
	unavailable: number;
}

interface Context {
	readonly counters: Counters;
	readonly references: WeakMap<object, number>;
	nextNodeId: number;
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const NATIVE_ERROR_STACK_GETTER = (() => {
	try {
		const descriptor = Object.getOwnPropertyDescriptor(new Error(), "stack");
		return typeof descriptor?.get === "function" ? descriptor.get : undefined;
	} catch {
		return undefined;
	}
})();

function boundedUtf8(value: string, maximumBytes: number): { value: string; truncated: boolean } {
	if (Buffer.byteLength(value, "utf8") <= maximumBytes) return { value, truncated: false };
	let low = 0;
	let high = Math.min(value.length, maximumBytes);
	while (low < high) {
		const middle = Math.ceil((low + high) / 2);
		if (Buffer.byteLength(value.slice(0, middle), "utf8") <= maximumBytes) low = middle;
		else high = middle - 1;
	}
	if (low > 0 && /[\uD800-\uDBFF]/.test(value[low - 1] ?? "")) low -= 1;
	return { value: value.slice(0, low), truncated: true };
}

function jsonString(value: string): string {
	return JSON.stringify(value);
}

function omission(reason: string, count?: number): JsonValue {
	return {
		$diagnosticType: "omitted",
		reason,
		...(count === undefined ? {} : { count }),
	};
}

function unsupported(kind: string): JsonValue {
	return { $diagnosticType: "unsupported", kind };
}

function unavailable(reason: string): JsonValue {
	return { $diagnosticType: "unavailable", reason };
}

function base64(bytes: Uint8Array): string {
	let result = "";
	for (let index = 0; index < bytes.length; index += 3) {
		const first = bytes[index] ?? 0;
		const second = bytes[index + 1];
		const third = bytes[index + 2];
		result += BASE64_ALPHABET[first >>> 2];
		result += BASE64_ALPHABET[((first & 0x03) << 4) | ((second ?? 0) >>> 4)];
		result += second === undefined ? "=" : BASE64_ALPHABET[((second & 0x0f) << 2) | ((third ?? 0) >>> 6)];
		result += third === undefined ? "=" : BASE64_ALPHABET[third & 0x3f];
	}
	return result;
}

function binaryValue(value: Uint8Array, context: Context, type: string, id: number): JsonValue {
	const retainedLength = Math.min(value.length, INCIDENT_RECORDER_DIAGNOSTIC_MAX_BINARY_BYTES);
	const retained = new Uint8Array(retainedLength);
	for (let index = 0; index < retainedLength; index += 1) retained[index] = value[index] ?? 0;
	if (retained.length !== value.length) context.counters.binaryTruncations += 1;
	return {
		$diagnosticType: type,
		id,
		encoding: "base64",
		value: base64(retained),
		...(retained.length !== value.length ? { truncated: true } : {}),
	};
}

function ownKeys(value: object, context: Context): (string | symbol)[] | undefined {
	try {
		return Reflect.ownKeys(value);
	} catch {
		context.counters.unavailable += 1;
		return undefined;
	}
}

function keyValue(key: string | symbol, context: Context): JsonValue {
	if (typeof key === "string") {
		const bounded = boundedUtf8(key, INCIDENT_RECORDER_DIAGNOSTIC_MAX_STRING_BYTES);
		if (!bounded.truncated) return key;
		context.counters.stringTruncations += 1;
		return {
			type: "string",
			value: bounded.value,
			truncated: true,
			originalBytes: Buffer.byteLength(key, "utf8"),
		};
	}
	return { type: "symbol" };
}

function sortKeys(keys: readonly (string | symbol)[]): (string | symbol)[] {
	const strings = keys.filter((key): key is string => typeof key === "string").sort();
	const symbols = keys.filter((key): key is symbol => typeof key === "symbol");
	return [...strings, ...symbols];
}

function isNativeError(value: object): boolean {
	try {
		return nodeTypes.isNativeError(value);
	} catch {
		return false;
	}
}

function nativeErrorStackValue(
	value: object,
	key: string | symbol,
	descriptor: PropertyDescriptor,
	context: Context,
): JsonValue | undefined {
	if (
		key !== "stack" ||
		!NATIVE_ERROR_STACK_GETTER ||
		!isNativeError(value) ||
		descriptor.get !== NATIVE_ERROR_STACK_GETTER
	)
		return undefined;
	for (const dependency of ["name", "message"] as const) {
		try {
			const dependencyDescriptor = Object.getOwnPropertyDescriptor(value, dependency);
			if (dependencyDescriptor && !("value" in dependencyDescriptor)) {
				context.counters.omissions += 1;
				context.counters.accessorOmissions += 1;
				return omission("native-error-stack-accessor-dependency");
			}
		} catch {
			context.counters.unavailable += 1;
			return unavailable("native-error-stack-dependency");
		}
	}
	try {
		const stack = Reflect.apply(NATIVE_ERROR_STACK_GETTER, value, []);
		if (typeof stack !== "string") {
			context.counters.unavailable += 1;
			return unavailable("native-error-stack-nonstring");
		}
		const bounded = boundedUtf8(stack, INCIDENT_RECORDER_DIAGNOSTIC_MAX_STACK_BYTES);
		if (bounded.truncated) context.counters.stringTruncations += 1;
		return bounded.value;
	} catch {
		context.counters.unavailable += 1;
		return unavailable("native-error-stack");
	}
}

function encodedPrimitive(value: unknown, context: Context, stringMaximumBytes: number): JsonValue | undefined {
	if (value === null || typeof value === "boolean") return value;
	if (typeof value === "string") {
		const bounded = boundedUtf8(value, stringMaximumBytes);
		if (bounded.truncated) context.counters.stringTruncations += 1;
		return bounded.value;
	}
	if (typeof value === "number") {
		if (Number.isFinite(value)) return value;
		context.counters.unsupported += 1;
		return { $diagnosticType: "number", value: String(value) };
	}
	if (typeof value === "undefined") return { $diagnosticType: "undefined" };
	if (typeof value === "bigint") {
		const bounded = boundedUtf8(String(value), stringMaximumBytes);
		if (bounded.truncated) context.counters.stringTruncations += 1;
		return {
			$diagnosticType: "bigint",
			value: bounded.value,
			...(bounded.truncated ? { truncated: true } : {}),
		};
	}
	if (typeof value === "symbol") {
		context.counters.unsupported += 1;
		return unsupported("symbol");
	}
	if (typeof value === "function") {
		context.counters.unsupported += 1;
		return unsupported("function");
	}
	return undefined;
}

function encodedObject(value: object, depth: number, context: Context): JsonValue {
	if (depth > INCIDENT_RECORDER_DIAGNOSTIC_MAX_DEPTH) {
		context.counters.omissions += 1;
		context.counters.depthOmissions += 1;
		return omission("depth");
	}
	const existing = context.references.get(value);
	if (existing !== undefined) return { $diagnosticType: "reference", id: existing };
	if (context.counters.nodes >= INCIDENT_RECORDER_DIAGNOSTIC_MAX_NODES) {
		context.counters.omissions += 1;
		return omission("node-budget");
	}
	const id = context.nextNodeId;
	context.nextNodeId += 1;
	context.counters.nodes += 1;
	context.references.set(value, id);

	if (Buffer.isBuffer(value)) return binaryValue(value, context, "buffer", id);
	try {
		if (ArrayBuffer.isView(value)) {
			const bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
			return binaryValue(bytes, context, "typed-bytes", id);
		}
		if (value instanceof ArrayBuffer) return binaryValue(new Uint8Array(value), context, "array-buffer", id);
	} catch {
		context.counters.unavailable += 1;
		if (depth === 0) throw new Error("diagnostic root binary inspection unavailable");
		return unavailable("binary-inspection");
	}

	const keys = ownKeys(value, context);
	if (!keys) {
		if (depth === 0) throw new Error("diagnostic root inspection unavailable");
		return unavailable("own-keys");
	}
	const orderedKeys = sortKeys(keys);
	const properties: JsonValue[] = [];
	const propertyLimit = Math.min(orderedKeys.length, INCIDENT_RECORDER_DIAGNOSTIC_MAX_PROPERTIES);
	for (let index = 0; index < propertyLimit; index += 1) {
		const key = orderedKeys[index];
		if (key === undefined) continue;
		context.counters.properties += 1;
		let descriptor: PropertyDescriptor | undefined;
		try {
			descriptor = Object.getOwnPropertyDescriptor(value, key);
		} catch {
			context.counters.unavailable += 1;
			if (depth === 0) throw new Error("diagnostic root property inspection unavailable");
		}
		if (!descriptor) {
			properties.push([keyValue(key, context), unavailable("property-descriptor")]);
			continue;
		}
		if (!("value" in descriptor)) {
			const nativeStack = nativeErrorStackValue(value, key, descriptor, context);
			if (nativeStack !== undefined) {
				properties.push([keyValue(key, context), nativeStack]);
				continue;
			}
			context.counters.omissions += 1;
			context.counters.accessorOmissions += 1;
			properties.push([keyValue(key, context), omission("accessor")]);
			continue;
		}
		const childMaximum =
			key === "stack" ? INCIDENT_RECORDER_DIAGNOSTIC_MAX_STACK_BYTES : INCIDENT_RECORDER_DIAGNOSTIC_MAX_STRING_BYTES;
		properties.push([keyValue(key, context), encodedValue(descriptor.value, depth + 1, context, childMaximum)]);
	}
	if (orderedKeys.length > propertyLimit) {
		const omitted = orderedKeys.length - propertyLimit;
		context.counters.omissions += omitted;
		properties.push(["$diagnosticOmittedProperties", omission("property-budget", omitted)]);
	}
	return {
		$diagnosticType: isNativeError(value) ? "error" : Array.isArray(value) ? "array" : "object",
		id,
		properties,
	};
}

function encodedValue(value: unknown, depth: number, context: Context, stringMaximumBytes: number): JsonValue {
	const primitive = encodedPrimitive(value, context, stringMaximumBytes);
	if (primitive !== undefined) return primitive;
	return typeof value === "object" && value !== null
		? encodedObject(value, depth, context)
		: unavailable("value-inspection");
}

function bytesOf(value: string): number {
	return Buffer.byteLength(value, "utf8");
}

function renderBounded(value: JsonValue, budget: number, context: Context): string {
	const primitive = value === null || typeof value !== "object";
	if (primitive) {
		const rendered = JSON.stringify(value);
		if (typeof rendered === "string" && bytesOf(rendered) <= budget) return rendered;
		context.counters.omissions += 1;
		return JSON.stringify(omission("byte-budget")) ?? "{}";
	}
	if (Array.isArray(value)) {
		const parts: string[] = [];
		let used = 2;
		for (const child of value) {
			const comma = parts.length === 0 ? 0 : 1;
			const childBudget = Math.max(0, budget - used - comma);
			const rendered = renderBounded(child, childBudget, context);
			const needed = comma + bytesOf(rendered);
			if (used + needed > budget) {
				context.counters.omissions += 1;
				const marker = JSON.stringify(omission("byte-budget")) ?? "{}";
				if (used + comma + bytesOf(marker) <= budget) {
					parts.push(marker);
					used += comma + bytesOf(marker);
				}
				break;
			}
			parts.push(rendered);
			used += needed;
		}
		return `[${parts.join(",")}]`;
	}
	const parts: string[] = [];
	let used = 2;
	for (const [key, child] of Object.entries(value)) {
		const keyText = jsonString(key);
		const comma = parts.length === 0 ? 0 : 1;
		const childBudget = Math.max(0, budget - used - comma - bytesOf(keyText) - 1);
		const rendered = renderBounded(child, childBudget, context);
		const entry = `${keyText}:${rendered}`;
		const needed = comma + bytesOf(entry);
		if (used + needed > budget) {
			context.counters.omissions += 1;
			const marker = `${jsonString("$diagnosticOmitted")}:${JSON.stringify(omission("byte-budget")) ?? "{}"}`;
			if (used + comma + bytesOf(marker) <= budget) {
				parts.push(marker);
				used += comma + bytesOf(marker);
			}
			break;
		}
		parts.push(entry);
		used += needed;
	}
	return `{${parts.join(",")}}`;
}

function unavailablePayload(reason: "inspection_failed" | "serialization_failed"): IncidentRecorderDiagnosticPayload {
	const body = Buffer.from(JSON.stringify({ schemaVersion: 2, state: "unavailable", reason }), "utf8");
	return {
		bytes: body,
		summary: Object.freeze({
			state: "unavailable",
			bytes: body.length,
			storedBytes: body.length,
			nodes: 0,
			properties: 0,
			omissions: 0,
			unsupported: 0,
			accessorOmissions: 0,
			depthOmissions: 0,
			stringTruncations: 0,
			binaryTruncations: 0,
			unavailable: 1,
		}),
	};
}

/**
 * Serialize a product diagnostic snapshot without invoking arbitrary user
 * accessors, toJSON hooks, function source conversion, or prototype methods.
 * Native Error.stack is the one deliberate runtime exception: Node's branded
 * built-in getter is retained so ordinary source-mapped stacks remain useful.
 */
export function serializeIncidentRecorderDiagnostic(value: unknown): IncidentRecorderDiagnosticPayload {
	const context: Context = {
		counters: {
			nodes: 0,
			properties: 0,
			omissions: 0,
			unsupported: 0,
			accessorOmissions: 0,
			depthOmissions: 0,
			stringTruncations: 0,
			binaryTruncations: 0,
			unavailable: 0,
		},
		references: new WeakMap<object, number>(),
		nextNodeId: 1,
	};
	try {
		const snapshot: JsonValue = {
			schemaVersion: 2,
			value: encodedValue(value, 0, context, INCIDENT_RECORDER_DIAGNOSTIC_MAX_STRING_BYTES),
		};
		const rendered = renderBounded(snapshot, INCIDENT_RECORDER_DIAGNOSTIC_PAYLOAD_MAX_BYTES, context);
		const body = Buffer.from(rendered, "utf8");
		if (body.length === 0 || body.length > INCIDENT_RECORDER_DIAGNOSTIC_PAYLOAD_MAX_BYTES) {
			return unavailablePayload("serialization_failed");
		}
		return {
			bytes: body,
			summary: Object.freeze({
				state: "serialized",
				bytes: body.length,
				storedBytes: body.length,
				...context.counters,
			}),
		};
	} catch {
		return unavailablePayload("inspection_failed");
	}
}
