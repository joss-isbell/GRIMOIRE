import type {
	IncidentRecorderCompactor,
	IncidentRecorderLiveRunEventsCursor,
	IncidentRecorderLiveRunGap,
	IncidentRecorderRunHistoryEvent,
} from "./incident-recorder-compactor.js";
import type { IncidentRecorderFinalizationExpectation } from "./incident-recorder-writer.js";

export type IncidentRecorderFinalizationBarrierReadResult = "complete" | "pending" | "empty" | "incomplete";

export interface IncidentRecorderFinalizationBarrierProof {
	readonly supervisorExit: boolean;
	readonly wrapperTerminal: boolean;
}

export type IncidentRecorderStoredFinalizationBarrierExpectation = IncidentRecorderFinalizationExpectation & {
	version: 1;
	exitCode: number | "unavailable";
	exitSignal: string | "unavailable";
};

interface BarrierReadState {
	expectationFingerprint: string;
	compactor: IncidentRecorderCompactor;
	occurrenceCursor?: IncidentRecorderLiveRunEventsCursor;
	runGapCursor?: IncidentRecorderLiveRunEventsCursor;
	globalGapCursor?: IncidentRecorderLiveRunEventsCursor;
	supervisorExitMatched: boolean;
	wrapperTerminalMatched: boolean;
	segmentOccurrenceCount: number;
	segmentGapCount: number;
	supervisorProducerGapStreams: Set<string>;
	supervisorWrapperGapStreams: Set<string>;
	wrapperProducerGapStreams: Set<string>;
	wrapperWrapperGapStreams: Set<string>;
	gapStreamOverflow: boolean;
}

const states = new Map<string, BarrierReadState>();
const MAX_BARRIER_STATES = 64;
const MAX_GAP_STREAMS = 64;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sequenceRangeEquals(values: readonly string[], first: string, last: string): boolean {
	if (values.length < 1 || values[0] !== first || values.at(-1) !== last) return false;
	try {
		return values.every((value, index) => BigInt(value) === BigInt(first) + BigInt(index));
	} catch {
		return false;
	}
}

function isUnsignedSequence(value: unknown): value is string {
	if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/.test(value)) return false;
	try {
		return BigInt(value) <= (1n << 64n) - 1n;
	} catch {
		return false;
	}
}

function expectedCode(value: number | "unavailable"): number | null {
	return value === "unavailable" ? null : value;
}

function expectedSignal(value: string | "unavailable"): string | null {
	return value === "unavailable" ? null : value;
}

function completeMatches(
	event: IncidentRecorderRunHistoryEvent,
	expectation: IncidentRecorderStoredFinalizationBarrierExpectation,
	expected: NonNullable<IncidentRecorderStoredFinalizationBarrierExpectation["supervisorExit"]>,
	kind: "exit" | "terminal",
): boolean {
	if (
		event.identity.runId !== expectation.runId ||
		event.identity.runToken !== expectation.runToken ||
		event.identity.producerId !== expected.producerId ||
		event.identity.occurrenceId !== expected.occurrenceId ||
		!sequenceRangeEquals(event.wrapperOrder, expected.firstWrapperSequence, expected.lastWrapperSequence) ||
		!sequenceRangeEquals(event.producerOrder, expected.firstProducerSequence, expected.lastProducerSequence)
	)
		return false;
	const metadata = event.metadata;
	const transport = event.transportIdentity;
	if (!isRecord(metadata) || !isRecord(transport)) return false;
	if (
		metadata.producerPid !== transport.wrapperPid ||
		transport.wrapperPid !== expectation.wrapperPid ||
		transport.wrapperStartId !== expectation.wrapperStartId
	)
		return false;
	if (kind === "exit") {
		return (
			event.type === "supervisor_exit" &&
			event.source === "recorder-events" &&
			Object.hasOwn(metadata, "code") &&
			Object.hasOwn(metadata, "signal") &&
			metadata.code === expectedCode(expectation.exitCode) &&
			metadata.signal === expectedSignal(expectation.exitSignal)
		);
	}
	return event.type === "capture_channel_terminal" && event.source === "recorder-control" && event.terminal === true;
}

function observeGapStreams(
	gaps: readonly IncidentRecorderLiveRunGap[],
	expectation: IncidentRecorderFinalizationExpectation,
	state: BarrierReadState,
): IncidentRecorderFinalizationBarrierProof {
	const supervisorExit = expectation.supervisorExit;
	const wrapperTerminal = expectation.wrapperTerminal;
	if (!supervisorExit || !wrapperTerminal) return { supervisorExit: false, wrapperTerminal: false };
	for (const gap of gaps) {
		const evidence = gap.evidence;
		if (
			evidence.runId !== expectation.runId ||
			evidence.runToken !== expectation.runToken ||
			typeof evidence.streamKeyHash !== "string" ||
			!/^[0-9a-f]{64}$/.test(evidence.streamKeyHash)
		)
			continue;
		try {
			if (
				evidence.producerId === supervisorExit.producerId &&
				isUnsignedSequence(evidence.expectedProducerFrom) &&
				isUnsignedSequence(evidence.expectedProducerThrough) &&
				BigInt(evidence.expectedProducerFrom) <= BigInt(supervisorExit.firstProducerSequence) &&
				BigInt(evidence.expectedProducerThrough) >= BigInt(supervisorExit.lastProducerSequence)
			)
				addBoundedGapStream(state, state.supervisorProducerGapStreams, evidence.streamKeyHash);
			if (
				evidence.wrapperPid === expectation.wrapperPid &&
				evidence.wrapperStartId === expectation.wrapperStartId &&
				isUnsignedSequence(evidence.expectedWrapperFrom) &&
				isUnsignedSequence(evidence.expectedWrapperThrough) &&
				BigInt(evidence.expectedWrapperFrom) <= BigInt(supervisorExit.firstWrapperSequence) &&
				BigInt(evidence.expectedWrapperThrough) >= BigInt(supervisorExit.lastWrapperSequence)
			)
				addBoundedGapStream(state, state.supervisorWrapperGapStreams, evidence.streamKeyHash);
			if (
				evidence.producerId === wrapperTerminal.producerId &&
				isUnsignedSequence(evidence.expectedProducerFrom) &&
				isUnsignedSequence(evidence.expectedProducerThrough) &&
				BigInt(evidence.expectedProducerFrom) <= BigInt(wrapperTerminal.firstProducerSequence) &&
				BigInt(evidence.expectedProducerThrough) >= BigInt(wrapperTerminal.lastProducerSequence)
			)
				addBoundedGapStream(state, state.wrapperProducerGapStreams, evidence.streamKeyHash);
			if (
				evidence.wrapperPid === expectation.wrapperPid &&
				evidence.wrapperStartId === expectation.wrapperStartId &&
				isUnsignedSequence(evidence.expectedWrapperFrom) &&
				isUnsignedSequence(evidence.expectedWrapperThrough) &&
				BigInt(evidence.expectedWrapperFrom) <= BigInt(wrapperTerminal.firstWrapperSequence) &&
				BigInt(evidence.expectedWrapperThrough) >= BigInt(wrapperTerminal.lastWrapperSequence)
			)
				addBoundedGapStream(state, state.wrapperWrapperGapStreams, evidence.streamKeyHash);
		} catch {}
	}
	return {
		supervisorExit: [...state.supervisorProducerGapStreams].some((stream) =>
			state.supervisorWrapperGapStreams.has(stream),
		),
		wrapperTerminal: [...state.wrapperProducerGapStreams].some((stream) =>
			state.wrapperWrapperGapStreams.has(stream),
		),
	};
}

function barrierFingerprint(expectation: IncidentRecorderStoredFinalizationBarrierExpectation): string {
	return JSON.stringify(expectation);
}

function stateFor(
	runDir: string,
	expectation: IncidentRecorderStoredFinalizationBarrierExpectation,
	compactor: IncidentRecorderCompactor,
): BarrierReadState {
	const expectationFingerprint = barrierFingerprint(expectation);
	const existing = states.get(runDir);
	if (existing?.expectationFingerprint === expectationFingerprint && existing.compactor === compactor) return existing;
	const state: BarrierReadState = {
		expectationFingerprint,
		compactor,
		supervisorExitMatched: false,
		wrapperTerminalMatched: false,
		segmentOccurrenceCount: 0,
		segmentGapCount: 0,
		supervisorProducerGapStreams: new Set(),
		supervisorWrapperGapStreams: new Set(),
		wrapperProducerGapStreams: new Set(),
		wrapperWrapperGapStreams: new Set(),
		gapStreamOverflow: false,
	};
	states.set(runDir, state);
	while (states.size > MAX_BARRIER_STATES) states.delete(states.keys().next().value as string);
	return state;
}

function addBoundedGapStream(state: BarrierReadState, streams: Set<string>, value: string): void {
	if (streams.has(value)) return;
	if (streams.size >= MAX_GAP_STREAMS) {
		state.gapStreamOverflow = true;
		return;
	}
	streams.add(value);
}

export function readCompactedFinalizationBarrier(input: {
	runDir: string;
	expectation: IncidentRecorderStoredFinalizationBarrierExpectation;
	compactor: IncidentRecorderCompactor;
	legacyProof?: IncidentRecorderFinalizationBarrierProof;
}): IncidentRecorderFinalizationBarrierReadResult {
	const { expectation, compactor } = input;
	if (
		!expectation.supervisorExit ||
		!expectation.wrapperTerminal ||
		expectation.supervisorExit.producerId !== expectation.wrapperTerminal.producerId
	)
		return "incomplete";
	const state = stateFor(input.runDir, expectation, compactor);
	let supervisorExit = state.supervisorExitMatched || input.legacyProof?.supervisorExit === true;
	let wrapperTerminal = state.wrapperTerminalMatched || input.legacyProof?.wrapperTerminal === true;
	state.supervisorExitMatched = supervisorExit;
	state.wrapperTerminalMatched = wrapperTerminal;
	if (state.gapStreamOverflow) return "incomplete";
	if (supervisorExit && wrapperTerminal) return "complete";
	try {
		const occurrencePage = compactor.readLiveRunEvents({ runId: expectation.runId, cursor: state.occurrenceCursor });
		state.segmentOccurrenceCount += occurrencePage.events.length;
		for (const event of occurrencePage.events) {
			supervisorExit ||= completeMatches(event, expectation, expectation.supervisorExit, "exit");
			wrapperTerminal ||= completeMatches(event, expectation, expectation.wrapperTerminal, "terminal");
		}
		state.supervisorExitMatched = supervisorExit;
		state.wrapperTerminalMatched = wrapperTerminal;
		if (occurrencePage.state !== "incomplete") state.occurrenceCursor = occurrencePage.cursor;
		if (supervisorExit && wrapperTerminal) return "complete";

		for (const runId of [expectation.runId, "__recorder__"] as const) {
			const cursorKey = runId === expectation.runId ? "runGapCursor" : "globalGapCursor";
			const gapPage = compactor.readLiveRunGaps({ runId, cursor: state[cursorKey] });
			if (runId === expectation.runId) state.segmentGapCount += gapPage.gaps.length;
			else if (
				gapPage.gaps.some(
					({ evidence }) => evidence.runId === expectation.runId && evidence.runToken === expectation.runToken,
				)
			)
				state.segmentGapCount += 1;
			const gapCovered = observeGapStreams(gapPage.gaps, expectation, state);
			if (gapPage.state !== "incomplete") state[cursorKey] = gapPage.cursor;
			supervisorExit ||= gapCovered.supervisorExit;
			wrapperTerminal ||= gapCovered.wrapperTerminal;
			state.supervisorExitMatched = supervisorExit;
			state.wrapperTerminalMatched = wrapperTerminal;
			if (state.gapStreamOverflow) return "incomplete";
			if (supervisorExit && wrapperTerminal) return "complete";
			if (gapPage.state === "incomplete") return "incomplete";
		}
		if (occurrencePage.state === "incomplete") return "incomplete";
		if (state.segmentOccurrenceCount === 0 && state.segmentGapCount === 0) return "empty";
		return "pending";
	} catch {
		return "incomplete";
	}
}
