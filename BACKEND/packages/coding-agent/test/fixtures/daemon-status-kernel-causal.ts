import { appendFileSync } from "node:fs";
import { join } from "node:path";
import {
	type FauxResponseFactory,
	fauxAssistantMessage,
	fauxToolCall,
	getApiProvider,
	registerFauxProvider,
} from "../../../ai/src/index.js";
import { subscribeKernelDiagnostics } from "../../src/core/kernel/diagnostics.js";
import type { ExtensionAPI } from "../../src/index.js";

export default function registerCausalFixture(pi: ExtensionAPI): void {
	const evidenceDir = process.env.PRIME_AGENT_CAUSAL_EVIDENCE_DIR;
	if (!evidenceDir) throw new Error("Missing isolated causal evidence directory");
	const record = (event: unknown): void => {
		appendFileSync(
			join(evidenceDir, `worker-${process.pid}.jsonl`),
			`${JSON.stringify({ at: new Date().toISOString(), workerPid: process.pid, event })}\n`,
		);
	};
	subscribeKernelDiagnostics(record);
	pi.on("tool_execution_end", (event) => record(event));
	process.on("exit", (code) => record({ type: "fixture_worker_exit", code }));

	const faux = registerFauxProvider({ provider: "causal-faux", models: [{ id: "kernel" }] });
	const respond: FauxResponseFactory = (context) => {
		faux.appendResponses([respond]);
		if (context.messages.at(-1)?.role === "toolResult") return fauxAssistantMessage("Cell completed.");
		const user = [...context.messages].reverse().find((message) => message.role === "user");
		if (!user) throw new Error("Missing fixture cell");
		const text =
			typeof user.content === "string"
				? user.content
				: user.content
						.filter((block) => block.type === "text")
						.map((block) => block.text)
						.join("\n");
		const cell: unknown = JSON.parse(text);
		if (!cell || typeof cell !== "object" || !("code" in cell) || typeof cell.code !== "string") {
			throw new Error("Fixture accepts only a JSON code cell");
		}
		return fauxAssistantMessage(fauxToolCall("ipython", { code: cell.code }), { stopReason: "toolUse" });
	};
	faux.setResponses([respond]);
	const api = getApiProvider(faux.api);
	if (!api) throw new Error("Missing faux API registration");
	pi.registerProvider(faux.getModel().provider, {
		api: faux.api,
		apiKey: "fixture-only",
		baseUrl: faux.getModel().baseUrl,
		streamSimple: api.streamSimple,
		models: faux.models,
	});
}
