import {
	type FauxResponseFactory,
	fauxAssistantMessage,
	fauxToolCall,
	getApiProvider,
	registerFauxProvider,
} from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "../../src/index.js";

/** Deterministic model transport; every operation still reaches the real IPython tool. */
export default function registerAdmissionFixture(pi: ExtensionAPI): void {
	const faux = registerFauxProvider({ provider: "admission-faux", models: [{ id: "kernel" }] });
	const respond: FauxResponseFactory = (context) => {
		faux.appendResponses([respond]);
		const last = context.messages.at(-1);
		if (last?.role === "toolResult") {
			if (last.isError) throw new Error("Real IPython tool failed during admission");
			return fauxAssistantMessage("Cell completed.");
		}
		const user = [...context.messages].reverse().find((message) => message.role === "user");
		if (!user) throw new Error("Missing admission cell");
		const text =
			typeof user.content === "string"
				? user.content
				: user.content
						.filter((block) => block.type === "text")
						.map((block) => block.text)
						.join("\n");
		const cell = JSON.parse(text) as { code?: unknown };
		if (typeof cell.code !== "string") throw new Error("Expected a JSON code cell");
		return fauxAssistantMessage(fauxToolCall("ipython", { code: cell.code }), { stopReason: "toolUse" });
	};
	faux.setResponses([respond]);
	const api = getApiProvider(faux.api);
	if (!api) throw new Error("Missing admission provider");
	pi.registerProvider(faux.getModel().provider, {
		api: faux.api,
		apiKey: "fixture-only",
		baseUrl: faux.getModel().baseUrl,
		streamSimple: api.streamSimple,
		models: faux.models,
	});
}
