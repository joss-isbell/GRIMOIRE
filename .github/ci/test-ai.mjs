import { spawnSync } from "node:child_process";

// Fork acceptance excludes unsupported providers/models, not the whole AI suite.
// Keep generic behavior tests in mixed files; these exact scenarios still use
// unsupported catalog entries even where their titles do not name the model.
const unsupportedNames = [
  /[Cc]opilot/,
  /OpenAI Codex Provider Abort/,
  /OpenAI Codex Provider.*should expose responseId/,
  /Cloudflare (?:Workers AI|AI Gateway) Provider/,
  /[Gg][Pp][Tt]-5\.2-codex/,
  /[Kk]imi[ -][Kk]2[.p]6/,
  /[Kk]imi[ -][Kk]3/,
  /[Qq]wen[ /-]?3\.8[ -][Mm]ax/,
  /Fireworks models.*registers the Fire Pass turbo router model/,
  /openai-completions empty tools handling.*uses conservative OpenAI-compatible fields for Cloudflare AI Gateway \/compat models/,
  /openai-completions empty tools handling.*sends session affinity headers for Workers AI through Cloudflare AI Gateway/,
  /openai-completions tool_choice.*distinguishes omitted reasoning from explicit off for Prime effort models/,
];
const pattern = `^(?!.*(?:${unsupportedNames.map((pattern) => pattern.source).join("|")})).*$`;
const result = spawnSync("npm", [
  "test", "--",
  "--exclude", "test/*copilot*.test.ts",
  "--exclude", "test/tool-call-id-normalization.test.ts",
  "--testNamePattern", pattern,
  ...process.argv.slice(2),
], { stdio: "inherit", env: { ...process.env, GRIMOIRE_CI: "1" } });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
