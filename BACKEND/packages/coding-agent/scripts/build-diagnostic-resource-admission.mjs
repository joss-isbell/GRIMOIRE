import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, realpath, symlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const [flag, requestedRoot] = process.argv.slice(2);
if (process.platform !== "linux" || flag !== "--output" || !requestedRoot || !isAbsolute(requestedRoot)) throw new Error("usage: Linux Node build-diagnostic-resource-admission.mjs --output /new/private/path");
const root = resolve(requestedRoot);
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const backend = dirname(dirname(packageRoot));
if (root.startsWith(`${backend}/`)) throw new Error("Admission output must be outside the public backend checkout");
await mkdir(root, { mode: 0o700 });
const bundle = join(root, "bundle");
await mkdir(bundle);
await symlink(join(backend, "node_modules"), join(root, "node_modules"));
await writeFile(join(root, "package.json"), '{"type":"module","private":true}\n');
const inputHashes = new Map();
const packages = new Map();
for (const directory of ["ai", "agent", "tui", "coding-agent"]) {
	const path = join(backend, "packages", directory);
	const json = JSON.parse(await readFile(join(path, "package.json"), "utf8"));
	packages.set(json.name, { path, json });
}
const sourcePlugin = { name: "freeze-canonical-source", setup(builder) {
	builder.onResolve({ filter: /^@earendil-works\/pi-/ }, (args) => {
		const name = [...packages.keys()].find((key) => args.path === key || args.path.startsWith(`${key}/`));
		if (!name) return;
		const { path, json } = packages.get(name);
		const key = `.${args.path.slice(name.length)}`;
		const exported = json.exports?.[key];
		const target = typeof exported === "string" ? exported : exported?.import ?? (key === "." ? json.main : undefined);
		if (!target) throw new Error(`Unresolved canonical package export: ${args.path}`);
		return { path: join(path, target.replace(/^\.\//, "").replace(/^dist\//, "src/").replace(/\.js$/, ".ts")) };
	});
	builder.onLoad({ filter: /\.(ts|tsx|js|mjs)$/ }, async (args) => {
		if (!args.path.startsWith(`${backend}/packages/`) || args.path.includes("/node_modules/")) return;
		const contents = await readFile(args.path, "utf8");
		inputHashes.set(args.path, createHash("sha256").update(contents).digest("hex"));
		return { contents, loader: args.path.endsWith(".tsx") ? "tsx" : args.path.endsWith(".ts") ? "ts" : "js" };
	});
} };
const entries = { cli: join(packageRoot, "src/cli.ts"), "diagnostic-evidence-service": join(packageRoot, "src/diagnostic-evidence-service.ts"),
	"diagnostic-evidence-store-worker": join(packageRoot, "src/modes/daemon/diagnostic-evidence-store-worker.ts"),
	"admission-workload": join(packageRoot, "test/fixtures/diagnostic-resource-workload.ts") };
const result = await build({ entryPoints: entries, outdir: bundle, bundle: true, splitting: true, format: "esm", platform: "node", metafile: true,
	external: ["zeromq", "koffi", "undici", "@silvia-odwyer/photon-node", "@mariozechner/clipboard"],
	define: { __PI_BUNDLED__: "true", __PI_BUILD_ID__: JSON.stringify("isolated-admission") }, plugins: [sourcePlugin],
	banner: { js: "import { createRequire as __admissionRequire } from 'node:module'; const require = __admissionRequire(import.meta.url);" }, logLevel: "warning" });
await build({ entryPoints: [join(packageRoot, "test/fixtures/diagnostic-resource-extension.ts")], outfile: join(bundle, "admission-extension.js"), format: "esm", platform: "node", bundle: false, logLevel: "warning" });
for (const [path, hash] of inputHashes) if (createHash("sha256").update(await readFile(path)).digest("hex") !== hash) throw new Error(`Canonical source changed during build: ${path}`);
const probe = await readFile(join(packageRoot, "scripts/diagnostic-causal.bt"));
await writeFile(join(root, "diagnostic-causal.bt"), probe);
const artifactHashes = {};
for (const path of [...Object.keys(result.metafile.outputs).map((path) => resolve(path)), join(bundle, "admission-extension.js"), join(root, "diagnostic-causal.bt")]) artifactHashes[path] = createHash("sha256").update(await readFile(path)).digest("hex");
const config = { schema: 1, id: randomUUID().replaceAll("-", "").slice(0, 16), root, packageRoot, node: await realpath(process.execPath),
	python: resolve(process.env.PRIME_AGENT_KERNEL_PYTHON ?? join(homedir(), ".prime/agent/kernel-venv/bin/python")),
	uid: process.getuid(), gid: process.getgid(), warmupSeconds: 15, measureSeconds: 45, order: ["A", "B", "B", "A"],
	atopIntervalSeconds: 1, cli: join(bundle, "cli.js"), workload: join(bundle, "admission-workload.js"), extension: join(bundle, "admission-extension.js"),
	service: join(bundle, "diagnostic-evidence-service.js"), probe: join(root, "diagnostic-causal.bt"), artifactHashes,
	limitations: ["pilot_only", "four_rounds_insufficient_for_tight_inference", "export_pressure_unmeasured_without_legitimate_incidents", "full_45_minute_native_window_not_established", "installed_full_host_atop_is_constant_background_private_pid_namespace_atop_measures_additional_test_process_capture"] };
config.runtimeRoot = `/var/tmp/${config.id}`;
await writeFile(join(root, "config.json"), JSON.stringify(config, null, 2), { mode: 0o600 });
await writeFile(join(root, "build.json"), JSON.stringify({ node: process.versions, sourceHashes: Object.fromEntries(inputHashes),
	gitHead: execFileSync("git", ["-C", dirname(backend), "rev-parse", "HEAD"], { encoding: "utf8" }).trim(), artifactHashes }, null, 2), { mode: 0o600 });
console.log(JSON.stringify({ config: join(root, "config.json"), sourceFiles: inputHashes.size, artifactFiles: Object.keys(artifactHashes).length }));
