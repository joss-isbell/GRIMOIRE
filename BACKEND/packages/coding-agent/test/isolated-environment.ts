import { randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, parse } from "node:path";

const MARKER = ".grimoire-test-environment.json";
const ROOT_ENV = "GRIMOIRE_TEST_ENV_ROOT";
const TOKEN_ENV = "GRIMOIRE_TEST_ENV_TOKEN";

export interface IsolatedTestEnvironment {
	root: string;
	env: NodeJS.ProcessEnv;
	owned: boolean;
	cleanup(): void;
}

function inheritedRoot(env: NodeJS.ProcessEnv): string | undefined {
	const root = env[ROOT_ENV];
	if (!root || !env[TOKEN_ENV] || !basename(root).startsWith("g-tests-")) return undefined;
	try {
		const marker: unknown = JSON.parse(readFileSync(join(root, MARKER), "utf8"));
		if (typeof marker !== "object" || marker === null || !("token" in marker) || marker.token !== env[TOKEN_ENV])
			return undefined;
		return root;
	} catch {
		return undefined;
	}
}

/** Never inherit a running agent's sockets, kernel override, sessions or credentials. */
function testEnvironment(base: NodeJS.ProcessEnv, root: string, token: string): NodeJS.ProcessEnv {
	const env = { ...base };
	for (const key of Object.keys(env)) {
		if (
			/^(PRIME_AGENT_|PI_|RLM_|HERDR_|ACP_|CONDA_|AWS_)/i.test(key) ||
			/_API_(KEY|TOKEN)$/i.test(key) ||
			/^(PYTHON(HOME|PATH|STARTUP)|VIRTUAL_ENV|UV_(PROJECT_ENVIRONMENT|PYTHON.*|VENV_CLEAR)|GOOGLE_APPLICATION_CREDENTIALS|ANTHROPIC_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|SSH_AUTH_SOCK|SSH_AGENT_PID|CODEX_HOME|CLAUDE_CONFIG_DIR)$/i.test(
				key,
			)
		)
			delete env[key];
	}
	const home = join(root, "home");
	const agent = join(home, ".prime", "agent");
	const paths = {
		HOME: home,
		USERPROFILE: home,
		APPDATA: join(root, "config"),
		LOCALAPPDATA: join(root, "data"),
		PRIME_AGENT_CODING_AGENT_DIR: agent,
		PRIME_AGENT_SESSION_DIR: join(root, "sessions"),
		PRIME_AGENT_KERNEL_VENV: join(agent, "kernel-venv"),
		XDG_CONFIG_HOME: join(root, "config"),
		XDG_DATA_HOME: join(root, "data"),
		XDG_CACHE_HOME: join(root, "cache"),
		XDG_STATE_HOME: join(root, "state"),
		XDG_RUNTIME_DIR: join(root, "run"),
		UV_CACHE_DIR: join(root, "cache", "uv"),
		UV_PYTHON_INSTALL_DIR: join(root, "python"),
		TMPDIR: join(root, "tmp"),
		TMP: join(root, "tmp"),
		TEMP: join(root, "tmp"),
	};
	for (const path of Object.values(paths)) mkdirSync(path, { recursive: true, mode: 0o700 });
	return {
		...env,
		...paths,
		HOMEDRIVE: parse(home).root.replace(/[\\/]$/, ""),
		HOMEPATH: home.slice(parse(home).root.length - 1),
		NPM_CONFIG_USERCONFIG: join(home, ".npmrc"),
		DO_NOT_TRACK: "1",
		PRIME_AGENT_TELEMETRY: "0",
		PRIME_AGENT_INSTALL_UV: "0",
		[ROOT_ENV]: root,
		[TOKEN_ENV]: token,
	};
}

/** A wrapper and Vitest share one sandbox; only its creator may remove it. */
export function isolatedTestEnvironment(base: NodeJS.ProcessEnv = process.env): IsolatedTestEnvironment {
	const inherited = inheritedRoot(base);
	const root = inherited ?? mkdtempSync(join(tmpdir(), "g-tests-"));
	const token = inherited ? base[TOKEN_ENV]! : randomUUID();
	if (!inherited) writeFileSync(join(root, MARKER), JSON.stringify({ token, ownerPid: process.pid }), { mode: 0o600 });
	return {
		root,
		env: testEnvironment(base, root, token),
		owned: inherited === undefined,
		cleanup: () => {
			// Never delete a pathname supplied by an inherited environment variable.
			if (!inherited) rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
		},
	};
}
