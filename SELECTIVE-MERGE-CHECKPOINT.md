# Selective v0.9.3 merge — completed on GitHub

## Durable result

On 2026-09-12 (America/Vancouver), `main` was fast-forwarded without force from `4cc20de8c9cbd95a554c27ffc84f3f20fb9ba4e1` to recovery checkpoint `fda85b3cf3fae77ad81e0ed1f572483f34dc2d44`. This document's commit records completion after that successful ref update.

The recovered implementation was already committed on `vi/selective-v093-ready`; it was reused, not rebuilt. The original `grim-16-incident-recorder` branch was not modified or merged wholesale.

| Commit | Completed work |
| --- | --- |
| `55746b5b8400fab27d6dabf0f7bbf479e4867511` | Selective v0.9.3 integration, prompt automatic notifications, kernel repair, and isolated tests, based directly on the previous main. |
| `32aeb6c65ea4be5724d9df00ee17da70e3b66842` | Existing isolated real-package repair check configuration. |
| `44325bdc1bfd2f1ae6f397f2053254a7f31e382f` | Independent session fixtures and explicit pauses for capacity-only assertions. |
| `fcaa73a6478fbceb067ebd0dd22dfe4cf1738c2c` | Clarified disposable test environments and fixture-local sessions. |
| `fda85b3cf3fae77ad81e0ed1f572483f34dc2d44` | Durable recovery checkpoint with scope and remaining operations. |

## Scope and verification limits

The saved integration provenance is in `BACKEND/docs/grimoire-selective-v093.md`. It identifies upstream v0.9.3 at `915c78f42c248b08238dd27fcd4bcab32c60beab`, excludes v0.9.4 and incident-recorder/diagnostic changes, and preserves existing main customizations. The newer automatic Shell-message producer is not introduced. Automatic subagent notifications bypass editable drafts and unrelated running shells, while respecting safe tool/turn boundaries and explicit stops/pauses.

This recovery performed bounded inspection: main ancestry; saved implementation history/provenance; the coding-agent v0.9.3 manifest; automatic-notification regression assertions; disposable test environment code; and the kernel directory, which has no incident diagnostic modules. No full repository audit or fresh passing test-suite result is claimed. The sandbox could not resolve `github.com` for checkout, and no alternate execution/export machinery was pursued.

## GRIMOIRE agent: remaining local operations only

Use this narrow checklist rather than repeating the broader acceptance matrix in the provenance document. Do not redo the integration or architecture work. Investigate only a concrete failure from these commands.

### 1. Update and build during a maintenance window

Do not switch or rebuild a checkout used by a live agent. Finish the active session first. Preserve any uncommitted work; stop if the worktree is dirty or a fast-forward fails. Do not automatically reset or stash it.

From `GRIMOIRE-WORKSPACE/`, first inspect:

```sh
git -C GRIMOIRE status --short
```

Only with a clean worktree and no agent using it:

```sh
git -C GRIMOIRE fetch origin main
git -C GRIMOIRE switch main
git -C GRIMOIRE merge --ff-only origin/main
cd GRIMOIRE/BACKEND
npm ci
npm run build --workspace packages/tui
npm exec --workspace packages/ai -- tsgo -p tsconfig.build.json
npm run build --workspace packages/agent
npm run build --workspace packages/coding-agent
```

### 2. Run only the focused regressions and isolated repair check

From `GRIMOIRE/BACKEND/`:

```sh
(
  cd packages/coding-agent
  npm run test -- test/kernel-bootstrap.test.ts test/isolated-environment.test.ts test/suite/regressions/grimoire-automatic-notifications.test.ts
  npm run test:repair
)
```

These entry points establish disposable test environments. The real-package repair test requires the local package/tooling environment; it is not evidence of a passing run until executed.

### 3. Smoke-test the local managed kernel and normal UI

After the maintenance transition, from `GRIMOIRE/BACKEND/`:

```sh
node --import tsx --input-type=module <<'JS'
import { ReplKernelManager } from './packages/coding-agent/src/core/kernel/index.ts';
const kernel = new ReplKernelManager({ cwd: process.cwd() });
try {
  const result = await kernel.execute('print(6 * 7)');
  if (result.status !== 'ok' || result.stdout.trim() !== '42') {
    throw new Error(JSON.stringify(result));
  }
  console.log('Local managed kernel: 42');
} finally {
  await kernel.shutdown({ snapshot: false });
}
JS
```

This smoke check intentionally uses the local managed environment, unlike the isolated regressions. Then launch the normal GRIMOIRE entry point and confirm the UI attaches. Report only the concrete failing command/error if either fails.

## Master index

`BACKEND/docs/grimoire-selective-v093.md` contains the detailed provenance and file-role index. Principal files, relative to `BACKEND/`, are:

| Directory and filename | Role |
| --- | --- |
| `packages/coding-agent/src/core/agent-session.ts` | Notification admission and safe-boundary scheduling, shell wake-up, and taskboard integration. |
| `packages/coding-agent/src/core/session-action-store.ts` | Delivery ownership and notification selection without discarding receipts. |
| `packages/coding-agent/src/core/kernel/bootstrap.ts` | Runtime selection, readiness validation, managed-environment repair, and bootstrap markers. |
| `packages/coding-agent/src/core/kernel/python-environment.ts` | Python subprocess environment construction. |
| `packages/coding-agent/src/core/kernel/repl-manager.ts` | REPL startup, restart readiness validation, and shutdown. |
| `packages/coding-agent/test/run-isolated.ts` | Test entry point that establishes disposable state before bootstrap and Vitest. |
| `packages/coding-agent/test/isolated-environment.ts` | Disposable home, agent, kernel, session, and cache locations with owned cleanup. |
| `packages/coding-agent/vitest.config.ts` | Applies the same isolation to direct Vitest invocation. |
| `packages/coding-agent/test/kernel-bootstrap.test.ts` | Focused bootstrap regression tests. |
| `packages/coding-agent/test/isolated-environment.test.ts` | Focused environment-isolation regression tests. |
| `packages/coding-agent/test/kernel-bootstrap-repair.test.ts` | Isolated real-package repair and same-manager restart tests. |
| `packages/coding-agent/test/suite/regressions/grimoire-automatic-notifications.test.ts` | Notification delivery during shell activity, safe boundaries, pauses, draft clearing, ordering, and recovery. |
