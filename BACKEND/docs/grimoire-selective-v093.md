# GRIMOIRE selective v0.9.3 integration

## Selection and provenance

The upstream baseline is the exact prime-agent v0.9.3 tag, `915c78f42c248b08238dd27fcd4bcab32c60beab`, applied to `BACKEND/`. The starting main revision is `4cc20de8c9cbd95a554c27ffc84f3f20fb9ba4e1`.

The source branch's integration commit `9a9f1b224b858454782a9ed92c2f36c801447351` used an upstream parent five commits after that tag. Those later upstream commits are not imported wholesale. In particular, the newer automatic Shell-message producer is not introduced. No v0.9.4 update is included.

Existing main taskboard history/rollback, shell wake-up fixes, and root CI configuration are retained. Reviewed notification, kernel-repair, and test-isolation deltas were adapted from the previous integration candidate `3cf7964e27883eebb7e484fb8a33bcba266d2bc1`; that candidate's v0.9.4 baseline and unrelated fullscreen changes are not imported.

The incident recorder and source-branch diagnostic changes are excluded. `grim-16-incident-recorder` is not merged as a whole and is not modified.

## Behavior

Automatic subagent messages and terminal notices bypass editable steering/follow-up drafts and unrelated running shell commands. They run at the next safe tool/turn boundary, rather than waiting for the entire agent run to finish. Explicit stops, pauses, compaction, and branch mutations still apply. Delivery receipts and recovery records remain intact; clearing editable drafts does not discard these notifications.

Managed kernel startup checks `rlm.repl` protocol 3 and required imports. Source launches prefer the current runtime checkout over stale copied build assets. Repairs keep the virtual environment and interpreter in place when usable, reinstall the runtime and packages whose imports fail, and validate the result before updating the bootstrap marker. The same kernel manager revalidates its managed interpreter after restart. Explicit interpreter overrides are validated rather than silently modified.

Test entry points create a disposable home, agent directory, session directory, kernel environment, cache, and runtime directory before bootstrap or application imports. Direct Vitest invocation uses the same isolation. Real repair tests refuse to operate outside their disposable environment.

## Acceptance commands

From `BACKEND/`:

```sh
npm run check
cd packages/coding-agent
npm run test -- test/kernel-bootstrap.test.ts test/isolated-environment.test.ts test/suite/regressions/grimoire-automatic-notifications.test.ts
npm run test:repair
```

Root CI also runs agent-core, AI, TUI, the full coding-agent shards, process tests, real-kernel tests, and Python runtime tests. `test:repair` provisions its own isolated environment and verifies that the same manager repairs missing `dill` and `rlm.repl` files while preserving an environment sentinel and the interpreter inode.

## Local handoff: environment-dependent operations only

Do not repeat repository investigation or redesign these changes. Do not switch a checkout that a live agent is currently using. From a separate terminal, first finish the active session or choose a maintenance window, preserving any uncommitted work.

From `GRIMOIRE-WORKSPACE/`, with the GRIMOIRE worktree clean:

```sh
git -C GRIMOIRE fetch origin main
git -C GRIMOIRE status --short
git -C GRIMOIRE switch main
git -C GRIMOIRE merge --ff-only origin/main
cd GRIMOIRE/BACKEND
npm ci
npm run build --workspace packages/tui
npm exec --workspace packages/ai -- tsgo -p tsconfig.build.json
npm run build --workspace packages/agent
npm run build --workspace packages/coding-agent
```

If the worktree is dirty or the fast-forward is rejected, preserve that state and report the concrete conflict; do not reset, stash, or overwrite it automatically. The source branch must remain available.

Verify the local managed kernel without making a model request:

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

This last check uses the local managed environment, unlike the isolated regression tests. Run it only after the maintenance transition. Then launch the normal GRIMOIRE entry point and verify the terminal UI attaches normally. Only investigate a concrete local failure, using its exact command and error; no broader re-audit is required.

## File index for a concrete local failure

| Directory and filename | Role |
| --- | --- |
| `packages/coding-agent/src/core/agent-session.ts` | Notification admission, safe-boundary scheduling, shell wake-up, and preserved taskboard integration. |
| `packages/coding-agent/src/core/session-action-store.ts` | Delivery ownership and selection; supports notification priority without discarding receipts. |
| `packages/coding-agent/src/core/kernel/bootstrap.ts` | Runtime asset selection, readiness checks, locking, package repair, and bootstrap markers. |
| `packages/coding-agent/src/core/kernel/python-environment.ts` | Constructs the Python subprocess environment without inherited Python path overrides. |
| `packages/coding-agent/src/core/kernel/repl-manager.ts` | Starts, restarts, and shuts down the REPL process; managed restarts re-run readiness checks. |
| `packages/coding-agent/test/run-isolated.ts`, `test/isolated-environment.ts`, and `vitest.config.ts` | Establish disposable test state before bootstrap, Vitest, and application imports. |
| `packages/coding-agent/test/kernel-bootstrap-repair.test.ts` | Real-package repair and same-manager restart regressions, confined to disposable test state. |
| `packages/coding-agent/test/suite/regressions/grimoire-automatic-notifications.test.ts` | Delivery during shell activity, safe tool boundaries, explicit stops, draft clearing, ordering, and recovery. |
| `.github/workflows/ci.yml` at repository root | Full acceptance matrix, including the isolated real-repair job. |

All paths except the final workflow row are relative to `BACKEND/`.
