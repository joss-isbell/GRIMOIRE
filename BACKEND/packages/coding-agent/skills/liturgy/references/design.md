# LITURGY design

LITURGY is the product name for Prime Agent's durable work-reconciliation
board. It records the Agent's materially understood work shape as phased,
nested tasks. This document describes the implemented skill design; it does not
make the board authoritative for the user's desired outcome or the delivered
product.

## Source examined

The design was based on the installed `omp/18.0.6` Bun executable. Its embedded
sources identify the TODO behavior in `prompts/tools/todo.md`, `tools/todo.ts`,
todo tracking, eager/mid-run reminders, and goal TODO context.

OMP provides these main outcomes:

- ordered phases and task states;
- one automatically promoted active task;
- blocked, completed, and abandoned work;
- session-branch persistence and goal-continuation reinjection;
- a sticky terminal HUD, stop-time reminders, and mid-run nudges;
- manual Markdown edit, import, and export.

## Prime-native reinterpretation

LITURGY preserves the useful execution outcomes without copying OMP's host
implementation:

| Outcome | Prime-native mechanism |
|---|---|
| Survive turns and compaction | Versioned JSON in `RLM_SESSION_DIR` |
| Resume a long objective | Prime's separate host-owned `goal` |
| Represent understood work shape | Ordered phases with root tasks and nested subtasks |
| Preserve identity through plan changes | Stable IDs and metadata-preserving `move` |
| Keep stale work inspectable | Visible `retired` terminal state |
| Parallel work | Multiple `in_progress` tasks with owners |
| Parent attention | Optional `focused_task_id`, separate from status |
| Delegation | Root records an admitted child name/ID; child reports by message or artifact |
| Blocked work | `blocked` only for an actual external dependency |
| Completion confidence | Result note plus concrete evidence references |
| Context recovery | `view` reloads the file-backed authoritative snapshot |
| Adoption | Global prompt routing rule plus this skill's routing description |

Stable generated task IDs replace OMP's verbatim-text identity and fuzzy content
mutation. Parallel status replaces OMP's single-active invariant because Prime
can run multiple child Agents at once. The optional focus pointer preserves a
single local next action without falsely serializing those children.

Nested tasks let discovery refine a known item without replacing its identity.
`move` promotes, demotes, reparents, or changes a task's phase while retaining
its ID and execution metadata. A task subtree must occupy one phase. Self
parenting, cycles, and parent/phase conflicts fail without changing persisted
state.

## Reconciliation lifecycle

1. Initialize one board from a user checklist or a truthful execution plan.
2. Start one or more tasks. Set the root's local focus separately when useful.
3. Record admitted child ownership on delegated tasks. When responsibility
   returns to the root, clear the stale owner as part of the next transition.
4. Update after material state changes. Verify child outputs before marking them
   completed.
5. Whenever understanding materially changes the work shape, reconcile it
   promptly: add discoveries; promote, demote, reparent, or move known work;
   retire stale items; and align status, blocker, owner, result, and evidence.
6. Block only on an external dependency. Continue other runnable tasks.
7. Reopen terminal work when it becomes actionable. Reopen clears stale owner,
   blocker, result, and evidence before the new attempt.
8. Before compaction and after recovery, view the board and use its revision.
9. Close only after every task is completed or retired and the outcome audit is
   finished. Retired work remains visible in history.

Each valid state mutation is an atomic file replacement and increments
`revision`. Callers can pass `expected_revision` to reject stale updates.
Invalid hierarchy changes, unknown schemas, and corrupt schemas fail closed and
retain the file for diagnosis.

## Boundaries

- Global installation makes the capability available in every session. It does
  not make live task state global. Each thread has an isolated board.
- Only the parent/root writes its board. A child has a different
  `RLM_SESSION_DIR`; shared writes are unsupported.
- Session deletion intentionally deletes its artifacts. Deactivation or resume
  preserves them.
- A child spawn, running state, queued message, or delivered message is not task
  completion.
- Evidence fields store references, not truth. The Agent must inspect and judge
  the evidence.
- The board is an execution aid. It does not replace canonical requirements,
  version-controlled output, an external operational ledger, or user-visible
  progress communication.
- The global prompt rule improves reliable adoption, but a skill cannot provide
  OMP's host-level sticky HUD, action counter, or hard stop hook. Those would
  require a Prime host feature rather than skill code.
- Name collisions can shadow a global skill according to normal Prime skill
  precedence. A custom `PRIME_AGENT_KERNEL_PYTHON` can also disable automatic
  package installation.
