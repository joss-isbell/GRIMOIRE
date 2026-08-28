---
name: liturgy
description: Maintains a durable, phased execution board for a Prime Agent thread, with nested work, stable task IDs, parallel owners, blockers, focus, results, and evidence. Use when the user requests todos/checklists or progress tracking, supplies multiple required work items, starts a persistent goal, or when substantive work spans several independently verifiable checkpoints, turns, compaction, or parallel child Agents. Skip simple one-step work.
---

# LITURGY

LITURGY is the product name for this durable work-reconciliation board. Use the
Python-backed `liturgy` module. The capability is global, but each board belongs
only to its Prime thread and is stored at `$RLM_SESSION_DIR/liturgy.json`.

## Common calls

```python
await liturgy("init", title="Ship the change", plan={
    "Discovery": ["Inspect current behavior", "Confirm intended outcome"],
    "Delivery": ["Implement bounded change", "Run acceptance checks"],
})
await liturgy("start", task="T001", focus=True)
await liturgy("add", phase="Discovery", tasks=["Investigate discovered edge case"],
              parent="T001")
await liturgy("move", task="T002", phase="Delivery", parent="T003")
await liturgy("done", task="T001", note="Located the state boundary",
              evidence=["src/state.ts:40-91"])
await liturgy("retire", task="T004", note="Superseded by the verified boundary")
await liturgy("view")
await liturgy("close", note="Outcome delivered and reconciled")
```

Omit `parent` in `move` to promote the task to a phase root. Pass
`clear_owner=True` on `start`, `move`, `block`, `unblock`, `done`, or `retire`
when responsibility returns to the root or is otherwise no longer assigned.
Do not combine `owner` and `clear_owner`. Use `help(liturgy)` for the complete
callable signature.

## State model

- `pending`: actionable but not started.
- `in_progress`: currently running. Several tasks may run in parallel.
- `blocked`: stopped by a real external dependency. A reason is required.
- `completed`: verified finished work.
- `retired`: visible stale work intentionally removed from the current work shape.
- `focus` is a separate local pointer. It does not limit parallel work.

Tasks may contain nested subtasks. A task and its descendants stay in one phase.
Use stable generated IDs such as `T003` for mutations. IDs and task metadata
survive `move`. Text matching is a convenience only. Duplicate task text is
valid and therefore may require IDs.

## Operating rules

1. The root Agent owns and writes its board. Child Agents have separate session
   directories. They report through `agent_message` or artifacts.
2. For delegated work, mark the task `in_progress` and set `owner` to the child
   name and ID. A spawn handle or delivered message is not proof of completion.
3. Use `blocked` only when work cannot proceed. Do not mark a running child task
   blocked merely because the root is awaiting its reply.
4. Update tasks at material milestones. Put the outcome in `note`. Put concise,
   inspectable proof such as a test result, command, or path in `evidence`.
5. Reconcile the board whenever materially understood work shape changes.
   Promptly add discoveries. Promote, demote, reparent, or move existing tasks
   with `move`. Retire stale items instead of hiding them. Align each affected
   task's status, blocker, owner, result, and evidence with reality.
6. Reopen terminal work when it becomes actionable again. Reopening clears its
   stale owner, blocker, result, and evidence so new work is not presented with
   old terminal metadata.
7. Before compaction or after recovery, call `view`. The JSON artifact is
   authoritative; notebook variables and transcript recollection are not.
8. `close` refuses while any task is pending, running, or blocked. Reconcile all
   work before closing. Retired items remain visible in the closed history.
9. Board calls must not replace substantive work or user-visible progress
   updates.

## Prime-native integration

- A board does not create or complete a Prime persistent goal. If the user
  explicitly starts a long-running goal, use `goal` as the host objective and
  pass its objective snapshot as `goal_objective` during `init`.
- Prime's goal continuation and child lifecycle remain authoritative. Do not
  build polling or continuation loops around this skill.
- Only the root Agent mutates its board. Store large child evidence in files and
  keep only references on the board.

See [references/design.md](references/design.md) for the OMP comparison,
lifecycle details, limitations, and verification model.
