"""Prime-native durable Liturgy state for one agent thread."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    from rlm import host_request as _host_request
except ImportError:  # Explicit standalone package-test mode.
    _host_request = None

_SCHEMA_VERSION = 1
_STATE_FILE = "liturgy.json"
_VALID_ACTIONS = {
    "view",
    "init",
    "add",
    "move",
    "start",
    "focus",
    "block",
    "unblock",
    "done",
    "retire",
    "reopen",
    "close",
    "history",
}
_TERMINAL = {"completed", "retired"}
_STATUSES = {"pending", "in_progress", "blocked", *_TERMINAL}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _standalone_state_path() -> Path:
    root = os.environ.get("LITURGY_STATE_DIR")
    if not root:
        raise RuntimeError(
            "liturgy needs the Prime Agent host bridge; LITURGY_STATE_DIR is only "
            "available in a standalone package-test process"
        )
    directory = Path(root).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / _STATE_FILE


def _empty_state() -> dict[str, Any]:
    return {"schema_version": _SCHEMA_VERSION, "revision": 0, "active": None, "history": []}


def _clean(value: str | None, field: str, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    cleaned = " ".join(value.split())
    if required and not cleaned:
        raise ValueError(f"{field} cannot be empty")
    return cleaned or None


def _all_tasks(board: dict[str, Any]) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    for phase in board["phases"]:
        for item in phase["tasks"]:
            yield phase, item


def _task_index(board: dict[str, Any]) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    return {item["id"]: (phase, item) for phase, item in _all_tasks(board)}


def _validate_board(board: dict[str, Any]) -> None:
    if not isinstance(board.get("phases"), list):
        raise RuntimeError("Invalid Liturgy phases; state was not changed")
    phase_names: set[str] = set()
    tasks: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for phase in board["phases"]:
        if not isinstance(phase, dict) or not isinstance(phase.get("name"), str) or not phase["name"].strip():
            raise RuntimeError("Invalid Liturgy phase; state was not changed")
        phase_key = phase["name"].casefold()
        if phase_key in phase_names or not isinstance(phase.get("tasks"), list):
            raise RuntimeError("Invalid or duplicate Liturgy phase; state was not changed")
        phase_names.add(phase_key)
        for item in phase["tasks"]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise RuntimeError("Invalid Liturgy task; state was not changed")
            task_id = item["id"]
            if task_id in tasks:
                raise RuntimeError(f"Duplicate task ID {task_id}; state was not changed")
            if not isinstance(item.get("text"), str) or not item["text"].strip():
                raise RuntimeError(f"Invalid text for {task_id}; state was not changed")
            if item.get("status") not in _STATUSES:
                raise RuntimeError(f"Invalid status for {task_id}; state was not changed")
            if item.get("parent_id") is not None and not isinstance(item["parent_id"], str):
                raise RuntimeError(f"Invalid parent for {task_id}; state was not changed")
            if item.get("owner") is not None and not isinstance(item["owner"], str):
                raise RuntimeError(f"Invalid owner for {task_id}; state was not changed")
            if item.get("blocker") is not None and not isinstance(item["blocker"], str):
                raise RuntimeError(f"Invalid blocker for {task_id}; state was not changed")
            if item.get("result") is not None and not isinstance(item["result"], str):
                raise RuntimeError(f"Invalid result for {task_id}; state was not changed")
            evidence = item.get("evidence")
            if not isinstance(evidence, list) or not all(isinstance(value, str) for value in evidence):
                raise RuntimeError(f"Invalid evidence for {task_id}; state was not changed")
            if item["status"] == "blocked":
                if not item.get("blocker"):
                    raise RuntimeError(f"Blocked task {task_id} needs a blocker; state was not changed")
            elif item.get("blocker") is not None:
                raise RuntimeError(f"Non-blocked task {task_id} has a blocker; state was not changed")
            if item["status"] not in _TERMINAL and (item.get("result") is not None or evidence):
                raise RuntimeError(f"Open task {task_id} has terminal metadata; state was not changed")
            tasks[task_id] = (phase, item)

    for task_id, (phase, item) in tasks.items():
        parent_id = item.get("parent_id")
        if parent_id is None:
            continue
        if parent_id == task_id or parent_id not in tasks:
            raise RuntimeError(f"Invalid parent for {task_id}; state was not changed")
        parent_phase, _ = tasks[parent_id]
        if parent_phase is not phase:
            raise RuntimeError(f"Parent and child phases differ for {task_id}; state was not changed")
        seen = {task_id}
        cursor: str | None = parent_id
        while cursor is not None:
            if cursor in seen:
                raise RuntimeError(f"Parent cycle at {task_id}; state was not changed")
            seen.add(cursor)
            cursor = tasks[cursor][1].get("parent_id")

    focused = board.get("focused_task_id")
    if focused is not None:
        if focused not in tasks or tasks[focused][1]["status"] not in {"pending", "in_progress"}:
            raise RuntimeError("Invalid focused task; state was not changed")
    next_number = board.get("next_task_number")
    if not isinstance(next_number, int) or next_number < 1:
        raise RuntimeError("Invalid next task number; state was not changed")


def _validate_state(state: dict[str, Any]) -> None:
    active = state.get("active")
    if active is not None:
        if not isinstance(active, dict):
            raise RuntimeError("Invalid active Liturgy; state was not changed")
        _validate_board(active)
    for board in state.get("history", []):
        if not isinstance(board, dict):
            raise RuntimeError("Invalid Liturgy history; state was not changed")
        _validate_board(board)


async def _load() -> dict[str, Any]:
    if _host_request is not None:
        response = await _host_request("liturgy.get", {})
        if not isinstance(response, dict) or "state" not in response:
            raise RuntimeError("Invalid liturgy.get response; state was not changed")
        state = response["state"]
        source = "host"
    else:
        path = _standalone_state_path()
        if not path.exists():
            return _empty_state()
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read liturgy state at {path}: {exc}") from exc
        source = str(path)
    if not isinstance(state, dict) or state.get("schema_version") != _SCHEMA_VERSION:
        raise RuntimeError(f"Unsupported liturgy schema from {source}; state was not changed")
    if not isinstance(state.get("revision"), int) or not isinstance(state.get("history"), list):
        raise RuntimeError(f"Invalid liturgy state from {source}; state was not changed")
    _validate_state(state)
    return state


async def _save(state: dict[str, Any]) -> None:
    _validate_state(state)
    expected_revision = state["revision"]
    if _host_request is not None:
        response = await _host_request(
            "liturgy.commit", {"expected_revision": expected_revision, "state": state}
        )
        if not isinstance(response, dict) or not isinstance(response.get("state"), dict):
            raise RuntimeError("Invalid liturgy.commit response; state was not changed")
        committed = response["state"]
        if committed.get("revision") != expected_revision + 1:
            raise RuntimeError("Invalid liturgy.commit revision; state was not changed")
        _validate_state(committed)
        state.clear()
        state.update(committed)
        return

    path = _standalone_state_path()
    current_revision = 0
    if path.exists():
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read liturgy state at {path}: {exc}") from exc
        if not isinstance(current, dict) or not isinstance(current.get("revision"), int):
            raise RuntimeError(f"Invalid liturgy state at {path}; state was not changed")
        current_revision = current["revision"]
    if current_revision != expected_revision:
        raise ValueError(
            f"Stale liturgy revision: expected {expected_revision}, current {current_revision}. "
            "View the Liturgy before retrying."
        )
    saved = {**state, "revision": expected_revision + 1}
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    payload = json.dumps(saved, indent=2, ensure_ascii=False) + "\n"
    try:
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise RuntimeError(f"Cannot write liturgy state at {path}: {exc}") from exc
    state.clear()
    state.update(saved)


def _new_board(
    title: str,
    phases: list[tuple[str, list[str]]],
    *,
    goal_objective: str | None = None,
    note: str | None = None,
    synthetic_default: bool = False,
) -> dict[str, Any]:
    now = _now()
    board: dict[str, Any] = {
        "id": f"L-{uuid.uuid4().hex[:10]}",
        "title": title,
        "goal_objective": goal_objective,
        "created_at": now,
        "updated_at": now,
        "next_task_number": 1,
        "focused_task_id": None,
        "phases": [],
        "events": [],
        "synthetic_default": synthetic_default,
    }
    for phase_name, values in phases:
        board["phases"].append(
            {"name": phase_name, "tasks": [_new_task(board, text) for text in values]}
        )
    if not synthetic_default:
        _record(board, "init", note=note)
    return board


def _default_board() -> dict[str, Any]:
    return _new_board("Agent work", [("Work", [])], synthetic_default=True)


def _is_untouched_default(board: dict[str, Any]) -> bool:
    phases = board.get("phases")
    return bool(
        board.get("synthetic_default") is True
        and board.get("title") == "Agent work"
        and board.get("goal_objective") is None
        and board.get("next_task_number") == 1
        and board.get("focused_task_id") is None
        and board.get("events") == []
        and isinstance(phases, list)
        and len(phases) == 1
        and phases[0].get("name") == "Work"
        and phases[0].get("tasks") == []
    )


def _board(state: dict[str, Any]) -> dict[str, Any]:
    board = state.get("active")
    if not isinstance(board, dict):
        raise ValueError("No active Liturgy")
    return board


def _is_open(board: dict[str, Any]) -> bool:
    return any(item["status"] not in _TERMINAL for _, item in _all_tasks(board))


def _counts(board: dict[str, Any]) -> dict[str, int]:
    counts = {key: 0 for key in ("pending", "in_progress", "blocked", "completed", "retired")}
    for _, item in _all_tasks(board):
        counts[item["status"]] += 1
    return counts


def _record(
    board: dict[str, Any],
    action: str,
    item: dict[str, Any] | None = None,
    *,
    previous: str | None = None,
    note: str | None = None,
) -> None:
    event: dict[str, Any] = {"at": _now(), "action": action}
    if item is not None:
        event.update({"task": item["id"], "from": previous, "to": item["status"]})
    if note:
        event["note"] = note
    board.setdefault("events", []).append(event)
    board["updated_at"] = event["at"]


def _resolve(board: dict[str, Any], reference: str | None, field: str = "task") -> dict[str, Any]:
    ref = _clean(reference, field, required=True)
    assert ref is not None
    folded = ref.casefold()
    exact_text: list[dict[str, Any]] = []
    fragments: list[dict[str, Any]] = []
    for _, item in _all_tasks(board):
        if item["id"].casefold() == folded:
            return item
        if item["text"].casefold() == folded:
            exact_text.append(item)
        elif folded in item["text"].casefold():
            fragments.append(item)
    matches = exact_text or fragments
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        choices = ", ".join(f"{item['id']} ({item['text']})" for item in matches)
        raise ValueError(f"{field.title()} reference is ambiguous: {choices}. Use a stable task ID.")
    raise ValueError(f"{field.title()} not found: {ref}. Use action='view' to recover stable IDs.")


def _phase(board: dict[str, Any], name: str) -> dict[str, Any] | None:
    return next((value for value in board["phases"] if value["name"].casefold() == name.casefold()), None)


def _new_task(board: dict[str, Any], text: str, parent_id: str | None = None) -> dict[str, Any]:
    number = int(board["next_task_number"])
    board["next_task_number"] = number + 1
    now = _now()
    return {
        "id": f"T{number:03d}",
        "text": text,
        "parent_id": parent_id,
        "status": "pending",
        "owner": None,
        "blocker": None,
        "result": None,
        "evidence": [],
        "created_at": now,
        "updated_at": now,
    }


def _normalize_tasks(values: list[str] | None) -> list[str]:
    if values is None:
        raise ValueError("tasks is required")
    cleaned: list[str] = []
    for value in values:
        text = _clean(value, "task text", required=True)
        assert text is not None
        cleaned.append(text)
    if not cleaned:
        raise ValueError("tasks cannot be empty")
    return cleaned


def _normalize_plan(plan: dict[str, list[str]] | None) -> list[tuple[str, list[str]]]:
    if not isinstance(plan, dict) or not plan:
        raise ValueError("plan must be a non-empty ordered phase-to-task mapping")
    normalized: list[tuple[str, list[str]]] = []
    seen_phases: set[str] = set()
    for raw_phase, raw_tasks in plan.items():
        phase = _clean(raw_phase, "phase", required=True)
        assert phase is not None
        key = phase.casefold()
        if key in seen_phases:
            raise ValueError(f"Duplicate phase name: {phase}")
        seen_phases.add(key)
        normalized.append((phase, _normalize_tasks(raw_tasks)))
    return normalized


def _normalize_evidence(values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    cleaned: list[str] = []
    for value in values:
        item = _clean(value, "evidence", required=True)
        assert item is not None
        cleaned.append(item)
    return cleaned


def _children(board: dict[str, Any], parent_id: str | None, phase: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in phase["tasks"] if item.get("parent_id") == parent_id]


def _subtree_ids(board: dict[str, Any], root_id: str) -> set[str]:
    result: set[str] = set()
    pending = [root_id]
    while pending:
        current = pending.pop()
        if current in result:
            continue
        result.add(current)
        pending.extend(item["id"] for _, item in _all_tasks(board) if item.get("parent_id") == current)
    return result


def _render(board: dict[str, Any], revision: int) -> str:
    counts = _counts(board)
    total = sum(counts.values())
    closed = counts["completed"] + counts["retired"]
    lines = [
        f"# {board['title']}",
        (
            f"Liturgy {board['id']} · revision {revision} · {closed}/{total} closed · "
            f"{counts['in_progress']} running · {counts['pending']} pending · "
            f"{counts['blocked']} blocked · {counts['retired']} retired"
        ),
    ]
    if board.get("goal_objective"):
        lines.append(f"Persistent goal: {board['goal_objective']}")
    markers = {
        "pending": "[ ]",
        "in_progress": "[/]",
        "blocked": "[!]",
        "completed": "[x]",
        "retired": "[-]",
    }
    focused = board.get("focused_task_id")

    def render_item(item: dict[str, Any], phase_value: dict[str, Any], depth: int) -> None:
        suffixes: list[str] = []
        if item["id"] == focused:
            suffixes.append("focus")
        if item.get("owner"):
            suffixes.append(f"owner: {item['owner']}")
        if item.get("blocker"):
            suffixes.append(f"blocked: {item['blocker']}")
        if item.get("result"):
            suffixes.append(f"result: {item['result']}")
        if item.get("evidence"):
            suffixes.append("evidence: " + " | ".join(item["evidence"]))
        suffix = f" — {'; '.join(suffixes)}" if suffixes else ""
        lines.append(f"{'  ' * depth}- {markers[item['status']]} {item['id']} {item['text']}{suffix}")
        for child in _children(board, item["id"], phase_value):
            render_item(child, phase_value, depth + 1)

    for phase_value in board["phases"]:
        lines.extend(["", f"## {phase_value['name']}"])
        for root in _children(board, None, phase_value):
            render_item(root, phase_value, 0)

    focused_item = next((item for _, item in _all_tasks(board) if item["id"] == focused), None)
    pending_item = next((item for _, item in _all_tasks(board) if item["status"] == "pending"), None)
    if focused_item:
        lines.extend(["", f"Local focus: {focused_item['id']} {focused_item['text']}"])
    elif pending_item:
        lines.extend(["", f"Suggested next: {pending_item['id']} {pending_item['text']} (not auto-started)"])
    elif counts["in_progress"]:
        lines.extend(["", "Local focus: none; running work is owned elsewhere or needs an explicit focus."])
    elif counts["blocked"]:
        lines.extend(["", "Next action: no runnable task; resolve or report the blockers."])
    else:
        lines.extend(["", "Next action: audit the outcome, then close the Liturgy."])
    return "\n".join(lines)


def _render_history(state: dict[str, Any]) -> str:
    history = state["history"]
    if not history:
        return f"No closed Liturgies. State revision: {state['revision']}."
    lines = [f"# Closed Liturgies (state revision {state['revision']})"]
    for board in reversed(history[-20:]):
        counts = _counts(board)
        total = sum(counts.values())
        closed = counts["completed"] + counts["retired"]
        lines.append(
            f"- {board['id']} {board['title']} — {closed}/{total} closed — "
            f"{board.get('closed_at', 'unknown time')}"
        )
    return "\n".join(lines)


async def run(
    action: str = "view",
    *,
    title: str | None = None,
    plan: dict[str, list[str]] | None = None,
    phase: str | None = None,
    tasks: list[str] | None = None,
    task: str | None = None,
    parent: str | None = None,
    note: str | None = None,
    reason: str | None = None,
    owner: str | None = None,
    clear_owner: bool = False,
    evidence: list[str] | None = None,
    goal_objective: str | None = None,
    focus: bool = False,
    expected_revision: int | None = None,
) -> str:
    """Manage durable Liturgy state for the current Prime Agent thread.

    ``parent`` is accepted by ``add`` and ``move``. Children always share their
    parent's phase. For ``move``, ``phase`` is the required destination and a
    missing or ``None`` parent promotes the task to a phase root. Set
    ``clear_owner`` on a task transition to remove an assignment that no longer
    reflects reality; it cannot be combined with ``owner``.
    """
    action = (_clean(action, "action", required=True) or "").casefold()
    if action not in _VALID_ACTIONS:
        raise ValueError(f"Unknown action {action!r}; expected one of {sorted(_VALID_ACTIONS)}")

    state = await _load()
    if action == "history":
        return _render_history(state)
    if expected_revision is not None and action != "view" and expected_revision != state["revision"]:
        raise ValueError(
            f"Stale liturgy revision: expected {expected_revision}, current {state['revision']}. "
            "View the Liturgy before retrying."
        )

    if action == "view" and not isinstance(state.get("active"), dict):
        while not isinstance(state.get("active"), dict):
            state["active"] = _default_board()
            try:
                await _save(state)
            except ValueError:
                # A concurrent first caller may have won the compare-and-swap.
                # Reload its board rather than replacing it or hiding later stale writes.
                state = await _load()
        return _render(state["active"], state["revision"])
    if action == "view":
        return _render(_board(state), state["revision"])

    creating_default = action != "init" and not isinstance(state.get("active"), dict)
    if creating_default:
        # The action and first board creation share one compare-and-swap commit.
        state["active"] = _default_board()

    clean_note = _clean(note, "note")
    clean_owner = _clean(owner, "owner")
    if clear_owner and clean_owner is not None:
        raise ValueError("owner and clear_owner cannot be used together")
    clean_evidence = _normalize_evidence(evidence)

    def reconcile_owner(item: dict[str, Any]) -> None:
        if clear_owner:
            item["owner"] = None
        elif clean_owner is not None:
            item["owner"] = clean_owner

    if action == "init":
        active = state.get("active")
        if isinstance(active, dict) and not _is_untouched_default(active):
            raise ValueError("An active Liturgy already exists. Reconcile and close it before creating another.")
        clean_title = _clean(title, "title", required=True)
        assert clean_title is not None
        normalized_plan = _normalize_plan(plan)
        board = _new_board(
            clean_title,
            normalized_plan,
            goal_objective=_clean(goal_objective, "goal_objective"),
            note=clean_note,
        )
        state["active"] = board
        await _save(state)
        return _render(board, state["revision"])

    board = _board(state)
    board["synthetic_default"] = False

    if action == "add":
        values = _normalize_tasks(tasks)
        parent_item = _resolve(board, parent, "parent") if parent is not None else None
        parent_phase = _task_index(board)[parent_item["id"]][0] if parent_item else None
        phase_name = _clean(phase, "phase", required=parent_item is None)
        if parent_phase is not None:
            if phase_name is not None and phase_name.casefold() != parent_phase["name"].casefold():
                raise ValueError("A child must be added to its parent's phase")
            target = parent_phase
        else:
            assert phase_name is not None
            target = _phase(board, phase_name)
            if target is None:
                target = {"name": phase_name, "tasks": []}
                board["phases"].append(target)
        target["tasks"].extend(_new_task(board, text, parent_item["id"] if parent_item else None) for text in values)
        _record(board, "add", note=clean_note)

    elif action == "move":
        item = _resolve(board, task)
        phase_name = _clean(phase, "phase", required=True)
        assert phase_name is not None
        new_parent = _resolve(board, parent, "parent") if parent is not None else None
        subtree = _subtree_ids(board, item["id"])
        if new_parent is not None and new_parent["id"] in subtree:
            raise ValueError("A task cannot be moved under itself or one of its descendants")
        target = _phase(board, phase_name)
        if new_parent is not None:
            parent_phase = _task_index(board)[new_parent["id"]][0]
            if parent_phase["name"].casefold() != phase_name.casefold():
                raise ValueError("Destination phase must match the new parent's phase")
            target = parent_phase
        elif target is None:
            target = {"name": phase_name, "tasks": []}
        assert target is not None
        moved = [candidate for _, candidate in _all_tasks(board) if candidate["id"] in subtree]
        for phase_value in board["phases"]:
            phase_value["tasks"] = [candidate for candidate in phase_value["tasks"] if candidate["id"] not in subtree]
        if target not in board["phases"]:
            board["phases"].append(target)
        item["parent_id"] = new_parent["id"] if new_parent else None
        target["tasks"].extend(moved)
        now = _now()
        for candidate in moved:
            candidate["updated_at"] = now
        reconcile_owner(item)
        _record(board, "move", item, previous=item["status"], note=clean_note)

    elif action == "close":
        if _is_open(board):
            counts = _counts(board)
            raise ValueError(
                "Cannot close a Liturgy with open work: "
                f"{counts['pending']} pending, {counts['in_progress']} running, {counts['blocked']} blocked. "
                "Finish or explicitly retire each item first."
            )
        archived = json.loads(json.dumps(board))
        archived["closed_at"] = _now()
        if clean_note:
            archived["close_note"] = clean_note
        state["history"].append(archived)
        state["active"] = None
        await _save(state)
        return "Liturgy closed.\n\n" + _render_history(state)

    else:
        item = _resolve(board, task)
        previous = item["status"]

        if action == "start":
            if previous in _TERMINAL:
                raise ValueError(f"{item['id']} is {previous}; use action='reopen' first")
            if previous == "blocked":
                raise ValueError(f"{item['id']} is blocked; use action='unblock' first")
            item["status"] = "in_progress"
            reconcile_owner(item)
            if focus:
                board["focused_task_id"] = item["id"]

        elif action == "focus":
            if previous not in {"pending", "in_progress"}:
                raise ValueError(f"{item['id']} is {previous}; only runnable work can be focused")
            board["focused_task_id"] = item["id"]

        elif action == "block":
            clean_reason = _clean(reason, "reason", required=True)
            if previous in _TERMINAL:
                raise ValueError(f"{item['id']} is {previous}; use action='reopen' first")
            item["status"] = "blocked"
            item["blocker"] = clean_reason
            reconcile_owner(item)
            if board.get("focused_task_id") == item["id"]:
                board["focused_task_id"] = None

        elif action == "unblock":
            if previous != "blocked":
                raise ValueError(f"{item['id']} is {previous}, not blocked")
            item["status"] = "pending"
            item["blocker"] = None
            reconcile_owner(item)

        elif action == "done":
            if previous in _TERMINAL:
                raise ValueError(f"{item['id']} is already {previous}")
            if previous == "blocked":
                raise ValueError(f"{item['id']} is blocked; unblock it before completion")
            item["status"] = "completed"
            item["blocker"] = None
            reconcile_owner(item)
            if clean_note is not None:
                item["result"] = clean_note
            if clean_evidence is not None:
                item["evidence"] = clean_evidence
            if board.get("focused_task_id") == item["id"]:
                board["focused_task_id"] = None

        elif action == "retire":
            if previous in _TERMINAL:
                raise ValueError(f"{item['id']} is already {previous}")
            item["status"] = "retired"
            item["blocker"] = None
            reconcile_owner(item)
            if clean_note is not None:
                item["result"] = clean_note
            if clean_evidence is not None:
                item["evidence"] = clean_evidence
            if board.get("focused_task_id") == item["id"]:
                board["focused_task_id"] = None

        elif action == "reopen":
            if previous not in _TERMINAL:
                raise ValueError(f"{item['id']} is {previous}, not closed")
            item["status"] = "pending"
            item["blocker"] = None
            item["result"] = None
            item["evidence"] = []
            item["owner"] = clean_owner

        item["updated_at"] = _now()
        _record(board, action, item, previous=previous, note=clean_note)

    await _save(state)
    return _render(board, state["revision"])
