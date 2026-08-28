import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liturgy


class LiturgyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_liturgy_dir = os.environ.get("LITURGY_STATE_DIR")
        os.environ["LITURGY_STATE_DIR"] = self.temp.name
        self.path = Path(self.temp.name) / "liturgy.json"

    def tearDown(self):
        if self.old_liturgy_dir is None:
            os.environ.pop("LITURGY_STATE_DIR", None)
        else:
            os.environ["LITURGY_STATE_DIR"] = self.old_liturgy_dir
        self.temp.cleanup()

    def call(self, action="view", **kwargs):
        return asyncio.run(liturgy.run(action, **kwargs))

    def state(self):
        return json.loads(self.path.read_text())

    def init_board(self):
        return self.call(
            "init",
            title="Deliver outcome",
            plan={
                "Discovery": ["Inspect current behavior", "Inspect current behavior"],
                "Verification": ["Run acceptance checks"],
            },
        )

    def find_task(self, task_id):
        def walk(tasks):
            for item in tasks:
                if item["id"] == task_id:
                    return item
                found = walk(item.get("tasks", []))
                if found is not None:
                    return found
            return None

        for phase in self.state()["active"]["phases"]:
            found = walk(phase["tasks"])
            if found is not None:
                return found
        self.fail(f"Task {task_id} was not found")

    def test_init_persists_stable_ids_and_duplicate_text(self):
        output = self.init_board()
        self.assertIn("T001 Inspect current behavior", output)
        self.assertIn("T002 Inspect current behavior", output)
        self.assertIn("revision 1", output)
        state = self.state()
        self.assertEqual(state["revision"], 1)
        self.assertEqual(state["active"]["phases"][0]["tasks"][0]["status"], "pending")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.call("start", task="Inspect current behavior")
        self.assertEqual(self.state()["revision"], 1)

    def test_discovered_root_and_subtask_are_added_promptly_and_render_nested(self):
        self.init_board()
        output = self.call("add", phase="Discovery", tasks=["Trace discovered boundary"])
        self.assertIn("T004 Trace discovered boundary", output)
        output = self.call(
            "add",
            phase="Discovery",
            parent="T004",
            tasks=["Cover discovered edge case"],
        )
        self.assertIn("- [ ] T004 Trace discovered boundary", output)
        self.assertIn("  - [ ] T005 Cover discovered edge case", output)
        task = self.find_task("T005")
        self.assertEqual(task["text"], "Cover discovered edge case")
        self.assertEqual(task["status"], "pending")

    def test_move_demotes_reparents_and_promotes_without_changing_identity_or_metadata(self):
        self.init_board()
        self.call("start", task="T002", owner="reviewer:sub-123")
        self.call("block", task="T002", reason="Awaiting a decision")
        before = self.find_task("T002")
        preserved = {
            key: before[key]
            for key in ("id", "text", "status", "owner", "blocker", "result", "evidence", "created_at")
        }

        self.call("move", task="T002", phase="Discovery", parent="T001")
        self.assertEqual(
            {key: self.find_task("T002")[key] for key in preserved},
            preserved,
        )

        self.call("move", task="T002", phase="Verification", parent="T003")
        self.assertEqual(
            {key: self.find_task("T002")[key] for key in preserved},
            preserved,
        )

        output = self.call("move", task="T002", phase="Discovery")
        self.assertIn("- [!] T002 Inspect current behavior", output)
        self.assertNotIn("  - [!] T002 Inspect current behavior", output)
        self.assertEqual(
            {key: self.find_task("T002")[key] for key in preserved},
            preserved,
        )

    def test_invalid_self_cycle_and_phase_placement_leave_state_unchanged(self):
        self.init_board()
        for kwargs, message in (
            ({"task": "T001", "phase": "Discovery", "parent": "T001"}, "itself|self"),
            ({"task": "T001", "phase": "Verification", "parent": "T002"}, "phase|parent"),
        ):
            before = self.path.read_bytes()
            with self.assertRaisesRegex(ValueError, message):
                self.call("move", **kwargs)
            self.assertEqual(self.path.read_bytes(), before)

        self.call("move", task="T002", phase="Discovery", parent="T001")
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "cycle|descendant"):
            self.call("move", task="T001", phase="Discovery", parent="T002")
        self.assertEqual(self.path.read_bytes(), before)

        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "phase|parent"):
            self.call("add", phase="Verification", parent="T001", tasks=["Invalid placement"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_retired_stale_work_remains_visible_and_allows_close(self):
        self.init_board()
        output = self.call(
            "retire",
            task="T001",
            note="Discovery made this stale",
            evidence=["decision:replacement-selected"],
        )
        self.assertIn("T001 Inspect current behavior", output)
        self.assertIn("result: Discovery made this stale", output)
        self.assertIn("evidence: decision:replacement-selected", output)
        self.assertEqual(self.find_task("T001")["status"], "retired")

        self.call("done", task="T002", note="Inspected")
        self.call("done", task="T003", note="Checks passed")
        closed = self.call("close", note="Reconciled materially changed work")
        self.assertIn("Liturgy closed", closed)
        archived = self.state()["history"][0]
        self.assertEqual(archived["phases"][0]["tasks"][0]["status"], "retired")

    def test_reopen_clears_stale_terminal_metadata_and_owner(self):
        self.init_board()
        for task_id, terminal_action in (("T001", "done"), ("T002", "retire")):
            with self.subTest(terminal_action=terminal_action):
                self.call("start", task=task_id, owner="reviewer:sub-123")
                self.call(
                    terminal_action,
                    task=task_id,
                    note="Old result",
                    evidence=["old:test-output"],
                )
                self.call("reopen", task=task_id, note="Understanding changed")
                task = self.find_task(task_id)
                self.assertEqual(task["status"], "pending")
                self.assertIsNone(task["owner"])
                self.assertIsNone(task["blocker"])
                self.assertIsNone(task["result"])
                self.assertEqual(task["evidence"], [])

    def test_multiple_running_tasks_and_separate_focus(self):
        self.init_board()
        self.call("start", task="T001", focus=True)
        output = self.call("start", task="T002", owner="reviewer:sub-123")
        self.assertIn("2 running", output)
        self.assertIn("T001 Inspect current behavior — focus", output)
        self.assertIn("owner: reviewer:sub-123", output)
        self.assertEqual(self.find_task("T001")["status"], "in_progress")
        self.assertEqual(self.find_task("T002")["status"], "in_progress")
        self.assertEqual(self.state()["active"]["focused_task_id"], "T001")

    def test_active_owner_can_be_cleared_when_responsibility_returns_to_root(self):
        self.init_board()
        self.call("start", task="T001", owner="reviewer:sub-123")
        self.call("move", task="T001", phase="Delivery", clear_owner=True)
        task = self.find_task("T001")
        self.assertEqual(task["status"], "in_progress")
        self.assertIsNone(task["owner"])
        with self.assertRaisesRegex(ValueError, "cannot be used together"):
            self.call("start", task="T001", owner="root", clear_owner=True)

    def test_done_records_result_and_evidence(self):
        self.init_board()
        self.call("start", task="T001", focus=True)
        output = self.call(
            "done",
            task="T001",
            note="Behavior boundary confirmed",
            evidence=["src/state.ts:40-91", "pytest: 12 passed"],
        )
        self.assertIn("result: Behavior boundary confirmed", output)
        self.assertIn("evidence: src/state.ts:40-91 | pytest: 12 passed", output)
        self.assertNotIn("Local focus: T001", output)

    def test_block_requires_reason_and_invalid_mutation_is_unchanged(self):
        self.init_board()
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "reason is required"):
            self.call("block", task="T001")
        self.assertEqual(self.path.read_bytes(), before)
        output = self.call("block", task="T001", reason="Awaiting user decision")
        self.assertIn("blocked: Awaiting user decision", output)
        with self.assertRaisesRegex(ValueError, "unblock"):
            self.call("done", task="T001")
        self.call("unblock", task="T001")
        self.assertEqual(self.find_task("T001")["status"], "pending")

    def test_stale_revision_and_close_gate_preserve_state(self):
        self.init_board()
        self.call("add", phase="Delivery", tasks=["Apply bounded change"], expected_revision=1)
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "Stale liturgy revision"):
            self.call("start", task="T001", expected_revision=1)
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaisesRegex(ValueError, "Cannot close"):
            self.call("close")
        for task_id in ("T001", "T002", "T003", "T004"):
            self.call("retire", task=task_id, note="Superseded in test")
        closed = self.call("close", note="Reconciled")
        self.assertIn("Liturgy closed", closed)
        self.assertIsNone(self.state()["active"])
        self.assertEqual(len(self.state()["history"]), 1)

    def test_unknown_schema_fails_closed_without_rewriting_file(self):
        self.path.write_text('{"schema_version": 99, "revision": 4, "active": null, "history": []}\n')
        before = self.path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "Unsupported liturgy schema"):
            self.call("view")
        self.assertEqual(self.path.read_bytes(), before)

    def test_atomic_replace_failure_keeps_last_valid_state(self):
        self.init_board()
        before = self.path.read_bytes()
        with mock.patch.object(liturgy.os, "replace", side_effect=OSError("simulated interruption")):
            with self.assertRaisesRegex(RuntimeError, "Cannot write"):
                self.call("start", task="T001")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(Path(self.temp.name).glob(".*.tmp")), [])

    def test_second_process_reads_same_thread_state(self):
        self.init_board()
        env = os.environ.copy()
        result = subprocess.run(
            [sys.executable, "-c", "import asyncio, liturgy; print(asyncio.run(liturgy.run('view')))"],
            env=env,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )
        self.assertIn("T001 Inspect current behavior", result.stdout)
        self.assertIn("revision 1", result.stdout)


if __name__ == "__main__":
    unittest.main()
