"""Assemble only pinned v0.9.3, existing main fixes, and reviewed repair deltas."""
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

MAIN = "4cc20de8c9cbd95a554c27ffc84f3f20fb9ba4e1"
V093 = "915c78f42c248b08238dd27fcd4bcab32c60beab"
V094 = "f771dfcedd684d1afff84ca2c6fa95c7a21efbc2"
REPAIRS = "3cf7964e27883eebb7e484fb8a33bcba266d2bc1"
MAIN_BASE = "d3c595fd251307e02f4ec4d7d4e5d26208f4b732"
REPAIR_BASE = "726db1e263d72b2a4a2d96dc9c8bb8e1ca8b079e"
SNAPSHOTS = os.environ.get("GRIMOIRE_SNAPSHOT_DIR")
repo = Path.cwd()
target = Path(sys.argv[1]).resolve()
backend = target / "BACKEND"
if target == repo:
    raise RuntimeError("Use a separate disposable worktree, never the source checkout")

def git(*args):
    return subprocess.check_output(["git", *args], cwd=repo)

def blob(ref, path):
    if SNAPSHOTS:
        folders = {MAIN: "main", V093: "upstream-v093", V094: "upstream-v094", REPAIRS: "previous-candidate"}
        file = Path(SNAPSHOTS) / folders[ref] / path
        return file.read_bytes() if file.is_file() else None
    result = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=repo, capture_output=True)
    return result.stdout if result.returncode == 0 else None

if not (target / ".git").exists() and not SNAPSHOTS:
    raise RuntimeError("Destination must be the workflow's disposable Git worktree")
if backend.exists():
    shutil.rmtree(backend)
if SNAPSHOTS:
    shutil.copytree(Path(SNAPSHOTS) / "upstream-v093", backend)
else:
    backend.mkdir()
    with tempfile.TemporaryFile() as archive:
        subprocess.run(["git", "archive", V093], stdout=archive, cwd=repo, check=True)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as contents:
            contents.extractall(backend, filter="data")

if SNAPSHOTS:
    selected = set()
    for name in ("main-local.patch", "previous-repairs.patch"):
        patch = (Path(SNAPSHOTS) / "exports" / name).read_text()
        selected.update(re.findall(r"^diff --git a/(\S+) b/", patch, re.M))
else:
    selected = set()
    for base, head in ((MAIN_BASE, MAIN), (REPAIR_BASE, REPAIRS)):
        selected.update(git("diff", "--name-only", base, head, "--", "BACKEND").decode().splitlines())
selected.discard("BACKEND/packages/coding-agent/CHANGELOG.md")
# This newer shell-completion feature does not exist at v0.9.3.
selected.discard("BACKEND/packages/coding-agent/test/suite/regressions/2068-shell-message-steering.test.ts")
conflicts = set()
with tempfile.TemporaryDirectory() as temporary:
    base_file = Path(temporary) / "base"
    repairs_file = Path(temporary) / "repairs"
    for name in sorted(selected):
        path = name.removeprefix("BACKEND/")
        output = target / name
        base, repairs = blob(V094, path), blob(REPAIRS, name)
        if repairs is None:
            raise RuntimeError(f"Missing selected repair file: {name}")
        output.parent.mkdir(parents=True, exist_ok=True)
        if base is None:
            output.write_bytes(repairs)
            continue
        if not output.exists():
            raise RuntimeError(f"Unexpected post-v0.9.3 path: {name}")
        base_file.write_bytes(base)
        repairs_file.write_bytes(repairs)
        result = subprocess.run(["git", "merge-file", "-p", "-L", "v093", "-L", "v094", "-L", "repairs", str(output), str(base_file), str(repairs_file)], capture_output=True)
        if result.returncode < 0 or result.returncode > 127:
            raise RuntimeError(result.stderr.decode())
        output.write_bytes(result.stdout)
        if result.returncode:
            conflicts.add(path)
expected = {"packages/coding-agent/docs/rlm.md", "packages/coding-agent/src/core/kernel/bootstrap.ts", "packages/coding-agent/test/kernel-bootstrap.test.ts"}
if conflicts != expected:
    raise RuntimeError(f"Unexpected conflicts: {conflicts}")
pattern = r"^<<<<<<<[^\n]*\n(.*?)^=======\n(.*?)^>>>>>>>[^\n]*\n"
package = backend / "packages/coding-agent"
file = package / "src/core/kernel/bootstrap.ts"
def resolve_bootstrap(match):
    ours, theirs = match.groups()
    if "RUNTIME_READY_CHECK" in ours:
        return ours + '// Check required imports together, avoiding a dozen cold interpreter launches.\nconst KERNEL_DEPENDENCIES_READY_CHECK = `# kernel dependencies\\nimport ${[STATE_SNAPSHOT_REQUIREMENT, ...DEFAULT_RLM_EXTRA_IMPORT_NAMES].join(", ")}`;\n'
    if "spawn(command" in ours:
        return ours.replace("env: process.env", "env: kernelPythonEnvironment()")
    raise RuntimeError("Unexpected bootstrap conflict")
text = re.sub(pattern, resolve_bootstrap, file.read_text(), flags=re.M | re.S)
file.write_text(text.replace("import { createHash }", "import { createHash, randomUUID }"))
file = package / "docs/rlm.md"
file.write_text(re.sub(pattern, lambda m: m[1], file.read_text(), flags=re.M | re.S))
file = package / "test/kernel-bootstrap.test.ts"
text = re.sub(pattern, lambda m: m[2], file.read_text(), flags=re.M | re.S)
file.write_text(re.sub(r'\n\tit\("resolves the venv python.*?\n\t}\);\n', "\n", text, flags=re.S))
file = package / "src/core/agent-session.ts"
text = file.read_text().replace('(message.customType === ASYNC_BASH_COMPLETION_CUSTOM_TYPE ||\n\t\t\t\tmessage.customType === RLM_CHILD_TERMINAL_NOTICE_CUSTOM_TYPE ||', '(message.customType === RLM_CHILD_TERMINAL_NOTICE_CUSTOM_TYPE ||')
file.write_text(text.replace('\n\t\t\tmessage.customType === ASYNC_BASH_COMPLETION_CUSTOM_TYPE ||', ''))
file = package / "test/suite/regressions/grimoire-automatic-notifications.test.ts"
text = file.read_text().replace('import type { HostRequestHandlers } from "../../../src/core/kernel/index.js";', 'import { createRlmChildTerminalNoticeMessage } from "../../../src/core/messages.js";')
a = text.index("\treturn (", text.index("function notify"))
b = text.index("\n}", a)
text = text[:a] + '\tharness.session.restorePendingNextTurnMessages([\n\t\tcreateRlmChildTerminalNoticeMessage({ kind: "completed_without_reply", childId: id, sessionName: "child" }),\n\t]);\n\treturn Promise.resolve();' + text[b:]
file.write_text(text.replace('"shell"', '"terminal"'))
file = package / ".changes/grimoire-selective-v094.md"
text = file.read_text().replace("shell-completion and subagent notifications", "subagent messages and terminal notifications")
file.unlink()
(package / ".changes/grimoire-selective-v093.md").write_text(text)
print(f"Assembled v0.9.3 with {len(selected)} selected repair/main paths")
