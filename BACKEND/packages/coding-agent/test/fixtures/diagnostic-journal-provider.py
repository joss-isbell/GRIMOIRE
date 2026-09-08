#!/usr/bin/python3
"""Test-only journalctl protocol fixture; no real journal or daemon access."""
import json
import os
import sys
import time

with open(os.path.join(os.path.dirname(sys.argv[0]), "provider.json"), encoding="utf-8") as source:
    config = json.load(source)
if config.get("unavailable"):
    print("provider fixture unavailable", file=sys.stderr)
    sys.exit(1)
entries = config.get("entries", [])
if "--output=export" in sys.argv and config.get("exportPause"):
    with open(os.path.join(os.path.dirname(sys.argv[0]), "export-started"), "w", encoding="utf-8") as marker:
        marker.write(str(os.getpid()))
    while True:
        time.sleep(1)
cursor = next((arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--cursor=")), None)
after = next((arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--after-cursor=")), None)
if cursor:
    entries = [line for line in entries if json.loads(line)["__CURSOR"] == cursor][:1]
elif after:
    indexes = [index for index, line in enumerate(entries) if json.loads(line)["__CURSOR"] == after]
    entries = entries[indexes[0] + 1:] if indexes else entries
for line in entries:
    if "--output=export" in sys.argv:
        print("MESSAGE=" + json.loads(line)["MESSAGE"] + "\n", flush=True)
    else:
        print(line, flush=True)
if "--follow" in sys.argv:
    seen = {json.loads(line)["__CURSOR"] for line in config.get("entries", [])}
    while True:
        time.sleep(0.05)
        with open(os.path.join(os.path.dirname(sys.argv[0]), "provider.json"), encoding="utf-8") as source:
            latest = json.load(source)
        for line in latest.get("entries", []):
            current = json.loads(line)["__CURSOR"]
            if current not in seen:
                print(line, flush=True)
                seen.add(current)
