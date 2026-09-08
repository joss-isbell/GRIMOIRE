#!/usr/bin/python3
"""Stock-atop command seam for isolated recorder lifecycle tests."""
import json
import os
import signal
import sys
import time

args = sys.argv[1:]
with open(args[args.index("-r") + 1], encoding="utf-8") as source:
    config = json.load(source)
if config.get("ignoreTerm"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if config.get("pidFile"):
    with open(config["pidFile"], "w", encoding="utf-8") as marker:
        json.dump({"pid": os.getpid(), "group": os.getpgrp()}, marker)
with open(args[args.index("-w") + 1], "wb", buffering=0) as output:
    output.write(b"native-header\n")
    while config.get("holdFile") and not os.path.exists(config["holdFile"]):
        time.sleep(0.05)
    output.write(b"native-sample\n")
print(json.dumps({"timestamp": config["timestamp"], "elapsed": 1, "CPU": {}}), flush=True)
if config.get("truncated"):
    print("raw file is incomplete!", file=sys.stderr, flush=True)
    sys.exit(9)
