#!/usr/bin/env python3
"""Run independent checks and save failures without reusing stale results."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
out = root / "output/optimization-validation"
if os.geteuid() != 0:
    raise SystemExit("Run with sudo/root")
out.mkdir(parents=True, exist_ok=True)
report = {"started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "sha256": {}, "checks": {}}
for name in ("src/probes/syscall_hotspot.bpf.c", "src/loader/cpu_hog.c", "src/common/proc_cpu.h"):
    report["sha256"][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
checks = {"diagnosis": ["bash", "tests/stage2-two-scenarios.sh"],
          "syscall": [sys.executable, "tests/compare-syscall-performance.py"],
          "cpu": [sys.executable, "tests/bench-two-scenarios.py"]}
for name, command in checks.items():
    print(f"Running {name}...", flush=True)
    env = dict(os.environ)
    env["SCENARIOS"] = "cpu" if name == "cpu" else "syscall"
    with (out / f"{name}.log").open("w") as log:
        result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    report["checks"][name] = result.returncode
    (out / "status.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{name}: {'PASS' if result.returncode == 0 else 'FAIL'}", flush=True)
    if result.returncode:
        print((out / f"{name}.log").read_text()[-3000:], flush=True)
print(f"Results: {out}", flush=True)
raise SystemExit(any(report["checks"].values()))
