#!/usr/bin/env python3
"""Root-only correctness and interleaved off/before/current comparison."""
import importlib.util
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "syscall-optimization"


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo/root")
    before = ROOT / "build/syscall_hotspot-before"
    if not before.is_file():
        raise SystemExit("Save the original build/syscall_hotspot as build/syscall_hotspot-before first")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "result.json").unlink(missing_ok=True)
    subprocess.run(["make", "-C", str(ROOT), "check"], check=True)
    workload = ROOT / "build/syscall-count-workload"
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                    str(ROOT / "tests/syscall-count-workload.c"), "-o", str(workload)], check=True)
    metrics = OUT / "accuracy.jsonl"
    metrics.unlink(missing_ok=True)
    with (OUT / "accuracy.log").open("w") as log:
        monitor = subprocess.Popen([str(ROOT / "build/syscall_hotspot"), "-d", "6",
                                    "-t", "4096", "-o", str(metrics)], stderr=log)
    expected = []
    try:
        time.sleep(0.7)
        if monitor.poll() is not None:
            raise RuntimeError("Probe failed to attach; see accuracy.log")
        for threads in (1, 4, 8):
            result = subprocess.run([str(workload), str(threads)], text=True,
                                    capture_output=True, check=True)
            expected.append(json.loads(result.stdout))
        monitor.wait(timeout=15)
        if monitor.returncode:
            raise RuntimeError("Probe exited unsuccessfully")
    finally:
        if monitor.poll() is None:
            monitor.terminate()
            monitor.wait(timeout=5)
    rows = [json.loads(line) for line in metrics.read_text().splitlines()]
    for item in expected:
        item["observed"] = sum(r["calls"] for r in rows if
            r.get("event") == "syscall_metric" and r["pid"] == item["pid"] and r["id"] == item["id"])
        item["error_percent"] = 100 * abs(item["observed"] - item["expected"]) / item["expected"]
    (OUT / "accuracy.json").write_text(json.dumps(expected, indent=2) + "\n")
    if any(item["error_percent"] > 0.5 for item in expected):
        raise RuntimeError("Syscall count error exceeds 0.5%; see accuracy.json")
    print("SYSCALL_COUNT_ACCURACY_OK", flush=True)

    spec = importlib.util.spec_from_file_location("bench", ROOT / "tests/bench-two-scenarios.py")
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    bench.OUT = OUT
    runs = {name: [] for name in ("off", "before", "current")}
    names = list(runs)
    for trial in range(6):
        # Rotate the order to balance warm-up and host load drift.
        for name in names[trial % 3:] + names[:trial % 3]:
            binary = before if name == "before" else ROOT / "build/syscall_hotspot"
            runs[name].append(bench.run_case("syscall", name != "off", f"{trial}-{name}", binary))
            print(f"trial={trial + 1} variant={name} rate={runs[name][-1]['throughput_per_s']}", flush=True)
    medians = {name: statistics.median(r["throughput_per_s"] for r in values)
               for name, values in runs.items()}
    report = {"kernel": os.uname().release, "trials": 6, "accuracy": expected,
              "runs": runs, "median_per_s": medians,
              "throughput_loss_percent": {name: round(100 * (1 - medians[name] / medians["off"]), 2)
                                           for name in ("before", "current")}}
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["throughput_loss_percent"]), flush=True)
    print("SYSCALL_COMPARISON_OK", flush=True)


if __name__ == "__main__":
    main()
