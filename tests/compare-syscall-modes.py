#!/usr/bin/env python3
"""Same-run full-capture syscall ablation, retaining all samples and source hashes."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TRIALS = 10
SECONDS = 15


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo/root")
    folder = ROOT / "output/syscall-modes" / dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    folder.mkdir(parents=True)
    (folder.parent / "latest.txt").write_text(str(folder) + "\n")
    subprocess.run(["make", "quality-tools"], cwd=ROOT, check=True)
    spec = importlib.util.spec_from_file_location("bench", ROOT / "tests/bench-two-scenarios.py")
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    bench.OUT = folder
    modes = {"off": [], "percpu": [], "shared": ["--shared-stats"],
             "cached_percpu": ["--cached-exit"],
             "cached_shared": ["--cached-exit", "--shared-stats"]}
    report = {"kernel": os.uname().release, "trials": TRIALS, "seconds": SECONDS,
              "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "arguments": modes, "runs": {k: [] for k in modes},
              "binary_sha256": hashlib.sha256((ROOT / "build/syscall_hotspot").read_bytes()).hexdigest()}

    def save():
        temp = folder / "result.tmp"
        temp.write_text(json.dumps(report, indent=2) + "\n")
        temp.replace(folder / "result.json")

    save()
    try:
        names = list(modes)
        for trial in range(TRIALS):
            # Every mode occupies every position twice; alternate reversal to
            # avoid consistently favoring a warmed machine or one direction.
            order = names[trial % len(names):] + names[:trial % len(names)]
            if trial >= len(names):
                order = list(reversed(order))
            for name in order:
                result = bench.run_case("syscall", name != "off", f"{trial}-{name}",
                                        seconds=SECONDS, monitor_args=modes[name])
                report["runs"][name].append(result)
                report["progress"] = {"trial": trial + 1, "mode": name}
                save()
                print(json.dumps(report["progress"]), flush=True)
        medians = {name: statistics.median(x["throughput_per_s"] for x in runs)
                   for name, runs in report["runs"].items()}
        baseline = [x["throughput_per_s"] for x in report["runs"]["off"]]
        report["baseline_cv"] = statistics.stdev(baseline) / statistics.mean(baseline)
        report["median_throughput_per_s"] = medians
        report["loss_percent"] = {name: 100 * (1 - value / medians["off"])
                                  for name, value in medians.items() if name != "off"}
        # Paired differences use the baseline of that rotation, avoiding claims
        # of improvement from separate-day before/after experiments.
        reference = report["runs"]["percpu"]
        report["paired_change_vs_percpu_percent"] = {
            name: [100 * (new["throughput_per_s"] / old["throughput_per_s"] - 1)
                   for old, new in zip(reference, runs)]
            for name, runs in report["runs"].items() if name not in ("off", "percpu")}
        report["formal_excellence_test"] = False  # Fifteen seconds, not the required thirty.
        report["execution"] = "completed"
    except Exception as exc:
        report["execution"] = "failed"
        report["error"] = str(exc)
        raise
    finally:
        report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        save()
        print(f"MODE_COMPARISON={folder / 'result.json'}", flush=True)


if __name__ == "__main__":
    main()
