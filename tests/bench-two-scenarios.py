#!/usr/bin/env python3
"""Paired before/after benchmark; run as root on the target openEuler VM."""

import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "benchmark"
TRIALS = int(os.environ.get("TRIALS", "3"))
SCENARIOS = tuple(os.environ.get("SCENARIOS", "syscall,cpu").split(","))


def monitor_stats(pid):
    status = Path(f"/proc/{pid}/status").read_text()
    rss = int(re.search(r"^VmRSS:\s+(\d+)", status, re.M).group(1))
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    # /proc/PID/stat: utime + stime, including loader user and kernel CPU.
    jiffies = int(fields[11]) + int(fields[12])
    return rss, jiffies


def run_case(kind, active, trial, monitor_binary=None, seconds=None):
    seconds = seconds if seconds is not None else (3 if kind == "syscall" else 5)
    monitor = None
    path = OUT / f"{kind}-{trial}-{'on' if active else 'off'}.jsonl"
    if active:
        path.unlink(missing_ok=True)
        binary = "syscall_hotspot" if kind == "syscall" else "cpu_hog"
        with path.with_suffix(".log").open("w") as stream:
            monitor = subprocess.Popen(
                [str(monitor_binary or ROOT / "build" / binary), "--duration", str(seconds + 2),
                 "--output", str(path)], stderr=stream
            )
        time.sleep(0.7)
        if monitor.poll() is not None:
            raise RuntimeError(f"{binary} failed to start; see {path.with_suffix('.log')}")
        rss_kib, before_ticks = monitor_stats(monitor.pid)
    if kind == "syscall":
        command = [str(ROOT / "build" / "syscall_bomb"), str(seconds)]
    else:
        command = ["stress-ng", "--cpu", "1", "--timeout", f"{seconds}s",
                   "--metrics-brief"]
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        if kind == "syscall":
            rate = float(re.search(r"rate_per_s=(\d+)", result.stdout).group(1))
        else:
            line = next(line for line in result.stderr.splitlines()
                        if re.search(r"\bcpu\s+\d+\s+", line))
            rate = float(re.search(r"\bcpu\s+\d+\s+[\d.]+\s+[\d.]+\s+"
                                   r"[\d.]+\s+([\d.]+)", line).group(1))
        if monitor:
            rss_kib = max(rss_kib, monitor_stats(monitor.pid)[0])
            after_ticks = monitor_stats(monitor.pid)[1]
            cpu_percent = 100 * (after_ticks - before_ticks) / (
                seconds * os.sysconf("SC_CLK_TCK"))
        else:
            rss_kib = cpu_percent = None
        return {"throughput_per_s": rate, "monitor_rss_kib": rss_kib,
                "monitor_cpu_percent_one_core": cpu_percent}
    finally:
        if monitor:
            monitor.wait(timeout=seconds + 5)
            if monitor.returncode:
                raise RuntimeError(f"monitor exited {monitor.returncode}; see {path}")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo/root for eBPF attach")
    if TRIALS < 1 or TRIALS > 20:
        raise SystemExit("TRIALS must be in 1..20")
    if not SCENARIOS or len(set(SCENARIOS)) != len(SCENARIOS) or any(
            s not in ("syscall", "cpu") for s in SCENARIOS):
        raise SystemExit("SCENARIOS must be syscall, cpu, or syscall,cpu")
    OUT.mkdir(parents=True, exist_ok=True)
    subprocess.run(["make", "-C", str(ROOT), "check"], check=True)
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(ROOT / "faults/syscall_bomb.c"), "-o",
                    str(ROOT / "build/syscall_bomb")], check=True)
    report = {"kernel": os.uname().release, "trials": TRIALS, "scenarios": {}}
    for kind in SCENARIOS:
        runs = {"off": [], "on": []}
        for trial in range(TRIALS):
            for active in ([False, True] if trial % 2 == 0 else [True, False]):
                key = "on" if active else "off"
                runs[key].append(run_case(kind, active, trial))
        off = statistics.median(x["throughput_per_s"] for x in runs["off"])
        on = statistics.median(x["throughput_per_s"] for x in runs["on"])
        report["scenarios"][kind] = {
            "runs": runs, "baseline_median_per_s": off,
            "monitored_median_per_s": on,
            "throughput_loss_percent": round(100 * (off - on) / off, 2),
            "latency_increase_percent_from_throughput": round(
                100 * (off / on - 1), 2),
            "monitor_rss_mib_max": round(max(
                x["monitor_rss_kib"] for x in runs["on"]) / 1024, 2),
            "monitor_cpu_percent_one_core_median": round(
                statistics.median(x["monitor_cpu_percent_one_core"]
                                  for x in runs["on"]), 2),
        }
    label = "result" if SCENARIOS == ("syscall", "cpu") else "result-" + "-".join(SCENARIOS)
    destination = OUT / f"{label}.json"
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report["scenarios"], ensure_ascii=False, indent=2))
    print(f"BENCHMARK_RESULT={destination}")


if __name__ == "__main__":
    main()
