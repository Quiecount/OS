#!/usr/bin/env python3
"""Reproducible quality evidence; full profile includes long-running trials.

Reference probes run only in accuracy cases, never in throughput cases.
Failures are saved as failures; unrun phases are never called passes.
"""
import argparse
import bisect
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import statistics
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--profile", choices=("smoke", "regression", "full"), default="smoke")
parser.add_argument("--phases", default="count,accuracy,diagnosis,performance,soak")
parser.add_argument("--alerts", default="SYSCALL_HOTSPOT,SYSCALL_SLOW,CPU_HOG,SCHED_DELAY")
parser.add_argument("--cached-exit", action="store_true", help="Test the opt-in syscall fast exit identity")
parser.add_argument("--require-accuracy", action="store_true", help="Fail exit status on generated accuracy checks exceeding their targets")
args = parser.parse_args()
ALERTS = args.alerts.split(",")
if not ALERTS or len(ALERTS) != len(set(ALERTS)) or any(x not in
        ("SYSCALL_HOTSPOT", "SYSCALL_SLOW", "CPU_HOG", "SCHED_DELAY") for x in ALERTS):
    parser.error("--alerts requires unique supported alert names")
FULL = args.profile == "full"
REGRESSION = args.profile == "regression"
OUT = ROOT / "output/quality" / (dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + args.profile)
REPORT = {"profile": args.profile, "kernel": os.uname().release,
          "logical_cpus": os.cpu_count(),
          "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
          "targets_are_project_proposals": True, "alerts": ALERTS, "cached_exit": args.cached_exit,
          "cases": [], "phases": {}, "sha256": {}}


def save():
    temp = OUT / "report.tmp"
    temp.write_text(json.dumps(REPORT, indent=2, ensure_ascii=False) + "\n")
    temp.replace(OUT / "report.json")


def resource(pid):
    status = Path(f"/proc/{pid}/status").read_text()
    rss = int(next(x for x in status.splitlines() if x.startswith("VmRSS:")).split()[1])
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    return rss, int(fields[11]) + int(fields[12])


def wait_ready(process, path, text):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{path.name}: exited {process.returncode}: {path.read_text()[-2000:]}")
        if text in path.read_text():
            return
        time.sleep(0.05)
    raise RuntimeError(f"{path.name}: readiness timeout")


def run_case(label, mode, seconds, threads=1, rate=0, duty=100,
             scenes=("syscall",), reference=False, extra=None, top=4096):
    folder = OUT / label
    folder.mkdir()
    processes, streams, monitors, observations = [], [], {}, {}
    done = threading.Event()
    watcher = None
    result = {"label": label, "mode": mode, "seconds": seconds, "threads": threads, "rate": rate, "duty": duty, "top": top}
    try:
        workload = subprocess.Popen([str(ROOT / "build/quality-workload"), mode, str(seconds),
                                     str(threads), str(rate), str(duty)], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(workload)
        identity = json.loads(workload.stdout.readline())
        pid = identity["pid"]
        for scene in scenes:
            binary = "syscall_hotspot" if scene == "syscall" else "cpu_hog"
            log_path = folder / f"{scene}.log"
            log = log_path.open("w"); streams.append(log)
            command = [str(ROOT / "build" / binary), "-t", str(top), "-o", str(folder / f"{scene}.jsonl")]
            if scene == "syscall" and args.cached_exit:
                command += ["--cached-exit"]
            if scene == "syscall" and reference:
                command += ["--histogram"]
            if extra:
                command += extra.get(scene, [])
            monitor = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log)
            processes.append(monitor); monitors[scene] = monitor
            wait_ready(monitor, log_path, "已启动")
            observations[scene] = [resource(monitor.pid)]
            maps = {}
            for fdinfo in Path(f"/proc/{monitor.pid}/fdinfo").iterdir():
                try:
                    fields = dict(line.split(":", 1) for line in fdinfo.read_text().splitlines() if ":" in line)
                    if "map_id" in fields:
                        maps[fields["map_id"].strip()] = {k:v.strip() for k,v in fields.items() if k.startswith("map_") or k in ("memlock","key_size","value_size","max_entries")}
                except OSError:
                    pass
            result.setdefault("bpf_maps", {})[scene] = maps
        ref = None
        if reference:
            log_path = folder / "reference.log"
            log = log_path.open("w"); streams.append(log)
            raw = (folder / "reference.txt").open("w"); streams.append(raw)
            ref = subprocess.Popen([str(ROOT / "build/quality-reference"), str(pid),
                                    str(identity[mode] if mode in identity else identity["getpid"]),
                                    str(math.ceil(seconds) + 30)], stdout=raw, stderr=log)
            processes.append(ref); wait_ready(ref, log_path, "READY")

        def watch():
            while not done.wait(0.5):
                for scene, monitor in monitors.items():
                    try:
                        observations[scene].append(resource(monitor.pid))
                    except (OSError, StopIteration):
                        pass
        watcher = threading.Thread(target=watch, daemon=True); watcher.start()
        began = time.monotonic()
        stdout, stderr = workload.communicate("x", timeout=seconds + 30)
        if workload.returncode:
            raise RuntimeError(f"workload failed {workload.returncode}: {stderr}")
        ground = json.loads(stdout)
        (folder / "workload.json").write_text(json.dumps({"identity": identity, "result": ground}) + "\n")
        time.sleep(0.05)
        for scene, monitor in monitors.items():
            observations[scene].append(resource(monitor.pid))
        elapsed = time.monotonic() - began
        for process in ([ref] if ref else []) + list(monitors.values()):
            process.send_signal(signal.SIGINT)
            if process.wait(timeout=10) != 0:
                raise RuntimeError("monitor/reference exited unsuccessfully; inspect logs")
        done.set(); watcher.join()
        for stream in streams: stream.flush()
        rows = {scene: [json.loads(line) for line in (folder / f"{scene}.jsonl").read_text().splitlines()]
                for scene in scenes}
        selected = {scene: [r for r in data if r.get("pid") == pid] for scene, data in rows.items()}
        # Regression for fragmented drain rows: one metric per object/window.
        for scene, data in selected.items():
            keys = [(r["event"], r.get("id"), r["window"]["start"], r["window"]["end"])
                    for r in data if r["event"] in ("cpu_metric", "syscall_metric")]
            if len(keys) != len(set(keys)):
                raise RuntimeError(f"duplicate {scene} metric for the same object/window")
        result.update(pid=pid, actual_duration_s=(ground["end_ns"] - ground["start_ns"]) / 1e9,
                      calls=ground["calls"], resources={})
        for scene, values in observations.items():
            result["resources"][scene] = {
                "rss_mib_max": max(x[0] for x in values) / 1024,
                "cpu_percent_one_core": 100 * (values[-1][1] - values[0][1]) / os.sysconf("SC_CLK_TCK") / elapsed}
        result["diagnoses"] = []
        for scene, data in selected.items():
            for row in data:
                if row.get("event") == "diagnosis":
                    result["diagnoses"].append({"type": row["type"], "after_start_s": (row["ts_ns"] - ground["start_ns"]) / 1e9})
        if mode in ("getpid", "stat", "open") and "syscall" in selected and top == 4096:
            ids = [identity[mode]] + ([identity["close"]] if mode == "open" else [])
            result["count_checks"] = []
            for syscall_id in ids:
                measured = sum(r["calls"] for r in selected["syscall"] if r.get("event") == "syscall_metric" and r["id"] == syscall_id)
                error = 100 * abs(measured - ground["calls"]) / max(1, ground["calls"])
                result["count_checks"].append({"id": syscall_id, "expected": ground["calls"], "measured": measured, "error_percent": error, "target_met": error <= 0.1})
        if reference:
            ref_samples = {0: [], 1: [], 2: []}
            for line in (folder / "reference.txt").read_text().splitlines():
                kind, ns = map(int, line.split()); ref_samples[kind].append(ns)
            result["reference_samples"] = {k: len(v) for k, v in ref_samples.items()}
            if "syscall" in selected:
                measured = [r for r in selected["syscall"] if r.get("event") == "syscall_metric" and r["id"] == identity.get(mode)]
                total = sum(r["calls"] for r in measured)
                if not total or not ref_samples[0]: raise RuntimeError("missing latency reference samples")
                mean = sum(r["mean_us"] * r["calls"] for r in measured) / total
                ref_mean = statistics.mean(ref_samples[0]) / 1000
                buckets = [sum(r["latency_buckets"][i] for r in measured) for i in range(384)]
                ref_p99 = sorted(ref_samples[0])[math.ceil(len(ref_samples[0]) * .99) - 1] / 1000
                p99 = histogram_p99(buckets) / 1000
                result["syscall_latency"] = {"mean_us": mean, "reference_mean_us": ref_mean, "mean_target_met": abs(mean-ref_mean) <= max(1, .1*ref_mean),
                    "p99_upper_us": p99, "reference_p99_us": ref_p99, "p99_target_met": abs(p99-ref_p99) <= max(1, .2*ref_p99),
                    "sample_count_difference": total-len(ref_samples[0])}
            if "cpu" in selected:
                measured = [r for r in selected["cpu"] if r.get("event") == "cpu_metric"]
                actual = sum(r["offcpu_completed_ms"] for r in measured)
                expected = sum(ref_samples[2]) / 1e6
                result["offcpu"] = {"measured_ms": actual, "reference_ms": expected,
                    "error_percent": 100*abs(actual-expected)/max(.001, expected), "target_met": abs(actual-expected) <= .05*expected}
                if ref_samples[1]:
                    buckets = [sum(r["runq_buckets"][i] for r in measured) for i in range(384)]
                    actual = histogram_p99(buckets)/1000
                    expected = sorted(ref_samples[1])[math.ceil(len(ref_samples[1])*.99)-1]/1000
                    result["runqlat"] = {"p99_upper_us": actual, "reference_p99_us": expected,
                                          "production_samples":sum(buckets), "reference_samples":len(ref_samples[1]),
                                          "target_met": abs(actual-expected) <= max(5, .2*expected)}
        if mode == "cpu" and "cpu" in selected:
            points = ground["cpu_samples"]
            metrics = [r for r in selected["cpu"] if r.get("event") == "cpu_metric"]
            # CPU rates cover /proc read-to-read intervals, NOT JSON output times.
            # Match each exact interval to independently sampled process CPU time.
            valid = [r for r in metrics if points and r.get("cpu_sample_valid") and
                     points[0][0]+.2e9 <= r["cpu_sample_start_ns"] < r["cpu_sample_end_ns"] <= points[-1][0]]
            duration_ns = sum(r["cpu_sample_end_ns"]-r["cpu_sample_start_ns"] for r in valid)
            if duration_ns >= 5e9:
                reference_cpu = 100*sum(interpolate(points, r["cpu_sample_end_ns"])-
                    interpolate(points, r["cpu_sample_start_ns"]) for r in valid)/duration_ns
                measured_cpu = sum(r["cpu_percent_one_core"]*(r["cpu_sample_end_ns"]-
                    r["cpu_sample_start_ns"]) for r in valid)/duration_ns
                result["cpu_accuracy"] = {"reference_percent": reference_cpu, "measured_percent": measured_cpu,
                    "error_percentage_points": abs(measured_cpu-reference_cpu), "target_met": abs(measured_cpu-reference_cpu) <= 2,
                    "aligned_duration_s": duration_ns/1e9,
                    "max_read_span_ms": max(r["cpu_read_span_ns"] for r in valid)/1e6}
            elif seconds >= 9:
                raise RuntimeError("CPU accuracy test has less than 5 seconds of valid aligned samples")
        result["execution"] = "passed"
    except Exception as exc:
        result["execution"] = "failed"; result["error"] = str(exc)
    finally:
        done.set()
        if watcher: watcher.join(timeout=2)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
        for stream in streams: stream.close()
    REPORT["cases"].append(result); save()
    print(json.dumps({"case": label, "execution": result["execution"], "error": result.get("error")}), flush=True)
    return result


def histogram_p99(buckets):
    if sum(buckets) <= 0: raise RuntimeError("empty histogram")
    target = math.ceil(sum(buckets)*.99)
    seen = 0
    for i, count in enumerate(buckets):
        seen += count
        if seen >= target:
            if i == 383: raise RuntimeError("histogram overflow")
            return i if i < 8 else ((9+i%8) << (i//8-1))-1
    raise RuntimeError("empty histogram")


def interpolate(points, x):
    i = bisect.bisect_left([p[0] for p in points], x)
    if i == 0: return points[0][1]
    a,b = points[i-1], points[min(i,len(points)-1)]
    return a[1]+(b[1]-a[1])*(x-a[0])/(b[0]-a[0])


def wilson(hits, n):
    if not n: return None
    z=1.959964; p=hits/n; denom=1+z*z/n
    mid=(p+z*z/(2*n))/denom
    half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/denom
    return [mid-half, mid+half]


def diagnosis_trials():
    results = {}
    for alert in ALERTS:
        stats = {"positive": 0, "detected": 0, "timely": 0, "negative": 0, "false_positives": 0, "execution_errors": 0}
        for positive, trials in ((True, 100 if FULL else (10 if REGRESSION else 1)),
                                 (False, 200 if FULL else (20 if REGRESSION else 1))):
            for i in range(trials):
                if alert == "SYSCALL_HOTSPOT":
                    options = dict(mode=("getpid", "stat", "open")[i%3], seconds=3 if positive else 2, rate=50000 if positive else 1000)
                    deadline = 2
                elif alert == "SYSCALL_SLOW":
                    options = dict(mode="read" if positive else ("getpid" if i%2 else "sleep"), seconds=3, rate=1000)
                    deadline = 2
                elif alert == "CPU_HOG":
                    options = dict(mode="cpu", seconds=13 if positive else (5 if i%2 else 9), duty=100 if positive or i%2 else 50, scenes=("cpu",))
                    deadline = 12
                else:
                    options = dict(mode="cpu", seconds=5 if positive else 3, threads=8 if positive else 1,
                                   duty=100 if positive else 20, scenes=("cpu",), extra={"cpu":["--baseline-p99-us","1000"]})
                    deadline = 2
                label = f"diagnosis-{alert}-{'positive' if positive else 'negative'}-{i:03}"
                case = run_case(label, top=10, **options)
                stats["positive" if positive else "negative"] += 1
                if case["execution"] != "passed": stats["execution_errors"] += 1
                detections = [d["after_start_s"] for d in case.get("diagnoses",[]) if d["type"] == alert]
                if positive:
                    stats["detected"] += bool(detections)
                    stats["timely"] += bool(detections and min(detections) <= deadline)
                else: stats["false_positives"] += bool(detections)
                results[alert] = dict(stats)
                REPORT["diagnosis_progress"] = results; save()
        stats["recall"] = stats["detected"]/stats["positive"]
        stats["false_positive_rate"] = stats["false_positives"]/stats["negative"]
        stats["recall_wilson_95"] = wilson(stats["detected"], stats["positive"])
        stats["false_positive_wilson_95"] = wilson(stats["false_positives"], stats["negative"])
        stats["sufficient_sample_size"] = FULL
        stats["quality_target_met"] = FULL and not stats["execution_errors"] and stats["recall"] >= .98 and stats["false_positive_rate"] <= .01
        stats["timeliness_target_met"] = FULL and stats["timely"] == stats["positive"]
        results[alert] = stats
    return results


def performance():
    import importlib.util
    spec=importlib.util.spec_from_file_location("bench", ROOT/"tests/bench-two-scenarios.py")
    bench=importlib.util.module_from_spec(spec); spec.loader.exec_module(bench)
    bench.OUT=OUT/"performance"; bench.OUT.mkdir()
    results={}
    for scene in ("syscall", "cpu"):
        runs={"off":[],"on":[]}
        for trial in range(10 if FULL else (6 if REGRESSION else 2)):
            for active in ([False,True] if trial%2==0 else [True,False]):
                monitor_args = ["--cached-exit"] if scene == "syscall" and args.cached_exit else []
                runs["on" if active else "off"].append(bench.run_case(scene, active, trial,
                    seconds=30 if FULL else (10 if REGRESSION else 3), monitor_args=monitor_args))
            REPORT["performance_progress"]={"scene":scene,"completed_pairs":trial+1}; save()
        med={k:statistics.median(r["throughput_per_s"] for r in v) for k,v in runs.items()}
        loss=100*(1-med["on"]/med["off"])
        base=[r["throughput_per_s"] for r in runs["off"]]
        cv=statistics.stdev(base)/statistics.mean(base) if len(base)>1 else 0
        results[scene]={"runs":runs,"median":med,"throughput_loss_percent":loss,
                        "baseline_cv":cv,"environment_stable":cv<=.05,
                        "sufficient_sample_size":FULL,
                        "target_met":FULL and cv<=.05 and loss <= (5 if scene=="syscall" else 2)}
    return results


def main():
    if os.geteuid()!=0: raise SystemExit("Run with sudo/root")
    OUT.mkdir(parents=True)
    (ROOT/"output/quality/latest.txt").write_text(str(OUT)+"\n")
    for file in sorted([*(ROOT/"src").rglob("*"), *(ROOT/"tests").glob("*"), ROOT/"Makefile"]):
        if file.is_file() and file.name != "vmlinux.h" and file.suffix not in (".pyc",):
            REPORT["sha256"][str(file.relative_to(ROOT))]=hashlib.sha256(file.read_bytes()).hexdigest()
    save()
    subprocess.run(["make","quality-tools"],cwd=ROOT,check=True)
    REPORT["binary_sha256"] = {name: hashlib.sha256((ROOT/"build"/name).read_bytes()).hexdigest()
                               for name in ("syscall_hotspot", "cpu_hog", "quality-reference", "quality-workload")}
    save()
    for phase in args.phases.split(","):
        began=time.monotonic()
        REPORT["active_phase"]=phase; save(); print(f"PHASE {phase}",flush=True)
        try:
            if phase=="count":
                results=[]
                for mode in ("getpid","stat","open"):
                    for threads in (1,4,8):
                        for rate in ((10000,100000,200000) if FULL or REGRESSION else (10000,)):
                            results.append(run_case(f"count-{mode}-{threads}-{rate}",mode,5 if FULL else 2,threads,rate))
            elif phase=="accuracy":
                results=[]
                for mode in ("getpid","stat","read","sleep"):
                    results.append(run_case(f"latency-{mode}",mode,30 if FULL else (10 if REGRESSION else 4),rate=10000,reference=True,scenes=("syscall","cpu")))
                for duty in ((20,50,75,85,100) if FULL or REGRESSION else (20,100)):
                    results.append(run_case(f"cpu-accuracy-{duty}","cpu",10,duty=duty,scenes=("cpu",)))
                if REGRESSION:
                    for threads in (4,8):
                        results.append(run_case(f"cpu-accuracy-multithread-{threads}","cpu",12,threads=threads,scenes=("cpu",)))
                    for threads in (1,4,8):
                        results.append(run_case(f"shared-count-{threads}","getpid",3,threads=threads,rate=100000,
                                                extra={"syscall":["--shared-stats"]}))
            elif phase=="diagnosis": results=diagnosis_trials()
            elif phase=="performance": results=performance()
            elif phase=="soak":
                results=[]
                for mode in ("getpid","stat","open"):
                    results.append(run_case(f"soak-{mode}",mode,600 if FULL else 3,threads=4,rate=100000,scenes=("syscall","cpu")))
            else: raise ValueError(f"Unknown phase {phase}")
            REPORT["phases"][phase]={"execution":"completed","elapsed_s":time.monotonic()-began,"results":results}
        except Exception as exc:
            REPORT["phases"][phase]={"execution":"failed","error":str(exc)}
        save()
    REPORT["active_phase"]=None
    REPORT["finished_at"]=dt.datetime.now(dt.timezone.utc).isoformat(); save()
    print(f"QUALITY_REPORT={OUT/'report.json'}",flush=True)
    failed=any(c["execution"]!="passed" for c in REPORT["cases"]) or any(p["execution"]=="failed" for p in REPORT["phases"].values())
    if args.require_accuracy:
        for case in REPORT["cases"]:
            checks = case.get("count_checks", []) + [case[k] for k in
                ("syscall_latency", "cpu_accuracy", "offcpu", "runqlat") if k in case]
            failed |= any(v is False for check in checks for k,v in check.items() if k.endswith("target_met"))
    return int(failed)


if __name__=="__main__":
    raise SystemExit(main())
