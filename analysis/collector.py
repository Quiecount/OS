#!/usr/bin/env python3
"""Collect JSONL metrics and diagnoses into the seven-field report schema.

Scene 1/2 loaders emit rule matches as diagnosis rows. Other scenes can add
the same rows as their rules become available. Raw events are counted without
fabricating diagnoses.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import sys

REQUIRED = ("type", "related_objects", "key_metrics", "suspected_root_cause",
            "evidence_chain", "recommendation")


def collect(lines):
    counts = Counter()
    by_pid = Counter()
    anomalies = []
    starts = []
    ends = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {number}: invalid JSON: {exc}") from exc
        scene = row.get("scene", "unknown")
        counts[scene] += 1
        if "pid" in row:
            by_pid[(scene, row["pid"])] += 1
        window = row.get("window", {})
        if "start" in window and "end" in window:
            starts.append(window["start"])
            ends.append(window["end"])
        if row.get("event") == "diagnosis":
            missing = [key for key in REQUIRED if key not in row]
            if missing:
                raise ValueError(f"line {number}: diagnosis missing {missing}")
            anomaly = {key: row[key] for key in REQUIRED}
            anomaly["confidence"] = 1.0  # exact rule match, not a calibrated probability
            anomalies.append(anomaly)
    now = datetime.now(timezone.utc).isoformat()
    return {
        "tool": "osmedic",
        "window": {"start": min(starts, default=now),
                   "end": max(ends, default=now)},
        "anomalies": anomalies,
        "event_counts": dict(counts),
        "top_processes": {
            f"{scene}/pid{pid}": n
            for (scene, pid), n in by_pid.most_common(10)
        },
    }


def main():
    parser = argparse.ArgumentParser(description="osmedic JSONL 汇总及诊断报告")
    parser.add_argument("--input", default="-", help="JSONL 文件，默认 stdin")
    parser.add_argument("--window", type=int, default=60,
                        help="保留兼容参数；场景 1/2 由加载器给出窗口")
    args = parser.parse_args()
    try:
        if args.input == "-":
            report = collect(sys.stdin)
        else:
            with open(args.input, encoding="utf-8") as stream:
                report = collect(stream)
    except (OSError, ValueError) as exc:
        print(f"collector: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
