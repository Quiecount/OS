#!/usr/bin/env python3
"""场景5 量化统计：计数 / 平均延迟 / P99 延迟准确度（对照 futex_calib 真值）

输入：
  --jsonl  采集的 JSONL 事件文件
  --truth   futex_calib 输出到 stderr 的真值 JSON 文件
            （{"expect_events": N, "timeout_us": T, "uaddr": "0x..."}）
输出（stdout，JSON）：匹配事件数、计数误差%、平均/P99 误差%
"""
import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True)
    ap.add_argument("--truth", required=True)
    args = ap.parse_args()

    truth = json.load(open(args.truth, encoding="utf-8"))
    expect = truth["expect_events"]
    timeout_us = truth["timeout_us"]
    uaddr = truth["uaddr"]

    durs = []
    with open(args.jsonl, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if evt.get("scene") == "lock" and evt.get("uaddr") == uaddr:
                durs.append(evt["duration_ns"])

    durs.sort()
    n = len(durs)
    if n == 0:
        print(json.dumps({"matched": 0, "expect": expect,
                          "count_err_pct": 100.0}))
        return

    avg_us = sum(durs) / n / 1000.0
    p99_us = durs[min(n - 1, int(n * 0.99))] / 1000.0

    out = {
        "matched": n,
        "expect": expect,
        "count_err_pct": abs(n - expect) / expect * 100.0,
        "timeout_us": timeout_us,
        "avg_us": round(avg_us, 1),
        "avg_err_pct": round(abs(avg_us - timeout_us) / timeout_us * 100.0, 3),
        "p99_us": round(p99_us, 1),
        "p99_err_pct": round(abs(p99_us - timeout_us) / timeout_us * 100.0, 3),
    }
    print(json.dumps(out))


if __name__ == "__main__":
    main()
