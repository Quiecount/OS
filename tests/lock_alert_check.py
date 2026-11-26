#!/usr/bin/env python3
"""场景5 锁竞争告警判定原型（阶段 3 规则引擎 LOCK_CONTENTION 的合取判定）

规则（合取，缺一不可——单指标会把 systemd 周期性睡眠误报为锁竞争）：
  同一 uaddr 的 waiter_count >= N 且 wait_ns_total >= X

输入：collector.py 输出的 JSON 报告
输出（stdout，JSON）：{"alert": bool, "hits": [...]}
"""
import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="-", help="collector JSON 文件，默认 stdin")
    ap.add_argument("--waiters", type=int, default=2,
                    help="同锁等待线程数下限（默认 2）")
    ap.add_argument("--total-ns", type=int, default=100000000,
                    help="同锁累计等待时长下限 ns（默认 0.1s）")
    args = ap.parse_args()

    stream = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
    report = json.load(stream)

    hits = [
        {
            "uaddr": e["uaddr"],
            "waiter_count": e["waiter_count"],
            "wait_ns_total": e["wait_ns_total"],
        }
        for e in report.get("lock_top", [])
        if e.get("waiter_count", 0) >= args.waiters
        and e.get("wait_ns_total", 0) >= args.total_ns
    ]
    print(json.dumps({"alert": len(hits) > 0, "hits": hits}))


if __name__ == "__main__":
    main()
