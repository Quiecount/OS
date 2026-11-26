#!/usr/bin/env python3
"""lock_contention JSONL 统计（现实负载分析用）
输出：事件总数 / 按进程名分布（事件数+累计等待）/ top5 锁聚合（waiter_count 按 tid）
用法: python3 lc_stats.py events.jsonl
"""
import json
import sys
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "-"
stream = open(path, encoding="utf-8") if path != "-" else sys.stdin

by_comm = defaultdict(lambda: [0, 0])
locks = defaultdict(
    lambda: {"count": 0, "wait_ns_total": 0, "wait_ns_max": 0,
             "tids": set(), "comms": set()})
n = 0
for line in stream:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue
    if e.get("scene") != "lock":
        continue
    n += 1
    c = e.get("comm", "?")
    d = e.get("duration_ns") or 0
    by_comm[c][0] += 1
    by_comm[c][1] += d
    st = locks[e.get("uaddr", "?")]
    st["count"] += 1
    st["wait_ns_total"] += d
    st["wait_ns_max"] = max(st["wait_ns_max"], d)
    st["tids"].add(e.get("tid", e.get("pid")))
    st["comms"].add(c)

print("total_lock_events:", n)
print("by_comm:")
for c, (cnt, tot) in sorted(by_comm.items(), key=lambda kv: -kv[1][1])[:10]:
    print("  %-20s events=%-6d wait_total=%.3fs" % (c, cnt, tot / 1e9))
print("top_locks:")
for u, st in sorted(locks.items(), key=lambda kv: -kv[1]["wait_ns_total"])[:5]:
    print("  %s count=%d waiter_count=%d wait_total=%.3fs wait_max=%.3fms comms=%s" % (
        u, st["count"], len(st["tids"]), st["wait_ns_total"] / 1e9,
        st["wait_ns_max"] / 1e6, ",".join(sorted(st["comms"])[:3])))
