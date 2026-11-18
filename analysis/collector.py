#!/usr/bin/env python3
"""osmedic 采集聚合层骨架（阶段 3 主体）

数据流：加载器把探针事件打印为 JSON Lines（stdout 或文件）
       → 本脚本读取 → 按场景聚合 → 规则引擎判定 → 输出七字段诊断报告

当前状态：骨架——只完成"读取 + 按场景/进程计数"；
基线对比、规则引擎、报告生成在阶段 3 补齐（见代码内 TODO 与开发计划 §四）。

用法：
    python3 analysis/collector.py --input events.jsonl
    （阶段 2 起各场景加载器提供 JSON Lines 输出模式后，可直接管道接入本脚本）
"""
import argparse
import json
import sys
from collections import defaultdict

# 场景代号与 src/events.h 的事件结构一一对应
# 详见 docs/系统设计_五场景总体框架.md
SCENARIOS = ("exec", "syscall", "cpu", "io", "mem", "lock")


def main():
    ap = argparse.ArgumentParser(description="osmedic 事件聚合（骨架）")
    ap.add_argument("--input", default="-", help="JSON Lines 输入文件，默认 stdin")
    ap.add_argument("--window", type=int, default=60,
                    help="统计窗口秒数（骨架暂未使用，阶段 3 实现滑动窗口）")
    args = ap.parse_args()

    counts = defaultdict(int)      # 场景 → 事件总数
    by_pid = defaultdict(int)      # (场景, pid) → 事件数

    stream = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue  # 跳过非 JSON 行（例如加载器的提示文本）

        scene = evt.get("scene", "unknown")
        counts[scene] += 1
        by_pid[(scene, evt.get("pid"))] += 1

        # TODO(阶段3)：按场景聚合核心指标——
        #   syscall → 每 pid×syscall 频次 Top-N 与延迟   → SYSCALL_HOTSPOT
        #   cpu     → runqlat 分位数 / 每进程 CPU%       → CPU_HOG / SCHED_DELAY
        #   io      → 延迟 P50/P99（按进程/设备）        → IO_JITTER
        #   mem     → 缺页速率、大块 mmap、OOM 事件      → MEM_PRESSURE / OOM_KILL
        #   lock    → 同 uaddr 等待线程数与累计时长      → LOCK_CONTENTION

    # TODO(阶段3)：与正常负载基线对比 → 命中规则 → 组装七字段报告
    #   （异常类型/关联对象/关键指标/时间窗口/疑似根因/证据链/建议结论，
    #     schema 见 docs/开发计划 §四，阶段 3 开工前冻结）
    report = {
        "tool": "osmedic",
        "stage": "skeleton",
        "window_sec": args.window,
        "event_counts": dict(counts),
        "top_processes": {
            f"{scene}/pid{pid}": n
            for (scene, pid), n in sorted(by_pid.items(), key=lambda x: -x[1])[:10]
        },
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
