#!/usr/bin/env python3
"""Turn saved quality evidence into a reviewable report; never infer missing passes."""
import argparse
import hashlib
import json
from pathlib import Path


def summarize(report):
    cases = report["cases"]
    phases = report.get("phases", {})
    full = report["profile"] == "full"
    lines = ["# 场景 1–2 质量评测结果", "",
             f"- 开始时间：{report['started_at']}",
             f"- 完成时间：{report.get('finished_at') or '尚未完成'}",
             f"- 当前阶段：{report.get('active_phase') or '已结束'}",
             f"- 环境：{report['kernel']}，{report['logical_cpus']} 个逻辑 CPU；配置 {report['profile']}",
             "- 以下门槛为项目建议目标，不是赛事官方优秀分数线。", "",
             "执行成功、指标达标和场景覆盖完整是三个不同结论。未完成项目不记为通过。", ""]

    def section(title, header, rows):
        lines.extend([f"## {title}", "", "| " + " | ".join(header) + " |",
                      "| " + " | ".join("---" for _ in header) + " |"])
        lines.extend("| " + " | ".join(map(str, row)) + " |" for row in rows)
        lines.append("")

    def verdict(ok):
        return "通过" if ok else "未达标"

    count_cases = [c for c in cases if c["label"].startswith("count-")]
    count_checks = [x for c in count_cases for x in c.get("count_checks", [])]
    section("场景 1：系统调用计数", ["项目", "结果"], [
        ["已执行组合 / 计划组合", f"{len(count_cases)} / {27 if report['profile'] != 'smoke' else 9}"],
        ["通过误差检查 / 已生成检查", f"{sum(x['target_met'] for x in count_checks)} / {len(count_checks)}"],
        ["最大相对误差（目标 ≤0.1%）", f"{max(x['error_percent'] for x in count_checks):.6f}%" if count_checks else "未测"],
    ])
    lines.extend(["open 场景分别核对 openat 和 close，因此检查数量多于组合数量。告警测试使用 Top-10 输出，不将其显示行求和用于计数准确度。", ""])
    section("计数负载实际覆盖", ["调用", "线程", "请求速率（次/秒）", "实际完成（次/秒）"], [
        [c["mode"], c["threads"], c["rate"], f"{c['calls']/c['actual_duration_s']:.0f}"]
        for c in count_cases if c.get("actual_duration_s")])
    lines.extend(["准确度通过只说明实际已执行调用被正确统计；实际速率低于请求速率的组合不能标为该请求速率已经覆盖。open 的速率按一对 openat/close 计，两种调用分别核对次数。", ""])
    section("场景 1：延迟参考对照", ["负载", "均值 / 参考 (µs)", "均值目标", "P99 桶上界 / 参考 (µs)", "P99 目标"], [
        [c["mode"], f"{x['mean_us']:.3f} / {x['reference_mean_us']:.3f}", verdict(x["mean_target_met"]),
         f"{x['p99_upper_us']:.3f} / {x['reference_p99_us']:.3f}", verdict(x["p99_target_met"])]
        for c in cases if (x := c.get("syscall_latency"))])
    lines.extend(["均值允许误差 max(1 µs, 参考值×10%)；P99 允许误差 max(1 µs, 参考值×20%)。参考探针仅在准确度测试开启，本身也有测量扰动。", ""])
    section("场景 2：CPU 准确度", ["名义负载档", "参考实测 CPU%", "监测 CPU%", "误差（百分点）", "≤2 pp"], [
        [c["duty"], f"{x['reference_percent']:.3f}", f"{x['measured_percent']:.3f}",
         f"{x['error_percentage_points']:.4f}", verdict(x["target_met"])]
        for c in cases if c["label"].startswith("cpu-accuracy-") and (x := c.get("cpu_accuracy"))])
    lines.extend(["CPU 参考为 CLOCK_PROCESS_CPUTIME_ID，按单核容量 100% 计。名义负载不等于实际覆盖占用率；虚拟机调度可能降低实际负载。", ""])
    extra_cpu = [(c["label"], c["cpu_accuracy"]) for c in cases
                 if not c["label"].startswith("cpu-accuracy-") and "cpu_accuracy" in c]
    if extra_cpu:
        failures = [(name, x) for name, x in extra_cpu if not x["target_met"]]
        lines.extend([f"告警试验中还生成 {len(extra_cpu)} 个 CPU 对照，其中 {len(failures)} 个超出 2 个百分点。不能只用上面固定负载档的通过结果宣称所有 CPU 测量均准确。", ""])
        if failures:
            section("告警试验附带 CPU 对照失败", ["用例", "误差（百分点）"],
                    [[name, f"{x['error_percentage_points']:.3f}"] for name, x in failures])
    section("场景 2：等待时间", ["负载", "runqlat P99 / 参考 (µs)", "P99 目标", "off-CPU 误差", "≤5%"], [
        [c["mode"], f"{r['p99_upper_us']:.3f} / {r['reference_p99_us']:.3f}" if r else "缺参考样本",
         verdict(r["target_met"]) if r else "未测", f"{o['error_percent']:.5f}%", verdict(o["target_met"])]
        for c in cases if (o := c.get("offcpu")) for r in [c.get("runqlat")]])
    lines.extend(["runqlat P99 允许误差 max(5 µs, 参考值×20%)。off-CPU 为已完成切出→切入区间的总和，按完成窗口归属，包含睡眠、阻塞与排队；不是每个窗口的实时等待时间。", ""])

    diagnosis = phases.get("diagnosis", {}).get("results", report.get("diagnosis_progress", {}))
    rows = []
    for alert in ("SYSCALL_HOTSPOT", "SYSCALL_SLOW", "CPU_HOG", "SCHED_DELAY"):
        x = diagnosis.get(alert)
        if not x:
            rows.append([alert, "未测", "未测", "未测", "未完成"])
            continue
        enough = full and x["positive"] == 100 and x["negative"] == 200
        ok = enough and not x["execution_errors"] and x["detected"] >= 98 and x["false_positives"] <= 2
        rows.append([alert, f"{x['detected']}/{x['positive']}", f"{x['false_positives']}/{x['negative']}",
                     f"{x['timely']}/{x['positive']}", verdict(ok) if enough else "样本不足，未作完整判定"])
    section("告警检出和误报", ["告警", "检出 / 异常试验", "误报 / 正常试验", "时限内 / 异常试验", "98% / 1% 经验比例目标"], rows)
    lines.extend(["热点、慢调用、调度延迟时限为负载启动后 2 秒；CPU_HOG 为启动后 12 秒（含 10 秒持续条件）。仅评价预先指定的测试进程，未标注的系统进程不计入误报分母。有限合成样本的经验比例不等于真实业务总体成功率；完整 JSON 保留 Wilson 95% 区间。", ""])
    perf = phases.get("performance", {}).get("results", {})
    rows = []
    for scene, threshold in (("syscall", 5), ("cpu", 2)):
        x = perf.get(scene)
        if not x:
            rows.append([scene, "未完成", "未完成", "未完成", f"≤{threshold}%", "未完成"])
        else:
            conclusion = verdict(x["target_met"]) if x.get("sufficient_sample_size") else "短回归，未作完整判定"
            rows.append([scene, len(x["runs"]["on"]), f"{x['throughput_loss_percent']:.3f}%",
                         f"{100*x['baseline_cv']:.3f}%", f"≤{threshold}%", conclusion])
    section("分场景吞吐开销", ["探针", "配对数", "吞吐损失", "基线变异系数", "目标", "结论"], rows)
    lines.extend(["损失=100×(1−开启吞吐中位数/关闭吞吐中位数)。负值按实验噪声解释；基线变异系数超过 5% 时不认定性能达标。完整配置每场景 10 对、每段 30 秒。", ""])
    resources = []
    for scene in ("syscall", "cpu"):
        entries = [c["resources"][scene] for c in cases if scene in c.get("resources", {}) and not c["label"].startswith("latency-")]
        if entries:
            resources.append([scene, f"{max(x['rss_mib_max'] for x in entries):.3f}",
                              f"{max(x['cpu_percent_one_core'] for x in entries):.3f}"])
    section("加载器资源（排除参考探针用例）", ["探针", "已测用例最大 RSS (MiB)", "最高用例平均单核 CPU%"], resources)
    lines.extend(["建议目标 RSS≤32 MiB、加载器 CPU≤2%。CPU 是整个用例的平均值，不是瞬时峰值；RSS 不包含内核 BPF map 内存，探针内核执行开销主要用吞吐对照评价。", ""])
    map_rows = []
    for scene in ("syscall", "cpu"):
        totals = [sum(int(m["memlock"]) for m in maps.values()) / 1048576
                  for c in cases for maps in [c.get("bpf_maps", {}).get(scene, {})]
                  if maps and all("memlock" in m for m in maps.values())]
        if totals:
            map_rows.append([scene, f"{max(totals):.3f}"])
    section("内核 map 内存记账", ["探针", "单次实例所有 map 的 memlock 最大合计 (MiB)"], map_rows)
    lines.extend(["数值取该加载器 /proc/PID/fdinfo 中各 map_id 的 memlock，单次实例内去重求和；这是内核接口记账值，与用户态 RSS 分列，不是整机物理内存增量。", ""])
    soak = [c for c in cases if c["label"].startswith("soak-")]
    section("长时间稳定性覆盖", ["负载", "已完成实际秒数", "执行结果", "计数最大误差"], [
        [c["mode"], f"{c.get('actual_duration_s', 0):.2f}", c["execution"],
         f"{max(x['error_percent'] for x in c['count_checks']):.6f}%" if c.get("count_checks") else "未生成"] for c in soak])
    if "soak" in phases:
        lines.extend(["完整配置为 getpid/stat/open 各 10 分钟，共 30 分钟，两个探针同时开启；smoke 配置每种仅 3 秒。以表中实际时长为准，不等于每个线程数与负载组合完成 30 分钟，也未覆盖高进程基数 map 饱和。", ""])
    else:
        lines.extend(["本轮未执行长时间稳定性阶段。旧版本的长测结果不能替代本版本验证。", ""])
    errors = [f"- {c['label']}: {c.get('error', 'unknown')}" for c in cases if c["execution"] != "passed"]
    errors += [f"- {name}: {phase.get('error', 'unknown')}" for name, phase in phases.items() if phase["execution"] == "failed"]
    lines.extend(["## 执行错误", "", *(errors or ["已完成部分未记录执行错误。"]), ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = args.report.read_bytes()
    result = summarize(json.loads(raw))
    result += f"\n原始 JSON 报告 SHA256：`{hashlib.sha256(raw).hexdigest()}`。\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
