#!/usr/bin/env bash
# osmedic 一键测试：五场景 注入 → 观测 → 判定（PASS/FAIL）
# 当前状态：骨架——流程占位；自动判定在阶段 3 由 analysis 层完成后接入
# 评分对应：工程质量-复现脚本项（4 分）
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== osmedic 一键测试（骨架）=="
for scene in 01_syscall 02_cpu 03_io 04_mem 05_lock; do
    echo "[$scene] TODO(阶段3)：启动对应探针加载器 → ./faults/${scene}.sh → 校验诊断输出含预期异常类型"
done
echo
echo "阶段 3 完成规则引擎后，本脚本对每个场景输出 PASS/FAIL 并汇总。"
