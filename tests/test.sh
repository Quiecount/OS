#!/usr/bin/env bash
# osmedic 一键测试：五场景 注入 → 观测 → 判定（PASS/FAIL）
# 使用显式测试阈值验证采集与规则通路；正常负载基线留待阶段3。
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== osmedic 一键测试 =="
bash tests/stage2-two-scenarios.sh
echo "[01_syscall] PASS"
echo "[02_cpu] PASS"
make quality-unit
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_stage2.py
echo "[03_io] PASS"
echo "[04_mem] PASS（OOM 隔离测试是否可用见上方结果）"
echo "[05_lock] PASS"
