#!/usr/bin/env bash
# osmedic 一键测试：五场景 注入 → 观测 → 判定（PASS/FAIL）
# 场景 1/2 已接入自动判定；其余场景仍是骨架。
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== osmedic 一键测试 =="
bash tests/stage2-two-scenarios.sh
echo "[01_syscall] PASS"
echo "[02_cpu] PASS"
for scene in 03_io 04_mem 05_lock; do
    echo "[$scene] TODO：场景尚未实现"
done
