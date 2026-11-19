#!/usr/bin/env bash
# 场景2 注入：CPU 异常占用（stress-ng 满载 4 核）
# 用法：./faults/02_cpu.sh [持续秒数，默认 60]
set -euo pipefail
DUR="${1:-60}"

command -v stress-ng >/dev/null || { echo "缺少 stress-ng：sudo dnf install -y stress-ng"; exit 1; }
echo "[注入] stress-ng --cpu 4 运行 ${DUR}s（另开终端观察探针输出）"
stress-ng --cpu 4 --timeout "${DUR}"s
echo "[结束] 场景2 注入完成"
