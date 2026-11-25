#!/usr/bin/env bash
# 场景1 注入：高频系统调用热点（syscall bomb）
# 用法：./faults/01_syscall.sh [持续秒数，默认 60]
set -euo pipefail
DUR="${1:-60}"
BIN="$(cd "$(dirname "$0")/.." && pwd)/build/syscall_bomb"

[ -x "$BIN" ] || { echo "找不到 $BIN —— 先在仓库根目录 make"; exit 1; }
echo "[注入] syscall bomb 运行 ${DUR}s（另开终端观察探针输出）"
timeout "$((DUR + 2))" "$BIN" "$DUR"
echo "[结束] 场景1 注入完成"
