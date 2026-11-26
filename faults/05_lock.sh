#!/usr/bin/env bash
# 场景5 注入：锁竞争（8 线程抢 1 把 pthread 锁，底层走 futex）
# 用法：./faults/05_lock.sh [持续秒数，默认 60]
set -euo pipefail
DUR="${1:-60}"
BIN="$(cd "$(dirname "$0")/.." && pwd)/build/lock_bomb"

[ -x "$BIN" ] || { echo "找不到 $BIN —— 先在仓库根目录 make"; exit 1; }
echo "[注入] 锁竞争程序运行 ${DUR}s（另开终端观察 futex 事件）"
timeout "$DUR" "$BIN" || true
echo "[结束] 场景5 注入完成"
