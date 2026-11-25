#!/usr/bin/env bash
# 场景5：8线程在同一互斥锁上等待，程序自行到时退出并join。
set -euo pipefail
DUR="${1:-60}"
[[ $# -le 1 && "$DUR" =~ ^[0-9]+$ && ${#DUR} -le 5 ]] && ((10#$DUR > 0 && 10#$DUR <= 86400)) || { echo '时长须为1..86400秒' >&2; exit 1; }
BIN="$(cd "$(dirname "$0")/.." && pwd)/build/lock_workload"
[[ -x "$BIN" ]] || { echo "找不到 $BIN，请先 make" >&2; exit 1; }
exec "$BIN" "$DUR"
