#!/usr/bin/env bash
# 场景3 注入：I/O 延迟抖动（fio 大队列深度直写）
# 用法：./faults/03_io.sh [持续秒数，默认 60]
set -euo pipefail
DUR="${1:-60}"
TESTFILE=/var/tmp/osmedic-fio.img

command -v fio >/dev/null || { echo "缺少 fio：sudo dnf install -y fio"; exit 1; }
echo "[注入] fio 直写 ${DUR}s（iodepth=32 制造设备队列拥堵）"
fio --name=osmedic-jam --filename="$TESTFILE" --size=512m \
    --rw=write --bs=1m --iodepth=32 --direct=1 --runtime="${DUR}" --time_based
rm -f "$TESTFILE"
echo "[结束] 场景3 注入完成"
