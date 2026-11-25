#!/usr/bin/env bash
# 场景3：只在临时普通文件上进行有界异步直写。
set -euo pipefail
DUR="${1:-60}"
[[ $# -le 1 && "$DUR" =~ ^[0-9]+$ && ${#DUR} -le 5 ]] && ((10#$DUR > 0 && 10#$DUR <= 86400)) || { echo '时长须为1..86400秒' >&2; exit 1; }
command -v fio >/dev/null || { echo '缺少 fio：sudo dnf install -y fio' >&2; exit 1; }
TESTFILE=$(mktemp "${OSMEDIC_IO_DIR:-/var/tmp}/osmedic-fio.XXXXXXXX")
trap 'rm -f -- "$TESTFILE"' EXIT
printf '[注入] 普通文件 %s，libaio/direct，iodepth=32，%ss\n' "$TESTFILE" "$DUR"
fio --name=osmedic-jam --filename="$TESTFILE" --size=64m --ioengine=libaio \
    --rw=write --bs=64k --iodepth=32 --direct=1 --runtime="$DUR" --time_based --group_reporting
