#!/usr/bin/env bash
# 场景4：默认仅64MiB工作集，反复分配/触页；不诱发全机OOM。
set -euo pipefail
DUR="${1:-60}"
[[ $# -le 1 && "$DUR" =~ ^[0-9]+$ && ${#DUR} -le 5 ]] && ((10#$DUR > 0 && 10#$DUR <= 86400)) || { echo '时长须为1..86400秒' >&2; exit 1; }
command -v stress-ng >/dev/null || { echo '缺少 stress-ng：sudo dnf install -y stress-ng' >&2; exit 1; }
printf '[注入] stress-ng --vm 1 --vm-bytes 64m，%ss\n' "$DUR"
stress-ng --vm 1 --vm-bytes 64m --vm-hang 0 --timeout "${DUR}s"
