#!/usr/bin/env bash
# 场景4 注入：内存压力（stress-ng 反复分配/释放内存，制造缺页与回收压力）
# 用法：./faults/04_mem.sh [持续秒数，默认 60]
set -euo pipefail
DUR="${1:-60}"

command -v stress-ng >/dev/null || { echo "缺少 stress-ng：sudo dnf install -y stress-ng"; exit 1; }
echo "[注入] stress-ng --vm 2 --vm-bytes 1G 运行 ${DUR}s"
# 注意：VM 内存小的环境把 --vm-bytes 调小（如 512m），避免直接 OOM 掉加载器
stress-ng --vm 2 --vm-bytes 1G --vm-hang 0 --timeout "${DUR}"s
echo "[结束] 场景4 注入完成"
