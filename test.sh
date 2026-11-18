#!/usr/bin/env bash
# osmedic 一键测试入口（实际逻辑在 tests/test.sh；评分"复现脚本"项的对外入口）
exec bash "$(dirname "$0")/tests/test.sh" "$@"
