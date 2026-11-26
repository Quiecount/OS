#!/usr/bin/env bash
# 场景5 量化测试一键序列（在 openEuler VM、仓库根目录下运行）
# 前置：make 已构建 build/futex_calib build/futex_bomb build/lock_bomb build/lock_contention
# 输出：每行 "TAG|json"，供 Windows 端汇总为指标表
set -uo pipefail
cd "$(dirname "$0")/.."

echo "== 校准档1：4线程 x 2500 次 x 1000us（真值 10000 事件）=="
./build/lock_contention --duration 5 > /tmp/q_c1.jsonl 2>/dev/null &
LP=$!; sleep 0.5
./build/futex_calib 4 2500 1000 2>/tmp/q_c1.truth
wait $LP
echo "CALIB1000|$(python3 tests/quant_stats.py --jsonl /tmp/q_c1.jsonl --truth /tmp/q_c1.truth)"

echo "== 校准档2：2线程 x 400 次 x 5000us（真值 800 事件）=="
./build/lock_contention --duration 6 > /tmp/q_c2.jsonl 2>/dev/null &
LP=$!; sleep 0.5
./build/futex_calib 2 400 5000 2>/tmp/q_c2.truth
wait $LP
echo "CALIB5000|$(python3 tests/quant_stats.py --jsonl /tmp/q_c2.jsonl --truth /tmp/q_c2.truth)"

echo "== 检出率：10 轮 lock_bomb 注入（3s）+ 采集 4.5s =="
for i in $(seq 1 10); do
  ./build/lock_contention --duration 4.5 > /tmp/q_d.jsonl 2>/dev/null &
  LP=$!; sleep 1
  timeout 3 ./build/lock_bomb > /dev/null 2>&1
  wait $LP
  python3 analysis/collector.py --input /tmp/q_d.jsonl 2>/dev/null > /tmp/q_d.json
  R=$(python3 tests/lock_alert_check.py --input /tmp/q_d.json)
  echo "DETECT|$R"
done

echo "== 误报率：10 轮无注入基线（4.5s）=="
for i in $(seq 1 10); do
  ./build/lock_contention --duration 4.5 > /tmp/q_e.jsonl 2>/dev/null
  python3 analysis/collector.py --input /tmp/q_e.jsonl 2>/dev/null > /tmp/q_e.json
  R=$(python3 tests/lock_alert_check.py --input /tmp/q_e.json)
  echo "FALSE|$R"
done

echo "== 极限吞吐：FUTEX_WAKE 洪泛 5s x2（关探针）=="
for i in 1 2; do
  echo "RATE_OFF|$(./build/futex_bomb 5)"
done

echo "== 极限吞吐：FUTEX_WAKE 洪泛 5s x2（开探针）=="
./build/lock_contention --duration 13 > /dev/null 2>/dev/null &
LP=$!; sleep 1
for i in 1 2; do
  echo "RATE_ON|$(./build/futex_bomb 5)"
done
wait $LP
echo "== 序列完成 =="
