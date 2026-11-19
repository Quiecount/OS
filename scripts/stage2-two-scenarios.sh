#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/output/stage2"
mkdir -p "${OUT}"
if [[ "${EUID}" -ne 0 ]]; then
  echo "需要 root：sudo bash scripts/stage2-two-scenarios.sh" >&2
  exit 1
fi
command -v stress-ng >/dev/null || { echo "请安装 stress-ng" >&2; exit 1; }
make -C "${ROOT}" check
${CC:-cc} -O2 -Wall -Wextra -Werror "${ROOT}/faults/syscall_bomb.c" -o "${ROOT}/build/syscall_bomb"
rm -f "${OUT}/syscall.jsonl" "${OUT}/cpu.jsonl" "${OUT}/cpu-delay.jsonl"

"${ROOT}/build/syscallhot" --duration 7 --output "${OUT}/syscall.jsonl" &
monitor_pid=$!
trap 'kill "$monitor_pid" 2>/dev/null || true' EXIT
sleep 1
"${ROOT}/build/syscall_bomb" 4 | tee "${OUT}/bomb.txt"
wait "$monitor_pid"
trap - EXIT

"${ROOT}/build/cpuwatch" --duration 16 --output "${OUT}/cpu.jsonl" &
monitor_pid=$!
trap 'kill "$monitor_pid" 2>/dev/null || true' EXIT
sleep 1
stress-ng --cpu 1 --timeout 13s --metrics-brief >"${OUT}/stress.txt" 2>&1
wait "$monitor_pid"
trap - EXIT

"${ROOT}/build/cpuwatch" --duration 8 --baseline-p99-us 100 --output "${OUT}/cpu-delay.jsonl" &
monitor_pid=$!
trap 'kill "$monitor_pid" 2>/dev/null || true' EXIT
sleep 1
stress-ng --cpu 8 --timeout 5s --metrics-brief >"${OUT}/stress-delay.txt" 2>&1
wait "$monitor_pid"
trap - EXIT

python3 - "${OUT}" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
def read(name):
    return [json.loads(line) for line in (out / name).read_text().splitlines() if line]
syscall_rows = read('syscall.jsonl')
cpu_rows = read('cpu.jsonl')
delay_rows = read('cpu-delay.jsonl')
hot = [r for r in syscall_rows if r.get('type') == 'SYSCALL_HOTSPOT'
       and any(o.get('comm') == 'syscall_bomb' for o in r['related_objects'])]
hog = [r for r in cpu_rows if r.get('type') == 'CPU_HOG'
       and any(o.get('comm', '').startswith('stress-ng-cpu') for o in r['related_objects'])]
delay = [r for r in delay_rows if r.get('type') == 'SCHED_DELAY']
assert hot, 'FAIL: 未检出 syscall bomb 热点'
assert hog, 'FAIL: 未检出持续 10 秒的 CPU_HOG'
assert delay, 'FAIL: 未检出超额 CPU 负载下的 SCHED_DELAY'
assert any(r.get('event') == 'scheduler_metric' for r in cpu_rows)
for row in hot + hog + delay:
    assert all(k in row for k in ('type', 'related_objects', 'key_metrics',
                                  'window', 'suspected_root_cause',
                                  'evidence_chain', 'recommendation'))
print(f'SYSCALL_HOTSPOT={len(hot)} CPU_HOG={len(hog)} SCHED_DELAY={len(delay)}')
print('STAGE2_TWO_SCENARIOS_OK')
PY
