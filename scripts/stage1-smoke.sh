#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/output/stage1"
EXEC_JSONL="${OUTPUT_DIR}/exec.jsonl"
IO_JSONL="${OUTPUT_DIR}/io.jsonl"

if [[ "${EUID}" -ne 0 ]]; then
  echo "阶段1端到端验收需要 root：sudo ./scripts/stage1-smoke.sh" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
rm -f "${EXEC_JSONL}" "${IO_JSONL}" "${OUTPUT_DIR}/io.bin"

make -C "${ROOT_DIR}" check

"${ROOT_DIR}/build/execsnoop" --duration 4 --output "${EXEC_JSONL}" &
exec_pid=$!
sleep 1
/usr/bin/true
/usr/bin/uname -a >/dev/null
wait "${exec_pid}"

"${ROOT_DIR}/build/biolatency" --interval 2 --duration 6 --output "${IO_JSONL}" &
io_pid=$!
sleep 1
dd if=/dev/zero of="${OUTPUT_DIR}/io.bin" bs=1M count=64 conv=fdatasync status=none
wait "${io_pid}"
rm -f "${OUTPUT_DIR}/io.bin"

python3 - "${EXEC_JSONL}" "${IO_JSONL}" <<'PY'
import json
import pathlib
import sys

exec_path, io_path = map(pathlib.Path, sys.argv[1:])

def load(path):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    if not rows:
        raise SystemExit(f"FAIL: {path} 没有事件")
    return rows

exec_rows = load(exec_path)
io_rows = load(io_path)

assert all(row["event"] == "process_exec" for row in exec_rows)
assert all(row["filename"] for row in exec_rows)
assert all(row["event"] == "block_io_latency_histogram" for row in io_rows)
assert all(row["samples"] > 0 and len(row["buckets"]) == 26 for row in io_rows)

print(f"EXEC_EVENTS={len(exec_rows)}")
print(f"IO_HISTOGRAMS={len(io_rows)}")
print("STAGE1_SMOKE_OK")
PY

echo "阶段1验收通过："
echo "  ${EXEC_JSONL}"
echo "  ${IO_JSONL}"
