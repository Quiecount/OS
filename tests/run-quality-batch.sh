#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$EUID" -ne 0 ]]; then
    echo 'Run with sudo/root' >&2
    exit 1
fi
mkdir -p output/quality
# flock prevents concurrent suites from distorting each other's results.
nohup flock -n output/quality/batch.lock bash -c '
    python3 tests/quality-evaluate.py --profile smoke --phases count,accuracy,performance &&
    python3 tests/quality-evaluate.py --profile full
' > output/quality/batch.log 2>&1 < /dev/null &
echo "$!" > output/quality/batch.pid
echo "Started PID $(cat output/quality/batch.pid). Log: output/quality/batch.log"
echo 'The VM must remain running; this suite takes approximately 2–3 hours.'
