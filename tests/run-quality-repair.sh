#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$EUID" -ne 0 ]]; then
    echo 'Run with sudo/root' >&2
    exit 1
fi
mkdir -p output/quality
# Take the shared lock before acknowledging launch; avoid silent no-op runs.
exec 9>output/quality/batch.lock
if ! flock -n 9; then
    echo 'Another quality suite is running; leave it undisturbed.' >&2
    exit 1
fi
nohup bash -c '
    set +e
    python3 tests/quality-evaluate.py --profile regression --phases count,accuracy,diagnosis,performance
    result=$?
    printf "%s\n" "$result" > output/quality/repair.exit
    exit "$result"
' > output/quality/repair.log 2>&1 < /dev/null &
echo "$!" > output/quality/repair.pid
echo "Started PID $(cat output/quality/repair.pid). Log: output/quality/repair.log"
echo 'About 15 minutes. Keep the VM running; the SSH window can close.'
