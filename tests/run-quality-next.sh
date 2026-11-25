#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$EUID" -ne 0 ]]; then
    echo 'Run with sudo/root' >&2
    exit 1
fi
mkdir -p output/quality
stamp=$(date +%Y%m%d-%H%M%S)
log="output/quality/next-${stamp}.log"
exec 9>output/quality/batch.lock
if ! flock -n 9; then
    echo 'Another quality suite is running; leave it undisturbed.' >&2
    exit 1
fi
# Never expose a previous batch's successful exit code while this one runs.
printf 'pending\n' > output/quality/next-quick.exit
printf 'pending\n' > output/quality/next-modes.exit
printf 'pending\n' > output/quality/next-cpu.exit
nohup bash -c '
    set +e
    python3 tests/quality-evaluate.py --profile regression --cached-exit --require-accuracy --phases count,accuracy,diagnosis --alerts SYSCALL_HOTSPOT,SYSCALL_SLOW
    quick=$?
    printf "%s\n" "$quick" > output/quality/next-quick.exit
    if [ "$quick" -eq 0 ]; then
        python3 tests/compare-syscall-modes.py
        printf "%s\n" "$?" > output/quality/next-modes.exit
    else
        printf "skipped_accuracy_gate\n" > output/quality/next-modes.exit
    fi
    # Independent CPU confirmation remains useful even if the syscall experiment fails.
    python3 tests/quality-evaluate.py --profile full --phases diagnosis --alerts CPU_HOG,SCHED_DELAY
    printf "%s\n" "$?" > output/quality/next-cpu.exit
    echo NEXT_BATCH_FINISHED
' > "$log" 2>&1 < /dev/null &
printf '%s\n' "$log" > output/quality/next-log.txt
echo "$!" > output/quality/next.pid
echo "Started PID $(cat output/quality/next.pid). Log: $log"
echo 'About 90 minutes. Keep the VM running; the SSH window can close.'
