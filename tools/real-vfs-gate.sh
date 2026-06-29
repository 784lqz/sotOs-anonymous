#!/usr/bin/env bash
# sotOs v2-real-vfs gate · boots, runs `real-vfs`, asserts the five markers.
set -euo pipefail
LOG="${1:-/tmp/real-vfs.log}"
need=( "\[real-vfs\] symlink-so OK"
       "\[real-vfs\] fstat OK"
       "\[real-vfs\] read\\+lseek OK"
       "\[real-vfs\] mmap OK"
       "\[real-vfs\] getdents OK" )
fail=0
for re in "${need[@]}"; do
    if LC_ALL=C grep -aqE "$re" "$LOG"; then echo "PASS · $re"
    else echo "FAIL · $re"; fail=1; fi
done
# no abnormal faults from the probe sotbox
if LC_ALL=C grep -aqE 'CapFault|VMFault.*vfsprobe|abnormal' "$LOG"; then
    echo "FAIL · abnormal fault present"; fail=1
fi
[ "$fail" -eq 0 ] && echo "[real-vfs-gate] PASS 5/5" || { echo "[real-vfs-gate] FAIL"; exit 1; }
