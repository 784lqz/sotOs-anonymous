#!/usr/bin/env bash
# Pillar 4 · release-validation runner (P4c).
# *** SCALED PROXY — NOT a literal 24h-3-malware-parallel run. ***
# Boots the OS once (the demo runs both `validate` and `soak`), then runs the P4a
# (concurrent 3-malware containment) + P4b (soak / leak-drift) gates on the one
# serial log, plus the Pillar-3 invisibility leg, and emits a combined verdict.
# Exit 0 iff both gates pass.
#
# Usage: scripts/pillar4-validate.sh [timeout_s] [log_path]
#   NEVER pkills the operator's QEMU (sotfs.img write-lock) — reports BLOCKED.
set -u
TIMEOUT="${1:-300}"
LOG="${2:-/tmp/pillar4.log}"
cd "$(dirname "$0")/.." || { echo "[pillar4] cannot cd to repo root"; exit 2; }

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[pillar4] BLOCKED · operator QEMU is running (holds the sotfs.img write-lock) — exit it and retry"
    exit 2
fi

echo "[pillar4] clean rebuild (defeats the binstore persist-coupling: a stale rwbinstore shadows the fresh sotshell) ..."
rm -f build/images/sotfs.img
if ! just build >/dev/null 2>&1; then echo "[pillar4] build FAILED"; exit 2; fi

echo "[pillar4] boot · just run-soak ${TIMEOUT}s (demo runs validate + soak) → ${LOG}"
just run-soak "$TIMEOUT" "$LOG" >/dev/null 2>&1 &
SOAK_PID=$!
for i in $(seq 1 $((TIMEOUT + 40))); do
    LC_ALL=C grep -aqiE '\[soak\] [0-9]+/[0-9]+ survived|\[soak\] STOP|POWEROFF' "$LOG" 2>/dev/null && break
    sleep 1
done
wait "$SOAK_PID" 2>/dev/null   # wait for THIS boot only (not stray bg jobs)

echo; echo "========== P4a · concurrent 3-malware containment =========="
bash scripts/validate.sh "$LOG"; va=$?
echo; echo "========== P4b · soak / leak-drift =========="
bash scripts/soak.sh "$LOG"; so=$?
echo; echo "========== P3 · trace-plane invisibility =========="
if LC_ALL=C grep -aqE 'invisible=YES' "$LOG"; then echo "PASS  invisible=YES"; else echo "INFO  invisibility marker not in this boot"; fi

echo
if [ "$va" -eq 0 ] && [ "$so" -eq 0 ]; then
    echo "========== PILLAR 4 VALIDATION: PASS (scaled proxy) =========="
    echo "  · 3 real malware families ran CONCURRENTLY and were each CONTAINED by the deception"
    echo "  · the runtime SURVIVED the spawn soak with ARENA ZERO-LEAK"
    echo "  · the only residual (client-vspace bookkeeping) is MEASURED + bounded"
    echo "  *** SCALED PROXY · NOT a literal 24h-3-malware-parallel run ***"
    exit 0
else
    echo "========== PILLAR 4 VALIDATION: FAIL (P4a rc=${va} · P4b rc=${so}) =========="
    exit 1
fi
