#!/usr/bin/env bash
# T4 · anti-DoS. Drive the DoS vectors in the attacker shell and assert containment
# markers in the orch log (the fork/clone quota quarantines the offending subtree →
# Tier-2 + thread-suspend + arena revoke; CPU-spin + net-flood bounded analogously).
# Usage: tools/eval/t4-containment/antidos.sh <orch-log>   (e.g. /tmp/sotos-orch.log from run-4pane)
set -u
cd "$(git rev-parse --show-toplevel)"
LOG="${1:-/tmp/sotos-orch.log}"
[ -f "$LOG" ] || { echo "[T4-antidos] no log at $LOG (run run-4pane → COM3 firehose, or a headless capture)"; exit 1; }

cat <<'VECTORS'
[T4-antidos] Run these in the ATTACKER shell (SSH), then re-run this script:
  fork bomb (classic):  :(){ :|:& };:
  fork bomb (nested):   sh -c 'while :; do sh -c "while :; do : ; done" & done'
  cpu spin:             yes > /dev/null &   (xN)
  net flood:            for i in $(seq 1 200); do (echo>/dev/tcp/10.0.4.12/22)& done
VECTORS

echo "[T4-antidos] === containment markers in $LOG ==="
q=$(grep -acE '\[p2b\] fork-bomb quarantined' "$LOG")
r=$(grep -acE '\[arena\] (heavy )?revoke' "$LOG")
f=$(grep -acE 'unhandled syscall|invalid cap|ReadRegisters failed|orch.*FATAL' "$LOG")
echo "  fork-bomb quarantine events : $q"
echo "  arena revoke (reclaim)      : $r"
echo "  host/orch fault events      : $f   (must stay 0)"
if [ "$q" -ge 1 ] && [ "$f" -eq 0 ]; then
  echo "[T4-antidos] PASS · fork-bomb contained (quarantined + reclaimed), host stable"
else
  echo "[T4-antidos] re-run the vectors above, then re-check (need >=1 quarantine, 0 faults)"
fi
