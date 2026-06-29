#!/usr/bin/env bash
# T4 · containment & memory soak. Leverages the MATURE existing gate scripts/soak.sh
# (which already parses [stats]/[soak] survival + the root_pages slope) and additionally
# extracts the per-cycle samples into a CSV for the F1 figure + the slope±CI regression.
#
# Usage: tools/eval/t4-containment/soak.sh <soak-serial-log>
#   Produce the log with the existing endurance boot, e.g.:
#     scripts/v1.5-endurance-run.sh   (or pillar4-validate.sh) → writes a serial log
#   then point this script at it. K~300 spawn/teardown cycles (scaled proxy; the slope
#   enables extrapolation per scripts/soak.sh's own disclaimer).
set -u
cd "$(git rev-parse --show-toplevel)"
LOG="${1:-/tmp/p4b.log}"
CSV="tools/eval/t4-containment/samples.csv"
[ -f "$LOG" ] || { echo "[T4] no soak log at $LOG — run scripts/v1.5-endurance-run.sh first"; exit 1; }

echo "[T4] === survival + slope verdict (via the existing gate) ==="
scripts/soak.sh "$LOG" || true

echo "[T4] === extracting per-cycle [stats] → $CSV (for F1 + regression) ==="
echo "iter,free_arenas,live_sotbox,root_pages" > "$CSV"
grep -aE '\[stats\] iter=[0-9]+ free_arenas=[0-9]+/[0-9]+ live_sotbox=[0-9]+ root_pages=[0-9]+' "$LOG" \
  | sed -E 's/.*iter=([0-9]+) free_arenas=([0-9]+)/[0-9]+ live_sotbox=([0-9]+) root_pages=([0-9]+).*/\1,\2,\3,\4/' \
  | sed -E 's#([0-9]+),([0-9]+)/[0-9]+ live_sotbox=([0-9]+) root_pages=([0-9]+)#\1,\2,\3,\4#' >> "$CSV" 2>/dev/null || true
# robust fallback parse (anchored, field-by-field) if the sed above misses:
if [ "$(wc -l < "$CSV")" -le 1 ]; then
  echo "iter,free_arenas,live_sotbox,root_pages" > "$CSV"
  while IFS= read -r ln; do
    it=$(echo "$ln" | grep -oE 'iter=[0-9]+' | grep -oE '[0-9]+')
    fa=$(echo "$ln" | grep -oE 'free_arenas=[0-9]+' | grep -oE '[0-9]+')
    ls=$(echo "$ln" | grep -oE 'live_sotbox=[0-9]+' | grep -oE '[0-9]+')
    rp=$(echo "$ln" | grep -oE 'root_pages=[0-9]+' | grep -oE '[0-9]+')
    [ -n "$it" ] && [ -n "$rp" ] && echo "$it,$fa,$ls,$rp" >> "$CSV"
  done < <(grep -aE '\[stats\] iter=' "$LOG")
fi
echo "[T4] $(($(wc -l < "$CSV")-1)) clean cycles → $CSV"

echo "[T4] === leak watermark (max unreclaimed after revoke) ==="
grep -aoE 'peak retyped=[0-9]+ \(=[0-9]+MiB\) reused=[0-9]+' "$LOG" | tail -3 || true

echo "[T4] === slope ± 95% CI (F1) ==="
python3 tools/eval/t4-containment/plot.py "$CSV"
