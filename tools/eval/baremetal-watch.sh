#!/usr/bin/env bash
# tools/eval/baremetal-watch.sh — live dashboard for baremetal-rerun.sh
#
# Auto-detects the current phase (native → guest-build → guest-boot → soak),
# tails the right log, shows the pinned build/QEMU processes, and flags a stall
# (how long since the active log was last written).  Read-only · run in any terminal.
#
#   tools/eval/baremetal-watch.sh            # refresh every 5s (Ctrl-C to quit)
#   tools/eval/baremetal-watch.sh 2          # refresh every 2s
#   tools/eval/baremetal-watch.sh once       # one snapshot then exit (good for `! ...`)
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$REPO"
ONESHOT=0; INT=5
case "${1:-}" in once) ONESHOT=1;; ''|*[!0-9]*) :;; *) INT="$1";; esac

hr(){ printf '── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((60-${#1}))))"; }
age(){ [ -e "$1" ] && echo $(( $(date +%s) - $(stat -c %Y "$1") )) || echo -1; }

snapshot(){
  RUN="$(ls -dt tools/eval/baremetal-*/ 2>/dev/null | head -1)"
  printf '═══ sotOs bare-metal eval · dashboard · %s ═══\n' "$(date '+%H:%M:%S')"
  if [ -z "$RUN" ]; then echo "No hay run todavía (tools/eval/baremetal-*/ vacío)."; return; fi
  echo "run: $RUN"

  hr "procesos vivos (CPU%) — señal #1 de que NO está colgado"
  ps -eo comm,pid,pcpu,etime --sort=-pcpu \
    | awk 'NR==1 || /cc1|cc1plus|qemu|ninja|^ld$|^gcc$|^cc$|^just$|cmake|perl/' | head -6

  bl="$RUN/guest-build.log"; sl="$RUN/guest-serial.log"; kl="$RUN/soak.log"
  ev="$(ls -dt evidence/v1.5-*/ 2>/dev/null | head -1)"
  newest="$(ls -t "$bl" "$sl" "$kl" 2>/dev/null | head -1)"
  qemu_up=0; pgrep -x qemu-system-x86_64 >/dev/null 2>&1 && qemu_up=1

  case "$newest" in
    "$kl")  # ───────────── SOAK ─────────────
      hr "FASE: SOAK (T4 · contención/endurance)"
      if [ -n "$ev" ] && [ -d "$ev" ]; then
        done=$(grep -acE 'boot [0-9]+ done' "$ev/run.log" 2>/dev/null)
        last=$(grep -aE '\-\-\-\- boot [0-9]+ ' "$ev/run.log" 2>/dev/null | tail -1)
        echo "evidence : $ev"
        echo "boots    : ${done} completados   ·   $last"
        [ -f "$ev/faults.txt" ] && echo "faults   : $(wc -l < "$ev/faults.txt") líneas en faults.txt"
        echo "── run.log (cola):"; tail -6 "$ev/run.log" 2>/dev/null | sed 's/^/  /'
        active="$ev/run.log"
      else
        echo "── soak.log (cola):"; tail -8 "$kl" 2>/dev/null | sed 's/^/  /'; active="$kl"
      fi ;;
    "$sl")  # ───────────── GUEST BOOT (ubench) ─────────────
      hr "FASE: GUEST BOOT (T5 · ubench bajo KVM · timeout 240s)"
      tail -8 "$sl" 2>/dev/null | tr -d '\000' | sed 's/^/  /'; active="$sl" ;;
    "$bl")  # ───────────── GUEST BUILD ─────────────
      hr "FASE: GUEST BUILD (just build · sin timeout → mirar ninja)"
      prog=$(grep -aoE '^\[[0-9]+/[0-9]+\]' "$bl" 2>/dev/null | tail -1)
      echo "ninja    : ${prog:-(aún sin pasos)}   $( [ "$qemu_up" = 1 ] && echo '· (qemu ya arriba)' )"
      echo "── guest-build.log (cola):"; tail -6 "$bl" 2>/dev/null | sed 's/^/  /'; active="$bl" ;;
    *)      # ───────────── NATIVE / arranque ─────────────
      hr "FASE: NATIVE baseline / arranque"
      [ -f "$RUN/native.txt" ] && tail -6 "$RUN/native.txt" | sed 's/^/  /' || echo "  (preflight/knobs…)"
      active="$RUN/summary.txt" ;;
  esac

  a=$(age "${active:-/nonexistent}")
  hr "estado"
  if [ "$a" -lt 0 ]; then echo "  (sin log activo aún)"
  elif [ "$a" -gt 420 ]; then echo "  ⚠  última escritura hace ${a}s — POSIBLE estancamiento (revisa procesos arriba)"
  else echo "  ✓ última escritura hace ${a}s — vivo"; fi
}

if [ "$ONESHOT" = 1 ]; then snapshot; exit 0; fi
trap 'echo; exit 0' INT
while :; do clear; snapshot; echo; echo "(refresco ${INT}s · Ctrl-C para salir)"; sleep "$INT"; done
