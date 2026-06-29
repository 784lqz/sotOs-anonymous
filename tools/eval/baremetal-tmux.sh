#!/usr/bin/env bash
# tools/eval/baremetal-tmux.sh — arranca el eval bare-metal + el dashboard en UN tmux.
#
#   PIN_CORES=2,3 SOAK_DURATION=1800 tools/eval/baremetal-tmux.sh
#   tools/eval/baremetal-tmux.sh --guest --no-strict      # pasa flags al harness
#   tools/eval/baremetal-tmux.sh --force                  # arranca aunque ya haya un run/qemu
#
# Layout (sesión "sotos-eval"):
#   ┌──────────────────────────────────────────┐
#   │ HARNESS  (sudo pide la pass AQUÍ — la tty │  ← foco inicial
#   │          del panel es interactiva)        │
#   ├──────────────────────────────────────────┤
#   │ DASHBOARD  baremetal-watch.sh (fase+logs) │  (24 filas, ancho completo)
#   └──────────────────────────────────────────┘
# Detach sin matar nada: Ctrl-b d   ·   re-adjuntar: tmux attach -t sotos-eval
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$REPO"
SESSION="${SESSION:-sotos-eval}"
PIN_CORES="${PIN_CORES:-2,3}"
SOAK_DURATION="${SOAK_DURATION:-1800}"
WATCH_INT="${WATCH_INT:-5}"

FORCE=0; EXTRA=()
for a in "$@"; do case "$a" in --force) FORCE=1;; *) EXTRA+=("$a");; esac; done

command -v tmux >/dev/null || { echo "tmux no instalado: sudo dnf install -y tmux" >&2; exit 1; }

# sudo pide contraseña → exige una terminal interactiva.  Si no, el run arrancaría
# detached y se colgaría en el prompt de sudo sin nadie que lo conteste.
[ -t 0 ] || { echo "Ejecuta esto en una terminal interactiva (sudo necesita teclado). Abortando." >&2; exit 1; }

# Ya existe la sesión → sólo adjuntar (no relanzar).
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Sesión '$SESSION' ya existe — adjuntando."
  [ -t 1 ] && exec tmux attach -t "$SESSION" || { echo "Adjunta con: tmux attach -t $SESSION"; exit 0; }
fi

# Evitar dos runs concurrentes: el soak toma el write-lock de build/images/sotfs.img.
if [ "$FORCE" = 0 ] && { pgrep -f 'baremetal-rerun\.sh' >/dev/null || pgrep -f 'qemu-system-x86_64' >/dev/null; }; then
  echo "⚠  Ya hay un run/qemu activo (arrancar otro chocaría con el write-lock de sotfs.img):" >&2
  pgrep -af 'baremetal-rerun\.sh|qemu-system-x86_64' | sed 's/^/    /' >&2
  echo "   Espera a que termine (mira: tools/eval/baremetal-watch.sh) o usa --force." >&2
  exit 2
fi

# NO `sudo` wrapper — the harness runs as the invoking user (build + QEMU must NOT run as root;
# the harness sudo's only the sysfs knobs, prompting once in this pane).
RUN_CMD="PIN_CORES='$PIN_CORES' SOAK_DURATION='$SOAK_DURATION' tools/eval/baremetal-rerun.sh ${EXTRA[*]:-}"

# Pane 0 (arriba): el harness.  Queda un shell vivo al terminar para leer el resumen.
tmux new-session -d -s "$SESSION" -c "$REPO" \
  "echo '== HARNESS ==  PIN_CORES=$PIN_CORES  SOAK_DURATION=${SOAK_DURATION}s'; echo; \
   $RUN_CMD; ec=\$?; echo; echo \"[harness terminó (rc=\$ec) · resumen en tools/eval/baremetal-*/summary.txt · Ctrl-b d para salir]\"; exec bash"

# Pane 1 (abajo, 24 filas, ancho completo): el dashboard.
tmux split-window -v -l 24 -t "$SESSION" -c "$REPO" "tools/eval/baremetal-watch.sh $WATCH_INT"

tmux set-option -t "$SESSION" mouse on >/dev/null 2>&1 || true
tmux select-pane -t "$SESSION":0.0     # foco en el harness para teclear la pass de sudo

echo "tmux '$SESSION' lanzado (HARNESS arriba · DASHBOARD abajo)."
if [ -t 1 ]; then exec tmux attach -t "$SESSION"
else echo "No hay tty aquí — adjunta en tu terminal con:  tmux attach -t $SESSION"; fi
