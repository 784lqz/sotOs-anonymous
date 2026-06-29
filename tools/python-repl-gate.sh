#!/usr/bin/env bash
# gate-python-repl · interactive `python` in the bbsh canary shell — console
# FOCUS + clean exit + heavy-arena RELEASE (the OOM fix).
#
# The bug: bare `python` spawns an interactive CPython REPL (heavy box, 128 MiB).
# It used to (a) compete with busybox for the keyboard → display glitch, and
# (b) never exit (input went to busybox, not the REPL) → it held its heavy arena
# forever; 4 of those exhaust the 4-slot heavy pool → out-of-memory.
#
# This gate proves: the REPL gets keyboard FOCUS (input reaches python, not the
# shell), and typing `exit()` cleanly exits it → `[arena] heavy revoke … 128 MiB`
# (slot returned to the pool · no leak · no OOM).  Windowed (virtio-keyboard).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-pyrepl-serial.log; MON=/tmp/sotos-pyrepl-mon.sock
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[python-repl-gate] BLOCKED: qemu live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[python-repl-gate] missing $t · run 'just build'"; exit 2; }; done
rm -f "$SLOG" "$MON"; : > "$SLOG"
mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }
timeout 260 qemu-system-x86_64 -m 4096 -display none -vga none -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT
waitfor 'busybox canary shell' 150 || { echo "[python-repl-gate] FAIL boot"; exit 1; }; sleep 4
echo "[python-repl-gate] typing 'python'…"; for k in p y t h o n; do mon "sendkey $k"; sleep 0.12; done; mon "sendkey ret"
waitfor 'Python 3.1' 40 || echo "[python-repl-gate] WARN · REPL banner not seen"
sleep 2
# 'ls' typed at the REPL must reach PYTHON (NameError), proving keyboard FOCUS.
echo "[python-repl-gate] typing 'ls' (must hit the REPL, not the shell)…"; for k in l s; do mon "sendkey $k"; sleep 0.15; done; mon "sendkey ret"; sleep 2
echo "[python-repl-gate] typing 'exit()'…"; for k in e x i t; do mon "sendkey $k"; sleep 0.15; done
mon "sendkey shift-9"; sleep 0.15; mon "sendkey shift-0"; sleep 0.15; mon "sendkey ret"; sleep 5
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== python REPL focus + clean-exit gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
[ "$(sg 'argv0=python')" -ge 1 ] && echo "PASS · python REPL spawned" || { echo "FAIL · REPL did not spawn"; fail=1; }
[ "$(sg 'Python 3.1')" -ge 1 ]  && echo "PASS · REPL reached its prompt" || { echo "FAIL · REPL banner missing"; fail=1; }
# FOCUS proof: 'ls' typed at the REPL produced a python NameError (it reached
# python, not busybox — busybox would have listed files).
[ "$(LC_ALL=C grep -ac 'NameError: name' "$SLOG")" -ge 1 ] \
  && echo "PASS · keyboard FOCUS on the REPL ('ls' hit python → NameError, not the shell)" \
  || { echo "FAIL · input did not reach the REPL (focus broken)"; fail=1; }
# exit() cleanly tears the heavy box down + returns its 128 MiB arena to the pool.
[ "$(sg 'exit()')" -ge 1 ] && echo "PASS · exit() typed into the REPL" || { echo "FAIL · exit() not delivered"; fail=1; }
[ "$(LC_ALL=C grep -acE 'heavy revoke .* 128 MiB' "$SLOG")" -ge 1 ] \
  && echo "PASS · REPL exit RELEASED the 128 MiB heavy arena (no leak · no OOM)" \
  || { echo "FAIL · heavy arena NOT released on REPL exit (the leak)"; fail=1; }
nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException|invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'PYTHON-REPL: PASS' || echo 'PYTHON-REPL: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
