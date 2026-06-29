#!/usr/bin/env bash
# grab-inhost.sh — fully-automated REAL capture of Scenario A (in-host payload).
# Boots sotOs headless (TCG), drives the operator console via QEMU HMP sendkey to
# run `inject-script /simulated_attacker.py`, captures the live serial (both the
# malware's stdout AND the operator's [sentinel]/[functor]/[ghost]/[phantom]/[dns]
# lines), then dumps the postmortem (sotinfo / sentinel-log).  Output → arg1.
#
# This replaces the *representative* scenario-A figure text with REAL captured lines.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
OUT="${1:-build/capture-inhost-serial.log}"
MON=/tmp/sotos-cap-mon.sock
pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
sleep 1
rm -f "$OUT" "$MON"; : > "$OUT"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.15); s.close()
PY
}
# type a literal string via sendkey (maps the chars our commands use)
typestr(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
sock,path,text=sys.argv[1],sys.argv[1],sys.argv[2]
M={' ':'spc','/':'slash','-':'minus','.':'dot','_':'shift-minus',':':'shift-semicolon'}
def send(c):
    s=socket.socket(socket.AF_UNIX); s.connect(path)
    s.sendall(("sendkey "+c+"\n").encode()); time.sleep(0.12); s.close()
for ch in text:
    send(M.get(ch, ch) if not ch.isalnum() else ch)
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$OUT" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[grab] booting headless TCG…"
timeout 900 qemu-system-x86_64 -m 2048 -display none -accel tcg -cpu max \
  -serial "file:$OUT" \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QP=$!
trap 'kill $QP 2>/dev/null; rm -f "$MON"' EXIT

if ! waitfor 'busybox canary shell' 600; then
  echo "[grab] NO_SHELL within 600s · tail:"; tail -8 "$OUT"; exit 1
fi
echo "[grab] shell up · F12 → operator console"
sleep 3; mon "sendkey f12"; sleep 2
waitfor 'OPERATOR CONSOLE' 25 || echo "[grab] (console banner not seen; continuing)"
sleep 1
echo "[grab] typing: inject-script /simulated_attacker.py"
typestr "inject-script /simulated_attacker.py"; mon "sendkey ret"

# wait for the demo to complete (7/7) — Python boot + 7 stages is slow under TCG
if waitfor 'stages exercised' 360; then
  echo "[grab] demo complete"
else
  echo "[grab] (completion marker not seen in 360s — capturing partial)"
fi
sleep 4
echo "[grab] postmortem: sotinfo"
typestr "sotinfo"; mon "sendkey ret"; sleep 6
echo "[grab] postmortem: sentinel-log"
typestr "sentinel-log"; mon "sendkey ret"; sleep 6

echo "======== captured deception lines ========"
LC_ALL=C grep -anE '\[\+\]|\[\!\]|\[\*\] |sentinel-ext|functor|ghost\]|phantom|sotnet|dns\]|tier2|procd\].*PHANTOM|HONEY_READ|inject-script|sotinfo|sentinel-log|stages exercised|TIER2' "$OUT" | tail -120
echo "======== end · serial: $OUT ($(wc -l < "$OUT") lines) ========"
kill $QP 2>/dev/null; rm -f "$MON"
