#!/usr/bin/env bash
# sotOs · GRAPHICAL-path gate · the off-the-shelf gtk3-demo under the FULL
# interactive window stack (virtio-gpu scanout + virtio-keyboard + virtio-tablet).
#
# WHY THIS EXISTS (the gap the headless gtk-gate could not see):
# The headless gtk-gate boots `-display none` with NO virtio-gpu and NO pointer
# device, so the auto-demo's gtk3-demo only ever loads its DEFAULT cursor — its
# cursor wl_shm pool never grows.  The interactive graphical path is different:
# a virtio-tablet feeds synthetic pointer motion, GTK loads several named cursors
# (text/hand/…), and libwayland-cursor GROWS its shared cursor pool in place
# (ftruncate + wl_shm_pool.resize, doubling: 4096 -> 8832 -> 18624 …).  The
# compositor used to treat wl_shm_pool.resize as a no-op, so a later create_buffer
# at the grown offset (e.g. off=9600) tripped a stale-`pool=4096` out-of-pool
# bounds EPROTO -> "Error flushing display: Protocol error" -> exit_group(1).
# Fixed by honoring resize in the compositor's o->size (src/wayland-compositor).
#
# This drives the EXACT operator scenario WITHOUT a host window: HMP `sendkey`
# (monitor over a unix socket) presses F12 -> operator console, types `gtk3-demo`,
# and lets it render.  PASS iff gtk3-demo renders its 852x699 window repeatedly,
# the cursor pool resizes, and NO out-of-bounds / EPROTO / protocol error / fault.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-gtk3win-serial.log
MON=/tmp/sotos-gtk3win-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[gtk3win] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[gtk3win] missing $t · run 'just build'"; exit 2; }; done
rm -f "$SLOG" "$MON"; : > "$SLOG"

# HMP monitor send helper · portable AF_UNIX write via python3.
mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[gtk3win] booting headless · virtio-gpu+keyboard+tablet · monitor=$MON (~4min)…"
timeout 260 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

# 1) interactive boot (keyboard present → canary shell, demo skipped)
waitfor 'busybox canary shell' 110 || { echo "[gtk3win] FAIL · never reached interactive boot"; tail -5 "$SLOG"; exit 1; }
sleep 3
# 2) F12 → operator console, type the command
echo "[gtk3win] canary shell up · F12 → operator console"
mon "sendkey f12"; sleep 2
waitfor 'OPERATOR CONSOLE' 15 || echo "[gtk3win] WARN · operator console banner not seen (continuing)"
sleep 1
echo "[gtk3win] typing 'gtk3-demo'…"
for k in g t k 3 minus d e m o; do mon "sendkey $k"; sleep 0.2; done
mon "sendkey ret"
# 3) let it render
waitfor 'spawned gtk3-demo' 40 || echo "[gtk3win] WARN · gtk3-demo spawn marker not seen yet"
echo "[gtk3win] launched · rendering ~55s…"
sleep 55

# 4) verdict
echo "=== gtk3-demo · GRAPHICAL window path ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
sge(){ LC_ALL=C grep -acE "$1" "$SLOG"; }

[ "$(sg '\[gtk3-demo\] spawned gtk3-demo.bin')" -ge 1 ] \
  && echo "PASS · off-the-shelf gtk3-demo spawned from the operator console" \
  || { echo "FAIL · gtk3-demo did not spawn"; fail=1; }

ncommit=$(sge '\[wl-compositor\] commit .*852x699')
[ "${ncommit:-0}" -ge 5 ] \
  && echo "PASS · ${ncommit} gtk3-demo 852x699 commits over wl_shm (window rendered repeatedly)" \
  || { echo "FAIL · only ${ncommit:-0} gtk3-demo 852x699 commits"; fail=1; }

# the bug-of-record · libwayland-cursor grows its cursor pool (ftruncate + resize);
# the compositor must follow o->size or a create_buffer at the grown offset EPROTOs.
nresize=$(sg '\[wl-compositor\] pool resize')
[ "${nresize:-0}" -ge 1 ] \
  && echo "PASS · ${nresize} wl_shm_pool.resize tracked (cursor pool grew · the graphical path exercised)" \
  || echo "WARN · no pool resize seen (cursor set may have fit the initial pool this run)"

{ [ "$(sg 'out of pool bounds')" -eq 0 ] && [ "$(sg 'EPROTO')" -eq 0 ] \
  && [ "$(sg 'Protocol error')" -eq 0 ] && [ "$(sg 'Error flushing display')" -eq 0 ]; } \
  && echo "PASS · no out-of-pool-bounds / EPROTO / protocol error (resize bug fixed)" \
  || { echo "FAIL · create_buffer out-of-pool-bounds / protocol error (resize not honored?)"; fail=1; }

{ [ "$(sg 'CapFault')" -eq 0 ] && [ "$(sg 'FAULT UserException')" -eq 0 ] \
  && [ "$(sg 'code=139')" -eq 0 ] && [ "$(sg 'Invocation of invalid cap')" -eq 0 ]; } \
  && echo "PASS · no cap/VM/User fault (clean graphical run)" \
  || { echo "FAIL · fault detected during the graphical gtk3-demo run"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'GTK3-DEMO WINDOW (graphical): PASS' || echo 'GTK3-DEMO WINDOW (graphical): FAIL' ) ==="
echo "(serial: $SLOG)"
kill $QPID 2>/dev/null; rm -f "$MON"
exit $fail
