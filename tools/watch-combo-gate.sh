#!/usr/bin/env bash
# sotOs · HEADLESS repro of the `watch` + SSH-attack combo.
#
# The combo only manifests with the live operator window, which made it
# impossible to verify headless.  This drives it WITHOUT a GTK window: a
# virtio-keyboard + QEMU `sendkey` (HMP monitor over a unix socket) presses F12
# (→ operator console) and types `watch`, then a real ssh recon attacks :22.
# PASS iff the attacker still gets served (honey /etc/passwd) WHILE watch is on.
#
# This is the empirical oracle for the watch-stalls-SSH bug (stop guessing).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
PORT=18022
SLOG=/tmp/sotos-watch-combo-serial.log
CLOG=/tmp/sotos-watch-combo-client.log
MON=/tmp/sotos-watch-combo-mon.sock
ASK=/tmp/sotos-watch-askpass.sh

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[combo] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[combo] missing $t · run 'just build'"; exit 2; }; done
rm -f "$SLOG" "$CLOG" "$MON"; : > "$SLOG"

# HMP monitor send helper · portable AF_UNIX write via python3 (nc -U flags vary).
mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[combo] booting headless (virtio-gpu + virtio-keyboard + :$PORT)…"
timeout 260 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

# 1) wait for the interactive canary shell (keyboard present → bbsh-auto)
waitfor 'busybox canary shell' 90 || waitfor 'N2 inbound LISTEN' 30 || { echo "[combo] FAIL · never reached interactive boot"; exit 1; }
sleep 3
echo "[combo] canary shell up · pressing F12 → operator console"
mon "sendkey f12"; sleep 2
waitfor 'OPERATOR CONSOLE' 15 || echo "[combo] WARN · operator console banner not seen (continuing)"
sleep 1
echo "[combo] typing 'watch'…"
for k in w a t c h; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"; sleep 2
waitfor 'DECEPTION MONITOR' 15 && echo "[combo] watch ACTIVE" || echo "[combo] WARN · DECEPTION MONITOR banner not seen"
sleep 2

# 2) attack: a real ssh recon while watch is active
echo "[combo] ssh attacker (recon) while watch is live…"
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
( sleep 3; printf 'whoami\n'; sleep 2; printf 'cat /etc/passwd\n'; sleep 3; printf 'exit\n'; sleep 3 ) | \
  timeout 70 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=3 -o ConnectTimeout=20 root@127.0.0.1 > "$CLOG" 2>&1 || true
sleep 2

# 3) verdict + diagnostics
echo "=== WATCH+SSH COMBO ==="; fail=0
cg(){ LC_ALL=C grep -ac "$1" "$CLOG"; }; sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
[ "$(cg 'root:x:0:0')" -ge 1 ] && echo "PASS · attacker served the honey passwd WHILE watch is active" \
  || { echo "FAIL · attacker got no honey (banner/recon stalled under watch)"; fail=1; }
echo "--- diagnostics (serial) ---"
echo "  banner served (synth-srv SSH):   $(sg '\[synth-srv\] inbound SSH')"
echo "  inbound reply → tcp_send_data:   $(sg 'inbound reply')"
echo "  SSH cred captured:               $(sg 'SSH cred')"
echo "  canary reads:                    $(sg '\[canary\] pid=')"
echo "  retx cap fired:                  $(sg 'retx cap')"
echo "  client banner timeout:           $(cg 'banner')"
echo "=== $( [ $fail -eq 0 ] && echo 'WATCH+SSH COMBO: PASS' || echo 'WATCH+SSH COMBO: FAIL' ) ==="
echo "(serial: $SLOG · client: $CLOG)"; exit $fail
