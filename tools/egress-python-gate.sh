#!/usr/bin/env bash
# gate-egress-python · the pip FOUNDATION · real CPython does an HTTPS GET (Tier-0e).
#
# python3.12-static (with its statically-linked OpenSSL _ssl module) at Tier-0e does
# an IN-PROCESS TLS 1.3 handshake to https://example.com — urllib.request.urlopen →
# socket → SSL_connect → recv — VERIFYING the real server cert against the real CA
# bundle at /etc/ssl/cert.pem.  No subprocess relay: python's _ssl drives the egress
# wire directly.  PASS = the python interpreter printed PYHTTPS_OK with the real body
# length + 'Example Domain' True + status 200, 0 faults.  NETWORK-DEPENDENT (opt-in) ·
# sendkey-triggered at the operator console.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-egress-python-serial.log
MON=/tmp/sotos-egress-python-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[egress-python-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi
if ! timeout 5 getent hosts example.com >/dev/null 2>&1 && ! timeout 5 bash -c '</dev/tcp/1.1.1.1/53' 2>/dev/null; then
  echo "[egress-python-gate] SKIP: host has no internet egress (network-dependent gate)"; exit 0
fi

echo "[egress-python-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-egress-python-build.log 2>&1 || { echo "[egress-python-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[egress-python-gate] booting headless (virtio-keyboard · operator-console trigger)…"
timeout 600 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[egress-python-gate] FAIL · never reached the interactive boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
echo "[egress-python-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[egress-python-gate] typing 'egress-python'…"
for k in e g r e s s minus p y t h o n; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
waitfor 'PYHTTPS_OK' 300 || waitfor '\[egress-python\] handler DONE' 20 \
  || echo "[egress-python-gate] WARN · PYHTTPS_OK not seen in window"
sleep 3; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== egress · python HTTPS gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[egress-python\] handler START')" -ge 1 ] \
  && echo "PASS · egress-python handler started" \
  || { echo "FAIL · handler never started"; fail=1; }

[ "$(LC_ALL=C grep -acE 'REAL connect [0-9.]+:443' "$SLOG")" -ge 1 ] \
  && echo "PASS · python opened a real TLS connect to example.com:443 (Tier-0e)" \
  || { echo "FAIL · no real :443 connect from python"; fail=1; }

# THE proof · python's socket+ssl fetched the verified HTTPS body in-process:
# PYHTTPS_OK <len> True b'HTTP/1.1 200 OK'  (True = 'Example Domain' in the body).
[ "$(LC_ALL=C grep -acE "PYHTTPS_OK [0-9]+ True b'HTTP/1.1 200" "$SLOG")" -ge 1 ] \
  && echo "PASS · real CPython HTTPS GET verified the cert + fetched the body ('Example Domain', 200 OK)" \
  || { echo "FAIL · python did not complete the verified HTTPS fetch"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'EGRESS-PYTHON: PASS' || echo 'EGRESS-PYTHON: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
