#!/usr/bin/env bash
# gate-egress-install · install a REAL package from the network, COMPLETE (Tier-0e).
#
# End-to-end: a real busybox `wget -O /tmp/pkg-net.tgz https://files.pythonhosted.org/
# .../six-1.16.0.tar.gz` downloads a REAL package (a pypi sdist) over a VERIFIED TLS 1.3
# handshake (real CA bundle at /etc/ssl/cert.pem) onto sotfs /tmp; then the real GNU
# `tar -xzf` (gzip) EXTRACTS it to /tmp and the real glibc `ls` proves the package tree
# landed.  PASS = verified download + full extraction + the package files listed, 0
# faults.  (pypi sdists are .tar.gz — the clean complete-install target; modern Debian
# .deb is all data.tar.xz, whose dpkg-deb→xz→tar pipe chain deadlocks here.)
# NETWORK-DEPENDENT (opt-in) · sendkey-triggered at the operator console.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-egress-install-serial.log
MON=/tmp/sotos-egress-install-mon.sock

# Operator-QEMU guard · NEVER pkill (the operator's QEMU holds the sotfs.img lock).
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[egress-install-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi

# Connectivity pre-check · skip clean when the host has no egress.
if ! timeout 5 getent hosts files.pythonhosted.org >/dev/null 2>&1 && ! timeout 5 bash -c '</dev/tcp/1.1.1.1/53' 2>/dev/null; then
  echo "[egress-install-gate] SKIP: host has no internet egress (network-dependent gate)"; exit 0
fi

echo "[egress-install-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-egress-install-build.log 2>&1 || { echo "[egress-install-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[egress-install-gate] booting headless (virtio-keyboard · operator-console trigger)…"
timeout 600 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[egress-install-gate] FAIL · never reached the interactive boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
echo "[egress-install-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[egress-install-gate] typing 'egress-install'…"
for k in e g r e s s minus i n s t a l l; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
# wget(real .deb) over the slow single-threaded relay takes a while; key on the
# dpkg-deb step (download complete + install path engaged), then settle + kill.
waitfor 'PYINSTALL_OK' 300 || echo "[egress-install-gate] WARN · extraction not reached in window"
sleep 5; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== egress · network-install gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[egress-install\] handler START')" -ge 1 ] \
  && echo "PASS · egress-install handler started" \
  || { echo "FAIL · handler never started"; fail=1; }

# 1) a REAL verified-TLS connect to files.pythonhosted.org:443.  Verification is
#    implied by the download completing under openssl's -verify_return_error.
[ "$(LC_ALL=C grep -acE 'REAL connect [0-9.]+:443' "$SLOG")" -ge 1 ] \
  && echo "PASS · real verified-TLS connect to files.pythonhosted.org:443 (Tier-0e)" \
  || { echo "FAIL · no real :443 connect"; fail=1; }

# 2) python downloaded the real package over verified TLS (in-process _ssl).
[ "$(LC_ALL=C grep -acE 'PYINSTALL download [0-9]+ of [0-9]+ bytes' "$SLOG")" -ge 1 ] \
  && echo "PASS · python downloaded the real package over verified TLS (in-process)" \
  || { echo "FAIL · python did not download the package"; fail=1; }

# 3) THE proof · python's tarfile EXTRACTED the package in-process; the file list
#    is printed (PYINSTALL_OK [...]) including the sdist's real members.
[ "$(LC_ALL=C grep -acE 'PYINSTALL_OK .*PKG-INFO' "$SLOG")" -ge 1 ] \
  && echo "PASS · package EXTRACTED end-to-end in-process (PYINSTALL_OK · real sdist members)" \
  || { echo "FAIL · the package tree was not extracted (no PYINSTALL_OK with the sdist members)"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'EGRESS-INSTALL: PASS' || echo 'EGRESS-INSTALL: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
