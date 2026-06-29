#!/usr/bin/env bash
# gate-egress-pipbuild · the FULL pip install · network-install-the-tool.
#
# real CPython runs pip ITSELF (pip rides in the stdlib zip):
#   1. `pip --version`  → exercises pip's ~150-module import tree; survives the
#      128 MiB heavy arena ONLY because of the in-life FRAME RECLAIM + .pyc stdlib.
#   2. `pip install --target /tmp/sp six`  → pip resolves six on pypi.org, downloads
#      the wheel from files.pythonhosted.org over a cert-verified TLS handshake, and
#      unpacks it into the writable /tmp/sp (a real site-packages).
#   3. `import six` from /tmp/sp  → the installed package is usable.
# PASS = PIP_VERSION_RC 0 + PIP_INSTALL_RC 0 + PIP_FULL_OK six + 0 faults.
# NETWORK-DEPENDENT (needs live internet / SLIRP egress) · sendkey-triggered.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-egress-pipbuild-serial.log
MON=/tmp/sotos-egress-pipbuild-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[egress-pipbuild-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi

echo "[egress-pipbuild-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-egress-pipbuild-build.log 2>&1 || { echo "[egress-pipbuild-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[egress-pipbuild-gate] booting headless…"
timeout 780 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[egress-pipbuild-gate] FAIL · never reached the interactive boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
echo "[egress-pipbuild-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[egress-pipbuild-gate] typing 'egress-pipbuild'…"
for k in e g r e s s minus p i p b u i l d; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
# download sdist over the slow egress + the in-process setuptools build → window.
waitfor 'PIPBUILD_OK' 420 || waitfor '\[egress-pipbuild\] handler DONE' 30 \
  || echo "[egress-pipbuild-gate] WARN · PIPBUILD_OK not seen in window"
sleep 2; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== egress pip-BUILD (sdist → wheel in-process) gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[egress-pipbuild\] handler START')" -ge 1 ] \
  && echo "PASS · egress-pipbuild handler started" \
  || { echo "FAIL · handler never started"; fail=1; }

# Step 1 · the source dist (no wheel) downloaded over the verified egress.
[ "$(LC_ALL=C grep -acE 'PIPBUILD download [0-9]+ of [0-9]+ bytes verified TLS' "$SLOG")" -ge 1 ] \
  && echo "PASS · six sdist downloaded over verified HTTPS" \
  || { echo "FAIL · sdist download failed (network/TLS)"; fail=1; }

# Step 2 · the REAL setuptools/wheel build backend built the wheel IN-PROCESS.
[ "$(LC_ALL=C grep -acE 'PIPBUILD built wheel six-1.16.0-.*\.whl' "$SLOG")" -ge 1 ] \
  && echo "PASS · setuptools build_meta built the wheel in-process (no subprocess)" \
  || { echo "FAIL · in-process build_wheel failed (setuptools/wheel import or build error)"; fail=1; }

# Step 3 · the freshly-BUILT wheel installs + imports from the writable target.
[ "$(sg 'PIPBUILD_OK')" -ge 1 ] \
  && echo "PASS · the built six wheel installs to /tmp/sp + imports (PIPBUILD_OK)" \
  || { echo "FAIL · could not install/import the built wheel"; fail=1; }

[ "$(LC_ALL=C grep -ac 'MemoryError' "$SLOG")" -eq 0 ] \
  && echo "PASS · no MemoryError (the arena held through the build churn)" \
  || { echo "FAIL · MemoryError — the build exhausted the arena"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'EGRESS-PIPBUILD: PASS' || echo 'EGRESS-PIPBUILD: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
