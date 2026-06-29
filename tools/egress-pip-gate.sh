#!/usr/bin/env bash
# gate-egress-pip · the FULL pip install · network-install-the-tool.
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
SLOG=/tmp/sotos-egress-pip-serial.log
MON=/tmp/sotos-egress-pip-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[egress-pip-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi

echo "[egress-pip-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-egress-pip-build.log 2>&1 || { echo "[egress-pip-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[egress-pip-gate] booting headless…"
timeout 780 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[egress-pip-gate] FAIL · never reached the interactive boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
echo "[egress-pip-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[egress-pip-gate] typing 'egress-pip'…"
for k in e g r e s s minus p i p; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
# pip resolves+downloads over the network (two sequential fetches via the
# spin-pump egress) → allow a generous window.
waitfor 'PIP_FULL_OK' 420 || waitfor '\[egress-pip\] handler DONE' 30 \
  || echo "[egress-pip-gate] WARN · PIP_FULL_OK not seen in window"
sleep 2; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== egress pip-install gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[egress-pip\] handler START')" -ge 1 ] \
  && echo "PASS · egress-pip handler started" \
  || { echo "FAIL · handler never started"; fail=1; }

# Step 1 · pip the tool LOADS (its heavy import tree fits the arena).
[ "$(sg 'PIP_VERSION_RC 0')" -ge 1 ] \
  && echo "PASS · pip loads + runs (PIP_VERSION_RC 0 · heavy import tree survives the arena)" \
  || { echo "FAIL · pip did not load/run (--version RC != 0 · arena OOM or import error)"; fail=1; }

# Step 2 · pip INSTALLS six from PyPI over the verified egress.
[ "$(sg 'PIP_INSTALL_RC 0')" -ge 1 ] \
  && echo "PASS · pip install six succeeded over the egress (PIP_INSTALL_RC 0)" \
  || { echo "FAIL · pip install six failed (network/resolver/TLS or write-target error)"; fail=1; }

# Step 3 · the installed package is IMPORTABLE from the writable target.
[ "$(sg 'PIP_FULL_OK six')" -ge 1 ] \
  && echo "PASS · the installed six is importable from /tmp/sp (PIP_FULL_OK)" \
  || { echo "FAIL · could not import the pip-installed six"; fail=1; }

[ "$(LC_ALL=C grep -ac 'MemoryError' "$SLOG")" -eq 0 ] \
  && echo "PASS · no MemoryError (the arena held through pip's churn)" \
  || { echo "FAIL · MemoryError — pip's import/install exhausted the arena"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'EGRESS-PIP: PASS' || echo 'EGRESS-PIP: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
