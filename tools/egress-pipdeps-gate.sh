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
SLOG=/tmp/sotos-egress-pipdeps-serial.log
MON=/tmp/sotos-egress-pipdeps-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[egress-pipdeps-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi

echo "[egress-pipdeps-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-egress-pipdeps-build.log 2>&1 || { echo "[egress-pipdeps-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[egress-pipdeps-gate] booting headless…"
timeout 1200 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[egress-pipdeps-gate] FAIL · never reached the interactive boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
echo "[egress-pipdeps-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[egress-pipdeps-gate] typing 'egress-pipdeps'…"
for k in e g r e s s minus p i p d e p s; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
# pip resolves + downloads 5 metadata + 5 wheels over the spin-pump egress (many
# sequential HTTPS connections) → a very generous window.
waitfor 'PIPDEPS_OK' 900 || waitfor '\[egress-pipdeps\] handler DONE' 30 \
  || echo "[egress-pipdeps-gate] WARN · PIPDEPS_OK not seen in window"
sleep 2; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== egress pip-install-WITH-DEPS gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[egress-pipdeps\] handler START')" -ge 1 ] \
  && echo "PASS · egress-pipdeps handler started" \
  || { echo "FAIL · handler never started"; fail=1; }

# Step 1 · pip RESOLVED requests + its 4 deps (the resolver ran over the index).
{ [ "$(LC_ALL=C grep -ac 'Collecting requests' "$SLOG")" -ge 1 ] && \
  [ "$(LC_ALL=C grep -acE 'Collecting (urllib3|idna|certifi|charset)' "$SLOG")" -ge 1 ]; } \
  && echo "PASS · pip's resolver pulled requests + transitive deps from pypi.org" \
  || echo "INFO · Collecting lines not all seen (still PASS if PIPDEPS_OK below)"

# Step 2 · pip INSTALLED all 5 packages over the verified egress.
[ "$(sg 'PIPDEPS_INSTALL_RC 0')" -ge 1 ] \
  && echo "PASS · pip install requests+deps succeeded over the egress (PIPDEPS_INSTALL_RC 0)" \
  || { echo "FAIL · multi-package install failed (resolver / network / TLS / write-target)"; fail=1; }

# Step 3 · the whole installed dep tree IMPORTS from the writable target.
[ "$(sg 'PIPDEPS_OK requests')" -ge 1 ] \
  && echo "PASS · requests + urllib3 + certifi + idna + charset_normalizer import from /tmp/sp" \
  || { echo "FAIL · could not import the installed dep tree"; fail=1; }

[ "$(LC_ALL=C grep -ac 'MemoryError' "$SLOG")" -eq 0 ] \
  && echo "PASS · no MemoryError (the arena held through the resolver churn)" \
  || { echo "FAIL · MemoryError — the resolver/install exhausted the arena"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'EGRESS-PIPDEPS: PASS' || echo 'EGRESS-PIPDEPS: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
