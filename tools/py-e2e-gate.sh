#!/usr/bin/env bash
# gate-py-e2e · a REAL CPython end-to-end program on sotOs:
#   verified-HTTPS GET example.com → parse the <title> → write the HTML + a JSON
#   sidecar (title/bytes/sha256) to /tmp/e2e → read both back → verify the sha256
#   round-trips.  Proves sotOs is a real Python compute host (egress + fs + json
#   + hashlib).  PASS = PY_E2E_OK ... roundtrip=True + 0 faults.
# NETWORK-DEPENDENT (needs live internet) · sendkey-triggered.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-pye2e-serial.log; MON=/tmp/sotos-pye2e-mon.sock
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[py-e2e-gate] BLOCKED: operator QEMU live"; exit 3; fi
echo "[py-e2e-gate] rebuilding…"; rm -f build/images/sotfs.img
just build >/tmp/sotos-pye2e-build.log 2>&1 || { echo "[py-e2e-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"
mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }
echo "[py-e2e-gate] booting headless…"
timeout 420 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT
waitfor 'busybox canary shell' 240 || { echo "[py-e2e-gate] FAIL · never reached boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
mon "sendkey f12"; sleep 2
echo "[py-e2e-gate] typing 'py-e2e'…"
for k in p y minus e 2 e; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
waitfor 'PY_E2E_OK' 300 || waitfor '\[py-e2e\] handler DONE' 30 || echo "[py-e2e-gate] WARN · PY_E2E_OK not seen"
sleep 2; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true
echo "=== python real end-to-end gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
[ "$(sg '\[py-e2e\] handler START')" -ge 1 ] && echo "PASS · py-e2e handler started" || { echo "FAIL · handler never started"; fail=1; }
[ "$(LC_ALL=C grep -ac "PY_E2E_OK title='Example Domain'" "$SLOG")" -ge 1 ] \
  && echo "PASS · HTTPS fetch + <title> parse (title='Example Domain')" \
  || { echo "FAIL · fetch/parse did not produce the expected title"; fail=1; }
[ "$(sg 'roundtrip=True')" -ge 1 ] \
  && echo "PASS · wrote HTML+JSON to /tmp/e2e, read back, sha256 round-trips (roundtrip=True)" \
  || { echo "FAIL · fs write/read-back/sha256 round-trip failed"; fail=1; }
nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException|invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'PY-E2E: PASS' || echo 'PY-E2E: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
