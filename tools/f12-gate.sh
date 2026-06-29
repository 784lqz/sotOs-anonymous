#!/usr/bin/env bash
# sotOs · F12 operator-console toggle gate.
#
# Boots interactive (virtio-gpu + keyboard) headless with QMP, then over the
# virtio-keyboard:
#   1. F12 in the canary shell (bbsh) → the operator console (the truth view)
#   2. types `list` → an operator-only command runs (ORCH_OP_QUERY_STATUS)
#   3. F12 in the operator console → a fresh canary shell respawns
# Asserts the toggle both ways + the operator console renders to the framebuffer
# + no synth-IPC flood (the bug this arc fixed) + no fault.
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[f12-gate] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[f12-gate] missing $t · run 'just build'"; exit 2; }; done

SLOG=/tmp/sotos-f12-serial.log
SOCK=/tmp/sotos-f12-qmp.sock
SHOT=/tmp/sotos-f12-shot.ppm
rm -f "$SLOG" "$SOCK" "$SHOT" "$SHOT.operator.ppm"

timeout 200 qemu-system-x86_64 -m 4096 -display none -vga none -serial "file:$SLOG" \
    -qmp "unix:$SOCK,server,nowait" -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci </dev/null >/dev/null 2>&1 &
QPID=$!

python3 tools/f12-probe.py "$SOCK" "$SLOG" "$SHOT" >/dev/null 2>&1

kill $QPID 2>/dev/null; wait $QPID 2>/dev/null

sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
fail=0
echo "=== F12 operator-console toggle gate ==="
chk(){ if [ "$(sg "$2")" -ge "${3:-1}" ]; then echo "PASS · $1";
       else echo "FAIL · $1"; fail=1; fi; }

chk "F12 #1 · bbsh → operator console"        "switching to operator console"
chk "operator console banner shown"           "OPERATOR CONSOLE"
chk "operator command ran (list→QUERY_STATUS)" "QUERY_STATUS served"
chk "F12 #2 · operator → canary shell respawn"  "bbsh: entering fault loop" 2

# The synth DNS_INSTALL flood this arc fixed must stay gone.
if [ "$(sg 'DNS_INSTALL domain=')" -eq 0 ]; then echo "PASS · no synth op flood";
else echo "FAIL · synth op flood resurfaced ($(sg 'DNS_INSTALL domain=') hits)"; fail=1; fi

# Serial must be sane (the flood ballooned it to ~190k lines).
lines=$(wc -l < "$SLOG")
if [ "$lines" -lt 5000 ]; then echo "PASS · serial sane ($lines lines)";
else echo "FAIL · serial bloated ($lines lines)"; fail=1; fi

[ "$(sg 'Invocation of invalid cap')" -eq 0 ] && [ "$(sg 'root server abort')" -eq 0 ] \
    && echo "PASS · no cap fault / abort" || { echo "FAIL · fault/abort"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'F12-TOGGLE: PASS' || echo 'F12-TOGGLE: FAIL' ) ==="
echo "(serial: $SLOG · operator screendump: $SHOT.operator.ppm)"
exit $fail
