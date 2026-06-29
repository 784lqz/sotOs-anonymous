#!/usr/bin/env bash
# sotOs · attacker-python canary-shell gate.
#
# Boots the interactive (virtio-gpu + keyboard) config headless with a QMP
# socket, types `python3 -c "print(40+2)"` into the bbsh canary shell over the
# virtio-keyboard, and asserts the DECEPTION invariant: an attacker who runs
# python in the canary shell gets REAL CPython, contained.
#   - execve('python') is intercepted → orch spawns python3.12-static
#   - it lands in a fresh HEAVY arena (24 MiB ELF > 16 MiB threshold)
#   - CPython prints 42 to the console the attacker is watching
#   - it exits cleanly + the heavy arena is revoked (no leak)
#   - the bbsh survives (back at the prompt) + no fault/abort
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[py-canary-gate] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[py-canary-gate] missing $t · run 'just build'"; exit 2; }; done

SLOG=/tmp/sotos-pycanary-serial.log
SOCK=/tmp/sotos-pycanary-qmp.sock
rm -f "$SLOG" "$SOCK"

timeout 220 qemu-system-x86_64 -m 4096 -display none -vga none -serial "file:$SLOG" \
    -qmp "unix:$SOCK,server,nowait" -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci </dev/null >/dev/null 2>&1 &
QPID=$!

python3 tools/python-canary-probe.py "$SOCK" "$SLOG" 'python3 -c "print(40+2)"' >/dev/null 2>&1

kill $QPID 2>/dev/null; wait $QPID 2>/dev/null

sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
fail=0
echo "=== attacker-python canary gate ==="
chk(){ if [ "$(sg "$2")" -ge 1 ]; then echo "PASS · $1";
       else echo "FAIL · $1"; fail=1; fi; }

chk "execve('python') intercepted"        "\[execve\].*python.*request orch CPython"
chk "CPython spawned into heavy arena"     "\[arena\] heavy acquire"
chk "spawn succeeded (rc=0)"               "\[python\] (canary) spawn rc=0"
chk "python-stdlib mount served"           "\[python-stdlib\] mount installed"
# The marquee: real CPython evaluated 40+2 and printed 42 to the console.
if LC_ALL=C grep -aq "guest:.* 42" "$SLOG" || LC_ALL=C grep -aqE '(^|[^0-9])42([^0-9]|$)' <(LC_ALL=C grep -a "guest:" "$SLOG"); then
    echo "PASS · CPython printed 42 (real interpreter output)";
else echo "FAIL · CPython printed 42 (real interpreter output)"; fail=1; fi
chk "heavy arena revoked (no leak)"        "\[arena\] heavy revoke"

[ "$(sg 'Invocation of invalid cap')" -eq 0 ] && [ "$(sg 'root server abort')" -eq 0 ] \
    && echo "PASS · no cap fault / abort" || { echo "FAIL · fault/abort"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'ATTACKER-PYTHON: PASS' || echo 'ATTACKER-PYTHON: FAIL' ) ==="
echo "(serial: $SLOG)"
exit $fail
