#!/usr/bin/env bash
# sotOs · Linux-ABI regression gate.
#
# Boots the interactive (virtio-gpu + keyboard) config headless with a QMP
# socket, types a battery of Linux-ABI-exercising commands into the bbsh canary
# shell over the virtio-keyboard, and asserts the deception-ABI invariants:
#   Tier 1 · file mutations fire [abi] handlers (mkdir/chmod/symlink)
#   Tier 3 · dangerous syscalls are captured ([abi-capture] mount/chroot)
#   Tier 4 · /proc recon reads return the response_profile (cmdline)
#   ZERO ENOSYS for the implemented syscalls (the honeypot's biggest tell)
#
# Best-effort: the bbsh line-edit + DSR dance can drop a keystroke, so the gate
# types with generous settle. A missing [abi] line is a WARN; an ENOSYS leak or
# a fault is a hard FAIL.
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[abi-gate] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[abi-gate] missing $t · run 'just build'"; exit 2; }; done

SLOG=/tmp/sotos-abi-serial.log
SOCK=/tmp/sotos-abi-qmp.sock
rm -f "$SLOG" "$SOCK"

timeout 220 qemu-system-x86_64 -m 4096 -display none -vga none -serial "file:$SLOG" \
    -qmp "unix:$SOCK,server,nowait" -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci </dev/null >/dev/null 2>&1 &
QPID=$!

python3 tools/abi-shell-probe.py "$SOCK" "$SLOG" \
    "mkdir /tmp/.hax" "chmod 755 /etc/hostname" "ln -s /a /b" \
    "mount -t tmpfs t /mnt" "chroot /tmp" "cat /proc/cmdline" >/dev/null 2>&1

kill $QPID 2>/dev/null; wait $QPID 2>/dev/null

sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
fail=0; warn=0
echo "=== LINUX-ABI gate ==="
chk(){ # chk <desc> <pattern> <hard?>
    if [ "$(sg "$2")" -ge 1 ]; then echo "PASS · $1";
    elif [ "${3:-soft}" = hard ]; then echo "FAIL · $1"; fail=1;
    else echo "WARN · $1 (keystroke may have dropped)"; warn=1; fi; }

chk "Tier 1 · mkdir handler fired"       "\[abi\] mkdir"
chk "Tier 1 · chmod handler fired"       "\[abi\] chmod"
chk "Tier 1 · symlink handler fired"     "\[abi\] symlink"
chk "Tier 3 · mount captured (-EPERM)"   "\[abi-capture\] mount"
chk "Tier 3 · chroot captured (-EPERM)"  "\[abi-capture\] chroot"
chk "Tier 4 · /proc/cmdline response_profile"     "BOOT_IMAGE=/boot/vmlinuz"

# Hard invariant: ZERO ENOSYS for implemented syscalls (the honeypot tell).
leaks=$(LC_ALL=C grep -aoE "ENOSYS sysno=(58|76|82|83|84|86|88|90|92|94|132|157|161|165|176|188|235|258|260|264|265|266|268|269|316|332|435)" "$SLOG" | sort -u)
if [ -z "$leaks" ]; then echo "PASS · ZERO ENOSYS for implemented syscalls";
else echo "FAIL · ENOSYS leak: $leaks"; fail=1; fi

[ "$(sg 'Invocation of invalid cap')" -eq 0 ] && [ "$(sg 'root server abort')" -eq 0 ] \
    && echo "PASS · no cap fault / abort" || { echo "FAIL · fault/abort"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'LINUX-ABI: PASS' || echo 'LINUX-ABI: FAIL' )$( [ $warn -ne 0 ] && echo ' (with WARNs)') ==="
echo "(serial: $SLOG)"
exit $fail
