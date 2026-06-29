#!/usr/bin/env bash
# Phase 1b gate · disk-backed fs scales (50 MiB write/readback), df believable,
# write→simreboot→read persists.  Single virtio-blk device (data region on
# sotfs.img).
#
# The 50 MiB self-test + simreboot persist leg are HEAVY (thousands of
# virtio-blk ops, many seconds) and must NOT run in the normal boot path, or
# they would slow/timeout the clock/git/glibcdyn/tui gates.  So they are
# compiled out by default and only enabled here, via a CMake reconfigure with
# -DSOTOS_FS_GATE=ON (see src/orch/CMakeLists.txt + src/orch/fs_gate_selftest.c).
# This gate restores -DSOTOS_FS_GATE=OFF on exit so subsequent gates build the
# normal (fast) orch again.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-fs-gate-serial.log
BUILD_DIR=build
KACCEL=$(test -w /dev/kvm 2>/dev/null && echo "" || echo "-DKernelSupportPCID=OFF")

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[fs-gate] BLOCKED: operator QEMU live (sotfs.img write lock)"; exit 3
fi

# Always turn the self-test back OFF when we leave, so the next gate's build is
# the normal fast orch.  Re-link the OFF flag and rebuild orch lazily on the
# next `just build`.
restore_off() {
  if [ -d "$BUILD_DIR" ]; then
    ( cd "$BUILD_DIR" && cmake -DSOTOS_FS_GATE=OFF .. >/tmp/fs-gate-restore.log 2>&1 ) || true
  fi
}

echo "[fs-gate] reconfigure with -DSOTOS_FS_GATE=ON…"
test -d "$BUILD_DIR" || ( cd "$BUILD_DIR" 2>/dev/null || just configure )
( cd "$BUILD_DIR" && cmake -DSOTOS_FS_GATE=ON .. >/tmp/fs-gate-cfg.log 2>&1 ) \
  || { echo "[fs-gate] cmake reconfigure FAILED (see /tmp/fs-gate-cfg.log)"; restore_off; exit 2; }

echo "[fs-gate] fresh rebuild (rm sotfs.img → clean data region + WAL)…"
rm -f build/images/sotfs.img
ninja -C "$BUILD_DIR" all >/tmp/fs-gate-build.log 2>&1 \
  || { echo "[fs-gate] build FAILED (see /tmp/fs-gate-build.log)"; restore_off; exit 2; }

for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[fs-gate] missing $t"; restore_off; exit 2; }; done

rm -f "$SLOG"; : > "$SLOG"
echo "[fs-gate] booting headless…"
timeout 350 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null; restore_off' EXIT
# Wait for the persist read-back marker (last thing the self-test prints), with
# a generous window (the 50 MiB write through virtio-blk RMW is slow).
for i in $(seq 1 330); do
  LC_ALL=C grep -qa 'fs-gate] persist read-back' "$SLOG" && break
  LC_ALL=C grep -qa 'fs-gate] persist read-back FAILED' "$SLOG" && break
  sleep 1
done
sleep 1; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== fs-phase1b gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
[ "$(sg 'fs-gate] scale 50MB.*MATCH')" -ge 1 ] && echo "PASS · 50 MB write+readback checksum matches" || { echo "FAIL · scale checksum"; fail=1; }
[ "$(sg 'fs-gate] df blocks=')" -ge 1 ] && echo "PASS · df reports real blkdev geometry" || { echo "FAIL · df"; fail=1; }
[ "$(sg 'fs-gate] persist read-back: SOTFS-PERSIST-OK')" -ge 1 ] && echo "PASS · write→simreboot→read persists" || { echo "FAIL · persistence"; fail=1; }
nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139' "$SLOG")
[ "$nf" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · $nf faults"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'FS-PHASE1B: PASS' || echo 'FS-PHASE1B: FAIL' ) ==="
exit $fail
