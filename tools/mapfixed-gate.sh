#!/usr/bin/env bash
# sotOs · Wine-prep gate · MAP_FIXED low-address reservation + commit semantics.
#
# The wine-preloader RESERVES the Windows low address ranges (DOS area + ~1.7 GiB
# low + a high top-down window) with large PROT_NONE MAP_FIXED mmaps BEFORE the PE
# loader runs, then COMMITs sub-ranges (MAP_FIXED with real prot, or mprotect).
# This is the first ❌ in docs/wine-spike.md's prerequisite table.  This gate runs
# mapfixed.bin — that exact pattern, decoupled from the Wine swamp — and asserts:
#   • a large PROT_NONE mmap reserves an address range frame-less (no arena blowup)
#   • a MAP_FIXED RW mmap commits + is writable INSIDE the reservation
#   • mprotect-to-accessible commits a page INSIDE the reservation (reserve-then-
#     commit pattern)
#   • a non-fixed anon mmap lands OUTSIDE the reservation (high-water skips it)
#   • a direct low MAP_FIXED at the DOS base (0x10000) maps
#   • zero faults
# The auto-demo runs `mapfixed` early (before bbsh) so the markers land in the
# headless boot window.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-mapfixed-serial.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[mapfixed-gate] BLOCKED: operator QEMU live"; exit 3; fi
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # demo is lean-skipped · build the full battery (restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[mapfixed-gate] missing $t · run 'just build'"; exit 2; }; done
rm -f "$SLOG"
echo "[mapfixed-gate] booting (auto-demo runs mapfixed early · ~150s)..."
timeout 170 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  < /dev/null > "$SLOG" 2>&1 || true

echo "=== Wine-prep · MAP_FIXED-low gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[mapfixed\] spawned mapfixed.bin')" -ge 1 ] \
  && echo "PASS · mapfixed.bin spawned (the preloader mmap pattern, Tier-0)" \
  || { echo "FAIL · mapfixed did not spawn"; fail=1; }

[ "$(sg '\[mapfixed\] reserve-low OK')" -ge 1 ] \
  && echo "PASS · large PROT_NONE reserve honored (frame-less Windows low range)" \
  || { echo "FAIL · PROT_NONE reservation"; fail=1; }
# the orch-side proof it was frame-less, not 256 MiB of frames
[ "$(sg '\[mmap\].*RESERVE.*frame-less')" -ge 1 ] \
  && echo "PASS · LucAs recorded a frame-less reservation (no arena blowup)" \
  || echo "WARN · no [mmap] RESERVE marker (size threshold / path?)"

[ "$(sg '\[mapfixed\] commit-fixed RW')" -ge 1 ] \
  && echo "PASS · MAP_FIXED RW commit INSIDE the reservation + write/read verified" \
  || { echo "FAIL · MAP_FIXED commit inside reservation"; fail=1; }

[ "$(sg '\[mapfixed\] mprotect-commit')" -ge 1 ] \
  && echo "PASS · mprotect-to-accessible commit (reserve-then-commit pattern)" \
  || { echo "FAIL · mprotect commit inside reservation"; fail=1; }

[ "$(sg '\[mapfixed\] anon-outside')" -ge 1 ] \
  && echo "PASS · non-fixed anon mmap landed OUTSIDE the reservation (high-water skip)" \
  || { echo "FAIL · anon mmap collided with the reservation"; fail=1; }

[ "$(sg '\[mapfixed\] dos-fixed @0x10000 OK')" -ge 1 ] \
  && echo "PASS · direct low MAP_FIXED at the DOS base (0x10000) maps" \
  || { echo "FAIL · low DOS-base MAP_FIXED"; fail=1; }

[ "$(sg '\[mapfixed\] ALL PASS')" -ge 1 ] \
  && echo "PASS · mapfixed reported ALL PASS + exited clean" \
  || { echo "FAIL · mapfixed did not reach ALL PASS"; fail=1; }

{ [ "$(sg 'CapFault')" -eq 0 ] && [ "$(sg 'FAULT UserException')" -eq 0 ] \
  && [ "$(sg 'FAULT VMFault')" -eq 0 ] && [ "$(sg 'code=139')" -eq 0 ] \
  && [ "$(sg 'Invocation of invalid cap')" -eq 0 ]; } \
  && echo "PASS · no cap/VM/User fault during the mapfixed run" \
  || { echo "FAIL · fault detected"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'MAP_FIXED-LOW (Wine-prep): PASS' || echo 'MAP_FIXED-LOW (Wine-prep): FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
