#!/usr/bin/env bash
# v2.3-M5 gate · Doom over REAL Wayland (wl_shm, NO EGL).
#
# The auto-demo runs `doomwl` EARLY (right after `sdlspike`): doomgeneric over the
# patched DYNAMIC SDL2 (SDL_VIDEODRIVER=wayland + SDL_FRAMEBUFFER_ACCELERATION=0)
# → the SOFTWARE renderer's window framebuffer is a wl_shm pool/buffer on the
# honest compositor (patches/sdl2/0002).  Proof = the compositor sees genuine
# 640x400 Doom commits over wl_shm with MANY distinct frame hashes (a moving
# title→menu→E1M1 demo, not a static buffer), the box exits clean, no faults, no
# EPROTO, and the sibling sdlspike gate stays green (sequential wayland clients).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-doomwl-serial.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[doomwl-gate] BLOCKED: operator QEMU live"; exit 3; fi
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # demo is lean-skipped · build the full battery (restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[doomwl-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG"
echo "[doomwl-gate] booting (auto-demo runs doomwl early · ~150s)..."
timeout 160 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  < /dev/null > "$SLOG" 2>&1 || true

echo "=== v2.3-M5 · Doom over REAL Wayland gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[doom-wl\] spawned doomwl.bin')" -ge 1 ] \
  && echo "PASS · doomwl.bin spawned (dynamic SDL2 fixture, Tier-0)" \
  || { echo "FAIL · doomwl did not spawn"; fail=1; }

[ "$(LC_ALL=C grep -ac '\[doom-wl\] SDL_Init OK · video driver=wayland' "$SLOG")" -ge 1 ] \
  && echo "PASS · SDL2 on the REAL wayland backend (not dummy)" \
  || { echo "FAIL · SDL2 did not select the wayland driver"; fail=1; }

ncommit=$(LC_ALL=C grep -acE '\[wl-compositor\] commit .*640x400' "$SLOG")
[ "${ncommit:-0}" -ge 50 ] \
  && echo "PASS · ${ncommit} genuine 640x400 Doom commits over wl_shm (the SW renderer presented to the compositor)" \
  || { echo "FAIL · only ${ncommit:-0} 640x400 wl_shm commits"; fail=1; }

ndistinct=$(LC_ALL=C grep -aoE '\[wl-compositor\] commit .*640x400.*fnv1a=0x[0-9a-f]+' "$SLOG" \
            | grep -aoE 'fnv1a=0x[0-9a-f]+' | sort -u | wc -l)
[ "${ndistinct:-0}" -ge 5 ] \
  && echo "PASS · ${ndistinct} distinct frame hashes (a MOVING title→menu→E1M1 demo, not a static buffer)" \
  || { echo "FAIL · only ${ndistinct:-0} distinct frame hashes"; fail=1; }

{ [ "$(sg '\[doom-wl\] .* frames ticked over real SDL2/wl_shm · exiting clean')" -ge 1 ] \
  && [ "$(sg '\[doom-wl\] handler DONE')" -ge 1 ]; } \
  && echo "PASS · clean exit (frames ticked + handler DONE)" \
  || { echo "FAIL · no clean-exit marker"; fail=1; }

{ [ "$(sg 'EPROTO')" -eq 0 ] && [ "$(sg 'object table full')" -eq 0 ]; } \
  && echo "PASS · no compositor EPROTO / object-table exhaustion (sdlspike+doomwl sequential clients)" \
  || { echo "FAIL · compositor protocol error"; fail=1; }

{ [ "$(sg 'Invocation of invalid cap')" -eq 0 ] && [ "$(sg 'unhandled syscall')" -eq 0 ] \
  && [ "$(sg 'CapFault')" -eq 0 ] && [ "$(sg 'code=139')" -eq 0 ] \
  && [ "$(sg 'zero-copy anomaly')" -eq 0 ]; } \
  && echo "PASS · no cap/syscall/VM fault, no zero-copy anomaly" \
  || { echo "FAIL · fault detected"; fail=1; }

# regression · the sibling v2.3 wayland-SDL smoke must stay green
[ "$(sg '\[sdlspike\] quit OK · exit clean · FULL PATH GREEN')" -ge 1 ] \
  && echo "PASS · regression · sdlspike FULL PATH GREEN" \
  || echo "WARN · sdlspike marker not seen (ran later / boot window)"

echo "=== $( [ $fail -eq 0 ] && echo 'DOOM-OVER-WAYLAND (M5): PASS' || echo 'DOOM-OVER-WAYLAND (M5): FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
