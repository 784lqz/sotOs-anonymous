#!/usr/bin/env bash
# Doom Phase 1a gate: boot (the auto-demo runs `doom`), assert the WAD loads,
# the engine inits, frames present (counter advances + fnv1a changes = a moving
# demo), and a PPM is dumped. Decodes the PPM → /tmp/doom-title.ppm for eyeball.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-doom-serial.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[doom-gate] BLOCKED: operator QEMU live"; exit 3; fi
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # demo is lean-skipped · build the full battery (restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do [ -f "$t" ] || { echo "[doom-gate] missing $t · run 'just build'"; exit 2; }; done
rm -f "$SLOG"
echo "[doom-gate] booting (auto-demo runs doom late · ~250s)..."
timeout 260 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  < /dev/null > "$SLOG" 2>&1 || true
echo "=== DOOM PHASE-1a gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
[ "$(LC_ALL=C grep -aci 'adding /doom1.wad\|W_Init' "$SLOG")" -ge 1 ] && echo "PASS · WAD loaded (POSIX file I/O over the binstore VFS)" || { echo "FAIL · WAD not loaded"; fail=1; }
# engine-init marker: doomgeneric prints "I_InitGraphics"; Chocolate Doom prints
# "I_Init: Setting up machine state." + "R_Init: Init DOOM refresh daemon".
[ "$(LC_ALL=C grep -aci 'I_InitGraphics\|I_Init: Setting up machine state\|R_Init: Init DOOM refresh daemon' "$SLOG")" -ge 1 ] && echo "PASS · engine init (Z/V/W/R/P/S_Init + graphics)" || { echo "FAIL · engine did not init"; fail=1; }
nframes=$(LC_ALL=C grep -aoE '\[doom\] frame=[0-9]+' "$SLOG" | sed -E 's/.*=//' | sort -n | tail -1)
[ "${nframes:-0}" -ge 100 ] && echo "PASS · ${nframes} frames presented (the render loop ran)" || { echo "FAIL · only ${nframes:-0} frames"; fail=1; }
uniqhash=$(LC_ALL=C grep -aoE 'fnv1a=0x[0-9a-f]+' "$SLOG" | sort -u | wc -l)
[ "$uniqhash" -ge 5 ] && echo "PASS · ${uniqhash} distinct frame hashes (a MOVING demo, not a blank/static buffer)" || { echo "FAIL · only ${uniqhash} distinct hashes"; fail=1; }
[ "$(sg 'doom-shim] .* frames ticked')" -ge 1 ] && echo "PASS · clean exit ([doom-shim] frames ticked + [doom] handler DONE)" || echo "WARN · clean-exit marker not seen"
if LC_ALL=C grep -aq '\[doom-ppm-begin\]' "$SLOG"; then
  python3 tools/doom-ppm-decode.py "$SLOG" /tmp/doom-title.ppm >/dev/null 2>&1 && echo "PASS · PPM decoded → /tmp/doom-title.ppm (eyeball: it is DOOM E1M1 gameplay)" || echo "WARN · PPM block present but decode failed"
else echo "WARN · no PPM block dumped"; fi
{ [ "$(sg 'Invocation of invalid cap')" -eq 0 ] && [ "$(sg 'unhandled syscall')" -eq 0 ]; } && echo "PASS · no cap/unhandled-syscall fault" || { echo "FAIL · fault"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'DOOM PHASE-1a: PASS' || echo 'DOOM PHASE-1a: FAIL' ) ==="
echo "(serial: $SLOG · ppm: /tmp/doom-title.ppm)"; exit $fail
