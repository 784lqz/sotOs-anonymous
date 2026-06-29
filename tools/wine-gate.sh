#!/usr/bin/env bash
# sotOs · Wine M1 gate · headless console PE (`wine /usr/lib/wine/hello.exe`).
#
# Wine is NOT in the auto-demo (it doesn't complete yet → would stall the headless
# boot), so this gate drives the EXACT operator scenario WITHOUT a host window: HMP
# `sendkey` (monitor over a unix socket) presses F12 → operator console, types
# `wine`, and lets the preloader→loader→ntdll→wineserver→PE chain run.
#
# CLASSIFICATION (the M1 success criterion): "if it fails, it must fail like Wine,
# not like sotOs." A Wine-level failure (missing DLL, could-not-create-prefix,
# unimplemented-syscall, registry-missing) is PROGRESS and the gate stays GREEN.
# A HOST fault — CapFault / FAULT UserException (the #GP frontier) / FAULT VMFault /
# code=139 / invalid-cap / Wayland EPROTO — is a BLOCKER and fails the gate.
#
# EXPECTED STATE BY PHASE (docs/wine-spike.md):
#   • Phase 2 (now): RED — the preloader-relaunched ld-musl #GPs (FAULT UserException
#     fsr=0xd, vector 13). The milestone ladder below shows how far the bootstrap got.
#   • Phase 3-4: GREEN as expected-fail-without-host-fault (wine reports missing
#     dll / no wineserver / unimplemented, but no host fault).
#   • Phase 5 (M1 done): GREEN + the hard assertion — hello.exe writes its string.
#
# Portable accel: real KVM when /dev/kvm is writable, else TCG software emulation
# (same detection as the justfile). Under TCG the kernel MUST be the PCID-off build
# (`just configure` sets -DKernelSupportPCID=OFF when /dev/kvm is absent), else the
# seL4 head.S pcid_check hangs the boot — this gate detects that and says so.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-wine-serial.log
MON=/tmp/sotos-wine-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[wine-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[wine-gate] missing $t · run 'just build'"; exit 2; }; done
rm -f "$SLOG" "$MON"; : > "$SLOG"

# Portable accel + budgets (TCG is ~10-20x slower than KVM, so stretch the waits).
if [ -w /dev/kvm ] 2>/dev/null; then
  ACCEL="-enable-kvm -cpu host"; TIMEOUT=320; SHELL_WAIT=120; RENDER=70; LABEL="KVM"
else
  ACCEL="-accel tcg -cpu max";   TIMEOUT=1500; SHELL_WAIT=700; RENDER=300; LABEL="TCG"
fi

# HMP monitor send helper · portable AF_UNIX write via python3.
mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[wine-gate] booting headless · accel=$LABEL · monitor=$MON (timeout ${TIMEOUT}s)…"
timeout "$TIMEOUT" qemu-system-x86_64 -m 4096 -display none $ACCEL \
  -serial "file:$SLOG" \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

# TCG sanity: if the kernel still has PCID compiled in, head.S hangs immediately.
if waitfor 'PCIDs not supported by the processor' 20; then
  echo "[wine-gate] FAIL · kernel hung at pcid_check — rebuild with -DKernelSupportPCID=OFF"
  echo "            (run 'just configure && just build' on a host without /dev/kvm)"
  exit 1
fi

# 1) interactive boot (keyboard present → canary shell, auto-demo skipped)
waitfor 'busybox canary shell' "$SHELL_WAIT" || { echo "[wine-gate] FAIL · never reached interactive boot in ${SHELL_WAIT}s"; tail -8 "$SLOG"; exit 1; }
sleep 3
# 2) F12 → operator console, type `wine`
echo "[wine-gate] canary shell up · F12 → operator console"
mon "sendkey f12"; sleep 2
waitfor 'OPERATOR CONSOLE' 20 || echo "[wine-gate] WARN · operator console banner not seen (continuing)"
sleep 1
echo "[wine-gate] typing 'wine'…"
for k in w i n e; do mon "sendkey $k"; sleep 0.2; done
mon "sendkey ret"
# 3) let the loader chain run
waitfor 'ORCH_OP_WINE' 40 || echo "[wine-gate] WARN · orch wine op marker not seen yet"
echo "[wine-gate] launched · observing ~${RENDER}s…"
sleep "$RENDER"

# 4) verdict
echo "=== Wine M1 · headless console PE ($LABEL) ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
sge(){ LC_ALL=C grep -acE "$1" "$SLOG"; }

# --- milestone ladder (INFORMATIONAL · how far the bootstrap got this run) ---
echo "--- bootstrap ladder (progress markers, not pass/fail) ---"
ladder(){ if [ "$(sg "$1")" -ge 1 ]; then echo "  reached · $2"; else echo "  ----    · $2"; fi; }
ladder 'ORCH_OP_WINE'                  'orch received the wine op'
ladder '\[orch\].*wine'                'orch spawned the wine loader'
ladder 'RESERVE'                       'preloader reserved Windows address ranges (frame-less)'
ladder 'FAULT UserException'           "ld-musl re-launch #GP (THE Phase-2 frontier)"
ladder 'pagemap'                       'ntdll touched /proc/self/pagemap'
ladder 'wineserver'                    'wineserver IPC referenced'
ladder 'builtin'                       'PE-dll closure (builtin library) referenced'

# --- HARD verdict: no host fault ---
echo "--- verdict ---"
{ [ "$(sg 'CapFault')" -eq 0 ] && [ "$(sg 'FAULT UserException')" -eq 0 ] \
  && [ "$(sg 'FAULT VMFault')" -eq 0 ] && [ "$(sg 'code=139')" -eq 0 ] \
  && [ "$(sg 'Invocation of invalid cap')" -eq 0 ] && [ "$(sg 'Error flushing display')" -eq 0 ] \
  && [ "$(sg 'EPROTO')" -eq 0 ]; } \
  && echo "PASS · no host fault (failures, if any, are Wine-level — progress)" \
  || { echo "FAIL · HOST fault detected (blocker · not a Wine-level failure)"; fail=1; }

# --- M1 hard assertion (Phase 5) · soft until then ---
if [ "$(sg 'hello from a Windows PE on sotOs')" -ge 1 ]; then
  echo "PASS · hello.exe wrote its string to stdout — *** WINE M1 COMPLETE ***"
else
  echo "INFO · hello.exe stdout not yet seen (expected until Phase 5)"
fi

echo "=== $( [ $fail -eq 0 ] && echo 'WINE M1 GATE: PASS (no host fault)' || echo 'WINE M1 GATE: FAIL (host fault)' ) ==="
echo "(serial: $SLOG)"
kill $QPID 2>/dev/null; rm -f "$MON"
exit $fail
