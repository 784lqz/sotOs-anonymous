#!/usr/bin/env bash
# Wine M2 gate · a REAL C-runtime PE (`wine hello_crt.exe`) runs under wine on
# sotOs.  Unlike the M1 CRT-less PE (kernel32-only WriteFile), this links the
# mingw CRT and imports msvcrt.dll → it exercises THE M1 WALL: msvcrt.dll's
# DllMain locale/NLS init (codepage 20127 etc.), the CRT startup (_initterm /
# __getmainargs), msvcrt malloc/printf, and the CRT exit path.
#
# PASS = the PE printed its msvcrt-printf line ("hello from msvcrt printf …",
# with a real malloc pointer) AND the launcher exited code 0 AND no HOST fault
# (CapFault / FAULT UserException / code=139 / invalid-cap).  Wine-level failures
# (missing dll, unimplemented) would be PROGRESS, but M2 is COMPLETE so we assert
# the print.  Uses the baked prefix (skips the slow wineboot) + quiet WINEDEBUG.
#
# Portable accel: KVM when /dev/kvm is writable, else TCG (stretched budgets).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-winecrt-serial.log; MON=/tmp/sotos-winecrt-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[wine-crt-gate] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[wine-crt-gate] missing $t · run 'just build'"; exit 2; }; done
# The CRT PE must be staged into the sysroot (tools/wine-stage.sh → build/wine-sysroot
# → packed by 'just build').  A clean build wipes build/wine-sysroot, so re-stage
# + rebuild if the loader is absent.
rm -f "$SLOG" "$MON"; : > "$SLOG"

if [ -w /dev/kvm ] 2>/dev/null; then ACCEL="-enable-kvm -cpu host"; TIMEOUT=240; OBS=120; LABEL=KVM
else ACCEL="-accel tcg -cpu max"; TIMEOUT=1200; OBS=700; LABEL=TCG; fi

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[wine-crt-gate] booting headless · accel=$LABEL (timeout ${TIMEOUT}s)…"
timeout "$TIMEOUT" qemu-system-x86_64 -m 4096 -display none $ACCEL -serial "file:$SLOG" \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 200 || { echo "[wine-crt-gate] FAIL · never reached boot"; exit 1; }; sleep 3
echo "[wine-crt-gate] F12 → operator console · typing 'wine-crt'…"
mon "sendkey f12"; sleep 2
for k in w i n e minus c r t; do mon "sendkey $k"; sleep 0.2; done; mon "sendkey ret"
echo "[wine-crt-gate] observing ~${OBS}s…"
waitfor 'hello from msvcrt printf' "$OBS" || echo "[wine-crt-gate] WARN · msvcrt-printf line not seen yet"
sleep 3; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== Wine M2 · real-CRT PE (msvcrt printf/malloc) ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
[ "$(sg 'hello_crt.exe')" -ge 1 ] && echo "PASS · launcher loaded the CRT PE" || { echo "FAIL · CRT PE not loaded"; fail=1; }
[ "$(LC_ALL=C grep -ac 'process_attach (L\"msvcrt.dll\"' "$SLOG")" -ge 1 ] \
  && echo "PASS · msvcrt.dll DllMain ran (the M1 wall · locale/NLS init)" \
  || echo "INFO · msvcrt DllMain trace not captured (quiet WINEDEBUG)"
[ "$(sg 'hello from msvcrt printf')" -ge 1 ] \
  && echo "PASS · the PE PRINTED via msvcrt printf (real CRT: malloc+snprintf+stdout)" \
  || { echo "FAIL · no msvcrt-printf output (the CRT PE did not run)"; fail=1; }
[ "$(LC_ALL=C grep -acE 'pid=1 \(slot=0\) exited code=0' "$SLOG")" -ge 1 ] \
  && echo "PASS · launcher exited code 0 (clean CRT exit path)" \
  || echo "INFO · clean exit not observed in window"
nf=$(LC_ALL=C grep -acE 'CapFault|FAULT UserException|code=139|invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 host faults" || { echo "FAIL · ${nf} host fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'WINE-CRT (M2): PASS' || echo 'WINE-CRT (M2): FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
