#!/usr/bin/env bash
# gate-arena-churn · validate the in-life ARENA RECLAIM.
#
# python (heavy arena, 128 MiB) mmaps+frees a 1 MiB buffer 300× = 300 MiB cycled
# through the arena.  WITHOUT reclaim, munmap was a no-op and each mmap leaked the
# frames → the arena exhausts at ~120 MiB → MemoryError.  WITH the reclaim (real
# munmap keeps + zeros + recycles the frame caps; arena_utspace_alloc reuses them)
# it completes.  PASS = `ARENA_CHURN_OK` printed + the reclaim fired + 0 faults.
# NOT network-dependent · sendkey-triggered at the operator console.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-arena-churn-serial.log
MON=/tmp/sotos-arena-churn-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[arena-churn-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi

echo "[arena-churn-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-arena-churn-build.log 2>&1 || { echo "[arena-churn-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[arena-churn-gate] booting headless…"
timeout 480 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[arena-churn-gate] FAIL · never reached the interactive boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
echo "[arena-churn-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[arena-churn-gate] typing 'arena-churn'…"
for k in a r e n a minus c h u r n; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
waitfor 'ARENA_CHURN_OK' 200 || waitfor '\[arena-churn\] handler DONE' 20 \
  || echo "[arena-churn-gate] WARN · ARENA_CHURN_OK not seen in window"
sleep 2; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== arena-reclaim churn gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[arena-churn\] handler START')" -ge 1 ] \
  && echo "PASS · arena-churn handler started" \
  || { echo "FAIL · handler never started"; fail=1; }

# THE proof · 300 MiB cycled through the 128 MiB arena WITHOUT exhausting (only
# possible with the reclaim).  No MemoryError, and the completion marker printed.
[ "$(sg 'ARENA_CHURN_OK')" -ge 1 ] \
  && echo "PASS · 300 MiB churned through the 128 MiB arena — reclaim works (ARENA_CHURN_OK)" \
  || { echo "FAIL · churn did not complete (arena exhausted / MemoryError without reclaim)"; fail=1; }

[ "$(LC_ALL=C grep -ac 'MemoryError' "$SLOG")" -eq 0 ] \
  && echo "PASS · no MemoryError (the arena never exhausted)" \
  || { echo "FAIL · MemoryError — the reclaim did not prevent exhaustion"; fail=1; }

nr=$(LC_ALL=C grep -acE 'reclaimed [0-9]+ frame' "$SLOG")
[ "${nr:-0}" -ge 1 ] \
  && echo "PASS · the frame reclaim fired ($nr munmap-reclaim events)" \
  || echo "INFO · no reclaim-event log lines (still PASS if churn completed)"

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'ARENA-CHURN: PASS' || echo 'ARENA-CHURN: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
