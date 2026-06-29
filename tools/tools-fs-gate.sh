#!/usr/bin/env bash
# gate-tools-fs · REAL GNU tar + coreutils do a recursive-filesystem workflow.
#
# GNU bash -c drives: build a nested dir tree → `tar -cf` it → `tar -xf` it
# elsewhere (the extract recreates the nested dirs via dir-fd-relative
# openat/mkdirat — GNU tar's dirfd-openat mis-resolved to "/" before the dir-fd
# VFS support) → cat a deep file → cp -r → rm -rf.  Uncompressed tar (no gzip
# subprocess → no single-threaded pipe deadlock).  PASS = TOOLS_FS_OK + the deep
# file read back through the extracted + copied trees + 0 faults.
# NOT network-dependent · sendkey-triggered at the operator console.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-toolsfs-serial.log
MON=/tmp/sotos-toolsfs-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[tools-fs-gate] BLOCKED: operator QEMU live"; exit 3
fi

echo "[tools-fs-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-toolsfs-build.log 2>&1 || { echo "[tools-fs-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[tools-fs-gate] booting headless…"
timeout 360 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[tools-fs-gate] FAIL · never reached boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
echo "[tools-fs-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[tools-fs-gate] typing 'tools-fs'…"
for k in t o o l s minus f s; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
waitfor 'TOOLS_FS_OK' 120 || waitfor '\[tools-fs\] handler DONE' 20 \
  || echo "[tools-fs-gate] WARN · TOOLS_FS_OK not seen in window"
sleep 2; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== real-tools fs battery gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[tools-fs\] handler START')" -ge 1 ] \
  && echo "PASS · tools-fs handler started" || { echo "FAIL · handler never started"; fail=1; }

# GNU tar EXTRACTED the nested tree (the dir-fd-exercising step).
[ "$(LC_ALL=C grep -ac 'read back the deep file: deepfile-contents' "$SLOG")" -ge 1 ] \
  && echo "PASS · GNU tar -xf recreated the nested tree (deep file read back · dir-fd extract)" \
  || { echo "FAIL · nested tar extract did not produce the deep file (dir-fd extract)"; fail=1; }

# cp -r reproduced the deep file in the copy.
[ "$(LC_ALL=C grep -ac 'copy has the deep file: deepfile-contents' "$SLOG")" -ge 1 ] \
  && echo "PASS · cp -r reproduced the nested tree" \
  || { echo "FAIL · cp -r did not reproduce the deep file"; fail=1; }

# rm -rf removed the copy (scandir + unlinkat by dir-fd).
[ "$(sg 'copy removed')" -ge 1 ] \
  && echo "PASS · rm -rf removed the tree (recursive scandir+unlinkat)" \
  || { echo "FAIL · rm -rf left the tree"; fail=1; }

[ "$(sg 'TOOLS_FS_OK')" -ge 1 ] \
  && echo "PASS · the full real-tools battery completed (TOOLS_FS_OK)" \
  || { echo "FAIL · battery did not complete"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException|invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'TOOLS-FS: PASS' || echo 'TOOLS-FS: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
