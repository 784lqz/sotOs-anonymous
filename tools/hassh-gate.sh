#!/usr/bin/env bash
# sotOs · HASSH gate · the sotOs SSH server's KEXINIT must reproduce OpenSSH 9.7's
# (Alpine 3.20) byte-for-byte → identical HASSHServer.  Target captured from a real
# alpine:3.20 sshd via tools/hassh.py.  Boots sotOs headless, probes :18022, compares.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
TARGET="e42184b06d45385a906f0803d04c83da"   # OpenSSH_9.7 / Alpine 3.20 (tools/hassh.py)
PORT=18022; SLOG=/tmp/sotos-hassh-serial.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[hassh] BLOCKED: a QEMU is live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do [ -f "$t" ] || { echo "[hassh] missing $t · run just build"; exit 2; }; done
rm -f "$SLOG"
timeout 120 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::${PORT}-:22 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 90); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[hassh] FAIL · :22 never LISTENed"; exit 1; }
sleep 2
echo "=== HASSH gate (target OpenSSH_9.7 = $TARGET) ==="
OUT=$(python3 tools/hassh.py 127.0.0.1 $PORT 2>&1); echo "$OUT"
GOT=$(echo "$OUT" | awk '/HASSHServer/{print $3}')
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true
if [ "$GOT" = "$TARGET" ]; then echo "=== HASSH: PASS (== OpenSSH 9.7) ==="; exit 0
else echo "=== HASSH: FAIL (got $GOT, want $TARGET) ==="; exit 1; fi
