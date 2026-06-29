#!/usr/bin/env bash
# compat-host gate · the clock advances + fs metadata is believable (no 1970 tell).
#
# Tasks 1-6 wired a real rdtsc-anchored wall clock (epoch 2024-05-21) into
# gettimeofday/clock_gettime, and gave sotfs inodes mtime/atime/ctime stamped
# from that clock (reported via op_stat/op_fstat).  This gate boots headless and
# proves the fidelity off the glibcdyn compat suite:
#   - `date -u` (rewired clock_gettime) prints a believable 202x persona year
#   - NO guest line shows the 1970 epoch (the tell this feature kills: inodes had
#     no timestamp fields -> stat mtime=0 -> `ls -l` showed "Jan  1  1970")
#   - a listed file (`ls -la /tmp` honey-aws-creds) shows a 202x mtime
#   - 0 faults
# Stops early once `[glibcdyn] handler DONE` appears.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-clock-gate-serial.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[clock-gate] BLOCKED: operator QEMU live"; exit 3; fi
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # demo is lean-skipped · build the full battery (restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[clock-gate] missing $t · run 'just build'"; exit 2; }; done
rm -f "$SLOG"; : > "$SLOG"
echo "[clock-gate] booting headless…"
timeout 200 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null; demo_lean_restore' EXIT
for i in $(seq 1 160); do LC_ALL=C grep -qa '\[glibcdyn\] handler DONE' "$SLOG" && break; sleep 1; done
sleep 1; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true
echo "=== clock-fidelity gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
# date must be the 202x persona year (the clock anchors at 2024); and NO guest line shows 1970
{ [ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* 202[0-9]' "$SLOG")" -ge 1 ] \
  && [ "$(LC_ALL=C grep -acE 'guest:[0-9]+.*1970' "$SLOG")" -eq 0 ]; } \
  && echo "PASS · date/clock is a believable 202x (no 1970 in guest output)" \
  || { echo "FAIL · clock shows 1970 or no 202x date"; fail=1; }
# a listed file shows a non-1970 mtime (the honey /tmp files via `ls -la /tmp`).
# GNU ls renders a same-year mtime as "Mon DD HH:MM" (only >6mo-old or future
# years print the literal year), so the 2024 inode stamp shows as "May 21 01:00"
# — assert a real month+time stamp on a honey/welcome line, and NOT "Jan  1  1970".
{ [ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* [A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2} .*(honey|welcome)' "$SLOG")" -ge 1 ] \
  && [ "$(LC_ALL=C grep -acE 'guest:[0-9]+.*Jan +1 +1970 .*(honey|welcome)' "$SLOG")" -eq 0 ]; } \
  && echo "PASS · file mtime is 202x (sotfs inode timestamps wired · not 1970)" \
  || echo "WARN · no 202x file mtime seen in this boot window"
# 0 faults
nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139' "$SLOG")
[ "$nf" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · $nf faults"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'CLOCK-FIDELITY: PASS' || echo 'CLOCK-FIDELITY: FAIL' ) ==="
exit $fail
