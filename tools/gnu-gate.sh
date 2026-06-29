#!/usr/bin/env bash
# compat-host gate · real GNU tools (musl-dynamic, from Alpine) run on sotOs.
#
# The auto-demo runs `gnu` EARLY: orch spawns, each as a fresh Tier-0 sotbox,
# the real GNU userland (NOT busybox) against the honey /etc/passwd + /tmp:
#   coreutils --coreutils-prog=ls -la /tmp      (GNU coreutils 9.5)
#   coreutils --coreutils-prog=cat /etc/passwd
#   coreutils --coreutils-prog=wc  -l /etc/passwd
#   grep -c '' /etc/passwd ; grep root /etc/passwd
#   sed s/root/ROOT/g /etc/passwd
#   gawk -F: '{ print $1 }' /etc/passwd
# PASS = each tool produces correct output, 0 faults.  Their lib closure
# (libacl/libattr/libcrypto/libgmp/libskarnet/libutmps · libpcre2 shared with
# git) resolves from the sysroot via ld-musl.
#
# Boots in the background and stops as soon as `[gnu] handler DONE` appears.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-gnu-gate-serial.log

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[gnu-gate] BLOCKED: operator QEMU live"; exit 3; fi
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # demo is lean-skipped · build the full battery (restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[gnu-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG"; : > "$SLOG"

echo "[gnu-gate] booting headless (auto-demo runs gnu early)…"
timeout 200 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null; demo_lean_restore' EXIT

waited=0
for i in $(seq 1 160); do
  LC_ALL=C grep -qa '\[gnu\] handler DONE' "$SLOG" && { waited=$i; break; }
  sleep 1; waited=$i
done
echo "[gnu-gate] gnu settled after ${waited}s ($(wc -l < "$SLOG") serial lines)"
sleep 1
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== compat-host · GNU-tools-on-sotOs gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[gnu\] === GNU coreutils ls -la /tmp')" -ge 1 ] \
  && echo "PASS · GNU coreutils launched from the binstore" \
  || { echo "FAIL · GNU tools did not launch (staging?)"; fail=1; }

# GNU ls long format: a guest line with perms + one of the honey files.
[ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* -rw-r--r--.* honey-aws-creds' "$SLOG")" -ge 1 ] \
  && echo "PASS · GNU coreutils ls -la formats the /tmp listing (perms+size+name)" \
  || { echo "FAIL · GNU ls long listing"; fail=1; }

# GNU cat + wc on /etc/passwd.
[ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* root:x:0:0:root' "$SLOG")" -ge 1 ] \
  && echo "PASS · GNU coreutils cat read /etc/passwd (honey served)" \
  || { echo "FAIL · GNU cat"; fail=1; }
[ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* 2 /etc/passwd' "$SLOG")" -ge 1 ] \
  && echo "PASS · GNU coreutils wc -l counted /etc/passwd" \
  || { echo "FAIL · GNU wc"; fail=1; }

# GNU sed substitution.
[ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* ROOT:x:0:0:ROOT' "$SLOG")" -ge 1 ] \
  && echo "PASS · GNU sed s/root/ROOT/g substituted" \
  || { echo "FAIL · GNU sed"; fail=1; }

# GNU awk field extraction: prints "user=<name>" so the match is unambiguous.
{ [ "$(sg 'user=root')" -ge 1 ] && [ "$(sg 'user=appuser')" -ge 1 ]; } \
  && echo "PASS · GNU gawk -F: extracted usernames (user=root, user=appuser)" \
  || { echo "FAIL · GNU gawk"; fail=1; }

[ "$(sg '\[gnu\] handler DONE')" -ge 1 ] \
  && echo "PASS · gnu handler completed cleanly" \
  || { echo "FAIL · gnu handler did not finish"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|Invocation of invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] \
  && echo "PASS · 0 faults across the GNU-tools run" \
  || { echo "FAIL · ${nf} fault(s)"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'GNU-TOOLS-ON-sotOs: PASS' || echo 'GNU-TOOLS-ON-sotOs: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
