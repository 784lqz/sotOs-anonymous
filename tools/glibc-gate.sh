#!/usr/bin/env bash
# compat-host gate · a glibc-static binary (real GNU/glibc libc, NOT musl) runs
# on sotOs.
#
# The auto-demo runs `glibc` EARLY (after mapfixed, before gitdemo): orch spawns
# glibc-probe (statically-linked against glibc) at Tier-0.  The probe exercises
# real glibc library code — stdio (printf/fopen/fgets/fclose), malloc/free,
# strtol, uname, getpid — and reads the honey /etc/passwd.  PASS = the probe
# prints all its lines + "DONE glibc runs on sotOs", 0 faults.
#
# THE bring-up fix this gate guards: static binaries now get a correct AT_PHNUM
# in the auxv (was hardcoded 0).  musl-static tolerated 0 (it finds PT_TLS via
# __ehdr_start); glibc-static walks AT_PHDR/AT_PHNUM to set up TLS and NULL-deref'd
# in _dl_allocate_tls_init with phnum=0.  (glibc-DYNAMIC, needing the ld-linux
# loader, is the next arc.)
#
# Boots in the background and stops the VM as soon as `[glibc] handler DONE`
# appears — glibc runs early (~3s under KVM), so the gate is fast.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-glibc-gate-serial.log

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[glibc-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3; fi
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # demo is lean-skipped · build the full battery (restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[glibc-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG"; : > "$SLOG"

echo "[glibc-gate] booting headless (auto-demo runs glibc early)…"
timeout 200 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null; demo_lean_restore' EXIT

waited=0
for i in $(seq 1 160); do
  LC_ALL=C grep -qa '\[glibc\] handler DONE' "$SLOG" && { waited=$i; break; }
  sleep 1; waited=$i
done
echo "[glibc-gate] glibc settled after ${waited}s ($(wc -l < "$SLOG") serial lines)"
sleep 1
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== compat-host · glibc-on-sotOs gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[glibc\] glibc-probe found via binstore')" -ge 1 ] \
  && echo "PASS · glibc-static probe loaded from the binstore" \
  || { echo "FAIL · glibc-probe not found (staging?)"; fail=1; }

# Real glibc library calls produced output (NOT musl).
[ "$(sg '\[glibc-probe\] hello from glibc-static')" -ge 1 ] \
  && echo "PASS · glibc CRT + stdio ran (printf)" \
  || { echo "FAIL · glibc-probe produced no output (TLS/startup crash?)"; fail=1; }

{ [ "$(sg '\[glibc-probe\] malloc+strcpy OK')" -ge 1 ] && [ "$(sg '\[glibc-probe\] strtol=12345')" -ge 1 ]; } \
  && echo "PASS · glibc malloc/free + strtol work" \
  || { echo "FAIL · glibc malloc/strtol"; fail=1; }

[ "$(sg '\[glibc-probe\] uname Linux')" -ge 1 ] \
  && echo "PASS · glibc uname() returns the Alpine persona" \
  || { echo "FAIL · glibc uname"; fail=1; }

# glibc stdio fopen/fgets read a real file (the honey /etc/passwd).
[ "$(sg '\[glibc-probe\] /etc/passwd: root:x:0:0')" -ge 1 ] \
  && echo "PASS · glibc fopen/fgets read /etc/passwd (honey served to glibc stdio)" \
  || { echo "FAIL · glibc fopen/fgets"; fail=1; }

[ "$(sg '\[glibc-probe\] DONE glibc runs on sotOs')" -ge 1 ] \
  && echo "PASS · probe ran to completion + clean exit" \
  || { echo "FAIL · probe did not finish"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|Invocation of invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] \
  && echo "PASS · 0 faults across the glibc run" \
  || { echo "FAIL · ${nf} fault(s) in the boot"; fail=1; }

# Regression · the sibling static binary that runs right before glibc stays green.
[ "$(sg '\[mapfixed\] ALL PASS')" -ge 1 ] \
  && echo "PASS · regression · mapfixed (static, AT_PHNUM change) ALL PASS" \
  || echo "WARN · mapfixed marker not seen (boot window / ordering)"

echo "=== $( [ $fail -eq 0 ] && echo 'GLIBC-ON-sotOs: PASS' || echo 'GLIBC-ON-sotOs: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
