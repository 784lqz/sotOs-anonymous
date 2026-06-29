#!/usr/bin/env bash
# compat-host gate · a glibc-DYNAMIC binary runs on sotOs via the REAL glibc
# dynamic linker ld-linux-x86-64.so.2 (not ld-musl).
#
# The auto-demo runs `glibcdyn` EARLY (after glibc): orch spawns an off-the-shelf
# glibc-dynamic PIE (hello-glibc-dyn, built on debian:13-slim) at Tier-0.  sotOs
# loads the PIE, fetches its interp (/lib64/ld-linux-x86-64.so.2) from the binstore
# by basename, and lets ld-linux self-relocate, open libc.so.6 (sysroot
# /usr/lib/x86_64-linux-gnu via the /lib alias), relocate it, run init, and jump
# to the PIE — which prints via glibc stdio.  PASS = the real ld-linux interp was
# selected + "hi glibc-DYNAMIC" printed + 0 faults.
#
# This is the glibc LOADER (the conquest beyond glibc-static).  No bring-up code
# changes were needed — the loader-fetch is basename-generic and the static
# AT_PHNUM fix (gate-glibc) carries over.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-glibcdyn-gate-serial.log

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[glibcdyn-gate] BLOCKED: operator QEMU live"; exit 3; fi
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # demo is lean-skipped · build the full battery (restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[glibcdyn-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG"; : > "$SLOG"

echo "[glibcdyn-gate] booting headless (auto-demo runs glibcdyn early)…"
timeout 200 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null; demo_lean_restore' EXIT

waited=0
for i in $(seq 1 160); do
  LC_ALL=C grep -qa '\[glibcdyn\] handler DONE' "$SLOG" && { waited=$i; break; }
  sleep 1; waited=$i
done
echo "[glibcdyn-gate] glibcdyn settled after ${waited}s ($(wc -l < "$SLOG") serial lines)"
sleep 1
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== compat-host · glibc-DYNAMIC-on-sotOs gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[glibcdyn\] hello-glibc-dyn found via binstore')" -ge 1 ] \
  && echo "PASS · glibc-dynamic PIE loaded from the binstore" \
  || { echo "FAIL · hello-glibc-dyn not found (staging?)"; fail=1; }

# The REAL glibc dynamic linker was selected (not ld-musl).
[ "$(sg "interp='/lib64/ld-linux-x86-64.so.2'")" -ge 1 ] \
  && echo "PASS · sotOs selected the real ld-linux-x86-64.so.2 interp" \
  || { echo "FAIL · ld-linux interp not selected"; fail=1; }

# ld-linux mapped a ~2 MiB file-backed region = libc.so.6 (it resolved + loaded it).
[ "$(LC_ALL=C grep -acE '\[mmap\] (lazy|file-backed) ok .* len=20[0-9]{5}' "$SLOG")" -ge 1 ] \
  && echo "PASS · ld-linux opened + mapped libc.so.6 from the sysroot (~2 MiB)" \
  || echo "WARN · libc.so.6 mmap size marker not matched (loader path may differ)"

# glibc stdio ran THROUGH ld-linux: the PIE's printf output.
[ "$(sg 'hi glibc-DYNAMIC 42')" -ge 1 ] \
  && echo "PASS · the glibc-dynamic PIE printed via glibc stdio (loader+libc+exec OK)" \
  || { echo "FAIL · no PIE output (loader/libc/reloc gap)"; fail=1; }

# A REAL off-the-shelf Debian binary: /bin/ls with its FULL glibc closure
# (libselinux/libcap/libpcre2-8/libc.so.6) produced a long listing of /tmp,
# with glibc NSS resolving uid/gid 0 -> "root root" (getpwuid/getgrgid).
[ "$(sg '\[glibcdyn\] === Debian /bin/ls')" -ge 1 ] \
  && echo "PASS · Debian /bin/ls (glibc PIE, full closure) launched" \
  || { echo "FAIL · debian-ls did not launch (staging?)"; fail=1; }
[ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* -rw-r--r-- 1 root root .* honey-aws-creds' "$SLOG")" -ge 1 ] \
  && echo "PASS · /bin/ls -la /tmp listed (perms + glibc-NSS name resolution: root root)" \
  || { echo "FAIL · /bin/ls long listing / NSS"; fail=1; }

# /bin/ls -la / now works (the VFS-root stat fix · was "cannot access '/'").
# The root dirs list as size-0 entries (e.g. "... root root 0 ... etc").
{ [ "$(sg "cannot access '/'")" -eq 0 ] \
  && [ "$(sg '\[glibcdyn\] === Debian /bin/ls -la /')" -ge 1 ] \
  && [ "$(LC_ALL=C grep -acE 'r.xr.xr.x 1 root root 0 .* (bin|etc|usr)' "$SLOG")" -ge 1 ]; } \
  && echo "PASS · /bin/ls -la / lists the VFS root tree (the stat-root fix)" \
  || { echo "FAIL · ls / (root stat fix)"; fail=1; }

# More real Debian coreutils.
[ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* Linux alpine-host 6.6.30.* GNU/Linux' "$SLOG")" -ge 1 ] \
  && echo "PASS · Debian uname -a (full GNU/Linux persona string)" \
  || { echo "FAIL · Debian uname -a"; fail=1; }

# CROSS-DISTRO · a Fedora binary ran on the Debian glibc runtime (forward-compat).
[ "$(sg '\[glibcdyn\] === Fedora uname')" -ge 1 ] \
  && echo "PASS · a Fedora binary ran on sotOs (Fedora 2.39 on Debian 2.41 glibc)" \
  || { echo "FAIL · Fedora cross-distro binary"; fail=1; }

# A REAL glibc SHELL · GNU bash 5.2 · version + builtins (loop/arith/expand/cond).
[ "$(sg 'GNU bash, version 5.2')" -ge 1 ] \
  && echo "PASS · GNU bash 5.2 runs (--version)" \
  || { echo "FAIL · bash --version"; fail=1; }
{ [ "$(sg 'iter 1')" -ge 1 ] && [ "$(sg 'iter 3')" -ge 1 ] \
  && [ "$(LC_ALL=C grep -acF 'arithmetic 6*7=42' "$SLOG")" -ge 1 ] \
  && [ "$(sg 'upcase=SOTOS')" -ge 1 ] && [ "$(sg 'conditional OK')" -ge 1 ]; } \
  && echo "PASS · bash builtins: for-loop + arithmetic + \${^^} expansion + [ ] test" \
  || { echo "FAIL · bash builtins"; fail=1; }
# getcwd syscall-ABI fix (was returning the buffer ptr, glibc wanted the length).
[ "$(LC_ALL=C grep -ac 'cannot access parent directories' "$SLOG")" -eq 0 ] \
  && echo "PASS · no bash getcwd warning (syscall returns length, not the ptr)" \
  || { echo "FAIL · bash getcwd warning (getcwd ABI)"; fail=1; }

# Clean exit + handler completion.
{ [ "$(sg 'pid=1 (slot=0) exited code=0')" -ge 1 ] && [ "$(sg '\[glibcdyn\] handler DONE')" -ge 1 ]; } \
  && echo "PASS · clean exit code=0 + handler completed" \
  || { echo "FAIL · did not exit cleanly"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|Invocation of invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] \
  && echo "PASS · 0 faults across the glibc-dynamic run" \
  || { echo "FAIL · ${nf} fault(s)"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'GLIBC-DYNAMIC-ON-sotOs: PASS' || echo 'GLIBC-DYNAMIC-ON-sotOs: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
