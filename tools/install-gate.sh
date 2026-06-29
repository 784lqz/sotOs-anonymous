#!/usr/bin/env bash
# install-arc P0.2 gate · `dpkg-deb -x /tmp/hello.deb /tmp/root` extracts a real
# tree on sotOs (Phase-0 slice · extracts to the already-writable /tmp · no /usr
# union yet — that's Phase 1).
#
# The auto-demo runs `dpkg-install` EARLY (right after gitdemo, before the slow
# GUI demos): orch spawns the unmodified off-the-shelf Debian `dpkg-deb` (a
# glibc-dynamic PIE via the real ld-linux) at Tier-0 and drives:
#     dpkg-deb -x /tmp/hello.deb /tmp/root
#     ls -la /tmp/root/usr/bin
# dpkg-deb internally ar-splits the .deb, then execve's the REAL `tar` + the
# `xz` decompressor (the data.tar is .xz-compressed) to unpack data.tar.xz into
# /tmp/root, writing /tmp/root/usr/bin/hello (a real ELF) onto the writable /tmp
# sotfs.  PASS = dpkg-deb ran (no execve ENOENT for dpkg-deb/tar/xz), the
# extracted /tmp/root/usr/bin/hello appears in the `ls -la` listing, and 0
# faults.  This is the gate for the real ar+tar+xz extraction path (dpkg-deb's
# helper execve resolution + the sotfs mkdir/write path on /tmp).
#
# Boots in the background and kills QEMU as soon as `[install] handler DONE`
# appears (install runs early), so the gate is fast and doesn't wait out the
# slow GUI demos that follow.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-install-gate-serial.log

# Operator-QEMU guard · NEVER pkill (the operator's QEMU holds the sotfs.img lock).
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[install-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi

# Fresh image · the install demo writes the extracted tree to the writable /tmp
# sotfs; a stale image could shadow a fresh dpkg-deb or carry an old /tmp/root.
echo "[install-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
# dpkg-install is lean-skipped · build the full battery (regenerates the fresh
# sotfs.img · restores the fast LEAN default on exit).
. tools/lib/demo-full.sh; ensure_full_demos || { echo "[install-gate] BLOCKED: build failed (see /tmp/demo-full-cfg.log)"; exit 2; }
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[install-gate] missing $t · build incomplete"; exit 2; }
done
rm -f "$SLOG"; : > "$SLOG"

echo "[install-gate] booting headless (auto-demo runs dpkg-install early)…"
timeout 220 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null; demo_lean_restore' EXIT

# Wait (up to ~180s) for the install handler to finish, then stop the VM early.
waited=0
for i in $(seq 1 180); do
  LC_ALL=C grep -qa '\[install\] handler DONE' "$SLOG" && { waited=$i; break; }
  sleep 1; waited=$i
done
echo "[install-gate] install settled after ${waited}s ($(wc -l < "$SLOG") serial lines)"
sleep 1
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== install-arc P0.2 · dpkg-deb -x extracts a real tree ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

# 1 · dpkg-deb was found + spawned (the real off-the-shelf Debian binary).
[ "$(sg '\[install\] dpkg-deb found via')" -ge 1 ] \
  && echo "PASS · dpkg-deb (glibc-dynamic) loaded from the binstore" \
  || { echo "FAIL · dpkg-deb binary not found (staging?)"; fail=1; }

# 2 · dpkg-deb actually ran (the extraction step spawned).
[ "$(sg '\[install\] === dpkg-deb -x')" -ge 1 ] \
  && echo "PASS · dpkg-deb -x /tmp/hello.deb /tmp/root ran" \
  || { echo "FAIL · dpkg-deb -x step did not run"; fail=1; }

# 3 · the helper closure resolved · dpkg-deb execve'd the REAL `tar` (binstore)
#     to unpack data.tar.xz · and NO execve ENOENT for the helpers.
[ "$(LC_ALL=C grep -acE "execve.*binstore 'tar'|replacing image with '/.*/tar'" "$SLOG")" -ge 1 ] \
  && echo "PASS · dpkg-deb execve'd the real tar (binstore) to unpack data.tar.xz" \
  || { echo "FAIL · dpkg-deb did not execve tar (helper resolution?)"; fail=1; }
nenoent=$(LC_ALL=C grep -acE 'execve.*(dpkg-deb|tar|xz).*ENOENT|No such file.*(tar|xz)|cannot exec' "$SLOG")
[ "${nenoent:-0}" -eq 0 ] \
  && echo "PASS · no execve ENOENT for dpkg-deb/tar/xz" \
  || { echo "FAIL · ${nenoent} helper execve ENOENT (tar/xz missing?)"; fail=1; }

# 4 · THE PROOF (a) · the extracted ELF actually hit the writable /tmp sotfs:
#     a real create_file of /root/usr/bin/hello (the /tmp mount root) + a real
#     FS WRITE on that exact path (the ~35KB ELF body, via tar's sotfs writes).
{ [ "$(LC_ALL=C grep -acE 'sotfs:create_file path=/root/usr/bin/hello' "$SLOG")" -ge 1 ] \
  && [ "$(LC_ALL=C grep -acE 'FS WRITE.*path=/root/usr/bin/hello' "$SLOG")" -ge 1 ]; } \
  && echo "PASS · /tmp/root/usr/bin/hello written to the sotfs (create_file + FS WRITE)" \
  || { echo "FAIL · /tmp/root/usr/bin/hello was NOT written to the sotfs (extraction failed)"; fail=1; }

# 4 · THE PROOF (b) · the real glibc `ls -la /tmp/root/usr/bin` lists the hello
#     ELF · ideally with the -rwxr-xr-x exec perm tar restored.  The .* swallows
#     the │guest│ prefix.
[ "$(LC_ALL=C grep -acE '\[install\] === ls -la /tmp/root/usr/bin' "$SLOG")" -ge 1 ] \
  && echo "PASS · ls -la /tmp/root/usr/bin step ran (real glibc /bin/ls)" \
  || { echo "FAIL · ls -la /tmp/root/usr/bin step did not run"; fail=1; }

# the `ls` guest output is CRLF-terminated → match `hello` then optional \r at EOL.
if LC_ALL=C grep -aqE 'guest.*-rwxr.xr.x.* hello[[:space:]]*$' "$SLOG"; then
  echo "PASS · /tmp/root/usr/bin/hello in the ls listing (ELF · -rwxr-xr-x)"
  LC_ALL=C grep -aE 'guest.*-rwxr.xr.x.* hello[[:space:]]*$' "$SLOG" | head -1 | tr -d '\r'
elif LC_ALL=C grep -aqE 'guest.*[[:space:]]hello[[:space:]]*$' "$SLOG"; then
  echo "PASS · /tmp/root/usr/bin/hello in the ls listing"
  LC_ALL=C grep -aE 'guest.*[[:space:]]hello[[:space:]]*$' "$SLOG" | head -1 | tr -d '\r'
else
  echo "FAIL · 'hello' not in the ls -la /tmp/root/usr/bin listing"; fail=1
  echo "---- ls listing context ----"
  LC_ALL=C grep -aA8 '\[install\] === ls -la /tmp/root/usr/bin' "$SLOG" | head -12
fi

# ── Phase 1 · the REAL install: `dpkg -i hello.deb` → installs + runs ────────
# 5a · dpkg drove the unpack+configure transcript.
[ "$(sg 'Unpacking hello')" -ge 1 ] && [ "$(sg 'Setting up hello')" -ge 1 ] \
  && echo "PASS · P1 · dpkg -i transcript (Unpacking + Setting up hello)" \
  || { echo "FAIL · P1 · dpkg -i did not unpack+configure hello"; fail=1; }
# 5b · NO dpkg error processing the archive (the install actually succeeded).
[ "$(sg 'error processing archive /tmp/hello.deb')" -eq 0 ] \
  && echo "PASS · P1 · dpkg -i finished with no archive-processing error" \
  || { echo "FAIL · P1 · dpkg -i reported 'error processing archive'"; fail=1; }
# 5c · the DB recorded the install (status-new → status committed).
[ "$(sg 'status-new -> /var/lib/dpkg/status')" -ge 1 ] \
  && echo "PASS · P1 · /var/lib/dpkg/status updated (DB records hello installed)" \
  || { echo "FAIL · P1 · the dpkg status DB was not committed"; fail=1; }
# 5d · the INSTALLED /usr/bin/hello loaded from the overlay AND ran.
[ "$(sg 'usr/bin/hello.*source=sotfs-graph')" -ge 1 ] \
  && echo "PASS · P1 · /usr/bin/hello loaded from the /usr overlay (installed ELF)" \
  || { echo "FAIL · P1 · /usr/bin/hello was not loaded from the overlay"; fail=1; }
[ "$(sg 'Hello, world!')" -ge 1 ] \
  && echo "PASS · P1 · /usr/bin/hello RAN → 'Hello, world!'  ★ dpkg -i end-to-end ★" \
  || { echo "FAIL · P1 · the installed /usr/bin/hello did not print 'Hello, world!'"; fail=1; }

# ── Phase 1b · a real postinst (maintainer script) with an observable /etc effect
# 1b-a · dpkg ran the postinst: `Setting up sotmark` + NO postinst-subprocess error.
{ [ "$(sg 'Setting up sotmark')" -ge 1 ] \
  && [ "$(sg 'error processing package sotmark')" -eq 0 ]; } \
  && echo "PASS · P1b · dpkg -i sotmark configured (postinst ran, no error)" \
  || { echo "FAIL · P1b · sotmark postinst did not configure cleanly"; fail=1; }
# 1b-b · the postinst executed via the binfmt_script shebang (fork+execve /bin/sh).
[ "$(LC_ALL=C grep -acE "shebang '/var/lib/dpkg/info/sotmark.postinst'.*interp '/bin/sh'" "$SLOG")" -ge 1 ] \
  && echo "PASS · P1b · postinst ran via #! shebang → /bin/sh (binfmt_script)" \
  || { echo "FAIL · P1b · the #! maintainer-script exec path did not fire"; fail=1; }
# 1b-c · THE side effect · the postinst wrote /etc/sotmark.conf in the writable
#        /etc union upper, and the real glibc cat reads it back (honey base intact).
{ [ "$(sg '\[sotmark.postinst\] wrote /etc/sotmark.conf')" -ge 1 ] \
  && [ "$(LC_ALL=C grep -acE 'guest.*sotmark: configured by postinst' "$SLOG")" -ge 1 ]; } \
  && echo "PASS · P1b · /etc/sotmark.conf written by postinst + read back (writable /etc)" \
  || { echo "FAIL · P1b · the /etc side effect was not observable"; fail=1; }
# 1b-d · deception intact · the honey /etc/passwd still serves the persona (base).
[ "$(LC_ALL=C grep -acE 'guest.*root:x:0:0:root' "$SLOG")" -ge 1 ] \
  && echo "PASS · P1b · honey /etc/passwd still served (union base · deception intact)" \
  || { echo "FAIL · P1b · honey /etc/passwd missing (union base regressed)"; fail=1; }

# 5 · clean handler lifecycle.
[ "$(sg '\[install\] handler DONE')" -ge 1 ] \
  && echo "PASS · install handler completed cleanly" \
  || { echo "FAIL · install handler did not finish (hang/crash?)"; fail=1; }

# 6 · zero faults across the run.
nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|Invocation of invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] \
  && echo "PASS · 0 faults across the install run" \
  || { echo "FAIL · ${nf} fault(s) in the boot"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'INSTALL: PASS' || echo 'INSTALL: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
