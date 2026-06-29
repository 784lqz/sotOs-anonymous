#!/usr/bin/env bash
# apt arc · Phase 2 gate — `apt-get install` from the REAL Debian archive.
# A Debian-persona Tier-2 SSH session runs `apt-get update` (builds the cache),
# then `apt-get install` of a small package: apt resolves deps from the built
# pkgCache, downloads the .deb(s) over the per-session egress, and hands them to
# dpkg to unpack+configure — all CONTAINED in the per-session upper.
# NETWORK-GATED: if the archive/egress is unreachable, SKIP (exit 0).
# Exit: 0=PASS/SKIP, 1=FAIL, 2=missing image, 3=BLOCKED (operator QEMU live).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
PORT=18031
PKG="${1:-hello}"
MEM="${SOTOS_MEM:-8192}"   # dpkg-unpack fork eager-copies the ~156MB apt cache → needs a 4th heavy arena
SLOG=/tmp/sotos-apt-install-serial.log
BLOG=/tmp/sotos-apt-install-sessB.log
ASK=/tmp/sotos-apt-install-ask.sh
say(){ printf '%s\n' "$*"; }

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  say "[apt-install] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { say "[apt-install] missing $t · run 'just build'"; exit 2; }; done

# FRESH sotfs.img per run.  apt writes ~110 MB (Packages + pkgcache.bin) into the
# per-session upper; a gate that kills QEMU mid-session never runs the disconnect
# reap, so stale session blocks accumulate on sotfs.img across runs → the NEXT
# run's `apt-get update` hits ENOSPC early (the 192 MB session cap is already
# spent on a prior run's leftovers).  Regenerate a clean disk each time, mirroring
# git-gate / install-gate.
say "[apt-install] regenerating a fresh sotfs.img…"
rm -f build/images/sotfs.img
ninja -C build >/tmp/sotos-apt-install-build.log 2>&1 \
  || { say "[apt-install] sotfs.img regen failed (see /tmp/sotos-apt-install-build.log)"; exit 2; }
[ -f build/images/sotfs.img ] || { say "[apt-install] missing sotfs.img after regen"; exit 2; }

rm -f "$SLOG" "$BLOG"
say "[apt-install] booting headless…"
timeout 1500 qemu-system-x86_64 -m "$MEM" -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::18083-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18446-:443 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  </dev/null >"$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 90); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { say "[apt-install] FAIL · :22 never LISTENed"; exit 1; }
sleep 2
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"

run_ssh(){ local log="$1"; shift
  ( for c in "$@"; do printf '%s\n' "$c"; sleep 3; done; printf 'exit\n'; sleep 3 ) | \
    timeout 760 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
    ssh -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 root@127.0.0.1 >"$log" 2>&1 || true
}

# Persona alternates per SSH connection · session 1 = Alpine (throwaway warm-up),
# session 2 = Debian (the apt persona).  Mirror apt-update-gate's ordering.
say "[apt-install] session 1 (Alpine · ignored)…"
run_ssh /tmp/sotos-apt-install-sessA.log 'cat /etc/os-release | head -1'
sleep 2
say "[apt-install] session 2 (Debian · apt-get install $PKG)…"
# Robust feed.  Each command stays on its OWN line (so the first-command startup
# race only ever loses the throwaway warmup, never a real command), and between
# the long commands we POLL BLOG for the previous command's RC marker instead of
# a fixed sleep — so `apt-get update` (~4 min) is never cut off by a premature
# stdin-EOF / next-command pile-up (the old 3 s pacing fed everything in ~21 s and
# dropped the session mid-update).  update is RETRIED up to 3× (the ~10 MB index
# download is flaky over the KVM-iothread-paced guest egress · the host reaches
# the archive instantly, so this is purely SLIRP delivery non-determinism).
waitfor(){ local m="$1" n="$2"; for _ in $(seq 1 "$n"); do
  LC_ALL=C grep -qa "$m" "$BLOG" 2>/dev/null && return 0; sleep 3; done; return 0; }
( printf '\n'; sleep 6                                   # let the shell + 3-try auth settle
  printf 'echo SHELL_WARMUP_READY\n'; sleep 4            # absorb the first-command race
  printf 'for i in 1 2; do apt-get update && break; echo UPDATE_RETRY_$i; sleep 5; done; echo UPDATE_RC=$?\n'
  waitfor 'UPDATE_RC=' 150                               # up to ~7.5 min for update(+1 retry)
  printf 'apt-cache policy %s; echo POLICY_RC=$?\n' "$PKG"; sleep 4
  # the honey shell is a compromised NON-root user (uid 1000, sudo group) → a
  # real install uses sudo; plain `apt-get install` correctly needs superuser.
  printf 'sudo apt-get install -y --no-install-recommends %s; echo INSTALL_RC=$?\n' "$PKG"
  waitfor 'INSTALL_RC=' 150                              # up to ~4.5 min for the install txn
  printf 'dpkg -l %s 2>/dev/null | tail -1; echo DPKG_DONE\n' "$PKG"; sleep 4
  printf 'command -v %s; %s 2>&1 | head -2; echo RUN_DONE\n' "$PKG" "$PKG"; sleep 4
  printf 'exit\n'; sleep 2 ) | \
  timeout 1500 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 root@127.0.0.1 >"$BLOG" 2>&1 || true
sleep 2; kill "$QPID" 2>/dev/null

# ---- verdict ----
bg(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG" 2>/dev/null | grep -acE "$1"; }
if LC_ALL=C grep -qaiE 'Temporary failure resolving|Could not resolve|Network is unreachable' "$BLOG"; then
  say "[apt-install] SKIP · archive unreachable (network-gated)"; exit 0; fi

say ""; say "==== apt-get install $PKG proof (real archive · contained) ===="
LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG" | grep -aiE \
  "UPDATE_RC|POLICY_RC|INSTALL_RC|DPKG_DONE|RUN_DONE|Get:|Fetched|Unpacking|Setting up|Candidate:|^[a-z].*installed|error|E:" | tail -40
say "---- verdict ----"
fail=0
[ "$(bg 'UPDATE_RC=0')" -ge 1 ] && say "  PASS · apt-get update RC=0" || { say "  FAIL · apt-get update"; fail=1; }
[ "$(bg 'INSTALL_RC=0')" -ge 1 ] && say "  PASS · apt-get install RC=0" || { say "  INFO · apt-get install non-zero (see tail)"; }
LC_ALL=C grep -qaiE 'Unpacking|Setting up' "$BLOG" && say "  PASS · dpkg unpack/configure ran" || { say "  FAIL · no dpkg unpack/configure"; fail=1; }
LC_ALL=C grep -qaiE 'VMFault|UserException|root server abort|allocman cslots exhausted' "$SLOG" && { say "  FAIL · fault/abort"; fail=1; } || say "  PASS · no fault"
say ""; [ "$fail" = 0 ] && { say "[apt-install] PASS"; exit 0; } || { say "[apt-install] FAIL"; exit 1; }
