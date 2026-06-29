#!/usr/bin/env bash
# compat-host gate · REAL Alpine git (musl-dynamic) runs on sotOs.
#
# The auto-demo runs `gitdemo` EARLY (right before sdlspike): orch spawns the
# unmodified Alpine git 2.45 binary (binstore) at Tier-0 and drives, as 3 fresh
# Tier-0 sotboxes sharing the /tmp sotfs graph:
#     git init /tmp/gitrepo
#     git -c user.* -C /tmp/gitrepo commit --allow-empty -m "first sotOs commit"
#     git --no-pager -C /tmp/gitrepo log --oneline
# PASS = git init succeeds, a real commit is created (root-commit), `git log`
# reads it back (the message prints twice: once from commit, once from log),
# the real Tier-0 rename() path fired (lucas_sotfs_rename · git finalizes every
# object/ref/index/HEAD via write-tmp-then-rename), and 0 faults / no object-write
# EINVAL.  This is the gate for the rename() + SOTFS_MAX_NAME=64 + /dev/urandom
# + link→EXDEV + dynamic libz/libpcre2 closure that git needs.
#
# Boots in the background and kills QEMU as soon as `[gitdemo] handler DONE`
# appears (gitdemo runs early), so the gate is fast and doesn't wait out the
# slow GUI demos that follow.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-git-gate-serial.log

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[git-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3; fi
# Fresh image per run.  The gitdemo writes a real .git tree to the disk-backed
# /tmp; reusing a dirty sotfs.img across runs accumulates a stale /tmp/gitrepo/
# .git, so a later `git init`+commit collides with it → "fatal: .git/index:
# index file smaller than expected" / README missing (the flaky FAILs).
# install-gate is reliable for exactly this reason — mirror it.
echo "[git-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # gitdemo is lean-skipped · full battery (regenerates the fresh sotfs.img · restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[git-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG"; : > "$SLOG"

echo "[git-gate] booting headless (auto-demo runs gitdemo early)…"
timeout 200 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null; demo_lean_restore' EXIT

# Wait (up to ~160s) for gitdemo to finish, then stop the VM early.
waited=0
for i in $(seq 1 160); do
  LC_ALL=C grep -qa '\[gitdemo\] handler DONE' "$SLOG" && { waited=$i; break; }
  sleep 1; waited=$i
done
echo "[git-gate] gitdemo settled after ${waited}s ($(wc -l < "$SLOG") serial lines)"
sleep 1
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== compat-host · git-on-sotOs gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[gitdemo\] git found via binstore')" -ge 1 ] \
  && echo "PASS · git (musl-dynamic) loaded from the binstore" \
  || { echo "FAIL · git binary not found (staging?)"; fail=1; }

# git init · "Initialized empty" on a fresh image, or "Reinitialized existing"
# when the sotfs WAL persisted /gitrepo from a previous boot (both are success).
{ [ "$(sg 'Initialized empty Git repository in /tmp/gitrepo')" -ge 1 ] \
  || [ "$(sg 'Reinitialized existing Git repository in /tmp/gitrepo')" -ge 1 ]; } \
  && echo "PASS · git init ran (.git tree on the writable /tmp sotfs mount)" \
  || { echo "FAIL · git init did not initialize the repo"; fail=1; }

# Real Tier-0 rename() — the load-bearing fix (git finalizes via write-tmp→rename).
nmv=$(sg '\[mv\] .* · renamed')
[ "${nmv:-0}" -ge 5 ] \
  && echo "PASS · real Tier-0 rename() fired ${nmv}× (lucas_sotfs_rename)" \
  || { echo "FAIL · real rename path did not run (${nmv:-0} renames)"; fail=1; }

# A REAL tracked file: orch seeds /tmp/gitrepo/README, git add stages it, and
# `git ls-files` lists it (robust across the WAL-persisted re-boot, where commit
# is --allow-empty but README stays tracked).
{ [ "$(sg '\[gitdemo\] seeded /tmp/gitrepo/README rc=0')" -ge 1 ] \
  && [ "$(LC_ALL=C grep -acE 'guest:[0-9]+.* README' "$SLOG")" -ge 1 ]; } \
  && echo "PASS · README seeded + git-add'd + tracked (git ls-files lists it)" \
  || { echo "FAIL · tracked file (seed=$(sg '\[gitdemo\] seeded /tmp/gitrepo/README rc=0') ls-files=$(LC_ALL=C grep -acE 'guest:[0-9]+.* README' "$SLOG"))"; fail=1; }

# A real commit was created — git prints "[<branch> <sha>] track README on sotOs"
# (with "(root-commit)" only on a fresh repo) — AND `git log` reads it back, so
# the message text appears at least twice (commit summary + ≥1 log line).
ncommit=$(sg 'track README on sotOs')
{ [ "$(LC_ALL=C grep -acE '\[master [0-9a-f(]' "$SLOG")" -ge 1 ] && [ "${ncommit:-0}" -ge 2 ]; } \
  && echo "PASS · real commit created + read back by git log (message ${ncommit}×)" \
  || { echo "FAIL · commit/log readback (commit-line=$(LC_ALL=C grep -acE '\[master [0-9a-f(]' "$SLOG") msg=${ncommit:-0})"; fail=1; }

# No object-write failure (the SOTFS_MAX_NAME=64 / EINVAL regression sentinel).
{ [ "$(sg 'unable to write file')" -eq 0 ] && [ "$(sg 'does not have any commits yet')" -eq 0 ]; } \
  && echo "PASS · no object-write EINVAL (38-char object names fit · SOTFS_MAX_NAME=64)" \
  || { echo "FAIL · git could not write objects (NAMETOOLONG/EINVAL regression?)"; fail=1; }

# Clean handler lifecycle + zero faults.
[ "$(sg '\[gitdemo\] handler DONE')" -ge 1 ] \
  && echo "PASS · gitdemo handler completed cleanly" \
  || { echo "FAIL · gitdemo handler did not finish (hang/crash?)"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|Invocation of invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] \
  && echo "PASS · 0 faults across the git run" \
  || { echo "FAIL · ${nf} fault(s) in the boot"; fail=1; }

# Regression · the sibling spike that runs right after gitdemo stays green.
[ "$(sg '\[mapfixed\] ALL PASS')" -ge 1 ] \
  && echo "PASS · regression · mapfixed ALL PASS" \
  || echo "WARN · mapfixed marker not seen (boot window / ordering)"

echo "=== $( [ $fail -eq 0 ] && echo 'GIT-ON-sotOs: PASS' || echo 'GIT-ON-sotOs: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
