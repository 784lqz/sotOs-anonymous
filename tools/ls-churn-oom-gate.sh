#!/usr/bin/env bash
# gate-ls-churn-oom · validate the in-life ARENA RECLAIM on the LIGHT path.
#
# Companion to tools/arena-churn-gate.sh — that gate exercises the HEAVY arena
# (python mmaps+frees 300 MiB).  This gate exercises the *regular* ("light")
# arena, where the bug actually bit: `ls` (busybox-static, ~1 MiB) runs in a
# light arena, and for any non-heavy arena `lucas_sys_munmap` was a NO-OP — it
# never unmapped or recycled frames, and the in-life frame free-list was
# disabled.  So musl's normal mmap->munmap->mmap allocator churn turned into
# monotonic, unreclaimed mmap growth: each `ls` retyped fresh frames that were
# never reused, climbing toward the arena's 8192-cslot ceiling
# (`cspace exhausted`), after which the box was reaped code=1.  The persistent
# canary shell is *also* a light arena, so its mmap_high_water grew monotonically
# over uptime — every fork copied a bigger [0x40000000, high_water) MMAP region
# (the `region MMAP ... N pages copied` count climbed), which is why the failure
# appeared only after a while of use, not on a fresh boot.
#
# This gate boots to the interactive canary shell (bbsh), drives a tight `ls`
# loop over populated sysroot dirs, and asserts the four regression signals from
# the diagnosis:
#   (a) ZERO `cspace exhausted` (the light arena never hit the cslot ceiling),
#   (b) every `ls` exited code=0 (no `exited code=1`, no `non-syscall fault cap
#       reached` — no ls child reaped on OOM),
#   (c) the per-fork `region MMAP ... N pages copied` count does NOT grow
#       monotonically across iterations (first ~= last, small jitter ok),
#   (d) the regular-arena revoke DIAG shows `reused>0` AND `[munmap] ... reclaimed
#       ... frame(s)` fired (the LIGHT arena recycled frames — was reused=0).
#
# BEFORE the fix this gate FAILS (reproduces cspace-exhausted / code=1 / reused=0
# / monotonic region-MMAP growth).  AFTER ungating the reclaim for regular arenas
# it PASSES.  NOT network-dependent.  Drives a real typed session over the serial
# console; NEVER pkills the operator's QEMU (reports BLOCKED on the write lock).
#
# Exit codes: 0=PASS, 1=FAIL, 2=build/image error, 3=BLOCKED (operator QEMU live)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

SLOG=/tmp/sotos-ls-churn-serial.log
IN=/tmp/sotos-ls-churn-in.fifo
SHELL_SRC=src/sotshell/main.c
QPID=""

# --- operator-QEMU guard (no pkill · it holds the sotfs.img write lock) ---
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[ls-churn-gate] BLOCKED: operator QEMU is live (holds the sotfs.img write lock)."
  echo "[ls-churn-gate] Ask the operator to exit it, then re-run."
  exit 3
fi

cleanup() {
  [ -n "${QPID:-}" ] && kill "$QPID" 2>/dev/null
  exec 3>&- 2>/dev/null
  [ -n "${QPID:-}" ] && wait "$QPID" 2>/dev/null
  rm -f "$IN"
  git checkout -- "$SHELL_SRC" 2>/dev/null
}
trap cleanup EXIT

# --- insert the throwaway bbsh-first demo entry (so the boot drops straight into
#     the interactive canary shell; reverted on exit, like tools/bbsh-gate.sh) ---
if ! grep -q 'auto-reverted by tools/ls-churn-oom-gate.sh' "$SHELL_SRC"; then
  perl -0pi -e 's/(static const char \*demo_commands\[\] = \{\n)/$1        "bbsh",   \/\* GATE-TEMP · auto-reverted by tools\/ls-churn-oom-gate.sh *\/\n/' "$SHELL_SRC"
fi
grep -q 'auto-reverted by tools/ls-churn-oom-gate.sh' "$SHELL_SRC" || { echo "[ls-churn-gate] FAILED to insert bbsh-first"; exit 2; }

echo "[ls-churn-gate] rebuilding (fresh sotfs.img → defeat stale rwbinstore)…"
rm -f build/images/sotfs.img
just build </dev/null >/tmp/sotos-ls-churn-build.log 2>&1 \
  || { echo "[ls-churn-gate] BLOCKED: build failed"; tail -8 /tmp/sotos-ls-churn-build.log; exit 2; }

for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
  [ -f "$t" ] || { echo "[ls-churn-gate] missing $t after build"; exit 2; }
done

rm -f "$IN" "$SLOG"; mkfifo "$IN"; : > "$SLOG"

waitfor(){ for _ in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[ls-churn-gate] booting headless (serial console)…"
timeout 480 qemu-system-x86_64 \
  -m 4096 -display none -vga none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 \
  -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
  -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18022-:22,hostfwd=tcp::18443-:443 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  < "$IN" > "$SLOG" 2>&1 &
QPID=$!
exec 3>"$IN"   # hold the FIFO write end open so QEMU's serial stdin stays open

echo "[ls-churn-gate] waiting for the interactive canary shell (bbsh)…"
waitfor 'bbsh: entering fault loop' 240 || { echo "[ls-churn-gate] FAIL · never reached the bbsh canary shell"; exit 1; }
sleep 3

# confirm the shell is consuming serial input (it echoes typed lines)
printf 'echo BBSH_READY_MARKER\n' >&3
waitfor 'BBSH_READY_MARKER' 30 || echo "[ls-churn-gate] WARN · bbsh prompt not confirmed (continuing)"

echo "[ls-churn-gate] driving the ls churn loop (50× ls -la of populated sysroot dirs)…"
# busybox-ash one-liner (no `seq` dependency); ls only EXISTING sysroot dirs so a
# clean run is code=0 (a missing dir would itself exit 1 and falsely trip (b)).
printf 'n=0; while [ $n -lt 50 ]; do ls -la /usr/bin /usr/lib /usr/share /usr/include >/dev/null 2>&1; n=$((n+1)); done; echo LS_CHURN_DONE\n' >&3

waitfor 'LS_CHURN_DONE' 360 || echo "[ls-churn-gate] WARN · churn loop did not signal DONE (likely OOM-aborted on the unfixed tree) · analysing partial log"
sleep 2
exec 3>&- 2>/dev/null
kill "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null || true

echo
echo "=== ls-churn OOM regression gate ==="
fail=0
g(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

bbsh_up=$(g 'bbsh: entering fault loop')
churn_done=$(g 'LS_CHURN_DONE')
[ "$bbsh_up" -ge 1 ]   && echo "INFO · reached the bbsh canary shell" \
                        || echo "INFO · bbsh shell marker absent"
[ "$churn_done" -ge 1 ] && echo "INFO · ls churn loop COMPLETED (LS_CHURN_DONE)" \
                        || echo "INFO · ls churn loop did NOT complete (consistent with OOM on the unfixed tree)"

# (a) zero cspace exhausted ---------------------------------------------------
ce=$(g 'cspace exhausted')
[ "$ce" -eq 0 ] \
  && echo "PASS (a) · no 'cspace exhausted' (light arena never hit the 8192-cslot ceiling)" \
  || { echo "FAIL (a) · 'cspace exhausted' x$ce — the light arena exhausted its cslot budget"; fail=1; }

# (b) every ls exits code=0 ---------------------------------------------------
c1=$(g 'exited code=1')
nf=$(g 'non-syscall fault cap reached')
if [ "$c1" -eq 0 ] && [ "$nf" -eq 0 ]; then
  echo "PASS (b) · every ls exited code=0 (no 'exited code=1', no fault-cap)"
else
  echo "FAIL (b) · ls reaped on OOM — 'exited code=1' x$c1, 'non-syscall fault cap reached' x$nf"; fail=1
fi

# (c) region MMAP must NOT grow monotonically ---------------------------------
mapfile -t MM < <(LC_ALL=C grep -a 'region MMAP' "$SLOG" | grep -oE '· [0-9]+ pages copied' | grep -oE '[0-9]+')
nmm=${#MM[@]}
if [ "$nmm" -ge 2 ]; then
  first=${MM[0]}; last=${MM[$((nmm-1))]}; delta=$((last - first))
  echo "INFO · region MMAP pages copied: first=$first last=$last delta=$delta (n=$nmm forks)"
  if [ "$delta" -gt 64 ]; then
    echo "FAIL (c) · region MMAP grew monotonically ($first→$last, +$delta pages) — unreclaimed mmap leak"; fail=1
  else
    echo "PASS (c) · region MMAP bounded ($first→$last, +$delta pages · jitter only)"
  fi
else
  echo "INFO (c) · <2 region MMAP samples (n=$nmm) · inconclusive (not counted as PASS or FAIL)"
fi

# (d) light-arena revoke reused>0 AND munmap reclaim fired — scoped to pid=1 (shell) + pid=2 (ls) ----
# [arena] revoke carries no pid field; [p2a] destroy slot=N pid=M always follows on the very next
# line.  Scope by selecting only revoke lines whose next line is a pid=1 or pid=2 destroy event
# (grep -B1 on the destroy pattern).  A heavy-arena box (apk/python) at boot gets a different pid
# and cannot satisfy this check even if its own arena reclaimed frames — it cannot mask a regression
# on the light path.
maxreused=$(LC_ALL=C grep -aB 1 '\[p2a\] destroy slot=[0-9]* pid=[12] · arena revoked' "$SLOG" \
             | LC_ALL=C grep -a '\[arena\] revoke ut=' \
             | grep -oE 'reused=[0-9]+' | grep -oE '[0-9]+' | sort -rn | head -1)
maxreused=${maxreused:-0}
munmaprec=$(LC_ALL=C grep -acE '\[munmap\] pid=[12] · reclaimed [0-9]+ frame' "$SLOG")
echo "INFO · light-arena revoke max reused=$maxreused · [munmap] reclaim events=$munmaprec"
if [ "$maxreused" -ge 1 ] && [ "$munmaprec" -ge 1 ]; then
  echo "PASS (d) · the regular arena recycled frames (reused=$maxreused) + [munmap] reclaim fired (x$munmaprec)"
else
  echo "FAIL (d) · regular arena reclaimed nothing (max reused=$maxreused, [munmap] reclaim x$munmaprec) — the LIGHT-path leak"; fail=1
fi

echo "=== $( [ $fail -eq 0 ] && echo 'LS-CHURN OOM: PASS' || echo 'LS-CHURN OOM: FAIL' ) ==="
echo "(serial: $SLOG · throwaway bbsh-first demo edit auto-reverted)"
exit $fail
