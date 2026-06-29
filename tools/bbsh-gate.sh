#!/usr/bin/env bash
# sotOs · interactive canary-shell gate (Linux-ABI arc · ADR-006)
#
# Proves the interactive `busybox sh -i` canary shell works end-to-end: a real
# typed session (char-by-char via the LucAs read-park) executes commands, the
# Tier-2 canary VFS is served (read /etc/passwd, mirror-drop on write), the
# session exits cleanly, and — crucially — the seL4/Linux syscall-ABI collision
# is GONE (busybox's blocking poll(timeout=-1) no longer mis-routes to a cap
# invocation): ZERO `Invocation of invalid cap` / `FAULT CapFault` / SIGSEGV.
#
# In-sandbox the post-demo 5s interactive window isn't reached within the QEMU
# timeout, so this gate TEMPORARILY inserts `bbsh` as the first demo command
# (a local, reverted edit), rebuilds, boots with `-serial stdio`, and feeds a
# fixed command stream. On real hardware an operator instead types at the
# console. See linux-abi-interactive-shell-design.
#
# NEVER pkills the operator's QEMU (reports BLOCKED on the sotfs.img write lock).
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

LOG=/tmp/sotos-bbsh-gate.log
SHELL_SRC=src/sotshell/main.c

# --- operator-QEMU guard (no pkill) ---
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[bbsh-gate] BLOCKED: operator QEMU is live (holds the sotfs.img write lock)."
    echo "[bbsh-gate] Ask the operator to exit it, then re-run."
    exit 3
fi

cleanup() { git checkout -- "$SHELL_SRC" 2>/dev/null; }
trap cleanup EXIT

# --- insert the throwaway bbsh-first demo entry (reverted on exit) ---
if ! grep -q '"bbsh",   /\* GATE-TEMP' "$SHELL_SRC"; then
    perl -0pi -e 's/(static const char \*demo_commands\[\] = \{\n)/$1        "bbsh",   \/\* GATE-TEMP · auto-reverted by tools\/bbsh-gate.sh *\/\n/' "$SHELL_SRC"
fi
grep -q '"bbsh",   /\* GATE-TEMP' "$SHELL_SRC" || { echo "[bbsh-gate] FAILED to insert bbsh-first"; exit 2; }

echo "[bbsh-gate] rebuilding with bbsh-first (rm sotfs.img → defeat stale rwbinstore)..."
rm -f build/images/sotfs.img
just build > /tmp/bbsh-gate-build.log 2>&1 || { echo "[bbsh-gate] build FAILED"; tail -5 /tmp/bbsh-gate-build.log; exit 2; }

echo "[bbsh-gate] booting + injecting interactive session..."
rm -f "$LOG"
( sleep 25
  printf 'busybox id\n';                   sleep 4
  printf 'cat /etc/passwd\n';              sleep 5
  printf 'cat /tmp/honey-aws-creds\n';     sleep 5
  printf 'echo CORRUPTED > /tmp/probe\n';  sleep 5
  printf 'exit\n';                         sleep 6
) | timeout 140 qemu-system-x86_64 \
    -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18022-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    > "$LOG" 2>&1

# --- assertions (presence-only · busybox echoes input; LC_ALL=C for the UTF-8 trace) ---
g() { LC_ALL=C grep -ac "$1" "$LOG"; }
fail=0
echo "=== interactive canary-shell gate ==="
[ "$(g '\[orch\] bbsh: spawning interactive')" -ge 1 ] && echo "PASS · bbsh spawned busybox sh -i" || { echo "FAIL · bbsh did not spawn"; fail=1; }
[ "$(LC_ALL=C grep -ac '/ \$' "$LOG")" -ge 1 ]        && echo "PASS · interactive prompt shown"   || { echo "FAIL · no prompt (isatty/flush?)"; fail=1; }
[ "$(g 'CANARY path=/etc/passwd')" -ge 1 ]             && echo "PASS · Tier-2 canary /etc/passwd served" || { echo "FAIL · canary read not served"; fail=1; }
[ "$(g 'silently dropped')" -ge 1 ] || [ "$(g 'Permission denied')" -ge 1 ] && echo "PASS · Tier-2 mirror-drop on write" || { echo "FAIL · no mirror-drop"; fail=1; }
[ "$(g '\[orch\] bbsh: fault loop returned')" -ge 1 ] && echo "PASS · clean exit (busybox exited)"  || { echo "FAIL · no clean exit"; fail=1; }
# the ADR-006 proof: the poll(-1) collision is gone
for bad in "Invocation of invalid cap" "FAULT CapFault" "cspace exhausted" "exited code=139"; do
    n=$(g "$bad")
    [ "$n" -eq 0 ] && echo "PASS · no '$bad'" || { echo "FAIL · '$bad' x$n (ABI collision / leak / crash)"; fail=1; }
done

echo "=== $( [ $fail -eq 0 ] && echo 'INTERACTIVE CANARY SHELL: PASS' || echo 'INTERACTIVE CANARY SHELL: FAIL' ) ==="
echo "(full serial: $LOG · throwaway demo edit auto-reverted)"
exit $fail
