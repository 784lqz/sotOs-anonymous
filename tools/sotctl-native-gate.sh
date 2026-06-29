#!/usr/bin/env bash
# sotctl-native-gate · prove the world-#3 NATIVE sotctl binary RUNS at runtime
# with the sotcrt + sotlibc + sel4runtime C runtime (NOT muslc / sel4muslcsys).
#
# The sotShell scripted demo runs `sotctl sessions`, which execve-launches the
# native sotctl seL4 binary.  It does the sotabi handshake + stats + render-stream
# and prints its OWN markers to the serial.  Those markers are the proof that
# sel4runtime's _start reached main() and sotcrt's printf reached seL4_DebugPutChar
# — i.e. the world-#3 runtime executes, not just links.
#
# Headless · NEVER touches an already-running operator QEMU (exits 3).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
LOG=/tmp/sotctl-native-gate-serial.log
TIMEOUT=200

say(){ printf '%s\n' "$*"; }

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  say "[sotctl-native-gate] a QEMU is already running — refusing to boot a second one (BLOCKED)"
  exit 3
fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { say "[sotctl-native-gate] missing $t · run 'just build'"; exit 2; }
done

rm -f "$LOG"
say "[sotctl-native-gate] booting headless (the scripted demo runs \`sotctl sessions\`)…"
timeout "$TIMEOUT" qemu-system-x86_64 \
  -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 \
  -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
  -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  </dev/null >"$LOG" 2>&1 &
QPID=$!
trap 'kill $QPID 2>/dev/null' EXIT

# Wait until the native sotctl finished (render-stream complete) or the demo
# moved past it, or boot ended.
for i in $(seq 1 "$TIMEOUT"); do
  LC_ALL=C grep -qaF "[sotctl-native] (render-stream complete" "$LOG" && break
  LC_ALL=C grep -qaF "demo done · L4-Phase-C v2 complete" "$LOG" && break
  kill -0 "$QPID" 2>/dev/null || break
  sleep 1
done
sleep 1
kill "$QPID" 2>/dev/null

say ""
say "==== sotctl-native runtime proof (sotcrt + sotlibc + sel4runtime · NO sel4muslcsys) ===="
fail=0
chk(){ if LC_ALL=C grep -qaF "$2" "$LOG"; then say "  PASS · $1"; else say "  FAIL · $1"; fail=1; fi; }
chk "orch spawned the native binary (orch_spawn_native rc=0)"          "[sotctl] native spawn rc=0"
chk "native main() ran + sotabi handshake printf hit the serial"       "[sotctl-native] sotabi v"
chk "stats read over the formal envelope (truth-core)"                 "[sotctl-native] stats ·"
chk "render-stream completed (binary drove sotabi to EOF + exited)"    "[sotctl-native] (render-stream complete"

if LC_ALL=C grep -qaiE "VMFault.*sotctl|sotctl.*VMFault|cap fault.*sotctl" "$LOG"; then
  say "  FAIL · a fault mentioning sotctl appeared in the serial"; fail=1
else
  say "  PASS · no sotctl-attributed fault in the serial"
fi

say ""
if [ "$fail" -eq 0 ]; then
  say "[sotctl-native-gate] PASS — the world-#3 native binary runs on sotcrt+sotlibc"
  exit 0
else
  say "[sotctl-native-gate] FAIL"
  say "---- [sotctl* serial lines ----"
  LC_ALL=C grep -aE "\[sotctl" "$LOG" | tail -20
  exit 1
fi
