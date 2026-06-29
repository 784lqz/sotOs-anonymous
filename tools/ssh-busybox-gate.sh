#!/usr/bin/env bash
# sotOs · SSH busybox canary-shell Phase-B gate (v0.84.0-ssh-busybox)
# A real ssh -tt logs in (2 rejects → 3rd accepted) and gets a REAL busybox sh -i
# at Tier-2 over the encrypted SSH channel: cat /etc/passwd = canary, write =
# mirror-drop, exit clean. Asserts ZERO invalid-cap/CapFault/cspace/MAC faults.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
PORT=18022; SLOG=/tmp/sotos-ssh-bbx-serial.log; CLOG=/tmp/sotos-ssh-bbx-client.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[bbx-gate] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do [ -f "$t" ] || { echo "[bbx-gate] missing $t"; exit 2; }; done
rm -f "$SLOG" "$CLOG"
echo "[bbx-gate] booting honeypot..."
timeout 240 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[bbx-gate] FAIL · :22 never LISTENed"; exit 1; }
sleep 2; echo "[bbx-gate] :22 LISTEN · ssh -tt + real busybox session..."
ASK=/tmp/sotos-askpass.sh; printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
# slow feed (keep stdin open between commands so busybox runs+outputs each before the next; exit last)
( sleep 3; printf 'busybox id\n'; sleep 3; printf 'cat /etc/passwd\n'; sleep 3;
  printf 'cat /tmp/honey-aws-creds\n'; sleep 3; printf 'echo CORRUPTED > /tmp/probe\n'; sleep 3;
  printf 'exit\n'; sleep 4 ) | \
  timeout 70 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -vvv -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 root@127.0.0.1 > "$CLOG" 2>&1 || true
echo "=== SSH BUSYBOX PHASE-B gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }; cg(){ LC_ALL=C grep -aic "$1" "$CLOG"; }
[ "$(sg 'ssh-shell:.*entering fault loop')" -ge 1 ] && echo "PASS · orch spawned busybox sh -i over SSH" || { echo "FAIL · busybox not spawned"; fail=1; }
[ "$(sg '\[synth-srv\] SSH cred conn=')" -ge 2 ] && echo "PASS · creds captured (>=2)" || { echo "FAIL · cred capture"; fail=1; }
{ [ "$(sg 'CANARY path=/etc/passwd')" -ge 1 ] || [ "$(cg 'root:')" -ge 1 ]; } && echo "PASS · canary /etc/passwd served over SSH" || { echo "FAIL · no canary passwd"; fail=1; }
{ [ "$(sg 'silently dropped')" -ge 1 ] || [ "$(cg 'Permission denied')" -ge 1 ]; } && echo "PASS · Tier-2 mirror-drop on write" || echo "WARN · mirror-drop not confirmed"
[ "$(sg 'ssh-shell: busybox exited')" -ge 1 ] && echo "PASS · clean exit + SHELL_EOF" || echo "WARN · clean-exit marker not seen"
# Catch every abnormal fault class (mirrors the v1-rc1 composite scan): MAC,
# invalid-cap, the abnormal LucAs FAULT names (NOT the normal VMFault/UnknownSyscall),
# the non-syscall cap escalation, cspace exhaustion, and code=139.
faults=$(LC_ALL=C grep -aEc 'Invocation of invalid cap|FAULT CapFault|FAULT UserException|FAULT NullFault|non-syscall fault cap reached|cspace exhausted|root server abort|exited code=139' "$SLOG")
{ [ "$(cg 'Corrupted MAC')" -eq 0 ] && [ "${faults:-0}" -eq 0 ]; } && echo "PASS · no MAC/cap/abnormal-fault" || { echo "FAIL · MAC/cap/abnormal-fault ($faults)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'SSH BUSYBOX PHASE-B: PASS' || echo 'SSH BUSYBOX PHASE-B: FAIL' ) ==="
echo "(serial: $SLOG · client: $CLOG)"; exit $fail
