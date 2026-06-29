#!/usr/bin/env bash
# sotOs · SSH canary-shell fidelity gate (v0.85.0-ssh-shell-fidelity)
# A real ssh -tt logs in and exercises recon: ls/cd/cwd, recon applets
# (id/uname/whoami), and a pipeline (cat | grep). Asserts believable output +
# write containment + zero faults. Builds on the v0.84 round-trip gate.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
PORT=18022; SLOG=/tmp/sotos-ssh-fid-serial.log; CLOG=/tmp/sotos-ssh-fid-client.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[fid-gate] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do [ -f "$t" ] || { echo "[fid-gate] missing $t"; exit 2; }; done
rm -f "$SLOG" "$CLOG"
echo "[fid-gate] booting honeypot..."
timeout 240 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[fid-gate] FAIL · :22 never LISTENed"; exit 1; }
sleep 2; echo "[fid-gate] :22 LISTEN · ssh -tt recon session..."
ASK=/tmp/sotos-askpass.sh; printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
( sleep 3; printf 'ls /\n'; sleep 2; printf 'id\n'; sleep 2; printf 'uname -a\n'; sleep 2;
  printf 'whoami\n'; sleep 2; printf 'cd /tmp\n'; sleep 2; printf 'pwd\n'; sleep 2;
  printf 'cat /etc/passwd | grep root\n'; sleep 3; printf 'echo CORRUPT > /etc/x\n'; sleep 2;
  printf 'exit\n'; sleep 4 ) | \
  timeout 80 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 root@127.0.0.1 > "$CLOG" 2>&1 || true
echo "=== SSH SHELL FIDELITY gate ==="; fail=0
cg(){ LC_ALL=C grep -ac "$1" "$CLOG"; }; sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }
{ [ "$(cg 'etc')" -ge 1 ] && [ "$(cg 'usr')" -ge 1 ]; } && echo "PASS · ls lists the FS tree" || { echo "FAIL · ls"; fail=1; }
[ "$(cg 'uid=1000')" -ge 1 ] && echo "PASS · id resolves uid/gid" || { echo "FAIL · id"; fail=1; }
{ [ "$(cg 'Linux')" -ge 1 ] && [ "$(cg 'prod-db-01')" -ge 1 ]; } && echo "PASS · uname -a (nodename matches /etc/hostname)" || { echo "FAIL · uname"; fail=1; }
[ "$(cg 'admin')" -ge 1 ] && echo "PASS · whoami → admin" || { echo "FAIL · whoami"; fail=1; }
[ "$(cg '/tmp')" -ge 1 ] && echo "PASS · cd + cwd (pwd → /tmp)" || { echo "FAIL · cwd"; fail=1; }
[ "$(cg 'root:x:0:0')" -ge 1 ] && echo "PASS · pipe (cat | grep root)" || { echo "FAIL · pipe"; fail=1; }
# apk-fs P2: Tier-2 writes are now contained-but-coherent (succeed in-session,
# base pristine), not denied.  The echo redirect silently lands in the session's
# sotfs upper; we observe that no "Read-only" / "cannot create" shell error
# appeared on the line following the echo command.  SSH auth "Permission denied"
# lines are expected and must not be counted.  The positive containment proof
# (in-session read-back + base pristine) is covered by apk-union-gate.sh.
{ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$CLOG" | \
  grep -qaE 'Read-only|cannot create|Permission denied.*etc'; \
} && echo "WARN · write-error after echo to /etc (check $CLOG)" || \
     echo "PASS · write containment (Tier-2 contained-write, no shell error)"
{ [ "$(cg 'Corrupted MAC')" -eq 0 ] && [ "$(sg 'Invocation of invalid cap')" -eq 0 ]; } && echo "PASS · no MAC/cap fault" || { echo "FAIL · MAC/cap fault"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'SSH SHELL FIDELITY: PASS' || echo 'SSH SHELL FIDELITY: FAIL' ) ==="
echo "(serial: $SLOG · client: $CLOG)"; exit $fail
