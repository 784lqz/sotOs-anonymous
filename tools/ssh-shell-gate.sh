#!/usr/bin/env bash
# sotOs · SSH channel Phase-A gate (v0.83.0-ssh-channel)
#
# A real OpenSSH client connects to the honeypot's :22 (hostfwd :18022), is
# rejected twice, then ACCEPTED on the 3rd password attempt, opens a session
# channel + pty + shell, and gets its typed bytes ECHOED back over the
# encrypted SSH transport. Proves the RFC 4254 connection layer end-to-end.
#
# Boots the honeypot itself (background), waits for the inbound LISTEN marker,
# runs ONE ssh (the responder is one-shot per boot). NEVER pkills operator QEMU.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
PORT=18022
SLOG=/tmp/sotos-ssh-shell-serial.log
CLOG=/tmp/sotos-ssh-shell-client.log

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[ssh-shell-gate] BLOCKED: operator QEMU live (sotfs.img write lock)."; exit 3
fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[ssh-shell-gate] missing $t — run 'just build'"; exit 2; }
done

rm -f "$SLOG" "$CLOG"
echo "[ssh-shell-gate] booting honeypot (background)..."
timeout 150 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 < /dev/null > "$SLOG" 2>&1 &
QEMU_PID=$!
cleanup() { kill "$QEMU_PID" 2>/dev/null; }
trap cleanup EXIT

# wait for the inbound stack to LISTEN on :22
for i in $(seq 1 60); do
    LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break
    sleep 1
done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[ssh-shell-gate] FAIL · :22 never LISTENed"; tail -5 "$SLOG"; exit 1; }
sleep 2
echo "[ssh-shell-gate] :22 LISTEN · connecting ssh -tt (3 password prompts)..."

# Auth policy = reject 2× then accept on the 3rd → the client must RE-SEND the
# password after each rejection. sshpass bails after the 1st prompt (assumes a
# wrong password), so use SSH_ASKPASS (ssh invokes it for EACH of the
# NumberOfPasswordPrompts=3 prompts). setsid -w detaches the controlling tty so
# ssh uses ASKPASS for auth; -tt still requests a remote pty for the session.
ASKPASS=/tmp/sotos-askpass.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASKPASS"; chmod +x "$ASKPASS"
timeout 40 env SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE=force setsid -w \
    ssh -tt -p "$PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 \
    root@127.0.0.1 <<< $'echo SOTMARKER-ALIVE' > "$CLOG" 2>&1 || true

echo "=== SSH channel Phase-A gate ==="
fail=0
sg() { LC_ALL=C grep -ac "$1" "$SLOG"; }
cg() { LC_ALL=C grep -aic "$1" "$CLOG"; }
creds=$(sg '\[synth-srv\] SSH cred conn=')
[ "$creds" -ge 1 ] && echo "PASS · credential capture fired ($creds attempt(s) logged)" || { echo "FAIL · no SSH cred capture in serial"; fail=1; }
# auth success: the client got past the password prompts (no infinite Permission denied)
if [ "$(cg 'Permission denied')" -ge 1 ] && [ "$creds" -ge 2 ]; then
    echo "PASS · auth rejected then accepted (2 fails logged, client proceeded)"
elif [ "$(cg 'Authenticated')" -ge 1 ]; then
    echo "PASS · ssh reports Authenticated"
else
    echo "WARN · could not confirm auth-success transition (check $CLOG)"
fi
# channel echo round-trip
[ "$(cg 'SOTMARKER-ALIVE')" -ge 1 ] && echo "PASS · CHANNEL_DATA echo round-tripped (SOTMARKER-ALIVE)" || { echo "FAIL · no channel echo (CHANNEL framing?)"; fail=1; }
# no codec/crypto breakage
[ "$(cg 'Corrupted MAC')" -eq 0 ] && [ "$(cg 'message authentication')" -eq 0 ] && echo "PASS · no MAC corruption" || { echo "FAIL · MAC corruption"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'SSH CHANNEL PHASE-A: PASS' || echo 'SSH CHANNEL PHASE-A: FAIL' ) ==="
echo "(serial: $SLOG · client: $CLOG)"
exit $fail
