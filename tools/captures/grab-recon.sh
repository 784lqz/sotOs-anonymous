#!/usr/bin/env bash
# grab-recon.sh — REAL capture of Scenario B (external recon).  Boots sotOs
# headless (TCG) with QEMU hostfwd (:18443→443, :18022→22, :18080→80), then drives
# REAL host-side attacker probes (openssl TLS 1.3 handshake + ssh recon session)
# against the deception host, captures BOTH the attacker transcript and the operator
# serial (sottrace / SSH cred capture / canary / containment), and renders the real
# sottrace netgraph from the captured serial.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
SLOG="${1:-build/capture-recon-serial.log}"
CLOG=build/capture-recon-client.log
ASK=/tmp/sotos-recon-askpass.sh
P443=18443; P22=18022; P80=18080
pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
sleep 1
rm -f "$SLOG" "$CLOG"; : > "$SLOG"; : > "$CLOG"

waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qaE "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[recon] booting headless TCG · hostfwd :$P443→443 :$P22→22 :$P80→80 …"
timeout 900 qemu-system-x86_64 -m 2048 -display none -accel tcg -cpu max \
  -serial "file:$SLOG" \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::$P443-:443,hostfwd=tcp::$P22-:22,hostfwd=tcp::$P80-:80 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 &
QP=$!
trap 'kill $QP 2>/dev/null' EXIT

waitfor 'N2 inbound LISTEN|inbound bytepipe ready|inbound LISTEN' 600 || {
  echo "[recon] inbound services never came up · tail:"; tail -10 "$SLOG"; exit 1; }
echo "[recon] inbound services up"; sleep 3

{
echo "######## ATTACKER · port liveness (bash /dev/tcp) ########"
for p in $P22 $P443 $P80; do
  (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && { echo "127.0.0.1:$p OPEN"; exec 3>&- 3<&-; } || echo "127.0.0.1:$p closed"
done
echo
echo "######## ATTACKER · TLS 1.3 handshake (openssl s_client) :443 ########"
printf 'GET / HTTP/1.0\r\nHost: honeypot\r\n\r\n' | \
  timeout 25 openssl s_client -connect 127.0.0.1:$P443 -tls1_3 -servername honeypot -ign_eof 2>&1 | \
  grep -iE 'Protocol|Cipher *:|subject=|issuer=|verify (return|error)|Server (public|Temp)|TLSv1.3|New,' | head -12
echo
echo "######## ATTACKER · SSH banner (ssh-keyscan) :22 ########"
timeout 20 ssh-keyscan -p $P22 -t ssh-ed25519,rsa 127.0.0.1 2>&1 | head -6
echo
echo "######## ATTACKER · SSH recon session (real ssh -tt, password auth) ########"
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
( sleep 3; printf 'whoami\n'; sleep 2; printf 'id\n'; sleep 2; printf 'uname -a\n'; sleep 2;
  printf 'cat /etc/passwd\n'; sleep 3; printf 'echo BACKDOOR > /etc/cron.d/persist\n'; sleep 3;
  printf 'exit\n'; sleep 3 ) | \
  timeout 90 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -tt -p $P22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 root@127.0.0.1 2>&1 | head -40
} | tee "$CLOG"
sleep 3

echo
echo "######## OPERATOR · sottrace / cred-capture / canary / containment (serial) ########"
LC_ALL=C grep -anE '\[sottrace\]|ACCEPT from|RESPONSE_PROFILE|SSH cred|user=.*pass=|\[canary\]|silenced|ISOLATED_WRITE|inbound LISTEN|inbound bytepipe|persona|ja3s|JA3S' "$SLOG" | head -50

echo
echo "######## OPERATOR · render the real sottrace netgraph ########"
python3 tools/sottrace_netgraph.py "$SLOG" || echo "[recon] (no sottrace edges parsed)"
[ -f sottrace.netgraph.dot ] && cp -f sottrace.netgraph.dot docs/captures/sottrace.netgraph.real.dot
echo "[recon] serial=$SLOG ($(wc -l < "$SLOG") lines) · client=$CLOG"
kill $QP 2>/dev/null
