#!/usr/bin/env bash
# sotOs vhost-net · RAW egress throughput — the spike's real speed number,
# isolated from apt's machinery (apt confounds it: ENOSPC on the session cap +
# the http-method pipe-IPC stall).  Boots tap+vhost, SSHes a honey session, and
# times a `wget -O /dev/null` of a real ~9 MB file from the Debian CDN. Discards
# the body so the per-session upper never fills.
#
# Prereq: `sudo tools/net-tap-setup.sh` once.  Runs as the normal user.
# Baseline to beat: SLIRP measured ~2574 B/s on the same CDN (≈ apt's ~5 min).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
export SOTOS_NET_MODE=vhost; . "$(dirname "$0")/lib/qemu-net.sh"
# Default target: a file served BY THE HOST on the tap IP (guest↔host over
# vhost · no DNS/NAT/CDN) — the purest inbound-throughput measurement. Start it
# first:  python3 -m http.server 8099 --bind 10.7.0.1 --directory /tmp
# with a known-size file (set SOTOS_DL_BYTES to its size for the rate calc).
URL="${SOTOS_DL_URL:-http://10.7.0.1:8099/sotos-bigfile.bin}"
DL_BYTES="${SOTOS_DL_BYTES:-50000000}"
SLOG=/tmp/sotos-vhost-tput-serial.log; BLOG=/tmp/sotos-vhost-tput-sess.log
ASK=/tmp/sotos-vhost-tput-ask.sh
say(){ printf '%s\n' "$*"; }

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then say "[vhost-tput] BLOCKED: operator QEMU live"; exit 3; fi
ip link show "${SOTOS_TAP:-sotos0}" >/dev/null 2>&1 || { say "[vhost-tput] tap missing · run: sudo tools/net-tap-setup.sh"; exit 2; }
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
  [ -f "$t" ] || { say "[vhost-tput] missing $t"; exit 2; }; done

rm -f "$SLOG" "$BLOG"
say "[vhost-tput] booting over $NET_MODE (guest $GUEST_IP)…"
timeout 400 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  $QEMU_NETARGS < /dev/null >"$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 90); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { say "[vhost-tput] FAIL · :22 never LISTENed"; exit 1; }
LC_ALL=C grep -qaE "lease=10\.7\.0\.50" "$SLOG" || say "[vhost-tput] WARN · no 10.7.0.50 lease"
sleep 2
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"

# Bracket the transfer with the guest's own clock (rdtsc wall-clock) so the rate
# is robust regardless of busybox's progress rendering. -O /dev/null discards.
( printf 'echo DL_T0=$(date +%%s); busybox wget -O /dev/null %s 2>&1; echo DL_RC=$?; echo DL_T1=$(date +%%s)\n' "$URL"; sleep 90; printf 'exit\n'; sleep 2 ) | \
  timeout 160 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -tt $SSH_PORT_ARG -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 "root@${SSH_HOST}" >"$BLOG" 2>&1 || true
sleep 1; kill "$QPID" 2>/dev/null

say ""; say "==== vhost-net raw throughput (guest↔host over tap) ===="
clean(){ LC_ALL=C sed 's/\r/\n/g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG"; }
clean | grep -aiE "DL_RC|DL_T0|DL_T1|wget:|%|saved|written|[0-9]+[kKmM] " | grep -vE "askpass|Permission denied|date \+" | tail -12
T0=$(clean | sed -n 's/^DL_T0=\([0-9]\+\).*/\1/p' | head -1)
T1=$(clean | sed -n 's/^DL_T1=\([0-9]\+\).*/\1/p' | head -1)
RC=$(clean | sed -n 's/^DL_RC=\([0-9]\+\).*/\1/p' | head -1)
say ""
# busybox wget -O /dev/null returns RC=1 on success (a /dev/null write quirk), so
# compute whenever both timestamps landed — T1 is only echoed once wget returns.
if [ -n "$T0" ] && [ -n "$T1" ]; then
  SECS=$((T1 - T0)); [ "$SECS" -lt 1 ] && SECS=1
  BPS=$((DL_BYTES / SECS)); KBPS=$((BPS / 1000)); MBPS=$(( (BPS * 10) / 1000000 ))
  say "  ${DL_BYTES} bytes in ${SECS}s  →  ${KBPS} KB/s (~${MBPS}/10 MB/s · DL_RC=${RC:-?})"
  say "  SLIRP baseline (measured): ~2574 B/s  →  vhost ~$((BPS/2574))× faster"
else
  say "  could not compute (DL_RC=${RC:-?} T0=${T0:-?} T1=${T1:-?}) — see $BLOG"
fi
