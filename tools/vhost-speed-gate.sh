#!/usr/bin/env bash
# sotOs vhost-net · Phase 0/3 SPEED measurement — the spike's decision metric.
# Boots over tap+vhost, SSHes the Debian persona session (the 2nd round-robin),
# times `apt-get update` against the REAL Debian archive, and asserts < 30 s
# (the target; ~5 min under SLIRP iothread-starvation).
#
# Prereq: host fabric up — `sudo tools/net-tap-setup.sh` ONCE (tap + dnsmasq +
# NAT + sotos0 in the trusted firewalld zone).  Runs as the normal user (the tap
# is user-owned; /dev/kvm + /dev/vhost-net are world-rw).
#
# Exit: 0=PASS(<30s)/SKIP(no egress), 1=FAIL(slow or apt error), 2=missing, 3=BLOCKED.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
. "$(dirname "$0")/lib/qemu-net.sh"     # NET_MODE/GUEST_IP/QEMU_NETARGS/SSH_HOST/SSH_PORT_ARG
export SOTOS_NET_MODE=vhost; . "$(dirname "$0")/lib/qemu-net.sh"   # force vhost
TARGET_SECS="${SOTOS_SPEED_TARGET:-30}"
SLOG=/tmp/sotos-vhost-speed-serial.log
ALOG=/tmp/sotos-vhost-speed-sessA.log
BLOG=/tmp/sotos-vhost-speed-sessB.log
ASK=/tmp/sotos-vhost-speed-ask.sh
say(){ printf '%s\n' "$*"; }

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then say "[vhost-speed] BLOCKED: operator QEMU live"; exit 3; fi
ip link show "${SOTOS_TAP:-sotos0}" >/dev/null 2>&1 || { say "[vhost-speed] tap missing · run: sudo tools/net-tap-setup.sh"; exit 2; }
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
  [ -f "$t" ] || { say "[vhost-speed] missing $t · run 'just build'"; exit 2; }; done

rm -f "$SLOG" "$ALOG" "$BLOG"
say "[vhost-speed] booting over $NET_MODE (guest $GUEST_IP)…"
timeout 700 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  $QEMU_NETARGS < /dev/null >"$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 90); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { say "[vhost-speed] FAIL · :22 never LISTENed"; exit 1; }
# Confirm the guest actually leased the tap IP (not the SLIRP fallback).
LC_ALL=C grep -qaE "lease=10\.7\.0\.50" "$SLOG" || say "[vhost-speed] WARN · guest did not lease 10.7.0.50 (DHCP/firewall?) — egress may fail"
sleep 2
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"

run_ssh(){ local log="$1"; shift
  ( for c in "$@"; do printf '%s\n' "$c"; sleep 3; done; printf 'exit\n'; sleep 3 ) | \
    timeout 560 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
    ssh -tt $SSH_PORT_ARG -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 "root@${SSH_HOST}" >"$log" 2>&1 || true
}

say "[vhost-speed] session 1 (Alpine · ignored)…"
run_ssh "$ALOG" 'cat /etc/os-release | head -1'
sleep 2
say "[vhost-speed] session 2 (Debian · timed apt-get update)…"
run_ssh "$BLOG" \
  'echo APT_T0=$(date +%s)' \
  'apt-get update; echo APT_UPDATE_RC=$?' \
  'echo APT_T1=$(date +%s)' \
  'ls /var/lib/apt/lists/ | grep -c _Packages; echo LISTS_DONE'
sleep 2; kill "$QPID" 2>/dev/null

if LC_ALL=C grep -qaiE 'Temporary failure resolving|Could not resolve|Network is unreachable|Cannot initiate' "$BLOG"; then
  say "[vhost-speed] SKIP · archive unreachable from guest egress (vhost NAT/forward?)"; exit 0; fi

T0=$(LC_ALL=C sed -n 's/.*APT_T0=\([0-9]\+\).*/\1/p' "$BLOG" | head -1)
T1=$(LC_ALL=C sed -n 's/.*APT_T1=\([0-9]\+\).*/\1/p' "$BLOG" | head -1)
say ""; say "==== vhost-net apt-get update timing ===="; fail=0
if LC_ALL=C grep -qaE '_Packages' "$BLOG"; then say "  PASS · index downloaded + lists populated (contained)"; else say "  FAIL · lists not populated (egress did not complete)"; fail=1; fi
if [ -n "$T0" ] && [ -n "$T1" ]; then
  SECS=$((T1 - T0))
  say "  apt-get update wall-clock: ${SECS}s (target <${TARGET_SECS}s)"
  if [ "$SECS" -lt "$TARGET_SECS" ]; then say "  PASS · under ${TARGET_SECS}s (vhost)"; else say "  FAIL · ${SECS}s ≥ ${TARGET_SECS}s — vhost did not hit the target"; fail=1; fi
else
  say "  FAIL · could not read APT_T0/APT_T1 timestamps from the session"; fail=1
fi
say ""
[ "$fail" -eq 0 ] && { say "[vhost-speed] PASS"; exit 0; } || { say "[vhost-speed] FAIL"; say "---- session-2 tail ----"; LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG" | tail -25; exit 1; }
