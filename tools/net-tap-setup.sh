#!/usr/bin/env bash
# sotOs vhost-net fabric · idempotent. Run ONCE per host session (sudo).
# Creates a user-owned tap so QEMU later opens it UNPRIVILEGED.
set -euo pipefail
TAP=sotos0; SUBNET=10.7.0.0/24; HOSTIP=10.7.0.1/24
OWNER="${SUDO_USER:-$USER}"
UPLINK="$(ip route show default | awk '/default/{print $5; exit}')"

ip link show "$TAP" >/dev/null 2>&1 || ip tuntap add dev "$TAP" mode tap user "$OWNER"
# `replace` is idempotent (add-if-absent, no error if present) — avoids the
# `ip addr show | grep -q` guard, which under `set -o pipefail` mis-fired:
# grep -q exits early → SIGPIPE on `ip addr show` → pipe seen as failed → the
# `|| ip addr add` ran on an already-assigned address and aborted the script.
ip addr replace "$HOSTIP" dev "$TAP"
ip link set "$TAP" up
sysctl -wq net.ipv4.ip_forward=1

# firewalld root-cause fix: an unassigned interface falls into the default zone,
# which on many hosts only accepts inbound on ports 1025-65535 — so the
# guest's DHCP DISCOVER (udp/67) and DNS (udp/53) to dnsmasq on this tap get
# DROPPED before they reach it.  sotos0 is an internal, host-controlled NAT
# subnet, so put it in the `trusted` zone (accept all) — that lets DHCP/DNS and
# any honeypot inbound through.  No-op if firewalld is absent.
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  firewall-cmd --zone=trusted --change-interface="$TAP" >/dev/null 2>&1 \
    || firewall-cmd --zone=trusted --add-interface="$TAP" >/dev/null 2>&1 || true
fi

iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE
iptables -C FORWARD -i "$TAP" -s "$SUBNET" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "$TAP" -s "$SUBNET" -j ACCEPT
iptables -C FORWARD -o "$TAP" -d "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -o "$TAP" -d "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT

if [ ! -f /tmp/sotos-dnsmasq.pid ] || ! kill -0 "$(cat /tmp/sotos-dnsmasq.pid 2>/dev/null)" 2>/dev/null; then
  dnsmasq --conf-file="$(dirname "$0")/net-dnsmasq.conf"
fi
echo "[net-tap-setup] sotos0 up · guest IP 10.7.0.50 · uplink $UPLINK · OK"
