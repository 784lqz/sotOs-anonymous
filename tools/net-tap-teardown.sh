#!/usr/bin/env bash
# sotOs vhost-net fabric · teardown.
set -uo pipefail
TAP=sotos0; SUBNET=10.7.0.0/24
UPLINK="$(ip route show default | awk '/default/{print $5; exit}')"
[ -f /tmp/sotos-dnsmasq.pid ] && kill "$(cat /tmp/sotos-dnsmasq.pid)" 2>/dev/null && rm -f /tmp/sotos-dnsmasq.pid
iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i "$TAP" -s "$SUBNET" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o "$TAP" -d "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
ip link del "$TAP" 2>/dev/null || true
echo "[net-tap-teardown] sotos0 removed · OK"
