#!/usr/bin/env bash
# sotOs vhost-net spike · DHCP boundary capture.
# Run as root:  sudo bash tools/dhcp-spike-capture.sh
#
# Boots sotOs once over the tap+vhost netdev while tcpdump watches sotos0, so we
# can see whether the guest's DHCP DISCOVER (and any ARP) actually reaches the
# host tap — and if so, whether dnsmasq answers. Decodes the pcap at the end.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
TAP=sotos0
BUILD=build
PCAP=/tmp/dhcp-cap.pcap
SERIAL=/tmp/spike-serial2.log
BOOT_SECS=60

command -v tcpdump >/dev/null || { echo "tcpdump not installed"; exit 1; }
[ -f "$BUILD/images/sotOs-root-image-x86_64-pc99" ] || { echo "build first"; exit 1; }

# Make sure the tap is administratively up (carrier appears when QEMU attaches).
ip link set "$TAP" up 2>/dev/null || true

echo "[cap] starting tcpdump on $TAP (arp + bootp + icmp6) ..."
tcpdump -i "$TAP" -nev -s0 -w "$PCAP" \
    'arp or (udp and (port 67 or port 68)) or icmp6' >/tmp/tcpdump.log 2>&1 &
TCPDUMP_PID=$!
sleep 1

# Run QEMU as the invoking (non-root) user: the tap is user-owned and
# /dev/kvm + /dev/vhost-net are world-rw, so QEMU works unprivileged. Running it
# as root under sudo produced zero serial output (SELinux/root quirk), so drop.
RUN_USER="${SUDO_USER:-lkz}"
echo "[cap] booting sotOs over tap+vhost for ${BOOT_SECS}s as user $RUN_USER ..."
runuser -u "$RUN_USER" -- timeout "$BOOT_SECS" qemu-system-x86_64 \
    -m 4096 -display none -serial stdio \
    -enable-kvm -cpu host \
    -kernel "$BUILD/images/kernel-x86_64-pc99" \
    -initrd "$BUILD/images/sotOs-root-image-x86_64-pc99" \
    -drive file="$BUILD/images/sotfs.img",format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev tap,id=net0,ifname="$TAP",script=no,downscript=no,vhost=on \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    > "$SERIAL" 2>&1 || true

sleep 1
kill "$TCPDUMP_PID" 2>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null
chmod a+r "$PCAP" "$SERIAL" 2>/dev/null

echo ""
echo "=== guest virtio-net + dhcp (serial) ==="
grep -aniE "virtio-net|dhcp|sotnet|tcp-server|route" "$SERIAL" | head -25
echo ""
echo "=== frames seen on $TAP (tcpdump decode) ==="
tcpdump -nev -r "$PCAP" 2>/dev/null | head -60
echo ""
echo "=== DHCP/BOOTP only ==="
tcpdump -nev -r "$PCAP" '(udp and (port 67 or port 68))' 2>/dev/null | head -20
echo ""
echo "pcap=$PCAP  serial=$SERIAL"
