#!/usr/bin/env bash
# sotOs vhost-net · Phase 2 verification (runs as the normal user — NO sudo).
# Prereq: the host fabric is up — run `sudo tools/net-tap-setup.sh` ONCE first
# (creates the user-owned tap, dnsmasq, NAT, and puts sotos0 in the trusted
# firewalld zone so DHCP/DNS reach dnsmasq).
#
# Boots sotOs over tap+vhost and asserts the guest:
#   1. DHCP-leases 10.7.0.50 (not the SLIRP fallback 10.0.2.15),
#   2. ARP-resolves the gateway 10.7.0.1,
#   3. installs it as the default route.
set -uo pipefail
cd "$(dirname "$0")/.."
BUILD=build; TAP=sotos0; SERIAL=/tmp/vhost-verify.log; BOOT_SECS=70

[ -f "$BUILD/images/sotOs-root-image-x86_64-pc99" ] || { echo "build first: just build"; exit 1; }
ip link show "$TAP" >/dev/null 2>&1 || { echo "tap $TAP missing · run: sudo tools/net-tap-setup.sh"; exit 1; }

echo "[verify] booting sotOs over tap+vhost (${BOOT_SECS}s) ..."
timeout "$BOOT_SECS" qemu-system-x86_64 \
    -m 4096 -display none -serial stdio \
    -enable-kvm -cpu host \
    -kernel "$BUILD/images/kernel-x86_64-pc99" \
    -initrd "$BUILD/images/sotOs-root-image-x86_64-pc99" \
    -drive file="$BUILD/images/sotfs.img",format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev tap,id=net0,ifname="$TAP",script=no,downscript=no,vhost=on \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    < /dev/null > "$SERIAL" 2>&1 || true

echo ""
echo "=== network bring-up (serial) ==="
grep -aniE "dhcp\]|arp\] learn|route\] (init|default)|sotnet\] init|N2 inbound" "$SERIAL" | head -25
echo ""
echo "=== verdict ==="
pass=0
grep -aqE "lease=10\.7\.0\.50"            "$SERIAL" && { echo "  PASS · DHCP leased 10.7.0.50"; } || { echo "  FAIL · no 10.7.0.50 lease (DHCP/firewall?)"; pass=1; }
grep -aqE "arp\] learn 10\.7\.0\.1"       "$SERIAL" && { echo "  PASS · gateway 10.7.0.1 ARP-resolved"; } || { echo "  FAIL · gateway not ARP-resolved"; pass=1; }
grep -aqE "default gw learned · 10\.7\.0\.1" "$SERIAL" && { echo "  PASS · default route installed"; } || { echo "  FAIL · default route not set"; pass=1; }
echo ""
[ "$pass" = 0 ] && echo "VHOST PHASE-2 VERIFY: PASS" || echo "VHOST PHASE-2 VERIFY: FAIL (serial=$SERIAL)"
exit "$pass"
