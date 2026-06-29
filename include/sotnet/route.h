/*
 * sotOs · sotNet N4 · routing table + default gateway.
 *
 * Tiny fixed-size routing table consulted by sotnet_send_udp() before
 * pushing a frame on the wire.  The table seeds a single default route
 * (0.0.0.0/0 → 10.0.2.2, MAC 52:55:0a:00:02:02) which matches QEMU's
 * user-mode NAT gateway.  Without this, every outbound UDP frame uses
 * the Ethernet broadcast destination, which QEMU silently drops for
 * non-DHCP traffic.
 *
 * All IP/mask fields are stored in network byte order.  Lookup performs
 * a longest-prefix match (LPM) by walking the static array.  If the
 * matching route has an all-zero gw_mac the lookup returns -1, and the
 * caller falls back to its previous broadcast behaviour.
 *
 * Lazy init: the first call to sotnet_route_lookup() seeds the default
 * route if the table has not yet been populated — no explicit init
 * call required from bootstrap.
 */
#ifndef SOTNET_ROUTE_H
#define SOTNET_ROUTE_H

#include <stdint.h>

#define SOTNET_ROUTE_MAX 8

struct sotnet_route {
    uint32_t dst_be;      /* destination network (network order) */
    uint32_t mask_be;     /* netmask (network order)             */
    uint32_t gw_be;       /* gateway IP (network order, 0 = directly connected) */
    uint8_t  gw_mac[6];   /* cached MAC (0 = unknown, falls back to broadcast)  */
    int      in_use;
};

/*
 * sotnet_route_init: seed the default route 0.0.0.0/0 → 10.0.2.2
 * (MAC 52:55:0a:00:02:02 — QEMU user-mode NAT gateway).  Safe to call
 * multiple times; subsequent calls clear and re-seed the table.
 */
void sotnet_route_init(void);

/*
 * sotnet_route_add: install a route.  dst_be/mask_be/gw_be are in network
 * byte order.  gw_mac is the resolved L2 address (may be all-zero to mean
 * "unknown — fall back to broadcast").  Returns 0 on success, -1 if the
 * table is full.
 */
int sotnet_route_add(uint32_t dst_be, uint32_t mask_be, uint32_t gw_be,
                     const uint8_t gw_mac[6]);

/*
 * sotnet_route_lookup: longest-prefix match against the table.  Copies
 * the matching route's gw_mac into out_eth_mac.  Returns 0 if a route
 * with a known (non-zero) MAC matches, -1 otherwise.  Lazily seeds the
 * default route on first call.
 */
int sotnet_route_lookup(uint32_t dst_ip_be, uint8_t out_eth_mac[6]);

/*
 * sotnet_route_set_default: overwrite the 0.0.0.0/0 default route in place with
 * a learned gateway (gw_be) and its resolved L2 address (gw_mac).  Called once
 * after DHCP+ARP so off-subnet egress targets the REAL next-hop on whatever L2
 * fabric we boot on (SLIRP gateway 10.0.2.2, or a tap gateway 10.7.0.1) rather
 * than only the hardcoded SLIRP gateway seeded by sotnet_route_init().
 */
void sotnet_route_set_default(uint32_t gw_be, const uint8_t gw_mac[6]);

#endif /* SOTNET_ROUTE_H */
