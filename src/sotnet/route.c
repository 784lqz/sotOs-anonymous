/*
 * sotOs · sotNet N4 · routing table + default gateway.
 *
 * See include/sotnet/route.h for the high-level contract.
 *
 * Implementation notes:
 *   · Fixed array of 8 routes (SOTNET_ROUTE_MAX).  Plenty for the
 *     v0.7 demo (one default route covers every outbound packet today).
 *   · Lookup walks the array and picks the entry with the longest mask
 *     that matches (dst & mask) == route->dst.  This makes a future
 *     subnet route (e.g. 10.0.2.0/24 → directly connected) automatically
 *     win over the default 0/0 entry once it is added.
 *   · Lazy init flag g_inited keeps callers from having to thread an
 *     explicit init step through bootstrap.c (which is owned by N1).
 */

#include <sotnet/route.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* v2.9 · operator `watch` quiet mode · suppress the per-packet route trace.
 * route_lookup runs on EVERY off-subnet TX (every TCP segment / UDP datagram),
 * so its trace is a firehose on a busy egress (apt download).  Gate it. */
extern int g_orch_quiet;

static struct sotnet_route g_routes[SOTNET_ROUTE_MAX];
static int                 g_inited = 0;

/* Count of set bits in a 32-bit value — used as longest-prefix metric.
 * Netmasks are contiguous, so this is equivalent to the prefix length. */
static int popcount32(uint32_t v)
{
    int c = 0;
    while (v) { c += (int)(v & 1u); v >>= 1; }
    return c;
}

static int mac_is_zero(const uint8_t mac[6])
{
    for (int i = 0; i < 6; ++i) if (mac[i] != 0) return 0;
    return 1;
}

void sotnet_route_init(void)
{
    memset(g_routes, 0, sizeof(g_routes));

    /* Default route: 0.0.0.0/0 → 10.0.2.2 (QEMU user-mode NAT gateway).
     *
     * 10.0.2.2 in network byte order = 0x0202000A on little-endian (the
     * bytes on the wire are 0x0A, 0x00, 0x02, 0x02 — IP[0]..IP[3]).
     * The QEMU virtio-net device assigns MAC 52:55:0A:00:02:02 to the
     * gateway endpoint (see hw/net/net_init.c in QEMU). */
    static const uint8_t gw_mac[6] = {0x52, 0x55, 0x0A, 0x00, 0x02, 0x02};
    uint32_t gw_be = 0x0202000Au;

    g_routes[0].in_use  = 1;
    g_routes[0].dst_be  = 0;
    g_routes[0].mask_be = 0;
    g_routes[0].gw_be   = gw_be;
    memcpy(g_routes[0].gw_mac, gw_mac, 6);

    g_inited = 1;
    printf("[route] init · default 0.0.0.0/0 → 10.0.2.2 mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]);
}

int sotnet_route_add(uint32_t dst_be, uint32_t mask_be, uint32_t gw_be,
                     const uint8_t gw_mac[6])
{
    if (!g_inited) sotnet_route_init();
    for (int i = 0; i < SOTNET_ROUTE_MAX; ++i) {
        if (g_routes[i].in_use) continue;
        g_routes[i].in_use  = 1;
        g_routes[i].dst_be  = dst_be & mask_be;   /* normalise */
        g_routes[i].mask_be = mask_be;
        g_routes[i].gw_be   = gw_be;
        if (gw_mac) memcpy(g_routes[i].gw_mac, gw_mac, 6);
        else        memset(g_routes[i].gw_mac, 0, 6);
        return 0;
    }
    return -1;   /* table full */
}

int sotnet_route_lookup(uint32_t dst_ip_be, uint8_t out_eth_mac[6])
{
    if (!g_inited) sotnet_route_init();

    int  best        = -1;
    int  best_prefix = -1;

    for (int i = 0; i < SOTNET_ROUTE_MAX; ++i) {
        if (!g_routes[i].in_use) continue;
        if ((dst_ip_be & g_routes[i].mask_be) != g_routes[i].dst_be) continue;
        int prefix = popcount32(g_routes[i].mask_be);
        if (prefix > best_prefix) {
            best_prefix = prefix;
            best        = i;
        }
    }

    if (best < 0) return -1;
    if (mac_is_zero(g_routes[best].gw_mac)) return -1;

    if (out_eth_mac) memcpy(out_eth_mac, g_routes[best].gw_mac, 6);

    /* Print dst IP bytes from network-order uint32 (LSB first on x86). */
    if (!g_orch_quiet) {
        const uint8_t *dip = (const uint8_t *)&dst_ip_be;
        const uint8_t *gip = (const uint8_t *)&g_routes[best].gw_be;
        const uint8_t *m   = g_routes[best].gw_mac;
        printf("[route] dst=%u.%u.%u.%u → gw=%u.%u.%u.%u mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
               dip[0], dip[1], dip[2], dip[3],
               gip[0], gip[1], gip[2], gip[3],
               m[0], m[1], m[2], m[3], m[4], m[5]);
    }
    return 0;
}

void sotnet_route_set_default(uint32_t gw_be, const uint8_t gw_mac[6])
{
    if (!g_inited) sotnet_route_init();

    /* Overwrite the default 0.0.0.0/0 route (route[0], seeded by route_init)
     * in place so the learned gateway wins for every off-subnet destination. */
    g_routes[0].in_use  = 1;
    g_routes[0].dst_be  = 0;
    g_routes[0].mask_be = 0;
    g_routes[0].gw_be   = gw_be;
    if (gw_mac) memcpy(g_routes[0].gw_mac, gw_mac, 6);

    const uint8_t *g = (const uint8_t *)&gw_be;
    const uint8_t *m = g_routes[0].gw_mac;
    printf("[route] default gw learned · %u.%u.%u.%u mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           g[0], g[1], g[2], g[3], m[0], m[1], m[2], m[3], m[4], m[5]);
}
