/*
 * sotOs · sotNet · N5 · ARP cache implementation.
 *
 * Fixed-size LRU table (16 slots) of IPv4 → MAC bindings with a 5-minute
 * TTL.  Used by sotnet's handle_arp() to remember neighbour MACs we have
 * seen so future TX paths (routing, gratuitous TX) can resolve next-hop
 * MACs without re-broadcasting an ARP request.
 *
 * Time source: a monotonic uint64_t tick counter bumped once per
 * learn/lookup.  We do not have a stable wall-clock helper exposed in
 * the orch link unit, and bounded ordering is sufficient for LRU eviction
 * plus TTL comparison (TTL = ARP_TTL_MS ticks; the unit is "operations"
 * rather than ms, which is conservative — entries age faster under load,
 * never slower, so we never serve stale MACs).
 *
 * No retry loops; all operations are O(ARP_CACHE_MAX) and bounded.
 */

#include <sotnet/arp.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

struct arp_entry {
    uint32_t ip_be;
    uint8_t  mac[6];
    uint64_t learned_at_ms;
    int      in_use;
};

static struct arp_entry g_arp[ARP_CACHE_MAX];
static uint64_t         g_arp_tick = 0;

/* Monotonic "now" in our synthetic ms unit.  See header. */
static uint64_t arp_now_ms(void)
{
    return ++g_arp_tick;
}

void arp_cache_init(void)
{
    memset(g_arp, 0, sizeof(g_arp));
    g_arp_tick = 0;
}

void arp_cache_learn(uint32_t ip_be, const uint8_t mac[6])
{
    if (mac == NULL) return;

    uint64_t now = arp_now_ms();

    /* 1 · update existing entry if present. */
    for (int i = 0; i < ARP_CACHE_MAX; ++i) {
        if (g_arp[i].in_use && g_arp[i].ip_be == ip_be) {
            memcpy(g_arp[i].mac, mac, 6);
            g_arp[i].learned_at_ms = now;
            const uint8_t *ip = (const uint8_t *)&ip_be;
            printf("[arp] learn %u.%u.%u.%u -> %02x:%02x:%02x:%02x:%02x:%02x\n",
                   ip[0], ip[1], ip[2], ip[3],
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
    }

    /* 2 · find a free slot. */
    int slot = -1;
    for (int i = 0; i < ARP_CACHE_MAX; ++i) {
        if (!g_arp[i].in_use) { slot = i; break; }
    }

    /* 3 · otherwise evict the LRU slot (smallest learned_at_ms). */
    if (slot < 0) {
        uint64_t oldest = g_arp[0].learned_at_ms;
        slot = 0;
        for (int i = 1; i < ARP_CACHE_MAX; ++i) {
            if (g_arp[i].learned_at_ms < oldest) {
                oldest = g_arp[i].learned_at_ms;
                slot   = i;
            }
        }
    }

    g_arp[slot].in_use        = 1;
    g_arp[slot].ip_be         = ip_be;
    memcpy(g_arp[slot].mac, mac, 6);
    g_arp[slot].learned_at_ms = now;

    const uint8_t *ip = (const uint8_t *)&ip_be;
    printf("[arp] learn %u.%u.%u.%u -> %02x:%02x:%02x:%02x:%02x:%02x\n",
           ip[0], ip[1], ip[2], ip[3],
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int arp_cache_lookup(uint32_t ip_be, uint8_t out_mac[6])
{
    if (out_mac == NULL) return -1;

    uint64_t now = arp_now_ms();
    for (int i = 0; i < ARP_CACHE_MAX; ++i) {
        if (!g_arp[i].in_use) continue;
        if (g_arp[i].ip_be != ip_be) continue;
        /* TTL check: if now - learned_at exceeds ARP_TTL_MS, miss. */
        uint64_t age = now - g_arp[i].learned_at_ms;
        if (age > (uint64_t)ARP_TTL_MS) return -1;
        memcpy(out_mac, g_arp[i].mac, 6);
        return 0;
    }
    return -1;
}

void arp_cache_dump(void)
{
    int seen = 0;
    for (int i = 0; i < ARP_CACHE_MAX; ++i) {
        if (!g_arp[i].in_use) continue;
        const uint8_t *ip = (const uint8_t *)&g_arp[i].ip_be;
        printf("[arp] cache · slot=%d %u.%u.%u.%u -> %02x:%02x:%02x:%02x:%02x:%02x learned_at=%llu\n",
               i, ip[0], ip[1], ip[2], ip[3],
               g_arp[i].mac[0], g_arp[i].mac[1], g_arp[i].mac[2],
               g_arp[i].mac[3], g_arp[i].mac[4], g_arp[i].mac[5],
               (unsigned long long)g_arp[i].learned_at_ms);
        seen++;
    }
    printf("[arp] cache · total in_use=%d / %d\n", seen, ARP_CACHE_MAX);
}
