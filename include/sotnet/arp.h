/*
 * sotOs · sotNet · N5 · ARP cache header.
 *
 * LRU cache of up to ARP_CACHE_MAX (16) IPv4 → MAC bindings.  Each entry
 * carries a learn timestamp; lookups treat entries older than ARP_TTL_MS
 * (5 minutes) as misses.  Eviction policy on insert: oldest learned_at_ms.
 *
 * Timestamps are produced by a monotonic counter (g_arp_tick) bumped on
 * each learn/lookup operation rather than wall-clock; seL4 muslc has no
 * stable monotonic clock helper exposed in this codebase, and bounded
 * relative ordering is all we need for LRU.
 *
 * Sender learning hook: handle_arp() in src/sotnet/sotnet.c calls
 * arp_cache_learn() before the inline reply logic so we learn the sender
 * MAC of every well-formed ARP frame addressed to our IP — request OR
 * reply.
 */
#ifndef SOTNET_ARP_H
#define SOTNET_ARP_H

#include <stdint.h>

#define ARP_CACHE_MAX 16
#define ARP_TTL_MS    300000   /* 5 minutes */

/* Initialise cache: clears all entries, resets tick counter.  Safe to
 * call multiple times; idempotent. */
void arp_cache_init(void);

/* Insert or refresh a binding.  ip_be is in network byte order; mac is
 * 6 bytes.  If an entry for ip_be already exists, MAC + timestamp are
 * updated in place.  Otherwise the oldest entry (smallest learned_at)
 * is evicted to make room.  Emits:
 *   [arp] learn A.B.C.D → xx:xx:xx:xx:xx:xx
 */
void arp_cache_learn(uint32_t ip_be, const uint8_t mac[6]);

/* Look up a binding.  Returns 0 and writes 6 bytes to out_mac on hit
 * (entry exists and not expired).  Returns -1 on miss. */
int arp_cache_lookup(uint32_t ip_be, uint8_t out_mac[6]);

/* Dump all in-use entries to stdout (sotShell introspection hook).
 * One [arp] cache · slot=i ... line per slot plus a totals line. */
void arp_cache_dump(void);

#endif /* SOTNET_ARP_H */
