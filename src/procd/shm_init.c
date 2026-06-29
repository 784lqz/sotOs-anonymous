/* sotOs · procd · SHM region initialization.
 *
 * PR 3: the 1 MiB region is a static .bss buffer.  Visible only to procd
 *       itself · sufficient for header dump + slot allocator unit tests.
 * PR 4: ring + ring accessor live alongside the slot tables in the same
 *       static buffer; orch only gets the notification half (NTF-only
 *       fallback, per the implementation plan).  Cross-vspace SHM
 *       mapping is deferred to PR 5 alongside the OP_SPAWN migration.
 *
 * Spec: procd-process-server-design §5.2 / §5.5.
 */
#include <stdint.h>
#include <procd/proc.h>
#include <procd/shm.h>
#include <procd/events.h>

static uint8_t g_shm_buf[PROCD_SHM_BYTES] __attribute__((aligned(4096)));

/* Set by procd_shm_init: the live base — the cross-mapped region when root
 * provided one in argv[4], else the static .bss fallback (NTF-only legacy). */
static void *g_shm_base = (void *)0;

extern void procd_table_init(void *shm_base);

void *procd_shm_init(void *shm_base) {
    void *base = shm_base ? shm_base : (void *)g_shm_buf;
    g_shm_base = base;

    procd_table_init(base);

    /* Initialize the event ring at hdr->evring_ofs (set by procd_table_init). */
    procd_shm_header_t *hdr = (procd_shm_header_t *)base;
    procd_event_ring_t *ring =
        (procd_event_ring_t *)((uint8_t *)base + hdr->evring_ofs);
    procd_event_ring_init(ring);

    return base;
}

procd_event_ring_t *procd_shm_ring(void) {
    void *base = g_shm_base ? g_shm_base : (void *)g_shm_buf;
    procd_shm_header_t *hdr = (procd_shm_header_t *)base;
    if (hdr->magic != PROCD_SHM_MAGIC) return (procd_event_ring_t *)0;
    return (procd_event_ring_t *)((uint8_t *)base + hdr->evring_ofs);
}
