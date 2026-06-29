/* sotOs · procd · event ring publish/consume.
 *
 * Single-writer (procd) / multi-reader (orch, lucas, anomaly) ring
 * mapped inside the 1 MiB SHM region at offset hdr->evring_ofs.
 *
 *   - head_seq is a monotonic uint64 advanced atomically by the writer.
 *   - entries[seq % N] holds the event at sequence seq.
 *   - Readers carry their own tail cursor.  procd_event_drain copies
 *     up to max_n entries [tail, head) into out_buf, advances tail, and
 *     reports OVERFLOW (snapping tail forward) when the consumer lag
 *     exceeds N/2 — i.e. when the ring has wrapped past the reader.
 *
 * Spec: procd-process-server-design §5.2 / §5.3.
 */
#include <string.h>
#include <procd/events.h>
#include <procd/shm.h>

void procd_event_ring_init(procd_event_ring_t *r) {
    memset(r, 0, sizeof(*r));
}

void procd_event_publish(procd_event_ring_t *r, uint32_t kind,
                          uint32_t slot, uint32_t extra32) {
    /* PR 5 fix · single-writer (procd) SPSC publish:
     *   1. Read head (RELAXED) to reserve next slot · no concurrent writer
     *      exists, so no atomicity needed on the reservation itself.
     *   2. Write entry · also no barrier needed because no other writer
     *      can race us.
     *   3. Publish head+1 (RELEASE) so concurrent readers observe the
     *      entry payload BEFORE they observe the head increment.  PR 4's
     *      fetch_add-first ordering let a reader see head=N+1 while
     *      entries[N] still held stale data.
     *
     * Multi-writer would need fetch_add + retry, but procd is the only
     * publisher in sotOs (the IPC dispatcher runs single-threaded). */
    uint64_t head = __atomic_load_n(&r->head_seq, __ATOMIC_RELAXED);
    procd_event_t *e = &r->entries[head & (PROCD_EVENT_RING_N - 1)];
    e->seq     = head;
    e->kind    = kind;
    e->slot    = slot;
    e->extra32 = extra32;
    e->_pad    = 0;
    __atomic_store_n(&r->head_seq, head + 1, __ATOMIC_RELEASE);
}

uint32_t procd_event_drain(const procd_event_ring_t *r, uint64_t *tail,
                            procd_event_t *out_buf, uint32_t max_n,
                            int *out_overflow) {
    *out_overflow = 0;
    uint64_t head = __atomic_load_n(&r->head_seq, __ATOMIC_ACQUIRE);
    if (*tail > head) {
        /* Reader was ahead (e.g. ring re-initialized under us). */
        *tail = head;
        return 0;
    }
    uint64_t lag = head - *tail;
    if (lag > PROCD_EVENT_RING_N / 2) {
        /* Consumer fell more than N/2 behind · oldest entries already
         * overwritten.  Snap tail to (head - N/4) so we resume at the
         * fresher quarter of the ring and let the caller log the drop. */
        *out_overflow = 1;
        *tail = head - PROCD_EVENT_RING_N / 4;
    }
    uint32_t n = 0;
    while (*tail < head && n < max_n) {
        out_buf[n] = r->entries[*tail & (PROCD_EVENT_RING_N - 1)];
        (*tail)++;
        n++;
    }
    return n;
}
