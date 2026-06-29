/* sotOs · procd · event ring kinds + publish/consume API.
 *
 * Spec: procd-process-server-design §5.3 / §8.3.
 */
#ifndef PROCD_EVENTS_H
#define PROCD_EVENTS_H

#include <stdint.h>
#include <procd/shm.h>  /* PROCD_EVENT_RING_N */

typedef enum {
    /* Lifecycle */
    PROCD_EV_PROC_BORN          = 0x10,
    PROCD_EV_PROC_EXITED        = 0x11,
    PROCD_EV_PROC_REAPED        = 0x12,
    PROCD_EV_THREAD_BORN        = 0x13,
    PROCD_EV_THREAD_EXITED      = 0x14,
    PROCD_EV_SIGCHLD            = 0x15,
    PROCD_EV_EXEC_OK            = 0x16,

    /* Tier / functor mutation */
    PROCD_EV_TIER_CHANGED       = 0x20,
    PROCD_EV_FUNCTOR_REBOUND    = 0x21,
    PROCD_EV_SYNTH_FORK       = 0x22,
    PROCD_EV_DENIED_TIER3       = 0x23,

    /* Recoverable errors */
    PROCD_EV_TABLE_FULL         = 0x30,
    PROCD_EV_KMEM_EXHAUSTED     = 0x31,
    PROCD_EV_BADGE_REJECT       = 0x32,
    PROCD_EV_CLONE_FLAG_ENOSYS  = 0x33,
    PROCD_EV_EXEC_FAIL          = 0x34,

    /* System */
    PROCD_EV_RING_OVERFLOW      = 0x40,
    PROCD_EV_CONSUMER_LAG       = 0x41,
} procd_event_kind_t;

typedef struct {
    uint64_t seq;
    uint32_t kind;
    uint32_t slot;
    uint32_t extra32;
    uint32_t _pad;
} procd_event_t;

_Static_assert(sizeof(procd_event_t) == 24, "procd_event_t size must be 24");

/* PR 4 · event ring layout living inside the SHM region at offset
 * hdr->evring_ofs.  Single writer (procd) / multi reader (orch, lucas,
 * anomaly).  head_seq is monotonic; entry index = seq % N.
 * Readers maintain their own tail cursor; if they lag more than N/2
 * behind, procd_event_drain reports OVERFLOW and the tail snaps
 * forward (dropping the oldest entries). */
typedef struct {
    volatile uint64_t head_seq;       /* writer cursor; monotonic */
    uint64_t          _pad[7];        /* cacheline separation */
    procd_event_t     entries[PROCD_EVENT_RING_N];
} procd_event_ring_t;

void     procd_event_ring_init(procd_event_ring_t *r);
void     procd_event_publish (procd_event_ring_t *r, uint32_t kind,
                                uint32_t slot, uint32_t extra32);
uint32_t procd_event_drain   (const procd_event_ring_t *r, uint64_t *tail,
                                procd_event_t *out_buf, uint32_t max_n,
                                int *out_overflow);

/* PR 4 · accessor implemented by shm_init.c; returns NULL before
 * procd_shm_init() has been invoked.  Only meaningful inside procd
 * itself (orch/anomaly/lucas get the base via root delegation). */
procd_event_ring_t *procd_shm_ring(void);

#endif /* PROCD_EVENTS_H */
