/* sotOs · procd · SHM region layout + seqlock primitives.
 *
 * Spec: procd-process-server-design §5.2 / §5.5.
 */
#ifndef PROCD_SHM_H
#define PROCD_SHM_H

#include <stdint.h>
#include <procd/proc.h>

#define PROCD_SHM_MAGIC      0x50524F43444D3031ULL  /* "PROCDM01" */
#define PROCD_SHM_BYTES      (1u << 20)              /* 1 MiB */
#define PROCD_EVENT_RING_N   1024u                   /* power of two */

typedef struct {
    uint64_t magic;
    uint32_t abi_version;
    uint32_t _pad32;
    uint32_t table_ofs;
    uint32_t table_n;
    uint32_t thread_ofs;
    uint32_t thread_n;
    uint32_t evring_ofs;
    uint32_t evring_n;
    uint32_t scratch_ofs;
    uint32_t scratch_size;
} procd_shm_header_t;

_Static_assert(sizeof(procd_shm_header_t) <= 64, "procd_shm_header_t too large");

/* Seqlock read helper for tier/functor hot path · no IPC. */
static inline proc_tier_t procd_tier_load(const proc_t *p) {
    for (;;) {
        uint64_t v1 = __atomic_load_n(&p->version, __ATOMIC_ACQUIRE);
        if (v1 & 1ull) { __builtin_ia32_pause(); continue; }
        proc_tier_t t = p->tier;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint64_t v2 = __atomic_load_n(&p->version, __ATOMIC_RELAXED);
        if (v1 == v2) return t;
    }
}

/* Bounded variant for hot-ish callers (e.g. the fork path) · returns the
 * tier on a settled read within `max_spins`, or PROC_TIER_0 on timeout
 * (caller treats that as "no Tier-2 signal" and uses its legacy source). */
static inline proc_tier_t procd_tier_load_bounded(const proc_t *p, int max_spins) {
    for (int i = 0; i < max_spins; ++i) {
        uint64_t v1 = __atomic_load_n(&p->version, __ATOMIC_ACQUIRE);
        if (v1 & 1ull) { __builtin_ia32_pause(); continue; }
        proc_tier_t t = p->tier;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint64_t v2 = __atomic_load_n(&p->version, __ATOMIC_RELAXED);
        if (v1 == v2) return t;
    }
    return PROC_TIER_0;
}

/* Seqlock write helpers · only procd is writer. */
static inline void procd_seqlock_begin(proc_t *p) {
    __atomic_fetch_or(&p->version, 1ull, __ATOMIC_RELEASE);
}
static inline void procd_seqlock_end(proc_t *p) {
    __atomic_fetch_add(&p->version, 1ull, __ATOMIC_RELEASE);
}

#endif /* PROCD_SHM_H */
