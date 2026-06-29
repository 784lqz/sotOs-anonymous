/* sotOs · procd · proc/thread slot allocator backed by SHM.
 *
 * The table lives in the SHM region (see shm_init.c).  Slot 0 of the
 * proc table is reserved as the "no parent" anomaly (ppid for the
 * root of the process tree); slot 0 of the thread table is reserved
 * symmetrically.  PIDs / TIDs are minted monotonically starting at 1.
 *
 * Only procd writes to these tables; readers (orch / anomaly / lucas
 * / sotfs / sotnet / synth) use the seqlock helpers in
 * <procd/shm.h> to observe a coherent snapshot.
 *
 * Spec: procd-process-server-design §5.5.
 */
#include <string.h>
#include <procd/proc.h>
#include <procd/shm.h>
#include <procd/events.h>

static procd_shm_header_t *g_hdr;
static proc_t   *g_procs;
static thread_t *g_threads;
static uint32_t  g_next_pid = 1;
static uint32_t  g_next_tid = 1;

void procd_table_init(void *shm_base) {
    g_hdr = (procd_shm_header_t *)shm_base;
    g_hdr->magic       = PROCD_SHM_MAGIC;
    g_hdr->abi_version = PROCD_ABI_VERSION;
    g_hdr->_pad32      = 0;
    g_hdr->table_ofs   = 64;
    g_hdr->table_n     = PROCD_MAX_PROCS;
    g_hdr->thread_ofs  = 64 + sizeof(proc_t) * PROCD_MAX_PROCS;
    g_hdr->thread_n    = PROCD_MAX_THREADS;
    g_hdr->evring_ofs  = g_hdr->thread_ofs + sizeof(thread_t) * PROCD_MAX_THREADS;
    g_hdr->evring_n    = PROCD_EVENT_RING_N;
    /* PR 5 fix · scratch_ofs must advance past the full procd_event_ring_t
     * structure.  The previous formula (16 + 24*N) undersized by 48 bytes
     * because procd_event_ring_t carries a 56-byte cacheline pad (_pad[7])
     * not 8.  Using sizeof keeps offset arithmetic in lock-step with the
     * struct definition for future layout edits. */
    g_hdr->scratch_ofs = g_hdr->evring_ofs + sizeof(procd_event_ring_t);
    g_hdr->scratch_size = PROCD_SHM_BYTES - g_hdr->scratch_ofs;

    g_procs   = (proc_t *)((uint8_t *)shm_base + g_hdr->table_ofs);
    g_threads = (thread_t *)((uint8_t *)shm_base + g_hdr->thread_ofs);

    memset(g_procs,   0, sizeof(proc_t)   * PROCD_MAX_PROCS);
    memset(g_threads, 0, sizeof(thread_t) * PROCD_MAX_THREADS);

    g_procs[0].state = PROC_STATE_DEAD;  /* slot 0 reserved · "no parent" */
    g_procs[0].slot  = 0;

    /* Reset PID counter so deterministic tests don't drift across init calls. */
    g_next_pid = 1;
    g_next_tid = 1;
}

int procd_slot_alloc(uint32_t *out_slot) {
    if (!out_slot) return -1;
    for (uint32_t i = 1; i < PROCD_MAX_PROCS; i++) {
        if (g_procs[i].state == PROC_STATE_FREE) {
            memset(&g_procs[i], 0, sizeof(proc_t));
            g_procs[i].slot     = i;
            g_procs[i].synthetic_pid = g_next_pid++;
            g_procs[i].state    = PROC_STATE_NASCENT;
            *out_slot = i;
            return 0;
        }
    }
    return -1;
}

int procd_slot_free(uint32_t slot) {
    if (slot == 0 || slot >= PROCD_MAX_PROCS) return -1;
    memset(&g_procs[slot], 0, sizeof(proc_t));
    g_procs[slot].state = PROC_STATE_FREE;
    return 0;
}

int procd_thread_alloc(uint32_t *out_tslot) {
    if (!out_tslot) return -1;
    for (uint32_t i = 1; i < PROCD_MAX_THREADS; i++) {
        if (g_threads[i].state == 0 && g_threads[i].tid == 0) {
            memset(&g_threads[i], 0, sizeof(thread_t));
            g_threads[i].tid    = g_next_tid++;
            g_threads[i].state  = 1; /* running */
            *out_tslot = i;
            return 0;
        }
    }
    return -1;
}

int procd_thread_free(uint32_t tslot) {
    if (tslot == 0 || tslot >= PROCD_MAX_THREADS) return -1;
    memset(&g_threads[tslot], 0, sizeof(thread_t));
    return 0;
}

/* PR 8 · thread_t accessors for OP_CLONE / OP_THREAD_EXIT handlers.
 *
 * procd_thread_at_index returns the thread_t at slot `i` (slot 0 is the
 * "no thread" anomaly · NULL is returned for it and any out-of-range
 * index).  procd_thread_by_tid does a linear scan over the thread table
 * to translate a synthetic_tid (assigned by procd_thread_alloc's monotonic
 * counter) back to the owning slot · O(N) over PROCD_MAX_THREADS which
 * is acceptable for the smoke / demo budget today.  PR 13's robust-list
 * cleanup will revisit if the scan becomes hot. */
thread_t *procd_thread_at_index(uint32_t i) {
    if (i == 0 || i >= PROCD_MAX_THREADS) return NULL;
    return &g_threads[i];
}

thread_t *procd_thread_by_tid(uint32_t tid) {
    if (tid == 0) return NULL;
    for (uint32_t i = 1; i < PROCD_MAX_THREADS; i++) {
        if (g_threads[i].tid == tid) return &g_threads[i];
    }
    return NULL;
}

proc_t *procd_table_get(uint32_t slot) {
    if (slot >= PROCD_MAX_PROCS) return NULL;
    return &g_procs[slot];
}

/* PR 6 · OP_WAIT support · find the first ZOMBIE child of the given parent
 * synthetic_pid.  Skip slot 0 (the "no parent" anomaly).  Returns NULL when
 * the caller has no reapable children.
 *
 * O(N) over PROCD_MAX_PROCS is acceptable today · PR 7+ adds an explicit
 * children-list per parent if profiling shows the wait path becomes hot. */
proc_t *procd_table_first_zombie_child(uint32_t ppid) {
    for (uint32_t i = 1; i < PROCD_MAX_PROCS; i++) {
        if (g_procs[i].state == PROC_STATE_ZOMBIE &&
            g_procs[i].ppid  == ppid) {
            return &g_procs[i];
        }
    }
    return NULL;
}

/* PR 9 · OP_SETPGID / OP_GETPGID support · find the proc_t by synthetic_pid.
 *
 * setpgid/getpgid take a target_pid argument; the caller may pass 0 to
 * mean "the caller's own pid" (handled at the handler layer) or any
 * monotonic synthetic_pid that procd minted previously.  This helper performs
 * the linear scan needed to translate that pid back to its slot · skips
 * slot 0 (the "no parent" anomaly) and any FREE slot.  Returns NULL if
 * no live process matches the synthetic_pid (caller treats as -ESRCH).
 *
 * O(N) over PROCD_MAX_PROCS · acceptable for the smoke / demo budget;
 * setpgid is a cold-path syscall (typically called once at shell job-
 * control setup).  A children-list refactor lands when profiling shows
 * hotness · same rationale as procd_table_first_zombie_child. */
proc_t *procd_table_lookup_by_synthetic_pid(uint32_t synthetic_pid) {
    if (synthetic_pid == 0) return NULL;
    for (uint32_t i = 1; i < PROCD_MAX_PROCS; i++) {
        if (g_procs[i].synthetic_pid == synthetic_pid &&
            g_procs[i].state    != PROC_STATE_FREE) {
            return &g_procs[i];
        }
    }
    return NULL;
}
