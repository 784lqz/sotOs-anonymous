/* sotOs · procd · WAL writer macro · dedupes the seqlock-then-log pattern.
 *
 * Every procd_seqlock_end(p) marks a committed mutation of proc_t.  PR 3
 * pairs that commit with a sotfs_wal_log_procd_mut() append so a
 * subsequent simreboot can rehydrate procd's slot table from the WAL.
 *
 * PR 3 scope reduction · procd lives in its own ELF and does not link
 * against sotos-sotfs (the WAL writer is in the orch/lucas process).
 * The g_wal_attached gate stays 0 until PR 4 lands the WAL IPC
 * (SOTFS_OP_WAL_LOG_PROCD_MUT or equivalent) and procd flips it on once
 * the EP is verified.  Until then PROCD_SEQLOCK_END_LOGGED degenerates
 * to a plain procd_seqlock_end · the ~14 call sites still get the
 * uniform shape so PR 4 only needs to wire the IPC stub.
 *
 * The helper is intentionally tiny so the compiler can inline it · no
 * function-call overhead on the no-op fast path.
 */
#ifndef PROCD_WAL_LOG_HELPER_H
#define PROCD_WAL_LOG_HELPER_H

#include <procd/proc.h>
#include <procd/shm.h>
#include <sotfs/wal.h>

extern int g_wal_attached;  /* set by procd init once WAL writer EP works */

static inline void procd_wal_log_p(const proc_t *p) {
    if (!g_wal_attached) return;
    if (!p) return;
    sotfs_wal_payload_procd_mut_t rec = {
        .slot         = p->slot,
        .synthetic_pid     = p->synthetic_pid,
        .ppid         = p->ppid,
        .pgid         = p->pgid,
        .sid          = p->sid,
        .tier         = (uint16_t)p->tier,
        .functor_fs   = p->functor_fs,
        .functor_net  = p->functor_net,
        .functor_proc = p->functor_proc,
        .state        = (uint8_t)p->state,
        .pledge_mask  = p->pledge_mask,
    };
    (void)sotfs_wal_log_procd_mut(&rec);
}

#define PROCD_SEQLOCK_END_LOGGED(p) \
    do { procd_seqlock_end(p); procd_wal_log_p(p); } while (0)

#endif /* PROCD_WAL_LOG_HELPER_H */
