/* sotOs · lucas · proc_t snapshot loader · reads procd's SHM via seqlock.
 *
 * Used by every process-introspection handler that needs to lie consistently
 * about another process (kill target, wait4 target, getppid, getsid).
 * Single seqlock loop per call · no IPC on the hot path.
 */
#ifndef LUCAS_PROCD_VIEW_H
#define LUCAS_PROCD_VIEW_H

#include <stdint.h>

typedef struct {
    uint32_t  synthetic_pid;
    uint32_t  ppid;          /* parent's synthetic_pid · 0 if no parent (init) */
    uint32_t  pgid;
    uint32_t  sid;
    uint32_t  tier;          /* proc_tier_t cast */
    uint16_t  functor_proc;  /* FPROC_IDENTITY | FPROC_SYNTH_FORK | FPROC_REVOKED */
    uint8_t   state;         /* proc_state_t cast */
    uint8_t   valid;         /* 0 if slot==0 or SHM unmapped · caller falls back */
    char      comm[16];      /* ABI v2 · short program name (NUL-terminated) */
    uint32_t  cow_session;   /* ABI v2 · owning SSH session id (0 = none) */
} lucas_proc_view_t;

/* Load a slot's snapshot via seqlock. Returns 0 on success (out->valid=1).
 * Returns -1 if slot==0 or g_procd_shm_base==NULL (out->valid=0). */
int lucas_procd_view_load(uint32_t slot, lucas_proc_view_t *out);

/* Linear-scan procd's table by synthetic_pid. Returns 0 if found (out->valid=1).
 * Returns -1 if not found. Cold path · ~256 iter worst case. */
int lucas_procd_view_by_synthetic_pid(uint32_t synthetic_pid, lucas_proc_view_t *out);

/* procd-readers · perf-safe accessor over orch's DEDICATED RO view
 * (g_procd_shm_ro · set at BOOTSTRAP).  Distinct from lucas_procd_view_*
 * above (which gate on g_procd_shm_base, kept 0 so getsid stays on the
 * randomized display_pid · anti-fingerprinting).  Bounded seqlock, no
 * unbounded spin; slot-direct (no 256-scan) for lucas_proct_load. */
int lucas_proct_load(uint32_t slot, lucas_proc_view_t *out);
int lucas_proct_find_synthetic_pid(uint32_t synthetic_pid, lucas_proc_view_t *out);

/* One-shot boot self-test · prints the first live proc read via
 * g_procd_shm_ro, proving the accessor works.  Called once at WAL-init. */
void lucas_proct_selftest(void);

#endif
