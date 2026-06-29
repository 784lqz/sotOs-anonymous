#include <lucas/functor.h>
#include "state.h"
#include <stdio.h>
#include <sottrace/trace.h>

const lucas_functor_t LUCAS_F_0 = {
    .name      = "F_0",
    .tier      = FUNCTOR_TIER_0,
    .writes_silenced  = false,
    .is_isolated = false,
};

const lucas_functor_t LUCAS_F_1 = {
    .name      = "F_1",
    .tier      = FUNCTOR_TIER_1,
    .writes_silenced  = true,
    .is_isolated = false,
};

const lucas_functor_t LUCAS_F_2 = {
    .name      = "F_2",
    .tier      = FUNCTOR_TIER_2,
    .writes_silenced  = false,
    .is_isolated = true,
};

const lucas_functor_t LUCAS_F_0E = {
    .name      = "F_0e",
    .tier      = FUNCTOR_TIER_EGRESS,
    .writes_silenced  = false,
    .is_isolated = false,
    .is_egress = true,
};

const lucas_functor_t *lucas_functor_for_tier(int tier) {
    switch (tier) {
        case 0:  return &LUCAS_F_0;
        case 1:  return &LUCAS_F_1;
        case 2:  return &LUCAS_F_2;
        case FUNCTOR_TIER_EGRESS: return &LUCAS_F_0E;
        default: return &LUCAS_F_0;
    }
}

/* procd PR 10 · forward decl · authoritative tier mutation through
 * procd's badged listen EP.  Lives in src/orch/procd_client.c.
 * No-op (returns -1) if the badged EP isn't wired or procd_slot is 0;
 * lucas_set_tier still flips writes_silenced/is_isolated regardless · the demo
 * invariant only depends on those flags. */
extern int orch_procd_set_tier(uint32_t target_slot, uint32_t new_tier);

void lucas_set_tier(struct lucas_state *st, int tier) {
    if (!st) return;
    if (st->trusted && tier > 0) {
        printf("[functor] pid=%d trusted · tier-pin · would promote → %d · suppressed\n",
               st->synthetic_pid, tier);
        return;   /* never promote a trusted sotbox */
    }
    const lucas_functor_t *prev = st->functor;
    st->tier    = tier;
    st->functor = lucas_functor_for_tier(tier);
    if (prev != st->functor) {
        printf("[functor] pid=%d transition %s → %s (η^%d→%d)\n",
               st->synthetic_pid,
               prev ? prev->name : "(null)",
               st->functor->name,
               prev ? (int)prev->tier : -1,
               tier);
        /* sottrace · trust-tier transition. Single chokepoint → captures
         * anomaly-driven, auto-T2, and pledge-gate promotions uniformly.
         * (functor identity is redundant with the tier here — F_0↔0, F_1↔1,
         * F_2↔2 — so we record only old→new.) */
        trace_emit_tier(st->slot_index, (uint32_t)st->synthetic_pid,
                        (uint32_t)(prev ? prev->tier : 0),
                        (uint32_t)tier);
    }

    /* PR 10 dual-write · mirror this tier flip into procd's authoritative
     * proc_t state.  procd publishes EV_TIER_CHANGED + EV_FUNCTOR_REBOUND
     * under the proc_t seqlock so future cross-vspace SHM readers (PR 14+)
     * observe the new tier coherently.  Best-effort · failures are silent
     * because the legacy flag flip above has already done the operator-
     * visible work for this PR. */
    if (st->procd_slot != 0) {
        (void)orch_procd_set_tier(st->procd_slot, (uint32_t)tier);
    }

    /* TIER1-REVOKE-GATES · do NOT auto-lock already-open writable fds on
     * Tier-1 promotion.  STAR's deception principle requires that the
     * sotBox can't tell its writes are being silenced — silent-success
     * (handlers_fs.c:165-171) preserves the illusion, while -EACCES on
     * a locked fd surfaces the policy change.  Hardening only ADDS deny
     * gates for NEW capability acquisitions (open(O_WRONLY) / socket() /
     * connect()), where -EACCES is semantically correct (the cap was
     * never obtained, not silently nulled).
     *
     * The `writes_denied` field remains usable by future operator-driven
     * "explicit lock" code paths (e.g., an `xtighten <pid>` command that
     * intentionally surfaces -EACCES to test sotBox response).  Today
     * it's only set by Tier-1 promotion if we ever flip the policy
     * back; left as 0 across all entries by default. */
}
