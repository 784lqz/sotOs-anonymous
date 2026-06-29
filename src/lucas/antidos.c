#include "antidos.h"
#include "state.h"
#include <lucas/functor.h>       /* lucas_set_tier — declared HERE (functor.h:53), NOT anomaly.h */
#include <orch/sotbox.h>         /* sotbox_get_slot, SOTBOX_MAX_SLOTS */
#include <sottrace/trace.h>      /* trace_emit_forkbomb_quarantined */
#include <sel4/sel4.h>
#include <stdio.h>

extern void    lucas_threads_suspend_all(lucas_state_t *st);                 /* threading.c:447 */
extern int64_t lucas_sys_exit_group(lucas_state_t *st, uint64_t code,
                                     uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

int64_t lucas_antidos_quarantine(lucas_state_t *st)
{
    printf("[p2b] fork-bomb quarantined pid=%d attempts=%u · Tier-2 + suspend subtree + terminate\n",
           st->synthetic_pid, st->fork_attempts);

    /* 1 · hostile tier (existing anomaly mechanism). */
    lucas_set_tier(st, 2);

    /* 2 · QUARANTINE: suspend the offending cell's threads so it stops consuming CPU + can
     *     no longer fork. (The parent is reaped below via exit_group; suspend is belt-
     *     and-suspenders + covers its clone-threads.) */
    if (st->client_tcb) seL4_TCB_Suspend(st->client_tcb);
    lucas_threads_suspend_all(st);

    /* 3 · flag-for-teardown + QUARANTINE the fork subtree (direct children, identified by parent_slot).
     *     They are suspended now (no CPU, no fork) and reaped by the fault-loop marked_for_teardown
     *     sweep (→ sotbox_destroy → arena revoke). One generation suffices for the gate;
     *     a nested bomb's grandchildren self-quarantine on their own quota. */
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *c = sotbox_get_slot(i);
        if (c && c != st && c->parent_slot == st->slot_index) {
            c->marked_for_teardown = 1;
            if (c->client_tcb) seL4_TCB_Suspend(c->client_tcb);
            lucas_threads_suspend_all(c);
        }
    }

    /* 4 · observability (family convention: int slot, ...). */
    trace_emit_forkbomb_quarantined(st->slot_index, st->synthetic_pid, st->fork_attempts);

    /* 5 · reap the PARENT through the exact existing exit path (sets st->exited=1 +
     *     exit_code → lucas_handle_one_fault returns 1 → orch_fault_loop reaps it →
     *     sotbox_destroy → sotbox_arena_revoke). 137 = 128+SIGKILL convention. */
    return lucas_sys_exit_group(st, 137, 0, 0, 0, 0, 0);
}
