/*
 * sotOs · orchestrator-side type aliases for the future sotBox model.
 *
 * For L3a we keep using the existing lucas_state_t struct verbatim
 * (so the L1+L2 syscall handlers compile unchanged) and just rename
 * it via typedef as sotbox_t.  T7 introduces the multi-slot
 * sotbox_table_t.
 */

#ifndef SOTOS_ORCH_SOTBOX_H
#define SOTOS_ORCH_SOTBOX_H

#include <stdbool.h>
#include <stdint.h>
#include <sel4/sel4.h>
#include "../../src/lucas/state.h"   /* gets lucas_state_t */
#include <orch/proto.h>              /* gets orch_status_entry_t for L4 */

typedef lucas_state_t sotbox_t;

#define SOTBOX_MAX_SLOTS 8

typedef struct sotbox_table {
    sotbox_t slots[SOTBOX_MAX_SLOTS];
    bool     used [SOTBOX_MAX_SLOTS];
} sotbox_table_t;

/* L3a-T7: slot allocator + lookup-by-badge (implemented in sotbox_table.c). */
int             sotbox_alloc_slot(lucas_state_t *st);
void            sotbox_free_slot(int slot);
lucas_state_t  *sotbox_lookup_by_badge(seL4_Word badge);

/* P2a · zero-leak teardown.  Manually reclaim all of a reaped sotbox's owned
 * seL4 objects (vspace + TCB + CNode + IPC frame + badged fault-EP cslot) so
 * the allocman pool returns to baseline.  No-op unless st->seL4_objects_owned.
 * Called from orch_fault_loop immediately before sotbox_free_slot at reap. */
void            sotbox_destroy(int slot);

/* L3a-T9: zombie-wait table (implemented in sotbox_table.c). */
void            sotbox_record_exit(int pid, int exit_code);
int             sotbox_reap(int pid_want, int *out_exit);
/* Arc B: total oldest-evictions from the zombie table (honest accounting). */
uint64_t        sotbox_zombies_evicted(void);
/* Arc B: deterministic over-capacity self-test (run once at bootstrap). */
void            sotbox_reaper_selftest(void);

/* L3b-T1: shared fault EP singleton (implemented in sotbox_table.c). */
void            orch_set_fault_ep(seL4_CPtr ep);
seL4_CPtr       orch_get_fault_ep(void);

/* L3b-T1: count of live sotBoxes (for orch_fault_loop termination). */
int             sotbox_alive_count(void);

/* L3b-T1: orchestrator's shared-EP fault loop (implemented in orch/fault_loop.c).
 * Blocks until all sotBoxes have exited. */
void            orch_fault_loop(seL4_CPtr shared_ep);

/* L3b-T2: called by lucas_sys_exit_group to unblock a waiting parent.
 * Returns 1 if a waiter was found and woken, 0 otherwise. */
int             sotbox_try_wakeup_waiter(int exited_pid, int exit_code);

/* L3b-T4: per-slot accessor used by pipe.c to iterate live sotBoxes. */
lucas_state_t  *sotbox_get_slot(int i);

/* P2b · release the child_storage[] slot a forked child occupies, at its reap. */
void            sotbox_fork_release_storage(lucas_state_t *st);

/* S-PID · translate synthetic_pid (anomaly-ring index = slot+1) to the random
 * display_pid the sotbox sees through getpid() (OBSD-ζ).  Returns 0 if the
 * slot is empty or synthetic_pid is out of range.  Display-layer helper used
 * by anomaly-log reply build · DOES NOT change synthetic_pid semantics. */
uint32_t        sotbox_synthetic_to_display_pid(uint32_t synthetic_pid);

/* L3b-T6: returns true if the process at caller_slot has any living children
 * or uncollected zombies.  Used by wait4 to return -ECHILD instead of parking
 * when there are no children left. */
bool            sotbox_has_children(int caller_slot);

/* L4-T1: dump zombie table into entries[] at start_idx; returns count added. */
int             sotbox_dump_zombies(orch_status_entry_t *entries,
                                    int max, int start_idx);

#endif /* SOTOS_ORCH_SOTBOX_H */
