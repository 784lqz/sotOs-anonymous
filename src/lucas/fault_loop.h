#ifndef SOTOS_LUCAS_FAULT_LOOP_H
#define SOTOS_LUCAS_FAULT_LOOP_H

#include <sel4/sel4.h>

struct lucas_state;

/* Run the companion's fault loop. Returns when the client exits.
 * (Legacy: used as a shim; L3b uses orch_fault_loop instead.) */
void lucas_fault_loop(struct lucas_state *st);

/* L3b-T1: process ONE fault IPC for the given sotBox.
 * Called by orch_fault_loop after seL4_Recv identifies the sotBox by badge.
 * Returns 1 if the client exited (orch_fault_loop should stop tracking it),
 * 0 on a normal handled fault (loop should continue). */
int lucas_handle_one_fault(struct lucas_state *st, seL4_MessageInfo_t info);

/* v0.10-fix: reset the non-syscall fault budget for `slot` to its full
 * initial credit.  Called by sotbox_init on each new spawn so that prior
 * sotBoxes' faults don't drain the next binary's budget. */
void lucas_fault_loop_reset_slot(int slot);

#endif /* SOTOS_LUCAS_FAULT_LOOP_H */
