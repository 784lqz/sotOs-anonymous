/* sotOs · audit IPC · cross-process audit emission · γ.
 *
 * Lucas runs in orch's vspace → direct call to orch_anomaly_log_append.
 * sotinit/sotcron are separate ELFs → seL4_Call to orch's audit-receive EP.
 *
 * Common ABI: audit_emit(kind, slot, arg0).  Implementation dispatches by
 * which process linked the .c file.
 */
#ifndef SOTOS_AUDIT_IPC_H
#define SOTOS_AUDIT_IPC_H

#include <stdint.h>

void sotos_audit_emit(uint16_t kind, uint32_t slot, uint64_t arg0);

/* sotinit/sotcron call this once at startup with the audit-receive
 * EP they got minted into argv. */
void sotos_audit_set_ep(uintptr_t ep_slot);

/* γ · PR 7 · expose the saved audit EP for other in-process IPC clients
 * (sotinit_sotfs_scan / sotcron's sister scan) that need to seL4_Call
 * back into orch.  Same EP serves AUDIT_APPEND + F_PERSIST_STAT today;
 * if PR 8+ adds caller-specific badging this getter is the choke point
 * for the swap.  Returns 0 if set_ep was never called or argv[3] was 0. */
uintptr_t sotos_audit_get_ep(void);

#endif
