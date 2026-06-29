/* sotOs · lucas audit_ipc · γ.
 *
 * Lucas runs in orch's vspace.  audit_emit calls orch_anomaly_log_append
 * directly (no IPC, no marshalling).  set_ep is a no-op for parity.
 */
#include <stdint.h>
#include <stdio.h>

#include <sotos/audit_ipc.h>

extern void orch_anomaly_log_append(uint32_t pid, uint16_t kind,
                                      uint64_t arg0, uint64_t arg1);

void sotos_audit_emit(uint16_t kind, uint32_t slot, uint64_t arg0) {
    orch_anomaly_log_append(slot, kind, arg0, /*arg1=*/0);
    printf("[lucas] AUDIT kind=0x%02x slot=%u arg0=0x%lx\n",
           kind, slot, (unsigned long)arg0);
}

void sotos_audit_set_ep(uintptr_t ep_slot) {
    (void)ep_slot;
}

uintptr_t sotos_audit_get_ep(void) {
    /* Lucas runs in orch's vspace · no IPC EP needed.  Return 0 so any
     * caller that pivots to seL4_Call short-circuits gracefully. */
    return 0;
}
