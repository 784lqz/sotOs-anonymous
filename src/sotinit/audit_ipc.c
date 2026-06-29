/* sotOs · sotinit audit_ipc · γ.  IPC to orch's audit-receive EP. */
#include <stdint.h>
#include <stdio.h>
#include <sel4/sel4.h>

#include <sotos/audit_ipc.h>
#include <orch/proto.h>

static seL4_CPtr g_audit_ep = 0;

void sotos_audit_set_ep(uintptr_t ep_slot) {
    g_audit_ep = (seL4_CPtr)ep_slot;
    printf("[sotinit] audit_ep set · slot=%lu\n", (unsigned long)g_audit_ep);
}

uintptr_t sotos_audit_get_ep(void) {
    return (uintptr_t)g_audit_ep;
}

void sotos_audit_emit(uint16_t kind, uint32_t slot, uint64_t arg0) {
    if (g_audit_ep == 0) {
        printf("[sotinit] AUDIT kind=0x%02x slot=%u arg0=0x%lx (NO_EP)\n",
               kind, slot, (unsigned long)arg0);
        return;
    }
    seL4_SetMR(0, ORCH_OP_AUDIT_APPEND);
    seL4_SetMR(1, ((uint64_t)kind) | (((uint64_t)slot) << 16));
    seL4_SetMR(2, arg0);
    seL4_SetMR(3, 0);
    seL4_Call(g_audit_ep, seL4_MessageInfo_new(0, 0, 0, 4));
    printf("[sotinit] AUDIT kind=0x%02x slot=%u arg0=0x%lx\n",
           kind, slot, (unsigned long)arg0);
}
