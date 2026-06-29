/*
 * sotOs · sto_cap_revoke adversarial test
 *
 * Validates the NoEffectsFromAborted invariant from the TLA+ v3 spec
 * operationally. A wrapped cap obtained inside a tx that later aborts
 * must NOT be invocable post-abort.
 *
 * Flow:
 *   1. begin tx
 *   2. wrap obj_id=42 in ACTIVE_OK mode → wrapped_id W
 *   3. invoke W → OK expected (tx ACTIVE, ACTIVE_OK matches)
 *   4. rollback tx
 *   5. invoke W → must NOT be OK (sweep marked the cap revoked)
 */

#include <sto/protocol.h>
#include <sto/status.h>
#include <sto/cap_ext.h>
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t call_op(seL4_CPtr ep, uint64_t op,
                         uint64_t a0, uint64_t a1, uint64_t a2)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(op, 0, 0, 3);
    seL4_SetMR(0, a0);
    seL4_SetMR(1, a1);
    seL4_SetMR(2, a2);
    info = seL4_Call(ep, info);
    return seL4_GetMR(0);
}

static void call_op2(seL4_CPtr ep, uint64_t op,
                      uint64_t a0, uint64_t a1, uint64_t a2,
                      uint64_t *out0, uint64_t *out1)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(op, 0, 0, 3);
    seL4_SetMR(0, a0);
    seL4_SetMR(1, a1);
    seL4_SetMR(2, a2);
    info = seL4_Call(ep, info);
    *out0 = seL4_GetMR(0);
    *out1 = seL4_GetMR(1);
}

int main(int argc, char *argv[])
{
    printf("[cap_revoke] starting\n");

    if (argc < 2) {
        printf("[cap_revoke] no session cap in argv[1] · halting\n");
        while (1) seL4_Yield();
    }
    seL4_CPtr session_ep = (seL4_CPtr)strtoul(argv[1], NULL, 10);

    uint64_t tx = call_op(session_ep, STO_OP_BEGIN, 0, 0, 0);
    printf("[cap_revoke] tx_id=%lu\n", (unsigned long)tx);
    if (tx == 0) {
        printf("[cap_revoke] FAIL · begin returned 0\n");
        while (1) seL4_Yield();
    }

    uint64_t status, wid;
    call_op2(session_ep, STO_OP_WRAP, tx, 42, STO_CAP_ACTIVE_OK, &status, &wid);
    if (status != STO_OK) {
        printf("[cap_revoke] FAIL · wrap returned %lu\n",
               (unsigned long)status);
        while (1) seL4_Yield();
    }
    printf("[cap_revoke] wrapped_id=%lu\n", (unsigned long)wid);

    /* Invoke during ACTIVE phase, ACTIVE_OK mode → OK */
    uint64_t inv1 = call_op(session_ep, STO_OP_INVOKE, wid, 0, 0);
    if (inv1 != STO_OK) {
        printf("[cap_revoke] FAIL · invoke during ACTIVE returned %lu\n",
               (unsigned long)inv1);
        while (1) seL4_Yield();
    }

    /* Rollback (no reply) */
    seL4_MessageInfo_t info = seL4_MessageInfo_new(STO_OP_ROLLBACK, 0, 0, 1);
    seL4_SetMR(0, tx);
    seL4_Send(session_ep, info);

    /* Now invoke must fail · cap was swept */
    uint64_t inv2 = call_op(session_ep, STO_OP_INVOKE, wid, 0, 0);
    if (inv2 != STO_INVALID_STATE && inv2 != STO_INVALID_TX) {
        printf("[cap_revoke] FAIL · invoke post-rollback returned %lu "
               "(expected INVALID_STATE or INVALID_TX)\n",
               (unsigned long)inv2);
        while (1) seL4_Yield();
    }

    printf("[cap_revoke] sto_cap_revoke · OK · cap revoked on abort\n");
    while (1) seL4_Yield();
    return 0;
}
