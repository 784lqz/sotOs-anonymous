/*
 * sotOs · sotFS-β-Phase-B · STO transaction wrapper
 *
 * When the STO server endpoint is delegated from root at orch bootstrap
 * (bs->sto_ep_slot != 0), uses real seL4_Call IPC to the sotOs-sto server.
 * Falls back to the Phase-A in-process counter when ep == 0 (graceful
 * degradation if the STO server was not spawned or delegation failed).
 *
 * Protocol (include/sto/protocol.h):
 *   STO_OP_BEGIN    (1): in=[] → out=[tx_id]
 *   STO_OP_COMMIT   (4): in=[tx_id] → out=[status]
 *   STO_OP_ROLLBACK (5): in=[tx_id] → NO REPLY (seL4_Send not seL4_Call)
 *
 * Log format:
 *   [sto] tx=N BEGIN op=sotfs:<op> [extra] (real IPC)
 *   [sto] tx=N COMMIT (real IPC)
 *   [sto] tx=N ABORT (real IPC)
 *   ... or ...
 *   [sto] tx=N BEGIN op=sotfs:<op> [extra] (local · STO ep not delegated)
 */

#include "sto_local.h"
#include <sto/protocol.h>
#include <sel4/sel4.h>
#include <stdio.h>

/* Provided by src/orch/sotbox_table.c. */
extern seL4_CPtr orch_get_sto_ep(void);

static uint32_t g_local_tx = 0;

sto_local_tx_t sto_local_begin(const char *op_label, const char *extra)
{
    seL4_CPtr ep = orch_get_sto_ep();
    if (ep != 0) {
        /* Real IPC · STO_OP_BEGIN: no args, server returns tx_id in MR(0). */
        seL4_MessageInfo_t info = seL4_MessageInfo_new(STO_OP_BEGIN, 0, 0, 0);
        info = seL4_Call(ep, info);
        uint32_t tx = (uint32_t)seL4_GetMR(0);
        if (tx == 0) {
            /* Server returned 0 = failure · fall back to local counter. */
            tx = ++g_local_tx;
            if (extra && extra[0] != '\0') {
                printf("[sto] tx=%u BEGIN op=%s %s (local fallback · no STO server reply)\n",
                       tx, op_label, extra);
            } else {
                printf("[sto] tx=%u BEGIN op=%s (local fallback · no STO server reply)\n",
                       tx, op_label);
            }
        } else {
            if (extra && extra[0] != '\0') {
                printf("[sto] tx=%u BEGIN op=%s %s (real IPC)\n",
                       tx, op_label, extra);
            } else {
                printf("[sto] tx=%u BEGIN op=%s (real IPC)\n", tx, op_label);
            }
        }
        return (sto_local_tx_t)tx;
    }

    /* Fallback · in-process counter (Phase A behavior). */
    uint32_t tx = ++g_local_tx;
    if (extra && extra[0] != '\0') {
        printf("[sto] tx=%u BEGIN op=%s %s (local · STO ep not delegated)\n",
               tx, op_label, extra);
    } else {
        printf("[sto] tx=%u BEGIN op=%s (local · STO ep not delegated)\n",
               tx, op_label);
    }
    return (sto_local_tx_t)tx;
}

void sto_local_commit(sto_local_tx_t tx)
{
    seL4_CPtr ep = orch_get_sto_ep();
    if (ep != 0) {
        /* Real IPC · STO_OP_COMMIT: MR(0)=tx_id, server replies with status. */
        seL4_MessageInfo_t info = seL4_MessageInfo_new(STO_OP_COMMIT, 0, 0, 1);
        seL4_SetMR(0, (seL4_Word)tx);
        seL4_Call(ep, info);
        printf("[sto] tx=%u COMMIT (real IPC)\n", (unsigned)tx);
        return;
    }
    printf("[sto] tx=%u COMMIT\n", (unsigned)tx);
}

void sto_local_abort(sto_local_tx_t tx)
{
    seL4_CPtr ep = orch_get_sto_ep();
    if (ep != 0) {
        /* Real IPC · STO_OP_ROLLBACK: MR(0)=tx_id.
         * Per protocol (ipc.c handle_rollback): server does NOT seL4_Reply.
         * Must use seL4_Send (fire-and-forget), NOT seL4_Call (would block). */
        seL4_MessageInfo_t info = seL4_MessageInfo_new(STO_OP_ROLLBACK, 0, 0, 1);
        seL4_SetMR(0, (seL4_Word)tx);
        seL4_Send(ep, info);
        printf("[sto] tx=%u ABORT (real IPC)\n", (unsigned)tx);
        return;
    }
    printf("[sto] tx=%u ABORT\n", (unsigned)tx);
}
