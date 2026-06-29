#include "ipc.h"
#include "registry.h"
#include <sto/protocol.h>
#include <sto/status.h>
#include <sto/cap_ext.h>
#include <stdio.h>

static sto_registry_t g_registry;

static void reply_status(int status) {
    seL4_MessageInfo_t r = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, (seL4_Word)status);
    seL4_Reply(r);
}

static void handle_begin(seL4_Word badge) {
    sto_transaction_t *tx = sto_registry_begin(&g_registry, (uint64_t)badge);
    seL4_MessageInfo_t r = seL4_MessageInfo_new(0, 0, 0, 1);
    if (!tx) {
        seL4_SetMR(0, 0);
    } else {
        seL4_SetMR(0, (seL4_Word)tx->tx_id);
    }
    seL4_Reply(r);
}

static void handle_read(seL4_Word badge) {
    seL4_Word tx_id  = seL4_GetMR(0);
    seL4_Word obj_id = seL4_GetMR(1);

    sto_transaction_t *tx = sto_registry_find(&g_registry,
                                              (uint64_t)tx_id,
                                              (uint64_t)badge);
    if (!tx) { reply_status(STO_INVALID_TX); return; }
    if (tx->phase != STO_PHASE_ACTIVE) { reply_status(STO_INVALID_STATE); return; }

    int rc = sto_registry_add_read(&g_registry, tx, (uint64_t)obj_id);
    reply_status(rc);
}

static void handle_stage(seL4_Word badge) {
    seL4_Word tx_id  = seL4_GetMR(0);
    seL4_Word obj_id = seL4_GetMR(1);

    sto_transaction_t *tx = sto_registry_find(&g_registry,
                                              (uint64_t)tx_id,
                                              (uint64_t)badge);
    if (!tx) { reply_status(STO_INVALID_TX); return; }
    if (tx->phase != STO_PHASE_ACTIVE) { reply_status(STO_INVALID_STATE); return; }

    /* TODO: if the message info carries an extra cap, map it and copy the
     * payload into a staging buffer. For now we only track obj_id. */

    int rc = sto_registry_add_write(&g_registry, tx, (uint64_t)obj_id);
    reply_status(rc);
}

static void handle_commit(seL4_Word badge) {
    seL4_Word tx_id = seL4_GetMR(0);

    sto_transaction_t *tx = sto_registry_find(&g_registry,
                                              (uint64_t)tx_id,
                                              (uint64_t)badge);
    if (!tx) { reply_status(STO_INVALID_TX); return; }
    if (tx->phase != STO_PHASE_ACTIVE) { reply_status(STO_INVALID_STATE); return; }

    if (!sto_registry_can_commit(&g_registry, tx)) {
        sto_registry_abort(&g_registry, tx);
        reply_status(STO_CONFLICT);
        return;
    }

    int rc = sto_registry_commit(&g_registry, tx);
    reply_status(rc);
}

static void handle_rollback(seL4_Word badge) {
    seL4_Word tx_id = seL4_GetMR(0);

    sto_transaction_t *tx = sto_registry_find(&g_registry,
                                              (uint64_t)tx_id,
                                              (uint64_t)badge);
    if (tx && tx->phase == STO_PHASE_ACTIVE) {
        sto_registry_abort(&g_registry, tx);
    }
    /* rollback has no reply per protocol; caller does seL4_Send not seL4_Call */
}

/* === cap_ext handlers (v3) === */

static void handle_wrap(seL4_Word badge) {
    seL4_Word tx_id  = seL4_GetMR(STO_MR_WRAP_TX_ID);
    seL4_Word obj_id = seL4_GetMR(STO_MR_WRAP_OBJ_ID);
    seL4_Word mode_w = seL4_GetMR(STO_MR_WRAP_MODE);

    sto_transaction_t *tx = sto_registry_find(&g_registry,
                                              (uint64_t)tx_id,
                                              (uint64_t)badge);
    if (!tx) { reply_status(STO_INVALID_TX); return; }
    if (tx->phase != STO_PHASE_ACTIVE) { reply_status(STO_INVALID_STATE); return; }

    enum sto_cap_mode mode;
    switch (mode_w) {
        case STO_CAP_COMMIT_ONLY: mode = STO_CAP_COMMIT_ONLY; break;
        case STO_CAP_ACTIVE_OK:   mode = STO_CAP_ACTIVE_OK;   break;
        default: reply_status(STO_PROTOCOL); return;
    }

    sto_wrapped_id_t wid = sto_registry_wrap(&g_registry, tx,
                                              (uint64_t)obj_id, mode);
    if (wid == 0) { reply_status(STO_QUOTA); return; }

    /* TODO: mint a kernel cap derived from the parent obj's cap,
     * badged with wid, deliver it via the reply cap slot. For v1 we
     * return only the wrapped_id token; the client uses it as the cap
     * argument to subsequent STO_OP_INVOKE calls over the session ep. */
    seL4_MessageInfo_t r = seL4_MessageInfo_new(0, 0, 0, 2);
    seL4_SetMR(STO_MR_WRAP_OUT_STATUS, STO_OK);
    seL4_SetMR(STO_MR_WRAP_OUT_CAP_ID, (seL4_Word)wid);
    seL4_Reply(r);
}

static void handle_invoke(seL4_Word badge) {
    (void)badge;
    seL4_Word wid = seL4_GetMR(STO_MR_INVOKE_CAP_ID);
    (void)seL4_GetMR(STO_MR_INVOKE_PAYLOAD);  /* not used in v1 */

    sto_wrapped_cap_t *wc = sto_registry_wrapped_find(&g_registry,
                                                       (sto_wrapped_id_t)wid);
    if (!wc) { reply_status(STO_INVALID_TX); return; }

    if (!sto_registry_wrapped_invocable(&g_registry, wc)) {
        reply_status(STO_INVALID_STATE);
        return;
    }

    /* TODO: real invoke would forward to whatever resource the cap
     * authorizes. For v1, success means we acknowledge the invocation. */
    reply_status(STO_OK);
}

void sto_serve(seL4_CPtr listen_ep)
{
    sto_registry_init(&g_registry);
    printf("[sto] server v3 listening on EP cap=%lu · OCC + cap_ext\n",
           (unsigned long)listen_ep);

    seL4_Word badge;
    seL4_MessageInfo_t info = seL4_Recv(listen_ep, &badge);

    while (1) {
        switch (seL4_MessageInfo_get_label(info)) {
            case STO_OP_BEGIN:    handle_begin(badge);    break;
            case STO_OP_READ:     handle_read(badge);     break;
            case STO_OP_STAGE:    handle_stage(badge);    break;
            case STO_OP_COMMIT:   handle_commit(badge);   break;
            case STO_OP_ROLLBACK: handle_rollback(badge); break;
            case STO_OP_WRAP:     handle_wrap(badge);     break;
            case STO_OP_INVOKE:   handle_invoke(badge);   break;
            /* STO_OP_UNWRAP is, in v1, equivalent to invoke with COMMIT_ONLY
             * semantics — already covered by handle_invoke. */
            case STO_OP_BENCH_PING:
                /* Benchmark IPC-roundtrip ping · reply silently (no print) so
                 * the bench measures pure IPC and the serial isn't flooded. */
                reply_status(STO_OK);
                break;
            default:
                printf("[sto] unknown opcode %lu (badge=%lu)\n",
                       (unsigned long)seL4_MessageInfo_get_label(info),
                       (unsigned long)badge);
                reply_status(STO_PROTOCOL);
                break;
        }

        info = seL4_Recv(listen_ep, &badge);
    }
}
