/*
 * sotOs · STO IPC protocol
 *
 * Cada session STO es un seL4 endpoint capability badged con un session_id
 * único asignado por el server. El kernel enforce que el badge no es
 * forjable: un cliente solo puede invocar caps que él tiene legítimamente
 * en su CSpace.
 *
 * El opcode de la operación va en seL4_MessageInfo_get_label.
 * Los argumentos van en message registers (MRs).
 *
 * Mapeo a la spec formal (formal/tla/STO.tla):
 *
 *   STO_OP_BEGIN    ↔  action Begin
 *   STO_OP_READ     ↔  action Read
 *   STO_OP_STAGE    ↔  action Write
 *   STO_OP_COMMIT   ↔  action Commit ∨ AbortOnConflict
 *   STO_OP_ROLLBACK ↔  action Rollback
 */

#ifndef SOTOS_STO_PROTOCOL_H
#define SOTOS_STO_PROTOCOL_H

#include <stdint.h>
#include <sto/status.h>

/* IPC op codes (go in MessageInfo.label) */
enum sto_op {
    STO_OP_BEGIN    = 1,
    STO_OP_READ     = 2,
    STO_OP_STAGE    = 3,
    STO_OP_COMMIT   = 4,
    STO_OP_ROLLBACK = 5,
    /* New in v3: cap_ext */
    STO_OP_WRAP     = 6,
    STO_OP_UNWRAP   = 7,
    STO_OP_INVOKE   = 8,
    /* Benchmark ping · the micro_baseline harness sends this to measure pure
     * seL4_Call→reply IPC roundtrip cost.  The server replies STO_OK
     * immediately and SILENTLY (no per-call print → no serial flood, and the
     * timed path is pure IPC, not IPC+printf).  Value matches the harness's
     * literal BASELINE_INVALID_OP (0xFFFF). */
    STO_OP_BENCH_PING = 0xFFFF,
};

/*
 * Message register layouts.
 *
 *   begin
 *     in:  []
 *     out: [tx_id]                            on success
 *          [0]                                on failure (status in label)
 *
 *   read
 *     in:  [tx_id, obj_id]
 *     out: [status]
 *
 *   stage
 *     in:  [tx_id, obj_id]
 *     extra cap: dataspace frame (the server reads & buffers content)
 *     out: [status]
 *
 *   commit
 *     in:  [tx_id]
 *     out: [status]
 *
 *   rollback
 *     in:  [tx_id]
 *     out: [void]                              (no reply)
 *
 *   wrap
 *     in:  [tx_id, obj_id, mode]
 *     out: [status, wrapped_cap_id]
 *     extra cap out: the freshly minted derived cap (returned via reply
 *     cap slot in v1.1; for v1 only the wrapped_cap_id token is returned)
 *
 *   unwrap
 *     in:  [wrapped_cap_id]
 *     out: [status]
 *     precondition: cap_tx must be COMMITTED
 *
 *   invoke
 *     in:  [wrapped_cap_id, op_payload]
 *     out: [status, result]
 *     server checks Invocable(cap) predicate from TLA+ spec.
 *
 * Server invariants (see formal/tla/STO.tla):
 *   I1. OnlyOwnerMutates: the endpoint badge identifies the owner.
 *       A client with badge B may only operate on transactions it created.
 *   I2. CommittedIsTerminal: a tx in COMMITTED state does not transition.
 *   I3. NoLostUpdate: commit validates the read set against the commit log.
 */

#endif /* SOTOS_STO_PROTOCOL_H */
