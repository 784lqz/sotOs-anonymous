/*
 * sotOs · Capability extensions interface
 *
 * Map to TLA+ spec actions in formal/tla/STO.tla v3:
 *
 *   sto_cap_wrap   ↔  action Wrap
 *   sto_cap_invoke ↔  actions Invoke / InvokeFails (the server picks
 *                                                    based on Invocable())
 *   sto_cap_unwrap ↔  effectively Invoke under COMMIT_ONLY semantics
 *
 * Auto-revoke is not a client-side operation: it happens implicitly
 * inside the server when the parent transaction transitions to ABORTED.
 */

#ifndef SOTOS_STO_CAP_EXT_H
#define SOTOS_STO_CAP_EXT_H

#include <stdint.h>

/* Wrap mode · controls when the derived cap is invocable. */
enum sto_cap_mode {
    STO_CAP_COMMIT_ONLY = 0,  /* invocable only after tx COMMITTED */
    STO_CAP_ACTIVE_OK   = 1,  /* invocable while tx is ACTIVE or COMMITTED */
};

/* Opaque identifier for a wrapped cap, server-assigned. */
typedef uint64_t sto_wrapped_id_t;

/* Message register layout helpers, used by both client and server side. */
#define STO_MR_WRAP_TX_ID       0
#define STO_MR_WRAP_OBJ_ID      1
#define STO_MR_WRAP_MODE        2

#define STO_MR_WRAP_OUT_STATUS  0
#define STO_MR_WRAP_OUT_CAP_ID  1

#define STO_MR_INVOKE_CAP_ID    0
#define STO_MR_INVOKE_PAYLOAD   1

#endif /* SOTOS_STO_CAP_EXT_H */
