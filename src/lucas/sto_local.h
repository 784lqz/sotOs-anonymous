/*
 * sotOs · sotFS-β · in-process STO transaction tracker
 *
 * Phase-B placeholder for real STO IPC integration (deferred to
 * sotFS-β-Phase-B once cap delegation pattern from root→orch is
 * settled for the orch image).
 *
 * The STO server (src/sto/) runs in a separate seL4 image and its
 * endpoint cap is not currently delegated to the lucas-orchestrator.
 * Rather than complicate the bootstrap sequence for this phase, we
 * track transactions in-process with a static counter that produces
 * the exact same operator-console log shape as real STO IPC would:
 *
 *   [sto] tx=N BEGIN op=sotfs:<op> ...
 *   [sto] tx=N COMMIT
 *   [sto] tx=N ABORT   (on DPO rewrite error)
 *
 * A future swap to real IPC is a one-line change in sto_local.c
 * (replace the printf + counter with a seL4_Call to g_sto_ep).
 */

#ifndef SOTOS_LUCAS_STO_LOCAL_H
#define SOTOS_LUCAS_STO_LOCAL_H

#include <stdint.h>

typedef uint32_t sto_local_tx_t;   /* opaque tx handle */

/* Begin a new transaction.  Returns a non-zero tx id.
 * op_label: short string like "sotfs:create_file". */
sto_local_tx_t sto_local_begin(const char *op_label, const char *extra);

/* Commit a previously begun transaction. */
void sto_local_commit(sto_local_tx_t tx);

/* Abort a previously begun transaction. */
void sto_local_abort(sto_local_tx_t tx);

#endif /* SOTOS_LUCAS_STO_LOCAL_H */
