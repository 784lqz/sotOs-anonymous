/*
 * sotOs · STO transaction registry · v3
 *
 * Backing store del STO server. Sin malloc · arrays de tamaño fijo.
 * Mapeo directo a la spec formal en formal/tla/STO.tla (v3 con cap_ext).
 *
 *   txs[t]        ↔ active[i].phase   (where active[i].tx_id == t)
 *   owners[t]     ↔ active[i].owner_badge
 *   reads[t]      ↔ active[i].read_set
 *   writes[t]     ↔ active[i].write_set
 *   commit_log    ↔ commit_log[]
 *   caps[k]       ↔ wrapped_pool[i] (where wrapped_pool[i].id == k)
 *   cap_tx[k]     ↔ wrapped_pool[i].tx_id
 *   cap_mode[k]   ↔ wrapped_pool[i].mode
 *
 * Invariantes que el código debe mantener:
 *   I1. OnlyOwnerMutates: toda operación valida owner_badge == caller_badge.
 *   I2. NoLostUpdate: sto_registry_can_commit chequea contra commit_log.
 *   I3. Bounded: STO_MAX_TX, STO_MAX_OBJ_PER_TX, STO_MAX_COMMIT_LOG,
 *               STO_MAX_WRAPPED_CAPS, STO_MAX_WRAPPED_PER_TX.
 *   I4. NoEffectsFromAborted: sweep_wrapped flags caps revoked on abort
 *               so subsequent sto_registry_wrapped_invocable returns false.
 *   I5. CommitOnlyVisibility: commit sweeps only ACTIVE_OK caps, not
 *               COMMIT_ONLY (those become invocable AT commit, not before).
 */

#ifndef SOTOS_STO_REGISTRY_H
#define SOTOS_STO_REGISTRY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sto/limits.h>
#include <sto/status.h>
#include <sto/cap_ext.h>

typedef enum {
    STO_PHASE_FREE      = 0,   /* slot is unused */
    STO_PHASE_ACTIVE    = 1,
    STO_PHASE_COMMITTED = 2,
    STO_PHASE_ABORTED   = 3,
} sto_phase_t;

typedef struct {
    uint64_t obj_ids[STO_MAX_OBJ_PER_TX];
    size_t   count;
} sto_obj_set_t;

typedef struct {
    uint64_t          tx_id;
    uint64_t          owner_badge;
    sto_phase_t       phase;
    sto_obj_set_t     read_set;
    sto_obj_set_t     write_set;
    /* New in v3: wrapped caps owned by this tx, tracked for O(1)-ish sweep. */
    sto_wrapped_id_t  wrapped_caps[STO_MAX_WRAPPED_PER_TX];
    size_t            wrapped_count;
} sto_transaction_t;

typedef struct {
    uint64_t       tx_id;
    sto_obj_set_t  write_set;
} sto_commit_entry_t;

/* New in v3: wrapped cap pool entry. */
typedef struct {
    sto_wrapped_id_t   id;          /* server-assigned, 0 == FREE slot */
    uint64_t           obj_id;
    uint64_t           tx_id;       /* parent transaction */
    enum sto_cap_mode  mode;
    bool               revoked;     /* sweep flag */
} sto_wrapped_cap_t;

typedef struct sto_registry {
    sto_transaction_t   active[STO_MAX_TX];
    size_t              active_count;

    sto_commit_entry_t  commit_log[STO_MAX_COMMIT_LOG];
    size_t              commit_log_count;

    uint64_t            next_tx_id;

    /* New in v3 */
    sto_wrapped_cap_t   wrapped_pool[STO_MAX_WRAPPED_CAPS];
    sto_wrapped_id_t    next_wrapped_id;  /* monotone, starts at 1 */
} sto_registry_t;

/* === Existing API (v2) === */

void sto_registry_init(sto_registry_t *r);
sto_transaction_t *sto_registry_begin(sto_registry_t *r, uint64_t owner_badge);
sto_transaction_t *sto_registry_find(sto_registry_t *r,
                                      uint64_t tx_id,
                                      uint64_t owner_badge);
int  sto_registry_add_read (sto_registry_t *r, sto_transaction_t *tx, uint64_t obj_id);
int  sto_registry_add_write(sto_registry_t *r, sto_transaction_t *tx, uint64_t obj_id);
bool sto_registry_can_commit(const sto_registry_t *r, const sto_transaction_t *tx);
int  sto_registry_commit   (sto_registry_t *r, sto_transaction_t *tx);
void sto_registry_abort    (sto_registry_t *r, sto_transaction_t *tx);

/* === cap_ext API (v3) === */

/* Wrap an obj_id under a tx. Allocates a wrapped cap slot, returns its id.
 * Returns 0 (invalid id) on STO_QUOTA. */
sto_wrapped_id_t sto_registry_wrap(sto_registry_t *r,
                                    sto_transaction_t *tx,
                                    uint64_t obj_id,
                                    enum sto_cap_mode mode);

/* Look up a wrapped cap by id. Returns NULL if not found or revoked. */
sto_wrapped_cap_t *sto_registry_wrapped_find(sto_registry_t *r,
                                              sto_wrapped_id_t id);

/* Check Invocable(k) from TLA+: cap is LIVE and tx state matches mode. */
bool sto_registry_wrapped_invocable(const sto_registry_t *r,
                                     const sto_wrapped_cap_t *wc);

/* Sweep: mark all wrapped caps of tx as revoked. Used on abort/rollback.
 * Idempotent. */
void sto_registry_sweep_wrapped(sto_registry_t *r, sto_transaction_t *tx);

/* Sweep only wrapped caps of `tx` matching `mode`. Used on commit to
 * revoke ACTIVE_OK caps while leaving COMMIT_ONLY caps LIVE (which is
 * exactly when those become invocable). This is the CommitOnlyVisibility
 * preservation in the implementation: a naive sweep_wrapped(r, tx) in
 * commit would have invalidated COMMIT_ONLY caps before they were
 * useful — the TLA+ spec catches that bug when ran against the model. */
void sto_registry_sweep_wrapped_by_mode(sto_registry_t *r,
                                         sto_transaction_t *tx,
                                         enum sto_cap_mode mode);

#endif /* SOTOS_STO_REGISTRY_H */
