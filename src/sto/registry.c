#include "registry.h"
#include <string.h>

static bool obj_set_contains(const sto_obj_set_t *s, uint64_t obj_id)
{
    for (size_t i = 0; i < s->count; ++i) {
        if (s->obj_ids[i] == obj_id) return true;
    }
    return false;
}

static bool obj_sets_intersect(const sto_obj_set_t *a, const sto_obj_set_t *b)
{
    for (size_t i = 0; i < a->count; ++i) {
        if (obj_set_contains(b, a->obj_ids[i])) return true;
    }
    return false;
}

static int obj_set_add(sto_obj_set_t *s, uint64_t obj_id)
{
    if (obj_set_contains(s, obj_id)) return STO_OK;
    if (s->count >= STO_MAX_OBJ_PER_TX) return STO_QUOTA;
    s->obj_ids[s->count++] = obj_id;
    return STO_OK;
}

void sto_registry_init(sto_registry_t *r)
{
    memset(r, 0, sizeof(*r));
    r->next_tx_id      = 1;
    r->next_wrapped_id = 1;
    for (size_t i = 0; i < STO_MAX_TX; ++i) {
        r->active[i].phase = STO_PHASE_FREE;
    }
    /* wrapped_pool[*].id == 0 means FREE; memset above already does that. */
}

sto_transaction_t *sto_registry_begin(sto_registry_t *r, uint64_t owner_badge)
{
    for (size_t i = 0; i < STO_MAX_TX; ++i) {
        if (r->active[i].phase == STO_PHASE_FREE) {
            sto_transaction_t *tx = &r->active[i];
            memset(tx, 0, sizeof(*tx));
            tx->tx_id       = r->next_tx_id++;
            tx->owner_badge = owner_badge;
            tx->phase       = STO_PHASE_ACTIVE;
            if (i >= r->active_count) r->active_count = i + 1;
            return tx;
        }
    }
    return NULL;
}

sto_transaction_t *sto_registry_find(sto_registry_t *r,
                                      uint64_t tx_id,
                                      uint64_t owner_badge)
{
    for (size_t i = 0; i < r->active_count; ++i) {
        sto_transaction_t *tx = &r->active[i];
        if (tx->phase == STO_PHASE_ACTIVE
            && tx->tx_id == tx_id
            && tx->owner_badge == owner_badge) {
            return tx;
        }
    }
    return NULL;
}

int sto_registry_add_read(sto_registry_t *r,
                          sto_transaction_t *tx,
                          uint64_t obj_id)
{
    (void)r;
    return obj_set_add(&tx->read_set, obj_id);
}

int sto_registry_add_write(sto_registry_t *r,
                           sto_transaction_t *tx,
                           uint64_t obj_id)
{
    (void)r;
    return obj_set_add(&tx->write_set, obj_id);
}

bool sto_registry_can_commit(const sto_registry_t *r,
                              const sto_transaction_t *tx)
{
    for (size_t i = 0; i < r->commit_log_count; ++i) {
        if (obj_sets_intersect(&tx->read_set, &r->commit_log[i].write_set))
            return false;
    }
    return true;
}

/* Registry GC · reclaim bounded resources without weakening OCC.
 * Recomputes active_count to the non-FREE high-water (keeps find() scans
 * tight) and, when NO transaction is still ACTIVE, clears the commit_log:
 * its only consumer is sto_registry_can_commit for ACTIVE txs (I2), so with
 * none active no pending validation can need those records.  This bounds the
 * commit_log for sequential single-client workloads (the throughput bench and
 * orch's own sotfs commits), which otherwise hit STO_MAX_COMMIT_LOG. */
static void sto_registry_gc(sto_registry_t *r)
{
    size_t live_active = 0, high = 0;
    for (size_t i = 0; i < STO_MAX_TX; ++i) {
        if (r->active[i].phase == STO_PHASE_ACTIVE)  live_active++;
        if (r->active[i].phase != STO_PHASE_FREE)    high = i + 1;
    }
    r->active_count = high;
    if (live_active == 0) r->commit_log_count = 0;
}

int sto_registry_commit(sto_registry_t *r, sto_transaction_t *tx)
{
    if (r->commit_log_count >= STO_MAX_COMMIT_LOG) return STO_QUOTA;

    sto_commit_entry_t *entry = &r->commit_log[r->commit_log_count++];
    entry->tx_id     = tx->tx_id;
    entry->write_set = tx->write_set;

    /* Sweep ACTIVE_OK caps only · COMMIT_ONLY caps become invocable
     * exactly here and must remain LIVE. A naive
     *     sto_registry_sweep_wrapped(r, tx);
     * would have revoked COMMIT_ONLY caps at the same moment they
     * became visible, violating CommitOnlyVisibility from the TLA+
     * spec (the model checker catches that). */
    sto_registry_sweep_wrapped_by_mode(r, tx, STO_CAP_ACTIVE_OK);

    /* Slot reclamation: free this tx's active slot UNLESS a COMMIT_ONLY
     * wrapped cap still depends on its COMMITTED phase for invocability
     * (I5 CommitOnlyVisibility · sto_registry_wrapped_invocable reads the
     * parent tx's phase).  The conflict record lives in the SEPARATE
     * commit_log, so freeing the active slot preserves NoLostUpdate (I2).
     * The common begin/read/stage/commit tx (no wrapped caps · the
     * throughput bench, orch's sotfs commits) is reclaimed immediately —
     * fixing the STO_MAX_TX leak that the old "keep COMMITTED forever"
     * TODO left behind. */
    bool has_live_commit_only = false;
    for (size_t i = 0; i < tx->wrapped_count; ++i) {
        sto_wrapped_cap_t *wc = sto_registry_wrapped_find(r, tx->wrapped_caps[i]);
        if (wc && wc->mode == STO_CAP_COMMIT_ONLY) { has_live_commit_only = true; break; }
    }
    tx->phase = has_live_commit_only ? STO_PHASE_COMMITTED : STO_PHASE_FREE;

    sto_registry_gc(r);
    return STO_OK;
}

void sto_registry_abort(sto_registry_t *r, sto_transaction_t *tx)
{
    /* On abort/rollback, revoke ALL wrapped caps regardless of mode.
     * Enforces NoEffectsFromAborted: once aborted, no further invocation
     * of any cap derived from this tx will succeed (the wrapped slot is
     * freed below · sto_registry_wrapped_find returns NULL). */
    sto_registry_sweep_wrapped(r, tx);
    tx->phase = STO_PHASE_FREE;
    sto_registry_gc(r);
}

/* === cap_ext === */

sto_wrapped_id_t sto_registry_wrap(sto_registry_t *r,
                                    sto_transaction_t *tx,
                                    uint64_t obj_id,
                                    enum sto_cap_mode mode)
{
    if (tx->wrapped_count >= STO_MAX_WRAPPED_PER_TX) return 0;

    for (size_t i = 0; i < STO_MAX_WRAPPED_CAPS; ++i) {
        if (r->wrapped_pool[i].id == 0) {
            sto_wrapped_id_t new_id = r->next_wrapped_id++;
            r->wrapped_pool[i] = (sto_wrapped_cap_t){
                .id      = new_id,
                .obj_id  = obj_id,
                .tx_id   = tx->tx_id,
                .mode    = mode,
                .revoked = false,
            };
            tx->wrapped_caps[tx->wrapped_count++] = new_id;
            return new_id;
        }
    }
    return 0;  /* pool exhausted */
}

sto_wrapped_cap_t *sto_registry_wrapped_find(sto_registry_t *r,
                                              sto_wrapped_id_t id)
{
    if (id == 0) return NULL;
    for (size_t i = 0; i < STO_MAX_WRAPPED_CAPS; ++i) {
        if (r->wrapped_pool[i].id == id) {
            return r->wrapped_pool[i].revoked ? NULL : &r->wrapped_pool[i];
        }
    }
    return NULL;
}

static const sto_transaction_t *find_tx_by_id(const sto_registry_t *r,
                                               uint64_t tx_id)
{
    for (size_t i = 0; i < r->active_count; ++i) {
        if (r->active[i].tx_id == tx_id) return &r->active[i];
    }
    return NULL;
}

bool sto_registry_wrapped_invocable(const sto_registry_t *r,
                                     const sto_wrapped_cap_t *wc)
{
    if (!wc || wc->revoked) return false;

    const sto_transaction_t *parent = find_tx_by_id(r, wc->tx_id);
    if (!parent) return false;

    if (wc->mode == STO_CAP_ACTIVE_OK)
        return parent->phase == STO_PHASE_ACTIVE
            || parent->phase == STO_PHASE_COMMITTED;
    /* COMMIT_ONLY */
    return parent->phase == STO_PHASE_COMMITTED;
}

void sto_registry_sweep_wrapped(sto_registry_t *r, sto_transaction_t *tx)
{
    for (size_t i = 0; i < tx->wrapped_count; ++i) {
        sto_wrapped_id_t target = tx->wrapped_caps[i];
        for (size_t j = 0; j < STO_MAX_WRAPPED_CAPS; ++j) {
            if (r->wrapped_pool[j].id == target) {
                /* Revoke AND reclaim the pool slot.  Externally equivalent to
                 * leaving it revoked (wrapped_find returns NULL → invocable
                 * false · I4 NoEffectsFromAborted holds) but frees the slot for
                 * reuse — fixing the STO_MAX_WRAPPED_CAPS leak that made the
                 * sweep_cost bench exhaust the pool.  Monotonic next_wrapped_id
                 * means a freed slot is reused only with a fresh id, so a stale
                 * id never collides. */
                r->wrapped_pool[j].revoked = true;
                r->wrapped_pool[j].id      = 0;   /* reclaim */
            }
        }
    }
    /* TODO: real implementation also calls seL4_CNode_Revoke on
     * the kernel cap that backs each wrapped slot. For v1 model the
     * software revoke is sufficient to validate the spec. */
}

void sto_registry_sweep_wrapped_by_mode(sto_registry_t *r,
                                         sto_transaction_t *tx,
                                         enum sto_cap_mode mode)
{
    for (size_t i = 0; i < tx->wrapped_count; ++i) {
        sto_wrapped_id_t target = tx->wrapped_caps[i];
        for (size_t j = 0; j < STO_MAX_WRAPPED_CAPS; ++j) {
            if (r->wrapped_pool[j].id == target
                && r->wrapped_pool[j].mode == mode) {
                r->wrapped_pool[j].revoked = true;
                r->wrapped_pool[j].id      = 0;   /* reclaim (see sweep_wrapped) */
            }
        }
    }
}
