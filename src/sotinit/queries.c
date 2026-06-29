/* sotOs · sotinit · operator query handlers.
 *
 * Backs the four operator-driven IPC verbs exposed on the sotinit listen
 * EP (PR 5 · spec §3 + §4.5):
 *
 *   SOTINIT_OP_LIST   · return the unit registry count.
 *   SOTINIT_OP_STATUS · return state + procd_slot for a single unit
 *                       (name lookup if req->name is non-empty, otherwise
 *                       index lookup via req->arg32).
 *   SOTINIT_OP_START  · service-only · activate a LOADED service via
 *                       sotinit_activate_service (re-uses the PR 3
 *                       procd OP_SPAWN client).  Idempotent on ACTIVE.
 *   SOTINIT_OP_STOP   · service-only · mark DISABLED.  PR 5 scope is
 *                       state-flip only · PR 6 wires the procd
 *                       OP_TERMINATE round-trip.
 *
 * The handlers are deliberately tiny pure functions: they read the
 * registry, optionally call sotinit_activate_service, and return a
 * sotinit_reply_t struct.  main.c's listen loop is responsible for the
 * MR pack/unpack (sotinit_request_t in, sotinit_reply_t out).
 *
 * Spec: init-cron-scheduler-design §3.
 */
#include <stdio.h>
#include <string.h>
#include <sotinit/proto.h>
#include <sotinit/unit.h>

extern int sotinit_activate_service(unit_t *u);

sotinit_reply_t sotinit_handle_list(const sotinit_request_t *req) {
    (void)req;
    sotinit_reply_t r = {0};
    r.result = (int32_t)sotinit_unit_count();
    return r;
}

sotinit_reply_t sotinit_handle_status(const sotinit_request_t *req) {
    sotinit_reply_t r = {0};
    unit_t *u = NULL;
    if (req->name[0]) u = sotinit_unit_by_name(req->name);
    else              u = sotinit_unit_by_index(req->arg32);
    if (!u) { r.result = -3; return r; }
    r.result      = 0;
    r.state       = (uint32_t)u->state;
    r.procd_slot  = u->procd_slot;
    return r;
}

sotinit_reply_t sotinit_handle_start(const sotinit_request_t *req) {
    unit_t *u = sotinit_unit_by_name(req->name);
    if (!u) {
        sotinit_reply_t r = {0};
        r.result = -3;
        return r;
    }
    if (u->kind != UNIT_KIND_SERVICE) {
        sotinit_reply_t r = {0};
        r.result = -22;
        return r;
    }
    if (u->state == UNIT_STATE_ACTIVE) {
        /* Idempotent · already running · echo state + slot. */
        sotinit_reply_t r = {0};
        r.result     = 0;
        r.state      = (uint32_t)u->state;
        r.procd_slot = u->procd_slot;
        return r;
    }
    int rc = sotinit_activate_service(u);
    sotinit_reply_t r = {0};
    r.result     = rc;
    r.state      = (uint32_t)u->state;
    r.procd_slot = u->procd_slot;
    return r;
}

/* PR 8 · SOTINIT_OP_ACTIVATE · sotcron's timer-fire dispatch.  sotcron
 * packs the target unit name into MR(2..9); main.c's listen loop has
 * already memcpy'd that into req->name (8 chars per word).  We look up
 * the unit, idempotent-NOP on ACTIVE, otherwise re-run
 * sotinit_activate_service · which fires procd OP_SPAWN and flips the
 * unit's state to ACTIVE.  Returns -3 (ENOENT) for unknown units and
 * -22 (EINVAL) for non-service kinds (timers can't fire timers).
 *
 * The audit line is the operator-visible evidence the smoke gate greps
 * for ("[sotinit] ACTIVATE <name> · result=N · state=S"); it surfaces
 * both happy-path and failure-path outcomes inline. */
sotinit_reply_t sotinit_handle_activate(const sotinit_request_t *req) {
    sotinit_reply_t r = {0};
    char name[SOTINIT_NAME_MAX] = {0};
    strncpy(name, req->name, SOTINIT_NAME_MAX - 1);
    name[SOTINIT_NAME_MAX - 1] = '\0';

    unit_t *u = sotinit_unit_by_name(name);
    if (!u || u->kind != UNIT_KIND_SERVICE) {
        r.result = -3;
        printf("[sotinit] ACTIVATE %s · result=%d · unknown or non-service\n",
               name, r.result);
        return r;
    }
    if (u->state == UNIT_STATE_ACTIVE) {
        /* Already active · idempotent · echo state + slot.  Log only the
         * FIRST idempotent activate per unit · a 30s cron timer would
         * otherwise flood the interactive console.  The first line still
         * satisfies the SOTINIT·activate smoke gate. */
        r.result     = 0;
        r.state      = (uint32_t)u->state;
        r.procd_slot = u->procd_slot;
        if (!(u->flags & UNIT_FLAG_ACTIVATE_LOGGED)) {
            printf("[sotinit] ACTIVATE %s · result=%d · state=%u (idempotent)\n",
                   name, r.result, u->state);
            u->flags |= UNIT_FLAG_ACTIVATE_LOGGED;
        }
        return r;
    }
    r.result     = sotinit_activate_service(u);
    r.state      = (uint32_t)u->state;
    r.procd_slot = u->procd_slot;
    printf("[sotinit] ACTIVATE %s · result=%d · state=%u\n",
           name, r.result, u->state);
    return r;
}

sotinit_reply_t sotinit_handle_stop(const sotinit_request_t *req) {
    unit_t *u = sotinit_unit_by_name(req->name);
    if (!u) {
        sotinit_reply_t r = {0};
        r.result = -3;
        return r;
    }
    if (u->procd_slot == 0) {
        /* No procd slot bound · treat as already stopped. */
        sotinit_reply_t r = {0};
        r.result = 0;
        return r;
    }
    /* PR 5 scope: just mark DISABLED.  PR 6 wires procd OP_TERMINATE
     * round-trip so the actual proc_t is reaped and EV_PROC_EXITED is
     * published.  Today the unit is just hidden from operator-driven
     * START · the procd_slot stays populated so STATUS still resolves. */
    u->state = UNIT_STATE_DISABLED;
    sotinit_reply_t r = {0};
    r.result = 0;
    r.state  = UNIT_STATE_DISABLED;
    return r;
}
