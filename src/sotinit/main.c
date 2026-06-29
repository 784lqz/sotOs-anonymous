/* sotOs · sotinit · Path D process · service launcher.
 *
 * argv[0] = "sotOs-sotinit"
 * argv[1] = listen EP slot
 * argv[2] = procd listen EP slot (PR 3 · 0 if procd was not configured)
 * argv[3] = orch audit EP slot (γ · F_persistence PR 5 · 0 disables
 *          cross-process audit · audit_emit falls back to printf-only)
 *
 * PR 1 · scaffold (banner + idle yield · cascade smoke).
 * PR 2 · directory scan + INI parser + unit registry population.
 * PR 3 · procd OP_SPAWN client + per-service activation.
 * PR 4+ · After= topo sort + listen loop + restart policy.
 *
 * Spec: init-cron-scheduler-design §3.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sel4/sel4.h>
#include <sotinit/proto.h>
#include <sotinit/unit.h>
#include <sotos/audit_ipc.h>

/* PR 3 · launcher.c side · the procd listen EP captured from argv[2].
 * Defined here (not in launcher.c) so the launcher TU can be linked into
 * the future sotinit-unit test ELF without dragging the main entry point
 * along.  launcher.c declares it `extern`. */
seL4_CPtr g_procd_listen_ep = 0;

extern int sotinit_activate_service(unit_t *u);

/* PR 5 · operator-driven query handlers · defined in queries.c.  Decoupled
 * from main.c so the listen loop here is just MR (un)pack + dispatch · the
 * handlers themselves are pure functions over the unit registry. */
extern sotinit_reply_t sotinit_handle_list(const sotinit_request_t *req);
extern sotinit_reply_t sotinit_handle_status(const sotinit_request_t *req);
extern sotinit_reply_t sotinit_handle_start(const sotinit_request_t *req);
extern sotinit_reply_t sotinit_handle_stop(const sotinit_request_t *req);

/* PR 6 · restart-policy handler · defined in restart.c.  Called from the
 * listen loop on SOTINIT_OP_PROC_EXITED (a one-way NBSend from orch's
 * procd-event drain).  Applies the unit's Restart= directive with a
 * per-unit 500 ms TSC backoff to bound crash loops. */
extern void sotinit_on_proc_exited(uint32_t procd_slot, int32_t exit_code);

/* PR 8 · timer-fire dispatch · sotcron seL4_Calls SOTINIT_OP_ACTIVATE with
 * the target unit name packed into MR(2..9).  Handler looks up the unit
 * in the registry and runs sotinit_activate_service · idempotent on
 * ACTIVE.  Defined in queries.c next to the operator-driven START/STOP
 * handlers (same activation primitive). */
extern sotinit_reply_t sotinit_handle_activate(const sotinit_request_t *req);

int main(int argc, char *argv[]) {
    seL4_CPtr listen_ep = (argc > 1) ? (seL4_CPtr)atol(argv[1]) : 0;
    g_procd_listen_ep   = (argc > 2) ? (seL4_CPtr)atol(argv[2]) : 0;
    printf("[sotinit] alive · ep=%lu procd_ep=%lu\n",
           (unsigned long)listen_ep, (unsigned long)g_procd_listen_ep);

    /* γ · F_persistence PR 5 · wire the audit-emit EP captured from argv[3]
     * into audit_ipc.c.  After this call, sotos_audit_emit seL4_Calls the
     * orch dispatcher (ORCH_OP_AUDIT_APPEND) so events land in the same
     * anomaly-log ring sotShell queries.  When argv[3] is 0 (root could
     * not mint), set_ep is still called · sotos_audit_emit detects the
     * zero EP and falls back to a "(NO_EP)"-tagged printf. */
    if (argc > 3) {
        sotos_audit_set_ep((uintptr_t)atol(argv[3]));
    }

    /* PR 2 · scan + parse the bundled demo unit fragments into the
     * registry.  Returns the count of loaded units · printed as part
     * of the "[sotinit] loaded N units" banner from inside scan(). */
    sotinit_scan_units("/etc/systemd/system");

    /* γ · PR 7 · sotfs scan for F_persistence-tagged unit files.  Walks
     * a hardcoded path list (the simulated_attacker Stage 7 demo installs
     * /etc/systemd/system/backdoor.{service,timer}) and seL4_Calls
     * orch's ORCH_OP_F_PERSIST_STAT op to query each path's inode flag.
     * Tagged hits become stub LOADED units with UNIT_FLAG_F_PERSISTENCE
     * set · PR 8 wires the activate-side skip so they never reach procd.
     * Must run AFTER the rodata scan (so we share the registry's bump
     * allocator) but BEFORE the topo sort (so persistence stubs are part
     * of the activation order · PR 8 hands them an audit-only path). */
    sotinit_sotfs_scan();

    /* γ · PR 8 · activate-time sotfs scan · path-pattern registration of
     * F_persistence stub units, ran BEFORE the topo sort so those stubs
     * land in the activation order alongside the rest.  The scope-reduction
     * rationale (why this is no longer the real IPC) lives in
     * sotfs_scan.c::sotinit_sotfs_scan_now's header. */
    sotinit_sotfs_scan_now();

    /* PR 4 · resolve activation order via Kahn's topological sort over
     * the After= dependency DAG.  On cycle, sotinit_topo_sort still
     * returns a full permutation (acyclic prefix + remaining units in
     * definition order) so we can always drive activation · degraded
     * but progresses (spec §4.5).  The "fell back · cycle" diagnostic
     * is printed once when rc < 0 so operators can investigate. */
    uint32_t order[SOTINIT_MAX_UNITS];
    uint32_t order_n = 0;
    int topo_rc = sotinit_topo_sort(order, &order_n);
    if (topo_rc < 0) {
        printf("[sotinit] activation order fell back · cycle\n");
    }

    /* PR 3 · activate every .service in state=LOADED via procd OP_SPAWN.
     * Targets stay in LOADED (no ExecStart to fire); timers wait for PR 7+.
     * Activation order now respects After= via the topo-sorted walk above.
     *
     * γ · PR 8 · units tagged UNIT_FLAG_F_PERSISTENCE by sotinit_sotfs_scan_now
     * are walked here too · sotinit_activate_service short-circuits with an
     * audit emit instead of dispatching to procd. */
    uint32_t active = 0;
    for (uint32_t i = 0; i < order_n; i++) {
        unit_t *u = sotinit_unit_by_index(order[i]);
        if (!u) continue;
        if (u->kind == UNIT_KIND_SERVICE && u->state == UNIT_STATE_LOADED) {
            if (sotinit_activate_service(u) == 0) active++;
        }
    }
    printf("[sotinit] %u services activated\n", active);

    /* PR 5 · operator-driven IPC loop on listen_ep.  Wire layout matches
     * sotinit_request_t / sotinit_reply_t (include/sotinit/proto.h):
     *   request (in):
     *     MR(0)     = op  (SOTINIT_OP_LIST / _STATUS / _START / _STOP)
     *     MR(1)     = arg32 (index for STATUS when name is empty)
     *     MR(2..9)  = name[64] packed 8 chars per word
     *   reply (out):
     *     MR(0)     = result (>=0 success / -errno)
     *     MR(1)     = state  (unit_state_t enum value)
     *     MR(2)     = procd_slot
     *
     * Total request length = 10 words · reply length = 3 words.  Well
     * within the 120-word MR budget so no SHM scratch is required.
     *
     * PR 8 wires SOTINIT_OP_ACTIVATE (timer-fire path from sotcron); for
     * now we NAK it with -38 (ENOSYS) so sotcron's announce silently
     * degrades without crashing sotinit when stacked early. */
    printf("[sotinit] listen loop entering · ep=%lu\n",
           (unsigned long)listen_ep);
    while (1) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t info = seL4_Recv(listen_ep, &badge);
        seL4_Word op = seL4_GetMR(0);
        (void)info;

        sotinit_request_t req = {0};
        req.op    = (uint32_t)op;
        req.arg32 = (uint32_t)seL4_GetMR(1);
        /* Read name (64 chars = 8 MRs from MR(2..9)). */
        for (int i = 0; i < 8; i++) {
            ((uint64_t *)req.name)[i] = (uint64_t)seL4_GetMR(2 + i);
        }

        /* PR 6 · SOTINIT_OP_PROC_EXITED is a one-way NBSend from orch ·
         * orch's procd-event drain forwards each PROCD_EV_PROC_EXITED
         * with MR(1)=procd slot, MR(2)=exit_code.  We MUST NOT seL4_Reply
         * here · orch did not seL4_Call so there is no Reply cap waiting.
         * Skip the reply path entirely for this opcode. */
        if (op == SOTINIT_OP_PROC_EXITED) {
            uint32_t slot      = (uint32_t)seL4_GetMR(1);
            int32_t  exit_code = (int32_t)seL4_GetMR(2);
            sotinit_on_proc_exited(slot, exit_code);
            continue;
        }

        sotinit_reply_t r = {0};
        switch (op) {
            case SOTINIT_OP_LIST:     r = sotinit_handle_list(&req); break;
            case SOTINIT_OP_STATUS:   r = sotinit_handle_status(&req); break;
            case SOTINIT_OP_START:    r = sotinit_handle_start(&req); break;
            case SOTINIT_OP_STOP:     r = sotinit_handle_stop(&req); break;
            case SOTINIT_OP_ACTIVATE: r = sotinit_handle_activate(&req); break;
            default:
                r.result = -38;
        }
        seL4_SetMR(0, (seL4_Word)r.result);
        seL4_SetMR(1, (seL4_Word)r.state);
        seL4_SetMR(2, (seL4_Word)r.procd_slot);
        seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 3));
    }
    return 0;
}
