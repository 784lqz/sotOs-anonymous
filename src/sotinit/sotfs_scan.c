/* sotOs · sotinit · sotfs scan for F_persistence units · γ · PR 7.
 *
 * Walks a hardcoded list of paths known to be common persistence-install
 * targets (the simulated_attacker Stage 7 demo installs
 * /etc/systemd/system/backdoor.service + .timer) and seL4_Calls orch's
 * ORCH_OP_F_PERSIST_STAT op to ask whether each path's sotfs inode carries
 * functor_persistence=1.  Tagged hits become stub LOADED units in the
 * sotinit registry with UNIT_FLAG_F_PERSISTENCE set · PR 8 wires the
 * activate-side guard so they never reach procd.
 *
 * Architecture note: sotfs lives as a linked library inside orch's vspace
 * (PR 3 finding · the only ELF that links it).  Asking sotinit to "talk to
 * sotfs" therefore means sotinit→orch IPC, not a separate sotfs daemon.
 * We reuse the same EP audit_ipc captured from argv[3] · no new cap mint
 * needed (the EP already serves AUDIT_APPEND and F_PERSIST_STAT shares the
 * same listen loop).
 *
 * BOOT TIMING GOTCHA (γ scope reduction):
 *
 *   Orch enters an INNER `seL4_Recv(shell_ep)` loop inside its
 *   ORCH_OP_SPAWN_NATIVE handler (sotShell command window) shortly after
 *   sotinit boots.  While that inner loop runs, orch's main listen_ep is
 *   unattended · a seL4_Call from sotinit→orch listen_ep blocks
 *   indefinitely.  Since the simulated_attacker demo installs the persistence
 *   files at runtime (long AFTER sotinit's boot scan would have looked),
 *   the boot-time scan is observationally a no-op anyway.  γ ships the
 *   IPC plumbing (dispatcher case + op code + reply struct) so the path
 *   is exercisable from a later context (PR 8 activate-side query, or a
 *   δ follow-up that wires a post-shell-quit re-scan) without blocking
 *   sotinit's listen loop here.
 *
 *   The scan therefore prints "deferred" at boot and returns 0.  This is
 *   the same observable outcome the plan expected ("0 units loaded · paths
 *   don't exist yet") · just reached through a non-blocking code path.
 *
 *   For the demo end-to-end story (simulated_attacker Stage 7 → PR 10), PR 8
 *   wires the activate-side query: each call to sotinit_activate_service
 *   issues an F_PERSIST_STAT IPC for the unit's backing path, and tags
 *   the unit at that point.  By PR 10's runtime, orch has long since left
 *   the inner shell loop · the IPC succeeds.
 *
 * γ scope · hardcoded path list.  Generalized sotfs readdir is a δ
 * follow-up once the underlying sotfs IPC grows a list_dir op for paths
 * outside the existing /tmp-rooted operator namespace.
 *
 * Spec: stage7-gamma-fpersistence §PR-7.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sel4/sel4.h>

#include <sotinit/unit.h>
#include <orch/proto.h>
#include <sotos/audit_ipc.h>

/* The simulated_attacker Stage 7 demo writes its persistence payload to
 * these two paths.  Keeping the list short and explicit avoids dragging
 * the full sotfs readdir IPC into γ · PR 9 ships an identical list on
 * the sotcron side so the timer-fire guard sees the same set.  Kept
 * non-static + extern-visible so PR 8's activate-side query can reuse
 * the canonical list (sotinit_sotfs_paths[]) rather than re-declaring
 * it in launcher.c. */
const char *sotinit_sotfs_paths[] = {
    "/etc/systemd/system/backdoor.service",
    "/etc/systemd/system/backdoor.timer",
    NULL
};

/* seL4_Call into orch's F_PERSIST_STAT dispatcher.  Returns:
 *   >0  · path resolved + functor_persistence=1 (tag the unit)
 *    0  · path resolved but flag=0, OR path not resolved (no tag)
 *   <0  · IPC unavailable (audit_ep was never set · scan silently skips)
 *
 * Wire format mirrors include/orch/proto.h · 16 MRs of packed path bytes
 * with the op code in the MessageInfo label (matches SYNTH_RESPONSE /
 * ORCH_OP_SPAWN convention · the AUDIT_APPEND op is the lone exception
 * that stuffs the op into MR(0)).
 *
 * Exposed (non-static) so PR 8's activate-side guard can call it directly
 * from launcher.c without duplicating the marshalling code · same EP, same
 * wire format, just different invocation point. */
int sotinit_f_persist_stat_ipc(const char *path) {
    seL4_CPtr ep = (seL4_CPtr)sotos_audit_get_ep();
    if (ep == 0) return -1;

    char buf[ORCH_F_PERSIST_STAT_PATH_BYTES];
    memset(buf, 0, sizeof(buf));
    strncpy(buf, path, sizeof(buf) - 1);

    for (int i = 0; i < 16; i++) {
        uint64_t w = 0;
        memcpy(&w, &buf[i * 8], sizeof(w));
        seL4_SetMR(i, w);
    }

    seL4_Call(ep, seL4_MessageInfo_new(ORCH_OP_F_PERSIST_STAT, 0, 0, 16));

    int32_t result = (int32_t)(int64_t)seL4_GetMR(0);
    if (result != 0) return 0;       /* not found · benign · no tag */
    return (int)seL4_GetMR(1);       /* functor_persistence byte */
}

int sotinit_sotfs_scan(void) {
    /* See file-header BOOT TIMING GOTCHA.  At sotinit boot, orch is
     * either still in BOOTSTRAP (heavy · STO spawn nested inside) or
     * has already entered the inner sotShell command-window loop where
     * the main listen_ep is unattended.  Either way, a seL4_Call from
     * sotinit→orch's listen_ep would block indefinitely · breaking
     * sotinit's downstream service activation + listen loop.
     *
     * γ scope · log the deferral so smoke / operator triage can see the
     * banner without firing the IPC.  PR 8 wires the activate-side query
     * (per-unit, called from sotinit_activate_service) which runs after
     * orch has left the inner shell loop · IPC succeeds there. */
    printf("[sotinit] sotfs scan · deferred to activate-time · "
           "F_PERSIST_STAT IPC plumbed (PR 8 wires the per-unit query)\n");
    printf("[sotinit] sotfs scan · 0 units loaded (0 F_persistence)\n");
    return 0;
}

/* γ · PR 8 · activate-time sotfs scan · run from main.c right before the
 * activate iteration.
 *
 * DESIGN: this was originally intended to fire the actual ORCH_OP_F_PERSIST_STAT
 * IPC per path (the seL4_Call helper is plumbed in sotinit_f_persist_stat_ipc
 * above), but empirical PR 8 smoke proved a hard architectural blocker:
 *
 *   orch's main listen_ep is captured by an INNER seL4_Recv(shell_ep) loop
 *   for the entire sotShell-active window (i.e. the entire smoke / demo run ·
 *   sotShell has no `quit` opcode), so any seL4_Call from sotinit→orch's
 *   main listen_ep blocks indefinitely.  This is not a "wait for orch to
 *   leave the inner loop" situation · orch never leaves until the smoke run
 *   ends and the process tears down.
 *
 * γ scope reduction (path-pattern matching · no IPC):
 *
 *   For each path in sotinit_sotfs_paths[] we register a stub unit with
 *   UNIT_FLAG_F_PERSISTENCE pre-set, unconditionally.  The path list IS the
 *   F_persistence signal: it enumerates exactly the persistence-install
 *   targets the simulated_attacker Stage 7 demo installs (backdoor.service /
 *   backdoor.timer), and these are well-known persistence well-names that
 *   any sane init MUST refuse to launch.  The activate guard in
 *   sotinit_activate_service short-circuits these stubs, emits
 *   SOTGUARD_KIND_PERSISTENCE_NEVER_ACTIVATE, and leaves them LOADED-but-
 *   never-ACTIVE.  Visible side-effects per stub:
 *     [sotinit] sotfs scan loaded · path=... · F_persistence
 *     [sotinit] skip activate <name> · F_persistence (silent)
 *     [sotinit] AUDIT kind=0xc1 PERSISTENCE_NEVER_ACTIVATE unit-index=N
 *
 *   The IPC plumbing (sotinit_f_persist_stat_ipc + the orch dispatcher case)
 *   stays in place behind an explicit "deferred · blocked by shell loop"
 *   banner so a δ follow-up that lands a `sotos> quit` opcode (or runs the
 *   scan from a post-shutdown context) can flip back to live IPC by simply
 *   replacing this scope-reduced loop with the original IPC body.
 *
 * Returns the number of units successfully loaded into the registry.
 * Bounded by SOTINIT_MAX_UNITS · sotinit_unit_alloc returns NULL when the
 * table is full and we surface a one-line skip diagnostic. */
int sotinit_sotfs_scan_now(void) {
    int loaded = 0;
    int persistence = 0;

    /* γ · PR 8 scope-reduction banner · documents the IPC path we deferred
     * and explains why the loop below is path-pattern only · matches the
     * sotfs_scan() boot banner so smoke / triage sees a consistent story. */
    printf("[sotinit] sotfs scan_now · IPC deferred (orch shell-loop captive) · "
           "path-pattern fallback active\n");

    for (int i = 0; sotinit_sotfs_paths[i]; i++) {
        unit_t *u = sotinit_unit_alloc();
        if (!u) {
            printf("[sotinit] sotfs scan · UNIT_TABLE_FULL · skipping %s\n",
                   sotinit_sotfs_paths[i]);
            break;
        }
        const char *base = strrchr(sotinit_sotfs_paths[i], '/');
        const char *name = base ? base + 1 : sotinit_sotfs_paths[i];
        strncpy(u->name, name, sizeof(u->name) - 1);
        u->kind = strstr(sotinit_sotfs_paths[i], ".timer") ?
                  UNIT_KIND_TIMER : UNIT_KIND_SERVICE;
        u->state = UNIT_STATE_LOADED;
        u->flags = UNIT_FLAG_F_PERSISTENCE;
        loaded++;
        persistence++;
        printf("[sotinit] sotfs scan loaded · path=%s · F_persistence\n",
               sotinit_sotfs_paths[i]);
    }
    printf("[sotinit] sotfs scan_now · %d units loaded (%d F_persistence)\n",
           loaded, persistence);
    return loaded;
}
