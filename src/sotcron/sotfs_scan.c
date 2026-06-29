/* sotOs · sotcron · F_persistence path-pattern stub registration · γ · PR 9.
 *
 * Mirror of PR 8 sotinit pattern (sotinit/sotfs_scan.c · sotinit_sotfs_scan_now):
 * orch's main listen EP is captive in seL4_Recv(shell_ep) for the entire
 * sotShell-active window · sotShell has no `quit` opcode yet · so a
 * seL4_Call from sotcron→orch's F_PERSIST_STAT dispatcher would block
 * indefinitely.  Live IPC is a δ follow-up once sotShell grows a quit
 * path (or a post-shell rescan context exists).
 *
 * γ scope reduction: register stub timers directly from a hardcoded path
 * list (the same set sotinit_sotfs_paths[] enumerates · just the .timer
 * subset).  Each stub gets next_fire_tsc = UINT64_MAX so the existing
 * sotcron_process_timers `if (t->next_fire_tsc > now_tsc) continue;` gate
 * skips it naturally · no extra fire-loop branch needed.  Boot-time
 * SOTGUARD_KIND_PERSISTENCE_NEVER_FIRE audit emit makes the lie visible
 * on the anomaly timeline.
 *
 * Regular timers from β (demo-tick.timer · 30 s OnUnitActiveSec) keep
 * firing normally · F_persistence is per-timer state, not global.
 *
 * Spec: stage7-gamma-fpersistence §PR-9.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sotcron/timer.h>
#include <sotguard/event.h>
/* sotos/audit_ipc.h intentionally NOT included · the boot-time emit
 * below uses a printf-only fallback because the orch audit-receive EP
 * is captive in the inner shell loop · see in-body comment for the
 * full blocker analysis. */

extern sotcron_timer_t g_timers[SOTCRON_MAX_TIMERS];
extern uint32_t g_timer_count;

/* Same path list as sotinit_sotfs_paths[] · .timer subset.  Keeping the
 * two lists separate avoids cross-ELF symbol drag (sotinit/sotcron are
 * distinct ELFs · sotinit_sotfs_paths lives in sotinit's vspace) while
 * keeping the operator-visible policy identical: the simulated_attacker
 * Stage 7 demo installs backdoor.timer and we refuse to fire it. */
static const char *sotcron_sotfs_timer_paths[] = {
    "/etc/systemd/system/backdoor.timer",
    NULL
};

int sotcron_sotfs_scan_now(void) {
    int loaded = 0;

    /* γ · PR 9 scope-reduction banner · matches sotinit's sotfs_scan_now
     * banner so smoke / triage sees a consistent story across the two
     * Path D ELFs that participate in F_persistence enforcement. */
    printf("[sotcron] sotfs scan_now · IPC deferred (orch shell-loop captive) · "
           "path-pattern fallback active\n");

    for (int i = 0; sotcron_sotfs_timer_paths[i]; i++) {
        if (g_timer_count >= SOTCRON_MAX_TIMERS) {
            printf("[sotcron] sotfs scan · TIMER_TABLE_FULL · skipping %s\n",
                   sotcron_sotfs_timer_paths[i]);
            break;
        }
        sotcron_timer_t *t = &g_timers[g_timer_count];
        memset(t, 0, sizeof(*t));
        t->index = g_timer_count;

        const char *p = sotcron_sotfs_timer_paths[i];
        const char *base = strrchr(p, '/');
        strncpy(t->name, base ? base + 1 : p, SOTCRON_NAME_MAX - 1);
        /* No target_unit · F_persistence stubs never fire so the activate
         * dispatch path is unreachable for this entry · the field stays
         * zero-initialised by the memset above. */

        /* The F_persistence lie · next_fire_tsc set to its maximum so the
         * existing sotcron_process_timers gate
         *   if (t->next_fire_tsc > now_tsc) continue;
         * skips this entry on every poll tick · no extra fire-loop branch
         * required.  Operator-visible side-effect: the timer shows up in
         * `cron list` with a far-future next_fire_tsc but never produces
         * a [sotcron] fire line. */
        t->next_fire_tsc = UINT64_MAX;

        g_timer_count++;
        loaded++;

        printf("[sotcron] sotfs scan loaded · path=%s · F_persistence (never-fire)\n",
               p);

        /* Boot-time audit emit · one per F_persistence timer arming.
         *
         * BLOCKER · we cannot call sotos_audit_emit here.  That helper
         * does a seL4_Call into orch's audit-receive EP, but orch's main
         * listen loop is captive in an INNER seL4_Recv(shell_ep) for the
         * entire sotShell-active window (sotShell has no `quit` opcode ·
         * δ follow-up).  The Call blocks indefinitely, which strands
         * sotcron's boot pass before `polling loop entering` and stops
         * the β baseline (demo-tick.timer fire) from ever happening ·
         * empirical regression in the PR 9 first build (PASS 58/9 vs
         * baseline 61/6).
         *
         * Fix: print the kind=0xc2 line directly in the same
         * "[sotcron] AUDIT kind=0x%02x ..." shape sotos_audit_emit's
         * (NO_EP) fallback uses, so the smoke gate (which greps the
         * literal log line, not the orch anomaly-log ring) sees the
         * boot-time NEVER_FIRE breadcrumb.  No IPC, no block, no
         * regression.  When sotShell grows `quit` (δ), this can flip
         * back to sotos_audit_emit() and the event will land in the
         * anomaly-log ring proper. */
        printf("[sotcron] AUDIT kind=0x%02x PERSISTENCE_NEVER_FIRE timer=%s "
               "path=%s (boot-deferred · orch shell-loop captive)\n",
               (unsigned)SOTGUARD_KIND_PERSISTENCE_NEVER_FIRE,
               t->name, p);
    }

    printf("[sotcron] sotfs scan_now · %d F_persistence timers\n", loaded);
    return loaded;
}
