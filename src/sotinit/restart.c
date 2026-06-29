/* sotOs · sotinit · restart policy handler (PR 6).
 *
 * Drives the systemd-style `Restart=` directive in response to procd's
 * PROCD_EV_PROC_EXITED events.  The transport is one-way:
 *
 *   procd  -- ring publish --> orch (orch_procd_drain in src/orch/main.c)
 *                                |
 *                                +-- forward as SOTINIT_OP_PROC_EXITED -->
 *                                              (seL4_NBSend, no reply)
 *                                                                       |
 *                                                                       v
 *                                                            sotinit_on_proc_exited
 *
 * Scope-reduction note · the β spec (§3.4) called for sotinit to read
 * procd's event ring directly from a RO SHM mapping.  Mapping procd's
 * 1 MiB SHM region into sotinit's vspace requires the same cross-process
 * SHM transport that PR 4 of persistence-substrate documented as deferred
 * ("async SHM-ring transport · two-process").  Orch already drains the
 * ring (PR 4 of procd) so we piggyback on that consumer · 80% less
 * plumbing for the same operator-visible outcome.
 *
 * Backoff · we guard restarts with a 500 ms TSC window per unit so a
 * crash-loop service can't pin the CPU.  TSC frequency is not calibrated
 * here · we assume ~1 GHz which yields a worst-case window of a few
 * hundred ms on real hardware.  Good enough for PR 6 · PR 7 of the
 * cron series adds a calibrated TSC helper we can share.
 *
 * Spec: init-cron-scheduler-design §3, §4.4.
 */
#include <stdio.h>
#include <stdint.h>
#include <sotinit/unit.h>
#include <sotguard/event.h>  /* β · PR 11 · SOTGUARD_KIND_SOTINIT_* audit kinds */

extern unit_t *sotinit_unit_by_procd_slot(uint32_t slot);
extern int sotinit_activate_service(unit_t *u);

/* Roughly 500 ms at 1 GHz (the actual TSC rate varies per platform · the
 * exact window doesn't matter, only that consecutive restarts are spaced
 * far enough apart to make a tight crash loop observably bounded). */
#define BACKOFF_TSC (500000000ull)

static uint64_t g_last_restart_tsc[SOTINIT_MAX_UNITS] = {0};

static uint64_t now_tsc(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

/* Called by main.c's listen-loop on SOTINIT_OP_PROC_EXITED.  Idempotent ·
 * if no unit is currently bound to procd_slot we log and drop (the slot
 * may have been re-used or the unit was stopped via OP_STOP earlier).
 *
 * Restart policy values come from unit_registry.c (parsed in scan.c's
 * kv_callback):
 *   0 = no         (default · do nothing, mark DISABLED)
 *   1 = on-failure (restart iff exit_code != 0, else DISABLED)
 *   2 = always     (restart regardless of exit_code)
 */
void sotinit_on_proc_exited(uint32_t procd_slot, int32_t exit_code) {
    unit_t *u = sotinit_unit_by_procd_slot(procd_slot);
    if (!u) {
        printf("[sotinit] proc_exited slot=%u · no matching unit\n",
               (unsigned)procd_slot);
        /* β · PR 11 · audit · still record the exit even if no unit
         * binding · slot may have been recycled or unit stopped.  This
         * gives an operator a fail-closed signal in anomaly-log that
         * orch's procd-event drain saw an unbindable EXIT. */
        printf("[sotinit] AUDIT kind=0x%02x SOTINIT_SERVICE_EXIT slot=%u exit_code=%d unit=(unbound)\n",
               (unsigned)SOTGUARD_KIND_SOTINIT_SERVICE_EXIT,
               (unsigned)procd_slot, (int)exit_code);
        return;
    }

    /* β · PR 11 · audit · every observed exit emits one SERVICE_EXIT event
     * at the entry of the handler · prior to restart-policy evaluation so
     * the timeline shows EXIT then (optionally) FAILED on backoff hit. */
    printf("[sotinit] AUDIT kind=0x%02x SOTINIT_SERVICE_EXIT unit=%s slot=%u exit_code=%d\n",
           (unsigned)SOTGUARD_KIND_SOTINIT_SERVICE_EXIT,
           u->name, (unsigned)procd_slot, (int)exit_code);

    /* Clear the slot binding so a subsequent restart's OP_SPAWN reply
     * can rebind cleanly · sotinit_activate_service writes the fresh
     * slot back via u->procd_slot. */
    uint32_t old_slot = u->procd_slot;
    u->procd_slot = 0;
    (void)old_slot;

    switch (u->restart_policy) {
        case 0: /* no */
            u->state = UNIT_STATE_DISABLED;
            printf("[sotinit] %s exited (code=%d) · Restart=no\n",
                   u->name, (int)exit_code);
            break;
        case 1: /* on-failure */
            if (exit_code != 0) {
                uint64_t now = now_tsc();
                if (u->index < SOTINIT_MAX_UNITS &&
                    now - g_last_restart_tsc[u->index] < BACKOFF_TSC) {
                    u->state = UNIT_STATE_FAILED;
                    printf("[sotinit] %s · restart backoff\n", u->name);
                    /* β · PR 11 · audit · restart policy gave up under
                     * crash-loop backoff · operator-visible FAILED event. */
                    printf("[sotinit] AUDIT kind=0x%02x SOTINIT_SERVICE_FAILED unit=%s reason=backoff_on_failure\n",
                           (unsigned)SOTGUARD_KIND_SOTINIT_SERVICE_FAILED,
                           u->name);
                    break;
                }
                if (u->index < SOTINIT_MAX_UNITS) {
                    g_last_restart_tsc[u->index] = now;
                }
                printf("[sotinit] %s exited (code=%d) · restarting\n",
                       u->name, (int)exit_code);
                u->state = UNIT_STATE_LOADED;
                sotinit_activate_service(u);
            } else {
                u->state = UNIT_STATE_DISABLED;
                printf("[sotinit] %s exited cleanly · Restart=on-failure\n",
                       u->name);
            }
            break;
        case 2: /* always */
            {
                uint64_t now = now_tsc();
                if (u->index < SOTINIT_MAX_UNITS &&
                    now - g_last_restart_tsc[u->index] < BACKOFF_TSC) {
                    u->state = UNIT_STATE_FAILED;
                    printf("[sotinit] %s · restart backoff\n", u->name);
                    printf("[sotinit] AUDIT kind=0x%02x SOTINIT_SERVICE_FAILED unit=%s reason=backoff_always\n",
                           (unsigned)SOTGUARD_KIND_SOTINIT_SERVICE_FAILED,
                           u->name);
                    break;
                }
                if (u->index < SOTINIT_MAX_UNITS) {
                    g_last_restart_tsc[u->index] = now;
                }
                printf("[sotinit] %s exited (code=%d) · Restart=always\n",
                       u->name, (int)exit_code);
                u->state = UNIT_STATE_LOADED;
                sotinit_activate_service(u);
            }
            break;
        default:
            /* Defensive: an unknown restart_policy value is treated as
             * "no" so a bad parser cannot trigger a spurious respawn. */
            u->state = UNIT_STATE_DISABLED;
            printf("[sotinit] %s exited (code=%d) · unknown Restart=%u · disabled\n",
                   u->name, (int)exit_code, (unsigned)u->restart_policy);
            break;
    }
}
