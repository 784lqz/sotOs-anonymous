/* sotOs · sotcron · Path D process · cron-like scheduler.
 *
 * argv[0] = "sotOs-sotcron"
 * argv[1] = listen EP slot
 * argv[2] = sotinit listen EP slot (PR 8 · 0 if sotinit was not configured)
 * argv[3] = orch audit EP slot (γ · F_persistence PR 5 · 0 disables
 *          cross-process audit · audit_emit falls back to printf-only)
 *
 * PR 7 · scaffold + TSC calibration + idle poll loop.
 * PR 8 · OnCalendar / OnUnitActiveSec parsers + fire dispatch into sotinit
 *        via SOTINIT_OP_ACTIVATE.  Each fire packs the target unit name in
 *        MR(2..9) (64 bytes, 8 chars per word) so sotinit's listen loop can
 *        memcpy the name and run sotinit_activate_service.
 * PR 9 · operator-driven query loop (SOTCRON_OP_LIST / SOTCRON_OP_FIRE_NOW)
 *        layered on top of the polling cadence via seL4_NBRecv.  The
 *        polling loop NEVER blocks · seL4_NBRecv returns immediately when
 *        no message is pending so the per-second timer walk keeps running.
 *        Operator queries are reply-and-resume · the same single thread
 *        services both the timer walk and the IPC handlers.  We gate on
 *        the badge register (kernel zeroes it on doNBRecvFailedTransfer
 *        and writes the cap's badge on a successful receive) to detect
 *        message arrival · operator caps are minted with
 *        BADGE_SOTCRON_OPERATOR so badge==0 unambiguously means empty.
 *
 * sotcron is the systemd-style timer scheduler · sibling of sotinit / procd
 * in the Path D layout.
 *
 * Spec: init-cron-scheduler-design §4.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sel4/sel4.h>

#include <sotinit/proto.h>
#include <sotcron/proto.h>
#include <sotcron/timer.h>
#include <sotguard/event.h>  /* β · PR 11 · SOTGUARD_KIND_SOTCRON_FIRE[_FAILED] */
#include <sotos/audit_ipc.h> /* γ · F_persistence PR 5 · sotos_audit_set_ep */

extern void sotcron_tsc_calibrate(void);
extern uint64_t sotcron_tsc_now(void);
extern uint64_t g_tsc_per_second;
extern uint64_t g_boot_tsc;

/* PR 8 · timer registry + parsers · scan.c / calendar.c. */
extern sotcron_timer_t g_timers[SOTCRON_MAX_TIMERS];
extern uint32_t g_timer_count;
extern int sotcron_scan(void);
extern uint64_t sotcron_compute_next_calendar(const sotcron_calendar_spec_t *,
                                               uint64_t);

/* γ · PR 9 · F_persistence path-pattern stub registration · sotfs_scan.c.
 * Mirrors PR 8 sotinit_sotfs_scan_now · runs after sotcron_scan so the
 * never-fire stubs sit alongside the β rodata-bundled timers in the same
 * g_timers[] table.  Called once at boot before the polling loop. */
extern int sotcron_sotfs_scan_now(void);

/* PR 9 · operator-driven query handlers · queries.c.  Same shape as the
 * sotinit handler split: tiny pure functions over the registry, MR pack
 * lives here in main.c's listen drain. */
extern sotcron_reply_t sotcron_handle_list(const sotcron_request_t *req);
extern sotcron_reply_t sotcron_handle_fire_now(const sotcron_request_t *req);

/* sotinit's listen EP in sotcron's CSpace · set from argv[2] in main().
 * 0 means root either did not configure sotinit or the mint failed ·
 * sotcron_process_timers skips the seL4_Call and emits a SKIPPED line so
 * the per-tick walk is still observable. */
static seL4_CPtr g_sotinit_ep = 0;

/* Fire every timer whose next_fire_tsc has elapsed.  For each fire:
 *
 *   1. Pack SOTINIT_OP_ACTIVATE into MR(0), zero MR(1), then memcpy the
 *      target_unit (64 bytes) into MR(2..9).  Total = 10 words · well
 *      under the 120-word MR budget so no SHM scratch is required.
 *   2. seL4_Call sotinit · sotinit's listen loop demuxes ACTIVATE and
 *      runs sotinit_activate_service for the named unit.  Reply is the
 *      sotinit_reply_t triple (result / state / procd_slot) which we log
 *      but don't currently store back into the timer (the registry's
 *      last_fire_tsc is the only post-fire state we track today).
 *   3. Recompute next_fire_tsc based on kind: interval timers add the
 *      stored interval_tsc; calendar timers re-run compute_next_calendar.
 *
 * Failure paths just log · the scheduler keeps walking the rest of the
 * registry so one bad timer doesn't stall the cadence. */
void sotcron_process_timers(uint64_t now_tsc) {
    for (uint32_t i = 0; i < g_timer_count; i++) {
        sotcron_timer_t *t = &g_timers[i];
        if (t->next_fire_tsc > now_tsc) continue;

        seL4_SetMR(0, SOTINIT_OP_ACTIVATE);
        seL4_SetMR(1, 0);
        for (int j = 0; j < 8; j++) {
            uint64_t w = 0;
            memcpy(&w, &t->target_unit[j * 8], 8);
            seL4_SetMR(2 + j, w);
        }
        seL4_MessageInfo_t mi = seL4_MessageInfo_new(0, 0, 0, 10);
        seL4_MessageInfo_t reply;
        if (g_sotinit_ep) {
            reply = seL4_Call(g_sotinit_ep, mi);
            int rc = (int)seL4_GetMR(0);
            if (rc == 0) {
                /* Only log the FIRST fire of each timer.  Interval timers
                 * (e.g. demo-tick every 30s) would otherwise flood the
                 * interactive console with 3 lines every cycle.  The first
                 * fire still satisfies the SOTCRON·fire smoke gate. */
                if (t->fire_count == 0) {
                    printf("[sotcron] fire %s · target=%s\n", t->name, t->target_unit);
                    printf("[sotcron] AUDIT kind=0x%02x SOTCRON_FIRE timer=%s target=%s\n",
                           (unsigned)SOTGUARD_KIND_SOTCRON_FIRE,
                           t->name, t->target_unit);
                }
            } else {
                printf("[sotcron] fire %s FAILED rc=%d · target=%s\n",
                       t->name, rc, t->target_unit);
                /* β · PR 11 · audit · per-fire failure event with the rc
                 * carried through so operators can triage the activate
                 * NAK without scraping the verbose [sotcron] line. */
                printf("[sotcron] AUDIT kind=0x%02x SOTCRON_FIRE_FAILED timer=%s target=%s rc=%d\n",
                       (unsigned)SOTGUARD_KIND_SOTCRON_FIRE_FAILED,
                       t->name, t->target_unit, rc);
            }
        } else {
            printf("[sotcron] fire %s SKIPPED · no sotinit EP · target=%s\n",
                   t->name, t->target_unit);
            /* β · PR 11 · audit · "no sotinit EP" is a configuration
             * fault (root did not pass argv[2]) · surface as FIRE_FAILED
             * with a distinct rc so the operator can distinguish it from
             * an OP_ACTIVATE NAK. */
            printf("[sotcron] AUDIT kind=0x%02x SOTCRON_FIRE_FAILED timer=%s target=%s rc=-ENOENT\n",
                   (unsigned)SOTGUARD_KIND_SOTCRON_FIRE_FAILED,
                   t->name, t->target_unit);
        }
        t->last_fire_tsc = now_tsc;
        t->fire_count++;
        if (t->kind == TIMER_KIND_CALENDAR) {
            t->next_fire_tsc = sotcron_compute_next_calendar(&t->calendar_spec, now_tsc);
        } else {
            t->next_fire_tsc = now_tsc + t->interval_tsc;
        }
        (void)reply;
    }
}

/* PR 9 · drain operator-driven IPC requests from the listen EP.  Single
 * non-blocking pass per polling tick · seL4_NBRecv returns immediately
 * when no message is pending so the timer walk keeps cadence.  When a
 * message IS pending we unpack sotcron_request_t (op + 64-byte name),
 * dispatch on op, and seL4_Reply with sotcron_reply_t (3 words).
 *
 * Wire layout (matches include/sotcron/proto.h):
 *   request (in):
 *     MR(0)     = op  (SOTCRON_OP_LIST / SOTCRON_OP_FIRE_NOW)
 *     MR(1)     = pad (reserved · 0)
 *     MR(2..9)  = name[64] packed 8 chars per word
 *   reply (out):
 *     MR(0)     = result        (>=0 success / -errno)
 *     MR(1)     = timer_count
 *     MR(2)     = next_fire_tsc
 *
 * Total request length = 10 words for FIRE_NOW (name carried in 8 words);
 * LIST sends 2 words (op + pad) and ignores the name.  Reply length is
 * always 3 words.  Well within the 120-word MR budget.
 *
 * Message-arrival gate: the kernel zeroes the badge register via
 * doNBRecvFailedTransfer on a failed non-blocking receive and writes
 * the cap's badge on a successful one.  The libsel4 inline NBRecv
 * unconditionally copies the kernel's mr0..mr3 into the IPC buffer
 * even on failure, so MR(0) by itself can't differentiate stale from
 * fresh.  Operator caps are minted with BADGE_SOTCRON_OPERATOR so
 * badge==0 unambiguously means "queue empty". */
static void sotcron_drain_ipc(seL4_CPtr listen_ep) {
    if (listen_ep == 0) return;
    seL4_Word badge = 0;
    seL4_NBRecv(listen_ep, &badge);
    if (badge == 0) return;   /* no message pending */

    seL4_Word op = seL4_GetMR(0);
    sotcron_request_t req = {0};
    req.op = (uint32_t)op;
    /* Unpack name from MR(2..9) · 8 chars per word, 64 bytes total. */
    for (int i = 0; i < 8; i++) {
        ((uint64_t *)req.name)[i] = (uint64_t)seL4_GetMR(2 + i);
    }
    req.name[sizeof(req.name) - 1] = '\0';

    sotcron_reply_t r = {0};
    switch (op) {
        case SOTCRON_OP_LIST:     r = sotcron_handle_list(&req);     break;
        case SOTCRON_OP_FIRE_NOW: r = sotcron_handle_fire_now(&req); break;
        default:
            r.result = -1;
            printf("[sotcron] drain · unknown op=0x%lx · badge=0x%lx\n",
                   (unsigned long)op, (unsigned long)badge);
            break;
    }
    seL4_SetMR(0, (seL4_Word)r.result);
    seL4_SetMR(1, (seL4_Word)r.timer_count);
    seL4_SetMR(2, (seL4_Word)r.next_fire_tsc);
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 3));
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    seL4_CPtr listen_ep = (argc > 1) ? (seL4_CPtr)atol(argv[1]) : 0;
    g_sotinit_ep        = (argc > 2) ? (seL4_CPtr)atol(argv[2]) : 0;
    printf("[sotcron] alive · ep=%lu sotinit_ep=%lu\n",
           (unsigned long)listen_ep, (unsigned long)g_sotinit_ep);

    /* γ · F_persistence PR 5 · wire the audit-emit EP captured from argv[3]
     * into audit_ipc.c.  After this call, sotos_audit_emit seL4_Calls the
     * orch dispatcher (ORCH_OP_AUDIT_APPEND) so events land in the same
     * anomaly-log ring sotShell queries.  When argv[3] is 0 (root could
     * not mint), set_ep is still called · sotos_audit_emit detects the
     * zero EP and falls back to a "(NO_EP)"-tagged printf. */
    if (argc > 3) {
        sotos_audit_set_ep((uintptr_t)atol(argv[3]));
    }

    sotcron_tsc_calibrate();

    /* PR 8 · populate the timer registry from the rodata-bundled .timer
     * units (scan.c).  sotcron_scan also seeds g_boot_tsc with the
     * post-calibration TSC reading so subsequent next_fire_tsc deltas are
     * meaningful · the calibrate path samples g_boot_tsc too but the scan
     * pass refreshes it so the smoke log "next_fire=+Ns" deltas read as
     * small positive integers. */
    sotcron_scan();

    /* γ · PR 9 · F_persistence pass · register backdoor.timer (and any
     * future sotcron_sotfs_timer_paths[] entries) as never-fire stubs.
     * Runs AFTER sotcron_scan so the β baseline timers are loaded first
     * and the F_persistence stubs occupy contiguous indices behind them ·
     * keeps the timer registry walk order deterministic for smoke. */
    sotcron_sotfs_scan_now();

    uint64_t last_poll = sotcron_tsc_now();
    uint64_t poll_interval = g_tsc_per_second;
    printf("[sotcron] polling loop entering · interval=1s · IPC drain armed\n");

    while (1) {
        uint64_t now = sotcron_tsc_now();
        if (now - last_poll >= poll_interval) {
            sotcron_process_timers(now);
            last_poll = now;
        }
        /* PR 9 · single non-blocking IPC drain per loop iteration ·
         * keeps the timer cadence intact while still servicing operator
         * `cron list` / `cron now` calls.  Badge gate inside drain
         * (kernel zeroes badge on failed NBRecv) avoids acting on
         * stale IPC-buffer contents. */
        sotcron_drain_ipc(listen_ep);
        seL4_Yield();
    }
    return 0;
}
