/* sotOs · sotcron · operator query handlers.
 *
 * Backs the two operator-driven IPC verbs exposed on the sotcron listen
 * EP (PR 9 · spec §4.5):
 *
 *   SOTCRON_OP_LIST     · return the timer registry count + next_fire_tsc of
 *                         the first timer.  Diagnostic banner "[sotcron] LIST"
 *                         is the smoke gate.
 *   SOTCRON_OP_FIRE_NOW · operator-fires a named timer · sets next_fire_tsc
 *                         to "now" so process_timers() fires it on the very
 *                         next polling tick.  Returns -3 (ENOENT) when the
 *                         name is not in the registry.
 *
 * Tiny pure functions: read/mutate the timer registry, return a
 * sotcron_reply_t struct.  main.c's listen loop is responsible for the
 * MR pack/unpack (sotcron_request_t in, sotcron_reply_t out).
 *
 * Spec: init-cron-scheduler-design §4.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sotcron/proto.h>
#include <sotcron/timer.h>

/* PR 8 · timer registry · scan.c populates g_timers[] and g_timer_count. */
extern sotcron_timer_t g_timers[SOTCRON_MAX_TIMERS];
extern uint32_t        g_timer_count;

/* PR 7 · TSC helper · tsc.c. */
extern uint64_t sotcron_tsc_now(void);

sotcron_reply_t sotcron_handle_list(const sotcron_request_t *req) {
    (void)req;
    sotcron_reply_t r = {0};
    r.result      = (int32_t)g_timer_count;
    r.timer_count = g_timer_count;
    if (g_timer_count > 0) r.next_fire_tsc = g_timers[0].next_fire_tsc;
    printf("[sotcron] LIST · count=%u\n", g_timer_count);
    return r;
}

sotcron_reply_t sotcron_handle_fire_now(const sotcron_request_t *req) {
    sotcron_reply_t r = {0};
    for (uint32_t i = 0; i < g_timer_count; i++) {
        if (strncmp(g_timers[i].name, req->name, SOTCRON_NAME_MAX) == 0) {
            g_timers[i].next_fire_tsc = sotcron_tsc_now();
            printf("[sotcron] FIRE_NOW · timer=%s · scheduled for next poll\n",
                   g_timers[i].name);
            r.result        = 0;
            r.timer_count   = g_timer_count;
            r.next_fire_tsc = g_timers[i].next_fire_tsc;
            return r;
        }
    }
    printf("[sotcron] FIRE_NOW · name=%s NOT FOUND\n", req->name);
    r.result = -3;
    return r;
}
