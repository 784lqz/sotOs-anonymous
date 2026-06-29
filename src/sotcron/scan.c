/* sotOs · sotcron · rodata-embedded timer scan.
 *
 * Mirrors sotinit/scan.c's Option C pattern: instead of walking the
 * conceptual /etc/systemd/system/ directory (which would require a sotfs
 * IPC channel into sotcron's CSpace · deferred), the bundled .timer unit
 * fragments live in this ELF's .rodata.  Each entry has a target_unit
 * (the .service the timer activates) and exactly one of an OnCalendar
 * or OnUnitActiveSec directive.
 *
 * The PR 8 baseline ships a single demo-tick.timer fixture · 30 s
 * interval pointing at demo-noop.service · which fires once during the
 * smoke window (~35 s after boot, well inside the 120 s smoke timeout).
 * The fire event reaches sotinit via seL4_Call(g_sotinit_ep,
 * SOTINIT_OP_ACTIVATE) and the operator-visible evidence is the
 * "[sotcron] fire demo-tick.timer · target=demo-noop.service" line.
 *
 * Spec: init-cron-scheduler-design §4.5.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sotcron/timer.h>

extern int sotcron_parse_on_calendar(const char *, sotcron_calendar_spec_t *);
extern int sotcron_parse_on_unit_active_sec(const char *, uint64_t *);
extern uint64_t sotcron_compute_next_calendar(const sotcron_calendar_spec_t *,
                                               uint64_t);
extern uint64_t g_tsc_per_second;
extern uint64_t g_boot_tsc;
extern uint64_t sotcron_tsc_now(void);

sotcron_timer_t g_timers[SOTCRON_MAX_TIMERS];
uint32_t g_timer_count = 0;

typedef struct {
    const char *name;
    const char *target_unit;
    const char *on_calendar;       /* NULL if interval-kind */
    const char *on_unit_active_sec;/* NULL if calendar-kind */
} bundled_timer_t;

static const bundled_timer_t g_bundled_timers[] = {
    {
        .name        = "demo-tick.timer",
        .target_unit = "demo-noop.service",
        .on_calendar = NULL,
        .on_unit_active_sec = "30s",
    },
};

int sotcron_scan(void) {
    uint64_t boot_now = sotcron_tsc_now();
    g_boot_tsc = boot_now;
    g_timer_count = 0;

    for (uint32_t i = 0; i < sizeof(g_bundled_timers)/sizeof(g_bundled_timers[0]); i++) {
        if (g_timer_count >= SOTCRON_MAX_TIMERS) break;
        const bundled_timer_t *src = &g_bundled_timers[i];
        sotcron_timer_t *t = &g_timers[g_timer_count];
        memset(t, 0, sizeof(*t));
        t->index = g_timer_count;
        strncpy(t->name, src->name, SOTCRON_NAME_MAX - 1);
        strncpy(t->target_unit, src->target_unit, SOTCRON_NAME_MAX - 1);

        if (src->on_calendar) {
            t->kind = TIMER_KIND_CALENDAR;
            if (sotcron_parse_on_calendar(src->on_calendar, &t->calendar_spec) != 0) {
                printf("[sotcron] WARN · bad OnCalendar=%s · skipping %s\n",
                       src->on_calendar, src->name);
                continue;
            }
            t->next_fire_tsc = sotcron_compute_next_calendar(&t->calendar_spec, boot_now);
        } else if (src->on_unit_active_sec) {
            t->kind = TIMER_KIND_INTERVAL;
            if (sotcron_parse_on_unit_active_sec(src->on_unit_active_sec, &t->interval_tsc) != 0) {
                printf("[sotcron] WARN · bad OnUnitActiveSec=%s · skipping %s\n",
                       src->on_unit_active_sec, src->name);
                continue;
            }
            t->next_fire_tsc = boot_now + t->interval_tsc;
        } else {
            continue;
        }
        printf("[sotcron] scan loaded %s · target=%s · next_fire=+%lus\n",
               t->name, t->target_unit,
               (unsigned long)((t->next_fire_tsc - boot_now) / g_tsc_per_second));
        g_timer_count++;
    }
    printf("[sotcron] scan complete · %u timers loaded\n", g_timer_count);
    return (int)g_timer_count;
}
