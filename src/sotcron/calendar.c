/* sotOs · sotcron · OnCalendar + OnUnitActiveSec parsers.
 *
 * Two tiny parsers that lift the systemd-style timer directives into the
 * sotcron_calendar_spec_t / interval_tsc fields of sotcron_timer_t (see
 * include/sotcron/timer.h).  The supported subset is intentionally narrow:
 *
 *   OnCalendar=*-*-* HH:MM:SS   · daily, with `*` wildcards on H/M/S
 *   OnUnitActiveSec=<N>(s|min|h|d)  · interval period
 *
 * Anything richer (weekday lists, ranges like `Mon..Fri`, multi-day
 * patterns) is rejected by sotcron_parse_on_calendar with -1 and the
 * caller marks the timer load as failed (the smoke gate would catch the
 * resulting "[sotcron] WARN · bad OnCalendar=..." log).  These are good
 * enough for the β-mandated demo-tick.timer fixture and exercise the full
 * scan/parse/fire pipeline end-to-end.
 *
 * sotcron_compute_next_calendar walks forward one second at a time over a
 * 24 h window looking for the first matching wall-clock instant; the
 * caller is responsible for re-running this after each fire to advance
 * the next_fire_tsc field.  The TSC anchor is g_boot_tsc + the synthetic
 * "seconds since boot" coordinate (sotcron does not have an absolute
 * wall-clock cap today · spec §4.4 punts NTP / RTC to a follow-up PR).
 *
 * Spec: init-cron-scheduler-design §4.4.
 */
#include <stdint.h>
#include <string.h>

#include <sotcron/timer.h>

extern uint64_t g_tsc_per_second;
extern uint64_t g_boot_tsc;

int sotcron_parse_on_calendar(const char *str, sotcron_calendar_spec_t *out) {
    if (strncmp(str, "*-*-* ", 6) != 0) return -1;
    const char *p = str + 6;
    int hh = -1, mm = -1, ss = -1;
    if (*p == '*') { hh = -1; p += 2; }
    else { hh = (p[0] - '0') * 10 + (p[1] - '0'); p += 3; }
    if (*p == '*') { mm = -1; p += 2; }
    else { mm = (p[0] - '0') * 10 + (p[1] - '0'); p += 3; }
    if (*p == '*') { ss = -1; }
    else { ss = (p[0] - '0') * 10 + (p[1] - '0'); }
    if (hh > 23 || mm > 59 || ss > 59) return -1;
    out->hour = (int8_t)hh;
    out->minute = (int8_t)mm;
    out->second = (int8_t)ss;
    return 0;
}

int sotcron_parse_on_unit_active_sec(const char *str, uint64_t *out_interval_tsc) {
    uint64_t n = 0;
    const char *p = str;
    while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; }
    if (p == str) return -1;
    uint64_t mult = 0;
    if      (strcmp(p, "s")   == 0) mult = 1;
    else if (strcmp(p, "min") == 0) mult = 60;
    else if (strcmp(p, "h")   == 0) mult = 3600;
    else if (strcmp(p, "d")   == 0) mult = 86400;
    else return -1;
    *out_interval_tsc = n * mult * g_tsc_per_second;
    return 0;
}

uint64_t sotcron_compute_next_calendar(const sotcron_calendar_spec_t *spec,
                                        uint64_t now_tsc) {
    uint64_t now_sec = (now_tsc - g_boot_tsc) / g_tsc_per_second;
    for (uint32_t delta = 1; delta < 86400; delta++) {
        uint64_t cand = now_sec + delta;
        uint32_t h = (cand / 3600) % 24;
        uint32_t m = (cand / 60) % 60;
        uint32_t s = cand % 60;
        if ((spec->hour < 0   || spec->hour   == (int8_t)h) &&
            (spec->minute < 0 || spec->minute == (int8_t)m) &&
            (spec->second < 0 || spec->second == (int8_t)s)) {
            return g_boot_tsc + cand * g_tsc_per_second;
        }
    }
    return now_tsc + 86400ULL * g_tsc_per_second;
}
