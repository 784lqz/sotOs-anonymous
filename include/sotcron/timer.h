/* sotOs · sotcron · timer registry types.
 *
 * Owns the in-memory timer table the scheduler walks once per poll tick.
 * PR 7 ships the type definitions only · no entries are populated yet.
 * PR 8 wires the OnCalendar / OnUnitActiveSec parsers and the fire
 * dispatch path that consumes next_fire_tsc.
 *
 * Spec: init-cron-scheduler-design §4.
 */
#ifndef SOTCRON_TIMER_H
#define SOTCRON_TIMER_H

#include <stdint.h>

#define SOTCRON_MAX_TIMERS 32
#define SOTCRON_NAME_MAX   64

typedef enum {
    TIMER_KIND_CALENDAR = 1,
    TIMER_KIND_INTERVAL = 2,
} sotcron_timer_kind_t;

typedef struct {
    int8_t hour;     /* -1 = wildcard */
    int8_t minute;
    int8_t second;
} sotcron_calendar_spec_t;

typedef struct {
    uint32_t index;
    sotcron_timer_kind_t kind;
    char     name[SOTCRON_NAME_MAX];
    char     target_unit[SOTCRON_NAME_MAX];
    sotcron_calendar_spec_t calendar_spec;
    uint64_t interval_tsc;
    uint64_t next_fire_tsc;
    uint64_t last_fire_tsc;
    uint32_t fire_count;     /* number of times this timer has fired */
} sotcron_timer_t;

#endif
