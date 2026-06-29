/* sotOs · sotinit · unit registry · bounded table.
 *
 * Single-process backing store for parsed unit_t entries.  Today the table
 * lives in sotinit's own .bss · the spec calls for a 64 KiB SHM region
 * shared with sotcron (read-only) and that becomes real in a later PR
 * once sotcron is spawned.  PR 2 ships the API + storage; subsequent PRs
 * slot in the SHM mapping without changing the call sites.
 *
 * Allocation is bump-only · sotinit_unit_alloc returns the next free slot
 * with state=LOADED and index=slot_idx prefilled.  Lookups by name /
 * procd_slot are linear scans bounded by SOTINIT_MAX_UNITS=64 · cheap and
 * we control the worst case at parse time.
 *
 * Spec: init-cron-scheduler-design §4.5.
 */
#include <string.h>
#include <sotinit/unit.h>

/* 4 KiB alignment so a future SHM mapping can place the table on a frame
 * boundary without trampoline copies.  See spec §4.5 (64 KiB SHM region). */
static unit_t g_units[SOTINIT_MAX_UNITS] __attribute__((aligned(4096)));
static uint32_t g_unit_count = 0;

unit_t *sotinit_unit_alloc(void) {
    if (g_unit_count >= SOTINIT_MAX_UNITS) return NULL;
    unit_t *u = &g_units[g_unit_count];
    memset(u, 0, sizeof(*u));
    u->index = g_unit_count;
    u->state = UNIT_STATE_LOADED;
    g_unit_count++;
    return u;
}

unit_t *sotinit_unit_by_index(uint32_t idx) {
    if (idx >= g_unit_count) return NULL;
    return &g_units[idx];
}

unit_t *sotinit_unit_by_name(const char *name) {
    if (!name) return NULL;
    for (uint32_t i = 0; i < g_unit_count; i++) {
        if (strcmp(g_units[i].name, name) == 0) return &g_units[i];
    }
    return NULL;
}

unit_t *sotinit_unit_by_procd_slot(uint32_t slot) {
    if (slot == 0) return NULL;
    for (uint32_t i = 0; i < g_unit_count; i++) {
        if (g_units[i].procd_slot == slot) return &g_units[i];
    }
    return NULL;
}

uint32_t sotinit_unit_count(void) { return g_unit_count; }
unit_t *sotinit_unit_table(void) { return g_units; }
