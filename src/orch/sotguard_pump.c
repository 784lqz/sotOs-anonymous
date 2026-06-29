/*
 * sotGuard policy pump · Phase 3 observation.
 *
 * Periodically polls the sotguard event ring, runs each recent event
 * through the policy engine, and logs any verdict.  Promotion decisions
 * stay inline in the existing trigger sites; this pump is purely an
 * observation layer that proves the bus + engine wire up end-to-end.
 *
 * Phase 4 will move promotion to be driven by these verdicts.
 *
 * NOTE: the engine's per-pid context table treats repeated events from
 * the same pid idempotently for non-counter rules, but the burst-write
 * and canary-read rules ARE counter-based.  Because the pump re-reads the
 * tail of the ring on every tick, the same write event may be replayed
 * across consecutive ticks and inflate the burst counter, producing a
 * verdict when no actual burst occurred.  This is acceptable for Phase 3
 * (observation only · the verdict is logged, never acted on).  Phase 4
 * will introduce per-pump cursoring (track last-seen monotonic g_total)
 * so promotion decisions only fire on freshly-emitted events.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include <sotguard/event.h>
#include <sotguard/engine.h>

#include "sotguard_pump.h"

/* How many recent events to peek per tick.  Bounded · the ring is
 * 256 entries.  Each tick re-reads the most-recent N regardless of
 * whether they've been seen before (overlap is acceptable for Phase 3
 * observation · see file header for the cursoring TODO in Phase 4). */
#define SG_PUMP_POLL_WINDOW 16

void sotguard_pump_init(void)
{
    sotguard_engine_init();
}

void sotguard_pump_tick(void)
{
    sotguard_event_t buf[SG_PUMP_POLL_WINDOW];
    size_t n = sotguard_recent(buf, SG_PUMP_POLL_WINDOW);
    for (size_t i = 0; i < n; ++i) {
        sotguard_rule_result_t verdict;
        memset(&verdict, 0, sizeof(verdict));
        int hit = sotguard_engine_eval(&buf[i], &verdict);
        if (hit) {
            printf("[sotguard] verdict: rule=%u pid=%u target_tier=%u %s\n",
                   (unsigned)verdict.rule,
                   (unsigned)verdict.pid,
                   (unsigned)verdict.target_tier,
                   verdict.reason);
        }
    }
}
