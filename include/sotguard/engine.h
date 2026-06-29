/*
 * sotOs * sotGuard * per-pid policy engine.
 *
 * Foundation for centralized trigger decisions in sotOs v0.22+.  The
 * engine maintains a small table of per-pid contexts (recon score,
 * burst-write tally, canary-read tally) and runs correlation rules
 * over the incoming event stream produced by G1's event bus.
 *
 * Contract:
 *   - Stateless except for the static g_ctxs table inside the unit;
 *     callers do not own context objects.
 *   - O(SOTGUARD_MAX_TRACKED_PIDS) lookup per event, no allocation,
 *     no kernel calls, no I/O.  Safe to call from any context that
 *     can read the event bus.
 *   - Returns 1 + populated rule_result iff a trigger should fire;
 *     the caller decides what to do with the verdict (promote tier,
 *     emit audit line, drop the pid, etc.).  G2 does NOT itself
 *     wire any trigger.
 *
 * The engine is intentionally simple in this first cut: three rules,
 * fixed thresholds.  Future cuts will read thresholds from a config
 * blob produced at boot.
 */
#ifndef SOTGUARD_ENGINE_H
#define SOTGUARD_ENGINE_H

#include <stdint.h>
#include <sotguard/event.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SOTGUARD_MAX_TRACKED_PIDS 16

/* Per-pid context.  Lives in static BSS inside policy_engine.c; this
 * type is exposed so future inspector tools can read the table. */
typedef struct {
    uint32_t pid;
    uint32_t recon_score;     /* read of /etc/passwd, /proc/self/maps, etc */
    uint32_t burst_writes;    /* consecutive writes within burst window */
    uint64_t last_write_ts;
    uint32_t canary_reads;
    uint8_t  in_use;
    uint8_t  pad[3];
} sotguard_pid_ctx_t;

/* Rule identifier returned in sotguard_rule_result_t when a rule fires.
 * SG_RULE_NONE is the anomaly "no rule fired" value. */
typedef enum {
    SG_RULE_NONE          = 0,
    SG_RULE_RECON_EXFIL   = 1,  /* read /etc/passwd then connect non-local */
    SG_RULE_BURST_WRITES  = 2,  /* >10 writes in <1ms */
    SG_RULE_CANARY_TRIPPED  = 3,  /* read >=2 canary files */
} sotguard_rule_id_t;

/* Verdict structure returned when a rule fires.  `reason` is a short,
 * human-readable tag for audit logs (NUL-terminated, never truncated
 * by the engine since rule tags are all <=31 chars). */
typedef struct {
    sotguard_rule_id_t rule;
    uint32_t           pid;
    uint8_t            target_tier;   /* 1 or 2 */
    char               reason[32];
} sotguard_rule_result_t;

/* Initialize the engine.  Called once at orch startup.  Idempotent. */
void sotguard_engine_init(void);

/* Process an incoming event.  Updates the per-pid context, applies
 * the rule set, and either:
 *   - returns 0 with `out` untouched (no rule fired), or
 *   - returns 1 with `out` populated (caller decides target tier from
 *     out->target_tier and out->rule).
 *
 * `ev` must not be NULL.  `out` must not be NULL.  When the per-pid
 * table is full and `ev->pid` is not already tracked, the event is
 * accepted but does not update any context (returns 0). */
int sotguard_engine_eval(const sotguard_event_t *ev,
                         sotguard_rule_result_t *out);

/* Reset per-pid context (e.g., on exit_group).  No-op if `pid` is not
 * currently tracked. */
void sotguard_engine_reset_pid(uint32_t pid);

#ifdef __cplusplus
}
#endif

#endif /* SOTGUARD_ENGINE_H */
