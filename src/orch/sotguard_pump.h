/*
 * sotOs · orch · sotGuard policy pump (Phase 3 · observation only).
 *
 * Periodically polls the sotguard event ring and runs each recent
 * event through the policy engine, logging any non-zero verdict.
 *
 * Phase 3 is OBSERVATION ONLY · the pump never promotes a sotbox
 * tier or otherwise alters runtime state.  Phase 4 will wire the
 * verdict into a promotion action; until then the pump is a pure
 * end-to-end smoke test of the bus + engine wiring.
 */
#ifndef SOTOS_ORCH_SOTGUARD_PUMP_H
#define SOTOS_ORCH_SOTGUARD_PUMP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the policy engine.  Call once at orch startup. */
void sotguard_pump_init(void);

/* Run the policy engine over the most-recent events on the bus.
 * Log any verdicts to stdout.  No promotion side-effects (Phase 3
 * is observation only).  Called periodically from orch's main loop. */
void sotguard_pump_tick(void);

#ifdef __cplusplus
}
#endif

#endif /* SOTOS_ORCH_SOTGUARD_PUMP_H */
