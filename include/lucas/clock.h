#ifndef LUCAS_CLOCK_H
#define LUCAS_CLOCK_H
#include <stdint.h>

/* Boot epoch: 2026-06-15 09:00:00 UTC.  Advanced from the old 2024-05-21 anchor:
 * a 2-years-stale clock is an anti-honeypot tell, AND real TLS egress verifies
 * server certs against notBefore — a pre-cert clock fails every chain. */
#define LUCAS_CLOCK_EPOCH_SEC 1781514000ULL

/* Pure: wall-clock = epoch_sec + (now_tsc - boot_tsc) / tsc_per_second.
 * Clamps to epoch when now_tsc < boot_tsc or tsc_per_second == 0. No globals. */
void lucas_clock_walltime(uint64_t boot_tsc, uint64_t tsc_per_second,
                          uint64_t epoch_sec, uint64_t now_tsc,
                          int64_t *out_sec, int64_t *out_nsec);

/* Capture boot_tsc + calibrate tsc_per_second once.  Call at boot. */
void lucas_clock_init(void);

/* Realtime (advancing wall clock) and monotonic (since boot) readers. */
void lucas_now_realtime(int64_t *sec, int64_t *nsec);
void lucas_now_monotonic(int64_t *sec, int64_t *nsec);

/* Compute the standard clocksource mult/shift for vDSO fast-path:
 *   ns = (cyc * mult) >> shift
 * Picks the LARGEST shift in [0,32] such that mult fits in uint32_t.
 * Pure arithmetic; no seL4 headers; safe to call from host unit tests. */
void lucas_clock_tsc_mult_shift(uint64_t tsc_per_second,
                                uint32_t *mult, uint32_t *shift);

/* Return the current clock globals used by lucas_now_realtime/monotonic.
 * Orch-side only; used by lucas_vvar_fill to snapshot params at boot. */
void lucas_clock_params(uint64_t *boot_tsc, uint64_t *tsc_per_second);

#endif
