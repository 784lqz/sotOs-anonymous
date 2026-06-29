/* src/lucas/vvar_fill.c — orch-side helper: fill a sotos_vvar page.
 *
 * Called once at boot (after lucas_clock_init) to populate the shared page
 * that the in-guest vDSO maps read-only.  The page is written while the
 * guest is still quiescent, so no seqlock update dance is needed here.
 *
 * Rationale for initial values:
 *   At the moment lucas_vvar_fill is called, rdtsc ≈ boot_tsc, so:
 *     REALTIME  = epoch + (boot_tsc - boot_tsc)/hz  = epoch  (wall_sec)
 *     MONOTONIC = 0     + (boot_tsc - boot_tsc)/hz  = 0
 *   The in-guest fast-path then adds (rdtsc - boot_tsc) scaled by mult/shift.
 */
#include <string.h>
#include "lucas/clock.h"
#include "vdso/sotos_vvar.h"

void lucas_vvar_fill(struct sotos_vvar *v)
{
    uint64_t boot_tsc, tsc_per_second;
    lucas_clock_params(&boot_tsc, &tsc_per_second);

    uint32_t mult, shift;
    lucas_clock_tsc_mult_shift(tsc_per_second, &mult, &shift);

    memset(v, 0, sizeof(*v));
    v->magic      = SOTOS_VVAR_MAGIC;
    v->seq        = 0;
    v->clock_mode = (tsc_per_second > 0) ? 1 : 0;
    v->shift      = shift;
    v->mult       = mult;
    v->boot_tsc   = boot_tsc;
    v->mask       = ~(uint64_t)0;
    v->wall_sec   = (int64_t)LUCAS_CLOCK_EPOCH_SEC;
    v->wall_nsec  = 0;
    v->mono_sec   = 0;
    v->mono_nsec  = 0;
}
