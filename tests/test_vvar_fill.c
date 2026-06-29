/* tests/test_vvar_fill.c — host unit test for lucas_vvar_fill (Task 2, vDSO arc)
 *
 * Stubs lucas_clock_params via the GNU linker --wrap mechanism so the
 * orchestrator globals (g_boot_tsc / g_tsc_per_second) do not affect the
 * assertions; we exercise the fill logic with a known fixed pair.
 *
 * Compile + run:
 *   gcc -O2 -I include -I src \
 *       -o /tmp/tvf \
 *       tests/test_vvar_fill.c src/lucas/vvar_fill.c src/lucas/clock.c \
 *       -Wl,--wrap=lucas_clock_params && /tmp/tvf
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "lucas/clock.h"
#include "vdso/sotos_vvar.h"

/* ------------------------------------------------------------------ */
/* Stub: replaces lucas_clock_params for this test binary only.        */
/* ------------------------------------------------------------------ */
void __wrap_lucas_clock_params(uint64_t *boot_tsc, uint64_t *tsc_per_second)
{
    *boot_tsc       = 1000000ULL;
    *tsc_per_second = 3000000000ULL;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static int failures;

#define CHECK(cond, msg) do {                                    \
    if (!(cond)) {                                               \
        printf("[tvf] FAIL: %s\n", (msg));                       \
        failures++;                                              \
    } else {                                                     \
        printf("[tvf] pass: %s\n", (msg));                       \
    }                                                            \
} while (0)

int main(void)
{
    struct sotos_vvar v;
    memset(&v, 0xaa, sizeof(v));   /* poison so zero fields are visible */

    lucas_vvar_fill(&v);

    /* --- structural fields --- */
    CHECK(v.magic == SOTOS_VVAR_MAGIC,            "magic == SOTOS_VVAR_MAGIC");
    CHECK(v.seq   == 0,                           "seq == 0");
    CHECK(v.clock_mode == 1,                      "clock_mode == 1  (tsc_per_second > 0)");

    /* --- TSC params --- */
    CHECK(v.boot_tsc == 1000000ULL,               "boot_tsc == 1000000");
    CHECK(v.mask     == ~(uint64_t)0,             "mask == ~0ULL");

    uint32_t exp_mult, exp_shift;
    lucas_clock_tsc_mult_shift(3000000000ULL, &exp_mult, &exp_shift);
    CHECK(v.mult  == exp_mult,                    "mult  matches lucas_clock_tsc_mult_shift");
    CHECK(v.shift == exp_shift,                   "shift matches lucas_clock_tsc_mult_shift");

    /* --- time bases --- */
    CHECK(v.wall_sec  == (int64_t)LUCAS_CLOCK_EPOCH_SEC, "wall_sec == LUCAS_CLOCK_EPOCH_SEC");
    CHECK(v.wall_nsec == 0,                       "wall_nsec == 0");
    CHECK(v.mono_sec  == 0,                       "mono_sec == 0");
    CHECK(v.mono_nsec == 0,                       "mono_nsec == 0");

    if (failures == 0)
        printf("[tvf] ALL PASS\n");
    else
        printf("[tvf] %d FAILURE(S)\n", failures);

    return failures ? 1 : 0;
}
