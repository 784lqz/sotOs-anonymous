/* tests/test_clock_multshift.c — host unit test for lucas_clock_tsc_mult_shift
 *
 * Compile: gcc -O2 -I include -o /tmp/tms \
 *              tests/test_clock_multshift.c src/lucas/clock.c && /tmp/tms
 *
 * Tolerance: relative error <= 1 ppm (1e-6), OR absolute error <= 2 ns
 * (floor for tiny cyc values where integer truncation dominates).
 */
#include <stdint.h>
#include <stdio.h>
#include "lucas/clock.h"

int main(void) {
    int failures = 0;

    static const uint64_t rates[] = {
        2500000000ULL,   /* typical KVM TSC ~2.5 GHz */
        3000000000ULL,   /* 3.0 GHz */
        1000000000ULL,   /* 1.0 GHz — forces shift < 32 */
    };
    static const uint64_t cycs[] = {
        1ULL,
        1000000ULL,
        1000000000ULL,
        1000000000000ULL,
    };

    for (int r = 0; r < (int)(sizeof(rates)/sizeof(rates[0])); r++) {
        uint64_t tsc_hz = rates[r];
        uint32_t mult, shift;
        lucas_clock_tsc_mult_shift(tsc_hz, &mult, &shift);

        for (int c = 0; c < (int)(sizeof(cycs)/sizeof(cycs[0])); c++) {
            uint64_t cyc = cycs[c];

            /* vDSO fast-path approximation */
            unsigned __int128 approx = ((unsigned __int128)cyc * mult) >> shift;
            /* Reference: exact integer ns (truncated, same as Linux vDSO) */
            unsigned __int128 exact  = (unsigned __int128)cyc * 1000000000ULL / tsc_hz;

            unsigned __int128 err = (approx >= exact)
                                  ? (approx - exact)
                                  : (exact  - approx);

            /* Pass: relative error <= 1 ppm  OR  absolute error <= 2 ns */
            int ok = (err * 1000000u <= exact) || (err <= 2u);

            printf("[tms] tsc=%-11llu cyc=%-13llu  mult=%-10u shift=%2u  "
                   "exact=%-13llu approx=%-13llu err=%-4llu  %s\n",
                   (unsigned long long)tsc_hz,
                   (unsigned long long)cyc,
                   mult, shift,
                   (unsigned long long)(uint64_t)exact,
                   (unsigned long long)(uint64_t)approx,
                   (unsigned long long)(uint64_t)err,
                   ok ? "PASS" : "FAIL");

            if (!ok) failures++;
        }
    }

    if (failures == 0)
        printf("[tms] ALL PASS\n");
    else
        printf("[tms] %d FAILURE(S)\n", failures);
    return failures ? 1 : 0;
}
