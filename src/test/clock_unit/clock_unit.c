/* Host unit test · `cc -I include src/test/clock_unit/clock_unit.c src/lucas/clock.c -o /tmp/clock_unit && /tmp/clock_unit` */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "lucas/clock.h"

int main(void) {
    int64_t sec = 0, nsec = 0;
    /* epoch 1716253200 (2024-05-21 09:00 UTC); 1e9 ticks/sec; 2.5e9 ticks after boot = +2.5s */
    lucas_clock_walltime(/*boot_tsc=*/1000, /*tsc_per_second=*/1000000000ULL,
                         /*epoch_sec=*/1716253200ULL, /*now_tsc=*/1000 + 2500000000ULL,
                         &sec, &nsec);
    assert(sec == 1716253202);
    assert(nsec == 500000000);

    /* now_tsc before boot_tsc must clamp to the epoch (never go backwards) */
    lucas_clock_walltime(5000, 1000000000ULL, 1716253200ULL, 4000, &sec, &nsec);
    assert(sec == 1716253200 && nsec == 0);

    /* tsc_per_second == 0 must not divide-by-zero; returns epoch */
    lucas_clock_walltime(0, 0, 1716253200ULL, 999, &sec, &nsec);
    assert(sec == 1716253200 && nsec == 0);

    printf("[clock-unit] ALL PASS\n");
    return 0;
}
