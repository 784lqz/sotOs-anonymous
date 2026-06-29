#include "lucas/clock.h"

void lucas_clock_walltime(uint64_t boot_tsc, uint64_t tsc_per_second,
                          uint64_t epoch_sec, uint64_t now_tsc,
                          int64_t *out_sec, int64_t *out_nsec) {
    if (tsc_per_second == 0 || now_tsc < boot_tsc) {
        *out_sec  = (int64_t)epoch_sec;
        *out_nsec = 0;
        return;
    }
    uint64_t delta = now_tsc - boot_tsc;
    uint64_t secs  = delta / tsc_per_second;
    uint64_t rem   = delta % tsc_per_second;
    *out_sec  = (int64_t)(epoch_sec + secs);
    *out_nsec = (int64_t)((rem * 1000000000ULL) / tsc_per_second);
}

static uint64_t g_boot_tsc = 0;
/* Fixed estimate · KVM `-cpu host` TSC is typically ~2.5–3 GHz.  An exact rate
 * needs a known wall reference (CPUID 0x15/0x16, or a PIT/HPET interval) — that
 * is a Phase-1b/future refinement.  An approximate rate is fine here: the clock
 * ADVANCES monotonically from a believable 2026 epoch (kills the 1970 tell);
 * being a few % off real-time is not an anti-honeypot tell on its own. */
static uint64_t g_tsc_per_second = 2500000000ULL;

static inline uint64_t clock_rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void lucas_clock_tsc_mult_shift(uint64_t tsc_per_second,
                                uint32_t *mult, uint32_t *shift) {
    /* Pick the largest shift in [0,32] such that
     *   m = (1_000_000_000 << shift) / tsc_per_second
     * still fits in uint32_t.  The vDSO fast-path then computes
     *   ns = (cyc * mult) >> shift
     * with no division and < 1 ppm error for any reasonable TSC rate. */
    if (tsc_per_second == 0) { *mult = 0; *shift = 0; return; }
    uint32_t best_s = 0, best_m = 0;
    for (int s = 0; s <= 32; s++) {
        uint64_t m = (1000000000ULL << s) / tsc_per_second;
        if (m > (uint64_t)0xffffffffu) break;
        best_s = (uint32_t)s;
        best_m = (uint32_t)m;
    }
    *shift = best_s;
    *mult  = best_m;
}

void lucas_clock_init(void) {
    /* Anchor the boot TSC.  (TSC-rate calibration via CPUID 0x16 is a documented
     * follow-up; the fixed estimate above is sufficient for Phase 1a fidelity.) */
    g_boot_tsc = clock_rdtsc();
}

void lucas_clock_params(uint64_t *boot_tsc, uint64_t *tsc_per_second) {
    *boot_tsc        = g_boot_tsc;
    *tsc_per_second  = g_tsc_per_second;
}

void lucas_now_realtime(int64_t *sec, int64_t *nsec) {
    lucas_clock_walltime(g_boot_tsc, g_tsc_per_second, LUCAS_CLOCK_EPOCH_SEC,
                         clock_rdtsc(), sec, nsec);
}

void lucas_now_monotonic(int64_t *sec, int64_t *nsec) {
    /* monotonic since boot = realtime - epoch */
    int64_t s, n;
    lucas_clock_walltime(g_boot_tsc, g_tsc_per_second, 0, clock_rdtsc(), &s, &n);
    *sec = s; *nsec = n;
}
