/*
 * sotOs · pidrand · deterministic display-pid generator (C2 #10).
 *
 * Stateless SplitMix64 finalizer over (fixed_seed + synthetic_pid), folded to a
 * plausible non-zero pid range.  No shared mutable state → reproducible across
 * boots and independent of call order.  Crucially, it never reads the global
 * arc4random stream, so the entropy-seeded ASLR draws are completely unchanged.
 */
#include <sotos/pidrand.h>

/* Fixed compile-time seed (golden-ratio constant) · reproducible by design. */
#define SOTOS_PIDRAND_SEED 0x9E3779B97F4A7C15ULL

/* Plausible Linux-like pid window · width is prime-ish to spread the fold. */
#define SOTOS_PID_LO 1000u
#define SOTOS_PID_SPAN 59000u   /* → range [1000, 60000) · always >= 1000 (non-zero) */

uint32_t sotos_pid_display(uint32_t synthetic_pid)
{
    uint64_t z = (uint64_t)synthetic_pid + SOTOS_PIDRAND_SEED;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    return SOTOS_PID_LO + (uint32_t)(z % SOTOS_PID_SPAN);  /* >= 1000 → never 0 */
}
