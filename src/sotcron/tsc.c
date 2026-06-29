/* sotOs · sotcron · TSC helpers + calibration.
 *
 * x86-64 rdtsc-based monotonic clock + a 1-second self-calibration that
 * spins seL4_Yield() in a tight loop to measure the per-second tick rate.
 * PR 7 ships the calibration with a hard-coded ~50 ms inner window scaled
 * up by 20×; subsequent PRs may swap to a PIT-driven calibration once
 * sotcron grows an HPET / APIC timer cap (out of scope for PR 7).
 *
 * The ~2.4 GHz fallback is a KVM-host-typical value · sane regardless of
 * the actual host clock since it bounds the polling cadence to ~1 s and
 * the timer fire path tolerates jitter (units fire on next tick boundary).
 *
 * Spec: init-cron-scheduler-design §4.4.
 */
#include <stdint.h>
#include <stdio.h>
#include <sel4/sel4.h>

uint64_t g_tsc_per_second = 0;
uint64_t g_boot_tsc       = 0;

uint64_t sotcron_tsc_now(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

void sotcron_tsc_calibrate(void) {
    g_boot_tsc = sotcron_tsc_now();
    uint64_t t0 = g_boot_tsc;
    for (int i = 0; i < 50000; i++) seL4_Yield();
    uint64_t t1 = sotcron_tsc_now();
    uint64_t calibrated = (t1 - t0) * 20;  /* 50ms * 20 = 1s */

    /* Sanity check: KVM TSCs typically 1-5 GHz. */
    if (calibrated < 100000000ull || calibrated > 50000000000ull) {
        printf("[sotcron] WARN · calibrated=%lu out of range · using fallback 2.4 GHz\n",
               (unsigned long)calibrated);
        calibrated = 2400000000ull;
    }
    g_tsc_per_second = calibrated;
    printf("[sotcron] tsc_per_second = %lu (calibrated)\n",
           (unsigned long)g_tsc_per_second);
}
