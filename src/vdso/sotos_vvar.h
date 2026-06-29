#ifndef SOTOS_VVAR_H
#define SOTOS_VVAR_H
#include <stdint.h>

#define SOTOS_VVAR_MAGIC 0x53565641u  /* "SVVA" */

/* clock ids (Linux x86-64 ABI) */
#define SOTOS_CLOCK_REALTIME          0
#define SOTOS_CLOCK_MONOTONIC         1
#define SOTOS_CLOCK_REALTIME_COARSE   5
#define SOTOS_CLOCK_MONOTONIC_COARSE  6
#define SOTOS_CLOCK_BOOTTIME          7

struct sotos_vvar {
    uint32_t magic;       /* SOTOS_VVAR_MAGIC */
    uint32_t seq;         /* seqlock; 0 fixed (static params, no updater) */
    int32_t  clock_mode;  /* 1 = TSC valid (use vDSO) · 0 = fallback to syscall */
    uint32_t shift;       /* tsc->ns: ns = (cyc * mult) >> shift */
    uint32_t mult;
    uint32_t _pad;
    uint64_t boot_tsc;
    uint64_t mask;        /* 64-bit TSC -> ~0 */
    int64_t  wall_sec, wall_nsec;   /* REALTIME base at boot (epoch) */
    int64_t  mono_sec, mono_nsec;   /* MONOTONIC base at boot (0) */
};

/* Orch-side helper: snapshot current clock params and write them into *v.
 * Call once at boot after lucas_clock_init(); the in-guest vDSO then reads
 * the mapped page directly without any syscalls.
 * Guard prevents pulling this into the guest vDSO image itself. */
#ifndef __SOTOS_VDSO__
void lucas_vvar_fill(struct sotos_vvar *v);
#endif

#endif /* SOTOS_VVAR_H */
