/* SOTOS vDSO · fallback stubs (raw syscall path)
 *
 * This translation unit is compiled into the guest-side linux-vdso.so.1.
 * No libc, no stack-protector, no unwind tables — pure freestanding PIC.
 *
 * Guard __SOTOS_VDSO__ keeps the orch-only lucas_vvar_fill() declaration
 * out of the vDSO image while still pulling in the shared vvar layout so
 * the compile proves the header is guest-side-safe.
 */
#define __SOTOS_VDSO__ 1
#include "sotos_vvar.h"

/* ── Minimal type definitions (no libc headers) ────────────────────────── */

struct timespec {
    long tv_sec;
    long tv_nsec;
};

struct timeval {
    long tv_sec;
    long tv_usec;
};

/* ── vvar access (hidden symbol → RIP-relative, no GOT) ───────────────────
 * `_sotos_vvar` is placed by vdso.lds at a fixed negative offset from the
 * image so the compiler emits a PC-relative reference resolved at link time —
 * the readelf gate forbids GOT/GLOB_DAT relocs.  Hidden visibility is what
 * forces the non-preemptible, RIP-relative access (no dynamic symbol). */
extern const struct sotos_vvar _sotos_vvar __attribute__((visibility("hidden")));

/* x86-64 monotonic-counter read; lfence serializes rdtsc against prior insns
 * so the sample is not reordered ahead of the seqlock load. */
static __inline__ uint64_t sotos_rdtsc(void)
{
    unsigned int lo, hi;
    __asm__ __volatile__("lfence; rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

/* ── Raw syscall helpers ─────────────────────────────────────────────────
 * x86-64 Linux syscall ABI:
 *   rax = syscall nr (in + out)
 *   rdi, rsi, rdx, r10, r8, r9 = args 1-6
 *   rcx, r11 = clobbered by the syscall instruction
 */

static __inline__ long __syscall1(long nr, long a1)
{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1)
        : "rcx", "r11", "memory");
    return ret;
}

static __inline__ long __syscall2(long nr, long a1, long a2)
{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory");
    return ret;
}

static __inline__ long __syscall3(long nr, long a1, long a2, long a3)
{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory");
    return ret;
}

/* ── Exported vDSO stubs ─────────────────────────────────────────────── */

__attribute__((visibility("default")))
long __vdso_clock_gettime(int clk, struct timespec *ts)
{
    /* Only the wall/monotonic clocks (and their _COARSE aliases) are served
     * in-guest; everything else (and a disabled TSC) takes the syscall path. */
    if (clk != SOTOS_CLOCK_REALTIME && clk != SOTOS_CLOCK_MONOTONIC &&
        clk != SOTOS_CLOCK_REALTIME_COARSE && clk != SOTOS_CLOCK_MONOTONIC_COARSE)
        return __syscall2(228, (long)clk, (long)ts);

    /* seqlock read of the (currently static) clock params.  seq is 0 today so
     * this passes on the first iteration; the dance keeps fidelity with the
     * Linux vDSO and is correct if an updater is added later. */
    uint32_t  seq;
    int32_t   clock_mode;
    uint32_t  shift, mult;
    uint64_t  boot_tsc, mask;
    int64_t   base_sec, base_nsec;
    do {
        seq        = _sotos_vvar.seq;
        __asm__ __volatile__("" ::: "memory");   /* read seq before fields */

        clock_mode = _sotos_vvar.clock_mode;
        shift      = _sotos_vvar.shift;
        mult       = _sotos_vvar.mult;
        boot_tsc   = _sotos_vvar.boot_tsc;
        mask       = _sotos_vvar.mask;
        if (clk == SOTOS_CLOCK_REALTIME || clk == SOTOS_CLOCK_REALTIME_COARSE) {
            base_sec  = _sotos_vvar.wall_sec;
            base_nsec = _sotos_vvar.wall_nsec;
        } else {
            base_sec  = _sotos_vvar.mono_sec;
            base_nsec = _sotos_vvar.mono_nsec;
        }

        __asm__ __volatile__("" ::: "memory");   /* read fields before re-check */
    } while ((seq & 1u) || seq != _sotos_vvar.seq);

    /* TSC not usable → fall back to the kernel (traps, but correct). */
    if (clock_mode == 0)
        return __syscall2(228, (long)clk, (long)ts);

    uint64_t cyc = (sotos_rdtsc() - boot_tsc) & mask;
    uint64_t ns  = (uint64_t)(((__uint128_t)cyc * mult) >> shift);

    int64_t sec  = base_sec;
    int64_t nsec = base_nsec + (int64_t)ns;
    if (nsec >= 1000000000) {
        sec  += nsec / 1000000000;
        nsec %= 1000000000;
    }

    ts->tv_sec  = sec;
    ts->tv_nsec = nsec;
    return 0;
}

__attribute__((visibility("default")))
long __vdso_gettimeofday(struct timeval *tv, void *tz)
{
    uint32_t  seq;
    int32_t   clock_mode;
    uint32_t  shift, mult;
    uint64_t  boot_tsc, mask;
    int64_t   base_sec, base_nsec;

    do {
        seq        = _sotos_vvar.seq;
        __asm__ __volatile__("" ::: "memory");

        clock_mode = _sotos_vvar.clock_mode;
        shift      = _sotos_vvar.shift;
        mult       = _sotos_vvar.mult;
        boot_tsc   = _sotos_vvar.boot_tsc;
        mask       = _sotos_vvar.mask;
        base_sec   = _sotos_vvar.wall_sec;
        base_nsec  = _sotos_vvar.wall_nsec;

        __asm__ __volatile__("" ::: "memory");
    } while ((seq & 1u) || seq != _sotos_vvar.seq);

    if (clock_mode == 0)
        return __syscall2(96, (long)tv, (long)tz);

    uint64_t cyc = (sotos_rdtsc() - boot_tsc) & mask;
    uint64_t ns  = (uint64_t)(((__uint128_t)cyc * mult) >> shift);

    int64_t sec  = base_sec;
    int64_t nsec = base_nsec + (int64_t)ns;
    if (nsec >= 1000000000) {
        sec  += nsec / 1000000000;
        nsec %= 1000000000;
    }

    if (tv) {
        tv->tv_sec  = sec;
        tv->tv_usec = nsec / 1000;
    }
    if (tz) {
        /* struct timezone = { int tz_minuteswest; int tz_dsttime; }; zero both */
        int *tzbuf = (int *)tz;
        tzbuf[0] = 0;
        tzbuf[1] = 0;
    }
    return 0;
}

__attribute__((visibility("default")))
long __vdso_time(long *t)
{
    uint32_t  seq;
    int32_t   clock_mode;
    uint32_t  shift, mult;
    uint64_t  boot_tsc, mask;
    int64_t   base_sec, base_nsec;

    do {
        seq        = _sotos_vvar.seq;
        __asm__ __volatile__("" ::: "memory");

        clock_mode = _sotos_vvar.clock_mode;
        shift      = _sotos_vvar.shift;
        mult       = _sotos_vvar.mult;
        boot_tsc   = _sotos_vvar.boot_tsc;
        mask       = _sotos_vvar.mask;
        base_sec   = _sotos_vvar.wall_sec;
        base_nsec  = _sotos_vvar.wall_nsec;

        __asm__ __volatile__("" ::: "memory");
    } while ((seq & 1u) || seq != _sotos_vvar.seq);

    if (clock_mode == 0)
        return __syscall1(201, (long)t);

    uint64_t cyc = (sotos_rdtsc() - boot_tsc) & mask;
    uint64_t ns  = (uint64_t)(((__uint128_t)cyc * mult) >> shift);

    int64_t sec  = base_sec;
    int64_t nsec = base_nsec + (int64_t)ns;
    if (nsec >= 1000000000)
        sec += nsec / 1000000000;

    if (t)
        *t = sec;
    return sec;
}

__attribute__((visibility("default")))
long __vdso_clock_getres(int clk, struct timespec *ts)
{
    if (clk != SOTOS_CLOCK_REALTIME && clk != SOTOS_CLOCK_MONOTONIC &&
        clk != SOTOS_CLOCK_REALTIME_COARSE && clk != SOTOS_CLOCK_MONOTONIC_COARSE)
        return __syscall2(229, (long)clk, (long)ts);

    if (ts) {
        ts->tv_sec  = 0;
        ts->tv_nsec = 1;
    }
    return 0;
}

__attribute__((visibility("default")))
long __vdso_getcpu(unsigned *cpu, unsigned *node, void *unused)
{
    (void)unused;
    if (cpu)  *cpu  = 0;
    if (node) *node = 0;
    return 0;
}

/* ── Weak aliases for glibc/musl compatibility ───────────────────────────
 * musl resolves __vdso_clock_gettime directly; glibc also accepts bare
 * clock_gettime / gettimeofday / time from the vDSO image.
 */
long clock_gettime(int, struct timespec *)
    __attribute__((weak, alias("__vdso_clock_gettime"), visibility("default")));

long gettimeofday(struct timeval *, void *)
    __attribute__((weak, alias("__vdso_gettimeofday"), visibility("default")));

long time(long *)
    __attribute__((weak, alias("__vdso_time"), visibility("default")));
