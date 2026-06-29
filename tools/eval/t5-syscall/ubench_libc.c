/* sotOs T5 · vDSO libc bench · Task 8
 *
 * A normal C program linked with musl (NOT -nostdlib).  Calls clock_gettime()
 * via the standard libc entry point so musl resolves __vdso_clock_gettime from
 * AT_SYSINFO_EHDR automatically.  If the vDSO is mapped and the VERSION symbol
 * is correct musl calls straight into the vDSO — no trap.
 *
 * Gate: min cycle count < 1000 proves the call went through the in-guest
 * vDSO (no seL4 fault round-trip).  A trapping syscall costs ~8000-17000 cyc.
 *
 * Build (static-musl, same toolchain as vdso_probe.bin):
 *   MUSL=$REPO/src/test/musl-x86_64
 *   GCCINC=$(gcc -print-file-name=include)
 *   gcc -O2 -no-pie -fno-pic -static -fno-stack-protector \
 *       -Wl,--build-id=none \
 *       -isystem $MUSL/include -isystem $GCCINC \
 *       -o ubench_libc.bin \
 *       $MUSL/lib/crt1.o $MUSL/lib/crti.o \
 *       ubench_libc.c \
 *       $MUSL/lib/libc.a $MUSL/lib/crtn.o && strip ubench_libc.bin
 */
#include <time.h>
#include <stdio.h>
#include <stdint.h>

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("lfence; rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(void) {
    struct timespec ts;
    uint64_t min = UINT64_MAX, total = 0;
    int N = 100000;
    /* warmup */
    for (int i = 0; i < 2000; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
    }
    for (int i = 0; i < N; i++) {
        uint64_t t0 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t t1 = rdtsc();
        uint64_t d = t1 - t0;
        if (d < min) min = d;
        total += d;
    }
    printf("[ubench-libc] clock_gettime min=%lu mean=%lu\n",
           (unsigned long)min, (unsigned long)(total / (uint64_t)N));
    return 0;
}
