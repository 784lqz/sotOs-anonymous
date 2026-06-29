/* fastpath_probe.c — sotOs fast-path gate probe · Task 9
 *
 * Calls sched_yield() (sysno 24) in a timed loop using lfence;rdtsc fences.
 * A trapping (un-fast-pathed) syscall costs ~8000-17000 cycles on this host;
 * a fast-pathed sched_yield (no seL4_Yield IPC, no ReadRegisters) lands in
 * the hundreds.  Gate asserts min < 2000 and ret == 0.
 *
 * Build:
 *   gcc -O2 -no-pie -fno-pic -nostdlib -static -fno-stack-protector \
 *       -Wl,--build-id=none \
 *       -o fastpath_probe.bin fastpath_probe.c && strip fastpath_probe.bin
 *
 * Uses raw _start + inline syscalls (no libc) to avoid any extraneous IPC
 * that would contaminate the measurement.
 *
 * Emits (gate marker):
 *   [fastpath-probe] sched_yield_cycles=<min> ret=<ret>
 */

typedef unsigned long u64;
typedef long          i64;

/* ── raw syscall stubs ─────────────────────────────────────────────────── */
static i64 sys0(i64 n) {
    i64 r;
    __asm__ __volatile__("syscall" : "=a"(r) : "a"(n) : "rcx", "r11", "memory");
    return r;
}
static i64 sys3(i64 n, i64 a, i64 b, i64 c) {
    i64 r;
    __asm__ __volatile__("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                         : "rcx", "r11", "memory");
    return r;
}

/* ── rdtsc with lfence serialisation ────────────────────────────────────── */
static u64 rdtsc(void) {
    unsigned lo, hi;
    __asm__ __volatile__("lfence; rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((u64)hi << 32) | lo;
}

/* ── minimal integer-to-decimal formatter ───────────────────────────────── */
static int utoa(u64 v, char *p) {
    char t[24]; int n = 0;
    if (!v) { *p = '0'; return 1; }
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    for (int i = 0; i < n; i++) p[i] = t[n - 1 - i];
    return n;
}
static int itoa_signed(i64 v, char *p) {
    if (v < 0) { *p++ = '-'; return 1 + (int)utoa((u64)(-v), p); }
    return (int)utoa((u64)v, p);
}

/* ── _start ─────────────────────────────────────────────────────────────── */
void _start(void) {
    const int WARMUP = 2000;
    const int ITERS  = 10000;

    /* warmup: prime the fast-path dispatch table and branch predictors */
    for (int i = 0; i < WARMUP; i++) sys0(24 /*sched_yield*/);

    /* timed measurement: record min latency over ITERS iterations */
    u64 mn = ~(u64)0;
    i64 last_ret = 0;
    for (int i = 0; i < ITERS; i++) {
        u64 a = rdtsc();
        last_ret = sys0(24 /*sched_yield*/);
        u64 b = rdtsc();
        u64 d = b - a;
        if (d < mn) mn = d;
    }

    /* emit gate marker: [fastpath-probe] sched_yield_cycles=<min> ret=<ret> */
    char buf[256];
    char *p = buf;
    const char *s;

    s = "[fastpath-probe] sched_yield_cycles=";
    while (*s) *p++ = *s++;
    p += utoa(mn, p);

    s = " ret=";
    while (*s) *p++ = *s++;
    p += itoa_signed(last_ret, p);
    *p++ = '\n';

    sys3(1 /*write*/, 1 /*stdout*/, (i64)buf, (i64)(p - buf));
    sys0(60 /*exit*/);
    for (;;);
}
