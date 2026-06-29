/*
 * sotOs sottrace-v1 T11 · canary-read · raw-syscall, libc-free fixture.
 *
 * A Tier-2 sotbox reads /etc/passwd through the guest VFS.  When the
 * active VFS is serving canary_entries (Tier 2), backends_static op_read
 * increments canary_read_count, prints [canary] pid=..., and calls
 * trace_emit_canary() — the SG_EV_CANARY_READ producer added in sottrace v0.
 * This fixture closes the v0 demo-coverage gap by driving that code path.
 *
 * Raw Linux syscalls only (SYS_open=2, SYS_read=0, SYS_write=1,
 * SYS_close=3, SYS_exit=60).  No libc.  Static ELF; committed binary.
 *
 * Build (host gcc):
 *   make -f Makefile.fixture
 */

typedef unsigned long  usize;

#define SYS_read    0
#define SYS_write   1
#define SYS_open    2
#define SYS_close   3
#define SYS_exit    60

#define O_RDONLY    0

static long sc3(long nr, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r)
                     : "a"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}

static void wl(const char *s, usize n) { (void)sc3(SYS_write, 1, (long)s, (long)n); }
#define WL(s) wl((s), sizeof(s) - 1)

/* Print "[canary-read] read <n> bytes\n" for a small non-negative n. */
static void print_read(long n)
{
    char out[40];
    usize i = 0;
    const char pfx[] = "[canary-read] read ";
    for (usize k = 0; k < sizeof(pfx) - 1; ++k) out[i++] = pfx[k];
    if (n < 0) { out[i++] = '-'; n = -n; }
    char digs[20];
    usize d = 0;
    if (n == 0) digs[d++] = '0';
    while (n > 0) { digs[d++] = (char)('0' + (n % 10)); n /= 10; }
    while (d > 0) out[i++] = digs[--d];
    const char sfx[] = " bytes\n";
    for (usize k = 0; k < sizeof(sfx) - 1; ++k) out[i++] = sfx[k];
    wl(out, i);
}

void _start(void)
{
    long fd = sc3(SYS_open, (long)"/etc/passwd", O_RDONLY, 0);
    if (fd < 0) {
        WL("[canary-read] open FAIL\n");
        (void)sc3(SYS_exit, 1, 0, 0);
        for (;;) {}
    }

    static char buf[512];
    long n = sc3(SYS_read, fd, (long)buf, (long)sizeof(buf));
    print_read(n);

    (void)sc3(SYS_close, fd, 0, 0);
    (void)sc3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
