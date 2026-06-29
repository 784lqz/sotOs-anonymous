/*
 * sotOs · Pillar-3 · sottrace Pro · anti-debug invisibility probe fixture.
 *
 * A freestanding, no-libc, static x86_64 Linux ELF (ET_EXEC, no PT_INTERP)
 * that exercises the classic anti-debugger / debugger-detection surface a
 * piece of evasive malware would use to discover it is being traced:
 *
 *   1. ptrace(PTRACE_TRACEME=0, 0, 0, 0)  · sys 101
 *        On a clean, untraced process the kernel returns 0; if a debugger
 *        already attached, it returns -EPERM.  (Pre-stub sotOs returned
 *        -ENOSYS, itself an anomaly — the cert documents the fix.)
 *   2. open("/proc/self/status", O_RDONLY) · sys 2 + read · sys 0
 *        scan for the "TracerPid:" line and parse the integer after it.
 *        A non-zero TracerPid is the canonical "I am being debugged" tell.
 *   3. getppid() · sys 110
 *   4. write(1, ...) a one-line verdict:
 *        [antidbg] ptrace_traceme=<r> tracerpid=<n> ppid=<n> invisible=<YES|NO>
 *      with invisible=YES iff (ptrace_traceme == 0 && tracerpid == 0).
 *   5. exit_group(0) · sys 231
 *
 * No libc, no PT_INTERP, no relocations.  Build (matches fork_bomb recipe):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none -o antidbg_probe.bin antidbg_probe.c
 *   strip antidbg_probe.bin
 *
 * Or via the included Makefile.fixture target.
 */

typedef unsigned long  u64;
typedef long           s64;

/* Raw x86_64 syscall wrappers · clobber list per the Linux x86_64 ABI. */
static inline s64 sc1(s64 n, s64 a1)
{
    s64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1)
                     : "rcx", "r11", "memory");
    return r;
}
static inline s64 sc3(s64 n, s64 a1, s64 a2, s64 a3)
{
    s64 r;
    register s64 rdx __asm__("rdx") = a3;
    __asm__ volatile("syscall" : "=a"(r)
                     : "a"(n), "D"(a1), "S"(a2), "r"(rdx)
                     : "rcx", "r11", "memory");
    return r;
}
static inline s64 sc4(s64 n, s64 a1, s64 a2, s64 a3, s64 a4)
{
    s64 r;
    register s64 rdx __asm__("rdx") = a3;
    register s64 r10 __asm__("r10") = a4;
    __asm__ volatile("syscall" : "=a"(r)
                     : "a"(n), "D"(a1), "S"(a2), "r"(rdx), "r"(r10)
                     : "rcx", "r11", "memory");
    return r;
}

#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_ptrace      101
#define SYS_getppid     110
#define SYS_exit_group  231

#define PTRACE_TRACEME  0
#define O_RDONLY        0

/* ---- tiny string helpers (no libc) ------------------------------------ */

static int str_eq_prefix(const char *s, const char *pfx)
{
    while (*pfx) {
        if (*s != *pfx) return 0;
        s++; pfx++;
    }
    return 1;
}

/* Append decimal rendering of (possibly negative) v to buf at *pos. */
static void put_dec(char *buf, int *pos, s64 v)
{
    char tmp[24];
    int  ti = 0;
    int  neg = 0;
    u64  uv;
    if (v < 0) { neg = 1; uv = (u64)(-(v + 1)) + 1ULL; }
    else       { uv = (u64)v; }
    if (uv == 0) tmp[ti++] = '0';
    while (uv) { tmp[ti++] = (char)('0' + (int)(uv % 10)); uv /= 10; }
    if (neg) buf[(*pos)++] = '-';
    while (ti) buf[(*pos)++] = tmp[--ti];
}

static void put_str(char *buf, int *pos, const char *s)
{
    while (*s) buf[(*pos)++] = *s++;
}

void _start(void)
{
    /* 1. ptrace(PTRACE_TRACEME, 0, 0, 0) */
    s64 traceme = sc4(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);

    /* 2. open + read /proc/self/status, parse TracerPid: */
    static char path[] = "/proc/self/status";
    static char rbuf[4096];
    s64 tracerpid = -1;            /* -1 = "TracerPid: line not found" */
    s64 fd = sc3(SYS_open, (s64)path, O_RDONLY, 0);
    if (fd >= 0) {
        s64 total = 0;
        for (;;) {
            s64 n = sc3(SYS_read, fd, (s64)(rbuf + total),
                        (s64)(sizeof(rbuf) - 1 - (u64)total));
            if (n <= 0) break;
            total += n;
            if ((u64)total >= sizeof(rbuf) - 1) break;
        }
        rbuf[total] = '\0';
        /* scan line by line for "TracerPid:" */
        for (s64 i = 0; i < total; i++) {
            if ((i == 0 || rbuf[i - 1] == '\n') &&
                str_eq_prefix(rbuf + i, "TracerPid:")) {
                const char *p = rbuf + i + 10; /* len("TracerPid:") */
                while (*p == ' ' || *p == '\t') p++;
                s64 val = 0;
                int seen = 0;
                while (*p >= '0' && *p <= '9') {
                    val = val * 10 + (*p - '0');
                    p++; seen = 1;
                }
                tracerpid = seen ? val : 0;
                break;
            }
        }
    }

    /* 3. getppid() */
    s64 ppid = sc1(SYS_getppid, 0);

    /* 4. build + write the verdict line */
    int invisible = (traceme == 0 && tracerpid == 0);
    char out[160];
    int  pos = 0;
    put_str(out, &pos, "[antidbg] ptrace_traceme=");
    put_dec(out, &pos, traceme);
    put_str(out, &pos, " tracerpid=");
    put_dec(out, &pos, tracerpid);
    put_str(out, &pos, " ppid=");
    put_dec(out, &pos, ppid);
    put_str(out, &pos, " invisible=");
    put_str(out, &pos, invisible ? "YES" : "NO");
    out[pos++] = '\n';
    sc3(SYS_write, 1, (s64)out, pos);

    /* 5. exit_group(0) */
    sc1(SYS_exit_group, 0);
    for (;;) { } /* not reached */
}
