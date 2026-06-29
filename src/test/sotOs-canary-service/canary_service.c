/*
 * sotOs sottrace-v1 canary-service · a benign listen/accept/recv fixture that an
 * inbound connection talks to.  Raw Linux syscalls only, libc-free (clone of the
 * N1a egress-probe skeleton): socket(AF_INET), bind (no-op stub), listen, accept
 * (PARKS via the T7 accept park/wake until an inbound connection completes), recv,
 * close, write, exit.  The accept park is woken by the T3 NBRecv liveness poll
 * when the TCP server hands it an accepted fd.  Markers on the serial drive the
 * end-to-end inbound observability gate (canary-svc listening / rx <n> / conn done).
 */

typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  usize;

#define SYS_read    0
#define SYS_write   1
#define SYS_close   3
#define SYS_socket  41
#define SYS_accept  43
#define SYS_recvfrom 45
#define SYS_bind    49
#define SYS_listen  50
#define SYS_exit    60

#define AF_INET     2
#define SOCK_STREAM 1
#define LISTEN_PORT 80

struct sockaddr_in_min {
    u16           sin_family;
    u16           sin_port;     /* network byte order */
    u32           sin_addr;     /* network byte order */
    unsigned char pad[8];
};

static long sc3(long nr, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r)
                     : "a"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}
static long sc6(long nr, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    __asm__ volatile("syscall" : "=a"(r)
                     : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}
static void wl(const char *s, usize n) { (void)sc3(SYS_write, 1, (long)s, (long)n); }
static void die(const char *s, usize n) { wl(s, n); (void)sc3(SYS_exit, 1, 0, 0); for (;;) {} }
#define WL(s)  wl((s), sizeof(s) - 1)
#define DIE(s) die((s), sizeof(s) - 1)

static u16 htons16(u16 v) { return (u16)((v << 8) | (v >> 8)); }

/* Print "[canary-svc] rx <n>\n" for a small non-negative n (decimal). */
static void print_rx(long n)
{
    char out[32];
    usize i = 0;
    const char pfx[] = "[canary-svc] rx ";
    for (usize k = 0; k < sizeof(pfx) - 1; ++k) out[i++] = pfx[k];
    if (n < 0) { out[i++] = '-'; n = -n; }
    char digs[20];
    usize d = 0;
    if (n == 0) digs[d++] = '0';
    while (n > 0) { digs[d++] = (char)('0' + (n % 10)); n /= 10; }
    while (d > 0) out[i++] = digs[--d];
    out[i++] = '\n';
    wl(out, i);
}

void _start(void)
{
    long fd = sc3(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (fd < 0) DIE("[canary-svc] socket FAIL\n");

    struct sockaddr_in_min sa;
    for (usize i = 0; i < sizeof(sa); ++i) ((unsigned char *)&sa)[i] = 0;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons16(LISTEN_PORT);
    sa.sin_addr   = 0;   /* INADDR_ANY */

    /* bind is a no-op stub on this substrate — fine. */
    (void)sc3(SYS_bind, fd, (long)&sa, (long)sizeof(sa));

    if (sc3(SYS_listen, fd, 1, 0) != 0) DIE("[canary-svc] listen FAIL\n");
    WL("[canary-svc] listening :80\n");

    /* accept PARKS via the T7 park/wake until an inbound connection completes. */
    long cfd = sc6(SYS_accept, fd, 0, 0, 0, 0, 0);
    if (cfd < 0) DIE("[canary-svc] accept FAIL\n");
    WL("[canary-svc] accepted\n");

    static char buf[512];
    for (;;) {
        long n = sc3(SYS_read, cfd, (long)buf, (long)sizeof(buf));
        print_rx(n);
        if (n <= 0) break;
        /* send a small canned canary banner once, on the first chunk. */
        static int banner_sent = 0;
        if (!banner_sent) {
            static const char banner[] =
                "HTTP/1.0 200 OK\r\nServer: sotOs-canary\r\n\r\nwelcome\r\n";
            (void)sc3(SYS_write, cfd, (long)banner, (long)(sizeof(banner) - 1));
            banner_sent = 1;
        }
    }

    (void)sc3(SYS_close, cfd, 0, 0);
    WL("[canary-svc] conn done\n");
    (void)sc3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
