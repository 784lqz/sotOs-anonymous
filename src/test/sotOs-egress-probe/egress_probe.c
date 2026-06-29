/*
 * sotOs N1a egress-probe · plain HTTP GET to a literal IP, proving REAL wire
 * egress from a Tier-0e sandbox. Raw Linux syscalls only: socket(AF_INET),
 * connect(sockaddr_in), write, read, close, exit. No DNS/TLS (those are N1b/N1c).
 * Target: 1.1.1.1:80 (stable anycast; returns an HTTP 301). The first response
 * line printed to the serial + the pcap are the real-egress proof.
 */

typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  usize;

#define SYS_read    0
#define SYS_write   1
#define SYS_close   3
#define SYS_socket  41
#define SYS_connect 42
#define SYS_exit    60

#define AF_INET     2
#define SOCK_STREAM 1

#define DST_A 1
#define DST_B 1
#define DST_C 1
#define DST_D 1
#define DST_PORT 80

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
static void wl(const char *s, usize n) { (void)sc3(SYS_write, 1, (long)s, (long)n); }
static void die(const char *s, usize n) { wl(s, n); (void)sc3(SYS_exit, 1, 0, 0); for (;;) {} }
#define WL(s)  wl((s), sizeof(s) - 1)
#define DIE(s) die((s), sizeof(s) - 1)

static u16 htons16(u16 v) { return (u16)((v << 8) | (v >> 8)); }

void _start(void)
{
    long fd = sc3(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (fd < 0) DIE("[egress-probe] socket FAIL\n");

    struct sockaddr_in_min sa;
    for (usize i = 0; i < sizeof(sa); ++i) ((unsigned char *)&sa)[i] = 0;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons16(DST_PORT);
    ((unsigned char *)&sa.sin_addr)[0] = DST_A;
    ((unsigned char *)&sa.sin_addr)[1] = DST_B;
    ((unsigned char *)&sa.sin_addr)[2] = DST_C;
    ((unsigned char *)&sa.sin_addr)[3] = DST_D;

    WL("[egress-probe] connecting 1.1.1.1:80 ...\n");
    if (sc3(SYS_connect, fd, (long)&sa, (long)sizeof(sa)) != 0)
        DIE("[egress-probe] connect FAIL\n");
    WL("[egress-probe] connect OK\n");

    static const char req[] =
        "GET / HTTP/1.0\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    long w = sc3(SYS_write, fd, (long)req, (long)(sizeof(req) - 1));
    if (w != (long)(sizeof(req) - 1)) DIE("[egress-probe] write FAIL\n");
    WL("[egress-probe] GET sent\n");

    static char buf[512];
    long r = sc3(SYS_read, fd, (long)buf, (long)sizeof(buf));
    if (r <= 0) DIE("[egress-probe] read FAIL (no response)\n");

    /* Print "[egress-probe] http OK · " + the first line of the real response. */
    WL("[egress-probe] http OK · ");
    usize n = (usize)r, i = 0;
    for (; i < n && buf[i] != '\r' && buf[i] != '\n'; ++i) {}
    wl(buf, i);
    WL("\n");

    (void)sc3(SYS_close, fd, 0, 0);
    (void)sc3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
