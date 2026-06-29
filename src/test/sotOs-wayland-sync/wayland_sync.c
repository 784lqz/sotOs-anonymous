/*
 * sotOs L12-gamma guest fixture · wl_display.sync round trip.
 *
 * Raw Linux syscalls only: socket(AF_UNIX), connect, write, read, exit.
 * Connects to the compositor route, sends a real wl_display.sync request,
 * and asserts the reply is a byte-exact wl_callback.done + wl_display.delete_id.
 */

typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  usize;

#define SYS_read    0
#define SYS_write   1
#define SYS_socket  41
#define SYS_connect 42
#define SYS_exit    60

#define AF_UNIX     1
#define SOCK_STREAM 1

#define WAYLAND_PATH "/run/user/1000/wayland-0"

struct sockaddr_un_min {
    u16  sun_family;
    char sun_path[108];
};

static long raw_syscall3(long nr, long a0, long a1, long a2)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
        : "rcx", "r11", "memory");
    return ret;
}

static void write_lit(const char *s, usize len)
{
    (void)raw_syscall3(SYS_write, 1, (long)s, (long)len);
}

static void die(const char *s, usize len)
{
    write_lit(s, len);
    (void)raw_syscall3(SYS_exit, 1, 0, 0);
    for (;;) {}
}

#define WRITE_LIT(s) write_lit((s), sizeof(s) - 1)
#define DIE_LIT(s)   die((s), sizeof(s) - 1)

void _start(void)
{
    static struct sockaddr_un_min sa;
    const char path[] = WAYLAND_PATH;

    sa.sun_family = AF_UNIX;
    for (usize i = 0; i < sizeof(sa.sun_path); ++i) sa.sun_path[i] = 0;
    for (usize i = 0; i < sizeof(path) && i < sizeof(sa.sun_path); ++i)
        sa.sun_path[i] = path[i];

    long fd = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) DIE_LIT("[wayland-sync] socket FAIL\n");

    long rc = raw_syscall3(SYS_connect, fd, (long)&sa,
                           (long)(sizeof(sa.sun_family) + sizeof(path)));
    if (rc != 0) DIE_LIT("[wayland-sync] connect FAIL\n");

    /* wl_display.sync(new_id=2): id=1, opcode=0, size=12. */
    u32 req[3];
    req[0] = 1;                     /* wl_display object id */
    req[1] = ((u32)12 << 16) | 0;   /* (size<<16) | opcode(sync=0) */
    req[2] = 2;                     /* new_id for the callback object */
    long w = raw_syscall3(SYS_write, fd, (long)req, (long)sizeof(req));
    if (w != (long)sizeof(req)) DIE_LIT("[wayland-sync] write FAIL\n");

    /* Reply: done(id=2,op=0,serial) + delete_id(id=1,op=1,arg=2).
     * LUCAS returns the whole 24-byte reply in a single drain, so one
     * read() of sizeof(rep) is sufficient (no short-read loop needed). */
    u32 rep[6];
    for (int i = 0; i < 6; ++i) rep[i] = 0;
    long r = raw_syscall3(SYS_read, fd, (long)rep, (long)sizeof(rep));
    if (r != (long)sizeof(rep)) DIE_LIT("[wayland-sync] read FAIL\n");

    if (rep[0] != 2)             DIE_LIT("[wayland-sync] done id FAIL\n");
    if ((rep[1] & 0xFFFF) != 0)  DIE_LIT("[wayland-sync] done opcode FAIL\n");
    if ((rep[1] >> 16) != 12)    DIE_LIT("[wayland-sync] done size FAIL\n");
    if (rep[3] != 1)             DIE_LIT("[wayland-sync] delete_id obj FAIL\n");
    if ((rep[4] & 0xFFFF) != 1)  DIE_LIT("[wayland-sync] delete_id opcode FAIL\n");
    if (rep[5] != 2)             DIE_LIT("[wayland-sync] delete_id arg FAIL\n");

    WRITE_LIT("[wayland-sync] callback done OK\n");

    (void)raw_syscall3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
