/*
 * sotOs L12-delta guest fixture · wl_registry globals + bind.
 *
 * Raw Linux syscalls only: socket(AF_UNIX), connect, write, read, exit.
 * connect → wl_display.get_registry → assert the wl_registry.global events
 * for wl_compositor (v4) + wl_shm (v1) byte-exact → wl_registry.bind the
 * compositor → exit. LUCAS returns the whole get_registry reply in one drain.
 */

typedef unsigned char  u8;
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

static u32 rd32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* Verify one wl_registry.global event at byte offset *off; advance *off.
 * Returns 0 on match, negative on any mismatch. */
static int check_global(const u8 *buf, usize *off, usize buflen,
                        u32 want_obj, u32 want_name,
                        const char *want_iface, u32 want_ilen /* incl NUL */,
                        u32 want_version)
{
    usize o = *off;
    if (o + 16 > buflen) return -1;
    u32 obj  = rd32(buf + o);
    u32 hdr  = rd32(buf + o + 4);
    u32 name = rd32(buf + o + 8);
    u32 slen = rd32(buf + o + 12);
    if (obj != want_obj)          return -2;
    if ((hdr & 0xFFFF) != 0)      return -3;   /* wl_registry.global = opcode 0 */
    if (name != want_name)        return -4;
    if (slen != want_ilen)        return -5;
    u32 padded = (slen + 3u) & ~3u;
    if (o + 16 + padded + 4 > buflen) return -6;
    for (u32 i = 0; i < want_ilen; ++i)
        if (buf[o + 16 + i] != (u8)want_iface[i]) return -7;
    u32 version = rd32(buf + o + 16 + padded);
    if (version != want_version)  return -8;
    *off = o + 16 + padded + 4;
    return 0;
}

void _start(void)
{
    static struct sockaddr_un_min sa;
    const char path[] = WAYLAND_PATH;

    sa.sun_family = AF_UNIX;
    for (usize i = 0; i < sizeof(sa.sun_path); ++i) sa.sun_path[i] = 0;
    for (usize i = 0; i < sizeof(path) && i < sizeof(sa.sun_path); ++i)
        sa.sun_path[i] = path[i];

    long fd = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) DIE_LIT("[wayland-info] socket FAIL\n");
    if (raw_syscall3(SYS_connect, fd, (long)&sa,
                     (long)(sizeof(sa.sun_family) + sizeof(path))) != 0)
        DIE_LIT("[wayland-info] connect FAIL\n");

    /* wl_display.get_registry(new_id=2): obj=1, opcode=1, size=12. */
    u32 req[3];
    req[0] = 1;
    req[1] = ((u32)12 << 16) | 1;
    req[2] = 2;
    if (raw_syscall3(SYS_write, fd, (long)req, (long)sizeof(req)) != (long)sizeof(req))
        DIE_LIT("[wayland-info] get_registry write FAIL\n");

    /* Reply = wl_registry.global(wl_compositor) + (wl_shm), 16 words / 64 B,
     * delivered in one drain. */
    static u8 buf[256];
    long r = raw_syscall3(SYS_read, fd, (long)buf, (long)sizeof(buf));
    if (r <= 0) DIE_LIT("[wayland-info] get_registry read FAIL\n");
    usize blen = (usize)r;

    usize off = 0;
    if (check_global(buf, &off, blen, 2, 1, "wl_compositor", 14, 4) != 0)
        DIE_LIT("[wayland-info] wl_compositor global FAIL\n");
    if (check_global(buf, &off, blen, 2, 2, "wl_shm", 7, 1) != 0)
        DIE_LIT("[wayland-info] wl_shm global FAIL\n");
    WRITE_LIT("[wayland-info] globals OK\n");

    /* wl_registry.bind(name=1, "wl_compositor", version=4, new_id=3) on obj=2. */
    u32 b[10];
    b[0] = 2;                       /* registry object */
    b[1] = ((u32)40 << 16) | 0;     /* size 40, opcode 0 = bind */
    b[2] = 1;                       /* name */
    b[3] = 14;                      /* interface strlen incl NUL */
    {
        u8 *sb = (u8 *)&b[4];
        const char ifc[] = "wl_compositor";   /* 13 chars + NUL = 14 */
        for (usize i = 0; i < 16; ++i)        sb[i] = 0;
        for (usize i = 0; i < sizeof(ifc); ++i) sb[i] = (u8)ifc[i];
    }
    b[8] = 4;                       /* version */
    b[9] = 3;                       /* new_id */
    if (raw_syscall3(SYS_write, fd, (long)b, (long)sizeof(b)) != (long)sizeof(b))
        DIE_LIT("[wayland-info] bind write FAIL\n");
    WRITE_LIT("[wayland-info] bind OK\n");

    (void)raw_syscall3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
