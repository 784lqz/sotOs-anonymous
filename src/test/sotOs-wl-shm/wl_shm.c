/*
 * sotOs L13-D1 guest fixture · hand-rolled wl_shm zero-copy pixel client.
 *
 * Raw Linux syscalls only: socket(AF_UNIX), connect, write, read,
 * memfd_create, ftruncate, mmap, exit.
 *
 * Connects to the compositor route /run/user/1000/wayland-0, binds wl_shm +
 * wl_compositor, memfd_create()s a 64x64 XRGB8888 pool, draws a known pixel
 * pattern, and drives create_pool → create_buffer → create_surface → attach →
 * (anomaly) → commit through to the compositor.  Proves the zero-copy shared
 * memory path: the compositor reads LIVE pool bytes at commit, so a anomaly
 * written AFTER attach but BEFORE commit is reflected in the checksum.
 *
 * Object ids are allocated sequentially as real Wayland clients do:
 *   wl_display=1, registry=2, wl_shm=3, wl_compositor=4, pool=5, buffer=6,
 *   surface=7.
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  usize;

#define SYS_read          0
#define SYS_write         1
#define SYS_mmap          9
#define SYS_exit          60
#define SYS_ftruncate     77
#define SYS_socket        41
#define SYS_connect       42
#define SYS_memfd_create  319

#define AF_UNIX     1
#define SOCK_STREAM 1

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_FAILED ((void *)-1)

#define POOL_W      64
#define POOL_H      64
#define POOL_STRIDE (POOL_W * 4)
#define POOL_SIZE   (POOL_W * POOL_H * 4)

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

static long raw_syscall6(long nr, long a0, long a1, long a2,
                         long a3, long a4, long a5)
{
    long ret;
    register long r10 __asm__("r10") = a3;
    register long r8  __asm__("r8")  = a4;
    register long r9  __asm__("r9")  = a5;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2),
          "r"(r10), "r"(r8), "r"(r9)
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

/* Print "0x%08x\n" of v after the given message prefix (no libc printf). */
static void log_hex(const char *prefix, usize plen, u32 v)
{
    static const char hexd[] = "0123456789abcdef";
    char buf[11];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 8; ++i)
        buf[2 + i] = hexd[(v >> ((7 - i) * 4)) & 0xF];
    buf[10] = '\n';
    write_lit(prefix, plen);
    write_lit(buf, sizeof(buf));
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
    if (fd < 0) DIE_LIT("[wl-shm-fixture] socket FAIL\n");

    long rc = raw_syscall3(SYS_connect, fd, (long)&sa,
                           (long)(sizeof(sa.sun_family) + sizeof(path)));
    if (rc != 0) DIE_LIT("[wl-shm-fixture] connect FAIL\n");

    /* 1) wl_display.get_registry(new_id=2): id=1, opcode=1, size=12. */
    {
        u32 req[3];
        req[0] = 1;                      /* wl_display object id */
        req[1] = ((u32)12 << 16) | 1;    /* (size<<16) | opcode(get_registry=1) */
        req[2] = 2;                      /* registry new_id */
        if (raw_syscall3(SYS_write, fd, (long)req, (long)sizeof(req))
            != (long)sizeof(req))
            DIE_LIT("[wl-shm-fixture] get_registry write FAIL\n");
    }

    /* Drain the registry globals reply (optional · we know the names). */
    {
        u32 rep[16];
        for (int i = 0; i < 16; ++i) rep[i] = 0;
        (void)raw_syscall3(SYS_read, fd, (long)rep, (long)sizeof(rep));
    }

    /* 2) wl_registry.bind(name=2, "wl_shm", version=1, new_id=3) on obj=2.
     * "wl_shm" = 6 chars + NUL = 7 bytes; padded to 8 (2 words).
     * Frame = [reg, hdr, name, slen, str0, str1, version, new_id] = 8 words. */
    {
        u32 b[8];
        b[0] = 2;                        /* registry object */
        b[1] = ((u32)32 << 16) | 0;      /* size 32, opcode 0 = bind */
        b[2] = 2;                        /* name = 2 (wl_shm global) */
        b[3] = 7;                        /* interface strlen incl NUL */
        {
            u8 *sb = (u8 *)&b[4];
            const char ifc[] = "wl_shm";          /* 6 chars + NUL = 7 */
            for (usize i = 0; i < 8; ++i)          sb[i] = 0;
            for (usize i = 0; i < sizeof(ifc); ++i) sb[i] = (u8)ifc[i];
        }
        b[6] = 1;                        /* version */
        b[7] = 3;                        /* bound new_id = wl_shm id */
        if (raw_syscall3(SYS_write, fd, (long)b, (long)sizeof(b))
            != (long)sizeof(b))
            DIE_LIT("[wl-shm-fixture] bind wl_shm write FAIL\n");
    }

    /* Drain the wl_shm.format events (optional). */
    {
        u32 rep[8];
        for (int i = 0; i < 8; ++i) rep[i] = 0;
        (void)raw_syscall3(SYS_read, fd, (long)rep, (long)sizeof(rep));
    }

    /* 3) wl_registry.bind(name=1, "wl_compositor", version=4, new_id=4) on obj=2.
     * "wl_compositor" = 13 + NUL = 14 bytes; padded to 16 (4 words).
     * Frame = [reg, hdr, name, slen, str0..str3, version, new_id] = 10 words. */
    {
        u32 b[10];
        b[0] = 2;                        /* registry object */
        b[1] = ((u32)40 << 16) | 0;      /* size 40, opcode 0 = bind */
        b[2] = 1;                        /* name = 1 (wl_compositor global) */
        b[3] = 14;                       /* interface strlen incl NUL */
        {
            u8 *sb = (u8 *)&b[4];
            const char ifc[] = "wl_compositor";   /* 13 chars + NUL = 14 */
            for (usize i = 0; i < 16; ++i)         sb[i] = 0;
            for (usize i = 0; i < sizeof(ifc); ++i) sb[i] = (u8)ifc[i];
        }
        b[8] = 4;                        /* version */
        b[9] = 4;                        /* bound new_id = wl_compositor id */
        if (raw_syscall3(SYS_write, fd, (long)b, (long)sizeof(b))
            != (long)sizeof(b))
            DIE_LIT("[wl-shm-fixture] bind wl_compositor write FAIL\n");
    }

    /* 4) memfd_create + ftruncate + mmap the pool. */
    {
        static const char memname[] = "wl-shm";
        long mfd = raw_syscall3(SYS_memfd_create, (long)memname, 0, 0);
        if (mfd < 0) DIE_LIT("[wl-shm-fixture] memfd_create FAIL\n");

        if (raw_syscall3(SYS_ftruncate, mfd, (long)POOL_SIZE, 0) != 0)
            DIE_LIT("[wl-shm-fixture] ftruncate FAIL\n");

        void *pmap = (void *)raw_syscall6(SYS_mmap, 0, (long)POOL_SIZE,
                                          PROT_READ | PROT_WRITE,
                                          MAP_SHARED, mfd, 0);
        if (pmap == MAP_FAILED) DIE_LIT("[wl-shm-fixture] mmap FAIL\n");
        u32 *pool = (u32 *)pmap;

        /* 5) draw the known pixel pattern. */
        for (u32 y = 0; y < POOL_H; ++y)
            for (u32 x = 0; x < POOL_W; ++x)
                pool[y * POOL_W + x] =
                    0xFF000000u | ((u32)x << 16) | ((u32)y << 8)
                    | (u32)((x ^ y) & 0xFF);

        /* 6) wl_shm.create_pool(new_id=5, fd=mfd, size). The request TARGETS the
         * wl_shm object (id 3, word0) per Wayland wire semantics; the new pool id
         * is arg0. 5 words (20 bytes); LUCAS appends the compositor vaddr+size. */
        {
            u32 cp[5];
            cp[0] = 3;                       /* wl_shm object id (request target) */
            cp[1] = ((u32)20 << 16) | 0;     /* size 20, opcode 0 = create_pool */
            cp[2] = 5;                       /* pool new_id (arg0) */
            cp[3] = (u32)mfd;                /* memfd fd (arg1) */
            cp[4] = (u32)POOL_SIZE;          /* pool size bytes (arg2) */
            if (raw_syscall3(SYS_write, fd, (long)cp, (long)sizeof(cp))
                != (long)sizeof(cp))
                DIE_LIT("[wl-shm-fixture] create_pool write FAIL\n");
        }

        /* 7) wl_shm_pool.create_buffer(new_id=6, off, w, h, stride, fmt).
         * Frame = [pool, hdr, buffer_new_id, off, w, h, stride, fmt] = 8 words. */
        {
            u32 cb[8];
            cb[0] = 5;                       /* pool object id */
            cb[1] = ((u32)32 << 16) | 0;     /* size 32, opcode 0 = create_buffer */
            cb[2] = 6;                        /* buffer new_id */
            cb[3] = 0;                        /* offset */
            cb[4] = POOL_W;                   /* width */
            cb[5] = POOL_H;                   /* height */
            cb[6] = POOL_STRIDE;              /* stride */
            cb[7] = 1;                        /* format XRGB8888 = 1 */
            if (raw_syscall3(SYS_write, fd, (long)cb, (long)sizeof(cb))
                != (long)sizeof(cb))
                DIE_LIT("[wl-shm-fixture] create_buffer write FAIL\n");
        }

        /* 8) wl_compositor.create_surface(new_id=7) on obj=4. */
        {
            u32 cs[3];
            cs[0] = 4;                       /* wl_compositor object id */
            cs[1] = ((u32)12 << 16) | 0;     /* size 12, opcode 0 = create_surface */
            cs[2] = 7;                        /* surface new_id */
            if (raw_syscall3(SYS_write, fd, (long)cs, (long)sizeof(cs))
                != (long)sizeof(cs))
                DIE_LIT("[wl-shm-fixture] create_surface write FAIL\n");
        }

        /* 9) wl_surface.attach(buffer=6, x=0, y=0) on obj=7. */
        {
            u32 at[5];
            at[0] = 7;                       /* surface object id */
            at[1] = ((u32)20 << 16) | 1;     /* size 20, opcode 1 = attach */
            at[2] = 6;                        /* buffer id */
            at[3] = 0;                        /* x */
            at[4] = 0;                        /* y */
            if (raw_syscall3(SYS_write, fd, (long)at, (long)sizeof(at))
                != (long)sizeof(at))
                DIE_LIT("[wl-shm-fixture] attach write FAIL\n");
        }

        /* 10) anomaly: write AFTER attach, BEFORE commit, to prove the
         * compositor reads LIVE shared memory at commit time. */
        pool[0] = 0xDEADBEEFu;

        /* 11) wl_surface.commit on obj=7. */
        {
            u32 cm[2];
            cm[0] = 7;                       /* surface object id */
            cm[1] = ((u32)8 << 16) | 6;      /* size 8, opcode 6 = commit */
            if (raw_syscall3(SYS_write, fd, (long)cm, (long)sizeof(cm))
                != (long)sizeof(cm))
                DIE_LIT("[wl-shm-fixture] commit write FAIL\n");
        }

        /* 12) log the expected checksum, recomputed AFTER the anomaly (the
         * compositor reads post-anomaly).  Same fnv1a as the compositor. */
        {
            u32 h = 2166136261u;
            const u8 *p = (const u8 *)pool;
            for (usize i = 0; i < (usize)POOL_SIZE; ++i) {
                h ^= p[i];
                h *= 16777619u;
            }
            static const char pfx[] =
                "[wl-shm-fixture] drew 64x64 expected fnv1a=";
            log_hex(pfx, sizeof(pfx) - 1, h);
        }
    }

    (void)raw_syscall3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
