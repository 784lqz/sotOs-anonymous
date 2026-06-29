/*
 * sotOs L14a-D1 guest fixture · hand-rolled HOSTILE screen-capture client.
 *
 * The inverse of wl_shm.c: instead of DRAWING pixels into a shared pool, this
 * fixture READS the screen — it simulates an infostealer that captures the
 * desktop.  It connects to the compositor route, binds the sotos_capture
 * global (name=3, advertised only by the CANARY compositor), issues a capture
 * request, and reads back a 5-word reply [vaddr_lo, vaddr_hi, w, h, stride]
 * pointing at a READ-ONLY view of the installed Canary Screenshot.  It then
 * FNV-1a-checksums the captured scene and logs it.
 *
 * Spawned AT TIER 2 (trusted=0) by cmd_wl_capture_client so LUCAS deterministically
 * routes it to the shadow compositor — where the only thing it can capture is
 * the installed canary scene, never a real surface.
 *
 * Raw Linux syscalls only: socket(AF_UNIX), connect, write, read, exit.
 *
 * Object ids are allocated sequentially as real Wayland clients do:
 *   wl_display=1, registry=2, sotos_capture=3.
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;
typedef unsigned long  usize;

#define SYS_read     0
#define SYS_write    1
#define SYS_exit     60
#define SYS_socket   41
#define SYS_connect  42

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

/* Print "<prefix>%ux%u fnv1a=0x%08x\n" without libc printf. */
static void log_capture(const char *prefix, usize plen, u32 w, u32 h, u32 v)
{
    static const char hexd[] = "0123456789abcdef";
    char buf[40];
    usize n = 0;
    /* width (decimal, up to 5 digits) */
    {
        char tmp[10]; int t = 0;
        u32 x = w;
        if (x == 0) tmp[t++] = '0';
        while (x) { tmp[t++] = (char)('0' + (x % 10)); x /= 10; }
        while (t) buf[n++] = tmp[--t];
    }
    buf[n++] = 'x';
    {
        char tmp[10]; int t = 0;
        u32 x = h;
        if (x == 0) tmp[t++] = '0';
        while (x) { tmp[t++] = (char)('0' + (x % 10)); x /= 10; }
        while (t) buf[n++] = tmp[--t];
    }
    {
        static const char tag[] = " fnv1a=0x";
        for (usize i = 0; i < sizeof(tag) - 1; ++i) buf[n++] = tag[i];
    }
    for (int i = 0; i < 8; ++i)
        buf[n++] = hexd[(v >> ((7 - i) * 4)) & 0xF];
    buf[n++] = '\n';
    write_lit(prefix, plen);
    write_lit(buf, n);
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
    if (fd < 0) DIE_LIT("[wl-capture] socket FAIL\n");

    long rc = raw_syscall3(SYS_connect, fd, (long)&sa,
                           (long)(sizeof(sa.sun_family) + sizeof(path)));
    if (rc != 0) DIE_LIT("[wl-capture] connect FAIL\n");

    /* 1) wl_display.get_registry(new_id=2): id=1, opcode=1, size=12. */
    {
        u32 req[3];
        req[0] = 1;                      /* wl_display object id */
        req[1] = ((u32)12 << 16) | 1;    /* (size<<16) | opcode(get_registry=1) */
        req[2] = 2;                      /* registry new_id */
        if (raw_syscall3(SYS_write, fd, (long)req, (long)sizeof(req))
            != (long)sizeof(req))
            DIE_LIT("[wl-capture] get_registry write FAIL\n");
    }

    /* Drain the registry globals reply (optional · we know the names). */
    {
        u32 rep[16];
        for (int i = 0; i < 16; ++i) rep[i] = 0;
        (void)raw_syscall3(SYS_read, fd, (long)rep, (long)sizeof(rep));
    }

    /* 2) wl_registry.bind(name=3, "sotos_capture", version=1, new_id=3) on obj=2.
     * "sotos_capture" = 13 chars + NUL = 14 bytes; padded to 16 (4 words).
     * The shadow's GLOBALS row is {3,"sotos_capture",14,1} — match slen=14.
     * Frame = [reg, hdr, name, slen, str0..str3, version, new_id] = 10 words. */
    {
        u32 b[10];
        b[0] = 2;                        /* registry object */
        b[1] = ((u32)40 << 16) | 0;      /* size 40, opcode 0 = bind */
        b[2] = 3;                        /* name = 3 (sotos_capture global) */
        b[3] = 14;                       /* interface strlen incl NUL */
        {
            u8 *sb = (u8 *)&b[4];
            const char ifc[] = "sotos_capture";  /* 13 chars + NUL = 14 */
            for (usize i = 0; i < 16; ++i)         sb[i] = 0;
            for (usize i = 0; i < sizeof(ifc); ++i) sb[i] = (u8)ifc[i];
        }
        b[8] = 1;                        /* version */
        b[9] = 3;                        /* bound new_id = sotos_capture id */
        if (raw_syscall3(SYS_write, fd, (long)b, (long)sizeof(b))
            != (long)sizeof(b))
            DIE_LIT("[wl-capture] bind sotos_capture write FAIL\n");
    }

    /* 3) sotos_capture.capture() on obj=3, opcode 0.  2 words (8 bytes).
     * LUCAS maps a fresh RO view of the installed canary screenshot and replies
     * with [vaddr_lo, vaddr_hi, w, h, stride]. */
    {
        u32 cap[2];
        cap[0] = 3;                      /* sotos_capture object id */
        cap[1] = ((u32)8 << 16) | 0;     /* size 8, opcode 0 = capture */
        if (raw_syscall3(SYS_write, fd, (long)cap, (long)sizeof(cap))
            != (long)sizeof(cap))
            DIE_LIT("[wl-capture] capture write FAIL\n");
    }

    /* 4) read the 5-word (20-byte) reply: [va_lo, va_hi, w, h, stride]. */
    {
        u32 reply[5];
        for (int i = 0; i < 5; ++i) reply[i] = 0;
        long n = raw_syscall3(SYS_read, fd, (long)reply, (long)sizeof(reply));
        if (n != (long)sizeof(reply))
            DIE_LIT("[wl-capture] capture reply short read FAIL\n");

        /* 5) reconstruct the 64-bit canary view vaddr (> 32 bits: 0x210000000). */
        u64 vaddr = (u64)reply[0] | ((u64)reply[1] << 32);
        u32 w      = reply[2];
        u32 h      = reply[3];
        u32 stride = reply[4];

        /* 6) read the installed canary scene: FNV-1a over h*stride bytes. */
        const u8 *p = (const u8 *)(usize)vaddr;
        usize total = (usize)h * (usize)stride;
        u32 chk = 2166136261u;
        for (usize i = 0; i < total; ++i) {
            chk ^= p[i];
            chk *= 16777619u;
        }

        static const char pfx[] = "[wl-capture] captured ";
        log_capture(pfx, sizeof(pfx) - 1, w, h, chk);
    }

    /* === wl_seat flow: bind + poll + read synthetic input batch === */

    /* 5) wl_registry.bind(name=4, "wl_seat", version=1, new_id=4).
     * "wl_seat" = 7 chars + NUL = 8 bytes; padded to 8 (2 words).
     * Frame = [reg, hdr, name, slen, str0, str1, version, new_id] = 8 words (32 bytes). */
    {
        u32 b[8];
        b[0] = 2;                           /* registry object id */
        b[1] = ((u32)32 << 16) | 0;         /* size 32, opcode 0 = bind */
        b[2] = 4;                           /* global name = 4 (wl_seat) */
        b[3] = 8;                           /* interface strlen incl NUL */
        /* "wl_seat\0" packed little-endian into 2 words */
        b[4] = (u32)'w' | ((u32)'l' << 8) | ((u32)'_' << 16) | ((u32)'s' << 24);
        b[5] = (u32)'e' | ((u32)'a' << 8) | ((u32)'t' << 16) | (0u << 24);
        b[6] = 1;                           /* version */
        b[7] = 4;                           /* bound new_id = wl_seat id */
        if (raw_syscall3(SYS_write, fd, (long)b, (long)sizeof(b))
            != (long)sizeof(b))
            DIE_LIT("[wl-capture] bind wl_seat write FAIL\n");
    }

    /* 6) wl_seat.get_keyboard() on obj=4, opcode 2, 8 bytes (2 words).
     * LUCAS maps a fresh RO view of the installed xkb keymap blob and replies with
     * a 4-word [kva_lo, kva_hi, size, format(=1 XKB_V1)] pointing at it. */
    {
        u32 gk[2];
        gk[0] = 4;                          /* wl_seat object id */
        gk[1] = ((u32)8 << 16) | 2;         /* size 8, opcode 2 = get_keyboard */
        if (raw_syscall3(SYS_write, fd, (long)gk, (long)sizeof(gk))
            != (long)sizeof(gk))
            DIE_LIT("[wl-capture] get_keyboard write FAIL\n");
    }

    /* 6b) read the 4-word (16-byte) keymap reply: [kva_lo, kva_hi, size, format].
     * Reconstruct the 64-bit keymap view vaddr (RO-mapped like the canary scene),
     * FNV-1a over `size` bytes read directly at that vaddr. */
    {
        u32 kreply[4];
        for (int i = 0; i < 4; ++i) kreply[i] = 0;
        long n = raw_syscall3(SYS_read, fd, (long)kreply, (long)sizeof(kreply));
        if (n != (long)sizeof(kreply))
            DIE_LIT("[wl-capture] keymap reply short read FAIL\n");

        u64 kva   = (u64)kreply[0] | ((u64)kreply[1] << 32);
        u32 ksize = kreply[2];

        const u8 *kp = (const u8 *)(usize)kva;
        u32 chk = 2166136261u;
        for (usize i = 0; i < (usize)ksize; ++i) {
            chk ^= kp[i];
            chk *= 16777619u;
        }

        /* log "[wl-capture] keymap <size> fnv1a=0xHHHHHHHH\n" */
        {
            static const char hexd[] = "0123456789abcdef";
            static const char pfx[]  = "[wl-capture] keymap ";
            static const char mid[]  = " fnv1a=0x";
            char tmp[10];
            int t = 0;
            u32 x = ksize;
            if (x == 0) tmp[t++] = '0';
            while (x) { tmp[t++] = (char)('0' + (x % 10)); x /= 10; }
            char sz_str[10];
            usize sz_len = 0;
            while (t) sz_str[sz_len++] = tmp[--t];

            char hex_str[9];
            for (int i = 0; i < 8; ++i)
                hex_str[i] = hexd[(chk >> ((7 - i) * 4)) & 0xF];

            write_lit(pfx,    sizeof(pfx) - 1);
            write_lit(sz_str, sz_len);
            write_lit(mid,    sizeof(mid) - 1);
            write_lit(hex_str, 8);
            write_lit("\n",   1);
        }
    }

    /* 7) wl_seat.poll() on obj=4, opcode 1, 8 bytes (2 words). */
    {
        u32 p[2];
        p[0] = 4;                           /* wl_seat object id */
        p[1] = ((u32)8 << 16) | 1;          /* size 8, opcode 1 = poll */
        if (raw_syscall3(SYS_write, fd, (long)p, (long)sizeof(p))
            != (long)sizeof(p))
            DIE_LIT("[wl-capture] wl_seat poll write FAIL\n");
    }

    /* 8) read the synthetic input event batch in one call.
     * Format: [count, count*(type,arg0,arg1,ts_ms)] → count=15 → 1+60=61 u32 = 244 bytes.
     * FNV-1a byte-wise over (1 + count*4)*4 bytes to match LUCAS's injected value. */
    {
        u8 buf[256];
        for (usize i = 0; i < sizeof(buf); ++i) buf[i] = 0;
        long n = raw_syscall3(SYS_read, fd, (long)buf, (long)sizeof(buf));
        if (n <= 0)
            DIE_LIT("[wl-capture] wl_seat read FAIL\n");

        u32 count = ((u32 *)buf)[0];
        usize blen = (usize)(1u + count * 4u) * 4u;

        /* byte-wise FNV-1a — identical to capture checksum loop */
        u32 h = 2166136261u;
        for (usize i = 0; i < blen; ++i) {
            h ^= buf[i];
            h *= 16777619u;
        }

        /* log "[wl-capture] input N events fnv1a=0xHHHHHHHH\n" */
        {
            static const char hexd[] = "0123456789abcdef";
            static const char pfx[]  = "[wl-capture] input ";
            static const char mid[]  = " events fnv1a=0x";
            char tmp[10];
            int t = 0;
            u32 x = count;
            if (x == 0) tmp[t++] = '0';
            while (x) { tmp[t++] = (char)('0' + (x % 10)); x /= 10; }
            /* reverse digits */
            char cnt_str[10];
            usize cnt_len = 0;
            while (t) cnt_str[cnt_len++] = tmp[--t];

            char hex_str[9];
            for (int i = 0; i < 8; ++i)
                hex_str[i] = hexd[(h >> ((7 - i) * 4)) & 0xF];

            write_lit(pfx,     sizeof(pfx) - 1);
            write_lit(cnt_str, cnt_len);
            write_lit(mid,     sizeof(mid) - 1);
            write_lit(hex_str, 8);
            write_lit("\n",    1);
        }
    }

    (void)raw_syscall3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
