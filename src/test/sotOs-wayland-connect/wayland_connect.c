/*
 * sotOs L12-beta guest fixture.
 *
 * Raw Linux syscalls only: socket(AF_UNIX), connect(sockaddr_un), write, exit.
 * The binary is intentionally tiny and libc-free so it can run as a LUCAS guest.
 */

typedef unsigned short u16;
typedef unsigned long  usize;

#define SYS_write   1
#define SYS_socket  41
#define SYS_connect 42
#define SYS_exit    60

#define AF_UNIX     1
#define SOCK_STREAM 1

#define WAYLAND_PATH "/run/user/1000/wayland-0"
#define BAD_PATH     "/run/user/1000/not-wayland"

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

static long connect_path(const char *path, usize path_len)
{
    static struct sockaddr_un_min sa;

    sa.sun_family = AF_UNIX;
    for (usize i = 0; i < sizeof(sa.sun_path); ++i) {
        sa.sun_path[i] = 0;
    }
    for (usize i = 0; i < path_len && i < sizeof(sa.sun_path); ++i) {
        sa.sun_path[i] = path[i];
    }

    long fd = raw_syscall3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return fd;
    }
    return raw_syscall3(SYS_connect, fd, (long)&sa, (long)(sizeof(sa.sun_family) + path_len));
}

void _start(void)
{
    long rc = connect_path(BAD_PATH, sizeof(BAD_PATH));
    if (rc >= 0) {
        DIE_LIT("[wayland-connect] bad path accepted FAIL\n");
    }
    WRITE_LIT("[wayland-connect] bad path refused OK\n");

    rc = connect_path(WAYLAND_PATH, sizeof(WAYLAND_PATH));
    if (rc != 0) {
        DIE_LIT("[wayland-connect] connect FAIL\n");
    }
    WRITE_LIT("[wayland-connect] connect OK\n");

    (void)raw_syscall3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
