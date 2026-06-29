/*
 * sotOs · Linux ABI structures + flags used at the syscall boundary.
 *
 * Field layouts must match what Linux x86_64 binaries (musl or static asm)
 * expect. Verified against the Linux kernel headers.
 */

#ifndef SOTOS_LUCAS_LINUX_ABI_H
#define SOTOS_LUCAS_LINUX_ABI_H

#include <stdint.h>

/* uname() · 6 fixed-size strings of 65 bytes each */
struct lx_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

/* mmap flags · subset */
#define LX_PROT_READ     0x1
#define LX_PROT_WRITE    0x2
#define LX_PROT_EXEC     0x4

#define LX_MAP_PRIVATE   0x02
#define LX_MAP_ANONYMOUS 0x20
#define LX_MAP_FIXED     0x10

/* arch_prctl codes */
#define LX_ARCH_SET_FS   0x1002
#define LX_ARCH_GET_FS   0x1003
#define LX_ARCH_SET_GS   0x1001
#define LX_ARCH_GET_GS   0x1004

/* Linux errno values used in v1 (negated when returned) */
#define LX_ENOSYS        38
#define LX_EBADF         9
#define LX_EINVAL        22
#define LX_EFAULT        14
#define LX_ENOMEM        12
/* Linux-ABI tiers · realistic errno set so unimplemented/contained syscalls
 * fail like a real (locked-down / read-only) kernel — never ENOSYS, which is
 * the honeypot's biggest tell under strace. */
#define LX_EPERM         1
#define LX_ENOENT        2
#define LX_ECHILD        10
#define LX_EAGAIN        11
#define LX_EACCES        13
#define LX_EEXIST        17
#define LX_EXDEV         18
#define LX_ENOTDIR       20
#define LX_EISDIR        21
#define LX_ENOSPC        28
#define LX_EROFS         30
#define LX_ENOTEMPTY     39
#define LX_ENODATA       61
#define LX_EOPNOTSUPP    95

/* ioctl request numbers (subset · termios + size) */
#define LX_TCGETS        0x5401
#define LX_TCSETS        0x5402
#define LX_TCSETSW       0x5403
#define LX_TCSETSF       0x5404
#define LX_TIOCGWINSZ    0x5413
#define LX_TIOCSWINSZ    0x5414
#define LX_TIOCSPGRP     0x5410
#define LX_TIOCGPGRP     0x540F
#define LX_FIONREAD      0x541B
#define LX_FIONBIO       0x5421

struct lx_termios {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t  c_line;
    uint8_t  c_cc[19];
};
struct lx_winsize {
    uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel;
};

#endif /* SOTOS_LUCAS_LINUX_ABI_H */
