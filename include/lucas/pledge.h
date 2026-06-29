#ifndef LUCAS_PLEDGE_H
#define LUCAS_PLEDGE_H

#include <stdint.h>

#define PLEDGE_STDIO   (1ULL << 0)   /* read/write/close/etc */
#define PLEDGE_RPATH   (1ULL << 1)   /* open(O_RDONLY), stat, readlink, getdents */
#define PLEDGE_WPATH   (1ULL << 2)   /* open(O_WRONLY|O_RDWR), unlink, mkdir, rmdir */
#define PLEDGE_INET    (1ULL << 3)   /* socket(AF_INET), connect, bind, sendto */
#define PLEDGE_UNIX    (1ULL << 4)   /* socket(AF_UNIX) */
#define PLEDGE_PROC    (1ULL << 5)   /* fork, wait4, kill (NO execve · see EXEC) */
/* OBSD-δ-3 · PLEDGE_EXEC now a distinct bit (was alias of PROC in δ-1). Spec §3
 * "daemons can fork but not exec" requires this separation. */
#define PLEDGE_EXEC    (1ULL << 6)   /* execve only · separate from PROC per spec §3 */
#define PLEDGE_FATTR   (1ULL << 7)   /* chmod, chown, fchmod, fchown */
#define PLEDGE_VMINFO  (1ULL << 8)   /* mmap, mprotect, munmap */
/* OBSD-δ-1 · bits 9..11 from docs/obsd-delta-pledge-templates.md §3. */
#define PLEDGE_TTY     (1ULL << 9)   /* ioctl(TIOCGWINSZ/TCSETS), pty pair ops */
#define PLEDGE_LUCAS   (1ULL << 10)  /* LUCAS-private syscalls (sotinfo, tier query, pledge) */
#define PLEDGE_SOTFS   (1ULL << 11)  /* sotFS-θ curvature/install/silenced-mount ops */
/* OBSD-δ-3 · SETID moved off bit 6 (which is now EXEC). Lives above the spec
 * class range; not listed in spec §3 table, so this bit position is an
 * implementation extension and can occupy any free slot. */
#define PLEDGE_SETID   (1ULL << 12)  /* setuid/setgid */
#define PLEDGE_ALL     0xFFFFFFFFFFFFFFFFULL  /* unrestricted · default for all sotBoxes */

/* Common templates · legacy (kept for backward compat). */
#define PLEDGE_TEMPLATE_COMPUTE_ONLY   (PLEDGE_STDIO | PLEDGE_RPATH)
#define PLEDGE_TEMPLATE_FILE_RW        (PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_FATTR)
#define PLEDGE_TEMPLATE_PIPELINE       (PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_PROC | PLEDGE_VMINFO)
#define PLEDGE_TEMPLATE_NETCLIENT      (PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_INET)

/* OBSD-δ-1 · named templates from spec §4 (Template profiles).
 * Operators reference these by symbol; the parser also accepts the
 * promise-string components individually. */
#define PLEDGE_T_TRUSTED_ROOT    PLEDGE_ALL
/* OBSD-δ-3 · T_SHELL gets explicit EXEC bit (spec §4 row 2: STDIO | RPATH |
 * WPATH | PROC | EXEC | TTY). Previously the EXEC bit was implicitly granted
 * via the PROC alias; now it must be OR'd in. */
#define PLEDGE_T_SHELL           (PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_PROC | PLEDGE_EXEC | PLEDGE_TTY)
#define PLEDGE_T_DAEMON_NETWORK  (PLEDGE_STDIO | PLEDGE_INET  | PLEDGE_RPATH)
#define PLEDGE_T_CANARY_TARGET    (PLEDGE_STDIO | PLEDGE_RPATH)
#define PLEDGE_T_PYTHON_SANDBOX  (PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_VMINFO)
#define PLEDGE_T_COMPUTE_ONLY    (PLEDGE_STDIO | PLEDGE_RPATH)
/* OBSD-δ-3 · T_PIPELINE_STAGE keeps PROC but does NOT add EXEC · spec §4
 * "may fork siblings but may not exec foreign code". The δ-1 alias made this
 * accidentally permit exec; now correctly enforced. */
#define PLEDGE_T_PIPELINE_STAGE  (PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_PROC | PLEDGE_VMINFO)
#define PLEDGE_T_NET_CLIENT      (PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_INET | PLEDGE_VMINFO)

typedef uint64_t pledge_mask_t;

/* Return the pledge category bitmask for the given Linux syscall number.
 * Returns 0 if the syscall is uncategorised (treated as always allowed
 * to avoid false positives during Phase 1 rollout). */
uint64_t pledge_category(uint64_t sysno);

/* OBSD-δ-1 · parse an OpenBSD-style promise string (e.g. "stdio rpath inet"
 * or "stdio,rpath,inet") into a pledge mask. Whitespace, commas, and
 * separating tabs are all accepted as delimiters. Unknown tokens are
 * ignored (forward-compat with future class additions). Returns 0 on an
 * empty input. */
pledge_mask_t pledge_parse(const char *promise_str);

/* OBSD-δ-1 · return the canonical lower-case class name for a single
 * pledge bit (e.g. PLEDGE_STDIO → "stdio"). Returns "?" if the bit is
 * unknown or not a single-bit mask. The returned pointer is static and
 * does not need to be freed. */
const char *pledge_class_name(pledge_mask_t single_bit);

/* OBSD-δ-2 · argument-aware category lookup. For most syscalls this just
 * returns pledge_category(sysno). For open/openat (and creat, when added)
 * it inspects O_ACCMODE in the flags arg and returns PLEDGE_RPATH for
 * O_RDONLY and PLEDGE_WPATH for O_WRONLY/O_RDWR, closing the WPATH gap
 * flagged by maintainer M1 follow-up.
 *
 *   args[0..5] map to the syscall arguments a0..a5. For openat, flags is
 *   args[2] (int openat(dirfd, path, flags, mode)). For open it is args[1]
 *   (int open(path, flags, mode)). */
pledge_mask_t pledge_check_args(uint64_t sysno, const uint64_t args[6]);

/* SPAWN-PLEDGE-CLI · resolve a textual pledge template name (e.g.
 * "T_PYTHON_SANDBOX" or "none") into the corresponding bitmask.
 *
 * Behavior:
 *   - NULL or "none" (case-sensitive) → PLEDGE_ALL, *ok = 1.
 *   - Known T_* template name        → template bitmask, *ok = 1.
 *   - Unknown name                   → PLEDGE_ALL, *ok = 0.
 *
 * Callers use the *ok out-param to distinguish unknown from "none".
 * Pass ok=NULL if the caller does not care (unknown will still return
 * PLEDGE_ALL · safest default for unrestricted execution). */
uint64_t lucas_pledge_template_from_name(const char *name, int *ok);

#endif /* LUCAS_PLEDGE_H */
