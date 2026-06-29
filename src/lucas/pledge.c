/*
 * sotOs · LUCAS · pledge · operation-class capability gate.
 *
 * Phase 0 shipped the per-sotBox `pledge` bitmask field and the dispatcher
 * gate (src/lucas/dispatch.c).  OBSD-δ-1 adds the user-facing surface:
 *
 *   - pledge_parse(): OpenBSD-style promise-string → bitmask
 *   - pledge_class_name(): bit → canonical name (for diagnostics)
 *   - lucas_sys_pledge(): the LUCAS-private syscall that narrows the
 *     caller's mask, with monotonic-narrowing semantics matching OpenBSD
 *     (new mask MUST be a subset of the current mask)
 *
 * The dispatcher gate itself is unchanged; it already emits
 * ANOMALY_EV_PLEDGE_VIOLATION when a categorised syscall falls outside
 * the current mask.  In δ-1 the default mask is PLEDGE_ALL (set at spawn)
 * so no violations fire until a sotBox calls pledge() to narrow.
 */
#include <lucas/pledge.h>
#include <lucas/syscalls.h>
#include "state.h"
#include "handlers.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* Linux EPERM · used by lucas_sys_pledge on monotonicity violation.
 * Defined locally so we don't widen the linux_abi.h surface in this
 * commit (out of file scope). */
#define LX_EPERM_LOCAL  1

/* Forward declaration · defined in handlers_fs.c. */
extern int lucas_copy_cstr_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                        char *buf, size_t buf_size);

/* ────────────────────────────────────────────────────────────────────
 * Category lookup table · existing API.
 *
 * Maps a Linux syscall number to the single PLEDGE_* bit that gates it.
 * Returns 0 for uncategorised syscalls (always allowed during phased
 * rollout · spec §6 "Init-phase privilege window", option (b)).
 * ──────────────────────────────────────────────────────────────────── */
uint64_t pledge_category(uint64_t sysno) {
    switch (sysno) {
        /* STDIO */
        case LX_SYS_read:
        case LX_SYS_write:
        case LX_SYS_close:
        case LX_SYS_lseek:
        case LX_SYS_dup:
        case LX_SYS_dup2:
        case LX_SYS_dup3:
        case LX_SYS_pipe:
        case LX_SYS_pipe2:
        case LX_SYS_ioctl:
        case LX_SYS_fcntl:
        case LX_SYS_exit:
        case LX_SYS_exit_group:
        case LX_SYS_writev:
            return PLEDGE_STDIO;

        /* RPATH (read-only path) */
        case LX_SYS_open:
        case LX_SYS_openat:
        case LX_SYS_stat:
        case LX_SYS_fstat:
        case LX_SYS_lstat:
        case LX_SYS_newfstatat:
        case LX_SYS_readlink:
        case LX_SYS_readlinkat:
        case LX_SYS_access:
        case LX_SYS_getcwd:
        case LX_SYS_getdents64:
            return PLEDGE_RPATH;

        /* WPATH (write-capable path) · mkdir/unlink/rmdir are the markers
         * for Phase 1; write-mode open is handled by the RPATH category
         * because we don't yet inspect open flags in the gate. */

        /* INET · sotNet socket surface (spec §3 bit 3). */
        case LX_SYS_socket:
        case LX_SYS_connect:
        case LX_SYS_accept:
        case LX_SYS_accept4:
        case LX_SYS_bind:
        case LX_SYS_listen:
        case LX_SYS_sendto:
        case LX_SYS_recvfrom:
        case LX_SYS_sendmsg:
        case LX_SYS_recvmsg:
        case LX_SYS_shutdown:
        case LX_SYS_getsockname:
        case LX_SYS_getpeername:
        case LX_SYS_socketpair:
        case LX_SYS_setsockopt:
        case LX_SYS_getsockopt:
            return PLEDGE_INET;

        /* PROC · fork/clone/wait/signal family (NO execve · see EXEC below).
         * OBSD-δ-3 follow-up: PROC and EXEC are now distinct bits per spec §3
         * ("daemons can fork but not exec"). Previously LX_SYS_execve lived in
         * this case because PLEDGE_EXEC was a #define alias of PLEDGE_PROC. */
        case LX_SYS_fork:
        case LX_SYS_clone:
        case LX_SYS_wait4:
        case LX_SYS_kill:
        case LX_SYS_tkill:
        case LX_SYS_tgkill:
            return PLEDGE_PROC;

        /* EXEC · program replacement only (spec §3 bit 6). Split from PROC so
         * a daemon template can grant fork without granting exec. */
        case LX_SYS_execve:
            return PLEDGE_EXEC;

        /* VMINFO */
        case LX_SYS_mmap:
        case LX_SYS_munmap:
        case LX_SYS_mprotect:
        case LX_SYS_brk:
            return PLEDGE_VMINFO;

        /* SETID */
        case LX_SYS_setuid:
        case LX_SYS_setgid:
            return PLEDGE_SETID;

        /* LUCAS-private surface (spec §3 bit 10). */
        case LX_SYS_pledge:
            return PLEDGE_LUCAS;

        /* Uncategorised · always allowed during Phase 1 rollout. */
        default:
            return 0;
    }
}

/* ────────────────────────────────────────────────────────────────────
 * OBSD-δ-2 · argument-aware classification.
 *
 * pledge_category() above only sees the syscall number, so it routed
 * every openat to PLEDGE_RPATH regardless of the open mode. A
 * T_CANARY_TARGET sotBox (stdio+rpath only, no wpath) could then call
 * openat(O_WRONLY) and silently pass the gate · maintainer M1 audit
 * follow-up #2.
 *
 * pledge_check_args() inspects the O_ACCMODE bits of the flags argument
 * for open/openat (and creat, when LX_SYS_creat is added) and returns
 * PLEDGE_WPATH for O_WRONLY/O_RDWR. All other syscalls fall through to
 * the plain pledge_category() table.
 *
 * The dispatch gate (src/lucas/dispatch.c) is the only caller.
 * ──────────────────────────────────────────────────────────────────── */
#define LX_O_ACCMODE  0x3   /* O_RDONLY | O_WRONLY | O_RDWR */

pledge_mask_t pledge_check_args(uint64_t sysno, const uint64_t args[6]) {
    switch (sysno) {
        case LX_SYS_open: {
            /* int open(const char *pathname, int flags, mode_t mode) */
            uint64_t access_mode = args[1] & LX_O_ACCMODE;
            return (access_mode == 0) ? PLEDGE_RPATH : PLEDGE_WPATH;
        }
        case LX_SYS_openat: {
            /* int openat(int dirfd, const char *pathname, int flags, mode_t mode) */
            uint64_t access_mode = args[2] & LX_O_ACCMODE;
            return (access_mode == 0) ? PLEDGE_RPATH : PLEDGE_WPATH;
        }
        default:
            return pledge_category(sysno);
    }
}

/* ────────────────────────────────────────────────────────────────────
 * Promise-string parser.
 *
 * Accepts OpenBSD-style space/comma-separated promise tokens (e.g.
 * "stdio rpath inet" or "stdio,rpath,inet").  Unknown tokens are ignored
 * for forward compatibility.  A fixed table keeps the parser at < 1 KiB.
 * ──────────────────────────────────────────────────────────────────── */
struct pledge_name_entry {
    const char     *name;
    pledge_mask_t   bit;
};

static const struct pledge_name_entry pledge_class_table[] = {
    { "stdio",   PLEDGE_STDIO  },
    { "rpath",   PLEDGE_RPATH  },
    { "wpath",   PLEDGE_WPATH  },
    { "inet",    PLEDGE_INET   },
    { "unix",    PLEDGE_UNIX   },
    { "proc",    PLEDGE_PROC   },
    { "exec",    PLEDGE_EXEC   },   /* OBSD-δ-3: distinct bit from PROC */
    { "setid",   PLEDGE_SETID  },
    { "fattr",   PLEDGE_FATTR  },
    { "vminfo",  PLEDGE_VMINFO },
    { "tty",     PLEDGE_TTY    },
    { "lucas",   PLEDGE_LUCAS  },
    { "sotfs",   PLEDGE_SOTFS  },
};
#define PLEDGE_CLASS_TABLE_LEN (sizeof(pledge_class_table) / sizeof(pledge_class_table[0]))

static int pledge_is_sep(char c) {
    return c == ' ' || c == '\t' || c == ',' || c == '\n' || c == '\r';
}

/* Case-insensitive ASCII compare of `tok` (length `len`) against `name`
 * (NUL-terminated). Returns 1 if equal. */
static int pledge_token_eq(const char *tok, size_t len, const char *name) {
    for (size_t i = 0; i < len; i++) {
        char a = tok[i];
        char b = name[i];
        if (b == '\0') return 0;
        if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
        if (a != b) return 0;
    }
    return name[len] == '\0';
}

pledge_mask_t pledge_parse(const char *promise_str) {
    if (promise_str == NULL) return 0;
    pledge_mask_t mask = 0;
    const char *p = promise_str;
    while (*p != '\0') {
        while (*p != '\0' && pledge_is_sep(*p)) p++;
        if (*p == '\0') break;
        const char *tok_start = p;
        while (*p != '\0' && !pledge_is_sep(*p)) p++;
        size_t tok_len = (size_t)(p - tok_start);
        for (size_t i = 0; i < PLEDGE_CLASS_TABLE_LEN; i++) {
            if (pledge_token_eq(tok_start, tok_len, pledge_class_table[i].name)) {
                mask |= pledge_class_table[i].bit;
                break;
            }
        }
    }
    return mask;
}

/* ────────────────────────────────────────────────────────────────────
 * SPAWN-PLEDGE-CLI · template-name lookup.
 *
 * Operators name pledge templates symbolically (e.g. "T_PYTHON_SANDBOX")
 * on the sotShell `python --pledge <name>` flag. We map names to the
 * PLEDGE_T_* bitmask defines from pledge.h. The table is kept here so
 * that any future consumer of `orch_spawn_msg_t.pledge` (not just
 * sotShell) can resolve the same names consistently.
 *
 * Unknown names return PLEDGE_ALL with *ok = 0 so the caller can
 * surface an error to the user while we still have a safe default in
 * the absence of caller-side checks. "none" is the explicit pass-
 * through that maps to PLEDGE_ALL with *ok = 1.
 * ──────────────────────────────────────────────────────────────────── */
struct pledge_template_entry {
    const char *name;
    uint64_t    mask;
};

static const struct pledge_template_entry pledge_template_table[] = {
    { "none",              PLEDGE_ALL              },
    { "T_TRUSTED_ROOT",    PLEDGE_T_TRUSTED_ROOT   },
    { "T_SHELL",           PLEDGE_T_SHELL          },
    { "T_DAEMON_NETWORK",  PLEDGE_T_DAEMON_NETWORK },
    { "T_CANARY_TARGET",    PLEDGE_T_CANARY_TARGET   },
    { "T_PYTHON_SANDBOX",  PLEDGE_T_PYTHON_SANDBOX },
    { "T_COMPUTE_ONLY",    PLEDGE_T_COMPUTE_ONLY   },
    { "T_PIPELINE_STAGE",  PLEDGE_T_PIPELINE_STAGE },
    { "T_NET_CLIENT",      PLEDGE_T_NET_CLIENT     },
};
#define PLEDGE_TEMPLATE_TABLE_LEN \
    (sizeof(pledge_template_table) / sizeof(pledge_template_table[0]))

uint64_t lucas_pledge_template_from_name(const char *name, int *ok) {
    if (name == NULL) {
        if (ok) *ok = 1;
        return PLEDGE_ALL;
    }
    for (size_t i = 0; i < PLEDGE_TEMPLATE_TABLE_LEN; i++) {
        if (strcmp(name, pledge_template_table[i].name) == 0) {
            if (ok) *ok = 1;
            return pledge_template_table[i].mask;
        }
    }
    if (ok) *ok = 0;
    return PLEDGE_ALL;
}

const char *pledge_class_name(pledge_mask_t single_bit) {
    /* Reject zero and non-single-bit inputs · class names are per-bit. */
    if (single_bit == 0) return "?";
    if ((single_bit & (single_bit - 1)) != 0) return "?";
    for (size_t i = 0; i < PLEDGE_CLASS_TABLE_LEN; i++) {
        if (pledge_class_table[i].bit == single_bit) {
            return pledge_class_table[i].name;
        }
    }
    return "?";
}

/* ────────────────────────────────────────────────────────────────────
 * lucas_sys_pledge(promise_vaddr, _unused...)
 *
 * Reads the NUL-terminated promise string from the client's vspace,
 * parses it into a bitmask, and ANDs it into st->pledge with monotonic
 * narrowing semantics:
 *
 *   - First call (current mask == PLEDGE_ALL): set the new mask
 *     directly (subject to being non-empty after parse).
 *   - Subsequent calls: new mask must be a SUBSET of the current mask.
 *     If it tries to add a bit that is not currently set, return -EPERM
 *     and leave the mask unchanged.
 *
 * Return: 0 on success, negated Linux errno on failure (-EFAULT if the
 * user pointer is unreadable, -EINVAL on empty parse, -EPERM on
 * non-monotonic narrowing).
 * ──────────────────────────────────────────────────────────────────── */
int64_t lucas_sys_pledge(lucas_state_t *st,
                          uint64_t promise_vaddr,
                          uint64_t _a1, uint64_t _a2, uint64_t _a3,
                          uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;

    /* NULL pointer means "no change" · matches OpenBSD's pledge(NULL, ...). */
    if (promise_vaddr == 0) {
        return 0;
    }

    char promise_buf[64];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)promise_vaddr,
                                     promise_buf, sizeof(promise_buf)) < 0) {
        return -(int64_t)14;  /* LX_EFAULT */
    }

    pledge_mask_t requested = pledge_parse(promise_buf);
    if (requested == 0) {
        /* Empty / unrecognised promise string · refuse rather than
         * accidentally relaxing to "no restriction". */
        return -(int64_t)22;  /* LX_EINVAL */
    }

    pledge_mask_t current = (pledge_mask_t)st->pledge;
    /* First-call detection: spawn always initialises st->pledge to
     * PLEDGE_ALL, so PLEDGE_ALL is the sole valid first-call anomaly.
     * The prior `current == 0` arm was a latent widening trap (no code
     * path produces a zero mask) and has been removed (maintainer M1
     * required follow-up #3). */
    int is_first_call = (current == PLEDGE_ALL);

    if (!is_first_call) {
        /* Monotonic: every requested bit must already be set. */
        if ((requested & ~current) != 0) {
            printf("[pledge] pid=%d · refused widening · req=0x%llx not subset of 0x%llx\n",
                   st->synthetic_pid,
                   (unsigned long long)requested,
                   (unsigned long long)current);
            return -(int64_t)LX_EPERM_LOCAL;
        }
    }

    /* AND-in: even on a first call we narrow to exactly `requested`. */
    st->pledge = is_first_call ? (uint64_t)requested
                               : (uint64_t)(current & requested);

    printf("[pledge] pid=%d · mask=0x%llx (\"%s\")\n",
           st->synthetic_pid,
           (unsigned long long)st->pledge,
           promise_buf);

    return 0;
}
