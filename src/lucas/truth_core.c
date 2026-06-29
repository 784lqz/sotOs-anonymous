/*
 * sotOs · truth-core (M1) — the single source of truth.
 *
 * Thin accessors over the REAL sotbox state (lucas_state).  See include/lucas/
 * truth.h for the architecture: /proc renders the Linux view from here, and a
 * future libsot/sotctl renders the native operator view from the SAME accessors
 * — so there is never a second source of truth.  NO new state lives here.
 */
#include <lucas/truth.h>
#include "state.h"
#include <lucas/procd_view.h>
#include <sotos/pidrand.h>
#include <string.h>
#include <stdio.h>

const char *truth_proc_exe(const struct lucas_state *st)
{
    if (st && st->exe_path[0]) {
        const char *e = st->exe_path;
        if (e[0] == '/') return e;             /* already an absolute path */
        /* A non-absolute argv[0].  Map the persona's real bash (spawned as the
         * binstore name "alpine-bash") to its canonical path so /proc/self/exe
         * is coherent with /proc/self/maps; any other non-absolute argv[0] in the
         * honey context is a busybox multi-call applet → /bin/busybox (exactly
         * what a real Alpine reports for ls/cat/… after resolving the symlink). */
        if (strstr(e, "bash")) return "/bin/bash";
        return "/bin/busybox";
    }
    return "/bin/busybox";   /* a no-exe context (early boot / kthread) */
}

int truth_proc_cmdline(const struct lucas_state *st, char *out, size_t cap)
{
    if (!out || cap == 0) return 0;
    const char *exe = truth_proc_exe(st);
    size_t n = 0;
    while (exe[n] && n + 1 < cap) { out[n] = exe[n]; n++; }
    out[n++] = '\0';   /* argv[0] is NUL-terminated · /proc/<pid>/cmdline format */
    return (int)n;
}

const char *truth_proc_cwd(const struct lucas_state *st)
{
    if (st && st->cwd[0]) return st->cwd;
    return "/";
}

/* ── fd table ─────────────────────────────────────────────────────────────── */

int truth_proc_fd_max(void) { return LUCAS_MAX_FDS; }

int truth_proc_fd_open(const struct lucas_state *st, int fd)
{
    if (!st || fd < 0 || fd >= LUCAS_MAX_FDS) return 0;
    return st->fds[fd].kind != LUCAS_FD_INVALID;
}

int truth_proc_fd_target(const struct lucas_state *st, int fd, char *out, size_t cap)
{
    if (!truth_proc_fd_open(st, fd) || !out || cap == 0) return -1;
    const lucas_fd_t *e = &st->fds[fd];
    /* A stable-ish synthetic inode per fd (real /proc shows socket:[N]/pipe:[N]
     * with the kernel inode; we don't expose seL4 identity, so derive it). */
    unsigned long ino = 30000UL + (unsigned long)fd;
    int n;
    switch (e->kind) {
    case LUCAS_FD_VFS:
        n = snprintf(out, cap, "%s", e->fd_path[0] ? e->fd_path : "/");
        break;
    case LUCAS_FD_SOCKET:
        n = snprintf(out, cap, "socket:[%lu]", ino);
        break;
    case LUCAS_FD_PIPE_READ:
    case LUCAS_FD_PIPE_WRITE:
        n = snprintf(out, cap, "pipe:[%lu]", ino);
        break;
    case LUCAS_FD_EPOLL:
        n = snprintf(out, cap, "anon_inode:[eventpoll]");
        break;
    case LUCAS_FD_FB:
        n = snprintf(out, cap, "/dev/fb0");
        break;
    case LUCAS_FD_NULL:
        n = snprintf(out, cap, "/dev/null");
        break;
    case LUCAS_FD_URANDOM:
        n = snprintf(out, cap, "/dev/urandom");
        break;
    case LUCAS_FD_STDIO:
    default:
        n = snprintf(out, cap, "/dev/pts/0");   /* the console tty */
        break;
    }
    return (n < 0) ? -1 : n;
}

/* ── process identity / accounting ────────────────────────────────────────── */

const char *truth_proc_comm(const struct lucas_state *st, char *out, size_t cap)
{
    if (!out || cap == 0) return out;
    const char *exe = truth_proc_exe(st);            /* absolute, persona-mapped */
    const char *base = exe;
    for (const char *p = exe; *p; ++p) if (*p == '/') base = p + 1;
    size_t i = 0;
    while (base[i] && i + 1 < cap) { out[i] = base[i]; i++; }
    out[i] = '\0';
    return out;
}

void truth_get_process(const struct lucas_state *st, struct truth_process *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->pid     = st ? (int)st->display_pid : 1;
    out->ppid    = 1;            /* the honey shell's parent is the sshd persona (pid 1 default) */
    out->uid     = 0;            /* the honey session logs in as root */
    out->gid     = 0;
    out->state   = 'R';
    out->threads = 1;

    /* VM accounting from REAL state: a base text/data span + the live heap + the
     * live mmap region (page-granular numbers a prober reads as plausible). */
    unsigned long heap = (st && st->brk_top > st->brk_base)
                           ? (unsigned long)(st->brk_top - st->brk_base) : 0;
    unsigned long mmap = (st && st->mmap_high_water > 0x40000000UL)
                           ? (unsigned long)(st->mmap_high_water - 0x40000000UL) : 0;
    out->vm_size_kb = (2048UL * 1024 + heap + mmap) / 1024;   /* ~2 MiB base + heap + mmap */
    out->vm_rss_kb  = out->vm_size_kb / 2;
    out->vm_stk_kb  = 132;

    int n = 0, fmax = truth_proc_fd_max();
    for (int fd = 0; fd < fmax; ++fd) if (truth_proc_fd_open(st, fd)) ++n;
    out->fd_count = n;
}

/* ── live process enumeration ─────────────────────────────────────────────── */

int truth_display_pid(struct lucas_state *st)
{
    if (!st) return 1;
    if (st->display_pid == 0)
        st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid);
    return (int)st->display_pid;
}

int truth_list_processes(struct truth_proc_entry *out, int max)
{
    if (!out || max <= 0) return 0;
    int count = 0;
    /* Walk the procd table (bounded scan · sparse slots tolerated).  Each valid
     * slot is a live sotbox; the guest-visible pid is the deterministic
     * sotos_pid_display() of its synthetic_pid (same map getpid uses). */
    for (uint32_t slot = 1; slot < 256 && count < max; ++slot) {
        lucas_proc_view_t v;
        if (lucas_proct_load(slot, &v) != 0 || !v.valid || v.synthetic_pid == 0)
            continue;
        struct truth_proc_entry *e = &out[count++];
        e->pid   = (int)sotos_pid_display(v.synthetic_pid);
        e->ppid  = v.ppid ? (int)sotos_pid_display(v.ppid) : 1;
        /* proc_state_t → R/S/D/Z (default S like a parked sotbox). */
        e->state = (v.state == 0) ? 'R' : 'S';
        e->tier  = v.tier;
        /* ABI v2 · carry comm + owning SSH session (Task 5 does the filtering). */
        memcpy(e->comm, v.comm, sizeof(e->comm));
        e->comm[sizeof(e->comm) - 1] = '\0';
        e->cow_session = v.cow_session;
    }
    return count;
}

int truth_list_session_processes(unsigned cow_session,
                                 struct truth_proc_entry *out, int max)
{
    if (!out || max <= 0) return 0;
    if (cow_session == 0) return 0;   /* operator / non-session → pure synth persona */
    int count = 0;
    for (uint32_t slot = 1; slot < 256 && count < max; ++slot) {
        lucas_proc_view_t v;
        if (lucas_proct_load(slot, &v) != 0 || !v.valid || v.synthetic_pid == 0)
            continue;
        if (v.cow_session != cow_session)
            continue;
        struct truth_proc_entry *e = &out[count++];
        e->pid   = (int)sotos_pid_display(v.synthetic_pid);
        e->ppid  = v.ppid ? (int)sotos_pid_display(v.ppid) : 1;
        e->state = (v.state == 0) ? 'R' : 'S';
        e->tier  = v.tier;
        memcpy(e->comm, v.comm, sizeof(e->comm));
        e->comm[sizeof(e->comm) - 1] = '\0';
        e->cow_session = v.cow_session;
    }
    return count;
}
