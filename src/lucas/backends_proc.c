/*
 * sotOs · LUCAS L2 · proc VFS backend.
 *
 * Synthesizes per-pid entries under /proc. In L2 we only support a
 * handful: /proc/self/cmdline, /proc/self/exe (symlink), /proc/self
 * directory listing. More entries arrive in L3 with the orchestrator.
 *
 * IMPORTANT (per spec Section 7.5): /proc/self/maps will be synthesized
 * to look like a credible Linux process map · NOT exposing seL4 frames.
 * That's L3 work; L2 returns ENOENT for /proc/self/maps so we don't
 * fingerprint sotOs accidentally.
 */

#include <lucas/vfs.h>
#include <lucas/clock.h>
#include "state.h"
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sotos/pidrand.h>   /* P3 · seed st->display_pid for /self/status Pid */
#include <lucas/truth.h>     /* truth-core · single source of truth (exe/cmdline/cwd) */
#include <libsot/sot_session.h>  /* libsot · operator session view (sotctl sessions) */

/* Per-companion state pointer · so the backend can read st->synthetic_pid. */
typedef struct {
    struct lucas_state *st;
} proc_state_t;

/* procfs-live-M1 · the proc backend is a SINGLETON (proc_state_singleton), so
 * ps->st is a single fixed sotbox — reading /proc/self/{maps,status} off it
 * returned the SAME process for every caller (the dominant tell: /proc/self
 * must reflect the PROCESS THAT OPENED IT).  The central dispatch bracket sets
 * the thread-local caller around every syscall, so at the proc open op the
 * caller IS the opener.  Prefer it; fall back to ps->st only if unset. */
extern struct lucas_state *lucas_get_current_caller(void);
static inline struct lucas_state *proc_caller_st(proc_state_t *ps) {
    struct lucas_state *c = lucas_get_current_caller();
    return c ? c : (ps ? ps->st : (struct lucas_state *)0);
}

typedef struct {
    int   kind;        /* 1 = cmdline, 2 = exe (symlink target), 3 = self dir, 4 = maps, 5 = status */
    int64_t inode;
    int   pid;          /* synthetic-process dir handle · the pid being listed */
    char  buf[4096];   /* holds full /proc/cpuinfo + /proc/meminfo (recon fidelity) */
    size_t buf_len;
    size_t cursor_dir;  /* getdents iterator */
} proc_handle_t;

#define LUCAS_PROC_MAX_OPEN 8
static proc_handle_t proc_pool[LUCAS_PROC_MAX_OPEN];
static proc_state_t  proc_state_singleton;

/* /proc/self/ direct children we expose for getdents. */
static const struct { const char *name; uint8_t type; } proc_self_children[] = {
    { "cmdline", LX_DT_REG },
    { "exe",     LX_DT_LNK },
    { "status",  LX_DT_REG },
    { "stat",    LX_DT_REG },   /* procfs-live · real comm/state/ppid (was '(sotsh)') */
    { "comm",    LX_DT_REG },   /* procfs-live · the real comm (was ENOENT) */
    { "maps",    LX_DT_REG },
    { "cgroup",  LX_DT_REG },   /* procfs-live · '0::/' (was ENOENT) */
    { "cwd",     LX_DT_LNK },
    { "fd",      LX_DT_DIR },
};
#define PROC_SELF_CHILDREN_N (sizeof(proc_self_children)/sizeof(proc_self_children[0]))

/* Synthetic process table · persona DEPTH for the prod-db-01 database server.
 * An attacker who lands and runs `ps aux`/`ps -ef` must see a believable
 * production box — init, kernel threads, sshd, a PostgreSQL cluster, cron/syslog
 * — not an empty list.  Each entry materialises /proc/<pid>/{stat,cmdline,status,
 * comm}; the root /proc getdents enumerates the pids.  cmdline="" = kernel thread
 * (ps shows [comm]).  uid 70 = postgres (added to canary_passwd for coherence). */
typedef struct {
    int          pid, ppid;
    unsigned     uid;
    char         state;      /* R/S/D/Z */
    const char  *comm;       /* short name · <=15 chars (kernel TASK_COMM_LEN) */
    const char  *cmdline;    /* full argv ("" → kernel thread → ps prints [comm]) */
} synth_proc_t;

static const synth_proc_t g_synth_procs[] = {
    {    1,    0,  0, 'S', "init",         "/sbin/init" },
    {    2,    0,  0, 'S', "kthreadd",     "" },
    {    3,    2,  0, 'S', "rcu_gp",       "" },
    {    9,    2,  0, 'S', "ksoftirqd/0",  "" },
    {   10,    2,  0, 'S', "rcu_sched",    "" },
    {   11,    2,  0, 'S', "migration/0",  "" },
    {  398,    1,  0, 'S', "syslogd",      "/sbin/syslogd -t" },
    {  412,    1,  0, 'S', "crond",        "/usr/sbin/crond -f -c /etc/crontabs" },
    {  455,    1,  0, 'S', "sshd",         "/usr/sbin/sshd -D" },
    {  503,    1, 70, 'S', "postgres",     "/usr/bin/postgres -D /var/lib/postgresql/16/data" },
    {  511,  503, 70, 'S', "postgres",     "postgres: checkpointer" },
    {  512,  503, 70, 'S', "postgres",     "postgres: background writer" },
    {  513,  503, 70, 'S', "postgres",     "postgres: walwriter" },
    {  514,  503, 70, 'S', "postgres",     "postgres: autovacuum launcher" },
    {  515,  503, 70, 'S', "postgres",     "postgres: logical replication launcher" },
    {  847,  455,  0, 'S', "sshd",         "sshd: root@pts/0" },
    /* persona-reconciliation (Task 5) · the synthetic shell `851 sh "-sh"` under
     * 847 was REMOVED.  Once the procfs renderer also lists the attacker's OWN
     * SESSION's real live procs (their bash + fork children, named, from procd),
     * keeping a fake "sh" under the same sshd that serves the session would
     * double-show ONE login as two shells (fake sh + real bash) — incoherent.
     * 847 ("sshd: root@pts/0") stays as the sshd that accepted the session; the
     * REAL session bash IS the session's one shell.  The real bash's apparent
     * parent comes from procd (its ppid display pid), not relinked to 847 — the
     * key invariant is one coherent shell per session, which we hold without the
     * fake entry. */
};
#define SYNTH_PROC_N (sizeof(g_synth_procs)/sizeof(g_synth_procs[0]))

static const synth_proc_t *synth_proc_by_pid(int pid) {
    for (size_t i = 0; i < SYNTH_PROC_N; ++i)
        if (g_synth_procs[i].pid == pid) return &g_synth_procs[i];
    return NULL;
}

/* procfs-live (Task 5) · the THIRD /proc/<pid> case, between proc_route_own_pid
 * (the caller's OWN pid → /self) and the synth table.  Looks up `pid` among the
 * CALLER's-session live procs (cow_session match), so /proc/<other-session-pid>/
 * {stat,status,comm,cmdline} renders the REAL pid/ppid/state/comm of the
 * attacker's OWN bash + fork children.  Returns 1 + fills *out on a match.
 * exe/maps/fd for these are NOT available (that data lives on the other
 * sotbox's lucas_state, not in procd) → those paths ENOENT (acceptable). */
static int proc_session_live_by_pid(void *backend, int pid,
                                    struct truth_proc_entry *out) {
    struct lucas_state *st = proc_caller_st((proc_state_t *)backend);
    if (!st || st->cow_session == 0) return 0;
    /* the caller's OWN pid routes to /self elsewhere — never claim it here. */
    if (pid == truth_display_pid(st)) return 0;
    struct truth_proc_entry pe[64];
    int n = truth_list_session_processes(st->cow_session, pe, 64);
    for (int i = 0; i < n; ++i) {
        if (pe[i].pid == pid) { *out = pe[i]; return 1; }
    }
    return 0;
}

/* Listening/established sockets owned by each process · the inodes match
 * /proc/net/tcp, so `netstat -tlnp` maps the port to "PID/Program" by reading
 * /proc/<pid>/fd/<n> → "socket:[<inode>]" (the real kernel mechanism). */
typedef struct { int pid, fd; long inode; } proc_sock_t;
static const proc_sock_t g_proc_socks[] = {
    { 455, 3, 14501 },   /* sshd · 0.0.0.0:22 listener */
    { 455, 4, 14502 },   /* sshd · :::22 (tcp6) listener */
    { 503, 5, 14622 },   /* postgres · 0.0.0.0:5432 */
    { 503, 6, 14623 },   /* postgres · 127.0.0.1:5432 */
    { 847, 3, 31204 },   /* sshd: root@pts/0 · established */
};
#define PROC_SOCK_N (sizeof(g_proc_socks)/sizeof(g_proc_socks[0]))

/* Parse a "/<pid>" or "/<pid>/<file>" proc suffix.  On match, *pid is the number
 * and *rest points at the "/<file>" tail ("" for the bare dir).  Returns 1 if the
 * leading component is all-digits, else 0. */
static int proc_parse_pid(const char *path, int *pid, const char **rest) {
    if (path[0] != '/' || path[1] < '0' || path[1] > '9') return 0;
    int n = 0; const char *p = path + 1;
    while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); ++p; }
    if (*p != '\0' && *p != '/') return 0;   /* e.g. "/1foo" is not a pid */
    *pid = n; *rest = p;
    return 1;
}

static int alloc_handle(int kind, proc_handle_t **out) {
    for (size_t i = 0; i < LUCAS_PROC_MAX_OPEN; ++i) {
        if (proc_pool[i].kind == 0) {
            proc_pool[i].kind = kind;
            proc_pool[i].cursor_dir = 0;
            proc_pool[i].buf_len = 0;
            *out = &proc_pool[i];
            return 0;
        }
    }
    return -24;
}

/* procfs-live · /proc/<own-display-pid>/* aliases /proc/self/* so the attacker's
 * OWN process is introspectable by its real pid (from getpid/$$/ps) with FULL
 * real data — the synth process table only covers the persona's fake procs, so a
 * live sotbox's own pid would otherwise ENOENT (a tell).  Rewrites into `buf`
 * (e.g. "/<mypid>/status" → "/self/status"); other pids pass through unchanged. */
static const char *proc_route_own_pid(void *backend, const char *path,
                                      char *buf, size_t cap) {
    int pid; const char *rest;
    if (!proc_parse_pid(path, &pid, &rest)) return path;
    struct lucas_state *st = proc_caller_st((proc_state_t *)backend);
    if (!st || pid != truth_display_pid(st)) return path;
    snprintf(buf, cap, "/self%s", rest);
    return buf;
}

static int op_open(void *backend, const char *path, int flags, uint32_t mode,
                    void **out_handle) {
    (void)flags; (void)mode;
    proc_handle_t *h = NULL;
    char rb[160]; path = proc_route_own_pid(backend, path, rb, sizeof(rb));

    /* path is the suffix after "/proc"; e.g. "/", "/self", "/self/cmdline". */
    if (strcmp(path, "/") == 0) {
        int rc = alloc_handle(3, &h);
        if (rc) return rc;
        h->inode = 1000;
        *out_handle = h;
        return 0;
    }
    if (strcmp(path, "/self") == 0 || strcmp(path, "/self/") == 0) {
        int rc = alloc_handle(3, &h);
        if (rc) return rc;
        h->inode = 2000;
        *out_handle = h;
        return 0;
    }
    /* procfs-live · /proc/self/fd · a real dir of the CALLER's open fds (rendered
     * from truth-core at getdents time).  inode 2001 marks the fd-dir handle. */
    if (strcmp(path, "/self/fd") == 0 || strcmp(path, "/self/fd/") == 0) {
        int rc = alloc_handle(3, &h);
        if (rc) return rc;
        h->inode = 2001;
        *out_handle = h;
        return 0;
    }
    if (strcmp(path, "/self/cmdline") == 0) {
        int rc = alloc_handle(1, &h);
        if (rc) return rc;
        /* procfs-live · render /proc/self/cmdline from truth-core, keyed on the
         * REAL caller (was a hardcoded "busybox" — a tell for any other binary). */
        h->buf_len = (size_t)truth_proc_cmdline(proc_caller_st(
                         (proc_state_t *)backend), h->buf, sizeof(h->buf));
        *out_handle = h;
        return 0;
    }
    /* Synthetic process table · /proc/<pid> and /proc/<pid>/{cmdline,comm,stat,
     * status}.  Makes `ps`/`top`/`pgrep` see a believable prod-db-01 process
     * list (init · kthreads · sshd · a postgres cluster · cron/syslog) instead
     * of an empty table.  PID 1 (init → /sbin/init) is now served from here. */
    {
        int pid; const char *rest;
        if (proc_parse_pid(path, &pid, &rest)) {
            const synth_proc_t *sp = synth_proc_by_pid(pid);
            if (!sp) {
                /* procfs-live (Task 5) · NOT synth → is it one of the caller's
                 * OWN session's live procs?  Render stat/status/comm/cmdline
                 * from procd; exe/cwd/root/fd are NOT available → ENOENT. */
                struct truth_proc_entry le;
                if (proc_session_live_by_pid(backend, pid, &le)) {
                    if (rest[0] == '\0') {            /* the /proc/<pid> directory */
                        int rc = alloc_handle(3, &h); if (rc) return rc;
                        h->inode = 5000 + pid; h->pid = pid;
                        *out_handle = h; return 0;
                    }
                    if (strcmp(rest, "/cwd") == 0 || strcmp(rest, "/exe") == 0 ||
                        strcmp(rest, "/root") == 0 || strcmp(rest, "/fd") == 0 ||
                        strncmp(rest, "/fd/", 4) == 0)
                        return -2;                   /* not available for other procs */
                    int rc = alloc_handle(1, &h); if (rc) return rc;
                    if (strcmp(rest, "/cmdline") == 0) {
                        /* argv unavailable for other procs → comm as a single arg. */
                        int k = snprintf(h->buf, sizeof(h->buf), "%s", le.comm);
                        h->buf[(k > 0 && k < (int)sizeof(h->buf)) ? k : 0] = '\0';
                        h->buf_len = (k > 0) ? (size_t)k + 1 : 0;
                    } else if (strcmp(rest, "/comm") == 0) {
                        int k = snprintf(h->buf, sizeof(h->buf), "%s\n", le.comm);
                        h->buf_len = (k > 0) ? (size_t)k : 0;
                    } else if (strcmp(rest, "/stat") == 0) {
                        /* busybox ps parses: pid (comm) state ppid ...; pad the
                         * remaining ~20 fields with 0s (plausible constants). */
                        int k = snprintf(h->buf, sizeof(h->buf),
                            "%d (%s) %c %d %d %d 0 -1 4194304 100 0 0 0 12 8 0 0 "
                            "20 0 1 0 %d 5242880 612 18446744073709551615 4194304 "
                            "5242880 140737488347136 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n",
                            le.pid, le.comm, le.state, le.ppid,
                            le.pid, le.pid, 1000 + le.pid * 7);
                        h->buf_len = (k > 0) ? (size_t)k : 0;
                    } else if (strcmp(rest, "/status") == 0) {
                        int k = snprintf(h->buf, sizeof(h->buf),
                            "Name:\t%s\nState:\t%c (%s)\nTgid:\t%d\nPid:\t%d\n"
                            "PPid:\t%d\nTracerPid:\t0\nUid:\t0\t0\t0\t0\n"
                            "Gid:\t0\t0\t0\t0\nVmRSS:\t  2048 kB\nThreads:\t1\n",
                            le.comm, le.state,
                            (le.state == 'R') ? "running" : "sleeping",
                            le.pid, le.pid, le.ppid);
                        h->buf_len = (k > 0) ? (size_t)k : 0;
                    } else {
                        h->kind = 0; return -2;
                    }
                    *out_handle = h; return 0;
                }
                return -2;  /* -ENOENT · no such (dead/foreign) pid */
            }
            if (rest[0] == '\0') {                 /* the /proc/<pid> directory */
                int rc = alloc_handle(3, &h); if (rc) return rc;
                h->inode = 5000 + pid; h->pid = pid;
                *out_handle = h; return 0;
            }
            if (strcmp(rest, "/fd") == 0) {        /* /proc/<pid>/fd · (listed empty) */
                int rc = alloc_handle(3, &h); if (rc) return rc;
                h->inode = 6000 + pid; h->pid = pid;
                *out_handle = h; return 0;
            }
            /* cwd/exe/root are symlinks · clients readlink them (op_readlink). */
            if (strcmp(rest, "/cwd") == 0 || strcmp(rest, "/exe") == 0 ||
                strcmp(rest, "/root") == 0)
                return -2;
            int rc = alloc_handle(1, &h); if (rc) return rc;
            if (strcmp(rest, "/cmdline") == 0) {
                size_t n = 0;                       /* argv · NUL-separated (kthread → 0 bytes) */
                for (const char *c = sp->cmdline; *c && n < sizeof(h->buf) - 1; ++c)
                    h->buf[n++] = (*c == ' ') ? '\0' : *c;
                if (n) h->buf[n++] = '\0';
                h->buf_len = n;
            } else if (strcmp(rest, "/comm") == 0) {
                int k = snprintf(h->buf, sizeof(h->buf), "%s\n", sp->comm);
                h->buf_len = (k > 0) ? (size_t)k : 0;
            } else if (strcmp(rest, "/stat") == 0) {
                int k = snprintf(h->buf, sizeof(h->buf),
                    "%d (%s) %c %d %d %d 0 -1 4194304 100 0 0 0 12 8 0 0 20 0 1 0 "
                    "%d 5242880 612 18446744073709551615 4194304 5242880 "
                    "140737488347136 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n",
                    sp->pid, sp->comm, sp->state, sp->ppid, sp->pid, sp->pid,
                    1000 + sp->pid * 7 /* starttime · stable */);
                h->buf_len = (k > 0) ? (size_t)k : 0;
            } else if (strcmp(rest, "/status") == 0) {
                int k = snprintf(h->buf, sizeof(h->buf),
                    "Name:\t%s\nState:\t%c (%s)\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\n"
                    "TracerPid:\t0\nUid:\t%u\t%u\t%u\t%u\nGid:\t%u\t%u\t%u\t%u\n"
                    "VmRSS:\t  %d kB\nThreads:\t1\n",
                    sp->comm, sp->state, (sp->state == 'R') ? "running" : "sleeping",
                    sp->pid, sp->pid, sp->ppid,
                    sp->uid, sp->uid, sp->uid, sp->uid,
                    sp->uid, sp->uid, sp->uid, sp->uid, 2048 + sp->pid);
                h->buf_len = (k > 0) ? (size_t)k : 0;
            } else {
                h->kind = 0; return -2;             /* unknown /proc/<pid>/<x> */
            }
            *out_handle = h; return 0;
        }
    }
    /* /self/maps · synthesize a credible Linux-format /proc/self/maps.
     * Per spec Section 7.5: never expose seL4 frame addresses. */
    if (strcmp(path, "/self/maps") == 0) {
        int rc = alloc_handle(4 /* kind=maps */, &h);
        if (rc) return rc;

        proc_state_t *ps = (proc_state_t *)backend;
        struct lucas_state *st = proc_caller_st(ps);

        char *mbuf = h->buf;
        int total = 0;
        int n;

        /* procfs-live-M1 · TEXT/DATA of the REAL running binary at its REAL load
         * base — coherent with /proc/self/exe (which already returns st->exe_path).
         * The old code hardcoded "/bin/busybox" at 0x400000 regardless of the
         * actual binary (a `cat /proc/self/maps` from bash/apk/nano said busybox —
         * the dominant analyst tell). dynamic PIE → bin_base; static → 0x400000.
         * %08lx is a MINIMUM width (expands for high dynamic bases · no truncation). */
        const char *exe = truth_proc_exe(st);   /* truth-core · coherent w/ /proc/self/exe */
        unsigned long tbase = (st && st->is_dynamic && st->bin_base)
                                ? (unsigned long)st->bin_base : 0x00400000UL;

        /* TEXT (read-execute) */
        n = snprintf(mbuf + total, sizeof(h->buf) - (size_t)total,
                     "%08lx-%08lx r-xp 00000000 08:01 1001       %s\n",
                     tbase, tbase + 0x100000UL, exe);
        total += n;

        /* DATA (read-write) */
        n = snprintf(mbuf + total, sizeof(h->buf) - (size_t)total,
                     "%08lx-%08lx rw-p 00100000 08:01 1001       %s\n",
                     tbase + 0x100000UL, tbase + 0x300000UL, exe);
        total += n;

        /* INTERP (ld-musl) · a dynamic binary maps its interpreter at interp_base.
         * Without this line a dynamic /proc/self/maps has no loader (a tell). */
        if (st && st->is_dynamic && st->interp_base) {
            const char *interp = (st->interp_path[0]) ? st->interp_path
                                                      : "/lib/ld-musl-x86_64.so.1";
            n = snprintf(mbuf + total, sizeof(h->buf) - (size_t)total,
                         "%08lx-%08lx r-xp 00000000 08:01 2002       %s\n",
                         (unsigned long)st->interp_base,
                         (unsigned long)st->interp_base + 0x40000UL, interp);
            total += n;
        }

        /* BRK / heap · only emit if brk has been grown */
        if (st && st->brk_top > st->brk_base && st->brk_base > 0) {
            n = snprintf(mbuf + total, sizeof(h->buf) - (size_t)total,
                         "%08lx-%08lx rw-p 00000000 00:00 0           [heap]\n",
                         (unsigned long)st->brk_base,
                         (unsigned long)((st->brk_top + 0xFFFUL) & ~0xFFFUL));
            total += n;
        }

        /* MMAP region · only emit if mmap has been used */
        if (st && st->mmap_high_water > 0x40000000UL) {
            n = snprintf(mbuf + total, sizeof(h->buf) - (size_t)total,
                         "%08lx-%08lx rw-p 00000000 00:00 0\n",
                         0x40000000UL,
                         (unsigned long)st->mmap_high_water);
            total += n;
        }

        /* STACK */
        if (st && st->stack_top > 0) {
            n = snprintf(mbuf + total, sizeof(h->buf) - (size_t)total,
                         "%08lx-%08lx rw-p 00000000 00:00 0           [stack]\n",
                         (unsigned long)(st->stack_top - 16 * 4096),
                         (unsigned long)((st->stack_top + 0xFFFUL) & ~0xFFFUL));
            total += n;
        } else {
            /* Fallback stack entry when st is unavailable */
            n = snprintf(mbuf + total, sizeof(h->buf) - (size_t)total,
                         "0fff0000-10000000 rw-p 00000000 00:00 0           [stack]\n");
            total += n;
        }

        /* vDSO arc · Task 4 · emit the REAL [vvar]/[vdso] span that
         * lucas_map_vdso mapped into this guest at SOTOS_VDSO_BASE (was a
         * hardcoded fake 7ffff7ffe000).  vvar is one page; vdso spans the
         * embedded vdso.so (ceil(blob/4096) pages).  Falls back to the
         * compile-time constants if a box hasn't recorded the mapping yet. */
        {
            unsigned long vvar_lo = (st && st->vvar_base)
                                    ? (unsigned long)st->vvar_base
                                    : (unsigned long)SOTOS_VDSO_BASE;
            unsigned long vdso_lo = (st && st->vdso_base)
                                    ? (unsigned long)st->vdso_base
                                    : (unsigned long)SOTOS_VDSO_EHDR;
            unsigned long code_pages = (st && st->vdso_code_pages)
                                       ? (unsigned long)st->vdso_code_pages
                                       : 2UL;
            n = snprintf(mbuf + total, sizeof(h->buf) - (size_t)total,
                         "%08lx-%08lx r--p 00000000 00:00 0           [vvar]\n"
                         "%08lx-%08lx r-xp 00000000 00:00 0           [vdso]\n",
                         vvar_lo, vvar_lo + 0x1000UL,
                         vdso_lo, vdso_lo + code_pages * 0x1000UL);
            total += n;
        }

        h->buf_len = (size_t)total;
        *out_handle = h;
        printf("[proc_vfs] open /self/maps · synthesized %d bytes\n", total);
        return 0;
    }

    /* /self/status · synthesize a credible Linux-format /proc/self/status.
     * P3 anti-debug fidelity: TracerPid:0 (untraced) + Pid == display_pid so a
     * prober comparing status-Pid to getpid() sees a consistent identity. */
    if (strcmp(path, "/self/status") == 0) {
        int rc = alloc_handle(5 /* kind=status */, &h);
        if (rc) return rc;

        proc_state_t *ps = (proc_state_t *)backend;
        struct lucas_state *st = proc_caller_st(ps);

        /* Mirror getpid's lazy display_pid seeding so status-Pid == getpid(). */
        if (st && st->display_pid == 0)
            st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid);

        /* procfs-live · render /proc/self/status from truth-core (the REAL caller).
         * Was hardcoded Name:sotsh / PPid:1 / Uid:0 / VmRSS:2048 for everyone — a
         * tell (Name contradicted the binary; fields were static).  Now Name =
         * the real comm, mem/threads/fd-count from real accounting. */
        struct truth_process tp;
        truth_get_process(st, &tp);
        char comm[32]; truth_proc_comm(st, comm, sizeof(comm));

        int total = snprintf(h->buf, sizeof(h->buf),
                     "Name:\t%s\n"
                     "Umask:\t0022\n"
                     "State:\t%c (running)\n"
                     "Tgid:\t%d\n"
                     "Ngid:\t0\n"
                     "Pid:\t%d\n"
                     "PPid:\t%d\n"
                     "TracerPid:\t0\n"
                     "Uid:\t%u\t%u\t%u\t%u\n"
                     "Gid:\t%u\t%u\t%u\t%u\n"
                     "FDSize:\t64\n"
                     "Groups:\t%u \n"
                     "VmPeak:\t%8lu kB\n"
                     "VmSize:\t%8lu kB\n"
                     "VmRSS:\t%8lu kB\n"
                     "VmStk:\t%8lu kB\n"
                     "Threads:\t%d\n"
                     "SigQ:\t0/7000\n"
                     "SigPnd:\t0000000000000000\n"
                     "Seccomp:\t0\n",
                     comm, tp.state, tp.pid, tp.pid, tp.ppid,
                     tp.uid, tp.uid, tp.uid, tp.uid,
                     tp.gid, tp.gid, tp.gid, tp.gid, tp.gid,
                     tp.vm_size_kb, tp.vm_size_kb, tp.vm_rss_kb, tp.vm_stk_kb,
                     tp.threads);
        h->buf_len = (total > 0) ? (size_t)total : 0;
        *out_handle = h;
        printf("[proc_vfs] open /self/status · truth-core Name=%s Pid=%d fds=%d (%d bytes)\n",
               comm, tp.pid, tp.fd_count, total);
        return 0;
    }

    /* Tier-4 · static /proc files · consistent Ubuntu 20.04 / 5.15 response_profile.
     * (cpuinfo/meminfo/version/uptime/loadavg/mounts/net/tcp are served by the
     * static canary backend; we add only the paths recon tools also expect.) */
    {
        static const struct { const char *p; const char *c; } T[] = {
            /* Recon paths an attacker reads FIRST · served here so the GUEST
             * /proc surface is complete (these were previously unreachable —
             * the /proc mount shadowed the static-backend copies).  Coherent
             * Alpine 3.20 + linux-lts 6.6.30 identity throughout. */
            { "/version",
              "Linux version 6.6.30-0-lts (buildozer@build-3-20-x86_64) (gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309, GNU ld (GNU Binutils) 2.42) #1-Alpine SMP PREEMPT_DYNAMIC 2024-05-22 10:00:00\n" },
            { "/cpuinfo",
              "processor\t: 0\n"
              "vendor_id\t: GenuineIntel\n"
              "cpu family\t: 6\n"
              "model\t\t: 85\n"
              "model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
              "stepping\t: 7\n"
              "microcode\t: 0x1\n"
              "cpu MHz\t\t: 2500.000\n"
              "cache size\t: 36608 KB\n"
              "physical id\t: 0\n"
              "siblings\t: 1\n"
              "core id\t\t: 0\n"
              "cpu cores\t: 1\n"
              "apicid\t\t: 0\n"
              "initial apicid\t: 0\n"
              "fpu\t\t: yes\n"
              "fpu_exception\t: yes\n"
              "cpuid level\t: 13\n"
              "wp\t\t: yes\n"
              "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves ida arat pku ospke\n"
              "bugs\t\t: spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit mmio_stale_data retbleed\n"
              "bogomips\t: 5000.00\n"
              "clflush size\t: 64\n"
              "cache_alignment\t: 64\n"
              "address sizes\t: 46 bits physical, 48 bits virtual\n"
              "power management:\n\n" },
            { "/meminfo",
              "MemTotal:        2048392 kB\nMemFree:         1373820 kB\nMemAvailable:    1716544 kB\n"
              "Buffers:           24576 kB\nCached:           412160 kB\nSwapCached:            0 kB\n"
              "Active:           312448 kB\nInactive:         268032 kB\nActive(anon):     144384 kB\n"
              "Inactive(anon):      512 kB\nActive(file):     168064 kB\nInactive(file):   267520 kB\n"
              "Unevictable:           0 kB\nMlocked:               0 kB\nSwapTotal:             0 kB\n"
              "SwapFree:              0 kB\nDirty:                 8 kB\nWriteback:             0 kB\n"
              "AnonPages:        143872 kB\nMapped:            98304 kB\nShmem:               512 kB\n"
              "KReclaimable:      28672 kB\nSlab:              57344 kB\nSReclaimable:      28672 kB\n"
              "SUnreclaim:        28672 kB\nKernelStack:        4096 kB\nPageTables:         6144 kB\n"
              "NFS_Unstable:          0 kB\nBounce:                0 kB\nWritebackTmp:          0 kB\n"
              "CommitLimit:     1024196 kB\nCommitted_AS:     524288 kB\nVmallocTotal:   34359738367 kB\n"
              "VmallocUsed:       16384 kB\nVmallocChunk:          0 kB\nPercpu:             1024 kB\n"
              "HugePages_Total:       0\nHugePages_Free:        0\nHugePages_Rsvd:        0\n"
              "HugePages_Surp:        0\nHugepagesize:       2048 kB\nHugetlb:               0 kB\n"
              "DirectMap4k:       65536 kB\nDirectMap2M:     2031616 kB\n" },
            { "/uptime",  "184273.45 1472918.32\n" },
            { "/loadavg", "0.08 0.03 0.01 1/142 28471\n" },
            { "/mounts",
              "/dev/vda3 / ext4 rw,relatime 0 0\n"
              "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
              "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
              "devtmpfs /dev devtmpfs rw,nosuid,relatime,size=1010048k,nr_inodes=252512,mode=755 0 0\n"
              "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
              "tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0\n"
              "devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620 0 0\n"
              "/dev/vda1 /boot ext4 rw,relatime 0 0\n" },
            { "/cmdline",
              "BOOT_IMAGE=vmlinuz-lts root=UUID=4f8d2a1c-9b3e-4c7a-8f1d-2e6b9a0c5d3f ro modules=sd-mod,usb-storage,ext4 quiet rootfstype=ext4\n" },
            { "/filesystems",
              "nodev\tsysfs\nnodev\tproc\nnodev\ttmpfs\nnodev\tdevtmpfs\nnodev\tcgroup\nnodev\tmqueue\n\text3\n\text4\n\txfs\n\tvfat\n" },
            { "/stat",
              "cpu  294821 4123 88210 19384726 5821 0 1942 0 0 0\n"
              "cpu0 294821 4123 88210 19384726 5821 0 1942 0 0 0\n"
              "intr 38271654\nctxt 91827364\nbtime 1781329727\nprocesses 28471\n"
              "procs_running 2\nprocs_blocked 0\n" },
            { "/sys/kernel/osrelease",        "6.6.30-0-lts\n" },
            { "/sys/kernel/ostype",           "Linux\n" },
            { "/sys/kernel/hostname",         "alpine-host\n" },
            { "/sys/kernel/version",          "#1-Alpine SMP PREEMPT_DYNAMIC 2024-05-22 10:00:00\n" },
            { "/sys/kernel/random/boot_id",   "4f8d2a1c-9b3e-4c7a-8f1d-2e6b9a0c5d3f\n" },
            { "/sys/kernel/random/uuid",      "7c2e9f10-3a4b-4d5e-9f80-1a2b3c4d5e6f\n" },
            { "/sys/kernel/pid_max",          "4194304\n" },
            /* recon-fidelity · the checks an intruder runs to spot a rootkit /
             * tampered kernel / network posture (all response_profile-consistent: a clean
             * Ubuntu 20.04 / 5.15 database server). */
            { "/sys/kernel/tainted",          "0\n" },   /* clean kernel · no out-of-tree modules */
            { "/sys/kernel/yama/ptrace_scope","1\n" },   /* restricted ptrace · matches invisible=YES */
            { "/sys/net/ipv4/ip_forward",     "0\n" },
            { "/sys/vm/swappiness",           "60\n" },
            { "/sys/vm/overcommit_memory",    "0\n" },
            { "/sys/vm/mmap_min_addr",        "65536\n" },
            { "/modules",
              "nf_tables 245760 1 - Live 0x0000000000000000\n"
              "ip_tables 32768 2 iptable_filter - Live 0x0000000000000000\n"
              "ext4 921600 1 - Live 0x0000000000000000\n"
              "virtio_net 61440 0 - Live 0x0000000000000000\n"
              "virtio_blk 20480 2 - Live 0x0000000000000000\n"
              "crc32c_intel 24576 0 - Live 0x0000000000000000\n" },
            { "/swaps",
              "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
              "/swap.img\t\t\t\tfile\t\t2097148\t\t0\t\t-2\n" },
            { "/diskstats",
              " 254       0 vda 128934 0 8472310 41203 88210 0 6418240 28471 0 38271 69674 0 0 0 0 0 0\n"
              " 254       1 vda1 128400 0 8460120 40980 88100 0 6418240 28400 0 38100 69380 0 0 0 0 0 0\n" },
            { "/net/route",
              "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
              "eth0\t00000000\t0102000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
              "eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" },
            { "/net/dev",
              "Inter-|   Receive                                                |  Transmit\n"
              " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
              "    lo: 1843920    8472    0    0    0     0          0         0  1843920    8472    0    0    0     0       0          0\n"
              "  eth0:284719283  381726    0    0    0     0          0         0 91827364  284719    0    0    0     0       0          0\n" },
            { "/net/udp",
              "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
              "    0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 18421\n" },
            /* /net/tcp · persona-coherent listeners (sshd :22 uid0, postgres :5432
             * uid70 on all + loopback) and the attacker's established SSH (st 01).
             * Hex local_address = LE-IP:port; st 0A=LISTEN, 01=ESTABLISHED. */
            { "/net/tcp",
              "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
              "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 14501 1 0000000000000000 100 0 0 10 0\n"
              "   1: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000    70        0 14622 1 0000000000000000 100 0 0 10 0\n"
              "   2: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000    70        0 14623 1 0000000000000000 100 0 0 10 0\n"
              "   3: 0F02000A:0016 0202000A:D54E 01 00000000:00000000 02:000A2F38 00000000     0        0 31204 4 0000000000000000 20 4 30 10 -1\n" },
            { "/net/tcp6",
              "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
              "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 14502 1 0000000000000000 100 0 0 10 0\n" },
            { "/key-users", "    0:    12 11/11 8/1000000 142/25000000\n" },
        };
        /* /sys/kernel/hostname · coherent with uname nodename + /etc/hostname
         * per tier (Tier-2 canary = prod-db-01, compat guests = alpine-host)
         * so `uname -n` vs /sys/kernel/hostname never diverges. */
        if (strcmp(path, "/sys/kernel/hostname") == 0) {
            proc_state_t *psh = (proc_state_t *)backend;
            struct lucas_state *sth = psh ? psh->st : NULL;
            int rc = alloc_handle(1, &h);
            if (rc) return rc;
            const char *hn = (sth && sth->tier == 2) ? "prod-db-01\n" : "alpine-host\n";
            size_t l = strlen(hn);
            memcpy(h->buf, hn, l);
            h->buf_len = l;
            *out_handle = h;
            return 0;
        }
        for (size_t i = 0; i < sizeof(T)/sizeof(T[0]); ++i) {
            if (strcmp(path, T[i].p) == 0) {
                int rc = alloc_handle(1, &h);
                if (rc) return rc;
                size_t l = strlen(T[i].c);
                if (l > sizeof(h->buf)) l = sizeof(h->buf);
                memcpy(h->buf, T[i].c, l);
                h->buf_len = l;
                *out_handle = h;
                return 0;
            }
        }
    }

    /* /self/environ · NUL-separated · attackers read it for secrets. */
    if (strcmp(path, "/self/environ") == 0) {
        static const char env[] =
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0"
            "TERM=xterm\0HOME=/root\0USER=root\0LOGNAME=root\0SHELL=/bin/bash\0PWD=/root\0";
        int rc = alloc_handle(1, &h);
        if (rc) return rc;
        memcpy(h->buf, env, sizeof(env));
        h->buf_len = sizeof(env);
        *out_handle = h;
        return 0;
    }

    /* /self/stat + /self/statm · ps/htop parse these. */
    if (strcmp(path, "/self/stat") == 0) {
        proc_state_t *ps = (proc_state_t *)backend;
        struct lucas_state *st = proc_caller_st(ps);
        if (st && st->display_pid == 0)
            st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid);
        /* procfs-live · render fields 2/3/4 (comm/state/ppid) from truth-core (the
         * REAL caller).  Was hardcoded '(sotsh) R 1' for everyone — `cat
         * /proc/self/stat` showing the literal honeypot name 'sotsh' was a glaring
         * tell; now field 2 is the real comm (busybox/bash/…). */
        struct truth_process tp; truth_get_process(st, &tp);
        char comm[32]; truth_proc_comm(st, comm, sizeof(comm));
        uint32_t pid = (tp.pid > 0) ? (uint32_t)tp.pid : 1;
        int rc = alloc_handle(1, &h);
        if (rc) return rc;
        int n = snprintf(h->buf, sizeof(h->buf),
            "%u (%s) %c %d %u %u 34816 -1 4194304 512 0 0 0 12 8 0 0 "
            "20 0 %d 0 1000 5242880 %lu 18446744073709551615 4194304 "
            "5242880 140737488347136 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n",
            pid, comm, tp.state, tp.ppid, pid, pid,
            tp.threads > 0 ? tp.threads : 1, tp.vm_rss_kb);
        h->buf_len = (n > 0) ? (size_t)n : 0;
        *out_handle = h;
        return 0;
    }
    /* /self/comm · the REAL caller's comm + newline (was ENOENT — a missing
     * standard file; a recon `cat /proc/self/comm` failed where real Linux works). */
    if (strcmp(path, "/self/comm") == 0) {
        proc_state_t *ps = (proc_state_t *)backend;
        struct lucas_state *st = proc_caller_st(ps);
        char comm[32]; truth_proc_comm(st, comm, sizeof(comm));
        int rc = alloc_handle(1, &h);
        if (rc) return rc;
        int n = snprintf(h->buf, sizeof(h->buf), "%s\n", comm);
        h->buf_len = (n > 0) ? (size_t)n : 0;
        *out_handle = h;
        return 0;
    }
    /* /self/cgroup · a believable single cgroup-v2 line (was ENOENT).  Coherent
     * with a non-containerised host: the unified hierarchy at the root scope. */
    if (strcmp(path, "/self/cgroup") == 0) {
        int rc = alloc_handle(1, &h);
        if (rc) return rc;
        const char s[] = "0::/\n";
        memcpy(h->buf, s, sizeof(s));
        h->buf_len = sizeof(s) - 1;
        *out_handle = h;
        return 0;
    }
    if (strcmp(path, "/self/statm") == 0) {
        int rc = alloc_handle(1, &h);
        if (rc) return rc;
        const char s[] = "1280 612 110 5 0 60 0\n";
        memcpy(h->buf, s, sizeof(s));
        h->buf_len = sizeof(s) - 1;
        *out_handle = h;
        return 0;
    }

    /* /self/exe is a symlink · client should call readlink, not open. */
    return -2;  /* -ENOENT */
}

static int op_close(void *backend, void *handle) {
    (void)backend;
    proc_handle_t *h = handle;
    if (!h) return -9;
    h->kind = 0;
    return 0;
}

static int64_t op_read(void *backend, void *handle, void *buf,
                        size_t count, int64_t cursor) {
    (void)backend;
    proc_handle_t *h = handle;
    if (!h) return -9;  /* -EBADF */
    if (h->kind != 1 && h->kind != 4 && h->kind != 5) return -9;  /* only cmdline/maps/status support read */
    if (cursor >= (int64_t)h->buf_len) return 0;
    size_t avail = h->buf_len - (size_t)cursor;
    size_t to_copy = count < avail ? count : avail;
    memcpy(buf, h->buf + cursor, to_copy);
    return (int64_t)to_copy;
}

static int op_stat(void *backend, const char *path, struct lx_stat *out) {
    char rb[160]; path = proc_route_own_pid(backend, path, rb, sizeof(rb));
    memset(out, 0, sizeof(*out));
    /* clock-fidelity · synthetic /proc nodes carry the wall clock (not 1970) so
     * `ls -la /` doesn't show "Jan  1  1970 proc".  Set before the field stores
     * below (none of which touch the time fields). */
    { int64_t s, n; lucas_now_realtime(&s, &n); (void)n;
      out->st_mtime = (uint64_t)s; out->st_atime = (uint64_t)s; out->st_ctime = (uint64_t)s; }
    if (strcmp(path, "/") == 0 || strcmp(path, "/self") == 0) {
        out->st_mode    = LX_S_IFDIR | 0555;
        out->st_nlink   = 2;
        out->st_blksize = 4096;
        return 0;
    }
    /* Synthetic process · /proc/<pid> dir carries the process's OWNER uid (busybox
     * `ps` reads the dir owner for the USER column); its files are REG. */
    {
        int pid; const char *rest;
        if (proc_parse_pid(path, &pid, &rest)) {
            const synth_proc_t *sp = synth_proc_by_pid(pid);
            if (!sp) {
                /* procfs-live (Task 5) · stat for the caller's OWN session live
                 * procs: /proc/<pid> = DIR, the REG files = REG.  exe/cwd/root/fd
                 * are not exposed (open ENOENTs them) → stat ENOENT too. */
                struct truth_proc_entry le;
                if (!proc_session_live_by_pid(backend, pid, &le)) return -2;
                out->st_uid = 0; out->st_gid = 0;
                out->st_blksize = 4096;
                if (rest[0] == '\0') {               /* the /proc/<pid> directory */
                    out->st_mode = LX_S_IFDIR | 0555;
                    out->st_nlink = 8;
                    return 0;
                }
                if (strcmp(rest, "/cmdline") == 0 || strcmp(rest, "/comm") == 0 ||
                    strcmp(rest, "/stat") == 0 || strcmp(rest, "/status") == 0) {
                    out->st_mode = LX_S_IFREG | 0444;
                    out->st_size = 0;
                    out->st_nlink = 1;
                    return 0;
                }
                return -2;                          /* exe/cwd/root/fd → ENOENT */
            }
            out->st_uid = sp->uid; out->st_gid = sp->uid;
            out->st_blksize = 4096;
            if (rest[0] == '\0' || strcmp(rest, "/fd") == 0) {   /* dirs */
                out->st_mode = LX_S_IFDIR | 0555;
                out->st_nlink = (rest[0] == '\0') ? 8 : 2;
                return 0;
            }
            if (strcmp(rest, "/cwd") == 0 || strcmp(rest, "/exe") == 0 ||
                strcmp(rest, "/root") == 0 ||
                strncmp(rest, "/fd/", 4) == 0) {                 /* symlinks */
                out->st_mode = LX_S_IFLNK | 0777;
                out->st_nlink = 1;
                out->st_size = 1;
                return 0;
            }
            out->st_mode = LX_S_IFREG | 0444;                    /* stat/cmdline/… */
            out->st_size = 0;      /* /proc files lie about size */
            out->st_nlink = 1;
            return 0;
        }
    }
    /* /proc/net and /proc/sys are directories (listed in the root getdents). */
    if (strcmp(path, "/net") == 0 || strcmp(path, "/sys") == 0 ||
        strcmp(path, "/sys/kernel") == 0) {
        out->st_mode    = LX_S_IFDIR | 0555;
        out->st_nlink   = 2;
        out->st_blksize = 4096;
        return 0;
    }
    if (strcmp(path, "/self/cmdline") == 0 ||
        strcmp(path, "/self/status") == 0  ||
        strcmp(path, "/self/maps") == 0     ||
        strcmp(path, "/self/stat") == 0     ||   /* procfs-live · statable (was missing) */
        strcmp(path, "/self/comm") == 0     ||   /* procfs-live · statable (was ENOENT) */
        strcmp(path, "/self/cgroup") == 0   ||   /* procfs-live · statable (was ENOENT) */
        strcmp(path, "/self/statm") == 0    ||
        /* the root-listing REG files (so `ls /proc` stats them OK) */
        strcmp(path, "/cpuinfo") == 0 || strcmp(path, "/meminfo") == 0 ||
        strcmp(path, "/version") == 0 || strcmp(path, "/uptime") == 0  ||
        strcmp(path, "/loadavg") == 0 || strcmp(path, "/mounts") == 0) {
        out->st_mode    = LX_S_IFREG | 0444;
        out->st_size    = 0;   /* /proc files lie about size */
        out->st_blksize = 4096;
        out->st_nlink   = 1;
        return 0;
    }
    if (strcmp(path, "/self/exe") == 0 || strcmp(path, "/self/cwd") == 0 ||
        strncmp(path, "/self/fd/", 9) == 0) {
        out->st_mode    = LX_S_IFLNK | 0777;
        out->st_size    = 16;
        out->st_blksize = 4096;
        out->st_nlink   = 1;
        return 0;
    }
    if (strcmp(path, "/self/fd") == 0) {
        out->st_mode    = LX_S_IFDIR | 0555;
        out->st_size    = 0;
        out->st_blksize = 4096;
        out->st_nlink   = 2;
        return 0;
    }
    /* Tier-4 · static /proc files + /self/* extras (REG · /proc lies about size). */
    if (strcmp(path, "/cmdline") == 0 || strcmp(path, "/filesystems") == 0 ||
        strcmp(path, "/stat") == 0 || strcmp(path, "/self/environ") == 0 ||
        strcmp(path, "/self/stat") == 0 || strcmp(path, "/self/statm") == 0 ||
        strcmp(path, "/modules") == 0 || strcmp(path, "/swaps") == 0 ||
        strcmp(path, "/diskstats") == 0 || strcmp(path, "/key-users") == 0 ||
        strcmp(path, "/net/route") == 0 || strcmp(path, "/net/dev") == 0 ||
        strcmp(path, "/net/udp") == 0 || strcmp(path, "/net/tcp") == 0 ||
        strcmp(path, "/net/tcp6") == 0 ||
        strncmp(path, "/sys/", 5) == 0) {
        out->st_mode    = LX_S_IFREG | 0444;
        out->st_size    = 0;
        out->st_blksize = 4096;
        out->st_nlink   = 1;
        return 0;
    }
    return -2;
}

static int op_fstat(void *backend, void *handle, struct lx_stat *out) {
    (void)backend;
    proc_handle_t *h = handle;
    if (!h) return -9;
    memset(out, 0, sizeof(*out));
    /* kind 1=cmdline (REG), 3=directory (DIR), 4=maps (REG).  Python's
     * open() in text mode rejects directories (errno EISDIR) when fstat
     * reports S_IFDIR · classify kind 4 (synthetic /self/maps) and kind 5
     * (synthetic /self/status) as REG. */
    if (h->kind == 1 || h->kind == 4 || h->kind == 5) {
        out->st_mode = LX_S_IFREG | 0444;
        out->st_size = (h->buf_len > 0) ? (int64_t)h->buf_len : 0;
    } else {
        out->st_mode = LX_S_IFDIR | 0555;
    }
    out->st_nlink   = 1;
    out->st_blksize = 4096;
    return 0;
}

/* Emit one dirent64 into `out` at `*written`; returns 0 (no room → caller stops)
 * or 1 (emitted, *written advanced). */
static int proc_emit_dirent(uint8_t *out, size_t *written, size_t count,
                            int64_t ino, int64_t off, const char *name, uint8_t type) {
    size_t name_len = strlen(name) + 1;
    size_t reclen = (offsetof(struct lx_dirent64, d_name) + name_len + 7) & ~7UL;
    if (*written + reclen > count) return 0;
    struct lx_dirent64 *de = (struct lx_dirent64 *)(out + *written);
    de->d_ino    = ino;
    de->d_off    = off;
    de->d_reclen = (uint16_t)reclen;
    de->d_type   = type;
    memcpy(de->d_name, name, name_len);
    *written += reclen;
    return 1;
}

static int64_t op_getdents(void *backend, void *handle, void *dirp,
                            size_t count, int64_t *cursor) {
    (void)backend; (void)cursor;
    proc_handle_t *h = handle;
    if (!h || h->kind != 3) return -20;
    uint8_t *out = dirp;
    size_t written = 0;

    /* /proc/<pid>/fd · stdin/out/err + this process's sockets (DT_LNK), so
     * `netstat -tlnp` can resolve socket:[inode] → PID/Program. */
    if (h->inode >= 6000) {
        int pid = h->pid;
        /* index 0,1,2 = std fds; then each matching g_proc_socks entry. */
        size_t std_n = 3;
        while (h->cursor_dir < std_n) {
            char nm[8]; snprintf(nm, sizeof(nm), "%zu", h->cursor_dir);
            if (!proc_emit_dirent(out, &written, count, 8000 + (int64_t)h->cursor_dir,
                                  (int64_t)(h->cursor_dir + 1), nm, LX_DT_LNK)) return (int64_t)written;
            ++h->cursor_dir;
        }
        size_t idx = std_n;
        for (size_t i = 0; i < PROC_SOCK_N; ++i) {
            if (g_proc_socks[i].pid != pid) continue;
            if (h->cursor_dir == idx) {
                char nm[8]; snprintf(nm, sizeof(nm), "%d", g_proc_socks[i].fd);
                if (!proc_emit_dirent(out, &written, count, 8100 + (int64_t)i,
                                      (int64_t)(idx + 1), nm, LX_DT_LNK)) return (int64_t)written;
                ++h->cursor_dir;
            }
            ++idx;
        }
        return (int64_t)written;
    }

    /* /proc/<pid> · per-process children (synthetic process table). */
    if (h->inode >= 5000) {
        static const struct { const char *n; uint8_t t; } K[] = {
            { "cmdline", LX_DT_REG }, { "comm", LX_DT_REG }, { "stat", LX_DT_REG },
            { "status",  LX_DT_REG }, { "cwd",  LX_DT_LNK }, { "exe",  LX_DT_LNK },
            { "root",    LX_DT_LNK }, { "fd",   LX_DT_DIR },
        };
        size_t N = sizeof(K) / sizeof(K[0]);
        while (h->cursor_dir < N) {
            if (!proc_emit_dirent(out, &written, count, 7000 + (int64_t)h->cursor_dir,
                                  (int64_t)(h->cursor_dir + 1), K[h->cursor_dir].n,
                                  K[h->cursor_dir].t)) break;
            ++h->cursor_dir;
        }
        return (int64_t)written;
    }

    /* /proc root · common files + "self" + every synthetic pid (DT_DIR), so
     * `ls /proc` and `ps`/`netstat`'s /proc scan see a believable process list. */
    if (h->inode == 1000) {
        /* procfs-live · one-shot evidence that truth_list_processes reads the
         * live process directory (procd SHM) — the enumeration a future
         * `sotctl process`/`sotctl sessions` renders.  Fires on the first
         * `ls /proc`/`ps` root scan. */
        static int listed_once = 0;
        if (!listed_once && h->cursor_dir == 0) {
            listed_once = 1;
            struct truth_proc_entry pe[32];
            int npe = truth_list_processes(pe, 32);
            printf("[truth] live processes = %d", npe);
            for (int i = 0; i < npe && i < 8; ++i)
                printf(" · pid=%d ppid=%d t%u comm=%s sess=%u",
                       pe[i].pid, pe[i].ppid, pe[i].tier,
                       pe[i].comm[0] ? pe[i].comm : "?", pe[i].cow_session);
            printf("\n");
            /* libsot proof · ONLY the lightweight session table here — this fires
             * synchronously inside op_getdents on the first `ls /proc`/`ps`, so a
             * heavy multi-print burst would block the guest's syscall and mangle
             * its listing.  The other sotctl views (process/overlay/anomaly/trace/
             * wal) are operator-invoked + unit-proven; not dumped on this hot path. */
            sot_session_print();
        }
        static const struct { const char *n; uint8_t t; } F[] = {
            { "cpuinfo", LX_DT_REG }, { "meminfo", LX_DT_REG }, { "version", LX_DT_REG },
            { "uptime",  LX_DT_REG }, { "loadavg", LX_DT_REG }, { "stat",    LX_DT_REG },
            { "mounts",  LX_DT_REG }, { "cmdline", LX_DT_REG }, { "filesystems", LX_DT_REG },
            { "swaps",   LX_DT_REG }, { "modules", LX_DT_REG }, { "diskstats", LX_DT_REG },
            { "net",     LX_DT_DIR }, { "sys",     LX_DT_DIR }, { "self",    LX_DT_DIR },
        };
        size_t NF = sizeof(F) / sizeof(F[0]);
        /* procfs-live (Task 5) · after the static files + synth pids, ALSO emit
         * the CALLER's-session live display pids (their real bash + fork
         * children), EXCLUDING the caller's own pid (reachable via /self) and
         * de-duped against the synth pids.  cow_session==0 callers (operator /
         * non-session) get NOTHING extra → the pure synth persona. */
        struct truth_proc_entry live[64];
        int nlive = 0;
        {
            struct lucas_state *cst = proc_caller_st((proc_state_t *)backend);
            if (cst && cst->cow_session != 0) {
                int own = truth_display_pid(cst);
                int raw = truth_list_session_processes(cst->cow_session, live, 64);
                for (int i = 0; i < raw && nlive < 64; ++i) {
                    if (live[i].pid == own) continue;            /* /self covers it */
                    if (synth_proc_by_pid(live[i].pid)) continue;/* dedup vs synth */
                    if (nlive != i) live[nlive] = live[i];       /* compact */
                    ++nlive;
                }
            }
        }
        size_t total = NF + SYNTH_PROC_N + (size_t)nlive;
        while (h->cursor_dir < total) {
            size_t i = h->cursor_dir;
            int ok;
            if (i < NF) {
                ok = proc_emit_dirent(out, &written, count, 100 + (int64_t)i,
                                      (int64_t)(i + 1), F[i].n, F[i].t);
            } else if (i < NF + SYNTH_PROC_N) {
                char pidbuf[16];
                int pid = g_synth_procs[i - NF].pid;
                snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
                ok = proc_emit_dirent(out, &written, count, 5000 + pid,
                                      (int64_t)(i + 1), pidbuf, LX_DT_DIR);
            } else {
                char pidbuf[16];
                int pid = live[i - NF - SYNTH_PROC_N].pid;
                snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
                ok = proc_emit_dirent(out, &written, count, 5000 + pid,
                                      (int64_t)(i + 1), pidbuf, LX_DT_DIR);
            }
            if (!ok) break;
            ++h->cursor_dir;
        }
        return (int64_t)written;
    }

    /* /proc/self/fd (inode 2001) · the CALLER's open fds, one DT_LNK each,
     * rendered from truth-core (the same fd table a future `sotctl fds` reads). */
    if (h->inode == 2001) {
        struct lucas_state *fst = proc_caller_st((proc_state_t *)backend);
        int fmax = truth_proc_fd_max();
        while ((int)h->cursor_dir < fmax) {
            int fd = (int)h->cursor_dir;
            if (truth_proc_fd_open(fst, fd)) {
                char nm[8]; snprintf(nm, sizeof(nm), "%d", fd);
                if (!proc_emit_dirent(out, &written, count, 4000 + (int64_t)fd,
                                      (int64_t)(fd + 1), nm, LX_DT_LNK)) break;
            }
            ++h->cursor_dir;
        }
        return (int64_t)written;
    }

    /* /proc/self (inode 2000) · the self-children. */
    while (h->cursor_dir < PROC_SELF_CHILDREN_N) {
        if (!proc_emit_dirent(out, &written, count, 3000 + (int64_t)h->cursor_dir,
                              (int64_t)(h->cursor_dir + 1),
                              proc_self_children[h->cursor_dir].name,
                              proc_self_children[h->cursor_dir].type)) break;
        ++h->cursor_dir;
    }
    return (int64_t)written;
}

static int op_readlink(void *backend, const char *path, char *buf, size_t size) {
    char rb[160]; path = proc_route_own_pid(backend, path, rb, sizeof(rb));
    /* Synthetic process · /proc/<pid>/{exe,cwd,root}.  Kernel threads (empty
     * cmdline) have no exe → ENOENT, exactly like real Linux. */
    {
        int pid; const char *rest;
        if (proc_parse_pid(path, &pid, &rest) && rest[0]) {
            const synth_proc_t *sp = synth_proc_by_pid(pid);
            if (!sp) return -2;
            const char *tgt = NULL;
            char sockbuf[32];
            if (strncmp(rest, "/fd/", 4) == 0) {
                int fd = 0; for (const char *c = rest + 4; *c >= '0' && *c <= '9'; ++c) fd = fd * 10 + (*c - '0');
                for (size_t i = 0; i < PROC_SOCK_N; ++i)
                    if (g_proc_socks[i].pid == pid && g_proc_socks[i].fd == fd) {
                        snprintf(sockbuf, sizeof(sockbuf), "socket:[%ld]", g_proc_socks[i].inode);
                        tgt = sockbuf; break;
                    }
                if (!tgt) tgt = "/dev/null";   /* std fds 0/1/2 */
            } else if (strcmp(rest, "/exe") == 0) {
                if (!sp->cmdline[0]) return -2;   /* kthread · no exe */
                static char exe[128];
                size_t n = 0;
                for (const char *c = sp->cmdline; *c && *c != ' ' && n < sizeof(exe) - 1; ++c)
                    exe[n++] = *c;
                exe[n] = '\0';
                tgt = (exe[0] == '/') ? exe : "/bin/busybox";
            } else if (strcmp(rest, "/cwd") == 0) {
                tgt = (sp->uid == 70) ? "/var/lib/postgresql/16/data" : "/";
            } else if (strcmp(rest, "/root") == 0) {
                tgt = "/";
            } else {
                return -22;   /* not a symlink */
            }
            size_t tl = strlen(tgt);
            if (tl > size) tl = size;
            memcpy(buf, tgt, tl);
            return (int)tl;
        }
    }
    /* procfs-live · /proc/self/fd/<n> → the CALLER's real fd target (truth-core). */
    if (strncmp(path, "/self/fd/", 9) == 0) {
        int fd = 0; for (const char *c = path + 9; *c >= '0' && *c <= '9'; ++c) fd = fd * 10 + (*c - '0');
        char tgt[LUCAS_PATH_MAX];
        int tn = truth_proc_fd_target(proc_caller_st((proc_state_t *)backend), fd, tgt, sizeof(tgt));
        if (tn < 0) return -2;   /* -ENOENT · fd not open */
        size_t tl = (size_t)tn; if (tl > size) tl = size;
        memcpy(buf, tgt, tl);
        return (int)tl;
    }
    /* procfs-live · /proc/self/cwd → the CALLER's real cwd (truth-core). */
    if (strcmp(path, "/self/cwd") == 0) {
        const char *cwd = truth_proc_cwd(proc_caller_st((proc_state_t *)backend));
        size_t tl = strlen(cwd); if (tl > size) tl = size;
        memcpy(buf, cwd, tl);
        return (int)tl;
    }
    if (strcmp(path, "/self/exe") != 0) return -22;
    /* procfs-live · /proc/self/exe renders from truth-core, keyed on the REAL
     * caller (the central dispatch bracket provides it) — COHERENT with
     * /proc/self/maps, which now also shows the real binary.  The old code hid
     * the real exe behind /bin/busybox for untrusted callers, but the Alpine
     * persona runs real distinct binaries (musl bash, the apk-installed nano),
     * so a /bin/busybox-for-everything /proc/self/exe contradicted maps (an
     * analyst diffs the two).  truth_proc_exe still maps non-absolute applet
     * argv[0] → /bin/busybox (what a real Alpine reports for ls/cat). */
    const char *target = truth_proc_exe(proc_caller_st((proc_state_t *)backend));
    size_t tlen = strlen(target);
    if (tlen > size) tlen = size;
    memcpy(buf, target, tlen);
    return (int)tlen;
}

static int64_t op_write_stub(void *backend, void *handle, const void *buf,
                              size_t count, int64_t cursor) {
    (void)backend; (void)handle; (void)buf; (void)count; (void)cursor;
    return -22;
}

const vfs_ops_t vfs_proc_ops = {
    .open     = op_open,
    .close    = op_close,
    .read     = op_read,
    .write    = op_write_stub,
    .stat     = op_stat,
    .fstat    = op_fstat,
    .getdents = op_getdents,
    .readlink = op_readlink,
};

void *vfs_proc_state(struct lucas_state *st) {
    proc_state_singleton.st = st;
    return &proc_state_singleton;
}
