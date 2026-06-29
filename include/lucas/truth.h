#ifndef LUCAS_TRUTH_H
#define LUCAS_TRUTH_H
/*
 * truth-core (M1) · the SINGLE source of truth for sotOs.
 *
 * A THIN facade over the EXISTING real sotbox state (lucas_state of the actual
 * caller, the fd table, the lazy-region table, sotfs mounts, sotnet sockets).
 * It introduces NO new state — it is the one place that READS the truth, so the
 * two renderers stay consistent:
 *
 *   truth-core ──► procfs/sysfs renderer  → the attacker (a Linux guest) sees a
 *                                           coherent Linux /proc, /sys, maps…
 *   truth-core ──► libsot native API      → the operator sees the real mechanism
 *                                           (future: sotctl).
 *
 * There must not be two sources of truth: /proc/self/exe and a future
 * `sotctl exe --pid P` must answer from the SAME truth_proc_* accessors.
 *
 * These are keyed on a process's lucas_state — the procfs renderer passes the
 * REAL caller (the central dispatch bracket sets the thread-local caller around
 * every syscall, so at a /proc open the caller IS the process that opened it).
 */
#include <stddef.h>

struct lucas_state;

/* Absolute path of the process's executable (/proc/<pid>/exe target). */
const char *truth_proc_exe(const struct lucas_state *st);

/* The process's command line into `out` as NUL-separated argv (the
 * /proc/<pid>/cmdline format).  Returns the number of bytes written (incl. the
 * trailing NUL).  For now this is argv[0] (= the exe path); full argv arrives
 * when the spawn/execve argv is threaded into truth-core. */
int truth_proc_cmdline(const struct lucas_state *st, char *out, size_t cap);

/* The process's current working directory (/proc/<pid>/cwd target). */
const char *truth_proc_cwd(const struct lucas_state *st);

/* ── fd table (the SAME table a future `sotctl fds` would read) ─────────────── */

/* Number of fd slots to scan (the fd table size). */
int truth_proc_fd_max(void);

/* Is fd `fd` open in this process? (1/0) */
int truth_proc_fd_open(const struct lucas_state *st, int fd);

/* The /proc/<pid>/fd/<fd> symlink target (the real backing object: a file path,
 * "socket:[inode]", "pipe:[inode]", "/dev/pts/0", …) into `out`.  Returns the
 * number of bytes written (excl. NUL), or <0 if `fd` is not open. */
int truth_proc_fd_target(const struct lucas_state *st, int fd, char *out, size_t cap);

/* ── process identity / accounting (the SAME data a future `sotctl process` reads) ─ */

/* Short command name (TASK_COMM_LEN-ish · /proc/<pid>/comm + status Name).
 * Derived from argv[0] basename: "cat"→cat, "/usr/bin/nano"→nano, the persona
 * bash ("alpine-bash")→bash.  Returns `out`. */
const char *truth_proc_comm(const struct lucas_state *st, char *out, size_t cap);

struct truth_process {
    int           pid;           /* display pid (== getpid()) */
    int           ppid;
    unsigned      uid, gid;
    char          state;         /* R/S/D/Z */
    int           threads;
    int           fd_count;      /* open fds */
    unsigned long vm_size_kb;    /* approximate, from real brk/mmap accounting */
    unsigned long vm_rss_kb;
    unsigned long vm_stk_kb;
};

/* Fill `out` from the REAL process state (the single source · /proc/<pid>/status
 * renders this; a future libsot/sotctl reads the same). */
void truth_get_process(const struct lucas_state *st, struct truth_process *out);

/* ── live process enumeration (the process directory · what `sotctl process` reads) ── */

struct truth_proc_entry {
    int      pid;        /* display pid (what the guest's getpid returns) */
    int      ppid;       /* parent's display pid */
    char     state;      /* R/S/D/Z */
    unsigned tier;       /* sotOs containment tier */
    char     comm[16];   /* ABI v2 · short program name (NUL-terminated) */
    unsigned cow_session;/* ABI v2 · owning SSH session id (0 = none) */
};

/* Enumerate the LIVE sotboxes from the process directory (procd SHM) into `out`
 * (up to `max`).  Returns the count.  This is truth-core's process list — the
 * SAME enumeration a future `sotctl process` / `sotctl sessions` reads. */
int truth_list_processes(struct truth_proc_entry *out, int max);

/* Session-filtered live enumeration · returns only the live procs whose
 * cow_session == `cow_session` (and cow_session != 0).  This is what the procfs
 * renderer shows an attacker for THEIR OWN session's `ps` (their real bash +
 * fork children), filtering out other sessions and system sotboxes.  If
 * cow_session == 0, returns 0 (an operator / non-session caller gets the pure
 * synth persona, no extra live pids). */
int truth_list_session_processes(unsigned cow_session,
                                 struct truth_proc_entry *out, int max);

/* The display pid (== getpid()) of this process, seeding it if unseeded. */
int truth_display_pid(struct lucas_state *st);

#endif /* LUCAS_TRUTH_H */
