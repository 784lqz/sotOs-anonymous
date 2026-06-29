#ifndef LIBSOT_SOT_SESSION_H
#define LIBSOT_SOT_SESSION_H
/*
 * libsot · the NATIVE sotOs operator API (M6).
 *
 * libsot exposes sotOs's own concepts — sessions, personas, overlays, tiers —
 * that do NOT exist in POSIX.  It reads the SAME truth-core as the procfs
 * renderer (there is no second source of truth): the procfs renderer shows the
 * ATTACKER a persona-curated Linux /proc; libsot shows the OPERATOR the real
 * mechanism that produced it.
 *
 * A Linux guest asks `cat /proc/<pid>/status` and sees the coherent lie.
 * A native operator asks `sotctl sessions` and sees the operative truth.
 *
 * First program: `sotctl sessions`.  This is the session view over truth-core
 * (the live sotboxes grouped by their owning cow_session).
 */
#include <stdint.h>

#define SOT_SESSION_MAX_PIDS   16
#define SOT_SESSION_MAX        32

struct sot_session {
    uint32_t session_id;            /* == cow_session (the SSH conn id) */
    char     persona[16];           /* the persona mask (e.g. "alpine-edge") */
    uint32_t tier;                  /* containment tier (max over the session's procs) */
    char     shell[16];             /* the session's root shell comm (e.g. "bash") */
    uint32_t overlay_bytes;         /* bytes the session has written into its contained upper */
    int      n_pids;
    int      pids[SOT_SESSION_MAX_PIDS];  /* the session's live display pids */
};

/* Enumerate the live SSH attacker sessions from truth-core into `out` (up to
 * `max`).  Returns the session count.  A "session" is the set of live sotboxes
 * sharing a non-zero cow_session (the interactive attacker + its children). */
int sot_session_list(struct sot_session *out, int max);

/* The `sotctl <sub>` commands.  Operator-only · all read truth-core, never /proc. */
void sot_session_print(void);            /* sotctl sessions */
void sot_proc_print(void);               /* sotctl process  · the TRUE live process list */
void sot_overlay_print(uint32_t session);/* sotctl overlay [--session N] · contained writes */
void sot_anomaly_print(void);            /* sotctl anomaly · the security-event ring */
void sot_trace_print(void);              /* sotctl trace · the sottrace audit stream */
void sot_wal_print(void);                /* sotctl wal · the deception-replay log status */
void sot_reap_print(uint32_t session);   /* sotctl reap <session> · CONTROL · free overlay */
void sot_policy_net_print(uint32_t arg); /* sotctl policy net on|off · CONTROL · egress policy */
void sot_promote_print(uint32_t pid);    /* sotctl promote <pid> · CONTROL · escalate tier */
void sot_quarantine_print(uint32_t pid); /* sotctl quarantine <pid> · CONTROL · max contain */
void sot_replay_print(void);             /* sotctl replay-export · WAL deception timeline */
void sot_canary_print(void);             /* sotctl canary list · tripwire inventory + live hits */
void sot_persona_print(uint32_t arg);    /* sotctl persona list/set · selection policy + assignments */
void sot_help_print(void);               /* sotctl help */

/* A live canary-read hit · a sotbox that touched a honeytoken (an IOC).  Filled
 * by orch_canary_hits (orch owns the sotbox slots w/ canary_read_count). */
struct sot_canary_hit { uint32_t pid; uint32_t session; int reads; };
int orch_canary_hits(struct sot_canary_hit *out, int max);  /* implemented in orch */

/* Render one SOTABI_OP_* op's table into `buf` (up to `cap`) instead of serial,
 * returning the byte length.  Used by orch to serve the native sotctl's render
 * stream over sotabi IPC — the SAME formatters, a buffer sink. */
int sot_render(int op, uint32_t arg, char *buf, int cap);

#endif /* LIBSOT_SOT_SESSION_H */
