/*
 * sotOs · libsot · sot_session — the operator's session view over truth-core.
 *
 * Reads truth_list_processes (the same procd-backed enumeration the procfs
 * renderer uses) and GROUPS the live sotboxes by their owning cow_session, so
 * the operator sees the real attacker sessions — NOT the persona-curated /proc.
 * No second source of truth: this is truth-core, rendered for the operator.
 *
 * NOTE (architecture): for this first cut libsot runs IN-ORCH (the operator
 * console is orch-side, and truth-core is reachable here directly).  When sotctl
 * becomes a standalone NATIVE binary (sotcrt/sotabi), this same API is reached
 * over a libsot IPC to orch — the accessors below do not change.
 */
#include <libsot/sot_session.h>
#include <lucas/truth.h>
#include <lucas/persona_session.h>   /* M3 · per-session persona name (sot_session_list) */
#include <lucas/sotfs_session.h>   /* overlay byte accounting + session_owner */
#include <sotfs/graph.h>           /* the sotfs graph · inode→path reverse for overlay diff */
#include <sotfs/wal.h>             /* WAL status (sotctl wal) */
#include <sotfs/layout.h>          /* SOTFS_WAL_OFFSET · WAL bytes-logged */
#include <sottrace/trace.h>        /* the sottrace ring · sotctl trace */
#include <orch/proto.h>            /* the anomaly ring entry + ANOMALY_EV_* kinds */
#include <sotabi/proto.h>          /* SOTABI_OP_* (the render-stream op codes) */
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/*
 * The dual output sink.  Every sot_*_print below emits through sot_emit (the
 * `printf` macro just below redirects them).  Normally sot_emit goes straight to
 * the operator serial (vprintf).  But when a render buffer is armed (sot_render,
 * for the native sotctl's sotabi render-stream), the SAME formatters append into
 * that buffer instead — ONE formatter, two sinks (no second source of truth).
 */
static char *g_sink;       /* armed buffer · NULL = emit to serial */
static int   g_sink_pos;
static int   g_sink_cap;

static void sot_emit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (g_sink) {
        if (g_sink_pos < g_sink_cap) {
            int w = vsnprintf(g_sink + g_sink_pos, (size_t)(g_sink_cap - g_sink_pos),
                              fmt, ap);
            if (w > 0) g_sink_pos += w;
            if (g_sink_pos > g_sink_cap) g_sink_pos = g_sink_cap;  /* truncated */
        }
    } else {
        vprintf(fmt, ap);
    }
    va_end(ap);
}

/* Redirect every printf in the formatters below to the dual sink.  Defined AFTER
 * sot_emit (which uses vprintf, the real libc), so no recursion. */
#define printf sot_emit

int sot_session_list(struct sot_session *out, int max)
{
    if (!out || max <= 0) return 0;

    static struct truth_proc_entry procs[128];
    int n = truth_list_processes(procs, (int)(sizeof(procs) / sizeof(procs[0])));

    int n_sessions = 0;
    for (int i = 0; i < n; ++i) {
        unsigned sess = procs[i].cow_session;
        if (sess == 0) continue;             /* not an interactive session */

        /* find or create the session bucket */
        struct sot_session *s = 0;
        for (int j = 0; j < n_sessions; ++j)
            if (out[j].session_id == sess) { s = &out[j]; break; }
        if (!s) {
            if (n_sessions >= max) continue;
            s = &out[n_sessions++];
            memset(s, 0, sizeof(*s));
            s->session_id = sess;
            /* M3 · the persona is now a PER-SESSION fact: read this session's real
             * persona name from its persona context (truth-core's single source),
             * not a global hardcode.  Fallback to "alpine-edge" if the ctx is gone
             * (e.g. mid-reap) so the operator view never shows an empty cell. */
            {
                lucas_persona_t pc;
                if (lucas_persona_session_get(sess, &pc) && pc.name[0])
                    strncpy(s->persona, pc.name, sizeof(s->persona) - 1);
                else
                    strncpy(s->persona, "alpine-edge", sizeof(s->persona) - 1);
            }
            s->overlay_bytes = lucas_sotfs_session_bytes(sess);  /* contained writes */
        }

        if (procs[i].tier > s->tier) s->tier = procs[i].tier;
        if (s->n_pids < SOT_SESSION_MAX_PIDS)
            s->pids[s->n_pids++] = procs[i].pid;

        /* the session's root shell = the proc whose parent is NOT in this session
         * (its ppid belongs to the persona's sshd, not another session proc). */
        int parent_in_session = 0;
        for (int k = 0; k < n; ++k)
            if (procs[k].cow_session == sess && procs[k].pid == procs[i].ppid) {
                parent_in_session = 1; break;
            }
        if (!parent_in_session && s->shell[0] == '\0')
            strncpy(s->shell, procs[i].comm, sizeof(s->shell) - 1);
    }
    return n_sessions;
}

void sot_session_print(void)
{
    static struct sot_session ss[SOT_SESSION_MAX];
    int n = sot_session_list(ss, SOT_SESSION_MAX);

    printf("[sotctl] SESSION  PERSONA       TIER  SHELL     OVERLAY   PIDS\n");
    if (n == 0) {
        printf("[sotctl]   (no active attacker sessions)\n");
        return;
    }
    for (int i = 0; i < n; ++i) {
        const struct sot_session *s = &ss[i];
        printf("[sotctl]   %-5u  %-12s  %u     %-8s  %6u B  ",
               s->session_id, s->persona, s->tier,
               s->shell[0] ? s->shell : "?", s->overlay_bytes);
        for (int p = 0; p < s->n_pids; ++p)
            printf("%s%d", p ? "," : "", s->pids[p]);
        printf("\n");
    }
}

/* sotctl process · the TRUE live process list (every sotbox · system + attacker),
 * the operator's `ps` over truth-core — distinct from the persona-curated /proc. */
void sot_proc_print(void)
{
    static struct truth_proc_entry procs[128];
    int n = truth_list_processes(procs, (int)(sizeof(procs)/sizeof(procs[0])));
    printf("[sotctl]   PID    PPID   TIER  SESS  COMM\n");
    for (int i = 0; i < n; ++i) {
        const struct truth_proc_entry *p = &procs[i];
        printf("[sotctl]   %-6d %-6d t%-3u  %-4u  %s\n",
               p->pid, p->ppid, p->tier, p->cow_session,
               p->comm[0] ? p->comm : "?");
    }
    printf("[sotctl]   (%d live sotboxes · the TRUTH, not the persona ps)\n", n);
}

/* Reverse-resolve an inode to its path by walking parent edges up to the subtree
 * root (the per-session upper hangs off the mount roots /tmp,/var,/usr,/etc). */
static void sot_inode_path(const struct sotfs_graph *g, int inode_id,
                           char *buf, size_t cap)
{
    char segs[24][SOTFS_MAX_NAME];
    int ns = 0, cur = inode_id, guard = 0;
    while (cur > 0 && cur != g->root_id && ns < 24 && guard++ < 256) {
        int found = -1;
        for (int e = 0; e < SOTFS_MAX_EDGES; ++e)
            if (g->edges[e].child_id == cur && g->edges[e].name[0]) { found = e; break; }
        if (found < 0) break;
        strncpy(segs[ns], g->edges[found].name, SOTFS_MAX_NAME - 1);
        segs[ns][SOTFS_MAX_NAME - 1] = '\0';
        ++ns;
        cur = g->edges[found].parent_id;
    }
    if (ns == 0) { strncpy(buf, "/?", cap - 1); buf[cap - 1] = '\0'; return; }
    size_t pos = 0; buf[0] = '\0';
    for (int i = ns - 1; i >= 0; --i) {
        int w = snprintf(buf + pos, cap - pos, "/%s", segs[i]);
        if (w < 0 || (size_t)w >= cap - pos) break;
        pos += (size_t)w;
    }
}

/* sotctl overlay [--session N] · the per-session contained-write accounting AND
 * the actual FILES the attacker wrote into its session upper (path + size) —
 * resolved from truth-core's sotfs graph (session_owner + the parent edges).
 * The base filesystem is untouched; reaped on disconnect. */
void sot_overlay_print(uint32_t session)
{
    static struct sot_session ss[SOT_SESSION_MAX];
    int n = sot_session_list(ss, SOT_SESSION_MAX);
    extern struct sotfs_graph *backends_sotfs_get_graph(void);
    const struct sotfs_graph *g = backends_sotfs_get_graph();

    printf("[sotctl] OVERLAY (contained writes · base filesystem intact)\n");
    int shown = 0;
    for (int i = 0; i < n; ++i) {
        if (session != 0 && ss[i].session_id != session) continue;
        printf("[sotctl]   session %-4u persona=%-12s overlay=%u bytes (reaped on disconnect)\n",
               ss[i].session_id, ss[i].persona, ss[i].overlay_bytes);
        shown++;
        if (!g) continue;
        /* enumerate the session-owned inodes (the diff) and resolve each path. */
        int files = 0;
        for (int id = 1; id <= SOTFS_MAX_INODES; ++id) {
            if (g->inodes[id - 1].id == 0) continue;
            if (lucas_sotfs_session_owner(id) != ss[i].session_id) continue;
            char path[256];
            sot_inode_path(g, id, path, sizeof(path));
            printf("[sotctl]       %-48s %7u B  %s\n", path, g->inodes[id - 1].size,
                   g->inodes[id - 1].kind == SOTFS_KIND_DIR ? "dir" : "file");
            ++files;
        }
        printf("[sotctl]     (%d session-owned inode(s) · the attacker's contained writes)\n", files);
    }
    if (!shown)
        printf("[sotctl]   (no contained writes%s)\n", session ? " for that session" : "");
}

/* ANOMALY_EV_* → short name (no string table exists upstream). */
static const char *sot_anomaly_kind_name(uint16_t kind)
{
    switch (kind) {
    case ANOMALY_EV_WRITE:            return "WRITE";
    case ANOMALY_EV_OPERATOR_PROMOTE: return "OPERATOR_PROMOTE";
    case ANOMALY_EV_PLEDGE_VIOLATION: return "PLEDGE_VIOLATION";
    case ANOMALY_EV_NET_PRECOMMIT:    return "NET_PRECOMMIT";
    case ANOMALY_EV_CURVATURE:        return "CURVATURE";
    case ANOMALY_EV_DNS_HIT:          return "DNS_HIT";
    case ANOMALY_EV_TCP_OPEN:         return "TCP_OPEN";
    case ANOMALY_EV_MSYSCALL:         return "MSYSCALL";
    case ANOMALY_EV_CRED_ACCESS:      return "CRED_ACCESS";
    case ANOMALY_EV_UNLINK:           return "UNLINK";
    case ANOMALY_EV_EXEC:             return "EXEC";
    case ANOMALY_EV_PROCD_PROC_BORN:        return "PROC_BORN";
    case ANOMALY_EV_PROCD_PROC_EXITED:      return "PROC_EXITED";
    case ANOMALY_EV_PROCD_TIER_CHANGED:     return "TIER_CHANGED";
    case ANOMALY_EV_PROCD_FUNCTOR_REBOUND:  return "FUNCTOR_REBOUND";
    case ANOMALY_EV_PROCD_SYNTH_FORK:       return "SYNTH_FORK";
    case ANOMALY_EV_PROCD_DENIED_TIER3:     return "DENIED_TIER3";
    case ANOMALY_EV_PROCD_OTHER:            return "PROCD_OTHER";
    default:                          return "OTHER";
    }
}

/* sotctl anomaly · tail the anomaly ring (the operator's security-event log —
 * tier promotions, contained writes, cred access, TCP opens, package installs).
 * Reads the SAME ring the operator dashboard reads; never /proc. */
void sot_anomaly_print(void)
{
    extern int orch_anomaly_log_snapshot(orch_anomaly_log_entry_t *out, int max);
    static orch_anomaly_log_entry_t ev[ORCH_ANOMALY_LOG_MAX];
    int n = orch_anomaly_log_snapshot(ev, ORCH_ANOMALY_LOG_MAX);
    printf("[sotctl] ANOMALY (security events · oldest→newest)\n");
    if (n == 0) { printf("[sotctl]   (no anomaly events yet)\n"); return; }
    for (int i = 0; i < n; ++i) {
        printf("[sotctl]   seq=%-4u pid=%-6u %-16s arg0=0x%llx arg1=0x%llx\n",
               ev[i].seq,
               ev[i].display_pid ? ev[i].display_pid : ev[i].pid,
               sot_anomaly_kind_name(ev[i].kind),
               (unsigned long long)ev[i].arg0,
               (unsigned long long)ev[i].arg1);
    }
}

/* sotctl trace · tail the sottrace ring — the per-syscall/per-event audit stream
 * (FS open/read/write, net connect, DNS, tier transitions, canary reads) the
 * operator's `watch` dashboard reads.  Newest-first. */
void sot_trace_print(void)
{
    static sotguard_event_t ev[32];
    uint32_t total = 0;
    uint32_t n = sottrace_peek_recent(ev, 32, &total);
    printf("[sotctl] TRACE (audit stream · newest-first · %u of %u events)\n", n, total);
    if (n == 0) { printf("[sotctl]   (no trace events yet)\n"); return; }
    for (uint32_t i = 0; i < n; ++i) {
        char line[160];
        sottrace_format_line(line, sizeof(line), &ev[i]);
        /* sottrace_format_line already prefixes "[sottrace] …"; re-tag for sotctl. */
        const char *p = line;
        if (strncmp(p, "[sottrace] ", 11) == 0) p += 11;
        printf("[sotctl]   %s\n", p);
    }
}

/* sotctl wal · the deception-replay log status — how much of the attacker's
 * timeline (creates/renames/synth-net/anomaly) is durably recorded for replay. */
void sot_wal_print(void)
{
    uint64_t cursor = sotfs_wal_cursor();
    uint64_t seq    = sotfs_wal_seq();
    uint64_t logged = (cursor > SOTFS_WAL_OFFSET) ? (cursor - SOTFS_WAL_OFFSET) : 0;
    printf("[sotctl] WAL (deception-replay log · sotfs_blkdev-backed)\n");
    printf("[sotctl]   records=%llu  logged=%llu bytes  region=[%u MiB,+%u MiB)\n",
           (unsigned long long)(seq > 0 ? seq - 1 : 0),
           (unsigned long long)logged,
           (unsigned)(SOTFS_WAL_OFFSET / (1024 * 1024)),
           (unsigned)(SOTFS_WAL_REGION_BYTES / (1024 * 1024)));
    printf("[sotctl]   (per-record tail needs the on-disk WAL parser · follow-up)\n");
}

/* sotctl replay-export · the deception-replay timeline · the PER-RECORD WAL
 * reader (sot_wal_print shows only status).  sotfs_wal_export formats the on-disk
 * records into a local buffer; we re-emit via the sink so it streams to the
 * native sotctl. */
void sot_replay_print(void)
{
    extern int sotfs_wal_export(char *, int, int);
    static char wbuf[6144];
    int n = sotfs_wal_export(wbuf, (int)sizeof(wbuf), 80);
    if (n > 0) printf("%s", wbuf);
    else       printf("[sotctl] REPLAY · (no records)\n");
}

/* sotctl canary list · the honeytoken tripwires that are ARMED (any READ is an
 * IOC) + the LIVE read-hits (which sessions chased the bait · the security
 * signal).  The per-event stream is `sotctl trace` (SG_EV_CANARY_READ); this is
 * the inventory + the per-session hit summary. */
void sot_canary_print(void)
{
    printf("[sotctl] CANARY tripwires armed (any READ of these is an IOC)\n");
    static const char *const inv[] = {
        "/etc/shadow                · password hashes (honey · $6$honey<name>$)",
        "/root/.bash_history        · root command trail (DB creds · S3 · API bearer)",
        "/home/*/.ssh/id_rsa        · SSH private keys (USE = a lateral-move tripwire)",
        "/home/*/.pgpass            · prod DB credentials",
        "/home/*/.bash_history      · per-user command trail",
        "/var/log/auth.log          · fabricated SSH/sudo auth trail",
        "/etc/crontab               · nightly pg_dump -> S3 backup honeytoken",
        "/etc/ssh/sshd_config       · auth-posture recon bait",
        NULL };
    for (int i = 0; inv[i]; ++i) printf("[sotctl]   %s\n", inv[i]);

    struct sot_canary_hit hits[16];
    int n = orch_canary_hits(hits, (int)(sizeof(hits) / sizeof(hits[0])));
    printf("[sotctl] CANARY hits (live · who chased the bait)\n");
    if (n == 0) {
        printf("[sotctl]   (no canary reads yet · no IOC)\n");
    } else {
        int total = 0;
        for (int i = 0; i < n; ++i) {
            printf("[sotctl]   session %-4u pid %-6u · %d canary read(s)  ** IOC **\n",
                   hits[i].session, hits[i].pid, hits[i].reads);
            total += hits[i].reads;
        }
        printf("[sotctl]   (%d session(s) · %d canary read(s) total · see `sotctl trace` "
               "for the per-file SG_EV_CANARY_READ events)\n", n, total);
    }
}

/* sotctl persona list/set · the persona-selection policy for NEW SSH sessions +
 * the seeded persona definitions + the live per-session assignments.  arg: 0 =
 * set-alpine, 1 = set-debian, 2 = set-auto (round-robin), 3 = list-only. */
void sot_persona_print(uint32_t arg)
{
    extern void orch_persona_pin_set(int);
    extern int  orch_persona_pin_get(void);
    if (arg == 0)      orch_persona_pin_set(0);     /* pin Alpine */
    else if (arg == 1) orch_persona_pin_set(1);     /* pin Debian */
    else if (arg == 2) orch_persona_pin_set(-1);    /* auto / round-robin */

    lucas_persona_t pa, pd;
    lucas_persona_for_profile(LUCAS_PERSONA_ALPINE, &pa);
    lucas_persona_for_profile(LUCAS_PERSONA_DEBIAN, &pd);
    printf("[sotctl] PERSONA definitions (the seeded stories · one per session):\n");
    printf("[sotctl]   alpine · %-13s host=%-13s musl / apk / busybox\n", pa.name, pa.host);
    printf("[sotctl]   debian · %-13s host=%-13s glibc / apt / GNU coreutils\n", pd.name, pd.host);
    int pin = orch_persona_pin_get();
    printf("[sotctl] PERSONA selection for NEW sessions: %s\n",
           pin == 0 ? "PINNED alpine" : pin == 1 ? "PINNED debian"
                                                  : "round-robin (alternating)");
    /* live per-session assignments (truth-core · grouped by cow_session) */
    static struct sot_session ss[SOT_SESSION_MAX];
    int n = sot_session_list(ss, SOT_SESSION_MAX);
    printf("[sotctl] PERSONA live assignments:\n");
    if (n == 0) printf("[sotctl]   (no active attacker sessions)\n");
    for (int i = 0; i < n; ++i)
        printf("[sotctl]   session %-4u · %s\n", ss[i].session_id, ss[i].persona);
}

void sot_help_print(void)
{
    printf("[sotctl] sotOs native control · reads the truth plane (not /proc)\n"
           "[sotctl]   sotctl sessions            · live attacker sessions\n"
           "[sotctl]   sotctl process             · the TRUE live process list\n"
           "[sotctl]   sotctl overlay [--session N]· contained writes per session\n"
           "[sotctl]   sotctl anomaly             · the security-event ring\n"
           "[sotctl]   sotctl trace               · the sottrace audit stream\n"
           "[sotctl]   sotctl wal                 · the deception-replay log status\n"
           "[sotctl]   sotctl reap <session>      · CONTROL · free a session's overlay\n"
           "[sotctl]   sotctl policy net <on|off> · CONTROL · attacker egress policy\n"
           "[sotctl]   sotctl promote <pid>       · CONTROL · escalate a box's tier\n"
           "[sotctl]   sotctl quarantine <pid>    · CONTROL · max-contain a box\n"
           "[sotctl]   sotctl replay-export       · export the WAL deception timeline\n"
           "[sotctl]   sotctl canary list         · tripwire inventory + live read-hits\n"
           "[sotctl]   sotctl persona list        · personas + selection policy + assignments\n"
           "[sotctl]   sotctl persona set <a|d|auto>· CONTROL · pin the persona for new sessions\n"
           "[sotctl]   sotctl help                · this\n");
}

/* sotctl reap <session> · the FIRST native CONTROL op (the plane MUTATES the
 * deception host, not just views it).  Frees a live attacker session's contained
 * overlay — its sotfs upper + COW-lite edits + per-session symlinks — so the
 * operator can wipe an attacker's contained writes ON DEMAND (normally this
 * happens at SSH disconnect).  The BASE filesystem is untouched (deception
 * intact); the session keeps running on the pristine base. */
void sot_reap_print(uint32_t session)
{
    if (session == 0) {
        printf("[sotctl] REAP · session 0 is the operator/base · nothing to reap\n");
        return;
    }
    extern void lucas_cow_reap(uint32_t);
    extern void lucas_symlink_reap(uint32_t);
    uint32_t before = lucas_sotfs_session_bytes(session);
    lucas_sotfs_session_reap(session);   /* sotfs upper · graph + disk blocks */
    lucas_cow_reap(session);             /* the COW-lite :w edits */
    lucas_symlink_reap(session);         /* per-session /tmp symlinks */
    uint32_t after = lucas_sotfs_session_bytes(session);
    printf("[sotctl] REAP · session %u · freed %u B of contained overlay "
           "(was %u B, now %u B) · base filesystem intact, session live on base\n",
           session, before > after ? before - after : before, before, after);
}

/* sotctl policy net <on|off|status|guarded> · CONTROL · the attacker net-egress
 * policy.  OFF = synth-only containment (no real wire); ON = real wire to ANY
 * dst (dev/open); GUARDED = real wire only to allowlisted dsts (+DNS), every
 * other dst SINKHOLED (synthetic success + IOC log, no real packet) — the
 * REQUIRED engagement posture (Gate 0 · no real attacks on third parties from
 * the host).  Does NOT touch the operator's own Tier-0e egress.
 * arg: 0=off, 1=on(open), 2=query, 3=guarded. */
void sot_policy_net_print(uint32_t arg)
{
    extern void lucas_net_policy_set(int);
    extern int  lucas_net_policy_get(void);
    extern void lucas_egress_guarded_set(int);
    extern int  lucas_egress_guarded_get(void);
    if (arg == 0)      { lucas_net_policy_set(0); }                       /* off */
    else if (arg == 1) { lucas_net_policy_set(1); lucas_egress_guarded_set(0); } /* on/open */
    else if (arg == 3) { lucas_net_policy_set(1); lucas_egress_guarded_set(1); } /* guarded */
    int on = lucas_net_policy_get();
    int guarded = lucas_egress_guarded_get();
    const char *mode = !on ? "OFF (synth-only · no real wire)"
                     : guarded ? "GUARDED (real wire → allowlist+DNS only · rest SINKHOLED · IOC'd · engagement-safe)"
                               : "ON/OPEN (real wire → ANY dst · DEV ONLY · not engagement-safe)";
    printf("[sotctl] POLICY net.egress = %s%s\n",
           mode, arg == 2 ? " (query)" : " (set by operator)");
    printf("[sotctl]   (operator Tier-0e egress is unaffected · this gates only the "
           "interactive SSH attacker session)\n");
}

/* sotctl promote/quarantine <pid> · CONTROL · escalate a LIVE sotbox's
 * containment tier by its display pid.  promote = +1 tier (capped 2); quarantine
 * = tier 2 (max canary containment).  never-downgrade (orch_tier_control). */
void sot_promote_print(uint32_t pid)
{
    extern int orch_tier_control(uint32_t, int);
    int nt = orch_tier_control(pid, 0);
    if (nt < 0)
        printf("[sotctl] PROMOTE pid=%u · no live sotbox with that pid · no change\n", pid);
    else
        printf("[sotctl] PROMOTE pid=%u · escalated containment → tier %d "
               "(never-downgrade · [trust] logged)\n", pid, nt);
}
void sot_quarantine_print(uint32_t pid)
{
    extern int orch_tier_control(uint32_t, int);
    int nt = orch_tier_control(pid, 1);
    if (nt < 0)
        printf("[sotctl] QUARANTINE pid=%u · no live sotbox with that pid · no change\n", pid);
    else
        printf("[sotctl] QUARANTINE pid=%u · max containment → tier %d "
               "(canary-isolated · its egress/writes are now synth-contained)\n", pid, nt);
}

#undef printf   /* the formatters above are redirected; the API below is not */

/*
 * sot_render — render one op's truth-plane table into `buf` (for the native
 * sotctl's sotabi render-stream).  Arms the dual sink, runs the SAME formatter
 * the in-orch path uses, returns the byte length written (clamped to cap).  The
 * native binary reaches this over IPC; orch calls it directly.
 */
int sot_render(int op, uint32_t arg, char *buf, int cap)
{
    if (!buf || cap <= 0) return 0;
    g_sink = buf;
    g_sink_pos = 0;
    g_sink_cap = cap;
    switch (op) {
    case SOTABI_OP_SESSIONS: sot_session_print();      break;
    case SOTABI_OP_PROCESS:  sot_proc_print();         break;
    case SOTABI_OP_OVERLAY:  sot_overlay_print(arg);   break;
    case SOTABI_OP_ANOMALY:  sot_anomaly_print();      break;
    case SOTABI_OP_TRACE:    sot_trace_print();        break;
    case SOTABI_OP_WAL:      sot_wal_print();           break;
    case SOTABI_OP_REAP:       sot_reap_print(arg);       break;
    case SOTABI_OP_POLICY_NET: sot_policy_net_print(arg); break;
    case SOTABI_OP_PROMOTE:    sot_promote_print(arg);    break;
    case SOTABI_OP_QUARANTINE: sot_quarantine_print(arg); break;
    case SOTABI_OP_REPLAY:     sot_replay_print();        break;
    case SOTABI_OP_CANARY:     sot_canary_print();        break;
    case SOTABI_OP_PERSONA:    sot_persona_print(arg);    break;
    default:                 sot_help_print();          break;
    }
    int n = g_sink_pos;
    g_sink = 0;             /* disarm · subsequent prints go to serial again */
    return n;
}
