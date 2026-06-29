/* sotOs · sottrace · native observability plane (v0).
 *
 * Per-sandbox lock-free rings of sotguard_event_t, written by a non-blocking
 * trace_emit (ring store only — NO printf/malloc/lock/seL4_Call/WAL). Single
 * writer = the orch thread, so the SPSC discipline (procd_event_ring_t) is
 * race-free. Consumers: a gated live serial drain + an on-demand snapshot.
 */
#ifndef SOTTRACE_TRACE_H
#define SOTTRACE_TRACE_H

#include <stdint.h>
#include <stddef.h>
#include <sotguard/event.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Forensic per-connection payload capture store ---- */
/* 64 KiB/direction · the interactive SSH session transcript (keystrokes IN +
 * shell output OUT) is appended here byte-by-byte for the post-engagement debrief.
 * 4 KiB lost almost everything (one `ls -la /` overflowed it); 64 KiB holds a
 * useful window (drops past CAP are counted).  Full multi-MB sessions still want
 * the sotfs/WAL spill (follow-up).  8 slots × 2 dirs × 64 KiB ≈ 1 MiB BSS. */
#define SOTTRACE_CAPTURE_CAP   65536
#define SOTTRACE_CAPTURE_SLOTS 8          /* last 8 sessions (an LRU) */
#define SOTTRACE_DIR_IN  0                /* request bytes (peer -> honeypot) */
#define SOTTRACE_DIR_OUT 1                /* reply bytes (honeypot -> peer, wire) */
typedef struct {
    uint16_t conn_id;     /* 0 = free */
    uint16_t _pad;
    uint32_t len;         /* IN bytes stored (<= CAP) */
    uint32_t dropped;     /* IN bytes seen past CAP */
    uint32_t bound;       /* monotonic bind-order, for LRU eviction (0 = free) */
    uint8_t  buf[SOTTRACE_CAPTURE_CAP];        /* IN stream */
    uint32_t len_out;     /* OUT bytes stored (<= CAP) */
    uint32_t dropped_out; /* OUT bytes seen past CAP */
    uint8_t  buf_out[SOTTRACE_CAPTURE_CAP];    /* OUT stream */
} sottrace_capture_t;
void     sottrace_capture_append(uint16_t conn_id, int dir, const uint8_t *data, uint32_t len);
void     sottrace_capture_release(uint16_t conn_id);   /* explicit free (NOT wired to conn_free) */
const sottrace_capture_t *sottrace_capture_get(uint16_t conn_id);  /* NULL if none */

/* Must stay a power of two (index = seq & (N-1)). */
#define SOTTRACE_RING_N      128
/* One ring per sotbox slot + one "system" ring for unattributed events
 * (DNS resolved in the poll loop, future system lifecycle). Keep
 * SOTTRACE_MAX_SLOTS == SOTBOX_MAX_SLOTS (include/orch/sotbox.h); a
 * _Static_assert in src/orch/main.c pins this equality. */
#define SOTTRACE_MAX_SLOTS   8
#define SOTTRACE_NRINGS      (SOTTRACE_MAX_SLOTS + 1)
#define SOTTRACE_SYS_RING    SOTTRACE_MAX_SLOTS   /* index of the system ring */
_Static_assert((uint64_t)SOTTRACE_NRINGS * SOTTRACE_RING_N <= 0xFFFFFFFFull,
               "trace ring total must fit in uint32_t");

typedef struct {
    volatile uint64_t head_seq;          /* writer cursor; monotonic */
    uint64_t          _pad[7];           /* cacheline separation */
    sotguard_event_t  entries[SOTTRACE_RING_N];
} sottrace_ring_t;

/* Live serial drain toggle. Default 0 (OFF) so a normal boot is
 * byte-identical to an untraced boot. Flipped by `sottrace on`/`off`. */
extern int g_trace_live;
/* v2.8 · when set (with g_trace_live), the live drain ALSO renders a clean,
 * severity-tagged dashboard line per event to the framebuffer (operator `watch`). */
extern int g_trace_to_fb;
/* v2.9 · operator `watch` quiet mode: gate the high-volume per-packet/per-syscall/
 * per-mmap debug printfs so the deception feed (serial + fb) is readable.  Off by
 * default → headless gates keep their full verbose markers. */
extern int g_orch_quiet;

/* --- producers (all called on the orch thread, mid-fault-safe) --- */
void trace_emit_enter(int slot, uint32_t synthetic_pid, uint32_t sysno,
                      const uint64_t args[6], uint64_t rip);
void trace_emit_exit (int slot, uint32_t synthetic_pid, uint32_t sysno,
                      int64_t ret, uint64_t rip);
void trace_emit_tier (int slot, uint32_t synthetic_pid, uint32_t old_tier,
                      uint32_t new_tier);
void trace_emit_canary(int slot, uint32_t synthetic_pid, const char *path);
void trace_emit_dns  (uint32_t pid, const char *domain, uint32_t ip_be);
void trace_emit_accept(int slot, uint32_t synthetic_pid, uint16_t conn_id,
                       uint32_t remote_ip_be, uint16_t remote_port_be,
                       uint16_t local_port_be);
void trace_emit_close (int slot, uint32_t synthetic_pid, uint16_t conn_id,
                       uint64_t rx_bytes, uint64_t tx_bytes);
/* sottrace · an inbound response_profile reply (HTTP/SSH/HTTPS) was served on conn_id.
 * local_port is host-order (80/22/443); reply_len is the bytes handed to TCP. */
void trace_emit_response_profile(int slot, uint16_t conn_id, uint16_t local_port, uint32_t reply_len);
/* sottrace · L14a · a canary screenshot view was mapped RO into a Tier-2 client. */
void trace_emit_canary_screenshot(int slot, uint16_t conn_id, uint32_t reply_len);
/* sottrace · L14b · synthetic input event(s) injected into a Tier-2 wl_seat client.
 * n_events is the count of wl_pointer/wl_keyboard/wl_touch events injected. */
void trace_emit_input_inject(int slot, uint16_t conn_id, uint32_t n_events);
/* sottrace · P2b · a fork-bomb cell was detected and quarantined/terminated.
 * synthetic_pid is the offending cell's display pid; attempts is its fork/clone count. */
void trace_emit_forkbomb_quarantined(int slot, uint32_t synthetic_pid, uint32_t attempts);
void trace_emit_isolated_write_drop(int slot, uint32_t synthetic_pid, const char *path);
/* sottrace · a Tier-2 sotbox opened a persistence-sensitive path (crontab, init,
 * cron.d, …) write-intent — the install is contained; surfaced distinctly in the
 * operator monitor so the persistence attempt reads as more than a generic FS open. */
void trace_emit_persistence(int slot, uint32_t synthetic_pid, const char *path);
/* sottrace · P3 · a backend FS op (open/read/write) with the resolved VFS path.
 * op = SG_EV_FS_OPEN / SG_EV_FS_READ / SG_EV_FS_WRITE. Read/write callers guard
 * on cursor==0 so it fires once per open (not per chunk). */
void trace_emit_fs(int slot, uint32_t pid, uint16_t op, uint64_t bytes,
                   const char *path);
/* sottrace · P3a · a network connection event into the trace rings. type =
 * SG_EV_NET_CONNECT (egress connect; SEND/RECV reserved). ip_be/port_be are
 * network byte order; conn_id is 0 for egress conns (no conn_id allocated). */
void trace_emit_net(int slot, uint32_t pid, uint16_t conn_id, uint16_t type,
                    uint32_t ip_be, uint16_t port_be, uint64_t bytes);

/* --- slot lifecycle --- */
void sottrace_reset_slot(int slot);      /* zero a reused slot's ring */

/* --- consumers --- */
/* Snapshot: fill out[] with the newest min(max,total) events across all
 * rings, NEWEST-FIRST by global seq. Returns count; sets *total_available
 * (so the caller can report truncation). Does NOT advance any cursor.
 * out must have room for at least max entries. */
uint32_t sottrace_peek_recent(sotguard_event_t *out, uint32_t max,
                              uint32_t *total_available);

/* Live: drain each ring's new entries (advancing per-ring owned tails) and
 * print one "[sottrace] ...\n" line per event. No-op when g_trace_live==0. */
void sottrace_drain_to_serial(void);

/* Format ONE event into buf as a single line (no trailing newline).
 * Shared by the live drain; exposed for the host unit test. */
void sottrace_format_line(char *buf, size_t n, const sotguard_event_t *e);

/* v2.8 · clean, severity-tagged dashboard line for the operator `watch` monitor
 * (no raw tsc/hex).  Sets buf[0]='\0' for events not worth surfacing. */
void sottrace_format_dashboard_line(char *buf, size_t n, const sotguard_event_t *e);

/* v2.8 · register a framebuffer sink for the dashboard feed (orch sets one that
 * paints to the console framebuffer).  Keeps trace.c free of orch symbols. */
void sottrace_set_fb_sink(void (*fn)(const char *line));

/* Register a sink for the LIVE serial drain's text lines (default → COM1 printf).
 * orch points this at COM2 (com2_trace_sink) so the audit stream gets its own
 * terminal instead of interleaving with the operator console on COM1. */
void sottrace_set_text_sink(void (*fn)(const char *line));

/* Emit a "[sottrace] tsc-anchor tsc=<TSC>\n" serial line. The host stamps it
 * with its own wall-clock on read, giving a coarse per-boot TSC<->wall map. */
void sottrace_emit_tsc_anchor(void);

/* Build a process->file disk-mutation graph into out (cap bytes): one
 * "G pid= tier= op= bytes= path=\n" line per SG_EV_FS_OPEN/READ/WRITE across all
 * rings. Returns bytes written. Consumed by tools/sottrace_graph.py. */
size_t sottrace_graph_build(char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* SOTTRACE_TRACE_H */
