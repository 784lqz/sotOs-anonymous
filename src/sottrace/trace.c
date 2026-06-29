/* sotOs · sottrace · ring + non-blocking emit + consumers. seL4-free. */
#include <sottrace/trace.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

int g_trace_live = 0;
int g_trace_to_fb = 0;   /* live drain also renders the clean dashboard to the framebuffer */
int g_orch_quiet = 0;    /* v2.9 · suppress the per-packet/syscall/mmap debug firehose (operator `watch`) */

/* Optional framebuffer sink for the dashboard feed.  trace.c stays seL4-/orch-free
 * (so the host unit test links): orch registers a sink that paints the line to the
 * framebuffer console.  NULL → no fb render (host test, or before registration). */
static void (*g_trace_fb_sink)(const char *line) = 0;
void sottrace_set_fb_sink(void (*fn)(const char *line)) { g_trace_fb_sink = fn; }

/* Optional text-line sink for the LIVE serial drain.  Default NULL → printf to
 * COM1 (unchanged · interleaved with the operator console).  orch registers a
 * sink that writes each audit line to COM2 (its own terminal) so the trace stream
 * stops sharing COM1 with the operator.  The sink receives the bare line and owns
 * its line-termination. */
static void (*g_trace_text_sink)(const char *line) = 0;
void sottrace_set_text_sink(void (*fn)(const char *line)) { g_trace_text_sink = fn; }

static void sottrace_emit_line(const char *line) {
    if (g_trace_text_sink) g_trace_text_sink(line);
    else printf("%s\n", line);   /* default · COM1 (orch stdio → seL4_DebugPutChar) */
}

/* TSC cycle clock. The =A form bootstrap.c uses is 32-bit (EAX:EDX); use the
 * explicit =a/=d 64-bit form so the full counter is captured on x86_64. */
static inline uint64_t sottrace_rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static sottrace_ring_t g_trace_rings[SOTTRACE_NRINGS];
static uint64_t        g_trace_tail[SOTTRACE_NRINGS];   /* live-drain owned cursors */
static uint64_t        g_trace_seq = 0;                 /* global monotonic order */

/* Map any slot to a valid ring index; out-of-range → system ring. */
static int ring_of(int slot) {
    if (slot < 0 || slot >= SOTTRACE_MAX_SLOTS) return SOTTRACE_SYS_RING;
    return slot;
}

/* SPSC publish (procd_event_publish pattern): RELAXED-load head, write the
 * entry, RELEASE-store head+1 so a reader sees the payload before the bump.
 * NO printf/malloc/lock/seL4_Call/WAL — this is the mid-fault-safe invariant. */
static void ring_publish(int ring_idx, const sotguard_event_t *ev) {
    sottrace_ring_t *r = &g_trace_rings[ring_idx];
    uint64_t head = __atomic_load_n(&r->head_seq, __ATOMIC_RELAXED);
    r->entries[head & (SOTTRACE_RING_N - 1)] = *ev;   /* POD struct copy */
    __atomic_store_n(&r->head_seq, head + 1, __ATOMIC_RELEASE);
}

void trace_emit_enter(int slot, uint32_t synthetic_pid, uint32_t sysno,
                      const uint64_t args[6], uint64_t rip) {
    sotguard_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid;
    ev.type = SG_EV_SYSCALL_ENTER;
    ev.timestamp = sottrace_rdtsc();
    ev.detail.syscall.sysno = sysno;
    ev.detail.syscall.ret = 0;
    ev.detail.syscall.rip = rip;
    for (int i = 0; i < 6; ++i) ev.detail.syscall.args[i] = args ? args[i] : 0;
    ring_publish(ring_of(slot), &ev);
}

void trace_emit_exit(int slot, uint32_t synthetic_pid, uint32_t sysno,
                     int64_t ret, uint64_t rip) {
    sotguard_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid;
    ev.type = SG_EV_SYSCALL_EXIT;
    ev.timestamp = sottrace_rdtsc();
    ev.detail.syscall.sysno = sysno;
    ev.detail.syscall.ret = ret;
    ev.detail.syscall.rip = rip;
    ring_publish(ring_of(slot), &ev);
}

void trace_emit_tier(int slot, uint32_t synthetic_pid, uint32_t old_tier,
                     uint32_t new_tier) {
    sotguard_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid;
    ev.type = SG_EV_TIER_ASSIGN;
    ev.timestamp = sottrace_rdtsc();
    ev.detail.tier.old_tier = old_tier;
    ev.detail.tier.new_tier = new_tier;
    ring_publish(ring_of(slot), &ev);
}

void trace_emit_canary(int slot, uint32_t synthetic_pid, const char *path) {
    sotguard_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid;
    ev.type = SG_EV_CANARY_READ;
    ev.timestamp = sottrace_rdtsc();
    if (path) strncpy(ev.detail.fs.path, path, sizeof(ev.detail.fs.path) - 1);
    ring_publish(ring_of(slot), &ev);
}

void trace_emit_dns(uint32_t pid, const char *domain, uint32_t ip_be) {
    sotguard_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.pid = pid;
    ev.type = SG_EV_DNS_LOOKUP;
    ev.timestamp = sottrace_rdtsc();
    if (domain) strncpy(ev.detail.dns.domain, domain, sizeof(ev.detail.dns.domain) - 1);
    ev.detail.dns.ip_be = ip_be;
    ring_publish(SOTTRACE_SYS_RING, &ev);   /* unattributed → system ring */
}

void trace_emit_accept(int slot, uint32_t synthetic_pid, uint16_t conn_id,
                       uint32_t remote_ip_be, uint16_t remote_port_be,
                       uint16_t local_port_be) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid; ev.type = SG_EV_INBOUND_ACCEPT;
    ev.conn_id = conn_id; ev.timestamp = sottrace_rdtsc();
    ev.detail.net.ip_be = remote_ip_be;
    ev.detail.net.port_be = remote_port_be;
    ev.detail.net.pad = local_port_be;     /* reuse pad to carry the local port */
    ring_publish(ring_of(slot), &ev);
}
void trace_emit_close(int slot, uint32_t synthetic_pid, uint16_t conn_id,
                      uint64_t rx_bytes, uint64_t tx_bytes) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid; ev.type = SG_EV_CONN_CLOSE;
    ev.conn_id = conn_id; ev.timestamp = sottrace_rdtsc();
    ev.detail.net.len = rx_bytes;              /* rx (full u64) in net.len */
    ev.detail.net.ip_be = (uint32_t)tx_bytes;  /* tx low-32 in net.ip_be (>4GB truncated · fine for canary sessions) */
    ring_publish(ring_of(slot), &ev);
}
void trace_emit_response_profile(int slot, uint16_t conn_id, uint16_t local_port, uint32_t reply_len) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.type = SG_EV_RESPONSE_PROFILE_SERVED;
    ev.conn_id = conn_id; ev.timestamp = sottrace_rdtsc();
    ev.detail.net.port_be = local_port;        /* host-order local port, stored as-is */
    ev.detail.net.len = reply_len;             /* bytes served back to the adversary */
    ring_publish(ring_of(slot), &ev);
}
void trace_emit_canary_screenshot(int slot, uint16_t conn_id, uint32_t reply_len) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.type = SG_EV_CANARY_SCREENSHOT;
    ev.conn_id = conn_id; ev.timestamp = sottrace_rdtsc();
    ev.detail.net.len = reply_len;             /* bytes of canary pixels exposed to the client */
    ring_publish(ring_of(slot), &ev);
}
void trace_emit_input_inject(int slot, uint16_t conn_id, uint32_t n_events) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.type = SG_EV_INPUT_INJECT;
    ev.conn_id = conn_id; ev.timestamp = sottrace_rdtsc();
    ev.detail.net.len = n_events;              /* event count injected into the Tier-2 seat */
    ring_publish(ring_of(slot), &ev);
}
void trace_emit_forkbomb_quarantined(int slot, uint32_t synthetic_pid, uint32_t attempts) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid; ev.type = SG_EV_FORKBOMB_QUARANTINED;
    ev.timestamp = sottrace_rdtsc();
    ev.detail.net.len = attempts;              /* cumulative fork/clone attempts at quarantine */
    ring_publish(ring_of(slot), &ev);
}
void trace_emit_isolated_write_drop(int slot, uint32_t synthetic_pid, const char *path) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid; ev.type = SG_EV_ISOLATED_WRITE_DROP;
    ev.timestamp = sottrace_rdtsc();
    if (path) strncpy(ev.detail.fs.path, path, sizeof(ev.detail.fs.path) - 1);
    ring_publish(ring_of(slot), &ev);
}
void trace_emit_persistence(int slot, uint32_t synthetic_pid, const char *path) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.pid = synthetic_pid; ev.type = SG_EV_PERSISTENCE_INSTALL;
    ev.timestamp = sottrace_rdtsc();
    if (path) strncpy(ev.detail.fs.path, path, sizeof(ev.detail.fs.path) - 1);
    ring_publish(ring_of(slot), &ev);
}

/* sottrace · P3 · a backend FS operation (open/read/write) with the resolved
 * VFS path attached. op is one of SG_EV_FS_OPEN / SG_EV_FS_READ / SG_EV_FS_WRITE.
 * Emitted from the sotfs/static backend ops (the handle carries the path);
 * read/write callers guard on cursor==0 so it fires once per open, not per
 * chunk (a 128-entry ring would otherwise lap and evict the conn's ACCEPT). */
void trace_emit_fs(int slot, uint32_t pid, uint16_t op, uint64_t bytes,
                   const char *path) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.pid = pid; ev.type = op;
    ev.timestamp = sottrace_rdtsc();
    ev.detail.fs.bytes = bytes;
    if (path) strncpy(ev.detail.fs.path, path, sizeof(ev.detail.fs.path) - 1);
    ring_publish(ring_of(slot), &ev);
}

/* sottrace · P3a · a network connection event (egress CONNECT primarily; SEND/
 * RECV reserved). ip_be/port_be are network byte order (as stored on the wire /
 * in sockaddr_in); the formatter decomposes them LSB-first like the ACCEPT case.
 * conn_id is 0 for egress conns (tcp_active_open conns carry no conn_id). */
void trace_emit_net(int slot, uint32_t pid, uint16_t conn_id, uint16_t type,
                    uint32_t ip_be, uint16_t port_be, uint64_t bytes) {
    sotguard_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.pid = pid; ev.type = type;
    ev.conn_id = conn_id; ev.timestamp = sottrace_rdtsc();
    ev.detail.net.ip_be = ip_be;
    ev.detail.net.port_be = port_be;
    ev.detail.net.pad = 0;
    ev.detail.net.len = bytes;
    ring_publish(ring_of(slot), &ev);
}

void sottrace_reset_slot(int slot) {
    int idx = ring_of(slot);
    if (idx == SOTTRACE_SYS_RING && (slot < 0 || slot >= SOTTRACE_MAX_SLOTS)) return;
    memset(&g_trace_rings[idx], 0, sizeof(g_trace_rings[idx]));
    g_trace_tail[idx] = 0;
}

uint32_t sottrace_peek_recent(sotguard_event_t *out, uint32_t max,
                              uint32_t *total_available) {
    uint32_t count = 0;
    uint64_t total = 0;
    if (max == 0) { if (total_available) *total_available = 0; return 0; }
    for (int rdx = 0; rdx < SOTTRACE_NRINGS; ++rdx) {
        sottrace_ring_t *r = &g_trace_rings[rdx];
        uint64_t head = __atomic_load_n(&r->head_seq, __ATOMIC_ACQUIRE);
        uint64_t used = head < SOTTRACE_RING_N ? head : SOTTRACE_RING_N;
        total += used;
        for (uint64_t s = head - used; s < head; ++s) {
            const sotguard_event_t *e = &r->entries[s & (SOTTRACE_RING_N - 1)];
            /* insert into out[0..count), kept sorted DESC by timestamp, cap max */
            if (count < max) {
                uint32_t i = count++;
                out[i] = *e;
                while (i > 0 && out[i].timestamp > out[i - 1].timestamp) {
                    sotguard_event_t t = out[i]; out[i] = out[i - 1]; out[i - 1] = t; i--;
                }
            } else if (e->timestamp > out[count - 1].timestamp) {
                uint32_t i = count - 1;
                out[i] = *e;
                while (i > 0 && out[i].timestamp > out[i - 1].timestamp) {
                    sotguard_event_t t = out[i]; out[i] = out[i - 1]; out[i - 1] = t; i--;
                }
            }
        }
    }
    if (total_available) *total_available = (uint32_t)total; /* total <= NRINGS*RING_N = 1152, fits u32 */
    return count;
}

/* Emit a serial line carrying the current TSC. The host stamps it with its own
 * wall-clock on read, giving a coarse TSC<->wall reference per boot. */
void sottrace_emit_tsc_anchor(void) {
    printf("[sottrace] tsc-anchor tsc=%llu\n", (unsigned long long)sottrace_rdtsc());
}

void sottrace_format_line(char *buf, size_t n, const sotguard_event_t *e) {
    switch (e->type) {
        case SG_EV_SYSCALL_ENTER:
            snprintf(buf, n,
                "[sottrace] tsc=%llu pid=%u ENTER sys=%u args=%llx,%llx,%llx,%llx,%llx,%llx rip=0x%llx",
                (unsigned long long)e->timestamp, e->pid, e->detail.syscall.sysno,
                (unsigned long long)e->detail.syscall.args[0],
                (unsigned long long)e->detail.syscall.args[1],
                (unsigned long long)e->detail.syscall.args[2],
                (unsigned long long)e->detail.syscall.args[3],
                (unsigned long long)e->detail.syscall.args[4],
                (unsigned long long)e->detail.syscall.args[5],
                (unsigned long long)e->detail.syscall.rip);
            break;
        case SG_EV_SYSCALL_EXIT:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u EXIT  sys=%u ret=%lld rip=0x%llx",
                (unsigned long long)e->timestamp, e->pid, e->detail.syscall.sysno,
                (long long)e->detail.syscall.ret,
                (unsigned long long)e->detail.syscall.rip);
            break;
        case SG_EV_TIER_ASSIGN:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u TIER  %u->%u",
                (unsigned long long)e->timestamp, e->pid,
                e->detail.tier.old_tier, e->detail.tier.new_tier);
            break;
        case SG_EV_CANARY_READ:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u CANARY path=%s",
                (unsigned long long)e->timestamp, e->pid, e->detail.fs.path);
            break;
        case SG_EV_DNS_LOOKUP:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u DNS   %s -> 0x%x",
                (unsigned long long)e->timestamp, e->pid,
                e->detail.dns.domain, e->detail.dns.ip_be);
            break;
        case SG_EV_INBOUND_ACCEPT: {
            uint32_t ip = e->detail.net.ip_be;
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u conn=%u ACCEPT from %u.%u.%u.%u:%u -> :%u",
                (unsigned long long)e->timestamp, e->pid, e->conn_id,
                ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF,
                __builtin_bswap16(e->detail.net.port_be), __builtin_bswap16(e->detail.net.pad));
            break; }
        case SG_EV_NET_CONNECT:
        case SG_EV_NET_SEND:
        case SG_EV_NET_RECV: {
            const char *op = e->type == SG_EV_NET_CONNECT ? "CONNECT" :
                             e->type == SG_EV_NET_SEND     ? "SEND"    : "RECV";
            uint32_t ip = e->detail.net.ip_be;
            snprintf(buf, n,
                "[sottrace] tsc=%llu pid=%u NET %s %u.%u.%u.%u:%u bytes=%llu conn=%u",
                (unsigned long long)e->timestamp, e->pid, op,
                ip&0xFF,(ip>>8)&0xFF,(ip>>16)&0xFF,(ip>>24)&0xFF,
                __builtin_bswap16(e->detail.net.port_be),
                (unsigned long long)e->detail.net.len, e->conn_id);
            break; }
        case SG_EV_CONN_CLOSE:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u conn=%u CLOSE rx=%llu tx=%u",
                (unsigned long long)e->timestamp, e->pid, e->conn_id,
                (unsigned long long)e->detail.net.len, e->detail.net.ip_be);
            break;
        case SG_EV_ISOLATED_WRITE_DROP:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u ISOLATED_WRITE_DROP path=%s",
                (unsigned long long)e->timestamp, e->pid, e->detail.fs.path);
            break;
        case SG_EV_PERSISTENCE_INSTALL:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u PERSISTENCE_INSTALL path=%s",
                (unsigned long long)e->timestamp, e->pid, e->detail.fs.path);
            break;
        case SG_EV_FS_OPEN:
        case SG_EV_FS_READ:
        case SG_EV_FS_WRITE: {
            const char *fop = e->type == SG_EV_FS_OPEN  ? "OPEN"  :
                              e->type == SG_EV_FS_READ   ? "READ"  : "WRITE";
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u FS %s bytes=%llu path=%s",
                (unsigned long long)e->timestamp, e->pid, fop,
                (unsigned long long)e->detail.fs.bytes, e->detail.fs.path);
            break; }
        case SG_EV_RESPONSE_PROFILE_SERVED: {
            const char *proto = e->detail.net.port_be == 80  ? "HTTP"  :
                                e->detail.net.port_be == 22  ? "SSH"   :
                                e->detail.net.port_be == 443 ? "HTTPS" : "?";
            snprintf(buf, n, "[sottrace] tsc=%llu conn=%u RESPONSE_PROFILE %s :%u served %llu bytes",
                (unsigned long long)e->timestamp, e->conn_id, proto,
                e->detail.net.port_be, (unsigned long long)e->detail.net.len);
            break; }
        case SG_EV_CANARY_SCREENSHOT:
            snprintf(buf, n, "[sottrace] tsc=%llu conn=%u CANARY_SCREENSHOT served %llu bytes",
                (unsigned long long)e->timestamp, e->conn_id,
                (unsigned long long)e->detail.net.len);
            break;
        case SG_EV_INPUT_INJECT:
            snprintf(buf, n, "[sottrace] tsc=%llu conn=%u INPUT_INJECT %llu events",
                (unsigned long long)e->timestamp, e->conn_id,
                (unsigned long long)e->detail.net.len);
            break;
        case SG_EV_FORKBOMB_QUARANTINED:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u FORKBOMB_QUARANTINED attempts=%llu",
                (unsigned long long)e->timestamp, e->pid,
                (unsigned long long)e->detail.net.len);
            break;
        default:
            snprintf(buf, n, "[sottrace] tsc=%llu pid=%u kind=%u",
                (unsigned long long)e->timestamp, e->pid, e->type);
            break;
    }
}

/* v2.8 · the DECEPTION MONITOR view: a clean, severity-tagged one-liner per
 * forensic event (no raw tsc/hex), for the operator `watch` dashboard rendered
 * to the framebuffer.  Sets buf[0]='\0' for events not worth surfacing.
 *
 * v2.9 · ANSI-colored by severity (the console_fb framebuffer parses SGR), so
 * the live monitor reads as a threat feed: RED = attacker hit something it
 * shouldn't (containment / C2 / isolation), YELLOW = bait taken (canary /
 * honey), CYAN = recon (fs/dns), GREEN = a new inbound connection.  Only the FB
 * sink consumes this formatter, so the codes never reach the serial. */
#define DASH_RED    "\033[91m"   /* bright red · contained / C2 / isolated      */
#define DASH_YELLOW "\033[33m"   /* bait taken · canary read / honey served     */
#define DASH_CYAN   "\033[36m"   /* recon · fs open/read, dns                    */
#define DASH_GREEN  "\033[32m"   /* a new attacker connection                    */
#define DASH_RST    "\033[0m"
void sottrace_format_dashboard_line(char *buf, size_t n, const sotguard_event_t *e) {
    switch (e->type) {
        case SG_EV_CANARY_READ:
            snprintf(buf, n, DASH_YELLOW "  CANARY READ    pid=%-3u %s" DASH_RST, e->pid, e->detail.fs.path);
            break;
        case SG_EV_ISOLATED_WRITE_DROP:
            snprintf(buf, n, DASH_RED "  CONTAINED      pid=%-3u write denied: %s" DASH_RST, e->pid, e->detail.fs.path);
            break;
        case SG_EV_PERSISTENCE_INSTALL:
            snprintf(buf, n, DASH_RED "  PERSIST        pid=%-3u install contained: %s" DASH_RST, e->pid, e->detail.fs.path);
            break;
        case SG_EV_TIER_ASSIGN:
            snprintf(buf, n, "%s  TIER           pid=%-3u %u -> %u%s" DASH_RST,
                     e->detail.tier.new_tier >= 2 ? DASH_RED : DASH_CYAN, e->pid,
                     e->detail.tier.old_tier, e->detail.tier.new_tier,
                     e->detail.tier.new_tier >= 2 ? "  (ISOLATED)" : "");
            break;
        case SG_EV_INBOUND_ACCEPT: {
            uint32_t ip = e->detail.net.ip_be;
            snprintf(buf, n, DASH_GREEN "  INBOUND        conn=%-2u %u.%u.%u.%u:%u -> :%u" DASH_RST, e->conn_id,
                     ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF,
                     __builtin_bswap16(e->detail.net.port_be), __builtin_bswap16(e->detail.net.pad));
            break; }
        case SG_EV_FS_OPEN:
            snprintf(buf, n, DASH_CYAN "  RECON open     pid=%-3u %s" DASH_RST, e->pid, e->detail.fs.path);
            break;
        case SG_EV_FS_READ:
            snprintf(buf, n, DASH_CYAN "  RECON read     pid=%-3u %s (%llu B)" DASH_RST, e->pid,
                     e->detail.fs.path, (unsigned long long)e->detail.fs.bytes);
            break;
        case SG_EV_FS_WRITE:
            snprintf(buf, n, DASH_YELLOW "  WRITE          pid=%-3u %s (%llu B)" DASH_RST, e->pid,
                     e->detail.fs.path, (unsigned long long)e->detail.fs.bytes);
            break;
        case SG_EV_DNS_LOOKUP:
            snprintf(buf, n, DASH_CYAN "  DNS            pid=%-3u %s" DASH_RST, e->pid, e->detail.dns.domain);
            break;
        case SG_EV_NET_CONNECT: {
            uint32_t ip = e->detail.net.ip_be;
            snprintf(buf, n, DASH_RED "  EGRESS (C2?)   pid=%-3u %u.%u.%u.%u:%u" DASH_RST, e->pid,
                     ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF,
                     __builtin_bswap16(e->detail.net.port_be));
            break; }
        /* SG_EV_RESPONSE_PROFILE_SERVED + SG_EV_CONN_CLOSE are transport, not
         * attacker actions (every SSH keystroke echo is a tiny response) — they'd
         * flood the monitor, so they fall through to the default (not surfaced). */
        case SG_EV_CANARY_SCREENSHOT:
            snprintf(buf, n, DASH_YELLOW "  HONEY SCREEN   conn=%-2u served %llu B" DASH_RST, e->conn_id,
                     (unsigned long long)e->detail.net.len);
            break;
        case SG_EV_INPUT_INJECT:
            snprintf(buf, n, DASH_CYAN "  INPUT INJECT   conn=%-2u %llu events" DASH_RST, e->conn_id,
                     (unsigned long long)e->detail.net.len);
            break;
        case SG_EV_FORKBOMB_QUARANTINED:
            snprintf(buf, n, DASH_RED "  FORKBOMB       pid=%-3u quarantined (%llu attempts)" DASH_RST,
                     e->pid, (unsigned long long)e->detail.net.len);
            break;
        default:
            if (n) buf[0] = '\0';   /* syscall flood / unknown → not surfaced */
            break;
    }
}

void sottrace_drain_to_serial(void) {
    if (!g_trace_live) return;
    char line[256];   /* ENTER worst-case ~201 chars + NUL; 256 gives headroom */
    for (int rdx = 0; rdx < SOTTRACE_NRINGS; ++rdx) {
        sottrace_ring_t *r = &g_trace_rings[rdx];
        uint64_t head = __atomic_load_n(&r->head_seq, __ATOMIC_ACQUIRE);
        uint64_t *tail = &g_trace_tail[rdx];
        if (*tail > head) { *tail = head; continue; }
        uint64_t lag = head - *tail;
        if (lag > SOTTRACE_RING_N) {
            /* consumer lapped · snap to the freshest N and report the drop */
            uint64_t dropped = lag - SOTTRACE_RING_N;
            char lost[64];
            snprintf(lost, sizeof(lost), "[sottrace] (lost %llu events on ring %d)",
                     (unsigned long long)dropped, rdx);
            sottrace_emit_line(lost);
            *tail = head - SOTTRACE_RING_N;
        }
        while (*tail < head) {
            const sotguard_event_t *e = &r->entries[*tail & (SOTTRACE_RING_N - 1)];
            /* live drain emits only forensic events — skip the per-syscall flood
             * (it would swamp the serial and stall the boot demo). `sottrace
             * recent` still shows ENTER/EXIT from the snapshot path. */
            if (e->type == SG_EV_SYSCALL_ENTER || e->type == SG_EV_SYSCALL_EXIT) {
                (*tail)++;
                continue;
            }
            /* quiet (operator `watch`): the per-keystroke SSH response-profile +
             * conn-close are transport noise — skip the raw serial line for them
             * (they are already dropped from the dashboard). */
            int noisy = (e->type == SG_EV_RESPONSE_PROFILE_SERVED || e->type == SG_EV_CONN_CLOSE);
            if (!(g_orch_quiet && noisy)) {
                sottrace_format_line(line, sizeof(line), e);
                sottrace_emit_line(line); /* COM1 printf by default · COM2 sink when registered */
            }
            /* v2.8 · the operator `watch` dashboard: render the clean tagged view
             * to the framebuffer (GTK window) via the registered sink, so the
             * operator sees the attacker's actions live without the raw tsc/hex. */
            if (g_trace_to_fb && g_trace_fb_sink) {
                char dl[160];
                sottrace_format_dashboard_line(dl, sizeof(dl), e);
                if (dl[0]) g_trace_fb_sink(dl);
            }
            (*tail)++;
        }
    }
}

/* Resolve the latest tier for a pid by scanning every ring for the most recent
 * (highest-TSC) SG_EV_TIER_ASSIGN naming that pid. Default 0 if none seen. */
static int graph_tier_of(uint32_t pid) {
    int tier = 0;
    uint64_t best_ts = 0;
    for (int rdx = 0; rdx < SOTTRACE_NRINGS; ++rdx) {
        sottrace_ring_t *r = &g_trace_rings[rdx];
        uint64_t head = __atomic_load_n(&r->head_seq, __ATOMIC_ACQUIRE);
        uint64_t used = head < SOTTRACE_RING_N ? head : SOTTRACE_RING_N;
        for (uint64_t s = head - used; s < head; ++s) {
            const sotguard_event_t *e = &r->entries[s & (SOTTRACE_RING_N - 1)];
            if (e->type == SG_EV_TIER_ASSIGN && e->pid == pid &&
                e->timestamp >= best_ts) {
                best_ts = e->timestamp;
                tier = (int)e->detail.tier.new_tier;
            }
        }
    }
    return tier;
}

/* Build a process->file disk-mutation graph: one "G pid= tier= op= bytes=
 * path=" line per SG_EV_FS_OPEN/READ/WRITE across all rings (newest-first walk,
 * matching sottrace_peek_recent's idiom). Returns bytes written (NUL-included
 * not guaranteed past cap). For the host tools/sottrace_graph.py consumer. */
size_t sottrace_graph_build(char *out, size_t cap) {
    if (!out || cap == 0) return 0;
    size_t used_out = 0;
    out[0] = '\0';
    for (int rdx = 0; rdx < SOTTRACE_NRINGS; ++rdx) {
        sottrace_ring_t *r = &g_trace_rings[rdx];
        uint64_t head = __atomic_load_n(&r->head_seq, __ATOMIC_ACQUIRE);
        uint64_t ring_used = head < SOTTRACE_RING_N ? head : SOTTRACE_RING_N;
        /* newest-first: walk from the freshest entry backwards */
        for (uint64_t k = 0; k < ring_used; ++k) {
            uint64_t s = head - 1 - k;
            const sotguard_event_t *e = &r->entries[s & (SOTTRACE_RING_N - 1)];
            if (e->type != SG_EV_FS_OPEN && e->type != SG_EV_FS_READ &&
                e->type != SG_EV_FS_WRITE) continue;
            const char *op = e->type == SG_EV_FS_OPEN  ? "OPEN"  :
                             e->type == SG_EV_FS_READ   ? "READ"  : "WRITE";
            int tier = graph_tier_of(e->pid);
            char line[160];
            int ln = snprintf(line, sizeof(line),
                "G pid=%u tier=%d op=%s bytes=%llu path=%s\n",
                e->pid, tier, op,
                (unsigned long long)e->detail.fs.bytes, e->detail.fs.path);
            if (ln < 0) continue;
            if (used_out + (size_t)ln >= cap) goto done;  /* leave room for NUL */
            memcpy(out + used_out, line, (size_t)ln);
            used_out += (size_t)ln;
        }
    }
done:
    out[used_out] = '\0';
    return used_out;
}
