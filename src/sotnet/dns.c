/*
 * sotOs · sotNet-ε · DNS deception · synth A record table.
 *
 * Phase 1 minimal: in-memory canary-domain table.  When a Tier 2
 * sotbox does getaddrinfo (eventually · LUCAS-side socket handler
 * needs wiring in Phase 2), the lookup goes here.  Returns an IP
 * we control (the synth server's IP) for known IoC domains.
 *
 * Phase 2 will parse actual DNS packets (UDP port 53 traffic) and
 * synthesize replies.
 */
#include <sotnet/dns.h>
#include <sotnet/sotnet.h>
#include <sotguard/event.h>
#include <string.h>
#include <stdio.h>
#include <sottrace/trace.h>

/* SG-NET Phase 2 · per-emit monotonic timestamp for sotGuard event bus.
 * Static, file-local; ticks once per canary-domain HIT.  See
 * include/sotguard/event.h line 17 for timestamp semantics. */
static uint64_t g_sg_dns_ts = 0;

/* sotNet-ε Phase 2 · anomaly notify hook · implemented in orch/backends_sotnet.c
 * (which has full seL4 includes).  Declared here as a weak symbol so dns.c
 * compiles without seL4 headers · same pattern as sotfs_graph_curvature_anomaly_notify.
 * DNS-PID-PREWORK · pid threaded so a future sotbox-side interceptor can pass
 * st->synthetic_pid; today all callers pass 0 (operator / bootstrap). */
void sotnet_dns_anomaly_notify(uint32_t pid, const char *domain, uint32_t ip_be) __attribute__((weak));
void sotnet_dns_anomaly_notify(uint32_t pid, const char *domain, uint32_t ip_be)
{
    (void)pid; (void)domain; (void)ip_be; /* default no-op stub */
}

#define DNS_MAX_CANARY_ENTRIES 16

typedef struct {
    int      in_use;
    char     domain[64];
    uint32_t answer_ip_be;
} dns_canary_entry_t;

static dns_canary_entry_t g_canary_domains[DNS_MAX_CANARY_ENTRIES];
static int g_initialised = 0;

/* Single in-flight forward slot (the forwarder is synchronous — at most one
 * outstanding query). Armed by dns_forward_query (Task 3), filled by the
 * sotnet_poll UDP-inbound hook when a matching :53 response lands. */
static volatile int      g_dns_fwd_armed    = 0;
static volatile uint16_t g_dns_fwd_txid     = 0;   /* expected DNS ID (host order) */
static volatile size_t   g_dns_fwd_resp_len = 0;
static uint8_t           g_dns_fwd_resp[512];

/* Called from sotnet_poll for every inbound UDP:53 datagram. udp_payload/len
 * are the UDP DATA (the DNS message). If a forward is armed and the DNS ID
 * matches, stash the message and signal the spinner. Cheap + safe when not armed. */
void dns_capture_udp_response(const uint8_t *udp_payload, size_t len)
{
    if (!g_dns_fwd_armed || len < 12 || len > sizeof(g_dns_fwd_resp)) return;
    uint16_t id = (uint16_t)(((uint16_t)udp_payload[0] << 8) | udp_payload[1]);
    if (id != g_dns_fwd_txid) return;        /* not our query */
    memcpy(g_dns_fwd_resp, udp_payload, len);
    g_dns_fwd_resp_len = len;
    g_dns_fwd_armed = 0;                      /* one-shot */
}

/* Forward `query` (a full DNS message) to the real nameserver (1.1.1.1, which
 * matches /etc/resolv.conf's nameserver in backends_static.c — keep them in
 * sync) over SLIRP and return the real response in `out`. Returns response
 * length, or 0 on timeout/error.
 *
 * SYNCHRONOUS + single-threaded: this function arms the capture slot, sends the
 * query, then spins sotnet_poll() ITSELF. sotnet_poll() calls
 * dns_capture_udp_response() on this same call stack when the answer arrives, so
 * there is no real concurrency and no memory-ordering hazard — the volatile
 * slot fields + the strict call sequence (memcpy then armed=0, observed by the
 * very next loop iteration) are sufficient. Only one forward may be in flight. */
size_t dns_forward_query(const uint8_t *query, size_t qlen, uint32_t pid,
                         uint8_t *out, size_t out_cap)
{
    if (!query || qlen < 12 || !out || out_cap == 0) return 0;

    /* network-byte-order ports (this code runs on x86_64 little-endian). */
    uint16_t port53_be   = (uint16_t)((53u   >> 8) | ((53u   & 0xff) << 8));
    uint16_t port1024_be = (uint16_t)((1024u >> 8) | ((1024u & 0xff) << 8));
    uint16_t txid = (uint16_t)(((uint16_t)query[0] << 8) | query[1]);

    /* Nameservers tried in order.  1.1.1.1 is the real public upstream (deception:
     * the honeypot looks like it queries a real resolver).  DNS-over-UDP has NO
     * retransmit, so a single dropped query OR reply — common over WSL2's SLIRP
     * NAT out to the public internet — made the forward time out and `apk update`
     * fail with "DNS lookup error" intermittently.  Fix: RE-SEND on loss, and
     * fall back to QEMU SLIRP's built-in DNS proxy 10.0.2.3 (it forwards to the
     * HOST resolver, reliable even when direct 1.1.1.1 egress is lossy/blocked),
     * so resolution still succeeds.  IPs are network byte order, a|b<<8|c<<16|
     * d<<24 (cf. route.c gw 0x0202000A == 10.0.2.2). */
    static const uint32_t ns_list[] = {
        0x01010101u, /* 1.1.1.1   · real public resolver */
        0x0302000Au, /* 10.0.2.3  · SLIRP proxy → host resolver (reliable fallback) */
    };

    for (unsigned ns = 0; ns < sizeof(ns_list) / sizeof(ns_list[0]); ++ns) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            g_dns_fwd_txid     = txid;
            g_dns_fwd_resp_len = 0;
            g_dns_fwd_armed    = 1;

            sotnet_send_udp(ns_list[ns], port53_be, port1024_be, query, qlen, pid);

            /* ~750k polls/attempt covers a cold real-internet RTT over SLIRP;
             * 4 attempts ≈ the prior single-shot 3M budget.  Bounded so a
             * genuinely-dead resolver still falls through to the timeout path
             * rather than hanging the single-threaded orch. */
            for (int i = 0; i < 750000; ++i) {
                (void)sotnet_poll();
                if (g_dns_fwd_resp_len > 0) break;
            }
            g_dns_fwd_armed = 0;

            size_t n = g_dns_fwd_resp_len;
            if (n > 0) {
                if (n > out_cap) return 0;
                memcpy(out, g_dns_fwd_resp, n);
                return n;
            }
        }
    }
    return 0;
}

static void dns_seed_canary(void) {
    if (g_initialised) return;
    g_initialised = 1;
    /* Canary domains · operator-installed IoCs.  Anomaly adds these
     * dynamically in Phase 2; Phase 1 seeds a fixed set. */
    /* Canary domains read as benign-but-real infra (CDN/telemetry/auth/object-store)
     * an attacker's tooling might actually contact — NOT self-describing .example
     * names ("malicious-c2.example" spelled the trap + .example is IANA reserved).
     * All resolve to the synth server (10.0.2.15) and still trip the IoC. */
    struct { const char *d; uint32_t ip; } seeds[] = {
        { "cdn-edge-telemetry.net.",   0x0F02000A },  /* 10.0.2.15 · synth server (local) */
        { "sync-api.cloudmetrics.io.", 0x0F02000A },
        { "assets.fastcdn-static.com.",0x0F02000A },
        { "auth-gw.idp-verify.net.",   0x0F02000A },
    };
    for (size_t i = 0; i < sizeof(seeds)/sizeof(seeds[0]); ++i) {
        g_canary_domains[i].in_use = 1;
        strncpy(g_canary_domains[i].domain, seeds[i].d, sizeof(g_canary_domains[i].domain) - 1);
        g_canary_domains[i].answer_ip_be = seeds[i].ip;
    }
    printf("[dns] sotNet-ε · seeded %zu canary domain entries\n",
           sizeof(seeds)/sizeof(seeds[0]));
}

/* Pure table lookup · NO anomaly/sotguard/trace side effects.  Returns 0 on a
 * canary HIT (out_ip_be set), -1 otherwise.  Used by the data-path UDP:53
 * interceptor so it can ENQUEUE the synth answer (unblock the probe's recvfrom)
 * BEFORE emitting the audit notify · the notify does a synchronous seL4_Call to
 * orch's anomaly EP, which must not gate delivery of the DNS reply. */
int dns_lookup_quiet(const char *domain, uint32_t *out_ip_be) {
    dns_seed_canary();
    for (int i = 0; i < DNS_MAX_CANARY_ENTRIES; ++i) {
        if (g_canary_domains[i].in_use && strcmp(g_canary_domains[i].domain, domain) == 0) {
            *out_ip_be = g_canary_domains[i].answer_ip_be;
            return 0;
        }
    }
    return -1;
}

/* Emit the audit side effects (anomaly-ext IPC + sotguard + sottrace) for a
 * canary-domain HIT.  Split out of dns_lookup so the data-path interceptor can
 * defer it until after the synth reply is enqueued. */
void dns_lookup_audit(uint32_t pid, const char *domain, uint32_t ip_be) {
    printf("[dns] synth A record · %s → %u.%u.%u.%u\n",
           domain,
           ip_be & 0xFF, (ip_be >> 8) & 0xFF,
           (ip_be >> 16) & 0xFF, (ip_be >> 24) & 0xFF);
    sotnet_dns_anomaly_notify(pid, domain, ip_be);
    {
        sotguard_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = (uint32_t)pid;
        ev.type = SG_EV_DNS_LOOKUP;
        ev.timestamp = ++g_sg_dns_ts;
        strncpy(ev.detail.dns.domain, domain, sizeof(ev.detail.dns.domain) - 1);
        ev.detail.dns.ip_be = ip_be;
        (void)sotguard_emit(&ev);
    }
    trace_emit_dns(pid, domain, ip_be);
}

int dns_lookup(uint32_t pid, const char *domain, uint32_t *out_ip_be) {
    dns_seed_canary();
    for (int i = 0; i < DNS_MAX_CANARY_ENTRIES; ++i) {
        if (g_canary_domains[i].in_use && strcmp(g_canary_domains[i].domain, domain) == 0) {
            *out_ip_be = g_canary_domains[i].answer_ip_be;
            printf("[dns] synth A record · %s → %u.%u.%u.%u\n",
                   domain,
                   *out_ip_be & 0xFF, (*out_ip_be >> 8) & 0xFF,
                   (*out_ip_be >> 16) & 0xFF, (*out_ip_be >> 24) & 0xFF);
            /* sotNet-ε Phase 2 · audit-log canary-domain lookup via anomaly-ext.
             * Weak hook · no-op when sotnet is linked without lucas backends.
             * DNS-PID-PREWORK · pid forwarded so the anomaly rule can promote
             * the caller to Tier-2 when a real sotbox pid arrives via the
             * future lucas_sys_sendto UDP:53 interceptor. */
            sotnet_dns_anomaly_notify(pid, domain, *out_ip_be);

            /* SG-NET Phase 2 · ADDITIVE sotGuard event-bus emit.  Feeds the
             * in-orch correlation ring alongside the anomaly-ext IPC above.
             * Best-effort lossy. */
            {
                sotguard_event_t ev;
                memset(&ev, 0, sizeof(ev));
                ev.pid = (uint32_t)pid;
                ev.type = SG_EV_DNS_LOOKUP;
                ev.timestamp = ++g_sg_dns_ts;
                strncpy(ev.detail.dns.domain, domain,
                        sizeof(ev.detail.dns.domain) - 1);
                ev.detail.dns.ip_be = *out_ip_be;
                (void)sotguard_emit(&ev);
            }
            /* sottrace · canary-domain lookup → system ring (no slot context
             * in the poll-loop resolution path). */
            trace_emit_dns(pid, domain, *out_ip_be);
            return 0;
        }
    }
    return -1;  /* not a canary domain · let real DNS handle */
}

int dns_list(dns_list_entry_t *out, int max) {
    dns_seed_canary();
    int n = 0;
    for (int i = 0; i < DNS_MAX_CANARY_ENTRIES && n < max; ++i) {
        if (g_canary_domains[i].in_use) {
            strncpy(out[n].domain, g_canary_domains[i].domain, sizeof(out[n].domain) - 1);
            out[n].domain[sizeof(out[n].domain) - 1] = '\0';
            out[n].ip_be = g_canary_domains[i].answer_ip_be;
            out[n].pad0  = 0;
            n++;
        }
    }
    return n;
}

int dns_install(const char *domain, uint32_t ip_be) {
    dns_seed_canary();
    for (int i = 0; i < DNS_MAX_CANARY_ENTRIES; ++i) {
        if (!g_canary_domains[i].in_use) {
            g_canary_domains[i].in_use = 1;
            strncpy(g_canary_domains[i].domain, domain, sizeof(g_canary_domains[i].domain) - 1);
            g_canary_domains[i].answer_ip_be = ip_be;
            printf("[dns] installed · %s → %u.%u.%u.%u\n",
                   domain,
                   ip_be & 0xFF, (ip_be >> 8) & 0xFF,
                   (ip_be >> 16) & 0xFF, (ip_be >> 24) & 0xFF);
            return 0;
        }
    }
    return -1;
}

/* DNS-SOTBOX-INTERCEPT · RFC 1035 length-prefixed labels → dotted string
 * with trailing dot.  Walks labels starting at `pkt + qname_start`.  For
 * each label-length byte L: rejects compression pointers ((L & 0xC0) != 0)
 * and labels > 63 bytes; copies L bytes followed by '.'; terminates at L=0.
 *
 * Returns total bytes consumed in the packet (including the final 0 byte),
 * or -1 on malformed input / buffer overflow.  out is null-terminated on
 * success.  Caps total qname at 255 bytes (RFC max).
 */
int dns_parse_qname(const uint8_t *pkt, size_t pkt_len, size_t qname_start,
                    char *out, size_t out_size)
{
    if (!pkt || !out || out_size == 0) return -1;
    if (qname_start >= pkt_len) return -1;

    size_t pos      = qname_start;
    size_t out_pos  = 0;
    size_t name_len = 0;  /* total qname bytes consumed (RFC max 255) */

    while (pos < pkt_len) {
        uint8_t L = pkt[pos];

        /* Reject compression pointers and reserved bit patterns · we only
         * accept fully-inline qnames for the simple sotbox query case. */
        if ((L & 0xC0) != 0) return -1;

        /* Move past the length byte itself. */
        pos++;
        name_len++;
        if (name_len > 255) return -1;

        if (L == 0) {
            /* End of name · terminate output and return total bytes consumed. */
            if (out_pos >= out_size) return -1;
            out[out_pos] = '\0';
            return (int)(pos - qname_start);
        }

        if (L > 63) return -1;
        if (pos + L > pkt_len) return -1;
        name_len += L;
        if (name_len > 255) return -1;

        /* +1 for the trailing '.' after this label, +1 reserved for final NUL. */
        if (out_pos + L + 1 >= out_size) return -1;
        for (uint8_t i = 0; i < L; ++i) {
            out[out_pos++] = (char)pkt[pos + i];
        }
        out[out_pos++] = '.';
        pos += L;
    }

    /* Walked past pkt_len without finding the terminating 0 length byte. */
    return -1;
}

/* DNS-SOTBOX-INTERCEPT · build a DNS A-record reply from the original query.
 *
 * Copies the 12-byte query header verbatim, then patches flags to 0x8400
 * (per spec contract · qr=1, opcode=0, aa=1, rcode=0) and ancount to 1.
 * Copies the question section verbatim (everything after the header up to
 * and including QTYPE + QCLASS).  Appends a single A-record answer using
 * DNS compression pointer 0xC00C (offset 12 = start of question name).
 * TTL = 60s.  RDATA = 4 bytes of answer_ip_be (already in network byte
 * order on the wire).
 *
 * Returns total bytes written into `out`, or 0 on error / bounds overflow.
 */
size_t dns_synth_a_response(const uint8_t *query, size_t query_len,
                            uint32_t answer_ip_be,
                            uint8_t *out, size_t out_cap)
{
    if (!query || !out || query_len < 12 || out_cap < 12) return 0;

    /* Locate end of question section: walk qname starting at offset 12,
     * then skip 4 bytes of QTYPE + QCLASS. */
    size_t pos = 12;
    while (pos < query_len) {
        uint8_t L = query[pos];
        if ((L & 0xC0) != 0) return 0;   /* reject compression in query */
        pos++;
        if (L == 0) break;
        if (L > 63) return 0;
        if (pos + L > query_len) return 0;
        pos += L;
    }
    if (pos > query_len) return 0;
    /* pos now points just past the 0-length terminator of the qname. */
    if (pos + 4 > query_len) return 0;   /* need QTYPE + QCLASS */
    size_t question_end = pos + 4;

    /* Answer record is 16 bytes:
     *   2  NAME    = 0xC00C (pointer to offset 12)
     *   2  TYPE    = 0x0001 (A)
     *   2  CLASS   = 0x0001 (IN)
     *   4  TTL     = 60
     *   2  RDLENGTH= 4
     *   4  RDATA   = answer_ip_be (network byte order) */
    if (question_end + 16 > out_cap) return 0;

    /* Copy query header + question section, then patch flags + ancount. */
    memcpy(out, query, question_end);
    out[2] = 0x84;   /* flags hi · qr=1, opcode=0, aa=1, tc=0, rd=0 */
    out[3] = 0x00;   /* flags lo · ra=0, z=0, rcode=0 (NOERROR) */
    /* ancount = 1 (network byte order). */
    out[6] = 0x00;
    out[7] = 0x01;
    /* nscount = arcount = 0 · zero in case the query had non-zero values. */
    out[8]  = 0x00;  out[9]  = 0x00;
    out[10] = 0x00;  out[11] = 0x00;

    size_t w = question_end;
    out[w++] = 0xC0;  out[w++] = 0x0C;            /* NAME · pointer offset 12 */
    out[w++] = 0x00;  out[w++] = 0x01;            /* TYPE = A */
    out[w++] = 0x00;  out[w++] = 0x01;            /* CLASS = IN */
    out[w++] = 0x00;  out[w++] = 0x00;            /* TTL hi */
    out[w++] = 0x00;  out[w++] = 0x3C;            /* TTL lo · 60s */
    out[w++] = 0x00;  out[w++] = 0x04;            /* RDLENGTH = 4 */
    /* RDATA · 4 bytes of answer_ip_be.  In this codebase the convention is
     * that byte 0 of the uint32 in memory holds the first dotted-quad octet
     * (see dns.c seeds: 0x0F02000A == 10.0.2.15 on a LE host).  That is
     * exactly the wire byte order for an A record · copy verbatim. */
    memcpy(out + w, &answer_ip_be, 4);
    w += 4;

    return w;
}

/* Read the 2-byte QTYPE that follows the question's qname. qname_consumed is
 * the byte count dns_parse_qname returned (qname incl. the root 0). QTYPE sits
 * at offset 12 + qname_consumed. Returns 0 on any bounds failure. */
uint16_t dns_query_qtype(const uint8_t *pkt, size_t len, int qname_consumed)
{
    if (!pkt || qname_consumed <= 0) return 0;
    size_t off = (size_t)12 + (size_t)qname_consumed;
    if (off + 2 > len) return 0;
    return (uint16_t)(((uint16_t)pkt[off] << 8) | pkt[off + 1]);
}

/* Build an EMPTY NOERROR response to query (used for AAAA so the resolver falls
 * back to the A record -> IPv4). Echo the ID + question, set QR=1, RA=1,
 * RCODE=0, ANCOUNT/NSCOUNT/ARCOUNT=0. The flags bytes are written explicitly
 * (preserving only RD from the query) so no attacker-controlled AA/TC/opcode/Z
 * bits leak into the response. QDCOUNT (bytes 4-5) is preserved verbatim from
 * the query. Returns total bytes written, or 0 on error. */
size_t dns_synth_empty_noerror(const uint8_t *query, size_t qlen,
                               uint8_t *out, size_t out_cap)
{
    if (!query || !out || qlen < 12 || qlen > out_cap) return 0;
    memcpy(out, query, qlen);
    out[2] = (uint8_t)((query[2] & 0x01) | 0x80);  /* preserve RD, set QR, clear AA/TC/opcode */
    out[3] = 0x80;                                  /* RA=1, RCODE=0, Z=0 */
    out[6] = 0; out[7] = 0;                     /* ANCOUNT=0 */
    out[8] = 0; out[9] = 0;                     /* NSCOUNT=0 */
    out[10] = 0; out[11] = 0;                   /* ARCOUNT=0 */
    return qlen;
}
