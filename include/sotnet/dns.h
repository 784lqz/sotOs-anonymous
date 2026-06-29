#ifndef SOTNET_DNS_H
#define SOTNET_DNS_H
#include <stdint.h>
#include <stddef.h>
/* DNS-PID-PREWORK · pid threaded through dns_lookup so a future sotbox-side
 * interceptor in lucas_sys_sendto (UDP:53) can pass st->synthetic_pid.  Today all
 * callers pass 0 (operator / bootstrap); the anomaly-side auto-promote rule
 * is dormant until that interceptor lands. */
int dns_lookup(uint32_t pid, const char *domain, uint32_t *out_ip_be);
/* Pure canary-table lookup (no anomaly/sotguard/trace side effects) + the
 * deferred audit emit · used by the data-path UDP:53 interceptor so it can
 * enqueue the synth reply BEFORE the audit notify's synchronous orch seL4_Call. */
int  dns_lookup_quiet(const char *domain, uint32_t *out_ip_be);
void dns_lookup_audit(uint32_t pid, const char *domain, uint32_t ip_be);
int dns_install(const char *domain, uint32_t ip_be);

typedef struct dns_list_entry {
    char     domain[64];
    uint32_t ip_be;
    uint32_t pad0;
} dns_list_entry_t;
int dns_list(dns_list_entry_t *out, int max);

/* sotNet-ε Phase 2 · anomaly notify hook.
 * Declared as a weak symbol so dns.c (which has no seL4 headers) can
 * call it.  The strong override lives in src/orch/backends_sotnet.c
 * next to the other sotnet anomaly hooks · same weak/strong pattern as
 * sotfs_graph_curvature_anomaly_notify.  Called by dns_lookup() on every
 * canary-domain HIT.  DNS-PID-PREWORK · pid plumbed in MR(0). */
void sotnet_dns_anomaly_notify(uint32_t pid, const char *domain, uint32_t ip_be);

/* DNS-SOTBOX-INTERCEPT · helpers used by lucas_sys_sendto to parse a UDP:53
 * query and synthesize a synth A-record reply for canary domains.
 *
 * dns_parse_qname: walk RFC-1035 length-prefixed labels starting at
 *   `qname_start` within `pkt[0..pkt_len)`.  Writes a dotted (with trailing
 *   dot) null-terminated qname into `out`.  Returns the total number of
 *   bytes consumed from the packet (including the final 0 length byte),
 *   or -1 on malformed input / buffer overflow.  Rejects DNS compression
 *   pointers (high 2 bits of any length byte set).  Caps label size at 63
 *   and total qname size at 255 bytes (RFC max).
 *
 * dns_synth_a_response: build a DNS A-record reply that echoes the query
 *   header + question, patches flags to 0x8400 and ancount to 1, then
 *   appends a single A record (NAME = 0xC00C pointer, TYPE=A, CLASS=IN,
 *   TTL=60, RDLENGTH=4, RDATA = answer_ip_be).  Returns total bytes
 *   written into `out`, or 0 on error / bounds overflow.
 */
int    dns_parse_qname(const uint8_t *pkt, size_t pkt_len, size_t qname_start,
                       char *out, size_t out_size);
size_t dns_synth_a_response(const uint8_t *query, size_t query_len,
                            uint32_t answer_ip_be,
                            uint8_t *out, size_t out_cap);

/* DNS-EGRESS Phase 1 · pure helpers, host-unit-testable (no seL4, no net).
 *
 * dns_query_qtype: read the 2-byte QTYPE following the question qname.
 *   qname_consumed is the byte count returned by dns_parse_qname (includes
 *   the trailing root 0 byte). QTYPE is at packet offset 12+qname_consumed.
 *   Returns 0 on any bounds failure (safe sentinel: 0 is not a valid QTYPE).
 *
 * dns_synth_empty_noerror: build a NOERROR response with zero answer RRs.
 *   Used to answer AAAA queries with an empty response so the resolver
 *   falls back to the A record (IPv4). Echoes ID + question section verbatim,
 *   sets QR=1, RA=1, RCODE=0, clears ANCOUNT/NSCOUNT/ARCOUNT.
 *   Returns total bytes written into out, or 0 on error / bounds overflow. */
uint16_t dns_query_qtype(const uint8_t *pkt, size_t len, int qname_consumed);
size_t   dns_synth_empty_noerror(const uint8_t *query, size_t qlen,
                                 uint8_t *out, size_t out_cap);

/* DNS-EGRESS Phase 1 · UDP response capture.
 * Called from sotnet_poll for every inbound UDP:53 datagram.  If a forward
 * is armed and the DNS ID matches, stashes the response for the spinner. */
void dns_capture_udp_response(const uint8_t *udp_payload, size_t len);

/* DNS-EGRESS Phase 1 · real forward.
 * Send `query` to 1.1.1.1 via sotnet_send_udp, spin sotnet_poll() until a
 * matching UDP:53 response lands in the capture slot, then copy it to `out`.
 * Returns response length, or 0 on timeout/error. SYNCHRONOUS; no concurrency. */
size_t dns_forward_query(const uint8_t *query, size_t qlen, uint32_t pid,
                         uint8_t *out, size_t out_cap);
#endif
