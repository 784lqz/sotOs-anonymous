/*
 * sotOs · sotNet · TCP/IP fingerprint logic (arc β).
 *
 * Pure, leaf, dependency-free functions that decide the OS-fingerprint-relevant
 * fields/behaviors. The packet builders (tcp.c / sotnet.c) call these so the
 * fingerprint lives in ONE place and is exhaustively host-testable (SLIRP can't
 * deliver malformed active probes to the guest, so this is the primary gate).
 */
#ifndef SOTNET_TCP_FP_H
#define SOTNET_TCP_FP_H

#include <stdint.h>
#include <stddef.h>

/* Standard TCP control bits (RFC 9293) — local copy keeps this module leaf and
 * matches include/sotnet/tcp.h's TCP_FLAG_* values exactly. */
#define SOTFP_F_FIN 0x01u
#define SOTFP_F_SYN 0x02u
#define SOTFP_F_RST 0x04u
#define SOTFP_F_PSH 0x08u
#define SOTFP_F_ACK 0x10u
#define SOTFP_F_URG 0x20u
#define SOTFP_F_ECE 0x40u
#define SOTFP_F_CWR 0x80u

/* OS IP-layer fingerprint TTL (modern Linux). */
#define SOTFP_TTL   64u

/* Stamp the IP fingerprint onto a 20-byte IPv4 header: ident = ip_id_host (written
 * network/big-endian), DF bit set iff df_set, ttl=64. Raw-byte offsets (RFC 791) to
 * stay leaf — caller recomputes the header checksum AFTER this. Per the MEASURED
 * real-Linux model (see spec): SYN-ACK + RST pass ip_id=0,df=1; ICMP/UDP pass
 * next-counter,df=0; established TCP segments pass next-counter,df=1. */
void sotfp_ip_set(void *ipv4_hdr20, uint16_t ip_id_host, int df_set);

/* Global incrementing IP-ID source (nmap class "I"). Returns the next id, advances. */
uint16_t sotfp_next_ip_id(void);
/* Seed the counter once at sotnet init (derive from g_our_ip) so the start isn't a
 * fixed 1; optional — unseeded it is deterministic, which the host unit test uses. */
void     sotfp_ip_id_seed(uint16_t seed);

/* Parse a TCP option block; return the window-scale shift (0..14), 0 if absent.
 * Bounds-checked: never reads past opt_len. */
uint8_t sotfp_parse_wscale(const uint8_t *opts, size_t opt_len);

/* RST generation per RFC 9293 §3.5.2. in_* are HOST order.
 * seg_len = payload_bytes + (SYN?1:0) + (FIN?1:0). Outputs host-order seq/ack. */
typedef struct { uint32_t seq; uint32_t ack; uint8_t flags; } sotfp_rst_t;
sotfp_rst_t sotfp_rst_fields(uint8_t in_flags, uint32_t in_seq,
                             uint32_t in_ack, uint32_t seg_len);

/* SYN-ACK flag byte: SYN|ACK, plus ECE iff the inbound SYN requested ECN. */
uint8_t sotfp_synack_flags(uint8_t in_syn_flags);

/* Routing for a packet with NO matching connection. */
typedef enum {
    SOTFP_ACT_SYN_ACCEPT,
    SOTFP_ACT_RST,
    SOTFP_ACT_DROP
} sotfp_action_t;
sotfp_action_t sotfp_unsolicited_action(uint8_t in_flags, int has_listener);

#endif /* SOTNET_TCP_FP_H */
