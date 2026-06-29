/*
 * sotOs · sotNet · TCP client · T2 worker
 *
 * Implements the active-open / SYN_SENT side of the 3-way handshake.
 * STRONG overrides for tcp_active_open() and tcp_client_on_synack(),
 * declared as weak no-ops in src/sotnet/tcp.c.
 *
 *   tcp_active_open()       · allocate conn, transmit SYN, enter SYN_SENT.
 *   tcp_client_on_synack()  · parse SYN-ACK, validate ack, send final ACK,
 *                             transition ESTABLISHED, notify T8 audit hook.
 *
 * Bounded, no malloc, single-threaded use from orch's fault loop.
 */

#include <sotnet/tcp.h>
#include <sotnet/tcp_conn.h>
#include <sotnet/tcp_fp.h>
#include <sotnet/sotnet.h>
#include <sotos/random.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* File-local byte-swap helpers (mirrors src/sotnet/tcp.c · all static). */
static inline uint16_t cli_ntohs_(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t cli_ntohl_(uint32_t v) {
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) |
           ((v & 0xFF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

/* Ephemeral port range per RFC 6056: 49152..65535. */
#define EPHEMERAL_PORT_BASE  49152u
#define EPHEMERAL_PORT_RANGE 16384u

/* ------------------------------------------------------------------ */
/* T2 · active open · STRONG override.                                */
/* ------------------------------------------------------------------ */

struct tcp_conn *tcp_active_open(uint32_t dst_ip_be, uint16_t dst_port_be,
                                  uint32_t pid)
{
    struct tcp_conn *conn = tcp_conn_alloc();
    if (!conn) {
        printf("[tcp-client] active open · conn table full\n");
        return NULL;
    }

    /* δ-2 · stash originating sotbox pid for anomaly TCP_OPEN attribution. */
    conn->origin_pid = pid;

    /* Ephemeral local port · RFC 6056 dynamic/private range. */
    uint16_t lport_host = (uint16_t)(EPHEMERAL_PORT_BASE +
                          sotos_arc4random_uniform(EPHEMERAL_PORT_RANGE));

    conn->state          = TCP_STATE_SYN_SENT;
    conn->remote_ip_be   = dst_ip_be;
    conn->remote_port_be = dst_port_be;
    conn->local_port_be  = (uint16_t)((lport_host << 8) | (lport_host >> 8)); /* BE */

    /* Random ISN (RFC 793).  Caller's data stream begins at snd_nxt + 1
     * once the SYN-ACK is received. */
    conn->snd_nxt = sotos_arc4random();
    conn->snd_una = conn->snd_nxt;
    conn->rcv_nxt = 0; /* unknown until SYN-ACK arrives */
    conn->listen_slot = -1;

    /* Pretty-print remote ip (BE bytes a.b.c.d). */
    const uint8_t *dip = (const uint8_t *)&dst_ip_be;
    uint16_t dport_host = cli_ntohs_(dst_port_be);

    if (tcp_send_segment(conn, TCP_FLAG_SYN, NULL, 0) != 0) {
        printf("[tcp-client] active open · tx SYN failed → %u.%u.%u.%u:%u\n",
               dip[0], dip[1], dip[2], dip[3], dport_host);
        tcp_conn_free(conn);
        return NULL;
    }

    printf("[tcp-client] active open → %u.%u.%u.%u:%u (lport=:%u) SYN sent\n",
           dip[0], dip[1], dip[2], dip[3], dport_host, lport_host);

    return conn;
}

/* ------------------------------------------------------------------ */
/* T2 · SYN-ACK handler · STRONG override.                            */
/* ------------------------------------------------------------------ */

void tcp_client_on_synack(struct tcp_conn *conn, const uint8_t *frame, size_t len)
{
    if (!conn || !frame) return;
    if (conn->state != TCP_STATE_SYN_SENT) return;
    if (len < (size_t)(14 + 20 + 20)) return;

    /* Re-parse IPv4 IHL to locate the TCP header (dispatcher already
     * validated proto=6 and dst==our_ip). */
    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(frame + 14);
    uint8_t ihl = (uint8_t)((ip->ihl_ver & 0x0Fu) * 4u);
    if (ihl < 20 || len < (size_t)(14 + ihl + 20)) return;
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(frame + 14 + ihl);

    /* Must be SYN+ACK.  RST already handled by dispatcher. */
    if (!((tcp->flags & TCP_FLAG_SYN) && (tcp->flags & TCP_FLAG_ACK))) return;

    uint32_t their_seq = cli_ntohl_(tcp->seq);
    uint32_t their_ack = cli_ntohl_(tcp->ack);

    /* Validate ack acknowledges our SYN (snd_nxt was the ISN; SYN consumes 1). */
    uint32_t expected_ack = conn->snd_nxt + 1u;
    if (their_ack != expected_ack) {
        const uint8_t *sip = (const uint8_t *)&ip->src;
        printf("[tcp-client] SYN-ACK ack mismatch from %u.%u.%u.%u:%u "
               "(got=%u want=%u) · ignoring\n",
               sip[0], sip[1], sip[2], sip[3],
               cli_ntohs_(tcp->src_port),
               (unsigned)their_ack, (unsigned)expected_ack);
        return;
    }

    /* Advance sequence cursors. */
    conn->rcv_nxt = their_seq + 1u;     /* SYN consumes one sequence number */
    conn->snd_una = expected_ack;
    conn->snd_nxt = expected_ack;        /* next data segment seq */
    conn->state   = TCP_STATE_ESTABLISHED;

    /* β · parse the peer's window-scale from the SYN-ACK. */
    {
        const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(frame + 14);
        uint8_t  ihl  = (uint8_t)((ip->ihl_ver & 0x0Fu) * 4u);
        const struct tcp_hdr *th = (const struct tcp_hdr *)(frame + 14 + ihl);
        uint8_t  doff = (uint8_t)((th->data_off >> 4) * 4u);
        if (doff > 20 && (size_t)(14 + ihl + doff) <= len) {
            const uint8_t *opts = frame + 14 + ihl + 20;
            conn->peer_wscale = sotfp_parse_wscale(opts, (size_t)(doff - 20));
        }
    }

    /* Final ACK of the 3-way handshake. */
    if (tcp_send_segment(conn, TCP_FLAG_ACK, NULL, 0) != 0) {
        printf("[tcp-client] tx final ACK failed · tearing down\n");
        tcp_conn_free(conn);
        return;
    }

    /* T8 audit hook · weak no-op until anomaly worker installs override. */
    tcp_audit_open(conn);

    const uint8_t *rip = (const uint8_t *)&conn->remote_ip_be;
    printf("[tcp-client] ESTABLISHED with %u.%u.%u.%u:%u\n",
           rip[0], rip[1], rip[2], rip[3],
           cli_ntohs_(conn->remote_port_be));
}
