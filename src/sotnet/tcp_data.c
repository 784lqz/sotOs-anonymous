/*
 * sotOs · sotNet · TCP data path (worker T3).
 *
 * Provides STRONG overrides for the data-path handlers declared in
 * include/sotnet/tcp_conn.h.  The scaffold (src/sotnet/tcp.c) installs
 * weak no-op defaults; this file replaces them with real behavior once
 * the connection has reached TCP_STATE_ESTABLISHED:
 *
 *   - tcp_send_data       : push outbound bytes via ACK|PSH segment.
 *   - tcp_data_on_segment : copy inbound payload to rx_buf, send ACK,
 *                           and observe peer ACKs of our outbound seq.
 *
 * Bounded: each send/recv is capped at TCP_TX_BUF_SIZE / TCP_RX_BUF_SIZE
 * (256 B).  No malloc.  No retry loops · retransmission is owned by T5.
 * Out-of-order segments are dropped and a duplicate ACK is sent
 * (δ-1 · no reassembly window yet).
 *
 * FIN handling is intentionally NOT here · the dispatcher in tcp.c routes
 * FIN-bearing segments to tcp_close_on_fin (T4) before reaching us.
 */

#include <sotnet/tcp.h>
#include <sotnet/tcp_conn.h>
#include <sotnet/sotnet.h>      /* struct eth_hdr, struct ipv4_hdr */
#include <sottrace/trace.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* File-local byte-swap helpers (mirror those in tcp.c · isolated to  */
/* keep this TU self-contained).                                       */
/* ------------------------------------------------------------------ */

static inline uint16_t t3_ntohs_(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t t3_ntohl_(uint32_t v)
{
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) |
           ((v & 0xFF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

/* Tiny helper · current pid (best-effort).  In orch userspace there is no
 * real notion of "self pid" for the TCP stack itself (it runs in orch's
 * context), so we log 0.  Workers that drive sends from a sotbox may
 * extend this later via a thread-local. */
static inline uint32_t t3_self_pid_(void) { return 0u; }

/* ------------------------------------------------------------------ */
/* tcp_send_data · push bytes on an ESTABLISHED connection.           */
/* ------------------------------------------------------------------ */

int tcp_send_data(struct tcp_conn *conn, const uint8_t *buf, size_t len)
{
    if (!conn) return -1;
    /* N2-T · also allow CLOSE_WAIT: a half-closed peer (it sent FIN, e.g. ncat
     * after pushing its request) has stopped sending but our side can still
     * transmit our reply.  A non-interactive honeypot client FINs immediately
     * after the request, so the response_profile/echo reply round-trips back through the
     * byte-pipe only after the conn is already in CLOSE_WAIT — refusing here
     * silently dropped every reply. ESTABLISHED + CLOSE_WAIT are the two states
     * where our send is valid. */
    if (conn->state != TCP_STATE_ESTABLISHED &&
        conn->state != TCP_STATE_CLOSE_WAIT) {
        printf("[tcp-data] send refused · state=%d (not ESTABLISHED/CLOSE_WAIT)\n",
               (int)conn->state);
        return -1;
    }
    if (!buf || len == 0) return 0;

    /* Bounded: cap to TX buffer size (T5 owns retx; one-segment-at-a-time). */
    if (len > TCP_TX_BUF_SIZE) len = TCP_TX_BUF_SIZE;

    uint32_t seq_before = conn->snd_nxt;
    int rc = tcp_send_segment(conn, (uint8_t)(TCP_FLAG_ACK | TCP_FLAG_PSH),
                              buf, len);
    if (rc != 0) {
        printf("[tcp-data] send failed · tx_rc=%d\n", rc);
        return -1;
    }

    /* Advance snd_nxt by the number of payload bytes consumed. */
    conn->snd_nxt = seq_before + (uint32_t)len;
    conn->tx_bytes += (uint64_t)len;

    const uint8_t *rip = (const uint8_t *)&conn->remote_ip_be;
    if (!g_orch_quiet)
    printf("[tcp-data] send pid=%u seq=%u len=%u to %u.%u.%u.%u:%u\n",
           (unsigned)t3_self_pid_(),
           (unsigned)seq_before,
           (unsigned)len,
           rip[0], rip[1], rip[2], rip[3],
           (unsigned)t3_ntohs_(conn->remote_port_be));

    return (int)len;
}

/* ------------------------------------------------------------------ */
/* tcp_data_on_segment · inbound data/ACK in ESTABLISHED state.       */
/* ------------------------------------------------------------------ */

void tcp_data_on_segment(struct tcp_conn *conn, const uint8_t *frame, size_t len)
{
    if (!conn || !frame) return;
    if (len < (size_t)(14 + 20 + 20)) return;

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(frame + 14);
    uint8_t ihl = (uint8_t)((ip->ihl_ver & 0x0Fu) * 4u);
    if (ihl < 20) return;
    if (len < (size_t)(14 + ihl + 20)) return;

    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(frame + 14 + ihl);
    uint8_t data_off = (uint8_t)((tcp->data_off >> 4) * 4u);
    if (data_off < 20) return;
    if (len < (size_t)(14 + ihl + data_off)) return;

    uint16_t ip_total = t3_ntohs_(ip->total_len);
    if (ip_total < (uint16_t)(ihl + data_off)) return;

    /* Sanity: ip_total must fit in the captured frame. */
    if ((size_t)(14 + ip_total) > len) return;

    uint32_t their_seq = t3_ntohl_(tcp->seq);
    uint32_t their_ack = t3_ntohl_(tcp->ack);
    uint8_t  flags     = tcp->flags;

    /* β · track the peer's scaled advertised window (parse-only; replies <=256B). */
    conn->snd_wnd = (uint32_t)t3_ntohs_(tcp->window) << conn->peer_wscale;

    size_t data_len = (size_t)(ip_total - ihl - data_off);

    /* ---- ACK handling: advance snd_una if peer ACK'd new ground. ---- */
    if (flags & TCP_FLAG_ACK) {
        /* Use signed delta so wrap-around comparisons are safe. */
        if ((int32_t)(their_ack - conn->snd_una) > 0) {
            conn->snd_una = their_ack;
            conn->retx_count = 0;   /* progress · reset the retransmit-cap counter */
            if (!g_orch_quiet)
            printf("[tcp-data] our seq=%u ACK'd by peer\n",
                   (unsigned)their_ack);
        }
    }

    /* ---- Data handling. ---- */
    if (data_len > 0) {
        if (their_seq == conn->rcv_nxt) {
            const uint8_t *payload = frame + 14 + ihl + data_off;
            sottrace_capture_append(conn->conn_id, SOTTRACE_DIR_IN, payload, (uint32_t)data_len);

            /* N2-T · an inbound responder-port conn (local :80/:22/:443) is bridged
             * to the net-synth responder via in_c2p. */
            uint16_t lport = __builtin_bswap16(conn->local_port_be);
            int bridged = (lport == 80 || lport == 22 || lport == 443);
            if (bridged) {
                extern void orch_inbound_push(uint16_t, uint16_t, const uint8_t *, uint32_t);
                orch_inbound_push(conn->conn_id, lport, payload, (uint32_t)data_len);
            }

            if (bridged && !conn->app_owned) {
                /* δ-2 · SYNTH-BRIDGED inbound with no guest reader: net-synth has
                 * consumed the payload off in_c2p, and nothing drains rx_buf — so
                 * accumulating here only collapses the advertised window (rx_free
                 * shrinks every segment) until the peer is throttled to zero-window
                 * probes (seconds apart).  That stalled the interactive honey-SSH
                 * session and anything running under it (e.g. `apk update`, whose
                 * multi-MiB fetch never progressed).  Consume the FULL segment
                 * without buffering: advance rcv_nxt past it and keep the window
                 * wide open.  (A guest accept() flips app_owned=1 → the else branch
                 * buffers for its read(), unchanged.) */
                conn->rcv_nxt   = their_seq + (uint32_t)data_len;
                conn->rx_bytes += (uint64_t)data_len;
            } else {
                /* APPEND to rx_buf (accumulate · the guest drains it via read()),
                 * buffering only what fits in the free space.  Advance rcv_nxt by
                 * the BUFFERED amount only — ACKing data we could NOT buffer would
                 * tell the peer we got it (no retransmit) → silent loss/corruption
                 * of a multi-segment response.  The advertised receive window
                 * (tcp_send_segment) tracks the free space so a well-behaved peer
                 * never overruns the buffer (copy_len == data_len in the common
                 * case). */
                size_t rx_free  = (conn->rx_len < TCP_RX_BUF_SIZE)
                                ? (TCP_RX_BUF_SIZE - conn->rx_len) : 0;
                size_t copy_len = (data_len < rx_free) ? data_len : rx_free;

                if (copy_len) memcpy(conn->rx_buf + conn->rx_len, payload, copy_len);
                conn->rx_len   += copy_len;
                conn->rcv_nxt   = their_seq + (uint32_t)copy_len;
                conn->rx_bytes += (uint64_t)copy_len;
            }

            /* Send pure ACK (re-advertises the now-open window). */
            (void)tcp_send_segment(conn, TCP_FLAG_ACK, NULL, 0);

            if (!g_orch_quiet)
            printf("[tcp-data] recv pid=%u seq=%u len=%u · ACK sent\n",
                   (unsigned)t3_self_pid_(),
                   (unsigned)their_seq,
                   (unsigned)data_len);
        } else {
            /* Out-of-order (or duplicate) · drop and send dup-ACK so the
             * peer fast-retransmits.  No reassembly window in δ-1. */
            (void)tcp_send_segment(conn, TCP_FLAG_ACK, NULL, 0);
            printf("[tcp-data] OOO seq=%u expected=%u · dup-ACK sent\n",
                   (unsigned)their_seq, (unsigned)conn->rcv_nxt);
        }
    }
    /* FIN is dispatched to tcp_close_on_fin (T4) by the scaffold before
     * we are called · nothing to do here. */
}
