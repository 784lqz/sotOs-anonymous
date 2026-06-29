/*
 * sotOs · sotNet · TCP close path (T4 · v0.8 real).
 *
 * Implements the active-/passive-close half of the TCP state machine per
 * RFC 793 §3.5.  STRONG overrides for the WEAK no-op defaults declared in
 * src/sotnet/tcp.c:
 *
 *   sotnet_tcp_close(conn)                 · app-initiated close
 *   tcp_close_on_fin(conn, frm, n)  · peer sent FIN
 *   tcp_close_on_finack(conn, ...)  · ACK arrival in a close-pending state
 *
 * State transitions handled:
 *
 *                    +----------+
 *                    |   EST    |
 *                    +----+-----+
 *           app close |    | peer FIN
 *                     v    v
 *               FIN_WAIT_1  CLOSE_WAIT
 *                | | |        |  app close
 *           ACK  | | | FIN    v
 *                v | |        LAST_ACK
 *         FIN_WAIT_2 |        |  ACK
 *                |   v        v
 *           FIN  |  CLOSING  CLOSED (freed)
 *                v   |
 *          TIME_WAIT<+
 *
 * TIME_WAIT lingering is owned by T5 (tcp_timer_tick) · we just stamp
 * conn->time_wait_tick = tcp_now_ms() when we enter the state.
 *
 * Conventions: C11, no malloc, bounded.  Log prefix `[tcp-close]`.
 */

#include <sotnet/tcp.h>
#include <sotnet/tcp_conn.h>
#include <sotnet/sotnet.h>      /* struct ipv4_hdr (for FIN seq validation) */
#include <sottrace/trace.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Byte-swap helpers (file-local · keep tcp.c's untouched).           */
/* ------------------------------------------------------------------ */

static inline uint16_t tcl_ntohs_(uint16_t v)
{
    return (uint16_t)((v << 8) | (v >> 8));
}

static inline uint32_t tcl_ntohl_(uint32_t v)
{
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) |
           ((v & 0xFF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

/* ------------------------------------------------------------------ */
/* tcp_close · app calls to initiate close.                           */
/* ------------------------------------------------------------------ */

void sotnet_tcp_close(struct tcp_conn *conn)
{
    if (!conn || !conn->in_use) return;

    tcp_state_t from = conn->state;

    switch (from) {
    case TCP_STATE_ESTABLISHED:
        /* Active close · send FIN-ACK.  FIN consumes one sequence number. */
        (void)tcp_send_segment(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
        conn->snd_nxt += 1u;
        conn->state    = TCP_STATE_FIN_WAIT_1;
        printf("[tcp-close] tcp_close state=%d -> %d\n",
               (int)from, (int)conn->state);
        return;

    case TCP_STATE_CLOSE_WAIT:
        /* Passive close completion · peer FIN'd us already; send our FIN. */
        (void)tcp_send_segment(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
        conn->snd_nxt += 1u;
        conn->state    = TCP_STATE_LAST_ACK;
        printf("[tcp-close] tcp_close state=%d -> %d\n",
               (int)from, (int)conn->state);
        return;

    default:
        /* Not in a closable state · log and free the slot.  Abnormal-state
         * teardown still owns a session · emit CONN_CLOSE before freeing so
         * the byte counters are not silently dropped (matches the terminal
         * emits above · slot −1 → system ring · conn_id correlates ACCEPT). */
        printf("[tcp-close] close from state=%d ignored\n", (int)from);
        trace_emit_close(-1, 0, conn->conn_id, conn->rx_bytes, conn->tx_bytes);
        tcp_conn_free(conn);
        return;
    }
}

/* ------------------------------------------------------------------ */
/* Helpers · extract TCP header out of a full Ethernet frame.         */
/* Returns NULL if the frame is too short / malformed.                */
/* ------------------------------------------------------------------ */

static const struct tcp_hdr *tcl_tcp_hdr_(const uint8_t *frame, size_t len)
{
    if (!frame || len < 14u + 20u + 20u) return NULL;
    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(frame + 14);
    uint8_t ihl = (uint8_t)((ip->ihl_ver & 0x0Fu) * 4u);
    if (ihl < 20u || len < (size_t)(14u + ihl + 20u)) return NULL;
    return (const struct tcp_hdr *)(frame + 14 + ihl);
}

/* ------------------------------------------------------------------ */
/* tcp_close_on_fin · peer sent FIN.                                  */
/* ------------------------------------------------------------------ */

void tcp_close_on_fin(struct tcp_conn *conn,
                      const uint8_t *frame, size_t len)
{
    if (!conn || !conn->in_use) return;

    const struct tcp_hdr *tcp = tcl_tcp_hdr_(frame, len);
    if (!tcp) return;

    /* The FIN sits AFTER any data in the segment.  For a pure FIN data_len==0
     * (fin_seq == seq · the original behavior); for a FIN+data segment the
     * payload was already consumed by tcp_data_on_segment (which advanced
     * rcv_nxt by data_len), so the FIN is now at seq + data_len == rcv_nxt. */
    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(frame + 14);
    uint8_t  ihl      = (uint8_t)((ip->ihl_ver & 0x0Fu) * 4u);
    uint8_t  data_off = (uint8_t)((tcp->data_off >> 4) * 4u);
    uint16_t ip_total = tcl_ntohs_(ip->total_len);
    size_t   data_len = (size_t)(ip_total - ihl - data_off);
    uint32_t fin_seq  = tcl_ntohl_(tcp->seq) + (uint32_t)data_len;
    if (fin_seq != conn->rcv_nxt) {
        return;   /* out-of-sequence FIN · ignore (sender will retx) */
    }

    tcp_state_t from = conn->state;

    switch (from) {
    case TCP_STATE_ESTABLISHED:
        /* Standard passive close · ACK the FIN, wait for app to close. */
        conn->rcv_nxt += 1u;    /* FIN consumes one seq · advance window. */
        (void)tcp_send_segment(conn, TCP_FLAG_ACK, NULL, 0);
        conn->state = TCP_STATE_CLOSE_WAIT;
        { const uint8_t *_r = (const uint8_t *)&conn->remote_ip_be;
        printf("[tcp-close] FIN recv state=%d -> %d · cid=%u lport=%u peer=%u.%u.%u.%u:%u rx=%llu\n",
               (int)from, (int)conn->state, (unsigned)conn->conn_id,
               (unsigned)tcl_ntohs_(conn->local_port_be),
               _r[0], _r[1], _r[2], _r[3], (unsigned)tcl_ntohs_(conn->remote_port_be),
               (unsigned long long)conn->rx_bytes); }
        return;

    case TCP_STATE_FIN_WAIT_1:
        /* Simultaneous close · both sides FIN'd, neither has been ACKed
         * yet.  ACK their FIN and move to CLOSING. */
        conn->rcv_nxt += 1u;
        (void)tcp_send_segment(conn, TCP_FLAG_ACK, NULL, 0);
        conn->state = TCP_STATE_CLOSING;
        { const uint8_t *_r = (const uint8_t *)&conn->remote_ip_be;
        printf("[tcp-close] FIN recv state=%d -> %d · cid=%u lport=%u peer=%u.%u.%u.%u:%u rx=%llu\n",
               (int)from, (int)conn->state, (unsigned)conn->conn_id,
               (unsigned)tcl_ntohs_(conn->local_port_be),
               _r[0], _r[1], _r[2], _r[3], (unsigned)tcl_ntohs_(conn->remote_port_be),
               (unsigned long long)conn->rx_bytes); }
        return;

    case TCP_STATE_FIN_WAIT_2:
        /* Our FIN was already ACKed.  ACK theirs and enter TIME_WAIT.
         * TERMINAL (active close) · rx/tx are both final here · emit the
         * CONN_CLOSE.  slot −1 → system ring; conn_id correlates to ACCEPT. */
        conn->rcv_nxt += 1u;
        (void)tcp_send_segment(conn, TCP_FLAG_ACK, NULL, 0);
        conn->state          = TCP_STATE_TIME_WAIT;
        conn->time_wait_tick = tcp_now_ms();
        trace_emit_close(-1, 0, conn->conn_id, conn->rx_bytes, conn->tx_bytes);
        { const uint8_t *_r = (const uint8_t *)&conn->remote_ip_be;
        printf("[tcp-close] FIN recv state=%d -> %d · cid=%u lport=%u peer=%u.%u.%u.%u:%u rx=%llu\n",
               (int)from, (int)conn->state, (unsigned)conn->conn_id,
               (unsigned)tcl_ntohs_(conn->local_port_be),
               _r[0], _r[1], _r[2], _r[3], (unsigned)tcl_ntohs_(conn->remote_port_be),
               (unsigned long long)conn->rx_bytes); }
        return;

    default:
        /* CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT · duplicate FIN.
         * Ignore (do not double-advance rcv_nxt). */
        return;
    }
}

/* ------------------------------------------------------------------ */
/* tcp_close_on_finack · ACK arrival in a close-pending state.        */
/* ------------------------------------------------------------------ */

void tcp_close_on_finack(struct tcp_conn *conn,
                         const uint8_t *frame, size_t len)
{
    if (!conn || !conn->in_use) return;
    (void)frame; (void)len;     /* ack number not yet validated · trust dispatcher */

    tcp_state_t from = conn->state;

    switch (from) {
    case TCP_STATE_FIN_WAIT_1:
        /* Peer ACK'd our FIN · half-close complete on our side. */
        conn->state = TCP_STATE_FIN_WAIT_2;
        printf("[tcp-close] ACK recv state=%d -> %d\n",
               (int)from, (int)conn->state);
        return;

    case TCP_STATE_CLOSING:
        /* Both sides have FIN'd; peer just ACK'd ours.  Linger in TIME_WAIT. */
        conn->state          = TCP_STATE_TIME_WAIT;
        conn->time_wait_tick = tcp_now_ms();
        printf("[tcp-close] ACK recv state=%d -> %d\n",
               (int)from, (int)conn->state);
        return;

    case TCP_STATE_LAST_ACK:
        /* Final ACK of our FIN in the passive-close path · connection done.
         * TERMINAL · rx/tx are both final here · emit BEFORE tcp_conn_free
         * (which clears conn fields).  slot −1 → system ring; conn_id
         * correlates this CLOSE to its ACCEPT regardless of ring. */
        trace_emit_close(-1, 0, conn->conn_id, conn->rx_bytes, conn->tx_bytes);
        printf("[tcp-close] ACK recv state=%d -> %d (LAST_ACK -> CLOSED)\n",
               (int)from, (int)TCP_STATE_CLOSED);
        tcp_conn_free(conn);
        return;

    default:
        /* Stray ACK · ignore. */
        return;
    }
}
