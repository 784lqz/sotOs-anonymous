/*
 * sotOs · sotNet · TCP server-side 3-way handshake (T1).
 *
 * Implements the strong overrides for the weak handlers declared in
 * include/sotnet/tcp_conn.h:
 *
 *   tcp_server_on_syn   · SYN received on listener  · -> SYN_RCVD, tx SYN-ACK
 *   tcp_server_on_ack   · ACK in SYN_RCVD           · -> ESTABLISHED (accept-ready)
 *   tcp_passive_open    · allocate a LISTEN slot
 *   tcp_accept_dequeue  · pop the first established conn for a listen port
 *
 * Bounded.  No malloc.  Single-threaded from orch's fault loop.
 *
 * Accept queue is implicit · a conn is "queueable" when:
 *   state == TCP_STATE_ESTABLISHED && listen_slot >= 0
 * tcp_accept_dequeue() marks it dequeued by setting listen_slot = -1.
 */

#include <sotnet/tcp.h>
#include <sotnet/tcp_conn.h>
#include <sotnet/tcp_fp.h>
#include <sotnet/sotnet.h>
#include <sotos/random.h>
#include <sottrace/trace.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* v1 · monotonic connection id source. conn_id 0 is reserved for "none". */
static uint16_t g_conn_id_next = 1;

/* v2.9 · monotonic count of inbound connections that reached ESTABLISHED.
 * Read by the headless boot (via orch ORCH_OP_QUERY_NET) so the demo host stays
 * alive WHILE it is being probed/attacked and powers off only once the network
 * goes idle — instead of a fixed window that cut off multi-connection gates
 * (e.g. the 9-probe TLS gate) mid-sequence. */
static uint32_t g_inbound_total;
uint32_t tcp_inbound_total(void) { return g_inbound_total; }

/* sottrace v1 · wake a sotbox parked in blocking accept() (no-op returning 0
 * when no box is parked).  Defined in src/lucas/handlers_net.c. */
extern int lucas_accept_wake_waiter(void);
/* N2-R Phase B · orch's inbound-push doorbell (defined in src/orch/main.c).
 * A len=0 push is the SSH server-speaks-first greet trigger. */
extern void orch_inbound_push(uint16_t conn_id, uint16_t local_port,
                              const uint8_t *data, uint32_t len);

/* ------------------------------------------------------------------ */
/* Byte-swap helpers (file-local · mirror tcp.c).                     */
/* ------------------------------------------------------------------ */

static inline uint16_t srv_ntohs_(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t srv_ntohl_(uint32_t v) {
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) |
           ((v & 0xFF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

/* Find the slot index of a LISTEN-state conn for the given local port.
 * Returns -1 if none. */
static int find_listen_slot_index(uint16_t local_port_be)
{
    int it = -1;
    struct tcp_conn *c;
    while ((c = tcp_conn_iter(&it)) != NULL) {
        if (c->state == TCP_STATE_LISTEN && c->local_port_be == local_port_be) {
            return it;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* tcp_server_on_syn                                                  */
/* ------------------------------------------------------------------ */

void tcp_server_on_syn(const uint8_t *frame, size_t len)
{
    if (!frame || len < 14 + 20 + 20) return;

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(frame + 14);
    uint8_t ihl = (uint8_t)((ip->ihl_ver & 0x0Fu) * 4u);
    if (ihl < 20 || len < (size_t)(14 + ihl + 20)) return;
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(frame + 14 + ihl);

    /* Verify listener exists. */
    if (tcp_conn_find_listen(tcp->dst_port) == NULL) {
        return;  /* Dispatcher already filtered, but double-check. */
    }
    int listen_idx = find_listen_slot_index(tcp->dst_port);
    if (listen_idx < 0) return;

    /* Allocate a per-connection slot (distinct from the LISTEN slot). */
    struct tcp_conn *conn = tcp_conn_alloc();
    if (!conn) {
        printf("[tcp-server] SYN drop · conn table full\n");
        return;
    }

    conn->conn_id  = g_conn_id_next++;
    if (g_conn_id_next == 0) g_conn_id_next = 1;   /* skip 0 on wrap */
    conn->rx_bytes = 0;
    conn->tx_bytes = 0;

    conn->state          = TCP_STATE_SYN_RCVD;
    conn->remote_ip_be   = ip->src;
    conn->remote_port_be = tcp->src_port;
    conn->local_port_be  = tcp->dst_port;
    conn->listen_slot    = listen_idx;
    /* δ-2 · passive open has no originating sotbox (server-side). */
    conn->origin_pid     = 0;

    /* Random ISN (host order). */
    conn->snd_nxt = sotos_arc4random();
    conn->snd_una = conn->snd_nxt;

    /* Their SYN consumes one sequence; rcv_nxt = their_seq + 1. */
    conn->rcv_nxt = srv_ntohl_(tcp->seq) + 1u;

    /* β · parse the peer's window-scale option (RX-parse correctness). */
    {
        uint8_t  doff = (uint8_t)((tcp->data_off >> 4) * 4u);   /* TCP header len */
        if (doff > 20 && (size_t)(14 + ihl + doff) <= len) {
            const uint8_t *opts = frame + 14 + ihl + 20;
            conn->peer_wscale = sotfp_parse_wscale(opts, (size_t)(doff - 20));
        }
    }

    /* Send SYN-ACK.  tcp_send_segment uses snd_nxt for seq and rcv_nxt for ack. */
    uint8_t synack_flags = sotfp_synack_flags(tcp->flags);   /* β · echo ECE iff ECN-setup SYN */
    (void)tcp_send_segment(conn, synack_flags, NULL, 0);

    const uint8_t *sip = (const uint8_t *)&ip->src;
    printf("[tcp-server] SYN from %u.%u.%u.%u:%u \xe2\x86\x92 SYN_RCVD lport=%u\n",
           sip[0], sip[1], sip[2], sip[3],
           srv_ntohs_(tcp->src_port),
           srv_ntohs_(tcp->dst_port));
}

/* ------------------------------------------------------------------ */
/* tcp_server_on_ack                                                  */
/* ------------------------------------------------------------------ */

void tcp_server_on_ack(struct tcp_conn *conn, const uint8_t *frame, size_t len)
{
    if (!conn || !frame || len < 14 + 20 + 20) return;
    if (conn->state != TCP_STATE_SYN_RCVD) return;

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(frame + 14);
    uint8_t ihl = (uint8_t)((ip->ihl_ver & 0x0Fu) * 4u);
    if (ihl < 20 || len < (size_t)(14 + ihl + 20)) return;
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(frame + 14 + ihl);

    uint32_t their_ack = srv_ntohl_(tcp->ack);
    uint32_t expected  = conn->snd_nxt + 1u;  /* +1 for the SYN we sent */

    if (their_ack != expected) {
        printf("[tcp-server] bad ACK %u (expected %u) · dropping\n",
               their_ack, expected);
        return;
    }

    /* Handshake complete. */
    conn->snd_una = expected;
    conn->snd_nxt = expected;
    conn->state   = TCP_STATE_ESTABLISHED;
    g_inbound_total++;   /* v2.9 · network-activity watermark (headless keepalive) */

    /* Notify anomaly (weak hook · T8 may override). */
    tcp_audit_open(conn);

    /* sottrace v1 · wake any sotbox parked in blocking accept() · the conn is
     * now ESTABLISHED + accept-ready (listen_slot >= 0).  No-op if none. */
    lucas_accept_wake_waiter();

    /* N2-R Phase B · SSH is server-speaks-first: the instant a :22 conn is
     * ESTABLISHED, fire a len=0 greet so net-synth emits the SSH banner
     * without waiting for client bytes.  (Banner logic = Task B2.) */
    if (srv_ntohs_(conn->local_port_be) == 22)
        orch_inbound_push(conn->conn_id, 22, (const uint8_t *)0, 0);

    const uint8_t *rip = (const uint8_t *)&conn->remote_ip_be;
    printf("[tcp-server] ESTABLISHED %u.%u.%u.%u:%u \xe2\x86\x94 :%u (conn ready for accept)\n",
           rip[0], rip[1], rip[2], rip[3],
           srv_ntohs_(conn->remote_port_be),
           srv_ntohs_(conn->local_port_be));

    /* P3 · BLOCKER-1 · the inbound bridge serves host conns WITHOUT a guest
     * accept() handler firing, so emit INBOUND_ACCEPT here at the ESTABLISHED
     * point — this is the only conn_id->5-tuple record the host correlate tool
     * can join on.  slot=-1 → system ring.  local_port_be is the REAL per-conn
     * destination port from the SYN (NOT a hardcoded 80). */
    trace_emit_accept(-1 /* system ring */, 0 /* server-side, no pid */,
                      conn->conn_id, conn->remote_ip_be,
                      conn->remote_port_be, conn->local_port_be);
}

/* ------------------------------------------------------------------ */
/* tcp_passive_open                                                   */
/* ------------------------------------------------------------------ */

struct tcp_conn *tcp_passive_open(uint16_t local_port_be)
{
    /* Disallow duplicate LISTEN on the same port. */
    if (tcp_conn_find_listen(local_port_be) != NULL) {
        printf("[tcp-server] LISTEN refused · port :%u already listening\n",
               srv_ntohs_(local_port_be));
        return NULL;
    }

    struct tcp_conn *conn = tcp_conn_alloc();
    if (!conn) {
        printf("[tcp-server] LISTEN failed · conn table full\n");
        return NULL;
    }

    conn->state         = TCP_STATE_LISTEN;
    conn->local_port_be = local_port_be;
    conn->listen_slot   = -1;  /* this IS the listen slot · points to nothing */
    /* δ-2 · LISTEN slot has no originating sotbox. */
    conn->origin_pid    = 0;
    conn->conn_id       = 0;   /* v1 · LISTEN is not a session */

    printf("[tcp-server] LISTEN on local port :%u\n", srv_ntohs_(local_port_be));
    return conn;
}

/* ------------------------------------------------------------------ */
/* tcp_accept_dequeue                                                 */
/* ------------------------------------------------------------------ */

struct tcp_conn *tcp_accept_dequeue(uint16_t local_port_be)
{
    int it = -1;
    struct tcp_conn *c;
    while ((c = tcp_conn_iter(&it)) != NULL) {
        if (c->state       == TCP_STATE_ESTABLISHED &&
            c->listen_slot >= 0 &&
            c->local_port_be == local_port_be) {
            c->listen_slot = -1;  /* mark dequeued */
            return c;
        }
    }
    return NULL;
}
