/*
 * sotOs · sotNet · TCP connection table API (v0.8 scaffold).
 *
 * Provides the per-connection state struct, state enum, and lookup/alloc API
 * shared by the TCP per-state handlers (T1-T5+T8 workers).
 *
 * Bounded · 16 simultaneous connections.  No malloc.
 * Single-threaded usage from orch's fault loop · no locks needed.
 *
 * Sizing: 3 of the slots are permanent LISTENers (:80 :22 :443), leaving 13 for
 * live connections.  ε3 (TLS 1.3 suite agility) added a 6th sequential :443
 * probe to tls13-gate.sh; openssl `-ign_eof` holds each conn open (SIGKILL'd by
 * `timeout`, so the slot only frees on the 60000-tick TIME_WAIT timer, which
 * does not elapse within the back-to-back gate window).  8 slots (5 live)
 * exhausted at the 6th probe → SYN drop.  16 gives the gate headroom AND models
 * a more credible honeypot (real recon opens many concurrent connections).
 */

#ifndef SOTNET_TCP_CONN_H
#define SOTNET_TCP_CONN_H

#include <stdint.h>
#include <stddef.h>

#define TCP_CONN_MAX 32   /* headroom vs scans/concurrency; the idle reaper (tcp_timer.c) is the real anti-leak */
#define TCP_TX_BUF_SIZE 256
/* δ-2 · the rx buffer ACCUMULATES in-order segments (append, not overwrite) so a
 * multi-segment response (HTTP body, TLS record flight) isn't truncated.  16 KiB
 * holds a typical HTTP response + a TLS handshake flight; the advertised receive
 * window tracks the free space (tcp_send_segment) so the peer never overruns it.
 * (Was 256 with an overwrite + full-data_len ACK → multi-segment data was ACK'd-
 * but-lost → corrupted headers.)  16 KiB × 16 conns = 256 KiB static. */
#define TCP_RX_BUF_SIZE 16384

typedef enum {
    TCP_STATE_CLOSED       = 0,
    TCP_STATE_LISTEN       = 1,
    TCP_STATE_SYN_SENT     = 2,
    TCP_STATE_SYN_RCVD     = 3,
    TCP_STATE_ESTABLISHED  = 4,
    TCP_STATE_FIN_WAIT_1   = 5,
    TCP_STATE_FIN_WAIT_2   = 6,
    TCP_STATE_CLOSE_WAIT   = 7,
    TCP_STATE_CLOSING      = 8,
    TCP_STATE_LAST_ACK     = 9,
    TCP_STATE_TIME_WAIT    = 10,
} tcp_state_t;

struct tcp_conn {
    int          in_use;
    uint16_t     conn_id;     /* v1 · monotonic per-connection id for sottrace session correlation */
    tcp_state_t  state;

    /* 4-tuple.  All BE (network order). */
    uint32_t     remote_ip_be;
    uint16_t     remote_port_be;
    uint16_t     local_port_be;

    /* Outbound seq cursors (host order). */
    uint32_t     snd_nxt;
    uint32_t     snd_una;
    /* Expected next inbound seq (host order). */
    uint32_t     rcv_nxt;

    /* β · peer's window-scale shift (0..14) parsed from its SYN/SYN-ACK; and the
     * peer's most-recently-advertised window, already scaled. PARSE-ONLY — NOT
     * read by send logic (replies are <=256B; forward-compat for >256B replies). */
    uint8_t      peer_wscale;
    uint32_t     snd_wnd;

    /* Last-tx tick (monotonic counter from tcp_timer.c). */
    uint32_t     last_tx_ms;
    /* TIME_WAIT entry tick. */
    uint32_t     time_wait_tick;

    /* Outbound retx buffer (data we sent but haven't yet ACKed). */
    uint8_t      tx_buf[TCP_TX_BUF_SIZE];
    size_t       tx_len;
    uint8_t      tx_flags;       /* flags used for last segment (for retx) */
    uint16_t     retx_count;     /* consecutive retransmits w/o ACK · capped (see tcp_timer.c) */

    /* Inbound buffer (data received and waiting for app). */
    uint8_t      rx_buf[TCP_RX_BUF_SIZE];
    size_t       rx_len;
    uint64_t     rx_bytes;    /* v1 · cumulative inbound bytes (on-wire, pre-truncation) */
    uint64_t     tx_bytes;    /* v1 · cumulative outbound bytes */

    /* For accept queue · -1 if not on queue, else the LISTEN slot index. */
    int          listen_slot;

    /* δ-2 · set when a GUEST sotbox accept()s this inbound conn and binds it to
     * an fd (handlers_net.c) → its payload is drained from rx_buf by the guest's
     * read().  When 0 on a bridged inbound port (:22/:80/:443), the segment is
     * consumed ONLY by the net-synth responder (orch_inbound_push → in_c2p), so
     * rx_buf must NOT accumulate (it is never drained → the advertised window
     * collapses → the interactive SSH session, and anything running under it like
     * `apk update`, stalls).  See tcp_data_on_segment. */
    uint8_t      app_owned;

    /* δ-2 · originating sotbox synthetic_pid for anomaly TCP_OPEN attribution.
     * 0 = system / passive-open / unattributed. */
    uint32_t     origin_pid;
};

/* ------------------------------------------------------------------ */
/* Connection table API (provided by scaffold src/sotnet/tcp.c).      */
/* ------------------------------------------------------------------ */

void              tcp_conn_init_table(void);
struct tcp_conn *tcp_conn_alloc(void);
void              tcp_conn_free(struct tcp_conn *conn);
/* Look up an EXACT 4-tuple match (excludes LISTEN slots). */
struct tcp_conn *tcp_conn_lookup(uint32_t remote_ip_be, uint16_t remote_port_be,
                                  uint16_t local_port_be);
/* Find a LISTEN-state conn for the given local port. */
struct tcp_conn *tcp_conn_find_listen(uint16_t local_port_be);
/* Find an in-use, non-LISTEN conn by its monotonic conn_id (0 = invalid). */
struct tcp_conn *tcp_conn_by_id(uint16_t conn_id);
/* Iterate · returns slot 0..TCP_CONN_MAX-1, NULL when done.  Caller may pass
 * iter_state = -1 to start. */
struct tcp_conn *tcp_conn_iter(int *iter_state);

/* ------------------------------------------------------------------ */
/* Frame send helper.                                                 */
/* ------------------------------------------------------------------ */

/* Builds Eth + IPv4 + TCP frame, computes checksums, transmits.
 * flags = combination of TCP_FLAG_* from include/sotnet/tcp.h.
 * data may be NULL for pure-control segments.
 * Returns 0 on success, -1 on validation failure. */
int tcp_send_segment(struct tcp_conn *conn, uint8_t flags,
                     const uint8_t *data, size_t data_len);

/* ------------------------------------------------------------------ */
/* Main packet entry · called from sotnet_poll IPv4 branch.           */
/* ------------------------------------------------------------------ */

void tcp_handle_packet(const uint8_t *frame, size_t len);

/* ------------------------------------------------------------------ */
/* Per-state handlers · workers provide STRONG overrides.             */
/* Scaffold provides WEAK no-op defaults so build links even if a unit*/
/* hasn't landed.                                                     */
/* ------------------------------------------------------------------ */

/* T1 · server side */
void tcp_server_on_syn(const uint8_t *frame, size_t len);
void tcp_server_on_ack(struct tcp_conn *conn, const uint8_t *frame, size_t len);
struct tcp_conn *tcp_passive_open(uint16_t local_port_be);
struct tcp_conn *tcp_accept_dequeue(uint16_t local_port_be);

/* T2 · client side */
struct tcp_conn *tcp_active_open(uint32_t dst_ip_be, uint16_t dst_port_be,
                                  uint32_t pid);
void tcp_client_on_synack(struct tcp_conn *conn, const uint8_t *frame, size_t len);

/* T3 · data path */
int  tcp_send_data(struct tcp_conn *conn, const uint8_t *buf, size_t len);
void tcp_data_on_segment(struct tcp_conn *conn, const uint8_t *frame, size_t len);

/* T4 · close path */
void sotnet_tcp_close(struct tcp_conn *conn);
void tcp_close_on_fin(struct tcp_conn *conn, const uint8_t *frame, size_t len);
void tcp_close_on_finack(struct tcp_conn *conn, const uint8_t *frame, size_t len);

/* T5 · retransmission timer */
void tcp_timer_tick(void);
/* Monotonic counter source · workers may read for timestamps. */
uint32_t tcp_now_ms(void);
/* Advance the counter · scaffold owns the storage.  T5's strong override of
 * tcp_timer_tick() MUST call this once per tick so other code's last_tx_ms
 * comparisons remain meaningful. */
void tcp_tick_advance(void);

/* T8 · anomaly audit hook */
void tcp_audit_open(struct tcp_conn *conn);

/* v2.9 · monotonic count of inbound conns that reached ESTABLISHED · the
 * headless boot reads this (via orch ORCH_OP_QUERY_NET) to stay alive while
 * being probed and power off only once the network is idle. */
uint32_t tcp_inbound_total(void);

#endif /* SOTNET_TCP_CONN_H */
