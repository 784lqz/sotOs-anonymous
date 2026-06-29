/*
 * sotOs · sotNet · TCP dispatcher + connection table (v0.8 scaffold).
 *
 * Replaces the N2 RST stub with a real state-machine dispatcher.
 * Per-state behavior is delegated to per-worker .c files:
 *
 *   T1 src/sotnet/tcp_server.c  · LISTEN, SYN_RCVD
 *   T2 src/sotnet/tcp_client.c  · SYN_SENT → ESTABLISHED (active open)
 *   T3 src/sotnet/tcp_data.c    · ESTABLISHED data path
 *   T4 src/sotnet/tcp_close.c   · FIN_WAIT_*, CLOSE_WAIT, LAST_ACK, TIME_WAIT
 *   T5 src/sotnet/tcp_timer.c   · retx + TIME_WAIT cleanup
 *   T8 src/sotnet/tcp_audit.c   · anomaly TCP_OPEN emission
 *
 * Each handler is declared WEAK here with a no-op default · workers provide
 * STRONG overrides in their owned files.  Build links even before all units
 * land; behavior is no-op until the worker arrives.
 *
 * No malloc.  Single-threaded use from orch's fault loop.  Bounded: 8 conns,
 * 256 B TX buf per conn, 256 B RX buf per conn.
 */

#include <sotnet/tcp.h>
#include <sotnet/tcp_conn.h>
#include <sotnet/tcp_fp.h>
#include <sotnet/sotnet.h>      /* struct eth_hdr, struct ipv4_hdr */
#include <sotnet/route.h>       /* sotnet_route_lookup · next-hop MAC */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

extern int  virtio_net_tx(const uint8_t *frame, size_t len);
extern void virtio_net_get_mac(uint8_t out[6]);

/* ------------------------------------------------------------------ */
/* Byte-swap + checksum helpers (file-local).                         */
/* ------------------------------------------------------------------ */

static inline uint16_t tcp_htons_(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint16_t tcp_ntohs_(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t tcp_htonl_(uint32_t v) {
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) |
           ((v & 0xFF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}
static inline uint32_t tcp_ntohl_(uint32_t v) { return tcp_htonl_(v); }

/* JA3S Fase 2 · TCP/IP SYN-ACK fingerprint.
 * Real TS-off Linux SYN-ACK option layout (captured from nginx:alpine,
 * net.ipv4.tcp_timestamps=0): MSS=1460, NOP, NOP, SACK-permitted, NOP,
 * Window-Scale=10 — 12 bytes, no EOL. Emitted ONLY on SYN-flagged segments
 * (server SYN-ACK + client active-open SYN); non-SYN segments stay optionless
 * (correct for a TS-off Linux). */
static const uint8_t LINUX_SYNACK_OPTS[] = {
    0x02, 0x04, 0x05, 0xb4,   /* MSS = 1460                          */
    0x01, 0x01,               /* NOP, NOP                            */
    0x04, 0x02,               /* SACK permitted                      */
    0x01,                     /* NOP                                 */
    0x03, 0x03, 0x0a,         /* Window scale = 10                   */
};  /* sizeof == 12, a multiple of 4 */
#define LINUX_SYNACK_WINDOW 64240u
#define IP_FLAGS_DF tcp_htons_(0x4000)   /* β: superseded by sotfp_ip_set; kept for reference */

static uint16_t tcp_csum(const uint8_t *pseudo, size_t pseudo_len,
                         const uint8_t *seg, size_t seg_len)
{
    uint32_t sum = 0;
    const uint16_t *p;
    size_t n;

    p = (const uint16_t *)pseudo; n = pseudo_len;
    while (n > 1) { sum += *p++; n -= 2; }
    if (n) sum += *(const uint8_t *)p;

    p = (const uint16_t *)seg; n = seg_len;
    while (n > 1) { sum += *p++; n -= 2; }
    if (n) sum += *(const uint8_t *)p;

    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t ip_csum(const void *buf, size_t len)
{
    const uint16_t *p = (const uint16_t *)buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* ------------------------------------------------------------------ */
/* Connection table.                                                  */
/* ------------------------------------------------------------------ */

static struct tcp_conn g_tcp_conns[TCP_CONN_MAX];
static int g_tcp_initialized = 0;

void tcp_conn_init_table(void)
{
    memset(g_tcp_conns, 0, sizeof(g_tcp_conns));
    for (int i = 0; i < TCP_CONN_MAX; ++i) g_tcp_conns[i].listen_slot = -1;
    g_tcp_initialized = 1;
}

static void lazy_init(void) { if (!g_tcp_initialized) tcp_conn_init_table(); }

struct tcp_conn *tcp_conn_alloc(void)
{
    lazy_init();
    for (int i = 0; i < TCP_CONN_MAX; ++i) {
        if (!g_tcp_conns[i].in_use) {
            memset(&g_tcp_conns[i], 0, sizeof(g_tcp_conns[i]));
            g_tcp_conns[i].in_use = 1;
            g_tcp_conns[i].state  = TCP_STATE_CLOSED;
            g_tcp_conns[i].listen_slot = -1;
            return &g_tcp_conns[i];
        }
    }
    return NULL;
}

void tcp_conn_free(struct tcp_conn *conn)
{
    if (!conn) return;
    memset(conn, 0, sizeof(*conn));
    conn->listen_slot = -1;
}

struct tcp_conn *tcp_conn_lookup(uint32_t remote_ip_be, uint16_t remote_port_be,
                                  uint16_t local_port_be)
{
    lazy_init();
    for (int i = 0; i < TCP_CONN_MAX; ++i) {
        struct tcp_conn *c = &g_tcp_conns[i];
        if (!c->in_use) continue;
        if (c->state == TCP_STATE_LISTEN) continue;
        if (c->remote_ip_be   == remote_ip_be &&
            c->remote_port_be == remote_port_be &&
            c->local_port_be  == local_port_be) {
            return c;
        }
    }
    return NULL;
}

struct tcp_conn *tcp_conn_find_listen(uint16_t local_port_be)
{
    lazy_init();
    for (int i = 0; i < TCP_CONN_MAX; ++i) {
        struct tcp_conn *c = &g_tcp_conns[i];
        if (c->in_use && c->state == TCP_STATE_LISTEN &&
            c->local_port_be == local_port_be) {
            return c;
        }
    }
    return NULL;
}

struct tcp_conn *tcp_conn_by_id(uint16_t conn_id)
{
    if (conn_id == 0) return NULL;                 /* 0 = LISTEN slot / invalid */
    for (int i = 0; i < TCP_CONN_MAX; ++i)
        if (g_tcp_conns[i].in_use && g_tcp_conns[i].conn_id == conn_id)
            return &g_tcp_conns[i];
    return NULL;
}

struct tcp_conn *tcp_conn_iter(int *iter_state)
{
    if (!iter_state) return NULL;
    lazy_init();
    int i = (*iter_state < 0) ? 0 : *iter_state + 1;
    for (; i < TCP_CONN_MAX; ++i) {
        if (g_tcp_conns[i].in_use) {
            *iter_state = i;
            return &g_tcp_conns[i];
        }
    }
    *iter_state = TCP_CONN_MAX;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Frame send helper.                                                 */
/* ------------------------------------------------------------------ */

int tcp_send_segment(struct tcp_conn *conn, uint8_t flags,
                     const uint8_t *data, size_t data_len)
{
    if (!conn) return -1;
    /* JA3S Fase 2 · Linux TCP options only on SYN-flagged segments. */
    size_t opt_len = (flags & TCP_FLAG_SYN) ? sizeof(LINUX_SYNACK_OPTS) : 0;
    if (opt_len + data_len > TCP_TX_BUF_SIZE) return -1;   /* frame buffer bound */

    size_t pkt_len = 14 + 20 + 20 + opt_len + data_len;
    if (pkt_len > 1500) return -1;

    static uint8_t frame[14 + 20 + 20 + TCP_TX_BUF_SIZE];
    memset(frame, 0, pkt_len);

    struct eth_hdr  *eth = (struct eth_hdr *)frame;
    struct ipv4_hdr *ip  = (struct ipv4_hdr *)(frame + 14);
    struct tcp_hdr  *tcp = (struct tcp_hdr *)(frame + 14 + 20);

    /* Ethernet.  Default to broadcast (SLIRP routes by IP regardless of dst
     * MAC), but consult the routing table for the next-hop (gateway) MAC: on a
     * real L2 fabric (tap) the host only IP-forwards frames addressed to the
     * gateway's MAC, so an off-subnet TCP dst (apt/curl over HTTP) MUST go to
     * the resolved gateway MAC or it is silently dropped. */
    uint8_t our_mac[6];
    virtio_net_get_mac(our_mac);
    memset(eth->dst, 0xFF, 6);
    {
        uint8_t route_mac[6];
        if (sotnet_route_lookup(conn->remote_ip_be, route_mac) == 0)
            memcpy(eth->dst, route_mac, 6);
    }
    memcpy(eth->src, our_mac, 6);
    eth->ethertype = tcp_htons_(0x0800);

    /* IPv4 */
    ip->ihl_ver    = (4u << 4) | 5u;
    ip->tos        = 0;
    ip->total_len  = tcp_htons_((uint16_t)(20 + 20 + opt_len + data_len));
    /* β · MEASURED Linux: SYN-ACK -> IP-ID 0 (keeps the α gate); established data/
     * ACK/FIN -> incrementing per-socket IP-ID (was wrongly 0); DF set always. */
    sotfp_ip_set(ip, (flags & TCP_FLAG_SYN) ? 0 : sotfp_next_ip_id(), 1);
    ip->proto      = 6;
    ip->hdr_csum   = 0;
    ip->src        = sotnet_get_our_ip();
    ip->dst        = conn->remote_ip_be;
    ip->hdr_csum   = ip_csum(ip, 20);

    /* TCP */
    tcp->src_port  = conn->local_port_be;
    tcp->dst_port  = conn->remote_port_be;
    tcp->seq       = tcp_htonl_(conn->snd_nxt);
    tcp->ack       = tcp_htonl_(conn->rcv_nxt);
    tcp->data_off  = (uint8_t)(((20 + opt_len) / 4) << 4);
    tcp->flags     = flags;
    /* SYN/SYN-ACK keep the fixed Linux window — it is a p0f/JA TCP fingerprint
     * tell (the α/β gates pin the SYN-ACK window).  A NON-SYN segment (a data ACK
     * on an established conn) advertises the REAL free receive-buffer space, so the
     * peer never sends more than rx_buf can hold (was a fixed 64240 into a tiny
     * buffer → the overflow was ACK'd-but-lost · multi-segment corruption). */
    {
        uint16_t win;
        if (flags & TCP_FLAG_SYN) {
            win = LINUX_SYNACK_WINDOW;
        } else {
            size_t rx_free = (conn->rx_len < TCP_RX_BUF_SIZE)
                           ? (TCP_RX_BUF_SIZE - conn->rx_len) : 0;
            win = (rx_free > 0xFFFFu) ? 0xFFFFu : (uint16_t)rx_free;
        }
        tcp->window = tcp_htons_(win);
    }
    tcp->csum      = 0;
    tcp->urgent    = 0;

    if (opt_len > 0) {
        memcpy(frame + 14 + 20 + 20, LINUX_SYNACK_OPTS, opt_len);
    }
    if (data && data_len > 0) {
        memcpy(frame + 14 + 20 + 20 + opt_len, data, data_len);
    }

    /* TCP checksum over pseudo-header + segment (header + data) */
    uint8_t pseudo[12];
    memcpy(pseudo + 0, &ip->src, 4);
    memcpy(pseudo + 4, &ip->dst, 4);
    pseudo[8]  = 0;
    pseudo[9]  = 6;
    uint16_t tcp_len_be = tcp_htons_((uint16_t)(20 + opt_len + data_len));
    memcpy(pseudo + 10, &tcp_len_be, 2);

    tcp->csum = tcp_csum(pseudo, sizeof(pseudo),
                         (const uint8_t *)tcp, 20 + opt_len + data_len);

    /* Cache the segment for retx (T5). */
    if (data && data_len > 0) {
        memcpy(conn->tx_buf, data, data_len);
        conn->tx_len   = data_len;
    }
    conn->tx_flags = flags;
    /* Only DATA / SYN / FIN advance last_tx_ms — those are what the retx timer tracks.
     * A pure ACK must NOT refresh it: a half-open peer that keeps a conn alive with bare
     * ACKs (e.g. an SSH client retransmitting its banner while the starved/silent server
     * never replies) would otherwise forever defeat the idle reaper (tcp_timer.c), so the
     * conn never ages out and the 32-slot table leaks to "SYN drop · conn table full". */
    if (data_len > 0 || (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)))
        conn->last_tx_ms = tcp_now_ms();

    return virtio_net_tx(frame, pkt_len);
}

/* ------------------------------------------------------------------ */
/* RST helper · used by dispatcher when no listener / unsolicited.    */
/* ------------------------------------------------------------------ */

static void send_rst(const uint8_t *in_frame, size_t in_len)
{
    if (in_len < 14 + 20 + 20) return;
    const struct eth_hdr  *in_eth = (const struct eth_hdr *)in_frame;
    const struct ipv4_hdr *in_ip  = (const struct ipv4_hdr *)(in_frame + 14);
    uint8_t ihl = (uint8_t)((in_ip->ihl_ver & 0x0Fu) * 4u);
    if (ihl < 20 || in_len < (size_t)(14 + ihl + 20)) return;
    const struct tcp_hdr *in_tcp = (const struct tcp_hdr *)(in_frame + 14 + ihl);

    static uint8_t reply[14 + 20 + 20];
    memset(reply, 0, sizeof(reply));
    struct eth_hdr  *eth = (struct eth_hdr *)reply;
    struct ipv4_hdr *ip  = (struct ipv4_hdr *)(reply + 14);
    struct tcp_hdr  *tcp = (struct tcp_hdr *)(reply + 14 + 20);

    uint8_t our_mac[6];
    virtio_net_get_mac(our_mac);
    memcpy(eth->dst, in_eth->src, 6);
    memcpy(eth->src, our_mac, 6);
    eth->ethertype = tcp_htons_(0x0800);

    ip->ihl_ver    = (4u << 4) | 5u;
    ip->total_len  = tcp_htons_(40);
    sotfp_ip_set(ip, 0, 1);    /* β · RST: IP-ID 0 + DF set + TTL 64 (measured) */
    ip->proto      = 6;
    ip->src        = in_ip->dst;
    ip->dst        = in_ip->src;
    ip->hdr_csum   = ip_csum(ip, 20);

    tcp->src_port = in_tcp->dst_port;
    tcp->dst_port = in_tcp->src_port;
    /* β · RFC 9293 reset: ACK-triggered -> seq=in.ack, flags=RST (no ACK);
     * otherwise seq=0, ack=in.seq+seglen, flags=RST|ACK. */
    uint8_t  in_doff   = (uint8_t)((in_tcp->data_off >> 4) * 4u);
    uint32_t payload   = 0;
    {
        size_t hdrs = (size_t)(14 + ihl + in_doff);
        if (in_len > hdrs) payload = (uint32_t)(in_len - hdrs);
    }
    uint32_t seg_len = payload
                     + ((in_tcp->flags & TCP_FLAG_SYN) ? 1u : 0u)
                     + ((in_tcp->flags & TCP_FLAG_FIN) ? 1u : 0u);
    sotfp_rst_t rf = sotfp_rst_fields(in_tcp->flags,
                                      tcp_ntohl_(in_tcp->seq),
                                      tcp_ntohl_(in_tcp->ack),
                                      seg_len);
    tcp->seq      = tcp_htonl_(rf.seq);
    tcp->ack      = tcp_htonl_(rf.ack);
    tcp->data_off = (5u << 4);
    tcp->flags    = rf.flags;

    uint8_t pseudo[12];
    memcpy(pseudo + 0, &ip->src, 4);
    memcpy(pseudo + 4, &ip->dst, 4);
    pseudo[8] = 0;
    pseudo[9] = 6;
    uint16_t tlen = tcp_htons_(20);
    memcpy(pseudo + 10, &tlen, 2);
    tcp->csum = tcp_csum(pseudo, sizeof(pseudo), (const uint8_t *)tcp, 20);

    virtio_net_tx(reply, sizeof(reply));
}

/* ------------------------------------------------------------------ */
/* Dispatcher · called from sotnet_poll IPv4 branch.                  */
/* ------------------------------------------------------------------ */

void tcp_handle_packet(const uint8_t *frame, size_t len)
{
    if (len < 14 + 20 + 20) return;
    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(frame + 14);
    uint8_t ihl = (uint8_t)((ip->ihl_ver & 0x0Fu) * 4u);
    if (ihl < 20 || len < (size_t)(14 + ihl + 20)) return;
    if (ip->proto != 6) return;
    if (ip->dst != sotnet_get_our_ip()) return;

    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(frame + 14 + ihl);
    uint8_t flags = tcp->flags;

    /* Lookup connection by 4-tuple (exact match · excludes LISTEN). */
    struct tcp_conn *conn = tcp_conn_lookup(ip->src, tcp->src_port, tcp->dst_port);

    if (!conn) {
        int has_listener = (tcp_conn_find_listen(tcp->dst_port) != NULL);
        switch (sotfp_unsolicited_action(flags, has_listener)) {
        case SOTFP_ACT_SYN_ACCEPT:
            tcp_server_on_syn(frame, len);
            return;
        case SOTFP_ACT_RST: {
            const uint8_t *sip = (const uint8_t *)&ip->src;
            printf("[tcp] unsolicited flags=0x%02x from %u.%u.%u.%u:%u -> dport=%u · RST\n",
                   flags, sip[0], sip[1], sip[2], sip[3],
                   tcp_ntohs_(tcp->src_port), tcp_ntohs_(tcp->dst_port));
            send_rst(frame, len);
            return;
        }
        case SOTFP_ACT_DROP:
        default:
            return;   /* β · open-port NULL/FIN/Xmas silence; never answer a RST */
        }
    }

    /* Existing connection · dispatch by state. */
    if (flags & TCP_FLAG_RST) {
        /* RST · tear down the connection. */
        tcp_conn_free(conn);
        return;
    }

    switch (conn->state) {
    case TCP_STATE_SYN_RCVD:
        if (flags & TCP_FLAG_ACK) {
            tcp_server_on_ack(conn, frame, len);
        }
        break;

    case TCP_STATE_SYN_SENT:
        if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
            tcp_client_on_synack(conn, frame, len);
        }
        break;

    case TCP_STATE_ESTABLISHED:
        /* Process any data payload (+ peer-ACK accounting) first.  This is a
         * no-op for a pure FIN/ACK but, for a FIN+data segment (e.g. a short
         * HTTP response that the peer combines with its FIN), it copies the
         * payload into rx_buf and advances rcv_nxt past the data — so the FIN
         * handler below sees the FIN at the (now-advanced) rcv_nxt. */
        tcp_data_on_segment(conn, frame, len);
        if (flags & TCP_FLAG_FIN) {
            tcp_close_on_fin(conn, frame, len);
        }
        break;

    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
        if (flags & TCP_FLAG_FIN) {
            tcp_close_on_fin(conn, frame, len);
        } else if (flags & TCP_FLAG_ACK) {
            tcp_close_on_finack(conn, frame, len);
        }
        break;

    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_TIME_WAIT:
    case TCP_STATE_CLOSED:
    case TCP_STATE_LISTEN:
    default:
        /* No action needed for these states from incoming packets. */
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Backward-compat shim: keep tcp_handle_syn symbol alive for any     */
/* callers that may still reference it (none expected post-scaffold). */
/* Delegates to tcp_handle_packet.                                    */
/* ------------------------------------------------------------------ */

void tcp_handle_syn(const uint8_t *frame, size_t len)
{
    tcp_handle_packet(frame, len);
}

/* ================================================================== */
/* WEAK no-op defaults for per-state handlers.                        */
/* Workers (T1-T5, T8) provide STRONG overrides in their own files.   */
/* ================================================================== */

__attribute__((weak)) void tcp_server_on_syn(const uint8_t *frame, size_t len)
{
    (void)frame; (void)len;
    /* No server worker (T1) installed · send RST so the client gives up. */
    send_rst(frame, len);
}

__attribute__((weak)) void tcp_server_on_ack(struct tcp_conn *conn,
                                              const uint8_t *frame, size_t len)
{
    (void)frame; (void)len;
    if (conn) tcp_conn_free(conn);
}

__attribute__((weak)) struct tcp_conn *tcp_passive_open(uint16_t local_port_be)
{
    (void)local_port_be;
    return NULL;
}

__attribute__((weak)) struct tcp_conn *tcp_accept_dequeue(uint16_t local_port_be)
{
    (void)local_port_be;
    return NULL;
}

/* Weak default · no conn is protected from the idle reaper (tcp_timer.c).  orch
 * overrides this to shield the live interactive SSH shell conn (long-lived + idle
 * between keystrokes) so the reaper only frees stuck/abandoned deception conns. */
__attribute__((weak)) int tcp_conn_protected(uint16_t conn_id)
{
    (void)conn_id;
    return 0;
}

__attribute__((weak)) struct tcp_conn *tcp_active_open(uint32_t dst_ip_be, uint16_t dst_port_be,
                                                        uint32_t pid)
{
    (void)dst_ip_be; (void)dst_port_be; (void)pid;
    return NULL;
}

__attribute__((weak)) void tcp_client_on_synack(struct tcp_conn *conn,
                                                 const uint8_t *frame, size_t len)
{
    (void)frame; (void)len;
    if (conn) tcp_conn_free(conn);
}

__attribute__((weak)) int tcp_send_data(struct tcp_conn *conn, const uint8_t *buf, size_t len)
{
    (void)conn; (void)buf; (void)len;
    return -1;
}

__attribute__((weak)) void tcp_data_on_segment(struct tcp_conn *conn,
                                                const uint8_t *frame, size_t len)
{
    (void)conn; (void)frame; (void)len;
}

__attribute__((weak)) void sotnet_tcp_close(struct tcp_conn *conn)
{
    if (conn) tcp_conn_free(conn);
}

__attribute__((weak)) void tcp_close_on_fin(struct tcp_conn *conn,
                                              const uint8_t *frame, size_t len)
{
    (void)frame; (void)len;
    if (conn) tcp_conn_free(conn);
}

__attribute__((weak)) void tcp_close_on_finack(struct tcp_conn *conn,
                                                 const uint8_t *frame, size_t len)
{
    (void)frame; (void)len;
    if (conn) tcp_conn_free(conn);
}

/* T5 retransmission timer · monotonic tick + retx scan.  Default: just tick.
 * The tick counter lives here (scaffold owns storage); T5's strong override
 * of tcp_timer_tick() must call tcp_tick_advance() to keep it monotonic. */
static uint32_t g_tcp_now_ms = 0;

uint32_t tcp_now_ms(void) { return g_tcp_now_ms; }
void     tcp_tick_advance(void) { g_tcp_now_ms++; }

__attribute__((weak)) void tcp_timer_tick(void)
{
    tcp_tick_advance();
}

/* T8 audit hook · no-op by default. */
__attribute__((weak)) void tcp_audit_open(struct tcp_conn *conn)
{
    (void)conn;
}
