/*
 * sotOs · sotNet-β-3 · minimal Ethernet/ARP/ICMP stack.
 *
 * Sits above virtio_net_tx / virtio_net_rx_poll (implemented in
 * src/sotfs/storage_virtio_net.c) and provides:
 *
 *   sotnet_init(our_ip_be)   — record our IP + read hardware MAC.
 *   sotnet_poll()            — drain one RX frame; handle ARP / ICMP.
 *
 * ARP handling: when we receive an ARP request whose target IP matches
 * ours, we send an ARP reply so the QEMU host (10.0.2.2) can resolve
 * our MAC.
 *
 * ICMP handling: when we receive an IPv4 ICMP echo request (type 8)
 * targeted at our IP, we swap src/dst, recompute checksums, and send
 * an echo reply (type 0).  ICMP payload is echoed verbatim.
 *
 * NOTE: QEMU user-mode networking does NOT send unsolicited ARPs to the
 * guest at boot time.  The first ARP/ICMP packet will typically arrive
 * only after the host sends a ping or tries to contact the guest.  As a
 * result, the 200-iteration poll loop in orch_bootstrap_init will very
 * likely see no frames — this is expected and not a bug.  Once QEMU
 * user-mode sends a packet (e.g. a forwarded connection or the host
 * pinging the guest), sotnet_poll will handle it.
 */

#include <sotnet/sotnet.h>
#include <sotnet/tcp.h>
#include <sotnet/tcp_conn.h>
#include <sotnet/tcp_fp.h>
#include <sotnet/ipv6.h>
#include <sotnet/arp.h>
#include <sotnet/route.h>
#include <sotnet/dns.h>
#include <sto_local.h>
#include <orch/proto.h>
#include <sotguard/event.h>
#include <sel4/sel4.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/* SG-NET Phase 2 · per-emit monotonic timestamp for the NET_PRECOMMIT
 * sotGuard event-bus producer.  Bumps once per UDP send · see
 * include/sotguard/event.h line 17 for semantics. */
static uint64_t g_sg_net_send_ts = 0;

/* sotNet-δ Phase 2 · anomaly EP accessor (defined in orch/sotbox_table.c,
 * linked into the same orch image as sotnet.c). */
extern seL4_CPtr orch_get_anomaly_ep(void);

/* -------------------------------------------------------------------------
 * sotNet-δ · STS (Secure Transactional Sockets) Phase 1 counters.
 * -------------------------------------------------------------------------*/
static uint32_t g_sotnet_sto_commits = 0;
static uint32_t g_sotnet_sto_aborts  = 0;

uint32_t sotnet_get_sto_commits(void) { return g_sotnet_sto_commits; }
uint32_t sotnet_get_sto_aborts(void)  { return g_sotnet_sto_aborts; }

/* Forward declarations for virtio-net layer (defined in storage_virtio_net.c). */
extern int  virtio_net_tx(const uint8_t *frame, size_t len);
extern int  virtio_net_rx_poll(uint8_t *out_buf, size_t buf_max, size_t *out_len);
extern void virtio_net_get_mac(uint8_t out[6]);

/* -------------------------------------------------------------------------
 * Internal state
 * -------------------------------------------------------------------------*/
static uint32_t g_our_ip  = 0;       /* our IP in network byte order */
static uint8_t  g_our_mac[6] = {0};  /* our Ethernet MAC */

/* sotNet-ζ · flow tracker */
static sotnet_flow_entry_t g_flows[SOTNET_MAX_FLOWS];

/* -------------------------------------------------------------------------
 * Byte-swap helpers (no <arpa/inet.h> available in seL4 muslc env).
 * -------------------------------------------------------------------------*/
static inline uint16_t htons_(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint16_t ntohs_(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }

/* -------------------------------------------------------------------------
 * Internet checksum (RFC 1071): ones-complement sum over 16-bit words.
 * Used for both IPv4 header checksum and ICMP checksum.
 * -------------------------------------------------------------------------*/
static uint16_t inet_csum(const void *buf, size_t len)
{
    const uint16_t *p = (const uint16_t *)buf;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* =========================================================================
 * Public API
 * =========================================================================*/

void sotnet_init(uint32_t our_ip_be)
{
    g_our_ip = our_ip_be;
    /* β · seed the egress IP-ID counter from our IP so the sequence start isn't a fixed 1. */
    sotfp_ip_id_seed((uint16_t)(g_our_ip ^ (g_our_ip >> 16)));
    virtio_net_get_mac(g_our_mac);
    /* N5 · ARP cache · ensure clean LRU state on every boot. */
    arp_cache_init();
    /* Print IP in host order for readability: 10.0.2.15 stored as 0x0F02000A.
     * Each byte pair in little-endian 32-bit: byte 0 = LSB = 0x0A = 10, etc. */
    uint8_t *ip = (uint8_t *)&our_ip_be;
    printf("[sotnet] init · IP=%u.%u.%u.%u  MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
           ip[0], ip[1], ip[2], ip[3],
           g_our_mac[0], g_our_mac[1], g_our_mac[2],
           g_our_mac[3], g_our_mac[4], g_our_mac[5]);
}

/* -------------------------------------------------------------------------
 * sotnet_resolve_gateway: ARP-resolve the next-hop gateway MAC.
 *
 * On a real L2 fabric (tap) the gateway MAC is not known a priori (unlike the
 * hardcoded SLIRP gateway), so we must actively ARP for it before off-subnet
 * egress can work.  Self-contained: builds + broadcasts an ARP request, polls
 * the RX ring, and learns any ARP sender into the arp_cache; returns once the
 * gateway's binding appears.  Bounded by ARP_RESOLVE_BUDGET and fail-soft.
 * -------------------------------------------------------------------------*/
int sotnet_resolve_gateway(uint32_t gw_ip_be, uint8_t out_mac[6])
{
    /* Already cached (e.g. learned passively from prior ARP traffic)? */
    if (arp_cache_lookup(gw_ip_be, out_mac) == 0) return 0;

    /* Build a broadcast ARP request: who-has gw_ip, tell g_our_ip / g_our_mac. */
    uint8_t req[14 + 28];
    memset(req, 0, sizeof(req));
    struct eth_hdr *e = (struct eth_hdr *)req;
    memset(e->dst, 0xFF, 6);
    memcpy(e->src, g_our_mac, 6);
    e->ethertype = htons_(0x0806);
    struct arp_pkt *a = (struct arp_pkt *)(req + 14);
    a->htype = htons_(1);
    a->ptype = htons_(0x0800);
    a->hlen  = 6;
    a->plen  = 4;
    a->oper  = htons_(1);   /* request */
    memcpy(a->sha, g_our_mac, 6);
    memcpy(a->spa, &g_our_ip, 4);
    memset(a->tha, 0, 6);
    memcpy(a->tpa, &gw_ip_be, 4);

    /* Bounded poll: re-send the request every RESEND ticks (each tx is a
     * VM-exit that lets the host backend deliver the reply), learn any ARP
     * sender, and finish as soon as the gateway binding is known. */
    static const int ARP_RESOLVE_BUDGET = 200000;
    static const int ARP_RESEND_EVERY   = 20000;
    static uint8_t rxf[2048];
    for (int i = 0; i < ARP_RESOLVE_BUDGET; ++i) {
        if ((i % ARP_RESEND_EVERY) == 0) virtio_net_tx(req, sizeof(req));
        size_t got = 0;
        if (virtio_net_rx_poll(rxf, sizeof(rxf), &got) != 0) continue;
        if (got < 14 + 28) continue;
        uint16_t et = (uint16_t)(((uint16_t)rxf[12] << 8) | rxf[13]);
        if (et != 0x0806) continue;             /* not ARP */
        /* Learn the sender (SHA at +14+8, SPA at +14+14) — same framing the
         * inbound handle_arp() learn hook uses. */
        const uint8_t *sender_mac = rxf + 14 + 8;
        uint32_t sender_ip_be;
        memcpy(&sender_ip_be, rxf + 14 + 14, 4);
        arp_cache_learn(sender_ip_be, sender_mac);
        if (arp_cache_lookup(gw_ip_be, out_mac) == 0) return 0;
    }
    return -1;
}

/* -------------------------------------------------------------------------
 * handle_arp: respond to an ARP request for our IP.
 * -------------------------------------------------------------------------*/
/* N5 · ARP cache learn hook (forward decl) · owned by arp-cache worker.
 * The worker provides arp_cache_learn() in src/sotnet/arp.c and calls it
 * from inside handle_arp() at the named sentinel below. */

static void handle_arp(const uint8_t *frame, size_t len)
{
    if (len < 14 + 28) return;

    /* N5 · ARP cache learn hook · feed sender (SHA/SPA) into arp_cache
     * BEFORE the inline reply logic.  Per ARP framing:
     *   - sender MAC (SHA) starts at offset 14 (eth_hdr) + 8 (htype 2 +
     *     ptype 2 + hlen 1 + plen 1 + oper 2).
     *   - sender IP  (SPA) starts at offset 14 + 14 (i.e. SHA + 6).
     * Learn for both request and reply frames so we capture the gateway
     * MAC even when QEMU only sends us replies. */
    {
        const uint8_t *sender_mac = frame + 14 + 8;
        uint32_t sender_ip_be;
        memcpy(&sender_ip_be, frame + 14 + 14, 4);
        arp_cache_learn(sender_ip_be, sender_mac);
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)frame;
    const struct arp_pkt *arp = (const struct arp_pkt *)(frame + 14);

    /* Only handle ARP requests (oper == 1). */
    if (ntohs_(arp->oper) != 1) return;

    /* Verify the request is for our IP. */
    if (memcmp(arp->tpa, &g_our_ip, 4) != 0) return;

    /* Build ARP reply in a stack buffer (14 eth + 28 arp = 42 bytes). */
    static uint8_t reply[14 + 28];
    memset(reply, 0, sizeof(reply));

    struct eth_hdr *rep_eth = (struct eth_hdr *)reply;
    struct arp_pkt *rep_arp = (struct arp_pkt *)(reply + 14);

    /* Ethernet header: reply goes back to requester. */
    memcpy(rep_eth->dst, eth->src, 6);
    memcpy(rep_eth->src, g_our_mac, 6);
    rep_eth->ethertype = htons_(0x0806);

    /* ARP fields. */
    rep_arp->htype = htons_(1);
    rep_arp->ptype = htons_(0x0800);
    rep_arp->hlen  = 6;
    rep_arp->plen  = 4;
    rep_arp->oper  = htons_(2);   /* reply */
    memcpy(rep_arp->sha, g_our_mac, 6);
    memcpy(rep_arp->spa, &g_our_ip, 4);
    memcpy(rep_arp->tha, arp->sha, 6);
    memcpy(rep_arp->tpa, arp->spa, 4);

    printf("[sotnet] ARP request from %u.%u.%u.%u · sending ARP reply\n",
           arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
    virtio_net_tx(reply, sizeof(reply));
}

/* -------------------------------------------------------------------------
 * handle_icmp: respond to an ICMP echo request targeted at our IP.
 * -------------------------------------------------------------------------*/
static void handle_icmp(const uint8_t *frame, size_t len)
{
    if (len < 14 + 20 + 8) return;   /* eth + ip_hdr_min + icmp_hdr */

    const struct eth_hdr  *eth  = (const struct eth_hdr *)frame;
    const struct ipv4_hdr *ip   = (const struct ipv4_hdr *)(frame + 14);
    uint8_t ihl = (ip->ihl_ver & 0x0Fu) * 4u;
    if (ihl < 20 || len < 14 + ihl + 8) return;

    /* Only handle ICMP (proto 1). */
    if (ip->proto != 1) return;

    /* Only handle packets addressed to us. */
    if (ip->dst != g_our_ip) return;

    const struct icmp_hdr *icmp = (const struct icmp_hdr *)(frame + 14 + ihl);

    /* Only handle echo request (type 8, code 0). */
    if (icmp->type != 8 || icmp->code != 0) return;

    /* Total reply frame size equals incoming frame size. */
    if (len > 1500) return;   /* sanity: virtio_net_tx won't accept > 1500 */

    /* Build reply in a static buffer (avoids large stack alloc in seL4). */
    static uint8_t reply[1514];
    memcpy(reply, frame, len);

    struct eth_hdr  *rep_eth  = (struct eth_hdr *)reply;
    struct ipv4_hdr *rep_ip   = (struct ipv4_hdr *)(reply + 14);
    struct icmp_hdr *rep_icmp = (struct icmp_hdr *)(reply + 14 + ihl);

    /* Swap Ethernet addresses. */
    uint8_t tmp_mac[6];
    memcpy(tmp_mac, rep_eth->dst, 6);
    memcpy(rep_eth->dst, rep_eth->src, 6);
    memcpy(rep_eth->src, tmp_mac, 6);
    /* Ensure reply comes from our MAC. */
    memcpy(rep_eth->src, g_our_mac, 6);

    /* Swap IP addresses. */
    uint32_t tmp_ip   = rep_ip->src;
    rep_ip->src       = rep_ip->dst;
    rep_ip->dst       = tmp_ip;
    /* β · ICMP echo-reply IP fingerprint (MEASURED real Linux): own INCREMENTING
     * IP-ID + DF CLEAR + TTL 64. Was echoing the prober's IP-ID (via the memcpy
     * above) with no DF — the egregious tell. ihl==20 for a normal echo. */
    sotfp_ip_set(rep_ip, sotfp_next_ip_id(), 0);
    rep_ip->hdr_csum  = 0;
    rep_ip->hdr_csum  = inet_csum(rep_ip, (size_t)ihl);

    /* ICMP: set type = 0 (echo reply), recompute checksum. */
    rep_icmp->type = 0;
    rep_icmp->csum = 0;
    size_t icmp_len = len - 14 - ihl;
    rep_icmp->csum = inet_csum(rep_icmp, icmp_len);

    printf("[sotnet] ICMP echo request from %u.%u.%u.%u seq=%u · sending reply\n",
           ((uint8_t *)&ip->src)[0], ((uint8_t *)&ip->src)[1],
           ((uint8_t *)&ip->src)[2], ((uint8_t *)&ip->src)[3],
           ntohs_(icmp->seq));
    virtio_net_tx(reply, len);
}

/* -------------------------------------------------------------------------
 * sotnet_get_our_ip: return our IPv4 address in network byte order.
 * -------------------------------------------------------------------------*/
uint32_t sotnet_get_our_ip(void)
{
    return g_our_ip;
}

/* -------------------------------------------------------------------------
 * sotnet_send_udp: build a complete eth+ip+udp frame and transmit it.
 *
 * dst_ip_be  : destination IPv4 address, network byte order.
 * dst_port_be: destination UDP port, network byte order.
 * src_port_be: source UDP port, network byte order.
 * data       : payload bytes (copied verbatim into UDP data area).
 * data_len   : payload length; capped at 1400 bytes.
 *
 * Returns the return value of virtio_net_tx (0 = success).
 * -------------------------------------------------------------------------*/
int sotnet_send_udp(uint32_t dst_ip_be, uint16_t dst_port_be,
                    uint16_t src_port_be, const void *data, size_t data_len,
                    uint32_t pid)
{
    /* sotNet-δ · STS Phase 1 · wrap the send in an STO transaction. */
    sto_local_tx_t tx = sto_local_begin("sotnet:send_udp", "");

    struct udp_hdr {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t len;
        uint16_t csum;
    } __attribute__((packed));

    if (data_len > 1400) data_len = 1400;

    /* sotNet-δ Phase 2 · build the packet INTO a per-tx buffer.
     * Bytes go into tx_buffer first; only transmitted after anomaly
     * pre-commit hook grants COMMIT. */
    static uint8_t tx_buffer[1518];
    size_t off = 0;

    /* Ethernet header: broadcast dst so QEMU user-mode NAT routes it. */
    struct eth_hdr *eth = (struct eth_hdr *)tx_buffer;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, g_our_mac, 6);
    eth->ethertype = htons_(0x0800);
    off = 14;

    /* IPv4 header. */
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(tx_buffer + off);
    ip->ihl_ver    = (4u << 4) | 5u;
    ip->tos        = 0;
    ip->total_len  = htons_((uint16_t)(20 + 8 + data_len));
    ip->proto      = 17;   /* UDP */
    ip->src        = g_our_ip;
    ip->dst        = dst_ip_be;
    sotfp_ip_set(ip, sotfp_next_ip_id(), 0);   /* β · incrementing IP-ID + DF clear (was 0x1234 swapped) */
    ip->hdr_csum   = 0;
    ip->hdr_csum   = inet_csum(ip, 20);
    off += 20;

    /* UDP header. */
    struct udp_hdr *udp = (struct udp_hdr *)(tx_buffer + off);
    udp->src_port = src_port_be;
    udp->dst_port = dst_port_be;
    udp->len      = htons_((uint16_t)(8 + data_len));
    udp->csum     = 0;   /* optional for IPv4 */
    off += 8;

    /* Payload. */
    memcpy(tx_buffer + off, data, data_len);
    off += data_len;
    size_t pkt_len = off;

    /* sotNet-δ Phase 2 · anomaly pre-commit hook.
     * Ask anomaly-ext whether this packet may go to wire.
     * Decisions: 0 = COMMIT (default), 1 = ABORT, 2 = SYNTH (redirect). */
    seL4_CPtr anomaly_ep = orch_get_anomaly_ep();
    int decision = 0;
    int promote_tier = 0;   /* reply MR(1) · reply-driven Tier-2 (NO orch_ep callback) */
    if (anomaly_ep != 0) {
        seL4_SetMR(0, (seL4_Word)pid);
        seL4_SetMR(1, ANOMALY_EV_NET_PRECOMMIT);
        seL4_SetMR(2, (seL4_Word)dst_ip_be);
        seL4_SetMR(3, (seL4_Word)pkt_len);
        seL4_MessageInfo_t reply_info =
            seL4_Call(anomaly_ep,
                      seL4_MessageInfo_new(ORCH_OP_ANOMALY_EVENT, 0, 0, 4));
        seL4_Word rlen = seL4_MessageInfo_get_length(reply_info);
        if (rlen > 0) decision = (int)seL4_GetMR(0);
        if (rlen > 1) promote_tier = (int)seL4_GetMR(1);
    }
    /* Apply any reply-driven promotion IN-PROCESS (anomaly no longer re-enters
     * orch via seL4_Call(orch_ep) · that deadlocks from orch-resident sends). */
    if (promote_tier > 0) {
        extern void orch_anomaly_apply_promote(uint32_t pid, int tier);
        orch_anomaly_apply_promote(pid, promote_tier);
    }

    /* SG-NET Phase 2 · ADDITIVE sotGuard event-bus emit.  Sibling of the
     * ANOMALY_EV_NET_PRECOMMIT IPC above · packet-gate semantics
     * (decision = COMMIT/ABORT/SYNTH) stay external in anomaly-ext.
     * This emit only feeds the in-orch correlation ring; it does NOT
     * influence the gate decision.  Best-effort lossy. */
    {
        sotguard_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = (uint32_t)pid;
        ev.type = SG_EV_NET_SEND;
        ev.timestamp = ++g_sg_net_send_ts;
        ev.detail.net.ip_be   = dst_ip_be;
        ev.detail.net.port_be = dst_port_be;  /* network byte order */
        ev.detail.net.len     = (uint64_t)pkt_len;
        (void)sotguard_emit(&ev);
    }

    if (decision == 2) {
        /* SYNTH · anomaly asked us to deflect this packet into the
         * synth server (deception path) instead of dropping it.  The
         * anomaly concurrently fires PROMOTE_TIER for this pid · we
         * just have to redirect the bytes.  Counted as a "would-be
         * abort that became synth" for the existing sto_aborts gauge. */
        extern void synth_record_redirect(uint32_t pid,
                                             uint32_t dst_ip_be,
                                             uint16_t dst_port_be,
                                             uint32_t len);
        synth_record_redirect(pid, dst_ip_be, dst_port_be, (uint32_t)pkt_len);
        printf("[net-synth] tx=%u SYNTH · pre-commit redirected pkt_len=%zu\n",
               tx, pkt_len);
        sto_local_abort(tx);
        g_sotnet_sto_aborts++;
        return 0;  /* synthetic success · caller treats bytes as delivered */
    } else if (decision != 0) {
        printf("[sotnet-δ] tx=%u ABORT · pre-commit hook rejected pkt_len=%zu · wire saw nothing\n",
               tx, pkt_len);
        g_sotnet_sto_aborts++;
        sto_local_abort(tx);
        return -1;
    }

    /* COMMIT path · anomaly approved · actually transmit. */
    /* Log: print dest IP bytes from network-order uint32 (little-endian on x86). */
    const uint8_t *dip = (const uint8_t *)&dst_ip_be;
    printf("[sotnet-β] UDP send · %u.%u.%u.%u:%u len=%zu\n",
           dip[0], dip[1], dip[2], dip[3],
           ntohs_(dst_port_be), data_len);

    /* sotNet-ζ · record flow for telemetry */
    sotnet_record_send(0, dst_ip_be, dst_port_be, src_port_be, (uint32_t)data_len);

    /* N4 · routing table consult · owned by routing worker · select dst eth_mac */
    {
        uint8_t route_mac[6];
        if (sotnet_route_lookup(dst_ip_be, route_mac) == 0) {
            for (int i = 0; i < 6; ++i) tx_buffer[i] = route_mac[i];
        }
        /* else: keep existing broadcast destination from above */
    }

    int rc = virtio_net_tx(tx_buffer, pkt_len);

    /* sotNet-δ · STS · commit or abort based on tx result. */
    if (rc == 0) {
        g_sotnet_sto_commits++;
        sto_local_commit(tx);
    } else {
        g_sotnet_sto_aborts++;
        sto_local_abort(tx);
    }
    return rc;
}

/* -------------------------------------------------------------------------
 * sotNet-ζ · flow tracker implementations
 * -------------------------------------------------------------------------*/
void sotnet_record_send(uint32_t pid, uint32_t dst_ip, uint16_t dst_port,
                        uint16_t src_port, uint32_t len)
{
    int slot = -1;
    for (int i = 0; i < SOTNET_MAX_FLOWS; ++i) {
        if (g_flows[i].in_use &&
            g_flows[i].dst_ip   == dst_ip   &&
            g_flows[i].dst_port == dst_port &&
            g_flows[i].src_port == src_port) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < SOTNET_MAX_FLOWS; ++i) {
            if (!g_flows[i].in_use) {
                slot = i;
                g_flows[i].in_use    = 1;
                g_flows[i].pid       = pid;
                g_flows[i].dst_ip    = dst_ip;
                g_flows[i].src_ip    = g_our_ip;
                g_flows[i].dst_port  = dst_port;
                g_flows[i].src_port  = src_port;
                g_flows[i].bytes_out = 0;
                g_flows[i].bytes_in  = 0;
                break;
            }
        }
    }
    if (slot < 0) return;   /* table full */
    g_flows[slot].bytes_out += len;
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    g_flows[slot].last_seen_tsc = ((uint64_t)hi << 32) | lo;
}

int sotnet_get_flows(sotnet_flow_entry_t *out, int max)
{
    int n = 0;
    for (int i = 0; i < SOTNET_MAX_FLOWS && n < max; ++i) {
        if (g_flows[i].in_use) out[n++] = g_flows[i];
    }
    return n;
}

/* -------------------------------------------------------------------------
 * sotNet-γ Phase 1 · Silenced Connection drop counters.
 * -------------------------------------------------------------------------*/
static uint32_t g_silenced_drops_total = 0;
static uint32_t g_silenced_bytes_total = 0;

void sotnet_record_silenced_drop(uint32_t pid, uint32_t len) {
    (void)pid;
    g_silenced_drops_total++;
    g_silenced_bytes_total += len;
}

uint32_t sotnet_get_silenced_drops(void) { return g_silenced_drops_total; }
uint32_t sotnet_get_silenced_bytes(void) { return g_silenced_bytes_total; }

/* -------------------------------------------------------------------------
 * sotNet-γ Phase 3-D-2 · pending_recv queue (synthetic synth delivery).
 *
 * Fixed-size static array · 16 slots × 256B body each = 4 KiB BSS.  Sized
 * for the operator-demo close-the-loop path; real RX backpressure for
 * production Tier 2 sockets is out of scope (δ-D-3 will revisit if needed).
 * -------------------------------------------------------------------------*/
struct pending_recv {
    int      in_use;
    uint32_t sotbox_pid;
    uint8_t  src_ip[4];
    uint16_t src_port;          /* network byte order (matches enqueue caller) */
    uint8_t  body[SOTNET_RECV_BODY_MAX];
    size_t   body_len;
};
static struct pending_recv g_recv_queue[SOTNET_RECV_QUEUE_SIZE];

/* BG2 · wake hook implemented by LUCAS (src/lucas/handlers_net.c).  Called
 * after a successful enqueue so any sotbox parked in WAITING_FOR_RECV with
 * matching pid is unblocked synchronously.  Returns 1 if a waiter was woken,
 * 0 otherwise (e.g. nobody is parked on this pid). */
extern int lucas_recv_wake_waiter(uint32_t pid);

int sotnet_recv_enqueue(uint32_t pid, const uint8_t src_ip[4],
                        uint16_t src_port, const uint8_t *body, size_t len)
{
    if (len > SOTNET_RECV_BODY_MAX) len = SOTNET_RECV_BODY_MAX;
    for (int i = 0; i < SOTNET_RECV_QUEUE_SIZE; ++i) {
        if (g_recv_queue[i].in_use) continue;
        g_recv_queue[i].in_use     = 1;
        g_recv_queue[i].sotbox_pid = pid;
        g_recv_queue[i].src_ip[0]  = src_ip[0];
        g_recv_queue[i].src_ip[1]  = src_ip[1];
        g_recv_queue[i].src_ip[2]  = src_ip[2];
        g_recv_queue[i].src_ip[3]  = src_ip[3];
        g_recv_queue[i].src_port   = src_port;
        g_recv_queue[i].body_len   = len;
        if (len && body) memcpy(g_recv_queue[i].body, body, len);
        /* src_port arrives in network byte order; print host-order for humans. */
        uint16_t port_host = (uint16_t)(((src_port & 0xFF) << 8) |
                                        ((src_port >> 8) & 0xFF));
        printf("[sotnet-γ] queued recv · pid=%u src=%u.%u.%u.%u:%u body_len=%u\n",
               pid, src_ip[0], src_ip[1], src_ip[2], src_ip[3],
               port_host, (unsigned)len);
        /* BG2 · wake any sotbox blocked in recvfrom on this pid · drains the
         * queue entry we just added into the parked vspace + Sends to the
         * saved reply cap.  No-op when no waiter matches. */
        (void)lucas_recv_wake_waiter(pid);
        return 0;
    }
    printf("[sotnet-γ] queued recv · pid=%u DROPPED · queue full (16 slots)\n", pid);
    return -1;
}

int sotnet_recv_dequeue(uint32_t pid, uint32_t want_ip_be,
                        uint8_t *out_buf, size_t buf_max,
                        uint8_t out_src_ip[4], uint16_t *out_src_port)
{
    for (int i = 0; i < SOTNET_RECV_QUEUE_SIZE; ++i) {
        if (!g_recv_queue[i].in_use) continue;
        if (g_recv_queue[i].sotbox_pid != pid) continue;
        /* Source filter · a connected socket (want_ip_be != 0) may only
         * dequeue an entry whose source IP matches its connected peer.  The
         * stored src_ip[0] is the first octet (== low byte of want_ip_be).
         * want_ip_be == 0 means "any source" (unconnected socket · legacy). */
        if (want_ip_be != 0) {
            if (g_recv_queue[i].src_ip[0] != (uint8_t)(want_ip_be      ) ||
                g_recv_queue[i].src_ip[1] != (uint8_t)(want_ip_be >>  8) ||
                g_recv_queue[i].src_ip[2] != (uint8_t)(want_ip_be >> 16) ||
                g_recv_queue[i].src_ip[3] != (uint8_t)(want_ip_be >> 24))
                continue;
        }
        size_t copy = g_recv_queue[i].body_len;
        if (copy > buf_max) copy = buf_max;
        if (out_buf && copy) memcpy(out_buf, g_recv_queue[i].body, copy);
        if (out_src_ip) {
            out_src_ip[0] = g_recv_queue[i].src_ip[0];
            out_src_ip[1] = g_recv_queue[i].src_ip[1];
            out_src_ip[2] = g_recv_queue[i].src_ip[2];
            out_src_ip[3] = g_recv_queue[i].src_ip[3];
        }
        if (out_src_port) *out_src_port = g_recv_queue[i].src_port;
        int orig_len = (int)g_recv_queue[i].body_len;
        g_recv_queue[i].in_use = 0;
        return orig_len;
    }
    return -1;
}

/* Non-destructive readiness peek · 1 if a pending recv datagram is queued for
 * `pid` (so poll()/select() can report the socket POLLIN-readable BEFORE the
 * guest calls recvfrom — musl's getaddrinfo polls the DNS socket first). */
int sotnet_recv_pending(uint32_t pid)
{
    for (int i = 0; i < SOTNET_RECV_QUEUE_SIZE; ++i)
        if (g_recv_queue[i].in_use && g_recv_queue[i].sotbox_pid == pid)
            return 1;
    return 0;
}

/* Non-destructive size peek · body_len of the first pending datagram for `pid`
 * whose source matches `want_ip_be` (0 = any source).  0 if none.  Backs
 * ioctl(FIONREAD): glibc's parallel-A/AAAA resolver sizes its on-demand answer
 * buffer from FIONREAD before recvfrom — without it the AAAA buffer stays
 * 0-length and the answer is lost. */
int sotnet_recv_peek_len(uint32_t pid, uint32_t want_ip_be)
{
    for (int i = 0; i < SOTNET_RECV_QUEUE_SIZE; ++i) {
        if (!g_recv_queue[i].in_use) continue;
        if (g_recv_queue[i].sotbox_pid != pid) continue;
        if (want_ip_be != 0) {
            if (g_recv_queue[i].src_ip[0] != (uint8_t)(want_ip_be      ) ||
                g_recv_queue[i].src_ip[1] != (uint8_t)(want_ip_be >>  8) ||
                g_recv_queue[i].src_ip[2] != (uint8_t)(want_ip_be >> 16) ||
                g_recv_queue[i].src_ip[3] != (uint8_t)(want_ip_be >> 24))
                continue;
        }
        return (int)g_recv_queue[i].body_len;
    }
    return 0;
}

void sotnet_recv_dump(void)
{
    int seen = 0;
    for (int i = 0; i < SOTNET_RECV_QUEUE_SIZE; ++i) {
        if (!g_recv_queue[i].in_use) continue;
        uint16_t port_host = (uint16_t)(((g_recv_queue[i].src_port & 0xFF) << 8) |
                                        ((g_recv_queue[i].src_port >> 8) & 0xFF));
        printf("[sotnet-γ] queue · slot=%d pid=%u src=%u.%u.%u.%u:%u body_len=%u\n",
               i, g_recv_queue[i].sotbox_pid,
               g_recv_queue[i].src_ip[0], g_recv_queue[i].src_ip[1],
               g_recv_queue[i].src_ip[2], g_recv_queue[i].src_ip[3],
               port_host, (unsigned)g_recv_queue[i].body_len);
        seen++;
    }
    printf("[sotnet-γ] queue · total in_use=%d / %d\n", seen, SOTNET_RECV_QUEUE_SIZE);
}

/* -------------------------------------------------------------------------
 * sotnet_poll: drain one RX frame and dispatch it.
 * -------------------------------------------------------------------------*/
int sotnet_poll(void)
{
    static uint8_t rx_buf[1536];
    size_t got = 0;

    if (virtio_net_rx_poll(rx_buf, sizeof(rx_buf), &got) != 0) return -1;
    if (got < 14) return -1;

    const struct eth_hdr *eth = (const struct eth_hdr *)rx_buf;
    uint16_t et = ntohs_(eth->ethertype);

    /* === v0.7 batch · pre-scaffolded dispatch slots ===
     * Each worker inserts its handler call at its named hook below.
     * Do NOT add new branches anywhere else. */
    if (et == 0x0806) {
        handle_arp(rx_buf, got);
    } else if (et == 0x0800) {
        handle_icmp(rx_buf, got);
        /* v0.8 · TCP real · dispatch all IPv4 proto=6 frames to the
         * connection-aware dispatcher (replaces the N2 RST-only stub). */
        if (got >= 14 + 20) {
            const uint8_t *ip_hdr = rx_buf + 14;
            uint8_t proto = ip_hdr[9];
            if (proto == 6) {
                tcp_handle_packet(rx_buf, got);
            }
            else if (proto == 17 && got >= 14 + 20 + 8) {
                /* UDP inbound · DNS-forward response capture (egress Phase 1).
                 * IHL is the low nibble of ip_hdr[0] (32-bit words). */
                unsigned ihl = (unsigned)(ip_hdr[0] & 0x0f) * 4u;
                if (ihl >= 20 && (size_t)(14 + ihl + 8) <= (size_t)got) {
                    const uint8_t *udp = ip_hdr + ihl;
                    uint16_t src_port = (uint16_t)(((uint16_t)udp[0] << 8) | udp[1]);
                    uint16_t ulen     = (uint16_t)(((uint16_t)udp[4] << 8) | udp[5]);
                    if (src_port == 53 && ulen >= 8 &&
                        (size_t)(14 + ihl + ulen) <= (size_t)got) {
                        dns_capture_udp_response(udp + 8, (size_t)ulen - 8);
                    }
                }
            }
        }
    }
    else if (et == 0x86dd) { handle_ipv6(rx_buf, got); }
    /* All other ethertypes are silently ignored. */
    return 0;
}
