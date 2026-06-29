/*
 * sotOs · sotNet · DHCP client (RFC 2131) · N1 worker
 *
 * Drives the DHCP handshake against QEMU's built-in user-mode DHCP server
 * (10.0.2.2).  Builds raw Ethernet/IPv4/UDP frames directly into a static
 * 576-byte packet buffer; transmits via virtio_net_tx; receives via
 * virtio_net_rx_poll.  No allocator; bounded everywhere.
 *
 *   DISCOVER (broadcast, ciaddr=0)        ->  server: OFFER (yiaddr=X)
 *   REQUEST  (broadcast, req-IP=X, srvid) ->  server: ACK   (yiaddr=X)
 *
 * On full success: calls sotnet_init(leased_ip) and logs the trace line.
 * On timeout: calls sotnet_init(0x0F02000A) and logs a fallback line.
 *
 * Notes:
 *   * Both DISCOVER and REQUEST go to the L2 broadcast / 255.255.255.255
 *     since we do not yet have an IP.  We cannot reuse sotnet_send_udp
 *     because it sources from g_our_ip (which is 0 before sotnet_init).
 *   * QEMU's RX poll is best-effort (see storage_virtio_net.c) — the loops
 *     here are iteration-bounded, not wall-clock bounded.  ~50 000 idle
 *     polls is empirically several hundred ms in QEMU + KVM which is more
 *     than enough for the local-emulated DHCP server.
 */

#include <sotnet/dhcp.h>
#include <sotnet/sotnet.h>
#include <sotos/random.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* virtio-net raw frame I/O (defined in src/sotfs/storage_virtio_net.c). */
extern int  virtio_net_tx(const uint8_t *frame, size_t len);
extern int  virtio_net_rx_poll(uint8_t *out_buf, size_t buf_max, size_t *out_len);
extern void virtio_net_get_mac(uint8_t out[6]);

/* sotnet_init is implemented in sotnet.c — we declare it here too so we
 * don't need to drag in any extra header. */
extern void sotnet_init(uint32_t our_ip_be);

/* Post-DHCP gateway resolution: ARP-resolve the learned next-hop and install it
 * as the default route so off-subnet egress works on a real tap fabric.
 * (impl in sotnet.c / route.c) */
extern int  sotnet_resolve_gateway(uint32_t gw_ip_be, uint8_t out_mac[6]);
extern void sotnet_route_set_default(uint32_t gw_be, const uint8_t gw_mac[6]);

/* ---------------------------------------------------------------------------
 * Byte-swap + checksum helpers (file-local copies; the equivalents in
 * sotnet.c are static so not reusable from here).
 * ---------------------------------------------------------------------------*/
static inline uint16_t hs_(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }

static uint16_t ipv4_csum(const void *buf, size_t len)
{
    const uint16_t *p = (const uint16_t *)buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* ---------------------------------------------------------------------------
 * On-wire BOOTP / DHCP fixed header (RFC 951 + 2131).  236 bytes followed
 * by the 4-byte magic cookie and variable options.
 * ---------------------------------------------------------------------------*/
struct bootp_hdr {
    uint8_t  op;        /* 1 = BOOTREQUEST, 2 = BOOTREPLY                  */
    uint8_t  htype;     /* 1 = Ethernet                                    */
    uint8_t  hlen;      /* 6                                               */
    uint8_t  hops;      /* 0                                               */
    uint32_t xid;       /* transaction id (random)                         */
    uint16_t secs;
    uint16_t flags;     /* high bit = broadcast                            */
    uint32_t ciaddr;    /* client IP                                       */
    uint32_t yiaddr;    /* your (assigned) IP                              */
    uint32_t siaddr;    /* next server IP                                  */
    uint32_t giaddr;    /* gateway IP                                      */
    uint8_t  chaddr[16];/* client HW addr; first 6 = MAC                   */
    uint8_t  sname[64];
    uint8_t  file[128];
} __attribute__((packed));

/* DHCP packet max we ever send/recv.  576 bytes is the RFC 2131 minimum
 * receive size for a server; way more than enough for our handshake. */
#define DHCP_PKT_MAX 576
#define ETH_HDR_LEN  14
#define IPV4_HDR_LEN 20
#define UDP_HDR_LEN  8
#define DHCP_FIXED   (236 + 4)   /* BOOTP hdr + magic cookie */

/* Maximum Ethernet/IP/UDP/DHCP frame we ever build. */
#define DHCP_FRAME_MAX (ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + DHCP_PKT_MAX)

/* Frame buffers — static, file-scope, never recursed into. */
static uint8_t g_tx_frame[DHCP_FRAME_MAX];
static uint8_t g_rx_frame[1536];

/* DHCP magic cookie (RFC 2131 §3): 99.130.83.99 = 0x63825363 (big-endian on
 * the wire).  We store as the 4 individual bytes so endianness is moot. */
static const uint8_t DHCP_COOKIE[4] = { 0x63, 0x82, 0x53, 0x63 };

/* DHCP message types (option 53) */
#define DHCP_DISCOVER  1
#define DHCP_OFFER     2
#define DHCP_REQUEST   3
#define DHCP_ACK       5

/* ---------------------------------------------------------------------------
 * build_dhcp_frame: build a full eth+ip+udp+bootp+options frame in g_tx_frame.
 *
 *   type           : DHCP message type (DHCP_DISCOVER or DHCP_REQUEST)
 *   xid_be         : transaction id (already in big-endian / network order)
 *   our_mac        : 6-byte hardware address (used as chaddr & eth src)
 *   requested_ip_be: only used for REQUEST (option 50); pass 0 for DISCOVER
 *   server_ip_be   : only used for REQUEST (option 54); pass 0 for DISCOVER
 *
 * Returns the total frame length in bytes.  Always fits in DHCP_FRAME_MAX.
 * ---------------------------------------------------------------------------*/
static size_t build_dhcp_frame(uint8_t type,
                               uint32_t xid_be,
                               const uint8_t our_mac[6],
                               uint32_t requested_ip_be,
                               uint32_t server_ip_be)
{
    memset(g_tx_frame, 0, sizeof(g_tx_frame));

    /* Ethernet: dst = broadcast, src = our MAC, ethertype = IPv4 (0x0800). */
    uint8_t *eth = g_tx_frame;
    memset(eth + 0, 0xFF, 6);
    memcpy(eth + 6, our_mac, 6);
    eth[12] = 0x08; eth[13] = 0x00;

    /* BOOTP fixed header + options buffer */
    uint8_t *udp_payload = g_tx_frame + ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;
    struct bootp_hdr *bp = (struct bootp_hdr *)udp_payload;
    bp->op      = 1;        /* BOOTREQUEST */
    bp->htype   = 1;        /* Ethernet */
    bp->hlen    = 6;
    bp->hops    = 0;
    bp->xid     = xid_be;
    bp->secs    = 0;
    bp->flags   = hs_(0x8000);   /* broadcast bit set */
    bp->ciaddr  = 0;
    bp->yiaddr  = 0;
    bp->siaddr  = 0;
    bp->giaddr  = 0;
    memcpy(bp->chaddr, our_mac, 6);

    /* Magic cookie + options. */
    uint8_t *opt = udp_payload + sizeof(struct bootp_hdr);
    memcpy(opt, DHCP_COOKIE, 4);
    opt += 4;

    /* Option 53: DHCP message type. */
    *opt++ = 53;
    *opt++ = 1;
    *opt++ = type;

    /* Option 55: parameter request list (subnet, router, dns).  Optional but
     * helps QEMU populate the OFFER with sensible values. */
    *opt++ = 55;
    *opt++ = 3;
    *opt++ = 1;   /* subnet mask  */
    *opt++ = 3;   /* router       */
    *opt++ = 6;   /* DNS          */

    if (type == DHCP_REQUEST) {
        /* Option 50: requested IP address. */
        *opt++ = 50;
        *opt++ = 4;
        memcpy(opt, &requested_ip_be, 4);
        opt += 4;

        /* Option 54: server identifier. */
        *opt++ = 54;
        *opt++ = 4;
        memcpy(opt, &server_ip_be, 4);
        opt += 4;
    }

    /* Option 255: end of options. */
    *opt++ = 255;

    size_t dhcp_len  = (size_t)(opt - udp_payload);
    size_t udp_len   = UDP_HDR_LEN + dhcp_len;
    size_t ip_len    = IPV4_HDR_LEN + udp_len;
    size_t frame_len = ETH_HDR_LEN + ip_len;

    /* IPv4 header. */
    uint8_t *ip = g_tx_frame + ETH_HDR_LEN;
    ip[0] = (4u << 4) | 5u;        /* version 4, IHL 5 */
    ip[1] = 0;                     /* TOS */
    ip[2] = (uint8_t)(ip_len >> 8);
    ip[3] = (uint8_t)(ip_len & 0xFF);
    ip[4] = 0; ip[5] = 0;          /* ident */
    ip[6] = 0; ip[7] = 0;          /* flags / frag */
    ip[8] = 64;                    /* TTL */
    ip[9] = 17;                    /* proto UDP */
    ip[10] = 0; ip[11] = 0;        /* csum placeholder */
    ip[12] = 0; ip[13] = 0; ip[14] = 0; ip[15] = 0;        /* src = 0.0.0.0 */
    ip[16] = 0xFF; ip[17] = 0xFF; ip[18] = 0xFF; ip[19] = 0xFF; /* dst = 255.255.255.255 */
    uint16_t ck = ipv4_csum(ip, IPV4_HDR_LEN);
    ip[10] = (uint8_t)(ck & 0xFF);
    ip[11] = (uint8_t)(ck >> 8);

    /* UDP header (src=68 client, dst=67 server, csum=0 — optional for IPv4). */
    uint8_t *udp = g_tx_frame + ETH_HDR_LEN + IPV4_HDR_LEN;
    udp[0] = 0; udp[1] = 68;
    udp[2] = 0; udp[3] = 67;
    udp[4] = (uint8_t)(udp_len >> 8);
    udp[5] = (uint8_t)(udp_len & 0xFF);
    udp[6] = 0; udp[7] = 0;

    return frame_len;
}

/* ---------------------------------------------------------------------------
 * parse_dhcp_reply: validate that the given Ethernet frame is a BOOTREPLY
 * matching our transaction id, extract yiaddr and the server identifier.
 *
 * Returns 1 on success and fills *out_type / *out_yiaddr / *out_server_id.
 * Returns 0 on any mismatch (not for us, wrong xid, malformed, etc.).
 * ---------------------------------------------------------------------------*/
static int parse_dhcp_reply(const uint8_t *frame, size_t len,
                            uint32_t expect_xid_be,
                            uint8_t *out_type,
                            uint32_t *out_yiaddr,
                            uint32_t *out_server_id,
                            uint32_t *out_router)
{
    if (len < ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + DHCP_FIXED) return 0;
    /* ethertype IPv4 */
    if (!(frame[12] == 0x08 && frame[13] == 0x00)) return 0;

    const uint8_t *ip = frame + ETH_HDR_LEN;
    if ((ip[0] >> 4) != 4) return 0;     /* not IPv4 */
    if (ip[9] != 17) return 0;            /* not UDP */
    size_t ihl = (ip[0] & 0x0F) * 4u;
    if (ihl < IPV4_HDR_LEN) return 0;

    const uint8_t *udp = ip + ihl;
    /* src port = 67 (server), dst port = 68 (client). */
    uint16_t src_port = (uint16_t)((udp[0] << 8) | udp[1]);
    uint16_t dst_port = (uint16_t)((udp[2] << 8) | udp[3]);
    if (src_port != 67 || dst_port != 68) return 0;

    const uint8_t *bp_raw = udp + UDP_HDR_LEN;
    const struct bootp_hdr *bp = (const struct bootp_hdr *)bp_raw;
    if (bp->op != 2) return 0;             /* BOOTREPLY */
    if (bp->xid != expect_xid_be) return 0; /* not our xid */

    /* Magic cookie check. */
    const uint8_t *opt = bp_raw + sizeof(struct bootp_hdr);
    if (memcmp(opt, DHCP_COOKIE, 4) != 0) return 0;
    opt += 4;

    /* Walk TLV options.  end_ptr is one past the last byte of frame; we
     * also bound by the BOOTP MTU we accept. */
    const uint8_t *end_ptr = frame + len;
    uint8_t msg_type = 0;
    uint32_t server_id = 0;
    uint32_t router    = 0;

    while (opt < end_ptr) {
        uint8_t tag = *opt++;
        if (tag == 0) continue;             /* pad */
        if (tag == 255) break;              /* end */
        if (opt >= end_ptr) return 0;
        uint8_t l = *opt++;
        if (opt + l > end_ptr) return 0;
        if (tag == 53 && l == 1) {
            msg_type = opt[0];
        } else if (tag == 54 && l == 4) {
            memcpy(&server_id, opt, 4);
        } else if (tag == 3 && l >= 4) {
            memcpy(&router, opt, 4);        /* option 3 · first router (gateway) */
        }
        opt += l;
    }

    if (msg_type == 0) return 0;

    *out_type      = msg_type;
    *out_yiaddr    = bp->yiaddr;
    *out_server_id = server_id;
    if (out_router) *out_router = router;
    return 1;
}

/* Number of RX poll iterations to wait for a single DHCP reply.  Empirically
 * QEMU user-mode DHCP responds within a few thousand polls, so 200 000 gives
 * a comfortable headroom while still bounding boot time. */
#define DHCP_RX_POLL_BUDGET 200000

/* ---------------------------------------------------------------------------
 * wait_for_dhcp_reply: poll RX for up to DHCP_RX_POLL_BUDGET iterations
 * looking for a DHCP reply with the given xid and expected type.
 *
 * On match: stores yiaddr and server_id, returns 1.
 * On timeout: returns 0.
 * ---------------------------------------------------------------------------*/
static int wait_for_dhcp_reply(uint32_t xid_be,
                               uint8_t expect_type,
                               uint32_t *out_yiaddr,
                               uint32_t *out_server_id,
                               uint32_t *out_router)
{
    for (int i = 0; i < DHCP_RX_POLL_BUDGET; ++i) {
        size_t got = 0;
        if (virtio_net_rx_poll(g_rx_frame, sizeof(g_rx_frame), &got) != 0) continue;
        if (got < ETH_HDR_LEN) continue;

        uint8_t  type      = 0;
        uint32_t yiaddr    = 0;
        uint32_t server_id = 0;
        uint32_t router    = 0;
        if (parse_dhcp_reply(g_rx_frame, got, xid_be,
                             &type, &yiaddr, &server_id, &router) &&
            type == expect_type) {
            *out_yiaddr    = yiaddr;
            *out_server_id = server_id;
            if (out_router) *out_router = router;
            return 1;
        }
        /* Non-DHCP frame (or wrong xid) — ignore and keep polling. */
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Public entry point.
 * ---------------------------------------------------------------------------*/
int sotnet_dhcp_acquire_or_fallback(void)
{
    uint8_t our_mac[6];
    virtio_net_get_mac(our_mac);

    /* Randomise transaction id.  arc4random returns a 32-bit value in host
     * byte order; the on-wire xid is opaque so any 32-bit value works — we
     * pass it through unchanged. */
    uint32_t xid_be = sotos_arc4random();

    /* --- DISCOVER ---------------------------------------------------------*/
    size_t f_len = build_dhcp_frame(DHCP_DISCOVER, xid_be, our_mac, 0, 0);
    if (virtio_net_tx(g_tx_frame, f_len) != 0) {
        printf("[dhcp] tx DISCOVER failed · falling back to hardcoded 10.0.2.15\n");
        sotnet_init(0x0F02000A);
        return 0;
    }

    uint32_t offered_ip = 0;
    uint32_t server_id  = 0;
    uint32_t offer_router = 0;
    if (!wait_for_dhcp_reply(xid_be, DHCP_OFFER, &offered_ip, &server_id, &offer_router)) {
        printf("[dhcp] timeout · falling back to hardcoded 10.0.2.15\n");
        sotnet_init(0x0F02000A);
        return 0;
    }

    /* --- REQUEST ----------------------------------------------------------*/
    f_len = build_dhcp_frame(DHCP_REQUEST, xid_be, our_mac, offered_ip, server_id);
    if (virtio_net_tx(g_tx_frame, f_len) != 0) {
        printf("[dhcp] tx REQUEST failed · falling back to hardcoded 10.0.2.15\n");
        sotnet_init(0x0F02000A);
        return 0;
    }

    uint32_t acked_ip   = 0;
    uint32_t ack_srv_id = 0;
    uint32_t ack_router = 0;
    if (!wait_for_dhcp_reply(xid_be, DHCP_ACK, &acked_ip, &ack_srv_id, &ack_router)) {
        printf("[dhcp] timeout · falling back to hardcoded 10.0.2.15\n");
        sotnet_init(0x0F02000A);
        return 0;
    }

    /* Gateway: prefer the DHCP router option (3); fall back to the server-id
     * (option 54), which equals the gateway on SLIRP and on a dnsmasq-on-the-
     * gateway tap.  Capture from the ACK, else the OFFER. */
    uint32_t gw_ip = ack_router ? ack_router
                   : offer_router ? offer_router
                   : ack_srv_id   ? ack_srv_id : server_id;

    /* Success — log the canonical trace and hand off to sotnet_init. */
    const uint8_t *oi = (const uint8_t *)&offered_ip;
    const uint8_t *yi = (const uint8_t *)&acked_ip;
    const uint8_t *gw = (const uint8_t *)&gw_ip;
    printf("[dhcp] DISCOVER \xe2\x86\x92 OFFER %u.%u.%u.%u \xe2\x86\x92 REQUEST \xe2\x86\x92 ACK · lease=%u.%u.%u.%u gw=%u.%u.%u.%u\n",
           oi[0], oi[1], oi[2], oi[3],
           yi[0], yi[1], yi[2], yi[3],
           gw[0], gw[1], gw[2], gw[3]);

    sotnet_init(acked_ip);

    /* Resolve the gateway's L2 address and install it as the default route, so
     * off-subnet egress (apt/curl over a real tap fabric) reaches the next-hop.
     * Fail-soft: if ARP doesn't resolve, the lazily seeded SLIRP default route
     * stays in place, so the SLIRP boot path is unaffected. */
    if (gw_ip) {
        uint8_t gw_mac[6];
        if (sotnet_resolve_gateway(gw_ip, gw_mac) == 0) {
            sotnet_route_set_default(gw_ip, gw_mac);
        } else {
            const uint8_t *g = (const uint8_t *)&gw_ip;
            printf("[dhcp] gateway %u.%u.%u.%u ARP unresolved · keeping default route\n",
                   g[0], g[1], g[2], g[3]);
        }
    }
    return 0;
}
