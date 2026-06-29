/*
 * sotOs · LUCAS · sotNet-α · socket syscall ABI stubs (spec §12.8.4).
 *
 * No actual network operations yet · these handlers return coherent
 * values so binaries calling socket() don't crash on ENOSYS.  Phase
 * β wires the IPC channel to sotOs-net-stack; Phase γ adds the STAR
 * tiers (Silenced Connection / Synth Internet).
 *
 * fd allocation reuses the existing LUCAS fd table.  The 'sotnet'
 * fd kind (LUCAS_FD_SOCKET = 5) is introduced in state.h so future
 * handlers can dispatch on it.  Close is handled by the LUCAS_FD_SOCKET
 * case added to lucas_sys_close in handlers_fs.c.
 *
 * Phase β plan:
 *   handlers_net.c becomes the IPC client side.
 *   sotOs-net-driver (new process) handles virtio-net frames.
 *   sotOs-net-stack (new process) maintains the IP/TCP state machine.
 *   LUCAS routes socket ops via badged IPC to net-stack.
 */

#include "handlers.h"
#include "state.h"
#include <lucas/linux_abi.h>
#include <lucas/syscalls.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sotnet/sotnet.h>
#include <sotnet/tcp_conn.h>
#include <sotnet/dns.h>
#include <sotnet/bytepipe.h>
#include <sottrace/trace.h>

/* sotNet γ-3-γ-1 · byte-channel readiness, defined in orch/main.c. */
extern int orch_bytepipe_ready(void);
/* L12-beta · Wayland route readiness, defined in orch/main.c. */
extern int orch_wayland_ready(void);
extern seL4_CPtr orch_wayland_listen_ep(void);
/* L13-A1 · compositor PD cap (PML4) minted by root, defined in orch/main.c. */
extern seL4_CPtr orch_wayland_pd_cap(void);
/* L14a-A1 · shadow compositor listen EP minted by root, defined in orch/main.c. */
extern seL4_CPtr orch_wayland_canary_ep(void);
/* α · PR 4 · WAL writer for synth redirects.  sotos-sotfs is linked
 * into the orch ELF (via sotOs-lucas) so this is an in-process call ·
 * gated by g_wal_attached from <sotfs/wal_ipc.h>. */
#include <sotfs/wal.h>
#include <sotfs/wal_ipc.h>

#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/capops.h>

/* Byte-swap helpers (no <arpa/inet.h> in seL4 muslc env). */
static inline uint16_t net_htons(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}
static inline uint32_t net_ntohl(uint32_t v) {
    return ((v >> 24) & 0x000000FFu) |
           ((v >>  8) & 0x0000FF00u) |
           ((v <<  8) & 0x00FF0000u) |
           ((v << 24) & 0xFF000000u);
}

/* δ-1 default local port (BE) used until lucas_sys_bind stores a real port.
 * 80 → BE = 0x5000 = 20480. */
static inline uint16_t lucas_default_local_port_be(void) {
    return net_htons(80);
}

/* N-SYNTH · static synthetic HTTP 200 reply returned by recv()
 * on synth-redirected sockets.  The malware (Stage 4 of the demo) does
 *   c2.connect((c2_ip, 443)); c2.sendall(...); c2.recv(1024)
 * and sees a coherent ACK · close-the-loop without touching the wire.
 * Defined once · bounded · no malloc. */
/* Generic, non-fingerprinted 200 · the old body ("ACK ID=7d9a · NEXT-STAGE=ok",
 * a fixed string with a UTF-8 middot in an HTTP body, identical to every dst) was
 * an instant tell.  An empty 200 OK carries no unique signature.  A truly
 * protocol/port-aware sinkhole reply is the next step (Block C follow-up). */
static const char SYNTH_HTTP_REPLY[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.26.3\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Content-Length: 0\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

#define LUCAS_AF_UNIX       1
#define LUCAS_AF_INET       2
#define LUCAS_AF_INET6      10
#define LUCAS_AF_NETLINK    16

/* apt-T7 · rtnetlink constants (defined locally · no kernel header in the
 * seL4/musl env).  All little-endian on x86-64; nlmsghdr/ifaddrmsg/rtattr are
 * 4-byte aligned. */
#define LUCAS_RTM_NEWLINK   16
#define LUCAS_RTM_GETLINK   18
#define LUCAS_RTM_NEWADDR   20
#define LUCAS_RTM_GETADDR   22
#define LUCAS_NLMSG_DONE    3
#define LUCAS_NLM_F_MULTI   2
#define LUCAS_IFA_ADDRESS   1
#define LUCAS_IFA_LOCAL     2
#define LUCAS_NLMSG_ALIGNTO 4u
#define LUCAS_NLMSG_ALIGN(len)  (((len) + LUCAS_NLMSG_ALIGNTO - 1u) & ~(LUCAS_NLMSG_ALIGNTO - 1u))
#define LUCAS_RTA_ALIGNTO   4u
#define LUCAS_RTA_ALIGN(len)    (((len) + LUCAS_RTA_ALIGNTO - 1u) & ~(LUCAS_RTA_ALIGNTO - 1u))
#define LUCAS_SOCK_STREAM   1
#define LUCAS_SOCK_TYPEMASK 0xF
#define LUCAS_UNIX_PATH_MAX 108
#define WAYLAND_SOCKET_PATH "/run/user/1000/wayland-0"
#define LUCAS_WL_MAX_WORDS  64   /* L12-delta · per-frame MR word cap (== wl_rx/4 = 256/4) */
/* L13-B3 · compositor read base for wl_shm pools.  MUST equal the compositor's
 * read base in C1 (built to 0x60000000); A3 smoke mapped a frame here OK. */
#define COMPOSITOR_SHM_POOL_BASE 0x60000000UL
/* L14a-C1 · client vaddr base where the canary screenshot RO view is mapped.
 * Clear of LUCAS_SHM_POOL_BASE 0x200000000 (L13's guest pool span) + anon/D3/N3. */
#define LUCAS_CANARY_SCREENSHOT_VIEW_BASE 0x210000000UL
#define LUCAS_KEYMAP_VIEW_BASE 0x220000000UL   /* clear of canary 0x210000000 */

/* N-SYNTH · is_synth_redirected(st, fd).
 *
 * Predicate: should the given socket fd be served by the synth server
 * instead of the real sotnet TCP path?  Used by sendto/recvfrom to fork
 * between synthesized-reply path and real-net path.
 *
 * Heuristic (self-contained, no cross-unit dep on N-CONNECT's
 * per-fd synth_redirected flag): a Tier-2 (isolated-write path) sotbox has
 * `st->functor->is_isolated == true`.  Any of its socket fds are treated
 * as synth-redirected · the existing sendto code at line 335 already
 * relies on the same predicate, so we mirror it here for recvfrom.
 *
 * When N-CONNECT merges and adds a per-fd flag, this helper can be
 * refined to honour both signals · the merge is intended to be
 * additive (logical OR). */
static inline bool is_synth_redirected(lucas_state_t *st, uint64_t fd) {
    if (!st || !st->functor) return false;
    if (fd >= LUCAS_MAX_FDS) return false;
    if (st->fds[fd].kind != LUCAS_FD_SOCKET) return false;
    /* Gate 0 · a sinkholed egress fd (GUARDED · non-allowlisted dst) takes the
     * synth path regardless of session: recv() gets the canned reply, send() is
     * dropped — no real wire — even on the interactive (cow_session != 0) attacker. */
    if (st->fds[fd].synth_sinkhole) return true;
    /* apk-network-install C1 · the interactive SSH attacker session
     * (cow_session != 0) does REAL recv on its sockets (high-interaction
     * honeypot · observe full behavior); only contained/automated Tier-2
     * sotboxes (cow_session == 0) get the synth reply path. */
    if (st->cow_session != 0) return false;
    return st->functor->is_isolated;
}

static inline int lucas_socket_family(const lucas_state_t *st, uint64_t fd) {
    return (int)((st->fds[fd].sock_typefam >> 16) & 0xFFFF);
}

static inline int lucas_socket_type(const lucas_state_t *st, uint64_t fd) {
    return (int)(st->fds[fd].sock_typefam & 0xFFFF);
}

/* N1 · Tier-0e · true when this sandbox is authorised for REAL wire egress. */
static inline bool lucas_is_egress(const lucas_state_t *st) {
    return st && st->functor && st->functor->is_egress;
}

/* apk-network-install C1 · high-interaction honeypot · true for the INTERACTIVE
 * SSH attacker session (cow_session != 0, set at SSH login).  Such a session
 * gets REAL outbound egress (DNS forward + TCP connect) so the attacker can
 * download the tools it needs and we observe its FULL behavior — effects stay
 * Tier-2 contained (writes → session upper, reaped on disconnect) and every
 * connection is IOC'd.  Spawned-malware Tier-2 sotboxes have cow_session == 0
 * (ORCH_OP_VALIDATE etc.), so they KEEP the synth containment — this predicate
 * is the clean line between "interactive attacker, observe everything" and
 * "automated containment test".  Combined with lucas_is_egress at every
 * real-vs-synth fork below. */
/* Operator net-egress policy (sotctl policy net on/off).  Default ON: the
 * high-interaction honeypot lets the interactive SSH attacker reach the REAL wire
 * (contained · observed).  `off` flips the attacker to synth-only containment
 * without touching the operator's own Tier-0e egress (lucas_is_egress). */
int g_lucas_net_egress_policy = 1;
void lucas_net_policy_set(int on) { g_lucas_net_egress_policy = on ? 1 : 0; }
int  lucas_net_policy_get(void)   { return g_lucas_net_egress_policy; }

/* ── Gate 0 · egress DESTINATION policy ───────────────────────────────────────
 * Separate from the on/off above.  When GUARDED, a real-wire session may only
 * reach allowlisted destinations (+ DNS, so name resolution still works); every
 * other non-local connect is SINKHOLED — synthetic success + an IOC log of
 * dst:port (the attacker's C2/exfil MAP) — so NO real packet leaves the host to
 * a third party.  Default OPEN preserves the dev download flow; the RED-TEAM
 * ENGAGEMENT MUST enable GUARDED (legal: no real attacks on third parties from
 * the honeypot host).  Toggle/allowlist via lucas_egress_* (sotctl policy egress). */
#define LUCAS_EGRESS_ALLOW_MAX 16
struct lucas_egress_allow { uint32_t net_be; uint32_t mask_be; uint16_t port_be; };
static struct lucas_egress_allow g_egress_allow[LUCAS_EGRESS_ALLOW_MAX];
static int g_egress_allow_n = 0;
static int g_egress_guarded = 0;   /* 0 = OPEN (dev) · 1 = GUARDED (engagement) */

void lucas_egress_guarded_set(int on) { g_egress_guarded = on ? 1 : 0; }
int  lucas_egress_guarded_get(void)   { return g_egress_guarded; }
void lucas_egress_allow_clear(void)   { g_egress_allow_n = 0; }
int  lucas_egress_allow_add(uint32_t net_be, uint32_t mask_be, uint16_t port_be) {
    if (g_egress_allow_n >= LUCAS_EGRESS_ALLOW_MAX) return -1;
    g_egress_allow[g_egress_allow_n].net_be  = net_be & mask_be;
    g_egress_allow[g_egress_allow_n].mask_be = mask_be;
    g_egress_allow[g_egress_allow_n].port_be = port_be;
    return g_egress_allow_n++;
}
/* True if the REAL wire may reach (addr_be,port_be): OPEN → always; GUARDED →
 * DNS (port 53) always, else must match an allowlist entry (port 0 = any port). */
static bool lucas_egress_dest_allowed(uint32_t addr_be, uint16_t port_be) {
    if (!g_egress_guarded) return true;
    if (port_be == net_htons(53)) return true;
    for (int i = 0; i < g_egress_allow_n; i++)
        if ((addr_be & g_egress_allow[i].mask_be) == g_egress_allow[i].net_be &&
            (g_egress_allow[i].port_be == 0 || g_egress_allow[i].port_be == port_be))
            return true;
    return false;
}

static inline bool lucas_honey_real_egress(const lucas_state_t *st) {
    return st && st->cow_session != 0 && g_lucas_net_egress_policy;
}

/* True when this sandbox should take the REAL wire path (Tier-0e egress OR the
 * interactive SSH attacker session). */
static inline bool lucas_real_wire(const lucas_state_t *st) {
    return lucas_is_egress(st) || lucas_honey_real_egress(st);
}

/* Forward-declare the copy helper defined in handlers_fs.c. */
int lucas_copy_to_client(struct lucas_state *st, uintptr_t client_vaddr,
                          const void *src_buf, size_t size);

/* Allocate a free fd slot (>=3) and mark it as a sotNet socket.
 * Stores family and type in flags for future Phase-β dispatch.
 * Returns the new fd index, or -(int)LX_EMFILE on exhaustion. */
static int alloc_sotnet_fd(lucas_state_t *st, int family, int type, int protocol)
{
    (void)protocol;
    for (int i = 3; i < LUCAS_MAX_FDS; ++i) {
        if (st->fds[i].kind == LUCAS_FD_INVALID && !st->fds[i].is_std) {
            st->fds[i].kind   = LUCAS_FD_SOCKET;
            st->fds[i].pipe   = NULL;
            st->fds[i].mount  = NULL;
            st->fds[i].handle = NULL;
            st->fds[i].cursor = 0;
            /* Address-family + type live in a DEDICATED field so fcntl(F_SETFL/
             * F_SETFD) — which overwrites `flags` with the fd's open-flags —
             * can't clobber the socket type (the bug that made a non-blocking
             * TCP socket connect() as UDP, no SYN).  `flags` starts clear and
             * holds O_NONBLOCK/O_CLOEXEC like any other fd. */
            st->fds[i].sock_typefam = (family << 16) | (type & 0xFFFF);
            st->fds[i].flags  = 0;
            st->fds[i].synth_recv_consumed = 0;
            st->fds[i].wayland_connected     = 0;
            st->fds[i].wayland_route_ep      = 0;
            memset(st->fds[i].unix_path, 0, sizeof(st->fds[i].unix_path));
            memset(st->fds[i].wl_rx, 0, sizeof(st->fds[i].wl_rx));
            st->fds[i].wl_rx_len    = 0;
            st->fds[i].wl_rx_cursor = 0;
            st->fds[i].connect_peer_ip_be    = 0;  /* γ-3-γ-2b */
            st->fds[i].connect_peer_port_be  = 0;
            if (st->fds[i].lwip_sess) {             /* SOCKET DEMUX · free lwIP egress session */
                extern void orch_lwip_egress_close(void *handle);
                orch_lwip_egress_close(st->fds[i].lwip_sess);
                st->fds[i].lwip_sess = NULL;
            }
            st->fds[i].tcp_conn = NULL;             /* N1 · δ-2 */
            st->fds[i].unix_listener_idx1 = 0;      /* WINE-M1 · AF_UNIX rendezvous */
            st->fds[i].unix_chan_idx1     = 0;
            st->fds[i].unix_server_end    = 0;
            st->fds[i].is_netlink           = (family == LUCAS_AF_NETLINK); /* apt-T7 */
            st->fds[i].netlink_dump_pending = 0;
            st->fds[i].netlink_dump_type    = 0;
            st->fds[i].netlink_seq          = 0;
            st->fds[i].netlink_pid          = 0;
            return i;
        }
    }
    return -24;  /* -EMFILE */
}

/* ===================================================================== */
/* apt-T7 · AF_NETLINK(NETLINK_ROUTE) RTM_GETADDR stub.                  */
/* ===================================================================== */
/*
 * glibc getaddrinfo's AI_ADDRCONFIG probe (__check_pf) opens a route-netlink
 * socket and dumps RTM_GETADDR to enumerate addresses; without a usable IPv4
 * interface it will not even query A records.  The shim returned 0 from
 * recvmsg → glibc aborts "Unexpected netlink response of size 0" (SIGABRT).
 *
 * We synthesize the MINIMAL valid reply: ONE IPv4 RTM_NEWADDR for eth0
 * (10.0.2.15 · the honey guest IP) + an NLMSG_DONE terminator, both in one
 * datagram.  glibc then sees IPv4 is configured and proceeds to resolve.
 */

/* True if a send buffer carries a route-netlink DUMP request we answer
 * (RTM_GETADDR or RTM_GETLINK · glibc getifaddrs does both for source selection).
 * *type_out/*seq_out get the request's nlmsg_type + nlmsg_seq (echoed in reply). */
static bool netlink_is_dump(const void *buf, size_t len,
                            uint16_t *type_out, uint32_t *seq_out)
{
    if (len < 16) return false;
    const uint8_t *p = (const uint8_t *)buf;
    uint16_t nlmsg_type = (uint16_t)(p[4] | (p[5] << 8));
    uint32_t nlmsg_seq  = (uint32_t)(p[8] | (p[9] << 8) | (p[10] << 16) | (p[11] << 24));
    if (nlmsg_type == LUCAS_RTM_GETADDR || nlmsg_type == LUCAS_RTM_GETLINK) {
        if (type_out) *type_out = nlmsg_type;
        if (seq_out)  *seq_out  = nlmsg_seq;
        return true;
    }
    return false;
}

/* Build ONE RTM_NEWLINK for eth0 (index 2, IFF_UP|IFF_RUNNING, ARPHRD_ETHER) so
 * glibc getifaddrs has a link to correlate the RTM_NEWADDR(index 2) against.
 * nlmsghdr 16 + ifinfomsg 16 + rtattr IFLA_IFNAME("eth0\0",pad) = 16+16+12 = 44. */
static size_t netlink_build_newlink(uint8_t *out, size_t cap, uint32_t seq, uint32_t pid)
{
    /* ifinfomsg {u8 family; u8 pad; u16 type; s32 index; u32 flags; u32 change;} = 16 */
    size_t hdr = 16, ifi = 16;
    /* rtattr IFLA_IFNAME(3): rta_len = 4 + strlen("eth0")+1 = 9 → RTA_ALIGN = 12 */
    size_t rta = LUCAS_RTA_ALIGN(4 + 5);   /* "eth0\0" = 5 */
    size_t total = hdr + ifi + rta;
    if (total > cap) return 0;
    memset(out, 0, total);
    uint8_t *p = out;
    uint32_t nlen = (uint32_t)total;
    p[0]=(uint8_t)nlen; p[1]=(uint8_t)(nlen>>8); p[2]=(uint8_t)(nlen>>16); p[3]=(uint8_t)(nlen>>24);
    p[4]=(uint8_t)LUCAS_RTM_NEWLINK; p[5]=(uint8_t)(LUCAS_RTM_NEWLINK>>8);
    p[6]=(uint8_t)LUCAS_NLM_F_MULTI; p[7]=(uint8_t)(LUCAS_NLM_F_MULTI>>8);
    p[8]=(uint8_t)seq; p[9]=(uint8_t)(seq>>8); p[10]=(uint8_t)(seq>>16); p[11]=(uint8_t)(seq>>24);
    p[12]=(uint8_t)pid; p[13]=(uint8_t)(pid>>8); p[14]=(uint8_t)(pid>>16); p[15]=(uint8_t)(pid>>24);
    uint8_t *ifi_p = p + 16;
    ifi_p[0]=0;            /* ifi_family = AF_UNSPEC */
    ifi_p[2]=1; ifi_p[3]=0;/* ifi_type = ARPHRD_ETHER(1) */
    ifi_p[4]=2; ifi_p[5]=0; ifi_p[6]=0; ifi_p[7]=0;        /* ifi_index = 2 (eth0) */
    ifi_p[8]=0x43; ifi_p[9]=0; ifi_p[10]=1; ifi_p[11]=0;   /* ifi_flags = IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST (0x1043) */
    uint8_t *a = ifi_p + 16;
    a[0]=9; a[1]=0;        /* rta_len = 4 + 5 */
    a[2]=3; a[3]=0;        /* rta_type = IFLA_IFNAME */
    a[4]='e'; a[5]='t'; a[6]='h'; a[7]='0'; a[8]='\0';
    return total;
}

/* Build ONE IPv4 RTM_NEWADDR(10.0.2.15) message into out.  Returns bytes (40), 0
 * if no fit.  Delivered as its OWN datagram (phase 1) — see netlink_handle_recv. */
static size_t netlink_build_newaddr(uint8_t *out, size_t cap, uint32_t seq, uint32_t pid)
{
    /* nlmsghdr 16 + ifaddrmsg 8 + rtattr IFA_LOCAL 8 + rtattr IFA_ADDRESS 8 = 40 */
    const uint8_t ip[4] = { 10, 0, 2, 15 };   /* g_our_ip = 0x0F02000A */
    size_t newaddr_len = 16 + 8 + 8 + 8;
    if (newaddr_len > cap) return 0;
    memset(out, 0, newaddr_len);
    uint8_t *p = out;
    /* nlmsghdr */
    p[0] = (uint8_t)(newaddr_len);       p[1] = (uint8_t)(newaddr_len >> 8);
    p[2] = (uint8_t)(newaddr_len >> 16); p[3] = (uint8_t)(newaddr_len >> 24);
    p[4] = (uint8_t)(LUCAS_RTM_NEWADDR); p[5] = (uint8_t)(LUCAS_RTM_NEWADDR >> 8);
    p[6] = (uint8_t)(LUCAS_NLM_F_MULTI); p[7] = (uint8_t)(LUCAS_NLM_F_MULTI >> 8);
    p[8] = (uint8_t)(seq);  p[9] = (uint8_t)(seq >> 8);
    p[10]= (uint8_t)(seq >> 16); p[11]= (uint8_t)(seq >> 24);
    p[12]= (uint8_t)(pid);  p[13]= (uint8_t)(pid >> 8);
    p[14]= (uint8_t)(pid >> 16); p[15]= (uint8_t)(pid >> 24);
    /* ifaddrmsg */
    uint8_t *ifa = p + 16;
    ifa[0] = (uint8_t)LUCAS_AF_INET;   /* ifa_family = AF_INET */
    ifa[1] = 24;                       /* ifa_prefixlen */
    ifa[2] = 0;                        /* ifa_flags */
    ifa[3] = 0;                        /* ifa_scope (RT_SCOPE_UNIVERSE) */
    ifa[4] = 2; ifa[5] = 0; ifa[6] = 0; ifa[7] = 0;   /* ifa_index = 2 (eth0) */
    /* rtattr IFA_LOCAL */
    uint8_t *a1 = ifa + 8;
    a1[0] = 8; a1[1] = 0;                       /* rta_len = 8 */
    a1[2] = (uint8_t)LUCAS_IFA_LOCAL; a1[3] = 0;/* rta_type = IFA_LOCAL */
    a1[4] = ip[0]; a1[5] = ip[1]; a1[6] = ip[2]; a1[7] = ip[3];
    /* rtattr IFA_ADDRESS */
    uint8_t *a2 = a1 + 8;
    a2[0] = 8; a2[1] = 0;
    a2[2] = (uint8_t)LUCAS_IFA_ADDRESS; a2[3] = 0;
    a2[4] = ip[0]; a2[5] = ip[1]; a2[6] = ip[2]; a2[7] = ip[3];
    return newaddr_len;
}

/* Build the NLMSG_DONE terminator into out.  Returns bytes (20), 0 if no fit.
 * Delivered as its OWN datagram (phase 2) so glibc's recvmsg loop terminates. */
static size_t netlink_build_done(uint8_t *out, size_t cap, uint32_t seq, uint32_t pid)
{
    size_t done_len = 16 + 4;                  /* nlmsghdr + int32 error */
    if (done_len > cap) return 0;
    memset(out, 0, done_len);
    uint8_t *d = out;
    uint32_t dlen = (uint32_t)done_len;
    d[0] = (uint8_t)(dlen);       d[1] = (uint8_t)(dlen >> 8);
    d[2] = (uint8_t)(dlen >> 16); d[3] = (uint8_t)(dlen >> 24);
    d[4] = (uint8_t)(LUCAS_NLMSG_DONE); d[5] = (uint8_t)(LUCAS_NLMSG_DONE >> 8);
    d[6] = (uint8_t)(LUCAS_NLM_F_MULTI); d[7] = (uint8_t)(LUCAS_NLM_F_MULTI >> 8);
    d[8] = (uint8_t)(seq);  d[9] = (uint8_t)(seq >> 8);
    d[10]= (uint8_t)(seq >> 16); d[11]= (uint8_t)(seq >> 24);
    d[12]= (uint8_t)(pid);  d[13]= (uint8_t)(pid >> 8);
    d[14]= (uint8_t)(pid >> 16); d[15]= (uint8_t)(pid >> 24);
    /* int32 error = 0 (already zeroed by memset) */
    return done_len;
}

/* apt-T7 · handle a send/sendto/sendmsg/write on a netlink fd.  Records a
 * pending dump if it's RTM_GETADDR; returns the consumed length (always
 * accepts the whole buffer so glibc proceeds to recvmsg). */
static int64_t netlink_handle_send(lucas_state_t *st, int fd,
                                   const void *kbuf, size_t len)
{
    uint32_t seq = 0; uint16_t rtype = 0;
    if (netlink_is_dump(kbuf, len, &rtype, &seq)) {
        const uint8_t *q = (const uint8_t *)kbuf;   /* len >= 16 guaranteed here */
        uint32_t rpid = (uint32_t)(q[12] | (q[13]<<8) | (q[14]<<16) | (q[15]<<24));
        st->fds[fd].netlink_dump_pending = 1;
        st->fds[fd].netlink_dump_type    = (uint8_t)rtype;
        st->fds[fd].netlink_seq          = seq;
        st->fds[fd].netlink_pid          = rpid;   /* echo it in the reply */
        printf("[netlink] pid=%d %s dump requested (seq=%u pid=%u) → reply queued\n",
               st->synthetic_pid,
               rtype == LUCAS_RTM_GETLINK ? "RTM_GETLINK" : "RTM_GETADDR",
               (unsigned int)seq, (unsigned int)rpid);
    } else {
        printf("[netlink] pid=%d send len=%zu (non-GETADDR · accepted)\n",
               st->synthetic_pid, len);
    }
    return (int64_t)len;
}

/* apt-T7 · handle a recv/recvfrom/recvmsg/read on a netlink fd.  The RTM_GETADDR
 * dump is delivered in TWO datagrams (kernel-accurate multipart): phase 1 = ONE
 * RTM_NEWADDR(10.0.2.15), phase 2 = NLMSG_DONE.  glibc __check_pf recvmsg-loops
 * until it sees NLMSG_DONE; a single COMBINED datagram made it recvmsg AGAIN and
 * hit "Unexpected netlink response of size 0" SIGABRT, so the terminator MUST be
 * its own read.  netlink_dump_pending is the phase (1→2→0).  MSG_PEEK(0x02) must
 * NOT advance the phase (glibc may peek to size first); MSG_TRUNC(0x20) returns
 * the true datagram length. */
static int64_t netlink_handle_recv(lucas_state_t *st, int fd,
                                   uintptr_t client_vaddr, size_t cap,
                                   uint64_t flags)
{
    const uint64_t MSG_PEEK_F  = 0x02;
    const uint64_t MSG_TRUNC_F = 0x20;
    uint8_t  phase    = st->fds[fd].netlink_dump_pending;
    uint8_t  dtype    = st->fds[fd].netlink_dump_type;
    uint32_t seq      = st->fds[fd].netlink_seq;
    /* nlmsg_pid in the reply MUST equal glibc's expected port id (the request's
     * nlmsg_pid = 0 · autobind, and our shim assigns no port).  glibc __check_pf
     * SKIPS (continues past) any reply message whose nlmsg_pid != its port — incl.
     * NLMSG_DONE — so a mismatch (e.g. the method's synthetic pid) makes it never
     * terminate → "Unexpected netlink response of size 0".  Echo the kernel's 0. */
    uint32_t reply_pid = st->fds[fd].netlink_pid;
    uint8_t reply[64];
    size_t n;
    if (phase == 0) {
        /* SAFETY NET · a netlink recv with no pending dump returns NLMSG_DONE,
         * never bare 0 — glibc aborts ("Unexpected netlink response of size 0")
         * the instant a netlink recvmsg returns 0, so a missed/duplicate read or
         * an unrecognized request must still terminate the dump gracefully. */
        n = netlink_build_done(reply, sizeof(reply), seq, reply_pid);
    } else if (phase == 1) {
        n = (dtype == LUCAS_RTM_GETLINK)
              ? netlink_build_newlink(reply, sizeof(reply), seq, reply_pid)
              : netlink_build_newaddr(reply, sizeof(reply), seq, reply_pid);
    } else {
        n = netlink_build_done(reply, sizeof(reply), seq, reply_pid);
    }
    if (n == 0) return -(int64_t)90;  /* EMSGSIZE (build failed) */

    /* Copy as much as fits.  Under MSG_TRUNC the return value is the REAL
     * datagram size even if truncated (this is how glibc sizes its buffer). */
    size_t copy = n < cap ? n : cap;
    if (copy && lucas_copy_to_client(st, client_vaddr, reply, copy) != 0)
        return -(int64_t)LX_EFAULT;

    if (!(flags & MSG_PEEK_F)) {
        st->fds[fd].netlink_dump_pending = (phase == 1) ? 2 : 0;   /* advance the dump */
        const char *what = (phase != 1) ? "NLMSG_DONE"
                         : (dtype == LUCAS_RTM_GETLINK) ? "RTM_NEWLINK(eth0)"
                                                        : "RTM_NEWADDR(10.0.2.15)";
        printf("[netlink] pid=%d %s delivered (%zu B · phase=%d)\n",
               st->synthetic_pid, what, n, phase);
    }
    /* MSG_TRUNC: report the true datagram length (n), not the copied length. */
    return (int64_t)((flags & MSG_TRUNC_F) ? n : copy);
}

/* ===================================================================== */
/* WINE-M1 · Phase 4 · cross-sotbox AF_UNIX SOCK_STREAM rendezvous.      */
/* ===================================================================== */
/*
 * wine and wineserver speak over an AF_UNIX stream socket at
 * $WINEPREFIX/.wine-0/server-<id>/socket.  Both are SEPARATE sotboxes, but every
 * sotbox's syscalls run here in orch's address space, so the AF_UNIX namespace
 * + connected channels live in process-global tables.  A listener is keyed by
 * its bound path; connect() matches a listener, allocates a channel (two byte
 * rings — client→server c2s, server→client s2c) and queues it on the listener
 * backlog; accept() dequeues it and hands the server its endpoint.  read/write
 * drain/fill the right ring half; a read on an empty ring parks
 * (WAITING_FOR_UNIX) and is woken when the peer writes or closes.
 *
 * This is the honest IPC path wineserver needs (the old listen() mis-routed
 * AF_UNIX to the TCP backend → EADDRINUSE).  SCM_RIGHTS fd-passing rides on top
 * via recvmsg/sendmsg (added incrementally as the wineserver handshake needs).
 */
#define LUCAS_UNIX_MAX_LISTENERS 8
#define LUCAS_UNIX_MAX_CHANNELS  16
#define LUCAS_UNIX_RING          65536u            /* per-direction · power of two ·
   * 64 KiB (16ch × 2dir = 2 MiB static).  32 KiB truncated an egress download whose
   * decrypted payload (e.g. a 34 KiB pypi sdist) overran the ring: under the single-
   * threaded orch, the openssl→wget relay can't drain wget (slow sotfs file writes)
   * fast enough mid-stream, so a ring smaller than the whole transfer loses the tail
   * → `tar: short read`.  64 KiB holds a small package whole; arbitrary-size needs
   * blocking write-park flow-control (deferred). */
#define LUCAS_UNIX_RING_MASK     (LUCAS_UNIX_RING - 1u)
#define LUCAS_UNIX_BACKLOG       8
#define LUCAS_UNIX_EAGAIN        ((int64_t)-100000) /* internal "would block" sentinel */
#ifndef SOTBOX_MAX_SLOTS
#define SOTBOX_MAX_SLOTS 8  /* fall-back · matches include/orch/sotbox.h */
#endif

typedef struct {
    int  in_use;
    char path[LUCAS_UNIX_PATH_MAX];
    int  owner_slot;                          /* sotbox slot that listen()ed */
    int  backlog[LUCAS_UNIX_BACKLOG];         /* channel idxs pending accept */
    int  bl_head, bl_count;
} unix_listener_t;

#define LUCAS_UNIX_SCM_MAX 8
typedef struct {
    int      in_use;
    uint8_t  c2s[LUCAS_UNIX_RING]; uint32_t c2s_h, c2s_t;   /* client → server */
    uint8_t  s2c[LUCAS_UNIX_RING]; uint32_t s2c_h, s2c_t;   /* server → client */
    int      client_slot, server_slot;
    uint8_t  client_closed, server_closed;
    /* Directional WRITE half-close (shutdown(SHUT_WR)): the end stopped writing
     * its ring, so the PEER's read sees EOF — but the end can still READ, so the
     * peer's write must NOT get EPIPE.  Distinct from *_closed (full close, both
     * directions).  client_wr_shut → c2s is done (server reads EOF); the s2c
     * write path keeps checking only *_closed. */
    uint8_t  client_wr_shut, server_wr_shut;
    /* WINE-M1 · socketpair refcounts.  0 = legacy rendezvous channel (connect/
     * accept): the first close of an end marks it closed.  socketpair sets both
     * to 1; SCM-passing the end to another sotbox and fork()ing a holder bump
     * the count; close decrements and only marks the end closed at 0.  This lets
     * the wine launcher create the pair, hand one end to wineserver (SCM) and
     * one to the forked child, then drop ITS copies without tearing the channel
     * down under the two real users (wineserver ↔ the new process). */
    int      client_refs, server_refs;
    /* WINE-M1 · SCM_RIGHTS fd-passing.  scm[E] = fds queued for the end E to
     * receive (E=0 client end, E=1 server end).  ring_seq = the read-ring
     * position (free-running tail) at the END of the sendmsg's data — the
     * message BOUNDARY.  A recvmsg never reads past the front boundary and
     * delivers a cmsg only once its data has been consumed, so wineserver (which
     * claims one fd per recvmsg) pairs each SCM fd with its own message.
     *
     * The in-flight fd is HELD BY THE CHANNEL, not referenced by {slot,fd}:
     *  - the sender may close() its copy right after sendmsg (POSIX SCM), and
     *  - the receiver may be a forked child that execve()s (which closes its
     *    inherited PIPE fds) BETWEEN the send and its first recvmsg.
     * Either would invalidate a {slot,fd} reference.  So at sendmsg the channel
     * takes its OWN refcount on the underlying object (pipe add_reader/writer, or
     * a socket-channel end ref) and records it here; delivery transfers that held
     * ref into a fresh fd in the receiving sotbox.  This mirrors a real kernel
     * holding the in-flight file in the socket buffer. */
    struct {
        uint32_t   ring_seq;
        lucas_fd_t held_fd;       /* FULL captured fd · preserves the backing for
                                   * every kind (VFS mount/handle for the USD
                                   * section, memfd, pipe ptr, socket-channel). */
        int        src_slot, src_fd; /* logging only */
    }        scm[2][LUCAS_UNIX_SCM_MAX];
    int      scm_n[2];   /* FIFO count · front = index 0 */
} unix_channel_t;

static unix_listener_t g_unix_listeners[LUCAS_UNIX_MAX_LISTENERS];
static unix_channel_t  g_unix_channels[LUCAS_UNIX_MAX_CHANNELS];

/* Re-scan epoll/poll waiters after an AF_UNIX readiness change (new backlog,
 * fresh ring bytes, peer close).  wineserver's main loop parks in epoll_wait,
 * NOT accept — without this a connect()/write() that arrives while it's parked
 * would never wake it.  The hook (iomux.c, also used by pipe.c) is a safe
 * no-op when no sotbox is epoll-parked. */
struct lucas_pipe;
extern void iomux_check_epoll_waiters(struct lucas_pipe *p);

static inline uint32_t uring_used(uint32_t h, uint32_t t) { return t - h; }
static inline uint32_t uring_free(uint32_t h, uint32_t t) { return LUCAS_UNIX_RING - (t - h); }

static int unix_listener_find(const char *path) {
    for (int i = 0; i < LUCAS_UNIX_MAX_LISTENERS; ++i)
        if (g_unix_listeners[i].in_use && strcmp(g_unix_listeners[i].path, path) == 0)
            return i;
    return -1;
}

/* Deliver any SCM_RIGHTS fds queued for the receiving end E of channel `ci`
 * into `st`'s msghdr: install each fd, write a cmsg (SOL_SOCKET/SCM_RIGHTS) at
 * ctl_vaddr, and set msghdr.msg_controllen (offset 40).  Always writes
 * msg_controllen (0 when no fds), so a stale MSG_CTRUNC is never seen.
 * struct cmsghdr x86-64: cmsg_len(u64)@0, cmsg_level(i32)@8, cmsg_type(i32)@12,
 * fds@16. */
static void unix_scm_deliver(lucas_state_t *st, int ci, uint8_t server_end,
                             uintptr_t msg_vaddr, uintptr_t ctl_vaddr, size_t ctllen) {
    uint64_t cl0 = 0;
    if (msg_vaddr) lucas_copy_to_client(st, msg_vaddr + 40, &cl0, 8);   /* default controllen=0 */
    if (ci < 0 || ci >= LUCAS_UNIX_MAX_CHANNELS) return;
    unix_channel_t *ch = &g_unix_channels[ci];
    int E = server_end ? 1 : 0;
    if (ch->scm_n[E] <= 0 || !ctl_vaddr || ctllen < 16 + 4) return;
    /* Deliver the FRONT message only, and only once the reader has consumed its
     * data (the boundary ring_seq is at/behind the read head).  This pairs one
     * cmsg with one recvmsg's data (wineserver claims one fd per recvmsg). */
    uint32_t head = server_end ? ch->c2s_h : ch->s2c_h;
    uint32_t seq0 = ch->scm[E][0].ring_seq;
    if ((int32_t)(head - seq0) < 0) return;   /* this message's data not read yet */
    int nfds = 0;                              /* group entries sharing this boundary */
    while (nfds < ch->scm_n[E] && ch->scm[E][nfds].ring_seq == seq0) nfds++;
    int cap = (int)((ctllen - 16) / 4);
    if (nfds > cap) nfds = cap;
    if (nfds <= 0) return;
    uint64_t cmsg_len = (uint64_t)(16 + nfds * 4);
    int32_t  lvl = 1 /*SOL_SOCKET*/, typ = 1 /*SCM_RIGHTS*/;
    lucas_copy_to_client(st, ctl_vaddr + 0,  &cmsg_len, 8);
    lucas_copy_to_client(st, ctl_vaddr + 8,  &lvl, 4);
    lucas_copy_to_client(st, ctl_vaddr + 12, &typ, 4);
    for (int i = 0; i < nfds; ++i) {
        /* Install the channel-held fd into a fresh slot in the RECEIVER (st),
         * transferring the full captured fd (and the ref the channel took at send
         * time — no extra add / no release).  A socket-channel end also re-homes
         * its owner slot to the receiver. */
        int nf = -1;
        for (int m = 3; m < LUCAS_MAX_FDS; ++m)
            if (st->fds[m].kind == LUCAS_FD_INVALID && !st->fds[m].is_std) { nf = m; break; }
        if (nf >= 0) {
            st->fds[nf] = ch->scm[E][i].held_fd;     /* full transfer */
            lucas_fd_t *d = &st->fds[nf];
            if (d->kind == LUCAS_FD_SOCKET && d->unix_chan_idx1) {
                int hc = d->unix_chan_idx1 - 1;
                if (hc >= 0 && hc < LUCAS_UNIX_MAX_CHANNELS) {
                    if (d->unix_server_end) g_unix_channels[hc].server_slot = st->slot_index;
                    else                    g_unix_channels[hc].client_slot = st->slot_index;
                }
            }
        }
        uint32_t f = (uint32_t)(nf >= 0 ? nf : -1);
        lucas_copy_to_client(st, ctl_vaddr + 16 + (size_t)i * 4, &f, 4);
        printf("[unix] SCM recv pid=%d · installed fd=%d kind=%d (src slot=%d fd=%d) seq=%u\n",
               st->synthetic_pid, nf, ch->scm[E][i].held_fd.kind,
               ch->scm[E][i].src_slot, ch->scm[E][i].src_fd, seq0);
    }
    lucas_copy_to_client(st, msg_vaddr + 40, &cmsg_len, 8);   /* controllen */
    for (int i = nfds; i < ch->scm_n[E]; ++i) ch->scm[E][i - nfds] = ch->scm[E][i];  /* FIFO pop */
    ch->scm_n[E] -= nfds;
}

/* Enqueue SCM_RIGHTS fds for the channel's OTHER end to read, tagged with the
 * message boundary (write-ring tail + this sendmsg's data len) so the receiver
 * pairs each fd with its own recvmsg.  CAPTURES each fd NOW by taking a channel
 * refcount on the underlying object (pipe add_reader/writer, or a socket-channel
 * end ref) and recording it — NOT a {slot,fd} reference, which would dangle once
 * the sender close()s its copy or the (forked) receiver execve()s away its
 * inherited fds.  Delivery transfers the held ref into a fresh receiver fd. */
static void unix_scm_enqueue(lucas_state_t *st, int ci, uint8_t sender_server_end,
                             const int *fds, int nfds, uint64_t data_len) {
    extern void lucas_pipe_add_reader(struct lucas_pipe *);
    extern void lucas_pipe_add_writer(struct lucas_pipe *);
    if (ci < 0 || ci >= LUCAS_UNIX_MAX_CHANNELS) return;
    unix_channel_t *ch = &g_unix_channels[ci];
    int E = sender_server_end ? 0 : 1;   /* receiver end = the OTHER end */
    /* boundary = end of THIS sendmsg's data in the ring the receiver reads. */
    uint32_t seq = (sender_server_end ? ch->s2c_t : ch->c2s_t) + (uint32_t)data_len;
    for (int i = 0; i < nfds && ch->scm_n[E] < LUCAS_UNIX_SCM_MAX; ++i) {
        if (fds[i] < 0 || fds[i] >= LUCAS_MAX_FDS) continue;
        lucas_fd_t *s = &st->fds[fds[i]];
        if (s->kind == LUCAS_FD_INVALID) continue;
        int idx = ch->scm_n[E];
        ch->scm[E][idx].ring_seq = seq;
        ch->scm[E][idx].held_fd  = *s;          /* full capture (all backing fields) */
        ch->scm[E][idx].src_slot = st->slot_index;
        ch->scm[E][idx].src_fd   = fds[i];
        /* Take the channel's own ref on the refcounted backings so the object
         * survives the sender close()ing its copy and a forked receiver
         * execve()ing away its inherited fds (VFS/memfd handles are process-global
         * in the shared graph, so the held copy stays valid without a bump). */
        if (s->kind == LUCAS_FD_PIPE_READ && s->pipe) {
            lucas_pipe_add_reader(s->pipe);
        } else if (s->kind == LUCAS_FD_PIPE_WRITE && s->pipe) {
            lucas_pipe_add_writer(s->pipe);
        } else if (s->kind == LUCAS_FD_SOCKET && s->unix_chan_idx1) {
            int hc = s->unix_chan_idx1 - 1;
            if (hc >= 0 && hc < LUCAS_UNIX_MAX_CHANNELS) {
                if (s->unix_server_end) { if (g_unix_channels[hc].server_refs > 0) g_unix_channels[hc].server_refs++; }
                else                    { if (g_unix_channels[hc].client_refs > 0) g_unix_channels[hc].client_refs++; }
            }
        } else if (s->kind == LUCAS_FD_VFS && s->handle &&
                   s->mount && s->mount->ops->dup_handle) {
            /* A VFS-backed fd (the KUSER_SHARED_DATA section, or a page-aligned PE
             * file wine maps file-backed for new_process — wineboot/start.exe).
             * The sender close()s its copy right after the send, and the backend
             * handle pool RECYCLES the slot, so sharing the sender's handle leaves
             * the receiver reading a recycled handle (op_read EBADF / bad inode →
             * "map_pe_header Bad file descriptor" → c000007b).  Give the held copy
             * its OWN independent handle (same inode/path) so its lifetime is the
             * receiver's; the receiver op_close()s it normally. */
            void *dup = s->mount->ops->dup_handle(s->mount->backend_state, s->handle);
            if (dup) {
                ch->scm[E][idx].held_fd.handle      = dup;
                ch->scm[E][idx].held_fd.lazy_pinned = 0;   /* receiver owns it */
                printf("[unix] SCM dup VFS fd=%d handle=%p->%p (sender slot=%d)\n",
                       fds[i], s->handle, dup, st->slot_index);
            } else {
                printf("[unix] SCM dup VFS fd=%d FAILED · handle=%p (pool full / src !in_use)\n",
                       fds[i], s->handle);
            }
        }
        ch->scm_n[E]++;
        printf("[unix] SCM send pid=%d chan[%d] · held fd=%d kind=%d seq=%u\n",
               st->synthetic_pid, ci, fds[i], s->kind, seq);
    }
}

/* do_unix_recv · drain the read ring half into the client buffer.  Returns
 * bytes read (>0), 0 on EOF (ring empty + peer closed), LUCAS_UNIX_EAGAIN when
 * empty but peer still open (caller parks), or -errno on copy fault. */
static int64_t do_unix_recv(lucas_state_t *st, int ci, uint8_t server_end,
                            uintptr_t buf_vaddr, uint64_t count) {
    if (ci < 0 || ci >= LUCAS_UNIX_MAX_CHANNELS || !g_unix_channels[ci].in_use)
        return 0;  /* channel gone → EOF */
    unix_channel_t *ch = &g_unix_channels[ci];
    uint8_t *ring; uint32_t *h, *t;
    if (server_end) { ring = ch->c2s; h = &ch->c2s_h; t = &ch->c2s_t; }  /* server reads c2s */
    else            { ring = ch->s2c; h = &ch->s2c_h; t = &ch->s2c_t; }  /* client reads s2c */
    uint32_t avail = uring_used(*h, *t);
    if (avail == 0) {
        /* EOF when the peer fully closed OR write-half-closed (SHUT_WR) its side
         * of THIS direction.  Server reads c2s → peer is the client. */
        uint8_t peer_done = server_end ? (ch->client_closed || ch->client_wr_shut)
                                       : (ch->server_closed || ch->server_wr_shut);
        return peer_done ? 0 : LUCAS_UNIX_EAGAIN;
    }
    uint32_t want = (count > avail) ? avail : (uint32_t)count;
    /* WINE-M1 · SCM framing: never read past the front control-message boundary,
     * so this recvmsg's data pairs with exactly one queued cmsg (one fd). */
    {
        int E = server_end ? 1 : 0;
        if (ch->scm_n[E] > 0) {
            uint32_t to_bound = ch->scm[E][0].ring_seq - *h;   /* bytes until boundary */
            if ((int32_t)to_bound > 0 && to_bound < want) want = to_bound;
        }
    }
    uint32_t done = 0;
    uint8_t tmp[2048];
    while (done < want) {
        uint32_t chunk = want - done; if (chunk > sizeof(tmp)) chunk = sizeof(tmp);
        for (uint32_t i = 0; i < chunk; ++i) { tmp[i] = ring[(*h) & LUCAS_UNIX_RING_MASK]; (*h)++; }
        if (lucas_copy_to_client(st, buf_vaddr + done, tmp, chunk) != 0)
            return (done > 0) ? (int64_t)done : -(int64_t)LX_EFAULT;
        done += chunk;
    }
    return (int64_t)done;
}

/* Wake a sotbox parked in WAITING_FOR_UNIX on (chan_idx, reader_is_server_end).
 * Re-drains the ring into its stashed buffer and Sends the saved reply cap. */
void lucas_unix_wake_reader(int chan_idx, uint8_t reader_is_server_end) {
    extern lucas_state_t *sotbox_get_slot(int idx);
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *w = sotbox_get_slot(i);
        if (!w || w->state != SOTBOX_STATE_WAITING_FOR_UNIX) continue;
        if (w->waiting_unix_chan1 != chan_idx + 1) continue;
        if (w->waiting_unix_server_end != reader_is_server_end) continue;
        int64_t r = do_unix_recv(w, chan_idx, reader_is_server_end,
                                 w->waiting_unix_buf_vaddr, w->waiting_unix_count);
        if (r == LUCAS_UNIX_EAGAIN) return;   /* spurious · stay parked */
        seL4_UserContext regs;
        if (seL4_TCB_ReadRegisters(w->client_tcb, false, 0, 18, &regs) == 0) {
            regs.rax = (uint64_t)r; regs.rip += 2; regs.rcx = regs.rip; regs.r11 = regs.rflags;
            seL4_TCB_WriteRegisters(w->client_tcb, false, 0, 18, &regs);
        }
        /* WINE-M1 · if this was a recvmsg park, also deliver any SCM_RIGHTS fds
         * into the stashed msghdr before resuming the client. */
        if (w->waiting_unix_msg_vaddr)
            unix_scm_deliver(w, chan_idx, reader_is_server_end,
                             w->waiting_unix_msg_vaddr, w->waiting_unix_msgctl,
                             w->waiting_unix_msgctllen);
        seL4_Send(w->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
        vka_cspace_free(w->vka, w->waiting_reply_cap);
        w->waiting_reply_cap     = 0;
        w->waiting_unix_chan1    = 0;
        w->waiting_unix_msg_vaddr = 0;
        w->waiting_unix_msgctl   = 0;
        w->waiting_unix_msgctllen = 0;
        w->state                 = SOTBOX_STATE_RUNNING;
        printf("[unix] WAKE reader pid=%d chan[%d] server_end=%u → %ld bytes\n",
               w->synthetic_pid, chan_idx, reader_is_server_end, (long)r);
        return;
    }
}

/* lucas_unix_send · append client bytes to the WRITE ring half, wake the peer
 * reader.  Returns bytes written, or -EPIPE if the peer closed, or -EAGAIN if
 * the ring is full. */
int64_t lucas_unix_send(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr, uint64_t len) {
    int ci = st->fds[fd].unix_chan_idx1 - 1;
    if (ci < 0 || ci >= LUCAS_UNIX_MAX_CHANNELS || !g_unix_channels[ci].in_use)
        return -(int64_t)32;  /* EPIPE */
    unix_channel_t *ch = &g_unix_channels[ci];
    uint8_t server = st->fds[fd].unix_server_end;
    uint8_t peer_closed = server ? ch->client_closed : ch->server_closed;
    if (peer_closed) return -(int64_t)32;  /* EPIPE */
    uint8_t *ring; uint32_t *h, *t;
    if (server) { ring = ch->s2c; h = &ch->s2c_h; t = &ch->s2c_t; }  /* server writes s2c */
    else        { ring = ch->c2s; h = &ch->c2s_h; t = &ch->c2s_t; }  /* client writes c2s */
    uint32_t freeb = uring_free(*h, *t);
    if (freeb == 0) return -(int64_t)11;  /* EAGAIN · ring full */
    uint32_t want = (len > freeb) ? freeb : (uint32_t)len;
    uint32_t done = 0;
    uint8_t tmp[2048];
    while (done < want) {
        uint32_t chunk = want - done; if (chunk > sizeof(tmp)) chunk = sizeof(tmp);
        if (lucas_copy_from_client(st, (uintptr_t)(buf_vaddr + done), tmp, chunk) != 0) break;
        for (uint32_t i = 0; i < chunk; ++i) { ring[(*t) & LUCAS_UNIX_RING_MASK] = tmp[i]; (*t)++; }
        done += chunk;
    }
    if (done == 0) return -(int64_t)LX_EFAULT;
    lucas_unix_wake_reader(ci, (uint8_t)(server ? 0 : 1));   /* wake the PEER end */
    iomux_check_epoll_waiters(NULL);                         /* …or epoll-parked on it */
    return (int64_t)done;
}

/* lucas_unix_recv · read ring half into client buffer; park if empty + open. */
int64_t lucas_unix_recv(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr, uint64_t count) {
    int ci = st->fds[fd].unix_chan_idx1 - 1;
    uint8_t server_end = st->fds[fd].unix_server_end;
    int64_t r = do_unix_recv(st, ci, server_end, (uintptr_t)buf_vaddr, count);
    if (r != LUCAS_UNIX_EAGAIN) return r;
    /* WINE-M1 · O_NONBLOCK (0x800): wineserver's main loop is epoll-driven and
     * sets its conn fd non-blocking — it MUST get -EAGAIN (not a park) on an
     * empty ring, else it blocks on the master socket forever and never reads
     * the per-thread request pipe wine wrote (deadlock).  Blocking fds (wine's
     * launcher recvmsg) still park.  (Socket fds stash family/type in the low
     * 16 bits of flags, but F_SETFL overwrites flags wholesale, so once a guest
     * sets O_NONBLOCK the 0x800 bit is authoritative here.) */
    if (st->fds[fd].flags & 0x800)
        return -(int64_t)11;   /* -EAGAIN */
    /* Empty + peer open · park (SaveCaller) until the peer writes/closes. */
    seL4_CPtr cslot;
    if (vka_cspace_alloc(st->vka, &cslot) != 0) return -(int64_t)11;
    cspacepath_t cp; vka_cspace_make_path(st->vka, cslot, &cp);
    if (seL4_CNode_SaveCaller(cp.root, cp.capPtr, cp.capDepth) != 0) {
        vka_cspace_free(st->vka, cslot); return -(int64_t)11;
    }
    st->waiting_reply_cap        = cslot;
    st->waiting_unix_chan1       = ci + 1;
    st->waiting_unix_server_end  = server_end;
    st->waiting_unix_buf_vaddr   = (uintptr_t)buf_vaddr;
    st->waiting_unix_count       = (size_t)count;
    st->waiting_unix_msg_vaddr   = 0;   /* read() default · recvmsg overrides for SCM */
    st->waiting_unix_msgctl      = 0;
    st->waiting_unix_msgctllen   = 0;
    st->state                    = SOTBOX_STATE_WAITING_FOR_UNIX;
    printf("[unix] PARK recv pid=%d chan[%d] server_end=%u count=%lu\n",
           st->synthetic_pid, ci, server_end, (unsigned long)count);
    return LUCAS_WAIT4_DEFERRED;
}

/* do_unix_accept · dequeue one pending connection from an AF_UNIX listener,
 * mint the server-side endpoint fd.  Returns new fd, -EAGAIN (empty), -errno. */
static int64_t do_unix_accept(lucas_state_t *st, int listen_fd,
                              uintptr_t addr_vaddr, uintptr_t addrlen_vaddr) {
    int li = st->fds[listen_fd].unix_listener_idx1 - 1;
    if (li < 0 || li >= LUCAS_UNIX_MAX_LISTENERS || !g_unix_listeners[li].in_use)
        return -(int64_t)LX_EBADF;
    unix_listener_t *L = &g_unix_listeners[li];
    if (L->bl_count == 0) return -(int64_t)11;  /* EAGAIN · nothing pending */
    int ci = L->backlog[L->bl_head];
    L->bl_head = (L->bl_head + 1) % LUCAS_UNIX_BACKLOG;
    L->bl_count--;
    int nf = alloc_sotnet_fd(st, LUCAS_AF_UNIX, LUCAS_SOCK_STREAM, 0);
    if (nf < 0) return (int64_t)nf;
    st->fds[nf].unix_chan_idx1  = ci + 1;
    st->fds[nf].unix_server_end = 1;
    if (ci >= 0 && ci < LUCAS_UNIX_MAX_CHANNELS) g_unix_channels[ci].server_slot = st->slot_index;
    if (addr_vaddr && addrlen_vaddr) {
        uint16_t fam = LUCAS_AF_UNIX; uint32_t alen = sizeof(fam);  /* unnamed peer */
        (void)lucas_copy_to_client(st, addr_vaddr, &fam, sizeof(fam));
        (void)lucas_copy_to_client(st, addrlen_vaddr, &alen, sizeof(alen));
    }
    printf("[unix] pid=%d accept · listener[%d] '%s' → chan[%d] newfd=%d\n",
           st->synthetic_pid, li, L->path, ci, nf);
    return (int64_t)nf;
}

/* Wake the listener owner if it is parked in accept (called from connect). */
void lucas_unix_accept_wake(int listener_idx) {
    extern lucas_state_t *sotbox_get_slot(int idx);
    if (listener_idx < 0 || listener_idx >= LUCAS_UNIX_MAX_LISTENERS) return;
    int owner = g_unix_listeners[listener_idx].owner_slot;
    lucas_state_t *w = sotbox_get_slot(owner);
    if (!w || w->state != SOTBOX_STATE_WAITING_FOR_ACCEPT) return;
    int lfd = w->waiting_accept_fd;
    if (lfd < 0 || lfd >= LUCAS_MAX_FDS) return;
    if (w->fds[lfd].unix_listener_idx1 - 1 != listener_idx) return;
    int64_t nf = do_unix_accept(w, lfd, w->waiting_accept_addr_vaddr,
                                w->waiting_accept_addrlen_vaddr);
    if (nf == -(int64_t)11) return;  /* race · still empty */
    seL4_UserContext regs;
    if (seL4_TCB_ReadRegisters(w->client_tcb, false, 0, 18, &regs) == 0) {
        regs.rax = (uint64_t)nf; regs.rip += 2; regs.rcx = regs.rip; regs.r11 = regs.rflags;
        seL4_TCB_WriteRegisters(w->client_tcb, false, 0, 18, &regs);
    }
    seL4_Send(w->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
    vka_cspace_free(w->vka, w->waiting_reply_cap);
    w->waiting_reply_cap = 0;
    w->state             = SOTBOX_STATE_RUNNING;
    printf("[unix] WAKE acceptor pid=%d → newfd=%ld\n", w->synthetic_pid, (long)nf);
}

/* Tear down an AF_UNIX socket fd at close()/exit · marks the channel end
 * closed and wakes the peer reader (EOF), frees a listener slot. */
void lucas_unix_close_fd(lucas_state_t *st, int fd) {
    if (fd < 0 || fd >= LUCAS_MAX_FDS) return;
    lucas_fd_t *e = &st->fds[fd];
    if (e->unix_listener_idx1) {
        int li = e->unix_listener_idx1 - 1;
        if (li >= 0 && li < LUCAS_UNIX_MAX_LISTENERS) g_unix_listeners[li].in_use = 0;
        e->unix_listener_idx1 = 0;
    }
    if (e->unix_chan_idx1) {
        int ci = e->unix_chan_idx1 - 1;
        if (ci >= 0 && ci < LUCAS_UNIX_MAX_CHANNELS && g_unix_channels[ci].in_use) {
            unix_channel_t *ch = &g_unix_channels[ci];
            /* WINE-M1 · refcounted (socketpair) ends: decrement and only mark
             * the end closed when the last holder drops it.  Legacy rendezvous
             * channels (refs==0) keep the old semantics: the first close marks
             * the end closed (the guard below collapses to that case). */
            int *refs = e->unix_server_end ? &ch->server_refs : &ch->client_refs;
            if (*refs > 0) (*refs)--;
            if (*refs <= 0) {
                if (e->unix_server_end) ch->server_closed = 1; else ch->client_closed = 1;
                lucas_unix_wake_reader(ci, (uint8_t)(e->unix_server_end ? 0 : 1));
                iomux_check_epoll_waiters(NULL);   /* peer's fd is now readable (EOF/HUP) */
                if (ch->client_closed && ch->server_closed) {
                    /* Release any still-held (undelivered) SCM fds so their pipe /
                     * channel-end refcounts don't leak when the channel is torn
                     * down before the receiver claimed them. */
                    extern void lucas_pipe_close_reader(struct lucas_pipe *);
                    extern void lucas_pipe_close_writer(struct lucas_pipe *);
                    for (int E2 = 0; E2 < 2; ++E2)
                        for (int k = 0; k < ch->scm_n[E2]; ++k) {
                            lucas_fd_t *h = &ch->scm[E2][k].held_fd;
                            if (h->kind == LUCAS_FD_PIPE_READ && h->pipe)
                                lucas_pipe_close_reader(h->pipe);
                            else if (h->kind == LUCAS_FD_PIPE_WRITE && h->pipe)
                                lucas_pipe_close_writer(h->pipe);
                            else if (h->kind == LUCAS_FD_SOCKET && h->unix_chan_idx1) {
                                int hc = h->unix_chan_idx1 - 1;
                                if (hc >= 0 && hc < LUCAS_UNIX_MAX_CHANNELS) {
                                    if (h->unix_server_end) { if (g_unix_channels[hc].server_refs > 0) g_unix_channels[hc].server_refs--; }
                                    else                    { if (g_unix_channels[hc].client_refs > 0) g_unix_channels[hc].client_refs--; }
                                }
                            } else if (h->kind == LUCAS_FD_VFS && h->handle && h->mount && h->mount->ops->close) {
                                h->mount->ops->close(h->mount->backend_state, h->handle);  /* free the dup'd handle */
                            }
                        }
                    ch->scm_n[0] = ch->scm_n[1] = 0;
                    ch->in_use = 0;
                }
            }
        }
        e->unix_chan_idx1  = 0;
        e->unix_server_end = 0;
    }
}

/* WINE-M1 · fork()/vfork() inherited a socket fd into `child`: if it is a
 * refcounted socketpair channel end, bump that end's count so the channel
 * survives the parent later closing its copy.  Called from sotbox_fork /
 * sotbox_vfork after the shallow fd-table copy (mirrors the pipe add_reader/
 * add_writer bumps).  No-op for legacy rendezvous channels (refs==0) and for
 * non-channel sockets. */
void lucas_unix_inherit_fd(lucas_state_t *child, int fd) {
    if (!child || fd < 0 || fd >= LUCAS_MAX_FDS) return;
    lucas_fd_t *e = &child->fds[fd];
    if (e->kind != LUCAS_FD_SOCKET || !e->unix_chan_idx1) return;
    int ci = e->unix_chan_idx1 - 1;
    if (ci < 0 || ci >= LUCAS_UNIX_MAX_CHANNELS || !g_unix_channels[ci].in_use) return;
    /* Bump the inherited end's refcount AND retarget its owner slot to the child.
     * wine's CreateProcess creates the socketpair in the parent, fork()s, then the
     * parent closes its copy — handing the end to the child.  The owner slot is
     * informational here (delivery installs into whoever recvmsg's, since SCM fds
     * are held by the channel, not routed by slot), but keeping it pointed at the
     * live holder is correct.  Only refcounted (socketpair) channels are touched;
     * legacy rendezvous channels (refs==0) are left alone. */
    if (e->unix_server_end) {
        if (g_unix_channels[ci].server_refs > 0) {
            g_unix_channels[ci].server_refs++;
            g_unix_channels[ci].server_slot = child->slot_index;
        }
    } else {
        if (g_unix_channels[ci].client_refs > 0) {
            g_unix_channels[ci].client_refs++;
            g_unix_channels[ci].client_slot = child->slot_index;
        }
    }
}

/* iomux predicates (poll/ppoll/select/epoll readiness · called from iomux.c). */
/* sotNet-δ · POLLIN readiness for an INET socket (DNS/HTTP egress).  poll()/
 * select() must report it readable BEFORE the guest's recvfrom/read, or a
 * poll-first client stalls: musl's getaddrinfo poll()s the DNS socket before
 * recvfrom (a not-ready report → timeout → retry → 'bad address'); an HTTP
 * client (busybox wget) poll()s the TCP socket before reading the body.
 *   (a) a queued synth/forwarded datagram for this pid (the DNS answer), or
 *   (b) a connected egress TCP socket with rx bytes OR closed (EOF). */
int lucas_inet_poll_readable(const lucas_state_t *st, int fd) {
    extern int sotnet_recv_pending(uint32_t pid);
    if (fd < 0 || fd >= LUCAS_MAX_FDS) return 0;
    /* SOCKET DEMUX · poll(POLLIN) on an lwIP-egress fd PUMPS the stack (flushes a
     * queued request, receives the response) and reports readable once the ring has
     * data or the peer closed.  This is the blocking/pumping point for a non-blocking
     * client (apt's http method): its recv() is non-blocking (EAGAIN until data), so
     * poll() is where the wait + RX drive happens. */
    if (st->fds[fd].lwip_sess != NULL) {
        extern int orch_lwip_egress_poll_in(void *handle);
        return orch_lwip_egress_poll_in(st->fds[fd].lwip_sess);
    }
    const struct tcp_conn *c = st->fds[fd].tcp_conn;
    if (c) {
        /* Connected TCP socket (the TLS client's fd): readability is ITS OWN rx
         * buffer / close state — NOT the pid-global queued-datagram flag.  THE
         * BUG: musl getaddrinfo leaves a duplicate/AAAA DNS answer undrained in
         * g_recv_queue, so `sotnet_recv_pending(pid)` stays true forever; reporting
         * the TCP fd readable on that basis made openssl s_client's relay loop
         * (`if (FD_ISSET(ssl_fd)) SSL_read; else if (FD_ISSET(stdin)) read`) read
         * the socket every iteration and NEVER read stdin → it never sent wget's
         * HTTP request → the server closed with no body.  Gate it to the conn. */
        return (c->rx_len > 0 || c->state != TCP_STATE_ESTABLISHED) ? 1 : 0;
    }
    /* Unconnected / DGRAM socket (musl's UDP:53 resolver): a queued forwarded/
     * synth datagram (the DNS answer) makes it readable. */
    if (sotnet_recv_pending((uint32_t)st->synthetic_pid)) return 1;
    return 0;
}
int lucas_unix_is_rendezvous(const lucas_state_t *st, int fd) {
    if (fd < 0 || fd >= LUCAS_MAX_FDS) return 0;
    return st->fds[fd].unix_listener_idx1 != 0 || st->fds[fd].unix_chan_idx1 != 0;
}
int lucas_unix_poll_readable(const lucas_state_t *st, int fd) {
    const lucas_fd_t *e = &st->fds[fd];
    if (e->unix_listener_idx1) {
        int li = e->unix_listener_idx1 - 1;
        return (li >= 0 && li < LUCAS_UNIX_MAX_LISTENERS && g_unix_listeners[li].in_use
                && g_unix_listeners[li].bl_count > 0) ? 1 : 0;
    }
    if (e->unix_chan_idx1) {
        int ci = e->unix_chan_idx1 - 1;
        if (ci < 0 || ci >= LUCAS_UNIX_MAX_CHANNELS || !g_unix_channels[ci].in_use)
            return 1;  /* gone → readable (delivers EOF) */
        const unix_channel_t *ch = &g_unix_channels[ci];
        uint32_t avail = e->unix_server_end ? uring_used(ch->c2s_h, ch->c2s_t)
                                            : uring_used(ch->s2c_h, ch->s2c_t);
        uint8_t peer_done = e->unix_server_end ? (ch->client_closed || ch->client_wr_shut)
                                               : (ch->server_closed || ch->server_wr_shut);
        return (avail > 0 || peer_done) ? 1 : 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* socket() · allocate a LUCAS fd slot for the requested socket type.  */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_socket(lucas_state_t *st,
                          uint64_t family, uint64_t type, uint64_t protocol,
                          uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_3; (void)_4; (void)_5;
    /* apt/glibc · DISABLE AF_NETLINK (family 16).  glibc getaddrinfo's
     * AI_ADDRCONFIG probe + getifaddrs enumerate interfaces over a route-netlink
     * socket; emulating the netlink PROTOCOL proved fragile (3 fixes, each
     * exposing a new edge: size-0 abort, nlmsg_pid-skip, RTM_GETLINK, then an
     * infinite NLMSG_DONE read loop that hung apt).  glibc handles a MISSING
     * netlink GRACEFULLY — __check_pf falls back to "assume IPv4+IPv6 configured"
     * and resolves normally.  So fail the socket instead of emulating it (the
     * is_netlink stub in handlers below is now dead, kept for reference). */
    if ((int)family == LUCAS_AF_NETLINK) {
        printf("[sotnet-α] pid=%d socket(AF_NETLINK) → -EAFNOSUPPORT (glibc falls back · no emulation)\n",
               st->synthetic_pid);
        return -(int64_t)97;   /* -EAFNOSUPPORT */
    }
    /* In Tier-1 the sotbox is allowed to *create* sockets · the deception
     * happens at connect() time (auto-promote Tier→2 + synth synth
     * fast-path).  Denying socket() outright surfaces -EACCES inside the
     * malware before any interesting interception can fire, which makes
     * the operator-visible narrative less useful (no `[synth] connect
     * FAST-PATH`, no `[dns] HIT`).  Let the cap through · gates are at
     * connect()/sendto() where the destination is observable. */
    int fd = alloc_sotnet_fd(st, (int)family, (int)type, (int)protocol);
    printf("[sotnet-α] pid=%d socket(family=%lu, type=%lu, protocol=%lu) → fd=%d\n",
           st->synthetic_pid,
           (unsigned long)family, (unsigned long)type,
           (unsigned long)protocol, fd);
    return (int64_t)fd;
}

/* ------------------------------------------------------------------ */
/* bind() · no-op success; addr is parsed-but-ignored in Phase α.      */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_bind(lucas_state_t *st,
                        uint64_t fd, uint64_t addr_vaddr, uint64_t addrlen,
                        uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_3; (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    /* WINE-M1 · AF_UNIX · record the bound path so listen()/the rendezvous can
     * key the listener on it (the old stub dropped it → listen mis-routed to
     * TCP).  sockaddr_un = { uint16 family; char sun_path[108]; }. */
    if (lucas_socket_family(st, fd) == LUCAS_AF_UNIX && addr_vaddr && addrlen >= 3) {
        struct { uint16_t family; char path[LUCAS_UNIX_PATH_MAX]; } __attribute__((packed)) usa;
        memset(&usa, 0, sizeof(usa));
        size_t cl = addrlen < sizeof(usa) ? (size_t)addrlen : sizeof(usa);
        if (lucas_copy_from_client(st, (uintptr_t)addr_vaddr, &usa, cl) != 0)
            return -(int64_t)LX_EFAULT;
        usa.path[LUCAS_UNIX_PATH_MAX - 1] = '\0';
        memset(st->fds[fd].unix_path, 0, sizeof(st->fds[fd].unix_path));
        strncpy(st->fds[fd].unix_path, usa.path, sizeof(st->fds[fd].unix_path) - 1);
        /* WINE-M1 · materialize the socket as a filesystem node so the wine
         * launcher's lstat("socket") poll-loop sees it and proceeds to
         * connect() (the connection itself rides the AF_UNIX rendezvous).
         * ONLY for a PATHNAME socket (sun_path[0] != '\0').  An empty sun_path is
         * an autobind/unnamed socket and a leading-NUL one is the abstract
         * namespace — NEITHER has a filesystem node.  apt/libsystemd autobind an
         * AF_UNIX socket (path='') whose empty path resolved to "/", so we were
         * materializing an S_IFSOCK node AT THE ROOT — which then made the forked
         * dpkg child's chdir("/") fail ENOTDIR → _exit(100) → "Sub-process dpkg
         * returned an error code (100)" with no unpack.  Skip the FS node; bind
         * still succeeds (returns 0). */
        if (usa.path[0] != '\0') {
            extern int lucas_vfs_create_node(lucas_state_t *st, const char *path);
            (void)lucas_vfs_create_node(st, usa.path);
        }
        printf("[unix] pid=%d bind(fd=%lu) path='%s'\n",
               st->synthetic_pid, (unsigned long)fd, st->fds[fd].unix_path);
        return 0;
    }

    printf("[sotnet-α] pid=%d bind(fd=%lu, addrlen=%lu) → 0 (stub)\n",
           st->synthetic_pid, (unsigned long)fd, (unsigned long)addrlen);
    return 0;
}

/* ------------------------------------------------------------------ */
/* listen() · sotNet-δ-1 · drive tcp_passive_open to create LISTEN slot. */
/* For δ-1: bind() is a stub, so we use a default local port (80).      */
/* δ-2 will wire bind to stash a real port into the fd struct.          */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_listen(lucas_state_t *st,
                          uint64_t fd, uint64_t backlog,
                          uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_2; (void)_3; (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    /* WINE-M1 · AF_UNIX · register a path-keyed listener instead of routing to
     * the TCP passive-open (which derived a bogus port 80 → EADDRINUSE and is
     * what blocked wineserver).  bind() must have stashed the path. */
    if (lucas_socket_family(st, fd) == LUCAS_AF_UNIX) {
        if (st->fds[fd].unix_path[0] == '\0') {
            printf("[unix] pid=%d listen(fd=%lu) · not bound · -EINVAL\n",
                   st->synthetic_pid, (unsigned long)fd);
            return -(int64_t)22;  /* EINVAL */
        }
        if (unix_listener_find(st->fds[fd].unix_path) >= 0) {
            printf("[unix] pid=%d listen path='%s' · already in use · -EADDRINUSE\n",
                   st->synthetic_pid, st->fds[fd].unix_path);
            return -(int64_t)98;  /* EADDRINUSE */
        }
        for (int i = 0; i < LUCAS_UNIX_MAX_LISTENERS; ++i) {
            if (!g_unix_listeners[i].in_use) {
                memset(&g_unix_listeners[i], 0, sizeof(g_unix_listeners[i]));
                g_unix_listeners[i].in_use     = 1;
                g_unix_listeners[i].owner_slot = st->slot_index;
                strncpy(g_unix_listeners[i].path, st->fds[fd].unix_path,
                        LUCAS_UNIX_PATH_MAX - 1);
                st->fds[fd].unix_listener_idx1 = i + 1;
                printf("[unix] pid=%d listen · listener[%d] path='%s' backlog=%lu\n",
                       st->synthetic_pid, i, g_unix_listeners[i].path,
                       (unsigned long)backlog);
                return 0;
            }
        }
        printf("[unix] pid=%d listen · listener table full · -EADDRINUSE\n",
               st->synthetic_pid);
        return -(int64_t)98;
    }

    uint16_t local_port_be = lucas_default_local_port_be();
    struct tcp_conn *lc = tcp_passive_open(local_port_be);
    if (!lc) {
        printf("[listen] pid=%d port=80 backlog=%lu · tcp_passive_open FAILED\n",
               st->synthetic_pid, (unsigned long)backlog);
        return -(int64_t)98;   /* EADDRINUSE · all TCP conn slots taken or port already LISTEN */
    }
    printf("[listen] pid=%d port=%u backlog=%d\n",
           st->synthetic_pid, 80, (int)backlog);
    return 0;
}

/* ------------------------------------------------------------------ */
/* accept() · sotNet-δ-1 · dequeue an ESTABLISHED conn from the LISTEN  */
/* slot.  Returns -EAGAIN if no completed handshakes are pending.       */
/* On success, allocates a fresh LUCAS_FD_SOCKET fd for the new conn    */
/* and fills *addr_out / *addrlen_out (when non-NULL) with the peer.    */
/* ------------------------------------------------------------------ */
/* do_accept · the accept "success tail" shared by the in-syscall fast path
 * (lucas_sys_accept) and the wake-up path (lucas_accept_wake_waiter).
 *
 *   dequeue (tcp_accept_dequeue) -> alloc_sotnet_fd -> bind st->fds[].tcp_conn
 *   -> fill peer sockaddr_in -> trace_emit_accept -> return new_fd.
 *
 * Returns:
 *   >= 0          · new fd for the accepted conn (success)
 *   -(int64_t)11  · EAGAIN anomaly · accept queue empty (no conn dequeued)
 *   < 0 (other)   · negative errno (fd-alloc / copy fault)
 *
 * Callers distinguish "no conn" from "got a conn" by the EAGAIN anomaly:
 * the fast path parks on it, the wake path stays parked on it (race). */
static int64_t do_accept(lucas_state_t *st, int listen_fd,
                         uintptr_t addr_vaddr, uintptr_t addrlen_vaddr)
{
    uint16_t local_port_be = lucas_default_local_port_be();
    struct tcp_conn *conn = tcp_accept_dequeue(local_port_be);
    if (!conn) {
        return -(int64_t)11;  /* EAGAIN · accept queue empty */
    }

    /* Allocate a new fd for the accepted connection.  Inherit family/type
     * from the listening socket's dedicated typefam stash (high/low 16 bits). */
    int family = (int)((st->fds[listen_fd].sock_typefam >> 16) & 0xFFFF);
    int type   = (int)( st->fds[listen_fd].sock_typefam        & 0xFFFF);
    int new_fd = alloc_sotnet_fd(st, family, type, 0);
    if (new_fd < 0) {
        return (int64_t)new_fd;
    }

    /* Fill peer sockaddr_in when caller asked for it. */
    if (addr_vaddr && addrlen_vaddr) {
        struct {
            uint16_t family;
            uint16_t port_be;
            uint32_t addr_be;
            uint8_t  pad[8];
        } __attribute__((packed)) sa;
        memset(&sa, 0, sizeof(sa));
        sa.family  = 2;  /* AF_INET */
        sa.port_be = conn->remote_port_be;
        sa.addr_be = conn->remote_ip_be;

        uint32_t user_alen = sizeof(sa);
        (void)lucas_copy_from_client(st, (uintptr_t)addrlen_vaddr,
                                     &user_alen, sizeof(user_alen));
        uint32_t write_len = user_alen < sizeof(sa) ? user_alen : sizeof(sa);
        if (write_len && lucas_copy_to_client(st, (uintptr_t)addr_vaddr,
                                              &sa, write_len) != 0) {
            /* Roll the fd back so we don't leak it. */
            st->fds[new_fd].kind = LUCAS_FD_INVALID;
            sotnet_tcp_close(conn);   /* v1.1 · don't orphan the dequeued conn on EFAULT */
            return -(int64_t)LX_EFAULT;
        }
        uint32_t actual = sizeof(sa);
        (void)lucas_copy_to_client(st, (uintptr_t)addrlen_vaddr,
                                   &actual, sizeof(actual));
    }

    /* N1/v1 · bind the accepted conn to the new fd so lucas_tcp_send/recv work.
     * Without this, read/write on an accepted fd hits the tcp_conn==NULL guard
     * and returns EBADF (the v0 inbound dead-path). Mirrors connect at :460. */
    st->fds[new_fd].tcp_conn = conn;
    /* δ-2 · a guest now owns this conn → its read() drains rx_buf, so the data
     * path MUST keep accumulating inbound payload (vs the synth-bridged default
     * that drains it to keep the receive window open).  See tcp_data_on_segment. */
    conn->app_owned = 1;

    trace_emit_accept(st->slot_index, (uint32_t)st->synthetic_pid, conn->conn_id,
                      conn->remote_ip_be, conn->remote_port_be, lucas_default_local_port_be());

    uint32_t rip = conn->remote_ip_be;
    uint16_t rport_host = (uint16_t)(((conn->remote_port_be & 0xFF) << 8) |
                                     ((conn->remote_port_be >> 8) & 0xFF));
    printf("[accept] pid=%d new conn from %u.%u.%u.%u:%u fd=%d\n",
           st->synthetic_pid,
           (unsigned)( rip        & 0xFF),
           (unsigned)((rip >>  8) & 0xFF),
           (unsigned)((rip >> 16) & 0xFF),
           (unsigned)((rip >> 24) & 0xFF),
           (unsigned)rport_host, new_fd);
    return (int64_t)new_fd;
}

int64_t lucas_sys_accept(lucas_state_t *st,
                          uint64_t fd, uint64_t addr_vaddr,
                          uint64_t addrlen_vaddr,
                          uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_3; (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    /* WINE-M1 · AF_UNIX listener · dequeue from the rendezvous backlog; park
     * (WAITING_FOR_ACCEPT) if empty · connect() wakes via lucas_unix_accept_wake. */
    if (st->fds[fd].unix_listener_idx1) {
        int64_t ur = do_unix_accept(st, (int)fd,
                                    (uintptr_t)addr_vaddr, (uintptr_t)addrlen_vaddr);
        if (ur != -(int64_t)11) return ur;   /* got a conn or hard error */
        seL4_CPtr ucslot;
        if (vka_cspace_alloc(st->vka, &ucslot) != 0) return -(int64_t)11;
        cspacepath_t ucp; vka_cspace_make_path(st->vka, ucslot, &ucp);
        if (seL4_CNode_SaveCaller(ucp.root, ucp.capPtr, ucp.capDepth) != 0) {
            vka_cspace_free(st->vka, ucslot); return -(int64_t)11;
        }
        st->waiting_reply_cap            = ucslot;
        st->waiting_accept_fd            = (int)fd;
        st->waiting_accept_addr_vaddr    = (uintptr_t)addr_vaddr;
        st->waiting_accept_addrlen_vaddr = (uintptr_t)addrlen_vaddr;
        st->state                        = SOTBOX_STATE_WAITING_FOR_ACCEPT;
        printf("[unix] PARK accept pid=%d fd=%lu\n",
               st->synthetic_pid, (unsigned long)fd);
        return LUCAS_WAIT4_DEFERRED;
    }

    int64_t r = do_accept(st, (int)fd,
                          (uintptr_t)addr_vaddr, (uintptr_t)addrlen_vaddr);
    if (r != -(int64_t)11) {
        /* Got a conn (>=0) or a hard errno · return it directly. */
        return r;
    }

    /* Accept queue empty · park the sotbox (mirror the recvfrom BG2 park).
     * SaveCaller stashes the reply cap · lucas_accept_wake_waiter Sends to it
     * once a handshake reaches ESTABLISHED. */
    seL4_CPtr cslot;
    if (vka_cspace_alloc(st->vka, &cslot) != 0) {
        printf("[sotnet] pid=%d accept park · vka_cspace_alloc FAILED · -EAGAIN\n",
               st->synthetic_pid);
        return -(int64_t)11;  /* EAGAIN · best-effort fall back */
    }
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, cslot, &cpath);
    int err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
    if (err) {
        vka_cspace_free(st->vka, cslot);
        printf("[sotnet] pid=%d accept park · SaveCaller FAILED (err=%d) · -EAGAIN\n",
               st->synthetic_pid, err);
        return -(int64_t)11;
    }

    st->waiting_reply_cap            = cslot;
    st->waiting_accept_fd            = (int)fd;
    st->waiting_accept_addr_vaddr    = (uintptr_t)addr_vaddr;
    st->waiting_accept_addrlen_vaddr = (uintptr_t)addrlen_vaddr;
    st->state                        = SOTBOX_STATE_WAITING_FOR_ACCEPT;
    printf("[sotnet] PARK accept pid=%d fd=%lu\n",
           st->synthetic_pid, (unsigned long)fd);
    return LUCAS_WAIT4_DEFERRED;
}

/* ------------------------------------------------------------------ */
/* accept4() · thin wrapper around accept.  flags (SOCK_NONBLOCK /     */
/* SOCK_CLOEXEC) are ignored in δ-1 · they affect the new fd state     */
/* and will be wired when alloc_sotnet_fd grows a flags arg.           */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_accept4(lucas_state_t *st,
                           uint64_t fd, uint64_t addr_vaddr,
                           uint64_t addrlen_vaddr,
                           uint64_t flags, uint64_t _4, uint64_t _5)
{
    (void)flags; (void)_4; (void)_5;
    return lucas_sys_accept(st, fd, addr_vaddr, addrlen_vaddr, 0, 0, 0);
}

/* ------------------------------------------------------------------ */
/* connect() · sotNet-δ-1 · drive TCP active open synchronously.       */
/* Calls tcp_active_open() then spins sotnet_poll + tcp_timer_tick     */
/* until the conn reaches ESTABLISHED, CLOSED (RST), or 100-tick TO.   */
/* The fd↔conn linkage is δ-2 work · here we only return success/fail. */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_connect(lucas_state_t *st,
                           uint64_t fd, uint64_t addr_vaddr, uint64_t addrlen,
                           uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_3; (void)_4; (void)_5;
    /* In Tier-1 the connect() does NOT outright deny · instead, the
     * destination-aware N-CONNECT-AUTO-T2 block below auto-promotes the
     * sotbox to Tier-2 on any non-local destination, which then triggers
     * the synth synth fast-path further down.  This preserves the
     * STAR deception narrative (the sotbox sees a successful connect to
     * its C2, but the traffic was synthesized by the synth server).
     * Local destinations (loopback, QEMU NAT 10.0.2.0/24) fall through
     * unchanged so DNS UDP queries to the local resolver still work. */
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    uint16_t family = 0;
    if (addrlen < sizeof(family)) {
        return -(int64_t)22;  /* EINVAL */
    }
    if (lucas_copy_from_client(st, (uintptr_t)addr_vaddr, &family, sizeof(family)) != 0)
        return -(int64_t)LX_EFAULT;

    if (family == LUCAS_AF_UNIX) {
        struct {
            uint16_t family;
            char     path[LUCAS_UNIX_PATH_MAX];
        } __attribute__((packed)) usa;

        memset(&usa, 0, sizeof(usa));
        size_t copy_len = addrlen < sizeof(usa) ? (size_t)addrlen : sizeof(usa);
        if (lucas_copy_from_client(st, (uintptr_t)addr_vaddr, &usa, copy_len) != 0)
            return -(int64_t)LX_EFAULT;
        usa.path[LUCAS_UNIX_PATH_MAX - 1] = '\0';

        int sock_family = lucas_socket_family(st, fd);
        int sock_type   = lucas_socket_type(st, fd);
        if (sock_family != LUCAS_AF_UNIX
            || ((sock_type & LUCAS_SOCK_TYPEMASK) != LUCAS_SOCK_STREAM)) {
            printf("[wayland] pid=%d connect fd=%lu path=%s wrong socket family/type=%d/%d -> -ECONNREFUSED\n",
                   st->synthetic_pid, (unsigned long)fd, usa.path,
                   sock_family, sock_type);
            return -(int64_t)111;  /* ECONNREFUSED */
        }

        /* The Wayland compositor keeps its dedicated route; EVERY other
         * AF_UNIX path goes through the WINE-M1 cross-sotbox rendezvous
         * (wineserver's socket).  connect matches a path-keyed listener,
         * allocates a channel (client end on this fd), queues it on the
         * listener backlog, and wakes a server parked in accept. */
        if (strcmp(usa.path, WAYLAND_SOCKET_PATH) != 0 || !orch_wayland_ready()) {
            int li = unix_listener_find(usa.path);
            if (li < 0) {
                printf("[unix] pid=%d connect path='%s' · no listener · -ECONNREFUSED\n",
                       st->synthetic_pid, usa.path);
                return -(int64_t)111;  /* ECONNREFUSED */
            }
            unix_listener_t *L = &g_unix_listeners[li];
            if (L->bl_count >= LUCAS_UNIX_BACKLOG) {
                printf("[unix] pid=%d connect path='%s' · backlog full · -ECONNREFUSED\n",
                       st->synthetic_pid, usa.path);
                return -(int64_t)111;
            }
            int ci = -1;
            for (int i = 0; i < LUCAS_UNIX_MAX_CHANNELS; ++i) {
                if (!g_unix_channels[i].in_use) {
                    memset(&g_unix_channels[i], 0, sizeof(g_unix_channels[i]));
                    g_unix_channels[i].in_use      = 1;
                    g_unix_channels[i].client_slot = st->slot_index;
                    g_unix_channels[i].server_slot = -1;
                    ci = i; break;
                }
            }
            if (ci < 0) {
                printf("[unix] pid=%d connect · channel table full · -ECONNREFUSED\n",
                       st->synthetic_pid);
                return -(int64_t)111;
            }
            L->backlog[(L->bl_head + L->bl_count) % LUCAS_UNIX_BACKLOG] = ci;
            L->bl_count++;
            st->fds[fd].unix_chan_idx1  = ci + 1;
            st->fds[fd].unix_server_end = 0;
            memset(st->fds[fd].unix_path, 0, sizeof(st->fds[fd].unix_path));
            strncpy(st->fds[fd].unix_path, usa.path, sizeof(st->fds[fd].unix_path) - 1);
            printf("[unix] pid=%d connect path='%s' → listener[%d] chan[%d] (queued)\n",
                   st->synthetic_pid, usa.path, li, ci);
            lucas_unix_accept_wake(li);       /* wake a server parked in accept */
            iomux_check_epoll_waiters(NULL);  /* …or parked in epoll_wait on the listen fd */
            return 0;   /* SOCK_STREAM connect completes once queued (Linux) */
        }

        st->fds[fd].wayland_connected = 1;
        st->fds[fd].wayland_route_ep  = (st->tier >= 2 && orch_wayland_canary_ep() != 0)
            ? orch_wayland_canary_ep()      /* hostile → isolated shadow compositor */
            : orch_wayland_listen_ep();     /* normal → honest compositor */
        memset(st->fds[fd].unix_path, 0, sizeof(st->fds[fd].unix_path));
        for (size_t i = 0; i < sizeof(st->fds[fd].unix_path) - 1 && usa.path[i]; ++i) {
            st->fds[fd].unix_path[i] = usa.path[i];
        }
        printf("[wayland] pid=%u connect tier=%d route=%s\n",
               st->synthetic_pid, st->tier, (st->tier >= 2 && orch_wayland_canary_ep() != 0) ? "CANARY" : "compositor");
        printf("[wayland] pid=%d connect fd=%lu path=%s route_ep=%lu -> OK\n",
               st->synthetic_pid, (unsigned long)fd, st->fds[fd].unix_path,
               (unsigned long)st->fds[fd].wayland_route_ep);
        return 0;
    }

    /* Parse sockaddr_in from client. */
    struct {
        uint16_t family;
        uint16_t port_be;
        uint32_t addr_be;
    } __attribute__((packed)) sa;

    if (lucas_copy_from_client(st, (uintptr_t)addr_vaddr, &sa, sizeof(sa)) != 0)
        return -(int64_t)LX_EFAULT;

    if (sa.family != LUCAS_AF_INET) {
        /* AF_INET6 DGRAM connect · musl's getaddrinfo AI_ADDRCONFIG probe connects
         * a UDP socket to [::1]:65535 to test whether the IPv6 stack is configured
         * (real Linux loopback connect returns 0).  Returning ECONNREFUSED here made
         * the openssl TLS client conclude the resolver path was broken and abort
         * BEFORE the real DNS query — no A-record lookup, no TCP connect.  A UDP
         * connect sends no packets, so report success (peer is irrelevant · we don't
         * decode the v6 sockaddr).  AAAA is force-empty (dns_synth_empty_noerror), so
         * the client still resolves only A records and connects over IPv4.  A v6
         * STREAM connect would be real v6 egress (unsupported) → keep ECONNREFUSED. */
        if (sa.family == LUCAS_AF_INET6) {
            int st_type6 = lucas_socket_type(st, fd);
            if (st_type6 >= 0 && (st_type6 & LUCAS_SOCK_TYPEMASK) != LUCAS_SOCK_STREAM) {
                printf("[connect] pid=%d → [::1]-style v6 UDP connect · addrconfig probe (peer set, no SYN)\n",
                       st->synthetic_pid);
                return 0;
            }
        }
        printf("[connect] pid=%d non-INET family=%u · -ECONNREFUSED\n",
               st->synthetic_pid, (unsigned int)sa.family);
        return -(int64_t)111;  /* ECONNREFUSED */
    }

    /* Pretty-print dotted quad + host-order port for logs. */
    uint8_t  a = (uint8_t)(sa.addr_be      );
    uint8_t  b = (uint8_t)(sa.addr_be >>  8);
    uint8_t  c = (uint8_t)(sa.addr_be >> 16);
    uint8_t  d = (uint8_t)(sa.addr_be >> 24);
    uint16_t port_host = (uint16_t)(((sa.port_be & 0xFF) << 8) |
                                    ((sa.port_be >> 8) & 0xFF));

    /* N-CONNECT-AUTO-T2 · Outbound connect to a non-local IP is the
     * canonical "exfiltration in progress" trigger.  If the sotbox isn't
     * Tier-2 yet, promote it now so the synthetic-response fast path
     * below fires (otherwise we'd burn 100 ticks SYN-SENT and return
     * ETIMEDOUT, missing the deception).  Skip 127.0.0.0/8 (loopback)
     * and 10.0.2.0/24 (QEMU NAT · the synthetic local subnet). */
    {
        bool non_local = (a != 127) && !(a == 10 && b == 0 && c == 2);
        if (non_local && lucas_real_wire(st) &&
            !lucas_egress_dest_allowed(sa.addr_be, sa.port_be)) {
            /* GATE 0 · GUARDED · this real-wire session would reach a non-allowlisted
             * third party.  SINKHOLE it: record the destination as a C2/exfil IOC
             * (this IS the C2 map), mark the fd so recv() hands a canned reply +
             * send() is dropped, and return synthetic connect success — NO real
             * packet leaves the host.  The attacker still believes egress works. */
            printf("[egress] pid=%d → SINKHOLE %u.%u.%u.%u:%u (guarded · not allowlisted · no real packets)\n",
                   st->synthetic_pid, a, b, c, d, port_host);
            trace_emit_net(st->slot_index, (uint32_t)st->synthetic_pid, 0,
                           SG_EV_NET_CONNECT, sa.addr_be, sa.port_be, 0);
            if (fd < LUCAS_MAX_FDS && st->fds[fd].kind == LUCAS_FD_SOCKET) {
                st->fds[fd].connect_peer_ip_be   = sa.addr_be;
                st->fds[fd].connect_peer_port_be = sa.port_be;
                st->fds[fd].synth_sinkhole       = 1;
            }
            return 0;
        }
        if (non_local && lucas_real_wire(st)) {
            /* N1 · Tier-0e egress OR the interactive SSH attacker session
             * (cow_session != 0 · high-interaction honeypot) · authorised for a
             * REAL connect · do NOT take the synth fast-path · fall through to
             * the real tcp_active_open below.  IOC'd via trace_emit_net. */
            printf("[egress] pid=%d → REAL connect %u.%u.%u.%u:%u (%s · wire)\n",
                   st->synthetic_pid, a, b, c, d, port_host,
                   lucas_is_egress(st) ? "Tier-0e" : "honey-session");
            /* P3a · push the egress connect into the trace rings (netgraph
             * keys egress on pid+peer). Use the LOCAL sa decode (network
             * order) — st->fds[fd].connect_peer_* is written later, still 0.
             * Egress conns carry no conn_id (tcp_active_open → 0). */
            trace_emit_net(st->slot_index, (uint32_t)st->synthetic_pid, 0,
                           SG_EV_NET_CONNECT, sa.addr_be, sa.port_be, 0);
        } else if (non_local && st->functor && !st->functor->is_isolated) {
            extern void lucas_set_tier(struct lucas_state *st, int tier);
            printf("[connect] pid=%d → non-local %u.%u.%u.%u · auto-promote Tier→2 (synth redirect)\n",
                   st->synthetic_pid, a, b, c, d);
            lucas_set_tier(st, 2);
        }
    }

    /* γ-3-γ-2b · cache the connect peer so a connected send()/recv() (no
     * per-call address · how a TLS client talks) routes over the byte-pipe. */
    if (fd < LUCAS_MAX_FDS && st->fds[fd].kind == LUCAS_FD_SOCKET) {
        st->fds[fd].connect_peer_ip_be   = sa.addr_be;
        st->fds[fd].connect_peer_port_be = sa.port_be;
    }

    /* N-CONNECT synth fast-path · Tier-2 sotbox connecting non-local
     * gets synthetic instant success (no real SYN sent).  Subsequent
     * send/recv land in the synth synth handler (is_synth_redirected).
     * EXCEPTION · the interactive SSH attacker session (lucas_real_wire ·
     * cow_session != 0) is authorised for a REAL connect (high-interaction
     * honeypot · observe full behavior) and must NOT be short-circuited here —
     * it already fell into the real-connect branch above and continues to
     * tcp_active_open below. */
    if (st->functor && st->functor->is_isolated && !lucas_real_wire(st)) {
        bool non_local = (a != 127) && !(a == 10 && b == 0 && c == 2);
        if (non_local) {
            printf("[synth] connect FAST-PATH · pid=%d tier=2 dst=%u.%u.%u.%u:%u · synthetic success\n",
                   st->synthetic_pid, a, b, c, d, port_host);
            return 0;
        }
    }

    /* A DGRAM (UDP) socket's connect() only sets the default peer (cached above)
     * — POSIX sends NO packets.  Return success here, BEFORE tcp_active_open:
     * an is_egress UDP connect (glibc's resolver, or dnsprobe, connecting its
     * UDP:53 socket to the nameserver) would otherwise open a REAL TCP SYN to the
     * DNS server and spin/park with no internet, wedging the orch loop and
     * starving concurrent inbound services (the TLS responder).  The subsequent
     * sendto()/recvfrom() carry the real UDP datagram + the DNS forward.  (Tier-2
     * UDP connects already returned via the synth fast-path above; this covers
     * the Tier-0e egress path — only a SOCK_STREAM connect does a real SYN.) */
    {
        int st_type = lucas_socket_type(st, fd);
        if (st_type >= 0 && (st_type & LUCAS_SOCK_TYPEMASK) != LUCAS_SOCK_STREAM) {
            printf("[connect] pid=%d → %u.%u.%u.%u:%u · UDP connect (peer set, no SYN)\n",
                   st->synthetic_pid, a, b, c, d, port_host);
            return 0;
        }
    }

    /* SOCKET DEMUX · a real OUTBOUND TCP connect rides the mature lwIP egress
     * stack when it is up (the δ stack stalled on real downloads).  Inbound
     * deception (listen/accept on :80/:22/:443) stays on δ — it never reaches
     * here.  On lwIP-connect failure, fall through to the legacy δ path. */
    {
        extern int   orch_lwip_egress_up(void);
        extern void *orch_lwip_egress_connect(uint32_t addr_be, uint16_t port_be);
        extern void *orch_lwip_egress_connect_start(uint32_t addr_be, uint16_t port_be);
        if (orch_lwip_egress_up()) {
            /* O_NONBLOCK (0x800): honour the non-blocking connect contract — return
             * -EINPROGRESS immediately and let the handshake complete async (the
             * client WaitFd(POLLOUT)s / getsockopt(SO_ERROR)s).  apt's http method
             * SetNonBlock(true)s its socket then connect()s expecting EINPROGRESS; a
             * synchronous-blocking connect returning 0 wedges its state machine so it
             * never sends the GET.  A blocking socket (apk) keeps the blocking path. */
            int nonblock = (st->fds[fd].flags & 0x800) != 0;
            if (nonblock) {
                void *sess = orch_lwip_egress_connect_start(sa.addr_be, sa.port_be);
                if (sess) {
                    st->fds[fd].lwip_sess = sess;
                    printf("[connect] pid=%d → %u.%u.%u.%u:%u EINPROGRESS via lwIP egress · fd=%lu (non-blocking)\n",
                           st->synthetic_pid, a, b, c, d, port_host, (unsigned long)fd);
                    return -(int64_t)115;   /* -EINPROGRESS */
                }
            } else {
                void *sess = orch_lwip_egress_connect(sa.addr_be, sa.port_be);
                if (sess) {
                    st->fds[fd].lwip_sess = sess;
                    printf("[connect] pid=%d → %u.%u.%u.%u:%u ESTABLISHED via lwIP egress · fd=%lu\n",
                           st->synthetic_pid, a, b, c, d, port_host, (unsigned long)fd);
                    return 0;
                }
            }
            printf("[connect] pid=%d → %u.%u.%u.%u:%u lwIP egress connect failed · δ fallback\n",
                   st->synthetic_pid, a, b, c, d, port_host);
        }
    }

    struct tcp_conn *conn = tcp_active_open(sa.addr_be, sa.port_be,
                                              (uint32_t)st->synthetic_pid);
    if (!conn) {
        printf("[connect] pid=%d → %u.%u.%u.%u:%u no conn slot · -ENOBUFS\n",
               st->synthetic_pid, a, b, c, d, port_host);
        return -(int64_t)105;  /* ENOBUFS */
    }

    /* Synchronous poll · drive RX + timer until ESTABLISHED/CLOSED or budget.
     * N1 · a Tier-0e egress connect must wait for a REAL internet SYN-ACK
     * (~ms = thousands of polls), not the µs a synthetic/local connect needs,
     * so widen the spin for egress.  Early-breaks on ESTABLISHED, so a fast
     * connect is unaffected; a non-egress connect keeps the original 100. */
    int spin = lucas_real_wire(st) ? 200000 : 100;
    for (int i = 0; i < spin; ++i) {
        (void)sotnet_poll();
        tcp_timer_tick();
        /* KVM host-CPU YIELD · a real-wire connect waits for the internet SYN-ACK,
         * which QEMU's iothread only DMAs into the RX ring when it gets the host
         * CPU — a tight sotnet_poll spin never yields it (demo-ssh-watch).  A paced
         * UART write (VM-exit → serial chardev) is the load-bearing yield; without
         * it the SYN-ACK never arrives and a real egress connect TIMEOUTs. */
        if (lucas_real_wire(st) && (i & 0x3FF) == 0) seL4_DebugPutChar('.');

        /* conn struct may be cleared by tcp_conn_free on RST · state
         * field then reads as 0 = TCP_STATE_CLOSED, which is what we
         * want for the refused branch. */
        if (conn->state == TCP_STATE_ESTABLISHED) {
            st->fds[fd].tcp_conn = conn;   /* N1 · δ-2 · bind conn to fd for write/read */
            printf("[connect] pid=%d → %u.%u.%u.%u:%u ESTABLISHED · fd=%lu bound\n",
                   st->synthetic_pid, a, b, c, d, port_host, (unsigned long)fd);
            return 0;
        }
        if (conn->state == TCP_STATE_CLOSED) {
            printf("[connect] pid=%d → %u.%u.%u.%u:%u REFUSED\n",
                   st->synthetic_pid, a, b, c, d, port_host);
            return -(int64_t)111;  /* ECONNREFUSED */
        }
        /* else still SYN_SENT · continue spinning. */
    }

    printf("[connect] pid=%d → %u.%u.%u.%u:%u TIMEOUT\n",
           st->synthetic_pid, a, b, c, d, port_host);
    /* Free the still-pending conn so we don't leak the slot. */
    sotnet_tcp_close(conn);
    return -(int64_t)110;  /* ETIMEDOUT */
}

/* ------------------------------------------------------------------ */
/* N1 · δ-2 · connected-TCP data path.  write()/read() on a socket fd  */
/* bound to a real tcp_conn (Tier-0e egress) drive the existing        */
/* tcp_send_data() / conn->rx_buf primitives in src/sotnet/tcp_data.c. */
/* ------------------------------------------------------------------ */
int64_t lucas_tcp_send(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr, uint64_t len)
{
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    /* SOCKET DEMUX · lwIP-backed egress fd → route the write to the mature stack. */
    if (st->fds[fd].lwip_sess != NULL) {
        extern int64_t orch_lwip_egress_send(void *handle, const uint8_t *buf, uint32_t len);
        if (len == 0) return 0;
        static uint8_t lwtxb[TCP_TX_BUF_SIZE];
        size_t n = (len < TCP_TX_BUF_SIZE) ? (size_t)len : TCP_TX_BUF_SIZE;
        if (lucas_copy_from_client(st, (uintptr_t)buf_vaddr, lwtxb, n) != 0)
            return -(int64_t)LX_EFAULT;
        int64_t sent = orch_lwip_egress_send(st->fds[fd].lwip_sess, lwtxb, (uint32_t)n);
        if (sent < 0) return -(int64_t)32;   /* EPIPE */
        printf("[egress-lwip] pid=%d write fd=%lu · sent %ld bytes\n",
               st->synthetic_pid, (unsigned long)fd, (long)sent);
        return sent;
    }

    if (st->fds[fd].tcp_conn == NULL)
        return -(int64_t)LX_EBADF;
    struct tcp_conn *conn = st->fds[fd].tcp_conn;
    /* ESTABLISHED or CLOSE_WAIT can still SEND: the peer's FIN (→ CLOSE_WAIT)
     * only half-closes ITS send direction; our local side may keep transmitting
     * until we send our own FIN.  THE BUG: returning ENOTCONN in CLOSE_WAIT made
     * openssl s_client's close_notify write (SSL_shutdown, 24 B) fail; it retried
     * in a TIGHT INFINITE LOOP → never flushed its block-buffered stdout (the
     * decrypted HTML) and never exited, so `wget -O -` produced no body.  Any
     * other state (CLOSING/LAST_ACK/CLOSED) genuinely can't send → EPIPE so the
     * writer stops cleanly instead of spinning on ENOTCONN. */
    if (conn->state != TCP_STATE_ESTABLISHED && conn->state != TCP_STATE_CLOSE_WAIT)
        return -(int64_t)32;    /* EPIPE · send side gone */
    if (len == 0) return 0;

    static uint8_t txb[TCP_TX_BUF_SIZE];
    size_t n = (len < TCP_TX_BUF_SIZE) ? (size_t)len : TCP_TX_BUF_SIZE;
    if (lucas_copy_from_client(st, (uintptr_t)buf_vaddr, txb, n) != 0)
        return -(int64_t)LX_EFAULT;

    int sent = tcp_send_data(conn, txb, n);
    if (sent < 0) return -(int64_t)5;   /* EIO */

    /* Drive the stack so the peer's ACK of our data is processed. */
    for (int i = 0; i < 200; ++i) { (void)sotnet_poll(); tcp_timer_tick(); }
    printf("[egress] pid=%d write fd=%lu · sent %d bytes on the wire\n",
           st->synthetic_pid, (unsigned long)fd, sent);
    return (int64_t)sent;
}

int64_t lucas_tcp_recv(lucas_state_t *st, uint64_t fd, uint64_t buf_vaddr, uint64_t count)
{
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    /* SOCKET DEMUX · lwIP-backed egress fd → read from the mature stack.  Honour
     * O_NONBLOCK (0x800): a non-blocking client (apt's http method) reads expecting
     * EAGAIN before it writes its request — blocking it there deadlocks. */
    if (st->fds[fd].lwip_sess != NULL) {
        extern int64_t orch_lwip_egress_recv(void *handle, uint8_t *buf, uint32_t len, int nonblock);
        static uint8_t lwrxb[TCP_TX_BUF_SIZE];
        size_t want = (count < TCP_TX_BUF_SIZE) ? (size_t)count : TCP_TX_BUF_SIZE;
        int nonblock = (st->fds[fd].flags & 0x800) != 0;
        int64_t got = orch_lwip_egress_recv(st->fds[fd].lwip_sess, lwrxb, (uint32_t)want, nonblock);
        if (got == -11) return -(int64_t)LX_EAGAIN;   /* no data yet (non-blocking) */
        if (got <= 0) return got;                     /* 0 = EOF · <0 = error */
        if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, lwrxb, (size_t)got) != 0)
            return -(int64_t)LX_EFAULT;
        return got;
    }

    if (st->fds[fd].tcp_conn == NULL)
        return -(int64_t)LX_EBADF;
    struct tcp_conn *conn = st->fds[fd].tcp_conn;

    /* Drain any already-buffered segment first; else spin RX until a data
     * segment lands, the peer closes, or the budget is exhausted.
     * N1 · KICK the RX queue every iteration while waiting (re-arm QEMU) — the
     * in-orch RX-drain probe proved this is what unsticks delivery past the
     * initial burst (the scan-hack only kicked on delivery → QEMU stayed dry →
     * the response was never delivered).  Wide budget for a real-internet RTT. */
    extern void virtio_net_rx_kick(void);
    extern seL4_CPtr orch_vnet_irq_ntf(void);
    extern seL4_CPtr orch_vnet_irq_handler(void);
    extern uint8_t   virtio_net_ack_isr(void);
    seL4_CPtr vnet_ntf  = orch_vnet_irq_ntf();
    seL4_CPtr vnet_irqh = orch_vnet_irq_handler();
    /* O_NONBLOCK (0x800) · a non-blocking reader (e.g. libfetch/openssl checking
     * for an early response BETWEEN request writes, or a select()-driven relay)
     * MUST get a prompt EAGAIN — blocking it in seL4_Wait stalls the caller's own
     * request send (it can't issue the next write while we hold it in read), which
     * made the peer time out the half-sent request and FIN with no response.  So
     * the IRQ block applies ONLY to genuinely-blocking reads; non-blocking reads
     * fall through to the legacy short busy-poll + EAGAIN below. */
    int fd_nonblock = (st->fds[fd].flags & 0x800) != 0;
    if (conn->rx_len == 0 && vnet_ntf != 0 && !fd_nonblock) {
        /* IRQ-driven RX (the egress-throughput fix) · instead of burning a 200k
         * busy-poll that never yields the host CPU under KVM, BLOCK on the
         * virtio-net IRQ notification.  seL4_Wait idles the vCPU (HLT) → QEMU's
         * iothread gets the host CPU → the inbound frame DMAs into the RX ring →
         * the device raises GSI 11 → the kernel Signals the notification → we wake.
         * Every received frame (data/ACK/FIN) raises the IRQ, so an active transfer
         * wakes us continuously.  Bounded to a few waits per read() so a genuinely
         * idle blocking socket still returns EAGAIN eventually. */
        for (int w = 0; w < 4 && conn->rx_len == 0; ++w) {
            (void)sotnet_poll();
            if (conn->rx_len > 0) break;
            if (conn->state != TCP_STATE_ESTABLISHED &&
                conn->state != TCP_STATE_CLOSE_WAIT) break;   /* peer done */
            tcp_timer_tick();
            (void)virtio_net_ack_isr();                       /* deassert handled INTx */
            if (vnet_irqh != 0) seL4_IRQHandler_Ack(vnet_irqh); /* re-arm (unmask) */
            seL4_Word irqb = 0;
            seL4_Wait(vnet_ntf, &irqb);                        /* BLOCK → vCPU idles */
        }
        (void)sotnet_poll();   /* drain whatever the wake delivered */
    } else if (conn->rx_len == 0) {
        /* Busy-poll fallback · non-blocking reader (fd_nonblock — falls here past
         * the IRQ block above) or IRQ not wired.  Legacy wide budget. */
        for (long i = 0; i < 200000L; ++i) {
            (void)sotnet_poll();
            virtio_net_rx_kick();                /* re-arm QEMU while waiting */
            if ((i & 0xFF) == 0) tcp_timer_tick();
            if (conn->rx_len > 0) break;
            if (conn->state != TCP_STATE_ESTABLISHED &&
                conn->state != TCP_STATE_CLOSE_WAIT) break;   /* peer done */
        }
    }
    if (conn->rx_len == 0) {
        /* Still ESTABLISHED with no data yet ≠ EOF.  A real non-blocking socket
         * returns EAGAIN here.  openssl s_client treats a 0-return as a CLOSED
         * connection and abandons the stdin↔socket relay — so after the handshake
         * it reads the socket, gets 0, and bails BEFORE relaying wget's HTTP
         * request (the server then ACKs nothing, FINs).  Return EAGAIN so the
         * relay loop keeps going: read the request from stdin, send it, then a
         * later socket read (whose spin pumps RX) catches the response.  Only a
         * peer FIN (CLOSE_WAIT / closed) is a true EOF. */
        if (conn->state == TCP_STATE_ESTABLISHED) {
            return -(int64_t)11;  /* EAGAIN · open, no data yet */
        }
        printf("[egress] pid=%d read fd=%lu · 0 bytes (EOF · state=%d · peer closed)\n",
               st->synthetic_pid, (unsigned long)fd, (int)conn->state);
        return 0;   /* EOF · peer sent FIN */
    }

    /* Free receive-window space BEFORE the drain.  Used to decide whether the
     * drain reopens a window the peer was throttled on — see the window-update
     * ACK below. */
    extern int tcp_send_segment(struct tcp_conn *conn, uint8_t flags,
                                const uint8_t *data, size_t data_len);
    size_t rx_free_before = (conn->rx_len < TCP_RX_BUF_SIZE)
                          ? (TCP_RX_BUF_SIZE - conn->rx_len) : 0;

    size_t n = (count < conn->rx_len) ? (size_t)count : conn->rx_len;
    if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, conn->rx_buf, n) != 0)
        return -(int64_t)LX_EFAULT;
    /* Consume n bytes from the single-segment rx_buf; keep any remainder so a
     * short read() doesn't lose the rest of the segment (rx_buf is overwritten
     * only when the next in-order segment arrives, which we only poll for when
     * rx_len == 0). */
    if (n < conn->rx_len) {
        memmove(conn->rx_buf, conn->rx_buf + n, conn->rx_len - n);
        conn->rx_len -= n;
    } else {
        conn->rx_len = 0;
    }

    /* WINDOW UPDATE · the advertised receive window IS the rx_buf free space
     * (tcp_send_segment).  On a bulk download (e.g. apt's 140 KB InRelease, apk's
     * APKINDEX) the 16 KiB rx_buf fills, our data-ACKs advertise a near-zero
     * window, and the sender pauses.  ACKs are otherwise sent ONLY when an inbound
     * segment arrives — but a paused sender sends nothing, so without a proactive
     * update the transfer only resumes on the peer's slow zero-window probe.
     *
     * δ-2 · re-advertise on EVERY drained read, not only when the buffer was
     * >half full.  Once the window has collapsed to a few bytes the sender pins
     * its segments to that tiny window (we saw 36–76 B APKINDEX segments), so the
     * buffer never refills past half and the old `rx_free_before < HALF` gate
     * never fired → the small window locked in and the download trickled to ~27
     * B/s.  A pure ACK after any read that freed space re-advertises the full
     * window immediately, so the sender returns to full-MSS segments. */
    (void)rx_free_before;
    if (n > 0 && conn->state == TCP_STATE_ESTABLISHED) {
        (void)tcp_send_segment(conn, 0x10 /* TCP_FLAG_ACK */, NULL, 0);
    }

    printf("[egress] pid=%d read fd=%lu · got %zu bytes from the wire\n",
           st->synthetic_pid, (unsigned long)fd, n);
    return (int64_t)n;
}

void lucas_socket_close_conn(lucas_state_t *st, uint64_t fd)
{
    if (fd >= LUCAS_MAX_FDS) return;
    if (st->fds[fd].lwip_sess) {   /* SOCKET DEMUX · lwIP egress session */
        extern void orch_lwip_egress_close(void *handle);
        orch_lwip_egress_close(st->fds[fd].lwip_sess);
        st->fds[fd].lwip_sess = NULL;
    }
    if (st->fds[fd].tcp_conn) {
        sotnet_tcp_close(st->fds[fd].tcp_conn);
        st->fds[fd].tcp_conn = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* L12-gamma · Wayland wire transport over the compositor route EP.    */
/* One 32-bit wire word per message register.  Synchronous seL4_Call;  */
/* the compositor parses MR0/MR1 and replies with the event words.     */
/* ------------------------------------------------------------------ */
/* L13-B3 · forward a Wayland wire frame to the compositor, optionally appending
 * `n_extra` sotOs-internal words after the `len`-byte request frame.  The base
 * `lucas_wayland_forward` is the thin wrapper (extra=NULL,n_extra=0); the
 * create_pool recognition path (below) calls this with the mapped compositor
 * vaddr + pool size as the two extra words. */
static int64_t lucas_wayland_forward_ex(lucas_state_t *st, uint64_t fd,
                                        uint64_t buf_vaddr, uint64_t len,
                                        const uint32_t *extra, size_t n_extra,
                                        int scm_fd, const uint32_t *inline_words)
{
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET
        || !st->fds[fd].wayland_connected)
        return -(int64_t)LX_EBADF;
    if (len == 0 || (len % 4) != 0)
        return -(int64_t)22;   /* EINVAL · wire words are 4 bytes */

    uint32_t req[LUCAS_WL_MAX_WORDS];
    size_t nwords = (size_t)len / 4;
    if (nwords > LUCAS_WL_MAX_WORDS) {
        printf("[wl-einval] msg too large · nwords=%zu cap=%d (len=%llu)\n",
               nwords, LUCAS_WL_MAX_WORDS, (unsigned long long)len);
        return -(int64_t)22;   /* EINVAL · frame too large for L12 control path */
    }
    if (nwords + n_extra > LUCAS_WL_MAX_WORDS) {
        printf("[wl-einval] msg+extra exceeds MR cap · nwords=%zu n_extra=%zu\n", nwords, n_extra);
        return -(int64_t)22;   /* EINVAL · request + appended words exceed MR cap */
    }
    /* inline_words != NULL → forward a message already reassembled in a local
     * buffer (the TX-reassembly path); else copy it from the client. */
    if (inline_words) memcpy(req, inline_words, nwords * 4);
    else if (lucas_copy_from_client(st, (uintptr_t)buf_vaddr, req, nwords * 4) != 0)
        return -(int64_t)LX_EFAULT;

    /* L13-B3 · request recognition (only on the direct entry path · n_extra==0,
     * so the recursive create_pool forward below does not re-trigger). */
    if (n_extra == 0 && nwords >= 2) {
        uint32_t obj    = req[0];
        uint32_t opcode = req[1] & 0xFFFFu;
        /* L14a-C1 · canary screenshot map (RO view into the Tier-2 client). */
        extern uintptr_t orch_canary_screenshot_map_view(vspace_t*, uintptr_t, uint32_t*, uint32_t*, uint32_t*);
        extern int orch_canary_screenshot_ready(void);
        /* L14b · orch xkb keymap pool (mirrors the canary externs above). */
        extern uintptr_t orch_keymap_map_view(vspace_t*, uintptr_t, uint32_t*);
        extern int orch_keymap_ready(void);
        extern void trace_emit_input_inject(int, uint16_t, uint32_t);

        /* wl_registry.bind(name, iface, version, new_id): obj is a registry id
         * (!= the wl_display id 1), opcode 0.  Wire (matches compositor):
         *   word2=name, word3=iface strlen, word[4..4+nstr)=string,
         *   word[4+nstr]=version, word[4+nstr+1]=bound new_id (last word).
         * When name==2 (wl_shm global), record the bound new_id. */
        if (obj != 1 && opcode == 0 && nwords >= 4 && req[2] == 2) {
            uint32_t bound = req[nwords - 1];   /* bound new_id is the last word */
            st->fds[fd].wl_shm_obj_id = bound;
            printf("[l13-bind] registry=%u name=2 (wl_shm) -> obj_id=%u\n",
                   obj, bound);
        }

        /* L14a-A1/C1 · wl_registry.bind for the sotos_capture global (name==3,
         * advertised by the shadow compositor).  Record the bound new_id so a
         * later request on it triggers the canary-screenshot map. */
        else if (obj != 1 && opcode == 0 && nwords >= 4 && req[2] == 3) {
            uint32_t bound = req[nwords - 1];   /* bound new_id is the last word */
            st->fds[fd].wl_capture_obj_id = bound;
            printf("[l14a-bind] registry=%u name=3 (sotos_capture) -> obj_id=%u\n",
                   obj, bound);
        }

        /* L14b · wl_registry.bind for the wl_seat global (name==4).  Record the
         * bound new_id so a later poll request on it triggers synthetic input. */
        else if (obj != 1 && opcode == 0 && nwords >= 4 && req[2] == 4) {
            uint32_t bound = req[nwords - 1];   /* bound new_id is the last word */
            st->fds[fd].wl_seat_obj_id = bound;
            printf("[l14b-bind] registry=%u name=4 (wl_seat) -> obj_id=%u\n",
                   obj, bound);
        }

        /* v2.7 live input · bind for the HONEST compositor's xdg_wm_base (name==5)
         * and wl_seat (name==6).  Recorded so a later get_xdg_surface / get_pointer
         * can be sniffed and synthesized wl_pointer events addressed at the WINDOW
         * surface.  (The Tier-2 shadow compositor uses name==4 for its seat, above.) */
        else if (st->tier < 2 && obj != 1 && opcode == 0 && nwords >= 4 && req[2] == 5) {
            st->fds[fd].wl_xdg_obj_id = req[nwords - 1];
        }
        else if (st->tier < 2 && obj != 1 && opcode == 0 && nwords >= 4 && req[2] == 6) {
            st->fds[fd].wl_seat_obj_id = req[nwords - 1];
            printf("[l14c-bind] registry=%u name=6 (wl_seat) -> obj_id=%u\n",
                   obj, st->fds[fd].wl_seat_obj_id);
        }

        /* wl_shm.create_pool(pool_new_id, opcode 0): the request object id is the
         * bound wl_shm id, opcode 0.  sotOs wire (4 words):
         *   word0=pool_new_id, word1=(size<<16)|0, word2=memfd_fd, word3=pool_sz */
        else if (st->fds[fd].wl_shm_obj_id != 0
                 && obj == st->fds[fd].wl_shm_obj_id
                 && opcode == 0
                 && (nwords >= 5 || (scm_fd >= 0 && nwords >= 4))) {
            /* create_pool. Two wire shapes:
             *  - hand-rolled (5 words): [wl_shm_id, hdr, pool_new_id, memfd_fd, pool_size]
             *  - real libwayland (4 words): [wl_shm_id, hdr, pool_new_id, pool_size];
             *    the pool fd arrives out-of-band via SCM_RIGHTS (scm_fd). */
            uint32_t memfd_fd = (scm_fd >= 0) ? (uint32_t)scm_fd : req[3];
            uint32_t pool_sz  = (scm_fd >= 0) ? req[3]           : req[4];
            (void)pool_sz;
            if (memfd_fd < LUCAS_MAX_FDS && st->fds[memfd_fd].is_memfd
                && st->fds[memfd_fd].shm_pool_id >= 0) {
                extern uintptr_t orch_shm_pool_map_compositor(int, seL4_CPtr, uintptr_t);
                extern size_t    orch_shm_pool_size(int);
                int pid = st->fds[memfd_fd].shm_pool_id;
                uintptr_t cva = orch_shm_pool_map_compositor(pid, orch_wayland_pd_cap(),
                                                             COMPOSITOR_SHM_POOL_BASE);
                if (!cva) {
                    printf("[l13-create_pool] memfd=%u pool=%d · compositor map FAILED · forwarding unmodified\n",
                           memfd_fd, pid);
                    return lucas_wayland_forward_ex(st, fd, buf_vaddr, len, NULL, 0, -1, inline_words);
                }
                /* v2.6 present · export the virtio-gpu scanout into the compositor's
                 * PD ONCE (at a fixed VA), so on commit the compositor can blit the
                 * surface straight into the scanout.  orch keeps owning the virtqueue
                 * flush (see the opcode-6 flush after the forward Call below), so the
                 * commit path never does a compositor→orch IPC that would deadlock
                 * LUCAS while it awaits the commit reply.  Headless (no virtio-gpu, as
                 * in the gate boot) → va stays 0 and the compositor skips the blit. */
                static uintptr_t s_scanout_va = 0;
                static int s_scanout_w = 0, s_scanout_h = 0, s_scanout_stride = 0;
                static int s_scanout_tried = 0;
                if (!s_scanout_tried) {
                    s_scanout_tried = 1;
                    extern uintptr_t gpu_export_to_pd(seL4_CPtr, uintptr_t, int *, int *, int *);
                    s_scanout_va = gpu_export_to_pd(orch_wayland_pd_cap(), 0x71000000UL,
                                                    &s_scanout_w, &s_scanout_h, &s_scanout_stride);
                }
                uint32_t cp_extra[6] = {
                    (uint32_t)(cva & 0xFFFFFFFFu),
                    (uint32_t)orch_shm_pool_size(pid),
                    (uint32_t)(s_scanout_va & 0xFFFFFFFFu),
                    (uint32_t)s_scanout_w,
                    (uint32_t)s_scanout_h,
                    (uint32_t)s_scanout_stride,
                };
                /* M4 · the wl_shm_pool object (req[2]=pool_new_id) now references
                 * the backing (ref C); record its wire id for refcount events. */
                extern void orch_shm_pool_attach(int, uint32_t, uint64_t, uint32_t);
                orch_shm_pool_attach(pid, (uint32_t)st->synthetic_pid, fd, req[2]);
                st->fds[fd].wl_pool_obj_id = req[2];  /* v2.7 · sniff create_buffer dims */
                printf("[l13-create_pool] memfd=%u pool=%d -> compositor @0x%lx size=%u scanout@0x%lx %dx%d\n",
                       memfd_fd, pid, (unsigned long)cva, cp_extra[1],
                       (unsigned long)s_scanout_va, s_scanout_w, s_scanout_h);
                return lucas_wayland_forward_ex(st, fd, buf_vaddr, len, cp_extra, 6, -1, inline_words);
            }
        }

        /* v2.7 live input · sniff (record + fall through to forward) the honest
         * client's xdg_wm_base.get_xdg_surface, wl_seat.get_pointer, and
         * wl_shm_pool.create_buffer so LUCAS knows the WINDOW surface/pointer ids +
         * window dims needed to address & coordinate-map synthesized wl_pointer
         * events.  get_xdg_surface (not create_surface) pins the WINDOW surface —
         * a toolkit also create_surfaces a separate cursor surface for set_cursor. */
        else if (st->tier < 2 && st->fds[fd].wl_xdg_obj_id != 0
                 && obj == st->fds[fd].wl_xdg_obj_id
                 && opcode == 2 && nwords >= 4) {        /* xdg_wm_base.get_xdg_surface(new_id, wl_surface) */
            st->fds[fd].wl_surface_obj_id = req[3];      /* req[3] = the window's wl_surface */
        }
        else if (st->tier < 2 && st->fds[fd].wl_seat_obj_id != 0
                 && obj == st->fds[fd].wl_seat_obj_id
                 && opcode == 0 && nwords >= 3) {        /* wl_seat.get_pointer(new_id) */
            st->fds[fd].wl_pointer_obj_id = req[2];
            printf("[l14c] pid=%u wl_pointer obj_id=%u (live input armed)\n",
                   st->synthetic_pid, req[2]);
        }
        else if (st->tier < 2 && st->fds[fd].wl_pool_obj_id != 0
                 && obj == st->fds[fd].wl_pool_obj_id
                 && opcode == 0 && nwords >= 6) {        /* wl_shm_pool.create_buffer */
            st->fds[fd].wl_win_w = (uint16_t)req[4];     /* wire: [pool,hdr,id,off,w,h,...] */
            st->fds[fd].wl_win_h = (uint16_t)req[5];
        }

        /* L14a-C1 · sotos_capture request: a Tier-2 client issued a capture on
         * the bound sotos_capture object.  Map a fresh RO view of the installed
         * canary screenshot frame into the client and reply addr+dims, so the
         * client reads the installed GNOME scene.  Gated on the bound obj id so it
         * never fires on get_registry/bind frames. */
        else if (st->tier >= 2                       /* defense-in-depth: only hostile clients capture */
                 && st->fds[fd].wl_capture_obj_id != 0
                 && obj == st->fds[fd].wl_capture_obj_id
                 && opcode == 0 && orch_canary_screenshot_ready()) {
            uint32_t cw=0, ch=0, cstride=0;
            uintptr_t va = orch_canary_screenshot_map_view(&st->client_vspace_abs, LUCAS_CANARY_SCREENSHOT_VIEW_BASE, &cw, &ch, &cstride);
            if (va) {
                /* va is >32-bit (0x210000000) → send BOTH halves. 5 words = 20 bytes. */
                uint32_t reply[5] = { (uint32_t)va, (uint32_t)(va >> 32), cw, ch, cstride };
                memcpy(st->fds[fd].wl_rx, reply, sizeof reply);
                st->fds[fd].wl_rx_len = sizeof reply; st->fds[fd].wl_rx_cursor = 0;
                trace_emit_canary_screenshot(-1, 0 /* no conn_id · canary capture is fd-local */, cw*ch*4);
                printf("[l14a-capture] pid=%u -> canary view @0x%lx %ux%u\n",
                       st->synthetic_pid, (unsigned long)va, cw, ch);
                return (int64_t)len;   /* write() succeeds; the client read()s the 5-word reply */
            }
        }

        /* L14b · wl_seat poll: a Tier-2 client polled the bound wl_seat object.
         * Inject a deterministic synthetic input batch into the client's read
         * buffer so the canary desktop looks "live".  Gated on the bound obj id
         * + opcode 1 so it never fires on get_registry/bind/capture frames. */
        else if (st->tier >= 2
                 && st->fds[fd].wl_seat_obj_id != 0
                 && obj == st->fds[fd].wl_seat_obj_id
                 && opcode == 1) {                          /* sotOs wl_seat poll */
            /* L14b · realistic synthetic input: smooth wl_fixed pointer motion +
             * timed key sequence. Record = {type,a,b,ts_ms}. type1=motion (a,b are
             * wl_fixed 24.8 = px<<8), type2=key (a=keycode,b=state). Deterministic
             * (hand-authored jitter) so the fnv1a gate is reproducible. */
            #define WLFX(px) ((uint32_t)((px) << 8))
            static const uint32_t EV[15][4] = {
                /* 11 smooth pointer steps (700,420)->(760,450), jittered timing */
                {1, WLFX(700), WLFX(420),   0},
                {1, WLFX(706), WLFX(423),  14},
                {1, WLFX(713), WLFX(426),  27},
                {1, WLFX(719), WLFX(429),  39},
                {1, WLFX(726), WLFX(432),  54},
                {1, WLFX(732), WLFX(435),  66},
                {1, WLFX(739), WLFX(438),  81},
                {1, WLFX(745), WLFX(441),  93},
                {1, WLFX(752), WLFX(444), 108},
                {1, WLFX(758), WLFX(447), 121},
                {1, WLFX(760), WLFX(450), 133},
                /* key sequence: 'l' down/up, Enter down/up — real evdev keycodes */
                {2, 38, 1, 360},   /* KEY_L  press   (evdev 38) */
                {2, 38, 0, 432},   /* KEY_L  release */
                {2, 28, 1, 690},   /* KEY_ENTER press (evdev 28) */
                {2, 28, 0, 754},   /* KEY_ENTER release */
            };
            uint32_t batch[1 + 15*4];
            /* S2 buffer guard — use sizeof on the actual member (no type-name guess; sizeof is
             * compile-time even on a runtime ptr). 244 <= 256. */
            _Static_assert(sizeof(uint32_t) * (1 + 15*4) <= sizeof st->fds[fd].wl_rx,
                           "wl_rx too small for the 15-event input batch");
            batch[0] = 15;
            for (int e = 0; e < 15; ++e)
                for (int w = 0; w < 4; ++w) batch[1 + e*4 + w] = EV[e][w];
            memcpy(st->fds[fd].wl_rx, batch, sizeof batch);   /* 244 bytes <= wl_rx[256] */
            st->fds[fd].wl_rx_len = sizeof batch; st->fds[fd].wl_rx_cursor = 0;
            uint32_t hh = 2166136261u; const uint8_t *bp = (const uint8_t*)batch;
            for (size_t i = 0; i < sizeof batch; ++i) { hh ^= bp[i]; hh *= 16777619u; }
            trace_emit_input_inject(-1, 0, 15);
            printf("[l14b-inject] pid=%u 15 events fnv1a=0x%08x\n", st->synthetic_pid, hh);
            return (int64_t)len;
        }

        /* L14b · wl_seat.get_keyboard (opcode 2): deliver a real xkb keymap. Map
         * the orch keymap blob RO into the client + reply [vaddr_lo, vaddr_hi,
         * size, format=1 (XKB_V1)] so the synthetic keyboard is protocol-correct. */
        else if (st->tier >= 2
                 && st->fds[fd].wl_seat_obj_id != 0
                 && obj == st->fds[fd].wl_seat_obj_id
                 && opcode == 2 && orch_keymap_ready()) {
            uint32_t ksize = 0;
            uintptr_t kva = orch_keymap_map_view(&st->client_vspace_abs, LUCAS_KEYMAP_VIEW_BASE, &ksize);
            if (kva) {
                uint32_t reply[4] = { (uint32_t)kva, (uint32_t)(kva >> 32), ksize, 1 /* XKB_V1 */ };
                memcpy(st->fds[fd].wl_rx, reply, sizeof reply);
                st->fds[fd].wl_rx_len = sizeof reply; st->fds[fd].wl_rx_cursor = 0;
                printf("[l14b-keymap] pid=%u -> keymap @0x%lx %u B\n",
                       st->synthetic_pid, (unsigned long)kva, ksize);
                return (int64_t)len;
            }
        }
    }

    /* M4 · observe wl_shm_pool.create_buffer/destroy + wl_buffer.destroy on the
     * direct forward path to maintain the pool refcount.  Acts only on tracked
     * pool/buffer wire-ids (keyed by owner), so wl_surface/xdg/etc never match. */
    if (n_extra == 0 && nwords >= 2) {
        extern void orch_shm_pool_wire_event(uint32_t, uint64_t, uint32_t, uint32_t, uint32_t);
        orch_shm_pool_wire_event((uint32_t)st->synthetic_pid, fd, req[0],
                                 req[1] & 0xFFFFu, nwords >= 3 ? req[2] : 0);
    }

    for (size_t i = 0; i < nwords; ++i)
        seL4_SetMR(i, (seL4_Word)req[i]);
    for (size_t i = 0; i < n_extra; ++i)
        seL4_SetMR(nwords + i, (seL4_Word)extra[i]);

    seL4_MessageInfo_t info  = seL4_MessageInfo_new(0, 0, 0, nwords + n_extra);
    seL4_MessageInfo_t reply = seL4_Call(st->fds[fd].wayland_route_ep, info);
    seL4_Word status = seL4_MessageInfo_get_label(reply);
    if (status != 0) {
        printf("[wayland] pid=%d write fd=%lu · compositor status=%lu -> error\n",
               st->synthetic_pid, (unsigned long)fd, (unsigned long)status);
        return -(int64_t)status;   /* L12-delta · label carries the errno */
    }
    /* v2.6 present · on a wl_surface.commit (opcode 6) the compositor has just
     * blitted the surface into the shared scanout (mapped via gpu_export_to_pd);
     * flush it to the QEMU display NOW — orch is free (the compositor already
     * replied), so this never deadlocks the commit Call above. */
    if (n_extra == 0 && nwords >= 2 && (req[1] & 0xFFFFu) == 6) {
        /* Coalesced present · mark dirty; the orch fault-loop idle branch does the
         * actual full-screen flush once per pass, so a burst of commits (e.g. GTK
         * hover redraws + cursor-surface commits during mouse motion) becomes ONE
         * present instead of a flush flood that freezes the -display gtk window. */
        extern void gpu_mark_dirty(void);
        gpu_mark_dirty();
    }
    size_t rwords = (size_t)seL4_MessageInfo_get_length(reply);
    if (rwords * 4 > sizeof(st->fds[fd].wl_rx))
        rwords = sizeof(st->fds[fd].wl_rx) / 4;   /* clamp · never overflow wl_rx */

    for (size_t i = 0; i < rwords; ++i) {
        uint32_t w = (uint32_t)seL4_GetMR(i);
        memcpy(&st->fds[fd].wl_rx[i * 4], &w, 4);
    }
    st->fds[fd].wl_rx_len    = (uint16_t)(rwords * 4);
    st->fds[fd].wl_rx_cursor = 0;
    /* (per-request forward trace silenced · M4 · it dominated the serial and
     * slowed window create/destroy churn; the compositor still logs key ops.) */
    return (int64_t)len;
}

/* L12-gamma entry · thin wrapper: forward with no appended sotOs words. */
int64_t lucas_wayland_forward(lucas_state_t *st, uint64_t fd,
                              uint64_t buf_vaddr, uint64_t len)
{
    return lucas_wayland_forward_ex(st, fd, buf_vaddr, len, NULL, 0, -1, NULL);
}

/* v2-wl-transport · real libwayland sends a sendmsg byte stream that may pack
 * MULTIPLE Wayland wire messages back-to-back (e.g. get_registry + the
 * roundtrip sync); the compositor parses exactly one message per seL4_Call.
 * Split the stream on wire-header boundaries (size = hdr>>16) and forward each
 * message via forward_ex, ACCUMULATING the per-message replies into `acc` (the
 * caller publishes acc into wl_rx once — forward_ex writes wl_rx[0..] per call,
 * which we'd otherwise clobber on the 2nd message).  base_vaddr is the client
 * address of the stream; each message is re-copied by forward_ex. */
static int64_t lucas_wayland_forward_stream(lucas_state_t *st, uint64_t fd,
                                            uint64_t base_vaddr, uint64_t len,
                                            uint8_t *acc, size_t acc_cap,
                                            size_t *acc_len, int scm_fd)
{
    if (len == 0 || (len % 4) != 0) return -(int64_t)22;   /* EINVAL */
    /* libwayland packs many requests into ONE sendmsg and flushes them as a
     * batch; this forwarder loops over the messages (each goes via the per-
     * message MR path).  TWO real-app behaviours a simple fixture (gtkspike)
     * never showed but gtk3-demo does:
     *   (a) a LARGE batch (bigger window + more widgets) — the buffer was 1 KiB
     *       ("up to 4 messages"); 64 KiB covers a realistic GTK flush.  static
     *       (orch is single-threaded · the fault handler is non-reentrant).
     *   (b) a message SPLIT across the sendmsg/iov boundary (libwayland's ring
     *       buffer wraps) — the old code saw the trailing partial as malformed
     *       wire → `wl_display_flush: Invalid argument` → the app exited.  Fix:
     *       reassemble — prepend any partial held from a prior call (wl_txacc),
     *       forward only COMPLETE messages, and stash a new trailing partial. */
    static uint8_t local[64 * 1024];
    size_t plen = st->fds[fd].wl_txacc_len;                /* held partial, if any */
    if (plen + len > sizeof(local)) return -(int64_t)22;   /* EINVAL · batch too large (defer) */
    if (plen) memcpy(local, st->fds[fd].wl_txacc, plen);
    if (lucas_copy_from_client(st, (uintptr_t)base_vaddr, local + plen, (size_t)len) != 0)
        return -(int64_t)LX_EFAULT;
    st->fds[fd].wl_txacc_len = 0;                          /* consumed into local */
    uint64_t total = (uint64_t)plen + len;
    uint64_t off = 0;
    while (off < total) {
        if (off + 8 > total) break;                        /* partial header → hold below */
        uint32_t hdr; memcpy(&hdr, local + off + 4, 4);
        uint64_t msg_size = (uint64_t)(hdr >> 16);          /* total bytes incl 8B header */
        if (msg_size < 8 || (msg_size % 4) != 0) {
            printf("[wl] malformed wire · off=%llu msg_size=%llu total=%llu\n",
                   (unsigned long long)off, (unsigned long long)msg_size, (unsigned long long)total);
            return -(int64_t)22;                            /* EINVAL · genuinely malformed */
        }
        if (off + msg_size > total) break;                  /* partial body → hold below */
        /* forward the COMPLETE message straight from the reassembly buffer */
        int64_t rc = lucas_wayland_forward_ex(st, fd, 0, msg_size,
                                              NULL, 0, scm_fd, (const uint32_t *)(local + off));
        if (rc < 0) return rc;
        size_t rlen = st->fds[fd].wl_rx_len;                /* this message's reply */
        if (*acc_len + rlen > acc_cap) rlen = acc_cap - *acc_len;
        memcpy(acc + *acc_len, st->fds[fd].wl_rx, rlen);
        *acc_len += rlen;
        off += msg_size;
    }
    /* Hold any trailing partial message for the next sendmsg (reassembly). */
    if (off < total) {
        size_t rem = (size_t)(total - off);
        if (rem > sizeof(st->fds[fd].wl_txacc)) return -(int64_t)22;  /* >1 msg · cannot hold */
        memcpy(st->fds[fd].wl_txacc, local + off, rem);
        st->fds[fd].wl_txacc_len = (uint16_t)rem;
    }
    return (int64_t)len;   /* all bytes from this iov accepted (partial held) */
}

/* x86_64 struct iovec / struct msghdr (LUCAS-local copies). */
struct wl_iovec  { uint64_t iov_base; uint64_t iov_len; };
struct wl_msghdr { uint64_t msg_name; uint32_t msg_namelen; uint32_t _p0;
                   uint64_t msg_iov;  uint64_t msg_iovlen;
                   uint64_t msg_control; uint64_t msg_controllen;
                   int32_t  msg_flags; uint32_t _p1; };
struct wl_cmsghdr { uint64_t cmsg_len; int32_t cmsg_level; int32_t cmsg_type; };  /* 16B */
#define WL_IOV_MAX     1024
#define WL_SOL_SOCKET  1
#define WL_SCM_RIGHTS  1

/* ====================================================================== */
/* v2.7 · live wl_pointer input  (virtio-tablet → honest GTK client)      */
/* ====================================================================== */
/* The sotOs wayland transport is synchronous (client request → compositor
 * reply); there is no async push.  So input rides the client's next poll/read
 * of the wayland fd: when the cursor changes we synthesize REAL wl_pointer wire
 * events into wl_rx (iomux then reports the fd readable → libwayland reads +
 * dispatches them).  Pointer-only — keyboard needs a keymap fd we cannot pass
 * over seL4_Call.  Events are committed at POLL time (lucas_wl_try_stage_input
 * is called from iomux_fd_ready), so a polled-readable fd always has bytes to
 * read — no read()==0 EOF/disconnect race. */

extern int      mouse_state(int *x, int *y, int *btn);     /* orch virtio-tablet  */
extern uint8_t *gpu_fb(int *w, int *h, int *stride);       /* orch scanout dims   */

static uint32_t g_wl_input_serial = 0x5000;   /* monotonic event serial          */
static uint32_t g_wl_input_time   = 1;        /* monotonic ms-ish event timestamp */

/* Map the absolute screen cursor to this client's surface-local px (the window is
 * blitted CENTERED into the scanout).  Returns 1 + fills outs iff a pointer +
 * surface + window-dims + a live tablet are all known; else 0 (e.g. headless). */
static int wl_pointer_sample(lucas_fd_t *e, int *sx, int *sy, int *btn, int *inside)
{
    if (e->wl_pointer_obj_id == 0 || e->wl_surface_obj_id == 0
        || e->wl_win_w == 0 || e->wl_win_h == 0)
        return 0;
    int mx, my, mb;
    if (!mouse_state(&mx, &my, &mb)) return 0;     /* no virtio-tablet / headless */
    int gw = 0, gh = 0, gs = 0;
    if (!gpu_fb(&gw, &gh, &gs) || gw == 0 || gh == 0) return 0;
    int ox = (gw - (int)e->wl_win_w) / 2; if (ox < 0) ox = 0;
    int oy = (gh - (int)e->wl_win_h) / 2; if (oy < 0) oy = 0;
    int x = mx - ox, y = my - oy;
    *sx = x; *sy = y; *btn = mb;
    *inside = (x >= 0 && y >= 0 && x < (int)e->wl_win_w && y < (int)e->wl_win_h);
    return 1;
}

/* True iff a fresh pointer event is pending AND the input buffer is free to take
 * it.  Side-effect-free (the readiness predicate).  Staged input goes to wl_in,
 * but we only stage when wl_rx is ALSO empty so input is never spliced into the
 * middle of a partially-read compositor reply.  Honest clients only (tier < 2):
 * a Tier-2 canary client must never receive live host-pointer input. */
int lucas_wl_input_pending(lucas_state_t *st, lucas_fd_t *e)
{
    if (st->tier >= 2) return 0;                       /* live input · honest clients only */
    if (!e->wayland_connected) return 0;
    if (e->wl_in_cursor < e->wl_in_len) return 0;      /* staged input not yet drained   */
    if (e->wl_rx_cursor < e->wl_rx_len) return 0;      /* a compositor reply pending     */
    int sx, sy, btn, inside;
    if (!wl_pointer_sample(e, &sx, &sy, &btn, &inside)) return 0;
    if (inside != e->wl_ptr_entered) return 1;                  /* enter / leave  */
    if (inside && (sx != e->wl_ptr_x || sy != e->wl_ptr_y
                   || btn != e->wl_ptr_btn)) return 1;          /* motion / button */
    return 0;
}

/* Build the pending wl_pointer events into wl_in (real Wayland wire framing:
 * [obj][size_bytes<<16|opcode][args…], coords in wl_fixed 24.8).  Idempotent:
 * only fills when wl_in is empty + a change exists (so repeated poll-scan calls
 * stage at most one batch).  Returns 1 if it staged. */
int lucas_wl_try_stage_input(lucas_state_t *st, lucas_fd_t *e)
{
    if (!lucas_wl_input_pending(st, e)) return 0;
    int sx, sy, btn, inside;
    if (!wl_pointer_sample(e, &sx, &sy, &btn, &inside)) return 0;

    uint32_t w[24]; size_t n = 0;
    uint32_t ptr = e->wl_pointer_obj_id, surf = e->wl_surface_obj_id;
    uint32_t fxx = (uint32_t)((sx < 0 ? 0 : sx) << 8);   /* wl_fixed 24.8 */
    uint32_t fxy = (uint32_t)((sy < 0 ? 0 : sy) << 8);
    uint32_t t   = (g_wl_input_time += 16);

    if (inside && !e->wl_ptr_entered) {
        uint32_t s = ++g_wl_input_serial;
        w[n++]=ptr; w[n++]=(6u*4u<<16)|0; w[n++]=s; w[n++]=surf; w[n++]=fxx; w[n++]=fxy; /* enter  */
        w[n++]=ptr; w[n++]=(5u*4u<<16)|2; w[n++]=t; w[n++]=fxx; w[n++]=fxy;              /* motion */
        e->wl_ptr_entered = 1;
    } else if (!inside && e->wl_ptr_entered) {
        uint32_t s = ++g_wl_input_serial;
        w[n++]=ptr; w[n++]=(4u*4u<<16)|1; w[n++]=s; w[n++]=surf;                          /* leave  */
        e->wl_ptr_entered = 0;
    } else if (inside) {
        if (sx != e->wl_ptr_x || sy != e->wl_ptr_y) {
            w[n++]=ptr; w[n++]=(5u*4u<<16)|2; w[n++]=t; w[n++]=fxx; w[n++]=fxy;           /* motion */
        }
    }
    /* Button transition is staged in its OWN batch, decoupled from enter/motion:
     * a press that coincides with the pointer entering the surface (the first
     * inside-sample already has btn=1) must NOT be swallowed by the enter branch.
     * wl_ptr_btn is therefore only advanced once the press/release is actually
     * emitted (see below) — so the next poll still sees the pending transition. */
    int staged_btn = 0;
    if (e->wl_ptr_entered && n == 0 && (uint8_t)btn != e->wl_ptr_btn) {
        uint32_t s = ++g_wl_input_serial;
        w[n++]=ptr; w[n++]=(6u*4u<<16)|3; w[n++]=s; w[n++]=t;
        w[n++]=0x110u /* BTN_LEFT */; w[n++]=(btn ? 1u : 0u);                          /* button */
        staged_btn = 1;
    }
    if (n == 0) return 0;
    w[n++]=ptr; w[n++]=(2u*4u<<16)|5;   /* wl_pointer.frame · ends the event group */

    e->wl_ptr_x = (int16_t)sx; e->wl_ptr_y = (int16_t)sy;
    if (staged_btn) e->wl_ptr_btn = (uint8_t)btn;   /* advance btn only when its edge was delivered */

    size_t bytes = n * 4;
    if (bytes > sizeof e->wl_in) bytes = sizeof e->wl_in;   /* guard · real max 52B */
    memcpy(e->wl_in, w, bytes);
    e->wl_in_len    = (uint16_t)bytes;
    e->wl_in_cursor = 0;
    return 1;
}

int64_t lucas_wayland_drain(lucas_state_t *st, uint64_t fd,
                            uint64_t buf_vaddr, uint64_t count)
{
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET
        || !st->fds[fd].wayland_connected)
        return -(int64_t)LX_EBADF;

    lucas_fd_t *e = &st->fds[fd];
    /* Compositor replies (wl_rx) take priority and are read to completion before
     * any synthesized input (wl_in) — input is never spliced into a partial reply.
     * When wl_rx is drained, deliver staged input (staging fresh if none pending). */
    const uint8_t *src; size_t avail;
    if (e->wl_rx_cursor < e->wl_rx_len) {
        src = &e->wl_rx[e->wl_rx_cursor];
        avail = (size_t)(e->wl_rx_len - e->wl_rx_cursor);
    } else {
        if (e->wl_in_cursor >= e->wl_in_len)
            lucas_wl_try_stage_input(st, e);   /* v2.7 · pull pending pointer input */
        if (e->wl_in_cursor >= e->wl_in_len)
            return 0;   /* EOF · nothing pending */
        src = &e->wl_in[e->wl_in_cursor];
        avail = (size_t)(e->wl_in_len - e->wl_in_cursor);
    }
    size_t n = (count < avail) ? (size_t)count : avail;
    if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, src, n) != 0)
        return -(int64_t)LX_EFAULT;
    if (e->wl_rx_cursor < e->wl_rx_len) e->wl_rx_cursor += (uint16_t)n;
    else                                e->wl_in_cursor += (uint16_t)n;
    return (int64_t)n;
}

/* ------------------------------------------------------------------ */
/* sendto() · sotNet-β-4 · routes UDP through the sotnet stack.        */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_sendto(lucas_state_t *st,
                          uint64_t fd, uint64_t buf_vaddr, uint64_t len,
                          uint64_t flags, uint64_t dest_vaddr, uint64_t dest_len)
{
    (void)flags; (void)dest_len;

    /* apt-T7 · AF_NETLINK route socket · glibc getaddrinfo's RTM_GETADDR dump.
     * Local interface enumeration · never touches the wire (handled before the
     * silenced/egress gates). */
    if (fd < LUCAS_MAX_FDS && st->fds[fd].kind == LUCAS_FD_SOCKET &&
        st->fds[fd].is_netlink) {
        uint8_t kb[256];
        size_t n = len < sizeof(kb) ? (size_t)len : sizeof(kb);
        if (n && lucas_copy_from_client(st, (uintptr_t)buf_vaddr, kb, n) != 0)
            return -(int64_t)LX_EFAULT;
        return netlink_handle_send(st, (int)fd, kb, n);
    }

    /* Silenced Connection · sotNet-γ Phase 1.  Bytes never reach wire.
     * TIER1-REVOKE-GATES · also bump cap_revoke_count so the operator
     * counter reflects this denial; the silent-drop semantics + the
     * silenced_drops anomaly are preserved for backward compat. */
    if (st->functor && st->functor->writes_silenced) {
        extern void sotnet_record_silenced_drop(uint32_t pid, uint32_t len);
        sotnet_record_silenced_drop(st->synthetic_pid, (uint32_t)len);
        st->cap_revoke_count++;
        printf("[silenced-net] pid=%d tier=1 · sendto fd=%lu len=%lu silently dropped (Silenced Connection · cap_revokes=%u)\n",
               st->synthetic_pid, (unsigned long)fd, (unsigned long)len,
               (unsigned int)st->cap_revoke_count);
        return (int64_t)len;   /* synthetic success */
    }

    /* apk-network-install C1 · a connected STREAM (TCP) socket send.  apk's HTTP
     * client sends its `GET … HTTP/1.1` via sendto(fd, …, NULL, 0) (a connected
     * send), NOT write() — so it never reaches lucas_tcp_send the way curl/pip do.
     * Route a real-wire caller (Tier-0e egress OR the interactive SSH attacker
     * session) to the real tcp_send path so the bytes go on the wire to the real
     * CDN.  Isolated non-real-wire sessions fall through to the synth redirect
     * below (deception · contained).  DNS (UDP:53) is not STREAM, so it is
     * unaffected and keeps its real-forward / canary handling. */
    if (lucas_real_wire(st) && fd < LUCAS_MAX_FDS &&
        st->fds[fd].kind == LUCAS_FD_SOCKET) {
        int stype = lucas_socket_type(st, fd);
        if (stype >= 0 && (stype & LUCAS_SOCK_TYPEMASK) == LUCAS_SOCK_STREAM) {
            return lucas_tcp_send(st, fd, buf_vaddr, len);
        }
    }

    if (st->functor && st->functor->is_isolated) {
        /* Peek at the destination port early · DNS UDP queries (dest
         * port 53) must NOT be synth-redirected.  sotnet's DNS
         * subsystem (sotNet-ε) intercepts them downstream and returns
         * the canary IP for known domains, which is the operator-visible
         * narrative for Stage 5.  Synth redirect is the wrong layer
         * for DNS because the synth server doesn't parse the DNS
         * query · it would just synthesize an opaque ACK that gives the
         * malware "Try again" (no response packet on the read side).
         * Let DNS fall through to the real sotnet path. */
        uint32_t dst_ip_be   = 0;
        uint16_t dst_port_be = 0;
        if (dest_vaddr != 0) {
            struct sockaddr_in_min {
                uint16_t family, port_be;
                uint32_t addr_be;
            } __attribute__((packed)) sa;
            memset(&sa, 0, sizeof(sa));
            if (lucas_copy_from_client(st, (uintptr_t)dest_vaddr,
                                       &sa, sizeof(sa)) == 0) {
                dst_ip_be   = sa.addr_be;
                dst_port_be = sa.port_be;
            }
        } else if (fd < LUCAS_MAX_FDS) {
            /* γ-3-γ-2b · connected send() (no dest) · use the connect() peer
             * cached on the fd, so a TLS client's stream send routes to c2p. */
            dst_ip_be   = st->fds[fd].connect_peer_ip_be;
            dst_port_be = (uint16_t)st->fds[fd].connect_peer_port_be;
        }
        uint16_t dst_port_h = (uint16_t)(((dst_port_be & 0xFF) << 8) |
                                         ((dst_port_be >> 8) & 0xFF));
        if (dst_port_h != 53) {
            /* isolated-write path · sotNet-γ Phase 2/3 · N-SYNTH.
             * Bytes are diverted to the synth server.  Return
             * synthetic full-byte-count success without wire egress. */
            /* γ-3-γ-1 · copy the real payload and push it into the c2p ring so
             * the responder sees the exact bytes (not just the length).  Falls
             * back silently to the metadata-only doorbell when the byte channel
             * is disabled. */
            if (orch_bytepipe_ready()) {
                static uint8_t redir_payload[BYTEPIPE_DATA_BYTES];
                uint32_t plen = (uint32_t)len;
                if (plen > BYTEPIPE_DATA_BYTES) plen = BYTEPIPE_DATA_BYTES;
                if (plen && buf_vaddr &&
                    lucas_copy_from_client(st, (uintptr_t)buf_vaddr,
                                           redir_payload, plen) == 0) {
                    bytepipe_ring_t *c2p = (bytepipe_ring_t *)BYTEPIPE_C2P_VADDR;
                    uint32_t pushed = bytepipe_push(c2p, redir_payload, plen);
                    printf("[sotnet-γ] c2p tx · pid=%d pushed=%u bytes\n",
                           st->synthetic_pid, pushed);
                }
            }

            extern void synth_record_redirect(uint32_t, uint32_t,
                                                uint16_t, uint32_t);
            synth_record_redirect((uint32_t)st->synthetic_pid,
                                    dst_ip_be, dst_port_be, (uint32_t)len);
            printf("[synth-srv] pid=%d sendto fd=%lu len=%lu (synthetic ack · no wire egress)\n",
                   st->synthetic_pid, (unsigned long)fd, (unsigned long)len);

            /* α · PR 4 · mirror the synth redirect to the sotfs WAL
             * so a simreboot can replay the deception event timeline.
             * Direct in-process call · gated by orch's g_wal_attached.
             * src_slot uses procd_slot when bound (PR 10 path) and
             * falls back to synthetic_pid when procd hasn't seen this sotbox
             * yet · keeps the WAL evidence usable on either path. */
            if (g_wal_attached) {
                sotfs_wal_payload_sotnet_synth_t rec = {
                    .src_slot         = (st->procd_slot != 0)
                                          ? st->procd_slot
                                          : (uint32_t)st->synthetic_pid,
                    .dst_ip_be        = dst_ip_be,
                    .dst_port_be      = dst_port_be,
                    .bytes_redirected = (uint32_t)len,
                };
                (void)sotfs_wal_log_sotnet_synth(&rec);
            }
            return (int64_t)len;
        }
        /* else: DNS · fall through to sotnet UDP / DNS subsystem. */
    }

    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    /* dest sockaddr_in layout: {u16 sin_family(2); u16 sin_port(BE); u32 sin_addr(BE); u8 pad[8]} */
    struct {
        uint16_t family;
        uint16_t port_be;
        uint32_t addr_be;
    } __attribute__((packed)) sa;
    memset(&sa, 0, sizeof(sa));

    /* CONNECTED UDP · glibc's resolver connect()s the DNS socket to the nameserver
     * then send()s the query with NO dest addr.  Synthesize the dest from the
     * connect peer cached on the fd (γ-3-γ-2b) so the query FORWARDS instead of
     * dropping — without this glibc getaddrinfo times out and apt Ign's the index.
     * musl uses sendto-with-dest and takes the else branch. */
    if (dest_vaddr == 0) {
        if (fd >= LUCAS_MAX_FDS || st->fds[fd].connect_peer_ip_be == 0) {
            printf("[sotnet-β] pid=%d sendto(fd=%lu, len=%lu) · no dest + no connect peer · drop\n",
                   st->synthetic_pid, (unsigned long)fd, (unsigned long)len);
            return (int64_t)len;
        }
        sa.family  = 2; /* AF_INET */
        sa.port_be = (uint16_t)st->fds[fd].connect_peer_port_be;
        sa.addr_be = st->fds[fd].connect_peer_ip_be;
        printf("[sotnet-β] pid=%d sendto(fd=%lu len=%lu) · connected UDP · dest from peer %u.%u.%u.%u:%u\n",
               st->synthetic_pid, (unsigned long)fd, (unsigned long)len,
               (sa.addr_be) & 0xFF, (sa.addr_be >> 8) & 0xFF,
               (sa.addr_be >> 16) & 0xFF, (sa.addr_be >> 24) & 0xFF,
               (unsigned)(((sa.port_be & 0xFF) << 8) | ((sa.port_be >> 8) & 0xFF)));
    } else if (lucas_copy_from_client(st, (uintptr_t)dest_vaddr, &sa, sizeof(sa)) != 0) {
        return -(int64_t)LX_EFAULT;
    }

    if (sa.family != 2 /* AF_INET */) {
        printf("[sotnet-β] pid=%d sendto(fd=%lu) · non-INET family=%u · drop\n",
               st->synthetic_pid, (unsigned long)fd, (unsigned int)sa.family);
        return (int64_t)len;
    }

    /* Copy payload from client (cap at 1400 bytes). */
    if (len > 1400) len = 1400;
    static uint8_t udp_payload[1400];
    if (lucas_copy_from_client(st, (uintptr_t)buf_vaddr, udp_payload, (size_t)len) != 0)
        return -(int64_t)LX_EFAULT;

    /* DNS-SOTBOX-INTERCEPT · UDP:53 hook · parse the query, look up the
     * canary table, synthesize a synth DNS A-record reply, and inject it
     * into the sotbox's recvfrom queue.  Malware sees a normal DNS
     * response · the operator sees the ANOMALY_EV_DNS_HIT event which
     * (via the v0.16.0 dormant rule with pid>=1 gate) auto-promotes the
     * caller to Tier-2.  Subsequent traffic to the answered IP routes to
     * synth.  Non-canary domain / parse failure: fall through to
     * sotnet_send_udp (anomaly pre-commit may still fire).
     *
     * Min DNS query = 12-byte header + 1-byte qname (root) + 4-byte
     * QTYPE+QCLASS = 17 bytes. */
    if (sa.port_be == net_htons(53) && len >= 17) {
        char domain[64];
        int qname_consumed = dns_parse_qname(udp_payload, (size_t)len,
                                              12, domain, sizeof(domain));
        if (qname_consumed > 0) {
            uint32_t answer_ip_be = 0;
            /* Quiet table lookup · enqueue the synth reply + print FIRST so the
             * probe's recvfrom is unblocked, THEN emit the audit side effects.
             * dns_lookup_audit does a synchronous seL4_Call to orch's anomaly EP;
             * deferring it until after the enqueue keeps the DNS reply delivery
             * independent of that Call (which otherwise stalled the data path
             * when orch was captive in the demo fault-loop). */
            if (dns_lookup_quiet(domain, &answer_ip_be) == 0) {
                static uint8_t resp_buf[256];
                size_t rlen = dns_synth_a_response(
                    udp_payload, (size_t)len, answer_ip_be,
                    resp_buf, sizeof(resp_buf));
                if (rlen > 0) {
                    uint8_t src_ip[4];
                    memcpy(src_ip, &sa.addr_be, 4);
                    sotnet_recv_enqueue((uint32_t)st->synthetic_pid,
                                         src_ip, net_htons(53),
                                         resp_buf, rlen);
                    printf("[dns-intercept] pid=%d · %s -> 0x%08x (synthetic, %zu B)\n",
                           st->synthetic_pid, domain,
                           (unsigned int)net_ntohl(answer_ip_be), rlen);
                    dns_lookup_audit((uint32_t)st->synthetic_pid, domain,
                                     answer_ip_be);
                    return (int64_t)len;
                }
            }
            /* EGRESS Phase 1 · non-canary domain + Tier-0e → forward to the REAL
             * nameserver (1.1.1.1) over SLIRP and inject the real answer. AAAA
             * (0x001c) → empty NOERROR so the resolver uses the A record (no IPv6
             * egress this phase). A (0x0001) → real forward. Non-egress callers
             * skip this entirely and keep the existing fall-through behaviour. */
            if (lucas_real_wire(st)) {
                uint16_t qtype = dns_query_qtype(udp_payload, (size_t)len, qname_consumed);
                static uint8_t fwd_buf[512];  /* truncates at 512B; oversized answers fall through */
                uint8_t src_ip[4]; memcpy(src_ip, &sa.addr_be, 4);
                if (qtype == 0x001c) {              /* AAAA → empty NOERROR */
                    size_t rlen = dns_synth_empty_noerror(udp_payload, (size_t)len,
                                                          fwd_buf, sizeof(fwd_buf));
                    if (rlen > 0) {
                        sotnet_recv_enqueue((uint32_t)st->synthetic_pid,
                                            src_ip, net_htons(53), fwd_buf, rlen);
                        printf("[dns-egress] pid=%d · %s AAAA -> empty NOERROR\n",
                               st->synthetic_pid, domain);
                        return (int64_t)len;
                    }
                } else if (qtype != 0) {            /* A, MX, TXT, and other non-AAAA qtypes → forward */
                    size_t rlen = dns_forward_query(udp_payload, (size_t)len,
                                                    (uint32_t)st->synthetic_pid,
                                                    fwd_buf, sizeof(fwd_buf));
                    if (rlen > 0) {
                        sotnet_recv_enqueue((uint32_t)st->synthetic_pid,
                                            src_ip, net_htons(53), fwd_buf, rlen);
                        printf("[dns-egress] pid=%d · %s -> forwarded (%zu B real answer)\n",
                               st->synthetic_pid, domain, rlen);
                        return (int64_t)len;
                    }
                    printf("[dns-egress] pid=%d · %s -> forward TIMEOUT/empty\n",
                           st->synthetic_pid, domain);
                    /* No real answer (no egress connectivity).  Enqueue an empty
                     * NOERROR so the caller's recvfrom RETURNS instead of parking
                     * forever — otherwise a hermetic (no-internet) boot would
                     * wedge the orch demo driver on this leg.  With live egress
                     * the real answer above is enqueued first and this is never
                     * reached. */
                    {
                        static uint8_t empty_buf[512];
                        size_t elen = dns_synth_empty_noerror(udp_payload,
                                                              (size_t)len,
                                                              empty_buf,
                                                              sizeof(empty_buf));
                        if (elen > 0) {
                            sotnet_recv_enqueue((uint32_t)st->synthetic_pid,
                                                src_ip, net_htons(53),
                                                empty_buf, elen);
                            return (int64_t)len;
                        }
                    }
                    /* fall through → sotnet_send_udp (best-effort) */
                }
            }
        }
        /* Non-canary domain or parse failure: fall through to
         * sotnet_send_udp (anomaly pre-commit may still fire). */
    }

    sotnet_send_udp(sa.addr_be, sa.port_be,
                    net_htons(1024), udp_payload, (size_t)len,
                    (uint32_t)st->synthetic_pid);
    return (int64_t)len;
}

/* ------------------------------------------------------------------ */
/* recvfrom() · sotNet-δ-1 · consume sotnet_recv_dequeue (synth RX). */
/* Linux signature:                                                    */
/*   ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,    */
/*                   struct sockaddr *src_addr, socklen_t *addrlen);   */
/*                                                                     */
/* BG2 · blocking semantics: when no payload is queued for this pid    */
/* and the caller did NOT pass MSG_DONTWAIT, we SaveCaller and park    */
/* the sotbox in SOTBOX_STATE_WAITING_FOR_RECV.  The wake-up hook      */
/* below (lucas_recv_wake_waiter) is called from sotnet_recv_enqueue   */
/* when a synth response lands · it drains the queue into the parked */
/* sotbox's vspace and Sends to the saved reply cap.                   */
/* ------------------------------------------------------------------ */

/* recvfrom_deliver: shared between the in-syscall fast path and the
 * deferred wake-up.  Drains one pending entry for `st->synthetic_pid` into
 * the caller's user buffer + src sockaddr.  Returns:
 *   >=0  · bytes delivered (success)
 *   -1   · no pending entry for this pid (caller should retry / park)
 *   -EFAULT/-EBADF style negative errno on copy failure
 *
 * On a -EFAULT path the queue slot has already been consumed (matches
 * existing pre-BG2 behaviour); we surface the errno so the caller can
 * still return a coherent syscall result. */
static int64_t recvfrom_deliver(lucas_state_t *st,
                                 uintptr_t buf_vaddr, size_t buf_size,
                                 uintptr_t addr_vaddr,
                                 uintptr_t addrlen_vaddr,
                                 uint32_t want_ip_be)
{
    /* γ-3-γ-2b · TLS/stream mode: a Tier-2 (shadow) sotbox's recv drains the
     * p2c ring directly — multi-KB, partial reads, no 256-byte queue cap, no
     * one-shot EOF.  When the ring is momentarily empty we SPIN-WITH-YIELD:
     * seL4_Yield() lets the equal-priority responder run (it processes the
     * client's flight and fills p2c), then we re-drain.  This is required
     * because orch services this recv inside orch_fault_loop (blocking on the
     * fault EP) — it would NOT reach its main loop to drain p2c / wake a parked
     * waiter, so a classic park here would deadlock.  Yield is cooperative (no
     * busy-spin · returns to us once the responder blocks again).  Bounded:
     * on timeout we return 0 (EOF) so the client fails gracefully, never hangs
     * the boot. */
    /* DNS-intercept (and any sotnet_recv_enqueue'd synth UDP reply) lands in the
     * per-pid g_recv_queue, NOT the p2c byte-pipe ring.  Drain that queue FIRST
     * so a queued datagram (e.g. the UDP:53 canary answer) is delivered even
     * when the byte-pipe is "ready" — otherwise the p2c-stream path below spins
     * on the empty ring and returns EOF, dropping the queued reply. */
    {
        uint8_t  q_ip[4]   = { 0, 0, 0, 0 };
        uint16_t q_port_be = 0;
        uint8_t  qbuf[512];
        size_t   qcap = buf_size < sizeof(qbuf) ? buf_size : sizeof(qbuf);
        int qgot = sotnet_recv_dequeue(st->synthetic_pid, want_ip_be, qbuf, qcap, q_ip, &q_port_be);
        if (qgot >= 0) {
            size_t out_len = (size_t)qgot;
            if (out_len > qcap) out_len = qcap;
            if (out_len && buf_vaddr &&
                lucas_copy_to_client(st, buf_vaddr, qbuf, out_len) != 0)
                return -(int64_t)LX_EFAULT;
            if (addr_vaddr && addrlen_vaddr) {
                struct { uint16_t family, port_be; uint32_t addr_be; uint8_t pad[8]; }
                    __attribute__((packed)) sa;
                memset(&sa, 0, sizeof sa);
                sa.family  = 2;
                sa.port_be = q_port_be;
                sa.addr_be = ((uint32_t)q_ip[0]) | ((uint32_t)q_ip[1] << 8) |
                             ((uint32_t)q_ip[2] << 16) | ((uint32_t)q_ip[3] << 24);
                uint32_t ualen = sizeof sa;
                (void)lucas_copy_from_client(st, addrlen_vaddr, &ualen, sizeof ualen);
                uint32_t wl = ualen < sizeof sa ? ualen : sizeof sa;
                if (wl) (void)lucas_copy_to_client(st, addr_vaddr, &sa, wl);
                uint32_t act = sizeof sa;
                (void)lucas_copy_to_client(st, addrlen_vaddr, &act, sizeof act);
            }
            printf("[recvfrom] pid=%d delivered %zu bytes from %u.%u.%u.%u:%u (queue)\n",
                   st->synthetic_pid, out_len, q_ip[0], q_ip[1], q_ip[2], q_ip[3],
                   (uint16_t)(((q_port_be & 0xFF) << 8) | ((q_port_be >> 8) & 0xFF)));
            return (int64_t)out_len;
        }
    }

    {
        extern int      orch_bytepipe_ready(void);
        extern uint32_t orch_bytepipe_p2c_pull(uint8_t *dst, uint32_t max);
        /* The p2c byte-pipe is the SYNTH network responder, used only by
         * automated Tier-2 sotboxes (cow_session == 0).  An interactive
         * real-wire session (cow_session != 0 · the honey SSH attacker, apt's
         * egress http method) does REAL recv on its sockets — draining the
         * real RX queue or parking — and must NOT be captured by the synth
         * stream branch, which would hand it a spurious EOF and break a live
         * DNS / HTTP exchange.  Mirrors is_synth_redirected()'s cow_session
         * guard (recvfrom_deliver has no fd to call it directly). */
        if (st->cow_session == 0 &&
            st->functor && st->functor->is_isolated && orch_bytepipe_ready()) {
            static uint8_t sbuf[8192];
            uint32_t scap = (buf_size < sizeof(sbuf)) ? (uint32_t)buf_size
                                                      : (uint32_t)sizeof(sbuf);
            uint32_t got = 0;
            for (int spin = 0; spin < 1000000; spin++) {
                got = orch_bytepipe_p2c_pull(sbuf, scap);
                if (got > 0) break;
                seL4_Yield();  /* let the responder run + fill p2c */
            }
            if (got == 0) {
                printf("[tls-net] pid=%d recv · p2c idle after spin · EOF\n",
                       st->synthetic_pid);
                return 0;      /* graceful EOF · client fails, no boot hang */
            }
            if (buf_vaddr && lucas_copy_to_client(st, buf_vaddr, sbuf, got) != 0)
                return -(int64_t)LX_EFAULT;
            if (addr_vaddr && addrlen_vaddr) {
                struct { uint16_t family, port_be; uint32_t addr_be; uint8_t pad[8]; }
                    __attribute__((packed)) sa;
                memset(&sa, 0, sizeof sa); sa.family = 2;
                uint32_t ualen = sizeof sa;
                (void)lucas_copy_from_client(st, addrlen_vaddr, &ualen, sizeof ualen);
                uint32_t wl = ualen < sizeof sa ? ualen : sizeof sa;
                if (wl) (void)lucas_copy_to_client(st, addr_vaddr, &sa, wl);
                uint32_t act = sizeof sa;
                (void)lucas_copy_to_client(st, addrlen_vaddr, &act, sizeof act);
            }
            printf("[tls-net] pid=%d recv · %u B from p2c (stream)\n",
                   st->synthetic_pid, got);
            return (int64_t)got;
        }
    }

    /* Bounded kernel scratch buffer · 512B is enough for synth-tier
     * synthetic UDP replies (SOTNET_RECV_BODY_MAX = 256 currently). */
    uint8_t kbuf[512];
    size_t cap = buf_size;
    if (cap > sizeof(kbuf)) cap = sizeof(kbuf);

    uint8_t  src_ip[4]   = { 0, 0, 0, 0 };
    uint16_t src_port_be = 0;

    int got = sotnet_recv_dequeue(st->synthetic_pid, want_ip_be, kbuf, cap, src_ip, &src_port_be);
    if (got < 0) {
        return -1;  /* no pending */
    }

    /* Body length actually delivered is min(orig_len, cap).  dequeue
     * returns the original body length, so clamp to cap for copy-out. */
    size_t out_len = (size_t)got;
    if (out_len > cap) out_len = cap;

    if (out_len && buf_vaddr) {
        if (lucas_copy_to_client(st, buf_vaddr, kbuf, out_len) != 0)
            return -(int64_t)LX_EFAULT;
    }

    /* Fill src sockaddr_in if caller asked for it. */
    if (addr_vaddr && addrlen_vaddr) {
        struct {
            uint16_t family;
            uint16_t port_be;
            uint32_t addr_be;
            uint8_t  pad[8];
        } __attribute__((packed)) sa;
        memset(&sa, 0, sizeof(sa));
        sa.family  = 2;  /* AF_INET */
        sa.port_be = src_port_be;
        sa.addr_be = ((uint32_t)src_ip[0]      ) |
                     ((uint32_t)src_ip[1] <<  8) |
                     ((uint32_t)src_ip[2] << 16) |
                     ((uint32_t)src_ip[3] << 24);

        /* Read caller-provided buffer capacity; clamp our write. */
        uint32_t user_alen = sizeof(sa);
        (void)lucas_copy_from_client(st, addrlen_vaddr,
                                     &user_alen, sizeof(user_alen));
        uint32_t write_len = user_alen < sizeof(sa) ? user_alen : sizeof(sa);
        if (write_len && lucas_copy_to_client(st, addr_vaddr,
                                              &sa, write_len) != 0)
            return -(int64_t)LX_EFAULT;
        uint32_t actual = sizeof(sa);
        (void)lucas_copy_to_client(st, addrlen_vaddr,
                                   &actual, sizeof(actual));
    }

    uint16_t port_host = (uint16_t)(((src_port_be & 0xFF) << 8) |
                                    ((src_port_be >> 8) & 0xFF));
    printf("[recvfrom] pid=%d delivered %zu bytes from %u.%u.%u.%u:%u\n",
           st->synthetic_pid, out_len,
           src_ip[0], src_ip[1], src_ip[2], src_ip[3], port_host);
    return (int64_t)out_len;
}

int64_t lucas_sys_recvfrom(lucas_state_t *st,
                            uint64_t fd, uint64_t buf_vaddr, uint64_t buf_size,
                            uint64_t flags, uint64_t addr_vaddr,
                            uint64_t addrlen_vaddr)
{
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    /* apt-T7 · AF_NETLINK route socket · deliver the queued RTM_GETADDR reply. */
    if (st->fds[fd].is_netlink) {
        return netlink_handle_recv(st, (int)fd, (uintptr_t)buf_vaddr,
                                   (size_t)buf_size, flags);
    }

    /* MSG_DONTWAIT = 0x40 on Linux x86_64. */
    const uint64_t MSG_DONTWAIT = 0x40;
    int nonblock = (flags & MSG_DONTWAIT) ? 1 : 0;

    /* SOCKET DEMUX · lwIP-backed egress fd → recv from the mature stack.  curl/wget
     * read the response via recvfrom() (NOT read()), so without this the recv falls
     * through to the δ stack and parks forever (the data is on lwIP).  Honour
     * MSG_DONTWAIT + the fd's O_NONBLOCK. */
    if (st->fds[fd].lwip_sess != NULL) {
        extern int64_t orch_lwip_egress_recv(void *handle, uint8_t *buf, uint32_t len, int nb);
        static uint8_t lwrxb[TCP_TX_BUF_SIZE];
        size_t want = (buf_size < TCP_TX_BUF_SIZE) ? (size_t)buf_size : TCP_TX_BUF_SIZE;
        int nb = nonblock || ((st->fds[fd].flags & 0x800) != 0);
        int64_t got = orch_lwip_egress_recv(st->fds[fd].lwip_sess, lwrxb, (uint32_t)want, nb);
        if (got == -11) return -(int64_t)LX_EAGAIN;
        if (got <= 0) return got;
        if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, lwrxb, (size_t)got) != 0)
            return -(int64_t)LX_EFAULT;
        return got;
    }

    /* N-SYNTH · synth-redirected fd · synthesize an HTTP 200 OK
     * reply on the FIRST recv, then return 0 (EOF) on subsequent calls so
     * Python's recv-loop terminates cleanly.  Bypasses the recvfrom_deliver
     * queue and the BG2 park path entirely · the synthesized reply lives
     * in a static const ROM string with no IPC round-trip required.
     *
     * Bounded by buf_size (caller's buffer capacity).  Source address is
     * not filled when caller passes addr_vaddr=0 (Python's `recv` always
     * does); if non-zero we synthesize a plausible peer sockaddr_in
     * (the connect-time peer · zeroed for now since N-CONNECT owns the
     * fd↔peer mapping). */
    /* POSIX · recv with a 0-size buffer returns 0 without consuming. */
    if (is_synth_redirected(st, fd) && buf_size == 0) {
        return 0;
    }
    /* γ-3-γ-2b · STREAM MODE (byte-pipe on): skip the legacy one-shot
     * HTTP-stub / 256-queue / EOF path entirely and fall through to the
     * normal recvfrom_deliver→park flow below, which drains the p2c ring as a
     * stream (multi-KB · partial reads · no one-shot EOF · block-on-empty).
     * The legacy block runs ONLY when the byte channel is disabled. */
    if (is_synth_redirected(st, fd) && !orch_bytepipe_ready()) {
        if (st->fds[fd].synth_recv_consumed) {
            /* Subsequent recv → 0 (EOF).  Lets `c2.recv(1024)` loops
             * terminate after the single ACK without spinning. */
            printf("[synth-srv] pid=%d recv fd=%lu · EOF (already consumed)\n",
                   st->synthetic_pid, (unsigned long)fd);
            return 0;
        }
        /* γ-3-γ-1 · prefer a real ring-fed reply if the responder pushed one
         * for this pid (delivered into the pending_recv queue via the p2c
         * drain).  Falls through to the static stub when the queue is empty,
         * preserving the existing single-ACK demo behavior. */
        {
            int64_t qr = recvfrom_deliver(st, (uintptr_t)buf_vaddr,
                                          (size_t)buf_size,
                                          (uintptr_t)addr_vaddr,
                                          (uintptr_t)addrlen_vaddr,
                                          st->fds[fd].connect_peer_ip_be);
            if (qr != -1) {
                st->fds[fd].synth_recv_consumed = 1;
                printf("[synth-srv] pid=%d recv fd=%lu · %lld B (ring-fed reply)\n",
                       st->synthetic_pid, (unsigned long)fd, (long long)qr);
                return qr;
            }
        }
        size_t reply_len = sizeof(SYNTH_HTTP_REPLY) - 1;  /* strip NUL */
        size_t out_len   = (buf_size < reply_len) ? (size_t)buf_size : reply_len;
        if (out_len && buf_vaddr) {
            if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr,
                                     SYNTH_HTTP_REPLY, out_len) != 0)
                return -(int64_t)LX_EFAULT;
        }
        /* Fill peer sockaddr_in (0.0.0.0:0 placeholder) if caller asked. */
        if (addr_vaddr && addrlen_vaddr) {
            struct {
                uint16_t family;
                uint16_t port_be;
                uint32_t addr_be;
                uint8_t  pad[8];
            } __attribute__((packed)) sa;
            memset(&sa, 0, sizeof(sa));
            sa.family = 2;  /* AF_INET */
            uint32_t user_alen = sizeof(sa);
            (void)lucas_copy_from_client(st, (uintptr_t)addrlen_vaddr,
                                         &user_alen, sizeof(user_alen));
            uint32_t write_len = user_alen < sizeof(sa) ? user_alen : sizeof(sa);
            if (write_len && lucas_copy_to_client(st, (uintptr_t)addr_vaddr,
                                                  &sa, write_len) != 0)
                return -(int64_t)LX_EFAULT;
            uint32_t actual = sizeof(sa);
            (void)lucas_copy_to_client(st, (uintptr_t)addrlen_vaddr,
                                       &actual, sizeof(actual));
        }
        st->fds[fd].synth_recv_consumed = 1;
        printf("[synth-srv] pid=%d recv fd=%lu · HTTP/1.1 200 OK (%zu B synthetic)\n",
               st->synthetic_pid, (unsigned long)fd, out_len);
        return (int64_t)out_len;
    }

    int64_t r = recvfrom_deliver(st,
                                  (uintptr_t)buf_vaddr, (size_t)buf_size,
                                  (uintptr_t)addr_vaddr,
                                  (uintptr_t)addrlen_vaddr,
                                  st->fds[fd].connect_peer_ip_be);
    if (r != -1) {
        /* Fast path: either delivered bytes or a copy-fault errno. */
        return r;
    }

    /* No pending recv for this pid. */
    if (nonblock) {
        printf("[sotnet-δ] pid=%d recvfrom(fd=%lu) · no pending · -EAGAIN\n",
               st->synthetic_pid, (unsigned long)fd);
        return -(int64_t)11;  /* EAGAIN */
    }

    /* BG2 · blocking recvfrom: park the sotbox.  SaveCaller mirrors the
     * pattern in src/orch/pipe.c (pipe_read parking) · the wake-up path
     * Sends to this cap once a synth response lands. */
    seL4_CPtr cslot;
    if (vka_cspace_alloc(st->vka, &cslot) != 0) {
        printf("[sotnet-δ] pid=%d recvfrom park · vka_cspace_alloc FAILED · -EAGAIN\n",
               st->synthetic_pid);
        return -(int64_t)11;  /* EAGAIN · best-effort fall back */
    }
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, cslot, &cpath);
    int err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
    if (err) {
        vka_cspace_free(st->vka, cslot);
        printf("[sotnet-δ] pid=%d recvfrom park · SaveCaller FAILED (err=%d) · -EAGAIN\n",
               st->synthetic_pid, err);
        return -(int64_t)11;
    }

    st->waiting_reply_cap         = cslot;
    st->waiting_recv_fd           = (int)fd;
    st->waiting_recv_buf_vaddr    = (uintptr_t)buf_vaddr;
    st->waiting_recv_buf_size     = (size_t)buf_size;
    st->waiting_recv_addr_vaddr   = (uintptr_t)addr_vaddr;
    st->waiting_recv_addrlen_vaddr = (uintptr_t)addrlen_vaddr;
    st->state                     = SOTBOX_STATE_WAITING_FOR_RECV;
    printf("[sotnet-δ] PARK recvfrom pid=%d fd=%lu buf_size=%lu cslot=%lu\n",
           st->synthetic_pid, (unsigned long)fd, (unsigned long)buf_size,
           (unsigned long)cslot);
    return LUCAS_WAIT4_DEFERRED;
}

/* ------------------------------------------------------------------ */
/* BG2 · wake-up hook · called by sotnet_recv_enqueue when a payload   */
/* lands for `pid`.  If a sotbox is parked in WAITING_FOR_RECV with    */
/* matching synthetic_pid, drain one queue entry into its vspace and Send   */
/* to the saved reply cap.  No-op if no parked waiter matches.         */
/*                                                                     */
/* Returns 1 if a waiter was woken, 0 otherwise.                       */
/* ------------------------------------------------------------------ */
extern lucas_state_t *sotbox_get_slot(int i);
#ifndef SOTBOX_MAX_SLOTS
#define SOTBOX_MAX_SLOTS 8  /* fall-back · matches include/orch/sotbox.h */
#endif

/* host-CPU-yield gate · TRUE iff some sotbox is parked in WAITING_FOR_RECV (a
 * blocking recvfrom on the wire — glibc's DNS answer or apt's HTTP body).  The
 * orch idle loop (main.c op==0) emits a paced UART write (the only real host-CPU
 * yield under -enable-kvm · demo-ssh-watch) ONLY while this holds, so true-idle
 * stays quiet but a parked inbound-waiter gets QEMU's iothread scheduled to DMA
 * the packet into the RX ring + fire the recv-wake.  Covers the recvfrom-PARK
 * path the egress pump (poll) + the connect spin (SYN-ACK) do not.  Cheap: one
 * state field per slot, and self-limiting (false the instant the recv wakes). */
bool lucas_egress_inflight(void)
{
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (st && st->state == SOTBOX_STATE_WAITING_FOR_RECV) return true;
    }
    return false;
}

int lucas_recv_wake_waiter(uint32_t pid)
{
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->state != SOTBOX_STATE_WAITING_FOR_RECV) continue;
        if ((uint32_t)st->synthetic_pid != pid) continue;

        /* Drain one queued entry into the parked sotbox's vspace.  The
         * deliver helper returns -1 only when the queue is empty for this
         * pid · since this wake hook is called immediately after enqueue,
         * a -1 here would mean a race with another consumer · safely
         * leave the sotbox parked for the next enqueue. */
        uint32_t want_ip_be =
            (st->waiting_recv_fd >= 0 && st->waiting_recv_fd < LUCAS_MAX_FDS)
            ? st->fds[st->waiting_recv_fd].connect_peer_ip_be : 0;
        int64_t r = recvfrom_deliver(st,
                                      st->waiting_recv_buf_vaddr,
                                      st->waiting_recv_buf_size,
                                      st->waiting_recv_addr_vaddr,
                                      st->waiting_recv_addrlen_vaddr,
                                      want_ip_be);
        if (r == -1) {
            printf("[sotnet-δ] WAKE recv pid=%u · queue empty (race) · stay parked\n",
                   pid);
            return 0;
        }

        /* Unblock: rewrite RAX/RIP and Send to the saved reply cap.
         * Same epilogue as pipe_resume_sotbox / epoll_resume_sotbox. */
        seL4_UserContext regs;
        if (seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs) == 0) {
            regs.rax = (uint64_t)r;
            regs.rip += 2;          /* advance past syscall instruction */
            regs.rcx  = regs.rip;
            regs.r11  = regs.rflags;
#ifdef LUCAS_TRACE_L2_WR
            printf("[l:wr-handlers_net:553] tcb=%lu rax=0x%lx rip=0x%lx (recvfrom_wake)\n",
                   (unsigned long)st->client_tcb,
                   (unsigned long)regs.rax,
                   (unsigned long)regs.rip);
#endif
            seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
        }
        seL4_Send(st->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
        vka_cspace_free(st->vka, st->waiting_reply_cap);

        st->waiting_reply_cap          = 0;
        st->waiting_recv_fd            = 0;
        st->waiting_recv_buf_vaddr     = 0;
        st->waiting_recv_buf_size      = 0;
        st->waiting_recv_addr_vaddr    = 0;
        st->waiting_recv_addrlen_vaddr = 0;
        st->state                      = SOTBOX_STATE_RUNNING;
        printf("[sotnet-δ] WAKE recvfrom pid=%u · %lld bytes delivered\n",
               pid, (long long)r);
        return 1;
    }
    return 0;
}

/* γ-3-γ-2b · is a sotbox parked in recvfrom for `pid`?  Used by orch's p2c
 * drain to decide whether to wake the waiter (stream delivery) vs leave the
 * bytes in p2c for its next recvfrom.  Mirrors the wake scan. */
int lucas_recv_waiter_present(uint32_t pid)
{
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->state != SOTBOX_STATE_WAITING_FOR_RECV) continue;
        if ((uint32_t)st->synthetic_pid == pid) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* sottrace v1 · accept wake-up hook · called by tcp_server_on_ack     */
/* when a handshake reaches ESTABLISHED (a conn becomes accept-ready). */
/* If a sotbox is parked in WAITING_FOR_ACCEPT, dequeue the conn via   */
/* do_accept, rewrite RAX=new_fd and Send to the saved reply cap.      */
/* No-op (returns 0) when no box is parked or the queue is still empty */
/* (race · stay parked for the next ESTABLISHED).                      */
/*                                                                     */
/* Returns 1 if a waiter was woken, 0 otherwise.                       */
/* ------------------------------------------------------------------ */
int lucas_accept_wake_waiter(void)
{
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->state != SOTBOX_STATE_WAITING_FOR_ACCEPT) continue;

        /* Dequeue one completed conn into a fresh fd.  do_accept returns the
         * EAGAIN anomaly when the queue is still empty (race with another
         * consumer) · safely leave the sotbox parked for the next wake. */
        int64_t r = do_accept(st, st->waiting_accept_fd,
                              st->waiting_accept_addr_vaddr,
                              st->waiting_accept_addrlen_vaddr);
        if (r == -(int64_t)11) {
            printf("[sotnet] WAKE accept pid=%d · queue empty (race) · stay parked\n",
                   st->synthetic_pid);
            return 0;
        }

        /* Unblock: rewrite RAX/RIP and Send to the saved reply cap.
         * Same epilogue as recvfrom_wake (rip+=2, rcx, r11, WriteRegisters). */
        seL4_UserContext regs;
        if (seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs) == 0) {
            regs.rax = (uint64_t)r;
            regs.rip += 2;          /* advance past syscall instruction */
            regs.rcx  = regs.rip;
            regs.r11  = regs.rflags;
#ifdef LUCAS_TRACE_L2_WR
            printf("[l:wr-handlers_net] tcb=%lu rax=0x%lx rip=0x%lx (accept_wake)\n",
                   (unsigned long)st->client_tcb,
                   (unsigned long)regs.rax,
                   (unsigned long)regs.rip);
#endif
            seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
        }
        seL4_Send(st->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
        vka_cspace_free(st->vka, st->waiting_reply_cap);

        st->waiting_reply_cap            = 0;
        st->waiting_accept_fd            = 0;
        st->waiting_accept_addr_vaddr    = 0;
        st->waiting_accept_addrlen_vaddr = 0;
        st->state                        = SOTBOX_STATE_RUNNING;
        printf("[sotnet] WAKE accept pid=%d · fd=%lld delivered\n",
               st->synthetic_pid, (long long)r);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* sendmsg() · no-op success.                                          */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_sendmsg(lucas_state_t *st,
                           uint64_t fd, uint64_t msg_vaddr, uint64_t _2,
                           uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_2; (void)_3; (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;
    struct wl_msghdr mh;
    if (lucas_copy_from_client(st, (uintptr_t)msg_vaddr, &mh, sizeof(mh)) != 0)
        return -(int64_t)LX_EFAULT;
    if ((int64_t)mh.msg_iovlen < 0 || mh.msg_iovlen > WL_IOV_MAX)
        return -(int64_t)22;   /* EINVAL */

    /* apt-T7 · AF_NETLINK route socket · gather iovecs into a kbuf and inspect
     * for an RTM_GETADDR dump request (glibc __check_pf usually sends via
     * sendto, but handle sendmsg too for robustness). */
    if (st->fds[fd].is_netlink) {
        uint8_t kb[256];
        size_t off = 0;
        for (uint64_t i = 0; i < mh.msg_iovlen && off < sizeof(kb); ++i) {
            struct wl_iovec iov;
            if (lucas_copy_from_client(st, (uintptr_t)(mh.msg_iov + i * sizeof(iov)),
                                       &iov, sizeof(iov)) != 0)
                return -(int64_t)LX_EFAULT;
            size_t take = iov.iov_len;
            if (take > sizeof(kb) - off) take = sizeof(kb) - off;
            if (take && lucas_copy_from_client(st, (uintptr_t)iov.iov_base,
                                               kb + off, take) != 0)
                return -(int64_t)LX_EFAULT;
            off += take;
        }
        return netlink_handle_send(st, (int)fd, kb, off);
    }

    /* WINE-M1 · AF_UNIX rendezvous channel (wineserver IPC): gather the iovecs
     * into the channel ring (the wine protocol request/reply bytes). */
    if (st->fds[fd].unix_chan_idx1) {
        int ci = st->fds[fd].unix_chan_idx1 - 1;
        uint8_t se = st->fds[fd].unix_server_end;
        /* Pre-sum this sendmsg's data length so the SCM cmsg can be tagged with
         * its message boundary (the fd is attached to THESE bytes). */
        uint64_t scm_data_len = 0;
        for (uint64_t i = 0; i < mh.msg_iovlen; ++i) {
            struct wl_iovec iov;
            if (lucas_copy_from_client(st, (uintptr_t)(mh.msg_iov + i * sizeof(iov)),
                                       &iov, sizeof(iov)) == 0)
                scm_data_len += iov.iov_len;
        }
        /* Extract + enqueue SCM_RIGHTS fds FIRST, so the wake fired by the data
         * send below already sees them (deliver data + cmsg atomically to a
         * recvmsg-parked peer).  cmsghdr x86-64: len(u64)@0, level(i32)@8,
         * type(i32)@12, fds@16. */
        if (mh.msg_control && mh.msg_controllen >= 16 + 4) {
            uint8_t hb[16];
            if (lucas_copy_from_client(st, (uintptr_t)mh.msg_control, hb, 16) == 0) {
                uint64_t clen; int32_t lvl, typ;
                memcpy(&clen, hb + 0, 8); memcpy(&lvl, hb + 8, 4); memcpy(&typ, hb + 12, 4);
                if (lvl == 1 && typ == 1 && clen >= 16) {   /* SOL_SOCKET / SCM_RIGHTS */
                    int nfds = (int)((clen - 16) / 4);
                    if (nfds > LUCAS_UNIX_SCM_MAX) nfds = LUCAS_UNIX_SCM_MAX;
                    int fds[LUCAS_UNIX_SCM_MAX];
                    for (int k = 0; k < nfds; ++k) {
                        uint32_t pf = (uint32_t)-1;
                        lucas_copy_from_client(st, (uintptr_t)(mh.msg_control + 16 + k * 4), &pf, 4);
                        fds[k] = (int)pf;
                    }
                    if (nfds > 0) {
                        unix_scm_enqueue(st, ci, se, fds, nfds, scm_data_len);
                        printf("[unix] pid=%d sendmsg fd=%lu · SCM_RIGHTS enqueue %d fd(s) data=%llu\n",
                               st->synthetic_pid, (unsigned long)fd, nfds,
                               (unsigned long long)scm_data_len);
                    }
                }
            }
        }
        int64_t tot = 0;
        for (uint64_t i = 0; i < mh.msg_iovlen; ++i) {
            struct wl_iovec iov;
            if (lucas_copy_from_client(st, (uintptr_t)(mh.msg_iov + i * sizeof(iov)),
                                       &iov, sizeof(iov)) != 0)
                return (tot > 0) ? tot : -(int64_t)LX_EFAULT;
            if (iov.iov_len == 0) continue;
            int64_t r = lucas_unix_send(st, fd, iov.iov_base, iov.iov_len);
            if (r < 0) return (tot > 0) ? tot : r;
            tot += r;
            if ((uint64_t)r < iov.iov_len) break;   /* ring full · short send */
        }
        printf("[unix] pid=%d sendmsg fd=%lu · %lld bytes\n",
               st->synthetic_pid, (unsigned long)fd, (long long)tot);
        return tot;
    }

    /* Non-Wayland sockets: preserve the legacy no-op-success (claim sent). */
    if (!st->fds[fd].wayland_connected) {
        int64_t tot = 0;
        for (uint64_t i = 0; i < mh.msg_iovlen; ++i) {
            struct wl_iovec iov;
            if (lucas_copy_from_client(st, (uintptr_t)(mh.msg_iov + i * sizeof(iov)),
                                       &iov, sizeof(iov)) != 0) break;
            tot += (int64_t)iov.iov_len;
        }
        printf("[sotnet-α] pid=%d sendmsg(fd=%lu) → %lld (non-wl stub)\n",
               st->synthetic_pid, (unsigned long)fd, (long long)tot);
        return tot;
    }

    /* Wayland: gather iovecs, split into wire messages, forward each, then
     * publish the accumulated compositor replies into wl_rx for the next
     * recvmsg/read.  SCM_RIGHTS (msg_control): wl_shm.create_pool passes the
     * pool memfd here — extract the first SCM_RIGHTS fd and hand it to the
     * forwarder, which maps the pool into the compositor (the real-libwayland
     * analogue of the hand-rolled 5-word create_pool). */
    int scm_fd = -1;
    if (mh.msg_control != 0 && mh.msg_controllen >= sizeof(struct wl_cmsghdr) + 4) {
        struct wl_cmsghdr ch;
        if (lucas_copy_from_client(st, (uintptr_t)mh.msg_control, &ch, sizeof(ch)) == 0
            && ch.cmsg_level == WL_SOL_SOCKET && ch.cmsg_type == WL_SCM_RIGHTS) {
            uint32_t f;
            if (lucas_copy_from_client(st, (uintptr_t)(mh.msg_control + sizeof(ch)),
                                       &f, 4) == 0) {
                scm_fd = (int)f;
                printf("[wayland] pid=%d sendmsg · SCM_RIGHTS fd=%d (pool memfd)\n",
                       st->synthetic_pid, scm_fd);
            }
        }
    }
    uint8_t acc[256]; size_t acc_len = 0;
    int64_t total = 0;
    for (uint64_t i = 0; i < mh.msg_iovlen; ++i) {
        struct wl_iovec iov;
        if (lucas_copy_from_client(st, (uintptr_t)(mh.msg_iov + i * sizeof(iov)),
                                   &iov, sizeof(iov)) != 0)
            return (total > 0) ? total : -(int64_t)LX_EFAULT;
        if (iov.iov_len == 0) continue;
        int64_t rc = lucas_wayland_forward_stream(st, fd, iov.iov_base, iov.iov_len,
                                                  acc, sizeof(acc), &acc_len, scm_fd);
        if (rc < 0) return (total > 0) ? total : rc;
        total += rc;
    }
    if (acc_len > sizeof(st->fds[fd].wl_rx)) acc_len = sizeof(st->fds[fd].wl_rx);
    memcpy(st->fds[fd].wl_rx, acc, acc_len);
    st->fds[fd].wl_rx_len    = (uint16_t)acc_len;
    st->fds[fd].wl_rx_cursor = 0;
    printf("[wayland] pid=%d sendmsg fd=%lu · %lld bytes forwarded · reply %zu bytes buffered\n",
           st->synthetic_pid, (unsigned long)fd, (long long)total, acc_len);
    return total;
}

/* ------------------------------------------------------------------ */
/* sendmmsg() · glibc's resolver sends the A+AAAA DNS queries TOGETHER     */
/* (vlen=2) via sendmmsg; ENOSYS meant it never sent → getaddrinfo timed   */
/* out → apt Ign'd the index.  Route each message's first iovec through    */
/* lucas_sys_sendto (which carries the connected-UDP DNS forward), write    */
/* each mmsghdr.msg_len, and return the count sent.                         */
/* struct mmsghdr { struct msghdr msg_hdr (56B); unsigned msg_len; } → 64B. */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_sendmmsg(lucas_state_t *st, uint64_t fd, uint64_t msgvec_vaddr,
                           uint64_t vlen, uint64_t flags, uint64_t _4, uint64_t _5)
{
    (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;
    if ((int64_t)vlen <= 0) return -(int64_t)22;   /* EINVAL */
    if (vlen > 64) vlen = 64;
    unsigned sent = 0;
    for (unsigned i = 0; i < (unsigned)vlen; ++i) {
        uintptr_t mm = (uintptr_t)msgvec_vaddr + (uintptr_t)i * 64u;
        struct wl_msghdr mh;
        if (lucas_copy_from_client(st, mm, &mh, sizeof(mh)) != 0) break;
        if ((int64_t)mh.msg_iovlen < 1 || mh.msg_iovlen > WL_IOV_MAX) break;
        struct wl_iovec iov;
        if (lucas_copy_from_client(st, (uintptr_t)mh.msg_iov, &iov, sizeof(iov)) != 0) break;
        /* send the first iovec via the sendto path · dest = msg_name (NULL on a
         * connected UDP socket → the connect-peer DNS forward · my T9 fix). */
        int64_t r = lucas_sys_sendto(st, fd, iov.iov_base, iov.iov_len, flags,
                                     mh.msg_name, mh.msg_namelen);
        if (r < 0) { if (i == 0) return r; break; }
        uint32_t mlen = (uint32_t)r;
        (void)lucas_copy_to_client(st, mm + 56, &mlen, 4);   /* mmsghdr.msg_len */
        ++sent;
    }
    printf("[sotnet-α] pid=%d sendmmsg fd=%lu vlen=%lu → %u sent\n",
           st->synthetic_pid, (unsigned long)fd, (unsigned long)vlen, sent);
    return (int64_t)sent;
}

/* ------------------------------------------------------------------ */
/* recvmsg() · Wayland: drain buffered compositor reply (wl_rx) into the  */
/* iovecs; -EAGAIN when empty (libwayland sets the fd non-blocking).      */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_recvmsg(lucas_state_t *st,
                           uint64_t fd, uint64_t msg_vaddr, uint64_t _2,
                           uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_3; (void)_4; (void)_5;
    uint64_t rmsg_flags = _2;   /* recvmsg(fd, msghdr, flags) · MSG_PEEK/MSG_TRUNC */
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;

    /* SOCKET DEMUX · lwIP-egress fd → recv the response into the first iovec (some
     * HTTP clients read via recvmsg).  Mirrors the recvfrom/read paths; honours
     * MSG_DONTWAIT + O_NONBLOCK. */
    if (st->fds[fd].lwip_sess != NULL) {
        extern int64_t orch_lwip_egress_recv(void *handle, uint8_t *buf, uint32_t len, int nb);
        uint32_t z32 = 0;
        lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 48), &z32, 4);   /* msg_flags=0 */
        struct wl_msghdr mh;
        if (lucas_copy_from_client(st, (uintptr_t)msg_vaddr, &mh, sizeof(mh)) != 0)
            return -(int64_t)LX_EFAULT;
        if ((int64_t)mh.msg_iovlen < 0 || mh.msg_iovlen > WL_IOV_MAX)
            return -(int64_t)22;
        struct wl_iovec iov; iov.iov_base = 0; iov.iov_len = 0;
        for (uint64_t i = 0; i < mh.msg_iovlen; ++i) {
            if (lucas_copy_from_client(st, (uintptr_t)(mh.msg_iov + i * sizeof(iov)),
                                       &iov, sizeof(iov)) != 0)
                return -(int64_t)LX_EFAULT;
            if (iov.iov_len) break;
        }
        if (iov.iov_len == 0) return 0;
        static uint8_t lwrxb[TCP_TX_BUF_SIZE];
        size_t want = (iov.iov_len < TCP_TX_BUF_SIZE) ? (size_t)iov.iov_len : TCP_TX_BUF_SIZE;
        int nb = ((rmsg_flags & 0x40) != 0) || ((st->fds[fd].flags & 0x800) != 0);
        int64_t got = orch_lwip_egress_recv(st->fds[fd].lwip_sess, lwrxb, (uint32_t)want, nb);
        if (got == -11) return -(int64_t)LX_EAGAIN;
        if (got <= 0) return got;
        if (lucas_copy_to_client(st, (uintptr_t)iov.iov_base, lwrxb, (size_t)got) != 0)
            return -(int64_t)LX_EFAULT;
        return got;
    }

    /* apt-T7 · AF_NETLINK route socket · scatter the RTM_GETADDR reply into the
     * first non-empty iovec (glibc __check_pf reads via recvmsg).  msg_flags=0. */
    if (st->fds[fd].is_netlink) {
        struct wl_msghdr nmh;
        if (lucas_copy_from_client(st, (uintptr_t)msg_vaddr, &nmh, sizeof(nmh)) != 0)
            return -(int64_t)LX_EFAULT;
        if ((int64_t)nmh.msg_iovlen < 0 || nmh.msg_iovlen > WL_IOV_MAX)
            return -(int64_t)22;
        uint32_t z32 = 0;
        lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 48), &z32, 4); /* msg_flags=0 */
        /* CRITICAL · fill msg_name with the KERNEL source address (nl_pid=0).
         * glibc __check_pf sets msg_name=&sockaddr_nl and SKIPS (continues) any
         * datagram whose source nl_pid != 0 — so without this it reads uninit
         * stack garbage, rejects every message (incl. our NLMSG_DONE), loops, and
         * hits "Unexpected netlink response of size 0".  sockaddr_nl =
         * {u16 nl_family=AF_NETLINK; u16 pad; u32 nl_pid=0; u32 nl_groups=0} = 12B. */
        if (nmh.msg_name && nmh.msg_namelen >= 12) {
            uint8_t snl[12] = { (uint8_t)LUCAS_AF_NETLINK, 0, 0,0, 0,0,0,0, 0,0,0,0 };
            lucas_copy_to_client(st, (uintptr_t)nmh.msg_name, snl, sizeof(snl));
            uint32_t nl = 12;
            lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 8), &nl, 4); /* msg_namelen=12 */
        }
        struct wl_iovec iov; iov.iov_base = 0; iov.iov_len = 0;
        for (uint64_t i = 0; i < nmh.msg_iovlen; ++i) {
            if (lucas_copy_from_client(st, (uintptr_t)(nmh.msg_iov + i * sizeof(iov)),
                                       &iov, sizeof(iov)) != 0)
                return -(int64_t)LX_EFAULT;
            if (iov.iov_len) break;
        }
        if (iov.iov_len == 0)
            return st->fds[fd].netlink_dump_pending ? -(int64_t)90 : 0;
        return netlink_handle_recv(st, (int)fd, (uintptr_t)iov.iov_base,
                                   (size_t)iov.iov_len, rmsg_flags);
    }

    /* WINE-M1 · AF_UNIX rendezvous channel (wineserver IPC): scatter channel
     * bytes into the iovecs; park (WAITING_FOR_UNIX) if the ring is empty. */
    if (st->fds[fd].unix_chan_idx1) {
        int ci = st->fds[fd].unix_chan_idx1 - 1;
        uint8_t se = st->fds[fd].unix_server_end;
        uint32_t z32 = 0;
        lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 48), &z32, 4);   /* msg_flags=0 */
        struct wl_msghdr umh;
        if (lucas_copy_from_client(st, (uintptr_t)msg_vaddr, &umh, sizeof(umh)) != 0)
            return -(int64_t)LX_EFAULT;
        if ((int64_t)umh.msg_iovlen < 0 || umh.msg_iovlen > WL_IOV_MAX)
            return -(int64_t)22;
        struct wl_iovec iov; iov.iov_base = 0; iov.iov_len = 0;
        for (uint64_t i = 0; i < umh.msg_iovlen; ++i) {
            if (lucas_copy_from_client(st, (uintptr_t)(umh.msg_iov + i * sizeof(iov)),
                                       &iov, sizeof(iov)) != 0)
                return -(int64_t)LX_EFAULT;
            if (iov.iov_len) break;   /* first non-empty iov (handshake msgs are 1 iov) */
        }
        if (iov.iov_len == 0) {   /* fd-only recvmsg (no data) · deliver SCM now */
            unix_scm_deliver(st, ci, se, msg_vaddr, umh.msg_control, umh.msg_controllen);
            return 0;
        }
        int64_t r = lucas_unix_recv(st, fd, iov.iov_base, iov.iov_len);  /* bytes / 0 EOF / DEFERRED */
        if (r == LUCAS_WAIT4_DEFERRED) {
            /* parked · stash the msghdr so the wake delivers SCM_RIGHTS too. */
            st->waiting_unix_msg_vaddr = (uintptr_t)msg_vaddr;
            st->waiting_unix_msgctl    = (uintptr_t)umh.msg_control;
            st->waiting_unix_msgctllen = (size_t)umh.msg_controllen;
            return r;
        }
        /* data present immediately · deliver any SCM_RIGHTS fds + cmsg now. */
        unix_scm_deliver(st, ci, se, msg_vaddr, umh.msg_control, umh.msg_controllen);
        printf("[unix] pid=%d recvmsg fd=%lu · %lld bytes%s\n",
               st->synthetic_pid, (unsigned long)fd, (long long)r, r == 0 ? " (EOF)" : "");
        return r;
    }

    /* DNS-intercept delivery · Alpine musl's __res_msend reads the nameserver
     * reply with recvmsg (not recvfrom) so it can validate the source via cmsg.
     * A forwarded UDP:53 answer lands in the per-pid g_recv_queue; deliver it
     * here, else the resolver poll()s readable (queue non-empty) → recvmsg → EOF
     * stub → never drains → infinite spin (openssl s_client hung the boot).
     * Scatter the datagram into the first non-empty iovec and fill msg_name with
     * the source sockaddr_in (mirrors recvfrom_deliver's queue branch). */
    {
        extern int sotnet_recv_pending(uint32_t pid);
        if (sotnet_recv_pending((uint32_t)st->synthetic_pid)) {
            struct wl_msghdr dmh;
            if (lucas_copy_from_client(st, (uintptr_t)msg_vaddr, &dmh, sizeof(dmh)) != 0)
                return -(int64_t)LX_EFAULT;
            if ((int64_t)dmh.msg_iovlen < 0 || dmh.msg_iovlen > WL_IOV_MAX)
                return -(int64_t)22;
            struct wl_iovec iov = { 0, 0 };
            for (uint64_t i = 0; i < dmh.msg_iovlen; ++i) {
                if (lucas_copy_from_client(st, (uintptr_t)(dmh.msg_iov + i * sizeof(iov)),
                                           &iov, sizeof(iov)) != 0)
                    return -(int64_t)LX_EFAULT;
                if (iov.iov_len) break;
            }
            uint8_t  q_ip[4]   = { 0, 0, 0, 0 };
            uint16_t q_port_be = 0;
            uint8_t  qbuf[512];
            size_t   qcap = (iov.iov_len && iov.iov_len < sizeof(qbuf))
                            ? (size_t)iov.iov_len : sizeof(qbuf);
            int qgot = sotnet_recv_dequeue(st->synthetic_pid,
                                           st->fds[fd].connect_peer_ip_be,
                                           qbuf, qcap, q_ip, &q_port_be);
            if (qgot >= 0) {
                size_t out_len = (size_t)qgot;
                if (iov.iov_len && out_len > iov.iov_len) out_len = (size_t)iov.iov_len;
                if (out_len && iov.iov_base &&
                    lucas_copy_to_client(st, (uintptr_t)iov.iov_base, qbuf, out_len) != 0)
                    return -(int64_t)LX_EFAULT;
                if (dmh.msg_name && dmh.msg_namelen >= 16) {
                    struct { uint16_t family, port_be; uint32_t addr_be; uint8_t pad[8]; }
                        __attribute__((packed)) sa;
                    memset(&sa, 0, sizeof sa);
                    sa.family  = 2;
                    sa.port_be = q_port_be;
                    sa.addr_be = ((uint32_t)q_ip[0]) | ((uint32_t)q_ip[1] << 8) |
                                 ((uint32_t)q_ip[2] << 16) | ((uint32_t)q_ip[3] << 24);
                    (void)lucas_copy_to_client(st, (uintptr_t)dmh.msg_name, &sa, sizeof sa);
                    uint32_t nl = sizeof sa;
                    (void)lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 8), &nl, 4);
                }
                /* clear msg_controllen (offset 40, 8B) + msg_flags (offset 48, 4B). */
                uint64_t z64 = 0; uint32_t z32 = 0;
                lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 40), &z64, 8);
                lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 48), &z32, 4);
                printf("[sotnet-α] pid=%d recvmsg(fd=%lu) · DNS-queue %zu B from %u.%u.%u.%u:%u\n",
                       st->synthetic_pid, (unsigned long)fd, out_len,
                       q_ip[0], q_ip[1], q_ip[2], q_ip[3],
                       (uint16_t)(((q_port_be & 0xFF) << 8) | ((q_port_be >> 8) & 0xFF)));
                return (int64_t)out_len;
            }
        }
    }

    if (!st->fds[fd].wayland_connected) {
        printf("[sotnet-α] pid=%d recvmsg(fd=%lu) → 0 (EOF · non-wl stub)\n",
               st->synthetic_pid, (unsigned long)fd);
        return 0;
    }
    struct wl_msghdr mh;
    if (lucas_copy_from_client(st, (uintptr_t)msg_vaddr, &mh, sizeof(mh)) != 0)
        return -(int64_t)LX_EFAULT;
    if ((int64_t)mh.msg_iovlen < 0 || mh.msg_iovlen > WL_IOV_MAX)
        return -(int64_t)22;   /* EINVAL */
    int64_t total = 0;
    for (uint64_t i = 0; i < mh.msg_iovlen; ++i) {
        struct wl_iovec iov;
        if (lucas_copy_from_client(st, (uintptr_t)(mh.msg_iov + i * sizeof(iov)),
                                   &iov, sizeof(iov)) != 0)
            return (total > 0) ? total : -(int64_t)LX_EFAULT;
        if (iov.iov_len == 0) continue;
        int64_t n = lucas_wayland_drain(st, fd, iov.iov_base, iov.iov_len);
        if (n < 0) return (total > 0) ? total : n;
        total += n;
        if ((uint64_t)n < iov.iov_len) break;   /* wl_rx exhausted */
    }
    /* Clear msg_controllen (offset 40) + msg_flags (offset 48) so libwayland
     * does not see a stale MSG_CTRUNC. */
    uint64_t z64 = 0; uint32_t z32 = 0;
    lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 40), &z64, 8);
    lucas_copy_to_client(st, (uintptr_t)(msg_vaddr + 48), &z32, 4);
    if (total == 0) return -(int64_t)11;   /* EAGAIN · non-blocking, no data yet */
    return total;
}

/* ------------------------------------------------------------------ */
/* shutdown() · no-op success.                                         */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_shutdown(lucas_state_t *st,
                            uint64_t fd, uint64_t how,
                            uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_2; (void)_3; (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;
    /* SHUT_WR / SHUT_RDWR on a socketpair channel end · propagate the write-side
     * half-close to the channel so the PEER's read sees EOF.  busybox wget writes
     * the HTTP request to the openssl helper over the socketpair then SHUT_WRs
     * its end; the openssl relay loop reads its stdin (the peer end) and, without
     * this EOF, PARKS forever waiting for more request data → the response is
     * never relayed back (deadlock).  Mark this end's closed flag (mirrors the
     * full-close path) and wake the peer reader; the read side stays open so the
     * response can still flow back over s2c. */
    if (st->fds[fd].unix_chan_idx1 && (how == 1 /*SHUT_WR*/ || how == 2 /*SHUT_RDWR*/)) {
        int ci = st->fds[fd].unix_chan_idx1 - 1;
        if (ci >= 0 && ci < LUCAS_UNIX_MAX_CHANNELS && g_unix_channels[ci].in_use) {
            /* Set the directional WRITE half-close, NOT the full-close flag: the
             * peer reading this end's ring sees EOF, but the peer can still WRITE
             * the OTHER direction (we can still read it) — so its write must not
             * get EPIPE.  (busybox wget SHUT_WRs after sending the request, then
             * reads the response openssl writes back over s2c.)  */
            if (st->fds[fd].unix_server_end) g_unix_channels[ci].server_wr_shut = 1;
            else                             g_unix_channels[ci].client_wr_shut = 1;
            lucas_unix_wake_reader(ci, (uint8_t)(st->fds[fd].unix_server_end ? 0 : 1));
            iomux_check_epoll_waiters(NULL);
            printf("[sotnet-α] pid=%d shutdown(fd=%lu, how=%lu) → 0 (channel write half-close · peer EOF)\n",
                   st->synthetic_pid, (unsigned long)fd, (unsigned long)how);
            return 0;
        }
    }
    printf("[sotnet-α] pid=%d shutdown(fd=%lu, how=%lu) → 0 (stub)\n",
           st->synthetic_pid, (unsigned long)fd, (unsigned long)how);
    return 0;
}

/* ------------------------------------------------------------------ */
/* getsockname() · return the guest's local source address (10.0.2.15).        */
/* ------------------------------------------------------------------ */
/* glibc getaddrinfo's RFC-3484 destination-address sort connect()s a UDP socket
 * to each resolved candidate, then getsockname()s the SOURCE address that would
 * be used (to score reachability/scope).  The old no-addr stub made glibc treat
 * every candidate as having no usable source → it discarded ALL of them → a
 * resolve that returned real IPs still failed (apt Ign'd the index).  Fill the
 * honey guest IP so the candidates keep a valid source and the sort succeeds. */
int64_t lucas_sys_getsockname(lucas_state_t *st,
                               uint64_t fd, uint64_t addr, uint64_t addrlen,
                               uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_3; (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;
    struct { uint16_t family, port_be; uint32_t addr_be; uint8_t pad[8]; }
        __attribute__((packed)) sa;
    memset(&sa, 0, sizeof sa);
    sa.family  = LUCAS_AF_INET;
    sa.addr_be = 0x0F02000Au;   /* 10.0.2.15 · g_our_ip (network byte order) */
    sa.port_be = 0;             /* local port · glibc's address sort scores the IP */
    if (addr && addrlen) {
        uint32_t ulen = 0;
        (void)lucas_copy_from_client(st, (uintptr_t)addrlen, &ulen, sizeof(ulen));
        uint32_t w = ulen < sizeof(sa) ? ulen : (uint32_t)sizeof(sa);
        if (w && lucas_copy_to_client(st, (uintptr_t)addr, &sa, w) != 0)
            return -(int64_t)LX_EFAULT;
        uint32_t actual = sizeof(sa);
        (void)lucas_copy_to_client(st, (uintptr_t)addrlen, &actual, sizeof(actual));
    }
    printf("[sotnet-α] pid=%d getsockname(fd=%lu) → 10.0.2.15\n",
           st->synthetic_pid, (unsigned long)fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* getpeername() · return the connected peer (cached at connect time).        */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_getpeername(lucas_state_t *st,
                               uint64_t fd, uint64_t addr, uint64_t addrlen,
                               uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_3; (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;
    lucas_fd_t *e = &st->fds[fd];
    /* Connected iff connect() cached a peer (the egress TLS client: python ssl
     * + openssl call getpeername to validate the socket before the handshake).
     * The old unconditional -ENOTCONN stub made python's ssl bail with "Socket
     * not connected". */
    int connected = e->connect_peer_ip_be != 0 ||
                    (e->tcp_conn && e->tcp_conn->state != TCP_STATE_CLOSED);
    if (!connected) {
        printf("[sotnet-α] pid=%d getpeername(fd=%lu) → -ENOTCONN (no peer)\n",
               st->synthetic_pid, (unsigned long)fd);
        return -(int64_t)107;  /* ENOTCONN */
    }
    struct { uint16_t family, port_be; uint32_t addr_be; uint8_t pad[8]; }
        __attribute__((packed)) sa;
    memset(&sa, 0, sizeof sa);
    sa.family  = LUCAS_AF_INET;
    sa.port_be = e->connect_peer_port_be;
    sa.addr_be = e->connect_peer_ip_be;
    if (addr && addrlen) {
        uint32_t ulen = 0;
        (void)lucas_copy_from_client(st, (uintptr_t)addrlen, &ulen, sizeof(ulen));
        uint32_t w = ulen < sizeof(sa) ? ulen : (uint32_t)sizeof(sa);
        if (w && lucas_copy_to_client(st, (uintptr_t)addr, &sa, w) != 0)
            return -(int64_t)LX_EFAULT;
        uint32_t actual = sizeof(sa);
        (void)lucas_copy_to_client(st, (uintptr_t)addrlen, &actual, sizeof(actual));
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* setsockopt() · no-op success; options silently accepted.            */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_setsockopt(lucas_state_t *st,
                              uint64_t fd, uint64_t level, uint64_t optname,
                              uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_3; (void)_4; (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;
    printf("[sotnet-α] pid=%d setsockopt(fd=%lu, level=%lu, opt=%lu) → 0 (stub)\n",
           st->synthetic_pid, (unsigned long)fd,
           (unsigned long)level, (unsigned long)optname);
    return 0;
}

/* ------------------------------------------------------------------ */
/* getsockopt() · SO_TYPE / SO_ERROR answered; others a no-op stub.    */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_getsockopt(lucas_state_t *st,
                              uint64_t fd, uint64_t level, uint64_t optname,
                              uint64_t optval, uint64_t optlen, uint64_t _5)
{
    (void)_5;
    if (fd >= LUCAS_MAX_FDS || st->fds[fd].kind != LUCAS_FD_SOCKET)
        return -(int64_t)LX_EBADF;
    /* SOL_SOCKET=1 · SO_ERROR=4 · SO_TYPE=3 (Linux x86_64).  python's ssl
     * wrap_socket REQUIRES getsockopt(SOL_SOCKET, SO_TYPE) == SOCK_STREAM, and
     * connect()-then-check uses SO_ERROR.  The old stub wrote nothing → python
     * read a stale 0 → "only stream sockets are supported".  Answer both. */
    if (level == 1 /*SOL_SOCKET*/ && (optname == 3 /*SO_TYPE*/ || optname == 4 /*SO_ERROR*/)) {
        int32_t val;
        if (optname == 3) {
            int t = lucas_socket_type(st, fd) & LUCAS_SOCK_TYPEMASK;
            val = (t == 0) ? LUCAS_SOCK_STREAM : t;   /* a connected TCP fd is STREAM */
        } else if (st->fds[fd].lwip_sess != NULL) {
            /* SO_ERROR on an lwIP-egress fd · reflects the async connect result
             * (0 = connected, ECONNREFUSED = failed).  A non-blocking client checks
             * this after its connect()→EINPROGRESS + WaitFd(POLLOUT). */
            extern int orch_lwip_egress_so_error(void *handle);
            val = orch_lwip_egress_so_error(st->fds[fd].lwip_sess);
        } else {
            val = 0;                                   /* SO_ERROR · no pending error */
        }
        if (optval && optlen) {
            uint32_t ulen = 0;
            (void)lucas_copy_from_client(st, (uintptr_t)optlen, &ulen, sizeof(ulen));
            uint32_t w = ulen < sizeof(val) ? ulen : (uint32_t)sizeof(val);
            if (w && lucas_copy_to_client(st, (uintptr_t)optval, &val, w) != 0)
                return -(int64_t)LX_EFAULT;
            uint32_t actual = sizeof(val);
            (void)lucas_copy_to_client(st, (uintptr_t)optlen, &actual, sizeof(actual));
        }
        printf("[sotnet-α] pid=%d getsockopt(fd=%lu, SOL_SOCKET, %s) → %d\n",
               st->synthetic_pid, (unsigned long)fd,
               optname == 3 ? "SO_TYPE" : "SO_ERROR", (int)val);
        return 0;
    }
    printf("[sotnet-α] pid=%d getsockopt(fd=%lu, level=%lu, opt=%lu) → 0 (stub)\n",
           st->synthetic_pid, (unsigned long)fd,
           (unsigned long)level, (unsigned long)optname);
    return 0;
}

/* ------------------------------------------------------------------ */
/* socketpair() · two connected fds.  For AF_UNIX (wine's CreateProcess uses
 * socketpair(AF_UNIX,SOCK_STREAM) for the new process's wineserver connection)
 * we back the pair with a REAL connected channel: fd1 = end0, fd2 = end1, the
 * two halves of one unix_channel_t (end0 writes c2s / reads s2c, end1 the
 * mirror).  Both ends start refcounted (refs=1) so they survive being handed to
 * wineserver (SCM) and to the forked child while the creator drops its copies.
 * Non-AF_UNIX keeps the old detached stub (no wine path needs it).            */
/* ------------------------------------------------------------------ */
int64_t lucas_sys_socketpair(lucas_state_t *st,
                              uint64_t family, uint64_t type, uint64_t protocol,
                              uint64_t fds_vaddr, uint64_t _4, uint64_t _5)
{
    (void)_4; (void)_5;
    int fd1 = alloc_sotnet_fd(st, (int)family, (int)type, (int)protocol);
    if (fd1 < 0) return (int64_t)fd1;
    int fd2 = alloc_sotnet_fd(st, (int)family, (int)type, (int)protocol);
    if (fd2 < 0) {
        st->fds[fd1].kind = LUCAS_FD_INVALID;
        return (int64_t)fd2;
    }
    int connected = 0;
    if ((int)family == LUCAS_AF_UNIX) {
        int ci = -1;
        for (int i = 0; i < LUCAS_UNIX_MAX_CHANNELS; ++i) {
            if (!g_unix_channels[i].in_use) {
                memset(&g_unix_channels[i], 0, sizeof(g_unix_channels[i]));
                g_unix_channels[i].in_use      = 1;
                g_unix_channels[i].client_slot = st->slot_index;   /* end0 */
                g_unix_channels[i].server_slot = st->slot_index;   /* end1 */
                g_unix_channels[i].client_refs = 1;
                g_unix_channels[i].server_refs = 1;
                ci = i; break;
            }
        }
        if (ci < 0) {
            st->fds[fd1].kind = LUCAS_FD_INVALID;
            st->fds[fd2].kind = LUCAS_FD_INVALID;
            return -(int64_t)24;  /* EMFILE · channel table full */
        }
        st->fds[fd1].unix_chan_idx1  = ci + 1; st->fds[fd1].unix_server_end = 0;
        st->fds[fd2].unix_chan_idx1  = ci + 1; st->fds[fd2].unix_server_end = 1;
        connected = 1;
    }
    int32_t pair[2] = { fd1, fd2 };
    if (lucas_copy_to_client(st, (uintptr_t)fds_vaddr,
                              pair, sizeof(pair)) != 0) {
        lucas_unix_close_fd(st, fd1);   /* drop the channel ends we just made */
        lucas_unix_close_fd(st, fd2);
        st->fds[fd1].kind = LUCAS_FD_INVALID;
        st->fds[fd2].kind = LUCAS_FD_INVALID;
        return -(int64_t)LX_EFAULT;
    }
    printf("[sotnet-α] pid=%d socketpair(family=%lu, type=%lu) → fds=[%d, %d] (%s)\n",
           st->synthetic_pid,
           (unsigned long)family, (unsigned long)type, fd1, fd2,
           connected ? "connected channel" : "stub");
    return 0;
}
