/*
 * sotOs · sotOs-net-synth · Synth Internet server.
 *
 * Phase 3-A scaffold: sits in Recv loop on its event EP.  When a
 * Tier 2 sotbox's sendto fires synth_record_redirect() in
 * src/sotnet/synth.c, that helper sends a SYNTH_REDIRECT IPC
 * here.  Phase 3-A just logs · Phase 3-B serves scripted HTTP/TLS
 * responses via response_profile_dispatch().
 *
 * Phase 3-C: after response_profile_dispatch logs, packs the response_profile body
 * into MRs and seL4_Calls orch's callback EP with
 * ORCH_OP_SYNTH_RESPONSE so orch can queue it for the originating
 * sotbox's next recvfrom() (Phase 3-D).
 *
 * argv convention (mirroring anomaly):
 *   argv[0] = "sotOs-net-synth"
 *   argv[1] = event EP slot (unbadged · synth seL4_Recvs here)
 *   argv[2] = orch callback EP slot (badged · synth seL4_Calls here)
 *             Optional: 0 or absent → callback disabled (Phase 3-A/B mode).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sel4/sel4.h>
#include <orch/proto.h>
#include <net-synth/response_profiles.h>
#include <net-synth/inbound_http.h>
#include <net-synth/inbound_ssh.h>
#include <net-synth/tls13.h>
#include <sotnet/bytepipe.h>
#include <sotnet/bytepipe_frame.h>
#include "tls_selftest.h"

/* SEL4UTILS_INITIAL_EP_SLOT = 1 in the standard sel4utils layout.
 * The convention: root copies the child's receive EP into slot 1 of
 * the child's CSpace before resuming it. */
#define SEL4UTILS_INITIAL_EP_SLOT 1

/* Phase 3-C: orch callback EP.  Set from argv[2] at startup.
 * 0 means callback is disabled (Phase 3-A/B compatibility). */
static seL4_CPtr g_orch_callback_ep = 0;

/* sotNet γ-3-γ-1 · byte channel.  The responder is the CONSUMER of c2p (it
 * drains the bytes a redirected sendto carried) and the PRODUCER of p2c (it
 * pushes its reply).  g_c2p_rd is the responder's private read cursor. */
static int      g_bytepipe_ready = 0;
static uint32_t g_c2p_rd         = 0;
/* N2-T · inbound framed transport · synth is the in_c2p consumer + in_p2c producer.
 * File-scope so the responder loop branch (later task) can read them. */
static int      g_bytepipe2_ready = 0;
static uint32_t g_in_c2p_rd       = 0;   /* synth is the in_c2p consumer */
/* SSH canary shell (Phase B) · synth is the SHELL_IN producer (decrypted
 * keystrokes -> busybox) and the SHELL_OUT consumer (busybox stdout -> wire).
 * g_shell_out_rd is synth's private read cursor into SHELL_OUT.  At most one
 * concurrent SSH shell (R2): g_ssh_shell_conn is the live shell's conn_id (0 = none). */
static int      g_bytepipe3_ready = 0;
static uint32_t g_shell_out_rd    = 0;
static uint16_t g_ssh_shell_conn  = 0;

/* sotNet γ-3-γ-2b · per-connection TLS server sessions, keyed by (pid,dst).
 * A real redirected client's handshake spans several redirect doorbells; the
 * br_ssl_server_context persists across them in a small LRU table. */
#include <bearssl.h>
#include "tls_rng.h"
#include <net-synth/tls_cert.h>

#define TLS_SESS_MAX 4
typedef struct {
    int      used;
    int      announced;            /* logged "handshake complete" once */
    int      app_replied;          /* γ-3-γ-2c · sent the response_profile reply once */
    uint32_t pid, dst_ip_be;
    uint16_t dst_port_be;
    uint16_t conn_id;              /* N2-R · inbound HTTPS session key */
    uint32_t last_seen;            /* LRU tick */
    br_ssl_server_context sc;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
} tls_sess_t;
static tls_sess_t g_tls_sess[TLS_SESS_MAX];
static uint32_t   g_tls_clock;

/* N2-R · the shared TLS-server engine init (mine2g · ECDHE-RSA PFS · cert ·
 * entropy injected BEFORE reset — the seed also feeds the ECDHE ephemeral key).
 * Used by both the outbound (pid,dst) session and the inbound (conn_id) session
 * so the cert/seed/suite logic lives in one place. JA3S/JA4S parity: ECDHE-RSA
 * AES-256-GCM-SHA384 (0xc030) preferred with AES-128-GCM-SHA256 (0xc02f) fallback,
 * matching a stock Nginx's TLS-1.2 selection (see ssl_server_mine2g.c). */
static void tls_engine_init(tls_sess_t *s) {
    s->announced = 0; s->app_replied = 0;
    br_ssl_server_init_mine2g(&s->sc, CHAIN, CHAIN_LEN, &SERVER_KEY);
    br_ssl_engine_set_buffer(&s->sc.eng, s->iobuf, sizeof s->iobuf, 1);
    uint8_t seed[32];
    tls_rng_fill(seed, sizeof seed);
    br_ssl_engine_inject_entropy(&s->sc.eng, seed, sizeof seed);  /* before reset */
    br_ssl_server_reset(&s->sc);
}

/* Find the session for (pid,dst) or (re)initialize the LRU/free slot as a
 * fresh TLS server (mine2g · cert · entropy injected BEFORE reset · the 2a
 * edges). */
static tls_sess_t *tls_sess_get(uint32_t pid, uint32_t ip_be, uint16_t port_be) {
    g_tls_clock++;
    tls_sess_t *lru = &g_tls_sess[0];
    for (int i = 0; i < TLS_SESS_MAX; i++) {
        tls_sess_t *s = &g_tls_sess[i];
        if (s->used && s->pid == pid && s->dst_ip_be == ip_be &&
            s->dst_port_be == port_be) {
            s->last_seen = g_tls_clock;
            return s;
        }
        if (!s->used) lru = s;
        else if (lru->used && s->last_seen < lru->last_seen) lru = s;
    }
    tls_sess_t *s = lru;
    s->used = 1;
    s->pid = pid; s->dst_ip_be = ip_be; s->dst_port_be = port_be;
    s->last_seen = g_tls_clock;
    tls_engine_init(s);
    printf("[synth-srv] TLS session open · pid=%u slot=%ld\n",
           pid, (long)(s - g_tls_sess));
    return s;
}

/* N2-R · inbound HTTPS sessions, keyed by conn_id, in their OWN LRU table so
 * inbound and the shipped outbound TLS path never evict each other. */
static tls_sess_t g_tls_in_sess[TLS_SESS_MAX];
static uint32_t   g_tls_in_clock;
static tls_sess_t *tls_sess_get_inbound(uint16_t conn_id) {
    g_tls_in_clock++;
    tls_sess_t *lru = &g_tls_in_sess[0];
    for (int i = 0; i < TLS_SESS_MAX; i++) {
        tls_sess_t *s = &g_tls_in_sess[i];
        if (s->used && s->conn_id == conn_id) { s->last_seen = g_tls_in_clock; return s; }
        if (!s->used) lru = s;
        else if (lru->used && s->last_seen < lru->last_seen) lru = s;
    }
    tls_sess_t *s = lru;
    s->used = 1; s->conn_id = conn_id; s->last_seen = g_tls_in_clock;
    tls_engine_init(s);
    printf("[synth-srv] inbound TLS session open · conn=%u slot=%ld\n",
           conn_id, (long)(s - g_tls_in_sess));
    return s;
}

/* ε1 · TLS 1.3 inbound sessions, keyed by conn_id, separate LRU from the 1.2 table. */
#define TLS13_IN_MAX 4
static tls13_sess_t g_tls13_in[TLS13_IN_MAX];
static uint32_t     g_tls13_in_clock;

/* per-conn version decision: 0 = undecided, 1 = TLS1.3, 2 = TLS1.2 (mine2g).
 * last_use is a monotonic tick bumped on every hit and on insert; used for LRU
 * eviction when the table is full (mirrors tls13_in_get / tls_sess_get_inbound). */
static struct { uint16_t conn_id; uint8_t decided; uint32_t last_use; } g_tls_ver[8];
static uint32_t g_tls_ver_clock;

/* Cache-only lookup (no insert): 0 = undecided, 1 = TLS1.3, 2 = TLS1.2. */
static uint8_t tls_ver_peek(uint16_t conn_id) {
    for (int i = 0; i < 8; i++)
        if (g_tls_ver[i].decided && g_tls_ver[i].conn_id == conn_id)
            return g_tls_ver[i].decided;
    return 0;
}

static uint8_t tls_ver_decide(uint16_t conn_id, const uint8_t *firstframe, uint32_t len) {
    g_tls_ver_clock++;
    for (int i = 0; i < 8; i++) {
        if (g_tls_ver[i].decided && g_tls_ver[i].conn_id == conn_id) {
            g_tls_ver[i].last_use = g_tls_ver_clock;
            return g_tls_ver[i].decided;
        }
    }
    int is13 = tls13_clienthello_offers_13(firstframe, len);
    uint8_t d = (is13 == 1) ? 1 : 2;
    /* find a free slot; if full, evict the least-recently-used entry so only a
     * stale/finished conn is displaced (never an active mid-handshake conn). */
    int lru_idx = 0;
    for (int i = 0; i < 8; i++) {
        if (!g_tls_ver[i].decided) { lru_idx = i; break; }
        if (g_tls_ver[i].last_use < g_tls_ver[lru_idx].last_use) lru_idx = i;
    }
    g_tls_ver[lru_idx].conn_id  = conn_id;
    g_tls_ver[lru_idx].decided  = d;
    g_tls_ver[lru_idx].last_use = g_tls_ver_clock;
    return d;
}

/* ε1 · LEADING-RECORD REASSEMBLY.  A real `openssl s_client` ClientHello is
 * ~1.4 KiB and arrives as TWO inbound frames (the kernel MSS splits it, e.g.
 * 1460 + 4 bytes — observed live).  The version decision (tls_ver_decide) must
 * see a COMPLETE TLS record: the truncated first frame parses as -1 (record
 * claims more bytes than present) → tls_ver_decide would wrongly default to the
 * 1.2 path → BearSSL gets a 1.3 ClientHello → handshake_failure.
 *
 * So for an UNDECIDED conn we buffer inbound frames here until the leading TLS
 * record (5-byte header + declared fragment) is fully present, then hand the
 * complete record to the dispatcher.  Once the version is decided the cache
 * short-circuits and frames flow straight through (the 1.3 feed / BearSSL pump
 * both reassemble subsequent records internally).
 *
 * Returns 1 with (*out_ptr,*out_len) set to the complete leading record when
 * ready; 0 if more frames are needed (caller must wait).  -1 on overflow. */
#define TLS443_REASM_MAX 4
static struct {
    int      used;
    uint16_t conn_id;
    uint32_t last_use;
    uint32_t len;
    uint8_t  buf[18432];          /* > any single ClientHello record (16 KiB max frag + slack) */
} g_tls443_reasm[TLS443_REASM_MAX];
static uint32_t g_tls443_reasm_clock;

static int tls443_reassemble_leading_record(uint16_t conn_id,
                                            const uint8_t *frame, uint32_t len,
                                            const uint8_t **out_ptr, uint32_t *out_len) {
    g_tls443_reasm_clock++;
    int idx = -1;
    for (int i = 0; i < TLS443_REASM_MAX; i++)
        if (g_tls443_reasm[i].used && g_tls443_reasm[i].conn_id == conn_id) { idx = i; break; }
    if (idx < 0) {
        /* Fast path: a single frame already carries a complete leading record →
         * no buffering needed (the common case for small ClientHellos). */
        if (len >= 5) {
            uint32_t reclen = 5u + (((uint32_t)frame[3] << 8) | frame[4]);
            if (len >= reclen) { *out_ptr = frame; *out_len = len; return 1; }
        }
        /* Allocate a reassembly slot (LRU-evict if full). */
        int lru = 0;
        for (int i = 0; i < TLS443_REASM_MAX; i++) {
            if (!g_tls443_reasm[i].used) { lru = i; break; }
            if (g_tls443_reasm[i].last_use < g_tls443_reasm[lru].last_use) lru = i;
        }
        idx = lru;
        g_tls443_reasm[idx].used = 1;
        g_tls443_reasm[idx].conn_id = conn_id;
        g_tls443_reasm[idx].len = 0;
    }
    g_tls443_reasm[idx].last_use = g_tls443_reasm_clock;
    if (g_tls443_reasm[idx].len + len > sizeof g_tls443_reasm[idx].buf) {
        g_tls443_reasm[idx].used = 0;           /* overflow · drop */
        return -1;
    }
    memcpy(g_tls443_reasm[idx].buf + g_tls443_reasm[idx].len, frame, len);
    g_tls443_reasm[idx].len += len;
    /* Complete leading record yet? */
    if (g_tls443_reasm[idx].len >= 5) {
        uint8_t *b = g_tls443_reasm[idx].buf;
        uint32_t reclen = 5u + (((uint32_t)b[3] << 8) | b[4]);
        if (g_tls443_reasm[idx].len >= reclen) {
            *out_ptr = g_tls443_reasm[idx].buf;
            *out_len = g_tls443_reasm[idx].len;  /* hand over everything buffered */
            g_tls443_reasm[idx].used = 0;        /* release; later frames pass through */
            return 1;
        }
    }
    return 0;                                    /* need more frames */
}

static tls13_sess_t *tls13_in_get(uint16_t conn_id) {
    g_tls13_in_clock++;
    tls13_sess_t *lru = &g_tls13_in[0];
    for (int i = 0; i < TLS13_IN_MAX; i++) {
        tls13_sess_t *s = &g_tls13_in[i];
        if (s->used && s->conn_id == conn_id) { s->last_seen = g_tls13_in_clock; return s; }
        if (!s->used) lru = s;
        else if (lru->used && s->last_seen < lru->last_seen) lru = s;
    }
    memset(lru, 0, sizeof *lru);
    lru->used = 1; lru->conn_id = conn_id; lru->last_seen = g_tls13_in_clock;
    printf("[synth-srv] inbound TLS1.3 session open · conn=%u slot=%ld\n",
           conn_id, (long)(lru - g_tls13_in));
    return lru;
}

int main(int argc, char *argv[]) {
    seL4_CPtr recv_ep = SEL4UTILS_INITIAL_EP_SLOT;

    /* argv[1]: override recv EP slot if provided (normally == 1). */
    if (argc > 1 && argv[1]) {
        seL4_CPtr slot = (seL4_CPtr)atol(argv[1]);
        if (slot != 0) recv_ep = slot;
    }

    /* argv[2]: orch callback EP for Phase 3-C response loop. */
    if (argc > 2 && argv[2]) {
        seL4_CPtr cb = (seL4_CPtr)atol(argv[2]);
        if (cb != 0) {
            g_orch_callback_ep = cb;
            printf("[synth-srv] callback EP registered · slot=%lu (Phase 3-C active)\n",
                   (unsigned long)g_orch_callback_ep);
        }
    }

    /* argv[3]: byte-channel readiness (1 = rings mapped by root). */
    if (argc > 3 && argv[3]) {
        g_bytepipe_ready = (atol(argv[3]) != 0) ? 1 : 0;
    }
    if (g_bytepipe_ready) {
        bytepipe_producer_init((bytepipe_ring_t *)BYTEPIPE_P2C_VADDR);
        /* Liveness: read c2p's magic through our RO view.  orch is the c2p
         * producer and ran bytepipe_producer_init at BOOTSTRAP (before us),
         * so a matching magic proves the cross-vspace mapping is live. */
        bytepipe_ring_t *c2p = (bytepipe_ring_t *)BYTEPIPE_C2P_VADDR;
        uint32_t m = __atomic_load_n(&c2p->magic, __ATOMIC_ACQUIRE);
        printf("[synth-srv] bytepipe ready · c2p magic=0x%08x %s\n",
               m, (m == BYTEPIPE_MAGIC) ? "(live)" : "(NOT live!)");
    }

    /* argv[4]: N2-T · inbound framed transport · synth produces in_p2c +
     * verifies orch's in_c2p magic is live cross-vspace. */
    if (argc > 4 && argv[4]) g_bytepipe2_ready = (atol(argv[4]) != 0) ? 1 : 0;
    if (g_bytepipe2_ready) {
        bytepipe_producer_init((bytepipe_ring_t *)BYTEPIPE_IN_P2C_VADDR);
        bytepipe_ring_t *in_c2p = (bytepipe_ring_t *)BYTEPIPE_IN_C2P_VADDR;
        uint32_t m = __atomic_load_n(&in_c2p->magic, __ATOMIC_ACQUIRE);
        printf("[synth-srv] inbound bytepipe ready · in_c2p magic=0x%08x %s\n",
               m, (m == BYTEPIPE_MAGIC) ? "(live)" : "(NOT live!)");
    }

    /* argv[5]: SSH canary shell (Phase B) · synth produces SHELL_IN +
     * consumes SHELL_OUT (orch ran the SHELL_OUT producer_init at BOOTSTRAP). */
    if (argc > 5 && argv[5]) g_bytepipe3_ready = (atol(argv[5]) != 0) ? 1 : 0;
    if (g_bytepipe3_ready) {
        bytepipe_producer_init((bytepipe_ring_t *)BYTEPIPE_SHELL_IN_VADDR);
        bytepipe_ring_t *so = (bytepipe_ring_t *)BYTEPIPE_SHELL_OUT_VADDR;
        uint32_t m = __atomic_load_n(&so->magic, __ATOMIC_ACQUIRE);
        printf("[synth-srv] shell bytepipe ready · shell_out magic=0x%08x %s\n",
               m, (m == BYTEPIPE_MAGIC) ? "(live)" : "(NOT live!)");
    }
    ssh_shell_rings_set_ready(g_bytepipe3_ready);   /* R7 · transport gates on this */

    printf("[synth-srv] spawned · recv_ep=%lu callback_ep=%lu · waiting for Tier 2 redirects\n",
           (unsigned long)recv_ep, (unsigned long)g_orch_callback_ep);

    /* γ-3-γ-2a · prove BearSSL runs a full TLS 1.2 handshake on-target. */
    tls_selftest_run();

    while (1) {
        /* SSH canary shell active: do NOT block on the doorbell — busybox stdout
         * (SHELL_OUT) and the attacker's typed commands (in_c2p) flow WITHOUT a
         * coincident SYNTH_INBOUND doorbell while orch is inside busybox's
         * nested fault loop. Busy-poll (NBRecv + Yield) so the in_c2p drain +
         * SHELL_OUT pump run every iteration. Revert to blocking Recv when no
         * shell is live (the normal idle path). */
        int shell_live = (g_bytepipe3_ready && g_ssh_shell_conn != 0);
        seL4_MessageInfo_t info;
        if (shell_live) { seL4_Word b = 0; info = seL4_NBRecv(recv_ep, &b); }
        else            { info = seL4_Recv(recv_ep, NULL); }
        seL4_Word op = seL4_MessageInfo_get_label(info);
        if (op == ORCH_OP_SYNTH_REDIRECT) {
            uint32_t pid        = (uint32_t)seL4_GetMR(0);
            uint32_t dst_ip_be  = (uint32_t)seL4_GetMR(1);
            uint16_t dst_port_be = (uint16_t)seL4_GetMR(2);
            uint32_t len        = (uint32_t)seL4_GetMR(3);

            /* γ-3-γ-1 · drain the exact sent bytes from c2p (the doorbell's
             * `len` is now advisory; the ring cursor is authoritative). */
            static uint8_t c2p_rx[BYTEPIPE_DATA_BYTES];
            uint32_t got = 0;
            if (g_bytepipe_ready) {
                bytepipe_ring_t *c2p = (bytepipe_ring_t *)BYTEPIPE_C2P_VADDR;
                got = bytepipe_pull(c2p, &g_c2p_rd, c2p_rx, sizeof(c2p_rx));
                char head[33];
                uint32_t hn = got < 32 ? got : 32;
                memcpy(head, c2p_rx, hn);
                head[hn] = '\0';
                printf("[synth-srv] c2p rx %u bytes · head='%s'\n", got, head);
            }

            /* Phase 3-B: log response_profile banner + body. */
            response_profile_dispatch(pid, dst_ip_be, dst_port_be, len);

            /* Phase 3-C: send the reply back to orch.  Over the byte channel
             * the body travels in p2c (no 64-byte cap); the doorbell carries
             * only routing + length.  Only fires if root wired argv[2]. */
            if (g_orch_callback_ep != 0) {
                /* γ-3-γ-1 echo proof: when the drained request carries the boot
                 * probe marker, reply with the EXACT drained bytes so the
                 * round-trip is byte-identical (the deterministic gate).  Over
                 * the byte channel the body travels in p2c (no 64-byte cap) and
                 * the response is a fire-and-forget NBSend wake — orch drains
                 * p2c opportunistically, so the push is observable even if the
                 * wake is dropped (the ring cursor is the source of truth). */
                if (g_bytepipe_ready && got >= 15 &&
                    memcmp(c2p_rx, "BYTEPIPE-PROBE-", 15) == 0) {
                    bytepipe_ring_t *p2c = (bytepipe_ring_t *)BYTEPIPE_P2C_VADDR;
                    bytepipe_set_meta(p2c, pid, dst_ip_be, dst_port_be);
                    uint32_t pushed = bytepipe_push(p2c, c2p_rx, got);
                    printf("[synth-srv] p2c tx · pid=%u pushed=%u bytes (echo · >64 ok) · SOTNET·bytepipe OK\n",
                           pid, pushed);
                    seL4_NBSend(g_orch_callback_ep,
                                seL4_MessageInfo_new(ORCH_OP_SYNTH_RESPONSE,
                                                     0, 0, 0));
                } else if (g_bytepipe_ready && got > 0) {
                    /* γ-3-γ-2b · real TLS · feed the client's flight into the
                     * per-connection engine, pump, drain the response to p2c.
                     * The session persists across redirect doorbells. */
                    tls_sess_t *s = tls_sess_get(pid, dst_ip_be, dst_port_be);
                    br_ssl_engine_context *eng = &s->sc.eng;
                    uint32_t fed = 0;
                    while (fed < got) {
                        size_t rlen = 0;
                        unsigned char *rbuf = br_ssl_engine_recvrec_buf(eng, &rlen);
                        if (rlen == 0) break;        /* engine must flush output first */
                        size_t n = (got - fed < rlen) ? (size_t)(got - fed) : rlen;
                        memcpy(rbuf, c2p_rx + fed, n);
                        br_ssl_engine_recvrec_ack(eng, n);
                        fed += (uint32_t)n;
                    }
                    /* γ-3-γ-2c · service the decrypted application stream on top
                     * of the proven record pump. The client's encrypted beacon
                     * record was just fed into recvrec; the engine has decrypted
                     * it, so recvapp now yields the plaintext (deception
                     * evidence). Reply once with the response_profile "tasking", encrypted
                     * via sendapp + flush; the existing sendrec drain below carries
                     * those records to p2c in this same iteration. */
                    {
                        size_t alen = 0;
                        unsigned char *abuf = br_ssl_engine_recvapp_buf(eng, &alen);
                        if (abuf && alen > 0) {
                            char beacon[41];
                            uint32_t bn = alen < 40 ? (uint32_t)alen : 40;
                            memcpy(beacon, abuf, bn);
                            beacon[bn] = '\0';
                            printf("[synth-srv] TLS app-data rx · pid=%u '%s'\n",
                                   pid, beacon);
                            br_ssl_engine_recvapp_ack(eng, alen);

                            if (!s->app_replied) {
                                char banner[128], body[256];
                                if (response_profile_get_payload(dst_ip_be, dst_port_be,
                                                        banner, sizeof banner,
                                                        body,   sizeof body) != 0) {
                                    /* response_profile miss → short fixed body so the
                                     * round-trip still completes (spec error path) */
                                    strcpy(body, "sotos-phantom: ack\n");
                                }
                                size_t blen = strlen(body), off = 0;
                                while (off < blen) {
                                    size_t wlen = 0;
                                    unsigned char *wbuf =
                                        br_ssl_engine_sendapp_buf(eng, &wlen);
                                    if (!wbuf || wlen == 0) break; /* not writable yet */
                                    size_t n = (blen - off < wlen)
                                               ? (blen - off) : wlen;
                                    memcpy(wbuf, body + off, n);
                                    br_ssl_engine_sendapp_ack(eng, n);
                                    off += n;
                                }
                                br_ssl_engine_flush(eng, 0);
                                s->app_replied = 1;
                                printf("[synth-srv] TLS app-data tx · pid=%u response_profile %zu B (encrypted)\n",
                                       pid, blen);
                            }
                        }
                    }
                    bytepipe_ring_t *p2c = (bytepipe_ring_t *)BYTEPIPE_P2C_VADDR;
                    bytepipe_set_meta(p2c, pid, dst_ip_be, dst_port_be);
                    uint32_t pushed = 0;
                    for (;;) {
                        size_t slen = 0;
                        unsigned char *sbuf = br_ssl_engine_sendrec_buf(eng, &slen);
                        if (slen == 0) break;
                        uint32_t w = bytepipe_push(p2c, sbuf, (uint32_t)slen);
                        br_ssl_engine_sendrec_ack(eng, w);
                        pushed += w;
                        if (w < slen) break;          /* ring full · backpressure */
                    }
                    (void)fed;
                    if (pushed) {
                        printf("[synth-srv] p2c tx · pid=%u pushed=%u bytes (tls)\n",
                               pid, pushed);
                        seL4_NBSend(g_orch_callback_ep,
                                    seL4_MessageInfo_new(ORCH_OP_SYNTH_RESPONSE,
                                                         0, 0, 0));
                    }
                    unsigned stf = br_ssl_engine_current_state(eng);
                    if (!s->announced && (stf & BR_SSL_SENDAPP) &&
                        br_ssl_engine_last_error(eng) == 0) {
                        br_ssl_session_parameters sp;
                        br_ssl_engine_get_session_parameters(eng, &sp);
                        printf("[synth-srv] TLS handshake complete · pid=%u suite=0x%04x\n",
                               pid, (unsigned)sp.cipher_suite);
                        s->announced = 1;
                    }
                    int terr = br_ssl_engine_last_error(eng);
                    if (terr != 0) {
                        printf("[synth-srv] TLS error · pid=%u err=%d\n", pid, terr);
                        s->used = 0;  /* drop the slot */
                    }
                } else {
                    char banner[128], body[256];
                    if (response_profile_get_payload(dst_ip_be, dst_port_be,
                                            banner, sizeof(banner),
                                            body,   sizeof(body)) == 0) {
                        size_t body_len = strlen(body);
                        if (g_bytepipe_ready) {
                            /* Cap-free path: body in p2c, NBSend wake to orch. */
                            bytepipe_ring_t *p2c =
                                (bytepipe_ring_t *)BYTEPIPE_P2C_VADDR;
                            bytepipe_set_meta(p2c, pid, dst_ip_be, dst_port_be);
                            uint32_t pushed = bytepipe_push(
                                p2c, (const uint8_t *)body, (uint32_t)body_len);
                            printf("[synth-srv] p2c tx · pid=%u pushed=%u bytes (response_profile)\n",
                                   pid, pushed);
                            seL4_NBSend(g_orch_callback_ep,
                                        seL4_MessageInfo_new(ORCH_OP_SYNTH_RESPONSE,
                                                             0, 0, 0));
                        } else {
                            /* Fallback (channel off): pack <=64 B into MRs. */
                            if (body_len > 64) body_len = 64;
                            seL4_SetMR(0, (seL4_Word)pid);
                            seL4_SetMR(1, (seL4_Word)dst_ip_be);
                            seL4_SetMR(2, (seL4_Word)dst_port_be);
                            seL4_SetMR(3, (seL4_Word)body_len);
                            size_t nwords = (body_len + 7) / 8;
                            for (size_t i = 0; i < nwords; ++i) {
                                seL4_Word w = 0;
                                size_t chunk = (body_len - i * 8 < 8)
                                               ? body_len - i * 8 : 8;
                                memcpy(&w, body + i * 8, chunk);
                                seL4_SetMR(4 + i, w);
                            }
                            seL4_Call(g_orch_callback_ep,
                                      seL4_MessageInfo_new(ORCH_OP_SYNTH_RESPONSE,
                                                           0, 0, 4 + nwords));
                            printf("[synth-srv] Phase 3-C · response IPC sent to orch · pid=%u body_len=%zu\n",
                                   pid, body_len);
                        }
                    }
                }
            }
        } else if (op == ORCH_OP_SYNTH_INBOUND || shell_live) {
            /* (`|| shell_live`: while an SSH shell is up we busy-poll, so this
             *  inbound drain + SHELL_OUT pump must run every iteration even when
             *  NBRecv returned no doorbell — op is then 0.)
             * N2-T/N2-R · drain inbound request frames from in_c2p and answer each
             * on in_p2c (same conn_id).  Port 80 → synthetic-Nginx response_profile via http_route;
             * other ports still echo (SSH/HTTPS response_profiles land in Phases B/C).  orch
             * drains in_p2c by poll, so no callback NBSend is needed here. */
            if (g_bytepipe2_ready) {
                bytepipe_ring_t *in_c2p = (bytepipe_ring_t *)BYTEPIPE_IN_C2P_VADDR;
                bytepipe_ring_t *in_p2c = (bytepipe_ring_t *)BYTEPIPE_IN_P2C_VADDR;
                bytepipe_frame_hdr_t fh;
                static uint8_t fbuf[BYTEPIPE_DATA_BYTES];
                static uint8_t respbuf[BYTEPIPE_DATA_BYTES];
                while (bytepipe_pull_frame(in_c2p, &g_in_c2p_rd, &fh, fbuf, sizeof fbuf)) {
                    if (fh.local_port == BYTEPIPE_PORT_SHELL_EOF) {
                        /* Phase B · R4 · busybox exited (orch pushed SHELL_EOF on
                         * in_c2p) → CHANNEL_EOF + CHANNEL_CLOSE on the wire + clear
                         * the live-shell state so a new shell can start. */
                        uint32_t rlen = ssh_emit_channel_close(fh.conn_id, respbuf, sizeof respbuf);
                        if (rlen) bytepipe_push_frame(in_p2c, fh.conn_id, 22, respbuf, rlen);
                        if (g_ssh_shell_conn == fh.conn_id) g_ssh_shell_conn = 0;
                        ssh_shell_set_busy(0);
                        printf("[synth-srv] ssh-shell EOF · conn=%u → CHANNEL_CLOSE %u bytes\n",
                               fh.conn_id, rlen);
                        continue;
                    }
                    if (fh.local_port == 80) {
                        /* N2-R Phase A · serve the synthetic Nginx response_profile in-vspace. */
                        uint32_t rlen = http_route(fbuf, fh.len, respbuf, sizeof respbuf);
                        bytepipe_push_frame(in_p2c, fh.conn_id, fh.local_port, respbuf, rlen);
                        printf("[synth-srv] inbound HTTP · conn=%u port=%u req=%u resp=%u bytes\n",
                               fh.conn_id, fh.local_port, fh.len, rlen);
                    } else if (fh.local_port == 22) {
                        /* N2-R Phase B · server-speaks-first SSH response_profile (stateful by conn). */
                        uint32_t rlen = ssh_respond(fh.conn_id, fbuf, fh.len, respbuf, sizeof respbuf);
                        if (rlen) {
                            bytepipe_push_frame(in_p2c, fh.conn_id, 22, respbuf, rlen);
                            printf("[synth-srv] inbound SSH · conn=%u req=%u resp=%u bytes\n",
                                   fh.conn_id, fh.len, rlen);
                        }
                        /* Phase B · the shell-request handler set a pending flag →
                         * signal orch to spawn busybox (once) on in_p2c, and mark the
                         * shell live (R2 · refuse a 2nd; track the conn for SHELL_OUT). */
                        if (g_bytepipe3_ready && ssh_take_shell_start(fh.conn_id)) {
                            /* exec-mode carries the command in the SHELL_START payload so
                             * orch runs `bash -c <cmd>` then closes; an interactive shell
                             * pushes an empty SHELL_START (→ bash -i). */
                            extern uint32_t ssh_take_exec_cmd(uint16_t, uint8_t *, uint32_t);
                            uint8_t excmd[256];
                            uint32_t exlen = ssh_take_exec_cmd(fh.conn_id, excmd, sizeof excmd);
                            bytepipe_push_frame(in_p2c, fh.conn_id, BYTEPIPE_PORT_SHELL_START,
                                                exlen ? excmd : NULL, exlen);
                            g_ssh_shell_conn = fh.conn_id;
                            ssh_shell_set_busy(1);
                            printf("[synth-srv] ssh-shell START · conn=%u → orch\n", fh.conn_id);
                        }
                        /* Phase B · R4 · attacker disconnected (CHANNEL_EOF/CLOSE) →
                         * tell orch to reap busybox (SHELL_KILL on in_p2c). */
                        if (g_bytepipe3_ready && ssh_take_client_eof(fh.conn_id)) {
                            bytepipe_push_frame(in_p2c, fh.conn_id, BYTEPIPE_PORT_SHELL_KILL, NULL, 0);
                            printf("[synth-srv] ssh-shell KILL · conn=%u → orch\n", fh.conn_id);
                        }
                    } else if (fh.local_port == 443) {
                        /* ε1 · the version decision needs a COMPLETE leading TLS
                         * record (the ClientHello), which a real openssl client
                         * splits across frames.  While undecided, reassemble; once
                         * decided, frames flow straight through (both paths buffer
                         * subsequent records internally). */
                        const uint8_t *dbuf = fbuf;
                        uint32_t       dlen = fh.len;
                        if (tls_ver_peek(fh.conn_id) == 0) {
                            const uint8_t *rec = NULL; uint32_t reclen = 0;
                            int rr = tls443_reassemble_leading_record(fh.conn_id, fbuf, fh.len, &rec, &reclen);
                            if (rr == 0) continue;                 /* need more frames */
                            if (rr < 0) {                          /* overflow · drop conn */
                                printf("[synth-srv] inbound TLS · conn=%u leading-record overflow\n", fh.conn_id);
                                continue;
                            }
                            dbuf = rec; dlen = reclen;
                        }
                        if (tls_ver_decide(fh.conn_id, dbuf, dlen) == 1) {
                            /* ε1 · TLS 1.3 path: feed the inbound frame; push any produced records. */
                            tls13_sess_t *t = tls13_in_get(fh.conn_id);
                            /* server flight (SH+EE+Cert+CertVerify+Finished) < 2 KiB; 8192 is ample */
                            static uint8_t t13_out[8192];
                            uint32_t t13_olen = 0;
                            int rc = tls13_inbound_feed(t, dbuf, dlen, t13_out, sizeof t13_out, &t13_olen, http_route);
                            if (rc == 0 && t13_olen) {
                                uint32_t off = 0;
                                const uint32_t lim = BYTEPIPE_DATA_BYTES - BYTEPIPE_FRAME_HDR_SZ;
                                while (off < t13_olen) {
                                    uint32_t k = (t13_olen - off < lim) ? (t13_olen - off) : lim;
                                    bytepipe_push_frame(in_p2c, fh.conn_id, 443, t13_out + off, k);
                                    off += k;
                                }
                            }
                            if (rc != 0) {
                                printf("[synth-srv] inbound TLS1.3 error · conn=%u\n", fh.conn_id);
                                t->used = 0;
                            } else {
                                /* ε3: report the SERVER-selected cipher suite (set on
                                 * CH1 by select_suite) — proves the server, not just
                                 * openssl, chose the suite. */
                                printf("[synth-srv] inbound TLS1.3 · conn=%u in=%u out=%u suite=0x%04x\n",
                                       fh.conn_id, dlen, t13_olen,
                                       (unsigned)(t->suite ? t->suite->id : 0));
                            }
                        } else {
                            /* TLS 1.2 mine2g path — UNCHANGED */
                            /* N2-R Phase C · terminate real TLS per conn_id, serve http_route
                             * inside the tunnel.  Reuses the SHIPPED BearSSL record-pump. */
                            tls_sess_t *s = tls_sess_get_inbound(fh.conn_id);
                            br_ssl_engine_context *eng = &s->sc.eng;
                            /* feed the client's record bytes (handshake or app-data) */
                            uint32_t fed = 0;
                            while (fed < dlen) {
                                size_t rl = 0; unsigned char *rb = br_ssl_engine_recvrec_buf(eng, &rl);
                                if (rl == 0) break;
                                size_t k = (dlen - fed < rl) ? (size_t)(dlen - fed) : rl;
                                memcpy(rb, dbuf + fed, k); br_ssl_engine_recvrec_ack(eng, k);
                                fed += (uint32_t)k;
                            }
                            /* Drain ALL decrypted app-data this doorbell (a request may span
                             * multiple TLS records in one frame).  recvapp-once would leave a
                             * leftover chunk → a spurious 2nd response next doorbell. */
                            for (;;) {
                                size_t al = 0; unsigned char *ab = br_ssl_engine_recvapp_buf(eng, &al);
                                if (!ab || al == 0) break;
                                uint32_t rlen = http_route(ab, (uint32_t)al, respbuf, sizeof respbuf);
                                br_ssl_engine_recvapp_ack(eng, al);
                                size_t off = 0;
                                while (off < rlen) {
                                    size_t wl = 0; unsigned char *wb = br_ssl_engine_sendapp_buf(eng, &wl);
                                    if (!wb || wl == 0) break;
                                    size_t k = (rlen - off < wl) ? (rlen - off) : wl;
                                    memcpy(wb, respbuf + off, k); br_ssl_engine_sendapp_ack(eng, k);
                                    off += k;
                                }
                                br_ssl_engine_flush(eng, 0);
                            }
                            /* drain TLS records (handshake and/or encrypted reply) to in_p2c.
                             * No backpressure: cap each record to the frameable size and ALWAYS
                             * ack what BearSSL offered (never under-ack → no infinite re-offer). */
                            uint32_t pushed = 0;
                            const uint32_t push_limit = BYTEPIPE_DATA_BYTES - BYTEPIPE_FRAME_HDR_SZ;
                            for (;;) {
                                size_t sl = 0; unsigned char *sb = br_ssl_engine_sendrec_buf(eng, &sl);
                                if (sl == 0) break;
                                uint32_t k = (uint32_t)(sl > push_limit ? push_limit : sl);
                                (void)bytepipe_push_frame(in_p2c, fh.conn_id, 443, sb, k);
                                br_ssl_engine_sendrec_ack(eng, (size_t)k);
                                pushed += k;
                            }
                            unsigned st = br_ssl_engine_current_state(eng);
                            if (!s->announced && (st & BR_SSL_SENDAPP) && br_ssl_engine_last_error(eng) == 0) {
                                printf("[synth-srv] inbound TLS handshake complete · conn=%u\n", fh.conn_id);
                                s->announced = 1;
                            }
                            int terr = br_ssl_engine_last_error(eng);
                            if (terr != 0) { printf("[synth-srv] inbound TLS error · conn=%u err=%d\n", fh.conn_id, terr); s->used = 0; }
                            if (pushed) printf("[synth-srv] inbound HTTPS · conn=%u pushed=%u bytes\n", fh.conn_id, pushed);
                        } /* end TLS 1.2 mine2g else */
                    } else {
                        /* Unknown ports keep echoing (harmless). */
                        bytepipe_push_frame(in_p2c, fh.conn_id, fh.local_port, fbuf, fh.len);
                        printf("[synth-srv] inbound echo · conn=%u port=%u %u bytes\n",
                               fh.conn_id, fh.local_port, fh.len);
                    }
                }

                /* Phase B · R5/R6 · SHELL_OUT pump.  In the SAME single-threaded
                 * main-loop body as the inbound dispatch (sequential, so seq_out/
                 * cc_out stay coherent · R6), drain busybox stdout FULLY each pass
                 * (R5 · cap 1 KB per pull, one encrypted CHANNEL_DATA per chunk →
                 * a >1 KB burst like canary /etc/passwd is never truncated/stranded). */
                if (g_bytepipe3_ready && g_ssh_shell_conn != 0) {
                    bytepipe_ring_t *so = (bytepipe_ring_t *)BYTEPIPE_SHELL_OUT_VADDR;
                    static uint8_t sbuf[1024];
                    static uint8_t resp[1024 + 64];
                    uint32_t n;
                    while ((n = bytepipe_pull(so, &g_shell_out_rd, sbuf, sizeof sbuf)) > 0) {
                        uint32_t rl = ssh_emit_channel_data(g_ssh_shell_conn, sbuf, n,
                                                            resp, sizeof resp);
                        if (rl) bytepipe_push_frame(in_p2c, g_ssh_shell_conn, 22, resp, rl);
                        if (n < sizeof sbuf) break;   /* ring drained */
                    }
                }
            }
        } else if (op == ORCH_OP_SYNTH_INSTALL) {
            uint32_t dst_ip_be   = (uint32_t)seL4_GetMR(0);
            uint16_t dst_port_be = (uint16_t)seL4_GetMR(1);
            response_profile_kind_t kind  = (response_profile_kind_t)seL4_GetMR(2);
            int rc = response_profile_install(dst_ip_be, dst_port_be, kind);
            printf("[synth-srv] install · dst=%u.%u.%u.%u:%u kind=%d rc=%d\n",
                   dst_ip_be & 0xFF, (dst_ip_be >> 8) & 0xFF,
                   (dst_ip_be >> 16) & 0xFF, (dst_ip_be >> 24) & 0xFF,
                   ((dst_port_be & 0xFF) << 8) | ((dst_port_be >> 8) & 0xFF),
                   (int)kind, rc);
        } else {
            printf("[synth-srv] unknown op=%lu\n", (unsigned long)op);
        }
        /* N2-T · ORCH_OP_SYNTH_INBOUND is delivered by orch via seL4_NBSend
         * (no reply cap) and its reply travels back over the in_p2c ring, so it
         * needs no IPC reply.  Replying to its absent reply cap is a wasted
         * syscall on every inbound segment — skip it.  (The other ops also
         * arrive via NBSend today, but their shared Reply is the pre-existing
         * harmless pattern; only the new inbound op is guarded here to avoid the
         * per-segment waste.) */
        if (op != ORCH_OP_SYNTH_INBOUND && !shell_live)
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
        /* SSH shell busy-poll: cooperative yield so we re-drain in_c2p + pump
         * SHELL_OUT promptly without burning the CPU. (NBRecv above won't block.) */
        if (shell_live) seL4_Yield();
    }
    return 0;
}
