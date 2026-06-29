/* sotOs · sotNet · arc β · TCP/IP fingerprint logic. See tcp_fp.h. */
#include <sotnet/tcp_fp.h>

/* Global incrementing IP-ID source. Module-global mutable state (still leaf at LINK
 * time — no external symbols). Starts at 0 -> first sotfp_next_ip_id() returns 1. */
static uint16_t g_ip_id = 0;

uint16_t sotfp_next_ip_id(void) { return ++g_ip_id; }
void     sotfp_ip_id_seed(uint16_t seed) { g_ip_id = seed; }

void sotfp_ip_set(void *ipv4_hdr20, uint16_t ip_id_host, int df_set)
{
    uint8_t *p = (uint8_t *)ipv4_hdr20;
    p[4] = (uint8_t)(ip_id_host >> 8);     /* ident hi (network/big-endian) */
    p[5] = (uint8_t)(ip_id_host & 0xFFu);  /* ident lo */
    p[6] = df_set ? 0x40 : 0x00;           /* flags hi: DF=0x4000 -> 0x40; frag-off bits 0 */
    p[7] = 0x00;                           /* frag-offset lo = 0 (unfragmented) */
    p[8] = (uint8_t)SOTFP_TTL;             /* ttl = 64 */
}

uint8_t sotfp_parse_wscale(const uint8_t *opts, size_t opt_len)
{
    size_t i = 0;
    while (i < opt_len) {
        uint8_t kind = opts[i];
        if (kind == 0) break;                 /* EOL */
        if (kind == 1) { i++; continue; }     /* NOP */
        if (i + 1 >= opt_len) break;          /* need a length byte */
        uint8_t olen = opts[i + 1];
        if (olen < 2 || i + olen > opt_len) break;   /* malformed/oversized */
        if (kind == 3 && olen == 3) {                /* Window Scale */
            uint8_t ws = opts[i + 2];
            return ws > 14 ? 14 : ws;                /* RFC 7323 caps at 14 */
        }
        i += olen;
    }
    return 0;
}

sotfp_rst_t sotfp_rst_fields(uint8_t in_flags, uint32_t in_seq,
                             uint32_t in_ack, uint32_t seg_len)
{
    sotfp_rst_t r;
    if (in_flags & SOTFP_F_ACK) {
        r.seq = in_ack; r.ack = 0; r.flags = (uint8_t)SOTFP_F_RST;
    } else {
        r.seq = 0; r.ack = in_seq + seg_len;
        r.flags = (uint8_t)(SOTFP_F_RST | SOTFP_F_ACK);
    }
    return r;
}

uint8_t sotfp_synack_flags(uint8_t in_syn_flags)
{
    uint8_t f = (uint8_t)(SOTFP_F_SYN | SOTFP_F_ACK);
    if ((in_syn_flags & SOTFP_F_ECE) && (in_syn_flags & SOTFP_F_CWR))
        f |= (uint8_t)SOTFP_F_ECE;
    return f;
}

sotfp_action_t sotfp_unsolicited_action(uint8_t in_flags, int has_listener)
{
    int syn = (in_flags & SOTFP_F_SYN) != 0;
    int ack = (in_flags & SOTFP_F_ACK) != 0;
    int rst = (in_flags & SOTFP_F_RST) != 0;

    if (rst) return SOTFP_ACT_DROP;                 /* never answer a RST */
    if (syn && !ack)                                 /* pure SYN (T3 Xmas-with-SYN too) */
        return has_listener ? SOTFP_ACT_SYN_ACCEPT : SOTFP_ACT_RST;
    if (!ack)                                         /* NULL / FIN / Xmas (no ACK) */
        return has_listener ? SOTFP_ACT_DROP : SOTFP_ACT_RST;
    return SOTFP_ACT_RST;                             /* unmatched ACK / SYN+ACK -> RST */
}
