/* Host unit test for src/sotnet/tcp_fp.c (arc β primary gate).
 * Build+run on the host (NOT part of `just build`):
 *   cc -I include src/test/sotnet_fp_unit/sotnet_fp_unit.c src/sotnet/tcp_fp.c \
 *      -o /tmp/sotnet_fp_unit && /tmp/sotnet_fp_unit
 */
#include <sotnet/tcp_fp.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL: %s (line %d)\n", #c, __LINE__); fails++; } } while (0)

int main(void)
{
    /* --- sotfp_ip_set: SYN-ACK/RST profile (id 0, DF set) --- */
    uint8_t ip[20]; memset(ip, 0xAB, sizeof ip);
    sotfp_ip_set(ip, 0, 1);
    CHECK(ip[4] == 0x00 && ip[5] == 0x00);      /* IP-ID 0 */
    CHECK(ip[6] == 0x40 && ip[7] == 0x00);      /* DF set, big-endian 0x4000 */
    CHECK(ip[8] == 64);                          /* TTL */
    /* --- sotfp_ip_set: ICMP/UDP profile (counter id, DF clear) --- */
    memset(ip, 0xAB, sizeof ip);
    sotfp_ip_set(ip, 0x1234, 0);
    CHECK(ip[4] == 0x12 && ip[5] == 0x34);      /* IP-ID written network/big-endian */
    CHECK(ip[6] == 0x00 && ip[7] == 0x00);      /* DF CLEAR (ICMP/UDP) */
    CHECK(ip[8] == 64);

    /* --- sotfp_next_ip_id increments; seed resets (nmap class "I") --- */
    sotfp_ip_id_seed(100);
    CHECK(sotfp_next_ip_id() == 101);
    CHECK(sotfp_next_ip_id() == 102);
    sotfp_ip_id_seed(0);
    CHECK(sotfp_next_ip_id() == 1);             /* unseeded base -> first id nonzero */

    /* --- sotfp_parse_wscale --- */
    /* The real Linux SYN-ACK option block: MSS,NOP,NOP,SACKperm,NOP,WS=10 */
    const uint8_t opts_ws10[] = {0x02,0x04,0x05,0xb4, 0x01,0x01, 0x04,0x02, 0x01, 0x03,0x03,0x0a};
    CHECK(sotfp_parse_wscale(opts_ws10, sizeof opts_ws10) == 10);
    const uint8_t opts_ws7[] = {0x03,0x03,0x07};
    CHECK(sotfp_parse_wscale(opts_ws7, sizeof opts_ws7) == 7);
    const uint8_t opts_none[] = {0x02,0x04,0x05,0xb4, 0x01,0x01, 0x04,0x02};
    CHECK(sotfp_parse_wscale(opts_none, sizeof opts_none) == 0);
    /* Truncated WS option (claims len 3 but only 2 bytes left) -> 0, no OOB. */
    const uint8_t opts_trunc[] = {0x03,0x03};
    CHECK(sotfp_parse_wscale(opts_trunc, sizeof opts_trunc) == 0);
    CHECK(sotfp_parse_wscale(opts_ws10, 0) == 0);
    /* Over-cap WS clamps to 14. */
    const uint8_t opts_big[] = {0x03,0x03,0x20};
    CHECK(sotfp_parse_wscale(opts_big, sizeof opts_big) == 14);

    /* --- sotfp_rst_fields --- */
    /* RST to a SYN (no ACK): seq=0, ack=in_seq+1, RST|ACK. */
    sotfp_rst_t r = sotfp_rst_fields(SOTFP_F_SYN, 1000, 0, 1);
    CHECK(r.seq == 0 && r.ack == 1001 && r.flags == (SOTFP_F_RST | SOTFP_F_ACK));
    /* RST to a bare ACK: seq=in_ack, ack=0, RST (no ACK bit). */
    r = sotfp_rst_fields(SOTFP_F_ACK, 5000, 7777, 0);
    CHECK(r.seq == 7777 && r.ack == 0 && r.flags == SOTFP_F_RST);
    /* RST to FIN+2 bytes data: seg_len = 2 + 1(FIN) = 3. */
    r = sotfp_rst_fields(SOTFP_F_FIN, 200, 0, 3);
    CHECK(r.seq == 0 && r.ack == 203 && r.flags == (SOTFP_F_RST | SOTFP_F_ACK));

    /* --- sotfp_synack_flags --- */
    CHECK(sotfp_synack_flags(SOTFP_F_SYN) == (SOTFP_F_SYN | SOTFP_F_ACK));
    CHECK(sotfp_synack_flags(SOTFP_F_SYN | SOTFP_F_ECE | SOTFP_F_CWR)
          == (SOTFP_F_SYN | SOTFP_F_ACK | SOTFP_F_ECE));
    CHECK(sotfp_synack_flags(SOTFP_F_SYN | SOTFP_F_ECE)   /* ECE without CWR -> no echo */
          == (SOTFP_F_SYN | SOTFP_F_ACK));
    CHECK(sotfp_synack_flags(SOTFP_F_SYN | SOTFP_F_CWR)   /* CWR without ECE -> no echo */
          == (SOTFP_F_SYN | SOTFP_F_ACK));

    /* --- sotfp_unsolicited_action (the T2-T7 table) --- */
    CHECK(sotfp_unsolicited_action(SOTFP_F_SYN, 1) == SOTFP_ACT_SYN_ACCEPT);  /* SYN -> open */
    CHECK(sotfp_unsolicited_action(SOTFP_F_SYN, 0) == SOTFP_ACT_RST);          /* T5 SYN->closed */
    CHECK(sotfp_unsolicited_action(0x00, 1) == SOTFP_ACT_DROP);                /* T2 NULL->open */
    CHECK(sotfp_unsolicited_action(0x00, 0) == SOTFP_ACT_RST);                 /* NULL->closed */
    CHECK(sotfp_unsolicited_action(SOTFP_F_FIN|SOTFP_F_PSH|SOTFP_F_URG, 1) == SOTFP_ACT_DROP); /* T7 Xmas->open */
    CHECK(sotfp_unsolicited_action(SOTFP_F_FIN|SOTFP_F_PSH|SOTFP_F_URG, 0) == SOTFP_ACT_RST);  /* T7 Xmas->closed */
    CHECK(sotfp_unsolicited_action(SOTFP_F_ACK, 1) == SOTFP_ACT_RST);          /* T4 ACK->open */
    CHECK(sotfp_unsolicited_action(SOTFP_F_ACK, 0) == SOTFP_ACT_RST);          /* T6 ACK->closed */
    CHECK(sotfp_unsolicited_action(SOTFP_F_RST, 1) == SOTFP_ACT_DROP);         /* never answer RST */
    CHECK(sotfp_unsolicited_action(SOTFP_F_RST, 0) == SOTFP_ACT_DROP);
    CHECK(sotfp_unsolicited_action(SOTFP_F_SYN|SOTFP_F_FIN, 1) == SOTFP_ACT_SYN_ACCEPT); /* T3 SYN wins */
    CHECK(sotfp_unsolicited_action(SOTFP_F_SYN|SOTFP_F_ACK, 0) == SOTFP_ACT_RST);        /* stray SYN+ACK -> closed */
    CHECK(sotfp_unsolicited_action(SOTFP_F_SYN|SOTFP_F_ACK, 1) == SOTFP_ACT_RST);        /* stray SYN+ACK -> open */
    /* adversarial WScale parse: olen=0 must not hang/OOB */
    { const uint8_t bad[] = {0x03,0x00,0x0a}; CHECK(sotfp_parse_wscale(bad, sizeof bad) == 0); }

    if (fails == 0) printf("[sotnet_fp] all cases OK\n");
    else            printf("[sotnet_fp] %d FAIL\n", fails);
    return fails ? 1 : 0;
}
