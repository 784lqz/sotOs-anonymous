/* sotOs · host unit test for the SSH wire encoders (arc-ζ1).
 * Byte-exact mpint/string vectors (RFC 4251 §5) incl. the 256-byte RSA-modulus
 * boundary (>127 kept length, +1 leading-zero) — the load-bearing case the
 * 5-critic flagged. Build: just test-ssh-kex-unit. */
#include <net-synth/ssh_wire.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0;

static void hex(const uint8_t *b, uint32_t n, char *out) {
    static const char *H = "0123456789abcdef";
    for (uint32_t i = 0; i < n; ++i) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = 0;
}

/* check: encode mpint(be[0..n)) and compare to the expected hex string */
static void chk_mpint(const char *name, const uint8_t *be, uint32_t n, const char *expect_hex) {
    uint8_t buf[512]; char got[1100];
    uint32_t off = ssh_put_mpint(buf, 0, sizeof buf, be, n);
    if (off == SSH_WIRE_ERR) { printf("FAIL %-22s overflow\n", name); g_fail++; return; }
    hex(buf, off, got);
    if (strcmp(got, expect_hex) == 0) printf("PASS %-22s %s\n", name, got);
    else { printf("FAIL %-22s got=%s want=%s\n", name, got, expect_hex); g_fail++; }
}

static void chk_string(const char *name, const char *s, const char *expect_hex) {
    uint8_t buf[64]; char got[160];
    uint32_t off = ssh_put_cstr(buf, 0, sizeof buf, s);
    if (off == SSH_WIRE_ERR) { printf("FAIL %-22s overflow\n", name); g_fail++; return; }
    hex(buf, off, got);
    if (strcmp(got, expect_hex) == 0) printf("PASS %-22s %s\n", name, got);
    else { printf("FAIL %-22s got=%s want=%s\n", name, got, expect_hex); g_fail++; }
}

int main(void) {
    /* RFC 4251 §5 worked examples */
    chk_mpint("mpint(0)",            (const uint8_t[]){0}, 1, "00000000");
    chk_mpint("mpint(empty)",        (const uint8_t*)"",   0, "00000000");
    chk_mpint("mpint(0x80)",         (const uint8_t[]){0x00,0x80}, 2, "0000000200" "80");
    chk_mpint("mpint(0x9a37...)",    (const uint8_t[]){0x09,0xa3,0x78,0xf9,0xb2,0xe3,0x32,0xa7}, 8,
              "0000000809a378f9b2e332a7");
    chk_mpint("mpint(leadzeros)",    (const uint8_t[]){0x00,0x00,0x12,0x34}, 4, "000000021234");
    chk_mpint("mpint(0xff)",         (const uint8_t[]){0xff}, 1, "0000000200ff");
    chk_mpint("mpint(e=010001)",     (const uint8_t[]){0x01,0x00,0x01}, 3, "00000003010001");

    /* the load-bearing case: a 256-byte modulus with MSB set -> length 0x00000101,
     * body = a prepended 0x00 then the 256 bytes (257-byte body). */
    {
        uint8_t n[256]; for (int i = 0; i < 256; ++i) n[i] = (uint8_t)(0x10 + i);
        n[0] = 0xe7;  /* MSB set, like TA0_RSA_N[0] */
        uint8_t buf[512];
        uint32_t off = ssh_put_mpint(buf, 0, sizeof buf, n, 256);
        int ok = (off == 4 + 1 + 256)
                 && buf[0]==0x00 && buf[1]==0x00 && buf[2]==0x01 && buf[3]==0x01
                 && buf[4]==0x00 && buf[5]==0xe7 && buf[off-1]==n[255];
        printf("%s mpint(n256,MSB)        len=%u prefix=%02x%02x%02x%02x body0=%02x body1=%02x\n",
               ok?"PASS":"FAIL", off, buf[0],buf[1],buf[2],buf[3], buf[4], buf[5]);
        if (!ok) g_fail++;
    }
    /* leading-zero strip on a long value: first two bytes zero -> 254 kept, MSB(0xe7) set -> 255 body */
    {
        uint8_t n[256]; memset(n, 0, sizeof n); n[2]=0xe7; n[255]=0x42;
        uint8_t buf[512];
        uint32_t off = ssh_put_mpint(buf, 0, sizeof buf, n, 256);
        /* kept = 254 (bytes 2..255), MSB set -> +1 -> body 255, length 0x000000ff */
        int ok = (off == 4 + 1 + 254) && buf[0]==0&&buf[1]==0&&buf[2]==0&&buf[3]==0xff
                 && buf[4]==0x00 && buf[5]==0xe7 && buf[off-1]==0x42;
        printf("%s mpint(n256,2leadzero)  len=%u prefix=%02x%02x%02x%02x\n",
               ok?"PASS":"FAIL", off, buf[0],buf[1],buf[2],buf[3]);
        if (!ok) g_fail++;
    }

    /* strings */
    chk_string("string(ssh-rsa)",    "ssh-rsa", "000000077373682d727361");
    chk_string("string(empty)",      "",        "00000000");
    chk_string("string(rsa-sha2-256)","rsa-sha2-256","0000000c7273612d736861322d323536");

    /* binary-packet framer: total multiple of 8, padding >= 4, for several payload sizes */
    for (uint32_t plen = 0; plen <= 600; plen += plen < 32 ? 1 : 113) {
        uint8_t pl[700]; memset(pl, 0xAB, sizeof pl);
        uint8_t out[800];
        uint32_t tot = ssh_pkt_frame(out, sizeof out, pl, plen);
        uint8_t padlen = out[4];
        uint32_t pktlen = ((uint32_t)out[0]<<24)|((uint32_t)out[1]<<16)|((uint32_t)out[2]<<8)|out[3];
        int ok = tot && (tot % 8 == 0) && (padlen >= 4) && (pktlen == 1 + plen + padlen) && (tot == 4 + pktlen);
        if (!ok) { printf("FAIL pkt_frame plen=%u tot=%u padlen=%u\n", plen, tot, padlen); g_fail++; }
    }
    printf("PASS pkt_frame(0..600)\n");

    printf("\n=== ssh-kex-unit: %s ===\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
