/* test_serialize.c — Task 7: handshake-message serializer tests (TDD). */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* Pull CHAIN / CHAIN_LEN from tls_cert.h so the certificate test can
   compute expected lengths at runtime — not hardcoded magic numbers. */
#include <bearssl.h>
#include <net-synth/tls_cert.h>
#include <net-synth/tls13.h>

/* ── helpers ──────────────────────────────────────────────────────────── */

static void rng_fill_11(uint8_t *p, size_t n) { memset(p, 0x11, n); }

/* ── test: EncryptedExtensions (fixed 6-byte message) ─────────────────── */
static void test_ee(void)
{
    uint8_t out[64];
    size_t  n = tls13_make_ee(out, sizeof(out));
    assert(n == 6);
    uint8_t expect[] = { 0x08, 0x00, 0x00, 0x02, 0x00, 0x00 };
    assert(memcmp(out, expect, 6) == 0);
    puts("PASS test_ee");
}

/* ── test: ServerHello structure (X25519 — ε1 byte-identical) ──────────── */
static void test_serverhello(void)
{
    uint8_t srv_pub[32]; memset(srv_pub, 0x22, 32);
    uint8_t sid[32];     memset(sid, 0x33, 32);
    uint8_t out[1024];

    size_t n = tls13_make_serverhello(out, sizeof(out),
                                      0x1301, TLS13_GROUP_X25519, srv_pub, 32,
                                      sid, 32, rng_fill_11);
    /* hs_type */
    assert(out[0] == 0x02);

    /* body_len = u24 at [1..3]; compute expected:
       2(lver)+32(rand)+1(sid_len)+32(sid)+2(cs)+1(comp)+2(ext_len)+
       6(supp_ver ext)+40(key_share ext) = 2+32+1+32+2+1+2+6+40 = 118 */
    uint32_t body_len = ((uint32_t)out[1]<<16)|((uint32_t)out[2]<<8)|out[3];
    assert(body_len == 118);
    assert(n == 4 + 118); /* hs header(4) + body */

    uint8_t *body = out + 4;
    /* legacy_version = 0x0303 */
    assert(body[0] == 0x03 && body[1] == 0x03);
    /* random: 32 bytes of 0x11 (filled by rng_fill_11) */
    for (int i = 0; i < 32; i++) assert(body[2 + i] == 0x11);
    /* session_id: u8 len=32 then 32 bytes of 0x33 */
    assert(body[34] == 32);
    for (int i = 0; i < 32; i++) assert(body[35 + i] == 0x33);
    /* cipher suite = 0x1301 */
    assert(body[67] == 0x13 && body[68] == 0x01);
    /* legacy_compression = 0x00 */
    assert(body[69] == 0x00);
    /* extensions_len = 46 = 6 + 40 */
    assert(body[70] == 0x00 && body[71] == 46);

    /* supported_versions: 00 2b 00 02 03 04 */
    uint8_t sv_ext[] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
    assert(memcmp(body + 72, sv_ext, 6) == 0);

    /* key_share: 00 33  00 24  00 1d  00 20  <32×0x22> */
    uint8_t *ks = body + 78;
    assert(ks[0] == 0x00 && ks[1] == 0x33);   /* type */
    assert(ks[2] == 0x00 && ks[3] == 0x24);   /* ext body len = 36 */
    assert(ks[4] == 0x00 && ks[5] == 0x1d);   /* group X25519 */
    assert(ks[6] == 0x00 && ks[7] == 0x20);   /* key len = 32 */
    for (int i = 0; i < 32; i++) assert(ks[8 + i] == 0x22);

    puts("PASS test_serverhello");
}

/* ── test: ServerHello key_share header for ANY group (ε2 task 5) ────────
 * For each of X25519/P-256/P-384, build a SH and byte-verify:
 *   - key_share ext header (type 0033, ext_body_len, group id, klen)
 *   - klen == on-wire key length (32/65/97) and the key bytes echoed
 *   - the parsed handshake body_len == n - 4 (no overflow / length drift). */
static void check_sh_group(uint16_t group, uint16_t klen, uint8_t fill)
{
    uint8_t srv_pub[97]; memset(srv_pub, fill, sizeof srv_pub);
    uint8_t sid[32];     memset(sid, 0x33, 32);
    uint8_t out[1024];

    size_t n = tls13_make_serverhello(out, sizeof(out),
                                      0x1301, group, srv_pub, klen,
                                      sid, 32, rng_fill_11);
    assert(n != 0);
    assert(out[0] == 0x02);

    /* total == 4 + body_len (header + parsed u24 body); no overflow. */
    uint32_t body_len = ((uint32_t)out[1]<<16)|((uint32_t)out[2]<<8)|out[3];
    assert(n == (size_t)(4 + body_len));

    uint8_t *body = out + 4;
    /* sid len=32 at [34]; cipher suite at [67]; extensions_len at [70]. */
    assert(body[34] == 32);
    assert(body[67] == 0x13 && body[68] == 0x01);

    /* extensions_len = 6 (supp_ver) + 8 + klen (key_share). */
    uint16_t ext_len = ((uint16_t)body[70] << 8) | body[71];
    assert(ext_len == (uint16_t)(6 + 8 + klen));

    /* key_share ext follows the 6-byte supported_versions ext at body+78. */
    uint8_t *ks = body + 78;
    assert(ks[0] == 0x00 && ks[1] == 0x33);                 /* type 0033 */
    uint16_t ext_body = ((uint16_t)ks[2] << 8) | ks[3];
    assert(ext_body == (uint16_t)(4 + klen));               /* group+klen+key */
    assert((((uint16_t)ks[4] << 8) | ks[5]) == group);      /* group id */
    assert((((uint16_t)ks[6] << 8) | ks[7]) == klen);       /* key length */
    for (uint16_t i = 0; i < klen; i++) assert(ks[8 + i] == fill);
}

static void test_serverhello_groups(void)
{
    check_sh_group(TLS13_GROUP_X25519,    32, 0x22);
    check_sh_group(TLS13_GROUP_SECP256R1, 65, 0x44);
    check_sh_group(TLS13_GROUP_SECP384R1, 97, 0x66);
    puts("PASS test_serverhello_groups");
}

/* ── test: HelloRetryRequest key_share group (ε2 task 5) ─────────────────
 * HRR carries the selected group with NO key: key_share = 00 33 00 02 <group>.
 * X25519 stays byte-identical to ε1 (00 33 00 02 00 1d); P-256 = 00 17. */
static void test_hrr(void)
{
    uint8_t sid[32]; memset(sid, 0x33, 32);
    uint8_t out[256];

    /* X25519 HRR — ε1 byte-identical. */
    size_t n = tls13_make_hrr(out, sizeof(out), 0x1301, TLS13_GROUP_X25519, sid, 32);
    /* body = 2(lver)+32(rand)+1+32(sid)+2(cs)+1(comp)+2(extlen)+6+6 = 84 */
    assert(n == 4 + 84);
    assert(out[0] == 0x02);
    uint32_t body_len = ((uint32_t)out[1]<<16)|((uint32_t)out[2]<<8)|out[3];
    assert(body_len == 84);
    uint8_t *body = out + 4;
    /* extensions_len = 6 + 6 = 12 */
    assert(body[70] == 0x00 && body[71] == 12);
    /* key_share (HRR variant, no key): 00 33 00 02 00 1d */
    uint8_t *ks = body + 78;
    uint8_t ks_x25519[] = { 0x00, 0x33, 0x00, 0x02, 0x00, 0x1d };
    assert(memcmp(ks, ks_x25519, 6) == 0);

    /* P-256 HRR — key_share names secp256r1 (no key): 00 33 00 02 00 17 */
    size_t n2 = tls13_make_hrr(out, sizeof(out), 0x1301, TLS13_GROUP_SECP256R1, sid, 32);
    assert(n2 == 4 + 84);  /* HRR key-less group → same length as X25519 */
    uint8_t *ks2 = out + 4 + 78;
    uint8_t ks_p256[] = { 0x00, 0x33, 0x00, 0x02, 0x00, 0x17 };
    assert(memcmp(ks2, ks_p256, 6) == 0);

    puts("PASS test_hrr");
}

/* ── test: Finished ────────────────────────────────────────────────────── */
static void test_finished(void)
{
    /* ── 0x1301 (SHA-256): finished_key = 0x00..0x1f, th = 0xaa*32 ── */
    uint8_t fk[32]; for (int i=0;i<32;i++) fk[i]=(uint8_t)i;
    uint8_t th[32]; memset(th, 0xaa, 32);
    uint8_t out[64];
    size_t n = tls13_make_finished(out, sizeof(out),
                                   tls13_suite_by_id(0x1301), fk, th);

    assert(n == 36);
    assert(out[0] == 0x14);
    assert(out[1] == 0x00 && out[2] == 0x00 && out[3] == 0x20);

    /* golden: python3 -c "import hmac,hashlib; fk=bytes(range(32));
       th=bytes([0xaa]*32); print(hmac.new(fk,th,hashlib.sha256).hexdigest())"
       = 43990e16779c4e9fd34d5e26ea42dc39be411c5828d0298fed3d5acdede9932e */
    static const uint8_t golden[32] = {
        0x43, 0x99, 0x0e, 0x16, 0x77, 0x9c, 0x4e, 0x9f,
        0xd3, 0x4d, 0x5e, 0x26, 0xea, 0x42, 0xdc, 0x39,
        0xbe, 0x41, 0x1c, 0x58, 0x28, 0xd0, 0x29, 0x8f,
        0xed, 0x3d, 0x5a, 0xcd, 0xed, 0xe9, 0x93, 0x2e
    };
    assert(memcmp(out + 4, golden, 32) == 0);

    /* ── ε3 0x1302 (SHA-384): finished_key = 0x00..0x2f, th = 0xaa*48 ──
     * length byte 0x30 (48) + a 48-byte HMAC-SHA-384 verify_data. */
    uint8_t fk6[48]; for (int i=0;i<48;i++) fk6[i]=(uint8_t)i;
    uint8_t th6[48]; memset(th6, 0xaa, 48);
    uint8_t out6[64];
    size_t n6 = tls13_make_finished(out6, sizeof(out6),
                                    tls13_suite_by_id(0x1302), fk6, th6);
    assert(n6 == 4 + 48);
    assert(out6[0] == 0x14);
    assert(out6[1] == 0x00 && out6[2] == 0x00 && out6[3] == 0x30);

    /* golden: python3 -c "import hmac,hashlib; fk=bytes(range(48));
       th=bytes([0xaa]*48); print(hmac.new(fk,th,hashlib.sha384).hexdigest())" */
    static const uint8_t golden6[48] = {
        0x95, 0x72, 0xd7, 0x03, 0xc2, 0xf4, 0x5e, 0x9d,
        0xcd, 0x84, 0xb7, 0x5a, 0xad, 0x82, 0x0b, 0x37,
        0x1e, 0xf0, 0x90, 0xb1, 0xf9, 0x61, 0x84, 0x32,
        0x13, 0xa6, 0xbc, 0x16, 0x22, 0x31, 0xa0, 0xdf,
        0xed, 0xc4, 0x4a, 0xd2, 0x4a, 0xf5, 0x9f, 0x2b,
        0x9c, 0xc9, 0x1e, 0x32, 0xf9, 0x8b, 0x2b, 0xd9
    };
    assert(memcmp(out6 + 4, golden6, 48) == 0);
    puts("PASS test_finished");
}

/* ── test: Certificate ─────────────────────────────────────────────────── */
static void test_certificate(void)
{
    uint8_t out[8192];
    size_t der_len = CHAIN[0].data_len;
    /* Expected body:
       1(context_len=0) + 3(cert_list_len) + 3(cert_data_len) + der_len + 2(ext=0)
       = 9 + der_len */
    size_t expected_body = 1 + 3 + (3 + der_len + 2);
    size_t expected_total = 4 + expected_body;

    size_t n = tls13_make_cert(out, sizeof(out));
    assert(n == expected_total);

    assert(out[0] == 0x0b);   /* hs type Certificate */

    /* body_len u24 */
    uint32_t blen = ((uint32_t)out[1]<<16)|((uint32_t)out[2]<<8)|out[3];
    assert(blen == expected_body);

    /* context len = 0 */
    assert(out[4] == 0x00);

    /* cert_list_len u24 = 3 + der_len + 2 */
    uint32_t cll = ((uint32_t)out[5]<<16)|((uint32_t)out[6]<<8)|out[7];
    assert(cll == (uint32_t)(3 + der_len + 2));

    /* cert_data_len u24 */
    uint32_t cdl = ((uint32_t)out[8]<<16)|((uint32_t)out[9]<<8)|out[10];
    assert(cdl == (uint32_t)der_len);

    /* DER bytes must match */
    assert(memcmp(out + 11, CHAIN[0].data, der_len) == 0);

    /* trailing extension u16 = 0 */
    assert(out[11 + der_len] == 0x00 && out[11 + der_len + 1] == 0x00);

    puts("PASS test_certificate");
}

/* ── test: CertificateVerify structure ────────────────────────────────── */
static void test_certverify(void)
{
    uint8_t th[32]; memset(th, 0xab, 32);
    uint8_t out[4096];

    const tls13_suite_t *su = tls13_suite_by_id(0x1301);
    size_t n = tls13_make_certverify(out, sizeof(out), su, th, 32, rng_fill_11);

    /* hs_type 0x0f, body = 2(sigalg)+2(sig_len)+256(sig) = 260 */
    assert(n == 4 + 260);
    assert(out[0] == 0x0f);
    uint32_t blen = ((uint32_t)out[1]<<16)|((uint32_t)out[2]<<8)|out[3];
    assert(blen == 260);
    /* sigalg 0x0804 */
    assert(out[4] == 0x08 && out[5] == 0x04);
    /* sig_len = 256 */
    assert(out[6] == 0x01 && out[7] == 0x00);

    puts("PASS test_certverify");
}

/* ── overflow guard: EE returns 0 when cap too small ──────────────────── */
static void test_overflow(void)
{
    uint8_t buf[3];
    size_t n = tls13_make_ee(buf, sizeof(buf));
    assert(n == 0);
    puts("PASS test_overflow");
}

int main(void)
{
    test_ee();
    test_serverhello();
    test_serverhello_groups();
    test_hrr();
    test_finished();
    test_certificate();
    test_certverify();
    test_overflow();
    puts("ALL PASS");
    return 0;
}
