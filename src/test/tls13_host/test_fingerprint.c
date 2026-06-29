/* test_fingerprint.c — ε4: PIN the ServerHello/HRR extension byte layout.
 *
 * These exact bytes are what tools/ja3s.py / ja4s() hash to the pinned
 * nginx-identical fingerprints (JA3S 771,<dec>,43-51 + JA4S t130200_<suite>_…).
 * The serializers (tls13_make_serverhello / tls13_make_hrr) are ALREADY
 * byte-exact with nginx; this test FREEZES that layout so a future change to
 * tls13.c cannot silently drift the wire fingerprint.
 *
 * RULE: if a serializer assertion here fails, the EXPECTED bytes below are
 * wrong (fix the test) — UNLESS it reveals a genuine layout bug, in which case
 * the serializer changed and the fingerprint just drifted: STOP and report.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <net-synth/tls13.h>

/* Deterministic random fill so the SH random is reproducible (irrelevant to
 * the fingerprint, but keeps the output stable for debugging). */
static void rng_fill_11(uint8_t *p, size_t n) { memset(p, 0x11, n); }

/* ── byte-exact compare with a hexdump-on-mismatch helper ─────────────────
 * Never weaken: any length or content mismatch aborts the process non-zero. */
static void expect_bytes(const char *what,
                         const uint8_t *got, size_t got_len,
                         const uint8_t *exp, size_t exp_len)
{
    int bad = (got_len != exp_len);
    if (!bad) bad = (memcmp(got, exp, exp_len) != 0);
    if (!bad) return;

    fprintf(stderr, "\nFAIL %s: byte layout MISMATCH\n", what);
    fprintf(stderr, "  expected (%zu bytes):", exp_len);
    for (size_t i = 0; i < exp_len; i++) fprintf(stderr, " %02x", exp[i]);
    fprintf(stderr, "\n  actual   (%zu bytes):", got_len);
    for (size_t i = 0; i < got_len; i++) fprintf(stderr, " %02x", got[i]);
    fprintf(stderr, "\n");
    abort();
}

#define CHECK_EQ(what, a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "\nFAIL %s: %s (0x%lx) != %s (0x%lx)\n", \
                (what), #a, (unsigned long)(a), #b, (unsigned long)(b)); \
        abort(); \
    } \
} while (0)

/* ── ServerHello extension-block locator ──────────────────────────────────
 * SH body layout (RFC 8446 §4.1.3): 2(lver)+32(rand)+1(sidlen)+sid_len(sid)
 *   +2(cipher)+1(comp)+2(extlen)+exts.  Returns a pointer to the extension
 *   region (first byte after the 2-byte extensions_len) and its length.
 *   Also surfaces cipher_suite + legacy_version for the body assertions. */
static const uint8_t *sh_ext_block(const uint8_t *out, size_t n,
                                   uint8_t sid_len,
                                   uint16_t *cipher, uint16_t *lver,
                                   size_t *ext_len_out)
{
    /* hs header: 0x02 type + u24 body_len */
    CHECK_EQ("SH hs_type", out[0], 0x02);
    uint32_t body_len = ((uint32_t)out[1] << 16) | ((uint32_t)out[2] << 8) | out[3];
    CHECK_EQ("SH total == 4+body_len", n, (size_t)(4 + body_len));

    const uint8_t *body = out + 4;
    *lver = ((uint16_t)body[0] << 8) | body[1];
    /* session_id length echoed at body[34]. */
    CHECK_EQ("SH sid_len echo", body[34], sid_len);

    size_t off = 2 + 32 + 1 + sid_len;        /* lver + rand + sidlen + sid   */
    *cipher = ((uint16_t)body[off] << 8) | body[off + 1];
    off += 2;                                  /* cipher_suite                 */
    CHECK_EQ("SH legacy_compression", body[off], 0x00);
    off += 1;                                  /* legacy_compression           */
    size_t ext_len = ((size_t)body[off] << 8) | body[off + 1];
    off += 2;                                  /* extensions_len               */

    /* The extension region must be exactly the rest of the message. */
    CHECK_EQ("SH ext region fills body", off + ext_len, (size_t)body_len);
    *ext_len_out = ext_len;
    return body + off;
}

/* ── PIN: ServerHello (X25519) for one suite ──────────────────────────────
 * The ext block MUST be EXACTLY:
 *   00 2b 00 02 03 04                     (supported_versions = 0x0304)
 *   00 33 00 24 00 1d 00 20 <32-byte key> (key_share, NOTHING after)
 */
static void pin_sh_x25519(uint16_t suite)
{
    uint8_t srv_pub[32]; memset(srv_pub, 0x22, sizeof srv_pub);
    uint8_t sid[32];     memset(sid, 0x33, sizeof sid);
    uint8_t out[1024];

    size_t n = tls13_make_serverhello(out, sizeof out, suite,
                                      TLS13_GROUP_X25519, srv_pub, 32,
                                      sid, 32, rng_fill_11);
    if (n == 0) { fprintf(stderr, "FAIL SH 0x%04x: serializer returned 0\n", suite); abort(); }

    uint16_t cipher, lver; size_t ext_len;
    const uint8_t *ext = sh_ext_block(out, n, 32, &cipher, &lver, &ext_len);

    CHECK_EQ("SH cipher_suite == suite", cipher, suite);
    CHECK_EQ("SH legacy_version == 0x0303", lver, 0x0303);

    /* The frozen extension block: [supported_versions][key_share], no more. */
    uint8_t exp[6 + 8 + 32];
    uint8_t *e = exp;
    /* supported_versions */
    *e++ = 0x00; *e++ = 0x2b; *e++ = 0x00; *e++ = 0x02; *e++ = 0x03; *e++ = 0x04;
    /* key_share: type 0033, ext_len 0024(36), group 001d, klen 0020(32), key */
    *e++ = 0x00; *e++ = 0x33; *e++ = 0x00; *e++ = 0x24;
    *e++ = 0x00; *e++ = 0x1d; *e++ = 0x00; *e++ = 0x20;
    memset(e, 0x22, 32);

    char what[64]; snprintf(what, sizeof what, "ServerHello ext block 0x%04x (X25519)", suite);
    expect_bytes(what, ext, ext_len, exp, sizeof exp);
}

/* ── PIN: the ext TYPE order [0x002b, 0x0033] is invariant across groups ───
 * A prime curve (P-256, klen 0x41=65) changes the key_share *body* length but
 * MUST NOT change the extension type order — that order is what is hashed. */
static void pin_sh_group_order(uint16_t group, uint16_t klen)
{
    uint8_t srv_pub[97]; memset(srv_pub, 0x55, sizeof srv_pub);
    uint8_t sid[32];     memset(sid, 0x33, sizeof sid);
    uint8_t out[1024];

    size_t n = tls13_make_serverhello(out, sizeof out, 0x1301,
                                      group, srv_pub, klen,
                                      sid, 32, rng_fill_11);
    if (n == 0) { fprintf(stderr, "FAIL SH group 0x%04x: returned 0\n", group); abort(); }

    uint16_t cipher, lver; size_t ext_len;
    const uint8_t *ext = sh_ext_block(out, n, 32, &cipher, &lver, &ext_len);

    /* Invariant 1: first ext is supported_versions (type 0x002b). */
    uint8_t sv[] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
    expect_bytes("SH first ext == supported_versions (group test)", ext, 6, sv, 6);

    /* Invariant 2: second ext is key_share (type 0x0033), body length tracks
     * the curve, group + klen echo the curve, and it is the LAST ext. */
    const uint8_t *ks = ext + 6;
    CHECK_EQ("SH 2nd ext type == 0x0033", (((uint16_t)ks[0] << 8) | ks[1]), 0x0033);
    uint16_t ks_body = ((uint16_t)ks[2] << 8) | ks[3];
    CHECK_EQ("SH key_share body len == 4+klen", ks_body, (uint16_t)(4 + klen));
    CHECK_EQ("SH key_share group", (((uint16_t)ks[4] << 8) | ks[5]), group);
    CHECK_EQ("SH key_share klen", (((uint16_t)ks[6] << 8) | ks[7]), klen);
    /* nothing after the key_share */
    CHECK_EQ("SH ext block ends at key_share", (size_t)(6 + 8 + klen), ext_len);

    /* The fingerprint-relevant claim: the ext TYPE sequence is [002b, 0033]. */
    CHECK_EQ("SH ext order [0]=002b", (((uint16_t)ext[0] << 8) | ext[1]), 0x002b);
    CHECK_EQ("SH ext order [1]=0033", (((uint16_t)ks[0]  << 8) | ks[1]),  0x0033);
}

/* ── PIN: HelloRetryRequest ───────────────────────────────────────────────
 * The ext block MUST be EXACTLY: 00 2b 00 02 03 04 00 33 00 02 00 1d
 * (key_share names the selected group, NO key). cipher == suite, random ==
 * SHA-256("HelloRetryRequest") anomaly (first 8 bytes cf21ad74e59a6111). */
static void pin_hrr(uint16_t suite)
{
    uint8_t sid[32]; memset(sid, 0x33, sizeof sid);
    uint8_t out[256];

    size_t n = tls13_make_hrr(out, sizeof out, suite, TLS13_GROUP_X25519, sid, 32);
    if (n == 0) { fprintf(stderr, "FAIL HRR 0x%04x: returned 0\n", suite); abort(); }

    uint16_t cipher, lver; size_t ext_len;
    const uint8_t *ext = sh_ext_block(out, n, 32, &cipher, &lver, &ext_len);

    CHECK_EQ("HRR cipher_suite == suite", cipher, suite);
    CHECK_EQ("HRR legacy_version == 0x0303", lver, 0x0303);

    /* The HRR special random anomaly (RFC 8446 §4.1.3): check the first 8. */
    const uint8_t *body = out + 4;
    static const uint8_t hrr_anomaly8[8] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11
    };
    expect_bytes("HRR random anomaly (first 8)", body + 2, 8, hrr_anomaly8, 8);

    /* The frozen HRR extension block: supported_versions + key_share(no key). */
    uint8_t exp[] = {
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,   /* supported_versions = 0x0304 */
        0x00, 0x33, 0x00, 0x02, 0x00, 0x1d    /* key_share = selected_group only */
    };
    char what[48]; snprintf(what, sizeof what, "HRR ext block 0x%04x", suite);
    expect_bytes(what, ext, ext_len, exp, sizeof exp);
}

int main(void)
{
    /* ServerHello (X25519) — exact ext bytes per suite; cipher echoes suite. */
    pin_sh_x25519(0x1301); puts("PASS pin SH 0x1301 (X25519)");
    pin_sh_x25519(0x1302); puts("PASS pin SH 0x1302 (X25519)");
    pin_sh_x25519(0x1303); puts("PASS pin SH 0x1303 (X25519)");

    /* Prime curve: body length changes, ext TYPE order stays [002b, 0033]. */
    pin_sh_group_order(TLS13_GROUP_SECP256R1, 65); puts("PASS pin SH ext order P-256 (klen 65)");
    pin_sh_group_order(TLS13_GROUP_SECP384R1, 97); puts("PASS pin SH ext order P-384 (klen 97)");

    /* HelloRetryRequest — exact ext bytes per suite; random == HRR anomaly. */
    pin_hrr(0x1301); puts("PASS pin HRR 0x1301");
    pin_hrr(0x1302); puts("PASS pin HRR 0x1302");
    pin_hrr(0x1303); puts("PASS pin HRR 0x1303");

    puts("ALL PASS");
    return 0;
}
