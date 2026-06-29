/* test_parse.c — Task 6: ClientHello parse + dispatch peek.
   Uses a real OpenSSL TLS 1.3 ClientHello captured from:
     openssl s_client -tls1_3 -connect 127.0.0.1:19443
   (recorded 2026-06-05) */
#include <net-synth/tls13.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* dummy app responder (unused on the handshake-only / fail-closed paths). */
static uint32_t dummy_app(const uint8_t *req, uint32_t reqlen,
                          uint8_t *out, uint32_t outcap)
{
    (void)req; (void)reqlen; (void)outcap;
    out[0] = 'O'; out[1] = 'K';
    return 2;
}

/* ── Real OpenSSL 1.3 ClientHello ──────────────────────────────────────── */
static const char CH_HEX[] =
    "16030105b3010005af03032129faed68685c84fa9420ff7c9366aa4b3b4972e3"
    "0a5aa594770b3a258c3cf220fd208c8d61861ec8c773a473b4ef0d18418639c0"
    "6a4c96d6183b48a84a7a45e6000813021303130113040100055e000b00040300"
    "0102000a001c001a11ec11eb11ed001d0017001e001900180100010101020103"
    "0104002300000016000000170000000d00240022090409050906040305030603"
    "080708080809080a080b080408050806040105010601002b0003020304002d00"
    "020101003304ea04e811ec04c0217113428b602ce86d5fb4c28c63a1083357e6"
    "96b5ee733f351b28a8214aeab5768d767c3ef814c62691d40b02a4da098bda8a"
    "a1c65b3fe01abeb7a61c3b8a570985fe06114bf4a047071bb2848610c6bcefd0"
    "800ca042bb1a788e2c1f4fabbec3415ae7344ae2889d40b188ff1998c7c1513f"
    "0255fed77adef710d01c61aee6800ca45831915bb872690c3a120d48c1eae402"
    "dfd12673327af6271795641e62ea729676bd544b4ac956569be9c45a035c7d90"
    "0109f4c901c8b2227a0471eb2651c3b544d97252c6a099b277497c5007eb76e8"
    "a275b73aca419b2bfca62aeeb80d5db29143b45418ca105a1c5bc393954985053"
    "9c4bd5d95b0319363a0517ee0cc7e55ab291eecaea5d711656bc14e8209da162a"
    "20ac550271b089f5af5908a996a61664d643847a476952a59998ae3102a95ae12"
    "f7648767b455a3a351c04b3b41e3409f261386e68987a17c61ccc81f10ace464b"
    "955f694563335113dc8612840dd07147bf90ab80b646bd0b7d4ab97447991185"
    "7a3442ea3636b18c791790da58a4e941068d1744fe3a14210ba375224dee5653"
    "08976f1898ba216012614ba38897679d19b47de1abc2e564081b7b38a5a20c71"
    "a277564d13041027a38465d374a703134ca05f5747c9bac4a89fa556a3a80f0f"
    "7cc46147b3575996cc161c5609cc0756781e474114c977595541f88195b7aa44"
    "38c33b64d9aaad8b071d11bd61f34dbfa75ec5926bfae871b8d54800d0c5b583"
    "4abc16cae24998a9c1aae60c4eaea2801d054cecf075aeb05ec485b835285635"
    "03a628b42d4b038c754374f8f0595e7c74b2f32175173f38658d06274fcea738"
    "4626acc9819f429b7f6a80646669ae7d5ac4f0a8b3c5566861319159f130eb96"
    "ba51b096a621cec387027aa21f7651bf5c705b89486008445c607c2d5a773822"
    "138509e984cd5ba84982c2fec675ae84aad9137fe7f89bb18167dd492f529c24"
    "dbd2a72d97cde75a303d77aae8b4ac61ac54d9392a0d2a7312bab53d7a7c6038"
    "c35e6528f77126027012a9e834026248a872468e7aa915b7aa718bca5c124f9e"
    "150885b1bcebe94ffbacc5b39839b67b620995893bf1a393959007d4c94bfcc5"
    "a3b029e8c757ecd75538cbaed72652dd953d5bb7069db555b7e5713163a8dcb1"
    "37797c658162c311a706ebc2b440f0a7c9727a1eb925ae25570665533d54739f"
    "cc103a0cb27e08020a073b6716a78b3176e4d33bc0960fa3d17a8c9900adaa2c"
    "4f98500bc111b2177ad394cb19284185791a72a39863180ec999124dd3ae9fd4"
    "1be920c6165a00edc3b74e8c512677c4248bbdb403c0dfeaa45928c282805c29"
    "c4b2cf7a8b58651a49c54e39352ce08c7dc720012cd2683b4326cf784016cc96"
    "31633924191c94f835316544419c8600e0572bb12ff8b96d72f5676967a7a2a7"
    "8742d036047bc1f2579d8838ceb34a93cfdb25bd421a535738d18b9fa2c13313"
    "b3cac3b078a8834a8d5307fe74279a78938d1c609773255c639e1827c229864a"
    "fca335ddd224b2c15deff1a57d836c0459422d25392d25b94ff877553614ab24"
    "baf8f8abf4ebc2155b6a82220a2f8bbb7a7aa2052873d4790940dc4e73834e6d"
    "1cad855b607dd43f51acc09eeaa5cf510b3c9adb6a55d486b8b6bb7d5c9e6b9f"
    "ef39d85a0371ad3dd375b83d115a2967f0dcfb792aa61486ca7ac6752b16c5fe"
    "73728e539ab0619e4b1a7e001d0020f559547915b2ba80e0b8429ad80f59abc5"
    "e10d15a55bf42800f1bccea821e21e001b0003020001";

static uint8_t *hex_decode(const char *hex, uint32_t *outlen)
{
    /* strip any whitespace / newlines */
    size_t hlen = strlen(hex);
    uint8_t *buf = malloc(hlen / 2 + 1);
    uint32_t n = 0;
    for (size_t i = 0; i < hlen; ) {
        while (i < hlen && (hex[i]==' '||hex[i]=='\n'||hex[i]=='\r')) i++;
        if (i + 2 > hlen) break;
        unsigned hi, lo;
        sscanf(hex + i, "%1x%1x", &hi, &lo);
        buf[n++] = (uint8_t)((hi << 4) | lo);
        i += 2;
    }
    *outlen = n;
    return buf;
}

#define ASSERT(cond, msg) do {                                          \
    if (!(cond)) {                                                      \
        fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);      \
        return 1;                                                        \
    }                                                                   \
    fprintf(stdout, "  ok : %s\n", (msg));                              \
} while(0)

/* ── crafted-ClientHello builder (wXX style, mirrors test_hrr.c) ──────────── */
static uint8_t  CB[1024];
static uint32_t cbn;
static void w8 (uint8_t v)  { CB[cbn++] = v; }
static void w16(uint16_t v) { CB[cbn++] = (uint8_t)(v >> 8); CB[cbn++] = (uint8_t)v; }
static void w24(uint32_t v) { CB[cbn++] = (uint8_t)(v>>16); CB[cbn++]=(uint8_t)(v>>8); CB[cbn++]=(uint8_t)v; }
static void wn (const uint8_t *p, uint32_t n) { memcpy(CB + cbn, p, n); cbn += n; }

/* Build a TLS 1.3 ClientHello that lists X25519 + secp256r1 + secp384r1 in
 * supported_groups and carries a single key_share for `group` (a `klen`-byte
 * uncompressed point 0x04||X||Y filled into *share_out for byte-match checks).
 * Returns the total record length. */
static uint32_t build_ch_group(uint16_t group, uint16_t klen, uint8_t *share_out)
{
    cbn = 0;

    /* Record header: 0x16 0x0301 <u16 frag_len> — patched at the end. */
    w8(0x16); w16(0x0301);
    uint32_t rec_len_at = cbn; w16(0);            /* placeholder */

    /* Handshake header: 0x01 <u24 body_len> — patched at the end. */
    uint32_t hs_start = cbn;
    w8(0x01);
    uint32_t hs_len_at = cbn; w24(0);             /* placeholder */
    uint32_t body_start = cbn;

    /* legacy_version */
    w16(0x0303);
    /* random (32 bytes, arbitrary) */
    for (int i = 0; i < 32; i++) w8((uint8_t)(0xA0 + i));
    /* session_id: 32 bytes (middlebox-compat) */
    w8(32);
    for (int i = 0; i < 32; i++) w8((uint8_t)(0x10 + i));
    /* cipher_suites: just TLS_AES_128_GCM_SHA256 (0x1301) */
    w16(2); w16(0x1301);
    /* compression methods: 1 byte, null */
    w8(1); w8(0x00);

    /* extensions */
    uint32_t ext_len_at = cbn; w16(0);            /* placeholder */
    uint32_t ext_start = cbn;

    /* supported_versions (0x002b): list of 1 → 0x0304 */
    w16(0x002b); w16(3); w8(2); w16(0x0304);

    /* supported_groups (0x000a): X25519, secp256r1, secp384r1 */
    w16(0x000a); w16(8); w16(6); w16(0x001d); w16(0x0017); w16(0x0018);

    /* signature_algorithms (0x000d): rsa_pss_rsae_sha256 (0x0804) */
    w16(0x000d); w16(4); w16(2); w16(0x0804);

    /* key_share (0x0033): a single `group` share (klen-byte uncompressed pt). */
    {
        uint8_t pt[97];
        pt[0] = 0x04;                             /* uncompressed point marker */
        for (uint16_t i = 1; i < klen; i++) pt[i] = (uint8_t)(0x40 + i);
        if (share_out) memcpy(share_out, pt, klen);
        uint16_t entry    = 2 + 2 + klen;         /* group(2)+klen(2)+key       */
        uint16_t ext_body = 2 + entry;            /* client_shares vector len   */
        w16(0x0033); w16(ext_body);
        w16(entry);                               /* client_shares vector len   */
        w16(group);                               /* selected group             */
        w16(klen);                                /* key length                 */
        wn(pt, klen);
    }

    /* Patch extension length. */
    uint16_t extlen = (uint16_t)(cbn - ext_start);
    CB[ext_len_at]     = (uint8_t)(extlen >> 8);
    CB[ext_len_at + 1] = (uint8_t)extlen;

    /* Patch handshake body length (u24). */
    uint32_t bodylen = cbn - body_start;
    CB[hs_len_at]     = (uint8_t)(bodylen >> 16);
    CB[hs_len_at + 1] = (uint8_t)(bodylen >> 8);
    CB[hs_len_at + 2] = (uint8_t)bodylen;

    /* Patch record fragment length (u16). */
    uint16_t fraglen = (uint16_t)(cbn - hs_start);
    CB[rec_len_at]     = (uint8_t)(fraglen >> 8);
    CB[rec_len_at + 1] = (uint8_t)fraglen;

    return cbn;
}

/* Real on-curve X25519 client public key (32B), lifted from the openssl CH
 * capture above — X25519 has no all-zero-output for a real point, so the driver's
 * derive_ecdhe accepts it (lets a CH reach the schedule rather than ECDHE-fail). */
static const uint8_t X25519_CLI_PUB[32] = {
    0xf5,0x59,0x54,0x79,0x15,0xb2,0xba,0x80,0xe0,0xb8,0x42,0x9a,0xd8,0x0f,0x59,0xab,
    0xc5,0xe1,0x0d,0x15,0xa5,0x5b,0xf4,0x28,0x00,0xf1,0xbc,0xce,0xa8,0x21,0xe2,0x1e
};

/* Build a TLS 1.3 ClientHello with a CALLER-SUPPLIED cipher_suites list
 * (`suites`, `nsuites` entries, may be 0 for an empty list) and a single
 * `group` key_share (X25519 share for 0x001d, else a synthetic uncompressed
 * point).  supported_groups lists X25519 only.  Returns the record length. */
static uint32_t build_ch_suites(const uint16_t *suites, uint16_t nsuites,
                                uint16_t group)
{
    cbn = 0;
    w8(0x16); w16(0x0301);
    uint32_t rec_len_at = cbn; w16(0);

    uint32_t hs_start = cbn;
    w8(0x01);
    uint32_t hs_len_at = cbn; w24(0);
    uint32_t body_start = cbn;

    w16(0x0303);                                /* legacy_version */
    for (int i = 0; i < 32; i++) w8((uint8_t)(0xA0 + i));   /* random */
    w8(32); for (int i = 0; i < 32; i++) w8((uint8_t)(0x10 + i)); /* session_id */
    /* cipher_suites: u16 byte-length + the supplied list (may be empty). */
    w16((uint16_t)(nsuites * 2));
    for (uint16_t i = 0; i < nsuites; i++) w16(suites[i]);
    w8(1); w8(0x00);                            /* compression */

    uint32_t ext_len_at = cbn; w16(0);
    uint32_t ext_start = cbn;

    w16(0x002b); w16(3); w8(2); w16(0x0304);    /* supported_versions */
    w16(0x000a); w16(4); w16(2); w16(0x001d);   /* supported_groups: X25519 */
    /* signature_algorithms: offer both 0x0804 and 0x0805 (covers all suites). */
    w16(0x000d); w16(6); w16(4); w16(0x0804); w16(0x0805);

    /* key_share: one entry for `group`.  For X25519 use the real on-curve point;
     * any other group gets a synthetic 32-byte placeholder (group selection
     * decides before the point is touched in the cases that use this). */
    {
        uint8_t pt[32];
        if (group == 0x001d) memcpy(pt, X25519_CLI_PUB, 32);
        else for (int i = 0; i < 32; i++) pt[i] = (uint8_t)(0x40 + i);
        uint16_t entry    = 2 + 2 + 32;
        uint16_t ext_body = 2 + entry;
        w16(0x0033); w16(ext_body);
        w16(entry);
        w16(group);
        w16(32);
        wn(pt, 32);
    }

    uint16_t extlen = (uint16_t)(cbn - ext_start);
    CB[ext_len_at]     = (uint8_t)(extlen >> 8);
    CB[ext_len_at + 1] = (uint8_t)extlen;

    uint32_t bodylen = cbn - body_start;
    CB[hs_len_at]     = (uint8_t)(bodylen >> 16);
    CB[hs_len_at + 1] = (uint8_t)(bodylen >> 8);
    CB[hs_len_at + 2] = (uint8_t)bodylen;

    uint16_t fraglen = (uint16_t)(cbn - hs_start);
    CB[rec_len_at]     = (uint8_t)(fraglen >> 8);
    CB[rec_len_at + 1] = (uint8_t)fraglen;
    return cbn;
}

/* ── ε3 B3 (a): empty cipher_suites list → no suite flag → select_suite NULL →
 *               driver fails closed (ST_ERR), no crash / no OOB. ── */
static int case_empty_cipher_list(void)
{
    fprintf(stdout, "--- B3(a): empty cipher_suites list → fail-closed ---\n");
    uint32_t chlen = build_ch_suites(NULL, 0, 0x001d);

    tls13_clienthello_t p;
    ASSERT(tls13_parse_clienthello(CB, chlen, &p) == 0, "empty-cipher CH parses (structurally valid)");
    ASSERT(p.ok == 1, "empty-cipher CH offers TLS 1.3");
    ASSERT(p.suite_1301 == 0, "no suite_1301 flag (empty list)");
    ASSERT(p.suite_1302 == 0, "no suite_1302 flag (empty list)");
    ASSERT(p.suite_1303 == 0, "no suite_1303 flag (empty list)");

    tls13_sess_t s; memset(&s, 0, sizeof s); s.st = TLS13_ST_START;
    uint8_t out[16384]; uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, CB, chlen, out, sizeof out, &outlen, dummy_app);
    ASSERT(r == -1, "empty-cipher CH rejected by driver (returns -1)");
    ASSERT(s.st == TLS13_ST_ERR, "state == ERR (select_suite NULL → fail-closed)");
    ASSERT(s.suite == NULL, "no suite selected for empty-cipher CH");
    return 0;
}

/* ── ε3 B3 (b): duplicate suite entries → flags idempotent, still selects the
 *               suite, no crash. ── */
static int case_duplicate_suites(void)
{
    fprintf(stdout, "--- B3(b): duplicate 0x1302 entries → idempotent select ---\n");
    const uint16_t dup[] = { 0x1302, 0x1302, 0x1302 };
    uint32_t chlen = build_ch_suites(dup, 3, 0x001d);

    tls13_clienthello_t p;
    ASSERT(tls13_parse_clienthello(CB, chlen, &p) == 0, "duplicate-suite CH parses");
    ASSERT(p.suite_1302 == 1, "suite_1302 flag set (idempotent over duplicates)");
    ASSERT(p.suite_1301 == 0, "no suite_1301 flag");
    ASSERT(p.suite_1303 == 0, "no suite_1303 flag");

    tls13_sess_t s; memset(&s, 0, sizeof s); s.st = TLS13_ST_START;
    uint8_t out[16384]; uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, CB, chlen, out, sizeof out, &outlen, dummy_app);
    ASSERT(r == 0, "duplicate-suite CH accepted (returns 0, no crash)");
    ASSERT(s.suite != NULL && s.suite->id == TLS13_AES_256_GCM_SHA384,
           "still selects 0x1302 despite duplicate entries");
    ASSERT(s.st == TLS13_ST_WAIT_FINISHED, "duplicate-suite CH drives to WAIT_FINISHED");
    return 0;
}

/* ── ε3 B3 (c): GREASE / unknown-only cipher list → no suite flag → fail-closed.
 *               (GREASE 0x0a0a / 0x?a?a + an unassigned suite 0x1305.) ── */
static int case_grease_only(void)
{
    fprintf(stdout, "--- B3(c): GREASE/unknown-only cipher list → fail-closed ---\n");
    const uint16_t grease[] = { 0x0a0a, 0x1a1a, 0x1305, 0x5a5a };
    uint32_t chlen = build_ch_suites(grease, 4, 0x001d);

    tls13_clienthello_t p;
    ASSERT(tls13_parse_clienthello(CB, chlen, &p) == 0, "GREASE-only CH parses");
    ASSERT(p.suite_1301 == 0, "no suite_1301 flag (GREASE only)");
    ASSERT(p.suite_1302 == 0, "no suite_1302 flag (GREASE only)");
    ASSERT(p.suite_1303 == 0, "no suite_1303 flag (GREASE only)");

    tls13_sess_t s; memset(&s, 0, sizeof s); s.st = TLS13_ST_START;
    uint8_t out[16384]; uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, CB, chlen, out, sizeof out, &outlen, dummy_app);
    ASSERT(r == -1, "GREASE-only CH rejected by driver (returns -1)");
    ASSERT(s.st == TLS13_ST_ERR, "state == ERR (no servable suite → fail-closed)");
    ASSERT(s.suite == NULL, "no suite selected for GREASE-only CH");
    return 0;
}

/* ── ε3 B3 (d): a SUPPORTED suite offered WITH only an UNSUPPORTED group.
 *               The CH offers 0x1302 but key_shares ONLY x448 (0x001e, not
 *               served) while supported_groups lists X25519 (servable).  The
 *               suite MUST be selected (0x1302) and group selection MUST fall
 *               back to HRR for the servable group — NOT crash, NOT pick the
 *               wrong suite, NOT accept the unserved share. ── */
static int case_suite_ok_group_unsupported(void)
{
    fprintf(stdout, "--- B3(d): supported suite (0x1302) + only-unsupported-group share"
            " → HRR, not crash / wrong-suite ---\n");

    /* Hand-build a CH: cipher_suites {0x1302}, supported_groups {X25519, x448},
     * key_share = x448 only (a group we do NOT serve). */
    cbn = 0;
    w8(0x16); w16(0x0301);
    uint32_t rec_len_at = cbn; w16(0);
    uint32_t hs_start = cbn;
    w8(0x01);
    uint32_t hs_len_at = cbn; w24(0);
    uint32_t body_start = cbn;
    w16(0x0303);
    for (int i = 0; i < 32; i++) w8((uint8_t)(0xA0 + i));
    w8(32); for (int i = 0; i < 32; i++) w8((uint8_t)(0x10 + i));
    w16(2); w16(0x1302);                          /* cipher_suites: ONLY 0x1302 */
    w8(1); w8(0x00);
    uint32_t ext_len_at = cbn; w16(0);
    uint32_t ext_start = cbn;
    w16(0x002b); w16(3); w8(2); w16(0x0304);
    /* supported_groups: X25519 (servable, HRR target) AND x448 (the sent share). */
    w16(0x000a); w16(6); w16(4); w16(0x001d); w16(0x001e);
    w16(0x000d); w16(6); w16(4); w16(0x0804); w16(0x0805);
    {                                             /* key_share: x448 only */
        uint8_t x448[56];
        for (int i = 0; i < 56; i++) x448[i] = (uint8_t)(0x40 + i);
        uint16_t entry = 2 + 2 + 56, ext_body = 2 + entry;
        w16(0x0033); w16(ext_body); w16(entry);
        w16(0x001e); w16(56); wn(x448, 56);
    }
    { uint16_t extlen = (uint16_t)(cbn - ext_start);
      CB[ext_len_at] = (uint8_t)(extlen >> 8); CB[ext_len_at+1] = (uint8_t)extlen; }
    { uint32_t bodylen = cbn - body_start;
      CB[hs_len_at]=(uint8_t)(bodylen>>16); CB[hs_len_at+1]=(uint8_t)(bodylen>>8); CB[hs_len_at+2]=(uint8_t)bodylen; }
    { uint16_t fraglen = (uint16_t)(cbn - hs_start);
      CB[rec_len_at]=(uint8_t)(fraglen>>8); CB[rec_len_at+1]=(uint8_t)fraglen; }
    uint32_t chlen = cbn;

    tls13_clienthello_t p;
    ASSERT(tls13_parse_clienthello(CB, chlen, &p) == 0, "(d) CH parses");
    ASSERT(p.suite_1302 == 1, "(d) parser flags suite_1302");
    ASSERT(p.x25519_in_groups == 1, "(d) X25519 listed in supported_groups");
    ASSERT(p.has_x25519_share == 0, "(d) NO X25519 key_share (only x448)");

    tls13_sess_t s; memset(&s, 0, sizeof s); s.st = TLS13_ST_START;
    uint8_t out[16384]; uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, CB, chlen, out, sizeof out, &outlen, dummy_app);

    ASSERT(r == 0, "(d) returns 0 (HRR path, no crash)");
    ASSERT(s.suite != NULL, "(d) a suite WAS selected (suite/group independent)");
    ASSERT(s.suite->id == TLS13_AES_256_GCM_SHA384, "(d) selected suite is 0x1302 (not wrong-suited)");
    ASSERT(s.hrr_sent == 1, "(d) genuine HRR emitted for the servable group");
    ASSERT(s.st == TLS13_ST_START, "(d) state still ST_START (awaiting CH2)");
    ASSERT(s.selected_group != 0x001e, "(d) did NOT accept the unserved x448 share");
    return 0;
}

int main(void)
{
    fprintf(stdout, "=== test_parse: ClientHello parse + offers_13 ===\n");

    uint32_t chlen;
    uint8_t *ch = hex_decode(CH_HEX, &chlen);
    fprintf(stdout, "  ClientHello length = %u bytes\n", chlen);

    /* ── 1. offers_13 positive ─────────────────────────────────────────── */
    int r = tls13_clienthello_offers_13(ch, chlen);
    ASSERT(r == 1, "tls13_clienthello_offers_13(real CH) == 1");

    /* ── 2. full parse ─────────────────────────────────────────────────── */
    tls13_clienthello_t parsed;
    int pr = tls13_parse_clienthello(ch, chlen, &parsed);
    ASSERT(pr == 0, "tls13_parse_clienthello returns 0");
    ASSERT(parsed.ok == 1,              "parsed.ok == 1");
    ASSERT(parsed.has_x25519_share == 1, "parsed.has_x25519_share == 1");
    ASSERT(parsed.suite_1301 == 1,      "parsed.suite_1301 == 1");
    ASSERT(parsed.sigalg_0804 == 1,     "parsed.sigalg_0804 == 1");
    ASSERT(parsed.x25519_in_groups == 1, "parsed.x25519_in_groups == 1");

    /* X25519 key must be 32 non-zero bytes */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (parsed.client_x25519[i] != 0) { all_zero = 0; break; }
    ASSERT(!all_zero, "client_x25519 is not all-zero");

    /* Expected key from the captured CH */
    static const uint8_t EXPECTED_X25519[32] = {
        0xf5,0x59,0x54,0x79,0x15,0xb2,0xba,0x80,
        0xe0,0xb8,0x42,0x9a,0xd8,0x0f,0x59,0xab,
        0xc5,0xe1,0x0d,0x15,0xa5,0x5b,0xf4,0x28,
        0x00,0xf1,0xbc,0xce,0xa8,0x21,0xe2,0x1e,
    };
    ASSERT(memcmp(parsed.client_x25519, EXPECTED_X25519, 32) == 0,
           "client_x25519 matches expected value");

    /* The captured CH also lists secp256r1 + secp384r1 in supported_groups
     * (0x0017, 0x0018) but sends only an X25519 key_share. */
    ASSERT(parsed.p256_in_groups == 1, "parsed.p256_in_groups == 1 (real CH)");
    ASSERT(parsed.p384_in_groups == 1, "parsed.p384_in_groups == 1 (real CH)");
    ASSERT(parsed.has_p256_share == 0, "parsed.has_p256_share == 0 (real CH, X25519 only)");
    ASSERT(parsed.has_p384_share == 0, "parsed.has_p384_share == 0 (real CH, X25519 only)");

    /* session_id: the CH has a 32-byte session_id (compat) */
    ASSERT(parsed.session_id_len == 32, "session_id_len == 32");

    /* ── 3. negative: too-short record ────────────────────────────────── */
    r = tls13_clienthello_offers_13(ch, 4);
    ASSERT(r == -1, "offers_13(ch, 4) == -1 (too short)");

    /* ── 4. negative: wrong content type ──────────────────────────────── */
    uint8_t bad_type[6];
    memcpy(bad_type, ch, 6);
    bad_type[0] = 0x17;  /* application_data */
    r = tls13_clienthello_offers_13(bad_type, 6);
    ASSERT(r == -1, "offers_13(rec[0]=0x17) == -1");

    /* ── 5. negative: wrong hs_type ───────────────────────────────────── */
    uint8_t bad_hs[10];
    memcpy(bad_hs, ch, 10);
    bad_hs[5] = 0x02;  /* ServerHello */
    r = tls13_clienthello_offers_13(bad_hs, 10);
    ASSERT(r == -1, "offers_13(hs_type=0x02) == -1");

    /* ── 6. negative: truncated mid-extensions ─────────────────────────── */
    r = tls13_clienthello_offers_13(ch, 50);
    /* must not crash; expect -1 (malformed) */
    ASSERT(r == -1, "offers_13(truncated at 50) == -1");

    /* ── 7. tls13_parse_clienthello on too-short → -1 ──────────────────── */
    tls13_clienthello_t out2;
    pr = tls13_parse_clienthello(ch, 4, &out2);
    ASSERT(pr == -1, "tls13_parse_clienthello(ch,4) == -1");

    /* ── 8. crafted CH with a 65-byte P-256 key_share ──────────────────── */
    {
        uint8_t expect_p256[65];
        uint32_t clen = build_ch_group(TLS13_GROUP_SECP256R1, 65, expect_p256);
        tls13_clienthello_t p;
        ASSERT(tls13_parse_clienthello(CB, clen, &p) == 0,
               "P-256 crafted CH parses");
        ASSERT(p.ok == 1, "P-256 CH offers TLS 1.3");
        ASSERT(p.suite_1301 == 1, "P-256 CH offers suite 0x1301");
        ASSERT(p.p256_in_groups == 1, "P-256 CH: p256_in_groups set");
        ASSERT(p.p384_in_groups == 1, "P-256 CH: p384_in_groups set");
        ASSERT(p.x25519_in_groups == 1, "P-256 CH: x25519_in_groups set");
        ASSERT(p.has_p256_share == 1, "P-256 CH: has_p256_share set");
        ASSERT(p.has_x25519_share == 0, "P-256 CH: no X25519 share");
        ASSERT(p.has_p384_share == 0, "P-256 CH: no P-384 share");
        ASSERT(p.client_p256[0] == 0x04, "P-256 share leads with 0x04");
        ASSERT(memcmp(p.client_p256, expect_p256, 65) == 0,
               "client_p256 byte-matches the crafted point");
    }

    /* ── 9. crafted CH with a 97-byte P-384 key_share ──────────────────── */
    {
        uint8_t expect_p384[97];
        uint32_t clen = build_ch_group(TLS13_GROUP_SECP384R1, 97, expect_p384);
        tls13_clienthello_t p;
        ASSERT(tls13_parse_clienthello(CB, clen, &p) == 0,
               "P-384 crafted CH parses");
        ASSERT(p.ok == 1, "P-384 CH offers TLS 1.3");
        ASSERT(p.suite_1301 == 1, "P-384 CH offers suite 0x1301");
        ASSERT(p.p256_in_groups == 1, "P-384 CH: p256_in_groups set");
        ASSERT(p.p384_in_groups == 1, "P-384 CH: p384_in_groups set");
        ASSERT(p.x25519_in_groups == 1, "P-384 CH: x25519_in_groups set");
        ASSERT(p.has_p384_share == 1, "P-384 CH: has_p384_share set");
        ASSERT(p.has_x25519_share == 0, "P-384 CH: no X25519 share");
        ASSERT(p.has_p256_share == 0, "P-384 CH: no P-256 share");
        ASSERT(p.client_p384[0] == 0x04, "P-384 share leads with 0x04");
        ASSERT(memcmp(p.client_p384, expect_p384, 97) == 0,
               "client_p384 byte-matches the crafted point");
    }

    free(ch);

    /* ── ε3 B3: adversarial cipher-suite agility (operator task-7 list a–d) ── */
    if (case_empty_cipher_list() != 0)         return 1;
    if (case_duplicate_suites() != 0)          return 1;
    if (case_grease_only() != 0)               return 1;
    if (case_suite_ok_group_unsupported() != 0) return 1;

    fprintf(stdout, "=== PASS ===\n");
    return 0;
}
