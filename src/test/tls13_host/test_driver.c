/* test_driver.c — Task 8: tls13_inbound_feed server handshake driver.
 *
 * Feeds the REAL OpenSSL TLS 1.3 ClientHello (same capture as test_parse.c)
 * into tls13_inbound_feed and asserts the structural shape of the server's
 * first flight.  Full crypto interop against openssl is Task 11; this catches
 * structural / state-machine bugs early.
 *
 * ε2 task 6 adds two group-selection cases: a hand-crafted CH that key_shares
 * P-256 (then P-384) with a REAL on-curve client point (fetched from the
 * oracle) must be ACCEPTED directly — ServerHello carries that group's
 * key_share, NO HRR, state WAIT_FINISHED, and the X-coord shared secret has the
 * curve's length. */
#include <net-synth/tls13.h>
#include <net-synth/tls13_keysched.h>
#include <bearssl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* AEAD seal/open + wire helpers (declared in the .c units linked in SRC_DRV). */
size_t tls13_record_seal(const tls13_suite_t *suite, const uint8_t *key,
                         const uint8_t iv[12], uint64_t seq,
                         uint8_t inner_type, const uint8_t *pt, size_t pt_len,
                         uint8_t *out, size_t out_cap);

/* Real OpenSSL 1.3 ClientHello (identical capture used by test_parse.c). */
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

/* dummy app responder (unused on the handshake-only path). */
static uint32_t dummy_app(const uint8_t *req, uint32_t reqlen,
                          uint8_t *out, uint32_t outcap)
{
    (void)req; (void)reqlen; (void)outcap;
    out[0] = 'O'; out[1] = 'K';
    return 2;
}

/* Find the first record of the given type in a server flight; return its
 * fragment length (rlen) and set *fragoff to the fragment start, or -1. */
static long find_record(const uint8_t *buf, uint32_t len, uint8_t type, uint32_t *fragoff)
{
    uint32_t off = 0;
    while (off + 5 <= len) {
        uint8_t  t = buf[off];
        uint16_t rl = (uint16_t)((buf[off+3] << 8) | buf[off+4]);
        if ((uint64_t)off + 5 + rl > len) return -1;
        if (t == type) { if (fragoff) *fragoff = off + 5; return rl; }
        off += 5u + rl;
    }
    return -1;
}

/* ── ε2 task 6: prime-curve key_share ClientHello + on-curve client point ──
 *
 * A hand-crafted minimal TLS 1.3 ClientHello that key_shares a SINGLE prime
 * curve (P-256 or P-384) with a real on-curve point.  The point comes from the
 * Python ECDH oracle (CLI_PUB), so derive_ecdhe's mul() accepts it. */

static uint8_t  CRAFT[1024];
static uint32_t cn;
static void c8 (uint8_t v)  { CRAFT[cn++] = v; }
static void c16(uint16_t v) { CRAFT[cn++] = (uint8_t)(v >> 8); CRAFT[cn++] = (uint8_t)v; }
static void c24(uint32_t v) { CRAFT[cn++]=(uint8_t)(v>>16); CRAFT[cn++]=(uint8_t)(v>>8); CRAFT[cn++]=(uint8_t)v; }
static void cn_(const uint8_t *p, uint32_t n) { memcpy(CRAFT + cn, p, n); cn += n; }

/* Build a CH that lists `group` in supported_groups and sends a single
 * key_share for it (klen bytes from `cli_pub`).  Returns the record length. */
static uint32_t build_share_ch(uint16_t group, const uint8_t *cli_pub, uint16_t klen)
{
    cn = 0;
    c8(0x16); c16(0x0301);
    uint32_t rec_len_at = cn; c16(0);

    uint32_t hs_start = cn;
    c8(0x01);
    uint32_t hs_len_at = cn; c24(0);
    uint32_t body_start = cn;

    c16(0x0303);                              /* legacy_version */
    for (int i = 0; i < 32; i++) c8((uint8_t)(0xA0 + i));   /* random */
    c8(32); for (int i = 0; i < 32; i++) c8((uint8_t)(0x10 + i)); /* session_id */
    c16(2); c16(0x1301);                      /* cipher_suites */
    c8(1); c8(0x00);                          /* compression */

    uint32_t ext_len_at = cn; c16(0);
    uint32_t ext_start = cn;

    c16(0x002b); c16(3); c8(2); c16(0x0304);  /* supported_versions */
    c16(0x000a); c16(4); c16(2); c16(group);  /* supported_groups: just `group` */
    c16(0x000d); c16(4); c16(2); c16(0x0804); /* signature_algorithms */

    /* key_share: one KeyShareEntry for `group`. */
    {
        uint16_t entry    = 2 + 2 + klen;      /* group + klen + key */
        uint16_t ext_body = 2 + entry;         /* client_shares vec len + entry */
        c16(0x0033); c16(ext_body);
        c16(entry);
        c16(group);
        c16(klen);
        cn_(cli_pub, klen);
    }

    uint16_t extlen = (uint16_t)(cn - ext_start);
    CRAFT[ext_len_at]     = (uint8_t)(extlen >> 8);
    CRAFT[ext_len_at + 1] = (uint8_t)extlen;

    uint32_t bodylen = cn - body_start;
    CRAFT[hs_len_at]     = (uint8_t)(bodylen >> 16);
    CRAFT[hs_len_at + 1] = (uint8_t)(bodylen >> 8);
    CRAFT[hs_len_at + 2] = (uint8_t)bodylen;

    uint16_t fraglen = (uint16_t)(cn - hs_start);
    CRAFT[rec_len_at]     = (uint8_t)(fraglen >> 8);
    CRAFT[rec_len_at + 1] = (uint8_t)fraglen;
    return cn;
}

/* Fetch the oracle's on-curve CLI_PUB for a curve (real point so mul accepts). */
static int hexnyb(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t oracle_cli_pub(const char *curve, uint8_t *out, size_t cap)
{
    FILE *p = popen("python3 oracle_ecdh.py", "r");
    if (!p) { fprintf(stderr, "FATAL: cannot run oracle_ecdh.py\n"); exit(2); }
    char line[1024], want[64];
    snprintf(want, sizeof want, "%s CLI_PUB", curve);
    size_t n = 0;
    while (fgets(line, sizeof line, p)) {
        if (strncmp(line, want, strlen(want)) != 0) continue;
        const char *h = line + strlen(want);
        while (*h == ' ') h++;
        while (h[0] && h[1]) {
            if (h[0]=='\n'||h[0]=='\r'||h[0]==' ') { h++; continue; }
            int hi = hexnyb(h[0]), lo = hexnyb(h[1]);
            if (hi < 0 || lo < 0) break;
            if (n >= cap) { fprintf(stderr, "FATAL: CLI_PUB overflow\n"); exit(2); }
            out[n++] = (uint8_t)((hi << 4) | lo);
            h += 2;
        }
        break;
    }
    pclose(p);
    return n;
}

/* Drive one prime-curve happy path: CH key_shares `group` with a real point →
 * SH carries that group's key_share, NO HRR, WAIT_FINISHED, X-coord len = coord. */
static int run_share_curve(const char *curve, uint16_t group,
                           uint16_t klen, uint16_t coord_len)
{
    fprintf(stdout, "--- %s share CH (group 0x%04x) ---\n", curve, group);

    uint8_t cli_pub[97];
    size_t  cplen = oracle_cli_pub(curve, cli_pub, sizeof cli_pub);
    ASSERT(cplen == klen, "oracle CLI_PUB length matches curve key length");

    uint32_t chlen = build_share_ch(group, cli_pub, klen);
    uint8_t *chbuf = malloc(chlen);
    memcpy(chbuf, CRAFT, chlen);

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    s.st = TLS13_ST_START;

    uint8_t out[16384];
    uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, chbuf, chlen, out, sizeof out, &outlen, dummy_app);

    ASSERT(r == 0, "tls13_inbound_feed returns 0 (prime-curve happy path)");
    ASSERT(s.hrr_sent == 0, "no HelloRetryRequest emitted (share honored)");
    ASSERT(s.st == TLS13_ST_WAIT_FINISHED, "state == TLS13_ST_WAIT_FINISHED");
    ASSERT(s.selected_group == group, "session selected_group == curve");
    ASSERT(s.ecdhe_shared_len == coord_len, "ecdhe_shared_len == X-coord length");

    /* No HRR special random anywhere in the flight (the share was accepted). */
    static const uint8_t HRR_RANDOM[32] = {
        0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
        0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C };
    int saw_hrr = 0;
    for (uint32_t i = 0; i + 32 <= outlen; i++)
        if (memcmp(out + i, HRR_RANDOM, 32) == 0) { saw_hrr = 1; break; }
    ASSERT(!saw_hrr, "server flight carries NO HRR special random");

    /* ServerHello must carry a key_share for `group` with klen on the wire:
     * pattern 00 33 <ext_body> <group> <klen> where ext_body = 4 + klen. */
    uint32_t shoff = 0;
    long shlen = find_record(out, outlen, 0x16, &shoff);
    ASSERT(shlen > 0, "ServerHello record located");
    const uint8_t *sh = out + shoff;
    ASSERT(sh[0] == 0x02, "ServerHello handshake type 0x02");

    int found_ks = 0;
    for (long i = 0; i + 8 <= shlen; i++) {
        if (sh[i]==0x00 && sh[i+1]==0x33 &&
            (((uint16_t)sh[i+2]<<8)|sh[i+3]) == (uint16_t)(4 + klen) &&
            (((uint16_t)sh[i+4]<<8)|sh[i+5]) == group &&
            (((uint16_t)sh[i+6]<<8)|sh[i+7]) == klen) { found_ks = 1; break; }
    }
    ASSERT(found_ks, "ServerHello key_share names the selected group + klen");

    /* Key schedule populated (handshake + app keys). */
    int hs_zero = 1; for (int i = 0; i < 16; i++) if (s.s_hs_key[i]) { hs_zero = 0; break; }
    ASSERT(!hs_zero, "key schedule populated s_hs_key");
    int ap_zero = 1; for (int i = 0; i < 16; i++) if (s.s_ap_key[i]) { ap_zero = 0; break; }
    ASSERT(!ap_zero, "key schedule populated s_ap_key");

    free(chbuf);
    return 0;
}

/* ── ε3 A5: 0x1302 (TLS_AES_256_GCM_SHA384) suite selection end-to-end ──────
 *
 * A CH offering BOTH 0x1302 and 0x1301 (0x1302 FIRST) with an X25519 key_share
 * must make the server SELECT 0x1302 — the client's first served suite under
 * ε4 client-order selection (was justified by ε3 server-preference; the VALUE is
 * unchanged because 0x1302 is offered first here).  Then:
 *   - the ServerHello carries cipher_suite 0x1302,
 *   - the key schedule runs the SHA-384 (48B) ladder (s.suite->hash_len == 48),
 *   - the server drives to WAIT_FINISHED,
 *   - a correctly-formed 48-byte client Finished (HMAC-SHA-384 over the CH..sFin
 *     transcript with c_finished_key) is ACCEPTED (state → APP),
 *   - a one-byte-tampered client Finished is REJECTED (state → ERR). */

/* Real on-curve X25519 client public key (32B), lifted from the openssl CH
 * capture above.  X25519 has no all-zero-output for a real point, so
 * derive_ecdhe accepts it. */
static const uint8_t X25519_CLI_PUB[32] = {
    0xf5,0x59,0x54,0x79,0x15,0xb2,0xba,0x80,0xe0,0xb8,0x42,0x9a,0xd8,0x0f,0x59,0xab,
    0xc5,0xe1,0x0d,0x15,0xa5,0x5b,0xf4,0x28,0x00,0xf1,0xbc,0xce,0xa8,0x21,0xe2,0x1e
};

/* Build a CH offering cipher_suites {first, second} (use 0 to omit `second`),
 * supported_groups X25519, and a single X25519 key_share.  Returns rec length. */
static uint32_t build_suite_ch(uint16_t first, uint16_t second)
{
    cn = 0;
    c8(0x16); c16(0x0301);
    uint32_t rec_len_at = cn; c16(0);

    uint32_t hs_start = cn;
    c8(0x01);
    uint32_t hs_len_at = cn; c24(0);
    uint32_t body_start = cn;

    c16(0x0303);                                /* legacy_version */
    for (int i = 0; i < 32; i++) c8((uint8_t)(0xC0 + i));   /* random */
    c8(32); for (int i = 0; i < 32; i++) c8((uint8_t)(0x30 + i)); /* session_id */
    if (second) { c16(4); c16(first); c16(second); }   /* cipher_suites (2) */
    else        { c16(2); c16(first); }                /* cipher_suites (1) */
    c8(1); c8(0x00);                            /* compression */

    uint32_t ext_len_at = cn; c16(0);
    uint32_t ext_start = cn;

    c16(0x002b); c16(3); c8(2); c16(0x0304);    /* supported_versions */
    c16(0x000a); c16(4); c16(2); c16(0x001d);   /* supported_groups: X25519 */
    /* signature_algorithms: offer BOTH rsa_pss_rsae_sha256 (0x0804) and
     * rsa_pss_rsae_sha384 (0x0805) so 0x1302's sigalg is acceptable. */
    c16(0x000d); c16(6); c16(4); c16(0x0804); c16(0x0805);

    /* key_share: one X25519 KeyShareEntry. */
    {
        uint16_t entry    = 2 + 2 + 32;          /* group + klen + key */
        uint16_t ext_body = 2 + entry;           /* client_shares vec len + entry */
        c16(0x0033); c16(ext_body);
        c16(entry);
        c16(0x001d);                             /* X25519 */
        c16(32);
        cn_(X25519_CLI_PUB, 32);
    }

    uint16_t extlen = (uint16_t)(cn - ext_start);
    CRAFT[ext_len_at]     = (uint8_t)(extlen >> 8);
    CRAFT[ext_len_at + 1] = (uint8_t)extlen;

    uint32_t bodylen = cn - body_start;
    CRAFT[hs_len_at]     = (uint8_t)(bodylen >> 16);
    CRAFT[hs_len_at + 1] = (uint8_t)(bodylen >> 8);
    CRAFT[hs_len_at + 2] = (uint8_t)bodylen;

    uint16_t fraglen = (uint16_t)(cn - hs_start);
    CRAFT[rec_len_at]     = (uint8_t)(fraglen >> 8);
    CRAFT[rec_len_at + 1] = (uint8_t)fraglen;
    return cn;
}

/* Seal a client Finished record under the client handshake key.  verify_data is
 * HMAC(suite hash)(c_finished_key, transcript_hash(CH..server Finished)).  If
 * `tamper` is set, flip one byte of verify_data first.  Returns sealed len. */
static size_t make_client_finished(const tls13_sess_t *s, int tamper,
                                   uint8_t *out, size_t cap)
{
    const tls13_suite_t *su = s->suite;
    size_t hlen = su->hash_len;
    const br_hash_class *vt = (const br_hash_class *)su->hash_vtable;

    uint8_t th[48], vd[48];
    tls13_transcript_hash(su, s->th_buf, s->th_len, th);

    br_hmac_key_context kc; br_hmac_context hc;
    br_hmac_key_init(&kc, vt, s->c_finished_key, hlen);
    br_hmac_init(&hc, &kc, hlen);
    br_hmac_update(&hc, th, hlen);
    br_hmac_out(&hc, vd);
    if (tamper) vd[0] ^= 0x01;

    /* msg = 0x14 || u24(hlen) || verify_data(hlen) */
    uint8_t msg[4 + 48];
    msg[0] = 0x14;
    msg[1] = 0x00; msg[2] = (uint8_t)(hlen >> 8); msg[3] = (uint8_t)hlen;
    memcpy(msg + 4, vd, hlen);

    return tls13_record_seal(su, s->c_hs_key, s->c_hs_iv, /*seq*/0,
                             0x16, msg, 4 + hlen, out, cap);
}

/* Seal a client Finished whose verify_data is HMAC'd over a DIFFERENT (wrong)
 * transcript hash than the server computed — the canonical "transcript mismatch"
 * (RFC 8446 §4.4.4): the message is well-formed (right length, right header) but
 * the verify_data binds the wrong transcript, so the server's HMAC compare must
 * reject.  Distinct from the byte-tamper test (which flips a correct value).
 * Returns sealed len. */
static size_t make_client_finished_wrong_transcript(const tls13_sess_t *s,
                                                     uint8_t *out, size_t cap)
{
    const tls13_suite_t *su = s->suite;
    size_t hlen = su->hash_len;
    const br_hash_class *vt = (const br_hash_class *)su->hash_vtable;

    /* A wrong transcript hash: HMAC over an all-0xAA buffer of hash_len bytes
     * instead of the real transcript_hash(CH..server Finished). */
    uint8_t wrong_th[48], vd[48];
    memset(wrong_th, 0xAA, hlen);

    br_hmac_key_context kc; br_hmac_context hc;
    br_hmac_key_init(&kc, vt, s->c_finished_key, hlen);
    br_hmac_init(&hc, &kc, hlen);
    br_hmac_update(&hc, wrong_th, hlen);
    br_hmac_out(&hc, vd);

    uint8_t msg[4 + 48];
    msg[0] = 0x14;
    msg[1] = 0x00; msg[2] = (uint8_t)(hlen >> 8); msg[3] = (uint8_t)hlen;
    memcpy(msg + 4, vd, hlen);

    return tls13_record_seal(su, s->c_hs_key, s->c_hs_iv, /*seq*/0,
                             0x16, msg, 4 + hlen, out, cap);
}

static int case_1302_select(void)
{
    fprintf(stdout, "--- ε3: 0x1302 suite selection (SHA-384, AES-256-GCM) ---\n");

    /* Offer 0x1302 FIRST, then 0x1301 (client-order → server serves 0x1302). */
    uint32_t chlen = build_suite_ch(TLS13_AES_256_GCM_SHA384,
                                    TLS13_AES_128_GCM_SHA256);
    uint8_t *chbuf = malloc(chlen);
    memcpy(chbuf, CRAFT, chlen);

    /* Sanity: parser flags both suites. */
    tls13_clienthello_t parsed;
    ASSERT(tls13_parse_clienthello(chbuf, chlen, &parsed) == 0, "0x1302 CH parses");
    ASSERT(parsed.ok, "CH offers TLS 1.3");
    ASSERT(parsed.suite_1302, "parser flags suite_1302");
    ASSERT(parsed.suite_1301, "parser flags suite_1301 (also offered)");
    ASSERT(parsed.has_x25519_share, "CH has an X25519 key_share");

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    s.st = TLS13_ST_START;

    uint8_t out[16384];
    uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, chbuf, chlen, out, sizeof out, &outlen, dummy_app);

    ASSERT(r == 0, "tls13_inbound_feed returns 0 (0x1302 happy path)");
    ASSERT(s.hrr_sent == 0, "no HelloRetryRequest (X25519 share honored)");
    ASSERT(s.st == TLS13_ST_WAIT_FINISHED, "state == WAIT_FINISHED");
    ASSERT(s.suite != NULL, "s.suite set");
    ASSERT(s.suite->id == TLS13_AES_256_GCM_SHA384, "server SELECTED 0x1302 (client's first served suite)");
    ASSERT(s.suite->hash_len == 48, "selected suite is SHA-384 (48B)");
    ASSERT(s.suite->key_len == 32, "selected suite is AES-256 (32B key)");

    /* ServerHello must carry cipher_suite 0x1302 (not the hardcoded 0x1301). */
    uint32_t shoff = 0;
    long shlen = find_record(out, outlen, 0x16, &shoff);
    ASSERT(shlen > 0, "ServerHello record located");
    const uint8_t *sh = out + shoff;
    ASSERT(sh[0] == 0x02, "ServerHello handshake type 0x02");
    /* cipher_suite sits after: type(1)+len(3)+ver(2)+random(32)+sid_len(1)+sid. */
    uint8_t sid_len = sh[1+3+2+32];
    const uint8_t *cs = sh + 1+3+2+32+1 + sid_len;
    ASSERT(cs[0] == 0x13 && cs[1] == 0x02, "ServerHello cipher_suite == 0x1302");

    /* The 48B schedule fields must be non-zero past byte 32 (SHA-384 ran, not
     * a truncated SHA-256 schedule). */
    int hi_nz = 0; for (int i = 32; i < 48; i++) if (s.s_finished_key[i]) { hi_nz = 1; break; }
    ASSERT(hi_nz, "s_finished_key bytes 32..47 non-zero (SHA-384 finished_key)");
    int sec_hi_nz = 0; for (int i = 32; i < 48; i++) if (s.master_secret[i]) { sec_hi_nz = 1; break; }
    ASSERT(sec_hi_nz, "master_secret bytes 32..47 non-zero (SHA-384 secret)");
    int apkey_hi_nz = 0; for (int i = 16; i < 32; i++) if (s.s_ap_key[i]) { apkey_hi_nz = 1; break; }
    ASSERT(apkey_hi_nz, "s_ap_key bytes 16..31 non-zero (AES-256 32B key)");

    /* A correctly-formed 48B client Finished must be ACCEPTED. */
    {
        tls13_sess_t sok = s;       /* copy: WAIT_FINISHED, suite=0x1302, keys set */
        uint8_t fin[256];
        size_t  fn = make_client_finished(&sok, /*tamper*/0, fin, sizeof fin);
        ASSERT(fn > 0, "client Finished sealed");
        uint8_t out2[4096]; uint32_t outlen2 = 0;
        int r2 = tls13_inbound_feed(&sok, fin, (uint32_t)fn, out2, sizeof out2, &outlen2, dummy_app);
        ASSERT(r2 == 0, "valid 48B client Finished accepted (returns 0)");
        ASSERT(sok.st == TLS13_ST_APP, "state advanced to APP after valid Finished");
    }

    /* A tampered client Finished must be REJECTED. */
    {
        tls13_sess_t sbad = s;
        uint8_t fin[256];
        size_t  fn = make_client_finished(&sbad, /*tamper*/1, fin, sizeof fin);
        ASSERT(fn > 0, "tampered client Finished sealed");
        uint8_t out3[4096]; uint32_t outlen3 = 0;
        int r3 = tls13_inbound_feed(&sbad, fin, (uint32_t)fn, out3, sizeof out3, &outlen3, dummy_app);
        ASSERT(r3 == -1, "tampered client Finished rejected (returns -1)");
        ASSERT(sbad.st == TLS13_ST_ERR, "state == ERR after tampered Finished");
    }

    /* ── ε3 B3 (g): transcript mismatch — a well-formed Finished whose
     * verify_data is HMAC'd over the WRONG transcript hash MUST be rejected. ── */
    {
        tls13_sess_t swt = s;
        uint8_t fin[256];
        size_t  fn = make_client_finished_wrong_transcript(&swt, fin, sizeof fin);
        ASSERT(fn > 0, "wrong-transcript client Finished sealed");
        uint8_t out4[4096]; uint32_t outlen4 = 0;
        int r4 = tls13_inbound_feed(&swt, fin, (uint32_t)fn, out4, sizeof out4, &outlen4, dummy_app);
        ASSERT(r4 == -1, "wrong-transcript client Finished rejected (returns -1)");
        ASSERT(swt.st == TLS13_ST_ERR, "state == ERR after transcript-mismatch Finished");
    }

    free(chbuf);
    return 0;
}

/* ── ε4: client-order cipher selection (match default nginx) ────────────────
 * Real default nginx (ssl_prefer_server_ciphers off) honors the CLIENT's
 * offered cipher order: it serves the client's FIRST-offered suite among the
 * three we support.  This replaces ε3's server-preference (0x1302>0x1303>0x1301).
 * Drive build_suite_ch({first, second}) end-to-end and assert the SELECTED suite
 * (s.suite->id AND the ServerHello cipher_suite bytes) equals the client's first
 * served suite — NOT the old server-preference winner.
 *
 * The discriminating case is [0x1301, 0x1302]: under server-pref the server
 * would (wrongly) pick 0x1302; under client-order it MUST pick 0x1301. */
static int run_client_order(uint16_t first, uint16_t second, uint16_t expect)
{
    if (second)
        fprintf(stdout, "  client-order: offer {0x%04x, 0x%04x} → expect 0x%04x\n",
                first, second, expect);
    else
        fprintf(stdout, "  client-order: offer {0x%04x} → expect 0x%04x\n",
                first, expect);

    uint32_t chlen = build_suite_ch(first, second);
    uint8_t *chbuf = malloc(chlen);
    memcpy(chbuf, CRAFT, chlen);

    tls13_sess_t s; memset(&s, 0, sizeof s); s.st = TLS13_ST_START;
    uint8_t out[16384]; uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, chbuf, chlen, out, sizeof out, &outlen, dummy_app);

    ASSERT(r == 0, "client-order CH happy path (returns 0)");
    ASSERT(s.suite != NULL, "client-order: a suite was selected");
    ASSERT(s.suite->id == expect, "client-order: s.suite->id == client's first served suite");

    /* And the ServerHello must carry that suite on the wire. */
    uint32_t shoff = 0;
    long shlen = find_record(out, outlen, 0x16, &shoff);
    ASSERT(shlen > 0, "client-order: ServerHello located");
    const uint8_t *sh = out + shoff;
    uint8_t sid_len = sh[1+3+2+32];
    const uint8_t *cs = sh + 1+3+2+32+1 + sid_len;
    ASSERT(cs[0] == (uint8_t)(expect >> 8) && cs[1] == (uint8_t)expect,
           "client-order: ServerHello cipher_suite == expected");

    free(chbuf);
    return 0;
}

static int case_client_order(void)
{
    fprintf(stdout, "--- ε4: client-order cipher selection (match default nginx) ---\n");
    /* [0x1301, 0x1302] → 0x1301  (THE discriminator: server-pref would pick 0x1302) */
    if (run_client_order(TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
                         TLS13_AES_128_GCM_SHA256) != 0) return 1;
    /* [0x1303, 0x1301] → 0x1303 */
    if (run_client_order(TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256,
                         TLS13_CHACHA20_POLY1305_SHA256) != 0) return 1;
    /* [0x1302] → 0x1302 */
    if (run_client_order(TLS13_AES_256_GCM_SHA384, 0,
                         TLS13_AES_256_GCM_SHA384) != 0) return 1;
    /* [0x1302, 0x1301] → 0x1302  (0x1302 first → still 0x1302; client-order, not pref) */
    if (run_client_order(TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256,
                         TLS13_AES_256_GCM_SHA384) != 0) return 1;
    return 0;
}

int main(void)
{
    fprintf(stdout, "=== test_driver: tls13_inbound_feed server flight ===\n");

    uint32_t chlen;
    uint8_t *ch = hex_decode(CH_HEX, &chlen);
    fprintf(stdout, "  ClientHello length = %u bytes\n", chlen);

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    s.st = TLS13_ST_START;

    uint8_t out[16384];
    uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, ch, chlen, out, sizeof out, &outlen, dummy_app);

    ASSERT(r == 0, "tls13_inbound_feed returns 0");
    ASSERT(outlen > 0, "server flight is non-empty");
    ASSERT(s.st == TLS13_ST_WAIT_FINISHED, "state == TLS13_ST_WAIT_FINISHED");

    /* First emitted record must be a cleartext handshake (ServerHello). */
    ASSERT(out[0] == 0x16, "first server record is cleartext handshake (0x16)");
    ASSERT(out[1] == 0x03 && out[2] == 0x03, "ServerHello record version 0x0303");

    /* Locate the ServerHello fragment and verify suite 0x1301 + a key_share. */
    uint32_t shoff = 0;
    long shlen = find_record(out, outlen, 0x16, &shoff);
    ASSERT(shlen > 0, "ServerHello record located");
    const uint8_t *sh = out + shoff;
    ASSERT(sh[0] == 0x02, "ServerHello handshake type 0x02");

    /* The real openssl CH_HEX offers cipher_suites { 1302 1303 1301 1304 } —
     * 0x1302 FIRST — so ε4 client-order selection MUST serve 0x1302 (the client's
     * first served suite).  Read the cipher_suite at its exact body offset (after
     * type+len+ver+random+sid_len+sid) rather than scanning (which could
     * false-match key bytes). */
    ASSERT(s.suite != NULL && s.suite->id == TLS13_AES_256_GCM_SHA384,
           "server selected 0x1302 (client's first served suite) for the real openssl CH");
    uint8_t sid_len = sh[1+3+2+32];
    const uint8_t *cs = sh + 1+3+2+32+1 + sid_len;
    ASSERT(cs[0] == 0x13 && cs[1] == 0x02, "ServerHello cipher_suite == 0x1302");

    int found_ks = 0;
    for (long i = 0; i + 1 < shlen; i++) {
        /* key_share ext: 00 33 00 24 00 1d 00 20 ... */
        if (i + 7 < shlen && sh[i]==0x00 && sh[i+1]==0x33 &&
            sh[i+2]==0x00 && sh[i+3]==0x24 && sh[i+4]==0x00 && sh[i+5]==0x1d)
            found_ks = 1;
    }
    ASSERT(found_ks, "ServerHello carries an X25519 key_share (0033 0024 001d)");

    /* Right after the ServerHello must come a change_cipher_spec record. */
    uint32_t ccsoff = 0;
    long ccslen = find_record(out, outlen, 0x14, &ccsoff);
    ASSERT(ccslen == 1, "change_cipher_spec record present (len 1)");

    /* Then at least one encrypted handshake record (EE/Cert/CV/Fin). */
    uint32_t encoff = 0;
    long enclen = find_record(out, outlen, 0x17, &encoff);
    ASSERT(enclen > 0, "encrypted server handshake record present (0x17)");

    /* Key schedule must have run: s_hs_key non-zero. */
    int hs_zero = 1;
    for (int i = 0; i < 16; i++) if (s.s_hs_key[i]) { hs_zero = 0; break; }
    ASSERT(!hs_zero, "key schedule populated s_hs_key (non-zero)");

    /* App keys derived too (th_full schedule ran). */
    int ap_zero = 1;
    for (int i = 0; i < 16; i++) if (s.s_ap_key[i]) { ap_zero = 0; break; }
    ASSERT(!ap_zero, "key schedule populated s_ap_key (non-zero)");

    /* ECDHE shared must be non-zero. */
    int ec_zero = 1;
    for (int i = 0; i < 32; i++) if (s.ecdhe_shared[i]) { ec_zero = 0; break; }
    ASSERT(!ec_zero, "ecdhe_shared computed (non-zero)");

    /* Transcript holds CH..server Finished (well past just the CH). */
    ASSERT(s.th_len > chlen - 5, "transcript spans the full server flight");

    free(ch);

    /* ── ε2 task 6: prime-curve key_share happy paths (honor the sent share) ── */
    if (run_share_curve("P256", TLS13_GROUP_SECP256R1, 65, 32) != 0) return 1;
    if (run_share_curve("P384", TLS13_GROUP_SECP384R1, 97, 48) != 0) return 1;

    /* ── ε3 A5: 0x1302 (TLS_AES_256_GCM_SHA384) end-to-end selection. ── */
    if (case_1302_select() != 0) return 1;

    /* ── ε4: client-order cipher selection (match default nginx). ── */
    if (case_client_order() != 0) return 1;

    fprintf(stdout, "=== PASS ===\n");
    return 0;
}
