/* test_hrr.c — ε2: P-256 direct-accept + a GENUINE HelloRetryRequest.
 *
 * ε2 honors the client's SENT key_share (select_group), so the two cases here
 * are:
 *
 *  (A) P-256 HAPPY PATH (no HRR).  The original ε1 test_hrr CH listed X25519 +
 *      P-256 in supported_groups and key_shared P-256 ONLY.  Under ε2 the server
 *      now SERVES P-256, so that share is honored DIRECTLY — ServerHello carries
 *      a P-256 key_share, selected_group 0x0017, state WAIT_FINISHED, NO HRR.
 *      The on-curve client point comes from the Python ECDH oracle so the real
 *      derive_ecdhe mul() accepts it.  This doubles as a P-256 happy-path gate.
 *
 *  (B) GENUINE HRR.  A CH that lists a SERVABLE group (X25519, 0x001d) in
 *      supported_groups but key_shares ONLY a group the server does NOT serve
 *      (x448, 0x001e).  select_group() finds no usable share → the server MUST
 *      emit a real HelloRetryRequest naming the server-preference servable group
 *      (X25519).  A 2nd such CH (still no usable share) MUST be rejected — no
 *      infinite loop.  This mimics `openssl s_client -curves x448:X25519`.
 *
 * Full HRR→CH2→finish interop is proven against openssl in the live gate. */
#include <net-synth/tls13.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* The RFC 8446 §4.1.3 HelloRetryRequest special random. */
static const uint8_t HRR_RANDOM[32] = {
    0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
    0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
};

#define ASSERT(cond, msg) do {                                          \
    if (!(cond)) {                                                      \
        fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);      \
        return 1;                                                        \
    }                                                                   \
    fprintf(stdout, "  ok : %s\n", (msg));                              \
} while(0)

/* Little wire-builder helpers (host test only). */
static uint8_t  CH[1024];
static uint32_t chn;
static void w8 (uint8_t v)  { CH[chn++] = v; }
static void w16(uint16_t v) { CH[chn++] = (uint8_t)(v >> 8); CH[chn++] = (uint8_t)v; }
static void w24(uint32_t v) { CH[chn++] = (uint8_t)(v>>16); CH[chn++]=(uint8_t)(v>>8); CH[chn++]=(uint8_t)v; }
static void wn (const uint8_t *p, uint32_t n) { memcpy(CH + chn, p, n); chn += n; }

/* Patch the three nested length fields and close out a CH built in CH[]. */
static uint32_t finish_ch(uint32_t rec_len_at, uint32_t hs_start,
                          uint32_t hs_len_at, uint32_t body_start,
                          uint32_t ext_len_at, uint32_t ext_start)
{
    uint16_t extlen = (uint16_t)(chn - ext_start);
    CH[ext_len_at]     = (uint8_t)(extlen >> 8);
    CH[ext_len_at + 1] = (uint8_t)extlen;

    uint32_t bodylen = chn - body_start;
    CH[hs_len_at]     = (uint8_t)(bodylen >> 16);
    CH[hs_len_at + 1] = (uint8_t)(bodylen >> 8);
    CH[hs_len_at + 2] = (uint8_t)bodylen;

    uint16_t fraglen = (uint16_t)(chn - hs_start);
    CH[rec_len_at]     = (uint8_t)(fraglen >> 8);
    CH[rec_len_at + 1] = (uint8_t)fraglen;
    return chn;
}

/* Emit the common CH prefix (record/handshake headers + body up to extensions)
 * and return the offsets finish_ch needs.  groups = the supported_groups list
 * (count entries of 2 bytes each), already byte-built by the caller via a small
 * inline. */

/* Build CH (A): X25519+P-256 in supported_groups, key_share P-256 ONLY (klen 65,
 * on-curve point from the oracle). */
static uint32_t build_ch_p256(const uint8_t *p256_pub /* 65B */)
{
    chn = 0;
    w8(0x16); w16(0x0301);
    uint32_t rec_len_at = chn; w16(0);

    uint32_t hs_start = chn;
    w8(0x01);
    uint32_t hs_len_at = chn; w24(0);
    uint32_t body_start = chn;

    w16(0x0303);
    for (int i = 0; i < 32; i++) w8((uint8_t)(0xA0 + i));   /* random */
    w8(32); for (int i = 0; i < 32; i++) w8((uint8_t)(0x10 + i)); /* session_id */
    w16(2); w16(0x1301);                                     /* cipher_suites */
    w8(1); w8(0x00);                                         /* compression */

    uint32_t ext_len_at = chn; w16(0);
    uint32_t ext_start = chn;

    w16(0x002b); w16(3); w8(2); w16(0x0304);                 /* supported_versions */
    /* supported_groups: X25519 (0x001d) AND secp256r1 (0x0017). */
    w16(0x000a); w16(6); w16(4); w16(0x001d); w16(0x0017);
    w16(0x000d); w16(4); w16(2); w16(0x0804);                /* signature_algorithms */

    /* key_share: a single P-256 share (65-byte uncompressed point). */
    {
        uint16_t entry = 2 + 2 + 65;          /* group + klen + key */
        uint16_t ext_body = 2 + entry;        /* client_shares vec len + entry */
        w16(0x0033); w16(ext_body);
        w16(entry);
        w16(0x0017);                          /* secp256r1 — a SERVED group */
        w16(65);
        wn(p256_pub, 65);
    }
    return finish_ch(rec_len_at, hs_start, hs_len_at, body_start, ext_len_at, ext_start);
}

/* Build CH (B): X25519 servable in supported_groups, key_share x448 ONLY (a
 * group we do NOT serve) → no usable share → genuine HRR for X25519. */
static uint32_t build_ch_hrr(void)
{
    chn = 0;
    w8(0x16); w16(0x0301);
    uint32_t rec_len_at = chn; w16(0);

    uint32_t hs_start = chn;
    w8(0x01);
    uint32_t hs_len_at = chn; w24(0);
    uint32_t body_start = chn;

    w16(0x0303);
    for (int i = 0; i < 32; i++) w8((uint8_t)(0xA0 + i));
    w8(32); for (int i = 0; i < 32; i++) w8((uint8_t)(0x10 + i));
    w16(2); w16(0x1301);
    w8(1); w8(0x00);

    uint32_t ext_len_at = chn; w16(0);
    uint32_t ext_start = chn;

    w16(0x002b); w16(3); w8(2); w16(0x0304);
    /* supported_groups: X25519 (servable, HRR target) AND x448 (the sent share).*/
    w16(0x000a); w16(6); w16(4); w16(0x001d); w16(0x001e);
    w16(0x000d); w16(4); w16(2); w16(0x0804);

    /* key_share: a single x448 share (56-byte point) — a group we do NOT serve. */
    {
        uint8_t x448[56];
        for (int i = 0; i < 56; i++) x448[i] = (uint8_t)(0x40 + i);
        uint16_t entry = 2 + 2 + 56;
        uint16_t ext_body = 2 + entry;
        w16(0x0033); w16(ext_body);
        w16(entry);
        w16(0x001e);                          /* x448 — unserved group */
        w16(56);
        wn(x448, 56);
    }
    return finish_ch(rec_len_at, hs_start, hs_len_at, body_start, ext_len_at, ext_start);
}

/* ── oracle point fetch (real on-curve P-256 point so derive_ecdhe accepts) ── */
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

/* Find the first record of `type`; return rlen + fragment offset, or -1. */
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

/* Build CH (C): ONLY X25519 (0x001d) in supported_groups, but key_share is a
 * P-256 (0x0017) share (65-byte uncompressed point, lead 0x04).
 * RFC 8446 §4.2.8 compliance: the P-256 share must NOT be accepted because
 * P-256 is NOT in supported_groups.  The server must fall back to HRR for the
 * one group that IS listed (X25519). */
static uint32_t build_ch_case_c(const uint8_t *p256_pub /* 65B */)
{
    chn = 0;
    w8(0x16); w16(0x0301);
    uint32_t rec_len_at = chn; w16(0);

    uint32_t hs_start = chn;
    w8(0x01);
    uint32_t hs_len_at = chn; w24(0);
    uint32_t body_start = chn;

    w16(0x0303);
    for (int i = 0; i < 32; i++) w8((uint8_t)(0xB0 + i));   /* random */
    w8(32); for (int i = 0; i < 32; i++) w8((uint8_t)(0x20 + i)); /* session_id */
    w16(2); w16(0x1301);                                     /* cipher_suites */
    w8(1); w8(0x00);                                         /* compression */

    uint32_t ext_len_at = chn; w16(0);
    uint32_t ext_start = chn;

    w16(0x002b); w16(3); w8(2); w16(0x0304);                 /* supported_versions */
    /* supported_groups: ONLY X25519 (0x001d) — P-256 deliberately OMITTED. */
    w16(0x000a); w16(4); w16(2); w16(0x001d);
    w16(0x000d); w16(4); w16(2); w16(0x0804);                /* signature_algorithms */

    /* key_share: a single P-256 share (65-byte uncompressed point) —
     * the share group (0x0017) is NOT listed in supported_groups above. */
    {
        uint16_t entry    = 2 + 2 + 65;   /* group + klen + key */
        uint16_t ext_body = 2 + entry;    /* client_shares vec len + entry */
        w16(0x0033); w16(ext_body);
        w16(entry);
        w16(0x0017);                      /* secp256r1 — NOT in supported_groups */
        w16(65);
        wn(p256_pub, 65);
    }
    return finish_ch(rec_len_at, hs_start, hs_len_at, body_start, ext_len_at, ext_start);
}

/* ── case (C): RFC 8446 §4.2.8 — key_share for group NOT in supported_groups
 *              must NOT be accepted; server falls back to HRR for the listed
 *              servable group (X25519).  select_group() requires *_in_groups,
 *              so the P-256 share is ignored entirely. ── */
static int case_c_ks_not_in_groups(void)
{
    fprintf(stdout, "--- case C: RFC 8446 §4.2.8 — P-256 key_share NOT in supported_groups"
            " → HRR for X25519 ---\n");

    /* Reuse the oracle's on-curve P-256 point (any well-formed 65-byte
     * uncompressed point suffices; the point is irrelevant because the share
     * must be ignored rather than accepted). */
    uint8_t p256[65];
    size_t plen = oracle_cli_pub("P256", p256, sizeof p256);
    ASSERT(plen == 65, "oracle P256 CLI_PUB is a 65-byte uncompressed point");

    uint32_t chlen = build_ch_case_c(p256);
    fprintf(stdout, "  crafted Case-C ClientHello = %u bytes\n", chlen);

    /* Sanity: parser sees a P-256 share but P-256 NOT in supported_groups,
     * and X25519 IS listed but has NO X25519 share. */
    tls13_clienthello_t parsed;
    ASSERT(tls13_parse_clienthello(CH, chlen, &parsed) == 0, "crafted Case-C CH parses");
    ASSERT(parsed.ok, "CH offers TLS 1.3");
    ASSERT(parsed.suite_1301, "CH offers suite 0x1301");
    ASSERT(parsed.has_p256_share, "CH has a P-256 key_share (the malformed one)");
    ASSERT(!parsed.p256_in_groups, "CH does NOT list P-256 in supported_groups");
    ASSERT(parsed.x25519_in_groups, "CH lists X25519 in supported_groups");
    ASSERT(!parsed.has_x25519_share, "CH has NO X25519 key_share");

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    s.st = TLS13_ST_START;

    uint8_t out[16384];
    uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, CH, chlen, out, sizeof out, &outlen, NULL);

    /* The P-256 share must NOT be accepted: select_group() returns 0 (share
     * present but group not in supported_groups), so the server must send
     * a genuine HRR for X25519 (the one servable group listed). */
    ASSERT(r == 0, "tls13_inbound_feed returns 0 (HRR path, not direct accept)");
    ASSERT(outlen > 0, "server emitted a flight");
    ASSERT(s.hrr_sent == 1, "s.hrr_sent == 1 (genuine HelloRetryRequest)");
    ASSERT(s.st == TLS13_ST_START, "state still ST_START (awaiting CH2)");
    ASSERT(s.selected_group != TLS13_GROUP_SECP256R1, "selected_group is NOT P-256 (0x0017)");

    /* The flight must carry the HRR special random — confirms HRR not ServerHello. */
    int saw_hrr = 0;
    for (uint32_t i = 0; i + 32 <= outlen; i++)
        if (memcmp(out + i, HRR_RANDOM, 32) == 0) { saw_hrr = 1; break; }
    ASSERT(saw_hrr, "server flight carries the HRR special random");

    /* The HRR key_share must name X25519 (0x001d) — the listed servable group. */
    uint32_t shoff = 0;
    long shlen = find_record(out, outlen, 0x16, &shoff);
    ASSERT(shlen > 0, "HRR record located");
    const uint8_t *hs = out + shoff;
    ASSERT(hs[0] == 0x02, "HRR handshake type 0x02 (server_hello)");
    int found_hrr_x25519_ks = 0;
    for (long i = 0; i + 6 <= shlen; i++) {
        if (hs[i]==0x00 && hs[i+1]==0x33 && hs[i+2]==0x00 && hs[i+3]==0x02 &&
            hs[i+4]==0x00 && hs[i+5]==0x1d) { found_hrr_x25519_ks = 1; break; }
    }
    ASSERT(found_hrr_x25519_ks, "HRR key_share names X25519 (0033 0002 001d)");

    /* No P-256 ServerHello — confirm the malformed share was not acted upon. */
    int found_p256_sh = 0;
    for (long i = 0; i + 8 <= shlen; i++) {
        if (hs[i]==0x00 && hs[i+1]==0x33 &&
            (((uint16_t)hs[i+2]<<8)|hs[i+3]) == (uint16_t)(4 + 65) &&
            (((uint16_t)hs[i+4]<<8)|hs[i+5]) == 0x0017) { found_p256_sh = 1; break; }
    }
    ASSERT(!found_p256_sh, "NO P-256 ServerHello key_share in response (share was ignored)");

    /* No handshake keys derived: HRR precedes the key schedule. */
    int hs_zero = 1;
    for (int i = 0; i < 16; i++) if (s.s_hs_key[i]) { hs_zero = 0; break; }
    ASSERT(hs_zero, "no handshake key derived yet (HRR is pre-key-schedule)");

    return 0;
}

/* ── case (A): P-256 share is honored DIRECTLY (no HRR) ── */
static int case_p256_direct(void)
{
    fprintf(stdout, "--- case A: P-256 key_share accepted directly (no HRR) ---\n");

    uint8_t p256[65];
    size_t plen = oracle_cli_pub("P256", p256, sizeof p256);
    ASSERT(plen == 65, "oracle P256 CLI_PUB is a 65-byte uncompressed point");

    uint32_t chlen = build_ch_p256(p256);
    fprintf(stdout, "  crafted P-256 ClientHello = %u bytes\n", chlen);

    /* Sanity: parser sees a P-256 share and X25519+P-256 in groups. */
    tls13_clienthello_t parsed;
    ASSERT(tls13_parse_clienthello(CH, chlen, &parsed) == 0, "crafted P-256 CH parses");
    ASSERT(parsed.ok, "CH offers TLS 1.3");
    ASSERT(parsed.suite_1301, "CH offers suite 0x1301");
    ASSERT(parsed.has_p256_share, "CH has a P-256 key_share");
    ASSERT(!parsed.has_x25519_share, "CH has NO X25519 key_share");
    ASSERT(parsed.x25519_in_groups, "CH lists X25519 in supported_groups");
    ASSERT(parsed.p256_in_groups, "CH lists P-256 in supported_groups");

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    s.st = TLS13_ST_START;

    uint8_t out[16384];
    uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, CH, chlen, out, sizeof out, &outlen, NULL);

    ASSERT(r == 0, "tls13_inbound_feed returns 0 (P-256 happy path)");
    ASSERT(s.hrr_sent == 0, "NO HelloRetryRequest emitted (share honored directly)");
    ASSERT(s.st == TLS13_ST_WAIT_FINISHED, "state == WAIT_FINISHED (full flight sent)");
    ASSERT(s.selected_group == TLS13_GROUP_SECP256R1, "selected_group == 0x0017 (P-256)");
    ASSERT(s.ecdhe_shared_len == 32, "P-256 ECDHE shared is the 32-byte X-coord");

    /* The flight must NOT carry the HRR special random. */
    int saw_hrr = 0;
    for (uint32_t i = 0; i + 32 <= outlen; i++)
        if (memcmp(out + i, HRR_RANDOM, 32) == 0) { saw_hrr = 1; break; }
    ASSERT(!saw_hrr, "server flight carries NO HRR special random");

    /* ServerHello must carry a P-256 key_share: 00 33 00 45 00 17 00 41. */
    uint32_t shoff = 0;
    long shlen = find_record(out, outlen, 0x16, &shoff);
    ASSERT(shlen > 0, "ServerHello record located");
    const uint8_t *sh = out + shoff;
    ASSERT(sh[0] == 0x02, "ServerHello handshake type 0x02");
    int found_ks = 0;
    for (long i = 0; i + 8 <= shlen; i++) {
        if (sh[i]==0x00 && sh[i+1]==0x33 &&
            (((uint16_t)sh[i+2]<<8)|sh[i+3]) == (uint16_t)(4 + 65) &&
            (((uint16_t)sh[i+4]<<8)|sh[i+5]) == 0x0017 &&
            (((uint16_t)sh[i+6]<<8)|sh[i+7]) == 65) { found_ks = 1; break; }
    }
    ASSERT(found_ks, "ServerHello key_share names P-256 (0033 0045 0017 0041)");

    /* Key schedule ran (the 32B P-256 X-coord IKM produced handshake keys). */
    int hs_zero = 1; for (int i = 0; i < 16; i++) if (s.s_hs_key[i]) { hs_zero = 0; break; }
    ASSERT(!hs_zero, "key schedule populated s_hs_key (P-256 32B IKM)");
    return 0;
}

/* ── case (B): genuine HRR + no infinite loop ── */
static int case_genuine_hrr(void)
{
    fprintf(stdout, "--- case B: genuine HRR (servable group listed, unserved share) ---\n");

    uint32_t chlen = build_ch_hrr();
    fprintf(stdout, "  crafted HRR-triggering ClientHello = %u bytes\n", chlen);

    /* Sanity: the parser sees X25519 servable in groups but no X25519 share. */
    tls13_clienthello_t parsed;
    ASSERT(tls13_parse_clienthello(CH, chlen, &parsed) == 0, "crafted CH parses");
    ASSERT(parsed.ok, "CH offers TLS 1.3");
    ASSERT(parsed.suite_1301, "CH offers suite 0x1301");
    ASSERT(parsed.x25519_in_groups, "CH lists X25519 (servable) in supported_groups");
    ASSERT(!parsed.has_x25519_share, "CH has NO X25519 key_share");
    ASSERT(!parsed.has_p256_share, "CH has NO P-256 key_share (only x448)");
    ASSERT(!parsed.has_p384_share, "CH has NO P-384 key_share (only x448)");

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    s.st = TLS13_ST_START;

    uint8_t out[16384];
    uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, CH, chlen, out, sizeof out, &outlen, NULL);

    ASSERT(r == 0, "tls13_inbound_feed returns 0 (HRR path)");
    ASSERT(outlen > 0, "server emitted a flight");
    ASSERT(s.hrr_sent == 1, "s.hrr_sent set (real HelloRetryRequest)");
    ASSERT(s.st == TLS13_ST_START, "state still ST_START (awaiting CH2)");

    /* First record: cleartext handshake. */
    ASSERT(out[0] == 0x16, "first record is cleartext handshake (0x16)");
    ASSERT(out[1] == 0x03 && out[2] == 0x03, "HRR record version 0x0303");
    uint16_t frag = (uint16_t)((out[3] << 8) | out[4]);
    ASSERT(5u + frag <= outlen, "HRR fragment fits");

    /* Body = handshake message: 0x02 (server_hello) || u24 len || body. */
    const uint8_t *hs = out + 5;
    ASSERT(hs[0] == 0x02, "HRR handshake type 0x02 (server_hello)");
    /* random is at hs[4..5] (skip 1 type + 3 len) + 2 legacy_version. */
    const uint8_t *random = hs + 4 + 2;
    ASSERT(memcmp(random, HRR_RANDOM, 32) == 0, "HRR random == special value");

    /* The HRR key_share must name the SERVER-PREFERENCE servable group X25519
     * (0x001d) with NO key: byte pattern 00 33 00 02 00 1d. */
    int found_hrr_ks = 0;
    for (uint16_t i = 0; i + 6 <= frag; i++) {
        if (hs[i]==0x00 && hs[i+1]==0x33 && hs[i+2]==0x00 && hs[i+3]==0x02 &&
            hs[i+4]==0x00 && hs[i+5]==0x1d) { found_hrr_ks = 1; break; }
    }
    ASSERT(found_hrr_ks, "HRR key_share names X25519 (0033 0002 001d, no key)");

    /* A cleartext change_cipher_spec should follow the HRR. */
    int found_ccs = 0;
    uint32_t off = 0;
    while (off + 5 <= outlen) {
        uint16_t rl = (uint16_t)((out[off+3] << 8) | out[off+4]);
        if (out[off] == 0x14 && rl == 1) { found_ccs = 1; break; }
        off += 5u + rl;
    }
    ASSERT(found_ccs, "change_cipher_spec follows the HRR");

    /* No application/handshake keys yet — HRR precedes the key schedule. */
    int hs_zero = 1;
    for (int i = 0; i < 16; i++) if (s.s_hs_key[i]) { hs_zero = 0; break; }
    ASSERT(hs_zero, "no handshake key derived yet (HRR is pre-key-schedule)");

    /* Feeding a 2nd CH that STILL lacks a usable share must fail (no loop). */
    {
        tls13_sess_t s2 = s;        /* copy: hrr_sent==1, ST_START */
        uint8_t out2[16384]; uint32_t outlen2 = 0;
        int r2 = tls13_inbound_feed(&s2, CH, chlen, out2, sizeof out2, &outlen2, NULL);
        ASSERT(r2 == -1, "second CH with no usable share is rejected (no loop)");
    }
    return 0;
}

/* ── ε3 A5: build a 0x1302-only HRR-triggering CH ──────────────────────────
 * cipher_suites = {0x1302}, supported_groups = {X25519, x448}, key_share = x448
 * (a group we do NOT serve) → select_group()==0 → genuine HRR for X25519 with the
 * SHA-384 (48B) synthetic message_hash (because the suite is selected pre-HRR). */
static uint32_t build_ch_hrr_1302(void)
{
    chn = 0;
    w8(0x16); w16(0x0301);
    uint32_t rec_len_at = chn; w16(0);

    uint32_t hs_start = chn;
    w8(0x01);
    uint32_t hs_len_at = chn; w24(0);
    uint32_t body_start = chn;

    w16(0x0303);
    for (int i = 0; i < 32; i++) w8((uint8_t)(0xA0 + i));
    w8(32); for (int i = 0; i < 32; i++) w8((uint8_t)(0x10 + i));
    w16(2); w16(0x1302);                      /* cipher_suites: ONLY 0x1302 */
    w8(1); w8(0x00);

    uint32_t ext_len_at = chn; w16(0);
    uint32_t ext_start = chn;

    w16(0x002b); w16(3); w8(2); w16(0x0304);
    /* supported_groups: X25519 (servable, HRR target) AND x448 (the sent share).*/
    w16(0x000a); w16(6); w16(4); w16(0x001d); w16(0x001e);
    /* signature_algorithms: offer rsa_pss_rsae_sha384 (0x0805) for 0x1302. */
    w16(0x000d); w16(6); w16(4); w16(0x0804); w16(0x0805);

    /* key_share: a single x448 share (56-byte point) — a group we do NOT serve. */
    {
        uint8_t x448[56];
        for (int i = 0; i < 56; i++) x448[i] = (uint8_t)(0x40 + i);
        uint16_t entry = 2 + 2 + 56;
        uint16_t ext_body = 2 + entry;
        w16(0x0033); w16(ext_body);
        w16(entry);
        w16(0x001e);                          /* x448 — unserved group */
        w16(56);
        wn(x448, 56);
    }
    return finish_ch(rec_len_at, hs_start, hs_len_at, body_start, ext_len_at, ext_start);
}

/* Build a minimal CH2 carrying a valid X25519 key_share, with a configurable
 * cipher_suites list, used to test the §4.1.4 CH2-suite-unchanged check. */
static const uint8_t X25519_CLI_PUB[32] = {
    0xf5,0x59,0x54,0x79,0x15,0xb2,0xba,0x80,0xe0,0xb8,0x42,0x9a,0xd8,0x0f,0x59,0xab,
    0xc5,0xe1,0x0d,0x15,0xa5,0x5b,0xf4,0x28,0x00,0xf1,0xbc,0xce,0xa8,0x21,0xe2,0x1e
};
static uint32_t build_ch2_x25519(uint16_t suite)
{
    chn = 0;
    w8(0x16); w16(0x0301);
    uint32_t rec_len_at = chn; w16(0);

    uint32_t hs_start = chn;
    w8(0x01);
    uint32_t hs_len_at = chn; w24(0);
    uint32_t body_start = chn;

    w16(0x0303);
    for (int i = 0; i < 32; i++) w8((uint8_t)(0xA0 + i));
    w8(32); for (int i = 0; i < 32; i++) w8((uint8_t)(0x10 + i));
    w16(2); w16(suite);                       /* cipher_suites: the requested one */
    w8(1); w8(0x00);

    uint32_t ext_len_at = chn; w16(0);
    uint32_t ext_start = chn;

    w16(0x002b); w16(3); w8(2); w16(0x0304);
    w16(0x000a); w16(6); w16(4); w16(0x001d); w16(0x001e);
    w16(0x000d); w16(6); w16(4); w16(0x0804); w16(0x0805);

    /* key_share: a single X25519 share (the group HRR asked for). */
    {
        uint16_t entry = 2 + 2 + 32;
        uint16_t ext_body = 2 + entry;
        w16(0x0033); w16(ext_body);
        w16(entry);
        w16(0x001d);                          /* X25519 */
        w16(32);
        wn(X25519_CLI_PUB, 32);
    }
    return finish_ch(rec_len_at, hs_start, hs_len_at, body_start, ext_len_at, ext_start);
}

/* ── case (D): 0x1302 HRR uses a SHA-384 (48B) synthetic message_hash ── */
static int case_hrr_1302_sha384(void)
{
    fprintf(stdout, "--- case D: 0x1302 HRR → SHA-384 (48B) synthetic message_hash ---\n");

    uint32_t chlen = build_ch_hrr_1302();
    fprintf(stdout, "  crafted 0x1302 HRR-triggering ClientHello = %u bytes\n", chlen);

    tls13_clienthello_t parsed;
    ASSERT(tls13_parse_clienthello(CH, chlen, &parsed) == 0, "crafted 0x1302 CH parses");
    ASSERT(parsed.ok, "CH offers TLS 1.3");
    ASSERT(parsed.suite_1302, "CH offers suite 0x1302");
    ASSERT(!parsed.suite_1301, "CH does NOT offer 0x1301");
    ASSERT(parsed.x25519_in_groups, "CH lists X25519 (servable) in supported_groups");
    ASSERT(!parsed.has_x25519_share, "CH has NO X25519 key_share (only x448)");

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    s.st = TLS13_ST_START;

    uint8_t out[16384];
    uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, CH, chlen, out, sizeof out, &outlen, NULL);

    ASSERT(r == 0, "tls13_inbound_feed returns 0 (HRR path)");
    ASSERT(s.hrr_sent == 1, "s.hrr_sent set (real HelloRetryRequest)");
    ASSERT(s.st == TLS13_ST_START, "state still ST_START (awaiting CH2)");

    /* The suite is selected on CH1 BEFORE the HRR branch. */
    ASSERT(s.suite != NULL, "s.suite selected on CH1");
    ASSERT(s.suite->id == TLS13_AES_256_GCM_SHA384, "selected suite is 0x1302");
    ASSERT(s.suite->hash_len == 48, "selected suite is SHA-384");

    /* The synthetic message_hash is the FIRST message in the transcript buffer:
     *   fe 00 00 30 || SHA-384(CH1)   (52 bytes: 4 header + 48 hash)
     * length byte 0x30 == 48 proves the SHA-384 (not SHA-256 0x20) synth. */
    ASSERT(s.th_buf[0] == 0xfe, "synth message_hash type 0xfe");
    ASSERT(s.th_buf[1] == 0x00 && s.th_buf[2] == 0x00, "synth u24 high bytes 0x0000");
    ASSERT(s.th_buf[3] == 0x30, "synth length byte == 0x30 (48 = SHA-384)");
    /* The synth (52B) is followed by the HRR handshake message in th_buf. */
    ASSERT(s.th_len > 52, "transcript = 52B synth + HRR message");

    /* The synthetic hash must NOT be a 32B SHA-256 synth (length byte 0x20). */
    ASSERT(s.th_buf[3] != 0x20, "synth length is NOT 0x20 (no SHA-256 leak on 0x1302)");

    return 0;
}

/* ── case (E): §4.1.4 — CH2 selecting a DIFFERENT suite than CH1 is REJECTED ──
 * Drive a genuine 0x1302 HRR, then feed a CH2 that offers a DIFFERENT suite
 * (0x1301) with a valid X25519 share.  The server MUST reject (ST_ERR). */
static int case_ch2_suite_change_rejected(void)
{
    fprintf(stdout, "--- case E: §4.1.4 CH2 changing suite (0x1302→0x1301) REJECTED ---\n");

    uint32_t ch1len = build_ch_hrr_1302();
    uint8_t ch1[1024]; memcpy(ch1, CH, ch1len);

    tls13_sess_t s;
    memset(&s, 0, sizeof s);
    s.st = TLS13_ST_START;
    uint8_t out[16384]; uint32_t outlen = 0;
    int r = tls13_inbound_feed(&s, ch1, ch1len, out, sizeof out, &outlen, NULL);
    ASSERT(r == 0, "CH1 → HRR ok");
    ASSERT(s.hrr_sent == 1, "HRR emitted on CH1");
    ASSERT(s.suite->id == TLS13_AES_256_GCM_SHA384, "CH1 selected 0x1302");

    /* CH2 with a valid X25519 share BUT a different suite (0x1301). */
    uint32_t ch2len = build_ch2_x25519(TLS13_AES_128_GCM_SHA256);
    uint8_t ch2[1024]; memcpy(ch2, CH, ch2len);

    uint8_t out2[16384]; uint32_t outlen2 = 0;
    int r2 = tls13_inbound_feed(&s, ch2, ch2len, out2, sizeof out2, &outlen2, NULL);
    ASSERT(r2 == -1, "CH2 changing the suite (0x1301 != CH1's 0x1302) is REJECTED");
    ASSERT(s.st == TLS13_ST_ERR, "state == ERR after suite-change CH2");

    /* Control: a CH2 that KEEPS 0x1302 with a valid X25519 share is ACCEPTED. */
    tls13_sess_t s2;
    memset(&s2, 0, sizeof s2);
    s2.st = TLS13_ST_START;
    uint8_t o1[16384]; uint32_t ol1 = 0;
    ASSERT(tls13_inbound_feed(&s2, ch1, ch1len, o1, sizeof o1, &ol1, NULL) == 0, "CH1 → HRR ok (control)");
    uint32_t ch2ok_len = build_ch2_x25519(TLS13_AES_256_GCM_SHA384);
    uint8_t ch2ok[1024]; memcpy(ch2ok, CH, ch2ok_len);
    uint8_t o2[16384]; uint32_t ol2 = 0;
    int rok = tls13_inbound_feed(&s2, ch2ok, ch2ok_len, o2, sizeof o2, &ol2, NULL);
    ASSERT(rok == 0, "CH2 keeping 0x1302 + valid X25519 share is ACCEPTED");
    ASSERT(s2.st == TLS13_ST_WAIT_FINISHED, "control CH2 drives to WAIT_FINISHED");
    ASSERT(s2.suite->id == TLS13_AES_256_GCM_SHA384, "control session stays 0x1302");

    return 0;
}

int main(void)
{
    fprintf(stdout, "=== test_hrr: P-256 direct-accept + genuine HelloRetryRequest"
            " + §4.2.8 regression ===\n");
    if (case_p256_direct() != 0)       return 1;
    if (case_genuine_hrr() != 0)       return 1;
    if (case_c_ks_not_in_groups() != 0) return 1;
    if (case_hrr_1302_sha384() != 0)   return 1;
    if (case_ch2_suite_change_rejected() != 0) return 1;
    fprintf(stdout, "=== PASS ===\n");
    return 0;
}
