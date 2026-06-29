/* tls13.c — ε1 ClientHello parse + TLS 1.3 dispatch peek (Task 6) +
              handshake-message serializers (Task 7). */
#include <net-synth/tls13.h>
#include <net-synth/tls_cert.h>
#include <net-synth/tls13_keysched.h>
#include "tls13_wire.h"
#include "tls13_sign.h"
#include "tls13_aead.h"
#include "tls_rng.h"
#include <bearssl.h>
#include <string.h>

/* ── internal helpers ────────────────────────────────────────────────────── */

/* Bounds-safe 1-byte read. */
static inline int safe_u8(const uint8_t *buf, uint32_t buflen,
                           uint32_t off, uint8_t *out)
{
    if (off >= buflen) return -1;
    *out = buf[off];
    return 0;
}

/* Bounds-safe 2-byte big-endian read. */
static inline int safe_u16(const uint8_t *buf, uint32_t buflen,
                            uint32_t off, uint16_t *out)
{
    if ((uint64_t)off + 2 > buflen) return -1;
    *out = tls13_rd16(buf + off);
    return 0;
}

/* Bounds-safe 3-byte big-endian read. */
static inline int safe_u24(const uint8_t *buf, uint32_t buflen,
                            uint32_t off, uint32_t *out)
{
    if ((uint64_t)off + 3 > buflen) return -1;
    *out = tls13_rd24(buf + off);
    return 0;
}

/* Advance offset by `n`; return -1 if that would exceed buflen. */
static inline int safe_advance(uint32_t *off, uint32_t n, uint32_t buflen)
{
    if ((uint64_t)*off + n > buflen) return -1;
    *off += n;
    return 0;
}

/* ── extension walkers ───────────────────────────────────────────────────── */

/*
 * Parse the extensions block of a ClientHello that starts at `ext_start`
 * within `rec` and spans `ext_total` bytes.  Fills `out` fields for each
 * extension we care about.  Returns 0 on success, -1 on any OOB read.
 */
static int walk_extensions(const uint8_t *rec, uint32_t reclen,
                            uint32_t ext_start, uint16_t ext_total,
                            tls13_clienthello_t *out)
{
    /* Guard: the whole extensions block must fit. */
    if ((uint64_t)ext_start + ext_total > reclen) return -1;

    uint32_t off = ext_start;
    uint32_t ext_end = ext_start + ext_total;

    while (off + 4 <= ext_end) {
        uint16_t etype, elen;
        if (safe_u16(rec, reclen, off, &etype) < 0) return -1;
        off += 2;
        if (safe_u16(rec, reclen, off, &elen)  < 0) return -1;
        off += 2;

        /* ext body must fit within the extensions block */
        if ((uint64_t)off + elen > ext_end) return -1;

        uint32_t body_off = off;   /* start of this extension's body */
        uint32_t body_end = off + elen;

        switch (etype) {

        /* ── supported_versions (0x002b) ──────────────────────────────── */
        case 0x002b: {
            if (body_off >= body_end) break;  /* empty body, skip */
            uint8_t list_len;
            if (safe_u8(rec, reclen, body_off, &list_len) < 0) return -1;
            uint32_t loff = body_off + 1;
            if ((uint64_t)loff + list_len > body_end) return -1;
            for (uint32_t i = 0; i + 2 <= (uint32_t)list_len; i += 2) {
                uint16_t ver;
                if (safe_u16(rec, reclen, loff + i, &ver) < 0) return -1;
                if (ver == 0x0304) {
                    out->ok = 1;  /* TLS 1.3 offered */
                }
            }
            break;
        }

        /* ── supported_groups (0x000a) ─────────────────────────────────── */
        case 0x000a: {
            if ((uint64_t)body_off + 2 > body_end) break;
            uint16_t grp_len;
            if (safe_u16(rec, reclen, body_off, &grp_len) < 0) return -1;
            uint32_t goff = body_off + 2;
            if ((uint64_t)goff + grp_len > body_end) return -1;
            for (uint32_t i = 0; i + 2 <= (uint32_t)grp_len; i += 2) {
                uint16_t grp;
                if (safe_u16(rec, reclen, goff + i, &grp) < 0) return -1;
                if (grp == TLS13_GROUP_X25519) {
                    out->x25519_in_groups = 1;
                } else if (grp == TLS13_GROUP_SECP256R1) {
                    out->p256_in_groups = 1;
                } else if (grp == TLS13_GROUP_SECP384R1) {
                    out->p384_in_groups = 1;
                }
            }
            break;
        }

        /* ── key_share (0x0033) ─────────────────────────────────────────── */
        case 0x0033: {
            if ((uint64_t)body_off + 2 > body_end) break;
            uint16_t shares_len;
            if (safe_u16(rec, reclen, body_off, &shares_len) < 0) return -1;
            uint32_t soff = body_off + 2;
            if ((uint64_t)soff + shares_len > body_end) return -1;
            uint32_t send = soff + shares_len;
            while (soff + 4 <= send) {
                uint16_t grp, klen;
                if (safe_u16(rec, reclen, soff, &grp) < 0) return -1;
                soff += 2;
                if (safe_u16(rec, reclen, soff, &klen) < 0) return -1;
                soff += 2;
                if ((uint64_t)soff + klen > send) return -1;
                if (grp == TLS13_GROUP_X25519 && klen == 32 &&
                    !out->has_x25519_share) {
                    memcpy(out->client_x25519, rec + soff, 32);
                    out->has_x25519_share = 1;
                } else if (grp == TLS13_GROUP_SECP256R1 && klen == 65 &&
                           rec[soff] == 0x04 && !out->has_p256_share) {
                    /* uncompressed point 0x04||X(32)||Y(32) */
                    memcpy(out->client_p256, rec + soff, 65);
                    out->has_p256_share = 1;
                } else if (grp == TLS13_GROUP_SECP384R1 && klen == 97 &&
                           rec[soff] == 0x04 && !out->has_p384_share) {
                    /* uncompressed point 0x04||X(48)||Y(48) */
                    memcpy(out->client_p384, rec + soff, 97);
                    out->has_p384_share = 1;
                }
                soff += klen;
            }
            break;
        }

        /* ── signature_algorithms (0x000d) ─────────────────────────────── */
        case 0x000d: {
            if ((uint64_t)body_off + 2 > body_end) break;
            uint16_t sa_len;
            if (safe_u16(rec, reclen, body_off, &sa_len) < 0) return -1;
            uint32_t saoff = body_off + 2;
            if ((uint64_t)saoff + sa_len > body_end) return -1;
            for (uint32_t i = 0; i + 2 <= (uint32_t)sa_len; i += 2) {
                uint16_t sa;
                if (safe_u16(rec, reclen, saoff + i, &sa) < 0) return -1;
                if (sa == 0x0804) {
                    out->sigalg_0804 = 1;
                }
            }
            break;
        }

        default:
            break;
        }

        off = body_end;
    }

    return 0;
}

/* ── public API ──────────────────────────────────────────────────────────── */

/*
 * tls13_parse_clienthello
 *
 * Parses a full TLS record (rec, reclen) that is expected to be a
 * ClientHello.  Fills *out; returns 0 on a structurally valid ClientHello
 * (even if optional fields are absent), -1 on malformed/OOB/not-a-CH.
 *
 * Record layout (RFC 8446 §5.1 + §4.1.2):
 *   rec[0]     = content_type  (0x16 = handshake)
 *   rec[1..2]  = legacy_record_version
 *   rec[3..4]  = fragment length (u16)
 *   rec[5]     = HandshakeType (0x01 = client_hello)
 *   rec[6..8]  = handshake body length (u24)
 *   rec[9..10] = legacy_version (0x0303)
 *   rec[11..42]= random (32 bytes)
 *   rec[43]    = session_id length (u8)
 *   ...        = session_id bytes
 *   (u16) cipher_suites length
 *   cipher_suite list
 *   (u8) compression methods length
 *   compression methods
 *   (u16) extensions length
 *   extension list
 */
int tls13_parse_clienthello(const uint8_t *rec, uint32_t reclen,
                             tls13_clienthello_t *out)
{
    if (!rec || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* ── TLS record header (5 bytes) ─────────────────────────────────── */
    if (reclen < 5) return -1;
    if (rec[0] != 0x16) return -1;           /* must be handshake */

    uint16_t frag_len;
    if (safe_u16(rec, reclen, 3, &frag_len) < 0) return -1;
    /* The fragment must fit inside the buffer we were given. */
    if ((uint32_t)frag_len + 5u > reclen) return -1;

    /* Clamp our view to exactly what the record header claims. */
    uint32_t rend = 5u + frag_len;           /* exclusive end of record */

    /* ── Handshake header (4 bytes: type + u24 length) ───────────────── */
    if (rend < 5u + 4u) return -1;
    if (rec[5] != 0x01) return -1;           /* must be ClientHello */

    uint32_t hs_len;
    if (safe_u24(rec, rend, 6, &hs_len) < 0) return -1;
    if ((uint64_t)9u + hs_len > rend) return -1;

    uint32_t hs_end = 9u + hs_len;           /* exclusive end of HS body */
    uint32_t off    = 9u;

    /* ── ClientHello body ────────────────────────────────────────────── */

    /* legacy_version (2 bytes) */
    if (safe_advance(&off, 2, hs_end) < 0) return -1;

    /* random (32 bytes) */
    if (safe_advance(&off, 32, hs_end) < 0) return -1;

    /* session_id: u8 length + bytes */
    uint8_t sid_len;
    if (safe_u8(rec, hs_end, off, &sid_len) < 0) return -1;
    off += 1;
    if (sid_len > 32) return -1;             /* RFC max is 32 */
    if (safe_advance(&off, sid_len, hs_end) < 0) return -1;
    out->session_id_len = sid_len;
    if (sid_len > 0)
        memcpy(out->session_id, rec + (off - sid_len), sid_len);

    /* cipher_suites: u16 length + u16 list */
    uint16_t cs_len;
    if (safe_u16(rec, hs_end, off, &cs_len) < 0) return -1;
    off += 2;
    if ((uint64_t)off + cs_len > hs_end) return -1;
    /* Scan the offered cipher_suites for the three TLS 1.3 suites we serve.
     * GREASE / unknown suites are ignored (no flag set).  ε4: also record the
     * FIRST served suite in client wire order (first_served_suite) so
     * select_suite can honor the client's order (match default nginx). */
    for (uint32_t i = 0; i + 2 <= (uint32_t)cs_len; i += 2) {
        uint16_t suite;
        if (safe_u16(rec, hs_end, off + i, &suite) < 0) return -1;
        if      (suite == TLS13_AES_128_GCM_SHA256)       out->suite_1301 = 1;
        else if (suite == TLS13_AES_256_GCM_SHA384)       out->suite_1302 = 1;
        else if (suite == TLS13_CHACHA20_POLY1305_SHA256) out->suite_1303 = 1;
        else continue;   /* GREASE/unknown: skip without affecting client order */
        if (out->first_served_suite == 0) out->first_served_suite = suite;
    }
    off += cs_len;

    /* compression methods: u8 length + bytes */
    uint8_t comp_len;
    if (safe_u8(rec, hs_end, off, &comp_len) < 0) return -1;
    off += 1;
    if (safe_advance(&off, comp_len, hs_end) < 0) return -1;

    /* extensions: u16 total length + extension list */
    if ((uint64_t)off + 2u > hs_end) return -1;
    uint16_t ext_total;
    if (safe_u16(rec, hs_end, off, &ext_total) < 0) return -1;
    off += 2;
    if ((uint64_t)off + ext_total > hs_end) return -1;

    /* Walk every extension, collecting what we need. */
    if (walk_extensions(rec, hs_end, off, ext_total, out) < 0) return -1;

    return 0;
}

/*
 * tls13_clienthello_offers_13
 *
 * Quick-peek variant: returns 1 if the record is a ClientHello that offers
 * TLS 1.3 via the supported_versions extension, 0 if it's a valid
 * ClientHello that does not offer TLS 1.3, -1 if it's malformed or not a
 * ClientHello.
 */
int tls13_clienthello_offers_13(const uint8_t *rec, uint32_t reclen)
{
    tls13_clienthello_t ch;
    if (reclen < 5)           return -1;
    if (rec[0] != 0x16)       return -1;
    if (reclen < 9 || rec[5] != 0x01) return -1;  /* fast path: not a CH */

    int r = tls13_parse_clienthello(rec, reclen, &ch);
    if (r < 0) return -1;
    return ch.ok ? 1 : 0;
}

/* ── Task 7: handshake-message serializers ───────────────────────────────
 *
 * All serializers follow the same pattern:
 *   • Write into a local staging buffer to compute exact body length.
 *   • bounds-check cap before any write to *out.
 *   • Return total bytes written, or 0 on overflow.
 *
 * Body layout: u8(hs_type) || u24(body_len) || body
 * The caller manages TLS record framing; we produce raw handshake messages.
 * ──────────────────────────────────────────────────────────────────────── */

/* Overflow guard: return 0 if total bytes needed exceed cap. */
#define CHK_CAP(total, cap)  do { if ((total) > (cap)) return 0; } while(0)

/* ── EncryptedExtensions ─────────────────────────────────────────────── */
size_t tls13_make_ee(uint8_t *out, size_t cap)
{
    CHK_CAP(6, cap);
    uint8_t *p = out;
    p += tls13_wr8 (p, 0x08);          /* HandshakeType = encrypted_extensions */
    p += tls13_wr24(p, 2);             /* body length = 2 */
    p += tls13_wr16(p, 0x0000);        /* empty extensions list */
    return (size_t)(p - out);
}

/* ── ServerHello ─────────────────────────────────────────────────────── */
size_t tls13_make_serverhello(uint8_t *out, size_t cap,
                              uint16_t suite_id, uint16_t group,
                              const uint8_t *srv_pub, uint16_t srv_pub_len,
                              const uint8_t *session_id, uint8_t sid_len,
                              void (*rng_fill)(uint8_t *, size_t))
{
    /* Body:
     *  2  legacy_version = 0x0303
     * 32  random
     *  1  session_id_len
     * sid_len  session_id echo
     *  2  cipher_suite = suite_id (0x1301/0x1302/0x1303)
     *  1  legacy_compression = 0x00
     *  2  extensions_len
     *  6  supported_versions ext: 002b 0002 0304
     *  8+srv_pub_len  key_share ext: 0033 <extlen> <group> <klen> <pub>
     *      (klen = srv_pub_len = 32 X25519 / 65 P-256 / 97 P-384)
     */
    size_t ks_ext_body = 2 + 2 + (size_t)srv_pub_len;  /* group + klen + key  */
    size_t ks_ext      = 4 + ks_ext_body;              /* ext type + ext_len  */
    size_t ext_total   = 6 + ks_ext;                   /* supp_ver + key_share */
    size_t body_len    = 2 + 32 + 1 + sid_len + 2 + 1 + 2 + ext_total;
    size_t total       = 4 + body_len;
    CHK_CAP(total, cap);

    uint8_t *p = out;

    /* Handshake header */
    p += tls13_wr8 (p, 0x02);             /* server_hello */
    p += tls13_wr24(p, (uint32_t)body_len);

    /* legacy_version */
    p += tls13_wr16(p, 0x0303);

    /* random (32 bytes from rng_fill) */
    rng_fill(p, 32);
    p += 32;

    /* session_id echo */
    p += tls13_wr8(p, sid_len);
    if (sid_len > 0) {
        memcpy(p, session_id, sid_len);
        p += sid_len;
    }

    /* cipher_suite (the selected suite) */
    p += tls13_wr16(p, suite_id);

    /* legacy_compression */
    p += tls13_wr8(p, 0x00);

    /* extensions_len = supported_versions(6) + key_share(8+srv_pub_len) */
    p += tls13_wr16(p, (uint16_t)ext_total);

    /* supported_versions: type=0x002b, len=2, selected=0x0304 */
    p += tls13_wr16(p, 0x002b);
    p += tls13_wr16(p, 0x0002);
    p += tls13_wr16(p, 0x0304);

    /* key_share: type=0x0033, ext_body_len, group, key_len, key */
    p += tls13_wr16(p, 0x0033);
    p += tls13_wr16(p, (uint16_t)ks_ext_body); /* group(2)+klen(2)+key(klen) */
    p += tls13_wr16(p, group);
    p += tls13_wr16(p, srv_pub_len);
    memcpy(p, srv_pub, srv_pub_len);
    p += srv_pub_len;

    return (size_t)(p - out);
}

/* ── HelloRetryRequest (Task 9) ──────────────────────────────────────────
 * RFC 8446 §4.1.4: HRR has the same structure as ServerHello but with the
 * fixed special random and a key_share extension that names the selected
 * group (X25519, 0x001d) WITHOUT a key.
 *
 * The special random (§4.1.3): SHA-256("HelloRetryRequest"). */
static const uint8_t TLS13_HRR_RANDOM[32] = {
    0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
    0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
};

size_t tls13_make_hrr(uint8_t *out, size_t cap,
                      uint16_t suite_id, uint16_t group,
                      const uint8_t *session_id, uint8_t sid_len)
{
    /* Body:
     *  2  legacy_version = 0x0303
     * 32  random = special HRR value
     *  1  session_id_len
     * sid_len  session_id echo
     *  2  cipher_suite = suite_id (must match the eventual ServerHello)
     *  1  legacy_compression = 0x00
     *  2  extensions_len
     *  6  supported_versions ext: 002b 0002 0304
     *  6  key_share ext:          0033 0002 <group>  (selected group, NO key)
     */
    size_t body_len = 2 + 32 + 1 + sid_len + 2 + 1 + 2 + 6 + 6;
    size_t total    = 4 + body_len;
    CHK_CAP(total, cap);

    uint8_t *p = out;

    /* Handshake header (HRR uses the server_hello type per RFC 8446 §4.1.4). */
    p += tls13_wr8 (p, 0x02);
    p += tls13_wr24(p, (uint32_t)body_len);

    /* legacy_version */
    p += tls13_wr16(p, 0x0303);

    /* random = special HRR value */
    memcpy(p, TLS13_HRR_RANDOM, 32);
    p += 32;

    /* session_id echo */
    p += tls13_wr8(p, sid_len);
    if (sid_len > 0) {
        memcpy(p, session_id, sid_len);
        p += sid_len;
    }

    /* cipher_suite (the selected suite; HRR must match the eventual SH) */
    p += tls13_wr16(p, suite_id);

    /* legacy_compression */
    p += tls13_wr8(p, 0x00);

    /* extensions_len = 6 + 6 = 12 */
    p += tls13_wr16(p, 12);

    /* supported_versions: type=0x002b, len=2, selected=0x0304 */
    p += tls13_wr16(p, 0x002b);
    p += tls13_wr16(p, 0x0002);
    p += tls13_wr16(p, 0x0304);

    /* key_share (HRR variant): type=0x0033, len=2, selected_group.
     * No key in HRR — the body is just the 2-byte selected group. */
    p += tls13_wr16(p, 0x0033);
    p += tls13_wr16(p, 0x0002);
    p += tls13_wr16(p, group);

    return (size_t)(p - out);
}

/* ── Certificate ─────────────────────────────────────────────────────── */
size_t tls13_make_cert(uint8_t *out, size_t cap)
{
    size_t der_len      = CHAIN[0].data_len;
    /* cert_list entry: u24(cert_data_len) + cert_data + u16(extensions=0) */
    size_t cert_entry   = 3 + der_len + 2;
    /* body: u8(ctx_len=0) + u24(cert_list_len) + cert_entry */
    size_t body_len     = 1 + 3 + cert_entry;
    size_t total        = 4 + body_len;
    CHK_CAP(total, cap);

    uint8_t *p = out;

    p += tls13_wr8 (p, 0x0b);                       /* Certificate */
    p += tls13_wr24(p, (uint32_t)body_len);

    p += tls13_wr8 (p, 0x00);                        /* empty request context */
    p += tls13_wr24(p, (uint32_t)cert_entry);        /* cert_list length */
    p += tls13_wr24(p, (uint32_t)der_len);           /* cert_data length */
    memcpy(p, CHAIN[0].data, der_len);
    p += der_len;
    p += tls13_wr16(p, 0x0000);                      /* extensions (empty) */

    return (size_t)(p - out);
}

/* ── CertificateVerify ───────────────────────────────────────────────── */
size_t tls13_make_certverify(uint8_t *out, size_t cap,
                             const tls13_suite_t *suite,
                             const uint8_t *th, size_t th_len,
                             void (*rng_fill)(uint8_t *, size_t))
{
    /* body: u16(sigalg) + u16(sig_len=256) + 256 sig bytes = 260 */
    size_t total = 4 + 260;
    CHK_CAP(total, cap);
    if (suite == NULL) return 0;

    /* sigalg + transcript-hash length come from the suite (0x1301/0x1303 →
     * 0x0804 over 32B SHA-256; 0x1302 → 0x0805 over 48B SHA-384).  The PSS
     * inner hash is then chosen from the sigalg inside tls13_sign_certverify
     * (landmine #3: transcript-hash source ≠ PSS-param source). */
    const uint16_t sigalg = suite->sigalg;

    uint8_t *p = out;
    p += tls13_wr8 (p, 0x0f);      /* CertificateVerify */
    p += tls13_wr24(p, 260);

    p += tls13_wr16(p, sigalg);    /* rsa_pss_rsae_sha256/384 */
    p += tls13_wr16(p, 256);       /* signature length */

    size_t sig_n = tls13_sign_certverify(sigalg, th, th_len, p, 256, rng_fill);
    if (sig_n != 256) return 0;
    p += 256;

    return (size_t)(p - out);
}

/* ── Finished ────────────────────────────────────────────────────────── */
size_t tls13_make_finished(uint8_t *out, size_t cap,
                           const tls13_suite_t *suite,
                           const uint8_t *finished_key,
                           const uint8_t *th)
{
    if (suite == NULL) suite = tls13_suite_by_id(0x1301);   /* pre-A5 default */
    const br_hash_class *vt   = (const br_hash_class *)suite->hash_vtable;
    size_t               hlen = suite->finished_len;        /* == hash_len */

    /* body: hlen-byte HMAC-H(finished_key, transcript_hash) */
    size_t total = 4 + hlen;
    CHK_CAP(total, cap);

    uint8_t *p = out;
    p += tls13_wr8 (p, 0x14);                /* Finished */
    p += tls13_wr24(p, (uint32_t)hlen);

    /* HMAC over the suite hash (SHA-256 32B | SHA-384 48B) using BearSSL br_hmac */
    br_hmac_key_context kc;
    br_hmac_context     hc;
    br_hmac_key_init(&kc, vt, finished_key, hlen);
    br_hmac_init(&hc, &kc, hlen);
    br_hmac_update(&hc, th, hlen);
    br_hmac_out(&hc, p);
    p += hlen;

    return (size_t)(p - out);
}

/* ── Task 8: server handshake state machine driver ───────────────────────────
 *
 * tls13_inbound_feed processes every TLS record in `in` and appends the server's
 * response records to `out`.  The transcript (s->th_buf/th_len) holds the
 * concatenation of handshake MESSAGES (u8 type||u24 len||body) — no record
 * headers, no change_cipher_spec — in RFC 8446 order.
 *
 * Sequence/epoch (RFC 8446 §5.3): the record sequence number resets to 0 every
 * time the traffic key changes.  We track s->seq_tx/s->seq_rx and reset on each
 * epoch switch (server handshake → server app; client handshake → client app).
 * ──────────────────────────────────────────────────────────────────────────── */

/* Append a cleartext handshake record [type 0x16 | 0x0303 | u16 len | frag] to out.
 * Returns 0 ok, -1 on overflow. */
static int emit_cleartext_hs(uint8_t *out, uint32_t outcap, uint32_t *opos,
                             const uint8_t *msg, size_t msg_len)
{
    if ((uint64_t)*opos + 5 + msg_len > outcap) return -1;
    uint8_t *p = out + *opos;
    p[0] = 0x16; p[1] = 0x03; p[2] = 0x03;
    tls13_wr16(p + 3, (uint16_t)msg_len);
    memcpy(p + 5, msg, msg_len);
    *opos += (uint32_t)(5 + msg_len);
    return 0;
}

/* Append a handshake message to the transcript buffer. Returns 0 ok, -1 if full. */
static int th_append(tls13_sess_t *s, const uint8_t *msg, size_t msg_len)
{
    if (s->th_len + msg_len > sizeof(s->th_buf)) return -1;
    memcpy(s->th_buf + s->th_len, msg, msg_len);
    s->th_len += msg_len;
    return 0;
}

/* Build one handshake message via `make`, append it to the transcript, then seal
 * it as an encrypted record (inner_type 0x16) under the server handshake key and
 * append it to out.  msgbuf is caller scratch.  Returns 0 ok, -1 on any failure. */
static int append_and_seal_hs(tls13_sess_t *s, uint8_t *msgbuf, size_t msg_len,
                              uint8_t *out, uint32_t outcap, uint32_t *opos)
{
    if (msg_len == 0) return -1;
    if (th_append(s, msgbuf, msg_len) < 0) return -1;
    if (*opos > outcap) return -1;
    size_t n = tls13_record_seal(s->suite, s->s_hs_key, s->s_hs_iv, s->seq_tx++,
                                 0x16, msgbuf, msg_len,
                                 out + *opos, outcap - *opos);
    if (n == 0) return -1;
    *opos += (uint32_t)n;
    return 0;
}

/* Build and emit the full server flight (ServerHello .. server Finished),
 * shared by the no-HRR path and the HRR path.  PRECONDITION: s->th_buf already
 * holds the transcript up to and including the ClientHello that precedes the
 * ServerHello (CH1 for the happy path, or synthetic||HRR||CH2 for the HRR path),
 * and s->ecdhe_shared / s->srv_eph_pub / s->legacy_session_id are set.
 * Drives the key schedule and leaves s->st = TLS13_ST_WAIT_FINISHED.
 * Returns 0 ok, -1 on failure (caller sets ST_ERR). */
static int build_server_flight(tls13_sess_t *s,
                               uint8_t *out, uint32_t outcap, uint32_t *opos)
{
    /* (4) ServerHello: build, transcript, emit as a CLEARTEXT record. */
    uint8_t shmsg[256];
    size_t  shn = tls13_make_serverhello(shmsg, sizeof shmsg,
                                         s->suite->id,
                                         s->selected_group,
                                         s->srv_eph_pub, s->srv_eph_pub_len,
                                         s->legacy_session_id,
                                         s->legacy_session_id_len, tls_rng_fill);
    if (shn == 0) return -1;
    if (th_append(s, shmsg, shn) < 0) return -1;
    if (emit_cleartext_hs(out, outcap, opos, shmsg, shn) < 0) return -1;

    /* (5) Handshake key schedule (th = CH..SH). New epoch → seq_tx = 0.
     * th buffers sized to SHA-384 max (48B); transcript_hash writes
     * suite->hash_len bytes (32 SHA-256 | 48 SHA-384). */
    uint8_t th_chsh[48];
    tls13_transcript_hash(s->suite, s->th_buf, s->th_len, th_chsh);
    tls13_key_schedule_handshake(s, th_chsh);
    s->seq_tx = 0;   /* server handshake epoch */
    s->tx_app = 0;

    /* (6) change_cipher_spec (cleartext, never transcript). */
    if ((uint64_t)*opos + 6 > outcap) return -1;
    { static const uint8_t ccs[6] = {0x14,0x03,0x03,0x00,0x01,0x01};
      memcpy(out + *opos, ccs, 6); *opos += 6; }

    /* (7) EE, Cert, CertVerify, Finished — each appended to transcript then
     *     sealed under the server handshake key. */
    uint8_t msg[2048];

    /* EncryptedExtensions */
    { size_t n = tls13_make_ee(msg, sizeof msg);
      if (append_and_seal_hs(s, msg, n, out, outcap, opos) < 0) return -1; }

    /* Certificate */
    { size_t n = tls13_make_cert(msg, sizeof msg);
      if (append_and_seal_hs(s, msg, n, out, outcap, opos) < 0) return -1; }

    /* CertificateVerify: th over CH..Cert (BEFORE appending CertVerify).
     * th sized to the suite hash (32 SHA-256 | 48 SHA-384). s->suite is set by
     * select_suite() on CH1, before this flight is built. */
    { uint8_t th_cert[48];
      tls13_transcript_hash(s->suite, s->th_buf, s->th_len, th_cert);
      size_t n = tls13_make_certverify(msg, sizeof msg, s->suite,
                                       th_cert, s->suite->hash_len, tls_rng_fill);
      if (append_and_seal_hs(s, msg, n, out, outcap, opos) < 0) return -1; }

    /* server Finished: th over CH..CertVerify, key = s_finished_key.
     * th_cv sized to SHA-384 max; make_finished reads suite->finished_len. */
    { uint8_t th_cv[48];
      tls13_transcript_hash(s->suite, s->th_buf, s->th_len, th_cv);
      size_t n = tls13_make_finished(msg, sizeof msg, s->suite,
                                     s->s_finished_key, th_cv);
      if (append_and_seal_hs(s, msg, n, out, outcap, opos) < 0) return -1; }

    /* (8) Application key schedule (th = CH..server Finished). */
    uint8_t th_full[48];
    tls13_transcript_hash(s->suite, s->th_buf, s->th_len, th_full);
    tls13_key_schedule_application(s, th_full);

    s->st     = TLS13_ST_WAIT_FINISHED;
    s->rx_app = 0;       /* client Finished still uses client handshake key */
    s->seq_rx = 0;       /* client handshake epoch */
    return 0;
}

/* Test hook (default NULL → production path): when set, derive_ecdhe asks this
 * for the server ephemeral scalar instead of generating a fresh random one
 * (via tls_rng_fill for X25519 or br_ec_keygen for the prime curves). This lets
 * the oracle-gated host test (test_ecdhe.c) feed the SAME fixed scalar the Python
 * ECDH oracle used, so the C server pub + shared secret byte-match the golden.
 * Returns the scalar length written into priv, or 0 if it declines (→ fall back
 * to the real RNG). NEVER invoked when NULL in any production build. */
int (*tls13_test_scalar_hook)(uint16_t group, uint8_t *priv, size_t cap) = 0;

/* Compute the server ephemeral key + ECDHE shared secret for `group` from a
 * ClientHello's key_share (client_pub, client_pub_len). Group dispatch:
 *   X25519 (0x001d): br_ec_c25519_m31, priv/pub/shared all 32B; the full 32B
 *     mul() output IS the shared secret.
 *   P-256 (0x0017) / P-384 (0x0018): br_ec_prime_i31, priv 32/48, pub 65/97
 *     (uncompressed 0x04||X||Y); mul() yields the full uncompressed point in
 *     place and the ECDHE shared secret is ONLY the X-coordinate, found via
 *     impl->xoff(curve,&xlen) (offset 1, len 32/48).
 * Fills s->srv_eph_priv/_len, s->srv_eph_pub/_len, s->ecdhe_shared/_len, and
 * s->selected_group. Returns 0 ok, -1 on bad input / all-zero shared / overflow. */
static int derive_ecdhe(tls13_sess_t *s, uint16_t group,
                        const uint8_t *client_pub, uint16_t client_pub_len)
{
    if (!client_pub) return -1;

    if (group == TLS13_GROUP_X25519) {
        if (client_pub_len != 32) return -1;
        if (!(tls13_test_scalar_hook &&
              tls13_test_scalar_hook(group, s->srv_eph_priv, 32) == 32))
            tls_rng_fill(s->srv_eph_priv, 32);
        s->srv_eph_priv_len = 32;
        (void)br_ec_c25519_m31.mulgen(s->srv_eph_pub, s->srv_eph_priv, 32,
                                      BR_EC_curve25519);
        s->srv_eph_pub_len = 32;
        uint8_t shared[32];
        memcpy(shared, client_pub, 32);   /* mul is in-place on the point */
        uint32_t ecok = br_ec_c25519_m31.mul(shared, 32, s->srv_eph_priv, 32,
                                             BR_EC_curve25519);
        uint8_t zz = 0; for (int i = 0; i < 32; i++) zz |= shared[i];
        if (!ecok || zz == 0) return -1;  /* all-zero K guard */
        memcpy(s->ecdhe_shared, shared, 32);
        s->ecdhe_shared_len = 32;
        s->selected_group = TLS13_GROUP_X25519;
        return 0;
    }

    /* Prime curves P-256 / P-384 via br_ec_prime_i31. */
    int      curve;
    size_t   privlen, publen;
    if (group == TLS13_GROUP_SECP256R1) {
        curve = BR_EC_secp256r1; privlen = 32; publen = 65;
    } else if (group == TLS13_GROUP_SECP384R1) {
        curve = BR_EC_secp384r1; privlen = 48; publen = 97;
    } else {
        return -1;  /* unsupported group */
    }
    if (client_pub_len != publen || client_pub[0] != 0x04) return -1;

    const br_ec_impl *impl = &br_ec_prime_i31;

    /* Server ephemeral private scalar: in-range (< subgroup order).
     * br_ec_keygen produces a valid in-range scalar from the PRNG; the test hook
     * supplies the oracle's fixed (in-range) scalar instead. */
    if (tls13_test_scalar_hook &&
        tls13_test_scalar_hook(group, s->srv_eph_priv, privlen) == (int)privlen) {
        s->srv_eph_priv_len = (uint16_t)privlen;
    } else {
        br_hmac_drbg_context rng;
        uint8_t seed[32];
        tls_rng_fill(seed, sizeof seed);
        br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof seed);
        br_ec_private_key sk;
        uint8_t kbuf[48];
        size_t klen = br_ec_keygen(&rng.vtable, impl, &sk, kbuf, curve);
        if (klen == 0 || klen > privlen) return -1;
        /* keygen may emit fewer bytes than privlen (leading zero); right-align
         * into the fixed-width scalar buffer so mulgen/mul see the full width. */
        memset(s->srv_eph_priv, 0, privlen);
        memcpy(s->srv_eph_priv + (privlen - klen), kbuf, klen);
        s->srv_eph_priv_len = (uint16_t)privlen;
    }

    /* Server public point = scalar * G (uncompressed 0x04||X||Y). */
    size_t pn = impl->mulgen(s->srv_eph_pub, s->srv_eph_priv, privlen, curve);
    if (pn != publen) return -1;
    s->srv_eph_pub_len = (uint16_t)publen;

    /* Shared point = scalar * client_pub, in place; secret = X-coordinate. */
    uint8_t pt[97];
    memcpy(pt, client_pub, publen);
    uint32_t ecok = impl->mul(pt, publen, s->srv_eph_priv, privlen, curve);

    size_t xlen = 0;
    size_t xoff = impl->xoff(curve, &xlen);
    if (xlen == 0 || xoff + xlen > publen || xlen > sizeof s->ecdhe_shared)
        return -1;

    uint8_t zz = 0; for (size_t i = 0; i < xlen; i++) zz |= pt[xoff + i];
    if (!ecok || zz == 0) return -1;  /* all-zero K guard */

    memcpy(s->ecdhe_shared, pt + xoff, xlen);
    s->ecdhe_shared_len = (uint16_t)xlen;
    s->selected_group = group;
    return 0;
}

/* Test-only thin accessor for the static derive_ecdhe (oracle-gated host test
 * test_ecdhe.c). Not declared in tls13.h; the test declares it extern. Unused in
 * production (no caller), and the static derive_ecdhe path is unchanged. */
int tls13_derive_ecdhe_for_test(tls13_sess_t *s, uint16_t group,
                                const uint8_t *client_pub, uint16_t client_pub_len)
{
    return derive_ecdhe(s, group, client_pub, client_pub_len);
}

/* ── ε2 task 6: group selection ─────────────────────────────────────────────
 * Choose the ECDHE group to USE from a parsed ClientHello, HONORING the share
 * the client actually sent so a single round-trip completes (no gratuitous HRR).
 * Returns the selected group id when the client sent a usable key_share for one
 * of the curves we serve, or 0 when it sent no usable share (→ HRR fallback).
 *
 * Documented preference order X25519 > P-256 > P-384: when the client offered
 * shares for several served curves at once we take the first in this order. This
 * is both the server's preference and a stable, deterministic tie-break — the
 * common single-share ClientHello is honored as-sent regardless. */
static uint16_t select_group(const tls13_clienthello_t *ch)
{
    /* RFC 8446 §4.2.8: a KeyShareEntry's group MUST be in supported_groups. A
     * usable share requires BOTH the share AND the group listed — else a
     * malformed CH (key_share for a group it didn't list) could bypass the HRR
     * fallback. Require has_*_share && *_in_groups for each. */
    if (ch->has_x25519_share && ch->x25519_in_groups) return TLS13_GROUP_X25519;
    if (ch->has_p256_share   && ch->p256_in_groups)   return TLS13_GROUP_SECP256R1;
    if (ch->has_p384_share   && ch->p384_in_groups)   return TLS13_GROUP_SECP384R1;
    return 0;   /* no usable (shared AND listed) group → caller decides HRR vs reject */
}

/* ── ε4 A5: cipher-suite selection — CLIENT order ───────────────────────────
 * Honor the CLIENT's offered cipher order (RFC 8446 §4.1.1 leaves the choice to
 * the server, but default nginx with `ssl_prefer_server_ciphers off` — and the
 * OpenSSL stack it defers to — serve the client's FIRST-offered suite). This is
 * the deception target and is consistent with the shipped 1.2 JA3S reference
 * (also default nginx).  ε3 shipped server-preference (0x1302>0x1303>0x1301), a
 * fingerprint divergence corrected here.  first_served_suite is the first served
 * suite in client wire order (0 if none); returns NULL when none was offered. */
static const tls13_suite_t *select_suite(const tls13_clienthello_t *ch)
{
    return tls13_suite_by_id(ch->first_served_suite);
}

int tls13_inbound_feed(tls13_sess_t *s, const uint8_t *in, uint32_t inlen,
                       uint8_t *out, uint32_t outcap, uint32_t *outlen,
                       tls13_app_fn app)
{
    if (!s || !in || !out || !outlen) { if (s) s->st = TLS13_ST_ERR; return -1; }
    *outlen = 0;
    uint32_t opos = 0;
    uint32_t off  = 0;

    /* Iterate every TLS record in the input buffer. */
    while (off + 5 <= inlen) {
        uint8_t  rtype = in[off];
        uint16_t rlen  = tls13_rd16(in + off + 3);
        if ((uint64_t)off + 5 + rlen > inlen) { s->st = TLS13_ST_ERR; return -1; }

        const uint8_t *rec  = in + off;          /* full record (hdr+frag)       */
        const uint8_t *frag = in + off + 5;      /* record fragment              */
        uint32_t       fraglen = rlen;
        uint32_t       reclen  = 5 + rlen;       /* full record length on wire   */
        off += reclen;

        /* change_cipher_spec: middlebox compat — ignore, never transcript. */
        if (rtype == 0x14) continue;

        if (rtype == 0x16) {
            /* Cleartext handshake — the only one we expect is a ClientHello.
             * In ST_START we may see either CH1 (hrr_sent==0) or, after we have
             * emitted a HelloRetryRequest, the retry CH2 (hrr_sent==1). */
            if (s->st != TLS13_ST_START) { s->st = TLS13_ST_ERR; return -1; }

            tls13_clienthello_t ch;
            if (tls13_parse_clienthello(rec, reclen, &ch) < 0) { s->st = TLS13_ST_ERR; return -1; }
            if (!ch.ok) { s->st = TLS13_ST_ERR; return -1; }

            /* ── ε3 A5: cipher-suite selection ────────────────────────────
             * Select the suite BEFORE the HRR branch: the HRR synthetic
             * message_hash length depends on the selected suite's hash. On CH1
             * fix s->suite; on CH2 (post-HRR) §4.1.4 forbids changing it, so
             * reject a CH2 whose selection differs (mirrors the group check). */
            {
                const tls13_suite_t *pick_suite = select_suite(&ch);
                if (pick_suite == NULL) { s->st = TLS13_ST_ERR; return -1; }
                if (!s->hrr_sent) {
                    s->suite = pick_suite;
                } else if (pick_suite != s->suite) {
                    s->st = TLS13_ST_ERR; return -1;   /* §4.1.4: CH2 must keep the suite */
                }
            }

            /* ── ε2 group selection (task 6) ──────────────────────────────
             * HONOR the client's sent share so the handshake completes in one
             * round-trip; only HRR when no usable share was sent. */
            uint16_t pick = select_group(&ch);

            if (pick == 0) {
                /* No usable key_share present. */
                if (s->hrr_sent) {
                    /* We already sent an HRR and the client STILL sent no usable
                     * share → misbehaving client; do not loop. */
                    s->st = TLS13_ST_ERR;
                    return -1;
                }
                /* HRR is only meaningful if the client lists a group we serve in
                 * supported_groups (so the retry can carry a share we can use).
                 * Pick by SERVER preference X25519 > P-256 > P-384. */
                uint16_t hrr_group;
                if      (ch.x25519_in_groups) hrr_group = TLS13_GROUP_X25519;
                else if (ch.p256_in_groups)   hrr_group = TLS13_GROUP_SECP256R1;
                else if (ch.p384_in_groups)   hrr_group = TLS13_GROUP_SECP384R1;
                else { s->st = TLS13_ST_ERR; return -1; }  /* no servable group */

                /* ── HelloRetryRequest (RFC 8446 §4.1.4 + §4.4.1) ──────────
                 * The transcript does NOT start with CH1.  CH1 is replaced by a
                 * synthetic "message_hash" handshake message:
                 *   fe || 00 00 20 || SHA-256(CH1)
                 * (hs_type=254, u24 len=32, body=Hash(CH1)).  Hash covers the
                 * full CH1 handshake message — the record fragment, no header.
                 * Then: synthetic || HelloRetryRequest || (CH2 || SH || ...)
                 * hash is the SELECTED suite's hash (SHA-256 32B for 0x1301/
                 * 0x1303, SHA-384 48B for 0x1302) — set on CH1 above. */
                size_t hlen = s->suite->hash_len;     /* 32 | 48 */
                uint8_t h1[48];
                tls13_transcript_hash(s->suite, frag, fraglen, h1);

                s->th_len = 0;
                uint8_t synth[4 + 48];
                synth[0] = 0xfe;            /* message_hash type            */
                synth[1] = 0x00; synth[2] = 0x00;
                synth[3] = (uint8_t)hlen;  /* len = hash_len (0x20 | 0x30)  */
                memcpy(synth + 4, h1, hlen);
                if (th_append(s, synth, 4 + hlen) < 0) { s->st = TLS13_ST_ERR; return -1; }

                /* Remember the session_id to echo in HRR (and later SH). */
                s->legacy_session_id_len = ch.session_id_len;
                if (ch.session_id_len)
                    memcpy(s->legacy_session_id, ch.session_id, ch.session_id_len);

                /* Build HRR for the chosen servable group, append to transcript,
                 * emit as a CLEARTEXT record. */
                uint8_t hrrmsg[128];
                size_t  hrrn = tls13_make_hrr(hrrmsg, sizeof hrrmsg,
                                              s->suite->id, hrr_group,
                                              s->legacy_session_id,
                                              s->legacy_session_id_len);
                if (hrrn == 0) { s->st = TLS13_ST_ERR; return -1; }
                if (th_append(s, hrrmsg, hrrn) < 0) { s->st = TLS13_ST_ERR; return -1; }
                if (emit_cleartext_hs(out, outcap, &opos, hrrmsg, hrrn) < 0) { s->st = TLS13_ST_ERR; return -1; }

                /* change_cipher_spec (cleartext, never transcript). */
                if ((uint64_t)opos + 6 > outcap) { s->st = TLS13_ST_ERR; return -1; }
                { static const uint8_t ccs[6] = {0x14,0x03,0x03,0x00,0x01,0x01};
                  memcpy(out + opos, ccs, 6); opos += 6; }

                s->hrr_sent  = 1;
                s->hrr_group = hrr_group;   /* CH2 must key_share THIS group (§4.1.4) */
                /* Stay in ST_START awaiting CH2 (hrr_sent disambiguates). */
                continue;
            }

            /* Client sent a usable share for `pick` — happy-path CH1 or retry CH2. */
            if (!s->hrr_sent) {
                /* Happy path: transcript starts with CH1. */
                if (th_append(s, frag, fraglen) < 0) { s->st = TLS13_ST_ERR; return -1; }
                s->legacy_session_id_len = ch.session_id_len;
                if (ch.session_id_len)
                    memcpy(s->legacy_session_id, ch.session_id, ch.session_id_len);
            } else {
                /* HRR path: RFC 8446 §4.1.4 — CH2 MUST carry a key_share for the
                 * exact group HRR asked for. Reject a CH2 that switched groups
                 * (a compliant client never does this; rejecting keeps the
                 * transcript/secret coherent instead of failing opaquely later). */
                if (pick != s->hrr_group) { s->st = TLS13_ST_ERR; return -1; }
                /* th_buf already holds synthetic||HRR; append CH2.
                 * Do NOT reset, do NOT re-derive the session_id (HRR echoed it). */
                if (th_append(s, frag, fraglen) < 0) { s->st = TLS13_ST_ERR; return -1; }
            }

            /* Server ephemeral + ECDHE shared for the selected group from this
             * CH's share. derive_ecdhe sets s->selected_group + the _len fields
             * FRESH each call (no stale leak across an HRR retry). */
            {
                const uint8_t *cpub;
                uint16_t       cpub_len;
                if (pick == TLS13_GROUP_X25519)        { cpub = ch.client_x25519; cpub_len = 32; }
                else if (pick == TLS13_GROUP_SECP256R1){ cpub = ch.client_p256;   cpub_len = 65; }
                else                                   { cpub = ch.client_p384;   cpub_len = 97; }
                if (derive_ecdhe(s, pick, cpub, cpub_len) < 0) { s->st = TLS13_ST_ERR; return -1; }
            }

            /* Build + emit the full server flight (SH..server Finished). */
            if (build_server_flight(s, out, outcap, &opos) < 0) { s->st = TLS13_ST_ERR; return -1; }
            continue;
        }

        if (rtype == 0x17) {
            /* Encrypted record. Choose RX key by epoch, decrypt, dispatch. */
            uint8_t  ptbuf[4096];
            size_t   ptlen = 0;
            uint8_t  inner = 0;
            const uint8_t *rxk, *rxiv;
            if (s->st == TLS13_ST_WAIT_FINISHED) { rxk = s->c_hs_key; rxiv = s->c_hs_iv; }
            else if (s->st == TLS13_ST_APP)      { rxk = s->c_ap_key; rxiv = s->c_ap_iv; }
            else { s->st = TLS13_ST_ERR; return -1; }

            if (tls13_record_open(s->suite, rxk, rxiv, s->seq_rx, rec, reclen,
                                  ptbuf, sizeof ptbuf, &ptlen, &inner) < 0) {
                s->st = TLS13_ST_ERR; return -1;
            }
            s->seq_rx++;

            if (s->st == TLS13_ST_WAIT_FINISHED) {
                /* Expect client Finished: inner 0x16, msg = 14 00 00 <hlen> ||
                 * hlen-byte verify_data, where hlen is the suite hash length
                 * (32 SHA-256 for 0x1301/0x1303, 48 SHA-384 for 0x1302). */
                const br_hash_class *vt   = (const br_hash_class *)s->suite->hash_vtable;
                size_t               hlen = s->suite->finished_len;   /* == hash_len */
                if (inner != 0x16) { s->st = TLS13_ST_ERR; return -1; }
                if (ptlen != 4 + hlen || ptbuf[0] != 0x14) { s->st = TLS13_ST_ERR; return -1; }
                if (tls13_rd24(ptbuf + 1) != hlen) { s->st = TLS13_ST_ERR; return -1; }

                /* verify_data = HMAC-H(c_finished_key, th(CH..server Finished)).
                 * client Finished not yet appended → s->th_buf is exactly CH..sFin. */
                uint8_t th_full[48], expect[48];
                tls13_transcript_hash(s->suite, s->th_buf, s->th_len, th_full);
                br_hmac_key_context kc; br_hmac_context hc;
                br_hmac_key_init(&kc, vt, s->c_finished_key, hlen);
                br_hmac_init(&hc, &kc, hlen);
                br_hmac_update(&hc, th_full, hlen);
                br_hmac_out(&hc, expect);
                /* constant-time compare over the suite's hlen bytes */
                uint8_t diff = 0; for (size_t i = 0; i < hlen; i++) diff |= expect[i] ^ ptbuf[4 + i];
                if (diff != 0) { s->st = TLS13_ST_ERR; return -1; }

                /* Client Finished verified → switch to client app epoch. */
                s->rx_app = 1;
                s->seq_rx = 0;
                s->st     = TLS13_ST_APP;
                continue;
            }

            /* ST_APP: app-data (inner 0x17). Hand to app(), seal the reply. */
            if (inner == 0x15) continue;          /* alert: ignore for ε1      */
            if (inner != 0x17) { s->st = TLS13_ST_ERR; return -1; }
            if (!app) continue;                   /* no responder configured   */

            uint8_t reply[4096];
            uint32_t rn = app(ptbuf, (uint32_t)ptlen, reply, sizeof reply);
            if (rn == 0) continue;                /* nothing to send back      */

            /* First server app record resets seq_tx to 0 (epoch switch). */
            if (!s->tx_app) { s->seq_tx = 0; s->tx_app = 1; }

            if (opos > outcap) { s->st = TLS13_ST_ERR; return -1; }
            size_t sn = tls13_record_seal(s->suite, s->s_ap_key, s->s_ap_iv, s->seq_tx++,
                                          0x17, reply, rn,
                                          out + opos, outcap - opos);
            if (sn == 0) { s->st = TLS13_ST_ERR; return -1; }
            opos += (uint32_t)sn;
            continue;
        }

        /* Unknown record type. */
        s->st = TLS13_ST_ERR;
        return -1;
    }

    *outlen = opos;
    return 0;
}
