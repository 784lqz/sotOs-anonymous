/* tls13_sign.c — TLS 1.3 server CertificateVerify signing (ε1 + ε3).
 *
 * RFC 8446 §4.4.3: with an RSA cert the CertificateVerify is signed with an
 * RSA-PSS scheme.  ε1/ε3-0x1301/0x1303 use rsa_pss_rsae_sha256 (sig alg 0x0804);
 * ε3-0x1302 (AES-256-GCM-SHA384) uses rsa_pss_rsae_sha384 (sig alg 0x0805).
 * BearSSL has no PSS sign, so we hand-roll EMSA-PSS-ENCODE + MGF1 (RFC 8017
 * §9.1.1) over the transcript hash, then call the raw RSA private op
 * (br_rsa_i31_private).
 *
 * THE THREE HASHES (landmine #3): for 0x1302 the transcript hash fed in is
 * SHA-384 (caller's responsibility — sourced from the suite), while the PSS
 * inner hash (mHash/H), MGF1 hash, and salt length are all sourced from the
 * SIGNATURE ALGORITHM (0x0805 → SHA-384).  They coincide for our table but are
 * conceptually distinct: this file picks every PSS parameter off `sigalg`, never
 * off a suite field.
 *
 * Verified against an INDEPENDENT verifier (Python cryptography PSS) — see
 * src/test/tls13_host/verify_sign.py.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <bearssl.h>
#include <net-synth/tls_cert.h>
#include "tls13_sign.h"

/* RSA-2048: modBits=2048, emBits=modBits-1=2047, emLen=ceil(2047/8)=256. */
#define EMLEN  256         /* ceil(2047/8) */
#define MAX_HLEN 48        /* SHA-384 output (>= SHA-256) */
#define MAX_TH   48        /* SHA-384 transcript hash (>= SHA-256) */

/* MGF1 (RFC 8017 §B.2.1) parameterised by an arbitrary BearSSL hash vtable.
 * hlen is the hash output length in bytes (the digest size of `vt`). */
static void mgf1(const uint8_t *seed, size_t seed_len,
                 uint8_t *mask, size_t mask_len,
                 const br_hash_class *vt, size_t hlen)
{
    uint32_t counter = 0;
    size_t off = 0;
    while (off < mask_len) {
        br_hash_compat_context c;
        uint8_t cnt[4];
        uint8_t digest[MAX_HLEN];
        cnt[0] = (uint8_t)(counter >> 24);
        cnt[1] = (uint8_t)(counter >> 16);
        cnt[2] = (uint8_t)(counter >> 8);
        cnt[3] = (uint8_t)(counter);
        vt->init(&c.vtable);
        vt->update(&c.vtable, seed, seed_len);
        vt->update(&c.vtable, cnt, 4);
        vt->out(&c.vtable, digest);

        size_t n = mask_len - off;
        if (n > hlen) n = hlen;
        memcpy(mask + off, digest, n);
        off += n;
        counter++;
    }
}

/* Sign the CertificateVerify content for transcript hash th[th_len], using the
 * PSS parameters dictated by `sigalg` (0x0804 → SHA-256/sLen=32, 0x0805 →
 * SHA-384/sLen=48).  th_len must match the sigalg's hash (32 or 48). */
size_t tls13_sign_certverify(uint16_t sigalg,
                             const uint8_t *th, size_t th_len,
                             uint8_t *sig, size_t sig_cap,
                             void (*rng_fill)(uint8_t*, size_t))
{
    if (sig == NULL || sig_cap < EMLEN || rng_fill == NULL || th == NULL)
        return 0;

    /* --- 0. Pick PSS parameters from the SIGNATURE ALGORITHM (landmine #3). --- */
    const br_hash_class *vt;
    size_t hlen;   /* PSS inner-hash output length (== SLEN here) */
    switch (sigalg) {
        case 0x0804: vt = &br_sha256_vtable; hlen = 32; break;
        case 0x0805: vt = &br_sha384_vtable; hlen = 48; break;
        default: return 0;
    }
    const size_t slen = hlen;            /* salt length == hash length */
    /* The trailing transcript hash MUST be the sigalg's hash size. */
    if (th_len != hlen) return 0;

    /* --- 1. Build the signed content (RFC 8446 §4.4.3). --- */
    /* 64 * 0x20 || "TLS 1.3, server CertificateVerify" (33B) || 0x00 || th[th_len] */
    static const char LABEL[] = "TLS 1.3, server CertificateVerify"; /* 33, no NUL */
    uint8_t content[64 + 33 + 1 + MAX_TH];
    const size_t content_len = 64 + 33 + 1 + th_len;   /* 130 (SHA-256) | 146 (SHA-384) */
    memset(content, 0x20, 64);
    memcpy(content + 64, LABEL, 33);
    content[64 + 33] = 0x00;
    memcpy(content + 64 + 33 + 1, th, th_len);

    /* --- 2. EMSA-PSS-ENCODE (RFC 8017 §9.1.1). --- */
    /* mHash = Hash(content) */
    uint8_t mHash[MAX_HLEN];
    {
        br_hash_compat_context c;
        vt->init(&c.vtable);
        vt->update(&c.vtable, content, content_len);
        vt->out(&c.vtable, mHash);
    }

    /* salt = slen random bytes */
    uint8_t salt[MAX_HLEN];
    rng_fill(salt, slen);

    /* M' = (0x00 * 8) || mHash || salt ; H = Hash(M') */
    uint8_t H[MAX_HLEN];
    {
        br_hash_compat_context c;
        uint8_t zeros8[8] = {0};
        vt->init(&c.vtable);
        vt->update(&c.vtable, zeros8, 8);
        vt->update(&c.vtable, mHash, hlen);
        vt->update(&c.vtable, salt, slen);
        vt->out(&c.vtable, H);
    }

    /* DB = PS(0x00 ...) || 0x01 || salt  (length = emLen-hLen-1) */
    const size_t db_len = EMLEN - hlen - 1;            /* 223 | 207 */
    const size_t ps_len = EMLEN - slen - hlen - 2;     /* 190 | 158 */
    uint8_t EM[EMLEN];
    uint8_t *DB = EM;                                  /* build maskedDB in place */
    memset(DB, 0x00, ps_len);
    DB[ps_len] = 0x01;
    memcpy(DB + ps_len + 1, salt, slen);

    /* dbMask = MGF1(H, db_len); maskedDB = DB XOR dbMask */
    uint8_t dbMask[EMLEN]; /* >= db_len */
    mgf1(H, hlen, dbMask, db_len, vt, hlen);
    for (size_t i = 0; i < db_len; i++)
        DB[i] ^= dbMask[i];

    /* clear the leftmost 8*emLen-emBits = 1 bit of maskedDB[0] (emBits=2047) */
    DB[0] &= 0x7F;

    /* EM = maskedDB || H || 0xbc */
    memcpy(EM + db_len, H, hlen);
    EM[EMLEN - 1] = 0xbc;

    /* --- 3. Raw RSA private op (in place): EM -> signature. --- */
    if (br_rsa_i31_private(EM, &SERVER_KEY) != 1)
        return 0;

    memcpy(sig, EM, EMLEN);
    return EMLEN;
}
