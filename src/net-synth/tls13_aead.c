/* tls13_aead.c — suite-dispatched TLS 1.3 record seal/open (RFC 8446 §5.2).
 *
 * The framing is AEAD-independent (RFC 5116 / RFC 8446 §5.3): the 12-byte nonce
 * (static_iv XOR (00..00||be64(seq))), the 5-byte AAD (17 03 03 || u16(ct_len)),
 * the inner_plaintext = content || inner_type (ε: zero padding), ct_len =
 * inner_len + 16-byte tag, and the trailing-zero strip on open are all shared.
 *
 * The cipher is selected by suite->aead:
 *   - AES-128-GCM (0x1301) and AES-256-GCM (0x1302) share the BearSSL br_gcm
 *     path; the only difference is the key length fed to br_aes_ct64_ctr_init
 *     (suite->key_len, 16 vs 32 — BearSSL's CTR init takes a variable key len),
 *     which closes the old silent 16-byte key-truncation hole.
 *   - ChaCha20-Poly1305 (0x1303) uses BearSSL's one-call AEAD
 *     br_poly1305_ctmul_run over br_chacha20_ct_run (RFC 7539).  That call does
 *     NOT verify the tag on decrypt — it recomputes one into a caller buffer — so
 *     open() does its own constant-time tag compare (diff |= a^b, never memcmp).
 *
 * suite == NULL defaults to 0x1301 (pre-A5 bridge): identical to the shipped
 * AES-128-GCM-SHA256 behaviour. */
#include <assert.h>
#include <string.h>
#include "tls13_aead.h"
#include "tls13_wire.h"
#include "net-synth/tls13.h"
#include <bearssl_aead.h>
#include <bearssl_block.h>
#include <bearssl_hash.h>

/* Build the 12-byte GCM/AEAD nonce per RFC 8446 §5.3:
 * nonce = static_iv XOR (00..00 || be64(seq))             */
static void mk_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce[12])
{
    uint8_t s[12] = {0};
    for (int i = 0; i < 8; i++)
        s[11 - i] = (uint8_t)(seq >> (8 * i));
    for (int i = 0; i < 12; i++)
        nonce[i] = iv[i] ^ s[i];
}

/* AES-128/256-GCM seal in place: buf holds inner_plaintext of inner_len bytes,
 * gets encrypted, and the 16-byte tag is appended at buf+inner_len.  hdr is the
 * 5-byte AAD.  key_len (16|32) selects AES-128 vs AES-256 — the ONLY difference
 * between the two GCM suites. */
static void gcm_seal(const uint8_t *key, uint8_t key_len, const uint8_t nonce[12],
                     const uint8_t *hdr, uint8_t *buf, size_t inner_len)
{
    br_aes_ct64_ctr_keys bc;
    br_aes_ct64_ctr_init(&bc, key, key_len);

    br_gcm_context gc;
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul64);
    br_gcm_reset(&gc, nonce, 12);
    br_gcm_aad_inject(&gc, hdr, 5);
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 1 /* encrypt */, buf, inner_len);
    br_gcm_get_tag(&gc, buf + inner_len);   /* append 16-byte tag */
}

/* AES-128/256-GCM open in place: pt holds inner_len ciphertext bytes (decrypted
 * in place); tag is the 16-byte tag from the wire.  Returns 1 on tag-valid, 0 on
 * auth failure (constant-time via br_gcm_check_tag). */
static int gcm_open(const uint8_t *key, uint8_t key_len, const uint8_t nonce[12],
                    const uint8_t *hdr, uint8_t *pt, size_t inner_len,
                    const uint8_t *tag)
{
    br_aes_ct64_ctr_keys bc;
    br_aes_ct64_ctr_init(&bc, key, key_len);

    br_gcm_context gc;
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul64);
    br_gcm_reset(&gc, nonce, 12);
    br_gcm_aad_inject(&gc, hdr, 5);          /* AAD = the 5-byte header */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 0 /* decrypt */, pt, inner_len);
    return br_gcm_check_tag(&gc, tag);       /* constant-time */
}

/* ChaCha20-Poly1305 seal in place (RFC 7539): buf holds inner_plaintext of
 * inner_len bytes, encrypted in place, and the 16-byte Poly1305 tag is written
 * at buf+inner_len.  nonce is the 12-byte TLS record nonce (same construction as
 * GCM); hdr is the 5-byte AAD.  key is always 32 bytes. */
static void chacha_seal(const uint8_t *key, const uint8_t nonce[12],
                        const uint8_t *hdr, uint8_t *buf, size_t inner_len)
{
    br_poly1305_ctmul_run(key, nonce, buf, inner_len, hdr, 5,
                          buf + inner_len /* tag */, &br_chacha20_ct_run,
                          1 /* encrypt */);
}

/* ChaCha20-Poly1305 open in place (RFC 7539): pt holds inner_len ciphertext
 * bytes, decrypted in place; tag is the 16-byte tag from the wire.  BearSSL's
 * one-call AEAD does NOT verify the tag — it recomputes one — so we constant-time
 * compare it ourselves.  Returns 1 on tag-valid, 0 on auth failure. */
static int chacha_open(const uint8_t *key, const uint8_t nonce[12],
                       const uint8_t *hdr, uint8_t *pt, size_t inner_len,
                       const uint8_t *tag)
{
    uint8_t computed[16];
    br_poly1305_ctmul_run(key, nonce, pt, inner_len, hdr, 5,
                          computed, &br_chacha20_ct_run, 0 /* decrypt */);

    /* Constant-time tag compare — never memcmp (timing side-channel +
     * early-exit).  Mirrors the Finished CT-compare in tls13.c. */
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; i++)
        diff |= computed[i] ^ tag[i];
    return diff == 0;
}

size_t tls13_record_seal(const tls13_suite_t *suite, const uint8_t *key,
                         const uint8_t iv[12], uint64_t seq,
                         uint8_t inner_type, const uint8_t *pt, size_t pt_len,
                         uint8_t *out, size_t out_cap)
{
    if (!suite) suite = tls13_suite_by_id(0x1301);   /* pre-A5 default */
    assert(key != NULL);

    /* Overflow-safe capacity guard: need at least 5 (header) + pt_len + 1 (inner_type) + 16 (tag) */
    if (out_cap < 22 || pt_len > out_cap - 22) return 0;

    /* inner_plaintext = content || inner_type_byte  (ε: zero padding) */
    size_t inner_len = pt_len + 1;
    size_t ct_len    = inner_len + 16;   /* +16-byte AEAD tag */
    size_t rec_len   = 5 + ct_len;
    if (rec_len > out_cap) return 0;     /* redundant but kept for clarity */

    /* 5-byte TLSCiphertext header (also the AEAD AAD). */
    uint8_t *hdr = out;
    hdr[0] = 0x17; hdr[1] = 0x03; hdr[2] = 0x03;
    tls13_wr16(hdr + 3, (uint16_t)ct_len);

    /* Copy plaintext into output buffer then append inner_type byte. */
    uint8_t *buf = out + 5;
    memcpy(buf, pt, pt_len);
    buf[pt_len] = inner_type;

    uint8_t nonce[12];
    mk_nonce(iv, seq, nonce);

    switch (suite->aead) {
    case TLS13_AEAD_AES_128_GCM:
    case TLS13_AEAD_AES_256_GCM:
        gcm_seal(key, suite->key_len, nonce, hdr, buf, inner_len);
        break;
    case TLS13_AEAD_CHACHA20_POLY1305:
        chacha_seal(key, nonce, hdr, buf, inner_len);
        break;
    default:
        return 0;
    }

    return rec_len;
}

int tls13_record_open(const tls13_suite_t *suite, const uint8_t *key,
                      const uint8_t iv[12], uint64_t seq,
                      const uint8_t *rec, size_t rec_len,
                      uint8_t *pt, size_t pt_cap, size_t *pt_len, uint8_t *inner_type)
{
    if (!suite) suite = tls13_suite_by_id(0x1301);   /* pre-A5 default */
    assert(key != NULL);

    /* Minimum: 5-byte header + 16-byte tag */
    if (rec_len < 5 + 16) return -1;

    /* Validate header fields and ciphertext length */
    if (rec[0] != 0x17 || rec[1] != 0x03 || rec[2] != 0x03) return -1;
    size_t ct_len    = tls13_rd16(rec + 3);
    if (5 + ct_len != rec_len) return -1;
    if (ct_len < 16) return -1;
    size_t inner_len = ct_len - 16;
    if (inner_len > pt_cap) return -1;

    /* Copy ciphertext into output buffer (we decrypt in place) */
    memcpy(pt, rec + 5, inner_len);

    uint8_t nonce[12];
    mk_nonce(iv, seq, nonce);

    int tag_ok;
    switch (suite->aead) {
    case TLS13_AEAD_AES_128_GCM:
    case TLS13_AEAD_AES_256_GCM:
        tag_ok = gcm_open(key, suite->key_len, nonce, rec /* AAD=hdr */,
                          pt, inner_len, rec + 5 + inner_len);
        break;
    case TLS13_AEAD_CHACHA20_POLY1305:
        tag_ok = chacha_open(key, nonce, rec /* AAD=hdr */,
                             pt, inner_len, rec + 5 + inner_len);
        break;
    default:
        memset(pt, 0, inner_len);
        return -1;
    }

    if (!tag_ok) { memset(pt, 0, inner_len); return -1; }

    /* Strip trailing zero padding; last non-zero byte is the content type */
    size_t n = inner_len;
    while (n > 0 && pt[n - 1] == 0) n--;
    if (n == 0) return -1;   /* no content type byte found */

    *inner_type = pt[n - 1];
    *pt_len     = n - 1;
    return 0;
}
