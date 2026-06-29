/* sotOs · net-synth · SSH-2.0 transport — arc-ζ1 cleartext KEX.
 *
 * Replaces the banner-only :22 response_profile with a REAL SSH key exchange:
 * version exchange + concrete KEXINIT + curve25519-sha256 ECDH + an
 * rsa-sha2-256 host-key signature over the exchange hash + KEX_ECDH_REPLY +
 * NEWKEYS, built on BearSSL primitives (X25519, SHA-256, RSA PKCS#1 sign).
 * The host key reuses the honeypot's existing RSA-2048 credential. ζ2 will add
 * the AES-CTR/HMAC encrypted layer + userauth. NOT a security boundary — a
 * deception responder; entropy is honeypot-grade (rdtsc).
 *
 * Implements ssh_respond() (declared in inbound_ssh.h) — the :22 dispatch ABI
 * called from main.c; this TU supersedes inbound_ssh.c. */
#include <net-synth/inbound_ssh.h>
#include <net-synth/ssh_transport.h>
#include <net-synth/ssh_wire.h>
#include <net-synth/tls_cert.h>   /* SERVER_KEY (RSA), TA0_RSA_N, TA0_RSA_E */
#include "tls_rng.h"                /* tls_rng_fill (local header in src/net-synth/) */
#include "sntrup761/crypto_api.h"   /* SSH HASSH arc · sntrup761x25519-sha512 hybrid KEX */
#include "poly1305/poly1305.h"      /* chacha20-poly1305@openssh.com raw Poly1305 MAC */
#include <bearssl.h>
#include <string.h>
#include <stdio.h>
#include <sotnet/bytepipe.h>   /* Phase B · SHELL_IN/OUT rings */
#include <sotnet/bytepipe_frame.h> /* Task B2 · SHELL_WINCH control frame on in_p2c */
#include <lucas/tty_session.h>     /* Task B2 · pure pty-req/window-change winsize decoders */

#define SSH_SESS_MAX 8
static ssh_conn_t g_ssh[SSH_SESS_MAX];

/* Phase B · 1 if root mapped the shell rings (set from main.c).  When 0 the
 * CHANNEL_DATA handler keeps the Phase A echo (R7 · graceful fallback). */
static int g_ssh_shell_rings_ready = 0;
void ssh_shell_rings_set_ready(int ready) { g_ssh_shell_rings_ready = ready ? 1 : 0; }

/* Phase B · R2 · 1 while a busybox shell is live (set by main.c when it pushes
 * SHELL_START, cleared on SHELL_EOF/CLOSE).  A 2nd concurrent shell-request is
 * refused with CHANNEL_FAILURE — one attacker shell at a time for v1. */
static int g_ssh_shell_busy = 0;
void ssh_shell_set_busy(int busy) { g_ssh_shell_busy = busy ? 1 : 0; }

static const char SSH_ID[]   = "SSH-2.0-OpenSSH_9.7\r\n";  /* sent on the wire (with CRLF) · Alpine 3.20 ships openssh 9.7p1 */
static const char SSH_VS[]   = "SSH-2.0-OpenSSH_9.7";       /* V_S for H (CRLF stripped, 19B) */

static void ssh_slot_init(ssh_conn_t *c, uint16_t conn_id) {
    memset(c, 0, sizeof *c);
    c->used = 1; c->conn_id = conn_id; c->phase = SSH_PHASE_FRESH;
}

/* Find-or-allocate the slot for conn_id. `fresh_connect` (the len==0 ESTABLISHED
 * greet) means a NEW TCP connection — reset any stale slot for this conn_id so a
 * reused conn_id (the 16-bit counter wraps) starts clean and re-greets. With no
 * CONN_CLOSE hook in ζ1, slot reclamation relies on (a) fresh-reset on reuse and
 * (b) evicting a TERMINAL slot (aborted or completed KEX) before any in-flight
 * one when the pool is full — so a flood of malformed handshakes cannot wedge an
 * active session (a CONN_CLOSE-driven free is a ζ2 follow-up). */
static ssh_conn_t *ssh_slot(uint16_t conn_id, int fresh_connect) {
    for (int i = 0; i < SSH_SESS_MAX; ++i)
        if (g_ssh[i].used && g_ssh[i].conn_id == conn_id) {
            if (fresh_connect) ssh_slot_init(&g_ssh[i], conn_id);
            return &g_ssh[i];
        }
    for (int i = 0; i < SSH_SESS_MAX; ++i)
        if (!g_ssh[i].used) { ssh_slot_init(&g_ssh[i], conn_id); return &g_ssh[i]; }
    /* pool full → evict a terminal slot (aborted/KEXED) before an in-flight one */
    for (int i = 0; i < SSH_SESS_MAX; ++i)
        if (g_ssh[i].aborted || g_ssh[i].phase == SSH_PHASE_KEXED) {
            ssh_slot_init(&g_ssh[i], conn_id); return &g_ssh[i];
        }
    /* all 8 in-flight (rare) → sacrifice a pre-KEX (IDSENT) slot before an
     * active authenticated one; only clobber slot 0 as an absolute last resort. */
    for (int i = 0; i < SSH_SESS_MAX; ++i)
        if (g_ssh[i].phase == SSH_PHASE_IDSENT) { ssh_slot_init(&g_ssh[i], conn_id); return &g_ssh[i]; }
    ssh_slot_init(&g_ssh[0], conn_id);
    return &g_ssh[0];
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Bounded SSH-wire readers over pl[0..pllen). Each advances *off and returns 0,
 * or -1 if the field would read past pllen (wrap-safe). */
static int ssh_rd_u32(const uint8_t *pl, uint32_t pllen, uint32_t *off, uint32_t *v) {
    uint32_t o = *off;
    if (o > pllen || pllen - o < 4) return -1;       /* o<=pllen first, so pllen-o can't wrap */
    *v = be32(pl + o); *off = o + 4; return 0;
}
static int ssh_rd_byte(const uint8_t *pl, uint32_t pllen, uint32_t *off, uint8_t *v) {
    uint32_t o = *off;
    if (o >= pllen) return -1;
    *v = pl[o]; *off = o + 1; return 0;
}
/* string = u32 len + len bytes. Sets *ptr/*len, advances *off past the body. */
static int ssh_rd_str(const uint8_t *pl, uint32_t pllen, uint32_t *off,
                      const uint8_t **ptr, uint32_t *len) {
    uint32_t o = *off, n;
    if (ssh_rd_u32(pl, pllen, &o, &n) != 0) return -1;
    if (n > pllen - o) return -1;                    /* o<=pllen (rd_u32 advanced ≤pllen) → no wrap */
    *ptr = pl + o; *len = n; *off = o + n; return 0;
}

/* chacha20-poly1305@openssh.com (PROTOCOL.chacha20poly1305).  Two ChaCha20 keys
 * K_2(payload, 0..32) and K_1(length, 32..64).  The original-ChaCha nonce = the
 * 64-bit packet seqnum; mapped onto BearSSL's IETF chacha (12B iv + 32b counter)
 * as iv = 8 zero bytes || seqnr_be(4), cc = block counter (0 = poly key + length,
 * 1 = payload). */
static void cc20_iv(uint32_t seqnr, uint8_t iv[12]) {
    memset(iv, 0, 8);
    iv[8]  = (uint8_t)(seqnr >> 24); iv[9]  = (uint8_t)(seqnr >> 16);
    iv[10] = (uint8_t)(seqnr >> 8);  iv[11] = (uint8_t)seqnr;
}
/* Seal one packet: out = enc_len(4) || enc(padlen||payload||padding) || tag(16).
 * Returns total bytes, or 0 on overflow. */
static uint32_t cc20_seal(const uint8_t *K, uint32_t seqnr, uint8_t *out, uint32_t outmax,
                          const uint8_t *payload, uint32_t plen) {
    const uint8_t *K2 = K, *K1 = K + 32;
    uint32_t pad = (8u - ((plen + 1u) % 8u)) % 8u; if (pad < 4) pad += 8;
    uint32_t pktlen = 1u + plen + pad;
    if (4u + pktlen + 16u > outmax) return 0;
    out[0]=(uint8_t)(pktlen>>24); out[1]=(uint8_t)(pktlen>>16); out[2]=(uint8_t)(pktlen>>8); out[3]=(uint8_t)pktlen;
    out[4]=(uint8_t)pad;
    if (plen) memcpy(out + 5, payload, plen);
    tls_rng_fill(out + 5 + plen, pad);
    uint8_t iv[12]; cc20_iv(seqnr, iv);
    uint8_t poly_key[32]; memset(poly_key, 0, 32);
    (void)br_chacha20_ct_run(K2, iv, 0, poly_key, 32);     /* block 0 → Poly1305 key */
    (void)br_chacha20_ct_run(K1, iv, 0, out, 4);           /* encrypt length */
    (void)br_chacha20_ct_run(K2, iv, 1, out + 4, pktlen);  /* encrypt payload from block 1 */
    poly1305_auth(out + 4 + pktlen, out, 4 + pktlen, poly_key);  /* tag over enc_len || enc_payload */
    return 4u + pktlen + 16u;
}
/* Open one packet from `in`(avail).  Returns consumed bytes (>0, payload in
 * `pl`/*pllen), 0 if more bytes are needed, or -1 on a bad length / auth fail. */
static int64_t cc20_open(const uint8_t *K, uint32_t seqnr, const uint8_t *in, uint32_t avail,
                         uint8_t *pl, uint32_t plmax, uint32_t *pllen) {
    if (avail < 4) return 0;
    const uint8_t *K2 = K, *K1 = K + 32;
    uint8_t iv[12]; cc20_iv(seqnr, iv);
    uint8_t lenbuf[4]; memcpy(lenbuf, in, 4);
    (void)br_chacha20_ct_run(K1, iv, 0, lenbuf, 4);
    uint32_t pktlen = be32(lenbuf);
    if (pktlen < 2 || pktlen > plmax + 64) return -1;
    uint32_t total = 4u + pktlen + 16u;
    if (avail < total) return 0;
    uint8_t poly_key[32]; memset(poly_key, 0, 32);
    (void)br_chacha20_ct_run(K2, iv, 0, poly_key, 32);
    uint8_t tag[16]; poly1305_auth(tag, in, 4 + pktlen, poly_key);
    uint8_t diff = 0; for (int i = 0; i < 16; ++i) diff |= tag[i] ^ in[4 + pktlen + i];
    if (diff) return -1;                                   /* auth failure */
    static uint8_t dec[2560];
    if (pktlen > sizeof dec) return -1;
    memcpy(dec, in + 4, pktlen);
    (void)br_chacha20_ct_run(K2, iv, 1, dec, pktlen);
    uint8_t padlen = dec[0];
    if ((uint32_t)padlen + 1u > pktlen) return -1;
    uint32_t p = pktlen - padlen - 1u;
    if (p > plmax) return -1;
    memcpy(pl, dec + 1, p); *pllen = p;
    return (int64_t)total;
}

/* aes{128,256}-gcm@openssh.com (RFC 5647).  The 4-byte packet_length is sent in
 * the clear and is the GCM AAD; padding_length || payload || padding is the
 * encrypted region (a multiple of 16); the 16-byte GCM tag follows.  The 12-byte
 * IV is the KDF output with its low 8 bytes treated as a BE64 invocation counter,
 * incremented by one after every packet (independent of the SSH seqnum). */
static void gcm_iv_incr(uint8_t iv[12]) {
    for (int i = 11; i >= 4; --i) { if (++iv[i] != 0) break; }
}
/* Seal: out = pktlen(4·clear) || enc(padlen||payload||padding) || tag(16). 0 on overflow. */
static uint32_t gcm_seal(br_gcm_context *g, uint8_t iv[12], uint8_t *out, uint32_t outmax,
                         const uint8_t *payload, uint32_t plen) {
    uint32_t pad = (16u - ((plen + 1u) % 16u)) % 16u; if (pad < 4) pad += 16;
    uint32_t pktlen = 1u + plen + pad;                 /* encrypted region · multiple of 16 */
    if (4u + pktlen + 16u > outmax) return 0;
    out[0]=(uint8_t)(pktlen>>24); out[1]=(uint8_t)(pktlen>>16); out[2]=(uint8_t)(pktlen>>8); out[3]=(uint8_t)pktlen;
    out[4]=(uint8_t)pad;
    if (plen) memcpy(out + 5, payload, plen);
    tls_rng_fill(out + 5 + plen, pad);
    br_gcm_reset(g, iv, 12);
    br_gcm_aad_inject(g, out, 4);                      /* AAD = cleartext packet_length */
    br_gcm_flip(g);
    br_gcm_run(g, 1, out + 4, pktlen);                 /* encrypt in place */
    br_gcm_get_tag(g, out + 4 + pktlen);
    gcm_iv_incr(iv);
    return 4u + pktlen + 16u;
}
/* Open one packet from in(avail).  >0 = consumed (payload in pl/*pllen), 0 = need
 * more bytes, -1 = bad length / GCM tag mismatch. */
static int64_t gcm_open(br_gcm_context *g, uint8_t iv[12], const uint8_t *in, uint32_t avail,
                        uint8_t *pl, uint32_t plmax, uint32_t *pllen) {
    if (avail < 4) return 0;
    uint32_t pktlen = be32(in);
    if ((pktlen & 15u) || pktlen < 16 || pktlen > plmax + 64) return -1;
    uint32_t total = 4u + pktlen + 16u;
    if (avail < total) return 0;
    static uint8_t dec[2560];
    if (pktlen > sizeof dec) return -1;
    memcpy(dec, in + 4, pktlen);
    br_gcm_reset(g, iv, 12);
    br_gcm_aad_inject(g, in, 4);
    br_gcm_flip(g);
    br_gcm_run(g, 0, dec, pktlen);                     /* decrypt the clone */
    if (!br_gcm_check_tag(g, in + 4 + pktlen)) return -1;   /* GCM auth failure */
    gcm_iv_incr(iv);
    uint8_t padlen = dec[0];
    if ((uint32_t)padlen + 1u > pktlen) return -1;
    uint32_t p = pktlen - padlen - 1u;
    if (p > plmax) return -1;
    memcpy(pl, dec + 1, p); *pllen = p;
    return (int64_t)total;
}

/* Does the comma-separated name-list s[0..sl) contain the exact token tok? */
static int list_has(const uint8_t *s, uint32_t sl, const char *tok) {
    uint32_t tl = (uint32_t)strlen(tok), i = 0;
    while (i < sl) {
        uint32_t j = i; while (j < sl && s[j] != ',') j++;
        if (j - i == tl && memcmp(s + i, tok, tl) == 0) return 1;
        i = j + 1;
    }
    return 0;
}

/* Parse the client's KEXINIT (c->ic) and decide, BEFORE do_kex's ssh_kdf (the
 * cipher/sig dictate keying + the host-key hash):
 *   - strict_kex  · client offers kex-strict-c-v00@openssh.com (anti-Terrapin)
 *   - sig_sha512  · client prefers rsa-sha2-512 over rsa-sha2-256 (first mutual)
 *   - cipher_chacha · client's first mutual cipher is chacha20-poly1305 (vs aes128-ctr) */
static void negotiate(ssh_conn_t *c) {
    const uint8_t *pl = c->ic; uint32_t pllen = c->ic_len;
    uint32_t off = 17;                                 /* skip msg(1) + cookie(16) */
    const uint8_t *kex, *hk, *enc; uint32_t kl, hl, el;
    if (ssh_rd_str(pl, pllen, &off, &kex, &kl) != 0) return;   /* kex_algorithms  */
    if (ssh_rd_str(pl, pllen, &off, &hk,  &hl) != 0) return;   /* server_host_key */
    if (ssh_rd_str(pl, pllen, &off, &enc, &el) != 0) return;   /* encryption_c2s  */

    c->strict_kex = list_has(kex, kl, "kex-strict-c-v00@openssh.com");

    /* host-key sig: first of the client's list that we offer (rsa-sha2-512/256) */
    for (uint32_t i = 0; i < hl; ) {
        uint32_t j = i; while (j < hl && hk[j] != ',') j++; uint32_t t = j - i;
        if (t == 12 && memcmp(hk + i, "rsa-sha2-512", 12) == 0) { c->sig_sha512 = 1; break; }
        if (t == 12 && memcmp(hk + i, "rsa-sha2-256", 12) == 0) { c->sig_sha512 = 0; break; }
        i = j + 1;
    }
    /* cipher: the client's first enc_c2s that we IMPLEMENT.  We advertise the full
     * OpenSSH 9.7 list (HASSH byte-match), so the true negotiated cipher is the
     * client's first — but only chacha20-poly1305 + aes{128,256}-gcm + aes128-ctr
     * are wired here (real clients prefer an AEAD cipher first; aes192/256-ctr +
     * the umac/etm MAC matrix are advertised-only · exotic-client residual). */
    for (uint32_t i = 0; i < el; ) {
        uint32_t j = i; while (j < el && enc[j] != ',') j++; uint32_t t = j - i;
        const uint8_t *tk = enc + i;
        if (t == 29 && memcmp(tk, "chacha20-poly1305@openssh.com", 29) == 0) { c->cipher_chacha = 1; break; }
        if (t == 22 && memcmp(tk, "aes256-gcm@openssh.com", 22) == 0) { c->cipher_gcm = 1; c->gcm_keylen = 32; break; }
        if (t == 22 && memcmp(tk, "aes128-gcm@openssh.com", 22) == 0) { c->cipher_gcm = 1; c->gcm_keylen = 16; break; }
        if (t == 10 && memcmp(tk, "aes128-ctr", 10) == 0) { c->cipher_chacha = 0; break; }
        i = j + 1;
    }
}

/* Sign the exchange hash H (Hlen bytes) with the negotiated RSA algorithm into
 * the signature blob sb (string algname || string sig).  RSASSA-PKCS1-v1.5 hashes
 * H as a message → the embedded digest is SHA-256(H) or SHA-512(H). */
static uint32_t sign_exchange_hash(ssh_conn_t *c, const uint8_t *H, uint32_t Hlen,
                                   uint8_t *sb, uint32_t sbcap) {
    uint8_t sig[256];
    uint32_t sbo = 0;
    if (c->sig_sha512) {
        uint8_t HH[64];
        br_sha512_context s; br_sha512_init(&s); br_sha512_update(&s, H, Hlen); br_sha512_out(&s, HH);
        if (!br_rsa_i31_pkcs1_sign(BR_HASH_OID_SHA512, HH, 64, &SERVER_KEY, sig)) { c->aborted = 1; return 0; }
        sbo = ssh_put_cstr(sb, sbo, sbcap, "rsa-sha2-512");
    } else {
        uint8_t HH[32];
        br_sha256_context s; br_sha256_init(&s); br_sha256_update(&s, H, Hlen); br_sha256_out(&s, HH);
        if (!br_rsa_i31_pkcs1_sign(BR_HASH_OID_SHA256, HH, 32, &SERVER_KEY, sig)) { c->aborted = 1; return 0; }
        sbo = ssh_put_cstr(sb, sbo, sbcap, "rsa-sha2-256");
    }
    sbo = ssh_put_string(sb, sbo, sbcap, sig, 256);
    return sbo;
}

/* Frame + (post-NEWKEYS) encrypt-and-MAC one binary packet; counts seq_out.
 * Returns bytes written to out, or 0 on overflow (caller aborts). */
static uint32_t ssh_emit(ssh_conn_t *c, uint8_t *out, uint32_t outmax,
                         const uint8_t *payload, uint32_t plen) {
    if (!c->send_enc) {
        uint32_t n = ssh_pkt_frame(out, outmax, payload, plen);  /* cleartext, mult-of-8 */
        if (n) c->seq_out++;
        return n;
    }
    if (c->cipher_gcm) {
        uint32_t n = gcm_seal(&c->gcm_out, c->giv_out, out, outmax, payload, plen);
        if (n) c->seq_out++;
        return n;
    }
    if (c->cipher_chacha) {
        uint32_t n = cc20_seal(c->cc20_s2c, c->seq_out, out, outmax, payload, plen);
        if (n) c->seq_out++;
        return n;
    }
    /* encrypted: pad so the whole 4+packet_length region is a multiple of 16
     * (RFC 4253 §6: 4 length + 1 padlen + payload + padding ≡ 0 mod block). */
    uint32_t pad = (16u - ((plen + 5u) % 16u)) % 16u;
    if (pad < 4) pad += 16;
    uint32_t pktlen = 1u + plen + pad;
    uint32_t total = 4u + pktlen;                 /* multiple of 16 */
    if (total + 32u > outmax) return 0;
    out[0] = (uint8_t)(pktlen >> 24); out[1] = (uint8_t)(pktlen >> 16);
    out[2] = (uint8_t)(pktlen >> 8);  out[3] = (uint8_t)pktlen;
    out[4] = (uint8_t)pad;
    if (plen) memcpy(out + 5, payload, plen);
    tls_rng_fill(out + 5 + plen, pad);            /* random padding */
    /* MAC = HMAC-SHA256(Int_s2c, seq_be32 || cleartext_packet), computed BEFORE encrypt. */
    uint8_t seqb[4] = { (uint8_t)(c->seq_out>>24),(uint8_t)(c->seq_out>>16),
                        (uint8_t)(c->seq_out>>8),(uint8_t)c->seq_out };
    br_hmac_key_context kc; br_hmac_key_init(&kc, &br_sha256_vtable, c->mac_out, 32);
    br_hmac_context hc;     br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, seqb, 4); br_hmac_update(&hc, out, total);
    uint8_t mac[32]; br_hmac_out(&hc, mac);
    /* encrypt packet_length..padding in place, then append the MAC in clear. */
    c->cc_out = br_aes_ct64_ctr_run(&c->cout, c->iv_out, c->cc_out, out, total);
    memcpy(out + total, mac, 32);
    c->seq_out++;
    return total + 32;
}

/* RFC 4253 §7.2 key derivation: key = HASH( K_enc || H || 'X' || session_id ).
 * HASH + the K encoding depend on the negotiated KEX: curve25519-sha256 uses
 * SHA-256 with K = mpint(shared); sntrup761x25519-sha512 uses SHA-512 with K =
 * string(SHA512(kem_key || ecdh_shared)).  Both are prepared into c->k_enc +
 * c->session_id (sid_len) by do_kex / do_kex_hybrid. */
static void ssh_kdf_one(ssh_conn_t *c, char label, uint8_t *out, uint32_t outlen) {
    uint8_t lb = (uint8_t)label;
    uint32_t hlen = c->kex_sha512 ? 64 : 32;
    uint32_t got = 0;
    while (got < outlen) {
        uint8_t d[64];
        if (c->kex_sha512) {
            br_sha512_context sh; br_sha512_init(&sh);
            br_sha512_update(&sh, c->k_enc, c->k_enc_len);
            br_sha512_update(&sh, c->session_id, c->sid_len);          /* H */
            if (got == 0) { br_sha512_update(&sh, &lb, 1); br_sha512_update(&sh, c->session_id, c->sid_len); }
            else br_sha512_update(&sh, out, got);                      /* K1..Kn (RFC 4253 §7.2 extend) */
            br_sha512_out(&sh, d);
        } else {
            br_sha256_context sh; br_sha256_init(&sh);
            br_sha256_update(&sh, c->k_enc, c->k_enc_len);
            br_sha256_update(&sh, c->session_id, c->sid_len);
            if (got == 0) { br_sha256_update(&sh, &lb, 1); br_sha256_update(&sh, c->session_id, c->sid_len); }
            else br_sha256_update(&sh, out, got);
            br_sha256_out(&sh, d);
        }
        uint32_t take = (outlen - got < hlen) ? (outlen - got) : hlen;
        memcpy(out + got, d, take);
        got += take;
    }
}

static void ssh_kdf(ssh_conn_t *c) {
    if (c->cipher_gcm) {
        /* aes-gcm@openssh.com · IV_c2s/IV_s2c (A/B, 12B) + Key_c2s/Key_s2c (C/D,
         * gcm_keylen).  No E/F MAC keys — the 16-byte GCM tag is the integrity. */
        uint8_t kc[32], ks[32];
        ssh_kdf_one(c, 'A', c->giv_in,  12);
        ssh_kdf_one(c, 'B', c->giv_out, 12);
        ssh_kdf_one(c, 'C', kc, c->gcm_keylen);
        ssh_kdf_one(c, 'D', ks, c->gcm_keylen);
        br_aes_ct64_ctr_init(&c->gcm_bc_in,  kc, c->gcm_keylen);
        br_aes_ct64_ctr_init(&c->gcm_bc_out, ks, c->gcm_keylen);
        br_gcm_init(&c->gcm_in,  &c->gcm_bc_in.vtable,  &br_ghash_ctmul);
        br_gcm_init(&c->gcm_out, &c->gcm_bc_out.vtable, &br_ghash_ctmul);
        return;
    }
    if (c->cipher_chacha) {
        /* chacha20-poly1305@openssh.com · 512 bits per direction (K_2 || K_1),
         * its nonce derives from the seqnum so no IV; no separate MAC. */
        ssh_kdf_one(c, 'C', c->cc20_c2s, 64);
        ssh_kdf_one(c, 'D', c->cc20_s2c, 64);
        return;
    }
    uint8_t iv[16], enc_c2s[16], enc_s2c[16];
    ssh_kdf_one(c, 'A', iv, 16);      memcpy(c->iv_in,  iv, 12); c->cc_in  = be32(iv + 12);
    ssh_kdf_one(c, 'B', iv, 16);      memcpy(c->iv_out, iv, 12); c->cc_out = be32(iv + 12);
    ssh_kdf_one(c, 'C', enc_c2s, 16); br_aes_ct64_ctr_init(&c->cin,  enc_c2s, 16);
    ssh_kdf_one(c, 'D', enc_s2c, 16); br_aes_ct64_ctr_init(&c->cout, enc_s2c, 16);
    ssh_kdf_one(c, 'E', c->mac_in, 32);
    ssh_kdf_one(c, 'F', c->mac_out, 32);
}

/* Emit our ID line + the server KEXINIT; capture I_S into c->is (pre-frame). */
static uint32_t emit_id_kexinit(ssh_conn_t *c, uint8_t *out, uint32_t outmax) {
    uint32_t off = 0;
    uint32_t idl = (uint32_t)(sizeof SSH_ID - 1);   /* 21, includes CRLF */
    if (idl > outmax) { c->aborted = 1; return 0; }
    memcpy(out, SSH_ID, idl); off = idl;

    /* Build the KEXINIT payload (msg 20 .. reserved) into c->is = I_S. */
    uint8_t cookie[16]; tls_rng_fill(cookie, 16);
    uint32_t p = 0, cap = sizeof c->is;
    p = ssh_put_byte (c->is, p, cap, SSH_MSG_KEXINIT);
    p = ssh_put_bytes(c->is, p, cap, cookie, 16);
    /* EXACT OpenSSH 9.7 (Alpine 3.20) lists → HASSHServer e42184b06d45385a906f0803d04c83da.
     * kex/enc/mac/comp are the HASSH inputs (must match byte-for-byte); server_host_key
     * is NOT a HASSH input, so we advertise only what we can actually sign (rsa-sha2-*). */
    p = ssh_put_cstr (c->is, p, cap, "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com");  /* kex_algorithms */
    p = ssh_put_cstr (c->is, p, cap, "rsa-sha2-512,rsa-sha2-256");   /* server_host_key (not in HASSH) */
    p = ssh_put_cstr (c->is, p, cap, "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com");   /* encryption_c2s */
    p = ssh_put_cstr (c->is, p, cap, "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com");   /* encryption_s2c */
    p = ssh_put_cstr (c->is, p, cap, "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1");   /* mac_c2s */
    p = ssh_put_cstr (c->is, p, cap, "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1");   /* mac_s2c */
    p = ssh_put_cstr (c->is, p, cap, "none,zlib@openssh.com");   /* compression_c2s */
    p = ssh_put_cstr (c->is, p, cap, "none,zlib@openssh.com");   /* compression_s2c */
    p = ssh_put_cstr (c->is, p, cap, "");                    /* languages_c2s         */
    p = ssh_put_cstr (c->is, p, cap, "");                    /* languages_s2c         */
    p = ssh_put_byte (c->is, p, cap, 0);                     /* first_kex_packet_follows */
    p = ssh_put_u32  (c->is, p, cap, 0);                     /* reserved              */
    if (p == SSH_WIRE_ERR) { c->aborted = 1; return off; }
    c->is_len = p;

    uint32_t n = ssh_emit(c, out + off, outmax - off, c->is, p);  /* seq_out = 0 (cleartext) */
    if (!n) { c->aborted = 1; return off; }
    off += n;
    c->phase = SSH_PHASE_IDSENT;
    return off;
}

/* curve25519 KEX → KEX_ECDH_REPLY + NEWKEYS. Returns bytes written to out. */
static uint32_t do_kex(ssh_conn_t *c, const uint8_t *qc, uint8_t *out, uint32_t outmax) {
    /* 1. ephemeral X25519 (no byte-swap; BearSSL c25519 wire form == SSH). */
    tls_rng_fill(c->scalar, 32);
    (void)br_ec_c25519_m31.mulgen(c->qs, c->scalar, 32, BR_EC_curve25519);  /* Q_S */
    uint8_t k[32]; memcpy(k, qc, 32);
    uint32_t ok = br_ec_c25519_m31.mul(k, 32, c->scalar, 32, BR_EC_curve25519);
    uint8_t z = 0; for (int i = 0; i < 32; ++i) z |= k[i];
    if (!ok || z == 0) { c->aborted = 1; return 0; }   /* all-zero K is the mandatory guard */
    memcpy(c->k_raw, k, 32);                            /* shared secret for the §7.2 KDF (post-guard) */

    /* 2. host-key blob K_S = string"ssh-rsa" || mpint e || mpint n (one buffer, hashed AND sent). */
    uint8_t ks[320]; uint32_t kso = 0;
    kso = ssh_put_cstr (ks, kso, sizeof ks, "ssh-rsa");
    kso = ssh_put_mpint(ks, kso, sizeof ks, TA0_RSA_E, (uint32_t)sizeof TA0_RSA_E);
    kso = ssh_put_mpint(ks, kso, sizeof ks, TA0_RSA_N, (uint32_t)sizeof TA0_RSA_N);
    if (kso == SSH_WIRE_ERR) { c->aborted = 1; return 0; }

    /* 3. exchange hash H = SHA256(str V_C, str V_S, str I_C, str I_S, str K_S, str Q_C, str Q_S, mpint K). */
    static uint8_t hb[8192];   /* static: avoid a large stack frame */
    uint32_t ho = 0;
    ho = ssh_put_string(hb, ho, sizeof hb, c->vc, c->vc_len);
    ho = ssh_put_string(hb, ho, sizeof hb, (const uint8_t *)SSH_VS, (uint32_t)(sizeof SSH_VS - 1));
    ho = ssh_put_string(hb, ho, sizeof hb, c->ic, c->ic_len);
    ho = ssh_put_string(hb, ho, sizeof hb, c->is, c->is_len);
    ho = ssh_put_string(hb, ho, sizeof hb, ks, kso);
    ho = ssh_put_string(hb, ho, sizeof hb, qc, 32);
    ho = ssh_put_string(hb, ho, sizeof hb, c->qs, 32);
    ho = ssh_put_mpint (hb, ho, sizeof hb, k, 32);
    if (ho == SSH_WIRE_ERR) { c->aborted = 1; return 0; }
    uint8_t H[32];
    br_sha256_context sh; br_sha256_init(&sh); br_sha256_update(&sh, hb, ho); br_sha256_out(&sh, H);
    memcpy(c->session_id, H, 32);   /* session_id = the exchange hash H (KDF input) */
    /* KDF generalisation · curve25519-sha256: SHA-256, K = mpint(shared). */
    c->kex_sha512 = 0; c->sid_len = 32;
    c->k_enc_len = ssh_put_mpint(c->k_enc, 0, sizeof c->k_enc, c->k_raw, 32);
    if (c->k_enc_len == SSH_WIRE_ERR) { c->aborted = 1; return 0; }

    /* 4. host-key signature over H with the negotiated rsa-sha2-512/256. */
    uint8_t sb[320];
    uint32_t sbo = sign_exchange_hash(c, H, 32, sb, sizeof sb);
    if (c->aborted || sbo == SSH_WIRE_ERR) { c->aborted = 1; return 0; }

    /* 5. KEX_ECDH_REPLY = byte 31 || string K_S || string Q_S || string sig_blob. */
    uint8_t rep[800]; uint32_t ro = 0;
    ro = ssh_put_byte  (rep, ro, sizeof rep, SSH_MSG_KEX_ECDH_REPLY);
    ro = ssh_put_string(rep, ro, sizeof rep, ks, kso);
    ro = ssh_put_string(rep, ro, sizeof rep, c->qs, 32);
    ro = ssh_put_string(rep, ro, sizeof rep, sb, sbo);
    if (ro == SSH_WIRE_ERR) { c->aborted = 1; return 0; }

    uint32_t off = 0, n;
    n = ssh_emit(c, out + off, outmax - off, rep, ro);     /* seq_out = 1 (cleartext) */
    if (!n) { c->aborted = 1; return off; } off += n;
    uint8_t nk = SSH_MSG_NEWKEYS;
    n = ssh_emit(c, out + off, outmax - off, &nk, 1);      /* seq_out = 2 (cleartext) */
    if (!n) { c->aborted = 1; return off; } off += n;

    /* Our NEWKEYS is sent in clear; everything we send AFTER it is encrypted. */
    ssh_kdf(c);
    c->send_enc = 1;
    if (c->strict_kex) c->seq_out = 0;   /* strict-KEX (anti-Terrapin) · reset send seqnum after NEWKEYS */
    c->phase = SSH_PHASE_KEXED;
    printf("[synth-srv] inbound SSH KEX complete · conn=%u\n", (unsigned)c->conn_id);
    return off;
}

/* sntrup761x25519-sha512@openssh.com hybrid KEX (the OpenSSH 9.7 default · the
 * SSH analog of the TLS hybrid).  Q_C = sntrup_pub(1158) || x25519_pub(32) [1190].
 * Server: sntrup_enc → (ciphertext 1039, kem_key 32); X25519 → ecdh_shared 32;
 * K = string( SHA512(kem_key || ecdh_shared) ); Q_S = ciphertext || server_x25519
 * [1071]; H = SHA512(V_C,V_S,I_C,I_S,K_S,Q_C,Q_S,K).  Phase B keeps the existing
 * rsa-sha2-256 host-key sig + aes128-ctr/hmac-sha2-256 (forced in the gate). */
static uint32_t do_kex_hybrid(ssh_conn_t *c, const uint8_t *qc, uint8_t *out, uint32_t outmax) {
    const uint8_t *sntrup_pub = qc;                                  /* 1158 */
    const uint8_t *client_c25519 = qc + crypto_kem_sntrup761_PUBLICKEYBYTES; /* 32 */

    /* 1. sntrup761 encapsulate against the client's KEM pubkey + X25519. */
    static uint8_t ct[crypto_kem_sntrup761_CIPHERTEXTBYTES];   /* 1039 (static · large) */
    uint8_t kem_key[crypto_kem_sntrup761_BYTES];               /* 32 */
    crypto_kem_sntrup761_enc(ct, kem_key, sntrup_pub);

    tls_rng_fill(c->scalar, 32);
    (void)br_ec_c25519_m31.mulgen(c->qs, c->scalar, 32, BR_EC_curve25519);   /* server X25519 pub */
    uint8_t ecdh[32]; memcpy(ecdh, client_c25519, 32);
    uint32_t ok = br_ec_c25519_m31.mul(ecdh, 32, c->scalar, 32, BR_EC_curve25519);
    uint8_t z = 0; for (int i = 0; i < 32; ++i) z |= ecdh[i];
    if (!ok || z == 0) { c->aborted = 1; return 0; }                          /* all-zero ecdh guard */

    /* 2. shared secret K = string( SHA512(kem_key || ecdh_shared) ). */
    uint8_t cat[64]; memcpy(cat, kem_key, 32); memcpy(cat + 32, ecdh, 32);
    uint8_t hk[64];
    { br_sha512_context s; br_sha512_init(&s); br_sha512_update(&s, cat, 64); br_sha512_out(&s, hk); }
    c->k_enc_len = ssh_put_string(c->k_enc, 0, sizeof c->k_enc, hk, 64);      /* uint32(64)||hash = 68B */
    if (c->k_enc_len == SSH_WIRE_ERR) { c->aborted = 1; return 0; }

    /* 3. host-key blob K_S (same RSA-2048 key as curve25519 path). */
    uint8_t ks[320]; uint32_t kso = 0;
    kso = ssh_put_cstr (ks, kso, sizeof ks, "ssh-rsa");
    kso = ssh_put_mpint(ks, kso, sizeof ks, TA0_RSA_E, (uint32_t)sizeof TA0_RSA_E);
    kso = ssh_put_mpint(ks, kso, sizeof ks, TA0_RSA_N, (uint32_t)sizeof TA0_RSA_N);
    if (kso == SSH_WIRE_ERR) { c->aborted = 1; return 0; }

    /* 4. Q_S = ciphertext(1039) || server X25519 pub(32) = 1071. */
    static uint8_t qs_blob[crypto_kem_sntrup761_CIPHERTEXTBYTES + 32];
    memcpy(qs_blob, ct, crypto_kem_sntrup761_CIPHERTEXTBYTES);
    memcpy(qs_blob + crypto_kem_sntrup761_CIPHERTEXTBYTES, c->qs, 32);
    const uint32_t qc_len = crypto_kem_sntrup761_PUBLICKEYBYTES + 32;   /* 1190 */
    const uint32_t qs_len = crypto_kem_sntrup761_CIPHERTEXTBYTES + 32;  /* 1071 */

    /* 5. H = SHA512( str V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, <K already string-encoded> ). */
    static uint8_t hb[8192];
    uint32_t ho = 0;
    ho = ssh_put_string(hb, ho, sizeof hb, c->vc, c->vc_len);
    ho = ssh_put_string(hb, ho, sizeof hb, (const uint8_t *)SSH_VS, (uint32_t)(sizeof SSH_VS - 1));
    ho = ssh_put_string(hb, ho, sizeof hb, c->ic, c->ic_len);
    ho = ssh_put_string(hb, ho, sizeof hb, c->is, c->is_len);
    ho = ssh_put_string(hb, ho, sizeof hb, ks, kso);
    ho = ssh_put_string(hb, ho, sizeof hb, qc, qc_len);
    ho = ssh_put_string(hb, ho, sizeof hb, qs_blob, qs_len);
    ho = ssh_put_bytes (hb, ho, sizeof hb, c->k_enc, c->k_enc_len);   /* K is already string(hash) */
    if (ho == SSH_WIRE_ERR) { c->aborted = 1; return 0; }
    uint8_t H[64];
    { br_sha512_context s; br_sha512_init(&s); br_sha512_update(&s, hb, ho); br_sha512_out(&s, H); }
    memcpy(c->session_id, H, 64);
    c->kex_sha512 = 1; c->sid_len = 64;

    /* 6. host-key signature over the 64B H with the negotiated rsa-sha2-512/256. */
    uint8_t sb[320];
    uint32_t sbo = sign_exchange_hash(c, H, 64, sb, sizeof sb);
    if (c->aborted || sbo == SSH_WIRE_ERR) { c->aborted = 1; return 0; }

    /* 7. KEX_ECDH_REPLY = 31 || string K_S(~283) || string Q_S(1075) || string sig(~283). */
    static uint8_t rep[2048];
    uint32_t ro = 0;
    ro = ssh_put_byte  (rep, ro, sizeof rep, SSH_MSG_KEX_ECDH_REPLY);
    ro = ssh_put_string(rep, ro, sizeof rep, ks, kso);
    ro = ssh_put_string(rep, ro, sizeof rep, qs_blob, qs_len);
    ro = ssh_put_string(rep, ro, sizeof rep, sb, sbo);
    if (ro == SSH_WIRE_ERR) { c->aborted = 1; return 0; }

    uint32_t off = 0, n;
    n = ssh_emit(c, out + off, outmax - off, rep, ro);
    if (!n) { c->aborted = 1; return off; } off += n;
    uint8_t nk = SSH_MSG_NEWKEYS;
    n = ssh_emit(c, out + off, outmax - off, &nk, 1);
    if (!n) { c->aborted = 1; return off; } off += n;

    ssh_kdf(c);
    c->send_enc = 1;
    if (c->strict_kex) c->seq_out = 0;   /* strict-KEX (anti-Terrapin) · reset send seqnum after NEWKEYS */
    c->phase = SSH_PHASE_KEXED;
    printf("[synth-srv] inbound SSH hybrid-KEX (sntrup761x25519) complete · conn=%u\n", (unsigned)c->conn_id);
    return off;
}

/* Pull the next complete binary packet from c->rx into c->pl (decrypting +
 * MAC-verifying when recv_enc). Returns 1 if a packet is ready (rx advanced,
 * seq_in++), 0 if more bytes are needed; sets c->aborted on a protocol error. */
static int ssh_next_packet(ssh_conn_t *c) {
    if (!c->recv_enc) {
        if (c->rxlen < 4) return 0;
        uint32_t pktlen = be32(c->rx);
        if (pktlen < 2 || pktlen > (uint32_t)(SSH_RX_MAX - 4)) { c->aborted = 1; return 0; }
        uint32_t total = 4 + pktlen;
        if (c->rxlen < total) return 0;
        uint8_t padlen = c->rx[4];
        if ((uint32_t)padlen + 1 > pktlen) { c->aborted = 1; return 0; }
        uint32_t pl = pktlen - padlen - 1;
        if (pl > SSH_PL_MAX) { c->aborted = 1; return 0; }
        memcpy(c->pl, c->rx + 5, pl); c->pllen = pl;
        memmove(c->rx, c->rx + total, c->rxlen - total); c->rxlen -= total;
        c->seq_in++;
        return 1;
    }
    if (c->cipher_gcm) {
        uint32_t pl = 0;
        int64_t consumed = gcm_open(&c->gcm_in, c->giv_in, c->rx, c->rxlen, c->pl, SSH_PL_MAX, &pl);
        if (consumed == 0) return 0;                       /* need more bytes */
        if (consumed < 0) { c->aborted = 1; return 0; }    /* bad length / GCM tag mismatch */
        c->pllen = pl;
        memmove(c->rx, c->rx + consumed, c->rxlen - (uint32_t)consumed); c->rxlen -= (uint32_t)consumed;
        c->seq_in++;
        return 1;
    }
    if (c->cipher_chacha) {
        uint32_t pl = 0;
        int64_t consumed = cc20_open(c->cc20_c2s, c->seq_in, c->rx, c->rxlen, c->pl, SSH_PL_MAX, &pl);
        if (consumed == 0) return 0;                       /* need more bytes */
        if (consumed < 0) { c->aborted = 1; return 0; }    /* bad length / Poly1305 auth fail */
        c->pllen = pl;
        memmove(c->rx, c->rx + consumed, c->rxlen - (uint32_t)consumed); c->rxlen -= (uint32_t)consumed;
        c->seq_in++;
        return 1;
    }
    /* encrypted: peek packet_length from a decrypted CLONE of the first block
     * (do NOT advance cc_in), then one contiguous decrypt of the whole packet. */
    if (c->rxlen < 16) return 0;
    uint8_t blk[16]; memcpy(blk, c->rx, 16);
    uint32_t cc_clone = c->cc_in;
    (void)br_aes_ct64_ctr_run(&c->cin, c->iv_in, cc_clone, blk, 16);
    uint32_t pktlen = be32(blk);
    if (pktlen < 12 || pktlen > (uint32_t)(SSH_RX_MAX - 4 - 32) || ((4 + pktlen) & 15)) {
        c->aborted = 1; return 0;
    }
    uint32_t total = 4 + pktlen;
    if (c->rxlen < total + 32) return 0;             /* full packet + MAC not buffered yet */
    uint32_t cc_saved = c->cc_in;                    /* advance the cipher counter only on MAC success */
    c->cc_in = br_aes_ct64_ctr_run(&c->cin, c->iv_in, c->cc_in, c->rx, total);
    uint8_t seqb[4] = { (uint8_t)(c->seq_in>>24),(uint8_t)(c->seq_in>>16),
                        (uint8_t)(c->seq_in>>8),(uint8_t)c->seq_in };
    br_hmac_key_context kc; br_hmac_key_init(&kc, &br_sha256_vtable, c->mac_in, 32);
    br_hmac_context hc;     br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, seqb, 4); br_hmac_update(&hc, c->rx, total);
    uint8_t mac[32]; br_hmac_out(&hc, mac);
    if (memcmp(mac, c->rx + total, 32) != 0) { c->cc_in = cc_saved; c->aborted = 1; return 0; }  /* Corrupted MAC → keep cipher state clean */
    uint8_t padlen = c->rx[4];
    if ((uint32_t)padlen + 1 > pktlen) { c->aborted = 1; return 0; }
    uint32_t pl = pktlen - padlen - 1;
    if (pl > SSH_PL_MAX) { c->aborted = 1; return 0; }
    memcpy(c->pl, c->rx + 5, pl); c->pllen = pl;
    memmove(c->rx, c->rx + total + 32, c->rxlen - (total + 32)); c->rxlen -= (total + 32);
    c->seq_in++;
    return 1;
}

/* USERAUTH_FAILURE = byte 51 || name-list "password" || boolean 0 (always fail). */
static uint32_t emit_userauth_failure(ssh_conn_t *c, uint8_t *out, uint32_t outmax) {
    uint8_t pl[32]; uint32_t p = 0;
    p = ssh_put_byte(pl, p, sizeof pl, SSH_MSG_USERAUTH_FAILURE);
    p = ssh_put_cstr(pl, p, sizeof pl, "password");
    p = ssh_put_byte(pl, p, sizeof pl, 0);
    if (p == SSH_WIRE_ERR) { c->aborted = 1; return 0; }
    return ssh_emit(c, out, outmax, pl, p);
}

/* USERAUTH_SUCCESS = byte 52 (no fields). */
static uint32_t emit_userauth_success(ssh_conn_t *c, uint8_t *out, uint32_t outmax) {
    uint8_t pl[4]; uint32_t p = 0;
    p = ssh_put_byte(pl, p, sizeof pl, SSH_MSG_USERAUTH_SUCCESS);
    if (p == SSH_WIRE_ERR) { c->aborted = 1; return 0; }
    return ssh_emit(c, out, outmax, pl, p);
}

/* Drain c->rx: client ID line, then each complete binary packet (decrypted
 * after NEWKEYS). Returns bytes written to out. */
static uint32_t consume(ssh_conn_t *c, uint8_t *out, uint32_t outmax) {
    uint32_t off = 0;

    /* (1) client ID line: first '\n'-terminated line beginning "SSH-". */
    while (!c->id_done && c->rxlen > 0) {
        uint32_t nl = 0; int found = 0;
        for (; nl < c->rxlen; ++nl) if (c->rx[nl] == '\n') { found = 1; break; }
        if (!found) { if (c->rxlen >= SSH_VC_MAX) { c->aborted = 1; } return off; }  /* wait / overflow */
        uint32_t linelen = nl;                       /* bytes before '\n' */
        if (linelen > 0 && c->rx[linelen - 1] == '\r') linelen--;  /* strip CR */
        if (linelen >= 4 && memcmp(c->rx, "SSH-", 4) == 0) {
            if (linelen >= SSH_VC_MAX) { c->aborted = 1; return off; }  /* over-long ID → never hash a truncated V_C */
            memcpy(c->vc, c->rx, linelen); c->vc_len = linelen; c->id_done = 1;
        }
        /* shift the line (incl '\n') out of rx; non-SSH preamble lines are skipped */
        uint32_t adv = nl + 1;
        memmove(c->rx, c->rx + adv, c->rxlen - adv); c->rxlen -= adv;
    }
    if (!c->id_done) return off;

    /* (2) binary packets — ssh_next_packet re-checks recv_enc each iteration, so a
     * coalesced NEWKEYS(cleartext)+SERVICE_REQUEST(encrypted) both drain in one pass. */
    while (ssh_next_packet(c) == 1) {
        uint8_t msg = c->pllen >= 1 ? c->pl[0] : 0;
        if (msg == SSH_MSG_KEXINIT) {
            /* Only the client's initial KEXINIT (during our IDSENT phase) is valid;
             * a later one is an unsupported rekey / a flood that would overwrite I_C. */
            if (c->phase > SSH_PHASE_IDSENT) { c->aborted = 1; return off; }
            if (c->pllen > SSH_IC_MAX) { c->aborted = 1; return off; }  /* never hash a truncated I_C */
            memcpy(c->ic, c->pl, c->pllen); c->ic_len = c->pllen;
            negotiate(c);   /* cipher + host-key sig + strict-KEX, before the KDF */
        } else if (msg == SSH_MSG_KEX_ECDH_INIT) {
            if (c->phase >= SSH_PHASE_KEXED) { c->aborted = 1; return off; }  /* no rekey / RSA-amp flood */
            /* The Q_C string length disambiguates the negotiated KEX (the client
             * sends Q_C for whatever it negotiated): 32 = curve25519-sha256,
             * 1190 = sntrup761x25519-sha512 (sntrup_pub 1158 || x25519 32). */
            uint32_t qcl = c->pllen >= 1 + 4 ? be32(c->pl + 1) : 0;
            const uint32_t hyb = crypto_kem_sntrup761_PUBLICKEYBYTES + 32;   /* 1190 */
                    if (qcl == 32 && c->pllen >= 1 + 4 + 32) {
                off += do_kex(c, c->pl + 5, out + off, outmax - off);
            } else if (qcl == hyb && c->pllen >= 1 + 4 + hyb) {
                off += do_kex_hybrid(c, c->pl + 5, out + off, outmax - off);
            } else { c->aborted = 1; }
        } else if (msg == SSH_MSG_NEWKEYS) {
            c->recv_enc = 1;                          /* the NEXT packet from the client is encrypted */
            if (c->strict_kex) c->seq_in = 0;         /* strict-KEX · reset recv seqnum after NEWKEYS */
        } else if (msg == SSH_MSG_SERVICE_REQUEST && c->recv_enc) {
            /* (must be encrypted — a pre-NEWKEYS SERVICE_REQUEST is a protocol violation)
             * byte 5 || string service-name → SERVICE_ACCEPT echoing the name. */
            uint32_t snlen = c->pllen >= 5 ? be32(c->pl + 1) : 0;
            if (snlen > 40 || (uint32_t)5 + snlen > c->pllen) snlen = 0;
            uint8_t rep[64]; uint32_t r = 0;
            r = ssh_put_byte  (rep, r, sizeof rep, SSH_MSG_SERVICE_ACCEPT);
            r = ssh_put_string(rep, r, sizeof rep, c->pl + 5, snlen);
            if (r != SSH_WIRE_ERR) {
                uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
                if (!n) { c->aborted = 1; return off; } off += n;
            }
        } else if (msg == SSH_MSG_USERAUTH_REQUEST && c->recv_enc) {
            if (c->phase != SSH_PHASE_AUTH) {
                c->phase = SSH_PHASE_AUTH;
                printf("[synth-srv] inbound SSH userauth · conn=%u\n", (unsigned)c->conn_id);
            }
            /* byte 50 || string user || string service || string method [|| bool || string pw].
             * All reads via the bounded helpers (wrap-safe). */
            uint32_t q = 1;
            const uint8_t *user = NULL, *method = NULL, *pw = NULL;
            uint32_t ulen = 0, svlen = 0, mlen = 0, pwlen = 0; uint8_t pwbool = 0;
            const uint8_t *svc = NULL;
            int is_password = 0;
            if (ssh_rd_str(c->pl, c->pllen, &q, &user, &ulen) == 0 &&
                ssh_rd_str(c->pl, c->pllen, &q, &svc, &svlen) == 0 &&
                ssh_rd_str(c->pl, c->pllen, &q, &method, &mlen) == 0) {
                is_password = (mlen == 8 && memcmp(method, "password", 8) == 0);
                /* honeypot credential capture: bounded user + (password only) cleartext pw. */
                if (is_password &&
                    ssh_rd_byte(c->pl, c->pllen, &q, &pwbool) == 0 &&
                    ssh_rd_str (c->pl, c->pllen, &q, &pw, &pwlen) == 0) {
                    int ul = ulen > 64 ? 64 : (int)ulen;
                    int pl_ = pwlen > 64 ? 64 : (int)pwlen;
                    printf("[synth-srv] SSH cred conn=%u user=%.*s pass=%.*s\n",
                           (unsigned)c->conn_id, ul, user, pl_, pw);
                }
            }
            if (is_password && c->auth_fails >= 2) {
                off += emit_userauth_success(c, out + off, outmax - off);  /* 3rd attempt → in */
            } else {
                if (is_password) c->auth_fails++;
                off += emit_userauth_failure(c, out + off, outmax - off);   /* none/early → fail */
            }
        } else if (msg == SSH_MSG_GLOBAL_REQUEST && c->recv_enc) {
            /* byte 80 || string request-name || bool want_reply [|| ...] · we want no globals. */
            uint32_t q = 1; const uint8_t *rn; uint32_t rnlen; uint8_t want = 0;
            if (ssh_rd_str(c->pl, c->pllen, &q, &rn, &rnlen) == 0)
                (void)ssh_rd_byte(c->pl, c->pllen, &q, &want);
            if (want) {
                uint8_t rep[4]; uint32_t r = ssh_put_byte(rep, 0, sizeof rep, SSH_MSG_REQUEST_FAILURE);
                if (r != SSH_WIRE_ERR) { uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
                    if (!n) { c->aborted = 1; return off; } off += n; }
            }
        } else if (msg == SSH_MSG_CHANNEL_OPEN && c->recv_enc) {
            /* byte 90 || string chan-type || u32 sender-chan || u32 init-window || u32 max-pkt */
            uint32_t q = 1; const uint8_t *ct; uint32_t ctlen, sender = 0, win = 0;
            if (ssh_rd_str(c->pl, c->pllen, &q, &ct, &ctlen) == 0 &&
                ssh_rd_u32(c->pl, c->pllen, &q, &sender) == 0 &&
                ssh_rd_u32(c->pl, c->pllen, &q, &win) == 0) {
                c->peer_chan = sender; c->peer_window = win;
                /* CONFIRMATION: recipient=peer, sender=0, our window 1 MiB, max packet 32 KiB */
                uint8_t rep[20]; uint32_t r = 0;
                r = ssh_put_byte(rep, r, sizeof rep, SSH_MSG_CHANNEL_OPEN_CONFIRM);
                r = ssh_put_u32 (rep, r, sizeof rep, c->peer_chan);
                r = ssh_put_u32 (rep, r, sizeof rep, 0);
                r = ssh_put_u32 (rep, r, sizeof rep, 0x00100000);
                r = ssh_put_u32 (rep, r, sizeof rep, 0x00008000);
                if (r != SSH_WIRE_ERR) { uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
                    if (!n) { c->aborted = 1; return off; } off += n; }
            }
        } else if (msg == SSH_MSG_CHANNEL_REQUEST && c->recv_enc) {
            /* byte 98 || u32 recipient || string req-type || bool want_reply [|| type-specific] */
            uint32_t q = 1, recip = 0; const uint8_t *rtype; uint32_t rtlen; uint8_t want = 0;
            if (ssh_rd_u32(c->pl, c->pllen, &q, &recip) == 0 &&
                ssh_rd_str(c->pl, c->pllen, &q, &rtype, &rtlen) == 0) {
                (void)ssh_rd_byte(c->pl, c->pllen, &q, &want);
                /* Task B2 · pty-req / window-change carry the terminal size in the
                 * type-specific payload that begins at pl[q] (after recipient,
                 * req-type string, want_reply bool).  q<=pllen is guaranteed by the
                 * bounded readers above, so pl+q / (pllen-q) is an in-bounds view.
                 * Decode (B1 decoders are bounds-safe) and, on success, forward the
                 * dims to orch (where the per-session lucas_state lives) as a
                 * SHELL_WINCH control frame on in_p2c — same conn-routing the
                 * SHELL_START/KILL control frames use (by c->conn_id). */
                if (g_ssh_shell_rings_ready &&
                    ((rtlen == 7 && memcmp(rtype, "pty-req", 7) == 0) ||
                     (rtlen == 13 && memcmp(rtype, "window-change", 13) == 0))) {
                    const uint8_t *winp = c->pl + q;
                    size_t winlen = (size_t)(c->pllen - q);
                    uint16_t cols = 0, rows = 0;
                    int dec = (rtlen == 7)
                        ? lucas_tty_ptyreq_winsize(winp, winlen, &cols, &rows)
                        : lucas_tty_winch_winsize (winp, winlen, &cols, &rows);
                    if (dec == 0 && cols && rows) {
                        uint8_t wb[4] = { (uint8_t)(cols >> 8), (uint8_t)(cols & 0xff),
                                          (uint8_t)(rows >> 8), (uint8_t)(rows & 0xff) };
                        bytepipe_push_frame((bytepipe_ring_t *)BYTEPIPE_IN_P2C_VADDR,
                                            c->conn_id, BYTEPIPE_PORT_SHELL_WINCH, wb, 4);
                        printf("[ssh] winch cols=%u rows=%u\n", cols, rows);
                    }
                }
                int is_shell = (rtlen == 5 && memcmp(rtype, "shell", 5) == 0) ||
                               (rtlen == 4 && memcmp(rtype, "exec", 4) == 0);
                /* exec-mode (`ssh host 'cmd'`): the type-specific payload after want_reply
                 * is `string command`.  Capture it so orch runs it non-interactively
                 * (bash -c) and closes the channel — a real sshd does this, and the recon
                 * eval drives the honey this way.  q already points past want_reply. */
                if (rtlen == 4 && memcmp(rtype, "exec", 4) == 0) {
                    uint32_t qe = q; const uint8_t *xc = NULL; uint32_t xl = 0;
                    if (ssh_rd_str(c->pl, c->pllen, &qe, &xc, &xl) == 0 && xl > 0) {
                        uint32_t n = xl < (sizeof c->exec_cmd - 1) ? xl : (sizeof c->exec_cmd - 1);
                        memcpy(c->exec_cmd, xc, n); c->exec_cmd[n] = '\0';
                        c->exec_len = (uint16_t)n; c->is_exec = 1;
                    }
                }
                /* Phase B · R2 · refuse a 2nd concurrent shell while one is live
                 * (rings up): reply CHANNEL_FAILURE, never signal SHELL_START. */
                if (is_shell && g_ssh_shell_rings_ready && g_ssh_shell_busy) {
                    if (want) {
                        uint8_t rep[8]; uint32_t r = 0;
                        r = ssh_put_byte(rep, r, sizeof rep, SSH_MSG_CHANNEL_FAILURE);
                        r = ssh_put_u32 (rep, r, sizeof rep, c->peer_chan);
                        if (r != SSH_WIRE_ERR) { uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
                            if (!n) { c->aborted = 1; return off; } off += n; }
                    }
                    if (c->aborted) return off;
                    continue;
                }
                if (is_shell) {
                    c->shell_active = 1;
                    /* Phase B · ask main.c to spawn busybox (once) when rings are up. */
                    if (g_ssh_shell_rings_ready) c->shell_start_pending = 1;
                }
                if (want) {  /* pty-req / shell / exec / env / window-change → SUCCESS */
                    uint8_t rep[8]; uint32_t r = 0;
                    r = ssh_put_byte(rep, r, sizeof rep, SSH_MSG_CHANNEL_SUCCESS);
                    r = ssh_put_u32 (rep, r, sizeof rep, c->peer_chan);
                    if (r != SSH_WIRE_ERR) { uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
                        if (!n) { c->aborted = 1; return off; } off += n; }
                }
            }
        } else if (msg == SSH_MSG_CHANNEL_WINDOW_ADJUST && c->recv_enc) {
            uint32_t q = 1, recip = 0, add = 0;
            if (ssh_rd_u32(c->pl, c->pllen, &q, &recip) == 0 &&
                ssh_rd_u32(c->pl, c->pllen, &q, &add) == 0)
                c->peer_window += add;   /* client granted us more send room */
        } else if (msg == SSH_MSG_CHANNEL_DATA && c->recv_enc) {
            /* byte 94 || u32 recipient || string data.  Phase B: when the busybox
             * shell is live (rings up), write the decrypted keystrokes to SHELL_IN
             * (orch/busybox stdin).  The shell's stdout returns via the SHELL_OUT
             * pump in main.c as a separate CHANNEL_DATA.  Phase A fallback (rings
             * absent · R7): echo `data` back so the attacker still gets feedback. */
            uint32_t q = 1, recip = 0; const uint8_t *data = NULL; uint32_t dlen = 0;
            if (ssh_rd_u32(c->pl, c->pllen, &q, &recip) == 0 &&
                ssh_rd_str(c->pl, c->pllen, &q, &data, &dlen) == 0 &&
                dlen > 0 && dlen <= 1024) {
                if (g_ssh_shell_rings_ready && c->shell_active) {
                    bytepipe_push((bytepipe_ring_t *)BYTEPIPE_SHELL_IN_VADDR, data, dlen);
                } else {
                    uint8_t rep[1024 + 16]; uint32_t r = 0;
                    r = ssh_put_byte  (rep, r, sizeof rep, SSH_MSG_CHANNEL_DATA);
                    r = ssh_put_u32   (rep, r, sizeof rep, c->peer_chan);
                    r = ssh_put_string(rep, r, sizeof rep, data, dlen);
                    if (r != SSH_WIRE_ERR) { uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
                        if (!n) { c->aborted = 1; return off; } off += n; }
                }
            }
        } else if (msg == SSH_MSG_CHANNEL_EOF && c->recv_enc) {
            /* client signalled no-more-INPUT (stdin closed) — the channel is still
             * OPEN and busybox keeps running the already-buffered commands (incl its
             * own `exit`). Do NOT reap on EOF: an automated/heredoc client sends all
             * commands then EOF immediately, and killing here would reap busybox
             * before it runs them. Only CHANNEL_CLOSE / TCP-RST reaps. */
        } else if (msg == SSH_MSG_CHANNEL_CLOSE && c->recv_enc) {
            uint8_t rep[8]; uint32_t r = 0;
            r = ssh_put_byte(rep, r, sizeof rep, SSH_MSG_CHANNEL_CLOSE);
            r = ssh_put_u32 (rep, r, sizeof rep, c->peer_chan);
            if (r != SSH_WIRE_ERR) {
                uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
                if (!n) { c->aborted = 1; return off; } off += n;
            }
            /* Phase B · R4 · attacker closed the channel → reap busybox. */
            if (g_ssh_shell_rings_ready && c->shell_active) c->client_eof = 1;
            c->shell_active = 0;
        }
        if (c->aborted) return off;
    }
    return off;
}

/* :22 dispatch entry (called per inbound frame from main.c). */
uint32_t ssh_respond(uint16_t conn_id, const uint8_t *req, uint32_t reqlen,
                     uint8_t *out, uint32_t outmax) {
    ssh_conn_t *c = ssh_slot(conn_id, reqlen == 0);   /* len==0 greet = a new TCP connection */
    if (c->aborted) return 0;
    uint32_t off = 0;

    if (c->phase == SSH_PHASE_FRESH)
        off += emit_id_kexinit(c, out, outmax);       /* server-speaks-first: ID + KEXINIT */

    if (reqlen > 0 && !c->aborted) {
        if (c->rxlen + reqlen > SSH_RX_MAX) { c->aborted = 1; return off; }
        memcpy(c->rx + c->rxlen, req, reqlen); c->rxlen += reqlen;
        off += consume(c, out + off, outmax - off);
    }
    return off;
}

/* Phase B · find an EXISTING slot for conn_id (no allocation). NULL if none. */
static ssh_conn_t *ssh_find(uint16_t conn_id) {
    for (int i = 0; i < SSH_SESS_MAX; ++i)
        if (g_ssh[i].used && g_ssh[i].conn_id == conn_id) return &g_ssh[i];
    return NULL;
}

int ssh_take_shell_start(uint16_t conn_id) {
    ssh_conn_t *c = ssh_find(conn_id);
    if (c && c->shell_start_pending) { c->shell_start_pending = 0; return 1; }
    return 0;
}

/* exec-mode companion: copy the captured exec command into buf, returning its length
 * (0 for an interactive shell).  Consumes the flag so a re-drain won't re-fire. */
uint32_t ssh_take_exec_cmd(uint16_t conn_id, uint8_t *buf, uint32_t buflen) {
    ssh_conn_t *c = ssh_find(conn_id);
    if (!c || !c->is_exec || c->exec_len == 0 || buflen == 0) return 0;
    uint32_t n = c->exec_len < buflen ? c->exec_len : buflen;
    memcpy(buf, c->exec_cmd, n);
    c->is_exec = 0; c->exec_len = 0;   /* consume */
    return n;
}

int ssh_take_client_eof(uint16_t conn_id) {
    ssh_conn_t *c = ssh_find(conn_id);
    if (c && c->client_eof) { c->client_eof = 0; return 1; }
    return 0;
}

uint32_t ssh_emit_channel_data(uint16_t conn_id, const uint8_t *data, uint32_t len,
                               uint8_t *out, uint32_t outmax) {
    ssh_conn_t *c = ssh_find(conn_id);
    if (!c || c->aborted || !c->send_enc) return 0;
    if (len == 0 || len > 1024) return 0;
    uint8_t rep[1024 + 16]; uint32_t r = 0;
    r = ssh_put_byte  (rep, r, sizeof rep, SSH_MSG_CHANNEL_DATA);
    r = ssh_put_u32   (rep, r, sizeof rep, c->peer_chan);
    r = ssh_put_string(rep, r, sizeof rep, data, len);
    if (r == SSH_WIRE_ERR) return 0;
    return ssh_emit(c, out, outmax, rep, r);
}

uint32_t ssh_emit_channel_close(uint16_t conn_id, uint8_t *out, uint32_t outmax) {
    ssh_conn_t *c = ssh_find(conn_id);
    if (!c || c->aborted || !c->send_enc) return 0;
    uint32_t off = 0;
    /* CHANNEL_EOF then CHANNEL_CLOSE on the attacker's channel. */
    { uint8_t rep[8]; uint32_t r = 0;
      r = ssh_put_byte(rep, r, sizeof rep, SSH_MSG_CHANNEL_EOF);
      r = ssh_put_u32 (rep, r, sizeof rep, c->peer_chan);
      if (r != SSH_WIRE_ERR) { uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
          if (!n) return off; off += n; } }
    { uint8_t rep[8]; uint32_t r = 0;
      r = ssh_put_byte(rep, r, sizeof rep, SSH_MSG_CHANNEL_CLOSE);
      r = ssh_put_u32 (rep, r, sizeof rep, c->peer_chan);
      if (r != SSH_WIRE_ERR) { uint32_t n = ssh_emit(c, out + off, outmax - off, rep, r);
          if (!n) return off; off += n; } }
    c->shell_active = 0;
    return off;
}
