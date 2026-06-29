#ifndef NET_SYNTH_TLS13_H
#define NET_SYNTH_TLS13_H
#include <stdint.h>
#include <stddef.h>

/* ε1 scope: suite 0x1301 (AES-128-GCM-SHA256), group X25519 (0x001d). */
#define TLS13_AES_128_GCM_SHA256       0x1301
/* ε3 scope: additional cipher suites. */
#define TLS13_AES_256_GCM_SHA384       0x1302
#define TLS13_CHACHA20_POLY1305_SHA256 0x1303
#define TLS13_GROUP_X25519             0x001d
/* ε2 scope: additional ECDHE key-share groups (prime curves, X-coord secret). */
#define TLS13_GROUP_SECP256R1          0x0017
#define TLS13_GROUP_SECP384R1          0x0018

/* ── ε3: cipher suite descriptor ──────────────────────────────────────────
 * Static const immutable descriptor.  hash_vtable is held as const void* so
 * the header need not pull <bearssl.h>; tls13_keysched.c casts back to
 * const br_hash_class*. */
typedef enum {
    TLS13_AEAD_AES_128_GCM = 0,
    TLS13_AEAD_AES_256_GCM,
    TLS13_AEAD_CHACHA20_POLY1305,
} tls13_aead_kind_t;

typedef struct tls13_suite {
    uint16_t          id;           /* 0x1301 / 0x1302 / 0x1303              */
    const void       *hash_vtable;  /* &br_sha256_vtable | &br_sha384_vtable */
    uint8_t           hash_len;     /* 32 | 48                               */
    tls13_aead_kind_t aead;
    uint8_t           key_len;      /* 16 | 32 | 32                          */
    uint8_t           iv_len;       /* 12 (RFC 8446 §5.3, all suites)        */
    uint8_t           tag_len;      /* 16                                    */
    uint8_t           finished_len; /* == hash_len                           */
    uint16_t          sigalg;       /* 0x0804 (SHA-256) | 0x0805 (SHA-384)  */
} tls13_suite_t;

/* Lookup by wire id; returns NULL for unknown suites. */
const tls13_suite_t *tls13_suite_by_id(uint16_t id);

typedef enum {
    TLS13_ST_START = 0,      /* awaiting ClientHello */
    TLS13_ST_WAIT_FINISHED,  /* sent our flight, awaiting client Finished */
    TLS13_ST_APP,            /* handshake done, app-data flowing */
    TLS13_ST_ERR,
} tls13_state_t;

typedef struct tls13_sess {
    int           used;
    uint16_t      conn_id;
    uint32_t      last_seen;
    tls13_state_t st;

    /* ε3: active cipher suite (set on CH1, before key schedule). */
    const tls13_suite_t *suite;

    /* transcript: a running hash over every handshake message, in order.
     * th_buf holds raw messages; hash computed on demand via suite->hash_vtable. */
    uint8_t       th_buf[16384];
    size_t        th_len;

    /* ECDHE server ephemeral + shared secret (group-agnostic; sized for P-384).
     * X25519: priv/pub/shared all 32B. P-256: priv 32, pub 65 (0x04||X||Y),
     * shared 32 (X only). P-384: priv 48, pub 97, shared 48 (X only). */
    uint8_t       srv_eph_priv[48];
    uint16_t      srv_eph_priv_len;
    uint8_t       srv_eph_pub[97];
    uint16_t      srv_eph_pub_len;
    uint8_t       ecdhe_shared[48];
    uint16_t      ecdhe_shared_len;
    uint16_t      selected_group;

    /* derived keys — widened to SHA-384 max (key=32, iv=12, finished/secrets=48).
     * ε1/ε2 (0x1301): uses first 16B of key, first 32B of finished/secrets.
     * ε3/0x1302: uses 32B key, 48B finished/secrets.
     * *_iv stays 12 (all suites per RFC 8446 §5.3). */
    uint8_t       c_hs_key[32], c_hs_iv[12];
    uint8_t       s_hs_key[32], s_hs_iv[12];
    uint8_t       c_ap_key[32], c_ap_iv[12];
    uint8_t       s_ap_key[32], s_ap_iv[12];
    uint8_t       c_finished_key[48];
    uint8_t       s_finished_key[48];
    uint8_t       c_hs_secret[48], s_hs_secret[48];
    uint8_t       master_secret[48];

    uint64_t      seq_rx;
    uint64_t      seq_tx;
    int           rx_app; /* 0 = handshake key, 1 = app key */
    int           tx_app; /* 0 = handshake key, 1 = app key */

    uint8_t       legacy_session_id[32];
    uint8_t       legacy_session_id_len;

    /* HelloRetryRequest (RFC 8446 §4.1.4): set once we have emitted an HRR.
     * State stays TLS13_ST_START while awaiting CH2; hrr_sent disambiguates
     * the first ClientHello (CH1) from the retry (CH2). hrr_group records the
     * group HRR asked for, so CH2 can be rejected if it key_shares a different
     * group (§4.1.4: the client MUST send a share for the indicated group). */
    uint8_t       hrr_sent;
    uint16_t      hrr_group;
} tls13_sess_t;

typedef uint32_t (*tls13_app_fn)(const uint8_t *req, uint32_t reqlen,
                                 uint8_t *out, uint32_t outcap);
/* Feed one inbound frame of client TLS record bytes (handshake or app-data).
   Appends server records to out (caller segments + pushes as in_p2c frames).
   Returns 0 ok, -1 fatal. app() is called with decrypted request bytes → reply plaintext. */
int tls13_inbound_feed(tls13_sess_t *s, const uint8_t *in, uint32_t inlen,
                       uint8_t *out, uint32_t outcap, uint32_t *outlen,
                       tls13_app_fn app);

/* Parsed ClientHello fields relevant to the TLS 1.3 handshake. */
typedef struct {
    int     ok;                 /* 1 if a usable TLS 1.3 CH parsed (has supported_versions=0x0304) */
    uint8_t client_x25519[32];  /* valid when has_x25519_share == 1 */
    int     has_x25519_share;
    int     x25519_in_groups;   /* X25519 (0x001d) listed in supported_groups (for HRR) */
    uint8_t client_p256[65];    /* valid when has_p256_share == 1 (0x04||X||Y) */
    int     has_p256_share;
    int     p256_in_groups;     /* secp256r1 (0x0017) listed in supported_groups */
    uint8_t client_p384[97];    /* valid when has_p384_share == 1 (0x04||X||Y) */
    int     has_p384_share;
    int     p384_in_groups;     /* secp384r1 (0x0018) listed in supported_groups */
    int     suite_1301;         /* TLS_AES_128_GCM_SHA256 offered */
    int     suite_1302;         /* TLS_AES_256_GCM_SHA384 offered */
    int     suite_1303;         /* TLS_CHACHA20_POLY1305_SHA256 offered */
    /* ε4: the FIRST suite (in client wire order) that is one of the three we
     * serve {0x1301,0x1302,0x1303}; 0 if none.  select_suite honors client
     * order (match default nginx, ssl_prefer_server_ciphers off). */
    uint16_t first_served_suite;
    int     sigalg_0804;        /* rsa_pss_rsae_sha256 offered */
    uint8_t session_id[32];
    uint8_t session_id_len;
} tls13_clienthello_t;

/* Parse a full TLS record that is expected to be a ClientHello.  Fills *out.
   Returns 0 on a structurally valid CH (even if optional fields absent),
   -1 on malformed / OOB / not-a-CH.  All reads are bounds-checked. */
int tls13_parse_clienthello(const uint8_t *rec, uint32_t reclen,
                             tls13_clienthello_t *out);

/* Peek a raw ClientHello record: 1 if it offers TLS 1.3 (0x0304 in supported_versions),
   0 if not (→ route to mine2g), -1 if not a ClientHello. */
int tls13_clienthello_offers_13(const uint8_t *rec, uint32_t reclen);

/* ── Task 7: handshake-message serializers ───────────────────────────────
 * Each produces one handshake message: u8(hs_type)||u24(body_len)||body.
 * Returns the total written length, or 0 on overflow (caller buf too small). */

/* ServerHello (hs_type=0x02). rng_fill provides the 32-byte random.
 * cipher_suite = the selected suite id (0x1301/0x1302/0x1303).
 * key_share = u16(group) || u16(srv_pub_len) || srv_pub.
 * srv_pub_len is the on-wire key length: 32 (X25519), 65 (P-256), 97 (P-384). */
size_t tls13_make_serverhello(uint8_t *out, size_t cap,
                              uint16_t suite_id, uint16_t group,
                              const uint8_t *srv_pub, uint16_t srv_pub_len,
                              const uint8_t *session_id, uint8_t sid_len,
                              void (*rng_fill)(uint8_t *, size_t));

/* EncryptedExtensions (hs_type=0x08): always 6 bytes { 08 00 00 02 00 00 }. */
size_t tls13_make_ee(uint8_t *out, size_t cap);

/* Certificate (hs_type=0x0b): single cert from CHAIN[0] in tls_cert.h. */
size_t tls13_make_cert(uint8_t *out, size_t cap);

/* CertificateVerify (hs_type=0x0f): 256-byte RSA-PSS sig.  sigalg + th_len are
 * taken from `suite` (0x1301/0x1303 → 0x0804 over 32B SHA-256; 0x1302 → 0x0805
 * over 48B SHA-384).  th must hold suite->hash_len bytes. */
size_t tls13_make_certverify(uint8_t *out, size_t cap,
                             const tls13_suite_t *suite,
                             const uint8_t *th, size_t th_len,
                             void (*rng_fill)(uint8_t *, size_t));

/* Finished (hs_type=0x14): verify_data = HMAC-H(finished_key, th), where H is
 * the suite hash (SHA-256 for 0x1301/0x1303, SHA-384 for 0x1302).  finished_key
 * and th must each hold suite->hash_len bytes (32 or 48). */
size_t tls13_make_finished(uint8_t *out, size_t cap,
                           const tls13_suite_t *suite,
                           const uint8_t *finished_key,
                           const uint8_t *th);

/* ── Task 9: HelloRetryRequest ────────────────────────────────────────────
 * HRR is a ServerHello (hs_type=0x02) carrying the fixed special random
 * (RFC 8446 §4.1.3) and a key_share extension that names the selected group
 * but carries NO key — asking the client to retry with a share for `group`.
 * cipher_suite = the selected suite id (must match the eventual ServerHello).
 * Returns the total handshake-message length, or 0 on overflow. */
size_t tls13_make_hrr(uint8_t *out, size_t cap,
                      uint16_t suite_id, uint16_t group,
                      const uint8_t *session_id, uint8_t sid_len);
#endif
