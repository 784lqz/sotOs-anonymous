#ifndef NET_SYNTH_TLS13_AEAD_H
#define NET_SYNTH_TLS13_AEAD_H
#include <stdint.h>
#include <stddef.h>
#include "net-synth/tls13.h"   /* tls13_suite_t (suite->aead / key_len) */

/* ε3: the record layer is suite-dispatched.  `suite` selects the AEAD and the
 * key length (suite->aead / suite->key_len); `key` points at suite->key_len
 * bytes (16 for AES-128-GCM, 32 for AES-256-GCM / ChaCha20-Poly1305).  If
 * `suite` is NULL the pre-A5 default 0x1301 (AES-128-GCM-SHA256) is used, so the
 * shipped behaviour is byte-identical until A5 wires suite selection.  The
 * nonce (RFC 8446 §5.3), 5-byte AAD, 16-byte tag and inner-type/padding handling
 * are AEAD-independent (RFC 5116). */

/* Seal: writes a full TLS 1.3 record (5B hdr + ciphertext + 16B tag) to out.
 * Returns total record length, or 0 on overflow. inner_type: 0x16 handshake,
 * 0x17 app-data, 0x15 alert. */
size_t tls13_record_seal(const tls13_suite_t *suite, const uint8_t *key,
                         const uint8_t iv[12], uint64_t seq,
                         uint8_t inner_type, const uint8_t *pt, size_t pt_len,
                         uint8_t *out, size_t out_cap);
/* Open: rec points at a full record (hdr+ct+tag), rec_len its length. Decrypts
 * into pt (capacity pt_cap); strips zero padding; sets *inner_type and *pt_len
 * (the content length, excluding the type byte). Returns 0 ok, -1 auth/format fail. */
int tls13_record_open(const tls13_suite_t *suite, const uint8_t *key,
                      const uint8_t iv[12], uint64_t seq,
                      const uint8_t *rec, size_t rec_len,
                      uint8_t *pt, size_t pt_cap, size_t *pt_len, uint8_t *inner_type);
#endif
