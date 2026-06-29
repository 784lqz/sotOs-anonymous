#ifndef NET_SYNTH_TLS13_KEYSCHED_H
#define NET_SYNTH_TLS13_KEYSCHED_H
#include <stdint.h>
#include <stddef.h>

/* ε3: suite-threaded HKDF primitives.  `suite` selects the hash (SHA-256 vs
 * SHA-384) and its output length; suite==NULL ⇒ SHA-256/32B (the ε1/ε2 default,
 * every legacy call passes NULL → byte-identical).  `out` buffers must hold
 * suite->hash_len (≤48) bytes for the hash/extract/derive entry points. */
struct tls13_suite; /* fwd (defined in net-synth/tls13.h) */

void tls13_hkdf_extract(const struct tls13_suite *suite,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len, uint8_t *out);
void tls13_expand_label(const struct tls13_suite *suite, const uint8_t *secret,
                        const char *label, const uint8_t *ctx, size_t ctx_len,
                        uint8_t *out, size_t out_len);
void tls13_derive_secret(const struct tls13_suite *suite, const uint8_t *secret,
                         const char *label, const uint8_t *transcript_hash,
                         uint8_t *out);
void tls13_transcript_hash(const struct tls13_suite *suite,
                           const uint8_t *msgs, size_t len, uint8_t *out);

struct tls13_sess; /* fwd (defined in net-synth/tls13.h) */
/* Fill handshake-stage secrets/keys/ivs/finished-keys from s->ecdhe_shared and
 * th_chsh = transcript_hash(ClientHello..ServerHello). Also computes master_secret. */
void tls13_key_schedule_handshake(struct tls13_sess *s, const uint8_t th_chsh[32]);
/* Fill application-stage keys/ivs from s->master_secret and
 * th_full = transcript_hash(ClientHello..server Finished). */
void tls13_key_schedule_application(struct tls13_sess *s, const uint8_t th_full[32]);
#endif
