/* sotOs glue for the vendored OpenSSH sntrup761 KEM (crypto_api.h declares these
 * as functions): randombytes → the net-synth RNG, crypto_hash_sha512 → BearSSL,
 * plus the optimisation-blocker globals the constant-time code references. */
#include <stdint.h>
#include <string.h>
#include "bearssl_hash.h"
#include "tls_rng.h"
#include "sntrup761/crypto_api.h"

volatile crypto_int16 crypto_int16_optblocker = 0;
volatile crypto_int32 crypto_int32_optblocker = 0;
volatile crypto_int64 crypto_int64_optblocker = 0;

void randombytes(void *buf, unsigned long long len) {
    tls_rng_fill((uint8_t *)buf, (size_t)len);
}

int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen) {
    br_sha512_context c;
    br_sha512_init(&c);
    br_sha512_update(&c, in, (size_t)inlen);
    br_sha512_out(&c, out);
    return 0;
}
