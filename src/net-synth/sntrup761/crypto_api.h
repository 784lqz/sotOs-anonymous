/* shim crypto_api.h for the vendored OpenSSH sntrup761.c · used by BOTH the host
 * KAT (just test-sntrup761-unit) and the sotOs net-synth build.  randombytes +
 * crypto_hash_sha512 are FUNCTIONS supplied by the embedder (host test: openssl
 * + urandom · sotOs: tls_rng + BearSSL br_sha512), not OpenSSH's arc4random /
 * SHA2_CTX macros. */
#ifndef crypto_api_h
#define crypto_api_h
#include <stdint.h>
#include <stdlib.h>
typedef int8_t   crypto_int8;   typedef uint8_t  crypto_uint8;
typedef int16_t  crypto_int16;  typedef uint16_t crypto_uint16;
typedef int32_t  crypto_int32;  typedef uint32_t crypto_uint32;
typedef int64_t  crypto_int64;  typedef uint64_t crypto_uint64;

#define crypto_kem_sntrup761_PUBLICKEYBYTES  1158
#define crypto_kem_sntrup761_SECRETKEYBYTES  1763
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_BYTES             32

int crypto_kem_sntrup761_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_sntrup761_enc(unsigned char *c, unsigned char *k, const unsigned char *pk);
int crypto_kem_sntrup761_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk);

void randombytes(void *buf, unsigned long long len);
int  crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);
#endif
