/* Host KAT · the vendored OpenSSH sntrup761 KEM is self-consistent:
 * keypair → enc → dec yields the SAME 32-byte shared secret (the property the
 * SSH hybrid KEX relies on · the server runs enc, the client dec).
 *   just test-sntrup761-unit
 */
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "crypto_api.h"

/* the optimisation-blockers sntrup761.c declares extern */
volatile crypto_int16 crypto_int16_optblocker = 0;
volatile crypto_int32 crypto_int32_optblocker = 0;
volatile crypto_int64 crypto_int64_optblocker = 0;

void randombytes(void *buf, unsigned long long len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, (size_t)len, f) != (size_t)len) { fprintf(stderr, "urandom fail\n"); exit(2); }
    fclose(f);
}
int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen) {
    SHA512(in, (size_t)inlen, out);
    return 0;
}

int main(void) {
    unsigned char pk[crypto_kem_sntrup761_PUBLICKEYBYTES];
    unsigned char sk[crypto_kem_sntrup761_SECRETKEYBYTES];
    unsigned char ct[crypto_kem_sntrup761_CIPHERTEXTBYTES];
    unsigned char ke[crypto_kem_sntrup761_BYTES], kd[crypto_kem_sntrup761_BYTES];
    int fails = 0;

    for (int round = 0; round < 5; ++round) {
        crypto_kem_sntrup761_keypair(pk, sk);   /* client */
        crypto_kem_sntrup761_enc(ct, ke, pk);   /* server encapsulates */
        crypto_kem_sntrup761_dec(kd, ct, sk);   /* client decapsulates */
        if (memcmp(ke, kd, sizeof(ke)) != 0) { printf("round %d: shared-secret MISMATCH\n", round); fails++; }
    }
    if (fails == 0) printf("sntrup761 host KAT: enc/dec shared-secret AGREE over 5 rounds (32B, PK=%d CT=%d)\n",
                           crypto_kem_sntrup761_PUBLICKEYBYTES, crypto_kem_sntrup761_CIPHERTEXTBYTES);
    return fails ? 1 : 0;
}
