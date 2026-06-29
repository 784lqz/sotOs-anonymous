/*
 * sotOs · SHA-256 · vendored from seL4_tools/elfloader-tool/src/utils/crypt_sha256.c
 *
 * The original is "public domain sha256 implementation based on fips180-3"
 * (DornerWorks SPDX: GPL-2.0-only header preserved in sha256.c).  We rename
 * the public symbols to the sotos_* namespace so future linkage against
 * libcrypto (OpenSSL or BoringSSL) cannot collide.
 *
 * One-shot:
 *     uint8_t md[32];
 *     sotos_sha256(buf, len, md);
 *
 * Streaming (recommended for large inputs · keeps stack usage bounded):
 *     sotos_sha256_t ctx;
 *     sotos_sha256_init(&ctx);
 *     sotos_sha256_update(&ctx, chunk, n);
 *     ...
 *     sotos_sha256_final(&ctx, md);
 *
 * All buffers are caller-allocated; no malloc, no globals.
 */
#ifndef SOTOS_SHA256_H
#define SOTOS_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SOTOS_SHA256_DIGEST_SIZE 32
#define SOTOS_SHA256_BLOCK_SIZE  64

typedef struct {
    uint64_t len;                              /* processed message length */
    uint32_t h[8];                             /* hash state */
    uint8_t  buf[SOTOS_SHA256_BLOCK_SIZE];     /* message block buffer */
} sotos_sha256_t;

void sotos_sha256_init  (sotos_sha256_t *s);
void sotos_sha256_update(sotos_sha256_t *s, const void *data, size_t len);
void sotos_sha256_final (sotos_sha256_t *s, uint8_t out[SOTOS_SHA256_DIGEST_SIZE]);

/* One-shot wrapper around init/update/final. */
void sotos_sha256(const void *data, size_t len,
                  uint8_t out[SOTOS_SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* SOTOS_SHA256_H */
