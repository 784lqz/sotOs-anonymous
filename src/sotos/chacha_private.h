/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.

Vendored into sotOs 2026-05-22.
Adapted from OpenBSD src/lib/libc/crypt/chacha_private.h
*/

#ifndef CHACHA_PRIVATE_H
#define CHACHA_PRIVATE_H

#include <stdint.h>

typedef struct {
    uint32_t input[16];
} chacha_ctx;

void chacha_keysetup(chacha_ctx *x, const uint8_t *k, uint32_t kbits);
void chacha_ivsetup(chacha_ctx *x, const uint8_t *iv, const uint8_t *counter);
void chacha_encrypt_bytes(chacha_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes);

#endif /* CHACHA_PRIVATE_H */
