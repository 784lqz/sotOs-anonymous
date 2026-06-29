/*
 * sotOs · arc4random (ChaCha20-based userspace CSPRNG) · vendored
 * from OpenBSD.  Provides cryptographic-quality bytes without any
 * VFS, file descriptor, or kernel-side state.
 *
 * Seed is one-time at orch bootstrap (sotos_arc4random_init).
 * Caller is responsible for seeding before any consumption.
 *
 * Original OpenBSD copyright:
 *   Copyright (c) 1996, David Mazieres <dm@uun.org>
 *   Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *   Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 *   Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 * ChaCha20 by D. J. Bernstein, public domain.
 */
#ifndef SOTOS_RANDOM_H
#define SOTOS_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One-time seed.  `seed` must have at least 40 bytes (32 key + 8 nonce). */
void sotos_arc4random_init(const uint8_t *seed, size_t seed_len);

/* Return 32 random bits.  Bootstrap MUST have been called first. */
uint32_t sotos_arc4random(void);

/* Fill `buf` with `n` random bytes. */
void sotos_arc4random_buf(void *buf, size_t n);

/* Return a uniformly distributed integer in [0, upper_bound). */
uint32_t sotos_arc4random_uniform(uint32_t upper_bound);

#ifdef __cplusplus
}
#endif

#endif /* SOTOS_RANDOM_H */
