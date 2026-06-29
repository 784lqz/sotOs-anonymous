/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */
/* Public Domain poly1305 from Andrew Moon (poly1305-donna-unrolled).
 * Cleaned for the sotOs net-synth build: dropped <sys/types.h>/u_char and the
 * OpenBSD __bounded__ attributes (GCC rejects them). */
#ifndef SOTOS_POLY1305_H
#define SOTOS_POLY1305_H
#include <stddef.h>
#define POLY1305_KEYLEN  32
#define POLY1305_TAGLEN  16
void poly1305_auth(unsigned char out[POLY1305_TAGLEN], const unsigned char *m,
                   size_t inlen, const unsigned char key[POLY1305_KEYLEN]);
#endif
