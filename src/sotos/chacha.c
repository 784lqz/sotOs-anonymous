/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.

Vendored into sotOs 2026-05-22 from
OpenBSD src/lib/libc/crypt/chacha_private.h (merged .c form).
ChaCha20 stream cipher — 256-bit key, 64-bit nonce, 64-bit counter.
*/

#include "chacha_private.h"

#define ROTATE(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define XOR(v, w)    ((v) ^ (w))
#define PLUS(v, w)   ((v) + (w))
#define PLUSONE(v)   (PLUS((v), 1))

#define U32TO8_LITTLE(p, v)       \
    do {                          \
        (p)[0] = (uint8_t)((v)      );   \
        (p)[1] = (uint8_t)((v) >>  8);   \
        (p)[2] = (uint8_t)((v) >> 16);   \
        (p)[3] = (uint8_t)((v) >> 24);   \
    } while (0)

#define U8TO32_LITTLE(p) \
    (((uint32_t)(p)[0]      ) | \
     ((uint32_t)(p)[1] <<  8) | \
     ((uint32_t)(p)[2] << 16) | \
     ((uint32_t)(p)[3] << 24))

#define QUARTERROUND(a,b,c,d) \
    a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
    c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
    a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
    c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[] = "expand 32-byte k";
static const char tau[]   = "expand 16-byte k";

void
chacha_keysetup(chacha_ctx *x, const uint8_t *k, uint32_t kbits)
{
    const char *constants;

    x->input[4] = U8TO32_LITTLE(k + 0);
    x->input[5] = U8TO32_LITTLE(k + 4);
    x->input[6] = U8TO32_LITTLE(k + 8);
    x->input[7] = U8TO32_LITTLE(k + 12);
    if (kbits == 256) { /* recommended */
        k += 16;
        constants = sigma;
    } else { /* 128-bit key */
        constants = tau;
    }
    x->input[8]  = U8TO32_LITTLE(k + 0);
    x->input[9]  = U8TO32_LITTLE(k + 4);
    x->input[10] = U8TO32_LITTLE(k + 8);
    x->input[11] = U8TO32_LITTLE(k + 12);
    x->input[0]  = U8TO32_LITTLE(constants + 0);
    x->input[1]  = U8TO32_LITTLE(constants + 4);
    x->input[2]  = U8TO32_LITTLE(constants + 8);
    x->input[3]  = U8TO32_LITTLE(constants + 12);
}

void
chacha_ivsetup(chacha_ctx *x, const uint8_t *iv, const uint8_t *counter)
{
    x->input[12] = counter == (void *)0 ? 0 : U8TO32_LITTLE(counter + 0);
    x->input[13] = counter == (void *)0 ? 0 : U8TO32_LITTLE(counter + 4);
    x->input[14] = U8TO32_LITTLE(iv + 0);
    x->input[15] = U8TO32_LITTLE(iv + 4);
}

void
chacha_encrypt_bytes(chacha_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7;
    uint32_t j8, j9, j10, j11, j12, j13, j14, j15;
    uint8_t tmp[64];
    uint8_t *ctarget = (void *)0;
    uint8_t *out = c;
    uint32_t i;

    if (!bytes) return;

    j0  = x->input[0];
    j1  = x->input[1];
    j2  = x->input[2];
    j3  = x->input[3];
    j4  = x->input[4];
    j5  = x->input[5];
    j6  = x->input[6];
    j7  = x->input[7];
    j8  = x->input[8];
    j9  = x->input[9];
    j10 = x->input[10];
    j11 = x->input[11];
    j12 = x->input[12];
    j13 = x->input[13];
    j14 = x->input[14];
    j15 = x->input[15];

    for (;;) {
        if (bytes < 64) {
            /* Use tmp buffer for partial block. */
            for (i = 0; i < bytes; ++i) tmp[i] = m[i];
            m = tmp;
            ctarget = c;
            c = tmp;
        }
        x0  = j0;  x1  = j1;  x2  = j2;  x3  = j3;
        x4  = j4;  x5  = j5;  x6  = j6;  x7  = j7;
        x8  = j8;  x9  = j9;  x10 = j10; x11 = j11;
        x12 = j12; x13 = j13; x14 = j14; x15 = j15;

        for (i = 20; i > 0; i -= 2) {
            QUARTERROUND( x0, x4, x8,x12)
            QUARTERROUND( x1, x5, x9,x13)
            QUARTERROUND( x2, x6,x10,x14)
            QUARTERROUND( x3, x7,x11,x15)
            QUARTERROUND( x0, x5,x10,x15)
            QUARTERROUND( x1, x6,x11,x12)
            QUARTERROUND( x2, x7, x8,x13)
            QUARTERROUND( x3, x4, x9,x14)
        }

        x0  = PLUS(x0,  j0);  x1  = PLUS(x1,  j1);
        x2  = PLUS(x2,  j2);  x3  = PLUS(x3,  j3);
        x4  = PLUS(x4,  j4);  x5  = PLUS(x5,  j5);
        x6  = PLUS(x6,  j6);  x7  = PLUS(x7,  j7);
        x8  = PLUS(x8,  j8);  x9  = PLUS(x9,  j9);
        x10 = PLUS(x10, j10); x11 = PLUS(x11, j11);
        x12 = PLUS(x12, j12); x13 = PLUS(x13, j13);
        x14 = PLUS(x14, j14); x15 = PLUS(x15, j15);

        /* XOR with message (or zero for keystream). */
        U32TO8_LITTLE(c + 0,  XOR(x0,  U8TO32_LITTLE(m + 0)));
        U32TO8_LITTLE(c + 4,  XOR(x1,  U8TO32_LITTLE(m + 4)));
        U32TO8_LITTLE(c + 8,  XOR(x2,  U8TO32_LITTLE(m + 8)));
        U32TO8_LITTLE(c + 12, XOR(x3,  U8TO32_LITTLE(m + 12)));
        U32TO8_LITTLE(c + 16, XOR(x4,  U8TO32_LITTLE(m + 16)));
        U32TO8_LITTLE(c + 20, XOR(x5,  U8TO32_LITTLE(m + 20)));
        U32TO8_LITTLE(c + 24, XOR(x6,  U8TO32_LITTLE(m + 24)));
        U32TO8_LITTLE(c + 28, XOR(x7,  U8TO32_LITTLE(m + 28)));
        U32TO8_LITTLE(c + 32, XOR(x8,  U8TO32_LITTLE(m + 32)));
        U32TO8_LITTLE(c + 36, XOR(x9,  U8TO32_LITTLE(m + 36)));
        U32TO8_LITTLE(c + 40, XOR(x10, U8TO32_LITTLE(m + 40)));
        U32TO8_LITTLE(c + 44, XOR(x11, U8TO32_LITTLE(m + 44)));
        U32TO8_LITTLE(c + 48, XOR(x12, U8TO32_LITTLE(m + 48)));
        U32TO8_LITTLE(c + 52, XOR(x13, U8TO32_LITTLE(m + 52)));
        U32TO8_LITTLE(c + 56, XOR(x14, U8TO32_LITTLE(m + 56)));
        U32TO8_LITTLE(c + 60, XOR(x15, U8TO32_LITTLE(m + 60)));

        /* Increment counter (64-bit). */
        j12 = PLUSONE(j12);
        if (!j12) j13 = PLUSONE(j13);

        if (bytes <= 64) {
            if (bytes < 64) {
                /* Copy from tmp to ctarget. */
                for (i = 0; i < bytes; ++i) ctarget[i] = tmp[i];
            }
            x->input[12] = j12;
            x->input[13] = j13;
            return;
        }
        bytes -= 64;
        m     += 64;
        c     += 64;
        out   += 64;
        (void)out;
    }
}
