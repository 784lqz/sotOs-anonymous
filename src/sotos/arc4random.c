/*	$OpenBSD: arc4random.c,v 1.58 2022/07/31 13:41:45 tb Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Vendored into sotOs 2026-05-22.
 *
 * Simplifications vs. upstream OpenBSD:
 *   - No per-thread state (single-threaded orch; no pthreads).
 *   - No rekey-on-fork via MAP_INHERIT_ZERO (orch controls fork).
 *   - No /dev/urandom fallback; seed is supplied explicitly via
 *     sotos_arc4random_init().  Caller MUST seed before consuming.
 *   - No automatic rekey after 1.6 MB output (TODO: sotFS-η-grade rekey).
 *   - Uses __builtin_memcpy / __builtin_memset to avoid libc dependency.
 */

#include <sotos/random.h>
#include "chacha_private.h"

#define KEYSZ   32
#define IVSZ     8
#define BLOCKSZ 64
/* sotOs L4: 4 * BLOCKSZ = 256 bytes.  Keeps BSS footprint minimal while
 * still amortising chacha_encrypt_bytes() calls.  Upstream OpenBSD uses
 * 16 * BLOCKSZ (1024 bytes); increase when sotFS-η rekey lands. */
#define RSBUFSZ (4 * BLOCKSZ)   /* 256 bytes per refill */

/* Static state — single-threaded orch, no locks needed. */
static int           rs_initialized;
static chacha_ctx    rs;
static uint8_t       rs_buf[RSBUFSZ];
static size_t        rs_have;   /* bytes available in rs_buf */
static size_t        rs_count;  /* bytes generated since last rekey */

static void
_rs_rekey(const uint8_t *dat, size_t datlen)
{
    /* Fill rs_buf with new keystream, then use first KEYSZ+IVSZ bytes
     * as the new key+iv.  Any caller-supplied dat is XOR'd in. */
    uint8_t rsbuf_backup[RSBUFSZ];
    __builtin_memset(rsbuf_backup, 0, sizeof(rsbuf_backup));

    /* Generate new keystream block. */
    chacha_encrypt_bytes(&rs, rsbuf_backup, rs_buf, sizeof(rs_buf));

    /* XOR in any additional seed data. */
    if (dat) {
        size_t i, m;
        m = datlen < KEYSZ + IVSZ ? datlen : KEYSZ + IVSZ;
        for (i = 0; i < m; i++)
            rs_buf[i] ^= dat[i];
    }

    /* Rekey with the first KEYSZ bytes, re-iv with the next IVSZ bytes. */
    chacha_keysetup(&rs, rs_buf, KEYSZ * 8);
    chacha_ivsetup(&rs, rs_buf + KEYSZ, (void *)0);

    /* Wipe and skip the key material we just consumed. */
    __builtin_memset(rs_buf, 0, KEYSZ + IVSZ);
    rs_have  = sizeof(rs_buf) - (KEYSZ + IVSZ);
    rs_count = 0;
}

static void
_rs_stir(const uint8_t *buf, size_t n)
{
    _rs_rekey(buf, n);
    /* Invalidate rs_buf after rekey. */
    rs_have = 0;
    __builtin_memset(rs_buf, 0, sizeof(rs_buf));
}

static void
_rs_stir_if_needed(size_t len)
{
    /* TODO (sotFS-η): rekey every 1.6 MB to limit key exposure.
     * For L4-grade single-boot orch, one-time seed is sufficient. */
    (void)len;
}

static void
_rs_random_buf(void *_buf, size_t n)
{
    uint8_t *buf = (uint8_t *)_buf;
    size_t m;

    _rs_stir_if_needed(n);

    while (n > 0) {
        if (rs_have > 0) {
            m = n < rs_have ? n : rs_have;
            __builtin_memcpy(buf, rs_buf + sizeof(rs_buf) - rs_have, m);
            __builtin_memset(rs_buf + sizeof(rs_buf) - rs_have, 0, m);
            buf     += m;
            n       -= m;
            rs_have -= m;
            rs_count += m;
        }
        if (rs_have == 0) {
            uint8_t zero[RSBUFSZ];
            __builtin_memset(zero, 0, sizeof(zero));
            chacha_encrypt_bytes(&rs, zero, rs_buf, sizeof(rs_buf));
            rs_have  = sizeof(rs_buf);
        }
    }
}

static uint32_t
_rs_random_u32(void)
{
    uint32_t val;
    _rs_random_buf(&val, sizeof(val));
    return val;
}

/*
 * sotos_arc4random_init — one-time seed.
 *
 * seed must have at least 40 bytes (32 key + 8 nonce).
 * If seed_len < 40, the remainder is treated as zero.
 */
void
sotos_arc4random_init(const uint8_t *seed, size_t seed_len)
{
    uint8_t keybuf[KEYSZ + IVSZ];
    __builtin_memset(keybuf, 0, sizeof(keybuf));

    size_t copy = seed_len < sizeof(keybuf) ? seed_len : sizeof(keybuf);
    __builtin_memcpy(keybuf, seed, copy);

    /* Bootstrap chacha state with an all-zero starting key+iv,
     * then immediately rekey with the provided seed material. */
    uint8_t zero_key[KEYSZ] = {0};
    uint8_t zero_iv[IVSZ]   = {0};
    chacha_keysetup(&rs, zero_key, KEYSZ * 8);
    chacha_ivsetup(&rs, zero_iv, (void *)0);

    rs_have  = 0;
    rs_count = 0;

    _rs_stir(keybuf, sizeof(keybuf));

    /* Wipe local copy of key material. */
    __builtin_memset(keybuf, 0, sizeof(keybuf));

    rs_initialized = 1;
}

uint32_t
sotos_arc4random(void)
{
    return _rs_random_u32();
}

void
sotos_arc4random_buf(void *buf, size_t n)
{
    _rs_random_buf(buf, n);
}

/*
 * sotos_arc4random_uniform — uniform distribution in [0, upper_bound).
 *
 * Uses rejection sampling to avoid modulo bias.
 * Follows the algorithm from OpenBSD arc4random_uniform.
 */
uint32_t
sotos_arc4random_uniform(uint32_t upper_bound)
{
    uint32_t r, min;

    if (upper_bound < 2)
        return 0;

    /* Calculate (2^32 % upper_bound) as 2^32 - upper_bound to avoid
     * 64-bit arithmetic on targets that lack it. */
    min = (uint32_t)(-(int32_t)upper_bound % (int32_t)upper_bound);

    /* Rejection loop: discard values in [0, min) to remove bias. */
    for (;;) {
        r = _rs_random_u32();
        if (r >= min)
            break;
    }

    return r % upper_bound;
}
