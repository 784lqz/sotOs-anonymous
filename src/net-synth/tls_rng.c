#include "tls_rng.h"

static inline uint64_t rdtsc_(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void tls_rng_fill(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return;
    for (size_t i = 0; i < len; i++) buf[i] = 0;
    volatile uint64_t acc = 0;
    /* Fold rdtsc samples into the buffer, with variable-length busy-work
     * between reads so the low bits decorrelate. HONEYPOT entropy. */
    for (size_t k = 0; k < len + 16; k++) {
        uint64_t t = rdtsc_();
        acc += t * 1000003u + 1u;
        buf[k % len] ^= (uint8_t)(t ^ (t >> 11) ^ (t >> 23) ^ (acc >> (k & 7)));
        for (volatile int j = 0; j < (int)(t & 0x3F); j++) { acc ^= (uint64_t)j; }
    }
}
