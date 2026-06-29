/* sotOs · net-synth · entropy for the TLS engine (sotNet γ-3-γ-2).
 * HONEYPOT entropy: rdtsc jitter. NOT a security boundary — sufficient for a
 * contained-sample threat model. BearSSL's engine owns its own HMAC-DRBG; this
 * just fills the initial-entropy buffer fed to br_ssl_engine_inject_entropy().
 * TPM-RNG top-up (OBSD-η) is a future enhancement, not in 2a. */
#ifndef NET_SYNTH_TLS_RNG_H
#define NET_SYNTH_TLS_RNG_H
#include <stddef.h>
#include <stdint.h>
/* Fill `buf[0..len)` with rdtsc-jitter entropy. */
void tls_rng_fill(uint8_t *buf, size_t len);
#endif /* NET_SYNTH_TLS_RNG_H */
