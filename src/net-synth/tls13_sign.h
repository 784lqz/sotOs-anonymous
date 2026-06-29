#ifndef NET_SYNTH_TLS13_SIGN_H
#define NET_SYNTH_TLS13_SIGN_H
#include <stdint.h>
#include <stddef.h>
/* Sign the TLS 1.3 server CertificateVerify content for transcript hash
 * th[th_len].  The RSA-PSS scheme is selected by `sigalg`:
 *   0x0804 (rsa_pss_rsae_sha256): SHA-256, MGF1-SHA-256, sLen=32, th_len=32.
 *   0x0805 (rsa_pss_rsae_sha384): SHA-384, MGF1-SHA-384, sLen=48, th_len=48.
 * th_len MUST match the sigalg's hash size.  Writes the raw RSA signature (256B
 * for RSA-2048) to sig.  Returns sig length (256) on success, 0 on error.
 * rng_fill supplies the PSS salt (sLen bytes). */
size_t tls13_sign_certverify(uint16_t sigalg,
                             const uint8_t *th, size_t th_len,
                             uint8_t *sig, size_t sig_cap,
                             void (*rng_fill)(uint8_t*, size_t));
#endif
