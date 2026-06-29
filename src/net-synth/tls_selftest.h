/* sotOs · net-synth · γ-3-γ-2a · in-process TLS 1.2 loopback self-handshake.
 * Proves BearSSL's engine + cert + RNG run on-target, with no transport. */
#ifndef NET_SYNTH_TLS_SELFTEST_H
#define NET_SYNTH_TLS_SELFTEST_H
/* Run once at startup. Logs '[bearssl] self-handshake OK · suite=0x%04x' on
 * success, or a FAILED line otherwise. Non-fatal (never blocks boot). */
void tls_selftest_run(void);
#endif /* NET_SYNTH_TLS_SELFTEST_H */
