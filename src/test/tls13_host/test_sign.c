/* test_sign.c — RSA-PSS CertificateVerify signing test (ε1 + ε3).
 * Emits N, E, CONTENT*, SIG*, SIGBAD* as hex to stdout for an INDEPENDENT
 * Python PSS verify (verify_sign.py) — the ζ lesson: do NOT self-verify.
 *
 *   ε1 (sigalg 0x0804): rsa_pss_rsae_sha256, sLen=32, 130-byte blob.
 *     labels CONTENT / SIG / SIGBAD.
 *   ε3 (sigalg 0x0805): rsa_pss_rsae_sha384, sLen=48, 146-byte blob (0x1302).
 *     labels CONTENT384 / SIG384 / SIGBAD384. */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <net-synth/tls_cert.h>
#include <net-synth/tls13_sign.h>

/* deterministic salt for reproducibility */
static void rng_fill_det(uint8_t *p, size_t n) { memset(p, 0x42, n); }

static void put_hex(const char *label, const uint8_t *b, size_t n)
{
    printf("%s ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* RFC 8446 §4.4.3 CertificateVerify content blob:
 * 64*0x20 || "TLS 1.3, server CertificateVerify" (33B) || 0x00 || th[th_len].
 * Returns the blob length (130 for th_len=32, 146 for th_len=48). */
static size_t build_content(uint8_t *content, const uint8_t *th, size_t th_len)
{
    static const char LABEL[] = "TLS 1.3, server CertificateVerify";
    memset(content, 0x20, 64);
    memcpy(content + 64, LABEL, 33);
    content[64 + 33] = 0x00;
    memcpy(content + 64 + 33 + 1, th, th_len);
    return 64 + 33 + 1 + th_len;
}

int main(void)
{
    put_hex("N", TA0_RSA_N, sizeof(TA0_RSA_N));
    put_hex("E", TA0_RSA_E, sizeof(TA0_RSA_E));

    /* ── ε1: SHA-256 / sigalg 0x0804 / 130-byte blob ───────────────────── */
    {
        uint8_t th[32];
        for (int i = 0; i < 32; i++) th[i] = (uint8_t)(i * 7 + 3);

        uint8_t content[64 + 33 + 1 + 32];
        size_t clen = build_content(content, th, 32);

        uint8_t sig[256];
        size_t sl = tls13_sign_certverify(0x0804, th, 32, sig, sizeof(sig),
                                          rng_fill_det);
        if (sl != 256) {
            fprintf(stderr, "sign(0x0804) FAILED (len=%zu)\n", sl);
            return 1;
        }

        put_hex("CONTENT", content, clen);
        put_hex("SIG", sig, sl);

        uint8_t sigbad[256];
        memcpy(sigbad, sig, sl);
        sigbad[sl - 1] ^= 0xff;
        put_hex("SIGBAD", sigbad, sl);
    }

    /* ── ε3: SHA-384 / sigalg 0x0805 / 146-byte blob (suite 0x1302) ─────── */
    {
        uint8_t th[48];
        for (int i = 0; i < 48; i++) th[i] = (uint8_t)(i * 11 + 5);

        uint8_t content[64 + 33 + 1 + 48];
        size_t clen = build_content(content, th, 48);

        uint8_t sig[256];
        size_t sl = tls13_sign_certverify(0x0805, th, 48, sig, sizeof(sig),
                                          rng_fill_det);
        if (sl != 256) {
            fprintf(stderr, "sign(0x0805) FAILED (len=%zu)\n", sl);
            return 1;
        }

        put_hex("CONTENT384", content, clen);
        put_hex("SIG384", sig, sl);

        uint8_t sigbad[256];
        memcpy(sigbad, sig, sl);
        sigbad[sl - 1] ^= 0xff;
        put_hex("SIGBAD384", sigbad, sl);
    }

    return 0;
}
