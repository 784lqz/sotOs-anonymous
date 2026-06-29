#include "tls_selftest.h"
#include "tls_rng.h"
#include <net-synth/tls_cert.h>
#include <bearssl.h>
#include <stdio.h>
#include <string.h>

/* Engine record buffers (BSS · ~33 KiB each · bidi). */
static unsigned char g_srv_iobuf[BR_SSL_BUFSIZE_BIDI];
static unsigned char g_cli_iobuf[BR_SSL_BUFSIZE_BIDI];

/* Move up to one buffer's worth of record bytes from `from` to `to`.
 * Returns the number of bytes moved (0 if nothing to move). */
static size_t pump_one(br_ssl_engine_context *from, br_ssl_engine_context *to) {
    size_t slen = 0, rlen = 0;
    unsigned char *sbuf = br_ssl_engine_sendrec_buf(from, &slen);
    if (slen == 0) return 0;
    unsigned char *rbuf = br_ssl_engine_recvrec_buf(to, &rlen);
    if (rlen == 0) return 0;
    size_t n = slen < rlen ? slen : rlen;
    memcpy(rbuf, sbuf, n);
    br_ssl_engine_recvrec_ack(to, n);
    br_ssl_engine_sendrec_ack(from, n);
    return n;
}

void tls_selftest_run(void) {
    static br_ssl_server_context sc;
    static br_ssl_client_context cc;
    static br_x509_minimal_context xc;
    uint8_t seed[32];

    /* Server: ECDHE-RSA · prefers AES-256-GCM-SHA384 (0xc030, Nginx-parity) with
     * AES-128-GCM-SHA256 (0xc02f) fallback. BearSSL's engine owns its HMAC-DRBG; there is
     * no OS seeder on this freestanding target, so inject entropy BEFORE reset
     * (reset generates the handshake random + the ECDHE ephemeral immediately and
     * would otherwise fail with NO_RANDOM). */
    br_ssl_server_init_mine2g(&sc, CHAIN, CHAIN_LEN, &SERVER_KEY);
    br_ssl_engine_set_buffer(&sc.eng, g_srv_iobuf, sizeof g_srv_iobuf, 1);
    tls_rng_fill(seed, sizeof seed);
    br_ssl_engine_inject_entropy(&sc.eng, seed, sizeof seed);
    br_ssl_server_reset(&sc);

    /* Client: validates the server's self-signed cert against the pinned TA.
     * No RTC on this target (BearSSL's time(NULL) returns ~1970, before the
     * cert's 2026 notBefore → spurious BR_ERR_X509_EXPIRED). Pin a fixed
     * validation time inside the cert window (2026-07-01 · days since year 0).
     * Keep within [notBefore, notAfter] if the cert is regenerated. */
    br_ssl_client_init_full(&cc, &xc, TAS, TAS_LEN);
    br_x509_minimal_set_time(&xc, 740163u, 0u);
    br_ssl_engine_set_buffer(&cc.eng, g_cli_iobuf, sizeof g_cli_iobuf, 1);
    tls_rng_fill(seed, sizeof seed);
    br_ssl_engine_inject_entropy(&cc.eng, seed, sizeof seed);
    br_ssl_client_reset(&cc, "sotos-phantom", 0);

    int done = 0, failed = 0;
    for (int i = 0; i < 64 && !done && !failed; i++) {
        pump_one(&cc.eng, &sc.eng);   /* client -> server */
        pump_one(&sc.eng, &cc.eng);   /* server -> client */
        if (br_ssl_engine_last_error(&sc.eng) != 0 ||
            br_ssl_engine_last_error(&cc.eng) != 0) { failed = 1; break; }
        unsigned sst = br_ssl_engine_current_state(&sc.eng);
        unsigned cst = br_ssl_engine_current_state(&cc.eng);
        if ((sst & BR_SSL_SENDAPP) && (cst & BR_SSL_SENDAPP)) { done = 1; }
    }

    if (done) {
        br_ssl_session_parameters sp;
        br_ssl_engine_get_session_parameters(&sc.eng, &sp);
        printf("[bearssl] self-handshake OK · suite=0x%04x\n",
               (unsigned)sp.cipher_suite);
    } else {
        printf("[bearssl] self-handshake FAILED · srv_err=%d cli_err=%d "
               "srv_state=0x%x cli_state=0x%x\n",
               br_ssl_engine_last_error(&sc.eng),
               br_ssl_engine_last_error(&cc.eng),
               (unsigned)br_ssl_engine_current_state(&sc.eng),
               (unsigned)br_ssl_engine_current_state(&cc.eng));
    }
}
