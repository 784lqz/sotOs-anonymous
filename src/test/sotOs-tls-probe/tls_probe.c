/* sotOs · guest fixture · sotOs-tls-probe (sotNet γ-3-γ-2b).
 *
 * A sandboxed C TLS client: connect() to a non-local IP (→ auto-promoted to
 * Tier-2 · all socket I/O is redirected over the byte-pipe to the internal
 * responder), then drive a real TLS 1.2 handshake with a BearSSL br_ssl_client.
 * Exit proof: "[tls-probe] handshake OK · suite=0x...". Links BearSSL (guest
 * ABI) + the guest Alpine musl. No app-data exchange (that is γ-3-γ-2c). */
#include <bearssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "probe_ta.h"   /* TAS / TAS_LEN · pinned responder cert */

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { printf("[tls-probe] socket failed\n"); return 1; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(443);
    sa.sin_addr.s_addr = htonl(0xCB007107u);  /* 203.0.113.7 · non-local → Tier-2 redirect */
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        printf("[tls-probe] connect failed\n"); return 1;
    }
    printf("[tls-probe] connected · driving TLS 1.2 handshake over the byte-pipe\n");

    br_ssl_client_context cc;
    br_x509_minimal_context xc;
    static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
    br_ssl_client_init_full(&cc, &xc, TAS, TAS_LEN);
    /* No RTC · pin a validation time inside the cert window (same as the 2a
     * self-test · 2026-07-01 in days-since-year-0). */
    br_x509_minimal_set_time(&xc, 740163u, 0u);
    br_ssl_engine_set_buffer(&cc.eng, iobuf, sizeof iobuf, 1);
    /* Guest entropy: rdtsc jitter (honeypot · inject BEFORE reset). */
    unsigned char seed[32];
    { uint32_t lo, hi; volatile uint64_t acc = 0;
      for (int i = 0; i < 32; i++) {
        __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
        acc += ((uint64_t)hi << 32) | lo;
        seed[i] = (unsigned char)(lo ^ (acc >> (i & 7)) ^ (hi >> (i & 3)));
      } }
    br_ssl_engine_inject_entropy(&cc.eng, seed, sizeof seed);
    br_ssl_client_reset(&cc, "sotos-phantom", 0);

    /* Engine-level pump bound to the socket: move handshake records until the
     * engine reaches "ready to send app data" (handshake complete) or closes. */
    for (;;) {
        unsigned st = br_ssl_engine_current_state(&cc.eng);
        if (st & BR_SSL_CLOSED) break;
        if (st & BR_SSL_SENDAPP) break;          /* handshake complete */
        if (st & BR_SSL_SENDREC) {
            size_t len; unsigned char *buf = br_ssl_engine_sendrec_buf(&cc.eng, &len);
            int w = (int)send(fd, buf, len, 0);
            if (w <= 0) break;
            br_ssl_engine_sendrec_ack(&cc.eng, (size_t)w);
            continue;
        }
        if (st & BR_SSL_RECVREC) {
            size_t len; unsigned char *buf = br_ssl_engine_recvrec_buf(&cc.eng, &len);
            int r = (int)recv(fd, buf, len, 0);
            if (r <= 0) break;
            br_ssl_engine_recvrec_ack(&cc.eng, (size_t)r);
            continue;
        }
        break;  /* no progress */
    }

    int err = br_ssl_engine_last_error(&cc.eng);
    unsigned st = br_ssl_engine_current_state(&cc.eng);
    if (!((st & BR_SSL_SENDAPP) && err == 0)) {
        printf("[tls-probe] handshake FAILED · err=%d state=0x%x\n", err, st);
        return 1;
    }
    br_ssl_session_parameters sp;
    br_ssl_engine_get_session_parameters(&cc.eng, &sp);
    printf("[tls-probe] handshake OK · suite=0x%04x\n", (unsigned)sp.cipher_suite);

    /* γ-3-γ-2c · encrypted app-data round-trip over the established session.
     * Send a beacon, flush, then pump records (same blocking send()/recv() as
     * the handshake · they cross the byte-pipe to the responder) until the
     * responder's encrypted response_profile reply has been decrypted. */
    static const char beacon[] = "BEACON sotos-probe v1";
    {
        size_t off = 0, blen = sizeof(beacon) - 1;
        while (off < blen) {
            size_t wlen; unsigned char *wbuf = br_ssl_engine_sendapp_buf(&cc.eng, &wlen);
            if (!wbuf || wlen == 0) break;
            size_t n = (blen - off < wlen) ? (blen - off) : wlen;
            memcpy(wbuf, beacon + off, n);
            br_ssl_engine_sendapp_ack(&cc.eng, n);
            off += n;
        }
        br_ssl_engine_flush(&cc.eng, 0);
    }

    char got[64]; int gotlen = -1;
    for (;;) {
        unsigned s2 = br_ssl_engine_current_state(&cc.eng);
        if (s2 & BR_SSL_CLOSED) break;
        if (s2 & BR_SSL_RECVAPP) {                /* responder's decrypted reply */
            size_t len; unsigned char *abuf = br_ssl_engine_recvapp_buf(&cc.eng, &len);
            gotlen = (int)(len < sizeof(got) - 1 ? len : sizeof(got) - 1);
            memcpy(got, abuf, gotlen);
            got[gotlen] = '\0';
            br_ssl_engine_recvapp_ack(&cc.eng, len);
            break;
        }
        if (s2 & BR_SSL_SENDREC) {                /* push our encrypted beacon out first */
            size_t len; unsigned char *buf = br_ssl_engine_sendrec_buf(&cc.eng, &len);
            int w = (int)send(fd, buf, len, 0);
            if (w <= 0) break;
            br_ssl_engine_sendrec_ack(&cc.eng, (size_t)w);
            continue;
        }
        if (s2 & BR_SSL_RECVREC) {                /* pull the reply record (spin-yield EOF) */
            size_t len; unsigned char *buf = br_ssl_engine_recvrec_buf(&cc.eng, &len);
            int r = (int)recv(fd, buf, len, 0);
            if (r <= 0) break;
            br_ssl_engine_recvrec_ack(&cc.eng, (size_t)r);
            continue;
        }
        break;
    }

    if (gotlen > 0) {
        printf("[tls-probe] app-data OK · got '%s'\n", got);
        return 0;
    }
    printf("[tls-probe] app-data FAILED · state=0x%x err=%d\n",
           br_ssl_engine_current_state(&cc.eng), br_ssl_engine_last_error(&cc.eng));
    return 1;
}
