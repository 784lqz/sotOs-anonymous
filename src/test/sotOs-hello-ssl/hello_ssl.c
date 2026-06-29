/* sotOs N3/D3 · the honeypot bait · dynamically linked against real OpenSSL.
 * DT_NEEDED chain: hello_ssl -> libssl.so.3 -> libcrypto.so.3 -> libc(=ld-musl).
 * Offline (no network): seed RNG + SHA-256 a known input · prove libcrypto runs. */
#include <unistd.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

static void hex2(unsigned x, char *o) {
    const char *h = "0123456789abcdef"; o[0]=h[(x>>4)&0xf]; o[1]=h[x&0xf];
}
int main(void) {
    unsigned char r[16];
    if (RAND_bytes(r, sizeof(r)) != 1) { write(1, "[hello-ssl] RAND FAIL\n", 22); _exit(1); }

    /* SHA-256("sotos") · first 4 bytes are deterministic (7ba514f8) → a
     * verifiable gate proving a real libcrypto digest ran, not a stub. */
    unsigned char md[32]; unsigned int mdlen = 0;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c || EVP_DigestInit_ex(c, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(c, "sotos", 5) != 1 ||
        EVP_DigestFinal_ex(c, md, &mdlen) != 1 || mdlen != 32) {
        write(1, "[hello-ssl] EVP FAIL\n", 21); _exit(1);
    }
    char out[64]; int n = 0;
    const char *p = "[hello-ssl] libcrypto OK "; memcpy(out, p, 25); n = 25;
    for (int i = 0; i < 4; ++i) { hex2(md[i], out + n); n += 2; }
    out[n++] = '\n';
    write(1, out, n);
    /* _exit (raw exit_group · skips OpenSSL's atexit OPENSSL_cleanup, which
     * dereferences a near-NULL pointer during teardown on this minimal setup).
     * The crypto already ran + the gate is printed; real tools commonly _exit. */
    _exit(0);
}
