# sotOs N3/D3 fixture — the OpenSSL bait

`hello_ssl.bin` is dynamically linked against **real OpenSSL** `libcrypto.so.3`
(4.48 MB, musl-built, from Alpine 3.20 / OpenSSL 3.3.7). It seeds the RNG
(`RAND_bytes`) and SHA-256s a known input, printing
`[hello-ssl] libcrypto OK 7ba514f8` (the first 4 bytes of SHA-256("sotos") are
deterministic → proves a *real* libcrypto digest ran, not a stub). This proves
sotOs hosts dynamically-linked-OpenSSL adversary tools, via the D3 **lazy
file-backed mmap** (eager seeding of a 4.5 MB 2-MiB-aligned `.so` would exhaust
the 16 MiB allocman pool). `RAND_bytes`/`EVP_*` live in libcrypto, so this first
gate is libcrypto-only; adding libssl (`SSL_CTX_new`) is a trivial follow-on.

**Build (host):**
1. `bash fetch-openssl.sh` — vendors `libcrypto.so.3` (+`libssl.so.3`) and the
   headers from an Alpine apk (needs internet · Alpine CDN).
2. `make -f Makefile.fixture` — builds `hello_ssl.bin`.

**Stub-link technique:** the musl-cross `ld` (binutils ~2.36) cannot read
Alpine's real `libcrypto.so.3` (`.relr.dyn` / RELR relocations), so `hello_ssl`
links against a tiny `stub_libcrypto.c` (SONAME `libcrypto.so.3`) and RUNS
against the real `libcrypto.so.3` (packed in the sysroot, resolved via the
`/lib`→`/usr/lib` alias). The stub is never loaded at runtime.
