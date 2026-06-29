/* Link-time STUB for libcrypto.so.3.  The musl-cross toolchain's older ld
 * cannot read Alpine's real libcrypto.so.3 (.relr.dyn / RELR relocations), so
 * hello_ssl links against this stub (SONAME libcrypto.so.3) to record the
 * NEEDED entry + resolve the symbol names.  At RUNTIME ld-musl loads the REAL
 * libcrypto.so.3 (packed in the sysroot, resolved via /lib) which provides the
 * real implementations — this stub is never loaded.  Signatures are irrelevant
 * (dynamic symbols match by name); empty void fns just export the names. */
void RAND_bytes(void) {}
void EVP_MD_CTX_new(void) {}
void EVP_DigestInit_ex(void) {}
void EVP_sha256(void) {}
void EVP_DigestUpdate(void) {}
void EVP_DigestFinal_ex(void) {}
void EVP_MD_CTX_free(void) {}
