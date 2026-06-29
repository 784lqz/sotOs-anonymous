/* sotOs apk-fs slice-2 · a SEPARATE shared object (ET_DYN) that exists ONLY in
 * the per-session upper at runtime — NOT baked into the sysroot.  Proves ld-musl
 * open()+mmap()s a NEEDED .so from the session upper (the libncursesw.so.6 case).
 * A writable global forces a RW PT_LOAD distinct from the R-X text PT_LOAD (so
 * the file-backed mmap path exercises both a PROT_READ|EXEC and a
 * PROT_READ|WRITE mapping). */
volatile int spk_state = 0x5DC;
int spk_probe(void) { return spk_state; }
