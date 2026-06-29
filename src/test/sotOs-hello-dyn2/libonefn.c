/* sotOs N3/D2 fixture · a REAL separate shared object (ET_DYN) that ld-musl
 * must open()+mmap() at runtime.  Exports one function; the writable global
 * forces a RW PT_LOAD distinct from the R-X text PT_LOAD (so the file-backed
 * mmap path exercises both a PROT_READ|EXEC and a PROT_READ|WRITE mapping). */
volatile int d2_state = 0x0D2;
int d2_probe(void) { return d2_state; }
