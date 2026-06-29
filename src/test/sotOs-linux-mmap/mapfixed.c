/* sotOs · Wine-prep gate fixture · the wine-preloader mmap PATTERN, decoupled.
 *
 * The wine-preloader RESERVES the Windows low address ranges (DOS area + ~1.7 GiB
 * low + a high top-down window) with large PROT_NONE MAP_FIXED mmaps BEFORE the PE
 * loader runs, so Win32 images land where they expect; then it COMMITs sub-ranges
 * (MAP_FIXED with real prot, or mprotect-to-accessible).  This fixture exercises
 * exactly that pattern (bounded sizes for a fast gate) so MAP_FIXED-low support
 * can be verified WITHOUT the whole Wine swamp.  Static musl · raw write() output.
 *
 * Build:  MUSL_CROSS=/tmp/x86_64-linux-musl-cross make -f Makefile.fixture
 */
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

static void emit(const char *s) { write(1, s, strlen(s)); }
static void emit_hex(unsigned long v) {
    char b[19]; b[0] = '0'; b[1] = 'x';
    const char *h = "0123456789abcdef";
    for (int i = 0; i < 16; i++) b[2 + i] = h[(v >> ((15 - i) * 4)) & 0xf];
    write(1, b, 18);
}
#define FAIL(msg) do { emit("[mapfixed] FAIL " msg "\n"); return 1; } while (0)

int main(void)
{
    emit("[mapfixed] start\n");

    /* 1) RESERVE a large PROT_NONE low range (mimic the preloader's ~1.7 GiB low
     *    reserve).  Sized to 1.25 GiB so the span CONTAINS LUCAS_MMAP_BASE
     *    (0x40000000) — that forces the non-fixed anon mmap in step 4 to be
     *    actively skipped PAST the reservation, genuinely exercising the high-
     *    water skip (a smaller reserve would sit below the base and never test it). */
    const uintptr_t LOW   = 0x110000UL;
    const size_t    LOWSZ = 0x50000000UL;   /* 1.25 GiB · contains 0x40000000 */
    void *r = mmap((void *)LOW, LOWSZ, PROT_NONE,
                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r == MAP_FAILED || (uintptr_t)r != LOW) FAIL("reserve-low");
    emit("[mapfixed] reserve-low OK @"); emit_hex((unsigned long)r);
    emit(" len="); emit_hex(LOWSZ); emit("\n");

    /* 2) COMMIT (MAP_FIXED, real prot) a RW window INSIDE the reservation; the
     *    backing must be allocated only for these pages, then write+read+verify. */
    uintptr_t C = LOW + 0x2000000UL;            /* 32 MiB into the reservation */
    void *c = mmap((void *)C, 0x4000, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (c == MAP_FAILED || (uintptr_t)c != C) FAIL("commit-fixed");
    volatile uint32_t *p = (uint32_t *)c;
    p[0] = 0xDEADBEEFu; p[1024] = 0x1234u;       /* first page + 4 KiB in */
    if (p[0] != 0xDEADBEEFu || p[1024] != 0x1234u) FAIL("commit-rw-verify");
    emit("[mapfixed] commit-fixed RW @"); emit_hex(C);
    emit(" val="); emit_hex(p[0]); emit(" OK\n");

    /* 3) COMMIT via mprotect-to-accessible on a DIFFERENT page still inside the
     *    PROT_NONE reservation (the reserve-then-mprotect-commit pattern). */
    uintptr_t M = LOW + 0x4000000UL;            /* 64 MiB into the reservation */
    if (mprotect((void *)M, 0x1000, PROT_READ | PROT_WRITE) != 0) FAIL("mprotect-commit");
    volatile uint32_t *q = (uint32_t *)M;
    q[0] = 0xCAFEF00Du;
    if (q[0] != 0xCAFEF00Du) FAIL("mprotect-verify");
    emit("[mapfixed] mprotect-commit @"); emit_hex(M);
    emit(" val="); emit_hex(q[0]); emit(" OK\n");

    /* 4) a NON-FIXED anon mmap MUST land OUTSIDE the reservation (the high-water
     *    allocator skips reserved Windows ranges). */
    void *o = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (o == MAP_FAILED) FAIL("anon-outside-map");
    uintptr_t ov = (uintptr_t)o;
    if (ov >= LOW && ov < LOW + LOWSZ) {
        emit("[mapfixed] FAIL anon landed INSIDE reservation @"); emit_hex(ov); emit("\n");
        return 1;
    }
    ((volatile uint32_t *)o)[0] = 0x5555u;
    emit("[mapfixed] anon-outside @"); emit_hex(ov); emit(" OK\n");

    /* 5) a DIRECT low MAP_FIXED commit at the DOS base (0x10000) — proves the
     *    loader can place images in the Windows low range at all. */
    void *d = mmap((void *)0x10000UL, 0x1000, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (d == MAP_FAILED || (uintptr_t)d != 0x10000UL) FAIL("dos-fixed");
    ((volatile uint32_t *)d)[0] = 0x0D05u;
    emit("[mapfixed] dos-fixed @0x10000 OK\n");

    emit("[mapfixed] ALL PASS\n");
    return 0;
}
