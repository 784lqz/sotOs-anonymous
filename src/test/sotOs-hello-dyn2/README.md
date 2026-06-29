# sotOs N3/D2 fixture — multi-lib dynamic binary

`hello_dyn2.bin` is a dynamically-linked musl PIE whose `DT_NEEDED` includes a
SEPARATE shared object, `libonefn.so` (exporting `d2_probe()`), beyond libc.
At runtime ld-musl `open()`+`mmap()`s `libonefn.so` (resolved via the `/lib` →
sysroot `/usr/lib` alias), relocates it, and the binary calls into it. Proves
the sotOs file-backed-mmap path. (musl has no separate libm.so — math is in
libc — so a custom one-function `.so` is the minimal real multi-lib test.)
Rebuild: `make -f Makefile.fixture MUSL_CROSS=/path/to/x86_64-linux-musl-cross`.
