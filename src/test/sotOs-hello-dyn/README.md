# sotOs-hello-dyn  (N3 / D1)

The first DYNAMICALLY-linked test binary for the dynamic-linker arc. `hello_dyn.bin`
is a trivial `write("...")` linked dynamically against musl (INTERP =
`/lib/ld-musl-x86_64.so.1`, DT_NEEDED = `libc.so`). For musl the interpreter IS
libc — a single file `ld-musl-x86_64.so.1` (here, the Alpine/musl-cross `libc.so`,
~733 KB, ET_DYN PIE, 2 PT_LOAD segments: R-X text ~600KB + RW data).

`ld-musl-x86_64.so.1` is the vendored dynamic runtime; the image must expose it at
`/lib/ld-musl-x86_64.so.1` so the loader can load it as the interp.

Built with the musl-cross toolchain (musl.cc). Rebuild: `MUSL_CROSS=… make -f Makefile.fixture`.
