# sotOs-real-vfs · Gate E fixture

End-to-end proof that the baked `/usr` sysroot serves a **real recursive musl
lib tree with symlinks**, so dynamic binaries resolve their `.so`s with no
per-lib special-casing.

- `libvfsprobe.c` → `libvfsprobe.so.1` — a tiny real shared object exporting
  `vfs_probe()` (returns `0x5A`).
- `vfsprobe.c` → `vfsprobe.bin` — a dynamic PIE whose `DT_NEEDED` is
  **`libvfsprobe.so`** (the SONAME *symlink* → `libvfsprobe.so.1`, deliberately
  unset SONAME so the link name is recorded). At runtime ld-musl must follow
  the sysroot symlink to load it. It then:
  1. calls `vfs_probe()` → `[real-vfs] symlink-so OK`
  2. `openat`/`fstat`/`read`/`lseek`/`mmap` on `/usr/lib/crt1.o` →
     `[real-vfs] fstat OK` / `read+lseek OK` / `mmap OK`
  3. `getdents64` over `/usr/lib` (must list `libvfsprobe.so.1`) →
     `[real-vfs] getdents OK`

The committed lib subtree the packer walks lives in `src/test/sysroot-lib/`
(the `libvfsprobe.so` → `libvfsprobe.so.1` git-tracked symlink + a `probe-sub/`
subdir). CMake stages it with `cp -a` (preserving the symlink as a LNK entry)
into the sysroot region.

## Build (prebuilt `.bin` + `.so.1` are committed)

Host musl-cross (musl.cc):

```sh
export MUSL_CROSS=/path/to/x86_64-linux-musl-cross
cd src/test/sotOs-real-vfs && make -f Makefile.fixture
```

Verify `readelf -d vfsprobe.bin | grep NEEDED` shows `libvfsprobe.so` (the
link, not `.so.1`), confirming the runtime symlink-follow path is exercised.

## Gate

```sh
bash tools/real-vfs-gate.sh /tmp/real-vfs.log   # asserts the five markers
```

`real-vfs` is wired as a sotShell command and runs early in `demo_commands[]`
so the markers appear within a headless boot window.
