# Vendored TinyCC (prebuilt static binary)

This directory holds a **prebuilt, committed** static x86_64 Linux ELF of
TinyCC (TCC), embedded into the boot CPIO via the same pattern as
`syscall_test.bin` / `anomaly_test.bin`.

**The build does NOT compile TCC.**  The prebuilt binary (`tcc.bin`) is
committed and embedded as-is; this file is the provenance record and the
rebuild recipe.  The build never reads the TinyCC source tree — only the
committed `tcc.bin`.

## Upstream

- Repository: https://github.com/TinyCC/tinycc
- Exact commit built: `3b1fe97a596a7c69e693e962f4fe9b35128b68fd`
  (`mob` branch, 2026-05-23)

## Build recipe (musl / Alpine, fully static, non-PIE)

A fully static x86_64 ELF is the hard requirement.  Glibc static link is
not used (matches the project convention: the other static Linux fixtures
— Alpine busybox, python-build-standalone — are musl-based).  Build inside
an Alpine (musl) container so `-static` links cleanly with no dynamic deps:

```sh
podman run --rm -v "$PWD:/out:Z" docker.io/library/alpine:latest sh -c '
  apk add --no-cache git build-base
  cd /tmp
  # NOT --depth 1: a shallow clone only fetches branch HEAD, so the
  # git checkout <sha> below would fail once mob moves past it.
  git clone https://github.com/TinyCC/tinycc tinycc
  cd tinycc
  git checkout 3b1fe97a596a7c69e693e962f4fe9b35128b68fd
  ./configure --cpu=x86_64 \
      --extra-cflags="-static -fno-pie" \
      --extra-ldflags="-static -no-pie"
  make tcc -j4
  cp tcc /out/tcc.bin
'
strip tcc.bin   # on the host, after copying out
```

Notes:
- `-no-pie` / `-fno-pie` force a plain `EXEC` (non-PIE) static ELF.  A
  default musl build yields `static-pie` (`DYN` type), which needs
  load-time self-relocation; the non-PIE `EXEC` form matches
  `anomaly_test.bin` and is the safe form for the seL4 ELF loader.

## Verification (this committed binary, after strip)

```
$ file tcc.bin   # (a BuildID[sha1]=... field may also appear · it differs per build)
tcc.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

$ readelf -d tcc.bin | grep NEEDED || echo "OK: no dynamic NEEDED"
OK: no dynamic NEEDED

$ readelf -h tcc.bin | grep Type
  Type:  EXEC (Executable file)
```

- sha256 (stripped): `16bc7e77be3fe88692c3f4bf64d03711371b320586eb34d6d9d5fdb69b6a9e86`
- size (stripped): 423896 bytes (~414 KiB)

## `runmain.o` (SP1 PR 5 · `tcc -run` startup stub)

`tcc -run` ALWAYS links its `_runmain` entry stub (the object that calls
`main()` and forwards argc/argv) from `<tccdir>/runmain.o` — even for a
freestanding source compiled with `-nostdlib`.  The committed
`runmain.o` is that stub, built from the **same** pinned TinyCC commit as
`tcc.bin` (the full `make` target — `make tcc` alone does NOT build it).
PR 5 plants it into sotfs at `/runmain.o` (seen by the sotbox VFS as
`/tmp/runmain.o`) and invokes `tcc -B/tmp -nostdlib -run <src>` so the
trusted compiler sotbox finds it.  A freestanding raw-syscall program
needs NOTHING else — `libtcc1.a` is not pulled in under `-nostdlib`.

Rebuild recipe (same container as `tcc.bin`, but run the full `make`):

```sh
podman run --rm -v "$PWD:/out:Z" docker.io/library/alpine:latest sh -c '
  apk add --no-cache git build-base
  cd /tmp && git clone https://github.com/TinyCC/tinycc tinycc && cd tinycc
  git checkout 3b1fe97a596a7c69e693e962f4fe9b35128b68fd
  ./configure --cpu=x86_64 \
      --extra-cflags="-static -fno-pie" --extra-ldflags="-static -no-pie"
  make -j4                       # full build · produces runmain.o + libtcc1.a
  cp runmain.o /out/runmain.o
'
```

- sha256 (`runmain.o`): `5da06032125fcc06e4b740462eab26f8f47b76bc1730f6a7052c0994f5f4b5fd`
- size: 3494 bytes (7 sotfs blocks @ 512 B)
- `*.o` is gitignored project-wide; `runmain.o` is exempted via a `!`
  negation rule in the top-level `.gitignore`.

## `libtcc1.a` (tcc-libc · TinyCC runtime helper lib for hosted linking)

When `tcc -o out.elf src.c` links a **hosted** musl program (no
`-nostdlib`), TinyCC pulls in its compiler-runtime helpers — the 64-bit
integer/float helpers (`__divdi3`, `__moddi3`, `__floatundisf`, …), the
soft-float/`alloca`/`va_list`/atomic stubs — from `<tccdir>/libtcc1.a`.
The freestanding `-nostdlib -run` path of SP1 never needed it; the hosted
milestone (tcc-libc PR7) does, so `libtcc1.a` is baked into the `/usr/lib`
sysroot (`-B/usr/lib`).  It is built from the **same** pinned TinyCC commit
as `tcc.bin` / `runmain.o` (the full `make` target produces it).

Rebuild recipe (same Alpine/musl container as `tcc.bin`, full `make`):

```sh
podman run --rm -v "$PWD/src/test/tcc-bin:/out:Z" docker.io/library/alpine:latest sh -c '
  apk add --no-cache git build-base
  cd /tmp && git clone https://github.com/TinyCC/tinycc tinycc && cd tinycc
  git checkout 3b1fe97a596a7c69e693e962f4fe9b35128b68fd
  ./configure --cpu=x86_64 \
      --extra-cflags="-static -fno-pie" --extra-ldflags="-static -no-pie"
  make -j4                       # full build · produces libtcc1.a (+ runmain.o)
  cp libtcc1.a /out/libtcc1.a
'
```

- sha256 (`libtcc1.a`): `a3cf4af6b049c3bef107a9012065cf0fb8bb26ec2345352321a82c8e3fe5033b`
- size: 50614 bytes (~50 KiB)
- members: `libtcc1.o stdatomic.o atomic.o builtin.o alloca.o alloca-bt.o
  tcov.o va_list.o dsohandle.o` (each `ELF 64-bit LSB relocatable, x86-64`).
- `*.a` is gitignored project-wide; `libtcc1.a` is exempted via a `!`
  negation rule in the top-level `.gitignore` (next to `runmain.o`).

Note: the full `make` errors out later on `bcheck.o`
(`__ctype_b_loc` is glibc-only; the musl/Alpine toolchain lacks it), but
that object is the **bounds-checker** stub (`-b` mode), which is NOT a
member of `libtcc1.a` — it is archived separately into `libtcc1-bt.a`,
which the hosted (non-bounds-checked) link does not use.  `libtcc1.a` is
fully assembled by the `tcc -ar rcs ../libtcc1.a …` step that runs *before*
the `bcheck.o` failure, so the committed archive is complete and valid.

## CPIO embedding

`tcc.bin` is added to `ORCH_CHILD_BINS` and the `MakeCPIO` list in
`src/orch/CMakeLists.txt`.  `MakeCPIO` names each entry by its file
**basename**, so the CPIO archive entry is **`tcc.bin`** (later PRs that
look it up via `cpio_get_file` must use that exact name).

No runtime use yet — the `tcc` command and exec-mapping support land in
PR 3-4 of the SP1 arc.
