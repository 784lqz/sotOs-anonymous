# Vendored standard x86_64 musl (for the in-OS TinyCC `/usr` sysroot)

`lib/{libc.a, crt1.o, crti.o, crtn.o}` is a **standard x86_64 musl** used to link
hosted C programs that the in-OS TinyCC emits (`#include <stdio.h>` + `printf`,
linked against musl). It is baked into the sotfs.img `/usr/lib` sysroot region
`[60,76 MiB)` by `scripts/build-sysroot.sh` (wired in `src/CMakeLists.txt`).

## Why a separate musl (not the OS `musllibc`)

The OS's musl (`external/musllibc`, built with `ARCH=x86_64_sel4`) routes its
syscalls through a **sel4 `__sysinfo` shim** — `arch/x86_64_sel4/syscall_arch.h`
defines `CALL_SYSINFO(...) = (*__sysinfo)(...)`, and `__sysinfo` is filled by
`__init_libc` from `aux[AT_SYSINFO]`. That works for sotOs's own seL4-native
binaries (the seL4 runtime supplies the shim) but is **wrong for a LucAs Linux
guest**: a TinyCC-emitted ELF runs as a sotbox whose raw `syscall` instructions
LucAs traps, and the loader supplies no `AT_SYSINFO`, so `__sysinfo == 0` and the
program SIGSEGVs in `__init_tp` (`call *__sysinfo`). See
`memory/project_musl_set_thread_area`.

A standard x86_64 musl issues syscalls with the inline `syscall` instruction and
`__set_thread_area` via `arch_prctl(ARCH_SET_FS)` — exactly what a LucAs guest
needs (and exactly what the working `tcc.bin` / `python3.12-static` use).

## Provenance

Extracted from Alpine Linux `musl-dev` (the stock upstream musl static lib + crt
for x86_64) — the same musl family `tcc.bin` was built against:

```sh
podman run --rm -v "$PWD/src/test/musl-x86_64/lib:/out:Z" docker.io/library/alpine:latest sh -c '
  apk add --no-cache musl-dev
  cp /usr/lib/libc.a /usr/lib/crt1.o /usr/lib/crti.o /usr/lib/crtn.o /out/'
```

Verification (the load-bearing property):

```
$ objdump -d lib/libc.a | grep -A5 '<__set_thread_area>:'
__set_thread_area:
    mov %rdi,%rsi
    mov $0x1002,%edi      # ARCH_SET_FS
    mov $0x9e,%eax        # 158 = arch_prctl
    syscall               # inline · NO *__sysinfo
    ret
```

`include/` is the **complete installed** Alpine musl-dev header tree (`apk add
musl-dev; cp -a /usr/include/.`). The in-tree `external/musllibc/include` is the
musl *source* tree and is missing the build-time-generated `bits/alltypes.h`, so
`#include <stdio.h>` failed (`bits/alltypes.h not found`) when used for a hosted
compile. The installed Alpine set ships the generated `bits/alltypes.h` and is
self-consistent with this `libc.a`. So the whole `/usr` sysroot (headers + lib +
crt) is one standard Alpine musl — exactly what `tcc.bin` was built against — and
emitted hosted programs compile, link, and run on the LucAs ABI.
