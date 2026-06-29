# LucAs_hello · L1 test fixture

`hello-linux.bin` is a pre-built static x86_64 Linux ELF used as the
test fixture for LucAs milestone L1. It calls only `write(1, ...)` and
`exit_group(0)`. The asm source is `hello.S`.

## Rebuild

On any Linux host with binutils and a recent gcc:

```bash
gcc -nostdlib -static -no-pie -o hello-linux.bin hello.S
strip hello-linux.bin
```

Verify on the host before re-committing:

```bash
./hello-linux.bin && echo "host OK"
```

## Why commit the binary

The build uses the host's gcc, which works fine for L1. Once LucAs
grows we may add a proper CMake `add_custom_command` driving an
external toolchain. For now, committing the ~5KB binary keeps the
build self-contained.
