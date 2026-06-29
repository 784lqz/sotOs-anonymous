# LucAs_fork_test · L3a fork/wait4 fixture

Tiny static x86_64 binary that exercises fork+wait4.  Used by the
L3a milestone demo: parent forks, child writes "CHILD HERE" and
exits 42, parent wait4s + writes "PARENT here · child reaped" and
exits 0.

## Rebuild

```bash
gcc -no-pie -nostdlib -static -Wl,--build-id=none -o fork_test.bin fork_test.S
strip fork_test.bin
```

## Why commit the binary

The binary (~4.5 KiB stripped ET_EXEC) is committed so the seL4 CMake
build can embed it into orch's CPIO archive without requiring a host
gcc invocation during the cross-compile step.

## Expected output (inside QEMU via LucAs)

```
[fork] parent pid=1 → child pid=2 (slot=1)
[fork]   region TEXT+RODATA: ... pages copied
[fork]   region STACK: ... pages copied
[fork] child resumed · entering nested fault loop
CHILD HERE
[fork] child exited with code=42 · returning pid=2 to parent
PARENT here · child reaped
[LucAs] LucAs_sys_exit_group(0) · client terminating
[LucAs] L1 demo complete · final state code=0
```
