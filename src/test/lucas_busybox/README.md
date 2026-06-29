# LucAs_busybox · L2 test fixture

`busybox-static.bin` is Alpine's prebuilt static x86_64 busybox
binary used as L2's test fixture. The LucAs layer must be able to
load and run it for `busybox ls /etc`, exercising the VFS backends
to emit fake content.

## Rebuild

On any Linux host:

```bash
curl -L https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox \
    -o busybox-static.bin
chmod +x busybox-static.bin
strip busybox-static.bin
```

## Why commit the binary

L2 needs a real Linux userland fixture to exercise the syscall
matrix. Committing the ~800 KB binary keeps the build self-contained;
when L5 introduces multiple identity profiles we may add other
fixtures here.

## Note · force-add to commit

`.bin` is gitignored at project root; commit with `git add -f`.
