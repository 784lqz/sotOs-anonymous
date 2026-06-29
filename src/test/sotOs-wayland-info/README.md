# sotOs-wayland-info

L12-delta raw-syscall fixture for `wl_registry` global enumeration + bind.

It connects to `/run/user/1000/wayland-0`, sends `wl_display.get_registry`,
asserts the reply is a byte-exact `wl_registry.global` for `wl_compositor`
(name 1, version 4) followed by one for `wl_shm` (name 2, version 1), then sends
`wl_registry.bind` for `wl_compositor` and asserts the write succeeded.

Rebuild with:

```sh
make -f Makefile.fixture
```
