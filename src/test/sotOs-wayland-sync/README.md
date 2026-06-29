# sotOs-wayland-sync

L12-gamma raw-syscall fixture for the minimal `wl_display.sync` round trip.

It connects to `/run/user/1000/wayland-0`, writes a real Wayland
`wl_display.sync(new_id=2)` request, reads the reply, and asserts it is a
byte-exact `wl_callback.done` on the callback object (id=2, opcode=0) followed by
`wl_display.delete_id(id=1, opcode=1, arg=2)`.

Rebuild with:

```sh
make -f Makefile.fixture
```
