# sotOs-wayland-connect

L12-beta raw-syscall fixture for the narrow Wayland AF_UNIX route.

It verifies two behaviors:

- `connect(AF_UNIX, "/run/user/1000/not-wayland")` is refused.
- `connect(AF_UNIX, "/run/user/1000/wayland-0")` succeeds once orch has an
  active Wayland compositor route.

Rebuild with:

```sh
make -f Makefile.fixture
```
