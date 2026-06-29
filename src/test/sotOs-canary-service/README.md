# sotOs-canary-service

sottrace-v1 (T10) raw-syscall canary-service fixture: a benign listen/accept/recv
sotbox that an inbound connection talks to.

Calls `socket(AF_INET)` / `bind(:80)` (no-op stub) / `listen` / prints
`[canary-svc] listening :80`, then `accept()` (PARKS via the T7 accept park/wake
until an inbound connection completes, woken by the T3 NBRecv liveness poll),
`recv()`s the request printing `[canary-svc] rx <n>`, sends a small canned canary
banner once, then `close()` + `[canary-svc] conn done`. No DNS/TLS, libc-free.
Spawned Tier-0e + trusted + PLEDGE_ALL via the `canary-service` shell command.

Drive a real inbound connection with `just run-honeypot` (adds QEMU hostfwd
`tcp::18080-:80`) then `nc 127.0.0.1 18080`.

Rebuild with:

```sh
make -f Makefile.fixture
```
