# sotOs-egress-probe

N1a raw-syscall fixture proving REAL outbound wire egress from a Tier-0e sandbox.

Connects to `1.1.1.1:80`, sends a plain `GET / HTTP/1.0`, reads the real response,
and prints its first line. No DNS/TLS (N1b/N1c add those). Spawned Tier-0e +
trusted so its traffic bypasses the deception interception and hits the real wire
(captured in the QEMU `filter-dump` pcap).

Rebuild with:

```sh
make -f Makefile.fixture
```
