# sotOs-tls-probe

Guest fixture for sotNet γ-3-γ-2b: a sandboxed C TLS client (BearSSL
`br_ssl_client`) that connects to a redirected IP and completes a TLS 1.2
handshake against the internal responder, every byte crossing the byte-pipe.

The fixture drives a real `br_ssl_client`: handshake (γ-3-γ-2b) then an
encrypted app-data round-trip (γ-3-γ-2c) — it sends the beacon
`"BEACON sotos-probe v1"`, then decrypts + verifies the responder's encrypted
response_profile reply. Proofs: `[tls-probe] handshake OK · suite=0x...` then
`[tls-probe] app-data OK · got '...'`.

The `.bin` is **pre-built on a Linux host and committed** (CMake does not compile
it). It links BearSSL (`external/bearssl/src`, portable constant-time paths) +
the guest Alpine musl (`src/test/musl-x86_64`, inline-syscall libc), so it is a
raw-syscall static x86_64 ELF that runs both as a LucAs guest and natively on the
host (Stage 1).

Rebuild:

```sh
make -f Makefile.fixture   # → tls_probe.bin
./tls_probe.bin            # Stage-1 smoke runs natively
```
