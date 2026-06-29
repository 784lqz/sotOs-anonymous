# sotOs-openssl · real Alpine OpenSSL 3.3.7 CLI (egress TLS client)

The real off-the-shelf OpenSSL `s_client` that busybox `wget https://…` spawns as
its TLS helper at FUNCTOR_TIER_EGRESS (Tier-0e).  Not built here — extracted
verbatim from Alpine so the egress path runs an unmodified, real TLS stack.

## Provenance

```sh
# host has IP egress but a broken host DNS resolver → pin a public nameserver:
podman run --rm --dns=1.1.1.1 alpine sh -c 'apk add --no-cache openssl >/dev/null 2>&1; \
  cat /usr/bin/openssl' > bin/openssl
podman run --rm --dns=1.1.1.1 alpine sh -c 'apk add --no-cache openssl >/dev/null 2>&1; \
  cat /usr/lib/libssl.so.3' > lib/libssl.so.3
chmod +x bin/openssl lib/libssl.so.3
```

- `bin/openssl`     — Alpine OpenSSL 3.3.7, musl-dynamic PIE, interp /lib/ld-musl-x86_64.so.1.
- `lib/libssl.so.3` — its libssl (libcrypto.so.3 + ld-musl are already staged for the
  N3/D3 OpenSSL bait, see src/test/sotOs-hello-ssl/).

## Wiring (src/CMakeLists.txt)

- `bin/openssl` → the binstore (execve target `/usr/local/sbin/openssl`, resolved by
  the shebang/PATH access stubs in src/lucas/backends_static.c).
- `lib/libssl.so.3` → the sysroot /usr/lib closure (ld-musl resolves it by soname).

The binstore header grew 4 KiB→8 KiB (51→64 entries) to fit openssl as the 52nd
binary — see include/sotfs/binstore.h and scripts/build-binstore.sh.
