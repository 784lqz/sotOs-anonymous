#!/usr/bin/env bash
# Fetch musl-built OpenSSL 3.3.7 (.so's + headers) from Alpine 3.20 for the D3
# fixture.  Outputs: ./libcrypto.so.3, ./libssl.so.3 (vendored next to this
# script) and /tmp/openssl-dev/include/openssl/* (headers · for building
# hello_ssl only, not vendored).  Needs host internet (Alpine CDN).
set -euo pipefail
DST="$(cd "$(dirname "$0")" && pwd)"   # capture BEFORE any cd (else $0 is relative)
B=https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64
W=/tmp/d3-openssl; mkdir -p "$W"; cd "$W"
for p in libcrypto3-3.3.7-r0 libssl3-3.3.7-r0 openssl-dev-3.3.7-r0; do
    [ -f "$p.apk" ] || wget -q -O "$p.apk" "$B/$p.apk"
done
rm -rf root && mkdir root && cd root
for p in libcrypto3-3.3.7-r0 libssl3-3.3.7-r0 openssl-dev-3.3.7-r0; do
    tar -xzf "../$p.apk" 2>/dev/null || true
done
cp -L lib/libcrypto.so.3 "$DST/libcrypto.so.3"
cp -L lib/libssl.so.3    "$DST/libssl.so.3"
rm -rf /tmp/openssl-dev && mkdir -p /tmp/openssl-dev && cp -a usr/include /tmp/openssl-dev/
echo "vendored: libcrypto.so.3 ($(stat -c%s "$DST/libcrypto.so.3") B) + libssl.so.3 ($(stat -c%s "$DST/libssl.so.3") B) · headers in /tmp/openssl-dev/include"
