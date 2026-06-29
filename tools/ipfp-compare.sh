#!/usr/bin/env bash
# arc β · capture a REAL Linux's ICMP echo-reply + closed-port RST IP/TCP fields
# as the fingerprint target (don't-guess). Best-effort: needs rootless podman.
# Mirrors tools/tcpfp-compare.sh's netns + tcpdump-sidecar pattern.
set -u
REF=/tmp/linux-ipfp.pcap
NET=ipfpref
podman rm -f ipfp-srv ipfp-cap >/dev/null 2>&1
podman network rm "$NET" >/dev/null 2>&1
podman network create "$NET" >/dev/null 2>&1 || { echo "[ipfp-compare] no podman netns — SKIP"; exit 0; }
# Reference host: alpine (modern musl/kernel, matches the α nginx:alpine profile).
podman run -d --name ipfp-srv --network "$NET" alpine:3.19 sleep 60 >/dev/null 2>&1 \
    || { echo "[ipfp-compare] no alpine image — SKIP"; exit 0; }
SRVIP=$(podman inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ipfp-srv)
# tcpdump sidecar sharing the server's netns (CAP_NET_RAW).
podman run -d --name ipfp-cap --network "container:ipfp-srv" --cap-add NET_RAW \
    alpine:3.19 sh -c "apk add -q tcpdump >/dev/null 2>&1; tcpdump -i any -w /cap.pcap -c 20 2>/dev/null" >/dev/null 2>&1
sleep 2
# Drive: ping (ICMP echo) + a connect to a CLOSED port (RST) from a client in the same net.
podman run --rm --network "$NET" alpine:3.19 sh -c "ping -c2 $SRVIP >/dev/null 2>&1; (echo | nc -w1 $SRVIP 9 >/dev/null 2>&1 || true)" >/dev/null 2>&1
sleep 2
podman cp ipfp-cap:/cap.pcap "$REF" 2>/dev/null || { echo "[ipfp-compare] capture copy failed — SKIP"; podman rm -f ipfp-srv ipfp-cap >/dev/null 2>&1; exit 0; }
podman rm -f ipfp-srv ipfp-cap >/dev/null 2>&1
podman network rm "$NET" >/dev/null 2>&1
echo "[ipfp-compare] reference capture: $REF"
python3 tools/ipfp.py "$REF"
