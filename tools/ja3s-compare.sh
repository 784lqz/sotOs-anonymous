#!/usr/bin/env bash
# JA3S compare — sotOs vs an ephemeral real Nginx (pinned to TLS1.2/ECDHE-RSA).
# Requires: a sotOs capture already at /tmp/honeypot.pcap (just run-honeypot-pcap +
# a ncat --ssl handshake), podman|docker, openssl, python3. No host tcpdump/sudo.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SOTOS_PCAP="${1:-/tmp/honeypot.pcap}"
NGINX_PCAP="/tmp/nginx-ref.pcap"
WORK="$(mktemp -d)"
ENGINE="$(command -v podman || command -v docker)"
[ -n "$ENGINE" ] || { echo "error: neither podman nor docker found on PATH" >&2; exit 1; }
NAME="ja3s-nginx-ref"
SNIFF="ja3s-sniffer"
CLIENT="ja3s-client"

cleanup() {
    # Remove the netns *sharers* (sniffer/client) before the netns *owner* (nginx);
    # podman refuses to remove a container whose netns another still joins.
    "$ENGINE" rm -f "$SNIFF" "$CLIENT" >/dev/null 2>&1
    "$ENGINE" rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

# 1. self-signed cert + a TLS1.2-pinned, ECDHE-RSA-only server block
openssl req -x509 -nodes -newkey rsa:2048 -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
    -days 1 -subj "/CN=nginx-ref" >/dev/null 2>&1
cat > "$WORK/nginx.conf" <<'EOF'
events {}
http {
    server {
        listen 443 ssl;
        ssl_protocols TLSv1.2;                          # pin so the suite is comparable to BearSSL
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;        # same suite sotOs now serves (0xc02f)
        ssl_certificate     /etc/nginx/c.pem;
        ssl_certificate_key /etc/nginx/k.pem;
        location / { return 200 "ref\n"; }
    }
}
EOF

# 2. start nginx — NO host port publish. Rootless podman's port-forwarder (pasta)
#    mangles the TLS handshake through a published port ("unexpected eof"), so we
#    drive the client INSIDE the netns instead (step 3c), where the server is :443.
"$ENGINE" run -d --replace --name "$NAME" \
    -v "$WORK/nginx.conf:/etc/nginx/nginx.conf:ro,Z" \
    -v "$WORK/c.pem:/etc/nginx/c.pem:ro,Z" \
    -v "$WORK/k.pem:/etc/nginx/k.pem:ro,Z" \
    nginx:alpine >/dev/null
sleep 3

# 3a. capture INSIDE the nginx netns (CAP_NET_RAW from the runtime, server on :443)
"$ENGINE" run -d --replace --name "$SNIFF" --net "container:$NAME" --cap-add NET_RAW \
    -v "$WORK:/cap:Z" alpine:latest \
    sh -c "apk add -q --no-cache tcpdump && tcpdump -i any -s0 -U -w /cap/nginx-ref.pcap 'tcp port 443'" >/dev/null
sleep 5   # 3b. let apk add tcpdump + the capture come up
# 3c. drive the TLS client from INSIDE the same netns to 127.0.0.1:443
"$ENGINE" run --rm --name "$CLIENT" --net "container:$NAME" alpine:latest \
    sh -c "apk add -q --no-cache openssl >/dev/null 2>&1; echo Q | openssl s_client -connect 127.0.0.1:443 -tls1_2 >/dev/null 2>&1 || true"
sleep 1
"$ENGINE" stop -t1 "$SNIFF" >/dev/null 2>&1
cp "$WORK/nginx-ref.pcap" "$NGINX_PCAP" 2>/dev/null || true

# 4. parse both with the SAME parser; the server is :443 in BOTH captures.
echo "=== sotOs ==="
JA3S_SERVER_PORT=443 python3 "$HERE/ja3s.py" "$SOTOS_PCAP"
echo "=== nginx (ref · TLS1.2) ==="
JA3S_SERVER_PORT=443 python3 "$HERE/ja3s.py" "$NGINX_PCAP"
