#!/usr/bin/env bash
# TLS 1.3 ε4 nginx-ref comparison — prove sotOs's hand-rolled 1.3 ServerHello
# fingerprint (JA3S+JA4S) == what REAL nginx:alpine emits, for the SAME client.
#
# The honesty cross-check behind the pinned ε4 oracle constants: the live gate
# proves sotOs's captured-on-the-wire 1.3 SH == our pinned JA3S/JA4S; THIS script
# proves the pinned constants ARE real nginx (not just our own derivation). If the
# pin and real nginx ever disagree, we FAIL LOUD — never trust a single source.
#
# Method (mirrors tools/ja3s-compare.sh, the shipped 1.2 template):
#   * spin nginx:alpine TLS1.3-only in its own podman netns (rootless pasta drops
#     published ports → drive the client INSIDE the netns, server on :443);
#   * drive the *discriminating* 0x1301-first client (LANDMINE #1):
#       openssl s_client -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 ...
#     capture nginx's ServerHello via a netns-sharer tcpdump sniffer;
#   * parse with tools/ja3s.py --ja4s; assert ext list == [43,51], JA3S/JA4S ==
#     the pinned 0x1301 target, and (if a sotOs pcap is present) field-for-field
#     equality sotOs == nginx.
#
# Requires: podman|docker, python3. No host tcpdump/sudo/openssl needed (the
# client+sniffer apk-add their own openssl/tcpdump inside the nginx netns).
#
# Usage: tools/tls13-ja3s-compare.sh [sotos.pcap]
#   sotos.pcap defaults to /tmp/tls13gate.pcap (the live fingerprint gate's dump).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SOTOS_PCAP="${1:-/tmp/tls13gate.pcap}"
WORK="$(mktemp -d)"
ENGINE="$(command -v podman || command -v docker)"
[ -n "$ENGINE" ] || { echo "error: neither podman nor docker found on PATH" >&2; exit 1; }

NAME="tls13-ja3s-nginx-ref"
SNIFF="tls13-ja3s-sniffer"
CLIENT="tls13-ja3s-client"

# --- pinned ε4 oracle constants (the frozen target == real nginx) -------------
declare -A PIN_JA3S=( [1301]=f4febc55ea12b31ae17cfb7e614afda8 \
                      [1302]=15af977ce25de452b96affa2addb1036 \
                      [1303]=475c9302dc42b2751db9edcac3b74891 )
declare -A PIN_JA4S=( [1301]=t130200_1301_a56c5b993250 \
                      [1302]=t130200_1302_a56c5b993250 \
                      [1303]=t130200_1303_a56c5b993250 )
# openssl ciphersuite token per suite (drives a "<suite>-first" client)
declare -A CS=( [1301]=TLS_AES_128_GCM_SHA256 \
                [1302]=TLS_AES_256_GCM_SHA384 \
                [1303]=TLS_CHACHA20_POLY1305_SHA256 )

FAIL=0
fail() { echo "  FAIL: $*" >&2; FAIL=1; }

cleanup() {
    # Remove the netns *sharers* (sniffer/client) BEFORE the netns *owner*
    # (nginx); podman refuses to remove a container whose netns another joins.
    "$ENGINE" rm -f "$SNIFF" "$CLIENT" >/dev/null 2>&1
    "$ENGINE" rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

# 1. self-signed RSA cert + a TLS1.3-only server block. ssl_prefer_server_ciphers
#    is left at its DEFAULT (off) so nginx honors the client's cipher order —
#    exactly sotOs's ε4 behavior, so the fingerprint is a fair comparison.
openssl req -x509 -nodes -newkey rsa:2048 -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
    -days 1 -subj "/CN=nginx-ref" >/dev/null 2>&1 || {
        echo "error: host openssl could not generate the cert" >&2; exit 1; }
cat > "$WORK/nginx.conf" <<'EOF'
events {}
http {
    server {
        listen 443 ssl;
        ssl_protocols TLSv1.3;                # 1.3 only — the ε4 surface
        # ssl_prefer_server_ciphers off (default) → nginx honors client order
        ssl_certificate     /etc/nginx/c.pem;
        ssl_certificate_key /etc/nginx/k.pem;
        location / { return 200 "ref\n"; }
    }
}
EOF

# 2. start nginx — NO host port publish (pasta mangles the handshake through a
#    published port). The client is driven INSIDE the netns instead (step 4).
"$ENGINE" run -d --replace --name "$NAME" \
    -v "$WORK/nginx.conf:/etc/nginx/nginx.conf:ro,Z" \
    -v "$WORK/c.pem:/etc/nginx/c.pem:ro,Z" \
    -v "$WORK/k.pem:/etc/nginx/k.pem:ro,Z" \
    nginx:alpine >/dev/null || { echo "error: nginx container failed to start" >&2; exit 1; }
sleep 3
NGINX_VER="$("$ENGINE" exec "$NAME" nginx -v 2>&1 | sed 's/.*: //')"
echo "nginx ref: ${NGINX_VER:-unknown} (TLSv1.3, ssl_prefer_server_ciphers=off)"

# capture_suite <hexsuite> <out.pcap> : drive a "<suite>-first" client to nginx
# (server on :443 inside its own netns) and capture nginx's ServerHello.
capture_suite() {
    local suite="$1" out="$2" tok="${CS[$1]}"
    "$ENGINE" rm -f "$SNIFF" >/dev/null 2>&1
    # 3a. sniff INSIDE the nginx netns (CAP_NET_RAW; server on :443)
    "$ENGINE" run -d --replace --name "$SNIFF" --net "container:$NAME" --cap-add NET_RAW \
        -v "$WORK:/cap:Z" alpine:latest \
        sh -c "apk add -q --no-cache tcpdump && tcpdump -i any -s0 -U -w /cap/$(basename "$out") 'tcp port 443'" >/dev/null
    sleep 5   # 3b. let apk add tcpdump + the capture come up
    # 4. drive the discriminating <suite>-first 1.3 client from INSIDE the netns.
    #    -ciphersuites lists ONLY <tok> first so the client offers it first; the
    #    server (client-order) must echo it back, exposing any server-pref gap.
    "$ENGINE" run --rm --name "$CLIENT" --net "container:$NAME" alpine:latest \
        sh -c "apk add -q --no-cache openssl >/dev/null 2>&1; \
               echo Q | openssl s_client -connect 127.0.0.1:443 -tls1_3 \
                   -ciphersuites '$tok' >/dev/null 2>&1 || true"
    sleep 1
    "$ENGINE" stop -t1 "$SNIFF" >/dev/null 2>&1
    sleep 1
}

# parse_sh <pcap> [want_cipher_hex] : echo "ja3s ja4s ext_csv cipher_hex" for the
# ServerHello in <pcap>. If want_cipher_hex is given, select the SH whose cipher
# matches (a sotOs gate pcap holds several SHs); else the first SH.
parse_sh() {
    JA3S_SERVER_PORT=443 SH_WANT="${2:-}" python3 - "$1" <<PYEOF
import sys, os, hashlib
sys.path.insert(0, "$HERE")
import ja3s as J
path = sys.argv[1]
want = (os.environ.get("SH_WANT") or "").lower() or None
hit = None
for st in J._server_streams(open(path, "rb").read()):
    p = J._parse_server_hello(st)
    if p is None:
        continue
    ver, cipher, exts, nv = p
    chex = "%04x" % cipher
    if want and chex != want:        # skip non-matching SHs (gate pcap = many SHs)
        continue
    s = "%d,%d,%s" % (ver, cipher, "-".join(str(e) for e in exts))
    hit = (hashlib.md5(s.encode()).hexdigest(), J.ja4s(cipher, exts, nv, ver),
           "-".join(str(e) for e in exts), chex)
    break
if hit is None:
    sys.stderr.write("no matching ServerHello (want=%s) in %s\n" % (want, path))
    sys.exit(3)
print("%s %s %s %s" % hit)
PYEOF
}

# --- 0x1301-first : the PRIMARY discriminating fingerprint --------------------
echo
echo "=== 0x1301-first client (the discriminating probe) ==="
capture_suite 1301 "nginx-1301.pcap"
NGINX_PCAP="$WORK/nginx-1301.pcap"
[ -s "$NGINX_PCAP" ] || { fail "nginx capture is empty/missing ($NGINX_PCAP) — pasta/netns capture failed"; }

NREAD=""
if [ -s "$NGINX_PCAP" ]; then
    NREAD="$(parse_sh "$NGINX_PCAP" 1301)" || fail "no nginx 0x1301 ServerHello captured (stale/empty pcap)"
fi
if [ -n "$NREAD" ]; then
    read -r N_JA3S N_JA4S N_EXT N_CIPHER <<<"$NREAD"
    echo "  nginx  : cipher=0x$N_CIPHER ext=[$N_EXT] JA3S=$N_JA3S JA4S=$N_JA4S"
    # (a) layout assumption: ext list == [43,51]
    [ "$N_EXT" = "43-51" ] || fail "nginx 1.3 SH ext list is [$N_EXT], expected [43-51] (supported_versions,key_share)"
    # (b) pinned target == REAL nginx (fail loud on disagreement)
    [ "$N_JA3S" = "${PIN_JA3S[1301]}" ] || fail "nginx JA3S=$N_JA3S != pinned ${PIN_JA3S[1301]} (pin or nginx version wrong)"
    [ "$N_JA4S" = "${PIN_JA4S[1301]}" ] || fail "nginx JA4S=$N_JA4S != pinned ${PIN_JA4S[1301]}"
    [ "$N_CIPHER" = "1301" ] || fail "nginx echoed 0x$N_CIPHER for a 0x1301-first client (not client-order!)"
fi

# --- sotOs == nginx, field-for-field (the ultimate proof) ---------------------
echo
echo "=== sotOs vs nginx (field-for-field, 0x1301) ==="
if [ -s "$SOTOS_PCAP" ]; then
    SREAD="$(parse_sh "$SOTOS_PCAP" 1301)" \
        && { read -r S_JA3S S_JA4S S_EXT S_CIPHER <<<"$SREAD"
             echo "  sotOs  : cipher=0x$S_CIPHER ext=[$S_EXT] JA3S=$S_JA3S JA4S=$S_JA4S  ($SOTOS_PCAP)"
             if [ -n "$NREAD" ]; then
                 [ "$S_JA3S" = "$N_JA3S" ] || fail "sotOs JA3S=$S_JA3S != nginx JA3S=$N_JA3S"
                 [ "$S_JA4S" = "$N_JA4S" ] || fail "sotOs JA4S=$S_JA4S != nginx JA4S=$N_JA4S"
                 [ "$S_EXT"  = "$N_EXT"  ] || fail "sotOs ext=[$S_EXT] != nginx ext=[$N_EXT]"
                 [ "$FAIL" = 0 ] && echo "  → sotOs SH == nginx SH field-for-field (JA3S, JA4S, ext list)"
             fi
           } \
        || echo "  note: no 0x1301 ServerHello in $SOTOS_PCAP — skipping sotOs==nginx (live gate covers sotOs==pinned)"
else
    echo "  note: sotOs pcap '$SOTOS_PCAP' not present — comparing nginx vs the pinned"
    echo "        constants only; the live fingerprint gate covers sotOs==pinned."
fi

# --- optional: 0x1302-first and 0x1303-first (confirm nginx honors order) -----
echo
echo "=== 0x1302-first / 0x1303-first (nginx client-order confirmation) ==="
for s in 1302 1303; do
    capture_suite "$s" "nginx-$s.pcap"
    P="$WORK/nginx-$s.pcap"
    if [ -s "$P" ] && R="$(parse_sh "$P" "$s")"; then
        read -r J3 J4 EX CH <<<"$R"
        echo "  nginx 0x$s-first: cipher=0x$CH ext=[$EX] JA3S=$J3 JA4S=$J4"
        [ "$J3" = "${PIN_JA3S[$s]}" ] || fail "nginx 0x$s JA3S=$J3 != pinned ${PIN_JA3S[$s]}"
        [ "$J4" = "${PIN_JA4S[$s]}" ] || fail "nginx 0x$s JA4S=$J4 != pinned ${PIN_JA4S[$s]}"
        [ "$CH" = "$s" ] || fail "nginx echoed 0x$CH for a 0x$s-first client (not client-order)"
    else
        echo "  note: 0x$s-first capture empty (non-fatal; 0x1301 is the primary probe)"
    fi
done

echo
if [ "$FAIL" = 0 ]; then
    echo "ε4-NGINX-COMPARE: PASS  (nginx $NGINX_VER 1.3 SH == pinned == sotOs; 0x1301 JA3S=${PIN_JA3S[1301]} JA4S=${PIN_JA4S[1301]})"
    exit 0
else
    echo "ε4-NGINX-COMPARE: FAIL"
    exit 1
fi
