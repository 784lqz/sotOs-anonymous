#!/usr/bin/env bash
# TCP/IP SYN-ACK fingerprint gate — sotOs vs a TS-off Linux (nginx:alpine, :80, in-netns).
# Gates on sig_os (option layout + wscale) + TTL/DF/IP-ID; MSS/window are path-dependent
# (informational). Exit 0 = match, 1 = mismatch. Requires podman|docker, python3.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SOTOS_PCAP="${1:-/tmp/honeypot.pcap}"
LINUX_PCAP="/tmp/linux-ref.pcap"
WORK="$(mktemp -d)"
ENGINE="$(command -v podman || command -v docker)"
[ -n "$ENGINE" ] || { echo "error: neither podman nor docker found on PATH" >&2; exit 2; }
NAME="tcpfp-ref"; SNIFF="tcpfp-sniff"

cleanup() {
    "$ENGINE" rm -f "$SNIFF" >/dev/null 2>&1
    "$ENGINE" rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

# 1. TS-off nginx (listens :80), capture its SYN-ACK in-netns via a loopback client.
"$ENGINE" run -d --replace --name "$NAME" --sysctl net.ipv4.tcp_timestamps=0 nginx:alpine >/dev/null
sleep 3
"$ENGINE" run -d --replace --name "$SNIFF" --net "container:$NAME" --cap-add NET_RAW \
    -v "$WORK:/cap:Z" alpine:latest \
    sh -c "apk add -q --no-cache tcpdump && tcpdump -i any -s0 -U -w /cap/linux-ref.pcap 'tcp port 80'" >/dev/null
sleep 5
"$ENGINE" run --rm --net "container:$NAME" alpine:latest \
    sh -c "apk add -q --no-cache curl >/dev/null 2>&1; curl -s -m3 http://127.0.0.1/ >/dev/null 2>&1 || true"
sleep 1
"$ENGINE" stop -t1 "$SNIFF" >/dev/null 2>&1
cp "$WORK/linux-ref.pcap" "$LINUX_PCAP" 2>/dev/null || true

echo "=== sotOs (:443) ==="
TCPFP_SERVER_PORT=443 python3 "$HERE/tcpfp.py" "$SOTOS_PCAP"
echo "=== linux ref (:80, TS-off, loopback) ==="
TCPFP_SERVER_PORT=80 python3 "$HERE/tcpfp.py" "$LINUX_PCAP"

echo "=== gate: sig_os + TTL/DF/IP-ID ==="
export TCPFP_DIR="$HERE"
python3 - "$SOTOS_PCAP" "$LINUX_PCAP" <<'PY'
import os, sys, json, subprocess
here = os.environ["TCPFP_DIR"]
def fp(path, port):
    env = dict(os.environ, TCPFP_SERVER_PORT=str(port))
    out = subprocess.check_output([sys.executable, os.path.join(here,"tcpfp.py"),"--json",path], env=env)
    return json.loads(out)
s = fp(sys.argv[1], 443); l = fp(sys.argv[2], 80)
ok = True
def check(name, got, want):
    global ok
    if got != want: ok = False
    print("  %-22s sotos=%-40s want=%-40s %s" % (name, got, want, "PASS" if got==want else "FAIL"))
check("sig_os (layout+ws)", s["sig_os"], l["sig_os"])
check("ttl", s["ttl"], 64)
check("df", s["df"], 1)
check("ip_id", s["ip_id"], 0)
print("  (informational: sotos mss=%s window=%s · linux-ref is loopback mss=%s window=%s)"
      % (s["mss"], s["window"], l["mss"], l["window"]))
print("RESULT:", "MATCH" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
PY
