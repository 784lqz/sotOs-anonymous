#!/usr/bin/env bash
# lwIP EGRESS DEMUX gate · apk update over the mature stack (2nd virtio-net = lwIP egress).
# Guest apk connect→send→recv to a local Alpine mirror routes through lucas demux →
# orch_lwip_egress_* → lwIP NIC.  PASS = "OK: NNNN distinct packages available", RC=0.
# Egress-client arc · LOCAL HTTP harness.
# Serves a real APKINDEX from the host; guest does `apk update` against
# http://10.0.2.2:8099 (IP literal → no DNS; local → no internet jitter / no
# remote slow-request FIN).  Isolates the egress request-send (POLLOUT) +
# download throughput so we can iterate fast.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PORT=18022
HTTP_PORT=8099
MIRROR=/tmp/apk-mirror
SLOG=/tmp/apk-harness-serial.log
ALOG=/tmp/apk-harness-sessA.log
HLOG=/tmp/apk-harness-http.log

[ -f "$MIRROR/alpine/v3.20/main/x86_64/APKINDEX.tar.gz" ] || { echo "mirror missing"; exit 2; }

pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
pkill -9 -f "http.server $HTTP_PORT" 2>/dev/null || true
sleep 1
rm -f "$SLOG" "$ALOG" "$HLOG"

echo "[harness] starting local HTTP mirror on :$HTTP_PORT ..."
( cd "$MIRROR" && python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 ) >"$HLOG" 2>&1 &
HPID=$!
sleep 1
curl -sS -o /dev/null -w "[harness] local server self-check http=%{http_code}\n" \
    "http://127.0.0.1:$HTTP_PORT/alpine/v3.20/main/x86_64/APKINDEX.tar.gz" || echo "[harness] self-check FAILED"

echo "[harness] booting guest ..."
timeout 360 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    -netdev user,id=net1 -device virtio-net-pci,netdev=net1,mac=52:54:00:12:34:57 \
    < /dev/null > "$SLOG" 2>&1 &
QPID=$!
trap 'kill $QPID 2>/dev/null; kill $HPID 2>/dev/null' EXIT

for i in $(seq 1 90); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[harness] FAIL · :22 never LISTENed"; exit 1; }
sleep 3

ASK=/tmp/apk-harness-ask.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
send(){ printf '%s\n' "$1"; sleep "${2:-3}"; }

session_a(){
    sleep 10
    send 'echo SESSA_ALIVE' 3
    send "echo http://10.0.2.2:$HTTP_PORT/alpine/v3.20/main > /etc/apk/repositories" 3
    send 'cat /etc/apk/repositories' 3
    send 'apk update 2>&1; echo APK_UPD_RC=$?' 120
    send 'exit' 4
}

echo "[harness] driving apk update against the local mirror ..."
session_a | timeout 200 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
    ssh -tt -p "$PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=4 -o ConnectTimeout=15 \
    root@127.0.0.1 >"$ALOG" 2>&1 || true

kill $QPID 2>/dev/null; kill $HPID 2>/dev/null

echo ""
echo "[harness] === session output ==="
LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$ALOG"
echo ""
echo "[harness] === HTTP server log (did the request arrive / get served?) ==="
cat "$HLOG" 2>/dev/null | tail -6
echo ""
echo "[harness] === egress to 10.0.2.2:$HTTP_PORT — request sent + response recv ==="
echo -n "req bytes sent (to :$HTTP_PORT): "; LC_ALL=C grep -aE "send pid=0 seq=[0-9]+ len=[0-9]+ to 10\.0\.2\.2:$HTTP_PORT" "$SLOG" 2>/dev/null | grep -oE "len=[0-9]+" | awk -F= '{s+=$2;n++} END{print (s+0)" in "(n+0)" writes"}'
echo -n "resp bytes recv (egress fd=4): "; LC_ALL=C grep -aE "egress pid=[0-9]+ read fd=[0-9]+ · got [0-9]+ bytes from the wire" "$SLOG" 2>/dev/null | grep -oE "got [0-9]+" | awk '{s+=$2;n++} END{print (s+0)" in "(n+0)" reads"}'
LC_ALL=C grep -aE "REAL connect 10\.0\.2\.2:$HTTP_PORT|ESTABLISHED with 10\.0\.2\.2:$HTTP_PORT|FIN recv|apknew|OK: [0-9]+ distinct" "$SLOG" 2>/dev/null | tail -8
