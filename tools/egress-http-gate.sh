#!/usr/bin/env bash
# gate-egress-http · Phase 2 · the REAL TLS-client proof (Tier-0e · REAL internet).
#
# A real off-the-shelf busybox `wget -O - https://example.com` runs at
# FUNCTOR_TIER_EGRESS: the openssl s_client TLS helper (real Alpine OpenSSL 3.3.7,
# musl-dynamic) does the handshake WITH certificate verification (-verify_return_error)
# against the real ca-certificates bundle served at /etc/ssl/cert.pem; the DNS-intercept
# forwards example.com to 1.1.1.1 over SLIRP; the synth-free real TCP carries the HTTPS
# exchange; the decrypted HTML relays openssl→wget→stdout.  PASS = real DNS + real :443
# connect + a verified REAL TLS handshake (the real >3 KB server cert) + the real
# example.com HTML body printed to the console, 0 faults.
#
# NETWORK-DEPENDENT (opt-in): needs real SLIRP egress to 1.1.1.1:53 + 93.184…:443.
# Skips clean when offline.  Triggered IN ISOLATION via the HMP monitor `sendkey`
# at the operator console (the orch is single-threaded · a boot-sequence demo
# shifts the inbound-probe gaps the tls13/ssh gates depend on).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-egress-http-serial.log
MON=/tmp/sotos-egress-http-mon.sock

# Operator-QEMU guard · NEVER pkill (the operator's QEMU holds the sotfs.img lock).
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[egress-http-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi

# Connectivity pre-check · skip clean when the host itself has no egress.
if ! timeout 5 getent hosts example.com >/dev/null 2>&1 && ! timeout 5 bash -c '</dev/tcp/1.1.1.1/53' 2>/dev/null; then
  echo "[egress-http-gate] SKIP: host has no internet egress (network-dependent gate)"; exit 0
fi

echo "[egress-http-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-egress-http-build.log 2>&1 || { echo "[egress-http-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[egress-http-gate] booting headless (virtio-keyboard · operator-console trigger)…"
timeout 480 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[egress-http-gate] FAIL · never reached the interactive boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
echo "[egress-http-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[egress-http-gate] typing 'egress-http'…"
for k in e g r e s s minus h t t p; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
# Wait for the END-TO-END proof: the real example.com HTML body relayed all the
# way to stdout ("Example Domain" in the page <title>/<h1>).  Fall back to the
# handler DONE marker; kill after a short settle either way.
waitfor 'Example Domain' 150 || waitfor '\[egress-http\] handler DONE' 20 \
  || echo "[egress-http-gate] WARN · body marker not seen in window"
sleep 3; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== egress Phase-2 · HTTPS-over-TLS gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[egress-http\] handler START')" -ge 1 ] \
  && echo "PASS · egress-http handler started" \
  || { echo "FAIL · handler never started"; fail=1; }

# THE assertions · prove the REAL TLS client (busybox wget → openssl s_client)
# does a REAL handshake with the real example.com over the wire AND fetches the
# real HTML body end-to-end (the body relays openssl→wget→stdout).

# 1) real DNS forward · example.com resolved via the real nameserver (1.1.1.1).
[ "$(LC_ALL=C grep -acE '\[dns-egress\] pid=[0-9]+ · example.com. -> forwarded' "$SLOG")" -ge 1 ] \
  && echo "PASS · example.com resolved via the real DNS forwarder" \
  || { echo "FAIL · DNS forward did not happen"; fail=1; }

# 2) real TCP connect to example.com's real IP on :443 (Tier-0e wire).
[ "$(LC_ALL=C grep -acE 'REAL connect [0-9.]+:443' "$SLOG")" -ge 1 ] \
  && echo "PASS · real TCP connect to example.com:443 (Tier-0e egress)" \
  || { echo "FAIL · no real :443 connect"; fail=1; }

# 3) THE TLS proof · a >3000-byte wire read = the REAL server certificate (the
#    full TLS handshake completed against example.com, not a synth/stub).
[ "$(LC_ALL=C grep -acE 'got 3[0-9]{3} bytes from the wire' "$SLOG")" -ge 1 ] \
  && echo "PASS · real TLS handshake · server certificate (>3 KB) received over the wire" \
  || { echo "FAIL · no large cert read · TLS handshake did not complete"; fail=1; }

# 4) THE END-TO-END proof · the real example.com HTML body, relayed all the way
#    to stdout (openssl decrypts → socketpair → wget → console).  "Example Domain"
#    is the literal text in example.com's <title> and <h1>.
[ "$(LC_ALL=C grep -ac 'Example Domain' "$SLOG")" -ge 1 ] \
  && echo "PASS · real example.com HTML body fetched end-to-end over TLS ('Example Domain')" \
  || { echo "FAIL · body not relayed to stdout (no 'Example Domain')"; fail=1; }

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'EGRESS-HTTP: PASS' || echo 'EGRESS-HTTP: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
