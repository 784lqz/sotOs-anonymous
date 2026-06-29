#!/usr/bin/env bash
# gate-egress-dns · Phase 1 · the DNS canary intercept (Tier-2, hermetic).
#
# `egress-dns` (cmd_egress_dns) is deliberately NOT in the shared auto-demo: the
# orch is single-threaded, so a demo in the boot sequence makes orch captive and
# shifts the inbound-probe gaps the tls13/ssh gates depend on.  Instead this gate
# triggers `egress-dns` IN ISOLATION via the HMP monitor `sendkey` at the sotos>
# operator console (mirrors tools/watch-combo-gate.sh): boot with a virtio
# keyboard, let the boot settle into the interactive busybox shell, F12 to the
# operator console, then type `egress-dns`.  The handler spawns the `dnsprobe`
# fixture (static musl · UDP:53 A-query) resolving the canary domain
# malicious-c2.example → the local DNS-intercept synth answers 10.0.2.15
# (contained · no real wire).  PASS = the synth answered + dnsprobe RESOLVED it +
# 0 faults.
#
# The Tier-0e REAL forward (example.com → 1.1.1.1) is NOT exercised here: it is
# network-dependent and its spin-poll, with no egress, would occupy the orch loop
# and wedge the boot.  Its code is wired into the DNS intercept (handlers_net.c)
# and the pure helpers are host-unit-tested (src/test/dns_unit · `cc -I include
# src/test/dns_unit/dns_unit.c src/sotnet/dns.c`).  A live end-to-end forward is a
# dedicated internet-connected follow-up.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-egress-dns-serial.log
MON=/tmp/sotos-egress-dns-mon.sock

# Operator-QEMU guard · NEVER pkill (the operator's QEMU holds the sotfs.img lock).
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[egress-dns-gate] BLOCKED: operator QEMU live (holds the sotfs.img lock)"; exit 3
fi

echo "[egress-dns-gate] rebuilding (fresh sotfs.img)…"
rm -f build/images/sotfs.img
just build >/tmp/sotos-egress-dns-build.log 2>&1 || { echo "[egress-dns-gate] BLOCKED: build failed"; exit 2; }
rm -f "$SLOG" "$MON"; : > "$SLOG"

# HMP monitor send helper · portable AF_UNIX write via python3.
mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "[egress-dns-gate] booting headless (virtio-keyboard · operator-console trigger)…"
timeout 320 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

# 1) wait for the interactive busybox shell (virtio-keyboard present → bbsh-auto).
waitfor 'busybox canary shell' 200 || { echo "[egress-dns-gate] FAIL · never reached the interactive boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 3
# 2) F12 → operator console (where sotShell commands like `egress-dns` run).
echo "[egress-dns-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
# 3) type `egress-dns` + Enter.  Hyphen → HMP keyname `minus`.
echo "[egress-dns-gate] typing 'egress-dns'…"
for k in e g r e s s minus d n s; do mon "sendkey $k"; sleep 0.25; done
mon "sendkey ret"
# 4) wait for the handler to finish.
waitfor '\[egress-dns\] handler DONE' 60 || echo "[egress-dns-gate] WARN · handler DONE marker not seen in window"
sleep 1; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== egress Phase-1 · DNS canary gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

# THE assertion · the canary domain resolves via the local synth table (contained).
[ "$(sg '\[dns-intercept\].*malicious-c2.example')" -ge 1 ] \
  && echo "PASS · canary malicious-c2.example resolved via the synth table (contained)" \
  || { echo "FAIL · canary domain not synth-answered"; fail=1; }
[ "$(LC_ALL=C grep -acE 'dnsprobe\] RESOLVED malicious-c2.example -> 10.0.2.15' "$SLOG")" -ge 1 ] \
  && echo "PASS · dnsprobe got the controlled IP 10.0.2.15 (no real wire)" \
  || { echo "FAIL · dnsprobe did not get the canary IP"; fail=1; }
[ "$(sg '\[egress-dns\] handler DONE')" -ge 1 ] \
  && echo "PASS · egress-dns handler completed cleanly" \
  || { echo "FAIL · egress-dns handler did not finish"; fail=1; }

echo "INFO · Tier-0e live forward deferred (network-dependent · code wired + dns_unit host-tested)"

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'EGRESS-DNS: PASS' || echo 'EGRESS-DNS: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
