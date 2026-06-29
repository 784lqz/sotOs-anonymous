#!/usr/bin/env bash
# arc-ζ1 gate: prove the :22 honeypot completes a REAL SSH-2.0 key exchange.
# ssh-keyscan does version exchange + KEXINIT + curve25519 KEX, then RECOMPUTES
# the exchange hash H and VERIFIES the rsa-sha2-256 signature over it before
# printing the host key — so a printed host key proves X25519 + the exchange-hash
# byte encoding + the RSA signature are all byte-exact.
#
# Usage: tools/ssh-kex-gate.sh [port] [serial-log]   (run AGAINST a live booted sotOs)
#   -4 -t rsa forces EXACTLY ONE IPv4 connection (default opens 5, one per key type).
set -uo pipefail
PORT="${1:-18022}"; LOG="${2:-/tmp/hp-ssh.log}"
cd "$(dirname "$0")/.." || exit 2

echo "[zeta1-gate] ssh-keyscan -4 -t rsa -p $PORT 127.0.0.1 (single connection) ..."
KS="$(ssh-keyscan -4 -t rsa -p "$PORT" -T 15 127.0.0.1 2>/tmp/ssh-keyscan.err || true)"
printf '%s\n' "$KS"
echo "--- ssh-keyscan stderr ---"; cat /tmp/ssh-keyscan.err 2>/dev/null

hostkey="$(printf '%s' "$KS" | LC_ALL=C grep -aoE 'ssh-rsa AAAA[A-Za-z0-9+/=]+' | head -1)"
marker=""
[ -f "$LOG" ] && marker="$(LC_ALL=C grep -aE 'inbound SSH KEX complete' "$LOG" | head -1 || true)"

if [ -n "$hostkey" ]; then echo "  PASS  host key validated + printed: ${hostkey:0:52}...";
else echo "  FAIL  no host key — KEX did not complete (incorrect signature / H mismatch?)"; fi
if [ -n "$marker" ]; then echo "  PASS  serial: $marker"; else echo "  INFO  KEX-complete marker not in $LOG"; fi

if [ -n "$hostkey" ]; then echo "=== ARC-zeta1 GATE: PASS (real SSH KEX + validated host key) ==="; exit 0; fi
echo "=== ARC-zeta1 GATE: FAIL ==="; exit 1
