#!/usr/bin/env bash
# arc-ζ2 gate: a real OpenSSH client completes the ENCRYPTED transport + userauth.
# `ssh -v` negotiates curve25519-sha256 + aes128-ctr + hmac-sha2-256, exchanges
# NEWKEYS (so encrypted packets flow), and reaches "Permission denied (password)"
# — proving the KDF + AES-CTR/HMAC codec + USERAUTH_FAILURE all work end-to-end.
#
# Usage: tools/ssh-auth-gate.sh [port] [serial-log]   (run AGAINST a live booted sotOs)
set -uo pipefail
PORT="${1:-18022}"; LOG="${2:-/tmp/hp-ssh.log}"
cd "$(dirname "$0")/.." || exit 2

echo "[zeta2-gate] sshpass + ssh -v -p $PORT (password auth, single connection) ..."
OUT="$(sshpass -p deception ssh -v -p "$PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o ConnectTimeout=12 -o NumberOfPasswordPrompts=2 \
        probe@127.0.0.1 true 2>&1 || true)"
printf '%s\n' "$OUT" | LC_ALL=C grep -aiE "kex:|host key|NEWKEYS|cipher|Authentications that can continue|Permission denied|Corrupted MAC|message authentication|bad packet" | head -20

kex="$(printf '%s' "$OUT"   | LC_ALL=C grep -aiE 'kex: .*curve25519-sha256' || true)"
newk="$(printf '%s' "$OUT"  | LC_ALL=C grep -aiE 'SSH2_MSG_NEWKEYS (received|sent)' || true)"
auth="$(printf '%s' "$OUT"  | LC_ALL=C grep -aiE 'Permission denied \(password\)|Authentications that can continue' || true)"
badmac="$(printf '%s' "$OUT"| LC_ALL=C grep -aiE 'Corrupted MAC|message authentication code incorrect' || true)"
marker=""; [ -f "$LOG" ] && marker="$(LC_ALL=C grep -aE 'inbound SSH userauth' "$LOG" | head -1 || true)"

[ -n "$kex" ]  && echo "  PASS  kex negotiated curve25519-sha256" || echo "  FAIL  curve25519-sha256 not negotiated"
[ -n "$newk" ] && echo "  PASS  NEWKEYS exchanged (encrypted transport active)" || echo "  WARN  no NEWKEYS line"
[ -z "$badmac" ] && echo "  PASS  no MAC corruption" || echo "  FAIL  $badmac"
[ -n "$auth" ] && echo "  PASS  reached userauth: $auth" || echo "  FAIL  did not reach the password prompt"
[ -n "$marker" ] && echo "  PASS  serial: $marker" || echo "  INFO  userauth marker not in $LOG"

if [ -n "$kex" ] && [ -z "$badmac" ] && [ -n "$auth" ]; then
    echo "=== ARC-zeta2 GATE: PASS (encrypted SSH transport + userauth) ==="; exit 0
fi
echo "=== ARC-zeta2 GATE: FAIL ==="; exit 1
