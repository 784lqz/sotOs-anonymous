#!/usr/bin/env bash
# arc-gamma gate: prove the inbound :443 ServerHello byte-matches nginx (JA3S)
# AND that RFC 7627 EMS key derivation is correct.
#   - JA3S match  = the fingerprint goal (parsed from a FRESH :443 pcap).
#   - app-data    = the LOAD-BEARING EMS-correctness proof: an HTTP body only
#                   returns after the Finished MAC verifies, which requires both
#                   sides to derive the SAME EMS master secret. openssl's
#                   "Extended master secret: yes" banner only proves the server
#                   ECHOED 0x0017 — a secondary signal, NOT crypto proof.
#
# Usage: tools/ja3s-ems-gate.sh [443-host-port] [pcap-path]
#   Default port 18443 = the run-honeypot-pcap hostfwd (justfile: tcp::18443-:443).
#   Run AGAINST a live booted sotOs (just run-honeypot-pcap) — host->guest :443.
set -uo pipefail
PORT="${1:-18443}"; PCAP="${2:-/tmp/honeypot.pcap}"
cd "$(dirname "$0")/.." || exit 2
TARGET_MD5="1af33e1657631357c73119488045302c"
TARGET_STR="771,49199,65281-11-35-23"

START=$(date +%s)
echo "[gamma-gate] openssl s_client (offers ec_point_formats + session_ticket + EMS; NO -alpn) -> :$PORT"
OUT="$(printf 'GET / HTTP/1.0\r\nHost: honeypot\r\n\r\n' | timeout 15 openssl s_client -connect 127.0.0.1:"$PORT" -tls1_2 -ign_eof 2>&1)"
ems="$(printf '%s' "$OUT"     | LC_ALL=C grep -aiE 'Extended master secret: *yes' || true)"
appdata="$(printf '%s' "$OUT" | LC_ALL=C grep -aiE 'HTTP/1|Server:|nginx|<html' || true)"
[ -n "$ems" ]     && echo "  ok    banner: EMS extension echoed (secondary signal)" || echo "  WARN  no EMS banner"
if [ -n "$appdata" ]; then echo "  PASS  app-data returned => Finished verified => EMS master secret CORRECT";
else echo "  FAIL  no app-data — handshake aborted (EMS derivation wrong, or :443 unreachable)"; fi

echo "[gamma-gate] JA3S freshness + match"
fresh=""
if [ ! -f "$PCAP" ]; then echo "  FAIL  pcap missing: $PCAP"; else
  MT=$(stat -c %Y "$PCAP" 2>/dev/null || echo 0)
  if [ "$MT" -ge "$START" ]; then fresh=1; echo "  ok    pcap is fresh (mtime >= connect start)";
  else echo "  FAIL  STALE pcap (mtime < connect start) — recapture via run-honeypot-pcap"; fi
fi
JS="$(JA3S_SERVER_PORT=443 python3 tools/ja3s.py "$PCAP" 2>/dev/null || true)"
echo "$JS"
md5ok=$(printf '%s' "$JS" | LC_ALL=C grep -aoF "$TARGET_MD5" | head -1)
strok=$(printf '%s' "$JS" | LC_ALL=C grep -aoF "$TARGET_STR" | head -1)
[ -n "$md5ok" ] && echo "  PASS  JA3S md5 == nginx ($TARGET_MD5)" || echo "  FAIL  JA3S md5 != nginx target"

# app-data (EMS proof) + a fresh JA3S match are BOTH required.
if [ -n "$appdata" ] && [ -n "$fresh" ] && [ -n "$md5ok" ] && [ -n "$strok" ]; then
    echo "=== ARC-gamma GATE: PASS (byte-exact JA3S + correct EMS, fresh capture) ==="; exit 0
else
    echo "=== ARC-gamma GATE: FAIL ==="; exit 1
fi
