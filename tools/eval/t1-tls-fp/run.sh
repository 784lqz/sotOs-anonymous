#!/usr/bin/env bash
# EXPERIMENT T1 · TLS FINGERPRINTS (JA3S / JA4S / JARM)
# Drive a FIXED client set identically against sotOs (:18443) and a reference
# nginx:alpine (:18444), capture each ServerHello with tcpdump, compute JA3S+JA4S via
# the real parser tools/ja3s.py, and JARM via the FoxIO jarm tool if present (else the
# local reachability stub). Aggregate over N runs (mode), compare, emit CSV + table.
# Pass condition: exact match (sotOs == ref) on JA3S, JA4S and JARM for EVERY client.
#
# Prereqs (pin versions via tools/eval/00-environment.sh):
#   - sotOs booted with TLS on :18443 (just run-4pane / run)
#   - reference: docker run --rm -p 18444:443 nginx:alpine@sha256:<DIGEST>  (TLS + cert)
#   - host tools: openssl, tcpdump (needs cap_net_raw/sudo), python3, tools/ja3s.py
#   - optional real JARM: pip install jarm  OR salesforce/jarm (jarm/jarm.py on PATH)
#
# Usage: tools/eval/t1-tls-fp/run.sh [RUNS]   (default 5)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

RUNS="${1:-5}"
SOTOS_HOST="${SOTOS_HOST:-127.0.0.1}"; SOTOS_PORT="${SOTOS_PORT:-18443}"
REF_HOST="${REF_HOST:-127.0.0.1}";     REF_PORT="${REF_PORT:-18444}"
EVAL_DIR="tools/eval/t1-tls-fp"
JA3S="tools/ja3s.py"
TS=$(date +%Y%m%d_%H%M%S)
RES="${EVAL_DIR}/results-${TS}"; mkdir -p "$RES"
CSV="${RES}/results.csv"; TABLE="${RES}/t1-table.txt"
IFACE="${IFACE:-lo}"   # tcpdump interface (loopback for hostfwd/docker on 127.0.0.1)

for b in openssl tcpdump python3; do command -v "$b" >/dev/null || { echo "[T1] FATAL: missing $b"; exit 1; }; done
[ -f "$JA3S" ] || { echo "[T1] FATAL: $JA3S missing"; exit 1; }
# JARM_BIN may be pre-set in the env (run-all passes it so it survives sudo's secure_path,
# which drops ~/.local/bin). Else detect jarm OR jarm.py on PATH.
JARM_BIN="${JARM_BIN:-$(command -v jarm jarm.py 2>/dev/null | head -1 || true)}"
[ -n "$JARM_BIN" ] || echo "[T1] WARN: no FoxIO jarm tool found — using the reachability stub (NOT real JARM; install 'jarm'/'jarm.py' for the paper)."

# Fixed client set (mirrors clients.manifest). {T} is replaced by host:port.
declare -A CLIENT
CLIENT[c1_tls13_default]="-tls1_3 -connect {T}"
CLIENT[c2_tls12]="-tls1_2 -connect {T}"
CLIENT[c3_tls13_p256]="-tls1_3 -groups P-256 -ciphersuites TLS_AES_128_GCM_SHA256 -connect {T}"
CLIENT[c4_tls13_p384]="-tls1_3 -groups P-384 -ciphersuites TLS_AES_128_GCM_SHA256 -connect {T}"
CLIENT[c5_reordered]="-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384 -connect {T}"
CLIENT[c6_aes256]="-tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -connect {T}"
CLIENT[c7_chacha]="-tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -connect {T}"
ORDER=(c1_tls13_default c2_tls12 c3_tls13_p256 c4_tls13_p384 c5_reordered c6_aes256 c7_chacha)

echo "run,client,target,ja3s,ja4s" > "$CSV"

# Capture one ServerHello and extract JA3S + JA4S. Echoes "<ja3s> <ja4s>".
probe_tls() {
    local tag="$1" host="$2" port="$3" args="$4" run="$5"
    local pcap="${RES}/${tag}_${run}.pcap" target="${host}:${port}"
    # -U = packet-buffered (write each packet immediately, so a kill never loses the
    # handshake). Then WAIT until tcpdump is actually capturing (it writes the 24-byte
    # pcap global header once ready) instead of a fixed too-short sleep — the loopback
    # TLS handshake is faster than tcpdump's startup, so the old 0.4s missed it → 0-byte
    # pcaps → JA3S=NONE for everyone.
    tcpdump -i "$IFACE" -U -s 0 -w "$pcap" "tcp port ${port}" >/dev/null 2>&1 &
    local tdpid=$!
    local w; for w in $(seq 1 25); do [ -s "$pcap" ] && break; sleep 0.2; done
    sleep 0.3
    echo | timeout 15 openssl s_client ${args/\{T\}/$target} >/dev/null 2>&1 || true
    sleep 0.6
    kill -INT "$tdpid" 2>/dev/null || true; wait "$tdpid" 2>/dev/null || true
    # ja3s.py filters server frames by src port (default 443), but we capture on the
    # hostfwd/docker port (18443/18444) — so we MUST pass the real port or it sees no
    # server frames → NONE. Read both fingerprints from --json (the human format's last
    # line is an ext list, so `tail -1 | awk '{print $NF}'` grabbed the wrong field).
    local ja3s ja4s js
    js=$(JA3S_SERVER_PORT="$port" python3 "$JA3S" --json "$pcap" 2>/dev/null)
    ja3s=$(printf '%s' "$js" | python3 -c "import sys,json;print(json.load(sys.stdin)['ja3s'])" 2>/dev/null)
    ja4s=$(printf '%s' "$js" | python3 -c "import sys,json;print(json.load(sys.stdin)['ja4s'])" 2>/dev/null)
    echo "${ja3s:-NONE} ${ja4s:-NONE}"
}

jarm_fp() {
    local host="$1" port="$2" out=""
    if [ -n "$JARM_BIN" ]; then
        # .py tools may lack a shebang (run under python3); binaries run directly.
        case "$JARM_BIN" in
            *.py) out=$(python3 "$JARM_BIN" "$host" -p "$port" 2>/dev/null | grep -oE '[0-9a-f]{62}' | head -1) ;;
            *)    out=$("$JARM_BIN" "$host" -p "$port" 2>/dev/null | grep -oE '[0-9a-f]{62}' | head -1) ;;
        esac
    fi
    if [ -n "$out" ]; then echo "$out"
    else python3 "${EVAL_DIR}/jarm-helper.py" "${host}:${port}" 2>/dev/null; fi  # stub fallback (no real JARM)
}

mode() { sort | uniq -c | sort -rn | head -1 | awk '{print $2}'; }

echo "[T1] RUNS=$RUNS  sotOs=${SOTOS_HOST}:${SOTOS_PORT}  ref=${REF_HOST}:${REF_PORT}  iface=$IFACE"
for cli in "${ORDER[@]}"; do
    args="${CLIENT[$cli]}"
    for r in $(seq 1 "$RUNS"); do
        read -r s3 s4 < <(probe_tls "sotos_${cli}" "$SOTOS_HOST" "$SOTOS_PORT" "$args" "$r")
        read -r r3 r4 < <(probe_tls "ref_${cli}"   "$REF_HOST"   "$REF_PORT"   "$args" "$r")
        echo "$r,$cli,sotos,$s3,$s4" >> "$CSV"
        echo "$r,$cli,ref,$r3,$r4"   >> "$CSV"
        printf "[T1]   %-18s run %d/%d  sotOs=%s  ref=%s\n" "$cli" "$r" "$RUNS" "${s3:0:8}" "${r3:0:8}"
    done
done
S_JARM=$(jarm_fp "$SOTOS_HOST" "$SOTOS_PORT"); R_JARM=$(jarm_fp "$REF_HOST" "$REF_PORT")

{
  echo "EXPERIMENT T1 · TLS FINGERPRINTS"
  echo "sotOs ${SOTOS_HOST}:${SOTOS_PORT}  vs  ref ${REF_HOST}:${REF_PORT}   ($RUNS runs/client)"
  printf "%-18s %-7s %-7s %-7s %-6s\n" "client" "JA3S" "JA4S" "JARM" "match"
  echo   "------------------+-------+-------+-------+------"
  allpass=1
  for cli in "${ORDER[@]}"; do
    s3=$(awk -F, -v c="$cli" '$2==c&&$3=="sotos"{print $4}' "$CSV" | mode)
    r3=$(awk -F, -v c="$cli" '$2==c&&$3=="ref"{print $4}'   "$CSV" | mode)
    s4=$(awk -F, -v c="$cli" '$2==c&&$3=="sotos"{print $5}' "$CSV" | mode)
    r4=$(awk -F, -v c="$cli" '$2==c&&$3=="ref"{print $5}'   "$CSV" | mode)
    # a match requires a REAL fingerprint on both sides — NONE==NONE is NOT a match.
    m3=$([ "$s3" != NONE ] && [ -n "$s3" ] && [ "$s3" = "$r3" ] && echo Y || echo N)
    m4=$([ "$s4" != NONE ] && [ -n "$s4" ] && [ "$s4" = "$r4" ] && echo Y || echo N)
    if [[ "$S_JARM" == jarm_* || "$R_JARM" == jarm_* ]]; then mj=stub   # reachability stub, not real JARM
    else mj=$([ "$S_JARM" != NONE ] && [ -n "$S_JARM" ] && [ "$S_JARM" = "$R_JARM" ] && echo Y || echo N); fi
    # row passes on the REAL fingerprints (JA3S+JA4S); a stub JARM neither passes nor fails it.
    if [ "$m3" = Y ] && [ "$m4" = Y ] && { [ "$mj" = Y ] || [ "$mj" = stub ]; }; then rm=PASS; else rm=FAIL; fi
    [ "$rm" = PASS ] || allpass=0
    [ "$mj" = stub ] && jarm_stub=1
    printf "%-18s %-7s %-7s %-7s %-6s\n" "$cli" "$m3" "$m4" "$mj" "$rm"
  done
  echo ""
  echo "JARM  sotOs=$S_JARM  ref=$R_JARM"
  [ "${jarm_stub:-0}" = 1 ] && echo "(JARM column is the reachability STUB, not real JARM — run 'pipx inject jarm colorama' then re-run for the paper's JARM row)"
  echo ""
  echo "PASS = JA3S+JA4S exact match every client (JARM too when real, not stub)."
  if [ "$allpass" = 1 ]; then
    [ "${jarm_stub:-0}" = 1 ] && echo "RESULT: PASS (JA3S/JA4S) · JARM=stub pending" || echo "RESULT: PASS"
  else echo "RESULT: FAIL (see the N rows above)"; fi
} | tee "$TABLE"

echo "[T1] done · CSV=$CSV  table=$TABLE  pcaps=$RES/*.pcap"
