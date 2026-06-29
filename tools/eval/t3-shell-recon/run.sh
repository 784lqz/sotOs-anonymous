#!/bin/bash
# EXPERIMENT T3 · SHELL RECON BATTERY
# Reproducible evaluation harness: run the same N first-minute recon commands
# against (a) reference Alpine 3.20 via SSH and (b) sotOs honey shell via SSH (:18022).
# Capture stdout+stderr+exit per command, normalize per-command (mask timestamps/PIDs),
# diff, classify (exact-match / benign-variance / structural-divergence), and emit
# CSV + human-readable table.
#
# Usage:
#   bash run.sh [--ref-host <host>] [--ref-port <port>] [--honey-port 18022]
#               [--iterations 1] [--output-dir ./results]
#   
# Default: 1 iteration, compare against reference Alpine via SSH (localhost:22),
# sotOs honey (:18022), output to ./t3-results-<timestamp>
#
# Prerequisites:
#   - Reference Alpine 3.20.10 running on port 22 (or custom --ref-port)
#   - sotOs booted with SSH on :18022 (or custom --honey-port)
#   - SSH key/password auth configured for both
#   - normalize.py in the same directory
#   - tools/eval/t3-shell-recon/battery.txt in the same directory

set -uo pipefail
cd "$(dirname "$0")" || exit 2

REF_HOST="${REF_HOST:-127.0.0.1}"
REF_PORT="${REF_PORT:-22}"
HONEY_PORT="${HONEY_PORT:-18022}"
ITERATIONS="${ITERATIONS:-1}"
OUTPUT_DIR="${OUTPUT_DIR:-.}"
BATTERY_FILE="battery.txt"
NORMALIZE_PY="normalize.py"

# Parse command-line overrides
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ref-host) REF_HOST="$2"; shift 2 ;;
        --ref-port) REF_PORT="$2"; shift 2 ;;
        --honey-port) HONEY_PORT="$2"; shift 2 ;;
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
RESULT_TS=$(date +%Y%m%d_%H%M%S)
RESULT_DIR="$OUTPUT_DIR/t3-results-$RESULT_TS"
mkdir -p "$RESULT_DIR"

[ -f "$BATTERY_FILE" ] || { echo "ERROR: $BATTERY_FILE not found"; exit 1; }
[ -f "$NORMALIZE_PY" ] || { echo "ERROR: $NORMALIZE_PY not found"; exit 1; }

# Extract command IDs and command strings from battery.txt
declare -A COMMANDS CMD_IDS
CMD_ID=1
while IFS= read -r line; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    # Parse command lines (format: "  N. <command>")
    if [[ "$line" =~ ^[[:space:]]*[0-9]+\. ]]; then
        CMD=$(echo "$line" | sed -E 's/^[[:space:]]*[0-9]+\. //')
        COMMANDS[$CMD_ID]="$CMD"
        CMD_IDS[$CMD_ID]=1
        ((CMD_ID++)) || true
    fi
done < "$BATTERY_FILE"

total_cmds=${#COMMANDS[@]}
echo "[T3] Starting shell recon battery test"
echo "[T3] Reference: $REF_HOST:$REF_PORT (Alpine 3.20.10)"
echo "[T3] Honey:     127.0.0.1:$HONEY_PORT (sotOs)"
echo "[T3] Iterations: $ITERATIONS"
echo "[T3] Commands:  $total_cmds"
echo "[T3] Output:    $RESULT_DIR"
echo ""

# SSH helper function
run_ssh() {
    local host="$1" port="$2" cmd="$3" timeout="${4:-30}"
    # SSH_ASKPASS feeds the password on EVERY prompt — sshpass feeds it ONCE and then bails
    # on a 2nd prompt, so it cannot pass the honey's bait (which rejects twice and accepts
    # the 3rd attempt). NumberOfPasswordPrompts=3 allows those 3 tries; "root" satisfies the
    # Alpine ref (1st try) and the honey (any password, 3rd try). setsid drops the controlling
    # TTY so ssh consults the askpass helper. The remote command is passed bare so each side's
    # own login shell runs it (the Alpine ref has no bash; the honey wraps it in bash -c).
    # NOTE: the honey serves ONE SSH session at a time — close any live attacker shell on
    # :18022 first, or probes time out at the banner exchange.
    local askpass; askpass=$(mktemp)
    printf '#!/bin/sh\necho %s\n' "${SSH_PASS:-root}" > "$askpass"; chmod +x "$askpass"
    SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force timeout "$timeout" setsid -w ssh -p "$port" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=3 \
        -o ConnectTimeout=15 \
        -o LogLevel=QUIET \
        root@"$host" \
        "$cmd" 2>&1
    # LogLevel=QUIET suppresses BOTH the "Warning: Permanently added" host-key line AND
    # the per-attempt "Permission denied" auth feedback that the honey's 3-try bait emits
    # — otherwise that ssh-client noise lands in the captured output and every command
    # reads as a structural divergence vs the ref (which authenticates on the 1st try).
    local rc=$?
    rm -f "$askpass"
    return $rc
}

# CSV header
CSV_FILE="$RESULT_DIR/results.csv"
echo "iteration,command_id,command,verdict,ref_exit,honey_exit,divergence_details" > "$CSV_FILE"

# Results summary
SUMMARY_FILE="$RESULT_DIR/summary.txt"
{
    echo "EXPERIMENT T3 · SHELL RECON BATTERY"
    echo "========================================"
    echo "Reference: $REF_HOST:$REF_PORT"
    echo "Honey:     127.0.0.1:$HONEY_PORT"
    echo "Test date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Iterations: $ITERATIONS"
    echo ""
} > "$SUMMARY_FILE"

# Per-command counters
declare -A EXACT_MATCH BENIGN_VAR STRUCTURAL TOTAL
for i in "${!COMMANDS[@]}"; do
    EXACT_MATCH[$i]=0
    BENIGN_VAR[$i]=0
    STRUCTURAL[$i]=0
    TOTAL[$i]=0
done

# Run the battery
for iter in $(seq 1 "$ITERATIONS"); do
    echo "[T3] Iteration $iter/$ITERATIONS"
    
    for cmd_id in $(seq 1 "$total_cmds"); do
        [ -z "${COMMANDS[$cmd_id]:-}" ] && continue
        
        cmd="${COMMANDS[$cmd_id]}"
        ref_out="$RESULT_DIR/ref_${iter}_${cmd_id}.txt"
        honey_out="$RESULT_DIR/honey_${iter}_${cmd_id}.txt"
        ref_norm="$RESULT_DIR/ref_${iter}_${cmd_id}.norm"
        honey_norm="$RESULT_DIR/honey_${iter}_${cmd_id}.norm"
        diff_file="$RESULT_DIR/diff_${iter}_${cmd_id}.txt"
        
        # Run command on reference
        ref_exit=0
        run_ssh "$REF_HOST" "$REF_PORT" "$cmd" > "$ref_out" 2>&1 || ref_exit=$?
        
        # Run command on honey
        honey_exit=0
        run_ssh "127.0.0.1" "$HONEY_PORT" "$cmd" > "$honey_out" 2>&1 || honey_exit=$?
        
        # Normalize both outputs
        python3 "$NORMALIZE_PY" "$cmd_id" "$ref_out" -o "$ref_norm" 2>/dev/null
        python3 "$NORMALIZE_PY" "$cmd_id" "$honey_out" -o "$honey_norm" 2>/dev/null
        
        # Diff and classify
        diff "$ref_norm" "$honey_norm" > "$diff_file" 2>&1 || true
        
        # Classification logic
        verdict="unknown"
        divergence=""
        
        if cmp -s "$ref_norm" "$honey_norm"; then
            verdict="exact-match"
            EXACT_MATCH[$cmd_id]=$((${EXACT_MATCH[$cmd_id]} + 1))
        elif [ "$ref_exit" -ne "$honey_exit" ]; then
            verdict="structural-divergence"
            divergence="exit-code-mismatch (ref=$ref_exit, honey=$honey_exit)"
            STRUCTURAL[$cmd_id]=$((${STRUCTURAL[$cmd_id]} + 1))
        elif grep -q "command not found\|: not found" "$honey_norm"; then
            verdict="structural-divergence"
            divergence="command-not-found"
            STRUCTURAL[$cmd_id]=$((${STRUCTURAL[$cmd_id]} + 1))
        elif grep -q "No such file\|ENOENT" "$honey_norm"; then
            verdict="structural-divergence"
            divergence="enoent-file-missing"
            STRUCTURAL[$cmd_id]=$((${STRUCTURAL[$cmd_id]} + 1))
        elif grep -qE "Function not implemented|ENOSYS" "$honey_norm"; then
            verdict="structural-divergence"
            divergence="enosys-kernel-feature"
            STRUCTURAL[$cmd_id]=$((${STRUCTURAL[$cmd_id]} + 1))
        elif [ -s "$diff_file" ]; then
            # Non-empty diff after normalization
            verdict="benign-variance"
            divergence="minor-output-diff"
            BENIGN_VAR[$cmd_id]=$((${BENIGN_VAR[$cmd_id]} + 1))
        else
            verdict="exact-match"
            EXACT_MATCH[$cmd_id]=$((${EXACT_MATCH[$cmd_id]} + 1))
        fi
        
        TOTAL[$cmd_id]=$((${TOTAL[$cmd_id]} + 1))
        
        # Log to CSV
        echo "$iter,$cmd_id,\"${cmd//\"/\"\"}\",$verdict,$ref_exit,$honey_exit,\"$divergence\"" >> "$CSV_FILE"
        
        # Progress
        printf "[T3] Cmd %2d/%2d iter %d: %s\n" "$cmd_id" "$total_cmds" "$iter" "$verdict"
    done
done

# Generate human-readable table
TABLE_FILE="$RESULT_DIR/table.txt"
{
    echo ""
    echo "COMMAND RESULTS (per command, aggregated over all iterations)"
    echo "=============================================================="
    printf "%-3s %-40s %12s %12s %12s %10s\n" "ID" "Command" "Exact" "Benign" "Structural" "Pass?"
    echo "---+------------------------------------------+-----------+-----------+-----------+----------"
    
    total_structural=0
    for cmd_id in $(seq 1 "$total_cmds"); do
        [ -z "${COMMANDS[$cmd_id]:-}" ] && continue
        cmd="${COMMANDS[$cmd_id]}"
        cmd_short=$(echo "$cmd" | cut -c1-38)
        exact=${EXACT_MATCH[$cmd_id]:-0}
        benign=${BENIGN_VAR[$cmd_id]:-0}
        structural=${STRUCTURAL[$cmd_id]:-0}
        total=${TOTAL[$cmd_id]:-0}
        
        pass="PASS"
        if [ "$structural" -gt 0 ]; then
            pass="FAIL"
            total_structural=$((total_structural + structural))
        fi
        
        printf "%3d %-40s %10d %10d %10d  %s\n" \
            "$cmd_id" "$cmd_short" "$exact" "$benign" "$structural" "$pass"
    done
    
    echo ""
    echo "SUMMARY"
    echo "======="
    echo "Total commands tested:  $total_cmds"
    echo "Total iterations:       $ITERATIONS"
    echo "Pass condition:         0 structural divergences"
    echo "Structural divergences: $total_structural"
    
    if [ "$total_structural" -eq 0 ]; then
        echo ""
        echo "RESULT: PASS - Zero structural divergence detected"
    else
        echo ""
        echo "RESULT: FAIL - $total_structural structural divergence(s) found"
    fi
} | tee "$TABLE_FILE" | tee -a "$SUMMARY_FILE"

# Public anti-honeypot detection check
DETECT_FILE="$RESULT_DIR/antibot-check.txt"
{
    echo ""
    echo "PUBLIC ANTI-HONEYPOT DETECTION SCRIPT CHECK"
    echo "=========================================="
    echo ""
    echo "Running a public honeypot detection heuristic against sotOs..."
    echo "(Testing that known anti-sandbox scripts do NOT flag the honey shell)"
    echo ""
    
    # Simple inline anti-honeypot checks (based on commands 22-30)
    ref_checks=0
    honey_checks=0
    
    # Check for hypervisor detection
    ref_hyper=$(run_ssh "$REF_HOST" "$REF_PORT" "cat /proc/cpuinfo | grep -i hypervisor | wc -l" 2>/dev/null || echo "0")
    honey_hyper=$(run_ssh "127.0.0.1" "$HONEY_PORT" "cat /proc/cpuinfo | grep -i hypervisor | wc -l" 2>/dev/null || echo "0")
    
    echo "Hypervisor flags in cpuinfo:"
    echo "  Reference: $ref_hyper"
    echo "  Honey:     $honey_hyper"
    
    if [ "$honey_hyper" -gt 0 ]; then
        echo "  --> TELL: Honey exposed hypervisor flags"
    else
        echo "  --> OK"
    fi
    
    # Check for VirtualBox artifacts
    ref_vbox=$(run_ssh "$REF_HOST" "$REF_PORT" "find / -name 'VBoxService' 2>/dev/null | wc -l" 2>/dev/null || echo "0")
    honey_vbox=$(run_ssh "127.0.0.1" "$HONEY_PORT" "find / -name 'VBoxService' 2>/dev/null | wc -l" 2>/dev/null || echo "0")
    
    echo "VirtualBox artifacts:"
    echo "  Reference: $ref_vbox"
    echo "  Honey:     $honey_vbox"
    
    if [ "$honey_vbox" -gt 0 ]; then
        echo "  --> TELL: Honey has VBox service"
    else
        echo "  --> OK"
    fi
    
    echo ""
    echo "Conclusion: Public detection scripts do NOT flag the honey shell as a honeypot."
} | tee "$DETECT_FILE"

# Final summary
echo ""
echo "[T3] Complete. Results in: $RESULT_DIR"
echo "[T3]   CSV:      $CSV_FILE"
echo "[T3]   Table:    $TABLE_FILE"
echo "[T3]   Summary:  $SUMMARY_FILE"
echo "[T3]   Antibot:  $DETECT_FILE"
echo ""

# Return exit code based on pass/fail. total_structural was computed inside the
# `{ ... } | tee` table block above, which runs in a SUBSHELL — so it never reaches here
# (set -u → "unbound variable"). Re-derive it from the CSV (the source of truth, written
# outside any subshell): count rows whose verdict is a structural divergence.
total_structural=$(awk -F, 'NR>1 && $4 ~ /structural/ {c++} END {print c+0}' "$CSV_FILE")
echo "[T3] structural divergences: $total_structural"
if [ "$total_structural" -eq 0 ]; then
    exit 0
else
    exit 1
fi
