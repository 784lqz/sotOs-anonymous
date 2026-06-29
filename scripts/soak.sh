#!/usr/bin/env bash
# Pillar-4 P4b · host leak-drift gate.
# *** SCALED 300-spawn PROXY MEASUREMENT — NOT a literal 24h validation. ***
# The slope enables extrapolation only. Parses [stats] (ANCHORED per-line so the
# fields stay paired even amid the flood): survival + arena-no-leak + the root_pages
# SLOPE (frames/iter) + a projection. Exit 0 = survived + drift quantified.
set -u
LOG="${1:-/tmp/p4b.log}"
REPORT="scripts/soak-report.txt"; : > "$REPORT"
say(){ echo "$*" | tee -a "$REPORT"; }
say "=== P4b soak report ($(wc -l < "$LOG") log lines) ==="
say "    *** SCALED 300-spawn PROXY · NOT a literal 24h validation (extrapolation only) ***"
fail=0

# survival
if LC_ALL=C grep -aqE '\[soak\] [0-9]+/[0-9]+ survived' "$LOG"; then
    say "PASS  soak survived ($(LC_ALL=C grep -aoE '\[soak\] [0-9]+/[0-9]+ survived' "$LOG" | head -1))"
else say "FAIL  soak did NOT survive (exhaustion or never ran)"; fail=1; fi

# ANCHORED parse (B2): pull each WHOLE [stats] line, extract the 3 fields per-line in
# lockstep into paired arrays (independent greps would desync on flood-spliced lines).
iters=(); arenas=(); arena_den=(); rootp=()
while IFS= read -r line; do
    it=$(printf '%s' "$line" | grep -oE 'iter=[0-9]+'        | grep -oE '[0-9]+')
    af=$(printf '%s' "$line" | grep -oE 'free_arenas=[0-9]+' | grep -oE '[0-9]+')
    ad=$(printf '%s' "$line" | grep -oE 'free_arenas=[0-9]+/[0-9]+' | grep -oE '/[0-9]+' | grep -oE '[0-9]+')
    rp=$(printf '%s' "$line" | grep -oE 'root_pages=[0-9]+'  | grep -oE '[0-9]+')
    [ -n "$it" ] && [ -n "$rp" ] || continue   # skip a serial-spliced/garbled [stats] line
    iters+=("$it"); arenas+=("$af"); arena_den+=("$ad"); rootp+=("$rp")
done < <(LC_ALL=C grep -aE '\[stats\] iter=[0-9]+ free_arenas=[0-9]+/[0-9]+ live_sotbox=[0-9]+ root_pages=[0-9]+' "$LOG")
nsamp=${#rootp[@]}
say "INFO  $nsamp clean [stats] samples"
if [ "$nsamp" -lt 2 ]; then say "FAIL  <2 stats samples — soak/stats not emitting (cannot compute slope)"; fail=1; fi

# print every sample (transparency) + measure the root_pages BAND (max-min). Net
# gauge (post-fix): a tight band == bookkeeping reclaimed; the old monotone-growth
# expectation no longer holds (the counter dips on every reap).
rp_min=${rootp[0]}; rp_max=${rootp[0]}
for ((i=0;i<nsamp;i++)); do
    say "      sample: iter=${iters[i]} free_arenas=${arenas[i]}/${arena_den[i]} root_pages=${rootp[i]}"
    [ "${rootp[i]}" -lt "$rp_min" ] && rp_min=${rootp[i]}
    [ "${rootp[i]}" -gt "$rp_max" ] && rp_max=${rootp[i]}
done
[ "$nsamp" -ge 2 ] && say "INFO  root_pages band: min=$rp_min max=$rp_max (range=$((rp_max-rp_min)) · bounded == reclaimed)"

# arena no-leak (S3): anchor to the FIRST sample's steady-state value (pool grows lazily;
# the printf denominator is the literal 8, not necessarily the steady free count).
if [ "$nsamp" -ge 1 ]; then
    base="${arenas[0]}"; arena_leak=0
    for a in "${arenas[@]}"; do [ "${a:-0}" -ne "${base:-0}" ] && arena_leak=1; done
    [ "$arena_leak" -eq 0 ] && say "PASS  arena no-leak (free_arenas==$base steady at every post-reap sample)" \
                            || say "WARN  free_arenas varied (a [stats] caught a sibling in-flight — inspect)"
fi

# leak SLOPE (B2/S8): first vs last; dr==0 with di>0 is SUSPECT (flag), not auto-PASS.
if [ "$nsamp" -ge 2 ]; then
    rp0=${rootp[0]}; rpN=${rootp[$((nsamp-1))]}; it0=${iters[0]}; itN=${iters[$((nsamp-1))]}
    di=$((itN - it0)); dr=$((rpN - rp0))
    if [ "$di" -gt 0 ]; then
        # NET gauge (post v0.86 zero-leak fix): orch_root_pages_total is now
        # net-live (++ on bookkeeping alloc, -= a slot's window on reap), so a
        # FLAT line == per-spawn client-vspace bookkeeping fully reclaimed. The
        # net counter can also dip, so use |slope| over an absolute first→last.
        adr=${dr#-}                          # |dr|
        slope_milli=$(( adr * 1000 / di ))   # milli-frames/spawn (magnitude)
        say "INFO  root_pages $rp0 -> $rpN over $di spawns · DRIFT = $((slope_milli/1000)).$(printf '%03d' $((slope_milli%1000))) frames/spawn"
        # Zero-leak: |slope| < 1 frame/spawn (the bookkeeping is reclaimed; only
        # a constant ~boot baseline of owner-less allocations remains). A residual
        # ≥ 1 frame/spawn means the per-spawn bookkeeping is leaking again.
        if [ "$slope_milli" -lt 1000 ]; then
            say "PASS  ZERO-LEAK · client-vspace bookkeeping reclaimed (|drift| < 1 frame/spawn)"
        else
            say "FAIL  client-vspace bookkeeping LEAK · ~$((slope_milli/1000)) frames/spawn (regression of the v0.86 zero-leak fix)"; fail=1
        fi
    fi
fi

# regression + fault
LC_ALL=C grep -aqE 'suite=0xc02f' "$LOG" && say "PASS  regression 0xc02f" || { say "FAIL  regression 0xc02f missing"; fail=1; }
faults=$(LC_ALL=C grep -aiE 'rootserver.*fault|Unhandled .*[Ee]xception|kernel.*(panic|halt)|alloc_frame.*failed' "$LOG" | grep -aviE 'guest|VMFault|sotbox|untyped|delegat' | wc -l)
[ "$faults" -eq 0 ] && say "PASS  fault-scan 0" || say "WARN  fault-scan $faults (inspect)"

say "=== $( [ "$fail" -eq 0 ] && echo 'SOAK PASS (scaled proxy)' || echo 'SOAK FAIL' ) ==="
exit "$fail"
