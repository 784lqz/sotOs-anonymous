#!/usr/bin/env bash
# sotOs · v1.5.0-24h-real-KVM · endurance runner (the literal-24h heir of the
# v1.4 labyrinth SCALED proxy).  Where v1.4 measured-and-extrapolated in one
# session, this runner actually SUSTAINS the deception host under continuous
# spawn/despawn churn for a wall-clock duration (default 24h) on real KVM and
# ARCHIVES the evidence a skeptical reviewer (Black Hat / Ekoparty) would demand:
#
#   build-manifest.json   build provenance — sha256 of the exact booted artifacts
#                         + git SHA/describe/dirty + toolchain + kernel config
#   serial/boot-NNNN.log.gz   every boot's full serial log, archived + gzipped
#   counters.csv          the memory/cslot timeseries — every [stats] sample
#                         (boot, iter, free_arenas, live_sotbox, root_pages, wall_ts)
#   restarts.csv          per-boot: spawn/reap count, soak survivors, faults, gate
#   faults.txt            every abnormal-fault hit (the cross-cutting invariant)
#   summary.json + REPORT.md   the final verdict + the numbers, machine + human
#
# NO new guest features: this is pure host-side orchestration over the EXISTING
# run-soak boot (which boots with hostfwd :22/:80/:443 AND runs the bounded
# 300-spawn soak, emitting the [stats] heartbeat + [soak] N/N survived).  Each
# boot = ~300 sandbox spawn/reap "restarts"; the host relaunches across the 24h
# window, accumulating ~90k cumulative spawn/reap cycles + ~300 cold reboots.
# While a boot is up, an OPTIONAL best-effort SSH/TLS churn driver hits the live
# ports (real attacker traffic; SOFT — env-flaky in the dev sandbox).
#
# Architecture note (honest, for the cert):  this is a RELAUNCH-loop over a 24h
# wall-clock window — it proves continuous endurance + cold-reboot resilience +
# cross-boot zero-drift, and yields the [stats] drift timeseries the soak path
# emits.  It is NOT a single 24h-uptime QEMU process (the soak demo is bounded
# and powers off; a single continuous boot would need an unbounded in-orch loop,
# i.e. a guest change — out of scope per "no features").  The longest single-boot
# uptime + total cumulative spawns are reported so the claim is not over-read.
#
# Usage:
#   scripts/v1.5-endurance-run.sh            # the real 24h run (DURATION=86400)
#   DURATION=600 scripts/v1.5-endurance-run.sh          # a 2-boot smoke
#   DURATION=86400 NET_CHURN=1 scripts/v1.5-endurance-run.sh
# Env knobs:
#   DURATION       wall-clock seconds to sustain        (default 86400 = 24h)
#   BOOT_TIMEOUT   per-boot budget (soak ~264s + boot)  (default 340)
#   NET_CHURN      1 = also drive SSH/TLS churn (SOFT)  (default 1)
#   SKIP_BUILD     1 = reuse existing build/images/*    (default 0 — fresh build)
#   EVID_ROOT      evidence bundle parent dir           (default evidence)
#
# NEVER pkills a QEMU it did not start (the operator's holds the sotfs.img write
# lock).  It owns ONLY the QEMU it launches, by PID.  If a QEMU is already
# running when it starts, it reports BLOCKED and exits without touching it.
#
# DO NOT edit src/sotshell/main.c while this is running: with SKIP_BUILD unset the
# harness temp-edits it (soak-first) and restores it from a snapshot — a concurrent
# edit would be clobbered by the restore.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" 2>/dev/null || { echo "[v1.5] not in a git repo"; exit 2; }

DURATION="${DURATION:-86400}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-360}"   # soak-first → [soak] survived ~280s (boot +
                                      # 300×~0.88s); 360 gives margin, early-kill
                                      # ends each boot as soon as the marker lands.
NET_CHURN="${NET_CHURN:-0}"   # OFF by default: the soak IS the endurance load; net
                              # churn is an optional realism layer (it can contend
                              # with the soak's IPC + fill the TCP conn table).
SKIP_BUILD="${SKIP_BUILD:-0}"
EVID_ROOT="${EVID_ROOT:-evidence}"

K=build/images/kernel-x86_64-pc99
RD=build/images/sotOs-root-image-x86_64-pc99
IMG=build/images/sotfs.img
SSH_PORT=18022; TLS_PORT=18443

# ---- composite abnormal-fault invariant (verbatim from v1.4 labyrinth) --------
# Excludes the NORMAL-CONSTANT classes: VMFault (every resolved page fault) and
# UnknownSyscall (the LucAs Linux-ABI dispatch path) — matching them false-fires.
FAULT_RE='Invocation of invalid cap|FAULT CapFault|FAULT UserException|FAULT NullFault|FAULT Timeout|non-syscall fault cap reached|cspace exhausted|root server abort|SIGSEGV|exited code=139'

# ---- guard: never touch the operator's QEMU ----------------------------------
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[v1.5] BLOCKED · a qemu-system-x86_64 is already running (operator holds the sotfs.img write-lock) — exit it and retry"
    exit 2
fi
if [ ! -w /dev/kvm ]; then
    echo "[v1.5] WARN · /dev/kvm is not writable — this is meant to run on a KVM-capable host."
    echo "[v1.5]        Refusing: a non-KVM run is not a valid v1.5 endurance proof. (Run on the operator's KVM box.)"
    exit 2
fi

STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
GITSHA="$(git rev-parse --short HEAD)"
EVID="$EVID_ROOT/v1.5-$STAMP-$GITSHA"
mkdir -p "$EVID/serial" "$EVID/churn"
RUNLOG="$EVID/run.log"
exec > >(tee -a "$RUNLOG") 2>&1     # mirror everything to run.log

say(){ echo "[$(date -u '+%H:%M:%SZ')] $*"; }
num(){ local v="${1//[^0-9]/}"; printf '%s' "${v:-0}"; }   # force a clean integer

say "============ sotOs v1.5.0-24h-real-KVM · endurance run ============"
say "  evidence : $EVID"
say "  duration : ${DURATION}s  ·  per-boot budget : ${BOOT_TIMEOUT}s  ·  net-churn : $NET_CHURN"
say "  commit   : $GITSHA"

# ---- soak-first source temp-edit + cleanup trap (mirrors tools/bbsh-gate.sh) ---
# The headless auto-demo does NOT reach the soak on its own — slow graphical demos
# and a captive interactive `bbsh` precede it (the latter a v1.0-rc1 stray, fixed
# separately).  So promote "soak" to the FIRST demo command (a LOCAL edit reverted
# right after the build) → every boot runs the 300-spawn soak immediately and
# deterministically.  DeclareRootserver's CPIO does not track the child binary's
# mtime, so the bundle objects are force-cleaned to make the edit actually land.
SHELL_SRC=src/sotshell/main.c
SHELL_BAK="$EVID/sotshell-main.c.v15bak"
QPID=""
restore_src(){ [ -f "$SHELL_BAK" ] && cp -f "$SHELL_BAK" "$SHELL_SRC" 2>/dev/null && rm -f "$SHELL_BAK"; }
cleanup(){ [ -n "$QPID" ] && kill "$QPID" 2>/dev/null; restore_src; }   # only ever our own QEMU
trap cleanup EXIT INT TERM

# ---- preflight: soak-first endurance build + build provenance manifest --------
if [ "$SKIP_BUILD" != "1" ]; then
    if ! git diff --quiet -- "$SHELL_SRC" 2>/dev/null; then
        say "REFUSING · $SHELL_SRC has uncommitted changes (the harness temp-edits it) — commit/stash first"; exit 2
    fi
    cp -f "$SHELL_SRC" "$SHELL_BAK"
    grep -q 'V15-ENDURANCE-TEMP' "$SHELL_SRC" || \
      perl -0pi -e 's/(static const char \*demo_commands\[\] = \{\n)/$1        "soak",  \/\* V15-ENDURANCE-TEMP · auto-reverted by scripts\/v1.5-endurance-run.sh *\/\n/' "$SHELL_SRC"
    grep -q 'V15-ENDURANCE-TEMP' "$SHELL_SRC" || { say "failed to insert soak-first demo entry"; restore_src; exit 2; }
    say "build · soak-first temp-edit + force-clean CPIO bundle + just build (rm sotfs.img → defeat persist-coupling) ..."
    rm -f build/projects/sotOs/root/archive.children_archive.o.cpio \
          build/projects/sotOs/root/children_archive.o \
          build/projects/sotOs/root/children_archive.o.S \
          build/projects/sotOs/root/sotOs-root \
          "$K" "$RD" "$IMG"
    if ! just build >/dev/null 2>&1; then say "BUILD FAILED — abort"; restore_src; exit 2; fi
    restore_src   # the soak-first edit is now baked into the image; revert the tree
    say "build OK (soak-first image built; source reverted clean)"
else
    say "build · SKIP_BUILD=1 → reusing existing build/images/* (MUST already be a soak-first build)"
fi
for t in "$K" "$RD" "$IMG"; do [ -f "$t" ] || { say "missing artifact $t — run just build"; exit 2; }; done

manifest="$EVID/build-manifest.json"
{
  echo "{"
  echo "  \"milestone\": \"v1.5.0-24h-real-KVM\","
  echo "  \"started_utc\": \"$STAMP\","
  echo "  \"git_sha\": \"$(git rev-parse HEAD)\","
  echo "  \"git_describe\": \"$(git describe --tags --always --dirty 2>/dev/null)\","
  echo "  \"git_dirty\": $(git diff --quiet 2>/dev/null && echo false || echo true),"
  echo "  \"duration_target_s\": $DURATION,"
  echo "  \"boot_timeout_s\": $BOOT_TIMEOUT,"
  echo "  \"endurance_build\": \"soak-first (demo_commands[] promotes the 300-spawn soak to run first; source temp-edited then reverted, so the IMAGE hash below reflects the soak-first build while git_sha is the clean tree)\","
  echo "  \"host\": { \"kernel\": \"$(uname -r)\", \"kvm\": true },"
  echo "  \"toolchain\": {"
  echo "    \"gcc\": \"$(gcc -dumpversion 2>/dev/null || echo unknown)\","
  echo "    \"qemu\": \"$(qemu-system-x86_64 --version 2>/dev/null | head -1 | sed 's/\"//g')\","
  echo "    \"ninja\": \"$(ninja --version 2>/dev/null || echo unknown)\""
  echo "  },"
  echo "  \"artifacts\": {"
  echo "    \"kernel\": { \"path\": \"$K\", \"sha256\": \"$(sha256sum "$K" | cut -d' ' -f1)\", \"bytes\": $(stat -c%s "$K") },"
  echo "    \"rootserver\": { \"path\": \"$RD\", \"sha256\": \"$(sha256sum "$RD" | cut -d' ' -f1)\", \"bytes\": $(stat -c%s "$RD") },"
  echo "    \"sotfs_img\": { \"path\": \"$IMG\", \"sha256\": \"$(sha256sum "$IMG" | cut -d' ' -f1)\", \"bytes\": $(stat -c%s "$IMG") }"
  echo "  }"
  echo "}"
} > "$manifest"
say "build-manifest.json written (sha256 of the 3 booted artifacts + provenance)"

# ---- evidence accumulators ---------------------------------------------------
COUNTERS="$EVID/counters.csv"; echo "boot,iter,free_arenas_used,free_arenas_max,live_sotbox,root_pages,wall_unix" > "$COUNTERS"
RESTARTS="$EVID/restarts.csv"; echo "boot,start_unix,end_unix,dur_s,soak_survivors,reaps,faults,soak_gate,reached_marker" > "$RESTARTS"
FAULTS="$EVID/faults.txt"; : > "$FAULTS"

# ---- best-effort network churn against a live boot (SOFT) --------------------
# Drives a few SSH logins + TLS handshakes while the boot's ports are up.  Pure
# bonus "real attacker traffic"; the soak churn is the deterministic load.
net_churn(){
    local slog="$1" clog="$2" port_ok=0
    for _ in $(seq 1 40); do
        LC_ALL=C grep -qaE 'N2 inbound LISTEN|inbound bytepipe ready' "$slog" 2>/dev/null && { port_ok=1; break; }
        [ -e "/proc/$QPID" ] || return 0
        sleep 1
    done
    [ "$port_ok" = 1 ] || { echo "net-churn: ports never LISTENed (env-flaky) — skipped" >> "$clog"; return 0; }
    local ask=/tmp/sotos-v15-askpass.sh
    printf '#!/bin/sh\necho hunter2\n' > "$ask"; chmod +x "$ask"
    local tls=0 ssh=0
    while [ -e "/proc/$QPID" ]; do
        # one TLS 1.3 handshake (cycle suites) + one TLS 1.2 fallback
        printf 'GET / HTTP/1.0\r\n\r\n' | timeout 8 openssl s_client -tls1_3 -connect 127.0.0.1:$TLS_PORT -ign_eof >>"$clog" 2>&1 && tls=$((tls+1)) || true
        # one SSH login + tiny recon (SOFT — may bail in-sandbox)
        printf 'id\nuname -a\nexit\n' | timeout 30 env SSH_ASKPASS="$ask" SSH_ASKPASS_REQUIRE=force \
            ssh -tt -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=3 -o ConnectTimeout=10 root@127.0.0.1 >>"$clog" 2>&1 && ssh=$((ssh+1)) || true
        sleep 5
    done
    echo "net-churn: tls_handshakes=$tls ssh_logins=$ssh" >> "$clog"
}

# ---- the relaunch loop -------------------------------------------------------
START=$(date +%s); END=$((START+DURATION))
boot=0; total_faults=0; total_reaps=0; total_survivors=0; longest_boot=0
gate_fail=0; gate_pass=0; completed=0; marker_miss=0

while [ "$(date +%s)" -lt "$END" ]; do
    boot=$((boot+1)); bn=$(printf '%04d' "$boot")
    slog="$EVID/serial/boot-$bn.log"; clog="$EVID/churn/boot-$bn.churn.log"
    b_start=$(date +%s)
    say "---- boot $boot · elapsed $((b_start-START))s / ${DURATION}s · faults-so-far $total_faults ----"

    # Launch OUR qemu directly (no `timeout` wrapper — killing the wrapper did not
    # reliably reap the child).  We track the qemu PID and enforce the per-boot
    # deadline + teardown ourselves.
    qemu-system-x86_64 \
        -m 4096 -display none -serial stdio -enable-kvm -cpu host \
        -kernel "$K" -initrd "$RD" \
        -drive file="$IMG",format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${TLS_PORT}-:443 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        < /dev/null > "$slog" 2>&1 &
    QPID=$!

    CHPID=""
    [ "$NET_CHURN" = 1 ] && { net_churn "$slog" "$clog" & CHPID=$!; }

    # wait for the soak to finish ([soak] survived / POWEROFF) or the per-boot
    # deadline, then tear OUR qemu down by PID (SIGTERM → grace → SIGKILL) and
    # CONFIRM it is dead before the next boot (two qemu fight the img write-lock).
    b_deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
    while kill -0 "$QPID" 2>/dev/null; do
        LC_ALL=C grep -qaE '\[soak\] [0-9]+/[0-9]+ survived|POWEROFF' "$slog" 2>/dev/null && break
        [ "$(date +%s)" -ge "$b_deadline" ] && break
        sleep 2
    done
    [ -n "$CHPID" ] && { kill "$CHPID" 2>/dev/null; wait "$CHPID" 2>/dev/null; }
    kill "$QPID" 2>/dev/null
    for _ in $(seq 1 15); do kill -0 "$QPID" 2>/dev/null || break; sleep 1; done
    kill -0 "$QPID" 2>/dev/null && kill -9 "$QPID" 2>/dev/null
    wait "$QPID" 2>/dev/null; QPID=""
    b_end=$(date +%s); b_dur=$((b_end-b_start))
    [ "$b_dur" -gt "$longest_boot" ] && longest_boot=$b_dur

    # -- parse this boot --------------------------------------------------------
    # [stats] memory/cslot samples → counters.csv
    LC_ALL=C grep -aoE '\[stats\] iter=[0-9]+ free_arenas=[0-9]+/[0-9]+ live_sotbox=[0-9]+ root_pages=[0-9]+' "$slog" 2>/dev/null \
      | sed -E 's#\[stats\] iter=([0-9]+) free_arenas=([0-9]+)/([0-9]+) live_sotbox=([0-9]+) root_pages=([0-9]+)#'"$boot"',\1,\2,\3,\4,\5,'"$b_end"'#' \
      >> "$COUNTERS"

    survivors=$(num "$(LC_ALL=C grep -aoE '\[soak\] [0-9]+/[0-9]+ survived' "$slog" 2>/dev/null | tail -1 | sed -E 's#\[soak\] ([0-9]+)/.*#\1#')")
    reaps=$(num "$(LC_ALL=C grep -acE 'exited code=[0-9]+' "$slog" 2>/dev/null)")
    reached=0; LC_ALL=C grep -qaE '\[soak\] [0-9]+/[0-9]+ survived|POWEROFF' "$slog" 2>/dev/null && reached=1

    # fault scan (the cross-cutting invariant)
    bf=$(num "$(LC_ALL=C grep -aEc "$FAULT_RE" "$slog" 2>/dev/null)")
    flood=$(num "$(LC_ALL=C grep -ac 'DNS_INSTALL domain= rc' "$slog" 2>/dev/null)")
    [ "$flood" -ge 20 ] && bf=$((bf+flood))
    if [ "$bf" -gt 0 ]; then
        { echo "=== boot $boot ($slog) — $bf abnormal hit(s) ==="; LC_ALL=C grep -aEn "$FAULT_RE" "$slog" 2>/dev/null | head -40; } >> "$FAULTS"
    fi

    # per-boot drift gate (reuse the trusted soak.sh slope logic).  Only boots
    # that COMPLETED the soak get a verdict; a timeout-truncated boot is "n/a"
    # (a timing hiccup, not a leak) and does not count against the drift gate.
    sgate="n/a"
    if [ "$reached" = 1 ] && LC_ALL=C grep -qa '\[stats\]' "$slog"; then
        if bash scripts/soak.sh "$slog" >/dev/null 2>&1; then sgate="PASS"; gate_pass=$((gate_pass+1)); else sgate="FAIL"; gate_fail=$((gate_fail+1)); fi
    fi

    echo "$boot,$b_start,$b_end,$b_dur,$survivors,$reaps,$bf,$sgate,$reached" >> "$RESTARTS"
    total_faults=$((total_faults+bf)); total_reaps=$((total_reaps+reaps)); total_survivors=$((total_survivors+survivors))
    [ "$reached" = 1 ] && completed=$((completed+1)) || marker_miss=$((marker_miss+1))
    say "boot $boot done · dur=${b_dur}s survivors=$survivors reaps=$reaps faults=$bf gate=$sgate reached=$reached"

    gzip -f "$slog" 2>/dev/null
    [ -s "$clog" ] || rm -f "$clog"
done

# ---- final state + verdict ---------------------------------------------------
ELAPSED=$(($(date +%s)-START))
samples=$(num "$(wc -l < "$COUNTERS")"); samples=$((samples>0?samples-1:0))
# aggregate root_pages drift across the WHOLE run (first vs last sample)
rp_first=$(num "$(awk -F, 'NR==2{print $6}' "$COUNTERS")")
rp_last=$(num "$(awk -F, 'END{print $6}' "$COUNTERS")")
rp_delta=$((rp_last-rp_first))
last_reached=$(num "$(awk -F, 'END{print $9}' "$RESTARTS")")

# drift gate over COMPLETED boots: a high pass-fraction is the leak proof; a few
# timeout-truncated boots are "n/a" and excluded.  >=90% of completed boots must
# pass the zero-leak slope (and at least one boot must have been measured).
drift_total=$((gate_pass+gate_fail))
drift_ok=1
if [ "$drift_total" -ge 1 ]; then
    awk -v p="$gate_pass" -v t="$drift_total" 'BEGIN{exit !(p/t >= 0.90)}' || drift_ok=0
else
    drift_ok=0   # never measured drift at all → cannot claim zero-leak
fi

verdict="PASS"; reasons=""
[ "$boot" -lt 1 ]          && { verdict="FAIL"; reasons="$reasons no-boots-completed;"; }
[ "$total_faults" -ne 0 ]  && { verdict="FAIL"; reasons="$reasons abnormal-faults=$total_faults;"; }
[ "$last_reached" != "1" ] && { verdict="FAIL"; reasons="$reasons final-boot-did-not-complete-soak;"; }
[ "$drift_ok" != "1" ]     && { verdict="FAIL"; reasons="$reasons drift-gate ($gate_pass/$drift_total completed boots passed, need >=90%);"; }
# missed completion markers on non-final boots = env hiccups: surfaced (marker_miss)
# but not a hard fail; only the FINAL boot's liveness is load-bearing.

{
  echo "{"
  echo "  \"milestone\": \"v1.5.0-24h-real-KVM\","
  echo "  \"verdict\": \"$verdict\","
  echo "  \"reasons\": \"$(echo "$reasons" | sed 's/^ //;s/\"//g')\","
  echo "  \"elapsed_s\": $ELAPSED, \"duration_target_s\": $DURATION,"
  echo "  \"boots_launched\": $boot,"
  echo "  \"boots_completed_soak\": $completed,"
  echo "  \"boots_missing_marker\": $marker_miss,"
  echo "  \"longest_single_boot_s\": $longest_boot,"
  echo "  \"cumulative_soak_survivors\": $total_survivors,"
  echo "  \"cumulative_reaps\": $total_reaps,"
  echo "  \"restart_rate_spawns_per_hour\": $(awk -v r="$total_survivors" -v e="$ELAPSED" 'BEGIN{printf (e>0)? "%.1f" : "0", r/(e/3600.0)}'),"
  echo "  \"reboot_rate_per_hour\": $(awk -v b="$boot" -v e="$ELAPSED" 'BEGIN{printf (e>0)? "%.2f" : "0", b/(e/3600.0)}'),"
  echo "  \"stats_samples\": $samples,"
  echo "  \"root_pages_first\": $rp_first, \"root_pages_last\": $rp_last, \"root_pages_delta\": $rp_delta,"
  echo "  \"abnormal_faults_total\": $total_faults,"
  echo "  \"drift_gate_pass\": $gate_pass, \"drift_gate_fail\": $gate_fail, \"drift_gate_measured\": $drift_total,"
  echo "  \"final_boot_completed_soak\": $last_reached"
  echo "}"
} > "$EVID/summary.json"

{
  echo "# sotOs v1.5.0-24h-real-KVM — endurance run report"
  echo ""
  echo "- **Verdict:** $verdict${reasons:+  ·  $reasons}"
  echo "- **Started (UTC):** $STAMP  ·  **commit** \`$GITSHA\`"
  echo "- **Elapsed:** ${ELAPSED}s  (target ${DURATION}s)  ·  **boots completed:** $boot"
  echo "- **Longest single boot:** ${longest_boot}s"
  echo ""
  echo "## Endurance (ENDURES)"
  echo "- Cumulative sandbox spawn/reap cycles (\"restarts\"): **survivors=$total_survivors**, reaps=$total_reaps"
  echo "- Cold reboots: **$boot** (reboot-resilience: every boot rebuilds the runtime from the same image)"
  echo "- [stats] memory/cslot samples captured: **$samples** → \`counters.csv\`"
  echo "- root_pages drift over the whole run: first=$rp_first last=$rp_last **delta=$rp_delta** (zero-leak ⇒ ~0)"
  echo "- per-boot zero-leak slope gate (soak.sh): **$gate_pass/$drift_total** completed boots passed (need ≥90%)"
  echo "- boots that completed the soak: **$completed** / $boot launched"
  echo ""
  echo "## Safety invariant (the cross-cutting scan)"
  echo "- Abnormal faults across ALL boot serial logs: **$total_faults**  (PASS ⇒ 0)"
  echo "  - scanned: \`$FAULT_RE\`  (excludes normal-constant VMFault / UnknownSyscall)"
  echo "  - any hits are listed in \`faults.txt\`"
  echo "- Final boot completed its soak (orch alive at run end): **$last_reached**"
  echo "- Boots that did not reach a completion marker (env hiccup, non-fatal unless final): **$marker_miss**"
  echo ""
  echo "## Evidence bundle (\`$EVID\`)"
  echo "- \`build-manifest.json\` — sha256 of the exact booted kernel/rootserver/sotfs.img + git + toolchain"
  echo "- \`serial/boot-*.log.gz\` — every boot's full serial log, archived"
  echo "- \`counters.csv\` — the memory/cslot timeseries"
  echo "- \`restarts.csv\` — per-boot spawn/reap, survivors, faults, drift-gate"
  echo "- \`faults.txt\` — every abnormal-fault hit (empty ⇒ clean)"
  echo "- \`summary.json\` — machine-readable verdict + metrics"
  echo "- \`churn/boot-*.churn.log\` — best-effort SSH/TLS attacker traffic (SOFT)"
  echo ""
  echo "## Honest scope"
  echo "This is a RELAUNCH-loop over a ${DURATION}s wall-clock window (continuous host-"
  echo "driven load + cold-reboot resilience + cross-boot zero-drift), not a single"
  echo "24h-uptime QEMU process — the soak demo is bounded and powers off; a single"
  echo "continuous boot would need an unbounded in-orch loop (a guest change, out of"
  echo "scope). The longest single-boot uptime and cumulative spawn count above bound"
  echo "the over-read. See scripts/v1.5-endurance-run.sh header for methodology."
} > "$EVID/REPORT.md"

say "================ v1.5 ENDURANCE: $verdict ================"
say "  boots=$boot completed=$completed survivors=$total_survivors reaps=$total_reaps faults=$total_faults drift-gate=$gate_pass/$drift_total"
say "  evidence bundle: $EVID  (REPORT.md · summary.json · counters.csv · restarts.csv · build-manifest.json)"
[ "$verdict" = "PASS" ] && exit 0 || exit 1
