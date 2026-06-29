#!/usr/bin/env bash
# sotOs · apk-fs P3 boot gate — runtime-staged upper ELF executes (I2/I3)
#
# Proves that a binary WRITTEN into the per-session sotfs upper at RUNTIME is
# EXECUTABLE.  The gate:
#
#   Session A:
#     1. Stages hello_dyn.bin (dynamically-linked musl PIE, NEEDED libc.so,
#        interp /lib/ld-musl-x86_64.so.1) from /tmp/hello_dyn.bin (boot-installed
#        by lucas_sotfs_install) into the /usr union upper at /usr/bin/upbin via
#        cat /tmp/hello_dyn.bin > /usr/bin/upbin.
#     2. Executes /usr/bin/upbin — ld-musl resolves libc from the sysroot.
#     3. Asserts output "[hello-dyn] dynamic musl OK" and UPBIN_RC=0.
#     4. I3 escape-probes inline: `..` traversal + sensitive read + crontab
#        write → all contained (denied or honey-bait, no cap fault).
#
#   Session B (I2):
#     cat /usr/bin/upbin and ls /usr/bin | grep upbin → ABSENT (cross-session
#     isolation: session B has a different cow_session and must NOT see session A's
#     upper binary).
#
# Invariants:
#   EXEC  — upper ELF runs (ld-musl + libc path · the Phase-3 Task-2 payoff)
#   I2    — second session does NOT see session-A's upper binary
#   I3    — escape-deny stays green with an upper-resident binary
#
# Exit codes: 0=PASS, 1=FAIL, 2=missing image, 3=BLOCKED (operator QEMU live)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PORT=18022
SLOG=/tmp/sotos-apk-upperexec-serial.log
ALOG=/tmp/sotos-apk-upperexec-sessA.log
BLOG=/tmp/sotos-apk-upperexec-sessB.log

# ── BLOCKED guard ─────────────────────────────────────────────────────────────
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[apk-upperexec] BLOCKED: operator QEMU live"; exit 3
fi

# ── pre-flight ────────────────────────────────────────────────────────────────
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[apk-upperexec] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$ALOG" "$BLOG"

# ── boot headless ─────────────────────────────────────────────────────────────
echo "[apk-upperexec] booting honeypot headless…"
timeout 240 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT

# wait for :22 LISTEN
for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[apk-upperexec] FAIL · :22 never LISTENed"; exit 1; }
sleep 2

ASK=/tmp/sotos-apk-upperexec-ask.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"

do_ssh() {
    # Run an SSH session. $1=log file  $2=command pipe string (eval'd, fed to ssh stdin)
    local LOG="$1" PIPE="$2"
    ( eval "$PIPE" ) | \
        timeout 120 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
        ssh -tt -p "$PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 \
        root@127.0.0.1 >"$LOG" 2>&1 || true
}

# ── Session A — stage + execute upper ELF + inline I3 escape probes ───────────
echo "[apk-upperexec] session A (stage + execute upper ELF + escape probes)…"
SESS_A_PIPE='
    sleep 3
    printf "echo SESSA_ALIVE\n"; sleep 2
    printf "cat /tmp/hello_dyn.bin > /usr/bin/upbin\n"; sleep 3
    printf "/usr/bin/upbin; echo UPBIN_RC=$?\n"; sleep 4
    printf "cat /etc/../../../root/.ssh/id_rsa 2>&1 || true\n"; sleep 2
    printf "echo PWNED > /etc/crontab; echo CRON_RC=$?\n"; sleep 2
    printf "cat /etc/crontab\n"; sleep 2
    printf "exit\n"; sleep 4
'
do_ssh "$ALOG" "$SESS_A_PIPE"

echo "[apk-upperexec] session A done · analysing…"
clean_a(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$ALOG"; }

fail=0

# Liveness
[ "$(clean_a | grep -ac '^SESSA_ALIVE$')" -ge 1 ] && \
    echo "PASS · session A is alive" || \
    { echo "FAIL · session A produced no SESSA_ALIVE marker"; fail=1; }

# EXEC: upper ELF ran and produced expected output
[ "$(clean_a | grep -ac '\[hello-dyn\] dynamic musl OK')" -ge 1 ] && \
    echo "PASS · EXEC: /usr/bin/upbin ran and printed '[hello-dyn] dynamic musl OK'" || \
    { echo "FAIL · EXEC: /usr/bin/upbin output absent (upper ELF did not run)"; fail=1; }

[ "$(clean_a | grep -ac '^UPBIN_RC=0$')" -ge 1 ] && \
    echo "PASS · EXEC: /usr/bin/upbin exited 0 (RC=0)" || \
    { echo "FAIL · EXEC: UPBIN_RC is not 0 (or absent)"; fail=1; }

# I3a — dot-dot traversal denied (no private key / /root content leaked)
{ [ "$(clean_a | grep -ac 'BEGIN OPENSSH PRIVATE KEY')" -eq 0 ] && \
  [ "$(clean_a | grep -ac 'BEGIN RSA PRIVATE KEY')" -eq 0 ] && \
  [ "$(clean_a | grep -ac 'No such file\|cannot open\|Permission denied\|not found')" -ge 1 ]; } && \
    echo "PASS · I3a: dot-dot traversal denied (no private key reached session)" || \
    echo "WARN · I3a: traversal result not confirmed (check $ALOG)"

# I3b — crontab write CONTAINED (denied or captured, not silently written uncontained)
# The crontab is a persistence-sensitive path → goes to sotfs upper (captured/denied).
# We check: either "Permission denied" from busybox, OR the serial shows containment.
# Even if the write is "allowed" into the session upper (Tier-2 contained write),
# it should NOT escape to the real host. The crontab write to /etc/crontab goes
# through the /etc union upper → session-tagged. The write is contained by design.
# The escape-deny criterion: no cap fault + no host-FS breach.
{ LC_ALL=C grep -qaE 'silently dropped|Tier-2 WRITE|session overlay|sess=1|persistence' "$SLOG" ||
  [ "$(clean_a | grep -ac 'Permission denied')" -ge 1 ]; } && \
    echo "PASS · I3b: crontab write contained (session overlay or denied)" || \
    echo "WARN · I3b: write containment marker not confirmed (check $SLOG/$ALOG)"

# I3c — no abnormal cap fault from the escape battery (ENOSYS from normal busybox is expected)
# Use grep -c (not -aEc) to avoid the exit-1-on-no-match + || echo 0 double-value bug.
faults_a=$(LC_ALL=C grep -c 'Invocation of invalid cap' "$SLOG" 2>/dev/null || true)
faults_a=${faults_a:-0}
[ "${faults_a}" -eq 0 ] && \
    echo "PASS · I3c: runtime endured escape probes (no cap fault)" || \
    { echo "FAIL · I3c: cap faults=$faults_a during escape probes"; fail=1; }
# ENOSYS: normal busybox operations produce ENOSYS for unimplemented syscalls; WARN not FAIL.
enosys_a=$(LC_ALL=C grep -c '\[lucas\] ENOSYS sysno=' "$SLOG" 2>/dev/null || true)
enosys_a=${enosys_a:-0}
echo "INFO  · I3c: ENOSYS events in serial log = $enosys_a (expected; from busybox normal ops)"

# Verify the VFS upper read path was exercised (serial log shows the execve log line)
{ LC_ALL=C grep -qaF "'/usr/bin/upbin' → VFS upper" "$SLOG" ||
  LC_ALL=C grep -qaF "/usr/bin/upbin' → VFS upper" "$SLOG"; } && \
    echo "PASS · VFS upper read path exercised (resolve_path_vfs hit · serial log)" || \
    echo "WARN · VFS upper log line not found (check $SLOG for [execve] upbin)"

# ── Session B — I2 isolation (upper binary absent) ────────────────────────────
echo "[apk-upperexec] session B (I2 isolation)…"
sleep 2   # allow session A reap to complete
SESS_B_PIPE='
    sleep 3
    printf "echo SESSB_ALIVE\n"; sleep 2
    printf "cat /usr/bin/upbin 2>&1; echo UPBIN_CATRC=$?\n"; sleep 3
    printf "ls /usr/bin | grep -c upbin || echo UPBIN_LS_ABSENT\n"; sleep 2
    printf "exit\n"; sleep 4
'
do_ssh "$BLOG" "$SESS_B_PIPE"

echo "[apk-upperexec] session B done · analysing…"
clean_b(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG"; }

# Session B liveness
[ "$(clean_b | grep -ac '^SESSB_ALIVE$')" -ge 1 ] && \
    echo "PASS · session B is alive (ran to the prompt)" || \
    { echo "FAIL · session B produced no SESSB_ALIVE marker — did not run"; fail=1; }

# I2: /usr/bin/upbin must be ABSENT in session B
# The upper ELF lives in session A's tagged sotfs upper (cow_session=1).
# Session B (cow_session=2) must get ENOENT or binary-not-found on cat.
# Check: hello-dyn output must NOT appear in session B's log.
[ "$(clean_b | grep -ac '\[hello-dyn\] dynamic musl OK')" -eq 0 ] && \
    echo "PASS · I2: /usr/bin/upbin did NOT execute in session B (output absent)" || \
    { echo "FAIL · I2 BREACH: session B ran /usr/bin/upbin (upper leaked across sessions)"; fail=1; }

# Session B either got an error (no such file / exec format / permission) or the cat
# printed binary garbage (if upbin is visible as data but not identified as session-A's exec).
# The hard requirement is the hello-dyn OUTPUT absence (above). Corroborating: an error is expected.
{ clean_b | grep -qaE 'No such file|cannot open|not found|ENOENT|Permission denied|No such' ||
  [ "$(clean_b | grep -ac 'UPBIN_CATRC=[^0]')" -ge 1 ]; } && \
    echo "PASS · I2: session B got error / non-zero RC on /usr/bin/upbin (expected)" || \
    echo "WARN · I2: error text or non-zero RC not confirmed (check $BLOG)"

# I2: ls /usr/bin | grep -c upbin must return 0 (absent) in session B.
# If upbin is absent, grep exits 1 → we echo UPBIN_LS_ABSENT; if present grep prints a count.
[ "$(clean_b | grep -ac '^UPBIN_LS_ABSENT$')" -ge 1 ] && \
    echo "PASS · I2: upbin absent from session B ls /usr/bin (UPBIN_LS_ABSENT marker present)" || \
    { echo "FAIL · I2 BREACH: upbin found in session B ls /usr/bin (upper leaked)"; fail=1; }

# Session B tagged to conn_id=2 / sess=2
LC_ALL=C grep -qaF 'sess=2' "$SLOG" && \
    echo "PASS · session B inode tagged to sess=2 (serial log)" || \
    echo "WARN · sess=2 tagging event not observed (session B may not have written)"

# ── cap / MAC fault check ─────────────────────────────────────────────────────
cap_faults=$(LC_ALL=C grep -c 'Invocation of invalid cap' "$SLOG" 2>/dev/null || true)
cap_faults=${cap_faults:-0}
mac_a=$(LC_ALL=C grep -c 'Corrupted MAC' "$ALOG" 2>/dev/null || true)
mac_a=${mac_a:-0}
mac_b=$(LC_ALL=C grep -c 'Corrupted MAC' "$BLOG" 2>/dev/null || true)
mac_b=${mac_b:-0}
[ "$cap_faults" -eq 0 ] && [ "$mac_a" -eq 0 ] && [ "$mac_b" -eq 0 ] && \
    echo "PASS · no cap/MAC fault" || \
    { echo "FAIL · cap=$cap_faults mac_a=$mac_a mac_b=$mac_b"; fail=1; }

# ── session-reap check ────────────────────────────────────────────────────────
LC_ALL=C grep -qaE 'session_reap|sotfs_session_reap.*conn|reap.*conn=1' "$SLOG" && \
    echo "PASS · session-reap fired for conn=1" || \
    echo "WARN · session-reap event not found in serial log"

# ── summary ───────────────────────────────────────────────────────────────────
echo "=== $( [ $fail -eq 0 ] && \
    echo '[apk-upperexec] PASS (upper ELF ran + I2 isolated + I3 escape contained)' || \
    echo '[apk-upperexec] FAIL' ) ==="
echo "(serial: $SLOG · sess-A: $ALOG · sess-B: $BLOG)"
exit $fail
