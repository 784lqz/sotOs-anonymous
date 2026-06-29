#!/usr/bin/env bash
# sotOs · apk-fs P2 boot gate — cross-mount containment (I1/I2)
#
# Proves that Tier-2 SSH session writes/creates across union backends land in a
# per-session-tagged sotfs upper and are NOT visible to a second session.
#
# Backend coverage (both via shell-builtin echo/cat — avoids forked-child
# tier-promotion race that affects external commands like mkdir):
#   /usr/newfile  → /usr union sotfs upper  (backends_union_ops + backends_sotfs)
#   /etc/newfile  → /etc union sotfs upper  (backends_union_ops + backends_sotfs)
#
# NOTE: /usr/bin/newfile and /etc/apk/world are not tested here because:
#  - /usr/bin/newfile needs a parent mkdir of /bin in the usr-upper; op_mkdir
#    in backends_sotfs lacks the cow_session bypass that op_open has (P2 gap).
#  - /etc/apk/world needs a parent mkdir of /etc/apk, same issue.
#  - Direct children (/usr/newfile, /etc/newfile) avoid any parent mkdir.
# NOTE: /opt/x mkdir is not tested because the external mkdir(1) command runs
#   as a forked child at tier=0 before the anomaly-ext tier-promotion fires;
#   tier2_route_session() returns 0 for that child → -EROFS.  The static
#   backend P2 route (Task 5) is covered by the host unit test instead.
#
# Invariants proved:
#   In-session coherence: session A reads back its own writes (the sotfs
#     upper is visible to the owning session).
#   I2 (isolation): session B does NOT see session A's creates. Session B has
#     a different cow_session and hits the SAME inode_hidden_from_caller()
#     gate.  Note: the server-side SHELL_IN ring reset is also corrected here
#     (fix in main.c: reset to ring->w not 0) so session B sees only its own
#     keystrokes.
#   I1 (structural): no clean operator SSH probe; covered structurally by the
#     same inode_hidden_from_caller() gate + host unit (served(owned,0)==0).
#     The session-reap after disconnect also ensures the next session/operator
#     sees pristine base.
#
# Exit codes: 0=PASS, 1=FAIL, 2=missing image, 3=BLOCKED (operator QEMU live)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PORT=18022
SLOG=/tmp/sotos-apk-union-serial.log
ALOG=/tmp/sotos-apk-union-sessA.log
BLOG=/tmp/sotos-apk-union-sessB.log

# ── BLOCKED guard ─────────────────────────────────────────────────────────────
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[apk-union-gate] BLOCKED: operator QEMU live"; exit 3
fi

# ── pre-flight ────────────────────────────────────────────────────────────────
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[apk-union-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$ALOG" "$BLOG"

# ── boot headless ─────────────────────────────────────────────────────────────
echo "[apk-union-gate] booting honeypot headless…"
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
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[apk-union-gate] FAIL · :22 never LISTENed"; exit 1; }
sleep 2

ASK=/tmp/sotos-apk-union-ask.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"

do_ssh() {
    # Run an SSH session. Commands are passed as a SINGLE argument (the pipe script).
    # $1 = log file   $2 = command pipe string (sent char by char to ssh stdin)
    local LOG="$1" PIPE="$2"
    ( eval "$PIPE" ) | \
        timeout 80 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
        ssh -tt -p "$PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 \
        root@127.0.0.1 >"$LOG" 2>&1 || true
}

# ── Session A — create + read-back ────────────────────────────────────────────
echo "[apk-union-gate] session A (write + in-session read-back)…"
SESS_A_PIPE='
    sleep 3
    printf "echo hi > /usr/newfile\n"; sleep 2
    printf "cat /usr/newfile\n"; sleep 2
    printf "echo etcdata > /etc/newfile\n"; sleep 2
    printf "cat /etc/newfile\n"; sleep 2
    printf "mkdir /usr/gdir\n"; sleep 2
    printf "ls /usr\n"; sleep 2
    printf "exit\n"; sleep 4
'
do_ssh "$ALOG" "$SESS_A_PIPE"

echo "[apk-union-gate] session A done · analysing…"
# Strip ANSI/VT escape codes + CR from log before grepping
clean_a(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$ALOG"; }

fail=0
[ "$(clean_a | grep -ac '^hi$')" -ge 1 ] && \
    echo "PASS · /usr/newfile in-session read-back (hi)" || \
    { echo "FAIL · /usr/newfile in-session read-back"; fail=1; }

[ "$(clean_a | grep -ac '^etcdata$')" -ge 1 ] && \
    echo "PASS · /etc/newfile in-session read-back (etcdata)" || \
    { echo "FAIL · /etc/newfile in-session read-back"; fail=1; }

# G2 · session A mkdir /usr/gdir must appear in session A's own ls output
# (proves the contained mkdir is visible in-session — in-session coherence).
[ "$(clean_a | grep -ac 'gdir')" -ge 1 ] && \
    echo "PASS · G2: /usr/gdir visible in session A (mkdir in-session coherence)" || \
    { echo "FAIL · G2: /usr/gdir not visible in session A"; fail=1; }

# Verify via serial log that session A's writes were CONTAINED.  Two containment
# paths exist depending on whether the target path already resolves to a base
# inode: a brand-new file takes the session-CREATE path ("sess=1 ... tagged"),
# while an existing path takes the COW-overlay WRITE path ("→ session overlay
# (base intact)").  Whether /usr/newfile|/etc/newfile is new vs existing is
# image/state-dependent, so accept EITHER as proof of containment (the hard I1/I2
# proof lives in the read-back + I2-absence asserts; this is a corroborating
# observation, kept WARN-only so its path-dependence can't false-fail the gate).
{ LC_ALL=C grep -qaF 'sess=1' "$SLOG" ||
  LC_ALL=C grep -qaE 'tier=2 · sotfs write inode=.* → session overlay' "$SLOG"; } && \
    echo "PASS · session A writes contained (session upper / overlay · base intact)" || \
    echo "WARN · session A containment event not observed in serial log"

# ── Session B — I2 isolation check ────────────────────────────────────────────
# After session A exits, lucas_sotfs_session_reap(1) fires (reaped).
# Session B (conn_id=2, cow_session=2) must NOT see session A's files.
# The shell_in_rd ring-reset fix (main.c: reset to ring->w not 0) ensures
# session B doesn't re-read session A's stale keystrokes.
echo "[apk-union-gate] session B (I2 isolation)…"
sleep 2   # allow reap to complete
SESS_B_PIPE='
    sleep 3
    printf "echo SESSB_ALIVE\n"; sleep 2
    printf "echo bdata > /usr/bfile\n"; sleep 2
    printf "cat /usr/bfile\n"; sleep 2
    printf "cat /usr/newfile 2>&1\n"; sleep 2
    printf "cat /etc/newfile 2>&1\n"; sleep 2
    printf "ls /usr\n"; sleep 2
    printf "exit\n"; sleep 4
'
do_ssh "$BLOG" "$SESS_B_PIPE"

echo "[apk-union-gate] session B done · analysing…"
clean_b(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG"; }

# Session B must prove it actually ran (else the I2 "absent" checks below are
# vacuously true on an empty log — silent-session false-green).
[ "$(clean_b | grep -ac '^SESSB_ALIVE$')" -ge 1 ] && \
    echo "PASS · session B is alive (ran to the prompt)" || \
    { echo "FAIL · session B produced no SESSB_ALIVE marker — did not run"; fail=1; }

# Session B's OWN contained write must read back (proves the create path works
# in B's context + B is exercising the same upper, so the I2 absence is meaningful).
[ "$(clean_b | grep -ac '^bdata$')" -ge 1 ] && \
    echo "PASS · session B own write /usr/bfile reads back (bdata)" || \
    { echo "FAIL · session B own write did not read back"; fail=1; }

# Session B must NOT see hi or etcdata
[ "$(clean_b | grep -ac '^hi$')" -eq 0 ] && \
    echo "PASS · I2: /usr/newfile content absent in session B" || \
    { echo "FAIL · I2 BREACH: session B sees /usr/newfile=hi"; fail=1; }

[ "$(clean_b | grep -ac '^etcdata$')" -eq 0 ] && \
    echo "PASS · I2: /etc/newfile content absent in session B" || \
    { echo "FAIL · I2 BREACH: session B sees /etc/newfile=etcdata"; fail=1; }

# G2 · session A's mkdir /usr/gdir must be ABSENT in session B's ls /usr
# (proves external mkdir containment — the G2 regression check).
[ "$(clean_b | grep -ac 'gdir')" -eq 0 ] && \
    echo "PASS · G2: /usr/gdir absent in session B (mkdir contained · G2 fixed)" || \
    { echo "FAIL · G2 BREACH: session B sees /usr/gdir (mkdir containment escape)"; fail=1; }

# Session B must get an error for both paths (ENOENT or similar)
{ LC_ALL=C grep -qaE 'No such file|cannot open|not found|ENOENT|permission' "$BLOG" ||
  clean_b | grep -qaE 'No such file|cannot open|not found|ENOENT|permission'; } && \
    echo "PASS · I2: session B got expected error (absent paths)" || \
    echo "WARN · I2: error text not confirmed (see $BLOG)"

# Verify session B was tagged to conn_id=2 / sess=2
LC_ALL=C grep -qaF 'sess=2' "$SLOG" && \
    echo "PASS · session B inode tagged to sess=2 (serial log)" || \
    echo "WARN · sess=2 tagging event not observed (session B may not have written)"

# ── session-reap check ────────────────────────────────────────────────────────
LC_ALL=C grep -qaE 'session_reap|sotfs_session_reap.*conn|reap.*conn=1' "$SLOG" && \
    echo "PASS · session-reap fired for conn=1 (operator sees pristine base)" || \
    echo "WARN · session-reap event not found in serial log (check spelling)"

# ── fault check ───────────────────────────────────────────────────────────────
# Note: grep -c always prints a count (even "0") and exits 1 on no match.
# Using "|| true" instead of "|| echo 0" avoids the double-value "0\n0" bug
# that occurs when grep prints "0" AND the fallback "echo 0" both fire.
cap_faults=$(LC_ALL=C grep -c 'Invocation of invalid cap' "$SLOG" 2>/dev/null || true)
cap_faults=${cap_faults:-0}
mac_a=$(LC_ALL=C grep -c 'Corrupted MAC' "$ALOG" 2>/dev/null || true)
mac_a=${mac_a:-0}
mac_b=$(LC_ALL=C grep -c 'Corrupted MAC' "$BLOG" 2>/dev/null || true)
mac_b=${mac_b:-0}
[ "$cap_faults" -eq 0 ] && [ "$mac_a" -eq 0 ] && [ "$mac_b" -eq 0 ] && \
    echo "PASS · no cap/MAC fault" || \
    { echo "FAIL · cap=$cap_faults mac_a=$mac_a mac_b=$mac_b"; fail=1; }

# ── summary ───────────────────────────────────────────────────────────────────
echo "=== $( [ $fail -eq 0 ] && \
    echo 'apk-union-gate: PASS (in-session coherence + I2 isolation)' || \
    echo 'apk-union-gate: FAIL' ) ==="
echo "(serial: $SLOG · sess-A: $ALOG · sess-B: $BLOG)"
exit $fail
