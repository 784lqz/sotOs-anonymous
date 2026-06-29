#!/usr/bin/env bash
# sotOs · turnkey SSH DECEPTION DEMO.
#
#   bash tools/demo-ssh.sh            # STANDALONE: boot a host + attack it + narrate both views
#   bash tools/demo-ssh.sh attack     # COMBO: attack an ALREADY-RUNNING instance (your
#                                     #   `just run-interactive` window) — no boot, no kill.
#                                     #   Watch the operator window (F12 → `watch`) for the
#                                     #   live TRUTH feed while this drives the attacker.
#
# Narrates the two views that make the demo land:
#   • THE LIE   — what the attacker saw   (client transcript: honey accounts,
#                 fake prod hostname, "Permission denied" on tamper)
#   • THE TRUTH — what sotOs did/recorded (serial: SSH persona + credential
#                 capture, canary reads = bait taken, write containment)
# STANDALONE is self-verifying: PASS iff the host DECEIVED + CONTAINED + RECORDED.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

MODE="${1:-standalone}"
PORT=18022
SLOG=/tmp/sotos-demo-ssh-serial.log     # the operator's view (serial · standalone only)
CLOG=/tmp/sotos-demo-ssh-client.log     # the attacker's view (ssh client)
ASK=/tmp/sotos-demo-askpass.sh

if [ -t 1 ]; then B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; Z=$'\e[0m'
else B=; DIM=; R=; G=; Y=; C=; Z=; fi
say(){ printf '%s\n' "$*"; }
rule(){ printf '%s\n' "════════════════════════════════════════════════════════════════"; }
rm -f "$CLOG"

rule; say "${B}  sotOs · SSH DECEPTION DEMO${Z}  ${DIM}(${MODE})${Z}"; rule

if [ "$MODE" = attack ]; then
  # COMBO · attack an already-running instance (operator's run-interactive).
  # NB: do NOT pre-probe the port with a bare TCP connect — a half-open connect
  # that never completes the SSH banner leaves a zombie the honeypot retransmits;
  # just let ssh (below) connect for real.  ssh's ConnectTimeout handles down.
  say "${C}[1/3]${Z} Targeting the running deception host on :${PORT}…"
  say "      ${DIM}(driving a real ssh attacker · watch the operator window: F12 → 'watch')${Z}"
else
  # STANDALONE · boot our own host (refuse to fight an operator QEMU for the lock).
  if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    say "${R}[demo] a QEMU is already running.${Z}  For the live combo run:  ${B}just demo-ssh attack${Z}"
    say "       (that drives the attacker against your running run-interactive window instead of booting)"
    exit 3
  fi
  for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
    [ -f "$t" ] || { say "${R}[demo] missing $t · run 'just build'${Z}"; exit 2; }; done
  rm -f "$SLOG"
  say "${C}[1/4]${Z} Booting the deception host (SSH honeypot on :${PORT})…"
  timeout 240 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 < /dev/null > "$SLOG" 2>&1 &
  QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
  for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
  LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { say "${R}[demo] FAIL · :22 never came up${Z}"; exit 1; }
  say "      ${G}✓${Z} :22 LISTEN — SSH persona online"
  sleep 2
fi

# ---- the attacker: a real ssh -tt recon session -----------------------------
STEP=$([ "$MODE" = attack ] && echo "2/3" || echo "2/4")
say "${C}[$STEP]${Z} Attacker connects over SSH and runs recon…"
say "      ${DIM}(real ssh -tt · password auth · 3rd try lets them 'in')${Z}"
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
( sleep 3;  printf 'whoami\n';   sleep 2; printf 'id\n';        sleep 2;
  printf 'uname -a\n';           sleep 2; printf 'cat /etc/passwd\n'; sleep 3;
  printf 'cat /etc/passwd | grep root\n'; sleep 3;
  printf 'echo BACKDOOR > /etc/cron.d/persist\n'; sleep 3;
  printf 'exit\n'; sleep 4 ) | \
  timeout 90 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 root@127.0.0.1 > "$CLOG" 2>&1 || true
sleep 2

# ---- THE LIE (what the attacker saw · from the client transcript) -----------
cg(){ LC_ALL=C grep -ac "$1" "$CLOG"; }
sg(){ [ -f "$SLOG" ] || { echo 0; return; }; LC_ALL=C grep -ac "$1" "$SLOG"; }  # grep -c prints the count even on 0 (exit 1) — no `|| echo 0` (it double-prints)
STEP=$([ "$MODE" = attack ] && echo "3/3" || echo "3/4")
say "${C}[$STEP]${Z} ${B}THE LIE${Z} — what the attacker saw:"
saw_passwd=0; saw_idun=0; saw_deny=0
[ "$(cg 'root:x:0:0')" -ge 1 ] && { saw_passwd=1; say "      ${Y}\$ cat /etc/passwd${Z}   → honey accounts ($(LC_ALL=C grep -ac '^[a-z].*:x:[0-9]' "$CLOG") users · root:x:0:0…)"; }
[ "$(cg 'uid=')"   -ge 1 ] && { saw_idun=1; say "      ${Y}\$ id${Z}                → $(LC_ALL=C grep -aoE 'uid=[0-9].*' "$CLOG" | head -1)"; }
[ "$(cg 'Linux')"  -ge 1 ] && { saw_idun=1; say "      ${Y}\$ uname -a${Z}          → $(LC_ALL=C grep -aoE 'Linux [^ ]+ .*' "$CLOG" | head -1 | cut -c1-52)…"; }
{ [ "$(cg 'denied')" -ge 1 ] || [ "$(cg 'Read-only')" -ge 1 ]; } && { saw_deny=1; say "      ${Y}\$ echo BACKDOOR > /etc/cron.d/persist${Z} → ${R}Permission denied${Z}"; }

# ---- THE TRUTH --------------------------------------------------------------
if [ "$MODE" = attack ]; then
  say "      ${B}THE TRUTH${Z} is streaming LIVE in the operator window → ${B}F12 → watch${Z}"
  say "      ${DIM}(cred capture · canary reads · write containment · all recorded by sottrace)${Z}"
else
  cred=$(LC_ALL=C grep -aoE 'SSH cred conn=[0-9]+ user=[^ ]+ pass=[^ ]+' "$SLOG" | head -1)
  ncanary=$(sg '\[canary\] pid=')
  say "${C}[4/4]${Z} ${B}THE TRUTH${Z} — what sotOs did (the operator's view):"
  [ "$(sg 'N2 inbound LISTEN')" -ge 1 ] && say "      ${G}⇄ INBOUND${Z}    SSH persona served the connection"
  if [ -n "$cred" ]; then
    u=$(printf '%s' "$cred" | sed -E 's/.*user=([^ ]+).*/\1/'); p=$(printf '%s' "$cred" | sed -E 's/.*pass=([^ ]+).*/\1/')
    say "      ${G}🔑 CRED CAPTURE${Z} attacker creds logged: user=${B}${u}${Z} pass=${B}${p}${Z}"
  fi
  [ "$ncanary" -ge 1 ] && say "      ${G}⚠ CANARY${Z}     attacker read the honey passwd — took the bait (${ncanary}×)"
  { [ "$(sg '\[silenced\]')" -ge 1 ] || [ "$(sg 'ISOLATED_WRITE_DROP')" -ge 1 ] || [ "$saw_deny" -ge 1 ]; } \
    && say "      ${G}⛔ CONTAINED${Z}  the tamper write was blocked + recorded (Tier-2 isolated)"
  say "      ${DIM}(serial: $SLOG · client: $CLOG)${Z}"
fi

# ---- verdict ----------------------------------------------------------------
rule
deceived=$(( saw_passwd && saw_idun ))
if [ "$MODE" = attack ]; then
  if [ "$deceived" -eq 1 ] && [ "$saw_deny" -eq 1 ]; then
    say "${G}${B}  DECEPTION DEMO: PASS${Z} — attacker ${G}deceived${Z} + ${G}contained${Z}.  Truth → operator's ${B}watch${Z}."
    rule; exit 0
  fi
  say "${R}${B}  DECEPTION DEMO: INCOMPLETE${Z}  deceived=$deceived contained=$saw_deny"
  if grep -qaiE 'timed out|refused|closed by remote' "$CLOG"; then
    say "  the ssh session didn't complete — is the host up with the :${PORT} forward?"
    say "  restart it from this branch:  ${B}just run-interactive${Z}  (then retry)"
  fi
  say "  (client: $CLOG)"; rule; exit 1
fi
cred=$(LC_ALL=C grep -aoE 'SSH cred conn=[0-9]+ user=[^ ]+ pass=[^ ]+' "$SLOG" | head -1)
ncanary=$(sg '\[canary\] pid=')
recorded=0; { [ "$ncanary" -ge 1 ] || [ -n "$cred" ]; } && recorded=1
contained=0; { [ "$(sg '\[silenced\]')" -ge 1 ] || [ "$(sg 'ISOLATED_WRITE_DROP')" -ge 1 ] || [ "$saw_deny" -ge 1 ]; } && contained=1
faults=0; { [ "$(sg 'Invocation of invalid cap')" -eq 0 ] && [ "$(sg 'CapFault')" -eq 0 ] && [ "$(sg 'code=139')" -eq 0 ]; } || faults=1
if [ "$deceived" -eq 1 ] && [ "$contained" -eq 1 ] && [ "$recorded" -eq 1 ] && [ "$faults" -eq 0 ]; then
  say "${G}${B}  DECEPTION DEMO: PASS${Z} — attacker ${G}deceived${Z}, ${G}contained${Z}, and ${G}recorded${Z}."
  rule; exit 0
fi
say "${R}${B}  DECEPTION DEMO: INCOMPLETE${Z}  deceived=$deceived contained=$contained recorded=$recorded faults=$faults"
say "  (see $SLOG / $CLOG)"; rule; exit 1
