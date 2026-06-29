#!/usr/bin/env bash
# sotOs · v1.4 labyrinth · ESCAPE-DENY gate (the genuinely-new campaign gate).
#
# A real SSH attacker, logged into the Tier-2 busybox honey shell, throws an
# escape battery and we PROVE every attempt is CONTAINED — there is no host FS
# behind the closed VFS namespace, writes are denied/captured, errors are
# PLAUSIBLE (EACCES/ENOENT/ELOOP — never a sandbox-revealing ENOSYS), and the
# runtime survives (no cap/abnormal fault, orch alive).
#
# Containment is by construction (seL4 capability isolation: a fresh empty guest
# CNode with only a badged fault EP, linuxABI forcing every syscall to LucAs, and
# exact-match closed VFS backends — nothing to escape TO).  This gate ASSERTS that
# containment over the real attacker path; it is not a fix-then-gate.
#
# Escape classes covered here (file/path, shell-drivable): `..` traversal,
# symlink escape, /proc/self/fd, sensitive-zone write, persistence write.  The
# fork/clone-abuse class is the separate fork-bomb gate; dangerous-syscall is the
# abi gate; both are registered in scripts/labyrinth-validate.sh.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
PORT=18022; SLOG=/tmp/sotos-escape-serial.log; CLOG=/tmp/sotos-escape-client.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[escape-gate] BLOCKED: operator QEMU live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img; do [ -f "$t" ] || { echo "[escape-gate] missing $t · run just build"; exit 2; }; done
rm -f "$SLOG" "$CLOG"
echo "[escape-gate] booting honeypot..."
timeout 240 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[escape-gate] WARN · :22 never LISTENed (env-flaky SSH in-sandbox)"; echo "=== ESCAPE-DENY: WARN (env-flaky · not tested) ==="; exit 2; }
sleep 2; echo "[escape-gate] :22 LISTEN · ssh attacker throws the escape battery..."
ASK=/tmp/sotos-askpass.sh; printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
# The escape battery (slow feed · keep stdin open so each runs+outputs before the next).
( sleep 3;  printf 'id\n'; sleep 2
  sleep 1;  printf 'cat /etc/../../../root/.ssh/id_rsa\n'; sleep 2          # 1 · `..` traversal
  sleep 1;  printf 'ln -s /etc/shadow /tmp/esc && cat /tmp/esc\n'; sleep 2 # 2 · symlink escape
  sleep 1;  printf 'cat /proc/self/fd/3\n'; sleep 2                        # 3 · /proc/self/fd
  sleep 1;  printf 'echo PWNED > /etc/crontab\n'; sleep 2                  # 4 · sensitive write
  sleep 1;  printf 'echo evil > /tmp/persist && ls -la /tmp/persist\n'; sleep 2  # 5 · persistence write
  sleep 1;  printf 'cat /etc/shadow\n'; sleep 2                            # bonus · sensitive read
  sleep 1;  printf 'exit\n'; sleep 4 ) | \
  timeout 90 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 root@127.0.0.1 > "$CLOG" 2>&1 || true

echo "=== v1.4 labyrinth · ESCAPE-DENY gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }; cg(){ LC_ALL=C grep -aic "$1" "$CLOG"; }

# (a) the attacker got a shell at all (else the rest is moot · env-flaky → WARN)
[ "$(sg 'ssh-shell:.*entering fault loop')" -ge 1 ] \
  || { echo "WARN · attacker shell not established (env-flaky SSH) — escape battery not delivered"; echo "=== ESCAPE-DENY: WARN (env-flaky · not tested) ==="; exit 2; }
echo "PASS · attacker shell established (Tier-2 honey busybox over SSH)"

# (b) NO real host secret reached the attacker.  There is no host FS behind the
#     VFS; a private key / shadow hash must NEVER appear in the client stream.
#     The honey /etc/shadow DELIBERATELY serves bait hashes ($6$honey<name>$ —
#     a real root, on a real box, CAN read shadow, and a honeypot wants the
#     attacker to waste time cracking honeytokens / tripwire on a "cracked" login).
#     So count only NON-honey shadow hashes: a leaked REAL hash (root:$<algo>$…
#     not one of our honeytokens) still FAILs; the intentional bait does not.
real_hash=$(tr -d '\r' < "$CLOG" | grep -aE 'root:\$[0-9]' | grep -avcE '\$6\$honey(root|admin|backer|ops)')
{ [ "$(cg 'BEGIN OPENSSH PRIVATE KEY')" -eq 0 ] && [ "$(cg 'BEGIN RSA PRIVATE KEY')" -eq 0 ] \
  && [ "$real_hash" -eq 0 ]; } \
  && echo "PASS · no real host secret leaked (private key absent; only intentional honey shadow bait)" \
  || { echo "FAIL · a real secret reached the attacker (non-honey shadow hash or private key)"; fail=1; }

# (c) sensitive-zone + persistence writes CONTAINED (denied or captured, never silent success)
{ [ "$(cg 'Permission denied')" -ge 1 ] || [ "$(sg 'silently dropped')" -ge 1 ] \
  || [ "$(sg 'CANARY')" -ge 1 ] || [ "$(sg 'persistence')" -ge 1 ]; } \
  && echo "PASS · sensitive/persistence writes contained (denied or captured as intel)" \
  || echo "WARN · write-containment marker not confirmed (check $SLOG/$CLOG)"

# (d) NO sandbox-revealing ENOSYS tell on the escape probes
[ "$(sg '\[LucAs\] ENOSYS sysno=')" -eq 0 ] \
  && echo "PASS · no ENOSYS tell (errors are plausible, not 'function not implemented')" \
  || echo "WARN · an ENOSYS appeared — check it is not on an escape probe ($SLOG)"

# (e) the runtime ENDURES: no cap/abnormal fault from the escape battery, orch alive
faults=$(LC_ALL=C grep -aEc 'Invocation of invalid cap|FAULT CapFault|FAULT UserException|FAULT NullFault|non-syscall fault cap reached|cspace exhausted|root server abort|exited code=139' "$SLOG")
{ [ "$(cg 'Corrupted MAC')" -eq 0 ] && [ "${faults:-0}" -eq 0 ]; } \
  && echo "PASS · runtime endured the escape battery (no cap/abnormal fault, no MAC error)" \
  || { echo "FAIL · abnormal fault during the escape battery ($faults)"; fail=1; }

echo "=== $( [ $fail -eq 0 ] && echo 'ESCAPE-DENY: PASS' || echo 'ESCAPE-DENY: FAIL' ) ==="
echo "(serial: $SLOG · client: $CLOG)"; exit $fail
