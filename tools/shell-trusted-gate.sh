#!/usr/bin/env bash
# gate-shell-trusted · TWO faces of `pip` on the interactive shell.
#
#  • DECEPTION (Tier-2 canary · the attacker's view · hermetic): in the boot
#    busybox canary shell, `pip install requests scapy` prints a believable
#    pip transcript (Collecting/Downloading/Successfully installed) and exits 0
#    — NO real network, NO 'pip: not found' / ENOSYS tell.  (execve_pip_facade)
#
#  • OPERATOR `shell --trusted` (Tier-0e · real egress): F12 → operator console
#    → `shell --trusted` spawns a busybox shell at FUNCTOR_TIER_EGRESS; a
#    `python3 --version` typed in it spawns REAL CPython that inherited the
#    trust (g_shell_trusted_egress) → proves the inheritance path.  A real
#    `pip install six` over the live wire is a best-effort (network) extra.
#
# Sendkey-driven (HMP unix-socket monitor).  The deception leg is hermetic; the
# real-egress leg needs live internet (skipped-soft when offline).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-shelltrusted-serial.log
MON=/tmp/sotos-shelltrusted-mon.sock

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[shell-trusted-gate] BLOCKED: operator QEMU live"; exit 3
fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[shell-trusted-gate] missing $t · run 'just build'"; exit 2; }; done
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.2); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }
# type a whole string char-by-char via sendkey (letters/digits/space/-/./ only).
typestr(){ local s="$1" c k; for (( i=0; i<${#s}; i++ )); do c="${s:$i:1}";
  case "$c" in
    " ") k="spc";; "-") k="minus";; ".") k="dot";; "/") k="slash";;
    *)   k="$c";;
  esac; mon "sendkey $k"; sleep 0.12; done; mon "sendkey ret"; }

echo "[shell-trusted-gate] booting headless…"
timeout 760 qemu-system-x86_64 -m 4096 -display none -vga none \
  -serial "file:$SLOG" -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci \
  -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT

waitfor 'busybox canary shell' 240 || { echo "[shell-trusted-gate] FAIL · never reached boot"; kill $QPID 2>/dev/null; exit 1; }
sleep 4

# --- 1) DECEPTION · pip in the Tier-2 canary shell (attacker's view) ---------
echo "[shell-trusted-gate] (canary) typing 'pip install requests scapy'…"
typestr "pip install requests scapy"
waitfor 'Successfully installed requests' 30 || echo "[shell-trusted-gate] WARN · deception transcript not seen yet"
sleep 2

# --- 2) OPERATOR shell --trusted · Tier-0e + python inheritance --------------
echo "[shell-trusted-gate] F12 → operator console…"
mon "sendkey f12"; sleep 2
echo "[shell-trusted-gate] typing 'shell --trusted'…"
typestr "shell --trusted"
waitfor 'Tier-0e TRUSTED' 20 || echo "[shell-trusted-gate] WARN · trusted shell spawn marker not seen"
sleep 3
echo "[shell-trusted-gate] (trusted) typing 'python3 --version'…"
typestr "python3 --version"
waitfor 'Python 3.1' 40 || echo "[shell-trusted-gate] WARN · trusted python version not seen"
sleep 2
# real egress: a plain interactive `pip install six` over the live wire.  Works
# end-to-end (resolve pypi.org → download wheel → install into the writable
# PIP_TARGET=/tmp/site-packages).  Network-dependent → non-gating (best-effort)
# so the hermetic legs still pass offline, but it PASSes whenever internet is up.
echo "[shell-trusted-gate] (trusted) typing 'pip install six' (real egress · network)…"
typestr "pip install six"
waitfor 'Successfully installed six-1' 280 || echo "[shell-trusted-gate] (info) real pip-install-six not observed (CI offline)"
sleep 2
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

echo "=== shell --trusted + pip deception gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

# DECEPTION (hard · hermetic)
[ "$(sg 'Collecting requests')" -ge 1 ] \
  && echo "PASS · deception · 'Collecting requests' shown" \
  || { echo "FAIL · deception transcript missing 'Collecting requests'"; fail=1; }
[ "$(sg 'Successfully installed requests-2.32.3')" -ge 1 ] \
  && echo "PASS · deception · 'Successfully installed requests-2.32.3 …' shown" \
  || { echo "FAIL · deception success line missing"; fail=1; }
[ "$(sg 'scapy-2.5.0')" -ge 1 ] \
  && echo "PASS · deception · second package (scapy-2.5.0) in the summary" \
  || { echo "FAIL · deception did not handle multiple packages"; fail=1; }

# OPERATOR trusted shell (hard · hermetic)
[ "$(sg 'Tier-0e TRUSTED')" -ge 1 ] \
  && echo "PASS · 'shell --trusted' spawned at Tier-0e (real egress)" \
  || { echo "FAIL · trusted shell did not spawn at Tier-0e"; fail=1; }
[ "$(sg 'trusted-egress) spawn')" -ge 1 ] \
  && echo "PASS · python child inherited Tier-0e (trusted-egress spawn)" \
  || { echo "FAIL · python child did not inherit trust"; fail=1; }
[ "$(sg 'Python 3.1')" -ge 1 ] \
  && echo "PASS · real CPython ran in the trusted shell (python3 --version)" \
  || { echo "FAIL · trusted python did not run"; fail=1; }

# real egress (best-effort · network · info only)
if [ "$(sg 'Successfully installed six-1')" -ge 1 ]; then
  echo "PASS(extra) · REAL 'pip install six' completed over the live wire"
else
  echo "INFO · real pip-install-six not observed (CI offline or slow) — not gating"
fi

nf=$(LC_ALL=C grep -acE 'CapFault|VMFault|code=139|FAULT UserException|invalid cap' "$SLOG")
[ "${nf:-0}" -eq 0 ] && echo "PASS · 0 faults" || { echo "FAIL · ${nf} fault(s)"; fail=1; }
echo "=== $( [ $fail -eq 0 ] && echo 'SHELL-TRUSTED: PASS' || echo 'SHELL-TRUSTED: FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
