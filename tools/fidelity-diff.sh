#!/usr/bin/env bash
# sotOs · terminal-fidelity diff · run the recon/usage battery on a REAL Alpine
# busybox sh (ground truth) AND on the sotOs honey shell over SSH (the attacker's
# clean channel · no orch debug), then show them side by side.  Each DIVERGENCE
# where sotOs errors / ENOSYS / gives a structurally-wrong answer (vs a mere
# persona-value difference like uname -r) is a fidelity TELL to close.
#
#   tools/fidelity-diff.sh            run both, write the report
#   tools/fidelity-diff.sh --alpine   only the Alpine ground truth
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
BAT="${BATTERY:-tools/fidelity/battery.sh}"
OUT=/tmp/fidelity; mkdir -p "$OUT"
ALP="$OUT/alpine.out"; SOT="$OUT/sotos.out"; REP="$OUT/report.txt"
PORT=18022; SLOG="$OUT/sotos-serial.log"; CLOG="$OUT/sotos-client.log"

# Build a MARKED script: echo a unique marker before each battery command so the
# output can be split per-command on both sides.
MARK="$OUT/marked.sh"; : > "$MARK"
n=0; while IFS= read -r cmd; do
  [ -z "$cmd" ] && continue
  n=$((n+1)); printf 'echo "##FID##%03d## %s"\n%s\n' "$n" "$cmd" "$cmd" >> "$MARK"
done < "$BAT"
echo "echo '##FID##END##'" >> "$MARK"
NCMD=$n

# ── ground truth · real Alpine busybox sh ───────────────────────────────────
echo "[fid] Alpine ground truth ($NCMD commands)…"
podman run --rm -i docker.io/library/alpine:3.20 sh 2>&1 < "$MARK" > "$ALP" || true
[ "${1:-}" = "--alpine" ] && { echo "[fid] alpine.out written"; exit 0; }

# ── sotOs honey shell over SSH ──────────────────────────────────────────────
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[fid] BLOCKED: a QEMU is live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[fid] missing $t · run ./demo.sh --check"; exit 2; }; done
rm -f "$SLOG" "$CLOG"
echo "[fid] booting sotOs (SSH on :$PORT)…"
timeout 380 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 90); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[fid] FAIL · :22 never LISTENed"; exit 1; }
sleep 2; echo "[fid] :22 up · feeding the battery over SSH…"
ASK="$OUT/askpass.sh"; printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
# Wait out the auth dance (2 rejects + the 3rd accept over SLIRP ≈ 10s) BEFORE
# feeding, else the battery is sent into the login and lost (busybox then EOFs).
# Feed line-by-line with a small gap so each command runs + drains in order.
( sleep 14; while IFS= read -r l; do printf '%s\n' "$l"; sleep 0.4; done < "$MARK"; sleep 10; printf 'exit\n'; sleep 3 ) | \
  timeout 160 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
  ssh -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 root@127.0.0.1 > "$CLOG" 2>&1 || true
# strip CR + the SSH banner noise; keep from the first marker on.
tr -d '\r' < "$CLOG" | awk '/##FID##001##/{f=1} f' > "$SOT"
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true

# ── side-by-side report ─────────────────────────────────────────────────────
python3 - "$ALP" "$SOT" "$BAT" "$NCMD" > "$REP" <<'PY'
import sys,re
alp=open(sys.argv[1],errors='replace').read(); sot=open(sys.argv[2],errors='replace').read()
cmds=[l for l in open(sys.argv[3]).read().splitlines() if l.strip()]
N=int(sys.argv[4])
def split(txt):
    out={}; cur=None; buf=[]
    for line in txt.splitlines():
        m=re.match(r'##FID##(\d{3}|END)##',line)
        if m:
            if cur is not None: out[cur]='\n'.join(buf).strip()
            if m.group(1)=='END': cur=None; break
            cur=int(m.group(1)); buf=[]
        elif cur is not None: buf.append(line)
    if cur is not None: out[cur]='\n'.join(buf).strip()
    return out
A=split(alp); S=split(sot)
def first(s,k=2): return ' / '.join(s.splitlines()[:k]) if s else '(empty)'
tells=0
for i in range(1,N+1):
    cmd=cmds[i-1] if i-1<len(cmds) else '?'
    a=A.get(i,'(MISSING)'); s=S.get(i,'(MISSING)')
    # heuristic tell: sotos errored/empty/not-found while alpine produced output
    al=a.lower(); sl=s.lower()
    tell=False
    if s in ('(MISSING)','') and a not in ('(MISSING)',''): tell=True
    for bad in ('not found','enosys','no such','cannot','unrecognized','applet not found','bad ','invalid option'):
        if bad in sl and bad not in al: tell=True
    mark='  ⚠TELL' if tell else ''
    if tell: tells+=1
    print(f'[{i:02d}] $ {cmd}{mark}')
    print(f'     alpine: {first(a)}')
    print(f'     sotos : {first(s)}')
print(f'\n=== {tells} candidate TELL(s) of {N} commands (eyeball the ⚠ lines + persona diffs) ===')
PY
echo "[fid] report → $REP"; echo "---"; cat "$REP"
