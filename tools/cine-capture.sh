#!/usr/bin/env bash
# sotOs · cinematic capture · drive the 3-act demo headless (virtio-gpu) and
# screendump the framebuffer at each beat → captures/cine/NN-*.png.  The same
# FB carries console_fb text (attacker/operator/pip/wine) AND the wayland render
# (GTK/Doom), so one screendump path captures every shot.  See CINE.md for the
# storyboard (caption + narration per shot).
#
# Network beats (pip) need live internet.  ~12 min total.  Produces 6 PNGs.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
OUT=captures/cine; mkdir -p "$OUT"
SLOG=/tmp/sotos-cine-serial.log; MON=/tmp/sotos-cine-mon.sock
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[cine] BLOCKED: a QEMU is live"; exit 3; fi
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[cine] missing $t · run ./demo.sh --check or 'just build'"; exit 2; }; done
rm -f "$SLOG" "$MON"; : > "$SLOG"

mon(){ python3 - "$MON" "$1" <<'PY' 2>/dev/null || true
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall((sys.argv[2]+"\n").encode()); time.sleep(0.25); s.close()
PY
}
waitfor(){ for i in $(seq 1 "${2:-60}"); do LC_ALL=C grep -qa "$1" "$SLOG" 2>/dev/null && return 0; sleep 1; done; return 1; }
type_str(){ local s="$1" c k; for (( i=0;i<${#s};i++ )); do c="${s:$i:1}";
  case "$c" in " ")k=spc;; "-")k=minus;; ".")k=dot;; "/")k=slash;; *)k="$c";; esac
  mon "sendkey $k"; sleep 0.10; done; mon "sendkey ret"; }
shot(){ # shot <name> · screendump the FB → PNG (PPM fallback if no converter)
  local n="$1" ppm="/tmp/cine-$1.ppm" png="$OUT/$1.png"
  mon "screendump $ppm"; sleep 2
  if [ -s "$ppm" ]; then
    (magick "$ppm" "$png" 2>/dev/null || convert "$ppm" "$png" 2>/dev/null || cp "$ppm" "$OUT/$1.ppm")
    echo "[cine] shot $1 → $( [ -f "$png" ] && echo "$png" || echo "$OUT/$1.ppm" )"
  else echo "[cine] WARN · shot $1 · no PPM produced"; fi; }

echo "[cine] booting headless (virtio-gpu · ~12 min)…"
# -vga none: virtio-gpu is the ONLY display, so screendump captures console_fb +
# the wayland render (without it QEMU adds a default VGA showing only SeaBIOS,
# which is what screendump would grab — the wrong scanout).
timeout 900 qemu-system-x86_64 -m 4096 -display none -vga none -enable-kvm -cpu host -serial "file:$SLOG" \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci -monitor "unix:$MON,server,nowait" &
QPID=$!; trap 'kill $QPID 2>/dev/null; rm -f "$MON"' EXIT
waitfor 'busybox canary shell' 180 || { echo "[cine] FAIL boot"; exit 1; }; sleep 4

# ── ACT 1a · attacker recon (canary shell) ──────────────────────────────────
# These are the NARRATIVE shots (text via console_fb) — captured reliably.
echo "[cine] ACT 1a · attacker recon"
type_str "whoami"; sleep 1
type_str "id"; sleep 1
type_str "uname -a"; sleep 1
type_str "cat /etc/passwd"; sleep 1
type_str "cat /tmp/honey-aws-creds"; sleep 2     # the AWS-canary bait (sotfs root = /tmp)
shot 01-attacker-recon

# ── ACT 1b · operator truth (F12) ───────────────────────────────────────────
echo "[cine] ACT 1b · operator truth view"
mon "sendkey f12"; sleep 3
type_str "list"; sleep 2
type_str "anomaly-log"; sleep 2
shot 02-operator-truth

# ── ACT 2 · pip install from PyPI (reliable operator path) ──────────────────
echo "[cine] ACT 2 · pip install from PyPI (egress-pip · ~2-3 min)"
type_str "egress-pip"
waitfor 'PIP_FULL_OK\|Successfully installed six' 220 || echo "[cine] (info) pip marker not seen"
sleep 2; shot 03-pip-pypi

# ── ACT 3 · Windows PE (wine-crt) · BEFORE the blocking graphical demos ──────
echo "[cine] ACT 3 · Windows PE (wine-crt)"
type_str "wine-crt"
waitfor 'hello from msvcrt printf' 140 || echo "[cine] (info) wine-crt marker not seen"
sleep 3; shot 04-wine-crt

# ── ACT 3 graphical · DOOM (captures cleanly headless) ──────────────────────
# `doom` (the /dev/fb0 doomgeneric path) blits each frame into the scanout AND
# gpu_flushes it, so screendump catches the real render.  (`doomwl`/`gtk3-demo`
# use the wayland path, which does NOT flush headless — grab those from the live
# window · see CINE.md.)  Wait for ~30 frames so it's past the title fade-in.
echo "[cine] ACT 3 graphical · doom (the iconic title screen)"
type_str "doom"
waitfor '\[doom\] frame=30' 90 || sleep 25
sleep 2; shot 05-doom

kill $QPID 2>/dev/null; wait $QPID 2>/dev/null || true
echo "[cine] DONE · captures in $OUT/ (GTK window: capture live · see CINE.md)"; ls -l "$OUT/"
